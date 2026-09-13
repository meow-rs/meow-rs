//! Client-side VLESS Encryption handshake and record-layer relay.
//!
//! Port of Xray/mihomo `encryption/client.go` (`ClientInstance.Init` /
//! `.Handshake`) plus the data-phase `CommonConn` / `XorConn` framing from
//! `common.go` / `xor.go`. Only the client role is implemented; a reference
//! server port lives in `server.rs` for the loopback integration test.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
use ml_kem::{EncapsulationKey, MlKem768};
use parking_lot::Mutex;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use x25519_dalek::{PublicKey, StaticSecret};

use meow_common::{MeowError, Result};
use meow_transport::Stream;

use super::aead::{
    blake3_sum256, create_padding, decode_header, decode_length, encode_header, encode_length,
    new_ctr, parse_padding, Aead, Aes256Ctr, Padding, MLKEM768_CT_LEN, MLKEM768_EK_LEN, TAG_LEN,
    X25519_LEN,
};
use ctr::cipher::StreamCipher;

/// Duplex buffer size for the plaintext side of the record relay.
const RELAY_BUF: usize = 32 * 1024;
/// Maximum plaintext bytes per record (`common.go`: `if len(b) > 8192`).
const MAX_CHUNK: usize = 8192;

/// A parsed long-term "NFS" public key from the `encryption` config string.
enum NfsKey {
    X25519(PublicKey),
    /// Boxed: an ML-KEM-768 encapsulation key is ~1.2 KiB (avoids a large enum).
    MlKem(Box<EncapsulationKey<MlKem768>>),
}

/// Cached 0-RTT resumption state, shared across dials on this instance.
#[derive(Default)]
pub(super) struct TicketCache {
    expire: Option<Instant>,
    pfs_key: Vec<u8>,
    ticket: Vec<u8>,
}

/// A shared VLESS Encryption client, mirroring Go's `ClientInstance`.
///
/// Held behind an `Arc` by the adapter; each dial runs [`Self::handshake`].
pub struct ClientInstance {
    nfs_keys: Vec<NfsKey>,
    nfs_keys_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    xor_mode: u32,
    seconds: u32,
    padding: Padding,
    use_aes: bool,
    cache: Arc<Mutex<TicketCache>>,
}

impl ClientInstance {
    /// `ClientInstance.Init` — parse the NFS keys and precompute relay sizes.
    pub fn init(
        nfs_keys_bytes: Vec<Vec<u8>>,
        xor_mode: u32,
        seconds: u32,
        padding: &str,
    ) -> std::result::Result<Self, String> {
        if nfs_keys_bytes.is_empty() {
            return Err("empty nfsPKeysBytes".into());
        }
        let mut nfs_keys = Vec::with_capacity(nfs_keys_bytes.len());
        let mut hash32s = Vec::with_capacity(nfs_keys_bytes.len());
        let mut relays_length: usize = 0;
        for k in &nfs_keys_bytes {
            if k.len() == X25519_LEN {
                let arr: [u8; 32] = k.as_slice().try_into().expect("checked len 32");
                nfs_keys.push(NfsKey::X25519(PublicKey::from(arr)));
                relays_length += X25519_LEN + 32;
            } else {
                let ek = EncapsulationKey::<MlKem768>::new_from_slice(k)
                    .map_err(|_| "invalid ML-KEM-768 encapsulation key".to_string())?;
                nfs_keys.push(NfsKey::MlKem(Box::new(ek)));
                relays_length += MLKEM768_CT_LEN + 32;
            }
            hash32s.push(blake3_sum256(k));
        }
        relays_length -= 32;

        let padding = parse_padding(padding)?;

        Ok(Self {
            nfs_keys,
            nfs_keys_bytes,
            hash32s,
            relays_length,
            xor_mode,
            seconds,
            padding,
            use_aes: has_aes_hardware(),
            cache: Arc::new(Mutex::new(TicketCache::default())),
        })
    }

    /// Configured XOR mode (0 native / 1 xorpub / 2 random).
    #[cfg(test)]
    pub fn xor_mode(&self) -> u32 {
        self.xor_mode
    }

    /// Configured 0-RTT flag (0 = 1-RTT, 1 = 0-RTT enabled).
    #[cfg(test)]
    pub fn seconds(&self) -> u32 {
        self.seconds
    }

    /// Run the encryption handshake over `stream` and return a plaintext duplex
    /// stream: everything written to it is record-framed and encrypted to the
    /// server, everything read from it is decrypted server output.
    pub async fn handshake(&self, mut stream: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let use_aes = self.use_aes;

        // ── iv + relays: per-key encapsulation / ECDH ─────────────────────────
        let iv: [u8; 16] = random_array();
        let mut relays = vec![0u8; self.relays_length];
        let mut nfs_key: Vec<u8> = Vec::new();
        let mut last_ctr: Option<Aes256Ctr> = None;
        let mut pos = 0usize;
        let n = self.nfs_keys.len();
        for (j, key) in self.nfs_keys.iter().enumerate() {
            let index = match key {
                NfsKey::X25519(server_pub) => {
                    let sk = StaticSecret::from(random_array::<32>());
                    let my_pub = PublicKey::from(&sk).to_bytes();
                    relays[pos..pos + X25519_LEN].copy_from_slice(&my_pub);
                    nfs_key = sk.diffie_hellman(server_pub).to_bytes().to_vec();
                    X25519_LEN
                }
                NfsKey::MlKem(ek) => {
                    let (ct, shared) = ek.encapsulate();
                    relays[pos..pos + MLKEM768_CT_LEN].copy_from_slice(ct.as_slice());
                    nfs_key = shared.as_slice().to_vec();
                    MLKEM768_CT_LEN
                }
            };
            if self.xor_mode > 0 {
                new_ctr(&self.nfs_keys_bytes[j], &iv)
                    .apply_keystream(&mut relays[pos..pos + index]);
            }
            if let Some(lc) = last_ctr.as_mut() {
                lc.apply_keystream(&mut relays[pos..pos + 32]);
            }
            if j == n - 1 {
                break;
            }
            let mut lc = new_ctr(&nfs_key, &iv);
            let mut hash = self.hash32s[j + 1];
            lc.apply_keystream(&mut hash);
            relays[pos + index..pos + index + 32].copy_from_slice(&hash);
            last_ctr = Some(lc);
            pos += index + 32;
        }

        let mut nfs_aead = Aead::new(&iv, &nfs_key, use_aes);
        let iv_and_relays = 16 + self.relays_length;

        // ── 0-RTT fast path (cached, unexpired ticket) ────────────────────────
        if self.seconds > 0 {
            let cached = {
                let cache = self.cache.lock();
                match cache.expire {
                    Some(exp) if Instant::now() < exp => {
                        Some((cache.pfs_key.clone(), cache.ticket.clone()))
                    }
                    _ => None,
                }
            };
            if let Some((pfs_key, ticket)) = cached {
                let mut pre_write = Vec::with_capacity(iv_and_relays + 18 + 32);
                pre_write.extend_from_slice(&iv);
                pre_write.extend_from_slice(&relays);
                pre_write.extend_from_slice(&nfs_aead.seal(&encode_length(32)));
                let enc_ticket = nfs_aead.seal(&ticket);
                pre_write.extend_from_slice(&enc_ticket);

                let united_key = concat(&pfs_key, &nfs_key);
                let aead = Aead::new(&enc_ticket, &united_key, use_aes);
                let write_ctr = (self.xor_mode == 2).then(|| new_ctr(&united_key, &iv));

                return Ok(spawn_relay(
                    stream,
                    DataPhase {
                        aead,
                        peer_aead: None,
                        united_key,
                        use_aes,
                        pre_write,
                        peer_padding_len: 0,
                        write_ctr,
                        read_ctr: None,
                        xor: self.xor_mode == 2,
                        // If the server rejects this 0-RTT ticket, drop it so the
                        // next dial falls back to a fresh 1-RTT handshake.
                        reset_cache: Some(Arc::clone(&self.cache)),
                    },
                ));
            }
        }

        // ── 1-RTT full handshake ──────────────────────────────────────────────
        let pfs_key_exchange_len = 18 + MLKEM768_EK_LEN + X25519_LEN + TAG_LEN;

        let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair();
        let mlkem_ek_bytes = mlkem_ek.to_bytes();
        let x_sk = StaticSecret::from(random_array::<32>());
        let x_pub = PublicKey::from(&x_sk).to_bytes();
        let mut pfs_public_key = Vec::with_capacity(MLKEM768_EK_LEN + X25519_LEN);
        pfs_public_key.extend_from_slice(mlkem_ek_bytes.as_slice());
        pfs_public_key.extend_from_slice(&x_pub);

        let mut client_hello = Vec::new();
        client_hello.extend_from_slice(&iv);
        client_hello.extend_from_slice(&relays);
        client_hello.extend_from_slice(&nfs_aead.seal(&encode_length(pfs_key_exchange_len - 18)));
        client_hello.extend_from_slice(&nfs_aead.seal(&pfs_public_key));

        let (padding_length, mut padding_lens, padding_gaps) = create_padding(&self.padding);
        let pad_body = vec![0u8; padding_length - 18 - TAG_LEN];
        client_hello.extend_from_slice(&nfs_aead.seal(&encode_length(padding_length - 18)));
        client_hello.extend_from_slice(&nfs_aead.seal(&pad_body));

        // Fragmented, gap-spaced clientHello write (anti-DPI traffic shaping).
        padding_lens[0] += iv_and_relays + pfs_key_exchange_len;
        let mut rest = client_hello.as_slice();
        for (i, &l) in padding_lens.iter().enumerate() {
            if l > 0 {
                let take = l.min(rest.len());
                stream
                    .write_all(&rest[..take])
                    .await
                    .map_err(MeowError::Io)?;
                rest = &rest[take..];
            }
            if let Some(gap) = padding_gaps.get(i) {
                if !gap.is_zero() {
                    tokio::time::sleep(*gap).await;
                }
            }
        }
        if !rest.is_empty() {
            stream.write_all(rest).await.map_err(MeowError::Io)?;
        }
        stream.flush().await.map_err(MeowError::Io)?;

        // ── Read the server's PFS key exchange ────────────────────────────────
        let mut enc_pfs_pub = vec![0u8; MLKEM768_CT_LEN + X25519_LEN + TAG_LEN];
        stream
            .read_exact(&mut enc_pfs_pub)
            .await
            .map_err(MeowError::Io)?;
        let dec = nfs_aead
            .open_max(&enc_pfs_pub)
            .map_err(|_| handshake_err("server PFS key AEAD open failed"))?;
        let mlkem_shared = mlkem_dk
            .decapsulate_slice(&dec[..MLKEM768_CT_LEN])
            .map_err(|_| handshake_err("ML-KEM-768 decapsulation failed"))?;
        let peer_x: [u8; 32] = dec[MLKEM768_CT_LEN..MLKEM768_CT_LEN + X25519_LEN]
            .try_into()
            .expect("32-byte X25519 slice");
        let x_shared = x_sk.diffie_hellman(&PublicKey::from(peer_x)).to_bytes();

        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(mlkem_shared.as_slice());
        pfs_key.extend_from_slice(&x_shared);
        let united_key = concat(&pfs_key, &nfs_key);

        let aead = Aead::new(&pfs_public_key, &united_key, use_aes);
        let mut peer_aead = Aead::new(&dec, &united_key, use_aes);

        // ── Ticket + padding length (for 0-RTT caching and data-phase skip) ───
        let mut enc_ticket = vec![0u8; 32];
        stream
            .read_exact(&mut enc_ticket)
            .await
            .map_err(MeowError::Io)?;
        let ticket = peer_aead
            .open(&enc_ticket)
            .map_err(|_| handshake_err("ticket AEAD open failed"))?;
        let seconds = decode_length(&ticket[..2]);
        if self.seconds > 0 && seconds > 0 {
            let mut cache = self.cache.lock();
            cache.expire = Some(Instant::now() + Duration::from_secs(seconds as u64));
            cache.pfs_key = pfs_key.clone();
            cache.ticket = ticket.clone();
        }

        let mut enc_length = vec![0u8; 18];
        stream
            .read_exact(&mut enc_length)
            .await
            .map_err(MeowError::Io)?;
        let dec_len = peer_aead
            .open(&enc_length)
            .map_err(|_| handshake_err("padding length AEAD open failed"))?;
        let peer_padding_len = decode_length(&dec_len[..2]);

        let (write_ctr, read_ctr) = if self.xor_mode == 2 {
            let ticket_iv: [u8; 16] = ticket[..16].try_into().expect("16-byte ticket");
            (
                Some(new_ctr(&united_key, &iv)),
                Some(new_ctr(&united_key, &ticket_iv)),
            )
        } else {
            (None, None)
        };

        Ok(spawn_relay(
            stream,
            DataPhase {
                aead,
                peer_aead: Some(peer_aead),
                united_key,
                use_aes,
                pre_write: Vec::new(),
                peer_padding_len,
                write_ctr,
                read_ctr,
                xor: self.xor_mode == 2,
                reset_cache: None,
            },
        ))
    }
}

/// State handed to the record-layer relay after a completed handshake.
///
/// Shape-agnostic: the same relay drives both the client and (test-only)
/// server data phase — only the AEADs, XOR keystreams, and pre-read/pre-write
/// framing differ.
pub(super) struct DataPhase {
    /// Write-direction AEAD.
    pub(super) aead: Aead,
    /// Read-direction AEAD; `None` for 0-RTT (derived from the server random).
    pub(super) peer_aead: Option<Aead>,
    pub(super) united_key: Vec<u8>,
    pub(super) use_aes: bool,
    /// Bytes prepended to the first outbound record (0-RTT clientHello).
    pub(super) pre_write: Vec<u8>,
    /// 1-RTT server padding body to read + decrypt + discard before records.
    pub(super) peer_padding_len: usize,
    /// Write-direction record-header XOR keystream (mode `random`).
    pub(super) write_ctr: Option<Aes256Ctr>,
    /// Read-direction record-header XOR keystream; `None`+`xor` ⇒ derive from
    /// the server random (0-RTT).
    pub(super) read_ctr: Option<Aes256Ctr>,
    pub(super) xor: bool,
    /// 0-RTT only: shared ticket cache to clear if the server rejects the
    /// replayed ticket (the first record fails to decode).
    pub(super) reset_cache: Option<Arc<Mutex<TicketCache>>>,
}

/// Spawn the bidirectional record relay and return the plaintext duplex half.
///
/// The returned stream owns both relay tasks: dropping it aborts them, which
/// is the bounded cleanup path when the upstream transport stays silent (no
/// data, FIN, or RST — issue #514). A write-side `shutdown()` alone only
/// half-closes; the read direction keeps delivering records until the peer
/// ends them.
pub(super) fn spawn_relay(stream: Box<dyn Stream>, dp: DataPhase) -> Box<dyn Stream> {
    let (client, proxy) = duplex(RELAY_BUF);
    let (rd, wr) = tokio::io::split(stream);
    let (proxy_rd, proxy_wr) = tokio::io::split(proxy);

    let DataPhase {
        aead,
        peer_aead,
        united_key,
        use_aes,
        pre_write,
        peer_padding_len,
        write_ctr,
        read_ctr,
        xor,
        reset_cache,
    } = dp;

    let read_key = united_key.clone();
    let read_task = tokio::spawn(read_loop(
        rd,
        proxy_wr,
        peer_aead,
        read_ctr,
        xor,
        peer_padding_len,
        read_key,
        use_aes,
        reset_cache,
    ));
    let write_task = tokio::spawn(write_loop(
        wr, proxy_rd, aead, write_ctr, pre_write, united_key, use_aes,
    ));

    let aborts = [read_task.abort_handle(), write_task.abort_handle()];

    // Same supervisor as the vmess relay: when the read side ends —
    // upstream close, decode failure — the exchange is over; stop the
    // write side instead of leaving it pumping into a dead transport
    // until the client endpoint drops (issue #514 review).
    tokio::spawn(async move {
        let _ = read_task.await;
        write_task.abort();
    });

    Box::new(crate::tasked_duplex::TaskedDuplex::new(client, aborts))
}

/// Read records from `rd`, decrypt, and forward plaintext to `proxy_wr`.
#[allow(clippy::too_many_arguments)]
async fn read_loop(
    mut rd: ReadHalf<Box<dyn Stream>>,
    mut proxy_wr: WriteHalf<DuplexStream>,
    peer_aead: Option<Aead>,
    mut read_ctr: Option<Aes256Ctr>,
    xor: bool,
    peer_padding_len: usize,
    united_key: Vec<u8>,
    use_aes: bool,
    reset_cache: Option<Arc<Mutex<TicketCache>>>,
) {
    // A 0-RTT rejection surfaces as a decode failure on the very first record
    // (the server sends deliberate noise). Until one record decodes cleanly,
    // treat an early failure as "ticket rejected" and drop it so the next dial
    // does a fresh 1-RTT handshake.
    let mut first_record_ok = false;
    let invalidate = |reset_cache: &Option<Arc<Mutex<TicketCache>>>| {
        if let Some(cache) = reset_cache {
            cache.lock().expire = None;
        }
    };

    // 0-RTT: derive the read AEAD (and read XOR keystream) from the 16-byte
    // server random that precedes the first record.
    let mut peer_aead = match peer_aead {
        Some(a) => a,
        None => {
            let mut sr = [0u8; 16];
            if rd.read_exact(&mut sr).await.is_err() {
                return;
            }
            if xor {
                read_ctr = Some(new_ctr(&united_key, &sr));
            }
            Aead::new(&sr, &united_key, use_aes)
        }
    };

    // 1-RTT: consume the server's padding body (decrypt + discard).
    if peer_padding_len > 0 {
        let mut pad = vec![0u8; peer_padding_len];
        if rd.read_exact(&mut pad).await.is_err() || peer_aead.open(&pad).is_err() {
            return;
        }
    }

    loop {
        let mut hdr = [0u8; 5];
        if rd.read_exact(&mut hdr).await.is_err() {
            break;
        }
        if let Some(ctr) = read_ctr.as_mut() {
            ctr.apply_keystream(&mut hdr);
        }
        let Ok(l) = decode_header(&hdr) else {
            if !first_record_ok {
                invalidate(&reset_cache);
            }
            break;
        };
        let mut data = vec![0u8; l];
        if rd.read_exact(&mut data).await.is_err() {
            break;
        }
        let rekey = peer_aead.is_exhausted().then(|| {
            let mut ctx = Vec::with_capacity(5 + data.len());
            ctx.extend_from_slice(&hdr);
            ctx.extend_from_slice(&data);
            Aead::new(&ctx, &united_key, use_aes)
        });
        let Ok(plain) = peer_aead.open_ad(&data, &hdr) else {
            if !first_record_ok {
                invalidate(&reset_cache);
            }
            break;
        };
        first_record_ok = true;
        if let Some(next) = rekey {
            peer_aead = next;
        }
        if proxy_wr.write_all(&plain).await.is_err() {
            break;
        }
    }
    let _ = proxy_wr.shutdown().await;
}

/// Read plaintext from `proxy_rd`, record-frame + encrypt, and write to `wr`.
async fn write_loop(
    mut wr: WriteHalf<Box<dyn Stream>>,
    mut proxy_rd: ReadHalf<DuplexStream>,
    mut aead: Aead,
    mut write_ctr: Option<Aes256Ctr>,
    mut pre_write: Vec<u8>,
    united_key: Vec<u8>,
    use_aes: bool,
) {
    let mut buf = vec![0u8; MAX_CHUNK];
    loop {
        let n = match proxy_rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let body = &buf[..n];

        let mut header = encode_header(body.len() + TAG_LEN);
        let exhausted = aead.is_exhausted();
        let sealed = aead.seal_ad(body, &header);
        if exhausted {
            let mut ctx = Vec::with_capacity(5 + sealed.len());
            ctx.extend_from_slice(&header);
            ctx.extend_from_slice(&sealed);
            aead = Aead::new(&ctx, &united_key, use_aes);
        }
        if let Some(ctr) = write_ctr.as_mut() {
            ctr.apply_keystream(&mut header);
        }

        let mut out = Vec::with_capacity(pre_write.len() + 5 + sealed.len());
        if !pre_write.is_empty() {
            out.append(&mut pre_write);
        }
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        if wr.write_all(&out).await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

// ─── helpers ──────────────────────────────────────────────────────────────────

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::Rng::fill(&mut rand::rng(), &mut b[..]);
    b
}

fn handshake_err(msg: &str) -> MeowError {
    MeowError::Proxy(format!("vless-encryption: {msg}"))
}

/// Whether the CPU has AES-GCM hardware acceleration — mirrors Go's
/// `HasAESGCMHardwareSupport`, which drives the AES-vs-ChaCha AEAD choice.
/// (Interop-safe either way: the server flips its cipher if the guess is wrong.)
fn has_aes_hardware() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}
