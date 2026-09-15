use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::header::{response_body_keys, Security};

/// Maximum plaintext per body record (matching upstream 16 KiB - 16 tag).
const MAX_PLAINTEXT: usize = 16384 - 16;

/// Body keys/IVs derived from the per-connection req_key and req_iv. The IVs
/// are the full 16-byte seeds; each record nonce is `count(2 BE) || iv[2..12]`.
struct DerivedKeys {
    write_key: Vec<u8>,
    write_iv: [u8; 16],
    read_key: Vec<u8>,
    read_iv: [u8; 16],
}

/// Expand a 16-byte AEAD seed key into the actual cipher key for `security`.
///
/// - AES-128-GCM: the 16-byte key is used directly.
/// - ChaCha20-Poly1305: 32-byte key `MD5(k) || MD5(MD5(k))`.
///
/// upstream: `transport/vmess/conn.go` (`sendRequest`, per-security branch).
fn expand_body_key(security: Security, key16: &[u8; 16]) -> Vec<u8> {
    match security {
        Security::Aes128Gcm => key16.to_vec(),
        Security::ChaCha20Poly1305 => {
            let md5_1: [u8; 16] = Md5::digest(key16).into();
            let md5_2: [u8; 16] = Md5::digest(md5_1).into();
            let mut k = Vec::with_capacity(32);
            k.extend_from_slice(&md5_1);
            k.extend_from_slice(&md5_2);
            k
        }
        Security::None => Vec::new(),
    }
}

fn derive_keys(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16]) -> DerivedKeys {
    // Request (write) direction uses the raw per-connection key/iv directly —
    // there is NO "VMess Body AEAD Key" KDF in the wire protocol.
    let write_key = expand_body_key(security, req_key);
    let write_iv = *req_iv;

    // Response (read) direction keys come from SHA-256 of the request key/iv.
    let (resp_key, resp_iv) = response_body_keys(req_key, req_iv);
    let read_key = expand_body_key(security, &resp_key);

    DerivedKeys {
        write_key,
        write_iv,
        read_key,
        read_iv: resp_iv,
    }
}

/// One direction's AEAD state. The cipher object (the expanded key schedule)
/// is built once per connection — only the nonce changes per record.
#[derive(Clone)]
enum RecordCipher {
    None,
    /// Boxed: the AES key schedule is ~10× the size of the other variants.
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl RecordCipher {
    fn new(security: Security, key: &[u8]) -> Self {
        match security {
            Security::None => Self::None,
            Security::Aes128Gcm => Self::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(key).expect("derived AES-128 key is 16 bytes"),
            )),
            Security::ChaCha20Poly1305 => Self::ChaCha20Poly1305(Box::new(
                ChaCha20Poly1305::new_from_slice(key).expect("derived ChaCha20 key is 32 bytes"),
            )),
        }
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::None => Err(std::io::Error::other("seal called with Security::None")),
            Self::Aes128Gcm(c) => c
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|e| std::io::Error::other(format!("aes-gcm encrypt: {e}"))),
            Self::ChaCha20Poly1305(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|e| std::io::Error::other(format!("chacha encrypt: {e}"))),
        }
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::None => Err(std::io::Error::other("open called with Security::None")),
            Self::Aes128Gcm(c) => c
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| std::io::Error::other(format!("aes-gcm decrypt: {e}"))),
            Self::ChaCha20Poly1305(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| std::io::Error::other(format!("chacha decrypt: {e}"))),
        }
    }
}

/// Build a 16-byte-seed record nonce: `count(2 BE) || iv[2..12]`. The first
/// two IV bytes are discarded (overwritten by the counter), matching mihomo
/// `aead.go` — a scheme that XORs the counter into the full IV only agrees
/// when `iv[0]==iv[1]==0`, so its records fail to authenticate on real servers.
fn record_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

/// Per-connection body cipher state for both directions.
///
/// `*_counter` is one past the last nonce value used. The wire format packs
/// it into a u16, so record `0xFFFF` is the last safe one — a 65537th record
/// would reuse nonce 0 under the same key. Reaching `NONCE_BUDGET` retires
/// the connection (issue #513): the error propagates up the stream and the
/// flow re-dials. mihomo shares this wrap (v2fly `aead.go`), so a >~1 GiB
/// transfer on one connection is a deliberate divergence from upstream.
pub struct BodyCipher {
    write: RecordCipher,
    write_iv: [u8; 16],
    read: RecordCipher,
    read_iv: [u8; 16],
    write_counter: u32,
    read_counter: u32,
}

/// Number of distinct nonces a u16 counter can produce. Mux logical flows
/// share this budget because they share the physical connection's keys.
const NONCE_BUDGET: u32 = 1 << 16;

impl BodyCipher {
    pub fn new(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16], resp_v: u8) -> Self {
        // resp_v gates the response *header* validation (in header.rs), not the
        // body IV; the parameter is kept for call-site signature stability.
        let _ = resp_v;
        let keys = derive_keys(security, req_key, req_iv);

        Self {
            write: RecordCipher::new(security, &keys.write_key),
            write_iv: keys.write_iv,
            read: RecordCipher::new(security, &keys.read_key),
            read_iv: keys.read_iv,
            write_counter: 0,
            read_counter: 0,
        }
    }

    /// Test hook: make the read direction decrypt what the write direction
    /// encrypts (real connections derive read keys from SHA-256 of req material).
    #[cfg(test)]
    fn mirror_write_to_read(&mut self) {
        self.read = self.write.clone();
        self.read_iv = self.write_iv;
        self.read_counter = self.write_counter;
    }

    fn write_nonce(&mut self) -> std::io::Result<[u8; 12]> {
        if self.write_counter >= NONCE_BUDGET {
            return Err(std::io::Error::other(
                "vmess body nonce budget exhausted; retiring connection",
            ));
        }
        let nonce = record_nonce(&self.write_iv, self.write_counter as u16);
        self.write_counter += 1;
        Ok(nonce)
    }

    fn read_nonce(&mut self) -> std::io::Result<[u8; 12]> {
        if self.read_counter >= NONCE_BUDGET {
            return Err(std::io::Error::other(
                "vmess body nonce budget exhausted; retiring connection",
            ));
        }
        let nonce = record_nonce(&self.read_iv, self.read_counter as u16);
        self.read_counter += 1;
        Ok(nonce)
    }

    /// Encrypt and write one body record: [len(2 BE)][ciphertext + tag(16)].
    /// Length includes the tag.
    pub async fn write_record<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        plaintext: &[u8],
    ) -> std::io::Result<()> {
        if matches!(self.write, RecordCipher::None) {
            // OPT_STANDARD advertises chunk streaming even when the security
            // type is none, so the payload still carries the 2-byte size.
            let len = u16::try_from(plaintext.len())
                .map_err(|_| std::io::Error::other("vmess plaintext record too large"))?;
            writer.write_all(&len.to_be_bytes()).await?;
            writer.write_all(plaintext).await?;
            return writer.flush().await;
        }

        let nonce = self.write_nonce()?;
        let ct = self.write.seal(&nonce, plaintext)?;
        let len = ct.len() as u16;
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&ct).await?;
        writer.flush().await
    }

    /// Read and decrypt one body record.
    ///
    /// `Ok(None)` is the clean close: the peer's FIN landed exactly on a
    /// record boundary (zero bytes into the next length prefix), or it sent
    /// the protocol's zero-length terminator record. Every `Err` — a
    /// partial length prefix, a body shorter than the prefix promised,
    /// decrypt failure, nonce-budget exhaustion, transport error — means a
    /// corrupt session and is fatal for the exchange: a truncated AEAD
    /// record must not be mistaken for a half-close (issue #514 review).
    pub async fn read_record<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<Option<Vec<u8>>> {
        // Two-phase length-prefix read: a bare `read` returning 0 is FIN
        // at a record boundary; `read_exact` alone cannot tell that apart
        // from a FIN arriving after part of the prefix already landed
        // (both surface as UnexpectedEof) — and mid-record EOF is fatal.
        let mut len_buf = [0u8; 2];
        match reader.read(&mut len_buf).await {
            Ok(0) => return Ok(None),
            Ok(n) => {
                reader.read_exact(&mut len_buf[n..]).await?;
            }
            Err(e) => return Err(e),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            // Explicit chunk-streaming terminator record.
            return Ok(None);
        }

        if matches!(self.read, RecordCipher::None) {
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            return Ok(Some(buf));
        }

        let mut ct = vec![0u8; len];
        reader.read_exact(&mut ct).await?;
        let nonce = self.read_nonce()?;
        self.read.open(&nonce, &ct).map(Some)
    }

    pub fn max_plaintext() -> usize {
        MAX_PLAINTEXT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> ([u8; 16], [u8; 16]) {
        let req_key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let req_iv = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ];
        (req_key, req_iv)
    }

    async fn body_modes_round_trip_with_protocol_framing() {
        let (req_key, req_iv) = test_keys();
        let plaintext = b"hello vmess body";

        for (security, overhead) in [
            (Security::Aes128Gcm, 16),
            (Security::ChaCha20Poly1305, 16),
            (Security::None, 0),
        ] {
            let mut writer = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            let mut wire = Vec::new();
            writer.write_record(&mut wire, plaintext).await.unwrap();

            let framed_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
            assert_eq!(framed_len, plaintext.len() + overhead);
            assert_eq!(wire.len(), 2 + framed_len);

            let mut reader = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            reader.mirror_write_to_read();
            let mut cursor = std::io::Cursor::new(wire);
            assert_eq!(
                reader.read_record(&mut cursor).await.unwrap().as_deref(),
                Some(plaintext.as_slice())
            );
        }
    }

    fn body_key_derivation_matches_protocol() {
        use sha2::{Digest, Sha256};

        let (req_key, req_iv) = test_keys();
        let aes = derive_keys(Security::Aes128Gcm, &req_key, &req_iv);
        assert_eq!(aes.write_key.as_slice(), &req_key);
        assert_eq!(aes.write_iv, req_iv);
        let bk: [u8; 32] = Sha256::digest(req_key).into();
        let bi: [u8; 32] = Sha256::digest(req_iv).into();
        assert_eq!(aes.read_key.as_slice(), &bk[..16]);
        assert_eq!(&aes.read_iv, &bi[..16]);

        let chacha = derive_keys(Security::ChaCha20Poly1305, &req_key, &req_iv);
        let md5_1: [u8; 16] = Md5::digest(req_key).into();
        let md5_2: [u8; 16] = Md5::digest(md5_1).into();
        assert_eq!(chacha.write_key, [md5_1, md5_2].concat());
    }

    fn record_nonce_overwrites_iv_prefix_and_increments() {
        let iv = [
            0xAA, 0xBB, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        assert_eq!(
            record_nonce(&iv, 0x1234),
            [0x12, 0x34, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        );

        let (req_key, _) = test_keys();
        let mut cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &iv, 0x42);
        assert_eq!(cipher.write_nonce().unwrap()[..2], [0, 0]);
        assert_eq!(cipher.write_nonce().unwrap()[..2], [0, 1]);
    }

    /// Record 0xFFFF is the last safe nonce; the 65537th record must error
    /// (retiring the connection) rather than reuse nonce 0 under the same key.
    /// Both AEAD suites and both directions — mux flows share the physical
    /// connection's BodyCipher, so this is the shared budget too.
    async fn nonce_budget_retires_instead_of_reusing() {
        let (req_key, req_iv) = test_keys();
        for security in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
            // Write direction.
            let mut c = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            c.write_counter = NONCE_BUDGET - 1;
            let mut wire = Vec::new();
            c.write_record(&mut wire, b"last").await.unwrap();
            let err = c
                .write_record(&mut wire, b"one too many")
                .await
                .unwrap_err();
            assert!(err.to_string().contains("nonce budget exhausted"));

            // Read direction: a peer that keeps sending past the budget must
            // be refused, not decrypted under a reused nonce.
            let mut c = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            c.mirror_write_to_read();
            c.read_counter = NONCE_BUDGET - 1;
            c.write_counter = NONCE_BUDGET - 1;
            let mut wire = Vec::new();
            c.write_record(&mut wire, b"last").await.unwrap();
            let mut cursor = std::io::Cursor::new(wire);
            assert_eq!(
                c.read_record(&mut cursor).await.unwrap().as_deref(),
                Some(b"last".as_slice())
            );
            // The next read would need nonce 0 again.
            let mut more = Vec::new();
            let mut c2 = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            c2.write_record(&mut more, b"overflow").await.unwrap();
            let mut cursor = std::io::Cursor::new(more);
            let err = c.read_record(&mut cursor).await.unwrap_err();
            assert!(err.to_string().contains("nonce budget exhausted"));
        }
    }

    /// End-to-end read-direction interop: a hand-rolled "server" encrypts a
    /// response record with the response keys (SHA-256 of req material) and
    /// the client's `read_record` must decrypt it. This fails if the read
    /// derivation or the nonce construction diverges from the wire spec —
    /// unlike the mirror-based round-trip which hides both.
    async fn read_record_decrypts_independently_encoded_response() {
        use aes_gcm::aead::Aead;
        use sha2::{Digest, Sha256};

        let (req_key, req_iv) = test_keys();
        let bk: [u8; 32] = Sha256::digest(req_key).into();
        let bi: [u8; 32] = Sha256::digest(req_iv).into();
        let resp_key: [u8; 16] = bk[..16].try_into().unwrap();
        let resp_iv: [u8; 16] = bi[..16].try_into().unwrap();

        // Server seals record 0 with nonce = count(0) || resp_iv[2..12].
        let plaintext = b"response payload from server";
        let nonce = super::record_nonce(&resp_iv, 0);
        let cipher = Aes128Gcm::new_from_slice(&resp_key).unwrap();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();
        let mut wire = (ct.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(&ct);

        let mut client = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        let mut cursor = std::io::Cursor::new(wire);
        let decrypted = client.read_record(&mut cursor).await.unwrap();
        assert_eq!(decrypted.as_deref(), Some(plaintext.as_slice()));
    }

    /// EOF classification contract: `Ok(None)` only for a FIN exactly at a
    /// record boundary or the zero-length terminator; every mid-record EOF
    /// is an `Err` — the relay treats it as a corrupt session, not a
    /// half-close (issue #514 review).
    async fn read_record_eof_classification() {
        let (req_key, req_iv) = test_keys();

        for security in [
            Security::None,
            Security::Aes128Gcm,
            Security::ChaCha20Poly1305,
        ] {
            // Boundary FIN: stream ends before any byte of the next record.
            let mut c = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            let mut cursor = std::io::Cursor::new(Vec::new());
            assert_eq!(
                c.read_record(&mut cursor).await.unwrap(),
                None,
                "{security:?}: boundary FIN must be Ok(None)"
            );

            // Terminator record: zero length prefix.
            let mut c = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            let mut cursor = std::io::Cursor::new(vec![0x00, 0x00]);
            assert_eq!(
                c.read_record(&mut cursor).await.unwrap(),
                None,
                "{security:?}: terminator record must be Ok(None)"
            );

            // Partial length prefix: one byte of the two arrived, then FIN.
            let mut c = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            let mut cursor = std::io::Cursor::new(vec![0x00]);
            assert!(
                c.read_record(&mut cursor).await.is_err(),
                "{security:?}: half-read length prefix must be fatal"
            );

            // Truncated body: prefix promises 8 bytes, 3 arrive.
            let mut c = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            let mut cursor = std::io::Cursor::new(vec![0x00, 0x08, 1, 2, 3]);
            assert!(
                c.read_record(&mut cursor).await.is_err(),
                "{security:?}: truncated body must be fatal"
            );
        }

        // AEAD tag corruption is fatal too (not an EOF at all).
        let (req_key, req_iv) = test_keys();
        let mut writer = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        let mut wire = Vec::new();
        writer.write_record(&mut wire, b"payload").await.unwrap();
        *wire.last_mut().unwrap() ^= 0xff;
        let mut reader = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        reader.mirror_write_to_read();
        let mut cursor = std::io::Cursor::new(wire);
        assert!(reader.read_record(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn body_wire_format_matches_protocol() {
        body_modes_round_trip_with_protocol_framing().await;
        body_key_derivation_matches_protocol();
        record_nonce_overwrites_iv_prefix_and_increments();
        read_record_decrypts_independently_encoded_response().await;
        read_record_eof_classification().await;
        nonce_budget_retires_instead_of_reusing().await;
    }
}
