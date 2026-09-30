use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(test)]
use super::header::response_body_keys;
use super::header::Security;
use crate::aead::{Aead, TAG_LEN};

/// Maximum plaintext per body record (matching upstream 16 KiB - 16 tag).
const MAX_PLAINTEXT: usize = 16384 - 16;

/// Body keys/IVs derived from the per-connection req_key and req_iv. The IVs
/// are the full 16-byte seeds; each record nonce is `count(2 BE) || iv[2..12]`.
/// Both directions' material at once — test-only; production builds each
/// direction separately (`new_writer`/`from_response_keys`) so no key
/// schedule is paid for twice (issue #533).
#[cfg(test)]
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

#[cfg(test)]
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
enum RecordCipher {
    None,
    /// Direction never constructed — a `BodyCipher` built via
    /// `new_writer`/`new_reader` carries only its own side's key schedule
    /// (issue #533). Distinct from `None` (the plaintext `security: none`
    /// codec): sealing/opening through it is a bug and must error, never
    /// silently emit plaintext records.
    Unbuilt,
    /// AES-128-GCM or ChaCha20-Poly1305, per the negotiated security.
    Aead(Aead),
}

impl RecordCipher {
    fn new(security: Security, key: &[u8]) -> Self {
        match security {
            Security::None => Self::None,
            Security::Aes128Gcm => Self::Aead(Aead::aes_128_gcm(key)),
            Security::ChaCha20Poly1305 => Self::Aead(Aead::chacha20_poly1305(key)),
        }
    }

    /// Encrypt `data` in place, writing the tag to `tag`.
    fn seal(&self, nonce: &[u8; 12], data: &mut [u8], tag: &mut [u8]) -> std::io::Result<()> {
        match self {
            Self::Unbuilt => Err(std::io::Error::other(
                "seal called on an unconstructed cipher direction",
            )),
            Self::None => Err(std::io::Error::other("seal called with Security::None")),
            Self::Aead(c) => c
                .seal_detached(nonce, &[], data, tag)
                .map_err(|_| std::io::Error::other("vmess body: record encrypt failed")),
        }
    }

    /// Verify and strip the trailing tag of `buf`, decrypting the rest in
    /// place.
    fn open(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            Self::Unbuilt => Err(std::io::Error::other(
                "open called on an unconstructed cipher direction",
            )),
            Self::None => Err(std::io::Error::other("open called with Security::None")),
            Self::Aead(c) => c
                .open_trailing(nonce, &[], buf)
                .map_err(|_| std::io::Error::other("vmess body: record authentication failed")),
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

/// Per-connection body cipher state for one direction — the other half is
/// `RecordCipher::Unbuilt` on values built via `new_writer`/`new_reader`/
/// `from_response_keys` (issue #533).
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
    /// Build both directions' key schedules — test-only. Production relays
    /// use [`Self::new_writer`]/[`Self::from_response_keys`]: the two halves
    /// of a spawned relay each touch only their own direction, so a pair of
    /// `new`s pays for two AEAD key schedules that are never used
    /// (issue #533). Composed from the directional constructors so the test
    /// fixture can never drift from production (issue #533 review).
    #[cfg(test)]
    pub(crate) fn new(
        security: Security,
        req_key: &[u8; 16],
        req_iv: &[u8; 16],
        resp_v: u8,
    ) -> Self {
        // resp_v gates the response *header* validation (in header.rs), not the
        // body IV; the parameter is kept for call-site signature stability.
        let _ = resp_v;
        let w = Self::new_writer(security, req_key, req_iv);
        let r = Self::new_reader(security, req_key, req_iv);
        Self {
            write: w.write,
            write_iv: w.write_iv,
            read: r.read,
            read_iv: r.read_iv,
            write_counter: 0,
            read_counter: 0,
        }
    }

    /// Build only the request (write) direction's key schedule — the raw
    /// per-connection `req_key`/`req_iv` directly (there is no
    /// "VMess Body AEAD Key" KDF on the wire). The read half is `Unbuilt` —
    /// `read_record` on this value is a bug and errors rather than emitting
    /// or accepting anything.
    pub fn new_writer(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16]) -> Self {
        Self {
            write: RecordCipher::new(security, &expand_body_key(security, req_key)),
            write_iv: *req_iv,
            read: RecordCipher::Unbuilt,
            read_iv: [0; 16],
            write_counter: 0,
            read_counter: 0,
        }
    }

    /// Build only the response (read) direction's key schedule; the write
    /// half is `Unbuilt`. Takes the request material — the SHA-256 hop to
    /// the response key/IV happens inside. See [`Self::new_writer`].
    ///
    /// `spawn_vmess_relay` calls [`Self::from_response_keys`] instead: it
    /// needs the derived pair for the response header anyway, so one
    /// derivation feeds both (issue #533 review). Test-only — production
    /// never derives the pair without also needing it for the header.
    #[cfg(test)]
    pub fn new_reader(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16]) -> Self {
        let (resp_key, resp_iv) = response_body_keys(req_key, req_iv);
        Self::from_response_keys(security, &resp_key, &resp_iv)
    }

    /// The read-direction constructor for callers that already derived the
    /// response key/IV via [`response_body_keys`] — `spawn_vmess_relay`
    /// shares one derivation between the response header AEAD and the body
    /// reader (issue #533 review).
    pub fn from_response_keys(security: Security, resp_key: &[u8; 16], resp_iv: &[u8; 16]) -> Self {
        Self {
            write: RecordCipher::Unbuilt,
            write_iv: [0; 16],
            read: RecordCipher::new(security, &expand_body_key(security, resp_key)),
            read_iv: *resp_iv,
            write_counter: 0,
            read_counter: 0,
        }
    }

    /// Test hook: [`Self::new`] with its write schedule on the read side
    /// too, so the codec opens what it seals (real connections derive read
    /// keys from SHA-256 of req material).
    #[cfg(test)]
    fn loopback(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16]) -> Self {
        let mut c = Self::new(security, req_key, req_iv, 0);
        c.read = Self::new(security, req_key, req_iv, 0).write;
        c.read_iv = c.write_iv;
        c
    }

    /// Test hook: the server-side mirror of [`Self::new`] — reads
    /// request-keyed records and writes response-keyed ones, i.e. the
    /// client constructor's two directions swapped. Lets duplex tests play
    /// a conformant VMess server without re-deriving keys by hand.
    #[cfg(test)]
    pub(crate) fn server_mirror(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16]) -> Self {
        let mut c = Self::new(security, req_key, req_iv, 0);
        std::mem::swap(&mut c.write, &mut c.read);
        std::mem::swap(&mut c.write_iv, &mut c.read_iv);
        c
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
        if matches!(self.write, RecordCipher::Unbuilt) {
            return Err(std::io::Error::other(
                "vmess body: write direction not built (reader cipher)",
            ));
        }
        if matches!(self.write, RecordCipher::None) {
            // OPT_STANDARD advertises chunk streaming even when the security
            // type is none, so the payload still carries the 2-byte size.
            let len = u16::try_from(plaintext.len())
                .map_err(|_| std::io::Error::other("vmess plaintext record too large"))?;
            writer.write_all(&len.to_be_bytes()).await?;
            writer.write_all(plaintext).await?;
            return writer.flush().await;
        }

        // Seal in place inside the finished frame, so the record leaves in
        // one write rather than a 2-byte length write and a body write.
        let len = u16::try_from(plaintext.len() + TAG_LEN)
            .map_err(|_| std::io::Error::other("vmess body record too large"))?;
        let nonce = self.write_nonce()?;
        let mut frame = Vec::with_capacity(2 + usize::from(len));
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(plaintext);
        frame.resize(2 + usize::from(len), 0);
        let (data, tag) = frame[2..].split_at_mut(plaintext.len());
        self.write.seal(&nonce, data, tag)?;
        writer.write_all(&frame).await?;
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
        // The Unbuilt check must precede the EOF paths too: a wrong-side
        // cipher returning `Ok(None)` would mask a wiring bug as a clean
        // half-close (issue #533 review).
        if matches!(self.read, RecordCipher::Unbuilt) {
            return Err(std::io::Error::other(
                "vmess body: read direction not built (writer cipher)",
            ));
        }
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

        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        let nonce = self.read_nonce()?;
        self.read.open(&nonce, &mut buf)?;
        Ok(Some(buf))
    }

    pub fn max_plaintext() -> usize {
        MAX_PLAINTEXT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // RustCrypto plays the independent peer: it pins the BoringSSL codec
    // to the wire spec rather than to itself.
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
    use chacha20poly1305::ChaCha20Poly1305;

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

    /// Directional constructors (issue #533): each half must derive exactly
    /// the same key schedule and IV as `BodyCipher::new`, and the unbuilt
    /// halves must hard-error rather than emit or accept anything. Each
    /// direction is independently anchored to the wire spec by
    /// `read_record_decrypts_independently_encoded_response` (read) and
    /// `write_record_decrypts_under_independently_derived_request_keys`
    /// (write) — the equivalence legs here are cross-checks, not the anchor.
    async fn directional_ciphers_round_trip_and_unbuilt_halves_error() {
        let (req_key, req_iv) = test_keys();
        let plaintext = b"directional body cipher";

        for security in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
            // new_writer's request-direction ciphertext opens under `new`'s
            // write schedule on the read side — so new_writer's schedule/IV
            // is the same as `new`'s, not merely self-consistent.
            let mut writer = BodyCipher::new_writer(security, &req_key, &req_iv);
            let mut wire = Vec::new();
            writer.write_record(&mut wire, plaintext).await.unwrap();

            let mut dual = BodyCipher::loopback(security, &req_key, &req_iv);
            let mut cursor = std::io::Cursor::new(wire.clone());
            assert_eq!(
                dual.read_record(&mut cursor).await.unwrap().as_deref(),
                Some(plaintext.as_slice())
            );

            // The same wire must NOT open under the response (read) key —
            // the SHA-256 hop genuinely separates the directions.
            let mut reader = BodyCipher::new_reader(security, &req_key, &req_iv);
            let mut cursor = std::io::Cursor::new(wire.clone());
            assert!(
                reader.read_record(&mut cursor).await.is_err(),
                "request-direction record must fail under the response key"
            );

            // Response-direction equivalence: seal with new_reader's read
            // material (moved into write), open with `new`'s real read
            // half — proves new_reader's schedule/IV matches `new`'s.
            let mut resp_writer = BodyCipher::new_reader(security, &req_key, &req_iv);
            resp_writer.write = BodyCipher::new_reader(security, &req_key, &req_iv).read;
            resp_writer.write_iv = resp_writer.read_iv;
            let mut wire2 = Vec::new();
            resp_writer
                .write_record(&mut wire2, plaintext)
                .await
                .unwrap();
            let mut dual2 = BodyCipher::new(security, &req_key, &req_iv, 0x42);
            let mut cursor2 = std::io::Cursor::new(wire2);
            assert_eq!(
                dual2.read_record(&mut cursor2).await.unwrap().as_deref(),
                Some(plaintext.as_slice())
            );

            // Unbuilt halves must error, not emit plaintext records.
            let mut sink = Vec::new();
            assert!(
                reader.write_record(&mut sink, b"x").await.is_err(),
                "new_reader must not be able to write"
            );
            assert!(sink.is_empty());
            let mut cursor = std::io::Cursor::new(wire);
            assert!(
                writer.read_record(&mut cursor).await.is_err(),
                "new_writer must not be able to read"
            );
        }

        // `security: none` (issue #533 review): the built half passes
        // framed plaintext through, and the `Unbuilt` half must still error
        // — it is NOT the `None` plaintext codec.
        let mut writer = BodyCipher::new_writer(Security::None, &req_key, &req_iv);
        let mut wire = Vec::new();
        writer.write_record(&mut wire, plaintext).await.unwrap();
        // [len(2 BE)][plaintext] — framed, but not encrypted.
        let mut reader = BodyCipher::new_reader(Security::None, &req_key, &req_iv);
        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(
            reader.read_record(&mut cursor).await.unwrap().as_deref(),
            Some(plaintext.as_slice())
        );
        let mut sink = Vec::new();
        assert!(reader.write_record(&mut sink, b"x").await.is_err());
        assert!(sink.is_empty());
        let mut empty = std::io::Cursor::new(Vec::new());
        assert!(writer.read_record(&mut empty).await.is_err());
        // The Unbuilt guard precedes the terminator/EOF fast paths too.
        let mut terminator = std::io::Cursor::new(vec![0x00, 0x00]);
        assert!(writer.read_record(&mut terminator).await.is_err());

        // The Unbuilt codec itself fails closed on seal/open — defense in
        // depth behind the read_record/write_record guards.
        assert!(RecordCipher::Unbuilt
            .seal(&[0; 12], &mut [0; 1], &mut [0; TAG_LEN])
            .is_err());
        assert!(RecordCipher::Unbuilt
            .open(&[0; 12], &mut vec![0; TAG_LEN + 1])
            .is_err());
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

            let mut reader = BodyCipher::loopback(security, &req_key, &req_iv);
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
            let mut c = BodyCipher::loopback(security, &req_key, &req_iv);
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
    /// unlike the loopback round-trip which hides both.
    async fn read_record_decrypts_independently_encoded_response() {
        use aes_gcm::aead::Aead;
        use sha2::{Digest, Sha256};

        let (req_key, req_iv) = test_keys();
        let bk: [u8; 32] = Sha256::digest(req_key).into();
        let bi: [u8; 32] = Sha256::digest(req_iv).into();
        let resp_key: [u8; 16] = bk[..16].try_into().unwrap();
        let resp_iv: [u8; 16] = bi[..16].try_into().unwrap();

        // Server seals records 0 and 1 with nonce = count(n) || resp_iv[2..12].
        let plaintext = b"response payload from server";
        let md5_1: [u8; 16] = Md5::digest(resp_key).into();
        let md5_2: [u8; 16] = Md5::digest(md5_1).into();
        let chacha_key = [md5_1, md5_2].concat();
        for security in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
            let mut wire = Vec::new();
            for count in 0..2 {
                let nonce = super::record_nonce(&resp_iv, count);
                let ct = match security {
                    // AES-128-GCM: the raw 16-byte response key.
                    Security::Aes128Gcm => Aes128Gcm::new_from_slice(&resp_key)
                        .unwrap()
                        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref()),
                    // ChaCha20-Poly1305: MD5(key) || MD5(MD5(key)).
                    _ => ChaCha20Poly1305::new_from_slice(&chacha_key)
                        .unwrap()
                        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref()),
                }
                .unwrap();
                wire.extend_from_slice(&(ct.len() as u16).to_be_bytes());
                wire.extend_from_slice(&ct);
            }

            // `new_reader`, not `new`: the production read path must be
            // pinned to the independently derived spec keys.
            let mut client = BodyCipher::new_reader(security, &req_key, &req_iv);
            let mut cursor = std::io::Cursor::new(wire);
            for _ in 0..2 {
                let decrypted = client.read_record(&mut cursor).await.unwrap();
                assert_eq!(decrypted.as_deref(), Some(plaintext.as_slice()));
            }
        }
    }

    /// Write-direction interop, mirroring the read-side test above: emit a
    /// record through `new_writer` and decrypt it in-test with a bare AEAD
    /// keyed by the raw request material per the wire spec. This is the only
    /// check that catches a systematic wrong-key or key/IV-swap bug inside
    /// `new_writer` — every loopback round-trip stays self-consistent
    /// even when both sides are wrong the same way (issue #533 review).
    async fn write_record_decrypts_under_independently_derived_request_keys() {
        use aes_gcm::aead::Aead;

        let (req_key, req_iv) = test_keys();
        let plaintext = b"request payload to server";

        // AES-128-GCM: the raw 16-byte req_key, nonce = count(0) || iv[2..12].
        let mut writer = BodyCipher::new_writer(Security::Aes128Gcm, &req_key, &req_iv);
        let mut wire = Vec::new();
        writer.write_record(&mut wire, plaintext).await.unwrap();
        let len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        assert_eq!(wire.len(), 2 + len);
        let cipher = Aes128Gcm::new_from_slice(&req_key).unwrap();
        let nonce = super::record_nonce(&req_iv, 0);
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce), &wire[2..])
            .unwrap();
        assert_eq!(pt, plaintext);

        // ChaCha20-Poly1305: key = MD5(req_key) || MD5(MD5(req_key)).
        let mut writer = BodyCipher::new_writer(Security::ChaCha20Poly1305, &req_key, &req_iv);
        let mut wire = Vec::new();
        writer.write_record(&mut wire, plaintext).await.unwrap();
        let md5_1: [u8; 16] = Md5::digest(req_key).into();
        let md5_2: [u8; 16] = Md5::digest(md5_1).into();
        let cipher = ChaCha20Poly1305::new_from_slice(&[md5_1, md5_2].concat()).unwrap();
        let nonce = super::record_nonce(&req_iv, 0);
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce), &wire[2..])
            .unwrap();
        assert_eq!(pt, plaintext);
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
        let mut reader = BodyCipher::loopback(Security::Aes128Gcm, &req_key, &req_iv);
        let mut cursor = std::io::Cursor::new(wire);
        assert!(reader.read_record(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn body_wire_format_matches_protocol() {
        directional_ciphers_round_trip_and_unbuilt_halves_error().await;
        body_modes_round_trip_with_protocol_framing().await;
        body_key_derivation_matches_protocol();
        record_nonce_overwrites_iv_prefix_and_increments();
        read_record_decrypts_independently_encoded_response().await;
        write_record_decrypts_under_independently_derived_request_keys().await;
        read_record_eof_classification().await;
        nonce_budget_retires_instead_of_reusing().await;
    }
}
