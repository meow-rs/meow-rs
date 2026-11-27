//! REALITY server-side authentication, handshake and cover relay.
//!
//! The accepted stream reuses the REALITY record implementation with its keys
//! installed in the opposite directions.  This keeps one audited record-layer
//! implementation and gives the inbound the same independent raw-passthrough
//! switches as the outbound.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boring::mlkem::{Algorithm as MlKemAlgorithm, MlKemPublicKey};
use boring::pkey::{Id, PKey, Private};
use boring::sign::Signer;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::reality_hello::{EXT_KEY_SHARE, GROUP_X25519, GROUP_X25519_MLKEM768};
use crate::reality_tls::{
    finished_verify_data, hkdf_sha256, put_u16, put_u24, read_record, read_u24, take, take_u16,
    take_u8, verify_finished, wrap_plain_record_tls13, x25519, x25519_public_from_private,
    ApplicationKeys, CipherSuite, HandshakeKeys, RealityTlsStream, HS_CERTIFICATE,
    HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_SERVER_HELLO,
    TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
    TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
};
use crate::{Result, Stream, TransportError};

const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const TLS13_VERSION: u16 = 0x0304;
const HYBRID_SHARE_LEN: usize = 1184 + 32;

const MAX_AUTHED_STREAM_BYTES: usize = 64 * 1024;
const MAX_AUTHED_STREAM_RECORDS: usize = 32;
const MAX_PLAINTEXT_RECORD: usize = 16 * 1024;
const REALITY_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const COVER_BUFFER: usize = 16 * 1024;
const COVER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const COVER_MAX_LIFETIME: Duration = Duration::from_secs(600);
const COVER_LIMITER_GRANULARITY: Duration = Duration::from_millis(10);
const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

type HmacSha512 = Hmac<Sha512>;

/// REALITY private identity and admission policy.
pub struct RealityServerConfig {
    /// Base64-decoded 32-byte server X25519 private scalar.  Its public key
    /// is the public key distributed to clients.
    pub private_key: [u8; 32],
    /// Base64-decoded short identifiers, already zero-padded to eight bytes.
    pub short_ids: Vec<[u8; 8]>,
    /// Exact destination names the REALITY handshake admits.  A client whose
    /// SNI is absent or outside this set falls through to the cover relay.
    pub server_names: HashSet<String>,
    /// Accepted client timestamp skew.  `None` uses the REALITY default of
    /// 120 seconds; `Some(Duration::ZERO)` disables the check.
    pub max_time_difference: Option<Duration>,
    /// Test clock hook; production uses `None`.  Sub-second precision is
    /// significant to the freshness-window comparison.
    pub now: Option<fn() -> SystemTime>,
}

impl fmt::Debug for RealityServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityServerConfig")
            .field("private_key", &"<redacted>")
            .field("short_ids", &"<redacted>")
            .field("server_names", &self.server_names)
            .field("max_time_difference", &self.max_time_difference)
            .finish_non_exhaustive()
    }
}

/// REALITY acceptor.  It owns no listener and never dials the cover target;
/// the inbound passes an already-connected target stream to [`CoverRelay::relay`].
#[derive(Clone)]
pub struct RealityServer {
    inner: Arc<RealityServerInner>,
}

struct RealityServerInner {
    private_key: [u8; 32],
    short_ids: Vec<[u8; 8]>,
    server_names: HashSet<String>,
    max_time_difference: Duration,
    certificate: RealityCertificate,
    now: fn() -> SystemTime,
    #[cfg(test)]
    corrupt_certificate_verify: bool,
}

/// Result of accepting one TCP stream.
pub enum RealityServerAccept {
    /// Authenticated REALITY client.  The stream is post-handshake and clean.
    Authenticated(Box<dyn Stream>),
    /// Ordinary TLS or unauthenticated REALITY-looking traffic.  Relay the
    /// preserved bytes first, then both directions transparently.
    Cover(CoverRelay),
}

impl fmt::Debug for RealityServerAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated(_) => f.write_str("RealityServerAccept::Authenticated(..)"),
            Self::Cover(_) => f.write_str("RealityServerAccept::Cover(..)"),
        }
    }
}

fn default_now() -> SystemTime {
    SystemTime::now()
}

impl RealityServer {
    pub fn new(config: &RealityServerConfig) -> Result<Self> {
        Self::with_certificate(config, RealityCertificate::generate)
    }

    fn with_certificate(
        config: &RealityServerConfig,
        certificate: impl FnOnce() -> Result<RealityCertificate>,
    ) -> Result<Self> {
        if config.short_ids.is_empty() || config.short_ids.len() > 64 {
            return Err(TransportError::Config(
                "REALITY server requires 1..64 short IDs".into(),
            ));
        }
        if config.server_names.is_empty() || config.server_names.len() > 64 {
            return Err(TransportError::Config(
                "REALITY server requires 1..64 destination server names".into(),
            ));
        }
        for name in &config.server_names {
            if !valid_server_name(name) {
                return Err(TransportError::Config(format!(
                    "REALITY server name is invalid: {name:?}"
                )));
            }
        }
        let max_time_difference = config
            .max_time_difference
            .unwrap_or(Duration::from_secs(120));
        Ok(Self {
            inner: Arc::new(RealityServerInner {
                private_key: config.private_key,
                short_ids: config.short_ids.clone(),
                server_names: config
                    .server_names
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
                max_time_difference,
                certificate: certificate()?,
                now: config.now.unwrap_or(default_now),
                #[cfg(test)]
                corrupt_certificate_verify: false,
            }),
        })
    }

    #[cfg(test)]
    fn new_with_ed25519_private_der(
        config: &RealityServerConfig,
        private_key_der: &[u8],
    ) -> Result<Self> {
        Self::with_certificate(config, || {
            RealityCertificate::from_private_key_der(private_key_der)
        })
    }

    #[cfg(test)]
    fn new_corrupting_certificate_verify(config: &RealityServerConfig) -> Result<Self> {
        let mut server = Self::new(config)?;
        Arc::get_mut(&mut server.inner)
            .expect("fresh REALITY server is unique")
            .corrupt_certificate_verify = true;
        Ok(server)
    }

    /// Read through the complete ClientHello, classify it, and either finish
    /// the REALITY TLS handshake or hand back the preserved wire bytes for a
    /// cover relay.  No response byte is emitted before authentication succeeds.
    pub async fn accept(&self, inner: Box<dyn Stream>) -> Result<RealityServerAccept> {
        tokio::time::timeout(REALITY_ACCEPT_TIMEOUT, self.accept_inner(inner))
            .await
            .map_err(|_| TransportError::Timeout("REALITY accept exceeded 15 seconds".into()))?
    }

    async fn accept_inner(&self, inner: Box<dyn Stream>) -> Result<RealityServerAccept> {
        let (inner, preflight) = read_client_hello_preflight(inner).await?;
        let (hello, wire_prefix) = match preflight {
            Preflight::Cover(wire) => {
                return Ok(RealityServerAccept::Cover(CoverRelay::new(inner, wire)))
            }
            Preflight::Candidate { hello, wire_prefix } => (hello, wire_prefix),
        };

        let Some(prepared) = self.classify(&hello) else {
            return Ok(RealityServerAccept::Cover(CoverRelay::new(
                inner,
                wire_prefix,
            )));
        };
        let stream = self
            .complete_handshake(inner, prepared)
            .await
            .inspect_err(|e| {
                tracing::debug!(error = %redact_error(e), "authenticated REALITY handshake failed");
            })?;
        Ok(RealityServerAccept::Authenticated(stream))
    }

    fn open_auth_plaintext(&self, hello: &ClientHello) -> Option<([u8; 32], Vec<u8>)> {
        let auth_share = hello.auth_share()?;
        let shared = x25519(&self.inner.private_key, &auth_share).ok()?;
        let auth_key: [u8; 32] = hkdf_sha256(&shared, &hello.random[..20], b"REALITY", 32)
            .try_into()
            .expect("REALITY AuthKey length");

        let ciphertext = hello.session_id.get(..16)?;
        let tag = hello.session_id.get(16..32)?;
        let mut aad = hello.raw.clone();
        aad[39..71].fill(0);
        let plaintext = aes_gcm_open(&auth_key, &hello.random[20..32], ciphertext, tag, &aad)?;
        if plaintext.len() != 16 {
            return None;
        }
        Some((auth_key, plaintext))
    }

    fn classify(&self, hello: &ClientHello) -> Option<PreparedHandshake> {
        if !hello.reality_session_id_layout
            || !hello.offers_tls13
            || hello.duplicate_extension
            || hello.sni_malformed
            || hello.key_share_malformed
        {
            return None;
        }
        let server_name = hello.server_name.as_deref()?;
        if !self.inner.server_names.contains(server_name) {
            return None;
        }
        let (auth_key, plaintext) = self.open_auth_plaintext(hello)?;
        let (_version, _reserved, unix_seconds, short_id) = parse_auth_plaintext(&plaintext)?;
        // The wire timestamp is whole Unix seconds, but the comparison
        // happens in the Duration domain: truncating the window to whole
        // seconds would collapse a sub-second window to zero width.
        let client_time = Duration::from_secs(u64::from(unix_seconds));
        if self.inner.max_time_difference != Duration::ZERO {
            let now = (self.inner.now)()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            if now.abs_diff(client_time) > self.inner.max_time_difference {
                return None;
            }
        }
        let mut matched = subtle::Choice::from(0);
        for configured in &self.inner.short_ids {
            matched |= configured.ct_eq(&short_id);
        }
        if !bool::from(matched) {
            return None;
        }

        let cipher = select_cipher(&hello.cipher_suites)?;
        let key_share = select_key_share(hello)?;
        Some(PreparedHandshake {
            raw_hello: hello.raw.clone(),
            session_id: hello.session_id.clone(),
            cipher,
            key_share,
            auth_key,
        })
    }

    async fn complete_handshake(
        &self,
        mut inner: Box<dyn Stream>,
        prepared: PreparedHandshake,
    ) -> Result<Box<dyn Stream>> {
        let hash = prepared.cipher.hash();
        let (server_key_exchange, shared_secret) = encapsulate_server_share(&prepared.key_share)?;
        let server_hello = build_server_hello(
            &prepared.session_id,
            prepared.cipher,
            &prepared.key_share.group,
            &server_key_exchange,
        );

        let mut transcript = prepared.raw_hello.clone();
        transcript.extend_from_slice(&server_hello);
        let mut hs = HandshakeKeys::derive(prepared.cipher, &shared_secret, &transcript);

        // EncryptedExtensions carries a two-byte extension-vector length even
        // when it is empty; a zero-length body is not a legal TLS 1.3 message.
        let ee = handshake_message(HS_ENCRYPTED_EXTENSIONS, &[0, 0]);
        transcript.extend_from_slice(&ee);
        let certificate_der = self.inner.certificate.for_auth_key(&prepared.auth_key);
        let certificate = certificate_message(&certificate_der);
        transcript.extend_from_slice(&certificate);

        let mut cv_body = Vec::with_capacity(2 + 2 + 64);
        put_u16(SIG_ED25519, &mut cv_body);
        put_u16(64, &mut cv_body);
        let signed = certificate_verify_input(&hash.digest(&transcript));
        let signature = self.inner.certificate.sign(&signed)?;
        #[cfg(test)]
        let mut signature = signature;
        #[cfg(test)]
        if self.inner.corrupt_certificate_verify {
            signature[0] ^= 1;
        }
        debug_assert_eq!(signature.len(), 64);
        cv_body.extend_from_slice(&signature);
        let certificate_verify = handshake_message(HS_CERTIFICATE_VERIFY, &cv_body);
        transcript.extend_from_slice(&certificate_verify);

        let finished_body = finished_verify_data(hash, &hs.server_secret, &transcript);
        let finished = handshake_message(HS_FINISHED, &finished_body);
        transcript.extend_from_slice(&finished);

        let mut encrypted_plain = Vec::with_capacity(
            ee.len() + certificate.len() + certificate_verify.len() + finished.len(),
        );
        encrypted_plain.extend_from_slice(&ee);
        encrypted_plain.extend_from_slice(&certificate);
        encrypted_plain.extend_from_slice(&certificate_verify);
        encrypted_plain.extend_from_slice(&finished);
        if encrypted_plain.len() > MAX_PLAINTEXT_RECORD {
            return Err(TransportError::Tls(
                "REALITY server flight exceeds one TLS plaintext record".into(),
            ));
        }
        let mut encrypted = hs.server.seal(TLS_RECORD_HANDSHAKE, &encrypted_plain)?;
        let mut out = wrap_plain_record_tls13(TLS_RECORD_HANDSHAKE, &server_hello)?;
        out.extend_from_slice(&wrap_plain_record_tls13(
            TLS_RECORD_CHANGE_CIPHER_SPEC,
            &[1],
        )?);
        out.append(&mut encrypted);
        inner.write_all(&out).await?;
        inner.flush().await?;

        let client_finished = read_client_finished(&mut inner, &mut hs).await?;
        verify_finished(hash, &hs.client_secret, &transcript, &client_finished)?;
        let app = ApplicationKeys::derive(prepared.cipher, &hs.master_secret, &transcript);
        Ok(Box::new(RealityTlsStream::new(
            inner, app.client, app.server,
        )))
    }
}

fn redact_error(e: &TransportError) -> String {
    match e {
        TransportError::Tls(_) | TransportError::Crypto(_) => "TLS cryptographic failure".into(),
        TransportError::Io(_) => "I/O failure".into(),
        other => other.to_string(),
    }
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.contains('/')
        && !name.chars().any(char::is_whitespace)
}

const SIG_ED25519: u16 = 0x0807;

fn parse_auth_plaintext(plaintext: &[u8]) -> Option<([u8; 3], u8, u32, [u8; 8])> {
    if plaintext.len() != 16 {
        return None;
    }
    Some((
        plaintext[0..3].try_into().ok()?,
        plaintext[3],
        u32::from_be_bytes(plaintext[4..8].try_into().ok()?),
        plaintext[8..16].try_into().ok()?,
    ))
}

fn certificate_verify_input(transcript_hash: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(64 + 33 + 1 + transcript_hash.len());
    signed.extend_from_slice(&[0x20; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0);
    signed.extend_from_slice(transcript_hash);
    signed
}

enum Preflight {
    Candidate {
        hello: ClientHello,
        wire_prefix: Vec<u8>,
    },
    Cover(Vec<u8>),
}

async fn read_client_hello_preflight(
    mut inner: Box<dyn Stream>,
) -> Result<(Box<dyn Stream>, Preflight)> {
    let mut wire_prefix = Vec::new();
    let mut handshake_bytes = Vec::new();
    for _ in 0..MAX_AUTHED_STREAM_RECORDS {
        let mut header = [0u8; 5];
        let remaining_budget = MAX_AUTHED_STREAM_BYTES - wire_prefix.len();
        if remaining_budget < header.len() {
            // A full header no longer fits.  Only the first byte beyond the
            // remaining budget is decisive, though: EOF exactly at the cap is
            // still the historical I/O boundary rather than a resource error.
            let needed = remaining_budget + 1;
            let mut pos = 0;
            while pos < needed {
                match inner.read(&mut header[pos..needed]).await {
                    Ok(0) => {
                        return Err(TransportError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "early eof",
                        )));
                    }
                    Ok(n) => {
                        pos += n;
                        if wire_prefix.len() + pos > MAX_AUTHED_STREAM_BYTES {
                            return Err(TransportError::ResourceLimit(
                                "REALITY ClientHello pre-read exceeds 64 KiB".into(),
                            ));
                        }
                    }
                    Err(e) => return Err(TransportError::Io(e)),
                }
            }
        }
        match inner.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) => return Err(TransportError::Io(e)),
        }
        wire_prefix.extend_from_slice(&header);
        // Match the pinned TLS server's first-record screen before trusting
        // the length: only a handshake record with a plausible TLS version
        // can carry a ClientHello.  Anything else is cover traffic after
        // exactly the bytes already consumed, regardless of the declared
        // body length.
        let record_version = u16::from_be_bytes([header[1], header[2]]);
        if header[0] != TLS_RECORD_HANDSHAKE || record_version >= 0x1000 {
            return Ok((inner, Preflight::Cover(wire_prefix)));
        }
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > MAX_PLAINTEXT_RECORD || len == 0 {
            return Err(TransportError::ResourceLimit(
                "REALITY ClientHello pre-read record length out of range".into(),
            ));
        }
        // The cap counts complete wire bytes — record headers included.
        // `wire_prefix` already holds this record's header, so
        // `wire_prefix.len() + len` is the exact total once the payload
        // lands; the spec bound is 64 KiB of wire in at most 32 records.
        if wire_prefix.len() + len > MAX_AUTHED_STREAM_BYTES {
            return Err(TransportError::ResourceLimit(
                "REALITY ClientHello pre-read exceeds 64 KiB".into(),
            ));
        }
        let mut payload = vec![0u8; len];
        if let Err(e) = inner.read_exact(&mut payload).await {
            return Err(TransportError::Io(e));
        }
        wire_prefix.extend_from_slice(&payload);
        handshake_bytes.extend_from_slice(&payload);
        if handshake_bytes.len() >= 4 {
            if handshake_bytes[0] != HS_CLIENT_HELLO {
                return Ok((inner, Preflight::Cover(wire_prefix)));
            }
            let message_len = read_u24(&handshake_bytes[1..4]);
            let total = 4usize.saturating_add(message_len);
            if total > MAX_AUTHED_STREAM_BYTES {
                return Err(TransportError::ResourceLimit(
                    "REALITY ClientHello exceeds 64 KiB".into(),
                ));
            }
            if handshake_bytes.len() == total {
                let raw = handshake_bytes[..total].to_vec();
                return match parse_client_hello(raw) {
                    Ok(hello) => Ok((inner, Preflight::Candidate { hello, wire_prefix })),
                    Err(_) => Ok((inner, Preflight::Cover(wire_prefix))),
                };
            }
            if handshake_bytes.len() > total {
                return Ok((inner, Preflight::Cover(wire_prefix)));
            }
        }
    }
    Err(TransportError::ResourceLimit(
        "REALITY ClientHello pre-read exceeded 32 records".into(),
    ))
}

struct ClientHello {
    raw: Vec<u8>,
    random: [u8; 32],
    session_id: Vec<u8>,
    server_name: Option<String>,
    cipher_suites: Vec<u16>,
    supported_groups: Vec<u16>,
    key_shares: Vec<KeyShareEntry>,
    offers_tls13: bool,
    reality_session_id_layout: bool,
    duplicate_extension: bool,
    sni_malformed: bool,
    key_share_malformed: bool,
}

struct KeyShareEntry {
    group: u16,
    bytes: Vec<u8>,
}

impl ClientHello {
    fn auth_share(&self) -> Option<[u8; 32]> {
        for entry in &self.key_shares {
            if entry.group == GROUP_X25519 && entry.bytes.len() == 32 {
                return entry.bytes.as_slice().try_into().ok();
            }
        }
        for entry in &self.key_shares {
            if entry.group == GROUP_X25519_MLKEM768 && entry.bytes.len() == HYBRID_SHARE_LEN {
                return entry.bytes[HYBRID_SHARE_LEN - 32..].try_into().ok();
            }
        }
        None
    }
}

fn parse_client_hello(raw: Vec<u8>) -> Result<ClientHello> {
    if raw.len() < 4 + 2 + 32 || raw[0] != HS_CLIENT_HELLO || read_u24(&raw[1..4]) + 4 != raw.len()
    {
        return Err(TransportError::Tls("malformed REALITY ClientHello".into()));
    }
    if raw.len() < 77 || raw[38] != 0x20 {
        return Err(TransportError::Tls("malformed REALITY session id".into()));
    }
    let mut pos = 4;
    if take(&raw, &mut pos, 2)? != [0x03, 0x03] {
        return Err(TransportError::Tls(
            "REALITY ClientHello legacy version".into(),
        ));
    }
    let random: [u8; 32] = take(&raw, &mut pos, 32)?.try_into().expect("32 bytes");
    let sid_len = take_u8(&raw, &mut pos)? as usize;
    let session_id = take(&raw, &mut pos, sid_len)?.to_vec();
    let suites_len = take_u16(&raw, &mut pos)? as usize;
    if !suites_len.is_multiple_of(2) {
        return Err(TransportError::Tls("malformed cipher suites".into()));
    }
    let suites_bytes = take(&raw, &mut pos, suites_len)?;
    let cipher_suites = suites_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_be_bytes(*b))
        .collect();
    let compression_len = take_u8(&raw, &mut pos)? as usize;
    let compression = take(&raw, &mut pos, compression_len)?;
    // RFC 8446 §4.1.2: a TLS 1.3 ClientHello carries exactly one
    // compression method, zero.  Anything else is not a REALITY client
    // shape — browsers and both pinned clients all send exactly `[0]`.
    if compression != [0] {
        return Err(TransportError::Tls(
            "REALITY ClientHello compression methods are not exactly [0]".into(),
        ));
    }
    let extensions_len = take_u16(&raw, &mut pos)? as usize;
    let extensions = take(&raw, &mut pos, extensions_len)?.to_vec();
    if pos != raw.len() {
        return Err(TransportError::Tls(
            "REALITY ClientHello trailing bytes".into(),
        ));
    }

    let mut out = ClientHello {
        raw,
        random,
        session_id,
        server_name: None,
        cipher_suites,
        supported_groups: Vec::new(),
        key_shares: Vec::new(),
        offers_tls13: false,
        reality_session_id_layout: sid_len == 32,
        duplicate_extension: false,
        sni_malformed: false,
        key_share_malformed: false,
    };
    let mut ep = 0;
    let mut seen = HashSet::new();
    while ep < extensions.len() {
        let ext_type = take_u16(&extensions, &mut ep)?;
        let ext_len = take_u16(&extensions, &mut ep)? as usize;
        let data = take(&extensions, &mut ep, ext_len)?;
        if !seen.insert(ext_type) {
            out.duplicate_extension = true;
        }
        match ext_type {
            EXT_SERVER_NAME => parse_server_name(data, &mut out),
            EXT_SUPPORTED_VERSIONS => {
                if data.is_empty()
                    || data[0] as usize + 1 != data.len()
                    || !data[0].is_multiple_of(2)
                {
                    return Err(TransportError::Tls("malformed supported_versions".into()));
                }
                out.offers_tls13 = data[1..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|b| u16::from_be_bytes(*b) == TLS13_VERSION);
            }
            EXT_SUPPORTED_GROUPS => {
                if data.len() < 2 {
                    return Err(TransportError::Tls("malformed supported_groups".into()));
                }
                let len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if len + 2 != data.len() || !len.is_multiple_of(2) {
                    return Err(TransportError::Tls("malformed supported_groups".into()));
                }
                out.supported_groups = data[2..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_be_bytes(*b))
                    .collect();
            }
            EXT_KEY_SHARE => parse_key_share(data, &mut out),
            _ => {}
        }
    }
    if ep != extensions.len() {
        return Err(TransportError::Tls(
            "REALITY extension block truncated".into(),
        ));
    }
    Ok(out)
}

fn parse_server_name(data: &[u8], out: &mut ClientHello) {
    let mut pos = 0;
    let Ok(list_len) = take_u16(data, &mut pos) else {
        out.sni_malformed = true;
        return;
    };
    let Ok(list) = take(data, &mut pos, list_len as usize) else {
        out.sni_malformed = true;
        return;
    };
    if pos != data.len() || list.len() < 3 {
        out.sni_malformed = true;
        return;
    }
    let mut lp = 0;
    while lp < list.len() {
        let Ok(kind) = take_u8(list, &mut lp) else {
            out.sni_malformed = true;
            return;
        };
        let Ok(len) = take_u16(list, &mut lp) else {
            out.sni_malformed = true;
            return;
        };
        let Ok(name) = take(list, &mut lp, len as usize) else {
            out.sni_malformed = true;
            return;
        };
        if kind != 0 || name.is_empty() {
            out.sni_malformed = true;
            return;
        }
        let Ok(name) = std::str::from_utf8(name) else {
            out.sni_malformed = true;
            return;
        };
        if out.server_name.is_some() {
            out.sni_malformed = true;
            return;
        }
        out.server_name = Some(name.to_ascii_lowercase());
    }
    if lp != list.len() {
        out.sni_malformed = true;
    }
}

fn parse_key_share(data: &[u8], out: &mut ClientHello) {
    let mut pos = 0;
    let Ok(list_len) = take_u16(data, &mut pos) else {
        out.key_share_malformed = true;
        return;
    };
    let Ok(list) = take(data, &mut pos, list_len as usize) else {
        out.key_share_malformed = true;
        return;
    };
    if pos != data.len() {
        out.key_share_malformed = true;
        return;
    }
    let mut lp = 0;
    let mut seen = HashSet::new();
    while lp < list.len() {
        let Ok(group) = take_u16(list, &mut lp) else {
            out.key_share_malformed = true;
            return;
        };
        let Ok(len) = take_u16(list, &mut lp) else {
            out.key_share_malformed = true;
            return;
        };
        let Ok(bytes) = take(list, &mut lp, len as usize) else {
            out.key_share_malformed = true;
            return;
        };
        if !seen.insert(group) {
            out.key_share_malformed = true;
        }
        out.key_shares.push(KeyShareEntry {
            group,
            bytes: bytes.to_vec(),
        });
    }
    if lp != list.len() {
        out.key_share_malformed = true;
    }
}

fn select_cipher(offered: &[u16]) -> Option<CipherSuite> {
    for suite in [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ] {
        if offered.contains(&suite) {
            return CipherSuite::try_from(suite).ok();
        }
    }
    None
}

struct PreparedHandshake {
    raw_hello: Vec<u8>,
    session_id: Vec<u8>,
    cipher: CipherSuite,
    key_share: ChosenKeyShare,
    auth_key: [u8; 32],
}

struct ChosenKeyShare {
    group: u16,
    client_share: Vec<u8>,
}

fn x25519_public_key_usable(bytes: &[u8]) -> bool {
    let Ok(public) = <[u8; 32]>::try_from(bytes) else {
        return false;
    };
    // Already-clamped form of scalar 9.  A fixed nonzero scalar is enough
    // for contributory validation: low-order inputs are precisely the ones
    // whose X25519 result is zero and therefore unusable for the handshake.
    let mut probe_private = [0u8; 32];
    probe_private[0] = 8;
    probe_private[31] = 64;
    x25519(&probe_private, &public).is_ok()
}

fn hybrid_key_share_usable(bytes: &[u8]) -> bool {
    if bytes.len() != HYBRID_SHARE_LEN {
        return false;
    }
    let (mlkem_public, x25519_public) = bytes.split_at(HYBRID_SHARE_LEN - 32);
    MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, mlkem_public).is_ok()
        && x25519_public_key_usable(x25519_public)
}

fn select_key_share(hello: &ClientHello) -> Option<ChosenKeyShare> {
    fn group_allowed(hello: &ClientHello, group: u16) -> bool {
        hello.supported_groups.is_empty() || hello.supported_groups.contains(&group)
    }
    if group_allowed(hello, GROUP_X25519_MLKEM768) {
        if let Some(entry) = hello.key_shares.iter().find(|entry| {
            entry.group == GROUP_X25519_MLKEM768 && hybrid_key_share_usable(&entry.bytes)
        }) {
            return Some(ChosenKeyShare {
                group: GROUP_X25519_MLKEM768,
                client_share: entry.bytes.clone(),
            });
        }
    }
    if group_allowed(hello, GROUP_X25519) {
        if let Some(entry) = hello
            .key_shares
            .iter()
            .find(|entry| entry.group == GROUP_X25519 && x25519_public_key_usable(&entry.bytes))
        {
            return Some(ChosenKeyShare {
                group: GROUP_X25519,
                client_share: entry.bytes.clone(),
            });
        }
    }
    None
}

fn encapsulate_server_share(chosen: &ChosenKeyShare) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut x_private = rand::random::<[u8; 32]>();
    crate::reality_tls::clamp_x25519_private(&mut x_private);
    let x_public = x25519_public_from_private(&x_private);
    if chosen.group == GROUP_X25519 {
        let client: [u8; 32] = chosen
            .client_share
            .as_slice()
            .try_into()
            .map_err(|_| TransportError::Tls("REALITY X25519 key share length".into()))?;
        return Ok((x_public.to_vec(), x25519(&x_private, &client)?.to_vec()));
    }
    if chosen.group != GROUP_X25519_MLKEM768 || chosen.client_share.len() != HYBRID_SHARE_LEN {
        return Err(TransportError::Tls("unsupported REALITY key share".into()));
    }
    let mlkem_public_bytes = &chosen.client_share[..HYBRID_SHARE_LEN - 32];
    let client_x: [u8; 32] = chosen.client_share[HYBRID_SHARE_LEN - 32..]
        .try_into()
        .expect("32-byte suffix");
    let mlkem_public = MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, mlkem_public_bytes)
        .map_err(|e| TransportError::Crypto(format!("REALITY ML-KEM client share: {e}")))?;
    let (ciphertext, mlkem_secret) = mlkem_public
        .encapsulate()
        .map_err(|e| TransportError::Crypto(format!("REALITY ML-KEM encapsulation: {e}")))?;
    if ciphertext.len() != 1088 {
        return Err(TransportError::Crypto(
            "REALITY ML-KEM ciphertext length".into(),
        ));
    }
    let x_secret = x25519(&x_private, &client_x)?;
    let mut server_share = Vec::with_capacity(1088 + 32);
    server_share.extend_from_slice(&ciphertext);
    server_share.extend_from_slice(&x_public);
    let mut shared = Vec::with_capacity(64);
    shared.extend_from_slice(&mlkem_secret);
    shared.extend_from_slice(&x_secret);
    Ok((server_share, shared))
}

fn build_server_hello(
    session_id: &[u8],
    cipher: CipherSuite,
    group: &u16,
    share: &[u8],
) -> Vec<u8> {
    let random = rand::random::<[u8; 32]>();
    let cipher_value = match cipher {
        CipherSuite::Aes128GcmSha256 => TLS_AES_128_GCM_SHA256,
        CipherSuite::Aes256GcmSha384 => TLS_AES_256_GCM_SHA384,
        CipherSuite::ChaCha20Poly1305Sha256 => TLS_CHACHA20_POLY1305_SHA256,
    };

    let mut supported_versions_ext = Vec::new();
    put_u16(TLS13_VERSION, &mut supported_versions_ext);
    let mut key_share_ext = Vec::new();
    put_u16(*group, &mut key_share_ext);
    put_u16(share.len() as u16, &mut key_share_ext);
    key_share_ext.extend_from_slice(share);

    let mut extensions = Vec::new();
    put_u16(EXT_SUPPORTED_VERSIONS, &mut extensions);
    put_u16(supported_versions_ext.len() as u16, &mut extensions);
    extensions.extend_from_slice(&supported_versions_ext);
    put_u16(EXT_KEY_SHARE, &mut extensions);
    put_u16(key_share_ext.len() as u16, &mut extensions);
    extensions.extend_from_slice(&key_share_ext);

    let mut body = Vec::with_capacity(2 + 32 + 1 + session_id.len() + 2 + 1 + 2 + extensions.len());
    put_u16(0x0303, &mut body);
    body.extend_from_slice(&random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    put_u16(cipher_value, &mut body);
    body.push(0);
    put_u16(extensions.len() as u16, &mut body);
    body.extend_from_slice(&extensions);
    handshake_message(HS_SERVER_HELLO, &body)
}

fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(kind);
    put_u24(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn certificate_message(certificate_der: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(3 + certificate_der.len() + 2);
    put_u24(certificate_der.len(), &mut entry);
    entry.extend_from_slice(certificate_der);
    put_u16(0, &mut entry);
    let mut list = Vec::with_capacity(3 + entry.len());
    put_u24(entry.len(), &mut list);
    list.extend_from_slice(&entry);
    let mut body = Vec::with_capacity(1 + list.len());
    body.push(0);
    body.extend_from_slice(&list);
    handshake_message(HS_CERTIFICATE, &body)
}

async fn read_client_finished(
    inner: &mut Box<dyn Stream>,
    hs: &mut HandshakeKeys,
) -> Result<Vec<u8>> {
    let mut handshake_bytes = Vec::new();
    for _ in 0..MAX_AUTHED_STREAM_RECORDS {
        let Some(record) = read_record(inner).await? else {
            return Err(TransportError::Tls(
                "EOF before REALITY client Finished".into(),
            ));
        };
        if record.typ == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record.typ != TLS_RECORD_APPLICATION_DATA {
            return Err(TransportError::Tls(format!(
                "REALITY client Finished record type {}",
                record.typ
            )));
        }
        let mut payload = record.payload;
        let (inner_type, len) = hs.client.open_in_place(&record.header, &mut payload)?;
        payload.truncate(len);
        if inner_type != TLS_RECORD_HANDSHAKE {
            return Err(TransportError::Tls(format!(
                "REALITY pre-Finished inner record type {inner_type}"
            )));
        }
        handshake_bytes.extend_from_slice(&payload);
        if handshake_bytes.len() >= 4 {
            if handshake_bytes[0] != HS_FINISHED {
                return Err(TransportError::Tls(format!(
                    "REALITY expected client Finished, got handshake {}",
                    handshake_bytes[0]
                )));
            }
            let total = 4 + read_u24(&handshake_bytes[1..4]);
            if total > MAX_AUTHED_STREAM_BYTES {
                return Err(TransportError::ResourceLimit(
                    "REALITY client Finished exceeds 64 KiB".into(),
                ));
            }
            if handshake_bytes.len() > total {
                return Err(TransportError::Tls(
                    "REALITY unexpected bytes after client Finished".into(),
                ));
            }
            if handshake_bytes.len() == total {
                return Ok(handshake_bytes[4..].to_vec());
            }
        }
    }
    Err(TransportError::ResourceLimit(
        "REALITY client Finished exceeded record limit".into(),
    ))
}

fn aes_gcm_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    if key.len() != 32 || nonce.len() != 12 || ciphertext.len() != 16 || tag.len() != 16 {
        return None;
    }
    let ctx = boring::aead::AeadCtx::new_default_tag(&boring::aead::Algorithm::aes_256_gcm(), key)
        .ok()?;
    let mut data = ciphertext.to_vec();
    let mut tag_buf = [0u8; 16];
    tag_buf.copy_from_slice(tag);
    let mut nonce_buf = [0u8; 12];
    nonce_buf.copy_from_slice(nonce);
    ctx.open_in_place(&nonce_buf, &mut data, &tag_buf, aad)
        .ok()?;
    Some(data)
}

struct RealityCertificate {
    key: PKey<Private>,
    template_der: Vec<u8>,
}

impl RealityCertificate {
    fn generate() -> Result<Self> {
        let key = PKey::generate(Id::ED25519)
            .map_err(|e| TransportError::Crypto(format!("REALITY Ed25519 identity: {e}")))?;
        Self::from_key(key)
    }

    #[cfg(test)]
    fn from_private_key_der(private_key_der: &[u8]) -> Result<Self> {
        let key = PKey::private_key_from_der(private_key_der)
            .map_err(|e| TransportError::Crypto(format!("REALITY Ed25519 test identity: {e}")))?;
        if key.id() != Id::ED25519 {
            return Err(TransportError::Crypto(
                "REALITY test identity is not Ed25519".into(),
            ));
        }
        Self::from_key(key)
    }

    fn from_key(key: PKey<Private>) -> Result<Self> {
        let mut public_key = [0u8; 32];
        let key_len = key
            .raw_public_key(&mut public_key)
            .map_err(|e| TransportError::Crypto(format!("REALITY Ed25519 public key: {e}")))?
            .len();
        if key_len != 32 {
            return Err(TransportError::Crypto(
                "REALITY Ed25519 public key length".into(),
            ));
        }
        let template_der = build_certificate_template(&public_key);
        Ok(Self { key, template_der })
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut signer = Signer::new_without_digest(&self.key).map_err(|e| {
            TransportError::Crypto(format!("REALITY CertificateVerify signer: {e}"))
        })?;
        signer
            .sign_oneshot_to_vec(message)
            .map_err(|e| TransportError::Crypto(format!("REALITY CertificateVerify sign: {e}")))
    }

    fn for_auth_key(&self, auth_key: &[u8; 32]) -> Vec<u8> {
        let mut der = self.template_der.clone();
        let signature_start = der.len() - 64;
        let mut mac =
            <HmacSha512 as Mac>::new_from_slice(auth_key).expect("HMAC accepts any key length");
        let mut public_key = [0u8; 32];
        let public_key = self
            .key
            .raw_public_key(&mut public_key)
            .expect("Ed25519 public key");
        mac.update(public_key);
        let signature = mac.finalize().into_bytes();
        der[signature_start..].copy_from_slice(&signature);
        der
    }
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        put_u16(len as u16, out);
    }
}

fn der_wrap(tag: u8, body: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    der_len(body.len(), out);
    out.extend_from_slice(body);
}

fn build_certificate_template(public_key: &[u8; 32]) -> Vec<u8> {
    let serial = [0x02, 0x01, 0x01];
    let mut algorithm = Vec::new();
    algorithm.extend_from_slice(ED25519_OID);
    let mut algorithm_seq = Vec::new();
    der_wrap(0x30, &algorithm, &mut algorithm_seq);

    let mut issuer = Vec::new();
    der_wrap(0x30, &[], &mut issuer);

    let mut validity_inner = Vec::new();
    der_wrap(0x17, b"250101000000Z", &mut validity_inner);
    der_wrap(0x17, b"490101000000Z", &mut validity_inner);
    let mut validity = Vec::new();
    der_wrap(0x30, &validity_inner, &mut validity);

    let mut spki_alg = Vec::new();
    spki_alg.extend_from_slice(ED25519_OID);
    let mut spki_alg_seq = Vec::new();
    der_wrap(0x30, &spki_alg, &mut spki_alg_seq);
    let mut bitstring_body = vec![0];
    bitstring_body.extend_from_slice(public_key);
    let mut bitstring = Vec::new();
    der_wrap(0x03, &bitstring_body, &mut bitstring);
    let mut spki_inner = Vec::new();
    spki_inner.extend_from_slice(&spki_alg_seq);
    spki_inner.extend_from_slice(&bitstring);
    let mut spki = Vec::new();
    der_wrap(0x30, &spki_inner, &mut spki);

    let mut version_explicit_inner = Vec::new();
    der_wrap(0x02, &[2], &mut version_explicit_inner);
    let mut version_explicit = Vec::new();
    der_wrap(0xa0, &version_explicit_inner, &mut version_explicit);

    let mut tbs_inner = Vec::new();
    tbs_inner.extend_from_slice(&version_explicit);
    tbs_inner.extend_from_slice(&serial);
    tbs_inner.extend_from_slice(&algorithm_seq);
    tbs_inner.extend_from_slice(&issuer);
    tbs_inner.extend_from_slice(&validity);
    tbs_inner.extend_from_slice(&issuer);
    tbs_inner.extend_from_slice(&spki);
    let mut tbs = Vec::new();
    der_wrap(0x30, &tbs_inner, &mut tbs);

    let mut sig_bits_body = vec![0];
    sig_bits_body.extend_from_slice(&[0u8; 64]);
    let mut sig_bits = Vec::new();
    der_wrap(0x03, &sig_bits_body, &mut sig_bits);

    let mut cert_inner = Vec::new();
    cert_inner.extend_from_slice(&tbs);
    cert_inner.extend_from_slice(&algorithm_seq);
    cert_inner.extend_from_slice(&sig_bits);
    let mut cert = Vec::new();
    der_wrap(0x30, &cert_inner, &mut cert);
    cert
}

/// Directional cover bandwidth policy.  Rates are bytes/second after the
/// configured exemption; zero disables bandwidth shaping for that direction.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoverBandwidthLimit {
    pub upload_bytes_per_second: u64,
    pub upload_exempt_bytes: u64,
    pub download_bytes_per_second: u64,
    pub download_exempt_bytes: u64,
    pub burst_bytes: u64,
}

/// A cover connection with the ClientHello bytes already consumed from the
/// client.  Those bytes must reach the target unchanged before any relay.
pub struct CoverRelay {
    client: Box<dyn Stream>,
    wire_prefix: Vec<u8>,
}

impl fmt::Debug for CoverRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoverRelay")
            .field("wire_prefix_len", &self.wire_prefix.len())
            .finish_non_exhaustive()
    }
}

impl CoverRelay {
    fn new(client: Box<dyn Stream>, wire_prefix: Vec<u8>) -> Self {
        Self {
            client,
            wire_prefix,
        }
    }

    pub fn wire_prefix_len(&self) -> usize {
        self.wire_prefix.len()
    }

    pub fn into_parts(self) -> (Box<dyn Stream>, Vec<u8>) {
        (self.client, self.wire_prefix)
    }

    pub async fn relay(self, target: Box<dyn Stream>) -> Result<()> {
        self.relay_with_limit(target, CoverBandwidthLimit::default())
            .await
    }

    pub async fn relay_with_limit(
        self,
        target: Box<dyn Stream>,
        limit: CoverBandwidthLimit,
    ) -> Result<()> {
        let (client, prefix) = self.into_parts();
        let (client_read, client_write) = tokio::io::split(client);
        let (target_read, target_write) = tokio::io::split(target);
        let (activity_tx, activity_rx) = tokio::sync::watch::channel(());
        let upload_limit = DirectionalLimit::new(
            limit.upload_bytes_per_second,
            limit.upload_exempt_bytes,
            limit.burst_bytes,
        );
        let download_limit = DirectionalLimit::new(
            limit.download_bytes_per_second,
            limit.download_exempt_bytes,
            limit.burst_bytes,
        );
        let upload = relay_direction(
            client_read,
            target_write,
            prefix,
            upload_limit,
            activity_tx.clone(),
        );
        let download = relay_direction(
            target_read,
            client_write,
            Vec::new(),
            download_limit,
            activity_tx,
        );
        let watchdog = idle_watchdog(activity_rx);
        let main = drive_cover(upload, download, watchdog);
        tokio::time::timeout(COVER_MAX_LIFETIME, main)
            .await
            .map_err(|_| TransportError::Timeout("REALITY cover relay lifetime exceeded".into()))?
    }
}

async fn drive_cover<U, D, W>(upload: U, download: D, watchdog: W) -> Result<()>
where
    U: std::future::Future<Output = Result<()>>,
    D: std::future::Future<Output = Result<()>>,
    W: std::future::Future<Output = Result<()>>,
{
    tokio::pin!(upload, download, watchdog);
    let mut upload_done = false;
    let mut download_done = false;
    loop {
        if upload_done && download_done {
            return Ok(());
        }
        tokio::select! {
            r = &mut upload, if !upload_done => {
                r?;
                upload_done = true;
            }
            r = &mut download, if !download_done => {
                r?;
                download_done = true;
            }
            r = &mut watchdog => {
                return r;
            }
        }
    }
}

async fn idle_watchdog(mut rx: tokio::sync::watch::Receiver<()>) -> Result<()> {
    loop {
        if tokio::time::timeout(COVER_IDLE_TIMEOUT, rx.changed())
            .await
            .is_err()
        {
            return Err(TransportError::Timeout(
                "REALITY cover relay idle timeout".into(),
            ));
        }
    }
}

struct DirectionalLimit {
    bytes_per_second: u64,
    exempt_bytes: u64,
    capacity: u64,
    tokens: u64,
    transferred: u64,
    refill_at: Instant,
}

impl DirectionalLimit {
    fn new(bytes_per_second: u64, exempt_bytes: u64, burst_bytes: u64) -> Self {
        let capacity = if bytes_per_second == 0 {
            0
        } else {
            burst_bytes.max(bytes_per_second).max(1)
        };
        Self {
            bytes_per_second,
            exempt_bytes,
            capacity,
            tokens: capacity,
            transferred: 0,
            refill_at: Instant::now(),
        }
    }

    async fn wait_for_allowance(&mut self, bytes: usize) -> usize {
        if self.bytes_per_second == 0 {
            return bytes;
        }
        let mut remaining = bytes as u64;
        let mut granted = 0u64;
        if self.transferred < self.exempt_bytes {
            let exempt = remaining.min(self.exempt_bytes - self.transferred);
            self.transferred += exempt;
            remaining -= exempt;
            granted += exempt;
        }
        if remaining == 0 {
            return granted as usize;
        }
        loop {
            self.refill();
            if self.tokens > 0 {
                let limited = remaining.min(self.tokens);
                self.tokens -= limited;
                self.transferred = self.transferred.saturating_add(limited);
                granted += limited;
                return granted as usize;
            }
            if granted > 0 {
                return granted as usize;
            }
            let nanos_per_byte = 1_000_000_000u64.div_ceil(self.bytes_per_second.max(1));
            tokio::time::sleep(Duration::from_nanos(nanos_per_byte).max(COVER_LIMITER_GRANULARITY))
                .await;
        }
    }

    fn refill(&mut self) {
        const NANOS_PER_SECOND: u128 = 1_000_000_000;
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.refill_at);
        if elapsed.is_zero() {
            return;
        }
        if self.tokens >= self.capacity {
            // While the bucket is full every further token is discarded,
            // so the uncredited time is semantically a no-op; pinning the
            // baseline keeps it from going stale over a long idle.
            self.refill_at = now;
            return;
        }
        // Nanoseconds times a byte rate overflows u64 within minutes at
        // high rates, and even the u128 product can saturate for absurd
        // idle×rate combinations.  The credit is only ever meaningful up
        // to the room left in the bucket, so clamping the u128 value
        // before the u64 conversion — instead of truncating it with
        // `as` — loses nothing (issue #974).
        let earned = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.bytes_per_second))
            / NANOS_PER_SECOND;
        if earned == 0 {
            if elapsed.as_secs() >= 1 {
                self.refill_at = now;
            }
            return;
        }
        let room = u128::from(self.capacity - self.tokens);
        if earned >= room {
            // Tokens beyond the bucket's room are discarded, together with
            // the time that produced them; keeping that time as credit would
            // let one idle period fund several consecutive bursts.
            self.tokens = self.capacity;
            self.refill_at = now;
            return;
        }
        // Advance the baseline by the exact time the credited tokens take
        // to accrue, preserving the sub-token remainder.  The saturating
        // conversion only triggers on multi-century idles, where pinning to
        // any reachable instant is equivalent.
        let spent_nanos = earned * NANOS_PER_SECOND / u128::from(self.bytes_per_second);
        self.refill_at += Duration::from_nanos(u64::try_from(spent_nanos).unwrap_or(u64::MAX));
        // `earned < room` came from a u64 difference, so the conversion is
        // lossless and the sum never exceeds `capacity`.
        self.tokens += earned as u64;
    }
}

async fn write_shaped<W>(
    writer: &mut W,
    bytes: &[u8],
    limit: &mut DirectionalLimit,
    activity: &tokio::sync::watch::Sender<()>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut pos = 0;
    while pos < bytes.len() {
        let allowed = limit.wait_for_allowance(bytes.len() - pos).await;
        debug_assert!(allowed > 0, "a non-empty shaped write must make progress");
        let end = pos + allowed;
        while pos < end {
            let n = writer.write(&bytes[pos..end]).await?;
            if n == 0 {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "REALITY cover relay zero write",
                )));
            }
            pos += n;
            // Idle means no bytes are crossing the relay.  Refresh on every
            // accepted partial write, not only after a whole throttled segment
            // survives kernel backpressure.
            let _ = activity.send(());
        }
        writer.flush().await?;
    }
    Ok(())
}

async fn relay_direction<R, W>(
    mut reader: R,
    mut writer: W,
    initial: Vec<u8>,
    mut limit: DirectionalLimit,
    activity: tokio::sync::watch::Sender<()>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !initial.is_empty() {
        write_shaped(&mut writer, &initial, &mut limit, &activity).await?;
        // The preserved ClientHello can run to 64 KiB; holding it for the
        // relay's lifetime would keep that allocation pinned per cover
        // connection long after its only use.
        drop(initial);
    }
    let mut buf = [0u8; COVER_BUFFER];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        write_shaped(&mut writer, &buf[..n], &mut limit, &activity).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality_tls::wrap_plain_record;
    use crate::reality_tls::{build_reality_client_hello, RealityTlsLayer};
    use crate::tls::TlsConfig;
    use crate::Transport;
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SERVER_NAME: &str = "www.example.com";
    const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn fixed_unix() -> u64 {
        1_700_000_000
    }

    fn fixed_system_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(fixed_unix())
    }

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let mut private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut private);
        let public = x25519_public_from_private(&private);
        (private, public)
    }

    fn server_config(private: [u8; 32]) -> RealityServerConfig {
        RealityServerConfig {
            private_key: private,
            short_ids: vec![[0u8; 8], SHORT_ID, [0xff; 8]],
            server_names: HashSet::from([SERVER_NAME.to_string()]),
            max_time_difference: None,
            now: Some(fixed_system_time),
        }
    }

    fn client_config(public: [u8; 32], short_id: [u8; 8], hybrid: bool) -> TlsConfig {
        let mut config = TlsConfig::new(SERVER_NAME);
        config.fingerprint = Some("chrome".into());
        config.reality = Some(crate::tls::RealityConfig {
            public_key: public,
            short_id,
            support_x25519_mlkem768: hybrid,
            protocol_clock: Some(fixed_system_time),
        });
        config
    }

    async fn authenticated_roundtrip(hybrid: bool) {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });

        let layer =
            RealityTlsLayer::new(&client_config(public, SHORT_ID, hybrid)).expect("client layer");
        let mut client = layer
            .connect(Box::new(client_io))
            .await
            .expect("REALITY client handshake must complete");

        let accepted = accept_task.await.expect("accept task").expect("accept");
        let RealityServerAccept::Authenticated(mut server_stream) = accepted else {
            panic!("valid REALITY client must authenticate");
        };

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 4];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server_stream.write_all(b"pong").await.unwrap();
        server_stream.flush().await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn authenticates_real_client_x25519_and_round_trips() {
        authenticated_roundtrip(false).await;
    }

    #[tokio::test]
    async fn authenticates_real_client_hybrid_and_round_trips() {
        authenticated_roundtrip(true).await;
    }

    async fn rejected_client_goes_to_cover(client_config: TlsConfig, server: RealityServer) {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let layer = RealityTlsLayer::new(&client_config).expect("client layer");
        let client_task = tokio::spawn(async move { layer.connect(Box::new(client_io)).await });
        let accepted = accept_task.await.expect("accept task").expect("accept");
        let RealityServerAccept::Cover(relay) = accepted else {
            panic!("invalid REALITY client must fall through to cover");
        };
        assert!(relay.wire_prefix_len() > 71);
        drop(relay);
        let client_result = client_task.await.expect("client task");
        assert!(
            client_result.is_err(),
            "unauthenticated client must not complete"
        );
    }

    #[tokio::test]
    async fn wrong_short_id_goes_to_cover_without_response() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        rejected_client_goes_to_cover(client_config(public, [9u8; 8], false), server).await;
    }

    #[tokio::test]
    async fn wrong_server_public_key_goes_to_cover_without_response() {
        let (private, _public) = keypair();
        let (_other_private, wrong_public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        rejected_client_goes_to_cover(client_config(wrong_public, SHORT_ID, false), server).await;
    }

    #[tokio::test]
    async fn wrong_sni_goes_to_cover_without_response() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let mut config = client_config(public, SHORT_ID, false);
        config.sni = Some("other.example.com".into());
        rejected_client_goes_to_cover(config, server).await;
    }

    async fn expect_authenticated(client_config: TlsConfig, server: RealityServer) {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let layer = RealityTlsLayer::new(&client_config).expect("client layer");
        let client_task = tokio::spawn(async move { layer.connect(Box::new(client_io)).await });
        let accepted = accept_task.await.expect("accept task").expect("accept");
        assert!(
            matches!(accepted, RealityServerAccept::Authenticated(_)),
            "in-window REALITY client must authenticate"
        );
        assert!(client_task.await.expect("client task").is_ok());
    }

    #[tokio::test]
    async fn expired_timestamp_goes_to_cover_but_zero_window_disables_check() {
        fn ancient_system_time() -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(1_000)
        }
        let (private, public) = keypair();
        let mut config = client_config(public, SHORT_ID, false);
        config.reality.as_mut().unwrap().protocol_clock = Some(ancient_system_time);

        let server = RealityServer::new(&server_config(private)).expect("server");
        rejected_client_goes_to_cover(config.clone(), server).await;

        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::ZERO);
        let server = RealityServer::new(&sc).expect("server");
        expect_authenticated(config, server).await;
    }

    #[tokio::test]
    async fn sub_second_window_accepts_client_ahead_across_second_boundary() {
        // The client truncates its clock to whole wire seconds, so a client
        // 100 ms ahead of the server can seal the *next* second.  A 500 ms
        // window must still accept it: the diff is 100 ms, not one second.
        fn server_now() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_900)
        }
        fn client_now() -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(1_700_000_001)
        }
        let (private, public) = keypair();
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now);
        let server = RealityServer::new(&sc).expect("server");
        let mut config = client_config(public, SHORT_ID, false);
        config.reality.as_mut().unwrap().protocol_clock = Some(client_now);
        expect_authenticated(config, server).await;
    }

    #[tokio::test]
    async fn sub_second_window_rejects_outside_window_in_both_directions() {
        fn server_now_late() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_900)
        }
        fn server_now_early() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_200)
        }
        fn client_now_ahead() -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(1_700_000_001)
        }
        let (private, public) = keypair();

        // Client behind: seals second T against a server at T+900ms → 900 ms
        // skew exceeds the 500 ms window.
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now_late);
        let server = RealityServer::new(&sc).expect("server");
        rejected_client_goes_to_cover(client_config(public, SHORT_ID, false), server).await;

        // Client ahead: seals T+1 against a server at T+200ms → 800 ms skew.
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now_early);
        let server = RealityServer::new(&sc).expect("server");
        let mut config = client_config(public, SHORT_ID, false);
        config.reality.as_mut().unwrap().protocol_clock = Some(client_now_ahead);
        rejected_client_goes_to_cover(config, server).await;
    }

    #[tokio::test]
    async fn window_boundary_is_inclusive() {
        fn server_now_exact() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_500)
        }
        fn server_now_beyond() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_500) + Duration::from_micros(1)
        }
        let (private, public) = keypair();

        // Skew exactly equal to the 500 ms window is accepted …
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now_exact);
        let server = RealityServer::new(&sc).expect("server");
        expect_authenticated(client_config(public, SHORT_ID, false), server).await;

        // … and one microsecond beyond it is rejected.
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now_beyond);
        let server = RealityServer::new(&sc).expect("server");
        rejected_client_goes_to_cover(client_config(public, SHORT_ID, false), server).await;
    }

    #[tokio::test]
    async fn huge_window_accepts_distant_timestamp_without_overflow() {
        fn ancient_system_time() -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(1_000)
        }
        let (private, public) = keypair();
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_micros(u64::MAX));
        let server = RealityServer::new(&sc).expect("server");
        let mut config = client_config(public, SHORT_ID, false);
        config.reality.as_mut().unwrap().protocol_clock = Some(ancient_system_time);
        expect_authenticated(config, server).await;
    }

    #[tokio::test]
    async fn corrupt_certificate_verify_is_rejected_by_real_client() {
        let (private, public) = keypair();
        let server = RealityServer::new_corrupting_certificate_verify(&server_config(private))
            .expect("server");
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let layer =
            RealityTlsLayer::new(&client_config(public, SHORT_ID, false)).expect("client layer");
        let client_result = layer.connect(Box::new(client_io)).await;
        assert!(
            client_result.is_err(),
            "bad CertificateVerify must fail the client"
        );
        assert!(accept_task.await.expect("accept task").is_err());
    }

    fn manual_valid_hello(public: [u8; 32], random: [u8; 32]) -> Vec<u8> {
        let mut client_private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut client_private);
        let client_public = x25519_public_from_private(&client_private);
        let shared = x25519(&client_private, &public).unwrap();
        let reality = crate::tls::RealityConfig {
            public_key: public,
            short_id: SHORT_ID,
            support_x25519_mlkem768: false,
            protocol_clock: Some(fixed_system_time),
        };
        build_reality_client_hello(
            SERVER_NAME,
            &[],
            &random,
            &client_public,
            None,
            &shared,
            &reality,
            crate::reality_hello::HelloProfile::Chrome,
        )
        .expect("manual hello")
        .0
    }

    fn manual_valid_hybrid_hello(public: [u8; 32]) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let mut client_private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut client_private);
        let client_public = x25519_public_from_private(&client_private);
        let shared = x25519(&client_private, &public).unwrap();
        let (pq_public, _pq_private) =
            boring::mlkem::MlKemPrivateKey::generate(boring::mlkem::Algorithm::MlKem768)
                .expect("ML-KEM keygen");
        let mut hybrid_x_private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut hybrid_x_private);
        let hybrid_x_public = x25519_public_from_private(&hybrid_x_private);
        let random = rand::random::<[u8; 32]>();
        let reality = crate::tls::RealityConfig {
            public_key: public,
            short_id: SHORT_ID,
            support_x25519_mlkem768: true,
            protocol_clock: Some(fixed_system_time),
        };
        let (hello, auth_key) = build_reality_client_hello(
            SERVER_NAME,
            &[],
            &random,
            &client_public,
            Some((pq_public.as_bytes(), &hybrid_x_public)),
            &shared,
            &reality,
            crate::reality_hello::HelloProfile::Chrome,
        )
        .expect("manual hybrid hello");
        (hello, random, auth_key)
    }

    fn key_share_data_range(hello: &[u8], wanted_group: u16) -> Option<std::ops::Range<usize>> {
        let mut pos = 4 + 2 + 32;
        let sid_len = *hello.get(pos)? as usize;
        pos += 1 + sid_len;
        let suites_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
        pos += 2 + suites_len;
        let compression_len = *hello.get(pos)? as usize;
        pos += 1 + compression_len;
        let extensions_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
        pos += 2;
        let extensions_end = pos.checked_add(extensions_len)?;
        while pos + 4 <= extensions_end {
            let typ = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
            let len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
            pos += 4;
            let data_end = pos.checked_add(len)?;
            if data_end > extensions_end || data_end > hello.len() {
                return None;
            }
            if typ == EXT_KEY_SHARE {
                let data = &hello[pos..data_end];
                if data.len() < 2 {
                    return None;
                }
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if list_len + 2 != data.len() {
                    return None;
                }
                let mut share_pos = 2;
                while share_pos + 4 <= data.len() {
                    let group = u16::from_be_bytes([data[share_pos], data[share_pos + 1]]);
                    let share_len =
                        u16::from_be_bytes([data[share_pos + 2], data[share_pos + 3]]) as usize;
                    share_pos += 4;
                    let share_end = share_pos.checked_add(share_len)?;
                    if share_end > data.len() {
                        return None;
                    }
                    if group == wanted_group {
                        return Some(pos + share_pos..pos + share_end);
                    }
                    share_pos = share_end;
                }
                return None;
            }
            pos = data_end;
        }
        None
    }

    fn reseal_reality_session_id(hello: &mut Vec<u8>, random: &[u8; 32], auth_key: &[u8; 32]) {
        hello[39..71].fill(0);
        let mut plaintext = Vec::with_capacity(16);
        plaintext.extend_from_slice(&[0, 0, 0, 0]);
        plaintext.extend_from_slice(&(fixed_unix() as u32).to_be_bytes());
        plaintext.extend_from_slice(&SHORT_ID);
        assert_eq!(plaintext.len(), 16);
        let cipher = Aes256Gcm::new_from_slice(auth_key).expect("AES-256-GCM key");
        let nonce = Nonce::from_slice(&random[20..32]);
        let tag = cipher
            .encrypt_in_place_detached(nonce, hello.as_slice(), &mut plaintext)
            .expect("re-seal REALITY session id");
        plaintext.extend_from_slice(&tag);
        hello[39..71].copy_from_slice(&plaintext);
    }

    fn server_hello_group(message: &[u8]) -> u16 {
        assert_eq!(message[0], HS_SERVER_HELLO);
        assert_eq!(message.len(), 4 + read_u24(&message[1..4]));
        let mut pos = 4 + 2 + 32;
        let sid_len = message[pos] as usize;
        pos += 1 + sid_len + 2 + 1;
        let extensions_len = u16::from_be_bytes([message[pos], message[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;
        while pos + 4 <= extensions_end {
            let typ = u16::from_be_bytes([message[pos], message[pos + 1]]);
            let len = u16::from_be_bytes([message[pos + 2], message[pos + 3]]) as usize;
            pos += 4;
            if typ == EXT_KEY_SHARE {
                assert!(len >= 4, "ServerHello key_share carries group and length");
                return u16::from_be_bytes([message[pos], message[pos + 1]]);
            }
            pos += len;
        }
        panic!("ServerHello key_share extension missing")
    }

    /// Selection itself must treat a correctly sized but unparsable ML-KEM
    /// encapsulation key as unavailable and move on to the usable classical
    /// share instead of committing to a handshake that cannot be built.
    #[test]
    fn unusable_hybrid_key_share_falls_back_to_classical_in_selection() {
        assert!(!x25519_public_key_usable(&[0u8; 32]));
        let mut probe_private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut probe_private);
        assert!(x25519_public_key_usable(&x25519_public_from_private(
            &probe_private
        )));

        let mut hybrid = vec![0xff; HYBRID_SHARE_LEN - 32];
        hybrid.extend_from_slice(&[7u8; 32]);
        assert!(
            MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, &hybrid[..HYBRID_SHARE_LEN - 32],)
                .is_err(),
            "the test mutation must produce an unusable ML-KEM public key"
        );
        let classical = vec![9u8; 32];
        let hello = ClientHello {
            raw: Vec::new(),
            random: [0u8; 32],
            session_id: Vec::new(),
            server_name: None,
            cipher_suites: Vec::new(),
            supported_groups: vec![GROUP_X25519_MLKEM768, GROUP_X25519],
            key_shares: vec![
                KeyShareEntry {
                    group: GROUP_X25519_MLKEM768,
                    bytes: hybrid,
                },
                KeyShareEntry {
                    group: GROUP_X25519,
                    bytes: classical.clone(),
                },
            ],
            offers_tls13: true,
            reality_session_id_layout: true,
            duplicate_extension: false,
            sni_malformed: false,
            key_share_malformed: false,
        };

        let chosen = select_key_share(&hello).expect("classical fallback remains usable");
        assert_eq!(chosen.group, GROUP_X25519);
        assert_eq!(chosen.client_share, classical);

        let (pq_public, _pq_private) =
            boring::mlkem::MlKemPrivateKey::generate(boring::mlkem::Algorithm::MlKem768)
                .expect("ML-KEM keygen");
        let mut usable_hybrid = pq_public.as_bytes().to_vec();
        usable_hybrid.extend_from_slice(&x25519_public_from_private(&probe_private));
        let hello = ClientHello {
            key_shares: vec![
                KeyShareEntry {
                    group: GROUP_X25519_MLKEM768,
                    bytes: usable_hybrid.clone(),
                },
                KeyShareEntry {
                    group: GROUP_X25519,
                    bytes: classical,
                },
            ],
            ..hello
        };
        let chosen = select_key_share(&hello).expect("usable hybrid remains selectable");
        assert_eq!(chosen.group, GROUP_X25519_MLKEM768);
        assert_eq!(chosen.client_share, usable_hybrid);
    }

    /// The same fallback must hold after REALITY authentication: a valid
    /// session-id proof made with the standalone X25519 share is not thrown
    /// away merely because the preferred hybrid share cannot encapsulate.
    #[tokio::test]
    async fn authenticated_unusable_hybrid_share_falls_back_to_classical_server_share() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });

        let (mut hello, random, auth_key) = manual_valid_hybrid_hello(public);
        let share_range = key_share_data_range(&hello, GROUP_X25519_MLKEM768)
            .expect("hybrid ClientHello carries a hybrid share");
        assert_eq!(share_range.end - share_range.start, HYBRID_SHARE_LEN);
        let mlkem_range = share_range.start..share_range.end - 32;
        hello[mlkem_range.clone()].fill(0xff);
        assert!(
            MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, &hello[mlkem_range],).is_err(),
            "the wire mutation must be an unusable ML-KEM public key"
        );
        reseal_reality_session_id(&mut hello, &random, &auth_key);

        client_io
            .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &hello).unwrap())
            .await
            .unwrap();
        client_io.flush().await.unwrap();
        let server_hello =
            tokio::time::timeout(Duration::from_secs(2), read_record(&mut client_io))
                .await
                .expect("authenticated fallback must emit a server flight")
                .expect("server flight record read")
                .expect("server flight must start with plaintext ServerHello");
        assert_eq!(server_hello.typ, TLS_RECORD_HANDSHAKE);
        assert_eq!(
            server_hello_group(&server_hello.payload),
            GROUP_X25519,
            "the unusable hybrid share must fall back to classical X25519"
        );

        drop(client_io);
        let _ = tokio::time::timeout(Duration::from_secs(1), accept_task).await;
    }

    #[tokio::test]
    async fn fragmented_client_hello_across_records_authenticates() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let hello = manual_valid_hello(public, rand::random::<[u8; 32]>());
        let split = 11;
        client_io
            .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &hello[..split]).unwrap())
            .await
            .unwrap();
        client_io
            .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &hello[split..]).unwrap())
            .await
            .unwrap();
        client_io.flush().await.unwrap();

        let mut header = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(2), client_io.read_exact(&mut header))
            .await
            .expect("valid fragmented hello must produce a server flight")
            .unwrap();
        assert_eq!(header[0], TLS_RECORD_HANDSHAKE);
        drop(client_io);
        assert!(accept_task.await.expect("accept task").is_err());
    }

    #[tokio::test]
    async fn non_client_hello_goes_to_cover_and_relay_is_byte_transparent() {
        let (private, _public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (mut client_peer, server_io) = tokio::io::duplex(128 * 1024);
        let (target_io, mut cover_peer) = tokio::io::duplex(128 * 1024);

        let original = wrap_plain_record(TLS_RECORD_HANDSHAKE, &[2, 0, 0, 1, 0]).unwrap();
        client_peer.write_all(&original).await.unwrap();
        client_peer.flush().await.unwrap();
        let accepted = server.accept(Box::new(server_io)).await.expect("accept");
        let RealityServerAccept::Cover(relay) = accepted else {
            panic!("non-ClientHello must go to cover");
        };
        assert_eq!(relay.wire_prefix_len(), original.len());
        let relay_task = tokio::spawn(async move { relay.relay(Box::new(target_io)).await });

        let mut got = vec![0u8; original.len()];
        cover_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got, original,
            "preserved wire prefix must be byte-identical"
        );
        cover_peer.write_all(b"cover-response").await.unwrap();
        cover_peer.flush().await.unwrap();
        let mut response = vec![0u8; b"cover-response".len()];
        client_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response, b"cover-response");

        drop(client_peer);
        drop(cover_peer);
        let _ = relay_task.await;
    }

    fn expect_preflight_cover(
        preflight: Result<(Box<dyn Stream>, Preflight)>,
    ) -> (Box<dyn Stream>, Vec<u8>) {
        let (inner, preflight) = preflight.expect("preflight itself must not fail");
        match preflight {
            Preflight::Cover(prefix) => (inner, prefix),
            Preflight::Candidate { .. } => {
                panic!("implausible record header must not be a candidate")
            }
        }
    }

    /// A record type that cannot carry a ClientHello is already decisive
    /// after the five-byte header; preflight must not wait for its body.
    #[tokio::test]
    async fn non_handshake_record_header_goes_to_cover_without_waiting_for_body() {
        let header = [TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0, 4];
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(&header).await.unwrap();
        writer.flush().await.unwrap();

        let preflight = tokio::time::timeout(
            Duration::from_millis(200),
            read_client_hello_preflight(Box::new(reader)),
        )
        .await
        .expect("the decisive header must classify before the accept timeout");
        let (_inner, prefix) = expect_preflight_cover(preflight);
        assert_eq!(prefix, header);
        drop(writer);
    }

    /// The impossible-type/version verdict also precedes the resource
    /// limits: those limits exist for real TLS candidates, not for input
    /// already known to belong on the cover path.
    #[tokio::test]
    async fn implausible_record_header_goes_to_cover_before_length_resource_check() {
        for header in [
            [TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x40, 1],
            [TLS_RECORD_HANDSHAKE, 0xff, 0xff, 0x40, 1],
        ] {
            let (mut writer, reader) = tokio::io::duplex(64);
            writer.write_all(&header).await.unwrap();
            writer.flush().await.unwrap();

            let preflight = tokio::time::timeout(
                Duration::from_millis(200),
                read_client_hello_preflight(Box::new(reader)),
            )
            .await
            .expect("the decisive header must classify promptly");
            let (_inner, prefix) = expect_preflight_cover(preflight);
            assert_eq!(prefix, header);
            drop(writer);
        }
    }

    /// Only the bytes actually consumed for the decisive header belong in
    /// the cover prefix; the unread record body stays on the stream and is
    /// relayed after that prefix, exactly once and in order.
    #[tokio::test]
    async fn cover_after_decisive_header_leaves_record_body_on_stream() {
        let header = [TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0, 4];
        let body = b"abcd";
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(&header).await.unwrap();
        writer.write_all(body).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let preflight = read_client_hello_preflight(Box::new(reader)).await;
        let (mut inner, prefix) = expect_preflight_cover(preflight);
        assert_eq!(prefix, header);
        let mut preserved = [0u8; 4];
        inner.read_exact(&mut preserved).await.unwrap();
        assert_eq!(&preserved, body);
    }

    fn padding_data_offset(hello: &[u8]) -> Option<usize> {
        let mut pos = 4 + 2 + 32;
        let sid_len = *hello.get(pos)? as usize;
        pos += 1 + sid_len;
        let suites_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
        pos += 2 + suites_len;
        let comp_len = *hello.get(pos)? as usize;
        pos += 1 + comp_len;
        let ext_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
        pos += 2;
        let end = pos.checked_add(ext_len)?;
        while pos + 4 <= end {
            let typ = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
            let len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
            pos += 4;
            if typ == 0xfe0d && len >= 144 {
                return Some(pos + len - 1);
            }
            pos = pos.checked_add(len)?;
        }
        None
    }

    #[tokio::test]
    async fn tampered_aad_goes_to_cover() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let mut hello = manual_valid_hello(public, rand::random::<[u8; 32]>());
        let grease_ech = padding_data_offset(&hello).expect("Chrome hello carries GREASE ECH");
        hello[grease_ech] ^= 1;
        client_io
            .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &hello).unwrap())
            .await
            .unwrap();
        client_io.flush().await.unwrap();
        let accepted = accept_task.await.expect("accept task").expect("accept");
        assert!(
            matches!(accepted, RealityServerAccept::Cover(_)),
            "AAD tamper must not authenticate"
        );
    }

    struct CorruptSecondWrite<S> {
        inner: S,
        writes: usize,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for CorruptSecondWrite<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for CorruptSecondWrite<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if !data.is_empty() {
                this.writes += 1;
                if this.writes == 2 {
                    let mut corrupted = data.to_vec();
                    let last = corrupted.len() - 1;
                    corrupted[last] ^= 1;
                    return std::pin::Pin::new(&mut this.inner).poll_write(cx, &corrupted);
                }
            }
            std::pin::Pin::new(&mut this.inner).poll_write(cx, data)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn authenticated_branch_with_corrupt_client_finished_fails_closed() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let layer =
            RealityTlsLayer::new(&client_config(public, SHORT_ID, false)).expect("client layer");
        let corrupted = CorruptSecondWrite {
            inner: client_io,
            writes: 0,
        };
        let client_task = tokio::spawn(async move { layer.connect(Box::new(corrupted)).await });
        let accept_result = accept_task.await.expect("accept task");
        assert!(
            accept_result.is_err(),
            "corrupt client Finished must close the authenticated branch"
        );
        let _ = client_task.await.expect("client task");
    }

    // ─── ClientHello pre-read wire cap, compression shape, token bucket ──────

    /// C4: the pre-read cap is 64 KiB of *wire* bytes — record headers
    /// included — not 64 KiB plus one header.  Drives the boundary: an
    /// accumulation of exactly 64 KiB must pass the size check (and fail
    /// later only because the peer hangs up), one byte more must be
    /// rejected as a resource limit.
    #[tokio::test]
    async fn preflight_wire_cap_counts_record_headers() {
        // The ClientHello claim is sized to never complete inside the
        // cap: message_len 65532 → total 65536, accepted by the inner
        // message-length check, so the wire byte cap is the only limit
        // that can fire.  Three full records then a fourth sized to land
        // exactly on, or one byte past, the 64 KiB wire total:
        // 3 × (5 + 16384) = 49167, the fourth header adds 5, so the
        // payload hitting exactly 65536 is 65536 − 49172 = 16364.
        fn wire_input(last_payload_len: usize) -> Vec<u8> {
            let mut input = Vec::new();
            let mut first_payload = vec![0u8; MAX_PLAINTEXT_RECORD];
            first_payload[..4].copy_from_slice(&[HS_CLIENT_HELLO, 0x00, 0xFF, 0xFC]);
            for payload in [
                first_payload,
                vec![0u8; MAX_PLAINTEXT_RECORD],
                vec![0u8; MAX_PLAINTEXT_RECORD],
                vec![0u8; last_payload_len],
            ] {
                input.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 0x03, 0x03]);
                input.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                input.extend_from_slice(&payload);
            }
            input
        }

        // Exactly at the cap: no resource error — the pre-read fails only
        // because the peer's EOF arrives with the hello still incomplete.
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&wire_input(16364)).await.unwrap();
        drop(writer);
        match read_client_hello_preflight(Box::new(reader)).await {
            Err(TransportError::Io(_)) => {}
            Err(err) => panic!("exactly 64 KiB of wire passes the size cap, got: {err:?}"),
            Ok(_) => panic!("incomplete hello at exactly 64 KiB wire must not classify"),
        }

        // One byte past the cap: the wire limit itself must fire.  Before
        // the fix the +5 header slack let this through to the same EOF.
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&wire_input(16365)).await.unwrap();
        drop(writer);
        match read_client_hello_preflight(Box::new(reader)).await {
            Err(TransportError::ResourceLimit(_)) => {}
            Err(err) => panic!("64 KiB + 1 of wire hits the resource limit, got: {err:?}"),
            Ok(_) => panic!("one byte past 64 KiB wire must be rejected"),
        }

        // A decisive non-TLS header cannot be used to carry the preserved
        // prefix past the same cap once the incomplete hello already fills it.
        let mut input = wire_input(16364);
        input.extend_from_slice(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0, 4]);
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&input).await.unwrap();
        drop(writer);
        match read_client_hello_preflight(Box::new(reader)).await {
            Err(TransportError::ResourceLimit(_)) => {}
            Err(err) => {
                panic!("a header beyond the 64 KiB cap hits the resource limit, got: {err:?}")
            }
            Ok(_) => panic!("a header beyond 64 KiB wire must not become cover prefix"),
        }

        // Even a fragment of the next header is decisive once it is the first
        // byte beyond the cap; truncation after it must not demote the error.
        let mut input = wire_input(16364);
        input.push(TLS_RECORD_APPLICATION_DATA);
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&input).await.unwrap();
        drop(writer);
        match read_client_hello_preflight(Box::new(reader)).await {
            Err(TransportError::ResourceLimit(_)) => {}
            Err(err) => {
                panic!("one byte beyond the 64 KiB cap hits the resource limit, got: {err:?}")
            }
            Ok(_) => panic!("one byte beyond 64 KiB wire must be rejected"),
        }
    }

    /// C6: TLS 1.3 admits exactly one compression method, zero — a REALITY
    /// candidate carrying anything else is not parsed as a candidate.
    #[test]
    fn client_hello_compression_must_be_exactly_null() {
        fn synthetic_client_hello(compression: &[u8]) -> Vec<u8> {
            let mut body = vec![0x03, 0x03];
            body.extend_from_slice(&[0xAA; 32]);
            body.push(0x20);
            body.extend_from_slice(&[0xBB; 32]);
            body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
            body.push(compression.len() as u8);
            body.extend_from_slice(compression);
            body.extend_from_slice(&[0, 0]); // empty extension vector
            let mut hello = vec![HS_CLIENT_HELLO];
            put_u24(body.len(), &mut hello);
            hello.extend_from_slice(&body);
            hello
        }

        parse_client_hello(synthetic_client_hello(&[0])).expect("exactly [0] parses");
        for bad in [&[][..], &[1][..], &[0, 0][..], &[1, 0][..], &[0, 1][..]] {
            assert!(
                parse_client_hello(synthetic_client_hello(bad)).is_err(),
                "compression {bad:?} must be rejected"
            );
        }
    }

    /// C3: token accrual saturates at the bucket's room instead of
    /// truncating the u128 intermediate — before the fix an idle×rate
    /// product of exactly 2^65 wrapped the `as u64` credit to zero.
    #[test]
    fn refill_saturates_instead_of_truncating() {
        // 2^63 B/s for 4 s earns exactly 2^65 tokens — beyond u64 — so
        // any wrap in the conversion chain is visible as a missing or
        // under-counted credit.
        let mut limit = DirectionalLimit::new(1u64 << 63, 0, 0);
        assert_eq!(limit.capacity, 1u64 << 63);
        limit.tokens = 0;
        limit.refill_at = Instant::now() - Duration::from_secs(4);
        limit.refill();
        assert_eq!(
            limit.tokens, limit.capacity,
            "the credit saturates the bucket instead of wrapping"
        );
        assert!(
            limit.refill_at <= Instant::now(),
            "the refill baseline must never pass the present"
        );
    }

    /// Once accrued credit saturates the bucket, the excess idle time is
    /// discarded rather than remaining available to fund another burst.
    #[test]
    fn saturated_refill_discards_excess_idle_time() {
        let mut limit = DirectionalLimit::new(1000, 0, 0);
        limit.tokens = 0;
        limit.refill_at = Instant::now() - Duration::from_secs(3);
        let before_refill = Instant::now();
        limit.refill();
        assert_eq!(limit.tokens, limit.capacity);
        assert!(
            limit.refill_at >= before_refill,
            "the saturated refill baseline must be pinned to the refill, not left in the past"
        );
    }

    /// A full bucket earns nothing further, and once room exists the
    /// normal-rate accrual still credits whole tokens — the saturation
    /// clamp must not eat ordinary refills.
    #[test]
    fn refill_still_accrues_at_normal_rates() {
        let mut limit = DirectionalLimit::new(1000, 0, 0);
        assert_eq!(limit.capacity, 1000);

        // Full bucket: refill pins the baseline without changing tokens.
        limit.refill();
        assert_eq!(limit.tokens, 1000);
        assert!(limit.refill_at <= Instant::now());

        // Half-drained bucket after 400+ ms idle at 1000 B/s: the credit
        // is hundreds of tokens, bounded by the rate and the elapsed
        // floor of 400 ms.
        limit.tokens = 500;
        limit.refill_at = Instant::now() - Duration::from_millis(400);
        limit.refill();
        assert!(
            limit.tokens >= 900,
            "400 ms at 1000 B/s restores at least 400 tokens, got {}",
            limit.tokens
        );
        assert!(limit.tokens <= 1000, "never beyond capacity");
    }

    struct RecordingWriter {
        writes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl AsyncWrite for RecordingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.writes.lock().unwrap().push(buf.to_vec());
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct OneByteThenPendingWriter {
        writes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl AsyncWrite for OneByteThenPendingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.writes.lock().unwrap().is_empty() {
                self.writes.lock().unwrap().push(buf[..1].to_vec());
                return std::task::Poll::Ready(Ok(1));
            }
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A writer that accepts one byte and then applies backpressure has still
    /// relayed data: even that partial progress must refresh the idle watchdog.
    #[tokio::test]
    async fn shaped_write_reports_partial_write_progress_as_activity() {
        let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (activity_tx, mut activity_rx) = tokio::sync::watch::channel(());
        activity_rx.borrow_and_update();
        let task = tokio::spawn({
            let writes = std::sync::Arc::clone(&writes);
            async move {
                let mut writer = OneByteThenPendingWriter { writes };
                let mut limit = DirectionalLimit::new(0, 0, 0);
                write_shaped(&mut writer, b"abc", &mut limit, &activity_tx).await
            }
        });

        let first_write = tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if !writes.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(first_write.is_ok(), "the one-byte write must be accepted");
        assert!(
            activity_rx.has_changed().expect("activity sender is alive"),
            "the accepted byte must refresh cover activity before the segment completes"
        );
        task.abort();
    }

    fn spawn_recorded_shaped_prefix(
        len: usize,
        writes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    ) -> tokio::task::JoinHandle<Result<()>> {
        let (activity_tx, _activity_rx) = tokio::sync::watch::channel(());
        tokio::spawn(relay_direction(
            tokio::io::empty(),
            RecordingWriter { writes },
            vec![0x5a; len],
            DirectionalLimit::new(1000, 0, 0),
            activity_tx,
        ))
    }

    /// A throttled prefix must make wire progress with the tokens already
    /// in the bucket instead of waiting for the whole multi-second block.
    #[tokio::test]
    async fn shaped_prefix_progresses_before_whole_prefix_is_throttled() {
        let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay = spawn_recorded_shaped_prefix(3000, std::sync::Arc::clone(&writes));

        let first_write = tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if !writes.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            first_write.is_ok(),
            "the first bucket-sized segment must reach the writer promptly"
        );
        relay.abort();
    }

    /// Rate accounting may span a block larger than the bucket, but the
    /// wire write must still be segmented at the configured burst size.
    #[tokio::test]
    async fn shaped_prefix_never_writes_more_than_bucket_capacity_in_one_burst() {
        let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay = spawn_recorded_shaped_prefix(1001, std::sync::Arc::clone(&writes));

        let completed = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if writes.lock().unwrap().iter().map(Vec::len).sum::<usize>() >= 1001 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(completed.is_ok(), "the small shaped prefix must complete");
        let chunks = writes.lock().unwrap().clone();
        assert!(
            chunks.iter().all(|chunk| chunk.len() <= 1000),
            "no write may exceed the 1000-byte bucket capacity: {:?}",
            chunks.iter().map(Vec::len).collect::<Vec<_>>()
        );
        assert!(
            chunks.len() > 1,
            "an over-capacity block must be split, got {:?}",
            chunks.iter().map(Vec::len).collect::<Vec<_>>()
        );
        assert_eq!(chunks.concat(), vec![0x5a; 1001]);
        relay.abort();
    }
}

#[cfg(test)]
mod independent_wire_vectors {
    use super::*;
    use std::collections::HashSet;

    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes128Gcm, Nonce, Tag};
    use boring::sign::Verifier;
    use hmac::Mac;
    use sha2::{Digest, Sha256};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::DuplexStream;

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/reality_independent_vectors.rs"
    ));

    type IndependentHmacSha256 = hmac::Hmac<Sha256>;
    type IndependentHmacSha512 = hmac::Hmac<sha2::Sha512>;

    fn hex_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have even length");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("generated hex"))
            .collect()
    }

    fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
        hex_bytes(hex)
            .try_into()
            .expect("generated hex constant length")
    }

    struct DecodedVector {
        client_hello: Vec<u8>,
        aad: Vec<u8>,
        sid: Vec<u8>,
        shared: Vec<u8>,
        auth_key: Vec<u8>,
        plaintext: Vec<u8>,
    }

    fn decode_vector(vector: &FrozenHelloVector) -> DecodedVector {
        DecodedVector {
            client_hello: hex_bytes(vector.client_hello_hex),
            aad: hex_bytes(vector.aad_hex),
            sid: hex_bytes(vector.sid_hex),
            shared: hex_bytes(vector.shared_hex),
            auth_key: hex_bytes(vector.auth_key_hex),
            plaintext: hex_bytes(vector.plaintext_hex),
        }
    }

    fn vector_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(UNIX_SECONDS)
    }

    fn vector_config() -> RealityServerConfig {
        RealityServerConfig {
            private_key: hex_array(SERVER_STATIC_PRIVATE_HEX),
            short_ids: vec![hex_array(SHORT_ID_HEX)],
            server_names: HashSet::from([SERVER_NAME.to_string()]),
            max_time_difference: None,
            now: Some(vector_now),
        }
    }

    fn vector_server() -> RealityServer {
        RealityServer::new_with_ed25519_private_der(
            &vector_config(),
            &hex_bytes(ED25519_PRIVATE_DER_HEX),
        )
        .expect("fixed-vector REALITY server")
    }

    fn plaintext_record(payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() <= u16::MAX as usize);
        let mut out = Vec::with_capacity(payload.len() + 5);
        out.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 0x03, 0x03]);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn independent_handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + body.len());
        out.push(kind);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        out.extend_from_slice(body);
        out
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac = <IndependentHmacSha256 as Mac>::new_from_slice(key)
            .expect("HMAC-SHA256 accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }

    fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac = <IndependentHmacSha512 as Mac>::new_from_slice(key)
            .expect("HMAC-SHA512 accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }

    fn hkdf_extract_independent(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        hmac_sha256(salt, &[ikm])
    }

    fn hkdf_expand_independent(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut okm = Vec::new();
        let mut previous = Vec::new();
        let mut counter = 1u8;
        while okm.len() < len {
            previous = hmac_sha256(prk, &[&previous, info, &[counter]]);
            okm.extend_from_slice(&previous);
            counter += 1;
        }
        okm.truncate(len);
        okm
    }

    fn hkdf_expand_label_independent(
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        hkdf_expand_independent(secret, &info, len)
    }

    fn derive_secret_independent(secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        hkdf_expand_label_independent(secret, label, transcript_hash, 32)
    }

    struct IndependentHandshakeSecrets {
        client_secret: Vec<u8>,
        server_secret: Vec<u8>,
        master_secret: Vec<u8>,
    }

    fn derive_handshake_secrets(
        shared_secret: &[u8],
        transcript: &[u8],
    ) -> IndependentHandshakeSecrets {
        let zero = [0u8; 32];
        let empty_hash = sha256(&[]);
        let early_secret = hkdf_extract_independent(&zero, &zero);
        let derived = derive_secret_independent(&early_secret, b"derived", &empty_hash);
        let handshake_secret = hkdf_extract_independent(&derived, shared_secret);
        let transcript_hash = sha256(transcript);
        let client_secret =
            derive_secret_independent(&handshake_secret, b"c hs traffic", &transcript_hash);
        let server_secret =
            derive_secret_independent(&handshake_secret, b"s hs traffic", &transcript_hash);
        let derived = derive_secret_independent(&handshake_secret, b"derived", &empty_hash);
        let master_secret = hkdf_extract_independent(&derived, &zero);
        IndependentHandshakeSecrets {
            client_secret,
            server_secret,
            master_secret,
        }
    }

    fn independent_finished_verify_data(secret: &[u8], transcript: &[u8]) -> Vec<u8> {
        let finished_key = hkdf_expand_label_independent(secret, b"finished", &[], 32);
        hmac_sha256(&finished_key, &[&sha256(transcript)])
    }

    struct IndependentRecordKey {
        cipher: Aes128Gcm,
        iv: [u8; 12],
        seq: u64,
    }

    impl IndependentRecordKey {
        fn new(secret: &[u8]) -> Self {
            let key = hkdf_expand_label_independent(secret, b"key", &[], 16);
            let iv = hkdf_expand_label_independent(secret, b"iv", &[], 12);
            Self {
                cipher: Aes128Gcm::new_from_slice(&key).expect("AES-128 key length"),
                iv: iv.try_into().expect("TLS IV length"),
                seq: 0,
            }
        }

        fn next_nonce(&mut self) -> [u8; 12] {
            assert_ne!(self.seq, u64::MAX, "test nonce sequence must not wrap");
            let mut nonce = self.iv;
            for (dst, src) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
                *dst ^= src;
            }
            self.seq += 1;
            nonce
        }

        fn seal(&mut self, inner_type: u8, plaintext: &[u8]) -> Vec<u8> {
            let body_len = plaintext.len() + 1;
            let record_len = body_len + 16;
            let mut header = [TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0, 0];
            header[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
            let nonce = self.next_nonce();
            let mut body = plaintext.to_vec();
            body.push(inner_type);
            let tag = self
                .cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), &header, &mut body)
                .expect("independent TLS record seal");
            body.extend_from_slice(&tag);
            let mut out = header.to_vec();
            out.extend_from_slice(&body);
            out
        }

        fn open(&mut self, header: &[u8; 5], payload: &[u8]) -> (u8, Vec<u8>) {
            let split = payload
                .len()
                .checked_sub(16)
                .expect("TLS ciphertext carries a tag");
            let (data, tag) = payload.split_at(split);
            let nonce = self.next_nonce();
            let mut body = data.to_vec();
            self.cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    header,
                    &mut body,
                    Tag::from_slice(tag),
                )
                .expect("independent TLS record open");
            let type_pos = body
                .iter()
                .rposition(|byte| *byte != 0)
                .expect("TLS inner plaintext type");
            let inner_type = body[type_pos];
            body.truncate(type_pos);
            (inner_type, body)
        }
    }

    fn independent_take<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> &'a [u8] {
        let end = pos.checked_add(len).expect("parser offset overflow");
        let out = input.get(*pos..end).expect("parser input truncated");
        *pos = end;
        out
    }

    fn independent_u16(input: &[u8], pos: &mut usize) -> u16 {
        let bytes = independent_take(input, pos, 2);
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    fn independent_u24(input: &[u8], pos: &mut usize) -> usize {
        let bytes = independent_take(input, pos, 3);
        ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
    }

    struct IndependentServerHello {
        cipher_suite: u16,
        session_id: Vec<u8>,
        group: u16,
        share: Vec<u8>,
    }

    fn parse_server_hello_independent(raw: &[u8]) -> IndependentServerHello {
        assert_eq!(raw[0], HS_SERVER_HELLO);
        let mut pos = 1;
        let body_len = independent_u24(raw, &mut pos);
        assert_eq!(pos + body_len, raw.len(), "one exact ServerHello message");
        assert_eq!(independent_take(raw, &mut pos, 2), &[0x03, 0x03]);
        independent_take(raw, &mut pos, 32);
        let sid_len = independent_take(raw, &mut pos, 1)[0] as usize;
        let session_id = independent_take(raw, &mut pos, sid_len).to_vec();
        let cipher_suite = independent_u16(raw, &mut pos);
        assert_eq!(independent_take(raw, &mut pos, 1), &[0]);
        let extensions_len = independent_u16(raw, &mut pos) as usize;
        let extensions_end = pos + extensions_len;
        let mut key_share = None;
        while pos < extensions_end {
            let ext_type = independent_u16(raw, &mut pos);
            let ext_len = independent_u16(raw, &mut pos) as usize;
            let data = independent_take(raw, &mut pos, ext_len);
            match ext_type {
                EXT_SUPPORTED_VERSIONS => assert_eq!(data, &[0x03, 0x04]),
                EXT_KEY_SHARE => {
                    let mut kp = 0;
                    let group = independent_u16(data, &mut kp);
                    let share_len = independent_u16(data, &mut kp) as usize;
                    let share = independent_take(data, &mut kp, share_len).to_vec();
                    assert_eq!(kp, data.len(), "ServerHello key_share exact length");
                    key_share = Some((group, share));
                }
                _ => panic!("unexpected ServerHello extension {ext_type:#x}"),
            }
        }
        assert_eq!(pos, extensions_end);
        let (group, share) = key_share.expect("ServerHello key_share");
        IndependentServerHello {
            cipher_suite,
            session_id,
            group,
            share,
        }
    }

    struct IndependentHandshakeMessage {
        kind: u8,
        raw: Vec<u8>,
        body: Vec<u8>,
    }

    fn split_handshake_messages(plaintext: &[u8]) -> Vec<IndependentHandshakeMessage> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < plaintext.len() {
            let kind = independent_take(plaintext, &mut pos, 1)[0];
            let len = independent_u24(plaintext, &mut pos);
            let start = pos - 4;
            let body = independent_take(plaintext, &mut pos, len).to_vec();
            out.push(IndependentHandshakeMessage {
                kind,
                raw: plaintext[start..pos].to_vec(),
                body,
            });
        }
        out
    }

    fn extract_certificate_der(message: &IndependentHandshakeMessage) -> Vec<u8> {
        assert_eq!(message.kind, HS_CERTIFICATE);
        let body = &message.body;
        assert_eq!(body[0], 0, "empty certificate request context");
        let mut pos = 1;
        let list_len = independent_u24(body, &mut pos);
        assert_eq!(pos + list_len, body.len(), "single exact certificate list");
        let der_len = independent_u24(body, &mut pos);
        let der = independent_take(body, &mut pos, der_len).to_vec();
        let extensions_len = independent_u16(body, &mut pos) as usize;
        assert_eq!(extensions_len, 0, "no leaf extensions in the server vector");
        assert_eq!(pos, body.len(), "exactly one certificate entry");
        der
    }

    fn extract_certificate_verify(message: &IndependentHandshakeMessage) -> Vec<u8> {
        assert_eq!(message.kind, HS_CERTIFICATE_VERIFY);
        assert_eq!(&message.body[..2], &SIG_ED25519.to_be_bytes());
        assert_eq!(&message.body[2..4], &64u16.to_be_bytes());
        assert_eq!(message.body.len(), 4 + 64);
        message.body[4..].to_vec()
    }

    fn verify_ed25519_signature(signature: &[u8], input: &[u8]) {
        let key = PKey::public_key_from_der(&hex_bytes(ED25519_SPKI_DER_HEX))
            .expect("fixed Ed25519 SPKI");
        let mut verifier = Verifier::new_without_digest(&key).expect("Ed25519 verifier");
        assert!(
            verifier
                .verify_oneshot(signature, input)
                .expect("Ed25519 verification"),
            "CertificateVerify signature must verify over the independent transcript input"
        );
    }

    fn expected_leaf_for_auth_key(auth_key: &[u8]) -> Vec<u8> {
        let mut der = hex_bytes(LEAF_DER_HEX);
        let mac = hmac_sha512(auth_key, &[&hex_bytes(ED25519_PUBLIC_HEX)]);
        assert_eq!(mac.len(), 64);
        let signature_start = der.len() - 64;
        der[signature_start..].copy_from_slice(&mac);
        der
    }

    fn independent_shared_secret(
        server_hello: &IndependentServerHello,
        client_x25519_private: &[u8; 32],
        hybrid_x25519_private: &[u8; 32],
        mlkem_seed: &[u8; 64],
    ) -> Vec<u8> {
        if server_hello.group == GROUP_X25519 {
            assert_eq!(server_hello.share.len(), 32);
            let server_public: [u8; 32] = server_hello
                .share
                .as_slice()
                .try_into()
                .expect("X25519 server share length");
            let secret = x25519_dalek::x25519(*client_x25519_private, server_public);
            assert_ne!(secret, [0u8; 32], "low-order TLS ECDH must be rejected");
            return secret.to_vec();
        }
        assert_eq!(server_hello.group, GROUP_X25519_MLKEM768);
        assert_eq!(server_hello.share.len(), 1088 + 32);
        let mlkem = boring::mlkem::MlKemPrivateKey::from_seed(
            boring::mlkem::Algorithm::MlKem768,
            mlkem_seed,
        )
        .expect("fixed ML-KEM seed");
        let mlkem_secret = mlkem
            .decapsulate(&server_hello.share[..1088])
            .expect("server ML-KEM ciphertext decapsulates");
        let server_x: [u8; 32] = server_hello.share[1088..]
            .try_into()
            .expect("hybrid X25519 server share length");
        let x_secret = x25519_dalek::x25519(*hybrid_x25519_private, server_x);
        assert_ne!(x_secret, [0u8; 32], "low-order hybrid TLS ECDH");
        let mut shared = mlkem_secret.to_vec();
        shared.extend_from_slice(&x_secret);
        shared
    }

    async fn read_required_record(
        io: &mut DuplexStream,
        what: &str,
    ) -> crate::reality_tls::TlsRecord {
        tokio::time::timeout(Duration::from_secs(2), read_record(io))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .unwrap_or_else(|e| panic!("failed to read {what}: {e}"))
            .unwrap_or_else(|| panic!("EOF before {what}"))
    }

    #[derive(Clone, Copy)]
    enum HelloFraming {
        SingleRecord,
        ByteWiseTcp,
        SplitRecords(&'static [usize]),
    }

    async fn write_client_hello(io: &mut DuplexStream, hello: &[u8], framing: HelloFraming) {
        match framing {
            HelloFraming::SingleRecord => {
                io.write_all(&plaintext_record(hello)).await.unwrap();
            }
            HelloFraming::ByteWiseTcp => {
                for byte in plaintext_record(hello).chunks(1) {
                    io.write_all(byte).await.unwrap();
                    io.flush().await.unwrap();
                }
            }
            HelloFraming::SplitRecords(pattern) => {
                assert!(pattern.iter().all(|len| *len != 0));
                let mut pos = 0;
                let mut index = 0;
                while pos < hello.len() {
                    let len = pattern[index % pattern.len()].min(hello.len() - pos);
                    io.write_all(&plaintext_record(&hello[pos..pos + len]))
                        .await
                        .unwrap();
                    pos += len;
                    index += 1;
                }
            }
        }
        io.flush().await.unwrap();
    }

    struct CompletedVectorHandshake {
        server_stream: Box<dyn Stream>,
        client_io: DuplexStream,
        client_app: IndependentRecordKey,
        server_app: IndependentRecordKey,
        client_finished_record: Vec<u8>,
        certificate_der: Vec<u8>,
        selected_group: u16,
    }

    async fn perform_vector_handshake(
        server: RealityServer,
        vector: &FrozenHelloVector,
        framing: HelloFraming,
    ) -> CompletedVectorHandshake {
        let decoded = decode_vector(vector);
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        write_client_hello(&mut client_io, &decoded.client_hello, framing).await;

        let server_hello_record = read_required_record(&mut client_io, "ServerHello").await;
        assert_eq!(server_hello_record.typ, TLS_RECORD_HANDSHAKE);
        let server_hello = parse_server_hello_independent(&server_hello_record.payload);
        assert_eq!(server_hello.cipher_suite, TLS_AES_128_GCM_SHA256);
        assert_eq!(
            server_hello.session_id,
            decoded.client_hello[39..71],
            "ServerHello must echo the encrypted REALITY session id"
        );
        let ccs = read_required_record(&mut client_io, "compatibility CCS").await;
        assert_eq!(ccs.typ, TLS_RECORD_CHANGE_CIPHER_SPEC);
        assert_eq!(ccs.payload, [1]);
        let encrypted_flight =
            read_required_record(&mut client_io, "encrypted server flight").await;
        assert_eq!(encrypted_flight.typ, TLS_RECORD_APPLICATION_DATA);

        let mut transcript = decoded.client_hello.clone();
        transcript.extend_from_slice(&server_hello_record.payload);
        let shared = independent_shared_secret(
            &server_hello,
            &hex_array(CLIENT_X25519_PRIVATE_HEX),
            &hex_array(HYBRID_X25519_PRIVATE_HEX),
            &hex_array(MLKEM768_SEED_HEX),
        );
        let secrets = derive_handshake_secrets(&shared, &transcript);
        let mut client_hs = IndependentRecordKey::new(&secrets.client_secret);
        let mut server_hs = IndependentRecordKey::new(&secrets.server_secret);
        let (inner_type, flight_plaintext) =
            server_hs.open(&encrypted_flight.header, &encrypted_flight.payload);
        assert_eq!(inner_type, TLS_RECORD_HANDSHAKE);
        let messages = split_handshake_messages(&flight_plaintext);
        assert_eq!(
            messages
                .iter()
                .map(|message| message.kind)
                .collect::<Vec<_>>(),
            vec![
                HS_ENCRYPTED_EXTENSIONS,
                HS_CERTIFICATE,
                HS_CERTIFICATE_VERIFY,
                HS_FINISHED
            ],
            "server flight message order"
        );
        assert_eq!(messages[0].body, [0, 0], "empty EncryptedExtensions vector");
        let certificate_der = extract_certificate_der(&messages[1]);
        assert_eq!(
            certificate_der,
            expected_leaf_for_auth_key(&decoded.auth_key),
            "{}: certificate HMAC must match the independent AuthKey/public-key vector",
            vector.name
        );
        let cv_signature = extract_certificate_verify(&messages[2]);

        let mut transcript_through_certificate = transcript.clone();
        transcript_through_certificate.extend_from_slice(&messages[0].raw);
        transcript_through_certificate.extend_from_slice(&messages[1].raw);
        let mut cv_input = vec![0x20; 64];
        cv_input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        cv_input.push(0);
        cv_input.extend_from_slice(&sha256(&transcript_through_certificate));
        verify_ed25519_signature(&cv_signature, &cv_input);

        let mut transcript_through_cv = transcript_through_certificate.clone();
        transcript_through_cv.extend_from_slice(&messages[2].raw);
        assert_eq!(
            messages[3].body,
            independent_finished_verify_data(&secrets.server_secret, &transcript_through_cv),
            "server Finished verify_data must match the independent TLS key schedule"
        );
        let mut transcript_with_server_finished = transcript_through_cv.clone();
        transcript_with_server_finished.extend_from_slice(&messages[3].raw);

        let client_verify = independent_finished_verify_data(
            &secrets.client_secret,
            &transcript_with_server_finished,
        );
        let client_finished = independent_handshake_message(HS_FINISHED, &client_verify);
        let client_finished_record = client_hs.seal(TLS_RECORD_HANDSHAKE, &client_finished);
        client_io.write_all(&client_finished_record).await.unwrap();
        client_io.flush().await.unwrap();

        let accepted = tokio::time::timeout(Duration::from_secs(2), accept_task)
            .await
            .expect("REALITY accept timed out")
            .expect("REALITY accept task joined")
            .expect("independent vector Finished must be accepted");
        let RealityServerAccept::Authenticated(server_stream) = accepted else {
            panic!("valid frozen vector must select the authenticated branch");
        };

        let client_app_secret = hkdf_expand_label_independent(
            &secrets.master_secret,
            b"c ap traffic",
            &sha256(&transcript_with_server_finished),
            32,
        );
        let server_app_secret = hkdf_expand_label_independent(
            &secrets.master_secret,
            b"s ap traffic",
            &sha256(&transcript_with_server_finished),
            32,
        );
        CompletedVectorHandshake {
            server_stream,
            client_io,
            client_app: IndependentRecordKey::new(&client_app_secret),
            server_app: IndependentRecordKey::new(&server_app_secret),
            client_finished_record,
            certificate_der,
            selected_group: server_hello.group,
        }
    }

    async fn assert_vector_roundtrip(completed: &mut CompletedVectorHandshake) {
        let ping = completed
            .client_app
            .seal(TLS_RECORD_APPLICATION_DATA, b"ping");
        completed.client_io.write_all(&ping).await.unwrap();
        completed.client_io.flush().await.unwrap();
        let mut buf = [0u8; 4];
        completed.server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        completed.server_stream.write_all(b"pong").await.unwrap();
        completed.server_stream.flush().await.unwrap();
        let record = read_required_record(&mut completed.client_io, "application pong").await;
        assert_eq!(record.typ, TLS_RECORD_APPLICATION_DATA);
        let (inner_type, plaintext) = completed.server_app.open(&record.header, &record.payload);
        assert_eq!(inner_type, TLS_RECORD_APPLICATION_DATA);
        assert_eq!(plaintext, b"pong");
    }

    async fn accept_cover_for_bytes(
        server: RealityServer,
        hello: &[u8],
        trailing: &[u8],
    ) -> (CoverRelay, DuplexStream) {
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let mut input = plaintext_record(hello);
        input.extend_from_slice(trailing);
        client_io.write_all(&input).await.unwrap();
        client_io.flush().await.unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(2), accept_task)
            .await
            .expect("cover accept timed out")
            .expect("cover accept task joined")
            .expect("cover classification must not be an I/O error");
        let RealityServerAccept::Cover(relay) = accepted else {
            panic!("negative vector must fall through to cover");
        };
        (relay, client_io)
    }

    async fn assert_no_response_bytes(client_io: &mut DuplexStream) {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(5), client_io.read(&mut byte)).await {
            Err(_) => {}
            Ok(Ok(0)) => panic!("cover branch closed before any cover-target relay"),
            Ok(Ok(n)) => panic!("unauthenticated candidate received {n} response bytes"),
            Ok(Err(e)) => panic!("failed while checking for cover-branch response bytes: {e}"),
        }
    }

    #[test]
    fn frozen_positive_vector_matches_independent_oracle_byte_for_byte() {
        let decoded = decode_vector(&POSITIVE_X25519);
        assert_eq!(decoded.client_hello.len(), 204);
        assert_eq!(decoded.client_hello[0], HS_CLIENT_HELLO);
        assert_eq!(decoded.client_hello[38], 0x20);
        assert_eq!(decoded.client_hello[39..71], decoded.sid[..]);
        let mut reconstructed_aad = decoded.client_hello.clone();
        reconstructed_aad[39..71].fill(0);
        assert_eq!(reconstructed_aad, decoded.aad);
        assert_eq!(decoded.plaintext.len(), 16);

        let server_private = hex_array::<32>(SERVER_STATIC_PRIVATE_HEX);
        let client_public = hex_array::<32>(CLIENT_X25519_PUBLIC_HEX);
        let shared = x25519(&server_private, &client_public).expect("vector ECDH");
        assert_eq!(shared.as_slice(), decoded.shared.as_slice());
        let auth_key = hkdf_sha256(&shared, &decoded.client_hello[6..26], b"REALITY", 32);
        assert_eq!(auth_key, decoded.auth_key);

        let parsed = parse_client_hello(decoded.client_hello.clone()).expect("vector parses");
        let server = vector_server();
        let (opened_key, plaintext) = server
            .open_auth_plaintext(&parsed)
            .expect("positive frozen vector must authenticate cryptographically");
        assert_eq!(opened_key.as_slice(), decoded.auth_key.as_slice());
        assert_eq!(plaintext, decoded.plaintext);
        let (version, reserved, unix_seconds, short_id) =
            parse_auth_plaintext(&plaintext).expect("16-byte auth plaintext parses");
        assert_eq!(version.as_slice(), hex_bytes(VERSION_HEX));
        assert_eq!(reserved, 0);
        assert_eq!(unix_seconds, UNIX_SECONDS as u32);
        assert_eq!(short_id.as_slice(), hex_bytes(SHORT_ID_HEX));
        assert!(
            server.classify(&parsed).is_some(),
            "positive vector also satisfies the frozen time window and Short ID"
        );
    }

    #[test]
    fn frozen_vector_key_material_is_bound_to_wire_bytes() {
        let positive = hex_bytes(POSITIVE_X25519.client_hello_hex);
        assert_eq!(&positive[6..38], &hex_bytes(RANDOM32_HEX));
        assert_eq!(
            x25519_public_from_private(&hex_array(SERVER_STATIC_PRIVATE_HEX)),
            hex_array::<32>(SERVER_STATIC_PUBLIC_HEX)
        );
        assert_eq!(
            x25519_public_from_private(&hex_array(CLIENT_X25519_PRIVATE_HEX)),
            hex_array::<32>(CLIENT_X25519_PUBLIC_HEX)
        );
        assert_eq!(
            x25519_public_from_private(&hex_array(HYBRID_X25519_PRIVATE_HEX)),
            hex_array::<32>(HYBRID_X25519_PUBLIC_HEX)
        );
        assert_eq!(
            x25519_public_from_private(&hex_array(WRONG_X25519_PRIVATE_HEX)),
            hex_array::<32>(WRONG_X25519_PUBLIC_HEX)
        );

        let mut hybrid_share = hex_bytes(MLKEM768_PUBLIC_HEX);
        hybrid_share.extend_from_slice(&hex_bytes(HYBRID_X25519_PUBLIC_HEX));
        for vector in [&POSITIVE_HYBRID, &DUAL_SHARE, &LOW_ORDER] {
            let hello = hex_bytes(vector.client_hello_hex);
            assert!(
                hello
                    .windows(hybrid_share.len())
                    .any(|window| window == hybrid_share),
                "{} must carry the frozen ML-KEM public key followed by the hybrid X25519 share",
                vector.name
            );
        }
        let duplicate = hex_bytes(DUPLICATE_KEY_SHARE.client_hello_hex);
        assert!(
            duplicate
                .windows(32)
                .any(|window| window == hex_bytes(WRONG_X25519_PUBLIC_HEX)),
            "the duplicate key_share vector carries the wrong second share as its negative control"
        );
    }

    #[test]
    fn fixed_leaf_hmac_and_certificate_verify_match_python_oracle() {
        let certificate =
            RealityCertificate::from_private_key_der(&hex_bytes(ED25519_PRIVATE_DER_HEX))
                .expect("fixed Ed25519 key");
        let auth_key = hex_array::<32>(POSITIVE_X25519.auth_key_hex);
        let leaf = certificate.for_auth_key(&auth_key);
        assert_eq!(leaf, hex_bytes(LEAF_DER_HEX));
        assert_eq!(
            &leaf[leaf.len() - 64..],
            &hex_bytes(CERTIFICATE_HMAC_HEX),
            "X.509 signatureValue content is exactly HMAC-SHA512(AuthKey, raw Ed25519 public key)"
        );

        let cv_input = certificate_verify_input(&hex_bytes(CV_TRANSCRIPT_HASH_HEX));
        assert_eq!(cv_input, hex_bytes(CV_INPUT_HEX));
        let cv_signature = certificate.sign(&cv_input).expect("sign fixed CV input");
        assert_eq!(
            cv_signature,
            hex_bytes(CV_SIGNATURE_HEX),
            "Ed25519 is deterministic; the signature must equal the Python cryptography oracle"
        );
        verify_ed25519_signature(&cv_signature, &cv_input);
    }

    #[tokio::test]
    async fn frozen_x25519_vector_completes_full_handshake_and_round_trips() {
        let mut completed = perform_vector_handshake(
            vector_server(),
            &POSITIVE_X25519,
            HelloFraming::SingleRecord,
        )
        .await;
        assert_eq!(completed.selected_group, GROUP_X25519);
        assert_eq!(completed.certificate_der, hex_bytes(LEAF_DER_HEX));
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn hybrid_only_vector_uses_final_32_bytes_and_completes() {
        let mut completed = perform_vector_handshake(
            vector_server(),
            &POSITIVE_HYBRID,
            HelloFraming::SingleRecord,
        )
        .await;
        assert_eq!(completed.selected_group, GROUP_X25519_MLKEM768);
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn dual_share_authentication_prefers_independent_x25519() {
        assert_eq!(DUAL_SHARE.shared_hex, POSITIVE_X25519.shared_hex);
        assert_ne!(DUAL_SHARE.shared_hex, POSITIVE_HYBRID.shared_hex);
        let mut completed =
            perform_vector_handshake(vector_server(), &DUAL_SHARE, HelloFraming::SingleRecord)
                .await;
        assert_eq!(
            completed.selected_group, GROUP_X25519_MLKEM768,
            "the TLS key exchange still prefers the offered hybrid share"
        );
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn single_bit_tampering_of_aad_ciphertext_or_tag_goes_to_cover() {
        let base = decode_vector(&POSITIVE_X25519).client_hello;
        for position in [
            6,                      // client_random[0]: HKDF salt and AAD
            PADDING_PAYLOAD_OFFSET, // ignored padding payload byte: pure AAD
            39,                     // first ciphertext byte
            54,                     // last ciphertext byte
            55,                     // first GCM tag byte
            70,                     // last GCM tag byte
        ] {
            let mut tampered = base.clone();
            tampered[position] ^= 1;
            let (relay, mut client_io) =
                accept_cover_for_bytes(vector_server(), &tampered, &[]).await;
            assert_eq!(
                relay.wire_prefix_len(),
                plaintext_record(&tampered).len(),
                "position {position}: cover receives exactly the consumed CH record"
            );
            assert_no_response_bytes(&mut client_io).await;
        }
    }

    #[tokio::test]
    async fn low_order_x25519_auth_share_is_rejected_without_panic() {
        assert_eq!(hex_bytes(LOW_ORDER.shared_hex), vec![0u8; 32]);
        let decoded = decode_vector(&LOW_ORDER);
        let (relay, mut client_io) =
            accept_cover_for_bytes(vector_server(), &decoded.client_hello, &[]).await;
        assert_eq!(
            relay.wire_prefix_len(),
            plaintext_record(&decoded.client_hello).len()
        );
        assert_no_response_bytes(&mut client_io).await;
    }

    #[tokio::test]
    async fn duplicate_key_share_and_supported_versions_are_rejected() {
        // Implementation semantics pinned here: a duplicate extension is
        // rejected outright.  The two key_share orders rule out both
        // first-wins and last-wins fallback interpretation.
        for vector in [
            &DUPLICATE_KEY_SHARE,
            &DUPLICATE_KEY_SHARE_REVERSED,
            &DUPLICATE_SUPPORTED_VERSIONS,
        ] {
            let decoded = decode_vector(vector);
            let (relay, mut client_io) =
                accept_cover_for_bytes(vector_server(), &decoded.client_hello, &[]).await;
            assert_eq!(
                relay.wire_prefix_len(),
                plaintext_record(&decoded.client_hello).len(),
                "{} duplicate extension must preserve exactly the CH wire prefix",
                vector.name
            );
            assert_no_response_bytes(&mut client_io).await;
        }
    }

    #[tokio::test]
    async fn byte_by_byte_tcp_fragmentation_has_the_same_authentication_result() {
        let mut completed =
            perform_vector_handshake(vector_server(), &POSITIVE_X25519, HelloFraming::ByteWiseTcp)
                .await;
        assert_eq!(completed.selected_group, GROUP_X25519);
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn pseudo_random_record_fragmentation_has_the_same_authentication_result() {
        const PATTERN: &[usize] = &[1, 2, 7, 3, 31, 5, 11, 13];
        let mut completed = perform_vector_handshake(
            vector_server(),
            &POSITIVE_X25519,
            HelloFraming::SplitRecords(PATTERN),
        )
        .await;
        assert_eq!(completed.selected_group, GROUP_X25519);
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn valid_client_hello_preflight_stops_exactly_before_trailing_bytes() {
        let hello = decode_vector(&POSITIVE_X25519).client_hello;
        let expected_prefix = plaintext_record(&hello);
        let trailing = b"already-readable trailing bytes";
        let mut batch = expected_prefix.clone();
        batch.extend_from_slice(trailing);
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&batch).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let (mut inner, preflight) = read_client_hello_preflight(Box::new(reader))
            .await
            .expect("valid vector preflight");
        let Preflight::Candidate { wire_prefix, .. } = preflight else {
            panic!("valid frozen vector must remain a REALITY candidate");
        };
        assert_eq!(wire_prefix, expected_prefix);
        let mut got = vec![0u8; trailing.len()];
        inner.read_exact(&mut got).await.unwrap();
        assert_eq!(got, trailing);
    }

    #[tokio::test]
    async fn trailing_bytes_in_same_write_are_not_consumed_from_cover_stream() {
        let mut tampered = decode_vector(&POSITIVE_X25519).client_hello;
        tampered[70] ^= 1;
        let trailing = b"trailing bytes in the same write batch";
        let expected_prefix = plaintext_record(&tampered);
        let (relay, client_io) = accept_cover_for_bytes(vector_server(), &tampered, trailing).await;
        assert_eq!(relay.wire_prefix_len(), expected_prefix.len());
        let (target_io, mut target_peer) = tokio::io::duplex(128 * 1024);
        let relay_task = tokio::spawn(async move { relay.relay(Box::new(target_io)).await });

        let mut got = vec![0u8; expected_prefix.len() + trailing.len()];
        target_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..expected_prefix.len()], &expected_prefix[..]);
        assert_eq!(&got[expected_prefix.len()..], trailing);
        drop(client_io);
        drop(target_peer);
        relay_task.abort();
    }

    #[tokio::test]
    async fn replayed_client_hello_is_accepted_but_replayed_old_finished_fails() {
        // REALITY deliberately has no nonce replay cache in the freshness
        // window: the same authenticated CH may open a new TLS transcript.
        // A replayed Finished is cryptographically bound to the old random
        // ServerHello/ephemeral share and must not validate on the new one.
        let server = vector_server();
        let first =
            perform_vector_handshake(server.clone(), &POSITIVE_X25519, HelloFraming::SingleRecord)
                .await;
        let old_finished = first.client_finished_record.clone();
        drop(first);

        let second =
            perform_vector_handshake(server.clone(), &POSITIVE_X25519, HelloFraming::SingleRecord)
                .await;
        assert_eq!(second.selected_group, GROUP_X25519);
        drop(second);

        let hello = decode_vector(&POSITIVE_X25519).client_hello;
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        client_io
            .write_all(&plaintext_record(&hello))
            .await
            .unwrap();
        client_io.write_all(&old_finished).await.unwrap();
        client_io.flush().await.unwrap();
        let accept_result = tokio::time::timeout(Duration::from_secs(2), accept_task)
            .await
            .expect("old-Finished accept timed out")
            .expect("old-Finished accept task joined");
        assert!(
            accept_result.is_err(),
            "a Finished replayed from the first transcript must fail on the second"
        );
    }

    #[tokio::test]
    async fn authenticated_reality_does_not_depend_on_cover_target_availability() {
        // The acceptor API has no cover dialer at all on the authenticated
        // branch.  Completing this handshake without any target object is the
        // transport-level proof that a down target cannot affect REALITY auth.
        let mut completed = perform_vector_handshake(
            vector_server(),
            &POSITIVE_X25519,
            HelloFraming::SingleRecord,
        )
        .await;
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn cover_drop_after_simulated_target_dial_failure_closes_client_cleanly() {
        // Ownership of dialing belongs to the inbound listener; the transport
        // contract exercised here is the failure path after that dial returns
        // error: drop the relay exactly once, with no background task or write.
        let mut tampered = decode_vector(&POSITIVE_X25519).client_hello;
        tampered[70] ^= 1;
        let (relay, mut client_io) = accept_cover_for_bytes(vector_server(), &tampered, &[]).await;
        drop(relay);
        let mut byte = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client_io.read(&mut byte))
            .await
            .expect("client close timed out")
            .expect("client close read");
        assert_eq!(
            n, 0,
            "dropping a never-dialed cover must close the client side"
        );
    }
}
