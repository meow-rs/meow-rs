//! REALITY server-side authentication, handshake and cover relay.
//!
//! The accepted stream is the client-side [`crate::reality_tls::RealityTlsStream`]
//! record implementation with its keys installed in the opposite directions.
//! This keeps one audited record-layer implementation and gives the inbound
//! the same independent raw-passthrough switches as the outbound.

use std::collections::HashSet;
use std::fmt;
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
    take_u8, verify_finished, wrap_plain_record, x25519, x25519_public_from_private,
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
    /// Test clock hook; production uses `None`.
    pub now_unix: Option<fn() -> u64>,
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
    now_unix: fn() -> u64,
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

fn default_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl RealityServer {
    pub fn new(config: &RealityServerConfig) -> Result<Self> {
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
                certificate: RealityCertificate::generate()?,
                now_unix: config.now_unix.unwrap_or(default_now_unix),
                #[cfg(test)]
                corrupt_certificate_verify: false,
            }),
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
        let auth_share = hello.auth_share()?;
        let shared = x25519(&self.inner.private_key, &auth_share).ok()?;
        let auth_key = hkdf_sha256(&shared, &hello.random[..20], b"REALITY", 32);

        let ciphertext = hello.session_id.get(..16)?;
        let tag = hello.session_id.get(16..32)?;
        let mut aad = hello.raw.clone();
        aad[39..71].fill(0);
        let plaintext = aes_gcm_open(&auth_key, &hello.random[20..32], ciphertext, tag, &aad)?;
        if plaintext.len() != 16 {
            return None;
        }
        let client_time = u32::from_be_bytes(plaintext[4..8].try_into().ok()?) as u64;
        if self.inner.max_time_difference != Duration::ZERO {
            let now = (self.inner.now_unix)();
            let window = self.inner.max_time_difference.as_secs();
            if now.abs_diff(client_time) > window {
                return None;
            }
        }
        let short_id: &[u8; 8] = plaintext[8..16].try_into().ok()?;
        let mut matched = subtle::Choice::from(0);
        for configured in &self.inner.short_ids {
            matched |= configured.ct_eq(short_id);
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
            auth_key: auth_key.try_into().expect("REALITY AuthKey length"),
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

        let ee = handshake_message(HS_ENCRYPTED_EXTENSIONS, &[]);
        transcript.extend_from_slice(&ee);
        let certificate_der = self.inner.certificate.for_auth_key(&prepared.auth_key);
        let certificate = certificate_message(&certificate_der);
        transcript.extend_from_slice(&certificate);

        let mut cv_body = Vec::with_capacity(2 + 2 + 64);
        put_u16(SIG_ED25519, &mut cv_body);
        put_u16(64, &mut cv_body);
        let mut signed = vec![0x20; 64];
        signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed.push(0);
        signed.extend_from_slice(&hash.digest(&transcript));
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
        let mut out = wrap_plain_record(TLS_RECORD_HANDSHAKE, &server_hello)?;
        out.extend_from_slice(&wrap_plain_record(TLS_RECORD_CHANGE_CIPHER_SPEC, &[1])?);
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
        match inner.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) => return Err(TransportError::Io(e)),
        }
        wire_prefix.extend_from_slice(&header);
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > MAX_PLAINTEXT_RECORD || len == 0 {
            return Err(TransportError::ResourceLimit(
                "REALITY ClientHello pre-read record length out of range".into(),
            ));
        }
        if wire_prefix.len() + len > MAX_AUTHED_STREAM_BYTES + 5 {
            return Err(TransportError::ResourceLimit(
                "REALITY ClientHello pre-read exceeds 64 KiB".into(),
            ));
        }
        let mut payload = vec![0u8; len];
        if let Err(e) = inner.read_exact(&mut payload).await {
            return Err(TransportError::Io(e));
        }
        wire_prefix.extend_from_slice(&payload);
        if header[0] != TLS_RECORD_HANDSHAKE {
            return Ok((inner, Preflight::Cover(wire_prefix)));
        }
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
    if !compression.contains(&0) {
        return Err(TransportError::Tls(
            "REALITY ClientHello lacks null compression".into(),
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

fn select_key_share(hello: &ClientHello) -> Option<ChosenKeyShare> {
    fn group_allowed(hello: &ClientHello, group: u16) -> bool {
        hello.supported_groups.is_empty() || hello.supported_groups.contains(&group)
    }
    if group_allowed(hello, GROUP_X25519_MLKEM768) {
        if let Some(entry) = hello.key_shares.iter().find(|entry| {
            entry.group == GROUP_X25519_MLKEM768 && entry.bytes.len() == HYBRID_SHARE_LEN
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
            .find(|entry| entry.group == GROUP_X25519 && entry.bytes.len() == 32)
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

    async fn wait(&mut self, bytes: usize) {
        if self.bytes_per_second == 0 {
            return;
        }
        let mut remaining = bytes as u64;
        if self.transferred < self.exempt_bytes {
            let exempt = remaining.min(self.exempt_bytes - self.transferred);
            self.transferred += exempt;
            remaining -= exempt;
        }
        self.transferred = self.transferred.saturating_add(remaining);
        while remaining > 0 {
            self.refill();
            if self.tokens == 0 {
                let nanos = 1_000_000_000u64 / self.bytes_per_second.max(1);
                tokio::time::sleep(Duration::from_nanos(nanos.max(1))).await;
                continue;
            }
            let used = remaining.min(self.tokens);
            self.tokens -= used;
            remaining -= used;
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.refill_at);
        if elapsed.is_zero() {
            return;
        }
        let add =
            (elapsed.as_nanos() * u128::from(self.bytes_per_second) / 1_000_000_000u128) as u64;
        if add > 0 {
            let spent = Duration::from_nanos(
                (u128::from(add) * 1_000_000_000u128 / u128::from(self.bytes_per_second)) as u64,
            );
            self.refill_at += spent;
            self.tokens = self.tokens.saturating_add(add).min(self.capacity);
        } else if elapsed.as_secs() >= 1 {
            self.refill_at = now;
        }
    }
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
        limit.wait(initial.len()).await;
        writer.write_all(&initial).await?;
        writer.flush().await?;
        let _ = activity.send(());
    }
    let mut buf = [0u8; COVER_BUFFER];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        limit.wait(n).await;
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        let _ = activity.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality_tls::{build_reality_client_hello, RealityTlsLayer};
    use crate::tls::TlsConfig;
    use crate::Transport;
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
            now_unix: Some(fixed_unix),
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
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let layer = RealityTlsLayer::new(&config).expect("client layer");
        let client_task = tokio::spawn(async move { layer.connect(Box::new(client_io)).await });
        let accepted = accept_task.await.expect("accept task").expect("accept");
        assert!(matches!(accepted, RealityServerAccept::Authenticated(_)));
        assert!(client_task.await.expect("client task").is_ok());
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
}
