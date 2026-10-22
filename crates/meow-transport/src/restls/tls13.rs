//! restls over TLS 1.3 — a record-level client handshake plus the tagged
//! data path, adapted from `reality_tls.rs` (which proved the record-level
//! TLS 1.3 client pattern in this crate) to upstream `restls-client-go`
//! semantics.
//!
//! Differences from `reality_tls`: the session_id carries the restls auth tag
//! `blake3(secret, keyshares)[:16]`; the cover certificate is verified for
//! real (Mozilla roots + hostname, or the configured pin); and the first
//! encrypted record may carry the server-auth mask, which decides whether the
//! connection continues as tagged restls or degrades to transparent TLS
//! (upstream `expectServerAuth`).

use std::collections::VecDeque;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::restls::conn::{CoverCipher, RestlsUpgraded};
use crate::restls::wire;
use crate::{Result, Stream, TransportError};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

pub(crate) const HS_CLIENT_HELLO: u8 = 1;
pub(crate) const HS_SERVER_HELLO: u8 = 2;
pub(crate) const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const HS_CERTIFICATE: u8 = 11;
pub(crate) const HS_CERTIFICATE_REQUEST: u8 = 13;
pub(crate) const HS_CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const HS_FINISHED: u8 = 20;
// Used by the jls post-handshake walker (`crate::jls`); dead under a
// restls-only build.
#[cfg_attr(not(feature = "jls"), allow(dead_code))]
pub(crate) const HS_KEY_UPDATE: u8 = 24;

pub(crate) const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub(crate) const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub(crate) const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

pub(crate) const GROUP_X25519: u16 = 0x001d;
pub(crate) const GROUP_P256: u16 = 0x0017;
pub(crate) const GROUP_P384: u16 = 0x0018;

/// RFC 8446 §4.1.3 — `SHA-256("HelloRetryRequest")`.
const HRR_RANDOM_MAGIC: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Bound on the pre-Finished server flight (same bar as `reality_tls`).
const MAX_PRE_AUTH_HS_MESSAGES: usize = 32;
const MAX_PRE_AUTH_TRANSCRIPT_LEN: usize = 1 << 20;

/// CCS record BoringSSL/utls-style clients send for middlebox compat.
const DUMMY_CCS: [u8; 6] = [
    wire::TLS_RECORD_CHANGE_CIPHER_SPEC,
    0x03,
    0x03,
    0x00,
    0x01,
    0x01,
];

/// Cover-certificate verification policy — shared by the TLS 1.3 and 1.2
/// record-level handshakes (upstream `ca` verifier semantics).
#[derive(Default)]
pub(crate) struct CertPolicy {
    /// Skip verification entirely (`skip-cert-verify`).
    pub(crate) skip_cert_verify: bool,
    /// DNS name to check — `name-cert-verify` override or SNI.
    pub(crate) verify_name: Option<String>,
    /// SHA-256 fingerprint of the cover cert (leaf or CA pin).
    pub(crate) cert_pin: Option<[u8; 32]>,
    /// Extra CA roots (DER) on top of the Mozilla bundle.
    pub(crate) additional_roots: Vec<Vec<u8>>,
}

/// Shared TLS 1.3 driver configuration — resolved options (restls's
/// `RestlsConfig`, jls's `JlsConfig`).
pub(crate) struct Tls13Config {
    /// Cover SNI (`host`).
    pub(crate) server_name: String,
    /// Certificate verification policy.
    pub(crate) cert: CertPolicy,
}

/// One ephemeral key share — one per advertised group so the cover never
/// needs HelloRetryRequest (which the restls server cannot relay; upstream
/// has the same constraint).
pub(crate) enum Ecdhe {
    X25519([u8; 32]),
    P256(boring::ec::EcKey<boring::pkey::Private>),
    P384(boring::ec::EcKey<boring::pkey::Private>),
}

pub(crate) struct KeyShare {
    pub(crate) group: u16,
    pub(crate) key: Ecdhe,
    /// Uncompressed public bytes as sent in the `key_share` extension.
    pub(crate) public: Vec<u8>,
}

impl KeyShare {
    pub(crate) fn generate(group: u16) -> Result<Self> {
        match group {
            GROUP_X25519 => {
                let mut private = rand::random::<[u8; 32]>();
                private[0] &= 248;
                private[31] &= 127;
                private[31] |= 64;
                let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
                Ok(Self {
                    group,
                    key: Ecdhe::X25519(private),
                    public: public.to_vec(),
                })
            }
            GROUP_P256 | GROUP_P384 => {
                let nid = if group == GROUP_P256 {
                    boring::nid::Nid::X9_62_PRIME256V1
                } else {
                    boring::nid::Nid::SECP384R1
                };
                let ec_group = boring::ec::EcGroup::from_curve_name(nid)
                    .map_err(|e| TransportError::Tls(format!("tls13: ec group: {e}")))?;
                let key = boring::ec::EcKey::generate(&ec_group)
                    .map_err(|e| TransportError::Tls(format!("tls13: ec generate: {e}")))?;
                let mut ctx = boring::bn::BigNumContext::new()
                    .map_err(|e| TransportError::Tls(format!("tls13: bn ctx: {e}")))?;
                let public = key
                    .public_key()
                    .to_bytes(
                        &ec_group,
                        boring::ec::PointConversionForm::UNCOMPRESSED,
                        &mut ctx,
                    )
                    .map_err(|e| TransportError::Tls(format!("tls13: ec pubkey: {e}")))?;
                Ok(Self {
                    group,
                    key: if group == GROUP_P256 {
                        Ecdhe::P256(key)
                    } else {
                        Ecdhe::P384(key)
                    },
                    public,
                })
            }
            _ => unreachable!(),
        }
    }

    /// ECDHE shared secret with the cover's key share.
    pub(crate) fn agree(&self, peer_public: &[u8]) -> Result<Vec<u8>> {
        match &self.key {
            Ecdhe::X25519(private) => {
                let peer: [u8; 32] = peer_public
                    .try_into()
                    .map_err(|_| TransportError::Tls("tls13: bad X25519 share".into()))?;
                let out = x25519_dalek::x25519(*private, peer);
                if out == [0u8; 32] {
                    return Err(TransportError::Tls("tls13: X25519 low-order".into()));
                }
                Ok(out.to_vec())
            }
            Ecdhe::P256(key) | Ecdhe::P384(key) => {
                let group = key.group();
                let mut ctx = boring::bn::BigNumContext::new()
                    .map_err(|e| TransportError::Tls(format!("tls13: bn ctx: {e}")))?;
                let point = boring::ec::EcPoint::from_bytes(group, peer_public, &mut ctx)
                    .map_err(|e| TransportError::Tls(format!("tls13: bad EC share: {e}")))?;
                let peer_key = boring::ec::EcKey::from_public_key(group, &point)
                    .map_err(|e| TransportError::Tls(format!("tls13: ec peer: {e}")))?;
                let pkey = boring::pkey::PKey::from_ec_key(peer_key)
                    .map_err(|e| TransportError::Tls(format!("tls13: pkey: {e}")))?;
                let ours = boring::pkey::PKey::from_ec_key(key.clone())
                    .map_err(|e| TransportError::Tls(format!("tls13: pkey: {e}")))?;
                let mut deriver = boring::derive::Deriver::new(&ours)
                    .map_err(|e| TransportError::Tls(format!("tls13: derive: {e}")))?;
                deriver
                    .set_peer(&pkey)
                    .map_err(|e| TransportError::Tls(format!("tls13: derive peer: {e}")))?;
                deriver
                    .derive_to_vec()
                    .map_err(|e| TransportError::Tls(format!("tls13: derive: {e}")))
            }
        }
    }
}

/// Offset of `random` inside a serialized ClientHello/ServerHello wire
/// message: type(1) ‖ length(3) ‖ legacy_version(2).
#[cfg(feature = "jls")]
pub(crate) const HELLO_RANDOM_OFFSET: usize = 6;
/// TLS hello `random` field length.
#[cfg(feature = "jls")]
pub(crate) const HELLO_RANDOM_LEN: usize = 32;
/// The ClientHello we sent plus the handshake facts the driver must
/// enforce: the verbatim session-id echo (RFC 8446 §4.1.3) and that the
/// server picked a suite we actually offered.
pub(crate) struct SentClientHello {
    /// Serialized hello — the exact bytes hashed into the transcript.
    pub(crate) hello: Vec<u8>,
    /// Compat `legacy_session_id` we sent.
    pub(crate) session_id: Vec<u8>,
    /// Cipher suites we offered.
    pub(crate) ciphers: &'static [u16],
}

/// Build a Chrome-parity middlebox-compat TLS 1.3 ClientHello shared by
/// restls and jls. `random`/`session_id`/`ciphers`/`alpn` are the
/// protocol-specific inputs; `offer_session_ticket` controls the empty
/// `session_ticket` extension (jls omits it — resumption cannot recompute
/// PSK binders over the patched random).
pub(crate) fn build_client_hello(
    server_name: &str,
    random: &[u8; 32],
    session_id: &[u8],
    ciphers: &'static [u16],
    alpn: &[&str],
    offer_session_ticket: bool,
    shares: &[KeyShare],
) -> Result<SentClientHello> {
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);

    put_u16((ciphers.len() * 2) as u16, &mut body);
    for c in ciphers {
        put_u16(*c, &mut body);
    }
    body.extend_from_slice(&[1, 0]); // legacy compression

    let mut exts = Vec::new();
    push_ext(&mut exts, 0, &server_name_ext(server_name)?);
    // supported_groups — exactly the groups we ship a share for.
    let groups: Vec<u16> = shares.iter().map(|s| s.group).collect();
    push_ext(&mut exts, 10, &u16_list_ext(&groups));
    push_ext(&mut exts, 11, &[1, 0]); // ec_point_formats: uncompressed
    push_ext(&mut exts, 13, &u16_list_ext(&SIG_ALGS));
    if !alpn.is_empty() {
        push_ext(&mut exts, 16, &alpn_ext(alpn)?);
    }
    if offer_session_ticket {
        push_ext(&mut exts, 35, &[]); // session_ticket (empty)
    }
    push_ext(&mut exts, 43, &[2, 0x03, 0x04]); // supported_versions: [1.3]
    push_ext(&mut exts, 45, &[1, 1]); // psk_key_exchange_modes: psk_dhe
    push_ext(&mut exts, 51, &key_share_ext(shares));

    put_u16(exts.len() as u16, &mut body);
    body.extend_from_slice(&exts);

    let mut hello = Vec::with_capacity(4 + body.len());
    hello.push(HS_CLIENT_HELLO);
    put_u24(body.len(), &mut hello);
    hello.extend_from_slice(&body);
    Ok(SentClientHello {
        hello,
        session_id: session_id.to_vec(),
        ciphers,
    })
}

/// Cipher suites the restls ClientHello offers — shared with the driver
/// so an unoffered suite in ServerHello is rejected.
const RESTLS_CIPHERS: [u16; 3] = [
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
];

/// Build the restls TLS 1.3 ClientHello. The session_id carries the auth tag
/// `blake3(secret, Σ(group‖share))[:16]` over the offered key shares —
/// upstream `generateSessionIDForTLS13` (psk identities are empty: no
/// resumption).
fn build_restls_client_hello(
    cfg: &Tls13Config,
    random: &[u8; 32],
    shares: &[KeyShare],
    secret: &[u8; 32],
) -> Result<SentClientHello> {
    let mut session_id = [0u8; 32];
    let mut tag = wire::restls_hasher(secret);
    for share in shares {
        tag.update(&share.group.to_be_bytes());
        tag.update(&share.public);
    }
    session_id[..wire::HANDSHAKE_MAC_LEN]
        .copy_from_slice(&tag.finalize().as_bytes()[..wire::HANDSHAKE_MAC_LEN]);
    session_id[wire::HANDSHAKE_MAC_LEN..].copy_from_slice(&rand::random::<[u8; 16]>());

    build_client_hello(
        &cfg.server_name,
        random,
        &session_id,
        &RESTLS_CIPHERS,
        &["h2", "http/1.1"],
        true,
        shares,
    )
}

/// Compat-CCS records tolerated while the cover's handshake flight is
/// in progress — middlebox noise is legal but unbounded CCS spam is not
/// (upstream bounds it via `maxUselessRecords`).
const MAX_FLIGHT_CCS: u32 = 32;

/// Signature algorithms offered for the cover's CertificateVerify.
pub(crate) const SIG_ALGS: [u16; 8] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0807, // ed25519
    0x0806, // rsa_pss_rsae_sha512
];

pub(crate) fn server_name_ext(server_name: &str) -> Result<Vec<u8>> {
    if server_name.len() > u16::MAX as usize {
        return Err(TransportError::Config("tls13: SNI too long".into()));
    }
    let mut name = Vec::new();
    name.push(0);
    put_u16(server_name.len() as u16, &mut name);
    name.extend_from_slice(server_name.as_bytes());
    let mut out = Vec::new();
    put_u16(name.len() as u16, &mut out);
    out.extend_from_slice(&name);
    Ok(out)
}

pub(crate) fn alpn_ext(alpn: &[&str]) -> Result<Vec<u8>> {
    let mut list = Vec::new();
    for proto in alpn {
        let b = proto.as_bytes();
        if b.len() > u8::MAX as usize {
            return Err(TransportError::Config("tls13: ALPN id too long".into()));
        }
        list.push(b.len() as u8);
        list.extend_from_slice(b);
    }
    let mut out = Vec::new();
    put_u16(list.len() as u16, &mut out);
    out.extend_from_slice(&list);
    Ok(out)
}

pub(crate) fn u16_list_ext(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + values.len() * 2);
    put_u16((values.len() * 2) as u16, &mut out);
    for v in values {
        put_u16(*v, &mut out);
    }
    out
}

pub(crate) fn key_share_ext(shares: &[KeyShare]) -> Vec<u8> {
    let mut entries = Vec::new();
    for share in shares {
        put_u16(share.group, &mut entries);
        put_u16(share.public.len() as u16, &mut entries);
        entries.extend_from_slice(&share.public);
    }
    let mut out = Vec::new();
    put_u16(entries.len() as u16, &mut out);
    out.extend_from_slice(&entries);
    out
}

pub(crate) fn push_ext(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    put_u16(typ, out);
    put_u16(data.len() as u16, out);
    out.extend_from_slice(data);
}

fn wrap_plain_record(typ: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(TransportError::Tls(
            "tls13: record payload too large".into(),
        ));
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(typ);
    out.extend_from_slice(&[0x03, 0x01]);
    put_u16(payload.len() as u16, &mut out);
    out.extend_from_slice(payload);
    Ok(out)
}

pub(crate) struct TlsRecord {
    pub(crate) header: [u8; 5],
    pub(crate) typ: u8,
    pub(crate) payload: Vec<u8>,
}

pub(crate) async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<TlsRecord>> {
    let mut header = [0u8; 5];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > wire::MAX_RECORD {
        return Err(TransportError::Tls(format!(
            "tls13: record too large {len}"
        )));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some(TlsRecord {
        header,
        typ: header[0],
        payload,
    }))
}

/// Read one plaintext handshake message with the expected type, skipping
/// CCS (bounded by `MAX_FLIGHT_CCS`). Handshake messages may be
/// fragmented across records — reassemble to the message boundary.
async fn read_plain_handshake<R: AsyncRead + Unpin>(
    r: &mut R,
    expected: u8,
    ccs: &mut u32,
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        let record = read_record(r)
            .await?
            .ok_or_else(|| TransportError::Tls("tls13: EOF reading ServerHello".into()))?;
        match record.typ {
            wire::TLS_RECORD_CHANGE_CIPHER_SPEC => {
                *ccs += 1;
                if *ccs > MAX_FLIGHT_CCS {
                    return Err(TransportError::Tls(
                        "restls: too many CCS records in server flight".into(),
                    ));
                }
                continue;
            }
            wire::TLS_RECORD_HANDSHAKE => {
                buf.extend_from_slice(&record.payload);
                if buf.len() > MAX_PRE_AUTH_TRANSCRIPT_LEN {
                    return Err(TransportError::Tls(
                        "tls13: oversized plaintext handshake".into(),
                    ));
                }
            }
            other => {
                return Err(TransportError::Tls(format!(
                    "tls13: expected handshake record, got {other}"
                )));
            }
        }
        if buf.len() < 4 {
            continue;
        }
        if buf[0] != expected {
            return Err(TransportError::Tls(
                "tls13: unexpected plaintext handshake".into(),
            ));
        }
        let len = read_u24(&buf[1..4]);
        if buf.len() < 4 + len {
            continue;
        }
        if buf.len() != 4 + len {
            return Err(TransportError::Tls(
                "tls13: unexpected plaintext handshake".into(),
            ));
        }
        return Ok(buf);
    }
}

pub(crate) struct ParsedServerHello {
    pub(crate) random: [u8; 32],
    pub(crate) session_id: Vec<u8>,
    pub(crate) cipher_suite: u16,
    pub(crate) key_share_group: u16,
    pub(crate) key_share: Vec<u8>,
}

pub(crate) fn parse_server_hello(raw: &[u8]) -> Result<ParsedServerHello> {
    if raw.len() < 42 || raw[0] != HS_SERVER_HELLO {
        return Err(TransportError::Tls("tls13: invalid ServerHello".into()));
    }
    let body_len = read_u24(&raw[1..4]);
    if raw.len() != 4 + body_len {
        return Err(TransportError::Tls("tls13: truncated ServerHello".into()));
    }
    let body = &raw[4..];
    if body[0..2] != [0x03, 0x03] {
        return Err(TransportError::Tls(
            "tls13: non-TLS1.3 legacy version".into(),
        ));
    }
    if body[2..34] == HRR_RANDOM_MAGIC {
        return Err(TransportError::Tls(
            "tls13: HelloRetryRequest is not supported".into(),
        ));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[2..34]);
    let mut pos = 34;
    let sid_len = take_u8(body, &mut pos)? as usize;
    let session_id = take(body, &mut pos, sid_len)?.to_vec();
    let cipher_suite = take_u16(body, &mut pos)?;
    let compression = take_u8(body, &mut pos)?;
    if compression != 0 {
        return Err(TransportError::Tls("tls13: SH compression != 0".into()));
    }
    let ext_len = take_u16(body, &mut pos)? as usize;
    let exts = take(body, &mut pos, ext_len)?;
    let mut key_share = None;
    let mut key_share_group = 0;
    let mut tls13 = false;
    let mut epos = 0;
    while epos < exts.len() {
        let typ = take_u16(exts, &mut epos)?;
        let len = take_u16(exts, &mut epos)? as usize;
        let data = take(exts, &mut epos, len)?;
        match typ {
            43 => tls13 = data == [0x03, 0x04],
            51 => {
                let mut p = 0;
                let group = take_u16(data, &mut p)?;
                let klen = take_u16(data, &mut p)? as usize;
                let bytes = take(data, &mut p, klen)?;
                key_share_group = group;
                key_share = Some(bytes.to_vec());
            }
            // Extensions forbidden in a TLS 1.3 ServerHello — upstream
            // `checkServerHelloOrHRR` alerts `unsupported_extension` on
            // these (they moved to EncryptedExtensions/Certificate or are
            // 1.2-only): status_request(5), alpn(16), sct(18),
            // extended_master_secret(23), session_ticket(35),
            // renegotiation_info(0xff01).
            5 | 16 | 18 | 23 | 35 | 0xff01 => {
                return Err(TransportError::Tls(format!(
                    "tls13: forbidden ServerHello extension {typ}"
                )));
            }
            _ => {}
        }
    }
    if !tls13 {
        return Err(TransportError::Tls(
            "tls13: server did not negotiate TLS 1.3".into(),
        ));
    }
    Ok(ParsedServerHello {
        random,
        session_id,
        cipher_suite,
        key_share_group,
        key_share: key_share
            .ok_or_else(|| TransportError::Tls("tls13: missing ServerHello key_share".into()))?,
    })
}

pub(crate) struct HandshakeMessage {
    pub(crate) typ: u8,
    pub(crate) body: Vec<u8>,
    pub(crate) raw: Vec<u8>,
}

pub(crate) fn pop_handshake_message(buf: &mut VecDeque<u8>) -> Option<HandshakeMessage> {
    if buf.len() < 4 {
        return None;
    }
    let header: Vec<u8> = buf.iter().copied().take(4).collect();
    let len = read_u24(&header[1..4]);
    if buf.len() < 4 + len {
        return None;
    }
    let raw = buf.drain(..4 + len).collect::<Vec<_>>();
    let body = raw[4..].to_vec();
    Some(HandshakeMessage {
        typ: raw[0],
        body,
        raw,
    })
}

/// Bounds-checked server flight — same bar as `reality_tls`'s guard, plus
/// the Certificate/CertificateVerify bodies are retained for verification.
#[derive(Default)]
struct ServerFlightGuard {
    message_count: usize,
    saw_encrypted_extensions: bool,
    saw_certificate: bool,
    saw_certificate_verify: bool,
    /// Server asked for a client certificate — we answer with an empty one.
    /// The request's `certificate_request_context` is echoed back per
    /// RFC 8446 §4.4.2 (always empty for server-initiated requests).
    saw_certificate_request: bool,
    cr_context: Vec<u8>,
    certificates: Vec<Vec<u8>>,
    cv_scheme: u16,
    cv_signature: Vec<u8>,
}

impl ServerFlightGuard {
    fn admit(&mut self, transcript: &mut Vec<u8>, msg: &HandshakeMessage) -> Result<()> {
        self.message_count += 1;
        if self.message_count > MAX_PRE_AUTH_HS_MESSAGES {
            return Err(TransportError::Tls(
                "tls13: server flight exceeded message bound".into(),
            ));
        }
        if transcript.len() + msg.raw.len() > MAX_PRE_AUTH_TRANSCRIPT_LEN {
            return Err(TransportError::Tls(
                "tls13: server flight exceeded transcript bound".into(),
            ));
        }
        match msg.typ {
            HS_ENCRYPTED_EXTENSIONS => {
                if self.saw_encrypted_extensions
                    || self.saw_certificate
                    || self.saw_certificate_verify
                {
                    return Err(TransportError::Tls("tls13: duplicate EE".into()));
                }
                self.saw_encrypted_extensions = true;
            }
            HS_CERTIFICATE => {
                if !self.saw_encrypted_extensions
                    || self.saw_certificate
                    || self.saw_certificate_verify
                {
                    return Err(TransportError::Tls("tls13: unexpected Certificate".into()));
                }
                self.saw_certificate = true;
                self.certificates = parse_certificate_list(&msg.body)?;
            }
            HS_CERTIFICATE_VERIFY => {
                if !self.saw_certificate || self.saw_certificate_verify {
                    return Err(TransportError::Tls("tls13: unexpected CV".into()));
                }
                self.saw_certificate_verify = true;
                let mut p = 0;
                self.cv_scheme = take_u16(&msg.body, &mut p)?;
                let sig_len = take_u16(&msg.body, &mut p)? as usize;
                self.cv_signature = take(&msg.body, &mut p, sig_len)?.to_vec();
            }
            HS_CERTIFICATE_REQUEST => {
                // Server flight order is EE → [CR] → Cert → CV → Fin —
                // a CR outside that slot is malformed.
                if !self.saw_encrypted_extensions
                    || self.saw_certificate
                    || self.saw_certificate_verify
                    || self.saw_certificate_request
                {
                    return Err(TransportError::Tls("restls: unexpected CR".into()));
                }
                self.saw_certificate_request = true;
                let mut p = 0;
                let ctx_len = take_u8(&msg.body, &mut p)? as usize;
                self.cr_context = take(&msg.body, &mut p, ctx_len)?.to_vec();
            }
            _ => {
                return Err(TransportError::Tls(format!(
                    "tls13: unexpected flight message {}",
                    msg.typ
                )))
            }
        }
        transcript.extend_from_slice(&msg.raw);
        Ok(())
    }

    fn complete(&self) -> bool {
        self.saw_encrypted_extensions && self.saw_certificate && self.saw_certificate_verify
    }
}

/// TLS 1.3 `Certificate` body → DER list (context byte + u24 list + entries).
pub(crate) fn parse_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut pos = 0;
    let ctx_len = take_u8(body, &mut pos)? as usize;
    take(body, &mut pos, ctx_len)?; // request_context
    let list_len = take_u24(body, &mut pos)?;
    let list = take(body, &mut pos, list_len)?;
    let mut certs = Vec::new();
    let mut lp = 0;
    while lp < list.len() {
        let clen = take_u24(list, &mut lp)?;
        certs.push(take(list, &mut lp, clen)?.to_vec());
        let ext_len = take_u16(list, &mut lp)? as usize;
        take(list, &mut lp, ext_len)?; // per-cert extensions
    }
    if certs.is_empty() {
        return Err(TransportError::Tls("tls13: empty certificate list".into()));
    }
    Ok(certs)
}

/// CV schemes legal in TLS 1.3 — `SIG_ALGS` minus PKCS#1 v1.5
/// (`0x0401`/`0x0501`), which RFC 8446 §4.4.3 forbids in
/// CertificateVerify even when offered in `signature_algorithms`.
/// Anything never offered is rejected the same way — matching
/// upstream's `isSupportedSignatureAlgorithm` gate.
const TLS13_CV_SCHEMES: [u16; 6] = [0x0403, 0x0804, 0x0503, 0x0805, 0x0807, 0x0806];

/// Verify the cover's CertificateVerify over the running transcript.
fn verify_certificate_verify(
    cipher: CipherSuite,
    scheme: u16,
    signature: &[u8],
    leaf_der: &[u8],
    transcript: &[u8],
) -> Result<()> {
    if !TLS13_CV_SCHEMES.contains(&scheme) {
        return Err(TransportError::Tls(format!(
            "restls: CV scheme 0x{scheme:04x} unoffered or illegal in TLS 1.3"
        )));
    }
    // TLS 1.3 CV content: 64×0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash.
    let mut content = Vec::with_capacity(64 + 34 + 64);
    content.extend_from_slice(&[0x20u8; 64]);
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
    content.extend_from_slice(&cipher.hash().digest(transcript));
    verify_signature(scheme, signature, &content, leaf_der)
}

/// Verify a TLS `SignatureScheme` signature over `content` with the leaf
/// cert's public key — shared by TLS 1.3 CertificateVerify and the TLS 1.2
/// ServerKeyExchange signature.
pub(crate) fn verify_signature(
    scheme: u16,
    signature: &[u8],
    content: &[u8],
    leaf_der: &[u8],
) -> Result<()> {
    let cert = boring::x509::X509::from_der(leaf_der)
        .map_err(|e| TransportError::Tls(format!("tls13: bad leaf cert: {e}")))?;
    let pkey = cert
        .public_key()
        .map_err(|e| TransportError::Tls(format!("tls13: leaf pubkey: {e}")))?;

    use boring::sign::Verifier;
    let (md, pss) = match scheme {
        // RSA-PSS with digest-length salt.
        0x0804 => (Some(boring::hash::MessageDigest::sha256()), true),
        0x0805 => (Some(boring::hash::MessageDigest::sha384()), true),
        0x0806 => (Some(boring::hash::MessageDigest::sha512()), true),
        // RSA PKCS#1 v1.5 and ECDSA share the plain-digest path.
        0x0401 | 0x0403 => (Some(boring::hash::MessageDigest::sha256()), false),
        0x0501 | 0x0503 => (Some(boring::hash::MessageDigest::sha384()), false),
        0x0601 | 0x0603 => (Some(boring::hash::MessageDigest::sha512()), false),
        // Ed25519 — no digest.
        0x0807 => (None, false),
        other => {
            return Err(TransportError::Tls(format!(
                "tls13: unsupported CV scheme 0x{other:04x}"
            )))
        }
    };
    let mut verifier = match md {
        Some(md) => Verifier::new(md, &pkey),
        None => Verifier::new_without_digest(&pkey),
    }
    .map_err(|e| TransportError::Tls(format!("tls13: CV verifier: {e}")))?;
    if pss {
        let md = md.expect("pss digest");
        verifier
            .set_rsa_padding(boring::rsa::Padding::PKCS1_PSS)
            .map_err(|e| TransportError::Tls(format!("tls13: CV pad: {e}")))?;
        verifier
            .set_rsa_pss_saltlen(boring::sign::RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| TransportError::Tls(format!("tls13: CV salt: {e}")))?;
        verifier
            .set_rsa_mgf1_md(md)
            .map_err(|e| TransportError::Tls(format!("tls13: CV mgf1: {e}")))?;
    }

    verifier
        .update(content)
        .map_err(|e| TransportError::Tls(format!("tls13: CV update: {e}")))?;
    let ok = verifier
        .verify(signature)
        .map_err(|e| TransportError::Tls(format!("tls13: CV verify: {e}")))?;
    if !ok {
        return Err(TransportError::Tls(
            "tls13: CertificateVerify mismatch".into(),
        ));
    }
    Ok(())
}

/// Verify the cover certificate chain per `policy` — `cert_pin` (leaf or CA
/// pin) → `skip_cert_verify` → Mozilla roots + `name` check.
pub(crate) fn verify_certificate_chain(
    policy: &CertPolicy,
    name: &str,
    certs: &[Vec<u8>],
) -> Result<()> {
    use boring::stack::Stack;
    use boring::x509::X509StoreContext;
    use sha2::Sha256;

    let leaf = boring::x509::X509::from_der(&certs[0])
        .map_err(|e| TransportError::Tls(format!("tls13: leaf DER: {e}")))?;
    let mut chain = Stack::new().map_err(|e| TransportError::Tls(format!("tls13: stack: {e}")))?;
    for der in &certs[1..] {
        let c = boring::x509::X509::from_der(der)
            .map_err(|e| TransportError::Tls(format!("tls13: chain DER: {e}")))?;
        chain
            .push(c)
            .map_err(|e| TransportError::Tls(format!("tls13: chain push: {e}")))?;
    }

    // Fingerprint pin — upstream `ca.NewFingerprintVerifier` semantics:
    // a pin matching the leaf accepts directly; a pin matching a chain
    // cert verifies the chain up to the pinned CA plus the name check.
    if let Some(pin) = &policy.cert_pin {
        for (i, der) in certs.iter().enumerate() {
            use subtle::ConstantTimeEq;
            if bool::from(Sha256::digest(der).as_slice().ct_eq(pin.as_slice())) {
                if i == 0 {
                    return Ok(());
                }
                // CA pin: verify leaf against a store holding the pinned cert.
                let pinned = boring::x509::X509::from_der(der)
                    .map_err(|e| TransportError::Tls(format!("tls13: pinned cert DER: {e}")))?;
                let mut builder = boring::x509::store::X509StoreBuilder::new()
                    .map_err(|e| TransportError::Tls(format!("tls13: store: {e}")))?;
                builder
                    .add_cert(pinned)
                    .map_err(|e| TransportError::Tls(format!("tls13: pin store: {e}")))?;
                builder
                    .verify_param_mut()
                    .set_host(name)
                    .map_err(|e| TransportError::Tls(format!("tls13: pin host: {e}")))?;
                let store = builder.build();
                let mut ctx = X509StoreContext::new()
                    .map_err(|e| TransportError::Tls(format!("tls13: ctx: {e}")))?;
                let (verified, err) = ctx
                    .init(&store, &leaf, &chain, |c| {
                        c.verify_cert().map(|ok| (ok, c.verify_result().err()))
                    })
                    .map_err(|e| TransportError::Tls(format!("tls13: pin verify: {e}")))?;
                return if verified {
                    Ok(())
                } else {
                    Err(TransportError::Tls(format!(
                        "tls13: pinned CA did not verify the chain: {}",
                        err.map_or("unknown", |e| e.error_string())
                    )))
                };
            }
        }
        return Err(TransportError::Tls(
            "tls13: certificate fingerprint mismatch".into(),
        ));
    }

    if policy.skip_cert_verify {
        return Ok(());
    }

    let mut builder = crate::tls::boring_backend::build_root_store(&policy.additional_roots)?;
    if !name.is_empty() {
        builder
            .verify_param_mut()
            .set_host(name)
            .map_err(|e| TransportError::Tls(format!("tls13: verify host: {e}")))?;
    }
    let store = builder.build();
    let mut ctx =
        X509StoreContext::new().map_err(|e| TransportError::Tls(format!("tls13: ctx: {e}")))?;
    let (verified, err) = ctx
        .init(&store, &leaf, &chain, |c| {
            c.verify_cert().map(|ok| {
                if ok
                    && c.chain()
                        .is_some_and(crate::tls::distrust::chain_is_distrusted)
                {
                    return (false, Some(boring::x509::X509VerifyError::CERT_REVOKED));
                }
                (ok, c.verify_result().err())
            })
        })
        .map_err(|e| TransportError::Tls(format!("tls13: verify: {e}")))?;
    if !verified {
        return Err(TransportError::Tls(format!(
            "tls13: certificate verification failed: {}",
            err.map_or("unknown", |e| e.error_string())
        )));
    }
    Ok(())
}

// ---- key schedule -------------------------------------------------------

/// TLS 1.3 hash algorithm — SHA-256 or SHA-384 depending on the suite.
#[derive(Clone, Copy)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    pub(crate) fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => {
                let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
                h.update(data);
                h.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut h = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
                h.update(data);
                h.finalize().into_bytes().to_vec()
            }
        }
    }

    pub(crate) fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        self.hmac(salt, ikm)
    }

    pub(crate) fn expand(self, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut okm = Vec::with_capacity(len);
        let mut previous = Vec::new();
        let mut counter = 1u8;
        while okm.len() < len {
            let mut hmac_input = Vec::with_capacity(previous.len() + info.len() + 1);
            hmac_input.extend_from_slice(&previous);
            hmac_input.extend_from_slice(info);
            hmac_input.push(counter);
            previous = self.hmac(prk, &hmac_input);
            okm.extend_from_slice(&previous);
            counter = counter.checked_add(1).expect("HKDF too long");
        }
        okm.truncate(len);
        okm
    }

    pub(crate) fn expand_label(
        self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Vec<u8> {
        let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
        put_u16(len as u16, &mut info);
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.expand(secret, &info, len)
    }

    pub(crate) fn derive_secret(
        self,
        secret: &[u8],
        label: &[u8],
        transcript_hash: &[u8],
    ) -> Vec<u8> {
        self.expand_label(secret, label, transcript_hash, self.len())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    pub(crate) fn try_from(value: u16) -> Result<Self> {
        match value {
            TLS_AES_128_GCM_SHA256 => Ok(Self::Aes128GcmSha256),
            TLS_AES_256_GCM_SHA384 => Ok(Self::Aes256GcmSha384),
            TLS_CHACHA20_POLY1305_SHA256 => Ok(Self::ChaCha20Poly1305Sha256),
            other => Err(TransportError::Tls(format!(
                "tls13: unsupported cipher suite 0x{other:04x}"
            ))),
        }
    }

    pub(crate) fn hash(self) -> HashAlg {
        match self {
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => HashAlg::Sha256,
            Self::Aes256GcmSha384 => HashAlg::Sha384,
        }
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }
}

/// AEAD record key — TLS 1.3 traffic keys with implicit sequence numbers.
/// The traffic secret is retained so a post-handshake KeyUpdate can
/// derive the next generation (`application_traffic_secret_N+1`).
pub(crate) struct RecordKey {
    cipher: CipherSuite,
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKey {
    pub(crate) fn new(cipher: CipherSuite, secret: &[u8]) -> Self {
        let key = cipher
            .hash()
            .expand_label(secret, b"key", &[], cipher.key_len());
        let iv_vec = cipher.hash().expand_label(secret, b"iv", &[], 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);
        Self {
            cipher,
            secret: secret.to_vec(),
            key,
            iv,
            seq: 0,
        }
    }

    /// `HKDF-Expand-Label(secret, "traffic upd", "", Hash.length)` — RFC
    /// 8446 §7.2 key update; resets the record sequence.
    pub(crate) fn rekey(&mut self) {
        self.secret = self.cipher.hash().expand_label(
            &self.secret,
            b"traffic upd",
            &[],
            self.cipher.hash().len(),
        );
        self.key =
            self.cipher
                .hash()
                .expand_label(&self.secret, b"key", &[], self.cipher.key_len());
        let iv_vec = self
            .cipher
            .hash()
            .expand_label(&self.secret, b"iv", &[], 12);
        self.iv.copy_from_slice(&iv_vec);
        self.seq = 0;
    }

    /// Seal a `key_update_not_requested` response, then rekey — per RFC
    /// 8446 the responder updates its sending keys after sending.
    pub(crate) fn seal_key_update_response(&mut self) -> Option<Vec<u8>> {
        const KEY_UPDATE_NOT_REQUESTED: [u8; 5] = [24, 0, 0, 1, 0];
        let record = self
            .seal(wire::TLS_RECORD_HANDSHAKE, &KEY_UPDATE_NOT_REQUESTED)
            .ok()?;
        self.rekey();
        Some(record)
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for (dst, src) in nonce[4..].iter_mut().zip(seq) {
            *dst ^= src;
        }
        self.seq += 1;
        nonce
    }

    /// Current nonce without consuming the sequence (the restls server-auth
    /// probe opens the first record twice — once masked, once raw).
    fn peek_nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for (dst, src) in nonce[4..].iter_mut().zip(seq) {
            *dst ^= src;
        }
        nonce
    }

    /// Seal `body` as one TLS 1.3 record (inner content type appended).
    pub(crate) fn seal(&mut self, inner_type: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(plaintext.len() + 1 + 16);
        body.extend_from_slice(plaintext);
        body.push(inner_type);
        let record_len = body.len() + 16;
        if record_len > u16::MAX as usize {
            return Err(TransportError::Tls("tls13: record too large".into()));
        }
        let mut header = Vec::with_capacity(5);
        header.push(wire::TLS_RECORD_APPLICATION_DATA);
        header.extend_from_slice(&[0x03, 0x03]);
        put_u16(record_len as u16, &mut header);
        let nonce = self.next_nonce();
        let tag = self.encrypt_detached(&nonce, &header, &mut body)?;
        header.extend_from_slice(&body);
        header.extend_from_slice(&tag);
        Ok(header)
    }

    /// Open one TLS 1.3 record; returns `(inner_type, plaintext)`.
    pub(crate) fn open(&mut self, header: &[u8; 5], ciphertext: &[u8]) -> Result<(u8, Vec<u8>)> {
        if ciphertext.len() < 16 {
            return Err(TransportError::Tls("tls13: short ciphertext".into()));
        }
        let split = ciphertext.len() - 16;
        let mut body = ciphertext[..split].to_vec();
        let tag = ciphertext[split..].to_vec();
        let nonce = self.peek_nonce();
        self.decrypt_detached(&nonce, header, &mut body, &tag)?;
        self.seq += 1;
        let Some(pos) = body.iter().rposition(|b| *b != 0) else {
            return Err(TransportError::Tls("tls13: missing inner type".into()));
        };
        let inner_type = body[pos];
        body.truncate(pos);
        Ok((inner_type, body))
    }

    fn encrypt_detached(&self, nonce: &[u8; 12], aad: &[u8], body: &mut [u8]) -> Result<Vec<u8>> {
        match self.cipher {
            CipherSuite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(&self.key)
                .expect("aes128 key")
                .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, body)
                .map(|t| t.to_vec())
                .map_err(|e| TransportError::Tls(format!("tls13: seal: {e}"))),
            CipherSuite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(&self.key)
                .expect("aes256 key")
                .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, body)
                .map(|t| t.to_vec())
                .map_err(|e| TransportError::Tls(format!("tls13: seal: {e}"))),
            CipherSuite::ChaCha20Poly1305Sha256 => {
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("chacha20 key")
                    .encrypt_in_place_detached(
                        chacha20poly1305::Nonce::from_slice(nonce),
                        aad,
                        body,
                    )
                    .map(|t| t.to_vec())
                    .map_err(|e| TransportError::Tls(format!("tls13: seal: {e}")))
            }
        }
    }

    fn decrypt_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Result<()> {
        let tag = Tag::from_slice(tag);
        match self.cipher {
            CipherSuite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(&self.key)
                .expect("aes128 key")
                .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, body, tag)
                .map_err(|e| TransportError::Tls(format!("tls13: open: {e}"))),
            CipherSuite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(&self.key)
                .expect("aes256 key")
                .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, body, tag)
                .map_err(|e| TransportError::Tls(format!("tls13: open: {e}"))),
            CipherSuite::ChaCha20Poly1305Sha256 => {
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("chacha20 key")
                    .decrypt_in_place_detached(
                        chacha20poly1305::Nonce::from_slice(nonce),
                        aad,
                        body,
                        chacha20poly1305::Tag::from_slice(tag),
                    )
                    .map_err(|e| TransportError::Tls(format!("tls13: open: {e}")))
            }
        }
    }
}

impl CoverCipher for RecordKey {
    fn open(&mut self, record: &mut [u8]) -> Option<(u8, Vec<u8>)> {
        if record.len() < 5 {
            return None;
        }
        let header: [u8; 5] = record[..5].try_into().ok()?;
        self.open(&header, &record[5..]).ok()
    }

    fn rekey(&mut self) {
        self.rekey();
    }

    fn seal_key_update_response(&mut self) -> Option<Vec<u8>> {
        self.seal_key_update_response()
    }

    fn seal(&mut self, body: &[u8]) -> Vec<u8> {
        // Fragment at the TLS plaintext limit — a >64KiB write would
        // otherwise overflow the record length field.
        let mut out = Vec::new();
        for chunk in body.chunks(wire::MAX_PLAINTEXT) {
            match self.seal(wire::TLS_RECORD_APPLICATION_DATA, chunk) {
                Ok(rec) => out.extend_from_slice(&rec),
                Err(_) => break,
            }
        }
        out
    }

    fn seal_close_notify(&mut self) -> Vec<u8> {
        // [warning, close_notify] — inner alert type under a data record.
        self.seal(wire::TLS_RECORD_ALERT, &[0x01, 0x00])
            .unwrap_or_default()
    }
}

struct HandshakeKeys {
    client: RecordKey,
    server: RecordKey,
    client_secret: Vec<u8>,
    server_secret: Vec<u8>,
    master_secret: Vec<u8>,
}

impl HandshakeKeys {
    fn derive(cipher: CipherSuite, shared_secret: &[u8], transcript: &[u8]) -> Self {
        let hash = cipher.hash();
        let zero = vec![0u8; hash.len()];
        let empty_hash = hash.digest(&[]);
        let early_secret = hash.extract(&zero, &zero);
        let derived = hash.derive_secret(&early_secret, b"derived", &empty_hash);
        let handshake_secret = hash.extract(&derived, shared_secret);
        let transcript_hash = hash.digest(transcript);
        let client_secret =
            hash.derive_secret(&handshake_secret, b"c hs traffic", &transcript_hash);
        let server_secret =
            hash.derive_secret(&handshake_secret, b"s hs traffic", &transcript_hash);
        let derived = hash.derive_secret(&handshake_secret, b"derived", &empty_hash);
        let master_secret = hash.extract(&derived, &zero);
        Self {
            client: RecordKey::new(cipher, &client_secret),
            server: RecordKey::new(cipher, &server_secret),
            client_secret,
            server_secret,
            master_secret,
        }
    }
}

fn verify_finished(
    cipher: CipherSuite,
    secret: &[u8],
    transcript: &[u8],
    received: &[u8],
) -> Result<()> {
    let finished_key = cipher
        .hash()
        .expand_label(secret, b"finished", &[], cipher.hash().len());
    let expected = cipher
        .hash()
        .hmac(&finished_key, &cipher.hash().digest(transcript));
    use subtle::ConstantTimeEq;
    if bool::from(expected.as_slice().ct_eq(received)) {
        Ok(())
    } else {
        Err(TransportError::Tls(
            "tls13: server Finished mismatch".into(),
        ))
    }
}

fn finished_verify_data(cipher: CipherSuite, secret: &[u8], transcript: &[u8]) -> Vec<u8> {
    let finished_key = cipher
        .hash()
        .expand_label(secret, b"finished", &[], cipher.hash().len());
    cipher
        .hash()
        .hmac(&finished_key, &cipher.hash().digest(transcript))
}

// ---- byte helpers --------------------------------------------------------

pub(crate) fn take<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| TransportError::Tls("tls13: parser overflow".into()))?;
    let out = input
        .get(*pos..end)
        .ok_or_else(|| TransportError::Tls("tls13: truncated input".into()))?;
    *pos = end;
    Ok(out)
}

pub(crate) fn take_u8(input: &[u8], pos: &mut usize) -> Result<u8> {
    Ok(take(input, pos, 1)?[0])
}

pub(crate) fn take_u16(input: &[u8], pos: &mut usize) -> Result<u16> {
    let b = take(input, pos, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

pub(crate) fn take_u24(input: &[u8], pos: &mut usize) -> Result<usize> {
    Ok(read_u24(take(input, pos, 3)?))
}

pub(crate) fn read_u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

pub(crate) fn put_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u24(value: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(&[(value >> 16) as u8, (value >> 8) as u8, value as u8]);
}

// ---- handshake driver ----------------------------------------------------

/// Post-handshake state produced by [`drive_tls13`] — each protocol
/// (`restls`, `jls`) wraps it in its own stream type.
pub(crate) struct Tls13Outcome<S> {
    pub(crate) inner: S,
    pub(crate) server_random: [u8; 32],
    /// The sealed client-Finished record (restls mixes it into the first
    /// tagged-record MAC).
    pub(crate) client_finished: Vec<u8>,
    /// `Some(authed)` when restls server-auth mask detection ran; `None`
    /// when `mask_secret` was not supplied (jls authenticates via the
    /// ServerHello random instead).
    pub(crate) masked_auth: Option<bool>,
    /// The `check_sh` verdict — `true` means the peer authenticated via
    /// its hello random and certificate checks were skipped (jls).
    /// Always `false` for restls, where auth is orthogonal to PKI.
    pub(crate) random_authed: bool,
    pub(crate) cipher: CipherSuite,
    pub(crate) client_ap_secret: Vec<u8>,
    pub(crate) server_ap_secret: Vec<u8>,
    /// Undecoded handshake bytes buffered past the server Finished — a
    /// record may coalesce post-handshake messages (NST, KeyUpdate) after
    /// Finished, or end mid-message. Consumers that reassemble post-
    /// handshake messages (jls) must seed their buffer with this.
    pub(crate) leftover_handshake: Vec<u8>,
}

/// Shared record-level TLS 1.3 handshake driver used by restls and jls.
///
/// The caller builds the ClientHello (`sent` — `sent.hello` is hashed
/// into the transcript and must be exactly what is sent; the driver
/// enforces the RFC 8446 §4.1.3 session-id echo and rejects a suite
/// outside `sent.ciphers` — both protocol-agnostic), and supplies
/// `check_sh`, which inspects the parsed ServerHello plus its raw wire
/// form for the protocol's auth scheme and returns whether the session
/// is authenticated-by-hello-random — when `true` the certificate chain
/// and CertificateVerify signature checks are skipped (upstream
/// `jlsAuthenticated()` semantics: the camouflage cert is a throwaway).
/// `mask_secret` enables the restls `expectServerAuth` probe on the
/// first encrypted flight record.
pub(crate) async fn drive_tls13<S>(
    mut inner: S,
    cfg: &Tls13Config,
    sent: SentClientHello,
    shares: &[KeyShare],
    mask_secret: Option<&[u8; 32]>,
    check_sh: impl Fn(&ParsedServerHello, &[u8]) -> Result<bool>,
) -> Result<Tls13Outcome<S>>
where
    S: Stream,
{
    // Chrome-parity compat CCS follows the ClientHello immediately.
    inner
        .write_all(&wrap_plain_record(wire::TLS_RECORD_HANDSHAKE, &sent.hello)?)
        .await?;
    inner.write_all(&DUMMY_CCS).await?;
    inner.flush().await?;

    let mut transcript = Vec::with_capacity(4096);
    transcript.extend_from_slice(&sent.hello);

    // Stray pre-handshake CCS is legal middlebox noise — count it only
    // to bound the streak.
    let mut server_ccs = 0u32;
    let server_hello = read_plain_handshake(&mut inner, HS_SERVER_HELLO, &mut server_ccs).await?;
    let parsed = parse_server_hello(&server_hello)?;
    // RFC 8446 §4.1.3: middlebox-compat mode requires the server to echo
    // the client's legacy_session_id verbatim.
    if parsed.session_id != sent.session_id {
        return Err(TransportError::Tls(
            "tls13: server did not echo the session_id".into(),
        ));
    }
    if !sent.ciphers.contains(&parsed.cipher_suite) {
        return Err(TransportError::Tls(format!(
            "tls13: server chose an unoffered cipher suite 0x{:04x}",
            parsed.cipher_suite
        )));
    }
    let random_authed = check_sh(&parsed, &server_hello)?;
    let share = shares
        .iter()
        .find(|s| s.group == parsed.key_share_group)
        .ok_or_else(|| TransportError::Tls("tls13: unoffered key_share group".into()))?;
    let shared_secret = share.agree(&parsed.key_share)?;
    transcript.extend_from_slice(&server_hello);
    let server_random = parsed.random;

    let cipher = CipherSuite::try_from(parsed.cipher_suite)?;
    let hs = HandshakeKeys::derive(cipher, &shared_secret, &transcript);
    let mut server_hs = hs.server;
    let mut client_hs = hs.client;

    let mut handshake_buf: VecDeque<u8> = VecDeque::new();
    let mut flight = ServerFlightGuard::default();
    let mut authed: Option<bool> = None;

    'flight: loop {
        let record = read_record(&mut inner)
            .await?
            .ok_or_else(|| TransportError::Tls("tls13: EOF in server flight".into()))?;
        if record.typ == wire::TLS_RECORD_CHANGE_CIPHER_SPEC {
            server_ccs += 1;
            if server_ccs > MAX_FLIGHT_CCS {
                return Err(TransportError::Tls(
                    "restls: too many CCS records in server flight".into(),
                ));
            }
            continue;
        }
        if record.typ != wire::TLS_RECORD_APPLICATION_DATA {
            return Err(TransportError::Tls(format!(
                "tls13: unexpected record type {} in server flight",
                record.typ
            )));
        }

        if let (None, Some(secret)) = (authed, mask_secret) {
            let mut full = record.header.to_vec();
            full.extend_from_slice(&record.payload);
            // Upstream probes the mask on the first encrypted record
            // whenever the server installed its handshake cipher exactly
            // once (`numCipherChange` counts cipher installations — not
            // CCS records). Probe unconditionally: a cover emitting zero
            // or several compat CCS records must not skip it.
            let (unmasked, _) = wire::unmask_server_auth(&full, secret, &server_random, false);
            let (typ, body) =
                match server_hs.open(&unmasked[..5].try_into().expect("header"), &unmasked[5..]) {
                    Ok((typ, body)) => {
                        authed = Some(true);
                        (typ, body)
                    }
                    Err(_) => {
                        authed = Some(false);
                        server_hs.open(&record.header, &record.payload)?
                    }
                };
            if typ != wire::TLS_RECORD_HANDSHAKE {
                return Err(TransportError::Tls(if authed == Some(true) {
                    "tls13: masked record was not handshake data".into()
                } else {
                    "tls13: unexpected early application data".into()
                }));
            }
            handshake_buf.extend(body);
        } else {
            let (typ, body) = server_hs.open(&record.header, &record.payload)?;
            if typ != wire::TLS_RECORD_HANDSHAKE {
                return Err(TransportError::Tls(
                    "tls13: unexpected mid-flight record".into(),
                ));
            }
            handshake_buf.extend(body);
        }
        // A dribbled 16 MiB (u24) message must not grow the reassembly
        // buffer without bound — the transcript cap alone doesn't reach it.
        if handshake_buf.len() > MAX_PRE_AUTH_TRANSCRIPT_LEN {
            return Err(TransportError::Tls("tls13: server flight too large".into()));
        }

        while let Some(msg) = pop_handshake_message(&mut handshake_buf) {
            match msg.typ {
                HS_ENCRYPTED_EXTENSIONS | HS_CERTIFICATE | HS_CERTIFICATE_REQUEST => {
                    flight.admit(&mut transcript, &msg)?;
                }
                HS_CERTIFICATE_VERIFY => {
                    flight.admit(&mut transcript, &msg)?;
                    if !random_authed {
                        verify_certificate_verify(
                            cipher,
                            flight.cv_scheme,
                            &flight.cv_signature,
                            &flight.certificates[0],
                            // Transcript hash must exclude the CV itself.
                            &transcript[..transcript.len() - msg.raw.len()],
                        )?;
                    }
                }
                HS_FINISHED => {
                    if !flight.complete() {
                        return Err(TransportError::Tls(
                            "tls13: Finished before complete server flight".into(),
                        ));
                    }
                    verify_finished(cipher, &hs.server_secret, &transcript, &msg.body)?;
                    transcript.extend_from_slice(&msg.raw);
                    break 'flight;
                }
                _ => {
                    return Err(TransportError::Tls(format!(
                        "tls13: unexpected handshake message {}",
                        msg.typ
                    )));
                }
            }
        }
    }

    if random_authed {
        // Upstream still *parses* every certificate DER on the
        // authenticated path (malformed → handshake error) even though
        // the chain verify and CV signature are skipped — a jls server
        // presenting garbage certs fails there, so fail here too.
        for der in &flight.certificates {
            boring::x509::X509::from_der(der)
                .map_err(|e| TransportError::Tls(format!("tls13: malformed certificate: {e}")))?;
        }
    } else {
        let name = cfg.cert.verify_name.as_deref().unwrap_or(&cfg.server_name);
        verify_certificate_chain(&cfg.cert, name, &flight.certificates)?;
    }

    // Transcript now runs through the server Finished: derive the
    // application secrets, then compute and send the client Finished.
    let hash = cipher.hash();
    let client_ap_secret = hash.derive_secret(
        &hs.master_secret,
        b"c ap traffic",
        &hash.digest(&transcript),
    );
    let server_ap_secret = hash.derive_secret(
        &hs.master_secret,
        b"s ap traffic",
        &hash.digest(&transcript),
    );

    // A CertificateRequest obliges a client Certificate message — empty
    // since we never carry client certs. It precedes Finished both on the
    // wire and in the transcript (its hash feeds verify_data).
    if flight.saw_certificate_request {
        let ctx = &flight.cr_context;
        let mut cert_msg = Vec::with_capacity(4 + 4 + ctx.len());
        cert_msg.push(HS_CERTIFICATE);
        put_u24(1 + ctx.len() + 3, &mut cert_msg);
        cert_msg.push(ctx.len() as u8);
        cert_msg.extend_from_slice(ctx);
        cert_msg.extend_from_slice(&[0, 0, 0]); // empty certificate_list
        transcript.extend_from_slice(&cert_msg);
        let sealed = client_hs.seal(wire::TLS_RECORD_HANDSHAKE, &cert_msg)?;
        inner.write_all(&sealed).await?;
    }
    let fin = finished_verify_data(cipher, &hs.client_secret, &transcript);
    let mut fin_msg = Vec::with_capacity(4 + fin.len());
    fin_msg.push(HS_FINISHED);
    put_u24(fin.len(), &mut fin_msg);
    fin_msg.extend_from_slice(&fin);
    let client_finished = client_hs.seal(wire::TLS_RECORD_HANDSHAKE, &fin_msg)?;
    inner.write_all(&client_finished).await?;
    inner.flush().await?;

    Ok(Tls13Outcome {
        inner,
        server_random,
        client_finished,
        masked_auth: authed,
        random_authed,
        cipher,
        client_ap_secret,
        server_ap_secret,
        leftover_handshake: handshake_buf.iter().copied().collect(),
    })
}

/// Run the restls TLS 1.3 handshake on `inner` and return the post-handshake
/// state for [`crate::restls::conn::RestlsStream`].
///
/// The first encrypted record decides `authed`: if `unmask_server_auth`
/// produces a record the negotiated cipher opens, the peer is a restls
/// server; if the raw record opens instead, it is a plain relay and the
/// stream degrades to transparent cover TLS (upstream `expectServerAuth`).
pub(crate) async fn dial<S>(
    inner: S,
    cfg: &Tls13Config,
    secret: &[u8; 32],
) -> Result<RestlsUpgraded<S>>
where
    S: Stream,
{
    let shares = [
        KeyShare::generate(GROUP_X25519)?,
        KeyShare::generate(GROUP_P256)?,
        KeyShare::generate(GROUP_P384)?,
    ];
    let client_random: [u8; 32] = rand::random();
    let sent = build_restls_client_hello(cfg, &client_random, &shares, secret)?;

    let out = drive_tls13(inner, cfg, sent, &shares, Some(secret), |_, _| {
        // restls always verifies the cover certificate — auth is
        // orthogonal to PKI here (the driver's session-id echo check is
        // the gate, and the masked-record probe carries the restls auth).
        Ok(false)
    })
    .await?;
    debug_assert!(!out.random_authed);

    Ok(RestlsUpgraded {
        inner: out.inner,
        server_random: out.server_random,
        client_finished: Some(out.client_finished),
        authed: out.masked_auth.unwrap_or(false),
        cover_read: Some(Box::new(RecordKey::new(out.cipher, &out.server_ap_secret))),
        cover_write: Some(Box::new(RecordKey::new(out.cipher, &out.client_ap_secret))),
        tls12_gcm: false,
        gcm_ctr_disabled: false,
        // TLS 1.3 nonces are IV-derived — no explicit slot to rewrite.
        gcm_next_seq: 0,
        cover_hs_pending: out.leftover_handshake,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 1.3 CV gate is exactly the offered list minus the PKCS#1
    /// v1.5 schemes — stricter than upstream's default-list check, and
    /// RFC 8446 §4.4.3-correct (CV must be a scheme we offered).
    #[test]
    fn cv_schemes_are_offered_minus_v15() {
        for s in TLS13_CV_SCHEMES {
            assert!(SIG_ALGS.contains(&s), "{s:#06x} gated but never offered");
        }
        assert!(!TLS13_CV_SCHEMES.contains(&0x0401));
        assert!(!TLS13_CV_SCHEMES.contains(&0x0501));
        assert_eq!(TLS13_CV_SCHEMES.len(), SIG_ALGS.len() - 2);
    }
}
