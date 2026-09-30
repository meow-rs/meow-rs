//! BoringSSL backend for [`TlsLayer`](super::TlsLayer).
//!
//! Every non-REALITY handshake goes through here: plain TLS, uTLS
//! fingerprint shaping, ECH (with server `retry_configs` self-healing),
//! mTLS and ALPN.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tokio::io::{AsyncRead, AsyncWrite};

use tracing::warn;

use super::boring_stream::BoringTlsStream;
use super::{ConnectTypedError, EchOpts, TlsConfig, TlsVersion};
use crate::{Result, Stream, TransportError};

impl TlsVersion {
    fn to_ssl(self) -> boring::ssl::SslVersion {
        match self {
            Self::Tls12 => boring::ssl::SslVersion::TLS1_2,
            Self::Tls13 => boring::ssl::SslVersion::TLS1_3,
        }
    }
}

struct FingerprintParams {
    /// OpenSSL cipher-list string controlling TLS 1.2 cipher order.
    /// TLS 1.3 ciphers (AES-128-GCM-SHA256, AES-256-GCM-SHA384,
    /// CHACHA20-POLY1305-SHA256) are always included by BoringSSL and are
    /// not controlled by this string.
    cipher_list: &'static str,
    /// OpenSSL curve-list string (e.g. `"X25519:P-256:P-384"`).
    /// Invariant: every shipped profile must stay hybrid-PQ-free — the
    /// shadow-tls v2 pin lifts for *known* fingerprints on the assumption
    /// that a resolved profile never offers `X25519MLKEM768` /
    /// `P256Kyber768Draft00` (upstream strips them surgically; we have no
    /// per-group strip).  A future ML-KEM-carrying parrot would need the
    /// pin decision in `tls_config_for` revisited.
    curves_list: &'static str,
    /// Inject GREASE values in ciphers, extensions, and named groups.
    /// Also enables ECH GREASE automatically.
    grease: bool,
    /// Randomise extension order (Chrome behaviour since v106).
    permute_extensions: bool,
    /// OpenSSL sigalgs string (`:` separated).
    sigalgs_list: &'static str,
}

// ── Profile constants (derived from metacubex/utls u_parrots.go) ─────────────
//
// TLS 1.2 cipher strings only — BoringSSL always prepends the three TLS 1.3
// ciphers (TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 /
// TLS_CHACHA20_POLY1305_SHA256) regardless of what set_cipher_list receives.
// GREASE placeholders are omitted here; set_grease_enabled(true) handles them.

/// Chrome 120 / chrome120 alias.
/// Reference: u_parrots.go lines 665–736, HelloChrome_120.
const CHROME: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: true,
    permute_extensions: true,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   rsa_pss_rsae_sha384:\
                   rsa_pkcs1_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha512",
};

/// Firefox 120 / firefox120 alias.
/// Reference: u_parrots.go lines ~1197, HelloFirefox_120.
const FIREFOX: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-AES256-SHA:\
                  ECDHE-ECDSA-AES128-SHA:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA:\
                  DES-CBC3-SHA",
    curves_list: "X25519:P-256:P-384:P-521",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   ecdsa_secp521r1_sha512:\
                   rsa_pss_rsae_sha256:\
                   rsa_pss_rsae_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha256:\
                   rsa_pkcs1_sha384:\
                   rsa_pkcs1_sha512",
};

/// Safari 16 / safari16 alias.
/// Reference: u_parrots.go lines ~1851, HelloSafari_16_0.
const SAFARI: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-ECDSA-AES256-SHA:\
                  ECDHE-ECDSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  ECDHE-RSA-AES128-SHA:\
                  AES256-GCM-SHA384:\
                  AES128-GCM-SHA256:\
                  AES256-SHA:\
                  AES128-SHA:\
                  ECDHE-ECDSA-3DES-EDE-CBC-SHA:\
                  ECDHE-RSA-3DES-EDE-CBC-SHA:\
                  DES-CBC3-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   ecdsa_secp521r1_sha512:\
                   rsa_pss_rsae_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha384:\
                   rsa_pkcs1_sha512:\
                   rsa_pkcs1_sha1",
};

/// iOS 14.
/// Reference: u_parrots.go lines ~1510, HelloIOS_14.
/// Cipher and curve list is identical to Safari 16; sigalg order differs.
const IOS: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-ECDSA-AES256-SHA:\
                  ECDHE-ECDSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  ECDHE-RSA-AES128-SHA:\
                  AES256-GCM-SHA384:\
                  AES128-GCM-SHA256:\
                  AES256-SHA:\
                  AES128-SHA:\
                  ECDHE-ECDSA-3DES-EDE-CBC-SHA:\
                  ECDHE-RSA-3DES-EDE-CBC-SHA:\
                  DES-CBC3-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   ecdsa_secp521r1_sha512:\
                   rsa_pss_rsae_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha384:\
                   rsa_pkcs1_sha512:\
                   rsa_pkcs1_sha1",
};

/// Android 11 OkHttp.
/// Reference: u_parrots.go lines ~1595, HelloAndroid_11_OkHttp.
/// No TLS 1.3 ciphers in OkHttp's list; boring still offers them by default.
/// P-256 precedes X25519 (OkHttp ordering).
const ANDROID: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA",
    curves_list: "P-256:X25519",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   rsa_pss_rsae_sha384:\
                   rsa_pkcs1_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha512",
};

/// Edge 85 (Chrome 83 base).
/// Reference: u_parrots.go lines ~1641, HelloEdge_85 / HelloChrome_83.
/// GREASE enabled; extension permutation absent (pre-Chrome-106).
const EDGE: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: true,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   rsa_pss_rsae_sha384:\
                   rsa_pkcs1_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha512:\
                   rsa_pkcs1_sha1",
};

/// Resolve a fingerprint string to its `FingerprintParams`.
///
/// Returns `None` for deferred/unknown profiles — `build_connector` warns
/// and falls back to BoringSSL defaults for those.
fn resolve_fingerprint(fp: &str) -> Option<&'static FingerprintParams> {
    if fp == "random" {
        // Weighted random at construction: chrome(6) safari(3) ios(2) firefox(1).
        // Use a simple modulo on a thread-local random u8.
        let v: u8 = rand::random();
        return Some(match v % 12 {
            0..=5 => &CHROME,
            6..=8 => &SAFARI,
            9..=10 => &IOS,
            _ => &FIREFOX,
        });
    }
    resolve_named_fingerprint(fp)
}

fn resolve_named_fingerprint(fp: &str) -> Option<&'static FingerprintParams> {
    match fp {
        "chrome" | "chrome120" => Some(&CHROME),
        "firefox" | "firefox120" => Some(&FIREFOX),
        "safari" | "safari16" => Some(&SAFARI),
        "ios" => Some(&IOS),
        "android" => Some(&ANDROID),
        "edge" => Some(&EDGE),
        _ => None,
    }
}

/// Whether `fp` names a fingerprint this backend actually shapes —
/// `random` counts (it always resolves to a real profile).  Pure
/// counterpart of [`resolve_fingerprint`]: it must not consume the
/// weighted pick, so it matches names rather than resolving.
pub(crate) fn fingerprint_is_known(fp: &str) -> bool {
    fp == "random" || resolve_named_fingerprint(fp).is_some()
}

/// Process-global parsed Mozilla CA roots. Parsed once from DER; each `X509`
/// is refcount-shared (`X509_up_ref` on clone), so building a per-connector
/// store from these is cheap and never re-parses the ~150 KB of DER. (boring's
/// `X509Store` is not `Clone`, so the store itself cannot be shared directly;
/// the certs are.)
static BORING_ROOTS: OnceLock<Vec<boring::x509::X509>> = OnceLock::new();

pub(crate) fn boring_roots() -> &'static [boring::x509::X509] {
    BORING_ROOTS.get_or_init(|| {
        webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|cert| {
                boring::x509::X509::from_der(cert.as_ref())
                    .expect("webpki_root_certs: invalid CA cert")
            })
            .collect()
    })
}

/// Build a fresh Mozilla-roots `X509StoreBuilder`, optionally seeded with extra
/// DER roots. Called once per distinct connector cache key, not per proxy.
pub(crate) fn build_root_store(
    additional_roots: &[Vec<u8>],
) -> Result<boring::x509::store::X509StoreBuilder> {
    let mut builder = boring::x509::store::X509StoreBuilder::new()
        .map_err(|e| TransportError::Config(format!("X509StoreBuilder::new: {e}")))?;
    for cert in boring_roots() {
        builder
            .add_cert(cert.clone())
            .map_err(|e| TransportError::Config(format!("root store add_cert: {e}")))?;
    }
    for der in additional_roots {
        let x509 = boring::x509::X509::from_der(der).map_err(|e| {
            TransportError::Config(format!("additional_roots: invalid CA cert (boring): {e}"))
        })?;
        builder.add_cert(x509).map_err(|e| {
            TransportError::Config(format!("additional_roots: add_cert (boring): {e}"))
        })?;
    }
    Ok(builder)
}

/// Cache key for [`CONNECTOR_CACHE`] — the [`TlsConfig`] fields that shape
/// the `SSL_CTX`.  SNI and ECH are per-connection (`ConnectConfiguration`),
/// so they stay out of the key.
#[derive(PartialEq, Eq, Hash)]
struct ConnectorKey {
    fingerprint: Option<String>,
    curves: Option<String>,
    alpn: Vec<String>,
    skip_cert_verify: bool,
}

/// Process-wide cache of BoringSSL `SslConnector`s.
///
/// An `SSL_CTX` with its verify store and session cache is ~160 KB; with
/// e.g. 100 TLS proxies from a subscription that would be ~16 MB of
/// identical contexts.  `SslConnector::clone()` is an `SSL_CTX_up_ref`, so
/// every layer with the same key shares one C-level context.
static CONNECTOR_CACHE: OnceLock<Mutex<HashMap<ConnectorKey, boring::ssl::SslConnector>>> =
    OnceLock::new();

/// Return a shared `SslConnector` for `config`, building (and caching) it on
/// first use.
///
/// Only configs without `additional_roots` / `client_cert` are cached —
/// those are rare (tests, mTLS) and would force hashing certificate blobs
/// into the key.  `fingerprint = "random"` is also uncached because the
/// profile is drawn at construction time and each layer should get its own
/// draw.  Such configs get a private, uncached build.
fn shared_connector(config: &TlsConfig) -> Result<boring::ssl::SslConnector> {
    let cacheable = config.additional_roots.is_empty()
        && config.client_cert.is_none()
        && config.fingerprint.as_deref() != Some("random");
    if !cacheable {
        return BoringInner::build_connector(config);
    }

    let key = ConnectorKey {
        fingerprint: config.fingerprint.clone(),
        curves: config.curves.clone(),
        alpn: config.alpn.clone(),
        skip_cert_verify: config.skip_cert_verify,
    };
    let cache = CONNECTOR_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let map = cache.lock().expect("boring connector cache poisoned");
        if let Some(shared) = map.get(&key) {
            return Ok(shared.clone());
        }
    }
    // Build outside the lock (SSL_CTX setup parses cipher/curve lists and
    // seeds the verify store); a racing builder for the same key just wins
    // or loses harmlessly.
    let built = BoringInner::build_connector(config)?;
    let mut map = cache.lock().expect("boring connector cache poisoned");
    Ok(map.entry(key).or_insert(built).clone())
}

pub(super) struct BoringInner {
    connector: boring::ssl::SslConnector,
    server_name: String,
    /// Certificate-verification hostname when it differs from
    /// `server_name` (gost-plugin `name-cert-verify`). Per-connection
    /// `X509_VERIFY_PARAM` state, so it stays out of the connector key.
    verify_name: Option<String>,
    /// SHA-256 cert-chain pin (mihomo `fingerprint`). Per-connection
    /// `SSL_set_custom_verify` state — like `verify_name`, it stays out
    /// of the connector cache key.
    cert_pin: Option<[u8; 32]>,
    /// Per-connection version bounds (`ConnectConfiguration` carries
    /// them, not the `SSL_CTX`, so they stay out of the connector key).
    min_version: Option<boring::ssl::SslVersion>,
    max_version: Option<boring::ssl::SslVersion>,
    /// Per-connection ECH config (task #9). Wrapped in a `Mutex` so the
    /// connect path can transparently rotate to server-supplied
    /// `retry_configs` after an ECH-rejection (task: ECH self-healing).
    /// The current connect attempt still fails — the inner stream has
    /// already been consumed by `tokio_boring::connect` — but every
    /// subsequent connect uses the refreshed key, recovering the proxy
    /// without operator intervention.
    ech: std::sync::Mutex<Option<EchOpts>>,
}

impl BoringInner {
    /// Cheap validation of the config — called eagerly from `TlsLayer::new()`
    /// so errors surface at startup, not on first connection.
    ///
    /// Everything that can make [`Self::build_connector`] fail is checked
    /// here so `TlsLayer::new` reports it at startup: `sni`, ALPN entry lengths (the wire format
    /// carries a one-byte length prefix), and — for the rare configs that
    /// carry `additional_roots` / `client_cert` / `curves` — a full dry-run
    /// build, since DER/PEM parse errors and an unparsable curve list are
    /// only discoverable by building.  The first two bypass the connector
    /// cache anyway; `curves` configs pay one extra `SSL_CTX` at startup
    /// and nothing on the dial path.
    pub(super) fn validate(config: &TlsConfig) -> Result<()> {
        if config.sni.is_none() {
            return Err(TransportError::Config(
                "TlsLayer requires sni to be Some; None is reserved for non-TLS paths.".into(),
            ));
        }
        if let Some(bad) = config
            .alpn
            .iter()
            .find(|p| p.is_empty() || p.len() > u8::MAX as usize)
        {
            return Err(TransportError::Config(format!(
                "alpn: protocol id {bad:?} must be 1–255 bytes (RFC 7301 §3.1)"
            )));
        }
        if let Some(EchOpts::Config(bytes)) = &config.ech {
            // ECHConfigList is u16-length-prefixed on the wire; a larger
            // blob is malformed — reject once at construction instead of
            // re-parsing it on every handshake.
            if bytes.len() > u16::MAX as usize {
                return Err(TransportError::Config(format!(
                    "ech: ECHConfigList {} bytes exceeds the u16 wire bound",
                    bytes.len()
                )));
            }
        }
        if let Some(verify_name) = &config.verify_name {
            // `X509_VERIFY_PARAM_set1_host` rejects NUL bytes and names
            // longer than 255 (DNS name cap) — surface that at startup
            // instead of failing every dial.
            if verify_name.is_empty() || verify_name.len() > 255 || verify_name.contains('\0') {
                return Err(TransportError::Config(format!(
                    "verify_name {verify_name:?} must be 1–255 bytes without NUL"
                )));
            }
        }
        if config.min_version == Some(TlsVersion::Tls13)
            && config.max_version == Some(TlsVersion::Tls12)
        {
            return Err(TransportError::Config(
                "min_version TLS 1.3 conflicts with max_version TLS 1.2".into(),
            ));
        }
        if config.ech.is_some() && config.max_version == Some(TlsVersion::Tls12) {
            return Err(TransportError::Config(
                "ech requires TLS 1.3 but max_version caps at TLS 1.2".into(),
            ));
        }
        if !config.additional_roots.is_empty()
            || config.client_cert.is_some()
            || config.curves.is_some()
        {
            Self::build_connector(config)?;
        }
        Ok(())
    }

    fn new(config: &TlsConfig) -> Result<Self> {
        let server_name = config.sni.clone().ok_or_else(|| {
            TransportError::Config(
                "TlsLayer requires sni to be Some; None is reserved for non-TLS paths.".into(),
            )
        })?;
        let connector = shared_connector(config)?;
        Ok(Self {
            connector,
            server_name,
            verify_name: config.verify_name.clone(),
            cert_pin: config.cert_pin,
            min_version: config.min_version.map(TlsVersion::to_ssl),
            max_version: config.max_version.map(TlsVersion::to_ssl),
            ech: std::sync::Mutex::new(config.ech.clone()),
        })
    }

    /// Build a fresh `SslConnector` (one `SSL_CTX`) for `config`.
    ///
    /// Callers should go through [`shared_connector`] so identical shaping
    /// keys share a single context; this is the uncached primitive.
    fn build_connector(config: &TlsConfig) -> Result<boring::ssl::SslConnector> {
        let mut b = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())
            .map_err(|e| TransportError::Config(format!("boring TLS init: {e}")))?;

        // ── Fingerprint shaping ──────────────────────────────────────────────
        if let Some(fp_str) = &config.fingerprint {
            if let Some(p) = resolve_fingerprint(fp_str) {
                b.set_cipher_list(p.cipher_list)
                    .map_err(|e| TransportError::Config(format!("boring: set_cipher_list: {e}")))?;
                b.set_curves_list(p.curves_list)
                    .map_err(|e| TransportError::Config(format!("boring: set_curves_list: {e}")))?;
                b.set_grease_enabled(p.grease);
                b.set_permute_extensions(p.permute_extensions);
                b.set_sigalgs_list(p.sigalgs_list).map_err(|e| {
                    TransportError::Config(format!("boring: set_sigalgs_list: {e}"))
                })?;
            } else {
                // Deferred profile — warn and continue with boring defaults.
                warn!(
                    "client-fingerprint=\"{}\" is not yet supported; \
                     using BoringSSL defaults. \
                     See docs/specs/ech-utls-design.md §10 for the deferred list.",
                    fp_str
                );
            }
        }

        // ── supported_groups override ────────────────────────────────────────
        // An explicit `curves` list applies after — and therefore overrides —
        // a resolved fingerprint profile's own list.  shadow-tls v2 uses it
        // only when no profile resolved (its pin would otherwise clobber
        // firefox/android's distinct group lists); upstream's
        // `BuildRemovedX25519MLKEM768HandshakeState` removes the hybrid-PQ
        // group surgically post-uTLS, which our whole-list override can only
        // express as a fallback for the unshaped default hello.
        if let Some(curves) = &config.curves {
            b.set_curves_list(curves)
                .map_err(|e| TransportError::Config(format!("boring: set_curves_list: {e}")))?;
        }

        // ── ALPN ────────────────────────────────────────────────────────────
        if !config.alpn.is_empty() {
            // ALPN wire format: each entry is a length-prefixed byte sequence.
            let wire: Vec<u8> = config
                .alpn
                .iter()
                .flat_map(|p| {
                    let b = p.as_bytes();
                    let mut v = Vec::with_capacity(1 + b.len());
                    v.push(b.len() as u8);
                    v.extend_from_slice(b);
                    v
                })
                .collect();
            b.set_alpn_protos(&wire)
                .map_err(|e| TransportError::Config(format!("boring: set_alpn_protos: {e}")))?;
        }

        // ── Certificate verification ─────────────────────────────────────────
        if config.skip_cert_verify {
            // Warned about once per proxy in `TlsLayer::new`.
            b.set_verify(boring::ssl::SslVerifyMode::NONE);
        } else {
            b.set_verify(boring::ssl::SslVerifyMode::PEER);
            // Mozilla CA bundle (plus any `additional_roots`) as the verify
            // store, rebuilt per distinct connector cache key from the shared,
            // pre-parsed root certs. `set_cert_store_builder` hands over the
            // builder as-is; boring 4.x deprecated the `X509Store` variant and
            // 5.x lifted that again, so either works.
            let store = build_root_store(&config.additional_roots)?;
            b.set_cert_store_builder(store);
        }

        // ── Client certificate (mTLS) ────────────────────────────────────────
        if let Some(cc) = &config.client_cert {
            let cert = boring::x509::X509::from_pem(&cc.cert_pem).map_err(|e| {
                TransportError::Config(format!(
                    "client_cert.cert_pem: PEM parse error (boring): {e}"
                ))
            })?;
            let key = boring::pkey::PKey::private_key_from_pem(&cc.key_pem).map_err(|e| {
                TransportError::Config(format!(
                    "client_cert.key_pem: PEM parse error (boring): {e}"
                ))
            })?;
            b.set_certificate(&cert)
                .map_err(|e| TransportError::Tls(format!("boring: set_certificate: {e}")))?;
            b.set_private_key(&key)
                .map_err(|e| TransportError::Tls(format!("boring: set_private_key: {e}")))?;
        }

        // BoringSSL defaults to SSL_SESS_CACHE_BOTH with unbounded size
        // (0 = unlimited) — every completed handshake stores an
        // SSL_SESSION that is never evicted, leaking memory proportional
        // to connection count.  Cap at 64 entries: enough for TLS 1.3
        // session-ticket resumption to the same upstream proxy server
        // (saves one round-trip per resumed connection), small enough
        // that memory is bounded even under sustained load.
        b.set_session_cache_size(64);

        Ok(b.build())
    }

    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        // Multiplexed transports (anytls, smux, …) implement `poll_flush` as a
        // barrier on a writer-task acknowledgement, so the first poll almost
        // always returns `Poll::Pending`.  tokio-boring's BIO bridge maps that
        // Pending to `ErrorKind::WouldBlock`; boring 5.x carries
        // cloudflare/boring@ed76885, which sets `BIO_set_retry_write` on
        // `BIO_CTRL_FLUSH`, so the handshake retries as `WANT_WRITE` instead of
        // dying with `SSL_ERROR_SYSCALL` (#569).  The 4.x-era
        // `TolerantFlushStream` workaround from #571 is gone;
        // `d1_tls_handshake_over_pending_flush_stream` guards the upstream
        // behaviour.
        //
        // `BoringTlsStream` adds XTLS-Vision's raw switch (issue #495).
        self.connect_typed(inner)
            .await
            .map(|s| Box::new(BoringTlsStream::new(s)) as Box<dyn Stream>)
            .map_err(ConnectTypedError::into_transport)
    }

    /// [`connect`](Self::connect) over a caller-provided stream type,
    /// returning the concrete `SslStream<S>` so the inner stream can be
    /// recovered after the handshake.  shadow-tls needs this: the cover
    /// handshake runs over a sniffer/patcher shim, then the TLS session
    /// is discarded and the recovered inner stream carries the framed
    /// data path.  Handshake failures keep the source stream recoverable
    /// via [`ConnectTypedError::Handshake`] (shadow-tls v3 expects the
    /// cover handshake to fail at Finished — the wire-patched ClientHello
    /// diverges the transcript — and proceeds off the recovered shim).
    ///
    /// Pending flushes retry natively under boring 5.x (see `connect`) —
    /// no caller-side workaround is needed for mux transports.
    async fn connect_typed<S>(&self, inner: S) -> super::TypedConnectResult<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut cfg = self
            .connector
            .configure()
            .map_err(|e| TransportError::Tls(format!("boring: configure: {e}")))
            .map_err(ConnectTypedError::Transport)?;

        // SNI — omitted for IP literals (RFC 6066 §3), matching Go's
        // crypto/tls.  Hostname
        // verification still runs: `tokio_boring::connect` hands the
        // literal to `X509_VERIFY_PARAM_set1_ip`, so a SAN `iPAddress`
        // match is required unless `skip_cert_verify` is set.
        cfg.set_use_server_name_indication(self.server_name.parse::<std::net::IpAddr>().is_err());

        // Version bounds — per-connection `ConnectConfiguration` state,
        // so they stay out of the connector cache key.  ECH's own
        // TLS 1.3 floor below intentionally overrides a lower `min`.
        if let Some(min) = self.min_version {
            cfg.set_min_proto_version(Some(min))
                .map_err(|e| TransportError::Config(format!("boring: set_min_proto_version: {e}")))
                .map_err(ConnectTypedError::Transport)?;
        }
        if let Some(max) = self.max_version {
            cfg.set_max_proto_version(Some(max))
                .map_err(|e| TransportError::Config(format!("boring: set_max_proto_version: {e}")))
                .map_err(ConnectTypedError::Transport)?;
        }

        // Snapshot the current ECH config before consuming `inner`. The lock
        // is held only across this snapshot — never across the await.
        let ech_snapshot = self.ech.lock().expect("ech mutex poisoned").clone();
        let ech_requested = ech_snapshot.is_some();

        // ECH inline path — per-connection setup on ConnectConfiguration.
        if let Some(EchOpts::Config(ech_bytes)) = &ech_snapshot {
            cfg.set_ech_config_list(ech_bytes)
                .map_err(|e| TransportError::Config(format!("boring: set_ech_config_list: {e}")))
                .map_err(ConnectTypedError::Transport)?;
            // RFC 9180 §6: ECH requires TLS 1.3.  BoringSSL enforces this
            // automatically when an ECH config list is set, but we set it
            // explicitly here so the requirement is visible at the call site.
            cfg.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))
                .map_err(|e| {
                    TransportError::Config(format!("boring: set_min_proto_version TLS1.3: {e}"))
                })
                .map_err(ConnectTypedError::Transport)?;
        }

        // `name-cert-verify` (mihomo `NameCertVerify`): the certificate is
        // verified against `verify_name` while SNI keeps `server_name`.
        // `tokio_boring::connect` couples both to one domain, so this path
        // builds the `Ssl` by hand and overrides `X509_VERIFY_PARAM`'s host.
        //
        // `fingerprint` (mihomo SSL pinning) goes further: upstream sets
        // `InsecureSkipVerify` and replaces verification with a SHA-256
        // pin check, so it installs `SSL_set_custom_verify` instead —
        // the callback then owns the accept/reject decision entirely.
        let handshake = if self.verify_name.is_some() || self.cert_pin.is_some() {
            // `verify_name`-only (no pin): `into_ssl` would seed the verify
            // param with `server_name` (hosts for DNS names, ip for IP
            // literals), and `check_id` enforces hosts and ip
            // *independently* — a `host=1.2.3.4; name-cert-verify=example.com`
            // config would demand a cert matching both, and BoringSSL has no
            // clear API (`set1_ip(NULL,0)` is rejected, unlike OpenSSL).
            // Prevent the seed instead: the param stays clean and exactly
            // one name check is installed below.  The pin arm doesn't need
            // this — its custom verify callback replaces verification
            // entirely, so the seeded fields are never consulted.
            if self.cert_pin.is_none() && self.verify_name.is_some() {
                cfg.set_verify_hostname(false);
            }
            let mut ssl = cfg
                .into_ssl(&self.server_name)
                .map_err(|e| TransportError::Tls(format!("boring: into_ssl: {e}")))
                .map_err(ConnectTypedError::Transport)?;
            if let Some(pin) = self.cert_pin {
                // Upstream: `serverName = state.ServerName`, overridden by
                // `NameCertVerify` — the pin's chain-verify DNS name.
                let check_name = self
                    .verify_name
                    .clone()
                    .unwrap_or_else(|| self.server_name.clone());
                ssl.set_custom_verify_callback(boring::ssl::SslVerifyMode::PEER, move |ssl| {
                    verify_cert_pin(ssl, &pin, &check_name)
                });
            } else if let Some(verify_name) = &self.verify_name {
                let param = ssl.param_mut();
                // Mirror `setup_verify_hostname`, keyed on `verify_name`
                // instead of `server_name`: NO_PARTIAL_WILDCARDS plus
                // `set_ip` for IP literals (`set_host` compares them as
                // DNS names and never matches an iPAddress SAN).
                param.set_hostflags(boring::x509::verify::X509CheckFlags::NO_PARTIAL_WILDCARDS);
                match verify_name.parse::<std::net::IpAddr>() {
                    Ok(ip) => param.set_ip(ip),
                    Err(_) => param.set_host(verify_name),
                }
                .map_err(|e| TransportError::Tls(format!("boring: set verify name: {e}")))
                .map_err(ConnectTypedError::Transport)?;
            }
            tokio_boring::SslStreamBuilder::new(ssl, inner)
                .connect()
                .await
        } else {
            tokio_boring::connect(cfg, &self.server_name, inner).await
        };

        match handshake {
            Ok(tls_stream) => {
                let ech_accepted = tls_stream.ssl().ech_accepted();
                let version = tls_stream.ssl().version_str();
                tracing::debug!(
                    sni = %self.server_name,
                    ech_requested = ech_requested,
                    ech_accepted = ech_accepted,
                    tls_version = %version,
                    "boring TLS handshake complete"
                );
                Ok(tls_stream)
            }
            Err(e) => {
                // If ECH was active and the server rejected with `ech_required`,
                // BoringSSL surfaces the new `retry_configs` blob the server
                // signed. Self-heal: store the new bytes so the *next*
                // `connect()` uses them. The current attempt still fails — the
                // inner stream is already consumed by `tokio_boring::connect`,
                // so we cannot re-dial here.
                // The retry-configs read MUST be gated on a real
                // `SSL_R_ECH_REJECTED` failure: `SSL_get0_ech_retry_configs`
                // is only valid for an authenticated ECH rejection — called
                // on any other failure (cert verify, reset mid-handshake) it
                // aborts debug builds and returns a non-empty garbage
                // placeholder that would poison `self.ech` for every
                // subsequent connect.
                if ech_requested && handshake_failed_ech_rejected(&e) {
                    if let Some(retry_configs) = e.ssl().and_then(|ssl| ssl.get_ech_retry_configs())
                    {
                        if !retry_configs.is_empty() {
                            let new_bytes = retry_configs.to_vec();
                            let hex = new_bytes
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>();
                            *self.ech.lock().expect("ech mutex poisoned") =
                                Some(EchOpts::Config(new_bytes));
                            tracing::warn!(
                                sni = %self.server_name,
                                retry_configs = %hex,
                                "ECH rejected by server; rotated to retry_configs — \
                                 next connect will use the new key"
                            );
                            return Err(ConnectTypedError::Transport(TransportError::Tls(
                                format!(
                                    "boring TLS handshake (ECH rejected; retry_configs={hex}): {e}"
                                ),
                            )));
                        }
                    }
                }
                Err(ConnectTypedError::Handshake(e))
            }
        }
    }
}

/// True when `e` is a mid-handshake failure carrying `SSL_R_ECH_REJECTED`
/// — the only state where `get_ech_retry_configs` is legal.
fn handshake_failed_ech_rejected<S>(e: &tokio_boring::HandshakeError<S>) -> bool {
    // `HandshakeError::ssl()` is `Some` only for a mid-handshake Failure —
    // a SetupFailure (pre-handshake, no ECH attempted) must not consult the
    // stored error. `code() == SSL` narrows to SSL-library failures (an
    // ECH rejection is always SSL_ERROR_SSL, never SYSCALL), and the
    // Display embeds the registered reason-code name `[ECH_REJECTED]` —
    // tokio-boring exposes reason codes only through `Error::source()`,
    // which requires `S: Debug` that `connect_typed`'s generic streams
    // don't have. `ECH_REJECTED` is a canonical reason symbol, not
    // free-form text, so it cannot collide with unrelated errors.
    e.ssl().is_some()
        && e.code() == Some(boring::ssl::ErrorCode::SSL)
        && e.to_string().contains("ECH_REJECTED")
}

/// Defers BoringSSL `SslConnector` construction to the first `connect()` call,
/// avoiding session cache and SSL_CTX allocation for proxy adapters that are
/// configured but never receive traffic (e.g. unused selector members).
///
/// Config is validated eagerly in [`TlsLayer::new`](super::TlsLayer::new)
/// via [`BoringInner::validate`], so the deferred build is not expected to
/// fail; if it does, the error is stored and returned from every `connect`.
pub(super) struct LazyBoringInner {
    config: TlsConfig,
    /// `Err` only if construction fails despite [`BoringInner::validate`]
    /// having passed (e.g. BoringSSL out of memory); surfaced as
    /// `TransportError::Config` on every connect rather than panicking.
    inner: OnceLock<std::result::Result<BoringInner, String>>,
}

impl LazyBoringInner {
    pub(super) fn new(config: TlsConfig) -> Self {
        Self {
            config,
            inner: OnceLock::new(),
        }
    }

    fn get_or_init(&self) -> Result<&BoringInner> {
        self.inner
            .get_or_init(|| BoringInner::new(&self.config).map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| TransportError::Config(format!("boring TLS init: {e}")))
    }

    pub(super) async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        self.get_or_init()?.connect(inner).await
    }

    pub(super) async fn connect_typed<S>(&self, inner: S) -> super::TypedConnectResult<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.get_or_init()
            .map_err(ConnectTypedError::Transport)?
            .connect_typed(inner)
            .await
    }
}

// ── Certificate pinning (mihomo `fingerprint`) ──────────────────────────────

/// Upstream `component/ca.NewFingerprintVerifier`: scan the peer chain
/// for a cert whose `SHA-256(DER)` equals `pin`.
///
/// - **Leaf match (i == 0)** → accept outright; the pin replaces CA
///   verification entirely (upstream sets `InsecureSkipVerify` before
///   installing `VerifyConnection`).
/// - **Non-leaf match (i > 0)** → the pinned cert becomes the trusted
///   root and the leaf is verified against it plus a `check_name`
///   hostname check (upstream `x509.VerifyOptions{Roots: {cert[i]},
///   Intermediates: certs[1..=i], DNSName: serverName}`).
/// - **No match** → reject with `bad_certificate`.
fn verify_cert_pin(
    ssl: &mut boring::ssl::SslRef,
    pin: &[u8; 32],
    check_name: &str,
) -> std::result::Result<(), boring::ssl::SslVerifyError> {
    use boring::ssl::{SslAlert, SslVerifyError};
    fn reject() -> SslVerifyError {
        SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE)
    }
    let Some(chain) = ssl.peer_cert_chain() else {
        return Err(reject());
    };
    pinned_chain_decision(chain, pin, check_name).map_err(|_| reject())
}

/// The pin decision, split out of `verify_cert_pin` so unit tests can
/// drive it without an `SslRef`: a pin on `certs[0]` accepts the leaf
/// as-pinned (upstream `FingerprintVerifier`'s `i == 0` arm — no name or
/// chain check); a deeper pin runs [`verify_leaf_under_pinned_cert`].
///
/// Divergence note: upstream composes `NewNameCertVerifier` *around* the
/// fingerprint verifier, so a leaf-pin hit still runs `VerifyHostname`
/// when `name-cert-verify` is set. Here a leaf pin is an identity check —
/// the cert bytes themselves are the pinned identity — so no name check
/// applies on that arm (meow accepts where upstream rejects).
fn pinned_chain_decision(
    chain: &boring::stack::StackRef<boring::x509::X509>,
    pin: &[u8; 32],
    check_name: &str,
) -> std::result::Result<(), boring::error::ErrorStack> {
    for (i, cert) in chain.iter().enumerate() {
        let Ok(digest) = cert.digest(boring::hash::MessageDigest::sha256()) else {
            continue;
        };
        if digest.as_ref() != pin.as_slice() {
            continue;
        }
        if i == 0 {
            return Ok(());
        }
        return verify_leaf_under_pinned_cert(chain, i, check_name);
    }
    Err(boring::error::ErrorStack::get())
}

/// `FingerprintVerifier`'s non-leaf arm: `certs[i]` is treated as the
/// only trusted root, `certs[1..=i]` as intermediates (the pinned cert
/// itself included — harmless, mirrors upstream's `certs[1 : i+1]`
/// slice), and the leaf must chain to the root and match `check_name`.
fn verify_leaf_under_pinned_cert(
    chain: &boring::stack::StackRef<boring::x509::X509>,
    pin_idx: usize,
    check_name: &str,
) -> std::result::Result<(), boring::error::ErrorStack> {
    use boring::{
        stack::Stack,
        x509::{
            store::X509StoreBuilder,
            verify::{X509CheckFlags, X509VerifyFlags},
            X509StoreContext,
        },
    };
    use foreign_types::ForeignTypeRef;
    let mut store_b = X509StoreBuilder::new()?;
    store_b.add_cert(&chain[pin_idx])?;
    let store = store_b.build();
    let mut untrusted = Stack::new()?;
    for cert in chain.iter().skip(1).take(pin_idx) {
        untrusted.push(cert.to_owned())?;
    }
    let mut ctx = X509StoreContext::new()?;
    let ok = ctx.init(&store, &chain[0], &untrusted, |ctx| {
        let param = ctx.verify_param_mut();
        // A pinned intermediate that is not itself self-signed must still
        // terminate the chain — Go's `Roots:` semantics. Without
        // PARTIAL_CHAIN the lookup keeps walking to a root that was never
        // sent and fails with "unable to get issuer certificate".
        // TRUSTED_FIRST is already the client default, but the partial-chain
        // check relies on it (the store copy of the pinned cert must be
        // preferred over the presented one), so set it explicitly.
        param.set_flags(X509VerifyFlags::PARTIAL_CHAIN | X509VerifyFlags::TRUSTED_FIRST);
        // A client `SSL_CTX` verifies with purpose `sslserver` by default;
        // this hand-built context must match that so a cert minted by the
        // pinned CA but unusable for server auth (e.g. a clientAuth-only
        // EKU) is rejected. boring's safe bindings omit `set_purpose`, so
        // call it through boring-sys — the same vendored BoringSSL boring
        // itself links.
        // SAFETY: `param` is the live `X509_VERIFY_PARAM` owned by this
        // context; the call only writes a scalar field on it.
        if unsafe {
            boring_sys::X509_VERIFY_PARAM_set_purpose(
                param.as_ptr(),
                boring_sys::X509_PURPOSE_SSL_SERVER,
            )
        } != 1
        {
            return Err(boring::error::ErrorStack::get());
        }
        // Exact parity with `X509_STORE_CTX_set_default("ssl_server")`,
        // which sets purpose AND trust; trust only matters for certs
        // carrying aux-trust entries (never on the wire), but set it
        // anyway so the param is identical to the normal client path.
        // SAFETY: same live `X509_VERIFY_PARAM`, scalar field write.
        if unsafe {
            boring_sys::X509_VERIFY_PARAM_set_trust(
                param.as_ptr(),
                boring_sys::X509_TRUST_SSL_SERVER,
            )
        } != 1
        {
            return Err(boring::error::ErrorStack::get());
        }
        param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
        // IP literals must go through `set_ip`: `set_host` compares them
        // as DNS names and never matches an iPAddress SAN.
        match check_name.parse::<std::net::IpAddr>() {
            Ok(ip) => param.set_ip(ip)?,
            Err(_) => param.set_host(check_name)?,
        }
        ctx.verify_cert()
    })?;
    if ok {
        Ok(())
    } else {
        Err(boring::error::ErrorStack::get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same_ctx(a: &boring::ssl::SslConnector, b: &boring::ssl::SslConnector) -> bool {
        std::ptr::eq(a.context(), b.context())
    }

    /// Same (fingerprint, curves, alpn, skip_cert_verify) → same shared
    /// `SSL_CTX`; different key → different context; uncacheable configs
    /// bypass the cache.
    #[test]
    fn boring_connector_is_shared_per_key() {
        let a = shared_connector(&TlsConfig::new("a.example")).expect("build a");
        let b = shared_connector(&TlsConfig::new("b.example")).expect("build b");
        assert!(
            same_ctx(&a, &b),
            "same key (no fingerprint, no alpn, no skip-verify) must share one SSL_CTX"
        );

        let alpn = shared_connector(&TlsConfig {
            alpn: vec!["h2".into()],
            ..TlsConfig::new("c.example")
        })
        .expect("build alpn");
        assert!(
            !same_ctx(&a, &alpn),
            "different alpn must build a distinct SSL_CTX"
        );

        let fp = shared_connector(&TlsConfig {
            fingerprint: Some("chrome".into()),
            ..TlsConfig::new("d.example")
        })
        .expect("build fp");
        assert!(
            !same_ctx(&a, &fp),
            "fingerprint must build a distinct SSL_CTX"
        );
        let fp2 = shared_connector(&TlsConfig {
            fingerprint: Some("chrome".into()),
            ..TlsConfig::new("e.example")
        })
        .expect("build fp2");
        assert!(
            same_ctx(&fp, &fp2),
            "same fingerprint must share the SSL_CTX"
        );

        let curves = shared_connector(&TlsConfig {
            curves: Some("X25519:P-256:P-384".into()),
            ..TlsConfig::new("g.example")
        })
        .expect("build curves");
        assert!(
            !same_ctx(&a, &curves),
            "explicit curves must build a distinct SSL_CTX"
        );
        let curves2 = shared_connector(&TlsConfig {
            curves: Some("P-256:X25519".into()),
            ..TlsConfig::new("h.example")
        })
        .expect("build curves2");
        assert!(
            !same_ctx(&curves, &curves2),
            "different curves lists must build distinct SSL_CTXs"
        );

        let skip = shared_connector(&TlsConfig {
            skip_cert_verify: true,
            ..TlsConfig::new("f.example")
        })
        .expect("build skip");
        assert!(
            !same_ctx(&a, &skip),
            "skip_cert_verify must build a distinct SSL_CTX"
        );

        // `random` draws a profile per construction — never shared.
        let r1 = shared_connector(&TlsConfig {
            fingerprint: Some("random".into()),
            ..TlsConfig::new("g.example")
        })
        .expect("build r1");
        let r2 = shared_connector(&TlsConfig {
            fingerprint: Some("random".into()),
            ..TlsConfig::new("h.example")
        })
        .expect("build r2");
        assert!(!same_ctx(&r1, &r2), "random fingerprint must not be cached");

        // Re-asking for an existing key hits the cache.
        let a2 = shared_connector(&TlsConfig::new("i.example")).expect("build a2");
        assert!(same_ctx(&a, &a2));
    }

    /// The shadow-tls v2 pin lifts for *known* fingerprints on the
    /// assumption that every shipped profile is hybrid-PQ-free — upstream
    /// strips `X25519MLKEM768`/`P256Kyber768Draft00` surgically after uTLS
    /// shaping, which our whole-list `curves` override cannot express.  If
    /// a future parrot adds a PQ group, this test fails loudly and the pin
    /// decision in `meow-proxy`'s `tls_config_for` must be revisited.
    #[test]
    fn all_named_profiles_are_hybrid_pq_free() {
        for name in [
            "chrome",
            "chrome120",
            "firefox",
            "firefox120",
            "safari",
            "safari16",
            "ios",
            "android",
            "edge",
        ] {
            let p = resolve_named_fingerprint(name).expect("named profile");
            assert!(
                !p.curves_list.contains("MLKEM") && !p.curves_list.contains("KYBER"),
                "profile {name} carries a hybrid-PQ group ({}) — the \
                 shadow-tls v2 conditional pin would lift and leak it",
                p.curves_list
            );
        }
        // The `random` pool must be covered by the same invariant.
        for p in [&CHROME, &SAFARI, &IOS, &FIREFOX] {
            assert!(
                !p.curves_list.contains("MLKEM") && !p.curves_list.contains("KYBER"),
                "random-pool profile carries a hybrid-PQ group ({})",
                p.curves_list
            );
        }
    }

    /// Knobs for `make_cert` — keep the common leaf case terse.
    struct CertOpts<'a> {
        /// CA:TRUE + keyCertSign/crlSign.
        is_ca: bool,
        /// dNSName SANs.
        dns: &'a [&'a str],
        /// iPAddress SANs ("127.0.0.1", "::1", …).
        ips: &'a [&'a str],
        /// ExtendedKeyUsage carrying only clientAuth — a cert the issuer
        /// minted for client use; the sslserver purpose check must reject
        /// it on a server handshake.
        client_auth_eku: bool,
    }

    /// Generate a throwaway cert for the CA-pin path. `issuer` is the
    /// issuer's (CN, cert, key) and signs the new cert (None →
    /// self-signed).
    fn make_cert(
        cn: &str,
        opts: &CertOpts<'_>,
        issuer: Option<(
            &str,
            &boring::x509::X509,
            &boring::pkey::PKey<boring::pkey::Private>,
        )>,
    ) -> (
        boring::x509::X509,
        boring::pkey::PKey<boring::pkey::Private>,
    ) {
        use boring::{
            asn1::{Asn1Integer, Asn1Time},
            bn::BigNum,
            ec::{EcGroup, EcKey},
            hash::MessageDigest,
            nid::Nid,
            pkey::PKey,
            x509::{
                extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
                X509Name, X509,
            },
        };
        let key = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let mut name_b = X509Name::builder().unwrap();
        name_b.append_entry_by_text("CN", cn).unwrap();
        let subject = name_b.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let serial = Asn1Integer::from_bn(&BigNum::from_u32(7).unwrap()).unwrap();
        b.set_serial_number(&serial).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_subject_name(&subject).unwrap();
        let (issuer_cn, issuer_key, issuer_cert) = match issuer {
            Some((icn, cert, k)) => (icn, k, Some(cert)),
            None => (cn, &key, None),
        };
        let mut issuer_b = X509Name::builder().unwrap();
        issuer_b.append_entry_by_text("CN", issuer_cn).unwrap();
        let issuer_name = issuer_b.build();
        b.set_issuer_name(&issuer_name).unwrap();
        if opts.is_ca {
            b.append_extension(&BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            b.append_extension(
                &KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        } else {
            let mut san = SubjectAlternativeName::new();
            for name in opts.dns {
                san.dns(name);
            }
            for ip in opts.ips {
                san.ip(ip);
            }
            let ctx = b.x509v3_context(issuer_cert.map(|c| &**c), None);
            b.append_extension(&san.build(&ctx).unwrap()).unwrap();
            if opts.client_auth_eku {
                b.append_extension(&ExtendedKeyUsage::new().client_auth().build().unwrap())
                    .unwrap();
            }
        }
        b.sign(issuer_key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    fn chain_of(certs: Vec<boring::x509::X509>) -> boring::stack::Stack<boring::x509::X509> {
        let mut chain = boring::stack::Stack::new().unwrap();
        for c in certs {
            chain.push(c).unwrap();
        }
        chain
    }

    impl CertOpts<'_> {
        const DEFAULT: Self = CertOpts {
            is_ca: false,
            dns: &[],
            ips: &[],
            client_auth_eku: false,
        };
    }

    const CA: CertOpts<'static> = CertOpts {
        is_ca: true,
        ..CertOpts::DEFAULT
    };

    /// `FingerprintVerifier` i>0 arm: pinning a CA cert accepts a leaf
    /// that chains to it and matches the check name; a name mismatch or
    /// unrelated issuer must fail.
    #[test]
    fn cert_pin_nonleaf_verifies_leaf_under_pinned_ca() {
        let (ca, ca_key) = make_cert("Test CA", &CA, None);
        let (leaf, _leaf_key) = make_cert(
            "srv.example.com",
            &CertOpts {
                dns: &["srv.example.com"],
                ..CertOpts::DEFAULT
            },
            Some(("Test CA", &ca, &ca_key)),
        );
        let chain = chain_of(vec![leaf, ca.clone()]);

        verify_leaf_under_pinned_cert(&chain, 1, "srv.example.com")
            .expect("leaf chaining to the pinned CA must verify");
        assert!(
            verify_leaf_under_pinned_cert(&chain, 1, "other.example.com").is_err(),
            "DNS name mismatch must fail"
        );

        // A leaf not issued by the pinned CA must fail.
        let (rogue_ca, rogue_key) = make_cert("Rogue CA", &CA, None);
        let (rogue_leaf, _) = make_cert(
            "srv.example.com",
            &CertOpts {
                dns: &["srv.example.com"],
                ..CertOpts::DEFAULT
            },
            Some(("Rogue CA", &rogue_ca, &rogue_key)),
        );
        let rogue_chain = chain_of(vec![rogue_leaf, ca]);
        assert!(
            verify_leaf_under_pinned_cert(&rogue_chain, 1, "srv.example.com").is_err(),
            "leaf not issued by the pinned CA must fail"
        );
    }

    /// A pinned intermediate that is *not* self-signed must still anchor
    /// the chain (PARTIAL_CHAIN): the server sends leaf + intermediate,
    /// the real root is never on the wire.
    #[test]
    fn cert_pin_nonleaf_verifies_under_unsent_root() {
        let (root, root_key) = make_cert("Root CA", &CA, None);
        let (inter, inter_key) =
            make_cert("Intermediate CA", &CA, Some(("Root CA", &root, &root_key)));
        let (leaf, _) = make_cert(
            "srv.example.com",
            &CertOpts {
                dns: &["srv.example.com"],
                ..CertOpts::DEFAULT
            },
            Some(("Intermediate CA", &inter, &inter_key)),
        );
        let chain = chain_of(vec![leaf, inter]);
        verify_leaf_under_pinned_cert(&chain, 1, "srv.example.com")
            .expect("pinning a non-self-signed intermediate must verify via PARTIAL_CHAIN");
    }

    /// The sslserver purpose: a leaf the pinned CA minted for *client*
    /// use (clientAuth-only EKU) must not pass as a server certificate.
    #[test]
    fn cert_pin_nonleaf_rejects_client_auth_only_eku() {
        let (ca, ca_key) = make_cert("Test CA", &CA, None);
        let (leaf, _) = make_cert(
            "srv.example.com",
            &CertOpts {
                dns: &["srv.example.com"],
                client_auth_eku: true,
                ..CertOpts::DEFAULT
            },
            Some(("Test CA", &ca, &ca_key)),
        );
        let chain = chain_of(vec![leaf, ca]);
        assert!(
            verify_leaf_under_pinned_cert(&chain, 1, "srv.example.com").is_err(),
            "clientAuth-only EKU must fail the sslserver purpose check"
        );
    }

    /// IP-literal check names verify against iPAddress SANs via `set_ip`,
    /// for both v4 and v6; a mismatched IP must still fail.
    #[test]
    fn cert_pin_nonleaf_verifies_ip_san() {
        let (ca, ca_key) = make_cert("Test CA", &CA, None);
        let (leaf4, _) = make_cert(
            "v4",
            &CertOpts {
                ips: &["127.0.0.1"],
                ..CertOpts::DEFAULT
            },
            Some(("Test CA", &ca, &ca_key)),
        );
        let (leaf6, _) = make_cert(
            "v6",
            &CertOpts {
                ips: &["::1"],
                ..CertOpts::DEFAULT
            },
            Some(("Test CA", &ca, &ca_key)),
        );
        let chain4 = chain_of(vec![leaf4, ca.clone()]);
        let chain6 = chain_of(vec![leaf6, ca]);
        verify_leaf_under_pinned_cert(&chain4, 1, "127.0.0.1")
            .expect("IPv4 SAN must match an IP check_name");
        verify_leaf_under_pinned_cert(&chain6, 1, "::1")
            .expect("IPv6 SAN must match an IP check_name");
        assert!(
            verify_leaf_under_pinned_cert(&chain4, 1, "127.0.0.2").is_err(),
            "a different IP must fail"
        );
        // An iPAddress SAN does not satisfy a DNS check_name.
        assert!(
            verify_leaf_under_pinned_cert(&chain4, 1, "localhost").is_err(),
            "DNS name against an IP-only SAN must fail"
        );
    }

    /// The leaf-pin arm (`i == 0`) accepts the leaf as-pinned — no chain,
    /// name or purpose check. Keep it distinct from the CA-pin semantics
    /// above: pinning the leaf is an identity check.
    #[test]
    fn cert_pin_leaf_accepts_as_pinned() {
        let (leaf, _) = make_cert("srv.example.com", &CertOpts::DEFAULT, None);
        let pin: [u8; 32] = leaf
            .digest(boring::hash::MessageDigest::sha256())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let chain = chain_of(vec![leaf]);
        pinned_chain_decision(&chain, &pin, "unrelated.example.com")
            .expect("pinning the leaf must accept it regardless of check_name");
        let wrong = [0u8; 32];
        assert!(
            pinned_chain_decision(&chain, &wrong, "srv.example.com").is_err(),
            "a pin matching nothing in the chain must fail"
        );
        // A one-byte-off pin must still fail — guards a prefix/truncated
        // compare in `pinned_chain_decision`.
        let mut near_miss = pin;
        near_miss[31] ^= 0xff;
        assert!(
            pinned_chain_decision(&chain, &near_miss, "srv.example.com").is_err(),
            "a pin differing only in the last byte must fail"
        );
    }

    fn sha256(cert: &boring::x509::X509) -> [u8; 32] {
        cert.digest(boring::hash::MessageDigest::sha256())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap()
    }

    /// The non-leaf dispatch leg: a pin matching `chain[1]` must route
    /// through `verify_leaf_under_pinned_cert` — including the name check
    /// the leaf arm skips.
    #[test]
    fn cert_pin_nonleaf_dispatch_runs_full_verify() {
        let (ca, ca_key) = make_cert("Test CA", &CA, None);
        let (leaf, _) = make_cert(
            "srv.example.com",
            &CertOpts {
                dns: &["srv.example.com"],
                ..CertOpts::DEFAULT
            },
            Some(("Test CA", &ca, &ca_key)),
        );
        let pin = sha256(&ca);
        let chain = chain_of(vec![leaf, ca]);
        pinned_chain_decision(&chain, &pin, "srv.example.com")
            .expect("pinning the CA must verify the leaf under it");
        assert!(
            pinned_chain_decision(&chain, &pin, "other.example.com").is_err(),
            "non-leaf pin must still enforce the name check"
        );
    }

    /// Depth-2 pin: `leaf -> inter -> root`, pin the root. The
    /// `skip(1).take(pin_idx)` slice must hand both intermediates to the
    /// verifier as untrusted.
    #[test]
    fn cert_pin_depth2_verifies_through_intermediate() {
        let (root, root_key) = make_cert("Test Root", &CA, None);
        let (inter, inter_key) =
            make_cert("Test Inter", &CA, Some(("Test Root", &root, &root_key)));
        let (leaf, _) = make_cert(
            "srv.example.com",
            &CertOpts {
                dns: &["srv.example.com"],
                ..CertOpts::DEFAULT
            },
            Some(("Test Inter", &inter, &inter_key)),
        );
        let pin = sha256(&root);
        let chain = chain_of(vec![leaf, inter, root]);
        pinned_chain_decision(&chain, &pin, "srv.example.com")
            .expect("pinning the root at depth 2 must verify leaf via the intermediate");
    }
}
