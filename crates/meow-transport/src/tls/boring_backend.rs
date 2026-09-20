//! BoringSSL backend for [`TlsLayer`](super::TlsLayer).
//!
//! Every non-REALITY handshake goes through here: plain TLS, uTLS
//! fingerprint shaping, ECH (with server `retry_configs` self-healing),
//! mTLS and ALPN.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tracing::warn;

use super::{EchOpts, TlsConfig};
use crate::{Result, Stream, TransportError};

struct FingerprintParams {
    /// OpenSSL cipher-list string controlling TLS 1.2 cipher order.
    /// TLS 1.3 ciphers (AES-128-GCM-SHA256, AES-256-GCM-SHA384,
    /// CHACHA20-POLY1305-SHA256) are always included by BoringSSL and are
    /// not controlled by this string.
    cipher_list: &'static str,
    /// OpenSSL curve-list string (e.g. `"X25519:P-256:P-384"`).
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
/// Returns `None` for deferred/unknown profiles — caller should fall through
/// to `warn_fingerprint_once` (not applicable in the boring path, but kept
/// for exhaustiveness).
fn resolve_fingerprint(fp: &str) -> Option<&'static FingerprintParams> {
    match fp {
        "chrome" | "chrome120" => Some(&CHROME),
        "firefox" | "firefox120" => Some(&FIREFOX),
        "safari" | "safari16" => Some(&SAFARI),
        "ios" => Some(&IOS),
        "android" => Some(&ANDROID),
        "edge" => Some(&EDGE),
        "random" => {
            // Weighted random at construction: chrome(6) safari(3) ios(2) firefox(1).
            // Use a simple modulo on a thread-local random u8.
            let v: u8 = rand::random();
            Some(match v % 12 {
                0..=5 => &CHROME,
                6..=8 => &SAFARI,
                9..=10 => &IOS,
                _ => &FIREFOX,
            })
        }
        _ => None,
    }
}

/// Process-global parsed Mozilla CA roots. Parsed once from DER; each `X509`
/// is refcount-shared (`X509_up_ref` on clone), so building a per-connector
/// store from these is cheap and never re-parses the ~150 KB of DER. (boring's
/// `X509Store` is not `Clone`, so the store itself cannot be shared directly;
/// the certs are.)
static BORING_ROOTS: OnceLock<Vec<boring::x509::X509>> = OnceLock::new();

fn boring_roots() -> &'static [boring::x509::X509] {
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
fn build_root_store(additional_roots: &[Vec<u8>]) -> Result<boring::x509::store::X509StoreBuilder> {
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
    /// carry `additional_roots` / `client_cert` — a full dry-run build, since
    /// DER/PEM parse errors are only discoverable by parsing.  Those configs
    /// bypass the connector cache anyway, so the dry run costs one extra
    /// `SSL_CTX` at startup and nothing on the dial path.
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
        if !config.additional_roots.is_empty() || config.client_cert.is_some() {
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
        let mut cfg = self
            .connector
            .configure()
            .map_err(|e| TransportError::Tls(format!("boring: configure: {e}")))?;

        // SNI — omitted for IP literals (RFC 6066 §3), matching Go's
        // crypto/tls.  Hostname
        // verification still runs: `tokio_boring::connect` hands the
        // literal to `X509_VERIFY_PARAM_set1_ip`, so a SAN `iPAddress`
        // match is required unless `skip_cert_verify` is set.
        cfg.set_use_server_name_indication(self.server_name.parse::<std::net::IpAddr>().is_err());

        // Snapshot the current ECH config before consuming `inner`. The lock
        // is held only across this snapshot — never across the await.
        let ech_snapshot = self.ech.lock().expect("ech mutex poisoned").clone();
        let ech_requested = ech_snapshot.is_some();

        // ECH inline path — per-connection setup on ConnectConfiguration.
        if let Some(EchOpts::Config(ech_bytes)) = &ech_snapshot {
            cfg.set_ech_config_list(ech_bytes)
                .map_err(|e| TransportError::Config(format!("boring: set_ech_config_list: {e}")))?;
            // RFC 9180 §6: ECH requires TLS 1.3.  BoringSSL enforces this
            // automatically when an ECH config list is set, but we set it
            // explicitly here so the requirement is visible at the call site.
            cfg.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))
                .map_err(|e| {
                    TransportError::Config(format!("boring: set_min_proto_version TLS1.3: {e}"))
                })?;
        }

        match tokio_boring::connect(cfg, &self.server_name, inner).await {
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
                Ok(Box::new(tls_stream))
            }
            Err(e) => {
                // If ECH was active and the server rejected with `ech_required`,
                // BoringSSL surfaces the new `retry_configs` blob the server
                // signed. Self-heal: store the new bytes so the *next*
                // `connect()` uses them. The current attempt still fails — the
                // inner stream is already consumed by `tokio_boring::connect`,
                // so we cannot re-dial here.
                if ech_requested {
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
                            return Err(TransportError::Tls(format!(
                                "boring TLS handshake (ECH rejected; retry_configs={hex}): {e}"
                            )));
                        }
                    }
                }
                Err(TransportError::Tls(format!("boring TLS handshake: {e}")))
            }
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same_ctx(a: &boring::ssl::SslConnector, b: &boring::ssl::SslConnector) -> bool {
        std::ptr::eq(a.context(), b.context())
    }

    /// Same (fingerprint, alpn, skip_cert_verify) → same shared `SSL_CTX`;
    /// different key → different context; uncacheable configs bypass the cache.
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
}
