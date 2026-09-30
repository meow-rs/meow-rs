//! TLS client transport layer (`features = ["tls"]`).
//!
//! [`TlsLayer`] wraps any inner [`Stream`] with a TLS handshake and returns the
//! upgraded stream ready for the next layer (WebSocket, gRPC, …) or for the
//! proxy protocol codec (Trojan, VMess, …).
//!
//! # Backend
//!
//! Every non-REALITY handshake is performed by BoringSSL (`boring` +
//! `tokio-boring`, see `tls/boring_backend.rs`): plain TLS, uTLS fingerprint
//! shaping (`client-fingerprint`), ECH (with server `retry_configs`
//! self-healing), mTLS and ALPN.  There is no rustls backend; `reality`
//! configs take the in-tree REALITY record layer (`reality_tls.rs`) instead.
//!
//! # SNI resolution contract
//!
//! `meow-config` resolves the effective SNI **before** constructing
//! [`TlsConfig`]; the transport layer never sees the dial address.
//! Resolution rules (applied in `meow-config`):
//!
//! | YAML `servername` | `server` field   | `TlsConfig.sni`       |
//! |-------------------|------------------|-----------------------|
//! | set               | any              | `Some(servername)`    |
//! | unset             | hostname         | `Some(hostname)`      |
//! | unset             | IP literal       | `Some("1.2.3.4")`*   |
//!
//! *An IP literal is used for certificate verification (SAN `iPAddress`)
//! but is **not** sent in the TLS SNI extension: RFC 6066 §3 prohibits IP
//! literals in SNI.  The BoringSSL path disables SNI explicitly
//! (`set_use_server_name_indication(false)`) and lets
//! `X509_VERIFY_PARAM_set1_ip` do the match.  Test case A9 asserts this.
//!
//! `sni = None` is never produced for a valid TLS connection; [`TlsLayer::new`]
//! returns [`TransportError::Config`] if it receives `None`.
//!
//! # Connector sharing
//!
//! The per-process BoringSSL `SSL_CTX` is memoised keyed on the
//! [`TlsConfig`] fields that shape it (`fingerprint`, `curves`,
//! `alpn`, `skip_cert_verify`).  A subscription with hundreds of TLS
//! proxies therefore costs one context per distinct key rather than
//! one per proxy.
//! Configs carrying `additional_roots` / `client_cert` (or the
//! per-construction `random` fingerprint) bypass the cache.

use std::io;

use async_trait::async_trait;
use tracing::warn;

use crate::{Result, Stream, Transport, TransportError};

pub(crate) mod boring_backend;
pub(crate) mod boring_stream;

use boring_backend::{BoringInner, LazyBoringInner};

// ─── Config structs ───────────────────────────────────────────────────────────

/// Source of the ECH config list.
///
/// DNS-sourced ECH (`ech-opts.enable = true` without `ech-opts.config`) is
/// resolved by `meow_config::ech_dns` before this layer is built — the DNS
/// HTTPS-record answer lands here as `Config` bytes, so the enum only ever
/// carries an inline list.
#[derive(Debug, Clone)]
pub enum EchOpts {
    /// Inline ECH config list bytes, base64-decoded by `meow-config` before
    /// this struct is constructed.
    ///
    /// YAML key: `ech-opts.config`
    Config(Vec<u8>),
}

/// REALITY client authentication parameters for TLS-based outbound proxies.
///
/// Built by `meow-config` from `reality-opts:`. The public key is the server's
/// X25519 public key, and `short_id` is the decoded, zero-padded short id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub support_x25519_mlkem768: bool,
}

/// TLS layer configuration, built by `meow-config` from YAML and passed
/// into [`TlsLayer::new`].  This struct never sees YAML directly.
///
/// Corresponds to the `tls:`, `skip-cert-verify:`, `alpn:`,
/// `client-fingerprint:`, and `ech-opts:` keys in a proxy entry.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Whether TLS is enabled.  If `false`, no [`TlsLayer`] should be
    /// constructed; this field is a convenience for config-side logic.
    pub enabled: bool,

    /// Effective SNI, resolved by config before construction (see module doc).
    /// Must be `Some` when `enabled = true`.
    pub sni: Option<String>,

    /// ALPN protocol IDs offered in the ClientHello.
    /// Empty slice → no ALPN extension.
    pub alpn: Vec<String>,

    /// Disable server certificate verification.  Emits a `warn!` once.
    pub skip_cert_verify: bool,

    /// Minimum negotiated TLS version (`None` = BoringSSL default).
    /// ECH forces ≥ TLS 1.3 regardless (RFC 9180 §6).
    pub min_version: Option<TlsVersion>,

    /// Maximum negotiated TLS version (`None` = BoringSSL default).
    /// Used by shadow-tls v1, which only speaks TLS 1.2 on the wire.
    pub max_version: Option<TlsVersion>,

    /// Hostname the peer certificate is verified against when it differs
    /// from the connection SNI (mihomo's `name-cert-verify` / Go
    /// `VerifyPeerCertificate` name override).  `None` → verify against
    /// `sni`.  Ignored when `skip_cert_verify` is set or on the REALITY
    /// path.
    pub verify_name: Option<String>,

    /// Certificate pinning by SHA-256 hash of a cert in the presented
    /// chain (mihomo `fingerprint` / SSL pinning — *not* a uTLS profile;
    /// uTLS lives in [`fingerprint`](Self::fingerprint)).
    ///
    /// When set, the pin **replaces** CA verification (upstream sets
    /// `InsecureSkipVerify` and runs the pin check in
    /// `VerifyPeerCertificate`): a leaf match accepts the cert outright; a
    /// non-leaf match verifies the leaf under the pinned cert as root
    /// plus a `check_name` DNS check (`verify_name`, else `sni`).
    /// Ignored on the REALITY path.
    pub cert_pin: Option<[u8; 32]>,

    /// Optional mutual-TLS client certificate (PEM-encoded).
    pub client_cert: Option<ClientCert>,

    /// `client-fingerprint` YAML value.
    ///
    /// uTLS fingerprint profile applied to the ClientHello: `chrome`,
    /// `firefox`, `safari`, `ios`, `android`, `edge`, `random`, plus
    /// version-pinned aliases.  Unknown profiles warn and use BoringSSL
    /// defaults.
    pub fingerprint: Option<String>,

    /// `supported_groups` override (BoringSSL colon-separated names, e.g.
    /// `"X25519:P-256:P-384"`).  `None` → BoringSSL's default — which in
    /// the BoringSSL vendored by boring-sys ≥5.x includes the
    /// `X25519MLKEM768` post-quantum key share (boring-pq.patch).
    /// Protocols that must not offer hybrid PQ (shadow-tls v2: upstream
    /// strips it because it breaks v2 servers) pin a classic list here.
    /// Applied after — and therefore overriding — a resolved
    /// [`fingerprint`](Self::fingerprint) profile's own curve list.
    pub curves: Option<String>,

    /// Extra CA certificates (DER-encoded) added to the root store in
    /// addition to `webpki-roots`.  Used in tests with self-signed certs;
    /// production deployments leave this empty.
    pub additional_roots: Vec<Vec<u8>>,

    /// ECH config source.
    ///
    /// `Some(EchOpts::Config(bytes))` → inline ECH config list.
    /// DNS-sourced ECH arrives here already resolved; see [`EchOpts`].
    ///
    /// Applied per connection by BoringSSL; a server `ech_required`
    /// rejection rotates the stored config to the supplied `retry_configs`.
    pub ech: Option<EchOpts>,

    /// REALITY authentication options. When present, TLS uses the dedicated
    /// REALITY TLS 1.3 path because the ClientHello session_id must be computed
    /// from this connection's X25519 key share before it is written.
    pub reality: Option<RealityConfig>,
}

impl TlsConfig {
    /// Convenience constructor: TLS enabled, SNI set, all other fields default.
    pub fn new(sni: impl Into<String>) -> Self {
        Self {
            enabled: true,
            sni: Some(sni.into()),
            alpn: Vec::new(),
            skip_cert_verify: false,
            min_version: None,
            max_version: None,
            verify_name: None,
            cert_pin: None,
            client_cert: None,
            fingerprint: None,
            curves: None,
            additional_roots: Vec::new(),
            ech: None,
            reality: None,
        }
    }
}

/// Whether `fp` names a uTLS fingerprint profile the boring backend
/// actually shapes (`chrome`, `firefox`, `safari`, `ios`, `android`,
/// `edge`, `random`, plus version-pinned aliases).  Unknown names fall
/// back to BoringSSL defaults with a warning — callers that must reason
/// about the *effective* ClientHello (e.g. shadow-tls v2's ML-KEM pin)
/// use this to tell a resolved profile's own group list from the
/// default hello.
pub fn is_supported_fingerprint(fp: &str) -> bool {
    boring_backend::fingerprint_is_known(fp)
}

/// TLS protocol version bound for [`TlsConfig::min_version`] /
/// [`TlsConfig::max_version`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
}

/// Optional mutual-TLS client certificate (PEM-encoded key and certificate).
#[derive(Debug, Clone)]
pub struct ClientCert {
    /// PEM-encoded X.509 certificate chain.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key (PKCS#8 or RSA).
    pub key_pem: Vec<u8>,
}

// ─── TLS backend dispatch ─────────────────────────────────────────────────────

enum TlsBackend {
    #[cfg(feature = "reality")]
    Reality(crate::reality_tls::RealityTlsLayer),
    Boring(Box<LazyBoringInner>),
}

// ─── TlsLayer (public facade) ─────────────────────────────────────────────────

/// TLS client transport layer.
///
/// Build once at startup from a [`TlsConfig`]; call [`Transport::connect`] for
/// each new connection.  Handshakes run on BoringSSL; `reality` configs take
/// the in-tree REALITY path instead.
pub struct TlsLayer {
    backend: TlsBackend,
}

impl TlsLayer {
    /// Construct a `TlsLayer` from the given configuration.
    ///
    /// The BoringSSL `SslConnector` is built lazily on the first `connect()`
    /// and shared across layers with the same shaping key; everything that
    /// can make that build fail is validated here so errors surface at
    /// startup.
    ///
    /// # Errors
    ///
    /// * [`TransportError::Config`] — `sni` is `None`.
    /// * [`TransportError::Config`] — an ALPN id is empty or longer than 255 bytes.
    /// * [`TransportError::Config`] — `reality` is set without the `reality` feature.
    /// * [`TransportError::Config`] — a DER in `additional_roots` is malformed.
    /// * [`TransportError::Config`] — `client_cert` PEM is unparseable.
    /// * [`TransportError::Tls`] — client cert + key don't match.
    pub fn new(config: &TlsConfig) -> Result<Self> {
        #[cfg(not(feature = "reality"))]
        if config.reality.is_some() {
            return Err(crate::TransportError::Config(
                "reality-opts requires the `reality` Cargo feature in this build; \
                 recompile with `--features reality`."
                    .into(),
            ));
        }

        #[cfg(feature = "reality")]
        if config.reality.is_some() {
            return Ok(Self {
                backend: TlsBackend::Reality(crate::reality_tls::RealityTlsLayer::new(config)?),
            });
        }

        // Warn at construction, once per proxy — the backend stays silent so
        // a lazily-built (and cached) SSL_CTX doesn't swallow the warning
        // for later proxies sharing it.
        if config.skip_cert_verify {
            warn!(
                sni = ?config.sni,
                "skip-cert-verify=true: TLS certificate verification is disabled; \
                 the connection is NOT authenticated against a trusted CA"
            );
        }

        BoringInner::validate(config)?;
        tracing::debug!(
            fingerprint = ?config.fingerprint,
            ech = config.ech.is_some(),
            sni = ?config.sni,
            "TLS: BoringSSL backend (lazy init)"
        );
        Ok(Self {
            backend: TlsBackend::Boring(Box::new(LazyBoringInner::new(config.clone()))),
        })
    }

    /// Handshake over a caller-owned stream type, returning the concrete
    /// `SslStream<S>` so the inner stream can be recovered afterwards via
    /// `SslStream::get_mut` — used by shadow-tls, which discards the TLS
    /// session once the cover handshake ends and continues on the raw
    /// conn.  `inner` sees BoringSSL's flush pends as ordinary
    /// `Pending`s (boring 5.x retries `BIO_CTRL_FLUSH` natively); a shim
    /// `S` must still implement poll contracts itself.
    ///
    /// Handshake failures surface as [`ConnectTypedError::Handshake`],
    /// which keeps the source stream recoverable (shadow-tls v3 treats a
    /// specific late-handshake failure as the expected outcome — the
    /// cover's Finished never verifies against the wire-patched
    /// ClientHello transcript).
    ///
    /// REALITY backends reject this — there is no TLS session to discard.
    pub async fn connect_typed<S>(&self, inner: S) -> TypedConnectResult<S>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match &self.backend {
            #[cfg(feature = "reality")]
            TlsBackend::Reality(_) => {
                Err(ConnectTypedError::Transport(crate::TransportError::Config(
                    "connect_typed is not supported on the REALITY backend".into(),
                )))
            }
            TlsBackend::Boring(lazy) => lazy.connect_typed(inner).await,
        }
    }
}

/// Result of [`TlsLayer::connect_typed`].
pub type TypedConnectResult<S> =
    std::result::Result<tokio_boring::SslStream<S>, ConnectTypedError<S>>;

/// Failure of [`TlsLayer::connect_typed`].
///
/// Split into two classes because callers that wrap the handshake in a
/// shim (shadow-tls) can still make use of the stream — and of the
/// aborted `Ssl`'s state — after a handshake error, while a setup error
/// never touched the wire.
pub enum ConnectTypedError<S> {
    /// Configuration/setup failed before the TLS handshake ran — nothing
    /// was sent, no stream to recover.
    Transport(TransportError),
    /// The TLS handshake failed mid-flight.  `into_source_stream()`
    /// recovers `S`; `ssl()` exposes the aborted session state (e.g.
    /// `verify_result`).
    Handshake(tokio_boring::HandshakeError<S>),
}

impl<S> ConnectTypedError<S> {
    /// Collapse into a plain [`TransportError`], discarding any
    /// recoverable stream — for callers that only want the error.
    pub fn into_transport(self) -> TransportError {
        match self {
            Self::Transport(e) => e,
            Self::Handshake(e) => {
                // Preserve the inner io error (raw errno) when the
                // handshake failed at the socket layer — ENOBUFS/ENOMEM
                // must reach DialFailureTracker's local-resource
                // classification intact (issue #680).
                match e.as_io_error() {
                    Some(io_err) => TransportError::Io(match io_err.raw_os_error() {
                        Some(errno) => io::Error::from_raw_os_error(errno),
                        None => io::Error::new(io_err.kind(), format!("boring TLS handshake: {e}")),
                    }),
                    None => TransportError::Tls(format!("boring TLS handshake: {e}")),
                }
            }
        }
    }
}

#[async_trait]
impl Transport for TlsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        match &self.backend {
            #[cfg(feature = "reality")]
            TlsBackend::Reality(r) => r.connect(inner).await,
            TlsBackend::Boring(lazy) => lazy.connect(inner).await,
        }
    }
}
