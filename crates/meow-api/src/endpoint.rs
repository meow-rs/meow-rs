//! Controller endpoint transports beyond the plain TCP socket (issue #974).
//!
//! `external-controller-tls` (BoringSSL HTTPS), `external-controller-unix`
//! (Unix-domain socket) and `external-controller-pipe` (Windows named pipe)
//! each serve a clone of the API router over the one shared `AppState`.
//! These listeners are best-effort: their bind/setup failures are logged
//! and skipped by the caller — only the plain `external-controller` TCP
//! bind is a startup-fatal contract.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{debug, warn};

/// Resolve a controller listen address the way upstream does: a bare
/// `:port` binds all interfaces, hostnames resolve through the resolver,
/// and the first answer wins. Kept a string until bind so `-t` never
/// performs this lookup.
async fn resolve_listen_addr(addr: &str) -> Result<SocketAddr> {
    let normalized = match addr.strip_prefix(':') {
        Some(port) => format!("0.0.0.0:{port}"),
        None => addr.to_owned(),
    };
    let mut addrs = tokio::net::lookup_host(&normalized)
        .await
        .with_context(|| format!("cannot resolve controller address '{addr}'"))?;
    addrs
        .next()
        .with_context(|| format!("controller address '{addr}' resolved to nothing"))
}

// ── TLS (external-controller-tls) ──────────────────────────────────

/// How long one TLS handshake may take before the accept side drops the
/// connection — an idle ClientHello must not hold a handshake slot forever.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Concurrent in-flight TLS handshakes — bounds the task-per-accept
/// churn a slow-loris burst could otherwise pile up.
const MAX_CONCURRENT_TLS_HANDSHAKES: usize = 128;
/// Handshaken connections waiting on axum's accept — bounds the channel
/// so a serve stall cannot absorb unbounded finished handshakes.
const TLS_READY_QUEUE: usize = 64;
/// PEM file cap — a certificate chain with its key fits far under this;
/// the bound keeps a wrong-path FIFO/device file from reading forever.
const MAX_PEM_FILE_BYTES: u64 = 1 << 20;

/// A bound `external-controller-tls` listener: TCP accept runs on a driver
/// task that performs the BoringSSL handshake per connection and hands
/// axum only finished `SslStream`s (the `tokio_boring` equivalent of a
/// `TlsAcceptor` service).
pub struct TlsEndpoint {
    local_addr: SocketAddr,
    rx: tokio::sync::mpsc::Receiver<(tokio_boring::SslStream<tokio::net::TcpStream>, SocketAddr)>,
    driver: tokio::task::JoinHandle<()>,
}

impl TlsEndpoint {
    /// The bound address — for the startup log before the endpoint moves
    /// into its serve task (same value as `Listener::local_addr`).
    pub fn addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for TlsEndpoint {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl axum::serve::Listener for TlsEndpoint {
    type Io = tokio_boring::SslStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The driver only stops on panic or `Drop::abort` — axum's
            // `Listener` contract has no error channel, so park rather
            // than spin on a closed channel.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

/// Bind the HTTPS controller endpoint. Identity order matches mihomo: a
/// configured `tls.certificate`/`tls.private-key` pair loads as inline PEM
/// (both carry `-----BEGIN`) else as two home-relative file paths; with
/// neither set the endpoint generates an ephemeral self-signed identity.
/// Bind/identity failures are for the caller to log-and-skip.
pub async fn bind_tls(
    addr: &str,
    certificate: Option<&str>,
    private_key: Option<&str>,
) -> Result<TlsEndpoint> {
    let acceptor = match (certificate, private_key) {
        (None, None) => {
            debug!("external-controller-tls: no identity configured; generating an ephemeral self-signed certificate");
            let (certs, key) = generate_self_signed_identity()?;
            meow_config::build_api_tls_acceptor_from_parts(&certs, &key)?
        }
        (Some(cert), Some(key)) => {
            let (cert_pem, key_pem) = load_identity_pair(cert, key)?;
            meow_config::build_api_tls_acceptor(&cert_pem, &key_pem)?
        }
        // build_config rejects a one-sided pair when the listener is
        // declared; CLI overrides pass through the same ApiConfig.
        _ => anyhow::bail!("tls.certificate and tls.private-key must be set together"),
    };
    let resolved = resolve_listen_addr(addr).await?;
    let listener = tokio::net::TcpListener::bind(resolved)
        .await
        .with_context(|| format!("external-controller-tls cannot bind {resolved}"))?;
    let local_addr = listener
        .local_addr()
        .context("external-controller-tls bound address")?;
    let (tx, rx) = tokio::sync::mpsc::channel(TLS_READY_QUEUE);
    let driver = tokio::spawn(drive_tls(listener, Arc::new(acceptor), tx));
    Ok(TlsEndpoint {
        local_addr,
        rx,
        driver,
    })
}

async fn drive_tls(
    listener: tokio::net::TcpListener,
    acceptor: Arc<boring::ssl::SslAcceptor>,
    tx: tokio::sync::mpsc::Sender<(tokio_boring::SslStream<tokio::net::TcpStream>, SocketAddr)>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TLS_HANDSHAKES));
    loop {
        if tx.is_closed() {
            return;
        }
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Awaiting the permit is the bound: with every slot held by
                // in-flight handshakes the accept loop applies backpressure
                // instead of piling up tasks (slow-loris guard).
                let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                    return;
                };
                let acceptor = Arc::clone(&acceptor);
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(
                        TLS_HANDSHAKE_TIMEOUT,
                        tokio_boring::accept(&acceptor, stream),
                    )
                    .await
                    {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, peer)).await;
                        }
                        Ok(Err(e)) => {
                            debug!("external-controller-tls handshake from {peer} failed: {e}");
                        }
                        Err(_) => {
                            debug!("external-controller-tls handshake from {peer} timed out");
                        }
                    }
                });
            }
            // Transient accept failure (fd exhaustion, …): log and retry
            // after a beat, per axum's `Listener` contract.
            Err(e) => {
                warn!("external-controller-tls accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// `tls.certificate`/`tls.private-key` as PEM bytes: both `-----BEGIN`
/// strings are inline material; anything else is a pair of file paths —
/// upstream's pair-level fallback, so a mixed inline/path pair is an
/// error (the PEM half can never resolve as a path).
fn load_identity_pair(cert: &str, key: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    if cert.contains("-----BEGIN") && key.contains("-----BEGIN") {
        return Ok((cert.as_bytes().to_vec(), key.as_bytes().to_vec()));
    }
    let cert_path = std::path::Path::new(cert);
    let key_path = std::path::Path::new(key);
    let cert_resolved = meow_config::resolve_home_contained(cert_path)
        .map_err(|e| anyhow::anyhow!("tls.certificate: {e}"))?;
    let key_resolved = meow_config::resolve_home_contained(key_path)
        .map_err(|e| anyhow::anyhow!("tls.private-key: {e}"))?;
    Ok((
        read_pem_file(&cert_resolved, "tls.certificate")?,
        read_pem_file(&key_resolved, "tls.private-key")?,
    ))
}

/// Bounded regular-file PEM read — the same discipline as the plugin
/// loaders: regular files only, `O_NONBLOCK` against FIFOs, and a hard
/// byte cap. Never called by `-t`/PUT (those validate shape only).
fn read_pem_file(path: &std::path::Path, what: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let meta = std::fs::metadata(path)
        .with_context(|| format!("{what}: cannot stat {}", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!("{what}: {} is not a regular file", path.display());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NONBLOCK);
    let file = opts
        .open(path)
        .with_context(|| format!("{what}: cannot open {}", path.display()))?;
    let mut buf = Vec::new();
    file.take(MAX_PEM_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("{what}: cannot read {}", path.display()))?;
    if buf.len() as u64 > MAX_PEM_FILE_BYTES {
        anyhow::bail!(
            "{what}: {} exceeds {} bytes",
            path.display(),
            MAX_PEM_FILE_BYTES
        );
    }
    Ok(buf)
}

/// The ephemeral identity mihomo serves when `external-controller-tls`
/// has no configured PEMs: a fresh self-signed P-256 certificate for
/// `localhost`/`127.0.0.1`/`::1`, valid a year.
fn generate_self_signed_identity() -> Result<(
    Vec<boring::x509::X509>,
    boring::pkey::PKey<boring::pkey::Private>,
)> {
    use boring::{
        asn1::{Asn1Integer, Asn1Time},
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        x509::{extension::SubjectAlternativeName, X509Name, X509},
    };
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut name_b = X509Name::builder()?;
    name_b.append_entry_by_text("CN", "meow")?;
    let name = name_b.build();
    let mut b = X509::builder()?;
    b.set_version(2)?;
    let bn = BigNum::from_u32(1)?;
    let serial = Asn1Integer::from_bn(&bn)?;
    b.set_serial_number(&serial)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    b.set_pubkey(&key)?;
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?;
    let mut san = SubjectAlternativeName::new();
    san.dns("localhost");
    san.ip("127.0.0.1");
    san.ip("::1");
    let ext = san.build(&b.x509v3_context(None, None))?;
    b.append_extension(&ext)?;
    b.sign(&key, MessageDigest::sha256())?;
    Ok((vec![b.build()], key))
}

// ── Unix socket (external-controller-unix) ─────────────────────────

/// A bound `external-controller-unix` socket. `accept` retries on the
/// transient errors a `Listener` impl must absorb.
#[cfg(unix)]
pub struct UnixEndpoint {
    listener: tokio::net::UnixListener,
}

#[cfg(unix)]
impl axum::serve::Listener for UnixEndpoint {
    type Io = tokio::net::UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.listener.accept().await {
                Ok(conn) => return conn,
                Err(e) => {
                    warn!("external-controller-unix accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// Removes the daemon's own socket file on drop — the guard outlives the
/// serve task so a shutdown never leaves a stale socket behind.
#[cfg(unix)]
pub struct UnixSocketGuard {
    path: Option<std::path::PathBuf>,
}

#[cfg(unix)]
impl UnixSocketGuard {
    /// The resolved path the socket was bound at.
    pub fn path(&self) -> &std::path::Path {
        self.path
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new(""))
    }

    /// Hand the path off without removing — for a caller that takes over
    /// cleanup (or knows the bind never landed).
    pub fn disarm(&mut self) {
        self.path = None;
    }
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            if let Err(e) = std::fs::remove_file(&path) {
                warn!(
                    "external-controller-unix: cannot remove {}: {e}",
                    path.display()
                );
            }
        }
    }
}

/// Bind `external-controller-unix` — meow's deliberately safer handling
/// (issue #974): where upstream unlinks an existing path unconditionally,
/// meow refuses a non-socket path, refuses another user's socket, and
/// reclaims only a *verified stale* socket it owns (connect →
/// `ECONNREFUSED` means nothing listens). The bound socket is `0600` —
/// upstream's `0666` opens the controller to every local user; meow also
/// keeps Bearer auth on, deliberate divergences both.
#[cfg(unix)]
pub fn bind_unix(path: &str) -> Result<(UnixEndpoint, UnixSocketGuard)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    let requested = std::path::Path::new(path);
    let resolved = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        meow_common::resolved_home_dir().join(requested)
    };
    match std::fs::symlink_metadata(&resolved) {
        Ok(md) if md.file_type().is_socket() => {
            if md.uid() != unsafe { libc::geteuid() } {
                anyhow::bail!(
                    "external-controller-unix: {} is a socket owned by another user; \
                     refusing to replace it",
                    resolved.display()
                );
            }
            match std::os::unix::net::UnixStream::connect(&resolved) {
                Ok(_) => anyhow::bail!(
                    "external-controller-unix: {} is already serving a live socket",
                    resolved.display()
                ),
                Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => {
                    warn!(
                        "external-controller-unix: reclaiming stale socket {}",
                        resolved.display()
                    );
                    std::fs::remove_file(&resolved).with_context(|| {
                        format!("cannot reclaim stale socket {}", resolved.display())
                    })?;
                }
                Err(e) => anyhow::bail!(
                    "external-controller-unix: cannot probe existing socket {}: {e}",
                    resolved.display()
                ),
            }
        }
        Ok(_) => anyhow::bail!(
            "external-controller-unix: {} exists and is not a socket; \
             refusing to replace an unrelated file",
            resolved.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = resolved.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "external-controller-unix: cannot create directory {}",
                        parent.display()
                    )
                })?;
            }
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "external-controller-unix: cannot stat {}",
                    resolved.display()
                )
            })
        }
    }
    let listener = tokio::net::UnixListener::bind(&resolved).with_context(|| {
        format!(
            "external-controller-unix cannot bind {}",
            resolved.display()
        )
    })?;
    // Owner-only — the controller is authenticated, but the socket file
    // never needs the world-read/write upstream grants it.
    if let Err(e) = std::fs::set_permissions(&resolved, std::fs::Permissions::from_mode(0o600)) {
        warn!(
            "external-controller-unix: cannot chmod {}: {e}",
            resolved.display()
        );
    }
    Ok((
        UnixEndpoint { listener },
        UnixSocketGuard {
            path: Some(resolved),
        },
    ))
}

// ── Windows named pipe (external-controller-pipe) ──────────────────

/// A bound `external-controller-pipe` listener. One `NamedPipeServer`
/// instance per connection: each `accept` waits on the pending instance's
/// client connect, then pre-creates the next one. Byte mode + reject
/// remote clients matches upstream's pipe semantics.
#[cfg(windows)]
pub struct PipeEndpoint {
    name: String,
    pending: tokio::net::windows::named_pipe::NamedPipeServer,
}

#[cfg(windows)]
impl PipeEndpoint {
    fn new_instance(&self) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
            .reject_remote_clients(true)
            .create(&self.name)
    }
}

#[cfg(windows)]
impl axum::serve::Listener for PipeEndpoint {
    type Io = tokio::net::windows::named_pipe::NamedPipeServer;
    type Addr = String;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.pending.connect().await {
                Ok(()) => match self.new_instance() {
                    Ok(next) => {
                        let connected = std::mem::replace(&mut self.pending, next);
                        return (connected, self.name.clone());
                    }
                    // A replacement-instance failure leaves `pending`
                    // connected — drop it rather than leak a half state.
                    Err(e) => {
                        warn!("external-controller-pipe: cannot create next instance: {e}");
                        match self.new_instance() {
                            Ok(next) => self.pending = next,
                            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
                        }
                    }
                },
                Err(e) => {
                    warn!("external-controller-pipe connect error: {e}");
                    match self.new_instance() {
                        Ok(next) => self.pending = next,
                        Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.name.clone())
    }
}

/// Bind `external-controller-pipe`. `first_pipe_instance` claims the name
/// so a squatting pipe cannot already exist; the default security
/// descriptor restricts access to the creating user and SYSTEM, which is
/// the restricted-ACL posture upstream applies by hand.
#[cfg(windows)]
pub fn bind_pipe(name: &str) -> Result<PipeEndpoint> {
    let pending = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
        .reject_remote_clients(true)
        .create(name)
        .with_context(|| format!("external-controller-pipe cannot create '{name}'"))?;
    Ok(PipeEndpoint {
        name: name.to_owned(),
        pending,
    })
}
