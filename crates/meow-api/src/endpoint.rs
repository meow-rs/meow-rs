//! Controller endpoint transports beyond the plain TCP socket (issue #974).
//!
//! `external-controller-tls` (BoringSSL HTTPS), `external-controller-unix`
//! (Unix-domain socket) and `external-controller-pipe` (Windows named pipe)
//! each serve a clone of the API router over the one shared `AppState`.
//! These listeners are best-effort: their bind/setup failures are logged
//! and skipped by the caller — only the plain `external-controller` TCP
//! bind is a startup-fatal contract.

use anyhow::{Context, Result};
use tracing::warn;

// ── TLS (external-controller-tls) ──────────────────────────────────

/// The HTTPS controller endpoint exists only under the `api-tls` feature
/// (issue #974): BoringSSL's acceptor plus axum's `http2` server code
/// cost ~500 KB in the `minimal` bundle, so ADR-0007 keeps the feature
/// off there. Without it `external-controller-tls` is dead config the
/// startup path warns about — parse/PUT keep working.
#[cfg(feature = "api-tls")]
mod tls {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use anyhow::{Context, Result};
    use tracing::{debug, warn};

    /// What a controller listen address binds, resolved the way
    /// upstream's `Listen("tcp", …)` behaves. Kept a string until bind
    /// so `-t` never performs this lookup.
    enum ListenTarget {
        /// A bare `:port` means "the wildcard" — `[::]` dual-stack
        /// first (accepts v4 *and* v6), `0.0.0.0` last for kernels
        /// that cannot do IPv6. Each candidate is tried in turn.
        Wildcard(Vec<SocketAddr>),
        /// A hostname binds the one answer Go's resolver order would
        /// serve first — the first v4 answer, else the first — once;
        /// alternate answers are not retried.
        Single(SocketAddr),
    }

    async fn resolve_listen_target(addr: &str) -> Result<ListenTarget> {
        if let Some(port) = addr
            .strip_prefix(':')
            .map(str::parse::<u16>)
            .transpose()
            .with_context(|| format!("controller address '{addr}': bad port"))?
        {
            // Even resolving [::] needs IPv6 support in the resolver;
            // the port-only contract is "the wildcard", so a v6-less
            // host degrades to the v4 wildcard rather than failing.
            let mut addrs: Vec<SocketAddr> =
                match tokio::net::lookup_host(format!("[::]:{port}")).await {
                    Ok(found) => found.collect(),
                    Err(_) => {
                        vec![SocketAddr::new(
                            std::net::Ipv4Addr::UNSPECIFIED.into(),
                            port,
                        )]
                    }
                };
            // The v4 twin is appended after [::] so the dual-stack
            // wildcard keeps its lead — the escape hatch only.
            let fallback = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port);
            if !addrs.contains(&fallback) {
                addrs.push(fallback);
            }
            if addrs.is_empty() {
                anyhow::bail!("controller address '{addr}' resolved to nothing");
            }
            return Ok(ListenTarget::Wildcard(addrs));
        }
        let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host(addr)
            .await
            .with_context(|| format!("cannot resolve controller address '{addr}'"))?
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("controller address '{addr}' resolved to nothing");
        }
        // Go's resolver order prefers v4 — stable-sort the family so
        // each family keeps its resolver order, then take the first.
        addrs.sort_by_key(SocketAddr::is_ipv6);
        Ok(ListenTarget::Single(addrs[0]))
    }

    /// Bind the resolved target — the wildcard list's first candidate
    /// that takes (the `:port` v6-capability fallback), or the
    /// hostname's single pick.
    async fn bind_listen_target(target: &ListenTarget) -> Result<tokio::net::TcpListener> {
        match target {
            ListenTarget::Single(addr) => bind_tcp_dual_stack(*addr).await,
            ListenTarget::Wildcard(addrs) => {
                let mut last_err = None;
                for addr in addrs {
                    match bind_tcp_dual_stack(*addr).await {
                        Ok(listener) => return Ok(listener),
                        Err(e) => {
                            warn!("external-controller-tls cannot bind {addr}: {e:#}");
                            last_err = Some(e);
                        }
                    }
                }
                Err(last_err.unwrap_or_else(|| anyhow::anyhow!("nothing to bind")))
            }
        }
    }

    /// Bind the resolved TLS listen address. An unspecified v6 address —
    /// reached through a bare `:port` or an explicit `[::]` — must accept
    /// v4-mapped clients like upstream, so `IPV6_V6ONLY` is forced off;
    /// platforms differ on the default (Windows defaults to v6-only).
    async fn bind_tcp_dual_stack(addr: SocketAddr) -> Result<tokio::net::TcpListener> {
        if addr.is_ipv6() && addr.ip().is_unspecified() {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .context("external-controller-tls: cannot create socket")?;
            socket
                .set_only_v6(false)
                .context("external-controller-tls: cannot clear IPV6_V6ONLY")?;
            // std's TcpListener::bind sets this on unix — the raw path
            // must not lose it: a TIME_WAIT socket sharing the port
            // otherwise fails a restart's rebind with EADDRINUSE.
            // Winsock's SO_REUSEADDR instead means "allow stealing an
            // in-use port" (why std and tokio never set it there), so
            // the flag is unix-only.
            #[cfg(unix)]
            socket
                .set_reuse_address(true)
                .context("external-controller-tls: cannot set SO_REUSEADDR")?;
            socket
                .set_nonblocking(true)
                .context("external-controller-tls: cannot set nonblocking")?;
            socket
                .bind(&addr.into())
                .with_context(|| format!("external-controller-tls cannot bind {addr}"))?;
            socket
                .listen(1024)
                .context("external-controller-tls: cannot listen")?;
            tokio::net::TcpListener::from_std(socket.into())
                .context("external-controller-tls: cannot adopt listener")
        } else {
            tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("external-controller-tls cannot bind {addr}"))
        }
    }

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
        rx: tokio::sync::mpsc::Receiver<(
            tokio_boring::SslStream<tokio::net::TcpStream>,
            SocketAddr,
        )>,
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
                build_api_tls_acceptor_from_parts(&certs, &key)?
            }
            (Some(cert), Some(key)) => {
                let (cert_pem, key_pem) = load_identity_pair(cert, key)?;
                build_api_tls_acceptor(&cert_pem, &key_pem)?
            }
            // Like upstream, a one-sided pair is an endpoint-local failure:
            // config build validates shape only, so this is the rejection
            // point that logs and skips just this listener (issue #974).
            _ => anyhow::bail!("tls.certificate and tls.private-key must be set together"),
        };
        let target = resolve_listen_target(addr).await?;
        let listener = bind_listen_target(&target).await?;
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
    /// upstream's pair-level fallback. The inline check classifies each
    /// value *before* any path resolution: a mixed inline/path pair fails
    /// here, so PEM bytes can never be echoed as a "path" into startup logs
    /// (issue #974).
    fn load_identity_pair(cert: &str, key: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let cert_inline = cert.contains("-----BEGIN");
        let key_inline = key.contains("-----BEGIN");
        if cert_inline != key_inline {
            anyhow::bail!(
                "tls.certificate and tls.private-key must be both inline PEM or both file paths"
            );
        }
        if cert_inline {
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
    /// has no configured PEMs: a fresh self-signed RSA-2048 certificate for
    /// `localhost`/`127.0.0.1`/`::1`, valid a year.
    fn generate_self_signed_identity() -> Result<(
        Vec<boring::x509::X509>,
        boring::pkey::PKey<boring::pkey::Private>,
    )> {
        use boring::{
            asn1::{Asn1Integer, Asn1Time},
            bn::BigNum,
            hash::MessageDigest,
            pkey::PKey,
            rsa::Rsa,
            x509::{extension::SubjectAlternativeName, X509Name, X509},
        };
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
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

    /// Build the BoringSSL acceptor for the `external-controller-tls`
    /// listener from PEM material (leaf first, extra chain certs after) —
    /// called at endpoint bind, never at config build (`-t` touches no PEM
    /// material or files). `mozilla_intermediate_v5` floors at
    /// TLS 1.2; ALPN advertises exactly the protocols the HTTP stack serves.
    fn build_api_tls_acceptor(
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<boring::ssl::SslAcceptor, anyhow::Error> {
        let certs = boring::x509::X509::stack_from_pem(cert_pem)
            .map_err(|e| anyhow::anyhow!("tls.certificate: not a valid PEM certificate: {e}"))?;
        if certs.is_empty() {
            anyhow::bail!("tls.certificate: PEM carries no certificate");
        }
        let key = boring::pkey::PKey::private_key_from_pem(key_pem)
            .map_err(|e| anyhow::anyhow!("tls.private-key: not a valid PEM private key: {e}"))?;
        build_api_tls_acceptor_from_parts(&certs, &key)
    }

    /// The acceptor build itself, on already-decoded identity material — the
    /// `external-controller-tls` endpoint's ephemeral self-signed identity
    /// reaches the same builder without a PEM round-trip (issue #974).
    fn build_api_tls_acceptor_from_parts(
        certs: &[boring::x509::X509],
        key: &boring::pkey::PKey<boring::pkey::Private>,
    ) -> Result<boring::ssl::SslAcceptor, anyhow::Error> {
        let mut builder =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                .map_err(|e| anyhow::anyhow!("external-controller-tls: {e}"))?;
        let leaf = certs
            .first()
            .ok_or_else(|| anyhow::anyhow!("tls.certificate: no certificate"))?;
        builder
            .set_certificate(leaf)
            .map_err(|e| anyhow::anyhow!("tls.certificate: {e}"))?;
        for extra in &certs[1..] {
            builder
                .add_extra_chain_cert(extra.clone())
                .map_err(|e| anyhow::anyhow!("tls.certificate chain: {e}"))?;
        }
        builder
            .set_private_key(key)
            .map_err(|e| anyhow::anyhow!("tls.private-key: {e}"))?;
        builder.check_private_key().map_err(|e| {
            anyhow::anyhow!("tls.certificate and tls.private-key do not form a pair: {e}")
        })?;
        // Server-side ALPN picks from the *client's* offer in preference
        // order `h2` then `http/1.1` — `set_alpn_protos` applies to client
        // contexts, not acceptors.
        builder.set_alpn_select_callback(|_, client| {
            boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", client)
                .ok_or(boring::ssl::AlpnError::NOACK)
        });
        Ok(builder.build())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn resolve_bare_port_offers_dual_stack_then_v4() {
            // `:port` = "the wildcard": [::] dual-stack first, 0.0.0.0
            // last for hosts that cannot do IPv6 (issue #974).
            let ListenTarget::Wildcard(addrs) = resolve_listen_target(":9090").await.unwrap()
            else {
                panic!("bare port must resolve to wildcard candidates");
            };
            assert_eq!(
                addrs.as_slice(),
                [
                    SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 9090),
                    SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 9090),
                ]
            );
        }

        #[tokio::test]
        async fn resolve_picks_hostname_v4_answer_once() {
            // localhost answers both families in every stock hosts file;
            // the single pick must be the first v4 one (issue #974).
            let all: Vec<SocketAddr> = tokio::net::lookup_host("localhost:0")
                .await
                .unwrap()
                .collect();
            assert!(all.len() >= 2, "localhost unexpectedly single-stack: {all:?}");
            let ListenTarget::Single(addr) = resolve_listen_target("localhost:0").await.unwrap()
            else {
                panic!("hostname must resolve to a single bind target");
            };
            assert!(addr.is_ipv4(), "v4 answer must be the pick: {addr}");
        }

        #[tokio::test]
        async fn resolve_bad_bare_port_fails() {
            assert!(resolve_listen_target(":notaport").await.is_err());
        }

        #[tokio::test]
        async fn bind_wildcard_walks_candidates_past_failures() {
            // 192.0.2.1 (TEST-NET-1) is never a local address: the first
            // candidate fails and the loop must reach the second.
            let listener = bind_listen_target(&ListenTarget::Wildcard(vec![
                SocketAddr::new(std::net::Ipv4Addr::new(192, 0, 2, 1).into(), 0),
                SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0),
            ]))
            .await
            .unwrap();
            assert_eq!(
                listener.local_addr().unwrap().ip(),
                std::net::Ipv4Addr::LOCALHOST
            );
        }
    }
}

#[cfg(feature = "api-tls")]
pub use tls::{bind_tls, TlsEndpoint};

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
/// serve task so a shutdown never leaves a stale socket behind. It
/// unlinks only the *same file* it bound: the recorded dev+inode must
/// still identify a socket, so a swapped-in regular file or another
/// process's socket is never deleted (issue #974).
#[cfg(unix)]
pub struct UnixSocketGuard {
    path: Option<std::path::PathBuf>,
    /// `(st_dev, st_ino)` of the bound socket — the identity check Drop
    /// applies before unlinking.
    ident: (u64, u64),
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
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if let Some(path) = self.path.take() {
            let ours = std::fs::symlink_metadata(&path)
                .is_ok_and(|md| md.file_type().is_socket() && (md.dev(), md.ino()) == self.ident);
            if !ours {
                warn!(
                    "external-controller-unix: {} was replaced; leaving it alone",
                    path.display()
                );
                return;
            }
            if let Err(e) = std::fs::remove_file(&path) {
                warn!(
                    "external-controller-unix: cannot remove {}: {e}",
                    path.display()
                );
            }
        }
    }
}

/// Upper bound on one liveness probe of an existing socket file. A
/// blocking connect can stall indefinitely when the peer is alive but
/// its accept queue is full — startup must not hang on it: a timed-out
/// or otherwise inconclusive probe is treated as "live or uncertain"
/// and the endpoint is skipped rather than the file deleted (issue #974).
#[cfg(unix)]
const STALE_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Beat between the two refusal probes: BSD/macOS answers
/// `ECONNREFUSED` for a saturated accept queue too, so a single refusal
/// is not proof of staleness — a queue that drained connects on the
/// second probe (issue #974).
#[cfg(unix)]
const STALE_REPROBE_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// One bounded connect probe of an existing socket file.
#[cfg(unix)]
enum UnixProbe {
    /// The connect completed — something is listening.
    Live,
    /// `ECONNREFUSED` — nothing accepted the connect.
    Refused,
    /// Neither of the above (a full backlog's `EAGAIN`, the probe
    /// timeout, …) — live-or-uncertain: the file stays.
    Uncertain(std::io::Error),
}

#[cfg(unix)]
async fn probe_unix_socket(path: &std::path::Path) -> UnixProbe {
    match tokio::time::timeout(STALE_PROBE_TIMEOUT, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(_)) => UnixProbe::Live,
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ECONNREFUSED) => UnixProbe::Refused,
        Ok(Err(e)) => UnixProbe::Uncertain(e),
        Err(_) => UnixProbe::Uncertain(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "probe timed out",
        )),
    }
}

/// Unlink `path` only if it still identifies the socket file that was
/// probed stale — the `(dev, ino, ctime, ctime_nsec)` recorded before
/// the probes. Two daemons can race the same stale path: between the
/// stat and this unlink the loser may have already removed it and bound
/// a live socket of its own, and deleting that replacement would kill
/// it. The residual re-stat→unlink window cannot be closed: unix
/// sockets have no unlink-by-handle (issue #974).
#[cfg(unix)]
fn reclaim_stale_socket(path: &std::path::Path, probed: (u64, u64, i64, i64)) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let same = std::fs::symlink_metadata(path).is_ok_and(|md| {
        md.file_type().is_socket() && (md.dev(), md.ino(), md.ctime(), md.ctime_nsec()) == probed
    });
    if !same {
        anyhow::bail!(
            "external-controller-unix: {} changed while it was probed; leaving it alone",
            path.display()
        );
    }
    std::fs::remove_file(path)
        .with_context(|| format!("cannot reclaim stale socket {}", path.display()))
}

/// Whether a live process still holds a unix socket bound at `path` —
/// asked only after the connect probe refuses, which is ambiguous
/// where a saturated accept queue also answers `ECONNREFUSED`
/// (BSD/macOS). The answer comes from kernel socket tables, not a
/// third probe: libproc fd enumeration on Apple targets,
/// `/proc/net/unix` on Linux (whose refusal is already conclusive —
/// the table is a second opinion for a `shutdown`-not-`close`d
/// listener), and nowhere on other unixes, which stay conservative
/// (issue #974).
#[cfg(target_vendor = "apple")]
fn unix_socket_still_bound(path: &std::path::Path) -> Result<bool> {
    apple::socket_bound_at(path)
}

/// The `/proc/net/unix` arm — kernel ABI: one row per live socket,
/// bound path in the last column.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unix_socket_still_bound(path: &std::path::Path) -> Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let theirs = path.as_os_str().as_bytes();
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let canon = canon.as_os_str().as_bytes();
    let Ok(table) = std::fs::read("/proc/net/unix") else {
        // Refusal is already conclusive on Linux — without the table
        // the probe's own answer stands.
        return Ok(false);
    };
    for line in table.split(|&b| b == b'\n') {
        // `Num RefCount Protocol Flags Type St Inode Path` — the path
        // is everything after the seventh field (it may contain
        // spaces).
        let Some(bound) = line.splitn(8, |&b| b == b' ').nth(7) else {
            continue;
        };
        if bound == theirs || bound == canon {
            return Ok(true);
        }
    }
    Ok(false)
}

/// No kernel socket table to consult — the refused probe stays
/// ambiguous, so the endpoint errs on the live side.
#[cfg(all(
    unix,
    not(target_vendor = "apple"),
    not(target_os = "linux"),
    not(target_os = "android")
))]
fn unix_socket_still_bound(_path: &std::path::Path) -> Result<bool> {
    anyhow::bail!("no kernel socket table is available on this platform")
}

/// The libproc arm — `proc_pidinfo`/`proc_pidfdinfo` are the public
/// `<sys/proc_info.h>` ABI `lsof` enumerates processes with. A bound
/// unix socket reports its `sun_path` in `unsi_addr` (and connected
/// peers report it in `unsi_caddr`) — either proves the path is live.
#[cfg(target_vendor = "apple")]
mod apple {
    use std::mem::{offset_of, size_of, ManuallyDrop};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use anyhow::{Context, Result};

    const PROC_PIDLISTFDS: libc::c_int = 1;
    const PROX_FDTYPE_SOCKET: u32 = 2;
    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    const SOCKINFO_UN: libc::c_int = 3;
    const SOCK_MAXADDRLEN: usize = 255;
    const VINFO_STAT_BYTES: usize = 136;
    /// Cap on one pid's fd table — a pathological table beyond this
    /// is truncated, never grown without bound.
    const MAX_PID_FDS: usize = 65536;

    #[repr(C)]
    struct ProcFdinfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }
    #[repr(C)]
    struct ProcFileinfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_rfu: i32,
    }
    #[repr(C)]
    struct SockbufInfo {
        sbi_cc: u32,
        sbi_hiwat: u32,
        sbi_mbcnt: u32,
        sbi_mbmax: u32,
        sbi_lowat: i32,
        sbi_flags: i16,
        sbi_timeo: i16,
    }
    #[repr(C)]
    union UnsiAddr {
        sun: libc::sockaddr_un,
        _dummy: [u8; SOCK_MAXADDRLEN],
    }
    #[repr(C)]
    struct UnSockinfo {
        unsi_conn_so: u64,
        unsi_conn_pcb: u64,
        unsi_addr: UnsiAddr,
        unsi_caddr: UnsiAddr,
    }
    #[repr(C)]
    union SoiProto {
        un: ManuallyDrop<UnSockinfo>,
        _pad: [u8; size_of::<UnSockinfo>()],
    }
    #[repr(C)]
    struct SocketInfo {
        soi_stat: [u8; VINFO_STAT_BYTES],
        soi_so: u64,
        soi_pcb: u64,
        soi_type: i32,
        soi_protocol: i32,
        soi_family: i32,
        soi_options: i16,
        soi_linger: i16,
        soi_state: i16,
        soi_qlen: i16,
        soi_incqlen: i16,
        soi_qlimit: i16,
        soi_timeo: i16,
        soi_error: u16,
        soi_oobmark: u32,
        soi_rcv: SockbufInfo,
        soi_snd: SockbufInfo,
        soi_kind: i32,
        soi_rfu: u32,
        soi_proto: SoiProto,
    }
    #[repr(C)]
    struct SocketFdinfo {
        pfi: ProcFileinfo,
        psi: SocketInfo,
    }

    // Pinned to <sys/proc_info.h> at compile time — a layout drift
    // fails the build rather than feeding reads at wrong offsets.
    const _: () = assert!(size_of::<SocketFdinfo>() == 792);
    const _: () = assert!(offset_of!(SocketFdinfo, psi.soi_family) == 184);
    const _: () = assert!(offset_of!(SocketFdinfo, psi.soi_kind) == 256);
    const _: () = assert!(offset_of!(SocketFdinfo, psi.soi_proto) == 264);
    const _: () = assert!(offset_of!(UnSockinfo, unsi_addr) == 16);
    const _: () = assert!(offset_of!(libc::sockaddr_un, sun_path) == 2);

    /// One `sockaddr_un`'s path bytes, NUL-trimmed.
    fn sun_path_bytes(sun: &libc::sockaddr_un) -> &[u8] {
        // SAFETY: reading the fixed-size array in place.
        let raw = unsafe {
            std::slice::from_raw_parts(sun.sun_path.as_ptr().cast::<u8>(), sun.sun_path.len())
        };
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        &raw[..end]
    }

    /// The spellings that name `path` — the path itself plus its
    /// canonical form, so a socket bound through a symlink (`/tmp` →
    /// `/private/tmp`, `/var` → `/private/var`) still matches.
    fn path_spellings(path: &Path) -> Vec<Vec<u8>> {
        let mut out = vec![path.as_os_str().as_bytes().to_vec()];
        if let Ok(canon) = std::fs::canonicalize(path) {
            let canon = canon.into_os_string().into_encoded_bytes();
            if canon != out[0] {
                out.push(canon);
            }
        }
        out
    }

    /// One candidate address against the spellings — raw first, then
    /// canonicalized on both sides (the bound path may be written
    /// under a different spelling; a live socket's file exists, so
    /// canonicalize resolves it).
    fn matches(ours: &[Vec<u8>], theirs: &[u8]) -> bool {
        if theirs.is_empty() {
            return false;
        }
        if ours.iter().any(|o| o.as_slice() == theirs) {
            return true;
        }
        std::fs::canonicalize(Path::new(std::ffi::OsStr::from_bytes(theirs)))
            .ok()
            .is_some_and(|c| {
                ours.iter()
                    .any(|o| o.as_slice() == c.as_os_str().as_bytes())
            })
    }

    /// Fill `fds` with pid's fd table. Returns false when the table
    /// could not be read at all (dead pid, or denied). A NULL buffer
    /// makes `proc_pidinfo` report the byte count the table needs —
    /// size to that first instead of growing blind.
    fn list_fds(pid: i32, fds: &mut Vec<ProcFdinfo>) -> bool {
        fds.clear();
        // SAFETY: no buffer is touched when none is passed.
        let need = unsafe {
            libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
        };
        if need <= 0 {
            return false;
        }
        let want = (need as usize)
            .div_ceil(size_of::<ProcFdinfo>())
            .min(MAX_PID_FDS);
        if fds.capacity() < want {
            fds.reserve(want - fds.len());
        }
        let byte_cap = (fds.capacity() * size_of::<ProcFdinfo>()) as libc::c_int;
        // SAFETY: `fds` exposes `byte_cap` bytes of valid capacity.
        let n = unsafe {
            libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), byte_cap)
        };
        if n <= 0 {
            return false;
        }
        // SAFETY: the kernel wrote `n` bytes; clamp in case the table
        // grew between the probe and the fetch.
        unsafe { fds.set_len((n as usize / size_of::<ProcFdinfo>()).min(fds.capacity())) };
        true
    }

    /// `path` still bound by a live process anywhere on the system.
    pub fn socket_bound_at(path: &Path) -> Result<bool> {
        let ours = path_spellings(path);
        let mut pids = vec![0 as libc::pid_t; 4096];
        // SAFETY: `pids` is valid for writes of its byte capacity.
        let n = unsafe {
            libc::proc_listallpids(
                pids.as_mut_ptr().cast(),
                (pids.len() * size_of::<libc::pid_t>()) as libc::c_int,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error()).context("proc_listallpids");
        }
        if n as usize > pids.len() {
            // Rare — the pid count outgrew the buffer between calls;
            // size to what the kernel asked for and retry once.
            pids.resize(n as usize + 64, 0);
            let n = unsafe {
                libc::proc_listallpids(
                    pids.as_mut_ptr().cast(),
                    (pids.len() * size_of::<libc::pid_t>()) as libc::c_int,
                )
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error()).context("proc_listallpids");
            }
            pids.truncate((n as usize).min(pids.len()));
        } else {
            pids.truncate(n as usize);
        }
        let mut fds: Vec<ProcFdinfo> = Vec::with_capacity(64);
        let mut inspected = 0usize;
        for &pid in &pids {
            if !list_fds(pid, &mut fds) {
                continue;
            }
            inspected += 1;
            for fd in &fds {
                if fd.proc_fdtype != PROX_FDTYPE_SOCKET {
                    continue;
                }
                // SAFETY: POD struct, fully overwritten by the kernel.
                let mut info: SocketFdinfo = unsafe { std::mem::zeroed() };
                let n = unsafe {
                    libc::proc_pidfdinfo(
                        pid,
                        fd.proc_fd,
                        PROC_PIDFDSOCKETINFO,
                        (&mut info as *mut SocketFdinfo).cast(),
                        size_of::<SocketFdinfo>() as libc::c_int,
                    )
                };
                if n < size_of::<SocketFdinfo>() as libc::c_int {
                    continue;
                }
                if info.psi.soi_family != libc::AF_UNIX || info.psi.soi_kind != SOCKINFO_UN {
                    continue;
                }
                // SAFETY: `soi_kind == SOCKINFO_UN` — the kernel
                // populated the `un` union arm for a unix socket.
                let un = unsafe { &*info.psi.soi_proto.un };
                let bound = sun_path_bytes(unsafe { &un.unsi_addr.sun });
                let peer = sun_path_bytes(unsafe { &un.unsi_caddr.sun });
                if matches(&ours, bound) || matches(&ours, peer) {
                    return Ok(true);
                }
            }
        }
        if inspected == 0 {
            anyhow::bail!("could not inspect any process's fd table");
        }
        Ok(false)
    }
}
/// mandatory NUL terminator (104 on Apple targets, 108 on Linux).
#[cfg(unix)]
fn sun_path_capacity() -> usize {
    unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
        .sun_path
        .len()
        - 1
}

/// `from` → `to` as a C-string pair for the platform rename primitive.
#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn paths_as_cstrings(
    from: &std::path::Path,
    to: &std::path::Path,
) -> std::io::Result<(std::ffi::CString, std::ffi::CString)> {
    use std::os::unix::ffi::OsStrExt;
    let c = |p: &std::path::Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains an interior NUL byte",
            )
        })
    };
    Ok((c(from)?, c(to)?))
}

/// Move `from` onto `to` without replacing an existing entry — the
/// atomic no-replace publish the unix endpoint needs: between the
/// stale-socket check and this call a racing peer may have bound its
/// own live socket or dropped an unrelated file at the path, and a
/// plain `rename` would silently overwrite it (issue #974). Every arm
/// answers EEXIST on an occupied target; other errors propagate.
#[cfg(target_vendor = "apple")]
fn rename_no_replace(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    let (from, to) = paths_as_cstrings(from, to)?;
    // SAFETY: both are valid NUL-terminated path strings.
    let rc = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The Linux arm — `renameat2(RENAME_NOREPLACE)` (kernel ≥ 3.15).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_no_replace(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    let (from, to) = paths_as_cstrings(from, to)?;
    // SAFETY: syscall numbers and the flag are kernel ABI; the glibc
    // wrapper arrived too late to rely on its name being exported.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The fallback arm — no first-class atomic rename-no-replace exists,
/// so hardlink + drop the staging name gives the same publish: `link`
/// answers EEXIST on an occupied target and a socket file hardlinks
/// like any other filesystem object.
#[cfg(all(
    unix,
    not(target_vendor = "apple"),
    not(target_os = "linux"),
    not(target_os = "android")
))]
fn rename_no_replace(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    std::fs::hard_link(from, to)?;
    let _ = std::fs::remove_file(from);
    Ok(())
}

/// Bind the pid-unique staging sibling the configured path is published
/// from. The name is claimed by `bind` itself — never by unlinking what
/// may be someone else's file — and every cleanup of `tmp` after this
/// point removes only a name this call created (issue #974).
#[cfg(unix)]
async fn bind_unix_staging(
    resolved: &std::path::Path,
) -> Result<(tokio::net::UnixListener, std::path::PathBuf)> {
    static STAGING_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for _ in 0..8 {
        let tmp = resolved.with_extension(format!(
            "meow-tmp-{}-{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        // The staging sibling must fit sun_path too — a configured
        // path near the limit fails here by name, not as a bind
        // error on a name the config never wrote (issue #974).
        if tmp.as_os_str().len() > sun_path_capacity() {
            anyhow::bail!(
                "external-controller-unix: {} leaves no room for the staging name within the {}-byte unix socket path limit",
                resolved.display(),
                sun_path_capacity()
            );
        }
        match tokio::net::UnixListener::bind(&tmp) {
            Ok(listener) => return Ok((listener, tmp)),
            // A same-named file exists — most likely a crashed run's
            // litter under a reused PID. Take the next name; the file
            // is not this call's to remove.
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "external-controller-unix cannot bind {}",
                        resolved.display()
                    )
                });
            }
        }
    }
    anyhow::bail!(
        "external-controller-unix cannot claim a staging name alongside {}",
        resolved.display()
    )
}

/// Bind `external-controller-unix` — meow's deliberately safer handling
/// (issue #974): where upstream unlinks an existing path unconditionally,
/// meow refuses a non-socket path, refuses another user's socket, and
/// reclaims only a *verified stale* socket it owns (connect →
/// `ECONNREFUSED` means nothing listens). The bound socket is `0600` —
/// upstream's `0666` opens the controller to every local user; meow also
/// keeps Bearer auth on, deliberate divergences both.
#[cfg(unix)]
pub async fn bind_unix(path: &str) -> Result<(UnixEndpoint, UnixSocketGuard)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    let requested = std::path::Path::new(path);
    let resolved = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        meow_common::resolved_home_dir().join(requested)
    };
    // The path length is an entry invariant, checked by name before any
    // filesystem work: `sun_path` is 104/108 bytes, so an over-long
    // config fails here rather than inside bind.
    if resolved.as_os_str().len() > sun_path_capacity() {
        anyhow::bail!(
            "external-controller-unix: {} exceeds the {}-byte unix socket path limit",
            resolved.display(),
            sun_path_capacity()
        );
    }
    match std::fs::symlink_metadata(&resolved) {
        Ok(md) if md.file_type().is_socket() => {
            if md.uid() != unsafe { libc::geteuid() } {
                anyhow::bail!(
                    "external-controller-unix: {} is a socket owned by another user; \
                     refusing to replace it",
                    resolved.display()
                );
            }
            match probe_unix_socket(&resolved).await {
                UnixProbe::Live => anyhow::bail!(
                    "external-controller-unix: {} is already serving a live socket",
                    resolved.display()
                ),
                UnixProbe::Refused => {
                    tokio::time::sleep(STALE_REPROBE_DELAY).await;
                    match probe_unix_socket(&resolved).await {
                        UnixProbe::Refused => {
                            // A refusal does not prove death where a
                            // saturated accept queue refuses too —
                            // unlink only what the kernel says no
                            // process still binds (issue #974).
                            match unix_socket_still_bound(&resolved) {
                                Ok(false) => {
                                    warn!(
                                        "external-controller-unix: reclaiming stale socket {}",
                                        resolved.display()
                                    );
                                    reclaim_stale_socket(
                                        &resolved,
                                        (md.dev(), md.ino(), md.ctime(), md.ctime_nsec()),
                                    )?;
                                }
                                Ok(true) => anyhow::bail!(
                                    "external-controller-unix: {} is still bound by a live process",
                                    resolved.display()
                                ),
                                Err(e) => anyhow::bail!(
                                    "external-controller-unix: cannot prove {} is a dead socket: {e}",
                                    resolved.display()
                                ),
                            }
                        }
                        UnixProbe::Live => anyhow::bail!(
                            "external-controller-unix: {} is already serving a live socket",
                            resolved.display()
                        ),
                        UnixProbe::Uncertain(e) => anyhow::bail!(
                            "external-controller-unix: cannot probe existing socket {}: {e}",
                            resolved.display()
                        ),
                    }
                }
                UnixProbe::Uncertain(e) => anyhow::bail!(
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
    // A bound socket file is created `0666 & ~umask` and stays that way
    // until a post-bind chmod lands. Bind a pid-unique sibling instead
    // and rename it onto the configured path already owner-only — the
    // final path is never observable permissive, and no process-global
    // umask dance is needed. rename preserves the inode and the
    // listening fd (issue #974). Crash litter is single-owner by
    // construction (the PID names it), so a leftover is safe to drop.
    let (listener, tmp) = bind_unix_staging(&resolved).await?;
    // Owner-only — the controller is authenticated, but the socket file
    // never needs the world-read/write upstream grants it. A failed
    // chmod fails the endpoint: serving a permissive socket would defeat
    // the divergence this mode exists for (issue #974). Applied to the
    // sibling, so on failure only the temp name needs cleanup.
    if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| {
            format!(
                "external-controller-unix: cannot chmod {} to owner-only",
                tmp.display()
            )
        });
    }
    // Publish atomically without replacing: EEXIST means someone else
    // won the path between our check and now — keep their file and let
    // this endpoint be skipped.
    if let Err(e) = rename_no_replace(&tmp, &resolved) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| {
            format!(
                "external-controller-unix: cannot move {} into place",
                resolved.display()
            )
        });
    }
    // Record the bound socket's identity so the guard removes only the
    // file this process created.
    let ident = std::fs::metadata(&resolved)
        .map(|md| (md.dev(), md.ino()))
        .with_context(|| {
            format!(
                "external-controller-unix: cannot stat bound socket {}",
                resolved.display()
            )
        })?;
    Ok((
        UnixEndpoint { listener },
        UnixSocketGuard {
            path: Some(resolved),
            ident,
        },
    ))
}

// ── Windows named pipe (external-controller-pipe) ──────────────────

/// The restricted ACL every pipe instance carries (issue #974): a
/// protected DACL granting GENERIC_ALL to the object owner only —
/// upstream posture is a per-owner pipe, not a shared one. Built once
/// per endpoint; `CreateNamedPipeW` copies the descriptor into each
/// kernel object, so the owned buffer only needs to outlive each create
/// call.
#[cfg(windows)]
struct PipeSecurity {
    attrs: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    /// The `LocalAlloc`'d security descriptor `attrs` points at.
    sd: *mut std::ffi::c_void,
}

// SAFETY: `sd` is an immutable kernel-owned descriptor read only inside
// synchronous `CreateNamedPipeW` calls; no interior mutability crosses
// the send boundary.
#[cfg(windows)]
unsafe impl Send for PipeSecurity {}
#[cfg(windows)]
unsafe impl Sync for PipeSecurity {}

#[cfg(windows)]
impl PipeSecurity {
    /// SDDL `D:P(A;;GA;;;OW)` → `SECURITY_ATTRIBUTES` for
    /// `ServerOptions::create_with_security_attributes_raw`.
    fn new() -> std::io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        // "D:P(A;;GA;;;OW)" as UTF-16 + NUL.
        let sddl: Vec<u16> = "D:P(A;;GA;;;OW)".encode_utf16().chain([0]).collect();
        let mut sd = std::ptr::null_mut();
        // SAFETY: `sddl` is a valid NUL-terminated UTF-16 string; `sd`
        // receives a LocalAlloc'd descriptor on success.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            attrs: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            },
            sd,
        })
    }

    fn as_raw(&self) -> *mut std::ffi::c_void {
        &self.attrs as *const _ as *mut std::ffi::c_void
    }
}

#[cfg(windows)]
impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.sd.is_null() {
            // SAFETY: `sd` came from ConvertSDDL's LocalAlloc.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.sd) };
        }
    }
}

/// A bound `external-controller-pipe` listener. One `NamedPipeServer`
/// instance per connection: each `accept` waits on the pending instance's
/// client connect, then tries to pre-create the next one. Byte mode +
/// reject remote clients + the restricted ACL matches upstream's pipe
/// semantics; a failed next-instance create never costs the client that
/// already connected — the following `accept` retries it (issue #974).
#[cfg(windows)]
pub struct PipeEndpoint {
    name: String,
    pending: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
    security: PipeSecurity,
}

#[cfg(windows)]
impl PipeEndpoint {
    fn new_instance(&self) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        // SAFETY: `security` outlives the synchronous create call; the
        // descriptor is copied into the new pipe object.
        unsafe {
            tokio::net::windows::named_pipe::ServerOptions::new()
                .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(&self.name, self.security.as_raw())
        }
    }
}

#[cfg(windows)]
impl axum::serve::Listener for PipeEndpoint {
    type Io = tokio::net::windows::named_pipe::NamedPipeServer;
    type Addr = String;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if self.pending.is_none() {
                match self.new_instance() {
                    Ok(next) => self.pending = Some(next),
                    Err(e) => {
                        warn!("external-controller-pipe: cannot create instance: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
            let pending = self.pending.as_mut().expect("pending set above");
            match pending.connect().await {
                Ok(()) => {
                    let connected = match self.new_instance() {
                        Ok(next) => self.pending.replace(next),
                        Err(e) => {
                            // Serve the client anyway — the next accept
                            // recreates the pending slot.
                            warn!("external-controller-pipe: cannot create next instance: {e}");
                            self.pending.take()
                        }
                    };
                    return (connected.expect("pending connected"), self.name.clone());
                }
                Err(e) => {
                    warn!("external-controller-pipe connect error: {e}");
                    self.pending = None;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.name.clone())
    }
}

/// Bind `external-controller-pipe`. `first_pipe_instance` claims the name
/// so a squatting pipe cannot already exist; the same owner-only ACL is
/// installed on the first and every subsequent instance via
/// `create_with_security_attributes_raw` (issue #974).
#[cfg(windows)]
pub fn bind_pipe(name: &str) -> Result<PipeEndpoint> {
    let security =
        PipeSecurity::new().context("external-controller-pipe cannot build security descriptor")?;
    let pending = unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, security.as_raw())
    }
    .with_context(|| format!("external-controller-pipe cannot create '{name}'"))?;
    Ok(PipeEndpoint {
        name: name.to_owned(),
        pending: Some(pending),
        security,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::reclaim_stale_socket;
    use std::os::unix::fs::MetadataExt;

    fn sock_ident(path: &std::path::Path) -> (u64, u64, i64, i64) {
        let md = std::fs::symlink_metadata(path).unwrap();
        (md.dev(), md.ino(), md.ctime(), md.ctime_nsec())
    }

    #[test]
    fn reclaim_removes_the_probed_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let ident = sock_ident(&path);
        reclaim_stale_socket(&path, ident).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn reclaim_refuses_a_swapped_socket() {
        // A loser of the probe→unlink race must not delete the winner's
        // live socket: the identity recorded at probe time no longer
        // names the file (issue #974).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let ident = sock_ident(&path);
        std::fs::remove_file(&path).unwrap();
        let _live = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(reclaim_stale_socket(&path, ident).is_err());
        assert!(path.exists());
        // A non-socket replacement is refused the same way.
        let regular = dir.path().join("regular");
        std::fs::write(&regular, b"x").unwrap();
        assert!(reclaim_stale_socket(&regular, ident).is_err());
        assert!(regular.exists());
    }
}
