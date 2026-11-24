//! AnyTLS server inbound listener (`listeners: - type: anytls`),
//! mihomo/Clash Meta compatible.
//!
//! Pipeline per accepted connection: TCP keepalive → BoringSSL TLS
//! accept (or the explicitly opted-in plaintext mode) → AnyTLS auth
//! preface (`SHA256(password)` + padding) against the multi-user table →
//! v1/v2 session. Every SYN'd logical stream carries a SOCKS-serialized
//! destination: ordinary destinations route through
//! [`route_inbound_tcp`] like every other inbound; exactly
//! `sp.v2.udp-over-tcp.arpa:0` opens a UoT v2 association whose packets
//! route through the tunnel's UDP machinery (`pre_handle_metadata` →
//! `resolve_udp_dst` → `dial_udp`) — never a direct dial.
//!
//! The rustls-based `meow_anytls::server` fixture is deliberately NOT
//! used: production TLS is BoringSSL and routing goes through the
//! tunnel, not `TcpProxyHandler`.

use anytls_rs::padding::PaddingFactory;
use anytls_rs::session::{Session, StreamIo};
use anytls_rs::uot;
use anytls_rs::util::{authenticate_user, AnyTlsError, UserMap};
use meow_common::{ConnType, Metadata, Network, TcpKeepaliveConfig};
use meow_tunnel::{route_inbound_tcp, Tunnel};
use smol_str::SmolStr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::DEFAULT_HANDSHAKE_TIMEOUT;

/// Default cap on in-flight inbound connections per listener when the
/// listener config doesn't set `max-connections` (mirrors
/// `mixed::DEFAULT_MAX_CONNECTIONS`, kept as a separate constant like
/// the other listeners' copies). `0` explicitly disables the cap.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Bound on the whole per-connection preamble — TLS handshake plus the
/// AnyTLS auth preface. mihomo leaves an unauthenticated connection
/// open-ended; meow bounds it like every other listener handshake so a
/// silent peer cannot hold a concurrency slot.
const AUTH_PREFACE_TIMEOUT: Duration = DEFAULT_HANDSHAKE_TIMEOUT;

/// Listener-facing `type: anytls` spec — the config crate validates
/// users/certificate pairing/security modes and hands plain values here
/// (mirroring `WgListenerSpec`'s relationship to `WgListenerConfig`).
/// `certificate`/`private_key` stay AS WRITTEN (PEM literal or path);
/// resolution happens in [`AnytlsListener::prepare`].
pub struct AnytlsListenerSpec {
    /// `(username, SHA256(password))` pairs in declaration order. An
    /// empty table is the upstream reject-all state — the listener
    /// still serves and every auth fails.
    pub users: Vec<(String, [u8; 32])>,
    /// `certificate` — inline PEM or filesystem path.
    pub certificate: Option<String>,
    /// `private-key` — same dual form.
    pub private_key: Option<String>,
    /// Explicit plaintext opt-in (`allow-insecure: true`).
    pub allow_insecure: bool,
    /// `padding-scheme` raw bytes — already validated by the shared
    /// `meow_common::anytls_padding` contract; re-validated here because
    /// `PaddingFactory::new` runs the same check.
    pub padding_scheme: Option<String>,
}

/// One logical stream's destination — the SOCKS-parsed target before it
/// becomes `Metadata`.
enum StreamTarget {
    /// Ordinary TCP destination → `route_inbound_tcp`.
    Tcp,
    /// The UoT v2 marker `sp.v2.udp-over-tcp.arpa:0` → [`uot`] handling.
    Uot,
    /// A reserved UoT form that must not route (legacy domain, or the v2
    /// domain on a non-zero port) → drop the stream.
    Reject,
}

pub struct AnytlsListener {
    tunnel: Tunnel,
    name: String,
    /// `None` only in the `allow-insecure` plaintext mode — the
    /// connection pipeline picks TLS-or-raw on this.
    acceptor: Option<Arc<boring::ssl::SslAcceptor>>,
    /// `SHA256(password)` → username (upstream `userMap` semantics).
    users: Arc<UserMap>,
    padding: Arc<PaddingFactory>,
    /// The concurrent-inbound cap shared across EVERY address this
    /// listener entry serves — `max_connections` bounds the entry, not
    /// each `run_on` invocation (one semaphore per socket would
    /// multiply the real cap by address count).
    conn_slots: Option<Arc<Semaphore>>,
    /// The configured cap behind `conn_slots` — the semaphore only
    /// knows REMAINING permits, so saturation diagnostics must read
    /// this, not the semaphore (N07).
    conn_max: usize,
    /// Keepalive posture applied to every accepted socket (see
    /// [`crate::keepalive`]); `enabled: false` writes no sockopts.
    tcp_keepalive: TcpKeepaliveConfig,
    /// `listeners[].proxy`/`rule` — the named-listener route override
    /// stamped onto every flow's `Metadata` (TCP and UoT).
    route_override: Option<meow_common::InboundRouteOverride>,
}

impl AnytlsListener {
    /// Build the listener's non-TLS state. TLS material resolves in
    /// [`Self::prepare`] so a missing/invalid PEM surfaces eagerly at
    /// spawn — never inside a detached accept task.
    pub fn new(
        tunnel: Tunnel,
        name: String,
        spec: AnytlsListenerSpec,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let users: UserMap = spec
            .users
            .into_iter()
            .map(|(name, digest)| (digest, name))
            .collect();
        // `padding-scheme: ""` is the absent form — mihomo treats an
        // explicit empty string as "no scheme", i.e. the default
        // factory. Non-empty values keep their bytes VERBATIM (the
        // padding-md5 is computed over them).
        let padding = match spec.padding_scheme.as_deref() {
            Some(scheme) if !scheme.is_empty() => {
                Arc::new(PaddingFactory::new(scheme.as_bytes()).map_err(|e| {
                    meow_common::MeowError::Config(format!("anytls listener: padding-scheme: {e}"))
                })?)
            }
            _ => PaddingFactory::default(),
        };
        let acceptor = match (&spec.certificate, &spec.private_key) {
            (Some(cert), Some(key)) => {
                let (cert_pem, key_pem) = load_identity_pair(cert, key)
                    .map_err(|e| meow_common::MeowError::Config(e.to_string()))?;
                Some(Arc::new(build_tls_acceptor(&cert_pem, &key_pem).map_err(
                    |e| meow_common::MeowError::Config(e.to_string()),
                )?))
            }
            (None, None) if spec.allow_insecure => None,
            _ => {
                return Err(Box::new(meow_common::MeowError::Config(
                    "anytls listener: certificate + private-key must be provided together, \
                     or allow-insecure: true set"
                        .into(),
                )));
            }
        };
        Ok(Self {
            tunnel,
            name,
            acceptor,
            users: Arc::new(users),
            padding,
            conn_slots: (DEFAULT_MAX_CONNECTIONS > 0)
                .then(|| Arc::new(Semaphore::new(DEFAULT_MAX_CONNECTIONS))),
            conn_max: DEFAULT_MAX_CONNECTIONS,
            tcp_keepalive: TcpKeepaliveConfig::default(),
            route_override: None,
        })
    }

    /// No-op placeholder for parity with other listeners' prepare/step
    /// split — `new` already resolves TLS eagerly, so there is nothing
    /// deferred. Kept so the spawn arm reads like its neighbours.
    pub fn prepare(self) -> Self {
        self
    }

    /// Override the concurrent-inbound cap (default
    /// [`DEFAULT_MAX_CONNECTIONS`]). `0` disables the cap.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.conn_slots = (max > 0).then(|| Arc::new(Semaphore::new(max)));
        self.conn_max = max;
        self
    }

    /// Override the TCP keepalive posture applied to every accepted
    /// socket (default [`TcpKeepaliveConfig::default`]).
    pub fn with_tcp_keepalive(mut self, cfg: TcpKeepaliveConfig) -> Self {
        self.tcp_keepalive = cfg;
        self
    }

    /// Install the named listener's `proxy:`/`rule:` route override —
    /// stamped onto every flow's `Metadata` before routing.
    pub fn with_route_override(mut self, ov: Option<meow_common::InboundRouteOverride>) -> Self {
        self.route_override = ov;
        self
    }

    /// Serve on an already-bound socket. The accept loop runs for the
    /// process lifetime; multi-address listeners spawn one `run_on` per
    /// bound socket on a shared `Arc`.
    pub async fn run_on(
        self: &Arc<Self>,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bound = listener.local_addr()?;
        let in_port = bound.port();
        let max_connections = self.conn_max;
        info!(
            "AnyTLS listener '{}' on {} (tls={}, users={})",
            self.name,
            bound,
            self.acceptor.is_some(),
            self.users.len(),
        );

        let mut warned_saturated = false;
        let mut accept_backoff = meow_common::ErrorBackoff::new();
        loop {
            // Acquire AFTER accept(): the cap must bound connections the
            // kernel actually delivered — pre-accept permits park the
            // loop while no peer has even connected.
            let (stream, peer) = match listener.accept().await {
                Ok(v) => {
                    accept_backoff.succeeded();
                    v
                }
                Err(e) => {
                    if accept_backoff.failed(&e).await {
                        error!("anytls listener '{}' accept error: {}", self.name, e);
                    } else {
                        debug!("anytls listener '{}' accept error: {}", self.name, e);
                    }
                    continue;
                }
            };
            let permit = if let Some(sem) = &self.conn_slots {
                let sem = Arc::clone(sem);
                if sem.available_permits() == 0 && !warned_saturated {
                    warn!(
                        "anytls listener '{}' saturated at {} concurrent connections; new clients will queue",
                        self.name, max_connections
                    );
                    warned_saturated = true;
                }
                match sem.acquire_owned().await {
                    Ok(p) => {
                        if warned_saturated {
                            debug!("anytls listener '{}' has free capacity again", self.name);
                            warned_saturated = false;
                        }
                        Some(p)
                    }
                    Err(_) => return Ok(()),
                }
            } else {
                None
            };

            crate::keepalive::apply(&stream, self.tcp_keepalive, &self.name);

            let listener = Arc::clone(self);
            tokio::spawn(async move {
                listener.handle_conn(stream, peer, in_port).await;
                drop(permit);
            });
        }
    }

    /// Per-connection pipeline: TLS/plaintext → auth preface → session.
    async fn handle_conn(&self, stream: tokio::net::TcpStream, peer: SocketAddr, in_port: u16) {
        // ONE absolute deadline for TLS accept + auth preface combined:
        // two independent per-phase timeouts would double the window a
        // parked peer can hold a concurrency slot.
        let deadline = tokio::time::Instant::now() + AUTH_PREFACE_TIMEOUT;
        let io: Box<dyn InboundIo> = match &self.acceptor {
            Some(acceptor) => {
                let acceptor = Arc::clone(acceptor);
                let tls = match tokio::time::timeout_at(
                    deadline,
                    tokio_boring::accept(&acceptor, stream),
                )
                .await
                {
                    Ok(Ok(tls)) => tls,
                    Ok(Err(e)) => {
                        debug!(
                            "anytls listener '{}' TLS accept from {peer}: {e}",
                            self.name
                        );
                        return;
                    }
                    Err(_) => {
                        debug!(
                            "anytls listener '{}' TLS accept from {peer} timed out",
                            self.name
                        );
                        return;
                    }
                };
                Box::new(tls)
            }
            None => Box::new(stream),
        };

        // `authenticate_user` reads the exact prefix the client writes —
        // SHA256(password) + u16be padding length + padding — in
        // bounded chunks.
        let mut io = io;
        let user = match tokio::time::timeout_at(deadline, authenticate_user(&mut io, &self.users))
            .await
        {
            Ok(Ok(user)) => user,
            Ok(Err(AnyTlsError::AuthenticationFailed)) => {
                // Wrong password — close silently (no response bytes),
                // the upstream behaviour.
                debug!(
                    "anytls listener '{}' auth from {peer}: unknown credential",
                    self.name
                );
                return;
            }
            Ok(Err(e)) => {
                debug!("anytls listener '{}' auth from {peer}: {e}", self.name);
                return;
            }
            Err(_) => {
                debug!(
                    "anytls listener '{}' auth from {peer}: preface timed out",
                    self.name
                );
                return;
            }
        };

        let (session, mut stream_rx) = Session::new_inbound(io, Arc::clone(&self.padding));
        let runner = {
            let session = Arc::clone(&session);
            tokio::spawn(async move { session.run_server().await })
        };
        let inner = Arc::clone(self.tunnel.inner());
        let in_name = self.name.clone();
        let route_override = self.route_override.clone();
        let user: SmolStr = user.into();
        let session_end = Arc::clone(&session);
        let dispatch = tokio::spawn(async move {
            // Every per-stream task the session spawns lives in ONE
            // supervision set: when the session dies, `JoinSet::abort_all`
            // retires the handlers (they drop their `Arc<Stream>` and
            // unblock) instead of leaking dials past connection teardown.
            let mut children = tokio::task::JoinSet::new();
            loop {
                while children.try_join_next().is_some() {}
                tokio::select! {
                    biased;
                    // Reap ahead of admission and cap live JoinSet tasks at
                    // `STREAM_ACCEPT_QUEUE` so rapid SYN/FIN churn cannot
                    // outrun reaping and grow `children` past the 128 cap (N02).
                    _ = children.join_next(), if !children.is_empty() => {}
                    stream = stream_rx.recv(), if children.len() < Session::STREAM_ACCEPT_QUEUE => match stream {
                        Some(stream) => {
                            let session = Arc::clone(&session);
                            let inner = Arc::clone(&inner);
                            let ctx = FlowCtx {
                                peer,
                                in_name: in_name.clone(),
                                in_port,
                                user: user.clone(),
                                route_override: route_override.clone(),
                            };
                            children.spawn(async move {
                                handle_stream(stream, session, inner, ctx).await;
                            });
                        }
                        None => break,
                    },
                }
            }
            // Admission closed (session teardown dropped its sender):
            // cancel every in-flight handler and WAIT for the cleanup —
            // dropping a JoinSet only *requests* cancellation.
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        // Await the session's death; `run_server`'s teardown drops the
        // accept sender, ending the dispatch loop above — so JOIN it
        // rather than abort: its exit is what retires the children.
        let _ = runner.await;
        let _ = session_end.close().await;
        let _ = dispatch.await;
    }
}

/// Per-connection context every accepted stream inherits — the peer,
/// the listener identity it arrived on and the authenticated user.
/// Grouped so the dispatch chain isn't a positional-argument list.
pub(crate) struct FlowCtx {
    pub peer: SocketAddr,
    pub in_name: String,
    pub in_port: u16,
    pub user: SmolStr,
    pub route_override: Option<meow_common::InboundRouteOverride>,
}

/// The stream's single close owner (F04): scope exit — normal return,
/// the death arm winning, or an outer abort dropping this future — runs
/// `Stream::close` exactly once via the guard; it never depends on
/// reaching a trailing statement (F04).
struct StreamOwner(Arc<anytls_rs::session::Stream>);

impl Drop for StreamOwner {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Per-stream dispatch umbrella: race the stream's work against its
/// death (peer FIN, admission eviction, session teardown), then close
/// through ONE owner. `Stream::close` is dieOnce-guarded and the
/// FIN it queues carries this instance's owner token, so a retired
/// generation can neither wire a stale FIN nor evict a recycled SID
/// (F04/F05).
async fn handle_stream(
    stream: Arc<anytls_rs::session::Stream>,
    session: Arc<Session>,
    inner: Arc<meow_tunnel::TunnelInner>,
    ctx: FlowCtx,
) {
    let _owner = StreamOwner(Arc::clone(&stream));
    let stream_id = stream.id();
    // Subscribe BEFORE checking `is_closed` — `notify_waiters` retains
    // no state, so a notify landing between a bare check and a fresh
    // waiter would strand this handler forever (F04).
    let died = stream.close_waiter();
    tokio::pin!(died);
    let _ = died.as_mut().enable();
    // A stream the session already retired (FIN raced ahead of dispatch)
    // needs no work arm at all — the guard still issues its close.
    if !stream.is_closed() {
        tokio::select! {
            // `biased`: when death and work are BOTH ready, death wins —
            // dispatch admission must not outrank retirement (F05).
            biased;
            _ = &mut died => {
                if session.is_closed() {
                    debug!("anytls stream {stream_id}: session teardown");
                } else {
                    debug!("anytls stream {stream_id}: died mid-dispatch");
                }
            }
            _ = handle_stream_inner(Arc::clone(&stream), Arc::clone(&session), inner, ctx) => {}
        }
    }
}

/// The stream's work proper — parse destination, ACK, route. NEVER
/// closes the stream itself; the umbrella owns that so a mid-flight
/// cancellation cannot skip or double the FIN.
async fn handle_stream_inner(
    stream: Arc<anytls_rs::session::Stream>,
    session: Arc<Session>,
    inner: Arc<meow_tunnel::TunnelInner>,
    ctx: FlowCtx,
) {
    let FlowCtx {
        peer,
        in_name,
        in_port,
        user,
        route_override,
    } = &ctx;
    let stream_id = stream.id();
    let mut io = StreamIo(Arc::clone(&stream));
    let dest = match tokio::time::timeout(DEFAULT_HANDSHAKE_TIMEOUT, uot::read_socks_addr(&mut io))
        .await
    {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            if !uot::is_eof(&e) {
                debug!("anytls stream {stream_id}: bad destination: {e}");
            }
            return;
        }
        Err(_) => {
            debug!("anytls stream {stream_id}: destination read timed out");
            return;
        }
    };

    let kind = if dest.is_uot_rejected() {
        StreamTarget::Reject
    } else if dest.is_uot_v2() {
        StreamTarget::Uot
    } else {
        // Domain destinations must be real hostnames before they route;
        // upstream rejects malformed targets at the same point.
        if let uot::UotAddr::Domain(host, _) = &dest {
            if !meow_common::is_valid_host(host) {
                debug!("anytls stream {stream_id}: target {host:?} is not a hostname");
                return;
            }
        }
        StreamTarget::Tcp
    };

    if matches!(kind, StreamTarget::Reject) {
        debug!("anytls stream {stream_id}: reserved UoT destination {dest} refused");
        return;
    }

    // SynAck ordering (spec §4): exactly one empty SynAck to a v2+ peer,
    // queued after destination validation and BEFORE any rule lookup or
    // dial — a blocked route must never reorder it behind stream data.
    // `handshake_success` checks the stream instance is still live so a
    // recycled SID can't be ACK'd under a stale handler, and awaits the
    // queue admission so the invariant is deterministic. No frame to v1.
    if let Err(e) = session.handshake_success(&stream).await {
        debug!("anytls stream {stream_id}: synack: {e}");
        return;
    }

    match kind {
        StreamTarget::Tcp => {
            let metadata = build_tcp_metadata(
                &dest,
                *peer,
                in_name,
                *in_port,
                user,
                route_override.as_ref(),
            );
            debug!(
                "anytls stream {stream_id}: {peer} -> {}",
                metadata.remote_address()
            );
            // `Box<dyn ProxyConn>`: the tunnel's downcast finds the
            // stream's `WriteBytes` path, so relay bulk moves into a
            // frame slot without a per-frame copy (F14).
            let mut conn: Box<dyn meow_common::ProxyConn> = Box::new(io);
            route_inbound_tcp(&inner, &mut conn, metadata, &[]).await;
        }
        StreamTarget::Uot => {
            crate::anytls_uot::run_uot_stream(io, inner, &ctx).await;
        }
        StreamTarget::Reject => unreachable!("rejected destinations returned above"),
    }
}

/// Map a parsed SOCKS destination + connection context into `Metadata`
/// for the tunnel (same shape as the shadowsocks builder, `conn_type`
/// `Anytls` and the authenticated `in_user` stamped).
fn build_tcp_metadata(
    dest: &uot::UotAddr,
    peer: SocketAddr,
    in_name: &str,
    in_port: u16,
    user: &SmolStr,
    route_override: Option<&meow_common::InboundRouteOverride>,
) -> Metadata {
    let (host, dst_ip, dst_port) = match dest {
        uot::UotAddr::Ip(sa) => (SmolStr::default(), Some(sa.ip()), sa.port()),
        uot::UotAddr::Domain(d, port) => (Metadata::lower_host(d), None, *port),
    };
    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Anytls,
        src_ip: Some(peer.ip()),
        src_port: peer.port(),
        dst_ip,
        dst_port,
        host,
        in_name: in_name.into(),
        in_port,
        in_user: Some(user.clone()),
        ..Default::default()
    };
    if let Some(ov) = route_override {
        ov.apply(&mut metadata);
    }
    metadata
}

/// The conn half a `type: anytls` preamble authenticates — BoringSSL's
/// `SslStream<TcpStream>` in TLS mode, the bare `TcpStream` in the
/// plaintext opt-in. `Session::new_inbound` consumes it directly.
pub(crate) trait InboundIo:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static> InboundIo
    for T
{
}

/// `certificate`/`private-key` → PEM bytes: both `-----BEGIN` strings
/// are inline material; anything else is a pair of file paths resolved
/// through the shared home-contained resolver — the same contract
/// `external-controller-tls` keeps (`load_identity_pair` in meow-api),
/// duplicated here so the listener crate does not depend on the API.
fn load_identity_pair(cert: &str, key: &str) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert_inline = cert.contains("-----BEGIN");
    let key_inline = key.contains("-----BEGIN");
    if cert_inline != key_inline {
        anyhow::bail!(
            "anytls certificate and private-key must be both inline PEM or both file paths"
        );
    }
    if cert_inline {
        return Ok((cert.as_bytes().to_vec(), key.as_bytes().to_vec()));
    }
    let cert_path = std::path::Path::new(cert);
    let key_path = std::path::Path::new(key);
    let cert_resolved = meow_config::resolve_home_contained(cert_path)
        .map_err(|e| anyhow::anyhow!("anytls certificate: {e}"))?;
    let key_resolved = meow_config::resolve_home_contained(key_path)
        .map_err(|e| anyhow::anyhow!("anytls private-key: {e}"))?;
    Ok((
        read_pem_file(&cert_resolved, "anytls certificate")?,
        read_pem_file(&key_resolved, "anytls private-key")?,
    ))
}

/// PEM files are capped like the API endpoint's (`MAX_PEM_FILE_BYTES`
/// there): a certificate chain is tens of KiB, never megabytes.
const MAX_PEM_FILE_BYTES: u64 = 1 << 20;

/// Bounded regular-file PEM read — regular files only, `O_NONBLOCK`
/// against FIFOs, hard byte cap (same discipline as meow-api's
/// `read_pem_file`).
fn read_pem_file(path: &std::path::Path, what: &str) -> Result<Vec<u8>, anyhow::Error> {
    use std::io::Read;
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("{what}: cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!("{what}: {} is not a regular file", path.display());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NONBLOCK);
    let file = opts
        .open(path)
        .map_err(|e| anyhow::anyhow!("{what}: cannot open {}: {e}", path.display()))?;
    let mut buf = Vec::new();
    file.take(MAX_PEM_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("{what}: cannot read {}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_PEM_FILE_BYTES {
        anyhow::bail!(
            "{what}: {} exceeds {} bytes",
            path.display(),
            MAX_PEM_FILE_BYTES
        );
    }
    Ok(buf)
}

/// BoringSSL acceptor for the AnyTLS inbound: `mozilla_intermediate_v5`
/// (TLS 1.2+), certificate chain + key from PEM — and deliberately NO
/// ALPN. AnyTLS carries no ALPN contract (upstream sets none on the
/// inbound); the API endpoint's h2/http1.1 callback is HTTP-specific
/// and does not belong here.
fn build_tls_acceptor(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<boring::ssl::SslAcceptor, anyhow::Error> {
    let certs = boring::x509::X509::stack_from_pem(cert_pem)
        .map_err(|e| anyhow::anyhow!("anytls certificate: not a valid PEM certificate: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("anytls certificate: PEM carries no certificate");
    }
    let key = boring::pkey::PKey::private_key_from_pem(key_pem)
        .map_err(|e| anyhow::anyhow!("anytls private-key: not a valid PEM private key: {e}"))?;
    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
            .map_err(|e| anyhow::anyhow!("anytls tls: {e}"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("anytls certificate: no certificate"))?;
    builder
        .set_certificate(leaf)
        .map_err(|e| anyhow::anyhow!("anytls certificate: {e}"))?;
    for extra in &certs[1..] {
        builder
            .add_extra_chain_cert(extra.clone())
            .map_err(|e| anyhow::anyhow!("anytls certificate chain: {e}"))?;
    }
    builder
        .set_private_key(&key)
        .map_err(|e| anyhow::anyhow!("anytls private-key: {e}"))?;
    builder.check_private_key().map_err(|e| {
        anyhow::anyhow!("anytls certificate and private-key do not form a pair: {e}")
    })?;
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    //! Production-entry coverage (F21): a REAL `run_on` accept loop —
    //! TCP socket → `allow-insecure` plaintext → auth preface → session
    //! frames → JoinSet dispatch → `route_inbound_tcp` onto a recording
    //! proxy. The wire peer is a raw `TcpStream` speaking frames.
    use super::*;
    use anytls_rs::hash_password;
    use anytls_rs::padding::{PaddingFactory, DEFAULT_PADDING_SCHEME};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    /// Recording TCP proxy: every `dial_tcp` notes the metadata and
    /// answers with an echo conn — bytes the stream writes come back.
    struct EchoTcpProxy {
        dials: AtomicUsize,
        seen: StdMutex<Vec<(String, Option<String>)>>,
        health: meow_common::ProxyHealth,
    }

    struct EchoConn(tokio::io::DuplexStream);
    impl meow_common::ProxyConn for EchoConn {}
    impl AsyncRead for EchoConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for EchoConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for EchoTcpProxy {
        fn name(&self) -> &str {
            "echo-tcp"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push((
                metadata.remote_address().to_string(),
                metadata.in_user.as_deref().map(str::to_string),
            ));
            let (io, mut peer) = tokio::io::duplex(1 << 16);
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match peer.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if peer.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            Ok(Box::new(EchoConn(io)))
        }
        async fn dial_udp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            Err(meow_common::MeowError::NotSupported("no udp".into()))
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for EchoTcpProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            Vec::new()
        }
    }

    fn echo_tunnel(proxy: &Arc<EchoTcpProxy>) -> Tunnel {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        let mut proxies = res.proxies;
        proxies.insert(
            "echo-tcp".into(),
            Arc::clone(proxy) as Arc<dyn meow_common::Proxy>,
        );
        tunnel.update_proxies(proxies, res.dialer_registry);
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "echo-tcp",
        ))]);
        tunnel
    }

    fn digest(password: &str) -> [u8; 32] {
        hash_password(password)
    }

    async fn write_frame(peer: &mut tokio::net::TcpStream, cmd: u8, sid: u32, data: &[u8]) {
        peer.write_u8(cmd).await.unwrap();
        peer.write_u32(sid).await.unwrap();
        peer.write_u16(data.len() as u16).await.unwrap();
        peer.write_all(data).await.unwrap();
    }

    async fn read_frame(peer: &mut tokio::net::TcpStream) -> (u8, u32, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut header = [0u8; 7];
            peer.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes([header[5], header[6]]) as usize;
            let mut data = vec![0u8; len];
            peer.read_exact(&mut data).await.unwrap();
            (
                header[0],
                u32::from_be_bytes(header[1..5].try_into().unwrap()),
                data,
            )
        })
        .await
        .expect("frame read stalled")
    }

    fn socks_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut v = vec![0x01];
        v.extend_from_slice(&ip);
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    fn socks_domain(host: &str, port: u16) -> Vec<u8> {
        let mut v = vec![0x03, host.len() as u8];
        v.extend_from_slice(host.as_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    /// F21: auth → settings → healthy stream (SynAck + echo data) →
    /// refused stream (bare FIN, no ACK, no dial) → peer FIN echo.
    #[tokio::test]
    async fn production_entry_auth_stream_ack_fin_and_refusal() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();
        tokio::time::timeout(Duration::from_secs(15), async {
            let proxy = Arc::new(EchoTcpProxy {
                dials: AtomicUsize::new(0),
                seen: StdMutex::new(Vec::new()),
                health: meow_common::ProxyHealth::new(),
            });
            let tunnel = echo_tunnel(&proxy);
            let listener = AnytlsListener::new(
                tunnel,
                "in-a".into(),
                AnytlsListenerSpec {
                    users: vec![("alice".into(), digest("pw"))],
                    certificate: None,
                    private_key: None,
                    allow_insecure: true,
                    padding_scheme: None,
                },
            )
            .unwrap();
            let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = bound.local_addr().unwrap().port();
            let server = tokio::spawn(async move { Arc::new(listener).run_on(bound).await });

            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            // Auth preface: SHA256(password) + u16be padLen + padding.
            client.write_all(&digest("pw")).await.unwrap();
            client.write_u16(0).await.unwrap();
            // v2 settings echoing the default scheme's md5 — no
            // UpdatePaddingScheme, first server frame is ServerSettings.
            let md5 = PaddingFactory::new(DEFAULT_PADDING_SCHEME.as_bytes())
                .unwrap()
                .md5()
                .to_string();
            write_frame(
                &mut client,
                4, // Settings
                0,
                format!("v=2\npadding-md5={md5}").as_bytes(),
            )
            .await;
            let (cmd, _sid, data) = read_frame(&mut client).await;
            assert_eq!(cmd, 10, "expected ServerSettings, got cmd {cmd}");
            assert!(data.windows(3).any(|w| w == b"v=2"));

            // Healthy stream: SYN → destination PSH → data PSH.
            write_frame(&mut client, 1, 7, &[]).await; // SYN
            write_frame(&mut client, 2, 7, &socks_ipv4([1, 2, 3, 4], 80)).await;
            write_frame(&mut client, 2, 7, b"ping").await;
            let (cmd, sid, _) = read_frame(&mut client).await;
            assert_eq!((cmd, sid), (7, 7), "expected SynAck sid=7");
            let (cmd, sid, data) = read_frame(&mut client).await;
            assert_eq!((cmd, sid), (2, 7), "expected PSH echo sid=7");
            assert_eq!(data, b"ping");
            // The echo proves route → dial → relay ran through the real
            // tunnel path — and stamped the authenticated user.
            assert_eq!(proxy.dials.load(Ordering::SeqCst), 1);
            {
                let seen = proxy.seen.lock().unwrap();
                assert_eq!(seen[0].0, "1.2.3.4:80");
                assert_eq!(seen[0].1.as_deref(), Some("alice"));
            }

            // Refused stream: legacy UoT marker → bare FIN, never ACKed,
            // never dialed.
            write_frame(&mut client, 1, 8, &[]).await;
            write_frame(
                &mut client,
                2,
                8,
                &socks_domain(anytls_rs::uot::UOT_LEGACY_DOMAIN, 0),
            )
            .await;
            let (cmd, sid, _) = read_frame(&mut client).await;
            assert_eq!(
                (cmd, sid),
                (3, 8),
                "reserved destination must retire with a bare FIN"
            );
            assert_eq!(proxy.dials.load(Ordering::SeqCst), 1);

            // Peer FIN on the healthy stream: upstream retires it with
            // `closeLocally` — NO echo. Reopening the SAME SID 7 (NEW-03)
            // must still ACK + relay, and the retired gen-1 handler's
            // teardown must not emit a late FIN/SynAck that kills gen-2.
            write_frame(&mut client, 3, 7, &[]).await;
            write_frame(&mut client, 1, 7, &[]).await;
            write_frame(&mut client, 2, 7, &socks_ipv4([5, 6, 7, 8], 443)).await;
            write_frame(&mut client, 2, 7, b"ping2").await;
            let (cmd, sid, _) = read_frame(&mut client).await;
            assert_eq!((cmd, sid), (7, 7), "recycled SID 7 must still ACK");
            let (cmd, sid, data) = read_frame(&mut client).await;
            assert_eq!((cmd, sid), (2, 7));
            assert_eq!(data, b"ping2");
            assert_eq!(proxy.dials.load(Ordering::SeqCst), 2);
            // Send another PSH on the recycled SID 7 after a settle window
            // to prove no late gen-1 FIN evicted or closed gen-2.
            assert!(
                tokio::time::timeout(Duration::from_millis(150), client.read(&mut [0u8; 8]))
                    .await
                    .is_err(),
                "retired gen-1 of SID 7 emitted a late frame"
            );
            write_frame(&mut client, 2, 7, b"ping3").await;
            let (cmd, sid, data) = read_frame(&mut client).await;
            assert_eq!((cmd, sid), (2, 7));
            assert_eq!(data, b"ping3");

            client.shutdown().await.unwrap();
            drop(client);
            server.abort();
            let _ = server.await;
        })
        .await
        .expect("production entry test timed out");
    }

    /// F21 auth edge: a wrong digest gets NO response bytes — the
    /// connection just closes (upstream behavior), and the listener
    /// keeps accepting afterwards.
    #[tokio::test]
    async fn production_entry_bad_auth_closes_silently() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let proxy = Arc::new(EchoTcpProxy {
                dials: AtomicUsize::new(0),
                seen: StdMutex::new(Vec::new()),
                health: meow_common::ProxyHealth::new(),
            });
            let tunnel = echo_tunnel(&proxy);
            let listener = AnytlsListener::new(
                tunnel,
                "in-a".into(),
                AnytlsListenerSpec {
                    users: vec![("alice".into(), digest("pw"))],
                    certificate: None,
                    private_key: None,
                    allow_insecure: true,
                    padding_scheme: None,
                },
            )
            .unwrap();
            let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = bound.local_addr().unwrap().port();
            let server = tokio::spawn(async move { Arc::new(listener).run_on(bound).await });

            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            client.write_all(&digest("wrong")).await.unwrap();
            client.write_u16(0).await.unwrap();
            // No Alert, no bytes — the socket must simply EOF.
            let got = tokio::time::timeout(Duration::from_secs(5), async {
                let mut buf = [0u8; 16];
                client.read(&mut buf).await
            })
            .await
            .expect("bad-auth close never arrived");
            // Zero bytes precede the close — EOF or a bare RST both
            // satisfy "no response bytes" (platform variance in how the
            // dropped socket reports).
            match got {
                Ok(0) => {}
                Ok(n) => panic!("a rejected auth emitted {n} bytes"),
                Err(e) => assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset,
                    "unexpected close error: {e}"
                ),
            }
            assert_eq!(proxy.dials.load(Ordering::SeqCst), 0);
            server.abort();
            let _ = server.await;
        })
        .await
        .expect("bad-auth test timed out");
    }
}
