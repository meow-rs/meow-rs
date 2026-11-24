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
use meow_common::{metadata_ip_literal, ConnType, Metadata, Network, TcpKeepaliveConfig};
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
    max_connections: usize,
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
        let padding = match spec.padding_scheme.as_deref() {
            Some(scheme) => Arc::new(PaddingFactory::new(scheme.as_bytes()).map_err(|e| {
                meow_common::MeowError::Config(format!("anytls listener: padding-scheme: {e}"))
            })?),
            None => PaddingFactory::default(),
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
            max_connections: DEFAULT_MAX_CONNECTIONS,
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
        self.max_connections = max;
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
        info!(
            "AnyTLS listener '{}' on {} (tls={}, users={})",
            self.name,
            bound,
            self.acceptor.is_some(),
            self.users.len(),
        );

        let sem: Option<Arc<Semaphore>> =
            (self.max_connections > 0).then(|| Arc::new(Semaphore::new(self.max_connections)));

        let mut warned_saturated = false;
        let mut accept_backoff = meow_common::ErrorBackoff::new();
        loop {
            let permit = if let Some(sem) = &sem {
                let sem = Arc::clone(sem);
                if sem.available_permits() == 0 && !warned_saturated {
                    warn!(
                        "anytls listener '{}' saturated at {} concurrent connections; new clients will queue",
                        self.name, self.max_connections
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

            let (stream, peer) = match listener.accept().await {
                Ok(v) => {
                    accept_backoff.succeeded();
                    v
                }
                Err(e) => {
                    drop(permit);
                    if accept_backoff.failed(&e).await {
                        error!("anytls listener '{}' accept error: {}", self.name, e);
                    } else {
                        debug!("anytls listener '{}' accept error: {}", self.name, e);
                    }
                    continue;
                }
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
        // TLS termination and the auth preface share one deadline: the
        // client has `AUTH_PREFACE_TIMEOUT` to present credentials —
        // upstream admits the connection either way, but a bounded
        // preface keeps a parked peer from holding a slot.
        let io: Box<dyn InboundIo> = match &self.acceptor {
            Some(acceptor) => {
                let acceptor = Arc::clone(acceptor);
                let tls = match tokio::time::timeout(
                    AUTH_PREFACE_TIMEOUT,
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
        let user = match tokio::time::timeout(
            AUTH_PREFACE_TIMEOUT,
            authenticate_user(&mut io, &self.users),
        )
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
        let dispatch = tokio::spawn(async move {
            while let Some(stream) = stream_rx.recv().await {
                let session = Arc::clone(&session);
                let inner = Arc::clone(&inner);
                let name = in_name.clone();
                let ov = route_override.clone();
                let user = user.clone();
                tokio::spawn(async move {
                    handle_stream(stream, session, inner, peer, name, in_port, user, ov).await;
                });
            }
        });
        // Await the session's death; the dispatch task ends when the
        // stream-accept channel closes with the session maps.
        let _ = runner.await;
        dispatch.abort();
    }
}

/// Per-stream dispatch: parse the SOCKS destination, ACK at the spec's
/// ordering point, then route TCP or open the UoT association.
async fn handle_stream(
    stream: Arc<anytls_rs::session::Stream>,
    session: Arc<Session>,
    inner: Arc<meow_tunnel::TunnelInner>,
    peer: SocketAddr,
    in_name: String,
    in_port: u16,
    user: SmolStr,
    route_override: Option<meow_common::InboundRouteOverride>,
) {
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
            stream.close();
            return;
        }
        Err(_) => {
            debug!("anytls stream {stream_id}: destination read timed out");
            stream.close();
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
                stream.close();
                return;
            }
        }
        StreamTarget::Tcp
    };

    if matches!(kind, StreamTarget::Reject) {
        debug!("anytls stream {stream_id}: reserved UoT destination {dest} refused");
        stream.close();
        return;
    }

    // SynAck ordering (spec §4): exactly one empty SynAck to a v2+ peer,
    // queued after destination validation and BEFORE any rule lookup or
    // dial — a blocked route must never reorder it behind stream data.
    // `handshake_success` awaits the queue admission so the invariant is
    // deterministic. No frame is sent to v1.
    if let Err(e) = session.handshake_success(stream_id).await {
        debug!("anytls stream {stream_id}: synack: {e}");
        stream.close();
        return;
    }

    match kind {
        StreamTarget::Tcp => {
            let metadata = build_tcp_metadata(
                &dest,
                peer,
                &in_name,
                in_port,
                &user,
                route_override.as_ref(),
            );
            debug!(
                "anytls stream {stream_id}: {peer} -> {}",
                metadata.remote_address()
            );
            route_inbound_tcp(&inner, &mut io, metadata, &[]).await;
        }
        StreamTarget::Uot => {
            crate::anytls_uot::run_uot_stream(
                io,
                inner,
                peer,
                &in_name,
                in_port,
                &user,
                route_override,
            )
            .await;
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

/// `Metadata` for one UoT target — `Network::Udp`, the authenticated
/// user and the route override stamped exactly like the TCP path.
pub(crate) fn build_udp_metadata(
    dst_ip: Option<std::net::IpAddr>,
    host: SmolStr,
    dst_port: u16,
    peer: SocketAddr,
    in_name: &str,
    in_port: u16,
    user: &SmolStr,
    route_override: Option<&meow_common::InboundRouteOverride>,
) -> (Metadata, Option<SocketAddr>) {
    let claimed = dst_ip
        .or_else(|| metadata_ip_literal(&host))
        .map(|ip| SocketAddr::new(ip.to_canonical(), dst_port));
    let mut metadata = Metadata {
        network: Network::Udp,
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
    (metadata, claimed)
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
