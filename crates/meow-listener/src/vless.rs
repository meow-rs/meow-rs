//! VLESS server inbound listener (`listeners: - type: vless`) with the
//! XTLS `xtls-rprx-vision` flow.
//!
//! Pipeline per accepted connection: TCP keepalive → standard TLS 1.3
//! accept or REALITY classification/handshake → bounded VLESS request
//! decode → UUID authentication → command dispatch. TCP commands are
//! wrapped in the server Vision codec and routed through
//! [`route_inbound_tcp`] with the authenticated username in
//! `Metadata.in_user`; Mux commands run the XUDP association in
//! `vless_xudp` over the same codec in XUDP mode. REALITY
//! classification failures are transparently relayed to the configured
//! cover target; authenticated REALITY flows never dial that target.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use meow_common::{ConnType, Metadata, Network, TcpKeepaliveConfig};
use meow_proxy::vless_inbound::{
    read_vless_request, VisionServerConn, VisionServerMode, VlessAddr, VlessRequestCommand,
};
use meow_transport::reality_server::{
    CoverBandwidthLimit, RealityServer, RealityServerAccept, RealityServerConfig,
};
use meow_transport::tls::server::{TlsServer, TlsServerConfig};
use meow_transport::Stream;
use meow_tunnel::{route_inbound_tcp, Tunnel};
use smol_str::SmolStr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::DEFAULT_HANDSHAKE_TIMEOUT;

/// Default cap on in-flight inbound connections per listener when the
/// listener config doesn't set `max-connections`. `0` explicitly disables
/// the cap (same named-listener contract as the other TCP inbounds).
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// REALITY classification/handshakes are bounded independently of the
/// listener lifecycle cap so `max-connections: 0` cannot let unauthenticated
/// ClientHello floods occupy unbounded concurrent handshake work.
const REALITY_HANDSHAKE_SLOTS: usize = 256;

/// Cover relays are unauthenticated by definition; cap them tighter than
/// authenticated flows. A saturated cover branch closes new probes instead
/// of queueing them behind established relays.
const REALITY_COVER_SLOTS: usize = 64;

/// Cover-target dial deadline. The cover branch must look like a direct
/// reverse proxy stall rather than a meow-internal long-lived attempt.
const COVER_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// Listener-facing `type: vless` spec. `certificate`/`private_key` stay
/// AS WRITTEN (PEM literal or path); resolution happens eagerly in
/// [`VlessListener::new`], before sockets are bound.
pub struct VlessListenerSpec {
    /// `(username, wire UUID)` pairs in declaration order. The config
    /// builder enforces non-empty, unique users and the sole supported
    /// `xtls-rprx-vision` flow.
    pub users: Vec<VlessUserSpec>,
    pub security: VlessSecuritySpec,
    /// `udp: false` rejects Mux/XUDP at the VLESS command layer — the
    /// primary enforcement point ahead of the codec's own backstop.
    pub udp: bool,
}

#[derive(Clone)]
pub struct VlessUserSpec {
    pub username: String,
    pub uuid: [u8; 16],
}

pub enum VlessSecuritySpec {
    /// Standard TLS 1.3 certificate pair.
    StandardTls {
        certificate: String,
        private_key: String,
        alpn: Vec<String>,
    },
    Reality(VlessRealitySpec),
}

pub struct VlessRealitySpec {
    /// `host:port` as written. The host is resolved only when a cover
    /// connection actually needs dialing.
    pub dest: String,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    /// Microseconds; `0` disables the REALITY freshness check.
    pub max_time_difference_us: u64,
    pub limit_fallback_upload: VlessFallbackLimit,
    pub limit_fallback_download: VlessFallbackLimit,
}

#[derive(Clone, Copy, Default)]
pub struct VlessFallbackLimit {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes_per_sec: u64,
}

enum SecurityRuntime {
    StandardTls(TlsServer),
    Reality(RealityRuntime),
}

struct RealityRuntime {
    server: RealityServer,
    dest_host: String,
    dest_port: u16,
    cover_limit: CoverBandwidthLimit,
    handshake_slots: Arc<Semaphore>,
    cover_slots: Arc<Semaphore>,
}

/// Bound endpoints of every live VLESS listener generation in this
/// process. A cover target resolving to any of them would re-enter the
/// REALITY classifier rather than reach a cover site. Weak refs keep a
/// dropped listener from poisoning later independent generations.
type EndpointSet = std::sync::RwLock<HashSet<SocketAddr>>;
type EndpointRegistry = parking_lot::Mutex<Vec<Weak<EndpointSet>>>;

fn endpoint_registries() -> &'static EndpointRegistry {
    static REGISTRIES: std::sync::OnceLock<EndpointRegistry> = std::sync::OnceLock::new();
    REGISTRIES.get_or_init(|| parking_lot::Mutex::new(Vec::new()))
}

pub struct VlessListener {
    tunnel: Tunnel,
    name: String,
    security: SecurityRuntime,
    users: Arc<HashMap<[u8; 16], SmolStr>>,
    udp: bool,
    /// Shared across every address this listener entry serves — the cap
    /// bounds the entry, not each socket.
    conn_slots: Option<Arc<Semaphore>>,
    conn_max: usize,
    tcp_keepalive: TcpKeepaliveConfig,
    route_override: Option<meow_common::InboundRouteOverride>,
    bound_endpoints: Arc<std::sync::RwLock<HashSet<SocketAddr>>>,
    vision_raw_read_switches: AtomicUsize,
    vision_raw_write_switches: AtomicUsize,
}

fn build_security_runtime(
    security: VlessSecuritySpec,
) -> Result<SecurityRuntime, Box<dyn std::error::Error + Send + Sync>> {
    match security {
        VlessSecuritySpec::StandardTls {
            certificate,
            private_key,
            alpn,
        } => {
            let (certificate_chain_pem, private_key_pem) =
                crate::pem::load_identity_pair(&certificate, &private_key, "vless")
                    .map_err(|e| meow_common::MeowError::Config(e.to_string()))?;
            let server = TlsServer::new(&TlsServerConfig {
                certificate_chain_pem,
                private_key_pem,
                alpn,
            })
            .map_err(|e| meow_common::MeowError::Config(format!("vless TLS: {e}")))?;
            Ok(SecurityRuntime::StandardTls(server))
        }
        VlessSecuritySpec::Reality(spec) => {
            let (dest_host, dest_port) = parse_reality_dest(&spec.dest)
                .map_err(|e| meow_common::MeowError::Config(e.to_string()))?;
            let server = RealityServer::new(&RealityServerConfig {
                private_key: spec.private_key,
                short_ids: spec.short_ids,
                server_names: spec.server_names.iter().cloned().collect(),
                max_time_difference: Some(Duration::from_micros(spec.max_time_difference_us)),
                now: Some(meow_common::protocol_now),
            })
            .map_err(|e| meow_common::MeowError::Config(format!("vless REALITY: {e}")))?;
            // The transport's current relay interface carries one shared
            // token-bucket capacity for both directions. Use the larger
            // configured burst rather than silently tightening a direction
            // whose operator configured more; the directional rates and
            // exemptions themselves map exactly.
            let burst_bytes = spec
                .limit_fallback_upload
                .burst_bytes_per_sec
                .max(spec.limit_fallback_download.burst_bytes_per_sec);
            Ok(SecurityRuntime::Reality(RealityRuntime {
                server,
                dest_host,
                dest_port,
                cover_limit: CoverBandwidthLimit {
                    upload_bytes_per_second: spec.limit_fallback_upload.bytes_per_sec,
                    upload_exempt_bytes: spec.limit_fallback_upload.after_bytes,
                    download_bytes_per_second: spec.limit_fallback_download.bytes_per_sec,
                    download_exempt_bytes: spec.limit_fallback_download.after_bytes,
                    burst_bytes,
                },
                handshake_slots: Arc::new(Semaphore::new(REALITY_HANDSHAKE_SLOTS)),
                cover_slots: Arc::new(Semaphore::new(REALITY_COVER_SLOTS)),
            }))
        }
    }
}

/// Run the exact security-material validation [`VlessListener::new`]
/// performs at startup, without binding sockets or contacting the cover
/// target. `meow -t` uses this so a certificate/key or REALITY parameter
/// that startup would reject cannot be reported as valid.
pub fn validate_security_spec(
    security: VlessSecuritySpec,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    build_security_runtime(security).map(drop)
}

fn cover_dial_budget(
    deadline: tokio::time::Instant,
    now: tokio::time::Instant,
) -> Option<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(COVER_DIAL_TIMEOUT))
}

impl VlessListener {
    /// Build the listener and validate/load all security material eagerly:
    /// a bad PEM/key pair or malformed REALITY parameter is a startup
    /// error, never a detached accept-task surprise.
    pub fn new(
        tunnel: Tunnel,
        name: String,
        spec: VlessListenerSpec,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if spec.users.is_empty() {
            return Err(Box::new(meow_common::MeowError::Config(
                "vless listener: users must not be empty".into(),
            )));
        }
        let users: HashMap<[u8; 16], SmolStr> = spec
            .users
            .into_iter()
            .map(|u| (u.uuid, SmolStr::from(u.username)))
            .collect();
        let security = build_security_runtime(spec.security)?;

        let bound_endpoints = Arc::new(std::sync::RwLock::new(HashSet::new()));
        endpoint_registries()
            .lock()
            .push(Arc::downgrade(&bound_endpoints));
        Ok(Self {
            tunnel,
            name,
            security,
            users: Arc::new(users),
            udp: spec.udp,
            conn_slots: (DEFAULT_MAX_CONNECTIONS > 0)
                .then(|| Arc::new(Semaphore::new(DEFAULT_MAX_CONNECTIONS))),
            conn_max: DEFAULT_MAX_CONNECTIONS,
            tcp_keepalive: TcpKeepaliveConfig::default(),
            route_override: None,
            bound_endpoints,
            vision_raw_read_switches: AtomicUsize::new(0),
            vision_raw_write_switches: AtomicUsize::new(0),
        })
    }

    /// No-op placeholder for parity with other listeners' prepare/step
    /// split — security material already resolves in `new`.
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

    pub fn with_tcp_keepalive(mut self, cfg: TcpKeepaliveConfig) -> Self {
        self.tcp_keepalive = cfg;
        self
    }

    pub fn with_route_override(mut self, ov: Option<meow_common::InboundRouteOverride>) -> Self {
        self.route_override = ov;
        self
    }

    /// Record an actually bound endpoint before accept tasks start. The
    /// runtime self-loop guard uses these endpoints; `port: 0` must be
    /// passed only after `local_addr()` resolves it.
    pub fn note_bound_endpoint(&self, addr: SocketAddr) {
        self.bound_endpoints
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(canonical_endpoint(addr));
    }

    /// Cumulative DIRECT switches observed on this listener, as
    /// `(uplink read, downlink write)`. Exposed for diagnostics and for the
    /// in-process interoperability tests: an echo alone cannot distinguish
    /// DIRECT from the END fallback.
    pub fn vision_raw_switch_counts(&self) -> (usize, usize) {
        (
            self.vision_raw_read_switches.load(Ordering::Relaxed),
            self.vision_raw_write_switches.load(Ordering::Relaxed),
        )
    }

    /// Serve on an already-bound socket. Multi-address listeners spawn
    /// one `run_on` per socket on a shared `Arc` and share the same cap,
    /// auth table, TLS/REALITY state and endpoint registry.
    pub async fn run_on(
        self: &Arc<Self>,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bound = listener.local_addr()?;
        self.note_bound_endpoint(bound);
        let in_port = bound.port();
        info!(
            "VLESS listener '{}' on {} (security={}, users={}, udp={})",
            self.name,
            bound,
            match self.security {
                SecurityRuntime::StandardTls(_) => "tls",
                SecurityRuntime::Reality(_) => "reality",
            },
            self.users.len(),
            self.udp,
        );

        let mut warned_saturated = false;
        let mut accept_backoff = meow_common::ErrorBackoff::new();
        loop {
            // Acquire AFTER accept(): the cap bounds connections the
            // kernel actually delivered rather than parking the accept
            // loop before a peer exists.
            let (stream, peer) = match listener.accept().await {
                Ok(v) => {
                    accept_backoff.succeeded();
                    v
                }
                Err(e) => {
                    if accept_backoff.failed(&e).await {
                        error!("vless listener '{}' accept error: {}", self.name, e);
                    } else {
                        debug!("vless listener '{}' accept error: {}", self.name, e);
                    }
                    continue;
                }
            };
            let permit = if let Some(sem) = &self.conn_slots {
                let sem = Arc::clone(sem);
                if sem.available_permits() == 0 && !warned_saturated {
                    warn!(
                        "vless listener '{}' saturated at {} concurrent connections; new clients will queue",
                        self.name, self.conn_max
                    );
                    warned_saturated = true;
                }
                match sem.acquire_owned().await {
                    Ok(p) => {
                        if warned_saturated {
                            debug!("vless listener '{}' has free capacity again", self.name);
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

    async fn handle_conn(&self, stream: tokio::net::TcpStream, peer: SocketAddr, in_port: u16) {
        // TLS/REALITY accept and the bounded VLESS request share ONE
        // absolute deadline. Splitting them would double the time a
        // silent peer can retain a connection slot.
        let deadline = tokio::time::Instant::now() + DEFAULT_HANDSHAKE_TIMEOUT;
        let inner: Box<dyn Stream> = Box::new(stream);
        let accepted = match &self.security {
            SecurityRuntime::StandardTls(server) => {
                match tokio::time::timeout_at(deadline, server.accept(inner)).await {
                    Ok(Ok(stream)) => Some(stream),
                    Ok(Err(e)) => {
                        debug!("vless listener '{}' TLS accept from {peer}: {e}", self.name);
                        None
                    }
                    Err(_) => {
                        debug!(
                            "vless listener '{}' TLS accept from {peer} timed out",
                            self.name
                        );
                        None
                    }
                }
            }
            SecurityRuntime::Reality(reality) => {
                let handshake_permit = match tokio::time::timeout_at(
                    deadline,
                    Arc::clone(&reality.handshake_slots).acquire_owned(),
                )
                .await
                {
                    Ok(Ok(permit)) => Some(permit),
                    Ok(Err(_)) => return,
                    Err(_) => {
                        debug!(
                            "vless listener '{}' REALITY handshake-slot wait from {peer} timed out",
                            self.name
                        );
                        return;
                    }
                };
                let accepted =
                    match tokio::time::timeout_at(deadline, reality.server.accept(inner)).await {
                        Ok(Ok(accept)) => Some(accept),
                        Ok(Err(e)) => {
                            debug!(
                                "vless listener '{}' REALITY accept from {peer}: {e}",
                                self.name
                            );
                            None
                        }
                        Err(_) => {
                            debug!(
                                "vless listener '{}' REALITY accept from {peer} timed out",
                                self.name
                            );
                            None
                        }
                    };
                drop(handshake_permit);
                match accepted {
                    Some(RealityServerAccept::Authenticated(stream)) => Some(stream),
                    Some(RealityServerAccept::Cover(relay)) => {
                        self.run_cover(reality, relay, peer, deadline).await;
                        None
                    }
                    None => None,
                }
            }
        };
        let Some(mut stream) = accepted else {
            return;
        };

        let request = match tokio::time::timeout_at(deadline, read_vless_request(&mut stream)).await
        {
            Ok(Ok(request)) => request,
            Ok(Err(e)) => {
                debug!("vless listener '{}' request from {peer}: {e}", self.name);
                graceful_close(&mut stream).await;
                return;
            }
            Err(_) => {
                debug!(
                    "vless listener '{}' request from {peer} timed out",
                    self.name
                );
                graceful_close(&mut stream).await;
                return;
            }
        };

        let Some(username) = self.users.get(&request.uuid).cloned() else {
            // Wrong bearer credential: no VLESS response, no DNS lookup,
            // no target dial — exactly the Vision server contract.
            debug!(
                "vless listener '{}' auth from {peer}: unknown credential",
                self.name
            );
            graceful_close(&mut stream).await;
            return;
        };

        match request.command {
            VlessRequestCommand::Tcp { port, target } => {
                if !meow_transport::supports_raw_passthrough(&mut *stream) {
                    // Both production acceptors are raw-capable. If a test
                    // or future transport is not, do not feed it to the
                    // codec: DIRECT would have to be silently downgraded.
                    warn!(
                        "vless listener '{}' closing {peer}: outer transport cannot switch to raw passthrough",
                        self.name
                    );
                    graceful_close(&mut stream).await;
                    return;
                }
                let metadata = build_tcp_metadata(
                    &target,
                    port,
                    peer,
                    &self.name,
                    in_port,
                    &username,
                    self.route_override.as_ref(),
                );
                debug!(
                    "vless listener '{}' {peer} user '{}' -> {}",
                    self.name,
                    username,
                    metadata.remote_address()
                );
                let mut conn = VisionServerConn::new(stream, request.uuid, VisionServerMode::Tcp);
                let inner = Arc::clone(self.tunnel.inner());
                route_inbound_tcp(&inner, &mut conn, metadata, &[]).await;
                if conn.read_switched_to_raw() {
                    self.vision_raw_read_switches
                        .fetch_add(1, Ordering::Relaxed);
                }
                if conn.write_switched_to_raw() {
                    self.vision_raw_write_switches
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            VlessRequestCommand::Mux => {
                // `udp: false` refuses Mux at the VLESS header layer — the
                // primary enforcement point, before any XUDP byte arrives
                // (the codec's `udp_permitted` is only a backstop). No
                // response header, no target resolution, no mux state.
                if !self.udp {
                    debug!(
                        "vless listener '{}' mux command from {peer}: udp disabled",
                        self.name
                    );
                    graceful_close(&mut stream).await;
                    return;
                }
                debug!(
                    "vless listener '{}' {peer} user '{}' -> XUDP association",
                    self.name, username
                );
                let conn = VisionServerConn::new(stream, request.uuid, VisionServerMode::Xudp);
                let inner = Arc::clone(self.tunnel.inner());
                crate::vless_xudp::run_xudp_conn(
                    conn,
                    inner,
                    crate::vless_xudp::XudpFlowCtx {
                        peer,
                        in_name: &self.name,
                        in_port,
                        user: &username,
                        route_override: self.route_override.as_ref(),
                    },
                    deadline,
                )
                .await;
            }
        }
    }

    async fn run_cover(
        &self,
        reality: &RealityRuntime,
        relay: meow_transport::reality_server::CoverRelay,
        peer: SocketAddr,
        deadline: tokio::time::Instant,
    ) {
        // Covers are unauthenticated long-lived relays: refuse new work at
        // saturation rather than letting probes queue behind the 10-minute
        // relay lifetime.
        let Ok(cover_permit) = Arc::clone(&reality.cover_slots).try_acquire_owned() else {
            debug!(
                "vless listener '{}' cover from {peer}: saturated at {} relays",
                self.name, REALITY_COVER_SLOTS
            );
            return;
        };
        // Accepting the REALITY ClientHello may already have consumed most
        // of the 15s handshake budget. The cover dial gets the shorter of
        // its own 3s budget and what remains of that absolute deadline;
        // it must not restart a fresh 3s clock after a slow accept.
        let now = tokio::time::Instant::now();
        let Some(dial_budget) = cover_dial_budget(deadline, now) else {
            debug!(
                "vless listener '{}' cover from {peer}: handshake deadline already spent",
                self.name
            );
            return;
        };
        let target = match tokio::time::timeout(dial_budget, self.dial_cover_target(reality)).await
        {
            Ok(Ok(target)) => target,
            Ok(Err(e)) => {
                debug!(
                    "vless listener '{}' cover from {peer}: target dial failed: {e}",
                    self.name
                );
                return;
            }
            Err(_) => {
                debug!(
                    "vless listener '{}' cover from {peer}: target dial exceeded {}ms",
                    self.name,
                    dial_budget.as_millis()
                );
                return;
            }
        };
        debug!(
            "vless listener '{}' cover from {peer}: relaying to {}:{}",
            self.name, reality.dest_host, reality.dest_port
        );
        if let Err(e) = relay.relay_with_limit(target, reality.cover_limit).await {
            debug!(
                "vless listener '{}' cover from {peer}: relay ended: {e}",
                self.name
            );
        }
        drop(cover_permit);
    }

    async fn dial_cover_target(
        &self,
        reality: &RealityRuntime,
    ) -> Result<Box<dyn Stream>, std::io::Error> {
        let candidates =
            meow_common::resolve_host_all(&reality.dest_host, reality.dest_port).await?;
        let endpoints = self.all_bound_endpoints();
        let local_addrs = local_addr_snapshot();
        let mut last_err = None;
        let mut looped = false;
        for addr in candidates {
            if endpoint_is_self(addr, &endpoints, local_addrs.as_ref()) {
                looped = true;
                warn!(
                    "vless listener '{}' REALITY cover target {}:{} resolved back to this listener at {addr}; candidate refused",
                    self.name, reality.dest_host, reality.dest_port
                );
                continue;
            }
            match meow_common::connect_tcp(addr).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(e) => last_err = Some(e),
            }
        }
        if looped && last_err.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "REALITY cover target resolves to this VLESS listener",
            ));
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "REALITY cover target resolved to no dialable address",
            )
        }))
    }

    fn all_bound_endpoints(&self) -> HashSet<SocketAddr> {
        let mut out: HashSet<SocketAddr> = self
            .bound_endpoints
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .copied()
            .collect();
        let mut registries = endpoint_registries().lock();
        registries.retain(|weak| {
            if let Some(set) = weak.upgrade() {
                // This listener's own set is already merged; merging it
                // again is harmless because the result is a set.
                out.extend(
                    set.read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .iter()
                        .copied(),
                );
                true
            } else {
                false
            }
        });
        out
    }
}

async fn graceful_close(stream: &mut Box<dyn Stream>) {
    let _ = tokio::time::timeout(Duration::from_millis(500), stream.shutdown()).await;
}

fn build_tcp_metadata(
    target: &VlessAddr,
    port: u16,
    peer: SocketAddr,
    in_name: &str,
    in_port: u16,
    user: &SmolStr,
    route_override: Option<&meow_common::InboundRouteOverride>,
) -> Metadata {
    let (host, dst_ip) = match target {
        VlessAddr::Ipv4(octets) => (SmolStr::default(), Some(IpAddr::from(*octets))),
        VlessAddr::Ipv6(octets) => (SmolStr::default(), Some(IpAddr::from(*octets))),
        VlessAddr::Domain(domain) => (Metadata::lower_host(domain), None),
    };
    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Vless,
        src_ip: Some(peer.ip()),
        src_port: peer.port(),
        dst_ip,
        dst_port: port,
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

/// Validate/split a REALITY `dest` (`host:port`, bracketed IPv6). The
/// config builder already enforces this shape; the listener-facing spec
/// remains useful for programmatic construction and tests.
fn parse_reality_dest(dest: &str) -> Result<(String, u16), anyhow::Error> {
    if dest.is_empty() || dest.contains("://") || dest.contains('@') || dest.contains('/') {
        anyhow::bail!("vless REALITY dest must be bare host:port");
    }
    let (host, port_str) = if let Some(rest) = dest.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            anyhow::bail!("vless REALITY dest: bracketed IPv6 must close as [addr]:port");
        };
        let Some(port) = tail.strip_prefix(':') else {
            anyhow::bail!("vless REALITY dest: bracketed IPv6 must be followed by :port");
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            anyhow::bail!("vless REALITY dest: invalid IPv6 literal");
        }
        (host.to_string(), port)
    } else {
        let Some((host, port)) = dest.rsplit_once(':') else {
            anyhow::bail!("vless REALITY dest: missing :port");
        };
        if host.contains(':') {
            anyhow::bail!("vless REALITY dest: IPv6 destinations must be bracketed");
        }
        (host.to_string(), port)
    };
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        anyhow::bail!("vless REALITY dest: invalid host");
    }
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!("vless REALITY dest: invalid port");
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("vless REALITY dest: invalid port"))?;
    if port == 0 {
        anyhow::bail!("vless REALITY dest: port 0 is not dialable");
    }
    Ok((host, port))
}

fn canonical_endpoint(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Snapshot local interface addresses for wildcard-bind self-loop checks.
/// Enumeration failure is conservative: `None` makes a same-port candidate
/// on a wildcard bind a self-loop.
fn local_addr_snapshot() -> Option<HashSet<IpAddr>> {
    #[cfg(unix)]
    {
        local_interface_addrs().map(|set| {
            set.into_iter()
                .map(|ip| ip.to_canonical())
                .collect::<HashSet<_>>()
        })
    }
    #[cfg(not(unix))]
    {
        let mut addrs = HashSet::new();
        addrs.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        addrs.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        Some(addrs)
    }
}

#[cfg(unix)]
fn local_interface_addrs() -> Option<HashSet<IpAddr>> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let mut addrs = HashSet::new();
    // SAFETY: `getifaddrs` fills `ifaddrs` on success; the list is walked
    // only within this scope and released by `freeifaddrs` before return.
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return None;
        }
        let mut cur = ifaddrs;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                match (*ifa.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        addrs.insert(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))));
                    }
                    libc::AF_INET6 => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        addrs.insert(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifaddrs);
    }
    (!addrs.is_empty()).then_some(addrs)
}

fn endpoint_is_self(
    candidate: SocketAddr,
    endpoints: &HashSet<SocketAddr>,
    local_addrs: Option<&HashSet<IpAddr>>,
) -> bool {
    let ip = candidate.ip().to_canonical();
    endpoints.iter().any(|bound| {
        if bound.port() != candidate.port() {
            return false;
        }
        let bind_ip = bound.ip().to_canonical();
        if ip == bind_ip {
            return true;
        }
        if bind_ip.is_loopback() && ip.is_loopback() && bind_ip.is_ipv4() == ip.is_ipv4() {
            return true;
        }
        bind_ip.is_unspecified()
            && (ip.is_unspecified() || local_addrs.is_none_or(|addrs| addrs.contains(&ip)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_dest_parser_accepts_domain_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            parse_reality_dest("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_reality_dest("127.0.0.1:8443").unwrap(),
            ("127.0.0.1".to_string(), 8443)
        );
        assert_eq!(
            parse_reality_dest("[::1]:8443").unwrap(),
            ("::1".to_string(), 8443)
        );
    }

    #[test]
    fn reality_dest_parser_rejects_unsafe_or_undialable_shapes() {
        for dest in [
            "",
            "https://example.com:443",
            "example.com",
            "::1:443",
            "example.com:0",
            "user@example.com:443",
        ] {
            assert!(parse_reality_dest(dest).is_err(), "{dest} must fail");
        }
    }

    #[test]
    fn self_loop_guard_matches_exact_loopback_and_wildcard_local_addresses() {
        let mut endpoints = HashSet::new();
        endpoints.insert(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            8443,
        ));
        assert!(endpoint_is_self(
            SocketAddr::new("127.0.0.44".parse().unwrap(), 8443),
            &endpoints,
            None,
        ));
        assert!(!endpoint_is_self(
            SocketAddr::new("192.0.2.10".parse().unwrap(), 8443),
            &endpoints,
            None,
        ));

        endpoints.clear();
        endpoints.insert(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            443,
        ));
        let local = HashSet::from(["192.0.2.10".parse::<IpAddr>().unwrap()]);
        assert!(endpoint_is_self(
            SocketAddr::new("192.0.2.10".parse().unwrap(), 443),
            &endpoints,
            Some(&local),
        ));
        assert!(!endpoint_is_self(
            SocketAddr::new("198.51.100.20".parse().unwrap(), 443),
            &endpoints,
            Some(&local),
        ));
        // Enumeration failure is conservative on a wildcard bind.
        assert!(endpoint_is_self(
            SocketAddr::new("198.51.100.20".parse().unwrap(), 443),
            &endpoints,
            None,
        ));
    }

    #[test]
    fn cover_dial_budget_is_capped_by_the_absolute_handshake_deadline() {
        let now = tokio::time::Instant::now();
        assert_eq!(
            cover_dial_budget(now + Duration::from_secs(15), now),
            Some(COVER_DIAL_TIMEOUT)
        );
        assert_eq!(
            cover_dial_budget(now + Duration::from_millis(1200), now),
            Some(Duration::from_millis(1200))
        );
        assert_eq!(cover_dial_budget(now, now), None);
        assert_eq!(cover_dial_budget(now - Duration::from_millis(1), now), None);
    }
}
