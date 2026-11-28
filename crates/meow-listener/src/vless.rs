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
    /// Cover target host, resolved only when a cover connection actually
    /// needs dialing. Structured upstream: meow-config parses and
    /// validates the configured `dest` string once (shape, bracketed
    /// IPv6, decimal non-zero port) and the app wiring passes the split
    /// result through — the listener must never re-parse a string form.
    pub dest_host: String,
    pub dest_port: u16,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    /// Microseconds; `0` disables the REALITY freshness check.
    pub max_time_difference_us: u64,
    pub limit_fallback_upload: VlessFallbackLimit,
    pub limit_fallback_download: VlessFallbackLimit,
    /// REALITY v2 mirror orchestration, normalized and validated by the
    /// shared config/runtime contract in `meow-common`.
    pub mimic: VlessRealityMimicSpec,
}

#[derive(Clone, Copy, Default)]
pub struct VlessFallbackLimit {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes_per_sec: u64,
}

pub use meow_common::{VlessRealityMimicMode, VlessRealityMimicSpec};

pub(crate) enum SecurityRuntime {
    StandardTls(TlsServer),
    Reality(RealityRuntime),
}

pub(crate) struct RealityRuntime {
    pub(crate) server: RealityServer,
    pub(crate) dest_host: String,
    pub(crate) dest_port: u16,
    pub(crate) cover_limit: CoverBandwidthLimit,
    pub(crate) handshake_slots: Arc<Semaphore>,
    pub(crate) probe_slots: Arc<Semaphore>,
    pub(crate) cover_slots: Arc<Semaphore>,
    pub(crate) mimic: VlessRealityMimicSpec,
    pub(crate) metrics: Arc<crate::vless_mimic::RealityV2Metrics>,
}

/// Whether a v6 wildcard socket also accepts IPv4 traffic. Linux and macOS
/// default such sockets to dual-stack; a host or embedder can still create a
/// v6-only socket, so the runtime guard records the real socket option instead
/// of guessing from the bound address. Meaningless for non-v6-wildcards.
#[derive(Clone, Copy)]
struct BoundEndpointCoverage {
    v6_wildcard_accepts_v4: bool,
}

impl BoundEndpointCoverage {
    #[cfg(test)]
    const CONSERVATIVE: Self = Self {
        v6_wildcard_accepts_v4: true,
    };
}

/// Bound endpoints of every live VLESS listener generation in this
/// process. A cover target resolving to any of them would re-enter the
/// REALITY classifier rather than reach a cover site. Weak refs keep a
/// dropped listener from poisoning later independent generations.
type EndpointSnapshot = HashMap<SocketAddr, BoundEndpointCoverage>;
type EndpointSet = std::sync::RwLock<EndpointSnapshot>;
type EndpointRegistry = parking_lot::Mutex<Vec<Weak<EndpointSet>>>;

fn endpoint_registries() -> &'static EndpointRegistry {
    static REGISTRIES: std::sync::OnceLock<EndpointRegistry> = std::sync::OnceLock::new();
    REGISTRIES.get_or_init(|| parking_lot::Mutex::new(Vec::new()))
}

/// RAII inverse of [`VlessListener::note_bound_endpoint`] for one socket:
/// the registration means "something is accepting here NOW", so it must
/// not survive the listen socket it describes. Dropping the guard — the
/// end of `run_on`, including cancellation — removes exactly the endpoint
/// it inserted; a port later reused by an unrelated service must not stay
/// blacklisted as a cover target.
struct EndpointRegistration {
    set: Arc<EndpointSet>,
    addr: SocketAddr,
}

impl EndpointRegistration {
    fn new(set: Arc<EndpointSet>, addr: SocketAddr) -> Self {
        Self { set, addr }
    }
}

impl Drop for EndpointRegistration {
    fn drop(&mut self) {
        self.set
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.addr);
    }
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
    bound_endpoints: Arc<EndpointSet>,
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
            spec.mimic
                .validate()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let dest_host = spec.dest_host.clone();
            let dest_port = spec.dest_port;
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
                probe_slots: Arc::new(Semaphore::new(spec.mimic.max_concurrent_probes)),
                cover_slots: Arc::new(Semaphore::new(REALITY_COVER_SLOTS)),
                mimic: spec.mimic,
                metrics: Arc::new(crate::vless_mimic::RealityV2Metrics::new()),
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

/// An unspecified address is not a routable remote host, so it can never
/// be a REALITY cover site no matter what meaning the local stack gives
/// `connect()` to it. Canonicalize first: the v4-mapped spelling
/// `::ffff:0.0.0.0` must not bypass the v4 unspecified check.
fn cover_candidate_is_dialable(addr: &SocketAddr) -> bool {
    !addr.ip().to_canonical().is_unspecified()
}

/// Filter per candidate rather than poisoning the whole DNS answer: a mixed
/// answer still contains valid routes to the configured cover host, while its
/// unspecified entries have no remote meaning at all.
fn dialable_cover_candidates(candidates: Vec<SocketAddr>) -> impl Iterator<Item = SocketAddr> {
    candidates.into_iter().filter(cover_candidate_is_dialable)
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

        let bound_endpoints = Arc::new(std::sync::RwLock::new(EndpointSnapshot::new()));
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
    /// passed only after `local_addr()` resolves it. `addr` must be that
    /// socket's local address: the socket is inspected because a v6 wildcard's
    /// `IPV6_V6ONLY` setting decides whether v4 loopback can re-enter it.
    pub fn note_bound_endpoint(&self, socket: &TcpListener, addr: SocketAddr) {
        self.bound_endpoints
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(canonical_endpoint(addr), endpoint_coverage(socket, addr));
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

    /// Internal fixed-label REALITY v2 counter snapshot.  This is diagnostic
    /// surface for in-process verification, not a public metrics API.
    #[doc(hidden)]
    pub fn reality_v2_metrics_snapshot(
        &self,
    ) -> Option<crate::vless_mimic::RealityV2MetricsSnapshot> {
        let SecurityRuntime::Reality(reality) = &self.security else {
            return None;
        };
        Some(reality.metrics.snapshot(
            &reality.handshake_slots,
            REALITY_HANDSHAKE_SLOTS,
            &reality.probe_slots,
            reality.mimic.max_concurrent_probes,
            &reality.cover_slots,
            REALITY_COVER_SLOTS,
        ))
    }

    /// Serve on an already-bound socket. Multi-address listeners spawn
    /// one `run_on` per socket on a shared `Arc` and share the same cap,
    /// auth table, TLS/REALITY state and endpoint registry.
    ///
    /// The accept loop SUPERVISES its connection tasks: cancelling this
    /// future — or its task — aborts every connection it spawned (the
    /// JoinSet's Drop), so cover relays, authenticated TCP relays and
    /// XUDP associations all die with their listen socket instead of
    /// detaching behind it. The endpoint registration follows the same
    /// lifetime through the guard below.
    pub async fn run_on(
        self: &Arc<Self>,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bound = listener.local_addr()?;
        self.note_bound_endpoint(&listener, bound);
        let _endpoint_registration =
            EndpointRegistration::new(Arc::clone(&self.bound_endpoints), canonical_endpoint(bound));
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

        let mut conns = tokio::task::JoinSet::new();
        let mut warned_saturated = false;
        let mut accept_backoff = meow_common::ErrorBackoff::new();
        loop {
            tokio::select! {
                // Reap finished connection tasks so their join slots and
                // any panics surface instead of accumulating; cancel-safe
                // and never the only arm, so accept is never starved.
                reaped = conns.join_next(), if !conns.is_empty() => {
                    if let Some(Err(e)) = reaped {
                        if e.is_panic() {
                            error!("vless listener '{}' connection task panicked: {}", self.name, e);
                        }
                    }
                    continue;
                }
                accepted = listener.accept() => {
                    // Acquire AFTER accept(): the cap bounds connections the
                    // kernel actually delivered rather than parking the accept
                    // loop before a peer exists.
                    let (stream, peer) = match accepted {
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

                    // REALITY admission happens BEFORE the spawn: the
                    // classification slots bound every socket in flight,
                    // including the ones still waiting to be classified.
                    // Without this, `max-connections: 0` would let an
                    // unauthenticated ClientHello flood pile up unbounded
                    // tasks holding sockets behind the semaphore. A
                    // saturated classifier refuses the socket outright —
                    // the same shape cover saturation already uses —
                    // because classification is unauthenticated work.
                    let handshake_permit = match &self.security {
                        SecurityRuntime::Reality(reality) => {
                            match Arc::clone(&reality.handshake_slots).try_acquire_owned() {
                                Ok(p) => Some(p),
                                Err(_) => {
                                    if matches!(reality.mimic.mode, VlessRealityMimicMode::DialFirst)
                                    {
                                        reality.metrics.inc_close(
                                            crate::vless_mimic::ClosePhase::Admission,
                                            crate::vless_mimic::CloseReason::HandshakeSaturated,
                                        );
                                    }
                                    debug!(
                                        "vless listener '{}' REALITY classification saturated at {} slots; refusing a peer",
                                        self.name, REALITY_HANDSHAKE_SLOTS
                                    );
                                    continue;
                                }
                            }
                        }
                        SecurityRuntime::StandardTls(_) => None,
                    };

                    crate::keepalive::apply(&stream, self.tcp_keepalive, &self.name);
                    // d_hs starts at admission, not at the first poll of the
                    // spawned task: executor queueing time is part of the
                    // handshake budget.
                    let handshake_deadline =
                        tokio::time::Instant::now() + DEFAULT_HANDSHAKE_TIMEOUT;
                    let listener = Arc::clone(self);
                    conns.spawn(async move {
                        listener
                            .handle_conn(stream, peer, in_port, handshake_permit, handshake_deadline)
                            .await;
                        drop(permit);
                    });
                    #[cfg(test)]
                    tests::after_connection_spawn_for_test().await;
                }
            }
        }
    }

    async fn handle_conn(
        &self,
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
        in_port: u16,
        handshake_permit: Option<tokio::sync::OwnedSemaphorePermit>,
        deadline: tokio::time::Instant,
    ) {
        // TLS/REALITY accept and the bounded VLESS request share ONE
        // absolute deadline. Splitting them would double the time a
        // silent peer can retain a connection slot.
        let accepted = match &self.security {
            SecurityRuntime::StandardTls(server) => {
                let inner: Box<dyn Stream> = Box::new(stream);
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
            SecurityRuntime::Reality(reality) => match reality.mimic.mode {
                VlessRealityMimicMode::DialFirst => {
                    let dial = self.dial_first_target(reality);
                    crate::vless_mimic::run_dial_first(
                        reality,
                        Box::new(stream),
                        deadline,
                        handshake_permit,
                        dial,
                    )
                    .await
                }
                VlessRealityMimicMode::Off => {
                    let inner: Box<dyn Stream> = Box::new(stream);
                    // The classification permit was acquired at admission,
                    // before this task existed; it is held through the
                    // handshake exactly as before and released right after
                    // classification — never for the relay's lifetime.
                    let accepted =
                        match tokio::time::timeout_at(deadline, reality.server.accept(inner)).await
                        {
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
                            // Boxed: the cover relay's two 16 KiB direction
                            // scratches live across its copy-loop awaits, so
                            // an unboxed relay future would embed them in
                            // EVERY connection task's future — including the
                            // authenticated majority that never covers.
                            Box::pin(self.run_cover(reality, relay, peer, deadline)).await;
                            None
                        }
                        None => None,
                    }
                }
            },
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

    async fn dial_first_target(
        &self,
        reality: &RealityRuntime,
    ) -> Result<crate::vless_mimic::DialedTarget, crate::vless_mimic::DialFirstDialError> {
        reality.metrics.inc_dial_started();
        let candidates = meow_common::resolve_host_all(&reality.dest_host, reality.dest_port)
            .await
            .map_err(|_| crate::vless_mimic::DialFirstDialError::Resolve)?;
        let endpoints = self.all_bound_endpoints();
        let local_addrs = local_addr_snapshot();
        let Some(addr) = dialable_cover_candidates(candidates)
            .find(|addr| !endpoint_is_self(*addr, &endpoints, local_addrs.as_ref()))
        else {
            return Err(crate::vless_mimic::DialFirstDialError::Resolve);
        };
        reality.metrics.inc_tcp_connect_started();
        let tcp_start = tokio::time::Instant::now();
        let stream = meow_common::connect_tcp(addr)
            .await
            .map_err(|_| crate::vless_mimic::DialFirstDialError::Connect)?;
        let tcp_ready = tokio::time::Instant::now();
        Ok(crate::vless_mimic::DialedTarget {
            stream,
            connect_elapsed: tcp_ready.saturating_duration_since(tcp_start),
        })
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
        for addr in dialable_cover_candidates(candidates) {
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

    fn all_bound_endpoints(&self) -> EndpointSnapshot {
        let mut out: EndpointSnapshot = self
            .bound_endpoints
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(addr, coverage)| (*addr, *coverage))
            .collect();
        let mut registries = endpoint_registries().lock();
        registries.retain(|weak| {
            if let Some(set) = weak.upgrade() {
                // This listener's own table is already merged; merging it
                // again is harmless because the keys are endpoints.
                out.extend(
                    set.read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .iter()
                        .map(|(addr, coverage)| (*addr, *coverage)),
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

fn canonical_endpoint(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn endpoint_coverage(socket: &TcpListener, addr: SocketAddr) -> BoundEndpointCoverage {
    let is_v6_wildcard = matches!(addr.ip(), IpAddr::V6(ip) if ip.is_unspecified());
    let v6_wildcard_accepts_v4 = is_v6_wildcard
        && socket2::SockRef::from(socket)
            .only_v6()
            .map_or(true, |only_v6| !only_v6);
    BoundEndpointCoverage {
        v6_wildcard_accepts_v4,
    }
}

/// Snapshot local interface addresses for wildcard-bind self-loop checks.
/// Every supported platform enumerates for real; any failure — or an
/// empty table, which no live machine can honestly produce — is `None`,
/// and `None` is conservative: a same-port candidate on a wildcard bind
/// is then treated as a self-loop. Returning a loopback-only set dressed
/// up as a complete inventory would invert that failure mode, letting a
/// wildcard-bind cover self-loop to a non-loopback local NIC escape
/// detection.
fn local_addr_snapshot() -> Option<HashSet<IpAddr>> {
    let raw = {
        #[cfg(unix)]
        {
            local_interface_addrs()
        }
        #[cfg(windows)]
        {
            local_interface_addrs_windows()
        }
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    };
    raw.map(|set| {
        set.into_iter()
            .map(|ip| ip.to_canonical())
            .collect::<HashSet<_>>()
    })
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

/// Windows interface inventory through `GetAdaptersAddresses`, walking
/// every adapter's unicast address list. Unlike the TUN device's
/// name-lookup use, nothing here may skip unicast — the unicast table IS
/// the answer — so the walk validates each sockaddr's family and length
/// before copying it rather than trusting the list's shape.
#[cfg(windows)]
fn local_interface_addrs_windows() -> Option<HashSet<IpAddr>> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    const FLAGS: u32 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // Same buffer discipline as the TUN device's name lookup: the u64
    // store keeps the list 8-aligned, overflow retries grow it, and more
    // than four overflows in a row is treated as enumeration failure
    // (conservative `None`), never as a partial table.
    let mut size: u32 = 15000;
    let mut buf = vec![0u64; size as usize / 8 + 1];
    let mut addrs = HashSet::new();
    for _ in 0..4 {
        // SAFETY: `buf` is 8-aligned by its element type, holds at least
        // `size` initialised bytes, and outlives the call; on overflow
        // the API writes the size it needs back through the same pointer.
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                FLAGS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            buf.resize(size as usize / 8 + 1, 0);
            continue;
        }
        if result != 0 {
            return None;
        }
        // SAFETY: on success the buffer starts with the adapter linked
        // list the call built inside it; the walk only reads entries of
        // that list while the buffer is alive.
        let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            let mut unicast = unsafe { (*adapter).FirstUnicastAddress };
            while !unicast.is_null() {
                // SAFETY: `unicast` is one node of the per-adapter list
                // the API chained inside the same buffer.
                let addr = unsafe { &*unicast };
                let sockaddr = addr.Address.lpSockaddr;
                let len = addr.Address.iSockaddrLength;
                if !sockaddr.is_null() {
                    // SAFETY: family/length are validated against the
                    // concrete sockaddr type before it is read as one.
                    unsafe {
                        let family = (*sockaddr).sa_family;
                        if family == AF_INET && len as usize >= std::mem::size_of::<SOCKADDR_IN>() {
                            let sa = &*(sockaddr as *const SOCKADDR_IN);
                            addrs.insert(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                                sa.sin_addr.S_un.S_addr,
                            ))));
                        } else if family == AF_INET6
                            && len as usize >= std::mem::size_of::<SOCKADDR_IN6>()
                        {
                            let sa = &*(sockaddr as *const SOCKADDR_IN6);
                            addrs.insert(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.u.Byte)));
                        }
                    }
                }
                unicast = addr.Next;
            }
            adapter = unsafe { (*adapter).Next };
        }
        return (!addrs.is_empty()).then_some(addrs);
    }
    None
}

fn endpoint_is_self(
    candidate: SocketAddr,
    endpoints: &EndpointSnapshot,
    local_addrs: Option<&HashSet<IpAddr>>,
) -> bool {
    let ip = candidate.ip().to_canonical();
    endpoints.iter().any(|(bound, coverage)| {
        if bound.port() != candidate.port() {
            return false;
        }
        let bind_ip = bound.ip().to_canonical();
        if ip == bind_ip {
            return true;
        }
        // Where connect(unspecified) is accepted it selects loopback, so a
        // same-family loopback bind is the endpoint such a candidate reaches.
        // Where the stack rejects that dial the extra refusal is still exact:
        // an unspecified candidate has no remote-cover meaning.
        if bind_ip.is_loopback()
            && (ip.is_loopback() || ip.is_unspecified())
            && bind_ip.is_ipv4() == ip.is_ipv4()
        {
            return true;
        }
        if !bind_ip.is_unspecified() {
            return false;
        }
        // `to_canonical` has already folded v4-mapped spellings, so 127/8 is
        // visible here in native v4 form. A v4 wildcard cannot receive v6; a
        // v6 wildcard receives v4 only when its recorded socket is dual-stack.
        let wildcard_covers_candidate = match bind_ip {
            IpAddr::V4(_) => ip.is_ipv4(),
            IpAddr::V6(_) => ip.is_ipv6() || coverage.v6_wildcard_accepts_v4,
        };
        wildcard_covers_candidate
            && (ip.is_unspecified()
                || ip.is_loopback()
                || local_addrs.is_none_or(|addrs| addrs.contains(&ip)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_transport::Transport;
    use tokio::io::AsyncReadExt;

    thread_local! {
        static ADVANCE_AFTER_CONNECTION_SPAWN: std::cell::RefCell<Option<Duration>> =
            const { std::cell::RefCell::new(None) };
        static CONNECTION_SPAWN_HOOKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    pub(super) async fn after_connection_spawn_for_test() {
        CONNECTION_SPAWN_HOOKS.with(|cell| cell.set(cell.get() + 1));
        let advance_by = ADVANCE_AFTER_CONNECTION_SPAWN.with(|cell| cell.borrow_mut().take());
        if let Some(advance_by) = advance_by {
            tokio::time::advance(advance_by).await;
        }
    }

    fn test_tunnel() -> Tunnel {
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        Tunnel::new(resolver)
    }

    fn test_reality_listener_with_dest(
        dest_host: &str,
        dest_port: u16,
        mimic: VlessRealityMimicSpec,
    ) -> Arc<VlessListener> {
        let spec = VlessListenerSpec {
            users: vec![VlessUserSpec {
                username: "alice".into(),
                uuid: [0x11; 16],
            }],
            security: VlessSecuritySpec::Reality(VlessRealitySpec {
                dest_host: dest_host.into(),
                dest_port,
                private_key: [0x42; 32],
                short_ids: vec![[0; 8]],
                server_names: vec!["localhost".into()],
                max_time_difference_us: 0,
                limit_fallback_upload: VlessFallbackLimit::default(),
                limit_fallback_download: VlessFallbackLimit::default(),
                mimic,
            }),
            udp: true,
        };
        Arc::new(VlessListener::new(test_tunnel(), "test".into(), spec).unwrap())
    }

    fn test_reality_listener_with(
        dest_port: u16,
        mimic: VlessRealityMimicSpec,
    ) -> Arc<VlessListener> {
        test_reality_listener_with_dest("127.0.0.1", dest_port, mimic)
    }

    fn test_reality_listener() -> Arc<VlessListener> {
        test_reality_listener_with(9, VlessRealityMimicSpec::off())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connection_task_future_does_not_embed_cover_scratch() {
        let listener = test_reality_listener();
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let probe_addr = probe.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(probe_addr).await.unwrap();
        let (server, peer) = probe.accept().await.unwrap();
        drop(client);
        let fut = listener.handle_conn(
            server,
            peer,
            443,
            None,
            tokio::time::Instant::now() + DEFAULT_HANDSHAKE_TIMEOUT,
        );
        let size = std::mem::size_of_val(&fut);
        eprintln!("handle_conn future size: {size}");
        drop(fut);
        // The cover relay's two 16 KiB direction scratches must not be
        // embedded in every connection task: boxed behind the cover
        // branch, the future stays small even though the relay itself
        // needs them when a cover actually runs.
        // Measured on the pinned toolchain: 25 KiB with the cover relay
        // boxed (the Vision codec's own state dominates), 68 KiB with the
        // two 16 KiB cover direction scratches embedded.
        assert!(
            size < 32 * 1024,
            "connection future embeds the cover relay scratch: {size} bytes"
        );
    }

    static HOST_RESOLVER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct InstalledHostResolver;

    impl Drop for InstalledHostResolver {
        fn drop(&mut self) {
            meow_common::clear_host_resolver();
        }
    }

    fn install_host_resolver_for_test(
        resolver: Arc<dyn meow_common::HostResolver>,
    ) -> InstalledHostResolver {
        meow_common::set_host_resolver(resolver);
        InstalledHostResolver
    }

    async fn system_resolve_all_for_test(host: &str) -> std::io::Result<Vec<IpAddr>> {
        // The hook is process-global while a test holds it; unrelated parallel
        // lookups keep their system-resolver behavior.
        let ips: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
            .await?
            .map(|addr| addr.ip())
            .collect();
        if ips.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "system resolver returned no addresses",
            ));
        }
        Ok(ips)
    }

    struct LoopbackAliasResolver;

    #[async_trait::async_trait]
    impl meow_common::HostResolver for LoopbackAliasResolver {
        async fn resolve(&self, host: &str) -> std::io::Result<IpAddr> {
            self.resolve_all(host).await.map(|ips| ips[0])
        }

        async fn resolve_all(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            if host.eq_ignore_ascii_case("cover-loopback-alias.invalid") {
                return Ok(vec![IpAddr::from([127, 0, 0, 2])]);
            }
            system_resolve_all_for_test(host).await
        }
    }

    struct ScriptedCoverResolver {
        answers: Vec<(String, Vec<IpAddr>)>,
    }

    #[async_trait::async_trait]
    impl meow_common::HostResolver for ScriptedCoverResolver {
        async fn resolve(&self, host: &str) -> std::io::Result<IpAddr> {
            self.resolve_all(host).await.map(|ips| ips[0])
        }

        async fn resolve_all(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            if let Some((_, ips)) = self
                .answers
                .iter()
                .find(|(answer_host, _)| answer_host.eq_ignore_ascii_case(host))
            {
                return Ok(ips.clone());
            }
            system_resolve_all_for_test(host).await
        }
    }

    struct PendingHostResolver {
        started: AtomicUsize,
        started_notify: tokio::sync::Notify,
        release: tokio::sync::watch::Receiver<bool>,
    }

    #[async_trait::async_trait]
    impl meow_common::HostResolver for PendingHostResolver {
        async fn resolve(&self, host: &str) -> std::io::Result<IpAddr> {
            self.resolve_all(host).await.map(|ips| ips[0])
        }

        async fn resolve_all(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.started.fetch_add(1, Ordering::Relaxed);
            self.started_notify.notify_one();
            let mut release = self.release.clone();
            while !*release.borrow() {
                release.changed().await.map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::Interrupted, "resolver release closed")
                })?;
            }
            Ok(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)])
        }
    }

    /// T3 residue: cancellation while the target hostname is still inside a
    /// controllable pending resolver must drop the whole dial future.  When
    /// the resolver later completes there is no continuation that can start
    /// TCP connect, so no target socket appears and the H permit is released.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reality_dial_first_resolver_cancellation_never_connects_after_completion() {
        let _host_resolver_lock = HOST_RESOLVER_TEST_LOCK.lock().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let target_accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn({
            let target_accepts = Arc::clone(&target_accepts);
            async move {
                while let Ok((_stream, _)) = target.accept().await {
                    target_accepts.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        let spec = VlessListenerSpec {
            users: vec![VlessUserSpec {
                username: "alice".into(),
                uuid: [0x11; 16],
            }],
            security: VlessSecuritySpec::Reality(VlessRealitySpec {
                dest_host: "pending-resolver.invalid".into(),
                dest_port: target_port,
                private_key: [0x42; 32],
                short_ids: vec![[0; 8]],
                server_names: vec!["localhost".into()],
                max_time_difference_us: 0,
                limit_fallback_upload: VlessFallbackLimit::default(),
                limit_fallback_download: VlessFallbackLimit::default(),
                mimic: VlessRealityMimicSpec::default(),
            }),
            udp: true,
        };
        let listener =
            Arc::new(VlessListener::new(test_tunnel(), "resolver-cancel".into(), spec).unwrap());
        let SecurityRuntime::Reality(reality) = &listener.security else {
            panic!("test listener must be REALITY");
        };
        let permit = Arc::clone(&reality.handshake_slots)
            .try_acquire_owned()
            .unwrap();

        let (release_tx, release_rx) = tokio::sync::watch::channel(false);
        let resolver = Arc::new(PendingHostResolver {
            started: AtomicUsize::new(0),
            started_notify: tokio::sync::Notify::new(),
            release: release_rx,
        });
        let host_resolver: Arc<dyn meow_common::HostResolver> =
            Arc::<PendingHostResolver>::clone(&resolver);
        let _host_resolver_guard = install_host_resolver_for_test(host_resolver);

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let probe_addr = probe.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(probe_addr).await.unwrap();
        let (server, peer) = probe.accept().await.unwrap();
        let task_listener = Arc::clone(&listener);
        let task = tokio::spawn(async move {
            task_listener
                .handle_conn(
                    server,
                    peer,
                    443,
                    Some(permit),
                    tokio::time::Instant::now() + DEFAULT_HANDSHAKE_TIMEOUT,
                )
                .await;
        });
        tokio::time::timeout(Duration::from_secs(2), resolver.started_notify.notified())
            .await
            .expect("dial-first resolver did not start");
        assert_eq!(resolver.started.load(Ordering::Relaxed), 1);

        task.abort();
        let _ = task.await;
        release_tx.send(true).expect("release pending resolver");
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        drop(_host_resolver_guard);
        drop(client);

        let mut snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        for _ in 0..50 {
            if snapshot.close_total.values().sum::<usize>() != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
            snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        }
        assert_eq!(
            snapshot.tcp_connect_started_total, 0,
            "late resolver completion restarted TCP connect"
        );
        assert_eq!(
            target_accepts.load(Ordering::Relaxed),
            0,
            "late resolver completion produced a target socket"
        );
        assert_eq!(
            snapshot.active_handshakes, 0,
            "cancelled resolver dial retained H"
        );
        assert_eq!(
            snapshot.close_total.get(&("read_and_dial", "canceled")),
            Some(&1),
            "unexpected close classification: {:?}",
            snapshot.close_total
        );
        eprintln!("resolver-cancellation evidence: pending-resolver started=1 aborted-before-completion tcp-connect=0 target-accepts=0 H=0 close=read_and_dial/canceled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dial_first_loopback_alias_resolution_is_refused_before_recursive_connect() {
        let _host_resolver_lock = HOST_RESOLVER_TEST_LOCK.lock().await;
        let _host_resolver_guard = install_host_resolver_for_test(Arc::new(LoopbackAliasResolver));

        let socket = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let listener = test_reality_listener_with_dest(
            "cover-loopback-alias.invalid",
            port,
            VlessRealityMimicSpec::default(),
        );
        let task_listener = Arc::clone(&listener);
        let task = tokio::spawn(async move {
            let _ = task_listener.run_on(socket).await;
        });

        // Dial-first starts the cover dial before any ClientHello byte.  The
        // injected resolver answers the fixed target with a 127/8 alias that
        // interface enumeration does not list; the guard must classify that
        // resolution failure shape as Resolve before TCP connect starts.
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let closed = matches!(
            tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(
            closed,
            "loopback-alias cover resolution must close the admitting client"
        );

        let snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        assert_eq!(
            snapshot.close_total.get(&("read_and_dial", "resolve")),
            Some(&1),
            "loopback-alias candidate must be refused as resolution failure: {snapshot:?}"
        );
        assert_eq!(snapshot.tcp_connect_started_total, 0);
        // Every recursively accepted connection would start another target
        // dial. Exactly one dial total is therefore the accept-chain bound.
        assert_eq!(snapshot.dial_started_total, 1);
        assert_eq!(snapshot.active_handshakes, 0);
        task.abort();
        let _ = task.await;
    }

    async fn assert_unspecified_resolution_is_refused(host: &str) {
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let listener =
            test_reality_listener_with_dest(host, port, VlessRealityMimicSpec::default());
        let task_listener = Arc::clone(&listener);
        let task = tokio::spawn(async move {
            let _ = task_listener.run_on(socket).await;
        });

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let closed = matches!(
            tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(
            closed,
            "{host} cover resolution must close the admitting client"
        );

        let snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        assert_eq!(
            snapshot.close_total.get(&("read_and_dial", "resolve")),
            Some(&1),
            "{host} unspecified candidate must be refused as resolution failure: {snapshot:?}"
        );
        assert_eq!(
            snapshot.tcp_connect_started_total, 0,
            "{host} unspecified candidate started TCP connect"
        );
        assert_eq!(
            snapshot.dial_started_total, 1,
            "{host} recursive accepts would start additional cover dials"
        );
        assert_eq!(snapshot.active_handshakes, 0);
        task.abort();
        let _ = task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dial_first_unspecified_resolution_is_refused_before_recursive_connect() {
        let _host_resolver_lock = HOST_RESOLVER_TEST_LOCK.lock().await;
        let _host_resolver_guard =
            install_host_resolver_for_test(Arc::new(ScriptedCoverResolver {
                answers: vec![
                    (
                        "cover-unspecified-v4.invalid".into(),
                        vec![IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)],
                    ),
                    (
                        "cover-unspecified-v6.invalid".into(),
                        vec![IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)],
                    ),
                    (
                        "cover-unspecified-mapped-v4.invalid".into(),
                        vec!["::ffff:0.0.0.0".parse::<IpAddr>().unwrap()],
                    ),
                ],
            }));

        for host in [
            "cover-unspecified-v4.invalid",
            "cover-unspecified-v6.invalid",
            "cover-unspecified-mapped-v4.invalid",
        ] {
            assert_unspecified_resolution_is_refused(host).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dial_first_mixed_resolution_skips_unspecified_and_dials_legal_candidate() {
        let _host_resolver_lock = HOST_RESOLVER_TEST_LOCK.lock().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let _host_resolver_guard =
            install_host_resolver_for_test(Arc::new(ScriptedCoverResolver {
                answers: vec![(
                    "cover-mixed-unspecified.invalid".into(),
                    vec![
                        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    ],
                )],
            }));
        let listener = test_reality_listener_with_dest(
            "cover-mixed-unspecified.invalid",
            target_port,
            VlessRealityMimicSpec::default(),
        );
        let SecurityRuntime::Reality(reality) = &listener.security else {
            panic!("test listener must be REALITY");
        };

        let dialed = listener
            .dial_first_target(reality)
            .await
            .expect("mixed resolution must retain the legal loopback candidate");
        assert_eq!(
            dialed.stream.peer_addr().unwrap().ip(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        let (_, peer) = tokio::time::timeout(Duration::from_secs(2), target.accept())
            .await
            .expect("legal candidate did not reach the target listener")
            .unwrap();
        assert_eq!(peer.ip(), IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        assert_eq!(snapshot.dial_started_total, 1);
        assert_eq!(snapshot.tcp_connect_started_total, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cover_dial_unspecified_resolution_has_no_dialable_candidate() {
        let _host_resolver_lock = HOST_RESOLVER_TEST_LOCK.lock().await;
        // The listener is dialable through loopback when unspecified is not
        // filtered, so an Ok here would prove the v1 cover path dialed it.
        let loopback_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = loopback_target.local_addr().unwrap().port();
        let _host_resolver_guard =
            install_host_resolver_for_test(Arc::new(ScriptedCoverResolver {
                answers: vec![(
                    "cover-only-unspecified.invalid".into(),
                    vec![
                        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    ],
                )],
            }));
        let listener = test_reality_listener_with_dest(
            "cover-only-unspecified.invalid",
            target_port,
            VlessRealityMimicSpec::off(),
        );
        let SecurityRuntime::Reality(reality) = &listener.security else {
            panic!("test listener must be REALITY");
        };

        let Err(err) = listener.dial_cover_target(reality).await else {
            panic!("unspecified-only resolution produced a cover target")
        };
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn cover_candidate_filter_drops_every_unspecified_spelling() {
        let legal_v4 = "192.0.2.10:443".parse::<SocketAddr>().unwrap();
        let legal_v6 = "[2001:db8::10]:443".parse::<SocketAddr>().unwrap();
        let candidates = vec![
            "0.0.0.0:443".parse::<SocketAddr>().unwrap(),
            "[::]:443".parse::<SocketAddr>().unwrap(),
            "[::ffff:0.0.0.0]:443".parse::<SocketAddr>().unwrap(),
            legal_v4,
            legal_v6,
        ];

        let retained: Vec<_> = dialable_cover_candidates(candidates).collect();
        assert_eq!(retained, vec![legal_v4, legal_v6]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reality_classification_admission_refuses_overflow_sockets() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = target.accept().await {
                held.push(stream);
            }
        });
        let listener = test_reality_listener_with(target_port, VlessRealityMimicSpec::default());
        // Saturate the classification slots externally: the permits are
        // the same semaphores the accept loop draws from, so every new
        // socket arriving now is by definition overflow.
        let SecurityRuntime::Reality(reality) = &listener.security else {
            panic!("test listener must be REALITY");
        };
        let mut held = Vec::new();
        for _ in 0..REALITY_HANDSHAKE_SLOTS {
            held.push(
                Arc::clone(&reality.handshake_slots)
                    .try_acquire_owned()
                    .unwrap(),
            );
        }
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task_listener = Arc::clone(&listener);
        let task = tokio::spawn(async move {
            let _ = task_listener.run_on(socket).await;
        });

        // Overflow at admission: the socket is refused rather than
        // spawning a task that parks holding it behind the semaphore.
        let mut overflowed = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let closed = matches!(
            tokio::time::timeout(Duration::from_secs(2), overflowed.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(
            closed,
            "overflow REALITY socket was parked behind the classification semaphore instead of refused"
        );
        let snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        assert_eq!(
            snapshot
                .close_total
                .get(&("admission", "handshake_saturated")),
            Some(&1)
        );

        // Freeing one slot admits the next socket: it stays open, parked
        // inside the handshake exactly like a silent classified peer.
        drop(held.pop());
        let mut admitted = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let open = tokio::time::timeout(Duration::from_millis(500), admitted.read(&mut byte))
            .await
            .is_err();
        assert!(open, "admitted REALITY socket must stay open");
        drop(admitted);
        task.abort();
        let _ = task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn off_mode_admission_saturation_does_not_count_v2_metrics() {
        let listener = test_reality_listener();
        let SecurityRuntime::Reality(reality) = &listener.security else {
            panic!("test listener must be REALITY");
        };
        let held: Vec<_> = (0..REALITY_HANDSHAKE_SLOTS)
            .map(|_| {
                Arc::clone(&reality.handshake_slots)
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect();
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task_listener = Arc::clone(&listener);
        let task = tokio::spawn(async move {
            let _ = task_listener.run_on(socket).await;
        });
        let mut overflowed = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let rejected = matches!(
            tokio::time::timeout(Duration::from_secs(2), overflowed.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(
            rejected,
            "off-mode overflow socket must be refused, not parked"
        );
        let snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        assert_eq!(
            snapshot
                .close_total
                .get(&("admission", "handshake_saturated")),
            None,
            "off mode admission rejection is v1 behavior, not v2 accounting"
        );
        drop(held);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn dial_first_run_on_deadline_counts_spawn_to_first_poll_delay() {
        let listener = test_reality_listener_with(9, VlessRealityMimicSpec::default());
        ADVANCE_AFTER_CONNECTION_SPAWN.with(|cell| {
            *cell.borrow_mut() = Some(DEFAULT_HANDSHAKE_TIMEOUT + Duration::from_millis(1));
        });
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task_listener = Arc::clone(&listener);
        let task = tokio::spawn(async move {
            let _ = task_listener.run_on(socket).await;
        });
        let _client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();

        let mut snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        for _ in 0..20 {
            if snapshot.close_total.get(&("read_and_dial", "deadline")) == Some(&1) {
                break;
            }
            tokio::task::yield_now().await;
            snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        }
        assert_eq!(
            snapshot.close_total.get(&("read_and_dial", "deadline")),
            Some(&1),
            "run_on admission deadline must include spawn-to-first-poll delay: {snapshot:?}"
        );
        assert_eq!(snapshot.tcp_connect_started_total, 0);
        assert_eq!(CONNECTION_SPAWN_HOOKS.with(std::cell::Cell::get), 1);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn dial_first_handshake_deadline_counts_executor_scheduling_delay() {
        let listener = test_reality_listener_with(9, VlessRealityMimicSpec::default());
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let probe_addr = probe.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(probe_addr).await.unwrap();
        let (server, peer) = probe.accept().await.unwrap();
        drop(client);
        let deadline = tokio::time::Instant::now() + DEFAULT_HANDSHAKE_TIMEOUT;
        let fut = listener.handle_conn(server, peer, 443, None, deadline);

        // The future exists but is never polled while the executor is
        // congested.  Advancing the full 15 seconds before that first poll
        // must expire d_hs because the deadline was fixed at admission.
        tokio::time::advance(DEFAULT_HANDSHAKE_TIMEOUT).await;
        fut.await;
        let snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        assert_eq!(
            snapshot.close_total.get(&("read_and_dial", "deadline")),
            Some(&1),
            "scheduling delay consumes d_hs: {snapshot:?}"
        );
        assert_eq!(snapshot.tcp_connect_started_total, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dial_first_cover_saturation_closes_without_cover_or_probe_counters() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let target_accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let target_accepts_task = Arc::clone(&target_accepts);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = target.accept().await {
                target_accepts_task.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                held.push(stream);
            }
        });
        let listener = test_reality_listener_with(target_port, VlessRealityMimicSpec::default());
        let SecurityRuntime::Reality(reality) = &listener.security else {
            panic!("test listener must be REALITY");
        };
        let mut held_permits = Vec::new();
        for _ in 0..REALITY_COVER_SLOTS {
            held_permits.push(
                Arc::clone(&reality.cover_slots)
                    .try_acquire_owned()
                    .unwrap(),
            );
        }
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task_listener = Arc::clone(&listener);
        let task = tokio::spawn(async move {
            let _ = task_listener.run_on(socket).await;
        });

        let tls = meow_transport::tls::TlsConfig {
            skip_cert_verify: true,
            ..meow_transport::tls::TlsConfig::new("localhost")
        };
        let layer = meow_transport::tls::TlsLayer::new(&tls).unwrap();
        let raw: Box<dyn Stream> = Box::new(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap(),
        );
        let _ = tokio::time::timeout(Duration::from_secs(2), layer.connect(raw)).await;
        let mut snapshot = listener.reality_v2_metrics_snapshot().unwrap();
        for _ in 0..100 {
            snapshot = listener.reality_v2_metrics_snapshot().unwrap();
            if snapshot.close_total.get(&("cover", "cover_saturated")) == Some(&1) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            snapshot.close_total.get(&("cover", "cover_saturated")),
            Some(&1),
            "C saturation is the only terminal counter: {snapshot:?}"
        );
        assert_eq!(snapshot.cover_total.values().sum::<usize>(), 0);
        assert_eq!(snapshot.probe_started_total, 0);
        assert_eq!(snapshot.committed_total, 0);
        assert_eq!(snapshot.mimic_hit_total, 0);
        assert_eq!(snapshot.close_total.values().sum::<usize>(), 1);
        assert_eq!(snapshot.active_handshakes, 0);
        assert_eq!(snapshot.active_probes, 0);
        assert_eq!(
            target_accepts.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "C saturation must close on the single already-started target connection"
        );
        drop(held_permits);
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn endpoint_registration_follows_the_listen_socket_lifetime() {
        let listener = test_reality_listener();
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = canonical_endpoint(socket.local_addr().unwrap());
        let task_listener = Arc::clone(&listener);
        let task = tokio::spawn(async move {
            let _ = task_listener.run_on(socket).await;
        });
        for _ in 0..100 {
            if listener
                .bound_endpoints
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&addr)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(listener
            .bound_endpoints
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&addr));
        task.abort();
        let _ = task.await;
        for _ in 0..100 {
            if !listener
                .bound_endpoints
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&addr)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("endpoint outlived its listen socket");
    }

    #[test]
    fn self_loop_guard_wildcard_covers_unenumerated_loopback_aliases() {
        let local = HashSet::from([
            "192.0.2.10".parse::<IpAddr>().unwrap(),
            "::1".parse::<IpAddr>().unwrap(),
        ]);
        let mut endpoints = EndpointSnapshot::new();
        endpoints.insert(
            "0.0.0.0:443".parse::<SocketAddr>().unwrap(),
            BoundEndpointCoverage::CONSERVATIVE,
        );

        for alias in ["127.0.0.2", "127.255.0.1"] {
            assert!(
                endpoint_is_self(
                    SocketAddr::new(alias.parse::<IpAddr>().unwrap(), 443),
                    &endpoints,
                    Some(&local),
                ),
                "{alias} is a 127/8 loopback alias even when unenumerated"
            );
        }
        assert!(
            endpoint_is_self(
                "[::ffff:127.0.0.2]:443".parse().unwrap(),
                &endpoints,
                Some(&local),
            ),
            "canonicalization folds the v4-mapped loopback alias before matching"
        );
        assert!(
            !endpoint_is_self("[::1]:443".parse().unwrap(), &endpoints, Some(&local),),
            "a v4 wildcard cannot be reached through IPv6 loopback"
        );

        endpoints.clear();
        endpoints.insert(
            "[::]:443".parse::<SocketAddr>().unwrap(),
            BoundEndpointCoverage {
                v6_wildcard_accepts_v4: true,
            },
        );
        assert!(endpoint_is_self(
            "[::1]:443".parse().unwrap(),
            &endpoints,
            Some(&local),
        ));
        assert!(
            endpoint_is_self("127.0.0.2:443".parse().unwrap(), &endpoints, Some(&local),),
            "a dual-stack v6 wildcard accepts v4 peers as mapped"
        );
        assert!(
            endpoint_is_self("0.0.0.0:443".parse().unwrap(), &endpoints, Some(&local),),
            "a dual-stack v6 wildcard accepts v4 unspecified as mapped"
        );
        assert!(
            endpoint_is_self("[::]:443".parse().unwrap(), &endpoints, Some(&local),),
            "v6 unspecified is the v6 wildcard itself regardless of v4 coverage"
        );

        endpoints.clear();
        endpoints.insert(
            "[::]:443".parse::<SocketAddr>().unwrap(),
            BoundEndpointCoverage {
                v6_wildcard_accepts_v4: false,
            },
        );
        assert!(endpoint_is_self(
            "[::1]:443".parse().unwrap(),
            &endpoints,
            Some(&local),
        ));
        assert!(
            !endpoint_is_self("127.0.0.2:443".parse().unwrap(), &endpoints, Some(&local),),
            "a v6-only wildcard cannot be reached through v4 loopback"
        );
        assert!(
            !endpoint_is_self("0.0.0.0:443".parse().unwrap(), &endpoints, Some(&local),),
            "a v6-only wildcard cannot be reached through v4 unspecified"
        );
        assert!(
            endpoint_is_self("[::]:443".parse().unwrap(), &endpoints, Some(&local),),
            "v6 unspecified remains the exact v6 wildcard on a v6-only socket"
        );

        endpoints.clear();
        endpoints.insert(
            "[::1]:443".parse::<SocketAddr>().unwrap(),
            BoundEndpointCoverage::CONSERVATIVE,
        );
        assert!(endpoint_is_self(
            "[::1]:443".parse().unwrap(),
            &endpoints,
            Some(&local),
        ));
        assert!(
            !endpoint_is_self("127.0.0.2:443".parse().unwrap(), &endpoints, Some(&local),),
            "a specific v6 loopback bind has no v4 loopback pair"
        );
    }

    #[test]
    fn self_loop_guard_unspecified_candidates_follow_loopback_dial_semantics() {
        let local = HashSet::new();
        let mut endpoints = EndpointSnapshot::new();
        endpoints.insert(
            "127.0.0.1:443".parse::<SocketAddr>().unwrap(),
            BoundEndpointCoverage::CONSERVATIVE,
        );
        assert!(
            endpoint_is_self("0.0.0.0:443".parse().unwrap(), &endpoints, Some(&local),),
            "v4 unspecified reaches a same-port v4 loopback bind where the stack accepts it"
        );
        assert!(
            endpoint_is_self(
                "[::ffff:0.0.0.0]:443".parse().unwrap(),
                &endpoints,
                Some(&local),
            ),
            "canonicalization folds v4-mapped unspecified before the family check"
        );
        assert!(
            !endpoint_is_self("[::]:443".parse().unwrap(), &endpoints, Some(&local),),
            "v6 unspecified cannot reach a v4 loopback bind"
        );

        endpoints.clear();
        endpoints.insert(
            "[::1]:443".parse::<SocketAddr>().unwrap(),
            BoundEndpointCoverage::CONSERVATIVE,
        );
        assert!(
            endpoint_is_self("[::]:443".parse().unwrap(), &endpoints, Some(&local),),
            "v6 unspecified reaches a same-port v6 loopback bind where the stack accepts it"
        );
        assert!(
            !endpoint_is_self("0.0.0.0:443".parse().unwrap(), &endpoints, Some(&local),),
            "v4 unspecified cannot reach a v6 loopback bind"
        );

        endpoints.clear();
        endpoints.insert(
            "192.0.2.10:443".parse::<SocketAddr>().unwrap(),
            BoundEndpointCoverage::CONSERVATIVE,
        );
        assert!(
            !endpoint_is_self("0.0.0.0:443".parse().unwrap(), &endpoints, Some(&local),),
            "unspecified dial semantics select loopback, not a non-loopback bind"
        );
    }

    #[test]
    fn self_loop_guard_matches_exact_loopback_and_wildcard_local_addresses() {
        let mut endpoints = EndpointSnapshot::new();
        endpoints.insert(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8443),
            BoundEndpointCoverage::CONSERVATIVE,
        );
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
        endpoints.insert(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 443),
            BoundEndpointCoverage::CONSERVATIVE,
        );
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
