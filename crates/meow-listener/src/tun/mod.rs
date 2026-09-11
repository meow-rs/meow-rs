//! TUN inbound — transparent proxying via an L3 device (issue #326).
//!
//! This is the transparent-proxy path for platforms without a
//! tproxy/REDIRECT firewall — Windows first and foremost — and works the
//! same on Linux and macOS. A `tun-rs` device receives raw IP packets; the
//! lwIP userspace TCP/IP stack ([`lwip`](https://github.com/madeye/lwip))
//! terminates them and hands us ordinary `AsyncRead + AsyncWrite` streams
//! (TCP) and a packet-level UDP socket, which are dispatched into the
//! tunnel exactly like every other inbound.
//!
//! lwIP's accept hook runs only after the TCP handshake, so a SYN-only
//! packet never becomes a `TcpStream`. PCB / window / heap caps live in
//! that crate's `lwipopts.h` (`MEMP_NUM_TCP_PCB`, `TCP_WND`, `MEM_SIZE`).
//! We still wait for the first payload byte before rule-match / stats /
//! DIRECT — empty ESTABLISHED sockets (Office reconnects) never enter
//! `handle_tcp`.
//!
//! ## Loop freedom (v1: fake-IP-scoped capture)
//!
//! The classic TUN failure mode is the routing loop: a global default route
//! into the device makes meow's *own* outbound dials re-enter the tun. v1
//! avoids the whole problem class by capturing only the fake-IP range:
//!
//! 1. The OS resolver is pointed at an address inside the routed range, so
//!    DNS queries enter the tun and `dns-hijack` answers them with fake IPs.
//! 2. Client connections to those fake IPs route into the tun; the fake-IP
//!    rewrite recovers the hostname and rules match on domain.
//! 3. Outbound dials — proxy upstreams *and* DIRECT — go to real IPs, which
//!    are never inside the fake range, so they take the physical route and
//!    cannot loop. No SO_MARK, interface binding, or bypass routes needed.
//!
//! The trade-off: IP-literal traffic (no DNS lookup) is not captured.
//!
//! ## Global route scope (#375, experimental, Linux-only)
//!
//! [`TunRouteScope::Global`] opts into capturing everything: `auto-route`
//! installs split default routes (`0.0.0.0/1` + `128.0.0.0/1`), and loop
//! freedom moves from route scoping to the outbound path — every socket
//! meow creates is bound to the physical interface
//! (`meow_common::set_outbound_interface`, `SO_BINDTODEVICE`) before
//! connect/bind, and hostname dials resolve through meow's own resolver
//! hook. Startup fails closed if the binding cannot be installed.
//!
//! On Windows the device is a Wintun adapter. `wintun.dll` is resolved next
//! to the executable (official Windows zips ship it there), then the working
//! directory; if neither exists the official signed DLL embedded in the
//! binary is written out. The process must run elevated. On Linux/macOS
//! creating the device requires root (CAP_NET_ADMIN).

mod device;
mod dns;
#[cfg(target_os = "windows")]
mod local_dns;
mod route;
mod udp;
#[cfg(any(test, target_os = "windows"))]
mod wintun;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::StreamExt;
use ipnet::Ipv4Net;
use meow_common::{ConnType, Metadata, Network, ProxyConn};
use meow_tunnel::Tunnel;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// How long a TUN TCP socket may sit after the handshake with no payload
/// before we drop it. SYN scans and half-open reconnects never become
/// meow connections.
const TUN_PAYLOAD_WAIT: Duration = crate::DEFAULT_HANDSHAKE_TIMEOUT;
/// First-read size when waiting for real traffic. Large enough to pull a
/// TLS ClientHello record header + a bit of payload in one shot.
const TUN_FIRST_READ: usize = 256;

use route::RouteGuard;

/// Process-global serialization point for lwIP generations (issue #514).
/// `NetStack::new` must not run while a previous core is still tearing
/// down — aborted pump tasks are reaped asynchronously, so the core's
/// `core_done` signal is the only reliable barrier. The mutex is held
/// across the (synchronous) stack build so two listeners can never
/// interleave through the gate.
static PREVIOUS_CORE: tokio::sync::Mutex<Option<tokio::sync::watch::Receiver<bool>>> =
    tokio::sync::Mutex::const_new(None);

/// Upper bound on waiting for a previous lwIP core's teardown. Teardown is
/// a synchronous pcb sweep — well under a second — so this only bounds a
/// wedged-core scenario; proceeding past it logs loudly because two live
/// cores risk corrupting lwIP's process-global pcb lists.
const PREVIOUS_CORE_TEARDOWN_WAIT: Duration = Duration::from_secs(10);

/// Tracks all child `JoinHandle`s spawned by a TUN listener. On drop,
/// aborts every tracked task — this guarantees the TUN device and all its
/// resources are fully released even when the parent task is externally
/// aborted. `shutdown()` additionally awaits the owned children so a
/// natural exit leaves nothing still touching the old stack's channels.
struct TaskGroup {
    /// Children this group can join (uniform `()` output): per-flow TCP
    /// handlers, the UDP dispatcher, the Windows local-DNS task.
    owned: Vec<tokio::task::JoinHandle<()>>,
    /// Abort handles for tasks whose `JoinHandle` is awaited elsewhere —
    /// the device↔stack pumps are polled inside `run_inner`'s select loop.
    tracked: Vec<tokio::task::AbortHandle>,
}

impl TaskGroup {
    fn new() -> Self {
        Self {
            owned: Vec::new(),
            tracked: Vec::new(),
        }
    }

    /// Track a `JoinHandle<T>` by recording its `AbortHandle`. Used for
    /// tasks whose join is owned by `run_inner` itself (the pumps).
    fn push<T>(&mut self, h: &tokio::task::JoinHandle<T>) {
        self.tracked.retain(|a| !a.is_finished());
        self.tracked.push(h.abort_handle());
    }

    /// Spawn a future and automatically track its handle. Reaps finished
    /// tasks first so the group does not grow unboundedly with every
    /// accepted TCP flow.
    fn spawn(&mut self, f: impl std::future::Future<Output = ()> + Send + 'static) {
        self.owned.retain(|h| !h.is_finished());
        self.owned.push(tokio::spawn(f));
    }

    /// Abort every tracked child, then await the owned set (issue #514):
    /// `run_inner` returns only when no child can still hold a stack
    /// handle — the lwIP core's `core_done` (which the next generation
    /// gates on) only fires after all those handles are gone.
    async fn shutdown(&mut self) {
        for a in &self.tracked {
            a.abort();
        }
        for h in &self.owned {
            h.abort();
        }
        for h in self.owned.drain(..) {
            let _ = h.await;
        }
        self.tracked.clear();
    }
}

impl Drop for TaskGroup {
    fn drop(&mut self) {
        for a in &self.tracked {
            a.abort();
        }
        for h in &self.owned {
            h.abort();
        }
    }
}

/// Listener-facing subset of the `tun:` config section, mapped from
/// `meow_config::TunConfig` by the app layer (mirrors how the other
/// listeners take plain ctor args rather than depending on meow-config).
#[derive(Debug, Clone)]
pub struct TunListenerConfig {
    /// Device name. `None` lets the platform pick (`utunN` on macOS).
    pub device: Option<String>,
    /// Device MTU. The config layer enforces ≥ 1280 (RFC 8200 §5).
    pub mtu: u16,
    /// Address + prefix assigned to the device.
    pub inet4_address: Ipv4Net,
    /// Install routes on startup (removed on shutdown). What gets routed is
    /// selected by `route_scope`.
    pub auto_route: bool,
    /// Scope of the installed routes (#375).
    pub route_scope: TunRouteScope,
    /// Physical interface outbound sockets bind to in global scope; `None`
    /// = auto-detect from the default route. Ignored in fake-IP scope.
    pub outbound_interface: Option<String>,
    /// Answer UDP :53 flows with the in-process DNS resolver.
    pub dns_hijack: bool,
    /// Idle timeout for UDP flows (flow-table eviction).
    pub udp_timeout: Duration,
    /// Cap on concurrent TUN TCP handler tasks. Inherited from the
    /// top-level `max-connections` key (default 256; `0` = unlimited).
    pub max_connections: usize,
}

/// Which routes `auto_route` installs (#375).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunRouteScope {
    /// v1: route only the fake-IP range — loop-free by construction.
    #[default]
    FakeIp,
    /// Route all IPv4 (split defaults `0.0.0.0/1` + `128.0.0.0/1`) into the
    /// device; outbound sockets bind to the physical interface for loop
    /// avoidance. Experimental, Linux-only.
    Global,
}

/// Outcome of TUN listener startup, sent through the readiness channel.
/// Allows callers to distinguish immediate setup failure from a timeout
/// without waiting for the full `TUN_STARTUP_TIMEOUT`.
pub enum TunReady {
    /// Device + stack + child tasks are fully initialized. The payload is
    /// the lwIP core's done signal — it flips `true` once that generation's
    /// teardown fully completes, which the owner must await before
    /// permitting a successor stack (issue #514).
    Ready(tokio::sync::watch::Receiver<bool>),
    /// Setup failed before reaching the accept loop.  The String carries
    /// the underlying error message so callers can surface it directly.
    Failed(String),
}

/// RAII helper that guarantees the readiness oneshot is always fired.
///
/// If `ready()` is called, the sender sends `TunReady::Ready` and is
/// consumed (no drop-side-effect).  If the notifier is dropped without
/// a prior `ready()` call — e.g. because `run()` hit a `?` and the
/// local variable goes out of scope — the sender fires
/// `TunReady::Failed(...)` so the caller gets an immediate,
/// descriptive error instead of a bare `RecvError`.
struct ReadyNotifier {
    tx: Option<tokio::sync::oneshot::Sender<TunReady>>,
}

impl ReadyNotifier {
    fn new(tx: tokio::sync::oneshot::Sender<TunReady>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Consume the notifier and send `TunReady::Ready` carrying the lwIP
    /// core's done signal.
    fn ready(mut self, core_done: tokio::sync::watch::Receiver<bool>) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(TunReady::Ready(core_done));
        } else {
            tracing::warn!("ReadyNotifier::ready called but tx was already None");
        }
    }

    /// Consume the notifier and send `TunReady::Failed` carrying the real
    /// setup error, so callers surface the underlying cause instead of the
    /// generic drop-time message.
    fn fail(mut self, msg: String) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(TunReady::Failed(msg));
        }
    }
}

impl Drop for ReadyNotifier {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(TunReady::Failed(
                "listener setup failed before reaching readiness".into(),
            ));
        }
    }
}

/// Wraps [`tun_rs::AsyncDevice`] together with its [`RouteGuard`] in a
/// single `Arc` so they share one reference-counted lifetime. Field
/// declaration order guarantees `route_guard` is dropped (routes deleted)
/// **before** `device` (adapter destroyed) when the last `Arc` clone goes
/// away — ensuring route deletion always succeeds because the adapter is
/// still alive.
struct TunDevice {
    /// Held only for its `Drop` side effect — routes are deleted when
    /// this field is dropped, before `device` is destroyed.
    #[allow(dead_code)]
    route_guard: Option<RouteGuard>,
    /// Held only for its `Drop` side effect — clears the process-global
    /// outbound-interface binding installed for global route scope.
    #[allow(dead_code)]
    iface_guard: Option<OutboundIfaceGuard>,
    pub(super) device: tun_rs::AsyncDevice,
}

/// RAII wrapper for `meow_common::set_outbound_interface`: global route
/// scope installs the binding at startup; dropping this (listener teardown /
/// config reload) clears it so later sessions don't inherit a stale
/// interface.
struct OutboundIfaceGuard;

impl Drop for OutboundIfaceGuard {
    fn drop(&mut self) {
        meow_common::clear_outbound_interface();
    }
}

pub struct TunListener {
    tunnel: Tunnel,
    cfg: TunListenerConfig,
    name: String,
    /// Optional readiness signal: sent once after the device, stack, and
    /// child tasks are fully initialized (before the accept loop).
    /// If the listener fails before reaching that point the notifier's
    /// `Drop` impl sends `TunReady::Failed`, giving callers an immediate
    /// error without waiting for a timeout.
    ready: Option<tokio::sync::oneshot::Sender<TunReady>>,
}

impl TunListener {
    pub fn new(tunnel: Tunnel, cfg: TunListenerConfig, name: String) -> Self {
        Self {
            tunnel,
            cfg,
            name,
            ready: None,
        }
    }

    /// Attach a readiness signal. The sender will fire `TunReady::Ready`
    /// after device creation + stack init + child-task setup succeeds,
    /// and before the accept loop starts.  If `run()` fails before
    /// reaching that point the notifier's `Drop` impl sends
    /// `TunReady::Failed(msg)`, giving callers an immediate error without
    /// waiting for a timeout.
    pub fn with_readiness_signal(mut self, tx: tokio::sync::oneshot::Sender<TunReady>) -> Self {
        self.ready = Some(tx);
        self
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Extract the readiness sender into a notifier so setup failures
        // reach the caller immediately: an `Err` from `run_inner` sends
        // `TunReady::Failed` with the real error message, and if the future
        // is dropped mid-setup the notifier's `Drop` impl sends a generic
        // failure — either way no timeout wait.
        let mut notifier = self.ready.take().map(ReadyNotifier::new);
        let result = self.run_inner(&mut notifier).await;
        if let Err(e) = &result {
            if let Some(n) = notifier.take() {
                n.fail(e.to_string());
            }
        }
        result
    }

    async fn run_inner(
        &self,
        notifier: &mut Option<ReadyNotifier>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let t0 = Instant::now();
        info!("TUN listener '{}' starting...", self.name);

        let cfg = &self.cfg;

        // Windows: sidecar wintun.dll next to the exe / in cwd, else extract
        // the official DLL embedded in this binary. Fail before the retry
        // loop so a missing library is not a generic device-create error.
        #[cfg(target_os = "windows")]
        let wintun_file = {
            let path = wintun::resolve_wintun_dll()?;
            info!("using Wintun library {}", path.display());
            path.to_string_lossy().into_owned()
        };

        // Try up to 5 device names and IPs in case the previous instance
        // left a stale adapter that hasn't been cleaned up yet (common on
        // Windows after an unclean shutdown).  After the first retry fails,
        // we also rotate the TUN IP to work around address conflicts.
        //
        // Each attempt runs on a blocking thread; the outer caller's
        // TUN_STARTUP_TIMEOUT guards the overall time spent here.
        const MAX_TUN_RETRIES: u32 = 5;
        let base_addr = cfg.inet4_address.addr();
        let prefix = cfg.inet4_address.prefix_len();
        let mut device: Option<tun_rs::AsyncDevice> = None;
        let mut dev_name = String::new();
        let mut used_addr = base_addr;
        let mut last_err: Option<String>;

        for attempt in 0..MAX_TUN_RETRIES {
            let name = device_name_for_attempt(cfg.device.as_deref(), attempt);

            // Rotate IP after the first retry fails (attempt >= 2).
            // Each /30 subnet spans 4 addresses, so we step by 4.
            let addr = if attempt >= 2 {
                let offset = (attempt - 1) * 4;
                std::net::Ipv4Addr::from(u32::from(base_addr).wrapping_add(offset))
            } else {
                base_addr
            };
            let ip_display = format!("{addr}/{prefix}");

            // Copy the values we need inside `spawn_blocking` so we don't
            // borrow `cfg` across the closure boundary.
            let mtu = cfg.mtu;
            let name_for_closure = name.clone();
            #[cfg(target_os = "windows")]
            let wintun_file = wintun_file.clone();

            let display_name = name.as_deref().unwrap_or("<platform default>");
            info!(
                "creating TUN device '{}' with {} (attempt {}/{})...",
                display_name,
                ip_display,
                attempt + 1,
                MAX_TUN_RETRIES,
            );

            match tokio::task::spawn_blocking(move || {
                let mut builder = tun_rs::DeviceBuilder::new()
                    .mtu(mtu)
                    .ipv4(addr, prefix, None);
                if let Some(n) = &name_for_closure {
                    builder = builder.name(n);
                }
                // Pin the Wintun DLL we resolved above so tun-rs does not
                // walk the process DLL search path.
                #[cfg(target_os = "windows")]
                {
                    builder = builder.wintun_file(wintun_file).wintun_log(true);
                }
                builder.build_async()
            })
            .await
            {
                Ok(Ok(d)) => {
                    dev_name = d
                        .name()
                        .unwrap_or_else(|_| name.clone().unwrap_or_default());
                    used_addr = addr;
                    device = Some(d);
                    break;
                }
                Ok(Err(e)) => {
                    warn!("failed to create TUN device '{}': {e}", display_name);
                    last_err = Some(e.to_string());
                }
                Err(join_err) => {
                    warn!(
                        "spawn_blocking for TUN device '{}' panicked: {join_err}",
                        display_name
                    );
                    last_err = Some(join_err.to_string());
                }
            }

            if attempt + 1 >= MAX_TUN_RETRIES {
                let detail = last_err.map(|e| format!(": {e}")).unwrap_or_default();
                return Err(Box::new(io::Error::other(format!(
                    "failed to create TUN device after {MAX_TUN_RETRIES} attempts{detail}"
                ))));
            }
        }
        // SAFETY: the loop either breaks with `device = Some(...)` and
        // `dev_name` set, or returns `Err` above.
        let device = device.unwrap();

        let tun_create_ms = t0.elapsed().as_secs_f64() * 1000.0;
        info!("TUN device '{dev_name}' created in {tun_create_ms:.0}ms");

        // Obtain the interface index before moving `device` into `TunDevice`.
        let if_index = device.if_index()?;

        // Global route scope (#375): before any routes go in, install the
        // outbound-interface binding so meow's own dials cannot loop back
        // into the device. Fail closed — a global default route without
        // working loop avoidance would blackhole the host's connectivity.
        let iface_guard = if cfg.auto_route && cfg.route_scope == TunRouteScope::Global {
            if !cfg!(target_os = "linux") {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "tun auto-route: global is currently Linux-only (tracked on #375); \
                     use auto-route: fake-ip on this platform",
                )));
            }
            let iface = match cfg.outbound_interface.clone() {
                Some(name) => name,
                None => route::default_interface().map_err(|e| {
                    io::Error::other(format!(
                        "tun auto-route: global: could not auto-detect the physical \
                         interface ({e}); set tun.outbound-interface explicitly"
                    ))
                })?,
            };
            meow_common::set_outbound_interface(&iface).map_err(|e| {
                io::Error::other(format!(
                    "tun auto-route: global: outbound interface binding failed ({e}); \
                     refusing to install default routes without loop avoidance"
                ))
            })?;
            info!(
                "tun '{}': global route scope — outbound sockets bound to '{iface}' \
                 (experimental, #375)",
                self.name
            );
            Some(OutboundIfaceGuard)
        } else {
            None
        };

        // auto-route: install the scope's routes (see module docs).
        //
        // RouteManager::add() calls into OS routing APIs that may block
        // (PowerShell on Windows), so it runs on a blocking thread. The
        // outer TUN_STARTUP_TIMEOUT guards the overall startup.
        let route_nets: Option<Vec<ipnet::IpNet>> = if cfg.auto_route {
            match cfg.route_scope {
                // Split defaults: two /1s cover all IPv4 while staying more
                // specific than the physical 0/0 default, so the original
                // route survives untouched and restore-on-drop is trivial.
                // The device's own /30 and the fake-IP range (if any) are
                // inside the /1s already.
                TunRouteScope::Global => Some(vec![
                    "0.0.0.0/1".parse().expect("static CIDR parses"),
                    "128.0.0.0/1".parse().expect("static CIDR parses"),
                ]),
                TunRouteScope::FakeIp => self.tunnel.resolver().fake_ip_v4_net().map(|n| vec![n]),
            }
        } else {
            None
        };

        let route_guard = if cfg.auto_route {
            match route_nets {
                Some(nets) => {
                    let t_route = Instant::now();

                    let result =
                        tokio::task::spawn_blocking(move || RouteGuard::setup(if_index, &nets))
                            .await;

                    match result {
                        Ok(Ok(g)) => {
                            let route_ms = t_route.elapsed().as_secs_f64() * 1000.0;
                            info!("auto-route installed in {route_ms:.0}ms");
                            Some(g)
                        }
                        Ok(Err(e)) => {
                            return Err(Box::new(io::Error::other(format!(
                                "failed to install auto-route: {e}"
                            ))));
                        }
                        Err(join_err) => {
                            return Err(Box::new(io::Error::other(format!(
                                "auto-route spawn_blocking panicked: {join_err}"
                            ))));
                        }
                    }
                }
                None => {
                    warn!(
                        "tun '{}': auto-route currently only routes the fake-IP range, but \
                         DNS is not in fake-ip mode — no routes installed. Add routes to \
                         '{dev_name}' manually (and make sure outbound traffic cannot loop \
                         back into the device).",
                        self.name
                    );
                    None
                }
            }
        } else {
            None
        };

        // Wrap the device and its route guard in a single `Arc` so they share
        // one reference-counted lifetime. Field order guarantees `route_guard`
        // is dropped (routes deleted) **before** `device` (adapter destroyed)
        // when the last `Arc` clone goes away — ensuring route deletion always
        // succeeds because the adapter is still alive.
        let device = Arc::new(TunDevice {
            route_guard,
            iface_guard,
            device,
        });

        // Windows: bind the loopback DNS sockets *before* DnsGuard repoints
        // the OS resolver at them. If port 53 is already taken (ICS, Docker,
        // another resolver), this fails startup loudly instead of silently
        // leaving the whole machine with DNS aimed at a dead address.
        #[cfg(target_os = "windows")]
        let local_dns_sockets = if cfg.dns_hijack
            && cfg.auto_route
            && self.tunnel.resolver().fake_ip_v4_gateway().is_some()
        {
            Some(local_dns::bind().await.map_err(|e| {
                io::Error::other(format!("loopback DNS server startup failed: {e}"))
            })?)
        } else {
            None
        };

        // When dns-hijack is on and we're in fake-IP mode, point the OS
        // resolver at the loopback DNS server.  The backup + set calls into
        // PowerShell (Get-DnsClientServerAddress / Set-DnsClientServerAddress)
        // which can take tens of seconds on Windows, so run them on a
        // blocking thread. The outer TUN_STARTUP_TIMEOUT guards the overall
        // startup.
        let _dns_guard = if cfg.dns_hijack && cfg.auto_route {
            let t_dns = Instant::now();
            let guard = match self.tunnel.resolver().fake_ip_v4_gateway() {
                Some(gateway) => {
                    let g = tokio::task::spawn_blocking(move || dns::DnsGuard::setup(gateway))
                        .await
                        .map_err(|join_err| {
                            Box::new(io::Error::other(format!(
                                "dns-guard spawn_blocking panicked: {join_err}"
                            )))
                        })?;
                    let dns_ms = t_dns.elapsed().as_secs_f64() * 1000.0;
                    let dns_active = g.is_some();
                    info!("dns-guard setup took {dns_ms:.0}ms (active: {dns_active})");
                    g
                }
                None => None,
            };
            guard
        } else {
            None
        };

        // lwIP answers ICMP echo itself. The core task is spawned inside
        // `NetStack::new` (one live stack per process — await `core_done`
        // before building a successor, e.g. on config reload).
        //
        // Issue #514: the previous generation's teardown finishes only
        // after every stack handle — including the split halves held by the
        // device pumps — is dropped. An aborted parent task cannot await
        // that reaping, so gate construction on the previous core's
        // `core_done` signal instead of trusting task ordering.
        let t_stack = Instant::now();
        let mut prev_slot = PREVIOUS_CORE.lock().await;
        // Clone, not take: if this task is dropped mid-wait (startup
        // timeout, `NetStack::new` error via `?`), the slot must keep the
        // barrier so the next generation still gates on this core's
        // teardown rather than building a second stack over a live one.
        if let Some(mut prev_done) = prev_slot.clone() {
            match timeout(
                PREVIOUS_CORE_TEARDOWN_WAIT,
                prev_done.wait_for(|done| *done),
            )
            .await
            {
                // Teardown signalled, or the core's sender vanished entirely
                // (core panicked/exited without signalling — nothing left to
                // wait on either way).
                Ok(_) => {}
                Err(_) => warn!(
                    "tun '{}': previous lwIP core still tearing down after {:?}; \
                     proceeding risks two live cores sharing pcb globals",
                    self.name, PREVIOUS_CORE_TEARDOWN_WAIT
                ),
            }
        }
        let (stack, mut tcp_listener, udp_socket) =
            lwip::NetStack::new().map_err(|e| io::Error::other(format!("lwIP netstack: {e}")))?;
        // Publish this generation's done signal so the next stack build
        // gates on it — including the case where this listener is aborted
        // before readiness fires.
        let core_done = stack.core_done();
        *prev_slot = Some(core_done.clone());
        drop(prev_slot);

        let stack_ms = t_stack.elapsed().as_secs_f64() * 1000.0;
        info!("lwIP netstack built in {stack_ms:.0}ms");

        let mut tasks = TaskGroup::new();

        // Windows: start the local DNS server on the sockets bound earlier
        // (before DnsGuard repointed system DNS at 127.0.0.1 / ::1). The
        // server answers queries using the same DnsServer::handle_query
        // pipeline as the TUN dns-hijack path, returning fake IPs.
        #[cfg(target_os = "windows")]
        if let Some(sockets) = local_dns_sockets {
            let resolver = self.tunnel.resolver_slot();
            tasks.spawn(async move {
                local_dns::run(sockets, resolver).await;
            });
        }

        let (mut pump_in, mut pump_out) = device::spawn_pumps(device, stack);
        tasks.push(&pump_in);
        tasks.push(&pump_out);
        tasks.spawn(udp::run_udp(
            self.tunnel.clone(),
            udp_socket,
            cfg.dns_hijack,
            cfg.udp_timeout,
            self.name.clone(),
            cfg.inet4_address,
        ));

        let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let max_conn = cfg.max_connections;
        info!(
            "TUN listener '{}' started on device '{dev_name}' ({}/{}, mtu {}, auto-route: {}, \
             dns-hijack: {}, max-connections: {}, stack: lwip, total startup {total_ms:.0}ms)",
            self.name,
            used_addr,
            prefix,
            cfg.mtu,
            cfg.auto_route,
            cfg.dns_hijack,
            if max_conn == 0 {
                "unlimited".to_string()
            } else {
                max_conn.to_string()
            },
        );

        // Signal readiness: device, stack, and child tasks are all up.
        // The payload hands the owner the lwIP core's done signal so a
        // later `stop_tun` can await real teardown (issue #514). An `Err`
        // return from this function sends `TunReady::Failed` (with the
        // real error) from `run` instead.
        if let Some(notifier) = notifier.take() {
            notifier.ready(core_done.clone());
            debug!("TUN listener '{}' readiness signalled", self.name);
        }

        let tun_net = cfg.inet4_address;
        let conn_limit: Option<Arc<Semaphore>> = if max_conn > 0 {
            Some(Arc::new(Semaphore::new(max_conn)))
        } else {
            None
        };
        let warned_saturated = Arc::new(AtomicBool::new(false));

        let result = loop {
            tokio::select! {
                accepted = tcp_listener.next() => match accepted {
                    Some((stream, src, dst)) => {
                        // Same loop guard as the UDP path: a dial to the
                        // TUN's own subnet routes back into the device.
                        if udp::is_looping_dst(dst.ip(), tun_net) {
                            debug!("tun TCP: dropping non-routable dst {dst} (from {src})");
                            drop(stream);
                            continue;
                        }
                        let tunnel = self.tunnel.clone();
                        let name = self.name.clone();
                        let sem = conn_limit.clone();
                        let warned = Arc::clone(&warned_saturated);
                        tasks.spawn(async move {
                            // lwIP only delivers this stream after the
                            // handshake. We still wait for the first payload
                            // before taking a max-connections slot / dialing.
                            let mut stream = stream;
                            let prefix = match wait_for_first_payload(&mut stream).await {
                                Ok(p) => p,
                                Err(e) => {
                                    debug!(
                                        "tun TCP: dropping {src} -> {dst} before payload: {e}"
                                    );
                                    return;
                                }
                            };
                            let permit = if let Some(sem) = sem {
                                if sem.available_permits() == 0
                                    && !warned.swap(true, Ordering::Relaxed)
                                {
                                    warn!(
                                        "TUN listener '{name}' saturated at max-connections; \
                                         payload-ready flows will wait"
                                    );
                                }
                                match Arc::clone(&sem).acquire_owned().await {
                                    Ok(p) => {
                                        if sem.available_permits() > 0 {
                                            warned.store(false, Ordering::Relaxed);
                                        }
                                        Some(p)
                                    }
                                    Err(_) => return,
                                }
                            } else {
                                None
                            };
                            let _permit = permit;
                            handle_tcp_flow(tunnel, stream, prefix, src, dst, &name).await;
                        });
                    }
                    None => break Err("netstack TCP listener closed".into()),
                },
                joined = &mut pump_in => {
                    break Err(pump_error("device→stack", joined).into());
                }
                joined = &mut pump_out => {
                    break Err(pump_error("stack→device", joined).into());
                }
            }
        };

        // Ordered teardown (issue #514): the lwIP core begins teardown only
        // once every stack handle is dropped — the pumps hold the split
        // halves and children hold the UDP socket — so abort and JOIN them
        // before returning. When this future is aborted mid-loop the tail
        // never runs, but `TaskGroup::drop` still requests the aborts and
        // the `core_done` gate above serializes the next generation once
        // the reaping completes.
        pump_in.abort();
        pump_out.abort();
        let _ = pump_in.await;
        let _ = pump_out.await;
        tasks.shutdown().await;
        drop(tcp_listener);
        result
    }
}

/// Device name to try on creation `attempt` (0-based).
///
/// macOS only accepts `utunN` device names and picks one itself when none is
/// given, so never invent a name there — pass the configured name through
/// unchanged (suffix rotation would produce an invalid `utunN-1`). Elsewhere
/// default to "meow-tun" and rotate a numeric suffix to sidestep stale
/// adapters from unclean shutdowns (common with wintun).
fn device_name_for_attempt(configured: Option<&str>, attempt: u32) -> Option<String> {
    if cfg!(target_os = "macos") {
        configured.map(str::to_string)
    } else {
        let base = configured.unwrap_or("meow-tun");
        Some(if attempt == 0 {
            base.to_string()
        } else {
            format!("{base}-{attempt}")
        })
    }
}

fn pump_error(direction: &str, joined: Result<io::Result<()>, tokio::task::JoinError>) -> String {
    match joined {
        Ok(Ok(())) => format!("tun {direction} pump exited"),
        Ok(Err(e)) => format!("tun {direction} pump failed: {e}"),
        Err(e) => format!("tun {direction} pump panicked: {e}"),
    }
}

/// Wait until the client sends at least one payload byte (handshake is
/// already done by lwIP). Times out empty ESTABLISHED sockets.
async fn wait_for_first_payload(tcp: &mut lwip::TcpStream) -> io::Result<Vec<u8>> {
    wait_for_first_payload_timed(tcp, TUN_PAYLOAD_WAIT).await
}

async fn wait_for_first_payload_timed<R>(tcp: &mut R, wait: Duration) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; TUN_FIRST_READ];
    let n = timeout(wait, tcp.read(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no payload after TCP handshake"))??;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed before sending payload",
        ));
    }
    buf.truncate(n);
    Ok(buf)
}

async fn handle_tcp_flow(
    tunnel: Tunnel,
    tcp: lwip::TcpStream,
    prefix: Vec<u8>,
    src: SocketAddr, // client behind the tun
    dst: SocketAddr, // original destination
    in_name: &str,
) {
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Tun,
        src_ip: Some(src.ip()),
        src_port: src.port(),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        in_name: in_name.into(),
        ..Default::default()
    };

    // handle_tcp does the rest: fake-IP rewrite, lazy rule match, stats
    // guard, dial, zero-alloc relay. `prefix` is the first payload already
    // read while waiting for real traffic.
    meow_tunnel::tcp::handle_tcp(
        tunnel.inner(),
        Box::new(TunTcpConn {
            prefix,
            pos: 0,
            inner: std::sync::Mutex::new(tcp),
        }),
        metadata,
    )
    .await;
}

/// Netstack TCP stream plus the bytes already consumed while waiting for
/// the first payload. The inner stream sits in a `Mutex` so the type is
/// `Sync` (`ProxyConn` requires it); lwIP's `TcpStream` is `Send` but not
/// `Sync`. Only one task ever polls a given connection.
struct TunTcpConn<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: std::sync::Mutex<S>,
}

impl<S: AsyncRead + Unpin> AsyncRead for TunTcpConn<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let rest = &this.prefix[this.pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix.clear();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let mut inner = this
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Pin::new(&mut *inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TunTcpConn<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut inner = this
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Pin::new(&mut *inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Sync + Unpin> ProxyConn for TunTcpConn<S> {}

#[cfg(test)]
mod tests {
    use super::{device_name_for_attempt, wait_for_first_payload_timed, TunTcpConn};
    use std::io;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_never_invents_a_device_name() {
        // Regression: passing a non-`utun` name to tun-rs fails device
        // creation on macOS ("device name must start with utun"), so an
        // unset `tun.device` must stay unset — the platform picks `utunN`.
        for attempt in 0..5 {
            assert_eq!(device_name_for_attempt(None, attempt), None);
            assert_eq!(
                device_name_for_attempt(Some("utun7"), attempt),
                Some("utun7".to_string()),
                "configured name passes through without suffix rotation"
            );
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn default_name_rotates_suffix_on_retries() {
        assert_eq!(
            device_name_for_attempt(None, 0),
            Some("meow-tun".to_string())
        );
        assert_eq!(
            device_name_for_attempt(None, 2),
            Some("meow-tun-2".to_string())
        );
        assert_eq!(
            device_name_for_attempt(Some("mytun"), 1),
            Some("mytun-1".to_string())
        );
    }

    #[tokio::test]
    async fn wait_for_payload_returns_first_bytes() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            server.write_all(b"GET /").await.unwrap();
        });
        let got = wait_for_first_payload_timed(&mut client, Duration::from_secs(1))
            .await
            .expect("payload");
        assert_eq!(got, b"GET /");
    }

    #[tokio::test]
    async fn wait_for_payload_times_out_without_data() {
        let (mut client, _server) = tokio::io::duplex(64);
        let err = wait_for_first_payload_timed(&mut client, Duration::from_millis(20))
            .await
            .expect_err("syn-only");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn wait_for_payload_eof_before_data_is_an_error() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server);
        let err = wait_for_first_payload_timed(&mut client, Duration::from_secs(1))
            .await
            .expect_err("eof");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn prefix_is_replayed_then_inner_bytes() {
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(b"world").await.unwrap();
        let mut conn = TunTcpConn {
            prefix: b"hello".to_vec(),
            pos: 0,
            inner: std::sync::Mutex::new(client),
        };
        let mut buf = vec![0u8; 16];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[tokio::test]
    async fn prefix_read_can_be_split_across_calls() {
        let (client, _server) = tokio::io::duplex(64);
        let mut conn = TunTcpConn {
            prefix: b"abcdef".to_vec(),
            pos: 0,
            inner: std::sync::Mutex::new(client),
        };
        let mut buf = [0u8; 2];
        assert_eq!(conn.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf, b"ab");
        assert_eq!(conn.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf, b"cd");
        assert_eq!(conn.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf, b"ef");
    }
}
