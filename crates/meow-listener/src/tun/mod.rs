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
//! An accepted flow then gets a short sniff window (`TUN_SNIFF_WINDOW`,
//! 200 ms) for the client's first bytes, which are replayed upstream as
//! the relay prefix. A flow that closes or resets inside the window
//! (connect scans, aborted reconnects) is dropped before rule-match /
//! stats / dial. A flow that stays silent is dialed anyway with an empty
//! prefix: server-first protocols (SMTP, POP3, IMAP, FTP, MySQL, VNC,
//! SSH) wait for the server's banner and would otherwise never get one
//! (#695).
//!
//! ## Route scope
//!
//! `auto-route` installs one of two scopes ([`TunRouteScope`]). The
//! classic TUN failure mode is the routing loop: a route into the device
//! that meow's *own* outbound dials also follow. Each scope rules it out
//! differently.
//!
//! **Global** (#375; the default on Linux, macOS and Windows) captures
//! everything the host originates, IPv6 too when the device has an
//! `inet6-address`. Loop freedom lives on the outbound path: every socket
//! meow creates is bound to the physical interface
//! (`meow_common::install_outbound_interface`: `SO_BINDTODEVICE` on Linux,
//! `IP_BOUND_IF` on macOS, `IP_UNICAST_IF` on Windows) before
//! connect/bind, and hostname dials resolve through meow's own resolver
//! hook. Startup fails closed if the binding cannot be installed.
//!
//! On Linux the device's default routes live in a routing table of their
//! own, which policy rules send only the flows the host originates to
//! (`policy_route.rs`): the replies on connections the host accepted from
//! another network keep the physical route, and traffic the host forwards
//! keeps the main table, where the fake-IP range is routed into the
//! device. Elsewhere — and on a Linux kernel without policy routing —
//! split default routes go in the main table: `0.0.0.0/1` + `128.0.0.0/1`
//! (on macOS an equivalent set that avoids the all-zero destination),
//! plus `::/1` + `8000::/1`.
//!
//! **Fake-IP** captures only the fake-IP range, loop-free by construction:
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
//! On Windows the device is a Wintun adapter. `wintun.dll` is resolved next
//! to the executable (official Windows zips ship it there), then the working
//! directory; if neither exists the official signed DLL embedded in the
//! binary is written out. The process must run elevated. On Linux/macOS
//! creating the device requires root (CAP_NET_ADMIN).

mod device;
mod dns;
#[cfg(target_os = "windows")]
mod local_dns;
mod outbound_binding;
#[cfg(target_os = "linux")]
mod policy_route;
mod route;
mod udp;
#[cfg(target_os = "windows")]
mod windows_device;
#[cfg(any(test, target_os = "windows"))]
mod wintun;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::StreamExt;
use ipnet::{Ipv4Net, Ipv6Net};
use meow_common::{ConnType, Metadata, Network, ProxyConn};
use meow_tunnel::Tunnel;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Post-handshake sniff window: how long an accepted TUN TCP flow may stay
/// silent before it is dialed anyway with an empty prefix (#695).
///
/// Server-first clients (SMTP, POP3, IMAP, FTP, MySQL, VNC, SSH) send
/// nothing until they see the server's banner, so they pay this window
/// once before the dial — it must stay well under a second. 200 ms is
/// mihomo's pre-dial peek window (`tunnel/tunnel.go` `handleTCPConn`:
/// `SetReadDeadline(now + 200ms)` + `Peek(1)`, deadline error ignored).
/// A client-first flow's first segment normally follows the handshake ACK
/// back-to-back and lands well inside it; one that misses the window just
/// relays its bytes without a prefix. Routing reads the first bytes only
/// for a flow the tunnel cannot name (an unmapped fake IP):
/// `meow_tunnel::tcp::handle_tcp` sniffs its SNI / `Host`, through the
/// replayed prefix or its own short wait.
const TUN_SNIFF_WINDOW: Duration = Duration::from_millis(200);
/// First-read size when waiting for real traffic. Large enough to pull a
/// TLS ClientHello record header + a bit of payload in one shot.
const TUN_FIRST_READ: usize = 256;

use route::RouteGuard;

pub use outbound_binding::OutboundBinding;

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
    /// IPv6 address + prefix assigned to the device; `None` = IPv4-only.
    /// In global scope it also adds the IPv6 split default routes (#375).
    pub inet6_address: Option<Ipv6Net>,
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

/// Which routes `auto_route` installs (#375; see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunRouteScope {
    /// Route only the fake-IP range — loop-free by construction.
    #[default]
    FakeIp,
    /// Route everything the host originates — IPv4, and IPv6 when the
    /// device has an IPv6 address — into the device; outbound sockets bind
    /// to the physical interface for loop avoidance.
    Global,
}

/// Outcome of TUN listener startup, sent through the readiness channel.
/// Allows callers to distinguish immediate setup failure from a timeout
/// without waiting for the full `TUN_STARTUP_TIMEOUT`.
pub enum TunReady {
    /// Device + stack + child tasks are fully initialized.
    Ready {
        /// The lwIP core's done signal — it flips `true` once that
        /// generation's teardown fully completes, which the owner must
        /// await before permitting a successor stack (issue #514).
        core_done: tokio::sync::watch::Receiver<bool>,
        /// Live UDP flow-table occupancy — written by the UDP read loop,
        /// readable at any time for observability (issue #515).
        udp_flows: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    },
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
    /// core's done signal and the UDP flow-table gauge.
    fn ready(
        mut self,
        core_done: tokio::sync::watch::Receiver<bool>,
        udp_flows: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(TunReady::Ready {
                core_done,
                udp_flows,
            });
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
    /// Global scope's policy routing on Linux, removed first: while its
    /// rules stand, the outbound binding (`iface_guard`) must hold.
    #[cfg(target_os = "linux")]
    #[allow(dead_code, reason = "held only for its Drop side effect")]
    policy_routes: Option<policy_route::PolicyRoutes>,
    /// Held only for its `Drop` side effect — routes are deleted when
    /// this field is dropped, before `device` is destroyed.
    #[allow(dead_code)]
    route_guard: Option<RouteGuard>,
    /// This listener's ownership of the process-global outbound-interface
    /// binding for global route scope, committed once the listener is up.
    /// Dropping it gives the ownership up (after `route_guard` has removed
    /// the routes it protects). A successor that already installed its own
    /// binding keeps it; otherwise the binding is cleared.
    iface_guard: Option<OutboundBinding>,
    pub(super) device: tun_rs::AsyncDevice,
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
    /// Global-scope binding installed by the caller before this listener
    /// was built (see [`Self::with_outbound_binding`]).
    outbound_binding: Option<OutboundBinding>,
}

impl TunListener {
    pub fn new(tunnel: Tunnel, cfg: TunListenerConfig, name: String) -> Self {
        Self {
            tunnel,
            cfg,
            name,
            ready: None,
            outbound_binding: None,
        }
    }

    /// Hand over an [`OutboundBinding`] the caller installed early — the
    /// binary does so before its first startup dial, and a config reload
    /// before the reload's first dial, so no socket predates the binding
    /// (issue #695). The listener uses it instead of installing its own
    /// and owns it from here on: it is given up with the routes on
    /// teardown, or straight away if startup fails or the listener is
    /// dropped without running. Ignored (and so given up) outside global
    /// route scope.
    pub fn with_outbound_binding(mut self, binding: OutboundBinding) -> Self {
        self.outbound_binding = Some(binding);
        self
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
        let preinstalled = self.outbound_binding.take();
        let result = self.run_inner(&mut notifier, preinstalled).await;
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
        preinstalled: Option<OutboundBinding>,
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
        // we also rotate the TUN addresses (IPv4 and IPv6 alike) to work
        // around address conflicts.
        //
        // Each attempt runs on a blocking thread; the outer caller's
        // TUN_STARTUP_TIMEOUT guards the overall time spent here.
        const MAX_TUN_RETRIES: u32 = 5;
        const TUN_CREATE_RETRY_DELAY: Duration = Duration::from_millis(500);
        let base_addr = cfg.inet4_address.addr();
        let prefix = cfg.inet4_address.prefix_len();
        let fake_ip_gateway = match self.tunnel.resolver().fake_ip_v4_gateway() {
            Some(std::net::IpAddr::V4(gateway)) => Some(gateway),
            _ => None,
        };
        let mut device: Option<tun_rs::AsyncDevice> = None;
        let mut dev_name = String::new();
        let mut used_addr = base_addr;
        // The IPv6 address the device actually carries: attempt >= 2
        // rotates it inside the configured subnet, so the startup log
        // records the rotated value, not just the configured one.
        let mut used_addr6 = cfg.inet6_address.map(|net| net.addr());
        let mut last_err: Option<String>;
        let mut if_index: Option<u32> = None;

        for attempt in 0..MAX_TUN_RETRIES {
            let name = device_name_for_attempt(cfg.device.as_deref(), attempt);

            // Rotate the addresses after the first retry fails
            // (attempt >= 2), so a conflict with an address another
            // adapter still holds is worked around (`rotate_v4`); the
            // IPv6 one steps within the configured subnet.
            let addr = rotate_v4(base_addr, attempt, fake_ip_gateway);
            let ip_display = format!("{addr}/{prefix}");

            // Copy the values we need inside `spawn_blocking` so we don't
            // borrow `cfg` across the closure boundary.
            let mtu = cfg.mtu;
            let inet6 = cfg.inet6_address.map(|net| rotate_v6(net, attempt));
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

            match tokio::task::spawn_blocking(move || -> io::Result<(tun_rs::AsyncDevice, u32)> {
                let mut builder = tun_rs::DeviceBuilder::new().mtu(mtu);
                // On Windows the listener assigns the addresses itself
                // once the adapter exists: the ones the builder sets
                // would start out tentative.
                #[cfg(not(target_os = "windows"))]
                {
                    builder = builder.ipv4(addr, prefix, None);
                    if let Some(v6) = inet6 {
                        builder = builder.ipv6(v6.addr(), v6.prefix_len());
                    }
                }
                if let Some(n) = &name_for_closure {
                    builder = builder.name(n);
                }
                // Pin the Wintun DLL we resolved above so tun-rs does not
                // walk the process DLL search path.
                #[cfg(target_os = "windows")]
                {
                    builder = builder.wintun_file(wintun_file).wintun_log(true);
                }
                // tun-rs opens a same-named, non-orphaned adapter instead
                // of creating one (an orphaned one it replaces), and
                // Wintun does not delete a merely-opened adapter when it
                // is closed: this run then replaces that adapter's
                // addresses. Warn so the reuse is visible.
                #[cfg(target_os = "windows")]
                if let Some(n) = &name_for_closure {
                    match windows_device::adapter_exists(n) {
                        Ok(true) => warn!(
                            "adapter '{n}' already exists; opening it and replacing the addresses it carries"
                        ),
                        Ok(false) => {}
                        Err(e) => {
                            warn!("could not check whether adapter '{n}' already exists: {e}");
                        }
                    }
                }
                let device = builder.build_async()?;
                // One read of the index serves both the address setup
                // and the caller.
                let if_index = device.if_index()?;
                // On failure the adapter drops here and the attempt retries.
                #[cfg(target_os = "windows")]
                windows_device::configure_addresses(
                    if_index,
                    Ipv4Net::new_assert(addr, prefix),
                    inet6,
                )?;
                Ok((device, if_index))
            })
            .await
            {
                Ok(Ok((d, idx))) => {
                    dev_name = d
                        .name()
                        .unwrap_or_else(|_| name.clone().unwrap_or_default());
                    used_addr = addr;
                    used_addr6 = inet6.map(|net| net.addr());
                    device = Some(d);
                    if_index = Some(idx);
                    break;
                }
                Ok(Err(e)) => {
                    warn!("failed to create or configure TUN device '{display_name}': {e}");
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
                    "failed to set up TUN device after {MAX_TUN_RETRIES} attempts{detail}"
                ))));
            }

            // The point of retrying is to outlast an asynchronously
            // closing stale adapter (common on Windows after an unclean
            // shutdown) — back-to-back attempts would race ahead of the
            // cleanup they exist to wait for. Bounded by TUN_STARTUP_TIMEOUT
            // (issue #641).
            tokio::time::sleep(TUN_CREATE_RETRY_DELAY).await;
        }
        // SAFETY: the loop either breaks with `device = Some(...)` and
        // `dev_name` set, or returns `Err` above.
        let device = device.unwrap();
        // SAFETY: set on the same break that sets `device`.
        let if_index = if_index.unwrap();

        let tun_create_ms = t0.elapsed().as_secs_f64() * 1000.0;
        info!("TUN device '{dev_name}' created in {tun_create_ms:.0}ms");

        // Global route scope (#375): before any routes go in, the
        // outbound-interface binding must be installed so meow's own dials
        // cannot loop back into the device — usually it already is (the
        // binary installs it before its first startup dial, a config
        // reload before the reload's first dial; issue #695).
        // Fail closed — a global default route without working loop
        // avoidance would blackhole the host's connectivity.
        let iface_guard = if cfg.auto_route && cfg.route_scope == TunRouteScope::Global {
            Some(match preinstalled {
                Some(binding) => binding,
                None => OutboundBinding::install(cfg.outbound_interface.as_deref())?,
            })
        } else {
            drop(preinstalled);
            None
        };

        // The subnet of the address the device took: a retry can step
        // off the configured one (`rotate_v4`). The IPv6 one stays inside
        // the configured subnet (`rotate_v6`).
        let tun_net = udp::TunNets {
            v4: Ipv4Net::new_assert(used_addr, prefix),
            v6: cfg.inet6_address,
        };
        let fake_ip_net = self.tunnel.resolver().fake_ip_v4_net();

        // Global scope on Linux: the device's default routes go in a table
        // of their own, which policy rules send only the flows this host
        // originates to (see `policy_route.rs`). Without policy routing
        // the split defaults below go in the main table instead.
        #[cfg(target_os = "linux")]
        let policy_routes = if cfg.auto_route && cfg.route_scope == TunRouteScope::Global {
            let (v4, v6) = (tun_net.v4, tun_net.v6);
            match tokio::task::spawn_blocking(move || {
                policy_route::PolicyRoutes::setup(if_index, v4, v6)
            })
            .await
            {
                Ok(Ok(routes)) => Some(routes),
                Ok(Err(e)) => {
                    warn!(
                        "tun '{}': policy routing unavailable ({e}); routing everything \
                         through the main table instead, which also sends the replies on \
                         connections accepted from other networks into '{dev_name}'",
                        self.name
                    );
                    None
                }
                Err(join_err) => {
                    return Err(Box::new(io::Error::other(format!(
                        "policy-route spawn_blocking panicked: {join_err}"
                    ))));
                }
            }
        } else {
            None
        };
        #[cfg(target_os = "linux")]
        let policy_routed = policy_routes.is_some();
        #[cfg(not(target_os = "linux"))]
        let policy_routed = false;

        // auto-route: install the scope's routes in the main table (see
        // module docs).
        let route_nets: Vec<ipnet::IpNet> = match (cfg.auto_route, cfg.route_scope) {
            (false, _) => Vec::new(),
            // The policy rules leave traffic the host forwards
            // (containers, VMs, a gateway's LAN clients) to the main table,
            // where the fake-IP range still catches its domain flows.
            (true, TunRouteScope::Global) if policy_routed => fake_ip_net.into_iter().collect(),
            // Split defaults: two /1s (macOS: eight routes that avoid the
            // all-zero key) cover all IPv4 while staying more specific
            // than the physical 0/0 default, so the original route
            // survives untouched and restore-on-drop is trivial. The
            // device's own /30 and the fake-IP range (if any) are inside
            // the /1s already.
            (true, TunRouteScope::Global) => global_route_nets(cfg.inet6_address.is_some()),
            (true, TunRouteScope::FakeIp) => {
                if fake_ip_net.is_none() {
                    warn!(
                        "tun '{}': 'auto-route: fake-ip' only routes the fake-IP range, but \
                         DNS is not in fake-ip mode — no routes installed. Use \
                         'auto-route: true', or add routes to '{dev_name}' manually.",
                        self.name
                    );
                }
                fake_ip_net.into_iter().collect()
            }
        };

        // RouteManager::add() calls into OS routing APIs that may block
        // (PowerShell on Windows), so it runs on a blocking thread. The
        // outer TUN_STARTUP_TIMEOUT guards the overall startup.
        let route_guard = if route_nets.is_empty() {
            None
        } else {
            let t_route = Instant::now();
            match tokio::task::spawn_blocking(move || RouteGuard::setup(if_index, &route_nets))
                .await
            {
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
        };

        // Wrap the device and its route guard in a single `Arc` so they share
        // one reference-counted lifetime. Field order guarantees `route_guard`
        // is dropped (routes deleted) **before** `device` (adapter destroyed)
        // when the last `Arc` clone goes away — ensuring route deletion always
        // succeeds because the adapter is still alive.
        let device = Arc::new(TunDevice {
            #[cfg(target_os = "linux")]
            policy_routes,
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
            let guard = match fake_ip_gateway {
                Some(gateway) => {
                    let addrs = dns::GuardAddrs::new(gateway, used_addr);
                    let g = tokio::task::spawn_blocking(move || dns::DnsGuard::setup(addrs))
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
                // A still-living predecessor owns the process-global pcb
                // lists `NetStack::new` is about to overwrite — proceeding
                // is a data race on C state, not a recoverable wait. Fail
                // the listener; the caller rolls `tun.enable` back.
                Err(_) => {
                    return Err(io::Error::other(format!(
                        "previous lwIP core did not finish teardown within \
                         {PREVIOUS_CORE_TEARDOWN_WAIT:?}; refusing to build \
                         a second stack over live pcb globals"
                    ))
                    .into());
                }
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

        // Nothing past here fails: the listener is up, and its binding is
        // the running one.
        if let Some(binding) = &device.iface_guard {
            binding.commit();
        }
        let (mut pump_in, mut pump_out) = device::spawn_pumps(device, stack);
        tasks.push(&pump_in);
        tasks.push(&pump_out);
        // Live UDP flow-table occupancy, readable via `TunReady::Ready` →
        // `TunHandle` for observability (issue #515).
        let udp_flows = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tasks.spawn(udp::run_udp(
            self.tunnel.clone(),
            udp_socket,
            cfg.dns_hijack,
            cfg.udp_timeout,
            self.name.clone(),
            tun_net,
            std::sync::Arc::clone(&udp_flows),
        ));

        let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let max_conn = cfg.max_connections;
        info!(
            "TUN listener '{}' started on device '{dev_name}' ({}/{}{}, mtu {}, auto-route: {}, \
             dns-hijack: {}, max-connections: {}, stack: lwip, total startup {total_ms:.0}ms)",
            self.name,
            used_addr,
            prefix,
            match (used_addr6, cfg.inet6_address) {
                (Some(addr), Some(net)) => format!(" + {addr}/{}", net.prefix_len()),
                _ => String::new(),
            },
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
            notifier.ready(core_done.clone(), udp_flows);
            debug!("TUN listener '{}' readiness signalled", self.name);
        }

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
                            // handshake. Sniff the client's first bytes for
                            // up to TUN_SNIFF_WINDOW; a close/reset inside
                            // the window drops the flow, silence dials it
                            // with an empty prefix (server-first, #695).
                            let mut stream = stream;
                            let prefix = match sniff_first_payload(&mut stream).await {
                                Ok(p) => {
                                    if p.is_empty() {
                                        debug!(
                                            "tun TCP: {src} -> {dst} silent for {}ms, \
                                             dialing without prefix",
                                            TUN_SNIFF_WINDOW.as_millis()
                                        );
                                    }
                                    p
                                }
                                Err(e) => {
                                    debug!(
                                        "tun TCP: dropping {src} -> {dst} before payload: {e}"
                                    );
                                    return;
                                }
                            };
                            // A slot is taken only once the flow leaves the
                            // sniff window (payload seen, or silent past it),
                            // so a flow that dies inside the window never
                            // occupies one. Past the window every flow —
                            // including an idle server-first one — holds its
                            // slot for its lifetime, exactly as on the other
                            // inbounds. Flows queued here at saturation are
                            // bounded by lwIP's MEMP_NUM_TCP_PCB.
                            let permit = if let Some(sem) = sem {
                                if sem.available_permits() == 0
                                    && !warned.swap(true, Ordering::Relaxed)
                                {
                                    warn!(
                                        "TUN listener '{name}' saturated at max-connections; \
                                         new flows will wait for a free slot before dialing"
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
        //
        // A pump arm that won the select! already consumed that handle's
        // output — re-polling a consumed JoinHandle panics
        // ("JoinHandle polled after completion"), so only await a pump
        // that is still running. abort() on a finished task is a no-op.
        pump_in.abort();
        pump_out.abort();
        if !pump_in.is_finished() {
            let _ = pump_in.await;
        }
        if !pump_out.is_finished() {
            let _ = pump_out.await;
        }
        tasks.shutdown().await;
        drop(tcp_listener);
        result
    }
}

/// The split default routes of global route scope (#375): more specific
/// than the physical default so it is never touched. IPv6 is included only
/// when the device carries an IPv6 address — routes into a device that
/// cannot source IPv6 would blackhole that traffic.
fn global_route_nets(ipv6: bool) -> Vec<ipnet::IpNet> {
    global_route_nets_for(ipv6, cfg!(target_os = "macos"))
}

/// Pure selection behind [`global_route_nets`], split out so both shapes
/// are unit-tested on every host.
///
/// Everywhere but macOS a family is two `/1`s. On macOS
/// (`zero_key_shadows_default`) the lower half is instead split into seven
/// routes that skip the first `/8`, so that **no installed route has the
/// all-zero destination**.
///
/// The reason is XNU's scoped route lookup, which is what an outbound
/// socket bound with `IP_BOUND_IF` / `IPV6_BOUND_IF` gets. When the best
/// match belongs to another interface (the TUN) and the bound interface
/// has no scoped route of its own — the primary interface's default is
/// unscoped — the kernel falls back to looking the default route up *by
/// key*, `0.0.0.0` / `::`. A `0.0.0.0/1` (or `::/1`) route shares that key
/// and is returned instead of the real default; its interface is not the
/// bound one, so the lookup fails and every dial meow makes dies with
/// `ENETUNREACH` (IPv4) / `EHOSTUNREACH` (IPv6) — for destinations in
/// *both* halves. Observed on macOS 26.6 (#375); removing the zero-keyed
/// route alone restores the bound sockets.
///
/// The skipped `0.0.0.0/8` is "this network" and never a destination. The
/// skipped `::/8` holds the unspecified/loopback addresses and the
/// IPv4-mapped and NAT64 (`64:ff9b::/96`) ranges, which therefore bypass
/// the device on macOS.
fn global_route_nets_for(ipv6: bool, zero_key_shadows_default: bool) -> Vec<ipnet::IpNet> {
    const V4: &[&str] = &["0.0.0.0/1", "128.0.0.0/1"];
    const V6: &[&str] = &["::/1", "8000::/1"];
    const V4_NO_ZERO_KEY: &[&str] = &[
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ];
    const V6_NO_ZERO_KEY: &[&str] = &[
        "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "2000::/3", "4000::/2", "8000::/1",
    ];
    let (v4, v6) = if zero_key_shadows_default {
        (V4_NO_ZERO_KEY, V6_NO_ZERO_KEY)
    } else {
        (V4, V6)
    };
    v4.iter()
        .chain(v6.iter().filter(|_| ipv6))
        .map(|net| net.parse().expect("static CIDR parses"))
        .collect()
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

/// The IPv4 address for `attempt`: the configured one for the first two,
/// then another, so a conflict with an address another adapter still holds
/// is worked around. An address in the fake-IP pool's reserved block
/// (network, gateway and the two above; the default device address is the
/// gateway) moves to the block's other host: the next /30 holds fake IPs
/// the pool hands out, and a device owning one would make it local.
/// Elsewhere each /30 subnet spans 4 addresses, so it steps to the next.
fn rotate_v4(base: Ipv4Addr, attempt: u32, fake_ip_gateway: Option<Ipv4Addr>) -> Ipv4Addr {
    if attempt < 2 {
        return base;
    }
    if let Some(gateway) = fake_ip_gateway {
        let spare = Ipv4Addr::from(u32::from(gateway).wrapping_add(1));
        if base == gateway {
            return spare;
        }
        if base == spare {
            return gateway;
        }
    }
    Ipv4Addr::from(u32::from(base).wrapping_add((attempt - 1) * 4))
}

/// The configured IPv6 net for `attempt`: from the third attempt the host
/// bits step by one address, wrapping inside the subnet, so a conflict
/// with an address another adapter still holds is worked around like the
/// IPv4 rotation above does. An all-zero interface identifier is skipped
/// (RFC 7136 reserves it for the subnet-router anycast on a /64); a
/// subnet with fewer than two host bits has nothing to rotate.
fn rotate_v6(net: Ipv6Net, attempt: u32) -> Ipv6Net {
    if attempt < 2 {
        return net;
    }
    let host_bits = 128 - u32::from(net.prefix_len());
    if host_bits < 2 {
        return net;
    }
    let bits = u128::from(net.addr());
    // `u128::MAX >> prefix` keeps the shift under 128 here (the early
    // return took care of /127 and /128) and gives the right mask for a
    // /0 config too.
    let host_mask = u128::MAX >> u32::from(net.prefix_len());
    // The host part steps through 1..=host_mask without repeating: the
    // all-zero identifier stays skipped, and a base address sitting on
    // the subnet's top host still moves to a fresh address per attempt.
    // A tiny subnet can cycle back onto the configured address; the
    // retry still moves to a fresh adapter name.
    //
    // The offset is added modulo host_mask, not modulo 2^128: for a /0
    // config host_mask is u128::MAX and a base host at the very top of
    // the space would otherwise wrap one above the residue ring, which
    // folds two attempts onto the same address. `host0` may equal
    // host_mask (≡ 0), where the wrapped sum is just `step`.
    let host0 = bits & host_mask;
    let step = u128::from(attempt - 2) % host_mask;
    let host = if host0 >= host_mask - step {
        host0 - (host_mask - step)
    } else {
        host0 + step
    } + 1;
    Ipv6Net::new_assert(
        std::net::Ipv6Addr::from((bits & !host_mask) | host),
        net.prefix_len(),
    )
}

fn pump_error(direction: &str, joined: Result<io::Result<()>, tokio::task::JoinError>) -> String {
    match joined {
        Ok(Ok(())) => format!("tun {direction} pump exited"),
        Ok(Err(e)) => format!("tun {direction} pump failed: {e}"),
        Err(e) => format!("tun {direction} pump panicked: {e}"),
    }
}

/// Sniff the client's first payload within [`TUN_SNIFF_WINDOW`] (the
/// handshake is already done by lwIP).
///
/// - `Ok(bytes)` — the client spoke first; `bytes` is the relay prefix.
/// - `Ok(empty)` — the window expired in silence: dial anyway, the server
///   may be the one to speak first (#695). No allocation is kept.
/// - `Err(_)` — EOF or reset before any payload: drop the flow.
async fn sniff_first_payload<R>(tcp: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    sniff_first_payload_within(tcp, TUN_SNIFF_WINDOW).await
}

/// [`sniff_first_payload`] with an explicit window. The stream stays usable
/// after the window expires: lwIP's `TcpStream::poll_read` only consumes a
/// chunk on the poll that returns it, so dropping the pending read loses
/// nothing — the relay picks up whatever arrives later.
async fn sniff_first_payload_within<R>(tcp: &mut R, window: Duration) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; TUN_FIRST_READ];
    let Ok(read) = timeout(window, tcp.read(&mut buf)).await else {
        return Ok(Vec::new());
    };
    let n = read?;
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

    // handle_tcp does the rest: name sniff for an unmapped fake IP,
    // fake-IP rewrite, lazy rule match, stats guard, dial, zero-alloc
    // relay. `prefix` is the first payload read during the sniff window; it
    // reaches the upstream as the relay's first client read (counted as
    // upload there). It is empty for a flow that stayed silent
    // (server-first): `TunTcpConn` then reads straight from the stream and
    // nothing is written upstream until a side speaks — no zero-length
    // write, no synthetic EOF.
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

/// Netstack TCP stream plus the bytes already consumed during the sniff
/// window (possibly none). The inner stream sits in a `Mutex` so the type is
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
    use super::{
        device_name_for_attempt, global_route_nets, global_route_nets_for, rotate_v4, rotate_v6,
        sniff_first_payload, sniff_first_payload_within, Ipv4Addr, Ipv6Net, TunTcpConn,
        TUN_SNIFF_WINDOW,
    };
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

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

    #[test]
    fn ipv4_address_steps_to_the_next_subnet_from_the_third_attempt() {
        let ip = |s: &str| -> Ipv4Addr { s.parse().unwrap() };
        let base = ip("172.19.0.1");
        let gateway = Some(ip("198.18.0.1"));
        assert_eq!(rotate_v4(base, 0, gateway), base);
        assert_eq!(rotate_v4(base, 1, gateway), base);
        assert_eq!(rotate_v4(base, 2, gateway), ip("172.19.0.5"));
        assert_eq!(rotate_v4(base, 3, gateway), ip("172.19.0.9"));
        // Without a fake-IP pool even the gateway's address steps on.
        assert_eq!(rotate_v4(ip("198.18.0.1"), 2, None), ip("198.18.0.5"));
    }

    #[test]
    fn ipv4_address_stays_in_the_fake_ip_reserved_block() {
        let ip = |s: &str| -> Ipv4Addr { s.parse().unwrap() };
        let gateway = ip("198.18.0.1");
        let spare = ip("198.18.0.2");
        // 198.18.0.5 is a fake IP the pool hands out: the device on the
        // gateway (the default) moves to the block's other host instead.
        assert_eq!(rotate_v4(gateway, 1, Some(gateway)), gateway);
        for attempt in 2..5 {
            assert_eq!(rotate_v4(gateway, attempt, Some(gateway)), spare);
            assert_eq!(rotate_v4(spare, attempt, Some(gateway)), gateway);
        }
    }

    #[test]
    fn ipv6_address_rotates_inside_the_configured_subnet_from_the_third_attempt() {
        let net = |s: &str| -> Ipv6Net { s.parse().unwrap() };
        let base = net("fdfe:dcba:9876::1/126");
        // The first two attempts keep the configured address, like the
        // IPv4 rotation keeps the first two.
        assert_eq!(rotate_v6(base, 0), base);
        assert_eq!(rotate_v6(base, 1), base);
        // From the third attempt the host bits step by one, inside the
        // subnet.
        assert_eq!(rotate_v6(base, 2), net("fdfe:dcba:9876::2/126"));
        assert_eq!(rotate_v6(base, 3), net("fdfe:dcba:9876::3/126"));
        // A two-bit subnet wraps back; the all-zero interface
        // identifier is skipped (RFC 7136).
        assert_eq!(rotate_v6(base, 4), base);
        // A /64 has the same interface-identifier space to step in.
        let wide = net("fd00::1/64");
        assert_eq!(rotate_v6(wide, 2), net("fd00::2/64"));
        assert_eq!(rotate_v6(wide, 4), net("fd00::4/64"));
        // A single-address subnet cannot rotate.
        assert_eq!(rotate_v6(net("fd00::1/128"), 4), net("fd00::1/128"));
        // A /0 config makes the mask u128::MAX: even a base host at the
        // very top of the space must yield three distinct nonzero
        // addresses (the offset is added modulo the mask, not 2^128).
        for top in [
            "::1/0",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/0",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0",
        ] {
            let base = net(top);
            let rotated: Vec<u128> = (2..5)
                .map(|attempt| u128::from(rotate_v6(base, attempt).addr()))
                .collect();
            for (i, host) in rotated.iter().enumerate() {
                assert_ne!(*host, 0, "{top} attempt {}", i + 2);
                assert!(
                    rotated[i + 1..].iter().all(|other| other != host),
                    "{top} attempt {} repeats {host:#x}",
                    i + 2
                );
            }
        }
    }

    #[test]
    fn global_routes_cover_ipv6_only_for_a_dual_stack_device() {
        let nets = |ipv6| -> Vec<String> {
            global_route_nets_for(ipv6, false)
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        // The platform's own set is one of the two shapes.
        assert_eq!(
            global_route_nets(true),
            global_route_nets_for(true, cfg!(target_os = "macos"))
        );
        assert_eq!(nets(false), ["0.0.0.0/1", "128.0.0.0/1"]);
        assert_eq!(nets(true), ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]);
        // Each family's pair covers the whole space without being a default.
        for family in [&nets(true)[..2], &nets(true)[2..]] {
            let pair: Vec<ipnet::IpNet> = family.iter().map(|n| n.parse().unwrap()).collect();
            assert!(pair.iter().all(|n| n.prefix_len() == 1));
            assert_ne!(pair[0].network(), pair[1].network());
        }
    }

    /// macOS (#375): a route keyed on the all-zero address shadows the
    /// physical default in the scoped lookup an `IP_BOUND_IF` socket gets,
    /// so the set must cover everything from the second `/8` up without
    /// ever using that key.
    #[test]
    fn macos_global_routes_never_use_the_all_zero_destination() {
        let nets = global_route_nets_for(true, true);
        assert!(nets.iter().all(|n| !n.network().is_unspecified()));
        assert_eq!(nets.iter().filter(|n| n.addr().is_ipv4()).count(), 8);
        assert_eq!(nets.iter().filter(|n| n.addr().is_ipv6()).count(), 8);
        assert_eq!(global_route_nets_for(false, true).len(), 8);

        let covering = |ip: &str| {
            let ip: std::net::IpAddr = ip.parse().unwrap();
            nets.iter().filter(|n| n.contains(&ip)).count()
        };
        // Exactly one route per address: contiguous, no overlap.
        for ip in [
            "1.0.0.0",
            "1.1.1.1",
            "8.8.8.8",
            "100.64.0.1",
            "127.255.255.255",
            "128.0.0.0",
            "198.18.0.1",
            "255.255.255.254",
            "100::1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "7fff::1",
            "8000::",
            "fd00::1",
        ] {
            assert_eq!(covering(ip), 1, "{ip}");
        }
        // Only the first /8 of each family is left out.
        for ip in ["0.0.0.0", "0.255.255.255", "::", "::1", "64:ff9b::101:101"] {
            assert_eq!(covering(ip), 0, "{ip}");
        }
    }

    #[test]
    fn sniff_window_is_short_enough_for_server_first_banners() {
        // #695: a server-first client (SMTP/IMAP/FTP/MySQL/SSH) waits this
        // long for its banner on every connect. Keep it on mihomo's
        // pre-dial peek (200 ms), never back up toward the 15 s handshake
        // timeout that used to drop these flows.
        assert_eq!(TUN_SNIFF_WINDOW, Duration::from_millis(200));
        assert!(TUN_SNIFF_WINDOW < crate::DEFAULT_HANDSHAKE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn sniff_returns_client_first_payload_inside_window() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // Late but inside the production window.
            tokio::time::sleep(TUN_SNIFF_WINDOW - Duration::from_millis(50)).await;
            server.write_all(b"GET /").await.unwrap();
            // Keep the peer open so the read sees data, not EOF.
            std::future::pending::<()>().await;
        });
        let got = sniff_first_payload(&mut client).await.expect("payload");
        assert_eq!(got, b"GET /");
    }

    #[tokio::test(start_paused = true)]
    async fn sniff_window_expiry_dials_with_empty_prefix() {
        // Server-first flow (#695): the client stays silent until it sees
        // a banner. Window expiry must proceed (empty prefix), not drop.
        let (mut client, mut server) = tokio::io::duplex(64);
        let start = tokio::time::Instant::now();
        let got = sniff_first_payload(&mut client)
            .await
            .expect("silence past the window proceeds instead of dropping");
        assert!(got.is_empty(), "no prefix for a silent flow");
        assert_eq!(got.capacity(), 0, "the scratch buffer is not kept");
        // Proceeds right at the window (paused clock; the timer wheel may
        // round the deadline up by a tick).
        let waited = start.elapsed();
        assert!(
            waited >= TUN_SNIFF_WINDOW && waited < TUN_SNIFF_WINDOW + Duration::from_millis(5),
            "waited {waited:?}"
        );

        // The abandoned read lost nothing: the client's reply to the
        // banner arrives after the window and the relay side reads it
        // through the (prefix-less) TunTcpConn.
        let mut conn = TunTcpConn {
            prefix: got,
            pos: 0,
            inner: std::sync::Mutex::new(client),
        };
        server.write_all(b"EHLO meow\r\n").await.unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"EHLO meow\r\n");
    }

    #[tokio::test]
    async fn sniff_eof_before_payload_drops_the_flow() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server);
        let err = sniff_first_payload_within(&mut client, Duration::from_secs(5))
            .await
            .expect_err("eof");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn sniff_reset_before_payload_drops_the_flow() {
        // lwIP surfaces an RST (tcp_err_cb) as a read error.
        struct Reset;
        impl AsyncRead for Reset {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
        }
        let err = sniff_first_payload_within(&mut Reset, Duration::from_secs(5))
            .await
            .expect_err("reset");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test(start_paused = true)]
    async fn empty_prefix_waits_for_inner_instead_of_reporting_eof() {
        // An empty prefix must not surface as a zero-length read — the
        // relay would take that as client EOF and half-close upstream
        // before the server's banner arrives.
        let (client, _server) = tokio::io::duplex(64);
        let mut conn = TunTcpConn {
            prefix: Vec::new(),
            pos: 0,
            inner: std::sync::Mutex::new(client),
        };
        let mut buf = [0u8; 8];
        let pending = tokio::time::timeout(Duration::from_secs(30), conn.read(&mut buf)).await;
        assert!(pending.is_err(), "read must pend, got {pending:?}");
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
