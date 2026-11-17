//! Outbound-socket protector hook for Android `VpnService.protect(fd)`.
//!
//! When meow-rs runs *inside* an Android VPN app, every outbound socket it
//! opens must bypass the VPN itself — otherwise packets to proxy upstreams
//! loop back into the tunnel and deadlock. Android exposes a per-fd hook
//! for this: `android.net.VpnService.protect(int fd)`. This module is the
//! single place the JNI bridge installs that hook; the proxy adapters that
//! open outbound sockets dial through [`connect_tcp`] / [`connect_tcp_host`]
//! / [`bind_udp`] / [`bind_udp_for_peer`], which call the installed
//! protector before `connect()` / `bind()` so the very first SYN / UDP
//! packet already bypasses the tunnel.
//!
//! ## Why the second hook (`HostResolver`)
//!
//! `VpnService.protect(fd)` only protects sockets meow-rs creates itself.
//! Libc's `getaddrinfo` (called by `tokio::net::lookup_host` and
//! `TcpStream::connect("host:port")`) opens its own DNS sockets that
//! meow-rs never sees, so on a VPN-active device those DNS queries route
//! *through* the VPN — i.e. through meow-rs's own tunnel — which then needs
//! to dial a proxy upstream, which needs DNS, which loops. To break that
//! loop, [`connect_tcp_host`] consults an optionally-installed
//! `HostResolver` (typically backed by meow-rs's own `meow_dns::Resolver`
//! whose upstream sockets *are* protected) before falling back to the
//! system resolver.
//!
//! The `SocketProtector` (raw-fd) hook is compiled only on Android and
//! OpenHarmony (`target_env = "ohos"`) in production — the platforms whose
//! VPN model demands it. OpenHarmony is fail-closed: without a protector
//! [`connect_tcp`] / [`bind_udp`] refuse to open a socket, and hostname
//! lookups go to the embedder's bootstrap resolver
//! (`set_bootstrap_host_resolver`) instead of libc. For tests we
//! also enable it on any unix host so CI can exercise it against real
//! loopback sockets. The `HostResolver` hook carries no platform dependency
//! and is compiled everywhere: Android installs it alongside the protector,
//! iOS installs it on its own (the NE process needs the off-tunnel, async,
//! coalesced resolution but not raw-fd protection).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};

// ─── Host-resolver hook (cross-platform) ──────────────────────────────────
//
// Unlike the `SocketProtector` (which protects raw fds and is meaningful only
// inside Android's `VpnService` model — see the `android` module below), the
// hostname→IP hook is useful on every VPN platform. Routing a hostname dial
// through meow-rs's own `meow_dns::Resolver` (whose upstream sockets either
// bypass the tunnel or are protected) instead of libc's `getaddrinfo` gives
// us three things the system resolver can't: it never loops a lookup back
// through our own tunnel, it runs fully async (no blocking-pool thread per
// `getaddrinfo`, so a wake-time burst of dials can't exhaust the pool), and
// it coalesces + caches concurrent lookups for the same host. The registry
// itself carries no platform dependency, so it is compiled unconditionally;
// only the *installation* is platform-specific (Android JNI bridge / iOS FFI
// engine start).

/// Hostname → IP resolution hook consulted by [`connect_tcp_host`],
/// [`resolve_host`] and [`resolve_host_all`] whenever one is installed.
/// Typically backed by `meow_dns::ResolverHostHook`.
#[async_trait]
pub trait HostResolver: Send + Sync {
    /// Resolve `host` to one `IpAddr`. Returning `Err` aborts the dial.
    async fn resolve(&self, host: &str) -> io::Result<IpAddr>;

    /// Resolve `host` to all candidate addresses, in resolver order.
    ///
    /// Implementations that only support single-address lookup may rely on
    /// this default. Multi-address resolvers should override it so callers can
    /// fall back across families or stale endpoints before failing the dial.
    async fn resolve_all(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.resolve(host).await.map(|ip| vec![ip])
    }

    /// Resolve `host` using only answers the implementation already holds —
    /// static mappings, warm cache — without any lookup that could itself
    /// need an outbound dial.
    ///
    /// Consulted instead of [`Self::resolve_all`] when the hook is re-entered
    /// — a nameserver that dials a proxy to answer a query, for the very
    /// hostname that proxy is reached at. `None` means "nothing known", and the
    /// caller falls through to the system resolver. The default answers
    /// nothing, which is always safe.
    fn resolve_all_local(&self, host: &str) -> Option<Vec<IpAddr>> {
        let _ = host;
        None
    }
}

static RESOLVER: RwLock<Option<Arc<dyn HostResolver>>> = RwLock::new(None);

/// OpenHarmony's stand-in for the system resolver (see
/// [`set_bootstrap_host_resolver`]).
#[cfg(target_env = "ohos")]
static BOOTSTRAP_RESOLVER: RwLock<Option<Arc<dyn HostResolver>>> = RwLock::new(None);

/// Install the OpenHarmony bootstrap resolver: a lookup that runs on the
/// physical network (e.g. the embedder's `connection.getAddressesByName`
/// bound to the default net), not through the VPN.
///
/// On OpenHarmony [`connect_tcp_host`] never falls back to libc's
/// `getaddrinfo` — its DNS sockets cannot be protected and would loop through
/// the tunnel — so every lookup the [`HostResolver`] hook does not answer
/// (none installed yet, or a re-entrant lookup from inside the hook) goes
/// here instead, and fails with `NotConnected` while none is installed.
/// Only compiled for `target_env = "ohos"`.
#[cfg(target_env = "ohos")]
pub fn set_bootstrap_host_resolver(resolver: Arc<dyn HostResolver>) {
    *BOOTSTRAP_RESOLVER.write() = Some(resolver);
}

/// Remove the OpenHarmony bootstrap resolver, if any.
#[cfg(target_env = "ohos")]
pub fn clear_bootstrap_host_resolver() {
    *BOOTSTRAP_RESOLVER.write() = None;
}

/// Install the global host resolver. Call once at startup, right after the
/// meow-rs `Resolver` is built. Safe to re-install (e.g. config reload) — the
/// new resolver takes effect on the next hostname dial.
pub fn set_host_resolver(resolver: Arc<dyn HostResolver>) {
    *RESOLVER.write() = Some(resolver);
}

/// Remove the currently installed host resolver, if any. Subsequent
/// hostname dials fall back to the system resolver.
pub fn clear_host_resolver() {
    *RESOLVER.write() = None;
}

/// Snapshot of the currently-installed host resolver.
pub fn host_resolver() -> Option<Arc<dyn HostResolver>> {
    RESOLVER.read().clone()
}

tokio::task_local! {
    /// Set for the duration of a [`HostResolver`] call made from
    /// [`resolve_addrs`]. See [`in_host_resolver`] for why.
    static IN_HOST_RESOLVER: ();
}

/// True when the current task is already inside a [`HostResolver`] call.
///
/// The hook is backed by meow-rs's own `meow_dns::Resolver`, and a nameserver
/// may be tagged `#PROXY` — i.e. answering the query means dialing a proxy,
/// which means resolving *that* proxy's server hostname, which re-enters the
/// hook. If the two hostnames coincide (the usual case: the proxy carrying
/// DNS is the one being dialed) the resolver's single-flight `inflight` map
/// would make the inner lookup wait on the outer one, deadlocking the dial
/// until it times out. Detecting the re-entry and falling back to the system
/// resolver for the inner lookup breaks the cycle. The whole chain — hook →
/// resolver → DNS client → proxy dial → hook — runs on one task, so a
/// task-local is a precise fence: unrelated concurrent dials keep using the
/// configured DNS.
fn in_host_resolver() -> bool {
    IN_HOST_RESOLVER.try_with(|()| ()).is_ok()
}

tokio::task_local! {
    /// Set for the duration of a `proxy.dial_tcp` call made by a
    /// DNS-via-proxy exchange (`meow_dns::client::DnsClient`). See
    /// [`in_dns_via_proxy_dial`] for why.
    static IN_DNS_VIA_PROXY_DIAL: ();
}

/// True when the current task is inside a proxy dial issued by a
/// DNS-via-proxy exchange.
///
/// `IN_HOST_RESOLVER` only covers the `resolve_addrs` hook path: a
/// `#PROXY`-tagged nameserver whose adapter resolves its target through
/// `Resolver::resolve_ips` directly (e.g. `DirectAdapter`'s injected
/// resolver) is not inside a hook call, so the fence above cannot see the
/// re-entry. The DNS exchange therefore marks the whole `proxy.dial_tcp`
/// with this task-local; `Resolver::resolve_ips` checks it at entry and,
/// instead of running the upstream pipeline — whose single-flight
/// `inflight` entry the outer lookup may already hold — answers from
/// `resolve_ips_local` (`hosts:` + cache) and falls back to the system
/// resolver on a miss. `#DIRECT` + domain upstream stays a degraded
/// configuration (the proxy resolves locally anyway); IP-literal
/// upstreams are unaffected.
pub fn in_dns_via_proxy_dial() -> bool {
    IN_DNS_VIA_PROXY_DIAL.try_with(|()| ()).is_ok()
}

/// Run `fut` with the [`in_dns_via_proxy_dial`] task-local set — the DNS
/// client's counterpart of `resolve_via_hook`'s `IN_HOST_RESOLVER` scope.
pub async fn dns_via_proxy_dial_scope<F: std::future::Future>(fut: F) -> F::Output {
    IN_DNS_VIA_PROXY_DIAL.scope((), fut).await
}

// ─── Per-node dialer options (issue #974) ──────────────────────────────────
//
// mihomo's per-`proxies:`-entry dialer fields — `routing-mark`,
// `interface-name`, `ip-version`, `tfo`, `mptcp` — plus the new top-level
// `interface-name` global. The config layer parses each leaf's fields into
// a [`crate::NodeDialerOpts`] carried by its `WrappedProxy`, which resolves
// node-over-global at dial time and installs the result here as a
// task-local scope around the adapter call. The socket helpers below —
// `connect_tcp`, `bind_udp`/`bind_udp_for_peer`, `resolve_addrs` — read the
// scope through [`dialer_opts`], so every socket a dial opens gets the
// node's own options, including the WireGuard endpoint socket bound inside
// `ensure_pump` (spec-delta: no WG carve-out).
//
// The scope REPLACES on nesting: a `dialer-proxy` front hop installs its
// own options for the physical socket it opens, while the rear hop's
// handshake rides the stream the front already built — matching mihomo,
// where each hop's dialer options apply to the socket that hop opens.

/// The address-family selection mihomo spells `ip-version` on a
/// `proxies:` node (issue #974). Resolution-time only: an IP-literal
/// `server:`/destination never reaches the filter because resolution
/// short-circuits before it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IpVersion {
    /// Keep the resolver's order unchanged (`ip-version: dual`, default).
    #[default]
    Dual,
    /// IPv4 candidates only; the dial fails when resolution yields none.
    Ipv4,
    /// IPv6 candidates only; the dial fails when resolution yields none.
    Ipv6,
    /// IPv4 candidates first, IPv6 kept as fallback — a stable reorder,
    /// relative order inside each family preserved.
    Ipv4Prefer,
    /// IPv6 candidates first, IPv4 kept as fallback — likewise stable.
    Ipv6Prefer,
}

impl std::fmt::Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Dual => "dual",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Ipv4Prefer => "ipv4-prefer",
            Self::Ipv6Prefer => "ipv6-prefer",
        })
    }
}

impl IpVersion {
    /// The [`std::fmt::Display`] strings' inverse — `None` for anything outside the
    /// five mihomo spellings (the parser turns that into a hard config
    /// error, it does not silently default).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "dual" => Self::Dual,
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "ipv4-prefer" => Self::Ipv4Prefer,
            "ipv6-prefer" => Self::Ipv6Prefer,
            _ => return None,
        })
    }
}

/// The top-level globals a node's options resolve over: `routing-mark`
/// (the same `SO_MARK` [`set_routing_mark`] installs) and `interface-name`.
#[derive(Debug, Clone, Default)]
pub struct GlobalDialerOpts {
    /// The global `SO_MARK`; `0` normalizes to unset, as everywhere else.
    pub routing_mark: Option<u32>,
    /// The global interface binding. A node's own `interface-name` wins.
    pub interface_name: Option<Arc<str>>,
}

/// The installed global dialer options — `routing-mark` reads `0` as
/// unset (the same normalization the parser and [`set_routing_mark`]
/// share), `interface-name` from [`set_global_interface_name`].
pub fn global_dialer_opts() -> GlobalDialerOpts {
    GlobalDialerOpts {
        routing_mark: Some(routing_mark()).filter(|mark| *mark != 0),
        interface_name: global_interface_name(),
    }
}

/// The dial-time effective options: a node's [`crate::NodeDialerOpts`]
/// resolved over [`GlobalDialerOpts`], every field concrete. A
/// `WrappedProxy` computes this per dial and installs it via
/// [`dialer_opts_scope`]; the socket helpers read [`dialer_opts`].
#[derive(Debug, Clone, Default)]
pub struct DialerOpts {
    /// Effective `SO_MARK` — node mark when set, else the global mark.
    /// Linux-only; skipped with a one-time warning elsewhere.
    pub routing_mark: Option<u32>,
    /// Effective interface binding — node > global > TUN owner binding.
    /// Resolved name→index at dial time; loopback peers stay exempt.
    pub interface_name: Option<Arc<str>>,
    /// Resolution-time family selection applied inside `resolve_addrs`
    /// (and to `DirectAdapter`'s own resolver output).
    pub ip_version: IpVersion,
    /// `TCP_FASTOPEN_CONNECT` on the node's TCP sockets. Linux-only.
    pub tfo: bool,
    /// Build the node's TCP sockets as MPTCP (`IPPROTO_MPTCP`). Linux-only.
    pub mptcp: bool,
}

impl DialerOpts {
    /// Node fields over the globals — the node value wins wherever it set
    /// one, mihomo's per-node-over-`interface-name`/`routing-mark`
    /// shadowing (issue #974).
    pub fn resolve(node: &crate::adapter::NodeDialerOpts, global: &GlobalDialerOpts) -> Self {
        Self {
            routing_mark: node.routing_mark.or(global.routing_mark),
            interface_name: node
                .interface_name
                .clone()
                .or_else(|| global.interface_name.clone()),
            ip_version: node.ip_version,
            tfo: node.tfo,
            mptcp: node.mptcp,
        }
    }

    /// Whether the plain Tokio dial/bind paths must step aside for the
    /// `socket2` path: any option the fast path cannot express on the
    /// socket (`ip-version` never qualifies — it is resolution-time).
    pub fn needs_socket2(&self) -> bool {
        self.routing_mark.is_some() || self.interface_name.is_some() || self.tfo || self.mptcp
    }

    /// Fill still-unset fields from [`global_dialer_opts`], making an
    /// unscoped read see the globals a scoped value already resolved:
    /// provider fetches, DNS upstreams and the built-in DIRECT run no
    /// scope, but the global `interface-name`/`routing-mark` applies to
    /// them exactly as mihomo's does.
    fn with_global_fallbacks(mut self) -> Self {
        let global = global_dialer_opts();
        if self.routing_mark.is_none() {
            self.routing_mark = global.routing_mark;
        }
        if self.interface_name.is_none() {
            self.interface_name = global.interface_name;
        }
        self
    }
}

tokio::task_local! {
    /// The resolved [`DialerOpts`] a `WrappedProxy` installs around one
    /// adapter dial. Task-local so the front hop of a `dialer-proxy` chain
    /// scoping *its* physical dial never bleeds into the rear's handshake —
    /// and a nested scope replaces rather than merges (each hop resolves
    /// its own node-over-global).
    static DIALER_OPTS: DialerOpts;
}

/// The dial scope's resolved options, with the globals merged into any
/// unset slot. No scope = defaults plus globals — so the live
/// `routing-mark`/`interface-name` still reach every socket a scoped or
/// unscoped caller opens.
pub fn dialer_opts() -> DialerOpts {
    DIALER_OPTS
        .try_with(Clone::clone)
        .unwrap_or_default()
        .with_global_fallbacks()
}

/// Run `fut` under `opts`, replacing any enclosing scope.
pub async fn dialer_opts_scope<F: std::future::Future>(opts: DialerOpts, fut: F) -> F::Output {
    DIALER_OPTS.scope(opts, fut).await
}

// ─── System-resolver result cache (Android / iOS only) ─────────────────────
//
// Backstop for the path that still hits libc `getaddrinfo` (no `HostResolver`
// installed, or one that defers to the system). A proxy upstream is dialed
// once per outbound flow, so a wake-from-sleep burst would otherwise fire one
// blocking `getaddrinfo` per flow against the same hostname while the network
// path is still transitioning. Caching the resolved addresses for a short TTL
// collapses that burst to a single lookup. Gated to the VPN platforms so
// desktop / CI dial behaviour is byte-for-byte unchanged.

/// How long a system-resolver result is reused before re-querying.
#[cfg(any(target_os = "android", target_os = "ios"))]
const SYS_DNS_TTL: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(any(target_os = "android", target_os = "ios"))]
fn sys_dns_cache(
) -> &'static RwLock<std::collections::HashMap<String, (Vec<IpAddr>, std::time::Instant)>> {
    static C: std::sync::OnceLock<
        RwLock<std::collections::HashMap<String, (Vec<IpAddr>, std::time::Instant)>>,
    > = std::sync::OnceLock::new();
    C.get_or_init(|| RwLock::new(std::collections::HashMap::new()))
}

/// Cached system-resolver addresses for `host`, or `None` on miss/expiry.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn sys_cache_get(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let guard = sys_dns_cache().read();
    let (ips, at) = guard.get(host)?;
    if at.elapsed() > SYS_DNS_TTL {
        return None;
    }
    Some(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
}
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn sys_cache_get(_host: &str, _port: u16) -> Option<Vec<SocketAddr>> {
    None
}

/// Record a fresh system-resolver result for `host`.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn sys_cache_put(host: &str, addrs: &[SocketAddr]) {
    let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
    sys_dns_cache()
        .write()
        .insert(host.to_string(), (ips, std::time::Instant::now()));
}
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn sys_cache_put(_host: &str, _addrs: &[SocketAddr]) {}

/// Drop any cached entry for `host` (called when every candidate failed to
/// connect, so the next dial re-resolves instead of reusing a dead address).
#[cfg(any(target_os = "android", target_os = "ios"))]
fn sys_cache_evict(host: &str) {
    sys_dns_cache().write().remove(host);
}
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn sys_cache_evict(_host: &str) {}

// In production we only compile the protector hook on Android and
// OpenHarmony (`target_env = "ohos"`, whose VPN extension has the same
// per-fd `VpnConnection.protect(fd)` model) — the platforms whose VPN model
// demands it — and we don't want other binaries paying any footprint for it. For tests we additionally
// enable the module on any unix host so CI (which does not target Android)
// can actually exercise the protector path against real loopback sockets.
#[cfg(any(target_os = "android", target_env = "ohos", all(test, unix)))]
mod android {
    use super::*;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::Arc;

    use parking_lot::RwLock;

    /// Hook invoked on every outbound socket fd just before `connect()` /
    /// `bind()`. Typically a thin JNI shim around
    /// `android.net.VpnService.protect(int)`, or on OpenHarmony a NAPI shim
    /// around `VpnConnection.protect(fd)`.
    ///
    /// On OpenHarmony a dial or bind made while none is installed fails
    /// with `NotConnected` instead of opening an unprotected socket.
    ///
    /// Implementations must not block — the call runs on the async runtime
    /// worker that is dialing the socket.
    pub trait SocketProtector: Send + Sync {
        /// Protect `fd`. Returning `Err` aborts the connect/bind and the
        /// error propagates back to the caller.
        fn protect(&self, fd: RawFd) -> io::Result<()>;
    }

    static PROTECTOR: RwLock<Option<Arc<dyn SocketProtector>>> = RwLock::new(None);

    /// Install the global socket protector. Call once during VPN startup,
    /// before any proxy adapter dials.
    ///
    /// Re-installing is allowed (e.g. VPN tear-down / re-create); the new
    /// protector takes effect on the next outbound socket.
    pub fn set_socket_protector(protector: Arc<dyn SocketProtector>) {
        *PROTECTOR.write() = Some(protector);
    }

    /// Remove the currently installed protector, if any.
    pub fn clear_socket_protector() {
        *PROTECTOR.write() = None;
    }

    /// Snapshot of the currently-installed protector. Exposed so callers
    /// that build sockets through `socket2` directly (e.g. for `SO_MARK`)
    /// can still apply protect on the fd they own.
    pub fn socket_protector() -> Option<Arc<dyn SocketProtector>> {
        PROTECTOR.read().clone()
    }

    pub(super) async fn connect_tcp_protected(
        dest: SocketAddr,
        protector: &dyn SocketProtector,
    ) -> io::Result<TcpStream> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if dest.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        protector.protect(socket.as_raw_fd())?;
        socket.set_nonblocking(true)?;

        match socket.connect(&dest.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)?;
        stream.writable().await?;
        if let Some(err) = stream.take_error()? {
            return Err(err);
        }
        Ok(stream)
    }

    pub(super) fn bind_udp_protected(
        local: SocketAddr,
        protector: &dyn SocketProtector,
    ) -> io::Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if local.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        protector.protect(socket.as_raw_fd())?;
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;

        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
    }
}

#[cfg(any(target_os = "android", target_env = "ohos", all(test, unix)))]
pub use android::{
    clear_socket_protector, set_socket_protector, socket_protector, SocketProtector,
};

/// mihomo's `routing-mark` — `SO_MARK` on every outbound
/// socket meow opens through this module (proxy servers, DIRECT, DNS,
/// health checks, provider fetches, TCP and UDP), so the deployer's
/// TPROXY/REDIRECT rules can exempt meow's own traffic. `0` = unset.
/// OpenHarmony is `target_os = "linux"` too, but its dials go through the
/// VPN protector — every mark consumer below is `not(target_env = "ohos")`,
/// so the state itself is excluded there as well.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
static ROUTING_MARK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Install (or clear with `None` / `Some(0)`) the global routing mark.
/// Setting `SO_MARK` needs `CAP_NET_ADMIN`; without it outbound sockets
/// fail to open, as in mihomo. Linux only; a no-op elsewhere.
pub fn set_routing_mark(mark: Option<u32>) {
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    ROUTING_MARK.store(mark.unwrap_or(0), std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
    if mark.is_some_and(|m| m != 0) {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!("routing-mark (SO_MARK) is Linux-only; ignored on this platform");
        });
    }
}

/// The live routing mark (`0` = unset; always `0` off Linux).
pub fn routing_mark() -> u32 {
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    {
        ROUTING_MARK.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
    {
        0
    }
}

/// mihomo's top-level `interface-name` (issue #974): every outbound socket
/// meow opens binds to this interface unless the node's own
/// `interface-name` overrides it — and unless the socket's peer is
/// loopback, which stays exempt like the TUN owner binding. The name is
/// resolved to an index per dial (no cache), so a destroyed-and-recreated
/// interface is followed. `None`/`""` = unset. The state compiles on every
/// platform; the *binding* fails closed with `Unsupported` on platforms
/// without per-socket binding (iOS, the BSDs), matching
/// [`install_outbound_interface`]'s contract.
static GLOBAL_INTERFACE_NAME: RwLock<Option<Arc<str>>> = RwLock::new(None);

/// Install (or clear with `None`) the global `interface-name`.
pub fn set_global_interface_name(name: Option<Arc<str>>) {
    *GLOBAL_INTERFACE_NAME.write() = name;
}

/// The installed global `interface-name`, if any.
pub fn global_interface_name() -> Option<Arc<str>> {
    GLOBAL_INTERFACE_NAME.read().clone()
}

/// Holders of firewall rules that exempt the current routing mark (meow's
/// managed tproxy tables): while any is alive the mark cannot change at
/// runtime, or meow's own traffic would stop matching the exemption.
static ROUTING_MARK_PINS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Keeps the routing mark pinned until dropped (see [`routing_mark_pinned`]).
#[must_use = "the mark is pinned only while the guard lives"]
pub struct RoutingMarkPin(());

/// Pin the routing mark for the lifetime of the returned guard.
pub fn pin_routing_mark() -> RoutingMarkPin {
    ROUTING_MARK_PINS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    RoutingMarkPin(())
}

impl Drop for RoutingMarkPin {
    fn drop(&mut self) {
        ROUTING_MARK_PINS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Whether installed firewall rules exempt the current mark, so it must
/// not change before a restart.
pub fn routing_mark_pinned() -> bool {
    ROUTING_MARK_PINS.load(std::sync::atomic::Ordering::Relaxed) > 0
}

/// Dial an outbound TCP stream to an already-resolved [`SocketAddr`]. On
/// Android, applies the installed `SocketProtector` (if any) to the
/// socket fd before `connect()` so the connection bypasses the VPN.
/// Desktop targets apply the installed outbound-interface policy, on
/// Linux the `routing-mark` `SO_MARK` (see [`set_routing_mark`]), and on
/// all three the resolved per-node [`DialerOpts`] (issue #974).
///
/// Callers that only have a hostname must use [`connect_tcp_host`] —
/// passing a hostname here is a compile error by construction (the type
/// is `SocketAddr`, not `ToSocketAddrs`). That split exists to prevent
/// silent regressions back into the system resolver; see the module docs
/// for the loop-routing failure mode.
pub async fn connect_tcp(addr: SocketAddr) -> io::Result<TcpStream> {
    // Platforms without the socket2 dial path: an `interface-name` cannot
    // be honored — fail closed rather than dial unbound, ahead of the
    // protector early-return so even an Android-protected dial refuses to
    // silently skip it; the Linux-only knobs degrade to a one-time
    // warning like `set_routing_mark`'s.
    #[cfg(all(
        not(target_env = "ohos"),
        not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
    ))]
    reject_unsupported_dialer_opts(&dialer_opts())?;
    #[cfg(any(target_os = "android", target_env = "ohos", all(test, unix)))]
    {
        if let Some(p) = android::socket_protector() {
            return android::connect_tcp_protected(addr, p.as_ref()).await;
        }
    }
    #[cfg(target_env = "ohos")]
    return Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "OpenHarmony socket protector is not initialized",
    ));
    // TUN global-route loop avoidance (#375): when an outbound interface is
    // installed, bind the socket to it before connect() so the SYN already
    // takes the physical route past the TUN default routes. The resolved
    // dialer opts (mark/interface/tfo/mptcp — the live mark already folds
    // in through `dialer_opts()`) take the same socket2 path (issue #974).
    #[cfg(all(
        not(target_env = "ohos"),
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    {
        let opts = dialer_opts();
        if opts.needs_socket2()
            || (crate::outbound_iface::binds_peer(addr.ip())
                && crate::outbound_iface::outbound_interface().is_some())
        {
            return connect_tcp_with_opts(addr, &opts).await;
        }
    }
    #[cfg(not(target_env = "ohos"))]
    {
        TcpStream::connect(addr).await
    }
}

/// `connect_tcp`'s socket2 path — the resolved [`DialerOpts`]
/// (`routing-mark`, `interface-name`, `tfo`, `mptcp`; issue #974) applied
/// before `connect()`, alongside the global mark and the TUN owner
/// binding the fast-path check already routed through here.
/// `ip-version` never reaches this far — it filtered the resolution
/// upstream in `resolve_addrs`.
// Unused on OpenHarmony, whose dials fail closed without a protector.
#[cfg(all(
    not(target_env = "ohos"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
async fn connect_tcp_with_opts(addr: SocketAddr, opts: &DialerOpts) -> io::Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    // `opts.routing_mark` is the resolved mark — node mark when set, else
    // the global — so `Some` is exactly "this socket carries a mark".
    #[cfg(target_os = "linux")]
    let protocol = if opts.mptcp {
        socket2::Protocol::MPTCP
    } else {
        socket2::Protocol::TCP
    };
    #[cfg(not(target_os = "linux"))]
    let protocol = socket2::Protocol::TCP;
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(protocol))?;
    #[cfg(target_os = "linux")]
    if let Some(mark) = opts.routing_mark {
        socket.set_mark(mark)?;
    }
    #[cfg(target_os = "linux")]
    if opts.tfo {
        apply_tcp_fastopen_connect(&socket)?;
    }
    warn_linux_only_skipped(opts, true);
    apply_interface_binding(&socket, domain, addr.ip(), opts)?;
    socket.set_nonblocking(true)?;
    let tokio_socket = tokio::net::TcpSocket::from_std_stream(socket.into());
    tokio_socket.connect(addr).await
}

/// Compatibility shim for [`connect_tcp_with_opts`] under the options in
/// scope — the `outbound_iface` tests drive the bound path directly.
#[cfg(all(
    test,
    not(target_env = "ohos"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub(crate) async fn connect_tcp_iface_bound(addr: SocketAddr) -> io::Result<TcpStream> {
    connect_tcp_with_opts(addr, &dialer_opts()).await
}

/// `TCP_FASTOPEN_CONNECT`: the `connect()` itself carries the TFO cookie
/// request — the `sendmsg`-with-`MSG_FASTOPEN` shape is the alternative
/// and stays an open question (see the issue's spec notes). Linux-only;
/// a failure here fails the dial like the other socket options.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn apply_tcp_fastopen_connect(socket: &socket2::Socket) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let enable: libc::c_int = 1;
    // SAFETY: `socket` keeps the fd alive for the call and `enable` is the
    // int value `TCP_FASTOPEN_CONNECT` expects.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN_CONNECT,
            std::ptr::addr_of!(enable).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Off-Linux the three socket-level dialer options have no setsockopt to
/// land on: mihomo skips them silently there, but a silent miss is harder
/// to debug than one line — warn once per option instead. `tcp` gates
/// `tfo`/`mptcp`: both are TCP-only, so the UDP path never warns on them.
#[cfg(all(
    not(target_env = "ohos"),
    any(target_os = "macos", target_os = "windows")
))]
fn warn_linux_only_skipped(opts: &DialerOpts, tcp: bool) {
    use std::sync::Once;
    static MARK: Once = Once::new();
    static TFO: Once = Once::new();
    static MPTCP: Once = Once::new();
    if opts.routing_mark.is_some() {
        MARK.call_once(|| {
            tracing::warn!("routing-mark is Linux-only; the per-node mark is ignored");
        });
    }
    if tcp && opts.tfo {
        TFO.call_once(|| tracing::warn!("tfo is Linux-only; ignored on this platform"));
    }
    if tcp && opts.mptcp {
        MPTCP.call_once(|| tracing::warn!("mptcp is Linux-only; ignored on this platform"));
    }
}

/// On Linux every knob lands — nothing to warn about.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn warn_linux_only_skipped(_opts: &DialerOpts, _tcp: bool) {}

/// Platforms with no socket2 dial path at all: a configured
/// `interface-name` fails closed (`Unsupported`), matching
/// [`install_outbound_interface`]'s posture; the Linux-only knobs warn
/// once and are skipped, as on macOS/Windows.
#[cfg(all(
    not(target_env = "ohos"),
    not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
))]
fn reject_unsupported_dialer_opts(opts: &DialerOpts) -> io::Result<()> {
    if let Some(name) = &opts.interface_name {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("interface-name '{name}' is not supported on this platform"),
        ));
    }
    if opts.routing_mark.is_some() || opts.tfo || opts.mptcp {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "per-node dialer options (routing-mark/tfo/mptcp) are not supported \
                 on this platform; ignored"
            );
        });
    }
    Ok(())
}

/// Interface binding shared by the TCP/UDP socket2 paths. An explicit
/// `interface-name` — node first, global otherwise — wins over the TUN
/// owner binding; a loopback peer stays unbound either way, the same
/// exemption `binds_peer` gives the TUN path (a socket scoped to a
/// physical interface cannot reach a loopback peer, and localhost dials
/// — external SIP003 plugin endpoints, test fixtures — must keep working).
#[cfg(all(
    not(target_env = "ohos"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn apply_interface_binding(
    socket: &socket2::Socket,
    domain: socket2::Domain,
    peer: IpAddr,
    opts: &DialerOpts,
) -> io::Result<()> {
    match &opts.interface_name {
        Some(name) if crate::outbound_iface::binds_peer(peer) => {
            crate::outbound_iface::bind_socket_to_name(socket, domain, name)
        }
        Some(_) => Ok(()),
        None => crate::outbound_iface::apply_outbound_interface_for_peer(socket, domain, peer),
    }
}

/// Single resolution chokepoint shared by [`connect_tcp_host`],
/// [`resolve_host`] and [`resolve_host_all`]. Resolution order:
///
/// 1. IP literal → returned verbatim (no lookup, no hook).
/// 2. Installed [`HostResolver`] (e.g. `meow_dns::ResolverHostHook`) → all
///    addresses it knows about. Preferred on every platform when present: it
///    runs async (no blocking-pool `getaddrinfo`), caches + coalesces
///    concurrent lookups, and on a VPN-active device its upstream sockets
///    don't loop the query back through our own tunnel. Consulted
///    independently of whether a `SocketProtector` is installed — iOS uses
///    the resolver hook without a protector.
///    Skipped when the call is itself nested inside a hook call (see
///    [`in_host_resolver`]).
/// 3. Short-TTL cache of prior system-resolver results (Android / iOS only)
///    → collapses a wake-time burst of dials to one `getaddrinfo`.
/// 4. System resolver (`tokio::net::lookup_host`), result cached.
///
/// Never returns an empty `Vec`.
async fn resolve_addrs(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    // `metadata_ip_literal` folds bracketed IPv6 display forms (`[::1]`)
    // into the literal — a `server:`/`BND.ADDR` string may arrive in that
    // shape and must not fall through to DNS (issue #701). The literal
    // also bypasses `ip-version`: it is not resolution output.
    if let Some(ip) = crate::metadata_ip_literal(host) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    // Every resolution path — hook, hook re-entry, system — converges here
    // so the scope's `ip-version` filter applies once to them all
    // (spec-delta for issue #974: the hook path must not escape it).
    let addrs = match host_resolver() {
        Some(r) if in_host_resolver() => {
            // Re-entered: answer from what the hook already knows, and only
            // fall through to the system resolver when it knows nothing.
            match r.resolve_all_local(host).filter(|ips| !ips.is_empty()) {
                Some(ips) => ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect(),
                None => {
                    tracing::debug!(
                        host,
                        "resolve: re-entrant host-resolver call (a DNS upstream dials through a \
                         proxy) — using the system resolver for this hop to avoid a lookup cycle"
                    );
                    resolve_addrs_system(host, port).await?
                }
            }
        }
        Some(r) => resolve_via_hook(r.as_ref(), host, port).await?,
        None => resolve_addrs_system(host, port).await?,
    };

    apply_ip_version_filter(addrs, dialer_opts().ip_version)
        .map_err(|e| io::Error::new(e.kind(), format!("resolve {host}:{port}: {e}")))
}

/// Apply `version`'s family selection to resolved `addrs` (mihomo
/// `ip-version`, issue #974): `dual` keeps resolver order; the exact
/// modes keep one family and error when none remain; the `prefer` modes
/// stable-sort that family first — relative order inside each family
/// preserved, and an empty result is still an error. `to_canonical`
/// classifies IPv4-mapped IPv6 addresses as IPv4, the same fold
/// `bind_udp_for_peer`/`canonical_socket_addr` use downstream.
///
/// Public so `DirectAdapter::resolve_targets` applies the same filter to
/// its own resolver view (the `type: direct` node's *target* hostname,
/// where `ip-version` selects the egress family, not the server).
pub fn apply_ip_version_filter(
    addrs: Vec<SocketAddr>,
    version: IpVersion,
) -> io::Result<Vec<SocketAddr>> {
    if version == IpVersion::Dual {
        return Ok(addrs);
    }
    let v4 = matches!(version, IpVersion::Ipv4 | IpVersion::Ipv4Prefer);
    let (primary, secondary): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs
        .into_iter()
        .partition(|addr| addr.ip().to_canonical().is_ipv4() == v4);
    let filtered: Vec<SocketAddr> = match version {
        IpVersion::Ipv4 | IpVersion::Ipv6 => primary,
        _ => primary.into_iter().chain(secondary).collect(),
    };
    if filtered.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("ip-version {version}: no matching address family"),
        ));
    }
    Ok(filtered)
}

/// The system-resolver tail of [`resolve_addrs`]: warm single-flight cache,
/// then `tokio::net::lookup_host` (OpenHarmony substitutes the bootstrap
/// hook — libc's resolver sockets cannot be protected), then cache the
/// answer. Never returns an empty `Vec`.
async fn resolve_addrs_system(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Some(cached) = sys_cache_get(host, port) {
        return Ok(cached);
    }

    // Not on OpenHarmony: it never falls back to the system resolver.
    #[cfg(all(not(target_env = "ohos"), any(target_os = "android", all(test, unix))))]
    {
        if android::socket_protector().is_some() {
            tracing::warn!(
                host,
                "resolve: protector installed but no HostResolver — falling back \
                 to system resolver, which may loop DNS through the VPN"
            );
        }
    }

    // OpenHarmony: libc's resolver sockets cannot be protected, so the
    // embedder's physical-network resolver stands in for it (fail-closed).
    #[cfg(target_env = "ohos")]
    let addrs: Vec<SocketAddr> = {
        let bootstrap = BOOTSTRAP_RESOLVER.read().clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "OpenHarmony bootstrap resolver is not initialized",
            )
        })?;
        resolve_via_hook(bootstrap.as_ref(), host, port).await?
    };
    #[cfg(not(target_env = "ohos"))]
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("resolve: no address for {host}:{port}"),
        ));
    }
    sys_cache_put(host, &addrs);
    Ok(addrs)
}

/// `resolve_addrs` for a caller-supplied [`HostResolver`] rather than the
/// installed global hook — e.g. an adapter carrying its own injected
/// resolver (the WireGuard endpoint lookup). The lookup runs under the same
/// `IN_HOST_RESOLVER` scope `resolve_via_hook` applies to the global
/// hook: an *unscoped* `resolve_all` would let a `#PROXY`-tagged nameserver
/// inside the hook re-enter this very dial and deadlock on the resolver's
/// single-flight map (see `in_host_resolver`). A re-entrant call answers
/// from `resolve_all_local` — what the hook already holds — then falls back
/// to the system resolver, matching `resolve_addrs`'s re-entry arm. Literal
/// hosts short-circuit before any hook, also as `resolve_addrs` does.
pub async fn resolve_host_all_via(
    r: &dyn HostResolver,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    if let Some(ip) = crate::metadata_ip_literal(host) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs = if in_host_resolver() {
        match r.resolve_all_local(host).filter(|ips| !ips.is_empty()) {
            Some(ips) => ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
            None => {
                tracing::debug!(
                    host,
                    "resolve: re-entrant resolver call — using the system resolver for this \
                     hop to avoid a lookup cycle"
                );
                resolve_addrs_system(host, port).await?
            }
        }
    } else {
        resolve_via_hook(r, host, port).await?
    };
    // The injected-resolver path resolves the same node-level names
    // `resolve_addrs` does (the WireGuard endpoint), so the dial scope's
    // `ip-version` filters it identically (issue #974).
    apply_ip_version_filter(addrs, dialer_opts().ip_version)
        .map_err(|e| io::Error::new(e.kind(), format!("resolve {host}:{port}: {e}")))
}

/// Run one [`HostResolver`] lookup with [`IN_HOST_RESOLVER`] set, so a dial
/// made while answering it takes the system-resolver path instead of
/// re-entering the hook.
async fn resolve_via_hook(
    r: &dyn HostResolver,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let ips = IN_HOST_RESOLVER.scope((), r.resolve_all(host)).await?;
    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("resolve: no address for {host}:{port}"),
        ));
    }
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

/// Dial an outbound TCP stream to `host:port`. The hostname is resolved
/// through `resolve_addrs` (installed `HostResolver` → cache → system
/// resolver). Address families race after a 250 ms fallback delay, retaining
/// resolver order within each family. Each candidate uses [`connect_tcp`] so the
/// `SocketProtector` (Android) still applies. If every candidate fails to
/// connect, any cached system-resolver entry is evicted so the next dial
/// re-resolves instead of reusing a dead address.
///
/// IP literals short-circuit inside `resolve_addrs` — no resolver hook is
/// consulted, but the protector still applies to the literal dial.
pub async fn connect_tcp_host(host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs = resolve_addrs(host, port).await?;
    let result = connect_tcp_candidates(addrs, connect_tcp).await;
    if result.is_err() {
        sys_cache_evict(host);
    }
    result
}

/// Connect resolved physical addresses using the caller's existing dial budget.
/// With a deadline, at most two attempts run at once and later addresses receive
/// a share of the remaining time. Without a deadline, preserve the ordinary
/// two-family fallback without introducing a new overall timeout. Callers must
/// retain their socket protection/binding and configured per-connect timeout —
/// under a deadline that per-connect timeout is a ceiling the fairness window
/// may tighten, so no candidate is guaranteed its full configured slice.
pub async fn connect_tcp_candidates<T, F, Fut>(addrs: Vec<SocketAddr>, dial: F) -> io::Result<T>
where
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    match crate::dial::dial_deadline() {
        Some(deadline) => connect_candidates_before(addrs, deadline, dial).await,
        None => connect_resolved_candidates(addrs, dial).await,
    }
}

async fn connect_candidates_before<T, F, Fut>(
    addrs: Vec<SocketAddr>,
    deadline: tokio::time::Instant,
    mut dial: F,
) -> io::Result<T>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    use futures::{stream::FuturesUnordered, StreamExt};
    use tokio::time::{sleep_until, timeout_at, Duration, Instant};
    const STAGGER: Duration = Duration::from_millis(250);
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
    let first_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
    let (mut first, mut other): (std::collections::VecDeque<_>, std::collections::VecDeque<_>) =
        addrs
            .into_iter()
            .partition(|addr| addr.is_ipv6() == first_v6);
    let mut ordered = std::collections::VecDeque::new();
    while !first.is_empty() || !other.is_empty() {
        if let Some(addr) = first.pop_front() {
            ordered.push_back(addr);
        }
        if let Some(addr) = other.pop_front() {
            ordered.push_back(addr);
        }
    }
    // All attempts belong to this one future. Once the queue is drained,
    // slicing no longer needs to free a slot: survivors can use the rest of
    // the caller budget. Atomic storage keeps the enclosing future Send.
    let all_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut pending = FuturesUnordered::new();
    let mut next = Instant::now();
    let mut last_err = None;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(last_err.unwrap_or_else(|| io::ErrorKind::TimedOut.into()));
        }
        if pending.is_empty() || (pending.len() < 2 && now >= next) {
            let waves = (pending.len() + ordered.len()).div_ceil(2).max(1);
            let window = (deadline - now).div_f64(waves as f64).min(ATTEMPT_TIMEOUT);
            if let Some(addr) = ordered.pop_front() {
                let attempt = dial(addr);
                let attempt_deadline = (now + window).min(deadline);
                all_started.store(ordered.is_empty(), std::sync::atomic::Ordering::Relaxed);
                let all_started = Arc::clone(&all_started);
                pending.push(async move {
                    tokio::pin!(attempt);
                    match timeout_at(attempt_deadline, &mut attempt).await {
                        Ok(result) => result,
                        Err(_) if all_started.load(std::sync::atomic::Ordering::Relaxed) => {
                            // Keep the original connect future; never restart a socket.
                            attempt.await
                        }
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "TCP candidate timed out",
                        )),
                    }
                });
                // Compress staggering for a nearly exhausted caller budget;
                // reserve time for the remaining addresses rather than sleeping
                // through their entire opportunity.
                next = now + STAGGER.min((deadline - now).div_f64((ordered.len() + 1) as f64));
            } else if pending.is_empty() {
                return Err(last_err.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "no TCP candidate addresses")
                }));
            }
        }
        tokio::select! {
            () = sleep_until(deadline) => return Err(last_err.unwrap_or_else(|| io::ErrorKind::TimedOut.into())),
            result = pending.next(), if !pending.is_empty() => {
                match result.expect("pending candidate") {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_err = crate::MeowError::prefer_errno_io(last_err, error),
                }
                next = Instant::now();
            }
            () = sleep_until(next), if pending.len() < 2 && !ordered.is_empty() => {}
        }
    }
}

// Race address families, not protocol handshakes. Each family retains resolver
// order and has at most one physical connect pending. No spawned task can
// outlive the caller; returning a winner drops the other family's future.
async fn connect_resolved_candidates<T, F, Fut>(addrs: Vec<SocketAddr>, dial: F) -> io::Result<T>
where
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let first_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
    let (preferred, fallback): (Vec<_>, Vec<_>) = addrs
        .into_iter()
        .partition(|addr| addr.is_ipv6() == first_v6);
    if fallback.is_empty() {
        return connect_address_family(preferred, &dial).await;
    }
    let first = connect_address_family(preferred, &dial);
    tokio::pin!(first);
    // A failed preferred family starts fallback immediately. Otherwise allow
    // it 250 ms before racing the other family under the caller's deadline.
    tokio::select! {
        biased;
        result = &mut first => {
            return match result {
                Ok(stream) => Ok(stream),
                Err(error) => connect_address_family(fallback, &dial)
                    .await
                    .map_err(|other| {
                        crate::MeowError::prefer_errno_io(Some(error), other)
                            .expect("prefer_errno_io yields Some for a Some prev")
                    }),
            };
        }
        () = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
    }
    let second = connect_address_family(fallback, &dial);
    tokio::pin!(second);
    tokio::select! {
        biased;
        result = &mut first => match result {
            Ok(stream) => Ok(stream),
            Err(error) => second.await.map_err(|other| {
                crate::MeowError::prefer_errno_io(Some(error), other)
                    .expect("prefer_errno_io yields Some for a Some prev")
            }),
        },
        result = &mut second => match result {
            Ok(stream) => Ok(stream),
            Err(error) => first.await.map_err(|other| {
                crate::MeowError::prefer_errno_io(Some(error), other)
                    .expect("prefer_errno_io yields Some for a Some prev")
            }),
        },
    }
}

async fn connect_address_family<T, F, Fut>(addrs: Vec<SocketAddr>, dial: &F) -> io::Result<T>
where
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let mut last_err = None;
    for addr in addrs {
        match dial(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_err = crate::MeowError::prefer_errno_io(last_err, error),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "connect_tcp_host: no addresses resolved",
        )
    }))
}

/// Resolve `host` to a single [`SocketAddr`] (the first candidate from
/// [`resolve_host_all`]).
///
/// Prefer [`resolve_host_all`] for call sites that can try candidates in
/// order (e.g. a UDP `connect()` loop): taking only the first address
/// silently drops the family fallback that `TcpStream::connect` gets for
/// free, which strands the caller on an unreachable family when the
/// resolver orders AAAA first on an IPv4-only network (or vice versa).
pub async fn resolve_host(host: &str, port: u16) -> io::Result<SocketAddr> {
    resolve_host_all(host, port).await.map(|addrs| addrs[0])
}

/// Resolve `host` to every candidate [`SocketAddr`], in resolver order,
/// via `resolve_addrs`. Never returns an empty `Vec` — no-address
/// resolution is an `Err`, so callers may index `[0]` safely.
pub async fn resolve_host_all(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    resolve_addrs(host, port).await
}

/// Bind an outbound UDP socket to `local`. On Android, applies the
/// installed `SocketProtector` (if any) to the socket fd before `bind()`.
/// Desktop targets apply the installed outbound-interface binding, which is
/// decided by the **local** address: only a socket pinned to a loopback
/// address is left unbound, so a wildcard bind is always bound. Sockets that
/// know their peer should use [`bind_udp_for_peer`] instead.
pub async fn bind_udp<A: ToSocketAddrs>(local: A) -> io::Result<UdpSocket> {
    bind_udp_with_peer(local, None).await
}

/// Bind an outbound wildcard UDP socket for traffic to `peer`. Like
/// [`bind_udp`], but the socket's family and the outbound-interface binding
/// follow the **peer**: a loopback peer is left unbound, so it stays
/// reachable under global route scope (the binding would make the send fail
/// with `EADDRNOTAVAIL` / `WSAEADDRNOTAVAIL`).
///
/// An IPv4-mapped `peer` gets an IPv4 socket, so the caller must send to /
/// `connect()` the [`canonical_socket_addr`] of its destination.
pub async fn bind_udp_for_peer(peer: IpAddr) -> io::Result<UdpSocket> {
    let peer = peer.to_canonical();
    let local = match peer {
        IpAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
    };
    bind_udp_with_peer(SocketAddr::new(local, 0), Some(peer)).await
}

/// `addr` with an IPv4-mapped IPv6 address (`[::ffff:a.b.c.d]:p`) turned
/// into plain IPv4 (`a.b.c.d:p`), the form a [`bind_udp_for_peer`] socket
/// can reach. Native IPv6 addresses — scope id and flow info included — and
/// IPv4 addresses come back unchanged.
pub fn canonical_socket_addr(mut addr: SocketAddr) -> SocketAddr {
    // `set_ip` keeps the scope id for a V6 → V6 change and rebuilds the
    // address only on a family change (mapped → V4, which has no scope).
    addr.set_ip(addr.ip().to_canonical());
    addr
}

/// The receive buffer quic-go asks for. The OS default (about 208 KiB on
/// Linux) overflows whenever a reader falls a few milliseconds behind a
/// fast download, and each dropped datagram is a loss the sender must
/// detect and resend.
const UDP_RECV_BUFFER_BYTES: usize = 7 << 20;

/// Grow a UDP socket's receive buffer, best effort — for QUIC endpoint
/// sockets and the UDP associations that carry them: every datagram the
/// kernel drops at a full receive buffer is a loss the transport must
/// detect and resend, so the association's kernel queue gets the same
/// headroom as the raw path's. Linux caps the request at
/// `net.core.rmem_max`, so a privileged meow forces it past the cap as
/// quic-go does; macOS rejects a size above `kern.ipc.maxsockbuf`, so the
/// request halves until one is taken. The send buffer keeps the OS
/// default: the driver does not pace, and a full send buffer is what holds
/// its bursts back from the interface queue.
pub fn enlarge_udp_recv_buffer(socket: &UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let mut size = UDP_RECV_BUFFER_BYTES;
    while size >= 1 << 20 && sock.set_recv_buffer_size(size).is_err() {
        size /= 2;
    }
    // getsockopt reports twice the size taken on Linux.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if sock
        .recv_buffer_size()
        .is_ok_and(|got| got < 2 * UDP_RECV_BUFFER_BYTES)
    {
        force_recv_buffer(socket);
    }
    tracing::debug!(size = ?sock.recv_buffer_size(), "udp socket receive buffer");
}

/// `SO_RCVBUFFORCE` needs `CAP_NET_ADMIN`, so it fails harmlessly (EPERM)
/// for an unprivileged meow.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn force_recv_buffer(socket: &UdpSocket) {
    use std::os::fd::AsRawFd;
    let size = UDP_RECV_BUFFER_BYTES as libc::c_int;
    // SAFETY: the socket stays open for the call, and the option value is a
    // c_int of the size passed.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            std::ptr::addr_of!(size).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

async fn bind_udp_with_peer<A: ToSocketAddrs>(
    local: A,
    peer: Option<IpAddr>,
) -> io::Result<UdpSocket> {
    // Only the interface-bound path below consults the peer.
    #[cfg(not(all(
        not(target_env = "ohos"),
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    )))]
    let _ = peer;
    // Ahead of the protector early-return for the same reason as
    // `connect_tcp`: an `interface-name` the platform cannot honor must
    // fail closed, not dial unbound.
    #[cfg(all(
        not(target_env = "ohos"),
        not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
    ))]
    reject_unsupported_dialer_opts(&dialer_opts())?;
    #[cfg(any(target_os = "android", target_env = "ohos", all(test, unix)))]
    {
        if let Some(p) = android::socket_protector() {
            let resolved = tokio::net::lookup_host(local)
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "bind_udp: no address resolved")
                })?;
            return android::bind_udp_protected(resolved, p.as_ref());
        }
    }
    #[cfg(target_env = "ohos")]
    return Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "OpenHarmony socket protector is not initialized",
    ));
    // TUN global-route loop avoidance (#375): bind the socket to the
    // installed outbound interface before the local-address bind, mirroring
    // `connect_tcp` — so the first datagram already bypasses the TUN routes.
    // The resolved dialer opts (mark/interface; issue #974 — `tfo`/`mptcp`
    // are TCP-only) take the same socket2 path.
    #[cfg(all(
        not(target_env = "ohos"),
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    {
        let opts = dialer_opts();
        if opts.needs_socket2() || crate::outbound_iface::outbound_interface().is_some() {
            let resolved = tokio::net::lookup_host(local)
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "bind_udp: no address resolved")
                })?;
            return bind_udp_with_opts(resolved, peer.unwrap_or(resolved.ip()), &opts);
        }
    }
    #[cfg(not(target_env = "ohos"))]
    {
        UdpSocket::bind(local).await
    }
}

/// `bind_udp_with_peer`'s socket2 path — the resolved [`DialerOpts`]
/// (`routing-mark`, `interface-name`; issue #974) applied before the
/// local-address bind, alongside the TUN owner binding the fast-path check
/// already routed here. `peer` decides the loopback exemption, exactly as
/// the installed-binding path's does. `tfo`/`mptcp` are TCP-only — they
/// never apply (nor warn) on a datagram socket.
// Unused on OpenHarmony, whose dials fail closed without a protector.
#[cfg(all(
    not(target_env = "ohos"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn bind_udp_with_opts(local: SocketAddr, peer: IpAddr, opts: &DialerOpts) -> io::Result<UdpSocket> {
    let domain = if local.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    #[cfg(target_os = "linux")]
    if let Some(mark) = opts.routing_mark {
        socket.set_mark(mark)?;
    }
    warn_linux_only_skipped(opts, false);
    apply_interface_binding(&socket, domain, peer, opts)?;
    socket.bind(&local.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Compatibility shim for [`bind_udp_with_opts`] under the options in
/// scope — the `outbound_iface` tests drive the bound path directly.
#[cfg(all(
    test,
    not(target_env = "ohos"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub(crate) fn bind_udp_iface_bound(local: SocketAddr, peer: IpAddr) -> io::Result<UdpSocket> {
    bind_udp_with_opts(local, peer, &dialer_opts())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::os::fd::RawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;

    /// Records every fd handed to it; never fails.
    struct Counting {
        count: AtomicUsize,
        seen_fds: parking_lot::Mutex<Vec<RawFd>>,
    }
    impl Counting {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                count: AtomicUsize::new(0),
                seen_fds: parking_lot::Mutex::new(Vec::new()),
            })
        }
        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }
    impl SocketProtector for Counting {
        fn protect(&self, fd: RawFd) -> io::Result<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.seen_fds.lock().push(fd);
            Ok(())
        }
    }

    /// Always errors — used to verify failure propagation.
    struct Failing;
    impl SocketProtector for Failing {
        fn protect(&self, _fd: RawFd) -> io::Result<()> {
            Err(io::Error::other("protect denied"))
        }
    }

    /// Counts every resolver call and returns fixed `IpAddr` candidates.
    struct FixedResolver {
        ips: Vec<IpAddr>,
        count: AtomicUsize,
        last_host: parking_lot::Mutex<Option<String>>,
    }
    impl FixedResolver {
        fn new(ip: IpAddr) -> Arc<Self> {
            Self::new_all(vec![ip])
        }

        fn new_all(ips: Vec<IpAddr>) -> Arc<Self> {
            Arc::new(Self {
                ips,
                count: AtomicUsize::new(0),
                last_host: parking_lot::Mutex::new(None),
            })
        }
        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
        fn last_host(&self) -> Option<String> {
            self.last_host.lock().clone()
        }
    }
    #[async_trait]
    impl HostResolver for FixedResolver {
        async fn resolve(&self, host: &str) -> io::Result<IpAddr> {
            self.count.fetch_add(1, Ordering::SeqCst);
            *self.last_host.lock() = Some(host.to_string());
            self.ips
                .first()
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no fixed address"))
        }

        async fn resolve_all(&self, host: &str) -> io::Result<Vec<IpAddr>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            *self.last_host.lock() = Some(host.to_string());
            Ok(self.ips.clone())
        }
    }

    /// Errors on every `resolve`.
    struct FailingResolver;
    #[async_trait]
    impl HostResolver for FailingResolver {
        async fn resolve(&self, _host: &str) -> io::Result<IpAddr> {
            Err(io::Error::other("resolve denied"))
        }

        async fn resolve_all(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            Err(io::Error::other("resolve denied"))
        }
    }

    /// Tracks the order of calls — used to verify protect runs BEFORE
    /// connect/bind. The fd argument must already be a valid (created) socket
    /// when protect is called, but the kernel `connect()` syscall must not
    /// have fired yet. We approximate this by observing that the fd is open
    /// (`fcntl(F_GETFD)` succeeds) but `getpeername` returns ENOTCONN.
    struct OrderingProbe {
        was_pre_connect: parking_lot::Mutex<Option<bool>>,
    }
    impl OrderingProbe {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                was_pre_connect: parking_lot::Mutex::new(None),
            })
        }
        fn was_pre_connect(&self) -> Option<bool> {
            *self.was_pre_connect.lock()
        }
    }
    impl SocketProtector for OrderingProbe {
        fn protect(&self, fd: RawFd) -> io::Result<()> {
            // SAFETY: fd is owned by the caller (still in socket2 wrapper);
            // F_GETFD doesn't mutate state, getpeername reads kernel state.
            let fd_open = unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1;
            let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&sa) as libc::socklen_t;
            let getpeer = unsafe {
                libc::getpeername(fd, &mut sa as *mut _ as *mut libc::sockaddr, &mut len)
            };
            let not_yet_connected = getpeer == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTCONN);
            *self.was_pre_connect.lock() = Some(fd_open && not_yet_connected);
            Ok(())
        }
    }

    /// Serialise tests that touch the process-global protector — they would
    /// otherwise race each other and corrupt count assertions. `tokio::sync`
    /// (not `parking_lot`) so the guard can be held across `.await`.
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    // ─── connect_tcp ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn no_protector_falls_back_to_plain_tokio() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let stream = connect_tcp(addr).await.expect("connect");
        let _ = accept.await.unwrap();
        // Round-trips like a normal stream.
        drop(stream);
    }

    #[tokio::test]
    async fn connect_tcp_invokes_protector_against_real_listener() {
        let _g = LOCK.lock().await;
        let counter = Counting::new();
        set_socket_protector(Arc::clone(&counter) as Arc<dyn SocketProtector>);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let stream = connect_tcp(addr).await.expect("connect");
        let _ = accept.await.unwrap();
        drop(stream);
        assert_eq!(counter.count(), 1, "protector must be called exactly once");
        clear_socket_protector();
    }

    #[tokio::test]
    async fn connect_tcp_propagates_protector_failure() {
        let _g = LOCK.lock().await;
        set_socket_protector(Arc::new(Failing) as Arc<dyn SocketProtector>);
        // Real listener so the error can only come from the protector, not
        // a network error masquerading as one.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let err = connect_tcp(addr).await.expect_err("protect should fail");
        assert!(err.to_string().contains("protect denied"), "{err}");
        clear_socket_protector();
    }

    #[tokio::test]
    async fn protect_runs_before_connect_syscall() {
        let _g = LOCK.lock().await;
        let probe = OrderingProbe::new();
        set_socket_protector(Arc::clone(&probe) as Arc<dyn SocketProtector>);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _stream = connect_tcp(addr).await.expect("connect");
        let _ = accept.await.unwrap();
        assert_eq!(
            probe.was_pre_connect(),
            Some(true),
            "fd must be open but not-yet-connected at the moment protect() runs — \
             this is the invariant Android's VpnService.protect relies on"
        );
        clear_socket_protector();
    }

    // ─── connect_tcp_host ────────────────────────────────────────────────────

    #[tokio::test]
    async fn connect_tcp_host_with_ip_literal_skips_resolver() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        clear_host_resolver();
        // Install a resolver that would fail if it were called — proving
        // the IP-literal short-circuit really did skip it.
        set_host_resolver(Arc::new(FailingResolver) as Arc<dyn HostResolver>);
        let counter = Counting::new();
        set_socket_protector(Arc::clone(&counter) as Arc<dyn SocketProtector>);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _stream = connect_tcp_host("127.0.0.1", port).await.expect("connect");
        let _ = accept.await.unwrap();
        assert_eq!(counter.count(), 1, "protector still applies to literal");

        clear_socket_protector();
        clear_host_resolver();
    }

    /// Issue #701: a bracketed IPv6 display form (`server: "[::1]"`) must
    /// fold to the literal inside `resolve_addrs` — never reach the
    /// resolver, which would fail on the bracketed "domain".
    #[tokio::test]
    async fn connect_tcp_host_with_bracketed_ipv6_literal_skips_resolver() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        clear_host_resolver();
        set_host_resolver(Arc::new(FailingResolver) as Arc<dyn HostResolver>);

        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _stream = connect_tcp_host("[::1]", port).await.expect("connect");
        let _ = accept.await.unwrap();

        clear_host_resolver();
    }

    #[tokio::test]
    async fn connect_tcp_host_uses_installed_resolver_when_protected() {
        let _g = LOCK.lock().await;
        let counter = Counting::new();
        set_socket_protector(Arc::clone(&counter) as Arc<dyn SocketProtector>);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let resolver = FixedResolver::new_all(vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::from([127, 0, 0, 1]),
        ]);
        set_host_resolver(Arc::clone(&resolver) as Arc<dyn HostResolver>);

        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _stream = connect_tcp_host("example.invalid", port)
            .await
            .expect("connect");
        let _ = accept.await.unwrap();

        assert_eq!(resolver.count(), 1, "resolver must be consulted once");
        assert_eq!(resolver.last_host().as_deref(), Some("example.invalid"));
        assert_eq!(
            counter.count(),
            2,
            "protector must apply to each resolved connect candidate"
        );

        clear_host_resolver();
        clear_socket_protector();
    }

    #[tokio::test]
    async fn connect_tcp_host_propagates_resolver_failure() {
        let _g = LOCK.lock().await;
        let counter = Counting::new();
        set_socket_protector(Arc::clone(&counter) as Arc<dyn SocketProtector>);
        set_host_resolver(Arc::new(FailingResolver) as Arc<dyn HostResolver>);

        let err = connect_tcp_host("example.invalid", 80)
            .await
            .expect_err("resolver should fail");
        assert!(err.to_string().contains("resolve denied"), "{err}");

        clear_host_resolver();
        clear_socket_protector();
    }

    #[tokio::test]
    async fn connect_tcp_host_without_protector_uses_plain_tokio() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        clear_host_resolver();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _stream = connect_tcp_host("127.0.0.1", port).await.expect("connect");
        let _ = accept.await.unwrap();
    }

    // ─── bind_udp ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn bind_udp_invokes_protector() {
        let _g = LOCK.lock().await;
        let counter = Counting::new();
        set_socket_protector(Arc::clone(&counter) as Arc<dyn SocketProtector>);
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sock = bind_udp(addr).await.expect("bind");
        assert!(sock.local_addr().unwrap().port() != 0);
        assert_eq!(counter.count(), 1);
        let peer_sock = bind_udp_for_peer(addr.ip()).await.expect("peer bind");
        assert!(peer_sock.local_addr().unwrap().port() != 0);
        assert_eq!(counter.count(), 2);
        clear_socket_protector();
    }

    #[tokio::test]
    async fn bind_udp_for_peer_follows_the_canonical_peer_family() {
        // Under LOCK: another test's protector must not count these binds.
        let _g = LOCK.lock().await;
        for (peer, v4) in [
            ("127.0.0.1", true),
            ("192.0.2.1", true),
            ("::ffff:127.0.0.1", true),
            ("::ffff:192.0.2.1", true),
            ("::1", false),
            ("fe80::1", false),
            ("2001:db8::1", false),
        ] {
            let sock = bind_udp_for_peer(peer.parse().unwrap())
                .await
                .expect("peer bind");
            let local = sock.local_addr().unwrap();
            assert_eq!(local.is_ipv4(), v4, "{peer}");
            assert!(local.ip().is_unspecified(), "{peer}: wildcard bind");
        }
    }

    #[test]
    fn canonical_socket_addr_unmaps_ipv4_and_keeps_ipv6_scope() {
        let cases = [
            ("[::ffff:127.0.0.1]:53", "127.0.0.1:53"),
            ("[::ffff:192.0.2.1]:443", "192.0.2.1:443"),
            ("192.0.2.1:80", "192.0.2.1:80"),
            ("[::1]:53", "[::1]:53"),
            ("[2001:db8::1]:443", "[2001:db8::1]:443"),
        ];
        for (input, want) in cases {
            let input: SocketAddr = input.parse().unwrap();
            assert_eq!(canonical_socket_addr(input), want.parse().unwrap());
        }
        // A link-local peer's scope id (and flow info) survive.
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            5353,
            7,
            3,
        ));
        let SocketAddr::V6(out) = canonical_socket_addr(scoped) else {
            panic!("family changed");
        };
        assert_eq!((out.scope_id(), out.flowinfo(), out.port()), (3, 7, 5353));
    }

    #[tokio::test]
    async fn bind_udp_propagates_protector_failure() {
        let _g = LOCK.lock().await;
        set_socket_protector(Arc::new(Failing) as Arc<dyn SocketProtector>);
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let err = bind_udp(addr).await.expect_err("protect should fail");
        assert!(err.to_string().contains("protect denied"), "{err}");
        clear_socket_protector();
    }

    #[tokio::test]
    async fn bind_udp_no_protector_falls_back_to_plain_tokio() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sock = bind_udp(addr).await.expect("bind");
        assert!(sock.local_addr().unwrap().port() != 0);
    }

    // ─── resolve_host / resolve_host_all ─────────────────────────────────────

    #[tokio::test]
    async fn resolve_host_all_ip_literal_is_single_candidate() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        clear_host_resolver();
        // Installing a failing resolver + protector proves the literal
        // short-circuit never consults the hook chain.
        set_socket_protector(Counting::new() as Arc<dyn SocketProtector>);
        set_host_resolver(Arc::new(FailingResolver) as Arc<dyn HostResolver>);

        let addrs = resolve_host_all("192.0.2.7", 443).await.expect("literal");
        assert_eq!(addrs, vec!["192.0.2.7:443".parse().unwrap()]);

        clear_host_resolver();
        clear_socket_protector();
    }

    #[tokio::test]
    async fn resolve_host_all_uses_installed_resolver_when_protected() {
        let _g = LOCK.lock().await;
        set_socket_protector(Counting::new() as Arc<dyn SocketProtector>);
        let resolver = FixedResolver::new_all(vec![
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from([127, 0, 0, 2]),
        ]);
        set_host_resolver(Arc::clone(&resolver) as Arc<dyn HostResolver>);

        let addrs = resolve_host_all("example.invalid", 8388)
            .await
            .expect("resolve");
        assert_eq!(
            addrs,
            vec![
                "127.0.0.1:8388".parse().unwrap(),
                "127.0.0.2:8388".parse().unwrap()
            ]
        );
        assert_eq!(resolver.count(), 1, "resolver must be consulted once");

        clear_host_resolver();
        clear_socket_protector();
    }

    #[tokio::test]
    async fn resolve_host_first_matches_resolve_host_all_head() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        clear_host_resolver();

        // `localhost` resolves through the system resolver (/etc/hosts) and
        // may legitimately return both families — exactly the multi-candidate
        // shape resolve_host_all exists for.
        let all = resolve_host_all("localhost", 1080).await.expect("resolve");
        assert!(!all.is_empty(), "resolve_host_all never returns empty Ok");
        let single = resolve_host("localhost", 1080).await.expect("resolve");
        assert_eq!(
            single, all[0],
            "resolve_host must stay an alias for the first candidate"
        );
    }

    // ─── registry semantics ─────────────────────────────────────────────────

    #[tokio::test]
    async fn protector_set_get_clear_round_trip() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        assert!(socket_protector().is_none());

        let c = Counting::new();
        set_socket_protector(Arc::clone(&c) as Arc<dyn SocketProtector>);
        assert!(socket_protector().is_some(), "registered protector visible");

        clear_socket_protector();
        assert!(
            socket_protector().is_none(),
            "clear must remove the registration"
        );
    }

    #[tokio::test]
    async fn protector_replacement_takes_effect_for_subsequent_lookups() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        let first = Counting::new();
        set_socket_protector(Arc::clone(&first) as Arc<dyn SocketProtector>);

        let second = Counting::new();
        set_socket_protector(Arc::clone(&second) as Arc<dyn SocketProtector>);

        // The currently-installed pointer is the second one.
        let snap = socket_protector().expect("protector installed");
        let _ = snap.protect(0); // arbitrary fd; Counting accepts any
        assert_eq!(first.count(), 0, "old protector must be detached");
        assert_eq!(second.count(), 1, "new protector receives calls");

        clear_socket_protector();
    }

    #[tokio::test]
    async fn host_resolver_set_get_clear_round_trip() {
        let _g = LOCK.lock().await;
        clear_host_resolver();
        assert!(host_resolver().is_none());

        let r = FixedResolver::new(IpAddr::from([127, 0, 0, 1]));
        set_host_resolver(Arc::clone(&r) as Arc<dyn HostResolver>);
        assert!(host_resolver().is_some());

        clear_host_resolver();
        assert!(host_resolver().is_none());
    }

    /// Stands in for a `#PROXY`-tagged nameserver: answering a lookup means
    /// dialing a proxy, which resolves that proxy's own server hostname.
    struct ReentrantResolver {
        calls: AtomicUsize,
        inner: parking_lot::Mutex<Option<io::Result<Vec<SocketAddr>>>>,
    }
    #[async_trait]
    impl HostResolver for ReentrantResolver {
        async fn resolve(&self, host: &str) -> io::Result<IpAddr> {
            self.resolve_all(host).await.map(|ips| ips[0])
        }

        async fn resolve_all(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // The nested dial the DNS upstream would make.
            *self.inner.lock() = Some(resolve_host_all("localhost", 53).await);
            Ok(vec![IpAddr::from([203, 0, 113, 7])])
        }
    }

    #[tokio::test]
    async fn nested_dial_inside_the_hook_uses_the_system_resolver() {
        let _g = LOCK.lock().await;
        clear_host_resolver();
        let r = Arc::new(ReentrantResolver {
            calls: AtomicUsize::new(0),
            inner: parking_lot::Mutex::new(None),
        });
        set_host_resolver(Arc::clone(&r) as Arc<dyn HostResolver>);

        let addrs = resolve_host_all("proxy.example", 443)
            .await
            .expect("outer lookup answered by the hook");
        assert_eq!(addrs, vec![SocketAddr::from(([203, 0, 113, 7], 443))]);

        // One hook call, not two: the nested dial must not re-enter it, or a
        // real resolver's single-flight map would deadlock the pair.
        assert_eq!(r.calls.load(Ordering::SeqCst), 1);
        let inner = r.inner.lock().take().expect("nested dial ran");
        let inner = inner.expect("system resolver answered the nested dial");
        assert!(
            inner.iter().all(|a| a.ip().is_loopback()),
            "nested dial must come from the system resolver, got {inner:?}"
        );

        clear_host_resolver();
    }

    /// Same nesting, but the hook knows the inner host statically (a `hosts:`
    /// entry or a warm cache line), so the system resolver is never reached.
    struct LocalAnswerResolver {
        local_calls: AtomicUsize,
        inner: parking_lot::Mutex<Option<io::Result<Vec<SocketAddr>>>>,
    }
    #[async_trait]
    impl HostResolver for LocalAnswerResolver {
        async fn resolve(&self, host: &str) -> io::Result<IpAddr> {
            self.resolve_all(host).await.map(|ips| ips[0])
        }

        async fn resolve_all(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            *self.inner.lock() = Some(resolve_host_all("node.example", 8388).await);
            Ok(vec![IpAddr::from([203, 0, 113, 7])])
        }

        fn resolve_all_local(&self, _host: &str) -> Option<Vec<IpAddr>> {
            self.local_calls.fetch_add(1, Ordering::SeqCst);
            Some(vec![IpAddr::from([192, 0, 2, 55])])
        }
    }

    #[tokio::test]
    async fn nested_dial_prefers_the_hooks_local_answer() {
        let _g = LOCK.lock().await;
        clear_host_resolver();
        let r = Arc::new(LocalAnswerResolver {
            local_calls: AtomicUsize::new(0),
            inner: parking_lot::Mutex::new(None),
        });
        set_host_resolver(Arc::clone(&r) as Arc<dyn HostResolver>);

        resolve_host_all("proxy.example", 443).await.unwrap();

        assert_eq!(r.local_calls.load(Ordering::SeqCst), 1);
        let inner = r.inner.lock().take().unwrap().unwrap();
        assert_eq!(
            inner,
            vec![SocketAddr::from(([192, 0, 2, 55], 8388))],
            "the nested hop must take the hook's local answer, not the OS resolver"
        );

        clear_host_resolver();
    }

    #[tokio::test]
    async fn hook_applies_again_after_the_nested_scope_ends() {
        let _g = LOCK.lock().await;
        clear_host_resolver();
        let r = FixedResolver::new(IpAddr::from([198, 51, 100, 4]));
        set_host_resolver(Arc::clone(&r) as Arc<dyn HostResolver>);

        for _ in 0..2 {
            let addrs = resolve_host_all("node.example", 8388).await.unwrap();
            assert_eq!(addrs, vec![SocketAddr::from(([198, 51, 100, 4], 8388))]);
        }
        assert_eq!(r.count(), 2, "the guard must not leak across calls");

        clear_host_resolver();
    }

    #[tokio::test]
    async fn injected_resolver_lookup_is_scoped_outside_a_hook() {
        let _g = LOCK.lock().await;
        clear_host_resolver();
        let r = FixedResolver::new(IpAddr::from([203, 0, 113, 9]));
        let addrs = resolve_host_all_via(r.as_ref(), "wg.example", 51820)
            .await
            .expect("caller-supplied resolver answers");
        assert_eq!(addrs, vec![SocketAddr::from(([203, 0, 113, 9], 51820))]);
        assert_eq!(r.count(), 1);
    }

    /// An adapter resolving its endpoint *inside* a global-hook call —
    /// e.g. the nameserver answering the query is `#PROXY`-tagged through
    /// this very adapter — must hit the same re-entry fence as the
    /// installed hook: answer from the system resolver, never call the
    /// injected hook again (the real resolver's single-flight map would
    /// deadlock the pair).
    #[tokio::test]
    async fn injected_resolver_inside_a_hook_scope_uses_the_system_resolver() {
        let _g = LOCK.lock().await;
        clear_host_resolver();

        struct Outer {
            inner: parking_lot::Mutex<Option<io::Result<Vec<SocketAddr>>>>,
            via: Arc<FixedResolver>,
        }
        #[async_trait]
        impl HostResolver for Outer {
            async fn resolve(&self, host: &str) -> io::Result<IpAddr> {
                self.resolve_all(host).await.map(|ips| ips[0])
            }
            async fn resolve_all(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
                *self.inner.lock() =
                    Some(resolve_host_all_via(self.via.as_ref(), "localhost", 51820).await);
                Ok(vec![IpAddr::from([203, 0, 113, 7])])
            }
        }

        let injected = FixedResolver::new(IpAddr::from([203, 0, 113, 9]));
        let outer = Arc::new(Outer {
            inner: parking_lot::Mutex::new(None),
            via: Arc::clone(&injected),
        });
        set_host_resolver(Arc::clone(&outer) as Arc<dyn HostResolver>);

        resolve_host_all("proxy.example", 443).await.unwrap();

        let inner = outer.inner.lock().take().expect("nested lookup ran");
        let inner = inner.expect("system resolver answered the re-entrant lookup");
        assert!(
            inner.iter().all(|a| a.ip().is_loopback()),
            "re-entrant injected lookup must use the system resolver, got {inner:?}"
        );
        assert_eq!(
            injected.count(),
            0,
            "the re-entrant call must not reach the injected resolver"
        );

        clear_host_resolver();
    }

    // ─── per-node dialer opts (issue #974) ─────────────────────────────────

    #[test]
    fn ip_version_names_roundtrip_and_reject_unknown() {
        for (name, want) in [
            ("dual", IpVersion::Dual),
            ("ipv4", IpVersion::Ipv4),
            ("ipv6", IpVersion::Ipv6),
            ("ipv4-prefer", IpVersion::Ipv4Prefer),
            ("ipv6-prefer", IpVersion::Ipv6Prefer),
        ] {
            assert_eq!(IpVersion::from_name(name), Some(want), "{name}");
            assert_eq!(want.to_string(), name, "{name}");
        }
        for bad in ["", "ipv4prefer", "v4", "IPV4", "dual-stack"] {
            assert_eq!(IpVersion::from_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn resolve_fills_node_over_global() {
        let node = crate::NodeDialerOpts {
            routing_mark: Some(7),
            ..Default::default()
        };
        let global = GlobalDialerOpts {
            routing_mark: Some(3),
            interface_name: Some(Arc::from("en0")),
        };
        let resolved = DialerOpts::resolve(&node, &global);
        // Set node fields win; unset ones inherit the global.
        assert_eq!(resolved.routing_mark, Some(7));
        assert_eq!(resolved.interface_name.as_deref(), Some("en0"));
        // A node interface-name shadows the global.
        let node = crate::NodeDialerOpts {
            interface_name: Some(Arc::from("utun3")),
            ..Default::default()
        };
        let resolved = DialerOpts::resolve(&node, &global);
        assert_eq!(resolved.routing_mark, Some(3));
        assert_eq!(resolved.interface_name.as_deref(), Some("utun3"));
    }

    #[test]
    fn needs_socket2_only_for_socket_options() {
        assert!(!DialerOpts::default().needs_socket2());
        // `ip-version` is resolution-time — never enough by itself.
        assert!(!DialerOpts {
            ip_version: IpVersion::Ipv6,
            ..Default::default()
        }
        .needs_socket2());
        assert!(DialerOpts {
            routing_mark: Some(1),
            ..Default::default()
        }
        .needs_socket2());
        assert!(DialerOpts {
            interface_name: Some(Arc::from("en0")),
            ..Default::default()
        }
        .needs_socket2());
        assert!(DialerOpts {
            tfo: true,
            ..Default::default()
        }
        .needs_socket2());
        assert!(DialerOpts {
            mptcp: true,
            ..Default::default()
        }
        .needs_socket2());
    }

    #[tokio::test]
    async fn scope_replaces_nested_and_reads_globals_outside() {
        let _g = LOCK.lock().await;
        set_global_interface_name(Some(Arc::from("en0")));
        let outer = DialerOpts {
            ip_version: IpVersion::Ipv6,
            tfo: true,
            ..Default::default()
        };
        let inner = DialerOpts {
            ip_version: IpVersion::Ipv4,
            ..Default::default()
        };
        dialer_opts_scope(outer, async {
            let opts = dialer_opts();
            assert_eq!(opts.ip_version, IpVersion::Ipv6);
            assert!(opts.tfo);
            // An unset slot still inherits the global.
            assert_eq!(opts.interface_name.as_deref(), Some("en0"));
            dialer_opts_scope(inner, async {
                // Nesting REPLACES — the front hop's own options, never a
                // merge of the rear's.
                let opts = dialer_opts();
                assert_eq!(opts.ip_version, IpVersion::Ipv4);
                assert!(!opts.tfo);
            })
            .await;
            // The enclosing scope is restored on the way out.
            assert_eq!(dialer_opts().ip_version, IpVersion::Ipv6);
        })
        .await;
        // Outside any scope: defaults plus globals.
        let opts = dialer_opts();
        assert_eq!(opts.ip_version, IpVersion::Dual);
        assert_eq!(opts.interface_name.as_deref(), Some("en0"));
        set_global_interface_name(None);
        assert!(dialer_opts().interface_name.is_none());
    }

    #[test]
    fn ip_version_filter_modes_stable_order_and_canonical() {
        let v4a: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let v4b: SocketAddr = "192.0.2.2:443".parse().unwrap();
        let v6a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v6b: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let mixed = vec![v4a, v6a, v4b, v6b];

        // `dual` is the identity — resolver order untouched.
        assert_eq!(
            apply_ip_version_filter(mixed.clone(), IpVersion::Dual).unwrap(),
            mixed
        );
        // Exact modes keep one family, in resolver order.
        assert_eq!(
            apply_ip_version_filter(mixed.clone(), IpVersion::Ipv4).unwrap(),
            vec![v4a, v4b]
        );
        assert_eq!(
            apply_ip_version_filter(mixed.clone(), IpVersion::Ipv6).unwrap(),
            vec![v6a, v6b]
        );
        // Prefer modes stable-reorder: family first, order inside each
        // family preserved.
        assert_eq!(
            apply_ip_version_filter(mixed.clone(), IpVersion::Ipv4Prefer).unwrap(),
            vec![v4a, v4b, v6a, v6b]
        );
        assert_eq!(
            apply_ip_version_filter(mixed, IpVersion::Ipv6Prefer).unwrap(),
            vec![v6a, v6b, v4a, v4b]
        );
        // An empty family errors for the exact modes…
        let v4_only = vec![v4a, v4b];
        assert!(apply_ip_version_filter(v4_only.clone(), IpVersion::Ipv6).is_err());
        // …but a prefer mode over one family still returns it.
        assert_eq!(
            apply_ip_version_filter(v4_only.clone(), IpVersion::Ipv4Prefer).unwrap(),
            v4_only
        );
        // An IPv4-mapped IPv6 address classifies as IPv4 (`to_canonical`),
        // the same fold the egress checks downstream apply.
        let mapped: SocketAddr = "[::ffff:192.0.2.9]:443".parse().unwrap();
        assert_eq!(
            apply_ip_version_filter(vec![v6a, mapped], IpVersion::Ipv4).unwrap(),
            vec![mapped]
        );
        // Empty input errors rather than passing through silently.
        assert!(apply_ip_version_filter(Vec::new(), IpVersion::Dual)
            .unwrap()
            .is_empty());
        assert!(apply_ip_version_filter(Vec::new(), IpVersion::Ipv4).is_err());
    }

    #[tokio::test]
    async fn resolve_addrs_literal_bypasses_filter_and_resolver() {
        let _g = LOCK.lock().await;
        clear_host_resolver();
        set_host_resolver(Arc::new(FailingResolver) as Arc<dyn HostResolver>);
        // Even under an `ipv6` scope a literal returns verbatim — it is
        // not resolution output (bracketed forms fold the same way).
        let scoped = DialerOpts {
            ip_version: IpVersion::Ipv6,
            ..Default::default()
        };
        let literal: SocketAddr = "127.0.0.1:53".parse().unwrap();
        assert_eq!(
            dialer_opts_scope(scoped.clone(), resolve_addrs("127.0.0.1", 53))
                .await
                .unwrap(),
            vec![literal]
        );
        let v6_literal: SocketAddr = "[::1]:53".parse().unwrap();
        assert_eq!(
            dialer_opts_scope(scoped, resolve_addrs("[::1]", 53))
                .await
                .unwrap(),
            vec![v6_literal]
        );
        clear_host_resolver();
    }

    #[tokio::test]
    async fn resolve_addrs_filters_all_resolution_paths() {
        let _g = LOCK.lock().await;
        clear_host_resolver();
        let v4: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::5]:53".parse().unwrap();
        let resolver =
            FixedResolver::new_all(vec![v6.ip(), v4.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        set_host_resolver(Arc::clone(&resolver) as Arc<dyn HostResolver>);
        let scoped = |ip_version| DialerOpts {
            ip_version,
            ..Default::default()
        };
        // The installed-hook path filters like the system path would.
        let got = dialer_opts_scope(scoped(IpVersion::Ipv4), resolve_addrs("h.test", 53))
            .await
            .unwrap();
        assert_eq!(got, vec![v4], "ipv4 keeps only the v4 candidate");
        let got = dialer_opts_scope(scoped(IpVersion::Ipv6Prefer), resolve_addrs("h.test", 53))
            .await
            .unwrap();
        assert_eq!(got.first(), Some(&v6), "prefer reorders, keeps both");
        assert_eq!(got.len(), 3);
        // A filtered-out family is a resolution failure with context.
        let resolver_v6 = FixedResolver::new_all(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        set_host_resolver(Arc::clone(&resolver_v6) as Arc<dyn HostResolver>);
        let err = dialer_opts_scope(scoped(IpVersion::Ipv4), resolve_addrs("h.test", 53))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("h.test:53"), "{err}");
        assert!(err.to_string().contains("ipv4"), "{err}");
        clear_host_resolver();
    }

    #[tokio::test]
    async fn resolve_host_all_via_filters_under_scope() {
        let _g = LOCK.lock().await;
        let v4 = IpAddr::from([192, 0, 2, 1]);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let resolver = FixedResolver::new_all(vec![v4, v6]);
        let scoped = DialerOpts {
            ip_version: IpVersion::Ipv6,
            ..Default::default()
        };
        // The injected-resolver path (WireGuard's endpoint lookup) takes
        // the same filter — it must not escape `ip-version`.
        let got = dialer_opts_scope(
            scoped,
            resolve_host_all_via(resolver.as_ref(), "ep.test", 51820),
        )
        .await
        .unwrap();
        assert_eq!(got, vec![SocketAddr::new(v6, 51820)]);
    }

    #[tokio::test]
    async fn global_interface_name_round_trip() {
        let _g = LOCK.lock().await;
        assert!(global_interface_name().is_none());
        set_global_interface_name(Some(Arc::from("en0")));
        assert_eq!(global_interface_name().as_deref(), Some("en0"));
        // The global reaches the resolved dialer opts of an unscoped read.
        assert_eq!(
            dialer_opts().interface_name.as_deref(),
            Some("en0"),
            "unscoped callers still see the global"
        );
        // …and of a scoped read whose node set nothing.
        let scoped = DialerOpts {
            ip_version: IpVersion::Ipv4,
            ..Default::default()
        };
        dialer_opts_scope(scoped, async {
            assert_eq!(dialer_opts().interface_name.as_deref(), Some("en0"));
        })
        .await;
        set_global_interface_name(None);
        assert!(global_interface_name().is_none());
        assert!(dialer_opts().interface_name.is_none());
    }
}

#[cfg(test)]
mod candidate_progress_regression {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn stalled_first_family_does_not_starve_reachable_second_family() {
        let addrs = vec![
            "[::1]:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        let result = tokio::time::timeout(
            crate::dial::DIAL_TIMEOUT,
            connect_resolved_candidates(addrs, |addr| async move {
                if addr.is_ipv6() {
                    std::future::pending::<()>().await;
                }
                Ok(addr)
            }),
        )
        .await;
        assert!(
            result.is_ok(),
            "reachable IPv4 candidate must be tried before the dial deadline"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fast_preferred_family_does_not_start_fallback() {
        let calls = std::sync::Mutex::new(Vec::new());
        let addrs = vec![
            "[::1]:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        let winner = connect_resolved_candidates(addrs, |addr| {
            calls.lock().unwrap().push(addr);
            async move { Ok(addr) }
        })
        .await
        .unwrap();
        assert!(winner.is_ipv6());
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_family_advances_immediately_in_resolver_order() {
        let calls = std::sync::Mutex::new(Vec::new());
        let addrs: Vec<SocketAddr> = ["[::1]:443", "127.0.0.1:443", "[::2]:443"]
            .into_iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let start = tokio::time::Instant::now();
        connect_resolved_candidates(addrs.clone(), |addr| {
            calls.lock().unwrap().push(addr);
            async move {
                if addr.is_ipv6() {
                    Err(io::ErrorKind::ConnectionRefused.into())
                } else {
                    Ok(addr)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(*calls.lock().unwrap(), vec![addrs[0], addrs[2], addrs[1]]);
        assert_eq!(start.elapsed(), std::time::Duration::ZERO);
    }

    struct PendingGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for PendingGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn winner_drops_stalled_loser_in_both_family_orders() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        for first_v6 in [true, false] {
            let active = Arc::new(AtomicUsize::new(0));
            let mut addrs: Vec<SocketAddr> = ["[::1]:443", "127.0.0.1:443"]
                .into_iter()
                .map(|s| s.parse().unwrap())
                .collect();
            if !first_v6 {
                addrs.reverse();
            }
            let start = tokio::time::Instant::now();
            let winner = connect_resolved_candidates(addrs, |addr| {
                let active = Arc::clone(&active);
                async move {
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    assert!(count <= 2);
                    let _guard = PendingGuard(active);
                    if addr.is_ipv6() == first_v6 {
                        std::future::pending::<()>().await;
                    }
                    Ok(addr)
                }
            })
            .await
            .unwrap();
            assert_ne!(winner.is_ipv6(), first_v6);
            assert_eq!(start.elapsed(), std::time::Duration::from_millis(250));
            assert_eq!(active.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn caller_deadline_cancels_both_candidates_without_resetting_budget() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let active = Arc::new(AtomicUsize::new(0));
        let started = AtomicUsize::new(0);
        let start = tokio::time::Instant::now();
        let result = crate::dial::with_dial_timeout("test", async {
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            let addrs = vec![
                "[::1]:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap(),
            ];
            connect_resolved_candidates(addrs, |_| {
                let active = Arc::clone(&active);
                let started = &started;
                async move {
                    assert_eq!(
                        crate::dial::dial_deadline(),
                        Some(start + crate::dial::DIAL_TIMEOUT)
                    );
                    started.fetch_add(1, Ordering::SeqCst);
                    active.fetch_add(1, Ordering::SeqCst);
                    let _guard = PendingGuard(active);
                    std::future::pending::<io::Result<()>>().await
                }
            })
            .await
            .map_err(crate::MeowError::Io)
        })
        .await;
        assert!(result.is_err());
        assert_eq!(start.elapsed(), crate::dial::DIAL_TIMEOUT);
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn all_failures_preserve_errno_and_empty_input_error() {
        let addrs = vec![
            "[::1]:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        let error = connect_resolved_candidates(addrs, |addr| async move {
            if addr.is_ipv6() {
                Err::<(), _>(io::Error::from_raw_os_error(24))
            } else {
                Err(io::Error::other("synthetic failure"))
            }
        })
        .await
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(24));
        let error = connect_resolved_candidates(Vec::new(), |_| async { Ok(()) })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

#[cfg(test)]
mod same_family_progress {
    use super::*;
    use std::time::Duration;
    #[tokio::test(start_paused = true)]
    async fn surviving_candidate_reclaims_budget_after_others_fail() {
        let addrs = (1..=3)
            .map(|p| SocketAddr::from(([192, 0, 2, 1], p)))
            .collect();
        let start = tokio::time::Instant::now();
        let result = crate::dial::with_dial_timeout("reclaim fixture", async {
            Ok(connect_tcp_candidates(addrs, |addr| async move {
                if addr.port() == 1 {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    Ok(addr)
                } else {
                    Err(io::ErrorKind::ConnectionRefused.into())
                }
            })
            .await?)
        })
        .await;
        assert_eq!(result.unwrap().port(), 1);
        assert_eq!(start.elapsed(), Duration::from_secs(3));
    }
    #[tokio::test(start_paused = true)]
    async fn stalled_same_family_addresses_do_not_starve_later_candidates() {
        let addresses = (1..=3)
            .map(|port| SocketAddr::from(([192, 0, 2, 1], port)))
            .collect();
        let start = tokio::time::Instant::now();
        let result = crate::dial::with_dial_timeout("same-family fixture", async {
            Ok(connect_tcp_candidates(addresses, |addr| async move {
                if addr.port() != 3 {
                    std::future::pending::<()>().await;
                }
                Ok(addr)
            })
            .await?)
        })
        .await;
        assert_eq!(result.unwrap().port(), 3);
        assert!(start.elapsed() < crate::dial::DIAL_TIMEOUT);
    }
    #[tokio::test(start_paused = true)]
    async fn no_caller_deadline_does_not_introduce_five_second_limit() {
        let addr = SocketAddr::from(([192, 0, 2, 1], 1));
        let start = tokio::time::Instant::now();
        let result = connect_tcp_candidates(vec![addr], |address| async move {
            tokio::time::sleep(Duration::from_secs(6)).await;
            Ok(address)
        })
        .await
        .unwrap();
        assert_eq!(result, addr);
        assert_eq!(start.elapsed(), Duration::from_secs(6));
    }

    #[tokio::test(start_paused = true)]
    async fn shared_deadline_race_bounds_and_drops_pending_attempts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Live(Arc<AtomicUsize>);
        impl Drop for Live {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let live = Arc::new(AtomicUsize::new(0));
        let addrs = (1..=4)
            .map(|p| SocketAddr::from(([192, 0, 2, 1], p)))
            .collect();
        let race = crate::dial::with_dial_timeout::<_, ()>("cancel fixture", async {
            Ok(connect_tcp_candidates(addrs, |_| {
                let live = Arc::clone(&live);
                async move {
                    assert!(live.fetch_add(1, Ordering::SeqCst) < 2);
                    let _guard = Live(live);
                    std::future::pending::<io::Result<()>>().await
                }
            })
            .await?)
        });
        assert!(tokio::time::timeout(Duration::from_secs(1), race)
            .await
            .is_err());
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}
