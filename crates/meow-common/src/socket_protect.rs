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

#[cfg(all(
    not(target_env = "ohos"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn routing_mark_set() -> bool {
    routing_mark() != 0
}

/// `SO_MARK` on a `socket2` socket per [`ROUTING_MARK`] (`0` = unset).
/// Linux-only by definition — `set_mark` exists on no other cfg target —
/// so callers wrap the call in `#[cfg(target_os = "linux")]`. OpenHarmony
/// counts as `linux` but its only callers are `not(target_env = "ohos")`,
/// so the fn is excluded there too.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn apply_routing_mark(socket: &socket2::Socket) -> io::Result<()> {
    match ROUTING_MARK.load(std::sync::atomic::Ordering::Relaxed) {
        0 => {}
        mark => socket.set_mark(mark)?,
    }
    Ok(())
}

/// Dial an outbound TCP stream to an already-resolved [`SocketAddr`]. On
/// Android, applies the installed `SocketProtector` (if any) to the
/// socket fd before `connect()` so the connection bypasses the VPN.
/// Desktop targets apply the installed outbound-interface policy, and on
/// Linux the `routing-mark` `SO_MARK` (see [`set_routing_mark`]).
///
/// Callers that only have a hostname must use [`connect_tcp_host`] —
/// passing a hostname here is a compile error by construction (the type
/// is `SocketAddr`, not `ToSocketAddrs`). That split exists to prevent
/// silent regressions back into the system resolver; see the module docs
/// for the loop-routing failure mode.
pub async fn connect_tcp(addr: SocketAddr) -> io::Result<TcpStream> {
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
    // takes the physical route past the TUN default routes.
    #[cfg(all(
        not(target_env = "ohos"),
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    {
        if routing_mark_set()
            || (crate::outbound_iface::binds_peer(addr.ip())
                && crate::outbound_iface::outbound_interface().is_some())
        {
            return connect_tcp_iface_bound(addr).await;
        }
    }
    #[cfg(not(target_env = "ohos"))]
    {
        TcpStream::connect(addr).await
    }
}

/// Dial with the socket bound to the installed outbound interface
/// (`SO_BINDTODEVICE` / `IP_BOUND_IF` / `IP_UNICAST_IF`) before `connect()`.
/// Uses `tokio::net::TcpSocket` for the async connect so connection errors
/// surface here, not on first I/O.
// Unused on OpenHarmony, whose dials fail closed without a protector.
#[cfg(all(
    not(target_env = "ohos"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub(crate) async fn connect_tcp_iface_bound(addr: SocketAddr) -> io::Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    #[cfg(target_os = "linux")]
    apply_routing_mark(&socket)?;
    crate::outbound_iface::apply_outbound_interface_for_peer(&socket, domain, addr.ip())?;
    socket.set_nonblocking(true)?;
    let tokio_socket = tokio::net::TcpSocket::from_std_stream(socket.into());
    tokio_socket.connect(addr).await
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
    // shape and must not fall through to DNS (issue #701).
    if let Some(ip) = crate::metadata_ip_literal(host) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    match host_resolver() {
        Some(r) if in_host_resolver() => {
            // Re-entered: answer from what the hook already knows, and only
            // fall through to the system resolver when it knows nothing.
            if let Some(ips) = r.resolve_all_local(host) {
                if !ips.is_empty() {
                    return Ok(ips
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect());
                }
            }
            tracing::debug!(
                host,
                "resolve: re-entrant host-resolver call (a DNS upstream dials through a \
                 proxy) — using the system resolver for this hop to avoid a lookup cycle"
            );
        }
        Some(r) => return resolve_via_hook(r.as_ref(), host, port).await,
        None => {}
    }

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
    #[cfg(all(
        not(target_env = "ohos"),
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    {
        if routing_mark_set() || crate::outbound_iface::outbound_interface().is_some() {
            let resolved = tokio::net::lookup_host(local)
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "bind_udp: no address resolved")
                })?;
            return bind_udp_iface_bound(resolved, peer.unwrap_or(resolved.ip()));
        }
    }
    #[cfg(not(target_env = "ohos"))]
    {
        UdpSocket::bind(local).await
    }
}

/// Bind a UDP socket to the installed outbound interface
/// (`SO_BINDTODEVICE` / `IP_BOUND_IF` / `IP_UNICAST_IF`), then to `local`.
/// The destination determines whether the interface binding is required.
/// A socket pinned to a loopback `local` address is left unbound where the
/// platform's binding would break it (see `outbound_iface::binds_peer`).
// Unused on OpenHarmony, whose dials fail closed without a protector.
#[cfg(all(
    not(target_env = "ohos"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub(crate) fn bind_udp_iface_bound(local: SocketAddr, peer: IpAddr) -> io::Result<UdpSocket> {
    let domain = if local.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    #[cfg(target_os = "linux")]
    apply_routing_mark(&socket)?;
    crate::outbound_iface::apply_outbound_interface_for_peer(&socket, domain, peer)?;
    socket.bind(&local.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
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
