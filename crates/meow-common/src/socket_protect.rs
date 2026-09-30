//! Outbound-socket protector hook for Android `VpnService.protect(fd)`.
//!
//! When meow-rs runs *inside* an Android VPN app, every outbound socket it
//! opens must bypass the VPN itself — otherwise packets to proxy upstreams
//! loop back into the tunnel and deadlock. Android exposes a per-fd hook
//! for this: `android.net.VpnService.protect(int fd)`. This module is the
//! single place the JNI bridge installs that hook; the proxy adapters that
//! open outbound sockets dial through [`connect_tcp`] / [`connect_tcp_host`]
//! / [`bind_udp`], which call the installed protector before `connect()` /
//! `bind()` so the very first SYN / UDP packet already bypasses the tunnel.
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
//! The `SocketProtector` (raw-fd) hook is compiled only on Android in
//! production — that's the platform whose VPN model demands it; for tests we
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

// In production we only compile the protector hook on Android — that's the
// platform whose VPN model demands `VpnService.protect(fd)` and we don't want
// non-Android binaries paying any footprint for it. For tests we additionally
// enable the module on any unix host so CI (which does not target Android)
// can actually exercise the protector path against real loopback sockets.
#[cfg(any(target_os = "android", all(test, unix)))]
mod android {
    use super::*;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::Arc;

    use parking_lot::RwLock;

    /// Hook invoked on every outbound socket fd just before `connect()` /
    /// `bind()`. Typically a thin JNI shim around
    /// `android.net.VpnService.protect(int)`.
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

#[cfg(any(target_os = "android", all(test, unix)))]
pub use android::{
    clear_socket_protector, set_socket_protector, socket_protector, SocketProtector,
};

/// Dial an outbound TCP stream to an already-resolved [`SocketAddr`]. On
/// Android, applies the installed `SocketProtector` (if any) to the
/// socket fd before `connect()` so the connection bypasses the VPN. On
/// every other target this is equivalent to [`TcpStream::connect`].
///
/// Callers that only have a hostname must use [`connect_tcp_host`] —
/// passing a hostname here is a compile error by construction (the type
/// is `SocketAddr`, not `ToSocketAddrs`). That split exists to prevent
/// silent regressions back into the system resolver; see the module docs
/// for the loop-routing failure mode.
pub async fn connect_tcp(addr: SocketAddr) -> io::Result<TcpStream> {
    #[cfg(any(target_os = "android", all(test, unix)))]
    {
        if let Some(p) = android::socket_protector() {
            return android::connect_tcp_protected(addr, p.as_ref()).await;
        }
    }
    // TUN global-route loop avoidance (#375): when an outbound interface is
    // installed, bind the socket to it before connect() so the SYN already
    // takes the physical route past the TUN default routes.
    #[cfg(target_os = "linux")]
    {
        if crate::outbound_iface::outbound_interface().is_some() {
            return connect_tcp_iface_bound(addr).await;
        }
    }
    TcpStream::connect(addr).await
}

/// Dial with the socket bound to the installed outbound interface
/// (`SO_BINDTODEVICE`) before `connect()`. Uses `tokio::net::TcpSocket` for
/// the async connect so connection errors surface here, not on first I/O.
#[cfg(target_os = "linux")]
async fn connect_tcp_iface_bound(addr: SocketAddr) -> io::Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    crate::outbound_iface::apply_outbound_interface(&socket)?;
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
    if let Ok(ip) = host.parse::<IpAddr>() {
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

    #[cfg(any(target_os = "android", all(test, unix)))]
    {
        if android::socket_protector().is_some() {
            tracing::warn!(
                host,
                "resolve: protector installed but no HostResolver — falling back \
                 to system resolver, which may loop DNS through the VPN"
            );
        }
    }

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
/// resolver), then each candidate is dialed via [`connect_tcp`] so the
/// `SocketProtector` (Android) still applies. If every candidate fails to
/// connect, any cached system-resolver entry is evicted so the next dial
/// re-resolves instead of reusing a dead address.
///
/// IP literals short-circuit inside `resolve_addrs` — no resolver hook is
/// consulted, but the protector still applies to the literal dial.
pub async fn connect_tcp_host(host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs = resolve_addrs(host, port).await?;
    let mut last_err: Option<io::Error> = None;
    for addr in &addrs {
        match connect_tcp(*addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                // An errno-backed failure (e.g. EMFILE on socket()) must
                // not be masked by a later errno-less error — it carries
                // the local-vs-member classification (issue #668).
                last_err = crate::MeowError::prefer_errno_io(last_err, e);
            }
        }
    }
    // Every candidate failed — drop any cached system entry so the next dial
    // re-resolves. No-op for the literal / resolver-hook paths (not cached).
    sys_cache_evict(host);
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

/// Bind an outbound UDP socket. On Android, applies the installed
/// `SocketProtector` (if any) to the socket fd before `bind()`. On every
/// other target this is equivalent to [`UdpSocket::bind`].
pub async fn bind_udp<A: ToSocketAddrs>(local: A) -> io::Result<UdpSocket> {
    #[cfg(any(target_os = "android", all(test, unix)))]
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
    // TUN global-route loop avoidance (#375): bind the socket to the
    // installed outbound interface before the local-address bind, mirroring
    // `connect_tcp` — so the first datagram already bypasses the TUN routes.
    #[cfg(target_os = "linux")]
    {
        if crate::outbound_iface::outbound_interface().is_some() {
            let resolved = tokio::net::lookup_host(local)
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "bind_udp: no address resolved")
                })?;
            return bind_udp_iface_bound(resolved);
        }
    }
    UdpSocket::bind(local).await
}

/// Bind a UDP socket to the installed outbound interface
/// (`SO_BINDTODEVICE`), then to `local`.
#[cfg(target_os = "linux")]
fn bind_udp_iface_bound(local: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if local.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    crate::outbound_iface::apply_outbound_interface(&socket)?;
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
        clear_socket_protector();
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
