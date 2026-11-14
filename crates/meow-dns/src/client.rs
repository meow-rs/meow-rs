//! Internal DNS client transports — UDP, TCP, DoT, DoH.
//!
//! Sockets are created through a pluggable [`SocketFactory`] so the caller
//! (e.g. an Android VPN service) can intercept fd creation and call
//! `protect()` before the socket is used. This is the reason the project
//! ships its own DNS client instead of relying on `hickory-resolver`.

use crate::cache::QueryFamilies;
#[cfg(feature = "quic-dns")]
use crate::quic::{QuicMode, QuicUpstream};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;

use meow_common::atomic::{AtomicU, Uint};
use std::sync::atomic::Ordering;

#[cfg(feature = "encrypted")]
use meow_transport::tls::{TlsConfig, TlsLayer};

/// Default per-query timeout (matches the hickory-resolver value previously
/// used in `Resolver::build_*`).
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum number of *idle* pooled `tcp://` streams per [`DnsClient`].
///
/// This bounds only the keep-alive pool: a stream is pushed on return
/// only while the pool is below this size (see [`Pool::push`]).
/// Concurrent exchanges are **not** capped by this value — a `tcp://`
/// nameserver can be a user's primary resolver (a common way to dodge
/// UDP truncation/pollution), and capping concurrent exchanges at the
/// pool size would queue bursts into the 5 s outer timeout and
/// reintroduce intermittent DNS timeouts (issue #460). Every
/// concurrent exchange beyond the pool simply opens its own
/// connection, and surplus validated streams are closed on return
/// instead of being pooled.
///
/// Tuning note (review N1): with this design the reuse benefit applies
/// to queries that arrive while an idle stream exists — a fully
/// concurrent burst larger than this capacity pays a fresh connect (and,
/// on Android, a `protect(fd)` call) per query. Raising the idle
/// capacity to match real burst concurrency (16–32) restores reuse for
/// bursts; the cost is a few more long-lived sockets per `tcp://`
/// upstream. Left at 4 for the maintainer to tune.
const TCP_POOL_CAPACITY: usize = 4;
/// How long a pooled `tcp://` stream may sit idle before it is closed rather
/// than reused.
///
/// A pooled stream can be dropped by an upstream or a NAT without an RST or a
/// FIN ever reaching us: the write still succeeds and the peer simply never
/// answers, so the reuse attempt burns its whole read deadline before falling
/// back to a fresh connect. Reaping on an idle clock keeps that worst case out
/// of the common path — queries arriving while a stream is still inside this
/// window can reuse it (staggered bursts share connections), while a stream
/// idle past this window is closed and the next query pays only a normal
/// connect. Note a *fully concurrent* burst larger than [`TCP_POOL_CAPACITY`]
/// dials fresh by design — reuse there would require capping concurrency,
/// which is exactly what this PR removes (see [`TCP_POOL_CAPACITY`]). RFC
/// 7766 §6.2.3 recommends clients close idle connections well inside typical
/// server timeouts; 30 s stays under the shortest of those while still
/// covering the bursts pooling exists to serve.
const TCP_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of *idle* pooled DoT/DoH sessions per [`DnsClient`].
/// Same doctrine as [`TCP_POOL_CAPACITY`]: bounds only the keep-alive
/// pool; concurrent exchanges are never capped — a burst dials fresh
/// conns and surplus validated sessions close at push.
#[cfg(feature = "encrypted")]
const TLS_POOL_CAPACITY: usize = 4;

/// Idle window for pooled DoT/DoH sessions — the same 30 s rationale as
/// [`TCP_POOL_IDLE_TIMEOUT`]: servers drop long-idle conns anyway, and
/// RFC 7766 §6.2.3 asks clients to close well inside server timeouts.
#[cfg(feature = "encrypted")]
const TLS_POOL_IDLE_TIMEOUT: Duration = TCP_POOL_IDLE_TIMEOUT;

/// Floor of a reused TLS conn's exchange deadline. The reuse attempt runs
/// under `min(timeout/2, max(4×est_rtt, REUSED_TLS_MIN_BUDGET))` — see
/// [`tls_reuse_budget`] for the full rule including the viability skip: a
/// silently half-closed conn (NAT/upstream dropped the socket — write
/// succeeds, peer never answers) must be discovered fast enough to leave
/// a full fresh-dial budget, while proxied DoH RTTs that legitimately
/// exceed a flat cap still get `4×` their proven exchange time.
#[cfg(feature = "encrypted")]
const REUSED_TLS_MIN_BUDGET: Duration = Duration::from_millis(250);

/// Budget for the best-effort `close_notify` a pooled TLS conn gets when
/// the pool discards it in an async context — pure politeness, so it is
/// capped hard and failure is ignored.
#[cfg(feature = "encrypted")]
const POLITE_CLOSE_BUDGET: Duration = Duration::from_millis(100);

/// Process-wide generation of pooled upstream connections (issue #695).
///
/// Every pooled `tcp://` stream records the generation current *before* its
/// socket was created; [`reset_pooled_connections`] bumps it, after which
/// stale streams are never handed to a query again nor returned to a pool.
/// Process-wide on purpose: the outbound-interface binding that makes a
/// pre-existing socket stale (`meow_common::outbound_iface`) is itself
/// process-global, and pools live in resolvers the tunnel cannot reach (the
/// `proxy-server-nameserver` host hook, a retained standalone DNS server).
static CONNECTION_GENERATION: AtomicU = AtomicU::new(0);

fn connection_generation() -> Uint {
    CONNECTION_GENERATION.load(Ordering::Acquire)
}

/// Retire every pooled DNS upstream connection in the process so the next
/// query dials a fresh socket — reaches pools in resolvers nobody holds a
/// handle to (e.g. the `proxy-server-nameserver` host hook).
///
/// Lock-free and non-blocking. Idle streams are closed lazily, on their
/// pool's next checkout (eagerly through [`DnsClient::reset_connections`] /
/// `Resolver::reset_connections`); an in-flight exchange finishes on the
/// stream it already holds — bounded by the per-query timeout — and then
/// closes it instead of pooling it.
pub fn reset_pooled_connections() {
    CONNECTION_GENERATION.fetch_add(1, Ordering::AcqRel);
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Factory that creates the raw sockets the DNS client transports run on.
///
/// Implementations may call platform-specific hooks (Android `protect()`,
/// Linux `SO_MARK`, …) before returning the socket so DNS traffic bypasses
/// the local VPN tunnel.
pub trait SocketFactory: Send + Sync + 'static {
    /// Bind an unconnected UDP socket. Implementations typically bind to
    /// `0.0.0.0:0`; a single-family socket like that must be paired with a
    /// [`bind_udp_for_peer`](Self::bind_udp_for_peer) override or upstreams
    /// of the other family stay unreachable.
    fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>>;

    /// Bind for a known upstream. The socket is `connect()`ed to the
    /// canonical form of `peer` — an IPv4-mapped peer dials plain IPv4 —
    /// so its family must match the canonical `peer`'s: an IPv4-bound
    /// socket can never reach a native IPv6 peer, and an IPv6-bound
    /// socket cannot be relied on to take a plain `sockaddr_in` either
    /// (dual-stack Linux happens to translate a mapped connect; the
    /// contract is deliberately stricter than that leniency). A factory
    /// whose [`bind_udp`](Self::bind_udp) yields a single-family socket
    /// **must** override this to bind in the canonical `peer`'s family —
    /// without that override mismatched upstreams still fail, the bug
    /// this hook fixes.
    ///
    /// The default delegates to [`bind_udp`](Self::bind_udp), so custom
    /// factories keep their socket creation and protection hooks, then
    /// refuses a family-mismatched pairing up front with
    /// `AddrNotAvailable` instead of a late, opaque `connect()` failure.
    fn bind_udp_for_peer(&self, peer: IpAddr) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(async move {
            let socket = self.bind_udp().await?;
            if socket.local_addr()?.is_ipv4() != peer.to_canonical().is_ipv4() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "SocketFactory::bind_udp returned a socket whose family \
                     cannot reach the peer; override bind_udp_for_peer",
                ));
            }
            Ok(socket)
        })
    }

    /// Open an outbound TCP connection to `addr`. Call sites pass the
    /// [`meow_common::canonical_socket_addr`] of the upstream, so the
    /// IPv4-mapped form never reaches the impl — an implementation that
    /// picks its socket family from `addr.is_ipv6()` sees the real dial
    /// family.
    fn connect_tcp(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>>;
}

/// Tokio default factory: routes through [`meow_common::bind_udp`] /
/// [`meow_common::connect_tcp`] so the Android `VpnService.protect(fd)`
/// hook (when installed) covers DNS upstream sockets too.
struct DefaultSocketFactory;

impl SocketFactory for DefaultSocketFactory {
    fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(meow_common::bind_udp(SocketAddr::from(([0u8; 4], 0))))
    }

    fn bind_udp_for_peer(&self, peer: IpAddr) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(meow_common::bind_udp_for_peer(peer))
    }

    fn connect_tcp(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(async move { meow_common::connect_tcp(addr).await })
    }
}

static SOCKET_FACTORY: OnceLock<Arc<dyn SocketFactory>> = OnceLock::new();
static DEFAULT_FACTORY: DefaultSocketFactory = DefaultSocketFactory;

/// Install a custom [`SocketFactory`]. Can only be called once; subsequent
/// calls return the supplied factory unchanged so the caller can detect the
/// programming error.
pub fn set_socket_factory(factory: Arc<dyn SocketFactory>) -> Result<(), Arc<dyn SocketFactory>> {
    SOCKET_FACTORY.set(factory)
}

fn factory() -> &'static dyn SocketFactory {
    match SOCKET_FACTORY.get() {
        Some(f) => f.as_ref(),
        None => &DEFAULT_FACTORY,
    }
}

/// All errors produced by the internal DNS client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("dns proto: {0}")]
    Proto(#[from] hickory_proto::ProtoError),
    #[error("dns decode: {0}")]
    Decode(#[from] hickory_proto::serialize::binary::DecodeError),
    #[error("query timed out after {0:?}")]
    Timeout(Duration),
    #[error("invalid response: {0}")]
    Protocol(&'static str),
    #[error("tls: {0}")]
    Tls(String),
    #[error("upstream returned rcode {0:?}")]
    Rcode(hickory_proto::op::ResponseCode),
}

impl ClientError {
    /// True when this failure carries a concrete OS errno (e.g. `EMFILE`
    /// opening the upstream socket). That errno is the signal
    /// `is_local_resource_error` uses to keep local resource exhaustion
    /// from dead-marking healthy proxy members, so it must survive the
    /// resolver boundary (#682).
    pub(crate) fn is_errno_backed(&self) -> bool {
        // `OutOfMemory` parity with `MeowError::io_errno_backed`: an
        // errno-less allocation failure is still local resource
        // pressure and must not lose `prefer_errno` ordering.
        matches!(self, Self::Io(e) if e.raw_os_error().is_some()
            || e.kind() == io::ErrorKind::OutOfMemory)
    }

    /// Re-express as `io::Error`, preserving `raw_os_error` when one
    /// exists. Used where a lookup failure must cross an `io::Result`
    /// boundary (`Resolver::resolve_ips`), including single-flight
    /// subscribers reconstructing an owned error from the broadcast's
    /// shared `Arc<ClientError>`.
    pub(crate) fn to_io(&self) -> io::Error {
        match self {
            Self::Io(e) => match e.raw_os_error() {
                Some(errno) => io::Error::from_raw_os_error(errno),
                None => io::Error::new(e.kind(), e.to_string()),
            },
            Self::Timeout(_) => io::Error::new(io::ErrorKind::TimedOut, self.to_string()),
            _ => io::Error::other(self.to_string()),
        }
    }
}

/// Multi-candidate error accumulator, mirroring
/// `MeowError::prefer_errno`: an errno-backed failure outranks a
/// context-only one, because it is the concrete local cause the caller's
/// error classifier must see (#682).
pub(crate) fn prefer_errno(
    prev: Option<ClientError>,
    next: Option<ClientError>,
) -> Option<ClientError> {
    let Some(next) = next else { return prev };
    if prev.as_ref().is_some_and(ClientError::is_errno_backed) && !next.is_errno_backed() {
        prev
    } else {
        Some(next)
    }
}

/// Optional proxy adapter for routing DNS queries through. When set, the
/// TCP exchange is performed via `proxy.dial_tcp` instead of
/// `factory().connect_tcp` — see ADR-0012 (issue #67 phase 2).
pub type DnsProxy = Arc<dyn meow_common::Proxy>;

/// A single DNS upstream the resolver can query.
pub struct DnsClient {
    transport: Transport,
    timeout: Duration,
    proxy: Option<DnsProxy>,
    /// The `(hostname, port)` a proxied exchange must ask the adapter to
    /// dial — set when the upstream's address is a hostname, which is left
    /// to the proxy for *remote* resolution (mihomo `newDNSDialer`
    /// semantics). `None` means the transport's `SocketAddr` is the dial
    /// target. See [`Resolver::build_single_resolver_with_proxy`].
    proxy_target: Option<(Arc<str>, u16)>,
    /// Extra CA roots (DER) for the DoT/DoH TLS handshake — empty in
    /// production; test code injects a self-signed chain here instead of
    /// disabling verification. See [`Self::with_tls_additional_roots`].
    #[cfg(feature = "encrypted")]
    tls_extra_roots: Vec<Vec<u8>>,
    label: Option<Arc<str>>,
    /// Idle direct `tcp://` connections. Streams are checked out for the whole
    /// exchange and returned only after the DNS response is fully validated.
    tcp_pool: Pool<TcpStream>,
    /// Idle DoT/DoH TLS sessions, pooled exactly like `tcp_pool`: one
    /// upstream-bound conn type (`TlsConn`) covers direct and `?proxy=`
    /// dials, checked out for the whole exchange so response-ID matching
    /// can never cross packets. A pooled `?proxy=` conn keeps the group
    /// member selected at dial time — reuse bypasses Selector/URLTest
    /// re-selection until the conn dies (self-healing trade-off).
    #[cfg(feature = "encrypted")]
    tls_pool: Pool<PooledTls>,
    /// `with_tls_pool_disabled` escape hatch (debug/test builds only —
    /// written nowhere else). The mutation control proving the reuse
    /// assertions measure real pooling: when set, every query pays the
    /// full dial + handshake.
    #[cfg(feature = "encrypted")]
    tls_pool_disabled: bool,
    /// DoH only: the upstream's shared HTTP/2 connection, set once a
    /// fresh conn negotiated `h2` and answered. Unlike `tls_pool` it is
    /// not checked out: concurrent queries each open a stream on it, so
    /// response matching stays per stream. Servers that pick `http/1.1`
    /// never fill it and keep using `tls_pool`.
    #[cfg(feature = "encrypted")]
    doh_h2: parking_lot::Mutex<Option<Arc<DohH2Conn>>>,
    /// Pooled conns rejected by the pre-checkout liveness probe —
    /// test/debug instrumentation separating "the probe caught the dead
    /// conn" from "the exchange-time EOF did": identical at accept-count
    /// granularity, distinguishable here (review M4).
    #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
    probe_dead: std::sync::atomic::AtomicUsize,
    /// The QUIC connection for `quic://` / `prefer-h3` entries. `None` for
    /// every other transport; the driver task is spawned on first use and
    /// re-dials by itself, so one client owns one connection per upstream.
    #[cfg(feature = "quic-dns")]
    quic: Option<Arc<QuicUpstream>>,
    /// The HTTP/2 / HTTP/1.1 DoH client a `prefer-h3` entry falls back to
    /// when the QUIC exchange fails. Built at construction so the fallback keeps its
    /// own TLS session pool, proxy tag and certificate roots.
    #[cfg(feature = "quic-dns")]
    doh_h1: Option<Box<DnsClient>>,
}

/// What the pool does to an element it discards while an async context
/// exists (push-side overflow, take-side reaping): bare `Drop` is the
/// baseline; [`PooledTls`] adds a best-effort `close_notify`. Sync discard
/// paths (`close_idle`, `reset`) always drop bare — spawning shutdown
/// tasks for politeness is rejected.
trait PoolElement: Send + 'static {
    /// Best-effort graceful close, internally bounded. Default is a no-op:
    /// the element is dropped bare, exactly like today.
    fn polite_close(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

impl PoolElement for TcpStream {}

/// A bounded keep-alive pool of upstream conns checked out for one whole
/// exchange at a time — `tcp://` sockets and (under `encrypted`) DoT/DoH
/// TLS sessions share this machinery. `E` is the bare element; the
/// generation stamp and the idle timestamp are tracked by the pool.
struct Pool<E: PoolElement> {
    /// Idle elements paired with the instant they were returned to the pool.
    /// Pushed and popped at the end, so the freshest conn is reused first
    /// and the staler ones age out instead of being handed to a query.
    idle: AsyncMutex<Vec<(PoolEntry<E>, Instant)>>,
    /// Upper bound on *idle* entries — enforced at [`Pool::push`], never a
    /// cap on concurrent exchanges (see [`TCP_POOL_CAPACITY`]).
    capacity: usize,
    idle_timeout: Duration,
    /// This pool's own generation, bumped by [`DnsClient::reset_connections`]
    /// — the per-client counterpart of [`CONNECTION_GENERATION`].
    generation: AtomicU,
}

/// The pool generation a conn was created under: stale once either the
/// process-wide or the pool-local counter moves (issue #695).
#[derive(Clone, Copy, PartialEq, Eq)]
struct PoolGeneration {
    global: Uint,
    local: Uint,
}

/// A pooled element plus the [`PoolGeneration`] captured before its conn
/// was created.
struct PoolEntry<E> {
    element: E,
    generation: PoolGeneration,
}

/// A negotiated DoT/DoH session ready for an exchange. Direct dials are
/// boxed `TcpStream`s via the `ProxyConn` blanket impl, proxied dials are
/// the adapter's own `ProxyConn` — one boxed element type covers both, so
/// pooled reuse skips the per-query `dial_tcp`/`protect(fd)` entirely.
#[cfg(feature = "encrypted")]
type TlsConn = Pin<Box<tokio_boring::SslStream<Box<dyn meow_common::ProxyConn>>>>;

/// A pooled TLS conn plus the conn's own last successful exchange
/// duration, recorded at push: it bounds the *next* reuse attempt's
/// deadline — proxied DoH RTTs legitimately exceed a flat 250 ms cap, so
/// the cap scales with the conn's proven RTT instead.
#[cfg(feature = "encrypted")]
struct PooledTls {
    stream: TlsConn,
    est_rtt: Duration,
}

#[cfg(feature = "encrypted")]
impl PoolElement for PooledTls {
    fn polite_close(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            // Pure politeness: a bounded `close_notify` where an async
            // context exists anyway; failure and timeout are ignored.
            let _ = tokio::time::timeout(POLITE_CLOSE_BUDGET, self.stream.shutdown()).await;
        })
    }
}

/// A DoH upstream's shared HTTP/2 connection. Every query clones the
/// `Arc` for the length of its stream; the connection task is aborted
/// when the last clone drops, so retiring it from
/// [`DnsClient::doh_h2`] never cuts a stream already in flight.
#[cfg(feature = "encrypted")]
struct DohH2Conn {
    send: h2::client::SendRequest<bytes::Bytes>,
    /// The task driving the connection's frames. Finished means the
    /// connection is gone (GOAWAY, reset, I/O error).
    driver: tokio::task::AbortHandle,
    /// The pool generation captured before the conn was dialed, so
    /// [`reset_pooled_connections`] and [`DnsClient::reset_connections`]
    /// retire it like a pooled TLS conn (issue #695).
    generation: PoolGeneration,
    use_state: parking_lot::Mutex<DohH2Use>,
}

#[cfg(feature = "encrypted")]
#[derive(Clone, Copy)]
struct DohH2Use {
    /// End of the last successful exchange: past [`TLS_POOL_IDLE_TIMEOUT`]
    /// the conn is dropped rather than reused, like an idle pooled conn.
    last_used: Instant,
    /// The last successful exchange's duration, the input to
    /// [`tls_reuse_budget`].
    est_rtt: Duration,
}

#[cfg(feature = "encrypted")]
impl DohH2Conn {
    fn reusable(&self, generation: PoolGeneration, now: Instant) -> bool {
        !self.driver.is_finished()
            && self.generation == generation
            && now.duration_since(self.use_state.lock().last_used) < TLS_POOL_IDLE_TIMEOUT
    }

    fn est_rtt(&self) -> Duration {
        self.use_state.lock().est_rtt
    }

    fn record_exchange(&self, est_rtt: Duration) {
        *self.use_state.lock() = DohH2Use {
            last_used: Instant::now(),
            est_rtt,
        };
    }
}

#[cfg(feature = "encrypted")]
impl Drop for DohH2Conn {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl<E: PoolElement> Pool<E> {
    fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            idle: AsyncMutex::new(Vec::with_capacity(capacity)),
            capacity,
            idle_timeout,
            generation: AtomicU::new(0),
        }
    }

    fn generation(&self) -> PoolGeneration {
        PoolGeneration {
            global: connection_generation(),
            local: self.generation.load(Ordering::Acquire),
        }
    }

    /// Retire every conn this pool handed out or holds — idle ones close
    /// now, checked-out ones on return. Returns the idle conns closed.
    fn reset(&self) -> usize {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.close_idle()
    }

    /// Return a validated conn to the idle pool, closing it instead when
    /// the pool is already at capacity or [`reset_pooled_connections`]
    /// retired its generation while it was checked out.
    ///
    /// The size bound is enforced *here*, on the push side — it is not an
    /// emergent property of the exchange path — so any future caller
    /// (e.g. a background reaper returning conns) cannot silently grow
    /// the pool beyond `capacity`.
    async fn push(&self, mut pooled: PoolEntry<E>) {
        {
            let mut idle = self.idle.lock().await;
            if idle.len() < self.capacity && pooled.generation == self.generation() {
                idle.push((pooled, Instant::now()));
                return;
            }
        }
        // Overflow/retired: close politely — an async context exists.
        pooled.element.polite_close().await;
    }

    /// Pop the freshest reusable conn, closing every idle-expired or
    /// generation-retired one on the way. Reaped conns get their
    /// [`PoolElement::polite_close`] after the lock is released.
    async fn take(&self) -> Option<PoolEntry<E>> {
        let generation = self.generation();
        let mut reaped = Vec::new();
        let taken = {
            let mut idle = self.idle.lock().await;
            reaped.extend(
                idle.extract_if(.., |(pooled, _)| pooled.generation != generation)
                    .map(|(entry, _)| entry),
            );
            take_fresh(&mut idle, Instant::now(), self.idle_timeout, &mut reaped)
        };
        for mut entry in reaped {
            entry.element.polite_close().await;
        }
        taken
    }

    /// Close every idle conn now, without waiting for the lock: a
    /// contended pool is mid-checkout and [`Self::take`] / [`Self::push`]
    /// drop retired conns on their own. Returns the number closed.
    fn close_idle(&self) -> usize {
        self.idle.try_lock().map_or(0, |mut idle| {
            let closed = idle.len();
            idle.clear();
            closed
        })
    }
}

/// Close every conn idle past `idle_timeout` and hand back the freshest
/// survivor, or `None` when the pool has nothing reusable. Expired
/// elements are moved into `reaped` for the caller to close (a sync drop
/// is all a plain socket needs; a TLS conn gets a `close_notify`).
///
/// Split out from the exchange so the reaping rule is testable without a
/// socket or a clock.
fn take_fresh<T>(
    idle: &mut Vec<(T, Instant)>,
    now: Instant,
    idle_timeout: Duration,
    reaped: &mut Vec<T>,
) -> Option<T> {
    reaped.extend(
        idle.extract_if(.., |(_, returned_at)| {
            now.duration_since(*returned_at) >= idle_timeout
        })
        .map(|(element, _)| element),
    );
    idle.pop().map(|(element, _)| element)
}

/// The exchange deadline for a reused pooled TLS conn — `None` when the
/// conn provably cannot answer inside the cap, sending the query
/// straight to the fresh dial.
///
/// `min(timeout/2, max(4×est_rtt, REUSED_TLS_MIN_BUDGET))`: the `t/2`
/// ceiling is what guarantees the fresh fallback its own `≥t/2` — a
/// failed reuse attempt can never burn more than half the query budget.
/// But a conn whose proven RTT already meets or exceeds that ceiling is
/// a *certain* miss that still spends the whole `t/2`, leaving
/// dial+handshake+exchange `≤t/2` — the systematic timeout a cold dial
/// would not have hit (review M2). The attempt is skipped instead, so
/// both branches stay reachable: a healthy conn answers inside its
/// budget, an answerable fresh path keeps the full `timeout`.
#[cfg(feature = "encrypted")]
fn tls_reuse_budget(timeout: Duration, est_rtt: Duration) -> Option<Duration> {
    let budget = (timeout / 2).min(est_rtt.saturating_mul(4).max(REUSED_TLS_MIN_BUDGET));
    // The attempt needs ~est_rtt inside `budget`; `est_rtt >= budget`
    // cannot win — the deadline fires first — so don't spend it.
    (est_rtt < budget).then_some(budget)
}

pub(crate) struct IpLookupResult {
    pub(crate) ips: Vec<IpAddr>,
    pub(crate) ttl: Duration,
    /// Preserve the per-family result for the BOTH path. The aggregate IP list
    /// is sufficient for callers that only need addresses, but the resolver
    /// cache also needs to retain NXDOMAIN versus NODATA.
    pub(crate) v4: Option<FamilyAnswer>,
    pub(crate) v6: Option<FamilyAnswer>,
}

pub(crate) enum FamilyLookupResult {
    Response(IpLookupResult),
    /// Authoritative "name does not exist". Carries the RFC 2308 negative
    /// cache TTL — `min(SOA.TTL, SOA.MINIMUM)` from the authority section, or
    /// `0` when the upstream omitted the SOA (the resolver's clamp floor
    /// still gives it a short cache lifetime).
    NxDomain(Duration),
}

/// One family's answer within a [`FamilySet`]. The resolver/cache consume this
/// unified shape so the per-family and "all enabled families" lookup paths
/// share one pipeline (review issue J). TTLs are the raw upstream values; the
/// resolver clamps them once before use.
#[derive(Clone, Debug)]
pub(crate) enum FamilyAnswer {
    /// NOERROR with at least one address record of this family.
    Answer { ips: Vec<IpAddr>, ttl: Duration },
    /// NOERROR with zero address records of this family (NODATA). Carries the
    /// upstream TTL so the cache can expire the negative on its own schedule.
    NoData(Duration),
    /// The upstream authoritatively said the name does not exist. Carries the
    /// RFC 2308 negative cache TTL (SOA-derived) so the cache can serve the
    /// NXDOMAIN rcode from cache for that family until its own expiry fires,
    /// damping DGA/retry-loop load (aligns with mihomo `putMsgToCache`).
    NxDomain(Duration),
    /// A network/timeout failure for this family — not a definitive answer.
    Failed,
}

/// A client's resolution result across the requested family set. `None` for a
/// family means "not queried" (e.g. the prefer-IPv4 path skips AAAA once A has
/// addresses); the resolver treats that as a cache miss for the family and
/// re-queries on demand.
#[derive(Clone, Debug)]
pub(crate) struct FamilySet {
    pub(crate) v4: Option<FamilyAnswer>,
    pub(crate) v6: Option<FamilyAnswer>,
    pub(crate) source: String,
}

enum Transport {
    Udp {
        addr: SocketAddr,
    },
    Tcp {
        addr: SocketAddr,
    },
    #[cfg(feature = "encrypted")]
    Dot {
        addr: SocketAddr,
        sni: Arc<str>,
    },
    #[cfg(feature = "encrypted")]
    Doh {
        addr: SocketAddr,
        sni: Arc<str>,
        path: Arc<str>,
    },
    /// DNS over QUIC (RFC 9250).
    #[cfg(feature = "quic-dns")]
    Doq {
        addr: SocketAddr,
        sni: Arc<str>,
    },
    /// DNS over HTTPS over HTTP/3 — mihomo `prefer-h3`, with the HTTP/1.1
    /// DoH path as the fallback (`self.doh_h1`).
    #[cfg(feature = "quic-dns")]
    Doh3 {
        addr: SocketAddr,
        sni: Arc<str>,
        path: Arc<str>,
    },
    RCode {
        code: ResponseCode,
    },
}

impl Transport {
    /// The socket address a *direct* dial (or an IP-literal proxy dial)
    /// would target. A hostname upstream routed via proxy stores a
    /// placeholder here — `proxy_dial` consults `proxy_target` first and
    /// never reaches this.
    fn dial_addr(&self) -> SocketAddr {
        match self {
            Self::Udp { addr } | Self::Tcp { addr } => *addr,
            #[cfg(feature = "encrypted")]
            Self::Dot { addr, .. } | Self::Doh { addr, .. } => *addr,
            #[cfg(feature = "quic-dns")]
            Self::Doq { addr, .. } | Self::Doh3 { addr, .. } => *addr,
            Self::RCode { .. } => unreachable!("rcode transport has no dial address"),
        }
    }
}

impl DnsClient {
    /// Plain DNS over UDP.
    pub fn udp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Udp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            proxy_target: None,
            #[cfg(feature = "encrypted")]
            tls_extra_roots: Vec::new(),
            label: None,
            tcp_pool: Pool::new(TCP_POOL_CAPACITY, TCP_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool: Pool::new(TLS_POOL_CAPACITY, TLS_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool_disabled: false,
            #[cfg(feature = "encrypted")]
            doh_h2: parking_lot::Mutex::new(None),
            #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
            probe_dead: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "quic-dns")]
            quic: None,
            #[cfg(feature = "quic-dns")]
            doh_h1: None,
        }
    }

    /// Plain DNS over TCP (RFC 7766 length-prefixed framing).
    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Tcp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            proxy_target: None,
            #[cfg(feature = "encrypted")]
            tls_extra_roots: Vec::new(),
            label: None,
            tcp_pool: Pool::new(TCP_POOL_CAPACITY, TCP_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool: Pool::new(TLS_POOL_CAPACITY, TLS_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool_disabled: false,
            #[cfg(feature = "encrypted")]
            doh_h2: parking_lot::Mutex::new(None),
            #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
            probe_dead: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "quic-dns")]
            quic: None,
            #[cfg(feature = "quic-dns")]
            doh_h1: None,
        }
    }

    /// Synthetic DNS response with a fixed response code and no answers.
    pub fn rcode(code: ResponseCode) -> Self {
        Self {
            transport: Transport::RCode { code },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            proxy_target: None,
            #[cfg(feature = "encrypted")]
            tls_extra_roots: Vec::new(),
            label: None,
            tcp_pool: Pool::new(TCP_POOL_CAPACITY, TCP_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool: Pool::new(TLS_POOL_CAPACITY, TLS_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool_disabled: false,
            #[cfg(feature = "encrypted")]
            doh_h2: parking_lot::Mutex::new(None),
            #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
            probe_dead: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "quic-dns")]
            quic: None,
            #[cfg(feature = "quic-dns")]
            doh_h1: None,
        }
    }

    /// DNS over TLS (RFC 7858).
    #[cfg(feature = "encrypted")]
    pub fn dot(addr: SocketAddr, sni: &str) -> Self {
        Self {
            transport: Transport::Dot {
                addr,
                sni: Arc::from(sni),
            },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            proxy_target: None,
            #[cfg(feature = "encrypted")]
            tls_extra_roots: Vec::new(),
            label: None,
            tcp_pool: Pool::new(TCP_POOL_CAPACITY, TCP_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool: Pool::new(TLS_POOL_CAPACITY, TLS_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool_disabled: false,
            #[cfg(feature = "encrypted")]
            doh_h2: parking_lot::Mutex::new(None),
            #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
            probe_dead: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "quic-dns")]
            quic: None,
            #[cfg(feature = "quic-dns")]
            doh_h1: None,
        }
    }

    /// DNS over HTTPS (RFC 8484) — HTTP/1.1 POST application/dns-message.
    #[cfg(feature = "encrypted")]
    pub fn doh(addr: SocketAddr, sni: &str, path: &str) -> Self {
        Self {
            transport: Transport::Doh {
                addr,
                sni: Arc::from(sni),
                path: Arc::from(path),
            },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            proxy_target: None,
            #[cfg(feature = "encrypted")]
            tls_extra_roots: Vec::new(),
            label: None,
            tcp_pool: Pool::new(TCP_POOL_CAPACITY, TCP_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool: Pool::new(TLS_POOL_CAPACITY, TLS_POOL_IDLE_TIMEOUT),
            #[cfg(feature = "encrypted")]
            tls_pool_disabled: false,
            #[cfg(feature = "encrypted")]
            doh_h2: parking_lot::Mutex::new(None),
            #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
            probe_dead: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "quic-dns")]
            quic: None,
            #[cfg(feature = "quic-dns")]
            doh_h1: None,
        }
    }

    /// DNS over QUIC (RFC 9250) — `quic://host[:port][#sni]`.
    ///
    /// One bidi stream per query, length-prefixed per RFC 9250 §4.2, with the
    /// DNS transaction ID zeroed on the wire (the peer MUST answer with ID 0;
    /// the caller's ID is restored before validation).
    #[cfg(feature = "quic-dns")]
    pub fn doq(addr: SocketAddr, sni: &str) -> Self {
        Self::with_quic(
            Transport::Doq {
                addr,
                sni: Arc::from(sni),
            },
            QuicMode::Doq,
            addr,
            sni,
            None,
        )
    }

    /// DNS over HTTPS over HTTP/3 — the `prefer-h3` form of a `https://`
    /// entry.
    ///
    /// The HTTP/1.1 DoH client built here is the fallback: when the QUIC
    /// exchange fails (no h3 support, UDP blocked, connection loss) the
    /// exchange is retried over HTTP/1.1, and a failed handshake parks h3 for
    /// this upstream so the next query does not pay a second timeout. The
    /// fallback shares this client's timeout, proxy tag, certificate roots and
    /// TLS session pool.
    #[cfg(feature = "quic-dns")]
    pub fn doh3(addr: SocketAddr, sni: &str, path: &str) -> Self {
        let h1 = DnsClient::doh(addr, sni, path);
        Self::with_quic(
            Transport::Doh3 {
                addr,
                sni: Arc::from(sni),
                path: Arc::from(path),
            },
            QuicMode::Doh3 {
                path: Arc::from(path),
            },
            addr,
            sni,
            Some(Box::new(h1)),
        )
    }

    /// DoH3 in mihomo's per-entry form (`?h3=true`): HTTP/3 only, with no
    /// HTTP/1.1 fallback. A failure is reported as-is.
    #[cfg(feature = "quic-dns")]
    pub fn doh3_force(addr: SocketAddr, sni: &str, path: &str) -> Self {
        Self::with_quic(
            Transport::Doh3 {
                addr,
                sni: Arc::from(sni),
                path: Arc::from(path),
            },
            QuicMode::Doh3 {
                path: Arc::from(path),
            },
            addr,
            sni,
            None,
        )
    }

    /// Shared tail of the two QUIC constructors.
    #[cfg(feature = "quic-dns")]
    fn with_quic(
        transport: Transport,
        mode: QuicMode,
        addr: SocketAddr,
        sni: &str,
        doh_h1: Option<Box<DnsClient>>,
    ) -> Self {
        Self {
            transport,
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            proxy_target: None,
            tls_extra_roots: Vec::new(),
            label: None,
            tcp_pool: Pool::new(TCP_POOL_CAPACITY, TCP_POOL_IDLE_TIMEOUT),
            tls_pool: Pool::new(TLS_POOL_CAPACITY, TLS_POOL_IDLE_TIMEOUT),
            tls_pool_disabled: false,
            #[cfg(feature = "encrypted")]
            doh_h2: parking_lot::Mutex::new(None),
            #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
            probe_dead: std::sync::atomic::AtomicUsize::new(0),
            quic: Some(Arc::new(QuicUpstream::new(mode, addr, Arc::from(sni)))),
            doh_h1,
        }
    }

    /// Override the per-query timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        #[cfg(feature = "quic-dns")]
        if let Some(h1) = self.doh_h1.as_mut() {
            h1.timeout = t;
        }
        self
    }

    /// Route this client's exchanges through `proxy` (issue #67 phase 2).
    ///
    /// When set:
    /// - TCP exchanges use `proxy.dial_tcp` instead of opening a direct
    ///   TCP connection.
    /// - DoT / DoH exchanges dial `proxy.dial_tcp` and run the TLS
    ///   handshake over the returned [`meow_common::ProxyConn`] via
    ///   [`TlsLayer::connect_typed`].
    /// - Literal-address UDP exchanges use the adapter's datagram support
    ///   when available. TCP-only adapters and hostname upstreams retain
    ///   TCP-over-proxy; explicit TCP entries always remain TCP.
    /// - A validated truncated UDP answer retries through the same proxy's
    ///   TCP transport under the original query deadline.
    pub fn with_proxy(mut self, proxy: DnsProxy) -> Self {
        #[cfg(feature = "quic-dns")]
        {
            if let Some(quic) = self.quic.as_ref() {
                quic.set_proxy(Arc::clone(&proxy));
            }
            if let Some(h1) = self.doh_h1.as_mut() {
                h1.proxy = Some(Arc::clone(&proxy));
            }
        }
        self.proxy = Some(proxy);
        self
    }

    /// Set the `(host, port)` pair a proxied exchange asks the adapter to
    /// dial — used when the upstream's configured address is a hostname:
    /// the proxy performs the *remote* resolution, so no local bootstrap
    /// lookup of the upstream name is needed (mihomo `newDNSDialer`
    /// semantics). Only meaningful together with [`Self::with_proxy`].
    pub(crate) fn with_proxy_target(mut self, host: Arc<str>, port: u16) -> Self {
        #[cfg(feature = "quic-dns")]
        {
            if let Some(quic) = self.quic.as_ref() {
                quic.set_proxy_target(Arc::clone(&host), port);
            }
            if let Some(h1) = self.doh_h1.as_mut() {
                h1.proxy_target = Some((Arc::clone(&host), port));
            }
        }
        self.proxy_target = Some((host, port));
        self
    }

    /// Trust `der`-encoded CA certificates *in addition to* the webpki
    /// roots for the DoT/DoH handshake — test hook so in-process TLS
    /// upstreams can present a self-signed chain without disabling
    /// verification.
    ///
    /// Compiled only into test and debug builds: `#[doc(hidden)]` alone
    /// still shipped the widening hook in release binaries, where nothing
    /// may extend the DoT/DoH trust set (r15 review M2). Integration
    /// tests call it under `debug_assertions`; release strips it.
    #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
    #[doc(hidden)]
    pub fn with_tls_additional_roots(mut self, der: Vec<u8>) -> Self {
        #[cfg(feature = "quic-dns")]
        {
            // The QUIC handshake uses the same trust set, so a test upstream
            // that presents a self-signed chain is reachable over DoQ/DoH3
            // too. Adding a root retires the live connection (it was
            // verified against the old store).
            if let Some(quic) = self.quic.as_ref() {
                quic.add_extra_root(der.clone());
            }
            if let Some(h1) = self.doh_h1.as_mut() {
                h1.tls_extra_roots.push(der.clone());
            }
        }
        self.tls_extra_roots.push(der);
        self
    }

    /// Disable the DoT/DoH session pool — every query pays a full dial +
    /// TLS handshake. Mutation control for the pooling tests: the
    /// accept/dial counters of a pool-disabled client prove the reuse
    /// assertions measure real reuse and not a silent no-op. Compiled
    /// only into test and debug builds, like
    /// [`Self::with_tls_additional_roots`].
    #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
    #[doc(hidden)]
    pub fn with_tls_pool_disabled(mut self) -> Self {
        self.tls_pool_disabled = true;
        #[cfg(feature = "quic-dns")]
        if let Some(h1) = self.doh_h1.as_mut() {
            h1.tls_pool_disabled = true;
        }
        self
    }

    /// Pooled TLS conns rejected by the pre-checkout liveness probe —
    /// instrumentation separating "the probe caught the dead conn" from
    /// "the exchange-time EOF did": identical at accept-count
    /// granularity, so this counter is what makes probe removal a
    /// testable mutation (review M4). Compiled only into test and debug
    /// builds, like [`Self::with_tls_pool_disabled`].
    #[cfg(all(feature = "encrypted", any(test, debug_assertions)))]
    #[doc(hidden)]
    pub fn tls_probe_rejections(&self) -> usize {
        self.probe_dead.load(Ordering::Relaxed)
    }

    /// Override the API/UI label used to report this upstream in DNS results.
    pub fn with_upstream_label(mut self, label: impl Into<String>) -> Self {
        let label: Arc<str> = Arc::from(label.into());
        #[cfg(feature = "quic-dns")]
        if let Some(h1) = self.doh_h1.as_mut() {
            h1.label = Some(Arc::clone(&label));
        }
        self.label = Some(label);
        self
    }

    /// Whether this client's exchanges are routed through a proxy adapter
    /// (`with_proxy`). Exposed so config-layer tests can assert that
    /// `#PROXY`-tagged nameserver entries actually got their adapter wired.
    pub fn is_proxied(&self) -> bool {
        self.proxy.is_some()
    }

    /// The adapter this client's exchanges route through, if any. Exposed
    /// for tests asserting the captured adapter stays bound to a retained
    /// dialer-registry generation across resolver republishes.
    pub fn proxy(&self) -> Option<&DnsProxy> {
        self.proxy.as_ref()
    }

    /// Drop this client's pooled upstream connections — `tcp://` sockets
    /// and, under `encrypted`, DoT/DoH TLS sessions — so the next query
    /// dials fresh (issue #695). Idle conns close now unless the pool is
    /// mid-checkout, in which case they close on the next checkout; a conn
    /// an in-flight query holds finishes that query (bounded by the
    /// per-query timeout) and is then closed instead of pooled.
    /// Non-blocking. Returns the idle conns closed now. UDP opens a socket
    /// per query and pools nothing.
    pub fn reset_connections(&self) -> usize {
        // The QUIC driver re-dials on its next query; the connection itself
        // is closed by the task, so this stays non-blocking.
        #[cfg(feature = "quic-dns")]
        if let Some(quic) = self.quic.as_ref() {
            quic.mark_stale();
        }
        // A DoH3 client's own pools are unused — the fallback's DoH TLS
        // sessions are what carries a parked h3 entry, so a reset must reach
        // them too (network change, proxy switch, `Resolver::reset_connections`).
        #[cfg(feature = "quic-dns")]
        let quic_fallback_reset = self.doh_h1.as_ref().map_or(0, |h1| h1.reset_connections());
        #[cfg(feature = "encrypted")]
        {
            // The pool reset bumps the generation the shared h2 conn was
            // stamped with; dropping it here closes it now instead of at
            // the next query. Its in-flight streams finish first.
            let h2_reset = usize::from(self.doh_h2.lock().take().is_some());
            #[cfg(feature = "quic-dns")]
            {
                self.tcp_pool.reset() + self.tls_pool.reset() + h2_reset + quic_fallback_reset
            }
            #[cfg(not(feature = "quic-dns"))]
            {
                self.tcp_pool.reset() + self.tls_pool.reset() + h2_reset
            }
        }
        #[cfg(not(feature = "encrypted"))]
        {
            self.tcp_pool.reset()
        }
    }

    /// Human-readable upstream identifier for API/UI surfaces.
    pub fn upstream_label(&self) -> String {
        let mut label = if let Some(label) = &self.label {
            label.to_string()
        } else {
            match &self.transport {
                Transport::Udp { addr } | Transport::Tcp { addr } => match &self.proxy_target {
                    // Hostname upstream via proxy: the placeholder
                    // `addr` is meaningless — report the real target.
                    Some((host, port)) => {
                        if *port == 53 {
                            host.to_string()
                        } else {
                            format!("{host}:{port}")
                        }
                    }
                    None => socket_label(*addr, 53),
                },
                Transport::RCode { code } => format!("rcode:{code:?}"),
                #[cfg(feature = "encrypted")]
                Transport::Dot { addr, sni, .. } => {
                    if sni.is_empty() {
                        format!("tls://{}", socket_label(*addr, 853))
                    } else if addr.port() == 853 {
                        format!("tls://{sni}")
                    } else {
                        format!("tls://{sni}:{}", addr.port())
                    }
                }
                #[cfg(feature = "encrypted")]
                Transport::Doh {
                    addr, sni, path, ..
                } => doh_label(addr, sni, path),
                #[cfg(feature = "quic-dns")]
                Transport::Doq { addr, sni, .. } => {
                    if sni.is_empty() {
                        format!("quic://{}", socket_label(*addr, 853))
                    } else if addr.port() == 853 {
                        format!("quic://{sni}")
                    } else {
                        format!("quic://{sni}:{}", addr.port())
                    }
                }
                // A DoH3 entry is the same URL as its HTTP/1.1 fallback, so
                // the label stays `https://…` — the transport is an
                // implementation detail of one upstream, not its identity.
                #[cfg(feature = "quic-dns")]
                Transport::Doh3 {
                    addr, sni, path, ..
                } => doh_label(addr, sni, path),
            }
        };
        if let Some(proxy) = &self.proxy {
            // Spelling-agnostic suffix: `#PROXY` would echo the plain-form
            // spelling onto `?proxy=` entries. `via <name>` also reports
            // the adapter actually dialed (r15 review I4).
            label.push_str(" via ");
            label.push_str(proxy.name());
        }
        label
    }

    /// Send a query for `(name, record_type)` and return the parsed response
    /// `Message`. The response transaction ID, message type, opcode, and
    /// question must match the request before any response flags or records
    /// are used.
    pub async fn query(&self, name: &str, record_type: RecordType) -> Result<Message, ClientError> {
        let parsed: Name = name
            .parse()
            .map_err(|_| ClientError::Protocol("invalid query name"))?;
        self.query_name(&parsed, record_type).await
    }

    /// `query` with an already-decoded `Name` — the generic relay forwards
    /// the wire-faithful name from the client's question. Re-rendering it
    /// to text and re-parsing would re-split labels containing a literal
    /// '.' and mangle non-UTF-8 bytes.
    pub async fn query_name(
        &self,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Message, ClientError> {
        tokio::time::timeout(
            self.timeout,
            self.query_parsed(Query::query(name.clone(), record_type)),
        )
        .await
        .map_err(|_| ClientError::Timeout(self.timeout))?
    }

    async fn query_inner(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Message, ClientError> {
        let parsed: Name = name
            .parse()
            .map_err(|_| ClientError::Protocol("invalid query name"))?;
        self.query_parsed(Query::query(parsed, record_type)).await
    }

    async fn query_parsed(&self, query: Query) -> Result<Message, ClientError> {
        let id: u16 = rand::random();
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        if let Transport::RCode { code } = &self.transport {
            let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = true;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = *code;
            resp.add_query(query);
            return Ok(resp);
        }
        msg.add_query(query.clone());
        let wire = msg.to_bytes()?;
        let expected = ExpectedResponse { id, query };
        self.exchange(&wire, &expected).await
    }

    /// Convenience: resolve every enabled address for `name`. A and AAAA are
    /// queried **concurrently** (IPv4 ordered first in the result) under one
    /// overall timeout; AAAA is skipped entirely when `ipv6_enabled` is
    /// false. Returns the addresses and minimum answer TTL.
    pub async fn lookup_ip(&self, name: &str) -> Result<(Vec<IpAddr>, Duration), ClientError> {
        let result = self.lookup_ip_with_ipv6(name, true).await?;
        Ok((result.ips, result.ttl))
    }

    pub(crate) async fn lookup_ip_with_ipv6(
        &self,
        name: &str,
        ipv6_enabled: bool,
    ) -> Result<IpLookupResult, ClientError> {
        tokio::time::timeout(
            self.timeout,
            self.lookup_ip_with_ipv6_inner(name, ipv6_enabled),
        )
        .await
        .map_err(|_| ClientError::Timeout(self.timeout))?
    }

    pub(crate) async fn lookup_family(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<FamilyLookupResult, ClientError> {
        let queried = QueryFamilies::from_record_type(record_type);
        if queried.is_empty() {
            return Err(ClientError::Protocol(
                "address family query must be A or AAAA",
            ));
        }
        let message = self.query(name, record_type).await?;
        match message.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => {
                // RFC 2308: a negative response's cache lifetime is
                // `min(SOA.TTL, SOA.MINIMUM)` from the authority section. Cache
                // it so repeat queries for a bogus name don't re-query upstream
                // on every attempt (DGA / retry loops). `0` when no SOA is
                // present; the resolver clamp floor still yields a short life.
                let ttl = negative_ttl(&message);
                return Ok(FamilyLookupResult::NxDomain(ttl));
            }
            code => return Err(ClientError::Rcode(code)),
        }
        let (ips, answer_ttl) = relevant_ip_answers(&message);
        let ttl = if ips.is_empty() {
            // RFC 2308: NODATA uses the SOA negative TTL, not a CNAME or
            // address-answer TTL accidentally found in the response.
            negative_ttl(&message)
        } else {
            Duration::from_secs(u64::from(answer_ttl.unwrap_or(0)))
        };
        Ok(FamilyLookupResult::Response(IpLookupResult {
            ips,
            ttl,
            v4: None,
            v6: None,
        }))
    }

    /// Unified entry point for the resolver pipeline (review issue J). For a
    /// single family (`IPV4`/`IPV6`) this is a per-family query that preserves
    /// the NXDOMAIN/NODATA distinction the DNS server needs; for `BOTH` it
    /// queries A and AAAA concurrently and returns every enabled address
    /// (IPv4 first) for `resolve_ips`, so `DirectAdapter` retains IPv6
    /// fallback when IPv4 connectivity fails. `Err` means the client could
    /// not produce *any* answer for the requested set (e.g. both families
    /// timed out); the resolver keeps racing the remaining clients.
    pub(crate) async fn lookup_set(
        &self,
        name: &str,
        want: QueryFamilies,
        ipv6_enabled: bool,
    ) -> Result<FamilySet, ClientError> {
        let source = self.upstream_label();
        if want == QueryFamilies::BOTH {
            let result = self.lookup_ip_with_ipv6(name, ipv6_enabled).await?;
            return Ok(family_set_from_ip_lookup(&result, source));
        }
        let family = if want == QueryFamilies::IPV4 {
            QueryFamilies::IPV4
        } else if want == QueryFamilies::IPV6 {
            QueryFamilies::IPV6
        } else {
            return Err(ClientError::Protocol(
                "lookup_set requires a single family or BOTH",
            ));
        };
        let record_type = match family {
            QueryFamilies::IPV4 => RecordType::A,
            _ => RecordType::AAAA,
        };
        let answer = match self.lookup_family(name, record_type).await {
            Ok(FamilyLookupResult::Response(r)) => {
                let ttl = r.ttl;
                if r.ips.is_empty() {
                    FamilyAnswer::NoData(ttl)
                } else {
                    FamilyAnswer::Answer { ips: r.ips, ttl }
                }
            }
            Ok(FamilyLookupResult::NxDomain(ttl)) => FamilyAnswer::NxDomain(ttl),
            // A transport failure must propagate: folding it into
            // `FamilyAnswer::Failed` erases the errno before the
            // resolver's error bookkeeping sees it (#682). `Failed`
            // remains for *response* verdicts (SERVFAIL rcode etc.).
            Err(e) => return Err(e),
        };
        let (v4, v6) = if family == QueryFamilies::IPV4 {
            (Some(answer), None)
        } else {
            (None, Some(answer))
        };
        Ok(FamilySet { v4, v6, source })
    }

    async fn lookup_ip_with_ipv6_inner(
        &self,
        name: &str,
        ipv6_enabled: bool,
    ) -> Result<IpLookupResult, ClientError> {
        // Query A and AAAA in parallel when IPv6 is enabled so callers
        // (notably `resolve_ips` → `DirectAdapter::dial_tcp`) receive *both*
        // address families and can fall back to IPv6 when IPv4 connectivity
        // fails. IPv4 addresses are placed first in the result list to
        // preserve prefer-IPv4 ordering — `dial_tcp` iterates in list order,
        // so IPv4 is tried before IPv6.
        //
        // Per-family answers are retained because the aggregate IP list
        // alone cannot distinguish NODATA from NXDOMAIN when it is later
        // written to the shared cache.
        if !ipv6_enabled {
            // IPv4-only path: a single A query, no AAAA.
            let answer = match self.query_inner(name, RecordType::A).await {
                Ok(message) => classify_family_message(&message),
                Err(error) => return Err(error),
            };
            let (ips, ttl) = match &answer {
                FamilyAnswer::Answer { ips, ttl } => (ips.clone(), *ttl),
                FamilyAnswer::NoData(ttl) | FamilyAnswer::NxDomain(ttl) => (Vec::new(), *ttl),
                FamilyAnswer::Failed => {
                    return Err(ClientError::Protocol("no response"));
                }
            };
            return Ok(IpLookupResult {
                ips,
                ttl,
                v4: Some(answer),
                v6: None,
            });
        }

        // Dual-stack path: race A and AAAA concurrently.
        let (v4_result, v6_result) = tokio::join!(
            self.query_inner(name, RecordType::A),
            self.query_inner(name, RecordType::AAAA)
        );
        merge_family_results(v4_result, v6_result)
    }

    /// Send a direct `tcp://` query through a bounded keep-alive pool.
    /// Checked-out streams stay local to this future, so cancellation drops a
    /// partially consumed stream instead of returning it to the pool.
    ///
    /// Concurrency is **not** capped: each in-flight exchange either reuses a
    /// pooled stream or opens its own connection, and validated streams are
    /// returned to the pool only while it is below
    /// [`TCP_POOL_CAPACITY`] (see [`Pool::push`]); surplus streams are
    /// closed. The async mutex only guards the idle-slot pop/push.
    ///
    /// The pooled (reused) attempt runs under a *short* read deadline — at
    /// most half the per-query timeout, and never more than 250 ms: a
    /// healthy reused stream answers in about one RTT, so a longer budget
    /// only helps a stream that has been idle-half-closed by an upstream or
    /// NAT (write succeeds, peer never answers). Capping the deadline keeps
    /// a stale-reuse discovery from cutting the fresh-connect retry budget
    /// in half. RST/EOF still fail fast; only the silent half-close case is
    /// bounded here. That deadline is the second line of defence:
    /// [`TCP_POOL_IDLE_TIMEOUT`] closes a stream before it has been idle
    /// long enough to be silently dropped, so the common path after a quiet
    /// period is a plain connect rather than a reuse attempt that has to
    /// time out first. DoT/DoH use the encrypted counterpart,
    /// [`Self::tls_exchange_pooled`], which adds a pre-checkout liveness
    /// probe and an RTT-scaled deadline (proxied DoH legitimately exceeds
    /// a flat 250 ms).
    /// Test hook: shorten the pooled-stream idle window so reaping can be
    /// exercised without sleeping for the production timeout.
    #[cfg(test)]
    fn with_tcp_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.tcp_pool.idle_timeout = idle_timeout;
        self
    }

    async fn tcp_exchange_pooled(
        &self,
        addr: SocketAddr,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<Message, ClientError> {
        let pooled = self.tcp_pool.take().await;
        // A reused stream should answer within about one RTT; anything
        // slower is presumed a silently half-closed stream. Bounding the
        // discovery attempt to at most half the query timeout (and 250 ms)
        // preserves a full budget for the fresh connect + exchange below.
        let pooled_budget = self.timeout / 2;
        let pooled_budget = pooled_budget.min(Duration::from_millis(250));

        if let Some(mut pooled) = pooled {
            let attempt = tcp_message_exchange(&mut pooled.element, wire, expected);
            if let Ok(Ok(response)) = tokio::time::timeout(pooled_budget, attempt).await {
                self.tcp_pool.push(pooled).await;
                return Ok(response);
            }
            // Timeout or error: drop the (possibly desynced/half-closed)
            // stream and reconnect. Do not return a timed-out reused stream
            // to the pool.
        }

        // Same canonicalisation as `udp_exchange`: a v4-mapped `tcp://`
        // upstream is dialed as plain IPv4 — the mapped form fails
        // connect() where a fresh v6 socket defaults to v6-only.
        let addr = meow_common::canonical_socket_addr(addr);
        // Captured before the socket exists: a reset racing the connect
        // must retire this stream too (issue #695).
        let generation = self.tcp_pool.generation();
        let mut stream = factory().connect_tcp(addr).await?;
        let response = tcp_message_exchange(&mut stream, wire, expected).await?;
        self.tcp_pool
            .push(PoolEntry {
                element: stream,
                generation,
            })
            .await;
        Ok(response)
    }

    /// Open one proxied TCP stream to this client's dial target.
    ///
    /// The [`Metadata`] carries the canonical DNS-via-proxy shape: for an
    /// IP upstream `host` is the address string and `dst_ip` is `Some`;
    /// for a hostname upstream ([`Self::with_proxy_target`]) `host` is the
    /// domain and `dst_ip` is `None` so the adapter forwards the domain to
    /// the remote side (mihomo `newDNSDialer` semantics).
    ///
    /// The whole `dial_tcp` runs inside
    /// [`meow_common::socket_protect::IN_DNS_VIA_PROXY_DIAL`]: a
    /// resolver-injected adapter (`DirectAdapter` with `resolve_ips`) that
    /// resolves its own dial target inside this dial re-enters
    /// `Resolver::resolve_ips`, and the fence makes that re-entry answer
    /// locally/system-side instead of re-running the upstream pipeline
    /// that issued this query in the first place (self-deadlock
    /// otherwise — see socket_protect.rs).
    async fn proxy_dial(
        &self,
        proxy: &DnsProxy,
    ) -> Result<Box<dyn meow_common::ProxyConn>, ClientError> {
        use meow_common::{ConnType, Metadata, Network};
        let (host, dst_ip, dst_port) = match &self.proxy_target {
            Some((host, port)) => (smol_str::SmolStr::from(host.as_ref()), None, *port),
            None => {
                // Same canonicalisation as `tcp_exchange_pooled` /
                // `dial_tls_inner`: a v4-mapped upstream is advertised
                // to the adapter as plain IPv4 — an adapter that dials
                // `dst_ip` verbatim (DirectAdapter) hits the mapped-form
                // connect() failure this PR fixes.
                let addr = meow_common::canonical_socket_addr(self.transport.dial_addr());
                (
                    smol_str::SmolStr::from(addr.ip().to_string()),
                    Some(addr.ip()),
                    addr.port(),
                )
            }
        };
        let metadata = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            host,
            dst_ip,
            dst_port,
            // DNS-via-proxy exchanges are resolver housekeeping — a `lazy`
            // group serving this dial must not count it as use.
            internal: true,
            ..Default::default()
        };
        meow_common::socket_protect::dns_via_proxy_dial_scope(proxy.dial_tcp(&metadata))
            .await
            // `into_io_error` keeps the innermost `Io` verbatim: an
            // errno-bearing dial failure (EMFILE under local fd pressure)
            // must not be flattened into a context-only `Other` before it
            // reaches the resolver's classifier (#682) — and
            // `Unsupported` refusals keep their kind.
            .map_err(|e| ClientError::Io(e.into_io_error("dns-via-proxy dial")))
    }

    /// One plain-TCP-over-proxy exchange (UDP proxied upstreams also land
    /// here — see [`Self::with_proxy`]).
    async fn proxy_tcp_exchange(
        &self,
        proxy: &DnsProxy,
        wire: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let mut stream = self.proxy_dial(proxy).await?;
        write_lp(&mut stream, wire).await?;
        read_lp(&mut stream).await
    }

    /// Run the TLS handshake for a DoT/DoH exchange over `inner` — a
    /// direct `TcpStream` or a proxied `ProxyConn` — and pin the result.
    /// `Pin<Box<_>>` keeps the `Unpin` bound regardless of whether
    /// `tokio_boring::SslStream<S>` itself is `Unpin`.
    #[cfg(feature = "encrypted")]
    async fn tls_connect_pinned<S>(
        &self,
        tls: &TlsLayer,
        inner: S,
    ) -> Result<Pin<Box<tokio_boring::SslStream<S>>>, ClientError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        tls.connect_typed(inner)
            .await
            .map(Box::pin)
            .map_err(tls_connect_error::<S>)
    }

    /// Open the raw conn a DoT/DoH session is built over: the adapter's
    /// `ProxyConn` under `?proxy=` (the dial keeps its `internal:true`
    /// housekeeping metadata), a boxed `TcpStream` otherwise — one
    /// `Box<dyn ProxyConn>` either way, so the pool stores a single type.
    #[cfg(feature = "encrypted")]
    async fn dial_tls_inner(&self) -> Result<Box<dyn meow_common::ProxyConn>, ClientError> {
        if let Some(proxy) = self.proxy.as_ref() {
            self.proxy_dial(proxy).await
        } else {
            // Same canonicalisation as `tcp_exchange_pooled`: a
            // v4-mapped `tls://`/`https://` upstream is dialed as plain
            // IPv4 — the mapped form fails connect() on a v6-only socket.
            let addr = meow_common::canonical_socket_addr(self.transport.dial_addr());
            let tcp = factory().connect_tcp(addr).await?;
            Ok(Box::new(tcp))
        }
    }

    /// Dial and TLS-handshake a fresh DoT/DoH conn — the cold path every
    /// query took before pooling.
    #[cfg(feature = "encrypted")]
    async fn tls_dial_handshake(&self) -> Result<TlsConn, ClientError> {
        let (sni, alpn): (&str, &[&str]) = match &self.transport {
            Transport::Dot { sni, .. } => (sni.as_ref(), &["dot"]),
            // Both, as mihomo offers them (`DefaultHTTPVersions`): the
            // server picks. Some answer only over h2 although they accept
            // `http/1.1` (Yandex DNS closes every HTTP/1.1 request), and
            // the negotiated ALPN, not this list, picks the framing.
            Transport::Doh { sni, .. } => (sni.as_ref(), &["h2", "http/1.1"]),
            _ => unreachable!("tls_dial_handshake on a non-TLS transport"),
        };
        let conn = self.dial_tls_inner().await?;
        let tls = tls_layer(sni, alpn, &self.tls_extra_roots)?;
        self.tls_connect_pinned(&tls, conn).await
    }

    /// One DNS exchange over an established TLS conn, returning the
    /// validated response and whether the conn may return to the pool.
    /// DoT is always reusable after a clean exchange; DoH defers to the
    /// response's own framing verdict — a `Connection: close` or
    /// close-delimited answer is still a correct answer, just not a
    /// reusable conn.
    #[cfg(feature = "encrypted")]
    async fn tls_message_exchange(
        &self,
        stream: &mut TlsConn,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<(Message, bool), ClientError> {
        match &self.transport {
            Transport::Dot { .. } => {
                write_lp(stream, wire).await?;
                let body = read_lp(stream).await?;
                Ok((decode_validated_response(&body, expected)?, true))
            }
            Transport::Doh { sni, path, .. } => {
                let (body, reusable) = doh_http_exchange(stream, sni, path, wire).await?;
                Ok((decode_validated_response(&body, expected)?, reusable))
            }
            _ => unreachable!("tls_message_exchange on a non-TLS transport"),
        }
    }

    /// A DoT/DoH query through a bounded keep-alive pool of TLS sessions —
    /// the encrypted counterpart of [`Self::tcp_exchange_pooled`], sharing
    /// its doctrine: exclusive checkout (no pipelining — a checked-out
    /// conn runs exactly one exchange, so response-ID matching cannot
    /// cross packets), concurrency never capped by the pool size, surplus
    /// conns closed at push.
    ///
    /// On top of the TCP flow it adds two TLS-specific defences:
    ///
    /// - a free pre-checkout liveness probe ([`tls_conn_alive`]) — a
    ///   half-open conn is discarded and redialed at zero query cost;
    /// - an RTT-scaled reuse deadline, `min(timeout/2, max(4×est_rtt,
    ///   250ms))` ([`tls_reuse_budget`]): a flat 250 ms cap would make
    ///   every proxied-DoH reuse self-defeating (deadline burns, redial
    ///   anyway), while silent-drop discovery only needs to outlive the
    ///   conn's own proven RTT. The `t/2` ceiling reserves the fresh
    ///   path its `≥t/2` floor — and a conn whose proven RTT already
    ///   exceeds it is never attempted at all (review M2).
    ///
    /// The retry whitelist is `{Io error, reuse deadline elapsed}` only —
    /// a `Protocol`/`Tls`/validation failure on a pooled conn cannot be
    /// staleness (only fully validated conns are ever pushed) and is
    /// returned verbatim, never retried, never pooled. A fresh attempt's
    /// error is authoritative and returned as-is.
    #[cfg(feature = "encrypted")]
    async fn tls_exchange_pooled(
        &self,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<Message, ClientError> {
        // A DoH upstream that negotiated h2 runs every query as a stream on
        // its one shared connection; the HTTP/1.1 pool below stays empty
        // for it. Same reuse doctrine as a pooled conn: an RTT-scaled
        // deadline, a retry on `Io`/deadline only, and the retried query
        // gets the fresh path.
        if let Some(conn) = (!self.tls_pool_disabled)
            .then(|| self.doh_h2_current())
            .flatten()
        {
            match tls_reuse_budget(self.timeout, conn.est_rtt()) {
                Some(budget) => {
                    let started = Instant::now();
                    match tokio::time::timeout(budget, self.doh_h2_request(&conn, wire)).await {
                        Ok(Ok(body)) => {
                            conn.record_exchange(started.elapsed());
                            return decode_validated_response(&body, expected);
                        }
                        Ok(Err(ClientError::Io(err))) => {
                            tracing::debug!(
                                upstream = %self.upstream_label(),
                                error = %err,
                                "dns doh h2: shared conn failed mid-exchange; retrying fresh"
                            );
                            self.doh_h2_retire(&conn);
                        }
                        Ok(Err(err)) => return Err(err),
                        Err(_elapsed) => {
                            tracing::debug!(
                                upstream = %self.upstream_label(),
                                budget = ?budget,
                                "dns doh h2: shared conn missed its reuse deadline; retrying fresh"
                            );
                            self.doh_h2_retire(&conn);
                        }
                    }
                }
                None => {
                    tracing::debug!(
                        upstream = %self.upstream_label(),
                        est_rtt = ?conn.est_rtt(),
                        "dns doh h2: proven RTT cannot meet the reuse cap; dialing fresh"
                    );
                }
            }
        }

        if !self.tls_pool_disabled {
            if let Some(mut pooled) = self.tls_pool.take().await {
                // `Some(budget)` only for a conn that is both alive at
                // the probe and able to answer inside its capped reuse
                // deadline — anything else falls straight through to
                // the fresh dial below with the full timeout in hand.
                let viable = if tls_conn_alive(&mut pooled.element.stream).await {
                    match tls_reuse_budget(self.timeout, pooled.element.est_rtt) {
                        Some(budget) => {
                            tracing::debug!(
                                upstream = %self.upstream_label(),
                                "dns tls pool: reusing pooled conn"
                            );
                            Some(budget)
                        }
                        None => {
                            tracing::debug!(
                                upstream = %self.upstream_label(),
                                est_rtt = ?pooled.element.est_rtt,
                                "dns tls pool: proven RTT cannot meet the reuse cap; dialing fresh"
                            );
                            None
                        }
                    }
                } else {
                    #[cfg(any(test, debug_assertions))]
                    self.probe_dead.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        upstream = %self.upstream_label(),
                        "dns tls pool: pooled conn dead at liveness probe; dialing fresh"
                    );
                    None
                };
                if let Some(budget) = viable {
                    let started = Instant::now();
                    let attempt =
                        self.tls_message_exchange(&mut pooled.element.stream, wire, expected);
                    match tokio::time::timeout(budget, attempt).await {
                        Ok(Ok((response, reusable))) => {
                            pooled.element.est_rtt = started.elapsed();
                            if reusable {
                                self.tls_pool.push(pooled).await;
                            }
                            return Ok(response);
                        }
                        Ok(Err(ClientError::Io(err))) => {
                            tracing::debug!(
                                upstream = %self.upstream_label(),
                                error = %err,
                                "dns tls pool: pooled conn failed mid-exchange; retrying fresh"
                            );
                        }
                        // `Protocol`/`Tls`/validation errors cannot be
                        // staleness — propagate verbatim, no retry.
                        Ok(Err(err)) => return Err(err),
                        Err(_elapsed) => {
                            tracing::debug!(
                                upstream = %self.upstream_label(),
                                budget = ?budget,
                                "dns tls pool: pooled conn missed its reuse deadline; retrying fresh"
                            );
                        }
                    }
                }
                // Dead/failed pooled conn drops here — never re-pooled.
            } else {
                tracing::debug!(
                    upstream = %self.upstream_label(),
                    "dns tls pool: miss; dialing fresh"
                );
            }
        }

        // Fresh dial. The generation is captured before the conn exists:
        // a reset racing the dial must retire this conn too (issue #695).
        let generation = self.tls_pool.generation();
        let mut stream = self.tls_dial_handshake().await?;
        // Only a DoH conn can carry `h2`: DoT offers `dot` alone.
        if matches!(self.transport, Transport::Doh { .. })
            && stream.ssl().selected_alpn_protocol() == Some(b"h2")
        {
            let conn = self.doh_h2_connect(stream, generation).await?;
            let started = Instant::now();
            let body = self.doh_h2_request(&conn, wire).await?;
            let response = decode_validated_response(&body, expected)?;
            conn.record_exchange(started.elapsed());
            if !self.tls_pool_disabled {
                self.doh_h2_install(conn);
            }
            return Ok(response);
        }
        let started = Instant::now();
        let (response, reusable) = self
            .tls_message_exchange(&mut stream, wire, expected)
            .await?;
        let est_rtt = started.elapsed();
        if reusable && !self.tls_pool_disabled {
            self.tls_pool
                .push(PoolEntry {
                    element: PooledTls { stream, est_rtt },
                    generation,
                })
                .await;
        }
        Ok(response)
    }

    /// The shared h2 conn when it can take another query, dropping it
    /// from the slot when it is dead, idle past the pool timeout, or from
    /// a retired generation.
    #[cfg(feature = "encrypted")]
    fn doh_h2_current(&self) -> Option<Arc<DohH2Conn>> {
        let generation = self.tls_pool.generation();
        let mut slot = self.doh_h2.lock();
        match slot.as_ref() {
            Some(conn) if conn.reusable(generation, Instant::now()) => Some(Arc::clone(conn)),
            Some(_) => {
                tracing::debug!(
                    upstream = %self.upstream_label(),
                    "dns doh h2: shared conn closed, idle or retired; dialing fresh"
                );
                *slot = None;
                None
            }
            None => None,
        }
    }

    /// Make `conn` the shared h2 conn unless a reusable one is already
    /// there: concurrent first queries each dial, and the surplus conns
    /// close once their own stream ends. A conn from a generation retired
    /// while it was dialing is never installed.
    #[cfg(feature = "encrypted")]
    fn doh_h2_install(&self, conn: Arc<DohH2Conn>) {
        let generation = self.tls_pool.generation();
        if !conn.reusable(generation, Instant::now()) {
            return;
        }
        let mut slot = self.doh_h2.lock();
        if slot
            .as_ref()
            .is_none_or(|current| !current.reusable(generation, Instant::now()))
        {
            *slot = Some(conn);
        }
    }

    /// Drop `conn` from the slot if it is still the shared one. Streams
    /// other queries hold on it run to their own end.
    #[cfg(feature = "encrypted")]
    fn doh_h2_retire(&self, conn: &Arc<DohH2Conn>) {
        let mut slot = self.doh_h2.lock();
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, conn))
        {
            *slot = None;
        }
    }

    /// Run the HTTP/2 handshake on a fresh conn that negotiated `h2` and
    /// spawn the task that drives its frames. Server push is refused: a
    /// DoH client has no use for it.
    #[cfg(feature = "encrypted")]
    async fn doh_h2_connect(
        &self,
        stream: TlsConn,
        generation: PoolGeneration,
    ) -> Result<Arc<DohH2Conn>, ClientError> {
        let (send, connection) = h2::client::Builder::new()
            .enable_push(false)
            .handshake::<_, bytes::Bytes>(stream)
            .await
            .map_err(|e| doh_h2_error(&e))?;
        let upstream = self.upstream_label();
        let driver = tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(%upstream, error = %err, "dns doh h2: connection ended");
            }
        })
        .abort_handle();
        Ok(Arc::new(DohH2Conn {
            send,
            driver,
            generation,
            use_state: parking_lot::Mutex::new(DohH2Use {
                last_used: Instant::now(),
                est_rtt: Duration::ZERO,
            }),
        }))
    }

    /// One DoH exchange as a `POST` stream on `conn` (RFC 8484 §4.1),
    /// returning the response body. The body is capped at
    /// [`MAX_DOH_RESPONSE_BYTES`], as on HTTP/1.1. Dropping the future
    /// (a deadline) resets the stream, not the connection.
    #[cfg(feature = "encrypted")]
    async fn doh_h2_request(&self, conn: &DohH2Conn, wire: &[u8]) -> Result<Vec<u8>, ClientError> {
        let Transport::Doh { sni, path, .. } = &self.transport else {
            unreachable!("doh_h2_request on a non-DoH transport");
        };
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(doh_h2_uri(sni, path))
            .header(http::header::USER_AGENT, "meow-rs")
            .header(http::header::ACCEPT, "application/dns-message")
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .header(http::header::CONTENT_LENGTH, wire.len())
            .body(())
            .map_err(|_| ClientError::Protocol("doh: invalid request URI"))?;
        let mut send = conn
            .send
            .clone()
            .ready()
            .await
            .map_err(|e| doh_h2_error(&e))?;
        let (response, mut request_body) = send
            .send_request(request, false)
            .map_err(|e| doh_h2_error(&e))?;
        request_body
            .send_data(bytes::Bytes::copy_from_slice(wire), true)
            .map_err(|e| doh_h2_error(&e))?;
        let response = response.await.map_err(|e| doh_h2_error(&e))?;
        if response.status() != http::StatusCode::OK {
            return Err(ClientError::Protocol("doh: non-200 status"));
        }
        let mut body = response.into_body();
        let mut out = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|e| doh_h2_error(&e))?;
            let _ = body.flow_control().release_capacity(chunk.len());
            if out.len() + chunk.len() > MAX_DOH_RESPONSE_BYTES {
                return Err(ClientError::Protocol("doh: response exceeds maximum size"));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    async fn exchange(
        &self,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<Message, ClientError> {
        if let Some(proxy) = self.proxy.as_ref() {
            if let Transport::Udp { addr } = &self.transport {
                if proxy.support_udp() && self.proxy_target.is_none() {
                    return proxy_udp_exchange(self, proxy, *addr, wire, expected).await;
                }
            }
            match &self.transport {
                Transport::Udp { .. } | Transport::Tcp { .. } => {
                    let response = self.proxy_tcp_exchange(proxy, wire).await?;
                    return decode_validated_response(&response, expected);
                }
                Transport::RCode { .. } => {
                    return Err(ClientError::Protocol(
                        "rcode transport should not perform network exchange",
                    ));
                }
                #[cfg(feature = "encrypted")]
                Transport::Dot { .. } | Transport::Doh { .. } => {
                    return self.tls_exchange_pooled(wire, expected).await;
                }
                // A `?proxy=` QUIC entry dials the adapter's own datagram
                // association, so it takes the same path as a direct one.
                #[cfg(feature = "quic-dns")]
                Transport::Doq { .. } => return self.quic_exchange(wire, expected).await,
                #[cfg(feature = "quic-dns")]
                Transport::Doh3 { .. } => return self.doh3_exchange(wire, expected).await,
            }
        }
        match &self.transport {
            Transport::Udp { addr } => udp_exchange(*addr, wire, expected).await,
            Transport::Tcp { addr } => self.tcp_exchange_pooled(*addr, wire, expected).await,
            Transport::RCode { .. } => Err(ClientError::Protocol(
                "rcode transport should not perform network exchange",
            )),
            #[cfg(feature = "encrypted")]
            Transport::Dot { .. } | Transport::Doh { .. } => {
                self.tls_exchange_pooled(wire, expected).await
            }
            #[cfg(feature = "quic-dns")]
            Transport::Doq { .. } => self.quic_exchange(wire, expected).await,
            #[cfg(feature = "quic-dns")]
            Transport::Doh3 { .. } => self.doh3_exchange(wire, expected).await,
        }
    }

    /// One DoQ exchange through the per-upstream connection driver.
    #[cfg(feature = "quic-dns")]
    async fn quic_exchange(
        &self,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<Message, ClientError> {
        let upstream = self.quic.as_ref().ok_or(ClientError::Protocol(
            "QUIC transport without an upstream driver",
        ))?;
        let response = upstream.exchange(wire).await?;
        decode_validated_response(&response, expected)
    }

    /// One DoH3 exchange, falling back to the HTTP/1.1 DoH path — the
    /// semantics `prefer-h3` names: h3 is preferred, not required.
    #[cfg(feature = "quic-dns")]
    async fn doh3_exchange(
        &self,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<Message, ClientError> {
        let upstream = self.quic.as_ref().ok_or(ClientError::Protocol(
            "prefer-h3 transport without an upstream driver",
        ))?;
        if upstream.h3_available() {
            // Half the budget. A hung QUIC handshake must leave the HTTP/1.1
            // fallback enough time to answer, or `prefer-h3` would turn a
            // dead UDP path into a dead resolver.
            let budget = self.timeout / 2;
            let failure = match tokio::time::timeout(budget, upstream.exchange(wire)).await {
                Ok(Ok(response)) => {
                    upstream.park_h3(false);
                    return decode_validated_response(&response, expected);
                }
                // A certificate failure is a verdict, not a transport
                // preference: the fallback would fail identically and the
                // silent retry would only hide it.
                Ok(Err(err @ ClientError::Tls(_))) => return Err(err),
                Ok(Err(err)) => err,
                Err(_elapsed) => ClientError::Timeout(budget),
            };
            // `?h3=true` (mihomo's per-entry form) means HTTP/3 only: there
            // is no fallback client to retry on.
            let Some(h1) = self.doh_h1.as_ref() else {
                return Err(failure);
            };
            tracing::debug!(
                upstream = %self.upstream_label(),
                error = %failure,
                "DoH3 exchange failed; retrying over HTTP/1.1"
            );
            // Park only for connectivity/handshake verdicts. A per-query
            // protocol answer on a healthy HTTP/3 connection (non-200 status,
            // empty body, peer reset) is not evidence that the server lacks
            // HTTP/3, and parking would send the next ten minutes of queries
            // over HTTP/1.1 for no reason.
            if matches!(failure, ClientError::Io(_) | ClientError::Timeout(_)) {
                upstream.park_h3(true);
            }
            // Boxed: `exchange` recursing through this helper would otherwise
            // make the async fn infinitely sized. The fallback client is a
            // plain DoH client, so the recursion is one level deep.
            return Box::pin(h1.exchange(wire, expected)).await;
        }
        let Some(h1) = self.doh_h1.as_ref() else {
            // Parked HTTP/3 on a force-only entry: the cooldown is
            // meaningless without a fallback, so retry QUIC instead of
            // failing a query that a fresh connection could answer.
            upstream.park_h3(false);
            let response = upstream.exchange(wire).await?;
            return decode_validated_response(&response, expected);
        };
        Box::pin(h1.exchange(wire, expected)).await
    }
}

struct ExpectedResponse {
    id: u16,
    query: Query,
}

fn decode_validated_response(
    wire: &[u8],
    expected: &ExpectedResponse,
) -> Result<Message, ClientError> {
    let response = Message::from_bytes(wire)?;
    validate_response(&response, expected)?;
    Ok(response)
}

async fn tcp_message_exchange(
    stream: &mut TcpStream,
    wire: &[u8],
    expected: &ExpectedResponse,
) -> Result<Message, ClientError> {
    write_lp(stream, wire).await?;
    let response = read_lp(stream).await?;
    decode_validated_response(&response, expected)
}

fn validate_response(response: &Message, expected: &ExpectedResponse) -> Result<(), ClientError> {
    if response.metadata.id != expected.id {
        return Err(ClientError::Protocol("response ID mismatch"));
    }
    if response.metadata.message_type != MessageType::Response {
        return Err(ClientError::Protocol("received DNS query as response"));
    }
    if response.metadata.op_code != OpCode::Query {
        return Err(ClientError::Protocol("response opcode mismatch"));
    }
    let [question] = response.queries.as_slice() else {
        return Err(ClientError::Protocol("response question count mismatch"));
    };
    if !question.name.eq_ignore_root(&expected.query.name) {
        return Err(ClientError::Protocol("response question name mismatch"));
    }
    if question.query_type != expected.query.query_type {
        return Err(ClientError::Protocol("response question type mismatch"));
    }
    if question.query_class != expected.query.query_class {
        return Err(ClientError::Protocol("response question class mismatch"));
    }
    Ok(())
}

/// `https://host[:port][path]` — the label DoH and its HTTP/3 form share,
/// since both name the same upstream URL.
#[cfg(feature = "encrypted")]
fn doh_label(addr: &SocketAddr, sni: &str, path: &str) -> String {
    if sni.is_empty() {
        format!("https://{}", socket_label(*addr, 443))
    } else if path == "/dns-query" {
        if addr.port() == 443 {
            format!("https://{sni}")
        } else {
            format!("https://{sni}:{}", addr.port())
        }
    } else if addr.port() == 443 {
        format!("https://{sni}{path}")
    } else {
        format!("https://{sni}:{}{path}", addr.port())
    }
}

fn socket_label(addr: SocketAddr, default_port: u16) -> String {
    if addr.port() == default_port {
        addr.ip().to_string()
    } else {
        addr.to_string()
    }
}

#[cfg(feature = "encrypted")]
fn tls_connect_error<S>(err: meow_transport::tls::ConnectTypedError<S>) -> ClientError {
    // `into_transport` keeps `Handshake`'s inner io error (raw errno)
    // intact — ENOBUFS/EMFILE at the socket layer must reach the
    // resolver's local-resource classification (#680/#682) instead of
    // being flattened into a context-less `Tls` string.
    match err.into_transport() {
        meow_transport::TransportError::Io(io_err) => ClientError::Io(io_err),
        other => ClientError::Tls(other.to_string()),
    }
}

/// The packet association belongs to this query future. Dropping an exchange
/// on success, error, timeout or caller cancellation always signals close.
struct DnsPacket(Box<dyn meow_common::ProxyPacketConn>);

impl Drop for DnsPacket {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}

async fn proxy_udp_exchange(
    client: &DnsClient,
    proxy: &DnsProxy,
    addr: SocketAddr,
    wire: &[u8],
    expected: &ExpectedResponse,
) -> Result<Message, ClientError> {
    use meow_common::{ConnType, Metadata, Network};
    // Same canonicalization as proxy_dial: an adapter dialing dst_ip
    // verbatim (DirectAdapter) fails on v4-mapped IPv6 nameservers.
    let addr = meow_common::canonical_socket_addr(addr);
    let metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Inner,
        host: smol_str::SmolStr::from(addr.ip().to_string()),
        dst_ip: Some(addr.ip()),
        dst_port: addr.port(),
        internal: true,
        ..Default::default()
    };
    let packet = DnsPacket(
        meow_common::socket_protect::dns_via_proxy_dial_scope(proxy.dial_udp(&metadata))
            .await
            .map_err(|e| e.into_io_error("dns-via-proxy UDP dial"))?,
    );
    let written = packet
        .0
        .write_packet(wire, &addr)
        .await
        .map_err(|e| e.into_io_error("dns-via-proxy UDP send"))?;
    if written != wire.len() {
        return Err(ClientError::Protocol("short DNS datagram write"));
    }
    // The full DNS wire limit, bounded per query. A shorter receive buffer
    // could silently truncate a datagram before its DNS TC flag is examined.
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = packet
            .0
            .read_packet(&mut buf)
            .await
            .map_err(|e| e.into_io_error("dns-via-proxy UDP receive"))?;
        // Bound transports may report an unspecified source by contract.
        // For per-packet transports verify both address and port, accepting
        // equivalent IPv4-mapped IPv6 representations.
        if !peer.ip().to_canonical().is_unspecified()
            && (peer.ip().to_canonical() != addr.ip().to_canonical() || peer.port() != addr.port())
        {
            continue;
        }
        let Some(bytes) = buf.get(..n) else {
            return Err(ClientError::Protocol("oversized DNS datagram read"));
        };
        let Ok(response) = decode_validated_response(bytes, expected) else {
            continue;
        };
        if response.metadata.truncation {
            // Release the UDP association before the explicit DNS TCP retry,
            // through the same proxy and under the query's original deadline.
            drop(packet);
            let response = client.proxy_tcp_exchange(proxy, wire).await?;
            return decode_validated_response(&response, expected);
        }
        return Ok(response);
    }
}

#[cfg(test)]
#[path = "proxy_udp_tests.rs"]
mod proxy_udp_tests;

fn ip_from_record(rec: &Record) -> Option<IpAddr> {
    match &rec.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

fn canonical_name(name: &Name) -> Name {
    let mut canonical = name.to_lowercase();
    canonical.set_fqdn(true);
    canonical
}

/// RFC 2308 negative-cache TTL for an NXDOMAIN/NODATA response: the minimum of
/// the SOA record's own TTL and its MINIMUM field, taken from the authority
/// (`authorities`) section. Returns `0` when no SOA is present — the
/// resolver's clamp floor still gives such a negative a short cache life.
/// Mirrors mihomo's `minimalTTL(concat(Answer, Ns, Extra))` for negative
/// responses (the SOA lives in the authority section).
fn negative_ttl(message: &Message) -> Duration {
    let mut best: Option<u32> = None;
    for record in &message.authorities {
        let RData::SOA(soa) = &record.data else {
            continue;
        };
        let ttl = record.ttl.min(soa.minimum);
        best = Some(best.map_or(ttl, |b| b.min(ttl)));
    }
    Duration::from_secs(u64::from(best.unwrap_or(0)))
}

fn classify_family_message(message: &Message) -> FamilyAnswer {
    match message.metadata.response_code {
        ResponseCode::NoError => {
            let (ips, ttl) = relevant_ip_answers(message);
            if ips.is_empty() {
                // NODATA uses the SOA negative TTL even when the response
                // contains a CNAME with its own TTL but no terminal address.
                FamilyAnswer::NoData(negative_ttl(message))
            } else {
                FamilyAnswer::Answer {
                    ips,
                    ttl: Duration::from_secs(u64::from(ttl.unwrap_or(0))),
                }
            }
        }
        ResponseCode::NXDomain => FamilyAnswer::NxDomain(negative_ttl(message)),
        _ => FamilyAnswer::Failed,
    }
}

/// Merge the concurrent A and AAAA exchange results of the dual-stack
/// `lookup_ip_with_ipv6_inner` path into one [`IpLookupResult`].
///
/// Verdict precedence (#682): a positive `Answer` on either family wins
/// over a sibling transport failure — an `Err` cannot veto dialable
/// addresses (name-authoritative NXDOMAIN can — see below).
/// NXDOMAIN is name-authoritative and settles the whole lookup (the
/// missing/errored sibling is reported as NXDOMAIN too, matching the
/// historical A-side propagation). Only when *no* usable answer exists —
/// the remaining verdicts are `NoData`/`Failed`, which say nothing about
/// the family whose exchange never completed — does an observed
/// transport failure surface as `Err`, with `prefer_errno` keeping the
/// errno-bearing one. This is what stops a one-sided `EMFILE` from being
/// reported as "host unresolvable" and dead-marking a healthy member.
fn merge_family_results(
    v4_result: Result<Message, ClientError>,
    v6_result: Result<Message, ClientError>,
) -> Result<IpLookupResult, ClientError> {
    let v4 = v4_result.as_ref().ok().map(classify_family_message);
    let v6 = v6_result.as_ref().ok().map(classify_family_message);

    // NXDOMAIN from A means the name does not exist at all — propagate
    // to both families (mirrors the old sequential behaviour).
    if let Some(FamilyAnswer::NxDomain(ttl)) = &v4 {
        return Ok(IpLookupResult {
            ips: Vec::new(),
            ttl: *ttl,
            v4: v4.clone(),
            v6: Some(FamilyAnswer::NxDomain(*ttl)),
        });
    }
    // Symmetric arm: a v6 NXDOMAIN is equally name-authoritative. When the
    // A exchange *errored* it still settles the lookup — an unknown family
    // state cannot resurrect a nonexistent name. (When v4 produced a
    // verdict, it is kept verbatim below.)
    if v4.is_none() {
        if let Some(FamilyAnswer::NxDomain(ttl)) = &v6 {
            return Ok(IpLookupResult {
                ips: Vec::new(),
                ttl: *ttl,
                v4: Some(FamilyAnswer::NxDomain(*ttl)),
                v6: v6.clone(),
            });
        }
    }

    // Collect addresses with IPv4 first (prefer-IPv4 ordering).
    let mut addrs = Vec::new();
    let mut min_ttl: Option<Duration> = None;
    if let Some(FamilyAnswer::Answer { ips, ttl }) = &v4 {
        addrs.extend_from_slice(ips);
        min_ttl = Some(*ttl);
    }
    if let Some(FamilyAnswer::Answer { ips, ttl }) = &v6 {
        addrs.extend_from_slice(ips);
        min_ttl = Some(min_ttl.map_or(*ttl, |current| current.min(*ttl)));
    }

    if addrs.is_empty() && (v4_result.is_err() || v6_result.is_err()) {
        // No usable answer and at least one family's exchange failed —
        // the lookup is *unproven*, not unresolvable (#682).
        return Err(prefer_errno(v4_result.err(), v6_result.err()).expect("gated by is_err"));
    }
    Ok(IpLookupResult {
        ips: addrs,
        ttl: min_ttl.unwrap_or(Duration::ZERO),
        v4,
        v6,
    })
}

struct CnameLink {
    target: Name,
    ttl: u32,
    ambiguous: bool,
}

fn relevant_ip_answers(message: &Message) -> (Vec<IpAddr>, Option<u32>) {
    let Some(question) = message.queries.first() else {
        return (Vec::new(), None);
    };
    if !matches!(question.query_type, RecordType::A | RecordType::AAAA) {
        return (Vec::new(), None);
    }

    // Index CNAME links once, then walk the single chain from QNAME. Besides
    // making answer order irrelevant, this keeps hostile reverse-ordered
    // chains linear instead of repeatedly rescanning every answer.
    let mut cname_links = HashMap::new();
    for record in &message.answers {
        if record.dns_class != question.query_class {
            continue;
        }
        let RData::CNAME(target) = &record.data else {
            continue;
        };
        let owner = canonical_name(&record.name);
        let target = canonical_name(&target.0);
        match cname_links.entry(owner) {
            Entry::Vacant(entry) => {
                entry.insert(CnameLink {
                    target,
                    ttl: record.ttl,
                    ambiguous: false,
                });
            }
            Entry::Occupied(mut entry) => {
                let link = entry.get_mut();
                if link.target == target {
                    link.ttl = link.ttl.min(record.ttl);
                } else {
                    // Multiple canonical names for one owner violate the
                    // CNAME rules. Do not pick an attacker-controlled branch.
                    link.ambiguous = true;
                }
            }
        }
    }

    let mut reachable = HashSet::new();
    let mut current = canonical_name(&question.name);
    let mut cname_ttl: Option<u32> = None;
    loop {
        if !reachable.insert(current.clone()) {
            // A CNAME loop has no usable terminal address.
            return (Vec::new(), None);
        }
        let Some(link) = cname_links.get(&current) else {
            break;
        };
        if link.ambiguous {
            return (Vec::new(), None);
        }
        cname_ttl = Some(cname_ttl.map_or(link.ttl, |ttl| ttl.min(link.ttl)));
        current = link.target.clone();
    }

    let mut addrs = Vec::new();
    let mut min_ttl = cname_ttl;
    for record in &message.answers {
        if record.dns_class != question.query_class
            || !reachable.contains(&canonical_name(&record.name))
        {
            continue;
        }
        let matches_query = matches!(
            (&record.data, question.query_type),
            (RData::A(_), RecordType::A) | (RData::AAAA(_), RecordType::AAAA)
        );
        if matches_query {
            addrs.extend(ip_from_record(record));
            min_ttl = Some(min_ttl.map_or(record.ttl, |ttl| ttl.min(record.ttl)));
        }
    }
    (addrs, min_ttl)
}

/// Convert the prefer-IPv4 A-then-AAAA result into a [`FamilySet`]. The
/// family answers retain NXDOMAIN versus NODATA so the shared cache cannot
/// downgrade the upstream RCODE.
fn family_set_from_ip_lookup(result: &IpLookupResult, source: String) -> FamilySet {
    FamilySet {
        v4: result.v4.clone(),
        v6: result.v6.clone(),
        source,
    }
}

async fn udp_exchange(
    addr: SocketAddr,
    wire: &[u8],
    expected: &ExpectedResponse,
) -> Result<Message, ClientError> {
    // A loopback upstream (e.g. the resolver's own `dns.listen` socket,
    // which some subscriptions name in `proxy-server-nameserver`) must be
    // dialed from a loopback-bound socket, not the wildcard the factory
    // binds for internet upstreams. Inside an iOS packet-tunnel extension
    // the process's wildcard-bound sockets are scoped to the physical
    // interface so they bypass the tunnel, and a scoped route lookup for
    // 127.0.0.1 fails at once — the query never reaches the listener.
    // Binding to the loopback address selects `lo0` explicitly; it also
    // needs no VPN `protect()` on Android because loopback is never routed
    // into the tunnel.
    let addr = meow_common::canonical_socket_addr(addr);
    let sock = if addr.ip().is_loopback() {
        let local: SocketAddr = match addr {
            SocketAddr::V4(_) => SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
        };
        UdpSocket::bind(local).await?
    } else {
        factory().bind_udp_for_peer(addr.ip()).await?
    };
    sock.connect(addr).await?;
    sock.send(wire).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        let Ok(response) = decode_validated_response(&buf[..n], expected) else {
            // A connected UDP socket only filters the peer tuple. Ignore
            // malformed or unrelated datagrams and keep waiting under the
            // query's original overall timeout.
            continue;
        };
        if response.metadata.truncation {
            // RFC 7766 §0: retry a truncated UDP answer over TCP with a
            // one-off connection (the truncation fallback is intentionally
            // not pooled).
            let mut stream = factory().connect_tcp(addr).await?;
            return tcp_message_exchange(&mut stream, wire, expected).await;
        }
        return Ok(response);
    }
}

async fn write_lp<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let len =
        u16::try_from(payload.len()).map_err(|_| io::Error::other("dns message too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

async fn read_lp<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>, ClientError> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// The HTTP/1.1 half of a DoH exchange — shared by the direct and
/// proxied paths, which differ only in how `stream` was dialed.
///
/// Sends a minimal `POST path` with `application/dns-message` (no
/// `Connection: close` — the session is poolable), restricted to
/// `Accept-Encoding: identity` so a coded body cannot poison the DNS
/// parse, then reads the response with full RFC 7230 §3.3 framing via
/// [`read_http_response`] and returns the DNS body plus the
/// pool-eligibility verdict.
#[cfg(feature = "encrypted")]
async fn doh_http_exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
    stream: &mut S,
    sni: &str,
    path: &str,
    wire: &[u8],
) -> Result<(Vec<u8>, bool), ClientError> {
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: meow-rs\r\n\
         Accept: application/dns-message\r\n\
         Accept-Encoding: identity\r\n\
         Content-Type: application/dns-message\r\n\
         Content-Length: {len}\r\n\
         \r\n",
        host = sni,
        len = wire.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(wire).await?;
    stream.flush().await?;

    read_http_response(stream).await
}

/// An h2 failure as `Io`: GOAWAY, a reset stream or a dead connection is
/// what the reuse path's `{Io, deadline}` retry whitelist exists for.
#[cfg(feature = "encrypted")]
fn doh_h2_error(err: &h2::Error) -> ClientError {
    ClientError::Io(io::Error::other(format!("doh h2: {err}")))
}

/// The `:scheme`/`:authority`/`:path` of a DoH request. `sni` is what
/// HTTP/1.1 sends as `Host`; an IPv6 literal needs brackets here.
#[cfg(feature = "encrypted")]
fn doh_h2_uri(sni: &str, path: &str) -> String {
    if sni.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("https://[{sni}]{path}")
    } else {
        format!("https://{sni}{path}")
    }
}

/// Incremental reader for one HTTP/1.1 DoH response. Reads run just ahead
/// of the parser and stop at message boundaries, so a keep-alive peer is
/// never asked for bytes it will never send; every byte read counts
/// toward [`MAX_DOH_RESPONSE_BYTES`].
#[cfg(feature = "encrypted")]
struct HttpReader<'a, R> {
    stream: &'a mut R,
    buf: Vec<u8>,
    /// Parse cursor: `buf[..pos]` is consumed.
    pos: usize,
}

/// The fields of a final (non-`1xx`) DoH response head that decide body
/// framing and pool eligibility.
#[cfg(feature = "encrypted")]
struct DohHead {
    /// `HTTP/1.1` status line — keep-alive is the 1.1 default; anything
    /// older is treated as close-delimited regardless of headers.
    http11: bool,
    /// A `Connection:` header carrying the `close` token.
    connection_close: bool,
    /// `Some(final_coding_is_chunked)` when a `Transfer-Encoding` header
    /// is present — per RFC 7230 §3.3.1 a non-chunked final coding makes
    /// the body close-delimited.
    transfer_encoding: Option<bool>,
    content_length: Option<usize>,
}

/// The classification boundary for DoH exchange failures (review M3):
/// an EOF *anywhere* inside an in-flight response is `Io`
/// (`UnexpectedEof`), never `Protocol` — on a pooled conn a mid-read EOF
/// is indistinguishable from a dead socket, so the `{Io, deadline}`
/// retry whitelist must see it for the transparent redial to fire.
/// `Protocol` is reserved for malformed *content*: bytes that actually
/// arrived and violate RFC 7230.
#[cfg(feature = "encrypted")]
fn doh_eof(context: &'static str) -> ClientError {
    ClientError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, context))
}

#[cfg(feature = "encrypted")]
impl<R> HttpReader<'_, R>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    fn new(stream: &mut R) -> HttpReader<'_, R> {
        HttpReader {
            stream,
            buf: Vec::with_capacity(1024),
            pos: 0,
        }
    }

    fn unconsumed(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
    }

    /// Append one more read to the buffer. `Ok(false)` on EOF.
    async fn fill(&mut self) -> Result<bool, ClientError> {
        let mut chunk = [0u8; 4096];
        let n = self.stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(false);
        }
        self.buf.extend_from_slice(&chunk[..n]);
        if self.buf.len() > MAX_DOH_RESPONSE_BYTES {
            return Err(ClientError::Protocol("doh: response exceeds maximum size"));
        }
        Ok(true)
    }

    /// Buffer until `needle` appears in the unconsumed bytes and return
    /// its offset from the cursor. `Err(Io(UnexpectedEof))` on EOF first
    /// — [`doh_eof`] keeps truncation retryable on pooled conns.
    async fn fill_until(
        &mut self,
        needle: &[u8],
        eof_err: &'static str,
    ) -> Result<usize, ClientError> {
        // `unconsumed()` only grows inside this loop (`pos` is untouched
        // until the caller consumes), so a start offset already scanned
        // stays ruled out: resume just `needle.len() - 1` bytes back —
        // a match may straddle the previous fill's tail. Rescanning the
        // whole buffer after every fill would let a byte-dribbling peer
        // turn the parse into O(buf²) CPU burn inside the query
        // deadline (review I2).
        let mut scanned = 0usize;
        loop {
            let hay = self.unconsumed();
            if let Some(at) = find_subseq(hay.get(scanned..).unwrap_or_default(), needle) {
                return Ok(scanned + at);
            }
            scanned = hay.len().saturating_sub(needle.len().saturating_sub(1));
            if !self.fill().await? {
                return Err(doh_eof(eof_err));
            }
        }
    }

    /// Take exactly `len` body bytes, buffered remainder first. An EOF
    /// inside a `Content-Length` body is a truncated exchange — an `Io`
    /// failure so a pooled conn hit by it is retryable once.
    async fn read_len(&mut self, len: usize) -> Result<Vec<u8>, ClientError> {
        while self.unconsumed().len() < len {
            if !self.fill().await? {
                return Err(doh_eof("doh: EOF inside content-length body"));
            }
        }
        let body = self.unconsumed()[..len].to_vec();
        self.consume(len);
        Ok(body)
    }

    /// Read a close-delimited body: buffered remainder plus the rest of
    /// the stream via [`read_bounded_http_response`] (the historical EOF
    /// arm), the total bounded by [`MAX_DOH_RESPONSE_BYTES`].
    async fn read_to_eof(&mut self) -> Result<Vec<u8>, ClientError> {
        // Include already-read headers and body in the same budget before
        // awaiting any more input. An oversized response need not send EOF.
        let all = read_bounded_http_response(self.stream, std::mem::take(&mut self.buf)).await?;
        Ok(all[self.pos..].to_vec())
    }

    /// Read a `Transfer-Encoding: chunked` body (RFC 7230 §4.1): hex-size
    /// lines (extensions ignored), data + trailing CRLF, a zero chunk,
    /// then trailer fields to the terminating empty line.
    async fn read_chunked(&mut self) -> Result<Vec<u8>, ClientError> {
        let mut body = Vec::new();
        loop {
            let line_len = self
                .fill_until(b"\r\n", "doh: EOF inside chunked body")
                .await?;
            let line = std::str::from_utf8(&self.unconsumed()[..line_len])
                .map_err(|_| ClientError::Protocol("doh: bad chunk size"))?;
            // Chunk extensions (`;name=val`) are ignored per §4.1.1.
            let size_token = line.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size_token, 16)
                .map_err(|_| ClientError::Protocol("doh: bad chunk size"))?;
            // Bound the declaration before any arithmetic: a
            // `usize::MAX`-scale chunk size must be a plain `Protocol`
            // rejection — otherwise `body.len() + size` and `size + 2`
            // below wrap into a slice-index panic (review M1).
            if size > MAX_DOH_RESPONSE_BYTES {
                return Err(ClientError::Protocol("doh: response exceeds maximum size"));
            }
            self.consume(line_len + 2);
            if size == 0 {
                // Trailer section: header fields to the empty line.
                loop {
                    let tlen = self
                        .fill_until(b"\r\n", "doh: EOF inside chunked trailer")
                        .await?;
                    self.consume(tlen + 2);
                    if tlen == 0 {
                        return Ok(body);
                    }
                }
            }
            if body.len() + size > MAX_DOH_RESPONSE_BYTES {
                return Err(ClientError::Protocol("doh: response exceeds maximum size"));
            }
            while self.unconsumed().len() < size + 2 {
                if !self.fill().await? {
                    return Err(doh_eof("doh: EOF inside chunked body"));
                }
            }
            if &self.unconsumed()[size..size + 2] != b"\r\n" {
                return Err(ClientError::Protocol("doh: bad chunk terminator"));
            }
            body.extend_from_slice(&self.unconsumed()[..size]);
            self.consume(size + 2);
        }
    }
}

/// Read one HTTP/1.1 response off a DoH stream with full RFC 7230 §3.3
/// framing: interim `1xx` blocks are skipped, status must be `200`, and
/// the body is framed by `Transfer-Encoding: chunked`, `Content-Length`,
/// or connection close — in that precedence.
///
/// Returns the body plus the pool-eligibility verdict: `false` for a
/// `Connection: close` header, a non-`HTTP/1.1` status line, a
/// non-chunked final transfer coding, or a close-delimited body — those
/// responses are still correct answers, their conns are just not
/// reusable. Non-200 statuses and framing errors (unparseable chunk
/// sizes, missing terminators, the size cap) are [`ClientError::Protocol`]
/// and never reach the pool — while an EOF at any parser stage is `Io`
/// per [`doh_eof`], because on a pooled conn it is indistinguishable
/// from a dead socket and must reach the `{Io, deadline}` retry
/// whitelist (review M3).
#[cfg(feature = "encrypted")]
async fn read_http_response<R>(stream: &mut R) -> Result<(Vec<u8>, bool), ClientError>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    let mut reader = HttpReader::new(stream);
    let head = loop {
        let head_len = reader
            .fill_until(b"\r\n\r\n", "doh: EOF inside response headers")
            .await?;
        let head_str = std::str::from_utf8(&reader.unconsumed()[..head_len])
            .map_err(|_| ClientError::Protocol("doh: bad headers"))?;
        let mut lines = head_str.lines();
        let status_line = lines
            .next()
            .ok_or(ClientError::Protocol("doh: empty response"))?;
        // "HTTP/1.1 200 OK" — version token, status code, reason phrase.
        let mut parts = status_line.split_whitespace();
        let version = parts.next().unwrap_or_default();
        let status: u16 = parts
            .next()
            .and_then(|code| code.parse().ok())
            .unwrap_or_default();
        if (100..200).contains(&status) && status != 101 {
            // Interim response (e.g. `100 Continue`) — consume this block
            // and read the final head that follows.
            reader.consume(head_len + 4);
            continue;
        }
        if status != 200 {
            return Err(ClientError::Protocol("doh: non-200 status"));
        }
        let mut head = DohHead {
            http11: version.eq_ignore_ascii_case("HTTP/1.1"),
            connection_close: false,
            transfer_encoding: None,
            content_length: None,
        };
        for line in lines {
            // Colon-less lines — including obs-fold continuations — are
            // skipped, so a `close` token folded onto a second line of
            // `Connection:` can be missed and the conn pooled anyway.
            // Tolerated deliberately: the desync stays bounded by the
            // checkout liveness probe + the next exchange's validation
            // (review I3).
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if name.trim().eq_ignore_ascii_case("connection") {
                head.connection_close = head.connection_close
                    || value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("close"));
            } else if name.trim().eq_ignore_ascii_case("transfer-encoding") {
                // The final coding of the (possibly multi-header) list
                // decides framing — earlier codings were already undone.
                head.transfer_encoding = Some(
                    value
                        .rsplit(',')
                        .next()
                        .is_some_and(|coding| coding.trim().eq_ignore_ascii_case("chunked")),
                );
            } else if name.trim().eq_ignore_ascii_case("content-encoding") {
                if !value.eq_ignore_ascii_case("identity") {
                    return Err(ClientError::Protocol("doh: unsupported content-encoding"));
                }
            } else if name.trim().eq_ignore_ascii_case("content-length") {
                // Duplicate CLs take the last value. RFC 7230 §3.3.3 #4
                // wants mismatched duplicates rejected — tolerated
                // deliberately, on the same bounded-desync reasoning as
                // the obs-fold skip above (review I3).
                head.content_length = Some(
                    value
                        .parse()
                        .map_err(|_| ClientError::Protocol("doh: bad content-length"))?,
                );
            }
        }
        reader.consume(head_len + 4);
        break head;
    };

    let reusable = head.http11 && !head.connection_close;
    match (head.transfer_encoding, head.content_length) {
        // Chunked is self-delimiting — the conn stays reusable.
        (Some(true), _) => Ok((reader.read_chunked().await?, reusable)),
        // A non-chunked final coding or no length at all: the body ends
        // at connection close — correct answer, unpoolable conn.
        (Some(false), _) | (None, None) => Ok((reader.read_to_eof().await?, false)),
        (None, Some(len)) => {
            if len > MAX_DOH_RESPONSE_BYTES {
                return Err(ClientError::Protocol("doh: response exceeds maximum size"));
            }
            Ok((reader.read_len(len).await?, reusable))
        }
    }
}

/// Free liveness probe before a pooled TLS conn is reused — costs no
/// wire bytes and consumes nothing on the healthy path:
///
/// - `SSL_pending > 0`: decrypted bytes sit buffered, but a drained
///   exchange leaves none — these are desync remnants. Dead.
/// - `poll_read` `Ready` with bytes: stray data, same desync. Dead (the
///   byte is consumed, but the conn is being discarded anyway).
/// - `poll_read` `Ready` with no bytes: close_notify/FIN or an error.
///   Dead.
/// - `poll_read` `Pending`: nothing arrived — TLS 1.3 session tickets
///   are consumed inside `SSL_read` and never surface as app data, so a
///   pending probe means a clean conn. Alive.
#[cfg(feature = "encrypted")]
async fn tls_conn_alive(stream: &mut TlsConn) -> bool {
    use std::task::Poll;
    use tokio::io::{AsyncRead, ReadBuf};

    if stream.ssl().pending() > 0 {
        return false;
    }
    let mut byte = [0u8; 1];
    std::future::poll_fn(|cx| {
        let mut rb = ReadBuf::new(&mut byte);
        // Ready(Ok) with bytes = stray desync data; with none =
        // close_notify/FIN; Ready(Err) = RST — all dead. (A byte may be
        // consumed, but the conn is being discarded regardless.) Only a
        // `Pending` poll means a clean, reusable conn.
        Poll::Ready(stream.as_mut().poll_read(cx, &mut rb).is_pending())
    })
    .await
}

/// Maximum DoH response size (HTTP/1.1 headers + DNS body), in bytes.
///
/// DNS wire messages are inherently capped at 65535 bytes — the 2-octet
/// length prefix used by DNS-over-TCP and DNS-over-TLS (`read_lp`) enforces
/// it structurally. DoH, however, frames the DNS message inside an HTTP
/// response, and every framing arm of [`read_http_response`] —
/// `Content-Length`, chunked, and close-delimited — applies this cap so a
/// misbehaving or hostile upstream cannot stream an arbitrarily large body
/// and drive unbounded heap growth (low-risk review item). Cap the total
/// response at the DNS message maximum plus generous room for HTTP/1.1
/// headers; a well-formed DoH answer always fits while an oversized response
/// is rejected.
#[cfg(feature = "encrypted")]
pub(crate) const MAX_DOH_RESPONSE_BYTES: usize = 65535 + 16 * 1024;

/// Read a stream to EOF, rejecting responses whose total size exceeds
/// [`MAX_DOH_RESPONSE_BYTES`]. This is the close-delimited body arm of
/// [`read_http_response`] (via [`HttpReader::read_to_eof`]) — split out so
/// the bounded read stays unit testable without standing up a TLS DoH
/// server.
#[cfg(feature = "encrypted")]
async fn read_bounded_http_response<R>(
    stream: &mut R,
    mut all: Vec<u8>,
) -> Result<Vec<u8>, ClientError>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        all.extend_from_slice(&chunk[..n]);
        if all.len() > MAX_DOH_RESPONSE_BYTES {
            return Err(ClientError::Protocol("doh: response exceeds maximum size"));
        }
    }
    Ok(all)
}

#[cfg(feature = "encrypted")]
fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Build the TLS layer for one DoT/DoH exchange.
///
/// Goes through `meow_transport::tls::TlsLayer`, so DNS uses the same
/// BoringSSL backend as every proxy handshake in the binary.  The backend
/// memoises its per-process TLS context keyed on
/// `(fingerprint, curves, alpn, skip_cert_verify)`, so this is a hash
/// lookup plus a refcount bump per query — negligible next to the fresh
/// TCP + TLS handshake each exchange performs.
///
/// `extra_roots` is empty in production; the test-only
/// [`DnsClient::with_tls_additional_roots`] hook fills it so in-process
/// upstreams can present self-signed chains.
#[cfg(feature = "encrypted")]
fn tls_layer(sni: &str, alpn: &[&str], extra_roots: &[Vec<u8>]) -> Result<TlsLayer, ClientError> {
    let config = TlsConfig {
        alpn: alpn.iter().map(|p| (*p).to_owned()).collect(),
        additional_roots: extra_roots.to_vec(),
        ..TlsConfig::new(sni)
    };
    TlsLayer::new(&config).map_err(|e| ClientError::Tls(format!("invalid SNI '{sni}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::DNSClass;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn expected(name: &str, record_type: RecordType, id: u16) -> ExpectedResponse {
        ExpectedResponse {
            id,
            query: Query::query(name.parse().unwrap(), record_type),
        }
    }

    fn response_for(request: &Message, id: u16) -> Message {
        let mut response = Message::new(id, MessageType::Response, OpCode::Query);
        response.add_queries(request.queries.iter().cloned());
        response
    }

    fn a_record(name: &str, ttl: u32, octets: [u8; 4]) -> Record {
        Record::from_rdata(
            name.parse().unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::from(octets))),
        )
    }

    fn cname_record(name: &str, ttl: u32, target: &str) -> Record {
        Record::from_rdata(
            name.parse().unwrap(),
            ttl,
            RData::CNAME(CNAME(target.parse().unwrap())),
        )
    }

    #[cfg(feature = "encrypted")]
    #[test]
    fn find_subseq_basic() {
        assert_eq!(find_subseq(b"abc\r\n\r\nbody", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subseq(b"abcdef", b"\r\n\r\n"), None);
        assert_eq!(find_subseq(b"", b"x"), None);
    }

    /// A close-delimited DoH body charges the bytes already buffered with
    /// the headers against the cap, so an oversized response is rejected
    /// without waiting for EOF.
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_close_delimited_counts_buffered_bytes_before_eof() {
        let (mut client, mut server) = tokio::io::duplex(2 * MAX_DOH_RESPONSE_BYTES);
        // Leave the peer open after exceeding the total budget. The first
        // fill includes part of this body along with the headers.
        let response = [
            b"HTTP/1.0 200 OK\r\n\r\n".to_vec(),
            vec![b'x'; MAX_DOH_RESPONSE_BYTES + 1],
        ]
        .concat();
        server.write_all(&response).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), read_http_response(&mut client))
            .await
            .expect("oversized buffered body must not wait for EOF");
        assert!(matches!(
            result,
            Err(ClientError::Protocol("doh: response exceeds maximum size"))
        ));
    }

    /// `Accept-Encoding: identity` is sent, and a server that ignores it
    /// with a coded body is rejected rather than fed garbage bytes.
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_requests_identity_from_a_compression_capable_server() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(server.read_u8().await.unwrap());
            }
            let head = String::from_utf8(head).unwrap();
            let mut query = [0; 5];
            server.read_exact(&mut query).await.unwrap();
            let body: &[u8] = if head.contains("\r\nAccept-Encoding: identity\r\n") {
                b"ABCD"
            } else {
                // A gzip-coded ABCD response; absence of Accept-Encoding does
                // not forbid a server from applying a content coding.
                &[
                    31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 115, 116, 114, 118, 1, 0, 165, 32, 23, 219, 4,
                    0, 0, 0,
                ]
            };
            let coding = if body == b"ABCD" { "identity" } else { "gzip" };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            server.write_all(response.as_bytes()).await.unwrap();
            server.write_all(body).await.unwrap();
        });
        let (body, _) = doh_http_exchange(&mut client, "dns.example", "/dns-query", b"query")
            .await
            .unwrap();
        peer.await.unwrap();
        assert_eq!(body, b"ABCD");
    }

    /// A DoH response at exactly the cap is accepted; one byte over the cap
    /// is rejected with a protocol error. Guards the low-risk review fix
    /// that bounds the previously unbounded `read_to_end`.
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_bounded_read_enforces_response_size_cap() {
        let at_cap = vec![0u8; MAX_DOH_RESPONSE_BYTES];
        let mut reader = at_cap.as_slice();
        let got = read_bounded_http_response(&mut reader, Vec::new())
            .await
            .unwrap();
        assert_eq!(got.len(), MAX_DOH_RESPONSE_BYTES);

        let over_cap = vec![0u8; MAX_DOH_RESPONSE_BYTES + 1];
        let mut reader = over_cap.as_slice();
        let err = read_bounded_http_response(&mut reader, Vec::new())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ClientError::Protocol("doh: response exceeds maximum size")
            ),
            "expected oversized-rejection, got {err:?}"
        );
    }

    /// Reader that yields at most `step` bytes per `poll_read` — proves
    /// the incremental parser never blocks on bytes past the message it
    /// is framing (a keep-alive peer owes it none) and copes with
    /// boundaries falling anywhere.
    #[cfg(feature = "encrypted")]
    struct Dribble<'a> {
        data: &'a [u8],
        step: usize,
    }

    #[cfg(feature = "encrypted")]
    impl tokio::io::AsyncRead for Dribble<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let n = self.step.min(self.data.len()).min(buf.remaining());
            buf.put_slice(&self.data[..n]);
            self.data = &self.data[n..];
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Drive `read_http_response` over a canned wire response, byte by
    /// byte — the dribble forces every parser boundary to split.
    #[cfg(feature = "encrypted")]
    async fn doh_response(raw: &[u8]) -> Result<(Vec<u8>, bool), ClientError> {
        let mut reader = Dribble { data: raw, step: 3 };
        read_http_response(&mut reader).await
    }

    /// A `Content-Encoding` other than `identity` is rejected while the
    /// headers are parsed — before the body is read or the connection is
    /// considered for pooling.
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_coded_response_is_rejected_before_body_and_pooling() {
        for coding in ["gzip", "br", "identity, gzip"] {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: 999\r\n\r\n"
            );
            assert!(matches!(
                doh_response(head.as_bytes()).await,
                Err(ClientError::Protocol("doh: unsupported content-encoding"))
            ));
        }
    }

    /// The DoH framing matrix (RFC 7230 §3.3): `Content-Length` and
    /// chunked bodies are poolable; `Connection: close`, HTTP/1.0, a
    /// non-chunked final coding and close-delimited bodies answer
    /// correctly but must not be pooled.
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_response_framing_matrix() {
        // Content-Length + keep-alive → reusable.
        let (body, reusable) = doh_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: application/dns-message\r\n\r\nABCD",
        )
        .await
        .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(reusable, "a CL response on a 1.1 conn must be poolable");

        // Chunked + keep-alive → reusable. Chunks split mid-data on
        // purpose; a trailer field rides the last chunk.
        let (body, reusable) = doh_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              2\r\nAB\r\n2;x=y\r\nCD\r\n0\r\nX-T: 1\r\n\r\n",
        )
        .await
        .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(
            reusable,
            "a chunked response on a 1.1 conn must be poolable"
        );

        // Content-Length + `Connection: close` → answer but unpoolable.
        let (body, reusable) =
            doh_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nABCD")
                .await
                .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(!reusable);

        // HTTP/1.0 + Content-Length → answer but unpoolable.
        let (body, reusable) = doh_response(b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nABCD")
            .await
            .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(!reusable);

        // No CL, no TE: close-delimited body — the whole tail is the
        // answer, the conn is spent.
        let (body, reusable) =
            doh_response(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\nABCD")
                .await
                .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(!reusable);

        // A non-chunked final transfer coding is close-delimited too
        // (RFC 7230 §3.3.3 #7).
        let (body, reusable) =
            doh_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nABCD")
                .await
                .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(!reusable);
    }

    /// Header-list semantics the framing depends on (review F5). All
    /// behaviours pinned here are the parser's *actual* contract:
    ///
    /// - a multi-coding `Transfer-Encoding` is decided by its **final**
    ///   coding (RFC 7230 §3.3.1) — `rsplit(',')`, so `gzip, chunked`
    ///   frames chunked while `chunked, gzip` is close-delimited;
    /// - a second `Transfer-Encoding` header continues the same list —
    ///   the later header's final coding decides;
    /// - contradictory duplicate `Content-Length` values take the
    ///   **last** value — a deliberate tolerance: RFC 7230 §3.3.3 #4
    ///   wants mismatched duplicates rejected, but a smuggling-shaped
    ///   desync here stays bounded by the checkout liveness probe +
    ///   the next exchange's response validation (see the parse loop);
    /// - obs-fold continuations are colon-less lines and skipped — a
    ///   `close` token folded onto `Connection:` is *missed* and the
    ///   conn pooled anyway, same bounded-desync tolerance;
    /// - `+N` is accepted by `usize::from_str` for `Content-Length`.
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_response_header_list_semantics() {
        // `TE: gzip, chunked` — the final coding is chunked, so the
        // body is chunk-framed and the conn stays poolable. (A
        // first-coding mutation reads this close-delimited instead.)
        let (body, reusable) = doh_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n\
              4\r\nABCD\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(reusable, "a chunked final coding must be poolable");

        // `TE: chunked, gzip` — final coding is NOT chunked: the body
        // is close-delimited (RFC 7230 §3.3.3 #7) and the conn dies.
        let (body, reusable) =
            doh_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nABCD")
                .await
                .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(!reusable, "a non-chunked final coding must not pool");

        // The same list split across two headers — `TE` fields combine
        // in order, so the later header's coding is the final one.
        let (body, reusable) = doh_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n\
              4\r\nABCD\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(reusable);
        let (body, reusable) = doh_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\nABCD",
        )
        .await
        .unwrap();
        assert_eq!(&body, b"ABCD");
        assert!(!reusable);

        // Contradictory duplicate `Content-Length`: last wins — pinned
        // in both orders (the documented §3.3.3 #4 tolerance).
        let (body, reusable) = doh_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nABCDEF",
        )
        .await
        .unwrap();
        assert_eq!(&body, b"ABCDEF", "the last Content-Length decides");
        assert!(reusable);
        let (body, reusable) =
            doh_response(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nContent-Length: 5\r\n\r\nABCDE")
                .await
                .unwrap();
        assert_eq!(&body, b"ABCDE", "the last Content-Length decides");
        assert!(reusable);

        // A malformed `Content-Length` is still a `Protocol` rejection —
        // both a junk value and the RFC's own merged-list smuggling
        // shape (`2, 2` — the same duplicate, one line).
        for raw in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5abc\r\n\r\nABCDE"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nAB"[..],
        ] {
            assert!(
                matches!(
                    doh_response(raw).await,
                    Err(ClientError::Protocol("doh: bad content-length"))
                ),
                "malformed Content-Length must reject: {raw:?}"
            );
        }

        // obs-fold: a continuation line carries no colon, so it is
        // skipped wholesale — a `close` token folded onto `Connection:`
        // is missed and the conn is pooled regardless. Pinned as the
        // deliberate tolerance it is: the desync is bounded by the
        // liveness probe catching the closed conn on next checkout.
        let (body, reusable) = doh_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n close\r\n\r\nOK",
        )
        .await
        .unwrap();
        assert_eq!(&body, b"OK");
        assert!(
            reusable,
            "a folded `close` token is missed by design (probe-bounded)"
        );

        // Same skip for a folded second `Content-Length` — it cannot
        // smuggle a value past the first header.
        let (body, reusable) =
            doh_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n 4\r\n\r\nAB")
                .await
                .unwrap();
        assert_eq!(&body, b"AB");
        assert!(reusable);

        // `+N` parses: `usize::from_str` accepts a leading `+`.
        let (body, reusable) = doh_response(b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nOK")
            .await
            .unwrap();
        assert_eq!(&body, b"OK");
        assert!(reusable);

        // A `close`-suffixed token is not `close` — only exact tokens
        // count in the `Connection:` list.
        let (body, reusable) =
            doh_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: x-close\r\n\r\nOK")
                .await
                .unwrap();
        assert_eq!(&body, b"OK");
        assert!(reusable);
    }

    /// Interim `1xx` blocks precede the final head; a `Connection:
    /// keep-alive, close` list still counts as close; non-200, framing
    /// errors and truncation surface as `Protocol`/`Io` — never pooled.
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_response_head_and_error_paths() {
        // `100 Continue` then the final 200 head.
        let (body, reusable) = doh_response(
            b"HTTP/1.1 100 Continue\r\n\r\n\
              HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        )
        .await
        .unwrap();
        assert_eq!(&body, b"OK");
        assert!(reusable);

        // Token list containing `close` → unpoolable.
        let (_, reusable) = doh_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive, close\r\n\r\nOK",
        )
        .await
        .unwrap();
        assert!(!reusable);

        // Non-200 → Protocol error.
        assert!(matches!(
            doh_response(b"HTTP/1.1 500 Nope\r\nContent-Length: 0\r\n\r\n").await,
            Err(ClientError::Protocol("doh: non-200 status"))
        ));

        // Bad chunk size → Protocol error.
        assert!(matches!(
            doh_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").await,
            Err(ClientError::Protocol("doh: bad chunk size"))
        ));

        // EOF inside the header block → Io, like every truncation
        // (a pooled conn dying mid-read is indistinguishable from
        // staleness — retryable once; review M3).
        assert!(matches!(
            doh_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4").await,
            Err(ClientError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));

        // EOF inside a Content-Length body → Io (retryable once on a
        // pooled conn, per the retry whitelist).
        assert!(matches!(
            doh_response(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nAB").await,
            Err(ClientError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));

        // A declared CL beyond the cap → Protocol error, no read needed.
        let declared_over = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_DOH_RESPONSE_BYTES + 1
        );
        assert!(matches!(
            doh_response(declared_over.as_bytes()).await,
            Err(ClientError::Protocol("doh: response exceeds maximum size"))
        ));
    }

    /// The EOF classification boundary (review M3): *every* truncation —
    /// an EOF at any parser stage — is `Io(UnexpectedEof)`, so a dead
    /// pooled conn rides the `{Io, deadline}` retry whitelist.
    /// `Protocol` is reserved for bytes that actually arrived and
    /// violate RFC 7230.
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_response_eof_anywhere_is_io_not_protocol() {
        for (stage, raw) in [
            ("mid-head", &b"HTTP/1.1 200 OK\r\nContent-Len"[..]),
            ("mid-1xx", &b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200"[..]),
            (
                "mid-cl-body",
                &b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nAB"[..],
            ),
            (
                "mid-chunk-size",
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2"[..],
            ),
            (
                "mid-chunk-data",
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nAB"[..],
            ),
            (
                "mid-chunk-trailer",
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\nX-T: 1"[..],
            ),
        ] {
            match doh_response(raw).await {
                Err(ClientError::Io(e)) => assert_eq!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof,
                    "{stage}: EOF must classify as Io(UnexpectedEof)"
                ),
                other => panic!("{stage}: expected Io(UnexpectedEof), got {other:?}"),
            }
        }
    }

    /// A `usize::MAX`-scale chunk-size declaration is a plain `Protocol`
    /// rejection — never an arithmetic panic. Regression for the
    /// `body.len() + size` / `size + 2` wrap that turned the declaration
    /// into an out-of-bounds slice index (review M1).
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_response_chunk_size_overflow_is_rejected() {
        for raw in [
            // First chunk declares usize::MAX.
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nB"[..],
            // A prior chunk makes `body.len() + size` the wrap site.
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nffffffffffffffff\r\nB"[..],
            // usize::MAX - 1 keeps `size + 2` on the wrap boundary too.
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nfffffffffffffffe\r\nB"[..],
        ] {
            match doh_response(raw).await {
                Err(ClientError::Protocol("doh: response exceeds maximum size")) => {}
                other => panic!("expected oversized-chunk rejection, got {other:?}"),
            }
        }
    }

    /// The reuse-deadline rule (review M2): a conn whose proven RTT is
    /// at or beyond its own capped budget can never win the attempt —
    /// `None` sends the query straight to the fresh dial so the fresh
    /// side keeps its `≥timeout/2` floor.
    #[cfg(feature = "encrypted")]
    #[test]
    fn tls_reuse_budget_skips_attempts_that_cannot_fit() {
        let t = Duration::from_secs(5);
        // Fast conn: the RTT-scaled term loses to the 250 ms floor.
        assert_eq!(
            tls_reuse_budget(t, Duration::ZERO),
            Some(REUSED_TLS_MIN_BUDGET)
        );
        // Proven RTT inside `t/2`: the `4×` scale loses to the `t/2` cap.
        assert_eq!(tls_reuse_budget(t, Duration::from_secs(2)), Some(t / 2));
        // RTT at or beyond `t/2`: the attempt can never make its own
        // deadline — skip it so the fresh path keeps the full timeout.
        assert_eq!(tls_reuse_budget(t, t / 2), None);
        assert_eq!(tls_reuse_budget(t, Duration::from_secs(3)), None);
        // Tiny timeout, fast conn: capped at `t/2`, not the 250 ms floor.
        assert_eq!(
            tls_reuse_budget(Duration::from_millis(400), Duration::from_millis(10)),
            Some(Duration::from_millis(200))
        );
        // `est_rtt == budget` is still a certain miss → skip.
        assert_eq!(
            tls_reuse_budget(Duration::from_millis(500), Duration::from_millis(250)),
            None
        );
    }

    // NOTE (review B3): the hermetic-silent-loopback version of this test
    // lives in its own PR (#476, `udp_client_times_out_when_no_response`).
    // This branch deliberately keeps main's original hunk untouched so the
    // two PRs do not both modify the same hunk; whichever lands second
    // rebases cleanly.
    #[tokio::test]
    async fn udp_client_times_out_when_no_response() {
        // A silent loopback peer makes the timeout path deterministic
        // regardless of the host network. Using a "guaranteed unroutable"
        // address like 192.0.2.1 is non-hermetic: many ISPs/routers hijack
        // outbound UDP/53 and answer with a spoofed source (Ok/NXDOMAIN) or
        // return ICMP unreachable (an Io error), so the client never reaches
        // Timeout.
        //
        // The sink is never read and never writes a reply. It only has to stay
        // bound for the duration of the query: a closed port would yield
        // ECONNREFUSED on the client's connected socket instead of a timeout.
        // The client sends a single datagram, so the kernel recv buffer never
        // fills and no drain task is needed. Binding for the whole test scope
        // covers that; the sink needs no explicit drop at the end — the query
        // has already completed by then (review low item).
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sink.local_addr().unwrap();
        let client = DnsClient::udp(addr).with_timeout(Duration::from_millis(200));
        let r = client.query("example.test", RecordType::A).await;
        assert!(matches!(r, Err(ClientError::Timeout(_))));
    }

    #[tokio::test]
    async fn rcode_client_returns_noerror_empty_without_network() {
        let client = DnsClient::rcode(ResponseCode::NoError);
        let resp = client.query("example.test", RecordType::A).await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
        assert_eq!(resp.queries.len(), 1);
    }

    #[test]
    fn response_validation_rejects_mismatched_metadata_and_question() {
        let expected = expected("victim.example", RecordType::A, 0x1234);
        let mut response = Message::new(0x1234, MessageType::Response, OpCode::Query);
        response.add_query(expected.query.clone());
        assert!(validate_response(&response, &expected).is_ok());

        response.metadata.id = 0x4321;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response ID mismatch"))
        ));
        response.metadata.id = expected.id;

        response.metadata.message_type = MessageType::Query;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("received DNS query as response"))
        ));
        response.metadata.message_type = MessageType::Response;

        response.metadata.op_code = OpCode::Status;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response opcode mismatch"))
        ));
        response.metadata.op_code = OpCode::Query;

        response.queries[0].name = "other.example".parse().unwrap();
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response question name mismatch"))
        ));
        response.queries[0].name = expected.query.name.clone();

        response.queries[0].query_type = RecordType::AAAA;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response question type mismatch"))
        ));
        response.queries[0].query_type = expected.query.query_type;

        response.queries[0].query_class = DNSClass::CH;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response question class mismatch"))
        ));
    }

    #[test]
    fn address_answers_are_limited_to_the_valid_cname_chain() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        // Deliberately put the terminal address and second CNAME before the
        // first link to prove answer ordering is irrelevant.
        message.add_answer(a_record("target.example", 300, [192, 0, 2, 10]));
        message.add_answer(cname_record("alias.example", 120, "target.example"));
        message.add_answer(a_record("unrelated.example", 1, [6, 6, 6, 6]));
        message.add_answer(cname_record("victim.example", 60, "alias.example"));

        let (addrs, ttl) = relevant_ip_answers(&message);
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        assert_eq!(ttl, Some(60));
    }

    #[test]
    fn unrelated_address_answer_is_not_returned() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        message.add_answer(a_record("unrelated.example", 30, [6, 6, 6, 6]));

        assert_eq!(relevant_ip_answers(&message), (Vec::new(), None));
    }

    #[test]
    fn cname_loop_is_rejected() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        message.add_answer(cname_record("victim.example", 60, "alias.example"));
        message.add_answer(cname_record("alias.example", 30, "victim.example"));
        message.add_answer(a_record("alias.example", 300, [192, 0, 2, 10]));

        assert_eq!(relevant_ip_answers(&message), (Vec::new(), None));
    }

    #[test]
    fn conflicting_cname_targets_are_rejected() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        message.add_answer(cname_record("victim.example", 60, "first.example"));
        message.add_answer(cname_record("victim.example", 30, "second.example"));
        message.add_answer(a_record("first.example", 300, [192, 0, 2, 10]));
        message.add_answer(a_record("second.example", 300, [192, 0, 2, 11]));

        assert_eq!(relevant_ip_answers(&message), (Vec::new(), None));
    }

    /// A factory that overrides only `bind_udp` with a single-family IPv4
    /// socket must get an explicit error — not a late `connect()`
    /// `EAFNOSUPPORT` — when an IPv6 peer asks for a socket it can never
    /// reach.
    #[tokio::test]
    async fn bind_udp_for_peer_default_rejects_v4_socket_for_v6_peer() {
        struct V4Only;
        impl SocketFactory for V4Only {
            fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>> {
                Box::pin(async { UdpSocket::bind("0.0.0.0:0").await })
            }
            fn connect_tcp(&self, _addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
                unreachable!("udp-only test factory")
            }
        }
        let err = V4Only
            .bind_udp_for_peer("2001:db8::53".parse().unwrap())
            .await
            .expect_err("an IPv4-bound socket cannot reach an IPv6 peer");
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
        // The same default keeps delegating for a peer the socket can reach.
        let socket = V4Only
            .bind_udp_for_peer("192.0.2.53".parse().unwrap())
            .await
            .expect("IPv4 peer keeps the delegated bind_udp socket");
        assert!(socket.local_addr().unwrap().is_ipv4());
    }

    /// The mirror-image pairing is just as unreachable: an IPv6-bound
    /// socket cannot `connect()` a plain IPv4 `sockaddr_in`, so the
    /// default refuses it too. Skipped when the host has no IPv6.
    #[tokio::test]
    async fn bind_udp_for_peer_default_rejects_v6_socket_for_v4_peer() {
        if UdpSocket::bind("[::1]:0").await.is_err() {
            eprintln!("no IPv6 loopback; skipping v6-socket reject test");
            return;
        }
        struct V6Only;
        impl SocketFactory for V6Only {
            fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>> {
                Box::pin(async { UdpSocket::bind("[::]:0").await })
            }
            fn connect_tcp(&self, _addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
                unreachable!("udp-only test factory")
            }
        }
        let err = V6Only
            .bind_udp_for_peer("192.0.2.53".parse().unwrap())
            .await
            .expect_err("an IPv6-bound socket cannot connect() a plain IPv4 peer");
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
        // Same-family peers keep the delegated bind_udp socket.
        let socket = V6Only
            .bind_udp_for_peer("2001:db8::53".parse().unwrap())
            .await
            .expect("IPv6 peer keeps the delegated bind_udp socket");
        assert!(socket.local_addr().unwrap().is_ipv6());
    }

    /// Probe first so a kernel with IPv6 disabled (e.g. `ipv6.disable=1`
    /// sandboxes) skips instead of failing on `EADDRNOTAVAIL`; the
    /// `unwrap` below still fails on a real `bind_udp_for_peer` regression.
    #[tokio::test]
    async fn default_udp_socket_matches_native_ipv6_nameserver_family() {
        if UdpSocket::bind("[::1]:0").await.is_err() {
            eprintln!("no IPv6 loopback; skipping v6 nameserver family test");
            return;
        }
        let socket = DefaultSocketFactory
            .bind_udp_for_peer("2001:db8::53".parse().unwrap())
            .await
            .unwrap();
        assert!(socket.local_addr().unwrap().is_ipv6());
    }

    #[tokio::test]
    async fn udp_accepts_ipv4_mapped_nameserver() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let addr = SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(), port);
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();
            let reply = response_for(&request, request.metadata.id);
            server
                .send_to(&reply.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });
        let response = DnsClient::udp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("example.test", RecordType::AAAA)
            .await
            .unwrap();
        assert_eq!(response.queries[0].query_type, RecordType::AAAA);
        // Await the server task so a panic on the passing path is
        // reported instead of dropped with the JoinHandle; a panic
        // before the reply already fails the test via the client
        // timeout above.
        server_task.await.unwrap();
    }

    /// A native IPv6 loopback nameserver (`[::1]:53`) takes the same
    /// loopback branch as the v4-mapped case above and must be dialed
    /// from an `[::1]`-bound socket. Skipped when the host has no IPv6
    /// loopback (minimal CI sandboxes).
    #[tokio::test]
    async fn udp_accepts_native_ipv6_loopback_nameserver() {
        let Ok(server) = UdpSocket::bind("[::1]:0").await else {
            eprintln!("no IPv6 loopback; skipping v6 loopback exchange test");
            return;
        };
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();
            let reply = response_for(&request, request.metadata.id);
            server
                .send_to(&reply.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });
        let response = DnsClient::udp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("example.test", RecordType::AAAA)
            .await
            .unwrap();
        assert_eq!(response.queries[0].query_type, RecordType::AAAA);
        // Same reason as the v4-mapped test above: report a server-task
        // panic instead of dropping it with the JoinHandle.
        server_task.await.unwrap();
    }

    /// A v4-mapped `tcp://` nameserver is canonicalised to plain IPv4
    /// before `connect_tcp` — the TCP counterpart of
    /// `udp_accepts_ipv4_mapped_nameserver`. Without it the mapped form
    /// fails connect() where a fresh v6 socket defaults to v6-only; on
    /// dual-stack Linux/macOS the kernel maps the connect, so the test
    /// is a real guard only on v6-only platforms (it passed elsewhere
    /// even before the fix).
    #[tokio::test]
    async fn tcp_accepts_ipv4_mapped_nameserver() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(), port);
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_lp(&mut stream).await.unwrap();
            let request = Message::from_bytes(&request).unwrap();
            let reply = response_for(&request, request.metadata.id);
            write_lp(&mut stream, &reply.to_bytes().unwrap())
                .await
                .unwrap();
        });
        let response = DnsClient::tcp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("example.test", RecordType::A)
            .await
            .unwrap();
        assert_eq!(response.queries[0].query_type, RecordType::A);
        // Same as the `udp_accepts_*` siblings above: report a
        // server-task panic instead of dropping it with the JoinHandle.
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_ignores_wrong_id_before_valid_response() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();

            let wrong = response_for(&request, request.metadata.id.wrapping_add(1));
            server
                .send_to(&wrong.to_bytes().unwrap(), peer)
                .await
                .unwrap();
            let valid = response_for(&request, request.metadata.id);
            server
                .send_to(&valid.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });

        let response = DnsClient::udp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("victim.example", RecordType::A)
            .await
            .unwrap();
        assert_eq!(response.queries[0].query_type, RecordType::A);
    }

    #[tokio::test]
    async fn wrong_id_truncated_udp_response_does_not_trigger_tcp_fallback() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();

            let mut wrong = response_for(&request, request.metadata.id.wrapping_add(1));
            wrong.metadata.truncation = true;
            server
                .send_to(&wrong.to_bytes().unwrap(), peer)
                .await
                .unwrap();
            let valid = response_for(&request, request.metadata.id);
            server
                .send_to(&valid.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });

        DnsClient::udp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("victim.example", RecordType::A)
            .await
            .expect("the valid UDP response must win without a TCP connection");
    }

    /// Persistent `tcp://` upstream counting accepted connections. A query
    /// for `held.example` is answered only after `release` is notified, and
    /// `held_tx` reports that the server is holding it.
    async fn spawn_gated_tcp_upstream(
        accepted: Arc<AtomicUsize>,
        held_tx: tokio::sync::mpsc::UnboundedSender<()>,
        release: Arc<tokio::sync::Notify>,
    ) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                let held_tx = held_tx.clone();
                let release = Arc::clone(&release);
                tokio::spawn(async move {
                    while let Ok(request) = read_lp(&mut stream).await {
                        let request = Message::from_bytes(&request).unwrap();
                        let held = request.queries.first().is_some_and(|q| {
                            q.name().to_ascii().trim_end_matches('.') == "held.example"
                        });
                        if held {
                            let notified = release.notified();
                            held_tx.send(()).unwrap();
                            notified.await;
                        }
                        let response = response_for(&request, request.metadata.id);
                        if write_lp(&mut stream, &response.to_bytes().unwrap())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    /// Issue #695: `reset_connections` closes the idle pooled stream so the
    /// next query dials fresh, and a stream an in-flight query holds across
    /// the reset completes that query but is never pooled afterwards.
    #[tokio::test]
    async fn reset_connections_redials_and_never_pools_an_in_flight_stream() {
        let accepted = Arc::new(AtomicUsize::new(0));
        let (held_tx, mut held_rx) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let addr =
            spawn_gated_tcp_upstream(Arc::clone(&accepted), held_tx, Arc::clone(&release)).await;
        let client = Arc::new(DnsClient::tcp(addr));

        client.query("warm.example", RecordType::A).await.unwrap();
        client.query("reuse.example", RecordType::A).await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "the pool is reused");

        assert_eq!(client.reset_connections(), 1, "the idle stream closes now");
        assert_eq!(client.reset_connections(), 0, "nothing left to close");
        client
            .query("after-reset.example", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "a reset forces a redial"
        );

        // Empty the pool so the held query rides a fresh connection (the
        // pooled attempt's short deadline would otherwise race the hold).
        client.reset_connections();
        let in_flight = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.query("held.example", RecordType::A).await }
        });
        held_rx.recv().await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
        assert_eq!(
            client.reset_connections(),
            0,
            "the in-flight stream is checked out, not idle"
        );
        release.notify_one();
        in_flight
            .await
            .unwrap()
            .expect("an in-flight query completes across a reset");

        client
            .query("after-in-flight.example", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            4,
            "the stream that was in flight across the reset must not be pooled"
        );
    }

    #[tokio::test]
    async fn tcp_rejects_mismatched_framed_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_lp(&mut stream).await.unwrap();
            let request = Message::from_bytes(&request).unwrap();
            let wrong = response_for(&request, request.metadata.id.wrapping_add(1));
            write_lp(&mut stream, &wrong.to_bytes().unwrap())
                .await
                .unwrap();
        });

        let result = DnsClient::tcp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("victim.example", RecordType::A)
            .await;
        assert!(matches!(
            result,
            Err(ClientError::Protocol("response ID mismatch"))
        ));
    }

    #[tokio::test]
    async fn lookup_ip_shares_one_timeout_across_a_and_aaaa() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = Arc::clone(&requests);
        tokio::spawn(async move {
            // A and AAAA ride separate connections (no pooling here), so the
            // server accepts twice. The point under test is that the *client*
            // covers both queries — issued concurrently, each on its own
            // socket — with one overall timeout, not that they share a
            // socket.
            for expected in [RecordType::A, RecordType::AAAA] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_lp(&mut stream).await.unwrap();
                let request = Message::from_bytes(&request).unwrap();
                assert_eq!(request.queries[0].query_type, expected);
                server_requests.fetch_add(1, Ordering::SeqCst);
                if expected == RecordType::A {
                    // Empty NOERROR (no address records) after 250 ms, so the
                    // prefer-IPv4 path falls back to AAAA.
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let response = response_for(&request, request.metadata.id);
                    write_lp(&mut stream, &response.to_bytes().unwrap())
                        .await
                        .unwrap();
                } else {
                    // AAAA never answers within the client budget.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        });

        let client = DnsClient::tcp(addr).with_timeout(Duration::from_millis(400));
        let result = tokio::time::timeout(
            Duration::from_millis(550),
            client.lookup_ip_with_ipv6("dual.example", true),
        )
        .await
        .expect("A and AAAA must share the client's overall timeout");
        assert!(matches!(result, Err(ClientError::Timeout(_))));
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[cfg(feature = "encrypted")]
    #[test]
    fn encrypted_upstream_labels_include_scheme() {
        let dot = DnsClient::dot("8.8.8.8:853".parse().unwrap(), "dns.google");
        assert_eq!(dot.upstream_label(), "tls://dns.google");

        let doh = DnsClient::doh(
            "1.1.1.1:443".parse().unwrap(),
            "cloudflare-dns.com",
            "/dns-query",
        );
        assert_eq!(doh.upstream_label(), "https://cloudflare-dns.com");
    }

    #[test]
    fn explicit_upstream_label_overrides_default_label() {
        let client = DnsClient::udp("8.8.8.8:53".parse().unwrap())
            .with_upstream_label("tls://dns.google:853");
        assert_eq!(client.upstream_label(), "tls://dns.google:853");
    }

    #[tokio::test]
    async fn tcp_short_frames_never_panic_or_return_to_pool() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let server_connections = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let index = server_connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    while read_lp(&mut stream).await.is_ok() {
                        // First connection answers with a zero-length frame,
                        // the second with a one-byte frame — both are
                        // malformed and must surface as `ClientError` instead
                        // of panicking or being returned to the pool.
                        let frame: &[u8] = if index == 0 { &[0, 0] } else { &[0, 1, 0] };
                        if stream.write_all(frame).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let client = DnsClient::tcp(addr).with_timeout(Duration::from_secs(1));
        for _ in 0..2 {
            assert!(client.query("victim.example", RecordType::A).await.is_err());
        }
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelled_tcp_exchange_discards_partial_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let connection = server_accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    if connection == 0 {
                        let request = read_lp(&mut stream).await.unwrap();
                        let request = Message::from_bytes(&request).unwrap();
                        let response = response_for(&request, request.metadata.id);
                        write_lp(&mut stream, &response.to_bytes().unwrap())
                            .await
                            .unwrap();
                        read_lp(&mut stream).await.unwrap();
                        stream.write_all(&[0, 64, 0]).await.unwrap();
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return;
                    }
                    let request = read_lp(&mut stream).await.unwrap();
                    let request = Message::from_bytes(&request).unwrap();
                    let response = response_for(&request, request.metadata.id);
                    write_lp(&mut stream, &response.to_bytes().unwrap())
                        .await
                        .unwrap();
                });
            }
        });

        let client = DnsClient::tcp(addr).with_timeout(Duration::from_millis(200));
        client
            .query("warm.example", RecordType::A)
            .await
            .expect("the first query primes the pool");
        // The reused stream stalls on a partial length-prefixed frame (the
        // server announces 64 bytes but sends 1, then sleeps). With a short
        // read deadline on the pooled attempt, the client
        // abandons the stale stream well before the 200 ms query budget is
        // spent and retries on a fresh connection — so this query succeeds
        // instead of burning the full timeout. Cancellation safety (the
        // partial stream is discarded, never returned to the pool) is what
        // makes the retry safe.
        client
            .query("partial.example", RecordType::A)
            .await
            .expect("stale pooled stream retried within budget");
        client
            .query("after-cancel.example", RecordType::A)
            .await
            .expect("the discarded partial stream must not be reused");
        assert!(accepted.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn tcp_pool_reuses_connections_without_capping_concurrency() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let server_accepted = Arc::clone(&accepted);
        let server_active = Arc::clone(&active);
        let server_released = Arc::clone(&released);
        let server_gate = Arc::clone(&gate);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                server_accepted.fetch_add(1, Ordering::SeqCst);
                let active = Arc::clone(&server_active);
                let released = Arc::clone(&server_released);
                let gate = Arc::clone(&server_gate);
                tokio::spawn(async move {
                    while let Ok(request) = read_lp(&mut stream).await {
                        let request = Message::from_bytes(&request).unwrap();
                        active.fetch_add(1, Ordering::SeqCst);
                        if !released.load(Ordering::SeqCst) {
                            gate.acquire().await.unwrap().forget();
                        }
                        active.fetch_sub(1, Ordering::SeqCst);
                        let response = response_for(&request, request.metadata.id);
                        if write_lp(&mut stream, &response.to_bytes().unwrap())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });

        let client = Arc::new(DnsClient::tcp(addr).with_timeout(Duration::from_secs(2)));
        // Deliberately more concurrent queries than TCP_POOL_CAPACITY:
        // a `tcp://` nameserver can be the primary resolver, and the
        // exchange path must never queue a burst behind the pool size.
        let burst = 2 * TCP_POOL_CAPACITY;
        let queries: Vec<_> = (0..burst)
            .map(|index| {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    client
                        .query(&format!("pool-{index}.example"), RecordType::A)
                        .await
                })
            })
            .collect();

        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) < burst {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("every concurrent TCP exchange should dial immediately");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            burst,
            "concurrency must not be capped at the pool size"
        );

        released.store(true, Ordering::SeqCst);
        gate.add_permits(burst);
        for query in queries {
            query.await.unwrap().unwrap();
        }
        assert!(
            client.tcp_pool.idle.lock().await.len() <= TCP_POOL_CAPACITY,
            "the idle pool must stay bounded at TCP_POOL_CAPACITY"
        );

        // Every burst connection was returned; the surplus was closed
        // instead of pooled, and the next query must reuse a pooled
        // stream rather than dial again.
        let accepted_before = accepted.load(Ordering::SeqCst);
        client
            .query("pool-reuse.example", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            accepted_before,
            "a query right after the burst should reuse a pooled connection"
        );
    }

    /// Benchmark server for [`tcp_pool_burst_connection_budget`]: answers
    /// every query immediately and counts accepted connections.
    async fn spawn_bench_dns_server(accepted: Arc<AtomicUsize>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                server_accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    while let Ok(request) = read_lp(&mut stream).await {
                        let request = Message::from_bytes(&request).unwrap();
                        let response = response_for(&request, request.metadata.id);
                        if write_lp(&mut stream, &response.to_bytes().unwrap())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    /// Review N1 benchmark: quantify the connection budget of the
    /// `TCP_POOL_CAPACITY = 4` idle pool when a `tcp://` nameserver is the
    /// primary resolver, under both arrival patterns a page load produces.
    /// Run with:
    ///
    /// ```text
    /// cargo test -p meow-dns --lib tcp_pool_burst -- --ignored --nocapture
    /// ```
    ///
    /// Informational by design (nothing is asserted about the measured
    /// numbers — they are environment-dependent): the behavioral
    /// guarantees (bursts never queue behind the pool, the pool stays
    /// bounded, a post-burst query reuses) are pinned by the reuse test
    /// above. Each phase uses a fresh client, so every phase starts with
    /// an empty pool.
    #[tokio::test]
    #[ignore]
    async fn tcp_pool_burst_connection_budget() {
        let accepted = Arc::new(AtomicUsize::new(0));
        let addr = spawn_bench_dns_server(Arc::clone(&accepted)).await;

        async fn run_burst(
            addr: std::net::SocketAddr,
            queries: usize,
            spawn_gap: Option<Duration>,
        ) -> usize {
            // Fresh client per phase → the phase starts with an empty pool.
            let client = Arc::new(DnsClient::tcp(addr).with_timeout(Duration::from_secs(10)));
            let mut handles = Vec::with_capacity(queries);
            for index in 0..queries {
                if let Some(gap) = spawn_gap {
                    tokio::time::sleep(gap).await;
                }
                let client = Arc::clone(&client);
                handles.push(tokio::spawn(async move {
                    client
                        .query(&format!("burst-{index}.example"), RecordType::A)
                        .await
                        .map(|_| ())
                }));
            }
            for handle in handles {
                handle.await.unwrap().unwrap();
            }
            let idle = client.tcp_pool.idle.lock().await.len();
            assert!(
                idle <= TCP_POOL_CAPACITY,
                "idle pool must stay bounded (saw {idle})"
            );
            idle
        }

        // Fully concurrent bursts — the pattern that pays one connect (and,
        // on Android, one protect(fd) call) per query above the capacity.
        for burst in [4usize, 16, 32, 64] {
            let start = Instant::now();
            let before = accepted.load(Ordering::SeqCst);
            run_burst(addr, burst, None).await;
            let connects = accepted.load(Ordering::SeqCst) - before;
            let reuse = 100.0 * (1.0 - connects as f64 / burst as f64);
            println!(
                "concurrent burst={burst:3}: {connects:3} connects (reuse {reuse:.0}%), \
                 {:.1} ms",
                start.elapsed().as_secs_f64() * 1e3
            );
        }

        // Staggered arrival — the pattern where a query lands while an idle
        // pooled stream exists, so the pool serves it. This is the shape
        // pooling exists for (review N1).
        for (total, gap_ms) in [(64usize, 5u64), (64, 20)] {
            let start = Instant::now();
            let before = accepted.load(Ordering::SeqCst);
            run_burst(addr, total, Some(Duration::from_millis(gap_ms))).await;
            let connects = accepted.load(Ordering::SeqCst) - before;
            let reuse = 100.0 * (1.0 - connects as f64 / total as f64);
            println!(
                "staggered  {total:3} @ {gap_ms:2} ms: {connects:3} connects \
                 (reuse {reuse:.0}%), {:.1} ms",
                start.elapsed().as_secs_f64() * 1e3
            );
        }
    }
    #[test]
    fn take_fresh_reaps_expired_and_returns_the_freshest() {
        let timeout = Duration::from_secs(30);
        let now = Instant::now();
        // Oldest first, freshest last — the order `push` produces.
        let mut idle = vec![
            (1u32, now - Duration::from_secs(90)),
            (2u32, now - Duration::from_secs(45)),
            (3u32, now - Duration::from_secs(5)),
        ];
        let mut reaped = Vec::new();
        assert_eq!(
            take_fresh(&mut idle, now, timeout, &mut reaped),
            Some(3),
            "the most recently returned stream must be reused first"
        );
        assert_eq!(
            reaped,
            vec![1, 2],
            "both streams idle past the timeout must have been reaped, not left pooled"
        );
        assert!(idle.is_empty());
    }

    #[test]
    fn take_fresh_returns_none_when_every_stream_is_stale() {
        let timeout = Duration::from_secs(30);
        let now = Instant::now();
        let mut idle = vec![
            (1u32, now - Duration::from_secs(31)),
            (2u32, now - Duration::from_secs(60)),
        ];
        let mut reaped = Vec::new();
        assert_eq!(
            take_fresh(&mut idle, now, timeout, &mut reaped),
            None,
            "an all-stale pool must force a fresh connect"
        );
        assert_eq!(reaped, vec![1, 2]);
        assert!(idle.is_empty());
    }

    #[test]
    fn take_fresh_keeps_streams_inside_the_window() {
        let timeout = Duration::from_secs(30);
        let now = Instant::now();
        let mut idle = vec![
            (1u32, now - Duration::from_secs(29)),
            (2u32, now - Duration::from_secs(1)),
        ];
        let mut reaped = Vec::new();
        assert_eq!(take_fresh(&mut idle, now, timeout, &mut reaped), Some(2));
        assert!(reaped.is_empty());
        assert_eq!(
            idle.len(),
            1,
            "a stream still inside the idle window must stay pooled"
        );
    }

    /// A stream idle past the timeout must be closed instead of reused: the
    /// second query dials a fresh connection rather than spending its read
    /// deadline discovering that a silently-dropped stream will never answer.
    #[tokio::test]
    async fn tcp_pool_discards_streams_idle_past_the_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));

        let server_accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                server_accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    while let Ok(request) = read_lp(&mut stream).await {
                        let request = Message::from_bytes(&request).unwrap();
                        let response = response_for(&request, request.metadata.id);
                        if write_lp(&mut stream, &response.to_bytes().unwrap())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });

        let idle_timeout = Duration::from_millis(20);
        let client = DnsClient::tcp(addr)
            .with_timeout(Duration::from_secs(2))
            .with_tcp_idle_timeout(idle_timeout);

        client.query("first.example", RecordType::A).await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        // Still inside the window: the pooled stream is reused.
        client.query("second.example", RecordType::A).await.unwrap();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "a stream inside the idle window must be reused"
        );

        // Past the window: the pooled stream is closed and a new one dialled.
        tokio::time::sleep(idle_timeout * 5).await;
        client.query("third.example", RecordType::A).await.unwrap();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "a stream idle past the timeout must be closed, not reused"
        );
    }

    /// RFC 2308: the negative cache TTL of an NXDOMAIN/NODATA response is
    /// `min(SOA.TTL, SOA.MINIMUM)` from the authority section. Verifies the
    /// helper used by the NXDOMAIN-cache path picks the smaller of the record
    /// TTL and the SOA MINIMUM field, and falls back to 0 when no SOA is
    /// present (the resolver clamp floor still gives it a short life).
    fn soa_record(name: &str, ttl: u32, minimum: u32) -> Record {
        use hickory_proto::rr::rdata::SOA;
        Record::from_rdata(
            name.parse().unwrap(),
            ttl,
            RData::SOA(SOA::new(
                "ns.example".parse().unwrap(),
                "hostmaster.example".parse().unwrap(),
                1,
                3600,
                900,
                1209600,
                minimum,
            )),
        )
    }

    #[test]
    fn negative_ttl_uses_min_of_soa_ttl_and_minimum() {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        // SOA TTL 600, MINIMUM 300 → negative TTL 300.
        msg.add_authority(soa_record("example.", 600, 300));
        assert_eq!(negative_ttl(&msg), Duration::from_secs(300));
    }

    #[test]
    fn negative_ttl_picks_the_soa_record_ttl_when_smaller_than_minimum() {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        // SOA TTL 120, MINIMUM 3600 → negative TTL 120.
        msg.add_authority(soa_record("example.", 120, 3600));
        assert_eq!(negative_ttl(&msg), Duration::from_secs(120));
    }

    #[test]
    fn negative_ttl_is_zero_when_no_soa_in_authority() {
        let msg = Message::new(1, MessageType::Response, OpCode::Query);
        assert_eq!(negative_ttl(&msg), Duration::ZERO);
    }

    /// `classify_family_message` is the BOTH-path classifier. Verify its four
    /// branches: NoError+addresses → Answer, NoError+empty → NoData(SOA TTL),
    /// NXDOMAIN → NxDomain(SOA TTL), other rcode → Failed.
    #[test]
    fn classify_family_message_branches() {
        use hickory_proto::op::ResponseCode;

        // NoError with an A record → Answer.
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_query(Query::query("a.example".parse().unwrap(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            "a.example".parse().unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let ans = classify_family_message(&msg);
        assert!(matches!(
            ans,
            FamilyAnswer::Answer { ips, ttl } if ips == vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))] && ttl == Duration::from_secs(60)
        ));

        // NoError with zero address records → NoData(SOA TTL).
        let mut msg = Message::new(2, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_query(Query::query(
            "empty.example".parse().unwrap(),
            RecordType::A,
        ));
        msg.add_authority(soa_record("example.", 600, 300));
        let ans = classify_family_message(&msg);
        assert!(matches!(ans, FamilyAnswer::NoData(t) if t == Duration::from_secs(300)));

        // NXDOMAIN → NxDomain(SOA TTL).
        let mut msg = Message::new(3, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        msg.add_query(Query::query("gone.example".parse().unwrap(), RecordType::A));
        msg.add_authority(soa_record("example.", 600, 300));
        let ans = classify_family_message(&msg);
        assert!(matches!(ans, FamilyAnswer::NxDomain(t) if t == Duration::from_secs(300)));

        // SERVFAIL → Failed.
        let mut msg = Message::new(4, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::ServFail;
        msg.add_query(Query::query("fail.example".parse().unwrap(), RecordType::A));
        let ans = classify_family_message(&msg);
        assert!(matches!(ans, FamilyAnswer::Failed));
    }

    /// `Proxy` that records the `Metadata` of every `dial_tcp` and refuses
    /// the connection — pins the `internal` marker on DNS-via-proxy
    /// exchanges (#555): a `lazy` group serving `#PROXY` upstreams must
    /// not count resolver housekeeping as use.
    struct CapturingMetaProxy {
        seen: std::sync::Mutex<Vec<meow_common::Metadata>>,
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for CapturingMetaProxy {
        fn name(&self) -> &str {
            "capture"
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
            m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            self.seen.lock().unwrap().push(m.clone());
            Err(meow_common::MeowError::NotSupported(
                "capture mock refuses connections".into(),
            ))
        }
        async fn dial_udp(
            &self,
            _m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            unimplemented!("capture mock has no UDP")
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for CapturingMetaProxy {
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

    #[tokio::test]
    async fn proxy_tcp_exchange_marks_metadata_internal() {
        let proxy = std::sync::Arc::new(CapturingMetaProxy {
            seen: std::sync::Mutex::new(Vec::new()),
            health: meow_common::ProxyHealth::new(),
        });
        let dyn_proxy: DnsProxy = std::sync::Arc::<CapturingMetaProxy>::clone(&proxy);
        let client = DnsClient::tcp("8.8.8.8:53".parse().unwrap()).with_proxy(dyn_proxy);
        let _ = client
            .exchange(b"\x00", &expected("probe.test", RecordType::A, 1))
            .await;
        let seen = proxy.seen.lock().unwrap();
        let meta = seen.first().expect("the exchange must reach dial_tcp");
        assert!(
            meta.internal,
            "DNS-via-proxy exchanges are housekeeping — a lazy group \
             must not count them as use"
        );
        assert_eq!(meta.conn_type, meow_common::ConnType::Inner);
    }

    /// `EMFILE` on unix, `WSAEMFILE` on Windows — both are in
    /// `is_local_resource_error`'s set. Literal constants keep a libc
    /// dependency out of the test tree.
    #[cfg(unix)]
    const EMFILE: i32 = 24;
    #[cfg(windows)]
    const EMFILE: i32 = 10024;

    /// `Proxy` whose `dial_tcp` fails with a fixed errno-bearing io
    /// error — drives the dns-via-proxy exchange to a local-resource
    /// failure without touching real sockets (#682).
    struct ErrnoProxy {
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for ErrnoProxy {
        fn name(&self) -> &str {
            "errno"
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
            _m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            Err(meow_common::MeowError::Io(io::Error::from_raw_os_error(
                EMFILE,
            )))
        }
        async fn dial_udp(
            &self,
            _m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            unimplemented!("errno mock has no UDP")
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for ErrnoProxy {
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

    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn encrypted_dns_uses_named_proxy_and_never_falls_back_after_dial_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let proxy = Arc::new(CapturingMetaProxy {
            seen: Default::default(),
            health: meow_common::ProxyHealth::new(),
        });
        for client in [
            DnsClient::dot(addr, "dns.example"),
            DnsClient::doh(addr, "dns.example", "/dns-query"),
        ] {
            assert!(client
                .with_proxy(Arc::clone(&proxy) as DnsProxy)
                .query("test.example", RecordType::A)
                .await
                .is_err());
        }
        {
            let seen = proxy.seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert!(seen
                .iter()
                .all(|m| m.internal && m.dst_ip == Some(addr.ip()) && m.dst_port == addr.port()));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let proxy: DnsProxy = Arc::new(ErrnoProxy {
            health: meow_common::ProxyHealth::new(),
        });
        let err = DnsClient::dot(addr, "dns.example")
            .with_proxy(proxy)
            .dial_tls_inner()
            .await
            .err()
            .unwrap();
        assert!(err.is_errno_backed());
    }

    fn emfile_client() -> DnsClient {
        DnsClient::udp("203.0.113.53:53".parse().unwrap()).with_proxy(std::sync::Arc::new(
            ErrnoProxy {
                health: meow_common::ProxyHealth::new(),
            },
        ))
    }

    /// #682: a `dns-via-proxy` dial failing with an errno-bearing io error
    /// must keep `raw_os_error` — `io::Error::other` used to erase it.
    #[tokio::test]
    async fn dns_via_proxy_dial_failure_keeps_errno() {
        let proxy: DnsProxy = std::sync::Arc::new(ErrnoProxy {
            health: meow_common::ProxyHealth::new(),
        });
        let client = DnsClient::tcp("8.8.8.8:53".parse().unwrap()).with_proxy(proxy);
        let err = client
            .proxy_dial(client.proxy.as_ref().unwrap())
            .await
            .err()
            .expect("the EMFILE mock must fail the dial");
        let ClientError::Io(e) = err else {
            panic!("expected Io, got {err:?}");
        };
        assert_eq!(e.raw_os_error(), Some(EMFILE));
    }

    /// #682: `lookup_set` must surface the errno for both the single-family
    /// path and the dual-stack both-failed path (which used to return the
    /// context-less `Protocol("no response")`).
    #[tokio::test]
    async fn lookup_set_propagates_errno_backed_failure() {
        let err = emfile_client()
            .lookup_set("probe.example", QueryFamilies::IPV4, false)
            .await
            .unwrap_err();
        assert!(
            err.is_errno_backed(),
            "single-family failure must carry the errno: {err:?}"
        );

        let err = emfile_client()
            .lookup_set("probe.example", QueryFamilies::BOTH, true)
            .await
            .unwrap_err();
        assert!(
            err.is_errno_backed(),
            "dual-stack all-failed must prefer the errno-bearing arm: {err:?}"
        );
        let ClientError::Io(e) = &err else {
            panic!("expected Io, got {err:?}");
        };
        assert_eq!(e.raw_os_error(), Some(EMFILE));
    }

    /// `to_io` round-trips the errno for single-flight subscribers, and
    /// errno-less errors keep their kind instead of collapsing to `Other`.
    #[test]
    fn client_error_to_io_preserves_errno_and_kind() {
        let io = ClientError::Io(io::Error::from_raw_os_error(EMFILE)).to_io();
        assert_eq!(io.raw_os_error(), Some(EMFILE));

        let kindless =
            ClientError::Io(io::Error::new(io::ErrorKind::ConnectionReset, "rst")).to_io();
        assert_eq!(kindless.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(kindless.raw_os_error(), None);

        let timeout = ClientError::Timeout(Duration::from_secs(5)).to_io();
        assert_eq!(timeout.kind(), io::ErrorKind::TimedOut);

        // prefer_errno: an errno-backed failure outranks a context-only one,
        // in either order.
        let errno = || ClientError::Io(io::Error::from_raw_os_error(EMFILE));
        let plain = || ClientError::Protocol("nope");
        assert!(prefer_errno(Some(plain()), Some(errno()))
            .unwrap()
            .is_errno_backed());
        assert!(prefer_errno(Some(errno()), Some(plain()))
            .unwrap()
            .is_errno_backed());
        assert!(prefer_errno(None, Some(plain())).is_some());
        assert!(prefer_errno(Some(errno()), None).unwrap().is_errno_backed());
    }

    /// #682 dual-stack merge precedence: a positive Answer on one family
    /// always wins over a sibling transport failure; a name-authoritative
    /// NXDOMAIN settles the lookup from either side; but a `NoData`/`Failed`
    /// sibling cannot stand in for a family whose exchange errored — the
    /// errno must surface instead of an unproven "unresolvable".
    #[test]
    fn merge_family_results_precedence() {
        use hickory_proto::op::ResponseCode;

        fn msg(code: ResponseCode) -> Message {
            let mut m = Message::new(9, MessageType::Response, OpCode::Query);
            m.metadata.response_code = code;
            m.add_query(Query::query("example.".parse().unwrap(), RecordType::A));
            m
        }
        fn a_answer() -> Message {
            let mut m = msg(ResponseCode::NoError);
            m.add_answer(a_record("example.", 60, [1, 2, 3, 4]));
            m
        }
        let errno = || Err(ClientError::Io(io::Error::from_raw_os_error(EMFILE)));

        // Sibling NoData cannot stand in for an unexchanged family —
        // the errno must surface, on either side.
        for (v4, v6) in [
            (errno(), Ok(msg(ResponseCode::NoError))),
            (Ok(msg(ResponseCode::NoError)), errno()),
        ] {
            let Err(err) = merge_family_results(v4, v6) else {
                panic!("NoData + transport failure is unproven, not unresolvable")
            };
            assert!(err.is_errno_backed(), "errno must survive: {err:?}");
        }

        // Same for a SERVFAIL-classified sibling.
        let Err(err) = merge_family_results(errno(), Ok(msg(ResponseCode::ServFail))) else {
            panic!("Failed + transport failure is unproven")
        };
        assert!(err.is_errno_backed());

        // NXDOMAIN is name-authoritative from either side — even against a
        // sibling transport error the name cannot resolve.
        for (v4, v6) in [
            (errno(), Ok(msg(ResponseCode::NXDomain))),
            (Ok(msg(ResponseCode::NXDomain)), errno()),
        ] {
            let r = merge_family_results(v4, v6).expect("NXDOMAIN settles the lookup");
            assert!(r.ips.is_empty());
            assert!(
                matches!(r.v4, Some(FamilyAnswer::NxDomain(_))),
                "missing sibling must be synthesized as NxDomain: {:?}",
                r.v4
            );
            assert!(matches!(r.v6, Some(FamilyAnswer::NxDomain(_))));
        }

        // A positive answer still wins over a sibling failure.
        let r = merge_family_results(Ok(a_answer()), errno())
            .expect("a dialable answer beats a sibling error");
        assert_eq!(r.ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);

        // Both families failed → errno arm.
        let Err(err) = merge_family_results(errno(), errno()) else {
            panic!("both-failed must surface the errno")
        };
        assert!(err.is_errno_backed());

        // Genuine negatives on both sides still collapse to Ok.
        let r = merge_family_results(
            Ok(msg(ResponseCode::NoError)),
            Ok(msg(ResponseCode::NXDomain)),
        )
        .unwrap();
        assert!(r.ips.is_empty());
    }
}

#[cfg(all(test, feature = "encrypted"))]
#[path = "doh_stream_tests.rs"]
mod doh_stream_tests;
