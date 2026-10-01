//! Internal DNS client transports — UDP, TCP, DoT, DoH.
//!
//! Sockets are created through a pluggable [`SocketFactory`] so the caller
//! (e.g. an Android VPN service) can intercept fd creation and call
//! `protect()` before the socket is used. This is the reason the project
//! ships its own DNS client instead of relying on `hickory-resolver`.

use crate::cache::QueryFamilies;
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
use meow_transport::{
    tls::{TlsConfig, TlsLayer},
    Transport as _,
};

/// Default per-query timeout (matches the hickory-resolver value previously
/// used in `Resolver::build_*`).
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum number of *idle* pooled `tcp://` streams per [`DnsClient`].
///
/// This bounds only the keep-alive pool: a stream is pushed on return
/// only while the pool is below this size (see [`TcpPool::push`]).
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
    /// `0.0.0.0:0`.
    fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>>;

    /// Open an outbound TCP connection to `addr`.
    fn connect_tcp(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>>;
}

/// Tokio default factory: routes through [`meow_common::bind_udp`] /
/// [`meow_common::connect_tcp`] so the Android `VpnService.protect(fd)`
/// hook (when installed) covers DNS upstream sockets too.
struct DefaultSocketFactory;

impl SocketFactory for DefaultSocketFactory {
    fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(async {
            // Bind to v4 unspecified; this is fine because we always
            // `connect()` the socket before sending, and connect() will
            // re-resolve the local address family.
            meow_common::bind_udp(SocketAddr::from(([0u8; 4], 0))).await
        })
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
    label: Option<Arc<str>>,
    /// Idle direct `tcp://` connections. Streams are checked out for the whole
    /// exchange and returned only after the DNS response is fully validated.
    tcp_pool: TcpPool,
}

struct TcpPool {
    /// Idle streams paired with the instant they were returned to the pool.
    /// Pushed and popped at the end, so the freshest stream is reused first
    /// and the staler ones age out instead of being handed to a query.
    idle: AsyncMutex<Vec<(PooledTcp, Instant)>>,
    idle_timeout: Duration,
    /// This pool's own generation, bumped by [`DnsClient::reset_connections`]
    /// — the per-client counterpart of [`CONNECTION_GENERATION`].
    generation: AtomicU,
}

/// The pool generation a stream was created under: stale once either the
/// process-wide or the pool-local counter moves (issue #695).
#[derive(Clone, Copy, PartialEq, Eq)]
struct PoolGeneration {
    global: Uint,
    local: Uint,
}

/// A pooled `tcp://` stream plus the [`PoolGeneration`] captured before its
/// socket was created.
struct PooledTcp {
    stream: TcpStream,
    generation: PoolGeneration,
}

impl TcpPool {
    fn new() -> Self {
        Self {
            idle: AsyncMutex::new(Vec::with_capacity(TCP_POOL_CAPACITY)),
            idle_timeout: TCP_POOL_IDLE_TIMEOUT,
            generation: AtomicU::new(0),
        }
    }

    fn generation(&self) -> PoolGeneration {
        PoolGeneration {
            global: connection_generation(),
            local: self.generation.load(Ordering::Acquire),
        }
    }

    /// Retire every stream this pool handed out or holds — idle ones close
    /// now, checked-out ones on return. Returns the idle streams closed.
    fn reset(&self) -> usize {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.close_idle()
    }

    /// Return a validated stream to the idle pool, closing it instead when
    /// the pool is already at capacity or [`reset_pooled_connections`]
    /// retired its generation while it was checked out.
    ///
    /// The size bound is enforced *here*, on the push side — it is not an
    /// emergent property of the exchange path — so any future caller
    /// (e.g. a background reaper returning streams) cannot silently grow
    /// the pool beyond [`TCP_POOL_CAPACITY`].
    async fn push(&self, pooled: PooledTcp) {
        let mut idle = self.idle.lock().await;
        if idle.len() < TCP_POOL_CAPACITY && pooled.generation == self.generation() {
            idle.push((pooled, Instant::now()));
        }
        // else: `pooled` drops here, closing the connection.
    }

    /// Pop the freshest reusable stream, closing every idle-expired or
    /// generation-retired one on the way.
    async fn take(&self) -> Option<PooledTcp> {
        let generation = self.generation();
        let mut idle = self.idle.lock().await;
        idle.retain(|(pooled, _)| pooled.generation == generation);
        take_fresh(&mut idle, Instant::now(), self.idle_timeout)
    }

    /// Close every idle stream now, without waiting for the lock: a
    /// contended pool is mid-checkout and [`Self::take`] / [`Self::push`]
    /// drop retired streams on their own. Returns the number closed.
    fn close_idle(&self) -> usize {
        self.idle.try_lock().map_or(0, |mut idle| {
            let closed = idle.len();
            idle.clear();
            closed
        })
    }
}

/// Close every stream idle past `idle_timeout` and hand back the freshest
/// survivor, or `None` when the pool has nothing reusable.
///
/// Split out from the exchange so the reaping rule is testable without a
/// socket or a clock: dropping the expired entries closes those connections.
fn take_fresh<T>(idle: &mut Vec<(T, Instant)>, now: Instant, idle_timeout: Duration) -> Option<T> {
    idle.retain(|(_, returned_at)| now.duration_since(*returned_at) < idle_timeout);
    idle.pop().map(|(stream, _)| stream)
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
    RCode {
        code: ResponseCode,
    },
}

impl DnsClient {
    /// Plain DNS over UDP.
    pub fn udp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Udp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
            tcp_pool: TcpPool::new(),
        }
    }

    /// Plain DNS over TCP (RFC 7766 length-prefixed framing).
    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Tcp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
            tcp_pool: TcpPool::new(),
        }
    }

    /// Synthetic DNS response with a fixed response code and no answers.
    pub fn rcode(code: ResponseCode) -> Self {
        Self {
            transport: Transport::RCode { code },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
            tcp_pool: TcpPool::new(),
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
            label: None,
            tcp_pool: TcpPool::new(),
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
            label: None,
            tcp_pool: TcpPool::new(),
        }
    }

    /// Override the per-query timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Route this client's exchanges through `proxy` (issue #67 phase 2).
    ///
    /// When set:
    /// - TCP / DoT / DoH exchanges use `proxy.dial_tcp` instead of opening
    ///   a direct TCP connection.
    /// - UDP exchanges fall through to TCP-over-proxy, since most proxy
    ///   adapters can't relay arbitrary UDP. The fallback matches the
    ///   semantics in ADR-0012.
    pub fn with_proxy(mut self, proxy: DnsProxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Override the API/UI label used to report this upstream in DNS results.
    pub fn with_upstream_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(Arc::from(label.into()));
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

    /// Drop this client's pooled `tcp://` connections so the next query
    /// dials a fresh socket (issue #695). Idle streams close now unless the
    /// pool is mid-checkout, in which case they close on the next checkout;
    /// a stream an in-flight query holds finishes that query (bounded by the
    /// per-query timeout) and is then closed instead of pooled. Non-blocking.
    /// Returns the idle streams closed now. UDP, DoT and DoH open a socket
    /// per query and pool nothing.
    pub fn reset_connections(&self) -> usize {
        self.tcp_pool.reset()
    }

    /// Human-readable upstream identifier for API/UI surfaces.
    pub fn upstream_label(&self) -> String {
        let mut label = if let Some(label) = &self.label {
            label.to_string()
        } else {
            match &self.transport {
                Transport::Udp { addr } | Transport::Tcp { addr } => socket_label(*addr, 53),
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
                } => {
                    if sni.is_empty() {
                        format!("https://{}", socket_label(*addr, 443))
                    } else if path.as_ref() == "/dns-query" {
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
            }
        };
        if self.proxy.is_some() {
            label.push_str("#PROXY");
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
    /// [`TCP_POOL_CAPACITY`] (see [`TcpPool::push`]); surplus streams are
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
    /// time out first. Pooling is intentionally scoped to plain
    /// `tcp://`; DoT/DoH keep a full TLS handshake per query and are out of
    /// scope.
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
            let attempt = tcp_message_exchange(&mut pooled.stream, wire, expected);
            if let Ok(Ok(response)) = tokio::time::timeout(pooled_budget, attempt).await {
                self.tcp_pool.push(pooled).await;
                return Ok(response);
            }
            // Timeout or error: drop the (possibly desynced/half-closed)
            // stream and reconnect. Do not return a timed-out reused stream
            // to the pool.
        }

        // Captured before the socket exists: a reset racing the connect
        // must retire this stream too (issue #695).
        let generation = self.tcp_pool.generation();
        let mut stream = factory().connect_tcp(addr).await?;
        let response = tcp_message_exchange(&mut stream, wire, expected).await?;
        self.tcp_pool.push(PooledTcp { stream, generation }).await;
        Ok(response)
    }

    async fn exchange(
        &self,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<Message, ClientError> {
        if let Some(proxy) = self.proxy.as_ref() {
            let addr = match &self.transport {
                Transport::Udp { addr } | Transport::Tcp { addr } => *addr,
                Transport::RCode { .. } => {
                    return Err(ClientError::Protocol(
                        "rcode transport should not perform network exchange",
                    ));
                }
                #[cfg(feature = "encrypted")]
                Transport::Dot { .. } | Transport::Doh { .. } => {
                    // DoT/DoH-over-proxy needs TLS layered on a Box<dyn
                    // ProxyConn>; the upstream tokio_rustls TlsConnector
                    // is generic over the IO stream but the call sites
                    // here aren't wired yet. ADR-0012 marks it
                    // follow-up. Refuse so misconfiguration is loud.
                    return Err(ClientError::Tls(
                        "DoT/DoH routing through a proxy is not implemented yet \
                        (issue #67 phase 2 follow-up); use plain udp:// or tcp:// for \
                        a #PROXY-tagged nameserver"
                            .to_string(),
                    ));
                }
            };
            let response = proxy_tcp_exchange(proxy, addr, wire).await?;
            return decode_validated_response(&response, expected);
        }
        match &self.transport {
            Transport::Udp { addr } => udp_exchange(*addr, wire, expected).await,
            Transport::Tcp { addr } => self.tcp_exchange_pooled(*addr, wire, expected).await,
            Transport::RCode { .. } => Err(ClientError::Protocol(
                "rcode transport should not perform network exchange",
            )),
            #[cfg(feature = "encrypted")]
            Transport::Dot { addr, sni } => {
                let response = dot_exchange(*addr, sni, wire).await?;
                decode_validated_response(&response, expected)
            }
            #[cfg(feature = "encrypted")]
            Transport::Doh { addr, sni, path } => {
                let response = doh_exchange(*addr, sni, path, wire).await?;
                decode_validated_response(&response, expected)
            }
        }
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

fn socket_label(addr: SocketAddr, default_port: u16) -> String {
    if addr.port() == default_port {
        addr.ip().to_string()
    } else {
        addr.to_string()
    }
}

async fn proxy_tcp_exchange(
    proxy: &DnsProxy,
    addr: SocketAddr,
    wire: &[u8],
) -> Result<Vec<u8>, ClientError> {
    use meow_common::{ConnType, Metadata, Network};
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        host: smol_str::SmolStr::from(addr.ip().to_string()),
        dst_ip: Some(addr.ip()),
        dst_port: addr.port(),
        // DNS-via-proxy exchanges are resolver housekeeping — a `lazy`
        // group serving this dial must not count it as use.
        internal: true,
        ..Default::default()
    };
    let mut stream = proxy
        .dial_tcp(&metadata)
        .await
        // `into_io_error` keeps the innermost `Io` verbatim: an errno-bearing
        // dial failure (EMFILE under local fd pressure) must not be flattened
        // into a context-only `Other` before it reaches the resolver's
        // classifier (#682) — and `Unsupported` refusals keep their kind.
        .map_err(|e| e.into_io_error("dns-via-proxy dial"))?;
    write_lp(&mut stream, wire).await?;
    read_lp(&mut stream).await
}

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
    let sock = if addr.ip().is_loopback() {
        let local: SocketAddr = match addr {
            SocketAddr::V4(_) => SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
        };
        UdpSocket::bind(local).await?
    } else {
        factory().bind_udp().await?
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

#[cfg(feature = "encrypted")]
async fn dot_exchange(addr: SocketAddr, sni: &str, wire: &[u8]) -> Result<Vec<u8>, ClientError> {
    let tls = tls_layer(sni, "dot")?;
    let tcp = factory().connect_tcp(addr).await?;
    let mut stream = tls.connect(Box::new(tcp)).await.map_err(|e| match e {
        // `TransportError::Io` still carries the raw errno (#680);
        // stringifying it here would re-flatten an `EMFILE`-class
        // handshake failure into a context-less `Tls` (#682).
        meow_transport::TransportError::Io(io_err) => ClientError::Io(io_err),
        other => ClientError::Tls(other.to_string()),
    })?;
    write_lp(&mut stream, wire).await?;
    read_lp(&mut stream).await
}

/// Maximum DoH response size (HTTP/1.1 headers + DNS body), in bytes.
///
/// DNS wire messages are inherently capped at 65535 bytes — the 2-octet
/// length prefix used by DNS-over-TCP and DNS-over-TLS (`read_lp`) enforces
/// it structurally. DoH, however, frames the DNS message inside an HTTP
/// response and this client reads the whole response with `Connection:
/// close` (no `Transfer-Encoding` parsing). An unbounded `read_to_end` there
/// let a misbehaving or hostile upstream stream an arbitrarily large body and
/// drive unbounded heap growth (low-risk review item). Cap the total response
/// at the DNS message maximum plus generous room for HTTP/1.1 headers; a
/// well-formed DoH answer always fits while an oversized response is rejected.
#[cfg(feature = "encrypted")]
const MAX_DOH_RESPONSE_BYTES: usize = 65535 + 16 * 1024;

/// Read an HTTP/1.1 response to EOF (the server uses `Connection: close`),
/// rejecting responses whose total size exceeds [`MAX_DOH_RESPONSE_BYTES`].
/// Extracted from [`doh_exchange`] so the bounded-read behaviour is unit
/// testable without standing up a TLS DoH server.
#[cfg(feature = "encrypted")]
async fn read_bounded_http_response<R>(stream: &mut R) -> Result<Vec<u8>, ClientError>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    let mut all = Vec::with_capacity(1024);
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
async fn doh_exchange(
    addr: SocketAddr,
    sni: &str,
    path: &str,
    wire: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let tls = tls_layer(sni, "http/1.1")?;
    let tcp = factory().connect_tcp(addr).await?;
    let mut stream = tls.connect(Box::new(tcp)).await.map_err(|e| match e {
        // `TransportError::Io` still carries the raw errno (#680);
        // stringifying it here would re-flatten an `EMFILE`-class
        // handshake failure into a context-less `Tls` (#682).
        meow_transport::TransportError::Io(io_err) => ClientError::Io(io_err),
        other => ClientError::Tls(other.to_string()),
    })?;

    // Minimal HTTP/1.1 POST. Connection: close so the server EOFs and we can
    // read-to-end without parsing chunked transfer-encoding.
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: meow-rs\r\n\
         Accept: application/dns-message\r\n\
         Content-Type: application/dns-message\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        host = sni,
        len = wire.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(wire).await?;
    stream.flush().await?;

    // Read the full HTTP/1.1 response with a bounded buffer. `Connection:
    // close` means the server EOFs after the body, so reading to EOF is
    // correct — but we cap the total to `MAX_DOH_RESPONSE_BYTES` so a
    // misbehaving upstream cannot stream an unbounded body into memory.
    let all = read_bounded_http_response(&mut stream).await?;
    let split = find_subseq(&all, b"\r\n\r\n")
        .ok_or(ClientError::Protocol("doh: missing header terminator"))?;
    let head_bytes = &all[..split];
    let body = &all[split + 4..];
    let head_str =
        std::str::from_utf8(head_bytes).map_err(|_| ClientError::Protocol("doh: bad headers"))?;
    let status_line = head_str
        .lines()
        .next()
        .ok_or(ClientError::Protocol("doh: empty response"))?;
    // "HTTP/1.1 200 OK" — extract the status code.
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts.next().unwrap_or("");
    if status != "200" {
        return Err(ClientError::Protocol("doh: non-200 status"));
    }
    Ok(body.to_vec())
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
#[cfg(feature = "encrypted")]
fn tls_layer(sni: &str, alpn: &str) -> Result<TlsLayer, ClientError> {
    let config = TlsConfig {
        alpn: vec![alpn.to_owned()],
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

    /// A DoH response at exactly the cap is accepted; one byte over the cap
    /// is rejected with a protocol error. Guards the low-risk review fix
    /// that bounds the previously unbounded `read_to_end`.
    #[cfg(feature = "encrypted")]
    #[tokio::test]
    async fn doh_bounded_read_enforces_response_size_cap() {
        let at_cap = vec![0u8; MAX_DOH_RESPONSE_BYTES];
        let mut reader = at_cap.as_slice();
        let got = read_bounded_http_response(&mut reader).await.unwrap();
        assert_eq!(got.len(), MAX_DOH_RESPONSE_BYTES);

        let over_cap = vec![0u8; MAX_DOH_RESPONSE_BYTES + 1];
        let mut reader = over_cap.as_slice();
        let err = read_bounded_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(
                err,
                ClientError::Protocol("doh: response exceeds maximum size")
            ),
            "expected oversized-rejection, got {err:?}"
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
        assert_eq!(
            take_fresh(&mut idle, now, timeout),
            Some(3),
            "the most recently returned stream must be reused first"
        );
        assert!(
            idle.is_empty(),
            "both streams idle past the timeout must have been closed, not left pooled"
        );
    }

    #[test]
    fn take_fresh_returns_none_when_every_stream_is_stale() {
        let timeout = Duration::from_secs(30);
        let now = Instant::now();
        let mut idle = vec![
            (1u32, now - Duration::from_secs(31)),
            (2u32, now - Duration::from_secs(60)),
        ];
        assert_eq!(
            take_fresh(&mut idle, now, timeout),
            None,
            "an all-stale pool must force a fresh connect"
        );
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
        assert_eq!(take_fresh(&mut idle, now, timeout), Some(2));
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
        let _ = proxy_tcp_exchange(&dyn_proxy, "8.8.8.8:53".parse().unwrap(), b"\x00").await;
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
        let err = proxy_tcp_exchange(&proxy, "8.8.8.8:53".parse().unwrap(), b"\x00")
            .await
            .unwrap_err();
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
