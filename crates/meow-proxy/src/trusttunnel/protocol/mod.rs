//! TrustTunnel wire protocol: one CONNECT per proxied flow over a pool of
//! multiplexed connections. The pool policy here is transport-agnostic; the
//! transports are [`http2`] (always) and [`http3`] (opt-in `trusttunnel-h3`).
//!
//! HTTP/2 connections are TLS streams the adapter supplies through the
//! workspace dialer, so that path never creates an outbound socket itself.
//! HTTP/3 has no such seam — QUIC owns its UDP socket — and binds through
//! `meow_common::bind_udp` instead.

mod headers;
mod http2;
#[cfg(feature = "trusttunnel-h3")]
mod http3;
mod stream;
mod udp;

pub use headers::ExtraHeaders;
pub use http2::{H2Connector, IoStream, StreamConnector};
#[cfg(feature = "trusttunnel-h3")]
pub use http3::QuicConnector;
pub use stream::TunnelStream;
pub use udp::UdpAssociation;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use http::{HeaderValue, Method, Request, StatusCode};
use stream::StreamKind;
#[derive(Debug)]
pub(crate) struct AuthenticationFailed;
impl std::fmt::Display for AuthenticationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustTunnel authentication failed")
    }
}
impl std::error::Error for AuthenticationFailed {}

use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

/// Establishes one new multiplexed connection for the pool.
#[async_trait]
pub trait Connector: Send + Sync {
    /// Dial, handshake, and start driving a connection. Every task the
    /// connection owns must stop when `cancel` fires — that token is how the
    /// pool, and `reset_sessions`, retire it.
    async fn connect(&self, cancel: CancellationToken) -> io::Result<Box<dyn Connection>>;
}

/// One live multiplexed connection to the endpoint.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Reserve room for exactly one more CONNECT stream, before any byte of
    /// the request is written.
    async fn admit(&self) -> Admission;
    /// Whether this connection still accepts new streams, independently of
    /// its remaining capacity. A GOAWAY retires admission, not live streams.
    fn is_reusable(&self) -> bool {
        true
    }
    /// The peer's advertised concurrent-stream ceiling, or `usize::MAX`
    /// while it is unknown. Transports whose refusal is observable up front
    /// report it through [`Admission::Full`] instead and keep this at the
    /// default.
    fn stream_ceiling(&self) -> usize {
        usize::MAX
    }
}

/// The outcome of asking a connection for stream room.
pub enum Admission {
    /// Granted: the [`Opener`] may send exactly one CONNECT.
    Granted(Box<dyn Opener>),
    /// The peer will not take another stream right now, but the connection
    /// is healthy — it stays pooled and the caller tries a different one.
    #[cfg_attr(
        not(feature = "trusttunnel-h3"),
        allow(
            dead_code,
            reason = "only the HTTP/3 transport can observe a full connection up front"
        )
    )]
    Full,
    /// The connection is going away. Retire it from the pool.
    Closed,
}

/// Admission granted for exactly one CONNECT stream.
#[async_trait]
pub trait Opener: Send {
    /// Send the CONNECT and await its response headers.
    ///
    /// Returns the status with the stream, rather than interpreting it: the
    /// policy for a refusal (and for the credential error in particular) is
    /// the pool's, in [`Client::open`].
    async fn open(
        self: Box<Self>,
        request: Request<()>,
        end: bool,
    ) -> io::Result<(StatusCode, StreamKind)>;
}

/// Credentials intentionally have no Debug implementation.
pub struct Options {
    pub username: String,
    pub password: String,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub timeout: Duration,
    pub health_check: bool,
    /// First field of every `user-agent` (`<platform>` in the spec).
    pub platform: String,
    /// Second field on a TCP CONNECT (`<app_name>` in the spec).
    pub app_name: String,
    /// Operator-supplied CONNECT headers, re-rendered per request.
    pub headers: ExtraHeaders,
}

impl Options {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            max_connections: 8,
            min_streams: 5,
            max_streams: 128,
            timeout: Duration::from_secs(10),
            health_check: false,
            platform: headers::default_platform().to_owned(),
            // Deliberately unversioned: `meow/0.22.0` narrowed every session
            // to one build of one client, which is the opposite of what a
            // protocol designed to look like ordinary HTTPS wants. Operators
            // who need to match a specific client set `platform`/`app-name`.
            app_name: "meow".to_owned(),
            headers: ExtraHeaders::default(),
        }
    }
}

struct Inner {
    connector: Arc<dyn Connector>,
    auth: HeaderValue,
    /// The three spec-shaped user-agents this client can send, resolved once:
    /// a TCP CONNECT, the `_udp2` multiplexer, and `_check`. Empty when the
    /// config supplies its own `user-agent`.
    agents: Option<Agents>,
    options: Options,
    sessions: Mutex<Vec<Arc<Session>>>,
    creating: AsyncMutex<()>,
    generation: AtomicU64,
    network_cancel: Mutex<CancellationToken>,
}

/// Resolved `user-agent` values, one per CONNECT target shape.
struct Agents {
    tcp: HeaderValue,
    udp2: HeaderValue,
    check: HeaderValue,
}

impl Agents {
    fn build(options: &Options) -> io::Result<Self> {
        let value = |authority: &str| {
            HeaderValue::from_str(&headers::user_agent(
                &options.platform,
                &options.app_name,
                authority,
            ))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid user-agent"))
        };
        Ok(Self {
            // Any authority that is not a pseudo-host takes the TCP shape.
            tcp: value("")?,
            udp2: value("_udp2")?,
            check: value("_check")?,
        })
    }

    fn select(&self, authority: &str) -> HeaderValue {
        match authority {
            "_check" => self.check.clone(),
            "_udp2" => self.udp2.clone(),
            _ => self.tcp.clone(),
        }
    }
}

struct Session {
    link: Box<dyn Connection>,
    cancel: CancellationToken,
    reusable: AtomicBool,
    /// Stop creating UDP associations and release the cached mux once its
    /// last association closes, without cancelling established TCP flows.
    retiring: CancellationToken,
    active: AtomicUsize,
    udp: AsyncMutex<Option<Arc<udp::Mux>>>,
}

impl Session {
    fn retire(&self) {
        self.reusable.store(false, Ordering::Release);
        self.retiring.cancel();
    }
    /// How many streams this connection may carry: our own configured
    /// ceiling, capped by the peer's.
    fn ceiling(&self, options: &Options) -> usize {
        options.max_streams.min(self.link.stream_ceiling())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct HandshakeGuard {
    session: Arc<Session>,
    complete: bool,
}
impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        if !self.complete {
            self.session.cancel.cancel();
        }
    }
}

pub struct Lease(Arc<Session>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Armed while a CONNECT is in flight, so a connection that never answers one
/// leaves the pool.
///
/// A pooled connection whose peer has gone silent — an expired NAT entry, a
/// laptop that slept, a half-open peer — reports nothing: `admit` grants (h2
/// has seen no connection error), the request lands in the kernel's send
/// buffer, and the response simply never arrives. Only the caller's deadline
/// ends that wait, and with the session still marked reusable the *next* dial
/// elects the very same one — it has no active streams, so it is the least
/// loaded candidate — and pays the same deadline again, for as long as the
/// kernel's retransmit timeout takes to error the socket. Each of those
/// failures is an ordinary `TimedOut`, which is exactly what
/// `DialFailureTracker` dead-marks a healthy node over.
///
/// Retire rather than cancel: a CONNECT can also go unanswered because the
/// *target* is slow, and the streams already running on that connection are
/// no business of this dial's. Leaving the admission pool costs one later
/// handshake; cancelling would cost every live flow on it.
struct InFlight(Option<Arc<Session>>);

impl InFlight {
    fn arm(session: &Arc<Session>) -> Self {
        Self(Some(Arc::clone(session)))
    }

    /// The response headers arrived (whatever their status): the connection
    /// demonstrably works.
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Some(session) = self.0.take() {
            session.retire();
        }
    }
}

#[derive(Clone)]
pub struct Client(Arc<Inner>);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Client {
    pub fn new(connector: Arc<dyn Connector>, options: Options) -> io::Result<Self> {
        if options.username.is_empty()
            || options.username.contains(':')
            || options.password.is_empty()
            || options.username.len() + options.password.len() > 4096
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TrustTunnel requires bounded username/password; username cannot contain ':'",
            ));
        }
        if !(1..=16).contains(&options.max_connections)
            || !(1..=512).contains(&options.max_streams)
            || options.min_streams > options.max_streams
            || options.timeout.is_zero()
            || options.timeout > Duration::from_secs(30)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TrustTunnel pool limits",
            ));
        }
        for (label, token, spaces) in [
            ("platform", &options.platform, false),
            ("app-name", &options.app_name, true),
        ] {
            headers::validate_token(label, token, spaces)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        }
        let mut auth = HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", options.username, options.password))
        ))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid credentials"))?;
        auth.set_sensitive(true);
        let agents = if options.headers.overrides_user_agent() {
            None
        } else {
            Some(Agents::build(&options)?)
        };
        Ok(Self(Arc::new(Inner {
            connector,
            auth,
            agents,
            options,
            sessions: Mutex::new(Vec::new()),
            creating: AsyncMutex::new(()),
            generation: AtomicU64::new(1),
            network_cancel: Mutex::new(CancellationToken::new()),
        })))
    }

    pub fn reset(&self) {
        self.0.generation.fetch_add(1, Ordering::AcqRel);
        {
            // Live GOAWAY streams leave the admission pool. Cancel their
            // network generation too, without retaining a session registry.
            let mut network = lock(&self.0.network_cancel);
            network.cancel();
            *network = CancellationToken::new();
        }
        for session in lock(&self.0.sessions).drain(..) {
            session.cancel.cancel();
        }
    }

    /// Sessions the pool can still elect — retired ones (cancelled, or marked
    /// unusable by [`InFlight`]) are left for the next `existing()` sweep to
    /// drop, so counting the vector itself would not say what a dial sees.
    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        lock(&self.0.sessions)
            .iter()
            .filter(|s| {
                !s.cancel.is_cancelled()
                    && s.reusable.load(Ordering::Acquire)
                    && s.link.is_reusable()
            })
            .count()
    }

    /// Lease a pooled session that can carry one more stream, skipping
    /// `avoid` — the session a caller was just refused admission on.
    ///
    /// `Ok(None)` means "dial a new connection"; the error means the pool is
    /// out of room on both axes at once.
    fn existing(&self, avoid: Option<&Arc<Session>>) -> io::Result<Option<Lease>> {
        let mut pool = lock(&self.0.sessions);
        pool.retain(|session| {
            let reusable = !session.cancel.is_cancelled()
                && session.reusable.load(Ordering::Acquire)
                && session.link.is_reusable();
            if !reusable {
                session.retire();
            }
            reusable
        });
        // Measured over the whole pool, not the filtered candidates: a
        // skipped or full session still occupies a connection slot.
        let at_capacity = pool.len() >= self.0.options.max_connections;
        let candidate = pool
            .iter()
            .filter(|session| !avoid.is_some_and(|busy| Arc::ptr_eq(session, busy)))
            .filter(|session| {
                session.active.load(Ordering::Acquire) < session.ceiling(&self.0.options)
            })
            .min_by_key(|session| session.active.load(Ordering::Acquire));
        let Some(session) = candidate else {
            // Nothing in the pool can take the stream. Below the connection
            // cap that is routine — the caller dials another one. At the cap
            // there is nowhere left to go, and a local-resource error says so
            // without letting `DialFailureTracker` dead-mark a healthy node
            // over our own pool ceiling.
            if at_capacity {
                return Err(meow_common::error::local_resource_limit(
                    "TrustTunnel stream limit reached",
                ));
            }
            return Ok(None);
        };
        // Spread load until every connection carries `min_streams`, then
        // pack — unless the pool cannot grow, where packing is all there is.
        let active = session.active.load(Ordering::Acquire);
        if active == 0 || active < self.0.options.min_streams || at_capacity {
            session.active.fetch_add(1, Ordering::AcqRel);
            return Ok(Some(Lease(Arc::clone(session))));
        }
        Ok(None)
    }

    async fn session(&self, avoid: Option<&Arc<Session>>) -> io::Result<Lease> {
        if let Some(lease) = self.existing(avoid)? {
            return Ok(lease);
        }
        let generation = self.0.generation.load(Ordering::Acquire);
        let _creating = self.0.creating.lock().await;
        if generation != self.0.generation.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "TrustTunnel session was reset",
            ));
        }
        if let Some(lease) = self.existing(avoid)? {
            return Ok(lease);
        }
        let cancel = lock(&self.0.network_cancel).child_token();
        // A half-established connection owns tasks keyed on this token, and
        // nothing else will ever retire them. The guard covers every way out
        // of the await, including the caller's deadline dropping this future
        // — dropping a `CancellationToken` does not cancel it, and the H3
        // driver task is spawned before its handshake resolves.
        let guard = cancel.clone().drop_guard();
        let link = self.0.connector.connect(cancel.clone()).await?;
        guard.disarm();
        let session = Arc::new(Session {
            link,
            cancel,
            reusable: AtomicBool::new(true),
            retiring: CancellationToken::new(),
            active: AtomicUsize::new(1),
            udp: AsyncMutex::new(None),
        });
        let lease = Lease(Arc::clone(&session));
        let mut handshake = HandshakeGuard {
            session: Arc::clone(&session),
            complete: false,
        };
        if self.0.options.health_check {
            let check = Lease(Arc::clone(&lease.0));
            check.0.active.fetch_add(1, Ordering::AcqRel);
            // tcp()/udp() own one deadline for pool acquisition, handshake,
            // health check and CONNECT; a second equal-duration timer cannot
            // expire before that outer deadline. No retry here: this session
            // was just handshaked, so a refusal is the connection itself
            // failing, not the recycle `connect` covers.
            let Admission::Granted(opener) = Self::admit(&check).await else {
                return Err(Self::admission_refused());
            };
            drop(self.open(opener, check, "_check").await?);
        }
        // Publish under the same lock as reset: a late handshake cannot revive
        // a connection belonging to a retired network generation.
        {
            let mut pool = lock(&self.0.sessions);
            if generation != self.0.generation.load(Ordering::Acquire) {
                session.cancel.cancel();
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "TrustTunnel session was reset",
                ));
            }
            pool.push(session);
        }
        handshake.complete = true;
        Ok(lease)
    }

    /// Reserve capacity for one new stream on `lease`'s connection, applying
    /// the pool-side consequence of a refusal: a connection that reports
    /// itself gone leaves the admission pool, so the caller's retry picks a
    /// different one.
    async fn admit(lease: &Lease) -> Admission {
        // `existing()` only elects a connection below the peer's acknowledged
        // stream ceiling, so h2's `ready()` has a slot waiting for it: a wait
        // that outlives the caller's deadline means the connection stopped
        // answering. (If the peer shrank its limit under live streams the wait
        // is legitimate — retiring the connection is still the conservative
        // answer, and costs one later handshake.)
        let inflight = InFlight::arm(&lease.0);
        let admission = lease.0.link.admit().await;
        inflight.disarm();
        if matches!(admission, Admission::Closed) {
            lease.0.retire();
        }
        admission
    }

    /// Error for a peer that refused admission on two successive sessions.
    fn admission_refused() -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "TrustTunnel peer refused to admit a new stream",
        )
    }

    /// Error for a refusal that survived the retry.
    ///
    /// A peer that is merely out of stream credit is not an unhealthy one:
    /// report it as a local resource limit so `DialFailureTracker` cannot
    /// dead-mark a working member over a concurrency ceiling.
    fn refused(admission: &Admission) -> io::Error {
        match admission {
            Admission::Full => {
                meow_common::error::local_resource_limit("TrustTunnel stream limit reached")
            }
            _ => Self::admission_refused(),
        }
    }

    /// Open one CONNECT stream, retrying once when the pooled session will
    /// not admit it.
    ///
    /// Retrying is safe precisely because nothing was sent: the "requests
    /// are not replayed" rule covers a request that reached the peer, not
    /// one that never left. Without the retry every routine server-side
    /// connection recycle costs one user-visible dial failure — and since
    /// the error is neither a capability nor a local-resource error, it also
    /// feeds `DialFailureTracker` toward dead-marking a healthy member.
    async fn connect(&self, authority: &str) -> io::Result<TunnelStream> {
        let lease = self.session(None).await?;
        if let Admission::Granted(opener) = Self::admit(&lease).await {
            return self.open(opener, lease, authority).await;
        }
        // Release the slot before re-electing, so a session that was only
        // full is not counted as one stream busier than it is. `admit`
        // either retired that session (`existing()` drops it) or left it
        // pooled and full (`avoid` skips it) — so `session()` now reuses
        // another pooled connection, dials a fresh one, or reports the
        // stream limit. One retry, not a loop: a peer that declines twice
        // is at its limit, not recycling.
        let declined = Arc::clone(&lease.0);
        drop(lease);
        let lease = self.session(Some(&declined)).await?;
        match Self::admit(&lease).await {
            Admission::Granted(opener) => self.open(opener, lease, authority).await,
            refusal => Err(Self::refused(&refusal)),
        }
    }

    async fn open(
        &self,
        opener: Box<dyn Opener>,
        lease: Lease,
        authority: &str,
    ) -> io::Result<TunnelStream> {
        let uri: http::Uri = authority.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid CONNECT authority")
        })?;
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("proxy-authorization", self.0.auth.clone());
        if let Some(agents) = &self.0.agents {
            request = request.header(http::header::USER_AGENT, agents.select(authority));
        }
        // Rendered per request, not per session: a `<random-string(…)>`
        // padding header whose value were fixed for the connection's life
        // would be exactly the constant it exists to avoid.
        for (name, template) in self.0.options.headers.iter() {
            request = request.header(name.clone(), template.render());
        }
        let request = request
            .body(())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid CONNECT request"))?;
        let end = authority == "_check";
        // From here to the response headers the connection is on trial: this
        // future is dropped by the caller's deadline (`tcp`/`udp` own the only
        // one), and a silent peer is otherwise indistinguishable from an idle
        // connection. See [`InFlight`].
        let inflight = InFlight::arm(&lease.0);
        let (status, stream) = opener.open(request, end).await?;
        inflight.disarm();
        if status != StatusCode::OK {
            // Dropping the stream resets it, on either transport.
            drop(stream);
            if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                lease.0.cancel.cancel();
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    AuthenticationFailed,
                ));
            }
            return Err(io::Error::other(format!(
                "TrustTunnel CONNECT returned {}",
                status.as_u16()
            )));
        }
        Ok(TunnelStream::new(stream, lease))
    }

    pub async fn tcp(&self, authority: &str) -> io::Result<TunnelStream> {
        if authority.starts_with('_') || !authority.contains(':') || authority.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TCP destination",
            ));
        }
        tokio::time::timeout(self.0.options.timeout, self.connect(authority))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TrustTunnel CONNECT timed out"))?
    }

    pub async fn udp(&self) -> io::Result<UdpAssociation> {
        tokio::time::timeout(self.0.options.timeout, async {
            // The same single retry `connect` does, inlined because the
            // `_udp2` mux is cached on the very session this lease names —
            // `connect` could hand back a stream on a different one.
            let mut declined: Option<Arc<Session>> = None;
            let mut refusal = Admission::Closed;
            for attempt in 0..2 {
                let lease = self.session(declined.as_ref()).await?;
                let session = Arc::clone(&lease.0);
                let mut slot = session.udp.lock().await;
                // `existing()` elected a reusable session, but a concurrent
                // dial's `InFlight` can retire it at any await from there on.
                // Retirement is pool-side only — the link may still admit —
                // so neither `admit` nor the cached mux's `is_closed()`
                // notices, and `associate()` would refuse with `BrokenPipe`.
                // A retired session is a refusal, and earns the same retry.
                let admission = if session.retiring.is_cancelled() {
                    Admission::Closed
                } else if let Some(mux) = slot.as_ref().filter(|m| !m.is_closed()) {
                    return mux.associate();
                } else {
                    Self::admit(&lease).await
                };
                refusal = match admission {
                    Admission::Granted(opener) => {
                        let stream = self.open(opener, lease, "_udp2").await?;
                        if !session.retiring.is_cancelled() {
                            let mux = udp::Mux::new(stream, &session.cancel, &session.retiring);
                            *slot = Some(Arc::clone(&mux));
                            return mux.associate();
                        }
                        Admission::Closed
                    }
                    other => other,
                };
                drop(slot);
                if attempt == 0 {
                    declined = Some(session);
                    continue;
                }
                break;
            }
            Err(Self::refused(&refusal))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TrustTunnel UDP CONNECT timed out"))?
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        lock(&self.network_cancel).cancel();
        for session in lock(&self.sessions).drain(..) {
            session.cancel.cancel();
        }
    }
}

fn spawn_scoped<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    use tracing::instrument::WithSubscriber;
    tokio::spawn(future.with_current_subscriber())
}

#[cfg(test)]
mod tests;
