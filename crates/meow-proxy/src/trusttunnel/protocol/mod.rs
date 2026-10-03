//! TrustTunnel HTTP/2 wire protocol. The adapter supplies verified TLS through
//! the workspace dialer; this module never creates an outbound socket itself.

mod stream;
mod udp;

pub use stream::TunnelStream;
pub use udp::UdpAssociation;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex as AsyncMutex,
};
use tokio_util::sync::CancellationToken;

pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> IoStream for T {}

#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect(&self, internal: bool) -> io::Result<Box<dyn IoStream>>;
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
        }
    }
}

struct Inner {
    connector: Arc<dyn Connector>,
    auth: HeaderValue,
    options: Options,
    sessions: Mutex<Vec<Arc<Session>>>,
    creating: AsyncMutex<()>,
    generation: AtomicU64,
    network_cancel: Mutex<CancellationToken>,
}

struct Session {
    sender: h2::client::SendRequest<Bytes>,
    cancel: CancellationToken,
    reusable: Arc<AtomicBool>,
    active: AtomicUsize,
    udp: AsyncMutex<Option<Arc<udp::Mux>>>,
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

pub(crate) struct Lease(Arc<Session>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone)]
pub struct Client(Arc<Inner>);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn h2_error(error: h2::Error) -> io::Error {
    if error.is_io() {
        error
            .into_io()
            .unwrap_or_else(|| io::Error::other("HTTP/2 transport failed"))
    } else {
        io::Error::other(error)
    }
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
        let mut auth = HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", options.username, options.password))
        ))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid credentials"))?;
        auth.set_sensitive(true);
        Ok(Self(Arc::new(Inner {
            connector,
            auth,
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

    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        lock(&self.0.sessions)
            .iter()
            .filter(|s| !s.cancel.is_cancelled())
            .count()
    }

    fn existing(&self, force: bool) -> io::Result<Option<Lease>> {
        let mut pool = lock(&self.0.sessions);
        pool.retain(|session| {
            !session.cancel.is_cancelled() && session.reusable.load(Ordering::Acquire)
        });
        if let Some(session) = pool.iter().min_by_key(|s| s.active.load(Ordering::Acquire)) {
            let active = session.active.load(Ordering::Acquire);
            if active == 0
                || active < self.0.options.min_streams
                || force
                || pool.len() >= self.0.options.max_connections
            {
                if active >= self.0.options.max_streams {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "TrustTunnel stream limit reached",
                    ));
                }
                session.active.fetch_add(1, Ordering::AcqRel);
                return Ok(Some(Lease(Arc::clone(session))));
            }
        }
        Ok(None)
    }

    async fn session(&self, internal: bool) -> io::Result<Lease> {
        if let Some(lease) = self.existing(false)? {
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
        if let Some(lease) = self.existing(false)? {
            return Ok(lease);
        }
        let cancel = lock(&self.0.network_cancel).child_token();
        let reusable = Arc::new(AtomicBool::new(true));
        let io = self.0.connector.connect(internal).await?;
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(131072)
            .initial_connection_window_size(2 * 1024 * 1024)
            .max_send_buffer_size(128 * 1024)
            .handshake(io)
            .await
            .map_err(h2_error)?;
        let canceled = cancel.clone();
        spawn_scoped(async move {
            tokio::select! { _ = canceled.cancelled() => {}, _ = connection => {} }
            canceled.cancel();
        });
        let session = Arc::new(Session {
            sender,
            cancel,
            reusable,
            active: AtomicUsize::new(1),
            udp: AsyncMutex::new(None),
        });
        let lease = Lease(Arc::clone(&session));
        let mut handshake = HandshakeGuard {
            session: Arc::clone(&session),
            complete: false,
        };
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
        if self.0.options.health_check {
            let check = Lease(Arc::clone(&lease.0));
            check.0.active.fetch_add(1, Ordering::AcqRel);
            drop(self.open(check, "_check").await?);
        }
        handshake.complete = true;
        Ok(lease)
    }

    async fn open(&self, lease: Lease, authority: &str) -> io::Result<TunnelStream> {
        let uri: http::Uri = authority.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid CONNECT authority")
        })?;
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("proxy-authorization", self.0.auth.clone())
            .header("user-agent", concat!("meow/", env!("CARGO_PKG_VERSION")))
            .body(())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid CONNECT request"))?;
        let mut sender = lease.0.sender.clone().ready().await.map_err(|error| {
            // GOAWAY retires admission without canceling successful streams.
            // This operation is not replayed; a later dial uses a new session.
            lease.0.reusable.store(false, Ordering::Release);
            h2_error(error)
        })?;
        let end = authority == "_check";
        let (response, mut send) = sender.send_request(request, end).map_err(h2_error)?;
        let result = response.await.map_err(h2_error)?;
        if result.status() != StatusCode::OK {
            send.send_reset(h2::Reason::CANCEL);
            if result.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                lease.0.cancel.cancel();
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TrustTunnel authentication failed",
                ));
            }
            return Err(io::Error::other(format!(
                "TrustTunnel CONNECT returned {}",
                result.status().as_u16()
            )));
        }
        Ok(TunnelStream::new(send, result.into_body(), lease, end))
    }

    pub async fn tcp_with_context(
        &self,
        authority: &str,
        internal: bool,
    ) -> io::Result<TunnelStream> {
        if authority.starts_with('_') || !authority.contains(':') || authority.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TCP destination",
            ));
        }
        tokio::time::timeout(self.0.options.timeout, async {
            self.open(self.session(internal).await?, authority).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TrustTunnel CONNECT timed out"))?
    }

    pub async fn udp_with_context(
        &self,
        source: std::net::SocketAddr,
        app_name: &str,
        internal: bool,
    ) -> io::Result<UdpAssociation> {
        tokio::time::timeout(self.0.options.timeout, async {
            let lease = self.session(internal).await?;
            let session = Arc::clone(&lease.0);
            let mut slot = session.udp.lock().await;
            let mux = if let Some(mux) = slot.as_ref().filter(|m| !m.is_closed()) {
                Arc::clone(mux)
            } else {
                let stream = self.open(lease, "_udp2").await?;
                let mux = udp::Mux::new(stream, &session.cancel);
                *slot = Some(Arc::clone(&mux));
                mux
            };
            mux.associate(source, app_name)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TrustTunnel UDP CONNECT timed out"))?
    }
    #[cfg(test)]
    pub async fn tcp(&self, authority: &str) -> io::Result<TunnelStream> {
        self.tcp_with_context(authority, false).await
    }

    #[cfg(test)]
    pub async fn udp(&self, source: std::net::SocketAddr, app: &str) -> io::Result<UdpAssociation> {
        self.udp_with_context(source, app, false).await
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
