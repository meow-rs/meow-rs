//! The HTTP/2 transport: one TLS stream per pooled connection, CONNECT per
//! proxied flow. The adapter supplies the verified TLS stream through
//! [`StreamConnector`]; this module owns the h2 handshake and its driver.

use super::{Admission, Connection, Opener, StreamKind};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http::{Request, StatusCode};
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> IoStream for T {}

/// Supplies one verified TLS stream to the endpoint.
#[async_trait]
pub trait StreamConnector: Send + Sync {
    async fn connect(&self) -> io::Result<Box<dyn IoStream>>;
}

/// Turns a TLS stream into a pooled HTTP/2 connection.
pub struct H2Connector(Arc<dyn StreamConnector>);

impl H2Connector {
    pub fn new(streams: Arc<dyn StreamConnector>) -> Self {
        Self(streams)
    }
}

#[async_trait]
impl super::Connector for H2Connector {
    async fn connect(&self, cancel: CancellationToken) -> io::Result<Box<dyn Connection>> {
        let io = self.0.connect().await?;
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(131_072)
            .initial_connection_window_size(2 * 1024 * 1024)
            .max_send_buffer_size(128 * 1024)
            .handshake(io)
            .await
            .map_err(h2_error)?;
        let peer_limit = Arc::new(AtomicUsize::new(usize::MAX));
        let sampler = Arc::clone(&peer_limit);
        let canceled = cancel;
        super::spawn_scoped(async move {
            // h2 exposes the peer's `SETTINGS_MAX_CONCURRENT_STREAMS` only on
            // the connection handle, and the handle is consumed by this task
            // — so sample it here, after every poll, into a slot the pool can
            // read. Without it a connection sitting at the peer's limit is
            // indistinguishable from an idle one: `poll_ready` answers
            // `Ready` whatever the limit says (it only tracks *this* handle's
            // own pending stream), so `send_request` would queue the stream
            // as pending-open and the dial would park in `response.await`
            // until its whole deadline expired — while a sibling connection,
            // or a new one, could have carried it immediately.
            let mut connection = connection;
            let driver = std::future::poll_fn(move |cx| {
                let polled = std::future::Future::poll(std::pin::Pin::new(&mut connection), cx);
                sampler.store(connection.max_concurrent_send_streams(), Ordering::Relaxed);
                polled
            });
            tokio::select! { _ = canceled.cancelled() => {}, _ = driver => {} }
            canceled.cancel();
        });
        Ok(Box::new(H2Connection { sender, peer_limit }))
    }
}

struct H2Connection {
    sender: h2::client::SendRequest<Bytes>,
    /// The peer's acknowledged `SETTINGS_MAX_CONCURRENT_STREAMS`, sampled by
    /// the connection driver. `usize::MAX` until the peer advertises a limit,
    /// which is also HTTP/2's own default — so a dial racing the first
    /// SETTINGS frame is never throttled by a stale zero.
    peer_limit: Arc<AtomicUsize>,
}

#[async_trait]
impl Connection for H2Connection {
    /// This cannot park on stream capacity: `poll_ready` only waits on a
    /// pending stream belonging to the same `SendRequest` handle, and each
    /// call clones a fresh one. The peer's concurrency limit is handled
    /// where it is observable instead — see [`Connection::stream_ceiling`].
    async fn admit(&self) -> Admission {
        match self.sender.clone().ready().await {
            Ok(sender) => Admission::Granted(Box::new(H2Opener(sender))),
            // A GOAWAY, or a connection on its way out. Unobservable until
            // this point, so the pool will have handed out a session that
            // already stopped accepting streams; retiring it is what makes
            // the caller's retry pick a different one.
            Err(_) => Admission::Closed,
        }
    }

    fn stream_ceiling(&self) -> usize {
        self.peer_limit.load(Ordering::Relaxed)
    }
}

struct H2Opener(h2::client::SendRequest<Bytes>);

#[async_trait]
impl Opener for H2Opener {
    async fn open(
        mut self: Box<Self>,
        request: Request<()>,
        end: bool,
    ) -> io::Result<(StatusCode, StreamKind)> {
        let (response, send) = self.0.send_request(request, end).map_err(h2_error)?;
        let result = response.await.map_err(h2_error)?;
        let status = result.status();
        Ok((
            status,
            StreamKind::H2(H2Stream::new(send, result.into_body(), end)),
        ))
    }
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

pub struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    pending: Bytes,
    shutdown: bool,
}

impl H2Stream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream, shutdown: bool) -> Self {
        Self {
            send,
            recv,
            pending: Bytes::new(),
            shutdown,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(
                    this.recv
                        .flow_control()
                        .release_capacity(n)
                        .map_err(h2_error),
                );
            }
            match this.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(bytes))) => this.pending = bytes,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(h2_error(error))),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.send.reserve_capacity(buf.len().min(16 * 1024));
        let mut capacity = this.send.capacity();
        if capacity == 0 {
            match this.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(0))) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Some(Ok(available))) => capacity = available,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(h2_error(error))),
                Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let n = capacity.min(buf.len()).min(16 * 1024);
        Poll::Ready(
            this.send
                .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                .map(|()| n)
                .map_err(h2_error),
        )
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // DATA is owned by the h2 driver after send_data; flushing another
        // logical stream must never wait for an unrelated stream's traffic.
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Ok(()));
        }
        this.shutdown = true;
        Poll::Ready(this.send.send_data(Bytes::new(), true).map_err(h2_error))
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        if !self.recv.is_end_stream() || !self.shutdown {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}
