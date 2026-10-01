//! yamux protocol (hashicorp/go-yamux wire format), client side, via the
//! libp2p `yamux` crate which interoperates with hashicorp yamux on the
//! wire.
//!
//! yamux 0.14 has no split Control: the `Connection` state machine must be
//! polled continuously to drive reads (data/FIN delivery to streams) AND to
//! open outbound streams.  One driver task owns the connection and polls a
//! hand-rolled state machine each wake-up: drain queued open requests, serve
//! one `poll_new_outbound`, drive one `poll_next_inbound`, then park (all
//! wakers — request channel, stream-open ack, socket — stay registered).
//! The crate speaks the `futures` IO traits; tokio-util compat bridges to
//! tokio's AsyncRead/AsyncWrite.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// tokio io bridged to the futures IO traits the yamux crate consumes
/// (\`TokioAsyncReadCompatExt::compat\`).
type FutIo<S> = tokio_util::compat::Compat<S>;

struct OpenRequest {
    respond: oneshot::Sender<std::result::Result<yamux::Stream, yamux::ConnectionError>>,
}

/// yamux session over one physical connection (client role).  The
/// concrete IO type is erased — only the driver task owns the connection.
pub struct Session {
    open_tx: mpsc::UnboundedSender<OpenRequest>,
    dead: Arc<AtomicBool>,
    _task: tokio::task::JoinHandle<()>,
}

impl Session {
    pub fn client<S>(io: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // yamux 0.14 dropped the per-stream open/close timeout knobs;
        // sing-mux sets both to 5 s — acceptable divergence.
        let config = yamux::Config::default();
        let io: FutIo<S> = io.compat();
        let mut connection = yamux::Connection::new(io, config, yamux::Mode::Client);
        let (open_tx, mut open_rx) = mpsc::unbounded_channel::<OpenRequest>();
        let dead = Arc::new(AtomicBool::new(false));
        let driver_dead = Arc::clone(&dead);
        let task = tokio::spawn(async move {
            // Queued open requests wait here in FIFO order; every request
            // keeps its own oneshot so none can be dropped by a newer one.
            let mut pending_opens: VecDeque<OpenRequest> = VecDeque::new();
            std::future::poll_fn(|cx| {
                loop {
                    // Drain queued open requests.
                    while let Poll::Ready(item) = open_rx.poll_recv(cx) {
                        match item {
                            Some(request) => pending_opens.push_back(request),
                            // All callers gone: shut the driver down.
                            None => return Poll::Ready(()),
                        }
                    }
                    // Serve stream opens until the connection reports
                    // Pending; looping here keeps the queue moving without
                    // waiting for an external wake-up.
                    if !pending_opens.is_empty() {
                        match connection.poll_new_outbound(cx) {
                            Poll::Ready(result) => {
                                let request = pending_opens.pop_front().expect("checked non-empty");
                                let _ = request.respond.send(result);
                                continue;
                            }
                            Poll::Pending => {}
                        }
                    }
                    // Drive inbound: data/FIN delivery plus connection teardown.
                    match connection.poll_next_inbound(cx) {
                        // Server-initiated streams are not expected in proxy
                        // mux; drop them (reset) and keep driving.
                        Poll::Ready(Some(Ok(stream))) => {
                            tracing::debug!("yamux: server-initiated stream dropped (reset)");
                            drop(stream);
                            continue;
                        }
                        Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                    return Poll::Pending;
                }
            })
            .await;
            driver_dead.store(true, Ordering::SeqCst);
        });
        Ok(Self {
            open_tx,
            dead,
            _task: task,
        })
    }

    pub async fn open_stream(&self) -> io::Result<Stream> {
        let (respond, response) = oneshot::channel();
        self.open_tx
            .send(OpenRequest { respond })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "yamux driver gone"))?;
        let stream = response
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "yamux driver dropped request"))?
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("yamux open: {e}")))?;
        Ok(Stream::from(stream))
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// Tear the session down now even while streams still hold it: aborts
    /// the driver (dropping the physical connection, so every stream fails)
    /// and marks it dead — an aborted driver never reaches its own
    /// `dead.store`. Used by pool resets (issue #695). Idempotent.
    pub fn close(&self) {
        self.dead.store(true, Ordering::SeqCst);
        self._task.abort();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Converges with h2mux::Session / smux::Session: aborting the
        // driver task drops the physical connection (and its fd)
        // immediately, instead of relying on `open_tx` closing to end the
        // driver loop. That path works today (MuxStreamKind::Yamux holds a
        // bare yamux::Stream with no back-reference to the Session, so
        // dropping the last stream does not itself end the driver), but an
        // evicted zero-stream session should not be able to keep the
        // socket alive waiting on the peer.
        self._task.abort();
    }
}

/// One yamux stream, exposed with tokio IO traits.
pub struct Stream {
    inner: tokio_util::compat::Compat<yamux::Stream>,
}

impl From<yamux::Stream> for Stream {
    fn from(stream: yamux::Stream) -> Self {
        Self {
            inner: stream.compat(),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// yamux echo server over a duplex pipe (crate-native server mode).
    async fn run_echo_server<S>(io: S) -> tokio::task::JoinHandle<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            let config = yamux::Config::default();
            let io = io.compat();
            let mut connection = yamux::Connection::new(io, config, yamux::Mode::Server);
            loop {
                match std::future::poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                    Some(Ok(stream)) => {
                        tokio::spawn(async move {
                            let mut stream = stream.compat();
                            let mut buf = vec![0u8; 4096];
                            loop {
                                match stream.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if stream.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Some(Err(_)) | None => return,
                }
            }
        })
    }

    #[tokio::test]
    async fn open_stream_echo_round_trip() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();

        stream.write_all(b"hello yamux").await.unwrap();
        let mut resp = [0u8; 11];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"hello yamux");
    }

    #[tokio::test]
    async fn two_streams_multiplex_independently() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());

        let mut a = session.open_stream().await.unwrap();
        let mut b = session.open_stream().await.unwrap();

        a.write_all(b"AAA").await.unwrap();
        b.write_all(b"BBB").await.unwrap();
        let mut buf = [0u8; 3];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"AAA");
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"BBB");
    }

    #[tokio::test]
    async fn concurrent_opens_all_succeed() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());

        // Open many streams at once: the driver must queue every request
        // instead of dropping earlier ones for later arrivals.
        let opens = (0..8)
            .map(|i| {
                let session = Arc::clone(&session);
                async move { (i, session.open_stream().await.unwrap()) }
            })
            .collect::<Vec<_>>();
        let streams = futures::future::join_all(opens).await;
        assert_eq!(streams.len(), 8);
        for (i, mut stream) in streams {
            let payload = format!("stream-{i}").into_bytes();
            stream.write_all(&payload).await.unwrap();
            let mut resp = vec![0u8; payload.len()];
            stream.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, payload);
        }
    }

    /// IO wrapper that flags when dropped, so a test can observe the
    /// physical connection actually being released (mirrors smux's
    /// equivalent test helper).
    struct DropTrackedIo {
        inner: tokio::io::DuplexStream,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for DropTrackedIo {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncRead for DropTrackedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DropTrackedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// Pins issue #427's yamux/h2mux driver-shutdown convergence: dropping
    /// the last `Session` reference must release the physical IO promptly
    /// (via the new `Drop` impl's `_task.abort()`), the same invariant
    /// h2mux::Session and smux::Session already guarantee.
    #[tokio::test]
    async fn dropping_idle_session_releases_physical_io() {
        let (client_io, _server_io) = tokio::io::duplex(64 * 1024);
        let dropped = Arc::new(AtomicBool::new(false));
        let session = Session::client(DropTrackedIo {
            inner: client_io,
            dropped: Arc::clone(&dropped),
        })
        .unwrap();
        drop(session);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping an idle session must stop its driver and release the fd");
    }
}
