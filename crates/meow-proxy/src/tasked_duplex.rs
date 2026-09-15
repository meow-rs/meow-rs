//! A [`DuplexStream`] endpoint that owns the background tasks relaying
//! between it and the real transport (issue #514).
//!
//! The VMess/VLESS record relays hand the caller a memory-duplex endpoint
//! while spawned tasks shuttle encrypted bytes on the underlying transport.
//! Dropping the endpoint alone cannot unblock a read parked on a silent
//! upstream — no data, FIN, or RST ever arrives — so the task (and the
//! transport it pins) used to leak for the process lifetime. Holding the
//! tasks' `AbortHandle`s here makes drop the bounded cleanup path: dropping
//! this stream aborts both halves and releases the transport promptly.
//!
//! Half-close is preserved: `poll_shutdown` closes the caller's write
//! direction — the read side keeps delivering upstream data until the peer
//! ends it or the stream is dropped. Shutdown is *graceful*: before
//! returning `Ready` it waits for the write-side relay task to drain the
//! bytes already accepted into the duplex buffer onto the transport and to
//! shut the transport's write half down. Without that wait, a
//! write→shutdown→drop sequence aborts the writer mid-drain and silently
//! drops accepted payload (issue #514 review follow-up). The wait is
//! bounded by [`SHUTDOWN_DRAIN_TIMEOUT`]: a wedged transport that can no
//! longer accept bytes must not pin the connection open forever, which is
//! the same bounded-teardown contract the abort-on-drop path provides.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::task::{AbortHandle, JoinHandle};

/// Upper bound on how long `poll_shutdown` waits for the write-side relay
/// task to flush buffered plaintext onto the transport. Live transports
/// drain in milliseconds; this only bounds wedged ones (full send buffer
/// on a dead peer), after which the task is aborted and shutdown reports
/// an error — accepted bytes were dropped mid-drain, so `Ok(())` would
/// claim a clean shutdown that did not happen. The bound is additive with
/// the relay's half-close linger — a wedged transport with a dead peer
/// tears down in at most drain-timeout + linger — never unbounded.
/// Note the error is best-effort through the tunnel relay: if the other
/// direction already finished, its earlier-armed linger may reap the
/// relay first and the caller sees `Ok` — teardown is bounded either way.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// A `DuplexStream` endpoint plus handles to the two tasks serving it.
///
/// Ownership is explicit rather than a bag of `AbortHandle`s: the
/// read-side task is owned by the protocol supervisor (which decides
/// whether its exit was a clean half-close or a fatal end and stops the
/// write side accordingly) — we hold only its `AbortHandle` so `Drop`
/// can still kill it. The write-side task is owned by us: its
/// `JoinHandle` is what `poll_shutdown` waits on for the graceful drain,
/// and its `AbortHandle` is derived here so no call site can forget it.
pub(crate) struct TaskedDuplex {
    inner: DuplexStream,
    /// Aborts the read-side relay task on drop.
    read_abort: AbortHandle,
    /// Resolves when the write-side relay task exits — i.e. all buffered
    /// plaintext has been framed/encrypted onto the transport and the
    /// transport's write half was shut down. `None` once shutdown has
    /// observed it.
    write_done: Option<JoinHandle<()>>,
    /// Abort handle for that same write task — fired when the drain wait
    /// times out so a wedged transport is released instead of pinning it,
    /// and on drop.
    write_abort: AbortHandle,
    /// Lazily armed on the first pending drain poll.
    drain_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl TaskedDuplex {
    /// `read_abort` aborts the read-side relay task (owned by the
    /// supervisor); `write_task` is the write-side relay task we wait on
    /// during graceful shutdown.
    pub fn new(inner: DuplexStream, read_abort: AbortHandle, write_task: JoinHandle<()>) -> Self {
        let write_abort = write_task.abort_handle();
        Self {
            inner,
            read_abort,
            write_done: Some(write_task),
            write_abort,
            drain_deadline: None,
        }
    }
}

impl AsyncRead for TaskedDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TaskedDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        // Graceful close: surface Ready only once the write-side task has
        // drained the duplex buffer onto the transport and shut the
        // transport down. A join error (aborted write task — e.g. a fatal
        // read-side failure — or a panic) also ends the wait, but reports
        // failure: accepted bytes were dropped, so `Ok(())` would claim a
        // clean shutdown that did not happen.
        if let Some(handle) = self.write_done.as_mut() {
            match Pin::new(handle).poll(cx) {
                Poll::Pending => {
                    let deadline = self.drain_deadline.get_or_insert_with(|| {
                        Box::pin(tokio::time::sleep(SHUTDOWN_DRAIN_TIMEOUT))
                    });
                    if deadline.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    // Wedged transport: release it so the connection tears
                    // down inside the same bound the abort-on-drop path
                    // provides — but the shutdown failed, say so.
                    self.write_abort.abort();
                    self.write_done = None;
                    tracing::warn!(
                        "tasked duplex: write drain timed out after {SHUTDOWN_DRAIN_TIMEOUT:?}; \
                         accepted payload dropped"
                    );
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "tasked duplex: write drain timed out",
                    )));
                }
                Poll::Ready(Err(e)) => {
                    // The writer died before draining (panic, or aborted by
                    // the supervisor after a fatal read-side failure).
                    if e.is_panic() {
                        tracing::warn!("tasked duplex write task panicked: {e}");
                    }
                    self.write_done = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "tasked duplex: write task ended before drain completed",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    self.write_done = None;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for TaskedDuplex {
    fn drop(&mut self) {
        self.read_abort.abort();
        self.write_abort.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Mirrors the real relay shape: one task pumping each direction
    /// between the memory duplex and the transport.
    fn spawn_pair(transport: DuplexStream) -> (TaskedDuplex, JoinHandle<bool>) {
        let (client, proxy) = tokio::io::duplex(4096);
        let (mut rd, mut wr) = tokio::io::split(transport);
        let (mut proxy_rd, mut proxy_wr) = tokio::io::split(proxy);
        let read_task = tokio::spawn(async move {
            // Clean EOF at the end, like the protocol read loops.
            tokio::io::copy(&mut rd, &mut proxy_wr).await.is_ok()
        });
        let write_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut proxy_rd, &mut wr).await;
            let _ = wr.shutdown().await;
        });
        let read_abort = read_task.abort_handle();
        (TaskedDuplex::new(client, read_abort, write_task), read_task)
    }

    /// Regression for the #514 review follow-up: `shutdown()` must wait for
    /// the write-side task to flush bytes already accepted into the duplex
    /// buffer onto the transport. Before the fix, write→shutdown→drop
    /// aborted the writer mid-drain and the peer saw zero bytes.
    #[tokio::test]
    async fn shutdown_drains_accepted_bytes_before_completing() {
        let (transport, mut peer) = tokio::io::duplex(4096);
        let (client, proxy) = tokio::io::duplex(4096);
        let (_rd, mut wr) = tokio::io::split(transport);
        let (mut proxy_rd, _proxy_wr) = tokio::io::split(proxy);
        let write_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut proxy_rd, &mut wr).await;
            let _ = wr.shutdown().await;
        });
        // No read pump in this scenario — a parked task stands in for it.
        let read_stub = tokio::spawn(std::future::pending::<()>());
        let mut conn = TaskedDuplex::new(client, read_stub.abort_handle(), write_task);

        conn.write_all(b"accepted payload").await.unwrap();
        // Must not return until the writer pushed the bytes to the wire.
        conn.shutdown().await.unwrap();
        drop(conn);

        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"accepted payload");
    }

    /// A write task that never drains (wedged transport) must not hang
    /// `shutdown()` forever — after [`SHUTDOWN_DRAIN_TIMEOUT`] the writer
    /// is aborted and shutdown reports failure: accepted bytes were
    /// dropped, so `Ok(())` would lie.
    #[tokio::test(start_paused = true)]
    async fn shutdown_times_out_and_reports_error_when_writer_wedged() {
        let (client, _proxy) = tokio::io::duplex(4096);
        let wedged_writer = tokio::spawn(std::future::pending::<()>());
        let read_stub = tokio::spawn(std::future::pending::<()>());
        let mut conn = TaskedDuplex::new(client, read_stub.abort_handle(), wedged_writer);

        conn.write_all(b"never delivered").await.unwrap();
        let err = conn
            .shutdown()
            .await
            .expect_err("a wedged drain must not report a clean shutdown");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        // Idempotent: the write side IS shut down (aborted) — a second
        // call must not re-poll the spent JoinHandle or re-report.
        conn.shutdown().await.unwrap();
    }

    /// If the write task is already gone when shutdown is polled (aborted
    /// by the supervisor after a fatal read-side failure), the drain can
    /// never complete — report failure rather than Ok(()).
    #[tokio::test]
    async fn shutdown_reports_error_when_writer_already_aborted() {
        let (client, _proxy) = tokio::io::duplex(4096);
        let write_task = tokio::spawn(std::future::pending::<()>());
        let write_abort = write_task.abort_handle();
        let read_stub = tokio::spawn(std::future::pending::<()>());
        let mut conn = TaskedDuplex::new(client, read_stub.abort_handle(), write_task);
        write_abort.abort();

        let err = conn
            .shutdown()
            .await
            .expect_err("a dead writer cannot complete the drain");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// After a graceful shutdown the read direction still delivers data
    /// the peer sends afterwards — half-close download stays intact.
    #[tokio::test]
    async fn read_side_still_delivers_after_shutdown() {
        let (transport, mut peer) = tokio::io::duplex(4096);
        let (mut conn, read_task) = spawn_pair(transport);

        conn.write_all(b"upload").await.unwrap();
        conn.shutdown().await.unwrap();

        // Peer observes the upload then FIN.
        let mut got = [0u8; 6];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"upload");
        assert_eq!(peer.read(&mut [0u8; 1]).await.unwrap(), 0);

        // A late answer still flows through the read direction.
        peer.write_all(b"late reply").await.unwrap();
        let mut buf = [0u8; 10];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"late reply");
        drop(conn);
        let _ = read_task.await;
    }
}
