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
/// success. The bound is additive with the relay's half-close linger —
/// a wedged transport with a dead peer tears down in at most
/// drain-timeout + linger — never unbounded.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// A `DuplexStream` endpoint plus the `AbortHandle`s of the tasks serving it.
pub(crate) struct TaskedDuplex {
    inner: DuplexStream,
    tasks: Box<[AbortHandle]>,
    /// Resolves when the write-side relay task exits — i.e. all buffered
    /// plaintext has been framed/encrypted onto the transport and the
    /// transport's write half was shut down. `None` once shutdown has
    /// observed it.
    write_done: Option<JoinHandle<()>>,
    /// Abort handle for that same write task — fired when the drain wait
    /// times out so a wedged transport is released instead of pinning it.
    write_abort: AbortHandle,
    /// Lazily armed on the first pending drain poll.
    drain_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl TaskedDuplex {
    pub fn new(
        inner: DuplexStream,
        tasks: impl IntoIterator<Item = AbortHandle>,
        write_task: JoinHandle<()>,
    ) -> Self {
        let write_abort = write_task.abort_handle();
        Self {
            inner,
            tasks: tasks.into_iter().collect(),
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
        // read-side failure — or a panic) also ends the wait: there is
        // nothing left to drain.
        if let Some(handle) = self.write_done.as_mut() {
            match Pin::new(handle).poll(cx) {
                Poll::Pending => {
                    let deadline = self.drain_deadline.get_or_insert_with(|| {
                        Box::pin(tokio::time::sleep(SHUTDOWN_DRAIN_TIMEOUT))
                    });
                    if deadline.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    // Wedged transport: release it and report success so the
                    // connection can tear down inside the same bound the
                    // abort-on-drop path provides.
                    self.write_abort.abort();
                }
                // A panic mid-drain loses buffered plaintext while the
                // caller sees Ok — keep it observable.
                Poll::Ready(Err(e)) if e.is_panic() => {
                    tracing::warn!("tasked duplex write task panicked: {e}");
                }
                Poll::Ready(_) => {}
            }
            self.write_done = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for TaskedDuplex {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        // `tasks` is expected to include the write task's handle, but the
        // struct does not enforce that — abort it here unconditionally so
        // a call site that forgot cannot leak the writer.
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
        let aborts = [read_task.abort_handle(), write_task.abort_handle()];
        (TaskedDuplex::new(client, aborts, write_task), read_task)
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
        let abort = write_task.abort_handle();
        let mut conn = TaskedDuplex::new(client, [abort], write_task);

        conn.write_all(b"accepted payload").await.unwrap();
        // Must not return until the writer pushed the bytes to the wire.
        conn.shutdown().await.unwrap();
        drop(conn);

        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"accepted payload");
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
