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
//! Half-close is preserved: `poll_shutdown` only closes the caller's write
//! direction — the read side keeps delivering upstream data until the peer
//! ends it or the stream is dropped.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::task::AbortHandle;

/// A `DuplexStream` endpoint plus the `AbortHandle`s of the tasks serving it.
pub(crate) struct TaskedDuplex {
    inner: DuplexStream,
    tasks: Box<[AbortHandle]>,
}

impl TaskedDuplex {
    pub fn new(inner: DuplexStream, tasks: impl IntoIterator<Item = AbortHandle>) -> Self {
        Self {
            inner,
            tasks: tasks.into_iter().collect(),
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
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for TaskedDuplex {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
