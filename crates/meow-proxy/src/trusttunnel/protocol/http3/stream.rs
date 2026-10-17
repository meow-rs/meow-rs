//! `H3Stream`: an `AsyncRead`/`AsyncWrite` view of one CONNECT stream,
//! bridged to the quiche driver over channels. Reads pull payload from a
//! per-stream channel the driver fills; writes become `Cmd::Write`, with a
//! byte budget released only once QUIC has accepted the bytes — so a slow
//! path backpressures the caller instead of growing a queue.

use super::driver::{Cmd, ReadItem};
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, Notify, Semaphore},
};
use tokio_util::sync::{PollSemaphore, PollSender};

pub(super) const WRITE_BUFFER_BYTES: u32 = 64 * 1024;
const WRITE_CHUNK_BYTES: usize = 16 * 1024;

pub struct H3Stream {
    id: u64,
    read_rx: mpsc::Receiver<ReadItem>,
    read_notify: Arc<Notify>,
    writer: PollSender<Cmd>,
    write_capacity: PollSemaphore,
    pending: Vec<u8>,
    pending_at: usize,
    read_done: bool,
    shutdown_sent: bool,
    shutdown: Arc<AtomicBool>,
}

impl H3Stream {
    pub(super) fn new(
        id: u64,
        read_rx: mpsc::Receiver<ReadItem>,
        read_notify: Arc<Notify>,
        cmd_tx: mpsc::Sender<Cmd>,
        capacity: Arc<Semaphore>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            id,
            read_rx,
            read_notify,
            writer: PollSender::new(cmd_tx),
            write_capacity: PollSemaphore::new(capacity),
            pending: Vec::new(),
            pending_at: 0,
            read_done: false,
            shutdown_sent: false,
            shutdown,
        }
    }

    fn drain(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.pending_at >= self.pending.len() {
            return false;
        }
        let available = &self.pending[self.pending_at..];
        let n = available.len().min(buf.remaining());
        buf.put_slice(&available[..n]);
        self.pending_at += n;
        true
    }
}

impl AsyncRead for H3Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.drain(buf) {
            return Poll::Ready(Ok(()));
        }
        if this.read_done {
            return Poll::Ready(Ok(()));
        }
        match this.read_rx.poll_recv(cx) {
            Poll::Ready(Some(ReadItem::Data(data))) => {
                this.pending = data;
                this.pending_at = 0;
                // Free the driver to read more into this stream's channel.
                this.read_notify.notify_one();
                this.drain(buf);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(ReadItem::Eof)) => {
                this.read_done = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(ReadItem::Err(kind))) => {
                this.read_done = true;
                Poll::Ready(Err(io::Error::new(kind, "TrustTunnel H3 stream failed")))
            }
            Poll::Ready(None) => {
                this.read_done = true;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "TrustTunnel H3 connection closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H3Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(WRITE_CHUNK_BYTES);
        let permit = match this.write_capacity.poll_acquire_many(cx, n as u32) {
            Poll::Ready(Some(permit)) => permit,
            Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => return Poll::Pending,
        };
        match this.writer.poll_reserve(cx) {
            Poll::Ready(Ok(())) => this
                .writer
                .send_item(Cmd::Write {
                    id: this.id,
                    data: buf[..n].to_vec(),
                    permit,
                })
                .map_or_else(
                    |_| Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    |()| Poll::Ready(Ok(n)),
                ),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Every permit being free means every prior write has entered QUIC's
        // own bounded send buffer. Acquiring them registers our waker too.
        match self
            .get_mut()
            .write_capacity
            .poll_acquire_many(cx, WRITE_BUFFER_BYTES)
        {
            Poll::Ready(Some(_permit)) => Poll::Ready(Ok(())),
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self;
        if this.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(this.as_mut().poll_flush(cx))?;
        let this = this.get_mut();
        this.shutdown.store(true, Ordering::Release);
        this.shutdown_sent = true;
        // The FIN is the driver's to send; a flag plus a wake-up works even
        // when the command channel is full.
        this.read_notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for H3Stream {
    fn drop(&mut self) {
        // Cancellation must work even if the command channel is full.
        self.read_rx.close();
        self.read_notify.notify_one();
    }
}

impl Unpin for H3Stream {}
