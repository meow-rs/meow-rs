use super::{h2_error, Lease};
use bytes::{Buf, Bytes};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    pending: Bytes,
    shutdown: bool,
}

impl H2Stream {
    pub(crate) fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream, shutdown: bool) -> Self {
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
        if this.send.capacity() == 0 {
            match this.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(0))) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(h2_error(error))),
                Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let n = this.send.capacity().min(buf.len()).min(16 * 1024);
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

pub struct TunnelStream {
    backend: H2Stream,
    _lease: Lease,
}

impl TunnelStream {
    pub(crate) fn new(
        send: h2::SendStream<Bytes>,
        recv: h2::RecvStream,
        lease: Lease,
        shutdown: bool,
    ) -> Self {
        Self {
            backend: H2Stream::new(send, recv, shutdown),
            _lease: lease,
        }
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().backend).poll_read(cx, out)
    }
}
impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().backend).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().backend).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().backend).poll_shutdown(cx)
    }
}
