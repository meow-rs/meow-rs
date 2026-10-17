use super::{http2::H2Stream, Lease};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// One CONNECT stream, as the transport that carries it sees it.
///
/// Dropping either variant resets the stream, which is how a refused CONNECT
/// (a non-200 response) is cancelled: [`super::Client::open`] drops the
/// stream and reports the status.
pub enum StreamKind {
    H2(H2Stream),
    #[cfg(feature = "trusttunnel-h3")]
    H3(super::http3::H3Stream),
}

macro_rules! dispatch {
    ($self:expr, $stream:ident => $body:expr) => {
        match $self {
            StreamKind::H2($stream) => $body,
            #[cfg(feature = "trusttunnel-h3")]
            StreamKind::H3($stream) => $body,
        }
    };
}

impl AsyncRead for StreamKind {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        dispatch!(self.get_mut(), stream => Pin::new(stream).poll_read(cx, buf))
    }
}

impl AsyncWrite for StreamKind {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        dispatch!(self.get_mut(), stream => Pin::new(stream).poll_write(cx, data))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        dispatch!(self.get_mut(), stream => Pin::new(stream).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        dispatch!(self.get_mut(), stream => Pin::new(stream).poll_shutdown(cx))
    }
}

/// A proxied stream, holding its connection's pool slot for its lifetime.
pub struct TunnelStream {
    backend: StreamKind,
    _lease: Lease,
}

impl TunnelStream {
    pub(crate) fn new(backend: StreamKind, lease: Lease) -> Self {
        Self {
            backend,
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
