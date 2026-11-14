use crate::error::Result;
use bytes::Bytes;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// An owned-`Bytes` write path for a connection whose downstream carries
/// `Bytes` buffers end to end — the channel-backed userspace streams
/// (WireGuard's `WgStream`) whose actor hands each item to a smoltcp
/// socket. The relay prefers this over `AsyncWrite::poll_write` when the
/// writer exposes it: the relay's frozen `BytesMut` region moves into the
/// conn with no `copy_from_slice`. A capability interface in the spirit
/// of [`ProxyConn::tcp_stream`]: implemented only where the path is
/// genuinely zero-copy; everything else keeps the `poll_write` slice.
///
/// The `Option` slot is the *caller's* staging area, and the contract
/// keeps the caller able to re-drive the poll: on `Poll::Ready(Ok)` the
/// slot is `None` — the conn took the bytes (or an earlier poll already
/// had them in flight); on `Poll::Pending` the slot stays `Some` — the
/// conn accepted nothing, so the caller re-presents the same slot on the
/// next poll. Ordering is the conn's: anything already stashed inside it
/// (a prior `poll_write`'s parked item) drains ahead of the slot's bytes.
pub trait WriteBytes: Unpin {
    fn poll_write_bytes(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut Option<Bytes>,
    ) -> Poll<std::io::Result<()>>;
}

pub trait ProxyConn: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    fn remote_destination(&self) -> String {
        String::new()
    }

    /// The kernel TCP socket this connection reads and writes byte for
    /// byte, if there is one. The relay then moves bulk traffic with
    /// `splice(2)` instead of copying it through userspace, so a wrapper
    /// that frames, encrypts, buffers or counts bytes must keep the
    /// default `None`.
    fn tcp_stream(&self) -> Option<&tokio::net::TcpStream> {
        None
    }

    /// The owned-`Bytes` write path of this connection, if it has one —
    /// the write-side counterpart of [`Self::tcp_stream`]. Writers that
    /// must copy a `&[u8]` into their own framing anyway keep the default
    /// `None`; the relay then stays on `poll_write`.
    fn write_bytes(&mut self) -> Option<&mut dyn WriteBytes> {
        None
    }
}

// Blanket impl for TcpStream etc.
impl ProxyConn for tokio::net::TcpStream {
    fn tcp_stream(&self) -> Option<&tokio::net::TcpStream> {
        Some(self)
    }
}

// Impl for Box<dyn ProxyConn>
impl<T: ProxyConn + ?Sized> ProxyConn for Box<T> {
    fn tcp_stream(&self) -> Option<&tokio::net::TcpStream> {
        (**self).tcp_stream()
    }

    fn write_bytes(&mut self) -> Option<&mut dyn WriteBytes> {
        (**self).write_bytes()
    }
}

#[async_trait::async_trait]
pub trait ProxyPacketConn: Send + Sync {
    /// Per-packet conns return the real wire source; bound conns may
    /// report the bound remote or an unspecified address when the
    /// underlying transport carries no source information. Consumers
    /// filtering on the source must skip the check for unspecified
    /// addresses or they would wedge bound conns.
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize>;
    fn local_addr(&self) -> Result<SocketAddr>;
    fn close(&self) -> Result<()>;
}

pub struct UdpPacket {
    pub data: Bytes,
    pub addr: SocketAddr,
}
