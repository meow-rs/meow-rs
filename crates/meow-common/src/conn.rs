use crate::error::Result;
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// An owned-buffer write path for a connection whose downstream carries
/// `Bytes` buffers end to end — the channel-backed userspace streams
/// (WireGuard's `WgStream`) whose actor hands each item to a smoltcp
/// socket, and frame-multiplexed writers (AnyTLS) whose 7-byte frame
/// header can overlay reserved headroom in place. The relay prefers this
/// over `AsyncWrite::poll_write` when the writer exposes it: the relay's
/// `BytesMut` region moves into the conn with no `copy_from_slice`. A
/// capability interface in the spirit of [`ProxyConn::tcp_stream`]:
/// implemented only where the path is genuinely zero-copy; everything
/// else keeps the `poll_write` slice.
///
/// The `Option` slot is the *caller's* staging area, and the contract
/// keeps the caller able to re-drive the poll: on `Poll::Pending` the
/// slot stays `Some` untouched — the conn accepted nothing, so the
/// caller re-presents the same slot on the next poll. On
/// `Poll::Ready(Ok)` the conn accepted the drained prefix: the slot is
/// `None` when everything moved, or still `Some` — holding the
/// unaccepted remainder, still led by the reserved headroom — when only
/// part did, and the caller re-presents it the same way (progress is
/// the slot's shrinkage). Ordering is the conn's: anything already
/// stashed inside it (a prior `poll_write`'s parked item) drains ahead
/// of the slot's bytes.
///
/// The slot is `BytesMut` (not `Bytes`) so a writer with
/// [`want_write_headroom`](Self::want_write_headroom) `> 0` can write its
/// framing into the prefix the caller reserved: callers presenting a
/// slot to such a writer MUST begin it with that many bytes — the writer
/// treats the region as its own scratch (AnyTLS overlays the frame
/// header there, turning one relay fill into one contiguous wire frame).
/// A writer reporting `0` receives payload from byte 0, as before.
pub trait WriteBytes: Unpin {
    fn poll_write_bytes(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut Option<BytesMut>,
    ) -> Poll<std::io::Result<()>>;

    /// Byte count the caller must reserve at the front of each
    /// `poll_write_bytes` slot for this writer's own framing. `0` (the
    /// default) means the writer takes payload-only buffers; writers that
    /// cannot use headroom (e.g. `WgStream`, which ships bytes to a
    /// channel) keep it explicitly.
    fn want_write_headroom(&self) -> usize {
        0
    }
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

    /// This conn's synchronous-poll view, if it has one — a capability
    /// interface in the spirit of [`ProxyConn::tcp_stream`]: `Some` only
    /// where every hop between buffer and wire completes inside one
    /// nonblocking call (a raw kernel datagram socket plus synchronous
    /// crypto), so a caller driving a poll loop can skip the
    /// task-and-channel bridge the async surface needs. Everything
    /// async — stream-framed fronts, SOCKS5-UoT, VLESS, mux — keeps
    /// `None`.
    ///
    /// `self: Arc<Self>` because the handle lives beside the conn (a
    /// socket wrapper holds both trait objects on the same allocation)
    /// and detection happens once, not per datagram.
    fn poll_packet_conn(self: Arc<Self>) -> Option<Arc<dyn PollPacketConn>> {
        let _ = self;
        None
    }
}

/// The synchronous-poll counterpart of [`ProxyPacketConn`], obtained
/// through [`ProxyPacketConn::poll_packet_conn`]. Same semantics per
/// direction with `Poll` added: `Ready(Ok)` means the datagram moved —
/// a read impl keeps polling through whatever per-datagram drops its
/// protocol layer filters out, so `Ready` always carries a real
/// datagram (or the truncation the underlying socket applied) —
/// `Pending` means the underlying socket is not ready and the caller
/// decides whether to park the waker or fall back to its own queueing,
/// and `Ready(Err)` is terminal — the association is dead.
///
/// Two structural contracts the async surface does not have:
///
/// - A poll impl must do its whole work inline: protocol-layer retries
///   (decrypt failures, foreign replies) loop inside one call, never
///   yield a `Pending` that is not the socket's own not-ready.
/// - The conn may only ever have **one registered waker per direction**.
///   A parked async `read_packet`/`write_packet` future and a `poll_*`
///   call register on the same kernel socket and steal each other's
///   readiness — callers must serialize so each direction is driven by
///   exactly one waiter at a time (the `PacketConnSocket` bridge
///   enforces this: reads are all-pump or all-poll, and a poll send only
///   runs while no pumped write is in flight).
pub trait PollPacketConn: ProxyPacketConn {
    /// The poll counterpart of [`ProxyPacketConn::read_packet`].
    fn poll_read_packet(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, SocketAddr)>>;

    /// The poll counterpart of [`ProxyPacketConn::write_packet`].
    fn poll_write_packet(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &SocketAddr,
    ) -> Poll<Result<usize>>;
}

pub struct UdpPacket {
    pub data: Bytes,
    pub addr: SocketAddr,
}
