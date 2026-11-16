//! `SocketIo` — a connected datagram endpoint shared by every QUIC/UDP
//! transport in meow-rs.
//!
//! Gated by the `datagram` feature: `kcptun` (the `kcptun` feature) and the
//! QUIC client drivers `hysteria2` / `trusttunnel-h3` in `meow-proxy` all
//! consume the same `poll_send`/`poll_recv` surface, so the trait lives
//! beside the transports rather than inside any one of them.

use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

/// A connected datagram endpoint: `poll_send`/`poll_recv` exchange datagrams
/// with one fixed peer, mirroring `UdpSocket`'s connected-mode surface.
///
/// `UdpSocket` itself covers the direct path; proxy-tunneled endpoints
/// (`dialer-proxy` chains, where a raw UDP socket would leak the real source
/// path) implement this over `ProxyPacketConn` inside `meow-proxy` — the
/// transport crate stays free of proxy-layer types.
pub trait SocketIo: Send + Sync {
    /// `UdpSocket::poll_send` semantics: one call = one datagram.
    fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>;
    /// `UdpSocket::poll_recv` semantics: fills `buf` with one datagram.
    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>;
    /// Upstream `SetReadBuffer`/`SetWriteBuffer`/`SetDSCP`. A no-op default —
    /// tunneled endpoints have no kernel socket to tune. `dscp` is the raw
    /// TOS byte value, matching kcp-go's `SetTOS` verbatim.
    fn apply_socket_options(&self, _sock_buf: usize, _dscp: u8) {}
    /// The local address quiche should record as this path's `to`, if the
    /// endpoint knows one. `None` — the default — means "no real socket
    /// address": the caller falls back to an unspecified placeholder of the
    /// peer's family (a bound proxy association owns no local tuple the
    /// peer could dial back to anyway). A raw `UdpSocket` reports its real
    /// `local_addr`.
    fn local_addr_hint(&self) -> Option<SocketAddr> {
        None
    }
    /// The largest UDP payload this path should carry, if the endpoint
    /// knows one. `None` — the default — leaves the caller's own ceiling
    /// in place: a raw `UdpSocket` relies on PMTUD to discover the path's.
    /// A tunneled endpoint reports a conservative cap when its per-packet
    /// encapsulation makes the stock ceiling unsafe (a ~1452-byte QUIC
    /// datagram plus a front proxy's header/AEAD overhead fragments at a
    /// 1500 path MTU, and a lost fragment kills the whole datagram).
    fn mtu_hint(&self) -> Option<usize> {
        None
    }
}

/// One non-blocking `poll_recv` for the drain pass that follows an
/// awaited read — `Ok(None)` on `Pending` ends the batch.
///
/// Waker contract: this polls once under a noop waker, so the poll
/// registers no wakeup of its own. That is only sound where the
/// enclosing select's next wakeup re-polls `poll_recv` with the real
/// task waker, and only for an endpoint that re-checks its queue before
/// answering `Pending` — a channel-backed endpoint's `Pending` already
/// means "empty at poll time", so nothing can be lost between the two
/// polls. The hysteria2 and trusttunnel-h3 drivers both meet this: the
/// drain pass runs inside the same select loop as the awaited read.
pub fn try_poll_recv_once<I: SocketIo + ?Sized>(
    io: &mut I,
    buf: &mut [u8],
) -> io::Result<Option<usize>> {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut rb = ReadBuf::new(buf);
    match io.poll_recv(&mut cx, &mut rb) {
        Poll::Ready(Ok(())) => Ok(Some(rb.filled().len())),
        Poll::Ready(Err(e)) => Err(e),
        Poll::Pending => Ok(None),
    }
}

impl SocketIo for UdpSocket {
    fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send(self, cx, buf)
    }
    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        UdpSocket::poll_recv(self, cx, buf)
    }
    fn apply_socket_options(&self, sock_buf: usize, dscp: u8) {
        let sock = socket2::SockRef::from(self);
        if sock_buf > 0 {
            let _ = sock.set_recv_buffer_size(sock_buf);
            let _ = sock.set_send_buffer_size(sock_buf);
        }
        if dscp > 0 {
            // Upstream `UDPSession.SetDSCP`: IPv4 carries the 6-bit DSCP
            // field inside the TOS byte (`dscp << 2` | ECN); IPv6 sets the
            // traffic class raw. `& 0xff` mirrors the kernel's u8 TOS store
            // for a >63 value.
            let _ = sock.set_tos(((dscp as u32) << 2) & 0xff);
            // socket2 only has `set_tclass_v6` on the targets listed here
            // (not on Windows, iOS or tvOS); elsewhere the IPv6 DSCP is
            // simply not applied (best-effort like the rest). Keep the list
            // in step with socket2's own `cfg` on that method.
            #[cfg(any(
                target_os = "android",
                target_os = "cygwin",
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "fuchsia",
                target_os = "linux",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            let _ = sock.set_tclass_v6(dscp as u32);
        }
    }
    fn local_addr_hint(&self) -> Option<SocketAddr> {
        self.local_addr().ok()
    }
}
