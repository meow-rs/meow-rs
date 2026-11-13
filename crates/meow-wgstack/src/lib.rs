//! `meow-wgstack` — the smoltcp/tokio plumbing shared by the WireGuard
//! outbound pump (`meow-proxy::wireguard`) and the WireGuard inbound
//! listener (`meow-listener::wireguard`).
//!
//! Everything here is direction-agnostic: a channel-backed smoltcp
//! [`Device`] the owning actor drives, the per-conn [`WgStream`]
//! AsyncRead/AsyncWrite shim with its backpressure machinery, the queue
//! and buffer constants both sides must agree on, and the endpoint
//! `SO_RCVBUF` enlarger. The boringtun `Tunn` is deliberately *not* here —
//! each actor owns its own session(s).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use meow_common::ProxyConn;
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// actor→conn stream events per TCP flow (≈32 × 16 KiB ≈ 512 KiB of read
/// backpressure per flow — deeper than the smoltcp socket window so the
/// relay read side, not the channel, is the stall point).
pub const TCP_READ_QUEUE: usize = 32;
/// conn→actor write items per TCP flow.
pub const TCP_WRITE_QUEUE: usize = 64;

/// Per-socket smoltcp buffers (rx and tx). The rx half doubles as the
/// advertised TCP window — smoltcp negotiates RFC 7323 window scaling in
/// SYN (`remote_win_shift = bit_width(capacity) - 16` = 19 - 16 = 3), so
/// per-flow
/// throughput caps at `TCP_SOCKET_BUF / RTT`: 64 KiB held a 140 ms-RTT
/// path to ~0.5 MB/s (measured on a real KR↔US peer), 256 KiB lifts the
/// cap to ~1.8 MB/s. Peers that don't answer with `window_scale` fall
/// back to the 16-bit wire window (~64 KiB cap) silently. Cost:
/// 2 × 256 KiB eagerly allocated per WG TCP connection.
///
/// `pub`: the endpoint socket's kernel receive buffer is sized from this
/// — a full-window burst arrives as ~this many WG datagrams (see
/// [`enlarge_recv_buffer`]).
pub const TCP_SOCKET_BUF: usize = 256 * 1024;

/// Endpoint→Tunn drain bound per loop iteration; excess waits for the next
/// wake-up rather than starving the rest of the service pass.
pub const WIRE_DRAIN_BUDGET: usize = 64;

/// boringtun's own device loop ticks its timers at 250 ms (rekey timeout is
/// 5 s, jitter ≤ 333 ms — this is well inside slack). Spec §3.4 sketched
/// 100 ms without naming a constant; the upstream cadence is the better
/// choice for idle CPU.
pub const WG_TIMER_INTERVAL: Duration = Duration::from_millis(250);

/// A channel-backed smoltcp [`Device`]: packets `Tunn::decapsulate` yields
/// are pushed into `rx_queue` for `Interface` ingress; everything
/// `Interface` egresses lands in `tx_queue` for `Tunn::encapsulate`.
/// `rx_queue` entries are [`Bytes`] (refcounted, `Deref<[u8]>`) so an
/// owning producer can hand a packet over without a second copy.
/// `tx_pool` recycles the egress buffers — the owner returns each drained
/// `tx_queue` Vec to it instead of dropping it, so `SmolTxToken::consume`
/// reuses the allocation rather than paying a `vec![]` per packet.
pub struct ChannelDevice {
    pub rx_queue: VecDeque<Bytes>,
    pub tx_queue: VecDeque<Vec<u8>>,
    pub tx_pool: VecDeque<Vec<u8>>,
    caps: DeviceCapabilities,
}

impl ChannelDevice {
    pub fn new(mtu: usize) -> Self {
        // `DeviceCapabilities` is #[non_exhaustive] — mutate from default.
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        // The "wire" is the WG tunnel; an IP packet up to inner MTU
        // always fits one WG data message.
        caps.max_transmission_unit = mtu;
        caps.max_burst_size = None;
        // `Checksum::Tx` — software-compute on send only, skip receive
        // verification. RX verification is redundant here: inner packets
        // arrive in `rx_queue` only after ChaCha20-Poly1305 AEAD open, so
        // their integrity is cryptographically proven already. TX stays
        // on — the plaintext inner packet leaves this stack for a peer
        // kernel/gVisor stack that does validate the checksums.
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps.checksum.icmpv6 = Checksum::Tx;
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            tx_pool: VecDeque::new(),
            caps,
        }
    }
}

pub struct SmolRxToken {
    packet: Bytes,
}

impl RxToken for SmolRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub struct SmolTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    pool: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for SmolTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Recycle a drained tx buffer when one is pooled; the full
        // clear+resize keeps stale bytes out of the emitted packet.
        let mut buf = self.pool.pop_back().unwrap_or_default();
        buf.clear();
        buf.resize(len, 0);
        let out = f(&mut buf);
        self.queue.push_back(buf);
        out
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = SmolRxToken;
    type TxToken<'a> = SmolTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(|packet| {
            (
                SmolRxToken { packet },
                SmolTxToken {
                    queue: &mut self.tx_queue,
                    pool: &mut self.tx_pool,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(SmolTxToken {
            queue: &mut self.tx_queue,
            pool: &mut self.tx_pool,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

/// conn→actor TCP items.
#[derive(Debug)]
pub enum TcpIo {
    Data(Bytes),
    /// `poll_shutdown`: FIN after everything queued ahead of it.
    Shutdown,
    /// Conn dropped without shutdown: abort the socket.
    Close,
}

/// actor→conn TCP events. `Closed` is queued strictly after every `Data`
/// already delivered, preserving read order.
pub enum StreamEvent {
    Data(Bytes),
    /// Orderly EOF (peer FIN'd, or the conn vanished). Abrupt socket death
    /// surfaces instead as the channel dropping → same `Ok(0)` shape a
    /// torn-down stream gets everywhere else in the adapter surface.
    Closed,
}

/// Async stream shim for a smoltcp TCP socket. Writes go to the owning
/// actor on a per-conn channel (disconnect = conn dropped = abort); reads
/// arrive as ordered [`StreamEvent`]s.
pub struct WgStream {
    pub remote: String,
    pub rx: mpsc::Receiver<StreamEvent>,
    pub tx: mpsc::Sender<TcpIo>,
    /// Conn → actor work-available signal. `Notify` pulse-merges
    /// identical to the bounded mpsc it replaced: a nudge that finds
    /// no waiter stores a single permit, so a busy actor still wakes
    /// promptly on its next select — while N nudges collapse to one
    /// instead of queuing N unit items.
    pub wake: Arc<tokio::sync::Notify>,
    /// Actor → conn write-capacity wake-up (the actor's per-socket
    /// drain notification this stream parks on when the channel is full).
    pub drain_notify: Arc<tokio::sync::Notify>,
    pub pending_read: Option<Bytes>,
    /// A `TcpIo` item the shared path couldn't push yet — retried ahead of
    /// accepting new write bytes so ordering survives.
    pub pending_write: Option<TcpIo>,
    /// Terminal read state: the actor sent `Closed` (or the channel died).
    pub read_eof: bool,
    pub write_done: bool,
}

impl WgStream {
    /// Wake the actor so it services this flow's queues now rather than at
    /// the next timer tick. Also nudged on every read pop — that is what
    /// re-arms a full-channel read backlog in `pending_read`.
    fn nudge(&self) {
        self.wake.notify_one();
    }

    /// The two wake sources a full-channel park must wait on: the
    /// actor's drain notification *and* the channel's close. The
    /// second arm is what un-parks a writer whose flow died while it
    /// waited — a dropped `write_rx` never fires `drain_notify` again,
    /// and without it the route task would stay pinned forever (holding
    /// the stream and the remote conn). Polling both registers the
    /// waker with either.
    ///
    /// `Ready(true)` = retry the send; `Ready(false)` = channel gone.
    fn poll_write_wait(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        let mut notified = std::pin::pin!(self.drain_notify.notified());
        if notified.as_mut().poll(cx).is_ready() {
            return Poll::Ready(true);
        }
        let mut closed = std::pin::pin!(self.tx.closed());
        if closed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(false);
        }
        Poll::Pending
    }
}

impl Drop for WgStream {
    fn drop(&mut self) {
        if !self.write_done {
            let _ = self.tx.try_send(TcpIo::Close);
            self.nudge();
        }
    }
}

fn stream_broken() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "wireguard stream closed")
}

impl AsyncRead for WgStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }
        if let Some(b) = &mut self.pending_read {
            let n = b.len().min(buf.remaining());
            buf.put_slice(&b[..n]);
            b.advance(n);
            if b.is_empty() {
                self.pending_read = None;
            }
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(StreamEvent::Data(mut b))) => {
                self.nudge();
                let n = b.len().min(buf.remaining());
                buf.put_slice(&b[..n]);
                b.advance(n);
                if !b.is_empty() {
                    self.pending_read = Some(b);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(StreamEvent::Closed)) | Poll::Ready(None) => {
                self.read_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WgStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_done {
            return Poll::Ready(Err(stream_broken()));
        }
        loop {
            if self.pending_write.is_some() {
                let item = self.pending_write.take().expect("checked is_some above");
                match self.tx.try_send(item) {
                    Ok(()) => continue,
                    Err(mpsc::error::TrySendError::Full(item)) => {
                        self.pending_write = Some(item);
                        // Park on the actor's drain notification — or the
                        // channel's close (see `poll_write_wait`). `Notify`
                        // stores one permit, so a drain between try_send
                        // and this poll is not missed.
                        match self.poll_write_wait(cx) {
                            Poll::Ready(true) => continue,
                            Poll::Ready(false) => {
                                self.write_done = true;
                                return Poll::Ready(Err(stream_broken()));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.write_done = true;
                        return Poll::Ready(Err(stream_broken()));
                    }
                }
            }
            let n = buf.len();
            match self.tx.try_send(TcpIo::Data(Bytes::copy_from_slice(buf))) {
                Ok(()) => {
                    self.nudge();
                    return Poll::Ready(Ok(n));
                }
                Err(mpsc::error::TrySendError::Full(item)) => {
                    self.pending_write = Some(item);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.write_done = true;
                    return Poll::Ready(Err(stream_broken()));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // The actor applies items in order; there is no deeper flush point.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.write_done {
            return Poll::Ready(Ok(()));
        }
        // Same backpressure contract as `poll_write`: drain anything parked
        // there, then queue the FIN — a full channel parks on the actor's
        // drain notification instead of silently dropping `Shutdown`.
        loop {
            let item = self.pending_write.take().unwrap_or(TcpIo::Shutdown);
            let is_shutdown = matches!(item, TcpIo::Shutdown);
            match self.tx.try_send(item) {
                Ok(()) => {
                    if is_shutdown {
                        self.write_done = true;
                        self.nudge();
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(mpsc::error::TrySendError::Full(item)) => {
                    self.pending_write = Some(item);
                    match self.poll_write_wait(cx) {
                        Poll::Ready(true) => continue,
                        Poll::Ready(false) => {
                            self.write_done = true;
                            return Poll::Ready(Err(stream_broken()));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.write_done = true;
                    return Poll::Ready(Err(stream_broken()));
                }
            }
        }
    }
}

impl ProxyConn for WgStream {
    fn remote_destination(&self) -> String {
        self.remote.clone()
    }
}

/// One full-window inner-TCP burst lands on this socket as ~`TCP_SOCKET_BUF`
/// bytes of back-to-back WG datagrams (~280 KB at the current window —
/// over the 208 KiB Linux default, which would drop the tail of every
/// saturated burst and cost an inner-TCP retransmit round). 4× absorbs
/// bursts from a few saturated flows at once; the kernel commits pages
/// only on use, so asking is cheap.
const ENDPOINT_RECV_BUFFER: usize = 4 * TCP_SOCKET_BUF;

/// Grow the endpoint socket's `SO_RCVBUF`, best effort — the same
/// contract as the hysteria2 enlarger: never fatal, halve until the OS
/// accepts one, floor at a single-burst size. Anything the OS grants
/// above the unconfigured default is a win.
pub fn enlarge_recv_buffer(socket: &tokio::net::UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let mut size = ENDPOINT_RECV_BUFFER;
    while size >= TCP_SOCKET_BUF && sock.set_recv_buffer_size(size).is_err() {
        size /= 2;
    }
    // getsockopt reports twice the size taken on Linux.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if sock
        .recv_buffer_size()
        .is_ok_and(|got| got < 2 * ENDPOINT_RECV_BUFFER)
    {
        force_recv_buffer(socket);
    }
    tracing::debug!(size = ?sock.recv_buffer_size(), "wireguard endpoint receive buffer");
}

/// `SO_RCVBUFFORCE` needs `CAP_NET_ADMIN`, so it fails harmlessly (EPERM)
/// for an unprivileged meow.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn force_recv_buffer(socket: &tokio::net::UdpSocket) {
    use std::os::fd::AsRawFd;
    let size = ENDPOINT_RECV_BUFFER as libc::c_int;
    // SAFETY: the socket stays open for the call, and the option value is
    // a c_int of the size passed.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            std::ptr::addr_of!(size).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The device computes checksums on TX (the peer's kernel/gVisor
    /// stack validates them on the plaintext inner packet) but skips RX
    /// verification — every inner packet reached `rx_queue` through a
    /// ChaCha20-Poly1305 AEAD open, so its integrity is already proven
    /// and the software check is dead work.
    #[test]
    fn channel_device_caps_checksum_tx_only() {
        let d = ChannelDevice::new(1420);
        let caps = d.capabilities();
        for (name, cap) in [
            ("ipv4", caps.checksum.ipv4),
            ("udp", caps.checksum.udp),
            ("tcp", caps.checksum.tcp),
            ("icmpv4", caps.checksum.icmpv4),
            ("icmpv6", caps.checksum.icmpv6),
        ] {
            assert!(!cap.rx(), "{name} rx checksum verification must be off");
            assert!(cap.tx(), "{name} tx checksum computation must stay on");
        }
    }

    /// A drained `tx_queue` Vec returned to `tx_pool` is the buffer the
    /// next `consume` hands out — pointer identity proves the reuse and
    /// with it the skipped allocation.
    #[test]
    fn tx_pool_reuse_after_warmup() {
        let mut d = ChannelDevice::new(1420);
        let token = d.transmit(SmolInstant::ZERO).expect("transmit token");
        token.consume(100, |buf| buf[0] = 0xAB);
        let vec = d.tx_queue.pop_front().expect("emitted packet");
        let ptr = vec.as_ptr();
        d.tx_pool.push_back(vec);

        let token = d.transmit(SmolInstant::ZERO).expect("transmit token");
        token.consume(50, |buf| {
            assert_eq!(buf.as_ptr(), ptr, "pooled buffer must be reused");
        });
        assert_eq!(
            d.tx_queue.back().expect("emitted packet").len(),
            50,
            "reused buffer is resized to the new packet"
        );
    }

    /// A pooled buffer is fully zeroed on reuse — bytes from the
    /// previous packet must never leak into the next emission.
    #[test]
    fn tx_pool_buf_zeroed_on_reuse() {
        let mut d = ChannelDevice::new(1420);
        let token = d.transmit(SmolInstant::ZERO).expect("transmit token");
        token.consume(100, |buf| buf.iter_mut().for_each(|b| *b = 0xFF));
        let vec = d.tx_queue.pop_front().expect("emitted packet");
        d.tx_pool.push_back(vec);

        let token = d.transmit(SmolInstant::ZERO).expect("transmit token");
        token.consume(50, |buf| {
            assert!(
                buf.iter().all(|&b| b == 0),
                "reused buffer must be fully zeroed"
            );
        });
    }
}
