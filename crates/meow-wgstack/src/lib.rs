//! `meow-wgstack` — the smoltcp/tokio plumbing shared by the WireGuard
//! outbound pump (`meow-proxy::wireguard`) and the WireGuard inbound
//! listener (`meow-listener::wireguard`).
//!
//! Everything here is direction-agnostic: a channel-backed smoltcp
//! [`Device`] the owning actor drives, the per-conn [`WgStream`]
//! AsyncRead/AsyncWrite shim with its backpressure machinery, the queue
//! and buffer constants both sides must agree on, the endpoint
//! `SO_RCVBUF` enlarger, and the [`BatchEndpoint`] batch-syscall
//! socket wrapper. The boringtun `Tunn` is deliberately *not* here —
//! each actor owns its own session(s).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use meow_common::ProxyConn;
use smoltcp::iface::{Interface, PollResult, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{self, error::SendError, OwnedPermit};

mod endpoint;
pub use endpoint::BatchEndpoint;

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

/// Bound on [`Interface::poll`] iterations per service pass — see
/// [`poll_burst`]. A permanently-progressing pass (a saturated bulk flow
/// emits a segment every poll) must not livelock the owning actor out of
/// its drain/flush halves; a capped burst simply resumes next pass —
/// `poll_delay` reports `Now` while segments remain queued.
pub const POLL_BURST: usize = 64;

/// boringtun's own device loop ticks its timers at 250 ms (rekey timeout is
/// 5 s, jitter ≤ 333 ms — this is well inside slack). Spec §3.4 sketched
/// 100 ms without naming a constant; the upstream cadence is the better
/// choice for idle CPU.
pub const WG_TIMER_INTERVAL: Duration = Duration::from_millis(250);

/// Upper bound on `ChannelDevice::tx_pool` residency; buffers returned
/// past the cap free instead of pooling.
const TX_POOL_CAP: usize = 128;

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
    /// Return a drained `tx_queue` buffer to `tx_pool`. The pool is a
    /// peak-water recycler, so cap it — a one-off burst must not pin
    /// MTU-sized allocations for the process lifetime.
    pub fn return_tx_buf(&mut self, buf: Vec<u8>) {
        if self.tx_pool.len() < TX_POOL_CAP {
            self.tx_pool.push_back(buf);
        }
    }

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

/// Drive `Interface::poll` until it reports no progress or [`POLL_BURST`]
/// iterations have run. smoltcp 0.12's socket egress dispatched at most
/// one TCP segment per socket per `poll` call, so a single poll per
/// service pass capped a bulk flow at ~1 segment per inner-RTT wake — the
/// WG listener measured ~285 KB/s that way. smoltcp 0.13's `poll` now
/// exhausts socket egress internally (upstream #1059), which makes the
/// second iteration here the usual exit; the loop stays anyway as *our*
/// bounded-budget driver — `SocketStateChanged` is the only progress
/// signal the interface reports (a packet ingressed *or* egressed) and
/// `None` means every socket went quiet — send window full, Nagle-held
/// tail, timers idle — so the loop breaks there. The whole burst shares
/// one timestamp: it is one logical service pass.
///
/// One more 0.12→0.13 delta worth knowing while reading latency
/// profiles: `RTTE_MIN_RTO` went 10 ms → 1000 ms (the RFC 6298 floor),
/// so on a sub-millisecond inner link a retransmit tail now sits ~1 s
/// where it used to fire ~100× sooner — expected upstream behavior, not
/// a wedge.
pub fn poll_burst(
    iface: &mut Interface,
    now: SmolInstant,
    device: &mut ChannelDevice,
    sockets: &mut SocketSet<'_>,
) {
    for _ in 0..POLL_BURST {
        match iface.poll(now, device, sockets) {
            PollResult::SocketStateChanged => {}
            PollResult::None => break,
        }
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

/// Boxed `Sender::reserve_owned` future — the storable capacity wait
/// whose in-semaphore waker survives `Pending` polls (see
/// [`WgStream::write_reserve`]).
type ReserveFut =
    Pin<Box<dyn Future<Output = Result<OwnedPermit<TcpIo>, SendError<()>>> + Send + Sync>>;

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
    pub pending_read: Option<Bytes>,
    /// A `TcpIo` item the shared path couldn't push yet — retried ahead of
    /// accepting new write bytes so ordering survives.
    pub pending_write: Option<TcpIo>,
    /// In-flight channel-capacity reservation while the conn→actor queue
    /// is full. The future is *stored*, not dropped on `Pending`, so its
    /// waker stays registered in the mpsc semaphore — the wake arrives.
    pub write_reserve: Option<ReserveFut>,
    /// A capacity slot already won by [`WgStream::write_reserve`],
    /// consumed by the next send instead of competing for a fresh one.
    pub write_permit: Option<OwnedPermit<TcpIo>>,
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

    /// Wait for channel capacity — an mpsc semaphore reservation, not a
    /// `Notify`. A `Notified` future only holds its waiter registration
    /// while it is *alive*: the old `pin!(notified()).poll()` dropped
    /// the future on `Pending`, unregistering the waker, so an actor's
    /// `notify_one` that landed while the route task slept on another
    /// direction's park stored a permit nobody ever polled — the writer
    /// slept forever with a full upstream receive buffer (measured:
    /// 532 KB stranded mid-download). `reserve_owned` *kept in a field*
    /// survives `Pending`, so its waker stays inside the channel's
    /// semaphore where the actor's drain finds it, and it resolves
    /// `Err` on a closed channel — the dead-flow exit the `tx.closed()`
    /// arm used to provide.
    ///
    /// `Ready(true)` = retry the send (a slot is held in `write_permit`);
    /// `Ready(false)` = channel gone.
    fn poll_write_wait(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        if self.write_permit.is_some() {
            return Poll::Ready(true);
        }
        let fut = self
            .write_reserve
            .get_or_insert_with(|| Box::pin(self.tx.clone().reserve_owned()));
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                self.write_reserve = None;
                self.write_permit = Some(permit);
                Poll::Ready(true)
            }
            Poll::Ready(Err(_)) => {
                self.write_reserve = None;
                Poll::Ready(false)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Send `item`, consuming the reservation first if one is held —
    /// the slot a parked poll waited for, not a second one.
    fn send_item(&mut self, item: TcpIo) -> Result<(), mpsc::error::TrySendError<TcpIo>> {
        if let Some(permit) = self.write_permit.take() {
            permit.send(item);
            return Ok(());
        }
        let res = self.tx.try_send(item);
        if res.is_ok() {
            // A parked reservation may already have claimed a freed slot;
            // dropping it returns the permit to the pool instead of
            // pinning capacity until the next `Full`.
            self.write_reserve = None;
        }
        res
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
                match self.send_item(item) {
                    Ok(()) => {
                        // The stash *is* this call's bytes — a retry after
                        // `Pending` hands back the same `buf`, so flushing
                        // it completes the write. Falling through to
                        // `try_send(Data(buf))` here would put the payload
                        // on the wire twice.
                        self.nudge();
                        return Poll::Ready(Ok(buf.len()));
                    }
                    Err(mpsc::error::TrySendError::Full(item)) => {
                        self.pending_write = Some(item);
                        // Park on a channel reservation — not a Notify —
                        // so the waker survives a `Pending` poll (see
                        // `poll_write_wait`).
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
            match self.send_item(TcpIo::Data(Bytes::copy_from_slice(buf))) {
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
        // there, then queue the FIN — a full channel parks on the channel
        // reservation instead of silently dropping `Shutdown`.
        loop {
            let item = self.pending_write.take().unwrap_or(TcpIo::Shutdown);
            let is_shutdown = matches!(item, TcpIo::Shutdown);
            match self.send_item(item) {
                Ok(()) => {
                    // `poll_write` symmetry: every queued item is fresh
                    // conn→actor work — nudge per send, not only on the
                    // terminal FIN, or a flushed stash item waits out
                    // the 250 ms timer tick.
                    self.nudge();
                    if is_shutdown {
                        self.write_done = true;
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

/// The send side needs the same headroom as the receive side: a
/// [`poll_burst`] egress burst is handed to the kernel in one
/// [`WIRE_DRAIN_BUDGET`] batch (~`POLL_BURST` × ~1.5 KB ≈ 90 KB), and the
/// default send buffer is far smaller than that on some platforms —
/// macOS grants only `9216` bytes of `SO_SNDBUF` out of the box, so a
/// burst beyond ~6 datagrams dies on `ENOBUFS` *inside* `send_batch_to`
/// (a short count, not a `WouldBlock`) and the inner TCP sees the
/// dropped tail as a hole to retransmit. 4×[`TCP_SOCKET_BUF`] absorbs a
/// full-window burst from several saturated flows; the kernel commits
/// pages only on use.
pub fn enlarge_send_buffer(socket: &tokio::net::UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let mut size = ENDPOINT_RECV_BUFFER;
    while size >= TCP_SOCKET_BUF && sock.set_send_buffer_size(size).is_err() {
        size /= 2;
    }
    if size < TCP_SOCKET_BUF {
        // The halving ladder exhausted without a single success — the
        // socket keeps its platform default (9 KiB on macOS), which
        // drops a `poll_burst` egress tail on ENOBUFS. Loud, not the
        // quiet line a granted raise gets.
        tracing::warn!(
            "wireguard endpoint send buffer: SO_SNDBUF raise rejected at \
             every size down to {TCP_SOCKET_BUF} — burst egress may lose \
             tail datagrams to ENOBUFS"
        );
    }
    tracing::debug!(size = ?sock.send_buffer_size(), "wireguard endpoint send buffer");
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

    /// `tx_pool` residency is capped: past `TX_POOL_CAP` a returned
    /// buffer frees instead of pooling — a one-off burst must not pin
    /// MTU-sized allocations for the process lifetime.
    #[test]
    fn tx_pool_cap_evicts_past_bound() {
        let mut d = ChannelDevice::new(1420);
        for _ in 0..TX_POOL_CAP + 1 {
            d.return_tx_buf(Vec::with_capacity(1420));
        }
        assert_eq!(
            d.tx_pool.len(),
            TX_POOL_CAP,
            "the (cap + 1)-th return must not pool"
        );
    }
}
