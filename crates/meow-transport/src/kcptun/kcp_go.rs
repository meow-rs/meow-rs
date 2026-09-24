//! Vendored `kcp` crate (0.6.0, MIT — `zonyitoo/kcp`) reworked to
//! `xtaci/kcp-go` v5.6.72 semantics. The upstream Go rewrite changed
//! retransmission scheduling and `Input` post-processing relative to
//! classic ikcp — these deltas keep the wire behavior indistinguishable
//! from a real kcptun/kcp-go peer:
//!
//! - `input` flushes immediately when UNA slides or a fast-retransmit
//!   threshold trips (upstream `Input` → `flush(FULL)`), instead of
//!   waiting out the maintenance interval — the whole point of KCP.
//! - ACK-clock flush: `acklist >= mtu/24` (and `ack_nodelay`) emit an
//!   ACK-only datagram without waiting for the interval.
//! - Resend scheduling: `resendts = current + rto` (no `+rtomin`),
//!   linear `rto += rx_rto`/`rx_rto/2` backoff (classic ikcp doubles),
//!   the `0xFFFFFFFF` fastack sentinel (one fast retransmit per RTO),
//!   and early retransmit on any dup-ack with an empty new-data queue.
//! - FEC-recovered segments pass `regular=false` so they can't
//!   regress `rmt_wnd` or skew the RTT estimator (upstream
//!   `IKCP_PACKET_FEC`).
//! - Upstream `parse_ack` marks `acked` lazily (removal happens via
//!   `parse_una` on the next segment), the RFC-6298-variant RTT
//!   estimator, the stale-ACK filter in the ack flush, `Send` fragment
//!   cap 255, exact `rcv_wnd` (no 128 floor), and `mtu <= 24` bound.

use std::cmp;
use std::collections::VecDeque;
use std::error::Error as StdError;
use std::fmt::{self, Debug};
use std::io::{self, Cursor, ErrorKind, Write};

use bytes::{Buf, BufMut, BytesMut};
use tracing::{debug, trace};

/// KCP protocol errors
#[derive(Debug, thiserror::Error)]
pub enum KcpError {
    #[error("conv inconsistent, expected {0}, found {1}")]
    ConvInconsistent(u32, u32),
    #[error("invalid mtu {0}")]
    InvalidMtu(usize),
    #[error("invalid segment size {0}")]
    InvalidSegmentSize(usize),
    #[error("invalid mss {0}")]
    InvalidMss(usize),
    #[error("invalid segment data size, expected {0}, found {1}")]
    InvalidSegmentDataSize(usize, usize),
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("need to call update() once")]
    NeedUpdate,
    #[error("recv queue is empty")]
    RecvQueueEmpty,
    #[error("expecting fragment")]
    ExpectingFragment,
    #[error("command {0} is not supported")]
    UnsupportedCmd(u8),
    #[error("user's send buffer is too big")]
    UserBufTooBig,
    #[error("user's recv buffer is too small")]
    UserBufTooSmall,
    #[error("empty send buffer")]
    EmptySend,
}

fn make_io_error<T>(kind: ErrorKind, msg: T) -> io::Error
where
    T: Into<Box<dyn StdError + Send + Sync>>,
{
    io::Error::new(kind, msg)
}

impl From<KcpError> for io::Error {
    fn from(err: KcpError) -> io::Error {
        let kind = match err {
            KcpError::RecvQueueEmpty | KcpError::ExpectingFragment | KcpError::UserBufTooSmall => {
                ErrorKind::WouldBlock
            }
            KcpError::IoError(err) => return err,
            _ => ErrorKind::Other,
        };
        make_io_error(kind, err)
    }
}

pub type KcpResult<T> = Result<T, KcpError>;

const KCP_RTO_NDL: u32 = 30; // no delay min rto
const KCP_RTO_MIN: u32 = 100; // normal min rto
const KCP_RTO_DEF: u32 = 200;
const KCP_RTO_MAX: u32 = 60000;

const KCP_CMD_PUSH: u8 = 81; // cmd: push data
const KCP_CMD_ACK: u8 = 82; // cmd: ack
const KCP_CMD_WASK: u8 = 83; // cmd: window probe (ask)
const KCP_CMD_WINS: u8 = 84; // cmd: window size (tell)

const KCP_ASK_SEND: u32 = 1; // need to send IKCP_CMD_WASK
const KCP_ASK_TELL: u32 = 2; // need to send IKCP_CMD_WINS

const KCP_WND_SND: u32 = 32;
const KCP_WND_RCV: u32 = 32; // upstream IKCP_WND_RCV (also seeds rmt_wnd)

const KCP_MTU_DEF: usize = 1400;
// const KCP_ACK_FAST: u32 = 3;

const KCP_INTERVAL: u32 = 100;
/// KCP Header size
pub const KCP_OVERHEAD: usize = 24;
const KCP_DEADLINK: u32 = 20;

const KCP_THRESH_INIT: u32 = 2;
const KCP_THRESH_MIN: u32 = 2;

const KCP_PROBE_INIT: u32 = 500; // upstream IKCP_PROBE_INIT (ms)
const KCP_PROBE_LIMIT: u32 = 120000; // up to 120 secs to probe window

/// Upstream `FlushType` — `Input` picks ACKONLY for ack-clock/nodelay
/// flushes and FULL for UNA-slide/fast-retransmit/timer flushes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlushType {
    /// Emit only the ack backlog (plus window-probe bookkeeping —
    /// upstream's phases 2–4 are ungated); never transmits PUSH data.
    AckOnly,
    /// Full maintenance flush — everything AckOnly does plus the
    /// retransmission pass over `snd_buf`.
    Full,
}

/// Read `conv` from raw buffer
pub fn get_conv(mut buf: &[u8]) -> u32 {
    if buf.len() < KCP_OVERHEAD {
        return 0;
    }
    buf.get_u32_le()
}

/// Set `conv` to raw buffer
pub fn set_conv(mut buf: &mut [u8], conv: u32) {
    if buf.len() < KCP_OVERHEAD {
        return;
    }
    buf.put_u32_le(conv);
}

/// Get `sn` from raw buffer
pub fn get_sn(buf: &[u8]) -> u32 {
    if buf.len() < KCP_OVERHEAD {
        return 0;
    }
    (&buf[12..]).get_u32_le()
}

#[inline]
fn bound(lower: u32, v: u32, upper: u32) -> u32 {
    cmp::min(cmp::max(lower, v), upper)
}

#[inline]
fn timediff(later: u32, earlier: u32) -> i32 {
    // Go computes `(int32)(later - earlier)` — a wrapping u32
    // subtraction reinterpreted. `as i32 - as i32` panics in debug
    // builds on wire-controlled operands.
    later.wrapping_sub(earlier) as i32
}

#[derive(Default, Clone, Debug)]
struct KcpSegment {
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    resendts: u32,
    rto: u32,
    fastack: u32,
    xmit: u32,
    /// Upstream kcp-go `acked`: set by `parse_ack`, the segment stays in
    /// `snd_buf` until `parse_una` slides past it on a later datagram.
    acked: bool,
    data: BytesMut,
}

impl KcpSegment {
    fn new_with_data(data: BytesMut) -> Self {
        KcpSegment {
            conv: 0,
            cmd: 0,
            frg: 0,
            wnd: 0,
            ts: 0,
            sn: 0,
            una: 0,
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
            acked: false,
            data,
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        if buf.remaining_mut() < self.encoded_len() {
            panic!(
                "REMAIN {} encoded {} {:?}",
                buf.remaining_mut(),
                self.encoded_len(),
                self
            );
        }

        buf.put_u32_le(self.conv);
        buf.put_u8(self.cmd);
        buf.put_u8(self.frg);
        buf.put_u16_le(self.wnd);
        buf.put_u32_le(self.ts);
        buf.put_u32_le(self.sn);
        buf.put_u32_le(self.una);
        buf.put_u32_le(self.data.len() as u32);
        buf.put_slice(&self.data);
    }

    fn encoded_len(&self) -> usize {
        KCP_OVERHEAD + self.data.len()
    }
}

#[derive(Default)]
struct KcpOutput<O>(O);

impl<O: Write> Write for KcpOutput<O> {
    #[inline]
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        trace!("[RO] {} bytes", data.len());
        self.0.write(data)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// KCP control
///
/// `self.current` is only refreshed by [`Kcp::update`]: callers must
/// `update(now)` before `input`, `flush`, or `flush_ack` — otherwise
/// `ts`/`resendts` are stamped with a stale clock and the peer sees an
/// inflated RTT. `conn.rs` honors this on every call site.
pub struct Kcp<Output> {
    /// Conversation ID
    conv: u32,
    /// Maximum Transmission Unit
    mtu: usize,
    /// Maximum Segment Size
    mss: usize,
    /// Connection state
    state: i32,

    /// First unacknowledged packet
    snd_una: u32,
    /// Next packet
    snd_nxt: u32,
    /// Next packet to be received
    rcv_nxt: u32,

    /// Congestion window threshold
    ssthresh: u32,

    /// ACK receive variable RTT
    rx_rttval: i32,
    /// ACK receive static RTT
    rx_srtt: i32,
    /// Resend time (calculated by ACK delay time)
    rx_rto: u32,
    /// Minimal resend timeout
    rx_minrto: u32,

    /// Send window
    snd_wnd: u32,
    /// Receive window
    rcv_wnd: u32,
    /// Remote receive window
    rmt_wnd: u32,
    /// Congestion window
    cwnd: u32,
    /// Check window
    /// - IKCP_ASK_TELL, telling window size to remote
    /// - IKCP_ASK_SEND, ask remote for window size
    probe: u32,

    /// Last update time
    current: u32,
    /// Flush interval
    interval: u32,
    /// Next flush interval
    ts_flush: u32,

    /// Enable nodelay
    nodelay: bool,
    /// Updated has been called or not
    updated: bool,

    /// Next check window timestamp
    ts_probe: u32,
    /// Check window wait time
    probe_wait: u32,

    /// Maximum resend time
    dead_link: u32,
    /// Bytes accumulated for cwnd increment
    incr: u32,

    snd_queue: VecDeque<KcpSegment>,
    rcv_queue: VecDeque<KcpSegment>,
    snd_buf: VecDeque<KcpSegment>,
    rcv_buf: VecDeque<KcpSegment>,

    /// Pending ACK
    acklist: VecDeque<(u32, u32)>,
    buf: BytesMut,

    /// ACK number to trigger fast resend
    fastresend: u32,
    /// Disable congestion control
    nocwnd: bool,
    /// Enable stream mode
    stream: bool,

    /// Get conv from the next input call
    input_conv: bool,

    output: KcpOutput<Output>,
}

impl<Output> Debug for Kcp<Output> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kcp")
            .field("conv", &self.conv)
            .field("mtu", &self.mtu)
            .field("mss", &self.mss)
            .field("state", &self.state)
            .field("snd_una", &self.snd_una)
            .field("snd_nxt", &self.snd_nxt)
            .field("rcv_nxt", &self.rcv_nxt)
            .field("ssthresh", &self.ssthresh)
            .field("rx_rttval", &self.rx_rttval)
            .field("rx_srtt", &self.rx_srtt)
            .field("rx_rto", &self.rx_rto)
            .field("rx_minrto", &self.rx_minrto)
            .field("snd_wnd", &self.snd_wnd)
            .field("rcv_wnd", &self.rcv_wnd)
            .field("rmt_wnd", &self.rmt_wnd)
            .field("cwnd", &self.cwnd)
            .field("probe", &self.probe)
            .field("current", &self.current)
            .field("interval", &self.interval)
            .field("ts_flush", &self.ts_flush)
            .field("nodelay", &self.nodelay)
            .field("updated", &self.updated)
            .field("ts_probe", &self.ts_probe)
            .field("probe_wait", &self.probe_wait)
            .field("dead_link", &self.dead_link)
            .field("incr", &self.incr)
            .field("snd_queue.len", &self.snd_queue.len())
            .field("rcv_queue.len", &self.rcv_queue.len())
            .field("snd_buf.len", &self.snd_buf.len())
            .field("rcv_buf.len", &self.rcv_buf.len())
            .field("acklist.len", &self.acklist.len())
            .field("buf.len", &self.buf.len())
            .field("fastresend", &self.fastresend)
            .field("nocwnd", &self.nocwnd)
            .field("stream", &self.stream)
            .field("input_conv", &self.input_conv)
            .finish()
    }
}

impl<Output> Kcp<Output> {
    /// Creates a KCP control object, `conv` must be equal in both endpoints in one connection.
    /// `output` is the callback object for writing.
    ///
    /// `conv` represents conversation.
    pub fn new(conv: u32, output: Output) -> Self {
        Kcp::construct(conv, output, false)
    }

    /// Creates a KCP control object in stream mode, `conv` must be equal in both endpoints in one connection.
    /// `output` is the callback object for writing.
    ///
    /// `conv` represents conversation.
    pub fn new_stream(conv: u32, output: Output) -> Self {
        Kcp::construct(conv, output, true)
    }

    fn construct(conv: u32, output: Output, stream: bool) -> Self {
        Kcp {
            conv,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ts_probe: 0,
            probe_wait: 0,
            snd_wnd: KCP_WND_SND,
            rcv_wnd: KCP_WND_RCV,
            rmt_wnd: KCP_WND_RCV,
            cwnd: 0,
            incr: 0,
            probe: 0,
            mtu: KCP_MTU_DEF,
            mss: KCP_MTU_DEF - KCP_OVERHEAD,
            stream,

            buf: BytesMut::with_capacity((KCP_MTU_DEF + KCP_OVERHEAD) * 3),

            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),

            state: 0,

            acklist: VecDeque::new(),

            rx_srtt: 0,
            rx_rttval: 0,
            rx_rto: KCP_RTO_DEF,
            rx_minrto: KCP_RTO_MIN,

            current: 0,
            interval: KCP_INTERVAL,
            ts_flush: KCP_INTERVAL,
            nodelay: false,
            updated: false,
            ssthresh: KCP_THRESH_INIT,
            fastresend: 0,
            nocwnd: false,
            dead_link: KCP_DEADLINK,

            input_conv: false,
            output: KcpOutput(output),
        }
    }

    // move available data from rcv_buf -> rcv_queue
    pub fn move_buf(&mut self) {
        while !self.rcv_buf.is_empty() {
            let nrcv_que = self.rcv_queue.len();
            {
                let seg = self.rcv_buf.front().unwrap();
                if seg.sn == self.rcv_nxt && nrcv_que < self.rcv_wnd as usize {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                } else {
                    break;
                }
            }

            let seg = self.rcv_buf.pop_front().unwrap();
            self.rcv_queue.push_back(seg);
        }
    }

    /// Receive data from buffer
    pub fn recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        if self.rcv_queue.is_empty() {
            return Err(KcpError::RecvQueueEmpty);
        }

        let peeksize = self.peeksize()?;

        if peeksize > buf.len() {
            debug!("recv peeksize={} bufsize={} too small", peeksize, buf.len());
            return Err(KcpError::UserBufTooSmall);
        }

        let recover = self.rcv_queue.len() >= self.rcv_wnd as usize;

        // Merge fragment
        let mut cur = Cursor::new(buf);
        while let Some(seg) = self.rcv_queue.pop_front() {
            Write::write_all(&mut cur, &seg.data)?;

            trace!("recv sn={}", seg.sn);

            if seg.frg == 0 {
                break;
            }
        }
        // Internal invariant — `panic = "abort"` in release must never
        // depend on it.
        debug_assert_eq!(cur.position() as usize, peeksize);

        self.move_buf();

        // fast recover
        if self.rcv_queue.len() < self.rcv_wnd as usize && recover {
            // ready to send back IKCP_CMD_WINS in ikcp_flush
            // tell remote my window size
            self.probe |= KCP_ASK_TELL;
        }

        Ok(cur.position() as usize)
    }

    /// Check buffer size without actually consuming it
    pub fn peeksize(&self) -> KcpResult<usize> {
        match self.rcv_queue.front() {
            Some(segment) => {
                if segment.frg == 0 {
                    return Ok(segment.data.len());
                }

                // Deliberately stricter than upstream: Go's `seg.frg+1`
                // wraps to 0 at frg=255, skipping the guard and merging
                // a truncated message; we require the full 256 fragments
                // instead (unreachable from a `Send`-compliant peer —
                // the 255-fragment cap means legitimate `frg <= 254`).
                if self.rcv_queue.len() < segment.frg as usize + 1 {
                    return Err(KcpError::ExpectingFragment);
                }

                let mut len = 0;

                for segment in &self.rcv_queue {
                    len += segment.data.len();
                    if segment.frg == 0 {
                        break;
                    }
                }

                Ok(len)
            }
            None => Err(KcpError::RecvQueueEmpty),
        }
    }

    /// Send bytes into buffer
    pub fn send(&mut self, mut buf: &[u8]) -> KcpResult<usize> {
        let mut sent_size = 0;

        // Defensive: `set_mtu` keeps mss >= 1, but `send` must not panic if
        // a future construction path ever violates that (issue #621 audit).
        if self.mss == 0 {
            return Err(KcpError::InvalidMss(0));
        }

        // Upstream `Send` rejects an empty buffer outright.
        if buf.is_empty() {
            return Err(KcpError::EmptySend);
        }

        // append to previous segment in streaming mode (if possible)
        if self.stream {
            if let Some(old) = self.snd_queue.back_mut() {
                let l = old.data.len();
                if l < self.mss {
                    let capacity = self.mss - l;
                    let extend = cmp::min(buf.len(), capacity);

                    trace!(
                        "send stream mss={} last length={} extend={}",
                        self.mss,
                        l,
                        extend
                    );

                    let (lf, rt) = buf.split_at(extend);
                    old.data.extend_from_slice(lf);
                    buf = rt;

                    old.frg = 0;
                    sent_size += extend;
                }
            }

            if buf.is_empty() {
                return Ok(sent_size);
            }
        }

        let count = if buf.len() <= self.mss {
            1
        } else {
            buf.len().div_ceil(self.mss)
        };

        // Upstream fragment limit is a u8 `frg` countdown — 255 segments.
        if count > 255 {
            debug!("send bufsize={} mss={} too large", buf.len(), self.mss);
            return Err(KcpError::UserBufTooBig);
        }

        let count = cmp::max(1, count);

        for i in 0..count {
            let size = cmp::min(self.mss, buf.len());

            let (lf, rt) = buf.split_at(size);

            let mut new_segment = KcpSegment::new_with_data(lf.into());
            buf = rt;

            new_segment.frg = if self.stream {
                0
            } else {
                (count - i - 1) as u8
            };

            self.snd_queue.push_back(new_segment);
            sent_size += size;
        }

        Ok(sent_size)
    }

    /// Upstream `update_ack` — RFC 6298-variant estimator. `srtt` moves
    /// by `delta>>3` (not the classic 7/8 blend), and a sample below the
    /// expected RTT floor gets 8x-reduced weight (`>>5` vs `>>2`) so a
    /// fast ACK can't drag `rttvar` down and starve the RTO.
    fn update_ack(&mut self, rtt: i32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt >> 1;
        } else {
            let mut delta = rtt.wrapping_sub(self.rx_srtt);
            self.rx_srtt = self.rx_srtt.wrapping_add(delta >> 3);
            if delta < 0 {
                // wrapping_neg mirrors Go's silent i32 wrap at MIN —
                // unreachable in practice (rtt >= 0, rx_srtt >= 0) but
                // keeps the port bulletproof under debug builds.
                delta = delta.wrapping_neg();
            }
            if rtt < self.rx_srtt.wrapping_sub(self.rx_rttval) {
                self.rx_rttval = self
                    .rx_rttval
                    .wrapping_add(delta.wrapping_sub(self.rx_rttval) >> 5);
            } else {
                self.rx_rttval = self
                    .rx_rttval
                    .wrapping_add(delta.wrapping_sub(self.rx_rttval) >> 2);
            }
        }
        let rto = (self.rx_srtt as u32)
            .wrapping_add(cmp::max(self.interval, (self.rx_rttval as u32) << 2));
        self.rx_rto = bound(self.rx_minrto, rto, KCP_RTO_MAX);
    }

    #[inline]
    fn shrink_buf(&mut self) {
        self.snd_una = match self.snd_buf.front() {
            Some(seg) => seg.sn,
            None => self.snd_nxt,
        };
    }

    /// Upstream `parse_ack` — mark only. The segment stays in `snd_buf`
    /// until `parse_una` slides past it, so a dup-ack burst doesn't pay
    /// a `VecDeque::remove` shift per ACK and `parse_fastack` keeps
    /// seeing the boundary segment it needs.
    fn parse_ack(&mut self, sn: u32) {
        if timediff(sn, self.snd_una) < 0 || timediff(sn, self.snd_nxt) >= 0 {
            return;
        }

        // `timediff` ordering handles seq wraparound — `Ordering::cmp` can't.
        let mut idx = 0;
        while idx < self.snd_buf.len() {
            let seg_sn = self.snd_buf[idx].sn;
            if sn == seg_sn {
                let seg = &mut self.snd_buf[idx];
                seg.acked = true;
                // Upstream `recycleSegment` frees the payload at mark
                // time — the segment only ever waits for `parse_una`.
                seg.data = BytesMut::new();
                break;
            }
            if timediff(sn, seg_sn) < 0 {
                break;
            }
            idx += 1;
        }
    }

    /// Upstream `parse_una` — returns how many leading segments UNA slid
    /// past; `input` flushes immediately when it moves.
    fn parse_una(&mut self, una: u32) -> usize {
        let mut count = 0;
        while let Some(seg) = self.snd_buf.front() {
            if timediff(una, seg.sn) > 0 {
                self.snd_buf.pop_front();
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// Upstream `parse_fastack` — increments dup-ack counters for every
    /// outstanding segment with `sn < ack.sn` and `seg.ts <= ack.ts`,
    /// skipping ones already fast-retransmitted this RTO (`0xFFFFFFFF`
    /// sentinel). Returns 1 when any segment crossed `fastresend` —
    /// `input` flushes FULL immediately on that signal.
    fn parse_fastack(&mut self, sn: u32, ts: u32) -> u32 {
        if timediff(sn, self.snd_una) < 0 || timediff(sn, self.snd_nxt) >= 0 {
            return 0;
        }

        let mut should_fastack = 0;
        for seg in &mut self.snd_buf {
            if timediff(sn, seg.sn) < 0 {
                break;
            } else if sn != seg.sn && timediff(seg.ts, ts) <= 0 && seg.fastack != 0xFFFFFFFF {
                seg.fastack = seg.fastack.wrapping_add(1);
                // Upstream compares against `uint32(fastresend)` — with
                // resend disabled (0) every dup-ack signals, and early
                // retransmit carries the recovery instead.
                if seg.fastack >= self.fastresend {
                    should_fastack = 1;
                }
            }
        }
        should_fastack
    }

    #[inline]
    fn ack_push(&mut self, sn: u32, ts: u32) {
        self.acklist.push_back((sn, ts));
    }

    /// `parse_data` — upstream delayed-copy semantics: the payload only
    /// materializes into the buffer when the segment actually inserts
    /// (a duplicate PUSH costs a scan, not an allocation).
    #[allow(
        clippy::too_many_arguments,
        reason = "one-to-one with the on-wire segment header — a struct would just re-pack it"
    )]
    fn parse_data(
        &mut self,
        conv: u32,
        cmd: u8,
        frg: u8,
        wnd: u16,
        ts: u32,
        sn: u32,
        una: u32,
        data: &[u8],
    ) {
        if timediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) >= 0
            || timediff(sn, self.rcv_nxt) < 0
        {
            return;
        }

        let mut repeat = false;
        let mut new_index = self.rcv_buf.len();

        for segment in self.rcv_buf.iter().rev() {
            if segment.sn == sn {
                repeat = true;
                break;
            }
            if timediff(sn, segment.sn) > 0 {
                break;
            }
            new_index -= 1;
        }

        if !repeat {
            let mut new_segment = KcpSegment::new_with_data(BytesMut::from(data));
            new_segment.conv = conv;
            new_segment.cmd = cmd;
            new_segment.frg = frg;
            new_segment.wnd = wnd;
            new_segment.ts = ts;
            new_segment.sn = sn;
            new_segment.una = una;
            self.rcv_buf.insert(new_index, new_segment);
        }

        // move available data from rcv_buf -> rcv_queue
        self.move_buf();
    }

    /// Get `conv` from the next `input` call
    #[inline]
    pub fn input_conv(&mut self) {
        self.input_conv = true;
    }

    /// Check if Kcp is waiting for the next input
    #[inline]
    pub fn waiting_conv(&self) -> bool {
        self.input_conv
    }

    /// Set `conv` value
    #[inline]
    pub fn set_conv(&mut self, conv: u32) {
        self.conv = conv;
    }

    /// Get `conv`
    #[inline]
    pub fn conv(&self) -> u32 {
        self.conv
    }

    fn wnd_unused(&self) -> u16 {
        if (self.rcv_queue.len() as u32) < self.rcv_wnd {
            (self.rcv_wnd - self.rcv_queue.len() as u32) as u16
        } else {
            0
        }
    }

    fn probe_wnd_size(&mut self) {
        // probe window size (if remote window size equals zero)
        if self.rmt_wnd == 0 {
            if self.probe_wait == 0 {
                self.probe_wait = KCP_PROBE_INIT;
                self.ts_probe = self.current.wrapping_add(self.probe_wait);
            } else {
                if timediff(self.current, self.ts_probe) >= 0 {
                    if self.probe_wait < KCP_PROBE_INIT {
                        self.probe_wait = KCP_PROBE_INIT;
                    }

                    self.probe_wait = self.probe_wait.wrapping_add(self.probe_wait / 2);

                    if self.probe_wait > KCP_PROBE_LIMIT {
                        self.probe_wait = KCP_PROBE_LIMIT;
                    }

                    self.ts_probe = self.current.wrapping_add(self.probe_wait);
                    self.probe |= KCP_ASK_SEND;
                }
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }
    }

    /// Determine when you should call `update`.
    /// Return when you should invoke `update` in millisec, if there is no `input`/`send` calling.
    /// You can call `update` in that time without calling it repeatly.
    pub fn check(&self, current: u32) -> u32 {
        if !self.updated {
            return 0;
        }

        let mut ts_flush = self.ts_flush;
        let mut tm_packet = u32::MAX;

        if timediff(current, ts_flush) >= 10000 || timediff(current, ts_flush) < -10000 {
            ts_flush = current;
        }

        if timediff(current, ts_flush) >= 0 {
            return 0;
        }

        let tm_flush = timediff(ts_flush, current) as u32;
        for seg in &self.snd_buf {
            // `acked` segs keep their stale `resendts` but never
            // retransmit (phase 5 skips them); `xmit == 0` segs slid in
            // during an ACK-only flush and are transmitted by the next
            // FULL flush. Neither can produce work sooner than
            // `ts_flush`, which `tm_flush` already covers — reporting
            // them as "due now" would spin a poll-driven caller.
            if seg.acked || seg.xmit == 0 {
                continue;
            }
            let diff = timediff(seg.resendts, current);
            if diff <= 0 {
                return 0;
            }
            if (diff as u32) < tm_packet {
                tm_packet = diff as u32;
            }
        }

        let mut minimal = cmp::min(tm_packet, tm_flush);
        if minimal >= self.interval {
            minimal = self.interval;
        }

        minimal
    }

    /// Change MTU size, default is 1400
    ///
    /// MTU = Maximum Transmission Unit. Upstream `SetMtu` only rejects
    /// `mtu <= IKCP_OVERHEAD` — the classic `mtu < 50` floor is gone.
    pub fn set_mtu(&mut self, mtu: usize) -> KcpResult<()> {
        if mtu <= KCP_OVERHEAD {
            debug!("set_mtu mtu={} invalid", mtu);
            return Err(KcpError::InvalidMtu(mtu));
        }

        self.mtu = mtu;
        self.mss = self.mtu - KCP_OVERHEAD;

        let target_size = mtu.saturating_add(KCP_OVERHEAD).saturating_mul(3);
        if target_size > self.buf.capacity() {
            self.buf.reserve(target_size - self.buf.capacity());
        }

        Ok(())
    }

    /// Get MTU
    #[inline]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Set check interval
    pub fn set_interval(&mut self, interval: u32) {
        self.interval = interval.clamp(10, 5000);
    }

    /// Set nodelay
    ///
    /// fastest config: nodelay(true, 20, 2, true)
    ///
    /// `nodelay`: default is disable (false)
    /// `interval`: internal update timer interval in millisec, default is 100ms
    /// `resend`: 0:disable fast resend(default), 1:enable fast resend
    /// `nc`: `false`: normal congestion control(default), `true`: disable congestion control
    pub fn set_nodelay(&mut self, nodelay: bool, interval: i32, resend: i32, nc: bool) {
        if nodelay {
            self.nodelay = true;
            self.rx_minrto = KCP_RTO_NDL;
        } else {
            self.nodelay = false;
            self.rx_minrto = KCP_RTO_MIN;
        }

        // Upstream `NoDelay` ignores a negative interval entirely.
        if interval >= 0 {
            self.interval = (interval as u32).clamp(10, 5000);
        }

        if resend >= 0 {
            self.fastresend = resend as u32;
        }

        self.nocwnd = nc;
    }

    /// Set `wndsize`
    /// set maximum window size: `sndwnd=32`, `rcvwnd=32` by default.
    /// Upstream `WndSize` — no floor on `rcvwnd` (the classic 128 floor
    /// silently inflated `rcv_wnd=1` configs).
    pub fn set_wndsize(&mut self, sndwnd: u32, rcvwnd: u32) {
        if sndwnd > 0 {
            self.snd_wnd = sndwnd;
        }

        if rcvwnd > 0 {
            self.rcv_wnd = rcvwnd;
        }
    }

    /// `snd_wnd` Send window
    #[inline]
    pub fn snd_wnd(&self) -> u32 {
        self.snd_wnd
    }

    /// `rcv_wnd` Receive window
    #[inline]
    pub fn rcv_wnd(&self) -> u32 {
        self.rcv_wnd
    }

    /// Get `waitsnd`, how many packet is waiting to be sent
    #[inline]
    pub fn wait_snd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }

    /// Get `rmt_wnd`, remote window size
    #[inline]
    pub fn rmt_wnd(&self) -> u32 {
        self.rmt_wnd
    }

    /// Set `rx_minrto`
    #[inline]
    pub fn set_rx_minrto(&mut self, rto: u32) {
        self.rx_minrto = rto;
    }

    /// Set `fastresend`
    #[inline]
    pub fn set_fast_resend(&mut self, fr: u32) {
        self.fastresend = fr;
    }

    /// KCP header size
    #[inline]
    pub fn header_len() -> usize {
        KCP_OVERHEAD
    }

    /// Enabled stream or not
    #[inline]
    pub fn is_stream(&self) -> bool {
        self.stream
    }

    /// Maximum Segment Size
    #[inline]
    pub fn mss(&self) -> usize {
        self.mss
    }

    /// Set maximum resend times
    #[inline]
    pub fn set_maximum_resend_times(&mut self, dead_link: u32) {
        self.dead_link = dead_link;
    }

    /// Check if KCP connection is dead (resend times excceeded)
    #[inline]
    pub fn is_dead_link(&self) -> bool {
        self.state != 0
    }
}

impl<Output: Write> Kcp<Output> {
    fn _flush_ack(&mut self, segment: &mut KcpSegment) -> KcpResult<()> {
        // flush acknowledges — upstream filters bufferbloat jitter:
        // entries UNA already covered (`sn < rcv_nxt`) are skipped,
        // except the newest, which keeps `una`/`wnd` on the wire fresh.
        let last = self.acklist.len().saturating_sub(1);
        for (i, &(sn, ts)) in self.acklist.iter().enumerate() {
            if self.buf.len() + KCP_OVERHEAD > self.mtu {
                self.output.write_all(&self.buf)?;
                self.buf.clear();
            }
            if timediff(sn, self.rcv_nxt) >= 0 || i == last {
                segment.sn = sn;
                segment.ts = ts;
                segment.encode(&mut self.buf);
            }
        }
        self.acklist.clear();

        Ok(())
    }

    fn _flush_probe_commands(&mut self, cmd: u8, segment: &mut KcpSegment) -> KcpResult<()> {
        segment.cmd = cmd;
        if self.buf.len() + KCP_OVERHEAD > self.mtu {
            self.output.write_all(&self.buf)?;
            self.buf.clear();
        }
        segment.encode(&mut self.buf);
        Ok(())
    }

    fn flush_probe_commands(&mut self, segment: &mut KcpSegment) -> KcpResult<()> {
        // flush window probing commands
        if (self.probe & KCP_ASK_SEND) != 0 {
            self._flush_probe_commands(KCP_CMD_WASK, segment)?;
        }

        // flush window probing commands
        if (self.probe & KCP_ASK_TELL) != 0 {
            self._flush_probe_commands(KCP_CMD_WINS, segment)?;
        }
        self.probe = 0;
        Ok(())
    }

    /// Flush pending ACKs
    pub fn flush_ack(&mut self) -> KcpResult<()> {
        if !self.updated {
            debug!("flush updated() must be called at least once");
            return Err(KcpError::NeedUpdate);
        }

        self.flush_inner(FlushType::AckOnly)
    }

    /// Flush pending data in buffer.
    pub fn flush(&mut self) -> KcpResult<()> {
        if !self.updated {
            debug!("flush updated() must be called at least once");
            return Err(KcpError::NeedUpdate);
        }

        self.flush_inner(FlushType::Full)
    }

    /// Call this when you received a packet from raw connection.
    ///
    /// `regular` — false for FEC-recovered payloads: a parity rebuild
    /// isn't a fresh transmission, so upstream (`IKCP_PACKET_FEC`) keeps
    /// it out of `rmt_wnd` and the RTT estimator.
    ///
    /// `ack_nodelay` — emit an ACK-only datagram immediately instead of
    /// waiting out `interval` (upstream `ackNoDelay`).
    pub fn input(&mut self, buf: &[u8], regular: bool, ack_nodelay: bool) -> KcpResult<usize> {
        let input_size = buf.len();

        trace!("[RI] {} bytes", buf.len());

        if buf.len() < KCP_OVERHEAD {
            debug!(
                "input bufsize={} too small, at least {}",
                buf.len(),
                KCP_OVERHEAD
            );
            return Err(KcpError::InvalidSegmentSize(buf.len()));
        }

        // Upstream: `snd_una` snapshot for the cwnd-growth check,
        // `updateRTT`/`latest` for the deferred single RTT sample, and
        // `flushSegments` signalling an immediate FULL flush.
        let old_una = self.snd_una;
        let mut update_rtt = false;
        let mut latest = 0u32;
        let mut flush_segments = 0u32;

        let mut buf = Cursor::new(buf);
        while buf.remaining() >= KCP_OVERHEAD {
            let conv = buf.get_u32_le();
            if conv != self.conv {
                // This allows getting conv from this call, which allows us to allocate
                // conv from the server side.
                if self.input_conv {
                    debug!("input conv={} updated, original conv={}", conv, self.conv);
                    self.conv = conv;
                    self.input_conv = false;
                } else {
                    debug!("input conv={} expected conv={} not match", conv, self.conv);
                    return Err(KcpError::ConvInconsistent(self.conv, conv));
                }
            }

            let cmd = buf.get_u8();
            let frg = buf.get_u8();
            let wnd = buf.get_u16_le();
            let ts = buf.get_u32_le();
            let sn = buf.get_u32_le();
            let una = buf.get_u32_le();
            let len = buf.get_u32_le() as usize;

            if buf.remaining() < len {
                debug!(
                    "input bufsize={} payload length={} remaining={} not match",
                    input_size,
                    len,
                    buf.remaining()
                );
                return Err(KcpError::InvalidSegmentDataSize(len, buf.remaining()));
            }

            match cmd {
                KCP_CMD_PUSH | KCP_CMD_ACK | KCP_CMD_WASK | KCP_CMD_WINS => {}
                _ => {
                    debug!("input cmd={} unrecognized", cmd);
                    return Err(KcpError::UnsupportedCmd(cmd));
                }
            }

            // Only a regular packet carries a trustworthy window —
            // a FEC rebuild may replay a stale `wnd` field.
            if regular {
                self.rmt_wnd = wnd as u32;
            }

            if self.parse_una(una) > 0 {
                flush_segments |= 1;
            }
            self.shrink_buf();

            let mut has_read_data = false;

            match cmd {
                KCP_CMD_ACK => {
                    // Upstream feeds every ACK through `parse_fastack`
                    // per-segment (not once on the max) and defers the
                    // RTT sample to the newest ACK in the datagram.
                    self.parse_ack(sn);
                    flush_segments |= self.parse_fastack(sn, ts);
                    update_rtt = true;
                    latest = ts;

                    trace!(
                        "input ack: sn={} rtt={} rto={}",
                        sn,
                        timediff(self.current, ts),
                        self.rx_rto
                    );
                }
                KCP_CMD_PUSH => {
                    trace!("input psh: sn={} ts={}", sn, ts);

                    if timediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) < 0 {
                        self.ack_push(sn, ts);
                        if timediff(sn, self.rcv_nxt) >= 0 {
                            // `remaining >= len` checked above; `parse_data`
                            // copies only when the segment actually inserts.
                            self.parse_data(conv, cmd, frg, wnd, ts, sn, una, &buf.chunk()[..len]);
                            buf.advance(len);
                            has_read_data = true;
                        }
                    }
                }
                KCP_CMD_WASK => {
                    // ready to send back IKCP_CMD_WINS in ikcp_flush
                    // tell remote my window size
                    trace!("input probe");
                    self.probe |= KCP_ASK_TELL;
                }
                KCP_CMD_WINS => {
                    // Do nothing
                    trace!("input wins: {}", wnd);
                }
                _ => unreachable!(),
            }

            // Force skip unread data
            if !has_read_data {
                let next_pos = buf.position() + len as u64;
                buf.set_position(next_pos);
            }
        }

        // One RTT sample per datagram, from the newest ACK — upstream
        // samples `latest`, and never from a FEC rebuild.
        if update_rtt && regular {
            let rtt = timediff(self.current, latest);
            if rtt >= 0 {
                self.update_ack(rtt);
            }
        }

        // Reno-style cwnd growth on UNA progress — upstream gates this
        // on `nocwnd == 0`; classic ikcp applied it unconditionally.
        // AIMD: slow start increments per ACK, congestion avoidance
        // re-bases `cwnd` on the byte accumulator (`incr/mss` rounded up).
        if !self.nocwnd && timediff(self.snd_una, old_una) > 0 && self.cwnd < self.rmt_wnd {
            let mss = self.mss as u32;
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                self.incr = self.incr.wrapping_add(mss);
            } else {
                if self.incr < mss {
                    self.incr = mss;
                }
                self.incr = self
                    .incr
                    .wrapping_add((mss.wrapping_mul(mss) / self.incr).wrapping_add(mss / 16));
                if self.cwnd.wrapping_add(1).wrapping_mul(mss) <= self.incr {
                    // Upstream guards `mss > 0` here; ours is always ≥ 1
                    // (ctor floor + `set_mtu` rejects `<= IKCP_OVERHEAD`).
                    self.cwnd = self.incr.wrapping_add(mss).wrapping_sub(1) / mss;
                }
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.rmt_wnd.wrapping_mul(mss);
            }
        }

        // Upstream `Input` tail: a UNA slide or a tripped fast-retransmit
        // threshold flushes everything NOW — the resend can't wait for
        // the maintenance interval (that wait was classic ikcp's big
        // latency cost). Otherwise an oversized ack backlog (or
        // `ack_nodelay`) emits an ACK-only datagram.
        if flush_segments != 0 {
            self.flush_inner(FlushType::Full)?;
        } else if self.acklist.len() >= self.mtu / KCP_OVERHEAD
            || (ack_nodelay && !self.acklist.is_empty())
        {
            self.flush_inner(FlushType::AckOnly)?;
        }

        Ok(buf.position() as usize)
    }

    /// Upstream `flush(flushType)` — one body for both datagram kinds:
    ///
    /// - Phase 1 emits the ack backlog on BOTH types; the stale filter
    ///   drops entries UNA already covered (except the newest, which
    ///   keeps `una`/`wnd` on the wire current).
    /// - Phases 2–4 (window probing, probe commands, snd_queue slide)
    ///   also run for ACKONLY — upstream slides the queue even when it
    ///   isn't going to transmit, so `newSegsCount` still bounds the
    ///   early-retransmit arm on the next FULL flush.
    /// - Phase 5 (initial transmit / fast / early / RTO retransmit) is
    ///   FULL-only; ACKONLY never emits PUSH/WASK/WINS payloads… wait,
    ///   upstream DOES emit probe commands on ACKONLY — phases 3 and 4
    ///   are ungated, only phase 5 is.
    fn flush_inner(&mut self, flush_type: FlushType) -> KcpResult<()> {
        let mut segment = KcpSegment {
            conv: self.conv,
            cmd: KCP_CMD_ACK,
            wnd: self.wnd_unused(),
            una: self.rcv_nxt,
            ..Default::default()
        };

        self._flush_ack(&mut segment)?;
        self.probe_wnd_size();
        self.flush_probe_commands(&mut segment)?;

        // calculate window size
        let mut cwnd = cmp::min(self.snd_wnd, self.rmt_wnd);
        if !self.nocwnd {
            cwnd = cmp::min(self.cwnd, cwnd);
        }

        // move data from snd_queue to snd_buf — upstream stamps only
        // conv/cmd/sn here; ts/wnd/una/rto/resendts are assigned when the
        // segment actually goes on the wire in phase 5.
        let mut new_segs = 0usize;
        while timediff(self.snd_nxt, self.snd_una.wrapping_add(cwnd)) < 0 {
            match self.snd_queue.pop_front() {
                Some(mut new_segment) => {
                    new_segment.conv = self.conv;
                    new_segment.cmd = KCP_CMD_PUSH;
                    new_segment.sn = self.snd_nxt;
                    self.snd_nxt = self.snd_nxt.wrapping_add(1);
                    self.snd_buf.push_back(new_segment);
                    new_segs += 1;
                }
                None => break,
            }
        }

        // calculate resent — `0xFFFFFFFF` when fast retransmit is off
        // (`fastack >= resent` can only match the sentinel itself, which
        // the `!= 0xFFFFFFFF` guards exclude).
        let resent = if self.fastresend > 0 {
            self.fastresend
        } else {
            u32::MAX
        };

        let mut lost = false;
        let mut change = 0;

        // Retransmission only happens on a FULL flush.
        if flush_type == FlushType::Full {
            for snd_segment in &mut self.snd_buf {
                let mut need_send = false;

                // Already ACKed, not yet UNA'd — never retransmit.
                if snd_segment.acked {
                    continue;
                }

                if snd_segment.xmit == 0 {
                    // Initial transmit: upstream schedules the first RTO
                    // at `current + rx_rto` — classic ikcp added rtomin
                    // (rto>>3) which delayed the first recovery.
                    need_send = true;
                    snd_segment.rto = self.rx_rto;
                    snd_segment.resendts = self.current.wrapping_add(snd_segment.rto);
                } else if snd_segment.fastack >= resent && snd_segment.fastack != 0xFFFFFFFF {
                    // Fast retransmit — the sentinel locks further fast
                    // retransmits until an RTO resets `fastack` to 0.
                    need_send = true;
                    snd_segment.fastack = 0xFFFFFFFF;
                    snd_segment.rto = self.rx_rto;
                    snd_segment.resendts = self.current.wrapping_add(snd_segment.rto);
                    change += 1;
                } else if snd_segment.fastack > 0
                    && snd_segment.fastack != 0xFFFFFFFF
                    && new_segs == 0
                {
                    // Early retransmit — any dup-ack with an empty new-
                    // data queue resends once, then locks like above.
                    need_send = true;
                    snd_segment.fastack = 0xFFFFFFFF;
                    snd_segment.rto = self.rx_rto;
                    snd_segment.resendts = self.current.wrapping_add(snd_segment.rto);
                    change += 1;
                } else if timediff(self.current, snd_segment.resendts) >= 0 {
                    // RTO: upstream backoff is LINEAR (+rx_rto, or
                    // +rx_rto/2 with nodelay) — classic ikcp doubled.
                    need_send = true;
                    if self.nodelay {
                        snd_segment.rto = snd_segment.rto.wrapping_add(self.rx_rto / 2);
                    } else {
                        snd_segment.rto = snd_segment.rto.wrapping_add(self.rx_rto);
                    }
                    snd_segment.fastack = 0;
                    snd_segment.resendts = self.current.wrapping_add(snd_segment.rto);
                    lost = true;
                }

                if need_send {
                    snd_segment.xmit = snd_segment.xmit.wrapping_add(1);
                    snd_segment.ts = self.current;
                    snd_segment.wnd = segment.wnd;
                    snd_segment.una = self.rcv_nxt;

                    let need = KCP_OVERHEAD + snd_segment.data.len();

                    if self.buf.len() + need > self.mtu {
                        self.output.write_all(&self.buf)?;
                        self.buf.clear();
                    }

                    snd_segment.encode(&mut self.buf);

                    if snd_segment.xmit >= self.dead_link {
                        self.state = -1; // (IUINT32)-1
                    }
                }
            }
        }

        // Flush all data in buffer
        if !self.buf.is_empty() {
            self.output.write_all(&self.buf)?;
            self.buf.clear();
        }

        // update ssthresh — upstream gates the whole cwnd update on
        // `nocwnd == 0` (nc=1 disables it entirely).
        if !self.nocwnd {
            if change > 0 {
                let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
                self.ssthresh = cmp::max(inflight / 2, KCP_THRESH_MIN);
                self.cwnd = self.ssthresh.wrapping_add(resent);
                self.incr = self.cwnd.wrapping_mul(self.mss as u32);
            }

            if lost {
                self.ssthresh = cmp::max(cwnd / 2, KCP_THRESH_MIN);
                self.cwnd = 1;
                self.incr = self.mss as u32;
            }

            if self.cwnd < 1 {
                self.cwnd = 1;
                self.incr = self.mss as u32;
            }
        }

        Ok(())
    }

    /// Update state every 10ms ~ 100ms.
    ///
    /// Or you can ask `check` when to call this again.
    pub fn update(&mut self, current: u32) -> KcpResult<()> {
        self.current = current;

        if !self.updated {
            self.updated = true;
            self.ts_flush = self.current;
        }

        let mut slap = timediff(self.current, self.ts_flush);

        if !(-10000..10000).contains(&slap) {
            self.ts_flush = self.current;
            slap = 0;
        }

        if slap >= 0 {
            self.ts_flush = self.ts_flush.wrapping_add(self.interval);
            if timediff(self.current, self.ts_flush) >= 0 {
                self.ts_flush = self.current.wrapping_add(self.interval);
            }
            self.flush()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Write` sink capturing each emitted datagram separately — `Kcp`
    /// `write_all`s exactly one wire datagram per call.
    #[derive(Default)]
    struct Sink(Vec<Vec<u8>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.push(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// One wire segment: `conv‖cmd‖frg‖wnd‖ts‖sn‖una‖len‖data`.
    fn seg(conv: u32, cmd: u8, wnd: u16, ts: u32, sn: u32, una: u32, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(KCP_OVERHEAD + data.len());
        b.extend_from_slice(&conv.to_le_bytes());
        b.push(cmd);
        b.push(0); // frg
        b.extend_from_slice(&wnd.to_le_bytes());
        b.extend_from_slice(&ts.to_le_bytes());
        b.extend_from_slice(&sn.to_le_bytes());
        b.extend_from_slice(&una.to_le_bytes());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(data);
        b
    }

    fn push(conv: u32, wnd: u16, ts: u32, sn: u32, una: u32, data: &[u8]) -> Vec<u8> {
        seg(conv, KCP_CMD_PUSH, wnd, ts, sn, una, data)
    }

    fn ack(conv: u32, wnd: u16, ts: u32, sn: u32, una: u32) -> Vec<u8> {
        seg(conv, KCP_CMD_ACK, wnd, ts, sn, una, &[])
    }

    /// Decode emitted datagrams into (cmd, sn) pairs.
    fn wire_cmds(kcp: &Kcp<Sink>) -> Vec<(u8, u32)> {
        let mut out = Vec::new();
        for dgram in &kcp.output.0 .0 {
            let mut cur = Cursor::new(&dgram[..]);
            while cur.remaining() >= KCP_OVERHEAD {
                let _conv = cur.get_u32_le();
                let cmd = cur.get_u8();
                let _frg = cur.get_u8();
                let _wnd = cur.get_u16_le();
                let _ts = cur.get_u32_le();
                let sn = cur.get_u32_le();
                let _una = cur.get_u32_le();
                let len = cur.get_u32_le() as usize;
                cur.set_position(cur.position() + len as u64);
                out.push((cmd, sn));
            }
        }
        out
    }

    /// Non-stream `Kcp` — each `send` stays its own segment, which the
    /// retransmission tests need (stream mode coalesces into one).
    fn fast3() -> Kcp<Sink> {
        let mut k = Kcp::new(1, Sink::default());
        k.set_nodelay(true, 10, 2, true);
        k
    }

    /// Issue #621: `send` must return an error — never panic — if mss is
    /// somehow zero (unreachable via `set_mtu` today, defensive only).
    #[test]
    fn send_with_zero_mss_errors_instead_of_panicking() {
        let mut k = fast3();
        k.mss = 0;
        assert!(matches!(k.send(b"aa"), Err(KcpError::InvalidMss(0))));
    }

    /// Upstream `Input` tail: a UNA slide flushes FULL immediately — the
    /// classic crate waited for the next `update` tick, so queued data
    /// sat an extra interval behind every ACK.
    #[test]
    fn una_slide_flushes_immediately() {
        let mut k = fast3();
        k.update(0).unwrap();
        k.send(b"aa").unwrap();
        k.update(10).unwrap(); // emits PUSH sn=0
        assert_eq!(wire_cmds(&k), vec![(KCP_CMD_PUSH, 0)]);

        k.send(b"bb").unwrap(); // queued, not yet on the wire
                                // ACK sn=0 with una=1 — slides UNA → immediate FULL flush must
                                // emit PUSH sn=1 without another update().
        k.input(&ack(1, 32, 0, 0, 1), true, false).unwrap();
        assert!(wire_cmds(&k).contains(&(KCP_CMD_PUSH, 1)));
    }

    /// Upstream fast retransmit: `fastack >= resent` fires once, then the
    /// `0xFFFFFFFF` sentinel locks the segment until an RTO resets it.
    #[test]
    fn fast_retransmit_fires_once_per_rto() {
        let mut k = fast3(); // resend=2
        k.update(0).unwrap();
        for _ in 0..4 {
            k.send(b"x").unwrap();
        }
        k.update(10).unwrap(); // PUSH 0..3 on the wire
        let base = wire_cmds(&k).len();

        // Dup-ack sn=3 twice → segs 0..2 reach fastack=2 → immediate
        // flush retransmits every unacked segment behind sn=3, each
        // exactly once (upstream resends all threshold-crossers).
        k.input(&ack(1, 32, 10, 3, 0), true, false).unwrap();
        k.input(&ack(1, 32, 10, 3, 0), true, false).unwrap();
        let after = wire_cmds(&k);
        let retransmits: Vec<u32> = after[base..]
            .iter()
            .filter(|&&(cmd, _)| cmd == KCP_CMD_PUSH)
            .map(|&(_, s)| s)
            .collect();
        assert_eq!(retransmits, vec![0, 1, 2]);

        // Sentinel: further dup-acks do NOT retransmit again.
        let n = wire_cmds(&k).len();
        for _ in 0..3 {
            k.input(&ack(1, 32, 10, 3, 0), true, false).unwrap();
        }
        let later = wire_cmds(&k);
        assert!(
            !later[n..].iter().any(|&(cmd, _)| cmd == KCP_CMD_PUSH),
            "sentinel must suppress repeat fast retransmits: {later:?}"
        );
    }

    /// Upstream early retransmit: with resend disabled (resent floor
    /// unreachable) a lone dup-ack still retransmits once when no new
    /// segments queued — the classic crate had no such path.
    #[test]
    fn early_retransmit_on_dup_ack() {
        let mut k = Kcp::new(1, Sink::default());
        k.set_nodelay(true, 10, 0, true); // resend=0
        k.update(0).unwrap();
        k.send(b"a").unwrap();
        k.send(b"b").unwrap();
        k.update(10).unwrap(); // PUSH 0,1
        let base = wire_cmds(&k).len();

        // One dup-ack for sn=1 → fastack on sn=0, new_segs==0 → early
        // retransmit fires immediately (upstream `resend=0` still relies
        // on this path).
        k.input(&ack(1, 32, 10, 1, 0), true, false).unwrap();
        let after = wire_cmds(&k);
        let pushes: Vec<_> = after[base..]
            .iter()
            .filter(|&&(cmd, _)| cmd == KCP_CMD_PUSH)
            .collect();
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0].1, 0);
    }

    /// Upstream RTO backoff is linear — `rto += rx_rto` (or `rx_rto/2`
    /// under nodelay), not the classic exponential doubling.
    #[test]
    fn rto_backoff_is_linear() {
        let mut k = Kcp::new(1, Sink::default());
        k.set_nodelay(false, 10, 2, false);
        k.update(0).unwrap();
        k.send(b"data").unwrap();
        k.update(10).unwrap(); // first transmit: rto = rx_rto (200)
        assert_eq!(k.snd_buf[0].rto, k.rx_rto);

        // First RTO: resendts was current+rto → advance past it.
        let t1 = k.snd_buf[0].resendts + 1;
        k.update(t1).unwrap();
        assert_eq!(k.snd_buf[0].xmit, 2);
        assert_eq!(k.snd_buf[0].rto, 2 * k.rx_rto, "linear +rx_rto");

        let t2 = k.snd_buf[0].resendts + 1;
        k.update(t2).unwrap();
        assert_eq!(k.snd_buf[0].xmit, 3);
        assert_eq!(k.snd_buf[0].rto, 3 * k.rx_rto, "still linear, not 4x");
    }

    /// Upstream ACK clocking: `acklist >= mtu/24` (58 @1400) emits an
    /// ACK-only datagram without waiting for the interval.
    #[test]
    fn ack_clocking_emits_without_update() {
        let mut k = fast3();
        k.update(0).unwrap();
        let threshold = k.mtu / KCP_OVERHEAD; // 58

        // Feed `threshold` PUSH segments in one datagram — below the
        // clocking bound nothing is emitted yet.
        let mut buf = Vec::new();
        for sn in 0..threshold as u32 {
            buf.extend_from_slice(&push(1, 32, 0, sn, 0, &[]));
        }
        // first threshold-1 segs: no flush
        k.input(&buf[..(threshold - 1) * KCP_OVERHEAD], true, false)
            .unwrap();
        assert!(k.output.0 .0.is_empty(), "below clocking bound");

        // the threshold-th seg trips the clock
        k.input(&buf[(threshold - 1) * KCP_OVERHEAD..], true, false)
            .unwrap();
        assert_eq!(k.output.0 .0.len(), 1);
        assert!(
            wire_cmds(&k).iter().all(|&(c, _)| c == KCP_CMD_ACK),
            "ACKONLY datagram carries only ACKs"
        );
    }

    /// Upstream `ackNoDelay`: a single inbound PUSH flushes its ACK
    /// immediately instead of waiting for the interval.
    #[test]
    fn ack_nodelay_emits_immediately() {
        let mut k = fast3();
        k.update(0).unwrap();
        k.input(&push(1, 32, 0, 0, 0, b"d"), true, true).unwrap();
        assert_eq!(wire_cmds(&k), vec![(KCP_CMD_ACK, 0)]);

        // Off → same input leaves the ack queued.
        let mut k2 = fast3();
        k2.update(0).unwrap();
        k2.input(&push(1, 32, 0, 0, 0, b"d"), true, false).unwrap();
        assert!(k2.output.0 .0.is_empty());
        k2.update(50).unwrap(); // interval flush carries it
        assert_eq!(wire_cmds(&k2), vec![(KCP_CMD_ACK, 0)]);
    }

    /// FEC-recovered payloads (`regular=false`) must not move `rmt_wnd`
    /// or feed the RTT estimator — upstream `IKCP_PACKET_FEC` gate.
    #[test]
    fn fec_input_ignores_wnd_and_rtt() {
        let mut k = fast3();
        k.update(0).unwrap();
        k.send(b"x").unwrap();
        k.update(10).unwrap();

        // A "FEC" packet advertising wnd=1 and acking sn=0.
        k.input(&ack(1, 1, 0, 0, 1), false, false).unwrap();
        assert_eq!(k.rmt_wnd, KCP_WND_RCV, "FEC packet must not shrink wnd");
        assert_eq!(k.rx_srtt, 0, "FEC packet must not sample RTT");

        // Same packet as regular → both update.
        k.input(&ack(1, 7, 0, 0, 1), true, false).unwrap();
        assert_eq!(k.rmt_wnd, 7);
        assert_ne!(k.rx_srtt, 0, "regular ACK samples RTT");
    }

    /// The ack flush drops entries UNA already covered (bufferbloat
    /// jitter) except the newest — one stale batch collapses to a single
    /// emitted ACK.
    #[test]
    fn stale_acks_filtered_except_newest() {
        let mut k = fast3();
        k.update(0).unwrap();
        // Deliver PUSH 0,1,2 — all queued for ack, and rcv_nxt slides
        // past them so all three are stale at flush time.
        let mut buf = Vec::new();
        for sn in 0..3u32 {
            buf.extend_from_slice(&push(1, 32, 0, sn, 0, &[]));
        }
        k.input(&buf, true, false).unwrap();
        assert_eq!(k.rcv_nxt, 3);

        k.update(50).unwrap(); // maintenance flush
        assert_eq!(wire_cmds(&k), vec![(KCP_CMD_ACK, 2)]);
    }

    /// `parse_ack` marks lazily: the segment stays in `snd_buf` (never
    /// retransmitted) until `parse_una` slides past it.
    #[test]
    fn acked_segments_stay_until_una() {
        let mut k = fast3();
        k.update(0).unwrap();
        k.send(b"0").unwrap();
        k.send(b"1").unwrap();
        k.update(10).unwrap();
        assert_eq!(k.snd_buf.len(), 2);

        // ACK sn=0 — marked, retained, snd_una still 0.
        k.input(&ack(1, 32, 10, 0, 0), true, false).unwrap();
        assert_eq!(k.snd_buf.len(), 2);
        assert!(k.snd_buf[0].acked);
        assert_eq!(k.snd_una, 0);

        // UNA slide pops it.
        k.input(&ack(1, 32, 10, 1, 1), true, false).unwrap();
        assert_eq!(k.snd_buf.len(), 1);
        assert_eq!(k.snd_una, 1);
    }

    /// An acked-but-not-una'd segment must never retransmit — the resend
    /// pass skips `acked` entries.
    #[test]
    fn acked_segments_never_retransmit() {
        let mut k = fast3();
        k.update(0).unwrap();
        k.send(b"a").unwrap();
        k.send(b"b").unwrap();
        k.update(10).unwrap(); // PUSH 0,1
        let base = wire_cmds(&k).len();

        // ACK sn=0 without una slide — seg0 marked acked.
        k.input(&ack(1, 32, 10, 0, 0), true, false).unwrap();

        // Force an RTO on seg1 only.
        let t = k.snd_buf[1].resendts + 1;
        k.update(t).unwrap();
        let after = wire_cmds(&k);
        let resends: Vec<u32> = after[base..]
            .iter()
            .filter(|&&(c, _)| c == KCP_CMD_PUSH)
            .map(|&(_, s)| s)
            .collect();
        assert_eq!(resends, vec![1], "only the unacked seg retransmits");
    }

    /// Upstream `Send` hard-caps at 255 fragments and rejects an empty
    /// buffer; `WndSize` applies exact values (no 128 floor).
    #[test]
    fn send_fragment_cap_and_empty() {
        let mut k = fast3();
        assert!(k.send(&[]).is_err());
        let mss = k.mss();
        assert_eq!(k.send(&vec![0u8; 255 * mss]).unwrap(), 255 * mss);
        assert!(k.send(&vec![0u8; 256 * mss]).is_err());

        k.set_wndsize(0, 1);
        assert_eq!(k.rcv_wnd, 1, "no 128 floor upstream");
        k.set_wndsize(0, 0);
        assert_eq!(k.rcv_wnd, 1, "zero keeps the previous value");
    }

    /// Upstream `SetMtu` rejects only `mtu <= 24`.
    #[test]
    fn mtu_bound_matches_upstream() {
        let mut k = fast3();
        assert!(k.set_mtu(24).is_err());
        assert!(k.set_mtu(25).is_ok());
        assert_eq!(k.mss(), 1);
    }

    /// Sequence numbers wrap at u32::MAX — every ordering decision goes
    /// through `timediff`, and UNA/UNA-slide arithmetic is `wrapping_*`.
    /// Drive both directions across the boundary.
    #[test]
    fn seq_numbers_wraparound() {
        let mut k = fast3();
        k.snd_nxt = u32::MAX - 1;
        k.snd_una = k.snd_nxt;
        k.rcv_nxt = k.snd_nxt;
        k.update(0).unwrap();

        k.send(b"a").unwrap();
        k.send(b"b").unwrap();
        k.update(10).unwrap();
        let wire = wire_cmds(&k);
        assert!(wire.contains(&(KCP_CMD_PUSH, u32::MAX - 1)));
        assert!(wire.contains(&(KCP_CMD_PUSH, u32::MAX)));

        // UNA slides across the wrap — parse_una must pop both.
        k.input(&ack(1, 32, 10, u32::MAX, 0), true, false).unwrap();
        assert_eq!(k.snd_una, 0);
        assert!(k.snd_buf.is_empty());

        // Send past the wrap again: sn=0.
        k.send(b"c").unwrap();
        k.update(20).unwrap();
        assert!(wire_cmds(&k).contains(&(KCP_CMD_PUSH, 0)));

        // Receive side across the wrap: sn MAX-1, MAX, 0 in order.
        let mut buf = Vec::new();
        for sn in [u32::MAX - 1, u32::MAX, 0] {
            buf.extend_from_slice(&push(1, 32, 0, sn, 0, b"p"));
        }
        k.input(&buf, true, false).unwrap();
        assert_eq!(k.rcv_nxt, 1);

        // Each PUSH is its own frg=0 message — three recv calls.
        let mut out = [0u8; 4];
        for _ in 0..3 {
            let n = k.recv(&mut out).unwrap();
            assert_eq!(&out[..n], b"p");
        }
    }

    /// Zero remote window arms the WASK probe after `probe_wait`; a peer
    /// WASK draws a WINS reply carrying `wnd_unused`.
    #[test]
    fn window_probe_wask_wins() {
        let mut k = fast3();
        k.update(0).unwrap();
        k.send(b"x").unwrap();
        k.update(10).unwrap();

        // Peer advertises wnd=0 and slides una — the FULL flush arms
        // the probe timer (probe_wait = KCP_PROBE_INIT).
        k.input(&ack(1, 0, 10, 0, 1), true, false).unwrap();
        assert_eq!(k.rmt_wnd, 0);
        assert_eq!(k.probe_wait, KCP_PROBE_INIT);

        // Past ts_probe → next flush emits WASK.
        let t = k.ts_probe + 1;
        k.update(t).unwrap();
        assert!(wire_cmds(&k).iter().any(|&(c, _)| c == KCP_CMD_WASK));
        assert!(k.probe_wait > KCP_PROBE_INIT, "escalating backoff");

        // Peer probes us → WINS on the next flush.
        k.input(&seg(1, KCP_CMD_WASK, 32, 0, 0, 0, &[]), true, false)
            .unwrap();
        let base = wire_cmds(&k).len();
        k.update(t + 20).unwrap();
        assert!(wire_cmds(&k)[base..]
            .iter()
            .any(|&(c, _)| c == KCP_CMD_WINS));

        // Window reopens → probe state resets.
        k.input(&ack(1, 64, 0, 0, 0), true, false).unwrap();
        k.update(t + 40).unwrap();
        assert_eq!(k.probe_wait, 0);
    }

    /// After the RTO arm resets `fastack` to 0, a fresh dup-ack burst
    /// fast-retransmits again — the sentinel is per-RTO, not permanent.
    #[test]
    fn fast_retransmit_rearms_after_rto() {
        let mut k = fast3(); // resend=2
        k.update(0).unwrap();
        k.send(b"a").unwrap();
        k.send(b"b").unwrap();
        k.update(10).unwrap(); // PUSH 0,1

        // First fast retransmit of sn=0 → sentinel.
        k.input(&ack(1, 32, 10, 1, 0), true, false).unwrap();
        k.input(&ack(1, 32, 10, 1, 0), true, false).unwrap();
        assert_eq!(k.snd_buf[0].fastack, 0xFFFFFFFF);
        let xmit_after_fast = k.snd_buf[0].xmit;

        // Force an RTO on sn=0 — resets fastack for the next round.
        let t = k.snd_buf[0].resendts + 1;
        k.update(t).unwrap();
        assert_eq!(k.snd_buf[0].fastack, 0, "RTO arm resets fastack");

        // Another dup-ack burst fast-retransmits sn=0 again.
        let base = wire_cmds(&k).len();
        for _ in 0..2 {
            k.input(&ack(1, 32, t, 1, 0), true, false).unwrap();
        }
        let after = wire_cmds(&k);
        assert!(
            after[base..].contains(&(KCP_CMD_PUSH, 0)),
            "fast retransmit must fire again after RTO reset"
        );
        assert!(k.snd_buf[0].xmit > xmit_after_fast);
    }

    /// `nodelay` halves the linear RTO backoff (`+rx_rto/2`).
    #[test]
    fn nodelay_halves_rto_backoff() {
        let mut k = Kcp::new(1, Sink::default());
        k.set_nodelay(true, 10, 2, false);
        k.update(0).unwrap();
        k.send(b"data").unwrap();
        k.update(10).unwrap();
        assert_eq!(k.snd_buf[0].rto, k.rx_rto);

        let t1 = k.snd_buf[0].resendts + 1;
        k.update(t1).unwrap();
        assert_eq!(
            k.snd_buf[0].rto,
            k.rx_rto + k.rx_rto / 2,
            "nodelay backoff is +rx_rto/2"
        );
    }

    /// Stream mode (the mode `KcpStream` uses) coalesces consecutive
    /// sends into one segment — distinct-segment tests use `new`.
    #[test]
    fn stream_mode_coalesces_sends() {
        let mut k = Kcp::new_stream(1, Sink::default());
        k.set_nodelay(true, 10, 2, true);
        k.update(0).unwrap();
        k.send(b"ab").unwrap();
        k.send(b"cd").unwrap();
        k.update(10).unwrap();

        let wire = wire_cmds(&k);
        let pushes = wire.iter().filter(|&&(c, _)| c == KCP_CMD_PUSH).count();
        assert_eq!(pushes, 1, "two sends merge into one segment");
    }

    /// RFC 6298-variant estimator: the first sample seeds srtt/rttval,
    /// a below-floor sample takes the damped `>>5` branch, a normal one
    /// `>>2`, and `rx_minrto` clamps tiny RTTs (upstream `update_ack`).
    #[test]
    fn rtt_estimator_tracks_upstream() {
        let mut k = fast3(); // nodelay → rx_minrto = 30, interval = 10
        k.update(0).unwrap();
        k.send(b"a").unwrap();
        k.send(b"b").unwrap();
        k.send(b"c").unwrap();
        k.update(10).unwrap(); // PUSH 0,1,2 stamped ts=10

        // First sample (rtt=90) seeds the estimator.
        k.update(100).unwrap();
        k.input(&ack(1, 32, 10, 0, 1), true, false).unwrap();
        assert_eq!(k.rx_srtt, 90);
        assert_eq!(k.rx_rttval, 45);
        assert_eq!(k.rx_rto, 90 + cmp::max(10, 4 * 45));

        // Normal sample (rtt=110): srtt += delta>>3, rttval >>2 branch.
        k.update(120).unwrap();
        k.input(&ack(1, 32, 10, 1, 2), true, false).unwrap();
        // delta=20 → srtt=92; 110 !< 92-45 → rttval += (20-45)>>2 = -7
        assert_eq!(k.rx_srtt, 92);
        assert_eq!(k.rx_rttval, 38);
        assert_eq!(k.rx_rto, 92 + cmp::max(10, 4 * 38));

        // Below-floor sample (forged ts=100 → rtt=30 < srtt-rttvar)
        // takes the damped >>5 branch.
        k.update(130).unwrap();
        k.input(&ack(1, 32, 100, 2, 3), true, false).unwrap();
        // delta=-62 → srtt=84; 30 < 84-38 → rttval += (62-38)>>5 = 0
        assert_eq!(k.rx_srtt, 84);
        assert_eq!(k.rx_rttval, 38);
        assert_eq!(k.rx_rto, 84 + cmp::max(10, 4 * 38));
    }

    /// A sub-interval first sample must still clamp `rx_rto` up to
    /// `rx_minrto` (30 under nodelay) — upstream `bound()` at the end
    /// of `update_ack`.
    #[test]
    fn rtt_estimator_minrto_floor() {
        let mut k = fast3();
        k.update(0).unwrap();
        k.send(b"a").unwrap();
        k.update(10).unwrap();
        k.update(11).unwrap();
        // rtt=1 → srtt=1, rttval=0 → rto = 1 + max(10, 0) = 11, clamped.
        k.input(&ack(1, 32, 10, 0, 1), true, false).unwrap();
        assert_eq!(k.rx_rto, 30);
    }

    /// Upstream Reno state machine under `nc=0` (reachable via
    /// `mode=manual`): `cwnd` bootstraps 0→1 at the first flush tail,
    /// slow-start grows it one packet per UNA-advancing input, AIMD
    /// accumulates `incr` bytes past `ssthresh`, fast retransmit halves
    /// and RTO collapses to one packet.
    #[test]
    fn cwnd_reno_state_machine() {
        let mut k = Kcp::new(1, Sink::default());
        k.set_nodelay(true, 10, 2, false); // nc=0 → congestion control on
        let mss = k.mss as u32; // 1376 at the default MTU

        k.update(0).unwrap(); // first flush tail bootstraps cwnd 0→1
        assert_eq!((k.cwnd, k.incr), (1, mss));

        for _ in 0..10 {
            k.send(b"payload").unwrap();
        }
        k.update(10).unwrap(); // effective window min(32, 32, cwnd=1)
        assert_eq!(wire_cmds(&k), vec![(KCP_CMD_PUSH, 0)]);

        // UNA slide → slow start: cwnd 1→2, incr += mss.
        k.input(&ack(1, 32, 10, 0, 1), true, false).unwrap();
        assert_eq!((k.cwnd, k.incr), (2, 2 * mss));
        assert_eq!(
            wire_cmds(&k),
            vec![(KCP_CMD_PUSH, 0), (KCP_CMD_PUSH, 1), (KCP_CMD_PUSH, 2)]
        );

        // cwnd reached ssthresh=2 → AIMD: incr += mss*mss/incr + mss/16,
        // cwnd restamps only when (cwnd+1)*mss <= incr.
        k.input(&ack(1, 32, 10, 2, 3), true, false).unwrap();
        let incr = 2 * mss + mss * mss / (2 * mss) + mss / 16;
        assert_eq!(k.incr, incr);
        assert_eq!(k.cwnd, 2, "3*mss not yet accumulated");

        k.input(&ack(1, 32, 10, 4, 5), true, false).unwrap();
        let incr = incr + mss * mss / incr + mss / 16;
        assert_eq!(k.incr, incr);
        assert_eq!(k.cwnd, incr.div_ceil(mss), "AIMD restamp");
        assert_eq!(k.cwnd, 4);

        // ACK sn=6 with una=5: marks 6, bumps seg5's fastack — but does
        // not advance una, so no cwnd growth.
        k.input(&ack(1, 32, 10, 6, 5), true, false).unwrap();
        k.input(&ack(1, 32, 10, 6, 5), true, false).unwrap();
        // second dup → fastack hits resent=2 → retransmit + halving:
        // ssthresh = max(inflight/2, 2), cwnd = ssthresh + resent.
        assert!(
            wire_cmds(&k)
                .iter()
                .any(|&(c, s)| c == KCP_CMD_PUSH && s == 5),
            "seg5 fast-retransmitted"
        );
        assert_eq!(k.ssthresh, cmp::max((9 - 5) / 2, 2));
        assert_eq!(k.cwnd, k.ssthresh + 2);
        assert_eq!(k.incr, k.cwnd * mss);

        // RTO on seg5 → collapse to slow start.
        let t1 = k.snd_buf[0].resendts + 1;
        k.update(t1).unwrap();
        assert_eq!((k.cwnd, k.incr), (1, mss));
        assert_eq!(k.ssthresh, cmp::max(4 / 2, 2));
    }

    /// Emitted wire fields, not just (cmd, sn): ACKs echo the PUSH `ts`
    /// and stamp live `una`/`wnd`; retransmits restamp all three.
    #[test]
    fn emitted_headers_carry_echoed_ts_and_live_wnd_una() {
        let mut k = fast3();
        k.update(0).unwrap();
        k.input(&push(1, 32, 1234, 0, 0, b"hi"), true, false)
            .unwrap();
        k.update(10).unwrap(); // maintenance flush emits the queued ACK

        let mut cur = Cursor::new(&k.output.0 .0[0][..]);
        assert_eq!(cur.get_u32_le(), 1); // conv
        assert_eq!(cur.get_u8(), KCP_CMD_ACK);
        let _frg = cur.get_u8();
        assert_eq!(cur.get_u16_le(), 31, "wnd = wnd_unused = 32 - 1");
        assert_eq!(cur.get_u32_le(), 1234, "ACK echoes the PUSH ts");
        let _sn = cur.get_u32_le();
        assert_eq!(cur.get_u32_le(), 1, "una = rcv_nxt after sn=0");

        // Retransmit restamps ts/wnd/una on the PUSH itself.
        k.send(b"x").unwrap();
        k.update(20).unwrap(); // PUSH sn=0, ts=20
        let t1 = k.snd_buf[0].resendts + 1;
        k.update(t1).unwrap(); // RTO → re-PUSH
        let last = k.output.0 .0.last().unwrap();
        let mut cur = Cursor::new(&last[..]);
        let _conv = cur.get_u32_le();
        assert_eq!(cur.get_u8(), KCP_CMD_PUSH);
        let _frg = cur.get_u8();
        assert_eq!(cur.get_u16_le(), 31);
        assert_eq!(cur.get_u32_le(), t1, "retransmit stamps fresh ts");
        let _sn = cur.get_u32_le();
        assert_eq!(cur.get_u32_le(), 1, "una still rcv_nxt");
    }

    /// `parse_data` ingress: out-of-window segments are neither ACKed
    /// nor buffered, duplicates dedup, out-of-order PUSHes reorder.
    #[test]
    fn parse_data_bounds_dedup_and_reorders() {
        let mut k = fast3();
        k.update(0).unwrap();
        // sn = rcv_nxt + rcv_wnd → outside the window entirely.
        k.input(&push(1, 32, 0, 32, 0, b"far"), true, false)
            .unwrap();
        assert!(k.rcv_buf.is_empty());
        assert!(k.acklist.is_empty(), "out-of-window gets no ACK");

        for (sn, p) in [(2u32, &b"c"[..]), (1, &b"b"[..]), (0, &b"a"[..])] {
            k.input(&push(1, 32, 0, sn, 0, p), true, false).unwrap();
        }
        k.input(&push(1, 32, 0, 1, 0, b"b"), true, false).unwrap(); // dup

        let mut buf = [0u8; 8];
        for &expected in b"abc" {
            assert_eq!(k.recv(&mut buf).unwrap(), 1);
            assert_eq!(buf[0], expected);
        }
        assert_eq!(k.rcv_nxt, 3);
    }

    /// Early retransmit is gated on `new_segs == 0`: a dup-ack while
    /// fresh data is queued slides and sends the new data instead —
    /// only an empty queue spends the resend.
    #[test]
    fn early_retransmit_waits_for_empty_queue() {
        let mut k = Kcp::new(1, Sink::default());
        k.set_nodelay(true, 10, 0, true); // resend=0 → early-retransmit only
        k.update(0).unwrap();
        k.send(b"a").unwrap();
        k.send(b"b").unwrap();
        k.update(10).unwrap(); // PUSH 0,1
        k.send(b"c").unwrap(); // queued, unsent

        // Dup-ack sn=1/una=0: marks 1 acked, bumps seg0's fastack, but
        // the queued "c" must slide first — no resend of sn=0.
        k.input(&ack(1, 32, 10, 1, 0), true, false).unwrap();
        let pushes: Vec<u32> = wire_cmds(&k)
            .iter()
            .filter(|&&(c, _)| c == KCP_CMD_PUSH)
            .map(|&(_, s)| s)
            .collect();
        assert_eq!(pushes, vec![0, 1, 2]);

        // Same dup-ack with an empty queue → early retransmit fires.
        k.input(&ack(1, 32, 10, 1, 0), true, false).unwrap();
        let pushes: Vec<u32> = wire_cmds(&k)
            .iter()
            .filter(|&&(c, _)| c == KCP_CMD_PUSH)
            .map(|&(_, s)| s)
            .collect();
        assert_eq!(pushes, vec![0, 1, 2, 0]);
    }

    /// Pin the anti-spin divergence: `check()` skips `acked` segments
    /// (stale `resendts` never re-arms) and `xmit == 0` segments (the
    /// next FULL flush covers them via `tm_flush`). Without the skips
    /// a poll-driven caller re-arms a 0ms timer forever.
    #[test]
    fn check_ignores_acked_and_unsent_segments() {
        let mut k = fast3();
        k.update(0).unwrap();
        k.send(b"a").unwrap();
        k.update(10).unwrap(); // PUSH sn=0; ts_flush=20
        k.input(&ack(1, 32, 10, 0, 0), true, false).unwrap(); // acked, retained
        k.snd_buf[0].resendts = 5; // stale — due "now"
        assert_eq!(k.check(15), 5, "acked seg must not report due-now");

        k.snd_buf[0].acked = false;
        k.snd_buf[0].xmit = 0; // slid in by an AckOnly flush
        k.snd_buf[0].resendts = 0;
        assert_eq!(k.check(15), 5, "xmit==0 seg defers to tm_flush");
    }
}
