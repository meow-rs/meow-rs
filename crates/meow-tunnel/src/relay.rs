// M2 relay-buffer-pool (ADR-0011 T6):
//   `tokio::io::copy_bidirectional_with_sizes` allocates a `Box<[u8]>` per
//   direction per connection (via `CopyBuffer::new`). At 4 KiB per direction
//   that is 8 KiB heap per TCP connection setup — confirmed in the dhat
//   baseline as sites #2 and #3 (66 MB each over 8 105 connections).
//
//   This module provides `copy_bidirectional_buf` which accepts caller-supplied
//   `&mut [u8]` scratch buffers. Callers declare `[0u8; BUF]` arrays inside the
//   enclosing async fn; those arrays become part of the future's state machine
//   and are paid for at task-spawn time (one allocation per task, shared with
//   everything else in the future), not at relay-call time.
//
//   Public API: `copy_bidirectional_buf` and `RELAY_BUF_SIZE`.
//   No new public types exposed — no M2 API break.
//
// Direction fairness (#345):
//   The two directions are driven by ONE future, so they can never run on two
//   cores at once — but they must not starve each other either. Each direction
//   advances at most one buffer fill+drain cycle per turn, and turns strictly
//   alternate a→b, b→a inside the poll loop. A busy direction therefore delays
//   the other by at most one `RELAY_BUF_SIZE` cycle, instead of monopolizing
//   the task until its reader runs dry (the pre-#345 behavior, where a→b was
//   always polled first and drained to `Pending` before b→a ever ran).
//   `RELAY_CYCLES_PER_POLL` additionally bounds total work per poll so the
//   relay yields to sibling tasks even on streams that don't participate in
//   tokio's coop budget.
//
// Kernel splice (Linux / Android):
//   When both endpoints of a direction are bare TCP sockets (a SOCKS5 /
//   HTTP CONNECT / TProxy client relayed to DIRECT), the bulk tier is a pipe
//   instead of the 32 KiB buffer: `splice(2)` moves the bytes socket to
//   pipe to socket without copying them through userspace, which is how the
//   Go runtime relays TCP to TCP. Callers opt in through
//   [`copy_bidirectional_buf_tracked_splice`] and a [`TcpView`] per endpoint.

use meow_common::ProxyConn;
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Buffer size used for each relay direction at connection setup.
/// 4 KiB halves the tokio default (8 KiB) to save 8 KiB/conn at the
/// cost of more syscalls; acceptable for proxy workloads where connections
/// are long-lived and latency matters less than memory at 5k+ conns.
/// Directions that prove bulk are upgraded to the private
/// `RELAY_BULK_BUF_SIZE` (32 KiB) — see the tiered-buffer note below.
pub const RELAY_BUF_SIZE: usize = 4 * 1024;

/// Tiered bulk buffer (#386): once a direction has relayed
/// [`RELAY_BULK_UPGRADE_BYTES`], its scratch buffer is swapped for a
/// heap-allocated buffer of this size, matching Go mihomo's 32 KiB relay
/// buffers. At 4 KiB the relay is syscall-bound on fast paths — one
/// read+write pair per 4 KiB left bulk throughput ~40% behind mihomo
/// (19 vs 31 Gbps loopback, see the issue) — while at 32 KiB the gap closes
/// to parity. The upgrade is lazy so the per-connection footprint at 5k+
/// mostly-idle connections stays at the small stack buffers; only
/// connections that actually stream pay the 32 KiB, amortized over at least
/// [`RELAY_BULK_UPGRADE_BYTES`] of traffic. The one-time allocation is far
/// past HP-1's warmup window and amortizes to ~0.0001 allocations per
/// iteration over its 10k-iteration budget (ADR-0008 §3 threshold 0.5).
const RELAY_BULK_BUF_SIZE: usize = 32 * 1024;

/// Bytes a direction must relay before its scratch buffer is upgraded to
/// [`RELAY_BULK_BUF_SIZE`]. Typical request/response exchanges stay below
/// this and never allocate; a bulk stream crosses it in single-digit
/// milliseconds.
const RELAY_BULK_UPGRADE_BYTES: u64 = 128 * 1024;

/// Idle window granted to the surviving relay direction after the *other*
/// direction has reached EOF.
///
/// Without a bound, a peer that closes one half of the connection and then
/// holds its read side open forever pins this future — and with it both
/// underlying sockets. That surfaces as leaked CLOSE-WAIT sockets on the
/// inbound (client) side (the client sent FIN but meow never `close()`s its
/// socket) and FIN-WAIT-2 on the outbound side. The reference mihomo kernel
/// avoids this by tearing the whole relay down once *either* direction
/// completes; this linger is the equivalent, but lenient.
///
/// The window is an **idle timeout, not an absolute deadline**: it is re-armed
/// every time the surviving direction transfers more bytes, so a legitimate
/// half-closed connection that keeps streaming (e.g. a client that shuts down
/// its write side after a request, then downloads a large response) is never
/// truncated mid-transfer. Only a connection that goes genuinely silent for the
/// full window — no progress in either direction — is reaped. A normal
/// simultaneous close drains in microseconds, far inside the window.
pub const RELAY_HALF_CLOSE_LINGER: Duration = Duration::from_secs(30);

/// Upper bound on buffer fill+drain cycles executed per `poll_fn` invocation
/// across both directions before the relay voluntarily yields back to the
/// scheduler (self-waking first, so it is promptly re-polled).
///
/// Real sockets already hit tokio's per-task coop budget (128 ops) around the
/// same magnitude, but coop is an implementation detail of tokio's leaf
/// resources — custom `ProxyConn` stacks (or the in-memory streams used in
/// tests) may never return `Pending` on their own. This cap makes the yield
/// deterministic: at 4 KiB per cycle it bounds one poll at 256 KiB relayed.
const RELAY_CYCLES_PER_POLL: u32 = 64;

/// Byte-based companion to [`RELAY_CYCLES_PER_POLL`]: after bulk upgrade a
/// single cycle moves up to 32 KiB, so 64 cycles would stretch one poll to
/// 2 MiB. Yield once this many bytes have moved in a poll instead, keeping
/// the pre-upgrade 256 KiB-per-poll bound regardless of buffer size.
const RELAY_BYTES_PER_POLL: u64 = 256 * 1024;

// ---------------------------------------------------------------------------
// Internal copy-one-direction state (no heap allocation)
// ---------------------------------------------------------------------------

/// Outcome of one [`HalfCopy::poll_cycle`] turn.
enum Cycle {
    /// EOF reached, buffer fully flushed, writer shutdown complete.
    Done,
    /// The cycle moved data and the direction may have more work available —
    /// give the peer direction a turn, then call again.
    Progress,
    /// Blocked on the reader or the writer; a waker is registered.
    Pending,
}

/// The kernel TCP socket behind a relay endpoint, when the endpoint reads
/// and writes it byte for byte. A direction whose reader and writer both
/// have one relays its bulk traffic with `splice(2)` on Linux and Android.
pub type TcpView<T> = for<'x> fn(&'x T) -> Option<&'x TcpStream>;

/// [`TcpView`] of a bare socket.
pub fn tcp_view(stream: &TcpStream) -> Option<&TcpStream> {
    Some(stream)
}

/// [`TcpView`] of a dialed connection: `Some` only when the adapter hands
/// back the socket itself (DIRECT), see [`ProxyConn::tcp_stream`].
pub fn proxy_conn_tcp_view(conn: &dyn ProxyConn) -> Option<&TcpStream> {
    conn.tcp_stream()
}

/// Per-direction scratch storage: the caller's stack array until the
/// direction proves bulk, then a one-time owned upgrade (#386), or a splice
/// pipe when both of its endpoints are bare sockets.
enum Scratch<'buf> {
    Borrowed(&'buf mut [u8]),
    Owned(Box<[u8]>),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Pipe(splice::Pipe),
}

/// The bulk tier for a direction (#386): a splice pipe when the platform
/// has `splice(2)` and both endpoints are bare sockets, otherwise (or when
/// the pipe cannot be created, e.g. at the fd limit) the owned
/// [`RELAY_BULK_BUF_SIZE`] buffer.
fn bulk_scratch<'buf, R: ?Sized, W: ?Sized>(
    reader: &R,
    writer: &W,
    views: Option<(TcpView<R>, TcpView<W>)>,
) -> Scratch<'buf> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some((reader_tcp, writer_tcp)) = views {
        if reader_tcp(reader).is_some() && writer_tcp(writer).is_some() {
            if let Some(pipe) = splice::Pipe::new() {
                return Scratch::Pipe(pipe);
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = (reader, writer, views);
    Scratch::Owned(vec![0u8; RELAY_BULK_BUF_SIZE].into_boxed_slice())
}

fn poll_read_into<R: AsyncRead + Unpin + ?Sized>(
    cx: &mut Context<'_>,
    reader: &mut R,
    buf: &mut [u8],
) -> Poll<io::Result<usize>> {
    let mut rb = ReadBuf::new(buf);
    Pin::new(reader)
        .poll_read(cx, &mut rb)
        .map_ok(|()| rb.filled().len())
}

/// Whether a direction that has relayed `amt` bytes through a `buf_len`-byte
/// scratch buffer should upgrade to the owned [`RELAY_BULK_BUF_SIZE`] buffer.
/// Callers that already supply a bulk-sized (or larger) buffer never upgrade.
fn wants_bulk_upgrade(amt: u64, buf_len: usize) -> bool {
    amt >= RELAY_BULK_UPGRADE_BYTES && buf_len < RELAY_BULK_BUF_SIZE
}

struct HalfCopy<'buf> {
    buf: Scratch<'buf>,
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    need_flush: bool,
}

impl<'buf> HalfCopy<'buf> {
    fn new(buf: &'buf mut [u8]) -> Self {
        Self {
            buf: Scratch::Borrowed(buf),
            read_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
            need_flush: false,
        }
    }

    /// Advance this direction by at most ONE buffer fill+drain cycle.
    ///
    /// The pre-#345 `poll_copy` looped read→write until `Pending`, so a busy
    /// direction monopolized the poll while the peer direction waited. Capping
    /// each turn at a single cycle lets the caller interleave the two
    /// directions fairly; the caller loops as long as either side reports
    /// [`Cycle::Progress`].
    ///
    /// `views` find the reader's and writer's sockets for the splice tier;
    /// in pipe mode `pos..cap` counts the bytes sitting in the pipe.
    fn poll_cycle<R, W, F>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        writer: &mut W,
        views: Option<(TcpView<R>, TcpView<W>)>,
        on_progress: &mut F,
    ) -> io::Result<Cycle>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
        F: FnMut(u64),
    {
        // Refill the buffer when empty — at most one read per cycle.
        if self.pos == self.cap && !self.read_done {
            // Tiered upgrade (#386): the buffer is empty, so swapping it is
            // safe — no buffered bytes to carry over. One allocation (or one
            // pipe) per bulk direction for the connection's remaining lifetime.
            if let Scratch::Borrowed(buf) = &self.buf {
                if wants_bulk_upgrade(self.amt, buf.len()) {
                    self.buf = bulk_scratch(&*reader, &*writer, views);
                }
            }
            let read = match &mut self.buf {
                Scratch::Borrowed(buf) => poll_read_into(cx, reader, buf),
                Scratch::Owned(buf) => poll_read_into(cx, reader, buf),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Scratch::Pipe(pipe) => match views.and_then(|(reader_tcp, _)| reader_tcp(reader)) {
                    Some(src) => pipe.poll_fill(cx, src),
                    None => Poll::Ready(Err(splice::lost_socket())),
                },
            };
            match read {
                Poll::Ready(Ok(0)) => self.read_done = true,
                Poll::Ready(Ok(filled)) => {
                    self.pos = 0;
                    self.cap = filled;
                }
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => {
                    // Nothing buffered and the reader is idle: push written
                    // bytes to the peer before parking this direction.
                    if self.need_flush {
                        match Pin::new(&mut *writer).poll_flush(cx) {
                            Poll::Ready(Ok(())) => self.need_flush = false,
                            Poll::Ready(Err(e)) => return Err(e),
                            Poll::Pending => return Ok(Cycle::Pending),
                        }
                    }
                    return Ok(Cycle::Pending);
                }
            }
        }

        // Drain buffered data to the writer.
        while self.pos < self.cap {
            let written = match &mut self.buf {
                Scratch::Borrowed(buf) => {
                    Pin::new(&mut *writer).poll_write(cx, &buf[self.pos..self.cap])
                }
                Scratch::Owned(buf) => {
                    Pin::new(&mut *writer).poll_write(cx, &buf[self.pos..self.cap])
                }
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Scratch::Pipe(pipe) => match views.and_then(|(_, writer_tcp)| writer_tcp(writer)) {
                    Some(dst) => pipe.poll_drain(cx, dst, self.cap - self.pos),
                    None => Poll::Ready(Err(splice::lost_socket())),
                },
            };
            match written {
                Poll::Ready(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero bytes to writer",
                    ));
                }
                Poll::Ready(Ok(n)) => {
                    self.pos += n;
                    self.amt += n as u64;
                    on_progress(n as u64);
                    self.need_flush = true;
                }
                Poll::Ready(Err(e)) => return Err(e),
                // Blocked on the writer — retrying this direction cannot help
                // until its waker fires, even though bytes may have moved.
                Poll::Pending => return Ok(Cycle::Pending),
            }
        }

        if self.read_done {
            return match Pin::new(&mut *writer).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => Ok(Cycle::Done),
                Poll::Ready(Err(e)) => Err(e),
                Poll::Pending => Ok(Cycle::Pending),
            };
        }

        // Buffer drained and the reader has not hit EOF: more work may be
        // immediately available next turn.
        Ok(Cycle::Progress)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Bidirectional relay using caller-supplied scratch buffers.
///
/// `buf_a_to_b` and `buf_b_to_a` are borrowed for the duration of the copy;
/// they must be at least 1 byte (typically `RELAY_BUF_SIZE`).
/// Callers declare these as `[0u8; RELAY_BUF_SIZE]` arrays in the enclosing
/// async fn so they live in the future's state machine — zero per-relay heap
/// allocation (ADR-0011 T6 / ADR-0008 HP-1 goal).
///
/// Returns `(bytes_a_to_b, bytes_b_to_a)`.
pub async fn copy_bidirectional_buf<A, B>(
    a: &mut A,
    b: &mut B,
    buf_a_to_b: &mut [u8],
    buf_b_to_a: &mut [u8],
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    copy_bidirectional_buf_tracked(a, b, buf_a_to_b, buf_b_to_a, |_| {}, |_| {}).await
}

/// Tracked variant of [`copy_bidirectional_buf`]. The callbacks run after
/// bytes are successfully written in each direction, allowing live traffic
/// and connection statistics without waiting for relay completion.
pub async fn copy_bidirectional_buf_tracked<A, B, FA, FB>(
    a: &mut A,
    b: &mut B,
    buf_a_to_b: &mut [u8],
    buf_b_to_a: &mut [u8],
    on_a_to_b: FA,
    on_b_to_a: FB,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    FA: FnMut(u64),
    FB: FnMut(u64),
{
    relay(a, b, buf_a_to_b, buf_b_to_a, None, on_a_to_b, on_b_to_a).await
}

/// [`copy_bidirectional_buf_tracked`] for endpoints that may be bare TCP
/// sockets: `views` (for `a`, then `b`) find each endpoint's socket. A
/// direction whose two endpoints both have one switches to `splice(2)` at
/// the bulk tier on Linux and Android, so its bytes never cross into
/// userspace; elsewhere, and for any other direction, this is
/// [`copy_bidirectional_buf_tracked`]. The callbacks see the same byte
/// counts either way.
pub async fn copy_bidirectional_buf_tracked_splice<A, B, FA, FB>(
    a: &mut A,
    b: &mut B,
    buf_a_to_b: &mut [u8],
    buf_b_to_a: &mut [u8],
    views: (TcpView<A>, TcpView<B>),
    on_a_to_b: FA,
    on_b_to_a: FB,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    FA: FnMut(u64),
    FB: FnMut(u64),
{
    relay(
        a,
        b,
        buf_a_to_b,
        buf_b_to_a,
        Some(views),
        on_a_to_b,
        on_b_to_a,
    )
    .await
}

async fn relay<A, B, FA, FB>(
    a: &mut A,
    b: &mut B,
    buf_a_to_b: &mut [u8],
    buf_b_to_a: &mut [u8],
    views: Option<(TcpView<A>, TcpView<B>)>,
    mut on_a_to_b: FA,
    mut on_b_to_a: FB,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    FA: FnMut(u64),
    FB: FnMut(u64),
{
    let views_b_to_a = views.map(|(a_tcp, b_tcp)| (b_tcp, a_tcp));
    let mut a_to_b = HalfCopy::new(buf_a_to_b);
    let mut b_to_a = HalfCopy::new(buf_b_to_a);
    let mut a_done = false;
    let mut b_done = false;

    // Linger timer reaping a half-closed-then-stuck connection. Created up front
    // so it can be pinned on the stack (no per-relay heap allocation), but not
    // polled — and therefore not registered with the timer driver — until one
    // direction has finished and the other is still running. See
    // `RELAY_HALF_CLOSE_LINGER`.
    let linger = tokio::time::sleep(RELAY_HALF_CLOSE_LINGER);
    tokio::pin!(linger);
    let mut linger_armed = false;
    // Bytes transferred by the surviving direction when the linger was last
    // (re)armed. Used to re-arm the idle window on every byte of progress so an
    // active half-closed transfer is never truncated. See `RELAY_HALF_CLOSE_LINGER`.
    let mut linger_progress: u64 = 0;

    poll_fn(move |cx| {
        // Fair interleave (#345): alternate single fill+drain cycles between
        // the directions instead of draining one to `Pending` before touching
        // the other. Loop while either direction reports `Progress`, up to
        // `RELAY_CYCLES_PER_POLL` progress cycles per poll.
        //
        // Once a direction returns `Pending` it is parked for the REST of this
        // poll: it can only become ready again by waking the task (which
        // re-enters this closure), so re-polling it every iteration would just
        // burn a readiness check + waker re-registration per 4 KiB cycle of
        // the busy direction. A readiness event that fires while we are still
        // looping marks the task notified and triggers an immediate re-poll,
        // so no wakeup is lost by parking.
        let mut cycles: u32 = 0;
        let poll_start_bytes = a_to_b.amt + b_to_a.amt;
        let mut a_parked = false;
        let mut b_parked = false;
        loop {
            let mut progressed = false;

            if !a_done && !a_parked {
                match a_to_b.poll_cycle(cx, &mut *a, &mut *b, views, &mut on_a_to_b) {
                    Ok(Cycle::Done) => a_done = true,
                    Ok(Cycle::Progress) => {
                        progressed = true;
                        cycles += 1;
                    }
                    Ok(Cycle::Pending) => a_parked = true,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            if !b_done && !b_parked {
                match b_to_a.poll_cycle(cx, &mut *b, &mut *a, views_b_to_a, &mut on_b_to_a) {
                    Ok(Cycle::Done) => b_done = true,
                    Ok(Cycle::Progress) => {
                        progressed = true;
                        cycles += 1;
                    }
                    Ok(Cycle::Pending) => b_parked = true,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            if a_done && b_done {
                return Poll::Ready(Ok((a_to_b.amt, b_to_a.amt)));
            }

            if !progressed {
                break;
            }

            if cycles >= RELAY_CYCLES_PER_POLL
                || (a_to_b.amt + b_to_a.amt) - poll_start_bytes >= RELAY_BYTES_PER_POLL
            {
                // Yield to sibling tasks; self-wake so the scheduler re-polls
                // this relay promptly. The byte bound keeps one poll at
                // ~256 KiB even after a bulk buffer upgrade.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        // Exactly one direction has finished while the other is still open.
        // Arm the idle window on that transition and re-arm it on every byte the
        // surviving direction makes progress, then let it race that direction:
        // whichever resolves first ends the relay. Because the window resets on
        // progress, an actively-streaming half-closed connection is never
        // truncated — only one that goes silent for the full window is reaped.
        // The surviving direction is re-polled above on every wake, so if it
        // drains before the timer fires we still return the full byte counts.
        if a_done || b_done {
            let surviving_amt = if a_done { b_to_a.amt } else { a_to_b.amt };
            if !linger_armed || surviving_amt != linger_progress {
                linger_armed = true;
                linger_progress = surviving_amt;
                linger
                    .as_mut()
                    .reset(tokio::time::Instant::now() + RELAY_HALF_CLOSE_LINGER);
            }
            if linger.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok((a_to_b.amt, b_to_a.amt)));
            }
        }

        Poll::Pending
    })
    .await
}

/// `splice(2)` plumbing for the bulk tier: socket to pipe to socket, all in
/// the kernel. One pipe per bulk direction, created at the tier upgrade and
/// closed with the relay.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod splice {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::task::{ready, Context, Poll};
    use tokio::io::Interest;
    use tokio::net::TcpStream;

    /// Pipe capacity asked for at creation; the default is 64 KiB.
    const PIPE_SIZE: libc::c_int = 1 << 20;

    #[cfg(test)]
    thread_local! {
        /// Pipes this thread opened, for the tests to tell which tier ran.
        pub(crate) static OPENED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Upper bound per `splice(2)` call; the kernel stops earlier at the
    /// pipe's capacity or at what the socket has queued.
    const MAX_SPLICE: usize = 1 << 20;

    pub(super) struct Pipe {
        rd: OwnedFd,
        wr: OwnedFd,
    }

    impl Pipe {
        /// `None` when splicing could kill the process (see
        /// [`sigpipe_is_handled`]), when it is out of descriptors, or when
        /// the kernel hands out a pipe smaller than the bulk buffer: past
        /// `fs.pipe-user-pages-soft` an unprivileged user's new pipes get
        /// two pages, which would move less per call than the copy.
        pub(super) fn new() -> Option<Self> {
            if !sigpipe_is_handled() {
                return None;
            }
            let mut fds: [libc::c_int; 2] = [-1; 2];
            // SAFETY: `fds` is a valid two-element out-array for pipe2.
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
                return None;
            }
            // SAFETY: pipe2 succeeded, so both fds are open and owned by
            // nothing else.
            let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            // Growing the pipe is best effort, like the Go runtime: past
            // the quota or `fs.pipe-max-size` it keeps its 64 KiB.
            // SAFETY: fcntl on an fd we own.
            unsafe { libc::fcntl(wr.as_raw_fd(), libc::F_SETPIPE_SZ, PIPE_SIZE) };
            // SAFETY: fcntl on an fd we own.
            let size = unsafe { libc::fcntl(wr.as_raw_fd(), libc::F_GETPIPE_SZ) };
            if usize::try_from(size).map_or(true, |size| size < super::RELAY_BULK_BUF_SIZE) {
                return None;
            }
            #[cfg(test)]
            OPENED.with(|n| n.set(n.get() + 1));
            Some(Self { rd, wr })
        }

        /// Move what `src` has queued into this empty pipe; `Ok(0)` is EOF.
        pub(super) fn poll_fill(
            &self,
            cx: &mut Context<'_>,
            src: &TcpStream,
        ) -> Poll<io::Result<usize>> {
            let wr = self.wr.as_raw_fd();
            loop {
                ready!(src.poll_read_ready(cx))?;
                // The pipe is empty, so `WouldBlock` can only mean the
                // socket ran dry: `try_io` clears its readiness and the
                // next `poll_read_ready` parks the task.
                match src.try_io(Interest::READABLE, || {
                    splice(src.as_raw_fd(), wr, MAX_SPLICE)
                }) {
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    res => return Poll::Ready(res),
                }
            }
        }

        /// Move up to `len` of the pipe's bytes (all of them, by the
        /// caller's count) into `dst`.
        pub(super) fn poll_drain(
            &self,
            cx: &mut Context<'_>,
            dst: &TcpStream,
            len: usize,
        ) -> Poll<io::Result<usize>> {
            let rd = self.rd.as_raw_fd();
            loop {
                ready!(dst.poll_write_ready(cx))?;
                // The pipe holds `len` bytes, so `WouldBlock` can only mean
                // the socket's send buffer is full.
                match dst.try_io(Interest::WRITABLE, || splice(rd, dst.as_raw_fd(), len)) {
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    res => return Poll::Ready(res),
                }
            }
        }
    }

    /// `splice(2)` into a socket whose peer is gone raises `SIGPIPE`, as
    /// it takes no `MSG_NOSIGNAL`. The meow binary ignores the signal (the
    /// Rust runtime does so before `main`); a process that embeds the
    /// engine may not, and there the relay keeps to the copy rather than
    /// risk the signal's default action.
    fn sigpipe_is_handled() -> bool {
        let mut current = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
        // SAFETY: a null new action makes this a pure query into `current`.
        if unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), current.as_mut_ptr()) } != 0 {
            return false;
        }
        // SAFETY: sigaction succeeded and filled `current`.
        unsafe { current.assume_init() }.sa_sigaction != libc::SIG_DFL
    }

    fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
        // SAFETY: both fds are borrowed from live owners for the call; pipes
        // and sockets take no offsets.
        let n = unsafe {
            libc::splice(
                from,
                std::ptr::null_mut(),
                to,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };
        usize::try_from(n).map_err(|_| io::Error::last_os_error())
    }

    /// A `TcpView` that found a socket at the tier upgrade lost it later.
    pub(super) fn lost_socket() -> io::Error {
        io::Error::other("relay: a spliced endpoint no longer exposes its socket")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_small() {
        let (mut a, mut b) = duplex(64);
        let (mut a2, mut b2) = duplex(64);

        // Write some data into the pipe ends that will be relayed.
        use tokio::io::AsyncWriteExt;
        a.write_all(b"hello").await.unwrap();
        a.shutdown().await.unwrap();
        b2.write_all(b"world").await.unwrap();
        b2.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];
        let (up, down) = copy_bidirectional_buf(&mut b, &mut a2, &mut buf1, &mut buf2)
            .await
            .unwrap();

        assert_eq!(up, 5, "a→b direction");
        assert_eq!(down, 5, "b→a direction");
    }

    // Tiered upgrade decision (#386): small callers upgrade only after the
    // bulk threshold; callers that already supply bulk-sized buffers never do.
    #[test]
    fn bulk_upgrade_decision() {
        assert!(!wants_bulk_upgrade(0, RELAY_BUF_SIZE));
        assert!(!wants_bulk_upgrade(
            RELAY_BULK_UPGRADE_BYTES - 1,
            RELAY_BUF_SIZE
        ));
        assert!(wants_bulk_upgrade(RELAY_BULK_UPGRADE_BYTES, RELAY_BUF_SIZE));
        assert!(!wants_bulk_upgrade(u64::MAX, RELAY_BULK_BUF_SIZE));
        assert!(!wants_bulk_upgrade(u64::MAX, RELAY_BULK_BUF_SIZE * 2));
    }

    // Data integrity across the in-flight buffer swap (#386): stream several
    // multiples of the upgrade threshold through standard small caller
    // buffers in both directions and verify every byte arrives, in order.
    #[tokio::test]
    async fn bulk_stream_survives_buffer_upgrade() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const TOTAL: usize = (RELAY_BULK_UPGRADE_BYTES as usize) * 4;

        let (mut client, mut a) = duplex(16 * 1024);
        let (mut b, mut upstream) = duplex(16 * 1024);

        let relay = tokio::spawn(async move {
            let mut buf1 = [0u8; RELAY_BUF_SIZE];
            let mut buf2 = [0u8; RELAY_BUF_SIZE];
            copy_bidirectional_buf(&mut a, &mut b, &mut buf1, &mut buf2).await
        });

        let pattern: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

        // client → upstream
        let tx = {
            let pattern = pattern.clone();
            tokio::spawn(async move {
                client.write_all(&pattern).await.unwrap();
                client.shutdown().await.unwrap();
                client
            })
        };
        let mut received = vec![0u8; TOTAL];
        upstream.read_exact(&mut received).await.unwrap();
        assert_eq!(
            received, pattern,
            "client→upstream bytes must survive the upgrade"
        );

        // upstream → client, past the threshold in the other direction too.
        // Write and read concurrently: the duplex pipes are far smaller than
        // TOTAL, so a sequential write-then-read would deadlock and trip the
        // half-close linger instead of exercising the upgrade.
        let tx_back = {
            let pattern = pattern.clone();
            tokio::spawn(async move {
                upstream.write_all(&pattern).await.unwrap();
                upstream.shutdown().await.unwrap();
            })
        };
        let mut client = tx.await.unwrap();
        let mut back = vec![0u8; TOTAL];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(
            back, pattern,
            "upstream→client bytes must survive the upgrade"
        );
        tx_back.await.unwrap();

        let (up, down) = relay.await.unwrap().unwrap();
        assert_eq!(up, TOTAL as u64);
        assert_eq!(down, TOTAL as u64);
    }

    // Regression: a peer that half-closes (sends EOF on its write side) and
    // then holds its read side open forever must not pin the relay. Before the
    // half-close linger, `copy_bidirectional_buf` waited for *both* directions
    // to EOF, so this hung indefinitely — surfacing in production as leaked
    // CLOSE-WAIT (inbound) / FIN-WAIT-2 (outbound) sockets.
    #[tokio::test(start_paused = true)]
    async fn half_closed_peer_does_not_pin_relay() {
        use tokio::io::AsyncWriteExt;

        // `a` is the relay's view of the "client": the client sends a byte then
        // closes its write side, so a→b sees EOF. `b` is the relay's view of the
        // "upstream", whose far end (`_upstream_held_open`) never sends and never
        // closes, so b→a would otherwise block forever. The underscore-prefixed
        // binding is kept (not dropped) for the whole test so `b` never sees EOF.
        let (mut client, mut a) = duplex(64);
        let (mut b, _upstream_held_open) = duplex(64);

        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];

        // With paused time the linger only elapses via the runtime's auto-advance
        // once the future is genuinely stalled, so completion proves the timer —
        // not real wall-clock — drove teardown.
        let (up, down) = tokio::time::timeout(
            RELAY_HALF_CLOSE_LINGER * 4,
            copy_bidirectional_buf(&mut a, &mut b, &mut buf1, &mut buf2),
        )
        .await
        .expect("relay must tear down within the linger window, not hang")
        .expect("relay returns Ok after the linger reaps the stuck direction");

        assert_eq!(up, 1, "the client's byte was relayed before teardown");
        assert_eq!(down, 0, "upstream never sent anything");
    }

    // Regression: a legitimate half-closed connection that keeps actively
    // streaming on the surviving direction must NOT be truncated by the linger.
    // The client shuts down its write side, then the upstream streams for far
    // longer than one linger window, with each gap shorter than the window. An
    // absolute-deadline linger would cut this off at `RELAY_HALF_CLOSE_LINGER`;
    // the idle-timeout linger re-arms on every chunk and lets it all through.
    #[tokio::test(start_paused = true)]
    async fn active_half_closed_transfer_is_not_truncated() {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut a) = duplex(64);
        let (mut b, mut upstream) = duplex(64);

        // Client sends one byte then half-closes — a→b sees EOF, arming the linger.
        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();

        // Upstream streams 6 chunks spaced at half the linger window (total span
        // 3× the window), then closes. No single gap reaches the window, so the
        // idle timer keeps getting re-armed and never reaps the live transfer.
        let feeder = tokio::spawn(async move {
            for _ in 0..6 {
                tokio::time::sleep(RELAY_HALF_CLOSE_LINGER / 2).await;
                upstream.write_all(b"yy").await.unwrap();
            }
            upstream.shutdown().await.unwrap();
        });

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];

        // Drain `a` (the relay writes upstream bytes here) so the duplex buffer
        // never backpressures and the relay can run to upstream's clean EOF.
        let drain = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut sink = Vec::new();
            client.read_to_end(&mut sink).await.unwrap();
            sink.len()
        });

        let (up, down) = copy_bidirectional_buf(&mut a, &mut b, &mut buf1, &mut buf2)
            .await
            .expect("relay completes via upstream EOF, not a truncating linger");

        feeder.await.unwrap();
        let drained = drain.await.unwrap();

        assert_eq!(up, 1, "the client's byte was relayed");
        assert_eq!(
            down, 12,
            "every upstream byte must be relayed — the active transfer is not truncated"
        );
        assert_eq!(drained, 12, "client received the full upstream stream");
    }

    // Regression for #345: under symmetric load, neither direction may
    // monopolize the relay. The old `poll_copy` drained the entire a→b
    // direction to `Pending` before b→a was polled at all, so every a→b
    // progress event fired before the first b→a event. The interleaved relay
    // alternates one buffer cycle per direction, so both directions must show
    // progress from the very start of the transfer.
    #[tokio::test]
    async fn directions_interleave_under_symmetric_load() {
        use tokio::io::AsyncWriteExt;

        // 8 relay-buffers of data queued in EACH direction before the relay
        // starts, with enough duplex capacity that no write ever backpressures
        // — progress order is then determined purely by relay poll order.
        let total = RELAY_BUF_SIZE * 8;
        let (mut client, mut a) = duplex(total * 2);
        let (mut b, mut upstream) = duplex(total * 2);

        client.write_all(&vec![1u8; total]).await.unwrap();
        client.shutdown().await.unwrap();
        upstream.write_all(&vec![2u8; total]).await.unwrap();
        upstream.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];

        // Record the order of write-progress events per direction.
        let events = std::cell::RefCell::new(Vec::new());
        let (up, down) = copy_bidirectional_buf_tracked(
            &mut a,
            &mut b,
            &mut buf1,
            &mut buf2,
            |n| events.borrow_mut().push(('a', n)),
            |n| events.borrow_mut().push(('b', n)),
        )
        .await
        .unwrap();

        assert_eq!(up as usize, total, "a→b relayed everything");
        assert_eq!(down as usize, total, "b→a relayed everything");

        let events = events.into_inner();
        let first_b = events
            .iter()
            .position(|e| e.0 == 'b')
            .expect("b→a made progress");
        let last_a = events
            .iter()
            .rposition(|e| e.0 == 'a')
            .expect("a→b made progress");
        assert!(
            first_b < last_a,
            "b→a must progress before a→b fully drains (first b event at \
             index {first_b}, last a event at index {last_a})"
        );
        assert!(
            first_b <= 2,
            "with fair interleaving b→a's first progress arrives within the \
             first few cycles, not at index {first_b}"
        );
    }

    #[tokio::test]
    async fn empty_streams() {
        let (mut a, mut b) = duplex(64);
        let (mut a2, mut b2) = duplex(64);

        use tokio::io::AsyncWriteExt;
        a.shutdown().await.unwrap();
        b2.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];
        let (up, down) = copy_bidirectional_buf(&mut b, &mut a2, &mut buf1, &mut buf2)
            .await
            .unwrap();
        assert_eq!(up, 0);
        assert_eq!(down, 0);
    }

    /// The splice tier, driven over real loopback sockets. The tests run
    /// on a current-thread runtime, so the relay's pipes show up in this
    /// thread's `splice::OPENED`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    mod spliced {
        use super::super::splice::OPENED;
        use super::*;
        use std::cell::Cell;
        use std::rc::Rc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        async fn tcp_pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (dialed, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
            (dialed.unwrap(), accepted.unwrap().0)
        }

        fn pattern(len: usize, seed: u8) -> Vec<u8> {
            (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
        }

        fn no_socket(_: &tokio::io::DuplexStream) -> Option<&TcpStream> {
            None
        }

        /// Write `data` and half-close; read the peer to EOF meanwhile.
        async fn exchange(stream: TcpStream, data: &[u8]) -> Vec<u8> {
            let (mut rd, mut wr) = stream.into_split();
            let send = async {
                wr.write_all(data).await.unwrap();
                wr.shutdown().await.unwrap();
            };
            let mut got = Vec::new();
            let recv = rd.read_to_end(&mut got);
            let ((), n) = tokio::join!(send, recv);
            n.unwrap();
            got
        }

        // Both directions at once, many multiples of the upgrade
        // threshold, through a DIRECT-shaped `dyn ProxyConn` remote: every
        // byte arrives in order, each direction opens one pipe, and the
        // callbacks see the same totals as the result.
        #[tokio::test]
        async fn bulk_both_ways_goes_through_pipes() {
            const TOTAL: usize = 8 << 20;
            let (client, mut a) = tcp_pair().await;
            let (b, upstream) = tcp_pair().await;
            let mut b: Box<dyn ProxyConn> = Box::new(b);
            let before = OPENED.with(Cell::get);

            let up_seen = Rc::new(Cell::new(0u64));
            let down_seen = Rc::new(Cell::new(0u64));
            let (up_cb, down_cb) = (Rc::clone(&up_seen), Rc::clone(&down_seen));
            let relay = async {
                let mut buf1 = [0u8; RELAY_BUF_SIZE];
                let mut buf2 = [0u8; RELAY_BUF_SIZE];
                copy_bidirectional_buf_tracked_splice(
                    &mut a,
                    &mut *b,
                    &mut buf1,
                    &mut buf2,
                    (tcp_view, proxy_conn_tcp_view),
                    |n| up_cb.set(up_cb.get() + n),
                    |n| down_cb.set(down_cb.get() + n),
                )
                .await
            };
            let (up_data, down_data) = (pattern(TOTAL, 0), pattern(TOTAL, 0x5a));
            let (relayed, at_upstream, at_client) = tokio::join!(
                relay,
                exchange(upstream, &down_data),
                exchange(client, &up_data)
            );

            assert!(at_upstream == up_data, "client to upstream bytes differ");
            assert!(at_client == down_data, "upstream to client bytes differ");
            assert_eq!(relayed.unwrap(), (TOTAL as u64, TOTAL as u64));
            assert_eq!(
                (up_seen.get(), down_seen.get()),
                (TOTAL as u64, TOTAL as u64)
            );
            assert_eq!(OPENED.with(Cell::get) - before, 2);
        }

        // A spliced direction's EOF reaches the peer as a FIN while the
        // other direction keeps flowing: the request side half-closes
        // first and the reply still arrives in full.
        #[tokio::test]
        async fn half_close_crosses_the_pipe() {
            const LEN: usize = 1 << 20;
            let (client, mut a) = tcp_pair().await;
            let (mut b, upstream) = tcp_pair().await;
            let before = OPENED.with(Cell::get);

            let relay = async {
                let mut buf1 = [0u8; RELAY_BUF_SIZE];
                let mut buf2 = [0u8; RELAY_BUF_SIZE];
                copy_bidirectional_buf_tracked_splice(
                    &mut a,
                    &mut b,
                    &mut buf1,
                    &mut buf2,
                    (tcp_view, tcp_view),
                    |_| {},
                    |_| {},
                )
                .await
            };
            let request = pattern(LEN, 1);
            let reply = pattern(LEN, 2);
            let server = async {
                let (mut rd, mut wr) = upstream.into_split();
                let mut got = Vec::new();
                rd.read_to_end(&mut got).await.unwrap();
                wr.write_all(&reply).await.unwrap();
                wr.shutdown().await.unwrap();
                got
            };
            let (relayed, at_upstream, at_client) =
                tokio::join!(relay, server, exchange(client, &request));

            assert!(at_upstream == request, "request bytes differ");
            assert!(at_client == reply, "reply bytes differ");
            assert_eq!(relayed.unwrap(), (LEN as u64, LEN as u64));
            assert_eq!(OPENED.with(Cell::get) - before, 2);
        }

        // An endpoint without a socket keeps both directions on the
        // userspace buffers.
        #[tokio::test]
        async fn socketless_endpoint_keeps_the_buffer_copy() {
            const LEN: usize = 1 << 20;
            let (client, mut a) = tcp_pair().await;
            let (mut b, mut upstream) = duplex(64 * 1024);
            let before = OPENED.with(Cell::get);

            let relay = async {
                let mut buf1 = [0u8; RELAY_BUF_SIZE];
                let mut buf2 = [0u8; RELAY_BUF_SIZE];
                copy_bidirectional_buf_tracked_splice(
                    &mut a,
                    &mut b,
                    &mut buf1,
                    &mut buf2,
                    (tcp_view, no_socket),
                    |_| {},
                    |_| {},
                )
                .await
            };
            let request = pattern(LEN, 3);
            let reply = pattern(LEN, 4);
            let server = async {
                let mut got = vec![0u8; LEN];
                upstream.read_exact(&mut got).await.unwrap();
                upstream.write_all(&reply).await.unwrap();
                upstream.shutdown().await.unwrap();
                got
            };
            let (relayed, at_upstream, at_client) =
                tokio::join!(relay, server, exchange(client, &request));

            assert!(at_upstream == request, "request bytes differ");
            assert!(at_client == reply, "reply bytes differ");
            assert_eq!(relayed.unwrap(), (LEN as u64, LEN as u64));
            assert_eq!(OPENED.with(Cell::get), before);
        }
    }
}
