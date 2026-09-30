//! Snell protocol constants and the high-level `Snell` stream wrapper.
//!
//! Bridges the version-specific AEAD codec to the snell request/response
//! semantics:
//!
//! * The client writes a 5-byte `[ver | cmd | client-id-len=0 | host-len |
//!   host... | port:u16 BE]` connect request after the salt is in flight.
//! * The server replies with a status byte (Tunnel/Pong/Error). Error
//!   responses carry `[code, msg-len, msg...]`.
//! * Either side may send a zero-payload frame to signal half-close; in
//!   reuse mode the client emits a zero chunk after each session so the
//!   connection can be returned to the pool and reused for the next request.
//! * v6 always uses the reuse-capable request and defers it into the
//!   session's first record (see [`Snell::defer_request`]).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::v3::{is_zero_chunk as is_v3_zero_chunk, V3Conn};
use super::v4::{is_zero_chunk as is_v4_zero_chunk, V4Conn, MAX_PAYLOAD_LENGTH};
use super::v6::{V6Codec, V6Conn, MAX_RECORD_PAYLOAD as V6_MAX_RECORD_PAYLOAD};

/// First byte of every Snell request — `0x01` since v1.
pub const HEADER_VERSION: u8 = 1;

pub const COMMAND_CONNECT: u8 = 1;
/// Reuse-capable TCP connect; used when the client maintains a pool.
pub const COMMAND_CONNECT_V2: u8 = 5;
pub const COMMAND_UDP: u8 = 6;
/// First byte of each UDP-over-TCP request frame.
pub const COMMAND_UDP_FORWARD: u8 = 1;

pub const RESPONSE_TUNNEL: u8 = 0;
pub const RESPONSE_PONG: u8 = 1;
pub const RESPONSE_ERROR: u8 = 2;

/// True iff an error is a version-specific Snell zero-chunk half-close
/// (v6 reuses v4's).
pub fn is_zero_chunk(err: &io::Error) -> bool {
    is_v3_zero_chunk(err) || is_v4_zero_chunk(err)
}

/// Application-layer error returned by the snell peer.
#[derive(Debug, Clone)]
pub struct AppError {
    pub code: u8,
    pub message: String,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "snell server error code={} msg={}",
            self.code, self.message
        )
    }
}

impl std::error::Error for AppError {}

/// Encode a TCP CONNECT request. The host is sent as text, IP literals
/// included.
pub fn connect_request(host: &str, port: u16, reuse: bool) -> io::Result<Vec<u8>> {
    if host.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snell: host name too long",
        ));
    }
    let mut buf = Vec::with_capacity(5 + host.len() + 2);
    buf.push(HEADER_VERSION);
    buf.push(if reuse {
        COMMAND_CONNECT_V2
    } else {
        COMMAND_CONNECT
    });
    buf.push(0); // empty client ID
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    Ok(buf)
}

/// Write a TCP CONNECT request through the caller's encrypted stream.
pub async fn write_header<W: AsyncWrite + Unpin>(
    stream: &mut W,
    host: &str,
    port: u16,
    reuse: bool,
) -> io::Result<()> {
    stream.write_all(&connect_request(host, port, reuse)?).await
}

/// UDP-ASSOCIATE request (empty client ID).
pub const UDP_REQUEST: [u8; 3] = [HEADER_VERSION, COMMAND_UDP, 0x00];

/// Write a UDP-ASSOCIATE request header.
pub async fn write_udp_header<W: AsyncWrite + Unpin>(stream: &mut W) -> io::Result<()> {
    stream.write_all(&UDP_REQUEST).await
}

/// Emit a zero-chunk (`payload_len == 0 && padding_len == 0`) — the
/// half-close signal recognized by the peer. The Snell codecs turn a
/// zero-byte `poll_write` into a zero-chunk frame, so this is a thin wrapper.
pub async fn write_zero_chunk<W: AsyncWrite + Unpin>(stream: &mut W) -> io::Result<()> {
    // A codec may first finish an in-flight payload write and report that
    // payload's consumed length. Keep polling until the empty input itself
    // completes, which is reported as zero bytes consumed.
    loop {
        if std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_write(cx, &[])).await? == 0 {
            break;
        }
    }
    stream.flush().await
}

// ─── Snell stream wrapper ────────────────────────────────────────────────────

enum SnellInner<S> {
    V3(V3Conn<S>),
    V4(V4Conn<S>),
    V6(V6Conn<S>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> SnellInner<S> {
    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_read(cx, out),
            SnellInner::V4(conn) => Pin::new(conn).poll_read(cx, out),
            SnellInner::V6(conn) => Pin::new(conn).poll_read(cx, out),
        }
    }

    fn poll_write_inner(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_write(cx, buf),
            SnellInner::V4(conn) => Pin::new(conn).poll_write(cx, buf),
            SnellInner::V6(conn) => Pin::new(conn).poll_write(cx, buf),
        }
    }

    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_flush(cx),
            SnellInner::V4(conn) => Pin::new(conn).poll_flush(cx),
            SnellInner::V6(conn) => Pin::new(conn).poll_flush(cx),
        }
    }

    fn poll_shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_shutdown(cx),
            SnellInner::V4(conn) => Pin::new(conn).poll_shutdown(cx),
            SnellInner::V6(conn) => Pin::new(conn).poll_shutdown(cx),
        }
    }
}

/// Cross-poll state for [`Snell::poll_write_packet_frame`]. One instance per
/// datagram write; the caller keeps it alive across `Poll::Pending` returns
/// because the stream lock (and thus `&mut Snell`) is released between polls.
#[derive(Default)]
pub struct PacketFrameProgress {
    /// This progress has begun a frame write: on v4 the frame was staged
    /// into the writer's pending buffer; on v3 it marks that this progress
    /// owns the codec's staged/pending output (v3 credits `written` only
    /// after the pending bytes drain, so `written` alone cannot tell a
    /// mid-drain resume from a fresh write).
    staged: bool,
    /// v3: bytes of `frame` already accepted by the AEAD stream.
    written: usize,
}

/// AEAD-wrapped stream with snell request/response semantics.
///
/// On the first `poll_read`, the wrapper consumes the server's status byte
/// before yielding any relay bytes (`read_reply`). Subsequent reads pass
/// through directly. The wrapper exposes
/// [`Snell::poll_write_packet_frame`]/[`Snell::write_packet_frame`] so the
/// UDP relay can emit one datagram per frame and fail fast on a torn write
/// (`frame_write_torn` below).
pub struct Snell<S> {
    inner: SnellInner<S>,
    /// Set to `true` after the reply byte has been consumed once. Reset to
    /// `false` by [`Snell::reset_reply_state`] when a pooled connection is
    /// re-used for a fresh request.
    reply_consumed: bool,
    /// The current session ended with the peer's zero-chunk. Unlike a raw TCP
    /// EOF, this makes a v4/v5 connection eligible for protocol-level reuse
    /// once our own zero-chunk has also been sent.
    peer_half_closed: bool,
    /// Armed when a packet-frame write starts; cleared only when it runs to
    /// completion. A future dropped mid-write (or an errored one) leaves the
    /// AEAD stream mid-frame — a later write would append after the torn
    /// prefix (v3) or clobber undrained pending bytes (v4), desyncing every
    /// following datagram permanently. Any such attempt errors instead
    /// (issue #625 item 16; the conn-level poison for item 3 lives in
    /// `udp::SnellPacketConn`).
    frame_write_torn: bool,
}

impl<S> Snell<S> {
    pub fn from_v4(inner: V4Conn<S>) -> Self {
        Self {
            inner: SnellInner::V4(inner),
            reply_consumed: false,
            peer_half_closed: false,
            frame_write_torn: false,
        }
    }

    pub fn from_v3(inner: V3Conn<S>) -> Self {
        Self {
            inner: SnellInner::V3(inner),
            reply_consumed: false,
            peer_half_closed: false,
            frame_write_torn: false,
        }
    }

    pub fn new(inner: S, psk: Arc<[u8]>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            inner: SnellInner::V4(V4Conn::new(inner, psk)),
            reply_consumed: false,
            peer_half_closed: false,
            frame_write_torn: false,
        }
    }

    pub fn new_v3(inner: S, psk: Arc<[u8]>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            inner: SnellInner::V3(V3Conn::new(inner, psk)),
            reply_consumed: false,
            peer_half_closed: false,
            frame_write_torn: false,
        }
    }

    pub fn new_v6(inner: S, psk: Arc<[u8]>, codec: V6Codec) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            inner: SnellInner::V6(V6Conn::new(inner, psk, codec)),
            reply_consumed: false,
            peer_half_closed: false,
            frame_write_torn: false,
        }
    }

    /// v6: queue `request` to lead the next record, so it shares a record
    /// with the session's first payload bytes. Earlier versions write their
    /// request eagerly and reject this.
    pub fn defer_request(&mut self, request: Vec<u8>) -> io::Result<()> {
        match &mut self.inner {
            SnellInner::V6(conn) => {
                conn.defer_request(request);
                Ok(())
            }
            SnellInner::V3(_) | SnellInner::V4(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "snell: deferred requests are v6-only",
            )),
        }
    }

    /// Largest datagram frame the codec carries in one record.
    pub fn max_packet_frame_len(&self) -> usize {
        match &self.inner {
            SnellInner::V3(_) | SnellInner::V4(_) => MAX_PAYLOAD_LENGTH,
            SnellInner::V6(_) => V6_MAX_RECORD_PAYLOAD,
        }
    }

    /// After a successful pool reuse the next request's reply byte is
    /// pending again — reset the flag so the next `read` consumes it.
    pub fn reset_reply_state(&mut self) {
        self.reply_consumed = false;
        self.peer_half_closed = false;
    }

    pub fn peer_half_closed(&self) -> bool {
        self.peer_half_closed
    }

    /// Whether the zero chunk alone completes a local half-close. A v6
    /// server aborts the whole session on transport EOF — dropping any
    /// reply the upstream has yet to send — so its write side must stay
    /// open until the connection is dropped.
    pub fn half_close_keeps_transport(&self) -> bool {
        matches!(self.inner, SnellInner::V6(_))
    }

    /// Stage a single frame carrying `buf` verbatim as a UDP datagram
    /// payload. v4 uses its packet-frame path to keep one datagram in one
    /// frame; v3 mirrors mihomo and writes through the regular AEAD stream.
    ///
    /// Cancellation or failure mid-write tears the AEAD frame on the wire;
    /// the tear is sticky — subsequent packet-frame writes error instead of
    /// desyncing the stream (issue #625.16).
    ///
    /// An empty `buf` is a valid packet frame but on v4 also reads as a
    /// zero-chunk half-close to the peer — don't use it for keepalives.
    pub async fn write_packet_frame(&mut self, buf: &[u8]) -> io::Result<usize>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if buf.len() > self.max_packet_frame_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            ));
        }
        self.begin_fresh_frame_write()?;
        let result = self.write_packet_frame_inner(buf).await;
        if result.is_ok() {
            self.frame_write_torn = false;
        }
        result
    }

    /// Entry gate for a brand-new packet-frame write (not a resume of an
    /// in-progress one — `progress` itself is the resume token). A fresh
    /// write on a torn stream fails fast; otherwise the write is armed and
    /// `frame_write_torn` stays set until the frame completes.
    ///
    /// Undrained codec-pending bytes are treated as torn even if
    /// `frame_write_torn` is clear: they can only come from a write that
    /// bypassed this gate (e.g. the `AsyncWrite` passthrough), and a fresh
    /// frame would append after them / mis-credit their drain.
    fn begin_fresh_frame_write(&mut self) -> io::Result<()> {
        let pending_leftover = match &self.inner {
            SnellInner::V3(conn) => conn.has_pending_write(),
            SnellInner::V4(conn) => conn.has_pending_write(),
            SnellInner::V6(conn) => conn.has_pending_write(),
        };
        if self.frame_write_torn || pending_leftover {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snell: packet conn desynced by an earlier incomplete frame write",
            ));
        }
        self.frame_write_torn = true;
        Ok(())
    }

    async fn write_packet_frame_inner(&mut self, buf: &[u8]) -> io::Result<usize>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if buf.len() > self.max_packet_frame_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            ));
        }
        match &mut self.inner {
            SnellInner::V3(conn) => {
                conn.write_all(buf).await?;
                conn.flush().await?;
            }
            SnellInner::V4(conn) => {
                conn.stage_packet_frame(buf)?;
                // poll_flush drains the staged frame AND flushes the
                // underlying stream — unconditionally, so a transport-level
                // flush that pended after `pending` emptied is finished too.
                std::future::poll_fn(|cx| Pin::new(&mut *conn).poll_flush(cx)).await?;
            }
            SnellInner::V6(conn) => {
                conn.stage_packet_frame(buf)?;
                std::future::poll_fn(|cx| Pin::new(&mut *conn).poll_flush(cx)).await?;
            }
        }
        Ok(buf.len())
    }

    /// Poll-based equivalent of [`Snell::write_packet_frame`] for callers
    /// that must not hold a lock across an `.await` (issue #278): the UDP
    /// packet conn locks the shared stream only for the duration of each
    /// poll, so `progress` carries the write state between polls.
    ///
    /// v4/v6 stage `frame` as a single packet record and drain it; v3
    /// writes through the regular AEAD stream. Both flush before returning
    /// `Ready(Ok(()))`.
    ///
    /// Contract: resuming an in-flight write must pass the *same* `frame`
    /// slice on every poll — `progress` tracks position, not content. A
    /// different slice on resume mis-credits `written` on v3; on v4 the
    /// staged frame is fixed at first poll and the new slice is ignored.
    pub fn poll_write_packet_frame(
        &mut self,
        cx: &mut Context<'_>,
        frame: &[u8],
        progress: &mut PacketFrameProgress,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if frame.len() > self.max_packet_frame_len() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            )));
        }
        // `progress` doubles as the resume token: `staged`/`written` mark a
        // poll continuing an in-flight write. A *fresh* progress arriving
        // while `frame_write_torn` is set means the previous write was
        // abandoned mid-frame (the codec may still hold undrained bytes) —
        // refuse it. The conn-level poison flag already catches this in the
        // packet-conn path; this in-Snell gate covers any future direct
        // caller (issue #625.16).
        let resuming = progress.staged || progress.written > 0;
        if !resuming {
            if let Err(e) = self.begin_fresh_frame_write() {
                return Poll::Ready(Err(e));
            }
        }
        match &mut self.inner {
            SnellInner::V3(conn) => {
                // v3 credits `written` only after the staged cipher frame
                // drains, so a mid-drain resume can arrive with
                // `written == 0` — `staged` marks that this progress already
                // entered and owns the codec's pending buffer.
                progress.staged = true;
                while progress.written < frame.len() {
                    match Pin::new(&mut *conn).poll_write(cx, &frame[progress.written..]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "snell v3: packet frame write returned 0",
                            )));
                        }
                        Poll::Ready(Ok(n)) => progress.written += n,
                    }
                }
                match Pin::new(conn).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        self.frame_write_torn = false;
                        *progress = PacketFrameProgress::default();
                        Poll::Ready(Ok(()))
                    }
                    other => other,
                }
            }
            SnellInner::V4(conn) => {
                if !progress.staged {
                    match conn.stage_packet_frame(frame) {
                        Ok(()) => progress.staged = true,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                // poll_flush drains the staged frame AND flushes the
                // underlying stream — call it unconditionally so a resume
                // after `pending` emptied also finishes a transport flush
                // that pended on the previous poll.
                match Pin::new(&mut *conn).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
                self.frame_write_torn = false;
                *progress = PacketFrameProgress::default();
                Poll::Ready(Ok(()))
            }
            SnellInner::V6(conn) => {
                if !progress.staged {
                    match conn.stage_packet_frame(frame) {
                        Ok(()) => progress.staged = true,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                // Same unconditional drain + flush as v4.
                match Pin::new(&mut *conn).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
                self.frame_write_torn = false;
                *progress = PacketFrameProgress::default();
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Snell<S> {
    /// Consume the server's status byte. Idempotent — calls after the first
    /// successful invocation are no-ops until [`Snell::reset_reply_state`].
    pub async fn read_reply(&mut self) -> io::Result<()> {
        if self.reply_consumed {
            return Ok(());
        }
        let mut byte = [0u8; 1];
        self.read_exact_underlying(&mut byte).await?;
        self.reply_consumed = true;
        match byte[0] {
            RESPONSE_TUNNEL | RESPONSE_PONG => Ok(()),
            RESPONSE_ERROR => {
                let mut buf = [0u8; 1];
                self.read_exact_underlying(&mut buf).await?;
                let code = buf[0];
                self.read_exact_underlying(&mut buf).await?;
                let len = buf[0] as usize;
                let mut msg = vec![0u8; len];
                if len > 0 {
                    self.read_exact_underlying(&mut msg).await?;
                }
                let message = String::from_utf8_lossy(&msg).into_owned();
                Err(io::Error::other(AppError { code, message }))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("snell: unknown response code 0x{other:x}"),
            )),
        }
    }

    /// Whether an idle pooled connection still looks usable: one read poll
    /// (with a no-op waker) must find nothing — no data, EOF or error. A
    /// v6 request is only written with the session's first bytes, so a
    /// connection the server dropped while idle is caught here rather than
    /// after the caller has handed it data.
    pub fn idle_conn_alive(&mut self) -> bool {
        let mut cx = Context::from_waker(Waker::noop());
        let mut byte = [0u8; 1];
        let mut rb = ReadBuf::new(&mut byte);
        self.inner.poll_read_inner(&mut cx, &mut rb).is_pending()
    }

    async fn read_exact_underlying(&mut self, buf: &mut [u8]) -> io::Result<()> {
        // Read directly from the AEAD-decoded stream, bypassing the reply
        // guard (otherwise we'd recurse).
        let mut filled = 0;
        while filled < buf.len() {
            let mut rb = ReadBuf::new(&mut buf[filled..]);
            std::future::poll_fn(|cx| self.inner.poll_read_inner(cx, &mut rb)).await?;
            let n = rb.filled().len();
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell: unexpected EOF reading reply",
                ));
            }
            filled += n;
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Snell<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First-read reply handshake. Implemented as a hand-rolled state
        // machine: the byte is read via `poll_read` on the inner stream into
        // a tiny scratch buffer, then we recurse on the body read in the
        // same poll once the reply is consumed.
        let this = &mut *self;
        if this.peer_half_closed {
            return Poll::Ready(Ok(()));
        }
        if !this.reply_consumed {
            let mut buf = [0u8; 1];
            let mut rb = ReadBuf::new(&mut buf);
            match this.inner.poll_read_inner(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if rb.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell: EOF before reply byte",
                )));
            }
            this.reply_consumed = true;
            match buf[0] {
                RESPONSE_TUNNEL | RESPONSE_PONG => {}
                RESPONSE_ERROR => {
                    // We're inside poll_read — surface the error rather than
                    // trying to read the error tail synchronously. The caller
                    // will report it; for richer messages the explicit
                    // `read_reply` path is preferred (the adapter calls it for
                    // UDP, and on TCP the next byte is data, so any error is
                    // surfaced as an io::Error here).
                    return Poll::Ready(Err(io::Error::other(
                        "snell: server returned error response (use read_reply for details)",
                    )));
                }
                other => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("snell: unknown response code 0x{other:x}"),
                    )));
                }
            }
        }
        // Map the v4 zero-chunk into a clean EOF for the caller.
        match this.inner.poll_read_inner(cx, out) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if is_zero_chunk(&e) => {
                this.peer_half_closed = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Snell<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_write_inner(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_flush_inner(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_shutdown_inner(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, DuplexStream};

    /// Wrap an await that could hang so a failure is an assertion instead of
    /// a test-runner timeout.
    async fn within<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("test future timed out")
    }

    /// Client `Snell` wrapper on one duplex half, mock-server `V4Conn` on the
    /// other. The v4 codec is symmetric (each direction sends its own salt),
    /// so a bare `V4Conn` works as the server side.
    fn rig() -> (Snell<DuplexStream>, V4Conn<DuplexStream>) {
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        (Snell::new(a, Arc::clone(&psk)), V4Conn::new(b, psk))
    }

    /// Transport wrapper whose `poll_flush` parks while `blocked` — `duplex`'s
    /// own flush always succeeds, so without this a test can never reach the
    /// "codec `pending` drained but transport flush still pending" state.
    /// `flushes` counts attempts so a resume can prove the flush was retried.
    /// Manual-poll only: a blocked `poll_flush` never registers the waker, so
    /// `.await`ing it would hang.
    struct FlushGate<S> {
        inner: S,
        blocked: Arc<std::sync::atomic::AtomicBool>,
        flushes: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<S> FlushGate<S> {
        fn new(
            inner: S,
        ) -> (
            Self,
            Arc<std::sync::atomic::AtomicBool>,
            Arc<std::sync::atomic::AtomicUsize>,
        ) {
            let blocked = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let flushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            (
                Self {
                    inner,
                    blocked: Arc::clone(&blocked),
                    flushes: Arc::clone(&flushes),
                },
                blocked,
                flushes,
            )
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for FlushGate<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for FlushGate<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.blocked.load(std::sync::atomic::Ordering::Relaxed) {
                Poll::Pending
            } else {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn write_header_connect_layout() {
        let (mut client, mut peer) = rig();
        within(write_header(&mut client, "example.com", 443, false))
            .await
            .unwrap();
        within(client.flush()).await.unwrap();

        let mut got = [0u8; 17];
        within(peer.read_exact(&mut got)).await.unwrap();
        let mut expected = vec![HEADER_VERSION, COMMAND_CONNECT, 0, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&[0x01, 0xBB]); // 443 BE
        assert_eq!(&got[..], &expected[..]);
    }

    #[tokio::test]
    async fn write_header_reuse_uses_connect_v2() {
        let (mut client, mut peer) = rig();
        within(write_header(&mut client, "example.com", 443, true))
            .await
            .unwrap();
        within(client.flush()).await.unwrap();

        let mut got = [0u8; 17];
        within(peer.read_exact(&mut got)).await.unwrap();
        assert_eq!(got[0], HEADER_VERSION);
        assert_eq!(got[1], COMMAND_CONNECT_V2);
    }

    #[tokio::test]
    async fn write_header_rejects_long_host() {
        let host = "h".repeat(256);
        let mut sink = tokio::io::sink();
        let err = write_header(&mut sink, &host, 80, false).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Issue #625.16: `write_packet_frame` (the non-poll variant kept for
    /// external/test callers) cancelled mid-write leaves a torn AEAD frame on the
    /// wire. The tear is sticky — later writes must fail fast instead of
    /// silently appending after the torn prefix (v3) or clobbering
    /// undrained pending bytes (v4).
    #[tokio::test]
    async fn cancelled_packet_frame_write_tears_conn_v4() {
        let (a, _b) = tokio::io::duplex(1 << 10);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let mut client = Snell::new(a, psk);

        // A 4 KiB frame exceeds the 1 KiB duplex buffer — the write pends
        // mid-frame and the timeout drops the future.
        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            client.write_packet_frame(&[0xAA; 4096]),
        )
        .await;
        assert!(cancelled.is_err(), "write must have timed out mid-frame");

        // `within` so a regression that drops the gate hangs-bounded rather
        // than stalling the suite on the full pipe.
        let err = within(client.write_packet_frame(b"x")).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(
            err.to_string().contains("desynced"),
            "write after a cancelled write must fail fast, got {err:?}"
        );
    }

    /// Same tear semantics on the v3 codec, where datagrams ride the plain
    /// AEAD stream — a cancelled write leaves the peer mid-frame.
    #[tokio::test]
    async fn cancelled_packet_frame_write_tears_conn_v3() {
        let (a, _b) = tokio::io::duplex(1 << 10);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let mut client = Snell::new_v3(a, psk);

        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            client.write_packet_frame(&[0xAA; 4096]),
        )
        .await;
        assert!(cancelled.is_err(), "write must have timed out mid-frame");

        let err = within(client.write_packet_frame(b"x")).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(
            err.to_string().contains("desynced"),
            "write after a cancelled write must fail fast, got {err:?}"
        );
    }

    /// The poll variant must refuse a fresh `PacketFrameProgress` on a torn
    /// stream — the conn-level poison is the primary guard, this is the
    /// in-codec backstop for any future direct caller.
    #[test]
    fn poll_packet_frame_refuses_fresh_progress_on_torn_stream() {
        for versioned in [false, true] {
            let (a, _b) = tokio::io::duplex(1 << 10);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let mut client = if versioned {
                Snell::new_v3(a, psk)
            } else {
                Snell::new(a, psk)
            };
            let mut cx = Context::from_waker(std::task::Waker::noop());

            let frame = vec![0xAA; 4096];
            let mut progress = PacketFrameProgress::default();
            let poll = client.poll_write_packet_frame(&mut cx, &frame, &mut progress);
            assert!(
                matches!(poll, Poll::Pending),
                "v{}: write must park mid-frame on the tiny pipe, got {poll:?}",
                if versioned { 3 } else { 4 }
            );

            // A fresh progress — a NEW write while the first is still
            // in-flight — must fail fast instead of clobbering the codec's
            // undrained pending bytes.
            let mut fresh = PacketFrameProgress::default();
            match client.poll_write_packet_frame(&mut cx, &frame, &mut fresh) {
                Poll::Ready(Err(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
                    assert!(
                        e.to_string().contains("desynced"),
                        "v{}: expected desync error, got {e}",
                        if versioned { 3 } else { 4 }
                    );
                }
                other => panic!(
                    "v{}: expected desynced error on torn stream, got {other:?}",
                    if versioned { 3 } else { 4 }
                ),
            }

            // Resuming the in-flight write with the same progress is the
            // legitimate continuation path — it must not be refused.
            // Strictly `Pending`: the peer half is never read, so the
            // staged frame can never fully drain — `Ready(Ok)` here would
            // mean a pending-drop bug cleared the tear early.
            let poll = client.poll_write_packet_frame(&mut cx, &frame, &mut progress);
            assert!(
                matches!(poll, Poll::Pending),
                "v{}: resume on the undrained pipe must stay Pending, got {poll:?}",
                if versioned { 3 } else { 4 }
            );
        }
    }

    /// `frame_write_torn` must refuse on its own: park a write on the
    /// *transport* flush after the codec `pending` buffer has fully drained
    /// (a state `tokio::io::duplex` alone can never reach — its flush always
    /// succeeds), abandon the write, and a fresh progress must still fail
    /// fast even though `pending_leftover` is false.
    ///
    /// The same rig pins the unconditional resume `poll_flush`: once the
    /// gate opens, resuming the original progress must call `poll_flush`
    /// again — with a `has_pending_write()` shortcut it would return
    /// `Ready(Ok)` without retrying the pended transport flush.
    #[test]
    fn torn_flag_alone_refuses_fresh_write_and_resume_retries_flush() {
        use std::sync::atomic::Ordering;
        for versioned in [false, true] {
            let (a, _b) = tokio::io::duplex(1 << 16);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let (gate, blocked, flushes) = FlushGate::new(a);
            let mut client = if versioned {
                Snell::new_v3(gate, psk)
            } else {
                Snell::new(gate, psk)
            };
            let mut cx = Context::from_waker(std::task::Waker::noop());

            // Pipe is big enough that the whole staged frame drains into the
            // transport; only the flush pends. Codec `pending` ends empty.
            let frame = vec![0xAA; 4096];
            let mut progress = PacketFrameProgress::default();
            let poll = client.poll_write_packet_frame(&mut cx, &frame, &mut progress);
            assert!(
                matches!(poll, Poll::Pending),
                "v{}: blocked transport flush must park the write, got {poll:?}",
                if versioned { 3 } else { 4 }
            );

            // Abandon the write. Codec pending is empty — only the torn flag
            // can refuse the fresh write that follows.
            let mut fresh = PacketFrameProgress::default();
            match client.poll_write_packet_frame(&mut cx, &frame, &mut fresh) {
                Poll::Ready(Err(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
                    assert!(
                        e.to_string().contains("desynced"),
                        "v{}: expected desync error, got {e}",
                        if versioned { 3 } else { 4 }
                    );
                }
                other => panic!(
                    "v{}: torn flag must refuse fresh progress even with empty codec pending, got {other:?}",
                    if versioned { 3 } else { 4 }
                ),
            }

            // Unblock the transport flush and resume the original progress —
            // it must retry the flush (a `has_pending_write` shortcut would
            // return Ready without flushing).
            blocked.store(false, Ordering::Relaxed);
            let poll = client.poll_write_packet_frame(&mut cx, &frame, &mut progress);
            assert!(
                matches!(poll, Poll::Ready(Ok(()))),
                "v{}: resume after flush unblocked must complete, got {poll:?}",
                if versioned { 3 } else { 4 }
            );
            assert!(
                flushes.load(Ordering::Relaxed) >= 2,
                "v{}: resume must retry the transport flush",
                if versioned { 3 } else { 4 }
            );
        }
    }

    /// Codec `pending` bytes left by a write that bypassed the frame gate
    /// (raw `AsyncWrite` passthrough) are treated as torn: a fresh
    /// `poll_write_packet_frame` must refuse even though `frame_write_torn`
    /// was never armed.
    #[test]
    fn leftover_codec_pending_refuses_fresh_frame_write() {
        for versioned in [false, true] {
            let (a, _b) = tokio::io::duplex(1 << 10);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let mut client = if versioned {
                Snell::new_v3(a, psk)
            } else {
                Snell::new(a, psk)
            };
            let mut cx = Context::from_waker(std::task::Waker::noop());

            // Raw AsyncWrite: 4 KiB into a 1 KiB pipe leaves undrained codec
            // pending bytes — `frame_write_torn` stays clear.
            let raw = vec![0xAA; 4096];
            let _ = Pin::new(&mut client).poll_write(&mut cx, &raw);

            let mut fresh = PacketFrameProgress::default();
            match client.poll_write_packet_frame(&mut cx, b"x", &mut fresh) {
                Poll::Ready(Err(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
                    assert!(
                        e.to_string().contains("desynced"),
                        "v{}: expected desync error, got {e}",
                        if versioned { 3 } else { 4 }
                    );
                }
                other => panic!(
                    "v{}: leftover codec pending must refuse fresh progress, got {other:?}",
                    if versioned { 3 } else { 4 }
                ),
            }
        }
    }

    /// A pended frame write resumed with the same progress must deliver the
    /// frame intact — the peer decodes exactly the original bytes, so
    /// re-staging, mis-credited `written`, or a skipped drain would corrupt
    /// the wire image and fail this assertion.
    #[test]
    fn resumed_packet_frame_write_completes_with_intact_frame() {
        for versioned in [false, true] {
            let (a, b) = tokio::io::duplex(1 << 10);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let mut client = if versioned {
                Snell::new_v3(a, Arc::clone(&psk))
            } else {
                Snell::new(a, Arc::clone(&psk))
            };
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let frame = vec![0xAB; 4096];
            let mut progress = PacketFrameProgress::default();
            assert!(
                client
                    .poll_write_packet_frame(&mut cx, &frame, &mut progress)
                    .is_pending(),
                "v{}: frame must park on the tiny pipe",
                if versioned { 3 } else { 4 }
            );

            // Interleave: drain the wire from the peer codec, re-poll the
            // same progress — repeat until the write completes. Both peer
            // codecs decrypt the packet frame back to the original payload.
            let mut plain = Vec::new();
            let mut scratch = [0u8; 1 << 14];
            let mut completed = false;
            macro_rules! pump {
                ($peer:expr) => {
                    for _ in 0..512 {
                        if !completed {
                            match client.poll_write_packet_frame(&mut cx, &frame, &mut progress) {
                                Poll::Ready(Ok(())) => completed = true,
                                Poll::Ready(Err(e)) => panic!("resume: {e}"),
                                Poll::Pending => {}
                            }
                        }
                        // Drain everything the wire currently holds — the
                        // peer codec buffers partial ciphertext internally
                        // and yields plaintext once the frame is complete.
                        loop {
                            let mut rb = ReadBuf::new(&mut scratch);
                            match Pin::new(&mut $peer).poll_read(&mut cx, &mut rb) {
                                Poll::Ready(Ok(())) => {
                                    if rb.filled().is_empty() {
                                        break;
                                    }
                                    plain.extend_from_slice(rb.filled());
                                }
                                Poll::Ready(Err(e)) => panic!("peer read: {e}"),
                                Poll::Pending => break,
                            }
                        }
                        if completed && plain.len() >= frame.len() {
                            break;
                        }
                    }
                };
            }
            if versioned {
                let mut peer = V3Conn::new(b, psk);
                pump!(peer);
            } else {
                let mut peer = V4Conn::new(b, psk);
                pump!(peer);
            }
            assert!(
                completed,
                "v{}: resumed write never completed",
                if versioned { 3 } else { 4 }
            );
            assert_eq!(
                plain,
                frame,
                "v{}: peer decoded corrupted frame",
                if versioned { 3 } else { 4 }
            );
        }
    }

    /// Happy-path guard for the non-poll variant: a completed frame write
    /// clears the tear flag so subsequent writes proceed.
    #[tokio::test]
    async fn completed_packet_frame_write_leaves_conn_usable() {
        let (mut client, mut peer) = rig();
        within(client.write_packet_frame(b"datagram"))
            .await
            .unwrap();
        within(client.write_packet_frame(b"second")).await.unwrap();

        // Both frames arrive intact and in order — no torn prefixes.
        let mut got = [0u8; 64];
        let n = within(peer.read(&mut got)).await.unwrap();
        assert!(n >= b"datagram".len(), "peer saw {n} bytes");
    }

    /// Same guard on the v3 codec: two consecutive completed frame writes —
    /// pins that the v3 completion path clears `frame_write_torn` (a second
    /// write must not trip the tear gate).
    #[tokio::test]
    async fn completed_packet_frame_write_leaves_conn_usable_v3() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let mut client = Snell::new_v3(a, Arc::clone(&psk));
        let mut peer = V3Conn::new(b, psk);

        within(client.write_packet_frame(b"datagram"))
            .await
            .unwrap();
        within(client.write_packet_frame(b"second")).await.unwrap();

        let mut got = [0u8; 64];
        let n = within(peer.read(&mut got)).await.unwrap();
        assert!(n >= b"datagram".len(), "peer saw {n} bytes");
    }

    #[tokio::test]
    async fn write_udp_header_layout() {
        let (mut client, mut peer) = rig();
        within(write_udp_header(&mut client)).await.unwrap();
        within(client.flush()).await.unwrap();

        let mut got = [0u8; 3];
        within(peer.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, [HEADER_VERSION, COMMAND_UDP, 0x00]);
    }

    #[tokio::test]
    async fn read_reply_accepts_tunnel_and_pong() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.flush()).await.unwrap();
        within(client.read_reply()).await.unwrap();

        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_PONG])).await.unwrap();
        within(peer.flush()).await.unwrap();
        within(client.read_reply()).await.unwrap();
    }

    #[tokio::test]
    async fn read_reply_parses_error_code_and_message() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_ERROR, 42, 5, b'o', b'o', b'p', b's', b'!']))
            .await
            .unwrap();
        within(peer.flush()).await.unwrap();

        let err = within(client.read_reply()).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("42"), "missing error code in: {msg}");
        assert!(msg.contains("oops!"), "missing error message in: {msg}");
    }

    #[tokio::test]
    async fn read_reply_rejects_unknown_code() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[0x7F])).await.unwrap();
        within(peer.flush()).await.unwrap();

        let err = within(client.read_reply()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("unknown response code"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn first_read_consumes_reply_then_yields_data() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"hello")).await.unwrap();
        within(peer.flush()).await.unwrap();

        let mut buf = [0u8; 16];
        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Reply already consumed by the first read — explicit call is a no-op.
        within(client.read_reply()).await.unwrap();
    }

    #[tokio::test]
    async fn zero_chunk_maps_to_clean_eof() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.flush()).await.unwrap();
        within(write_zero_chunk(&mut peer)).await.unwrap();

        let mut buf = [0u8; 8];
        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(n, 0, "zero chunk should surface as clean EOF");
    }

    #[tokio::test]
    async fn reset_reply_state_consumes_next_status_byte() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"hello")).await.unwrap();
        within(peer.flush()).await.unwrap();

        let mut buf = [0u8; 16];
        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Pool-reuse semantics: the next request's status byte is pending
        // again after a reset.
        client.reset_reply_state();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"again")).await.unwrap();
        within(peer.flush()).await.unwrap();

        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"again");
    }

    #[tokio::test]
    async fn write_packet_frame_rejects_oversize() {
        let (mut client, _peer) = rig();
        let oversize = vec![0u8; MAX_PAYLOAD_LENGTH + 1];
        let err = within(client.write_packet_frame(&oversize))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // The rejection happens before the tear flag arms — the conn stays
        // usable for a normal datagram.
        within(client.write_packet_frame(b"after")).await.unwrap();
    }

    #[tokio::test]
    async fn write_packet_frame_roundtrips() {
        let (mut client, mut peer) = rig();
        let n = within(client.write_packet_frame(b"datagram"))
            .await
            .unwrap();
        assert_eq!(n, b"datagram".len());

        // Each datagram is exactly one AEAD frame, so a single read drains it.
        let mut buf = [0u8; 64];
        let m = within(peer.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..m], b"datagram");
    }
}
