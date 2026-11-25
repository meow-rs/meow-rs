//! A multiplexed AnyTLS stream with bounded, cancellation-safe writes.

use crate::protocol::{Command, Frame, HEADER_OVERHEAD_SIZE};
use crate::session::StreamReader;
use crate::session::writer::{MAX_FRAME_PAYLOAD, QUEUED_FRAMES, StreamWriter};
use crate::util::{AnyTlsError, Result};
use bytes::{Bytes, BytesMut};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, oneshot};
use tokio_util::sync::PollSemaphore;

struct WriteState {
    closed: bool,
    fin_sent: bool,
    permits: PollSemaphore,
    flush: Option<oneshot::Receiver<Result<()>>>,
    waker: Option<Waker>,
}

/// Retire a registered stream if opening it fails or its dial is cancelled.
pub(crate) struct OpeningStreamGuard(Option<Arc<Stream>>);

impl OpeningStreamGuard {
    pub(crate) fn new(stream: Arc<Stream>) -> Self {
        Self(Some(stream))
    }
    pub(crate) fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for OpeningStreamGuard {
    fn drop(&mut self) {
        if let Some(stream) = &self.0 {
            stream.close();
        }
    }
}

/// A `'static` pending `reader.lock_owned()` acquisition — the
/// contention fallback `poll_read` stores between polls.
type PendingReadLock =
    Pin<Box<dyn Future<Output = tokio::sync::OwnedMutexGuard<StreamReader>> + Send>>;

/// Stream represents a single data stream within a Session.
pub struct Stream {
    id: u32,
    /// Self-weak bound by the session right after `Arc::new` — the
    /// instance identity tagged onto this stream's FIN/SynAck frames.
    /// Stream *ids* are peer-assigned and recyclable, so the wire writer
    /// commits those frames only while this exact instance still owns
    /// the sid in the session map (F05: a retired handler's frame must
    /// not kill a recycled SID's new stream). A `Weak` needs no
    /// instance counter, so the identity is portable to targets without
    /// 64-bit atomics (F19/N05) and cannot collide with an un-reaped
    /// old generation — its control block outlives the stream itself.
    self_weak: Mutex<std::sync::Weak<Stream>>,
    reader: Arc<tokio::sync::Mutex<StreamReader>>,
    writer: StreamWriter,
    // Only synchronous admission and close operations run under this lock.
    // In particular, no network I/O or await occurs while it is held.
    write_state: Mutex<WriteState>,
    close_notify: Notify,
    // Synchronous mutexes too — each critical section is a bare
    // `Option` take/store, so `notify_synack`/`close_with_error` can be
    // sync fns. That matters: an eviction path calls them right after
    // removing the stream from the session maps, and an `.await` there
    // would open a cancellation window in which the waiter pends
    // forever on an already-evicted stream (issue #621).
    synack_tx: Mutex<Option<oneshot::Sender<Result<()>>>>,
    /// Write-only bookkeeping — upstream parity for `closeErr`. Nothing
    /// reads it; kept so the close reason is inspectable in debugging.
    close_error: Mutex<Option<AnyTlsError>>,
    /// `poll_read`'s pending lock acquisition under contention. Only
    /// populated while an `&self` reader path holds `reader`; the
    /// uncontended `try_lock` fast path never allocates. The `Mutex`
    /// exists only for `Stream: Sync` — `poll_read` reaches the value
    /// through `get_mut`, so no lock is ever taken.
    pending_read: Mutex<Option<PendingReadLock>>,
}

impl Stream {
    pub fn new(
        id: u32,
        reader: StreamReader,
        writer: StreamWriter,
    ) -> (Self, oneshot::Receiver<Result<()>>) {
        let (synack_tx, synack_rx) = oneshot::channel();
        let permits = PollSemaphore::new(Arc::clone(&writer.budget));
        (
            Self {
                id,
                self_weak: Mutex::new(std::sync::Weak::new()),
                reader: Arc::new(tokio::sync::Mutex::new(reader)),
                writer,
                write_state: Mutex::new(WriteState {
                    closed: false,
                    fin_sent: false,
                    permits,
                    flush: None,
                    waker: None,
                }),
                close_notify: Notify::new(),
                synack_tx: Mutex::new(Some(synack_tx)),
                close_error: Mutex::new(None),
                pending_read: Mutex::new(None),
            },
            synack_rx,
        )
    }

    /// Resolve the stream's synack-waiter once; subsequent calls no-op
    /// (the first notify wins — e.g. a SynAck already landed).
    ///
    /// Deliberately synchronous: callers invoke this immediately after
    /// evicting the stream from the session maps, and an await between
    /// removal and wakeup would be a cancellation gap (issue #621).
    pub fn notify_synack(&self, result: Result<()>) {
        if let Some(tx) = self.synack_tx.lock().unwrap().take() {
            let _ = tx.send(result);
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    /// Bind the self-weak used to tag this instance's control frames.
    /// Called by the session immediately after `Arc::new` — streams
    /// only ever live inside an Arc.
    pub(crate) fn bind_self(self: &Arc<Self>) {
        *self.self_weak.lock().unwrap() = Arc::downgrade(self);
    }

    /// The owner token a control frame carries — `None` on an unbound
    /// (bare) stream, which cannot collide under a recycled sid, so the
    /// unconditional-legacy path is correct for it.
    pub(crate) fn owner(&self) -> Option<std::sync::Weak<Stream>> {
        let w = self.self_weak.lock().unwrap().clone();
        (w.strong_count() > 0).then_some(w)
    }

    /// Mark the stream closed locally without emitting a `Fin` —
    /// upstream `closeLocally` semantics: the peer already ended the
    /// stream, so no reply is owed. Synchronous for the same reason as
    /// [`notify_synack`](Self::notify_synack).
    pub fn close_with_error(&self, err: AnyTlsError) {
        self.mark_closed(false);
        *self.close_error.lock().unwrap() = Some(err);
    }

    pub fn is_closed(&self) -> bool {
        self.write_state.lock().unwrap().closed
    }

    fn mark_closed(&self, send_fin: bool) {
        let mut state = self.write_state.lock().unwrap();
        // Upstream `dieOnce` parity: once the stream is dead — locally or
        // by peer FIN — a later `close()` emits no FIN at all (a recycled
        // SID's new stream must not see a stale close's frame).
        let was_closed = state.closed;
        state.closed = true;
        // Drop a pending semaphore acquisition, releasing its reserved permits.
        state.permits = PollSemaphore::new(Arc::clone(&self.writer.budget));
        if send_fin && !state.fin_sent && !was_closed {
            state.fin_sent = true;
            // A pending flush may precede FIN. Shutdown must acknowledge a
            // fresh barrier after it, even if an earlier flush was cancelled.
            state.flush = None;
            let _ = self.writer.enqueue(
                Frame::control(Command::Fin, self.id),
                None,
                None,
                self.owner(),
            );
        }
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        self.close_notify.notify_waiters();
    }

    /// Queue exactly one FIN after all accepted writes, including from Drop.
    pub fn close(&self) {
        self.mark_closed(true);
    }

    /// A future resolving when the stream dies — local close, peer FIN,
    /// eviction, or session teardown. Listeners race a stream's work
    /// against it so a retired instance stops dispatching immediately
    /// instead of finishing a dial on the session's behalf.
    pub fn close_waiter(&self) -> tokio::sync::futures::Notified<'_> {
        self.close_notify.notified()
    }

    pub fn reader(&self) -> &Arc<tokio::sync::Mutex<StreamReader>> {
        &self.reader
    }

    /// Accept one frame with session-wide backpressure. Cancellation either
    /// enqueues the entire frame or none of it; the session owns physical I/O.
    pub async fn send_data(&self, data: Bytes) -> Result<()> {
        if data.len() > MAX_FRAME_PAYLOAD {
            return Err(AnyTlsError::Protocol(
                "frame payload exceeds u16 length".into(),
            ));
        }
        let closed = self.close_notify.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        if self.is_closed() {
            return Err(AnyTlsError::StreamClosed);
        }
        if data.is_empty() {
            return Ok(());
        }
        let permit = tokio::select! {
            biased;
            _ = &mut closed => return Err(AnyTlsError::StreamClosed),
            permit = Arc::clone(&self.writer.budget).acquire_owned() =>
                permit.map_err(|_| AnyTlsError::SessionClosed)?,
        };
        let state = self.write_state.lock().unwrap();
        if state.closed {
            return Err(AnyTlsError::StreamClosed);
        }
        self.writer
            .enqueue(Frame::data(self.id, data), Some(permit), None, None)
    }

    fn poll_pending_flush(
        state: &mut WriteState,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(flush) = state.flush.as_mut() {
            let result = std::task::ready!(Pin::new(flush).poll(cx));
            state.flush = None;
            return Poll::Ready(match result {
                Ok(result) => result.map_err(std::io::Error::other),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "session writer closed",
                )),
            });
        }
        Poll::Ready(Ok(()))
    }

    pub fn poll_write_data(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = self.write_state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }
        // Do not let a cancelled flush become a stale barrier for later writes.
        std::task::ready!(Self::poll_pending_flush(&mut state, cx))?;
        state.waker = Some(cx.waker().clone());
        let permit = std::task::ready!(state.permits.poll_acquire(cx)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "session writer closed")
        })?;
        let len = buf.len().min(MAX_FRAME_PAYLOAD);
        self.writer
            .enqueue(
                Frame::data(self.id, Bytes::copy_from_slice(&buf[..len])),
                Some(permit),
                None,
                None,
            )
            .map_err(std::io::Error::other)?;
        Poll::Ready(Ok(len))
    }

    /// Framing headroom this stream asks callers to reserve ahead of each
    /// [`poll_write_bytes_data`](Self::poll_write_bytes_data) slot: the
    /// 7-byte frame header
    /// ([`Command` | stream id | length]). The relay reads it once per
    /// direction and leads every fill with that many zeros; the stream
    /// overlays the header in place, turning one fill into ONE
    /// contiguous wire image with no payload copy.
    pub fn want_write_headroom(&self) -> usize {
        HEADER_OVERHEAD_SIZE
    }

    /// Owned-buffer counterpart of `poll_write_data` behind the relay's
    /// `WriteBytes` probe: the caller's `BytesMut` region becomes the
    /// frame payload via `split_to` — no `copy_from_slice`, no second
    /// allocation.
    ///
    /// The `Option` slot stays the caller's staging area per the
    /// `WriteBytes` contract: `Poll::Ready(Ok)` leaves it `None` once
    /// every chunk was queued — a slot needing more frames than the
    /// whole writer budget instead leaves a `Some` remainder for
    /// re-presentation (the continuation below re-prefixes it, so the
    /// headroom check stays unambiguous); `Poll::Pending` leaves the
    /// buffer untouched for the caller to re-present — permit
    /// acquisition is all-or-nothing BEFORE the slot is taken, so a
    /// re-presented slot is always either the caller's or that
    /// fresh-prefixed remainder.
    ///
    /// Headroom contract: when the slot begins with
    /// `HEADER_OVERHEAD_SIZE` zero bytes — what a caller honouring
    /// [`want_write_headroom`](Self::want_write_headroom) reserves —
    /// the first frame's header is written into that prefix and the
    /// whole `[header | payload]` image is queued as one contiguous
    /// `Bytes` (`WriteRequest::Wire`); a slot without the reserved
    /// prefix takes the per-frame `Frame::data` path. A slot larger
    /// than `MAX_FRAME_PAYLOAD` drains as several frames under one
    /// poll, one budget permit each — ordering is the session queue's
    /// FIFO.
    pub fn poll_write_bytes_data(
        &self,
        cx: &mut Context<'_>,
        bytes: &mut Option<BytesMut>,
    ) -> Poll<std::io::Result<()>> {
        let mut state = self.write_state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }
        // Same barrier rule as `poll_write_data`: a cancelled flush must
        // not wedge later writes.
        std::task::ready!(Self::poll_pending_flush(&mut state, cx))?;
        state.waker = Some(cx.waker().clone());
        let Some(b) = bytes.as_ref() else {
            return Poll::Ready(Ok(()));
        };
        if b.is_empty() {
            bytes.take();
            return Poll::Ready(Ok(()));
        }
        // Caller-reserved framing space? A complying caller's slot leads
        // with `HEADER_OVERHEAD_SIZE` zeros (the relay puts them ahead
        // of every read); a bare-payload slot falls back to per-frame
        // headers — a WriteBytes-contract violation that still works but
        // forfeits the contiguous path (the conn's `poll_write_bytes`
        // debug_asserts it; the fallback stays legal for direct Stream
        // callers, which tests deliberately exercise).
        let headroom = if b.len() >= HEADER_OVERHEAD_SIZE
            && b[..HEADER_OVERHEAD_SIZE].iter().all(|v| *v == 0)
        {
            HEADER_OVERHEAD_SIZE
        } else {
            0
        };
        let payload_len = b.len() - headroom;
        // One permit per emitted frame, acquired atomically before the
        // slot is taken: `Pending` leaves the caller's buffer exactly as
        // presented. `enqueue`/`enqueue_wire` can only fail on a closed
        // session, which `budget.is_closed` already gates here.
        let frames_needed = payload_len
            .div_ceil(MAX_FRAME_PAYLOAD)
            .clamp(1, QUEUED_FRAMES);
        let mut permit =
            std::task::ready!(state.permits.poll_acquire_many(cx, frames_needed as u32))
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "session writer closed")
                })?;
        let mut rest = bytes.take().expect("slot checked non-empty");
        for i in 0..frames_needed {
            let one = permit
                .split(1)
                .expect("permits were acquired for every frame");
            if i == 0 && headroom > 0 {
                // Contiguous path: the reserved prefix takes the header
                // and the image ships as a single `Bytes` — the wire
                // writer never reassembles it.
                let take = headroom + payload_len.min(MAX_FRAME_PAYLOAD);
                let mut image = rest.split_to(take);
                let plen = (take - headroom) as u16;
                image[0] = u8::from(Command::Push);
                image[1..5].copy_from_slice(&self.id.to_be_bytes());
                image[5..7].copy_from_slice(&plen.to_be_bytes());
                self.writer
                    .enqueue_wire(image.freeze(), Some(one), None)
                    .map_err(std::io::Error::other)?;
            } else {
                let take = rest.len().min(MAX_FRAME_PAYLOAD);
                let chunk = rest.split_to(take);
                self.writer
                    .enqueue(Frame::data(self.id, chunk.freeze()), Some(one), None, None)
                    .map_err(std::io::Error::other)?;
            }
        }
        if !rest.is_empty() {
            // Only reachable for a slot needing > QUEUED_FRAMES frames
            // (>4 MiB): put back the undrained remainder behind a fresh
            // reserved prefix so it satisfies the same slot contract on
            // the next poll — the headroom check above stays sound
            // whether the slot is the caller's or this continuation.
            let mut pending = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + rest.len());
            pending.extend_from_slice(&[0u8; HEADER_OVERHEAD_SIZE]);
            pending.extend_from_slice(&rest);
            *bytes = Some(pending);
        }
        Poll::Ready(Ok(()))
    }

    pub fn poll_flush_data(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut state = self.write_state.lock().unwrap();
        // A caller may cancel a backpressured write and then flush instead.
        // Release any capacity reserved by that abandoned acquisition.
        state.permits = PollSemaphore::new(Arc::clone(&self.writer.budget));
        if state.flush.is_none() {
            state.flush = Some(self.writer.flush().map_err(std::io::Error::other)?);
        }
        Self::poll_pending_flush(&mut state, cx)
    }

    pub fn poll_shutdown_data(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.close();
        self.poll_flush_data(cx)
    }
}

impl Stream {
    /// `&self` read entry shared by `AsyncRead for Stream` and
    /// `AsyncRead for Arc<Stream>` — every state item it touches is
    /// already behind a mutex, so the only difference is how
    /// `pending_read` is reached (`lock()` here, `get_mut()` was
    /// possible on the `&mut` path; the critical section is a bare
    /// get-or-insert plus one poll either way).
    fn poll_read_data(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Fast path — uncontended: `try_lock` borrows the reader and
        // drives `StreamReader::poll_read` straight into `buf`. Zero
        // allocation, no boxed future; the B4 `Bytes` leftover feeds
        // the caller directly. (The old code rebuilt a `Box::pin`d
        // read future + a `vec![0; remaining]` scratch on EVERY poll,
        // Pending included, then dropped both.)
        if let Ok(mut guard) = self.reader.try_lock() {
            return Pin::new(&mut *guard).poll_read(cx, buf);
        }

        // Contended — an `&self` reader path holds the mutex. Ride one
        // stored `lock_owned` future across polls: `OwnedMutexGuard` is
        // `'static`, so the future can live on `self` until the mutex
        // is free, and the waker is registered once with the mutex's
        // wait queue rather than re-armed every poll.
        let mut pending = self.pending_read.lock().unwrap();
        let fut = pending.get_or_insert_with(|| {
            let reader = Arc::clone(&self.reader);
            Box::pin(async move { reader.lock_owned().await })
        });
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(mut guard) => {
                *pending = None;
                Pin::new(&mut *guard).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().poll_read_data(cx, buf)
    }
}

/// `Arc<Stream>` as a relay-facing conn: the session's stream-accept
/// channel hands inbound listeners `Arc<Stream>`s and `Arc` is not a
/// fundamental type, so `AsyncRead`/`AsyncWrite` can't be implemented on
/// it directly — this newtype carries them. `Deref<Target = Stream>`
/// keeps `id()`/`close()`/`reader()` reachable; reads share the same
/// reader mutex the `Stream` impl drives; writes go through the same
/// `&self` enqueue path `Stream` itself uses.
#[derive(Clone)]
pub struct StreamIo(pub Arc<Stream>);

impl std::ops::Deref for StreamIo {
    type Target = Stream;
    fn deref(&self) -> &Stream {
        &self.0
    }
}

impl AsyncRead for StreamIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.0.poll_read_data(cx, buf)
    }
}

impl AsyncWrite for StreamIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.poll_write_data(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.0.poll_flush_data(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.0.poll_shutdown_data(cx)
    }
}

/// The owned-`Bytes` write path the tunnel relay probes for: forwards to
/// [`Stream::poll_write_bytes_data`] so a relay fill becomes one frame
/// with the header overlaid in the caller's reserved headroom — no
/// per-frame `copy_from_slice`.
impl meow_common::WriteBytes for StreamIo {
    fn poll_write_bytes(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut Option<BytesMut>,
    ) -> Poll<std::io::Result<()>> {
        self.0.poll_write_bytes_data(cx, bytes)
    }
    fn want_write_headroom(&self) -> usize {
        self.0.want_write_headroom()
    }
}

/// `ProxyConn` for the frame-multiplexed stream: NO `tcp_stream` (the
/// relay must never splice a muxed logical flow), `write_bytes` exposes
/// the headroom path above so inbound TCP relays batch zero-copy.
impl meow_common::ProxyConn for StreamIo {
    fn write_bytes(&mut self) -> Option<&mut dyn meow_common::WriteBytes> {
        Some(self)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_write_data(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush_data(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_shutdown_data(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::writer::WriteRequest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    fn stream() -> (Stream, mpsc::UnboundedReceiver<WriteRequest>) {
        let (writer, rx) = StreamWriter::channel();
        let (_, reader_rx) = mpsc::unbounded_channel();
        (
            Stream::new(1, StreamReader::new(1, reader_rx), writer).0,
            rx,
        )
    }

    fn frame(request: WriteRequest) -> Frame {
        match request {
            WriteRequest::Frame { frame, .. } => frame,
            WriteRequest::Flush(_) | WriteRequest::Wire { .. } => panic!("expected frame"),
        }
    }

    #[tokio::test]
    async fn writes_are_bounded_and_fin_follows_accepted_data() {
        let (mut stream, mut rx) = stream();
        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        assert!(rx.try_recv().is_err());
        for _ in 0..64 {
            stream.write_all(b"data").await.unwrap();
        }
        let mut write = Box::pin(stream.write(b"blocked"));
        assert!(
            write
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(write);
        stream.close();
        assert!(
            stream
                .send_data(Bytes::from_static(b"after-fin"))
                .await
                .is_err()
        );
        for _ in 0..64 {
            assert_eq!(frame(rx.recv().await.unwrap()).data, b"data"[..]);
        }
        assert_eq!(frame(rx.recv().await.unwrap()).cmd, Command::Fin);
        stream.close();
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn oversized_tcp_write_is_chunked() {
        let (mut stream, mut rx) = stream();
        let data = vec![42; MAX_FRAME_PAYLOAD + 5];
        stream.write_all(&data).await.unwrap();
        assert_eq!(
            frame(rx.recv().await.unwrap()).data.len(),
            MAX_FRAME_PAYLOAD
        );
        assert_eq!(frame(rx.recv().await.unwrap()).data.len(), 5);
        assert!(stream.send_data(Bytes::from(data)).await.is_err());
    }

    #[tokio::test]
    async fn flush_waits_for_writer_acknowledgement() {
        let (mut stream, mut rx) = stream();
        let mut flush = Box::pin(stream.flush());
        assert!(
            flush
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        match rx.recv().await.unwrap() {
            WriteRequest::Flush(tx) => tx.send(Ok(())).unwrap(),
            _ => panic!("expected flush"),
        }
        flush.await.unwrap();
    }

    #[tokio::test]
    async fn close_wakes_a_blocked_async_send() {
        let (mut stream, _rx) = stream();
        for _ in 0..64 {
            stream.write_all(b"data").await.unwrap();
        }
        let mut send = Box::pin(stream.send_data(Bytes::from_static(b"blocked")));
        assert!(
            send.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        stream.close();
        assert!(send.await.is_err());
    }

    #[tokio::test]
    async fn shutdown_does_not_acknowledge_a_flush_before_fin() {
        let (mut stream, mut rx) = stream();
        let mut flush = Box::pin(stream.flush());
        assert!(
            flush
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(flush);
        let WriteRequest::Flush(old_flush) = rx.recv().await.unwrap() else {
            panic!("expected flush")
        };
        let mut shutdown = Box::pin(stream.shutdown());
        assert!(
            shutdown
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let _ = old_flush.send(Ok(()));
        assert!(
            shutdown
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(frame(rx.recv().await.unwrap()).cmd, Command::Fin);
        let WriteRequest::Flush(new_flush) = rx.recv().await.unwrap() else {
            panic!("expected flush")
        };
        new_flush.send(Ok(())).unwrap();
        shutdown.await.unwrap();
        assert!(rx.try_recv().is_err());
    }

    /// B3: a slot carrying the caller's reserved headroom prefix ships
    /// as ONE contiguous `WriteRequest::Wire` — header overlaid in
    /// place, payload untouched, pointer identity preserved.
    #[tokio::test]
    async fn headroom_slot_produces_contiguous_wire_frame() {
        let (stream, mut rx) = stream();
        let mut buf = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + 11);
        buf.extend_from_slice(&[0u8; HEADER_OVERHEAD_SIZE]);
        buf.extend_from_slice(b"hello world");
        let payload_ptr = buf[HEADER_OVERHEAD_SIZE..].as_ptr();
        let mut slot = Some(buf);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            stream.poll_write_bytes_data(&mut cx, &mut slot),
            Poll::Ready(Ok(()))
        ));
        assert!(slot.is_none(), "consumed slot is cleared");
        match rx.recv().await.unwrap() {
            WriteRequest::Wire { wire, .. } => {
                // [cmd | sid | len | payload] — one contiguous Bytes.
                assert_eq!(wire[0], u8::from(Command::Push));
                assert_eq!(u32::from_be_bytes(wire[1..5].try_into().unwrap()), 1);
                assert_eq!(u16::from_be_bytes([wire[5], wire[6]]), 11);
                assert_eq!(&wire[7..], b"hello world");
                // The wire image IS the caller's allocation: the payload
                // starts exactly where the caller's payload did.
                assert_eq!(wire[HEADER_OVERHEAD_SIZE..].as_ptr(), payload_ptr);
            }
            other => panic!("expected a Wire request, got a frame of {:?}", {
                match other {
                    WriteRequest::Frame { frame, .. } => u8::from(frame.cmd),
                    WriteRequest::Flush(_) => 255,
                    WriteRequest::Wire { .. } => unreachable!(),
                }
            }),
        }
        assert!(rx.try_recv().is_err(), "one fill → one frame");
    }

    /// B3: a slot WITHOUT the reserved prefix takes the ordinary
    /// `Frame::data` path — payload split at `MAX_FRAME_PAYLOAD`, one
    /// budget permit per frame.
    #[tokio::test]
    async fn bare_slot_chunks_into_plain_frames() {
        let (stream, mut rx) = stream();
        let payload = vec![0x5Au8; MAX_FRAME_PAYLOAD + 5];
        let mut slot = Some(BytesMut::from(&payload[..]));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            stream.poll_write_bytes_data(&mut cx, &mut slot),
            Poll::Ready(Ok(()))
        ));
        assert!(slot.is_none());
        let first = frame(rx.recv().await.unwrap());
        assert_eq!(first.cmd, Command::Push);
        assert_eq!(first.data.len(), MAX_FRAME_PAYLOAD);
        let second = frame(rx.recv().await.unwrap());
        assert_eq!(second.data.len(), 5);
        assert_eq!(&second.data[..], &payload[MAX_FRAME_PAYLOAD..]);
        assert!(rx.try_recv().is_err());
    }

    /// B3: the headroom prefix and a >MAX_FRAME_PAYLOAD payload combine
    /// into a contiguous first frame + `Frame::data` continuation — and
    /// the first frame is exactly `HEADER + MAX_FRAME_PAYLOAD` long.
    #[tokio::test]
    async fn headroom_slot_oversized_continues_as_plain_frames() {
        let (stream, mut rx) = stream();
        let mut buf = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + MAX_FRAME_PAYLOAD + 3);
        buf.extend_from_slice(&[0u8; HEADER_OVERHEAD_SIZE]);
        buf.extend_from_slice(&vec![0x77u8; MAX_FRAME_PAYLOAD + 3]);
        let mut slot = Some(buf);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            stream.poll_write_bytes_data(&mut cx, &mut slot),
            Poll::Ready(Ok(()))
        ));
        match rx.recv().await.unwrap() {
            WriteRequest::Wire { wire, .. } => {
                assert_eq!(wire.len(), HEADER_OVERHEAD_SIZE + MAX_FRAME_PAYLOAD);
                assert_eq!(
                    u16::from_be_bytes([wire[5], wire[6]]) as usize,
                    MAX_FRAME_PAYLOAD
                );
            }
            _ => panic!("first frame must be the contiguous Wire image"),
        }
        let rest = frame(rx.recv().await.unwrap());
        assert_eq!(rest.data.len(), 3);
        assert!(rx.try_recv().is_err());
    }

    /// B3: a saturated budget pends the poll and leaves the caller's
    /// slot untouched — the all-or-nothing acquire is what keeps the
    /// re-presented buffer's headroom check unambiguous.
    #[tokio::test]
    async fn headroom_slot_pending_leaves_buffer_untouched() {
        let (stream, mut rx) = stream();
        // Exhaust the writer budget.
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..QUEUED_FRAMES {
            match stream.poll_write_data(&mut cx, b"x") {
                Poll::Ready(Ok(_)) => {}
                other => panic!("budget fill must succeed, got {other:?}"),
            }
        }
        let mut buf = BytesMut::from(&[0u8; HEADER_OVERHEAD_SIZE + 4][..]);
        buf[HEADER_OVERHEAD_SIZE..].copy_from_slice(b"data");
        let buf_snapshot = buf.clone();
        let mut slot = Some(buf);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            stream.poll_write_bytes_data(&mut cx, &mut slot),
            Poll::Pending
        ));
        let slot_ref = slot.as_ref().expect("slot stays Some on Pending");
        assert_eq!(&slot_ref[..], &buf_snapshot[..], "untouched for retry");
        // Drain one queued frame → retry must now succeed.
        let _ = rx.recv().await.unwrap();
        assert!(matches!(
            stream.poll_write_bytes_data(&mut cx, &mut slot),
            Poll::Ready(Ok(()))
        ));
    }

    #[tokio::test]
    async fn test_stream_read() {
        let (writer, _rx) = StreamWriter::channel();
        let (reader_tx, reader_rx) = mpsc::unbounded_channel();
        let (mut stream, _) = Stream::new(1, StreamReader::new(1, reader_rx), writer);
        reader_tx.send(Bytes::from_static(b"world").into()).unwrap();
        let mut buf = [0; 10];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 5);
        assert_eq!(&buf[..5], b"world");
    }
}
