//! A multiplexed AnyTLS stream with bounded, cancellation-safe writes.

use crate::protocol::{Command, Frame};
use crate::session::StreamReader;
use crate::session::writer::{MAX_FRAME_PAYLOAD, StreamWriter};
use crate::util::{AnyTlsError, Result};
use bytes::Bytes;
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

/// Stream represents a single data stream within a Session.
pub struct Stream {
    id: u32,
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
        state.closed = true;
        // Drop a pending semaphore acquisition, releasing its reserved permits.
        state.permits = PollSemaphore::new(Arc::clone(&self.writer.budget));
        if send_fin && !state.fin_sent {
            state.fin_sent = true;
            // A pending flush may precede FIN. Shutdown must acknowledge a
            // fresh barrier after it, even if an earlier flush was cancelled.
            state.flush = None;
            let _ = self
                .writer
                .enqueue(Frame::control(Command::Fin, self.id), None, None);
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
            .enqueue(Frame::data(self.id, data), Some(permit), None)
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
            )
            .map_err(std::io::Error::other)?;
        Poll::Ready(Ok(len))
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

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let stream_id = self.id;
        let remaining = buf.remaining();

        // 使用 tokio::task::block_in_place 同步读取
        // 这避免了复杂的 Future polling 和借用问题
        let reader = Arc::clone(&self.reader);

        // 创建读取 future
        let mut read_fut = Box::pin(async move {
            let mut reader_guard = reader.lock().await;
            let mut temp_buf = vec![0u8; remaining];
            let n = reader_guard.read(&mut temp_buf).await?;
            Ok::<(usize, Vec<u8>), std::io::Error>((n, temp_buf))
        });

        // Poll the future
        match read_fut.as_mut().poll(cx) {
            Poll::Ready(Ok((n, temp_buf))) => {
                if n > 0 {
                    buf.put_slice(&temp_buf[..n]);
                    tracing::trace!(
                        "[Stream] poll_read: Read {} bytes (stream_id={})",
                        n,
                        stream_id
                    );
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                tracing::error!(
                    "[Stream] poll_read: Error reading (stream_id={}): {}",
                    stream_id,
                    e
                );
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
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
            WriteRequest::Flush(_) => panic!("expected frame"),
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

    #[tokio::test]
    async fn test_stream_read() {
        let (writer, _rx) = StreamWriter::channel();
        let (reader_tx, reader_rx) = mpsc::unbounded_channel();
        let (mut stream, _) = Stream::new(1, StreamReader::new(1, reader_rx), writer);
        reader_tx.send(Bytes::from_static(b"world")).unwrap();
        let mut buf = [0; 10];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 5);
        assert_eq!(&buf[..5], b"world");
    }
}
