//! Cancellation-safe admission to the session's single wire writer.

use crate::protocol::Frame;
use crate::util::{AnyTlsError, Result};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;
// At most 64 data/control frames (about 4 MiB of payload) per session.
// FIN and flush markers bypass the budget so Drop never needs to spawn a task.
const QUEUED_FRAMES: usize = 64;

pub(crate) enum WriteRequest {
    Frame {
        frame: Frame,
        _permit: Option<OwnedSemaphorePermit>,
        completion: Option<oneshot::Sender<Result<()>>>,
    },
    Flush(oneshot::Sender<Result<()>>),
}

/// Shared handle to a session writer. Created by `Session`, cloned into streams.
#[derive(Clone)]
pub struct StreamWriter {
    tx: mpsc::UnboundedSender<WriteRequest>,
    pub(crate) budget: Arc<Semaphore>,
}

impl StreamWriter {
    pub(crate) fn channel() -> (Self, mpsc::UnboundedReceiver<WriteRequest>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                tx,
                budget: Arc::new(Semaphore::new(QUEUED_FRAMES)),
            },
            rx,
        )
    }

    pub(crate) fn close(&self) {
        self.budget.close();
    }

    pub(crate) fn enqueue(
        &self,
        frame: Frame,
        permit: Option<OwnedSemaphorePermit>,
        completion: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
        if self.budget.is_closed() {
            return Err(AnyTlsError::SessionClosed);
        }
        self.tx
            .send(WriteRequest::Frame {
                frame,
                _permit: permit,
                completion,
            })
            .map_err(|_| AnyTlsError::SessionClosed)
    }

    pub(crate) async fn write_frame(&self, frame: Frame) -> Result<()> {
        if frame.data.len() > MAX_FRAME_PAYLOAD {
            return Err(AnyTlsError::Protocol(
                "frame payload exceeds u16 length".into(),
            ));
        }
        let permit = Arc::clone(&self.budget)
            .acquire_owned()
            .await
            .map_err(|_| AnyTlsError::SessionClosed)?;
        let (tx, rx) = oneshot::channel();
        self.enqueue(frame, Some(permit), Some(tx))?;
        // Dropping this receiver cannot cancel the physical frame write.
        rx.await.map_err(|_| AnyTlsError::SessionClosed)?
    }

    /// Fire-and-forget admission: the identical budget permit + FIFO
    /// queueing as [`write_frame`](Self::write_frame), but resolves once
    /// the frame is queued — the single writer task completes the
    /// physical write in order. Used where the write+flush round-trip
    /// would only add latency (the stream-open SYN and address frames,
    /// matching anytls-go's enqueue semantics). A closed session still
    /// fails fast through the budget check.
    pub(crate) async fn enqueue_frame(&self, frame: Frame) -> Result<()> {
        if frame.data.len() > MAX_FRAME_PAYLOAD {
            return Err(AnyTlsError::Protocol(
                "frame payload exceeds u16 length".into(),
            ));
        }
        let permit = Arc::clone(&self.budget)
            .acquire_owned()
            .await
            .map_err(|_| AnyTlsError::SessionClosed)?;
        self.enqueue(frame, Some(permit), None)
    }

    pub(crate) fn flush(&self) -> Result<oneshot::Receiver<Result<()>>> {
        let (tx, rx) = oneshot::channel();
        if self.budget.is_closed() {
            return Err(AnyTlsError::SessionClosed);
        }
        self.tx
            .send(WriteRequest::Flush(tx))
            .map_err(|_| AnyTlsError::SessionClosed)?;
        Ok(rx)
    }
}
