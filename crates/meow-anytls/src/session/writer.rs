//! Cancellation-safe admission to the session's single wire writer.

use crate::protocol::{Command, Frame, HEADER_OVERHEAD_SIZE};
use crate::util::{AnyTlsError, Result};
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

/// Largest payload one frame carries. Chosen so a relay-sized bulk fill
/// plus its 7-byte header fits one 64 KiB scratch exactly: the relay
/// reserves `HEADER_OVERHEAD_SIZE` ahead of a `64 KiB - 7` read window,
/// so every fill ships as ONE frame — a 65535 cap would split a
/// 65536-byte fill into a full frame + a 7-byte tail fragment.
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024 - HEADER_OVERHEAD_SIZE;
// The protocol ceiling is u16::MAX (the wire length field); the value
// above is the batching sweet spot beneath it — a relay-sized fill +
// header fits 64 KiB exactly.
const _: () = assert!(MAX_FRAME_PAYLOAD <= u16::MAX as usize);
// At most 64 data/control frames (about 4 MiB of payload) per session.
// FIN and flush markers bypass the budget so Drop never needs to spawn a task.
pub(crate) const QUEUED_FRAMES: usize = 64;

/// Payload cap per command kind: data frames use the batching bound so
/// a relay-sized fill + header fits 64 KiB; control frames ride the
/// protocol's u16 ceiling — an UpdatePaddingScheme can legitimately be
/// larger than the batching target and must still send.
fn frame_payload_cap(cmd: Command) -> usize {
    if cmd == Command::Push {
        MAX_FRAME_PAYLOAD
    } else {
        u16::MAX as usize
    }
}

pub(crate) enum WriteRequest {
    Frame {
        frame: Frame,
        _permit: Option<OwnedSemaphorePermit>,
        completion: Option<oneshot::Sender<Result<()>>>,
        /// The `Stream` instance that issued this frame, when the frame
        /// must not outlive its owner's sid ownership (Fin, SynAck).
        /// The batch writer commits the frame to the wire only while
        /// the instance still owns `frame.stream_id` in the session map
        /// — a retired handler's Fin/SynAck can neither reach the peer
        /// nor evict a recycled SID's new stream (F05).
        owner: Option<std::sync::Weak<crate::session::stream::Stream>>,
    },
    /// A pre-encoded contiguous wire image — `[header | payload]` in ONE
    /// `Bytes` — produced by `Stream::poll_write_bytes_data` when the
    /// caller's slot carried the frame's headroom prefix. Skips the
    /// session's per-frame header+payload reassembly entirely: the batch
    /// writer moves it to the wire untouched.
    Wire {
        wire: Bytes,
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
        owner: Option<std::sync::Weak<crate::session::stream::Stream>>,
    ) -> Result<()> {
        if self.budget.is_closed() {
            return Err(AnyTlsError::SessionClosed);
        }
        self.tx
            .send(WriteRequest::Frame {
                frame,
                _permit: permit,
                completion,
                owner,
            })
            .map_err(|_| AnyTlsError::SessionClosed)
    }

    pub(crate) async fn write_frame(&self, frame: Frame) -> Result<()> {
        self.write_frame_owned(frame, None).await
    }

    /// `write_frame` with an owner token — see [`WriteRequest::Frame::owner`].
    pub(crate) async fn write_frame_owned(
        &self,
        frame: Frame,
        owner: Option<std::sync::Weak<crate::session::stream::Stream>>,
    ) -> Result<()> {
        if frame.data.len() > frame_payload_cap(frame.cmd) {
            return Err(AnyTlsError::Protocol(
                "frame payload exceeds u16 length".into(),
            ));
        }
        let permit = Arc::clone(&self.budget)
            .acquire_owned()
            .await
            .map_err(|_| AnyTlsError::SessionClosed)?;
        let (tx, rx) = oneshot::channel();
        self.enqueue(frame, Some(permit), Some(tx), owner)?;
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
        if frame.data.len() > frame_payload_cap(frame.cmd) {
            return Err(AnyTlsError::Protocol(
                "frame payload exceeds u16 length".into(),
            ));
        }
        let permit = Arc::clone(&self.budget)
            .acquire_owned()
            .await
            .map_err(|_| AnyTlsError::SessionClosed)?;
        self.enqueue(frame, Some(permit), None, None)
    }

    /// Fire-and-forget admission of a contiguous wire image — the
    /// [`WriteRequest::Wire`] counterpart of [`enqueue`](Self::enqueue).
    /// The image already carries its header, so the session writer only
    /// ever moves it.
    pub(crate) fn enqueue_wire(
        &self,
        wire: Bytes,
        permit: Option<OwnedSemaphorePermit>,
        completion: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
        if self.budget.is_closed() {
            return Err(AnyTlsError::SessionClosed);
        }
        self.tx
            .send(WriteRequest::Wire {
                wire,
                _permit: permit,
                completion,
            })
            .map_err(|_| AnyTlsError::SessionClosed)
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
