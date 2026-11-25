//! Cancellation-safe admission to the session's single wire writer.

use crate::protocol::{Command, Frame, HEADER_OVERHEAD_SIZE};
use crate::util::{AnyTlsError, Result};
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

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

/// RAII token tracking an in-flight control frame so the session writer
/// enforces its forward-progress deadline while at least one control frame
/// is queued or writing, without imposing that timer on data-only batches.
pub(crate) struct ControlTicket {
    counter: Arc<AtomicUsize>,
}

impl Drop for ControlTicket {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Release);
    }
}

pub(crate) enum WriteRequest {
    Frame {
        frame: Frame,
        _permit: Option<OwnedSemaphorePermit>,
        _control: Option<ControlTicket>,
        completion: Option<oneshot::Sender<Result<()>>>,
        /// The `Stream` instance that issued this frame, when the frame
        /// must not outlive its owner's sid ownership (Fin, SynAck).
        /// Checked under the physical writer lock right before bytes hit
        /// the transport so a retired handler's frame can neither reach
        /// the peer nor evict a recycled SID's new stream (F05/F06).
        owner: Option<std::sync::Weak<crate::session::stream::Stream>>,
        /// Set when a bounded caller (`write_control_frame*`) timed out
        /// or was cancelled before commit — strands the queued frame at
        /// the wire-commit gate so it cannot fire late (F06).
        abandoned: Option<Arc<AtomicBool>>,
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
    pending_controls: Arc<AtomicUsize>,
    pub(crate) control_notify: Arc<Notify>,
}

impl StreamWriter {
    pub(crate) fn channel() -> (Self, mpsc::UnboundedReceiver<WriteRequest>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                tx,
                budget: Arc::new(Semaphore::new(QUEUED_FRAMES)),
                pending_controls: Arc::new(AtomicUsize::new(0)),
                control_notify: Arc::new(Notify::new()),
            },
            rx,
        )
    }

    pub(crate) fn close(&self) {
        self.budget.close();
    }

    pub(crate) fn has_pending_controls(&self) -> bool {
        self.pending_controls.load(Ordering::Acquire) > 0
    }

    pub(crate) fn enqueue(
        &self,
        frame: Frame,
        permit: Option<OwnedSemaphorePermit>,
        completion: Option<oneshot::Sender<Result<()>>>,
        owner: Option<std::sync::Weak<crate::session::stream::Stream>>,
    ) -> Result<()> {
        self.enqueue_with_abandon(frame, permit, completion, owner, None)
    }

    fn enqueue_with_abandon(
        &self,
        frame: Frame,
        permit: Option<OwnedSemaphorePermit>,
        completion: Option<oneshot::Sender<Result<()>>>,
        owner: Option<std::sync::Weak<crate::session::stream::Stream>>,
        abandoned: Option<Arc<AtomicBool>>,
    ) -> Result<()> {
        if self.budget.is_closed() {
            return Err(AnyTlsError::SessionClosed);
        }
        let is_control = !matches!(frame.cmd, Command::Push | Command::Waste);
        let control = is_control.then(|| {
            self.pending_controls.fetch_add(1, Ordering::AcqRel);
            ControlTicket {
                counter: Arc::clone(&self.pending_controls),
            }
        });
        self.tx
            .send(WriteRequest::Frame {
                frame,
                _permit: permit,
                _control: control,
                completion,
                owner,
                abandoned,
            })
            .map_err(|_| AnyTlsError::SessionClosed)?;
        if is_control {
            self.control_notify.notify_waiters();
        }
        Ok(())
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
        self.write_frame_cancellable(frame, owner, None).await
    }

    pub(crate) async fn write_frame_cancellable(
        &self,
        frame: Frame,
        owner: Option<std::sync::Weak<crate::session::stream::Stream>>,
        abandoned: Option<Arc<AtomicBool>>,
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
        self.enqueue_with_abandon(frame, Some(permit), Some(tx), owner, abandoned)?;
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
