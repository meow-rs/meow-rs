//! B3 zero-copy: a relay-style `BytesMut` slot carrying the reserved
//! 7-byte headroom prefix must reach the wire as ONE contiguous frame —
//! header overlaid in place, payload moved untouched. The vectored
//! writer below captures each `IoSlice`: the frame's pointer must equal
//! the caller's buffer pointer (the same allocation end to end), and a
//! 65529-byte fill — the relay's `64 KiB - headroom` read window — must
//! ship as exactly one frame (no 7-byte tail fragment).

use anytls_rs::padding::PaddingFactory;
use anytls_rs::protocol::{Command, HEADER_OVERHEAD_SIZE};
use anytls_rs::session::{Session, writer::MAX_FRAME_PAYLOAD};
use bytes::BytesMut;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncWrite;

/// Shared recorder state a test inspects after handing the writer half
/// to the session.
type Calls = Arc<Mutex<Vec<Vec<Vec<u8>>>>>;
type Ptrs = Arc<Mutex<Vec<usize>>>;

/// A vectored sink that records every `IoSlice` it is handed — the wire
/// image as the session's `write_vectored` presented it, per call.
struct VectoredRecorder {
    /// Each element is one `write_vectored` call's slice list.
    calls: Calls,
    /// Every slice's data pointer, flattened across calls, in the same
    /// order as `calls`.
    ptrs: Ptrs,
}

impl VectoredRecorder {
    fn new() -> (Self, Calls, Ptrs) {
        let calls = Calls::default();
        let ptrs = Ptrs::default();
        (
            Self {
                calls: Arc::clone(&calls),
                ptrs: Arc::clone(&ptrs),
            },
            calls,
            ptrs,
        )
    }
}

impl AsyncWrite for VectoredRecorder {
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.calls.lock().unwrap().push(vec![buf.to_vec()]);
        self.ptrs.lock().unwrap().push(buf.as_ptr() as usize);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.calls
            .lock()
            .unwrap()
            .push(bufs.iter().map(|b| b.to_vec()).collect());
        self.ptrs
            .lock()
            .unwrap()
            .extend(bufs.iter().map(|b| b.as_ptr() as usize));
        Poll::Ready(Ok(bufs.iter().map(|b| b.len()).sum()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Flatten every recorded call into one ordered slice list — the wire
/// byte stream as the writer saw it, batch-agnostic (a drain may batch
/// the SYN and the first data frame into one `write_vectored`).
fn flat(calls: &Calls) -> Vec<Vec<u8>> {
    calls.lock().unwrap().concat()
}

/// Wait until at least `n` slices have reached the writer.
async fn wait_slices(calls: &Calls, n: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if flat(calls).len() >= n {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed out waiting for session writes")
}

/// Server session (no client buffering/padding) over the recorder, with
/// the writer task running.
async fn session_pair(rec: VectoredRecorder) -> Arc<Session> {
    let session = Arc::new(Session::new_server(
        tokio::io::empty(),
        rec,
        PaddingFactory::default(),
    ));
    let worker = Arc::clone(&session);
    tokio::spawn(async move {
        let _ = worker.process_stream_data().await;
    });
    session
}

/// One headroom slot → exactly one IoSlice on the wire, sharing the
/// caller's allocation pointer, containing [Push | sid | len | payload].
#[tokio::test]
async fn headroom_fill_reaches_wire_as_one_contiguous_frame() {
    let (rec, calls, ptrs) = VectoredRecorder::new();
    let session = session_pair(rec).await;
    let (stream, _synack) = session.open_stream().await.unwrap();

    let payload = vec![0xABu8; 4096];
    let mut buf = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + payload.len());
    buf.extend_from_slice(&[0u8; HEADER_OVERHEAD_SIZE]);
    buf.extend_from_slice(&payload);
    let buf_ptr = buf.as_ptr() as usize;
    let mut slot = Some(buf);

    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        stream.poll_write_bytes_data(&mut cx, &mut slot),
        Poll::Ready(Ok(()))
    ));
    assert!(slot.is_none());

    // SYN contributes ≥1 slice; the data frame is the LAST slice —
    // FIFO inside whatever batch the drain caught.
    wait_slices(&calls, 2).await;
    tokio::task::yield_now().await;
    let wire = flat(&calls);
    let image = wire.last().expect("data slice must exist");
    assert_eq!(
        image.len(),
        HEADER_OVERHEAD_SIZE + payload.len(),
        "contiguous [header|payload] image — a Split frame would have \
         emitted separate header and payload slices"
    );
    assert_eq!(image[0], u8::from(Command::Push));
    assert_eq!(
        u32::from_be_bytes(image[1..5].try_into().unwrap()),
        stream.id()
    );
    assert_eq!(
        u16::from_be_bytes([image[5], image[6]]) as usize,
        payload.len()
    );
    assert_eq!(&image[HEADER_OVERHEAD_SIZE..], &payload[..]);

    // Pointer identity: the wire slice starts at the caller's buffer —
    // the header was overlaid into the reserved prefix, the payload
    // never moved.
    let ptrs = ptrs.lock().unwrap().clone();
    assert_eq!(
        *ptrs.last().unwrap(),
        buf_ptr,
        "wire image is the caller's own allocation"
    );

    session.close().await.unwrap();
}

/// A 65529-byte payload (the relay's `64 KiB - 7` read window) ships as
/// exactly one frame — `MAX_FRAME_PAYLOAD = 65529` exists to kill the
/// tail fragment a 65535 cap produced on a 64 KiB fill.
#[tokio::test]
async fn relay_sized_fill_is_exactly_one_frame() {
    let (rec, calls, _ptrs) = VectoredRecorder::new();
    let session = session_pair(rec).await;
    let (stream, _synack) = session.open_stream().await.unwrap();

    let mut buf = BytesMut::with_capacity(64 * 1024);
    buf.extend_from_slice(&[0u8; HEADER_OVERHEAD_SIZE]);
    buf.resize(64 * 1024, 0xCD);
    let mut slot = Some(buf);

    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        stream.poll_write_bytes_data(&mut cx, &mut slot),
        Poll::Ready(Ok(()))
    ));

    wait_slices(&calls, 2).await;
    let wire = flat(&calls);
    let pushes: Vec<&Vec<u8>> = wire
        .iter()
        .filter(|s| s[0] == u8::from(Command::Push))
        .collect();
    assert_eq!(pushes.len(), 1, "one fill must be one frame — no tail");
    assert_eq!(pushes[0].len(), 64 * 1024);
    assert_eq!(
        u16::from_be_bytes([pushes[0][5], pushes[0][6]]) as usize,
        MAX_FRAME_PAYLOAD
    );

    session.close().await.unwrap();
}
