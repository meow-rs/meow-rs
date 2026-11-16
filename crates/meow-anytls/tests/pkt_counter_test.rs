//! B2 regression: the first padded session write must consume padding
//! scheme index **1** — index 0 already belongs to the authentication
//! packet (`send_authentication` takes `generate_record_payload_sizes(0)`
//! for padding0). `Session::write_with_padding` used `fetch_add`'s OLD
//! value, so its first padded write indexed the scheme at 0 instead of
//! upstream `pktCounter.Add(1)`'s new value.
//!
//! The scheme index is observable without instrumenting the counter: a
//! fixed `N-N` size makes the whole padded record exactly N bytes on the
//! wire (payload + Waste frame to fill), so distinct per-index record
//! sizes reveal which index each write consumed.

use anytls_rs::padding::PaddingFactory;
use anytls_rs::protocol::Frame;
use anytls_rs::session::Session;
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

/// Records every `poll_write`'s length — the padded-record-size
/// observatory (padding always goes through `write_all`, never
/// `write_vectored`).
#[derive(Default)]
struct SizeWriter {
    writes: Arc<Mutex<Vec<usize>>>,
}

impl AsyncWrite for SizeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.lock().unwrap().push(buf.len());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Auth consumes scheme index 0 (30-byte padding0), so the session's
/// first three padded writes must index the scheme at 1, 2, 3 —
/// observable as record sizes 111, 222, 333 on the wire. The pre-fix
/// off-by-one produced index 0 on the first write instead.
#[tokio::test]
async fn padded_session_writes_start_at_scheme_index_one() {
    let padding = Arc::new(
        PaddingFactory::new(b"stop=8\n0=30-30\n1=111-111\n2=222-222\n3=333-333".as_slice())
            .unwrap(),
    )
    .into_shared();

    let writes = Arc::new(Mutex::new(Vec::new()));
    let session = Arc::new(Session::new_client(
        tokio::io::empty(),
        SizeWriter {
            writes: Arc::clone(&writes),
        },
        padding,
        None,
    ));
    let worker = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.process_stream_data().await })
    };

    // `write_frame` resolves once the batch carrying the frame has been
    // written + flushed, so after each await the record is observable.
    for _ in 0..3 {
        session
            .write_frame(Frame::data(1, Bytes::from_static(&[0xAA; 16])))
            .await
            .unwrap();
    }

    assert_eq!(*writes.lock().unwrap(), vec![111, 222, 333]);

    session.close().await.unwrap();
    worker.await.unwrap().unwrap();
}
