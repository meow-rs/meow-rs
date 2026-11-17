//! B3 relay-path integration: fills shaped exactly like the relay's
//! `Scratch::BytesMut` arm produces them — `want_write_headroom()` zero
//! bytes ahead of the payload — must emerge from the session as ordered,
//! contiguous, byte-exact frames. This drives the real queue path:
//! `poll_write_bytes_data` → `WriteRequest::Wire` → `write_batch` →
//! wire, decoded at the peer end of a duplex.

use anytls_rs::padding::PaddingFactory;
use anytls_rs::protocol::{Command, HEADER_OVERHEAD_SIZE};
use anytls_rs::session::{Session, writer::MAX_FRAME_PAYLOAD};
use bytes::{BufMut, BytesMut};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, DuplexStream, duplex};

/// Build a relay-shaped fill: `headroom` reserved zeros followed by
/// `pattern` payload — what `Scratch::BytesMut`'s read arm produces.
fn relay_fill(headroom: usize, payload: &[u8]) -> BytesMut {
    let mut bm = BytesMut::with_capacity(headroom + payload.len());
    bm.put_bytes(0, headroom);
    bm.extend_from_slice(payload);
    bm
}

/// Read exactly one frame from the peer end; skips nothing (padding is
/// off for server sessions).
async fn read_frame(peer: &mut DuplexStream) -> (u8, u32, Vec<u8>) {
    let mut header = [0u8; HEADER_OVERHEAD_SIZE];
    tokio::time::timeout(Duration::from_secs(5), peer.read_exact(&mut header))
        .await
        .expect("frame header timed out")
        .unwrap();
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut payload = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), peer.read_exact(&mut payload))
        .await
        .expect("frame payload timed out")
        .unwrap();
    (
        header[0],
        u32::from_be_bytes(header[1..5].try_into().unwrap()),
        payload,
    )
}

async fn server_session(peer_writer: DuplexStream) -> Arc<Session> {
    let session = Arc::new(Session::new_server(
        tokio::io::empty(),
        peer_writer,
        PaddingFactory::default(),
    ));
    let worker = Arc::clone(&session);
    tokio::spawn(async move {
        let _ = worker.process_stream_data().await;
    });
    session
}

/// The stream's declared headroom want is the 7-byte frame header.
#[tokio::test]
async fn stream_declares_frame_headroom() {
    let (client, _peer) = duplex(1024);
    let session = server_session(client).await;
    let (stream, _synack) = session.open_stream().await.unwrap();
    assert_eq!(stream.want_write_headroom(), HEADER_OVERHEAD_SIZE);
    session.close().await.unwrap();
}

/// End-to-end relay emulation: the scratch fill (headroom + payload)
/// crosses `poll_write_bytes_data` → session FIFO → wire → peer decode,
/// arriving as one Push frame with the payload byte-exact.
#[tokio::test]
async fn relay_fill_decodes_as_one_push_at_the_peer() {
    let (client, mut peer) = duplex(256 * 1024);
    let session = server_session(client).await;
    let (stream, _synack) = session.open_stream().await.unwrap();

    // First frame at the peer is the open's SYN — drain it.
    let (cmd, _sid, _p) = read_frame(&mut peer).await;
    assert_eq!(cmd, u8::from(Command::Syn));

    // The relay's declared want drives the scratch layout.
    let headroom = stream.want_write_headroom();
    let payload: Vec<u8> = (0..8192u32).flat_map(|v| v.to_be_bytes()).collect();
    let mut slot = Some(relay_fill(headroom, &payload));
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        stream.poll_write_bytes_data(&mut cx, &mut slot),
        Poll::Ready(Ok(()))
    ));
    assert!(slot.is_none());

    let (cmd, sid, decoded) = read_frame(&mut peer).await;
    assert_eq!(cmd, u8::from(Command::Push));
    assert_eq!(sid, stream.id());
    assert_eq!(decoded, payload, "payload crosses verbatim");

    session.close().await.unwrap();
}

/// The relay's maximum fill — `64 KiB` scratch minus the 7-byte
/// reservation = `MAX_FRAME_PAYLOAD` payload — crosses as ONE frame:
/// `MAX_FRAME_PAYLOAD` exists precisely so this fill never fragments.
#[tokio::test]
async fn max_relay_fill_is_one_frame_on_the_wire() {
    let (client, mut peer) = duplex(256 * 1024);
    let session = server_session(client).await;
    let (stream, _synack) = session.open_stream().await.unwrap();
    let (cmd, _sid, _p) = read_frame(&mut peer).await;
    assert_eq!(cmd, u8::from(Command::Syn));

    let headroom = stream.want_write_headroom();
    let fill_len = 64 * 1024 - headroom;
    assert_eq!(fill_len, MAX_FRAME_PAYLOAD, "the read window is one frame");
    let payload = vec![0xA5u8; fill_len];
    let mut slot = Some(relay_fill(headroom, &payload));
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        stream.poll_write_bytes_data(&mut cx, &mut slot),
        Poll::Ready(Ok(()))
    ));

    let (cmd, sid, decoded) = read_frame(&mut peer).await;
    assert_eq!(cmd, u8::from(Command::Push));
    assert_eq!(sid, stream.id());
    assert_eq!(decoded.len(), fill_len);
    assert_eq!(decoded, payload);

    // And the stream is silent after it — no tail fragment follows.
    let mut one = [0u8; 1];
    let extra = tokio::time::timeout(Duration::from_millis(250), peer.read(&mut one)).await;
    assert!(extra.is_err(), "no second frame follows a max fill");

    session.close().await.unwrap();
}

/// Fills queued back-to-back preserve wire order — the session FIFO is
/// the ordering contract the relay's sequential `poll_cycle` relies on.
#[tokio::test]
async fn consecutive_relay_fills_keep_fifo_order() {
    let (client, mut peer) = duplex(256 * 1024);
    let session = server_session(client).await;
    let (stream, _synack) = session.open_stream().await.unwrap();
    let (cmd, _sid, _p) = read_frame(&mut peer).await;
    assert_eq!(cmd, u8::from(Command::Syn));

    let headroom = stream.want_write_headroom();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    for i in 0u8..4 {
        let payload = vec![i; 1024 + i as usize];
        let mut slot = Some(relay_fill(headroom, &payload));
        assert!(matches!(
            stream.poll_write_bytes_data(&mut cx, &mut slot),
            Poll::Ready(Ok(()))
        ));
    }
    for i in 0u8..4 {
        let (cmd, sid, decoded) = read_frame(&mut peer).await;
        assert_eq!(cmd, u8::from(Command::Push));
        assert_eq!(sid, stream.id());
        assert_eq!(decoded, vec![i; 1024 + i as usize], "fill {i} out of order");
    }

    session.close().await.unwrap();
}

/// A headroom-free slot (a caller that presents bare payload) still
/// crosses correctly through the `Frame::data` path — the contract's
/// non-headroom arm.
#[tokio::test]
async fn bare_payload_slot_crosses_via_plain_frames() {
    let (client, mut peer) = duplex(256 * 1024);
    let session = server_session(client).await;
    let (stream, _synack) = session.open_stream().await.unwrap();
    let (cmd, _sid, _p) = read_frame(&mut peer).await;
    assert_eq!(cmd, u8::from(Command::Syn));

    let payload = b"no headroom reserved".to_vec();
    let mut slot = Some(BytesMut::from(&payload[..]));
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        stream.poll_write_bytes_data(&mut cx, &mut slot),
        Poll::Ready(Ok(()))
    ));
    let (cmd, sid, decoded) = read_frame(&mut peer).await;
    assert_eq!(cmd, u8::from(Command::Push));
    assert_eq!(sid, stream.id());
    assert_eq!(decoded, payload);

    session.close().await.unwrap();
}
