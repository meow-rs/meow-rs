//! Integration tests for the gRPC (gun) transport layer.
//!
//! All tests require `--features grpc` (enforced via `required-features` in
//! Cargo.toml).
//!
//! # Test plan coverage
//!
//! | ID | Description |
//! |----|-------------|
//! | A  | `grpc_framing_matches_upstream` — byte-for-byte wire format comparison with a hand-rolled reference encoder |
//! | B  | `grpc_service_name_in_path` — `:path` must be `/{service_name}/Tun` |
//! | C  | `grpc_content_type_header` — request must carry `content-type: application/grpc` |
//! | D  | `grpc_round_trip` — 4 MiB loopback echo through a real h2 server |
//! | E  | `grpc_round_trip_with_deferred_response` — server withholds response HEADERS until the first client hunk (issue #377) |
//! | F  | `grpc_poll_write_rejects_changed_buffer_after_pending` — changed-buffer guard (issue #433) |
//! | G  | `grpc_poll_write_same_buffer_retry_succeeds_after_pending` — legitimate same-buffer retry still completes (issue #433) |
//! | H  | `grpc_shutdown_flushes_stashed_frame_before_eos` — shutdown flushes a frame stashed by a cancelled write (PR #440 follow-up) |
//! | I  | `grpc_shutdown_after_rejected_buffer_does_not_resurrect_frame` — shutdown never resends a frame cleared by the changed-buffer rejection (PR #440 follow-up) |
//! | J  | `grpc_empty_write_is_noop_even_with_stashed_frame` — `write(&[])` returns `Ok(0)` without tripping the changed-buffer guard (PR #440 follow-up) |
//! | K  | `grpc_receive_window_absorbs_1mib_before_first_read` — the client advertises proxy-sized receive windows, so a server can push 1 MiB before the first read (issue #495) |

mod support;

use std::time::Duration;

use meow_transport::grpc::{decode_gun_frame, encode_gun_frame, GrpcConfig, GrpcLayer};
use meow_transport::Transport;
use meow_transport::TransportError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use support::h2_push::spawn_h2_push_server;
use support::loopback::{spawn_grpc_server, spawn_grpc_server_deferred_response};

async fn assert_grpc_config_error(config: GrpcConfig, expected: &str) {
    let (client, _server) = tokio::io::duplex(64);
    let layer = GrpcLayer::new(config);
    let Err(err) = layer.connect(Box::new(client)).await else {
        panic!("invalid grpc config unexpectedly connected");
    };
    match err {
        TransportError::Config(msg) => {
            assert!(
                msg.contains(expected),
                "expected config error containing {expected:?}, got: {msg}"
            );
        }
        other => panic!("expected TransportError::Config, got: {other:?}"),
    }
}

// ─── A: Reference framing test ────────────────────────────────────────────────
//
// Port of `transport/gun/gun.go`'s WriteBytes / ReadBytes encoding.
// Asserts byte-for-byte equality with a hand-rolled reference encoder so any
// upstream divergence is caught before it silently breaks VMess/VLESS-over-gRPC.

/// Encode `payload` using the spec definition:
///   `[0x00] [BE32(inner_len)] [0x0A] [uleb128(payload.len())] [payload]`
///
/// This is the independent reference framer — it intentionally does NOT call
/// `encode_gun_frame`; the two results are compared byte-for-byte in the test.
fn reference_encode(payload: &[u8]) -> Vec<u8> {
    // uleb128(n): emit 7 bits per byte, MSB = 1 if more bytes follow.
    fn uleb128(mut n: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        loop {
            let mut byte = (n & 0x7F) as u8;
            n >>= 7;
            if n != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if n == 0 {
                break;
            }
        }
        out
    }

    let varint = uleb128(payload.len() as u64);
    // inner = [field-1 tag] + varint + payload
    let inner_len = 1 + varint.len() + payload.len();

    let mut buf = Vec::with_capacity(5 + inner_len);
    buf.push(0x00u8); // grpc compression flag — always 0x00 (no compression)
    let n = inner_len as u32;
    buf.extend_from_slice(&n.to_be_bytes()); // BE32(inner_len)
    buf.push(0x0Au8); // proto field 1, wire type 2 (length-delimited)
    buf.extend_from_slice(&varint); // uleb128(payload.len())
    buf.extend_from_slice(payload); // raw payload bytes
    buf
}

/// A: `grpc_framing_matches_upstream`
///
/// Encodes a 1 KiB payload with both the crate's `encode_gun_frame` and the
/// inline reference framer, then asserts byte-for-byte equality.  Also verifies
/// that `decode_gun_frame` fully recovers the original payload.
#[test]
fn grpc_framing_matches_upstream() {
    // 1 KiB of a repeating pattern — non-zero to catch off-by-one in byte slices.
    let payload: Vec<u8> = (0u8..=255).cycle().take(1024).collect();

    let encoded = encode_gun_frame(&payload);
    let reference = reference_encode(&payload);

    assert_eq!(
        encoded, reference,
        "encode_gun_frame must match reference wire format byte-for-byte"
    );

    // Spot-check the 5-byte gRPC header manually.
    // uleb128(1024): 1024 = 0b10000000000; first 7 bits = 0 (need more) → 0x80;
    // next 7 bits = 8 → 0x08.  inner_len = 1 + 2 + 1024 = 1027 = 0x403.
    assert_eq!(encoded[0], 0x00, "compression flag must be 0x00");
    assert_eq!(
        &encoded[1..5],
        &[0x00, 0x00, 0x04, 0x03],
        "BE32(inner_len=1027)"
    );
    assert_eq!(encoded[5], 0x0A, "proto field tag must be 0x0A");
    assert_eq!(&encoded[6..8], &[0x80, 0x08], "uleb128(1024)");
    assert_eq!(&encoded[8..], payload.as_slice(), "payload bytes");

    // decode must be the exact inverse.
    let decoded = decode_gun_frame(&encoded).expect("decode_gun_frame");
    assert_eq!(decoded, payload.as_slice());
}

#[test]
fn grpc_decode_rejects_payload_length_overflow_without_panic() {
    let mut frame = vec![
        0x00, // compression flag
        0x00, 0x00, 0x00, 0x0B, // inner_len = tag + 10-byte varint
        0x0A, // proto field 1, wire type 2
    ];
    frame.extend_from_slice(&[0xFF; 9]);
    frame.push(0x01); // uleb128(u64::MAX)

    let err = decode_gun_frame(&frame).expect_err("overflowing payload length must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("payload length") && msg.contains("overflow"),
        "expected payload length overflow error, got: {msg}"
    );
}

#[tokio::test]
async fn grpc_rejects_invalid_request_config_before_handshake() {
    assert_grpc_config_error(
        GrpcConfig {
            service_name: "Bad Service".into(),
            ..Default::default()
        },
        "invalid request config",
    )
    .await;

    assert_grpc_config_error(
        GrpcConfig {
            authority: "bad authority".into(),
            ..Default::default()
        },
        "invalid request config",
    )
    .await;
}

// ─── B: Service name in :path ─────────────────────────────────────────────────

/// B: `grpc_service_name_in_path`
///
/// Connects via `GrpcLayer` with `service_name = "TestService"` and asserts
/// that the h2 request `:path` is `/TestService/Tun`.
///
/// upstream: transport/gun/gun.go — path is always `/{svcName}/Tun`.
#[tokio::test]
async fn grpc_service_name_in_path() {
    let (addr, info_rx) = spawn_grpc_server().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig {
        service_name: "TestService".into(),
        ..Default::default()
    });
    let _stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    let info = tokio::time::timeout(Duration::from_secs(5), info_rx)
        .await
        .expect("timeout waiting for grpc conn info")
        .expect("server dropped sender");

    assert_eq!(
        info.path, "/TestService/Tun",
        ":path must be /<service_name>/Tun"
    );
}

// ─── C: content-type header ───────────────────────────────────────────────────

/// C: `grpc_content_type_header`
///
/// Connects via `GrpcLayer` and asserts that the HTTP/2 request carries
/// `content-type: application/grpc`.
///
/// upstream: transport/gun/gun.go — sends `application/grpc`, not
/// `application/grpc+proto` (no codec suffix).
#[tokio::test]
async fn grpc_content_type_header() {
    let (addr, info_rx) = spawn_grpc_server().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig::default());
    let _stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    let info = tokio::time::timeout(Duration::from_secs(5), info_rx)
        .await
        .expect("timeout waiting for grpc conn info")
        .expect("server dropped sender");

    assert_eq!(
        info.content_type.as_deref(),
        Some("application/grpc"),
        "content-type must be application/grpc (no codec suffix)"
    );
}

// ─── D: Round-trip 4 MiB ─────────────────────────────────────────────────────

/// D: `grpc_round_trip`
///
/// Streams 4 MiB through a real h2 echo server via `GrpcLayer`.  The write
/// and read halves run concurrently (via `tokio::io::split`) to avoid
/// deadlocking on h2 flow-control.  Asserts the received bytes equal the
/// sent bytes.
#[tokio::test]
async fn grpc_round_trip() {
    const PAYLOAD_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

    let (addr, _info_rx) = spawn_grpc_server().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig::default());
    let gun_stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    // Split the GunStream so write and read can proceed concurrently.
    let (mut read_half, mut write_half) = tokio::io::split(gun_stream);

    // Build the send buffer: repeating 0x00..=0xFF pattern.
    let send_buf: Vec<u8> = (0u8..=255).cycle().take(PAYLOAD_SIZE).collect();
    let send_clone = send_buf.clone();

    // Write task: send all bytes, then signal EOF.
    let write_task = tokio::spawn(async move {
        write_half
            .write_all(&send_clone)
            .await
            .expect("write_all 4 MiB");
        write_half.shutdown().await.expect("shutdown");
    });

    // Read until EOF (server echoes back the gun-framed data, GunStream decodes).
    let mut recv_buf = Vec::with_capacity(PAYLOAD_SIZE);
    read_half
        .read_to_end(&mut recv_buf)
        .await
        .expect("read_to_end 4 MiB");

    write_task.await.expect("write task");

    assert_eq!(
        recv_buf.len(),
        PAYLOAD_SIZE,
        "received byte count must match sent byte count"
    );
    assert_eq!(recv_buf, send_buf, "round-trip bytes must be identical");
}

// ─── E: Response HEADERS withheld until the first client hunk ─────────────────

/// E: `grpc_round_trip_with_deferred_response`
///
/// Regression test for issue #377. xray's `Tun` handler reads the client's
/// first hunk before writing anything, and grpc-go only flushes response
/// headers on the first `SendMsg`, so a client that awaits the response inside
/// `connect()` deadlocks: the server waits for data that the client will not
/// send until the response arrives. `GrpcLayer::connect` must therefore return
/// as soon as the request HEADERS are queued and resolve the response lazily on
/// the first read.
#[tokio::test]
async fn grpc_round_trip_with_deferred_response() {
    let (addr, _info_rx) = spawn_grpc_server_deferred_response().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig::default());
    let mut stream = tokio::time::timeout(Duration::from_secs(5), layer.connect(Box::new(tcp)))
        .await
        .expect("connect must not block on the server's response")
        .expect("grpc connect");

    stream.write_all(b"ping").await.expect("write");
    stream.flush().await.expect("flush");

    let mut got = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut got))
        .await
        .expect("echo must arrive once the server answers")
        .expect("read_exact");
    assert_eq!(
        &got, b"ping",
        "round-trip bytes must survive the deferred response"
    );
}

// ─── F/G: Changed-buffer guard after Pending (issue #433) ─────────────────────

/// Spawn an in-process h2 server over one end of a duplex pipe that accepts a
/// single request, sends a 200 response, and then withholds flow-control
/// capacity: it never releases the request body's receive window until it gets
/// a message on `release_rx` (if ever), after which it drains and releases
/// everything. Keeping the window shut forces the client's `poll_write` into
/// the `Pending` + stashed-frame state that issue #433 is about.
///
/// The collected request-body bytes are sent through the returned receiver
/// once the client half-closes with a clean end-of-stream. Reading the body
/// to completion inside the task (instead of `std::mem::forget`-ing it) both
/// keeps the h2 stream alive while the client has a write outstanding and
/// lets tests H/I assert exactly which frames reached the wire.
fn spawn_capacity_hoarding_server(
    server_io: tokio::io::DuplexStream,
    release_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::sync::oneshot::Receiver<Vec<u8>> {
    let (body_tx, body_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok(mut conn) = h2::server::handshake(server_io).await else {
            return;
        };
        let Some(Ok((request, mut respond))) = conn.accept().await else {
            return;
        };
        // Drive connection-level frames in the background.
        tokio::spawn(async move { while conn.accept().await.is_some() {} });

        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("resp");
        let _ = respond.send_response(response, false);

        // Consume DATA frames but do NOT release capacity — the client's
        // send window (65535 initial) empties and stays empty.
        let mut body = request.into_body();
        let mut release_rx = release_rx;
        let mut received = Vec::new();
        loop {
            tokio::select! {
                chunk = body.data() => match chunk {
                    Some(Ok(chunk)) => received.extend_from_slice(&chunk),
                    Some(Err(_)) => return, // stream error — client went away
                    None => {
                        let _ = body_tx.send(received);
                        return;
                    }
                },
                _ = &mut release_rx => break,
            }
        }
        // Reopen the window: release everything held so far, then keep
        // draining + releasing so the retried write completes; the body stays
        // alive in this loop until end-of-stream or a reset.
        let _ = body.flow_control().release_capacity(received.len());
        loop {
            match body.data().await {
                Some(Ok(chunk)) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    received.extend_from_slice(&chunk);
                }
                Some(Err(_)) => return,
                None => {
                    let _ = body_tx.send(received);
                    return;
                }
            }
        }
    });
    body_rx
}

/// Payload that fills the initial h2 send window: 65535 bytes of 0xAA encode
/// to a 65544-byte gun frame — larger than the 65535-byte window — so after
/// writing it the window is fully exhausted.  Tests H/I rebuild the expected
/// wire bytes from these constants.
const WINDOW_FILL_BYTE: u8 = 0xAA;
const WINDOW_FILL_LEN: usize = 65535;

/// Exhaust the client's h2 send window so the next write stashes its frame and
/// returns `Pending`, then interrupt that write, leaving `pending_write` set.
/// Returns the connected stream with a stashed frame for `pending_payload`.
async fn gun_stream_with_stashed_frame(
    client_io: tokio::io::DuplexStream,
    pending_payload: &[u8],
) -> Box<dyn meow_transport::Stream> {
    let layer = GrpcLayer::new(GrpcConfig::default());
    let mut stream = layer
        .connect(Box::new(client_io))
        .await
        .expect("grpc connect");

    // Fully exhaust the send window (the server never releases capacity on
    // its own).
    let fill = vec![WINDOW_FILL_BYTE; WINDOW_FILL_LEN];
    tokio::time::timeout(Duration::from_secs(5), stream.write(&fill))
        .await
        .expect("window-filling write must complete")
        .expect("window-filling write");

    // This write cannot get capacity: poll_write encodes + stashes the frame
    // and returns Pending. The timeout drops the write future at that await
    // point (cancellation), leaving pending_write set — the #433 setup.
    let interrupted =
        tokio::time::timeout(Duration::from_millis(200), stream.write(pending_payload)).await;
    assert!(
        interrupted.is_err(),
        "write must be blocked on flow control (send window exhausted)"
    );

    stream
}

/// F: `grpc_poll_write_rejects_changed_buffer_after_pending`
///
/// Regression test for issue #433. After `poll_write` stashes an encoded gun
/// frame and returns `Pending` (h2 send window exhausted), re-polling with a
/// *different* buffer must fail with `InvalidInput` — before the fix the
/// stashed stale frame was silently sent while `Ok(new_buf.len())` was
/// reported, corrupting the stream with no error. Mirrors the `H2Stream`
/// guard test `poll_write_rejects_changed_buffer_after_pending` (h2mux).
#[tokio::test]
async fn grpc_poll_write_rejects_changed_buffer_after_pending() {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (_release_tx, release_rx) = tokio::sync::oneshot::channel();
    let _body_rx = spawn_capacity_hoarding_server(server_io, release_rx);

    let pending = vec![0xBB; 100];
    let mut stream = gun_stream_with_stashed_frame(client_io, &pending).await;

    // Re-poll with a different buffer — the guard must reject it immediately.
    // Without the guard this write just parks on poll_capacity forever (the
    // window never reopens), so a hang here is itself a regression signal.
    let different = vec![0xCC; 50];
    let result = tokio::time::timeout(Duration::from_secs(5), stream.write(&different))
        .await
        .expect("changed-buffer write hung — the changed-buffer guard is missing");
    let err = result.expect_err("changed buffer after Pending must be rejected");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "expected InvalidInput, got: {err}"
    );
}

/// G: `grpc_poll_write_same_buffer_retry_succeeds_after_pending`
///
/// Companion to F: the guard must not false-positive. Retrying the write with
/// the *same* buffer after `Pending` is the contract-conforming path and must
/// still complete once the server releases flow-control capacity, reporting
/// the full buffer length.
#[tokio::test]
async fn grpc_poll_write_same_buffer_retry_succeeds_after_pending() {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let _body_rx = spawn_capacity_hoarding_server(server_io, release_rx);

    let pending = vec![0xBB; 100];
    let mut stream = gun_stream_with_stashed_frame(client_io, &pending).await;

    // Reopen the window, then retry with the SAME buffer: the stashed frame
    // is sent and the write reports the full payload length.
    release_tx.send(()).expect("server task alive");
    let n = tokio::time::timeout(Duration::from_secs(5), stream.write(&pending))
        .await
        .expect("same-buffer retry must complete once capacity is released")
        .expect("same-buffer retry must succeed");
    assert_eq!(
        n,
        pending.len(),
        "retry must report the full payload length"
    );
}

// ─── H/I: Shutdown with a stashed frame (PR #440 review follow-up) ────────────

/// H: `grpc_shutdown_flushes_stashed_frame_before_eos`
///
/// Follow-up to the PR #440 review: `poll_shutdown` used to send an empty
/// DATA+EOS while an encoded frame from a cancelled write still sat in
/// `pending_write`, silently truncating the stream. Shutdown must flush the
/// stashed frame together with the EOS instead of discarding it.
#[tokio::test]
async fn grpc_shutdown_flushes_stashed_frame_before_eos() {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let body_rx = spawn_capacity_hoarding_server(server_io, release_rx);

    let pending = vec![0xBB; 100];
    let mut stream = gun_stream_with_stashed_frame(client_io, &pending).await;

    // Shutdown with the frame still stashed (the parked write was cancelled,
    // never retried). h2 queues the flushed frame beyond the closed window,
    // so this completes even before the server releases capacity.
    tokio::time::timeout(Duration::from_secs(5), stream.shutdown())
        .await
        .expect("shutdown must not block on flow control")
        .expect("shutdown");

    // Reopen the window so the queued frames can reach the server.
    release_tx.send(()).expect("server task alive");

    let received = tokio::time::timeout(Duration::from_secs(5), body_rx)
        .await
        .expect("server must observe end-of-stream")
        .expect("server sent collected body");

    let mut expected = encode_gun_frame(&vec![WINDOW_FILL_BYTE; WINDOW_FILL_LEN]);
    expected.extend_from_slice(&encode_gun_frame(&pending));
    assert_eq!(
        received, expected,
        "the stashed frame must be delivered before EOS"
    );
}

/// I: `grpc_shutdown_after_rejected_buffer_does_not_resurrect_frame`
///
/// Companion to H: only a frame stashed by a *cancelled* write gets flushed.
/// A frame cleared by the changed-buffer `InvalidInput` rejection (test F)
/// must not reappear on the wire when the stream is later shut down.
#[tokio::test]
async fn grpc_shutdown_after_rejected_buffer_does_not_resurrect_frame() {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let body_rx = spawn_capacity_hoarding_server(server_io, release_rx);

    let pending = vec![0xBB; 100];
    let mut stream = gun_stream_with_stashed_frame(client_io, &pending).await;

    // Trip the changed-buffer guard: the stashed frame is cleared and the
    // write fails with InvalidInput.
    let different = vec![0xCC; 50];
    let err = tokio::time::timeout(Duration::from_secs(5), stream.write(&different))
        .await
        .expect("changed-buffer write must fail fast")
        .expect_err("changed buffer after Pending must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    tokio::time::timeout(Duration::from_secs(5), stream.shutdown())
        .await
        .expect("shutdown must not block on flow control")
        .expect("shutdown");
    release_tx.send(()).expect("server task alive");

    let received = tokio::time::timeout(Duration::from_secs(5), body_rx)
        .await
        .expect("server must observe end-of-stream")
        .expect("server sent collected body");
    assert_eq!(
        received,
        encode_gun_frame(&vec![WINDOW_FILL_BYTE; WINDOW_FILL_LEN]),
        "a frame cleared by the changed-buffer rejection must not be resurrected at shutdown"
    );
}

/// J: `grpc_empty_write_is_noop_even_with_stashed_frame`
///
/// Follow-up to the PR #440 review: `poll_write` lacked `H2Stream`'s
/// empty-buffer early return, so `write(&[])` while a frame was stashed was
/// misread as a changed-buffer retry and failed with `InvalidInput` (and an
/// empty write on an idle stream sent a useless zero-payload gun frame). An
/// empty write must report `Ok(0)`, leave the stash intact, and send nothing.
#[tokio::test]
async fn grpc_empty_write_is_noop_even_with_stashed_frame() {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let body_rx = spawn_capacity_hoarding_server(server_io, release_rx);

    let pending = vec![0xBB; 100];
    let mut stream = gun_stream_with_stashed_frame(client_io, &pending).await;

    // An empty write is a distinct logical write, not a retry: Ok(0).
    let n = tokio::time::timeout(Duration::from_secs(5), stream.write(&[]))
        .await
        .expect("empty write must not block")
        .expect("empty write must succeed");
    assert_eq!(n, 0, "empty write must report Ok(0)");

    // The stash must survive it: the contract-conforming same-buffer retry
    // still completes once capacity is released, and exactly the fill frame
    // plus the stashed frame reach the wire (no zero-payload frame).
    release_tx.send(()).expect("server task alive");
    let n = tokio::time::timeout(Duration::from_secs(5), stream.write(&pending))
        .await
        .expect("same-buffer retry must complete once capacity is released")
        .expect("same-buffer retry must succeed");
    assert_eq!(n, pending.len());

    tokio::time::timeout(Duration::from_secs(5), stream.shutdown())
        .await
        .expect("shutdown must not block")
        .expect("shutdown");
    let received = tokio::time::timeout(Duration::from_secs(5), body_rx)
        .await
        .expect("server must observe end-of-stream")
        .expect("server sent collected body");
    let mut expected = encode_gun_frame(&vec![WINDOW_FILL_BYTE; WINDOW_FILL_LEN]);
    expected.extend_from_slice(&encode_gun_frame(&pending));
    assert_eq!(
        received, expected,
        "an empty write must put nothing on the wire"
    );
}

// ─── K: receive windows ───────────────────────────────────────────────────────

/// K: the client must advertise receive windows well above h2's 65 535-byte
/// default (issue #495 item 12).  The server pushes 1 MiB of gun frames while
/// the client does not read a single byte; with the default windows it would
/// park after 64 KiB waiting for a WINDOW_UPDATE that only a read can
/// produce, and the timeout below would fire.
#[tokio::test]
async fn grpc_receive_window_absorbs_1mib_before_first_read() {
    const PAYLOAD_SIZE: usize = 1024 * 1024;
    const HUNK: usize = 16 * 1024;

    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let payload: Vec<u8> = (0u8..=255).cycle().take(PAYLOAD_SIZE).collect();
    let wire: Vec<u8> = payload.chunks(HUNK).flat_map(encode_gun_frame).collect();
    let wire_len = wire.len();
    let pushed = spawn_h2_push_server(server_io, wire);

    let layer = GrpcLayer::new(GrpcConfig::default());
    let mut stream = layer
        .connect(Box::new(client_io))
        .await
        .expect("grpc connect");

    // Deliberately no read until the server reports the whole push done.
    let pushed = tokio::time::timeout(Duration::from_secs(5), pushed)
        .await
        .expect("server must push 1 MiB into the client's receive window without a read")
        .expect("push server task");
    assert_eq!(pushed, wire_len);

    let mut recv_buf = Vec::with_capacity(PAYLOAD_SIZE);
    stream
        .read_to_end(&mut recv_buf)
        .await
        .expect("read_to_end 1 MiB");
    assert_eq!(recv_buf, payload, "pushed bytes must decode intact");
}
