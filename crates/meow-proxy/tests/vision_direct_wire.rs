//! Controlled-wire evidence for Vision DIRECT over a real BoringSSL transport.
//!
//! The in-memory wire preserves explicitly released write batches as read
//! batches.  That gives the tests byte-level control over whether the final
//! outer-TLS ciphertext and the first post-DIRECT raw bytes become visible in
//! one receive batch — the edge a plain socket or duplex cannot reproduce
//! deterministically.

#![cfg(feature = "vless-vision")]

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use meow_proxy::vless_inbound::{VisionServerConn, VisionServerMode};
use meow_transport::tls::server::{TlsServer, TlsServerConfig};
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::{Stream, Transport};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(5);
const UUID: [u8; 16] = [0x71; 16];
const COMMAND_CONTINUE: u8 = 0x00;
const COMMAND_DIRECT: u8 = 0x02;

#[derive(Clone, Copy)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

struct PendingBatch {
    bytes: Vec<u8>,
    pos: usize,
}

struct DirectionState {
    manual: bool,
    open: Vec<u8>,
    queue: VecDeque<PendingBatch>,
    emitted: Vec<Vec<u8>>,
    read_waker: Option<Waker>,
    shutdown: bool,
}

impl DirectionState {
    fn new() -> Self {
        Self {
            manual: false,
            open: Vec::new(),
            queue: VecDeque::new(),
            emitted: Vec::new(),
            read_waker: None,
            shutdown: false,
        }
    }
}

struct WireShared {
    client_to_server: Mutex<DirectionState>,
    server_to_client: Mutex<DirectionState>,
}

fn direction_state(shared: &WireShared, direction: Direction) -> &Mutex<DirectionState> {
    match direction {
        Direction::ClientToServer => &shared.client_to_server,
        Direction::ServerToClient => &shared.server_to_client,
    }
}

fn seal_open(state: &mut DirectionState) -> Option<Waker> {
    if state.open.is_empty() {
        return None;
    }
    let bytes = std::mem::take(&mut state.open);
    state.emitted.push(bytes.clone());
    state.queue.push_back(PendingBatch { bytes, pos: 0 });
    state.read_waker.take()
}

#[derive(Clone)]
struct WireControl {
    shared: Arc<WireShared>,
}

impl WireControl {
    fn set_manual(&self) {
        self.shared
            .client_to_server
            .lock()
            .expect("controlled wire mutex poisoned")
            .manual = true;
        self.shared
            .server_to_client
            .lock()
            .expect("controlled wire mutex poisoned")
            .manual = true;
    }

    /// Deliver the in-flight write bytes to the peer as one read batch.
    /// Flush deliberately does not do this: TCP flush is not a segment
    /// boundary, while this control models the network scheduler exactly.
    fn release(&self, direction: Direction) -> bool {
        let (sealed, waker) = {
            let mut state = direction_state(&self.shared, direction)
                .lock()
                .expect("controlled wire mutex poisoned");
            let sealed = !state.open.is_empty();
            let waker = seal_open(&mut state);
            (sealed, waker)
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        sealed
    }

    fn batch_count(&self, direction: Direction) -> usize {
        direction_state(&self.shared, direction)
            .lock()
            .expect("controlled wire mutex poisoned")
            .emitted
            .len()
    }

    fn batches_since(&self, direction: Direction, start: usize) -> Vec<Vec<u8>> {
        direction_state(&self.shared, direction)
            .lock()
            .expect("controlled wire mutex poisoned")
            .emitted[start..]
            .to_vec()
    }
}

struct ControlledIo {
    shared: Arc<WireShared>,
    read_direction: Direction,
    write_direction: Direction,
}

fn controlled_wire() -> (ControlledIo, ControlledIo, WireControl) {
    let shared = Arc::new(WireShared {
        client_to_server: Mutex::new(DirectionState::new()),
        server_to_client: Mutex::new(DirectionState::new()),
    });
    (
        ControlledIo {
            shared: Arc::clone(&shared),
            read_direction: Direction::ServerToClient,
            write_direction: Direction::ClientToServer,
        },
        ControlledIo {
            shared: Arc::clone(&shared),
            read_direction: Direction::ClientToServer,
            write_direction: Direction::ServerToClient,
        },
        WireControl { shared },
    )
}

impl AsyncRead for ControlledIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut state = direction_state(&this.shared, this.read_direction)
            .lock()
            .expect("controlled wire mutex poisoned");
        let Some(batch) = state.queue.front_mut() else {
            if state.shutdown {
                return Poll::Ready(Ok(()));
            }
            state.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        };

        let available = batch.bytes.len() - batch.pos;
        let n = available.min(buf.remaining());
        buf.put_slice(&batch.bytes[batch.pos..batch.pos + n]);
        batch.pos += n;
        if batch.pos == batch.bytes.len() {
            state.queue.pop_front();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ControlledIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let waker = {
            let mut state = direction_state(&this.shared, this.write_direction)
                .lock()
                .expect("controlled wire mutex poisoned");
            if state.shutdown {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "controlled wire write side is shut down",
                )));
            }
            state.open.extend_from_slice(buf);
            (!state.manual).then(|| seal_open(&mut state)).flatten()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Accepted bytes are already in flight in the wire model; like a
        // TCP socket flush, this does not schedule or segment their delivery.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let waker = {
            let mut state = direction_state(&this.shared, this.write_direction)
                .lock()
                .expect("controlled wire mutex poisoned");
            let mut waker = seal_open(&mut state);
            state.shutdown = true;
            if waker.is_none() {
                waker = state.read_waker.take();
            }
            waker
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

struct UplinkEncoder {
    sent_uuid: bool,
}

impl UplinkEncoder {
    fn new() -> Self {
        Self { sent_uuid: false }
    }

    fn frame(&mut self, command: u8, content: &[u8], padding_len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.sent_uuid {
            out.extend_from_slice(&UUID);
            self.sent_uuid = true;
        }
        out.push(command);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding_len as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding_len, 0);
        out
    }
}

struct DownlinkFrame {
    command: u8,
    content: Vec<u8>,
}

struct DownlinkDecoder {
    response_pending: bool,
    need_uuid: bool,
}

impl DownlinkDecoder {
    fn new() -> Self {
        Self {
            response_pending: true,
            need_uuid: true,
        }
    }

    async fn next_frame(&mut self, client: &mut Box<dyn Stream>) -> DownlinkFrame {
        if self.response_pending {
            let mut response = [0u8; 2];
            read_exact_timeout(&mut **client, &mut response).await;
            assert_eq!(response, [0, 0], "VLESS response header");
            self.response_pending = false;
        }

        let header_len = if self.need_uuid { 21 } else { 5 };
        let mut header = vec![0u8; header_len];
        read_exact_timeout(&mut **client, &mut header).await;
        let offset = if self.need_uuid {
            assert_eq!(&header[..16], &UUID, "server frame UUID");
            self.need_uuid = false;
            16
        } else {
            0
        };
        let command = header[offset];
        let content_len = u16::from_be_bytes([header[offset + 1], header[offset + 2]]) as usize;
        let padding_len = u16::from_be_bytes([header[offset + 3], header[offset + 4]]) as usize;

        let mut content = vec![0u8; content_len];
        if content_len != 0 {
            read_exact_timeout(&mut **client, &mut content).await;
        }
        let mut padding = vec![0u8; padding_len];
        if padding_len != 0 {
            read_exact_timeout(&mut **client, &mut padding).await;
        }
        DownlinkFrame { command, content }
    }
}

struct VisionWireFixture {
    conn: VisionServerConn,
    client: Box<dyn Stream>,
    control: WireControl,
    uplink: UplinkEncoder,
    downlink: DownlinkDecoder,
}

impl VisionWireFixture {
    async fn new() -> Self {
        let (client_io, server_io, control) = controlled_wire();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = TlsServer::new(&TlsServerConfig {
            certificate_chain_pem: generated.cert.pem().into_bytes(),
            private_key_pem: generated.key_pair.serialize_pem().into_bytes(),
            alpn: Vec::new(),
        })
        .expect("TLS server acceptor");
        let client_layer = TlsLayer::new(&TlsConfig {
            skip_cert_verify: true,
            ..TlsConfig::new("localhost")
        })
        .expect("TLS client layer");

        let (client_result, server_result) = tokio::join!(
            client_layer.connect(Box::new(client_io)),
            server.accept(Box::new(server_io)),
        );
        let mut client = client_result.expect("client TLS handshake");
        let mut server_tls = server_result.expect("server TLS handshake");
        assert!(
            meow_transport::supports_raw_passthrough(&mut *client),
            "client outer transport must be raw-capable BoringSSL"
        );
        assert!(
            meow_transport::supports_raw_passthrough(&mut *server_tls),
            "server outer transport must be raw-capable BoringSSL"
        );
        control.set_manual();

        Self {
            conn: VisionServerConn::new(server_tls, UUID, VisionServerMode::Tcp),
            client,
            control,
            uplink: UplinkEncoder::new(),
            downlink: DownlinkDecoder::new(),
        }
    }
}

async fn read_exact_timeout<S>(stream: &mut S, buf: &mut [u8])
where
    S: ?Sized + AsyncRead + Unpin,
{
    timeout(T, stream.read_exact(buf))
        .await
        .expect("read timed out")
        .expect("read failed");
}

fn handshake_record(message_type: u8, body: &[u8]) -> Vec<u8> {
    let handshake_len = body.len() + 4;
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&(handshake_len as u16).to_be_bytes());
    record.push(message_type);
    record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    record.extend_from_slice(body);
    record
}

fn client_hello_record() -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x42; 32]);
    body.push(0); // session id
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0); // null compression
    body.extend_from_slice(&0u16.to_be_bytes());
    handshake_record(0x01, &body)
}

fn server_hello_record() -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x24; 32]);
    body.push(0); // session id
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(0); // null compression
    body.extend_from_slice(&6u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    handshake_record(0x02, &body)
}

fn app_record(payload: &[u8]) -> Vec<u8> {
    let mut record = vec![0x17, 0x03, 0x03];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn assert_tls_records_then_raw(batch: &[u8], raw_suffix: &[u8]) {
    assert!(
        batch.len() > raw_suffix.len() && batch.ends_with(raw_suffix),
        "batch must be outer-TLS ciphertext immediately followed by the raw suffix"
    );
    let tls_bytes = &batch[..batch.len() - raw_suffix.len()];
    let mut pos = 0usize;
    let mut records = 0usize;
    while pos < tls_bytes.len() {
        assert!(
            tls_bytes.len() - pos >= 5,
            "truncated outer TLS record header at {pos}"
        );
        assert_eq!(
            tls_bytes[pos], 0x17,
            "post-handshake outer record must be application data"
        );
        assert_eq!(tls_bytes[pos + 1], 0x03);
        assert_eq!(tls_bytes[pos + 2], 0x03);
        let record_len = u16::from_be_bytes([tls_bytes[pos + 3], tls_bytes[pos + 4]]) as usize;
        let end = pos + 5 + record_len;
        assert!(
            end <= tls_bytes.len(),
            "outer TLS record overruns the ciphertext prefix"
        );
        pos = end;
        records += 1;
    }
    assert!(records > 0, "no outer TLS record before the raw suffix");
}

async fn prime_tls13_evidence(fixture: &mut VisionWireFixture) {
    let client_hello = client_hello_record();
    let frame = fixture.uplink.frame(COMMAND_CONTINUE, &client_hello, 0);
    fixture.client.write_all(&frame).await.unwrap();
    fixture.client.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ClientToServer));

    let mut got_client_hello = vec![0u8; client_hello.len()];
    read_exact_timeout(&mut fixture.conn, &mut got_client_hello).await;
    assert_eq!(got_client_hello, client_hello);

    let server_hello = server_hello_record();
    fixture.conn.write_all(&server_hello).await.unwrap();
    fixture.conn.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ServerToClient));
    let frame = fixture.downlink.next_frame(&mut fixture.client).await;
    assert_eq!(frame.command, COMMAND_CONTINUE);
    assert_eq!(frame.content, server_hello);
}

#[tokio::test]
async fn uplink_direct_tail_in_one_receive_batch_stays_aligned() {
    let mut fixture = VisionWireFixture::new().await;
    prime_tls13_evidence(&mut fixture).await;

    let direct_content = app_record(b"uplink framed application data");
    let raw_tail = b"first raw uplink bytes\x00\x01\x02";
    let direct_frame = fixture.uplink.frame(COMMAND_DIRECT, &direct_content, 11);

    let before = fixture.control.batch_count(Direction::ClientToServer);
    fixture.client.write_all(&direct_frame).await.unwrap();
    fixture.client.flush().await.unwrap();
    assert!(meow_transport::enable_raw_write_passthrough(
        &mut *fixture.client
    ));
    fixture.client.write_all(raw_tail).await.unwrap();
    fixture.client.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ClientToServer));

    let batches = fixture
        .control
        .batches_since(Direction::ClientToServer, before);
    assert_eq!(
        batches.len(),
        1,
        "final TLS ciphertext and first raw bytes must form one receive batch"
    );
    assert_tls_records_then_raw(&batches[0], raw_tail);

    let mut framed = vec![0u8; direct_content.len()];
    read_exact_timeout(&mut fixture.conn, &mut framed).await;
    assert_eq!(framed, direct_content);
    let mut raw = vec![0u8; raw_tail.len()];
    read_exact_timeout(&mut fixture.conn, &mut raw).await;
    assert_eq!(raw, raw_tail);
    assert!(fixture.conn.read_switched_to_raw());
    assert!(!fixture.conn.write_switched_to_raw());

    // The uplink is already raw, but with no complete downlink application
    // record the downlink must still be a Vision frame inside outer TLS.
    let framed_downlink = [0x17, 0x03];
    fixture.conn.write_all(&framed_downlink).await.unwrap();
    fixture.conn.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ServerToClient));
    let frame = fixture.downlink.next_frame(&mut fixture.client).await;
    assert_eq!(frame.command, COMMAND_CONTINUE);
    assert_eq!(frame.content, framed_downlink);
    assert!(!fixture.conn.write_switched_to_raw());
}

#[tokio::test]
async fn downlink_direct_can_precede_uplink_direct_independently() {
    let mut fixture = VisionWireFixture::new().await;
    prime_tls13_evidence(&mut fixture).await;

    let app = app_record(b"downlink application data");
    let raw_tail = b"raw downlink while uplink remains framed";
    let before = fixture.control.batch_count(Direction::ServerToClient);
    fixture.conn.write_all(&app).await.unwrap();
    fixture.conn.flush().await.unwrap();
    assert!(fixture.conn.write_switched_to_raw());
    fixture.conn.write_all(raw_tail).await.unwrap();
    fixture.conn.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ServerToClient));

    let batches = fixture
        .control
        .batches_since(Direction::ServerToClient, before);
    assert_eq!(batches.len(), 1);
    assert_tls_records_then_raw(&batches[0], raw_tail);

    let frame = fixture.downlink.next_frame(&mut fixture.client).await;
    assert_eq!(frame.command, COMMAND_DIRECT);
    assert_eq!(frame.content, app);
    assert!(meow_transport::enable_raw_read_passthrough(
        &mut *fixture.client
    ));
    let mut raw = vec![0u8; raw_tail.len()];
    read_exact_timeout(&mut *fixture.client, &mut raw).await;
    assert_eq!(raw, raw_tail);
    assert!(!fixture.conn.read_switched_to_raw());

    // The opposite direction is untouched: this uplink payload still has to
    // arrive as a Vision frame inside outer TLS, not as raw bytes.
    let uplink_payload = b"uplink still framed";
    let frame = fixture.uplink.frame(COMMAND_CONTINUE, uplink_payload, 7);
    fixture.client.write_all(&frame).await.unwrap();
    fixture.client.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ClientToServer));
    let mut got = vec![0u8; uplink_payload.len()];
    read_exact_timeout(&mut fixture.conn, &mut got).await;
    assert_eq!(got, uplink_payload);
    assert!(!fixture.conn.read_switched_to_raw());
}

async fn enter_bidirectional_direct(fixture: &mut VisionWireFixture) {
    prime_tls13_evidence(fixture).await;

    let downlink_app = app_record(b"downlink direct setup");
    fixture.conn.write_all(&downlink_app).await.unwrap();
    fixture.conn.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ServerToClient));
    let frame = fixture.downlink.next_frame(&mut fixture.client).await;
    assert_eq!(frame.command, COMMAND_DIRECT);
    assert_eq!(frame.content, downlink_app);
    assert!(meow_transport::enable_raw_read_passthrough(
        &mut *fixture.client
    ));
    assert!(fixture.conn.write_switched_to_raw());

    let uplink_app = app_record(b"uplink direct setup");
    let frame = fixture.uplink.frame(COMMAND_DIRECT, &uplink_app, 0);
    fixture.client.write_all(&frame).await.unwrap();
    fixture.client.flush().await.unwrap();
    assert!(meow_transport::enable_raw_write_passthrough(
        &mut *fixture.client
    ));
    let first_raw = [0x5a];
    fixture.client.write_all(&first_raw).await.unwrap();
    fixture.client.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ClientToServer));

    let mut framed = vec![0u8; uplink_app.len()];
    read_exact_timeout(&mut fixture.conn, &mut framed).await;
    assert_eq!(framed, uplink_app);
    let mut raw = [0u8; 1];
    read_exact_timeout(&mut fixture.conn, &mut raw).await;
    assert_eq!(raw, first_raw);
    assert!(fixture.conn.read_switched_to_raw());
}

#[tokio::test]
async fn raw_write_half_close_is_eof_and_the_read_direction_continues() {
    let mut fixture = VisionWireFixture::new().await;
    enter_bidirectional_direct(&mut fixture).await;

    let final_uplink = b"final raw uplink before half-close";
    fixture.client.write_all(final_uplink).await.unwrap();
    fixture.client.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ClientToServer));
    let mut got = vec![0u8; final_uplink.len()];
    read_exact_timeout(&mut fixture.conn, &mut got).await;
    assert_eq!(got, final_uplink);

    fixture.client.shutdown().await.unwrap();
    let mut eof = [0u8; 8];
    // In raw mode close must be the transport EOF itself.  A TLS close_notify
    // would be ciphertext-shaped bytes here and this read would return them
    // instead of zero.
    let n = timeout(T, fixture.conn.read(&mut eof))
        .await
        .expect("EOF read timed out")
        .expect("EOF read failed");
    assert_eq!(n, 0);

    let downlink_after_close = b"server raw bytes after client write close";
    fixture.conn.write_all(downlink_after_close).await.unwrap();
    fixture.conn.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ServerToClient));
    let mut got = vec![0u8; downlink_after_close.len()];
    read_exact_timeout(&mut *fixture.client, &mut got).await;
    assert_eq!(got, downlink_after_close);
}

#[tokio::test]
async fn server_raw_write_half_close_is_eof_and_uplink_continues() {
    let mut fixture = VisionWireFixture::new().await;
    enter_bidirectional_direct(&mut fixture).await;

    fixture.conn.shutdown().await.unwrap();
    let mut eof = [0u8; 8];
    let n = timeout(T, fixture.client.read(&mut eof))
        .await
        .expect("EOF read timed out")
        .expect("EOF read failed");
    assert_eq!(n, 0, "raw shutdown must not emit a TLS close_notify");

    let uplink_after_close = b"client raw bytes after server write close";
    fixture.client.write_all(uplink_after_close).await.unwrap();
    fixture.client.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ClientToServer));
    let mut got = vec![0u8; uplink_after_close.len()];
    read_exact_timeout(&mut fixture.conn, &mut got).await;
    assert_eq!(got, uplink_after_close);
}

#[tokio::test]
async fn fragmented_inner_app_record_earns_direct_on_real_tls_stream() {
    let mut fixture = VisionWireFixture::new().await;
    prime_tls13_evidence(&mut fixture).await;

    let app = app_record(b"fragmented inner application record");
    let split_a = 2;
    let split_b = 7;
    assert!(split_b < app.len());
    let pieces = [&app[..split_a], &app[split_a..split_b], &app[split_b..]];

    for piece in &pieces[..2] {
        fixture.conn.write_all(piece).await.unwrap();
        fixture.conn.flush().await.unwrap();
        assert!(fixture.control.release(Direction::ServerToClient));
        let frame = fixture.downlink.next_frame(&mut fixture.client).await;
        assert_eq!(frame.command, COMMAND_CONTINUE);
        assert_eq!(frame.content, *piece);
    }

    let raw_tail = b"raw bytes after fragmented DIRECT";
    let before = fixture.control.batch_count(Direction::ServerToClient);
    fixture.conn.write_all(pieces[2]).await.unwrap();
    fixture.conn.flush().await.unwrap();
    assert!(
        fixture.conn.write_switched_to_raw(),
        "completion of the cross-write inner TLS record must trigger DIRECT"
    );
    fixture.conn.write_all(raw_tail).await.unwrap();
    fixture.conn.flush().await.unwrap();
    assert!(fixture.control.release(Direction::ServerToClient));

    let batches = fixture
        .control
        .batches_since(Direction::ServerToClient, before);
    assert_eq!(batches.len(), 1);
    assert_tls_records_then_raw(&batches[0], raw_tail);

    let frame = fixture.downlink.next_frame(&mut fixture.client).await;
    assert_eq!(frame.command, COMMAND_DIRECT);
    assert_eq!(frame.content, pieces[2]);
    assert!(meow_transport::enable_raw_read_passthrough(
        &mut *fixture.client
    ));
    let mut raw = vec![0u8; raw_tail.len()];
    read_exact_timeout(&mut *fixture.client, &mut raw).await;
    assert_eq!(raw, raw_tail);
}
