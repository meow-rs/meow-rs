#![cfg(feature = "snell")]
//! Integration tests for the Snell adapter.
//!
//! Uses embedded mock Snell servers: the AEAD codecs are symmetric (each
//! direction sends its own salt and derives its own key), so wrapping an
//! accepted `TcpStream` speaks the server side. No external binaries required.

use meow_common::{MeowError, Metadata, Network, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::snell::protocol::{
    write_header, AppError, Snell, COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_UDP,
    COMMAND_UDP_FORWARD, HEADER_VERSION, RESPONSE_ERROR, RESPONSE_TUNNEL,
};
use meow_proxy::snell::v3::{is_zero_chunk as is_v3_zero_chunk, V3Conn};
use meow_proxy::snell::v4::{is_zero_chunk as is_v4_zero_chunk, V4Conn};
use meow_proxy::snell::{SnellAdapter, SnellObfs, SnellVersion};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const PSK: &str = "snell-integration-psk";
const TIMEOUT: Duration = Duration::from_secs(10);

/// What the mock server does after reading (and recording) a request header.
#[derive(Clone, Copy)]
enum Behavior {
    /// Reply `RESPONSE_TUNNEL`, then echo every chunk back. Honours the
    /// zero-chunk half-close handshake so reuse-mode sessions work.
    Echo,
    /// `Echo` for one session, then close the TCP connection right after
    /// acknowledging the client's half-close.
    EchoThenClose,
    /// Send a tail and the server zero-chunk before the client half-closes,
    /// then require the client zero-chunk before accepting another session.
    PeerClosesFirst,
    /// Reply `RESPONSE_ERROR` with the given code/message, then close.
    ErrorReply { code: u8, msg: &'static str },
    /// Reply a single raw status byte, then close.
    RawReplyByte(u8),
}

/// One request header as seen by the mock server.
#[derive(Debug, Clone)]
struct RecordedRequest {
    cmd: u8,
    host: String,
    port: u16,
}

struct MockServer {
    addr: SocketAddr,
    /// Number of accepted TCP connections (not sessions).
    accepted: Arc<AtomicUsize>,
    /// Number of connections the server has closed.
    closed: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    /// Protocol violations observed by spawned per-connection tasks. A panic
    /// inside a tokio-spawned task would be swallowed by the runtime, so the
    /// serve functions report violations through this list instead and every
    /// test asserts it is empty via [`MockServer::assert_no_violations`].
    violations: Arc<Mutex<Vec<String>>>,
}

impl MockServer {
    fn assert_no_violations(&self) {
        let violations = self.violations.lock().unwrap();
        assert!(
            violations.is_empty(),
            "mock server observed protocol violations: {violations:?}"
        );
    }
}

/// Emit a Snell zero-chunk (half-close) frame. `write_all(&[])` short-circuits
/// inside tokio without calling `poll_write`, so drive the poll by hand.
async fn send_zero_chunk<S: AsyncRead + AsyncWrite + Unpin>(conn: &mut S) -> std::io::Result<()> {
    std::future::poll_fn(|cx| Pin::new(&mut *conn).poll_write(cx, &[])).await?;
    conn.flush().await
}

/// Echo loop for a `COMMAND_UDP` session: parse each client datagram frame
/// `[0x01, 0x00, family, ip, port_be, payload]` and echo back a response
/// frame `[family, ip, port_be, payload]` as a single write.
///
/// Runs inside a tokio-spawned task where panics would be swallowed, so
/// protocol violations are reported as `Err(message)` and surfaced by
/// [`MockServer::assert_no_violations`].
async fn serve_udp_echo<S>(
    conn: &mut S,
    is_zero_chunk: fn(&std::io::Error) -> bool,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match conn.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if is_zero_chunk(&e) => {
                let _ = send_zero_chunk(conn).await;
                return Ok(());
            }
            Err(_) => return Ok(()),
        };
        let frame = &buf[..n];
        if frame.len() < 3 {
            return Err(format!("udp request frame too short: {n} bytes"));
        }
        if frame[0] != COMMAND_UDP_FORWARD {
            let cmd = frame[0];
            return Err(format!("bad udp frame command 0x{cmd:x}"));
        }
        if frame[1] != 0 {
            let host_len = frame[1];
            return Err(format!(
                "expected raw-IP address encoding (host_len 0), got host_len {host_len}"
            ));
        }
        let family = frame[2];
        let ip_len = match family {
            0x04 => 4,
            0x06 => 16,
            other => return Err(format!("unknown udp address family 0x{other:x}")),
        };
        if frame.len() < 3 + ip_len + 2 {
            return Err(format!(
                "udp frame truncated: {n} bytes for family 0x{family:x}"
            ));
        }
        let mut reply = Vec::with_capacity(1 + ip_len + 2 + frame.len());
        reply.push(family);
        reply.extend_from_slice(&frame[3..3 + ip_len + 2]); // ip + port
        reply.extend_from_slice(&frame[3 + ip_len + 2..]); // payload
        if conn.write_all(&reply).await.is_err() || conn.flush().await.is_err() {
            return Ok(());
        }
    }
}

/// Serve one accepted connection. Loops over sessions so reuse-mode clients
/// can issue several CONNECTs on the same TCP stream.
///
/// Runs inside a tokio-spawned task where panics would be swallowed, so
/// protocol violations are reported as `Err(message)` and surfaced by
/// [`MockServer::assert_no_violations`].
async fn serve_conn(
    mut conn: impl AsyncRead + AsyncWrite + Unpin,
    behavior: Behavior,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    is_zero_chunk: fn(&std::io::Error) -> bool,
) -> Result<(), String> {
    loop {
        // Request header: [ver, cmd, client_id_len] then, for CONNECT
        // commands, [host_len, host..., port_be].
        let mut prefix = [0u8; 3];
        if conn.read_exact(&mut prefix).await.is_err() {
            return Ok(());
        }
        if prefix[0] != HEADER_VERSION {
            let ver = prefix[0];
            return Err(format!("unexpected snell header version {ver}"));
        }
        if prefix[2] != 0 {
            let id_len = prefix[2];
            return Err(format!("expected empty client id, got length {id_len}"));
        }
        let cmd = prefix[1];
        let (host, port) = if cmd == COMMAND_UDP {
            (String::new(), 0u16)
        } else {
            let mut len = [0u8; 1];
            if conn.read_exact(&mut len).await.is_err() {
                return Ok(());
            }
            let mut host_buf = vec![0u8; len[0] as usize];
            if conn.read_exact(&mut host_buf).await.is_err() {
                return Ok(());
            }
            let mut port_buf = [0u8; 2];
            if conn.read_exact(&mut port_buf).await.is_err() {
                return Ok(());
            }
            (
                String::from_utf8(host_buf).map_err(|e| format!("host must be utf-8: {e}"))?,
                u16::from_be_bytes(port_buf),
            )
        };
        requests
            .lock()
            .unwrap()
            .push(RecordedRequest { cmd, host, port });

        match behavior {
            Behavior::ErrorReply { code, msg } => {
                let mut reply = vec![RESPONSE_ERROR, code, msg.len() as u8];
                reply.extend_from_slice(msg.as_bytes());
                let _ = conn.write_all(&reply).await;
                let _ = conn.flush().await;
                return Ok(());
            }
            Behavior::RawReplyByte(byte) => {
                let _ = conn.write_all(&[byte]).await;
                let _ = conn.flush().await;
                return Ok(());
            }
            Behavior::Echo | Behavior::EchoThenClose | Behavior::PeerClosesFirst => {
                if conn.write_all(&[RESPONSE_TUNNEL]).await.is_err() || conn.flush().await.is_err()
                {
                    return Ok(());
                }
                if cmd == COMMAND_UDP {
                    return serve_udp_echo(&mut conn, is_zero_chunk).await;
                }
                if matches!(behavior, Behavior::PeerClosesFirst) {
                    if conn.write_all(b"tail").await.is_err()
                        || send_zero_chunk(&mut conn).await.is_err()
                    {
                        return Ok(());
                    }
                    let mut buf = [0u8; 1024];
                    match conn.read(&mut buf).await {
                        Ok(0) => return Ok(()),
                        Ok(n) => {
                            return Err(format!(
                                "received {n} payload bytes after peer half-close"
                            ));
                        }
                        Err(e) if is_zero_chunk(&e) => {}
                        Err(_) => return Ok(()),
                    }
                    continue;
                }
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) => return Ok(()),
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err()
                                || conn.flush().await.is_err()
                            {
                                return Ok(());
                            }
                        }
                        Err(e) if is_zero_chunk(&e) => {
                            // Acknowledge the client's half-close with our
                            // own zero chunk, then wait for the next session
                            // header on the same TCP stream (reuse mode).
                            if send_zero_chunk(&mut conn).await.is_err()
                                || matches!(behavior, Behavior::EchoThenClose)
                            {
                                return Ok(());
                            }
                            break;
                        }
                        Err(_) => return Ok(()),
                    }
                }
            }
        }
    }
}

async fn start_mock_server(psk: &'static str, behavior: Behavior) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let requests: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let violations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let accepted_task = Arc::clone(&accepted);
    let closed_task = Arc::clone(&closed);
    let requests_task = Arc::clone(&requests);
    let violations_task = Arc::clone(&violations);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            accepted_task.fetch_add(1, Ordering::SeqCst);
            let conn = V4Conn::new(stream, Arc::from(psk.as_bytes()));
            let requests_conn = Arc::clone(&requests_task);
            let violations_conn = Arc::clone(&violations_task);
            let closed_conn = Arc::clone(&closed_task);
            tokio::spawn(async move {
                if let Err(violation) =
                    serve_conn(conn, behavior, requests_conn, is_v4_zero_chunk).await
                {
                    violations_conn.lock().unwrap().push(violation);
                }
                closed_conn.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    MockServer {
        addr,
        accepted,
        closed,
        requests,
        violations,
    }
}

async fn start_v3_mock_server(psk: &'static str, behavior: Behavior) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let requests: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let violations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let accepted_task = Arc::clone(&accepted);
    let closed_task = Arc::clone(&closed);
    let requests_task = Arc::clone(&requests);
    let violations_task = Arc::clone(&violations);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            accepted_task.fetch_add(1, Ordering::SeqCst);
            let conn = V3Conn::new(stream, Arc::from(psk.as_bytes()));
            let requests_conn = Arc::clone(&requests_task);
            let violations_conn = Arc::clone(&violations_task);
            let closed_conn = Arc::clone(&closed_task);
            tokio::spawn(async move {
                if let Err(violation) =
                    serve_conn(conn, behavior, requests_conn, is_v3_zero_chunk).await
                {
                    violations_conn.lock().unwrap().push(violation);
                }
                closed_conn.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    MockServer {
        addr,
        accepted,
        closed,
        requests,
        violations,
    }
}

fn make_adapter(server_port: u16, psk: &str, udp: bool, reuse: bool) -> SnellAdapter {
    make_adapter_with_version(server_port, psk, SnellVersion::V4, udp, reuse)
}

fn make_adapter_with_version(
    server_port: u16,
    psk: &str,
    version: SnellVersion,
    udp: bool,
    reuse: bool,
) -> SnellAdapter {
    SnellAdapter::new(
        "snell-test",
        "127.0.0.1",
        server_port,
        psk,
        SnellObfs::None,
        version,
        udp,
        reuse,
        Arc::new(DirectDialer),
    )
    .expect("adapter config must be valid")
}

fn tcp_metadata(host: &str, port: u16) -> Metadata {
    Metadata {
        network: Network::Tcp,
        host: host.into(),
        dst_port: port,
        ..Default::default()
    }
}

/// Write `payload`, flush, and read the echo back, all under timeouts.
async fn roundtrip<C>(conn: &mut C, payload: &[u8])
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    timeout(TIMEOUT, conn.write_all(payload))
        .await
        .expect("write timed out")
        .expect("write failed");
    timeout(TIMEOUT, conn.flush())
        .await
        .expect("flush timed out")
        .expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("echo read timed out")
        .expect("echo read failed");
    assert_eq!(buf, payload, "echoed payload must match");
}

/// Wait until the adapter's reuse pool holds at least `want` idle conns.
/// `PooledConn::Drop` returns the conn from a spawned task (drain + put), so
/// a fixed sleep would race it; poll the pool size under the global timeout
/// instead.
async fn wait_for_pool_size(adapter: &SnellAdapter, want: usize) {
    timeout(TIMEOUT, async {
        while adapter.idle_pool_size() < want {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reuse pool was not replenished in time");
}

async fn wait_for_closed(server: &MockServer, want: usize) {
    timeout(TIMEOUT, async {
        while server.closed.load(Ordering::SeqCst) < want {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mock server did not close enough connections in time");
}

async fn wait_for_accepted(server: &MockServer, want: usize) {
    timeout(TIMEOUT, async {
        while server.accepted.load(Ordering::SeqCst) < want {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mock server did not accept enough connections in time");
}

/// Exercise the adapter behind a bidirectional relay. The local side
/// half-closes first; the relay sends the client zero-chunk, consumes the
/// server zero-chunk as EOF, and only then drops the proxy connection.
async fn relay_roundtrip(adapter: &SnellAdapter, metadata: &Metadata, payload: &[u8]) {
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(metadata))
        .await
        .expect("dial timed out")
        .expect("dial failed");
    let (mut client, mut relay_side) = tokio::io::duplex(64 * 1024);

    let relay = async {
        tokio::io::copy_bidirectional(&mut relay_side, &mut conn)
            .await
            .expect("bidirectional relay failed");
    };
    let client_io = async {
        client
            .write_all(payload)
            .await
            .expect("client write failed");
        client.flush().await.expect("client flush failed");
        let mut echoed = vec![0u8; payload.len()];
        client
            .read_exact(&mut echoed)
            .await
            .expect("client echo read failed");
        assert_eq!(echoed, payload);
        client.shutdown().await.expect("client shutdown failed");
        let mut trailing = Vec::new();
        client
            .read_to_end(&mut trailing)
            .await
            .expect("client EOF read failed");
        assert!(trailing.is_empty());
    };

    timeout(TIMEOUT, async { tokio::join!(relay, client_io) })
        .await
        .expect("relay lifecycle timed out");
}

#[tokio::test]
async fn tcp_connect_roundtrip_no_reuse() {
    let server = start_mock_server(PSK, Behavior::Echo).await;
    let adapter = make_adapter(server.addr.port(), PSK, false, false);

    let metadata = tcp_metadata("echo.example.com", 8080);
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial timed out")
        .expect("dial failed");
    roundtrip(&mut conn, b"hello snell").await;

    {
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cmd, COMMAND_CONNECT);
        assert_eq!(requests[0].host, "echo.example.com");
        assert_eq!(requests[0].port, 8080);
    }
    server.assert_no_violations();
}

#[tokio::test]
async fn tcp_connect_roundtrip_v3_reuse_flag_ignored() {
    let server = start_v3_mock_server(PSK, Behavior::Echo).await;
    let adapter = make_adapter_with_version(server.addr.port(), PSK, SnellVersion::V3, false, true);

    let metadata = tcp_metadata("v3.example.com", 8443);
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial timed out")
        .expect("dial failed");
    roundtrip(&mut conn, b"hello snell v3").await;

    {
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].cmd, COMMAND_CONNECT,
            "Snell v3 must not use CommandConnectV2 even when reuse=true"
        );
        assert_eq!(requests[0].host, "v3.example.com");
        assert_eq!(requests[0].port, 8443);
    }
    assert_eq!(
        adapter.idle_pool_size(),
        0,
        "Snell v3 must not create a reuse pool"
    );
    server.assert_no_violations();
}

#[tokio::test]
async fn tcp_large_payload_roundtrip() {
    let server = start_mock_server(PSK, Behavior::Echo).await;
    let adapter = make_adapter(server.addr.port(), PSK, false, false);

    let conn = timeout(
        TIMEOUT,
        adapter.dial_tcp(&tcp_metadata("bulk.example.com", 80)),
    )
    .await
    .expect("dial timed out")
    .expect("dial failed");

    // ~100 KiB patterned payload — spans many frames and exercises the v4
    // payload-limit ramp-up in both directions.
    let payload: Vec<u8> = (0u32..100 * 1024).map(|i| (i % 251) as u8).collect();
    let (mut read_half, mut write_half) = tokio::io::split(conn);
    let to_send = payload.clone();
    let writer = tokio::spawn(async move {
        write_half
            .write_all(&to_send)
            .await
            .expect("large write failed");
        write_half.flush().await.expect("large flush failed");
    });

    let mut got = vec![0u8; payload.len()];
    timeout(TIMEOUT, read_half.read_exact(&mut got))
        .await
        .expect("large echo read timed out")
        .expect("large echo read failed");
    timeout(TIMEOUT, writer)
        .await
        .expect("writer join timed out")
        .expect("writer task panicked");
    assert_eq!(got, payload, "100 KiB payload must round-trip intact");

    {
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cmd, COMMAND_CONNECT);
    }
    server.assert_no_violations();
}

#[tokio::test]
async fn metadata_ip_literal_when_no_host() {
    let server = start_mock_server(PSK, Behavior::Echo).await;
    let adapter = make_adapter(server.addr.port(), PSK, false, false);

    // No host — the adapter must fall back to the destination IP literal.
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: 4242,
        ..Default::default()
    };
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial timed out")
        .expect("dial failed");
    roundtrip(&mut conn, b"ip literal").await;

    {
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cmd, COMMAND_CONNECT);
        assert_eq!(requests[0].host, "127.0.0.1");
        assert_eq!(requests[0].port, 4242);
    }
    server.assert_no_violations();
}

#[tokio::test]
async fn reuse_pool_reuses_tcp_connection() {
    let server = start_mock_server(PSK, Behavior::Echo).await;
    let adapter = make_adapter(server.addr.port(), PSK, false, true);
    let metadata = tcp_metadata("reuse.example.com", 443);

    // Session 1 dials; every later session reuses the pooled TCP connection.
    for session in 1..=4 {
        relay_roundtrip(&adapter, &metadata, format!("session-{session}").as_bytes()).await;
        wait_for_pool_size(&adapter, 1).await;
    }
    assert_eq!(
        server.accepted.load(Ordering::SeqCst),
        1,
        "every session must reuse the pooled TCP connection"
    );

    {
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(
            requests.iter().all(|r| r.cmd == COMMAND_CONNECT_V2),
            "reuse mode must always send COMMAND_CONNECT_V2, got {requests:?}"
        );
    }
    server.assert_no_violations();
}

#[tokio::test]
async fn pooled_conn_closed_while_idle_is_skipped() {
    let server = start_mock_server(PSK, Behavior::EchoThenClose).await;
    let adapter = make_adapter(server.addr.port(), PSK, false, true);
    let metadata = tcp_metadata("idle-close.example.com", 443);

    relay_roundtrip(&adapter, &metadata, b"session-1").await;
    wait_for_pool_size(&adapter, 1).await;
    wait_for_closed(&server, 1).await;

    // The pooled conn now reads EOF, so session 2 must dial fresh instead
    // of sending its header into the closed connection.
    relay_roundtrip(&adapter, &metadata, b"session-2").await;
    assert_eq!(
        server.accepted.load(Ordering::SeqCst),
        2,
        "session 2 must not reuse the closed connection"
    );
    server.assert_no_violations();
}

#[tokio::test]
async fn peer_half_close_is_acknowledged_before_pooling() {
    let server = start_mock_server(PSK, Behavior::PeerClosesFirst).await;
    let adapter = make_adapter(server.addr.port(), PSK, false, true);
    let metadata = tcp_metadata("peer-close.example.com", 443);

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial 1 timed out")
        .expect("dial 1 failed");
    let mut tail = [0u8; 4];
    timeout(TIMEOUT, conn.read_exact(&mut tail))
        .await
        .expect("tail read timed out")
        .expect("tail read failed");
    assert_eq!(&tail, b"tail");
    assert_eq!(
        timeout(TIMEOUT, conn.read(&mut tail))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(conn);
    wait_for_pool_size(&adapter, 1).await;

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial 2 timed out")
        .expect("dial 2 failed");
    timeout(TIMEOUT, conn.read_exact(&mut tail))
        .await
        .expect("reused tail read timed out")
        .expect("reused tail read failed");
    assert_eq!(&tail, b"tail");
    assert_eq!(
        server.accepted.load(Ordering::SeqCst),
        1,
        "second session must reuse the clean TCP connection"
    );
    assert_eq!(
        timeout(TIMEOUT, conn.read(&mut tail))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(conn);
    server.assert_no_violations();
}

#[tokio::test]
async fn unread_peer_tail_is_never_pooled() {
    let server = start_mock_server(PSK, Behavior::PeerClosesFirst).await;
    let adapter = make_adapter(server.addr.port(), PSK, false, true);
    let metadata = tcp_metadata("dirty.example.com", 443);

    let conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial 1 timed out")
        .expect("dial 1 failed");
    // Leave the response, tail and server zero-chunk unread. Draining these
    // in Drop would incorrectly make the still-unacknowledged session look
    // reusable.
    drop(conn);
    assert_eq!(adapter.idle_pool_size(), 0);

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial 2 timed out")
        .expect("dial 2 failed");
    wait_for_accepted(&server, 2).await;
    let mut tail = [0u8; 4];
    timeout(TIMEOUT, conn.read_exact(&mut tail))
        .await
        .expect("fresh tail read timed out")
        .expect("fresh tail read failed");
    assert_eq!(&tail, b"tail");
    assert_eq!(
        timeout(TIMEOUT, conn.read(&mut tail))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(conn);
    server.assert_no_violations();
}

#[tokio::test]
async fn server_error_reply_fails_first_read() {
    let server = start_mock_server(
        PSK,
        Behavior::ErrorReply {
            code: 42,
            msg: "denied",
        },
    )
    .await;
    let adapter = make_adapter(server.addr.port(), PSK, false, false);

    // The CONNECT header is written blind, so the dial itself succeeds.
    let mut conn = timeout(
        TIMEOUT,
        adapter.dial_tcp(&tcp_metadata("denied.example.com", 80)),
    )
    .await
    .expect("dial timed out")
    .expect("dial must succeed — the header is written blind");

    let mut buf = [0u8; 16];
    let err = timeout(TIMEOUT, conn.read(&mut buf))
        .await
        .expect("read timed out")
        .expect_err("first read must surface the server error reply");
    assert_eq!(err.kind(), ErrorKind::Other);
    assert!(
        err.to_string().contains("error response"),
        "unexpected error: {err}"
    );

    // The poll_read path deliberately reports a generic error; the structured
    // code + message must be observable via the explicit `read_reply` path.
    // Speak the protocol by hand on a fresh connection to verify it.
    let tcp = timeout(TIMEOUT, TcpStream::connect(server.addr))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    let mut snell = Snell::new(tcp, Arc::from(PSK.as_bytes()));
    timeout(
        TIMEOUT,
        write_header(&mut snell, "denied.example.com", 80, false),
    )
    .await
    .expect("header write timed out")
    .expect("header write failed");
    timeout(TIMEOUT, snell.flush())
        .await
        .expect("flush timed out")
        .expect("flush failed");
    let err = timeout(TIMEOUT, snell.read_reply())
        .await
        .expect("read_reply timed out")
        .expect_err("read_reply must surface the structured server error");
    let app = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<AppError>())
        .unwrap_or_else(|| panic!("error must carry an AppError payload, got: {err}"));
    assert_eq!(app.code, 42, "server error code must be surfaced");
    assert_eq!(
        app.message, "denied",
        "server error message must be surfaced"
    );

    server.assert_no_violations();
}

#[tokio::test]
async fn unknown_reply_byte_rejected() {
    let server = start_mock_server(PSK, Behavior::RawReplyByte(0x7E)).await;
    let adapter = make_adapter(server.addr.port(), PSK, false, false);

    let mut conn = timeout(
        TIMEOUT,
        adapter.dial_tcp(&tcp_metadata("weird.example.com", 80)),
    )
    .await
    .expect("dial timed out")
    .expect("dial failed");

    let mut buf = [0u8; 16];
    let err = timeout(TIMEOUT, conn.read(&mut buf))
        .await
        .expect("read timed out")
        .expect_err("first read must reject the unknown reply byte");
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("unknown response code"),
        "unexpected error: {err}"
    );
    server.assert_no_violations();
}

#[tokio::test]
async fn wrong_psk_fails_with_decrypt_error() {
    // Custom mock: replies `RESPONSE_TUNNEL` immediately, AEAD-sealed under a
    // *different* PSK, without reading the request first. The client must
    // fail to open the frame — deterministically an InvalidData decrypt
    // error, not an opaque EOF/reset from the server tearing down.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let mut conn = V4Conn::new(stream, Arc::from(b"a-completely-different-psk".as_slice()));
        if conn.write_all(&[RESPONSE_TUNNEL]).await.is_err() || conn.flush().await.is_err() {
            return;
        }
        // Hold the conn open until the client has read the bogus reply (this
        // read fails to decrypt the client's header — irrelevant here).
        let mut buf = [0u8; 1024];
        let _ = conn.read(&mut buf).await;
    });

    let adapter = make_adapter(addr.port(), PSK, false, false);
    let mut conn = timeout(
        TIMEOUT,
        adapter.dial_tcp(&tcp_metadata("psk.example.com", 80)),
    )
    .await
    .expect("dial timed out")
    .expect("dial must succeed — the header is written blind");

    let mut buf = [0u8; 16];
    let err = timeout(TIMEOUT, conn.read(&mut buf))
        .await
        .expect("read timed out")
        .expect_err("read with a mismatched psk must fail");
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidData,
        "wrong psk must surface as an AEAD decrypt failure, got: {err}"
    );
    assert!(
        err.to_string().contains("decrypt"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn udp_roundtrip_ipv4() {
    let server = start_mock_server(PSK, Behavior::Echo).await;
    let adapter = make_adapter(server.addr.port(), PSK, true, false);

    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        dst_port: 5353,
        ..Default::default()
    };
    let pc = timeout(TIMEOUT, adapter.dial_udp(&metadata))
        .await
        .expect("dial_udp timed out")
        .expect("dial_udp failed");

    let dst: SocketAddr = "1.2.3.4:5353".parse().unwrap();
    let payload = b"dns-query-ipv4";
    let n = timeout(TIMEOUT, pc.write_packet(payload, &dst))
        .await
        .expect("write_packet timed out")
        .expect("write_packet failed");
    assert_eq!(n, payload.len());

    let mut buf = [0u8; 1500];
    let (n, from) = timeout(TIMEOUT, pc.read_packet(&mut buf))
        .await
        .expect("read_packet timed out")
        .expect("read_packet failed");
    assert_eq!(&buf[..n], payload);
    assert_eq!(from, dst, "echoed source address must round-trip");

    {
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cmd, COMMAND_UDP);
    }
    server.assert_no_violations();
}

#[tokio::test]
async fn udp_roundtrip_ipv4_v3() {
    let server = start_v3_mock_server(PSK, Behavior::Echo).await;
    let adapter = make_adapter_with_version(server.addr.port(), PSK, SnellVersion::V3, true, false);

    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
        dst_port: 53,
        ..Default::default()
    };
    let pc = timeout(TIMEOUT, adapter.dial_udp(&metadata))
        .await
        .expect("dial_udp timed out")
        .expect("dial_udp failed");

    let dst: SocketAddr = "8.8.4.4:53".parse().unwrap();
    let payload = b"dns-query-v3";
    let n = timeout(TIMEOUT, pc.write_packet(payload, &dst))
        .await
        .expect("write_packet timed out")
        .expect("write_packet failed");
    assert_eq!(n, payload.len());

    let mut buf = [0u8; 1500];
    let (n, from) = timeout(TIMEOUT, pc.read_packet(&mut buf))
        .await
        .expect("read_packet timed out")
        .expect("read_packet failed");
    assert_eq!(&buf[..n], payload);
    assert_eq!(from, dst, "echoed source address must round-trip");

    {
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cmd, COMMAND_UDP);
    }
    server.assert_no_violations();
}

#[tokio::test]
async fn udp_roundtrip_ipv6() {
    let server = start_mock_server(PSK, Behavior::Echo).await;
    let adapter = make_adapter(server.addr.port(), PSK, true, false);

    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some("2001:db8::1".parse().unwrap()),
        dst_port: 53,
        ..Default::default()
    };
    let pc = timeout(TIMEOUT, adapter.dial_udp(&metadata))
        .await
        .expect("dial_udp timed out")
        .expect("dial_udp failed");

    let dst: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
    let payload = b"dns-query-ipv6";
    let n = timeout(TIMEOUT, pc.write_packet(payload, &dst))
        .await
        .expect("write_packet timed out")
        .expect("write_packet failed");
    assert_eq!(n, payload.len());

    let mut buf = [0u8; 1500];
    let (n, from) = timeout(TIMEOUT, pc.read_packet(&mut buf))
        .await
        .expect("read_packet timed out")
        .expect("read_packet failed");
    assert_eq!(&buf[..n], payload);
    assert_eq!(from, dst, "echoed source address must round-trip");

    {
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cmd, COMMAND_UDP);
    }
    server.assert_no_violations();
}

#[tokio::test]
async fn udp_disabled_is_rejected() {
    // Port 1 is never dialed — the rejection happens before any I/O.
    let adapter = make_adapter(1, PSK, false, false);
    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: 53,
        ..Default::default()
    };
    match adapter.dial_udp(&metadata).await {
        Ok(_) => panic!("dial_udp must fail when udp is disabled"),
        Err(MeowError::NotSupported(msg)) => {
            assert!(
                msg.to_lowercase().contains("udp"),
                "error should mention udp: {msg}"
            );
        }
        Err(other) => panic!("expected NotSupported, got {other:?}"),
    }
}

#[test]
fn constructor_rejects_bad_config() {
    assert!(
        SnellAdapter::new(
            "s",
            "127.0.0.1",
            80,
            "",
            SnellObfs::None,
            SnellVersion::V4,
            false,
            false,
            Arc::new(DirectDialer),
        )
        .is_err(),
        "empty psk must be rejected"
    );
    assert!(
        SnellAdapter::new(
            "s",
            "127.0.0.1",
            0,
            PSK,
            SnellObfs::None,
            SnellVersion::V4,
            false,
            false,
            Arc::new(DirectDialer),
        )
        .is_err(),
        "port 0 must be rejected"
    );
    assert!(
        SnellAdapter::new(
            "s",
            "",
            80,
            PSK,
            SnellObfs::None,
            SnellVersion::V4,
            false,
            false,
            Arc::new(DirectDialer),
        )
        .is_err(),
        "empty server must be rejected"
    );
}
