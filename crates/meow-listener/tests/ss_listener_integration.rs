#![cfg(feature = "listener-shadowsocks")]
//! Integration tests for the shadowsocks encrypted-server inbound listener.
//!
//! Drives the real `ShadowsocksListener` → `route_inbound_tcp` → DIRECT
//! relay path with an in-process `shadowsocks` crate *client* and a local
//! echo server. No external binary (`sslocal`/`ssserver`) required.
//!
//! Cipher decryption is exercised end-to-end: the client encrypts with the
//! same `aes-256-gcm` key the listener expects; a wrong password fails at
//! `ProxyServerStream::handshake` and the connection is dropped without
//! leaking the target.

mod common;

use common::{direct_tunnel, spawn_echo_server};
use meow_listener::{ShadowsocksListener, SsObfsMode};
use meow_transport::simple_obfs::client::{HttpObfs, TlsObfs};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend};
use shadowsocks::relay::Address;
use shadowsocks::ProxyClientStream;
use shadowsocks::ProxySocket;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const CIPHER: &str = "aes-256-gcm";
const PASSWORD: &str = "test-ss-listener-password";
const TIMEOUT: Duration = Duration::from_secs(5);

/// Drive one send→echo exchange with retransmission. UDP has no backlog, so
/// a datagram sent before the listener's relay socket finished binding is
/// silently dropped by the OS — the fixed sleep in the bind helpers shrinks
/// but does not eliminate that window (observed ~1-in-3 flake under parallel
/// test load). Retrying the *first* exchange (250ms interval, 3s budget)
/// makes the UDP tests deterministic; once an echo comes back the relay is
/// proven up and later exchanges need no retry. This mirrors real SS
/// clients, which retransmit UDP (DNS) queries.
async fn udp_echo_with_retry<S>(
    client: &ProxySocket<S>,
    ss_addr: std::net::SocketAddr,
    target: &Address,
    payload: &[u8],
    buf: &mut [u8],
) -> usize
where
    S: DatagramSend + DatagramReceive + Send + Sync + 'static,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        client.send_to(ss_addr, target, payload).await.unwrap();
        match tokio::time::timeout(Duration::from_millis(250), client.recv_from(buf)).await {
            Ok(Ok((n, ..))) => return n,
            Ok(Err(e)) => panic!("udp recv failed: {e}"),
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("udp echo did not arrive within 3s of retransmission");
                }
            }
        }
    }
}

/// Build a shadowsocks *client* `ServerConfig` pointing at the listener.
fn client_cfg(ss_addr: std::net::SocketAddr) -> ServerConfig {
    let method = CIPHER.parse::<CipherKind>().unwrap();
    ServerConfig::new(ss_addr, PASSWORD, method).unwrap()
}

/// Bind a `ShadowsocksListener` (TCP, no obfs, no UDP) on an ephemeral port
/// and return its address. The accept loop is spawned in the background.
async fn bind_ss_listener() -> std::net::SocketAddr {
    bind_ss_listener_with(false).await
}

/// Like [`bind_ss_listener`] but with `udp: true` so the listener also starts
/// the SS UDP relay on the same resolved port.
async fn bind_ss_listener_udp() -> std::net::SocketAddr {
    bind_ss_listener_with(true).await
}

async fn bind_ss_listener_with(udp: bool) -> std::net::SocketAddr {
    bind_ss_listener_cfg(udp, None).await
}

/// Bind a `ShadowsocksListener` with a simple-obfs mode (TCP only; UDP is
/// auto-disabled by the listener when obfs is set).
async fn bind_ss_listener_obfs(obfs: SsObfsMode) -> std::net::SocketAddr {
    bind_ss_listener_cfg(false, Some(obfs)).await
}

async fn bind_ss_listener_cfg(udp: bool, obfs: Option<SsObfsMode>) -> std::net::SocketAddr {
    let tunnel = direct_tunnel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ss = ShadowsocksListener::new(tunnel, addr, "ss-test".into(), CIPHER, PASSWORD, udp, obfs)
        .unwrap();
    tokio::spawn(async move {
        let _ = ss.run_on(listener).await;
    });
    // The TCP socket is already bound, so the kernel backlog accepts
    // connections before the accept loop runs. For UDP tests, the relay
    // socket is bound inside `run_on`; a brief yield gives the spawned
    // task time to start. 50ms is conservative — the ProxySocket::bind is
    // a single syscall.
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Like [`bind_ss_listener_cfg`] but with an explicit `max-connections`
/// override, so tests can exercise the TCP concurrency cap and the UDP
/// flow-table cap (both share the value).
async fn bind_ss_listener_udp_capped(max_connections: usize) -> std::net::SocketAddr {
    let tunnel = direct_tunnel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ss = ShadowsocksListener::new(tunnel, addr, "ss-test".into(), CIPHER, PASSWORD, true, None)
        .unwrap()
        .with_max_connections(max_connections);
    tokio::spawn(async move {
        let _ = ss.run_on(listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Like [`bind_ss_listener_udp`] but with an explicit cipher + password: the
/// AEAD-2022 tests need a base64 PSK rather than the suite's shared
/// `aes-256-gcm` password.
async fn bind_ss_listener_udp_with(cipher: &str, password: &str) -> std::net::SocketAddr {
    let tunnel = direct_tunnel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ss = ShadowsocksListener::new(
        tunnel,
        addr,
        "ss-test-2022".into(),
        cipher,
        password,
        true,
        None,
    )
    .unwrap();
    tokio::spawn(async move {
        let _ = ss.run_on(listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Spawn a UDP echo server on an ephemeral port; returns its address.
async fn spawn_udp_echo_server() -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                break;
            };
            if sock.send_to(&buf[..n], src).await.is_err() {
                break;
            }
        }
    });
    addr
}

#[tokio::test]
async fn ss_tcp_listener_relays_to_direct_echo() {
    let echo = spawn_echo_server().await;
    let ss_addr = bind_ss_listener().await;

    let ctx = Context::new_shared(ServerType::Local);
    let cfg = client_cfg(ss_addr);
    let mut stream = tokio::time::timeout(TIMEOUT, ProxyClientStream::connect(ctx, &cfg, echo))
        .await
        .expect("client connect timed out")
        .expect("client connect failed");

    let payload = b"hello through ss listener";
    stream.write_all(payload).await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("echo read timed out")
        .expect("echo read failed");
    assert_eq!(&buf[..n], payload, "echoed payload must match");
}

#[tokio::test]
async fn ss_tcp_listener_rejects_wrong_password() {
    let echo = spawn_echo_server().await;
    let ss_addr = bind_ss_listener().await;

    // Client with a wrong password. The SS AEAD handshake (first block
    // decrypt) fails on the server side; the connection is dropped. The
    // client's write/read then surfaces an error or EOF — never the echo.
    // The rejection is fast (sub-millisecond AEAD tag check); 2s is a
    // generous safety net, not the expected latency.
    let method = CIPHER.parse::<CipherKind>().unwrap();
    let bad_cfg = ServerConfig::new(ss_addr, "wrong-password", method).unwrap();
    let ctx = Context::new_shared(ServerType::Local);

    // `connect` only opens the TCP link; the AEAD tag is checked on the first
    // read/write of payload, so we drive a write + read and assert no echo.
    let mut stream = tokio::time::timeout(
        Duration::from_secs(2),
        ProxyClientStream::connect(ctx, &bad_cfg, echo),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    let _ = stream.write_all(b"should-not-relay").await;
    let mut buf = [0u8; 64];
    let res = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    // Either a clean EOF (0 bytes) or an error — never the echoed payload.
    // (clippy: collapse the two empty arms into one pattern.)
    match res {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("wrong-password connection relayed {n} bytes (should be rejected)"),
        Err(_) => panic!("read timed out"),
    }
}

#[tokio::test]
async fn ss_udp_listener_relays_to_direct_echo() {
    let echo = spawn_udp_echo_server().await;
    let ss_addr = bind_ss_listener_udp().await;

    // Client-side SS UDP socket: a bound (non-connected) socket so we can use
    // `send_to`/`recv_from` (the connected-socket `send`/`recv` pair would also
    // work, but `send_to` keeps the server endpoint explicit and inspectable).
    let ctx = Context::new_shared(ServerType::Local);
    let cfg = client_cfg(ss_addr);
    let raw =
        shadowsocks::net::UdpSocket::bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .await
            .unwrap();
    let client = ProxySocket::from_socket(
        shadowsocks::relay::udprelay::proxy_socket::UdpSocketType::Client,
        ctx,
        &cfg,
        raw,
    );

    let payload = b"hello ss udp";
    let mut buf = [0u8; 128];
    let n = udp_echo_with_retry(
        &client,
        ss_addr,
        &Address::SocketAddress(echo),
        payload,
        &mut buf,
    )
    .await;
    assert_eq!(&buf[..n], payload, "echoed UDP payload must match");
}

#[tokio::test]
async fn ss_udp_flow_table_cap_drops_new_flows_but_keeps_existing() {
    // `max-connections: 1` also caps the UDP flow table at 1 (peer, target)
    // flow. The first flow must relay; a datagram to a *new* target is
    // dropped while the table is saturated; the existing flow keeps
    // relaying (the cap only blocks new-flow creation).
    let echo1 = spawn_udp_echo_server().await;
    let echo2 = spawn_udp_echo_server().await;
    let ss_addr = bind_ss_listener_udp_capped(1).await;

    let ctx = Context::new_shared(ServerType::Local);
    let cfg = client_cfg(ss_addr);
    let raw =
        shadowsocks::net::UdpSocket::bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .await
            .unwrap();
    let client = ProxySocket::from_socket(
        shadowsocks::relay::udprelay::proxy_socket::UdpSocketType::Client,
        ctx,
        &cfg,
        raw,
    );

    // Flow 1 fills the table (cap = 1) and must echo. Retransmission here is
    // harmless for the cap semantics: every retry targets the same
    // (peer, target) key, so the first datagram that gets through creates
    // the flow and the rest hit the existing-flow fast path.
    let mut buf = [0u8; 128];
    let n = udp_echo_with_retry(
        &client,
        ss_addr,
        &Address::SocketAddress(echo1),
        b"flow-1",
        &mut buf,
    )
    .await;
    assert_eq!(&buf[..n], b"flow-1", "first flow must relay below the cap");

    // Drain strays: legacy ciphers have no replay dedup, so a retransmitted
    // "flow-1" copy that arrived after the first was processed produces a
    // *second* echo still queued in the socket. Leftover replies would
    // satisfy the negative assert below for the wrong reason. `Ok(Ok(..))`
    // — a persistently erroring recv must end the drain, not spin forever.
    while let Ok(Ok(..)) =
        tokio::time::timeout(Duration::from_millis(50), client.recv_from(&mut buf)).await
    {}

    // A new target while saturated: dropped server-side, no echo. 300ms is
    // ~100x the observed drop latency (a HashMap length check), so a pass
    // never depends on timing luck.
    client
        .send_to(ss_addr, &Address::SocketAddress(echo2), b"flow-2")
        .await
        .unwrap();
    let res = tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await;
    assert!(
        res.is_err(),
        "new flow must be dropped while the table is saturated"
    );

    // The existing flow is unaffected — datagrams for it still pass.
    client
        .send_to(ss_addr, &Address::SocketAddress(echo1), b"flow-1-again")
        .await
        .unwrap();
    let (n, _, _, _) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("existing flow echo timed out")
        .expect("existing flow recv failed");
    assert_eq!(
        &buf[..n],
        b"flow-1-again",
        "existing flow must keep relaying at the cap"
    );
}

// ── simple-obfs TCP relay (HTTP + TLS) ──────────────────────────────────────
//
// The client wraps its TcpStream in the obfs *client* codec, then hands it to
// `ProxyClientStream::from_stream` for SS encryption. The listener wraps the
// accepted stream in the obfs *server* codec before `ProxyServerStream`
// decrypts — exercising the full obfs↔SS layering end-to-end.

async fn ss_obfs_tcp_round_trip(obfs: SsObfsMode) {
    let echo = spawn_echo_server().await;
    let ss_addr = bind_ss_listener_obfs(obfs).await;

    let ctx = Context::new_shared(ServerType::Local);
    let cfg = client_cfg(ss_addr);
    let raw = TcpStream::connect(ss_addr).await.unwrap();
    // The obfs client needs a host/port (HTTP) or server name (TLS). Use the
    // listener's address — the value is only embedded in fake headers/SNI and
    // is never validated by the server codec.
    match obfs {
        SsObfsMode::Http => {
            let obfs = HttpObfs::new(raw, "example.com".to_string(), ss_addr.port()).unwrap();
            relay_echo(ProxyClientStream::from_stream(ctx, obfs, &cfg, echo)).await;
        }
        SsObfsMode::Tls => {
            let obfs = TlsObfs::new(raw, "example.com".to_string()).unwrap();
            relay_echo(ProxyClientStream::from_stream(ctx, obfs, &cfg, echo)).await;
        }
    }
}

/// Drive a `ProxyClientStream` echo round-trip and assert the payload matches.
async fn relay_echo<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: ProxyClientStream<S>,
) {
    let payload = b"hello through ss obfs";
    stream.write_all(payload).await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("obfs echo timed out")
        .expect("obfs echo read failed");
    assert_eq!(&buf[..n], payload, "echoed obfs payload must match");
}

#[tokio::test]
async fn ss_tcp_listener_with_http_obfs_relays() {
    ss_obfs_tcp_round_trip(SsObfsMode::Http).await;
}

#[tokio::test]
async fn ss_tcp_listener_with_tls_obfs_relays() {
    ss_obfs_tcp_round_trip(SsObfsMode::Tls).await;
}

// ── AEAD-2022 control plane (SIP022) ────────────────────────────────────────
//
// Only the 2022 cipher category carries session IDs — older AEAD/stream
// ciphers ignore the control on both sides, so these tests run their own
// `2022-blake3-aes-256-gcm` listener and drive datagrams with explicit
// non-zero client session IDs through `send_to_with_ctrl`: the crate's
// `send_to` shortcut sends an all-zero control, which would let a `0 == 0`
// comparison pass against a buggy all-zero reply.

/// 32-byte PSK in the AEAD-2022 base64 key format, and the cipher using it.
const PSK_2022: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
const CIPHER_2022: &str = "2022-blake3-aes-256-gcm";

/// A bound (unconnected) client-side `ProxySocket` for the 2022 listener.
async fn ss_2022_client(ss_addr: std::net::SocketAddr) -> ProxySocket<shadowsocks::net::UdpSocket> {
    let ctx = Context::new_shared(ServerType::Local);
    let cfg = ServerConfig::new(
        ss_addr,
        PSK_2022,
        CIPHER_2022.parse::<CipherKind>().unwrap(),
    )
    .unwrap();
    let raw =
        shadowsocks::net::UdpSocket::bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .await
            .unwrap();
    ProxySocket::from_socket(
        shadowsocks::relay::udprelay::proxy_socket::UdpSocketType::Client,
        ctx,
        &cfg,
        raw,
    )
}

/// A client control carrying the given session + packet IDs.
fn client_ctrl(client_session_id: u64, packet_id: u64) -> UdpSocketControlData {
    let mut c = UdpSocketControlData::default();
    c.client_session_id = client_session_id;
    c.packet_id = packet_id;
    c
}

/// One send→recv exchange with an explicit control; returns
/// `(payload_len, reply_peer, reply_addr, reply_control)`. A `None` control
/// on a 2022 reply is a hard failure — session data is mandatory there.
async fn exchange_ctrl<S>(
    client: &ProxySocket<S>,
    ss_addr: std::net::SocketAddr,
    target: &Address,
    control: &UdpSocketControlData,
    payload: &[u8],
    buf: &mut [u8],
) -> (usize, std::net::SocketAddr, Address, UdpSocketControlData)
where
    S: DatagramSend + DatagramReceive + Send + Sync + 'static,
{
    client
        .send_to_with_ctrl(ss_addr, target, control, payload)
        .await
        .unwrap();
    match tokio::time::timeout(TIMEOUT, client.recv_from_with_ctrl(buf)).await {
        Ok(Ok((n, peer, addr, _total, Some(reply)))) => (n, peer, addr, reply),
        Ok(Ok((_, _, _, _, None))) => panic!("AEAD-2022 replies must carry a control"),
        Ok(Err(e)) => panic!("udp recv failed: {e}"),
        Err(_) => panic!("2022 udp echo timed out"),
    }
}

/// [`exchange_ctrl`] with the same retransmission rationale as
/// `udp_echo_with_retry`: a datagram sent before the listener's relay socket
/// is bound is silently lost, so the *first* exchange retries until the
/// relay proves itself up. Retransmissions reuse the same packet ID — a real
/// retransmission, which the server's replay window correctly drops; the
/// reply to the first processed copy is what we receive.
async fn exchange_ctrl_retry<S>(
    client: &ProxySocket<S>,
    ss_addr: std::net::SocketAddr,
    target: &Address,
    control: &UdpSocketControlData,
    payload: &[u8],
    buf: &mut [u8],
) -> (usize, std::net::SocketAddr, Address, UdpSocketControlData)
where
    S: DatagramSend + DatagramReceive + Send + Sync + 'static,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        client
            .send_to_with_ctrl(ss_addr, target, control, payload)
            .await
            .unwrap();
        match tokio::time::timeout(Duration::from_millis(250), client.recv_from_with_ctrl(buf))
            .await
        {
            Ok(Ok((n, peer, addr, _total, Some(reply)))) => return (n, peer, addr, reply),
            Ok(Ok((_, _, _, _, None))) => panic!("AEAD-2022 replies must carry a control"),
            Ok(Err(e)) => panic!("udp recv failed: {e}"),
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("2022 udp echo did not arrive within 3s of retransmission");
                }
            }
        }
    }
}

/// SIP022 §3.2.2/§3.2.3: the reply must echo the client's session ID, carry a
/// fresh non-zero server session ID, and number replies with the session's
/// own packet-ID counter.
#[tokio::test]
async fn ss_udp_2022_reply_echoes_client_session_id() {
    const CLIENT_SESSION_ID: u64 = 0x00ff_00ff_1234_5678;

    let echo = spawn_udp_echo_server().await;
    let ss_addr = bind_ss_listener_udp_with(CIPHER_2022, PSK_2022).await;
    let client = ss_2022_client(ss_addr).await;
    let target = Address::SocketAddress(echo);
    let mut buf = [0u8; 256];

    let (n, peer, addr, reply) = exchange_ctrl_retry(
        &client,
        ss_addr,
        &target,
        &client_ctrl(CLIENT_SESSION_ID, 0),
        b"hello 2022 udp",
        &mut buf,
    )
    .await;

    assert_eq!(&buf[..n], b"hello 2022 udp", "echoed payload must match");
    assert_eq!(
        peer, ss_addr,
        "the reply must come from the listener socket"
    );
    assert_eq!(addr, target, "the reply names the responder's address");
    assert_eq!(
        reply.client_session_id, CLIENT_SESSION_ID,
        "the reply header must echo the client session ID"
    );
    assert_ne!(
        reply.server_session_id, 0,
        "the server must mint its own random session ID"
    );
    assert_ne!(
        reply.server_session_id, CLIENT_SESSION_ID,
        "the server session ID must not reuse the client's"
    );
    assert_eq!(
        reply.packet_id, 1,
        "the session's reply counter pre-increments, starting at 1 (ssserver parity)"
    );
    let server_session_id = reply.server_session_id;

    // A second exchange on the same session: the server session ID is stable
    // and the reply packet IDs keep increasing (§3.2.3 — the reply direction
    // owns its counter, shared across the session's flows).
    let (n, _peer, addr, reply) = exchange_ctrl(
        &client,
        ss_addr,
        &target,
        &client_ctrl(CLIENT_SESSION_ID, 1),
        b"second packet",
        &mut buf,
    )
    .await;
    assert_eq!(&buf[..n], b"second packet");
    assert_eq!(addr, target, "the reply names the responder's address");
    assert_eq!(reply.client_session_id, CLIENT_SESSION_ID);
    assert_eq!(
        reply.server_session_id, server_session_id,
        "the server session ID is stable for the session's lifetime"
    );
    assert_eq!(
        reply.packet_id, 2,
        "reply packet IDs count up within the session"
    );
}

/// SIP022 §3.2.4: the client session ID — not the `(peer, target)` tuple — is
/// the session discriminator. One session multiplexing two targets sees a
/// single server session ID and a session-wide reply packet counter.
#[tokio::test]
async fn ss_udp_2022_one_client_session_spans_targets() {
    const CSID: u64 = 0x5eed_5eed_0001;

    let echo1 = spawn_udp_echo_server().await;
    let echo2 = spawn_udp_echo_server().await;
    let ss_addr = bind_ss_listener_udp_with(CIPHER_2022, PSK_2022).await;
    let client = ss_2022_client(ss_addr).await;
    let mut buf = [0u8; 256];

    let (n1, peer1, addr1, reply1) = exchange_ctrl_retry(
        &client,
        ss_addr,
        &Address::SocketAddress(echo1),
        &client_ctrl(CSID, 0),
        b"to echo1",
        &mut buf,
    )
    .await;
    let (n2, peer2, addr2, reply2) = exchange_ctrl(
        &client,
        ss_addr,
        &Address::SocketAddress(echo2),
        &client_ctrl(CSID, 1),
        b"to echo2",
        &mut buf,
    )
    .await;

    // Pin the whole reply tuple: payload, source, and the responder address
    // — a flow keyed without the target would route datagram 2 through
    // flow 1's conn and mislabel the reply.
    assert_eq!(&buf[..n2], b"to echo2");
    assert_eq!(n1, b"to echo1".len());
    assert_eq!(peer1, ss_addr);
    assert_eq!(peer2, ss_addr);
    assert_eq!(addr1, Address::SocketAddress(echo1));
    assert_eq!(addr2, Address::SocketAddress(echo2));

    assert_eq!(
        reply1.server_session_id, reply2.server_session_id,
        "one client session must see ONE server session across targets"
    );
    assert_eq!(
        (reply1.packet_id, reply2.packet_id),
        (1, 2),
        "the reply packet counter is session-wide across flows"
    );
}

/// SIP022 §3.2.4: a *new* client session ID on an existing `(peer, target)`
/// pair is a new relay session — the reply must echo the new ID and carry a
/// fresh server session ID with its own packet counter.
#[tokio::test]
async fn ss_udp_2022_rotated_client_session_rekeys_replies() {
    const CSID_A: u64 = 0xaaaa_0001;
    const CSID_B: u64 = 0xbbbb_0002;

    let echo = spawn_udp_echo_server().await;
    let ss_addr = bind_ss_listener_udp_with(CIPHER_2022, PSK_2022).await;
    let client = ss_2022_client(ss_addr).await;
    let target = Address::SocketAddress(echo);
    let mut buf = [0u8; 256];

    let (_n_a, _peer_a, _addr_a, reply_a) = exchange_ctrl_retry(
        &client,
        ss_addr,
        &target,
        &client_ctrl(CSID_A, 0),
        b"session a",
        &mut buf,
    )
    .await;

    // Same target, new client session ID: the old flow must not answer with
    // the stale session — the reply echoes CSID_B under a fresh server ID.
    let (n, _peer_b, _addr_b, reply_b) = exchange_ctrl(
        &client,
        ss_addr,
        &target,
        &client_ctrl(CSID_B, 0),
        b"session b",
        &mut buf,
    )
    .await;

    assert_eq!(&buf[..n], b"session b");
    assert_eq!(
        reply_b.client_session_id, CSID_B,
        "the reply must echo the rotated client session ID"
    );
    assert_ne!(
        reply_b.server_session_id, reply_a.server_session_id,
        "a new client session mints a new server session ID"
    );
    assert_eq!(
        reply_b.packet_id, 1,
        "the new session restarts the reply packet counter"
    );
}

/// SIP022 §3.2.4: a datagram re-sent with an already-seen packet ID is
/// replay — the server's sliding-window filter drops it before forwarding.
#[tokio::test]
async fn ss_udp_2022_replayed_packet_id_is_dropped() {
    const CSID: u64 = 0xcccc_0003;

    let echo = spawn_udp_echo_server().await;
    let ss_addr = bind_ss_listener_udp_with(CIPHER_2022, PSK_2022).await;
    let client = ss_2022_client(ss_addr).await;
    let target = Address::SocketAddress(echo);
    let mut buf = [0u8; 256];

    let (n, _peer, _addr, _ctrl) = exchange_ctrl_retry(
        &client,
        ss_addr,
        &target,
        &client_ctrl(CSID, 0),
        b"first and only",
        &mut buf,
    )
    .await;
    assert_eq!(&buf[..n], b"first and only");

    // Bit-identical resend: without the window the flow would relay it to
    // the echo server and a second reply would come back.
    client
        .send_to_with_ctrl(ss_addr, &target, &client_ctrl(CSID, 0), b"first and only")
        .await
        .unwrap();
    let res = tokio::time::timeout(
        Duration::from_millis(400),
        client.recv_from_with_ctrl(&mut buf),
    )
    .await;
    assert!(
        res.is_err(),
        "a replayed packet ID must not produce a reply"
    );
}
