//! Integration test: SOCKS5 handshake + CONNECT round-trip through a local echo server.
//!
//! The test drives the full `handle_socks5` path:
//!   client ──SOCKS5──► handle_socks5 ──DIRECT dial──► echo server
//!
//! After the handshake, data written by the client is echoed back via the
//! proxy relay, confirming that bytes flow end-to-end.
#![cfg(feature = "listener-socks5")]

mod common;

use common::{direct_tunnel, spawn_echo_server};
use meow_common::auth::{AuthConfig, Credentials};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Open a real loopback TCP pair.  Returns `(server_side, client_side)`.
async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accept_res, connect_res) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    let (server, _) = accept_res.unwrap();
    let client = connect_res.unwrap();
    (server, client)
}

/// Encode a SOCKS5 CONNECT request for an IPv4 target.
///
/// Layout (RFC 1928):
///   Greeting:  05 01 00                          (ver=5, nmethods=1, method=NoAuth)
///   Request:   05 01 00 01 <ip4> <port_be>       (ver=5, CMD_CONNECT, rsv, ATYP_IPV4)
fn socks5_connect_ipv4(target: SocketAddr) -> Vec<u8> {
    let std::net::IpAddr::V4(ip4) = target.ip() else {
        panic!("expected IPv4 target");
    };
    let mut buf = Vec::new();
    // Greeting
    buf.extend_from_slice(&[0x05, 0x01, 0x00]);
    // CONNECT request
    buf.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
    buf.extend_from_slice(&ip4.octets());
    buf.extend_from_slice(&target.port().to_be_bytes());
    buf
}

/// The server reply to the greeting is `05 00` (NoAuth chosen).
/// The reply to a successful CONNECT is `05 00 00 01 00 00 00 00 00 00`.
fn assert_socks5_connect_success(reply: &[u8]) {
    assert!(reply.len() >= 2, "greeting reply too short");
    assert_eq!(reply[0], 0x05, "expected SOCKS5 version in greeting reply");
    assert_eq!(reply[1], 0x00, "expected NoAuth method chosen");

    assert!(
        reply.len() >= 12,
        "CONNECT reply too short: {} bytes",
        reply.len()
    );
    assert_eq!(reply[2], 0x05, "expected SOCKS5 version in CONNECT reply");
    assert_eq!(reply[3], 0x00, "expected REP_SUCCESS in CONNECT reply");
}

#[tokio::test]
async fn socks5_connect_proxies_bytes_to_echo_server() {
    // 1. Start a local echo server — this is what the proxy will DIRECT-dial.
    let echo_addr = spawn_echo_server().await;

    // 2. Build a real loopback TCP pair to feed bytes to handle_socks5.
    let (server_stream, mut client_stream) = loopback_pair().await;

    // 3. Run handle_socks5 in a background task (it blocks until the relay closes).
    let tunnel = direct_tunnel();
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let handle = tokio::spawn(async move {
        meow_listener::socks5::handle_socks5(
            &tunnel,
            server_stream,
            server_addr,
            None, // no sniffer
            None, // no auth
            "test",
            0,
            None,
            None,
        )
        .await;
    });

    // 4. Client: send SOCKS5 greeting + CONNECT targeting the echo server.
    let req = socks5_connect_ipv4(echo_addr);
    client_stream.write_all(&req).await.unwrap();

    // 5. Read the two replies: greeting (2 bytes) + CONNECT success (10 bytes).
    let mut reply = [0u8; 12];
    client_stream.read_exact(&mut reply).await.unwrap();
    assert_socks5_connect_success(&reply);

    // 6. Now the relay is established. Write test data and read it echoed back.
    let probe = b"hello-socks5";
    client_stream.write_all(probe).await.unwrap();
    let mut echo_buf = [0u8; 12];
    client_stream.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(
        &echo_buf, probe,
        "echo mismatch: relay did not forward bytes"
    );

    // 7. Close the client half — the relay task should terminate cleanly.
    drop(client_stream);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("handle_socks5 task did not finish in time")
        .expect("handle_socks5 task panicked");
}

#[tokio::test]
async fn socks5_rejects_no_auth_when_client_does_not_offer_it() {
    let (server_stream, mut client_stream) = loopback_pair().await;
    let tunnel = direct_tunnel();
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let handle = tokio::spawn(async move {
        meow_listener::socks5::handle_socks5(
            &tunnel,
            server_stream,
            server_addr,
            None,
            None,
            "test",
            0,
            None,
            None,
        )
        .await;
    });

    client_stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

    let mut reply = [0u8; 2];
    client_stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0xFF]);

    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("handle_socks5 task did not finish in time")
        .expect("handle_socks5 task panicked");
}

#[tokio::test]
async fn socks5_rejects_invalid_utf8_domain_name() {
    let (server_stream, mut client_stream) = loopback_pair().await;
    let tunnel = direct_tunnel();
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let handle = tokio::spawn(async move {
        meow_listener::socks5::handle_socks5(
            &tunnel,
            server_stream,
            server_addr,
            None,
            None,
            "test",
            0,
            None,
            None,
        )
        .await;
    });

    client_stream
        .write_all(&[
            0x05, 0x01, 0x00, // greeting: no-auth
            0x05, 0x01, 0x00, 0x03, // CONNECT domain
            0x01, 0xFF, // invalid one-byte UTF-8 domain
            0x00, 0x50, // port 80
        ])
        .await
        .unwrap();

    let mut greeting = [0u8; 2];
    client_stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    let mut eof = [0u8; 1];
    let n = client_stream.read(&mut eof).await.unwrap();
    assert_eq!(n, 0, "invalid domain should close the SOCKS5 session");

    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("handle_socks5 task did not finish in time")
        .expect("handle_socks5 task panicked");
}

#[tokio::test]
async fn socks5_rejects_invalid_utf8_auth_credentials() {
    let (server_stream, mut client_stream) = loopback_pair().await;
    let tunnel = direct_tunnel();
    let server_addr: SocketAddr = "192.0.2.10:12345".parse().unwrap();
    let mut credentials = HashMap::new();
    credentials.insert(String::new(), String::new());
    let auth = AuthConfig::new(Arc::new(Credentials::new(credentials)), Vec::new());
    let handle = tokio::spawn(async move {
        meow_listener::socks5::handle_socks5(
            &tunnel,
            server_stream,
            server_addr,
            None,
            Some(&auth),
            "test",
            0,
            None,
            None,
        )
        .await;
    });

    client_stream
        .write_all(&[
            0x05, 0x01, 0x02, // greeting: username/password auth
            0x01, // auth sub-negotiation version
            0x01, 0xFF, // invalid one-byte UTF-8 username
            0x00, // empty password
        ])
        .await
        .unwrap();

    let mut method_reply = [0u8; 2];
    client_stream.read_exact(&mut method_reply).await.unwrap();
    assert_eq!(method_reply, [0x05, 0x02]);

    let mut auth_reply = [0u8; 2];
    client_stream.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [0x01, 0x01]);

    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("handle_socks5 task did not finish in time")
        .expect("handle_socks5 task panicked");
}
