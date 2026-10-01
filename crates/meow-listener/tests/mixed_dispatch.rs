//! Integration test: MixedListener dispatches connections by first byte.
//!
//! `MixedListener` peeks the first byte to decide protocol:
//!   0x05  → SOCKS5 handler
//!   other → HTTP proxy handler
//!
//! This test spins up a real `MixedListener` and sends two connections to it —
//! one using a SOCKS5 greeting and one using an HTTP CONNECT — and asserts each
//! routes to the correct handler (identified by the response format).
#![cfg(feature = "listener-mixed")]

mod common;

use common::{direct_tunnel, spawn_echo_server};
use meow_listener::MixedListener;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Start a `MixedListener` on an OS-assigned port and return the port number.
/// The listener runs in a background task for the duration of the test.
async fn start_mixed_listener(echo_addr: std::net::SocketAddr) -> u16 {
    // We need the tunnel to route DIRECT to the echo server.  Both the SOCKS5
    // CONNECT and the HTTP CONNECT will target echo_addr explicitly, so
    // TunnelMode::Direct is sufficient.
    let _ = echo_addr; // used via CONNECT request target, not tunnel config
                       // Allocate an ephemeral port, then release it so MixedListener can bind it.
                       // Slight TOCTOU but acceptable in loopback tests.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let bind: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listener = MixedListener::new(direct_tunnel(), bind, "test-mixed".to_string());
    tokio::spawn(async move {
        let _ = listener.run().await;
    });

    // Poll until the listener actually accepts — the bind happens inside
    // the spawned task, so a fixed settle is a startup race (issue #641).
    // The deadline is a std Instant: it stays real-time even if this test
    // were ever switched to `start_paused`.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(bind)).await {
            Err(_) if std::time::Instant::now() >= deadline => {
                panic!("mixed listener never came up: connect timed out")
            }
            Err(_) => {}
            Ok(Ok(probe)) => {
                drop(probe);
                break;
            }
            Ok(Err(_)) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(Err(e)) => panic!("mixed listener never came up: {e}"),
        }
    }
    port
}

/// Build a SOCKS5 CONNECT greeting + request for an IPv4 target.
fn socks5_greeting_and_connect(target: std::net::SocketAddr) -> Vec<u8> {
    let std::net::IpAddr::V4(ip4) = target.ip() else {
        panic!("expected IPv4");
    };
    let mut buf = vec![0x05, 0x01, 0x00]; // greeting: version, nmethods, NoAuth
    buf.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]); // CONNECT, RSV, ATYP_IPV4
    buf.extend_from_slice(&ip4.octets());
    buf.extend_from_slice(&target.port().to_be_bytes());
    buf
}

#[tokio::test]
async fn mixed_socks5_byte_routes_to_socks5_handler() {
    let echo_addr = spawn_echo_server().await;
    let port = start_mixed_listener(echo_addr).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    // Send SOCKS5 greeting + CONNECT.
    let req = socks5_greeting_and_connect(echo_addr);
    stream.write_all(&req).await.unwrap();

    // Expect SOCKS5 greeting reply: 05 00
    let mut greet_reply = [0u8; 2];
    stream.read_exact(&mut greet_reply).await.unwrap();
    assert_eq!(
        greet_reply[0], 0x05,
        "first reply byte must be SOCKS5 version"
    );
    assert_eq!(greet_reply[1], 0x00, "NoAuth must be chosen");

    // Expect CONNECT success reply (10 bytes): 05 00 00 01 ...
    let mut conn_reply = [0u8; 10];
    stream.read_exact(&mut conn_reply).await.unwrap();
    assert_eq!(conn_reply[0], 0x05, "CONNECT reply version");
    assert_eq!(conn_reply[1], 0x00, "CONNECT REP_SUCCESS");

    // Tunnel is live — verify data flows.
    let probe = b"socks5-via-mixed";
    stream.write_all(probe).await.unwrap();
    let mut echo = vec![0u8; probe.len()];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(echo.as_slice(), probe);
}

#[tokio::test]
async fn mixed_http_first_byte_routes_to_http_handler() {
    let echo_addr = spawn_echo_server().await;
    let port = start_mixed_listener(echo_addr).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    // First byte is 'C' (0x43) — starts "CONNECT", which is NOT 0x05, so the
    // mixed listener routes to the HTTP handler.
    let request = format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    // Read until \r\n\r\n — expect "200 Connection established".
    let mut resp = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.unwrap();
        resp.push(byte[0]);
        if resp.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(resp.len() < 4096, "response headers > 4 KiB");
    }
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.contains("200"),
        "expected HTTP 200, got: {resp_str}"
    );

    // Tunnel is live — verify data flows.
    let probe = b"http-via-mixed";
    stream.write_all(probe).await.unwrap();
    let mut echo = vec![0u8; probe.len()];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(echo.as_slice(), probe);
}
