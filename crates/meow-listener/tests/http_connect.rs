//! Integration test: HTTP CONNECT handshake + relay through a local echo server.
//!
//! The test drives the full `handle_http` path:
//!   client ──HTTP CONNECT──► handle_http ──DIRECT dial──► echo server
//!
//! After the 200 response, data written by the client is relayed to the
//! echo server and echoed back, confirming the tunnel is live.
#![cfg(feature = "listener-http")]

mod common;

use common::{direct_tunnel, spawn_echo_server};
use std::net::SocketAddr;
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

#[tokio::test]
async fn http_connect_proxies_bytes_to_echo_server() {
    // 1. Start a local echo server.
    let echo_addr = spawn_echo_server().await;

    // 2. Build a real loopback pair.
    let (server_stream, mut client_stream) = loopback_pair().await;

    // 3. Run handle_http in a background task.
    let tunnel = direct_tunnel();
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let handle = tokio::spawn(async move {
        meow_listener::http_proxy::handle_http(
            &tunnel,
            server_stream,
            src,
            None, // no sniffer
            None, // no auth
            "test",
            0,
            None,
        )
        .await;
    });

    // 4. Send HTTP CONNECT targeting the echo server's IP:port.
    let request = format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n");
    client_stream.write_all(request.as_bytes()).await.unwrap();

    // 5. Read until we see the response status line ("200 Connection established").
    let mut response_buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        client_stream.read_exact(&mut byte).await.unwrap();
        response_buf.push(byte[0]);
        // Headers end at \r\n\r\n
        if response_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(response_buf.len() < 4096, "response headers exceeded 4 KiB");
    }
    let response_str = String::from_utf8_lossy(&response_buf);
    assert!(
        response_str.contains("200"),
        "expected 200 Connection established, got: {response_str}"
    );

    // 6. Tunnel is live — write probe bytes and read the echo.
    let probe = b"hello-http-connect";
    client_stream.write_all(probe).await.unwrap();
    let mut echo_buf = vec![0u8; probe.len()];
    client_stream.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(
        echo_buf.as_slice(),
        probe,
        "echo mismatch: relay did not forward bytes"
    );

    // 7. Close and wait for the relay task to finish.
    drop(client_stream);
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("handle_http task did not finish in time")
        .expect("handle_http task panicked");
}
