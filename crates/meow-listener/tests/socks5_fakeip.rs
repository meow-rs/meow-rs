//! Regression test: a SOCKS5 CONNECT to a fake IP must be reverse-mapped to
//! its hostname before dialing.
//!
//! On iOS the tun2socks bridge forwards captured TCP flows to the local SOCKS5
//! listener using the fake IP (28.x / 198.18.x) as the target — the only thing
//! it knows. `handle_socks5_inner` must call `pre_handle_metadata` to recover
//! the real hostname from the fake-IP reverse map before rule matching and
//! dialing; otherwise the flow dials the dead fake IP — or, since #618, is
//! dropped outright when no reverse mapping survives (and rule matching sees
//! the placeholder, so every fake-IP'd domain falls through to MATCH()/final).
//!
//! The fixture seeds the resolver cache so the recovered hostname resolves to a
//! local echo server. The echo round-trip succeeds only when the reverse-map
//! ran; without it the relay dials the fake IP and no bytes come back.
#![cfg(feature = "listener-socks5")]

mod common;

use common::{fakeip_tunnel, spawn_echo_server};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accept_res, connect_res) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    (accept_res.unwrap().0, connect_res.unwrap())
}

/// SOCKS5 greeting + CONNECT to an IPv4 target (RFC 1928).
fn socks5_connect_ipv4(target: SocketAddr) -> Vec<u8> {
    let std::net::IpAddr::V4(ip4) = target.ip() else {
        panic!("expected IPv4 target");
    };
    let mut buf = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01];
    buf.extend_from_slice(&ip4.octets());
    buf.extend_from_slice(&target.port().to_be_bytes());
    buf
}

#[tokio::test]
async fn socks5_connect_to_fake_ip_reverse_maps_and_dials_real_host() {
    // Echo server is what "example.test" really resolves to.
    let echo_addr = spawn_echo_server().await;

    // Fake-IP tunnel: example.test → <fake>, and the cache maps it back to the
    // echo server's IP for the dial. Direct mode isolates the reverse-map step.
    let (tunnel, fake_ip) = fakeip_tunnel("example.test", echo_addr.ip()).await;
    assert_ne!(
        fake_ip,
        echo_addr.ip(),
        "fake IP must differ from the real target"
    );

    let (server_stream, mut client_stream) = loopback_pair().await;
    let listener_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let handle = tokio::spawn(async move {
        meow_listener::socks5::handle_socks5(
            &tunnel,
            server_stream,
            listener_addr,
            None, // no sniffer — force the reverse-map path, not SNI/Host recovery
            None, // no auth
            "test",
            0,
            None,
            None,
        )
        .await;
    });

    // CONNECT to the FAKE IP, but the echo server's port. The listener must
    // recover example.test and dial echo_addr.ip():port.
    let target = SocketAddr::new(fake_ip, echo_addr.port());
    client_stream
        .write_all(&socks5_connect_ipv4(target))
        .await
        .unwrap();

    let mut reply = [0u8; 12];
    client_stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05, "greeting reply version");
    assert_eq!(reply[1], 0x00, "NoAuth chosen");
    assert_eq!(reply[3], 0x00, "CONNECT must succeed (REP_SUCCESS)");

    // The relay is up only if the dial reached the echo server. Without the
    // reverse-map the flow would have been dropped (pre-#618: dialed the
    // dead fake IP) and this round-trip would hang or fail outright.
    let probe = b"fakeip-revmap";
    client_stream.write_all(probe).await.unwrap();
    let mut echo_buf = [0u8; 13];
    tokio::time::timeout(
        Duration::from_secs(2),
        client_stream.read_exact(&mut echo_buf),
    )
    .await
    .expect("echo timed out — fake IP was not reverse-mapped to the real host")
    .expect("echo read failed");
    assert_eq!(
        &echo_buf, probe,
        "relay did not forward bytes to echo server"
    );

    drop(client_stream);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}
