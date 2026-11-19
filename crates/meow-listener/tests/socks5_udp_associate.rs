//! Integration test: SOCKS5 inbound UDP ASSOCIATE round-trip.
//!
//!   client ──SOCKS5 UDP ASSOCIATE──► handle_socks5 ──DIRECT──► UDP echo server
//!
//! Drives the full `handle_socks5` UDP path: handshake → associate reply → a
//! wrapped datagram is relayed to a real UDP echo server and the echoed reply
//! flows back (unwrapped) to the client.
#![cfg(feature = "listener-socks5")]

mod common;

use common::direct_tunnel;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

/// Spawn a UDP echo server: echoes each datagram back to its sender.
async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            if sock.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// Wrap `data` for `target` in a SOCKS5 UDP request header (IPv4).
fn wrap(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("ipv4 only in test");
    };
    let mut v = vec![0, 0, 0, 0x01]; // RSV(2) FRAG(1) ATYP=v4
    v.extend_from_slice(&ip.octets());
    v.extend_from_slice(&target.port().to_be_bytes());
    v.extend_from_slice(data);
    v
}

/// Parse a SOCKS5 UDP reply (IPv4) → (src, data).
fn unwrap_reply(buf: &[u8]) -> (SocketAddr, &[u8]) {
    assert_eq!(buf[2], 0, "FRAG must be 0");
    assert_eq!(buf[3], 0x01, "expected v4 reply");
    let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    let port = u16::from_be_bytes([buf[8], buf[9]]);
    (SocketAddr::from((ip, port)), &buf[10..])
}

#[tokio::test]
async fn socks5_udp_associate_relays_to_echo_server() {
    let echo_addr = spawn_udp_echo().await;

    // Loopback TCP pair feeding handle_socks5.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ctrl_addr = listener.local_addr().unwrap();
    let (accept_res, connect_res) = tokio::join!(listener.accept(), TcpStream::connect(ctrl_addr));
    let (server_stream, client_peer) = accept_res.unwrap();
    let mut client = connect_res.unwrap();

    let tunnel = direct_tunnel();
    tokio::spawn(async move {
        meow_listener::socks5::handle_socks5(
            &tunnel,
            server_stream,
            client_peer,
            None,
            None,
            "socks-in",
            ctrl_addr.port(),
            None,
            None,
        )
        .await;
    });

    // Handshake: greeting → NoAuth.
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet = [0u8; 2];
    client.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [0x05, 0x00]);

    // UDP ASSOCIATE request (advertised source 0.0.0.0:0).
    client
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    // Reply: VER REP RSV ATYP(v4) BND.ADDR(4) BND.PORT(2).
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "associate must succeed");
    let relay = SocketAddr::from((
        std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));

    // Send a wrapped datagram targeting the echo server.
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(&wrap(echo_addr, b"ping"), relay).await.unwrap();

    // Receive the echoed reply, unwrap, and verify.
    let mut rbuf = [0u8; 2048];
    let (n, _from) = timeout(Duration::from_secs(2), udp.recv_from(&mut rbuf))
        .await
        .expect("relay reply timed out")
        .unwrap();
    let (src, data) = unwrap_reply(&rbuf[..n]);
    assert_eq!(data, b"ping");
    assert_eq!(src, echo_addr, "reply source must be the echo server");

    // Keep `client` alive until here so the association stays open.
    drop(client);
}
