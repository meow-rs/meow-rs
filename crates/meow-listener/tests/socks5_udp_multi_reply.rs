//! Repro for issue: meow's SOCKS5 UDP relay returns at most one server→client
//! datagram per session, stalling QUIC handshakes (server first flight is ~3).
//!
//! A UDP server replies to ONE client datagram with THREE distinct datagrams;
//! we assert all three are relayed back through meow's UDP ASSOCIATE path.
#![cfg(feature = "listener-socks5")]

mod common;

use common::direct_tunnel;
use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

/// UDP server: on the first datagram from a peer, send back 3 distinct replies.
async fn spawn_udp_three_reply() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (_n, peer) = sock.recv_from(&mut buf).await.unwrap();
        for i in 0u8..3 {
            let _ = sock.send_to(&[b'R', i], peer).await;
        }
        // keep socket alive a moment
        tokio::time::sleep(Duration::from_millis(500)).await;
    });
    addr
}

fn wrap(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("ipv4 only");
    };
    let mut v = vec![0, 0, 0, 0x01];
    v.extend_from_slice(&ip.octets());
    v.extend_from_slice(&target.port().to_be_bytes());
    v.extend_from_slice(data);
    v
}

fn payload(buf: &[u8]) -> Vec<u8> {
    // RSV(2) FRAG(1) ATYP(1) + v4(4) + port(2) = 10-byte header
    buf[10..].to_vec()
}

#[tokio::test]
async fn relay_returns_full_server_first_flight() {
    let server = spawn_udp_three_reply().await;

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
            "in",
            ctrl_addr.port(),
            None,
            None,
        )
        .await;
    });

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut g = [0u8; 2];
    client.read_exact(&mut g).await.unwrap();
    client
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut rep = [0u8; 10];
    client.read_exact(&mut rep).await.unwrap();
    let relay = SocketAddr::from((
        std::net::Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]),
        u16::from_be_bytes([rep[8], rep[9]]),
    ));

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(&wrap(server, b"hello"), relay).await.unwrap();

    // Collect replies for up to 2s.
    let mut got: HashSet<Vec<u8>> = HashSet::new();
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while got.len() < 3 && tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(400), udp.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                got.insert(payload(&buf[..n]));
            }
            _ => break,
        }
    }

    assert_eq!(
        got.len(),
        3,
        "meow relayed {} of 3 server reply datagrams (QUIC first flight stalls if <3)",
        got.len()
    );
}
