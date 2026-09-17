#![cfg(feature = "trojan")]
//! Integration tests for the Trojan adapter.
//!
//! Uses an embedded mock Trojan server with a self-signed certificate.
//! No external binaries required.

use meow_common::{MeowError, Metadata, Network, ProxyAdapter};
use meow_proxy::TrojanAdapter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

const TROJAN_PASSWORD: &str = "test-trojan-password";
const TIMEOUT: Duration = Duration::from_secs(10);

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed cert for "localhost" using rcgen.
fn generate_self_signed_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
    );
    (cert_der, key_der)
}

/// Start a TCP echo server.
async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, handle)
}

/// Compute Trojan hex password (SHA-224).
fn trojan_hex_password(password: &str) -> String {
    use sha2::{Digest, Sha224};
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

/// Read a SOCKS5-style address from a reader.
async fn read_socks5_addr<R: AsyncReadExt + Unpin>(reader: &mut R) -> SocketAddr {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await.unwrap();
    match atyp[0] {
        0x01 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await.unwrap();
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.unwrap();
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await.unwrap();
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.unwrap();
            SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes(port),
            )
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await.unwrap();
            let mut domain = vec![0u8; len[0] as usize];
            reader.read_exact(&mut domain).await.unwrap();
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.unwrap();
            let domain_str = String::from_utf8_lossy(&domain);
            let ip = if domain_str == "localhost" {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                panic!("mock server cannot resolve domain: {domain_str}");
            };
            SocketAddr::new(ip, u16::from_be_bytes(port))
        }
        _ => panic!("unknown ATYP: {}", atyp[0]),
    }
}

/// Start a mock Trojan server with self-signed TLS.
///
/// Handles CMD=0x01 (TCP CONNECT) by relaying to the target address.
async fn start_mock_trojan_server(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_hex = trojan_hex_password(TROJAN_PASSWORD);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let expected_hex = expected_hex.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    eprintln!("mock trojan: TLS accept error");
                    return;
                };

                // Read Trojan header: 56-byte hex password
                let mut password_buf = [0u8; 56];
                tls.read_exact(&mut password_buf).await.unwrap();
                let received_hex = String::from_utf8_lossy(&password_buf);
                assert_eq!(received_hex.as_ref(), expected_hex.as_str());

                // CRLF
                let mut crlf = [0u8; 2];
                tls.read_exact(&mut crlf).await.unwrap();
                assert_eq!(&crlf, b"\r\n");

                // CMD
                let mut cmd = [0u8; 1];
                tls.read_exact(&mut cmd).await.unwrap();

                // Target address
                let target_addr = read_socks5_addr(&mut tls).await;

                // Trailing CRLF
                let mut crlf2 = [0u8; 2];
                tls.read_exact(&mut crlf2).await.unwrap();
                assert_eq!(&crlf2, b"\r\n");

                match cmd[0] {
                    0x01 => {
                        // TCP relay
                        let mut target = TcpStream::connect(target_addr).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut tls, &mut target).await;
                    }
                    0x03 => {
                        // UDP_ASSOCIATE: pump per-packet frames in both
                        // directions over the TLS stream.  `target_addr` from
                        // the request header is informational; each datagram
                        // names its own destination.
                        run_mock_udp_associate(tls).await;
                    }
                    other => {
                        eprintln!("mock trojan: unsupported cmd: {other}");
                    }
                }
            });
        }
    });

    (addr, handle)
}

/// Read one SOCKS5 address surfacing IO errors cleanly (the TCP-test
/// `read_socks5_addr` helper above panics, which is fine inside a steady
/// stream but noisy when the UDP-relay test tears down the TLS pipe).
async fn try_read_socks5_addr<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await?;
    match atyp[0] {
        0x01 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await?;
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip)),
                u16::from_be_bytes(port),
            ))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await?;
            Ok(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes(port),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            reader.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await?;
            // Best-effort: parse domain as IP literal; otherwise use UNSPEC.
            let s = String::from_utf8_lossy(&domain);
            let ip: IpAddr = s.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
        }
        other => Err(std::io::Error::other(format!("unknown ATYP {other:#x}"))),
    }
}

/// Read one Trojan UDP frame
/// (`ATYP | ADDR | PORT | LEN(u16 BE) | CRLF | PAYLOAD`) from the TLS stream
/// and return the decoded destination plus the payload bytes.
async fn read_trojan_udp_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(SocketAddr, Vec<u8>)> {
    let addr = try_read_socks5_addr(reader).await?;
    let mut len_bytes = [0u8; 2];
    reader.read_exact(&mut len_bytes).await?;
    let length = u16::from_be_bytes(len_bytes) as usize;
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;
    if &crlf != b"\r\n" {
        return Err(std::io::Error::other("trojan udp: missing CRLF"));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    Ok((addr, payload))
}

/// Write one Trojan UDP frame to the TLS stream.
async fn write_trojan_udp_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    addr: SocketAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 23);
    match addr.ip() {
        IpAddr::V4(v4) => {
            frame.push(0x01);
            frame.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            frame.push(0x04);
            frame.extend_from_slice(&v6.octets());
        }
    }
    frame.extend_from_slice(&addr.port().to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await?;
    writer.flush().await
}

/// Mock UDP_ASSOCIATE handler:
///   * Reads framed UDP packets from the TLS stream.
///   * Forwards each payload to the destination over a real UDP socket
///     (single shared socket, like a Trojan server's "back end").
///   * Echoes any inbound UDP datagrams back over the TLS stream framed with
///     the source address.
async fn run_mock_udp_associate<S>(tls: S)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut tls_r, mut tls_w) = tokio::io::split(tls);
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    // tls -> udp: forward each frame to its named destination.
    let udp_send = Arc::clone(&udp);
    let send_task = tokio::spawn(async move {
        while let Ok((addr, payload)) = read_trojan_udp_frame(&mut tls_r).await {
            if udp_send.send_to(&payload, addr).await.is_err() {
                break;
            }
        }
    });

    // udp -> tls: every reply is wrapped back into a frame.
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                break;
            };
            if write_trojan_udp_frame(&mut tls_w, peer, &buf[..n])
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let _ = send_task.await;
    recv_task.abort();
}

#[tokio::test]
async fn test_trojan_tcp_relay() {
    install_crypto_provider();

    // Generate self-signed cert
    let (cert_der, key_der) = generate_self_signed_cert();

    // Start echo server and mock trojan server
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let (trojan_addr, _trojan_handle) = start_mock_trojan_server(cert_der, key_der).await;

    // Create adapter with skip_verify=true
    let adapter = TrojanAdapter::new(
        "test-trojan",
        "127.0.0.1",
        trojan_addr.port(),
        TROJAN_PASSWORD,
        "localhost", // SNI
        true,        // skip_verify
        false,       // udp
        std::sync::Arc::new(meow_proxy::dialer::DirectDialer),
    );

    // Build metadata pointing to the echo server
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial TCP through the Trojan proxy
    let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
    let mut conn = result
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Write and read back
    let payload = b"hello trojan tcp";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");

    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch");

    // Second round
    let payload2 = b"second trojan message";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");

    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(&buf2, payload2, "TCP echo mismatch round 2");
}

#[tokio::test]
async fn test_trojan_tcp_large_payload() {
    install_crypto_provider();

    let (cert_der, key_der) = generate_self_signed_cert();
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let (trojan_addr, _trojan_handle) = start_mock_trojan_server(cert_der, key_der).await;

    let adapter = TrojanAdapter::new(
        "test-trojan",
        "127.0.0.1",
        trojan_addr.port(),
        TROJAN_PASSWORD,
        "localhost",
        true,
        false,
        std::sync::Arc::new(meow_proxy::dialer::DirectDialer),
    );

    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
    let mut conn = result
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Send a larger payload (64KB)
    let payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    conn.write_all(&payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");

    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(buf, payload, "large payload echo mismatch");
}

// ─── UDP relay tests ─────────────────────────────────────────────────────────

/// UDP echo server: every datagram bounces back to its sender.
async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            if socket.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    (addr, handle)
}

#[tokio::test]
async fn test_trojan_udp_echo() {
    install_crypto_provider();

    let (cert_der, key_der) = generate_self_signed_cert();
    let (echo_addr, _echo_handle) = start_udp_echo_server().await;
    let (trojan_addr, _trojan_handle) = start_mock_trojan_server(cert_der, key_der).await;

    // udp=true so dial_udp succeeds.
    let adapter = TrojanAdapter::new(
        "test-trojan-udp",
        "127.0.0.1",
        trojan_addr.port(),
        TROJAN_PASSWORD,
        "localhost",
        true,
        true,
        std::sync::Arc::new(meow_proxy::dialer::DirectDialer),
    );

    // The CMD=0x03 header carries a placeholder destination (the echo server),
    // but every actual datagram below targets `echo_addr` independently.
    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let pc = timeout(TIMEOUT, adapter.dial_udp(&metadata))
        .await
        .expect("UDP dial timed out")
        .expect("UDP dial failed");

    // Round-trip a few packets.
    let payloads: [&[u8]; 3] = [
        b"hello trojan udp",
        b"second packet",
        b"third packet with a slightly longer payload to test framing",
    ];

    for p in &payloads {
        let n = timeout(TIMEOUT, pc.write_packet(p, &echo_addr))
            .await
            .expect("write_packet timed out")
            .expect("write_packet failed");
        assert_eq!(n, p.len());

        let mut buf = vec![0u8; 4096];
        let (n, from) = timeout(TIMEOUT, pc.read_packet(&mut buf))
            .await
            .expect("read_packet timed out")
            .expect("read_packet failed");
        assert_eq!(&buf[..n], *p, "UDP echo payload mismatch");
        // The mock server echoes the *peer* address (the UDP echo server's
        // local address), so the port must match.  IP may be 127.0.0.1 or
        // the literal 0.0.0.0 placeholder on some platforms, so check port.
        assert_eq!(from.port(), echo_addr.port(), "UDP echo source port");
    }
}

#[tokio::test]
async fn test_trojan_udp_multi_destination() {
    install_crypto_provider();

    let (cert_der, key_der) = generate_self_signed_cert();
    let (echo_a, _ha) = start_udp_echo_server().await;
    let (echo_b, _hb) = start_udp_echo_server().await;
    let (trojan_addr, _trojan_handle) = start_mock_trojan_server(cert_der, key_der).await;

    let adapter = TrojanAdapter::new(
        "test-trojan-udp-multi",
        "127.0.0.1",
        trojan_addr.port(),
        TROJAN_PASSWORD,
        "localhost",
        true,
        true,
        std::sync::Arc::new(meow_proxy::dialer::DirectDialer),
    );

    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_a.port(),
        ..Default::default()
    };

    let pc = timeout(TIMEOUT, adapter.dial_udp(&metadata))
        .await
        .expect("UDP dial timed out")
        .expect("UDP dial failed");

    // Send to A and B over the same packet conn; the server must route each
    // datagram to its individual destination.
    pc.write_packet(b"to-a", &echo_a).await.unwrap();
    pc.write_packet(b"to-b", &echo_b).await.unwrap();

    // Both echoes should come back; order is not guaranteed.
    let mut got = Vec::new();
    for _ in 0..2 {
        let mut buf = vec![0u8; 1024];
        let (n, from) = timeout(TIMEOUT, pc.read_packet(&mut buf))
            .await
            .expect("read_packet timed out")
            .expect("read_packet failed");
        got.push((from.port(), buf[..n].to_vec()));
    }
    let expect_a = (echo_a.port(), b"to-a".to_vec());
    let expect_b = (echo_b.port(), b"to-b".to_vec());
    assert!(
        got.contains(&expect_a) && got.contains(&expect_b),
        "expected echoes from both servers, got {got:?}"
    );
}

#[tokio::test]
async fn test_trojan_udp_disabled_returns_not_supported() {
    install_crypto_provider();

    // udp=false → dial_udp must reject without opening a TLS connection.
    let adapter = TrojanAdapter::new(
        "test-trojan-noudp",
        "127.0.0.1",
        1, // unreachable port — proves we never tried to dial
        TROJAN_PASSWORD,
        "localhost",
        true,
        false,
        std::sync::Arc::new(meow_proxy::dialer::DirectDialer),
    );

    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: 53,
        ..Default::default()
    };

    match adapter.dial_udp(&metadata).await {
        Ok(_) => panic!("dial_udp should fail when udp is disabled"),
        Err(MeowError::NotSupported(_)) => {}
        Err(other) => panic!("expected NotSupported, got {other:?}"),
    }
}

/// Issue #570 — `connect_over` must run the adapter's own TLS layer plus the
/// Trojan password/CONNECT header on the caller-supplied stream. The mock
/// terminates TLS (`acceptor.accept`), so a plaintext Trojan header would
/// fail the handshake outright.
#[tokio::test]
async fn test_trojan_connect_over_runs_tls_and_handshake() {
    install_crypto_provider();

    let (cert_der, key_der) = generate_self_signed_cert();
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let (trojan_addr, _trojan_handle) = start_mock_trojan_server(cert_der, key_der).await;

    let adapter = TrojanAdapter::new(
        "test-trojan-relay",
        "127.0.0.1",
        trojan_addr.port(),
        TROJAN_PASSWORD,
        "localhost",
        true,
        false,
        std::sync::Arc::new(meow_proxy::dialer::DirectDialer),
    );

    // Relay hop-0 leg: plain TCP already connected to the Trojan server.
    let upstream = TcpStream::connect(trojan_addr).await.unwrap();
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(TIMEOUT, adapter.connect_over(Box::new(upstream), &metadata))
        .await
        .expect("connect_over timed out")
        .expect("connect_over failed");

    let payload = b"trojan over relay-supplied stream";
    conn.write_all(payload).await.expect("write failed");
    conn.flush().await.expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.expect("read_exact failed");
    assert_eq!(&buf, payload, "echo mismatch through connect_over");
}
