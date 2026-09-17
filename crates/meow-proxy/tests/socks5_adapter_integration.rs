//! Integration tests for the outbound SOCKS5 adapter.
//!
//! Embedded SOCKS5 server (RFC 1928 + RFC 1929 username/password) on
//! `127.0.0.1:0` that speaks only the TCP CONNECT subset the adapter exercises.
//! No TLS — the adapter's TLS-wrap branch is covered by source-level units.

use meow_common::{ConnType, MeowError, Metadata, Network, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::Socks5Adapter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const TIMEOUT: Duration = Duration::from_secs(10);

async fn start_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, h)
}

#[derive(Clone, Copy)]
enum AuthPolicy {
    None,
    UserPass(&'static str, &'static str),
}

async fn start_socks5(policy: AuthPolicy) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        loop {
            let Ok((client, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                if let Err(e) = serve_socks5(client, policy).await {
                    eprintln!("mock-socks5: {e}");
                }
            });
        }
    });
    (addr, h)
}

async fn serve_socks5<S>(mut client: S, policy: AuthPolicy) -> std::io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // ── Method negotiation ──
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Ok(());
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    let want = match policy {
        AuthPolicy::None => 0x00,
        AuthPolicy::UserPass(..) => 0x02,
    };
    if !methods.contains(&want) {
        client.write_all(&[0x05, 0xff]).await?; // no acceptable method
        return Ok(());
    }
    client.write_all(&[0x05, want]).await?;

    // ── Sub-negotiation if password auth was chosen ──
    if let AuthPolicy::UserPass(eu, ep) = policy {
        let mut sub = [0u8; 2];
        client.read_exact(&mut sub).await?;
        if sub[0] != 0x01 {
            return Ok(());
        }
        let ulen = sub[1] as usize;
        let mut user = vec![0u8; ulen];
        client.read_exact(&mut user).await?;
        let mut plen_b = [0u8; 1];
        client.read_exact(&mut plen_b).await?;
        let plen = plen_b[0] as usize;
        let mut pass = vec![0u8; plen];
        client.read_exact(&mut pass).await?;

        let ok = user == eu.as_bytes() && pass == ep.as_bytes();
        client
            .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
            .await?;
        if !ok {
            return Ok(());
        }
    }

    // ── CONNECT request ──
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        // Reply COMMAND_NOT_SUPPORTED.
        client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }
    let target = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p).await?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), u16::from_be_bytes(p)).to_string()
        }
        0x03 => {
            let mut n = [0u8; 1];
            client.read_exact(&mut n).await?;
            let mut host = vec![0u8; n[0] as usize];
            client.read_exact(&mut host).await?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p).await?;
            format!(
                "{}:{}",
                std::str::from_utf8(&host).unwrap_or(""),
                u16::from_be_bytes(p)
            )
        }
        0x04 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p).await?;
            SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(a)),
                u16::from_be_bytes(p),
            )
            .to_string()
        }
        _ => {
            client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };

    // ── Dial upstream and splice ──
    let Ok(mut upstream) = TcpStream::connect(&target).await else {
        // Connection refused / host unreachable.
        client
            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    };

    // Reply success with BIND.ADDR = 0.0.0.0:0 (RFC 1928 §6: "implementation
    // dependent" — the client typically ignores BIND.ADDR for CONNECT).
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

fn metadata_for(target: SocketAddr) -> Metadata {
    Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        dst_ip: Some(target.ip()),
        host: target.ip().to_string().into(),
        dst_port: target.port(),
        ..Default::default()
    }
}

fn metadata_for_host(host: &str, port: u16) -> Metadata {
    Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        dst_ip: None,
        host: host.into(),
        dst_port: port,
        ..Default::default()
    }
}

#[tokio::test]
async fn no_auth_tunnel_round_trips_through_echo() {
    let (echo, _e) = start_echo().await;
    let (s5, _h) = start_socks5(AuthPolicy::None).await;
    let adapter = Socks5Adapter::new(
        "p",
        "127.0.0.1",
        s5.port(),
        None,
        false,
        false,
        Arc::new(DirectDialer),
    );
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(echo)))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");
    conn.write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    timeout(TIMEOUT, conn.read_exact(&mut got))
        .await
        .expect("read timed out")
        .expect("echo");
    assert_eq!(&got, b"hello");
}

#[tokio::test]
async fn correct_userpass_succeeds_and_tunnels() {
    let (echo, _e) = start_echo().await;
    let (s5, _h) = start_socks5(AuthPolicy::UserPass("alice", "p@ss")).await;
    let adapter = Socks5Adapter::new(
        "p",
        "127.0.0.1",
        s5.port(),
        Some(("alice".into(), "p@ss".into())),
        false,
        false,
        Arc::new(DirectDialer),
    );
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(echo)))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");
    conn.write_all(b"world").await.unwrap();
    let mut got = [0u8; 5];
    timeout(TIMEOUT, conn.read_exact(&mut got))
        .await
        .expect("read timed out")
        .expect("echo");
    assert_eq!(&got, b"world");
}

#[tokio::test]
async fn wrong_password_fails_with_proxy_auth_failed() {
    let (echo, _e) = start_echo().await;
    let (s5, _h) = start_socks5(AuthPolicy::UserPass("alice", "right")).await;
    let adapter = Socks5Adapter::new(
        "p",
        "127.0.0.1",
        s5.port(),
        Some(("alice".into(), "wrong".into())),
        false,
        false,
        Arc::new(DirectDialer),
    );
    let err = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(echo)))
        .await
        .expect("dial timed out")
        .err()
        .expect("must reject");
    assert!(
        matches!(err, MeowError::ProxyAuthFailed),
        "expected ProxyAuthFailed, got {err:?}"
    );
}

#[tokio::test]
async fn missing_auth_to_authed_server_fails() {
    // Server requires user/pass; adapter offers none → server returns 0xff
    // (no acceptable method). Adapter must surface an error, not hang or
    // succeed.
    let (echo, _e) = start_echo().await;
    let (s5, _h) = start_socks5(AuthPolicy::UserPass("alice", "p")).await;
    let adapter = Socks5Adapter::new(
        "p",
        "127.0.0.1",
        s5.port(),
        None,
        false,
        false,
        Arc::new(DirectDialer),
    );
    let res = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(echo)))
        .await
        .expect("dial timed out");
    assert!(res.is_err(), "dial must fail when methods rejected");
}

#[tokio::test]
async fn unreachable_target_surfaces_proxy_error() {
    // Server can speak SOCKS5 but the target it tries to dial is closed →
    // SOCKS5 reply rep=0x05 (connection refused). Adapter must not return Ok.
    let (s5, _h) = start_socks5(AuthPolicy::None).await;
    let adapter = Socks5Adapter::new(
        "p",
        "127.0.0.1",
        s5.port(),
        None,
        false,
        false,
        Arc::new(DirectDialer),
    );
    // High port nothing listens on (claim+drop trick).
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), p)
    };
    let res = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(dead)))
        .await
        .expect("dial timed out");
    assert!(res.is_err(), "dial must fail when target unreachable");
}

#[tokio::test]
async fn hostname_atyp_03_is_sent_when_dst_ip_absent() {
    // When metadata has a hostname but no resolved IP, the adapter must send
    // ATYP=0x03 (domain name). Our embedded server resolves the hostname
    // ("localhost") itself.
    let (echo, _e) = start_echo().await;
    let (s5, _h) = start_socks5(AuthPolicy::None).await;
    let adapter = Socks5Adapter::new(
        "p",
        "127.0.0.1",
        s5.port(),
        None,
        false,
        false,
        Arc::new(DirectDialer),
    );
    let mut conn = timeout(
        TIMEOUT,
        adapter.dial_tcp(&metadata_for_host("localhost", echo.port())),
    )
    .await
    .expect("dial timed out")
    .expect("dial_tcp");
    conn.write_all(b"via-hostname").await.unwrap();
    let mut got = [0u8; 12];
    timeout(TIMEOUT, conn.read_exact(&mut got))
        .await
        .expect("read timed out")
        .expect("echo");
    assert_eq!(&got, b"via-hostname");
}

// ─── Issue #570: relay-chain final hop (connect_over) ───────────────────────

/// Plain `connect_over`: auth negotiation + CONNECT run on the supplied stream.
#[tokio::test]
async fn connect_over_plain_runs_socks5_handshake() {
    let (echo, _e) = start_echo().await;
    let (s5, _h) = start_socks5(AuthPolicy::None).await;
    let adapter = Socks5Adapter::new(
        "test-s5-co",
        &s5.ip().to_string(),
        s5.port(),
        None,
        false,
        false,
        Arc::new(DirectDialer),
    );

    let upstream = TcpStream::connect(s5).await.expect("upstream connect");
    let mut conn = timeout(
        TIMEOUT,
        adapter.connect_over(Box::new(upstream), &metadata_for(echo)),
    )
    .await
    .expect("connect_over timed out")
    .expect("connect_over failed");

    let payload = b"socks5 connect_over round-trip";
    conn.write_all(payload).await.expect("write failed");
    conn.flush().await.expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.expect("read_exact failed");
    assert_eq!(&buf, payload, "echo mismatch through connect_over");
}

/// `tls: true` `connect_over`: the adapter must wrap the supplied stream in
/// TLS *before* SOCKS5 negotiation — the mock terminates TLS via rustls, so
/// plaintext greeting bytes would fail the TLS handshake outright. This is
/// the regression test for the pre-fix behaviour that skipped the TLS layer.
#[tokio::test]
async fn connect_over_tls_wraps_supplied_stream() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
    );
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let (echo, _e) = start_echo().await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s5 = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    eprintln!("tls-socks5: TLS accept failed — plaintext greeting?");
                    return;
                };
                if let Err(e) = serve_socks5(tls, AuthPolicy::None).await {
                    eprintln!("tls-socks5: {e}");
                }
            });
        }
    });

    let adapter = Socks5Adapter::new(
        "test-s5-co-tls",
        "localhost", // SNI matches the self-signed cert SAN
        s5.port(),
        None,
        true, // tls
        true, // skip_cert_verify
        Arc::new(DirectDialer),
    );

    let upstream = TcpStream::connect(s5).await.expect("upstream connect");
    let mut conn = timeout(
        TIMEOUT,
        adapter.connect_over(Box::new(upstream), &metadata_for(echo)),
    )
    .await
    .expect("connect_over timed out")
    .expect("connect_over failed");

    let payload = b"socks5+tls connect_over round-trip";
    conn.write_all(payload).await.expect("write failed");
    conn.flush().await.expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.expect("read_exact failed");
    assert_eq!(&buf, payload, "echo mismatch through TLS connect_over");
}
