//! Integration tests for the outbound HTTP CONNECT adapter.
//!
//! Stands up an embedded HTTP/1.1 proxy on `127.0.0.1:0` that speaks the
//! minimum subset needed to validate the adapter: status-line + headers +
//! `\r\n\r\n`, Basic auth check, then dump bytes bidirectionally to the
//! target. No TLS — the adapter's TLS-wrap branch is covered separately by
//! the unit tests in `http_adapter.rs`.

use base64::Engine as _;
use meow_common::{ConnType, MeowError, Metadata, Network, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::HttpAdapter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const TIMEOUT: Duration = Duration::from_secs(10);

/// TCP echo server. Returns `(addr, JoinHandle)`.
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

/// Embedded HTTP/1.1 CONNECT proxy.
/// `expected_auth = Some(("u","p"))` requires Basic auth; `None` accepts any.
async fn start_proxy(
    expected_auth: Option<(&'static str, &'static str)>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        loop {
            let Ok((client, _)) = l.accept().await else {
                break;
            };
            let auth = expected_auth;
            tokio::spawn(async move {
                if let Err(e) = serve_connect(client, auth).await {
                    eprintln!("mock-proxy: {e}");
                }
            });
        }
    });
    (addr, h)
}

async fn serve_connect<S>(
    mut client: S,
    expected_auth: Option<(&'static str, &'static str)>,
) -> std::io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut reader = BufReader::new(&mut client);

    // First line: "CONNECT host:port HTTP/1.1"
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "CONNECT" {
        return reply(&mut client, "HTTP/1.1 400 Bad Request").await;
    }
    let target = parts[1].to_string();

    // Drain headers.
    let mut got_auth: Option<String> = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(rest) = line.to_lowercase().strip_prefix("proxy-authorization:") {
            got_auth = Some(rest.trim().to_string());
        }
    }

    if let Some((u, p)) = expected_auth {
        let expected = format!(
            "basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        );
        match got_auth {
            Some(got) if got.eq_ignore_ascii_case(&expected) => {}
            _ => return reply(&mut client, "HTTP/1.1 407 Proxy Authentication Required").await,
        }
    }

    // Resolve and dial the target. A failed dial → 502.
    let Ok(mut upstream) = TcpStream::connect(&target).await else {
        return reply(&mut client, "HTTP/1.1 502 Bad Gateway").await;
    };

    // Send 200 then splice bytes.
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

async fn reply<S>(client: &mut S, status_line: &str) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let body = format!("{status_line}\r\nContent-Length: 0\r\n\r\n");
    client.write_all(body.as_bytes()).await?;
    let _ = client.shutdown().await;
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

#[tokio::test]
async fn connect_no_auth_round_trips_payload_to_echo() {
    let (echo, _h_echo) = start_echo().await;
    let (proxy, _h_proxy) = start_proxy(None).await;
    let adapter = HttpAdapter::new(
        "p",
        "127.0.0.1",
        proxy.port(),
        None,
        false,
        false,
        vec![],
        Arc::new(DirectDialer),
    );

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(echo)))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");

    let payload = b"hello-from-test";
    conn.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    timeout(TIMEOUT, conn.read_exact(&mut got))
        .await
        .expect("read timed out")
        .expect("read echoed bytes");
    assert_eq!(&got, payload);
}

#[tokio::test]
async fn connect_with_correct_basic_auth_succeeds() {
    let (echo, _e) = start_echo().await;
    let (proxy, _p) = start_proxy(Some(("u", "secret"))).await;
    let adapter = HttpAdapter::new(
        "p",
        "127.0.0.1",
        proxy.port(),
        Some(("u".into(), "secret".into())),
        false,
        false,
        vec![],
        Arc::new(DirectDialer),
    );
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(echo)))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");
    conn.write_all(b"ok").await.unwrap();
    let mut got = [0u8; 2];
    timeout(TIMEOUT, conn.read_exact(&mut got))
        .await
        .expect("read timed out")
        .expect("echo");
    assert_eq!(&got, b"ok");
}

#[tokio::test]
async fn connect_with_wrong_password_returns_proxy_auth_failed() {
    let (echo, _e) = start_echo().await;
    let (proxy, _p) = start_proxy(Some(("u", "right"))).await;
    let adapter = HttpAdapter::new(
        "p",
        "127.0.0.1",
        proxy.port(),
        Some(("u".into(), "wrong".into())),
        false,
        false,
        vec![],
        Arc::new(DirectDialer),
    );
    let err = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(echo)))
        .await
        .expect("dial timed out")
        .err()
        .expect("must reject wrong password");
    assert!(
        matches!(err, MeowError::ProxyAuthFailed),
        "expected ProxyAuthFailed, got {err:?}"
    );
}

#[tokio::test]
async fn connect_with_missing_auth_header_when_required_returns_proxy_auth_failed() {
    let (echo, _e) = start_echo().await;
    let (proxy, _p) = start_proxy(Some(("u", "secret"))).await;
    // Adapter dialled WITHOUT credentials at all.
    let adapter = HttpAdapter::new(
        "p",
        "127.0.0.1",
        proxy.port(),
        None,
        false,
        false,
        vec![],
        Arc::new(DirectDialer),
    );
    let err = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(echo)))
        .await
        .expect("dial timed out")
        .err()
        .expect("must reject missing auth");
    assert!(
        matches!(err, MeowError::ProxyAuthFailed),
        "expected ProxyAuthFailed, got {err:?}"
    );
}

#[tokio::test]
async fn connect_to_unreachable_target_returns_http_connect_failed() {
    // Proxy will try to dial port 1 on a localhost address that nothing listens on
    // → respond 502. Adapter must surface that as `HttpConnectFailed(502)`.
    let (proxy, _p) = start_proxy(None).await;
    let adapter = HttpAdapter::new(
        "p",
        "127.0.0.1",
        proxy.port(),
        None,
        false,
        false,
        vec![],
        Arc::new(DirectDialer),
    );
    // Pick a SocketAddr the proxy can't reach (high random ephemeral whose
    // listener we never opened). Using IP literal so the adapter doesn't try
    // its own DNS.
    let dead_target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1);
    let err = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(dead_target)))
        .await
        .expect("dial timed out")
        .err()
        .expect("unreachable target must fail");
    match err {
        MeowError::HttpConnectFailed(code) => assert_eq!(code, 502),
        other => panic!("expected HttpConnectFailed(502), got {other:?}"),
    }
}

#[tokio::test]
async fn connect_extra_headers_are_sent_to_proxy() {
    // Stand up a custom one-shot proxy that captures the request headers,
    // then assert the adapter-supplied X-Test header appeared.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (echo, _e) = start_echo().await;
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut client, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        // Read until we see \r\n\r\n.
        let mut total = 0;
        while total < buf.len() {
            let n = client.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        buf.truncate(total);
        let req = String::from_utf8_lossy(&buf).to_string();
        let _ = tx.send(req);

        // Continue the tunnel so the dial succeeds.
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let upstream = TcpStream::connect(echo).await.unwrap();
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut cr, &mut uw).await;
        });
        let _ = tokio::io::copy(&mut ur, &mut cw).await;
    });

    let adapter = HttpAdapter::new(
        "p",
        "127.0.0.1",
        addr.port(),
        None,
        false,
        false,
        vec![("X-Test".into(), "abc123".into())],
        Arc::new(DirectDialer),
    );
    let _ = timeout(TIMEOUT, adapter.dial_tcp(&metadata_for(echo)))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");

    let req = timeout(TIMEOUT, rx)
        .await
        .expect("captured")
        .expect("oneshot");
    assert!(
        req.contains("X-Test: abc123"),
        "extra header missing from CONNECT request:\n{req}"
    );
    // Adapter must also send Host (RFC 7230 §5.4).
    assert!(
        req.lines().any(|l| l.to_lowercase().starts_with("host:")),
        "Host header missing from CONNECT request:\n{req}"
    );
}

// ─── Issue #570: relay-chain final hop (connect_over) ───────────────────────

/// Plain (no-TLS) `connect_over`: the adapter must send the CONNECT request
/// on the caller-supplied stream.
#[tokio::test]
async fn connect_over_plain_sends_connect_on_supplied_stream() {
    let (echo, _h_echo) = start_echo().await;
    let (proxy, _h_proxy) = start_proxy(None).await;

    let adapter = HttpAdapter::new(
        "test-http-co",
        &proxy.ip().to_string(),
        proxy.port(),
        None,
        false,
        false,
        vec![],
        Arc::new(DirectDialer),
    );

    let upstream = TcpStream::connect(proxy).await.expect("upstream connect");
    let mut conn = timeout(
        TIMEOUT,
        adapter.connect_over(Box::new(upstream), &metadata_for(echo)),
    )
    .await
    .expect("connect_over timed out")
    .expect("connect_over failed");

    let payload = b"http connect_over round-trip";
    conn.write_all(payload).await.expect("write failed");
    conn.flush().await.expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.expect("read_exact failed");
    assert_eq!(&buf, payload, "echo mismatch through connect_over");
}

/// `tls: true` `connect_over`: the adapter must wrap the supplied stream in
/// TLS *before* the CONNECT handshake — the mock terminates TLS via rustls,
/// so a plaintext CONNECT would fail the TLS handshake outright. This is the
/// regression test for the pre-fix behaviour that skipped the TLS layer.
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

    let (echo, _h_echo) = start_echo().await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    eprintln!("tls-proxy: TLS accept failed — plaintext CONNECT?");
                    return;
                };
                if let Err(e) = serve_connect(tls, None).await {
                    eprintln!("tls-proxy: {e}");
                }
            });
        }
    });

    let adapter = HttpAdapter::new(
        "test-http-co-tls",
        "localhost", // SNI matches the self-signed cert SAN
        proxy.port(),
        None,
        true, // tls
        true, // skip_cert_verify
        vec![],
        Arc::new(DirectDialer),
    );

    let upstream = TcpStream::connect(proxy).await.expect("upstream connect");
    let mut conn = timeout(
        TIMEOUT,
        adapter.connect_over(Box::new(upstream), &metadata_for(echo)),
    )
    .await
    .expect("connect_over timed out")
    .expect("connect_over failed");

    let payload = b"https connect_over round-trip";
    conn.write_all(payload).await.expect("write failed");
    conn.flush().await.expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.expect("read_exact failed");
    assert_eq!(&buf, payload, "echo mismatch through TLS connect_over");
}
