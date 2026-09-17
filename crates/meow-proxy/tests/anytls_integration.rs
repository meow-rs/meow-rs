#![cfg(feature = "anytls")]
//! Integration tests for the AnyTLS adapter against the upstream
//! `anytls-rs` server.
//!
//! No external binaries: the test spawns a real `anytls_rs::server::Server`
//! (its default `TcpProxyHandler` proxies streams to whatever destination
//! the client supplies in the first SOCKS5-style frame) and our adapter
//! dials through it to a local TCP echo server.

use std::net::SocketAddr;
use std::sync::Arc;

use anytls_rs::client::UDP_OVER_TCP_MAGIC_ADDR;
use anytls_rs::padding::PaddingFactory;
use anytls_rs::protocol::Command;
use anytls_rs::server::Server as AnytlsServer;
use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::AnytlsAdapter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

const PASSWORD: &str = "test-anytls-password";
const T: Duration = Duration::from_secs(15);

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn self_signed_cert() -> (
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

/// Local TCP echo server. Returns its bound `127.0.0.1:port`.
async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, h)
}

/// Start an upstream `anytls_rs::server::Server` on a free `127.0.0.1` port
/// using the supplied self-signed cert and the same password the adapter
/// will authenticate with. Returns the bound socket addr.
async fn start_anytls_server(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)));

    // Bind first so we can hand the bound port back before spawning the
    // server's accept loop.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // re-bound by Server::listen below

    let padding = PaddingFactory::default();
    let server = AnytlsServer::new(PASSWORD, acceptor, padding, None);
    let listen_addr = format!("127.0.0.1:{}", addr.port());
    let h = tokio::spawn(async move {
        let _ = server.listen(&listen_addr).await;
    });
    // Give the accept loop a beat to rebind.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, h)
}

#[tokio::test]
async fn anytls_round_trip_through_upstream_server() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    // Adapter points at our anytls server, with skip-cert-verify so it
    // accepts the self-signed cert.
    let adapter = AnytlsAdapter::new(
        "test-anytls",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::from(echo_addr.ip().to_string()),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(T, adapter.dial_tcp(&metadata))
        .await
        .expect("dial_tcp must not stall")
        .expect("dial_tcp must succeed end-to-end");

    let payload = b"meow<>anytls round-trip";
    timeout(T, conn.write_all(payload))
        .await
        .expect("write must not stall")
        .expect("write must succeed");
    timeout(T, conn.flush())
        .await
        .expect("flush must not stall")
        .expect("flush must succeed");

    let mut buf = vec![0u8; payload.len()];
    timeout(T, conn.read_exact(&mut buf))
        .await
        .expect("echo must not stall")
        .expect("echo must succeed");
    assert_eq!(&buf[..], payload, "echo payload must match what we wrote");
}

#[tokio::test]
async fn anytls_ip_only_destination_round_trips() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;
    let adapter = AnytlsAdapter::new(
        "test-anytls-ip-only",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    // SOCKS5 IP literals and transparent inbounds without a reverse-table hit
    // carry no hostname. The adapter must encode dst_ip rather than an empty
    // domain or a sniffed rule-only hostname.
    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::default(),
        dst_ip: Some(echo_addr.ip()),
        dst_port: echo_addr.port(),
        sniff_host: smol_str::SmolStr::from("must-not-be-dialed.invalid"),
        ..Default::default()
    };

    let mut conn = timeout(T, adapter.dial_tcp(&metadata))
        .await
        .expect("dial_tcp must not stall")
        .expect("IP-only dial must succeed");
    let payload = b"ip-only-anytls";
    conn.write_all(payload).await.unwrap();
    let mut echoed = vec![0; payload.len()];
    timeout(T, conn.read_exact(&mut echoed))
        .await
        .expect("echo must not stall")
        .expect("echo must succeed");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn anytls_concurrent_dials_each_get_independent_streams() {
    install_crypto_provider();
    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    // Build the adapter once, share it across tasks — confirms the adapter
    // itself doesn't serialise dials behind some internal mutex and that the
    // upstream server tolerates multiple concurrent sessions.
    let adapter = Arc::new(
        AnytlsAdapter::new(
            "test-anytls-concurrent",
            &server_addr.ip().to_string(),
            server_addr.port(),
            PASSWORD,
            Some("localhost"),
            true,
            true,
        )
        .expect("adapter must build"),
    );

    let mut handles = Vec::new();
    for i in 0..4u8 {
        let adapter = Arc::clone(&adapter);
        handles.push(tokio::spawn(async move {
            let metadata = Metadata {
                network: Network::Tcp,
                host: smol_str::SmolStr::from(echo_addr.ip().to_string()),
                dst_port: echo_addr.port(),
                ..Default::default()
            };
            let mut conn = adapter.dial_tcp(&metadata).await.expect("dial");
            // Per-task payload so a crossed-wires bug would surface as the
            // wrong stamp coming back.
            let payload = [b'#', b'a' + i, b'\n'];
            conn.write_all(&payload).await.unwrap();
            conn.flush().await.unwrap();
            let mut got = [0u8; 3];
            conn.read_exact(&mut got).await.unwrap();
            assert_eq!(got, payload, "task {i} got crossed bytes");
        }));
    }
    for h in handles {
        timeout(T, h).await.expect("task timed out").expect("task");
    }
}

#[tokio::test]
async fn anytls_sequential_writes_same_connection() {
    // The adapter must support multiple write/read cycles over one stream
    // without re-handshaking or resetting state.
    install_crypto_provider();
    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-seq",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::from(echo_addr.ip().to_string()),
        dst_port: echo_addr.port(),
        ..Default::default()
    };
    let mut conn = timeout(T, adapter.dial_tcp(&metadata))
        .await
        .expect("dial timeout")
        .expect("dial");

    for round in 0..5u8 {
        let payload = [b'r', b'0' + round, b'\n'];
        conn.write_all(&payload).await.unwrap();
        conn.flush().await.unwrap();
        let mut got = [0u8; 3];
        timeout(T, conn.read_exact(&mut got))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(got, payload, "round {round}");
    }
}

#[tokio::test]
async fn anytls_rejects_wrong_password() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-bad",
        &server_addr.ip().to_string(),
        server_addr.port(),
        "WRONG-PASSWORD",
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::from(echo_addr.ip().to_string()),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // The server hard-closes on bad password. The adapter should not
    // return a working stream — either dial fails outright or the first
    // write/read fails. Tolerate both shapes; what we're guarding is that
    // wrong passwords don't silently succeed.
    let dial = timeout(T, adapter.dial_tcp(&metadata)).await;
    match dial {
        // Timed out (server stalled the auth) or dial errored — both
        // acceptable shapes of "wrong password is rejected."
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(mut conn)) => {
            // Dial returned a conn — exercise it and require failure on
            // either side of the round trip.
            let payload = b"should-not-reach";
            let w = timeout(T, conn.write_all(payload)).await;
            let mut buf = vec![0u8; payload.len()];
            let r = timeout(T, conn.read_exact(&mut buf)).await;
            assert!(
                w.is_err()
                    || w.unwrap().is_err()
                    || r.is_err()
                    || r.unwrap().is_err()
                    || &buf[..] != payload,
                "wrong password must not deliver an end-to-end round trip"
            );
        }
    }
}

// ─── UDP over AnyTLS (sing-box udp-over-tcp v2, Bind format) ─────────────────

/// Local UDP echo server. Returns its bound `127.0.0.1:port`.
async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            if sock.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    (addr, h)
}

fn udp_metadata(dst: SocketAddr) -> Metadata {
    Metadata {
        network: Network::Udp,
        host: smol_str::SmolStr::from(dst.ip().to_string()),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        ..Default::default()
    }
}

#[tokio::test]
async fn anytls_udp_round_trip_through_upstream_server() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_udp_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-udp",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let conn = timeout(T, adapter.dial_udp(&udp_metadata(echo_addr)))
        .await
        .expect("dial_udp must not stall")
        .expect("dial_udp must succeed end-to-end");

    let payload = b"meow<>anytls udp round-trip";
    let sent = timeout(T, conn.write_packet(payload, &echo_addr))
        .await
        .expect("write_packet must not stall")
        .expect("write_packet must succeed");
    assert_eq!(sent, payload.len());

    let mut buf = vec![0u8; 2048];
    let (n, from) = timeout(T, conn.read_packet(&mut buf))
        .await
        .expect("read_packet must not stall")
        .expect("read_packet must succeed");
    assert_eq!(&buf[..n], payload, "echoed payload must match");
    // Bind format carries the real source per packet — if the reply header
    // were mis-encoded this would come back as 0.0.0.0:0 or garbage.
    assert_eq!(from, echo_addr, "reply must carry the peer address");
}

#[tokio::test]
async fn anytls_udp_routes_each_packet_to_its_own_destination() {
    // Bind format (isConnect=0) means the destination travels with every
    // datagram rather than being pinned at handshake. Two echo servers on one
    // packet conn prove that path, and that replies are attributed correctly.
    install_crypto_provider();

    let (echo_a, _a_h) = start_udp_echo_server().await;
    let (echo_b, _b_h) = start_udp_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-udp-multi",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let conn = timeout(T, adapter.dial_udp(&udp_metadata(echo_a)))
        .await
        .expect("dial_udp must not stall")
        .expect("dial_udp must succeed");

    timeout(T, conn.write_packet(b"to-a", &echo_a))
        .await
        .expect("write a must not stall")
        .expect("write a");
    timeout(T, conn.write_packet(b"to-b", &echo_b))
        .await
        .expect("write b must not stall")
        .expect("write b");

    // Replies may arrive in either order; key them by source address.
    let mut seen = std::collections::HashMap::new();
    let mut buf = vec![0u8; 2048];
    for _ in 0..2 {
        let (n, from) = timeout(T, conn.read_packet(&mut buf))
            .await
            .expect("read_packet must not stall")
            .expect("read_packet must succeed");
        seen.insert(from, buf[..n].to_vec());
    }

    assert_eq!(seen.get(&echo_a).map(Vec::as_slice), Some(&b"to-a"[..]));
    assert_eq!(seen.get(&echo_b).map(Vec::as_slice), Some(&b"to-b"[..]));
}

#[tokio::test]
async fn anytls_udp_is_refused_when_not_enabled() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_udp_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-udp-off",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        false,
    )
    .expect("adapter must build");

    assert!(!adapter.support_udp(), "udp: false must not advertise UDP");
    let Err(err) = adapter.dial_udp(&udp_metadata(echo_addr)).await else {
        panic!("dial_udp must be refused when `udp` is off");
    };
    assert!(err.to_string().contains("udp: true"), "msg: {err}");
}

// ─── Regression: auth record must fit in one TLS record (#469 / #470) ───────
//
// The owner (madeye) asked for a regression test for the single-TLS-record
// auth fix. The unit test added in `meow-anytls/src/util/auth.rs`
// (`send_authentication_writes_whole_record_in_one_call`) pins the property
// on `send_authentication` directly, but it lives inside the *vendored*
// crate — a future re-vendor of `meow-anytls` would wipe it out and
// silently reintroduce the 3-write bug. This integration test lives in
// `meow-proxy` (a consumer of the vendored crate), so it survives
// re-vendoring, and it exercises the real `AnytlsAdapter` end to end
// through a real TLS stack.

/// Drive a raw `rustls` server over a tokio `TcpStream`, feeding it
/// ciphertext **one TLS record at a time**, and return the plaintext of the
/// first application-data record the client sends.
///
/// The reference anytls server (anytls-go / sing-anytls / sing-box)
/// authenticates with a *single* read off the TLS connection
/// (`ReadOnceFrom`), then parses `SHA256(password) (32) + padding0 length
/// (2) + padding0` from that one buffer. On a rustls TLS stream each
/// `write_all` is its own TLS record, so splitting the auth across multiple
/// `write_all`s produces multiple TLS records: the server's single read
/// returns only the first one and EOFs on the 2-byte padding length (`EOF:
/// read padding length: fallback disabled`), tearing the session down
/// before SYNACK (#469).
///
/// A naive "single `poll_read`" test is *not* a reliable guard here: rustls
/// coalesces already-arrived records into one `poll_read`, so it would
/// false-pass under the old multi-write code. Driving the server
/// record-by-record — parse the 5-byte TLS record header, feed exactly one
/// record to `read_tls`, decrypt, read its plaintext — pins the true
/// invariant ("the auth is one TLS record") with no timing or coalescing
/// dependency. It works for both TLS 1.2 and 1.3: in 1.3 the client's
/// Finished travels in a type-23 record on the wire but yields *no*
/// application plaintext, so `reader().read()` returns 0 for it and the
/// loop skips it; the first non-empty plaintext is the auth.
fn invalid_data<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

async fn capture_first_appdata_plaintext(
    mut tcp: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut raw: Vec<u8> = Vec::with_capacity(8192);
    let mut acceptor = rustls::server::Acceptor::default();
    let mut conn: Option<rustls::server::ServerConnection> = None;

    loop {
        // Ensure `raw` holds at least one complete TLS record: a 5-byte
        // header (type, version[2], length[2]) followed by `length` bytes.
        while raw.len() < 5 || raw.len() < 5 + usize::from(u16::from_be_bytes([raw[3], raw[4]])) {
            let mut chunk = [0u8; 4096];
            let n = tcp.read(&mut chunk).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "anytls regression server: EOF before first app-data record",
                ));
            }
            raw.extend_from_slice(&chunk[..n]);
        }
        let rec_len = usize::from(u16::from_be_bytes([raw[3], raw[4]]));
        let record: Vec<u8> = raw.drain(..5 + rec_len).collect();

        // Feed exactly this one record to rustls.
        {
            let mut cur = std::io::Cursor::new(&record[..]);
            if let Some(c) = conn.as_mut() {
                c.read_tls(&mut cur)?;
            } else {
                acceptor.read_tls(&mut cur)?;
            }
        }

        // Promote the Acceptor to a ServerConnection once the ClientHello
        // has been received.
        if conn.is_none() {
            if let Some(accepted) = acceptor.accept().map_err(|(e, _)| invalid_data(e))? {
                conn = Some(
                    accepted
                        .into_connection(Arc::clone(&config))
                        .map_err(|(e, _)| invalid_data(e))?,
                );
            }
        }

        // Decrypt / advance state, flush any queued TLS bytes, and — once
        // the handshake is done — look for the first application plaintext.
        if let Some(c) = conn.as_mut() {
            c.process_new_packets().map_err(invalid_data)?;

            while c.wants_write() {
                let mut out = Vec::new();
                let written = c.write_tls(&mut out)?;
                if written == 0 {
                    break;
                }
                tcp.write_all(&out).await?;
            }

            if !c.is_handshaking() {
                let mut plain = vec![0u8; 65535];
                // rustls' `Reader::read` returns `WouldBlock` when a record
                // carries no application plaintext (e.g. the TLS 1.3 client
                // Finished, which rides in a type-23 record on the wire).
                // Treat that as "zero bytes for this record" and keep
                // scanning; the first non-empty plaintext is the auth.
                let n = {
                    let mut r = c.reader();
                    match r.read(&mut plain) {
                        Ok(n) => n,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
                        Err(e) => return Err(e),
                    }
                };
                if n > 0 {
                    plain.truncate(n);
                    return Ok(plain);
                }
            }
        }
    }
}

/// Regression for #469: the AnyTLS auth record must arrive in a *single* TLS
/// record, because the reference anytls server authenticates with one read
/// off the TLS connection. The `anytls_rs::server::Server`-based tests above
/// use `read_exact` (incremental) auth and so never caught the multi-write
/// bug; this test drives a record-granular TLS server (see
/// [`capture_first_appdata_plaintext`]) and asserts the first application
/// record carries the *entire* auth header. It lives in `meow-proxy`, not
/// the vendored `meow-anytls` crate, so a future re-vendor cannot silently
/// drop it.
#[tokio::test]
async fn anytls_auth_record_arrives_in_single_tls_record() {
    install_crypto_provider();
    let (cert, key) = self_signed_cert();
    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let server_h = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept regression client");
        let result = capture_first_appdata_plaintext(tcp, server_config).await;
        let _ = tx.send(result);
    });

    // Real adapter: it dials, completes the TLS handshake, and emits the
    // auth record. We don't care whether `dial_tcp` ultimately succeeds —
    // the regression server closes right after capturing auth, so the
    // client's post-auth SYNACK wait may error. The assertion is purely
    // server-side: did the whole auth come over in one TLS record? Run the
    // dial on a detached task so the test isn't held hostage to the
    // client's post-auth timeout.
    //
    // Invariant this test depends on: a *freshly constructed* adapter has
    // an empty session pool, so the first `dial_tcp` opens a brand-new
    // session — i.e. performs the TLS handshake and calls
    // `send_authentication` (the very thing we're guarding). Reusing an
    // adapter across tests, or any future pool change that served a cached
    // session instead of dialing, would skip auth and silently
    // false-pass. Keep the adapter test-local and one-shot.
    let adapter = AnytlsAdapter::new(
        "regress-single-tls-record",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let dial_h = tokio::spawn(async move {
        let metadata = Metadata {
            network: Network::Tcp,
            host: smol_str::SmolStr::from("127.0.0.1"),
            // Unused: the regression server closes before any relay happens.
            dst_port: 1,
            ..Default::default()
        };
        // Drive the dial; ignore the outcome.
        let _ = timeout(T, adapter.dial_tcp(&metadata)).await;
    });

    let record = timeout(T, rx)
        .await
        .expect("regression server must report in time")
        .expect("regression server channel must not close prematurely")
        .expect("regression server handshake/capture must not error");

    // Under the old 3-write code the first TLS record carried only the
    // 32-byte password hash; the reference server's single read then EOF'd
    // on the 2-byte padding length. Require the full header at minimum.
    assert!(
        record.len() >= 34,
        "first TLS record must carry the entire auth header (>= 34 bytes: \
         32-byte password hash + 2-byte padding0 length); got only {} bytes — \
         the auth was split across multiple TLS records (regression of #469)",
        record.len(),
    );

    let expected_hash = anytls_rs::hash_password(PASSWORD);
    assert_eq!(
        &record[..32],
        expected_hash.as_slice(),
        "password-hash prefix must match the adapter's password",
    );
    let padding_len = usize::from(u16::from_be_bytes([record[32], record[33]]));
    assert_eq!(
        record.len(),
        32 + 2 + padding_len,
        "record length must equal 32 (hash) + 2 (length) + padding0 length",
    );
    assert!(
        record[34..].iter().all(|&b| b == 0),
        "padding0 bytes must be zero-filled",
    );

    // Best-effort cleanup; the tasks are likely already settled.
    server_h.abort();
    dial_h.abort();
}

// ─── Regression: UoT request must precede the SYNACK wait (#535) ──────────
//
// sing-box's anytls inbound sequences a UoT stream as: read destination →
// see the magic address → `uot.ReadRequest(conn)` blocks on the wire →
// `RoutePacketConnectionEx` → `N.HandshakeSuccess` → SYNACK. A client that
// returns the stream from `dial_udp` and writes the UoT request lazily with
// the first datagram deadlocks against it: client waits SYNACK, server
// waits request. The vendored `anytls_rs::server::Server` SYNACKs
// unconditionally right after the destination (handler.rs), so the tests
// above cannot pin this ordering. The fake below speaks just enough AnyTLS
// — TLS, auth, the frame layer — to reproduce sing-box's ordering: it
// withholds SYNACK until the UoT request has been consumed, then echoes
// datagrams back.

/// Bytes consumed by a SOCKS5-family `ATYP+ADDR+PORT` at the front of
/// `buf`; `None` while more bytes are needed.
fn socks5_addr_len(buf: &[u8]) -> Option<usize> {
    let need = match *buf.first()? {
        0x01 => 1 + 4 + 2,
        0x03 => 2 + usize::from(*buf.get(1)?) + 2,
        0x04 => 1 + 16 + 2,
        other => panic!("fake anytls server: bad socks5 atyp {other:#x}"),
    };
    (buf.len() >= need).then_some(need)
}

/// Same shape for a uot-family `ATYP+ADDR+PORT` (0x00/0x01/0x02).
fn uot_addr_len(buf: &[u8]) -> Option<usize> {
    let need = match *buf.first()? {
        0x00 => 1 + 4 + 2,
        0x02 => 2 + usize::from(*buf.get(1)?) + 2,
        0x01 => 1 + 16 + 2,
        other => panic!("fake anytls server: bad uot atyp {other:#x}"),
    };
    (buf.len() >= need).then_some(need)
}

/// Bytes consumed by a complete uot datagram (`addr + u16 len + payload`).
fn uot_datagram_len(buf: &[u8]) -> Option<usize> {
    let addr_len = uot_addr_len(buf)?;
    let payload = u16::from_be_bytes([*buf.get(addr_len)?, *buf.get(addr_len + 1)?]) as usize;
    (buf.len() >= addr_len + 2 + payload).then_some(addr_len + 2 + payload)
}

/// Whether a parsed SOCKS5-family `addr+port` slice names the UoT magic
/// destination (`sp.v2.udp-over-tcp.arpa`, domain form).
fn is_uot_magic(socks5_addr: &[u8]) -> bool {
    let magic = UDP_OVER_TCP_MAGIC_ADDR.as_bytes();
    socks5_addr.len() == magic.len() + 4
        && socks5_addr[0] == 0x03
        && usize::from(socks5_addr[1]) == magic.len()
        && socks5_addr[2..2 + magic.len()] == *magic
}

async fn write_anytls_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    cmd: Command,
    stream_id: u32,
    data: &[u8],
) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(7 + data.len());
    frame.push(u8::from(cmd));
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    writer.write_all(&frame).await?;
    writer.flush().await
}

/// Per-stream reassembly state for the fake server. PSH payloads are
/// appended to `buf` and consumed element by element — AnyTLS padding may
/// split a frame across TLS records, and the client may coalesce writes,
/// so framing must be rebuilt from the byte stream.
#[derive(Default)]
struct FakeUotStream {
    buf: Vec<u8>,
    stage: FakeUotStage,
}

#[derive(Default)]
enum FakeUotStage {
    /// Waiting for the SOCKS5 destination that follows SYN.
    #[default]
    Dst,
    /// UoT stream: holding SYNACK until the request arrives (sing-box order).
    Request,
    /// UoT relay: parse and echo whole datagrams.
    Relay,
    /// Non-UoT stream: SYNACK already sent; payload is drained and dropped.
    Dead,
}

/// One accepted connection of the fake server: authenticate, then serve
/// frames until EOF.
async fn run_singbox_uot_session(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(tls);

    // Auth record: SHA256(password) + u16be padding0_len + padding0. Read
    // and discard — ordering, not auth, is what this fake pins.
    let mut auth = [0u8; 34];
    reader.read_exact(&mut auth).await?;
    let mut padding = vec![0u8; u16::from_be_bytes([auth[32], auth[33]]) as usize];
    reader.read_exact(&mut padding).await?;

    let mut streams = std::collections::HashMap::<u32, FakeUotStream>::new();
    loop {
        let mut header = [0u8; 7];
        reader.read_exact(&mut header).await?;
        let cmd = Command::from(header[0]);
        let stream_id = u32::from_be_bytes(header[1..5].try_into().unwrap());
        let mut data = vec![0u8; u16::from_be_bytes([header[5], header[6]]) as usize];
        reader.read_exact(&mut data).await?;

        match cmd {
            Command::Syn => {
                streams.insert(stream_id, FakeUotStream::default());
            }
            Command::Fin => {
                streams.remove(&stream_id);
            }
            Command::HeartRequest => {
                write_anytls_frame(&mut writer, Command::HeartResponse, stream_id, &[]).await?;
            }
            Command::Push => {
                let Some(stream) = streams.get_mut(&stream_id) else {
                    continue;
                };
                stream.buf.extend_from_slice(&data);
                loop {
                    match stream.stage {
                        FakeUotStage::Dst => {
                            let Some(n) = socks5_addr_len(&stream.buf) else {
                                break;
                            };
                            let uot = is_uot_magic(&stream.buf[..n]);
                            stream.buf.drain(..n);
                            if uot {
                                stream.stage = FakeUotStage::Request;
                            } else {
                                // Non-UoT destination: SYNACK immediately,
                                // the vendored server's unconditional shape.
                                write_anytls_frame(&mut writer, Command::SynAck, stream_id, &[])
                                    .await?;
                                stream.stage = FakeUotStage::Dead;
                            }
                        }
                        FakeUotStage::Request => {
                            // UoT request: isConnect (1) + SOCKS5 addr+port.
                            // `dial_udp` only ever sends Bind (isConnect=0),
                            // so the byte is skipped without validation.
                            if stream.buf.is_empty() {
                                break;
                            }
                            let Some(n) = socks5_addr_len(&stream.buf[1..]) else {
                                break;
                            };
                            stream.buf.drain(..1 + n);
                            // sing-box order: the request must be on the wire
                            // before handshake success is reported.
                            write_anytls_frame(&mut writer, Command::SynAck, stream_id, &[])
                                .await?;
                            stream.stage = FakeUotStage::Relay;
                        }
                        FakeUotStage::Relay => {
                            let Some(n) = uot_datagram_len(&stream.buf) else {
                                break;
                            };
                            // Echo: the datagram's own uot addr becomes the
                            // reply's source address.
                            let datagram = stream.buf[..n].to_vec();
                            stream.buf.drain(..n);
                            write_anytls_frame(&mut writer, Command::Push, stream_id, &datagram)
                                .await?;
                        }
                        FakeUotStage::Dead => {
                            stream.buf.clear();
                            break;
                        }
                    }
                }
            }
            // Settings, ServerSettings-side commands, Waste padding, alerts:
            // none need a response for this fake.
            _ => {}
        }
    }
}

/// Start the sing-box-ordered fake AnyTLS server; returns its bound addr.
async fn start_singbox_uot_server(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = Arc::clone(&acceptor);
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let _ = run_singbox_uot_session(tls).await;
                }
            });
        }
    });
    (addr, h)
}

/// Regression for issue #535: `dial_udp` must put the UoT request on the
/// wire before it waits for SYNACK. Under the old lazy-request shape the
/// server below withholds SYNACK forever (its UoT-request read never
/// completes), the dial stalls until the outer deadline, and this test
/// fails at the 5-second timeout — the exact deadlock sing-box produced.
#[tokio::test]
async fn anytls_udp_survives_singbox_synack_after_uot_request_ordering() {
    install_crypto_provider();

    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_singbox_uot_server(cert, key).await;
    let adapter = AnytlsAdapter::new(
        "test-anytls-udp-singbox",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    // Arbitrary UDP destination; the fake echoes datagrams itself.
    let target: SocketAddr = "192.0.2.1:5353".parse().unwrap();
    let conn = timeout(
        Duration::from_secs(5),
        adapter.dial_udp(&udp_metadata(target)),
    )
    .await
    .expect("dial_udp deadlocks while SYNACK is gated on the uot request")
    .expect("dial_udp must succeed against sing-box-ordered SYNACK");

    timeout(T, conn.write_packet(b"ping", &target))
        .await
        .expect("write_packet must not stall")
        .expect("write_packet must succeed");
    let mut buf = [0u8; 64];
    let (n, from) = timeout(T, conn.read_packet(&mut buf))
        .await
        .expect("read_packet must not stall")
        .expect("read_packet must succeed");
    assert_eq!(&buf[..n], b"ping", "echoed payload must match");
    assert_eq!(from, target, "reply must carry the datagram's uot source");
}

/// Companion to the UoT-ordering regression: the same sing-box-ordered
/// fake must still SYNACK a *non*-UoT destination right after the address,
/// which is the unconditional shape the vendored server (and sing-box for
/// regular streams) produces. Covers the fake's `Dead` stage — payload is
/// drained, not echoed — and pins that `dial_tcp` was untouched by the
/// eager-payload open path.
#[tokio::test]
async fn anytls_tcp_gets_immediate_synack_from_singbox_ordered_fake() {
    install_crypto_provider();

    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_singbox_uot_server(cert, key).await;
    let adapter = AnytlsAdapter::new(
        "test-anytls-tcp-singbox",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::from("192.0.2.2"),
        dst_ip: Some("192.0.2.2".parse().unwrap()),
        dst_port: 443,
        ..Default::default()
    };
    let mut conn = timeout(T, adapter.dial_tcp(&metadata))
        .await
        .expect("dial_tcp must not stall on a non-uot destination")
        .expect("dial_tcp must succeed — synack follows the dst immediately");

    // The fake drains non-uot payload (Dead stage); write reaches the wire
    // but nothing is echoed, so only the write side is asserted.
    timeout(T, conn.write_all(b"GET / HTTP/1.0\r\n\r\n"))
        .await
        .expect("tcp write must not stall")
        .expect("tcp write must succeed");
    conn.flush().await.unwrap();
}

/// Issue #570 — `connect_over` must apply the adapter's TLS layer to the
/// relay-supplied stream, then run AnyTLS auth + session + proxy-stream on
/// top. The upstream is plain TCP to the anytls server; the adapter's own
/// TlsLayer terminates on it, so the server sees a normal TLS client.
#[tokio::test]
async fn anytls_connect_over_runs_tls_auth_and_stream() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-connect-over",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        false,
    )
    .expect("adapter must build");

    // Relay hop-0 leg: plain TCP already connected to the anytls server.
    let upstream = tokio::net::TcpStream::connect(server_addr)
        .await
        .expect("upstream connect");
    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::from(echo_addr.ip().to_string()),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(T, adapter.connect_over(Box::new(upstream), &metadata))
        .await
        .expect("connect_over must not stall")
        .expect("connect_over must succeed end-to-end");

    let payload = b"anytls over relay-supplied stream";
    timeout(T, conn.write_all(payload))
        .await
        .expect("write must not stall")
        .expect("write must succeed");
    timeout(T, conn.flush())
        .await
        .expect("flush must not stall")
        .expect("flush must succeed");

    let mut buf = vec![0u8; payload.len()];
    timeout(T, conn.read_exact(&mut buf))
        .await
        .expect("echo must not stall")
        .expect("echo must succeed");
    assert_eq!(&buf[..], payload, "echo payload must match what we wrote");
}
