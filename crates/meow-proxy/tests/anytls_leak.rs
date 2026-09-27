#![cfg(feature = "anytls")]
//! Regression test for issue #201 item 4: the AnyTLS adapter must not leak
//! file descriptors (one TLS socket per orphaned session) under repeated
//! sequential dials. The upstream `anytls-rs` session pool removed a reused
//! session from the pool but never returned it, so every reused session was
//! orphaned — kept alive forever by its heartbeat task — leaking its fd. Under
//! churn this exhausted fds ("No file descriptors available (os error 24)")
//! and then aborted on allocation failure.
//!
//! This test dials many times through an in-process anytls server and asserts
//! the process's open-fd count stays bounded.

use std::net::SocketAddr;
use std::sync::Arc;

use anytls_rs::padding::PaddingFactory;
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

/// Count this process's currently-open file descriptors. Works on Linux
/// (`/proc/self/fd`) and macOS (`/dev/fd`). Returns `None` on platforms where
/// neither is available, in which case the test skips its assertion.
fn open_fd_count() -> Option<usize> {
    for dir in ["/proc/self/fd", "/dev/fd"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            return Some(rd.count());
        }
    }
    None
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

async fn start_anytls_server(
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
    drop(listener);

    let padding = PaddingFactory::default();
    let server = AnytlsServer::new(PASSWORD, acceptor, padding, None);
    let listen_addr = format!("127.0.0.1:{}", addr.port());
    let h = tokio::spawn(async move {
        let _ = server.listen(&listen_addr).await;
    });
    // Poll until the accept loop has actually re-bound — a fixed sleep
    // races the bind on a loaded runner and flakes the first dial.
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return (addr, h);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("anytls test server did not rebind within 5s");
}

async fn one_round_trip(adapter: &AnytlsAdapter, echo_addr: SocketAddr) {
    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::from(echo_addr.ip().to_string()),
        dst_port: echo_addr.port(),
        ..Default::default()
    };
    let mut conn = timeout(T, adapter.dial_tcp(&metadata))
        .await
        .expect("dial must not stall")
        .expect("dial must succeed");
    let payload = b"leakprobe";
    conn.write_all(payload).await.expect("write");
    conn.flush().await.expect("flush");
    let mut buf = [0u8; 9];
    timeout(T, conn.read_exact(&mut buf))
        .await
        .expect("echo must not stall")
        .expect("echo");
    assert_eq!(&buf[..], payload);
    // conn dropped here -> exercises AnytlsConn teardown
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anytls_repeated_dials_do_not_leak_fds() {
    install_crypto_provider();
    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-leak",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    // Warm up: reach steady state (pooled warm session established).
    for _ in 0..3 {
        one_round_trip(&adapter, echo_addr).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let baseline = open_fd_count();
    eprintln!("baseline fds: {baseline:?}");

    const N: usize = 40;
    for i in 0..N {
        one_round_trip(&adapter, echo_addr).await;
        if i % 10 == 9 {
            eprintln!("after {} dials: fds = {:?}", i + 1, open_fd_count());
        }
    }
    // Teardown settles asynchronously — poll until the fd count drops back
    // under the bound instead of asserting after a fixed sleep, which
    // false-fails whenever teardown lags on a loaded runner.
    let mut after = open_fd_count();
    if let Some(b) = baseline {
        for _ in 0..100 {
            match after {
                Some(a) if a.saturating_sub(b) <= 8 => break,
                _ => {}
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
            after = open_fd_count();
        }
    }
    eprintln!("after {N} dials: fds = {after:?} (baseline {baseline:?})");

    if let (Some(b), Some(a)) = (baseline, after) {
        let growth = a.saturating_sub(b);
        // A correct, non-leaking adapter reuses/closes sessions, so fd growth
        // across N dials must stay small and bounded — NOT proportional to N.
        assert!(
            growth <= 8,
            "fd leak: {N} sequential dials grew open fds by {growth} \
             (baseline {b} -> {a}); expected a small bounded delta. \
             This is issue #201 item 4 (orphaned anytls sessions leak their socket)."
        );
    }
}
