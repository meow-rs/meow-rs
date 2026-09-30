//! VMess, VLESS encryption and VLESS XTLS-Vision against the official
//! Xray-core server.
//!
//! The server binary is extracted from the pinned `ghcr.io/xtls/xray-core`
//! image and run natively. These tests pin the record-layer AEADs — VMess
//! AES-128-GCM / ChaCha20-Poly1305 and VLESS encryption's AES-256-GCM — to
//! a real peer; the in-crate tests only check them against another Rust
//! implementation.  The Vision leg pins the DIRECT switch to the raw socket
//! under plain TLS (issue #495).
//!
//! Without Docker the tests skip; `MEOW_REQUIRE_DOCKER=1` (set in CI) turns
//! a skip into a failure.

#![cfg(any(
    feature = "vmess",
    feature = "vless-encryption",
    feature = "vless-vision"
))]

use meow_common::{Metadata, Network, ProxyAdapter, ProxyConn};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::TransportChain;
use serde_json::{json, Value};
use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout, Duration, Instant};

const IMAGE_XRAY: &str = "ghcr.io/xtls/xray-core:26.3.27";
const UUID: &str = "3971e1b2-18a3-4f83-8fa6-bf9b142ee258";
const T: Duration = Duration::from_secs(30);

fn docker_required() -> bool {
    std::env::var_os("MEOW_REQUIRE_DOCKER").is_some()
        || std::env::var_os("MIHOMO_REQUIRE_INTEGRATION_BINS").is_some()
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn skip_or_panic(reason: impl AsRef<str>) {
    let reason = reason.as_ref();
    assert!(!docker_required(), "{reason}");
    eprintln!("skipping xray docker integration test: {reason}");
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn uuid_bytes() -> [u8; 16] {
    hex::decode(UUID.replace('-', ""))
        .unwrap()
        .try_into()
        .unwrap()
}

struct XrayServer {
    _dir: TempDir,
    child: std::process::Child,
    log_path: PathBuf,
}

impl XrayServer {
    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for XrayServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn extract_xray_binary(dir: &Path) -> Option<PathBuf> {
    // Tests in one binary run in parallel under the same pid; the counter
    // keeps their extraction containers apart.
    static EXTRACTIONS: AtomicUsize = AtomicUsize::new(0);

    let cached = Command::new("docker")
        .args(["image", "inspect", IMAGE_XRAY])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !cached {
        let pulled = Command::new("docker")
            .args(["pull", IMAGE_XRAY])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !pulled {
            return None;
        }
    }

    let name = format!(
        "meow-xray-extract-{}-{}",
        std::process::id(),
        EXTRACTIONS.fetch_add(1, Ordering::Relaxed)
    );
    let created = Command::new("docker")
        .args(["create", "--name", &name, IMAGE_XRAY])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !created {
        return None;
    }
    let bin = dir.join("xray");
    let copied = Command::new("docker")
        .args([
            "cp",
            &format!("{name}:/usr/local/bin/xray"),
            &bin.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    let _ = Command::new("docker")
        .args(["rm", "-f", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    copied.then_some(bin)
}

/// Run Xray with a single `inbound` on `127.0.0.1:port` and a direct
/// (`freedom`) outbound, and wait until it accepts TCP.
async fn start_xray(port: u16, mut inbound: Value) -> Option<XrayServer> {
    if !cfg!(target_os = "linux") {
        skip_or_panic("test requires the Linux xray binary from the Docker image");
        return None;
    }
    if !docker_available() {
        skip_or_panic("docker daemon is not available");
        return None;
    }

    let dir = TempDir::new().unwrap();
    let Some(xray) = extract_xray_binary(dir.path()) else {
        skip_or_panic(format!("failed to extract xray from {IMAGE_XRAY}"));
        return None;
    };
    inbound["listen"] = json!("127.0.0.1");
    inbound["port"] = json!(port);
    let config = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [inbound],
        "outbounds": [{ "protocol": "freedom" }],
    });
    let config_path = dir.path().join("config.json");
    std::fs::write(&config_path, config.to_string()).unwrap();

    let log_path = dir.path().join("xray.log");
    let log = File::create(&log_path).unwrap();
    let child = Command::new(&xray)
        .args(["run", "-c", &config_path.to_string_lossy()])
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap_or_else(|e| panic!("failed to start xray: {e}"));
    let server = XrayServer {
        _dir: dir,
        child,
        log_path,
    };

    let deadline = Instant::now() + T;
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        assert!(
            Instant::now() < deadline,
            "xray never listened on {port}\n{}",
            server.logs()
        );
        sleep(Duration::from_millis(100)).await;
    }
    Some(server)
}

async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    (addr, handle)
}

/// Size of the request [`start_reply_after_request_server`] waits for.
const REQUEST_LEN: usize = 90 * 1024;

/// Upstream that answers once the whole [`REQUEST_LEN`]-byte request has
/// arrived: echoes it back and closes. It keys on the byte count, not on
/// EOF, because Xray's `freedom` outbound does not forward the client's FIN
/// upstream — it tears the pair down once the `downlinkOnly` policy window
/// (1 s by default) passes.
async fn start_reply_after_request_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = vec![0u8; REQUEST_LEN];
                if stream.read_exact(&mut request).await.is_ok() {
                    let _ = stream.write_all(&request).await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    (addr, handle)
}

fn metadata_for(addr: SocketAddr, network: Network) -> Metadata {
    Metadata {
        network,
        host: addr.ip().to_string().into(),
        dst_port: addr.port(),
        ..Default::default()
    }
}

fn patterned(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251) as u8 ^ seed.wrapping_mul(31))
        .collect()
}

async fn dial(
    adapter: &dyn ProxyAdapter,
    metadata: &Metadata,
    server: &XrayServer,
) -> Box<dyn ProxyConn> {
    timeout(T, adapter.dial_tcp(metadata))
        .await
        .unwrap_or_else(|_| panic!("dial timed out\n{}", server.logs()))
        .unwrap_or_else(|e| panic!("dial failed: {e}\n{}", server.logs()))
}

/// Stream `payload` through an echo upstream with both directions in
/// flight, then half-close and expect a clean EOF.
async fn bulk_echo<S>(mut conn: S, payload: &[u8], server: &XrayServer)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(&mut conn);
    let write = async {
        wr.write_all(payload).await?;
        wr.flush().await
    };
    let read = async {
        let mut echoed = vec![0u8; payload.len()];
        rd.read_exact(&mut echoed).await.map(|_| echoed)
    };
    let (written, echoed) = timeout(T, async { tokio::join!(write, read) })
        .await
        .unwrap_or_else(|_| panic!("bulk echo timed out\n{}", server.logs()));
    written.unwrap_or_else(|e| panic!("bulk write failed: {e}\n{}", server.logs()));
    let echoed = echoed.unwrap_or_else(|e| panic!("bulk read failed: {e}\n{}", server.logs()));
    assert!(echoed == payload, "bulk echo corrupted the payload");

    timeout(T, conn.shutdown())
        .await
        .expect("shutdown timed out")
        .expect("shutdown failed");
    let mut tail = Vec::new();
    timeout(T, conn.read_to_end(&mut tail))
        .await
        .unwrap_or_else(|_| panic!("EOF after half-close timed out\n{}", server.logs()))
        .expect("EOF read failed");
    assert!(tail.is_empty(), "unexpected bytes after the echo");
}

/// Send a [`REQUEST_LEN`]-byte request, half-close at once, and expect the
/// full reply: shutting down the write side must not cut the read side.
async fn reply_after_half_close(mut conn: Box<dyn ProxyConn>, seed: u8, server: &XrayServer) {
    let payload = patterned(REQUEST_LEN, seed);
    timeout(T, conn.write_all(&payload))
        .await
        .expect("write timed out")
        .unwrap_or_else(|e| panic!("write failed: {e}\n{}", server.logs()));
    timeout(T, conn.shutdown())
        .await
        .expect("shutdown timed out")
        .unwrap_or_else(|e| panic!("shutdown failed: {e}\n{}", server.logs()));
    let mut reply = Vec::new();
    timeout(T, conn.read_to_end(&mut reply))
        .await
        .unwrap_or_else(|_| panic!("reply after half-close timed out\n{}", server.logs()))
        .unwrap_or_else(|e| panic!("reply read failed: {e}\n{}", server.logs()));
    assert_eq!(reply.len(), payload.len(), "short reply after half-close");
    assert!(reply == payload, "reply after half-close corrupted");
}

#[cfg(feature = "vmess")]
mod vmess {
    use super::*;
    use meow_proxy::vmess::Security;
    use meow_proxy::VmessAdapter;

    async fn round_trips(security: Security) {
        let port = free_tcp_port();
        let inbound = json!({
            "protocol": "vmess",
            "settings": { "clients": [{ "id": UUID }] },
        });
        let Some(server) = start_xray(port, inbound).await else {
            return;
        };
        let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
        let (replier, _reply_h) = start_reply_after_request_server().await;
        let adapter = VmessAdapter::new(
            "docker-xray-vmess",
            "127.0.0.1",
            port,
            uuid_bytes(),
            security,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        // 1 MiB each way: ~64 full body records plus a partial one.
        let conn = dial(&adapter, &metadata_for(tcp_echo, Network::Tcp), &server).await;
        bulk_echo(conn, &patterned((1 << 20) + 777, 1), &server).await;
        let conn = dial(&adapter, &metadata_for(replier, Network::Tcp), &server).await;
        reply_after_half_close(conn, 2, &server).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vmess_aes_128_gcm_against_xray() {
        round_trips(Security::Aes128Gcm).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vmess_chacha20_poly1305_against_xray() {
        round_trips(Security::ChaCha20Poly1305).await;
    }
}

#[cfg(feature = "vless-encryption")]
mod vless_encryption {
    use super::*;
    use meow_proxy::{parse_client_encryption, VlessAdapter};
    use tokio::net::UdpSocket;

    /// X25519 pair from `xray vlessenc` — throwaway keys for this test.
    const SERVER_KEY: &str = "wNtq6aAkhPsuJfzdcXaDjUVZ_n90IyfHyvLcVHZOhng";
    const CLIENT_KEY: &str = "RP1IcCCNd2u_f55q5v48HCXujbHz0bgO_EB29w2bZWg";

    async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], peer).await;
            }
        });
        (addr, handle)
    }

    /// `xor_mode` is `native` (plain records) or `random` (masked record
    /// headers); the AEAD under both is the same.
    async fn round_trips(xor_mode: &str) {
        let port = free_tcp_port();
        let inbound = json!({
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": UUID }],
                "decryption": format!("mlkem768x25519plus.{xor_mode}.600s.{SERVER_KEY}"),
            },
        });
        let Some(server) = start_xray(port, inbound).await else {
            return;
        };
        let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
        let (replier, _reply_h) = start_reply_after_request_server().await;
        let (udp_echo, _udp_h) = start_udp_echo_server().await;
        let mut adapter = VlessAdapter::new(
            "docker-xray-vless-encryption",
            "127.0.0.1",
            port,
            uuid_bytes(),
            None,
            true,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );
        let encryption = format!("mlkem768x25519plus.{xor_mode}.0rtt.{CLIENT_KEY}");
        let client = parse_client_encryption(&encryption)
            .expect("encryption string parses")
            .expect("encryption is enabled");
        adapter.set_encryption(Some(Arc::new(client)));

        // The first dial runs the 1-RTT handshake and caches the ticket;
        // the rest resume with 0-RTT. 1 MiB is ~128 full 8 KiB records.
        let echo_md = metadata_for(tcp_echo, Network::Tcp);
        for seed in 1..=2 {
            let conn = dial(&adapter, &echo_md, &server).await;
            bulk_echo(conn, &patterned((1 << 20) + 777, seed), &server).await;
        }
        let conn = dial(&adapter, &metadata_for(replier, Network::Tcp), &server).await;
        reply_after_half_close(conn, 3, &server).await;

        let packets = timeout(T, adapter.dial_udp(&metadata_for(udp_echo, Network::Udp)))
            .await
            .expect("udp dial timed out")
            .unwrap_or_else(|e| panic!("udp dial failed: {e}\n{}", server.logs()));
        let mut buf = vec![0u8; 64 * 1024];
        for (seed, len) in [(4u8, 21usize), (5, 1400), (6, 8000)] {
            let datagram = patterned(len, seed);
            timeout(T, packets.write_packet(&datagram, &udp_echo))
                .await
                .expect("udp write timed out")
                .expect("udp write failed");
            // Plain VLESS UDP names no per-packet source; the conn reports
            // a placeholder, so only the payload is checked.
            let (n, _) = timeout(T, packets.read_packet(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("udp read of {len} B timed out\n{}", server.logs()))
                .expect("udp read failed");
            assert!(buf[..n] == datagram[..], "udp datagram of {len} B changed");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vless_encryption_native_against_xray() {
        round_trips("native").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vless_encryption_random_against_xray() {
        round_trips("random").await;
    }
}

#[cfg(feature = "vless-vision")]
mod vless_vision {
    use super::*;
    use meow_proxy::{VlessAdapter, VlessFlow};
    use meow_transport::tls::{TlsConfig, TlsLayer};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Mutex;

    /// Collects the client's `tracing` output to show which Vision path ran.
    #[derive(Clone, Default)]
    struct LogSink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    fn pkcs8_key(key: &rcgen::KeyPair) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
    }

    /// TLS 1.3-only echo upstream.  Its ServerHello is what makes Xray and
    /// the client leave padding for DIRECT.
    async fn start_tls13_echo_server() -> (
        SocketAddr,
        CertificateDer<'static>,
        tokio::task::JoinHandle<()>,
    ) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], pkcs8_key(&ck.key_pair))
                .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let (mut rd, mut wr) = tokio::io::split(tls);
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                    let _ = wr.shutdown().await;
                });
            }
        });
        (addr, cert, handle)
    }

    /// Issue #495 item 5: Vision over plain (non-REALITY) TLS against a
    /// TLS 1.3 destination.  Both sides switch to the socket under the
    /// outer TLS after the inner handshake — Xray on its own once it sees
    /// the TLS 1.3 ServerHello — so the client must switch its BoringSSL
    /// stream both ways.  Before the fix the first inner app-data record
    /// failed with "DIRECT requested but transport cannot switch".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vless_vision_over_tls_to_tls13_target_against_xray() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let port = free_tcp_port();
        let outer = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem_lines = |pem: String| pem.lines().map(str::to_owned).collect::<Vec<_>>();
        let inbound = json!({
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": UUID, "flow": "xtls-rprx-vision" }],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "raw",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{
                        "certificate": pem_lines(outer.cert.pem()),
                        "key": pem_lines(outer.key_pair.serialize_pem()),
                    }],
                },
            },
        });
        let Some(server) = start_xray(port, inbound).await else {
            return;
        };
        let (target, target_cert, _target_h) = start_tls13_echo_server().await;

        let tls = TlsConfig {
            skip_cert_verify: true,
            ..TlsConfig::new("localhost")
        };
        let mut chain = TransportChain::empty();
        chain.push(Box::new(TlsLayer::new(&tls).expect("outer TLS layer")));
        let adapter = VlessAdapter::new(
            "docker-xray-vless-vision",
            "127.0.0.1",
            port,
            uuid_bytes(),
            Some(VlessFlow::XtlsRprxVision),
            false,
            chain,
            Arc::new(DirectDialer),
        );

        let mut roots = rustls::RootCertStore::empty();
        roots.add(target_cert).unwrap();
        let inner_cfg =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(inner_cfg));

        let logs = LogSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        // The client conn is polled on this thread only (`block_on`), so a
        // thread-local subscriber sees every Vision event.
        let guard = tracing::subscriber::set_default(subscriber);
        let conn = dial(&adapter, &metadata_for(target, Network::Tcp), &server).await;
        let inner = timeout(
            T,
            connector.connect(ServerName::try_from("localhost").unwrap(), conn),
        )
        .await
        .unwrap_or_else(|_| panic!("inner TLS handshake timed out\n{}", server.logs()))
        .unwrap_or_else(|e| panic!("inner TLS handshake failed: {e}\n{}", server.logs()));
        assert_eq!(
            inner.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        // 1 MiB each way: the bulk of it rides the raw socket.
        bulk_echo(inner, &patterned((1 << 20) + 777, 7), &server).await;
        drop(guard);

        let logs = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
        for event in [
            "XTLS Vision direct write passthrough enabled",
            "XTLS Vision direct passthrough enabled",
        ] {
            assert!(logs.contains(event), "no `{event}` in client logs:\n{logs}");
        }
    }
}
