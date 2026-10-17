#![cfg(feature = "trusttunnel")]
//! Official TrustTunnel H2 endpoint interop. No ignored or implicit-skip legs.
//! `TRUSTTUNNEL_SERVER_BIN` must point to the official endpoint executable.
//! `MEOW_TRUSTTUNNEL_E2E_ALLOW_SKIP=1` permits a loud skip only outside CI.

use async_trait::async_trait;
use meow_common::{MeowError, Metadata, Network, ProxyAdapter};
use meow_proxy::{
    dialer::{DirectDialer, TcpDialer},
    trusttunnel::{CertificateVerificationError, Options, Transport, TrustTunnelAdapter},
};
use meow_transport::{tls::TlsConfig, Stream};
use std::{
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const WAIT: Duration = Duration::from_secs(10);

fn endpoint_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("TRUSTTUNNEL_SERVER_BIN") {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "TRUSTTUNNEL_SERVER_BIN is not a file: {path:?}"
        );
        return Some(path.canonicalize().expect("resolve endpoint executable"));
    }
    assert_eq!(
        std::env::var("MEOW_TRUSTTUNNEL_E2E_ALLOW_SKIP")
            .ok()
            .as_deref(),
        Some("1"),
        "trusttunnel_e2e requires TRUSTTUNNEL_SERVER_BIN; use \
         scripts/fetch-trusttunnel-endpoint.sh or explicitly set \
         MEOW_TRUSTTUNNEL_E2E_ALLOW_SKIP=1 for a local-only skip"
    );
    assert!(
        std::env::var_os("CI").is_none(),
        "CI must run the official TrustTunnel peer; skipping is local-only"
    );
    eprintln!("SKIP: trusttunnel_e2e — TRUSTTUNNEL_SERVER_BIN unset (local opt-in)");
    None
}

struct Endpoint {
    child: Child,
    directory: tempfile::TempDir,
    port: u16,
    certificate: Vec<u8>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("official endpoint console: {}", self.log());
            eprintln!(
                "official endpoint log: {}",
                fs::read_to_string(self.directory.path().join("endpoint.log")).unwrap_or_default()
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Endpoint {
    async fn start() -> Option<Self> {
        let binary = endpoint_binary()?;
        // The official process binds its own socket, so an ephemeral-port
        // reservation cannot be inherited. Retry only an explicit bind
        // collision, never authentication/protocol/startup failures.
        for attempt in 0..3 {
            let (endpoint, ready) = Self::start_once(&binary).await;
            if ready {
                return Some(endpoint);
            }
            let diagnostic = endpoint.log();
            let console =
                fs::read_to_string(endpoint.directory.path().join("endpoint-console.log"))
                    .unwrap_or_default();
            assert!(
                attempt < 2
                    && format!("{diagnostic} {console}")
                        .to_ascii_lowercase()
                        .contains("address already in use"),
                "official endpoint startup failed: {diagnostic} {console}"
            );
        }
        unreachable!("bounded startup attempts always return or panic")
    }

    async fn start_once(binary: &std::path::Path) -> (Self, bool) {
        let directory = tempfile::tempdir().unwrap();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(directory.path().join("cert.pem"), generated.cert.pem()).unwrap();
        fs::write(
            directory.path().join("key.pem"),
            generated.key_pair.serialize_pem(),
        )
        .unwrap();
        fs::write(
            directory.path().join("credentials.toml"),
            "[[client]]\nusername=\"fixture\"\npassword=\"test-password\"\n",
        )
        .unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        fs::write(
            directory.path().join("vpn.toml"),
            format!(
                // `listen_protocols.quic` is the official endpoint's
                // HTTP/3 codec; it binds UDP on the same port, which is
                // what the `quic: true` legs dial. Enabling both leaves
                // the HTTP/2 legs (and the TCP readiness probe) untouched.
                "listen_address=\"127.0.0.1:{port}\"\nallow_private_network_connections=true\n\
                 credentials_file=\"credentials.toml\"\n[listen_protocols.http2]\n\
                 initial_stream_window_size=131072\n[listen_protocols.quic]\n"
            ),
        )
        .unwrap();
        fs::write(
            directory.path().join("hosts.toml"),
            "[[main_hosts]]\nhostname=\"localhost\"\ncert_chain_path=\"cert.pem\"\n\
             private_key_path=\"key.pem\"\n",
        )
        .unwrap();
        let log = fs::File::create(directory.path().join("endpoint-console.log")).unwrap();
        let child = Command::new(binary)
            .args([
                "vpn.toml",
                "hosts.toml",
                "--jobs",
                "2",
                "--logfile",
                "endpoint.log",
            ])
            .current_dir(directory.path())
            .stdout(log.try_clone().unwrap())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn official TrustTunnel endpoint");
        let mut endpoint = Self {
            child,
            directory,
            port,
            certificate: generated.cert.der().to_vec(),
        };
        let ready = timeout(WAIT, async {
            loop {
                if endpoint.child.try_wait().unwrap().is_some() {
                    return false;
                }
                if TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .is_ok()
                {
                    return true;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or(false);
        (endpoint, ready)
    }

    fn log(&self) -> String {
        fs::read_to_string(self.directory.path().join("endpoint-console.log")).unwrap_or_default()
    }

    fn adapter(
        &self,
        password: &str,
        trust: bool,
        verify_name: &str,
        dialer: Arc<dyn TcpDialer>,
    ) -> TrustTunnelAdapter {
        let mut tls = TlsConfig::new("localhost");
        tls.verify_name = Some(verify_name.into());
        if trust {
            tls.additional_roots.push(self.certificate.clone());
        }
        let mut options = Options::new("fixture".into(), password.into());
        options.max_connections = 1;
        options.min_streams = 8;
        options.health_check = true; // Successful dials must first pass `_check`.
        TrustTunnelAdapter::new(
            "fixture",
            "127.0.0.1",
            self.port,
            tls,
            options,
            true,
            Transport::H2,
            dialer,
        )
        .unwrap()
    }

    /// The same endpoint over HTTP/3. Trust is expressed with
    /// `skip-cert-verify` rather than an extra root: the QUIC transport owns
    /// its socket and its verify store, and `certificate` / `ca` / `ca-str`
    /// are refused for this adapter at config load, so there is no
    /// additional-roots path to honour. `insecure: false` is therefore the
    /// leg that proves the quiche verifier still fails closed on this
    /// self-signed leaf.
    #[cfg(feature = "trusttunnel-h3")]
    fn h3_adapter(&self, password: &str, insecure: bool) -> TrustTunnelAdapter {
        let mut tls = TlsConfig::new("localhost");
        tls.skip_cert_verify = insecure;
        let mut options = Options::new("fixture".into(), password.into());
        options.max_connections = 1;
        options.min_streams = 8;
        options.health_check = true; // Successful dials must first pass `_check`.
        TrustTunnelAdapter::new(
            "fixture",
            "127.0.0.1",
            self.port,
            tls,
            options,
            true,
            Transport::H3,
            Arc::new(DirectDialer),
        )
        .unwrap()
    }
}

#[derive(Default)]
struct CountingDialer(AtomicUsize);

#[async_trait]
impl TcpDialer for CountingDialer {
    async fn dial(&self, host: &str, port: u16, internal: bool) -> io::Result<Box<dyn Stream>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        DirectDialer.dial(host, port, internal).await
    }
}

fn target(address: SocketAddr) -> Metadata {
    Metadata {
        dst_ip: Some(address.ip()),
        dst_port: address.port(),
        ..Default::default()
    }
}

#[tokio::test]
async fn official_h2_tcp_udp_check_pool_and_half_close() {
    let Some(endpoint) = Endpoint::start().await else {
        return;
    };
    let counter = Arc::new(CountingDialer::default());
    let dialer: Arc<dyn TcpDialer> = Arc::<CountingDialer>::clone(&counter);
    let proxy = endpoint.adapter("test-password", true, "localhost", dialer);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = vec![0; 256 * 1024];
        stream.read_exact(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut stream = proxy.dial_tcp(&target(address)).await.unwrap();
    let payload = vec![42; 256 * 1024];
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut received = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);
    echo.await.unwrap();

    for ipv6_encoded in [false, true] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = if ipv6_encoded {
            // v1.1.0 decodes ::1 as zero-padded 0.0.0.1. An IPv4-mapped
            // IPv6 address exercises its 16-byte IPv6 wire path using a
            // loopback peer without changing the host's interface addresses.
            SocketAddr::new(
                Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(),
                socket.local_addr().unwrap().port(),
            )
        } else {
            socket.local_addr().unwrap()
        };
        let echo = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            for _ in 0..3 {
                let (len, source) = socket.recv_from(&mut bytes).await.unwrap();
                socket.send_to(&bytes[..len], source).await.unwrap();
            }
        });
        let mut metadata = target(address);
        metadata.network = Network::Udp;
        metadata.src_ip = Some(if address.is_ipv6() {
            "2001:db8::1".parse().unwrap()
        } else {
            Ipv4Addr::new(192, 0, 2, 1).into()
        });
        metadata.src_port = 12345;
        let packet = proxy.dial_udp(&metadata).await.unwrap();
        for payload in [b"first".as_slice(), b"second", b"third"] {
            packet.write_packet(payload, &address).await.unwrap();
            let mut bytes = [0; 2048];
            let (len, source) = timeout(WAIT, packet.read_packet(&mut bytes))
                .await
                .unwrap()
                .unwrap_or_else(|error| panic!("UDP target {address}: {error}"));
            assert_eq!(source, address);
            assert_eq!(&bytes[..len], payload);
        }
        packet.close().unwrap();
        echo.await.unwrap();
    }
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        1,
        "TCP, UDP and _check share one TLS connection"
    );
}

#[tokio::test]
async fn official_h2_authentication_and_certificate_fail_closed() {
    let Some(endpoint) = Endpoint::start().await else {
        return;
    };
    let metadata = target("127.0.0.1:1".parse().unwrap());
    let error = endpoint
        .adapter("wrong-password", true, "localhost", Arc::new(DirectDialer))
        .dial_tcp(&metadata)
        .await
        .err()
        .unwrap();
    assert!(matches!(error, MeowError::ProxyAuthFailed));
    assert!(!error.to_string().contains("wrong-password"));
    for (trust, name) in [(false, "localhost"), (true, "wrong.example.test")] {
        let error = endpoint
            .adapter("test-password", trust, name, Arc::new(DirectDialer))
            .dial_tcp(&metadata)
            .await
            .err()
            .unwrap();
        let MeowError::Io(error) = error else {
            panic!("expected certificate IO failure")
        };
        let certificate = error
            .get_ref()
            .unwrap()
            .downcast_ref::<CertificateVerificationError>()
            .expect("official peer failure must retain X509 verification result");
        assert_eq!(certificate.code(), if trust { 62 } else { 18 });
    }
}

#[tokio::test]
async fn official_h2_slow_writer_isolation_and_reset() {
    let Some(endpoint) = Endpoint::start().await else {
        return;
    };
    let counter = Arc::new(CountingDialer::default());
    let dialer: Arc<dyn TcpDialer> = Arc::<CountingDialer>::clone(&counter);
    let proxy = endpoint.adapter("test-password", true, "localhost", dialer);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metadata = target(listener.local_addr().unwrap());
    let (accepted, receipt) = tokio::sync::oneshot::channel();
    let echo = tokio::spawn(async move {
        let (stalled, _) = listener.accept().await.unwrap();
        accepted.send(()).unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        drop(stalled);
    });
    let mut first = proxy.dial_tcp(&metadata).await.unwrap();
    timeout(WAIT, receipt).await.unwrap().unwrap();
    let stalled = tokio::spawn(async move { first.write_all(&vec![13; 16 * 1024 * 1024]).await });
    let mut second = proxy.dial_tcp(&metadata).await.unwrap();
    second.write_all(b"ping").await.unwrap();
    let mut bytes = [0; 4];
    timeout(WAIT, second.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"ping");
    stalled.abort();
    let _ = stalled.await;
    echo.await.unwrap();
    drop(second);
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metadata = target(listener.local_addr().unwrap());
    let peer = tokio::spawn(async move {
        let (_old, _) = listener.accept().await.unwrap();
        let (mut new, _) = listener.accept().await.unwrap();
        new.write_all(b"fresh").await.unwrap();
    });
    let mut old = proxy.dial_tcp(&metadata).await.unwrap();
    proxy.reset_sessions();
    assert!(timeout(WAIT, old.read(&mut [0; 1])).await.unwrap().is_err());
    let mut new = proxy.dial_tcp(&metadata).await.unwrap();
    let mut bytes = [0; 5];
    timeout(WAIT, new.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"fresh");
    assert_eq!(counter.0.load(Ordering::SeqCst), 2);
    peer.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn official_h2_concurrent_downloads_preserve_every_byte() {
    let Some(endpoint) = Endpoint::start().await else {
        return;
    };
    let proxy =
        Arc::new(endpoint.adapter("test-password", true, "localhost", Arc::new(DirectDialer)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    const STREAMS: usize = 4;
    const ROUNDS: usize = 2;
    const SIZE: usize = 2 * 1024 * 1024;
    let peer = tokio::spawn(async move {
        let mut writers = tokio::task::JoinSet::new();
        for _ in 0..STREAMS * ROUNDS {
            let (mut stream, _) = listener.accept().await.unwrap();
            writers.spawn(async move {
                let mut request = [0; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"bulk");
                let chunk = vec![42; 64 * 1024];
                for _ in 0..SIZE / chunk.len() {
                    stream.write_all(&chunk).await.unwrap();
                }
                stream.shutdown().await.unwrap();
            });
        }
        while let Some(result) = writers.join_next().await {
            result.unwrap();
        }
    });
    let mut readers = tokio::task::JoinSet::new();
    for _ in 0..STREAMS {
        let proxy = Arc::clone(&proxy);
        readers.spawn(async move {
            for _ in 0..ROUNDS {
                let mut stream = proxy.dial_tcp(&target(address)).await.unwrap();
                stream.write_all(b"bulk").await.unwrap();
                let mut bytes = Vec::new();
                timeout(WAIT, stream.read_to_end(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(bytes.len(), SIZE);
                assert!(bytes.iter().all(|byte| *byte == 42));
            }
        });
    }
    while let Some(result) = readers.join_next().await {
        result.unwrap();
    }
    peer.await.unwrap();
}

/// The same official endpoint over HTTP/3 (`[listen_protocols.quic]`): one
/// QUIC connection carrying `_check`, a tunnelled TCP stream and the `_udp2`
/// multiplexer, plus the two fail-closed paths. This is the only leg that
/// proves our quiche/HTTP/3 CONNECT is what the reference implementation
/// expects on the wire — a plain `:method`/`:authority` field section with no
/// `:scheme` and no `:path`, and the same length-prefixed UDP frames.
#[cfg(feature = "trusttunnel-h3")]
#[tokio::test]
async fn official_h3_tcp_udp_check_and_fail_closed_paths() {
    let Some(endpoint) = Endpoint::start().await else {
        return;
    };
    let proxy = endpoint.h3_adapter("test-password", true);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = vec![0; 256 * 1024];
        stream.read_exact(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut stream = proxy.dial_tcp(&target(address)).await.unwrap();
    let payload = vec![42; 256 * 1024];
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut received = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);
    echo.await.unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut bytes = [0; 2048];
        for _ in 0..3 {
            let (len, source) = socket.recv_from(&mut bytes).await.unwrap();
            socket.send_to(&bytes[..len], source).await.unwrap();
        }
    });
    let mut metadata = target(address);
    metadata.network = Network::Udp;
    metadata.src_ip = Some(Ipv4Addr::new(192, 0, 2, 1).into());
    metadata.src_port = 12345;
    let packet = proxy.dial_udp(&metadata).await.unwrap();
    for payload in [b"first".as_slice(), b"second", b"third"] {
        packet.write_packet(payload, &address).await.unwrap();
        let mut bytes = [0; 2048];
        let (len, source) = timeout(WAIT, packet.read_packet(&mut bytes))
            .await
            .unwrap()
            .unwrap_or_else(|error| panic!("UDP over HTTP/3: {error}"));
        assert_eq!(source, address);
        assert_eq!(&bytes[..len], payload);
    }
    packet.close().unwrap();
    echo.await.unwrap();

    // The QUIC connection that carried `_check`, a finished stream and the
    // datagram multiplexer is still the one the next dial reuses.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 5];
        stream.read_exact(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let mut reused = proxy.dial_tcp(&target(address)).await.unwrap();
    reused.write_all(b"again").await.unwrap();
    let mut bytes = [0; 5];
    timeout(WAIT, reused.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"again");
    echo.await.unwrap();

    let metadata = target("127.0.0.1:1".parse().unwrap());
    let error = endpoint
        .h3_adapter("wrong-password", true)
        .dial_tcp(&metadata)
        .await
        .err()
        .unwrap();
    assert!(matches!(error, MeowError::ProxyAuthFailed), "{error}");
    assert!(!error.to_string().contains("wrong-password"));

    // Verification on the QUIC path is real: the self-signed leaf is not in
    // the bundled root store, so a dial that does not opt out fails.
    let error = endpoint
        .h3_adapter("test-password", false)
        .dial_tcp(&metadata)
        .await
        .err()
        .unwrap();
    assert!(!matches!(error, MeowError::ProxyAuthFailed), "{error}");
}
