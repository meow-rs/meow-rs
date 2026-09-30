#![cfg(feature = "snell")]

use async_trait::async_trait;
use meow_common::{Metadata, Network, ProxyAdapter, ProxyConn, ProxyPacketConn};
use meow_proxy::dialer::{DirectDialer, TcpDialer};
use meow_proxy::{SnellAdapter, SnellObfs, SnellV6Mode, SnellVersion};
use meow_transport::Stream;
use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{sleep, timeout, timeout_at, Duration, Instant};

const IMAGE_SNELL_V3: &str = "geekdada/snell-server:3.0.1";
const IMAGE_SNELL_V4: &str = "geekdada/snell-server:4.1.1";
const IMAGE_SNELL_V5: &str = "geekdada/snell-server:5.0.1";
const IMAGE_SNELL_V6: &str = "geekdada/snell-server:6.0.0rc2";
const PSK: &str = "meow-snell-docker-psk";
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

fn skip_or_panic(reason: impl AsRef<str>) -> bool {
    let reason = reason.as_ref();
    if docker_required() {
        panic!("{reason}");
    }
    eprintln!("skipping snell docker integration test: {reason}");
    false
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct SnellServer {
    _dir: TempDir,
    child: std::process::Child,
    log_path: PathBuf,
}

impl SnellServer {
    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for SnellServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ensure_snell_binary(dir: &Path, image: &str) -> Option<PathBuf> {
    // Tests in one binary run in parallel under the same pid; the counter
    // keeps their extraction containers apart.
    static EXTRACTIONS: AtomicUsize = AtomicUsize::new(0);

    let bin = dir.join("snell-server");
    if bin.exists() {
        return Some(bin);
    }

    let cached = Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !cached {
        let pull = Command::new("docker")
            .args(["pull", image])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if pull.is_err() || !pull.unwrap_or_default().success() {
            return None;
        }
    }

    let extract_name = format!(
        "meow-snell-extract-{}-{}",
        std::process::id(),
        EXTRACTIONS.fetch_add(1, Ordering::Relaxed)
    );
    let _ = Command::new("docker")
        .args(["rm", "-f", &extract_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let create = Command::new("docker")
        .args(["create", "--name", &extract_name, image])
        .output()
        .ok()?;
    if !create.status.success() {
        return None;
    }

    let copy = Command::new("docker")
        .args([
            "cp",
            &format!("{extract_name}:/usr/bin/snell-server"),
            &bin.to_string_lossy(),
        ])
        .output()
        .ok()?;
    let _ = Command::new("docker")
        .args(["rm", "-f", &extract_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !copy.status.success() {
        return None;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&bin) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&bin, perms);
        }
    }
    Some(bin)
}

/// `extra` carries the version-specific lines (`obfs = …` for v3,
/// `mode = …` for v6, which has no obfs setting).
fn write_server_config(dir: &Path, port: u16, extra: &str) -> PathBuf {
    let config_path = dir.join("snell-server.conf");
    let config = format!("[snell-server]\nlisten = 127.0.0.1:{port}\npsk = {PSK}\n{extra}");
    std::fs::write(&config_path, config).unwrap();
    config_path
}

fn start_snell_server(port: u16, image: &str, extra_config: &str) -> Option<SnellServer> {
    if !cfg!(target_os = "linux") {
        skip_or_panic("test requires Linux snell-server binary from Docker image");
        return None;
    }
    if !docker_available() {
        skip_or_panic("docker daemon is not available");
        return None;
    }

    let dir = TempDir::new().unwrap();
    let Some(snell_bin) = ensure_snell_binary(dir.path(), image) else {
        skip_or_panic(format!("failed to extract snell-server from {image}"));
        return None;
    };
    let config_path = write_server_config(dir.path(), port, extra_config);
    let log_path = dir.path().join("server.log");
    let log_file = match File::create(&log_path) {
        Ok(file) => file,
        Err(e) => {
            skip_or_panic(format!("failed to create snell-server log file: {e}"));
            return None;
        }
    };
    let stdout = log_file.try_clone().map_or(Stdio::null(), Stdio::from);
    let child = match Command::new(&snell_bin)
        .args(["-c", &config_path.to_string_lossy()])
        .stdout(stdout)
        .stderr(Stdio::from(log_file))
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            skip_or_panic(format!("failed to start snell-server process: {e}"));
            return None;
        }
    };

    Some(SnellServer {
        _dir: dir,
        child,
        log_path,
    })
}

/// v6 dials only open TCP (the request rides the first record), so a dial
/// succeeding says nothing about the server; probe the listener directly.
async fn wait_until_listening(server: &SnellServer, port: u16) {
    let deadline = Instant::now() + T;
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        assert!(
            Instant::now() < deadline,
            "snell-server never listened on {port}\n{}",
            server.logs()
        );
        sleep(Duration::from_millis(100)).await;
    }
}

async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
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

/// Upstream that answers only after the client's half-close: it reads to
/// EOF, then echoes everything back and closes.
async fn start_reply_after_eof_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                if stream.read_to_end(&mut request).await.is_ok() {
                    let _ = stream.write_all(&request).await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    (addr, handle)
}

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

/// Direct dialer that counts TCP dials, so reuse is observable end to end.
struct CountingDialer(Arc<AtomicUsize>);

#[async_trait]
impl TcpDialer for CountingDialer {
    async fn dial(
        &self,
        host: &str,
        port: u16,
        internal: bool,
    ) -> std::io::Result<Box<dyn Stream>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        DirectDialer.dial(host, port, internal).await
    }
}

fn counted_adapter(
    port: u16,
    version: SnellVersion,
    reuse: bool,
    dials: &Arc<AtomicUsize>,
) -> SnellAdapter {
    SnellAdapter::new(
        "docker-snell",
        "127.0.0.1",
        port,
        PSK,
        SnellObfs::None,
        version,
        true,
        reuse,
        Arc::new(CountingDialer(Arc::clone(dials))),
    )
    .expect("snell adapter must build")
}

fn v6_adapter(port: u16, mode: SnellV6Mode, reuse: bool, dials: &Arc<AtomicUsize>) -> SnellAdapter {
    counted_adapter(port, SnellVersion::V6, reuse, dials)
        .with_v6_mode(mode)
        .expect("snell v6 adapter must build")
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

/// Stream `payload` through an echo upstream with both directions in
/// flight, then half-close and expect a clean EOF.
async fn bulk_echo(mut conn: Box<dyn ProxyConn>, payload: &[u8], server: &SnellServer) {
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

/// Send `payload`, half-close, and expect the upstream's post-EOF reply.
async fn reply_after_eof(mut conn: Box<dyn ProxyConn>, payload: &[u8], server: &SnellServer) {
    timeout(T, conn.write_all(payload))
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

async fn wait_for_pool_size(adapter: &SnellAdapter, want: usize) {
    timeout(T, async {
        while adapter.idle_pool_size() < want {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reuse pool was not replenished in time");
}

async fn v6_round_trips(mode: SnellV6Mode) {
    let server_port = free_tcp_port();
    let Some(server) = start_snell_server(
        server_port,
        IMAGE_SNELL_V6,
        &format!("mode = {}\n", mode.as_str()),
    ) else {
        return;
    };
    wait_until_listening(&server, server_port).await;
    // Datagrams past the 16 KiB cap of earlier versions.
    fresh_round_trips(&server, 20_000, |reuse, dials| {
        v6_adapter(server_port, mode, reuse, dials)
    })
    .await;
    pooled_round_trips(&server, |reuse, dials| {
        v6_adapter(server_port, mode, reuse, dials)
    })
    .await;
}

/// v3–v5, whose servers take the `obfs` setting (off here) instead of a
/// `mode`.
async fn versioned_round_trips(image: &str, version: SnellVersion, max_datagram: usize) {
    let server_port = free_tcp_port();
    let Some(server) = start_snell_server(server_port, image, "obfs = off\n") else {
        return;
    };
    wait_until_listening(&server, server_port).await;
    fresh_round_trips(&server, max_datagram, |reuse, dials| {
        counted_adapter(server_port, version, reuse, dials)
    })
    .await;
}

/// Bulk echo, a reply the upstream sends only after the client's
/// half-close, and UDP up to `max_datagram` bytes — each session on a
/// connection of its own. `adapter(reuse, dials)` builds the client.
/// Echo one datagram of each length in `lens` through a UDP association.
/// UDP is best-effort, and the official v3.0.1 server now and then drops the
/// first datagram of an association on a busy host, so a datagram whose echo
/// does not arrive is resent with a fresh payload. A late echo of an earlier
/// payload is skipped; any other reply fails the test.
async fn udp_echo_round_trips(
    packets: &dyn ProxyPacketConn,
    echo: SocketAddr,
    lens: &[usize],
    server: &SnellServer,
) {
    const ATTEMPTS: u8 = 3;
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
    let mut buf = vec![0u8; 64 * 1024];
    let mut unanswered = Vec::new();
    'datagrams: for (i, &len) in (0u8..).zip(lens) {
        for attempt in 0..ATTEMPTS {
            let datagram = patterned(len, 3 + i * ATTEMPTS + attempt);
            timeout(T, packets.write_packet(&datagram, &echo))
                .await
                .expect("udp write timed out")
                .expect("udp write failed");
            let deadline = Instant::now() + ATTEMPT_TIMEOUT;
            while let Ok(read) = timeout_at(deadline, packets.read_packet(&mut buf)).await {
                let (n, src) = read.expect("udp read failed");
                assert_eq!(src, echo);
                if buf[..n] == datagram[..] {
                    continue 'datagrams;
                }
                assert!(
                    unanswered.iter().any(|sent: &Vec<u8>| buf[..n] == sent[..]),
                    "udp datagram of {len} B changed"
                );
            }
            unanswered.push(datagram);
        }
        panic!(
            "udp echo of {len} B timed out after {ATTEMPTS} attempts\n{}",
            server.logs()
        );
    }
}

async fn fresh_round_trips(
    server: &SnellServer,
    max_datagram: usize,
    adapter: impl Fn(bool, &Arc<AtomicUsize>) -> SnellAdapter,
) {
    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
    let (eof_reply, _eof_h) = start_reply_after_eof_server().await;
    let (udp_echo, _udp_h) = start_udp_echo_server().await;

    // Several records per direction, then the zero-chunk half-close.
    let dials = Arc::new(AtomicUsize::new(0));
    let fresh = adapter(false, &dials);
    let conn = timeout(T, fresh.dial_tcp(&metadata_for(tcp_echo, Network::Tcp)))
        .await
        .expect("dial timed out")
        .expect("dial failed");
    bulk_echo(conn, &patterned(300 * 1024, 1), server).await;
    let conn = timeout(T, fresh.dial_tcp(&metadata_for(eof_reply, Network::Tcp)))
        .await
        .expect("dial timed out")
        .expect("dial failed");
    reply_after_eof(conn, &patterned(90 * 1024, 2), server).await;

    let udp_md = metadata_for(udp_echo, Network::Udp);
    let packets = timeout(T, fresh.dial_udp(&udp_md))
        .await
        .expect("udp associate timed out")
        .unwrap_or_else(|e| panic!("udp associate failed: {e}\n{}", server.logs()));
    udp_echo_round_trips(&*packets, udp_echo, &[21, 1400, max_datagram], server).await;
    assert_eq!(dials.load(Ordering::SeqCst), 3, "one dial per session");
}

/// Four sessions over one pooled connection, including one that waits on
/// the upstream's post-EOF reply.
async fn pooled_round_trips(
    server: &SnellServer,
    adapter: impl Fn(bool, &Arc<AtomicUsize>) -> SnellAdapter,
) {
    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
    let (eof_reply, _eof_h) = start_reply_after_eof_server().await;
    let echo_md = metadata_for(tcp_echo, Network::Tcp);
    let eof_md = metadata_for(eof_reply, Network::Tcp);

    let dials = Arc::new(AtomicUsize::new(0));
    let pooled = adapter(true, &dials);
    for session in 0u8..4 {
        let md = if session == 2 { &eof_md } else { &echo_md };
        let conn = timeout(T, pooled.dial_tcp(md))
            .await
            .expect("dial timed out")
            .expect("dial failed");
        let payload = patterned(40 * 1024, 10 + session);
        if session == 2 {
            reply_after_eof(conn, &payload, server).await;
        } else {
            bulk_echo(conn, &payload, server).await;
        }
        wait_for_pool_size(&pooled, 1).await;
    }
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "sessions must share one connection\n{}",
        server.logs()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snell_v3_docker_round_trips() {
    versioned_round_trips(IMAGE_SNELL_V3, SnellVersion::V3, 16_000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snell_v4_docker_round_trips() {
    versioned_round_trips(IMAGE_SNELL_V4, SnellVersion::V4, 16_000).await;
}

/// A v5 server splits a reply bigger than its current record size (about
/// 5 KB on a fresh connection) across records, and a UDP response frame has
/// no length to reassemble it by, so datagrams stay below that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snell_v5_docker_round_trips() {
    versioned_round_trips(IMAGE_SNELL_V5, SnellVersion::V5, 4_000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snell_v6_docker_default_mode() {
    v6_round_trips(SnellV6Mode::Default).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snell_v6_docker_unshaped_mode() {
    v6_round_trips(SnellV6Mode::Unshaped).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snell_v6_docker_unsafe_raw_mode() {
    v6_round_trips(SnellV6Mode::UnsafeRaw).await;
}
