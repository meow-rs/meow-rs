#![cfg(feature = "ss")]
//! Integration tests for the Shadowsocks adapter.
//!
//! Requires `ssserver` (from shadowsocks-rust) to be installed and in PATH.
//! Tests are skipped automatically if `ssserver` is not available.

use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::ShadowsocksAdapter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Duration};

const SS_PASSWORD: &str = "test-password-1234";
const SS_CIPHER: &str = "aes-256-gcm";
const TIMEOUT: Duration = Duration::from_secs(10);

fn ssserver_available() -> bool {
    std::process::Command::new("ssserver")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn obfs_available() -> bool {
    std::process::Command::new("obfs-local")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
        && std::process::Command::new("obfs-server")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
}

fn obfs_server_available() -> bool {
    std::process::Command::new("obfs-server")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Returns true if `MIHOMO_REQUIRE_INTEGRATION_BINS=1` is set. CI exports this
/// so that integration tests must actually run instead of being silently
/// skipped when their helper binaries are missing.
fn require_integration_bins() -> bool {
    std::env::var("MIHOMO_REQUIRE_INTEGRATION_BINS")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Helper that either skips with a message (local dev) or hard-fails the test
/// (CI), depending on `MIHOMO_REQUIRE_INTEGRATION_BINS`.
#[track_caller]
fn skip_or_fail(reason: &str) {
    if require_integration_bins() {
        panic!("{reason} (MIHOMO_REQUIRE_INTEGRATION_BINS=1)");
    }
    eprintln!("SKIP: {reason}");
}

/// Start a TCP echo server that reads data and writes it back.
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

/// Start a UDP echo server that receives datagrams and sends them back.
async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    (addr, handle)
}

/// Start ssserver with the given port and target echo servers configured.
async fn start_ssserver(ss_port: u16) -> Child {
    start_ssserver_inner(ss_port, SS_CIPHER, SS_PASSWORD, None, None).await
}

/// Start ssserver with an explicit cipher + key (AEAD-2022 needs a base64
/// iPSK rather than the suite's shared password).
async fn start_ssserver_with_cipher(ss_port: u16, cipher: &str, key: &str) -> Child {
    start_ssserver_inner(ss_port, cipher, key, None, None).await
}

/// Start ssserver with an optional SIP003 plugin.
async fn start_ssserver_with_plugin(ss_port: u16, plugin: &str, plugin_opts: &str) -> Child {
    start_ssserver_inner(
        ss_port,
        SS_CIPHER,
        SS_PASSWORD,
        Some(plugin),
        Some(plugin_opts),
    )
    .await
}

async fn start_ssserver_inner(
    ss_port: u16,
    cipher: &str,
    password: &str,
    plugin: Option<&str>,
    plugin_opts: Option<&str>,
) -> Child {
    let mut args = vec![
        "-s".to_string(),
        format!("127.0.0.1:{}", ss_port),
        "-k".to_string(),
        password.to_string(),
        "-m".to_string(),
        cipher.to_string(),
        "-U".to_string(), // enable UDP relay
    ];
    if let Some(p) = plugin {
        args.push("--plugin".to_string());
        args.push(p.to_string());
    }
    if let Some(opts) = plugin_opts {
        args.push("--plugin-opts".to_string());
        args.push(opts.to_string());
    }

    // stderr is inherited on purpose: when ssserver dies on startup (e.g. a
    // port bind failure) the test otherwise fails with an opaque reset/EOF
    // and no clue why.
    let mut child = Command::new("ssserver")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start ssserver");

    // Wait for ssserver (or its SIP003 plugin, which owns the external port)
    // to be ready by attempting TCP connections. Plugin startup on a loaded CI
    // runner can be slow, so allow a generous window.
    for _ in 0..100 {
        if let Some(status) = child.try_wait().expect("ssserver try_wait failed") {
            panic!("ssserver exited during startup: {status}");
        }
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{ss_port}"))
            .await
            .is_ok()
        {
            // A successful connect only proves the TCP side is up; ssserver
            // still aborts moments later if e.g. its UDP bind (-U) fails.
            // Give it a beat and confirm it survived before handing it out.
            sleep(Duration::from_millis(50)).await;
            if let Some(status) = child.try_wait().expect("ssserver try_wait failed") {
                panic!("ssserver exited right after binding: {status}");
            }
            return child;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("ssserver did not become ready within 10 seconds");
}

/// Hand out server ports from a range *below* the Linux ephemeral range
/// (32768–60999), checked free by binding.
///
/// Ports must not come from `bind(":0")`: the port is released before
/// ssserver's plugin subprocess binds it (~100ms later), and during that
/// window the kernel can hand the same ephemeral port to a concurrent test's
/// `free_port()` or echo server. The readiness probe then connects to that
/// impostor listener and the test dials a port its own server never bound
/// (seen in CI as `Connection refused` / `UnexpectedEof` flakes). A
/// process-wide counter outside the ephemeral range makes in-process
/// collisions impossible; the bind check skips ports held by other processes.
///
/// Both TCP *and* UDP must be free: ssserver runs with `-U` and binds both on
/// the same port, and a UDP-only conflict kills it right after its TCP side
/// came up (seen in CI as `ConnectionReset` on the first write). The base is
/// staggered by PID so consecutive runs don't all contend on the same ports.
async fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT_OFFSET: AtomicU16 = AtomicU16::new(0);
    let base = 21000 + (std::process::id() % 500) as u16 * 16;
    loop {
        let offset = NEXT_OFFSET.fetch_add(1, Ordering::Relaxed);
        assert!(offset < 1000, "test port allocator exhausted");
        let port = base + offset;
        if TcpListener::bind(("127.0.0.1", port)).await.is_ok()
            && UdpSocket::bind(("127.0.0.1", port)).await.is_ok()
        {
            return port;
        }
    }
}

#[tokio::test]
async fn test_ss_tcp_relay() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }

    // Start echo server and ssserver
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver(ss_port).await;

    // Create adapter
    let adapter = ShadowsocksAdapter::new(
        "test-ss",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        None,
        None,
        Arc::new(DirectDialer),
    )
    .unwrap();

    // Build metadata pointing to the echo server
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial TCP through the SS proxy
    let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
    let mut conn = result
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Write and read back
    let payload = b"hello shadowsocks tcp";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");

    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch");

    // Second round
    let payload2 = b"second message";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");

    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(&buf2, payload2, "TCP echo mismatch round 2");
}

#[tokio::test]
async fn test_ss_udp_relay() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }

    // Start echo server and ssserver
    let (echo_addr, _echo_handle) = start_udp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver(ss_port).await;

    // Create adapter with UDP enabled
    let adapter = ShadowsocksAdapter::new(
        "test-ss",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        true,
        None,
        None,
        Arc::new(DirectDialer),
    )
    .unwrap();

    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial UDP through the SS proxy
    let result = timeout(TIMEOUT, adapter.dial_udp(&metadata)).await;
    let conn = result
        .expect("UDP dial timed out")
        .expect("UDP dial failed");

    // Write a packet and read it back
    let payload = b"hello shadowsocks udp";
    let written = conn
        .write_packet(payload, &echo_addr)
        .await
        .expect("UDP write_packet failed");
    assert_eq!(written, payload.len());

    let mut buf = vec![0u8; 65536];
    let read_result = timeout(TIMEOUT, conn.read_packet(&mut buf)).await;
    let (n, from_addr) = read_result
        .expect("UDP read timed out")
        .expect("UDP read_packet failed");
    assert_eq!(&buf[..n], payload, "UDP echo mismatch");
    assert_eq!(from_addr, echo_addr, "UDP source address mismatch");

    // Second round
    let payload2 = b"udp round two";
    conn.write_packet(payload2, &echo_addr)
        .await
        .expect("UDP write2 failed");

    let read_result2 = timeout(TIMEOUT, conn.read_packet(&mut buf)).await;
    let (n2, _) = read_result2
        .expect("UDP read2 timed out")
        .expect("UDP read_packet2 failed");
    assert_eq!(&buf[..n2], payload2, "UDP echo mismatch round 2");
}

/// AEAD-2022 UDP outbound against a real `ssserver` (SIP022 §3.2.2/§3.2.4).
///
/// The client must mint a session ID and count packet IDs up per session.
/// With the old all-zero control every datagram repeated
/// `(client_session_id=0, packet_id=0)` and the server's mandatory replay
/// filter dropped everything after the first packet — several echo rounds in
/// a row is exactly what that bug breaks.
#[tokio::test]
async fn test_ss_udp_relay_2022() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }

    // AEAD-2022 keys are base64 iPSKs, not arbitrary passwords — 16 bytes
    // for the aes-128-gcm variant ("1234567890123456").
    const CIPHER_2022: &str = "2022-blake3-aes-128-gcm";
    const PSK_2022: &str = "MTIzNDU2Nzg5MDEyMzQ1Ng==";

    let (echo_addr, _echo_handle) = start_udp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver_with_cipher(ss_port, CIPHER_2022, PSK_2022).await;

    let adapter = ShadowsocksAdapter::new(
        "test-ss-2022",
        "127.0.0.1",
        ss_port,
        PSK_2022,
        CIPHER_2022,
        true,
        None,
        None,
        Arc::new(DirectDialer),
    )
    .unwrap();

    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };
    let conn = timeout(TIMEOUT, adapter.dial_udp(&metadata))
        .await
        .expect("UDP dial timed out")
        .expect("UDP dial failed");

    let mut buf = vec![0u8; 65536];
    for round in 0..5u8 {
        let payload = format!("ss-2022 udp round {round}");
        conn.write_packet(payload.as_bytes(), &echo_addr)
            .await
            .expect("UDP write_packet failed");
        let (n, from_addr) = timeout(TIMEOUT, conn.read_packet(&mut buf))
            .await
            .expect("UDP read timed out — server replay filter may be dropping packets")
            .expect("UDP read_packet failed");
        assert_eq!(&buf[..n], payload.as_bytes(), "UDP echo mismatch");
        assert_eq!(from_addr, echo_addr, "UDP source address mismatch");
    }
}

#[tokio::test]
async fn test_ss_tcp_relay_with_obfs_plugin() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }
    if !obfs_available() {
        skip_or_fail("obfs-local/obfs-server not found in PATH");
        return;
    }

    // Start echo server and ssserver with obfs-server plugin
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver_with_plugin(ss_port, "obfs-server", "obfs=http").await;

    // Create adapter with obfs-local plugin (client side)
    let adapter = ShadowsocksAdapter::new(
        "test-ss-obfs",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("obfs-local"),
        Some("obfs=http"),
        Arc::new(DirectDialer),
    )
    .expect("failed to create adapter with obfs-local plugin");

    // Give the obfs-local plugin subprocess time to start listening
    sleep(Duration::from_secs(1)).await;

    // Build metadata pointing to the echo server
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial TCP through the SS proxy with obfs plugin
    let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
    let mut conn = result
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Write and read back
    let payload = b"hello shadowsocks obfs-http";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");

    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch through obfs plugin");

    // Second round
    let payload2 = b"obfs round two";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");

    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(
        &buf2, payload2,
        "TCP echo mismatch through obfs plugin round 2"
    );
}

/// End-to-end test for the *built-in* simple-obfs HTTP client. Uses
/// `obfs-server` on the server side (still external, since simple-obfs has no
/// server-side native impl) and the in-process `HttpObfs` wrapper on the
/// client side. Verifies wire compatibility with the reference Go protocol.
#[tokio::test]
async fn test_ss_tcp_relay_with_builtin_obfs_http() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }
    if !obfs_server_available() {
        skip_or_fail("obfs-server not found in PATH");
        return;
    }

    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver_with_plugin(ss_port, "obfs-server", "obfs=http").await;

    // Client uses the *built-in* simple-obfs HTTP plugin (no external binary).
    let adapter = ShadowsocksAdapter::new(
        "test-ss-builtin-obfs-http",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("obfs"),
        Some("mode=http;host=bing.com"),
        Arc::new(DirectDialer),
    )
    .expect("failed to create adapter with built-in obfs http");

    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Round 1
    let payload = b"hello shadowsocks built-in obfs-http";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch via built-in obfs-http");

    // Round 2 — exercises the post-handshake passthrough path.
    let payload2 = b"second message via builtin obfs";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");
    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(
        &buf2, payload2,
        "TCP echo round-2 mismatch via built-in obfs-http"
    );
}

/// Same as above, but for `mode=tls` simple-obfs.
#[tokio::test]
async fn test_ss_tcp_relay_with_builtin_obfs_tls() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }
    if !obfs_server_available() {
        skip_or_fail("obfs-server not found in PATH");
        return;
    }

    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver_with_plugin(ss_port, "obfs-server", "obfs=tls").await;

    let adapter = ShadowsocksAdapter::new(
        "test-ss-builtin-obfs-tls",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("obfs"),
        Some("mode=tls;host=cloudflare.com"),
        Arc::new(DirectDialer),
    )
    .expect("failed to create adapter with built-in obfs tls");

    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    let payload = b"hello shadowsocks built-in obfs-tls";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch via built-in obfs-tls");

    // Round 2 to exercise post-handshake framing.
    let payload2 = b"second message via builtin obfs-tls";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");
    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(
        &buf2, payload2,
        "TCP echo round-2 mismatch via built-in obfs-tls"
    );
}

// ─── Issue #570: relay-chain final hop (connect_over) ───────────────────────

/// `connect_over` must wrap the caller-supplied stream in SS crypto framing —
/// `ProxyClientStream` writes the target address encrypted, and ssserver
/// relays to the echo server.
#[tokio::test]
async fn test_ss_connect_over_runs_ss_handshake() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }

    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver(ss_port).await;

    let adapter = ShadowsocksAdapter::new(
        "test-ss-connect-over",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        None,
        None,
        Arc::new(DirectDialer),
    )
    .unwrap();

    // Relay hop-0 leg: plain TCP already connected to ssserver.
    let upstream = tokio::net::TcpStream::connect(format!("127.0.0.1:{ss_port}"))
        .await
        .expect("upstream connect");
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

    let payload = b"ss over relay-supplied stream";
    conn.write_all(payload).await.expect("write failed");
    conn.flush().await.expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.expect("read_exact failed");
    assert_eq!(&buf, payload, "echo mismatch through connect_over");
}

/// An external SIP003 plugin owns its own outbound connection — it cannot
/// consume a relay-supplied stream. `connect_over` must fail loudly with
/// `NotSupported` instead of silently dialing direct.
#[tokio::test]
async fn test_ss_connect_over_external_plugin_not_supported() {
    if !obfs_available() {
        skip_or_fail("obfs-local not found in PATH");
        return;
    }

    // obfs-local only needs to *start*; connect_over must reject before any
    // traffic, so point it at a throwaway listener — the plugin binds its own
    // loopback listener regardless.
    let dead_end = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ss_port = dead_end.local_addr().unwrap().port();
    let adapter = ShadowsocksAdapter::new(
        "test-ss-ext-plugin",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("obfs-local"),
        Some("obfs=http"),
        Arc::new(DirectDialer),
    )
    .expect("adapter with external plugin must construct");

    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: 443,
        ..Default::default()
    };
    let upstream = tokio::net::TcpStream::connect(format!("127.0.0.1:{ss_port}"))
        .await
        .expect("upstream connect");

    match adapter.connect_over(Box::new(upstream), &metadata).await {
        Err(meow_common::MeowError::NotSupported(_)) => {}
        Err(other) => panic!("expected NotSupported, got {other:?}"),
        Ok(_) => panic!("external SIP003 plugin must not support connect_over"),
    }
}

/// `connect_over` with the *built-in* simple-obfs plugin must wrap the
/// supplied stream in HTTP obfs before SS crypto — the server-side
/// `obfs-server` unwraps it. Same wire path as the external plugin, but the
/// stream ownership stays in-process so connect_over works.
#[tokio::test]
async fn test_ss_connect_over_builtin_obfs_http() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }
    if !obfs_server_available() {
        skip_or_fail("obfs-server not found in PATH");
        return;
    }

    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver_with_plugin(ss_port, "obfs-server", "obfs=http").await;

    let adapter = ShadowsocksAdapter::new(
        "test-ss-co-builtin-obfs",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("obfs"),
        Some("obfs=http"),
        Arc::new(DirectDialer),
    )
    .expect("failed to create adapter with built-in obfs");

    let upstream = tokio::net::TcpStream::connect(format!("127.0.0.1:{ss_port}"))
        .await
        .expect("upstream connect");
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

    let payload = b"ss+builtin-obfs over relay-supplied stream";
    conn.write_all(payload).await.expect("write failed");
    conn.flush().await.expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.expect("read_exact failed");
    assert_eq!(&buf, payload, "echo mismatch through obfs connect_over");
}
