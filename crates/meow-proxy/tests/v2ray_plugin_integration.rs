#![cfg(feature = "ss")]
//! Real-peer interop for the built-in `v2ray-plugin` transport:
//!
//!   meow-rs ShadowsocksAdapter  --ws-->  v2ray-plugin server  -->  ssserver  -->  TCP echo
//!
//! The server is an official v2ray-plugin release that `ssserver` runs as
//! its SIP003 plugin. Legs:
//!   - a server with default options, which demultiplexes every
//!     connection as Mux.Cool, against the client's default (`mux` on):
//!     plain WebSocket, TLS, a bulk transfer and a half-close;
//!   - a `mux=0` server, which expects the stream raw, against a `mux=0`
//!     client: plain WebSocket and TLS;
//!   - a raw client against a default server, which must not get through.
//!
//! Needs `V2RAY_PLUGIN_BIN`, the path of an official release binary
//! (`bash scripts/fetch-v2ray-plugin.sh <dir>` puts one at
//! `<dir>/v2ray-plugin`), and `ssserver` (shadowsocks-rust) on `PATH`.
//! Without them the suite fails; `MEOW_V2RAY_PLUGIN_E2E_ALLOW_SKIP=1`
//! prints a loud skip for local runs only, and CI never sets it.

use meow_common::{Metadata, Network, ProxyAdapter, ProxyConn};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::ShadowsocksAdapter;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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

/// The official v2ray-plugin binary, or `None` for an allowed local skip.
fn plugin_binary() -> Option<PathBuf> {
    let missing = match std::env::var_os("V2RAY_PLUGIN_BIN").map(PathBuf::from) {
        Some(path) => {
            assert!(path.is_file(), "V2RAY_PLUGIN_BIN is not a file: {path:?}");
            if ssserver_available() {
                return Some(path);
            }
            "ssserver (shadowsocks-rust) is not on PATH"
        }
        None => "V2RAY_PLUGIN_BIN is unset",
    };
    assert_eq!(
        std::env::var("MEOW_V2RAY_PLUGIN_E2E_ALLOW_SKIP")
            .ok()
            .as_deref(),
        Some("1"),
        "v2ray_plugin_integration needs a real v2ray-plugin server: {missing}. \
         Run `bash scripts/fetch-v2ray-plugin.sh <dir>`, export \
         V2RAY_PLUGIN_BIN=<dir>/v2ray-plugin and install ssserver, or set \
         MEOW_V2RAY_PLUGIN_E2E_ALLOW_SKIP=1 to skip locally"
    );
    assert!(
        std::env::var_os("CI").is_none(),
        "CI must run the real v2ray-plugin peer; skipping is local-only"
    );
    eprintln!(
        "SKIP: v2ray_plugin_integration — {missing} \
         (MEOW_V2RAY_PLUGIN_E2E_ALLOW_SKIP=1, local only)"
    );
    None
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 16 * 1024];
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

/// Reads `len` bytes, waits `delay`, sends them back and closes: the reply
/// comes well after the client is done sending.
async fn start_delayed_echo_server(
    len: usize,
    delay: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; len];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                sleep(delay).await;
                let _ = stream.write_all(&buf).await;
            });
        }
    });
    (addr, handle)
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn start_ssserver_with_plugin(ss_port: u16, plugin: &Path, plugin_opts: &str) -> Child {
    let child = Command::new("ssserver")
        .arg("-s")
        .arg(format!("127.0.0.1:{ss_port}"))
        .args(["-k", SS_PASSWORD, "-m", SS_CIPHER])
        .arg("--plugin")
        .arg(plugin)
        .args(["--plugin-opts", plugin_opts])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start ssserver");

    // Give ssserver + its plugin subprocess time to listen on `ss_port`.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{ss_port}"))
            .await
            .is_ok()
        {
            return child;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("ssserver did not become ready within 5 seconds");
}

/// Generate a self-signed cert for `common_name` and return two
/// `NamedTempFile`s (cert PEM, key PEM). Keeping the handles alive keeps
/// the files on disk for the duration of the test.
fn generate_self_signed_pem(common_name: &str) -> (NamedTempFile, NamedTempFile) {
    let ck = rcgen::generate_simple_self_signed(vec![common_name.to_string()])
        .expect("self-signed cert");
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();

    let mut cert_file = NamedTempFile::new().expect("cert tempfile");
    cert_file
        .write_all(cert_pem.as_bytes())
        .expect("write cert pem");
    cert_file.flush().unwrap();

    let mut key_file = NamedTempFile::new().expect("key tempfile");
    key_file
        .write_all(key_pem.as_bytes())
        .expect("write key pem");
    key_file.flush().unwrap();

    (cert_file, key_file)
}

/// The server's `cert=…;key=…` opts for a fresh self-signed
/// `example.com` certificate; keep the files alive while the server runs.
fn tls_files() -> (String, NamedTempFile, NamedTempFile) {
    install_crypto_provider();
    let (cert_file, key_file) = generate_self_signed_pem("example.com");
    let opts = format!(
        "cert={};key={}",
        cert_file.path().to_str().unwrap(),
        key_file.path().to_str().unwrap()
    );
    (opts, cert_file, key_file)
}

fn adapter(name: &str, ss_port: u16, client_opts: &str) -> ShadowsocksAdapter {
    ShadowsocksAdapter::new(
        name,
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("v2ray-plugin"),
        Some(client_opts),
        None,
        Arc::new(DirectDialer),
    )
    .expect("failed to create adapter with built-in v2ray-plugin")
}

async fn dial(adapter: &ShadowsocksAdapter, target: SocketAddr) -> Box<dyn ProxyConn> {
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: target.port(),
        ..Default::default()
    };
    timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial_tcp timed out")
        .expect("dial_tcp failed")
}

async fn run_roundtrip(adapter: &ShadowsocksAdapter, echo_addr: SocketAddr) {
    let mut conn = dial(adapter, echo_addr).await;
    for payload in [&b"hello v2ray-plugin"[..], b"round two payload"] {
        conn.write_all(payload).await.expect("write failed");
        conn.flush().await.expect("flush failed");
        let mut buf = vec![0u8; payload.len()];
        timeout(TIMEOUT, conn.read_exact(&mut buf))
            .await
            .expect("echo timed out")
            .expect("read_exact failed");
        assert_eq!(buf, payload, "echo mismatch");
    }
}

#[tokio::test]
async fn mux_default_server_websocket() {
    let Some(plugin) = plugin_binary() else {
        return;
    };
    let (echo_addr, _echo) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver =
        start_ssserver_with_plugin(ss_port, &plugin, "server;host=example.com;path=/ws").await;

    // No `mux` key: on by default, like the upstream client.
    let adapter = adapter(
        "v2ray-mux",
        ss_port,
        "mode=websocket;host=example.com;path=/ws",
    );
    run_roundtrip(&adapter, echo_addr).await;
}

#[tokio::test]
async fn mux_default_server_tls_websocket() {
    let Some(plugin) = plugin_binary() else {
        return;
    };
    let (cert_opts, _cert, _key) = tls_files();
    let (echo_addr, _echo) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let server_opts = format!("server;tls;host=example.com;path=/ws;{cert_opts}");
    let _ssserver = start_ssserver_with_plugin(ss_port, &plugin, &server_opts).await;

    // `mux=true` is how a mihomo-style `plugin-opts: {mux: true}` arrives.
    let adapter = adapter(
        "v2ray-mux-tls",
        ss_port,
        "mode=websocket;tls;mux=true;host=example.com;path=/ws;skip-cert-verify=true",
    );
    run_roundtrip(&adapter, echo_addr).await;
}

/// A megabyte each way, written while the echo is read back: many full
/// Keep frames in both directions, split and reassembled across WebSocket
/// messages.
#[tokio::test]
async fn mux_default_server_bulk_transfer() {
    let Some(plugin) = plugin_binary() else {
        return;
    };
    let (echo_addr, _echo) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver =
        start_ssserver_with_plugin(ss_port, &plugin, "server;host=example.com;path=/ws").await;
    let adapter = adapter("v2ray-mux-bulk", ss_port, "host=example.com;path=/ws");

    let data: Vec<u8> = (0..1024 * 1024).map(|i: u32| (i % 251) as u8).collect();
    let conn = dial(&adapter, echo_addr).await;
    let (mut rd, mut wr) = tokio::io::split(conn);
    let send = async {
        // The shadowsocks crate sends at most one AEAD chunk (16 KiB) of
        // the first write, so open with a small one, as a relay does; the
        // rest goes in chunks of 16 KiB, which the framing splits at 8 KiB.
        let (first, rest) = data.split_at(1024);
        wr.write_all(first).await?;
        wr.write_all(rest).await?;
        wr.flush().await
    };
    let mut back = vec![0u8; data.len()];
    let recv = rd.read_exact(&mut back);
    let (sent, received) = timeout(TIMEOUT, async { tokio::join!(send, recv) })
        .await
        .expect("bulk echo timed out");
    sent.expect("bulk write failed");
    received.expect("bulk read failed");
    assert!(back == data, "bulk echo mismatch");
}

/// Shutting down the write side ends our half of the session only: a
/// reply the target sends after that still arrives, then EOF.
#[tokio::test]
async fn mux_default_server_half_close_keeps_the_reply() {
    let Some(plugin) = plugin_binary() else {
        return;
    };
    let payload = b"reply after my FIN";
    let (echo_addr, _echo) =
        start_delayed_echo_server(payload.len(), Duration::from_millis(300)).await;
    let ss_port = free_port().await;
    let _ssserver =
        start_ssserver_with_plugin(ss_port, &plugin, "server;host=example.com;path=/ws").await;
    let adapter = adapter("v2ray-mux-half-close", ss_port, "host=example.com;path=/ws");

    let mut conn = dial(&adapter, echo_addr).await;
    conn.write_all(payload).await.expect("write failed");
    conn.shutdown().await.expect("shutdown failed");
    let mut reply = Vec::new();
    timeout(TIMEOUT, conn.read_to_end(&mut reply))
        .await
        .expect("reply timed out")
        .expect("read_to_end failed");
    assert_eq!(reply, payload);
}

#[tokio::test]
async fn raw_mux0_server_websocket() {
    let Some(plugin) = plugin_binary() else {
        return;
    };
    let (echo_addr, _echo) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver =
        start_ssserver_with_plugin(ss_port, &plugin, "server;mux=0;host=example.com;path=/ws")
            .await;

    let adapter = adapter(
        "v2ray-raw",
        ss_port,
        "mode=websocket;mux=0;host=example.com;path=/ws",
    );
    run_roundtrip(&adapter, echo_addr).await;
}

#[tokio::test]
async fn raw_mux0_server_tls_websocket() {
    let Some(plugin) = plugin_binary() else {
        return;
    };
    let (cert_opts, _cert, _key) = tls_files();
    let (echo_addr, _echo) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let server_opts = format!("server;tls;mux=0;host=example.com;path=/ws;{cert_opts}");
    let _ssserver = start_ssserver_with_plugin(ss_port, &plugin, &server_opts).await;

    // `mux=false` is how a mihomo-style `plugin-opts: {mux: false}` arrives.
    let adapter = adapter(
        "v2ray-raw-tls",
        ss_port,
        "mode=websocket;tls;mux=false;host=example.com;path=/ws;skip-cert-verify=true",
    );
    run_roundtrip(&adapter, echo_addr).await;
}

/// The bug this suite guards: a raw stream to a server with default
/// options never gets an echo (the server reads the Shadowsocks salt as a
/// Mux.Cool frame header and drops the connection).
#[tokio::test]
async fn raw_client_gets_nothing_from_a_default_server() {
    let Some(plugin) = plugin_binary() else {
        return;
    };
    let (echo_addr, _echo) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver =
        start_ssserver_with_plugin(ss_port, &plugin, "server;host=example.com;path=/ws").await;
    let adapter = adapter(
        "v2ray-raw-vs-mux",
        ss_port,
        "mux=0;host=example.com;path=/ws",
    );

    let mut conn = dial(&adapter, echo_addr).await;
    let payload = b"never echoed";
    // The write may already fail once the server has dropped us.
    let _ = conn.write_all(payload).await;
    let _ = conn.flush().await;
    let mut buf = vec![0u8; payload.len()];
    let echoed = matches!(
        timeout(Duration::from_secs(3), conn.read_exact(&mut buf)).await,
        Ok(Ok(_))
    );
    assert!(!echoed, "a raw client must not get through a mux server");
}
