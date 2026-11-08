#![cfg(feature = "gost-plugin")]
//! Real-server integration test for the built-in `gost-plugin` transport.
//!
//!   meow-rs ShadowsocksAdapter  --ws+smux-->  gost `ss+mws` listener  -->  TCP echo
//!
//! Requires a real `gost` binary (`$GOST_BIN` overrides, otherwise `gost`
//! on PATH). The `ss+mws` listener is exactly what mihomo's built-in
//! gost-plugin client targets: WebSocket transport with a single-stream
//! smux v1 session — so a green run proves third-party wire interop, not
//! just self-consistency of meow's own codec.
//!
//! When the binary is missing the test emits a loud `SKIP:` line and
//! passes, matching `v2ray_plugin_integration.rs`.

use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::ShadowsocksAdapter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Duration};

const SS_PASSWORD: &str = "test-password-1234";
const SS_CIPHER: &str = "aes-256-gcm";
const TIMEOUT: Duration = Duration::from_secs(10);

/// `$GOST_BIN` overrides; otherwise `gost` must be on PATH.
fn gost_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("GOST_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        panic!("GOST_BIN is set but does not point at a file: {path:?}");
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let exe = if cfg!(windows) {
            dir.join("gost.exe")
        } else {
            dir.join("gost")
        };
        if exe.is_file() {
            return Some(exe);
        }
    }
    None
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

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// `gost -L "ss+mws://cipher:pass@127.0.0.1:port?path=/ws"` — the upstream
/// mux-websocket SS listener (see the gost-plugin / mihomo docs).
async fn start_gost_mws(gost: &PathBuf, port: u16) -> Child {
    let spec = format!("ss+mws://{SS_CIPHER}:{SS_PASSWORD}@127.0.0.1:{port}?path=/ws");
    let child = Command::new(gost)
        .args(["-L", &spec])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start gost");

    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            return child;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("gost did not become ready within 5 seconds");
}

#[tokio::test]
async fn test_ss_gost_plugin_ws_mux_real_server() {
    let Some(gost) = gost_binary() else {
        eprintln!("SKIP: gost binary not found ($GOST_BIN unset, `gost` not on PATH)");
        return;
    };

    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let gost_port = free_port().await;
    let _gost = start_gost_mws(&gost, gost_port).await;

    let adapter = ShadowsocksAdapter::new(
        "test-ss-gost-ws-mux",
        "127.0.0.1",
        gost_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("gost-plugin"),
        Some("mode=websocket;mux=true;host=bing.com;path=/ws"),
        None,
        Arc::new(DirectDialer),
    )
    .expect("failed to create adapter with built-in gost-plugin");

    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial_tcp timed out")
        .expect("dial_tcp failed");

    // Two round trips across the smux-framed websocket stream.
    let payload = b"hello gost-plugin";
    conn.write_all(payload).await.expect("write failed");
    conn.flush().await.expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.expect("read_exact failed");
    assert_eq!(&buf, payload, "echo mismatch");

    let payload2 = b"round two payload";
    conn.write_all(payload2).await.expect("write2 failed");
    conn.flush().await.expect("flush2 failed");
    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("read_exact2 failed");
    assert_eq!(&buf2, payload2, "echo mismatch round 2");
}
