//! End-to-end smoke test against a real Snell server.
//!
//! Gated behind the `SNELL_SMOKE` env var so CI doesn't dial anyone.
//! Example:
//!
//! ```bash
//! SNELL_SMOKE=1 SNELL_SERVER=82.40.35.29:63689 SNELL_PSK=... SNELL_VERSION=3 \
//!     SNELL_OBFS_MODE=http SNELL_OBFS_HOST=/ \
//!     cargo test -p meow-proxy --features snell --test snell_smoke -- --nocapture
//! ```
//!
//! For v6, `SNELL_VERSION=6` plus `SNELL_V6_MODE=default|unshaped|unsafe-raw`
//! (default `default`).

#![cfg(feature = "snell")]

use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::{SnellAdapter, SnellObfs, SnellV6Mode, SnellVersion};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn opt_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn split_server_addr(server_addr: &str) -> (&str, u16) {
    let (host, port) = server_addr
        .rsplit_once(':')
        .expect("SNELL_SERVER must be host:port");
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = port.parse().expect("SNELL_SERVER port must be a u16");
    (host, port)
}

fn parse_version() -> SnellVersion {
    match opt_env("SNELL_VERSION")
        .unwrap_or_else(|| "4".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "3" | "v3" => SnellVersion::V3,
        "4" | "v4" => SnellVersion::V4,
        "5" | "v5" => SnellVersion::V5,
        "6" | "v6" => SnellVersion::V6,
        other => panic!("SNELL_VERSION must be 3, 4, 5, or 6; got {other}"),
    }
}

fn parse_v6_mode() -> SnellV6Mode {
    let mode = opt_env("SNELL_V6_MODE").unwrap_or_default();
    SnellV6Mode::parse(mode.trim()).unwrap_or_else(|| {
        panic!("SNELL_V6_MODE must be default, unshaped, or unsafe-raw; got {mode}")
    })
}

fn parse_obfs(server_host: &str) -> SnellObfs {
    let mode = opt_env("SNELL_OBFS_MODE")
        .unwrap_or_else(|| "off".to_string())
        .trim()
        .to_ascii_lowercase();
    let host = opt_env("SNELL_OBFS_HOST").unwrap_or_else(|| server_host.to_string());
    match mode.as_str() {
        "" | "off" | "none" => SnellObfs::None,
        "http" => SnellObfs::Http { host },
        "tls" => SnellObfs::Tls { server: host },
        other => panic!("SNELL_OBFS_MODE must be off, http, or tls; got {other}"),
    }
}

fn bool_env(key: &str, default: bool) -> bool {
    opt_env(key).map_or(default, |v| {
        matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
    })
}

fn dns_query_for_example_com() -> Vec<u8> {
    let mut query = Vec::with_capacity(29);
    query.extend_from_slice(&[
        0x4d, 0x57, // ID
        0x01, 0x00, // standard recursive query
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ]);
    query.push(7);
    query.extend_from_slice(b"example");
    query.push(3);
    query.extend_from_slice(b"com");
    query.push(0);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    query
}

fn assert_dns_response(buf: &[u8]) {
    assert!(
        buf.len() >= 12,
        "DNS response too short: {} bytes",
        buf.len()
    );
    assert_eq!(&buf[..2], &[0x4d, 0x57], "DNS response ID mismatch");
    assert_ne!(buf[2] & 0x80, 0, "DNS response QR bit not set");
}

async fn verify_udp(adapter: &SnellAdapter) {
    let target: SocketAddr = opt_env("SNELL_UDP_TARGET")
        .unwrap_or_else(|| "1.1.1.1:53".to_string())
        .parse()
        .expect("SNELL_UDP_TARGET must be a SocketAddr");
    eprintln!("snell smoke: sending UDP DNS query via Snell to {target}");

    let metadata = Metadata {
        network: Network::Udp,
        ..Default::default()
    };
    let packet_conn = tokio::time::timeout(Duration::from_secs(10), adapter.dial_udp(&metadata))
        .await
        .expect("snell udp dial timeout")
        .expect("snell udp dial ok");

    let query = dns_query_for_example_com();
    tokio::time::timeout(
        Duration::from_secs(10),
        packet_conn.write_packet(&query, &target),
    )
    .await
    .expect("snell udp write timeout")
    .expect("snell udp write ok");

    let mut buf = [0u8; 1500];
    let (n, from) =
        tokio::time::timeout(Duration::from_secs(10), packet_conn.read_packet(&mut buf))
            .await
            .expect("snell udp read timeout")
            .expect("snell udp read ok");
    eprintln!("snell smoke: UDP response {n} bytes from {from}");
    assert_eq!(from.port(), target.port(), "UDP response port mismatch");
    assert_dns_response(&buf[..n]);
    packet_conn.close().expect("snell udp close ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snell_dial_real_server() {
    if opt_env("SNELL_SMOKE").is_none() {
        eprintln!("SNELL_SMOKE not set; skipping. Set it to run this test.");
        return;
    }
    let server_addr =
        opt_env("SNELL_SERVER").expect("SNELL_SERVER (host:port) required when SNELL_SMOKE=1");
    let psk = opt_env("SNELL_PSK").expect("SNELL_PSK required when SNELL_SMOKE=1");
    let (server_host, server_port) = split_server_addr(&server_addr);
    let version = parse_version();
    let obfs = parse_obfs(server_host);
    let udp = bool_env("SNELL_UDP", false);
    let reuse = bool_env("SNELL_REUSE", false);

    let target_host = opt_env("SNELL_TARGET_HOST").unwrap_or_else(|| "httpbin.org".to_string());
    let target_port: u16 = opt_env("SNELL_TARGET_PORT")
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let target_path = opt_env("SNELL_TARGET_PATH").unwrap_or_else(|| "/ip".to_string());

    eprintln!(
        "snell smoke: dialing {target_host}:{target_port} via {server_addr} \
         (version={} udp={udp} reuse={reuse})",
        version.as_str()
    );

    let adapter = SnellAdapter::new(
        "snell-smoke",
        server_host,
        server_port,
        &psk,
        obfs,
        version,
        udp,
        reuse,
        Arc::new(DirectDialer),
    )
    .expect("snell adapter config");
    let adapter = if version == SnellVersion::V6 {
        adapter
            .with_v6_mode(parse_v6_mode())
            .expect("snell v6 mode")
    } else {
        adapter
    };
    let metadata = Metadata {
        network: Network::Tcp,
        host: target_host.clone().into(),
        dst_port: target_port,
        ..Default::default()
    };
    let mut conn = tokio::time::timeout(Duration::from_secs(10), adapter.dial_tcp(&metadata))
        .await
        .expect("snell dial timeout")
        .expect("snell dial ok");

    // HTTP/1.0 GET.
    let request =
        format!("GET {target_path} HTTP/1.0\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
    conn.write_all(request.as_bytes())
        .await
        .expect("write http req");
    conn.flush().await.expect("flush http req");

    // Read up to 4 KiB; we read in a loop so a mid-stream snell error
    // doesn't discard the bytes we already have.
    let mut buf = Vec::with_capacity(4096);
    let mut scratch = [0u8; 1024];
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(10), conn.read(&mut scratch)).await {
            Err(_) => {
                eprintln!("read timed out after {} bytes", buf.len());
                break;
            }
            Ok(Err(e)) => {
                eprintln!("read error after {} bytes: {e}", buf.len());
                break;
            }
            Ok(Ok(0)) => {
                eprintln!("read EOF (snell zero-chunk) after {} bytes", buf.len());
                break;
            }
            Ok(Ok(n)) => n,
        };
        buf.extend_from_slice(&scratch[..n]);
        if buf.len() >= 4096 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    eprintln!("--- decoded server response (first 400 B) ---");
    eprintln!("{}", &head[..head.len().min(400)]);
    eprintln!("--- end ({} B total) ---", buf.len());
    assert!(
        head.starts_with("HTTP/1."),
        "expected HTTP response head, got: {:?}",
        &head[..head.len().min(80)]
    );

    if udp && bool_env("SNELL_VALIDATE_UDP", false) {
        verify_udp(&adapter).await;
    }
}
