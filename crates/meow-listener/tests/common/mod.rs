//! Shared test helpers for meow-listener integration tests.
//!
//! Each integration test binary compiles this module independently, so a
//! helper used by only some of them looks "dead" to the others.
#![allow(dead_code)]

use meow_common::DnsMode;
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Build a minimal `Tunnel` in `Direct` mode (no rules, no extra proxies).
///
/// `TunnelMode::Direct` routes every connection through the built-in
/// `DirectAdapter`, which does a real TCP dial to whatever address the
/// client requested. Tests should target a locally-bound echo server.
pub fn direct_tunnel() -> Tunnel {
    let hosts = DomainTrie::new();
    let resolver = Arc::new(Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        hosts,
        false,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    tunnel.set_mode(meow_common::TunnelMode::Direct);
    tunnel
}

/// Build a `Tunnel` in fake-IP mode, synthesise a fake IP for `host`, and seed
/// the resolver cache so `host` resolves back to `real_ip` on the dial path.
///
/// Returns `(tunnel, fake_ip)`. A SOCKS5 client that CONNECTs to `fake_ip`
/// should reach `real_ip` **iff** the listener reverse-maps the fake IP to
/// `host` before dialing (see `pre_handle_metadata`). Direct mode keeps rule
/// matching out of the picture so the test isolates the reverse-map step.
pub async fn fakeip_tunnel(host: &str, real_ip: std::net::IpAddr) -> (Tunnel, std::net::IpAddr) {
    use ipnet::IpNet;
    use meow_dns::fakeip::{MemoryStore, Pool};
    use std::time::Duration;

    let mut resolver = Resolver::new(
        vec![],
        vec![],
        DnsMode::FakeIp,
        DomainTrie::new(),
        true,
        true,
    );
    let net = "198.18.0.0/16".parse::<IpNet>().unwrap();
    resolver.set_fakeip_v4(Arc::new(
        Pool::new(net, Arc::new(MemoryStore::new(1024))).unwrap(),
    ));
    let resolver = Arc::new(resolver);

    // Synthesise the fake IP first (cache empty for `host`), which records the
    // fake-IP → host reverse mapping the listener will later recover.
    let fake = resolver.lookup_ipv4(host).await.unwrap();
    assert!(resolver.is_fake_ip(fake), "expected a fake IP, got {fake}");

    // Then seed the forward cache so the reverse-mapped host dials `real_ip`.
    resolver.preload_cache(host, &[real_ip], Duration::from_secs(300));

    let tunnel = Tunnel::new(resolver);
    tunnel.set_mode(meow_common::TunnelMode::Direct);
    (tunnel, fake)
}

/// Spawn a local echo server that accepts one connection, echoes all bytes
/// back, then exits.  Returns the bound `SocketAddr`.
pub async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 4096];
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
    addr
}

/// Spawn a minimal HTTP origin that reads one request head through
/// `\r\n\r\n` and answers a fixed `200 OK`. Unlike `spawn_echo_server`
/// (which reflects the forwarded `GET` request line — bytes that are not
/// a response status line), this lets a plain-HTTP relay test assert a
/// real `200` round-trip.
pub async fn spawn_http_ok_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf[len..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            });
        }
    });
    addr
}

/// Spawn the upstream HTTP proxy mock: counts accepts, answers every
/// CONNECT with 200, then echoes.
pub async fn spawn_counting_http_upstream(
) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf[len..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                if stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, accepts)
}

/// Issue #734 harness: the issue's config (`DOMAIN,evil.com,REJECT`, then
/// `MATCH,proxy` where `proxy` is an `http` upstream), routed at a local
/// mock whose accept count shows whether any flow reached the upstream.
pub async fn issue_734_tunnel() -> (meow_tunnel::Tunnel, Arc<std::sync::atomic::AtomicUsize>) {
    let (upstream, accepts) = spawn_counting_http_upstream().await;
    let yaml = format!(
        "proxies:\n  - name: proxy\n    type: http\n    server: 127.0.0.1\n    port: {}\n\
         rules:\n  - DOMAIN,evil.com,REJECT\n  - MATCH,proxy\n",
        upstream.port()
    );
    let raw = meow_config::parse_raw_yaml(&yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).unwrap();
    let tunnel = direct_tunnel();
    tunnel.set_mode(meow_common::TunnelMode::Rule);
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.update_rules(res.rules);
    (tunnel, accepts)
}
