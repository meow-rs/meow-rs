//! Issue #734: a listener-supplied destination host that is not a hostname
//! must be refused at ingress, undialed.
//!
//! The harness mirrors the issue's config: `DOMAIN,evil.com,REJECT` then
//! `MATCH,proxy`, where `proxy` is an `http` upstream (a local mock that
//! counts accepted connections). Before the fix `a@evil.com` missed the
//! DOMAIN rule, fell to MATCH, and the adapter wrote
//! `CONNECT a@evil.com:443`, which the peer parses as host `evil.com`.
#![cfg(all(feature = "listener-http", feature = "listener-socks5"))]

mod common;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The bypass hosts from the issue plus the other non-hostname bytes.
const BAD_HOSTS: &[&str] = &[
    "a@evil.com",
    "user:pass@evil.com",
    "evil.com/x",
    "evil.com?q=1",
    "evil.com#f",
    "evil%2ecom",
];

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    (accepted.unwrap().0, connected.unwrap())
}

/// Drive one HTTP proxy request; returns the response head the listener
/// wrote (or whatever arrived before it closed).
async fn http_exchange(tunnel: &meow_tunnel::Tunnel, request: &[u8]) -> Vec<u8> {
    let (server, mut client) = loopback_pair().await;
    let tunnel = tunnel.clone();
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    tokio::spawn(async move {
        meow_listener::http_proxy::handle_http(&tunnel, server, src, None, None, "http", 0).await;
    });
    client.write_all(request).await.unwrap();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    while let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(500), client.read(&mut buf)).await
    {
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    response
}

/// Drive one SOCKS5 CONNECT to an `ATYP_DOMAIN` target; returns the
/// 10-byte CONNECT reply.
async fn socks5_connect_domain(tunnel: &meow_tunnel::Tunnel, host: &[u8]) -> [u8; 10] {
    let (server, mut client) = loopback_pair().await;
    let tunnel = tunnel.clone();
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    tokio::spawn(async move {
        meow_listener::socks5::handle_socks5(&tunnel, server, src, None, None, "socks", 0).await;
    });
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut req = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    req.extend_from_slice(host);
    req.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
        .await
        .expect("SOCKS5 reply timed out")
        .unwrap();
    reply
}

/// Give a wrongly-spawned dial time to land before asserting it did not.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn http_connect_with_non_hostname_target_is_400_and_undialed() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;

    // Positive control: a normal name goes through MATCH,proxy.
    let ok = http_exchange(&tunnel, b"CONNECT good.example:443 HTTP/1.1\r\n\r\n").await;
    assert!(
        ok.starts_with(b"HTTP/1.1 200"),
        "{:?}",
        String::from_utf8_lossy(&ok)
    );
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "control must reach the upstream"
    );

    for host in BAD_HOSTS {
        let request = format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n");
        let response = http_exchange(&tunnel, request.as_bytes()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
            "{host:?}: {:?}",
            String::from_utf8_lossy(&response)
        );
    }
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "no non-hostname CONNECT may reach the upstream"
    );
}

#[tokio::test]
async fn http_absolute_form_with_non_hostname_authority_is_400_and_undialed() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    // `/`, `?` and `#` end the authority in absolute-form, so those cases
    // name `evil.com` itself: the DOMAIN rule must see that and REJECT.
    for target in [
        "http://evil.com/x",
        "http://evil.com?q=1",
        "http://evil.com:80?q",
    ] {
        let request = format!("GET {target} HTTP/1.1\r\nHost: evil.com\r\n\r\n");
        let response = http_exchange(&tunnel, request.as_bytes()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
            "{target:?} must hit DOMAIN,evil.com,REJECT: {:?}",
            String::from_utf8_lossy(&response)
        );
    }
    for host in [
        "a@evil.com",
        "user:pass@evil.com",
        "evil%2ecom",
        "evil.com:443:443",
    ] {
        let request = format!("GET http://{host}/ HTTP/1.1\r\nHost: evil.com\r\n\r\n");
        let response = http_exchange(&tunnel, request.as_bytes()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
            "{host:?}: {:?}",
            String::from_utf8_lossy(&response)
        );
    }
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn socks5_domain_with_non_hostname_bytes_is_refused_and_undialed() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;

    // Positive control: a normal name gets REP_SUCCESS and reaches the proxy.
    let ok = socks5_connect_domain(&tunnel, b"good.example").await;
    assert_eq!(ok[1], 0x00, "control must succeed");
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "control must reach the upstream"
    );

    let mut bad: Vec<&[u8]> = BAD_HOSTS.iter().map(|h| h.as_bytes()).collect();
    bad.extend([&b"evil.com:443"[..], b"evil.com\0", b"evil com", b""]);
    for host in bad {
        let reply = socks5_connect_domain(&tunnel, host).await;
        assert_eq!(
            reply[..2],
            [5, 0x01],
            "{:?} must get general failure",
            String::from_utf8_lossy(host)
        );
    }
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "no non-hostname SOCKS5 target may reach the upstream"
    );
}
