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

/// The bypass hosts from the issue plus the other non-hostname bytes —
/// including `inet_aton` spellings a libc dial path would fold into IPs.
const BAD_HOSTS: &[&str] = &[
    "a@evil.com",
    "user:pass@evil.com",
    "evil.com/x",
    "evil.com?q=1",
    "evil.com#f",
    "evil%2ecom",
    "123.456",
    "2130706433",
    "0177.0.0.1",
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
    http_exchange_with(tunnel, None, request).await
}

/// Same drive with a `SnifferRuntime` installed. The caller owns the
/// sniffer as `'static` (a test may `Box::leak` it) so the handler can
/// live in `tokio::spawn` like every other request here.
async fn http_exchange_sniffed(
    tunnel: &meow_tunnel::Tunnel,
    sniffer: &'static meow_listener::sniffer::SnifferRuntime,
    request: &[u8],
) -> Vec<u8> {
    http_exchange_with(tunnel, Some(sniffer), request).await
}

async fn http_exchange_with(
    tunnel: &meow_tunnel::Tunnel,
    sniffer: Option<&'static meow_listener::sniffer::SnifferRuntime>,
    request: &[u8],
) -> Vec<u8> {
    let (server, mut client) = loopback_pair().await;
    let tunnel = tunnel.clone();
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    tokio::spawn(async move {
        meow_listener::http_proxy::handle_http(&tunnel, server, src, sniffer, None, "http", 0)
            .await;
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

/// Origin-form (`GET /path`) carries no authority in the request line — the
/// `Host:` header is the destination. `Host: 127.0.0.1:<port>` must relay
/// to that literal and that port.
#[tokio::test]
async fn http_origin_form_ip_literal_host_relays() {
    let tunnel = common::direct_tunnel();
    let backend = common::spawn_http_ok_server().await;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        backend.port()
    );
    let response = http_exchange(&tunnel, request.as_bytes()).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "origin-form + literal Host must relay: {:?}",
        String::from_utf8_lossy(&response)
    );
}

/// Same shape through the rule engine: a domain `Host:` must pass the
/// hostname gate and reach `MATCH,proxy` — refused only by a dead
/// upstream, never by a 400.
#[tokio::test]
async fn http_origin_form_domain_host_reaches_upstream() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(&tunnel, b"GET / HTTP/1.1\r\nHost: good.example\r\n\r\n").await;
    assert!(
        !response.starts_with(b"HTTP/1.1 400"),
        "domain Host must not be refused: {:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "the origin-form request must reach the upstream"
    );
}

/// The Host header becomes the authority, so a non-hostname value is
/// refused with 400 exactly like a bad absolute-form authority.
#[tokio::test]
async fn http_origin_form_bad_host_is_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    for host in ["a@evil.com", "evil.com/x", "evil%2ecom"] {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
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

/// HTTP/1.1 requires `Host:` on origin-form; without it the gate still
/// refuses, exactly as a request with a bad authority.
#[tokio::test]
async fn http_origin_form_missing_host_is_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(&tunnel, b"GET / HTTP/1.1\r\n\r\n").await;
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "{:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

/// Asterisk-form keeps its own refusal: `OPTIONS *` names no host and the
/// Host header does not rescue it — the authority slot is only restored
/// when the request-target's authority is empty, and `*` is non-empty.
#[tokio::test]
async fn http_asterisk_form_is_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response =
        http_exchange(&tunnel, b"OPTIONS * HTTP/1.1\r\nHost: good.example\r\n\r\n").await;
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "{:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

/// Only `/`-leading request-targets are origin-form. `?x` is neither
/// origin-form nor a parseable authority — the Host header must not
/// rescue it either.
#[tokio::test]
async fn http_query_form_target_is_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(&tunnel, b"GET ?x HTTP/1.1\r\nHost: good.example\r\n\r\n").await;
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "{:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

/// RFC 9110 §5.4: a duplicated Host field makes the authority ambiguous —
/// the listener refuses rather than silently picking the first.
#[tokio::test]
async fn http_origin_form_duplicate_host_is_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(
        &tunnel,
        b"GET / HTTP/1.1\r\nHost: good.example\r\nHost: evil.com\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "{:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

/// `Host: x.com.` passes the gate (the predicate strips one trailing
/// dot) and — with `rule_host()` normalizing trailing dots too — now
/// hits `DOMAIN,evil.com` exactly as `evil.com` would: REJECT owns the
/// flow and no upstream dial ever happens. The stored host keeps the
/// verbatim `evil.com.` for dialing.
#[tokio::test]
async fn http_origin_form_trailing_dot_host_normalizes_for_rules() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(&tunnel, b"GET / HTTP/1.1\r\nHost: evil.com.\r\n\r\n").await;
    assert!(
        response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
        "trailing-dot Host must hit DOMAIN,evil.com,REJECT: {:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "DOMAIN,evil.com must own the normalized `evil.com.` — REJECT, no upstream"
    );
}

/// Same normalization through CONNECT: `evil.com.:443` hits the DOMAIN
/// arm, not the tunnel. CONNECT pre-acks `200 Connection established`
/// before routing, so the observable proof REJECT (not MATCH,proxy) owns
/// the flow is that no upstream CONNECT is ever attempted — the tunnel
/// drops it after the ack.
#[tokio::test]
async fn http_connect_trailing_dot_target_hits_domain_reject() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(&tunnel, b"CONNECT evil.com.:443 HTTP/1.1\r\n\r\n").await;
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "the pre-routing ack is unchanged: {:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "DOMAIN,evil.com must own the normalized `evil.com.` — REJECT, no upstream CONNECT"
    );
}

/// Absolute-form authority with a trailing dot normalizes the same way:
/// `GET http://evil.com./` hits `DOMAIN,evil.com` → REJECT even though a
/// conflicting `Host: good.example` is present (the target authority
/// always wins the routing name).
#[tokio::test]
async fn http_absolute_form_trailing_dot_authority_hits_domain_reject() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(
        &tunnel,
        b"GET http://evil.com./ HTTP/1.1\r\nHost: good.example\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
        "DOMAIN,evil.com must REJECT via the normalized authority: {:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

/// A bracketed IPv6 `Host` is a valid literal: `Host: [::1]` folds into
/// `dst_ip`, falls through `DOMAIN,evil.com` to `MATCH,proxy`, and the
/// flow reaches the upstream — refused there, never at the gate.
#[tokio::test]
async fn http_origin_form_bracketed_v6_host_is_not_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(&tunnel, b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n").await;
    assert!(
        !response.starts_with(b"HTTP/1.1 400"),
        "bracketed v6 literal must pass the gate: {:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "the literal falls to MATCH,proxy — the gate may not refuse it"
    );
}

/// A `Host` with a non-numeric port (`x.com:badport`) keeps the colon in
/// the host (`parse_host_port` only splits a valid u16) and fails
/// validation — same 400 as any bad authority.
#[tokio::test]
async fn http_origin_form_malformed_host_port_is_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(&tunnel, b"GET / HTTP/1.1\r\nHost: x.com:badport\r\n\r\n").await;
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "{:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

/// The Host fallback only fires for `/`-leading targets: an absolute-form
/// request routes by its own authority, and a conflicting Host header is
/// ignored. `GET http://evil.com/` + `Host: good.example` must hit
/// DOMAIN,evil.com → REJECT, never the proxy arm.
#[tokio::test]
async fn http_absolute_form_authority_beats_conflicting_host() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(
        &tunnel,
        b"GET http://evil.com/ HTTP/1.1\r\nHost: good.example\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
        "DOMAIN,evil.com must REJECT via the target authority: {:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

/// Sniffer-enabled counterpart of `http_absolute_form_authority_beats_conflicting_host`.
/// With the sniffer on, the plain-HTTP path still routes by the request
/// target's authority when it is a domain: `GET http://evil.com/` +
/// `Host: good.example` must hit DOMAIN,evil.com → REJECT. The sniffed
/// `good.example` is NOT adopted into `sniff_host` — rules read
/// `sniff_host` while the dial reads `host`, so adopting it would route
/// by `good.example` yet still dial `evil.com`, slipping past the REJECT
/// (the regression this pins).
///
/// The routing pin is the upstream accept count: a REJECT-502 never
/// dials, and `accepts == 0` proves the DOMAIN arm owned the flow.
#[tokio::test]
async fn http_absolute_form_authority_beats_conflicting_sniffed_host() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let sniffer: &'static _ = Box::leak(Box::new(meow_listener::sniffer::SnifferRuntime::new(
        meow_common::sniffer::SnifferConfig {
            enable: true,
            ..Default::default()
        },
    )));
    let response = http_exchange_sniffed(
        &tunnel,
        sniffer,
        b"GET http://evil.com/ HTTP/1.1\r\nHost: good.example\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
        "DOMAIN,evil.com must REJECT via the target authority: {:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "the explicit authority wins — a conflicting sniffed name must not reroute the dial"
    );
}

/// The flip side of the authority priority: an IP-literal authority
/// carries no routing name, so the sniffed `Host:` IS still adopted —
/// `GET http://127.0.0.1/` + `Host: good.example` hits
/// `DOMAIN-SUFFIX,good.example,REJECT` even though the bare literal
/// would fall through to MATCH,proxy (the control request proves it by
/// dialing on a name the rule does not cover). Losing this would break
/// the sniffer's design purpose: recovering a routing name for
/// IP-literal flows.
#[tokio::test]
async fn http_ip_literal_authority_still_adopts_sniffed_host() {
    let (upstream, accepts) = common::spawn_counting_http_upstream().await;
    let yaml = format!(
        "proxies:\n  - name: proxy\n    type: http\n    server: 127.0.0.1\n    port: {}\n\
         rules:\n  - DOMAIN-SUFFIX,good.example,REJECT\n  - MATCH,proxy\n",
        upstream.port()
    );
    let raw = meow_config::parse_raw_yaml(&yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).unwrap();
    let tunnel = common::direct_tunnel();
    tunnel.set_mode(meow_common::TunnelMode::Rule);
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.update_rules(res.rules);

    let sniffer: &'static _ = Box::leak(Box::new(meow_listener::sniffer::SnifferRuntime::new(
        meow_common::sniffer::SnifferConfig {
            enable: true,
            ..Default::default()
        },
    )));

    // Control: a sniffed name the suffix rule does not cover falls to
    // MATCH,proxy and dials — proves the REJECT below is the sniffed-name
    // arm, not something the IP literal itself triggers.
    let control = http_exchange_sniffed(
        &tunnel,
        sniffer,
        b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: other.example\r\n\r\n",
    )
    .await;
    assert!(
        !control.starts_with(b"HTTP/1.1 400"),
        "control must pass the gate: {:?}",
        String::from_utf8_lossy(&control)
    );
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "control must reach the upstream via MATCH,proxy"
    );

    let response = http_exchange_sniffed(
        &tunnel,
        sniffer,
        b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: good.example\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
        "DOMAIN-SUFFIX,good.example must REJECT via the sniffed name: {:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "the sniffed `good.example` must own the flow — REJECT, no dial"
    );
}

/// `Host: 127.0.0.1:0` restores port 0 — no socket can dial it — so the
/// listener refuses with 400 like any other unusable authority instead
/// of routing an undialable port.
#[tokio::test]
async fn http_origin_form_zero_port_host_is_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(&tunnel, b"GET / HTTP/1.1\r\nHost: 127.0.0.1:0\r\n\r\n").await;
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "{:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

/// `CONNECT x:0` names the same unusable port-0 authority — it must be
/// refused with 400 at the shared authority parse, not pre-acked with
/// `200 Connection established` and left to fail on the dial.
#[tokio::test]
async fn http_connect_zero_port_target_is_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    for target in [
        &b"CONNECT good.example:0 HTTP/1.1\r\n\r\n"[..],
        &b"CONNECT 127.0.0.1:0 HTTP/1.1\r\n\r\n"[..],
    ] {
        let response = http_exchange(&tunnel, target).await;
        assert!(
            response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
            "{:?}",
            String::from_utf8_lossy(&response)
        );
    }
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "no port-0 CONNECT may reach the upstream"
    );
}

/// Absolute-form `http://x:0/` goes through the same authority parse as
/// CONNECT — the explicit `:0` port is refused with 400, not carried to
/// the dial like a valid host:port pair.
#[tokio::test]
async fn http_absolute_form_zero_port_authority_is_400() {
    let (tunnel, accepts) = common::issue_734_tunnel().await;
    let response = http_exchange(
        &tunnel,
        b"GET http://good.example:0/ HTTP/1.1\r\nHost: good.example:0\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "{:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}

/// The literal fold is pinned end-to-end at rule level: `Host: 127.0.0.1`
/// must reach the IP rules as `dst_ip` — `IP-CIDR,...,no-resolve` reads
/// `dst_ip` only and never resolves `host`, so a mere `host` string would
/// slip to `MATCH,proxy` and dial. Both the listener (`host_to_ip`) and
/// `pre_handle_metadata` fold literals; this pins the visible outcome.
#[tokio::test]
async fn http_origin_form_literal_host_populates_dst_ip_for_ipcidr() {
    let (upstream, accepts) = common::spawn_counting_http_upstream().await;
    let yaml = format!(
        "proxies:\n  - name: proxy\n    type: http\n    server: 127.0.0.1\n    port: {}\n\
         rules:\n  - IP-CIDR,127.0.0.0/8,REJECT,no-resolve\n  - MATCH,proxy\n",
        upstream.port()
    );
    let raw = meow_config::parse_raw_yaml(&yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).unwrap();
    let tunnel = common::direct_tunnel();
    tunnel.set_mode(meow_common::TunnelMode::Rule);
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.update_rules(res.rules);

    let response = http_exchange(&tunnel, b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await;
    assert!(
        !response.starts_with(b"HTTP/1.1 200"),
        "IP-CIDR must see the folded literal, got: {:?}",
        String::from_utf8_lossy(&response)
    );
    settle().await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "the literal must never reach the proxy — dst_ip gates it upstream"
    );
}

/// Origin-form with a declared body: `POST /submit` + `Content-Length`
/// takes the Host fallback like any `/`-leading target, and the body
/// relays — a pinned 200 round-trip.
#[tokio::test]
async fn http_origin_form_post_with_content_length_body_relays() {
    let tunnel = common::direct_tunnel();
    let backend = common::spawn_http_ok_server().await;
    let request = format!(
        "POST /submit HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 3\r\n\r\nabc",
        backend.port()
    );
    let response = http_exchange(&tunnel, request.as_bytes()).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "POST + Content-Length must relay: {:?}",
        String::from_utf8_lossy(&response)
    );
}

/// A `//path` request-target is network-path form on paper, but it is
/// still `/`-leading: the Host fallback fires and the target's own
/// `//authority` slot is never consulted — pinned as a 200 relay.
#[tokio::test]
async fn http_origin_form_network_path_target_uses_host_header() {
    let tunnel = common::direct_tunnel();
    let backend = common::spawn_http_ok_server().await;
    let request = format!(
        "GET //path HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        backend.port()
    );
    let response = http_exchange(&tunnel, request.as_bytes()).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "//path must route by the Host header: {:?}",
        String::from_utf8_lossy(&response)
    );
}

/// Header names are case-insensitive: `HOST:` supplies the authority for
/// an origin-form target exactly like `Host:` — a pinned 200.
#[tokio::test]
async fn http_origin_form_uppercase_host_header_relays() {
    let tunnel = common::direct_tunnel();
    let backend = common::spawn_http_ok_server().await;
    let request = format!(
        "GET / HTTP/1.1\r\nHOST: 127.0.0.1:{}\r\n\r\n",
        backend.port()
    );
    let response = http_exchange(&tunnel, request.as_bytes()).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "uppercase HOST: must supply the authority: {:?}",
        String::from_utf8_lossy(&response)
    );
}

/// `Connection: upgrade` + `Upgrade: websocket` on an origin-form
/// request: the Host fallback still supplies the authority, and when the
/// origin declines the upgrade (a plain 200) the response relays
/// untouched — a pinned 200.
#[tokio::test]
async fn http_origin_form_upgrade_websocket_declined_relays() {
    let tunnel = common::direct_tunnel();
    let backend = common::spawn_http_ok_server().await;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        backend.port()
    );
    let response = http_exchange(&tunnel, request.as_bytes()).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "an upgrade-nominated request must still relay: {:?}",
        String::from_utf8_lossy(&response)
    );
}
