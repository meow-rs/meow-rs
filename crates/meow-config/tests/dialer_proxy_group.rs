//! A node's `dialer-proxy` must survive being reached through a proxy group,
//! and a dialer must be able to name a group (issue #513).
//!
//! Proxy groups clone their members eagerly, so applying the chain after the
//! group build left every group holding the pre-dialer adapter: selecting the
//! node through the group dialled its own server directly and silently bypassed
//! the chain the user configured for policy reasons. The dialer pass now runs
//! before groups are built and binds the front hop *by name* (mihomo
//! `component/proxydialer/byname.go`), so both paths chain identically and a
//! group that does not exist yet at build time is still a valid dialer.
//!
//! The observable is which mock server each dial physically contacts. Every TLS
//! handshake fails fast against the plain listeners — the accept counts, not the
//! dial result, are what these tests assert on.

use meow_common::{Metadata, Network};
use meow_config::raw::RawConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

/// TCP listener that counts accepts and drops each connection immediately, so
/// the client-side TLS handshake errors out instead of hanging on a ServerHello
/// that never arrives.
async fn counting_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (addr, count)
}

/// `A` chains through the leaf proxy `B`; `C` chains through the group `G2`
/// (which holds `B`); `G` is a select group over `A`.
fn config(port_a: u16, port_b: u16, port_c: u16) -> RawConfig {
    serde_yaml::from_str(&format!(
        r#"
mixed-port: 17890
mode: rule
proxies:
  - name: A
    type: trojan
    server: 127.0.0.1
    port: {port_a}
    password: issue-513
    dialer-proxy: B
  - name: B
    type: trojan
    server: 127.0.0.1
    port: {port_b}
    password: issue-513
  - name: C
    type: trojan
    server: 127.0.0.1
    port: {port_c}
    password: issue-513
    dialer-proxy: G2
proxy-groups:
  - name: G
    type: select
    proxies: [A]
  - name: G2
    type: select
    proxies: [B]
rules:
  - MATCH,DIRECT
"#
    ))
    .unwrap()
}

/// Registry plus the three mock servers, with per-server accept counters.
/// `dialer_registry` is a keepalive: `DialerTarget`s resolve through it
/// weakly (issue #533), so dropping it would fail every chained dial closed.
struct Harness {
    proxies: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
    accepts: HashMap<&'static str, Arc<AtomicUsize>>,
    _dialer_registry: meow_proxy::dialer::ProxyRegistry,
}

impl Harness {
    fn accepts(&self, server: &str) -> usize {
        self.accepts[server].load(Ordering::SeqCst)
    }

    /// Dial `name` and discard the outcome — the handshakes are expected to
    /// fail, only the physical contact matters.
    async fn dial(&self, name: &str) {
        let metadata = Metadata {
            network: Network::Tcp,
            host: "127.0.0.1".into(),
            dst_ip: Some("127.0.0.1".parse().unwrap()),
            dst_port: 9,
            ..Default::default()
        };
        let proxy = self
            .proxies
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be in the registry"));
        let _ = proxy.dial_tcp(&metadata).await;
    }
}

async fn harness() -> Harness {
    let (server_a, a_accepts) = counting_listener().await;
    let (server_b, b_accepts) = counting_listener().await;
    let (server_c, c_accepts) = counting_listener().await;

    let raw = config(server_a.port(), server_b.port(), server_c.port());
    let meow_config::RebuildResult {
        proxies,
        dialer_registry,
        ..
    } = meow_config::rebuild_from_raw(&raw).expect("rebuild ok");

    Harness {
        proxies,
        accepts: HashMap::from([("A", a_accepts), ("B", b_accepts), ("C", c_accepts)]),
        _dialer_registry: dialer_registry,
    }
}

/// The regression: `G` selects `A`, and `A` declares `dialer-proxy: B`. Both
/// the direct registry dial and the dial through the group must contact B's
/// server first. Before the fix the group held the pre-dialer `A` and contacted
/// A's server directly, bypassing the chain.
#[tokio::test]
async fn group_member_honours_its_dialer_proxy() {
    let h = harness().await;

    h.dial("A").await;
    assert_eq!(h.accepts("B"), 1, "registry A must chain through dialer B");
    assert_eq!(
        h.accepts("A"),
        0,
        "registry A must not contact its own server directly"
    );

    h.dial("G").await;
    assert_eq!(
        h.accepts("B"),
        2,
        "the group must reach the chained A, not a stale pre-dialer copy"
    );
    assert_eq!(
        h.accepts("A"),
        0,
        "dialer-proxy bypassed when the node is reached via a group"
    );
}

/// A `dialer-proxy` may name a group. The group is built *after* the dialer
/// pass, so only by-name resolution can find it; capturing an `Arc` at build
/// time would have nothing to capture.
#[tokio::test]
async fn dialer_may_name_a_group_built_later() {
    let h = harness().await;

    h.dial("C").await;
    assert_eq!(
        h.accepts("B"),
        1,
        "C must chain through group G2, whose only member is B"
    );
    assert_eq!(
        h.accepts("C"),
        0,
        "C must not contact its own server directly"
    );
}

/// A dialer that can route back to the chained proxy through group membership
/// is a hard config error: the loop never reaches I/O, so the first dial
/// recurses synchronously until the native stack overflows. This includes the
/// auto-created `GLOBAL`, which selects over every registry entry.
#[test]
fn group_dialer_routing_back_is_a_config_error() {
    for (dialer, groups) in [
        // G selects A itself.
        ("G", "  - name: G\n    type: select\n    proxies: [A, B]"),
        // Nested: G holds G2, G2 selects A.
        ("G", "  - name: G\n    type: select\n    proxies: [G2]\n  - name: G2\n    type: select\n    proxies: [A]"),
        // include-all-proxies pulls every top-level proxy in.
        ("G", "  - name: G\n    type: select\n    include-all-proxies: true"),
        // The auto-created GLOBAL contains everything.
        ("GLOBAL", ""),
        // A declared GLOBAL that fails to build is backstopped by the
        // auto-created all-members one.
        ("GLOBAL", "  - name: GLOBAL\n    type: select\n    proxies: [ghost-node]"),
        // Duplicate group names: the registry keeps the last *successful*
        // declaration — {A} — not the last-declared {ghost-node} block.
        ("G", "  - name: G\n    type: select\n    proxies: [A]\n  - name: G\n    type: select\n    proxies: [ghost-node]"),
    ] {
        let raw: RawConfig = serde_yaml::from_str(&format!(
            r#"
mixed-port: 17890
proxies:
  - name: A
    type: trojan
    server: 127.0.0.1
    port: 1
    password: issue-513
    dialer-proxy: {dialer}
  - name: B
    type: trojan
    server: 127.0.0.1
    port: 2
    password: issue-513
proxy-groups:
{groups}
rules:
  - MATCH,DIRECT
"#
        ))
        .unwrap();
        let err = meow_config::rebuild_from_raw(&raw)
            .err()
            .expect("a dialer that routes back to its source must be rejected");
        assert!(
            err.to_string().contains("through group membership"),
            "dialer {dialer}: unexpected error: {err}"
        );
    }
}

/// A dialer may name a group only if it actually builds: a *declared* group
/// whose members all fail to resolve never enters the registry, and the load
/// must fail at build time rather than on the first dial.
#[test]
fn dialer_to_unbuilt_group_is_a_config_error() {
    let raw: RawConfig = serde_yaml::from_str(
        r#"
mixed-port: 17890
proxies:
  - name: A
    type: trojan
    server: 127.0.0.1
    port: 1
    password: issue-513
    dialer-proxy: G
proxy-groups:
  - name: G
    type: select
    proxies: [ghost-node]
rules:
  - MATCH,DIRECT
"#,
    )
    .unwrap();
    let err = meow_config::rebuild_from_raw(&raw)
        .err()
        .expect("a dialer naming a group that never built must be rejected");
    assert!(
        err.to_string()
            .contains("did not build into a registry entry"),
        "unexpected: {err}"
    );
}

/// A remote rule-provider fetch dials through `download_proxy` — the first
/// named proxy — *inside* the config build. When that proxy is itself
/// chained, its front hop must already resolve: publishing the by-name
/// registry has to happen before provider fetches, not after. The observable
/// is whether B's server was contacted.
#[tokio::test]
async fn provider_fetch_through_chained_download_proxy_resolves() {
    let (server_b, b_accepts) = counting_listener().await;
    let (server_a, _a_accepts) = counting_listener().await;

    let raw: RawConfig = serde_yaml::from_str(&format!(
        r#"
mixed-port: 17890
proxies:
  - name: A
    type: trojan
    server: 127.0.0.1
    port: {port_a}
    password: issue-513
    dialer-proxy: B
  - name: B
    type: trojan
    server: 127.0.0.1
    port: {port_b}
    password: issue-513
rule-providers:
  rp:
    type: http
    behavior: domain
    url: http://127.0.0.1:9/payload.mrs
rules:
  - MATCH,DIRECT
"#,
        port_a = server_a.port(),
        port_b = server_b.port(),
    ))
    .unwrap();

    // The fetch itself fails — the mock listener drops every connection — so
    // the provider is warn-skipped, but the dial must have reached B.
    // `rebuild_from_raw` blocks until the fetch resolves, so it runs on the
    // blocking pool to keep the accept loop's executor free.
    let _ = tokio::task::spawn_blocking(move || meow_config::rebuild_from_raw(&raw)).await;
    assert!(
        b_accepts.load(Ordering::SeqCst) >= 1,
        "the provider fetch must chain through B; 0 accepts means the front \
         hop could not resolve during the build"
    );
}
