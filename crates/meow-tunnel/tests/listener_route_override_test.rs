/// `listeners[].proxy` / `listeners[].rule` route overrides
/// (SPEC_LISTENER_SURFACE item 2): the tunnel resolves
/// `Metadata.special_proxy` before mode dispatch and process lookup,
/// resolves `Metadata.special_rules` against the route table's named
/// `sub-rules` blocks instead of the top-level list, fails closed on a
/// missing forced proxy or block, and never stamps a fictitious
/// top-level rule hit or disable state for block matches.
use meow_common::{Metadata, Network, TunnelMode};
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use std::sync::Arc;

fn test_resolver() -> Arc<Resolver> {
    Arc::new(Resolver::new(
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        DomainTrie::new(),
        false,
        false,
    ))
}

/// Publish proxies + top-level rules + named sub-rules blocks through the
/// same `update_routing` call the app/API make — one coherent snapshot.
fn tunnel_with(yaml: &str) -> Tunnel {
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).unwrap();
    let tunnel = Tunnel::new(test_resolver());
    tunnel.set_mode(TunnelMode::Rule);
    tunnel.update_routing(res.proxies, res.rules, res.sub_rules, res.dialer_registry);
    tunnel
}

/// The adapter a resolution picked IS the registry entry for `name` —
/// `type: direct` nodes all report `adapter.name() == "DIRECT"`, so
/// identity goes through `Arc` identity on the route snapshot, not the
/// display name.
fn assert_resolved_to(t: &meow_tunnel::tunnel::ResolvedTarget, name: &str) {
    if matches!(name, "DIRECT" | "REJECT") {
        assert_eq!(t.adapter.name(), name);
    } else {
        let entry = t
            .route
            .proxies
            .get(name)
            .unwrap_or_else(|| panic!("'{name}' not in route table"));
        let entry: Arc<dyn meow_common::ProxyAdapter> =
            Arc::clone(entry) as Arc<dyn meow_common::ProxyAdapter>;
        assert!(
            Arc::ptr_eq(&t.adapter, &entry),
            "resolved adapter is not the '{name}' registry entry"
        );
    }
}

fn tcp_md(host: &str) -> Metadata {
    Metadata {
        host: host.into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    }
}

const BASE: &str = "\
proxies:
  - name: A
    type: direct
  - name: B
    type: direct
proxy-groups:
  - name: GRP
    type: select
    proxies: [A, B]
rules:
  - DOMAIN-SUFFIX,top.example,A
  - MATCH,B
sub-rules:
  inner:
    - DOMAIN-SUFFIX,inner.example,B
    - MATCH,DIRECT
  empty-block: []
";

#[tokio::test]
async fn forced_proxy_beats_rule_match_and_mode() {
    let tunnel = tunnel_with(BASE);
    // `top.example` matches top-level rule 1 → A, but the listener forced B.
    let mut md = tcp_md("top.example");
    md.special_proxy = "B".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    assert_eq!(t.rule_name.as_str(), "ListenerProxy");
    assert_eq!(t.rule_payload.as_str(), "B");
    assert_resolved_to(&t, "B");

    // Global mode does not shield a flow from its listener's forced proxy.
    tunnel.set_mode(TunnelMode::Global);
    let mut md = tcp_md("anything.example");
    md.special_proxy = "A".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    assert_resolved_to(&t, "A");
}

#[tokio::test]
async fn forced_proxy_direct_and_group_resolve_live() {
    let tunnel = tunnel_with(BASE);
    let mut md = tcp_md("x.example");
    md.special_proxy = "DIRECT".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    assert_resolved_to(&t, "DIRECT");

    // A group name resolves to the live group adapter — membership is
    // consulted per-flow, never a startup-cached leaf.
    let mut md = tcp_md("x.example");
    md.special_proxy = "GRP".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    assert_resolved_to(&t, "GRP");
}

#[tokio::test]
async fn forced_proxy_missing_fails_closed() {
    let tunnel = tunnel_with(BASE);
    let mut md = tcp_md("top.example");
    md.special_proxy = "GHOST".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    // Fail closed, no slide to the top-level A match or DIRECT.
    assert_eq!(t.rule_name.as_str(), "ListenerProxy");
    assert_eq!(t.rule_payload.as_str(), "GHOST");
    assert_resolved_to(&t, "REJECT");
}

#[tokio::test]
async fn named_rule_block_replaces_top_level_scan() {
    let tunnel = tunnel_with(BASE);
    // `inner.example` matches nothing top-level (falls to MATCH → B), but
    // the selected block's DOMAIN-SUFFIX sends it to B as well — so use a
    // host the top list would send to A and the block sends DIRECT.
    let mut md = tcp_md("top.example");
    md.special_rules = "inner".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    // The block has no top.example rule → its own MATCH → DIRECT; the
    // top-level DOMAIN-SUFFIX→A is never consulted.
    assert_resolved_to(&t, "DIRECT");

    let mut md = tcp_md("inner.example");
    md.special_rules = "inner".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    assert_resolved_to(&t, "B");
}

#[tokio::test]
async fn named_rule_block_empty_or_exhausted_goes_direct() {
    let tunnel = tunnel_with(BASE);
    let mut md = tcp_md("top.example");
    md.special_rules = "empty-block".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    assert_resolved_to(&t, "DIRECT");
}

#[tokio::test]
async fn named_rule_block_missing_fails_closed() {
    let tunnel = tunnel_with(BASE);
    let mut md = tcp_md("top.example");
    md.special_rules = "no-such-block".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    assert_eq!(t.rule_name.as_str(), "ListenerProxy");
    assert_resolved_to(&t, "REJECT");
}

#[tokio::test]
async fn forced_proxy_wins_over_named_rule_block() {
    let tunnel = tunnel_with(BASE);
    // Both set: upstream `resolveMetadata` applies specialProxy first.
    let mut md = tcp_md("inner.example");
    md.special_proxy = "A".into();
    md.special_rules = "inner".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    assert_eq!(t.rule_name.as_str(), "ListenerProxy");
    assert_resolved_to(&t, "A");
}

#[tokio::test]
async fn sub_rules_survive_partial_route_updates() {
    let tunnel = tunnel_with(BASE);
    // `update_proxies` / `update_rules` inherit the snapshot's sub_rules —
    // a warm proxy-group PUT must not strand listeners' rule blocks.
    let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    let mut md = tcp_md("inner.example");
    md.special_rules = "inner".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    // B is gone from the proxy map, so the block's DOMAIN-SUFFIX,B match
    // is skipped (upstream `continue`); MATCH,DIRECT still lands.
    assert_resolved_to(&t, "DIRECT");
}

#[tokio::test]
async fn config_rejects_listener_rule_without_block() {
    let err = meow_config::load_config_from_str(
        "listeners:\n  - name: in1\n    type: mixed\n    port: 0\n    rule: ghost\n",
    )
    .await
    .err()
    .map(|e| e.to_string())
    .unwrap_or_default();
    // `listeners[].rule` selects a same-document `sub-rules:` block —
    // an unknown name is a hard parse error, not a runtime fallback.
    assert!(err.contains("ghost") && err.contains("sub-rules"), "{err}");
}

/// A block match on a UDP-incapable target fails closed: `udp: false` is
/// a routing preference the TOP-LEVEL scan slides past (issue #969), but
/// a `rule:` override owns the flow's whole policy, so the block scan
/// stops on the match and the materialize arm rejects rather than slide
/// to block-exhaustion DIRECT (`RouteTargetProbe::check`'s
/// `stats.is_none()` arm).
#[tokio::test]
async fn named_rule_block_udp_incapable_match_rejects() {
    let yaml = "\
proxies:
  - name: no-udp
    type: socks5
    server: 127.0.0.1
    port: 1080
    udp: false
rules:
  - MATCH,DIRECT
sub-rules:
  blk:
    - DOMAIN-SUFFIX,udp.example,no-udp
    - MATCH,DIRECT
";
    let tunnel = tunnel_with(yaml);
    let mut md = tcp_md("udp.example");
    md.network = Network::Udp;
    md.special_rules = "blk".into();
    let t = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
    // The block rule DID match — this is the fail-closed arm, not the
    // missing-block ListenerProxy path; had the scan slid, the block's
    // own MATCH would have landed DIRECT.
    assert_eq!(t.rule_name.as_str(), "DomainSuffix");
    assert_eq!(t.rule_payload.as_str(), "udp.example");
    assert_resolved_to(&t, "REJECT");
}

/// A listener-selectable block's IP demand must reach the eager
/// `pre_resolve` gate even when the top-level list demands none: UDP
/// callers still resolve `dst_ip` through `needs_ip_resolution` before
/// matching (the lazy scan enriches mid-scan, but UDP's NAT key is built
/// ahead of it), so `RouteTable::needs_ip_resolution` ORs every named
/// block's compiled set in.
#[tokio::test]
async fn sub_rules_ip_rule_flips_needs_ip_resolution() {
    let yaml = "\
rules:
  - MATCH,DIRECT
sub-rules:
  ipblk:
    - IP-CIDR,203.0.113.0/24,DIRECT
    - MATCH,DIRECT
";
    let tunnel = tunnel_with(yaml);
    assert!(
        tunnel
            .inner()
            .needs_ip_resolution
            .load(std::sync::atomic::Ordering::Relaxed),
        "a block's IP-CIDR demand must publish needs_ip_resolution"
    );

    // Negative control: without the block's IP rule the same shape stays
    // false — the flip comes from the block, not from `sub-rules:` alone.
    let tunnel =
        tunnel_with("rules:\n  - MATCH,DIRECT\nsub-rules:\n  ipblk:\n    - MATCH,DIRECT\n");
    assert!(!tunnel
        .inner()
        .needs_ip_resolution
        .load(std::sync::atomic::Ordering::Relaxed));
}

/// `listeners[].proxy` forced-target admission (Class A): a name that
/// declares no proxy, group, or built-in is a hard config-build error,
/// not a per-flow fail-closed the inbound would only discover at runtime.
#[tokio::test]
async fn config_rejects_listener_proxy_naming_nothing() {
    let err = meow_config::load_config_from_str(
        "listeners:\n  - name: in1\n    type: mixed\n    port: 0\n    proxy: ghost\n",
    )
    .await
    .err()
    .map(|e| e.to_string())
    .unwrap_or_default();
    assert!(err.contains("ghost") && err.contains("proxy"), "{err}");
}

#[tokio::test]
async fn config_carries_proxy_rule_override_on_named_listener() {
    // `proxy:` names a same-document entry — admission rejects dangling
    // forced targets, so P must exist here for the override to be carried.
    let cfg = meow_config::load_config_from_str(
        "proxies:\n  - name: P\n    type: direct\n\
         sub-rules:\n  blk:\n    - MATCH,DIRECT\n\
         listeners:\n  - name: in1\n    type: mixed\n    port: 0\n    proxy: P\n    rule: blk\n",
    )
    .await
    .expect("config must load");
    let nl = cfg
        .listeners
        .named
        .iter()
        .find(|l| l.name == "in1")
        .expect("named listener");
    let ov = nl.route_override.as_ref().expect("route_override set");
    assert_eq!(ov.proxy.as_deref(), Some("P"));
    assert_eq!(ov.rule.as_deref(), Some("blk"));
    assert!(cfg.sub_rules.contains_key("blk"));
}
