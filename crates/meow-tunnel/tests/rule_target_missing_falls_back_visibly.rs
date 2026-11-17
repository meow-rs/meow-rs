//! A matched rule whose target the registry does not hold is *skipped*, and
//! the scan continues — mihomo's `match()` does `continue` on
//! `proxies[adapter] == nil`, reaching DIRECT only via the no-match tail
//! (issue #513).
//!
//! Before this change meow-rs stopped at the first match and silently
//! substituted DIRECT: a subscription that dropped one node could bypass a
//! later REJECT upstream would have honored. The scan now mirrors upstream,
//! and the skip still warns — the /logs broadcast keeps only the message
//! field, so target and rule type are interpolated into the message text.

use meow_common::{AdapterType, DnsMode, Metadata, Network, Rule, TunnelMode};
use meow_dns::Resolver;
use meow_rules::final_rule::FinalRule;
use meow_trie::DomainTrie;
use meow_tunnel::{ResolvedTarget, Tunnel};
use std::sync::Arc;

fn resolver() -> Arc<Resolver> {
    Arc::new(Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ))
}

/// A tunnel in rule mode whose registry is the one every real load publishes:
/// the built-in DIRECT / REJECT / REJECT-DROP entries and nothing else.
fn tunnel_with_builtin_registry() -> Tunnel {
    let tunnel = Tunnel::new(resolver());
    let res = meow_config::rebuild_from_raw(&meow_config::raw::RawConfig::default())
        .expect("an empty config must build its built-in registry");
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    tunnel
}

fn metadata() -> Metadata {
    Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    }
}

/// The rules a real config leaves behind when a node was dropped: a `MATCH`
/// naming something the registry does not hold.
fn tunnel_with_ghost_target() -> Tunnel {
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("ghost-group"))];
    tunnel.update_rules(rules);
    tunnel
}

#[tokio::test]
async fn a_matched_rule_with_a_missing_target_is_skipped_to_the_tail() {
    let tunnel = tunnel_with_ghost_target();

    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .await
        .expect("the no-match tail always resolves");

    // The MATCH was skipped, not honored: nothing matched, so the reported
    // rule is the no-match tail and the dial is DIRECT — exactly what
    // upstream produces for `MATCH,ghost`.
    assert_eq!(rule, "Final");
    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
}

#[tokio::test]
async fn a_skipped_match_does_not_count_as_a_rule_hit() {
    let tunnel = tunnel_with_ghost_target();
    tunnel
        .inner()
        .resolve_proxy(&metadata())
        .await
        .expect("the no-match tail always resolves");

    assert!(
        tunnel.statistics().rule_match.snapshot().is_empty(),
        "a skipped rule must not be counted as a match — the DIRECT dial is the no-match tail"
    );
}

/// The parity case: `DOMAIN,ads.x,ghost` followed by `DOMAIN,ads.x,REJECT`
/// must refuse the connection, not silently direct-dial it.
#[tokio::test]
async fn a_later_rule_still_matches_after_a_skipped_dead_target() {
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(meow_rules::domain::DomainRule::new(
            "example.test",
            "ghost-group",
        )),
        Box::new(FinalRule::new("REJECT")),
    ];
    tunnel.update_rules(rules);

    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .await
        .expect("the FINAL rule resolves");

    assert_eq!(rule, "Match");
    assert_eq!(
        proxy.adapter_type(),
        AdapterType::Reject,
        "upstream skips the dead-target rule and lands on the later match"
    );
}

#[tokio::test]
async fn the_lazy_resolve_path_skips_the_same_way() {
    let tunnel = tunnel_with_ghost_target();

    let mut md = metadata();
    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy_lazy(&mut md)
        .await
        .expect("the no-match tail always resolves");

    assert_eq!(rule, "Final");
    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
    assert!(
        tunnel.statistics().rule_match.snapshot().is_empty(),
        "both resolve paths share the skipping scan, so both report no match"
    );
}

#[tokio::test]
async fn a_target_the_registry_holds_is_used_as_is() {
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("REJECT-DROP"))];
    tunnel.update_rules(rules);

    let ResolvedTarget {
        adapter: proxy,
        rule_name: _rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .await
        .expect("a MATCH rule always resolves");

    assert_eq!(proxy.adapter_type(), AdapterType::RejectDrop);
    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(("MATCH", "REJECT"), 1)],
        "a refusal the registry really performed is still counted as one"
    );
}

#[tokio::test]
async fn a_rule_naming_direct_needs_no_registry_entry() {
    // DIRECT is a built-in the tunnel owns an adapter for, so a rule naming it
    // must resolve even before any registry snapshot has been published — and
    // must not be reported as a fallback, because it is the intended target.
    let tunnel = Tunnel::new(resolver());
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("DIRECT"))];
    tunnel.update_rules(rules);

    let ResolvedTarget {
        adapter: proxy,
        rule_name: _rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .await
        .expect("a MATCH rule always resolves");

    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(("MATCH", "DIRECT"), 1)]
    );
}

#[tokio::test]
async fn no_rule_matching_still_falls_through_to_direct() {
    // Nothing matching at all is the ordinary end of the rule list, which has
    // never touched the match counters.
    let tunnel = tunnel_with_builtin_registry();
    let rules: Vec<Box<dyn Rule>> = vec![];
    tunnel.update_rules(rules);

    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .await
        .expect("the no-match path still yields DIRECT");

    assert_eq!(rule, "Final");
    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
    assert!(
        tunnel.statistics().rule_match.snapshot().is_empty(),
        "the fall-through is not a rule match and must not be counted as one"
    );
}

/// mihomo's `match()` runs a second `continue` for UDP flows: a matched rule
/// whose target lacks `SupportUDP()` is skipped, not dialed to failure.
#[tokio::test]
async fn udp_flow_skips_a_target_without_udp_support() {
    let yaml =
        "proxies:\n  - name: TCP-ONLY\n    type: http\n    server: 127.0.0.1\n    port: 8080\n";
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).expect("http node parses");

    let tunnel = Tunnel::new(resolver());
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(meow_rules::domain::DomainRule::new(
            "example.test",
            "TCP-ONLY",
        )),
        Box::new(FinalRule::new("REJECT")),
    ];
    tunnel.update_rules(rules);

    let mut udp_meta = metadata();
    udp_meta.network = Network::Udp;
    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&udp_meta)
        .await
        .expect("the later rule must win");

    // TCP flow still lands on the http adapter; UDP flow skips to REJECT —
    // exactly upstream's `!adapter.SupportUDP()` continue.
    assert_eq!(rule, "Match");
    assert_eq!(proxy.adapter_type(), AdapterType::Reject);

    let ResolvedTarget {
        adapter: tcp_proxy,
        rule_name: _r,
        rule_payload: _p,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .await
        .expect("tcp resolves");
    assert_eq!(tcp_proxy.adapter_type(), AdapterType::Http);
}

/// Issue #969 on the injected path: a `dialer-proxy` leaf whose adapter
/// carries the chain by *injection* — no `DialerProxyAdapter` wrapper —
/// must fail a matched UDP rule closed exactly like the relay fallback.
/// The config build marks the registry entry `ChainedProxy` for this
/// verdict; an unmarked leaf reads as a plain `udp: false` node and would
/// slide to `MATCH,DIRECT` in plaintext.
#[tokio::test]
async fn injected_http_chained_udp_fails_closed_not_slides_to_direct() {
    let yaml = "proxies:\n\
        \x20 - name: front\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n\
        \x20 - name: chained\n    type: http\n    server: 127.0.0.1\n    port: 8080\n    dialer-proxy: front\n";
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).expect("http chain parses");

    let tunnel = Tunnel::new(resolver());
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(meow_rules::domain::DomainRule::new(
            "example.test",
            "chained",
        )),
        Box::new(FinalRule::new("DIRECT")),
    ];
    tunnel.update_rules(rules);

    let mut udp_meta = metadata();
    udp_meta.network = Network::Udp;
    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&udp_meta)
        .await
        .expect("the match resolves to the chained target");

    // The scan stops *on* the match: the chained node is returned (its
    // dial then refuses UDP loudly), never the later rule's DIRECT.
    assert_eq!(rule, "Domain");
    assert_eq!(proxy.name(), "chained");
    assert_eq!(proxy.adapter_type(), AdapterType::Http);
}

/// The sibling shape (issue #969): a UDP-capable leaf whose injected
/// `dialer-proxy` front cannot carry UDP. `socks5` stands in for `ss`
/// (feature-gated out of this crate's dev tree) — both fold
/// `dialer.supports_udp()` into `support_udp`, which is what the probe
/// reads; the `ChainedProxy` marker then pins the fail-closed verdict.
#[tokio::test]
async fn injected_udp_leaf_via_udp_incapable_front_fails_closed() {
    let yaml = "proxies:\n\
        \x20 - name: front\n    type: http\n    server: 127.0.0.1\n    port: 8080\n\
        \x20 - name: chained\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    udp: true\n    dialer-proxy: front\n";
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).expect("socks5-via-http chain parses");

    let tunnel = Tunnel::new(resolver());
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(meow_rules::domain::DomainRule::new(
            "example.test",
            "chained",
        )),
        Box::new(FinalRule::new("DIRECT")),
    ];
    tunnel.update_rules(rules);

    let mut udp_meta = metadata();
    udp_meta.network = Network::Udp;
    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&udp_meta)
        .await
        .expect("the match resolves to the chained target");

    assert_eq!(rule, "Domain");
    assert_eq!(proxy.name(), "chained");
    assert_eq!(proxy.adapter_type(), AdapterType::Socks5);
}

/// The transparent half of #969 stays intact: a `type: direct` node cannot
/// take an injected dialer, so the chain lands on the relay-based
/// `DialerProxyAdapter`, whose transparent inner legitimately advertises
/// UDP — the flow routes over the front's association, never `Unusable`.
#[tokio::test]
async fn transparent_direct_relay_fallback_still_routes_udp() {
    let yaml = "proxies:\n\
        \x20 - name: front\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    udp: true\n\
        \x20 - name: chained\n    type: direct\n    dialer-proxy: front\n";
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).expect("direct chain parses");

    let tunnel = Tunnel::new(resolver());
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(meow_rules::domain::DomainRule::new(
            "example.test",
            "chained",
        )),
        Box::new(FinalRule::new("REJECT")),
    ];
    tunnel.update_rules(rules);

    let mut udp_meta = metadata();
    udp_meta.network = Network::Udp;
    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&udp_meta)
        .await
        .expect("the match resolves to the chained target");

    // Usable, not Unusable: the UDP flow takes the declared chain.
    assert_eq!(rule, "Domain");
    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
    assert!(
        proxy.support_udp(),
        "a transparent inner keeps UDP advertised over the front's association"
    );
    assert!(
        proxy.has_configured_dialer(),
        "the resolved adapter is the chain wrapper, not a bare DIRECT tail"
    );
}

/// The narrowing must not widen (issue #969): an *unchained* node that
/// cannot carry UDP keeps mihomo's `continue` — `udp: false` is a routing
/// preference, not a chain the flow must die inside — so the scan still
/// slides to the next rule.
#[tokio::test]
async fn plain_udp_false_unchained_still_slides() {
    let yaml = "proxies:\n  - name: no-udp\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    udp: false\n";
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).expect("socks5 node parses");

    let tunnel = Tunnel::new(resolver());
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(meow_rules::domain::DomainRule::new(
            "example.test",
            "no-udp",
        )),
        Box::new(FinalRule::new("REJECT")),
    ];
    tunnel.update_rules(rules);

    let mut udp_meta = metadata();
    udp_meta.network = Network::Udp;
    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&udp_meta)
        .await
        .expect("the later rule must win");

    assert_eq!(rule, "Match");
    assert_eq!(
        proxy.adapter_type(),
        AdapterType::Reject,
        "an unchained udp:false target stays Missing, not Unusable"
    );
}

/// The group counterpart of `transparent_direct_relay_fallback_still_routes_udp`
/// (issue #969): a `type: direct` member chained via `dialer-proxy` rides the
/// relay-based `DialerProxyAdapter`, whose transparent inner legitimately
/// advertises UDP — a group that forwards the verdict to its pick keeps the
/// rule Usable and the flow routes over the front's association.
#[tokio::test]
async fn transparent_direct_member_in_group_still_routes_udp() {
    let yaml = "proxies:\n\
        \x20 - name: front\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    udp: true\n\
        \x20 - name: chained-direct\n    type: direct\n    dialer-proxy: front\n\
        proxy-groups:\n\
        \x20 - name: g\n    type: select\n    proxies: [chained-direct]\n";
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).expect("direct chain in a group parses");

    let tunnel = Tunnel::new(resolver());
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(meow_rules::domain::DomainRule::new("example.test", "g")),
        Box::new(FinalRule::new("REJECT")),
    ];
    tunnel.update_rules(rules);

    let mut udp_meta = metadata();
    udp_meta.network = Network::Udp;
    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&udp_meta)
        .await
        .expect("the match resolves to the group");

    // Usable, not Unusable: the group's pick is a transparent chained
    // member, so the UDP flow takes the declared chain via the group.
    assert_eq!(rule, "Domain");
    assert_eq!(proxy.name(), "g");
    assert!(
        proxy.support_udp(),
        "a transparent inner keeps UDP advertised through the group pick"
    );
}

/// The group counterpart of `plain_udp_false_unchained_still_slides`
/// (issue #969): an *unchained* `udp: false` member inside a group is a
/// routing preference, not a chain the flow must die inside — the group
/// reports `support_udp() == false` without the fail-closed verdict, so
/// mihomo's `continue` is preserved and the scan still slides.
#[tokio::test]
async fn plain_udp_false_member_unchained_in_group_still_slides() {
    let yaml = "proxies:\n\
        \x20 - name: no-udp\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    udp: false\n\
        proxy-groups:\n\
        \x20 - name: g\n    type: select\n    proxies: [no-udp]\n";
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).expect("group over udp:false member parses");

    let tunnel = Tunnel::new(resolver());
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(meow_rules::domain::DomainRule::new("example.test", "g")),
        Box::new(FinalRule::new("REJECT")),
    ];
    tunnel.update_rules(rules);

    let mut udp_meta = metadata();
    udp_meta.network = Network::Udp;
    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&udp_meta)
        .await
        .expect("the later rule must win");

    assert_eq!(rule, "Match");
    assert_eq!(
        proxy.adapter_type(),
        AdapterType::Reject,
        "a group whose pick is an unchained udp:false member stays Missing, not Unusable"
    );
}

/// The residual #969 hole this change closes end-to-end: a rule targeting a
/// *group* whose pick is a chained, UDP-incapable member must stop on the
/// match — the group forwards `is_dialer_proxy_non_transparent` to the same
/// pick `support_udp` consults — instead of sliding to `MATCH,DIRECT` in
/// plaintext. Before the forwarding existed, every group answered `false`
/// and the scan slid past the pinned chain.
#[tokio::test]
async fn group_pick_chained_udp_incapable_fails_closed() {
    let yaml = "proxies:\n\
        \x20 - name: front\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n\
        \x20 - name: chained\n    type: http\n    server: 127.0.0.1\n    port: 8080\n    dialer-proxy: front\n\
        proxy-groups:\n\
        \x20 - name: g\n    type: select\n    proxies: [chained]\n";
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).expect("group over chained member parses");
    let group = Arc::clone(&res.proxies["g"]);
    assert!(
        group.is_dialer_proxy_non_transparent(),
        "the group's pick must carry the chain marker through member capture"
    );

    let tunnel = Tunnel::new(resolver());
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(meow_rules::domain::DomainRule::new("example.test", "g")),
        Box::new(FinalRule::new("DIRECT")),
    ];
    tunnel.update_rules(rules);

    let mut udp_meta = metadata();
    udp_meta.network = Network::Udp;
    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&udp_meta)
        .await
        .expect("the match resolves to the group");

    // The scan stops *on* the match: the group is returned (its pick's
    // dial then refuses UDP loudly), never the later rule's DIRECT.
    assert_eq!(rule, "Domain");
    assert_eq!(proxy.name(), "g");
}
