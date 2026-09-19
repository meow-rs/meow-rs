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

#[test]
fn a_matched_rule_with_a_missing_target_is_skipped_to_the_tail() {
    let tunnel = tunnel_with_ghost_target();

    let ResolvedTarget {
        adapter: proxy,
        rule_name: rule,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("the no-match tail always resolves");

    // The MATCH was skipped, not honored: nothing matched, so the reported
    // rule is the no-match tail and the dial is DIRECT — exactly what
    // upstream produces for `MATCH,ghost`.
    assert_eq!(rule, "Final");
    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
}

#[test]
fn a_skipped_match_does_not_count_as_a_rule_hit() {
    let tunnel = tunnel_with_ghost_target();
    tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("the no-match tail always resolves");

    assert!(
        tunnel.statistics().rule_match.snapshot().is_empty(),
        "a skipped rule must not be counted as a match — the DIRECT dial is the no-match tail"
    );
}

/// The parity case: `DOMAIN,ads.x,ghost` followed by `DOMAIN,ads.x,REJECT`
/// must refuse the connection, not silently direct-dial it.
#[test]
fn a_later_rule_still_matches_after_a_skipped_dead_target() {
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
        .expect("the FINAL rule resolves");

    assert_eq!(rule, "MATCH");
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

#[test]
fn a_target_the_registry_holds_is_used_as_is() {
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
        .expect("a MATCH rule always resolves");

    assert_eq!(proxy.adapter_type(), AdapterType::RejectDrop);
    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(("MATCH", "REJECT"), 1)],
        "a refusal the registry really performed is still counted as one"
    );
}

#[test]
fn a_rule_naming_direct_needs_no_registry_entry() {
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
        .expect("a MATCH rule always resolves");

    assert_eq!(proxy.adapter_type(), AdapterType::Direct);
    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(("MATCH", "DIRECT"), 1)]
    );
}

#[test]
fn no_rule_matching_still_falls_through_to_direct() {
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
#[test]
fn udp_flow_skips_a_target_without_udp_support() {
    let yaml =
        "proxies:\n  - name: TCP-ONLY\n    type: http\n    server: 127.0.0.1\n    port: 8080\n";
    let raw: meow_config::raw::RawConfig = serde_yaml::from_str(yaml).unwrap();
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
        .expect("the later rule must win");

    // TCP flow still lands on the http adapter; UDP flow skips to REJECT —
    // exactly upstream's `!adapter.SupportUDP()` continue.
    assert_eq!(rule, "MATCH");
    assert_eq!(proxy.adapter_type(), AdapterType::Reject);

    let ResolvedTarget {
        adapter: tcp_proxy,
        rule_name: _r,
        rule_payload: _p,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&metadata())
        .expect("tcp resolves");
    assert_eq!(tcp_proxy.adapter_type(), AdapterType::Http);
}
