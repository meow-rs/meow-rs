//! Verify lazy enrichment in `resolve_proxy_lazy`: DNS pre-resolution runs
//! only when the rule scan reaches an IP-demanding rule, and is skipped
//! entirely when an earlier rule already matched.

use meow_common::{DnsMode, Metadata, Network, Rule};
use meow_dns::{HostEntry, Resolver};
use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule, ipcidr::IpCidrRule};
use meow_trie::DomainTrie;
use meow_tunnel::{ResolvedTarget, Tunnel};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn build_resolver_with_host(host: &str, ip: IpAddr) -> Arc<Resolver> {
    let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
    hosts.insert(host, vec![ip].into());
    Arc::new(Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        hosts,
        true,
        true,
    ))
}

/// A rule scan skips a match whose target is absent from the registry
/// (issue #513), so these tests publish a registry that actually holds the
/// names their rules target (`PROXY`, `DOM`) as direct-backed entries.
fn tunnel_with_targets(resolver: Arc<Resolver>, names: &[&str]) -> Tunnel {
    let raw = format!(
        "proxies:\n{}\n",
        names
            .iter()
            .map(|n| format!("  - name: {n}\n    type: direct"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let cfg: meow_config::raw::RawConfig = serde_yaml::from_str(&raw).unwrap();
    let res = meow_config::rebuild_from_raw(&cfg).unwrap();
    let tunnel = Tunnel::new(resolver);
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel
}

#[tokio::test]
async fn lazy_resolves_ip_when_scan_reaches_ipcidr_rule() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = tunnel_with_targets(resolver, &["PROXY", "DOM"]);

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap()),
        Box::new(FinalRule::new("DIRECT")),
    ];
    tunnel.update_rules(rules);

    let mut md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    let ResolvedTarget {
        adapter: _proxy,
        rule_name,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy_lazy(&mut md)
        .await
        .expect("rule should match");
    assert_eq!(rule_name, "IP-CIDR");
    assert_eq!(
        md.dst_ip,
        Some(real_ip),
        "lazy path must have resolved dst_ip to evaluate the IP rule",
    );
}

#[tokio::test]
async fn lazy_skips_dns_when_domain_rule_matches_first() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = tunnel_with_targets(resolver, &["PROXY", "DOM"]);

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainSuffixRule::new("example.test", "DOM")),
        Box::new(IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap()),
        Box::new(FinalRule::new("DIRECT")),
    ];
    tunnel.update_rules(rules);

    let mut md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    let ResolvedTarget {
        adapter: _proxy,
        rule_name,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy_lazy(&mut md)
        .await
        .expect("rule should match");
    assert_eq!(rule_name, "DOMAIN-SUFFIX");
    assert!(
        md.dst_ip.is_none(),
        "domain match must not trigger DNS resolution",
    );
}

#[tokio::test]
async fn lazy_falls_through_to_final_when_nothing_matches() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = tunnel_with_targets(resolver, &["PROXY", "DOM"]);

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap()),
        Box::new(FinalRule::new("DIRECT")),
    ];
    tunnel.update_rules(rules);

    let mut md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    let ResolvedTarget {
        adapter: _proxy,
        rule_name,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy_lazy(&mut md)
        .await
        .expect("FINAL should match");
    // Resolution happened (9.9.9.9 does not match the CIDR), then the
    // strict re-match fell through to FINAL.
    assert_eq!(md.dst_ip, Some(real_ip));
    assert_eq!(rule_name, "MATCH");
}
