//! Verify that hostname-only metadata is resolved to a real IP before
//! IP-CIDR / GeoIP rule matching, using the internal Resolver.

use meow_common::{DnsMode, Metadata, Network, Rule};
use meow_dns::{HostEntry, Resolver};
use meow_rules::ipcidr::IpCidrRule;
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

#[tokio::test]
async fn pre_resolve_populates_dst_ip_for_ipcidr_rule() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = Tunnel::new(resolver);

    // A rule scan skips a match whose target is absent from the registry
    // (issue #513), so publish a `PROXY` entry the rule can resolve to.
    let cfg: meow_config::raw::RawConfig =
        serde_yaml::from_str("proxies:\n  - name: PROXY\n    type: direct\n").unwrap();
    let res = meow_config::rebuild_from_raw(&cfg).unwrap();
    tunnel.update_proxies(res.proxies, res.dialer_registry);

    let rule: Box<dyn Rule> =
        Box::new(IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap());
    tunnel.update_rules(vec![rule]);

    let mut md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert!(md.dst_ip.is_none());

    tunnel.inner().pre_resolve(&mut md).await;

    assert_eq!(md.dst_ip, Some(real_ip), "pre_resolve should fill dst_ip");
    let ResolvedTarget {
        adapter: _proxy,
        rule_name,
        rule_payload: _payload,
        route: _route,
    } = tunnel
        .inner()
        .resolve_proxy(&md)
        .expect("rule should match");
    assert_eq!(rule_name, "IP-CIDR");
}

#[tokio::test]
async fn pre_resolve_skips_when_no_rule_needs_ip() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = Tunnel::new(resolver);

    // Empty rules => needs_ip_resolution is false. pre_resolve must not
    // populate dst_ip.
    let mut md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    tunnel.inner().pre_resolve(&mut md).await;
    assert!(md.dst_ip.is_none(), "no rules need ip => no resolution");
}
