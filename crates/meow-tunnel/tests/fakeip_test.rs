//! End-to-end fake-IP behaviour through the tunnel layer:
//!
//! 1. Resolver synthesises a stable fake IP for a host.
//! 2. A connection arriving with that fake IP as `metadata.dst_ip` (the
//!    common case from a TUN/tproxy listener) is rewritten back to the
//!    hostname by `TunnelInner::pre_handle_metadata` before rule matching.
//! 3. `pre_resolve` then re-resolves the hostname to a real IP.

use ipnet::IpNet;
use meow_common::{DnsMode, Metadata, Network};
use meow_dns::fakeip::{MemoryStore, Pool};
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::{PreHandleVerdict, Tunnel};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

fn build_fakeip_resolver() -> Arc<Resolver> {
    let mut resolver = Resolver::new(
        vec![],
        vec![],
        DnsMode::FakeIp,
        DomainTrie::new(),
        true,
        true,
    );
    let net = "198.18.0.0/16".parse::<IpNet>().unwrap();
    let pool = Pool::new(net, Arc::new(MemoryStore::new(1024))).unwrap();
    resolver.set_fakeip_v4(Arc::new(pool));
    Arc::new(resolver)
}

#[tokio::test]
async fn fakeip_destination_rewritten_to_hostname() {
    let resolver = build_fakeip_resolver();

    // Synthesise a fake IP for the host first (this is what a DNS query
    // would have done before the connection arrived).
    let fake = resolver.lookup_ipv4("example.test").await.unwrap();
    assert!(
        resolver.is_fake_ip(fake),
        "synthesised IP must be recognised as fake, got {fake}"
    );
    assert_eq!(&fake.to_string()[..6], "198.18");

    // Build a tunnel and hand it a connection with dst_ip = fake, host = empty.
    let tunnel = Tunnel::new(resolver);
    let mut md = Metadata {
        host: "".into(),
        dst_ip: Some(fake),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };

    let verdict = tunnel.inner().pre_handle_metadata(&mut md);

    assert_eq!(verdict, PreHandleVerdict::Continue);
    assert_eq!(
        md.host.as_str(),
        "example.test",
        "pre_handle_metadata must recover hostname from the pool reverse map"
    );
    assert_eq!(
        md.dst_ip, None,
        "pre_handle_metadata must clear the fake IP so the adapter re-resolves"
    );
}

#[tokio::test]
async fn live_fakeip_routes_and_dials_by_the_mapped_name() {
    let resolver = build_fakeip_resolver();
    let fake = resolver.lookup_ipv4("mapped.test").await.unwrap();
    let tunnel = Tunnel::new(resolver);
    let cfg = meow_config::rebuild_from_raw(&Default::default()).unwrap();
    tunnel.update_proxies(cfg.proxies, cfg.dialer_registry);
    tunnel.update_rules(vec![
        Box::new(meow_rules::domain_suffix::DomainSuffixRule::new(
            "sniffed.test",
            "REJECT",
        )),
        Box::new(meow_rules::domain_suffix::DomainSuffixRule::new(
            "mapped.test",
            "DIRECT",
        )),
    ]);
    for network in [Network::Tcp, Network::Udp] {
        // A conflicting sniffed name is discarded; a matching one —
        // including its FQDN spelling — is kept verbatim, as is no
        // sniffed name at all.
        for (sniff, expected_sniff) in [
            ("sniffed.test", ""),
            ("mapped.test.", "mapped.test."),
            ("", ""),
        ] {
            let mut md = Metadata {
                network,
                dst_ip: Some(fake),
                dst_port: 443,
                sniff_host: sniff.into(),
                ..Default::default()
            };
            assert_eq!(
                tunnel.inner().pre_handle_metadata(&mut md),
                PreHandleVerdict::Continue
            );
            assert_eq!(md.sniff_host.as_str(), expected_sniff);
            assert_eq!(md.host.as_str(), "mapped.test");
            let target = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
            assert_eq!(target.rule_payload, "mapped.test");
            assert_eq!(target.adapter.name(), "DIRECT");
            assert_eq!(md.remote_address().to_string(), "mapped.test:443");
        }
    }
}

#[tokio::test]
async fn non_fakeip_destination_passes_through() {
    // Same resolver, but the incoming connection arrives with a real IP
    // (e.g. a SOCKS5 client dialed directly). pre_handle_metadata must
    // NOT modify dst_ip or host.
    let resolver = build_fakeip_resolver();
    let tunnel = Tunnel::new(resolver);
    let bystander = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let mut md = Metadata {
        host: "".into(),
        dst_ip: Some(bystander),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    let verdict = tunnel.inner().pre_handle_metadata(&mut md);
    assert_eq!(verdict, PreHandleVerdict::Continue);
    assert_eq!(md.dst_ip, Some(bystander), "real IP must stay put");
    assert_eq!(md.host.as_str(), "");
}

/// Issue #618: an address inside the fake-IP range with no live
/// allocation (stale after restart/wrap, or a literal connect into the
/// range) must be dropped — never dialed. Under TUN `auto-route` the
/// whole fake range routes into the device, so dialing a stale fake IP
/// re-enters the listener and self-saturates `max-connections`.
#[tokio::test]
async fn unmapped_fakeip_destination_is_dropped() {
    let resolver = build_fakeip_resolver();
    let tunnel = Tunnel::new(resolver);

    // In range, never allocated: first allocatable (.4), pool gateway
    // (.1), network (.0) and broadcast (.255.255) all drop.
    for octets in [
        [198, 18, 0, 4],
        [198, 18, 0, 1],
        [198, 18, 0, 0],
        [198, 18, 255, 255],
    ] {
        let stale = IpAddr::V4(Ipv4Addr::from(octets));
        let mut md = Metadata {
            host: "".into(),
            dst_ip: Some(stale),
            dst_port: 80,
            network: Network::Tcp,
            ..Default::default()
        };
        assert_eq!(
            tunnel.inner().pre_handle_metadata(&mut md),
            PreHandleVerdict::Drop,
            "unmapped fake-IP {stale} must be dropped, not dialed"
        );
        assert_eq!(
            md.dst_ip,
            Some(stale),
            "Drop leaves metadata untouched — the caller aborts"
        );
    }
}

/// `CONNECT 198.18.0.9:443` through the HTTP listener puts the *literal*
/// in `metadata.host` alongside `dst_ip` — a literal is the same stale
/// address, not a rescuable name, so the verdict must still be Drop.
#[tokio::test]
async fn fakeip_literal_in_host_does_not_rescue() {
    let resolver = build_fakeip_resolver();
    let tunnel = Tunnel::new(resolver);
    let mut md = Metadata {
        host: "198.18.0.9".into(),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Drop,
        "an IP literal in `host` is not a recoverable hostname"
    );
}

/// SOCKS5 `ATYP_DOMAIN` / SS `DomainNameAddress` put the literal in `host`
/// with `dst_ip = None` — without `fixMetadata`-style folding the range
/// check never ran at all. The literal must be folded into `dst_ip` and
/// dropped. A *live* fake IP carried the same way still reverse-maps.
#[tokio::test]
async fn fakeip_domain_typed_literal_folds_and_drops() {
    let resolver = build_fakeip_resolver();
    let fake = resolver.lookup_ipv4("example.test").await.unwrap();
    let tunnel = Tunnel::new(resolver);

    // Stale, domain-typed: folds into dst_ip → Drop.
    let mut md = Metadata {
        host: "198.18.0.9".into(),
        dst_ip: None,
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Drop,
        "domain-typed stale literal must fold into dst_ip and drop"
    );

    // Live allocation, domain-typed: folds → reverse-maps → rescues.
    let mut md = Metadata {
        host: fake.to_string().into(),
        dst_ip: None,
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Continue
    );
    assert_eq!(md.host.as_str(), "example.test");
    assert_eq!(md.dst_ip, None);
}

/// A sniffed name (`sniff_host`) rescues a stale flow even when `host` is
/// empty — upstream re-runs `TCPSniff` on this exact failure. The promoted
/// name must replace the literal so `remote_address()` dials the name.
#[tokio::test]
async fn sniff_host_rescues_stale_fakeip() {
    let resolver = build_fakeip_resolver();
    let tunnel = Tunnel::new(resolver);
    let mut md = Metadata {
        host: "".into(),
        sniff_host: "sni.example".into(),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Continue
    );
    assert_eq!(md.host.as_str(), "sni.example", "sniffed name promoted");
    assert_eq!(md.dst_ip, None, "stale literal cleared on rescue");

    // A sniffed *literal* is no rescue either.
    let mut md = Metadata {
        host: "".into(),
        sniff_host: "198.18.0.9".into(),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Drop,
        "an IP literal in sniff_host is not a name"
    );
}

/// `::ffff:198.18.x.x` (v4-mapped v6) must hit the v4 range check —
/// upstream `fixMetadata` unmaps `DstIP` before `preHandleMetadata`.
#[tokio::test]
async fn v4_mapped_v6_fakeip_drops() {
    let resolver = build_fakeip_resolver();
    let tunnel = Tunnel::new(resolver);
    let mut md = Metadata {
        host: "".into(),
        dst_ip: Some("::ffff:198.18.0.9".parse().unwrap()),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Drop,
        "v4-mapped v6 must unmap before the range check"
    );
    assert_eq!(
        md.dst_ip,
        Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))),
        "dst_ip is normalized to its canonical form"
    );
}

/// A *snooped* reverse name for a stale fake IP still rescues the flow:
/// the adapter dials the learned name. A snoop entry keyed on a pool-range
/// IP can only exist via an upstream answer inside the range (a chained
/// fake-IP resolver sharing the range, or poisoned data) — safe because
/// `resolve_ips` filters in-range results, so the rescued name cannot
/// resolve back into the range and re-sustain the loop.
#[tokio::test]
async fn snooped_name_for_stale_fakeip_rescues() {
    let resolver = build_fakeip_resolver();
    resolver.preload_cache(
        "snooped.test",
        &[IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))],
        std::time::Duration::from_secs(60),
    );
    let tunnel = Tunnel::new(resolver);
    let mut md = Metadata {
        host: "".into(),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Continue,
        "a snooped name is a real recovery path — dial by name"
    );
    assert_eq!(md.host.as_str(), "snooped.test");
    assert_eq!(md.dst_ip, None);
}

/// The v6 pool arm of `in_fake_ip_range`: an unmapped v6 fake IP drops,
/// while a v6 literal against a v4-only pool passes through untouched.
#[tokio::test]
async fn fakeip_v6_range_drops_unmapped() {
    let mut resolver = Resolver::new(
        vec![],
        vec![],
        DnsMode::FakeIp,
        DomainTrie::new(),
        true,
        true,
    );
    resolver.set_fakeip_v6(Arc::new(
        Pool::new(
            "fc00::/64".parse::<IpNet>().unwrap(),
            Arc::new(MemoryStore::new(1024)),
        )
        .unwrap(),
    ));
    let resolver = Arc::new(resolver);
    let tunnel = Tunnel::new(resolver);

    let mut md = Metadata {
        host: "".into(),
        dst_ip: Some("fc00::9".parse().unwrap()),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Drop,
        "unmapped v6 fake-IP must drop"
    );

    // v4-only pool: a v6 literal is out of range → untouched.
    let resolver = build_fakeip_resolver();
    let tunnel = Tunnel::new(resolver);
    let v6 = IpAddr::V6("fd00::1".parse().unwrap());
    let mut md = Metadata {
        host: "".into(),
        dst_ip: Some(v6),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Continue
    );
    assert_eq!(md.dst_ip, Some(v6), "out-of-range literal must stay put");
}

/// Issue #618 sibling: a stale fake IP that still carries a hostname
/// (e.g. sniffed SNI) is rescued — the adapter resolves the real name
/// instead of dialing the looping literal. A sniffed name that
/// conflicts with the surviving `host` is discarded: `rule_host()`
/// prefers `sniff_host`, so keeping it would route by one domain while
/// `remote_address()` dials another.
#[tokio::test]
async fn stale_fakeip_with_host_falls_back_to_name() {
    let resolver = build_fakeip_resolver();
    let tunnel = Tunnel::new(resolver);
    let cfg = meow_config::rebuild_from_raw(&Default::default()).unwrap();
    tunnel.update_proxies(cfg.proxies, cfg.dialer_registry);
    tunnel.update_rules(vec![
        Box::new(meow_rules::domain_suffix::DomainSuffixRule::new(
            "sniffed.test",
            "REJECT",
        )),
        Box::new(meow_rules::domain_suffix::DomainSuffixRule::new(
            "example.test",
            "DIRECT",
        )),
    ]);
    let mut md = Metadata {
        host: "example.test".into(),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Continue
    );
    assert_eq!(
        md.dst_ip, None,
        "stale literal must clear so the adapter resolves the host"
    );
    assert_eq!(md.host.as_str(), "example.test");

    // The rescued `host` wins the dial, so a sniffed name that differs
    // must not keep routing the flow by its own domain; a matching one
    // (modulo a trailing dot) is kept verbatim.
    for (sniff, expected_sniff) in [
        ("sniffed.test", ""),
        ("example.test.", "example.test."),
        ("", ""),
    ] {
        let mut md = Metadata {
            host: "example.test".into(),
            sniff_host: sniff.into(),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))),
            dst_port: 443,
            network: Network::Tcp,
            ..Default::default()
        };
        assert_eq!(
            tunnel.inner().pre_handle_metadata(&mut md),
            PreHandleVerdict::Continue
        );
        assert_eq!(md.sniff_host.as_str(), expected_sniff);
        assert_eq!(md.host.as_str(), "example.test");
        let target = tunnel.inner().resolve_proxy_lazy(&mut md).await.unwrap();
        assert_eq!(target.rule_payload, "example.test");
        assert_eq!(target.adapter.name(), "DIRECT");
        assert_eq!(md.remote_address().to_string(), "example.test:443");
    }
}

/// Issue #701: `CONNECT [::1]:443` fills `host="[::1]"` *and*
/// `dst_ip=::1` (the HTTP listener parses one bracket-tolerantly and
/// keeps the other verbatim). The literal must still be folded out —
/// otherwise host-first encoders emit `"[::1]"` as a domain on the wire
/// even though the typed IP is right there. A conflicting `dst_ip`
/// keeps precedence: the literal host is display text, not a name.
#[tokio::test]
async fn bracketed_host_literal_cleared_alongside_dst_ip() {
    let resolver = build_fakeip_resolver();
    let tunnel = Tunnel::new(resolver);
    let mut md = Metadata {
        host: "[::1]".into(),
        dst_ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Continue
    );
    assert_eq!(md.host.as_str(), "", "a literal is never a domain name");
    assert_eq!(md.dst_ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    // Same fold for a bare-literal host that disagrees with dst_ip:
    // dst_ip wins, the literal display string is dropped.
    let mut md = Metadata {
        host: "8.8.8.8".into(),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert_eq!(
        tunnel.inner().pre_handle_metadata(&mut md),
        PreHandleVerdict::Continue
    );
    assert_eq!(md.host.as_str(), "");
    assert_eq!(md.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
}

#[tokio::test]
async fn fakeip_skipper_bypasses_filtered_host() {
    // Build a resolver with a skipper that BYPASSES the test host. The
    // fake-IP pool then leaves the host alone — but because there's no
    // upstream nameserver configured, the lookup returns None.
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
    use meow_dns::fakeip::{Skipper, SkipperMode};
    resolver.set_fakeip_skipper(Skipper::new(
        &["+.bypass.test".to_string()],
        SkipperMode::BlackList,
    ));

    let result = resolver.lookup_ipv4("foo.bypass.test").await;
    assert!(
        result.is_none(),
        "filtered host with no upstream resolver must return None, got {result:?}"
    );
    // Non-filtered host still gets a fake IP.
    let other = resolver.lookup_ipv4("other.test").await.unwrap();
    assert!(resolver.is_fake_ip(other));
}
