//! `dns.respect-rules`: dial a nameserver's *own* connection through the
//! tunnel's rule engine.
//!
//! mihomo's `respect-rules` reuses `resolveMetadata` on a synthetic
//! `metadata` whose destination is the upstream DNS server
//! (`tunnel/dns_dialer.go`): the rules pick a proxy for the DNS server, not
//! for the domain being looked up. This module is the meow-rs counterpart —
//! it holds a weak handle to the tunnel instead of capturing a route
//! generation, so a `rules:`/`proxies:` swap is picked up by the next dial
//! with no republish (and no chance of pinning a dead generation).
//!
//! Recursion is bounded by configuration, not by this code:
//! `dns.respect-rules` requires `proxy-server-nameserver`
//! (`RawDns::respect_rules`), so the proxy's own server hostname resolves
//! through a resolver that is deliberately *not* rule-routed, and the
//! nameserver URLs themselves are resolved at build time.

use crate::tunnel::{ResolvedTarget, TunnelInner};
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use std::sync::{Arc, Weak};
use tracing::debug;

/// The adapter a `respect-rules` nameserver dials through: a thin router over
/// one live tunnel.
///
/// Health surface is inert — this adapter never appears in the route table and
/// no health check ever probes it, so it reports "alive while the tunnel
/// exists" and no delay history.
pub struct RulesDialer {
    inner: Weak<TunnelInner>,
    /// Inert health cell — the router is never probed (it is not in the route
    /// table), and `ProxyAdapter::health` must return a reference that does not
    /// borrow through a lock guard.
    health: ProxyHealth,
}

impl RulesDialer {
    pub fn new(inner: Weak<TunnelInner>) -> Self {
        Self {
            inner,
            health: ProxyHealth::new(),
        }
    }

    /// The tunnel's decision for `metadata`, plus the route generation it came
    /// from. The caller must keep the returned target alive across the dial —
    /// it pins the generation's dialer registry (see [`ResolvedTarget`]).
    async fn resolve(&self, metadata: &Metadata) -> Result<ResolvedTarget> {
        let inner = self.inner.upgrade().ok_or_else(|| {
            MeowError::Proxy("dns.respect-rules: the owning tunnel no longer exists".into())
        })?;
        // `resolve_proxy` is mihomo's `resolveMetadata`: special-proxy forward,
        // then mode dispatch (direct/global/rule), then the rule scan with lazy
        // IP/process enrichment. `metadata.type` is `inner`, so a process rule
        // never triggers an OS lookup on the DNS path.
        let target = inner.resolve_proxy(metadata).await.ok_or_else(|| {
            MeowError::Proxy("dns.respect-rules: the rule engine returned no decision".into())
        })?;
        debug!(
            upstream = %metadata.host,
            port = metadata.dst_port,
            adapter = target.adapter.name(),
            rule = %target.rule_name,
            "dns.respect-rules: nameserver dial routed"
        );
        Ok(target)
    }
}

/// Fill `cell` with a dialer bound to `tunnel`.
///
/// Called by the two install sites — `meow` startup and
/// `meow_api::routes::install_resolver_everywhere` — so the construction
/// contract lives in one place. Publish *before* the resolver generation
/// becomes reachable (`Tunnel::set_resolver`): a query that lands on the new
/// generation while its cell is still empty fails its rule-routed dial.
pub fn publish(cell: &meow_dns::RespectRulesCell, tunnel: &crate::Tunnel) {
    *cell.write() = Some(Arc::new(RulesDialer::new(tunnel.weak_inner())));
}

#[async_trait::async_trait]
impl ProxyAdapter for RulesDialer {
    fn name(&self) -> &str {
        meow_dns::RESPECT_RULES_PROXY
    }

    fn addr(&self) -> &str {
        ""
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }

    fn support_udp(&self) -> bool {
        // The matched adapter answers for itself at dial time; claiming UDP
        // here keeps the DNS build from rejecting UDP upstreams up front.
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        // `target` owns the pinned route generation (see `ResolvedTarget`)
        // and stays in scope for the whole dial.
        self.resolve(metadata)
            .await?
            .adapter
            .dial_tcp(metadata)
            .await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.resolve(metadata)
            .await?
            .adapter
            .dial_udp(metadata)
            .await
    }
}

impl Proxy for RulesDialer {
    fn alive(&self) -> bool {
        self.inner.strong_count() > 0
    }

    fn alive_for_url(&self, _url: &str) -> bool {
        self.alive()
    }

    fn last_delay(&self) -> u16 {
        0
    }

    fn last_delay_for_url(&self, _url: &str) -> u16 {
        0
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ConnType, DnsMode, Network, ProxyHealth};
    use std::collections::HashMap;

    /// A proxy that records the fact it was dialled by failing with its name.
    struct Recording {
        name: &'static str,
        health: ProxyHealth,
    }

    #[async_trait::async_trait]
    impl ProxyAdapter for Recording {
        fn name(&self) -> &str {
            self.name
        }
        fn addr(&self) -> &str {
            ""
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
        fn support_udp(&self) -> bool {
            true
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
            Err(MeowError::Proxy(format!("{} dialed", self.name)))
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            Err(MeowError::Proxy(format!("{} dialed", self.name)))
        }
    }

    impl Proxy for Recording {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
    }

    fn recording_proxies() -> HashMap<smol_str::SmolStr, Arc<dyn Proxy>> {
        let mut proxies: HashMap<smol_str::SmolStr, Arc<dyn Proxy>> = HashMap::new();
        for name in ["HIT", "MISS"] {
            proxies.insert(
                smol_str::SmolStr::new(name),
                Arc::new(Recording {
                    name,
                    health: ProxyHealth::new(),
                }) as Arc<dyn Proxy>,
            );
        }
        proxies
    }

    fn rules(lines: &[&str]) -> Vec<Box<dyn meow_common::Rule>> {
        lines
            .iter()
            .map(|line| {
                meow_rules::parse_rule(line, &meow_rules::ParserContext::default()).unwrap()
            })
            .collect()
    }

    fn tunnel_with(lines: &[&str]) -> crate::Tunnel {
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            false,
        ));
        let tunnel = crate::Tunnel::new(resolver);
        tunnel.update_routing(
            recording_proxies(),
            rules(lines),
            Default::default(),
            Default::default(),
        );
        tunnel
    }

    /// The metadata the DNS client builds for a proxied exchange: the
    /// upstream's own address, `type: inner`.
    fn upstream_meta(ip: &str) -> Metadata {
        Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            host: ip.into(),
            dst_ip: Some(ip.parse().unwrap()),
            dst_port: 53,
            internal: true,
            ..Default::default()
        }
    }

    /// The rules see the *nameserver* address, so an IP rule above the
    /// catch-all decides which adapter carries the DNS query.
    #[tokio::test]
    async fn routes_the_upstream_dial_by_rule() {
        let tunnel = tunnel_with(&["IP-CIDR,192.0.2.0/24,HIT", "MATCH,MISS"]);
        let dialer = RulesDialer::new(tunnel.weak_inner());

        let Err(err) = dialer.dial_tcp(&upstream_meta("192.0.2.53")).await else {
            panic!("the recording proxy always fails the dial");
        };
        assert!(err.to_string().contains("HIT dialed"), "{err}");

        let Err(err) = dialer.dial_tcp(&upstream_meta("198.51.100.7")).await else {
            panic!("the recording proxy always fails the dial");
        };
        assert!(err.to_string().contains("MISS dialed"), "{err}");
    }

    /// The design promise: a `rules:` swap is seen by the *next* dial with
    /// no republish and no pinned generation.
    #[tokio::test]
    async fn rules_swap_is_seen_by_the_next_dial() {
        let tunnel = tunnel_with(&["MATCH,MISS"]);
        let dialer = RulesDialer::new(tunnel.weak_inner());
        let Err(err) = dialer.dial_tcp(&upstream_meta("192.0.2.53")).await else {
            panic!("the recording proxy always fails the dial");
        };
        assert!(err.to_string().contains("MISS dialed"), "{err}");

        tunnel.update_routing(
            recording_proxies(),
            rules(&["MATCH,HIT"]),
            Default::default(),
            Default::default(),
        );
        let Err(err) = dialer.dial_tcp(&upstream_meta("192.0.2.53")).await else {
            panic!("the recording proxy always fails the dial");
        };
        assert!(err.to_string().contains("HIT dialed"), "{err}");
    }

    /// A UDP upstream goes through `dial_udp` and must honour the same rule
    /// decision.
    #[tokio::test]
    async fn udp_dials_follow_the_same_decision() {
        let tunnel = tunnel_with(&["IP-CIDR,192.0.2.0/24,HIT", "MATCH,MISS"]);
        let dialer = RulesDialer::new(tunnel.weak_inner());
        let mut meta = upstream_meta("192.0.2.53");
        meta.network = Network::Udp;
        let Err(err) = dialer.dial_udp(&meta).await else {
            panic!("the recording proxy always fails the dial");
        };
        assert!(err.to_string().contains("HIT dialed"), "{err}");
    }

    /// A dial after the tunnel is gone must fail loudly instead of falling
    /// back to a direct connection.
    #[tokio::test]
    async fn dead_tunnel_fails_the_dial() {
        let weak = {
            let tunnel = tunnel_with(&["MATCH,MISS"]);
            tunnel.weak_inner()
        };
        let dialer = RulesDialer::new(weak);
        let Err(err) = dialer.dial_tcp(&upstream_meta("192.0.2.53")).await else {
            panic!("a dead tunnel must not dial");
        };
        assert!(err.to_string().contains("no longer exists"), "{err}");
    }
}
