//! DNS must dial the published route generation, not startup's draft adapters.
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use meow_proxy::dialer::{DialerTarget, ProxyRegistry};
use smol_str::SmolStr;
use std::{collections::HashMap, sync::Arc};

pub(crate) fn registry(
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    generation: &ProxyRegistry,
) -> HashMap<SmolStr, Arc<dyn Proxy>> {
    proxies
        .iter()
        .map(|(name, proxy)| {
            let bound: Arc<dyn Proxy> = Arc::new(DnsProxy {
                target: DialerTarget::new(name.clone(), generation),
                addr: proxy.addr().into(),
                adapter_type: proxy.adapter_type(),
                health: ProxyHealth::new(),
                configured_dialer: proxy.has_configured_dialer(),
                fingerprint: proxy.client_fingerprint().map(Box::from),
            });
            (name.clone(), bound)
        })
        .collect()
}

/// No sessions or lifecycle owner: the tunnel's routing table owns the target.
/// The weak target also avoids resolver -> DIRECT -> resolver reference cycles.
struct DnsProxy {
    target: DialerTarget,
    addr: String,
    adapter_type: AdapterType,
    health: ProxyHealth,
    configured_dialer: bool,
    /// The published entry's baked uTLS `client-fingerprint`. Bound at
    /// construction like `configured_dialer` because the trait's
    /// `Option<&str>` cannot borrow through `resolve()`'s temporary
    /// `Arc` — and it need not: `ProxyRegistry::publish` runs once per
    /// generation cell, so the name resolves to this same adapter for
    /// the wrapper's whole generation (issue #974 review).
    fingerprint: Option<Box<str>>,
}

impl DnsProxy {
    fn resolve(&self) -> Result<Arc<dyn Proxy>> {
        self.target
            .resolve()
            .ok_or_else(|| MeowError::Proxy(self.target.missing_error()))
    }
}

#[async_trait::async_trait]
impl ProxyAdapter for DnsProxy {
    fn name(&self) -> &str {
        self.target.name()
    }
    fn addr(&self) -> &str {
        &self.addr
    }
    fn adapter_type(&self) -> AdapterType {
        self.adapter_type
    }
    fn health(&self) -> &ProxyHealth {
        // A reference cannot be returned through `resolve()`'s temporary
        // Arc, so writes to this cell are intentionally discarded — every
        // read path (`alive`, `last_delay`, `delay_history`) resolves to
        // the published proxy's own health instead.
        &self.health
    }
    fn dialer_hop(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.target
            .resolve()
            .and_then(|proxy| proxy.dialer_hop(metadata))
    }
    fn has_configured_dialer(&self) -> bool {
        self.configured_dialer
    }
    fn support_udp(&self) -> bool {
        self.target.resolve().is_some_and(|p| p.support_udp())
    }
    /// Forward the published entry's own answer — bound at construction
    /// because the resolved proxy is a temporary `Arc` (see the field).
    fn client_fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.resolve()?.dial_tcp(metadata).await
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.resolve()?.dial_udp(metadata).await
    }
}

impl Proxy for DnsProxy {
    fn alive(&self) -> bool {
        self.target.resolve().is_some_and(|p| p.alive())
    }
    fn alive_for_url(&self, url: &str) -> bool {
        self.target.resolve().is_some_and(|p| p.alive_for_url(url))
    }
    fn last_delay(&self) -> u16 {
        self.target.resolve().map_or(0, |p| p.last_delay())
    }
    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.target
            .resolve()
            .map_or(0, |p| p.last_delay_for_url(url))
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.target
            .resolve()
            .map_or_else(Vec::new, |p| p.delay_history())
    }
    /// Forward like `support_udp`: the published entry's own verdict, so
    /// a chained member resolved through this wrapper reads exactly as the
    /// route generation reports it (issue #969 — the wrapper contract).
    fn is_dialer_proxy_non_transparent(&self) -> bool {
        self.target
            .resolve()
            .is_some_and(|p| p.is_dialer_proxy_non_transparent())
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use meow_common::Metadata;
    use std::sync::Arc;

    #[tokio::test]
    async fn dns_proxy_startup_uses_the_runtime_route_instance() {
        let config = crate::load_config_from_str(
            "\
            proxies:\n  - {name: upstream, type: direct}\n  - {name: tcp-only, type: http, server: 192.0.2.1, port: 80}\n\
            proxy-groups:\n  - {name: selected, type: select, proxies: [upstream, tcp-only]}\n\
            dns:\n  enable: true\n  use-system-hosts: false\n\
              \x20 nameserver: ['udp://192.0.2.53:53#selected']\n\
            rules: [MATCH,selected]\n",
        )
        .await
        .unwrap();
        let client = &config.dns.resolver.main_nameservers()[0];
        let proxy = client.proxy().unwrap();
        assert!(proxy.support_udp());
        let selector = config.proxies["selected"].selection().unwrap();
        selector.set("tcp-only").await.unwrap();
        assert!(
            !proxy.support_udp(),
            "DNS retained startup's stale selector"
        );
        // Keeping a DNS resolver alive after the config's route generation
        // is retired must neither keep that generation alive nor dial direct.
        let resolver = Arc::clone(&config.dns.resolver);
        let weak = config.dialer_registry.downgrade();
        drop(config);
        assert!(weak.upgrade().is_none());
        let client = &resolver.main_nameservers()[0];
        assert!(client
            .proxy()
            .unwrap()
            .dial_tcp(&Metadata::default())
            .await
            .is_err());
        assert!(client
            .proxy()
            .unwrap()
            .dial_udp(&Metadata::default())
            .await
            .is_err());
    }

    /// Issue #974 review: a `type: dns` leaf fails `ConnType::Inner`
    /// closed — a dialer-hop metadata must never reach its answer path.
    /// The guard has to hold end-to-end, not just on a direct adapter
    /// call: here through the DnsProxy nameserver wrapper (`#dns-out`)
    /// and again through a selector group (`#sel` → dns-out), whose
    /// picked member is only known at dial time.
    #[tokio::test]
    async fn dns_leaf_rejects_inner_dials_through_wrappers() {
        use meow_common::ConnType;
        let config = crate::load_config_from_str(
            "\
            proxies:\n  - {name: dns-out, type: dns}\n\
            proxy-groups:\n  - {name: sel, type: select, proxies: [dns-out]}\n\
            dns:\n  enable: true\n  use-system-hosts: false\n\
              \x20 nameserver: ['udp://192.0.2.53:53#dns-out', 'udp://192.0.2.54:53#sel']\n\
            rules: [MATCH,dns-out]\n",
        )
        .await
        .unwrap();
        let inner = Metadata {
            conn_type: ConnType::Inner,
            ..Default::default()
        };
        let leaf = config.dns.resolver.main_nameservers()[0].proxy().unwrap();
        let group = config.dns.resolver.main_nameservers()[1].proxy().unwrap();
        for (tag, proxy) in [("direct tag", leaf), ("selector pick", group)] {
            assert!(
                proxy.dial_tcp(&inner).await.is_err(),
                "{tag}: a dns leaf must refuse the inner dial"
            );
            assert!(
                proxy.dial_udp(&inner).await.is_err(),
                "{tag}: a dns leaf must refuse the inner dial"
            );
        }
    }

    #[tokio::test]
    async fn dns_proxy_reload_uses_the_candidate_generation() {
        let config = crate::load_config_from_str(
            "\
            proxies:\n  - {name: upstream, type: direct}\n\
            dns:\n  enable: true\n  use-system-hosts: false\n\
              \x20 nameserver: ['udp://192.0.2.53:53#upstream']\n\
            rules: [MATCH,upstream]\n",
        )
        .await
        .unwrap();
        let old = Arc::clone(config.dns.resolver.main_nameservers()[0].proxy().unwrap());
        let candidate = crate::rebuild_from_raw(&config.raw).unwrap();
        let dns = crate::parse_dns_from_raw(
            &config.raw,
            None,
            &candidate.proxies,
            None,
            None,
            Some(&config.dns.resolver),
            Some(&candidate.dialer_registry),
        )
        .await
        .unwrap();
        let proxy = dns.resolver.main_nameservers()[0].proxy().unwrap();
        drop(config);
        assert!(old.dial_udp(&Metadata::default()).await.is_err());
        assert!(
            proxy.support_udp(),
            "retiring the old registry invalidated the new one"
        );
        let weak = candidate.dialer_registry.downgrade();
        drop(candidate);
        assert!(
            weak.upgrade().is_none(),
            "DNS wrapper formed a registry cycle"
        );
        assert!(proxy.dial_udp(&Metadata::default()).await.is_err());
    }
}
