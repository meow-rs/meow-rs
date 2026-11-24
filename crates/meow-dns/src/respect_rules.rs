//! `dns.respect-rules` plumbing: the indirection a rule-routed nameserver
//! dials through.
//!
//! # Why this is a cell and not a proxy
//!
//! A `respect-rules` entry must reach the tunnel's rule engine, but the DNS
//! resolver is built by `meow-config` *before* the tunnel exists (the tunnel
//! takes the resolver, not the other way round — `meow-dns` cannot depend on
//! `meow-tunnel`). The resolver therefore cannot hold the dialer directly.
//!
//! [`RespectRulesProxy`] is the seam: the resolver build stores it as the
//! upstream's proxy, and whoever owns the tunnel publishes the real
//! rule-routed dialer into [`RespectRulesCell`] afterwards (startup and every
//! DNS install). Because the published dialer holds a *weak* handle to the
//! tunnel and re-reads the route table on every dial, one publication serves
//! every later `rules:`/`proxies:` swap — a reload does not need to rebuild
//! the resolver, and a stale rule table cannot be pinned.
//!
//! Empty cell semantics mirror [`crate::server::DnsOutboundCell`]: a dial
//! before publication fails loudly instead of silently dialling direct. A
//! `respect-rules` upstream that leaked a direct dial would bypass exactly the
//! policy the operator asked for.

use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use parking_lot::RwLock;
use std::sync::Arc;

/// Registry key the resolver build binds a `respect-rules` upstream to.
///
/// It lives in the same `proxy_registry` map as real `#PROXY` names so the
/// existing `?proxy=`/`#PROXY` resolution path needs no special case. The
/// spelling is reserved: `meow-config` rejects a config that declares a proxy
/// with this name, so an entry can never be silently routed by a user node.
pub const RESPECT_RULES_PROXY: &str = "__meow_respect_rules__";

/// Shared slot holding the rule-routed dialer for one DNS generation.
///
/// `None` means "not published yet" — the DNS build ran but the owning
/// application has not installed its tunnel-backed dialer. Every dial in that
/// window fails with a `Proxy` error.
pub type RespectRulesCell = Arc<RwLock<Option<Arc<dyn Proxy>>>>;

/// A fresh, empty cell — the DNS build hands one to every rule-routed
/// upstream of one resolver generation.
pub fn new_respect_rules_cell() -> RespectRulesCell {
    Arc::new(RwLock::new(None))
}

/// The proxy a `respect-rules` nameserver carries until the real dialer is
/// published: a forwarding cell with no route knowledge of its own.
///
/// Only the dial entry points matter to the DNS client; the identity and
/// health methods forward to the published dialer when there is one and
/// report inert values otherwise (the client never reads them, and the wrapper
/// is never in the route table, so no rule can select it).
pub struct RespectRulesProxy {
    cell: RespectRulesCell,
    /// Inert health cell: a forwarding wrapper has no probes of its own, and
    /// `AdapterType::health` must hand out a reference that outlives the lock
    /// guard — every read path resolves to the published dialer instead.
    health: ProxyHealth,
}

impl RespectRulesProxy {
    pub fn new(cell: RespectRulesCell) -> Self {
        Self {
            cell,
            health: ProxyHealth::new(),
        }
    }

    fn resolve(&self) -> Result<Arc<dyn Proxy>> {
        self.cell.read().clone().ok_or_else(|| {
            MeowError::Proxy(
                "dns.respect-rules: the rule-routed dialer has not been installed yet".into(),
            )
        })
    }
}

#[async_trait::async_trait]
impl ProxyAdapter for RespectRulesProxy {
    fn name(&self) -> &str {
        RESPECT_RULES_PROXY
    }

    fn addr(&self) -> &str {
        ""
    }

    /// Inert by design (see the `health` field): writes are discarded, and
    /// the forwarding read paths are `Proxy::alive` / `last_delay*` /
    /// `delay_history`.
    fn health(&self) -> &ProxyHealth {
        &self.health
    }

    fn adapter_type(&self) -> AdapterType {
        self.cell
            .read()
            .as_ref()
            .map_or(AdapterType::Direct, |proxy| proxy.adapter_type())
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.resolve()?.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.resolve()?.dial_udp(metadata).await
    }
}

impl Proxy for RespectRulesProxy {
    fn alive(&self) -> bool {
        self.cell.read().as_ref().is_some_and(|proxy| proxy.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.cell
            .read()
            .as_ref()
            .is_some_and(|proxy| proxy.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.cell
            .read()
            .as_ref()
            .map_or(0, |proxy| proxy.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.cell
            .read()
            .as_ref()
            .map_or(0, |proxy| proxy.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.cell
            .read()
            .as_ref()
            .map_or_else(Vec::new, |proxy| proxy.delay_history())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub {
        label: &'static str,
        health: ProxyHealth,
    }

    impl Stub {
        fn new(label: &'static str) -> Self {
            Self {
                label,
                health: ProxyHealth::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl ProxyAdapter for Stub {
        fn name(&self) -> &str {
            "STUB"
        }
        fn addr(&self) -> &str {
            "stub:0"
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
            Err(MeowError::Proxy(format!("{} reached", self.label)))
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            Err(MeowError::Proxy(format!("{} reached", self.label)))
        }
    }

    impl Proxy for Stub {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            42
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            42
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
    }

    #[tokio::test]
    async fn empty_cell_fails_the_dial_loudly() {
        let proxy = RespectRulesProxy::new(new_respect_rules_cell());
        let Err(err) = proxy.dial_tcp(&Metadata::default()).await else {
            panic!("an unpublished dialer must not dial");
        };
        assert!(err.to_string().contains("respect-rules"), "{err}");
    }

    /// A plain UDP upstream reaches the adapter through `dial_udp`, which
    /// must fail on an unpublished cell just like the TCP path.
    #[tokio::test]
    async fn empty_cell_fails_the_udp_dial_loudly() {
        let proxy = RespectRulesProxy::new(new_respect_rules_cell());
        let Err(err) = proxy.dial_udp(&Metadata::default()).await else {
            panic!("an unpublished dialer must not dial");
        };
        assert!(err.to_string().contains("respect-rules"), "{err}");
    }

    #[tokio::test]
    async fn published_dialer_is_forwarded() {
        let cell = new_respect_rules_cell();
        let proxy = RespectRulesProxy::new(Arc::clone(&cell));
        *cell.write() = Some(Arc::new(Stub::new("first")));
        assert_eq!(proxy.last_delay(), 42);
        let Err(err) = proxy.dial_tcp(&Metadata::default()).await else {
            panic!("the stub dial fails");
        };
        assert!(err.to_string().contains("first reached"), "{err}");
    }

    /// The documented reload contract: a second publication is observed by
    /// the next dial (no cached resolve).
    #[tokio::test]
    async fn republish_is_observed_by_the_next_dial() {
        let cell = new_respect_rules_cell();
        let proxy = RespectRulesProxy::new(Arc::clone(&cell));
        *cell.write() = Some(Arc::new(Stub::new("first")));
        let Err(err) = proxy.dial_tcp(&Metadata::default()).await else {
            panic!("the stub dial fails");
        };
        assert!(err.to_string().contains("first reached"), "{err}");
        *cell.write() = Some(Arc::new(Stub::new("second")));
        let Err(err) = proxy.dial_tcp(&Metadata::default()).await else {
            panic!("the stub dial fails");
        };
        assert!(err.to_string().contains("second reached"), "{err}");
    }
}
