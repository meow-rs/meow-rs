//! Per-outbound `dialer-proxy` support (issue #210, mihomo-compatible).
//!
//! A `dialer-proxy` makes a single outbound establish its underlying connection
//! *through* another proxy/group instead of dialling the OS socket directly:
//!
//! ```yaml
//! - name: daniel
//!   type: snell
//!   server: ss.example.com
//!   port: 8443
//!   dialer-proxy: fast      # reach ss.example.com via the `fast` proxy
//! ```
//!
//! This is exactly a two-hop relay chain `[dialer, inner]` where the final hop
//! (`inner`) connects to the real target, so we reuse the existing relay dial
//! algorithm (`relay::relay_tcp`) rather than introducing a second chained
//! dialer (architect guidance on issue #210).  `DialerProxyAdapter` otherwise
//! presents itself as the inner outbound — same name, type, address, and health
//! — so dashboards and rules see no difference.
//!
//! The front hop is held as a [`DialerTarget`] — a *name* plus a registry
//! handle — and resolved on every dial, matching mihomo's
//! `component/proxydialer/byname.go`.  Capturing the front proxy as an `Arc`
//! while the config is still being built freezes a stale entry instead: proxy
//! groups clone their members before the `dialer-proxy` pass replaces them, so
//! a grouped node would silently bypass its chain (issue #513).
//!
//! ## Limitations (first implementation)
//!
//! - **UDP**: routing a UDP association through an arbitrary dialer requires
//!   per-protocol UDP-over-proxy framing that meow-rs does not yet implement.
//!   Dialling UDP *directly* would silently leak the real source path, so
//!   `dial_udp` returns [`MeowError::UdpNotSupported`] (Class A, ADR-0002) when a
//!   dialer-proxy is configured.
//! - **As a relay hop**: when a dialer-proxy outbound itself appears inside a
//!   `relay` chain, `connect_over` delegates to the inner adapter — the relay
//!   chain already defines the path, so the per-outbound dialer is not applied a
//!   second time. At the chain's *first* hop the wrapper is kept instead and
//!   its own `dial_tcp` runs, so the configured front dialer still fires.

use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use std::sync::Arc;

use super::relay::relay_tcp;
use crate::dialer::DialerTarget;

/// Wraps an outbound so its underlying connection is dialled through `dialer`.
pub struct DialerProxyAdapter {
    /// The actual outbound (SS/Trojan/VLESS/Snell/…); identity is borrowed from
    /// it so the wrapper is transparent to the API and rule engine.
    inner: Arc<dyn Proxy>,
    /// Front proxy/group the inner outbound dials through, resolved by name on
    /// every dial.
    dialer: DialerTarget,
}

impl DialerProxyAdapter {
    pub fn new(inner: Arc<dyn Proxy>, dialer: DialerTarget) -> Self {
        Self { inner, dialer }
    }

    /// Name of the front dialer proxy/group (for diagnostics/tests).
    pub fn dialer_name(&self) -> &str {
        self.dialer.name()
    }

    /// The wrapped outbound. Used by relay flattening to splice an inner
    /// relay group's members into the outer chain.
    pub(crate) fn inner(&self) -> &Arc<dyn Proxy> {
        &self.inner
    }
}

#[async_trait]
impl ProxyAdapter for DialerProxyAdapter {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn adapter_type(&self) -> AdapterType {
        self.inner.adapter_type()
    }

    fn addr(&self) -> &str {
        self.inner.addr()
    }

    /// UDP through an arbitrary dialer is not yet supported; see module docs.
    fn support_udp(&self) -> bool {
        false
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        // `[dialer, inner]`: dialer dials inner's server, inner connects to the
        // real target via `connect_over`. An unresolvable front hop must fail —
        // dialling direct would leak past a chain configured for policy reasons.
        let front = self
            .dialer
            .resolve()
            .ok_or_else(|| MeowError::Proxy(self.dialer.missing_error()))?;
        let chain = [front, Arc::clone(&self.inner)];
        relay_tcp(&chain, metadata).await
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::UdpNotSupported)
    }

    /// As a relay hop the chain already defines the path; do not re-apply the
    /// per-outbound dialer. Delegate to the inner adapter's handshake.
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        self.inner.connect_over(stream, metadata).await
    }

    fn unwrap_proxy(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.inner.unwrap_proxy(metadata)
    }

    fn health(&self) -> &ProxyHealth {
        self.inner.health()
    }
}

impl Proxy for DialerProxyAdapter {
    fn alive(&self) -> bool {
        self.inner.alive()
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.inner.alive_for_url(url)
    }

    fn last_delay(&self) -> u16 {
        self.inner.last_delay()
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.inner.last_delay_for_url(url)
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.inner.delay_history()
    }

    /// Lets relay `flatten_hops` downcast the wrapper and reach an inner
    /// `RelayGroup`'s members.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn members(&self) -> Option<Vec<String>> {
        self.inner.members()
    }

    fn current(&self) -> Option<String> {
        self.inner.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::ProxyRegistry;
    use crate::group::test_support::MockProxy;
    use meow_common::MeowError;
    use smol_str::SmolStr;
    use std::collections::HashMap;

    fn meta(host: &str, port: u16) -> Metadata {
        Metadata {
            host: host.into(),
            dst_port: port,
            ..Default::default()
        }
    }

    /// Publish `dialer` in a registry of its own and hand back the target that
    /// resolves it — the late-binding shape `meow-config` builds at load time.
    fn front(dialer: Arc<MockProxy>) -> DialerTarget {
        let name = SmolStr::from(dialer.name());
        let registry = ProxyRegistry::default();
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(name.clone(), dialer);
        registry.publish(Arc::new(proxies));
        DialerTarget::new(name, registry)
    }

    #[tokio::test]
    async fn dial_tcp_routes_through_dialer_first() {
        let dialer = MockProxy::new("fast");
        let inner = MockProxy::new("daniel");
        let adapter = DialerProxyAdapter::new(Arc::clone(&inner) as _, front(Arc::clone(&dialer)));

        // dialer.dial_tcp errors at relay hop 0 → confirms the chain dials the
        // front proxy first. The inner adapter is only reached via connect_over,
        // so its dial_tcp counter stays at zero.
        match adapter.dial_tcp(&meta("example.com", 443)).await {
            Err(MeowError::RelayHopFailed { hop: 0, .. }) => {}
            other => panic!("expected relay hop-0 failure, got {:?}", other.err()),
        }
        assert_eq!(dialer.dials(), 1, "front dialer must be dialled");
        assert_eq!(
            inner.dials(),
            0,
            "inner is reached via connect_over, not dial_tcp"
        );
    }

    /// A front hop that never resolves (registry not published, or the name
    /// gone after a rebuild) must fail the dial. Falling back to a direct dial
    /// would leak past a chain the user configured for policy reasons.
    #[tokio::test]
    async fn unresolved_front_hop_fails_loudly() {
        let inner = MockProxy::new("daniel");
        let adapter = DialerProxyAdapter::new(
            Arc::clone(&inner) as _,
            DialerTarget::new("ghost", ProxyRegistry::default()),
        );

        match adapter.dial_tcp(&meta("example.com", 443)).await {
            Err(MeowError::Proxy(msg)) => assert!(
                msg.contains("ghost"),
                "the error must name the missing dialer: {msg}"
            ),
            other => panic!("expected a Proxy error, got {:?}", other.err()),
        }
        assert_eq!(inner.dials(), 0, "the inner outbound must not be dialled");
    }

    #[tokio::test]
    async fn udp_is_unsupported() {
        let adapter =
            DialerProxyAdapter::new(MockProxy::new("inner"), front(MockProxy::new_udp("fast")));
        assert!(!adapter.support_udp());
        match adapter.dial_udp(&meta("example.com", 53)).await {
            Err(MeowError::UdpNotSupported) => {}
            other => panic!("expected UdpNotSupported, got {:?}", other.err()),
        }
    }

    #[test]
    fn identity_delegates_to_inner() {
        let inner = MockProxy::new("daniel");
        let adapter = DialerProxyAdapter::new(inner, front(MockProxy::new("fast")));
        assert_eq!(adapter.name(), "daniel");
        assert_eq!(adapter.dialer_name(), "fast");
        assert_eq!(adapter.adapter_type(), AdapterType::Direct); // MockProxy's type
    }
}
