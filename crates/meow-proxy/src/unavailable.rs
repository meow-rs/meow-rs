//! A named, permanently-dead placeholder for a node this binary cannot build.
//!
//! Some node defects cannot be answered by dropping the node. When a group
//! lists it, a dropped member silently shifts traffic to the group's other
//! members — or, if none survive, degrades to a direct dial, sending in the
//! clear exactly the traffic the operator asked to tunnel.
//!
//! Rejecting the whole config instead is not an answer either: proxy-provider
//! and subscription payloads are authored by a third party and refreshed at
//! runtime, so a payload-level rejection lets the feed's operator stop the
//! daemon from starting, and discards every working node in the same payload
//! on each refresh. A node naming a protocol that is not compiled into the
//! running binary is the worst case of both: the user cannot fix it by editing
//! their config at all.
//!
//! This adapter is the third option, and the shape `apply_dialer_proxies`
//! already uses for a malformed `dialer-proxy` (`MALFORMED_DIALER_PREFIX`):
//! the name stays bound, every dial fails loudly naming the node and the
//! reason, and health reports dead so `url-test` / `fallback` route around it
//! the same way they route around any down node. A rule, or a group with
//! nothing live to prefer over it, that resolves to it fails the dial — TCP
//! and UDP alike — instead of skipping past it, and one bad entry costs
//! exactly that entry.
//!
//! One pre-existing exception is not this type's to close: `load-balance`
//! filters its picks on liveness for every member type, so a load-balance
//! group with no live UDP-capable member declines UDP and the rule scan moves
//! on — exactly as it does when every member is an ordinary down node.

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};

pub struct UnavailableAdapter {
    name: String,
    reason: String,
    declared: AdapterType,
    health: ProxyHealth,
}

impl UnavailableAdapter {
    /// `reason` is rendered into every dial error, so it must not carry
    /// anything from the node's credential fields. `declared` is the type the
    /// node asked to be — see [`UnavailableAdapter::adapter_type`].
    pub fn new(name: impl Into<String>, reason: impl Into<String>, declared: AdapterType) -> Self {
        let health = ProxyHealth::new();
        // Dead from birth: this adapter has no connection to lose, and a
        // group must treat it as unusable without having to probe it first.
        health.set_alive(false);
        Self {
            name: name.into(),
            reason: reason.into(),
            declared,
            health,
        }
    }

    fn error(&self) -> MeowError {
        MeowError::Proxy(format!(
            "proxy '{}' is unavailable in this build: {}",
            self.name, self.reason
        ))
    }
}

#[async_trait]
impl ProxyAdapter for UnavailableAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    /// The type the node *declared*, with `alive = false` — not `Reject`.
    ///
    /// Reporting `Reject` would make a misconfigured node indistinguishable
    /// from an intentional one everywhere the type is consumed: `/proxies`
    /// would list it as `type: Reject`, the tunnel would bucket rule hits on
    /// it as action `REJECT` in match statistics, and `record_dial_failure`
    /// would exempt it as a type whose errors describe the target. The whole
    /// purpose of this adapter is to make the misconfiguration visible, so it
    /// keeps the declared type and lets `alive = false` carry the bad news.
    fn adapter_type(&self) -> AdapterType {
        self.declared
    }

    fn addr(&self) -> &str {
        ""
    }

    /// Always advertise UDP, even though `dial_udp` can never succeed — the
    /// one deliberate exception to issue #700's "only advertise what
    /// `dial_udp` implements" rule.
    ///
    /// The rule engine treats a UDP target without UDP support as absent: it
    /// skips the rule and keeps scanning, and an exhausted scan dials DIRECT
    /// (mihomo's `!SupportUDP()` continue). An honest `false` here would turn
    /// this placeholder into exactly the hole it exists to close — the TCP
    /// dial fails closed while the same flow's UDP/QUIC leaves in the clear.
    /// Advertising UDP keeps the rule, and its `dial_udp` refuses the
    /// association. The groups that pick by liveness (`url-test`,
    /// `fallback`, `load-balance`) already route around this entry, because
    /// it is dead from birth, so the advertisement never wins a live
    /// sibling's slot.
    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        Err(self.error())
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(self.error())
    }

    async fn connect_over(
        &self,
        _stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Err(self.error())
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> UnavailableAdapter {
        UnavailableAdapter::new(
            "vpn-tokyo",
            "trusttunnel is not compiled into this build",
            AdapterType::TrustTunnel,
        )
    }

    #[test]
    fn reports_the_node_name_and_is_dead() {
        let adapter = fixture();
        assert_eq!(adapter.name(), "vpn-tokyo");
        assert!(!adapter.health().alive());
        // Advertised so the rule engine keeps the match and fails the UDP
        // dial, instead of skipping past the node to DIRECT.
        assert!(adapter.support_udp());
        // The declared type, not `Reject`: a node that failed to parse must
        // not read as an intentional reject in the API listing, in match
        // statistics, or in the group dial-failure exemptions.
        assert_eq!(adapter.adapter_type(), AdapterType::TrustTunnel);
    }

    #[tokio::test]
    async fn every_dial_fails_naming_the_node_and_reason() {
        let adapter = fixture();
        let metadata = Metadata::default();
        for error in [
            adapter.dial_tcp(&metadata).await.err(),
            adapter.dial_udp(&metadata).await.err(),
        ] {
            let error = error.expect("an unavailable node must never produce a connection");
            let rendered = error.to_string();
            assert!(rendered.contains("vpn-tokyo"), "{rendered}");
            assert!(
                rendered.contains("not compiled into this build"),
                "{rendered}"
            );
        }
    }
}
