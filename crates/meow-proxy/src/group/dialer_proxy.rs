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
//! ## Limitations
//!
//! - **UDP**: this *wrapper* is the fallback for transports that own their
//!   framing and cannot accept an injected dialer — routing a UDP
//!   association through an arbitrary dialer needs per-protocol
//!   UDP-over-proxy framing, so for a non-transparent inner `dial_udp`
//!   returns [`MeowError::UdpNotSupported`] (Class A, ADR-0002) here. The
//!   one exception is a *transparent* inner (a direct-class adapter: a
//!   `type: direct` node, which `reject_unthreaded_dialer` turns away from
//!   the injected path precisely because it owns no transport to inject
//!   into). A transparent inner contributes nothing but a raw egress, so
//!   the front hop is the only non-transparent hop and the flow rides the
//!   front's `dial_udp_conn` association end to end — the same route a
//!   natively injected dialer takes. `support_udp` advertises exactly
//!   that distinction: `true` for a transparent inner routes UDP through
//!   the front's association and a front without UDP fails the dial
//!   loudly; `false` for anything else makes the rule probe report the
//!   target `Unusable` — the scan stops *on* the matched rule and the
//!   flow fails at dial, never sliding to a later rule's target
//!   (issue #969). Protocols that do accept an injected `TcpDialer`
//!   (e.g. Shadowsocks, SOCKS5, hysteria2, TrustTunnel H3) chain UDP
//!   natively and never reach this adapter — but they carry no wrapper
//!   either, so the config build marks their registry entries with
//!   `meow_config`'s `ChainedProxy` to report the same
//!   `is_dialer_proxy_non_transparent` verdict this adapter's
//!   `!transparent` does. Any wrapper above a `DialerProxyAdapter` must
//!   likewise forward the predicate (the `dialer_hop` contract).
//! - **As a relay hop**: when a dialer-proxy outbound itself appears inside a
//!   `relay` chain, `connect_over` delegates to the inner adapter — the relay
//!   chain already defines the path, so the per-outbound dialer is not applied a
//!   second time. At the chain's *first* hop the wrapper is kept instead and
//!   its own `dial_tcp` runs, so the configured front dialer still fires.

use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, PollPacketConn, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, Result,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::relay::relay_tcp;
use crate::dialer::{DialerTarget, NamedProxyDialer, TcpDialer, UdpTarget};

/// Whether `inner` is a *transparent* (direct-class) outbound: it owns no
/// server transport of its own, so the front hop is the only
/// non-transparent hop and a UDP flow can ride the front's
/// `dial_udp_conn` association end to end.
///
/// `Compatible` is upstream's `C.Compatible` — a `*Direct` under another
/// name, the same pairing `relay`'s hop filtering and the tunnel's
/// `routes_direct` use. `Pass`/`Reject` are deliberately *not* listed:
/// they are nops that must send nothing, not transports the front can
/// stand in for — and the match probe's `unwraps_to(Pass)` check precedes
/// the UDP-capability check regardless, so their advertisement here could
/// never be observed through the rule path.
///
/// The `alive` gate is the [`UnavailableAdapter`](crate::UnavailableAdapter)
/// guard: a dead-from-birth placeholder keeps the *declared* type tag,
/// so `type: trusttunnel`-as-`Direct` would otherwise read transparent —
/// and routing its UDP through the front would dial past a node whose
/// whole purpose is failing every dial loudly. Config build already
/// keeps placeholders out of this wrapper (the `placeholder_names` set
/// maintained while applying dialer edges); the check makes the
/// invariant local so a future call site cannot reopen the hole.
fn inner_is_transparent(inner: &Arc<dyn Proxy>) -> bool {
    inner.alive()
        && matches!(
            inner.adapter_type(),
            AdapterType::Direct | AdapterType::Compatible
        )
}

/// The `Box<dyn ProxyPacketConn>` view of a front's `Arc`-shared UDP
/// association. `dial_udp_conn` returns `Arc` for multi-consumer
/// transports (kcptun's pump tasks); a `dial_udp` caller needs only the
/// trait object.
struct ArcPacketConn(Arc<dyn ProxyPacketConn>);

#[async_trait]
impl ProxyPacketConn for ArcPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.0.read_packet(buf).await
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        self.0.write_packet(buf, addr).await
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr()
    }

    fn close(&self) -> Result<()> {
        self.0.close()
    }

    /// A pure shim — the inner conn's own poll capability, passed
    /// through untouched.
    fn poll_packet_conn(self: Arc<Self>) -> Option<Arc<dyn PollPacketConn>> {
        Arc::clone(&self.0).poll_packet_conn()
    }
}

/// Wraps an outbound so its underlying connection is dialled through `dialer`.
pub struct DialerProxyAdapter {
    /// The actual outbound (SS/Trojan/VLESS/Snell/…); identity is borrowed from
    /// it so the wrapper is transparent to the API and rule engine.
    inner: Arc<dyn Proxy>,
    /// Front proxy/group the inner outbound dials through, resolved by name on
    /// every dial.
    dialer: DialerTarget,
    /// Whether the wrapped outbound is a transparent (direct-class) adapter —
    /// see [`inner_is_transparent`]. Computed once at construction: the tag
    /// cannot change, and reading the health bit once keeps a later
    /// liveness flap from flapping the advertised capability.
    transparent: bool,
    /// Once-per-adapter latch for the `dial_udp` refusal: a UDP NAT
    /// rebuild re-dials, and the match probe already logged why the scan
    /// stopped here — repeating this warn per session is noise.
    warned_udp: AtomicBool,
}

impl DialerProxyAdapter {
    pub fn new(inner: Arc<dyn Proxy>, dialer: DialerTarget) -> Self {
        let transparent = inner_is_transparent(&inner);
        Self {
            inner,
            dialer,
            transparent,
            warned_udp: AtomicBool::new(false),
        }
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

    /// Advertise exactly what `dial_udp` can route: a transparent inner's
    /// whole path is the front's UDP association, so it advertises `true`;
    /// anything else stays `false`. The front's own capability is
    /// deliberately *not* consulted — answering `false` for a UDP-less
    /// front would pin the failure on this node (an `Unusable` verdict:
    /// "the named outbound cannot carry UDP") instead of on the front
    /// association that actually lacks UDP, and the match still fails
    /// closed either way (issue #969). `true` keeps the failure where it
    /// belongs: `dial_udp` → the front's `dial_udp_conn` refuses loudly.
    fn support_udp(&self) -> bool {
        self.transparent
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        // `[dialer, inner]`: dialer dials inner's server, inner connects to the
        // real target via `connect_over`. An unresolvable front hop must fail —
        // dialling direct would leak past a chain configured for policy reasons.
        // The depth guard mirrors `NamedProxyDialer`: a provider-sourced member
        // can route the front hop's group selection back to this adapter
        // (issue #489).
        crate::dialer::scoped_chain_dial(
            self.dialer.name(),
            |name| {
                MeowError::Proxy(format!(
                    "dialer-proxy '{name}': chain exceeds {} hops; a provider \
                     member or group is routing the dial back into itself",
                    crate::dialer::MAX_DIALER_CHAIN_DEPTH
                ))
            },
            async {
                let front = self
                    .dialer
                    .resolve()
                    .ok_or_else(|| MeowError::Proxy(self.dialer.missing_error()))?;
                // `relay_tcp` resolves the front's groups against the final
                // target, so the note's and the counters' walks use that
                // metadata too.
                crate::dialer::note_front_hop(&front, self.inner.addr(), metadata);
                let counters = crate::dialer::front_hop_counters(
                    &front,
                    metadata,
                    self.dialer.traffic().as_deref(),
                );
                let chain = [front, Arc::clone(&self.inner)];
                relay_tcp(&chain, metadata, counters).await
            },
        )
        .await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.transparent {
            // First refusal only — a UDP NAT rebuild re-dials, and the
            // flow already cost the match scan its `Unusable` warn.
            if !self.warned_udp.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "dialer-proxy '{}' (front: {}) cannot carry UDP — the \
                     flow fails at this dial instead of sliding to a later \
                     rule's target (issue #969)",
                    self.name(),
                    self.dialer.name()
                );
            }
            return Err(MeowError::UdpNotSupported);
        }
        // The transparent inner contributes nothing but a raw egress, so
        // the front's association to the *flow destination* is the whole
        // path. Going through `NamedProxyDialer` (not a resolved
        // `ProxyDialer` by hand) keeps every injected-path protection:
        // the `scoped_chain_dial` depth guard, the front-hop conn note,
        // hop traffic counters, and group failure blame. `owner` stays
        // unset — it only feeds the TCP `FrontHop` frame.
        let target = match metadata.domain_udp_target() {
            // A host-only destination delegates resolution to the front's
            // own view (issue #657 semantics, same as the injected path);
            // `named` folds an IP-literal host back to `Addr`.
            Some((host, port)) => UdpTarget::named(host, port),
            None => match metadata.dst_ip {
                Some(ip) => UdpTarget::Addr(SocketAddr::new(ip, metadata.dst_port)),
                None => {
                    return Err(MeowError::Proxy(format!(
                        "dialer-proxy '{}': UDP flow carries no destination",
                        self.dialer.name()
                    )));
                }
            },
        };
        let conn = NamedProxyDialer::new(self.dialer.clone())
            .dial_udp_conn(target, metadata.is_internal())
            .await
            .map_err(|e| MeowError::io_with("dialer-proxy udp", e))?;
        Ok(Box::new(ArcPacketConn(conn)))
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

    fn unwrap_proxy(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.inner.unwrap_proxy(metadata, touch)
    }

    /// The front's pick for the final target, as `dial_tcp` relays to it.
    fn dialer_hop(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        crate::dialer::front_hop_carrier(&self.dialer.resolve()?, metadata)
    }

    /// This wrapper exists only because a `dialer-proxy:` was configured —
    /// the declared chain holds even while the front's pick sends nothing
    /// and `dialer_hop` returns `None`.
    fn has_configured_dialer(&self) -> bool {
        true
    }

    /// Forward the session flush (issue #695): `member_proxies` exposes the
    /// inner adapter's members, never the inner adapter itself, so the
    /// reachability walk would otherwise miss its pools. A wrapper chain is
    /// built bottom-up, so this cannot recurse into a cycle.
    fn reset_sessions(&self) {
        self.inner.reset_sessions();
    }

    fn health(&self) -> &ProxyHealth {
        self.inner.health()
    }

    /// Transparent wrapper — the baked fingerprint is the leaf's.
    fn client_fingerprint(&self) -> Option<&str> {
        self.inner.client_fingerprint()
    }

    /// Transparent like the rest of this wrapper — a rematch leaf must
    /// keep reporting its action to the match-time probe even wrapped,
    /// or the chain silently reads as an ordinary dialable target
    /// (issue #974).
    fn rematch_action(&self) -> Option<meow_common::RematchAction<'_>> {
        self.inner.rematch_action()
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

    /// `!transparent` is exactly the `support_udp` condition: the UDP probe
    /// fails a matched rule on this adapter closed (issue #969) where a
    /// plain `udp: false` node keeps mihomo's `continue`.
    fn is_dialer_proxy_non_transparent(&self) -> bool {
        !self.transparent
    }

    fn members(&self) -> Option<Vec<String>> {
        self.inner.members()
    }

    fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        self.inner.member_proxies()
    }

    fn current(&self) -> Option<String> {
        self.inner.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::ProxyRegistry;
    use crate::group::test_support::{registry_of, MockProxy};
    use meow_common::{MeowError, Network};
    use smol_str::SmolStr;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn meta(host: &str, port: u16) -> Metadata {
        Metadata {
            host: host.into(),
            dst_port: port,
            ..Default::default()
        }
    }

    /// A UDP flow's metadata: listeners always resolve `dst_ip` before
    /// `dial_udp` (`None` here means a chained layer is delegating a
    /// domain — see `domain_udp_target`).
    fn udp_meta(host: &str, dst_ip: Option<&str>, port: u16) -> Metadata {
        Metadata {
            network: Network::Udp,
            host: host.into(),
            dst_ip: dst_ip.map(|ip| ip.parse().unwrap()),
            dst_port: port,
            ..Default::default()
        }
    }

    /// Publish `dialer` in a registry of its own and hand back the target that
    /// resolves it — the late-binding shape `meow-config` builds at load time.
    /// The registry is returned alongside because `DialerTarget` only holds it
    /// weakly: the caller must keep the handle alive for the target to resolve
    /// (issue #533).
    fn front(dialer: Arc<MockProxy>) -> (DialerTarget, ProxyRegistry) {
        let name = SmolStr::from(dialer.name());
        let registry = ProxyRegistry::default();
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(name.clone(), dialer);
        registry.publish(Arc::new(proxies));
        (DialerTarget::new(name, &registry), registry)
    }

    #[tokio::test]
    async fn dial_tcp_routes_through_dialer_first() {
        let dialer = MockProxy::new("fast");
        let inner = MockProxy::new("daniel");
        let (target, _registry) = front(Arc::clone(&dialer));
        let adapter = DialerProxyAdapter::new(Arc::clone(&inner) as _, target);

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

    /// The relay-wrapper path notes the dialer group's pick like the
    /// injected dialer does.
    #[tokio::test]
    async fn dial_tcp_notes_the_dialer_groups_pick() {
        use crate::group::selector::SelectorGroup;
        use meow_common::conn_notes::ConnNotes;

        let pick = MockProxy::new_failing("HK-01", AdapterType::Trojan, "boom");
        let fast: Arc<dyn Proxy> = Arc::new(SelectorGroup::new("fast", vec![pick]));
        let registry = ProxyRegistry::default();
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(SmolStr::from("fast"), fast);
        registry.publish(Arc::new(proxies));
        let adapter = DialerProxyAdapter::new(
            MockProxy::new("daniel"),
            DialerTarget::new("fast", &registry),
        );

        let notes = ConnNotes::new();
        ConnNotes::scope(Some(notes.clone()), async {
            let _ = adapter.dial_tcp(&meta("example.com", 443)).await;
        })
        .await;
        let texts = notes.texts();
        assert_eq!(texts.len(), 1, "{texts:?}");
        assert!(
            texts[0].ends_with(" via dialer-proxy fast → HK-01 (Trojan)"),
            "{texts:?}"
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
            DialerTarget::new("ghost", &ProxyRegistry::default()),
        );

        match adapter.dial_tcp(&meta("example.com", 443)).await {
            Err(MeowError::Proxy(msg)) => {
                assert!(
                    msg.contains("ghost"),
                    "the error must name the missing dialer: {msg}"
                );
                // The temporary registry dropped at the end of the `new`
                // call — this is the dead-cell arm, not the live-registry
                // "name absent" arm (issue #533 review).
                assert!(
                    msg.contains("generation dropped"),
                    "expected the dead-cell wording, got: {msg}"
                );
            }
            other => panic!("expected a Proxy error, got {:?}", other.err()),
        }
        assert_eq!(inner.dials(), 0, "the inner outbound must not be dialled");
    }

    /// Sink conn the UDP-capable front hands out — dial assertions only
    /// need writes to succeed; reads park forever.
    struct SinkPacketConn;

    #[async_trait]
    impl ProxyPacketConn for SinkPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> Result<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    /// UDP front mock: records every `dial_udp` metadata and honours the
    /// `udp` flag — `false` produces `UdpNotSupported` like a UDP-incapable
    /// front (HTTP, Reject).
    struct UdpFront {
        udp: bool,
        seen: Mutex<Vec<Metadata>>,
        health: ProxyHealth,
    }

    impl UdpFront {
        fn new(udp: bool) -> Arc<Self> {
            Arc::new(Self {
                udp,
                seen: Mutex::new(Vec::new()),
                health: ProxyHealth::new(),
            })
        }
    }

    #[async_trait]
    impl ProxyAdapter for UdpFront {
        fn name(&self) -> &str {
            "fast"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Socks5
        }
        fn addr(&self) -> &str {
            "127.0.0.1:1080"
        }
        fn support_udp(&self) -> bool {
            self.udp
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
            Err(MeowError::NotSupported("test mock: no TCP".into()))
        }
        async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            self.seen.lock().unwrap().push(metadata.clone());
            if !self.udp {
                return Err(MeowError::UdpNotSupported);
            }
            Ok(Box::new(SinkPacketConn))
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for UdpFront {
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

    /// Publish a non-`MockProxy` front and hand back the resolving target —
    /// the `front` helper above is typed on `MockProxy`. Like [`front`], the
    /// returned registry must outlive the adapter's dials: the target only
    /// holds the registry weakly (issue #533).
    fn publish(p: &Arc<dyn Proxy>) -> (DialerTarget, ProxyRegistry) {
        let registry = registry_of(&[p]);
        (DialerTarget::new(p.name(), &registry), registry)
    }

    /// T-D1-1: a non-transparent inner keeps `UdpNotSupported` — the probe
    /// reads `support_udp() == false` on a DPA as `Unusable` (issue #969),
    /// so the match stops on the named rule and the dial refuses rather
    /// than silently sliding to a later `DIRECT` rule.
    #[tokio::test]
    async fn udp_is_unsupported() {
        let (target, _registry) = front(MockProxy::new_udp("fast"));
        let adapter = DialerProxyAdapter::new(
            MockProxy::new_failing("inner", AdapterType::Trojan, "boom"),
            target,
        );
        assert!(!adapter.support_udp());
        match adapter.dial_udp(&meta("example.com", 53)).await {
            Err(MeowError::UdpNotSupported) => {}
            other => panic!("expected UdpNotSupported, got {:?}", other.err()),
        }
    }

    /// T-D1-2: a transparent inner routes the flow's UDP association
    /// through the front hop — the same path an injected `TcpDialer`
    /// would take (`proxyDialer.ListenPacket` upstream).
    #[tokio::test]
    async fn transparent_inner_routes_udp_through_the_front() {
        let udp_front = UdpFront::new(true);
        let (target, _registry) = publish(&(Arc::clone(&udp_front) as Arc<dyn Proxy>));
        let adapter = DialerProxyAdapter::new(MockProxy::new("direct-node"), target);
        assert!(adapter.support_udp(), "a transparent inner advertises UDP");

        let m = udp_meta("example.com", Some("203.0.113.9"), 53);
        let conn = adapter
            .dial_udp(&m)
            .await
            .expect("a UDP-capable front must yield a conn");
        let dst: SocketAddr = "203.0.113.9:53".parse().unwrap();
        assert_eq!(conn.write_packet(b"x", &dst).await.unwrap(), 1);

        // The front was asked exactly once, for the *flow destination*
        // (transparent inner owns no server), with `Inner`/`Udp` metadata
        // like every injected-dialer association.
        let seen = udp_front.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].dst_ip, Some(dst.ip()));
        assert_eq!(seen[0].dst_port, 53);
        assert_eq!(seen[0].network, Network::Udp);
        assert!(!seen[0].internal);
    }

    /// The `internal` housekeeping marker rides the chained association —
    /// a probe chained through the wrapper must not count as use on a lazy
    /// front group (issue #555 boundary, same as the injected path).
    #[tokio::test]
    async fn transparent_inner_marks_internal_udp_dials() {
        let udp_front = UdpFront::new(true);
        let (target, _registry) = publish(&(Arc::clone(&udp_front) as Arc<dyn Proxy>));
        let adapter = DialerProxyAdapter::new(MockProxy::new("direct-node"), target);

        let m = Metadata {
            internal: true,
            ..udp_meta("probe.test", Some("203.0.113.9"), 53)
        };
        let _ = adapter.dial_udp(&m).await.expect("conn");
        assert!(udp_front.seen.lock().unwrap().last().unwrap().internal);
    }

    /// A host-only destination is delegated to the front as a *name* — the
    /// issue-#657 semantics the injected path applies: the front resolves
    /// with the view its chained leg already used.
    #[tokio::test]
    async fn transparent_inner_delegates_domain_udp_targets() {
        let udp_front = UdpFront::new(true);
        let (target, _registry) = publish(&(Arc::clone(&udp_front) as Arc<dyn Proxy>));
        let adapter = DialerProxyAdapter::new(MockProxy::new("direct-node"), target);

        let m = udp_meta("example.com", None, 443);
        let _ = adapter.dial_udp(&m).await.expect("conn");
        let seen = udp_front.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].host.as_str(), "example.com");
        assert_eq!(seen[0].dst_ip, None, "a name target carries no literal");
        assert_eq!(seen[0].dst_port, 443);
    }

    /// T-D1-3: a transparent inner over a UDP-incapable front still
    /// advertises the capability — so the match keeps the rule — but the
    /// dial refuses with a *capability* error: fail-closed, no dead-mark,
    /// and no slide to a later `DIRECT` rule.
    #[tokio::test]
    async fn transparent_inner_without_udp_front_fails_closed() {
        let udp_front = UdpFront::new(false);
        let (target, _registry) = publish(&(Arc::clone(&udp_front) as Arc<dyn Proxy>));
        let adapter = DialerProxyAdapter::new(MockProxy::new("direct-node"), target);
        assert!(
            adapter.support_udp(),
            "the advertisement holds so the match does not slide"
        );
        match adapter
            .dial_udp(&udp_meta("example.com", Some("203.0.113.9"), 53))
            .await
        {
            Err(e) => assert!(
                e.is_capability_error(),
                "a UDP-less front must refuse as a capability, got {e:?}"
            ),
            Ok(_) => panic!("a UDP-less front must fail the chained dial"),
        }
    }

    /// The [`UnavailableAdapter`] guard: a dead-from-birth inner keeps the
    /// declared type tag — `Direct` here — but must not turn transparent.
    /// Routing its UDP through the front would dial past a node whose
    /// whole purpose is failing every dial loudly.
    #[tokio::test]
    async fn dead_inner_stays_non_transparent() {
        let dead = MockProxy::new("dead-direct");
        dead.set_alive(false);
        let (target, _registry) = front(MockProxy::new_udp("fast"));
        let adapter = DialerProxyAdapter::new(dead, target);
        assert!(!adapter.support_udp());
        match adapter.dial_udp(&meta("example.com", 53)).await {
            Err(MeowError::UdpNotSupported) => {}
            other => panic!("expected UdpNotSupported, got {:?}", other.err()),
        }
    }

    #[test]
    fn identity_delegates_to_inner() {
        let inner = MockProxy::new("daniel");
        let (target, _registry) = front(MockProxy::new("fast"));
        let adapter = DialerProxyAdapter::new(inner, target);
        assert_eq!(adapter.name(), "daniel");
        assert_eq!(adapter.dialer_name(), "fast");
        assert_eq!(adapter.adapter_type(), AdapterType::Direct); // MockProxy's type
    }

    /// Issue #695: `member_proxies` exposes the inner outbound's members,
    /// never the inner outbound itself, so the reachability walk only
    /// reaches its pools through the wrapper's own forwarding. The front
    /// hop is not reset through the wrapper: it is a route-table entry the
    /// walk reaches on its own.
    #[test]
    fn reset_sessions_reaches_the_inner_outbound() {
        let inner = MockProxy::new("daniel");
        let fast = MockProxy::new("fast");
        let (target, _registry) = front(Arc::clone(&fast));
        let adapter: Arc<dyn Proxy> =
            Arc::new(DialerProxyAdapter::new(Arc::clone(&inner) as _, target));
        assert_eq!(meow_common::reset_sessions_reachable([adapter]), 1);
        assert_eq!(inner.resets(), 1);
        assert_eq!(fast.resets(), 0);
    }
}
