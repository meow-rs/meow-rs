use super::selector_store::SelectorWriter;
use super::{DialFailureTracker, UsageTracker};
use async_trait::async_trait;
use meow_common::{
    AdapterType, ChainHealth, ChainTarget, DelayHistory, GroupDisplay, MeowError, Metadata,
    ProviderSlot, Proxy, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, ProxySelection,
    Result,
};
use parking_lot::RwLock;
use smol_str::SmolStr;
use std::sync::Arc;

pub struct FallbackGroup {
    name: SmolStr,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,
    /// Tri-state like `UrlTestGroup::fixed`: `Some(name)` an explicit pin,
    /// `Some("")` an explicit unfix or a dead-pin suppression that hides
    /// the stored pin for this generation, `None` "never set" — the
    /// store's saved pin then applies lazily.
    fixed: RwLock<Option<SmolStr>>,
    store: Option<SelectorWriter>,
    test_url: String,
    expected_status: String,
    health: ProxyHealth,
    display: GroupDisplay,
    usage: UsageTracker,
    dial_failures: DialFailureTracker,
    chain_health: Arc<ChainHealth>,
}

impl FallbackGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: Vec::new(),
            fixed: RwLock::new(None),
            store: None,
            test_url: "https://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            health: ProxyHealth::new(),
            display: GroupDisplay::default(),
            usage: UsageTracker::new(),
            dial_failures: DialFailureTracker::new(),
            chain_health: Arc::new(ChainHealth::tracking_carriers()),
        }
    }

    pub fn new_with_providers(
        name: &str,
        proxies: Vec<Arc<dyn Proxy>>,
        slots: Vec<ProviderSlot>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: slots,
            fixed: RwLock::new(None),
            store: None,
            test_url: "https://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            health: ProxyHealth::new(),
            display: GroupDisplay::default(),
            usage: UsageTracker::new(),
            dial_failures: DialFailureTracker::new(),
            chain_health: Arc::new(ChainHealth::tracking_carriers()),
        }
    }

    /// Attach the health-check keys and the epoch-fenced persistence
    /// writer. The saved pin is not copied out here: `effective_fixed`
    /// asks the store lazily, so the group follows the map the backing's
    /// `commit` adopts — a build-time snapshot could name whatever the
    /// file held before adoption refreshed it (issue #974 review).
    #[must_use]
    pub fn with_runtime_options(
        mut self,
        test_url: String,
        expected_status: String,
        store: Option<SelectorWriter>,
    ) -> Self {
        self.test_url = test_url;
        self.expected_status = expected_status;
        self.store = store;
        self
    }

    /// Attach the group's `hidden:` / `icon:` keys, which `GET /proxies`
    /// reports on the group.
    #[must_use]
    pub fn with_display(mut self, display: GroupDisplay) -> Self {
        self.display = display;
        self
    }

    fn find_member(&self, name: &str) -> Option<Arc<dyn Proxy>> {
        for p in &self.static_proxies {
            if p.name() == name {
                return Some(Arc::clone(p));
            }
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                if p.name() == name {
                    return Some(Arc::clone(p));
                }
            }
        }
        None
    }

    /// The pin in force: an explicit `force_set` pick or unfix/dead-pin
    /// sentinel, else the persisted pin — read lazily so the group sees
    /// the map the backing serves (including a store pin written between
    /// the build's open and its commit).
    fn effective_fixed(&self) -> Option<SmolStr> {
        match self.fixed.read().clone() {
            Some(name) if !name.is_empty() => Some(name),
            Some(_) => None,
            None => self
                .store
                .as_ref()
                .and_then(|store| store.get(&self.name))
                .filter(|v| !v.is_empty())
                .map(SmolStr::from),
        }
    }

    /// Write the unfix sentinel only if the stale pin still names
    /// `name` — an explicit pin is compared directly; a store-sourced
    /// pin (fixed is `None`) is re-read under the write lock so a pin
    /// that changed to a different value since `effective_fixed` ran is
    /// not suppressed along with the dead one.
    fn suppress_pin_if_still(&self, name: &SmolStr) {
        let mut pinned = self.fixed.write();
        let still_stale = match pinned.as_ref() {
            Some(cur) if !cur.is_empty() => *cur == *name,
            Some(_) => false,
            None => {
                self.store
                    .as_ref()
                    .and_then(|store| store.get(&self.name))
                    .as_deref()
                    == Some(name.as_str())
            }
        };
        if still_stale {
            *pinned = Some(SmolStr::default());
        }
    }

    /// Single-pass scan: returns the first alive proxy, or the first
    /// proxy of any kind if none are alive.  Walks `static_proxies` and
    /// each provider slot directly without building a unified `Vec`.
    fn first_alive(&self) -> Option<Arc<dyn Proxy>> {
        let fixed_name = self.effective_fixed();
        if let Some(name) = fixed_name {
            if let Some(proxy) = self.find_member(&name) {
                if proxy.alive_for_url(&self.test_url) {
                    return Some(proxy);
                }
            }
            // Upstream clears a stale fallback pin in memory when it is
            // observed dead, but leaves the persistent cache untouched —
            // here the `""` sentinel suppresses this generation's view of
            // the stored pin without rewriting the file.
            self.suppress_pin_if_still(&name);
        }
        let mut fallback: Option<Arc<dyn Proxy>> = None;
        for p in &self.static_proxies {
            if fallback.is_none() {
                fallback = Some(Arc::clone(p));
            }
            if p.alive() {
                return Some(Arc::clone(p));
            }
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                if fallback.is_none() {
                    fallback = Some(Arc::clone(p));
                }
                if p.alive() {
                    return Some(Arc::clone(p));
                }
            }
        }
        fallback
    }

    /// [`Self::first_alive`], or for a `dialer-proxy` front hop the first
    /// alive member not blocked for its target. The group's order holds for
    /// front hops too, so no carrier is passed: a front hop returns to an
    /// earlier member once it is no longer blocked, and the health check's
    /// chain probes keep a member that still fails blocked. The carrier the
    /// table tracks names the member whose failures count against the
    /// chained outbound (see `front_hop_failed`).
    fn pick_for(
        &self,
        metadata: &Metadata,
        dial: bool,
    ) -> Option<(Arc<dyn Proxy>, Option<ChainTarget>)> {
        let pick = self.first_alive()?;
        let Some(target) = super::front_hop_target(&self.chain_health, metadata, dial) else {
            return Some((pick, None));
        };
        let pick = super::front_hop_pick(
            &self.name,
            &self.chain_health,
            &target,
            pick,
            None,
            || self.member_proxy_list(),
            |p| p.alive(),
            dial,
        );
        Some((pick, Some(target)))
    }

    fn member_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .static_proxies
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                out.push(p.name().to_string());
            }
        }
        out
    }

    /// Static members followed by every provider-slot member, in
    /// `member_names` order.
    fn member_proxy_list(&self) -> Vec<Arc<dyn Proxy>> {
        let mut out: Vec<Arc<dyn Proxy>> = self.static_proxies.iter().map(Arc::clone).collect();
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                out.push(Arc::clone(p));
            }
        }
        out
    }
}

#[async_trait]
impl ProxyAdapter for FallbackGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Fallback
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.first_alive().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.usage.touch_user_traffic(metadata);
        let (proxy, front_hop) = self
            .pick_for(metadata, true)
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
        if let Some(target) = &front_hop {
            super::note_front_hop_member(&self.chain_health, target, &proxy);
        }
        let attempt = super::DialAttempt::new(&self.name, &self.dial_failures, &proxy);
        let conn = attempt.run(proxy.dial_tcp(metadata)).await?;
        Ok(match front_hop {
            Some(target) => {
                super::watch_front_hop(conn, &self.name, &self.chain_health, target, &proxy)
            }
            None => conn,
        })
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.usage.touch_user_traffic(metadata);
        let proxy = self
            .first_alive()
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
        let attempt = super::DialAttempt::new(&self.name, &self.dial_failures, &proxy);
        attempt.run(proxy.dial_udp(metadata)).await
    }

    fn unwrap_proxy(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        if touch {
            self.usage.touch_user_traffic(metadata);
        }
        self.pick_for(metadata, false).map(|(pick, _)| pick)
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for FallbackGroup {
    fn alive(&self) -> bool {
        // Own `health` bit AND delegated member liveness — the write side
        // of `record_dial_failure` escalation and `record_delay` sweeps
        // lands on `health`, so a pure delegation made every dead-mark on a
        // nested group member a silent no-op (issue #681).
        self.health.alive() && self.first_alive().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.health.alive() && self.first_alive().is_some_and(|p| p.alive_for_url(url))
    }

    /// Forward to the same member `support_udp` consults — the first
    /// alive pick a UDP dial would take. `false` on no pick: the slide
    /// is the safe failure side (issue #969).
    fn is_dialer_proxy_non_transparent(&self) -> bool {
        self.first_alive()
            .is_some_and(|p| p.is_dialer_proxy_non_transparent())
    }

    fn last_delay(&self) -> u16 {
        self.first_alive().map_or(0, |p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.first_alive().map_or(0, |p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.first_alive()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.member_names())
    }

    fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        Some(self.member_proxy_list())
    }

    fn current(&self) -> Option<String> {
        self.first_alive().map(|p| p.name().to_string())
    }

    fn selection(&self) -> Option<&dyn ProxySelection> {
        Some(self)
    }

    fn test_url(&self) -> Option<&str> {
        Some(&self.test_url)
    }

    fn expected_status(&self) -> Option<&str> {
        Some(&self.expected_status)
    }

    fn group_display(&self) -> Option<&GroupDisplay> {
        Some(&self.display)
    }

    fn usage_generation(&self) -> u64 {
        self.usage.generation()
    }

    fn chain_health(&self) -> Option<&Arc<ChainHealth>> {
        Some(&self.chain_health)
    }
}

#[async_trait]
impl ProxySelection for FallbackGroup {
    async fn set(&self, name: &str) -> Result<()> {
        let proxy = self
            .find_member(name)
            .ok_or_else(|| MeowError::Proxy("proxy not exist".into()))?;
        self.force_set(Some(name));
        if !proxy.alive_for_url(&self.test_url) {
            let _ = crate::health::probe_and_record(
                &proxy,
                &self.test_url,
                (!self.expected_status.is_empty()).then_some(self.expected_status.as_str()),
                std::time::Duration::from_secs(5),
            )
            .await;
        }
        Ok(())
    }

    fn force_set(&self, name: Option<&str>) {
        // Same contract as `UrlTestGroup::force_set`: `""` suppresses the
        // stored pin for this generation; `""` on disk is upstream's
        // cleared pin.
        *self.fixed.write() = Some(name.map_or_else(SmolStr::default, SmolStr::from));
        if let Some(store) = &self.store {
            store.set(&self.name, name.unwrap_or(""));
        }
    }

    fn fixed(&self) -> Option<String> {
        Some(
            self.effective_fixed()
                .map_or_else(String::new, |n| n.to_string()),
        )
    }

    fn can_unfix(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::test_support::MockProxy;
    use meow_common::Metadata;

    #[test]
    fn picks_first_when_all_alive() {
        let g = FallbackGroup::new("fb", vec![MockProxy::new("a"), MockProxy::new("b")]);
        assert_eq!(g.first_alive().unwrap().name(), "a");
    }

    #[test]
    fn skips_dead_to_next_alive() {
        let a = MockProxy::new("a");
        a.set_alive(false);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new("b"), MockProxy::new("c")]);
        assert_eq!(g.first_alive().unwrap().name(), "b");
    }

    #[test]
    fn all_dead_returns_first_proxy_as_last_resort() {
        // Upstream behaviour: when every member is dead, still return *something*
        // (the first proxy) so the caller can attempt the dial and surface a
        // real network error rather than a "no proxy" config error.
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_alive(false);
        b.set_alive(false);
        let g = FallbackGroup::new("fb", vec![a, b]);
        assert_eq!(g.first_alive().unwrap().name(), "a");
    }

    #[test]
    fn recovery_promotes_revived_member_back_to_head() {
        let a = MockProxy::new("a");
        a.set_alive(false);
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new("b")]);
        assert_eq!(g.first_alive().unwrap().name(), "b");
        a_ref.set_alive(true);
        assert_eq!(
            g.first_alive().unwrap().name(),
            "a",
            "head proxy regaining health must reclaim primary slot"
        );
    }

    #[test]
    fn member_names_preserve_declaration_order() {
        let g = FallbackGroup::new(
            "fb",
            vec![
                MockProxy::new("a"),
                MockProxy::new("b"),
                MockProxy::new("c"),
            ],
        );
        assert_eq!(g.member_names(), vec!["a", "b", "c"]);
    }

    /// `member_proxies()` must cover provider-slot members (issue #543
    /// item 1) and list them in `member_names()` order.
    #[test]
    fn member_proxies_include_provider_slots_in_member_names_order() {
        let slot: ProviderSlot = Arc::new(RwLock::new(vec![
            MockProxy::new("p1") as Arc<dyn Proxy>,
            MockProxy::new("p2") as Arc<dyn Proxy>,
        ]));
        let g = FallbackGroup::new_with_providers(
            "fb",
            vec![MockProxy::new("a"), MockProxy::new("b")],
            vec![slot],
        );
        let names: Vec<String> = g
            .member_proxies()
            .expect("groups expose members")
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        assert_eq!(names, g.member_names());
        assert_eq!(names, vec!["a", "b", "p1", "p2"]);
    }

    #[tokio::test]
    async fn dial_tcp_routes_through_first_alive() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_alive(false);
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let g = FallbackGroup::new("fb", vec![a, b]);
        assert_eq!(g.usage_generation(), 0, "unused group has no use");
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert_eq!(g.usage_generation(), 1, "dial records group use");
        assert_eq!(a_ref.dials(), 0);
        assert_eq!(b_ref.dials(), 1);
    }

    #[tokio::test]
    async fn health_probe_dials_do_not_count_as_use() {
        // Lazy health checks dial members with `ConnType::Tunnel`.  If those
        // dials incremented the usage generation, a parent group probing a
        // lazy child would keep the child's own probe loop awake forever.
        let g = FallbackGroup::new("fb", vec![MockProxy::new("a")]);
        let probe_meta = Metadata {
            conn_type: meow_common::ConnType::Tunnel,
            ..Default::default()
        };
        let _ = g.dial_tcp(&probe_meta).await;
        assert_eq!(
            g.usage_generation(),
            0,
            "probe dials must not mark the group as used"
        );
        // The `internal` flag (provider fetches, probes chained through
        // `dialer-proxy`) is the same housekeeping signal — also skipped
        // (issue #555).
        let internal_meta = Metadata {
            conn_type: meow_common::ConnType::Inner,
            internal: true,
            ..Default::default()
        };
        let _ = g.dial_tcp(&internal_meta).await;
        assert_eq!(
            g.usage_generation(),
            0,
            "internal dials must not mark the group as used"
        );
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert_eq!(g.usage_generation(), 1, "real traffic still marks use");
    }

    /// Issue #533: `unwrap_proxy(meta, false)` is the match-time peek —
    /// it must not record usage; `touch=true` (the real dial path) does.
    #[test]
    fn unwrap_peek_does_not_touch_usage() {
        let g = FallbackGroup::new("fb", vec![MockProxy::new("a"), MockProxy::new("b")]);
        let meta = Metadata::default();
        let peeked = g
            .unwrap_proxy(&meta, false)
            .expect("peek yields the first alive member");
        assert_eq!(peeked.name(), "a", "peek must return the pick target");
        assert_eq!(
            g.usage_generation(),
            0,
            "peek must not mark the group as used"
        );
        let _ = g.unwrap_proxy(&meta, true);
        assert_eq!(g.usage_generation(), 1, "real unwrap records the use");
    }

    /// Issue #681 wedge repro: `fallback: [selector, spare]` where the
    /// selector's pick always fails. Escalation used to dead-mark the
    /// selector's own (unread) health bit, so `alive()` stayed delegated-
    /// true and every dial re-picked the broken member forever.
    #[tokio::test]
    async fn dead_marked_selector_member_is_skipped() {
        let leaf = MockProxy::new("leaf"); // dial always errors
        let sel: Arc<dyn Proxy> = Arc::new(crate::group::selector::SelectorGroup::new(
            "sel",
            vec![leaf],
        ));
        let spare = MockProxy::new("spare");
        let spare_ref = Arc::clone(&spare);
        let g = FallbackGroup::new("fb", vec![sel, spare]);

        // Five dial failures inside the window escalate (each `dial_tcp`
        // fails instantly, so the streak stays inside 5s).
        for _ in 0..5 {
            let _ = g.dial_tcp(&Metadata::default()).await;
        }
        assert_eq!(
            spare_ref.dials(),
            0,
            "before escalation the first member is picked"
        );
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert_eq!(
            spare_ref.dials(),
            1,
            "dead-marked selector member must be skipped"
        );
    }

    #[test]
    fn support_udp_reflects_first_alive() {
        let a = MockProxy::new("a"); // tcp-only
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new_udp("b")]);
        assert!(!g.support_udp(), "a is alive and tcp-only");
        a_ref.set_alive(false);
        assert!(g.support_udp(), "fallback to udp-capable b");
    }

    /// Issue #969: when the first *alive* pick is a `dialer-proxy`-chained,
    /// UDP-incapable member the group must answer the pair the match probe
    /// reads — `support_udp() == false` and
    /// `is_dialer_proxy_non_transparent() == true` — so the scan stops on
    /// the matched rule instead of sliding to a later target. The verdict
    /// tracks `first_alive` exactly like `support_udp` does.
    #[test]
    fn fallback_pick_chained_udp_incapable_fails_closed() {
        let chained_inner = MockProxy::new_udp_unsupported("chained", AdapterType::Snell);
        let chained_inner_ref = Arc::clone(&chained_inner);
        let chained: Arc<dyn Proxy> = Arc::new(crate::DialerProxyAdapter::new(
            chained_inner,
            crate::dialer::DialerTarget::new(
                "never-resolved",
                &crate::dialer::ProxyRegistry::default(),
            ),
        ));
        let g = FallbackGroup::new("fb", vec![chained, MockProxy::new_udp("udp-ok")]);

        assert_eq!(g.first_alive().unwrap().name(), "chained");
        assert!(
            !g.support_udp(),
            "the first-alive pick cannot carry UDP — the group advertises its pick"
        );
        assert!(
            g.is_dialer_proxy_non_transparent(),
            "the fail-closed verdict must follow the same pick support_udp consults"
        );

        // Dead-marking the chained member moves the pick — and both
        // verdicts — to the UDP-capable spare.
        chained_inner_ref.set_alive(false);
        assert!(g.support_udp(), "fallback to udp-capable b");
        assert!(!g.is_dialer_proxy_non_transparent());
    }

    #[tokio::test]
    async fn user_pin_overrides_order_and_can_be_cleared() {
        let g = FallbackGroup::new("fb", vec![MockProxy::new("a"), MockProxy::new("b")]);
        ProxySelection::set(&g, "b").await.unwrap();
        assert_eq!(g.first_alive().unwrap().name(), "b");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some("b"));

        ProxySelection::force_set(&g, None);
        assert_eq!(g.first_alive().unwrap().name(), "a");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some(""));
    }

    #[tokio::test]
    async fn dead_fallback_pin_is_forgotten_in_memory() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let b_ref = Arc::clone(&b);
        let g = FallbackGroup::new("fb", vec![a, b]);
        ProxySelection::set(&g, "b").await.unwrap();
        b_ref.set_alive(false);
        assert_eq!(g.first_alive().unwrap().name(), "a");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some(""));
    }

    #[tokio::test]
    async fn repeated_dial_failures_mark_member_dead() {
        // mihomo GroupBase.onDialFailed: five failures within the window
        // escalate; the escalation marks the failed member dead so routing
        // skips it until the next probe revives it.
        let a = MockProxy::new_failing("a", AdapterType::Shadowsocks, "dial timed out");
        let b = MockProxy::new_failing("b", AdapterType::Shadowsocks, "dial timed out");
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let g = FallbackGroup::new("fb", vec![a, b]);

        for i in 1..5 {
            let _ = g.dial_tcp(&Metadata::default()).await;
            assert!(
                a_ref.alive(),
                "failure {i} is below the escalation threshold"
            );
        }
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert!(
            !a_ref.alive(),
            "the repeatedly failing member is marked dead"
        );
        assert!(b_ref.alive(), "the untouched member stays alive");

        // The dead member is skipped: the next dial reaches b instead.
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert_eq!(b_ref.dials(), 1, "routing moved past the dead member");
        assert_eq!(a_ref.dials(), 5);
    }

    #[tokio::test]
    async fn internal_dial_failures_still_mark_member_dead() {
        // `touch_user_traffic` skips internal dials, but
        // `record_dial_failure` deliberately does NOT (#555): a failed
        // housekeeping dial is real evidence the member is down — the
        // asymmetry must hold or housekeeping could mask a dead member.
        let a = MockProxy::new_failing("a", AdapterType::Shadowsocks, "dial timed out");
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new("b")]);
        let internal_meta = Metadata {
            internal: true,
            ..Default::default()
        };

        for _ in 0..5 {
            let _ = g.dial_tcp(&internal_meta).await;
        }
        assert!(
            !a_ref.alive(),
            "internal dial failures must still escalate to dead"
        );
        // …and the usage gate stays untouched by the same dials.
        assert_eq!(g.usage_generation(), 0);
    }

    #[tokio::test]
    async fn connection_refused_marks_member_dead_immediately() {
        // mihomo escalates "connection refused" without waiting for the
        // failure streak.
        let a = MockProxy::new_failing("a", AdapterType::Shadowsocks, "connection refused");
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new("b")]);

        let _ = g.dial_tcp(&Metadata::default()).await;
        assert!(!a_ref.alive(), "refused escalates on the first failure");
    }

    #[tokio::test]
    async fn direct_member_failures_are_exempt_from_escalation() {
        // mihomo exempts Direct/Reject-family members: their dial errors
        // describe the target, not the member.
        let a = MockProxy::new_failing("d", AdapterType::Direct, "connection refused");
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a]);

        for _ in 0..10 {
            let _ = g.dial_tcp(&Metadata::default()).await;
        }
        assert!(
            a_ref.alive(),
            "direct members are exempt from failure tracking"
        );
    }

    #[tokio::test]
    async fn udp_unsupported_member_failures_are_exempt_from_escalation() {
        // mihomo ignores ErrNotSupport failures; meow surfaces them as
        // MeowError::UdpNotSupported (relay chains, dialer proxies). They
        // describe a capability, not health, so UDP traffic must never mark
        // an otherwise healthy member dead.
        let a = MockProxy::new_udp_unsupported("r", AdapterType::Relay);
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a]);

        for _ in 0..10 {
            let _ = g.dial_udp(&Metadata::default()).await;
        }
        assert!(
            a_ref.alive(),
            "structural UdpNotSupported errors are exempt from failure tracking"
        );
    }

    /// The persisted pin is consulted lazily, like `SelectorGroup`'s — a
    /// store write between the build's open and the backing's adoption is
    /// the pin the group serves.
    #[test]
    fn persisted_pin_applies_lazily() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::group::selector_store::SelectorStore::open(dir.path().join("s.json"));
        let g = FallbackGroup::new("fb", vec![MockProxy::new("a"), MockProxy::new("b")])
            .with_runtime_options(
                "https://www.gstatic.com/generate_204".to_string(),
                String::new(),
                Some(crate::group::selector_store::SelectorWriter::standalone(
                    Arc::clone(&store),
                )),
            );

        store.set("fb", "b");
        assert_eq!(
            g.first_alive().unwrap().name(),
            "b",
            "a post-build store pin must be honored"
        );
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some("b"));
    }

    /// A store-sourced pin observed dead is suppressed in memory only —
    /// the file keeps it (upstream parity). Forgetting the pin reverts
    /// to declaration order, so a revived first member is picked again
    /// exactly like the eager-copy clearing was.
    #[test]
    fn dead_store_pin_is_suppressed_without_rewriting_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let store = crate::group::selector_store::SelectorStore::open(path.clone());
        let a = MockProxy::new("a");
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new("b")]).with_runtime_options(
            "https://www.gstatic.com/generate_204".to_string(),
            String::new(),
            Some(crate::group::selector_store::SelectorWriter::standalone(
                Arc::clone(&store),
            )),
        );

        store.set("fb", "a");
        a_ref.set_alive(false);
        assert_eq!(g.first_alive().unwrap().name(), "b");
        assert_eq!(
            store.get("fb").as_deref(),
            Some("a"),
            "a dead store pin is suppressed in memory, never rewritten"
        );

        a_ref.set_alive(true);
        assert_eq!(
            g.first_alive().unwrap().name(),
            "a",
            "with the pin forgotten, declaration order picks the revived member"
        );
        let on_disk: std::collections::HashMap<String, String> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(on_disk.get("fb").map(String::as_str), Some("a"));
    }

    /// A store pin overwritten between `first_alive`'s read and the
    /// suppress write keeps its new value — the suppression re-checks
    /// under the write lock (Codex review).
    #[test]
    fn suppress_does_not_clobber_a_newer_store_pin() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::group::selector_store::SelectorStore::open(dir.path().join("s.json"));
        let a = MockProxy::new("a");
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new("b")]).with_runtime_options(
            "https://www.gstatic.com/generate_204".to_string(),
            String::new(),
            Some(crate::group::selector_store::SelectorWriter::standalone(
                Arc::clone(&store),
            )),
        );

        store.set("fb", "a");
        a_ref.set_alive(false);
        // `first_alive` reads "a" dead; simulate the pin being replaced
        // before the suppression lands by re-arming the store with a
        // live pin and checking the suppress path directly.
        assert_eq!(g.effective_fixed().as_deref(), Some("a"));
        store.set("fb", "b");
        g.suppress_pin_if_still(&smol_str::SmolStr::from("a"));
        assert_eq!(
            g.effective_fixed().as_deref(),
            Some("b"),
            "a pin that changed to a different value must not be suppressed"
        );
    }
}
