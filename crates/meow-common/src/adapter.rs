use crate::adapter_type::AdapterType;
use crate::conn::{ProxyConn, ProxyPacketConn};
use crate::error::Result;
use crate::metadata::Metadata;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayHistory {
    #[serde(with = "rfc3339_system_time")]
    pub time: SystemTime,
    pub delay: u16,
}

/// Wire format for [`DelayHistory::time`]: an RFC 3339 string, matching
/// upstream Go mihomo where `history[].time` marshals via `time.Time`
/// (`"2024-01-15T10:30:45Z"`). serde's default `SystemTime` representation
/// is a `{secs_since_epoch, nanos_since_epoch}` object, which breaks API
/// clients and dashboards that decode the upstream string shape — a probe
/// recording history made `GET /proxies` undecodable for them.
mod rfc3339_system_time {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::SystemTime;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(t: &SystemTime, serializer: S) -> Result<S::Ok, S::Error> {
        let formatted = OffsetDateTime::from(*t)
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&formatted)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SystemTime, D::Error> {
        let s = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&s, &Rfc3339)
            .map(SystemTime::from)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyState {
    pub alive: bool,
    pub history: Vec<DelayHistory>,
}

/// Per-adapter liveness + rolling delay history. Owned by every concrete
/// adapter and accessed via [`ProxyAdapter::health`]. Writers use interior
/// mutability so the trait method can return `&ProxyHealth`.
pub struct ProxyHealth {
    alive: AtomicBool,
    history: RwLock<VecDeque<DelayHistory>>,
    max_history: usize,
}

impl ProxyHealth {
    pub fn new() -> Self {
        Self {
            alive: AtomicBool::new(true),
            history: RwLock::new(VecDeque::new()),
            max_history: 10,
        }
    }

    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::Relaxed);
    }

    pub fn last_delay(&self) -> u16 {
        self.history
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .back()
            .map_or(0, |h| h.delay)
    }

    pub fn delay_history(&self) -> Vec<DelayHistory> {
        self.history
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    pub fn record_delay(&self, delay: u16) {
        let mut history = self
            .history
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        history.push_back(DelayHistory {
            time: SystemTime::now(),
            delay,
        });
        if history.len() > self.max_history {
            history.pop_front();
        }
        self.alive.store(delay > 0, Ordering::Relaxed);
    }

    pub fn state(&self) -> ProxyState {
        ProxyState {
            alive: self.alive(),
            history: self.delay_history(),
        }
    }
}

impl Default for ProxyHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait ProxyAdapter: Send + Sync {
    fn name(&self) -> &str;
    fn adapter_type(&self) -> AdapterType;
    fn addr(&self) -> &str;
    fn support_udp(&self) -> bool;
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>>;
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>>;
    /// Run this adapter's complete post-connect pipeline over `stream`.
    ///
    /// Used by relay groups (M1.C-2) to chain proxy hops without dialling a
    /// new TCP connection.  Equivalent to mihomo's `DialContextWithDialer`
    /// where the injected dialer yields the existing stream: the adapter runs
    /// its full configured transport stack (TLS / WebSocket / obfs **to its
    /// own server**) and then the protocol handshake targeting `metadata`.
    /// The relay chain guarantees `stream` already terminates at this
    /// adapter's server.
    ///
    /// Single-use resources don't apply here: mux/`reuse` pooling is skipped
    /// (the stream cannot be re-dialled), and adapters whose protocol needs a
    /// dedicated socket (hysteria2's QUIC/UDP) or a subprocess-owned leg (SS
    /// external SIP003 plugins) keep the default.
    ///
    /// Default implementation returns `Err(NotSupported)`.  Override in
    /// adapters that support relay chaining (HTTP CONNECT, SOCKS5, …).
    ///
    /// upstream: `adapter/outbound/<proto>.go` — `DialContextWithDialer`
    async fn connect_over(
        &self,
        _stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Err(crate::error::MeowError::NotSupported(format!(
            "{}: connect_over not supported",
            self.name()
        )))
    }
    /// Resolve one selection layer — for groups, the member a dial would
    /// use. `touch` mirrors upstream `Unwrap(metadata, touch)`: `false` is
    /// a peek for match-time probing (round-robin counters do not advance,
    /// usage stats are not recorded); `true` is the real dial path. The
    /// permitted peek-time writes are upstream's: Fallback may drop a
    /// `fixed` selection whose member went dead (as `findAliveProxy` does
    /// regardless of `touch`), and UrlTest may refresh its `fastest` pick
    /// (as `fast(touch)` does) so the probe can never disagree with the
    /// next dial.
    fn unwrap_proxy(&self, _metadata: &Metadata, _touch: bool) -> Option<Arc<dyn Proxy>> {
        None
    }
    /// Drop every transport session this adapter caches across dials (mux
    /// session pools, a hysteria2 QUIC connection, pooled Snell/anytls
    /// sessions, a kcptun KCP session, …) so the next dial opens fresh
    /// sockets.
    ///
    /// Called when the outbound-interface binding changes
    /// (`meow_common::outbound_iface`, issue #695): a socket created before
    /// the binding was installed stays unbound for life and, under
    /// `tun.auto-route: global`, loops back into the TUN device. Idle
    /// sessions close immediately; sessions still carrying streams are
    /// closed too (their in-flight streams fail) or at least never handed
    /// out again — the caller cancels the TCP relays and UDP sessions that
    /// ride on them in the same operation. A session whose dial is still in
    /// flight when this runs must not be cached once it completes.
    ///
    /// Must be cheap, non-blocking, and safe to call concurrently with
    /// dials. Groups do not forward this to their members — the caller
    /// visits every adapter reachable through
    /// [`Proxy::member_proxies`] itself, so a group cycle cannot recurse.
    /// Transparent wrappers whose inner adapter is not a member (the config
    /// layer's `WrappedProxy`, the `dialer-proxy` wrapper) must forward it,
    /// or the inner adapter's default no-op runs instead.
    ///
    /// upstream: mihomo has no per-adapter equivalent — `ApplyConfig` swaps
    /// in freshly built adapters and calls `resolver.ResetConnection()`.
    fn reset_sessions(&self) {}
    /// Per-adapter health handle — owned, infallible. Writers: dashboards
    /// and delay endpoints record probe results through
    /// `health().record_delay`; `DialFailureTracker` escalation dead-marks
    /// failed group members via `health().set_alive(false)` and probe
    /// sweeps revive them via `record_delay`. For group adapters those
    /// writes must stay observable — each group's `alive()` reads this bit
    /// alongside its delegated member check (issue #681).
    fn health(&self) -> &ProxyHealth;
}

/// Shared live proxy list owned by a `ProxyProvider`.
/// Groups hold `Vec<ProviderSlot>` and walk statics then slot contents under
/// a read guard at pick time — the provider swaps the `Vec` on refresh and
/// the group sees the new membership on its next dial without caching.
pub type ProviderSlot = std::sync::Arc<parking_lot::RwLock<Vec<std::sync::Arc<dyn Proxy>>>>;

/// Runtime selection capability implemented by mihomo-compatible outbound
/// groups. `Selector`, `URLTest`, and `Fallback` are selectable; leaf
/// adapters and non-selectable groups return `None` from [`Proxy::selection`].
#[async_trait]
pub trait ProxySelection: Send + Sync {
    /// Validate and select a member by name.
    async fn set(&self, name: &str) -> Result<()>;

    /// Set or clear a selection without validation. This mirrors mihomo's
    /// `SelectAble.ForceSet` and is used to unfix automatic groups before a
    /// group health check.
    fn force_set(&self, name: Option<&str>);

    /// Value exposed as the mihomo `fixed` field. Automatic groups return
    /// `Some("")` while unfixed; selectors return `None` because upstream
    /// does not expose `fixed` for them.
    fn fixed(&self) -> Option<String>;

    /// Only automatic groups can be returned to automatic mode through
    /// `DELETE /proxies/{name}`.
    fn can_unfix(&self) -> bool;
}

pub trait Proxy: ProxyAdapter {
    fn alive(&self) -> bool;
    fn alive_for_url(&self, url: &str) -> bool;
    fn last_delay(&self) -> u16;
    fn last_delay_for_url(&self, url: &str) -> u16;
    fn delay_history(&self) -> Vec<DelayHistory>;
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }
    /// For group adapters: the ordered list of member proxy names.
    /// Leaf adapters return `None`.
    fn members(&self) -> Option<Vec<String>> {
        None
    }
    /// For group adapters: the member proxies themselves, in the same
    /// order as [`members`](Self::members). Includes members sourced from
    /// `use:` / `include-all` provider slots, which are not keys of the
    /// route table — anything that needs to probe or inspect *every*
    /// member must resolve through this rather than look the names up in
    /// the proxies map (issue #543 item 1). Leaf adapters return `None`.
    fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        None
    }
    /// For group adapters: the name of the currently active member
    /// (selected/fastest/first-alive depending on group kind).
    fn current(&self) -> Option<String> {
        None
    }

    /// Optional runtime selection capability for outbound groups.
    fn selection(&self) -> Option<&dyn ProxySelection> {
        None
    }

    /// Group health-check URL exposed by the mihomo API.
    fn test_url(&self) -> Option<&str> {
        None
    }

    /// Group expected-status expression exposed by the mihomo API.
    fn expected_status(&self) -> Option<&str> {
        None
    }

    /// Monotonic traffic-use generation for genuinely lazy health checks.
    /// Leaf adapters return zero; automatic groups increment on every dial.
    fn usage_generation(&self) -> u64 {
        0
    }
}

/// Call [`ProxyAdapter::reset_sessions`] once on every distinct adapter
/// reachable from `roots` — the roots themselves plus, transitively, every
/// group member including provider-sourced ones
/// ([`Proxy::member_proxies`]). Adapters are deduplicated by `Arc` identity,
/// so a member shared by several groups is reset once and a group cycle
/// terminates. Returns the number of distinct adapters visited.
///
/// Groups are visited too (their default `reset_sessions` is a no-op) so a
/// group type that does cache sessions can opt in without changing callers.
pub fn reset_sessions_reachable<I>(roots: I) -> usize
where
    I: IntoIterator<Item = Arc<dyn Proxy>>,
{
    let mut seen: std::collections::HashSet<*const ()> = std::collections::HashSet::new();
    let mut stack: Vec<Arc<dyn Proxy>> = roots.into_iter().collect();
    while let Some(proxy) = stack.pop() {
        // Thin data pointer: the same object reached through differently
        // typed `Arc<dyn Proxy>` handles must still dedupe.
        if !seen.insert(Arc::as_ptr(&proxy).cast::<()>()) {
            continue;
        }
        proxy.reset_sessions();
        if let Some(members) = proxy.member_proxies() {
            stack.extend(members);
        }
    }
    seen.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    /// Minimal leaf/group: counts `reset_sessions` calls; a group's members
    /// are set after construction so tests can build cycles.
    struct CountingProxy {
        resets: std::sync::atomic::AtomicUsize,
        members: std::sync::Mutex<Option<Vec<Arc<dyn Proxy>>>>,
        health: ProxyHealth,
    }

    impl CountingProxy {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                resets: std::sync::atomic::AtomicUsize::new(0),
                members: std::sync::Mutex::new(None),
                health: ProxyHealth::new(),
            })
        }

        fn resets(&self) -> usize {
            self.resets.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProxyAdapter for CountingProxy {
        fn name(&self) -> &str {
            "counting"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
            unreachable!("never dialed")
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            unreachable!("never dialed")
        }
        fn reset_sessions(&self) {
            self.resets.fetch_add(1, Ordering::SeqCst);
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for CountingProxy {
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
        fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
            self.members.lock().unwrap().clone()
        }
    }

    #[test]
    fn reset_sessions_reachable_visits_each_adapter_once_across_cycles() {
        let leaf_a = CountingProxy::new();
        let leaf_b = CountingProxy::new();
        let group_x = CountingProxy::new();
        let group_y = CountingProxy::new();
        // x → {a, b, y}; y → {a, x}: `a` is shared, x ↔ y is a cycle.
        *group_x.members.lock().unwrap() = Some(vec![
            Arc::clone(&leaf_a) as Arc<dyn Proxy>,
            Arc::clone(&leaf_b) as Arc<dyn Proxy>,
            Arc::clone(&group_y) as Arc<dyn Proxy>,
        ]);
        *group_y.members.lock().unwrap() = Some(vec![
            Arc::clone(&leaf_a) as Arc<dyn Proxy>,
            Arc::clone(&group_x) as Arc<dyn Proxy>,
        ]);

        // `a` is also a root in its own right (a route-table entry).
        let visited = reset_sessions_reachable([
            Arc::clone(&group_x) as Arc<dyn Proxy>,
            Arc::clone(&leaf_a) as Arc<dyn Proxy>,
        ]);

        assert_eq!(visited, 4);
        for proxy in [&leaf_a, &leaf_b, &group_x, &group_y] {
            assert_eq!(proxy.resets(), 1);
        }
        // Break the cycle so the test does not leak the pair.
        group_x.members.lock().unwrap().take();
    }

    #[test]
    fn delay_history_time_serializes_as_rfc3339_string() {
        let entry = DelayHistory {
            time: UNIX_EPOCH + Duration::from_secs(1_751_527_000),
            delay: 76,
        };
        let json = serde_json::to_value(&entry).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({"time": "2025-07-03T07:16:40Z", "delay": 76}),
        );
    }

    #[test]
    fn delay_history_round_trips_through_json() {
        let entry = DelayHistory {
            time: UNIX_EPOCH + Duration::from_secs(1_751_527_000),
            delay: 321,
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let back: DelayHistory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.time, entry.time);
        assert_eq!(back.delay, entry.delay);
    }
}
