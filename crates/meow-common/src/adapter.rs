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
    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        None
    }
    /// Per-adapter health handle — owned, infallible. Dashboards (via the
    /// delay endpoints) record probe results through `health().record_delay`
    /// so `GET /proxies/:name` reflects the measurement.
    fn health(&self) -> &ProxyHealth;
}

/// Shared live proxy list owned by a `ProxyProvider`.
/// Groups hold `Vec<ProviderSlot>` and call `effective_proxies()` at dial time
/// to merge static members with provider-supplied proxies without caching.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

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
