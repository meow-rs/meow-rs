//! Per-rule runtime state behind mihomo's `/rules` `extra` object and
//! `PATCH /rules/disable` (`constant.RuleWrapper`): a hit counter, the last
//! hit time, and the disabled switch dashboards toggle.
//!
//! One instance per rule list: a rebuilt rule list starts fresh, as
//! mihomo's wrappers do on reload. Misses are not counted — the compiled
//! matcher never visits most rules, so a miss count would mean evaluating
//! every rule per connection; `/rules` reports zero for them.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
use std::time::{SystemTime, UNIX_EPOCH};

use meow_common::atomic::AtomicU;

#[derive(Default)]
struct RuleStat {
    hits: AtomicU,
    /// Unix seconds of the last hit, 0 when never.
    hit_at: AtomicU32,
    disabled: AtomicBool,
}

/// Snapshot of one rule's state for the API.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleStatView {
    pub hits: u64,
    pub hit_at: u32,
    pub disabled: bool,
}

#[derive(Default)]
pub struct RuleStats {
    entries: Box<[RuleStat]>,
    /// Fast path: matching consults the per-rule switch only once any rule
    /// has been disabled.
    any_disabled: AtomicBool,
}

impl RuleStats {
    pub fn new(rule_count: usize) -> Self {
        Self {
            entries: (0..rule_count).map(|_| RuleStat::default()).collect(),
            any_disabled: AtomicBool::new(false),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    pub fn is_enabled(&self, index: usize) -> bool {
        !self.any_disabled.load(Relaxed)
            || !self
                .entries
                .get(index)
                .is_some_and(|e| e.disabled.load(Relaxed))
    }

    /// Returns `false` for an index past the end (mihomo skips those).
    pub fn set_disabled(&self, index: usize, disabled: bool) -> bool {
        let Some(e) = self.entries.get(index) else {
            return false;
        };
        e.disabled.store(disabled, Relaxed);
        if disabled {
            self.any_disabled.store(true, Relaxed);
        }
        true
    }

    #[inline]
    pub fn record_hit(&self, index: usize) {
        if let Some(e) = self.entries.get(index) {
            e.hits.fetch_add(1, Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
            e.hit_at.store(now, Relaxed);
        }
    }

    #[allow(
        clippy::useless_conversion,
        reason = "AtomicU is AtomicU32 on targets without 64-bit atomics (mipsel)"
    )]
    pub fn view(&self, index: usize) -> RuleStatView {
        self.entries
            .get(index)
            .map(|e| RuleStatView {
                hits: e.hits.load(Relaxed).into(),
                hit_at: e.hit_at.load(Relaxed),
                disabled: e.disabled.load(Relaxed),
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_hits_and_bounds() {
        let s = RuleStats::new(2);
        assert!(s.is_enabled(0) && s.is_enabled(1) && s.is_enabled(9));
        assert!(s.set_disabled(1, true));
        assert!(!s.set_disabled(2, true), "past the end");
        assert!(s.is_enabled(0) && !s.is_enabled(1));
        s.record_hit(0);
        s.record_hit(0);
        s.record_hit(5);
        let v = s.view(0);
        assert_eq!(v.hits, 2);
        assert!(v.hit_at > 0 && !v.disabled);
        assert!(s.view(1).disabled);
        assert!(s.set_disabled(1, false));
        assert!(s.is_enabled(1));
    }
}
