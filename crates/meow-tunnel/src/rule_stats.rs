//! Per-rule runtime state behind mihomo's `/rules` `extra` object and
//! `PATCH /rules/disable` (`constant.RuleWrapper`): a hit counter, the last
//! hit time, and the disabled switch dashboards toggle.
//!
//! One instance per rule list. A rebuilt list (any config commit,
//! subscription refresh) carries each rule's state over by (type, payload,
//! target), the n-th equal rule taking the n-th one's, so a disabled rule
//! stays disabled. Misses are not counted — the compiled
//! matcher never visits most rules, so a miss count would mean evaluating
//! every rule per connection; `/rules` reports zero for them.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering::Relaxed};
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
    /// Fast path: matching consults the per-rule switch only while any
    /// rule is disabled. A re-enable decrements back to 0 — a one-way
    /// latch would leave the slow path on forever after one disable cycle.
    disabled_count: AtomicUsize,
}

impl RuleStats {
    pub fn new(rule_count: usize) -> Self {
        Self {
            entries: (0..rule_count).map(|_| RuleStat::default()).collect(),
            disabled_count: AtomicUsize::new(0),
        }
    }

    /// Stats for `new_rules`, carrying over the state of equal rules
    /// (type, payload, target; the n-th equal one takes the n-th's) from
    /// `old_rules` / `old`.
    pub fn carried<'a>(
        old_rules: &'a [Box<dyn meow_common::Rule>],
        old: &Self,
        new_rules: &'a [Box<dyn meow_common::Rule>],
    ) -> Self {
        let fresh = Self::new(new_rules.len());
        if old.is_empty() || new_rules.is_empty() {
            return fresh;
        }
        type Key<'a> = (meow_common::RuleType, &'a str, &'a str);
        fn key(r: &dyn meow_common::Rule) -> Key<'_> {
            (r.rule_type(), r.payload(), r.adapter())
        }
        // Fast path — the common reload is the same list verbatim: equal
        // keys in equal positions copy state slot-for-slot and skip the
        // map + VecDeque allocation entirely.
        if old_rules.len() == new_rules.len()
            && old_rules
                .iter()
                .zip(new_rules.iter())
                .all(|(a, b)| key(a.as_ref()) == key(b.as_ref()))
        {
            for (from, to) in old.entries.iter().zip(fresh.entries.iter()) {
                to.hits.store(from.hits.load(Relaxed), Relaxed);
                to.hit_at.store(from.hit_at.load(Relaxed), Relaxed);
                if from.disabled.load(Relaxed) {
                    to.disabled.store(true, Relaxed);
                    fresh.disabled_count.fetch_add(1, Relaxed);
                }
            }
            return fresh;
        }
        let mut by_key: std::collections::HashMap<Key<'a>, std::collections::VecDeque<usize>> =
            std::collections::HashMap::new();
        for (i, r) in old_rules.iter().enumerate() {
            by_key.entry(key(r.as_ref())).or_default().push_back(i);
        }
        for (i, r) in new_rules.iter().enumerate() {
            let Some(j) = by_key
                .get_mut(&key(r.as_ref()))
                .and_then(std::collections::VecDeque::pop_front)
            else {
                continue;
            };
            let (Some(from), Some(to)) = (old.entries.get(j), fresh.entries.get(i)) else {
                continue;
            };
            to.hits.store(from.hits.load(Relaxed), Relaxed);
            to.hit_at.store(from.hit_at.load(Relaxed), Relaxed);
            if from.disabled.load(Relaxed) {
                to.disabled.store(true, Relaxed);
                fresh.disabled_count.fetch_add(1, Relaxed);
            }
        }
        fresh
    }

    /// Whether rule `index` is switched off.
    pub fn is_disabled(&self, index: usize) -> bool {
        !self.is_enabled(index)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    pub fn is_enabled(&self, index: usize) -> bool {
        self.disabled_count.load(Relaxed) == 0
            || !self
                .entries
                .get(index)
                .is_some_and(|e| e.disabled.load(Relaxed))
    }

    /// Returns `false` for an index past the end (mihomo skips those).
    /// `disabled_count` moves only on an actual transition — rewriting the
    /// same value must not unbalance it.
    pub fn set_disabled(&self, index: usize, disabled: bool) -> bool {
        let Some(e) = self.entries.get(index) else {
            return false;
        };
        if e.disabled.swap(disabled, Relaxed) == disabled {
            return true;
        }
        if disabled {
            self.disabled_count.fetch_add(1, Relaxed);
        } else {
            self.disabled_count.fetch_sub(1, Relaxed);
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

    /// The count gates `is_enabled`'s fast path: it must move only on a
    /// real transition and return to 0 once nothing is disabled, not
    /// latch on after the first disable (issue #882 review).
    #[test]
    fn disabled_count_tracks_transitions() {
        let s = RuleStats::new(2);
        s.set_disabled(0, true);
        s.set_disabled(1, true);
        assert_eq!(s.disabled_count.load(Relaxed), 2);
        // Rewriting the same value is not a transition.
        s.set_disabled(0, true);
        assert_eq!(s.disabled_count.load(Relaxed), 2);
        s.set_disabled(0, false);
        assert_eq!(s.disabled_count.load(Relaxed), 1);
        assert!(!s.is_enabled(1) && s.is_enabled(0));
        s.set_disabled(1, false);
        assert_eq!(s.disabled_count.load(Relaxed), 0);
        assert!(s.is_enabled(0) && s.is_enabled(1));
    }

    /// A rebuilt list keeps the switch of an equal rule, the n-th equal
    /// rule taking the n-th one's; new rules start enabled.
    #[test]
    fn carried_follows_equal_rules() {
        use meow_rules::domain_suffix::DomainSuffixRule;
        let r = |p: &str, t: &str| -> Box<dyn meow_common::Rule> {
            Box::new(DomainSuffixRule::new(p, t))
        };
        let old = vec![r("a.com", "P"), r("b.com", "P"), r("b.com", "P")];
        let stats = RuleStats::new(old.len());
        stats.set_disabled(0, true);
        stats.set_disabled(2, true);
        stats.record_hit(1);
        let new = vec![
            r("new.com", "P"),
            r("b.com", "P"),
            r("a.com", "P"),
            r("b.com", "P"),
        ];
        let c = RuleStats::carried(&old, &stats, &new);
        assert!(c.is_enabled(0));
        assert!(c.is_enabled(1) && c.view(1).hits == 1);
        assert!(c.is_disabled(2));
        assert!(c.is_disabled(3));
    }

    /// The same list rebuilt verbatim hits the positional fast path —
    /// same semantics as the map walk (issue #882 review).
    #[test]
    fn carried_identical_list_copies_positionally() {
        use meow_rules::domain_suffix::DomainSuffixRule;
        let r = |p: &str| -> Box<dyn meow_common::Rule> { Box::new(DomainSuffixRule::new(p, "P")) };
        let old = vec![r("a.com"), r("b.com")];
        let stats = RuleStats::new(old.len());
        stats.set_disabled(1, true);
        stats.record_hit(0);
        let new = vec![r("a.com"), r("b.com")];
        let c = RuleStats::carried(&old, &stats, &new);
        assert_eq!(c.view(0).hits, 1);
        assert!(c.is_enabled(0) && c.is_disabled(1));
        assert_eq!(c.disabled_count.load(Relaxed), 1);
    }
}
