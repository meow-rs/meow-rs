//! SUB-RULE — references a named block of rules and evaluates them in order.
//!
//! Semantics: the first inner rule that matches wins; SUB-RULE returns that
//! rule's adapter as the routing target. If no inner rule matches, SUB-RULE
//! does not match — the tunnel loop continues to the next top-level rule
//! (fall-through). There is no default-target field.
//!
//! upstream `rules/logic/logic.go::matchSubRules` (lines 179–190):
//!
//! ```text
//! func matchSubRules(metadata *C.Metadata, name string, subRules map[string][]C.Rule) (bool, string) {
//!     for _, rule := range subRules[name] {
//!         if m, a := rule.Match(metadata); m {
//!             if a == "" {
//!                 return m, rule.Adapter()
//!             }
//!             return m, a
//!         }
//!     }
//!     return false, ""
//! }
//! ```
//!
//! upstream `rules/logic/logic.go::Logic.Match` SUB-RULE case (lines 192–198):
//!
//! ```text
//! case SUB_RULE:
//!     if l.payload == "" || l.ShouldResolveIP() && !metadata.Resolved() {
//!         return false, ""
//!     }
//!     return matchSubRules(metadata, l.adapter, subRules)
//! ```
//!
//! Baseline note: this gate ports the push-resolution generation of
//! upstream (pre-`ae7967f`); the later `LogicRules` refactor removed it
//! and let inner IP rules pull `helper.ResolveIP` themselves. Our engine
//! drives resolution (`RuleMatchHelper` is a marker struct), so the gate
//! is the correct port — future upstream-chasing should not treat its
//! absence there as a signal to remove it here.
//!
//! Our Rust translation compiles the block reference at parse time: each
//! `SubRule` owns an `Arc<Vec<Box<dyn Rule>>>` that points to the resolved
//! block. Sharing via `Arc` is reference-count sharing only; not semantically
//! observable.

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType, TargetProbe};
use std::sync::Arc;

/// Opaque handle to a shared, resolved sub-rule block.
pub type SubRuleBlock = Arc<Vec<Box<dyn Rule>>>;

pub struct SubRuleRule {
    block_name: String,
    block: SubRuleBlock,
}

impl SubRuleRule {
    pub fn new(block_name: &str, block: SubRuleBlock) -> Self {
        Self {
            block_name: block_name.to_string(),
            block,
        }
    }

    /// Test-only constructor that hides the `Arc` wrapping. Keeping the
    /// public `new` identical to how the config parser produces a SubRule.
    #[cfg(test)]
    pub(crate) fn from_rules(block_name: &str, rules: Vec<Box<dyn Rule>>) -> Self {
        Self::new(block_name, Arc::new(rules))
    }
}

impl Rule for SubRuleRule {
    fn rule_type(&self) -> RuleType {
        RuleType::SubRule
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        // Retained for API compatibility — only asks "did anything match?".
        // Non-authoritative: it applies no PASS-RULE filtering; the probe-
        // aware `match_and_resolve` is the contract the engines use.
        //
        // upstream logic.go: `l.ShouldResolveIP() && !metadata.Resolved()`
        // skips the block until the dst IP is resolved — without it an
        // inner domain rule can match early and pre-empt an inner IP rule
        // that would have matched once the address resolved (#625).
        if self.should_resolve_ip() && !metadata.resolved() {
            return false;
        }
        self.block
            .iter()
            .any(|r| r.match_metadata(metadata, helper))
    }

    fn adapter(&self) -> &str {
        // The target is resolved by `match_and_resolve` from the matching
        // inner rule. `adapter()` exposes the block name for diagnostics /
        // `MatchResult.payload`. This mirrors how upstream stores the
        // block name in the SUB-RULE entry's `target` slot (see
        // `rules/parser.go:80-81 NewSubRule`) — it is not a proxy name.
        &self.block_name
    }

    fn payload(&self) -> &str {
        &self.block_name
    }

    fn should_resolve_ip(&self) -> bool {
        // Dead children can never fire — their metadata demands must not
        // leak into the aggregate (#625).
        self.block
            .iter()
            .any(|r| !r.never_matches() && r.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.block
            .iter()
            .any(|r| !r.never_matches() && r.should_find_process())
    }

    fn never_matches(&self) -> bool {
        // An empty or all-dead block can never produce a match —
        // SUB-RULE falls through when every inner rule misses.
        self.block.iter().all(|r| r.never_matches())
    }

    fn match_and_resolve<'a>(
        &'a self,
        metadata: &Metadata,
        helper: &RuleMatchHelper,
        probe: &dyn TargetProbe,
    ) -> Option<&'a str> {
        // upstream logic.go::Logic.Match SUB_RULE arm — the whole block is
        // skipped while the dst IP is unresolved (#625); same gate as
        // `match_metadata` above.
        if self.should_resolve_ip() && !metadata.resolved() {
            return None;
        }
        // upstream: rules/logic/logic.go::matchSubRules — an inner rule
        // resolving to the literal `PASS-RULE` name or a PASS-RULE-typed
        // adapter (`CheckPassRule`) is skipped and the scan moves to the
        // next inner rule.
        for rule in self.block.iter() {
            if let Some(target) = rule.match_and_resolve(metadata, helper, probe) {
                if target == "PASS-RULE" || probe.is_pass_rule(target) {
                    continue;
                }
                return Some(target);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{Metadata, RuleMatchHelper, RuleType};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    /// Stub rule that always matches and returns a fixed target.
    struct MatchRule {
        adapter: String,
    }
    impl Rule for MatchRule {
        fn rule_type(&self) -> RuleType {
            RuleType::Match
        }
        fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
            true
        }
        fn adapter(&self) -> &str {
            &self.adapter
        }
        fn payload(&self) -> &str {
            ""
        }
    }

    /// Stub rule that never matches.
    struct NoMatchRule {
        adapter: String,
    }
    impl Rule for NoMatchRule {
        fn rule_type(&self) -> RuleType {
            RuleType::Match
        }
        fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
            false
        }
        fn adapter(&self) -> &str {
            &self.adapter
        }
        fn payload(&self) -> &str {
            ""
        }
    }

    fn match_rule(adapter: &str) -> Box<dyn Rule> {
        Box::new(MatchRule {
            adapter: adapter.to_string(),
        })
    }

    fn no_match_rule(adapter: &str) -> Box<dyn Rule> {
        Box::new(NoMatchRule {
            adapter: adapter.to_string(),
        })
    }

    /// A1 — first matching rule's adapter is returned.
    #[test]
    fn sub_rule_inner_match_returns_inner_target() {
        let sub = SubRuleRule::from_rules("BLOCK", vec![match_rule("DIRECT")]);
        let m = Metadata::default();
        assert_eq!(
            sub.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("DIRECT")
        );
    }

    /// A2 — block exhaustion propagates as None.
    #[test]
    fn sub_rule_block_exhausted_returns_none() {
        let sub = SubRuleRule::from_rules("BLOCK", vec![no_match_rule("A")]);
        let m = Metadata::default();
        assert_eq!(sub.match_and_resolve(&m, &helper(), &|_: &str| true), None);
    }

    /// A3 — first match wins.
    #[test]
    fn sub_rule_returns_first_matching_rule_target() {
        let sub = SubRuleRule::from_rules(
            "BLOCK",
            vec![no_match_rule("A"), match_rule("B"), match_rule("C")],
        );
        let m = Metadata::default();
        assert_eq!(
            sub.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("B")
        );
    }

    /// A4 — empty block returns None.
    #[test]
    fn sub_rule_empty_block_returns_none() {
        let sub = SubRuleRule::from_rules("BLOCK", vec![]);
        let m = Metadata::default();
        assert_eq!(sub.match_and_resolve(&m, &helper(), &|_: &str| true), None);
    }

    /// A5 — MATCH inside block always produces a result.
    #[test]
    fn sub_rule_match_rule_inside_block() {
        let sub = SubRuleRule::from_rules("BLOCK", vec![match_rule("Fallback")]);
        let m = Metadata::default();
        assert_eq!(
            sub.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("Fallback")
        );
    }

    /// A6 — target comes from inner rule, not from block_name.
    #[test]
    fn sub_rule_target_is_from_matched_rule_not_struct_field() {
        let block: SubRuleBlock = Arc::new(vec![match_rule("DIRECT")]);
        let a = SubRuleRule::new("BLOCK-A", Arc::clone(&block));
        let b = SubRuleRule::new("BLOCK-B", block);
        let m = Metadata::default();
        assert_eq!(
            a.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("DIRECT")
        );
        assert_eq!(
            b.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("DIRECT")
        );
    }

    /// B1 — nested SubRule returns leaf target.
    #[test]
    fn sub_rule_nested_one_level() {
        let inner: SubRuleBlock = Arc::new(vec![match_rule("DIRECT")]);
        let nested = SubRuleRule::new("B", inner);
        let outer = SubRuleRule::from_rules("A", vec![Box::new(nested)]);
        let m = Metadata::default();
        assert_eq!(
            outer.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("DIRECT")
        );
    }

    /// B2 — inner no-match propagates as None.
    #[test]
    fn sub_rule_nested_one_level_no_match_falls_through() {
        let inner: SubRuleBlock = Arc::new(vec![no_match_rule("X")]);
        let nested = SubRuleRule::new("B", inner);
        let outer = SubRuleRule::from_rules("A", vec![Box::new(nested)]);
        let m = Metadata::default();
        assert_eq!(
            outer.match_and_resolve(&m, &helper(), &|_: &str| true),
            None
        );
    }

    /// B3 — two-level chain returns leaf target.
    #[test]
    fn sub_rule_nested_two_levels() {
        let leaf: SubRuleBlock = Arc::new(vec![match_rule("LEAF")]);
        let mid = SubRuleRule::new("C", leaf);
        let outer_mid: SubRuleBlock = Arc::new(vec![Box::new(mid) as Box<dyn Rule>]);
        let top_mid = SubRuleRule::new("B", outer_mid);
        let top = SubRuleRule::from_rules("A", vec![Box::new(top_mid)]);
        let m = Metadata::default();
        assert_eq!(
            top.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("LEAF")
        );
    }

    /// Provably-dead stub carrying both metadata demands: the aggregate
    /// must not leak them (#625).
    struct DeadDemandingRule;
    impl Rule for DeadDemandingRule {
        fn rule_type(&self) -> RuleType {
            RuleType::Match
        }
        fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
            false
        }
        fn adapter(&self) -> &str {
            "X"
        }
        fn payload(&self) -> &str {
            "dead"
        }
        fn should_resolve_ip(&self) -> bool {
            true
        }
        fn should_find_process(&self) -> bool {
            true
        }
        fn never_matches(&self) -> bool {
            true
        }
    }

    /// D1 — an all-dead (or empty) block is provably dead.
    #[test]
    fn sub_rule_dead_block_never_matches() {
        let sub = SubRuleRule::from_rules("BLOCK", vec![Box::new(DeadDemandingRule)]);
        assert!(sub.never_matches());
        let empty = SubRuleRule::from_rules("BLOCK", vec![]);
        assert!(empty.never_matches());
    }

    /// Issue #625 — upstream `Logic.Match` SUB_RULE arm: a block whose
    /// rules demand a resolved IP must not match while `metadata.resolved()`
    /// is still false. Without the gate an inner domain-type matcher wins
    /// early, pre-empting an inner IP rule that would have matched once
    /// the address resolved.
    #[test]
    fn sub_rule_waits_for_ip_resolution() {
        /// IP-rule stand-in: demands resolution, matches only when the
        /// dst IP is present.
        struct NeedsIpRule;
        impl Rule for NeedsIpRule {
            fn rule_type(&self) -> RuleType {
                RuleType::Match
            }
            fn match_metadata(&self, m: &Metadata, _: &RuleMatchHelper) -> bool {
                m.resolved()
            }
            fn adapter(&self) -> &str {
                "IP-TARGET"
            }
            fn payload(&self) -> &str {
                "ip"
            }
            fn should_resolve_ip(&self) -> bool {
                true
            }
        }

        // Domain-first ordering: the early matcher must NOT win while the
        // metadata is still unresolved.
        let sub = SubRuleRule::from_rules(
            "BLOCK",
            vec![match_rule("DOMAIN-TARGET"), Box::new(NeedsIpRule)],
        );
        let unresolved = Metadata::default();
        assert!(
            sub.match_and_resolve(&unresolved, &helper(), &|_: &str| true)
                .is_none(),
            "a resolution-demanding block must not match unresolved metadata"
        );
        assert!(!sub.match_metadata(&unresolved, &helper()));

        let resolved = Metadata {
            dst_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            ..Metadata::default()
        };
        assert_eq!(
            sub.match_and_resolve(&resolved, &helper(), &|_: &str| true),
            Some("DOMAIN-TARGET"),
            "post-resolution the block evaluates in order"
        );
    }

    /// D2 — dead children's demands do not leak into the aggregate.
    #[test]
    fn sub_rule_aggregation_skips_dead_children() {
        let sub = SubRuleRule::from_rules(
            "BLOCK",
            vec![Box::new(DeadDemandingRule), match_rule("DIRECT")],
        );
        assert!(!sub.never_matches());
        assert!(!sub.should_resolve_ip());
        assert!(!sub.should_find_process());
    }
}
