//! SUB-RULE — references a named block of rules and evaluates them in order.
//!
//! Semantics: the first inner rule that matches wins; SUB-RULE returns that
//! rule's adapter as the routing target. If no inner rule matches, SUB-RULE
//! does not match — the tunnel loop continues to the next top-level rule
//! (fall-through). There is no default-target field.
//!
//! The conditional form (issue #974) adds a read-only predicate tree and an
//! optional MEOW-only fourth-field fallback:
//!
//! ```text
//! SUB-RULE,<name>                    // plain reference
//! SUB-RULE,(<cond>),<name>           // mihomo's conditional form
//! SUB-RULE,(<cond>),<name>,<target>  // MEOW extension: exhaust fallback
//! ```
//!
//! A true condition enters the block scan; a false one skips it entirely —
//! including any DNS / process demand the block would carry. A true
//! condition over an exhausted block (empty, all-miss, or all PASS-skipped)
//! falls through for the three-field form, or yields the fallback target
//! for the four-field form. The fallback itself goes through the outer
//! target checks like any other candidate.
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
//! Baseline note: the unresolved-IP gate ports the push-resolution
//! generation of upstream (pre-`ae7967f`); the later `LogicRules` refactor
//! removed it and let inner IP rules pull `helper.ResolveIP` themselves.
//! It is kept on the *plain* reference path only — the conditional
//! evaluation instead reports per-predicate demands upstream-style
//! (issue #974 §3.3), so the gate is the correct port for both.
//!
//! Our Rust translation compiles the block reference at parse time: each
//! `SubRule` owns an `Arc<Vec<Box<dyn Rule>>>` that points to the resolved
//! block. Sharing via `Arc` is reference-count sharing only; not semantically
//! observable.

use meow_common::{MatchDemand, Metadata, Rule, RuleMatchHelper, RuleType, TargetProbe};
use smol_str::SmolStr;
use std::sync::Arc;

use crate::adapter::{intern_adapter, Adapter};
use crate::logic::{AndRule, NotRule, OrRule};

/// Opaque handle to a shared, resolved sub-rule block.
pub type SubRuleBlock = Arc<Vec<Box<dyn Rule>>>;

/// The outcome of a demand-aware [`SubRuleRule::match_staged`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedVerdict<'a> {
    /// A candidate target — an inner rule's adapter or the fourth-field
    /// fallback. The outer scan still applies its target checks.
    Matched(&'a str),
    /// Condition false, or true + block exhausted with no fallback.
    Miss,
    /// A reached, live predicate demands metadata the caller can still
    /// materialize — the IR maps this to `NeedsEnrichment`
    /// (issue #974 §3.3). Never reported under [`MatchDemand::NONE`].
    Need { ip: bool, process: bool },
}

/// Outcome of one condition-tree node under demand-aware evaluation.
enum CondVerdict {
    True,
    False,
    /// An IP-demanding leaf with no `dst_ip` whose demand the gate
    /// cannot fulfill — undecidable, never read as false: `NOT` of it
    /// stays undecided (issue #974 spec §3.3).
    Undecided,
    Need {
        ip: bool,
        process: bool,
    },
}

pub struct SubRuleRule {
    block_name: String,
    block: SubRuleBlock,
    /// The condition predicate tree — `None` for the plain
    /// `SUB-RULE,<name>` reference. Built from shared-leg-grammar leaves
    /// plus the logic composites; its adapters are placeholders and
    /// never route, validate or account.
    cond: Option<Box<dyn Rule>>,
    /// MEOW's fourth field (issue #974): yielded when a true condition's
    /// block exhausts without a candidate.
    fallback: Option<Adapter>,
    /// `/rules` payload: `<name>` for the plain form, `(cond),<name>` or
    /// `(cond),<name>,<target>` for the conditional forms (upstream's
    /// conditional payload, `rules/logic/logic.go::Payload`).
    display: SmolStr,
    /// Staged (demand-aware) evaluation needed anywhere in the chain —
    /// this rule's own condition, or a member that is itself staged.
    staged: bool,
}

impl SubRuleRule {
    pub fn new(block_name: &str, block: SubRuleBlock) -> Self {
        let mut this = Self {
            block_name: block_name.to_string(),
            block,
            cond: None,
            fallback: None,
            display: SmolStr::from(block_name),
            staged: false,
        };
        this.staged = this.compute_staged();
        this
    }

    /// The conditional form: `cond` is the already-built predicate tree
    /// (`parse_cond` + `CondExpr::build`), `cond_text` its balanced
    /// `(…)` source for the `/rules` payload, `fallback` the optional
    /// fourth field.
    pub fn new_conditional(
        block_name: &str,
        block: SubRuleBlock,
        cond: Box<dyn Rule>,
        cond_text: &str,
        fallback: Option<&str>,
    ) -> Self {
        let display = match fallback {
            Some(target) => SmolStr::from(format!("{cond_text},{block_name},{target}")),
            None => SmolStr::from(format!("{cond_text},{block_name}")),
        };
        Self {
            block_name: block_name.to_string(),
            block,
            cond: Some(cond),
            fallback: fallback.map(intern_adapter),
            display,
            staged: true,
        }
    }

    /// Test-only constructor that hides the `Arc` wrapping. Keeping the
    /// public `new` identical to how the config parser produces a SubRule.
    #[cfg(test)]
    pub(crate) fn from_rules(block_name: &str, rules: Vec<Box<dyn Rule>>) -> Self {
        Self::new(block_name, Arc::new(rules))
    }

    /// Whether this reference needs the staged (condition-first,
    /// demand-propagating) evaluation path — its own condition or a
    /// nested conditional member anywhere in the block chain.
    pub fn is_staged(&self) -> bool {
        self.staged
    }

    /// The condition predicate tree, for the config-time
    /// `domain_payload_defect` walk (issue #974).
    pub fn cond(&self) -> Option<&dyn Rule> {
        self.cond.as_deref()
    }

    fn compute_staged(&self) -> bool {
        self.cond.is_some()
            || self.block.iter().any(|member| {
                member
                    .as_any()
                    .and_then(|any| any.downcast_ref::<SubRuleRule>())
                    .is_some_and(SubRuleRule::is_staged)
            })
    }

    /// Demand-aware evaluation: condition first, then an ordered block
    /// scan where only *reached* members may ask for enrichment. The
    /// IR's dynamic-adapter slots call this under the lazy demand gate;
    /// [`MatchDemand::NONE`] degenerates it to plain evaluation (every
    /// unreachable demand simply reads its predicate as false — the
    /// strict and probe scans use that).
    pub fn match_staged<'a>(
        &'a self,
        metadata: &Metadata,
        helper: &RuleMatchHelper,
        probe: &dyn TargetProbe,
        demand: &MatchDemand,
    ) -> StagedVerdict<'a> {
        if let Some(cond) = &self.cond {
            match eval_cond(cond.as_ref(), metadata, helper, demand) {
                CondVerdict::True => {}
                CondVerdict::False | CondVerdict::Undecided => return StagedVerdict::Miss,
                CondVerdict::Need { ip, process } => return StagedVerdict::Need { ip, process },
            }
        }
        // The plain reference's unresolved-IP gate, scoped to the
        // ordinary members: while the block carries a live IP-demanding
        // member and the flow is unresolved, the whole ordinary section
        // waits — a leading domain member must not pre-empt an IP member
        // that would match post-resolution (#625). Staged members carry
        // their own demand-aware gates and evaluate on position.
        //
        // The gate is a *plain reference* behaviour only: a true
        // condition enters an ordered block scan where each member's own
        // demand is consulted at its position (docs/specs/sub-rules.md —
        // the conditional form reports per-predicate needs "instead of
        // the push-resolution gate the plain reference keeps"). Applying
        // it here would force DNS before a deterministic earlier hit,
        // and drop that hit entirely when resolution is unavailable.
        let ordinary_needs_ip = self.cond.is_none()
            && self.block.iter().any(|member| {
                member
                    .as_any()
                    .and_then(|any| any.downcast_ref::<SubRuleRule>())
                    .is_none_or(|sub| !sub.is_staged())
                    && !member.never_matches()
                    && member.should_resolve_ip()
            });
        for member in self.block.iter() {
            if let Some(sub) = member
                .as_any()
                .and_then(|any| any.downcast_ref::<SubRuleRule>())
            {
                if sub.is_staged() {
                    // A staged member propagates verdicts wholesale: its
                    // cond, inner order and fallback all apply inside.
                    match sub.match_staged(metadata, helper, probe, demand) {
                        StagedVerdict::Matched(target) => {
                            if target == "PASS-RULE" || probe.is_pass_rule(target) {
                                continue;
                            }
                            return StagedVerdict::Matched(target);
                        }
                        StagedVerdict::Miss => continue,
                        need @ StagedVerdict::Need { .. } => return need,
                    }
                }
            }
            if ordinary_needs_ip && !metadata.resolved() {
                // Under `MatchDemand::NONE` this is exactly the plain
                // gate's skip; under the demand gate it reports the IP
                // the ordinary section needs — or concedes the block is
                // unreachable when nothing can resolve it.
                return if demand.needs_ip(metadata) {
                    StagedVerdict::Need {
                        ip: true,
                        process: false,
                    }
                } else {
                    StagedVerdict::Miss
                };
            }
            // A non-staged member asks for enrichment through its own
            // aggregate demand — but only when live and reachable, so a
            // never-match member or an earlier winner can never spend a
            // lookup on this flow.
            if !member.never_matches() {
                let ip = member.should_resolve_ip() && demand.needs_ip(metadata);
                let process = member.should_find_process() && demand.needs_process(metadata);
                if ip || process {
                    return StagedVerdict::Need { ip, process };
                }
            }
            if let Some(target) = member.match_and_resolve(metadata, helper, probe) {
                if target == "PASS-RULE" || probe.is_pass_rule(target) {
                    continue;
                }
                return StagedVerdict::Matched(target);
            }
        }
        // Block exhausted: the four-field fallback fires only on a true
        // condition; the three-field form falls through.
        match &self.fallback {
            Some(fallback) => StagedVerdict::Matched(fallback),
            None => StagedVerdict::Miss,
        }
    }
}

/// Demand-aware condition-tree evaluation: AND stops on false, OR on
/// true, NOT inverts only a decided verdict — "still needs enrichment"
/// is never read as false, and neither is "undecidable": an IP-demanding
/// leaf whose input the flow does not carry and the gate cannot produce
/// is [`CondVerdict::Undecided`], which a `NOT` propagates unchanged
/// (issue #974 §3.3 — undecided, never as false).
fn eval_cond(
    node: &dyn Rule,
    metadata: &Metadata,
    helper: &RuleMatchHelper,
    demand: &MatchDemand,
) -> CondVerdict {
    if let Some(any) = node.as_any() {
        if let Some(and) = any.downcast_ref::<AndRule>() {
            let mut undecided = false;
            for leg in and.sub_rules() {
                match eval_cond(leg.as_ref(), metadata, helper, demand) {
                    CondVerdict::False => return CondVerdict::False,
                    need @ CondVerdict::Need { .. } => return need,
                    CondVerdict::Undecided => undecided = true,
                    CondVerdict::True => {}
                }
            }
            return if undecided {
                CondVerdict::Undecided
            } else {
                CondVerdict::True
            };
        }
        if let Some(or) = any.downcast_ref::<OrRule>() {
            let mut undecided = false;
            for leg in or.sub_rules() {
                match eval_cond(leg.as_ref(), metadata, helper, demand) {
                    CondVerdict::True => return CondVerdict::True,
                    need @ CondVerdict::Need { .. } => return need,
                    CondVerdict::Undecided => undecided = true,
                    CondVerdict::False => {}
                }
            }
            return if undecided {
                CondVerdict::Undecided
            } else {
                CondVerdict::False
            };
        }
        if let Some(not) = any.downcast_ref::<NotRule>() {
            return match eval_cond(not.inner(), metadata, helper, demand) {
                CondVerdict::True => CondVerdict::False,
                CondVerdict::False => CondVerdict::True,
                other => other,
            };
        }
    }
    // A deterministic hit settles the leaf before any demand is spent:
    // what the flow already proves — a domain entry inside a mixed
    // classical provider, an exact host — stays true however the missing
    // metadata would resolve, so it must not wait on (or be dropped to)
    // an IP member that merely *could* match post-resolution (issue #974
    // review). A miss falls through to the demand gates.
    if node.match_metadata(metadata, helper) {
        return CondVerdict::True;
    }
    // Leaf: only a live, reached leaf may report a demand — and only a
    // dst-GEOIP-style rule asks for an IP (a `no-resolve` or `src` leaf
    // never does). A dead leaf just evaluates — always false anyway.
    if !node.never_matches() {
        let wants_ip = node.should_resolve_ip();
        let ip = wants_ip && demand.needs_ip(metadata);
        let process = node.should_find_process() && demand.needs_process(metadata);
        if ip || process {
            return CondVerdict::Need { ip, process };
        }
        // An IP-demanding leaf whose input is absent and whose demand the
        // gate cannot fulfill is undecidable — not false. `no-resolve` /
        // `src` leaves never land here (`wants_ip` is false for them),
        // and a process leaf with no process info reads its "no process"
        // as decided, like its top-level rule does.
        if wants_ip && !metadata.resolved() {
            return CondVerdict::Undecided;
        }
    }
    CondVerdict::False
}

impl Rule for SubRuleRule {
    fn rule_type(&self) -> RuleType {
        RuleType::SubRule
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        // Retained for API compatibility — only asks "did anything match?".
        // Non-authoritative: it applies no PASS-RULE filtering; the probe-
        // aware `match_and_resolve` is the contract the engines use.
        if self.staged {
            return matches!(
                self.match_staged(metadata, helper, &|_: &str| true, &MatchDemand::NONE),
                StagedVerdict::Matched(_)
            );
        }
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
        &self.display
    }

    fn should_resolve_ip(&self) -> bool {
        // Dead children can never fire — their metadata demands must not
        // leak into the aggregate (#625).
        self.cond
            .as_ref()
            .is_some_and(|c| !c.never_matches() && c.should_resolve_ip())
            || self
                .block
                .iter()
                .any(|r| !r.never_matches() && r.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.cond
            .as_ref()
            .is_some_and(|c| !c.never_matches() && c.should_find_process())
            || self
                .block
                .iter()
                .any(|r| !r.never_matches() && r.should_find_process())
    }

    fn never_matches(&self) -> bool {
        if let Some(cond) = &self.cond {
            if cond.never_matches() {
                return true;
            }
            // A fourth-field fallback still fires on a true condition —
            // an all-dead block alone cannot prove the reference dead.
            return self.fallback.is_none() && self.block.iter().all(|r| r.never_matches());
        }
        // An empty or all-dead block can never produce a match —
        // SUB-RULE falls through when every inner rule misses.
        self.block.iter().all(|r| r.never_matches())
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn match_and_resolve<'a>(
        &'a self,
        metadata: &Metadata,
        helper: &RuleMatchHelper,
        probe: &dyn TargetProbe,
    ) -> Option<&'a str> {
        if self.staged {
            return match self.match_staged(metadata, helper, probe, &MatchDemand::NONE) {
                StagedVerdict::Matched(target) => Some(target),
                StagedVerdict::Miss | StagedVerdict::Need { .. } => None,
            };
        }
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

    // ── Issue #974: staged (conditional) evaluation ─────────────────

    /// A cond-tree leaf stub: returns a fixed verdict and carries
    /// optional demands.
    struct CondLeaf {
        verdict: bool,
        ip: bool,
        process: bool,
        dead: bool,
    }
    impl Rule for CondLeaf {
        fn rule_type(&self) -> RuleType {
            RuleType::Domain
        }
        fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
            self.verdict
        }
        fn adapter(&self) -> &str {
            "COND"
        }
        fn payload(&self) -> &str {
            "cond"
        }
        fn should_resolve_ip(&self) -> bool {
            self.ip
        }
        fn should_find_process(&self) -> bool {
            self.process
        }
        fn never_matches(&self) -> bool {
            self.dead
        }
        fn as_any(&self) -> Option<&dyn std::any::Any> {
            Some(self)
        }
    }

    fn cond_ref(block: Vec<Box<dyn Rule>>, verdict: bool, fallback: Option<&str>) -> SubRuleRule {
        let cond: Box<dyn Rule> = Box::new(CondLeaf {
            verdict,
            ip: false,
            process: false,
            dead: false,
        });
        SubRuleRule::new_conditional("blk", Arc::new(block), cond, "(DOMAIN,a)", fallback)
    }

    /// Condition false skips the block entirely — no inner evaluation,
    /// no fallback.
    #[test]
    fn cond_false_skips_block() {
        let sub = cond_ref(vec![match_rule("INNER")], false, Some("FB"));
        let m = Metadata::default();
        assert_eq!(sub.match_and_resolve(&m, &helper(), &|_: &str| true), None);
        assert!(!sub.match_metadata(&m, &helper()));
    }

    /// Condition true + inner hit → the inner target wins.
    #[test]
    fn cond_true_inner_match() {
        let sub = cond_ref(
            vec![no_match_rule("A"), match_rule("INNER")],
            true,
            Some("FB"),
        );
        let m = Metadata::default();
        assert_eq!(
            sub.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("INNER")
        );
    }

    /// Condition true + exhausted block → three-field falls through,
    /// four-field yields the fallback.
    #[test]
    fn cond_true_exhaustion() {
        let three = cond_ref(vec![no_match_rule("A")], true, None);
        let four = cond_ref(vec![no_match_rule("A")], true, Some("FB"));
        let m = Metadata::default();
        assert_eq!(
            three.match_and_resolve(&m, &helper(), &|_: &str| true),
            None
        );
        assert_eq!(
            four.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("FB")
        );
        // An empty block is "exhausted" too.
        let empty = cond_ref(vec![], true, Some("FB"));
        assert_eq!(
            empty.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("FB")
        );
    }

    /// never_matches: a dead cond proves the reference dead even with a
    /// fallback; an all-dead block does not while a fallback exists.
    #[test]
    fn cond_never_matches_policy() {
        let dead_cond: Box<dyn Rule> = Box::new(CondLeaf {
            verdict: false,
            ip: false,
            process: false,
            dead: true,
        });
        let dead = SubRuleRule::new_conditional(
            "blk",
            Arc::new(vec![]),
            dead_cond,
            "(GEOIP,XX)",
            Some("FB"),
        );
        assert!(dead.never_matches());

        let dead_block = cond_ref(vec![Box::new(DeadDemandingRule)], true, Some("FB"));
        assert!(
            !dead_block.never_matches(),
            "a fallback keeps an all-dead-block reference live"
        );
        let dead_no_fb = cond_ref(vec![Box::new(DeadDemandingRule)], true, None);
        assert!(dead_no_fb.never_matches());
    }

    /// Staged demand: a reached, live member reports the process need;
    /// an earlier winner stops the scan first.
    #[test]
    fn staged_member_demands() {
        struct ProcRule;
        impl Rule for ProcRule {
            fn rule_type(&self) -> RuleType {
                RuleType::ProcessName
            }
            fn match_metadata(&self, m: &Metadata, _: &RuleMatchHelper) -> bool {
                m.process == "curl"
            }
            fn adapter(&self) -> &str {
                "PROC"
            }
            fn payload(&self) -> &str {
                "curl"
            }
            fn should_find_process(&self) -> bool {
                true
            }
        }
        let sub = cond_ref(vec![Box::new(ProcRule), match_rule("LATE")], true, None);
        let m = Metadata {
            src_ip: Some("10.0.0.1".parse().unwrap()),
            src_port: 1234,
            ..Default::default()
        };
        // Under an actionable gate the process-demanding member blocks
        // before any target resolves.
        let demand = MatchDemand {
            ip: true,
            process: true,
        };
        assert_eq!(
            sub.match_staged(&m, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Need {
                ip: false,
                process: true
            }
        );
        // Under NONE (no enrichment available) the member just misses,
        // and the later rule still wins.
        assert_eq!(
            sub.match_staged(&m, &helper(), &|_: &str| true, &MatchDemand::NONE),
            StagedVerdict::Matched("LATE")
        );

        // An earlier winner pre-empts the demand entirely.
        let early_win = cond_ref(vec![match_rule("EARLY"), Box::new(ProcRule)], true, None);
        assert_eq!(
            early_win.match_staged(&m, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Matched("EARLY")
        );
    }

    /// A cond leaf demanding metadata reports Need before the block is
    /// entered — AND the block's members never run at all that pass.
    #[test]
    fn staged_cond_demands_before_block() {
        let cond: Box<dyn Rule> = Box::new(CondLeaf {
            verdict: false, // would be false anyway if evaluated
            ip: true,
            process: false,
            dead: false,
        });
        let sub = SubRuleRule::new_conditional(
            "blk",
            Arc::new(vec![match_rule("INNER")]),
            cond,
            "(GEOIP,JP)",
            Some("FB"),
        );
        let m = Metadata {
            host: "x.example".into(),
            src_ip: Some("10.0.0.1".parse().unwrap()),
            src_port: 1,
            ..Default::default()
        };
        let demand = MatchDemand {
            ip: true,
            process: true,
        };
        assert_eq!(
            sub.match_staged(&m, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Need {
                ip: true,
                process: false
            }
        );
        // With dst_ip already resolved, the leaf evaluates → false →
        // the block is skipped (no fallback, no inner match).
        let resolved = Metadata {
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            ..m
        };
        assert_eq!(
            sub.match_staged(&resolved, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Miss
        );
    }

    /// Staged propagates through a plain member into a nested
    /// conditional member.
    #[test]
    fn staged_propagates_through_plain_member() {
        let inner_cond = cond_ref(vec![match_rule("LEAF")], true, None);
        let plain_member: SubRuleBlock = Arc::new(vec![Box::new(inner_cond) as Box<dyn Rule>]);
        let outer = SubRuleRule::new("outer", plain_member);
        assert!(outer.is_staged());
        let m = Metadata::default();
        assert_eq!(
            outer.match_and_resolve(&m, &helper(), &|_: &str| true),
            Some("LEAF")
        );
    }

    /// IP-rule stand-in for the staged-block gate tests.
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

    /// Issue #974 review — the plain reference's unresolved-IP gate
    /// survives a staged member in the same block: while the ordinary
    /// section carries an IP-demanding rule and the flow is unresolved,
    /// it waits (or misses under an unactionable gate) rather than
    /// letting a leading domain member pre-empt the IP rule.
    #[test]
    fn staged_block_retains_plain_ip_gate() {
        let staged_member = cond_ref(vec![match_rule("STAGED")], true, None);
        let block: Vec<Box<dyn Rule>> = vec![
            match_rule("DOMAIN-TARGET"),
            Box::new(NeedsIpRule),
            Box::new(staged_member),
        ];
        let outer = SubRuleRule::new("blk", Arc::new(block));
        assert!(outer.is_staged());
        let unresolved = Metadata {
            host: "x.example".into(),
            ..Default::default()
        };
        // Eager path: the gate is the plain skip — the leading domain
        // member must NOT win while the flow is unresolved.
        assert!(
            outer
                .match_and_resolve(&unresolved, &helper(), &|_: &str| true)
                .is_none(),
            "the ordinary section must wait for resolution"
        );
        assert!(!outer.match_metadata(&unresolved, &helper()));
        // Actionable gate: the section reports the IP it waits for.
        let demand = MatchDemand {
            ip: true,
            process: true,
        };
        assert_eq!(
            outer.match_staged(&unresolved, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Need {
                ip: true,
                process: false
            }
        );
        // Resolved: the block evaluates in order — the domain member wins.
        let resolved = Metadata {
            dst_ip: Some("9.9.9.9".parse().unwrap()),
            ..unresolved
        };
        assert_eq!(
            outer.match_and_resolve(&resolved, &helper(), &|_: &str| true),
            Some("DOMAIN-TARGET")
        );
    }

    /// Issue #974 spec — an IP-demanding cond leaf the gate cannot
    /// fulfill is undecided, never false: a `NOT` over it stays
    /// undecided, so the block is not entered on an unresolvable flow.
    #[test]
    fn cond_undecided_ip_leaf_under_not() {
        use crate::logic::NotRule;
        let leaf: Box<dyn Rule> = Box::new(CondLeaf {
            verdict: false,
            ip: true,
            process: false,
            dead: false,
        });
        let not: Box<dyn Rule> = Box::new(NotRule::new(leaf, "PH"));
        let sub = SubRuleRule::new_conditional(
            "blk",
            Arc::new(vec![match_rule("INNER")]),
            not,
            "(!(GEOIP,JP))",
            None,
        );
        // Host empty → no name to resolve → the leaf is undecidable under
        // either gate; `!(undecidable)` is undecidable, never true.
        let unresolved = Metadata::default();
        assert_eq!(
            sub.match_staged(&unresolved, &helper(), &|_: &str| true, &MatchDemand::NONE),
            StagedVerdict::Miss
        );
        let demand = MatchDemand {
            ip: true,
            process: true,
        };
        assert_eq!(
            sub.match_staged(&unresolved, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Miss,
            "an undecidable leaf under NOT must not enter the block"
        );
        // A resolvable flow still reports the demand instead.
        let resolvable = Metadata {
            host: "x.example".into(),
            ..Metadata::default()
        };
        assert_eq!(
            sub.match_staged(&resolvable, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Need {
                ip: true,
                process: false
            }
        );
        // Resolved → the leaf evaluates to false → NOT true → block entered.
        let resolved = Metadata {
            dst_ip: Some("9.9.9.9".parse().unwrap()),
            ..unresolved
        };
        assert_eq!(
            sub.match_staged(&resolved, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Matched("INNER")
        );
    }

    /// Issue #974 review — the ordinary-section IP gate is a *plain
    /// reference* behaviour: a true condition enters an ordered block
    /// scan, so a leading deterministic member must win before a later
    /// IP-demanding member's need is even consulted — under both an
    /// actionable gate (no DNS spent) and `MatchDemand::NONE` (the hit
    /// must not be dropped).
    #[test]
    fn cond_true_block_evaluates_ordered_without_aggregate_gate() {
        let sub = cond_ref(
            vec![match_rule("DOMAIN-TARGET"), Box::new(NeedsIpRule)],
            true,
            None,
        );
        let unresolved = Metadata {
            host: "x.example".into(),
            ..Default::default()
        };
        // Under an empty gate the domain member's hit must stand — the
        // aggregate gate used to drop the whole block to Miss here.
        assert_eq!(
            sub.match_staged(&unresolved, &helper(), &|_: &str| true, &MatchDemand::NONE),
            StagedVerdict::Matched("DOMAIN-TARGET")
        );
        assert_eq!(
            sub.match_and_resolve(&unresolved, &helper(), &|_: &str| true),
            Some("DOMAIN-TARGET")
        );
        // Under an actionable gate the deterministic member still wins
        // first — no DNS is spent on the trailing IP member.
        let demand = MatchDemand {
            ip: true,
            process: true,
        };
        assert_eq!(
            sub.match_staged(&unresolved, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Matched("DOMAIN-TARGET")
        );

        // Order is still honoured: when the IP member leads, its own
        // demand is reported at its position.
        let ip_first = cond_ref(vec![Box::new(NeedsIpRule), match_rule("LATE")], true, None);
        assert_eq!(
            ip_first.match_staged(&unresolved, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Need {
                ip: true,
                process: false
            }
        );
        assert_eq!(
            ip_first.match_staged(&unresolved, &helper(), &|_: &str| true, &MatchDemand::NONE),
            StagedVerdict::Matched("LATE")
        );
    }

    /// Issue #974 review — a `(RULE-SET,name)` cond leaf over a mixed
    /// classical provider: the provider's domain entries match a
    /// hostname deterministically, so the leaf must read True rather
    /// than Need/Undecided on an unresolved flow — the aggregate
    /// `should_resolve_ip` must not shadow the deterministic hit.
    #[test]
    fn cond_ruleset_leaf_deterministic_hit_beats_ip_demand() {
        use crate::parser::RuleSets;
        let set = crate::rule_set::build_rule_set(
            crate::rule_set::RuleSetBehavior::Classical,
            &[
                "DOMAIN,hit.example".to_string(),
                "IP-CIDR,10.0.0.0/8".to_string(),
            ],
            &crate::parser::ParserContext::empty(),
        );
        let mut rule_sets: RuleSets = RuleSets::new();
        rule_sets.insert("mixed".to_string(), std::sync::Arc::from(set));
        let expr = crate::sub_rule_cond::parse_cond("(RULE-SET,mixed)").unwrap();
        let cond = expr
            .build(&crate::parser::ParserContext::empty(), &rule_sets)
            .unwrap();
        let sub = SubRuleRule::new_conditional(
            "blk",
            Arc::new(vec![match_rule("INNER")]),
            cond,
            "(RULE-SET,mixed)",
            None,
        );
        let unresolved = Metadata {
            host: "hit.example".into(),
            ..Default::default()
        };
        // NONE: the domain entry's hit must stand — before the fix the
        // aggregate IP demand turned the leaf Undecided and the block
        // never ran.
        assert_eq!(
            sub.match_staged(&unresolved, &helper(), &|_: &str| true, &MatchDemand::NONE),
            StagedVerdict::Matched("INNER")
        );
        // An actionable gate must not spend DNS on a decided leaf either.
        let demand = MatchDemand {
            ip: true,
            process: true,
        };
        assert_eq!(
            sub.match_staged(&unresolved, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Matched("INNER")
        );

        // A hostname the domain entries do not cover is still
        // undecidable — the IP member may match post-resolution.
        let other = Metadata {
            host: "other.example".into(),
            ..Default::default()
        };
        assert_eq!(
            sub.match_staged(&other, &helper(), &|_: &str| true, &MatchDemand::NONE),
            StagedVerdict::Miss
        );
        assert_eq!(
            sub.match_staged(&other, &helper(), &|_: &str| true, &demand),
            StagedVerdict::Need {
                ip: true,
                process: false
            }
        );
    }
}
