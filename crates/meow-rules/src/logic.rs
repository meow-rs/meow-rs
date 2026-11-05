use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

/// mihomo's display payload of a logic rule (`rules/logic/logic.go`
/// `Payload()`): `((Type,payload) && (Type,payload))`, which `/rules` and a
/// connection's `rulePayload` report and dashboards show.
fn logic_payload(rules: &[Box<dyn Rule>], sep: &str) -> SmolStr {
    let parts: Vec<String> = rules
        .iter()
        .map(|r| format!("({},{})", r.rule_type().mihomo_name(), r.payload()))
        .collect();
    format!("({})", parts.join(sep)).into()
}

pub struct AndRule {
    rules: Vec<Box<dyn Rule>>,
    adapter: Adapter,
    payload: SmolStr,
}

impl AndRule {
    pub fn new(rules: Vec<Box<dyn Rule>>, adapter: &str) -> Self {
        let payload = logic_payload(&rules, " && ");
        Self {
            rules,
            adapter: intern_adapter(adapter),
            payload,
        }
    }

    pub fn sub_rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }
}

impl Rule for AndRule {
    fn rule_type(&self) -> RuleType {
        RuleType::And
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.rules
            .iter()
            .all(|r| r.match_metadata(metadata, helper))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload
    }

    fn should_resolve_ip(&self) -> bool {
        // Dead children can never fire — their metadata demands must not
        // leak into the aggregate (#625).
        self.rules
            .iter()
            .any(|r| !r.never_matches() && r.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.rules
            .iter()
            .any(|r| !r.never_matches() && r.should_find_process())
    }

    fn never_matches(&self) -> bool {
        // AND semantics: one provably-dead child makes the whole tree
        // unreachable regardless of the remaining arms.
        self.rules.iter().any(|r| r.never_matches())
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

pub struct OrRule {
    rules: Vec<Box<dyn Rule>>,
    adapter: Adapter,
    payload: SmolStr,
}

impl OrRule {
    pub fn new(rules: Vec<Box<dyn Rule>>, adapter: &str) -> Self {
        let payload = logic_payload(&rules, " || ");
        Self {
            rules,
            adapter: intern_adapter(adapter),
            payload,
        }
    }

    pub fn sub_rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }
}

impl Rule for OrRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Or
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.rules
            .iter()
            .any(|r| r.match_metadata(metadata, helper))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload
    }

    fn should_resolve_ip(&self) -> bool {
        self.rules
            .iter()
            .any(|r| !r.never_matches() && r.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.rules
            .iter()
            .any(|r| !r.never_matches() && r.should_find_process())
    }

    fn never_matches(&self) -> bool {
        // OR dies only when *every* arm is provably dead — including the
        // vacuous empty tree (`any()` on no children is false at match
        // time too).
        self.rules.iter().all(|r| r.never_matches())
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

pub struct NotRule {
    rule: Box<dyn Rule>,
    adapter: Adapter,
    payload: SmolStr,
}

impl NotRule {
    pub fn new(rule: Box<dyn Rule>, adapter: &str) -> Self {
        let payload = format!("(!({},{}))", rule.rule_type().mihomo_name(), rule.payload()).into();
        Self {
            rule,
            adapter: intern_adapter(adapter),
            payload,
        }
    }

    pub fn inner(&self) -> &dyn Rule {
        self.rule.as_ref()
    }
}

impl Rule for NotRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Not
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        !self.rule.match_metadata(metadata, helper)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload
    }

    fn should_resolve_ip(&self) -> bool {
        // A dead inner makes NOT unconditionally true — it matches
        // without the child's metadata demands ever mattering (#625).
        !self.rule.never_matches() && self.rule.should_resolve_ip()
    }

    fn should_find_process(&self) -> bool {
        !self.rule.never_matches() && self.rule.should_find_process()
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::Metadata;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    /// Provably-dead stub carrying both metadata demands: composites must
    /// prune it and must not aggregate its demands (#625).
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

    /// Live stub with no demands of its own.
    struct LivePlainRule;
    impl Rule for LivePlainRule {
        fn rule_type(&self) -> RuleType {
            RuleType::Match
        }
        fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
            true
        }
        fn adapter(&self) -> &str {
            "X"
        }
        fn payload(&self) -> &str {
            "live"
        }
    }

    #[test]
    fn and_with_dead_child_never_matches() {
        let and = AndRule::new(
            vec![Box::new(LivePlainRule), Box::new(DeadDemandingRule)],
            "A",
        );
        assert!(and.never_matches());
        assert!(!and.match_metadata(&Metadata::default(), &helper()));
    }

    #[test]
    fn and_with_only_live_children_stays() {
        let and = AndRule::new(vec![Box::new(LivePlainRule)], "A");
        assert!(!and.never_matches());
    }

    #[test]
    fn or_with_only_dead_children_never_matches() {
        let or = OrRule::new(
            vec![Box::new(DeadDemandingRule), Box::new(DeadDemandingRule)],
            "A",
        );
        assert!(or.never_matches());
    }

    #[test]
    fn or_with_live_child_stays_but_drops_dead_demands() {
        let or = OrRule::new(
            vec![Box::new(DeadDemandingRule), Box::new(LivePlainRule)],
            "A",
        );
        assert!(!or.never_matches());
        assert!(!or.should_resolve_ip());
        assert!(!or.should_find_process());
    }

    #[test]
    fn empty_or_never_matches() {
        let or = OrRule::new(vec![], "A");
        assert!(or.never_matches());
        assert!(!or.match_metadata(&Metadata::default(), &helper()));
    }

    #[test]
    fn not_of_dead_child_demands_nothing_and_matches() {
        let not = NotRule::new(Box::new(DeadDemandingRule), "A");
        assert!(!not.should_resolve_ip());
        assert!(!not.should_find_process());
        // NOT(dead) is unconditionally true.
        assert!(not.match_metadata(&Metadata::default(), &helper()));
    }
}
