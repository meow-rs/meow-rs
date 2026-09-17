use std::sync::Arc;

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

use crate::rule_set::RuleSet;

/// A `RULE-SET,<name>,<adapter>[,no-resolve]` rule — a thin wrapper that
/// delegates matching to an `Arc<dyn RuleSet>` loaded by the rule-provider
/// subsystem.
pub struct RuleSetRule {
    name: SmolStr,
    set: Arc<dyn RuleSet>,
    adapter: Adapter,
    no_resolve: bool,
}

impl RuleSetRule {
    pub fn new(name: &str, set: Arc<dyn RuleSet>, adapter: &str, no_resolve: bool) -> Self {
        Self {
            name: name.into(),
            set,
            adapter: intern_adapter(adapter),
            no_resolve,
        }
    }

    pub fn rule_set(&self) -> &Arc<dyn RuleSet> {
        &self.set
    }
}

impl Rule for RuleSetRule {
    fn rule_type(&self) -> RuleType {
        RuleType::RuleSet
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.set.matches(metadata, helper)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.name
    }

    fn should_resolve_ip(&self) -> bool {
        self.set.should_resolve_ip() && !self.no_resolve
    }

    fn should_find_process(&self) -> bool {
        self.set.should_find_process()
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}
