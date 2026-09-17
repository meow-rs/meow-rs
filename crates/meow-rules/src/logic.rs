use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct AndRule {
    rules: Vec<Box<dyn Rule>>,
    adapter: Adapter,
    payload: SmolStr,
}

impl AndRule {
    pub fn new(rules: Vec<Box<dyn Rule>>, adapter: &str) -> Self {
        let payload = rules
            .iter()
            .map(|r| r.payload().to_string())
            .collect::<Vec<_>>()
            .join(" AND ")
            .into();
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
        self.rules.iter().any(|r| r.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.rules.iter().any(|r| r.should_find_process())
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
        let payload = rules
            .iter()
            .map(|r| r.payload().to_string())
            .collect::<Vec<_>>()
            .join(" OR ")
            .into();
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
        self.rules.iter().any(|r| r.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.rules.iter().any(|r| r.should_find_process())
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
        let payload = format!("NOT {}", rule.payload()).into();
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
        self.rule.should_resolve_ip()
    }

    fn should_find_process(&self) -> bool {
        self.rule.should_find_process()
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}
