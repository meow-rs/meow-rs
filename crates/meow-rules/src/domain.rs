use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct DomainRule {
    domain: SmolStr,
    adapter: Adapter,
}

impl DomainRule {
    pub fn new(domain: &str, adapter: &str) -> Self {
        Self {
            domain: domain.to_lowercase().into(),
            adapter: intern_adapter(adapter),
        }
    }
}

impl Rule for DomainRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Domain
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        metadata.rule_host().eq_ignore_ascii_case(&self.domain)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.domain
    }
}
