use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};

pub struct FinalRule {
    adapter: Adapter,
}

impl FinalRule {
    pub fn new(adapter: &str) -> Self {
        Self {
            adapter: intern_adapter(adapter),
        }
    }
}

impl Rule for FinalRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Match
    }

    fn match_metadata(&self, _metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        true
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        ""
    }
}
