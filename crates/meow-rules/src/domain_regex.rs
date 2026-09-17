use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use regex::Regex;
use smol_str::SmolStr;

pub struct DomainRegexRule {
    regex: Regex,
    pattern: SmolStr,
    adapter: Adapter,
}

impl DomainRegexRule {
    pub fn new(pattern: &str, adapter: &str) -> Result<Self, regex::Error> {
        let regex = Regex::new(pattern)?;
        Ok(Self {
            regex,
            pattern: pattern.into(),
            adapter: intern_adapter(adapter),
        })
    }
}

impl Rule for DomainRegexRule {
    fn rule_type(&self) -> RuleType {
        RuleType::DomainRegex
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        self.regex.is_match(metadata.rule_host())
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.pattern
    }
}
