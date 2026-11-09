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

#[cfg(test)]
mod tests {
    use super::*;

    /// `Regex::new("")` is a zero-width match — `is_match` is true on
    /// every `rule_host()` including `""`, so an empty payload silently
    /// swallows every flow. The config-time `domain_payload_defect`
    /// match-all reason depends on this contract (issue #869).
    #[test]
    fn empty_regex_payload_matches_every_flow() {
        let rule = DomainRegexRule::new("", "X").unwrap();
        assert!(rule.match_metadata(&Metadata::default(), &RuleMatchHelper));
        let named = Metadata {
            host: "example.com".into(),
            ..Metadata::default()
        };
        assert!(rule.match_metadata(&named, &RuleMatchHelper));
    }
}
