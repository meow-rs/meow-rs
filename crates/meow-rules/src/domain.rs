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

#[cfg(test)]
mod tests {
    use super::*;

    /// `rule_host()` is `""` on host-less flows and `"" == ""`, so an
    /// empty payload silently matches every IP-literal destination — a
    /// host-less match-all, not dead config (issue #869). The config-time
    /// `domain_payload_defect` reason depends on this contract.
    #[test]
    fn empty_domain_payload_matches_host_less_flows() {
        let rule = DomainRule::new("", "X");
        assert!(rule.match_metadata(&Metadata::default(), &RuleMatchHelper));
        let named = Metadata {
            host: "example.com".into(),
            ..Metadata::default()
        };
        assert!(!rule.match_metadata(&named, &RuleMatchHelper));
    }
}
