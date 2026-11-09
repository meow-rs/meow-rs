use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct DomainSuffixRule {
    suffix: SmolStr,
    adapter: Adapter,
}

impl DomainSuffixRule {
    pub fn new(suffix: &str, adapter: &str) -> Self {
        Self {
            suffix: suffix.to_ascii_lowercase().into(),
            adapter: intern_adapter(adapter),
        }
    }
}

impl Rule for DomainSuffixRule {
    fn rule_type(&self) -> RuleType {
        RuleType::DomainSuffix
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let host = metadata.rule_host().as_bytes();
        let suffix = self.suffix.as_bytes();
        if host.len() == suffix.len() {
            return host.eq_ignore_ascii_case(suffix);
        }
        // Subdomain match: host must end with ".{suffix}" (no alloc).
        if host.len() > suffix.len() {
            let dot_pos = host.len() - suffix.len() - 1;
            if host[dot_pos] == b'.' && host[dot_pos + 1..].eq_ignore_ascii_case(suffix) {
                return true;
            }
        }
        false
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.suffix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rule_host()` is `""` on host-less flows and `"" == ""` under the
    /// equal-length arm, so an empty payload silently matches every
    /// IP-literal destination — a host-less match-all, not dead config
    /// (issue #869). The config-time `domain_payload_defect` reason
    /// depends on this contract.
    #[test]
    fn empty_suffix_payload_matches_host_less_flows() {
        let rule = DomainSuffixRule::new("", "X");
        assert!(rule.match_metadata(&Metadata::default(), &RuleMatchHelper));
        let named = Metadata {
            host: "example.com".into(),
            ..Metadata::default()
        };
        assert!(!rule.match_metadata(&named, &RuleMatchHelper));
    }
}
