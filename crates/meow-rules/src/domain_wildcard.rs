//! DOMAIN-WILDCARD rule — glob match on `Metadata.rule_host`.
//!
//! Semantics: `*` matches any sequence of non-dot characters within a single
//! label.  Case-insensitive.  No `?` single-character wildcard.
//!
//! upstream: `rules/common/domain_wildcard.go` — compiles `*` to
//! `[^.]+` (single-label).

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct DomainWildcardRule {
    pattern: regex::Regex,
    raw: SmolStr,
    adapter: Adapter,
}

impl DomainWildcardRule {
    /// Compile `pattern` (a glob with `*` only) into a case-insensitive
    /// regex that anchors the full host string.
    ///
    /// upstream: `rules/common/domain_wildcard.go`
    pub fn new(pattern: &str, adapter: &str) -> Result<Self, String> {
        let escaped = regex::escape(pattern);
        // `*` — single-label: any sequence of non-dot characters.
        let expanded = escaped.replace(r"\*", r"[^.]+");
        let re = regex::Regex::new(&format!("^(?i){expanded}$"))
            .map_err(|e| format!("invalid DOMAIN-WILDCARD pattern '{pattern}': {e}"))?;
        Ok(Self {
            pattern: re,
            raw: pattern.into(),
            adapter: intern_adapter(adapter),
        })
    }
}

impl Rule for DomainWildcardRule {
    fn rule_type(&self) -> RuleType {
        RuleType::DomainWildcard
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let host = metadata.rule_host();
        if host.is_empty() {
            return false;
        }
        self.pattern.is_match(host)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_host(host: &str) -> Metadata {
        Metadata {
            host: host.into(),
            ..Default::default()
        }
    }

    #[test]
    fn domain_wildcard_single_label_match() {
        let r = DomainWildcardRule::new("*.example.com", "PROXY").unwrap();
        assert!(r.match_metadata(&meta_host("foo.example.com"), &helper()));
    }

    /// `*` is single-label only — does not span dots.
    /// upstream: `rules/common/domain_wildcard.go` — `*` compiles to `[^.]+`.
    #[test]
    fn domain_wildcard_no_match_multi_label() {
        let r = DomainWildcardRule::new("*.example.com", "PROXY").unwrap();
        assert!(!r.match_metadata(&meta_host("foo.bar.example.com"), &helper()));
    }

    #[test]
    fn domain_wildcard_case_insensitive() {
        let r = DomainWildcardRule::new("*.EXAMPLE.COM", "PROXY").unwrap();
        assert!(r.match_metadata(&meta_host("foo.example.com"), &helper()));

        let r2 = DomainWildcardRule::new("*.example.com", "PROXY").unwrap();
        assert!(r2.match_metadata(&meta_host("FOO.EXAMPLE.COM"), &helper()));
    }

    #[test]
    fn domain_wildcard_no_match_wrong_parent() {
        let r = DomainWildcardRule::new("*.example.com", "PROXY").unwrap();
        assert!(!r.match_metadata(&meta_host("foo.notexample.com"), &helper()));
    }

    /// `?` is NOT a wildcard — upstream doesn't support it either.
    #[test]
    fn domain_wildcard_no_question_mark_support() {
        let r = DomainWildcardRule::new("?.example.com", "PROXY").unwrap();
        assert!(!r.match_metadata(&meta_host("a.example.com"), &helper()));
    }

    #[test]
    fn domain_wildcard_double_wildcard() {
        let r = DomainWildcardRule::new("*.*.example.com", "PROXY").unwrap();
        assert!(r.match_metadata(&meta_host("a.b.example.com"), &helper()));
        assert!(!r.match_metadata(&meta_host("a.b.c.example.com"), &helper()));
    }

    #[test]
    fn domain_wildcard_rule_type_and_payload() {
        let r = DomainWildcardRule::new("*.example.com", "PROXY").unwrap();
        assert_eq!(r.rule_type(), RuleType::DomainWildcard);
        assert_eq!(r.payload(), "*.example.com");
        assert_eq!(r.adapter(), "PROXY");
    }

    #[test]
    fn domain_wildcard_empty_host_no_match() {
        let r = DomainWildcardRule::new("*.example.com", "PROXY").unwrap();
        assert!(!r.match_metadata(&meta_host(""), &helper()));
    }

    #[test]
    fn domain_wildcard_uses_sniff_host() {
        let r = DomainWildcardRule::new("*.example.com", "PROXY").unwrap();
        let mut m = meta_host("fake.com");
        m.sniff_host = "real.example.com".into();
        assert!(r.match_metadata(&m, &helper()));
    }
}
