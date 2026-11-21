//! REMATCH-NAME rule — matches on the marker a `type: rematch` control
//! outbound stamped on the flow (`Metadata.rematch_name`, issue #974).
//!
//! upstream: `rules/common/rematch.go` — the payload is a `/`-separated
//! name list, each alternative compared for exact equality; the rule
//! never demands destination-IP resolution or process lookup.

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct RematchNameRule {
    /// The `/`-separated alternatives, each trimmed. Matching is exact,
    /// case-sensitive byte equality — no regex, glob or substring
    /// semantics, and no `|` alternation (a `|` byte stays literal).
    names: Box<[SmolStr]>,
    /// The field's verbatim text — what `/rules` reports and a config
    /// round-trip rewrites — distinct from `names` because the stored
    /// alternatives dropped their per-token whitespace.
    raw: SmolStr,
    adapter: Adapter,
}

impl RematchNameRule {
    pub fn new(names: &str, adapter: &str) -> Result<Self, String> {
        let alts: Vec<SmolStr> = names.split('/').map(str::trim).map(SmolStr::from).collect();
        // Upstream rejects the whole rule on an empty alternative —
        // `a//b` or a lone `/` is a typo, not "also match the unset
        // marker" (an unset marker never matches anything).
        if alts.iter().any(SmolStr::is_empty) {
            return Err(format!(
                "REMATCH-NAME: empty name in list '{names}' — an unset marker never matches"
            ));
        }
        Ok(Self {
            names: alts.into_boxed_slice(),
            raw: SmolStr::from(names),
            adapter: intern_adapter(adapter),
        })
    }
}

impl Rule for RematchNameRule {
    fn rule_type(&self) -> RuleType {
        RuleType::RematchName
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let name = metadata.rematch_name();
        !name.is_empty() && self.names.iter().any(|alt| alt.as_str() == name)
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
    use meow_common::{Metadata, RuleMatchHelper};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_with_marker(name: &str) -> Metadata {
        let mut m = Metadata::default();
        m.set_rematch_name(name);
        m
    }

    #[test]
    fn matches_exact_name() {
        let r = RematchNameRule::new("stage1", "REJECT").unwrap();
        assert!(r.match_metadata(&meta_with_marker("stage1"), &helper()));
    }

    #[test]
    fn alternates_split_on_slash() {
        let r = RematchNameRule::new("stage1/alternative", "REJECT").unwrap();
        assert!(r.match_metadata(&meta_with_marker("stage1"), &helper()));
        assert!(r.match_metadata(&meta_with_marker("alternative"), &helper()));
        assert!(!r.match_metadata(&meta_with_marker("other"), &helper()));
    }

    #[test]
    fn tokens_are_trimmed_but_match_is_exact() {
        let r = RematchNameRule::new(" stage1 / alternative ", "REJECT").unwrap();
        assert!(r.match_metadata(&meta_with_marker("stage1"), &helper()));
        // No substring or case folding: `Stage1`, `stage10`, `stag` miss.
        for miss in ["Stage1", "STAGE1", "stage10", "stag", "stage1 alternative"] {
            assert!(
                !r.match_metadata(&meta_with_marker(miss), &helper()),
                "'{miss}' must not match"
            );
        }
    }

    #[test]
    fn unset_marker_never_matches() {
        let r = RematchNameRule::new("stage1", "REJECT").unwrap();
        assert!(!r.match_metadata(&Metadata::default(), &helper()));
    }

    #[test]
    fn empty_alternatives_reject() {
        for bad in ["", "/", "a//b", "/a", "a/", " / "] {
            assert!(
                RematchNameRule::new(bad, "REJECT").is_err(),
                "'{bad}' must be rejected"
            );
        }
    }

    #[test]
    fn no_ip_or_process_demand() {
        let r = RematchNameRule::new("stage1", "REJECT").unwrap();
        assert!(!r.should_resolve_ip());
        assert!(!r.should_find_process());
    }

    #[test]
    fn payload_preserves_field_text() {
        let r = RematchNameRule::new(" stage1 / alternative ", "REJECT").unwrap();
        assert_eq!(r.payload(), " stage1 / alternative ");
        assert_eq!(r.rule_type().as_str(), "REMATCH-NAME");
        assert_eq!(r.rule_type().mihomo_name(), "RematchName");
    }
}
