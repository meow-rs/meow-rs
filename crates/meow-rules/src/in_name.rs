//! IN-NAME rule — matches on the inbound listener name (`Metadata.in_name`).
//!
//! upstream: `rules/common/inbound.go`

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct InNameRule {
    name: SmolStr,
    adapter: Adapter,
}

impl InNameRule {
    pub fn new(name: &str, adapter: &str) -> Result<Self, String> {
        Ok(Self {
            name: name.into(),
            adapter: intern_adapter(adapter),
        })
    }
}

impl Rule for InNameRule {
    fn rule_type(&self) -> RuleType {
        RuleType::InName
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        !metadata.in_name.is_empty() && metadata.in_name.as_str() == &*self.name
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{Metadata, RuleMatchHelper};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_with_name(in_name: &str) -> Metadata {
        Metadata {
            in_name: in_name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn in_name_rule_matches_named_listener() {
        let r = InNameRule::new("corp", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_name("corp"), &helper()));
    }

    #[test]
    fn in_name_rule_no_match_different_name() {
        let r = InNameRule::new("corp", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_name("personal"), &helper()));
    }

    #[test]
    fn in_name_empty_in_metadata_never_matches() {
        let r = InNameRule::new("corp", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_name(""), &helper()));
    }
}
