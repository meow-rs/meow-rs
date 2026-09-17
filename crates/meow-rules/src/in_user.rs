//! IN-USER rule — matches on the authenticated inbound username (`Metadata.in_user`).
//!
//! `Metadata.in_user` is `None` when no auth is configured or the connection
//! bypassed auth. This rule never matches in that case.
//!
//! upstream: `rules/common/inbound.go`

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct InUserRule {
    username: SmolStr,
    adapter: Adapter,
}

impl InUserRule {
    pub fn new(username: &str, adapter: &str) -> Result<Self, String> {
        Ok(Self {
            username: username.into(),
            adapter: intern_adapter(adapter),
        })
    }
}

impl Rule for InUserRule {
    fn rule_type(&self) -> RuleType {
        RuleType::InUser
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        metadata.in_user.as_deref() == Some(&*self.username)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.username
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{Metadata, RuleMatchHelper};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_with_user(in_user: Option<&str>) -> Metadata {
        Metadata {
            in_user: in_user.map(Into::into),
            ..Default::default()
        }
    }

    #[test]
    fn in_user_matches_when_populated() {
        let r = InUserRule::new("alice", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_user(Some("alice")), &helper()));
    }

    #[test]
    fn in_user_no_match_different_user() {
        let r = InUserRule::new("alice", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_user(Some("bob")), &helper()));
    }

    #[test]
    fn in_user_none_never_matches() {
        // No auth configured: in_user is None → IN-USER never matches.
        // upstream: rules/common/inbound.go (populated only after auth)
        let r = InUserRule::new("alice", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_user(None), &helper()));
    }
}
