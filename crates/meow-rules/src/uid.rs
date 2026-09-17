//! UID rule — matches on `Metadata.uid` (Unix process user ID).
//!
//! Linux-only: on non-Linux platforms the rule parses successfully but
//! `match_metadata` always returns `false`, and a `warn!` is emitted
//! once at parse time.  Class B per ADR-0002: user's traffic still routes
//! correctly (rule is skipped); the warn signals that the rule is a no-op.
//!
//! upstream: `rules/common/uid.go`

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct UidRule {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    uid: u32,
    raw: SmolStr,
    adapter: Adapter,
}

impl UidRule {
    /// Parse `uid` as a Unix UID (unsigned integer).
    ///
    /// Emits a warn on non-Linux: `rules/common/uid.go` — UID rules are
    /// meaningless outside Linux.  Class B per ADR-0002.
    ///
    /// upstream: `rules/common/uid.go`
    pub fn new(uid: &str, adapter: &str) -> Result<Self, String> {
        let value: u32 = uid
            .trim()
            .parse()
            .map_err(|e| format!("invalid UID value '{}': {}", uid.trim(), e))?;

        #[cfg(not(target_os = "linux"))]
        tracing::warn!(
            uid = value,
            "UID rule is Linux-only; this rule will never match on the current platform \
             (Class B per ADR-0002 — upstream: rules/common/uid.go)"
        );

        Ok(Self {
            uid: value,
            raw: uid.into(),
            adapter: intern_adapter(adapter),
        })
    }
}

impl Rule for UidRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Uid
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        #[cfg(target_os = "linux")]
        return metadata.uid == Some(self.uid);

        #[cfg(not(target_os = "linux"))]
        {
            let _ = metadata;
            false
        }
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }

    fn should_find_process(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{Metadata, RuleMatchHelper};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    #[test]
    fn uid_parse_succeeds_cross_platform() {
        // Must NOT return an error on non-Linux — rule is valid config.
        // upstream: rules/common/uid.go
        let r = UidRule::new("1000", "DIRECT");
        assert!(r.is_ok(), "UID parse must succeed on all platforms");
    }

    #[test]
    fn uid_invalid_payload_errors() {
        assert!(UidRule::new("abc", "DIRECT").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uid_match_linux() {
        let r = UidRule::new("1000", "DIRECT").unwrap();
        let meta = Metadata {
            uid: Some(1000),
            ..Default::default()
        };
        assert!(r.match_metadata(&meta, &helper()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uid_no_match_linux() {
        let r = UidRule::new("1000", "DIRECT").unwrap();
        let meta = Metadata {
            uid: Some(2000),
            ..Default::default()
        };
        assert!(!r.match_metadata(&meta, &helper()));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn uid_never_matches_non_linux() {
        // Class B per ADR-0002: always false on non-Linux.
        let r = UidRule::new("1000", "DIRECT").unwrap();
        let meta = Metadata {
            uid: Some(1000),
            ..Default::default()
        };
        assert!(
            !r.match_metadata(&meta, &helper()),
            "UID must never match on non-Linux"
        );
    }
}
