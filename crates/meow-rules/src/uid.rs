//! UID rule — matches on `Metadata.uid` (Unix process user ID).
//!
//! Linux-only: on non-Linux platforms the rule parses successfully but
//! `match_metadata` always returns `false`, and a `warn!` is emitted
//! once at parse time.  Class B per ADR-0002: user's traffic still routes
//! correctly (rule is skipped); the warn signals that the rule is a no-op.
//! The exception is an embedder whose inbound supplies `uid` itself (an
//! Android VPN, see `meow_common::process_lookup::enable_inbound_process_info`):
//! there the rule matches that uid on any platform.
//!
//! upstream: `rules/common/uid.go`

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct UidRule {
    uid: u32,
    raw: SmolStr,
    adapter: Adapter,
}

impl UidRule {
    /// Parse `uid` as a Unix UID (unsigned integer).
    ///
    /// Emits a warn on non-Linux, unless the inbound supplies uids:
    /// `rules/common/uid.go` — UID rules are meaningless outside Linux.
    /// Class B per ADR-0002.
    ///
    /// upstream: `rules/common/uid.go`
    pub fn new(uid: &str, adapter: &str) -> Result<Self, String> {
        let value: u32 = uid
            .trim()
            .parse()
            .map_err(|e| format!("invalid UID value '{}': {}", uid.trim(), e))?;

        if !meow_common::process_lookup::uid_info_available() {
            tracing::warn!(
                uid = value,
                "UID rule is Linux-only; this rule will never match on the current platform \
                 (Class B per ADR-0002 — upstream: rules/common/uid.go)"
            );
        }

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
        meow_common::process_lookup::uid_info_available() && metadata.uid == Some(self.uid)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }

    fn should_find_process(&self) -> bool {
        // UID matching is Linux-only by policy (the parse-time Class B
        // warn); off Linux the rule is dead, so demanding a process-table
        // walk per connection would be pure cost (#625).
        cfg!(target_os = "linux")
    }

    fn never_matches(&self) -> bool {
        // `match_metadata` is a constant `false` off Linux unless the
        // inbound supplies `uid` — the rule is provably dead there even
        // though e.g. the macOS lookup does populate `metadata.uid`
        // (deadness is a policy choice, Class B per ADR-0002).
        !meow_common::process_lookup::uid_info_available()
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

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn uid_reports_dead_and_demands_nothing_non_linux() {
        // A provably-dead rule must not pin process-lookup demand (#625).
        let r = UidRule::new("1000", "DIRECT").unwrap();
        assert!(r.never_matches());
        assert!(!r.should_find_process());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uid_live_and_demands_process_linux() {
        let r = UidRule::new("1000", "DIRECT").unwrap();
        assert!(!r.never_matches());
        assert!(r.should_find_process());
    }
}
