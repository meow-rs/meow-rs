//! DSCP rule — matches on `Metadata.dscp` (IP Differentiated Services Code Point).
//!
//! Payload: integer 0–63.
//!
//! Match semantics: `None` (non-TProxy listener) never matches, including
//! `DSCP,0`.  This prevents the previous silent misroute where every
//! HTTP/SOCKS5 connection matched `DSCP,0` due to the old `u8` default of 0.
//! Class A fix per ADR-0002.
//!
//! upstream: `rules/common/dscp.go`

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct DscpRule {
    value: u8,
    raw: SmolStr,
    adapter: Adapter,
}

impl DscpRule {
    /// Parse `dscp` as integer 0–63.
    ///
    /// upstream: `rules/common/dscp.go`
    pub fn new(dscp: &str, adapter: &str) -> Result<Self, String> {
        let value: u8 = dscp
            .trim()
            .parse()
            .map_err(|e| format!("invalid DSCP value '{}': {}", dscp.trim(), e))?;
        if value > 63 {
            return Err(format!("invalid DSCP value {value}: must be 0–63 (6 bits)"));
        }
        Ok(Self {
            value,
            raw: dscp.into(),
            adapter: intern_adapter(adapter),
        })
    }
}

impl Rule for DscpRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Dscp
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        // None (HTTP/SOCKS5/Mixed listeners) never matches any DSCP rule.
        // upstream: rules/common/dscp.go — same semantics; DSCP is only set on
        // TProxy connections where IP_RECVTOS cmsg is available.
        metadata.dscp == Some(self.value)
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

    fn meta_with_dscp(dscp: Option<u8>) -> Metadata {
        Metadata {
            dscp,
            ..Default::default()
        }
    }

    #[test]
    fn dscp_match_cases() {
        // (label, rule payload, metadata dscp, expected match)
        let cases: &[(&str, &str, Option<u8>, bool)] = &[
            ("EF (46) matches dscp 46", "46", Some(46), true),
            ("rule 46 must not match dscp 0", "46", Some(0), false),
        ];

        let mut failures = Vec::new();
        for &(label, payload, dscp, expected) in cases {
            let r = DscpRule::new(payload, "PROXY").unwrap();
            let got = r.match_metadata(&meta_with_dscp(dscp), &helper());
            if got != expected {
                failures.push(format!(
                    "{label}: DSCP,{payload} vs metadata dscp={dscp:?} — expected {expected}, got {got}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "DSCP match mismatches:\n{}",
            failures.join("\n")
        );
    }

    /// `None` (HTTP/SOCKS5/Mixed) must never match any DSCP rule, including 0.
    /// Class A per ADR-0002: old `u8` default caused `DSCP,0` to match every
    /// HTTP/SOCKS5 connection silently.
    #[test]
    fn dscp_none_metadata_never_matches() {
        let r = DscpRule::new("0", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_dscp(None), &helper()));
    }

    #[test]
    fn dscp_rule_never_matches_unset_metadata() {
        // Same as above — belt-and-braces: DSCP,0 must not fire on non-TProxy.
        let r = DscpRule::new("0", "DIRECT").unwrap();
        let meta = Metadata::default(); // dscp: None
        assert!(!r.match_metadata(&meta, &helper()));
    }

    #[test]
    fn dscp_validity_cases() {
        // (payload, expect_ok)
        let cases: &[(&str, bool)] = &[
            ("64", false),  // out of range (> 63)
            ("255", false), // out of range (> 63)
            ("abc", false), // not an integer
            ("63", true),   // boundary: max valid 6-bit value
        ];
        let mut failures = Vec::new();
        for (payload, expect_ok) in cases {
            let got = DscpRule::new(payload, "DIRECT");
            if got.is_ok() != *expect_ok {
                failures.push(format!(
                    "DSCP payload {payload:?}: expected {}, got {:?}",
                    if *expect_ok { "Ok" } else { "Err" },
                    got.as_ref().map(|_| "Ok").map_err(String::as_str),
                ));
            }
        }
        assert!(failures.is_empty(), "DSCP validity failures: {failures:#?}");
    }
}
