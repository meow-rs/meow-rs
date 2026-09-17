//! IN-PORT rule — matches on the inbound listener port (`Metadata.in_port`).
//!
//! Payload: a port number, a `lo-hi` range, or a comma/slash-separated list.
//!
//! upstream: `rules/common/inport.go`

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct InPortRule {
    /// Inclusive `(lo, hi)` pairs; a single port is `(p, p)`.
    ranges: Box<[(u16, u16)]>,
    raw: SmolStr,
    adapter: Adapter,
}

impl InPortRule {
    /// Parse `ports` as `"8080"`, `"1000-2000"`, or a comma/slash list.
    ///
    /// upstream: `rules/common/inport.go::NewInPort`
    pub fn new(ports: &str, adapter: &str) -> Result<Self, String> {
        let mut ranges = Vec::new();
        for part in ports.split([',', '/']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((l, r)) = part.split_once('-') {
                let lo = l
                    .trim()
                    .parse::<u16>()
                    .map_err(|e| format!("invalid IN-PORT range start '{}': {}", l.trim(), e))?;
                let hi = r
                    .trim()
                    .parse::<u16>()
                    .map_err(|e| format!("invalid IN-PORT range end '{}': {}", r.trim(), e))?;
                if lo > hi {
                    return Err(format!(
                        "invalid IN-PORT range {lo}-{hi}: start must be <= end"
                    ));
                }
                ranges.push((lo, hi));
            } else {
                let p = part
                    .parse::<u16>()
                    .map_err(|e| format!("invalid IN-PORT '{part}': {e}"))?;
                ranges.push((p, p));
            }
        }

        if ranges.is_empty() {
            return Err("invalid IN-PORT: empty range list".to_string());
        }

        Ok(Self {
            ranges: ranges.into_boxed_slice(),
            raw: ports.into(),
            adapter: intern_adapter(adapter),
        })
    }

    fn matches_port(&self, port: u16) -> bool {
        self.ranges
            .iter()
            .any(|&(lo, hi)| (lo..=hi).contains(&port))
    }
}

impl Rule for InPortRule {
    fn rule_type(&self) -> RuleType {
        RuleType::InPort
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        // in_port == 0 means the listener did not populate the field (legacy path).
        // Do not match — an in_port of 0 is "unknown", not port 0.
        if metadata.in_port == 0 {
            return false;
        }
        self.matches_port(metadata.in_port)
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

    fn meta_with_port(in_port: u16) -> Metadata {
        Metadata {
            in_port,
            ..Default::default()
        }
    }

    #[test]
    fn in_port_match_cases() {
        // (payload, adapter, metadata.in_port, expected match, label)
        let cases = [
            ("8080", "DIRECT", 8080u16, true, "exact match"),
            ("8080", "DIRECT", 8081, false, "exact no match"),
            ("1000-2000", "PROXY", 1000, true, "range lower bound"),
            ("1000-2000", "PROXY", 2000, true, "range upper bound"),
            (
                "1000-2000",
                "PROXY",
                999,
                false,
                "range rejects below lower bound",
            ),
            (
                "1000-2000",
                "PROXY",
                2001,
                false,
                "range rejects above upper bound",
            ),
            // in_port == 0 means the listener did not populate the field
            // ("unknown"), not port 0 — it must never match.
            (
                "8080",
                "DIRECT",
                0,
                false,
                "zero in_port never matches nonzero rule",
            ),
            (
                "80/8080/443/8443",
                "PROXY",
                8080,
                true,
                "slash list matches interior entry",
            ),
            (
                "80/8080/443/8443",
                "PROXY",
                8443,
                true,
                "slash list matches last entry",
            ),
            (
                "80/8080/443/8443",
                "PROXY",
                53,
                false,
                "slash list rejects unlisted port",
            ),
        ];

        let mut failures = Vec::new();
        for (spec, adapter, port, expected, label) in cases {
            let rule = InPortRule::new(spec, adapter).unwrap();
            let got = rule.match_metadata(&meta_with_port(port), &helper());
            if got != expected {
                failures.push(format!(
                    "{label}: IN-PORT '{spec}' vs in_port {port} => {got}, expected {expected}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "IN-PORT match mismatches: {failures:#?}"
        );
    }

    #[test]
    fn in_port_invalid_payload_errors() {
        // NOT panic — parse error returned.
        // upstream: rules/common/inport.go::NewInPort
        assert!(InPortRule::new("abc", "DIRECT").is_err());
    }

    #[test]
    fn in_port_inverted_range_errors() {
        assert!(InPortRule::new("2000-1000", "DIRECT").is_err());
    }
}
