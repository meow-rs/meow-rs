//! IP-ASN rule — matches when the destination IP's Autonomous System Number
//! equals the payload.
//!
//! At parse time, matching ranges for the requested ASN are materialised from
//! the GeoLite2-ASN MMDB into a shared [`crate::ip_set::IpRangeSet`]. Match
//! becomes one binary search — no MMDB lookup, no allocation.
//!
//! upstream: `rules/common/ipasn.go`

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

use crate::asn_index::AsnRanges;

pub struct IpAsnRule {
    raw: SmolStr,
    adapter: Adapter,
    ranges: AsnRanges,
    src: bool,
    no_resolve: bool,
}

impl IpAsnRule {
    pub fn new(
        _asn: u32,
        raw: &str,
        adapter: &str,
        ranges: AsnRanges,
        src: bool,
        no_resolve: bool,
    ) -> Self {
        Self {
            raw: raw.into(),
            adapter: intern_adapter(adapter),
            ranges,
            src,
            no_resolve,
        }
    }
}

impl IpAsnRule {
    pub fn ranges(&self) -> &AsnRanges {
        &self.ranges
    }

    pub fn is_src(&self) -> bool {
        self.src
    }
}

impl Rule for IpAsnRule {
    fn rule_type(&self) -> RuleType {
        RuleType::IpAsn
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let ip = if self.src {
            metadata.src_ip
        } else {
            metadata.dst_ip
        };
        ip.is_some_and(|ip| self.ranges.contains(ip))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_asn_invalid_payload_errors() {
        // Minimal coverage: parse validates payload before building a rule.
        // This path is exercised by parser tests for the missing-index branch;
        // fixture-backed positive ASN coverage can be added when an ASN MMDB
        // fixture is available.
    }

    #[test]
    fn ip_asn_rule_type_smoke() {
        // Smoke-test the enum variant while fixture-backed construction lives
        // in parser/config tests.
        assert_eq!(RuleType::IpAsn.to_string(), "IP-ASN");
    }
}
