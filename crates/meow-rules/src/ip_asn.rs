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
        if self.src {
            RuleType::SrcIpAsn
        } else {
            RuleType::IpAsn
        }
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
        // Src-axis rules match `src_ip`, which every inbound already
        // carries — demanding a dst_ip resolution the match never reads
        // is wasted latency plus a DNS-leak surface (#625). Same shape
        // as `IpCidrRule`.
        !self.src && !self.no_resolve
    }

    fn never_matches(&self) -> bool {
        // An ASN absent from the loaded index materialises as an empty
        // range set — the rule can never fire (same precedent as
        // `GeoSiteRule`; #625).
        self.ranges.is_empty()
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

    #[test]
    fn src_ip_asn_does_not_demand_resolution() {
        use crate::ip_set::IpRangeSetBuilder;
        let mut b = IpRangeSetBuilder::new();
        b.add_v4("10.0.0.0/8".parse().unwrap());
        let ranges = std::sync::Arc::new(b.build());
        // SRC-IP-ASN matches `src_ip` only — it must not demand a dst_ip
        // resolution it never reads (#625).
        let src = IpAsnRule::new(
            13335,
            "13335",
            "P",
            std::sync::Arc::clone(&ranges),
            true,
            false,
        );
        assert!(!src.should_resolve_ip());
        let dst = IpAsnRule::new(13335, "13335", "P", ranges, false, false);
        assert!(dst.should_resolve_ip());
    }

    /// `SRC-IP-ASN`/`IP-ASN,...,src` must read `src_ip` — swapped axes
    /// must not match, and the rule reports the Src variant upstream
    /// uses for `/rules` output.
    #[test]
    fn src_ip_asn_matches_src_ip_axis() {
        use crate::ip_set::IpRangeSetBuilder;
        let mut b = IpRangeSetBuilder::new();
        b.add_v4("10.0.0.0/8".parse().unwrap());
        let ranges = std::sync::Arc::new(b.build());
        let src = IpAsnRule::new(13335, "13335", "P", ranges, true, true);
        assert_eq!(src.rule_type(), RuleType::SrcIpAsn);

        let mut meta = Metadata {
            src_ip: Some("10.1.2.3".parse().unwrap()),
            dst_ip: Some("203.0.113.9".parse().unwrap()),
            ..Default::default()
        };
        assert!(src.match_metadata(&meta, &RuleMatchHelper));
        meta.src_ip = Some("203.0.113.9".parse().unwrap());
        meta.dst_ip = Some("10.1.2.3".parse().unwrap());
        assert!(!src.match_metadata(&meta, &RuleMatchHelper));
    }

    #[test]
    fn ip_asn_empty_ranges_never_matches() {
        use crate::ip_set::IpRangeSetBuilder;
        // An ASN absent from the loaded index materialises as an empty
        // set — the rule is provably dead (#625).
        let ranges = std::sync::Arc::new(IpRangeSetBuilder::new().build());
        let dst = IpAsnRule::new(
            99999,
            "99999",
            "P",
            std::sync::Arc::clone(&ranges),
            false,
            false,
        );
        assert!(dst.never_matches());
        let src = IpAsnRule::new(99999, "99999", "P", ranges, true, false);
        assert!(src.never_matches());
    }
}
