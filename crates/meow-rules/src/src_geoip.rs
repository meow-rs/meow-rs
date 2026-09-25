//! SRC-GEOIP rule — GeoIP lookup on the connection's **source** IP.
//!
//! Identical to [`crate::geoip::GeoIpRule`] except it reads `Metadata.src_ip`
//! instead of `dst_ip`. Like `GEOIP`, the country's CIDR list is materialised
//! into a shared [`crate::ip_set::IpRangeSet`] at parse time via
//! [`crate::country_index::CountryIndex`] — match is one binary search, no
//! MMDB access on the hot path.
//!
//! `no-resolve` is not applicable: the source IP is always an IP address
//! (TProxy captures the real client IP; no hostname resolution needed).
//!
//! upstream: `rules/common/geoip.go::Rule` (`isSource` flag)

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

use crate::country_index::CountryRanges;

pub struct SrcGeoIpRule {
    country: SmolStr,
    adapter: Adapter,
    ranges: CountryRanges,
}

impl SrcGeoIpRule {
    pub fn new(country: &str, adapter: &str, ranges: CountryRanges) -> Self {
        Self {
            country: country.to_uppercase().into(),
            adapter: intern_adapter(adapter),
            ranges,
        }
    }
}

impl SrcGeoIpRule {
    pub fn ranges(&self) -> &CountryRanges {
        &self.ranges
    }
}

impl Rule for SrcGeoIpRule {
    fn rule_type(&self) -> RuleType {
        RuleType::SrcGeoIp
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        metadata.src_ip.is_some_and(|ip| self.ranges.contains(ip))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.country
    }

    fn never_matches(&self) -> bool {
        // A payload absent from the loaded index materialises as an
        // empty range set — the rule can never fire (same precedent as
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
    use crate::ip_set::IpRangeSetBuilder;
    use std::net::IpAddr;
    use std::sync::Arc;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    #[test]
    fn src_geoip_empty_ranges_never_matches() {
        // A country code absent from the loaded index materialises as an
        // empty set — the rule is provably dead (#625).
        let r = SrcGeoIpRule::new("ZZ", "P", Arc::new(IpRangeSetBuilder::new().build()));
        assert!(r.never_matches());
        let meta = Metadata {
            src_ip: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            ..Default::default()
        };
        assert!(!r.match_metadata(&meta, &helper()));
    }

    /// `SRC-GEOIP`/`GEOIP,...,src` must match on `src_ip` — the same
    /// addresses on the opposite axes must not match.
    #[test]
    fn src_geoip_matches_src_ip_axis() {
        let mut b = IpRangeSetBuilder::new();
        b.add_v4("10.0.0.0/8".parse().unwrap());
        let r = SrcGeoIpRule::new("CN", "P", Arc::new(b.build()));

        let mut meta = Metadata {
            src_ip: Some("10.1.2.3".parse::<IpAddr>().unwrap()),
            dst_ip: Some("203.0.113.9".parse::<IpAddr>().unwrap()),
            ..Default::default()
        };
        assert!(r.match_metadata(&meta, &helper()));
        meta.src_ip = Some("203.0.113.9".parse::<IpAddr>().unwrap());
        meta.dst_ip = Some("10.1.2.3".parse::<IpAddr>().unwrap());
        assert!(!r.match_metadata(&meta, &helper()));
    }
}
