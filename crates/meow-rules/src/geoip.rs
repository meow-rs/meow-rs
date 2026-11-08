//! `GEOIP` rule — match on the **destination** IP's country.
//!
//! At parse time the country's CIDR list is materialised into a shared
//! [`crate::ip_set::IpRangeSet`] via [`crate::country_index::CountryIndex`].
//! Match becomes one binary search — no MMDB lookup, no allocation.
//!
//! upstream: `rules/common/geoip.go::Rule` (the `isSource = false` path)

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

use crate::country_index::CountryRanges;

pub struct GeoIpRule {
    country: SmolStr,
    adapter: Adapter,
    no_resolve: bool,
    ranges: CountryRanges,
}

impl GeoIpRule {
    pub fn new(country: &str, adapter: &str, no_resolve: bool, ranges: CountryRanges) -> Self {
        Self {
            country: country.to_uppercase().into(),
            adapter: intern_adapter(adapter),
            no_resolve,
            ranges,
        }
    }
}

impl GeoIpRule {
    pub fn ranges(&self) -> &CountryRanges {
        &self.ranges
    }
}

impl Rule for GeoIpRule {
    fn rule_type(&self) -> RuleType {
        RuleType::GeoIp
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        metadata.dst_ip.is_some_and(|ip| self.ranges.contains(ip))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.country
    }

    /// The country's coalesced IPv4+IPv6 range count — mihomo's
    /// `GetRecodeSize` for `GET /rules`'s `size`.
    fn size(&self) -> i64 {
        let (v4, v6) = self.ranges.interval_counts();
        (v4 + v6) as i64
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
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
    fn geoip_empty_ranges_never_matches() {
        // A country code absent from the loaded index materialises as an
        // empty set — the rule is provably dead and must not pin a
        // resolution demand (#625).
        let r = GeoIpRule::new("ZZ", "P", false, Arc::new(IpRangeSetBuilder::new().build()));
        assert!(r.never_matches());
        let meta = Metadata {
            dst_ip: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            ..Default::default()
        };
        assert!(!r.match_metadata(&meta, &helper()));
    }

    #[test]
    fn geoip_non_empty_ranges_stays_live() {
        let mut b = IpRangeSetBuilder::new();
        b.add_v4("10.0.0.0/8".parse().unwrap());
        let r = GeoIpRule::new("US", "P", false, Arc::new(b.build()));
        assert!(!r.never_matches());
        assert!(r.should_resolve_ip());
    }
}
