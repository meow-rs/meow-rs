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

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}
