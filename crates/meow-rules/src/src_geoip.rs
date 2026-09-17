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

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}
