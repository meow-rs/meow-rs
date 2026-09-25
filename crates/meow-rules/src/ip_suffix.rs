//! IP-SUFFIX rule — suffix match on the binary representation of the
//! destination IP address.
//!
//! Payload format: `addr/prefix_len`.  Unlike IP-CIDR which masks the
//! **high** `prefix_len` bits, IP-SUFFIX masks the **low** `prefix_len`
//! bits:
//!
//! ```text
//! mask  = (1 << prefix_len) - 1     // bitmask over the low prefix_len bits
//! match = (ip & mask) == (payload & mask)
//! ```
//!
//! upstream: `rules/common/ipcidr.go` — IP-SUFFIX branch.

use ipnet::IpNet;
use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;
use std::net::IpAddr;

pub struct IpSuffixRule {
    payload_raw: SmolStr,
    adapter: Adapter,
    family: Family,
    src: bool,
    no_resolve: bool,
}

#[derive(Debug, Clone, Copy)]
enum Family {
    V4 { suffix: u32, mask: u32 },
    V6 { suffix: u128, mask: u128 },
}

/// The compiled suffix predicate, detached from the rule so the rule IR can
/// evaluate it without virtual dispatch. `Copy`; matching allocates nothing.
#[derive(Debug, Clone, Copy)]
pub struct IpSuffixMatcher {
    family: Family,
}

impl IpSuffixMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match (self.family, ip) {
            (Family::V4 { suffix, mask }, IpAddr::V4(v4)) => {
                let ip_u32 = u32::from_be_bytes(v4.octets());
                (ip_u32 & mask) == suffix
            }
            (Family::V6 { suffix, mask }, IpAddr::V6(v6)) => {
                let ip_u128 = u128::from_be_bytes(v6.octets());
                (ip_u128 & mask) == suffix
            }
            // Cross-family comparisons never match — not a panic.
            _ => false,
        }
    }
}

impl IpSuffixRule {
    /// Parse `addr/prefix_len` — same shape as IP-CIDR, distinct semantics.
    ///
    /// Validates `prefix_len ≤ 32` for IPv4 and `≤ 128` for IPv6.
    ///
    /// upstream: `rules/common/ipcidr.go`
    pub fn new(payload: &str, adapter: &str, src: bool, no_resolve: bool) -> Result<Self, String> {
        let net: IpNet = payload.parse().map_err(|e| {
            format!(
                "invalid IP-SUFFIX: expected addr/prefix_len where prefix_len ≤ 32 (IPv4) or \
                 128 (IPv6): {payload} ({e})"
            )
        })?;
        let family = match net {
            IpNet::V4(v4) => {
                let prefix = v4.prefix_len();
                if prefix > 32 {
                    return Err(format!(
                        "invalid IP-SUFFIX: IPv4 prefix_len {prefix} exceeds 32"
                    ));
                }
                // Low `prefix` bits form the match mask.
                let mask: u32 = if prefix == 0 {
                    0
                } else if prefix >= 32 {
                    u32::MAX
                } else {
                    (1u32 << prefix) - 1
                };
                let addr_u32 = u32::from_be_bytes(v4.addr().octets()) & mask;
                Family::V4 {
                    suffix: addr_u32,
                    mask,
                }
            }
            IpNet::V6(v6) => {
                let prefix = v6.prefix_len();
                if prefix > 128 {
                    return Err(format!(
                        "invalid IP-SUFFIX: IPv6 prefix_len {prefix} exceeds 128"
                    ));
                }
                let mask: u128 = if prefix == 0 {
                    0
                } else if prefix >= 128 {
                    u128::MAX
                } else {
                    (1u128 << prefix) - 1
                };
                let addr_u128 = u128::from_be_bytes(v6.addr().octets()) & mask;
                Family::V6 {
                    suffix: addr_u128,
                    mask,
                }
            }
        };
        Ok(Self {
            payload_raw: payload.into(),
            adapter: intern_adapter(adapter),
            family,
            src,
            no_resolve,
        })
    }

    fn matches_ip(&self, ip: IpAddr) -> bool {
        self.matcher().matches(ip)
    }

    pub fn matcher(&self) -> IpSuffixMatcher {
        IpSuffixMatcher {
            family: self.family,
        }
    }

    pub fn is_src(&self) -> bool {
        self.src
    }
}

impl Rule for IpSuffixRule {
    fn rule_type(&self) -> RuleType {
        if self.src {
            RuleType::SrcIpSuffix
        } else {
            RuleType::IpSuffix
        }
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let ip = if self.src {
            metadata.src_ip
        } else {
            metadata.dst_ip
        };
        match ip {
            Some(ip) => self.matches_ip(ip),
            None => false,
        }
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload_raw
    }

    fn should_resolve_ip(&self) -> bool {
        // Src-axis rules match `src_ip`, which every inbound already
        // carries — demanding a dst_ip resolution the match never reads
        // is wasted latency plus a DNS-leak surface (#625). Same shape
        // as `IpCidrRule`.
        !self.src && !self.no_resolve
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_dst(ip: &str) -> Metadata {
        Metadata {
            dst_ip: Some(IpAddr::from_str(ip).unwrap()),
            ..Default::default()
        }
    }

    /// Upstream: `rules/common/ipcidr.go` — IP-SUFFIX applies the mask to the
    /// **low** bits. Cross-family comparisons must not panic; they return false.
    #[test]
    fn ip_suffix_matches_ip_cases() {
        // (label, payload, candidate ip, expected)
        let cases: &[(&str, &str, &str, bool)] = &[
            // /32 — exact IPv4 match.
            ("ipv4 /32 exact hit", "8.8.8.8/32", "8.8.8.8", true),
            ("ipv4 /32 exact miss", "8.8.8.8/32", "8.8.8.9", false),
            // /8 — low byte must equal 0x01 → matches any a.b.c.1.
            ("ipv4 /8 low byte hit a", "0.0.0.1/8", "10.20.30.1", true),
            ("ipv4 /8 low byte hit b", "0.0.0.1/8", "192.168.0.1", true),
            ("ipv4 /8 low byte miss", "0.0.0.1/8", "10.20.30.2", false),
            // /24 — low 24 bits must equal 0x010203 (0.1.2.3) → matches x.1.2.3.
            ("ipv4 /24 hit a", "0.1.2.3/24", "10.1.2.3", true),
            ("ipv4 /24 hit b", "0.1.2.3/24", "200.1.2.3", true),
            ("ipv4 /24 miss", "0.1.2.3/24", "10.1.2.4", false),
            // /64 — low 64 bits must equal ::1.
            ("ipv6 /64 low half hit a", "::1/64", "2001:db8::1", true),
            ("ipv6 /64 low half hit b", "::1/64", "fd00::1", true),
            ("ipv6 /64 low half miss", "::1/64", "2001:db8::2", false),
            // /128 — exact IPv6 match.
            ("ipv6 /128 hit", "2001:db8::1/128", "2001:db8::1", true),
            ("ipv6 /128 miss", "2001:db8::1/128", "2001:db8::2", false),
            // Cross-family: never matches, never panics.
            ("ipv4 rule vs ipv6 addr", "0.0.0.1/8", "::1", false),
            ("ipv6 rule vs ipv4 addr", "::1/8", "1.2.3.4", false),
        ];

        // Every case runs; failures are collected so one bad row does not hide
        // the rest.
        let mut failures = Vec::new();
        for (label, payload, ip, expected) in cases {
            let rule = IpSuffixRule::new(payload, "PROXY", false, true).unwrap();
            let got = rule.matches_ip(IpAddr::from_str(ip).unwrap());
            if got != *expected {
                failures.push(format!(
                    "{label}: IP-SUFFIX {payload} vs {ip} = {got}, expected {expected}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "IP-SUFFIX match mismatches:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn ip_suffix_invalid_payload_errors() {
        match IpSuffixRule::new("not-an-ip", "PROXY", false, true) {
            Ok(_) => panic!("expected parse error"),
            Err(err) => assert!(err.contains("IP-SUFFIX"), "unexpected error: {err}"),
        }
    }

    #[test]
    fn ip_suffix_invalid_prefix_len_errors() {
        // ipnet rejects /33 on IPv4 itself, but make sure the error path returns Err.
        assert!(IpSuffixRule::new("1.2.3.4/33", "PROXY", false, true).is_err());
        assert!(IpSuffixRule::new("::1/129", "PROXY", false, true).is_err());
    }

    #[test]
    fn ip_suffix_rule_type_and_payload() {
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        assert_eq!(r.rule_type(), RuleType::IpSuffix);
        assert_eq!(r.payload(), "0.0.0.1/8");
        assert_eq!(r.adapter(), "PROXY");
    }

    #[test]
    fn ip_suffix_no_dst_ip_no_match() {
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        let m = Metadata::default();
        assert!(!r.match_metadata(&m, &helper()));
    }

    #[test]
    fn ip_suffix_match_metadata_uses_dst() {
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        assert!(r.match_metadata(&meta_dst("1.2.3.1"), &helper()));
        assert!(!r.match_metadata(&meta_dst("1.2.3.2"), &helper()));
    }

    #[test]
    fn ip_suffix_should_resolve_flag() {
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, false).unwrap();
        assert!(r.should_resolve_ip());
        let r2 = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        assert!(!r2.should_resolve_ip());
    }

    #[test]
    fn src_ip_suffix_does_not_demand_resolution() {
        // SRC-IP-SUFFIX matches `src_ip` only — without `no-resolve` it
        // must not demand a dst_ip resolution it never reads (#625).
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", true, false).unwrap();
        assert!(!r.should_resolve_ip());
        let r2 = IpSuffixRule::new("0.0.0.1/8", "PROXY", true, true).unwrap();
        assert!(!r2.should_resolve_ip());
    }
}
