//! `lan-allowed-ips` / `lan-disallowed-ips` — the top-level inbound CIDR
//! ACL the mixed/HTTP/SOCKS TCP accept loops apply to every accepted
//! connection (mihomo's `adapter/inbound/ipfilter` —
//! `IsRemoteAddrDisAllowed`).
//!
//! The ACL is a startup snapshot: listeners hold a shared immutable copy
//! resolved once at config load. A remote is admitted when it matches at
//! least one allow CIDR and no deny CIDR; there are no implicit
//! exceptions — loopback and RFC 1918 are denied whenever the resolved
//! lists do not cover them.

use ipnet::IpNet;
use std::net::IpAddr;

/// Immutable allow/deny CIDR pair resolved at config load.
///
/// `None`-equivalent defaults are produced by the config resolver
/// (`meow_config::resolve_lan_acl`): an omitted allow list becomes
/// `0.0.0.0/0` + `::/0`, so an *explicit* `lan-allowed-ips: []` stays
/// distinguishable and admits nobody.
#[derive(Debug, Clone, Default)]
pub struct LanAcl {
    /// CIDRs a remote must match at least one of.
    allowed: Vec<IpNet>,
    /// CIDRs a remote must not match.
    denied: Vec<IpNet>,
}

impl LanAcl {
    pub fn new(allowed: Vec<IpNet>, denied: Vec<IpNet>) -> Self {
        Self { allowed, denied }
    }

    /// The accept-loop admission check: require an allow match AND no
    /// deny match. IPv4-mapped IPv6 peers (`::ffff:a.b.c.d`) are unmapped
    /// before lookup so a v4 CIDR covers them, mirroring upstream's
    /// `Unmap` in `IsRemoteAddrDisAllowed`.
    pub fn allows(&self, src_ip: IpAddr) -> bool {
        let ip = src_ip.to_canonical();
        self.allowed.iter().any(|n| n.contains(&ip)) && !self.denied.iter().any(|n| n.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(allowed: &[&str], denied: &[&str]) -> LanAcl {
        LanAcl::new(
            allowed.iter().map(|s| s.parse().unwrap()).collect(),
            denied.iter().map(|s| s.parse().unwrap()).collect(),
        )
    }

    #[test]
    fn omitted_allow_defaults_admit_everything() {
        let a = acl(&["0.0.0.0/0", "::/0"], &[]);
        assert!(a.allows("127.0.0.1".parse().unwrap()));
        assert!(a.allows("10.0.0.5".parse().unwrap()));
        assert!(a.allows("::1".parse().unwrap()));
        assert!(a.allows("fe80::1".parse().unwrap()));
    }

    #[test]
    fn empty_allow_list_admits_nobody() {
        let a = acl(&[], &[]);
        assert!(!a.allows("127.0.0.1".parse().unwrap()));
        assert!(!a.allows("::1".parse().unwrap()));
    }

    #[test]
    fn deny_wins_over_allow_overlap() {
        let a = acl(&["10.0.0.0/8"], &["10.1.2.0/24"]);
        assert!(a.allows("10.2.0.1".parse().unwrap()));
        assert!(!a.allows("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn explicit_lists_have_no_loopback_exception() {
        let a = acl(&["192.168.0.0/16"], &[]);
        assert!(!a.allows("127.0.0.1".parse().unwrap()));
        assert!(a.allows("192.168.1.9".parse().unwrap()));
    }

    #[test]
    fn mapped_v4_peer_uses_v4_lists() {
        let a = acl(&["10.0.0.0/8"], &[]);
        let mapped: IpAddr = "::ffff:10.2.3.4".parse().unwrap();
        assert!(a.allows(mapped));
        let mapped_denied: IpAddr = "::ffff:172.16.0.9".parse().unwrap();
        assert!(!a.allows(mapped_denied));
    }

    #[test]
    fn deny_only_blocks_matching_source() {
        let a = acl(&["0.0.0.0/0", "::/0"], &["169.254.0.0/16"]);
        assert!(a.allows("192.0.2.1".parse().unwrap()));
        assert!(!a.allows("169.254.1.1".parse().unwrap()));
    }
}
