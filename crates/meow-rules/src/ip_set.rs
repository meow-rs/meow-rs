//! Compact, immutable IP range sets for GEOIP / IP-ASN / ipcidr rule-sets.
//!
//! A set is two sorted, disjoint, coalesced interval lists (IPv4 and IPv6),
//! each stored as parallel `starts` / `ends` arrays. Membership is one
//! binary search over `starts` (4-byte stride for IPv4) plus one bounds
//! check — no pointer chasing. Memory is 8 bytes per IPv4 interval and
//! 32 bytes per IPv6 interval after coalescing, versus one 16-byte heap
//! node per prefix *bit* for the Patricia trie this replaces.
//!
//! Adjacent and overlapping networks merge into one interval at build time,
//! which preserves membership exactly (a rule-set matches an address iff
//! some entry contains it) while typically shrinking country tables by a
//! large factor.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Sorted, disjoint inclusive intervals over one address family.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Intervals<A: Copy + Ord> {
    starts: Box<[A]>,
    ends: Box<[A]>,
}

impl<A: Copy + Ord> Intervals<A> {
    #[inline]
    fn contains(&self, addr: A) -> bool {
        // Index of the last interval whose start is <= addr.
        let idx = self.starts.partition_point(|&start| start <= addr);
        idx > 0 && addr <= self.ends[idx - 1]
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    fn len(&self) -> usize {
        self.starts.len()
    }

    /// Coalesce an unordered list of inclusive intervals.
    fn from_unsorted(mut ranges: Vec<(A, A)>, next: impl Fn(A) -> Option<A>) -> Self {
        ranges.sort_unstable();
        let mut starts: Vec<A> = Vec::new();
        let mut ends: Vec<A> = Vec::new();
        for (start, end) in ranges {
            if let Some(last_end) = ends.last_mut() {
                // Overlapping or adjacent: extend the previous interval.
                let touches = start <= *last_end || next(*last_end) == Some(start);
                if touches {
                    if end > *last_end {
                        *last_end = end;
                    }
                    continue;
                }
            }
            starts.push(start);
            ends.push(end);
        }
        Self {
            starts: starts.into_boxed_slice(),
            ends: ends.into_boxed_slice(),
        }
    }
}

/// Immutable IPv4 + IPv6 range set. Build with [`IpRangeSetBuilder`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpRangeSet {
    v4: Intervals<u32>,
    v6: Intervals<u128>,
}

impl IpRangeSet {
    /// Build directly from networks; convenience over the builder.
    pub fn from_nets<I: IntoIterator<Item = IpNet>>(nets: I) -> Self {
        let mut builder = IpRangeSetBuilder::default();
        for net in nets {
            builder.add(net);
        }
        builder.build()
    }

    #[inline]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.contains_v4(v4),
            IpAddr::V6(v6) => self.contains_v6(v6),
        }
    }

    #[inline]
    pub fn contains_v4(&self, addr: Ipv4Addr) -> bool {
        self.v4.contains(u32::from(addr))
    }

    #[inline]
    pub fn contains_v6(&self, addr: Ipv6Addr) -> bool {
        self.v6.contains(u128::from(addr))
    }

    /// True iff every address of `net` is in the set.
    pub fn covers(&self, net: IpNet) -> bool {
        match net {
            IpNet::V4(v4) => {
                let (start, end) = v4_bounds(v4);
                let idx = self.v4.starts.partition_point(|&s| s <= start);
                idx > 0 && end <= self.v4.ends[idx - 1]
            }
            IpNet::V6(v6) => {
                let (start, end) = v6_bounds(v6);
                let idx = self.v6.starts.partition_point(|&s| s <= start);
                idx > 0 && end <= self.v6.ends[idx - 1]
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn has_v4(&self) -> bool {
        !self.v4.is_empty()
    }

    pub fn has_v6(&self) -> bool {
        !self.v6.is_empty()
    }

    /// Number of coalesced intervals (IPv4, IPv6).
    pub fn interval_counts(&self) -> (usize, usize) {
        (self.v4.len(), self.v6.len())
    }
}

/// Accumulates networks, then coalesces them into an [`IpRangeSet`].
#[derive(Debug, Default)]
pub struct IpRangeSetBuilder {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpRangeSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, net: IpNet) {
        match net {
            IpNet::V4(v4) => self.add_v4(v4),
            IpNet::V6(v6) => self.add_v6(v6),
        }
    }

    pub fn add_v4(&mut self, net: Ipv4Net) {
        let (start, end) = v4_bounds(net);
        push_merging(&mut self.v4, start, end, |a| a.checked_add(1));
    }

    pub fn add_v6(&mut self, net: Ipv6Net) {
        let (start, end) = v6_bounds(net);
        push_merging(&mut self.v6, start, end, |a| a.checked_add(1));
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn build(self) -> IpRangeSet {
        IpRangeSet {
            v4: Intervals::from_unsorted(self.v4, |a| a.checked_add(1)),
            v6: Intervals::from_unsorted(self.v6, |a| a.checked_add(1)),
        }
    }
}

/// Append an interval, folding it into the previous one when it overlaps
/// or touches it. Sources such as an MMDB walk emit networks in address
/// order, so this keeps the pending list at its coalesced size instead of
/// buffering every raw network until `build` (the walk of one large
/// country otherwise peaks at several MiB of `u128` pairs). Unordered input
/// simply falls through to `build`'s sort-and-merge.
#[inline]
fn push_merging<A: Copy + Ord>(
    pending: &mut Vec<(A, A)>,
    start: A,
    end: A,
    next: impl Fn(A) -> Option<A>,
) {
    if let Some(last) = pending.last_mut() {
        let touches = start >= last.0 && (start <= last.1 || next(last.1) == Some(start));
        if touches {
            if end > last.1 {
                last.1 = end;
            }
            return;
        }
    }
    pending.push((start, end));
}

#[inline]
fn v4_bounds(net: Ipv4Net) -> (u32, u32) {
    (u32::from(net.network()), u32::from(net.broadcast()))
}

#[inline]
fn v6_bounds(net: Ipv6Net) -> (u128, u128) {
    (u128::from(net.network()), u128::from(net.broadcast()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(entries: &[&str]) -> IpRangeSet {
        IpRangeSet::from_nets(entries.iter().map(|e| e.parse().unwrap()))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_set_contains_nothing() {
        let s = IpRangeSet::default();
        assert!(s.is_empty());
        assert!(!s.contains(ip("0.0.0.0")));
        assert!(!s.contains(ip("255.255.255.255")));
        assert!(!s.contains(ip("::")));
    }

    #[test]
    fn membership_matches_prefix_semantics() {
        let s = set(&["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32", "fd00::/8"]);
        assert!(s.contains(ip("10.1.2.3")));
        assert!(s.contains(ip("10.0.0.0")));
        assert!(s.contains(ip("10.255.255.255")));
        assert!(!s.contains(ip("11.0.0.0")));
        assert!(!s.contains(ip("9.255.255.255")));
        assert!(s.contains(ip("192.168.1.77")));
        assert!(!s.contains(ip("192.168.2.1")));
        assert!(s.contains(ip("2001:db8::1")));
        assert!(!s.contains(ip("2001:db9::1")));
        assert!(s.contains(ip("fd12::1")));
        assert!(!s.contains(ip("fe80::1")));
    }

    #[test]
    fn adjacent_and_nested_networks_coalesce() {
        let s = set(&[
            "10.0.0.0/24",
            "10.0.1.0/24",
            "10.0.0.128/25", // nested
            "10.0.2.0/23",   // adjacent to the /23 formed above
            "10.0.8.0/24",   // gap
        ]);
        assert_eq!(s.interval_counts(), (2, 0));
        assert!(s.contains(ip("10.0.3.255")));
        assert!(!s.contains(ip("10.0.4.0")));
        assert!(s.contains(ip("10.0.8.1")));
    }

    #[test]
    fn covers_requires_full_containment() {
        let s = set(&["10.0.0.0/9", "10.128.0.0/9", "2001:db8::/48"]);
        assert!(s.covers("10.0.0.0/8".parse().unwrap()));
        assert!(s.covers("10.5.0.0/16".parse().unwrap()));
        assert!(!s.covers("10.0.0.0/7".parse().unwrap()));
        assert!(!s.covers("11.0.0.0/8".parse().unwrap()));
        assert!(s.covers("2001:db8::/64".parse().unwrap()));
        assert!(!s.covers("2001:db8::/32".parse().unwrap()));
    }

    #[test]
    fn full_address_space_edges() {
        let s = set(&["0.0.0.0/0", "::/0"]);
        assert_eq!(s.interval_counts(), (1, 1));
        assert!(s.contains(ip("0.0.0.0")));
        assert!(s.contains(ip("255.255.255.255")));
        assert!(s.contains(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
        let top = set(&["255.255.255.0/24", "255.255.254.0/24"]);
        assert_eq!(top.interval_counts(), (1, 0));
        assert!(top.contains(ip("255.255.255.255")));
    }

    #[test]
    fn coalescing_preserves_membership_exhaustively() {
        // Every /28 across a small window, inserted in shuffled order with
        // duplicates: membership of each address must equal the naive check.
        let mut nets: Vec<Ipv4Net> = Vec::new();
        let mut seed = 0x1234_5678u32;
        for i in 0..64u32 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            if !seed.is_multiple_of(3) {
                let base = 0x0A00_0000 + i * 16;
                nets.push(Ipv4Net::new(Ipv4Addr::from(base), 28).unwrap());
                nets.push(Ipv4Net::new(Ipv4Addr::from(base), 28).unwrap());
            }
        }
        let s = IpRangeSet::from_nets(nets.iter().map(|n| IpNet::V4(*n)));
        for addr in 0x0A00_0000u32 - 8..0x0A00_0000 + 64 * 16 + 8 {
            let a = Ipv4Addr::from(addr);
            let naive = nets.iter().any(|n| n.contains(&a));
            assert_eq!(s.contains(IpAddr::V4(a)), naive, "addr {a}");
        }
    }
}
