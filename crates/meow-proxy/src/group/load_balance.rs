use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, Result,
};
use smol_str::SmolStr;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::{DialFailureTracker, UsageTracker};

#[derive(Debug)]
pub enum LbStrategy {
    RoundRobin,
    ConsistentHashing,
}

pub struct LoadBalanceGroup {
    name: SmolStr,
    static_proxies: Vec<Arc<dyn Proxy>>,
    /// Provider-sourced members (`use:` / `include-all`), each a live
    /// slot whose contents the owning provider swaps on refresh — the
    /// same `ProviderSlot` shape url-test/fallback/selector carry.
    /// Invariant: slots only ever hold leaf adapters (provider payloads
    /// cannot declare groups), so member walks never recurse into another
    /// group's slot guards.
    provider_slots: Vec<ProviderSlot>,
    strategy: LbStrategy,
    counter: AtomicUsize,
    /// Group health-check `url:` (upstream `TestUrl`) — pick-time member
    /// eligibility is `alive_for_url(test_url)`, and the sweep/API read it
    /// via `Proxy::test_url`.
    test_url: String,
    expected_status: String,
    health: ProxyHealth,
    usage: UsageTracker,
    /// mihomo `GroupBase.onDialFailed` escalation: repeated member dial
    /// failures mark the member dead between sweeps — an additional
    /// liveness signal on top of the periodic sweep, which probes provider
    /// members too via `member_proxies()` (issue #543).
    dial_failures: DialFailureTracker,
}

impl LoadBalanceGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>, strategy: LbStrategy) -> Self {
        Self::new_with_providers(name, proxies, strategy, Vec::new())
    }

    pub fn new_with_providers(
        name: &str,
        proxies: Vec<Arc<dyn Proxy>>,
        strategy: LbStrategy,
        slots: Vec<ProviderSlot>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: slots,
            strategy,
            counter: AtomicUsize::new(0),
            test_url: "https://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            health: ProxyHealth::new(),
            usage: UsageTracker::new(),
            dial_failures: DialFailureTracker::new(),
        }
    }

    /// Visit every member in canonical order — static `proxies:` entries
    /// first, then each provider slot under its read guard (the same order
    /// url-test/selector enumerate). `f` returning `false` stops the walk.
    fn for_each_member(&self, mut f: impl FnMut(&Arc<dyn Proxy>) -> bool) {
        for p in &self.static_proxies {
            if !f(p) {
                return;
            }
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                if !f(p) {
                    return;
                }
            }
        }
    }

    fn any_member(&self, mut pred: impl FnMut(&Arc<dyn Proxy>) -> bool) -> bool {
        let mut hit = false;
        self.for_each_member(|p| {
            hit = pred(p);
            !hit
        });
        hit
    }

    /// First alive member in canonical order (for `current()`/`delay_history`).
    fn first_alive_member(&self) -> Option<Arc<dyn Proxy>> {
        let mut out = None;
        self.for_each_member(|p| {
            if p.alive() {
                out = Some(Arc::clone(p));
                false
            } else {
                true
            }
        });
        out
    }

    /// Smallest positive delay across alive members (0 = none measured).
    fn min_alive_delay(&self, mut delay: impl FnMut(&Arc<dyn Proxy>) -> u16) -> u16 {
        let mut best = 0u16;
        self.for_each_member(|p| {
            if p.alive() {
                let d = delay(p);
                if d > 0 && (best == 0 || d < best) {
                    best = d;
                }
            }
            true
        });
        best
    }

    /// Attach the group health-check `url:` (upstream `TestUrl`). Member
    /// eligibility on every pick is `alive_for_url(test_url)`, and the
    /// sweep/API read it via `Proxy::test_url` (issue #621).
    #[must_use]
    pub fn with_test_url(mut self, test_url: String) -> Self {
        self.test_url = test_url;
        self
    }

    /// Attach the group-level `expected-status` probe expression
    /// (upstream `GroupCommonOption`; the health sweep reads it via
    /// `Proxy::expected_status`).
    #[must_use]
    pub fn with_expected_status(mut self, expected_status: String) -> Self {
        self.expected_status = expected_status;
        self
    }

    /// Select a proxy from the alive set for a TCP connection.
    ///
    /// Returns `None` if no alive proxy exists.
    ///
    /// TODO(perf M2): cache alive-set or use a pre-filtered index if profiling shows this hot
    pub fn select(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.pick(metadata, false, true)
    }

    fn select_udp(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.pick(metadata, true, true)
    }

    /// Eligibility for a pick: alive for the group's test URL (upstream
    /// `AliveForTestUrl(testUrl)` — for leaf adapters the single health
    /// flag makes this identical to `alive()`), and UDP-capable when the
    /// pick is for a UDP flow (upstream LB does not filter by UDP — that
    /// asymmetry is local).
    fn eligible(&self, p: &Arc<dyn Proxy>, udp_only: bool) -> bool {
        p.alive_for_url(&self.test_url) && (!udp_only || p.support_udp())
    }

    /// One immutable member snapshot per pick — statics first, then each
    /// provider slot's current contents. The previous two-pass form
    /// (count eligible, then re-walk under fresh slot read-guards) could
    /// observe a member death or a provider-slot swap between passes and
    /// shift the pick or yield `None` for one dial (issue #621).
    fn pick(&self, metadata: &Metadata, udp_only: bool, advance: bool) -> Option<Arc<dyn Proxy>> {
        let members = self.member_proxies().unwrap_or_default();
        match self.strategy {
            LbStrategy::RoundRobin => {
                // Evaluate eligibility once: a health flag can flip between
                // a count pass and a pick pass, which would shrink the set
                // under `c % old_len` and yield `None` for a dial that had
                // live members (issue #621 review).
                let eligible: Vec<&Arc<dyn Proxy>> = members
                    .iter()
                    .filter(|p| self.eligible(p, udp_only))
                    .collect();
                if eligible.is_empty() {
                    return None;
                }
                // `advance=false` is the match-time peek (`Unwrap(metadata,
                // false)` upstream): round-robin reads the counter without
                // committing it.
                let c = if advance {
                    self.counter.fetch_add(1, Ordering::Relaxed)
                } else {
                    self.counter.load(Ordering::Relaxed)
                };
                Some(Arc::clone(eligible[c % eligible.len()]))
            }
            LbStrategy::ConsistentHashing => {
                // mihomo `strategyConsistentHashing`: jump-hash the
                // destination key over the FULL member list; on an
                // ineligible member retry with the incremented hash, up
                // to five times, then fall back to a linear scan
                // (adapter/outbound/loadbalance.go).
                if members.is_empty() {
                    return None;
                }
                let mut key = fnv1a64(get_key(metadata).as_bytes());
                for _ in 0..5 {
                    let idx = jump_hash(key, members.len()) as usize;
                    let p = &members[idx];
                    if self.eligible(p, udp_only) {
                        return Some(Arc::clone(p));
                    }
                    key = key.wrapping_add(1);
                }
                members
                    .iter()
                    .find(|p| self.eligible(p, udp_only))
                    .map(Arc::clone)
            }
        }
    }
}

/// mihomo `getKey`: the consistent-hashing key derives from the
/// *destination*, not the client. An IP-literal host is used verbatim, a
/// domain is reduced to its eTLD+1 (`a.b.example.co.uk` → `example.co.uk`,
/// so all of a registrable domain's hosts share one member), and anything
/// else falls back to `dst_ip` (empty when neither exists — every such
/// connection then lands on the same member, deterministic not random).
fn get_key(metadata: &Metadata) -> String {
    if !metadata.host.is_empty() {
        if metadata.host.parse::<IpAddr>().is_ok() {
            return metadata.host.to_string();
        }
        // Lowercasing is a deliberate improvement, not upstream parity —
        // Go's publicsuffix lookup is case-sensitive, so `getKey` there
        // returns the mixed-case eTLD+1; DNS is case-insensitive, so
        // folding first groups `WWW.Example.COM` with `example.com`
        // instead of splitting them across members. Unreachable in
        // practice either way: every ingress already lowercases `host`.
        //
        // A host still carrying a port/brackets (`example.com:443`,
        // `[::1]`) isn't a bare domain. Upstream's helper *succeeds* on
        // dotted ones (wildcard rule → the whole `domain:port` string
        // becomes the key) and only fails on single-label port strings —
        // we instead fall back to `dst_ip`, which keeps the destination
        // keyed rather than inventing a suffix. Defensive: no ingress
        // leaves a port in `host` today.
        let lower = metadata.host.to_ascii_lowercase();
        if !lower.contains(':') {
            if let Some(domain) = psl::domain_str(&lower) {
                return domain.to_string();
            }
        }
    }
    metadata.dst_ip.map(|ip| ip.to_string()).unwrap_or_default()
}

/// FNV-1a 64-bit over the destination key. Upstream hashes with
/// `utils.MapHash` (Go `maphash`, seeded per process — its assignments are
/// deliberately *not* reproducible across restarts), so parity targets the
/// key derivation and selection structure, not bit-identical buckets; a
/// fixed 64-bit hash gives us the stable cross-restart mapping upstream
/// itself cannot offer.
fn fnv1a64(data: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Lamping–Veach jump consistent hash — a direct port of mihomo's
/// `jumpHash` (adapter/outbound/loadbalance.go): same 64-bit LCG state and
/// the same float64 bucket arithmetic, so identical keys land on identical
/// bucket indices for a given member count.
fn jump_hash(mut key: u64, buckets: usize) -> u32 {
    if buckets == 0 {
        return 0;
    }
    let (mut b, mut j) = (-1i64, 0i64);
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b + 1) as f64 * ((1u64 << 31) as f64 / ((key >> 33) + 1) as f64)) as i64;
    }
    b as u32
}

#[async_trait]
impl ProxyAdapter for LoadBalanceGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::LoadBalance
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.any_member(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.usage.touch_user_traffic(metadata);
        let proxy = self.select(metadata).ok_or(MeowError::NoProxyAvailable)?;
        let attempt = super::DialAttempt::new(&self.name, &self.dial_failures, &proxy);
        attempt.finish(proxy.dial_tcp(metadata).await)
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.usage.touch_user_traffic(metadata);
        let proxy = self
            .select_udp(metadata)
            .ok_or(MeowError::NoProxyAvailable)?;
        let attempt = super::DialAttempt::new(&self.name, &self.dial_failures, &proxy);
        attempt.finish(proxy.dial_udp(metadata).await)
    }

    fn unwrap_proxy(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        if touch {
            self.usage.touch_user_traffic(metadata);
        }
        // Peek the same member space the upcoming dial uses: UDP flows pick
        // from UDP-capable members only (upstream LB does not filter by UDP,
        // so this asymmetry is local — keep probe and dial consistent).
        self.pick(
            metadata,
            metadata.network == meow_common::Network::Udp,
            touch,
        )
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for LoadBalanceGroup {
    fn alive(&self) -> bool {
        self.any_member(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.any_member(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.min_alive_delay(|p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.min_alive_delay(|p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.first_alive_member()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        let mut out = Vec::new();
        self.for_each_member(|p| {
            out.push(p.name().to_string());
            true
        });
        Some(out)
    }

    fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        let mut out = Vec::new();
        self.for_each_member(|p| {
            out.push(Arc::clone(p));
            true
        });
        Some(out)
    }

    fn current(&self) -> Option<String> {
        // For load-balance, no single "current" proxy; return first alive for API compat.
        self.first_alive_member().map(|p| p.name().to_string())
    }

    fn test_url(&self) -> Option<&str> {
        Some(&self.test_url)
    }

    fn expected_status(&self) -> Option<&str> {
        Some(&self.expected_status)
    }

    fn usage_generation(&self) -> u64 {
        self.usage.generation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::test_support::MockProxy;
    use meow_common::{ConnType, DnsMode, Network};
    use smol_str::SmolStr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn meta_no_src() -> Metadata {
        Metadata {
            src_ip: None,
            ..Metadata::default()
        }
    }

    /// Destination-domain metadata — the consistent-hashing key derives
    /// from the destination (mihomo `getKey`), not the client.
    fn meta_dst_host(host: &str) -> Metadata {
        Metadata {
            host: SmolStr::from(host),
            network: Network::Tcp,
            conn_type: ConnType::Http,
            dst_port: 443,
            dns_mode: DnsMode::Normal,
            ..Metadata::default()
        }
    }

    fn make_rr(proxies: Vec<Arc<dyn Proxy>>) -> LoadBalanceGroup {
        LoadBalanceGroup::new("test-lb", proxies, LbStrategy::RoundRobin)
    }

    fn make_ch(proxies: Vec<Arc<dyn Proxy>>) -> LoadBalanceGroup {
        LoadBalanceGroup::new("test-lb", proxies, LbStrategy::ConsistentHashing)
    }

    // ─── D. Hash primitives (mihomo getKey + jumpHash) ───────────────────────

    #[test]
    fn fnv1a64_known_vectors() {
        // Known-answer vectors for the inline FNV-1a 64-bit hash feeding
        // jump_hash (consistent hashing).
        let cases: &[(&str, &[u8], u64)] = &[
            ("empty input (offset basis)", &[], 0xcbf2_9ce4_8422_2325),
            ("single null byte", &[0x00], 0xaf63_bd4c_8601_b7df),
            ("example.com", b"example.com", 0x5768_4663_4e27_14c6),
        ];

        let mut failures = Vec::new();
        for (label, input, expected) in cases {
            let got = fnv1a64(input);
            if got != *expected {
                failures.push(format!(
                    "{label}: fnv1a64({input:?}) = {got:#018x}, expected {expected:#018x}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "FNV-1a-64 vector mismatches:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn jump_hash_stays_in_range() {
        for key in [
            0u64,
            1,
            u64::MAX,
            fnv1a64(b"example.com"),
            fnv1a64(b"203.0.113.7"),
        ] {
            for buckets in 1..=8usize {
                let idx = jump_hash(key, buckets) as usize;
                assert!(idx < buckets, "jump_hash({key}, {buckets}) = {idx}");
            }
        }
    }

    #[test]
    fn jump_hash_known_answer_vectors() {
        // Reference values from an independent Lamping–Veach implementation
        // (the same upstream formulation): (key, [buckets 1,2,3,5,10]).
        let vectors: &[(u64, [u32; 5])] = &[
            (0, [0, 0, 0, 0, 0]),
            (1, [0, 0, 0, 0, 6]),
            (2, [0, 0, 0, 3, 6]),
            (12345, [0, 1, 1, 1, 1]),
            (fnv1a64(b"example.com"), [0, 0, 2, 3, 6]),
        ];
        for (key, expected) in vectors {
            for (i, buckets) in [1usize, 2, 3, 5, 10].iter().enumerate() {
                assert_eq!(
                    jump_hash(*key, *buckets),
                    expected[i],
                    "jump_hash({key}, {buckets})"
                );
            }
        }
    }

    #[test]
    fn get_key_host_ip_literal_passthrough() {
        // mihomo getKey: an IP-literal host is the key verbatim.
        assert_eq!(get_key(&meta_dst_host("203.0.113.7")), "203.0.113.7");
        assert_eq!(get_key(&meta_dst_host("2001:db8::1")), "2001:db8::1");
    }

    #[test]
    fn get_key_domain_reduces_to_etld_plus_one() {
        // All hosts under one registrable domain share a member.
        assert_eq!(
            get_key(&meta_dst_host("a.b.example.co.uk")),
            "example.co.uk"
        );
        assert_eq!(get_key(&meta_dst_host("cdn1.example.com")), "example.com");
        // Uppercase folds to the lowercase eTLD+1 — our deliberate
        // improvement over Go's case-sensitive lookup (see get_key).
        assert_eq!(get_key(&meta_dst_host("WWW.Example.COM")), "example.com");
    }

    #[test]
    fn get_key_falls_back_to_dst_ip_then_empty() {
        // A host that IS a public suffix has no eTLD+1 → dst_ip.
        let mut m = meta_dst_host("co.uk");
        m.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)));
        assert_eq!(get_key(&m), "198.51.100.2");
        // No host → dst_ip; neither → "" (deterministic, not random).
        let ip_only = Metadata {
            dst_ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ..Default::default()
        };
        assert_eq!(get_key(&ip_only), "::1");
        assert_eq!(get_key(&Metadata::default()), "");
    }

    #[test]
    fn get_key_edge_cases() {
        // Trailing-dot FQDN reduces like its non-FQDN form (psl trims it).
        assert_eq!(get_key(&meta_dst_host("www.example.com.")), "example.com");
        // Unknown TLD → psl wildcard: the full host is the eTLD+1, matching
        // Go's EffectiveTLDPlusOne on `foo.local`/`foo.internal`.
        assert_eq!(get_key(&meta_dst_host("foo.local")), "foo.local");
        assert_eq!(get_key(&meta_dst_host("a.foo.internal")), "foo.internal");
        // A host still carrying a port is not a domain — upstream's helper
        // fails and falls back to DstIP; pin that parity.
        let mut m = meta_dst_host("example.com:443");
        m.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
        assert_eq!(get_key(&m), "203.0.113.9");
    }

    // ─── A. Round-robin strategy ──────────────────────────────────────────────

    #[test]
    fn round_robin_cycles_through_alive_proxies() {
        // upstream: adapter/outbound/loadbalance.go::RoundRobin.Addr
        // NOT random; NOT skipping index on wrap — strictly sequential.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = make_rr(proxies);
        let meta = meta_no_src();

        let expected = ["A", "B", "C", "A", "B", "C", "A", "B", "C", "A"];
        for name in &expected {
            let selected = group.select(&meta).expect("should select");
            assert_eq!(selected.name(), *name, "expected {name}");
        }
    }

    #[test]
    fn round_robin_skips_dead_proxy() {
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        b.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = make_rr(proxies);
        let meta = meta_no_src();

        // 6 calls → only A and C appear, alternating [A,C,A,C,A,C]
        for i in 0..6 {
            let selected = group.select(&meta).expect("should select");
            let expect = if i % 2 == 0 { "A" } else { "C" };
            assert_eq!(selected.name(), expect);
        }
    }

    #[test]
    fn round_robin_single_alive_always_selects_it() {
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        b.set_alive(false);
        c.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = make_rr(proxies);
        let meta = meta_no_src();
        for _ in 0..5 {
            assert_eq!(group.select(&meta).unwrap().name(), "A");
        }
    }

    #[test]
    fn round_robin_counter_wraps_correctly() {
        // Guards against unchecked arithmetic on counter overflow.
        // 4 proxies alive; counter starts at usize::MAX - 1.
        let proxies: Vec<Arc<dyn Proxy>> = (0..4)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = LoadBalanceGroup {
            name: "wrap-test".into(),
            static_proxies: proxies,
            provider_slots: Vec::new(),
            strategy: LbStrategy::RoundRobin,
            counter: AtomicUsize::new(usize::MAX - 1),
            test_url: "https://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            health: ProxyHealth::new(),
            usage: super::UsageTracker::new(),
            dial_failures: DialFailureTracker::new(),
        };
        let meta = meta_no_src();
        // Should not panic; indices are (usize::MAX-1)%4 and (usize::MAX)%4
        let r1 = group.select(&meta);
        let r2 = group.select(&meta);
        assert!(r1.is_some());
        assert!(r2.is_some());
    }

    #[test]
    fn round_robin_handles_alive_set_flap() {
        // Alive-set is rebuilt on every select() — modulo is on current alive count.
        // NOT out-of-bounds panic. NOT stale-index access. ADR-0002 acceptance criterion #11.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, Arc::clone(&b) as Arc<dyn Proxy>, c];
        let group = make_rr(proxies);
        let meta = meta_no_src();

        let r1 = group.select(&meta);
        assert!(r1.is_some());

        b.set_alive(false);

        let r2 = group.select(&meta);
        assert!(
            r2.is_some(),
            "select after flap must not panic or return None"
        );
        assert!(r2.as_ref().unwrap().alive(), "selected proxy must be alive");
    }

    // ─── B. Consistent-hashing strategy ──────────────────────────────────────

    #[test]
    fn consistent_hashing_stable_for_same_dst() {
        // upstream: adapter/outbound/loadbalance.go::strategyConsistentHashing
        // NOT volatile — same destination key + fixed proxy list → same
        // member every time.
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);
        let meta = meta_dst_host("example.com");

        let first = group.select(&meta).unwrap().name().to_string();
        for _ in 0..99 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    #[test]
    fn consistent_hashing_ignores_src_ip() {
        // The key derives from the destination (mihomo getKey) — two
        // clients reaching the same host share a member; that's the whole
        // point of consistent hashing (per-egress spread).
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);

        let mut a = meta_dst_host("example.com");
        a.src_ip = Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let mut b = meta_dst_host("example.com");
        b.src_ip = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        assert_eq!(
            group.select(&a).unwrap().name(),
            group.select(&b).unwrap().name()
        );
    }

    #[test]
    fn consistent_hashing_spreads_across_dst_keys() {
        // Different destinations must not all collapse onto one member —
        // scan dst hosts until two land on different members.
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);

        let mut seen = std::collections::BTreeSet::new();
        for i in 0..64u8 {
            let meta = meta_dst_host(&format!("host{i}.example{i}.com"));
            seen.insert(group.select(&meta).unwrap().name().to_string());
            if seen.len() > 1 {
                return;
            }
        }
        panic!("64 distinct dst keys all hashed to one member");
    }

    #[test]
    fn consistent_hashing_retries_past_dead_member() {
        // The member a key maps to dies → the jump-hash retry (key+1…+4)
        // or the linear fallback must land on an *alive* member.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![
            Arc::clone(&a) as Arc<dyn Proxy>,
            Arc::clone(&b) as Arc<dyn Proxy>,
            Arc::clone(&c) as Arc<dyn Proxy>,
        ];
        let group = make_ch(proxies);
        let meta = meta_dst_host("example.com");

        let picked = group.select(&meta).unwrap().name().to_string();
        for p in [&a, &b, &c] {
            p.set_alive(p.name() != picked);
        }
        let selected = group
            .select(&meta)
            .expect("must still select with the mapped member dead");
        assert!(selected.alive(), "selected proxy must be alive");
    }

    #[test]
    fn consistent_hashing_dead_member_remaps_only_its_keys() {
        // Jump-hash's minimal-reshuffle property: killing a member moves
        // only the keys that mapped to it; keys on surviving members keep
        // their member (upstream relies on this for connection stability).
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![
            Arc::clone(&a) as Arc<dyn Proxy>,
            Arc::clone(&b) as Arc<dyn Proxy>,
            Arc::clone(&c) as Arc<dyn Proxy>,
        ];
        let group = make_ch(proxies);

        // Find two dst keys landing on different members.
        let (mut k1, mut k2) = (None, None);
        for i in 0..64u8 {
            let meta = meta_dst_host(&format!("site{i}.example{i}.net"));
            let name = group.select(&meta).unwrap().name().to_string();
            match name.as_str() {
                n if k1.is_none() => k1 = Some((meta, n.to_string())),
                n if n != k1.as_ref().unwrap().1 && k2.is_none() => {
                    k2 = Some((meta, n.to_string()));
                }
                _ => {}
            }
            if k2.is_some() {
                break;
            }
        }
        let (k1, n1) = k1.unwrap();
        let (k2, n2) = k2.unwrap();

        // Kill the member k1 maps to; k2's mapping must not move.
        for p in [&a, &b, &c] {
            if p.name() == n1 {
                p.set_alive(false);
            }
        }
        assert_ne!(group.select(&k1).unwrap().name(), n1);
        assert_eq!(group.select(&k2).unwrap().name(), n2, "k2 must not remap");
    }

    #[test]
    fn consistent_hashing_absent_dst_deterministic() {
        // No host and no dst_ip → the empty key — every such connection
        // lands on the same member. NOT random. NOT NoProxyAvailable.
        // Upstream hashes "" identically.
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);
        let meta = meta_no_src();

        let first = group.select(&meta).unwrap().name().to_string();
        for _ in 0..9 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    #[test]
    fn consistent_hashing_ipv6_dst_stable() {
        // IPv6 dst literal → the canonical ip string is the key — same
        // member across calls.
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);
        let ip6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let meta = Metadata {
            dst_ip: Some(ip6),
            ..Default::default()
        };

        let first = group.select(&meta).unwrap().name().to_string();
        for _ in 0..9 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    // ─── C. All-dead and zero-proxy error paths ───────────────────────────────

    #[test]
    fn all_proxies_dead_round_robin_returns_no_proxy_available() {
        // upstream Go: returns the round-robin slot (a dead proxy). NOT here.
        // ADR-0002 Class A.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        a.set_alive(false);
        b.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = make_rr(proxies);
        assert!(group.select(&meta_no_src()).is_none());
    }

    #[test]
    fn all_proxies_dead_consistent_hashing_returns_no_proxy_available() {
        // upstream Go panics with index out of bounds. NOT here — ADR-0002 Class A.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        a.set_alive(false);
        b.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = make_ch(proxies);
        assert!(group.select(&meta_dst_host("example.com")).is_none());
    }

    #[test]
    fn empty_proxy_list_returns_no_proxy_available() {
        // Guards against proxies[0] or unwrap() on empty vec at construction.
        let group = make_rr(vec![]);
        assert!(group.select(&meta_no_src()).is_none());
    }

    // ─── E. UDP support ───────────────────────────────────────────────────────

    #[test]
    fn support_udp_reflects_membership() {
        // support_udp() is `any()` over members: true when at least one member
        // supports UDP, false when none do.
        type Case = (&'static str, Vec<Arc<dyn Proxy>>, bool);
        let cases: Vec<Case> = vec![
            (
                "one of three members supports UDP",
                vec![
                    MockProxy::new_udp("A"),
                    MockProxy::new("B"),
                    MockProxy::new("C"),
                ],
                true,
            ),
            (
                "no member supports UDP",
                vec![MockProxy::new("A"), MockProxy::new("B")],
                false,
            ),
        ];

        let mut failures = Vec::new();
        for (label, proxies, expected) in cases {
            let got = make_rr(proxies).support_udp();
            if got != expected {
                failures.push(format!(
                    "{label}: expected support_udp() == {expected}, got {got}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    }

    #[tokio::test]
    async fn dial_udp_filters_to_udp_capable_alive_proxies() {
        // A: UDP+alive, B: no-UDP+alive, C: UDP+dead
        // dial_udp() must select only A.
        let a = MockProxy::new_udp("A");
        let b = MockProxy::new("B"); // no UDP
        let c = MockProxy::new_udp("C");
        c.set_alive(false);
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let c_ref = Arc::clone(&c);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = make_rr(proxies);
        // dial_udp returns error from MockProxy but that's OK — we care about which was tried
        let _ = group.dial_udp(&meta_no_src()).await;
        assert_eq!(a_ref.dials(), 1, "A (UDP+alive) must be tried");
        assert_eq!(b_ref.dials(), 0, "B (no UDP) must not be tried");
        assert_eq!(c_ref.dials(), 0, "C (dead) must not be tried");
    }

    #[tokio::test]
    async fn dial_udp_all_udp_proxies_dead_returns_error() {
        // All UDP-capable proxies dead → NoProxyAvailable. NOT a dial to non-UDP proxy.
        let a = MockProxy::new_udp("A");
        let b = MockProxy::new("B"); // no UDP, alive
        a.set_alive(false);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = make_rr(proxies);
        let result = group.dial_udp(&meta_no_src()).await;
        assert!(
            matches!(result, Err(MeowError::NoProxyAvailable)),
            "expected NoProxyAvailable, got: {:?}",
            result.err()
        );
    }

    // ─── G. AdapterType and ProxyAdapter trait methods ────────────────────────

    #[test]
    fn adapter_type_is_load_balance() {
        let group = make_rr(vec![MockProxy::new("X")]);
        assert_eq!(group.adapter_type(), AdapterType::LoadBalance);
    }

    #[test]
    fn adapter_type_serialises_to_load_balance() {
        let json = serde_json::to_string(&AdapterType::LoadBalance).unwrap();
        assert_eq!(json, r#""LoadBalance""#);
    }

    #[test]
    fn group_name_returns_config_name() {
        let group = make_rr(vec![MockProxy::new("X")]);
        assert_eq!(group.name(), "test-lb");
    }

    #[test]
    fn group_addr_returns_empty() {
        let group = make_rr(vec![MockProxy::new("X")]);
        assert_eq!(group.addr(), "");
    }

    // ─── H. Lazy health-check / usage tracking ────────────────────────────────

    #[tokio::test]
    async fn dial_records_group_use_for_lazy_probe() {
        // #485: a lazy load-balance group is only probed after a dial bumps the
        // usage generation (health_check.rs::should_probe). Mirrors
        // fallback.rs::dial_tcp_routes_through_first_alive.
        let group = make_rr(vec![MockProxy::new("A")]);
        assert_eq!(group.usage_generation(), 0, "unused group has no use");
        let _ = group.dial_tcp(&meta_no_src()).await;
        assert_eq!(group.usage_generation(), 1, "dial records group use");
    }

    #[tokio::test]
    async fn health_probe_dials_do_not_count_as_use() {
        // Sweep probes dial members with `ConnType::Tunnel`; if that bumped the
        // usage generation a lazy group would keep itself awake forever.
        // Mirrors fallback.rs::health_probe_dials_do_not_count_as_use.
        let group = make_rr(vec![MockProxy::new("A")]);
        let probe_meta = Metadata {
            conn_type: ConnType::Tunnel,
            ..meta_no_src()
        };
        let _ = group.dial_tcp(&probe_meta).await;
        assert_eq!(
            group.usage_generation(),
            0,
            "probe dials must not mark the group as used"
        );
        // #555: housekeeping traffic marked `internal` (provider/geodata
        // fetches, DNS-via-proxy, dialer-proxy-chained probes) is skipped
        // the same way — both disjuncts of `is_internal()` are covered.
        let internal_meta = Metadata {
            internal: true,
            ..meta_no_src()
        };
        let _ = group.dial_tcp(&internal_meta).await;
        assert_eq!(
            group.usage_generation(),
            0,
            "internal dials must not mark the group as used"
        );
        let _ = group.dial_tcp(&meta_no_src()).await;
        assert_eq!(group.usage_generation(), 1, "real traffic still marks use");
    }

    // ─── I. Provider slots (issue #533 item 3) ──────────────────────────────

    fn slot_of(proxies: Vec<Arc<dyn Proxy>>) -> ProviderSlot {
        Arc::new(parking_lot::RwLock::new(proxies))
    }

    #[test]
    fn round_robin_cycles_statics_then_slot_members() {
        // One static + a two-member provider slot: the pick space is the
        // concatenation in canonical order (statics first, slot members after).
        let slot = slot_of(vec![MockProxy::new("P1"), MockProxy::new("P2")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        let meta = meta_no_src();
        let got: Vec<String> = (0..6)
            .map(|_| group.select(&meta).unwrap().name().to_string())
            .collect();
        assert_eq!(got, ["A", "P1", "P2", "A", "P1", "P2"]);
    }

    #[test]
    fn provider_slot_refresh_is_seen_on_next_select() {
        // The slot is a live RwLock<Vec>: swapping its contents must change
        // both `members()` and the pick space without rebuilding the group.
        let slot = slot_of(vec![MockProxy::new("P1")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![],
            LbStrategy::RoundRobin,
            vec![Arc::clone(&slot)],
        );
        let meta = meta_no_src();
        assert_eq!(group.members().unwrap(), ["P1"]);
        assert_eq!(group.select(&meta).unwrap().name(), "P1");

        *slot.write() = vec![MockProxy::new("P9")];
        assert_eq!(group.members().unwrap(), ["P9"]);
        assert_eq!(group.select(&meta).unwrap().name(), "P9");
    }

    #[test]
    fn dead_slot_member_is_skipped() {
        let dead = MockProxy::new("PD");
        dead.set_alive(false);
        let slot = slot_of(vec![dead, MockProxy::new("P1")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        let meta = meta_no_src();
        // Assert the full cycle, not just "PD is never picked" — a pick
        // space that ignored slots entirely would also satisfy that.
        let got: Vec<String> = (0..4)
            .map(|_| group.select(&meta).unwrap().name().to_string())
            .collect();
        assert_eq!(got, ["A", "P1", "A", "P1"]);
    }

    #[test]
    fn consistent_hashing_stable_across_slots() {
        // Same dst key must keep landing on the same member whether the
        // member set is static or slot-sourced. Find a dst whose hash lands
        // on a slot member first — otherwise a statics-only pick space
        // would satisfy the stability assertion vacuously.
        let slot = slot_of(vec![MockProxy::new("P1"), MockProxy::new("P2")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::ConsistentHashing,
            vec![slot],
        );
        let (meta, first) = (0..=255u8)
            .map(|i| meta_dst_host(&format!("host{i}.dst{i}.xyz")))
            .find_map(|m| {
                let name = group.select(&m).unwrap().name().to_string();
                (name != "A").then_some((m, name))
            })
            .expect("some dst key must hash onto a slot member");
        for _ in 0..9 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    #[test]
    fn members_and_support_udp_include_slots() {
        let slot = slot_of(vec![MockProxy::new_udp("PU")]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        assert_eq!(group.members().unwrap(), ["A", "PU"]);
        assert!(group.support_udp(), "slot member's UDP support counts");
    }

    #[test]
    fn select_udp_picks_udp_capable_slot_member() {
        let slot = slot_of(vec![MockProxy::new_udp("PU"), MockProxy::new("PN")]);
        let group =
            LoadBalanceGroup::new_with_providers("lb", vec![], LbStrategy::RoundRobin, vec![slot]);
        let meta = meta_no_src();
        for _ in 0..4 {
            assert_eq!(group.select_udp(&meta).unwrap().name(), "PU");
        }
    }

    #[tokio::test]
    async fn dial_udp_reaches_udp_capable_slot_member() {
        // End-to-end through `ProxyAdapter::dial_udp` — not just `select_udp`.
        let pu = MockProxy::new_udp("PU");
        let pn = MockProxy::new("PN");
        let pu_ref = Arc::clone(&pu);
        let pn_ref = Arc::clone(&pn);
        let slot = slot_of(vec![pu, pn]);
        let group =
            LoadBalanceGroup::new_with_providers("lb", vec![], LbStrategy::RoundRobin, vec![slot]);
        for _ in 0..3 {
            let _ = group.dial_udp(&meta_no_src()).await;
        }
        assert_eq!(
            pu_ref.dials(),
            3,
            "every UDP dial reaches the capable member"
        );
        assert_eq!(pn_ref.dials(), 0, "non-UDP member is never tried");
    }

    #[tokio::test]
    async fn repeated_dial_failures_mark_slot_member_dead() {
        // The group sweep probes provider members via `member_proxies()`
        // (issue #543); mihomo's onDialFailed escalation —
        // DialAttempt/DialFailureTracker — is the additional between-sweeps
        // signal that dead-marks a failing member faster than `interval`.
        // Mirrors urltest's `repeated_dial_failures_mark_member_dead`.
        let failing = MockProxy::new_failing("P1", AdapterType::Shadowsocks, "dial timed out");
        let slot = slot_of(vec![Arc::clone(&failing) as Arc<dyn Proxy>]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        // Round-robin alternates A,P1,A,P1… — only P1's failures count (A is
        // a Direct adapter, exempt). The 5th P1 failure (dial #10) kills it.
        for i in 1..10 {
            let _ = group.dial_tcp(&meta_no_src()).await;
            assert!(
                failing.alive(),
                "failure {i} below the escalation threshold"
            );
        }
        let _ = group.dial_tcp(&meta_no_src()).await;
        assert!(!failing.alive(), "five failures mark the slot member dead");
        let _ = group.dial_tcp(&meta_no_src()).await;
        assert_eq!(
            failing.dials(),
            5,
            "the dead member no longer receives dials"
        );
    }

    #[tokio::test]
    async fn connection_refused_marks_slot_member_dead_immediately() {
        // mihomo escalates "connection refused" without a streak.
        let failing = MockProxy::new_failing("P1", AdapterType::Shadowsocks, "connection refused");
        let slot = slot_of(vec![Arc::clone(&failing) as Arc<dyn Proxy>]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("A")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        let _ = group.dial_tcp(&meta_no_src()).await; // A
        let _ = group.dial_tcp(&meta_no_src()).await; // P1 — refused
        assert!(!failing.alive(), "refused escalates on the first failure");
    }

    /// `dial_udp` runs the same `DialAttempt` escalation as `dial_tcp` —
    /// a UDP-capable member that keeps failing must dead-mark exactly like
    /// the TCP path, otherwise dead UDP members stay in `select_udp`'s
    /// pick space forever between sweeps.
    #[tokio::test]
    async fn repeated_udp_dial_failures_mark_slot_member_dead() {
        let failing = MockProxy::new_failing_udp("P1", AdapterType::Shadowsocks, "dial timed out");
        let slot = slot_of(vec![Arc::clone(&failing) as Arc<dyn Proxy>]);
        let group =
            LoadBalanceGroup::new_with_providers("lb", vec![], LbStrategy::RoundRobin, vec![slot]);
        for i in 1..5 {
            let _ = group.dial_udp(&meta_no_src()).await;
            assert!(
                failing.alive(),
                "UDP failure {i} below the escalation threshold"
            );
        }
        let _ = group.dial_udp(&meta_no_src()).await;
        assert!(
            !failing.alive(),
            "five UDP failures mark the slot member dead"
        );
        let _ = group.dial_udp(&meta_no_src()).await;
        assert_eq!(
            failing.dials(),
            5,
            "the dead member leaves the UDP pick space"
        );
    }

    /// `member_proxies()` must cover provider-slot members (issue #543
    /// item 1) and list them in `members()` order — the health sweep
    /// and the group-delay endpoint resolve through it, not the route map.
    #[test]
    fn member_proxies_include_provider_slots_in_member_names_order() {
        let slot = slot_of(vec![
            MockProxy::new("p1") as Arc<dyn Proxy>,
            MockProxy::new("p2") as Arc<dyn Proxy>,
        ]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![MockProxy::new("a"), MockProxy::new("b")],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        let names: Vec<String> = group
            .member_proxies()
            .expect("groups expose members")
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        assert_eq!(names, group.members().unwrap());
        assert_eq!(names, vec!["a", "b", "p1", "p2"]);
    }

    #[test]
    fn slot_members_feed_alive_for_url_current_and_delay() {
        // All statics dead, one alive slot member: group liveness, current
        // pick, and delay reporting must see the provider member.
        let member = MockProxy::new("P1");
        member.set_delay(50);
        let slot = slot_of(vec![member]);
        let dead = MockProxy::new("A");
        dead.set_alive(false);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![dead],
            LbStrategy::RoundRobin,
            vec![slot],
        );
        assert!(group.alive());
        assert!(group.alive_for_url("https://x"));
        assert_eq!(group.current().as_deref(), Some("P1"));
        assert_eq!(group.last_delay(), 50);
        assert_eq!(group.last_delay_for_url("https://x"), 50);
        assert_eq!(
            group.delay_history().len(),
            1,
            "delay history comes from the alive slot member"
        );
    }

    #[test]
    fn consistent_hashing_picks_alive_after_slot_member_death() {
        // A slot member dying mid-run must not strand the hash: the pick
        // space shrinks and the same dst key lands on an *alive* member.
        let a = MockProxy::new("P1");
        let b = MockProxy::new("P2");
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let slot = slot_of(vec![a, b]);
        let group = LoadBalanceGroup::new_with_providers(
            "lb",
            vec![],
            LbStrategy::ConsistentHashing,
            vec![slot],
        );
        let meta = meta_dst_host("stable.example.org");
        let _ = group.select(&meta);
        a_ref.set_alive(false);
        b_ref.set_alive(false);
        assert!(
            group.select(&meta).is_none(),
            "all dead → None, not a dead pick"
        );
        b_ref.set_alive(true);
        for _ in 0..3 {
            assert_eq!(group.select(&meta).unwrap().name(), "P2");
        }
    }

    /// Issue #533: match-time probing calls `unwrap_proxy(meta, false)` —
    /// upstream's `Unwrap(metadata, touch=false)` peek. Round-robin must
    /// not advance the counter, and the peeked member must equal the next
    /// real pick while the alive set is stable.
    #[test]
    fn unwrap_peek_does_not_advance_round_robin() {
        let group = LoadBalanceGroup::new(
            "lb",
            vec![
                MockProxy::new("A"),
                MockProxy::new("B"),
                MockProxy::new("C"),
            ],
            LbStrategy::RoundRobin,
        );
        let meta = Metadata::default();
        let peeked = group.unwrap_proxy(&meta, false).unwrap();
        let peeked_again = group.unwrap_proxy(&meta, false).unwrap();
        assert!(
            Arc::ptr_eq(&peeked, &peeked_again),
            "repeated peeks must not rotate"
        );
        let picked = group.select(&meta).unwrap();
        assert!(
            Arc::ptr_eq(&peeked, &picked),
            "peek must show the member the next pick would take"
        );
        // The real pick committed the counter — the next peek sees the
        // following member.
        let next_peek = group.unwrap_proxy(&meta, false).unwrap();
        assert!(
            !Arc::ptr_eq(&peeked, &next_peek),
            "after a committed pick the peek must move on"
        );
    }
}
