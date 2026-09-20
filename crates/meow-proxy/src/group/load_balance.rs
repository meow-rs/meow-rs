use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use smol_str::SmolStr;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::UsageTracker;

#[derive(Debug)]
pub enum LbStrategy {
    RoundRobin,
    ConsistentHashing,
}

pub struct LoadBalanceGroup {
    name: SmolStr,
    proxies: Vec<Arc<dyn Proxy>>,
    strategy: LbStrategy,
    counter: AtomicUsize,
    health: ProxyHealth,
    usage: UsageTracker,
}

impl LoadBalanceGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>, strategy: LbStrategy) -> Self {
        Self {
            name: SmolStr::from(name),
            proxies,
            strategy,
            counter: AtomicUsize::new(0),
            health: ProxyHealth::new(),
            usage: UsageTracker::new(),
        }
    }

    /// Select a proxy from the alive set for a TCP connection.
    ///
    /// Returns `None` if no alive proxy exists.
    ///
    /// TODO(perf M2): cache alive-set or use a pre-filtered index if profiling shows this hot
    pub fn select(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        match self.strategy {
            LbStrategy::RoundRobin => {
                let alive_count = self.proxies.iter().filter(|p| p.alive()).count();
                if alive_count == 0 {
                    return None;
                }
                let target_idx = self.counter.fetch_add(1, Ordering::Relaxed) % alive_count;
                self.proxies
                    .iter()
                    .filter(|p| p.alive())
                    .nth(target_idx)
                    .cloned()
            }
            LbStrategy::ConsistentHashing => {
                let alive_count = self.proxies.iter().filter(|p| p.alive()).count();
                if alive_count == 0 {
                    return None;
                }
                let (bytes, len) = src_ip_bytes(metadata);
                let hash = fnv1a(&bytes[..len]);
                let target_idx = (hash as usize) % alive_count;
                self.proxies
                    .iter()
                    .filter(|p| p.alive())
                    .nth(target_idx)
                    .cloned()
            }
        }
    }

    fn select_udp(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        match self.strategy {
            LbStrategy::RoundRobin => {
                let alive_count = self
                    .proxies
                    .iter()
                    .filter(|p| p.alive() && p.support_udp())
                    .count();
                if alive_count == 0 {
                    return None;
                }
                let target_idx = self.counter.fetch_add(1, Ordering::Relaxed) % alive_count;
                self.proxies
                    .iter()
                    .filter(|p| p.alive() && p.support_udp())
                    .nth(target_idx)
                    .cloned()
            }
            LbStrategy::ConsistentHashing => {
                let alive_count = self
                    .proxies
                    .iter()
                    .filter(|p| p.alive() && p.support_udp())
                    .count();
                if alive_count == 0 {
                    return None;
                }
                let (bytes, len) = src_ip_bytes(metadata);
                let hash = fnv1a(&bytes[..len]);
                let target_idx = (hash as usize) % alive_count;
                self.proxies
                    .iter()
                    .filter(|p| p.alive() && p.support_udp())
                    .nth(target_idx)
                    .cloned()
            }
        }
    }
}

/// Extract raw IP bytes from `Metadata.src_ip` for FNV hashing.
///
/// IPv4 → 4 bytes. IPv6 → 16 bytes.
/// `None` (no src_addr, e.g. local probe) → 4 zero bytes (0.0.0.0 fallback).
/// Every connection without a src_addr hashes to the same proxy — deterministic,
/// not random. Upstream: undefined (assumes src always present).
fn src_ip_bytes(metadata: &Metadata) -> ([u8; 16], usize) {
    let mut buf = [0u8; 16];
    match metadata.src_ip {
        Some(IpAddr::V4(v4)) => {
            let octets = v4.octets();
            buf[..4].copy_from_slice(&octets);
            (buf, 4)
        }
        Some(IpAddr::V6(v6)) => {
            buf.copy_from_slice(&v6.octets());
            (buf, 16)
        }
        None => (buf, 4),
    }
}

/// FNV-1a 32-bit hash.
///
/// Inline implementation — no crate dep.
/// upstream: adapter/outbound/loadbalance.go uses fnv.New32() (FNV-1, not FNV-1a);
/// we use FNV-1a which has slightly better avalanche properties at no cost.
/// Result is stable for a given input but NOT bit-for-bit identical to Go output.
fn fnv1a(data: &[u8]) -> u32 {
    const OFFSET_BASIS: u32 = 0x811c9dc5;
    const PRIME: u32 = 0x01000193;
    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
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
        self.proxies.iter().any(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.usage.touch_user_traffic(metadata);
        let proxy = self.select(metadata).ok_or(MeowError::NoProxyAvailable)?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.usage.touch_user_traffic(metadata);
        let proxy = self
            .select_udp(metadata)
            .ok_or(MeowError::NoProxyAvailable)?;
        proxy.dial_udp(metadata).await
    }

    fn unwrap_proxy(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.usage.touch_user_traffic(metadata);
        self.select(metadata)
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for LoadBalanceGroup {
    fn alive(&self) -> bool {
        self.proxies.iter().any(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.proxies.iter().any(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.proxies
            .iter()
            .filter(|p| p.alive())
            .map(|p| p.last_delay())
            .filter(|&d| d > 0)
            .min()
            .unwrap_or(0)
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.proxies
            .iter()
            .filter(|p| p.alive())
            .map(|p| p.last_delay_for_url(url))
            .filter(|&d| d > 0)
            .min()
            .unwrap_or(0)
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.proxies
            .iter()
            .find(|p| p.alive())
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.proxies.iter().map(|p| p.name().to_string()).collect())
    }

    fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        Some(self.proxies.clone())
    }

    fn current(&self) -> Option<String> {
        // For load-balance, no single "current" proxy; return first alive for API compat.
        self.proxies
            .iter()
            .find(|p| p.alive())
            .map(|p| p.name().to_string())
    }

    fn usage_generation(&self) -> u64 {
        self.usage.generation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ConnType, DnsMode, Network, ProxyHealth};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ─── MockProxy ────────────────────────────────────────────────────────────

    struct MockProxy {
        name: String,
        health: ProxyHealth,
        udp: bool,
        dial_count: Arc<AtomicUsize>,
    }

    impl MockProxy {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                health: ProxyHealth::new(),
                udp: false,
                dial_count: Arc::new(AtomicUsize::new(0)),
            })
        }

        fn new_udp(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                health: ProxyHealth::new(),
                udp: true,
                dial_count: Arc::new(AtomicUsize::new(0)),
            })
        }

        fn mark_dead(&self) {
            self.health.set_alive(false);
        }
    }

    #[async_trait]
    impl ProxyAdapter for MockProxy {
        fn name(&self) -> &str {
            &self.name
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            self.udp
        }
        async fn dial_tcp(&self, _m: &Metadata) -> Result<Box<dyn ProxyConn>> {
            self.dial_count.fetch_add(1, Ordering::Relaxed);
            Err(MeowError::NotSupported("mock".into()))
        }
        async fn dial_udp(&self, _m: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            self.dial_count.fetch_add(1, Ordering::Relaxed);
            Err(MeowError::NotSupported("mock udp".into()))
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for MockProxy {
        fn alive(&self) -> bool {
            self.health.alive()
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            self.health.alive()
        }
        fn last_delay(&self) -> u16 {
            self.health.last_delay()
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            self.health.last_delay()
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            self.health.delay_history()
        }
    }

    fn meta_no_src() -> Metadata {
        Metadata {
            src_ip: None,
            ..Metadata::default()
        }
    }

    fn meta_src(ip: IpAddr) -> Metadata {
        Metadata {
            src_ip: Some(ip),
            network: Network::Tcp,
            conn_type: ConnType::Http,
            src_port: 12345,
            dst_port: 80,
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

    // ─── D. FNV-1a 32-bit implementation ─────────────────────────────────────

    #[test]
    fn fnv1a_known_vectors() {
        // Known-answer vectors for the inline FNV-1a 32-bit implementation.
        // Reference: https://fnvhash.github.io/fnv-calculator-online/
        // Case labels map to docs/specs/group-load-balance-test-plan.md D1-D3.
        // D3 ([1,1,1,1] = 0x154df079 / 357429369) guards consistent hashing,
        // which derives its proxy index from this hash.
        let cases: &[(&str, &[u8], u32)] = &[
            ("D1 empty input (offset basis)", &[], 0x811c_9dc5),
            ("D2 single null byte", &[0x00], 0x050c_5d1f),
            ("D3 ipv4 bytes 1.1.1.1", &[1, 1, 1, 1], 0x154d_f079),
        ];

        let mut failures = Vec::new();
        for (label, input, expected) in cases {
            let got = fnv1a(input);
            if got != *expected {
                failures.push(format!(
                    "{label}: fnv1a({input:?}) = {got:#010x}, expected {expected:#010x}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "FNV-1a vector mismatches:\n{}",
            failures.join("\n")
        );
    }

    // D4 is a build-time check: no `fnv` or `fnv1` crate dependency in Cargo.toml.

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
        b.mark_dead();
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
        b.mark_dead();
        c.mark_dead();
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
            proxies,
            strategy: LbStrategy::RoundRobin,
            counter: AtomicUsize::new(usize::MAX - 1),
            health: ProxyHealth::new(),
            usage: super::UsageTracker::new(),
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

        b.mark_dead();

        let r2 = group.select(&meta);
        assert!(
            r2.is_some(),
            "select after flap must not panic or return None"
        );
        assert!(r2.as_ref().unwrap().alive(), "selected proxy must be alive");
    }

    // ─── B. Consistent-hashing strategy ──────────────────────────────────────

    #[test]
    fn consistent_hashing_stable_for_same_src() {
        // upstream: adapter/outbound/loadbalance.go::ConsistentHashing.Addr
        // NOT volatile — same src IP + fixed proxy list → same proxy every time.
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);
        let meta = meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        let first = group.select(&meta).unwrap().name().to_string();
        for _ in 0..99 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    #[test]
    fn consistent_hashing_differs_for_different_src() {
        // verified: fnv1a([1,1,1,1]) % 3 = 0, fnv1a([127,0,0,1]) % 3 = 1
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);

        let m1 = meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let m2 = meta_src(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let p1 = group.select(&m1).unwrap().name().to_string();
        let p2 = group.select(&m2).unwrap().name().to_string();
        assert_ne!(
            p1, p2,
            "1.1.1.1 and 127.0.0.1 must map to different proxies"
        );
    }

    #[test]
    fn consistent_hashing_skips_dead_proxy() {
        // Mark the proxy that 1.1.1.1 would select as dead; another alive proxy is returned.
        // 1.1.1.1 → fnv1a([1,1,1,1]) % 3 = 0 → proxies[0]
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![Arc::clone(&a) as Arc<dyn Proxy>, b, c];
        let group = make_ch(proxies);
        let meta = meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        // Verify A is the normal selection
        assert_eq!(group.select(&meta).unwrap().name(), "A");
        // Mark A dead
        a.mark_dead();
        // Must still return an alive proxy
        let selected = group
            .select(&meta)
            .expect("should still select with A dead");
        assert!(selected.alive(), "selected proxy must be alive");
    }

    #[test]
    fn consistent_hashing_absent_src_addr_deterministic() {
        // src_addr: None → hashes to 0.0.0.0 (4 zero bytes) → deterministic bucket.
        // NOT random. NOT NoProxyAvailable. NOT an error.
        // Upstream: undefined (assumes src always present) — we define the fallback.
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
    fn consistent_hashing_ipv6_src_stable() {
        // IPv6 src IP → 16-byte hash input → same proxy across 10 calls.
        // Guards that src_ip_bytes() handles IpAddr::V6 without truncation.
        let proxies: Vec<Arc<dyn Proxy>> = (0..3)
            .map(|i| MockProxy::new(&i.to_string()) as Arc<dyn Proxy>)
            .collect();
        let group = make_ch(proxies);
        let ip6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let meta = meta_src(ip6);

        let first = group.select(&meta).unwrap().name().to_string();
        for _ in 0..9 {
            assert_eq!(group.select(&meta).unwrap().name(), first);
        }
    }

    #[test]
    fn consistent_hashing_reshuffles_on_list_change() {
        // consistent-hashing = stable for given src+list, NOT ring-consistent.
        // Users should not assume minimal disruption on list change — ADR-0002 Class B row #4.
        // 1.1.1.1 maps to proxy A (idx 0) with [A, B, C].
        // Mark B dead → alive = [A, C]; 1.1.1.1 → fnv1a([1,1,1,1]) % 2 = 1 → C.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        let c = MockProxy::new("C");
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, Arc::clone(&b) as Arc<dyn Proxy>, c];
        let group = make_ch(proxies);
        let meta = meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        assert_eq!(group.select(&meta).unwrap().name(), "A");
        b.mark_dead();
        // fnv1a([1,1,1,1]) % 2 = 1, alive=[A,C], so idx 1 = C
        assert_eq!(group.select(&meta).unwrap().name(), "C");
    }

    // ─── C. All-dead and zero-proxy error paths ───────────────────────────────

    #[test]
    fn all_proxies_dead_round_robin_returns_no_proxy_available() {
        // upstream Go: returns the round-robin slot (a dead proxy). NOT here.
        // ADR-0002 Class A.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        a.mark_dead();
        b.mark_dead();
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = make_rr(proxies);
        assert!(group.select(&meta_no_src()).is_none());
    }

    #[test]
    fn all_proxies_dead_consistent_hashing_returns_no_proxy_available() {
        // upstream Go panics with index out of bounds. NOT here — ADR-0002 Class A.
        let a = MockProxy::new("A");
        let b = MockProxy::new("B");
        a.mark_dead();
        b.mark_dead();
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = make_ch(proxies);
        assert!(group
            .select(&meta_src(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))))
            .is_none());
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
        c.mark_dead();
        let a_count = Arc::clone(&a.dial_count);
        let b_count = Arc::clone(&b.dial_count);
        let c_count = Arc::clone(&c.dial_count);
        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = make_rr(proxies);
        // dial_udp returns error from MockProxy but that's OK — we care about which was tried
        let _ = group.dial_udp(&meta_no_src()).await;
        assert_eq!(
            a_count.load(Ordering::Relaxed),
            1,
            "A (UDP+alive) must be tried"
        );
        assert_eq!(
            b_count.load(Ordering::Relaxed),
            0,
            "B (no UDP) must not be tried"
        );
        assert_eq!(
            c_count.load(Ordering::Relaxed),
            0,
            "C (dead) must not be tried"
        );
    }

    #[tokio::test]
    async fn dial_udp_all_udp_proxies_dead_returns_error() {
        // All UDP-capable proxies dead → NoProxyAvailable. NOT a dial to non-UDP proxy.
        let a = MockProxy::new_udp("A");
        let b = MockProxy::new("B"); // no UDP, alive
        a.mark_dead();
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
        let _ = group.dial_tcp(&meta_no_src()).await;
        assert_eq!(group.usage_generation(), 1, "real traffic still marks use");
    }
}
