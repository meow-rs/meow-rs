//! Opt-in retained-heap measurement for the rule matching module.
//!
//! Every rule-engine structure that survives config load is built here at a
//! realistic scale under a counting global allocator, and its retained bytes,
//! retained allocation count, and build-time peak are printed. Run:
//!
//! ```text
//! cargo test -p meow-rules --test footprint_test --release -- --ignored --nocapture
//! ```
//!
//! Set `MEOW_RULES_FIXTURE=/path/to/config.yaml` to additionally parse the
//! `rules:` section of a real config (GEOIP / RULE-SET lines are skipped
//! because they need external databases), and `MEOW_GEOIP_MMDB=/path/to/
//! Country.mmdb` to additionally build the GEOIP country index for CN + US.

use meow_common::Rule;
use meow_rules::mrs_parser::{write_geosite_mrs, GeositePayload};
use meow_rules::{
    geosite::GeositeDB,
    parse_rule,
    rule_set::{DomainRuleSet, IpCidrRuleSet, RuleSet},
    ParserContext,
};
use meow_trie::DomainTrie;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

struct CountingAlloc;

static LIVE_BYTES: AtomicI64 = AtomicI64::new(0);
static PEAK_BYTES: AtomicI64 = AtomicI64::new(0);
static LIVE_ALLOCS: AtomicI64 = AtomicI64::new(0);
static TOTAL_ALLOCS: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn on_alloc(size: usize) {
    let live = LIVE_BYTES.fetch_add(size as i64, Ordering::Relaxed) + size as i64;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
    LIVE_ALLOCS.fetch_add(1, Ordering::Relaxed);
    TOTAL_ALLOCS.fetch_add(1, Ordering::Relaxed);
}

fn on_dealloc(size: usize) {
    LIVE_BYTES.fetch_sub(size as i64, Ordering::Relaxed);
    LIVE_ALLOCS.fetch_sub(1, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        on_alloc(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        on_dealloc(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        on_dealloc(old_layout.size());
        on_alloc(new_size);
        unsafe { System.realloc(ptr, old_layout, new_size) }
    }
}

#[derive(Clone, Copy)]
struct Snapshot {
    live_bytes: i64,
    live_allocs: i64,
    peak_bytes: i64,
    total_allocs: u64,
}

fn snapshot() -> Snapshot {
    Snapshot {
        live_bytes: LIVE_BYTES.load(Ordering::Relaxed),
        live_allocs: LIVE_ALLOCS.load(Ordering::Relaxed),
        peak_bytes: PEAK_BYTES.load(Ordering::Relaxed),
        total_allocs: TOTAL_ALLOCS.load(Ordering::Relaxed),
    }
}

/// Run `f`, then report the heap it *retains* (live delta after the call),
/// the number of live allocations it retains, and the build-time peak above
/// the starting live size.
fn measure<T>(label: &str, per_unit: usize, f: impl FnOnce() -> T) -> T {
    let before = snapshot();
    PEAK_BYTES.store(before.live_bytes, Ordering::Relaxed);
    let value = f();
    let after = snapshot();
    let retained = after.live_bytes - before.live_bytes;
    let retained_allocs = after.live_allocs - before.live_allocs;
    let peak = after.peak_bytes - before.live_bytes;
    let total_allocs = after.total_allocs - before.total_allocs;
    println!(
        "{label:<34} retained={:>9} KiB ({:>6.1} B/unit) live_allocs={:>8} peak={:>9} KiB allocs={:>9}",
        retained / 1024,
        retained as f64 / per_unit.max(1) as f64,
        retained_allocs,
        peak / 1024,
        total_allocs,
    );
    value
}

// --- deterministic synthetic data -------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const WORDS: &[&str] = &[
    "api", "cdn", "static", "img", "www", "mail", "login", "auth", "shop", "news", "video",
    "music", "cloud", "app", "m", "edge", "assets", "media", "data", "files", "dl", "update",
    "push", "sync", "store", "play", "game", "live", "chat", "pay", "ads", "track", "stat", "log",
    "beta", "dev", "test", "cn", "us", "eu", "jp", "kr", "hk", "tw", "sg", "in", "de", "fr", "uk",
    "au", "ca", "br", "ru", "alpha", "gamma", "delta", "omega", "prime", "zeta", "nova", "pixel",
    "byte", "node", "link", "net", "web", "site", "page", "hub", "lab", "one", "pro", "plus",
    "max", "mini", "micro", "mega", "ultra", "super", "hyper", "meta", "core", "base", "home",
    "work", "life", "world", "global", "local", "east", "west", "north", "south",
];

const TLDS: &[&str] = &[
    "com", "net", "org", "cn", "com.cn", "io", "co", "me", "tv", "cc", "xyz", "info", "jp", "kr",
    "de", "uk", "co.uk", "app", "dev", "cloud", "ai", "top", "site", "edu", "gov",
];

/// Realistic hostname: 1-3 word labels over a 2-level base, ~8k distinct
/// registrable bases so the trie fans out the way real geosite data does.
fn synth_domain(rng: &mut Rng) -> String {
    let base = format!(
        "{}{}.{}",
        WORDS[rng.below(WORDS.len())],
        rng.below(120),
        TLDS[rng.below(TLDS.len())]
    );
    let extra = match rng.below(10) {
        0..=3 => 0,
        4..=7 => 1,
        8 => 2,
        _ => 3,
    };
    let mut host = base;
    for _ in 0..extra {
        host = format!("{}.{host}", WORDS[rng.below(WORDS.len())]);
    }
    host
}

fn synth_domain_entries(n: usize, seed: u64) -> Vec<String> {
    let mut rng = Rng(seed);
    (0..n)
        .map(|_| {
            let d = synth_domain(&mut rng);
            match rng.below(10) {
                0..=5 => format!("+.{d}"),
                6..=8 => d,
                _ => format!("*.{d}"),
            }
        })
        .collect()
}

fn synth_cidrs(n_v4: usize, n_v6: usize, seed: u64) -> Vec<String> {
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(n_v4 + n_v6);
    for _ in 0..n_v4 {
        let prefix = 10 + rng.below(15) as u8; // /10 .. /24
        let addr = (rng.next() as u32) & (u32::MAX << (32 - prefix));
        out.push(format!("{}/{prefix}", std::net::Ipv4Addr::from(addr)));
    }
    for _ in 0..n_v6 {
        let prefix = 20 + rng.below(29) as u8; // /20 .. /48
        let hi = (rng.next() & 0x1fff_ffff_ffff_ffff) | 0x2000_0000_0000_0000;
        let addr = (u128::from(hi) << 64) & (u128::MAX << (128 - prefix));
        out.push(format!("{}/{prefix}", std::net::Ipv6Addr::from(addr)));
    }
    out
}

const ADAPTERS: &[&str] = &[
    "🎯Direct",
    "Proxies",
    "Google",
    "Crypto",
    "Scholar",
    "Microsoft",
    "AI",
    "Steam",
    "Xbox",
    "HBO",
    "Tiktok",
    "REJECT",
    "DIRECT",
];

/// Rule mix modelled on a real ~7.5k-line config: ~88% DOMAIN-SUFFIX, 6%
/// IP-CIDR, 4% DOMAIN-KEYWORD, 1.5% DOMAIN, a few PROCESS-NAME, one MATCH.
fn synth_rule_lines(n: usize, seed: u64) -> Vec<String> {
    let mut rng = Rng(seed);
    let mut lines = Vec::with_capacity(n + 1);
    for _ in 0..n {
        let adapter = ADAPTERS[rng.below(ADAPTERS.len())];
        let line = match rng.below(1000) {
            0..=879 => format!("DOMAIN-SUFFIX,{},{adapter}", synth_domain(&mut rng)),
            880..=939 => {
                let prefix = 8 + rng.below(17) as u8;
                let addr = (rng.next() as u32) & (u32::MAX << (32 - prefix));
                format!(
                    "IP-CIDR,{}/{prefix},{adapter},no-resolve",
                    std::net::Ipv4Addr::from(addr)
                )
            }
            940..=979 => format!(
                "DOMAIN-KEYWORD,{}{},{adapter}",
                WORDS[rng.below(WORDS.len())],
                rng.below(100)
            ),
            980..=994 => format!("DOMAIN,{},{adapter}", synth_domain(&mut rng)),
            _ => format!(
                "PROCESS-NAME,{}{},{adapter}",
                WORDS[rng.below(WORDS.len())],
                rng.below(50)
            ),
        };
        lines.push(line);
    }
    lines.push("MATCH,Proxies".to_string());
    lines
}

fn parse_lines(lines: &[String]) -> Vec<Box<dyn Rule>> {
    let ctx = ParserContext::empty();
    lines
        .iter()
        .filter_map(|line| parse_rule(line, &ctx).ok())
        .collect()
}

fn build_geosite_fixture() -> Vec<u8> {
    let payload = GeositePayload {
        categories: vec![
            ("cn".to_string(), synth_domain_entries(40_000, 11)),
            (
                "geolocation-!cn".to_string(),
                synth_domain_entries(40_000, 12),
            ),
            (
                "category-ads-all".to_string(),
                synth_domain_entries(40_000, 13),
            ),
        ],
    };
    write_geosite_mrs(&payload).expect("encode geosite fixture")
}

#[test]
#[ignore = "retained-heap measurement; opt in with --ignored --nocapture"]
fn rule_module_retained_heap() {
    println!("\n=== rule matching module retained heap ===");

    let domain_entries = synth_domain_entries(100_000, 1);
    let domain_set = measure("DomainRuleSet 100k entries", 100_000, || {
        DomainRuleSet::from_entries(&domain_entries)
    });
    assert!(domain_set.len() >= 90_000);
    drop(domain_entries);

    let cidr_entries = synth_cidrs(10_000, 2_000, 2);
    let cidr_set = measure("IpCidrRuleSet 10k v4 + 2k v6", 12_000, || {
        IpCidrRuleSet::from_entries(&cidr_entries)
    });
    assert_eq!(cidr_set.len(), 12_000);
    drop(cidr_entries);

    let geosite_bytes = build_geosite_fixture();
    let geosite = measure("GeositeDB 3 x 40k domains", 120_000, || {
        GeositeDB::from_bytes(&geosite_bytes, None).expect("geosite fixture loads")
    });
    assert_eq!(geosite.category_count(), 3);
    drop(geosite_bytes);

    let lines = synth_rule_lines(7_500, 3);
    let rules = measure("parse_rule 7.5k mixed rules", 7_501, || parse_lines(&lines));
    assert_eq!(rules.len(), 7_501);

    let trie = measure("DomainTrie<usize> index 7.5k", 7_501, || {
        let mut trie: DomainTrie<usize> = DomainTrie::new();
        for (idx, rule) in rules.iter().enumerate() {
            match rule.rule_type() {
                meow_common::RuleType::DomainSuffix => {
                    trie.insert(&format!("+.{}", rule.payload()), idx);
                    trie.insert(rule.payload(), idx);
                }
                meow_common::RuleType::Domain => {
                    trie.insert(rule.payload(), idx);
                }
                _ => {}
            }
        }
        trie.seal();
        trie
    });
    assert!(!trie.is_empty());

    if let Ok(path) = std::env::var("MEOW_RULES_FIXTURE") {
        let text = std::fs::read_to_string(&path).expect("read MEOW_RULES_FIXTURE");
        let real_lines: Vec<String> = text
            .lines()
            .skip_while(|l| l.trim_end() != "rules:")
            .skip(1)
            .take_while(|l| l.starts_with("  - ") || l.starts_with("- "))
            .map(|l| l.trim_start().trim_start_matches("- ").trim().to_string())
            .filter(|l| !l.starts_with("GEOIP") && !l.starts_with("RULE-SET"))
            .collect();
        let n = real_lines.len();
        let real_rules = measure("parse_rule real config", n, || parse_lines(&real_lines));
        println!("real config: {} lines -> {} rules", n, real_rules.len());
        std::hint::black_box(real_rules);
    }

    if let Ok(path) = std::env::var("MEOW_GEOIP_MMDB") {
        use meow_rules::country_index::CountryIndex;
        use std::collections::HashSet;
        let bytes = std::fs::read(&path).expect("read MEOW_GEOIP_MMDB");
        let reader = maxminddb::Reader::from_source(bytes).expect("open MMDB");
        let allowed: HashSet<String> = ["CN", "US"].into_iter().map(String::from).collect();
        let index = measure("CountryIndex CN + US", 2, || {
            CountryIndex::build(&reader, &allowed).expect("build CountryIndex")
        });
        drop(reader);
        for cc in ["CN", "US"] {
            let (v4, v6) = index.ranges_for(cc).interval_counts();
            println!("{cc}: {v4} IPv4 intervals, {v6} IPv6 intervals");
        }
        std::hint::black_box(index);
    }

    std::hint::black_box((domain_set, cidr_set, geosite, rules, trie));
}
