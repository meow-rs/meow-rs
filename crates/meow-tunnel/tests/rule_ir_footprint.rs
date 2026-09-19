//! Opt-in memory-footprint measurement for the rule IR.
//!
//! Run:
//!
//! ```text
//! cargo test -p meow-tunnel --test rule_ir_footprint --release -- --ignored --nocapture
//! ```

use meow_common::{Metadata, Rule, RuleMatchHelper};
use meow_config::raw::RawConfig;
use meow_tunnel::match_engine::{match_rules, DomainIndex};
use meow_tunnel::rule_ir::CompiledRuleSet;
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

const ECH_PRESSURE_CONFIG: &str = include_str!("fixtures/memleak_ech_pressure_config.yaml");
const HOT_LOOP_ITERS: usize = 100_000;

struct CountingAlloc;

static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static DEALLOCS: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        DEALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        DEALLOC_BYTES.fetch_add(old_layout.size() as u64, Ordering::Relaxed);
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        DEALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, old_layout, new_size) }
    }
}

#[derive(Debug, Clone, Copy)]
struct AllocSnapshot {
    allocated_bytes: u64,
    deallocated_bytes: u64,
    live_bytes: i64,
    allocations: u64,
    deallocations: u64,
    live_allocations: i64,
}

fn reset_allocs() {
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    DEALLOC_BYTES.store(0, Ordering::Relaxed);
    ALLOCS.store(0, Ordering::Relaxed);
    DEALLOCS.store(0, Ordering::Relaxed);
}

fn alloc_snapshot() -> AllocSnapshot {
    let allocated_bytes = ALLOC_BYTES.load(Ordering::Relaxed);
    let deallocated_bytes = DEALLOC_BYTES.load(Ordering::Relaxed);
    let allocations = ALLOCS.load(Ordering::Relaxed);
    let deallocations = DEALLOCS.load(Ordering::Relaxed);
    AllocSnapshot {
        allocated_bytes,
        deallocated_bytes,
        live_bytes: allocated_bytes as i64 - deallocated_bytes as i64,
        allocations,
        deallocations,
        live_allocations: allocations as i64 - deallocations as i64,
    }
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, AllocSnapshot) {
    reset_allocs();
    let value = f();
    let snapshot = alloc_snapshot();
    (value, snapshot)
}

fn load_raw_fixture() -> RawConfig {
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(ECH_PRESSURE_CONFIG).expect("fixture config must be valid YAML");
    value
        .apply_merge()
        .expect("fixture config merge keys must expand");
    serde_yaml::from_value(value).expect("fixture config must deserialize as RawConfig")
}

fn fixture_cases() -> Vec<Metadata> {
    vec![
        Metadata {
            host: "www.maxlv.net".into(),
            dst_port: 443,
            ..Default::default()
        },
        Metadata {
            host: "github.com".into(),
            dst_port: 443,
            ..Default::default()
        },
        Metadata {
            dst_port: 443,
            dst_ip: Some("223.5.5.5".parse::<IpAddr>().unwrap()),
            ..Default::default()
        },
        Metadata {
            host: "unmatched.invalid".into(),
            dst_port: 443,
            dst_ip: Some("203.0.113.1".parse::<IpAddr>().unwrap()),
            ..Default::default()
        },
    ]
}

fn scan_linear<'a>(rules: &'a [Box<dyn Rule>], metadata: &Metadata) -> Option<&'a str> {
    let helper = RuleMatchHelper;
    for rule in rules {
        if let Some(adapter) = rule.match_and_resolve(metadata, &helper) {
            return Some(adapter);
        }
    }
    None
}

fn measure_hot_loop(
    rules: &[Box<dyn Rule>],
    index: &DomainIndex,
    compiled: &CompiledRuleSet,
    cases: &[Metadata],
    matcher: Matcher,
) -> AllocSnapshot {
    reset_allocs();
    for _ in 0..HOT_LOOP_ITERS {
        for metadata in cases {
            match matcher {
                Matcher::Linear => {
                    std::hint::black_box(scan_linear(
                        std::hint::black_box(rules),
                        std::hint::black_box(metadata),
                    ));
                }
                Matcher::Indexed => {
                    std::hint::black_box(match_rules(
                        std::hint::black_box(metadata),
                        std::hint::black_box(rules),
                        std::hint::black_box(index),
                        &|_| true,
                    ));
                }
                Matcher::Ir => {
                    std::hint::black_box(compiled.match_rules(
                        std::hint::black_box(metadata),
                        std::hint::black_box(rules),
                        &|_| true,
                    ));
                }
            }
        }
    }
    alloc_snapshot()
}

#[derive(Debug, Clone, Copy)]
enum Matcher {
    Linear,
    Indexed,
    Ir,
}

fn rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                return rest
                    .split_whitespace()
                    .next()
                    .and_then(|kb| kb.parse().ok());
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    {
        let pid = std::process::id().to_string();
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid])
            .output()
            .ok()?;
        String::from_utf8_lossy(&output.stdout).trim().parse().ok()
    }
}

fn print_alloc_row(label: &str, snapshot: AllocSnapshot) {
    println!(
        "{label:<28} alloc={:>10} B dealloc={:>10} B live={:>10} B allocs={:>7} deallocs={:>7} live_allocs={:>6}",
        snapshot.allocated_bytes,
        snapshot.deallocated_bytes,
        snapshot.live_bytes,
        snapshot.allocations,
        snapshot.deallocations,
        snapshot.live_allocations
    );
}

#[test]
#[ignore = "memory-footprint measurement; opt in with --ignored --nocapture"]
fn rule_ir_fixture_memory_footprint() {
    let rss_start = rss_kb();

    let raw = load_raw_fixture();
    let (rebuilt, rules_alloc) = measure(|| meow_config::rebuild_from_raw(&raw));
    let rules = match rebuilt {
        Ok(res) => res.rules,
        // The fixture contains GEOIP rules that eagerly load the local GeoIP/
        // geosite databases (resolved under `~/.config/meow`). Those data files
        // are absent on CI and most dev machines, so skip the measurement
        // instead of failing — this is an opt-in footprint probe, not a
        // correctness gate. Run it where the geo databases exist.
        Err(e) => {
            eprintln!(
                "skipping rule_ir_fixture_memory_footprint: fixture rebuild failed \
                 (likely missing GeoIP/geosite data): {e:#}"
            );
            return;
        }
    };
    assert_eq!(rules.len(), 19, "fixture rule count changed");
    let rss_after_rules = rss_kb();

    let (index, index_alloc) = measure(|| DomainIndex::build(&rules));
    let rss_after_index = rss_kb();

    let (compiled, ir_alloc) = measure(|| CompiledRuleSet::build(&rules));
    let rss_after_ir = rss_kb();

    let cases = fixture_cases();

    let linear_hot = measure_hot_loop(&rules, &index, &compiled, &cases, Matcher::Linear);
    let indexed_hot = measure_hot_loop(&rules, &index, &compiled, &cases, Matcher::Indexed);
    let ir_hot = measure_hot_loop(&rules, &index, &compiled, &cases, Matcher::Ir);

    println!("\n=== rule IR fixture memory footprint ===");
    println!("fixture rules: {}", rules.len());
    println!(
        "hot loop: {HOT_LOOP_ITERS} iterations x {} cases",
        cases.len()
    );
    if let Some(kb) = rss_start {
        println!("rss start:        {kb:>8} KiB");
    }
    if let Some(kb) = rss_after_rules {
        println!("rss after rules:  {kb:>8} KiB");
    }
    if let Some(kb) = rss_after_index {
        println!("rss after index:  {kb:>8} KiB");
    }
    if let Some(kb) = rss_after_ir {
        println!("rss after IR:     {kb:>8} KiB");
    }
    println!();
    print_alloc_row("parse rules", rules_alloc);
    print_alloc_row("legacy DomainIndex", index_alloc);
    print_alloc_row("CompiledRuleSet", ir_alloc);
    println!();
    print_alloc_row("hot loop linear", linear_hot);
    print_alloc_row("hot loop indexed", indexed_hot);
    print_alloc_row("hot loop IR", ir_hot);

    std::hint::black_box((rules, index, compiled));
}
