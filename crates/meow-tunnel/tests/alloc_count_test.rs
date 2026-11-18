use meow_common::{ConnType, DnsMode, Metadata, Network, Rule, RuleType};
use meow_config::load_config_from_str;
use meow_tunnel::match_engine::{match_rules, DomainIndex};
use meow_tunnel::rule_ir::{CompiledRuleSet, DemandGate, LazyMatchOutcome};
use meow_tunnel::Statistics;
use smallvec::smallvec;
use smol_str::SmolStr;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard, PoisonError};

struct CountingAlloc;

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOC_TEST_LOCK: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAlloc = CountingAlloc;

/// Serialize the measuring tests, recovering from poisoning so a failed
/// assertion in one test surfaces as that test's failure instead of
/// cascading `PoisonError`s into the rest.
///
/// The counters are process-global: anything a concurrent thread allocates
/// lands in the measuring test's window. Every test must therefore acquire
/// this lock BEFORE any allocating work — fixtures included — not just
/// before its measured section. The libtest harness itself still allocates
/// outside any lock we can take (test-thread spawn preambles, the previous
/// test's result reporting), so after acquiring, wait for the allocation
/// counter to go quiet: parked threads don't allocate, and the harness
/// settles within a few milliseconds.
fn serial() -> MutexGuard<'static, ()> {
    let guard = ALLOC_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut last = ALLOC_COUNT.load(Ordering::SeqCst);
    for _ in 0..250 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        let now = ALLOC_COUNT.load(Ordering::SeqCst);
        if now == last {
            break;
        }
        last = now;
    }
    guard
}

fn reset_counts() -> (usize, usize) {
    let a = ALLOC_COUNT.swap(0, Ordering::SeqCst);
    let d = DEALLOC_COUNT.swap(0, Ordering::SeqCst);
    (a, d)
}

fn snapshot() -> (usize, usize) {
    (
        ALLOC_COUNT.load(Ordering::SeqCst),
        DEALLOC_COUNT.load(Ordering::SeqCst),
    )
}

/// `cargo llvm-cov` instruments every binary it builds and sets
/// `LLVM_PROFILE_FILE` on the test process so it can write `.profraw` data.
/// That instrumentation injects its own heap allocations, which invalidates the
/// ADR-0008 hot-path allocation-count thresholds asserted below. When running
/// under coverage we still exercise the product code paths (so coverage data is
/// collected) but skip the count assertions, which would otherwise be flaky
/// around their boundaries. The uninstrumented `Test` workflow remains the
/// source of truth for these invariants.
fn under_coverage_instrumentation() -> bool {
    std::env::var_os("LLVM_PROFILE_FILE").is_some()
}

struct SimpleDomainRule {
    domain: String,
    adapter: String,
}

impl SimpleDomainRule {
    fn new(domain: &str, adapter: &str) -> Self {
        Self {
            domain: domain.to_lowercase(),
            adapter: adapter.to_string(),
        }
    }
}

impl Rule for SimpleDomainRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Domain
    }
    fn match_metadata(&self, metadata: &Metadata, _helper: &meow_common::RuleMatchHelper) -> bool {
        metadata.host.eq_ignore_ascii_case(&self.domain)
    }
    fn adapter(&self) -> &str {
        &self.adapter
    }
    fn payload(&self) -> &str {
        &self.domain
    }
}

struct FinalRule {
    adapter: String,
}
impl FinalRule {
    fn new(adapter: &str) -> Self {
        Self {
            adapter: adapter.to_string(),
        }
    }
}
impl Rule for FinalRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Match
    }
    fn match_metadata(&self, _: &Metadata, _: &meow_common::RuleMatchHelper) -> bool {
        true
    }
    fn adapter(&self) -> &str {
        &self.adapter
    }
    fn payload(&self) -> &str {
        ""
    }
}

fn test_metadata() -> Metadata {
    Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        host: SmolStr::new_static("example.com"),
        dst_port: 443,
        dns_mode: DnsMode::Normal,
        ..Default::default()
    }
}

#[test]
fn rule_match_zero_alloc_on_hot_path() {
    let _guard = serial();
    let long_adapter = "ProxyNameThatExceedsSmolStrInlineCapacity";
    let long_domain = "very-long-subdomain-name-that-exceeds-inline-capacity.example.com";
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(SimpleDomainRule::new(long_domain, long_adapter)),
        Box::new(FinalRule::new("DIRECT")),
    ];
    let index = DomainIndex::build(&rules);
    let meta = Metadata {
        host: SmolStr::from(long_domain),
        ..test_metadata()
    };

    // Warm up
    let _ = match_rules(&meta, &rules, &index, &|_: &str| true);

    reset_counts();
    let n = 1000;
    for _ in 0..n {
        let result = match_rules(&meta, &rules, &index, &|_: &str| true);
        let _ = std::hint::black_box(result);
    }
    let (allocs, _) = snapshot();

    let per_match = allocs as f64 / n as f64;
    println!("rule_match: {allocs} allocs for {n} iterations = {per_match:.3} per match");
    if under_coverage_instrumentation() {
        println!("skipping alloc assertion under coverage instrumentation");
        return;
    }
    // Rule matching returns borrowed adapter/payload text and the domain index
    // is sealed, so even long adapter names and payloads must not allocate.
    assert!(
        allocs == 0,
        "expected zero heap allocations per rule match, got {allocs} total ({per_match:.3}/match)"
    );
}

#[test]
fn rule_engine_pressure_zero_alloc_free_on_critical_path() {
    const ITERS: usize = 50_000;

    // Take the serialization lock before building any fixture: loading the
    // provider-backed config allocates heavily, and doing that on a
    // concurrent test thread pollutes whichever test is measuring the
    // process-global counters at that moment (observed as
    // track_connection_alloc_count "failing" at 8+ allocs/conn once the
    // geodata files exist locally). A manual runtime instead of
    // #[tokio::test] keeps the runtime construction inside the lock too.
    let _guard = serial();

    let required_providers = [
        "/Users/mlv/.config/meow/Country.mmdb",
        "/Users/mlv/.config/meow/geosite.dat",
    ];
    if let Some(missing) = required_providers
        .iter()
        .find(|path| !std::path::Path::new(path).exists())
    {
        println!("skipping provider-backed pressure test; missing {missing}");
        return;
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime must build");
    let config = runtime
        .block_on(load_config_from_str(include_str!(
            "fixtures/memleak_ech_pressure_config.yaml"
        )))
        .expect("memleak ECH pressure config must load with geodata providers");
    let rules = config.rules;
    let index = DomainIndex::build(&rules);
    let domain_hit = Metadata {
        host: SmolStr::new_static("api.maxlv.net"),
        ..test_metadata()
    };
    let geosite_hit = Metadata {
        host: SmolStr::new_static("github.com"),
        ..test_metadata()
    };
    let geoip_hit = Metadata {
        dst_ip: Some("223.5.5.5".parse().expect("valid CN DNS IP")),
        ..test_metadata()
    };
    let full_scan_final = Metadata {
        host: SmolStr::new_static("no-index-hit.example.net"),
        ..test_metadata()
    };

    // Warm up any lazy test/runtime state outside the measured critical path.
    assert_eq!(
        match_rules(&domain_hit, &rules, &index, &|_: &str| true)
            .expect("domain suffix rule should match")
            .adapter_name,
        "直连"
    );
    assert_eq!(
        match_rules(&geosite_hit, &rules, &index, &|_: &str| true)
            .expect("GEOSITE github rule should match")
            .adapter_name,
        "Github"
    );
    assert_eq!(
        match_rules(&geoip_hit, &rules, &index, &|_: &str| true)
            .expect("GEOIP CN rule should match")
            .adapter_name,
        "国内"
    );
    assert_eq!(
        match_rules(&full_scan_final, &rules, &index, &|_: &str| true)
            .expect("final rule should match")
            .adapter_name,
        "其他"
    );

    reset_counts();
    for _ in 0..ITERS {
        let domain = match_rules(
            std::hint::black_box(&domain_hit),
            std::hint::black_box(&rules),
            std::hint::black_box(&index),
            &|_: &str| true,
        );
        let geosite = match_rules(
            std::hint::black_box(&geosite_hit),
            std::hint::black_box(&rules),
            std::hint::black_box(&index),
            &|_: &str| true,
        );
        let geoip = match_rules(
            std::hint::black_box(&geoip_hit),
            std::hint::black_box(&rules),
            std::hint::black_box(&index),
            &|_: &str| true,
        );
        let full_scan = match_rules(
            std::hint::black_box(&full_scan_final),
            std::hint::black_box(&rules),
            std::hint::black_box(&index),
            &|_: &str| true,
        );
        std::hint::black_box((domain, geosite, geoip, full_scan));
    }
    let (allocs, deallocs) = snapshot();

    println!(
        "rule_engine_pressure: {allocs} allocs / {deallocs} frees across {} match calls",
        ITERS * 4
    );
    if under_coverage_instrumentation() {
        println!("skipping alloc/free assertion under coverage instrumentation");
        return;
    }
    assert_eq!(
        allocs, 0,
        "rule engine critical path allocated {allocs} times under pressure"
    );
    assert_eq!(
        deallocs, 0,
        "rule engine critical path freed heap memory {deallocs} times under pressure"
    );
}

#[test]
fn track_connection_alloc_count() {
    let _guard = serial();
    let stats = Statistics::new();
    let meta = test_metadata();

    // Warm up DashMap
    let warmup_id = stats.track_connection(
        meta.pure(),
        SmolStr::new_static("DOMAIN"),
        SmolStr::new_static("example.com"),
        smallvec![Arc::from("Proxy")],
    );
    stats.close_connection(warmup_id);

    // Now measure steady-state
    reset_counts();
    let ids: Vec<_> = (0..100)
        .map(|_| {
            stats.track_connection(
                meta.pure(),
                SmolStr::new_static("DOMAIN"),
                SmolStr::new_static("example.com"),
                smallvec![Arc::from("Proxy")],
            )
        })
        .collect();
    let (allocs, _) = snapshot();

    for id in ids {
        stats.close_connection(id);
    }

    let per_conn = allocs as f64 / 100.0;
    println!("track_connection: {allocs} allocs for 100 conns = {per_conn:.2} per connection");
    if under_coverage_instrumentation() {
        println!("skipping alloc assertion under coverage instrumentation");
        return;
    }
    // SmallVec<[Arc<str>; 1]> avoids Vec heap alloc.
    // SmolStr fields inline. itoa for timestamp avoids format!.
    // Arc<Metadata> is 1 alloc. Arc::from("Proxy") is 1 alloc.
    // Uuid::new_v4 is stack-allocated.
    // DashMap insert may alloc for bucket growth.
    // Target: ≤ 3 allocs per connection (down from ~6+ before).
    assert!(
        per_conn <= 4.0,
        "expected ≤ 4 heap allocations per track_connection, got {per_conn:.2}"
    );
}

#[test]
fn metadata_remote_address_zero_alloc() {
    let _guard = serial();
    let meta = test_metadata();

    reset_counts();
    for _ in 0..100 {
        let addr = meta.remote_address();
        // Use it in a way that doesn't allocate (comparison, not to_string)
        assert!(!format!("{addr}").is_empty());
    }
    let (allocs_display, _) = snapshot();
    // format! itself allocates a String, so expect exactly 100 allocs (one per format! call).
    // The remote_address() call itself should be zero-alloc.
    println!("remote_address + format!: {allocs_display} allocs for 100 calls");

    // Now test remote_address alone without materialization.
    // The AddrDisplay wrapper itself is zero-alloc (borrows from Metadata).
    reset_counts();
    for _ in 0..1000 {
        let addr = meta.remote_address();
        let _ = std::hint::black_box(addr);
    }
    let (allocs_bare, _) = snapshot();
    println!("remote_address (bare): {allocs_bare} allocs for 1000 calls");
    if under_coverage_instrumentation() {
        println!("skipping alloc assertion under coverage instrumentation");
        return;
    }
    assert!(
        allocs_bare <= 5,
        "remote_address() should produce near-zero heap allocations, got {allocs_bare}"
    );
}

#[test]
fn lazy_match_zero_alloc_on_clean_scan() {
    // The lazy matcher buffers dead-target skips in a SmallVec and drains
    // them only on final outcomes — a scan that never hits a dead target or
    // a demanding slot must stay allocation-free (ADR-0008).
    let _guard = serial();

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(SimpleDomainRule::new("example.com", "DIRECT")),
        Box::new(FinalRule::new("DIRECT")),
    ];
    let compiled = CompiledRuleSet::build(&rules);
    let meta = test_metadata();

    // Warm up.
    let _ = compiled.match_rules_lazy(&meta, &rules, &|_: &str| true, DemandGate::ALL);

    reset_counts();
    let n = 1000;
    for _ in 0..n {
        let outcome = compiled.match_rules_lazy(&meta, &rules, &|_: &str| true, DemandGate::ALL);
        assert!(matches!(outcome, LazyMatchOutcome::Matched(_)));
        let _ = std::hint::black_box(outcome);
    }
    let (allocs, _) = snapshot();

    let per_match = allocs as f64 / n as f64;
    println!("lazy_rule_match: {allocs} allocs for {n} iterations = {per_match:.3} per match");
    if under_coverage_instrumentation() {
        println!("skipping alloc assertion under coverage instrumentation");
        return;
    }
    assert!(
        allocs == 0,
        "expected zero heap allocations per lazy rule match, got {allocs} total ({per_match:.3}/match)"
    );
}

#[test]
fn lazy_match_zero_alloc_with_dead_target_skips() {
    // The skipped-target buffer is a SmallVec with two inline slots — one
    // or two dead-target matches per connection must still be
    // allocation-free (ADR-0008); beyond that a heap spill is acceptable
    // but bounded to once per scan.
    let _guard = serial();

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(SimpleDomainRule::new("dead-a.example", "GHOST-A")),
        Box::new(SimpleDomainRule::new("dead-b.example", "GHOST-B")),
        Box::new(SimpleDomainRule::new("example.com", "DIRECT")),
        Box::new(FinalRule::new("DIRECT")),
    ];
    let compiled = CompiledRuleSet::build(&rules);
    let meta = Metadata {
        host: "dead-a.example".into(),
        ..test_metadata()
    };
    let no_ghosts = |name: &str| !name.starts_with("GHOST");

    // Warm up.
    let _ = compiled.match_rules_lazy(&meta, &rules, &no_ghosts, DemandGate::ALL);

    reset_counts();
    let n = 1000;
    for _ in 0..n {
        let outcome = compiled.match_rules_lazy(&meta, &rules, &no_ghosts, DemandGate::ALL);
        assert!(matches!(outcome, LazyMatchOutcome::Matched(_)));
        let _ = std::hint::black_box(outcome);
    }
    let (allocs, _) = snapshot();

    let per_match = allocs as f64 / n as f64;
    println!("lazy_rule_match dead-target: {allocs} allocs for {n} = {per_match:.3}/match");
    if under_coverage_instrumentation() {
        println!("skipping alloc assertion under coverage instrumentation");
        return;
    }
    assert!(
        allocs == 0,
        "one dead-target skip must stay inline in the SmallVec, got {allocs} allocs ({per_match:.3}/match)"
    );
}
