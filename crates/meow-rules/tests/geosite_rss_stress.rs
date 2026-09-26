//! Live-bytes stress test: 10K domains × 100K queries.
//!
//! Issue #625: this used to measure RSS via `ps`, which flakes under the
//! threaded test harness — sibling tests' allocations land inside the
//! same process RSS. The assertion now runs on a counting
//! `#[global_allocator]` (live requested bytes), and a shared lane mutex
//! keeps the two tests' measurement windows from overlapping.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Counts requested allocation sizes; `dealloc` subtracts them, so the
/// gauge reads live heap bytes — immune to RSS noise (page caching,
/// jemalloc arenas, sibling threads) that made the `ps` version flake.
struct LiveBytes;

unsafe impl GlobalAlloc for LiveBytes {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            LIVE_BYTES.fetch_add(new_size, Ordering::Relaxed);
            LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: LiveBytes = LiveBytes;

fn live_bytes() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

/// Serializes the measurement windows of the tests in this binary —
/// otherwise a parallel sibling's allocations pollute the delta.
static MEASURE_LANE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn build_geosite_db(num_domains: usize) -> meow_rules::geosite::GeositeDB {
    let mut db = meow_rules::geosite::GeositeDB::empty();
    for i in 0..num_domains {
        db.insert("test-category", &format!("domain{i}.example.com"));
    }
    db
}

#[test]
fn geosite_rss_10k_rules_100k_queries() {
    let _lane = MEASURE_LANE.lock().unwrap();
    let num_domains = 10_000;
    let num_queries = 100_000;

    let db = build_geosite_db(num_domains);

    let mut hits = 0u64;
    let mut misses = 0u64;
    for i in 0..num_queries {
        let domain = if i % 3 == 0 {
            format!("domain{}.example.com", i % num_domains)
        } else if i % 3 == 1 {
            format!("nonexistent{i}.other.org")
        } else {
            format!("Domain{}.Example.COM", i % num_domains)
        };
        if db.lookup("test-category", &domain) {
            hits += 1;
        } else {
            misses += 1;
        }
    }

    // Warm steady state reached — measure the second batch's delta.
    let live_after_100k = live_bytes();
    for i in 0..num_queries {
        let domain = format!("domain{}.example.com", i % num_domains);
        let _ = db.lookup("test-category", &domain);
    }
    let growth = live_bytes().saturating_sub(live_after_100k);
    eprintln!("10K domains, 100K→200K queries: live-bytes growth {growth} B; hits {hits}, misses {misses}");

    // Batch 1 must actually exercise the hit path — a miss-only workload
    // would make the growth assertion vacuous.
    assert!(hits > 0, "batch 1 produced zero hits — test is vacuous");
    // Lookups allocate only transient strings — live bytes must return to
    // baseline. Slack covers lazy-once interning inside the lookup path.
    assert!(
        growth <= 64 * 1024,
        "live bytes grew {growth} B between 100K→200K queries — possible leak"
    );
}

#[test]
fn geosite_rss_real_dat_100k_queries() {
    let _lane = MEASURE_LANE.lock().unwrap();
    use std::collections::HashSet;
    use std::path::PathBuf;

    let home = std::env::var("HOME").unwrap_or_default();
    let dat_path = PathBuf::from(&home).join(".config/meow/geosite.dat");
    if !dat_path.exists() {
        eprintln!("Skipping: {} not found", dat_path.display());
        return;
    }

    let allowed: HashSet<String> = ["cn", "google", "geolocation-!cn"]
        .iter()
        .map(ToString::to_string)
        .collect();

    let db = meow_rules::geosite::GeositeDB::load_from_path(&dat_path, Some(&allowed))
        .expect("load geosite.dat");

    let domains = [
        "www.google.com",
        "baidu.com",
        "www.baidu.com",
        "maps.google.com",
        "nonexistent.example.org",
        "YouTube.COM",
        "api.twitter.com",
        "GITHUB.com",
        "cdn.jsdelivr.net",
        "unknown12345.xyz",
    ];

    let num_queries = 100_000;
    let mut hits = 0u64;
    for i in 0..num_queries {
        let domain = domains[i % domains.len()];
        for cat in ["cn", "google", "geolocation-!cn"] {
            if db.lookup(cat, domain) {
                hits += 1;
            }
        }
    }

    let live_after_100k = live_bytes();
    for i in 0..num_queries {
        let domain = domains[i % domains.len()];
        for cat in ["cn", "google", "geolocation-!cn"] {
            let _ = db.lookup(cat, domain);
        }
    }
    let growth = live_bytes().saturating_sub(live_after_100k);
    eprintln!("real geosite.dat, 100K→200K queries: live-bytes growth {growth} B; hits {hits}");

    // Batch 1 must actually exercise the hit path — a zero-hit run would
    // make the growth assertion vacuous.
    assert!(hits > 0, "batch 1 produced zero hits — test is vacuous");
    assert!(
        growth <= 64 * 1024,
        "live bytes grew {growth} B between query batches — possible leak"
    );
}
