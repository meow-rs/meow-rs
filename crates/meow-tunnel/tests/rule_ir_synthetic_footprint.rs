//! Opt-in retained-heap measurement for the compiled rule IR over a
//! synthetic config shaped like a real ~7.5k-rule one (no geo databases
//! needed, unlike `rule_ir_footprint`). Run:
//!
//! ```text
//! cargo test -p meow-tunnel --test rule_ir_synthetic_footprint --release -- --ignored --nocapture
//! ```

use meow_common::Rule;
use meow_rules::{parse_rule, ParserContext};
use meow_tunnel::rule_ir::CompiledRuleSet;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

struct CountingAlloc;

static LIVE_BYTES: AtomicI64 = AtomicI64::new(0);
static LIVE_ALLOCS: AtomicI64 = AtomicI64::new(0);

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE_BYTES.fetch_add(layout.size() as i64, Ordering::Relaxed);
        LIVE_ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size() as i64, Ordering::Relaxed);
        LIVE_ALLOCS.fetch_sub(1, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        LIVE_BYTES.fetch_add(
            new_size as i64 - old_layout.size() as i64,
            Ordering::Relaxed,
        );
        unsafe { System.realloc(ptr, old_layout, new_size) }
    }
}

fn measure<T>(label: &str, units: usize, f: impl FnOnce() -> T) -> T {
    let bytes = LIVE_BYTES.load(Ordering::Relaxed);
    let allocs = LIVE_ALLOCS.load(Ordering::Relaxed);
    let value = f();
    let retained = LIVE_BYTES.load(Ordering::Relaxed) - bytes;
    let live = LIVE_ALLOCS.load(Ordering::Relaxed) - allocs;
    println!(
        "{label:<30} retained={:>8} KiB ({:>6.1} B/unit) live_allocs={live:>7}",
        retained / 1024,
        retained as f64 / units.max(1) as f64
    );
    value
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
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
    "music", "cloud", "app", "edge", "assets", "media", "data", "files", "update", "push", "sync",
    "store", "play", "game", "live", "chat", "pay", "ads", "track", "stat", "log",
];
const TLDS: &[&str] = &[
    "com", "net", "org", "cn", "com.cn", "io", "co", "me", "tv", "cc",
];
const ADAPTERS: &[&str] = &["DIRECT", "Proxies", "Google", "Crypto", "Scholar", "REJECT"];

fn synth_lines(n: usize) -> Vec<String> {
    let mut rng = Rng(7);
    let mut lines = Vec::with_capacity(n + 1);
    for _ in 0..n {
        let adapter = ADAPTERS[rng.below(ADAPTERS.len())];
        let domain = format!(
            "{}{}.{}",
            WORDS[rng.below(WORDS.len())],
            rng.below(4000),
            TLDS[rng.below(TLDS.len())]
        );
        let line = match rng.below(100) {
            0..=87 => format!("DOMAIN-SUFFIX,{domain},{adapter}"),
            88..=93 => {
                let prefix = 8 + rng.below(17) as u8;
                let addr = (rng.next() as u32) & (u32::MAX << (32 - prefix));
                format!(
                    "IP-CIDR,{}/{prefix},{adapter},no-resolve",
                    std::net::Ipv4Addr::from(addr)
                )
            }
            94..=97 => format!(
                "DOMAIN-KEYWORD,{}{},{adapter}",
                WORDS[rng.below(WORDS.len())],
                rng.below(100)
            ),
            _ => format!("DOMAIN,{domain},{adapter}"),
        };
        lines.push(line);
    }
    lines.push("MATCH,Proxies".to_string());
    lines
}

#[test]
#[ignore = "retained-heap measurement; opt in with --ignored --nocapture"]
fn rule_ir_synthetic_retained_heap() {
    let lines = synth_lines(7_500);
    let ctx = ParserContext::empty();
    let rules: Vec<Box<dyn Rule>> = measure("parse 7.5k rules", lines.len(), || {
        lines
            .iter()
            .map(|l| parse_rule(l, &ctx).expect("synthetic line parses"))
            .collect()
    });
    let compiled = measure("CompiledRuleSet::build", rules.len(), || {
        CompiledRuleSet::build(&rules)
    });
    println!(
        "live slots: {} (of {} rules), linear plan: {}",
        compiled.len(),
        rules.len(),
        compiled.uses_linear_scan_plan()
    );
    std::hint::black_box((rules, compiled));
}
