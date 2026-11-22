use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use meow_common::{Metadata, Rule, RuleMatchHelper};
use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule, ipcidr::IpCidrRule};
use std::net::IpAddr;

fn build_rules(n: usize) -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::with_capacity(n + 1);
    for i in 0..n {
        match i % 3 {
            0 => rules.push(Box::new(DomainSuffixRule::new(
                &format!("suffix{i}.example.com"),
                "DIRECT",
            ))),
            1 => rules.push(Box::new(DomainSuffixRule::new(
                &format!("other{i}.net"),
                "Proxy",
            ))),
            _ => {
                let cidr = format!("10.{}.0.0/16", i % 256);
                if let Ok(r) = IpCidrRule::new(&cidr, "DIRECT", false, true) {
                    rules.push(Box::new(r));
                }
            }
        }
    }
    rules.push(Box::new(FinalRule::new("DIRECT")));
    rules
}

fn make_metadata_hit(n: usize) -> Metadata {
    // Host matches the last DOMAIN-SUFFIX rule inserted (worst-case scan).
    // Rules are built i % 3 == 0 → DomainSuffix. Find the last such i < n.
    let last_suffix_i = (0..n).rev().find(|&i| i % 3 == 0).unwrap_or(0);
    Metadata {
        host: format!("host.suffix{last_suffix_i}.example.com").into(),
        dst_port: 443,
        ..Default::default()
    }
}

fn make_metadata_miss() -> Metadata {
    // Hits the FINAL rule (full scan)
    Metadata {
        host: "nomatch.unknown.invalid".into(),
        dst_port: 80,
        dst_ip: Some("203.0.113.1".parse::<IpAddr>().unwrap()),
        ..Default::default()
    }
}

fn scan_rules(rules: &[Box<dyn Rule>], metadata: &Metadata) -> Option<String> {
    let helper = RuleMatchHelper;
    for rule in rules {
        if let Some(adapter) = rule.match_and_resolve(metadata, &helper, &|_: &str| true) {
            return Some(adapter.into());
        }
    }
    None
}

fn bench_rule_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scan");

    for n in [50usize, 200, 500, 10_000] {
        let rules = build_rules(n);
        let meta_hit = make_metadata_hit(n);
        let meta_miss = make_metadata_miss();

        group.bench_with_input(BenchmarkId::new("hit_last", n), &n, |b, _| {
            b.iter(|| black_box(scan_rules(black_box(&rules), black_box(&meta_hit))));
        });

        group.bench_with_input(BenchmarkId::new("miss_final", n), &n, |b, _| {
            b.iter(|| black_box(scan_rules(black_box(&rules), black_box(&meta_miss))));
        });
    }

    group.finish();
}

fn bench_classical_provider(c: &mut Criterion) {
    use meow_rules::{ClassicalRuleSet, ParserContext, RuleSet};

    let mut group = c.benchmark_group("classical_provider");
    for size in [16usize, 64, 32_768] {
        let mut entries: Vec<String> = (0..size)
            .map(|i| {
                let kind = if i % 2 == 0 {
                    "DOMAIN"
                } else {
                    "DOMAIN-SUFFIX"
                };
                format!("{kind},r{i}.example")
            })
            .collect();
        entries.push(r"DOMAIN-REGEX,^rx[0-9]+\.example$".into());
        let set = ClassicalRuleSet::from_entries(&entries, &ParserContext::empty());
        for (name, host, expected) in [
            ("first", "r0.example".to_owned(), true),
            ("last", format!("sub.r{}.example", size - 1), true),
            ("miss", "unlisted.example".to_owned(), false),
        ] {
            let meta = Metadata {
                host: host.into(),
                ..Default::default()
            };
            assert_eq!(set.matches(&meta, &RuleMatchHelper), expected);
            group.bench_function(BenchmarkId::new(name, size), |b| {
                b.iter(|| set.matches(black_box(&meta), &RuleMatchHelper));
            });
        }
        group.bench_function(BenchmarkId::new("dns_mixed_case_miss", size), |b| {
            b.iter(|| set.matches_domain(black_box("unLIsted.Example")));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_rule_scan, bench_classical_provider);
criterion_main!(benches);
