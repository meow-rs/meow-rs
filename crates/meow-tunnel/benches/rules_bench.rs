/// Rule-engine match benchmark — linear scan vs domain-index early-exit vs
/// compiled native IR (ADR-0008 §7 sub-area 0).
///
/// Fixture: `tests/fixtures/memleak_ech_pressure_config.yaml`, which exercises
/// a realistic GEOSITE/GEOIP-heavy Clash config rather than synthetic rules.
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use meow_config::raw::RawConfig;
use meow_rules::{
    domain_suffix::DomainSuffixRule, domain_wildcard::DomainWildcardRule, final_rule::FinalRule,
    ipcidr::IpCidrRule,
};
use meow_tunnel::match_engine::{match_rules, DomainIndex};
use meow_tunnel::rule_ir::CompiledRuleSet;
use std::net::IpAddr;

const ECH_PRESSURE_CONFIG: &str =
    include_str!("../tests/fixtures/memleak_ech_pressure_config.yaml");

struct FixtureCase {
    name: &'static str,
    metadata: Metadata,
    expected_rule_type: RuleType,
    expected_payload: &'static str,
}

struct BenchCase {
    name: &'static str,
    metadata: Metadata,
    expected_rule_type: RuleType,
    expected_payload: &'static str,
}

fn load_fixture_rules() -> Vec<Box<dyn Rule>> {
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(ECH_PRESSURE_CONFIG).expect("fixture config must be valid YAML");
    value
        .apply_merge()
        .expect("fixture config merge keys must expand");
    let raw: RawConfig =
        serde_yaml::from_value(value).expect("fixture config must deserialize as RawConfig");
    let rules = meow_config::rebuild_from_raw(&raw)
        .expect("fixture config rules must rebuild")
        .rules;
    assert_eq!(rules.len(), 19, "fixture rule count changed");
    rules
}

fn fixture_cases() -> Vec<FixtureCase> {
    vec![
        FixtureCase {
            name: "fixture_domain_suffix_maxlv",
            metadata: Metadata {
                host: "www.maxlv.net".into(),
                dst_port: 443,
                ..Default::default()
            },
            expected_rule_type: RuleType::DomainSuffix,
            expected_payload: "maxlv.net",
        },
        FixtureCase {
            name: "fixture_geosite_github",
            metadata: Metadata {
                host: "github.com".into(),
                dst_port: 443,
                ..Default::default()
            },
            expected_rule_type: RuleType::GeoSite,
            expected_payload: "github",
        },
        FixtureCase {
            name: "fixture_geoip_cn",
            metadata: Metadata {
                dst_port: 443,
                dst_ip: Some("223.5.5.5".parse::<IpAddr>().unwrap()),
                ..Default::default()
            },
            expected_rule_type: RuleType::GeoIp,
            expected_payload: "CN",
        },
        FixtureCase {
            name: "fixture_match_fallthrough",
            metadata: Metadata {
                host: "unmatched.invalid".into(),
                dst_port: 443,
                dst_ip: Some("203.0.113.1".parse::<IpAddr>().unwrap()),
                ..Default::default()
            },
            expected_rule_type: RuleType::Match,
            expected_payload: "",
        },
    ]
}

fn build_synthetic_rules(n: usize) -> Vec<Box<dyn Rule>> {
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
                if let Ok(rule) = IpCidrRule::new(&cidr, "DIRECT", false, true) {
                    rules.push(Box::new(rule));
                }
            }
        }
    }
    rules.push(Box::new(FinalRule::new("DIRECT")));
    rules
}

fn synthetic_10k_cases() -> Vec<BenchCase> {
    let last_suffix_i = (0..10_000).rev().find(|&i| i % 3 == 0).unwrap_or(0);
    vec![
        BenchCase {
            name: "synthetic_10k_domain_suffix_hit",
            metadata: Metadata {
                host: format!("host.suffix{last_suffix_i}.example.com").into(),
                dst_port: 443,
                ..Default::default()
            },
            expected_rule_type: RuleType::DomainSuffix,
            expected_payload: "suffix9999.example.com",
        },
        BenchCase {
            name: "synthetic_10k_match_fallthrough",
            metadata: Metadata {
                host: "nomatch.unknown.invalid".into(),
                dst_port: 80,
                dst_ip: Some("203.0.113.1".parse::<IpAddr>().unwrap()),
                ..Default::default()
            },
            expected_rule_type: RuleType::Match,
            expected_payload: "",
        },
    ]
}

fn build_synthetic_wildcard_rules(n: usize) -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::with_capacity(n + 1);
    for i in 0..n {
        rules.push(Box::new(
            DomainWildcardRule::new(&format!("*.blocked{i}.example.com"), "Proxy")
                .expect("synthetic wildcard rule must compile"),
        ));
    }
    rules.push(Box::new(FinalRule::new("DIRECT")));
    rules
}

fn synthetic_10k_wildcard_cases() -> Vec<BenchCase> {
    vec![BenchCase {
        name: "synthetic_10k_wildcard_miss",
        metadata: Metadata {
            host: "nomatch.unknown.invalid".into(),
            dst_port: 443,
            ..Default::default()
        },
        expected_rule_type: RuleType::Match,
        expected_payload: "",
    }]
}

fn scan_linear<'a>(
    rules: &'a [Box<dyn Rule>],
    metadata: &Metadata,
) -> Option<(&'a str, RuleType, &'a str)> {
    let helper = RuleMatchHelper;
    for rule in rules {
        if let Some(adapter) = rule.match_and_resolve(metadata, &helper) {
            return Some((adapter, rule.rule_type(), rule.payload()));
        }
    }
    None
}

fn assert_matchers_agree(
    rules: &[Box<dyn Rule>],
    index: &DomainIndex,
    compiled: &CompiledRuleSet,
    case: &BenchCase,
) {
    let linear = scan_linear(rules, &case.metadata);
    let indexed = match_rules(&case.metadata, rules, index, &|_| true)
        .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
    let ir = compiled
        .match_rules(&case.metadata, rules, &|_| true)
        .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));

    assert_eq!(indexed, linear, "indexed diverged for {}", case.name);
    assert_eq!(ir, linear, "IR diverged for {}", case.name);

    let Some((_, rule_type, payload)) = ir else {
        panic!("benchmark case {} did not match", case.name);
    };
    assert_eq!(rule_type, case.expected_rule_type, "{}", case.name);
    assert_eq!(payload, case.expected_payload, "{}", case.name);
}

fn bench_case_group(
    c: &mut Criterion,
    rules: &[Box<dyn Rule>],
    index: &DomainIndex,
    compiled: &CompiledRuleSet,
    case: &BenchCase,
) {
    assert_matchers_agree(rules, index, compiled, case);

    let mut group = c.benchmark_group(case.name);

    group.bench_function(BenchmarkId::new("before_linear", case.name), |b| {
        b.iter(|| black_box(scan_linear(black_box(rules), black_box(&case.metadata))));
    });

    group.bench_function(BenchmarkId::new("after_indexed", case.name), |b| {
        b.iter(|| {
            black_box(match_rules(
                black_box(&case.metadata),
                black_box(rules),
                black_box(index),
                &|_| true,
            ))
        });
    });

    group.bench_function(BenchmarkId::new("after_ir", case.name), |b| {
        b.iter(|| {
            black_box(compiled.match_rules(black_box(&case.metadata), black_box(rules), &|_| true))
        });
    });

    group.finish();
}

fn bench_fixture_rules(c: &mut Criterion) {
    let rules = load_fixture_rules();
    let index = DomainIndex::build(&rules);
    let compiled = CompiledRuleSet::build(&rules);
    let cases = fixture_cases()
        .into_iter()
        .map(|case| BenchCase {
            name: case.name,
            metadata: case.metadata,
            expected_rule_type: case.expected_rule_type,
            expected_payload: case.expected_payload,
        })
        .collect::<Vec<_>>();

    for case in &cases {
        bench_case_group(c, &rules, &index, &compiled, case);
    }
}

fn bench_synthetic_10k_rules(c: &mut Criterion) {
    let rules = build_synthetic_rules(10_000);
    let index = DomainIndex::build(&rules);
    let compiled = CompiledRuleSet::build(&rules);
    let cases = synthetic_10k_cases();

    for case in &cases {
        bench_case_group(c, &rules, &index, &compiled, case);
    }
}

fn bench_synthetic_10k_wildcard_rules(c: &mut Criterion) {
    let rules = build_synthetic_wildcard_rules(10_000);
    let index = DomainIndex::build(&rules);
    let compiled = CompiledRuleSet::build(&rules);
    let cases = synthetic_10k_wildcard_cases();

    for case in &cases {
        bench_case_group(c, &rules, &index, &compiled, case);
    }
}

criterion_group!(
    benches,
    bench_fixture_rules,
    bench_synthetic_10k_rules,
    bench_synthetic_10k_wildcard_rules
);
criterion_main!(benches);
