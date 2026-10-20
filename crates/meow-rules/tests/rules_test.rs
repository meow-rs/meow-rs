//! Comprehensive tests for all rule types, mirroring Clash rule matching behavior.

use meow_common::{Metadata, Network, Rule, RuleMatchHelper, RuleType};
use meow_rules::domain::DomainRule;
use meow_rules::domain_keyword::DomainKeywordRule;
use meow_rules::domain_regex::DomainRegexRule;
use meow_rules::domain_suffix::DomainSuffixRule;
use meow_rules::final_rule::FinalRule;
use meow_rules::ipcidr::IpCidrRule;
use meow_rules::logic::{AndRule, NotRule, OrRule};
use meow_rules::network::NetworkRule;
use meow_rules::port::PortRule;
use meow_rules::process::ProcessRule;
use meow_rules::{parse_rule as parse_rule_raw, ParserContext};

/// Shim matching the pre-`ParserContext` single-argument shape so the bulk
/// of this test suite can stay unchanged. Individual tests that need a
/// populated context (e.g. GEOIP with a real reader) can call
/// `parse_rule_raw(..., &ctx)` directly.
fn parse_rule(line: &str) -> Result<Box<dyn Rule>, String> {
    parse_rule_raw(line, &ParserContext::empty())
}

fn helper() -> RuleMatchHelper {
    RuleMatchHelper
}

fn meta(host: &str, dst_port: u16) -> Metadata {
    Metadata {
        host: host.into(),
        dst_port,
        ..Default::default()
    }
}

fn meta_ip(ip: &str, dst_port: u16) -> Metadata {
    Metadata {
        dst_ip: Some(ip.parse().unwrap()),
        dst_port,
        ..Default::default()
    }
}

// ─── DOMAIN ─────────────────────────────────────────────────────────

#[test]
fn domain_match_cases() {
    // (case label, DOMAIN pattern, request host, expected match)
    let cases: &[(&str, &str, &str, bool)] = &[
        ("exact match", "google.com", "google.com", true),
        (
            "case-insensitive: mixed-case pattern vs lowercase host",
            "Google.COM",
            "google.com",
            true,
        ),
        (
            "case-insensitive: mixed-case pattern vs uppercase host",
            "Google.COM",
            "GOOGLE.COM",
            true,
        ),
        // DOMAIN is exact-only: a subdomain must NOT match (that is DOMAIN-SUFFIX).
        ("no match: subdomain", "google.com", "www.google.com", false),
        (
            "no match: different domain",
            "google.com",
            "example.com",
            false,
        ),
    ];

    let mut failures = Vec::new();
    for (label, pattern, host, expected) in cases {
        let r = DomainRule::new(pattern, "Proxy");
        let got = r.match_metadata(&meta(host, 443), &helper());
        if got != *expected {
            failures.push(format!(
                "{label}: DOMAIN,{pattern} vs host {host} => {got}, expected {expected}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "domain match failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn domain_uses_sniff_host() {
    let r = DomainRule::new("real.com", "Proxy");
    let mut m = meta("fake.com", 443);
    m.sniff_host = "real.com".into();
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn domain_type_and_payload() {
    let r = DomainRule::new("example.com", "DIRECT");
    assert_eq!(r.rule_type(), RuleType::Domain);
    assert_eq!(r.payload(), "example.com");
    assert_eq!(r.adapter(), "DIRECT");
}

// ─── DOMAIN-SUFFIX ──────────────────────────────────────────────────

#[test]
fn domain_suffix_match_cases() {
    // (case label, DOMAIN-SUFFIX pattern, request host, expected match)
    let cases: &[(&str, &str, &str, bool)] = &[
        (
            "exact match: host equals suffix",
            "google.com",
            "google.com",
            true,
        ),
        ("subdomain: one label", "google.com", "www.google.com", true),
        (
            "subdomain: one label (mail)",
            "google.com",
            "mail.google.com",
            true,
        ),
        (
            "subdomain: multiple labels",
            "google.com",
            "a.b.c.google.com",
            true,
        ),
        // "notgoogle.com" must NOT match suffix "google.com": the suffix has to
        // start at a label boundary, not mid-label.
        (
            "no match: partial label",
            "google.com",
            "notgoogle.com",
            false,
        ),
        (
            "case-insensitive: mixed-case pattern and host",
            "Google.COM",
            "WWW.google.com",
            true,
        ),
        (
            "no match: different domain",
            "google.com",
            "example.com",
            false,
        ),
    ];

    let mut failures = Vec::new();
    for (label, pattern, host, expected) in cases {
        let r = DomainSuffixRule::new(pattern, "Proxy");
        let got = r.match_metadata(&meta(host, 443), &helper());
        if got != *expected {
            failures.push(format!(
                "{label}: DOMAIN-SUFFIX,{pattern} vs host {host} => {got}, expected {expected}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "domain-suffix match failures:\n{}",
        failures.join("\n")
    );
}

// ─── DOMAIN-KEYWORD ─────────────────────────────────────────────────

#[test]
fn domain_keyword_match_cases() {
    // (case label, DOMAIN-KEYWORD pattern, request host, expected match)
    let cases: &[(&str, &str, &str, bool)] = &[
        (
            "match: keyword as interior label",
            "google",
            "www.google.com",
            true,
        ),
        (
            "match: keyword as leading label",
            "google",
            "google.co.jp",
            true,
        ),
        (
            "case-insensitive: uppercase pattern vs lowercase host",
            "GOOGLE",
            "www.google.com",
            true,
        ),
        (
            "no match: keyword absent from host",
            "google",
            "example.com",
            false,
        ),
        (
            "partial: keyword matches a mid-label substring, not only whole labels",
            "oog",
            "google.com",
            true,
        ),
    ];

    let mut failures = Vec::new();
    for (label, pattern, host, expected) in cases {
        let r = DomainKeywordRule::new(pattern, "Proxy");
        let got = r.match_metadata(&meta(host, 443), &helper());
        if got != *expected {
            failures.push(format!(
                "{label}: DOMAIN-KEYWORD,{pattern} vs host {host} => {got}, expected {expected}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "domain-keyword match failures:\n{}",
        failures.join("\n")
    );
}

// ─── DOMAIN-REGEX ───────────────────────────────────────────────────

#[test]
fn domain_regex_match_cases() {
    // (case label, DOMAIN-REGEX pattern, request host, dst port, expected match)
    let cases: &[(&str, &str, &str, u16, bool)] = &[
        // from `domain_regex_match`
        (
            "anchored: apex domain",
            r"^(.*\.)?google\.com$",
            "google.com",
            443,
            true,
        ),
        (
            "anchored: subdomain",
            r"^(.*\.)?google\.com$",
            "www.google.com",
            443,
            true,
        ),
        // from `domain_regex_no_match`
        (
            "anchored: unrelated domain",
            r"^(.*\.)?google\.com$",
            "example.com",
            443,
            false,
        ),
        // `$` anchor must reject a lookalike that only *contains* the domain.
        (
            "anchored: suffix-lookalike must not match",
            r"^(.*\.)?google\.com$",
            "google.com.evil.net",
            443,
            false,
        ),
        // from `domain_regex_complex`
        (
            "complex: ads. label",
            r"^ad[sv]?\d*\.",
            "ads.example.com",
            80,
            true,
        ),
        (
            "complex: adv123. label",
            r"^ad[sv]?\d*\.",
            "adv123.tracker.io",
            80,
            true,
        ),
        (
            "complex: admin. must not match",
            r"^ad[sv]?\d*\.",
            "admin.example.com",
            80,
            false,
        ),
    ];

    let mut failures = Vec::new();
    for &(label, pattern, host, dst_port, expected) in cases {
        let r = DomainRegexRule::new(pattern, "Proxy").unwrap();
        let got = r.match_metadata(&meta(host, dst_port), &helper());
        if got != expected {
            failures.push(format!(
                "{label}: DOMAIN-REGEX,{pattern} vs host {host}:{dst_port} => {got}, expected {expected}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "domain-regex match failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn domain_regex_invalid() {
    assert!(DomainRegexRule::new(r"[invalid", "Proxy").is_err());
}

#[test]
fn domain_regex_type() {
    let r = DomainRegexRule::new(r"test", "Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainRegex);
}

// ─── IP-CIDR ────────────────────────────────────────────────────────

#[test]
fn ipcidr_match_cases() {
    // (label, cidr, dst ip, expected match)
    let cases: [(&str, &str, &str, bool); 8] = [
        (
            "v4 /24 low host in range",
            "192.168.1.0/24",
            "192.168.1.1",
            true,
        ),
        (
            "v4 /24 high host in range",
            "192.168.1.0/24",
            "192.168.1.254",
            true,
        ),
        (
            "v4 /24 adjacent prefix",
            "192.168.1.0/24",
            "192.168.2.1",
            false,
        ),
        (
            "v4 /24 unrelated private block",
            "192.168.1.0/24",
            "10.0.0.1",
            false,
        ),
        ("v4 /32 single host exact", "10.0.0.1/32", "10.0.0.1", true),
        (
            "v4 /32 single host neighbour",
            "10.0.0.1/32",
            "10.0.0.2",
            false,
        ),
        ("v6 /8 inside ULA prefix", "fd00::/8", "fd12::1", true),
        ("v6 /8 outside ULA prefix", "fd00::/8", "2001:db8::1", false),
    ];

    let mut failures = Vec::new();
    for (label, cidr, ip, expected) in cases {
        let r = IpCidrRule::new(cidr, "DIRECT", false, true).unwrap();
        let got = r.match_metadata(&meta_ip(ip, 80), &helper());
        if got != expected {
            failures.push(format!(
                "{label}: IP-CIDR,{cidr} vs {ip} -> expected {expected}, got {got}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "ipcidr match mismatches:\n{}",
        failures.join("\n")
    );
}

#[test]
fn ipcidr_no_ip_no_match() {
    let r = IpCidrRule::new("192.168.1.0/24", "DIRECT", false, true).unwrap();
    // No IP set -> no match
    assert!(!r.match_metadata(&meta("example.com", 80), &helper()));
}

#[test]
fn ipcidr_src_match_cases() {
    let r = IpCidrRule::new("10.0.0.0/8", "DIRECT", true, true).unwrap();
    assert_eq!(r.rule_type(), RuleType::SrcIpCidr);

    for (src_ip, expected) in [("10.1.2.3", true), ("192.168.1.1", false)] {
        let mut m = meta("", 80);
        m.src_ip = Some(src_ip.parse().unwrap());
        assert_eq!(
            r.match_metadata(&m, &helper()),
            expected,
            "src_ip {src_ip} vs 10.0.0.0/8: expected match={expected}"
        );
    }
}

#[test]
fn ipcidr_should_resolve() {
    let r = IpCidrRule::new("0.0.0.0/0", "DIRECT", false, false).unwrap();
    assert!(r.should_resolve_ip());
    let r2 = IpCidrRule::new("0.0.0.0/0", "DIRECT", false, true).unwrap();
    assert!(!r2.should_resolve_ip());
}

#[test]
fn ipcidr_invalid() {
    assert!(IpCidrRule::new("not-a-cidr", "DIRECT", false, true).is_err());
}

// ─── PORT ───────────────────────────────────────────────────────────

#[test]
fn port_match_cases() {
    // (spec, adapter, host, dst_port, expected_match)
    let cases: &[(&str, &str, &str, u16, bool)] = &[
        // port_single_match
        ("80", "DIRECT", "example.com", 80, true),
        ("80", "DIRECT", "example.com", 443, false),
        // port_range_match
        ("8000-9000", "Proxy", "", 8000, true),
        ("8000-9000", "Proxy", "", 8500, true),
        ("8000-9000", "Proxy", "", 9000, true),
        ("8000-9000", "Proxy", "", 7999, false),
        ("8000-9000", "Proxy", "", 9001, false),
        // port_multiple
        ("80,443,8080", "Proxy", "", 80, true),
        ("80,443,8080", "Proxy", "", 443, true),
        ("80,443,8080", "Proxy", "", 8080, true),
        ("80,443,8080", "Proxy", "", 8081, false),
        // port_slash_multiple
        ("80/8080/443/8443", "Proxy", "", 80, true),
        ("80/8080/443/8443", "Proxy", "", 8080, true),
        ("80/8080/443/8443", "Proxy", "", 443, true),
        ("80/8080/443/8443", "Proxy", "", 8443, true),
        ("80/8080/443/8443", "Proxy", "", 22, false),
        // port_mixed_single_and_range
        ("22,80,8000-9000", "Proxy", "", 22, true),
        ("22,80,8000-9000", "Proxy", "", 8500, true),
        ("22,80,8000-9000", "Proxy", "", 23, false),
    ];

    let mut failures = Vec::new();
    for (spec, adapter, host, port, expected) in cases {
        let r = PortRule::new(spec, adapter, false)
            .unwrap_or_else(|e| panic!("PortRule::new({spec:?}) failed: {e}"));
        let got = r.match_metadata(&meta(host, *port), &helper());
        if got != *expected {
            failures.push(format!(
                "spec {spec:?} port {port}: expected match={expected}, got {got}"
            ));
        }
    }
    assert!(failures.is_empty(), "port match mismatches: {failures:#?}");
}

#[test]
fn port_src() {
    let r = PortRule::new("12345", "Proxy", true).unwrap();
    assert_eq!(r.rule_type(), RuleType::SrcPort);
    let mut m = meta("", 80);
    m.src_port = 12345;
    assert!(r.match_metadata(&m, &helper()));
    m.src_port = 99;
    assert!(!r.match_metadata(&m, &helper()));
}

#[test]
fn port_dst_type() {
    let r = PortRule::new("80", "Proxy", false).unwrap();
    assert_eq!(r.rule_type(), RuleType::DstPort);
}

#[test]
fn port_invalid() {
    assert!(PortRule::new("abc", "Proxy", false).is_err());
    assert!(PortRule::new("99999", "Proxy", false).is_err());
}

// ─── NETWORK ────────────────────────────────────────────────────────

#[test]
fn network_match_cases() {
    // (case label, NETWORK payload, metadata network, expected match)
    let cases: &[(&str, &str, Network, bool)] = &[
        ("tcp rule vs tcp traffic", "tcp", Network::Tcp, true),
        ("tcp rule vs udp traffic", "tcp", Network::Udp, false),
        ("udp rule vs udp traffic", "udp", Network::Udp, true),
        ("udp rule vs tcp traffic", "udp", Network::Tcp, false),
    ];

    let mut failures = Vec::new();
    for (label, payload, network, expected) in cases {
        let r = NetworkRule::new(payload, "Proxy").unwrap();
        let mut m = meta("", 80);
        m.network = *network;
        let got = r.match_metadata(&m, &helper());
        if got != *expected {
            failures.push(format!(
                "{label}: NETWORK,{payload} vs metadata network {network:?} => {got}, expected {expected}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "network match failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn network_parse_validity_cases() {
    // (literal, should_parse)
    let cases: &[(&str, bool)] = &[
        ("TCP", true),   // case-insensitive accept
        ("Udp", true),   // case-insensitive accept
        ("icmp", false), // unknown network rejected
    ];
    let mut failures = Vec::new();
    for (literal, should_parse) in cases {
        let ok = NetworkRule::new(literal, "Proxy").is_ok();
        if ok != *should_parse {
            failures.push(format!(
                "NetworkRule::new({literal:?}): expected is_ok()={should_parse}, got {ok}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "network parse validity mismatches: {failures:?}"
    );
}

// ─── PROCESS-NAME ───────────────────────────────────────────────────

#[test]
fn process_match_cases() {
    // (label, rule pattern, metadata process name, expected match)
    let cases: &[(&str, &str, &str, bool)] = &[
        ("exact name matches", "chrome", "chrome", true),
        ("pattern case is ignored", "Chrome", "chrome", true),
        (
            "different process does not match",
            "chrome",
            "firefox",
            false,
        ),
    ];
    let mut failures = Vec::new();
    for &(label, pattern, process, expected) in cases {
        let r = ProcessRule::new(pattern, "Proxy");
        let mut m = meta("", 443);
        m.process = process.into();
        let got = r.match_metadata(&m, &helper());
        if got != expected {
            failures.push(format!(
                "{label}: PROCESS-NAME,{pattern} vs process {process:?} expected {expected}, got {got}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "process-name match mismatches: {failures:?}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn process_should_find() {
    let r = ProcessRule::new("chrome", "Proxy");
    assert!(r.should_find_process());
}

// ─── MATCH (FinalRule) ──────────────────────────────────────────────

#[test]
fn final_always_matches() {
    let r = FinalRule::new("DIRECT");
    assert!(r.match_metadata(&meta("anything.com", 1), &helper()));
    assert!(r.match_metadata(&meta("", 0), &helper()));
    assert!(r.match_metadata(&meta_ip("1.2.3.4", 999), &helper()));
}

#[test]
fn final_type_and_payload() {
    let r = FinalRule::new("Proxy");
    assert_eq!(r.rule_type(), RuleType::Match);
    assert_eq!(r.payload(), "");
    assert_eq!(r.adapter(), "Proxy");
}

// ─── LOGIC: AND ─────────────────────────────────────────────────────

#[test]
fn and_rule_match_cases() {
    // AndRule([DOMAIN-SUFFIX,google.com] AND [DST-PORT,443]) matches only when
    // every child rule matches.
    let cases: &[(&str, &str, u16, bool)] = &[
        ("all children match", "www.google.com", 443, true),
        (
            "domain matches but port does not",
            "www.google.com",
            80,
            false,
        ),
        (
            "port matches but domain does not",
            "example.com",
            443,
            false,
        ),
    ];

    let mut failures = Vec::new();
    for &(label, host, port, expected) in cases {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("google.com", "")),
            Box::new(PortRule::new("443", "", false).unwrap()),
        ];
        let r = AndRule::new(rules, "Proxy");
        let actual = r.match_metadata(&meta(host, port), &helper());
        if actual != expected {
            failures.push(format!(
                "case `{label}` (host={host}, port={port}): expected {expected}, got {actual}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "AndRule match mismatches:\n{}",
        failures.join("\n")
    );
}

#[test]
fn and_type() {
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new(""))];
    let r = AndRule::new(rules, "Proxy");
    assert_eq!(r.rule_type(), RuleType::And);
}

// ─── LOGIC: OR ──────────────────────────────────────────────────────

#[test]
fn or_rule_match_cases() {
    // OR([DOMAIN google.com, DOMAIN example.com]) — (host, expected):
    // first sub-rule matches, second sub-rule matches, neither matches.
    let cases: &[(&str, bool)] = &[
        ("google.com", true),
        ("example.com", true),
        ("other.com", false),
    ];

    let mut failures = Vec::new();
    for &(host, expected) in cases {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainRule::new("google.com", "")),
            Box::new(DomainRule::new("example.com", "")),
        ];
        let r = OrRule::new(rules, "Proxy");
        let got = r.match_metadata(&meta(host, 80), &helper());
        if got != expected {
            failures.push(format!(
                "OR([DOMAIN google.com, DOMAIN example.com]) vs host {host}: expected {expected}, got {got}"
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn or_type() {
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new(""))];
    let r = OrRule::new(rules, "Proxy");
    assert_eq!(r.rule_type(), RuleType::Or);
}

// ─── LOGIC: NOT ─────────────────────────────────────────────────────

#[test]
fn not_inverts_match() {
    let inner = Box::new(DomainRule::new("google.com", ""));
    let r = NotRule::new(inner, "Proxy");
    assert!(!r.match_metadata(&meta("google.com", 80), &helper()));
    assert!(r.match_metadata(&meta("example.com", 80), &helper()));
}

#[test]
fn not_type() {
    let inner = Box::new(FinalRule::new(""));
    let r = NotRule::new(inner, "Proxy");
    assert_eq!(r.rule_type(), RuleType::Not);
}

// ─── LOGIC: NESTED ──────────────────────────────────────────────────

#[test]
fn nested_not_and() {
    // NOT(DOMAIN-SUFFIX google.com AND DST-PORT 443)
    // Matches when it's NOT (google.com on port 443)
    let inner: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainSuffixRule::new("google.com", "")),
        Box::new(PortRule::new("443", "", false).unwrap()),
    ];
    let and = Box::new(AndRule::new(inner, ""));
    let r = NotRule::new(and, "Proxy");

    // google.com:443 → AND matches → NOT doesn't match
    assert!(!r.match_metadata(&meta("google.com", 443), &helper()));
    // google.com:80 → AND doesn't match → NOT matches
    assert!(r.match_metadata(&meta("google.com", 80), &helper()));
    // example.com:443 → AND doesn't match → NOT matches
    assert!(r.match_metadata(&meta("example.com", 443), &helper()));
}

#[test]
fn nested_or_and() {
    // (DOMAIN google.com) OR (DOMAIN-SUFFIX example.com AND DST-PORT 443)
    let and_rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainSuffixRule::new("example.com", "")),
        Box::new(PortRule::new("443", "", false).unwrap()),
    ];
    let or_rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainRule::new("google.com", "")),
        Box::new(AndRule::new(and_rules, "")),
    ];
    let r = OrRule::new(or_rules, "Proxy");

    assert!(r.match_metadata(&meta("google.com", 80), &helper()));
    assert!(r.match_metadata(&meta("www.example.com", 443), &helper()));
    assert!(!r.match_metadata(&meta("www.example.com", 80), &helper()));
    assert!(!r.match_metadata(&meta("other.com", 443), &helper()));
}

// ─── PARSER ─────────────────────────────────────────────────────────

#[test]
fn parse_domain() {
    let r = parse_rule("DOMAIN,google.com,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::Domain);
    assert_eq!(r.adapter(), "Proxy");
    assert!(r.match_metadata(&meta("google.com", 80), &helper()));
}

#[test]
fn parse_domain_suffix() {
    let r = parse_rule("DOMAIN-SUFFIX,google.com,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainSuffix);
    assert!(r.match_metadata(&meta("www.google.com", 80), &helper()));
}

#[test]
fn parse_domain_keyword() {
    let r = parse_rule("DOMAIN-KEYWORD,google,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainKeyword);
    assert!(r.match_metadata(&meta("google.com", 80), &helper()));
}

#[test]
fn parse_domain_regex() {
    let r = parse_rule(r"DOMAIN-REGEX,\.google\.com$,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainRegex);
    assert!(r.match_metadata(&meta("www.google.com", 80), &helper()));
    assert!(!r.match_metadata(&meta("google.com", 80), &helper()));
}

#[test]
fn parse_ip_cidr() {
    let r = parse_rule("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve").unwrap();
    assert_eq!(r.rule_type(), RuleType::IpCidr);
    assert!(r.match_metadata(&meta_ip("192.168.1.1", 80), &helper()));
    assert!(!r.match_metadata(&meta_ip("10.0.0.1", 80), &helper()));
}

#[test]
fn parse_ip_cidr6() {
    let r = parse_rule("IP-CIDR6,fd00::/8,DIRECT,no-resolve").unwrap();
    assert_eq!(r.rule_type(), RuleType::IpCidr);
    assert!(r.match_metadata(&meta_ip("fd12::1", 80), &helper()));
}

#[test]
fn parse_src_ip_cidr() {
    let r = parse_rule("SRC-IP-CIDR,10.0.0.0/8,DIRECT").unwrap();
    assert_eq!(r.rule_type(), RuleType::SrcIpCidr);
    let mut m = meta("", 80);
    m.src_ip = Some("10.1.2.3".parse().unwrap());
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_dst_port() {
    let r = parse_rule("DST-PORT,443,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DstPort);
    assert!(r.match_metadata(&meta("", 443), &helper()));
    assert!(!r.match_metadata(&meta("", 80), &helper()));
}

#[test]
fn parse_dst_port_slash_list() {
    let r = parse_rule("DST-PORT,80/8080/443/8443,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DstPort);
    assert!(r.match_metadata(&meta("", 8080), &helper()));
    assert!(r.match_metadata(&meta("", 8443), &helper()));
    assert!(!r.match_metadata(&meta("", 53), &helper()));
}

#[test]
fn parse_src_port() {
    let r = parse_rule("SRC-PORT,12345,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::SrcPort);
    let mut m = meta("", 80);
    m.src_port = 12345;
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_network() {
    let r = parse_rule("NETWORK,udp,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::Network);
    let mut m = meta("", 53);
    m.network = Network::Udp;
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_process_name() {
    let r = parse_rule("PROCESS-NAME,firefox,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::ProcessName);
    let mut m = meta("", 80);
    m.process = "firefox".into();
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_match() {
    let r = parse_rule("MATCH,DIRECT").unwrap();
    assert_eq!(r.rule_type(), RuleType::Match);
    assert!(r.match_metadata(&meta("anything", 1), &helper()));
}

#[test]
fn parse_rule_malformed_input_errors() {
    // Syntactically malformed rule lines the parser must reject. Each case is
    // labelled and every case is evaluated, so a regression names the exact
    // offending input(s) instead of stopping at the first failure.
    let cases = [
        ("too few parts: type only", "DOMAIN"),
        ("too few parts: no target", "DOMAIN,google.com"),
        ("invalid regex payload", "DOMAIN-REGEX,[bad,Proxy"),
        ("invalid CIDR payload", "IP-CIDR,not-a-cidr,DIRECT"),
    ];

    let accepted: Vec<&str> = cases
        .iter()
        .filter(|(_, line)| parse_rule(line).is_ok())
        .map(|(label, _)| *label)
        .collect();

    assert!(
        accepted.is_empty(),
        "parse_rule accepted malformed lines: {accepted:?}"
    );
}

#[test]
fn parse_geoip_error() {
    // GEOIP needs maxminddb reader, can't be parsed from string
    assert!(parse_rule("GEOIP,CN,Proxy").is_err());
}

// ─── RULE CHAIN (simulated routing) ─────────────────────────────────

#[test]
fn rule_chain_first_match_wins() {
    let rules: Vec<Box<dyn Rule>> = vec![
        parse_rule("DOMAIN-SUFFIX,google.com,Proxy").unwrap(),
        parse_rule("DOMAIN-KEYWORD,google,Fallback").unwrap(),
        parse_rule("MATCH,DIRECT").unwrap(),
    ];

    let m = meta("www.google.com", 443);
    let h = helper();

    let matched = rules.iter().find(|r| r.match_metadata(&m, &h)).unwrap();
    // First matching rule wins (DOMAIN-SUFFIX, not DOMAIN-KEYWORD)
    assert_eq!(matched.adapter(), "Proxy");
    assert_eq!(matched.rule_type(), RuleType::DomainSuffix);
}

#[test]
fn rule_chain_fallthrough_to_match() {
    let rules: Vec<Box<dyn Rule>> = vec![
        parse_rule("DOMAIN,google.com,Proxy").unwrap(),
        parse_rule("IP-CIDR,10.0.0.0/8,LAN,no-resolve").unwrap(),
        parse_rule("MATCH,DIRECT").unwrap(),
    ];

    let m = meta("unknown.example.org", 80);
    let h = helper();

    let matched = rules.iter().find(|r| r.match_metadata(&m, &h)).unwrap();
    assert_eq!(matched.adapter(), "DIRECT");
    assert_eq!(matched.rule_type(), RuleType::Match);
}

#[test]
fn rule_chain_ip_match() {
    let rules: Vec<Box<dyn Rule>> = vec![
        parse_rule("DOMAIN-SUFFIX,internal.corp,Work").unwrap(),
        parse_rule("IP-CIDR,192.168.0.0/16,LAN,no-resolve").unwrap(),
        parse_rule("IP-CIDR,10.0.0.0/8,LAN,no-resolve").unwrap(),
        parse_rule("DST-PORT,22,SSH").unwrap(),
        parse_rule("MATCH,DIRECT").unwrap(),
    ];

    let h = helper();

    // Matches domain rule
    let m1 = meta("app.internal.corp", 443);
    let r1 = rules.iter().find(|r| r.match_metadata(&m1, &h)).unwrap();
    assert_eq!(r1.adapter(), "Work");

    // Matches IP CIDR
    let m2 = meta_ip("192.168.1.100", 80);
    let r2 = rules.iter().find(|r| r.match_metadata(&m2, &h)).unwrap();
    assert_eq!(r2.adapter(), "LAN");

    // Matches port
    let m3 = meta("server.example.com", 22);
    let r3 = rules.iter().find(|r| r.match_metadata(&m3, &h)).unwrap();
    assert_eq!(r3.adapter(), "SSH");

    // Falls through to MATCH
    let m4 = meta("random.site.com", 8080);
    let r4 = rules.iter().find(|r| r.match_metadata(&m4, &h)).unwrap();
    assert_eq!(r4.adapter(), "DIRECT");
}

#[test]
fn and_rule_should_resolve_ip_recurses_into_children() {
    use meow_rules::ipcidr::IpCidrRule;
    let inner = IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap();
    let and = AndRule::new(vec![Box::new(inner)], "PROXY");
    assert!(and.should_resolve_ip());
}

// ─── IN-PORT (M1.D-1) ──────────────────────────────────────────────

#[test]
fn parse_in_port_exact_match() {
    let r = parse_rule("IN-PORT,7890,DIRECT").unwrap();
    assert_eq!(r.rule_type(), RuleType::InPort);
    let m = Metadata {
        in_port: 7890,
        ..Default::default()
    };
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_in_port_range_match() {
    let r = parse_rule("IN-PORT,100-200,PROXY").unwrap();
    let m = Metadata {
        in_port: 150,
        ..Default::default()
    };
    assert!(r.match_metadata(&m, &helper()));
    let m_below = Metadata {
        in_port: 99,
        ..Default::default()
    };
    assert!(!r.match_metadata(&m_below, &helper()));
}

#[test]
fn parse_in_port_zero_never_matches() {
    // upstream: rules/common/inport.go — in_port 0 means listener didn't populate.
    // NOT a match on the sentinel zero.
    let r = parse_rule("IN-PORT,7890,DIRECT").unwrap();
    let m = Metadata::default(); // in_port: 0
    assert!(!r.match_metadata(&m, &helper()));
}

// ─── DSCP (M1.D-1) ─────────────────────────────────────────────────

#[test]
fn parse_dscp_match_some() {
    let r = parse_rule("DSCP,46,PROXY").unwrap();
    assert_eq!(r.rule_type(), RuleType::Dscp);
    let m = Metadata {
        dscp: Some(46),
        ..Default::default()
    };
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_dscp_none_never_matches() {
    // Class A fix per ADR-0002 — upstream: rules/common/dscp.go.
    // NOT a match when dscp is None (HTTP/SOCKS5 listener).
    let r = parse_rule("DSCP,0,DIRECT").unwrap();
    let m = Metadata::default(); // dscp: None
    assert!(!r.match_metadata(&m, &helper()));
}

#[test]
fn parse_dscp_zero_matches_a_flow_marked_zero() {
    // A DSCP the inbound did read (TProxy) matches even when it is 0: only
    // an unknown DSCP (`None`, which the API shows as 0) never matches.
    let r = parse_rule("DSCP,0,DIRECT").unwrap();
    let m = Metadata {
        dscp: Some(0),
        ..Default::default()
    };
    assert!(r.match_metadata(&m, &helper()));
}

// ─── UID (M1.D-1) ──────────────────────────────────────────────────

#[test]
fn parse_uid_succeeds_cross_platform() {
    // upstream: rules/common/uid.go — UID rules are Linux-only at match time
    // but parse must succeed on every platform (Class B per ADR-0002).
    let r = parse_rule("UID,1000,DIRECT").unwrap();
    assert_eq!(r.rule_type(), RuleType::Uid);
}

#[test]
fn parse_uid_none_metadata_never_matches() {
    let r = parse_rule("UID,1000,DIRECT").unwrap();
    let m = Metadata {
        uid: None,
        ..Default::default()
    };
    assert!(!r.match_metadata(&m, &helper()));
}

// ─── SRC-GEOIP (M1.D-1) — fixture-DB-backed, skipped without reader ─

#[test]
fn parse_src_geoip_missing_reader_errors() {
    // Class A per ADR-0002 — upstream: rules/common/geoip.go (isSource path).
    // NOT a silent pass-through when reader absent.
    assert!(parse_rule("SRC-GEOIP,AU,PROXY").is_err());
}

// ─── PROCESS-PATH (M1.D-1) ─────────────────────────────────────────

#[test]
fn parse_process_path_prefix_match() {
    // Divergence from upstream exact-match (Class B per ADR-0002).
    // upstream: rules/common/process.go — exact match only.
    // NOT exact-only in our impl.
    let r = parse_rule("PROCESS-PATH,/usr/bin,PROXY").unwrap();
    assert_eq!(r.rule_type(), RuleType::ProcessPath);
    let m = Metadata {
        process_path: "/usr/bin/curl".into(),
        ..Default::default()
    };
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_process_path_different_dir_no_match() {
    let r = parse_rule("PROCESS-PATH,/usr/bin,PROXY").unwrap();
    let m = Metadata {
        process_path: "/usr/local/bin/curl".into(),
        ..Default::default()
    };
    assert!(!r.match_metadata(&m, &helper()));
}

// ─── DOMAIN-WILDCARD (M1.D-6) ──────────────────────────────────────

#[test]
fn parse_domain_wildcard_single_label() {
    let r = parse_rule("DOMAIN-WILDCARD,*.example.com,PROXY").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainWildcard);
    assert!(r.match_metadata(&meta("foo.example.com", 443), &helper()));
}

#[test]
fn parse_domain_wildcard_no_match_multi_label() {
    // upstream: rules/common/domain_wildcard.go — `*` is single-label [^.]+.
    // NOT a match on multi-label hosts.
    let r = parse_rule("DOMAIN-WILDCARD,*.example.com,PROXY").unwrap();
    assert!(!r.match_metadata(&meta("foo.bar.example.com", 443), &helper()));
}

// ─── IP-SUFFIX (M1.D-3) ────────────────────────────────────────────

#[test]
fn parse_ip_suffix_ipv4_low_byte() {
    // upstream: rules/common/ipcidr.go — IP-SUFFIX masks low bits.
    let r = parse_rule("IP-SUFFIX,0.0.0.1/8,PROXY").unwrap();
    assert_eq!(r.rule_type(), RuleType::IpSuffix);
    assert!(r.match_metadata(&meta_ip("10.20.30.1", 80), &helper()));
    assert!(!r.match_metadata(&meta_ip("10.20.30.2", 80), &helper()));
}

#[test]
fn parse_ip_suffix_invalid_payload_errors() {
    // Error message must self-identify as IP-SUFFIX (NOT IP-CIDR).
    let Err(err) = parse_rule("IP-SUFFIX,not-an-ip,PROXY") else {
        panic!("expected parse error");
    };
    assert!(err.contains("IP-SUFFIX"), "unexpected error: {err}");
}

// ─── IP-ASN (M1.D-3) — requires fixture DB, skipped without reader ─

#[test]
fn parse_ip_asn_missing_reader_hard_errors() {
    // Class A per ADR-0002 — upstream: rules/common/ipasn.go.
    // NOT a silent skip when DB missing (we reject at parse).
    let Err(err) = parse_rule("IP-ASN,13335,PROXY") else {
        panic!("expected parse error");
    };
    assert!(
        err.contains("GeoLite2-ASN"),
        "error should name the missing DB file, got: {err}"
    );
}

// ─── Parser dispatch guards (I-series) ─────────────────────────────

#[test]
fn parse_unknown_rule_type_still_errors() {
    // Guard-rail: the `_ => unknown rule type` arm was not removed.
    let Err(err) = parse_rule("MADE-UP-RULE,foo,DIRECT") else {
        panic!("expected parse error");
    };
    assert!(err.contains("unknown rule type"), "unexpected error: {err}");
}

// ─── GEOSITE (M1.D-2) ──────────────────────────────────────────────

#[test]
fn parse_geosite_without_db_tolerated_always_no_match() {
    // Class A divergence from upstream (spec §Divergences #3): upstream
    // errors at parse if DB absent; we tolerate and no-match at runtime.
    // upstream: rules/geosite.go — errors at parse if DB absent.
    let r = parse_rule("GEOSITE,cn,DIRECT").unwrap();
    assert_eq!(r.rule_type(), RuleType::GeoSite);
    assert_eq!(r.adapter(), "DIRECT");
    // No DB → no match, no panic.
    assert!(!r.match_metadata(&meta("baidu.com", 443), &helper()));
}

#[test]
fn parse_geosite_with_fixture_db_matches() {
    use meow_rules::geosite::GeositeDB;
    use meow_rules::parse_rule as parse_rule_raw;
    use meow_rules::ParserContext;
    use std::sync::Arc;

    let mut db = GeositeDB::empty();
    db.insert("cn", "baidu.com");
    db.insert("cn", "qq.com");
    db.insert("ads", "ad.example.com");
    let ctx = ParserContext {
        geosite: Some(Arc::new(db)),
        ..Default::default()
    };
    let r = parse_rule_raw("GEOSITE,cn,DIRECT", &ctx).unwrap();
    assert!(r.match_metadata(&meta("baidu.com", 443), &helper()));
    assert!(r.match_metadata(&meta("qq.com", 443), &helper()));
    assert!(!r.match_metadata(&meta("google.com", 443), &helper()));
}

#[test]
fn parse_geosite_at_suffix_filters_attribute_category() {
    // upstream: rules/geosite.go — @-attribute filters the category.
    use meow_rules::geosite::GeositeDB;
    use meow_rules::parse_rule as parse_rule_raw;
    use meow_rules::ParserContext;
    use std::sync::Arc;

    let mut db = GeositeDB::empty();
    db.insert("microsoft", "global.example");
    db.insert("microsoft@cn", "cn.example");
    let ctx = ParserContext {
        geosite: Some(Arc::new(db)),
        ..Default::default()
    };
    let r = parse_rule_raw("GEOSITE,microsoft@cn,DIRECT", &ctx).unwrap();
    assert!(r.match_metadata(&meta("cn.example", 443), &helper()));
    assert!(!r.match_metadata(&meta("global.example", 443), &helper()));
}

#[test]
fn parse_geosite_empty_category_hard_errors() {
    let Err(err) = parse_rule("GEOSITE,,DIRECT") else {
        panic!("expected parse error");
    };
    assert!(err.contains("GEOSITE"), "unexpected: {err}");
}

#[test]
fn parse_geosite_shared_arc_across_rules() {
    // F1 — multiple GEOSITE rules share one Arc<GeositeDB>.
    // Guard: constructing N rules with the same context clones the Arc,
    // it does NOT re-load or re-parse the DB per rule.
    use meow_rules::geosite::GeositeDB;
    use meow_rules::parse_rule as parse_rule_raw;
    use meow_rules::ParserContext;
    use std::sync::Arc;

    let mut db = GeositeDB::empty();
    db.insert("cn", "baidu.com");
    db.insert("ads", "ad.example.com");
    let arc = Arc::new(db);
    let ctx = ParserContext {
        geosite: Some(Arc::clone(&arc)),
        ..Default::default()
    };
    let _r1 = parse_rule_raw("GEOSITE,cn,DIRECT", &ctx).unwrap();
    let _r2 = parse_rule_raw("GEOSITE,ads,REJECT", &ctx).unwrap();
    let _r3 = parse_rule_raw("GEOSITE,geolocation-!cn,Proxy", &ctx).unwrap();
    // Each rule clones the Arc; strong_count is original (1 from `arc`)
    // + 3 (one per rule) + 1 (from ctx.geosite) = 5.
    assert_eq!(Arc::strong_count(&arc), 5);
}
