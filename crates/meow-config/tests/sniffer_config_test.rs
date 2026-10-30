//! Config-parser tests for the `sniffer:` YAML block.
//!
//! These exercise [`meow_config::load_config_from_str`] end-to-end and
//! assert on the resulting `Config.sniffer` (a [`SnifferConfig`]) — the
//! parser itself (`parse_sniffer_config`) is private.
//!
//! # Test plan coverage (S-series)
//!
//! | ID  | Description                                                            |
//! |-----|------------------------------------------------------------------------|
//! | S1  | absent `sniffer:` + absent `tproxy_sni:` → default (disabled)          |
//! | S2  | `enable: true` + no `sniff:` map at all → hard error                   |
//! | S3  | `enable: true` + `sniff:` map with no recognised protocols → hard err  |
//! | S4  | `enable: true` + `sniff.TLS.ports: [443]` → loaded, tls_ports=[443]    |
//! | S5  | `enable: true` + `sniff.HTTP.ports: [80]` → loaded, http_ports=[80]    |
//! | S6  | `enable: true` + both TLS and HTTP populated → both lists set          |
//! | S7  | Protocol keys are case-insensitive (`tls:`, `Tls:`, `TLS:` all work)   |
//! | S8  | `sniff.QUIC` is parsed but ignored (warn-only)                         |
//! | S9  | Unknown protocol key is parsed but ignored (warn-only)                 |
//! | S10 | `enable: false` + empty `sniff:` → loads (no port-presence check)      |
//! | S11 | `timeout: 0` → hard error (out of range)                               |
//! | S12 | `timeout: 60001` → hard error (out of range)                           |
//! | S13 | `timeout: 250` → loaded, Duration::from_millis(250)                    |
//! | S14 | `skip-domain` and `force-domain` lists pass through verbatim           |
//! | S15 | deprecated `tproxy_sni: true` alone → enable=true, tls=[443]           |
//! | S16 | `sniffer:` + `tproxy_sni: true` → sniffer wins; tproxy_sni ignored     |
//! | S17 | `force-dns-mapping: true` → warns and accepted; rest of config loads   |
//! | S18 | `parse-pure-ip` / `override-destination` overrides apply               |
//! | S19 | strict mode promotes an unknown protocol key to a hard error           |
//! | S20 | empty-label `skip-domain`/`force-domain`: lenient loads, strict errs   |

use meow_config::load_config_from_str;

// `Config` doesn't implement `Debug`, so `Result::expect_err` is unusable.
// This helper unwraps the `Err` arm or panics with a useful message.
async fn expect_load_err(yaml: &str) -> String {
    match load_config_from_str(yaml).await {
        Ok(_) => panic!("expected load_config_from_str to fail, but it succeeded"),
        Err(e) => e.to_string(),
    }
}

// ─── S1: defaults — neither sniffer: nor tproxy_sni: set ─────────────────

#[tokio::test]
async fn s1_no_sniffer_block_yields_default_disabled() {
    let cfg = load_config_from_str("port: 7890\n")
        .await
        .expect("config must load");
    assert!(!cfg.sniffer.enable, "default sniffer must be disabled");
    // When disabled, port lists carry the `SnifferConfig::default()` values
    // and are inert at runtime — we only assert the disable flag.
    assert!(!cfg.sniffer.override_destination);
}

// ─── S2: enable: true with no `sniff:` map at all ────────────────────────

#[tokio::test]
async fn s2_enable_true_without_sniff_map_errors() {
    let yaml = r#"
sniffer:
  enable: true
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("sniff"),
        "error must mention `sniff`: got {err}"
    );
}

// ─── S3: enable: true with sniff: map that has no recognised protos ──────

#[tokio::test]
async fn s3_enable_true_with_only_unknown_protocols_errors() {
    let yaml = r#"
sniffer:
  enable: true
  sniff:
    QUIC:
      ports: [443]
    SOMETHING:
      ports: [9999]
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("no ports"),
        "error must mention 'no ports': got {err}"
    );
}

// ─── S4: TLS ports only ──────────────────────────────────────────────────

#[tokio::test]
async fn s4_tls_only_loads() {
    let yaml = r#"
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443, 8443]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert!(cfg.sniffer.enable);
    assert_eq!(cfg.sniffer.tls_ports, vec![443, 8443]);
    assert_eq!(cfg.sniffer.http_ports, Vec::<u16>::new());
}

// ─── S5: HTTP ports only ─────────────────────────────────────────────────

#[tokio::test]
async fn s5_http_only_loads() {
    let yaml = r#"
sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert!(cfg.sniffer.enable);
    assert_eq!(cfg.sniffer.http_ports, vec![80, 8080]);
    assert_eq!(cfg.sniffer.tls_ports, Vec::<u16>::new());
}

// ─── S6: both TLS and HTTP ───────────────────────────────────────────────

#[tokio::test]
async fn s6_both_protocols_loads() {
    let yaml = r#"
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443]
    HTTP:
      ports: [80]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert_eq!(cfg.sniffer.tls_ports, vec![443]);
    assert_eq!(cfg.sniffer.http_ports, vec![80]);
}

// ─── S7: case-insensitive protocol keys ──────────────────────────────────

#[tokio::test]
async fn s7_lowercase_protocol_keys_accepted() {
    let yaml = r#"
sniffer:
  enable: true
  sniff:
    tls:
      ports: [443]
    http:
      ports: [80]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert_eq!(cfg.sniffer.tls_ports, vec![443]);
    assert_eq!(cfg.sniffer.http_ports, vec![80]);
}

// ─── S8: QUIC is ignored (warn-only) ─────────────────────────────────────

#[tokio::test]
async fn s8_quic_protocol_ignored_with_other_proto_present() {
    let yaml = r#"
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443]
    QUIC:
      ports: [443]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    // QUIC entry is silently dropped — we don't synthesise a quic_ports field.
    assert_eq!(cfg.sniffer.tls_ports, vec![443]);
    assert_eq!(cfg.sniffer.http_ports, Vec::<u16>::new());
}

// ─── S9: unknown protocol key is ignored ─────────────────────────────────

#[tokio::test]
async fn s9_unknown_protocol_ignored_with_known_proto_present() {
    let yaml = r#"
sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80]
    PIRATE-PROTOCOL:
      ports: [1337]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert_eq!(cfg.sniffer.http_ports, vec![80]);
    assert_eq!(cfg.sniffer.tls_ports, Vec::<u16>::new());
}

// ─── S10: enable: false + empty sniff is OK ──────────────────────────────

#[tokio::test]
async fn s10_disabled_with_empty_sniff_loads() {
    // No `sniff:` key at all, no error because enable is false.
    let yaml = r#"
sniffer:
  enable: false
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert!(!cfg.sniffer.enable);
}

// ─── S11/S12: timeout out of range ───────────────────────────────────────

#[tokio::test]
async fn s11_timeout_zero_errors() {
    let yaml = r#"
sniffer:
  enable: true
  timeout: 0
  sniff:
    TLS:
      ports: [443]
"#;
    let err = expect_load_err(yaml).await;
    assert!(err.contains("timeout"), "got: {err}");
}

#[tokio::test]
async fn s12_timeout_above_max_errors() {
    let yaml = r#"
sniffer:
  enable: true
  timeout: 60001
  sniff:
    TLS:
      ports: [443]
"#;
    let err = expect_load_err(yaml).await;
    assert!(err.contains("timeout"), "got: {err}");
}

// ─── S13: custom timeout in range ────────────────────────────────────────

#[tokio::test]
async fn s13_timeout_custom_value_applied() {
    let yaml = r#"
sniffer:
  enable: true
  timeout: 250
  sniff:
    TLS:
      ports: [443]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert_eq!(cfg.sniffer.timeout, std::time::Duration::from_millis(250));
}

// ─── S14: skip-domain / force-domain pass-through ────────────────────────

#[tokio::test]
async fn s14_skip_and_force_domain_passthrough() {
    let yaml = r#"
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443]
  skip-domain:
    - "*.ads.example.com"
    - tracker.evil.test
  force-domain:
    - "+.cdn.example.com"
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert_eq!(
        cfg.sniffer.skip_domain,
        vec![
            "*.ads.example.com".to_string(),
            "tracker.evil.test".to_string()
        ]
    );
    assert_eq!(
        cfg.sniffer.force_domain,
        vec!["+.cdn.example.com".to_string()]
    );
}

// ─── S15: deprecated `tproxy_sni: true` alone ────────────────────────────

#[tokio::test]
async fn s15_deprecated_tproxy_sni_alone_synthesises_minimal_config() {
    // RawConfig is `kebab-case` — the YAML key is `tproxy-sni`, mapping to
    // the `tproxy_sni` field in Rust.
    let yaml = r#"
tproxy-sni: true
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert!(cfg.sniffer.enable);
    assert_eq!(cfg.sniffer.tls_ports, vec![443]);
    assert_eq!(cfg.sniffer.http_ports, Vec::<u16>::new());
    assert!(cfg.sniffer.parse_pure_ip);
    assert!(!cfg.sniffer.override_destination);
}

// ─── S16: sniffer + tproxy_sni → sniffer wins ────────────────────────────

#[tokio::test]
async fn s16_sniffer_block_wins_when_both_present() {
    let yaml = r#"
tproxy-sni: true
sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    // sniffer block dictates: HTTP-only, no TLS — tproxy_sni's "TLS:443" is ignored.
    assert_eq!(cfg.sniffer.http_ports, vec![80]);
    assert_eq!(cfg.sniffer.tls_ports, Vec::<u16>::new());
}

// ─── S17: force-dns-mapping accepted (warn-only) ─────────────────────────

#[tokio::test]
async fn s17_force_dns_mapping_accepted_with_warn() {
    let yaml = r#"
sniffer:
  enable: true
  force-dns-mapping: true
  sniff:
    TLS:
      ports: [443]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert!(cfg.sniffer.enable);
    assert_eq!(cfg.sniffer.tls_ports, vec![443]);
    // No assertion on the warn line — `tracing` capture would couple us to
    // the global subscriber. The intent is "no hard error".
}

// ─── S18: parse-pure-ip and override-destination overrides ───────────────

#[tokio::test]
async fn s18_parse_pure_ip_and_override_destination_apply() {
    let yaml = r#"
sniffer:
  enable: true
  parse-pure-ip: false
  override-destination: true
  sniff:
    TLS:
      ports: [443]
"#;
    let cfg = load_config_from_str(yaml).await.expect("must load");
    assert!(!cfg.sniffer.parse_pure_ip);
    assert!(cfg.sniffer.override_destination);
}

// ─── S19: strict: true promotes an unknown protocol key to a hard error ──

#[tokio::test]
async fn s19_strict_unknown_protocol_is_a_hard_error() {
    let yaml = r#"
strict: true
sniffer:
  enable: true
  sniff:
    PIRATE-PROTOCOL:
      ports: [443]
    TLS:
      ports: [443]
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("PIRATE-PROTOCOL"),
        "error must name the dead key, got: {err}"
    );
}

// ─── S20: empty-label skip-domain / force-domain ─────────────────────────
//
// An empty-label entry inserts a `DomainTrie` node no query name can ever
// match — the same dead-node shape as `hosts:` (issue #822). Lenient mode
// surfaces it with a warn and loads; strict mode refuses.
#[tokio::test]
async fn s20_empty_label_domain_lists_lenient_loads_strict_errors() {
    let lenient = r#"
sniffer:
  enable: true
  skip-domain: [a..b, fine.example]
  force-domain: [+.also..bad]
  sniff:
    TLS:
      ports: [443]
"#;
    let cfg = load_config_from_str(lenient).await.expect("must load");
    assert!(
        cfg.sniffer.skip_domain.iter().any(|d| d == "a..b"),
        "the verbatim list is preserved — only observability changes"
    );

    for field in ["skip-domain", "force-domain"] {
        let strict = format!(
            "strict: true\nsniffer:\n  enable: true\n  {field}: [a..b]\n  sniff:\n    TLS:\n      ports: [443]\n"
        );
        let err = expect_load_err(&strict).await;
        assert!(
            err.contains("empty label") && err.contains(field),
            "{field}: strict must name the dead entry, got: {err}"
        );
    }
}

// ─── S21: refused-shape skip-domain / force-domain ───────────────────────
//
// An all-dots or prefix-only entry (`.`, `+.`) is refused by the sniffer
// runtime's `DomainTrie::insert` outright — no node is built at all — so
// it takes the same lenient-warn / strict-error path as an empty label
// rather than silently dropping.
#[tokio::test]
async fn s21_refused_domain_lists_lenient_loads_strict_errors() {
    for field in ["skip-domain", "force-domain"] {
        for dead in [".", "+.", "*.", ".."] {
            let lenient = format!(
                "sniffer:\n  enable: true\n  {field}: ['{dead}', fine.example]\n  sniff:\n    TLS:\n      ports: [443]\n"
            );
            load_config_from_str(&lenient)
                .await
                .unwrap_or_else(|_| panic!("{field}={dead:?} must load in lenient mode"));
            let strict = format!(
                "strict: true\nsniffer:\n  enable: true\n  {field}: ['{dead}']\n  sniff:\n    TLS:\n      ports: [443]\n"
            );
            let err = expect_load_err(&strict).await;
            assert!(
                err.contains("not a valid domain pattern") && err.contains(field),
                "{field}={dead:?}: strict must name the refused entry, got: {err}"
            );
        }
    }
}
