//! Parser tests for the top-level `lan-allowed-ips` /
//! `lan-disallowed-ips` inbound ACL (mihomo's `ipfilter` shape).
//!
//! These exercise [`meow_config::load_config_from_str`] end-to-end for
//! the admission matrix — omission vs. explicit `[]`, host-bit
//! normalization, malformed entries, explicit `null`, and the hard error
//! for keys nested under `listeners:` — plus the [`Config`] plumbing the
//! accept loops consume (`config.listeners.lan_acl`).

use meow_config::load_config_from_str;

async fn expect_load_err(yaml: &str) -> String {
    match load_config_from_str(yaml).await {
        Ok(_) => panic!("expected load_config_from_str to fail, but it succeeded"),
        Err(e) => e.to_string(),
    }
}

fn allows(cfg: &meow_config::Config, ip: &str) -> bool {
    cfg.listeners.lan_acl.allows(ip.parse().unwrap())
}

// ─── defaults ────────────────────────────────────────────────────────────

#[tokio::test]
async fn omitted_lists_admit_everything() {
    let cfg = load_config_from_str("mixed-port: 7890\n")
        .await
        .expect("config must load");
    for ip in ["127.0.0.1", "10.0.0.9", "192.168.1.1", "::1", "fe80::1"] {
        assert!(allows(&cfg, ip), "omitted ACL must admit {ip}");
    }
}

#[tokio::test]
async fn explicit_empty_allow_list_admits_nobody() {
    // `lan-allowed-ips: []` is not the omitted allow-all — a supplied
    // list replaces the default wholesale.
    let cfg = load_config_from_str("mixed-port: 7890\nlan-allowed-ips: []\n")
        .await
        .expect("config must load");
    for ip in ["127.0.0.1", "10.0.0.9", "::1"] {
        assert!(!allows(&cfg, ip), "explicit [] must deny {ip}");
    }
}

// ─── matching semantics ──────────────────────────────────────────────────

#[tokio::test]
async fn allow_list_scopes_admission() {
    let cfg = load_config_from_str("mixed-port: 7890\nlan-allowed-ips: [10.0.0.0/8, fd00::/8]\n")
        .await
        .expect("config must load");
    assert!(allows(&cfg, "10.9.9.9"));
    assert!(allows(&cfg, "fd00::42"));
    assert!(!allows(&cfg, "127.0.0.1"), "no implicit loopback exception");
    assert!(!allows(&cfg, "192.168.1.1"));
}

#[tokio::test]
async fn deny_wins_over_allow_overlap() {
    let cfg = load_config_from_str(
        "mixed-port: 7890\nlan-allowed-ips: [0.0.0.0/0]\nlan-disallowed-ips: [169.254.0.0/16]\n",
    )
    .await
    .expect("config must load");
    assert!(allows(&cfg, "192.0.2.1"));
    assert!(!allows(&cfg, "169.254.1.1"));
    // A supplied allow list replaces the default wholesale — with only
    // 0.0.0.0/0 allowed, IPv6 peers have no allow match.
    assert!(!allows(&cfg, "fe80::1"));
}

#[tokio::test]
async fn host_bits_normalize() {
    // Upstream `-t` accepts a CIDR carrying host bits; the stored ACL is
    // the truncated network.
    let cfg = load_config_from_str("mixed-port: 7890\nlan-allowed-ips: [10.1.2.3/24]\n")
        .await
        .expect("config must load");
    assert!(allows(&cfg, "10.1.2.99"));
    assert!(!allows(&cfg, "10.1.3.1"));
}

#[tokio::test]
async fn mapped_v4_peer_matches_v4_lists() {
    let cfg = load_config_from_str("mixed-port: 7890\nlan-allowed-ips: [10.0.0.0/8]\n")
        .await
        .expect("config must load");
    assert!(allows(&cfg, "::ffff:10.2.3.4"));
    assert!(!allows(&cfg, "::ffff:192.168.0.1"));
}

// ─── malformed values are hard errors ────────────────────────────────────

#[tokio::test]
async fn bare_ip_is_rejected() {
    let err = expect_load_err("mixed-port: 7890\nlan-allowed-ips: [10.0.0.1]\n").await;
    assert!(
        err.contains("lan-allowed-ips[0]") && err.contains("CIDR"),
        "diagnostic must name key, index and reason: {err}"
    );
}

#[tokio::test]
async fn malformed_prefix_is_rejected() {
    for bad in [
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "not-a-cidr/24",
        "10.0.0.0/abc",
        "::1/129",
    ] {
        let err = expect_load_err(&format!("lan-disallowed-ips: ['{bad}']\n")).await;
        assert!(
            err.contains("lan-disallowed-ips[0]"),
            "{bad}: diagnostic must name key and index: {err}"
        );
    }
}

#[tokio::test]
async fn element_index_in_error() {
    let err = expect_load_err("lan-allowed-ips: [10.0.0.0/8, bogus, 172.16.0.0/12]\n").await;
    assert!(err.contains("lan-allowed-ips[1]"), "{err}");
}

#[tokio::test]
async fn explicit_null_is_rejected() {
    // `null` must not decay into the allow-all default.
    for key in ["lan-allowed-ips", "lan-disallowed-ips"] {
        let err = expect_load_err(&format!("{key}: ~\n")).await;
        assert!(!err.is_empty(), "{key}: ~");
        let err = expect_load_err(&format!("{key}: null\n")).await;
        assert!(!err.is_empty(), "{key}: null");
    }
}

#[tokio::test]
async fn non_list_value_is_rejected() {
    for bad in [
        "lan-allowed-ips: 10.0.0.0/8\n",
        "lan-allowed-ips: {net: 10.0.0.0/8}\n",
    ] {
        let err = expect_load_err(bad).await;
        assert!(!err.is_empty(), "{bad}");
    }
}

// ─── placement ───────────────────────────────────────────────────────────

#[tokio::test]
async fn nested_under_listener_is_hard_error() {
    // Upstream would pass it as an unknown key — meow refuses a dead
    // access guard instead of silently ignoring it.
    let yaml = "listeners:\n  - name: lan\n    type: http\n    port: 8081\n    lan-allowed-ips: [127.0.0.0/8]\n";
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("lan") && err.contains("lan-allowed-ips") && err.contains("top-level"),
        "diagnostic must direct to the top level: {err}"
    );
}

#[tokio::test]
async fn nested_deny_key_also_errors() {
    let yaml =
        "listeners:\n  - name: lan\n    type: mixed\n    port: 8081\n    lan-disallowed-ips: []\n";
    let err = expect_load_err(yaml).await;
    assert!(err.contains("lan-disallowed-ips"), "{err}");
}

#[tokio::test]
async fn acl_does_not_change_binds() {
    // The ACL is admission control, not a bind knob: `allow-lan: false`
    // still binds loopback, and an ACL never widens it — nor narrows an
    // explicitly bound listener.
    let cfg = load_config_from_str(
        "mixed-port: 7890\nallow-lan: false\nlan-allowed-ips: [0.0.0.0/0, ::/0]\n",
    )
    .await
    .expect("config must load");
    let mixed = cfg
        .listeners
        .named
        .iter()
        .find(|l| l.name == "mixed")
        .expect("mixed shorthand");
    assert_eq!(mixed.listen, "127.0.0.1");
    assert!(allows(&cfg, "192.0.2.1"), "open ACL admits, bind stays put");
}

// ─── persistence round-trip ──────────────────────────────────────────────

#[tokio::test]
async fn saved_document_omits_unset_acl_keys() {
    // The save path emits `key: null` for unskipped Options — the ACL
    // keys must serialize only when set, or a PUT-saved file would fail
    // its own `null` check on the next boot.
    let raw = meow_config::parse_raw_yaml("mixed-port: 7890\n").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    meow_config::save_raw_config(path.to_str().unwrap(), &raw).unwrap();
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(
        !saved.contains("lan-allowed-ips") && !saved.contains("lan-disallowed-ips"),
        "unset ACL keys must not serialize: {saved}"
    );
    load_config_from_str(&saved)
        .await
        .expect("saved document must re-parse");
}
