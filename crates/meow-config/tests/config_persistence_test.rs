use meow_config::raw::{RawConfig, RawProxyGroup, RawSubscription};
use meow_config::{rebuild_from_raw, save_raw_config};
use std::collections::HashMap;

fn minimal_raw_config() -> RawConfig {
    RawConfig {
        mixed_port: Some(7890),
        mode: Some("rule".into()),
        rules: Some(vec![
            "DOMAIN,example.com,DIRECT".into(),
            "MATCH,REJECT".into(),
        ]),
        ..Default::default()
    }
}

// ── save_raw_config tests ────────────────────────────────────────

#[test]
fn save_creates_valid_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let path_str = path.to_str().unwrap();

    let raw = minimal_raw_config();
    save_raw_config(path_str, &raw).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    // Should be valid YAML that deserializes back
    let loaded: RawConfig = serde_yaml::from_str(&content).unwrap();
    assert_eq!(loaded.mixed_port, Some(7890));
    assert_eq!(loaded.mode, Some("rule".into()));
    assert_eq!(loaded.rules.as_ref().unwrap().len(), 2);
}

#[test]
fn save_creates_backup_of_existing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let bak_path = dir.path().join("config.yaml.bak");
    let path_str = path.to_str().unwrap();

    // Write original
    std::fs::write(&path, "original-content").unwrap();

    let raw = minimal_raw_config();
    save_raw_config(path_str, &raw).unwrap();

    // Backup should have original content
    assert!(bak_path.exists());
    assert_eq!(
        std::fs::read_to_string(&bak_path).unwrap(),
        "original-content"
    );

    // Main file should have new content
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("mixed-port"));
}

#[test]
fn save_no_backup_when_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let bak_path = dir.path().join("config.yaml.bak");
    let path_str = path.to_str().unwrap();

    let raw = minimal_raw_config();
    save_raw_config(path_str, &raw).unwrap();

    assert!(path.exists());
    assert!(!bak_path.exists());
}

#[test]
fn save_roundtrip_with_subscriptions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let path_str = path.to_str().unwrap();

    let mut raw = minimal_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "provider1".into(),
        url: "https://example.com/sub.yaml".into(),
        interval: Some(3600),
        last_updated: Some(1700000000),
        proxy: None,
    }]);

    save_raw_config(path_str, &raw).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let loaded: RawConfig = serde_yaml::from_str(&content).unwrap();
    let subs = loaded.subscriptions.unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].name, "provider1");
    assert_eq!(subs[0].url, "https://example.com/sub.yaml");
    assert_eq!(subs[0].interval, Some(3600));
    assert_eq!(subs[0].last_updated, Some(1700000000));
}

#[test]
fn save_roundtrip_with_proxy_groups() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let path_str = path.to_str().unwrap();

    let mut raw = minimal_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "auto".into(),
        group_type: "url-test".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        url: Some("http://www.gstatic.com/generate_204".into()),
        interval: Some(300),
        tolerance: Some(150),
        ..Default::default()
    }]);

    save_raw_config(path_str, &raw).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let loaded: RawConfig = serde_yaml::from_str(&content).unwrap();
    let groups = loaded.proxy_groups.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "auto");
    assert_eq!(groups[0].group_type, "url-test");
    assert_eq!(groups[0].tolerance, Some(150));
}

#[test]
fn save_overwrites_previous_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let bak_path = dir.path().join("config.yaml.bak");
    let path_str = path.to_str().unwrap();

    // First write
    std::fs::write(&path, "v1").unwrap();
    save_raw_config(path_str, &minimal_raw_config()).unwrap();
    assert_eq!(std::fs::read_to_string(&bak_path).unwrap(), "v1");

    // Second write — backup should now be the YAML from first save
    let first_save = std::fs::read_to_string(&path).unwrap();
    save_raw_config(path_str, &minimal_raw_config()).unwrap();
    assert_eq!(std::fs::read_to_string(&bak_path).unwrap(), first_save);
}

// ── rebuild_from_raw tests ───────────────────────────────────────

#[test]
fn rebuild_from_raw_includes_builtins() {
    let raw = minimal_raw_config();
    let proxies = rebuild_from_raw(&raw).unwrap().proxies;
    assert!(proxies.contains_key("DIRECT"));
    assert!(proxies.contains_key("REJECT"));
    assert!(proxies.contains_key("REJECT-DROP"));
}

#[test]
fn rebuild_from_raw_parses_rules() {
    let raw = minimal_raw_config();
    let rules = rebuild_from_raw(&raw).unwrap().rules;
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].payload(), "example.com");
    assert_eq!(rules[0].adapter(), "DIRECT");
}

#[test]
fn rebuild_from_raw_empty_config() {
    let raw = RawConfig::default();
    let res = rebuild_from_raw(&raw).unwrap();
    let (proxies, rules) = (res.proxies, res.rules);
    // 6 built-in adapters (DIRECT/REJECT/REJECT-DROP/COMPATIBLE/PASS/
    // PASS-RULE) + auto-created GLOBAL.
    assert_eq!(proxies.len(), 7);
    assert!(proxies.contains_key("GLOBAL"));
    assert!(rules.is_empty());
}

#[test]
fn rebuild_from_raw_with_groups() {
    let mut raw = minimal_raw_config();
    raw.proxy_groups = Some(vec![
        RawProxyGroup {
            name: "Select".into(),
            group_type: "select".into(),
            proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
            ..Default::default()
        },
        RawProxyGroup {
            name: "Auto".into(),
            group_type: "url-test".into(),
            proxies: Some(vec!["DIRECT".into()]),
            url: Some("http://test.com".into()),
            interval: Some(300),
            tolerance: Some(100),
            ..Default::default()
        },
    ]);
    let proxies = rebuild_from_raw(&raw).unwrap().proxies;
    assert!(proxies.contains_key("Select"));
    assert!(proxies.contains_key("Auto"));
    assert!(proxies.contains_key("GLOBAL"));
    // 6 built-ins + 2 groups + 1 auto-created GLOBAL
    assert_eq!(proxies.len(), 9);
}

#[test]
fn auto_global_defaults_to_final_match_group() {
    let raw: RawConfig = serde_yaml::from_str(
        r#"
proxies:
  - {name: "137.15 G | 500.00 G", type: socks5, server: 127.0.0.1, port: 1}
  - {name: "HK 01", type: socks5, server: 127.0.0.1, port: 2}
proxy-groups:
  - {name: AutoSelect, type: url-test, proxies: ["HK 01"]}
  - {name: Proxies, type: select, proxies: [AutoSelect, "HK 01"]}
rules:
  - DOMAIN,example.com,DIRECT
  - MATCH,Proxies
"#,
    )
    .unwrap();

    let proxies = rebuild_from_raw(&raw).unwrap().proxies;
    let global = proxies.get("GLOBAL").expect("auto-created GLOBAL");

    assert_eq!(global.current().as_deref(), Some("Proxies"));
    let members = global.members().expect("GLOBAL selector members");
    assert_eq!(members.first().map(String::as_str), Some("Proxies"));
    assert!(members.contains(&"137.15 G | 500.00 G".to_string()));
    assert!(members.contains(&"AutoSelect".to_string()));
    assert!(members.contains(&"HK 01".to_string()));
    assert!(members.contains(&"DIRECT".to_string()));
    assert!(members.contains(&"REJECT".to_string()));
}

/// Issue #533: the match-loop signal adapters register as real built-ins,
/// and the auto-created GLOBAL member list mirrors upstream `config.go` —
/// its provider is seeded from `proxyList` (DIRECT, REJECT, user leaves and
/// groups), so COMPATIBLE/REJECT-DROP never appear as members (COMPATIBLE
/// is only the default selection upstream) and the Pass/PassRule type tags
/// are filtered as match-loop signals.
#[test]
fn auto_global_excludes_signal_builtins() {
    let raw: RawConfig = serde_yaml::from_str(
        r#"
proxies:
  - {name: "HK 01", type: socks5, server: 127.0.0.1, port: 2}
rules:
  - MATCH,HK 01
"#,
    )
    .unwrap();
    let proxies = rebuild_from_raw(&raw).unwrap().proxies;

    use meow_common::AdapterType;
    assert_eq!(proxies["PASS"].adapter_type(), AdapterType::Pass);
    assert_eq!(proxies["PASS-RULE"].adapter_type(), AdapterType::PassRule);
    assert_eq!(
        proxies["COMPATIBLE"].adapter_type(),
        AdapterType::Compatible
    );

    let members = proxies["GLOBAL"].members().expect("GLOBAL members");
    for excluded in ["PASS", "PASS-RULE", "COMPATIBLE", "REJECT-DROP"] {
        assert!(
            !members.iter().any(|m| m == excluded),
            "{excluded} must not be a GLOBAL member"
        );
    }
    for selectable in ["DIRECT", "REJECT", "HK 01"] {
        assert!(
            members.iter().any(|m| m == selectable),
            "{selectable} stays selectable"
        );
    }
}

/// Issue #533: a `proxies:` leaf named after a built-in must not shadow
/// it — a shadowed `PASS` would silently invert "skip this rule" into
/// "proxy it". The built-in survives; the shadowing leaf is dropped with
/// a warning (upstream hard-errors on the duplicate).
#[test]
fn builtin_names_cannot_be_shadowed_by_leaf() {
    // All six built-ins are shadow-proof: a leaf named like one is dropped
    // (warn) — each name must still resolve to the built-in adapter type.
    let raw: RawConfig = serde_yaml::from_str(
        r#"
proxies:
  - {name: "PASS", type: socks5, server: 127.0.0.1, port: 9}
  - {name: "PASS-RULE", type: socks5, server: 127.0.0.1, port: 9}
  - {name: "COMPATIBLE", type: socks5, server: 127.0.0.1, port: 9}
  - {name: "DIRECT", type: socks5, server: 127.0.0.1, port: 9}
  - {name: "REJECT", type: socks5, server: 127.0.0.1, port: 9}
  - {name: "REJECT-DROP", type: socks5, server: 127.0.0.1, port: 9}
  - {name: "HK 01", type: socks5, server: 127.0.0.1, port: 2}
rules:
  - MATCH,HK 01
"#,
    )
    .unwrap();
    let proxies = rebuild_from_raw(&raw).unwrap().proxies;
    for (name, want) in [
        ("PASS", meow_common::AdapterType::Pass),
        ("PASS-RULE", meow_common::AdapterType::PassRule),
        ("COMPATIBLE", meow_common::AdapterType::Compatible),
        ("DIRECT", meow_common::AdapterType::Direct),
        ("REJECT", meow_common::AdapterType::Reject),
        ("REJECT-DROP", meow_common::AdapterType::RejectDrop),
    ] {
        assert_eq!(
            proxies[name].adapter_type(),
            want,
            "shadowing leaf must not replace the {name} built-in"
        );
    }
}

/// Issue #561: a `proxy-groups:` entry named after a built-in is a hard
/// error, matching mihomo's `proxy group %s: the duplicate name` check —
/// a warn-drop is not enough because parents may already have captured
/// the built-in before the shadowing group is dropped.
#[test]
fn builtin_names_cannot_be_shadowed_by_group() {
    let raw: RawConfig = serde_yaml::from_str(
        r#"
proxies:
  - {name: "HK 01", type: socks5, server: 127.0.0.1, port: 2}
proxy-groups:
  - {name: "REJECT", type: select, proxies: ["HK 01"]}
rules:
  - MATCH,HK 01
"#,
    )
    .unwrap();
    match rebuild_from_raw(&raw) {
        Err(err) => assert!(
            err.to_string().contains("duplicate name"),
            "unexpected error: {err}"
        ),
        Ok(_) => panic!("a group named REJECT must be rejected"),
    }
}

#[test]
fn auto_global_falls_back_to_first_declared_outbound() {
    let group_first: RawConfig = serde_yaml::from_str(
        r#"
proxies:
  - {name: "HK 01", type: socks5, server: 127.0.0.1, port: 2}
proxy-groups:
  - {name: Proxies, type: select, proxies: ["HK 01"]}
rules:
  - MATCH,DIRECT
"#,
    )
    .unwrap();
    let proxies = rebuild_from_raw(&group_first).unwrap().proxies;
    assert_eq!(
        proxies
            .get("GLOBAL")
            .and_then(|global| global.current())
            .as_deref(),
        Some("Proxies")
    );

    let proxy_only: RawConfig = serde_yaml::from_str(
        r#"
proxies:
  - {name: "HK 01", type: socks5, server: 127.0.0.1, port: 2}
rules:
  - MATCH,DIRECT
"#,
    )
    .unwrap();
    let proxies = rebuild_from_raw(&proxy_only).unwrap().proxies;
    assert_eq!(
        proxies
            .get("GLOBAL")
            .and_then(|global| global.current())
            .as_deref(),
        Some("HK 01")
    );
}

#[test]
fn user_declared_global_keeps_its_own_default() {
    let raw: RawConfig = serde_yaml::from_str(
        r#"
proxies:
  - {name: "HK 01", type: socks5, server: 127.0.0.1, port: 2}
proxy-groups:
  - {name: Proxies, type: select, proxies: ["HK 01"]}
  - {name: GLOBAL, type: select, proxies: [DIRECT, Proxies]}
rules:
  - MATCH,Proxies
"#,
    )
    .unwrap();
    let proxies = rebuild_from_raw(&raw).unwrap().proxies;
    let global = proxies.get("GLOBAL").expect("user GLOBAL");
    assert_eq!(global.current().as_deref(), Some("DIRECT"));
    assert_eq!(
        global.members().expect("GLOBAL members"),
        vec!["DIRECT".to_string(), "Proxies".to_string()]
    );
}

#[test]
fn rebuild_from_raw_skips_invalid_proxy() {
    let mut raw = minimal_raw_config();
    let mut bad_proxy = HashMap::new();
    bad_proxy.insert("name".to_string(), serde_yaml::Value::String("bad".into()));
    bad_proxy.insert(
        "type".to_string(),
        serde_yaml::Value::String("unknown_protocol".into()),
    );
    raw.proxies = Some(vec![bad_proxy]);
    // Should not fail, just skip
    let proxies = rebuild_from_raw(&raw).unwrap().proxies;
    assert!(!proxies.contains_key("bad"));
}

// ── RawConfig serialization tests ────────────────────────────────

#[test]
fn raw_config_serialize_deserialize_roundtrip() {
    let raw = minimal_raw_config();
    let yaml = serde_yaml::to_string(&raw).unwrap();
    let loaded: RawConfig = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(loaded.mixed_port, raw.mixed_port);
    assert_eq!(loaded.mode, raw.mode);
    assert_eq!(loaded.rules, raw.rules);
}

#[test]
fn raw_subscription_serde() {
    let sub = RawSubscription {
        name: "test".into(),
        url: "https://example.com".into(),
        interval: Some(7200),
        last_updated: Some(1700000000),
        proxy: None,
    };
    let yaml = serde_yaml::to_string(&sub).unwrap();
    assert!(
        !yaml.contains("proxy"),
        "absent proxy must be omitted: {yaml}"
    );
    let loaded: RawSubscription = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(loaded.name, "test");
    assert_eq!(loaded.url, "https://example.com");
    assert_eq!(loaded.interval, Some(7200));
    assert_eq!(loaded.last_updated, Some(1700000000));
    assert_eq!(loaded.proxy, None);
}

#[test]
fn raw_subscription_serde_proxy() {
    let sub = RawSubscription {
        name: "test".into(),
        url: "https://example.com".into(),
        interval: Some(7200),
        last_updated: Some(1700000000),
        proxy: Some("front".into()),
    };
    let yaml = serde_yaml::to_string(&sub).unwrap();
    assert!(yaml.contains("proxy: front"), "{yaml}");
    let loaded: RawSubscription = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(loaded.proxy.as_deref(), Some("front"));
}

#[test]
fn raw_config_clone() {
    let mut raw = minimal_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "s".into(),
        url: "u".into(),
        interval: None,
        last_updated: None,
        proxy: None,
    }]);
    let cloned = raw.clone();
    assert_eq!(cloned.mixed_port, raw.mixed_port);
    assert_eq!(
        cloned.subscriptions.as_ref().unwrap()[0].name,
        raw.subscriptions.as_ref().unwrap()[0].name
    );
}
