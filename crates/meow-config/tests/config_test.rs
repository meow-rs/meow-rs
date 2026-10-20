use meow_config::{load_config_from_str, ListenerSpec};

// Some tests use #[tokio::test] because ShadowsocksAdapter plugin startup
// internally requires a tokio runtime (tokio::process::Command).

#[tokio::test]
async fn test_minimal_config() {
    let yaml = r#"
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.mixed_port, Some(7890));
    assert!(config.listeners.socks_port.is_none());
    assert!(config.listeners.http_port.is_none());
    // Default mode is Rule
    assert_eq!(config.general.mode.to_string(), "rule");
    // Built-in proxies: DIRECT, REJECT, REJECT-DROP, COMPATIBLE, PASS, PASS-RULE
    assert!(config.proxies.contains_key("DIRECT"));
    assert!(config.proxies.contains_key("REJECT"));
    assert!(config.proxies.contains_key("REJECT-DROP"));
    assert!(!config.general.connection_notes);
    assert!(config.general.logbook, "the logbook is on by default");
}

#[tokio::test]
async fn test_connection_notes_flag() {
    let config = load_config_from_str("connection-notes: true\n")
        .await
        .unwrap();
    assert!(config.general.connection_notes);
}

#[tokio::test]
async fn test_logbook_switch() {
    for (yaml, enabled) in [
        ("logbook:\n  enable: false\n", false),
        ("logbook:\n  enable: true\n", true),
        ("logbook: {}\n", true),
    ] {
        let config = load_config_from_str(yaml).await.unwrap();
        assert_eq!(config.general.logbook, enabled, "{yaml}");
    }
}

#[tokio::test]
async fn test_proxy_group_forward_reference_preserves_nested_group() {
    let yaml = r#"
proxies:
  - name: node-a
    type: socks5
    server: 127.0.0.1
    port: 10001
  - name: node-b
    type: socks5
    server: 127.0.0.1
    port: 10002

proxy-groups:
  - name: upper-selector
    type: select
    proxies:
      - failover
      # Preserve the existing lenient behavior in the referencing group too.
      - missing-upper-member
  - name: failover
    type: fallback
    url: https://www.gstatic.com/generate_204
    interval: 300
    proxies:
      - node-a
      - node-b
      # This missing member prevented the referenced group from resolving in
      # the strict pass and triggered the forward-reference regression.
      - missing-fallback-member
"#;

    let config = load_config_from_str(yaml).await.unwrap();
    let selector = config
        .proxies
        .get("upper-selector")
        .expect("forward-referencing selector must be built");
    let fallback = config
        .proxies
        .get("failover")
        .expect("referenced fallback group must be built");

    assert_eq!(selector.members().unwrap(), ["failover"]);
    assert_eq!(selector.current().as_deref(), Some("failover"));
    assert_eq!(fallback.members().unwrap(), ["node-a", "node-b"]);
    assert_eq!(fallback.current().as_deref(), Some("node-a"));
}

/// Issue #561: a group may not reuse the name of an existing registry
/// entry. Before the duplicate-name check, this config built: `parent`
/// captured the leaf `child`, then the group `child` replaced the
/// registry entry — parent and registry disagreed about the name.
/// Mirroring mihomo (`proxy group %s: the duplicate name`), the load now
/// fails instead.
#[tokio::test]
async fn test_group_name_colliding_with_leaf_proxy_is_rejected() {
    let yaml = r#"
proxies:
  - name: child
    type: socks5
    server: 127.0.0.1
    port: 10001
  - name: node-a
    type: socks5
    server: 127.0.0.1
    port: 10002

proxy-groups:
  - name: parent
    type: select
    proxies:
      - child
  - name: child
    type: select
    proxies:
      - node-a
"#;

    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a group named after a leaf proxy must be rejected");
    assert!(
        err.to_string().contains("duplicate name"),
        "unexpected error: {err}"
    );
}

/// Issue #561's minimal config: two `child` declarations, the later one
/// unresolvable. Previously `parent` captured the first `child` while the
/// lenient second pass replaced the registry entry with the last-built
/// one — two different objects under one name.
#[tokio::test]
async fn test_duplicate_group_names_are_rejected() {
    let yaml = r#"
proxies:
  - name: node-a
    type: socks5
    server: 127.0.0.1
    port: 10001
  - name: node-b
    type: socks5
    server: 127.0.0.1
    port: 10002

proxy-groups:
  - name: parent
    type: select
    proxies:
      - child
  - name: child
    type: select
    proxies:
      - node-a
  - name: child
    type: select
    proxies:
      - missing-group
      - node-b
"#;

    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("duplicate group names must be rejected");
    assert!(
        err.to_string().contains("duplicate name"),
        "unexpected error: {err}"
    );
}

/// The duplicate check is declaration-level: a later same-named block
/// that could never build (unknown type) is still a duplicate, not a
/// benign extra declaration.
#[tokio::test]
async fn test_duplicate_group_name_rejected_even_when_last_block_is_invalid() {
    let yaml = r#"
proxy-groups:
  - name: child
    type: select
    proxies: [DIRECT]
  - name: child
    type: not-a-real-type
"#;

    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a duplicate that cannot build must still be rejected");
    assert!(
        err.to_string().contains("duplicate name"),
        "unexpected error: {err}"
    );
}

/// The mirror ordering fails too: an unbuildable *first* declaration does
/// not hide the duplicate — the check scans declarations, not
/// successfully-built groups.
#[tokio::test]
async fn test_duplicate_group_name_rejected_even_when_first_block_is_invalid() {
    let yaml = r#"
proxy-groups:
  - name: child
    type: not-a-real-type
  - name: child
    type: select
    proxies: [DIRECT]
"#;

    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a duplicate whose first block cannot build is still a duplicate");
    assert!(
        err.to_string().contains("duplicate name"),
        "unexpected error: {err}"
    );
}

/// `proxies:` leaf duplicates keep the documented last-wins behavior —
/// every leaf settles before any group captures members, so a same-named
/// leaf cannot split the registry the way group duplicates did. This is a
/// deliberate divergence from upstream, which hard-errors on leaf
/// duplicates (`proxy %s is the duplicate name`).
#[tokio::test]
async fn test_duplicate_leaf_proxy_names_still_last_wins() {
    let yaml = r#"
proxies:
  - name: node
    type: socks5
    server: 127.0.0.1
    port: 10001
  - name: node
    type: direct
proxy-groups:
  - name: g
    type: select
    proxies: [node]
rules:
  - MATCH,g
"#;

    let config = load_config_from_str(yaml)
        .await
        .expect("duplicate proxies: entries stay last-wins");
    assert_eq!(
        config.proxies["node"].adapter_type(),
        meow_common::AdapterType::Direct,
        "the last-declared block wins the registry slot"
    );
}

/// A group may not shadow a built-in either — every built-in is a
/// registry entry, so a same-named group would split parents that
/// captured the built-in from rules resolving the name.
#[tokio::test]
async fn test_group_name_colliding_with_builtin_is_rejected() {
    for name in [
        "DIRECT",
        "REJECT",
        "REJECT-DROP",
        "COMPATIBLE",
        "PASS",
        "PASS-RULE",
    ] {
        let yaml = format!(
            r#"
proxy-groups:
  - name: {name}
    type: select
    proxies: [REJECT]
"#
        );

        let err = load_config_from_str(&yaml)
            .await
            .err()
            .unwrap_or_else(|| panic!("a group named {name} must be rejected"));
        assert!(
            err.to_string().contains("duplicate name"),
            "{name}: unexpected error: {err}"
        );
    }

    // Registry keys are case-sensitive (byte-exact, like upstream's
    // map[string]): a lowercase `direct` group is a distinct name.
    let yaml = r#"
proxy-groups:
  - name: direct
    type: select
    proxies: [DIRECT]
"#;
    load_config_from_str(yaml)
        .await
        .expect("names are matched byte-exactly — 'direct' is not 'DIRECT'");
}

/// Issue #562: a declared group cycle must be rejected with its path —
/// previously the lenient pass silently truncated the unresolvable edge
/// and the result depended on declaration order.
#[tokio::test]
async fn test_group_cycle_is_rejected_both_declaration_orders() {
    // The reported path starts at the first-declared cycle member.
    for (groups, want) in [
        (
            "  - {name: A, type: select, proxies: [B, DIRECT]}\n  - {name: B, type: select, proxies: [A]}",
            "A -> B -> A",
        ),
        (
            "  - {name: B, type: select, proxies: [A]}\n  - {name: A, type: select, proxies: [B, DIRECT]}",
            "B -> A -> B",
        ),
    ] {
        let yaml = format!("proxy-groups:\n{groups}\n");
        let err = load_config_from_str(&yaml)
            .await
            .err()
            .unwrap_or_else(|| panic!("a declared group cycle must be rejected: {groups}"));
        assert!(
            err.to_string()
                .contains(&format!("proxy-group cycle detected: {want}")),
            "unexpected error for {groups}: {err}"
        );
    }
}

/// Self-reference is a degenerate cycle.
#[tokio::test]
async fn test_group_self_reference_is_rejected() {
    let yaml = r#"
proxy-groups:
  - {name: A, type: select, proxies: [A, DIRECT]}
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a self-referencing group must be rejected");
    assert!(
        err.to_string()
            .contains("proxy-group cycle detected: A -> A"),
        "unexpected error: {err}"
    );
}

/// A cycle with no usable leaf members is still a declared cycle — the
/// rejection is declaration-level, not "we happened to have a fallback".
#[tokio::test]
async fn test_group_cycle_without_leaf_members_is_rejected() {
    let yaml = r#"
proxy-groups:
  - {name: A, type: select, proxies: [B]}
  - {name: B, type: select, proxies: [A]}
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a leafless group cycle must be rejected");
    assert!(
        err.to_string().contains("proxy-group cycle detected"),
        "unexpected error: {err}"
    );
}

/// A diamond (A→B, A→C, B→D, C→D) is NOT a cycle — `Done` marks must not
/// be misread as back-edges. And a tail feeding a cycle reports the
/// cycle path, not the tail.
#[tokio::test]
async fn test_group_diamond_builds_and_tail_cycle_reports_cycle_only() {
    let yaml = r#"
proxies:
  - {name: node-a, type: socks5, server: 127.0.0.1, port: 10001}

proxy-groups:
  - {name: A, type: select, proxies: [B, C]}
  - {name: B, type: select, proxies: [D]}
  - {name: C, type: select, proxies: [D]}
  - {name: D, type: select, proxies: [node-a]}
"#;
    load_config_from_str(yaml)
        .await
        .expect("a diamond is acyclic and must build");

    let yaml = r#"
proxy-groups:
  - {name: tail, type: select, proxies: [A]}
  - {name: A, type: select, proxies: [B, DIRECT]}
  - {name: B, type: select, proxies: [A]}
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a tail feeding a cycle must be rejected");
    // The reported path is the cycle, excluding the `tail` prefix.
    assert!(
        err.to_string().contains("A -> B -> A"),
        "unexpected error: {err}"
    );
    assert!(
        !err.to_string().contains("tail"),
        "tail must not appear in the cycle path: {err}"
    );
}

/// Edges only come from `proxies:` members naming a declared group —
/// a member that names no declared group (missing leaf, leaf proxy,
/// provider slot) never participates, so an acyclic forward reference
/// with a missing leaf keeps the lenient #536 behavior.
#[tokio::test]
async fn test_acyclic_group_chain_with_missing_leaf_still_builds() {
    let yaml = r#"
proxies:
  - {name: node-a, type: socks5, server: 127.0.0.1, port: 10001}

proxy-groups:
  - {name: outer, type: select, proxies: [inner, ghost-leaf]}
  - {name: inner, type: select, proxies: [node-a]}
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("forward reference with a missing leaf must still build");
    let outer = config.proxies.get("outer").expect("outer must be built");
    assert_eq!(outer.members().unwrap(), ["inner"]);
}

/// A deeper cycle (A→B→C→A) reports the full path through every hop.
#[tokio::test]
async fn test_group_three_node_cycle_reports_full_path() {
    let yaml = r#"
proxy-groups:
  - {name: A, type: select, proxies: [B]}
  - {name: B, type: select, proxies: [C]}
  - {name: C, type: select, proxies: [A]}
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a three-node group cycle must be rejected");
    assert!(
        err.to_string()
            .contains("proxy-group cycle detected: A -> B -> C -> A"),
        "unexpected error: {err}"
    );
}

/// A declared `GLOBAL` group is legal (it suppresses the auto-created
/// one), but a `GLOBAL -> GLOBAL` member edge is still a declared cycle.
#[tokio::test]
async fn test_global_group_self_reference_is_rejected() {
    let yaml = r#"
proxy-groups:
  - {name: GLOBAL, type: select, proxies: [GLOBAL, DIRECT]}
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a self-referencing GLOBAL group must be rejected");
    assert!(
        err.to_string()
            .contains("proxy-group cycle detected: GLOBAL -> GLOBAL"),
        "unexpected error: {err}"
    );
}

/// The check is unconditional — `strict: true` rejects the same cycle
/// (the registry split it prevents is structural, not a parse defect).
#[tokio::test]
async fn test_group_cycle_is_rejected_under_strict() {
    let yaml = r#"
strict: true
proxy-groups:
  - {name: A, type: select, proxies: [B, DIRECT]}
  - {name: B, type: select, proxies: [A]}
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("strict mode must reject a declared group cycle too");
    assert!(
        err.to_string().contains("proxy-group cycle detected"),
        "unexpected error: {err}"
    );
}

/// The check is type-agnostic — a relay↔relay cycle is a declared cycle
/// too (members still come from `proxies:`).
#[tokio::test]
async fn test_group_cycle_through_relay_type_is_rejected() {
    let yaml = r#"
proxy-groups:
  - {name: A, type: relay, proxies: [B, DIRECT]}
  - {name: B, type: relay, proxies: [A]}
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a relay group cycle must be rejected");
    assert!(
        err.to_string().contains("proxy-group cycle detected"),
        "unexpected error: {err}"
    );
}

/// A `use:` member naming a declared group is NOT a membership edge —
/// provider slots resolve leaf nodes only. If `use:` created edges this
/// would read as A -> B -> A.
#[tokio::test]
async fn test_group_use_member_does_not_close_a_cycle() {
    let yaml = r#"
proxies:
  - {name: node-a, type: socks5, server: 127.0.0.1, port: 10001}
proxy-groups:
  - {name: A, type: select, proxies: [node-a], use: [B]}
  - {name: B, type: select, proxies: [node-a], use: [A]}
rules:
  - MATCH,A
"#;
    load_config_from_str(yaml)
        .await
        .expect("use: resolves providers only — no group edge, no cycle");
}

/// A declared self-reference is rejected even when `exclude-filter`
/// would have matched it — filters never apply to static `proxies:`
/// members (upstream's DAG check reads the raw member names too).
#[tokio::test]
async fn test_group_self_reference_with_exclude_filter_is_rejected() {
    let yaml = r#"
proxy-groups:
  - {name: A, type: select, proxies: [A, DIRECT], exclude-filter: "^A$"}
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a filtered-out self-reference is still a declared cycle");
    assert!(
        err.to_string()
            .contains("proxy-group cycle detected: A -> A"),
        "unexpected error: {err}"
    );
}

/// A missing member mixed into a cycle changes nothing — `ghost` names
/// no declared group, so it is not an edge; the A↔B cycle is still
/// reported.
#[tokio::test]
async fn test_group_cycle_with_missing_mixed_member_is_rejected() {
    let yaml = r#"
proxy-groups:
  - {name: A, type: select, proxies: [B, ghost]}
  - {name: B, type: select, proxies: [A]}
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("a cycle with a missing member is still a declared cycle");
    assert!(
        err.to_string()
            .contains("proxy-group cycle detected: A -> B -> A"),
        "unexpected error: {err}"
    );
}

/// An acyclic edge INTO a declared GLOBAL is fine — GLOBAL is a normal
/// declared group when the user declares it; only cycles are rejected.
#[tokio::test]
async fn test_acyclic_edge_into_declared_global_builds() {
    let yaml = r#"
proxies:
  - {name: node-a, type: socks5, server: 127.0.0.1, port: 10001}
proxy-groups:
  - {name: A, type: select, proxies: [GLOBAL]}
  - {name: GLOBAL, type: select, proxies: [node-a]}
rules:
  - MATCH,A
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("A -> GLOBAL is acyclic when GLOBAL is declared");
    assert!(
        config.proxies["A"]
            .members()
            .is_some_and(|m| m.iter().any(|n| n == "GLOBAL")),
        "A must keep its declared GLOBAL member"
    );
}

#[tokio::test]
async fn test_missing_member_does_not_expand_include_all_to_proxy_groups() {
    let yaml = r#"
proxies:
  - name: node-a
    type: socks5
    server: 127.0.0.1
    port: 10001

proxy-groups:
  - name: aggregate
    type: select
    include-all-proxies: true
    proxies:
      - missing-node
  - name: later
    type: select
    proxies:
      - node-a
"#;

    let config = load_config_from_str(yaml).await.unwrap();
    let aggregate = config
        .proxies
        .get("aggregate")
        .expect("aggregate must be built leniently");

    assert!(
        !aggregate
            .members()
            .expect("aggregate must expose its members")
            .iter()
            .any(|name| name == "later"),
        "mihomo include-all-proxies must not include a later proxy group"
    );
}

#[tokio::test]
async fn test_include_all_proxies_excludes_proxy_groups() {
    let yaml = r#"
proxies:
  - name: node-a
    type: socks5
    server: 127.0.0.1
    port: 10001

proxy-groups:
  - name: earlier
    type: select
    proxies:
      - node-a
  - name: aggregate
    type: select
    include-all-proxies: true
"#;

    let config = load_config_from_str(yaml).await.unwrap();
    let aggregate = config
        .proxies
        .get("aggregate")
        .expect("aggregate must be built");
    let members = aggregate
        .members()
        .expect("aggregate must expose its members");

    assert!(members.iter().any(|name| name == "node-a"));
    assert!(
        !members.iter().any(|name| name == "earlier"),
        "mihomo include-all-proxies must not include proxy groups"
    );
}

#[tokio::test]
async fn test_deferred_sibling_does_not_change_include_all_proxy_membership() {
    let yaml = r#"
proxies:
  - {name: leaf-d, type: socks5, server: 127.0.0.1, port: 10001}
  - {name: leaf-g, type: socks5, server: 127.0.0.1, port: 10002}
proxy-groups:
  - {name: D, type: select, proxies: [G, leaf-d]}
  - {name: X, type: select, include-all-proxies: true, proxies: [missing-x]}
  - {name: G, type: select, proxies: [leaf-g, missing-g]}
"#;

    let config = load_config_from_str(yaml).await.unwrap();
    let d_members = config
        .proxies
        .get("D")
        .expect("D must be built")
        .members()
        .expect("D must expose its members");
    assert!(d_members.iter().any(|name| name == "G"));
    assert!(d_members.iter().any(|name| name == "leaf-d"));

    let x_members = config
        .proxies
        .get("X")
        .expect("X must be built")
        .members()
        .expect("X must expose its members");
    assert_eq!(x_members, ["leaf-d", "leaf-g"]);
}

#[tokio::test]
async fn test_general_config_table() {
    struct Case {
        label: &'static str,
        yaml: &'static str,
        mode: &'static str,
        log_level: &'static str,
        ipv6: bool,
        allow_lan: bool,
        bind_address: &'static str,
    }

    let cases = [
        Case {
            label: "defaults (empty config)",
            yaml: "",
            mode: "rule",
            log_level: "info",
            // Default matches mihomo/Clash: IPv6 resolution is opt-in
            // (`meow_config::effective_ipv6`).
            ipv6: false,
            allow_lan: false,
            bind_address: "127.0.0.1",
        },
        Case {
            label: "custom general section",
            yaml: r#"
mode: global
log-level: debug
ipv6: true
allow-lan: true
bind-address: "0.0.0.0"
"#,
            mode: "global",
            log_level: "debug",
            ipv6: true,
            allow_lan: true,
            bind_address: "0.0.0.0",
        },
        Case {
            label: "explicit ipv6 disable",
            yaml: "ipv6: false",
            mode: "rule",
            log_level: "info",
            ipv6: false,
            allow_lan: false,
            bind_address: "127.0.0.1",
        },
    ];

    // Collect every mismatch instead of panicking on the first one, so both
    // the defaults path and the override path always run and a failure names
    // the case and the field.
    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        let config = load_config_from_str(case.yaml).await.unwrap();
        let general = &config.general;

        let mode = general.mode.to_string();
        if mode != case.mode {
            failures.push(format!(
                "[{}] mode: expected {:?}, got {:?}",
                case.label, case.mode, mode
            ));
        }
        if general.log_level != case.log_level {
            failures.push(format!(
                "[{}] log_level: expected {:?}, got {:?}",
                case.label, case.log_level, general.log_level
            ));
        }
        if general.ipv6 != case.ipv6 {
            failures.push(format!(
                "[{}] ipv6: expected {}, got {}",
                case.label, case.ipv6, general.ipv6
            ));
        }
        if general.allow_lan != case.allow_lan {
            failures.push(format!(
                "[{}] allow_lan: expected {}, got {}",
                case.label, case.allow_lan, general.allow_lan
            ));
        }
        if general.bind_address != case.bind_address {
            failures.push(format!(
                "[{}] bind_address: expected {:?}, got {:?}",
                case.label, case.bind_address, general.bind_address
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn test_direct_mode_config() {
    let yaml = r#"
mode: direct
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.general.mode.to_string(), "direct");
}

#[tokio::test]
async fn test_invalid_mode_defaults_to_rule() {
    let yaml = r#"
mode: bogus
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.general.mode.to_string(), "rule");
}

#[tokio::test]
async fn test_listener_ports() {
    let yaml = r#"
port: 7891
socks-port: 7892
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.http_port, Some(7891));
    assert_eq!(config.listeners.socks_port, Some(7892));
    assert_eq!(config.listeners.mixed_port, Some(7890));
}

#[tokio::test]
async fn test_listener_bind_address_allow_lan() {
    let yaml = r#"
allow-lan: true
bind-address: "0.0.0.0"
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.bind_address, "0.0.0.0");
}

#[tokio::test]
async fn test_listener_bind_address_no_lan() {
    let yaml = r#"
allow-lan: false
bind-address: "0.0.0.0"
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // When allow-lan is false, bind_address is forced to 127.0.0.1
    assert_eq!(config.listeners.bind_address, "127.0.0.1");
}

#[tokio::test]
async fn test_api_config() {
    let yaml = r#"
external-controller: "127.0.0.1:9090"
secret: "my-secret"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(
        config.api.external_controller.unwrap().to_string(),
        "127.0.0.1:9090"
    );
    assert_eq!(config.api.secret.as_deref(), Some("my-secret"));
}

#[tokio::test]
async fn test_api_config_none() {
    let yaml = "";
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.api.external_controller.is_none());
    assert!(config.api.secret.is_none());
}

#[tokio::test]
async fn test_dns_disabled_by_default() {
    let yaml = "";
    let config = load_config_from_str(yaml).await.unwrap();
    // DNS listen addr should be None when DNS is not configured
    assert!(config.dns.listen_addr.is_none());
}

#[tokio::test]
async fn test_dns_config_enabled() {
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  nameserver:
    - "8.8.8.8"
    - "8.8.4.4:53"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.dns.listen_addr.unwrap().to_string(), "0.0.0.0:5353");
}

#[tokio::test]
async fn test_dns_listen_ephemeral_port() {
    let yaml = r#"
dns:
  enable: true
  listen: 127.0.0.1:0
  nameserver:
    - 1.1.1.1
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.dns.listen_addr.unwrap().to_string(), "127.0.0.1:0");
}

#[tokio::test]
async fn test_named_listener_listen_host_port_ephemeral() {
    let yaml = r#"
listeners:
  - name: mixed
    type: mixed
    listen: 127.0.0.1:0
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.named.len(), 1);
    let nl = &config.listeners.named[0];
    assert_eq!(nl.name, "mixed");
    assert_eq!(nl.listen, "127.0.0.1");
    assert_eq!(nl.port, 0);
}

#[tokio::test]
async fn test_named_listener_listen_host_port_explicit() {
    let yaml = r#"
listeners:
  - name: socks
    type: socks5
    listen: 0.0.0.0:7891
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let nl = &config.listeners.named[0];
    assert_eq!(nl.name, "socks");
    assert_eq!(nl.listen, "0.0.0.0");
    assert_eq!(nl.port, 7891);
}

#[tokio::test]
async fn test_named_listener_listen_port_conflict() {
    let yaml = r#"
listeners:
  - name: socks
    type: socks5
    listen: 127.0.0.1:7891
    port: 7892
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("conflicting listen/port must hard-error");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("conflicts"), "msg: {msg}");
}

#[tokio::test]
async fn test_two_ephemeral_listeners_do_not_conflict() {
    let yaml = r#"
listeners:
  - name: a
    type: mixed
    listen: 127.0.0.1:0
  - name: b
    type: socks5
    listen: 127.0.0.1:0
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.named.len(), 2);
    assert!(config.listeners.named.iter().all(|nl| nl.port == 0));
}

#[tokio::test]
async fn test_dns_config_fakeip_enabled() {
    // `enhanced-mode: fake-ip` must be accepted, with the pool synthesising
    // IPs from the configured CIDR.
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  enhanced-mode: fake-ip
  fake-ip-range: "198.18.0.1/16"
  fake-ip-filter:
    - "+.local"
    - "example.com"
  nameserver:
    - "8.8.8.8"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.dns.resolver.mode().to_string(), "fake-ip");
    // Skipper bypasses filtered domains: lookup returns no fake IP for them.
    let r = &config.dns.resolver;
    let v4 = r.lookup_ipv4("foo.test").await.unwrap();
    let foo_octets = match v4 {
        std::net::IpAddr::V4(v) => v.octets(),
        _ => panic!("expected v4"),
    };
    assert_eq!(
        &foo_octets[..2],
        &[198, 18],
        "non-filtered host must get a fake IP from 198.18.0.0/16, got {v4}"
    );
    assert!(r.is_fake_ip(v4));
    let again = r.lookup_ipv4("foo.test").await.unwrap();
    assert_eq!(again, v4, "fake-IP must be stable per host");
    // Reverse lookup recovers the hostname.
    assert_eq!(r.reverse_lookup(v4).as_deref(), Some("foo.test"));
    // Flush wipes the pool.
    r.flush_fake_ip().unwrap();
    assert!(r.reverse_lookup(v4).is_none());
}

#[tokio::test]
async fn test_dns_config_fakeip_default_range() {
    // Omitting fake-ip-range should pick the upstream default 198.18.0.1/16.
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  enhanced-mode: fake-ip
  nameserver:
    - "8.8.8.8"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.dns.resolver.mode().to_string(), "fake-ip");
    let ip = config
        .dns
        .resolver
        .lookup_ipv4("anything.test")
        .await
        .unwrap();
    let std::net::IpAddr::V4(v4) = ip else {
        panic!("expected v4");
    };
    assert_eq!(&v4.octets()[..2], &[198, 18]);
}

#[tokio::test]
async fn test_dns_config_fakeip_invalid_range_errors() {
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  enhanced-mode: fake-ip
  fake-ip-range: "not-a-cidr"
  nameserver:
    - "8.8.8.8"
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("expected error for invalid CIDR");
    };
    assert!(
        err.to_string().contains("fake-ip-range"),
        "expected fake-ip-range parse error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_config_disabled() {
    let yaml = r#"
dns:
  enable: false
  listen: "0.0.0.0:5353"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // When DNS is disabled, listen_addr should be None
    assert!(config.dns.listen_addr.is_none());
}

#[tokio::test]
async fn test_proxy_parsing_ss() {
    let yaml = r#"
proxies:
  - name: "ss-server"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    udp: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("ss-server"));
}

#[tokio::test]
async fn test_proxy_parsing_trojan() {
    let yaml = r#"
proxies:
  - name: "trojan-server"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    sni: "example.com"
    skip-cert-verify: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-server"));
}

#[cfg(feature = "mux")]
#[tokio::test]
async fn test_proxy_parsing_trojan_legacy_mux_enabled() {
    let yaml = r#"
proxies:
  - name: "trojan-mux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    mux:
      enabled: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-mux"));
}

#[cfg(feature = "mux")]
#[tokio::test]
async fn test_proxy_parsing_trojan_smux_enabled() {
    let yaml = r#"
proxies:
  - name: "trojan-smux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    smux:
      enabled: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-smux"));
}

#[tokio::test]
async fn test_proxy_parsing_prefers_smux_when_both_keys_present() {
    let yaml = r#"
proxies:
  - name: "trojan-double-mux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    smux:
      enabled: true
    mux:
      enabled: false
"#;
    // The canonical smux: key wins (warn) and the node stays usable.
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-double-mux"));
}

#[tokio::test]
async fn test_proxy_parsing_rejects_non_boolean_mux_enabled() {
    let yaml = r#"
proxies:
  - name: "trojan-bad-mux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    smux:
      enabled: "true"
"#;
    // A string "true" must not be silently treated as disabled.
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(!config.proxies.contains_key("trojan-bad-mux"));
}

#[tokio::test]
async fn test_proxy_parsing_rejects_scalar_mux_block() {
    let yaml = r#"
proxies:
  - name: "trojan-scalar-mux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    smux: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(!config.proxies.contains_key("trojan-scalar-mux"));
}

#[cfg(feature = "mux")]
#[tokio::test]
async fn test_proxy_parsing_trojan_mux_h2mux_accepted() {
    let yaml = r#"
proxies:
  - name: "trojan-mux-h2"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    mux:
      enabled: true
      protocol: h2mux
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-mux-h2"));
}

#[tokio::test]
async fn test_unsupported_proxy_type_skipped() {
    let yaml = r#"
proxies:
  - name: "wireguard-server"
    type: wireguard
    server: "1.2.3.4"
    port: 443
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(!config.proxies.contains_key("wireguard-server"));
}

#[tokio::test]
async fn test_vmess_minimal_config() {
    let yaml = r#"
proxies:
  - name: "vmess-test"
    type: vmess
    server: "1.2.3.4"
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    cipher: auto
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("vmess-test"));
}

#[tokio::test]
async fn test_vmess_cipher_zero_hard_errors() {
    let yaml = r#"
proxies:
  - name: "vmess-zero"
    type: vmess
    server: "1.2.3.4"
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    cipher: zero
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(
        !config.proxies.contains_key("vmess-zero"),
        "cipher:zero must be rejected"
    );
}

#[tokio::test]
async fn test_vmess_with_ws_transport() {
    let yaml = r#"
proxies:
  - name: "vmess-ws"
    type: vmess
    server: "example.com"
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    cipher: aes-128-gcm
    tls: true
    network: ws
    ws-opts:
      path: /vmess
      headers:
        Host: example.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("vmess-ws"));
}

#[tokio::test]
async fn test_rule_parsing() {
    let yaml = r#"
rules:
  - "DOMAIN-SUFFIX,google.com,DIRECT"
  - "DOMAIN-KEYWORD,facebook,REJECT"
  - "MATCH,DIRECT"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 3);
}

#[tokio::test]
async fn test_rule_parsing_with_comments() {
    let yaml = r#"
rules:
  - "DOMAIN,example.com,DIRECT"
  - "MATCH,DIRECT"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 2);
}

#[tokio::test]
async fn test_empty_rules() {
    let yaml = "";
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.rules.is_empty());
}

#[tokio::test]
async fn test_memleak_regression_config_is_direct_only() {
    let config = load_config_from_str(include_str!("fixtures/memleak_regression_direct.yaml"))
        .await
        .unwrap();

    assert_eq!(config.listeners.mixed_port, Some(17890));
    assert!(config.proxies.contains_key("DIRECT"));
    assert!(config.raw.proxies.as_ref().is_none_or(Vec::is_empty));
    assert!(config.rules.iter().all(|rule| rule.adapter() == "DIRECT"));
}

#[tokio::test]
async fn test_proxy_group_select() {
    let yaml = r#"
proxies:
  - name: "ss1"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "pass"

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - ss1
      - DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("Proxy"));
}

#[tokio::test]
async fn test_relay_dials_through_group_at_later_hop() {
    use meow_common::Metadata;
    use tokio::net::TcpListener;

    let yaml = r#"
proxy-groups:
  - name: exit
    type: select
    proxies:
      - DIRECT
  - name: chain
    type: relay
    proxies:
      - DIRECT
      - exit

rules:
  - MATCH,chain
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let chain = config.proxies.get("chain").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();

    let conn = chain
        .dial_tcp(&Metadata {
            host: target.ip().to_string().into(),
            dst_port: target.port(),
            ..Default::default()
        })
        .await
        .expect("relay should resolve the group hop and dial the final target");

    let (_accepted, peer) = listener.accept().await.unwrap();
    assert!(peer.ip().is_loopback());
    drop(conn);
}

#[tokio::test]
async fn test_proxy_group_missing_proxy_warn_not_fail() {
    let yaml = r#"
proxies:
  - name: "ss1"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "pass"

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - ss1
      - nonexistent-proxy
"#;
    // Should succeed even with missing proxy reference
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("Proxy"));
}

#[tokio::test]
async fn test_full_config() {
    let yaml = r#"
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false
external-controller: "127.0.0.1:9090"

dns:
  enable: true
  listen: "0.0.0.0:5353"
  nameserver:
    - "8.8.8.8"
    - "8.8.4.4"

proxies:
  - name: "ss-test"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "test-password"
    udp: true

proxy-groups:
  - name: "auto"
    type: url-test
    proxies:
      - ss-test
    url: "http://www.gstatic.com/generate_204"
    interval: 300

rules:
  - "DOMAIN-SUFFIX,google.com,auto"
  - "MATCH,DIRECT"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.mixed_port, Some(7890));
    assert_eq!(config.general.mode.to_string(), "rule");
    assert!(config.proxies.contains_key("ss-test"));
    assert!(config.proxies.contains_key("auto"));
    assert!(config.proxies.contains_key("DIRECT"));
    assert_eq!(config.rules.len(), 2);
    assert!(config.dns.listen_addr.is_some());
    assert!(config.api.external_controller.is_some());
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_plugin_missing_binary() {
    // A non-existent plugin binary causes proxy creation to fail.
    // The config loader logs a warning and skips the proxy (does not panic).
    let yaml = r#"
proxies:
  - name: "ss-missing-plugin"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: nonexistent-plugin-binary-xyz
    plugin-opts:
      mode: http
      host: example.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // The proxy is skipped because the plugin binary doesn't exist
    assert!(!config.proxies.contains_key("ss-missing-plugin"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_plugin_opts_string() {
    // Plugin opts can be passed as a pre-formatted string.
    // Uses a non-existent plugin to verify config parsing succeeds.
    let yaml = r#"
proxies:
  - name: "ss-plugin-str"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: nonexistent-plugin-binary-xyz
    plugin-opts: "obfs=http;obfs-host=example.com"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // Skipped because plugin binary doesn't exist, but config parsing succeeds
    assert!(!config.proxies.contains_key("ss-plugin-str"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_table() {
    // Built-in simple-obfs (`plugin: obfs` / `plugin: simple-obfs`) needs no
    // external binary, so a well-formed node must register; a node whose obfs
    // config cannot be resolved to a valid mode must be skipped (never
    // silently falling back to the "external plugin" path).
    //
    // Each case supplies the `plugin:`/`plugin-opts:` tail (and, where it
    // matters, the `server:` value) plus the expected registration outcome.
    struct Case {
        label: &'static str,
        name: &'static str,
        server: &'static str,
        plugin_block: &'static str,
        expect_present: bool,
    }

    let cases = [
        Case {
            label: "yaml map, mode=http",
            name: "ss-obfs-http",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: http\n      host: bing.com\n",
            expect_present: true,
        },
        Case {
            label: "yaml map, mode=tls",
            name: "ss-obfs-tls",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: tls\n      host: gateway.icloud.com\n",
            expect_present: true,
        },
        Case {
            label: "SIP003 string form `obfs=tls;obfs-host=...`",
            name: "ss-obfs-str",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts: \"obfs=tls;obfs-host=cloudflare.com\"\n",
            expect_present: true,
        },
        Case {
            label: "legacy `plugin: simple-obfs` alias",
            name: "ss-simple-obfs",
            server: "1.2.3.4",
            plugin_block: "    plugin: simple-obfs\n    plugin-opts:\n      mode: http\n      host: bing.com\n",
            expect_present: true,
        },
        Case {
            label: "yaml map with SIP003-native keys `obfs`/`obfs-host`",
            name: "ss-obfs-sip003-map",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      obfs: tls\n      obfs-host: gateway.icloud.com\n",
            expect_present: true,
        },
        Case {
            label: "mode parsed case-insensitively (TLS)",
            name: "ss-obfs-upper",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: TLS\n      host: cloudflare.com\n",
            expect_present: true,
        },
        Case {
            label: "host omitted falls back to the ss server name",
            name: "ss-obfs-default-host",
            server: "ss.example.org",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: http\n",
            expect_present: true,
        },
        Case {
            label: "missing `mode` is invalid -> skipped",
            name: "ss-obfs-bad",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      host: example.com\n",
            expect_present: false,
        },
        Case {
            label: "no plugin-opts at all -> skipped, no external fallback",
            name: "ss-obfs-no-opts",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n",
            expect_present: false,
        },
        Case {
            label: "unknown mode `quic` -> skipped",
            name: "ss-obfs-bad-mode",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: quic\n      host: foo\n",
            expect_present: false,
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        let yaml = format!(
            "proxies:\n  - name: \"{}\"\n    type: ss\n    server: \"{}\"\n    port: 8388\n    cipher: \"aes-256-gcm\"\n    password: \"password123\"\n{}",
            case.name, case.server, case.plugin_block
        );
        let config = load_config_from_str(&yaml).await.unwrap();
        let present = config.proxies.contains_key(case.name);
        if present != case.expect_present {
            failures.push(format!(
                "[{}] proxy `{}`: expected present={}, got present={}",
                case.label, case.name, case.expect_present, present
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "built-in obfs parsing mismatches:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_gost_plugin() {
    // `gost-plugin` is an in-process built-in (issue #533): a ws transport
    // with upstream defaults host=bing.com / mux=true.  Well-formed nodes
    // register; a node whose `plugin-opts` is missing the required
    // `mode: websocket` is skipped (never falls back to the external
    // SIP003 path).  Nested `headers`/`ech-opts` maps must survive
    // `plugin-opts` serialization.
    struct Case {
        label: &'static str,
        name: &'static str,
        plugin_block: &'static str,
        expect_present: bool,
    }

    let cases = [
        // `mux: false` keeps every fixture valid under a `ss`-without-`mux`
        // build, where the upstream `mux` default (`true`) is a parse error.
        Case {
            label: "yaml map, mode=websocket",
            name: "ss-gost-basic",
            plugin_block: "    plugin: gost-plugin\n    plugin-opts:\n      mode: websocket\n      host: cdn.example.com\n      path: /ws\n      tls: true\n      mux: false\n",
            expect_present: true,
        },
        Case {
            label: "nested headers map",
            name: "ss-gost-headers",
            plugin_block: "    plugin: gost-plugin\n    plugin-opts:\n      mode: websocket\n      mux: false\n      headers:\n        CF-Token: abc\n        Host: edge.example.com\n",
            expect_present: true,
        },
        Case {
            label: "nested ech-opts map",
            name: "ss-gost-ech",
            plugin_block: "    plugin: gost-plugin\n    plugin-opts:\n      mode: websocket\n      mux: false\n      tls: true\n      ech-opts:\n        enable: true\n        config: \"QUJD\"\n",
            expect_present: true,
        },
        Case {
            label: "SIP003 string form",
            name: "ss-gost-str",
            plugin_block: "    plugin: gost-plugin\n    plugin-opts: \"mode=websocket;tls;host=cdn.example.com;mux=false\"\n",
            expect_present: true,
        },
        Case {
            label: "missing mode -> skipped",
            name: "ss-gost-no-mode",
            plugin_block: "    plugin: gost-plugin\n    plugin-opts:\n      host: example.com\n      mux: false\n",
            expect_present: false,
        },
        Case {
            label: "unsupported mode -> skipped",
            name: "ss-gost-bad-mode",
            plugin_block: "    plugin: gost-plugin\n    plugin-opts:\n      mode: quic\n      mux: false\n",
            expect_present: false,
        },
        Case {
            label: "lone certificate -> skipped",
            name: "ss-gost-bad-cert",
            plugin_block: "    plugin: gost-plugin\n    plugin-opts:\n      mode: websocket\n      mux: false\n      certificate: PEM\n",
            expect_present: false,
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        let yaml = format!(
            "proxies:\n  - name: \"{}\"\n    type: ss\n    server: \"1.2.3.4\"\n    port: 8388\n    cipher: \"aes-256-gcm\"\n    password: \"password123\"\n{}",
            case.name, case.plugin_block
        );
        let config = load_config_from_str(&yaml).await.unwrap();
        let present = config.proxies.contains_key(case.name);
        if present != case.expect_present {
            failures.push(format!(
                "[{}] proxy `{}`: expected present={}, got present={}",
                case.label, case.name, case.expect_present, present
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "gost-plugin parsing mismatches:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn test_invalid_yaml() {
    let yaml = "{{invalid yaml}}";
    assert!(load_config_from_str(yaml).await.is_err());
}

#[tokio::test]
async fn test_file_rule_provider_end_to_end() {
    // File rule-providers need a containment root for their `path:` (issue
    // #429), so this goes through `load_config` with a real config file whose
    // directory doubles as the provider root — the normal on-disk setup.
    let dir = tempfile::tempdir().unwrap();
    let list_path = dir.path().join("ads.yaml");
    std::fs::write(
        &list_path,
        "payload:\n  - '+.ads.example'\n  - banner.test\n",
    )
    .unwrap();

    let yaml = r#"
mixed-port: 7890
rule-providers:
  ads:
    type: file
    behavior: domain
    format: yaml
    path: ads.yaml
rules:
  - RULE-SET,ads,REJECT
  - MATCH,DIRECT
"#;
    let config_path = dir.path().join("config.yaml");
    std::fs::write(&config_path, yaml).unwrap();

    let config = meow_config::load_config(config_path.to_str().unwrap())
        .await
        .unwrap();
    // RULE-SET rule + MATCH
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].rule_type().to_string(), "RULE-SET");
    assert_eq!(config.rules[0].adapter(), "REJECT");
    assert_eq!(config.rules[0].payload(), "ads");

    // Verify the RULE-SET rule actually matches via its backing set.
    use meow_common::{Metadata, RuleMatchHelper};
    let helper = RuleMatchHelper;
    let meta = Metadata {
        host: "tracker.ads.example".into(),
        dst_port: 443,
        ..Default::default()
    };
    assert!(config.rules[0].match_metadata(&meta, &helper));

    let meta_miss = Metadata {
        host: "example.com".into(),
        dst_port: 443,
        ..Default::default()
    };
    assert!(!config.rules[0].match_metadata(&meta_miss, &helper));
}

#[tokio::test]
async fn test_missing_rule_provider_is_skipped() {
    // Referencing an undefined rule-set should warn and skip, not panic.
    let yaml = r#"
mixed-port: 7890
rules:
  - RULE-SET,nonexistent,REJECT
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // Only the MATCH rule survives.
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].rule_type().to_string(), "MATCH");
}

// ─── SUB-RULE (M1.D-7) ─────────────────────────────────────────────

/// C1 — undefined block → hard parse error (Class A per ADR-0002).
/// upstream: upstream errors at runtime; we reject at parse.
#[tokio::test]
async fn sub_rule_undefined_block_hard_errors() {
    let yaml = r#"
mixed-port: 7890
rules:
  - SUB-RULE,MISSING
  - MATCH,DIRECT
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("expected error");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("MISSING"), "unexpected: {msg}");
}

/// D1 — cycle (A → B → A) → hard parse error.
#[tokio::test]
async fn sub_rule_cycle_hard_errors() {
    let yaml = r#"
mixed-port: 7890
sub-rules:
  A:
    - SUB-RULE,B
  B:
    - SUB-RULE,A
rules:
  - SUB-RULE,A
  - MATCH,DIRECT
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("expected error");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("cycle"), "unexpected: {msg}");
}

/// D2 — self-reference is a degenerate cycle.
#[tokio::test]
async fn sub_rule_self_reference_hard_errors() {
    let yaml = r#"
mixed-port: 7890
sub-rules:
  A:
    - SUB-RULE,A
rules:
  - SUB-RULE,A
  - MATCH,DIRECT
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("expected error");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("cycle"), "unexpected: {msg}");
}

/// D5 — diamond (A → B, A → C, B → D, C → D) is NOT a cycle. Parse succeeds.
#[tokio::test]
async fn sub_rule_diamond_not_a_cycle() {
    let yaml = r#"
mixed-port: 7890
sub-rules:
  A:
    - SUB-RULE,B
    - SUB-RULE,C
  B:
    - SUB-RULE,D
  C:
    - SUB-RULE,D
  D:
    - DOMAIN,example.com,DIRECT
rules:
  - SUB-RULE,A
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].rule_type().to_string(), "SUB-RULE");
    assert_eq!(config.rules[1].rule_type().to_string(), "MATCH");
}

/// A1/L — block match returns inner rule's target.
#[tokio::test]
async fn sub_rule_block_match_returns_inner_target() {
    use meow_common::{Metadata, RuleMatchHelper};
    let yaml = r#"
mixed-port: 7890
sub-rules:
  STREAMING:
    - DOMAIN-SUFFIX,netflix.com,Stream
rules:
  - SUB-RULE,STREAMING
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let helper = RuleMatchHelper;
    let m = Metadata {
        host: "www.netflix.com".into(),
        dst_port: 443,
        ..Default::default()
    };
    let target = config.rules[0].match_and_resolve(&m, &helper, &|_: &str| true);
    assert_eq!(target, Some("Stream"));
}

/// A2/L — block exhaustion returns None so outer loop continues.
#[tokio::test]
async fn sub_rule_block_exhaustion_falls_through() {
    use meow_common::{Metadata, RuleMatchHelper};
    let yaml = r#"
mixed-port: 7890
sub-rules:
  STREAMING:
    - DOMAIN-SUFFIX,netflix.com,Stream
rules:
  - SUB-RULE,STREAMING
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let helper = RuleMatchHelper;
    let m = Metadata {
        host: "example.com".into(),
        dst_port: 443,
        ..Default::default()
    };
    // SUB-RULE with non-matching inner returns None.
    assert!(config.rules[0]
        .match_and_resolve(&m, &helper, &|_: &str| true)
        .is_none());
    // MATCH still wins.
    assert_eq!(
        config.rules[1].match_and_resolve(&m, &helper, &|_: &str| true),
        Some("DIRECT")
    );
}

/// F3 — forward reference from `rules:` to `sub-rules:` resolves.
#[tokio::test]
async fn sub_rules_section_parsed_before_rules_section() {
    let yaml = r#"
mixed-port: 7890
rules:
  - SUB-RULE,LATER
  - MATCH,DIRECT
sub-rules:
  LATER:
    - DOMAIN,example.com,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].rule_type().to_string(), "SUB-RULE");
}

/// E1 — empty block is accepted (warn-only per spec Class B).
#[tokio::test]
async fn sub_rule_empty_block_accepted() {
    let yaml = r#"
mixed-port: 7890
sub-rules:
  EMPTY: []
rules:
  - SUB-RULE,EMPTY
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 2);
}

#[tokio::test]
async fn test_expected_status_integer_accepted_end_to_end() {
    // issue #390: `expected-status: 204` (unquoted integer, as documented)
    // used to abort config load with "invalid type: integer `204`, expected
    // a string" — in both proxy-groups and proxy-provider health-checks.
    let yaml = r#"
proxies:
  - name: p1
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: test
proxy-groups:
  - name: auto
    type: url-test
    proxies: [p1]
    url: http://www.gstatic.com/generate_204
    interval: 300
    expected-status: 204
proxy-providers:
  prov:
    type: file
    path: /nonexistent/meow-issue-390-provider.yaml
    health-check:
      enable: true
      interval: 300
      expected-status: 204
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("auto"));
}

#[tokio::test]
async fn test_shorthand_port_zero_means_disabled() {
    // mihomo compat: `mixed-port: 0` (and the other shorthand port fields)
    // means the inbound is disabled, not "bind an ephemeral port". Ephemeral
    // ports are an explicit `listeners:`-entry opt-in.
    let yaml = r#"
mixed-port: 0
socks-port: 0
port: 0
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.listeners.named.is_empty());
}

// ── ListenerSpec sni value tests ───────────────────────────────
//
// Verify that the per-listener `tproxy-sni` override and the global
// `tproxy-sni` default are correctly folded into the `TProxy { sni }`
// variant at config-build time.

#[tokio::test]
async fn test_tproxy_shorthand_uses_global_sni_default() {
    let yaml = r#"
tproxy-port: 7893
tproxy-sni: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let tproxy = config
        .listeners
        .named
        .iter()
        .find(|nl| matches!(nl.spec, ListenerSpec::TProxy { .. }))
        .expect("tproxy shorthand listener must exist");
    assert_eq!(
        tproxy.spec,
        ListenerSpec::TProxy {
            sni: true,
            firewall: true,
            udp: false,
            udp_timeout: 60,
        },
        "shorthand tproxy-port should inherit the global tproxy-sni default"
    );
    // TProxy always hard-binds 127.0.0.1
    assert_eq!(tproxy.listen, "127.0.0.1");
}

#[tokio::test]
async fn test_tproxy_shorthand_global_sni_false() {
    let yaml = r#"
tproxy-port: 7893
tproxy-sni: false
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let tproxy = config
        .listeners
        .named
        .iter()
        .find(|nl| matches!(nl.spec, ListenerSpec::TProxy { .. }))
        .expect("tproxy shorthand listener must exist");
    assert_eq!(
        tproxy.spec,
        ListenerSpec::TProxy {
            sni: false,
            firewall: true,
            udp: false,
            udp_timeout: 60,
        },
        "shorthand tproxy-port with global tproxy-sni: false"
    );
}

#[tokio::test]
async fn test_tproxy_named_listener_per_listener_sni_override() {
    let yaml = r#"
tproxy-sni: false
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 127.0.0.1:7894
    tproxy-sni: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let tproxy = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "my-tproxy")
        .expect("named tproxy listener must exist");
    assert_eq!(
        tproxy.spec,
        ListenerSpec::TProxy {
            sni: true,
            firewall: true,
            udp: false,
            udp_timeout: 60,
        },
        "per-listener tproxy-sni: true must override the global false default"
    );
}

// ── Issue #563: per-listener `firewall` on tproxy ────────────────
//
// `firewall: false` delegates nftables/pf rule management to an external
// system. The shorthand `tproxy-port` always keeps the managed default;
// only an explicit `listeners:` entry can opt out.

#[tokio::test]
async fn test_tproxy_firewall_defaults_true() {
    let yaml = r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 0.0.0.0:5332
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let tproxy = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "my-tproxy")
        .expect("named tproxy listener must exist");
    assert_eq!(
        tproxy.spec,
        ListenerSpec::TProxy {
            sni: true,
            firewall: true,
            udp: false,
            udp_timeout: 60,
        },
        "omitted firewall must default to managed"
    );
}

#[tokio::test]
async fn test_tproxy_firewall_explicit_false() {
    for value in ["false", "true"] {
        let yaml = format!(
            r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 0.0.0.0:5332
    firewall: {value}
"#
        );
        let config = load_config_from_str(&yaml).await.unwrap();
        let tproxy = config
            .listeners
            .named
            .iter()
            .find(|nl| nl.name == "my-tproxy")
            .expect("named tproxy listener must exist");
        let expected = value == "true";
        assert_eq!(
            tproxy.spec,
            ListenerSpec::TProxy {
                sni: true,
                firewall: expected,
                udp: false,
                udp_timeout: 60,
            },
            "firewall: {value} must round-trip"
        );
    }
}

/// `tproxy-port` shorthand cannot opt out — external management is an
/// explicit `listeners:`-only feature.
#[tokio::test]
async fn test_tproxy_shorthand_keeps_managed_firewall() {
    let yaml = "tproxy-port: 7893\n";
    let config = load_config_from_str(yaml).await.unwrap();
    let tproxy = config
        .listeners
        .named
        .iter()
        .find(|nl| matches!(nl.spec, ListenerSpec::TProxy { .. }))
        .expect("tproxy shorthand listener must exist");
    assert_eq!(
        tproxy.spec,
        ListenerSpec::TProxy {
            sni: true,
            firewall: true,
            udp: false,
            udp_timeout: 60,
        },
        "shorthand tproxy-port must keep the managed-firewall default"
    );
}

/// A persisted spec written before the `firewall` field existed must
/// deserialize with the managed default, not `false`.
#[test]
fn test_tproxy_spec_deserialization_defaults_firewall_true() {
    let spec: ListenerSpec = serde_yaml::from_str("!tproxy\nsni: true\n").unwrap();
    assert_eq!(
        spec,
        ListenerSpec::TProxy {
            sni: true,
            firewall: true,
            udp: false,
            udp_timeout: 60,
        },
        "legacy spec without `firewall` must default to managed"
    );
}

/// A spec carrying the new `udp`/`udp_timeout` fields round-trips through
/// serde with the values intact — the kebab-case config key (`udp-timeout`)
/// and the snake_case spec field (`udp_timeout`) are different documents.
#[test]
fn test_tproxy_spec_deserialization_round_trips_udp() {
    let spec: ListenerSpec =
        serde_yaml::from_str("!tproxy\nsni: false\nfirewall: false\nudp: true\nudp_timeout: 30\n")
            .unwrap();
    assert_eq!(
        spec,
        ListenerSpec::TProxy {
            sni: false,
            firewall: false,
            udp: true,
            udp_timeout: 30,
        },
        "spec with `udp`/`udp_timeout` must deserialize"
    );
}

/// `firewall:` on a non-tproxy listener is inert — parsed with a warning
/// rather than silently changing that listener's behaviour. The warning is
/// captured via a scoped subscriber; the config build is driven on a
/// current-thread runtime inside `with_default` so the thread-local
/// dispatch is in effect when the warn fires.
#[test]
fn test_firewall_on_non_tproxy_listener_warns() {
    let yaml = r#"
listeners:
  - name: my-mixed
    type: mixed
    listen: 127.0.0.1:7890
    firewall: false
"#;
    #[derive(Clone)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Sink;
        fn make_writer(&'a self) -> Sink {
            self.clone()
        }
    }
    let sink = Sink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let config = tracing::subscriber::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(load_config_from_str(yaml))
            .unwrap()
    });
    let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    assert!(
        logs.contains("only meaningful on `type: tproxy`"),
        "expected a misuse warning, got: {logs}"
    );

    let mixed = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "my-mixed")
        .expect("named mixed listener must exist");
    assert_eq!(mixed.spec, ListenerSpec::Mixed);
}

/// Issue #563: `firewall:` is a `listeners:`-entry key — there is no top-level
/// equivalent. A stray top-level `firewall: false` must warn rather than
/// silently keep the managed firewall, and it must not disable the
/// `tproxy-port` shorthand's managed mode.
#[test]
fn test_top_level_firewall_warns_and_is_ignored() {
    let yaml = r#"
firewall: false
tproxy-port: 7893
"#;
    #[derive(Clone)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Sink;
        fn make_writer(&'a self) -> Sink {
            self.clone()
        }
    }
    let sink = Sink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let config = tracing::subscriber::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(load_config_from_str(yaml))
            .unwrap()
    });
    let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    assert!(
        logs.contains("top-level key is ignored"),
        "expected a top-level `firewall:` warning, got: {logs}"
    );

    // The shorthand listener stays managed (firewall: true).
    let tproxy = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "tproxy")
        .expect("tproxy shorthand listener must exist");
    match &tproxy.spec {
        ListenerSpec::TProxy { firewall, .. } => {
            assert!(
                *firewall,
                "top-level `firewall:` must not reach the shorthand"
            );
        }
        other => panic!("expected a tproxy listener, got {other:?}"),
    }
}

/// Issue #564 review: misplaced UDP/tproxy-sni keys warn rather than being
/// silently ignored — top-level `udp:`/`udp-timeout:`, `udp:` on a
/// non-tproxy/non-ss listener, `udp-timeout:` on ss, and `tproxy-sni:` on a
/// non-tproxy entry.
#[test]
fn test_misplaced_udp_and_sni_keys_warn() {
    let yaml = r#"
udp: true
udp-timeout: 30
listeners:
  - name: my-http
    type: http
    listen: 127.0.0.1:7890
    udp: true
    tproxy-sni: true
  - name: my-ss
    type: shadowsocks
    listen: 127.0.0.1:8388
    cipher: aes-128-gcm
    password: pw
    udp-timeout: 30
"#;
    #[derive(Clone)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Sink;
        fn make_writer(&'a self) -> Sink {
            self.clone()
        }
    }
    let sink = Sink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(load_config_from_str(yaml))
            .unwrap()
    });
    let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    for needle in [
        "udp: only meaningful under a `listeners:` entry",
        "udp-timeout: only meaningful under a `listeners:`/`tun:` entry",
        "my-http].udp: only meaningful on `type: tproxy`/`shadowsocks`",
        "my-ss].udp-timeout: only meaningful on `type: tproxy`",
        "my-http].tproxy-sni: only meaningful on `type: tproxy`",
    ] {
        assert!(logs.contains(needle), "missing warning '{needle}': {logs}");
    }
}

// ── Issue #564: opt-in `udp`/`udp-timeout` on tproxy ─────────────
//
// `udp: true` adds the Linux UDP TPROXY path on the same port. It requires
// `firewall: false` (meow's managed rules are host TCP REDIRECT only and
// cannot promise LAN UDP TPROXY policy routing), is IPv4-only in this
// release, and defaults off — an omitted `udp` creates no socket, needs no
// extra privileges, and changes nothing about the TCP path.

#[tokio::test]
async fn test_tproxy_udp_opt_in() {
    let yaml = r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 0.0.0.0:5332
    firewall: false
    udp: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let tproxy = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "my-tproxy")
        .expect("named tproxy listener must exist");
    assert_eq!(
        tproxy.spec,
        ListenerSpec::TProxy {
            sni: true,
            firewall: false,
            udp: true,
            udp_timeout: 60,
        },
        "udp: true + firewall: false must produce the UDP-enabled spec with the default timeout"
    );
}

#[tokio::test]
async fn test_tproxy_udp_timeout_round_trips() {
    let yaml = r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 0.0.0.0:5332
    firewall: false
    udp: true
    udp-timeout: 120
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let ListenerSpec::TProxy { udp_timeout, .. } = config.listeners.named[0].spec else {
        panic!("expected tproxy spec");
    };
    assert_eq!(udp_timeout, 120);
}

/// `udp: true` without `firewall: false` is a hard error — the managed
/// firewall only installs host TCP REDIRECT rules and cannot express UDP
/// TPROXY policy routing, so silently degrading to TCP-only is not an
/// option.
#[tokio::test]
async fn test_tproxy_udp_requires_external_firewall() {
    for firewall_line in ["", "    firewall: true\n"] {
        let yaml = format!(
            r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 0.0.0.0:5332
{firewall_line}    udp: true
"#
        );
        let err = load_config_from_str(&yaml)
            .await
            .err()
            .expect("udp: true with managed firewall must fail");
        assert!(
            err.to_string().contains("firewall: false"),
            "error must name the required setting, got: {err}"
        );
    }
}

#[tokio::test]
async fn test_tproxy_udp_timeout_zero_rejected() {
    let yaml = r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 0.0.0.0:5332
    firewall: false
    udp: true
    udp-timeout: 0
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("udp-timeout: 0 must fail");
    assert!(err.to_string().contains("udp-timeout"), "got: {err}");
}

/// `udp-timeout: 0` is rejected on a TCP-only tproxy listener too — the
/// field parse validates positivity before the `udp`/`type` checks, so an
/// invalid value can never silently ride along inert.
#[tokio::test]
async fn test_tproxy_udp_timeout_zero_rejected_without_udp() {
    let yaml = r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 0.0.0.0:5332
    udp-timeout: 0
"#;
    let err = load_config_from_str(yaml)
        .await
        .err()
        .expect("udp-timeout: 0 must fail even without udp: true");
    assert!(err.to_string().contains("udp-timeout"), "got: {err}");
}

/// IPv6 and dual-stack (`::`) binds are rejected for `udp: true` — the
/// receive path is IPv4-only (`IP_RECVORIGDSTADDR`) and `::` would
/// silently accept v6 datagrams it cannot handle.
#[tokio::test]
async fn test_tproxy_udp_rejects_ipv6_listen() {
    for listen in ["[::1]:5332", "[::]:5332", "[::ffff:1.2.3.4]:5332"] {
        let yaml = format!(
            r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: "{listen}"
    firewall: false
    udp: true
"#
        );
        let err = load_config_from_str(&yaml)
            .await
            .err()
            .expect("udp: true on IPv6/dual-stack must fail");
        assert!(err.to_string().contains("IPv4-only"), "got: {err}");
    }
}

/// `firewall: false` alone (no `udp`) stays legal — it is the #563
/// external-management contract, orthogonal to the UDP opt-in.
#[tokio::test]
async fn test_tproxy_external_firewall_without_udp_is_legal() {
    let yaml = r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 0.0.0.0:5332
    firewall: false
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let ListenerSpec::TProxy { firewall, udp, .. } = config.listeners.named[0].spec else {
        panic!("expected tproxy spec");
    };
    assert!(!firewall && !udp);
}

/// `udp-timeout` on a tproxy listener without `udp: true` is inert —
/// parsed with a warning rather than silently stored.
#[test]
fn test_tproxy_udp_timeout_without_udp_warns() {
    let yaml = r#"
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 127.0.0.1:5332
    udp-timeout: 30
"#;
    #[derive(Clone)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Sink;
        fn make_writer(&'a self) -> Sink {
            self.clone()
        }
    }
    let sink = Sink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let config = tracing::subscriber::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(load_config_from_str(yaml))
            .unwrap()
    });
    let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    assert!(
        logs.contains("has no effect unless `udp: true`"),
        "expected the inert udp-timeout warning, got: {logs}"
    );

    let ListenerSpec::TProxy {
        udp, udp_timeout, ..
    } = config.listeners.named[0].spec
    else {
        panic!("expected tproxy spec");
    };
    assert!(!udp && udp_timeout == 30);
}

/// `udp:` on a non-tproxy/non-shadowsocks listener is inert — parsed with
/// a warning, never silently changing that listener's behaviour.
#[test]
fn test_udp_on_mixed_listener_warns() {
    let yaml = r#"
listeners:
  - name: my-mixed
    type: mixed
    listen: 127.0.0.1:7890
    udp: true
    udp-timeout: 30
"#;
    #[derive(Clone)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Sink;
        fn make_writer(&'a self) -> Sink {
            self.clone()
        }
    }
    let sink = Sink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let config = tracing::subscriber::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(load_config_from_str(yaml))
            .unwrap()
    });
    let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    assert!(
        logs.contains("only meaningful on `type: tproxy`/`shadowsocks`")
            && logs.contains("only meaningful on `type: tproxy`, ignored"),
        "expected both misuse warnings, got: {logs}"
    );

    let mixed = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "my-mixed")
        .expect("named mixed listener must exist");
    assert_eq!(mixed.spec, ListenerSpec::Mixed);
}

/// The shadowsocks listener keeps its own `udp` semantics (default true)
/// untouched by the tproxy reuse of the same raw key.
#[tokio::test]
async fn test_shadowsocks_udp_semantics_unchanged() {
    for (udp_line, expected) in [("", true), ("    udp: false\n", false)] {
        let yaml = format!(
            r#"
listeners:
  - name: my-ss
    type: shadowsocks
    listen: 127.0.0.1:8388
    cipher: aes-256-gcm
    password: secret
{udp_line}"#
        );
        let config = load_config_from_str(&yaml).await.unwrap();
        let ListenerSpec::Shadowsocks(ss) = &config.listeners.named[0].spec else {
            panic!("expected shadowsocks spec");
        };
        assert_eq!(ss.udp, expected, "udp_line={udp_line:?}");
    }
}

#[tokio::test]
async fn test_tproxy_named_listener_falls_back_to_global_sni() {
    let yaml = r#"
tproxy-sni: true
listeners:
  - name: my-tproxy
    type: tproxy
    listen: 127.0.0.1:7894
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let tproxy = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "my-tproxy")
        .expect("named tproxy listener must exist");
    assert_eq!(
        tproxy.spec,
        ListenerSpec::TProxy {
            sni: true,
            firewall: true,
            udp: false,
            udp_timeout: 60,
        },
        "named tproxy without per-listener tproxy-sni should fall back to global true"
    );
}

#[tokio::test]
async fn test_tproxy_named_listener_default_listen_is_loopback() {
    // Without an explicit `listen:`, a tproxy named listener should default
    // to 127.0.0.1 (matching the shorthand behaviour), not the global bind.
    let yaml = r#"
bind-address: 0.0.0.0
listeners:
  - name: my-tproxy
    type: tproxy
    port: 7895
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let tproxy = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "my-tproxy")
        .expect("named tproxy listener must exist");
    assert_eq!(
        tproxy.listen, "127.0.0.1",
        "tproxy named listener without explicit listen should default to 127.0.0.1"
    );
}

#[tokio::test]
async fn test_non_tproxy_listener_spec_values() {
    let yaml = r#"
listeners:
  - name: m
    type: mixed
    listen: 127.0.0.1:0
  - name: h
    type: http
    listen: 127.0.0.1:0
  - name: s
    type: socks5
    listen: 127.0.0.1:0
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let m = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "m")
        .unwrap();
    assert_eq!(m.spec, ListenerSpec::Mixed);
    let h = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "h")
        .unwrap();
    assert_eq!(h.spec, ListenerSpec::Http);
    let s = config
        .listeners
        .named
        .iter()
        .find(|nl| nl.name == "s")
        .unwrap();
    assert_eq!(s.spec, ListenerSpec::Socks5);
}

#[tokio::test]
async fn test_listener_type_name() {
    // type_name() is the canonical string used by the API (`GET /listeners`)
    // and startup logs. Verify it matches the upstream mihomo `type:` value.
    assert_eq!(ListenerSpec::Mixed.type_name(), "mixed");
    assert_eq!(ListenerSpec::Http.type_name(), "http");
    assert_eq!(ListenerSpec::Socks5.type_name(), "socks5");
    assert_eq!(
        ListenerSpec::TProxy {
            sni: true,
            firewall: true,
            udp: false,
            udp_timeout: 60,
        }
        .type_name(),
        "tproxy"
    );
    assert_eq!(
        ListenerSpec::TProxy {
            sni: false,
            firewall: true,
            udp: false,
            udp_timeout: 60,
        }
        .type_name(),
        "tproxy"
    );
}

#[tokio::test]
async fn test_unknown_listener_type_errors() {
    let yaml = r#"
listeners:
  - name: bad
    type: socks4
    listen: 127.0.0.1:0
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("unknown listener type must hard-error");
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("unknown listener type") && msg.contains("socks4"),
        "error should name the bad type: {msg}"
    );
}

// ── shadowsocks listener config parsing ────────────────────────────────────

use meow_config::{ObfsMode, SsListenerConfig};

fn ss_listener_yaml(body: &str) -> String {
    format!(
        r#"mode: direct
proxies:
  - name: d
    type: direct
rules:
  - MATCH,d
listeners:
  - name: ss-in
    type: shadowsocks
    listen: 127.0.0.1:18388
{body}
"#
    )
}

#[tokio::test]
async fn test_ss_listener_valid_defaults() {
    // cipher + password required; udp defaults to true (upstream parity).
    let yaml = ss_listener_yaml("    cipher: aes-256-gcm\n    password: secret\n");
    let config = load_config_from_str(&yaml).await.unwrap();
    let nl = &config.listeners.named[0];
    let ListenerSpec::Shadowsocks(ss) = &nl.spec else {
        panic!("expected Shadowsocks spec, got {:?}", nl.spec);
    };
    assert_eq!(ss.cipher, "aes-256-gcm");
    assert_eq!(ss.password, "secret");
    assert!(ss.udp, "udp should default to true");
    assert!(ss.simple_obfs.is_none());
}

#[tokio::test]
async fn test_ss_listener_ss_alias() {
    // `type: ss` is the short alias for `shadowsocks`.
    let yaml = ss_listener_yaml("    cipher: aes-256-gcm\n    password: secret\n")
        .replace("shadowsocks", "ss");
    let config = load_config_from_str(&yaml).await.unwrap();
    assert!(matches!(
        config.listeners.named[0].spec,
        ListenerSpec::Shadowsocks(_)
    ));
}

#[tokio::test]
async fn test_ss_listener_missing_cipher_errors() {
    let yaml = ss_listener_yaml("    password: secret\n");
    let Err(err) = load_config_from_str(&yaml).await else {
        panic!("missing cipher must hard-error");
    };
    assert!(
        format!("{err:#}").contains("cipher"),
        "msg should mention cipher"
    );
}

#[tokio::test]
async fn test_ss_listener_missing_password_errors() {
    let yaml = ss_listener_yaml("    cipher: aes-256-gcm\n");
    let Err(err) = load_config_from_str(&yaml).await else {
        panic!("missing password must hard-error");
    };
    assert!(format!("{err:#}").contains("password"));
}

#[tokio::test]
async fn test_ss_listener_invalid_obfs_mode_errors() {
    let yaml = ss_listener_yaml(
        "    cipher: aes-256-gcm\n    password: secret\n    simple-obfs:\n      enable: true\n      mode: quic\n",
    );
    let Err(err) = load_config_from_str(&yaml).await else {
        panic!("invalid obfs mode must hard-error");
    };
    assert!(format!("{err:#}").contains("quic"));
}

#[tokio::test]
async fn test_ss_listener_obfs_http_tls_parsed() {
    for mode in ["http", "tls"] {
        let yaml = ss_listener_yaml(&format!(
            "    cipher: aes-256-gcm\n    password: secret\n    simple-obfs:\n      enable: true\n      mode: {mode}\n"
        ));
        let config = load_config_from_str(&yaml).await.unwrap();
        let ListenerSpec::Shadowsocks(SsListenerConfig {
            simple_obfs: Some(o),
            ..
        }) = &config.listeners.named[0].spec
        else {
            panic!("expected obfs");
        };
        let expected = if mode == "http" {
            ObfsMode::Http
        } else {
            ObfsMode::Tls
        };
        assert_eq!(o.mode, expected, "mode {mode}");
    }
}

#[tokio::test]
async fn test_ss_listener_obfs_disabled_when_enable_false() {
    let yaml = ss_listener_yaml(
        "    cipher: aes-256-gcm\n    password: secret\n    simple-obfs:\n      enable: false\n      mode: http\n",
    );
    let config = load_config_from_str(&yaml).await.unwrap();
    let ListenerSpec::Shadowsocks(ss) = &config.listeners.named[0].spec else {
        panic!("expected ss");
    };
    assert!(ss.simple_obfs.is_none(), "enable:false must not set obfs");
}

#[tokio::test]
async fn test_ss_listener_unsupported_suboption_warns_not_errors() {
    // ADR-0002: unsupported upstream sub-options (shadow-tls, res-tls, …)
    // must warn and be ignored, not hard-error, so mihomo configs still boot.
    let yaml = ss_listener_yaml(
        "    cipher: aes-256-gcm\n    password: secret\n    shadow-tls:\n      version: v3\n",
    );
    let config = load_config_from_str(&yaml).await.unwrap();
    let ListenerSpec::Shadowsocks(ss) = &config.listeners.named[0].spec else {
        panic!("expected ss");
    };
    assert_eq!(ss.cipher, "aes-256-gcm");
}

#[tokio::test]
async fn test_ss_listener_udp_explicit_false() {
    let yaml = ss_listener_yaml("    cipher: aes-256-gcm\n    password: secret\n    udp: false\n");
    let config = load_config_from_str(&yaml).await.unwrap();
    let ListenerSpec::Shadowsocks(ss) = &config.listeners.named[0].spec else {
        panic!("expected ss");
    };
    assert!(!ss.udp);
}
