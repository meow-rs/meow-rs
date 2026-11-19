//! Config-parser tests for `listeners:` `type: tun` entries (spec §3 —
//! the named TUN listener surface).
//!
//! These exercise [`meow_config::load_config_from_str`] end-to-end and
//! assert on the `ListenerSpec::Tun` inside `Config.listeners.named` —
//! `parse_named_tun_config` is exercised through it.
//!
//! # Test plan coverage (NT-series)
//!
//! | ID   | Description                                                        |
//! |------|--------------------------------------------------------------------|
//! | NT1  | minimal entry → named defaults (mtu 9000, udp-timeout 300s,        |
//! |      | auto-route off, dns-hijack on, stack lwip, fake-IP-derived /30)    |
//! | NT2  | `0` on mtu/udp-timeout means "default" on the named path           |
//! | NT3  | flat TUN fields land (`device`, `stack`, `auto-route`,             |
//! |      | `dns-hijack`, `inet4-address`, `outbound-interface`)               |
//! | NT4  | stack: `system`/`mixed` → System; `mips`/`gvisor` → Lwip;          |
//! |      | `lwip` accepted; unknown spelling → hard error                     |
//! | NT5  | socket-shape keys (`port`, `listen`, `enable`, nested `tun:`)      |
//! |      | → hard error                                                       |
//! | NT6  | two named TUNs → hard error                                        |
//! | NT7  | named TUN + `tun.enable: true` → hard error; disabled              |
//! |      | top-level section is fine                                          |
//! | NT8  | named TUN shares the listener name registry                        |
//! | NT9  | `proxy`/`rule` land as route_override; undefined `sub-rules:`      |
//! |      | reference → hard error                                             |
//! | NT10 | `dns-hijack` absent → on; `[]` → off; non-:53 entries warn+ignored |
//! | NT11 | `inet4-address` first-of-list; invalid CIDR → hard error;          |
//! |      | `inet6-address` global-only                                        |
//! | NT12 | `auto-route` strings: `global`, `fake-ip`, bogus → hard error      |
//! | NT13 | `named_tun_global_route_interface` agrees with the parsed spec     |

use meow_config::{load_config_from_str, ListenerSpec, TunStack};

/// A `listeners:` document with one `type: tun` entry; `extra` fields
/// splice in at 4-space indent (empty string = minimal form).
fn tun_yaml(extra: &str) -> String {
    format!("listeners:\n  - name: tun0\n    type: tun\n{extra}")
}

/// Parse the doc and return the single named listener's `TunConfig`.
async fn build_tun(yaml: &str) -> meow_config::TunConfig {
    let config = load_config_from_str(yaml)
        .await
        .unwrap_or_else(|e| panic!("config must load: {e:#}\nyaml:\n{yaml}"));
    let nl = config
        .listeners
        .named
        .iter()
        .find(|l| l.name == "tun0")
        .expect("named listener present");
    let ListenerSpec::Tun(cfg) = &nl.spec else {
        panic!("expected ListenerSpec::Tun, got {:?}", nl.spec);
    };
    cfg.clone()
}

async fn err_of(yaml: &str) -> String {
    match load_config_from_str(yaml).await {
        Err(e) => format!("{e:#}"),
        Ok(_) => panic!("config must fail to load\nyaml:\n{yaml}"),
    }
}

// ─── NT1: the named defaults profile ────────────────────────────────────

#[tokio::test]
async fn nt1_minimal_entry_uses_named_defaults() {
    let cfg = build_tun(&tun_yaml("")).await;
    assert!(cfg.enable, "the entry's presence is the enabled state");
    assert_eq!(cfg.mtu, 9000, "named profile: MTU 9000");
    assert_eq!(
        cfg.udp_timeout,
        std::time::Duration::from_secs(300),
        "named profile: UDP idle timeout 300s"
    );
    assert!(!cfg.auto_route, "named profile: auto-route off");
    assert!(cfg.dns_hijack, "named profile: dns-hijack on");
    assert_eq!(cfg.stack, TunStack::Lwip);
    assert_eq!(
        cfg.inet4_address.to_string(),
        "198.18.0.1/30",
        "default device address derives from the fake-IP range"
    );
    assert_eq!(cfg.max_connections, 256, "inherits global max-connections");
}

#[tokio::test]
async fn nt1_device_and_explicit_fields_land() {
    let cfg = build_tun(&tun_yaml(
        "    device: utun9\n    mtu: 1500\n    max-connections: 64\n",
    ))
    .await;
    assert_eq!(cfg.device.as_deref(), Some("utun9"));
    assert_eq!(cfg.mtu, 1500);
    assert_eq!(cfg.max_connections, 64);
}

// ─── NT2: explicit 0 means "default" on the named path ──────────────────

#[tokio::test]
async fn nt2_zero_means_default_for_mtu_and_udp_timeout() {
    let cfg = build_tun(&tun_yaml("    mtu: 0\n    udp-timeout: 0\n")).await;
    assert_eq!(cfg.mtu, 9000);
    assert_eq!(cfg.udp_timeout, std::time::Duration::from_secs(300));
}

#[tokio::test]
async fn nt2_mtu_below_ipv6_floor_is_a_hard_error() {
    let err = err_of(&tun_yaml("    mtu: 1200\n")).await;
    assert!(
        err.contains("listeners[tun0].mtu") && err.contains("1280"),
        "unexpected error: {err}"
    );
}

// ─── NT3: stack spellings ───────────────────────────────────────────────

#[tokio::test]
async fn nt3_stack_system_and_mixed_select_kernel_stack() {
    for spelling in ["system", "mixed"] {
        let cfg = build_tun(&tun_yaml(&format!("    stack: {spelling}\n"))).await;
        assert_eq!(cfg.stack, TunStack::System, "stack: {spelling}");
    }
}

#[tokio::test]
async fn nt3_stack_mips_and_gvisor_fold_to_lwip() {
    for spelling in ["mips", "gvisor", "lwip"] {
        let cfg = build_tun(&tun_yaml(&format!("    stack: {spelling}\n"))).await;
        assert_eq!(cfg.stack, TunStack::Lwip, "stack: {spelling}");
    }
}

#[tokio::test]
async fn nt3_unknown_stack_is_a_hard_error() {
    let err = err_of(&tun_yaml("    stack: turbo\n")).await;
    assert!(
        err.contains("listeners[tun0].stack") && err.contains("turbo"),
        "unexpected error: {err}"
    );
}

// ─── NT4: socket-shape keys are shape errors ────────────────────────────

#[tokio::test]
async fn nt4_socket_shape_keys_are_hard_errors() {
    for extra in [
        "    port: 9090\n",
        "    listen: 127.0.0.1:9090\n",
        "    enable: true\n",
        "    tun:\n      enable: true\n",
    ] {
        let err = err_of(&tun_yaml(extra)).await;
        assert!(
            err.contains("flat on the entry"),
            "{extra:?} must fail with the flat-form diagnostic, got: {err}"
        );
    }
}

// ─── NT5: one effective TUN ─────────────────────────────────────────────

#[tokio::test]
async fn nt5_two_named_tuns_are_a_hard_error() {
    let err =
        err_of("listeners:\n  - name: tun-a\n    type: tun\n  - name: tun-b\n    type: tun\n")
            .await;
    assert!(
        err.contains("one effective TUN") || err.contains("second named"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn nt5_named_tun_plus_enabled_top_level_is_a_hard_error() {
    let yaml = format!("tun:\n  enable: true\n{}", tun_yaml(""));
    let err = err_of(&yaml).await;
    assert!(
        err.contains("cannot coexist") && err.contains("tun.enable"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn nt5_named_tun_coexists_with_disabled_top_level() {
    let yaml = format!("tun:\n  enable: false\n{}", tun_yaml(""));
    let config = load_config_from_str(&yaml)
        .await
        .expect("disabled top-level section must not collide");
    assert!(!config.tun.enable);
    let cfg = build_tun(&yaml).await;
    assert!(cfg.enable);
}

// ─── NT6: name registry is shared ───────────────────────────────────────

#[tokio::test]
async fn nt6_name_collides_with_socket_listener() {
    let err = err_of(
        "listeners:\n  - name: dup\n    type: socks\n    port: 1080\n  - name: dup\n    type: tun\n",
    )
    .await;
    assert!(err.contains("dup"), "unexpected error: {err}");
}

// ─── NT7: route overrides ───────────────────────────────────────────────

#[tokio::test]
async fn nt7_proxy_and_rule_land_as_route_override() {
    let yaml = format!(
        "proxies:\n  - name: out\n    type: direct\n\nsub-rules:\n  bulk: ['DOMAIN,example.com,out']\n\nrules:\n  - MATCH,out\n\n{}",
        tun_yaml("    proxy: out\n    rule: bulk\n")
    );
    let config = load_config_from_str(&yaml)
        .await
        .unwrap_or_else(|e| panic!("config must load: {e:#}\nyaml:\n{yaml}"));
    let nl = &config.listeners.named[0];
    let ov = nl.route_override.as_ref().expect("route override present");
    assert_eq!(ov.proxy.as_deref(), Some("out"));
    assert_eq!(ov.rule.as_deref(), Some("bulk"));
}

#[tokio::test]
async fn nt7_undefined_sub_rules_reference_is_a_hard_error() {
    let err = err_of(&tun_yaml("    rule: missing\n")).await;
    assert!(
        err.contains("undefined sub-rules"),
        "unexpected error: {err}"
    );
}

// ─── NT8: dns-hijack forms ──────────────────────────────────────────────

#[tokio::test]
async fn nt8_dns_hijack_forms() {
    assert!(build_tun(&tun_yaml("")).await.dns_hijack);
    assert!(
        !build_tun(&tun_yaml("    dns-hijack: []\n"))
            .await
            .dns_hijack
    );
    assert!(
        build_tun(&tun_yaml("    dns-hijack: [any:53]\n"))
            .await
            .dns_hijack
    );
    assert!(
        build_tun(&tun_yaml("    dns-hijack: [0.0.0.0:53]\n"))
            .await
            .dns_hijack
    );
    // Non-:53 targets warn and are ignored rather than reinterpreted.
    assert!(
        !build_tun(&tun_yaml("    dns-hijack: [8.8.8.8:5353]\n"))
            .await
            .dns_hijack
    );
}

// ─── NT9: addresses ─────────────────────────────────────────────────────

#[tokio::test]
async fn nt9_inet4_first_of_list_and_invalid_cidr() {
    let cfg = build_tun(&tun_yaml("    inet4-address: [192.0.2.1/24]\n")).await;
    assert_eq!(cfg.inet4_address.to_string(), "192.0.2.1/24");
    let err = err_of(&tun_yaml("    inet4-address: not-a-cidr\n")).await;
    assert!(
        err.contains("listeners[tun0].inet4-address"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn nt9_inet6_only_in_global_scope() {
    // Without global auto-route the IPv6 address is normalised out.
    let cfg = build_tun(&tun_yaml("    inet6-address: fdfe:dcba:987::1/64\n")).await;
    assert!(cfg.inet6_address.is_none());
    let cfg = build_tun(&tun_yaml(
        "    auto-route: global\n    inet6-address: fdfe:dcba:987::1/64\n",
    ))
    .await;
    assert_eq!(
        cfg.inet6_address
            .expect("global scope keeps IPv6")
            .to_string(),
        "fdfe:dcba:987::1/64"
    );
}

// ─── NT10: auto-route forms ─────────────────────────────────────────────

#[tokio::test]
async fn nt10_auto_route_bool_and_mode_strings() {
    assert!(!build_tun(&tun_yaml("")).await.auto_route);
    for (spelling, global) in [
        ("true", true),
        ("global", true),
        ("fake-ip", false),
        ("false", false),
    ] {
        let cfg = build_tun(&tun_yaml(&format!("    auto-route: {spelling}\n"))).await;
        assert_eq!(
            cfg.auto_route,
            global || spelling == "fake-ip",
            "{spelling}"
        );
        if spelling == "fake-ip" {
            assert!(cfg.auto_route);
        }
    }
    let err = err_of(&tun_yaml("    auto-route: everywhere\n")).await;
    assert!(
        err.contains("listeners[tun0].auto-route"),
        "unexpected error: {err}"
    );
}

// ─── NT11: socket-only keys warn, not err ───────────────────────────────

#[tokio::test]
async fn nt11_socket_only_fields_warn_not_error() {
    // `firewall`, `udp`, `cipher`, `routing-mark`, `tproxy-sni`,
    // `transparent` are meaningful only on socket listener types.
    let cfg = build_tun(&tun_yaml(
        "    firewall: false\n    udp: true\n    cipher: aes-128-gcm\n    routing-mark: 5\n",
    ))
    .await;
    assert!(cfg.enable);
}

#[tokio::test]
async fn nt11_unsupported_upstream_fields_warn_not_error() {
    let cfg = build_tun(&tun_yaml(
        "    auto-detect-interface: true\n    strict-route: true\n    dns-mode: fake-ip\n    gso: true\n",
    ))
    .await;
    assert!(cfg.enable);
}

// ─── NT12: early-binding helper agrees with the spec ────────────────────

#[tokio::test]
async fn nt12_named_tun_global_route_interface() {
    // Global scope carries the optional interface through.
    let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(
        "listeners:\n  - name: t\n    type: tun\n    auto-route: global\n    outbound-interface: eth0\n",
    )
    .unwrap();
    assert_eq!(
        meow_config::named_tun_global_route_interface(&raw),
        Some(Some("eth0".to_string()))
    );
    // Global scope without the key → Some(None).
    let raw: meow_config::raw::RawConfig =
        serde_saphyr::from_str("listeners:\n  - name: t\n    type: tun\n    auto-route: true\n")
            .unwrap();
    assert_eq!(
        meow_config::named_tun_global_route_interface(&raw),
        Some(None)
    );
    // Off / fake-ip / absent listener → None.
    for yaml in [
        "listeners:\n  - name: t\n    type: tun\n",
        "listeners:\n  - name: t\n    type: tun\n    auto-route: fake-ip\n",
        "listeners:\n  - name: s\n    type: socks\n    port: 1080\n",
    ] {
        let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(
            meow_config::named_tun_global_route_interface(&raw),
            None,
            "{yaml}"
        );
    }
}
