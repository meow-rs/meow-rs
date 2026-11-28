//! VLESS *listener* schema contracts (`listeners:` entry `type: vless`)
//! end-to-end through `load_config_from_str` — the same path startup,
//! `-t` and `PUT /configs` share. The fine-grained rejection matrix lives
//! in the `listener_surface_tests` unit tests inside `src/lib.rs`; this
//! file pins the full-config integration surface: happy paths for both
//! security modes, the dual `users` shape across anytls/vless in one
//! document, raw round-trip persistence, and `-t`-path validation.

use meow_config::{load_config_from_str, ListenerSpec};

const USER_A: &str =
    "      - username: alice\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n";
const USER_B: &str =
    "      - username: bob\n        uuid: \"b831381d-6324-4d53-ad4f-8cda48b30811\"\n        flow: xtls-rprx-vision\n";
const CERT: &str =
    "    certificate: \"-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\"\n    private-key: \"-----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----\"\n";
const REALITY: &str = "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo\"\n      short-id: [\"0123456789abcdef\", \"ab\"]\n      server-names: [\"example.com\", \"www.example.com\"]\n      max-time-difference: 60000000\n";

fn tls_doc() -> String {
    format!("listeners:\n  - name: vision-in\n    type: vless\n    port: 8443\n{CERT}    users:\n{USER_A}{USER_B}")
}

fn reality_doc() -> String {
    format!("listeners:\n  - name: vision-in\n    type: vless\n    port: 8443\n{REALITY}    users:\n{USER_A}")
}

async fn err_of(yaml: &str) -> String {
    match load_config_from_str(yaml).await {
        Err(e) => format!("{e:#}"),
        Ok(_) => panic!("config must fail to load\nyaml:\n{yaml}"),
    }
}

#[tokio::test]
async fn vless_listener_tls_end_to_end() {
    let config = load_config_from_str(&tls_doc())
        .await
        .unwrap_or_else(|e| panic!("config must load: {e:#}"));
    assert_eq!(config.listeners.named.len(), 1);
    let nl = &config.listeners.named[0];
    assert_eq!(nl.name, "vision-in");
    assert_eq!(nl.port, 8443);
    assert_eq!(nl.spec.type_name(), "vless");
    let ListenerSpec::Vless(cfg) = &nl.spec else {
        panic!("expected ListenerSpec::Vless, got {:?}", nl.spec);
    };
    assert_eq!(cfg.users.len(), 2);
    assert_eq!(cfg.users[0].username, "alice");
    assert_eq!(cfg.users[1].username, "bob");
    assert!(cfg.udp);
    assert!(matches!(
        cfg.security,
        meow_config::VlessSecurity::StandardTls { .. }
    ));
}

#[tokio::test]
async fn vless_listener_reality_end_to_end() {
    let config = load_config_from_str(&reality_doc())
        .await
        .unwrap_or_else(|e| panic!("config must load: {e:#}"));
    let nl = &config.listeners.named[0];
    let ListenerSpec::Vless(cfg) = &nl.spec else {
        panic!("expected ListenerSpec::Vless, got {:?}", nl.spec);
    };
    let meow_config::VlessSecurity::Reality(rc) = &cfg.security else {
        panic!("expected REALITY mode");
    };
    assert_eq!(rc.dest, "www.example.com:443");
    assert_eq!(rc.short_ids.len(), 2);
    // `"ab"` right-zero-pads into the 8-byte comparison form.
    assert_eq!(rc.short_ids[1][..2], [0xab, 0x00]);
    assert_eq!(rc.server_names.len(), 2);
    assert_eq!(rc.max_time_difference_us, 60_000_000);
}

#[tokio::test]
async fn vless_rejection_reaches_full_load_path() {
    // The `-t`/startup/PUT shared surface: a shape violation deep inside
    // the listener spec must fail the WHOLE document load, not just the
    // listener builder.
    let err = err_of(&format!(
        "listeners:\n  - name: vision-in\n    type: vless\n    port: 8443\n    users:\n{USER_A}"
    ))
    .await;
    assert!(err.contains("no plaintext mode"), "{err}");

    // Wrong flow rejected end-to-end.
    let err = err_of(&format!(
        "listeners:\n  - name: vision-in\n    type: vless\n    port: 8443\n{CERT}    users:\n      - username: a\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision-udp443\n"
    ))
    .await;
    assert!(err.contains("client-local"), "{err}");

    // REALITY + certificate exclusivity end-to-end.
    let err = err_of(&format!(
        "listeners:\n  - name: vision-in\n    type: vless\n    port: 8443\n{CERT}{REALITY}    users:\n{USER_A}"
    ))
    .await;
    assert!(err.contains("mutually exclusive"), "{err}");
}

#[tokio::test]
async fn vless_and_anytls_users_shapes_coexist() {
    // One document, both user-table shapes: the anytls mapping and the
    // vless list must parse side by side and build their own typed
    // forms — the dual-shape capture must not regress either.
    let yaml = format!(
        "listeners:\n  - name: vision-in\n    type: vless\n    port: 0\n{CERT}    users:\n{USER_A}  - name: anytls-in\n    type: anytls\n    port: 0\n    allow-insecure: true\n    users:\n      carol: pw1\n      dave: pw2\n"
    );
    let config = load_config_from_str(&yaml)
        .await
        .unwrap_or_else(|e| panic!("config must load: {e:#}"));
    assert_eq!(config.listeners.named.len(), 2);
    let ListenerSpec::Vless(vless_cfg) = &config.listeners.named[0].spec else {
        panic!("expected vless spec");
    };
    assert_eq!(vless_cfg.users.len(), 1);
    let ListenerSpec::Anytls(anytls_cfg) = &config.listeners.named[1].spec else {
        panic!("expected anytls spec");
    };
    assert_eq!(
        anytls_cfg
            .users
            .iter()
            .map(|u| u.name.as_str())
            .collect::<Vec<_>>(),
        ["carol", "dave"]
    );

    // Cross-shape misuse errors end-to-end: list on anytls, map on vless.
    let err = err_of(
        "listeners:\n  - name: a\n    type: anytls\n    port: 0\n    allow-insecure: true\n    users:\n      - username: x\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n",
    )
    .await;
    assert!(err.contains("MAPPING"), "{err}");
    let err = err_of(&format!(
        "listeners:\n  - name: v\n    type: vless\n    port: 0\n{CERT}    users: {{alice: pw}}\n"
    ))
    .await;
    assert!(err.contains("LIST"), "{err}");
}

#[tokio::test]
async fn vless_raw_round_trip_preserves_users_shape() {
    // The save path re-serializes the raw document: the vless users list
    // must round-trip as a list (and reality-config as a mapping), the
    // way the anytls mapping round-trips as a mapping.
    let yaml = reality_doc();
    let raw: meow_config::raw::RawConfig = meow_config::parse_raw_yaml(&yaml).unwrap();
    let out = serde_saphyr::to_string_with_options(
        &raw,
        serde_saphyr::ser_options! { folded_wrap_chars: usize::MAX },
    )
    .unwrap();
    let raw2: meow_config::raw::RawConfig = meow_config::parse_raw_yaml(&out).unwrap();
    let users2 = raw2.listeners.as_ref().unwrap()[0].users.clone();
    let Some(meow_config::raw::RawListenerUsers::List(entries)) = users2 else {
        panic!("vless users must round-trip as a list");
    };
    assert_eq!(entries.len(), 1);
    // …and the re-parsed document still builds the same typed spec.
    let listeners = meow_config::resolve_named_listeners(&raw2).unwrap();
    assert!(matches!(listeners[0].spec, ListenerSpec::Vless(_)));
}

#[tokio::test]
async fn anytls_users_mapping_round_trip_unchanged() {
    // Regression pin for the pre-vless contract: the anytls mapping
    // round-trips as a mapping with the same key order and values.
    let yaml = "listeners:\n  - name: a\n    type: anytls\n    port: 0\n    allow-insecure: true\n    users:\n      zeta: pw-z\n      alpha: pw-a\n";
    let raw: meow_config::raw::RawConfig = meow_config::parse_raw_yaml(yaml).unwrap();
    let out = serde_saphyr::to_string_with_options(
        &raw,
        serde_saphyr::ser_options! { folded_wrap_chars: usize::MAX },
    )
    .unwrap();
    let raw2: meow_config::raw::RawConfig = meow_config::parse_raw_yaml(&out).unwrap();
    let users2 = raw2.listeners.as_ref().unwrap()[0].users.clone();
    let Some(meow_config::raw::RawListenerUsers::Mapping(pairs)) = users2 else {
        panic!("anytls users must round-trip as a mapping");
    };
    assert_eq!(
        pairs,
        vec![
            ("zeta".to_string(), "pw-z".to_string()),
            ("alpha".to_string(), "pw-a".to_string())
        ]
    );
}

fn reality_doc_with_mimic(mimic: &str) -> String {
    reality_doc().replace(
        "      max-time-difference: 60000000\n",
        &format!("      max-time-difference: 60000000\n{mimic}"),
    )
}

async fn reality_mimic(yaml: &str) -> meow_common::VlessRealityMimicSpec {
    let config = load_config_from_str(yaml)
        .await
        .unwrap_or_else(|e| panic!("config must load: {e:#}\nyaml:\n{yaml}"));
    let ListenerSpec::Vless(cfg) = &config.listeners.named[0].spec else {
        panic!("expected vless");
    };
    let meow_config::VlessSecurity::Reality(rc) = &cfg.security else {
        panic!("expected reality");
    };
    rc.mimic
}

#[tokio::test]
async fn vless_reality_mimic_absent_empty_and_explicit_defaults_are_identical() {
    use meow_common::{VlessRealityMimicMode, VlessRealityMimicSpec};

    let absent = reality_mimic(&reality_doc()).await;
    assert_eq!(absent, VlessRealityMimicSpec::default());
    assert_eq!(absent.mode, VlessRealityMimicMode::DialFirst);
    assert_eq!(absent.probe_timeout_ms, 3_000);
    assert_eq!(absent.quiescence_min_ms, 15);
    assert_eq!(absent.quiescence_max_ms, 40);
    assert_eq!(absent.max_concurrent_probes, 64);

    for suffix in ["      mimic: {}\n"] {
        let yaml = reality_doc_with_mimic(suffix);
        assert_eq!(reality_mimic(&yaml).await, absent, "suffix {suffix:?}");
    }

    let explicit = reality_doc_with_mimic(
        "      mimic:\n        mode: dial-first\n        probe-timeout-ms: 3000\n        quiescence-min-ms: 15\n        quiescence-max-ms: 40\n        max-concurrent-probes: 64\n",
    );
    assert_eq!(reality_mimic(&explicit).await, absent);

    // Serde persistence of the typed listener carries the normalized form,
    // including for an originally absent block.
    let json = serde_json::to_value(absent).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "mode": "dial-first",
            "probe-timeout-ms": 3000,
            "quiescence-min-ms": 15,
            "quiescence-max-ms": 40,
            "max-concurrent-probes": 64,
        })
    );
}

#[tokio::test]
async fn vless_reality_mimic_valid_explicit_fields_and_mode_off() {
    let yaml = reality_doc_with_mimic(
        "      mimic:\n        mode: off\n        probe-timeout-ms: 15000\n        quiescence-min-ms: 200\n        quiescence-max-ms: 500\n        max-concurrent-probes: 256\n",
    );
    let spec = reality_mimic(&yaml).await;
    assert_eq!(spec.mode, meow_common::VlessRealityMimicMode::Off);
    assert_eq!(spec.probe_timeout_ms, 15_000);
    assert_eq!(spec.quiescence_min_ms, 200);
    assert_eq!(spec.quiescence_max_ms, 500);
    assert_eq!(spec.max_concurrent_probes, 256);

    let yaml = reality_doc_with_mimic(
        "      mimic:\n        probe-timeout-ms: 500\n        quiescence-min-ms: 5\n        quiescence-max-ms: 10\n        max-concurrent-probes: 1\n",
    );
    let spec = reality_mimic(&yaml).await;
    assert_eq!(spec.mode, meow_common::VlessRealityMimicMode::DialFirst);
    assert_eq!(spec.probe_timeout_ms, 500);
    assert_eq!(spec.quiescence_min_ms, 5);
    assert_eq!(spec.quiescence_max_ms, 10);
    assert_eq!(spec.max_concurrent_probes, 1);
}

#[tokio::test]
async fn vless_reality_mimic_rejection_matrix() {
    let cases: &[(&str, &str)] = &[
        ("      mimic: null\n", "null"),
        ("      mimic: 5\n", "mapping"),
        ("      mimic: []\n", "mapping"),
        ("      mimic:\n        unknown: 1\n", "unknown"),
        ("      mimic:\n        mode: null\n", "mode"),
        ("      mimic:\n        mode: auto\n", "mode"),
        ("      mimic:\n        probe-timeout-ms: null\n", "null"),
        (
            "      mimic:\n        probe-timeout-ms: 499\n",
            "probe-timeout-ms",
        ),
        (
            "      mimic:\n        probe-timeout-ms: 15001\n",
            "probe-timeout-ms",
        ),
        (
            "      mimic:\n        probe-timeout-ms: 3000.0\n",
            "integer",
        ),
        (
            "      mimic:\n        probe-timeout-ms: \"3000\"\n",
            "integer",
        ),
        (
            "      mimic:\n        quiescence-min-ms: 4\n",
            "quiescence-min-ms",
        ),
        (
            "      mimic:\n        quiescence-min-ms: 201\n",
            "quiescence-min-ms",
        ),
        (
            "      mimic:\n        quiescence-max-ms: 9\n",
            "quiescence-max-ms",
        ),
        (
            "      mimic:\n        quiescence-max-ms: 501\n",
            "quiescence-max-ms",
        ),
        (
            "      mimic:\n        quiescence-min-ms: 41\n        quiescence-max-ms: 40\n",
            "quiescence-min",
        ),
        (
            "      mimic:\n        probe-timeout-ms: 500\n        quiescence-max-ms: 500\n",
            "probe-timeout",
        ),
        (
            "      mimic:\n        max-concurrent-probes: 0\n",
            "max-concurrent-probes",
        ),
        (
            "      mimic:\n        max-concurrent-probes: 257\n",
            "max-concurrent-probes",
        ),
        // Explicit numeric fields are validated even in the rollback mode.
        (
            "      mimic:\n        mode: off\n        max-concurrent-probes: 0\n",
            "max-concurrent-probes",
        ),
        (
            "      mimic:\n        mode: off\n        quiescence-min-ms: 41\n",
            "quiescence-min",
        ),
    ];
    for (mimic, hint) in cases {
        let err = err_of(&reality_doc_with_mimic(mimic)).await;
        assert!(
            err.contains(hint),
            "expected {hint:?} in {err:?}\ncase:\n{mimic}"
        );
    }

    // YAML duplicate keys fail before semantic parsing, on the same shared path.
    let err = err_of(&reality_doc_with_mimic(
        "      mimic:\n        mode: off\n        mode: off\n",
    ))
    .await;
    assert!(err.contains("duplicate"), "{err}");
}

#[tokio::test]
async fn vless_mimic_is_reality_only_not_standard_tls_surface() {
    // A same-named top-level key on the standard-TLS listener is not a
    // spelling variant of reality-config.mimic and must remain an error.
    let yaml = tls_doc().replace("    users:\n", "    mimic:\n      mode: off\n    users:\n");
    let err = err_of(&yaml).await;
    assert!(err.contains("mimic"), "{err}");

    // Nested under the wrong security surface is rejected by the existing
    // TLS/REALITY exclusivity gate rather than reinterpreted.
    let yaml = tls_doc().replace(
        "    users:\n",
        "    reality-config:\n      mimic:\n        mode: off\n    users:\n",
    );
    let err = err_of(&yaml).await;
    assert!(err.contains("mutually exclusive"), "{err}");
}
