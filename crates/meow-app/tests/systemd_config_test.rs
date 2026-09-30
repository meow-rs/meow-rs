#![cfg(unix)] // systemd is Linux-only; PermissionsExt is unavailable on Windows.

use meow_config::raw::RawConfig;
use meow_config::save_raw_config;
use std::os::unix::fs::PermissionsExt;

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

// ── systemd unit generation tests ───────────────────────────────────

#[test]
fn systemd_unit_generation_table() {
    // Table of (case_label, bin_path, config_path, expected_substrings).
    // Rows correspond 1:1 to the former standalone tests:
    //   read-write paths for config dir        <- unit_contains_read_write_paths_for_config_dir
    //   exec start uses absolute config path   <- unit_exec_start_uses_absolute_config_path
    //   hardening: protect system strict       <- unit_has_protect_system_strict
    //   working directory matches config parent<- unit_working_directory_matches_config_parent
    //   nested config path consistency         <- unit_paths_consistent_for_nested_config
    //   edge case: config at filesystem root   <- unit_root_config_path_defaults_to_slash
    let cases: &[(&str, &str, &str, &[&str])] = &[
        (
            "read-write paths for config dir",
            "/usr/bin/meow",
            "/etc/meow/config.yaml",
            &["ReadWritePaths=\"/etc/meow\""],
        ),
        (
            "exec start uses absolute config path",
            "/usr/bin/meow",
            "/etc/meow/config.yaml",
            &["ExecStart=\"/usr/bin/meow\" -f \"/etc/meow/config.yaml\""],
        ),
        (
            "hardening: protect system strict",
            "/usr/bin/meow",
            "/etc/meow/config.yaml",
            &["ProtectSystem=strict"],
        ),
        (
            "working directory matches config parent",
            "/usr/bin/meow",
            "/opt/meow/config.yaml",
            &["WorkingDirectory=/opt/meow", "ReadWritePaths=\"/opt/meow\""],
        ),
        (
            "nested config path consistency",
            "/usr/bin/meow",
            "/var/lib/meow/configs/config.yaml",
            &[
                "WorkingDirectory=/var/lib/meow/configs",
                "ReadWritePaths=\"/var/lib/meow/configs\"",
            ],
        ),
        (
            "edge case: config at filesystem root",
            "/usr/bin/meow",
            "/config.yaml",
            &["WorkingDirectory=/", "ReadWritePaths=\"/\""],
        ),
    ];

    // Every case runs even if an earlier one fails, so a single run reports
    // all mismatches instead of stopping at the first.
    let mut failures: Vec<String> = Vec::new();
    for &(label, bin, config_path, expected) in cases {
        let unit =
            meow_app::generate_systemd_unit(bin, config_path).expect("benign paths must generate");
        for needle in expected {
            if !unit.contains(needle) {
                failures.push(format!(
                    "[{label}] generate_systemd_unit({bin:?}, {config_path:?}) is missing {needle:?}\ngenerated unit:\n{unit}"
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "systemd unit generation mismatches:\n{}",
        failures.join("\n---\n")
    );
}

#[test]
fn systemd_unit_emits_each_field_per_its_grammar() {
    // ExecStart argv and ReadWritePaths are quoted word lists;
    // WorkingDirectory is a raw rvalue — systemd does not unquote it
    // (issue #689).
    let unit = meow_app::generate_systemd_unit("/opt/my dir/meow", "/etc/100% real/config.yaml")
        .expect("space/percent paths must generate");

    assert!(
        unit.contains("ExecStart=\"/opt/my dir/meow\" -f \"/etc/100%% real/config.yaml\""),
        "ExecStart must quote argv and double %:\n{unit}"
    );
    assert!(
        unit.contains("WorkingDirectory=/etc/100%% real"),
        "WorkingDirectory must be RAW (no quotes), %% escaped:\n{unit}"
    );
    assert!(
        !unit.contains("WorkingDirectory=\""),
        "quoting WorkingDirectory makes the unit unloadable:\n{unit}"
    );
    assert!(
        unit.contains("ReadWritePaths=\"/etc/100%% real\""),
        "ReadWritePaths must quote entries:\n{unit}"
    );
    assert!(!unit.contains("100% "), "unescaped % survived:\n{unit}");

    // Escapes inside the quoted argument slot.
    let unit2 = meow_app::generate_systemd_unit("/usr/bin/meow", "/etc/a\"b\\c/d$config.yaml")
        .expect("quote/backslash/$ path must generate");
    assert!(
        unit2.contains("-f \"/etc/a\\\"b\\\\c/d$$config.yaml\""),
        "arg escaping wrong (\\\" \\\\ $$):\n{unit2}"
    );

    // `%` in the program slot doubles too; `${...}` becomes `$${...}`
    // so systemd cannot env-expand it — but only in the argv argument:
    // command->path is not argv, so the program word must keep `$`
    // verbatim (and WorkingDirectory/ReadWritePaths never env-expand).
    let unit3 = meow_app::generate_systemd_unit("/usr/100%bin/me$ow", "/etc/${X}/config.yaml")
        .expect("percent/env-looking paths must generate");
    assert!(
        unit3.contains("ExecStart=\"/usr/100%%bin/me$ow\" -f \"/etc/$${X}/config.yaml\""),
        "exe %% + verbatim $ + arg $$ wrong:\n{unit3}"
    );
    assert!(
        !unit3.contains("-f \"/etc/${X}"),
        "bare ${{X}} in the argv slot would env-expand at runtime:\n{unit3}"
    );
    assert!(
        unit3.contains("WorkingDirectory=/etc/${X}"),
        "WorkingDirectory keeps $ verbatim (no env expansion there):\n{unit3}"
    );
    assert!(
        unit3.contains("ReadWritePaths=\"/etc/${X}\""),
        "ReadWritePaths keeps $ verbatim (no env expansion there):\n{unit3}"
    );
}

#[test]
fn systemd_unit_arg_slot_c_escapes() {
    // A control char in the *filename* of a clean dir is representable
    // in the ExecStart -f argument (CUNESCAPE decodes \n/\r/\t) — this
    // is the only slot with an escape channel; the dir half stays clean.
    for (label, cfg, needle) in [
        ("tab", "/etc/meow/a\tb.yaml", "-f \"/etc/meow/a\\tb.yaml\""),
        (
            "newline",
            "/etc/meow/a\nb.yaml",
            "-f \"/etc/meow/a\\nb.yaml\"",
        ),
        ("cr", "/etc/meow/a\rb.yaml", "-f \"/etc/meow/a\\rb.yaml\""),
    ] {
        let unit = meow_app::generate_systemd_unit("/usr/bin/meow", cfg)
            .unwrap_or_else(|e| panic!("[{label}] arg slot must generate: {e}"));
        assert!(
            unit.contains(needle),
            "[{label}] missing {needle:?}:\n{unit}"
        );
        assert!(
            !unit.contains(cfg),
            "[{label}] raw control char must not survive:\n{unit}"
        );
    }
}

#[test]
fn systemd_unit_rejects_unrepresentable_paths() {
    let gen = |exe: &str, cfg: &str| meow_app::generate_systemd_unit(exe, cfg);

    // C0 has no escape anywhere except the ExecStart -f argument — and
    // the config dir feeds WorkingDirectory/ReadWritePaths where even
    // \n/\r/\t are unrepresentable, so the whole unit is rejected.
    for (label, bad) in [
        ("bell", "/x/a\x07b"),
        ("vtab", "/x/a\x0bb"),
        ("nul-in-path", "/x/a\0b"),
        ("newline-in-dir", "/etc/a\nb"),
        ("tab-in-dir", "/etc/a\tb"),
        ("cr-in-dir", "/etc/a\rb"),
    ] {
        let err = gen("/usr/bin/meow", &format!("{bad}/config.yaml"))
            .expect_err(&format!("[{label}] config path must be rejected"));
        assert!(
            err.to_string().contains("cannot represent"),
            "[{label}] unexpected error: {err}"
        );
    }

    // exe_path program word: systemd's string_is_safe refuses these.
    for (label, bad) in [
        ("quote", "/opt/a\"b/meow"),
        ("apostrophe", "/opt/a'b/meow"),
        ("backslash", "/opt/a\\b/meow"),
        ("del", "/opt/a\x7fb/meow"),
        ("newline", "/opt/a\nb/meow"),
    ] {
        let err = gen(bad, "/etc/meow/config.yaml")
            .expect_err(&format!("[{label}] exe path must be rejected"));
        let _ = err;
    }

    // ':' in work_dir would parse as a ReadWritePaths bind pair.
    gen("/usr/bin/meow", "/etc/a:b/config.yaml").expect_err("':' in work_dir must be rejected");

    // Relative or `..`-containing paths produce non-absolute/broken dirs.
    for (label, cfg) in [
        ("bare filename", "config.yaml"),
        ("relative", "etc/meow/config.yaml"),
        ("dotdot", "/etc/../x/config.yaml"),
    ] {
        gen("/usr/bin/meow", cfg).expect_err(&format!("[{label}] must be rejected"));
    }

    // Same for exe_path: program word must be absolute, `..`-free, and
    // not a directory.
    for (label, exe) in [
        ("relative exe", "meow"),
        ("dotdot exe", "/opt/../x/meow"),
        ("dir exe", "/opt/meow/"),
    ] {
        gen(exe, "/etc/meow/config.yaml").expect_err(&format!("[{label}] must be rejected"));
    }

    // WorkingDirectory hazards: trailing backslash (line continuation),
    // trailing whitespace, and '#' / ';' comment-separator chars.
    for (label, cfg) in [
        ("trailing backslash", "/etc/a\\/config.yaml"),
        ("trailing space dir", "/etc/a /config.yaml"),
        ("hash in dir", "/etc/a#b/config.yaml"),
        ("semicolon in dir", "/etc/a;b/config.yaml"),
    ] {
        gen("/usr/bin/meow", cfg).expect_err(&format!("[{label}] must be rejected"));
    }
}

// ── config save under restricted permissions (simulates ProtectSystem=strict) ──

#[test]
fn save_config_works_in_writable_subdir_of_readonly_parent() {
    // Simulates the systemd ProtectSystem=strict scenario:
    // parent directory is read-only, but config dir is writable via ReadWritePaths.
    let parent = tempfile::tempdir().unwrap();
    let config_dir = parent.path().join("meow");
    std::fs::create_dir_all(&config_dir).unwrap();

    let config_path = config_dir.join("config.yaml");
    let config_str = config_path.to_str().unwrap();

    // Write initial config
    let raw = minimal_raw_config();
    save_raw_config(config_str, &raw).unwrap();

    // Make the parent directory read-only (simulating ProtectSystem=strict)
    let parent_perms = std::fs::Permissions::from_mode(0o555);
    std::fs::set_permissions(parent.path(), parent_perms).unwrap();

    // Config directory stays writable (simulating ReadWritePaths)
    let config_perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(&config_dir, config_perms).unwrap();

    // save_raw_config should succeed — .tmp and .bak are in the config dir
    let mut updated = minimal_raw_config();
    updated.mixed_port = Some(8080);
    let result = save_raw_config(config_str, &updated);

    // Restore parent permissions so tempdir cleanup works
    let restore_perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(parent.path(), restore_perms).unwrap();

    result.expect("save_raw_config must succeed when config dir is writable");

    // Verify the updated config was written
    let content = std::fs::read_to_string(&config_path).unwrap();
    let loaded: RawConfig = serde_yaml::from_str(&content).unwrap();
    assert_eq!(loaded.mixed_port, Some(8080));
}

#[test]
fn save_config_fails_in_readonly_directory() {
    // Root bypasses filesystem permission checks, so this test is only
    // meaningful for non-root users (which matches the systemd scenario
    // where the service runs as a non-root user or with ProtectSystem=strict).
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Skipping: running as root (permission checks are bypassed)");
        return;
    }

    // Verifies that without ReadWritePaths (i.e. config dir is also read-only),
    // saving would fail — confirming the test above is meaningful.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let config_str = config_path.to_str().unwrap();

    // Write initial config while we still can
    let raw = minimal_raw_config();
    save_raw_config(config_str, &raw).unwrap();

    // Make directory read-only
    let ro_perms = std::fs::Permissions::from_mode(0o555);
    std::fs::set_permissions(dir.path(), ro_perms).unwrap();

    // Attempt to save — should fail because .tmp cannot be created
    let result = save_raw_config(config_str, &raw);

    // Restore permissions for cleanup
    let rw_perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(dir.path(), rw_perms).unwrap();

    assert!(
        result.is_err(),
        "save_raw_config should fail when directory is read-only"
    );
}

#[test]
fn save_creates_tmp_and_bak_in_same_dir_as_config() {
    // Verifies that atomic write artifacts (.tmp, .bak) are co-located with
    // the config file, so a single ReadWritePaths entry covers everything.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let config_str = config_path.to_str().unwrap();

    // First save — creates config, no .bak
    let raw = minimal_raw_config();
    save_raw_config(config_str, &raw).unwrap();
    assert!(!dir.path().join("config.yaml.bak").exists());

    // Second save — creates .bak from previous
    save_raw_config(config_str, &raw).unwrap();
    assert!(
        dir.path().join("config.yaml.bak").exists(),
        ".bak must be in the same directory as the config"
    );

    // *.tmp scratch should have been renamed away (not left behind) —
    // scratch names are unique per call (`config.yaml.<pid>.<n>.tmp`), so
    // glob the dir rather than asserting one literal name.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name())
        .filter(|n| n.to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no *.tmp scratch must be left behind after successful save, found {leftovers:?}"
    );
}
