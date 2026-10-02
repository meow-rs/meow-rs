//! Config validation invoked by LuCI must not fetch remote subscriptions.

#[tokio::test]
async fn config_test_does_not_contact_remote_providers() {
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    server.set_nonblocking(true).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "proxy-providers:\n  remote:\n    type: http\n    url: http://{}/subscription\n    path: ./remote.yaml\n    interval: 3600\nproxy-groups:\n  - name: PROXY\n    type: select\n    use: [remote]\nrule-providers:\n  remote-rules:\n    type: http\n    behavior: domain\n    url: http://{}/rules\n    path: ./rules.yaml\n    interval: 0\nrules: ['RULE-SET,remote-rules,PROXY', 'MATCH,PROXY']\n",
            server.local_addr().unwrap(),
            server.local_addr().unwrap()
        ),
    )
    .unwrap();
    let mut command = offline_command();
    command
        .arg("-d")
        .arg(directory.path())
        .arg("-f")
        .arg(&config);
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .expect("offline validation must not wait for a subscription response")
        .unwrap();
    assert!(
        output.status.success(),
        "config test failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        server.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "config validation must not contact the provider"
    );
}

#[tokio::test]
async fn config_test_validates_cached_rules_without_refreshing() {
    for (payload, valid) in [("payload: [example.test]\n", true), ("payload: [", false)] {
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("rules.yaml"), payload).unwrap();
        let config = directory.path().join("config.yaml");
        std::fs::write(&config, format!(
            "strict: true\nrule-providers:\n  cached:\n    type: http\n    behavior: domain\n    format: yaml\n    url: http://{}/rules\n    path: ./rules.yaml\n    interval: 0\nrules: ['RULE-SET,cached,DIRECT']\n",
            server.local_addr().unwrap()
        )).unwrap();
        let output = run_offline(directory.path(), &config).await;
        assert_eq!(output.status.success(), valid, "{output:?}");
        assert_eq!(
            server.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn config_test_does_not_download_missing_geodata() {
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    server.set_nonblocking(true).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.yaml");
    std::fs::write(&config, format!(
        "geodata:\n  mmdb-path: '{}'\n  url:\n    mmdb: http://{}/country.mmdb\nrules: ['GEOIP,US,DIRECT']\n",
        directory.path().join("missing.mmdb").display(), server.local_addr().unwrap()
    )).unwrap();
    let output = run_offline(directory.path(), &config).await;
    assert!(
        output.status.success(),
        "first-start configs must validate before geodata is downloaded: {output:?}"
    );
    assert_eq!(
        server.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

/// A `meow -t` command hardened the way this suite requires: kills the
/// child on drop, strips inherited proxy env vars, and is meant to run
/// under a timeout — offline validation must never hang on network I/O.
fn offline_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"));
    command.arg("-t").kill_on_drop(true);
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(variable);
    }
    command
}

async fn run_offline(
    directory: &std::path::Path,
    config: &std::path::Path,
) -> std::process::Output {
    let mut command = offline_command();
    command.args(["-d"]).arg(directory).arg("-f").arg(config);
    tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .expect("offline validation must finish without network access")
        .unwrap()
}

#[tokio::test]
async fn config_test_never_starts_external_plugins() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("plugin.yaml");
    // This executable deliberately does not exist. Adapter construction must
    // validate the proxy without even attempting to spawn it during -t.
    std::fs::write(&config, format!(
        "strict: true\nproxies:\n  - name: plugin\n    type: ss\n    server: 127.0.0.1\n    port: 1234\n    cipher: aes-128-gcm\n    password: test\n    plugin: '{}'\nrules: ['MATCH,plugin']\n",
        directory.path().join("never-execute").display()
    )).unwrap();
    let output = run_offline(directory.path(), &config).await;
    assert!(output.status.success(), "{output:?}");
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"))
        .args(["--no-external-plugins", "-t", "-f"])
        .arg(&config)
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("external plugins are disabled")
            || String::from_utf8_lossy(&output.stderr).contains("external plugins are disabled")
    );
}

#[tokio::test]
async fn config_test_defers_dns_sourced_ech() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("ech.yaml");
    std::fs::write(&config,
        "proxies:\n  - name: tls\n    type: trojan\n    server: 127.0.0.1\n    port: 443\n    password: test\n    ech-opts: {enable: true, query-server-name: offline-validation.invalid}\nrules: ['MATCH,tls']\n"
    ).unwrap();
    let output = run_offline(directory.path(), &config).await;
    assert!(output.status.success(), "{output:?}");
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !logs.contains("ech-dns:"),
        "ECH lookup must not run: {logs}"
    );
}

/// Regression for issue #711: `-t` used to validate `-f` even when
/// `--config-string` was given. Both directions are discriminating:
/// a broken string must fail `-t` even with a valid file present, and a
/// valid string must pass `-t` even when the file does not exist.
#[tokio::test]
async fn config_test_uses_config_string_over_file() {
    use base64::Engine;
    let b64 = |yaml: &str| base64::engine::general_purpose::STANDARD.encode(yaml);

    // (a) broken --config-string + valid -f file → must FAIL (previously
    // the file's validity leaked into the result).
    let directory = tempfile::tempdir().unwrap();
    let good_file = directory.path().join("good.yaml");
    std::fs::write(&good_file, "mixed-port: 0\nrules: ['MATCH,DIRECT']\n").unwrap();
    let mut command = offline_command();
    command
        .arg("-f")
        .arg(&good_file)
        .arg("--config-string")
        .arg(b64("rules: [this is not a valid rule: [}}"));
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .expect("offline validation must finish without network access")
        .unwrap();
    assert!(
        !output.status.success(),
        "broken --config-string must fail -t even with a valid -f file: {output:?}"
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        logs.contains("--config-string"),
        "error must blame the string source: {logs}"
    );

    // (b) valid --config-string + nonexistent -f → must PASS.
    let missing = directory.path().join("does-not-exist.yaml");
    let mut command = offline_command();
    command
        .arg("-f")
        .arg(&missing)
        .arg("--config-string")
        .arg(b64("mixed-port: 0\nrules: ['MATCH,DIRECT']\n"));
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .expect("offline validation must finish without network access")
        .unwrap();
    assert!(
        output.status.success(),
        "valid --config-string must pass -t despite missing -f file: {output:?}"
    );

    // (c) BOM parity: a front-end that base64-encodes a BOM'd file must
    // get the same result as -f on that file (load_raw_config strips it).
    let mut command = offline_command();
    command
        .arg("--config-string")
        .arg(b64("\u{feff}mixed-port: 0\nrules: ['MATCH,DIRECT']\n"));
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .expect("offline validation must finish without network access")
        .unwrap();
    assert!(
        output.status.success(),
        "BOM'd --config-string must parse like a BOM'd file: {output:?}"
    );
}
