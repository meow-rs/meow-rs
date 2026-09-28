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
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"));
    command
        .arg("-d")
        .arg(directory.path())
        .arg("-f")
        .arg(&config)
        .arg("-t")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .kill_on_drop(true);
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

async fn run_offline(
    directory: &std::path::Path,
    config: &std::path::Path,
) -> std::process::Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"));
    command
        .args(["-d"])
        .arg(directory)
        .arg("-f")
        .arg(config)
        .arg("-t")
        .kill_on_drop(true);
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
