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
    let mut command = offline_command();
    command.arg("--no-external-plugins").arg("-f").arg(&config);
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .expect("offline validation must finish without network access")
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

/// Regression for issue #716: `-t` used to run real DNS bootstrap for
/// hostname-bearing upstreams (`udp://name`, DoH/DoT, `nameserver-policy`,
/// `proxy-server-nameserver`) — network I/O during "offline" validation,
/// and on an isolated host a structurally valid config failed with
/// `CannotResolve`. Point `default-nameserver` at a bound UDP socket that
/// never answers: pre-fix the bootstrap query hits it (and `-t` fails);
/// post-fix the socket must receive nothing and `-t` must pass.
#[tokio::test]
async fn config_test_does_not_run_dns_bootstrap() {
    let sentinel = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sentinel.set_nonblocking(true).unwrap();
    let sentinel_addr = sentinel.local_addr().unwrap();

    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("dns-bootstrap.yaml");
    std::fs::write(
        &config,
        format!(
            "dns:\n  enable: true\n  default-nameserver: ['{sentinel_addr}']\n  nameserver: ['udp://bootstrap-must-not-run.invalid:53']\n  proxy-server-nameserver: ['udp://psn-must-not-run.invalid:53']\n  nameserver-policy: {{'+.internal.example': 'udp://policy-must-not-run.invalid:53'}}\nrules: ['MATCH,DIRECT']\n"
        ),
    )
    .unwrap();

    let output = run_offline(directory.path(), &config).await;
    assert!(
        output.status.success(),
        "offline -t must pass for hostname-bearing dns upstreams: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Any pre-fix bootstrap datagram is already queued (loopback delivery
    // is synchronous) — a nonblocking recv decides immediately.
    let err = sentinel
        .recv_from(&mut [0u8; 2048])
        .expect_err("offline validation sent a real DNS bootstrap query");
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock, "{err}");

    // Verdict parity: a hostname policy entry with NO IP-literal
    // bootstrap source (default-nameserver absent, nameserver hostname-
    // only) is statically unservable — runtime warn-skips it into a "no
    // valid nameservers" error, and `-t` must reproduce that verdict
    // rather than green-light a config that cannot start.
    let bad = directory.path().join("dns-no-bootstrap-src.yaml");
    std::fs::write(
        &bad,
        "dns:\n  enable: true\n  nameserver: ['udp://bootstrap-must-not-run.invalid:53']\n  nameserver-policy: {'+.internal.example': 'udp://policy-must-not-run.invalid:53'}\nrules: ['MATCH,DIRECT']\n",
    )
    .unwrap();
    let output = run_offline(directory.path(), &bad).await;
    assert!(
        !output.status.success(),
        "-t must reject a nameserver-policy that has no bootstrap source: {output:?}"
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        logs.contains("no valid nameservers"),
        "failure must come from the unbootstrappable policy, not an earlier error: {logs}"
    );
}

/// Regression for issue #717: `meow install --config-string …` used to
/// silently install a service unit pointing at the default `-f` path —
/// resurrecting whatever `config.yaml` happened to sit in the launch
/// directory. The combination must now fail fast and tell the user to
/// write a real file.
#[tokio::test]
async fn install_rejects_config_string() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD
        .encode("mixed-port: 0\nrules: ['MATCH,DIRECT']\n");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"));
    command
        .arg("--config-string")
        .arg(b64)
        .arg("install")
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
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .expect("install rejection must not block")
        .unwrap();
    assert!(
        !output.status.success(),
        "install --config-string must fail instead of baking a phantom -f path: {output:?}"
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        logs.contains("--config-string") && logs.contains("-f"),
        "the error must name the flag and point at -f: {logs}"
    );
}

/// Issue #717 end-to-end: a daemon started from `--config-string` has no
/// backing file — `POST /api/config/save` must refuse (400) and the launch
/// directory must NOT gain a phantom `config.yaml`.
#[tokio::test]
async fn config_string_run_never_writes_phantom_config() {
    use base64::Engine;

    // Reserve a loopback port for the API.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let api_port = probe.local_addr().unwrap().port();
    drop(probe);

    let workdir = tempfile::tempdir().unwrap();
    let yaml = format!(
        "mixed-port: 0\nexternal-controller: '127.0.0.1:{api_port}'\nrules: ['MATCH,DIRECT']\n"
    );
    let b64 = base64::engine::general_purpose::STANDARD.encode(yaml);

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"));
    child
        .arg("--config-string")
        .arg(b64)
        .current_dir(workdir.path())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        child.env_remove(variable);
    }
    let mut child = child.spawn().expect("spawn meow");

    // Wait for the API to accept connections (bounded).
    let ready = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", api_port))
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    if ready.is_err() {
        let _ = child.kill().await;
        panic!("api server did not come up within 15s");
    }

    let response = tokio::time::timeout(std::time::Duration::from_secs(10), reqwest_save(api_port))
        .await
        .expect("save request must not hang")
        .expect("save request failed");
    assert_eq!(
        response, 400,
        "save on a --config-string daemon must be refused, got {response}"
    );

    child.kill().await.unwrap();
    assert!(
        !workdir.path().join("config.yaml").exists(),
        "a --config-string run must not create ./config.yaml"
    );
}

/// Minimal HTTP POST for the e2e above — keeps the test file free of an
/// HTTP-client dependency; returns the status code.
async fn reqwest_save(port: u16) -> std::io::Result<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    stream
        .write_all(b"POST /api/config/save HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Ok(status)
}
