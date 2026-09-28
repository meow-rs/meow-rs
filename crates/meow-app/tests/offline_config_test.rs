//! Config validation invoked by LuCI must not fetch remote subscriptions.

#[tokio::test]
async fn config_test_does_not_contact_remote_proxy_provider() {
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    server.set_nonblocking(true).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "proxy-providers:\n  remote:\n    type: http\n    url: http://{}/subscription\n    path: ./remote.yaml\n    interval: 3600\nproxy-groups:\n  - name: PROXY\n    type: select\n    use: [remote]\nrules: ['MATCH,PROXY']\n",
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
