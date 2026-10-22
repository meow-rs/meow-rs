//! The built `meow-cli` binary against the real meow-api router, the way a
//! user runs it: over TCP, with the API secret, reading what it prints.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use meow_api::log_stream::{LogLevel, LogMessage};
use meow_api::routes::{create_router, AppState};
use meow_common::{controller_file, DnsMode};
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use tokio::sync::broadcast;

const SECRET: &str = "s3cret";

const CONFIG: &str = r#"
mode: rule
log-level: info
proxy-groups:
  - name: "节点选择"
    type: select
    proxies: [DIRECT, REJECT]
  - name: Auto
    type: url-test
    proxies: [DIRECT, REJECT]
    url: https://www.gstatic.com/generate_204
    interval: 300
rules:
  - DOMAIN,example.com,节点选择
  - MATCH,DIRECT
"#;

/// The API, served on a loopback port as meow serves it.
struct Meow {
    addr: SocketAddr,
    state: Arc<AppState>,
    dir: tempfile::TempDir,
}

impl Meow {
    async fn start() -> Self {
        let raw = meow_config::parse_raw_yaml(CONFIG).unwrap();
        let resolver = Arc::new(Resolver::new(
            vec!["8.8.8.8:53".parse().unwrap()],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let meow_config::RebuildResult { proxies, rules, .. } =
            meow_config::rebuild_from_raw(&raw).unwrap();
        tunnel.update_proxies(proxies, Default::default());
        tunnel.update_rules(rules);

        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState {
            tunnel,
            secret: Some(SECRET.into()),
            config_path: Some(dir.path().join("config.yaml").display().to_string()),
            raw_config: Arc::new(RwLock::new(raw)),
            log_tx: broadcast::channel(16).0,
            proxy_providers: Arc::new(DashMap::new()),
            provider_dialer_registry: Default::default(),
            rule_providers: Arc::new(RwLock::new(HashMap::new())),
            rule_provider_refresh: Default::default(),
            proxy_provider_refresh: Default::default(),
            listeners: vec![],
            external_ui: None,
            traffic_feed: Default::default(),
            dns_server: Default::default(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = create_router(Arc::clone(&state));
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { addr, state, dir }
    }

    /// `meow-cli` aimed at this meow through the environment.
    fn cli(&self, args: &[&str]) -> Command {
        let mut command = bare_cli(args);
        command
            .env("MEOW_CONTROLLER", self.addr.to_string())
            .env("MEOW_SECRET", SECRET);
        command
    }

    async fn run(&self, args: &[&str]) -> String {
        succeeds(self.cli(args), args).await
    }

    async fn fails(&self, args: &[&str]) -> String {
        fails(self.cli(args), args).await
    }

    /// A config file meow-cli can read the controller and secret from.
    fn config_file(&self, rules: &[&str]) -> PathBuf {
        let mut text = format!(
            "external-controller: :{}\nsecret: {SECRET}\n{}",
            self.addr.port(),
            CONFIG.split("rules:").next().unwrap()
        );
        text.push_str("rules:\n");
        for rule in rules {
            text.push_str("  - ");
            text.push_str(rule);
            text.push('\n');
        }
        let path = self.dir.path().join("meow.yaml");
        std::fs::write(&path, text).unwrap();
        path
    }
}

/// `meow-cli` with none of the caller's `MEOW_*` settings, and blind to
/// any meow running on this machine.
fn bare_cli(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_meow-cli"));
    command
        .args(args)
        .env_remove("MEOW_CONTROLLER")
        .env_remove("MEOW_CONFIG")
        .env_remove("MEOW_SECRET")
        .env(
            controller_file::DIR_ENV,
            Path::new(env!("CARGO_TARGET_TMPDIR")).join("no-meow-running"),
        )
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

async fn output(mut command: Command) -> std::process::Output {
    tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("meow-cli did not finish")
        .unwrap()
}

async fn succeeds(command: Command, args: &[&str]) -> String {
    let out = output(command).await;
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        out.status.success(),
        "meow-cli {args:?} failed: {stderr}\nstdout: {stdout}"
    );
    stdout
}

async fn fails(command: Command, args: &[&str]) -> String {
    let out = output(command).await;
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "meow-cli {args:?} should fail; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    stderr
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn status_reads_the_running_config() {
    let meow = Meow::start().await;
    let text = meow.run(&["status"]).await;
    assert!(text.starts_with("meow "), "{text}");
    assert!(text.contains(&format!(" at {}", meow.addr)), "{text}");
    assert!(text.contains("mode         rule"), "{text}");
    assert!(text.contains("connections  0 open"), "{text}");

    let status = json(&meow.run(&["status", "--json"]).await);
    assert_eq!(status["configs"]["mode"], "rule");
    assert_eq!(status["connections"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_secret_says_how_to_give_it() {
    let meow = Meow::start().await;
    let mut command = bare_cli(&["status"]);
    command.env("MEOW_CONTROLLER", meow.addr.to_string());
    let stderr = fails(command, &["status"]).await;
    assert!(
        stderr.contains("meow wants the API secret (401)"),
        "{stderr}"
    );
    assert!(!stderr.contains(SECRET));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_secret_can_come_from_stdin() {
    let meow = Meow::start().await;
    let mut command = bare_cli(&["--secret-stdin", "mode"]);
    command
        .env("MEOW_CONTROLLER", meow.addr.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(format!("{SECRET}\n").as_bytes())
        .await
        .unwrap();
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "rule\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_controller_is_named() {
    // A port nothing listens on: bind one, then free it.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let mut command = bare_cli(&["status"]);
    command.env("MEOW_CONTROLLER", addr.to_string());
    let stderr = fails(command, &["status"]).await;
    assert!(
        stderr.contains(&format!("cannot reach meow's controller at {addr}")),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_selector_switches_and_shows_its_choice() {
    let meow = Meow::start().await;
    let list = meow.run(&["group", "list"]).await;
    assert!(list.contains("节点选择 -> DIRECT"), "{list}");

    let text = meow.run(&["group", "select", "节点选择", "REJECT"]).await;
    assert_eq!(text, "节点选择 -> REJECT\n");
    let show = json(&meow.run(&["--json", "group", "show", "节点选择"]).await);
    assert_eq!(show["now"], "REJECT");
    let show = meow.run(&["group", "show", "节点选择"]).await;
    assert!(show.contains("*  "), "{show}");

    let stderr = meow.fails(&["group", "select", "节点选择", "nope"]).await;
    assert!(stderr.contains("meow answered 400"), "{stderr}");
    let stderr = meow.fails(&["group", "unfix", "节点选择"]).await;
    assert!(
        stderr.contains("only url-test and fallback groups"),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_automatic_group_pins_and_unpins() {
    let meow = Meow::start().await;
    let text = meow.run(&["group", "select", "Auto", "REJECT"]).await;
    assert_eq!(text, "Auto -> REJECT (pinned)\n");
    let show = json(&meow.run(&["--json", "group", "show", "Auto"]).await);
    assert_eq!(show["fixed"], "REJECT");

    let text = meow.run(&["group", "unfix", "Auto"]).await;
    assert!(!text.contains("pinned"), "{text}");
    let show = json(&meow.run(&["--json", "group", "show", "Auto"]).await);
    assert_eq!(show["fixed"], "");
}

#[tokio::test(flavor = "multi_thread")]
async fn mode_and_log_level_switch_in_memory() {
    let meow = Meow::start().await;
    assert_eq!(meow.run(&["mode"]).await, "rule\n");
    assert_eq!(meow.run(&["mode", "global"]).await, "global\n");
    assert_eq!(meow.run(&["mode"]).await, "global\n");
    assert_eq!(
        json(&meow.run(&["--json", "mode", "direct"]).await),
        serde_json::json!({ "mode": "direct" })
    );

    assert_eq!(meow.run(&["log-level", "warning"]).await, "warning\n");
    assert_eq!(meow.run(&["log-level"]).await, "warning\n");
    // `--json` is global: it may follow the subcommand.
    let level = json(&meow.run(&["log-level", "--json"]).await);
    assert_eq!(level["log-level"], "warning");
}

#[tokio::test(flavor = "multi_thread")]
async fn rules_list_in_match_order() {
    let meow = Meow::start().await;
    let text = meow.run(&["rule", "list"]).await;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert!(lines[1].contains("example.com") && lines[1].ends_with("节点选择"));
    assert!(lines[2].starts_with("1 "), "{text}");

    let filtered = meow.run(&["rule", "list", "--filter", "EXAMPLE"]).await;
    assert_eq!(filtered.lines().count(), 2, "{filtered}");
    let rules = json(&meow.run(&["--json", "rule", "list"]).await);
    assert_eq!(rules["rules"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_config_file_names_the_controller_and_reloads() {
    let meow = Meow::start().await;
    let config = meow.config_file(&[
        "DOMAIN,example.com,节点选择",
        "DOMAIN-SUFFIX,example.org,Auto",
        "MATCH,DIRECT",
    ]);
    let config = config.to_str().unwrap();

    // `external-controller: :PORT` reaches the loopback; the secret comes
    // from the same file.
    let text = succeeds(bare_cli(&["--config", config, "mode"]), &["mode"]).await;
    assert_eq!(text, "rule\n");

    let text = succeeds(bare_cli(&["--config", config, "reload"]), &["reload"]).await;
    assert_eq!(text, format!("reloaded {config}\n"));
    let rules = meow.run(&["rule", "list", "--filter", "example.org"]).await;
    assert!(
        rules.contains("DOMAIN-SUFFIX  example.org  Auto"),
        "{rules}"
    );

    // A config that does not parse is refused and the old one stays.
    let broken = meow.dir.path().join("broken.yaml");
    std::fs::write(&broken, "rules: [unclosed\n").unwrap();
    let stderr = meow.fails(&["reload", broken.to_str().unwrap()]).await;
    assert!(stderr.contains("meow answered 400"), "{stderr}");
    let rules = json(&meow.run(&["--json", "rule", "list"]).await);
    assert_eq!(rules["rules"].as_array().unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_config_without_a_controller_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path: &Path = &dir.path().join("plain.yaml");
    std::fs::write(path, "mixed-port: 7890\n").unwrap();
    let stderr = fails(
        bare_cli(&["--config", path.to_str().unwrap(), "status"]),
        &["status"],
    )
    .await;
    assert!(stderr.contains("sets no external-controller"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_running_meow_is_found_without_options() {
    let meow = Meow::start().await;
    let config = meow.config_file(&["DOMAIN-SUFFIX,example.org,Auto", "MATCH,DIRECT"]);
    // What meow publishes once its external-controller is bound.
    let runtime = meow.dir.path().join("controllers");
    let _published =
        controller_file::publish_in(&runtime, meow.addr, Some(SECRET), Some(&config)).unwrap();
    let found = |args: &[&str]| {
        let mut command = bare_cli(args);
        command.env(controller_file::DIR_ENV, &runtime);
        command
    };

    let text = succeeds(found(&["status"]), &["status"]).await;
    assert!(text.contains(&format!(" at {}", meow.addr)), "{text}");

    // `reload` loads the config that meow loaded.
    let text = succeeds(found(&["reload"]), &["reload"]).await;
    assert_eq!(text, format!("reloaded {}\n", config.display()));
    let rules = meow.run(&["rule", "list", "--filter", "example.org"]).await;
    assert!(
        rules.contains("DOMAIN-SUFFIX  example.org  Auto"),
        "{rules}"
    );

    // An address given by hand gets the secret meow published for it.
    let mut command = found(&["mode"]);
    command.env("MEOW_CONTROLLER", meow.addr.to_string());
    assert_eq!(succeeds(command, &["mode"]).await, "rule\n");

    // With a second meow running, meow-cli names both and picks neither.
    let other = runtime.join("1.json");
    std::fs::write(&other, r#"{"pid":1,"controller":"127.0.0.1:9"}"#).unwrap();
    let lock = std::fs::File::open(&other).unwrap();
    lock.lock_shared().unwrap();
    let stderr = fails(found(&["status"]), &["status"]).await;
    assert!(
        stderr.contains("2 meows are running; choose one with --controller"),
        "{stderr}"
    );
    assert!(stderr.contains(&meow.addr.to_string()), "{stderr}");
    assert!(!stderr.contains(SECRET), "{stderr}");

    // Once that meow is gone its lock is too, and its file is swept.
    drop(lock);
    succeeds(found(&["status"]), &["status"]).await;
    assert!(!other.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_list_and_close() {
    let meow = Meow::start().await;
    assert_eq!(meow.run(&["conn", "list"]).await, "no open connections\n");
    let list = json(&meow.run(&["--json", "connections", "list"]).await);
    assert_eq!(list, serde_json::json!([]));
    assert_eq!(
        meow.run(&["conn", "close", "--all"]).await,
        "closed every connection\n"
    );
    let stderr = meow.fails(&["conn", "show", "1a2b"]).await;
    assert!(stderr.contains("1a2b"), "{stderr}");
    // meow answers 204 to closing any well-formed id: meow-cli checks first.
    let gone = "0f8e2b1c-5d4a-4c3b-9a2e-7f6d5c4b3a21";
    let stderr = meow.fails(&["conn", "close", gone]).await;
    assert!(stderr.contains(gone), "{stderr}");
    let stderr = meow.fails(&["conn", "close", ""]).await;
    assert!(stderr.contains("connection id"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_cache_and_logbook_read_when_empty() {
    let meow = Meow::start().await;
    assert_eq!(meow.run(&["dns", "cache"]).await, "no cached answers\n");
    let logbook = meow.run(&["logbook"]).await;
    assert!(
        logbook == "no entries\n" || logbook.starts_with("the logbook is off"),
        "{logbook}"
    );
    assert_eq!(meow.run(&["provider", "list"]).await, "no providers\n");
    assert_eq!(
        meow.run(&["subscription", "list"]).await,
        "no subscriptions\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_stop_after_count() {
    let meow = Meow::start().await;
    let text = meow.run(&["traffic", "--count", "2", "--json"]).await;
    let samples: Vec<serde_json::Value> = text.lines().map(json).collect();
    assert_eq!(samples.len(), 2, "{text}");
    assert!(samples[0].get("up").is_some(), "{text}");

    // The log stream: feed lines until meow-cli has read the one it waits
    // for. Debug lines sit below `--level info` and never show.
    let log_tx = meow.state.log_tx.clone();
    let feeder = tokio::spawn(async move {
        loop {
            for (level, payload) in [(LogLevel::Debug, "hidden"), (LogLevel::Warning, "shown")] {
                let _ = log_tx.send(LogMessage {
                    level,
                    payload: payload.into(),
                    time: time::OffsetDateTime::now_utc(),
                });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let text = meow.run(&["log", "--count", "1"]).await;
    feeder.abort();
    assert_eq!(text, "warning  shown\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_skill_prints_itself() {
    let text = succeeds(bare_cli(&["skill"]), &["skill"]).await;
    assert_eq!(text, include_str!("../skills/meow-cli/SKILL.md"));
    // `lines()`: a Windows checkout may turn the file's newlines into CRLF.
    let head: Vec<&str> = text.lines().take(2).collect();
    assert_eq!(head, ["---", "name: meow-cli"]);
}
