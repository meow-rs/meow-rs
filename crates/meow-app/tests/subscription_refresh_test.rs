//! Integration test for [`meow_app::subscription_refresh::run_loop`].
//!
//! Issue #543: the scheduled refresh rebuilt the candidate with
//! `rebuild_from_raw_with_resolver`, which wires no `SelectorStore`. A
//! fetched `select` group lost the user's persisted choice on every
//! refresh (and a `use:`/`include-all` group resolved against an empty
//! provider map before the shared registry was threaded). The loop must
//! rebuild via `rebuild_from_raw_runtime` — matching `PUT /configs`.

use dashmap::DashMap;
use meow_common::DnsMode;
use meow_config::proxy_provider::{load_proxy_providers, ProxyProvider};
use meow_config::raw::RawConfig;
use meow_config::rule_provider_refresh::RefreshSupervisor;
use meow_dns::Resolver;
use meow_proxy::SelectorStore;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serve one subscription payload over plain HTTP/1.1 (close per request).
async fn spawn_origin(body: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Consume the request head before responding — a short
                // single read could leave tail bytes that turn the close
                // into an RST, clobbering the buffered response.
                let mut buf = [0u8; 4096];
                let mut head = Vec::new();
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            head.extend_from_slice(&buf[..n]);
                            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn resolver() -> Arc<Resolver> {
    Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ))
}

struct Fixture {
    // Held so the tempdir (config + provider payload) outlives the test.
    dir: tempfile::TempDir,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    config_path: String,
    proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
    provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
}

/// Shared scaffolding: a two-node file provider `prov` and an origin
/// serving `sub_body` as subscription `s`. The loop is NOT spawned here —
/// each test finishes arranging global state (e.g. the SelectorStore)
/// before calling [`spawn_loop`] so the first pass can't race it.
async fn fixture(sub_body: &'static str) -> Fixture {
    let sub_addr = spawn_origin(sub_body).await;
    fixture_at(sub_addr).await
}

/// Same scaffolding as [`fixture`] but against a caller-provided origin —
/// lets a test gate the response itself.
async fn fixture_at(sub_addr: std::net::SocketAddr) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    // The provider cache dir is derived from `config_path`'s parent (no
    // home-dir override in tests), so the provider payload lives beside
    // the config file.
    let provider_path = dir.path().join("provider_prov.yaml");
    let mut provider_file = std::fs::File::create(&provider_path).unwrap();
    // `type: http` keeps its configured name — a `direct` node's `name()`
    // is hardcoded "DIRECT" and would mask the membership assertion.
    write!(
        provider_file,
        "proxies:\n\
         \x20 - name: node-a\n\
         \x20   type: http\n\
         \x20   server: 127.0.0.1\n\
         \x20   port: 9\n\
         \x20 - name: node-b\n\
         \x20   type: http\n\
         \x20   server: 127.0.0.1\n\
         \x20   port: 9\n"
    )
    .unwrap();

    let raw: RawConfig = serde_yaml::from_str(&format!(
        "mode: rule\n\
         proxy-providers:\n\
         \x20 prov:\n\
         \x20   type: file\n\
         \x20   path: provider_prov.yaml\n\
         subscriptions:\n\
         \x20 - name: s\n\
         \x20   url: http://{sub_addr}/sub\n\
         \x20   interval: 3600\n\
         rules:\n\
         \x20 - MATCH,DIRECT\n"
    ))
    .unwrap();

    // The shared provider-dialer registry, populated the same way
    // startup does (`Config::provider_dialer_registry`, not the per-build
    // generation cell `RebuildResult::dialer_registry`).
    // `ipv6` must match what the rebuild computes (`effective_ipv6` of the
    // fixture YAML = false): a mismatch makes `matches_def` reject the
    // live provider, and the commit would wire a fresh empty slot that a
    // detached refresh fills asynchronously — a race, not a test.
    let provider_dialer_registry = meow_proxy::dialer::ProxyRegistry::default();
    let proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>> = Arc::new(
        load_proxy_providers(
            raw.proxy_providers.as_ref().unwrap(),
            Some(dir.path()),
            false,
            false,
            &provider_dialer_registry,
        )
        .await
        .unwrap()
        .into_iter()
        .collect(),
    );
    assert_eq!(
        proxy_providers.get("prov").unwrap().proxies().len(),
        2,
        "file provider must load its nodes before the test"
    );

    // Diverge the on-disk payload AFTER the live provider loaded it: a
    // commit that reuses the shared provider keeps [node-a, node-b],
    // while one that rebuilds the provider from scratch re-reads the
    // file and sees only [node-a]. That makes the members assertion
    // below discriminate provider-map sharing deterministically instead
    // of racing a detached refresh fill.
    let mut provider_file = std::fs::File::create(&provider_path).unwrap();
    write!(
        provider_file,
        "proxies:\n\
         \x20 - name: node-a\n\
         \x20   type: http\n\
         \x20   server: 127.0.0.1\n\
         \x20   port: 9\n"
    )
    .unwrap();

    let config_path = dir.path().join("config.yaml");
    std::fs::write(&config_path, "").unwrap();

    Fixture {
        tunnel: Tunnel::new(resolver()),
        raw_config: Arc::new(RwLock::new(raw)),
        config_path: config_path.to_string_lossy().into_owned(),
        proxy_providers,
        provider_dialer_registry,
        dir,
    }
}

fn spawn_loop(fx: &Fixture) {
    tokio::spawn(meow_app::subscription_refresh::run_loop(
        Arc::clone(&fx.raw_config),
        fx.tunnel.clone(),
        fx.config_path.clone(),
        Arc::new(RwLock::new(None)),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::clone(&fx.proxy_providers),
        fx.provider_dialer_registry.clone(),
        Arc::new(RefreshSupervisor::default()),
        Arc::new(meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor::default()),
    ));
}

/// Poll the tunnel until group `name` is committed by the refresh loop.
async fn wait_group(tunnel: &Tunnel, name: &str) -> Arc<dyn meow_common::Proxy> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(group) = tunnel.proxy(name) {
                break group;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("group '{name}' must be committed by the refresh"))
}

/// A refreshed subscription whose group draws members from a *local*
/// `proxy-providers:` entry must keep them — the refresh commit rebuilds
/// against the live provider registry, not an empty map.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refreshed_use_group_keeps_provider_members() {
    let fx = fixture(
        "proxies: []\n\
         proxy-groups:\n\
         \x20 - name: g\n\
         \x20   type: select\n\
         \x20   use: [prov]\n\
         rules:\n\
         \x20 - MATCH,g\n",
    )
    .await;
    spawn_loop(&fx);

    let group = wait_group(&fx.tunnel, "g").await;
    let members = group.members().unwrap_or_default();
    assert_eq!(members, vec!["node-a".to_string(), "node-b".to_string()]);
}

/// The user's persisted `select` choice must survive a refresh commit.
/// `rebuild_from_raw_runtime` wires `SelectorStore::global()` into the
/// rebuilt groups; the plain resolver variant builds them with no store,
/// resetting `selected` to the first member on every refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refreshed_select_group_keeps_persisted_choice() {
    let fx = fixture(
        "proxies: []\n\
         proxy-groups:\n\
         \x20 - name: sel-g\n\
         \x20   type: select\n\
         \x20   use: [prov]\n\
         rules:\n\
         \x20 - MATCH,sel-g\n",
    )
    .await;

    // Persist `sel-g → node-b` BEFORE the loop spawns — `with_store`
    // reads the store once at group construction, so the choice must be
    // in place before the first refresh commits.
    // NOTE: `SelectorStore::open` binds the process-global on first call
    // and later `open`s never rebind it — under plain `cargo test` this
    // store leaks into sibling tests' `rebuild_from_raw_runtime` groups
    // (harmless today: priming is keyed by group name). Nextest gives
    // each test its own process, so CI is immune; keep it that way by
    // not asserting `global()` identity in other tests of this file.
    let store = SelectorStore::open(fx.dir.path().join("sel.json"));
    store.set("sel-g", "node-b");
    spawn_loop(&fx);

    let group = wait_group(&fx.tunnel, "sel-g").await;
    let metadata = meow_common::Metadata::default();
    let picked = group
        .unwrap_proxy(&metadata, false)
        .expect("select group must resolve a member");
    assert_eq!(
        picked.name(),
        "node-b",
        "refresh must restore the persisted choice, not the first member"
    );
}

/// Origin that holds its response until the test releases it: `got_rx`
/// fires once the request head arrives (the fetch is in flight), `go_tx`
/// releases the response body. One request only — the test deletes the
/// subscription so no second pass fetches.
async fn spawn_gated_origin(
    body: &'static str,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (got_tx, got_rx) = tokio::sync::oneshot::channel();
    let (go_tx, go_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 4096];
        let mut head = Vec::new();
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    head.extend_from_slice(&buf[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        let _ = got_tx.send(());
        let _ = go_rx.await;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = sock.write_all(resp.as_bytes()).await;
        let _ = sock.shutdown().await;
    });
    (addr, got_rx, go_tx)
}

/// A `DELETE` landing while the refresh fetch is in flight must discard
/// the fetched payload: the loop re-verifies the subscription inside the
/// `CONFIG_MUTATION` lane before committing, mirroring the manual
/// endpoint's 404 recheck (issue #543 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_during_in_flight_refresh_discards_payload() {
    let (sub_addr, got_rx, go_tx) = spawn_gated_origin(
        "proxies:\n\
         \x20 - name: resurrected\n\
         \x20   type: http\n\
         \x20   server: 127.0.0.1\n\
         \x20   port: 9\n\
         rules:\n\
         \x20 - MATCH,DIRECT\n",
    )
    .await;
    let fx = fixture_at(sub_addr).await;
    spawn_loop(&fx);

    // The fetch is in flight; park the loop on the mutation lane while
    // the "DELETE" commits. This mirrors the endpoint's raw-config effect
    // (entry removed + owned sections emptied); the endpoint's rebuild
    // and save are irrelevant to the recheck under test.
    tokio::time::timeout(std::time::Duration::from_secs(10), got_rx)
        .await
        .expect("origin must see the request within 10s")
        .expect("origin must see the request");
    let lane = meow_api::routes::CONFIG_MUTATION.lock().await;
    go_tx.send(()).expect("origin must still be listening");
    // Let the loop consume the response and queue on the lane — it
    // cannot run its commit section while we hold it, so the delete
    // below is guaranteed to precede the candidate build.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    {
        let mut live = fx.raw_config.write();
        if let Some(subs) = live.subscriptions.as_mut() {
            subs.retain(|s| s.name != "s");
        }
        live.proxies = None;
        live.proxy_groups = None;
        live.rules = None;
    }
    drop(lane);

    // tokio's Mutex is FIFO-fair: this re-acquisition queues behind the
    // parked loop and resolves only after its in-lane section (recheck →
    // discard, or a buggy commit) has run to completion.
    let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
    assert!(
        fx.tunnel.proxy("resurrected").is_none(),
        "a deleted subscription's fetched payload must not be committed"
    );
    assert!(
        fx.raw_config
            .read()
            .proxies
            .as_deref()
            .unwrap_or_default()
            .iter()
            .all(|p| p.get("name").and_then(|n| n.as_str()) != Some("resurrected")),
        "raw_config must not regain the deleted subscription's nodes"
    );
}

/// Issue #562: a subscription payload whose `proxy-groups:` declares a
/// cycle hits the declaration-level check inside the refresh rebuild —
/// the error arm stamps `last_updated` and keeps the previous routing,
/// so the cyclic groups never enter the route table.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refreshed_subscription_with_group_cycle_is_not_committed() {
    let fx = fixture(
        "proxies: []\n\
         proxy-groups:\n\
         \x20 - name: A\n\
         \x20   type: select\n\
         \x20   proxies: [B]\n\
         \x20 - name: B\n\
         \x20   type: select\n\
         \x20   proxies: [A]\n\
         rules:\n\
         \x20 - MATCH,DIRECT\n",
    )
    .await;
    spawn_loop(&fx);

    // `last_updated` lands before the live raw is touched on every
    // outcome — commit writes it via the candidate swap (after
    // `update_routing`), rejection stamps it in place. Seeing the stamp
    // therefore means the iteration's outcome is already decided.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if fx
                .raw_config
                .read()
                .subscriptions
                .as_ref()
                .is_some_and(|subs| subs.iter().all(|s| s.last_updated.is_some()))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the refresh loop must attempt the cyclic subscription");

    assert!(
        fx.tunnel.proxy("A").is_none() && fx.tunnel.proxy("B").is_none(),
        "a cyclic group set must not be committed"
    );
    assert!(
        fx.raw_config
            .read()
            .proxy_groups
            .as_deref()
            .unwrap_or_default()
            .iter()
            .all(|g| g.name != "A" && g.name != "B"),
        "the rejected candidate must not replace the live raw config"
    );
}

/// `Proxy` that records each `dial_tcp` target and dials the real
/// destination — proves the refresh fetch transits the resolved `proxy:`
/// hop instead of going direct (issue #625).
struct RecordingFront {
    seen: std::sync::Mutex<Vec<(String, u16)>>,
    health: meow_common::ProxyHealth,
}

#[async_trait::async_trait]
impl meow_common::ProxyAdapter for RecordingFront {
    fn name(&self) -> &str {
        "front"
    }
    fn adapter_type(&self) -> meow_common::AdapterType {
        meow_common::AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(
        &self,
        m: &meow_common::Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
        self.seen
            .lock()
            .unwrap()
            .push((m.host.to_string(), m.dst_port));
        let stream = tokio::net::TcpStream::connect((m.host.as_str(), m.dst_port))
            .await
            .map_err(meow_common::MeowError::Io)?;
        Ok(Box::new(stream))
    }
    async fn dial_udp(
        &self,
        _m: &meow_common::Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
        unimplemented!("no udp")
    }
    fn health(&self) -> &meow_common::ProxyHealth {
        &self.health
    }
}

impl meow_common::Proxy for RecordingFront {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
        Vec::new()
    }
}

/// The refresh loop must route `proxy:`-bearing subscription fetches
/// through the name resolved out of the live provider-dialer registry —
/// a regression dropping the field (always-direct fetch) leaves `seen`
/// empty and would leak egress past the declared chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_fetches_through_subscription_proxy() {
    let fx = fixture("proxies:\n  - {name: n1, type: http, server: 127.0.0.1, port: 9}\n").await;
    let ghost_url = fx.raw_config.read().subscriptions.as_ref().unwrap()[0]
        .url
        .clone();
    {
        let mut raw = fx.raw_config.write();
        let subs = raw.subscriptions.as_mut().unwrap();
        subs[0].proxy = Some("front".to_string());
        // Same origin URL: a regression that fetched `ghost` directly
        // would succeed and stamp `last_updated` — fail-closed requires
        // it never reach the network at all. Inserted FIRST so the pass
        // rejects it synchronously before `s`'s fetch resolves — by the
        // time `n1` commits below, `ghost-sub` has definitively been
        // processed.
        subs.insert(
            0,
            meow_config::raw::RawSubscription {
                name: "ghost-sub".to_string(),
                url: ghost_url,
                interval: Some(3600),
                last_updated: None,
                proxy: Some("ghost".to_string()),
            },
        );
    }
    let front = Arc::new(RecordingFront {
        seen: std::sync::Mutex::new(Vec::new()),
        health: meow_common::ProxyHealth::new(),
    });
    fx.provider_dialer_registry
        .publish(Arc::new(HashMap::from([(
            smol_str::SmolStr::from("front"),
            Arc::clone(&front) as Arc<dyn meow_common::Proxy>,
        )])));
    spawn_loop(&fx);

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if !front.seen.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the refresh must dial the subscription origin through `front`");

    // The fetched payload commits — `n1` lands as a top-level leaf.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if fx.tunnel.proxy("n1").is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the subscription payload must be committed");

    // The unresolvable sibling stayed fail-closed: `last_updated` is
    // stamped only on a successful fetch, so `None` here proves the
    // ghost name never reached the network (issue #625 review).
    let raw = fx.raw_config.read();
    let ghost = raw
        .subscriptions
        .as_ref()
        .unwrap()
        .iter()
        .find(|s| s.name == "ghost-sub")
        .unwrap();
    assert!(
        ghost.last_updated.is_none(),
        "an unresolvable subscription proxy must not fetch"
    );
}
