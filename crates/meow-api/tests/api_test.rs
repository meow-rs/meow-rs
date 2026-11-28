use axum::http::{Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use meow_api::routes::{create_router, AppState};
use meow_common::{DnsMode, Proxy};
use meow_config::raw::{RawConfig, RawProxyGroup, RawSubscription};
use meow_dns::{HostEntry, Resolver};
use meow_trie::DomainTrie;
use meow_tunnel::{ResolvedTarget, Tunnel};
use parking_lot::RwLock;
use smallvec::smallvec;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower::ServiceExt;

/// Serialization for every test that commits `/configs`: a commit
/// re-asserts the process-wide knobs (interface name, UA, tcp-concurrent,
/// find-process-mode, outbound keepalive), so a sibling commit between a
/// test's request and its observation is the only way the globals go
/// stale. Holding this lane for a test's whole body keeps the committed
/// posture stable to observe — no retry windows.
static PROCESS_GLOBALS_LANE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn process_globals_lane() -> tokio::sync::MutexGuard<'static, ()> {
    PROCESS_GLOBALS_LANE.lock().await
}

fn test_log_tx() -> broadcast::Sender<meow_api::log_stream::LogMessage> {
    broadcast::channel(16).0
}

fn test_raw_config() -> RawConfig {
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

fn test_state(raw: RawConfig) -> Arc<AppState> {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    // Leak the tempdir so it persists for the test — fine for tests
    std::mem::forget(dir);
    test_state_with_backing(raw, Some(config_path))
}

/// State as if the daemon had been started via `--config-string`: there is
/// no backing config file, so persist endpoints must refuse or explicitly
/// skip the write rather than create a phantom `./config.yaml` (issue #717).
fn test_state_ephemeral(raw: RawConfig) -> Arc<AppState> {
    test_state_with_backing(raw, None)
}

fn test_state_with_backing(raw: RawConfig, config_path: Option<String>) -> Arc<AppState> {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);

    // Build proxies/rules from raw and apply
    let meow_config::RebuildResult {
        proxies,
        rules,
        sub_rules,
        ..
    } = meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies, Default::default());
    tunnel.update_rules_with_sub_rules(rules, sub_rules);

    Arc::new(AppState {
        tunnel,
        secret: None,
        config_path,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        proxy_providers: Arc::new(DashMap::new()),
        provider_dialer_registry: Default::default(),
        ntp_reconcile: None,
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        rule_provider_refresh: Default::default(),
        proxy_provider_refresh: Default::default(),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
        dns_server: Default::default(),
        ui_storage: Default::default(),
        listener_gate: None,
        cors: Default::default(),
    })
}

fn test_state_with_route(raw: RawConfig, named: Vec<(&str, Arc<dyn Proxy>)>) -> Arc<AppState> {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);

    let mut proxies = std::collections::HashMap::new();
    for (name, proxy) in named {
        proxies.insert(smol_str::SmolStr::from(name), proxy);
    }
    tunnel.update_proxies(proxies, Default::default());

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    std::mem::forget(dir);

    Arc::new(AppState {
        tunnel,
        secret: None,
        config_path: Some(config_path),
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        proxy_providers: Arc::new(DashMap::new()),
        provider_dialer_registry: Default::default(),
        ntp_reconcile: None,
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        rule_provider_refresh: Default::default(),
        proxy_provider_refresh: Default::default(),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
        dns_server: Default::default(),
        ui_storage: Default::default(),
        listener_gate: None,
        cors: Default::default(),
    })
}

fn test_state_default() -> Arc<AppState> {
    test_state(test_raw_config())
}

fn test_state_with_secret(secret: &str) -> Arc<AppState> {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let raw = test_raw_config();
    let meow_config::RebuildResult {
        proxies,
        rules,
        sub_rules,
        ..
    } = meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies, Default::default());
    tunnel.update_rules_with_sub_rules(rules, sub_rules);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    std::mem::forget(dir);

    Arc::new(AppState {
        tunnel,
        secret: Some(secret.to_string()),
        config_path: Some(config_path),
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        proxy_providers: Arc::new(DashMap::new()),
        provider_dialer_registry: Default::default(),
        ntp_reconcile: None,
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        rule_provider_refresh: Default::default(),
        proxy_provider_refresh: Default::default(),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
        dns_server: Default::default(),
        ui_storage: Default::default(),
        listener_gate: None,
        cors: Default::default(),
    })
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ── UI tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn ui_serves_html() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/ui").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("<!DOCTYPE html>"));
    assert!(body.contains("meow-rs"));
}

/// Issue #563: `GET /listeners` discloses the tproxy firewall mode so a
/// deployer can tell whether redirect rules are meow-managed or their own.
#[tokio::test]
async fn listeners_endpoint_discloses_tproxy_firewall_mode() {
    use meow_config::{ListenerSpec, NamedListener};

    let mut state = test_state_default();
    Arc::get_mut(&mut state).unwrap().listeners = vec![
        NamedListener {
            name: "ext-tproxy".into(),
            spec: ListenerSpec::TProxy {
                sni: false,
                firewall: false,
                udp: true,
                udp_timeout: 30,
                transparent: false,
            },
            port: 7894,
            listen: "127.0.0.1".into(),
            max_connections: 256,
            route_override: None,
            routing_mark: None,
        },
        NamedListener {
            name: "mixed".into(),
            spec: ListenerSpec::Mixed,
            port: 7890,
            listen: "127.0.0.1".into(),
            max_connections: 256,
            route_override: None,
            routing_mark: None,
        },
    ];

    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/listeners")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body[0]["name"], "ext-tproxy");
    assert_eq!(body[0]["firewall"], false);
    // `udp`/`udp-timeout` disclose whether the external-TPROXY UDP path is
    // actually enabled — the deployer's rules are useless without it (#564).
    assert_eq!(body[0]["udp"], true);
    assert_eq!(body[0]["udp-timeout"], 30);
    // Non-tproxy listeners carry none of the tproxy keys at all.
    assert_eq!(body[1]["name"], "mixed");
    assert!(body[1].get("firewall").is_none());
    assert!(body[1].get("udp").is_none());
    assert!(body[1].get("udp-timeout").is_none());
}

fn vless_reality_document() -> &'static str {
    concat!(
        "mode: rule\n",
        "listeners:\n",
        "  - name: vision-in\n",
        "    type: vless\n",
        "    listen: 127.0.0.1\n",
        "    port: 0\n",
        "    reality-config:\n",
        "      dest: \"www.example.com:443\"\n",
        "      private-key: \"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo\"\n",
        "      short-id: [\"0123456789abcdef\"]\n",
        "      server-names: [\"www.example.com\"]\n",
        "    users:\n",
        "      - username: alice\n",
        "        uuid: \"11111111-1111-4111-8111-111111111111\"\n",
        "        flow: xtls-rprx-vision\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    )
}

fn missing_vless_listener_gate(spec: &meow_config::ListenerSpec) -> Option<&'static str> {
    matches!(spec, meow_config::ListenerSpec::Vless(_)).then_some("listener-vless")
}

const TEST_TLS_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\nMIIBNzCB36ADAgECAgkAqoMW3roW4aowCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ\nbG9jYWxob3N0MCAXDTI2MTEyNzA3MTgyNFoYDzIxMjYxMTAzMDcxODI0WjAUMRIw\nEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASIGoOq\nLSbzRlVYeSsZVPuRVEVl1vLuy9fwyAeaL3SRkdksE6rZ9tKfs4ccpNw8A0QRAUTo\n2nYqxjRaUSuzhoAqoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0E\nAwIDRwAwRAIgVO92ZOhBj5iaeBEcc28ORj/8DLr1N+l82YVP+hUyKcMCIHvlI+/W\n5TgvSmdKR6y3DejAKXxI8JLvbyNUnmd55Ncs\n-----END CERTIFICATE-----\n";
const TEST_TLS_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTTqgqtc3lQE45oGc\nyMVp3aW7293O/nrp6irnV1G0qMehRANCAASIGoOqLSbzRlVYeSsZVPuRVEVl1vLu\ny9fwyAeaL3SRkdksE6rZ9tKfs4ccpNw8A0QRAUTo2nYqxjRaUSuzhoAq\n-----END PRIVATE KEY-----\n";
const TEST_TLS_OTHER_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDBYCQih1i0LucHMc\nkEgJsSB37HsgJPttBJHT3GNKZyWhRANCAAQ+JSSbwLstC0vrRCw6UuOIhSOXF3Xo\nQEYVASJmRW5WJcO8AfsPNkPJaKY/UwhpRzhHjnUccxQ0VJ7u8eqNxDHq\n-----END PRIVATE KEY-----\n";

fn pem_block(pem: &str) -> String {
    pem.lines().map(|line| format!("      {line}\n")).collect()
}

fn vless_tls_document(certificate: &str, private_key: &str) -> String {
    format!(
        "mode: rule\nlisteners:\n  - name: vision-tls-in\n    type: vless\n    listen: 127.0.0.1\n    port: 0\n    certificate: |\n{}    private-key: |\n{}    users:\n      - username: alice\n        uuid: \"11111111-1111-4111-8111-111111111111\"\n        flow: xtls-rprx-vision\nrules:\n  - MATCH,DIRECT\n",
        pem_block(certificate),
        pem_block(private_key)
    )
}

/// The PUT admission gate must run the same security-identity validation
/// startup runs: a certificate/key pair that cannot form a TLS identity is
/// not an environment defect `force` can wave through — it can never boot.
#[tokio::test]
async fn put_configs_rejects_vless_tls_identity_startup_would_reject() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let certificate = TEST_TLS_CERTIFICATE;
    let matching_key = TEST_TLS_PRIVATE_KEY;
    let mismatched_key = TEST_TLS_OTHER_PRIVATE_KEY;

    for query in ["", "?force=true"] {
        let resp = put_configs_payload(
            &state,
            &vless_tls_document(certificate, mismatched_key),
            query,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query {query}");
        let body = body_string(resp).await;
        assert!(body.contains("vless security"), "{body}");
        assert!(
            !body.contains("BEGIN PRIVATE KEY") && !body.contains("BEGIN CERTIFICATE"),
            "PEM material leaked into the rejection: {body}"
        );
    }
    assert!(
        state.raw_config.read().listeners.is_none(),
        "the rejected identity must not commit"
    );

    let resp =
        put_configs_payload(&state, &vless_tls_document(certificate, matching_key), "").await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// REALITY's runtime cardinality is part of the security identity the next
/// boot either can or cannot construct. More than 64 syntactically valid
/// short IDs must be refused at PUT admission, force included.
#[tokio::test]
async fn put_configs_rejects_vless_reality_short_id_overflow_even_force() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let ids = (1..=65)
        .map(|i| format!("\"{i:02x}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let yaml = vless_reality_document().replace(
        "short-id: [\"0123456789abcdef\"]",
        &format!("short-id: [{ids}]"),
    );

    for query in ["", "?force=true"] {
        let resp = put_configs_payload(&state, &yaml, query).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query {query}");
        let body = body_string(resp).await;
        assert!(body.contains("short-id"), "{body}");
        assert!(body.contains("64"), "{body}");
    }
    assert!(
        state.raw_config.read().listeners.is_none(),
        "the overflowing identity must not commit"
    );
}

/// `decryption` can carry sensitive Xray inbound material in imported
/// configurations. The rejection is allowed to name the field and the sole
/// supported value, never the operator-supplied secret.
#[tokio::test]
async fn put_configs_vless_decryption_rejection_never_echoes_value() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let secret = "xray_inbound_private_key_9f8e7d6c5b4a";
    let yaml = vless_reality_document().replace(
        "    type: vless\n",
        &format!("    type: vless\n    decryption: {secret}\n"),
    );

    let resp = put_configs_payload(&state, &yaml, "").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(body.contains("decryption"), "{body}");
    assert!(body.contains("none"), "{body}");
    assert!(
        !body.contains(secret),
        "decryption value leaked into the API response: {body}"
    );
}

/// `type: vless` is one of the persistence-hard feature gates: even
/// `?force=true` must not write a listener this binary cannot serve,
/// because the next startup would fail its unservable-inbound check.
#[tokio::test]
async fn put_configs_force_rejects_vless_when_listener_feature_is_missing() {
    use base64::Engine as _;

    let mut state = test_state_default();
    let config_path = state.config_path.clone().unwrap();
    Arc::get_mut(&mut state).unwrap().listener_gate = Some(missing_vless_listener_gate);
    let payload = base64::engine::general_purpose::STANDARD.encode(vless_reality_document());
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs?force=true")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({ "payload": payload }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    let message = body["message"].as_str().unwrap();
    assert!(
        message.contains("type vless") && message.contains("listener-vless"),
        "unexpected rejection: {message}"
    );
    assert!(
        state.raw_config.read().listeners.is_none(),
        "the rejected candidate must not mutate the live raw config"
    );
    assert!(
        !std::path::Path::new(&config_path).exists(),
        "the force path must not persist an unservable vless listener"
    );
}

fn vless_reality_named_listener(
    name: &str,
    first_port: u16,
    second_port: Option<u16>,
) -> meow_config::NamedListener {
    use meow_config::{
        ListenerBind, ListenerSpec, NamedListener, RealityLimitFallback, VlessListenerConfig,
        VlessRealityConfig, VlessSecurity, VlessUser,
    };

    let mut addresses = vec![ListenerBind {
        listen: "127.0.0.1".into(),
        port: first_port,
    }];
    if let Some(port) = second_port {
        addresses.push(ListenerBind {
            listen: "127.0.0.2".into(),
            port,
        });
    }
    NamedListener {
        name: name.into(),
        spec: ListenerSpec::Vless(VlessListenerConfig {
            users: vec![VlessUser {
                username: "alice".into(),
                uuid: [
                    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11,
                    0x11, 0x11, 0x11,
                ],
            }],
            security: VlessSecurity::Reality(VlessRealityConfig {
                dest: "www.example.com:443".into(),
                dest_host: "www.example.com".into(),
                dest_port: 443,
                private_key: [0x42; 32],
                short_ids: vec![[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]],
                server_names: vec!["www.example.com".into()],
                max_time_difference_us: 120_000_000,
                limit_fallback_upload: RealityLimitFallback::default(),
                limit_fallback_download: RealityLimitFallback::default(),
                mimic: meow_common::VlessRealityMimicSpec::default(),
            }),
            udp: true,
            addresses,
        }),
        port: first_port,
        listen: "127.0.0.1".into(),
        max_connections: 256,
        route_override: None,
        routing_mark: None,
    }
}

/// `GET /listeners` is an endpoint snapshot, not a config dump: VLESS
/// credentials (`users[].uuid`, REALITY `private-key` and `short-id`) must
/// never cross the API boundary, while multi-bind entries disclose only
/// their bound endpoints.
#[tokio::test]
async fn listeners_endpoint_redacts_vless_credentials() {
    use base64::Engine as _;

    let mut state = test_state_default();
    Arc::get_mut(&mut state).unwrap().listeners =
        vec![vless_reality_named_listener("vision-in", 18443, None)];
    let resp = create_router(state)
        .oneshot(
            Request::get("/listeners")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    let reality_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42; 32]);
    for leaked in [
        "11111111-1111-4111-8111-111111111111",
        "0123456789abcdef",
        reality_key.as_str(),
        "private-key",
        "short-id",
        "mimic",
        "users",
        "uuid",
    ] {
        assert!(
            !body.contains(leaked),
            "GET /listeners leaked {leaked}: {body}"
        );
    }
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let mut keys = json[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys, ["listen", "name", "port", "type"]);
}

/// The startup path rewrites `port: 0` to every OS-assigned endpoint
/// before constructing this snapshot (meow-app's multi-bind publish).
/// The API must report that complete snapshot without collapsing the
/// multi-address entry back to one address or exposing the configured zero.
#[tokio::test]
async fn listeners_endpoint_publishes_vless_ephemeral_multi_bind_snapshot() {
    let mut state = test_state_default();
    Arc::get_mut(&mut state).unwrap().listeners = vec![vless_reality_named_listener(
        "vision-in",
        32443,
        Some(32444),
    )];
    let resp = create_router(state)
        .oneshot(
            Request::get("/listeners")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body[0]["port"], 32443);
    assert_ne!(body[0]["port"], 0);
    assert_eq!(
        body[0]["addresses"],
        serde_json::json!([
            { "listen": "127.0.0.1", "port": 32443 },
            { "listen": "127.0.0.2", "port": 32444 },
        ])
    );
}

/// A committed document can carry REALITY private key material. The
/// end-to-end API persistence path must therefore land owner-only both
/// the replacement config and the backup of the file it replaced.
#[cfg(unix)]
#[tokio::test]
async fn put_configs_persists_vless_secrets_with_owner_only_file_modes() {
    use base64::Engine as _;
    use std::os::unix::fs::PermissionsExt as _;

    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let config_path = std::path::PathBuf::from(state.config_path.clone().unwrap());
    std::fs::write(&config_path, "mode: rule\n").unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let payload = base64::engine::general_purpose::STANDARD.encode(vless_reality_document());
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({ "payload": payload }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/save")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        std::fs::read_to_string(&config_path)
            .unwrap()
            .contains("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo"),
        "the test document must really persist secret-bearing material"
    );
    for path in [config_path.clone(), config_path.with_extension("yaml.bak")] {
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "{} must be owner-only",
            path.display()
        );
    }
    assert_eq!(
        std::fs::read_to_string(config_path.with_extension("yaml.bak")).unwrap(),
        "mode: rule\n"
    );
}

/// `reality-config.mimic` is REALITY runtime configuration, not an
/// environment defect. Both plain and forced PUT admission use the same
/// typed parser startup uses, so malformed or out-of-range values can
/// never be persisted into the next boot.
#[tokio::test]
async fn put_configs_rejects_vless_reality_mimic_even_force() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    for mimic in [
        "      mimic: null\n",
        "      mimic:\n        mode: sideways\n",
        "      mimic:\n        probe-timeout-ms: 499\n",
        "      mimic:\n        mode: off\n        max-concurrent-probes: 0\n",
        "      mimic:\n        quiescence-min-ms: 41\n        quiescence-max-ms: 40\n",
    ] {
        let yaml = vless_reality_document().replace(
            "      server-names: [\"www.example.com\"]\n",
            &format!("      server-names: [\"www.example.com\"]\n{mimic}"),
        );
        for query in ["", "?force=true"] {
            let resp = put_configs_payload(&state, &yaml, query).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{mimic} {query}");
            let body = body_string(resp).await;
            assert!(body.contains("mimic"), "{body}");
        }
    }
    assert!(
        state.raw_config.read().listeners.is_none(),
        "every malformed mimic candidate must be refused before commit"
    );
}

/// Listener comparison is semantic after normalization: absent, `{}` and
/// explicit default mimic are the same startup snapshot, while a real
/// mode change still earns the restart warning. The test observes the
/// warning itself rather than inferring it from a deserialized enum.
#[test]
fn put_configs_vless_mimic_equivalence_and_restart_warning() {
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

    let with_mimic = |mimic: &str| {
        vless_reality_document().replace(
            "      server-names: [\"www.example.com\"]\n",
            &format!("      server-names: [\"www.example.com\"]\n{mimic}"),
        )
    };
    let explicit_defaults = with_mimic(
        "      mimic:\n        mode: dial-first\n        probe-timeout-ms: 3000\n        quiescence-min-ms: 15\n        quiescence-max-ms: 40\n        max-concurrent-probes: 64\n",
    );
    let empty = with_mimic("      mimic: {}\n");
    let numeric_only = with_mimic("      mimic:\n        probe-timeout-ms: 4000\n");
    let off = with_mimic("      mimic:\n        mode: off\n");

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
            .block_on(async {
                let _globals_lane = process_globals_lane().await;
                let mut state = test_state_default();
                Arc::get_mut(&mut state).unwrap().listeners =
                    vec![vless_reality_named_listener("running-vision", 18443, None)];
                assert_eq!(
                    put_configs_payload(&state, vless_reality_document(), "")
                        .await
                        .status(),
                    StatusCode::NO_CONTENT
                );
                sink.0.lock().unwrap().clear();

                for equivalent in [empty, explicit_defaults] {
                    assert_eq!(
                        put_configs_payload(&state, &equivalent, "").await.status(),
                        StatusCode::NO_CONTENT
                    );
                    let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
                    assert!(
                        !logs.contains("listeners: changed"),
                        "equivalent normalized mimic must not warn: {logs}"
                    );
                    sink.0.lock().unwrap().clear();
                }

                assert_eq!(
                    put_configs_payload(&state, &numeric_only, "")
                        .await
                        .status(),
                    StatusCode::NO_CONTENT
                );
                let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
                assert!(
                    logs.contains("listeners: changed") && logs.contains("restart meow"),
                    "a numeric-only mimic change must produce the restart warning: {logs}"
                );
                sink.0.lock().unwrap().clear();

                assert_eq!(
                    put_configs_payload(&state, vless_reality_document(), "")
                        .await
                        .status(),
                    StatusCode::NO_CONTENT
                );
                sink.0.lock().unwrap().clear();
                assert_eq!(
                    put_configs_payload(&state, &off, "").await.status(),
                    StatusCode::NO_CONTENT
                );
                let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
                assert!(
                    logs.contains("listeners: changed") && logs.contains("restart meow"),
                    "mode off must produce the startup-snapshot restart warning: {logs}"
                );

                // These assertions are the narrow witness available here:
                // AppState still publishes the original startup listener row's
                // name and bound port. They do not attempt to prove socket
                // ownership or every typed field.
                assert_eq!(state.listeners.len(), 1);
                assert_eq!(state.listeners[0].name, "running-vision");
                assert_eq!(state.listeners[0].port, 18443);
            });
    });
}

#[tokio::test]
async fn ui_wildcard_serves_same_html() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/ui/some/path")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("<!DOCTYPE html>"));
}

// issue #223: when `external-ui` is configured, `/ui` serves the static
// directory instead of the built-in panel.
#[tokio::test]
async fn external_ui_serves_static_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        "<html><body>third-party dashboard</body></html>",
    )
    .unwrap();
    std::fs::write(dir.path().join("app.js"), "console.log('hi')").unwrap();

    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let raw = test_raw_config();
    let meow_config::RebuildResult {
        proxies,
        rules,
        sub_rules,
        ..
    } = meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies, Default::default());
    tunnel.update_rules_with_sub_rules(rules, sub_rules);
    let state = Arc::new(AppState {
        tunnel,
        secret: None,
        config_path: Some(String::new()),
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        proxy_providers: Arc::new(DashMap::new()),
        provider_dialer_registry: Default::default(),
        ntp_reconcile: None,
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        rule_provider_refresh: Default::default(),
        proxy_provider_refresh: Default::default(),
        listeners: vec![],
        external_ui: Some(dir.path().to_path_buf()),
        traffic_feed: Default::default(),
        dns_server: Default::default(),
        ui_storage: Default::default(),
        listener_gate: None,
        cors: Default::default(),
    });
    let app = create_router(state);

    // `/ui` resolves index.html in the directory.
    let resp = app
        .clone()
        .oneshot(Request::get("/ui").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("third-party dashboard"));

    // A nested asset is served from the directory.
    let resp = app
        .oneshot(
            Request::get("/ui/app.js")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("console.log"));
}

// ── Existing endpoint tests ──────────────────────────────────────

#[tokio::test]
async fn root_returns_hello() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["hello"], "meow");
}

#[tokio::test]
async fn version_endpoint() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/version")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["version"], format!("v{}", env!("CARGO_PKG_VERSION")));
    assert_eq!(json["meta"], true);
}

#[tokio::test]
async fn get_proxies_contains_builtins() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/proxies")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let proxies = json["proxies"].as_object().unwrap();
    assert!(proxies.contains_key("DIRECT"));
    assert!(proxies.contains_key("REJECT"));
    assert!(proxies.contains_key("REJECT-DROP"));
    // issue #533: the match-loop signal built-ins are registered and
    // visible through the API, same as upstream's proxies map.
    assert!(proxies.contains_key("COMPATIBLE"));
    assert!(proxies.contains_key("PASS"));
    assert!(proxies.contains_key("PASS-RULE"));
}

#[tokio::test]
async fn get_proxy_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/proxies/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_proxy_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/proxies/DIRECT")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "DIRECT");
}

// ── provider-name and provider members on /proxies ──────────────────

async fn get_json(state: &Arc<AppState>, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = create_router(Arc::clone(state))
        .oneshot(Request::get(path).body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Commit `config` through `PUT /configs` after writing each
/// `(provider, payload)` to `<provider>.yaml` beside the backing config
/// (`{dir}` in `config` expands to that directory), then wait for every
/// provider's detached first load to publish its nodes.
async fn state_with_file_providers(config: &str, providers: &[(&str, &str)]) -> Arc<AppState> {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let dir = std::path::Path::new(state.config_path.as_deref().unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    for (name, payload) in providers {
        std::fs::write(dir.join(format!("{name}.yaml")), payload).unwrap();
    }
    let document = config.replace("{dir}", &dir.display().to_string());
    let response = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "payload": base64::engine::general_purpose::STANDARD.encode(&document)
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    for (name, payload) in providers {
        let expected = payload.matches("name:").count();
        let provider = Arc::clone(state.proxy_providers.get(*name).unwrap().value());
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while provider.proxies().len() < expected {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("provider {name} must publish its nodes"));
    }
    state
}

/// A provider file of SOCKS5 nodes named `names`, all pointing at `server`.
/// (`type: direct` would not do: a direct node always calls itself `DIRECT`.)
fn socks5_nodes(names: &[&str], server: std::net::SocketAddr) -> String {
    use std::fmt::Write as _;
    let mut yaml = String::from("proxies:\n");
    for name in names {
        writeln!(
            yaml,
            "  - {{name: {name}, type: socks5, server: {}, port: {}}}",
            server.ip(),
            server.port()
        )
        .unwrap();
    }
    yaml
}

/// A no-auth SOCKS5 server relaying every CONNECT, so a node pointing at it
/// passes a real delay probe.
async fn spawn_socks5_relay() -> std::net::SocketAddr {
    async fn relay(mut client: tokio::net::TcpStream) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await?;
        let mut methods = vec![0u8; usize::from(greeting[1])];
        client.read_exact(&mut methods).await?;
        client.write_all(&[5, 0]).await?;
        let mut request = [0u8; 4];
        client.read_exact(&mut request).await?;
        let host = match request[3] {
            1 => {
                let mut ip = [0u8; 4];
                client.read_exact(&mut ip).await?;
                Ipv4Addr::from(ip).to_string()
            }
            3 => {
                let mut domain = vec![0u8; usize::from(client.read_u8().await?)];
                client.read_exact(&mut domain).await?;
                String::from_utf8_lossy(&domain).into_owned()
            }
            _ => return Ok(()),
        };
        let port = client.read_u16().await?;
        let mut upstream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
        client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(relay(client));
        }
    });
    addr
}

/// Nodes the tests never dial point here; nothing listens on port 1.
const UNUSED_SERVER: std::net::SocketAddr =
    std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

const AIRPORT_CONFIG: &str = "mode: rule
proxies:
  - {name: home, type: socks5, server: 127.0.0.1, port: 1}
proxy-providers:
  airport:
    type: file
    path: {dir}/airport.yaml
proxy-groups:
  - {name: PROXY, type: select, proxies: [home], use: [airport]}
rules: ['MATCH,PROXY']
";

/// mihomo sets `provider-name` on every proxy it serializes: the provider's
/// name on a node a proxy-provider supplied, `""` on everything else. Clash
/// Party reads it to pick the delay route; without it every provider node
/// went to `/proxies/{name}/delay` and showed as timed out.
#[tokio::test]
async fn provider_members_carry_provider_name() {
    let nodes = socks5_nodes(&["hk-01", "jp-01"], UNUSED_SERVER);
    let state = state_with_file_providers(AIRPORT_CONFIG, &[("airport", nodes.as_str())]).await;

    let (status, all) = get_json(&state, "/providers/proxies").await;
    assert_eq!(status, StatusCode::OK);
    let (status, one) = get_json(&state, "/providers/proxies/airport").await;
    assert_eq!(status, StatusCode::OK);
    for listing in [&all["providers"]["airport"], &one] {
        let nodes = listing["proxies"].as_array().unwrap();
        assert_eq!(nodes.len(), 2, "{listing}");
        for node in nodes {
            assert_eq!(node["provider-name"], "airport", "{node}");
        }
    }
    let (status, node) = get_json(&state, "/providers/proxies/airport/hk-01").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(node["provider-name"], "airport");

    // `/proxies` keeps mihomo's shape: route-table entries only, each with
    // an empty `provider-name`; provider nodes are listed by their provider.
    let (status, json) = get_json(&state, "/proxies").await;
    assert_eq!(status, StatusCode::OK);
    let proxies = json["proxies"].as_object().unwrap();
    for name in ["home", "PROXY", "GLOBAL", "DIRECT"] {
        assert_eq!(proxies[name]["provider-name"], "", "{name}");
    }
    assert!(!proxies.contains_key("hk-01"), "{json}");
    assert_eq!(
        proxies["PROXY"]["all"],
        serde_json::json!(["home", "hk-01", "jp-01"])
    );

    // A provider node resolves on `/proxies/{name}` too, naming its provider.
    let (status, node) = get_json(&state, "/proxies/hk-01").await;
    assert_eq!(status, StatusCode::OK, "{node}");
    assert_eq!(node["name"], "hk-01");
    assert_eq!(node["provider-name"], "airport");
    let (_, home) = get_json(&state, "/proxies/home").await;
    assert_eq!(home["provider-name"], "");
}

/// `GET /proxies/{name}/delay` used to 404 for a provider node, so a client
/// probing each member of a `use:` group there saw every provider node as
/// down. It now probes the provider's own adapter, the same one
/// `/providers/proxies/{provider}/{name}/healthcheck` probes.
#[tokio::test]
async fn provider_member_delay_resolves_through_proxies_route() {
    let nodes = socks5_nodes(&["hk-01"], spawn_socks5_relay().await);
    let state = state_with_file_providers(AIRPORT_CONFIG, &[("airport", nodes.as_str())]).await;
    let origin = spawn_sub_origin("").await;
    let url = format!("http://{origin}/generate_204");

    let (status, body) = get_json(
        &state,
        &format!("/proxies/hk-01/delay?url={url}&timeout=5000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["delay"].as_u64().unwrap() >= 1, "{body}");
    let provider = Arc::clone(state.proxy_providers.get("airport").unwrap().value());
    let node = provider
        .proxies()
        .into_iter()
        .find(|proxy| proxy.name() == "hk-01")
        .unwrap();
    assert_eq!(
        node.delay_history().len(),
        1,
        "the probe records on the provider's node"
    );

    // The route Clash Party takes once `provider-name` is set.
    let (status, body) = get_json(
        &state,
        &format!("/providers/proxies/airport/hk-01/healthcheck?url={url}&timeout=5000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(node.delay_history().len(), 2);

    let (status, body) = get_json(
        &state,
        &format!("/proxies/nowhere/delay?url={url}&timeout=5000"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["message"], "resource not found");
}

/// Names the route table and the providers share resolve the way groups
/// already treat them: the route-table entry wins, then providers in name
/// order (the order `include-all` lists them in).
#[tokio::test]
async fn proxies_route_prefers_route_table_then_provider_name_order() {
    let beta = socks5_nodes(&["twin", "shared"], UNUSED_SERVER);
    let alpha = socks5_nodes(&["shared"], UNUSED_SERVER);
    let state = state_with_file_providers(
        "mode: rule
proxies:
  - {name: twin, type: socks5, server: 127.0.0.1, port: 1}
proxy-providers:
  beta:
    type: file
    path: {dir}/beta.yaml
  alpha:
    type: file
    path: {dir}/alpha.yaml
proxy-groups:
  - {name: PROXY, type: select, proxies: [twin], use: [beta, alpha]}
rules: ['MATCH,PROXY']
",
        &[("beta", beta.as_str()), ("alpha", alpha.as_str())],
    )
    .await;

    let (status, twin) = get_json(&state, "/proxies/twin").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(twin["provider-name"], "", "the inline proxy wins");
    let (status, shared) = get_json(&state, "/proxies/shared").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(shared["provider-name"], "alpha", "first provider by name");
    let (status, beta) = get_json(&state, "/providers/proxies/beta/shared").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(beta["provider-name"], "beta");
}

/// `enable` gates only the scheduled sweep: the manual
/// `/providers/proxies/{name}/healthcheck` probes with the block's url
/// either way (mihomo `execute` ignores `Enable`), while a block with no
/// url — like a missing block — answers 204 without probing anything
/// (upstream's empty-testUrl skip).
#[tokio::test]
async fn provider_healthcheck_ignores_enable_and_skips_empty_url() {
    let relay = spawn_socks5_relay().await;
    let origin = spawn_sub_origin("").await;
    let nodes = socks5_nodes(&["hk-01"], relay);
    let config = format!(
        "mode: rule
proxies:
  - {{name: home, type: socks5, server: 127.0.0.1, port: 1}}
proxy-providers:
  disabled-hc:
    type: file
    path: {{dir}}/disabled-hc.yaml
    health-check:
      enable: false
      url: http://{origin}/generate_204
      timeout: 5000
  no-url:
    type: file
    path: {{dir}}/no-url.yaml
    health-check:
      enable: true
proxy-groups:
  - {{name: PROXY, type: select, proxies: [home], use: [disabled-hc, no-url]}}
rules: ['MATCH,PROXY']
"
    );
    let state = state_with_file_providers(
        &config,
        &[("disabled-hc", nodes.as_str()), ("no-url", nodes.as_str())],
    )
    .await;
    let node = |name: &str| {
        let provider = Arc::clone(state.proxy_providers.get(name).unwrap().value());
        provider
            .proxies()
            .into_iter()
            .find(|proxy| proxy.name() == "hk-01")
            .unwrap()
    };
    let disabled_node = node("disabled-hc");
    assert!(
        disabled_node.delay_history().is_empty(),
        "enable: false spawns no sweep — nothing may have probed yet"
    );

    // A manual request probes anyway: `enable` disables the timer, not
    // the endpoint.
    let (status, _) = get_json(&state, "/providers/proxies/disabled-hc/healthcheck").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        disabled_node.delay_history().len(),
        1,
        "the manual probe records on the member's own ProxyHealth"
    );

    // No url: 204 without probing (upstream `execute` skips an empty
    // testUrl); `enable: true` does not conjure a probe target.
    let no_url_node = node("no-url");
    let (status, _) = get_json(&state, "/providers/proxies/no-url/healthcheck").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        no_url_node.delay_history().is_empty(),
        "an empty url must probe nothing"
    );
}

/// mihomo reports `hidden` and `icon` on every group (`false` / `""` when
/// unset) and on no leaf proxy. Clash Party leaves hidden groups out of its
/// list and draws the icon on the group's header.
#[tokio::test]
async fn groups_report_hidden_and_icon() {
    let raw: RawConfig = serde_saphyr::from_str(
        r#"
mode: rule
proxies:
  - {name: n1, type: direct}
  - {name: n2, type: direct}
proxy-groups:
  - {name: Hidden, type: select, proxies: [n1], hidden: true, icon: "https://example.com/hk.png"}
  - {name: Auto, type: url-test, proxies: [n1, n2]}
  - {name: Backup, type: fallback, proxies: [n1, n2], hidden: true}
  - {name: Spread, type: load-balance, proxies: [n1, n2], icon: "<svg/>"}
rules: ['MATCH,DIRECT']
"#,
    )
    .unwrap();
    let state = test_state(raw);

    let (status, json) = get_json(&state, "/proxies").await;
    assert_eq!(status, StatusCode::OK);
    let proxies = &json["proxies"];
    for (name, hidden, icon) in [
        ("Hidden", true, "https://example.com/hk.png"),
        ("Auto", false, ""),
        ("Backup", true, ""),
        ("Spread", false, "<svg/>"),
        ("GLOBAL", false, ""),
    ] {
        assert_eq!(proxies[name]["hidden"], hidden, "{name}");
        assert_eq!(proxies[name]["icon"], icon, "{name}");
        assert_eq!(proxies[name]["provider-name"], "", "{name}");
    }
    for leaf in ["n1", "DIRECT"] {
        let entry = proxies[leaf].as_object().unwrap();
        assert!(
            !entry.contains_key("hidden") && !entry.contains_key("icon"),
            "{leaf}: {entry:?}"
        );
    }

    for path in ["/proxies/Hidden", "/group/Hidden"] {
        let (status, group) = get_json(&state, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(group["hidden"], true, "{path}");
        assert_eq!(group["icon"], "https://example.com/hk.png", "{path}");
    }
}

#[tokio::test]
async fn get_configs_returns_mode() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["mode"], "rule");
}

#[tokio::test]
async fn get_configs_returns_default_ipv6_false_when_omitted() {
    // The raw config does not set `ipv6`, so the API must report the runtime
    // default (`false`, matching mihomo/Clash) via `meow_config::effective_ipv6`.
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(
        json["ipv6"], false,
        "omitted ipv6 must report the runtime default (false)"
    );
}

#[tokio::test]
async fn patch_configs_change_mode() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"mode":"direct"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify the mode changed
    let app2 = create_router(state);
    let resp2 = app2
        .oneshot(
            Request::get("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp2).await;
    assert_eq!(json["mode"], "direct");
}

#[tokio::test]
async fn patch_configs_invalid_mode() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"mode":"invalid"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Issue #974: `PATCH /configs` with `interface-name` updates the live
/// global dialer binding (mihomo's top-level option), GET reports it,
/// and `""` clears back to unset.
///
/// `global_interface_name` is process-wide state that *every* config
/// commit re-asserts — parallel tests' TUN/PUT swaps can reset it to
/// their raw's `None` between this test's PATCH and its reads. So the
/// assertions run under `CONFIG_MUTATION` (the same lane the writers
/// serialize on): once held, the observed global is stable.
#[tokio::test]
async fn patch_configs_interface_name_lifecycle() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let patch = |body: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = body.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    let get_iface = |state: &Arc<AppState>| {
        let app = create_router(Arc::clone(state));
        async move {
            let json = body_json(
                app.oneshot(
                    Request::get("/configs")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
            )
            .await;
            json["interface-name"].as_str().unwrap().to_string()
        }
    };

    // Unset reports the mihomo-compatible empty string. (Only this test
    // ever *sets* a name — every other writer commits `None` — so the
    // unset observation needs no lane.)
    assert_eq!(get_iface(&state).await, "");

    // Setting it updates the live global, the raw config, and GET. A
    // concurrent test's swap may win the lane after our PATCH's commit
    // and reset the global to `None` — re-PATCH and retry until the
    // lane sees our value (bounded: writers are finite).
    let mut attempts = 0;
    loop {
        let resp = patch(r#"{"interface-name":"eth9"}"#).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            state.raw_config.read().interface_name.as_deref(),
            Some("eth9")
        );
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if meow_common::global_interface_name().as_deref() == Some("eth9") {
            assert_eq!(get_iface(&state).await, "eth9");
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept resetting the global name");
    }

    // `""` clears the live global again — the raw keeps the user's
    // `""` (normalized away on the next load, like mihomo). Every
    // other writer also commits `None`, so the cleared state is
    // race-free to observe.
    let resp = patch(r#"{"interface-name":""}"#).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
    assert!(meow_common::global_interface_name().is_none());
    assert_eq!(get_iface(&state).await, "");
}

/// Issue #974: `PATCH /configs` with `global-ua` installs the process-wide
/// UA override the internal fetchers and probes send, GET echoes it, `""`
/// clears back to `clash.meta/<version>`, and a value carrying header bytes
/// is rejected without mutating the live override or the committed raw.
/// `global-client-fingerprint` is exposed on GET but not PATCHable —
/// adapters bake it at parse, so it only changes through `PUT /configs`.
///
/// `GLOBAL_UA` is process-wide state every config commit re-asserts —
/// like `global_interface_name` above, the set-side assertions retry under
/// `CONFIG_MUTATION` against racing writers.
#[tokio::test]
async fn patch_configs_global_ua_lifecycle() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let patch = |body: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = body.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    let get_ua = |state: &Arc<AppState>| {
        let app = create_router(Arc::clone(state));
        async move {
            let json = body_json(
                app.oneshot(
                    Request::get("/configs")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
            )
            .await;
            (
                json["global-ua"].as_str().unwrap().to_string(),
                json["global-client-fingerprint"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        }
    };

    // Unset: the mihomo-compatible empty string, both keys exposed. A
    // racing writer may have left a UA installed, so clear it ourselves
    // first and read under the lane — a commit between the clear and the
    // read would swap the live global mid-assertion.
    let mut attempts = 0;
    loop {
        let resp = patch(r#"{"global-ua":""}"#).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if meow_common::global_ua().is_none() {
            assert_eq!(get_ua(&state).await, ("".into(), "".into()));
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept re-installing a global UA");
    }

    // Set → the live global, the raw, and GET all carry it (retry loop:
    // a parallel writer's commit can reset the shared global).
    let mut attempts = 0;
    loop {
        let resp = patch(r#"{"global-ua":"mihomo/v1.18.0"}"#).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if meow_common::global_ua().as_deref() == Some("mihomo/v1.18.0") {
            assert_eq!(get_ua(&state).await, ("mihomo/v1.18.0".into(), "".into()));
            assert_eq!(
                state.raw_config.read().global_ua.as_deref(),
                Some("mihomo/v1.18.0")
            );
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept resetting the global UA");
    }

    // Header bytes are refused — `state.raw_config` is this test's own
    // cell, so the unmutated check is race-free. The live UA must stay
    // EXACTLY what it was — not merely "not the bad value" — so the
    // snapshot/compare pair runs under the lane on both sides of the
    // request, and retries when a sibling commit legitimately moved it.
    let mut attempts = 0;
    loop {
        let before = {
            let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
            meow_common::global_ua()
        };
        let resp = patch("{\"global-ua\":\"bad\\r\\nua\"}").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if meow_common::global_ua() == before {
            assert_eq!(
                state.raw_config.read().global_ua.as_deref(),
                Some("mihomo/v1.18.0"),
                "a rejected PATCH must not reach the committed raw"
            );
            break;
        }
        attempts += 1;
        assert!(
            attempts < 20,
            "a rejected PATCH kept mutating the live global UA"
        );
    }

    // `""` clears the live override — same retry shape as the set side:
    // a racing PUT commits `Some(..)`, so the cleared state is only safe
    // to observe while the lane is held.
    let mut attempts = 0;
    loop {
        let resp = patch(r#"{"global-ua":""}"#).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if meow_common::global_ua().is_none() {
            assert_eq!(get_ua(&state).await, ("".into(), "".into()));
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept re-installing a global UA");
    }
}

/// `tcp-concurrent` is a live process-global like `global-ua`: PATCH
/// flips it without a rebuild, GET reports the live boolean, the
/// committed raw keeps the last PATCH, a replacement PUT applies its own
/// value at the swap (omission resets to the meow-rs default `true`),
/// and a rejected PATCH leaves the running value alone.
///
/// The process-global is shared with every config commit — the
/// assertions run under `CONFIG_MUTATION` like `global_ua`'s.
#[tokio::test]
async fn patch_configs_tcp_concurrent_lifecycle() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    // The process-global must return to `true` even if this test panics —
    // a leaked `false` silently sequentializes every sibling's dials.
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            meow_common::dial::set_tcp_concurrent(true);
        }
    }
    let _reset = Reset;
    let state = test_state_default();
    let patch = |body: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = body.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    let get_concurrent = |state: &Arc<AppState>| {
        let app = create_router(Arc::clone(state));
        async move {
            let json = body_json(
                app.oneshot(
                    Request::get("/configs")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
            )
            .await;
            json["tcp-concurrent"].as_bool().expect("tcp-concurrent")
        }
    };
    // A racing PUT may have committed either value — PATCH the one this
    // test needs and observe under the lane, retrying when a sibling
    // commit legitimately flipped it back.
    let mut attempts = 0;
    loop {
        let resp = patch(r#"{"tcp-concurrent":false}"#).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if !meow_common::dial::tcp_concurrent() {
            assert!(!get_concurrent(&state).await);
            assert_eq!(
                state.raw_config.read().tcp_concurrent,
                Some(false),
                "the PATCH must persist into committed raw"
            );
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept resetting tcp-concurrent");
    }

    // Absent/null PATCHes mean no change — the running `false` survives.
    for body in [r#"{"log-level":"info"}"#, r#"{"tcp-concurrent":null}"#] {
        let resp = patch(body).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
    // Observe `false` unconditionally under the lane — a sibling commit
    // that flipped it is retried like the flips above, not skipped over.
    let mut attempts = 0;
    loop {
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if !meow_common::dial::tcp_concurrent() {
            assert!(!get_concurrent(&state).await);
            break;
        }
        drop(_lane);
        let resp = patch(r#"{"tcp-concurrent":false}"#).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        attempts += 1;
        assert!(attempts < 20, "writers kept resetting tcp-concurrent");
    }

    // A wrong-type PATCH is refused before any mutation — the live value
    // and the committed raw must not move.
    {
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        let before = meow_common::dial::tcp_concurrent();
        let resp = patch(r#"{"tcp-concurrent":"yes","mode":"direct"}"#).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(meow_common::dial::tcp_concurrent(), before);
        assert_eq!(
            state.raw_config.read().tcp_concurrent,
            Some(false),
            "a rejected PATCH must not reach the committed raw"
        );
        assert_ne!(
            state.tunnel.mode().to_string(),
            "direct",
            "the bundled mode change must be rolled back with the rejection"
        );
    }

    // `true` flips it back; GET reports the live policy again.
    let mut attempts = 0;
    loop {
        let resp = patch(r#"{"tcp-concurrent":true}"#).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if meow_common::dial::tcp_concurrent() {
            assert!(get_concurrent(&state).await);
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept resetting tcp-concurrent");
    }

    // A replacement PUT installs its own value at the accepted swap.
    let put = |document: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"payload": payload}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    let mut attempts = 0;
    loop {
        let resp = put("mode: rule\ntcp-concurrent: false\nrules:\n  - MATCH,DIRECT\n").await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if !meow_common::dial::tcp_concurrent() {
            assert!(!get_concurrent(&state).await);
            assert_eq!(state.raw_config.read().tcp_concurrent, Some(false));
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept resetting tcp-concurrent");
    }
    // Omission resets to the meow-rs default `true` (upstream's default
    // is `false` — the divergence is deliberate).
    let mut attempts = 0;
    loop {
        let resp = put("mode: rule\nrules:\n  - MATCH,DIRECT\n").await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if meow_common::dial::tcp_concurrent() {
            assert!(get_concurrent(&state).await);
            assert_eq!(state.raw_config.read().tcp_concurrent, None);
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept resetting tcp-concurrent");
    }
}

/// `find-process-mode` rides the same live-policy lane as
/// `tcp-concurrent`, but per-tunnel: PATCH flips it without a rebuild,
/// GET reports the live mode, the committed raw keeps the last PATCH, a
/// replacement PUT applies its own value at the swap (omission resets to
/// upstream's default `strict`), and a bad spelling is refused before
/// any bundled mutation lands (issue #974).
#[tokio::test]
async fn patch_configs_find_process_mode_lifecycle() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state_default();
    let patch = |body: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = body.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    let get_mode = |state: &Arc<AppState>| {
        let app = create_router(Arc::clone(state));
        async move {
            let json = body_json(
                app.oneshot(
                    Request::get("/configs")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
            )
            .await;
            json["find-process-mode"]
                .as_str()
                .expect("find-process-mode")
                .to_string()
        }
    };
    let put = |document: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"payload": payload}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    // Default is upstream's `strict`.
    assert_eq!(
        state.tunnel.process_lookup_mode(),
        meow_common::ProcessLookupMode::Strict
    );
    assert_eq!(get_mode(&state).await, "strict");

    let resp = patch(r#"{"find-process-mode":"always"}"#).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        state.tunnel.process_lookup_mode(),
        meow_common::ProcessLookupMode::Always
    );
    assert_eq!(get_mode(&state).await, "always");
    assert_eq!(
        state.raw_config.read().find_process_mode,
        Some(meow_common::ProcessLookupMode::Always),
        "the PATCH must persist into committed raw"
    );

    // Absent/null PATCHes mean no change — `always` survives both.
    for body in [r#"{"log-level":"info"}"#, r#"{"find-process-mode":null}"#] {
        let resp = patch(body).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
    assert_eq!(
        state.tunnel.process_lookup_mode(),
        meow_common::ProcessLookupMode::Always
    );

    // An unknown spelling fails JSON extraction before anything applies:
    // the bundled `mode` mutation must not land either.
    let resp = patch(r#"{"find-process-mode":"sometimes","mode":"direct"}"#).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        state.tunnel.process_lookup_mode(),
        meow_common::ProcessLookupMode::Always
    );
    assert_eq!(
        state.raw_config.read().find_process_mode,
        Some(meow_common::ProcessLookupMode::Always)
    );
    assert_ne!(
        state.tunnel.mode().to_string(),
        "direct",
        "the bundled mode change must be rolled back with the rejection"
    );

    // Case-insensitive like the YAML key.
    let resp = patch(r#"{"find-process-mode":"OFF"}"#).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        state.tunnel.process_lookup_mode(),
        meow_common::ProcessLookupMode::Off
    );
    assert_eq!(get_mode(&state).await, "off");

    // A replacement PUT applies its value at the accepted swap; an
    // omitted key resets to upstream's `strict` and clears the raw.
    let resp = put("mode: rule\nfind-process-mode: always\nrules:\n  - MATCH,DIRECT\n").await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        state.tunnel.process_lookup_mode(),
        meow_common::ProcessLookupMode::Always
    );
    assert_eq!(
        state.raw_config.read().find_process_mode,
        Some(meow_common::ProcessLookupMode::Always)
    );

    let resp = put("mode: rule\nrules:\n  - MATCH,DIRECT\n").await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        state.tunnel.process_lookup_mode(),
        meow_common::ProcessLookupMode::Strict
    );
    assert_eq!(get_mode(&state).await, "strict");
    assert_eq!(state.raw_config.read().find_process_mode, None);
}

/// Issue #974: `PUT /configs` commits `global-ua` and
/// `global-client-fingerprint` from the new document — the UA installs
/// process-wide, the fingerprint lands in the committed raw GET reports.
/// A document whose `global-ua` carries header bytes is refused and
/// never mutates the live override.
#[tokio::test]
async fn put_configs_commits_global_ua_and_client_fingerprint() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state_default();
    // This test leaves `Some("mihomo/v1.18.0")` installed on the happy
    // path — reset it on every exit so later tests never inherit it.
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            meow_common::set_global_ua(None);
        }
    }
    let _reset = Reset;
    let put = |document: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "payload": payload }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    // A document with header-injection bytes in `global-ua` fails at
    // candidate validation — and the live override must stay EXACTLY what
    // it was, not merely "not the bad value": snapshot/compare under the
    // lane on both sides, retrying when a sibling commit legitimately
    // moved it between the two reads.
    let mut attempts = 0;
    loop {
        let before = {
            let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
            meow_common::global_ua()
        };
        let resp = put("global-ua: \"bad\\r\\nua\"\n").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if meow_common::global_ua() == before {
            assert!(state.raw_config.read().global_ua.is_none());
            break;
        }
        attempts += 1;
        assert!(
            attempts < 20,
            "a rejected PUT kept mutating the live global UA"
        );
    }

    // The happy path: both keys commit together — and the VLESS REALITY
    // node declares no `client-fingerprint` of its own, so its adapter can
    // only satisfy the REALITY uTLS gate by inheriting the global the PUT
    // committed (issue #974 review).
    let mut attempts = 0;
    loop {
        let resp = put(
            "global-ua: mihomo/v1.18.0\nglobal-client-fingerprint: chrome\n\
             proxies:\n  - {name: rl, type: vless, server: rl.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, reality-opts: {public-key: hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo}}\n",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            state.raw_config.read().global_client_fingerprint.as_deref(),
            Some("chrome")
        );
        assert_eq!(
            state.raw_config.read().global_ua.as_deref(),
            Some("mihomo/v1.18.0")
        );
        let rl = state
            .tunnel
            .proxy("rl")
            .expect("the VLESS node registers in the tunnel");
        assert_eq!(
            rl.client_fingerprint(),
            Some("chrome"),
            "without the committed global the REALITY gate would have dropped it"
        );
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        if meow_common::global_ua().as_deref() == Some("mihomo/v1.18.0") {
            // GET inside the lane: the live UA it reports can't be reset
            // by a racing commit while it's held.
            let json = body_json(
                create_router(Arc::clone(&state))
                    .oneshot(
                        Request::get("/configs")
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(json["global-ua"], "mihomo/v1.18.0");
            assert_eq!(json["global-client-fingerprint"], "chrome");
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept resetting the global UA");
    }

    // Ordered cleanup under the lane: a racing reader between here and
    // the `Reset` guard's drop never observes this test's stale value.
    let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
    meow_common::set_global_ua(None);
}

/// `?force` degrades the `global-ua` admission gate to warn + rewrite:
/// an invalid value must never persist, because the verbatim-commit arm
/// (strict and lenient rebuilds both fail) lands `raw_config` untouched
/// and every later warm mutation re-validates the field through its
/// rebuild — a persisted injection string would 400 them all and
/// hard-error the next boot. The gate rewrites it to the live override.
#[tokio::test]
async fn put_configs_force_invalid_global_ua_commits_live_value() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    // This test installs a live UA — reset it on every exit so later
    // tests never inherit it.
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            meow_common::set_global_ua(None);
        }
    }
    let _reset = Reset;
    let put = |uri: &'static str, document: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "payload": payload }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    // The committed `global-ua`, checked under the mutation lane: never
    // the injected value, always boot-valid. Returns whether it is the
    // live override this test installed (a racing writer's commit can
    // swap the process-global the gate copies — equally valid, but not
    // ours, so the caller retries).
    let check_committed_ua = |state: &Arc<AppState>| {
        let state = Arc::clone(state);
        async move {
            let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
            let committed = state.raw_config.read().global_ua.clone();
            assert!(
                meow_config::validate_global_ua(committed.as_deref()).is_ok(),
                "a forced commit must persist a boot-valid global-ua, got {committed:?}"
            );
            committed.as_deref() == Some("mihomo/v1.18.0")
        }
    };

    let mut attempts = 0;
    loop {
        // The live override the gate should copy on the forced PUTs.
        let resp = put("/configs", "global-ua: mihomo/v1.18.0\n").await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Arm 1 — the verbatim-commit early return: duplicate group names
        // are rejected unconditionally, so the rebuild fails under strict
        // AND lenient and `raw_config` is persisted as written.
        let resp = put(
            "/configs?force=true",
            concat!(
                "global-ua: \"bad\\r\\nua\"\n",
                "proxy-groups:\n",
                "  - {name: dup, type: select, proxies: [DIRECT]}\n",
                "  - {name: dup, type: select, proxies: [REJECT]}\n",
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        {
            let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
            let raw = state.raw_config.read();
            assert!(
                raw.proxy_groups.as_deref().is_some_and(|groups| groups
                    .iter()
                    .filter(|g| g.name == "dup")
                    .count()
                    == 2),
                "the unbuildable document must commit verbatim"
            );
        }
        assert!(
            state.tunnel.proxy("dup").is_none(),
            "nothing built — the previous route table is kept"
        );
        if !check_committed_ua(&state).await {
            attempts += 1;
            assert!(attempts < 20, "writers kept resetting the global UA");
            continue;
        }

        // Arm 2 — a buildable document: the gate normalizes `global-ua`
        // before the rebuild ever sees it.
        let resp = put(
            "/configs?force=true",
            "global-ua: \"bad\\r\\nua\"\nmode: rule\nrules:\n  - MATCH,DIRECT\n",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        if check_committed_ua(&state).await {
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "writers kept resetting the global UA");
    }

    // The poison check: a warm-path mutation on the committed document
    // re-validates `global-ua` through its rebuild — it must succeed.
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"rules":["MATCH,DIRECT"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a forced commit must not poison later warm-path mutations"
    );

    // Ordered cleanup under the lane, same as the PUT test above.
    let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
    meow_common::set_global_ua(None);
}

/// Issue #974: `PUT /configs` commits the `keep-alive-*`, `profile`, and
/// `ntp` top-level knobs; `GET /configs` reports the resolved values —
/// `ntp.write-to-system` always `false` — and `PATCH` applies only the
/// keep-alive keys while leaving the PUT-only sections untouched.
#[tokio::test]
async fn put_configs_roundtrips_top_level_knobs() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    // The PUT installs a non-default keepalive posture on the process
    // global — restore it on every exit so later tests never inherit it.
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            meow_common::set_outbound_tcp_keepalive(meow_common::OutboundTcpKeepalive::default());
        }
    }
    let _reset = Reset;
    let put = |document: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "payload": payload }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    let get = || {
        let app = create_router(Arc::clone(&state));
        async move {
            body_json(
                app.oneshot(
                    Request::get("/configs")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
            )
            .await
        }
    };

    // GET reports keep-alive from the live process global. The lane
    // `process_globals_lane` keeps every config-committing sibling out
    // for this test's whole body, so the PUT's committed posture is
    // stable to observe — the mutation-lane assert below can never see
    // it reset mid-flight (no retry window).
    let resp = put(
        "mode: rule\n\
         keep-alive-idle: 45\n\
         keep-alive-interval: 5\n\
         disable-keep-alive: true\n\
         profile:\n  store-selected: false\n  store-fake-ip: true\n\
         ntp:\n  enable: true\n  server: ntp.test\n  port: 1123\n  interval: 60\n  dialer-proxy: DIRECT\n  write-to-system: true\n\
         rules:\n  - MATCH,DIRECT\n",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    {
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        let live = meow_common::outbound_tcp_keepalive();
        assert!(!live.enabled);
        assert_eq!(live.idle.as_secs(), 45);
        assert_eq!(live.interval.as_secs(), 5);
        let json = get().await;
        assert_eq!(json["keep-alive-idle"], 45);
        assert_eq!(json["keep-alive-interval"], 5);
        assert_eq!(json["disable-keep-alive"], true);
        assert_eq!(json["store-selected"], false);
        assert_eq!(json["store-fake-ip"], true);
    }
    let json = get().await;
    assert_eq!(
        json["ntp"],
        serde_json::json!({
            "enable": true,
            "server": "ntp.test",
            "port": 1123,
            "interval": 60,
            "write-to-system": false,
        }),
        "GET reports the resolved ntp section: DIRECT normalizes to the \
         omitted spelling and write-to-system is never claimed"
    );
    assert_eq!(
        state
            .raw_config
            .read()
            .ntp
            .as_ref()
            .and_then(|n| n.write_to_system),
        Some(true),
        "the raw spelling persists verbatim; only the resolved view drops it"
    );

    // PATCH: keep-alive keys apply (merged over the committed document);
    // `ntp`/`profile` body keys are not PATCH fields — unknown keys are
    // ignored and must leave both the document and GET report alone.
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "keep-alive-idle": 30,
                        "ntp": { "enable": false },
                        "profile": { "store-selected": true },
                        "store-selected": true,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let json = get().await;
    assert_eq!(json["ntp"]["enable"], true, "PATCH must not touch ntp:");
    assert_eq!(
        json["store-selected"], false,
        "PATCH must not touch profile"
    );
    {
        let raw = state.raw_config.read();
        assert!(
            raw.ntp.is_some() && raw.profile.is_some(),
            "PATCH must not merge PUT-only sections into the document"
        );
    }

    // Ordered cleanup under the lane: a racing reader between here and
    // the `Reset` guard's drop never observes this test's stale posture.
    let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
    meow_common::set_outbound_tcp_keepalive(meow_common::OutboundTcpKeepalive::default());
}

/// Issue #974: the forced verbatim-commit fallback — strict AND lenient
/// rebuilds both fail — must not claim a changed effective profile, ntp,
/// or outbound-keepalive posture: each diff alone rejects the PUT, and a
/// knob-free document still commits verbatim.
#[tokio::test]
async fn put_configs_force_fallback_rejects_effective_knob_diffs() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    // The reconcile spy proves a rejected PUT never feeds the candidate's
    // resolved ntp config to the supervisor.
    let seen = Arc::new(std::sync::Mutex::new(Vec::<meow_config::NtpConfig>::new()));
    let mut state = test_state(test_raw_config());
    Arc::get_mut(&mut state).unwrap().ntp_reconcile = Some({
        let seen = Arc::clone(&seen);
        Arc::new(move |cfg| seen.lock().unwrap().push(cfg)) as meow_api::routes::NtpReconcile
    });
    let put = |uri: &'static str, document: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "payload": payload }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    // Duplicate group names fail strict AND lenient — the unbuildable
    // document the verbatim fallback would otherwise commit as written.
    const UNBUILDABLE: &str = "proxy-groups:\n\
         \x20 - {name: dup, type: select, proxies: [DIRECT]}\n\
         \x20 - {name: dup, type: select, proxies: [REJECT]}\n";

    // Each effective-knob diff rejects before the fallback commits. The
    // `tun:` enable flip is the same refusal: the verbatim commit keeps
    // the previous routing and resolver, so a transition it cannot back
    // with a built candidate must not fire (issue #974). Effective
    // `find-process-mode` is the same live tunnel policy — a diff the
    // fallback cannot rebuild is refused, an equal value is not.
    for (label, knob) in [
        ("profile", "profile:\n  store-selected: false\n"),
        ("ntp", "ntp:\n  enable: true\n  server: ntp.test\n"),
        ("keepalive", "keep-alive-idle: 60\n"),
        ("tun", "tun:\n  enable: true\n"),
        ("find-process-mode", "find-process-mode: always\n"),
    ] {
        let before = seen.lock().unwrap().len();
        let resp = put(
            "/configs?force=true",
            &format!("mode: rule\n{knob}{UNBUILDABLE}"),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{label} diff must be rejected under the verbatim fallback"
        );
        assert_eq!(
            seen.lock().unwrap().len(),
            before,
            "{label}: a rejected PUT must not reach the ntp supervisor"
        );
        // The committed document keeps its original knob-free sections.
        {
            let raw = state.raw_config.read();
            assert!(
                raw.ntp.is_none()
                    && raw.profile.is_none()
                    && raw.keep_alive_idle.is_none()
                    && raw.tun.is_none()
                    && raw.find_process_mode.is_none(),
                "{label}: a rejected PUT must not touch the committed document"
            );
        }
    }

    // The knob-free unbuildable document still commits verbatim — the
    // fallback's force leniency itself is unchanged.
    let resp = put("/configs?force=true", &format!("mode: rule\n{UNBUILDABLE}")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    {
        let raw = state.raw_config.read();
        assert!(
            raw.proxy_groups.as_deref().is_some_and(|groups| groups
                .iter()
                .filter(|g| g.name == "dup")
                .count()
                == 2),
            "the unbuildable document must commit verbatim"
        );
    }
    // ...and the verbatim commit's ntp section still reaches the
    // supervisor (resolved disabled — a no-op for it).
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "the committed document's ntp section must reconcile"
    );
}

/// Issue #974 review: the forced verbatim-commit fallback keeps the
/// previous route table, but the committed document's `dns:` verdict must
/// still publish — a verbatim `dns.enable: false` installs the disabled
/// generation, so a `type: dns` leaf's answers flip to SERVFAIL even
/// though the route table (and the leaf adapter itself) was kept. Before
/// the fix the lane committed with `PendingPublish::default()`, so the
/// old enabled generation kept answering and a later same-inputs PUT
/// short-circuited on `dns_inputs_equal` without reconciling.
#[tokio::test]
async fn put_configs_force_verbatim_publishes_dns_disable() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType};
    use meow_common::Metadata;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Committed: DNS enabled with a hosts answer and a `type: dns` leaf
    // reached by DST-PORT,53. Rebuild through the runtime lane so the
    // leaf binds the tunnel's outbound cell — the production publish —
    // then install the enabled generation the way
    // `install_resolver_everywhere` does.
    let raw = meow_config::parse_raw_yaml(
        "mode: rule\n\
         dns:\n\
         \x20 enable: true\n\
         \x20 nameserver: [127.0.0.1:9]\n\
         proxies:\n\
         \x20 - {name: dns-out, type: dns}\n\
         rules:\n\
         \x20 - DST-PORT,53,dns-out\n",
    )
    .unwrap();
    let state = test_state(raw);
    let mut hosts = DomainTrie::new();
    hosts.insert(
        "example.com",
        HostEntry::Addresses(vec!["10.0.0.1".parse().unwrap()]),
    );
    state.tunnel.set_resolver(
        Arc::new(Resolver::new(
            vec!["127.0.0.1:9".parse().unwrap()],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            true,
        )),
        true,
    );
    let meow_config::RebuildResult {
        proxies,
        rules,
        sub_rules,
        ..
    } = meow_config::rebuild_from_raw_runtime(
        &state.raw_config.read().clone(),
        Some(&state.tunnel.resolver_slot()),
        &HashMap::new(),
        None,
        &state.provider_dialer_registry,
        &state.tunnel.selection_backing(),
        &state.tunnel.dns_outbound_cell(),
    )
    .unwrap();
    state.tunnel.update_proxies(proxies, Default::default());
    state.tunnel.update_rules_with_sub_rules(rules, sub_rules);
    *state.tunnel.dns_outbound_cell().write() = Some(state.tunnel.resolver_slot());

    async fn leaf_exchange(state: &Arc<AppState>, id: u16) -> Message {
        let metadata = Metadata {
            host: "example.com".into(),
            dst_port: 53,
            ..Default::default()
        };
        let ResolvedTarget { adapter, .. } =
            state.tunnel.inner().resolve_proxy(&metadata).await.unwrap();
        assert_eq!(adapter.name(), "dns-out");
        let mut conn = adapter.dial_tcp(&metadata).await.unwrap();
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let wire = query.to_vec().unwrap();
        conn.write_all(&(wire.len() as u16).to_be_bytes())
            .await
            .unwrap();
        conn.write_all(&wire).await.unwrap();
        conn.flush().await.unwrap();
        let mut prefix = [0u8; 2];
        conn.read_exact(&mut prefix).await.unwrap();
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        conn.read_exact(&mut body).await.unwrap();
        Message::from_vec(&body).unwrap()
    }

    let before = leaf_exchange(&state, 1).await;
    assert_eq!(before.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        before.answers[0].data,
        RData::A("10.0.0.1".parse().unwrap()),
        "the enabled generation must answer the hosts hit"
    );

    // Duplicate group names fail strict AND lenient — the verbatim lane
    // commits the document as written. Its `dns.enable: false` must still
    // install into the resolver slot the kept leaf reads.
    const UNBUILDABLE: &str = "proxy-groups:\n\
         \x20 - {name: dup, type: select, proxies: [DIRECT]}\n\
         \x20 - {name: dup, type: select, proxies: [REJECT]}\n";
    let payload = base64::engine::general_purpose::STANDARD.encode(format!(
        "mode: rule\n\
         dns:\n\
         \x20 enable: false\n\
         {UNBUILDABLE}"
    ));
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs?force=true")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({ "payload": payload }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let after = leaf_exchange(&state, 2).await;
    assert_eq!(
        after.metadata.response_code,
        ResponseCode::ServFail,
        "a verbatim `dns.enable: false` commit must publish the disabled \
         generation to the dns-outbound cell"
    );
}

/// Issue #974 review: the forced verbatim-commit fallback compares
/// effective `ntp:` values only — a candidate that keeps the committed
/// `ntp:` block verbatim but deletes the named `dialer-proxy` target
/// shows no ntp diff, and without the raw-level declared-name check it
/// would commit a reference the next startup's built-map check
/// hard-fails. A target the candidate still declares commits as before.
#[tokio::test]
async fn put_configs_force_fallback_rejects_dangling_ntp_target() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    // Committed: ntp enabled through `front`, `front` itself declared.
    let state = test_state(
        meow_config::parse_raw_yaml(
            "mode: rule\nntp:\n  enable: true\n  dialer-proxy: front\n\
             proxies:\n  - {name: front, type: direct}\nrules:\n  - MATCH,front\n",
        )
        .unwrap(),
    );
    let put = |document: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs?force=true")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "payload": payload }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    // Duplicate group names fail strict AND lenient — the unbuildable
    // document the verbatim fallback would otherwise commit as written.
    const UNBUILDABLE: &str = "proxy-groups:\n\
         \x20 - {name: dup, type: select, proxies: [DIRECT]}\n\
         \x20 - {name: dup, type: select, proxies: [REJECT]}\n";

    // `front` deleted, `ntp:` kept verbatim — the dangling reference must
    // be refused rather than persisted for the next boot to trip over.
    let resp = put(&format!(
        "mode: rule\nntp:\n  enable: true\n  dialer-proxy: front\n\
         {UNBUILDABLE}rules:\n  - MATCH,DIRECT\n"
    ))
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a dangling ntp.dialer-proxy must not commit through the verbatim fallback"
    );
    {
        let raw = state.raw_config.read();
        assert!(
            raw.proxies.as_deref().is_some_and(|proxies| proxies
                .iter()
                .any(|p| p.get("name").and_then(serde_json::Value::as_str) == Some("front"))),
            "the rejected document must not replace the committed one"
        );
    }

    // A non-transport built-in is refused on the same lane — committed
    // below with the same `dialer-proxy` so the ntp diff gate stays
    // silent and only the declared-name check can catch it.
    {
        let mut raw = state.raw_config.write();
        raw.ntp = Some(meow_config::raw::RawNtp {
            enable: Some(true),
            dialer_proxy: Some("REJECT".into()),
            ..Default::default()
        });
    }
    let resp = put(&format!(
        "mode: rule\nntp:\n  enable: true\n  dialer-proxy: REJECT\n\
         {UNBUILDABLE}rules:\n  - MATCH,DIRECT\n"
    ))
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a non-transport built-in must not dial ntp through the verbatim fallback"
    );
    assert_eq!(
        state.raw_config.read().ntp.as_ref().unwrap().enable,
        Some(true),
        "the rejected document must not persist"
    );

    // `front` still declared in the candidate → the verbatim commit keeps
    // working (the enabled ntp block resolves through the raw names).
    {
        let mut raw = state.raw_config.write();
        raw.ntp = Some(meow_config::raw::RawNtp {
            enable: Some(true),
            dialer_proxy: Some("front".into()),
            ..Default::default()
        });
    }
    let resp = put(&format!(
        "mode: rule\nntp:\n  enable: true\n  dialer-proxy: front\n\
         proxies:\n  - {{name: front, type: direct}}\n\
         {UNBUILDABLE}rules:\n  - MATCH,DIRECT\n"
    ))
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a declared target keeps the verbatim commit"
    );
}

/// Issue #974 review: the forced verbatim-commit fallback must not commit
/// a `sub-rules:` section that fails its structural checks — the section
/// has no lenient arm, so a defect committed verbatim would hard-fail the
/// next boot and every warm mutation until then. Declared rule-provider
/// names stand in as empty sets (availability is environment, not shape);
/// a well-formed section still commits as written.
#[tokio::test]
async fn put_configs_force_fallback_gates_sub_rules_shape() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let put = |document: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs?force=true")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "payload": payload }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    // Duplicate group names fail strict AND lenient — the verbatim
    // fallback is the only path the candidates below can reach.
    const UNBUILDABLE: &str = "proxy-groups:\n\
         \x20 - {name: dup, type: select, proxies: [DIRECT]}\n\
         \x20 - {name: dup, type: select, proxies: [REJECT]}\n";

    // A malformed condition inside a block body is shape — the verbatim
    // commit must refuse it, and the committed document must not move.
    let resp = put(&format!(
        "mode: rule\n{UNBUILDABLE}\
         sub-rules:\n  blk:\n    - SUB-RULE,(MATCH,x),inner\n  inner:\n    - DOMAIN,x.test,DIRECT\n\
         rules:\n  - MATCH,DIRECT\n"
    ))
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        state.raw_config.read().sub_rules.is_none(),
        "the rejected document must not replace the committed one"
    );

    // A top-level `rules:` reference to an undefined block hits the same
    // gate — both builds already fail on it, and the fallback must too.
    let resp = put(&format!(
        "mode: rule\n{UNBUILDABLE}\
         sub-rules:\n  blk:\n    - DOMAIN,x.test,DIRECT\n\
         rules:\n  - SUB-RULE,ghost\n"
    ))
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Structurally sound `sub-rules:` — a conditional reference carrying
    // the MEOW fourth-field fallback included — still commits verbatim.
    let resp = put(&format!(
        "mode: rule\n{UNBUILDABLE}\
         sub-rules:\n  blk:\n    - DOMAIN,x.test,DIRECT\n\
         rules:\n  - SUB-RULE,(DOMAIN,x.test),blk,DIRECT\n  - MATCH,DIRECT\n"
    ))
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(state
        .raw_config
        .read()
        .sub_rules
        .as_ref()
        .is_some_and(|m| m.contains_key("blk")));

    // A conditional reference gated on REMATCH-NAME is sound too — the
    // verbatim gate parses it through the build's block-aware path
    // (issue #974), not the plain rule parser that knows no `SUB-RULE`.
    let resp = put(&format!(
        "mode: rule\n{UNBUILDABLE}\
         sub-rules:\n  blk:\n    - DOMAIN,x.test,DIRECT\n\
         rules:\n  - SUB-RULE,(REMATCH-NAME,stage),blk\n  - MATCH,DIRECT\n"
    ))
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a sound REMATCH-NAME conditional must commit verbatim"
    );

    // A malformed REMATCH-NAME inside the same conditional — an empty
    // alternative the build would hard-fail on — still hits the gate.
    let resp = put(&format!(
        "mode: rule\n{UNBUILDABLE}\
         sub-rules:\n  blk:\n    - DOMAIN,x.test,DIRECT\n\
         rules:\n  - SUB-RULE,(REMATCH-NAME,),blk\n"
    ))
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Issue #974: `/rules/append` dry-parses a candidate line against the
/// committed `sub-rules:` — conditional references (any leaf type but
/// MATCH/SUB-RULE), the MEOW four-field fallback, and plain names all
/// resolve; a broken `sub-rules:` section reports its own error rather
/// than a phantom undefined block.
#[tokio::test]
async fn append_sub_rule_lines_dry_parse() {
    // Every accepted append commits a raw candidate, and the commit
    // re-asserts the process-wide knobs — the lane keeps a sibling
    // config test's commit-and-assert window intact.
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.sub_rules = Some(std::collections::HashMap::from([(
        "blk".to_string(),
        vec!["DOMAIN,inside.test,DIRECT".to_string()],
    )]));
    raw.rules = Some(vec!["SUB-RULE,blk".into(), "MATCH,DIRECT".into()]);
    let state = test_state(raw);
    let post = |rule: &'static str| {
        let app = create_router(Arc::clone(&state));
        async move {
            app.oneshot(
                Request::post("/rules/append")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "rule": rule }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    // Plain, conditional, and four-field references resolve against `blk`;
    // a cond leaf is any rule type except MATCH/SUB-RULE — the widened
    // upstream exclusion set (issue #974 review).
    for rule in [
        "SUB-RULE,(DOMAIN,ok.test),blk",
        "SUB-RULE,(DOMAIN,ok.test),blk,DIRECT",
        "SUB-RULE,((PROCESS-NAME,curl)&(DST-PORT,443)),blk",
    ] {
        assert_eq!(post(rule).await.status(), StatusCode::NO_CONTENT, "{rule}");
    }
    // The committed list carries the appended references; `/rules`
    // reports them in mihomo spelling with the cond text as payload.
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    let rules = json["rules"].as_array().unwrap();
    for payload in ["blk", "(DOMAIN,ok.test),blk", "(DOMAIN,ok.test),blk,DIRECT"] {
        assert!(
            rules
                .iter()
                .any(|r| r["type"] == "SubRules" && r["payload"] == payload),
            "a SubRules entry with payload {payload} must be reported"
        );
    }

    // MATCH/SUB-RULE leaves stay excluded, an undefined block name and a
    // malformed head fail — each with its own parse error.
    for rule in [
        "SUB-RULE,(MATCH,x),blk",
        "SUB-RULE,(SUB-RULE,blk),blk",
        "SUB-RULE,ghost",
        "SUB-RULE,(DOMAIN,x",
    ] {
        assert_eq!(post(rule).await.status(), StatusCode::BAD_REQUEST, "{rule}");
    }
    // The rejections left nothing behind: the rule count is unchanged.
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["rules"].as_array().unwrap().len(), 5);
}

/// Issue #974: the local shape/range gates precede the first candidate
/// network work — `ech-opts.enable` with no `config:` and no query
/// source is a deterministic strict defect that never dials, yet an
/// out-of-range `ntp.interval` must still be the reported failure.
#[tokio::test]
async fn put_configs_local_gates_precede_ech_preresolve() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let app = create_router(Arc::clone(&state));
    let document =
        "strict: true\nntp:\n  interval: 0\nproxies:\n  - name: p\n    type: direct\n    ech-opts:\n      enable: true\n";
    let payload = base64::engine::general_purpose::STANDARD.encode(document);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({ "payload": payload }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    let msg = body["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("ntp.interval"),
        "the ntp range defect must surface before the strict ECH defect: {msg}"
    );
}

/// A malformed `smux:`/`mux:` block on a static leaf is a node-level
/// defect, so the `check_mux_shape` admission gate mirrors the parse's
/// strictness: `strict` rejects the PUT before the ECH preresolve opens
/// sockets, while `?force=true` degrades it like every other strict
/// defect class — the lenient rebuild warn-drops the node and the
/// document commits.
#[tokio::test]
async fn put_configs_strict_bad_mux_gate_force_drops_node() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    let yaml = "strict: true\nmode: rule\n\
        proxies:\n  - {name: badmux, type: vless, server: vless.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, smux: true}\n\
        rules: ['MATCH,DIRECT']\n";

    let status = put_config_yaml(&state, yaml, false).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a strict smux shape defect must reject the candidate"
    );
    assert!(
        state.tunnel.proxy("badmux").is_none(),
        "the route map must be untouched"
    );
    assert!(
        state.raw_config.read().strict.is_none(),
        "the live raw config must be untouched"
    );

    // `?force=true` retries the same candidate leniently: the malformed
    // node is warn-dropped and the document commits.
    let status = put_config_yaml(&state, yaml, true).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "force retains the lenient escape"
    );
    assert!(
        state.tunnel.proxy("badmux").is_none(),
        "the lenient rebuild warn-drops the node"
    );
}

/// Issue #974: under `force`, a `dns:` section that fails its rebuild
/// keeps the previous resolver — but a candidate whose EFFECTIVE
/// store-fake-ip flag (profile > dns > false) differs from the committed
/// document's must not claim a posture the kept pool never implements.
/// A flag-unchanged candidate still degrades to 204 as before.
#[tokio::test]
async fn put_configs_force_broken_dns_gates_store_fake_ip() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let put = |uri: &'static str, document: &str| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "payload": payload }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    // `fake-ip-range` fails inside `reconcile_dns_config` — after the
    // routing rebuild succeeded — landing in the force keep-resolver arm.
    const BROKEN_DNS: &str =
        "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: not-a-cidr\n";

    // A changed effective flag (committed has none → false) rejects.
    let resp = put(
        "/configs?force=true",
        &format!(
            "mode: rule\nprofile:\n  store-fake-ip: true\n{BROKEN_DNS}rules:\n  - MATCH,DIRECT\n"
        ),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a store-fake-ip change must not commit through the kept resolver"
    );
    assert!(
        state.raw_config.read().profile.is_none(),
        "the rejected document must not persist"
    );

    // A `tun:` transition is refused on the same footing — with the
    // resolver kept, the device would respawn on fake-IP geometry the
    // kept generation does not implement.
    let resp = put(
        "/configs?force=true",
        &format!("mode: rule\ntun:\n  enable: true\n{BROKEN_DNS}rules:\n  - MATCH,DIRECT\n"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a tun transition must not commit through the kept resolver"
    );
    assert!(
        state.raw_config.read().tun.is_none(),
        "the rejected document must not persist"
    );

    // Flag unchanged (both sides resolve false) keeps the force degrade.
    let resp = put(
        "/configs?force=true",
        &format!("mode: rule\n{BROKEN_DNS}rules:\n  - MATCH,DIRECT\n"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "unchanged effective flag commits through the keep-resolver arm"
    );
}

/// Issue #974: at the API boundary every non-transport built-in
/// (`REJECT`/`REJECT-DROP`/`PASS`/`PASS-RULE`) is rejected as an
/// `ntp.dialer-proxy` target — they sit in the proxy map but cannot
/// carry the exchange — while `DIRECT` stays a valid dialer.
#[tokio::test]
async fn put_configs_rejects_ntp_dialer_proxy_builtin_policies() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let put = |document: String| {
        let app = create_router(Arc::clone(&state));
        let payload = base64::engine::general_purpose::STANDARD.encode(document);
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "payload": payload }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    for name in ["REJECT", "REJECT-DROP", "PASS", "PASS-RULE"] {
        let resp = put(format!(
            "ntp:\n  enable: true\n  dialer-proxy: {name}\nrules:\n  - MATCH,DIRECT\n"
        ))
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{name}: a non-transport built-in must not dial ntp"
        );
        assert!(
            state.raw_config.read().ntp.is_none(),
            "{name}: a rejected candidate must not touch the committed document"
        );
    }
    let resp =
        put("ntp:\n  enable: true\n  dialer-proxy: DIRECT\nrules:\n  - MATCH,DIRECT\n".to_string())
            .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "DIRECT remains a valid ntp dialer"
    );
}

/// Codex review: the NTP reconcile must run only after the commit has
/// installed the keepalive posture — the supervisor's worker dials
/// through it, so the hook must observe the committed values rather than
/// the pre-commit ones, on a fresh commit AND on a TUN-failure rollback
/// that restores the previous document.
#[tokio::test]
async fn put_configs_installs_keepalive_before_ntp_reconcile() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    // This test commits a keepalive posture — reset the process global
    // on every exit path.
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            meow_common::set_outbound_tcp_keepalive(meow_common::OutboundTcpKeepalive::default());
        }
    }
    let _reset = Reset;
    let observed = Arc::new(std::sync::Mutex::new(Vec::<
        meow_common::OutboundTcpKeepalive,
    >::new()));
    let mut state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    Arc::get_mut(&mut state).unwrap().ntp_reconcile = Some({
        let observed = Arc::clone(&observed);
        Arc::new(move |_| {
            observed
                .lock()
                .unwrap()
                .push(meow_common::outbound_tcp_keepalive());
        }) as meow_api::routes::NtpReconcile
    });
    let put = |yaml: &str| {
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
    };

    let yaml = "mode: rule\nkeep-alive-idle: 33\nkeep-alive-interval: 7\n\
                ntp:\n  enable: true\n  dialer-proxy: DIRECT\nrules:\n  - MATCH,DIRECT\n";
    assert_eq!(put(yaml).await.unwrap().status(), StatusCode::NO_CONTENT);
    let seen = observed.lock().unwrap().clone();
    let ka = seen
        .last()
        .expect("the commit must have reconciled ntp once");
    assert_eq!(
        (ka.idle.as_secs(), ka.interval.as_secs()),
        (33, 7),
        "the reconcile hook must already observe the committed keepalive"
    );
    drop(seen);
}

#[tokio::test]
async fn get_traffic() {
    let state = test_state_default();
    state.tunnel.statistics().add_upload(123);
    state.tunnel.statistics().add_download(456);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/traffic")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
        .await
        .expect("traffic frame timeout")
        .expect("traffic stream ended")
        .expect("traffic body error");
    let json: serde_json::Value =
        serde_json::from_slice(frame.data_ref().expect("traffic data frame")).unwrap();
    assert_eq!(json["up"], 0);
    assert_eq!(json["down"], 0);
    assert_eq!(json["upTotal"], 123);
    assert_eq!(json["downTotal"], 456);
}

/// `GET /statistics` reports the totals and each proxy's share, a closed
/// connection's included, keyed by the leaf that carried it.
#[tokio::test]
async fn get_statistics_reports_traffic_per_proxy() {
    let state = test_state_default();
    let stats = state.tunnel.statistics();
    let id = stats.track_connection(
        Default::default(),
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::default(),
        smallvec![Arc::from("HK-01"), Arc::from("Proxy")],
    );
    let counters = stats.connection_counters(id).unwrap();
    stats.record_upload(&counters, 10);
    stats.record_download(&counters, 20);
    stats.close_connection(id);
    stats.record_packet_upload(stats.proxy_counters("DIRECT").as_deref(), 3);

    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::get("/statistics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({
            "uploadTotal": 13,
            "downloadTotal": 20,
            "proxies": {
                "DIRECT": {"upload": 3, "download": 0},
                "HK-01": {"upload": 10, "download": 20},
            },
        })
    );
}

#[tokio::test]
async fn dns_results_returns_searchable_cache_entries() {
    let state = test_state_default();
    state.tunnel.resolver().preload_cache_with_source(
        "dns.google",
        &[
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        ],
        std::time::Duration::from_secs(300),
        Some("8.8.8.8"),
    );
    state.tunnel.resolver().preload_cache_with_source(
        "dns.alidns.com",
        &[
            IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
        ],
        std::time::Duration::from_secs(300),
        Some("223.5.5.5"),
    );

    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/dns/results?search=google&limit=10")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let entries = json.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "dns.google");
    assert_eq!(entries[0]["ips"][0], "8.8.8.8");
    assert_eq!(entries[0]["ips"][1], "8.8.4.4");
    assert_eq!(entries[0]["from_server"], "8.8.8.8");
    assert!(entries[0]["ttl"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn get_connections_empty() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["uploadTotal"], 0);
    assert_eq!(json["downloadTotal"], 0);
    assert!(json["memory"].is_number());
    assert!(json["connections"].as_array().unwrap().is_empty());
}

// ── Rules CRUD tests ─────────────────────────────────────────────

#[tokio::test]
async fn get_rules_returns_initial() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let rules = json["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["type"], "Domain");
    assert_eq!(rules[0]["payload"], "example.com");
    assert_eq!(rules[0]["proxy"], "DIRECT");
    assert_eq!(rules[1]["type"], "Match");
}

/// mihomo's `PATCH /rules/disable` (`{index: disabled}`, any content type)
/// and the `extra` object `/rules` reports it through.
#[tokio::test]
async fn disable_rules_sets_extra_disabled() {
    let state = test_state_default();
    let patch = |body: &'static str| {
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/rules/disable")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
    };
    assert_eq!(
        patch(r#"{"1":true,"9":true}"#).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        patch(r#"{"x":true}"#).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    let rules = json["rules"].as_array().unwrap();
    assert_eq!(rules[0]["extra"]["disabled"], false);
    assert_eq!(rules[1]["extra"]["disabled"], true);
    assert_eq!(rules[1]["extra"]["hitCount"], 0);
    assert_eq!(rules[1]["extra"]["hitAt"], "1970-01-01T00:00:00Z");
}

/// The lines a client rebuilds from `GET /rules` (mihomo names:
/// `Domain,example.com,DIRECT`) parse back; a negative index is skipped as
/// upstream's `map[int]bool` does; the disabled switch survives the commit.
#[tokio::test]
async fn rules_round_trip_keeps_disabled_switch() {
    let state = test_state_default();
    let send = |method: &str, uri: &str, body: String| {
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
    };
    let rules = || async {
        let resp = send("GET", "/rules", String::new()).await.unwrap();
        body_json(resp).await["rules"].as_array().unwrap().clone()
    };
    let resp = send("PATCH", "/rules/disable", r#"{"-1":true,"0":true}"#.into());
    assert_eq!(resp.await.unwrap().status(), StatusCode::NO_CONTENT);
    let lines: Vec<String> = rules()
        .await
        .iter()
        .map(|r| {
            let (t, p, x) = (&r["type"], &r["payload"], &r["proxy"]);
            let (t, p, x) = (
                t.as_str().unwrap(),
                p.as_str().unwrap(),
                x.as_str().unwrap(),
            );
            if p.is_empty() {
                format!("{t},{x}")
            } else {
                format!("{t},{p},{x}")
            }
        })
        .collect();
    assert_eq!(lines[0], "Domain,example.com,DIRECT");
    let resp = send(
        "POST",
        "/rules",
        serde_json::json!({ "rules": lines }).to_string(),
    );
    assert_eq!(resp.await.unwrap().status(), StatusCode::NO_CONTENT);
    let resp = send(
        "POST",
        "/rules/append",
        r#"{"rule":"DomainSuffix,a.org,DIRECT"}"#.into(),
    );
    assert_eq!(resp.await.unwrap().status(), StatusCode::NO_CONTENT);
    let after = rules().await;
    assert_eq!(after.len(), 3);
    assert_eq!(after[0]["type"], "Domain");
    assert_eq!(after[0]["extra"]["disabled"], true);
    assert_eq!(after[1]["extra"]["disabled"], false);
    assert_eq!(after[2]["type"], "DomainSuffix");
}

#[tokio::test]
async fn replace_rules() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"rules":["DOMAIN-SUFFIX,google.com,DIRECT","MATCH,REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify
    let app2 = create_router(Arc::clone(&state));
    let resp2 = app2
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp2).await;
    let rules = json["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["type"], "DomainSuffix");

    // Also verify raw_config was updated
    let raw = state.raw_config.read();
    let raw_rules = raw.rules.as_ref().unwrap();
    assert_eq!(raw_rules[0], "DOMAIN-SUFFIX,google.com,DIRECT");
}

#[tokio::test]
async fn update_rule_at_index() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"index":0,"rule":"DOMAIN-KEYWORD,test,REJECT"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    assert_eq!(raw.rules.as_ref().unwrap()[0], "DOMAIN-KEYWORD,test,REJECT");
}

#[tokio::test]
async fn update_rule_out_of_range() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"index":99,"rule":"MATCH,DIRECT"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_rule() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/rules/0")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let rules = raw.rules.as_ref().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], "MATCH,REJECT");
}

#[tokio::test]
async fn delete_rule_out_of_range() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/rules/99")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reorder_rules() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules/reorder")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"from":0,"to":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let rules = raw.rules.as_ref().unwrap();
    // MATCH was at index 1, DOMAIN was at 0; after moving 0→1, MATCH is first
    assert_eq!(rules[0], "MATCH,REJECT");
    assert_eq!(rules[1], "DOMAIN,example.com,DIRECT");
}

#[tokio::test]
async fn reorder_rules_out_of_range() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules/reorder")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"from":0,"to":99}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Proxy Groups CRUD tests ─────────────────────────────────────

#[tokio::test]
async fn get_proxy_groups_empty() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn create_proxy_group_selector() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/proxy-groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"MyGroup","type":"select","proxies":["DIRECT","REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "MyGroup");

    // Verify in raw config
    let raw = state.raw_config.read();
    let groups = raw.proxy_groups.as_ref().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "MyGroup");
    assert_eq!(groups[0].group_type, "select");
}

#[tokio::test]
async fn rejected_proxy_group_does_not_mutate_raw_config() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/proxy-groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"Broken","type":"relay","proxies":["DIRECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(state
        .raw_config
        .read()
        .proxy_groups
        .as_ref()
        .is_none_or(Vec::is_empty));
}

#[tokio::test]
async fn create_proxy_group_duplicate_name() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Existing".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/proxy-groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"Existing","type":"select","proxies":["DIRECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_proxy_groups_with_data() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "TestSelector".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let groups = json.as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "TestSelector");
    assert_eq!(groups[0]["type"], "select");
    assert_eq!(groups[0]["proxies"].as_array().unwrap().len(), 2);
    // Selector should have a current selection
    assert!(groups[0]["now"].is_string());
}

#[tokio::test]
async fn get_proxy_groups_expands_provider_backed_runtime_members() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "AUTO".into(),
        group_type: "url-test".into(),
        proxies: None,
        use_providers: Some(vec!["default".into()]),
        ..Default::default()
    }]);

    let node_a = delay_support::TestAdapter::new("node-a", delay_support::DialBehavior::InstantOk)
        .into_proxy();
    let node_b = delay_support::TestAdapter::new("node-b", delay_support::DialBehavior::InstantOk)
        .into_proxy();
    let slot: meow_common::ProviderSlot = Arc::new(RwLock::new(vec![node_a, node_b]));
    let auto: Arc<dyn Proxy> = Arc::new(meow_proxy::UrlTestGroup::new_with_providers(
        "AUTO",
        Vec::new(),
        150,
        vec![slot],
    ));
    let state = test_state_with_route(raw, vec![("AUTO", auto)]);
    let app = create_router(state);

    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let groups = json.as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "AUTO");
    assert_eq!(groups[0]["type"], "url-test");
    assert_eq!(groups[0]["now"], "node-a");
    let proxies = groups[0]["proxies"].as_array().unwrap();
    assert_eq!(proxies.len(), 2);
    assert_eq!(proxies[0], "node-a");
    assert_eq!(proxies[1], "node-b");
}

#[tokio::test]
async fn update_proxy_group() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "G1".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/G1")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"G1","type":"select","proxies":["DIRECT","REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let group = &raw.proxy_groups.as_ref().unwrap()[0];
    assert_eq!(group.proxies.as_ref().unwrap().len(), 2);
}

#[tokio::test]
async fn update_proxy_group_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/nonexistent")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"x","type":"select","proxies":["DIRECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_proxy_group() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "ToDelete".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    // Add a rule targeting this group
    raw.rules = Some(vec![
        "DOMAIN,test.com,ToDelete".into(),
        "DOMAIN,other.com,DIRECT".into(),
        "MATCH,REJECT".into(),
    ]);
    let state = test_state(raw);
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/proxy-groups/ToDelete")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    // Group should be removed
    assert!(raw.proxy_groups.as_ref().unwrap().is_empty());
    // Rule targeting the deleted group should be removed
    let rules = raw.rules.as_ref().unwrap();
    assert_eq!(rules.len(), 2);
    assert!(!rules.iter().any(|r| r.contains("ToDelete")));
}

#[tokio::test]
async fn delete_proxy_group_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/proxy-groups/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn select_proxy_invalid_target() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Sel".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/Sel/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"NONEXISTENT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn select_proxy_group_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/nonexistent/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"DIRECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Subscriptions tests ──────────────────────────────────────────

#[tokio::test]
async fn get_subscriptions_empty() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_subscriptions_with_data() {
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "sub1".into(),
        url: "https://example.com/sub".into(),
        interval: Some(3600),
        last_updated: Some(1000000),
        proxy: None,
        applied_proxies: Vec::new(),
        applied_groups: Vec::new(),
        applied_rules: Vec::new(),
        extra: Default::default(),
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let subs = json.as_array().unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0]["name"], "sub1");
    assert_eq!(subs[0]["url"], "https://example.com/sub");
    assert_eq!(subs[0]["interval"], 3600);
    assert_eq!(subs[0]["proxy_count"], 0);
}

#[tokio::test]
async fn get_subscriptions_reports_counts() {
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "mysub".into(),
        url: "https://example.com".into(),
        interval: None,
        last_updated: None,
        proxy: None,
        // Counts report the subscription's own contribution (issue
        // #640), not merged section totals — mark S1/G/MATCH,G as
        // applied while `selfhop` stays local and uncounted.
        applied_proxies: vec!["S1".into()],
        applied_groups: vec!["G".into()],
        applied_rules: vec!["MATCH,G".into()],
        extra: Default::default(),
    }]);
    let mut proxy1 = std::collections::HashMap::new();
    proxy1.insert("name".to_string(), serde_json::Value::String("S1".into()));
    proxy1.insert("type".to_string(), serde_json::Value::String("ss".into()));
    let mut local = std::collections::HashMap::new();
    local.insert(
        "name".to_string(),
        serde_json::Value::String("selfhop".into()),
    );
    local.insert("type".to_string(), serde_json::Value::String("http".into()));
    raw.proxies = Some(vec![proxy1, local]);
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "G".into(),
        group_type: "select".into(),
        proxies: Some(vec!["S1".into()]),
        ..Default::default()
    }]);
    raw.rules = Some(vec!["MATCH,G".into(), "MATCH,selfhop".into()]);

    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json[0]["proxy_count"], 1);
    assert_eq!(json[0]["group_count"], 1);
    assert_eq!(json[0]["rule_count"], 1);
}

#[tokio::test]
async fn delete_subscription_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/subscriptions/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Issue #640: `DELETE` removes only the entries the subscription
/// actually contributed (its `applied-*` tracking) — local proxies,
/// groups, and rules it never declared must survive.
#[tokio::test]
async fn delete_subscription_clears_data() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "delsub".into(),
        url: "https://example.com".into(),
        interval: None,
        last_updated: None,
        proxy: None,
        applied_proxies: vec!["S1".into()],
        applied_groups: vec!["G".into()],
        applied_rules: vec!["MATCH,G".into()],
        extra: Default::default(),
    }]);
    let mut proxy1 = std::collections::HashMap::new();
    proxy1.insert("name".to_string(), serde_json::Value::String("S1".into()));
    proxy1.insert("type".to_string(), serde_json::Value::String("ss".into()));
    let mut proxy2 = std::collections::HashMap::new();
    proxy2.insert(
        "name".to_string(),
        serde_json::Value::String("selfhop".into()),
    );
    proxy2.insert(
        "type".to_string(),
        serde_json::Value::String("direct".into()),
    );
    raw.proxies = Some(vec![proxy1, proxy2]);
    raw.proxy_groups = Some(vec![
        RawProxyGroup {
            name: "G".into(),
            group_type: "select".into(),
            proxies: Some(vec!["DIRECT".into(), "S1".into()]),
            ..Default::default()
        },
        RawProxyGroup {
            name: "local-g".into(),
            group_type: "select".into(),
            proxies: Some(vec!["selfhop".into()]),
            ..Default::default()
        },
    ]);
    raw.rules = Some(vec!["MATCH,G".into(), "MATCH,selfhop".into()]);

    let state = test_state(raw);
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/subscriptions/delsub")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    // Subscription removed; only its tracked contribution is gone.
    assert!(raw.subscriptions.as_deref().unwrap_or_default().is_empty());
    let proxies = raw.proxies.as_deref().unwrap_or_default();
    assert_eq!(proxies.len(), 1);
    assert_eq!(
        proxies[0].get("name").and_then(|n| n.as_str()),
        Some("selfhop")
    );
    let groups = raw.proxy_groups.as_deref().unwrap_or_default();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "local-g");
    assert_eq!(
        raw.rules.as_deref().unwrap_or_default(),
        &["MATCH,selfhop".to_string()]
    );
}

/// A `DELETE` landing while `POST /api/subscriptions/{name}/refresh` is
/// fetching must surface 404: the endpoint re-verifies the subscription
/// inside the `CONFIG_MUTATION` lane before committing (issue #543).
#[tokio::test]
async fn refresh_subscription_deleted_mid_fetch_returns_404() {
    let _globals_lane = process_globals_lane().await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Gated origin: signals when the request head arrives, then holds the
    // response until released — the refresh stays parked in its fetch.
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
        let body =
            "proxies:\n  - name: resurrected\n    type: http\n    server: 127.0.0.1\n    port: 9\n";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = sock.write_all(resp.as_bytes()).await;
        let _ = sock.shutdown().await;
    });

    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "s".into(),
        url: format!("http://{addr}/sub.yaml"),
        interval: None,
        last_updated: None,
        proxy: None,
        applied_proxies: Vec::new(),
        applied_groups: Vec::new(),
        applied_rules: Vec::new(),
        extra: Default::default(),
    }]);
    let state = test_state(raw);
    let app = create_router(Arc::clone(&state));

    let refresh_app = app.clone();
    let refresh = tokio::spawn(async move {
        refresh_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/subscriptions/s/refresh")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    });

    // Fetch is in flight at the gated origin; the DELETE commits first.
    tokio::time::timeout(std::time::Duration::from_secs(10), got_rx)
        .await
        .expect("origin must see the request within 10s")
        .expect("origin must see the request");
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/subscriptions/s")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let _ = go_tx.send(());
    let resp = refresh.await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(
        state
            .raw_config
            .read()
            .proxies
            .as_deref()
            .unwrap_or_default()
            .iter()
            .all(|p| p.get("name").and_then(|n| n.as_str()) != Some("resurrected")),
        "a deleted subscription's fetched payload must not be committed"
    );
}

/// `POST /api/subscriptions` resolves `proxy` against the live
/// provider-dialer registry before fetching: a blank name is a 400 that
/// never reaches the network, a resolvable name carries the fetch through
/// that hop, and the stored value is exposed by `GET` (issue #625).
#[tokio::test]
async fn add_subscription_proxy_resolution() {
    let _globals_lane = process_globals_lane().await;
    use meow_common::{
        AdapterType, DelayHistory, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth,
        ProxyPacketConn,
    };
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Records each `dial_tcp` target, then dials it for real — a direct
    /// fetch would leave `seen` empty (issue #625).
    struct RecordingFront {
        seen: Mutex<Vec<(String, u16)>>,
        health: ProxyHealth,
    }

    #[async_trait::async_trait]
    impl ProxyAdapter for RecordingFront {
        fn name(&self) -> &str {
            "front"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(&self, m: &Metadata) -> meow_common::Result<Box<dyn ProxyConn>> {
            self.seen
                .lock()
                .unwrap()
                .push((m.host.to_string(), m.dst_port));
            let stream = tokio::net::TcpStream::connect((m.host.as_str(), m.dst_port))
                .await
                .map_err(MeowError::Io)?;
            Ok(Box::new(stream))
        }
        async fn dial_udp(&self, _m: &Metadata) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
            unimplemented!("no udp")
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for RecordingFront {
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
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
    }

    // Origin serving a one-node subscription payload.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut sink = [0u8; 2048];
            let _ = sock.read(&mut sink).await;
            let body = "proxies:\n  - {name: n1, type: direct}\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });

    let raw = test_raw_config();
    let state = test_state(raw);
    let front = Arc::new(RecordingFront {
        seen: Mutex::new(Vec::new()),
        health: ProxyHealth::new(),
    });
    state
        .provider_dialer_registry
        .publish(Arc::new(std::collections::HashMap::from([(
            "front".into(),
            Arc::clone(&front) as Arc<dyn Proxy>,
        )])));
    let app = create_router(Arc::clone(&state));

    // Whitespace-only `proxy` is a typo, not a clear — 400, and nothing
    // is dialed.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/subscriptions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(format!(
                    r#"{{"name":"bad","url":"http://{addr}/sub.yaml","proxy":"   "}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        front.seen.lock().unwrap().is_empty(),
        "a blank proxy name must not reach the network"
    );

    // An unknown name fails closed the same way — 400, never a direct
    // fetch (issue #625).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/subscriptions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(format!(
                    r#"{{"name":"bad2","url":"http://{addr}/sub.yaml","proxy":"ghost"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        front.seen.lock().unwrap().is_empty(),
        "an unresolvable proxy name must not fall back to a direct fetch"
    );

    // A resolvable name carries the fetch through the hop.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/subscriptions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(format!(
                    r#"{{"name":"s","url":"http://{addr}/sub.yaml","proxy":"front"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        front
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|(host, _)| host == "127.0.0.1"),
        "the subscription fetch must transit `front`"
    );

    // And the stored proxy surfaces in GET /api/subscriptions.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json[0]["proxy"], "front");
}

/// Issue #640 repro: `POST /api/subscriptions` with a proxies-only payload
/// must merge into the local config — the hand-written proxy, group, and
/// rule table survive at runtime AND in the auto-saved file, while the
/// remote node joins `proxies:`. A refresh that drops the remote node
/// removes only the tracked contribution.
#[tokio::test]
async fn add_subscription_merges_with_local_config() {
    let _globals_lane = process_globals_lane().await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Proxies-only subscription — the common shape. Second fetch drops
    // `node-1` so the manual refresh below exercises contribution removal.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (switch_tx, switch_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let dropped = *switch_rx.borrow();
            let body: &'static str = if dropped {
                "proxies:\n  - {name: node-2, type: http, server: 127.0.0.1, port: 9}\n"
            } else {
                "proxies:\n  - {name: node-1, type: http, server: 127.0.0.1, port: 9}\n"
            };
            let mut sink = [0u8; 2048];
            let _ = sock.read(&mut sink).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });

    // The issue's hand-written config: a local helper proxy plus a rule
    // table referencing it.
    let mut raw = test_raw_config();
    // `http` keeps its configured name — a `direct` node's `name()` is
    // hardcoded "DIRECT" and would collide with the builtin.
    let mut selfhop = std::collections::HashMap::new();
    selfhop.insert(
        "name".to_string(),
        serde_json::Value::String("selfhop".into()),
    );
    selfhop.insert("type".to_string(), serde_json::Value::String("http".into()));
    selfhop.insert(
        "server".to_string(),
        serde_json::Value::String("127.0.0.1".into()),
    );
    selfhop.insert("port".to_string(), serde_json::Value::Number(18080.into()));
    raw.proxies = Some(vec![selfhop]);
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "local-g".into(),
        group_type: "select".into(),
        proxies: Some(vec!["selfhop".into()]),
        ..Default::default()
    }]);
    raw.rules = Some(vec!["DOMAIN,x.test,REJECT".into(), "MATCH,selfhop".into()]);
    let state = test_state(raw);
    let app = create_router(Arc::clone(&state));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/subscriptions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(format!(
                    r#"{{"name":"s","url":"http://{addr}/sub.yaml"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    // Counts report the merged section totals, not the payload's sizes.
    assert_eq!(json["proxy_count"], 2, "{json}");
    assert_eq!(json["group_count"], 1, "{json}");
    assert_eq!(json["rule_count"], 2, "{json}");

    {
        let raw = state.raw_config.read();
        let names: Vec<String> = raw
            .proxies
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        assert_eq!(names, vec!["selfhop".to_string(), "node-1".to_string()]);
        assert_eq!(
            raw.rules.as_deref().unwrap_or_default(),
            &[
                "DOMAIN,x.test,REJECT".to_string(),
                "MATCH,selfhop".to_string()
            ]
        );
        assert_eq!(
            raw.proxy_groups.as_deref().unwrap_or_default()[0].name,
            "local-g"
        );
        // The contribution is tracked so refresh/delete stay surgical.
        let subs = raw.subscriptions.as_deref().unwrap_or_default();
        assert_eq!(subs[0].applied_proxies, vec!["node-1".to_string()]);
        assert!(subs[0].applied_groups.is_empty());
        assert!(subs[0].applied_rules.is_empty());
    }

    // The auto-save must carry the merged config — a restart after the
    // add must not come back with the local table lost (issue #640).
    let saved = std::fs::read_to_string(state.config_path.as_deref().unwrap()).unwrap();
    assert!(saved.contains("selfhop"), "{saved}");
    assert!(saved.contains("DOMAIN,x.test,REJECT"), "{saved}");

    // Refresh after the remote dropped node-1: only the tracked
    // contribution is replaced — local entries and the remote node the
    // refresh actually ships survive.
    switch_tx.send(true).unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/subscriptions/s/refresh")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    {
        let raw = state.raw_config.read();
        let names: Vec<String> = raw
            .proxies
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        assert_eq!(
            names,
            vec!["selfhop".to_string(), "node-2".to_string()],
            "refresh must replace only the tracked contribution"
        );
        assert_eq!(
            raw.rules.as_deref().unwrap_or_default(),
            &[
                "DOMAIN,x.test,REJECT".to_string(),
                "MATCH,selfhop".to_string()
            ]
        );
        let subs = raw.subscriptions.as_deref().unwrap_or_default();
        assert_eq!(subs[0].applied_proxies, vec!["node-2".to_string()]);
    }

    // DELETE removes only the contribution — local config intact.
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/subscriptions/s")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let raw = state.raw_config.read();
    let names: Vec<String> = raw
        .proxies
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(str::to_string))
        .collect();
    assert_eq!(names, vec!["selfhop".to_string()]);
    assert_eq!(
        raw.rules.as_deref().unwrap_or_default(),
        &[
            "DOMAIN,x.test,REJECT".to_string(),
            "MATCH,selfhop".to_string()
        ]
    );
}

// ── Config save test ─────────────────────────────────────────────

#[tokio::test]
async fn save_config_creates_file() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/save")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify file was written
    let content = std::fs::read_to_string(state.config_path.as_deref().unwrap()).unwrap();
    assert!(content.contains("mixed-port"));
}

#[tokio::test]
async fn save_config_creates_backup() {
    let state = test_state_default();

    // Write initial file
    std::fs::write(state.config_path.as_deref().unwrap(), "old content").unwrap();

    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/save")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify backup was created
    let bak_path = format!("{}.bak", state.config_path.as_deref().unwrap());
    let bak_content = std::fs::read_to_string(bak_path).unwrap();
    assert_eq!(bak_content, "old content");
}

/// A `--config-string` run has no backing file — the save endpoint must
/// refuse explicitly instead of inventing `./config.yaml` (issue #717).
#[tokio::test]
async fn save_config_refuses_without_backing_file() {
    let state = test_state_ephemeral(test_raw_config());
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/save")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(
        body.contains("no backing config file"),
        "expected a no-backing-file refusal, got: {body}"
    );
}

/// Subscription deletes still apply in memory under `--config-string`;
/// only the disk write is skipped — the response stays 204 and the live
/// raw config drops the entry (issue #717).
#[tokio::test]
async fn delete_subscription_without_backing_file_skips_persist() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "delsub".into(),
        url: "https://example.com".into(),
        interval: None,
        last_updated: None,
        proxy: None,
        applied_proxies: Vec::new(),
        applied_groups: Vec::new(),
        applied_rules: Vec::new(),
        extra: Default::default(),
    }]);
    let state = test_state_ephemeral(raw);
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/subscriptions/delsub")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        state
            .raw_config
            .read()
            .subscriptions
            .as_deref()
            .is_none_or(<[_]>::is_empty),
        "subscription must be removed from the live raw config"
    );
}

/// Single-body subscription origin for the `persisted:false` tests. The
/// request head is drained to `\r\n\r\n` before responding so a short
/// read + `Connection: close` cannot RST-clobber the buffered response.
async fn spawn_sub_origin(body: &'static str) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 2048];
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
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    addr
}

/// The add response must report `"persisted": false` under
/// `--config-string` — the merge applies in memory, the skipped write is
/// explicit in the API contract (issue #717).
#[tokio::test]
async fn add_subscription_without_backing_file_reports_not_persisted() {
    let _globals_lane = process_globals_lane().await;
    let addr =
        spawn_sub_origin("proxies:\n  - {name: node-1, type: http, server: 127.0.0.1, port: 9}\n")
            .await;

    let state = test_state_ephemeral(test_raw_config());
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/subscriptions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(format!(
                    r#"{{"name":"s","url":"http://{addr}/sub.yaml"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["persisted"], false, "{json}");
    assert!(
        state.raw_config.read().subscriptions.is_some(),
        "the subscription must be committed in memory even unpersisted"
    );
}

/// Refresh shares the same `persist_candidate` plumbing as add — pin the
/// `"persisted": false` contract on this endpoint too (issue #717).
#[tokio::test]
async fn refresh_subscription_without_backing_file_reports_not_persisted() {
    let _globals_lane = process_globals_lane().await;
    let addr =
        spawn_sub_origin("proxies:\n  - {name: node-2, type: http, server: 127.0.0.1, port: 9}\n")
            .await;

    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "s".into(),
        url: format!("http://{addr}/sub.yaml"),
        interval: Some(600),
        last_updated: None,
        proxy: None,
        applied_proxies: vec![],
        applied_groups: vec![],
        applied_rules: vec![],
        extra: Default::default(),
    }]);
    let state = test_state_ephemeral(raw);
    let app = create_router(Arc::clone(&state));

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/subscriptions/s/refresh")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["persisted"], false, "{json}");
    assert!(
        state.raw_config.read().subscriptions.as_deref().unwrap()[0]
            .applied_proxies
            .contains(&"node-2".to_string()),
        "the refresh must commit its contribution in memory"
    );
}

// ── PUT /proxies/{name} selector switch test ─────────────────────

#[tokio::test]
async fn put_proxy_selector_switch() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "MySelector".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);

    // Switch to REJECT
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/proxies/MySelector")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// mihomo ignores the body's Content-Type; dashboards send selections as
/// `text/plain` or untyped.
#[tokio::test]
async fn put_proxy_selector_switch_without_json_content_type() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "MySelector".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);
    for content_type in [
        None,
        Some("text/plain;charset=UTF-8"),
        Some("application/x-www-form-urlencoded"),
        Some("application/octet-stream"),
        Some(""),
        Some("application/merge-patch+json"),
        // Malformed "+json" with no subtype before the suffix — must be
        // relabelled (not treated as JSON), otherwise axum 422s a non-JSON body.
        Some("application/+json"),
    ] {
        let mut req = Request::builder().method("PUT").uri("/proxies/MySelector");
        if let Some(t) = content_type {
            req = req.header("content-type", t);
        }
        let resp = create_router(Arc::clone(&state))
            .oneshot(
                req.body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "{content_type:?}");
    }
}

#[tokio::test]
async fn put_and_delete_automatic_group_selection() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![
        RawProxyGroup {
            name: "Auto".into(),
            group_type: "url-test".into(),
            proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
            ..Default::default()
        },
        RawProxyGroup {
            name: "Failover".into(),
            group_type: "fallback".into(),
            proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
            ..Default::default()
        },
    ]);
    let state = test_state(raw);
    let app = create_router(state);

    for group in ["Auto", "Failover"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/proxies/{group}"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let detail = app
            .clone()
            .oneshot(
                Request::get(format!("/group/{group}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_json(detail).await["fixed"], "REJECT");

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/proxies/{group}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let detail = app
            .clone()
            .oneshot(
                Request::get(format!("/group/{group}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_json(detail).await["fixed"], "");
    }
}

#[tokio::test]
async fn group_routes_filter_leaf_proxies() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Choice".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    let app = create_router(test_state(raw));
    let groups = app
        .clone()
        .oneshot(
            Request::get("/group")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(groups).await;
    assert!(json["proxies"].get("Choice").is_some());
    assert!(json["proxies"].get("DIRECT").is_none());

    let leaf = app
        .oneshot(
            Request::get("/group/DIRECT")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(leaf.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_proxy_not_a_group() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/proxies/DIRECT")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"something"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // DIRECT is not a SelectorGroup, returns BAD_REQUEST (matching mihomo behavior)
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn select_proxy_roundtrip() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Sel".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);

    // Select REJECT
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/Sel/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "select failed");

    // Read back proxy groups
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let groups: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let sel = &groups[0];
    assert_eq!(
        sel["now"], "REJECT",
        "now field should be REJECT after select"
    );
}

// ── Bearer auth middleware ───────────────────────────────────────

#[tokio::test]
async fn controller_without_secret_restricts_browser_access() {
    use axum::http::header;

    let app = create_router(test_state_with_secret(""));
    let cases = [
        ("/ui", "localhost:9090", None, None, StatusCode::OK),
        ("/version", "127.0.0.1:9090", None, None, StatusCode::OK),
        (
            "/version",
            "[::1]:9090",
            Some("http://[::1]:9090"),
            Some("same-origin"),
            StatusCode::OK,
        ),
        (
            "/version",
            "localhost:80",
            Some("http://localhost"),
            Some("same-origin"),
            StatusCode::OK,
        ),
        (
            "/version",
            "127.0.0.1:9090",
            Some("http://127.0.0.1:9091"),
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "/version",
            "localhost:9090",
            Some("https://localhost:9090"),
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "/version",
            "localhost:9090",
            Some("null"),
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "/version",
            "localhost:9090",
            None,
            Some("cross-site"),
            StatusCode::FORBIDDEN,
        ),
        (
            "/version",
            "controller.example:9090",
            None,
            None,
            StatusCode::FORBIDDEN,
        ),
    ];

    for (path, host, origin, fetch_site, status) in cases {
        let mut req = Request::get(path).header(header::HOST, host);
        if let Some(origin) = origin {
            req = req.header(header::ORIGIN, origin);
        }
        if let Some(fetch_site) = fetch_site {
            req = req.header("sec-fetch-site", fetch_site);
        }
        let response = app
            .clone()
            .oneshot(req.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{host} from {origin:?}");
        assert!(!response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    let response = app
        .oneshot(
            Request::post("/rules")
                .header(header::HOST, "127.0.0.1:9090")
                .header(header::ORIGIN, "https://dashboard.example")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(axum::body::Body::from(r#"{"rules":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn controller_with_secret_allows_authenticated_cross_origin_dashboards() {
    use axum::http::{header, Method};

    let app = create_router(test_state_with_secret("test-token"));
    let preflight = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/version")
                .header(header::HOST, "controller.example:9090")
                .header(header::ORIGIN, "https://dashboard.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization,content-type",
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(preflight.status(), StatusCode::OK);
    assert_eq!(
        preflight.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "*"
    );
    // Absent map under a configured secret resolves `["*"]`/`true` — the
    // configured-path shape: method echo, canonicalized header echo and
    // max-age 300 (issue #974).
    assert_eq!(
        preflight.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "Authorization, Content-Type"
    );
    assert_eq!(
        preflight.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "GET"
    );
    assert_eq!(preflight.headers()[header::ACCESS_CONTROL_MAX_AGE], "300");

    let response = app
        .oneshot(
            Request::get("/version")
                .header(header::HOST, "controller.example:9090")
                .header(header::ORIGIN, "https://dashboard.example")
                .header(header::AUTHORIZATION, "Bearer test-token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
}

#[tokio::test]
async fn auth_middleware_table() {
    use axum::http::header::HeaderValue;

    /// `Authorization` header a case sends.
    enum AuthHeader {
        /// No `Authorization` header at all.
        Absent,
        /// Header value that is valid ASCII.
        Str(&'static str),
        /// Raw bytes, so non-ASCII values can be exercised.
        Raw(&'static [u8]),
    }

    struct Case {
        label: &'static str,
        /// `None` → `AppState.secret` is `None`; `Some(s)` → `Some(s.to_string())`.
        secret: Option<&'static str>,
        method: &'static str,
        path: &'static str,
        auth: AuthHeader,
        /// JSON request body; sets `content-type: application/json` when present.
        body: Option<&'static str>,
        expected: StatusCode,
    }

    let cases = [
        Case {
            label: "unset secret: auth disabled, API request allowed",
            secret: None,
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Absent,
            body: None,
            expected: StatusCode::OK,
        },
        Case {
            label: "empty secret: auth disabled, API request allowed",
            secret: Some(""),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Absent,
            body: None,
            expected: StatusCode::OK,
        },
        Case {
            label: "missing Authorization header rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Absent,
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            label: "wrong token rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Bearer wrongtoken"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            label: "correct token allows request",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Bearer hunter2"),
            body: None,
            expected: StatusCode::OK,
        },
        Case {
            // /version is deliberately probed here: it proves the gate covers it too.
            label: "lowercase `bearer ` prefix rejected (only `Bearer ` is stripped)",
            secret: Some("hunter2"),
            method: "GET",
            path: "/version",
            auth: AuthHeader::Str("bearer hunter2"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            label: "non-Bearer scheme rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Basic hunter2"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            label: "UI routes remain unauthenticated",
            secret: Some("hunter2"),
            method: "GET",
            path: "/ui",
            auth: AuthHeader::Absent,
            body: None,
            expected: StatusCode::OK,
        },
        Case {
            label: "gated write endpoint rejects unauthenticated POST",
            secret: Some("hunter2"),
            method: "POST",
            path: "/rules",
            auth: AuthHeader::Absent,
            body: Some(r#"{"rules":[]}"#),
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            // "Bearer " with nothing after the space: strip_prefix yields "", != secret.
            label: "`Bearer ` with empty value rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Bearer "),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            // "Bearerhunter2" — no "Bearer " prefix, so strip_prefix returns None
            // and the middleware cannot extract a token.
            label: "no space after `Bearer` rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Bearerhunter2"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            // "Bearer café" — é is 0xC3 0xA9 (two UTF-8 bytes, not valid ASCII).
            // HeaderValue::to_str() returns Err for non-ASCII bytes, so the
            // middleware sees None for the provided token and returns 401.
            label: "multibyte UTF-8 header value rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Raw(b"Bearer caf\xc3\xa9"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        let state = match case.secret {
            None => test_state_default(),
            Some(secret) => test_state_with_secret(secret),
        };
        let app = create_router(state);

        let mut builder = Request::builder().method(case.method).uri(case.path);
        match case.auth {
            AuthHeader::Absent => {}
            AuthHeader::Str(value) => builder = builder.header("authorization", value),
            AuthHeader::Raw(bytes) => {
                builder = builder.header("authorization", HeaderValue::from_bytes(bytes).unwrap());
            }
        }
        let req = match case.body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
            None => builder.body(axum::body::Body::empty()).unwrap(),
        };

        let status = app.oneshot(req).await.unwrap().status();
        if status != case.expected {
            failures.push(format!(
                "[{}] {} {} → expected {}, got {status}",
                case.label, case.method, case.path, case.expected
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "auth middleware cases failed:\n{}",
        failures.join("\n")
    );
}

// ── Delay endpoints (M1.G-2) ─────────────────────────────────────────

mod delay_support {
    use meow_common::{
        AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn,
        ProxyHealth, ProxyPacketConn, Result,
    };
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[derive(Clone, Debug)]
    pub enum DialBehavior {
        InstantOk,
        SleepThenOk(Duration),
        SleepThenError(Duration),
        ImmediateError,
        /// Used by #29 tests: dial succeeds instantly but the canned HTTP
        /// response returns the given status code. Exercises the
        /// `expected`-param path and the status-line parsing path.
        InstantStatus(u16, &'static str),
        /// Dials to the port fail as refused; the rest succeed instantly.
        RefusesPort(u16),
    }

    pub struct TestAdapter {
        name: String,
        addr: String,
        /// `connect_over` passes the stream through rather than refusing.
        relays: bool,
        health: ProxyHealth,
        behavior: DialBehavior,
        pub dial_starts: Arc<Mutex<Vec<Instant>>>,
    }

    impl TestAdapter {
        pub fn new(name: &str, behavior: DialBehavior) -> Self {
            Self {
                name: name.to_string(),
                addr: String::new(),
                relays: false,
                health: ProxyHealth::new(),
                behavior,
                dial_starts: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// A proxy with a server at `addr`, rather than a DIRECT-like hop a
        /// relay passes through.
        pub fn at(mut self, addr: &str) -> Self {
            self.addr = addr.to_string();
            self
        }

        /// One that also runs over another proxy's stream, as a chained
        /// outbound does.
        pub fn relaying(mut self) -> Self {
            self.relays = true;
            self
        }

        pub fn into_proxy(self) -> Arc<dyn Proxy> {
            Arc::new(WrappedTest {
                inner: Arc::new(self),
            })
        }
    }

    /// Canned HTTP responder used so `url_test`'s real `GET` path exercises a
    /// full write/read cycle without needing a kernel socket. Writes are
    /// discarded; reads return a byte-at-a-time slice of the configured
    /// response (default: `HTTP/1.1 204 No Content\r\n\r\n`). Override the
    /// status via `CannedConn::with_status` to drive `expected`-param tests.
    struct CannedConn {
        response: Vec<u8>,
        cursor: usize,
    }
    impl CannedConn {
        fn ok() -> Self {
            Self::with_status(204, "No Content")
        }
        fn with_status(code: u16, reason: &str) -> Self {
            Self {
                response: format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\n\r\n")
                    .into_bytes(),
                cursor: 0,
            }
        }
    }
    impl tokio::io::AsyncRead for CannedConn {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let remaining = self.response.len() - self.cursor;
            if remaining == 0 {
                return std::task::Poll::Ready(Ok(()));
            }
            let n = remaining.min(buf.remaining());
            let start = self.cursor;
            let end = start + n;
            buf.put_slice(&self.response[start..end]);
            self.cursor += n;
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl tokio::io::AsyncWrite for CannedConn {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl Unpin for CannedConn {}
    impl ProxyConn for CannedConn {}

    struct NopPacketConn;
    #[async_trait::async_trait]
    impl ProxyPacketConn for NopPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            Err(MeowError::Proxy("nop".into()))
        }
        async fn write_packet(&self, _buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
            Ok(0)
        }
        fn local_addr(&self) -> Result<SocketAddr> {
            Err(MeowError::Proxy("nop".into()))
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl ProxyAdapter for TestAdapter {
        fn name(&self) -> &str {
            &self.name
        }
        fn adapter_type(&self) -> AdapterType {
            if self.addr.is_empty() {
                AdapterType::Direct
            } else {
                AdapterType::Http
            }
        }
        fn addr(&self) -> &str {
            &self.addr
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
            self.dial_starts.lock().unwrap().push(Instant::now());
            match &self.behavior {
                DialBehavior::RefusesPort(port) if metadata.dst_port == *port => {
                    Err(MeowError::Proxy("connection refused".into()))
                }
                DialBehavior::InstantOk | DialBehavior::RefusesPort(_) => {
                    Ok(Box::new(CannedConn::ok()))
                }
                DialBehavior::SleepThenOk(d) => {
                    tokio::time::sleep(*d).await;
                    Ok(Box::new(CannedConn::ok()))
                }
                DialBehavior::SleepThenError(d) => {
                    tokio::time::sleep(*d).await;
                    Err(MeowError::Proxy("test sleep-then-error".into()))
                }
                DialBehavior::ImmediateError => Err(MeowError::Proxy("test immediate".into())),
                DialBehavior::InstantStatus(code, reason) => {
                    Ok(Box::new(CannedConn::with_status(*code, reason)))
                }
            }
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            Ok(Box::new(NopPacketConn))
        }
        async fn connect_over(
            &self,
            stream: Box<dyn ProxyConn>,
            _metadata: &Metadata,
        ) -> Result<Box<dyn ProxyConn>> {
            if !self.relays {
                return Err(MeowError::NotSupported(format!(
                    "{}: connect_over not supported",
                    self.name
                )));
            }
            Ok(stream)
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    /// Forwards the `Proxy` trait to the wrapped `TestAdapter` so the tunnel
    /// registry can store `Arc<dyn Proxy>` directly.
    pub struct WrappedTest {
        inner: Arc<TestAdapter>,
    }

    #[async_trait::async_trait]
    impl ProxyAdapter for WrappedTest {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn adapter_type(&self) -> AdapterType {
            self.inner.adapter_type()
        }
        fn addr(&self) -> &str {
            self.inner.addr()
        }
        fn support_udp(&self) -> bool {
            self.inner.support_udp()
        }
        async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
            self.inner.dial_tcp(metadata).await
        }
        async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            self.inner.dial_udp(metadata).await
        }
        async fn connect_over(
            &self,
            stream: Box<dyn ProxyConn>,
            metadata: &Metadata,
        ) -> Result<Box<dyn ProxyConn>> {
            self.inner.connect_over(stream, metadata).await
        }
        fn health(&self) -> &ProxyHealth {
            self.inner.health()
        }
    }

    impl Proxy for WrappedTest {
        fn alive(&self) -> bool {
            self.inner.health().alive()
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            self.inner.health().alive()
        }
        fn last_delay(&self) -> u16 {
            self.inner.health().last_delay()
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            self.inner.health().last_delay()
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            self.inner.health().delay_history()
        }
    }

    /// Build an app state whose tunnel holds exactly the given set of named
    /// proxies. Uses the real `Tunnel` so the delay handlers exercise the
    /// production lookup path.
    pub fn state_with_proxies(named: Vec<(&str, Arc<dyn Proxy>)>) -> Arc<super::AppState> {
        use super::*;
        let mut proxies = std::collections::HashMap::new();
        for (name, proxy) in named {
            proxies.insert(smol_str::SmolStr::from(name), proxy);
        }

        let resolver = Arc::new(Resolver::new(
            vec!["8.8.8.8:53".parse().unwrap()],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        tunnel.update_proxies(proxies, Default::default());

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
        std::mem::forget(dir);

        Arc::new(AppState {
            tunnel,
            secret: None,
            config_path: Some(config_path),
            raw_config: Arc::new(RwLock::new(test_raw_config())),
            log_tx: tokio::sync::broadcast::channel(16).0,
            proxy_providers: Arc::new(DashMap::new()),
            provider_dialer_registry: Default::default(),
            ntp_reconcile: None,
            rule_providers: Arc::new(RwLock::new(HashMap::new())),
            rule_provider_refresh: Default::default(),
            proxy_provider_refresh: Default::default(),
            listeners: vec![],
            external_ui: None,
            traffic_feed: Default::default(),
            dns_server: Default::default(),
            ui_storage: Default::default(),
            listener_gate: None,
            cors: Default::default(),
        })
    }

    /// Build a fallback group that owns the given members. Caller keeps the
    /// member Arcs alive via the returned Vec.
    pub fn fallback_group(name: &str, members: Vec<Arc<dyn Proxy>>) -> Arc<dyn Proxy> {
        Arc::new(meow_proxy::FallbackGroup::new(name, members))
    }

    /// Build a url-test group. Used by E5 to verify the delay probe does not
    /// trigger reselection.
    pub fn url_test_group(name: &str, members: Vec<Arc<dyn Proxy>>) -> Arc<dyn Proxy> {
        Arc::new(meow_proxy::UrlTestGroup::new(name, members, 150))
    }

    /// Same as `state_with_proxies` but configures the auth middleware with a
    /// bearer secret so the delay endpoints can be exercised under the gated
    /// subrouter.
    pub fn state_with_proxies_and_secret(
        named: Vec<(&str, Arc<dyn Proxy>)>,
        secret: &str,
    ) -> Arc<super::AppState> {
        use super::*;
        let mut proxies = std::collections::HashMap::new();
        for (name, proxy) in named {
            proxies.insert(smol_str::SmolStr::from(name), proxy);
        }

        let resolver = Arc::new(Resolver::new(
            vec!["8.8.8.8:53".parse().unwrap()],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        tunnel.update_proxies(proxies, Default::default());

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
        std::mem::forget(dir);

        Arc::new(AppState {
            tunnel,
            secret: Some(secret.to_string()),
            config_path: Some(config_path),
            raw_config: Arc::new(RwLock::new(test_raw_config())),
            log_tx: tokio::sync::broadcast::channel(16).0,
            proxy_providers: Arc::new(DashMap::new()),
            provider_dialer_registry: Default::default(),
            ntp_reconcile: None,
            rule_providers: Arc::new(RwLock::new(HashMap::new())),
            rule_provider_refresh: Default::default(),
            proxy_provider_refresh: Default::default(),
            listeners: vec![],
            external_ui: None,
            traffic_feed: Default::default(),
            dns_server: Default::default(),
            ui_storage: Default::default(),
            listener_gate: None,
            cors: Default::default(),
        })
    }
}

use delay_support::{
    fallback_group, state_with_proxies, state_with_proxies_and_secret, url_test_group,
    DialBehavior, TestAdapter,
};

fn url_q() -> &'static str {
    "http://www.gstatic.com/generate_204"
}

async fn delay_req(app: axum::Router, path: String) -> axum::response::Response {
    app.oneshot(Request::get(path).body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap()
}

// ── A: single-proxy happy path ───────────────────────────────────────

#[tokio::test]
async fn a1_get_proxy_delay_ok_records_delay() {
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(Arc::clone(&state));
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    let delay = body["delay"].as_u64().unwrap();
    assert!(delay > 0, "delay must be positive, got {delay}");
    assert_eq!(body.as_object().unwrap().len(), 1, "only the delay key");
    // Verify recorded into history
    let route = state.tunnel.route_snapshot();
    let proxies = &route.proxies;
    let proxy = proxies.get("T").unwrap();
    assert_eq!(proxy.delay_history().len(), 1);
}

// ── B: single-proxy error surface ────────────────────────────────────

/// Error-surface table for the single-proxy delay endpoint: every case shares
/// the same `TestAdapter`/state setup and differs only in the request path and
/// the expected status/body. Cases are labelled and all of them run even when
/// an earlier one fails.
#[tokio::test]
async fn b_series_delay_error_table() {
    struct Case {
        label: &'static str,
        path: String,
        expected_status: StatusCode,
        expected_body: Option<&'static [u8]>,
    }

    let cases = vec![
        Case {
            label: "b1 missing url is 400 Body invalid",
            path: "/proxies/T/delay?timeout=1000".to_string(),
            expected_status: StatusCode::BAD_REQUEST,
            expected_body: Some(br#"{"message":"Body invalid"}"#),
        },
        Case {
            label: "b2 missing timeout is 400 Body invalid",
            path: format!("/proxies/T/delay?url={}", url_q()),
            expected_status: StatusCode::BAD_REQUEST,
            expected_body: Some(br#"{"message":"Body invalid"}"#),
        },
        Case {
            label: "b3 timeout too large is 400 Body invalid",
            path: format!("/proxies/T/delay?url={}&timeout=100000", url_q()),
            expected_status: StatusCode::BAD_REQUEST,
            expected_body: Some(br#"{"message":"Body invalid"}"#),
        },
        Case {
            label: "b4 timeout zero is 400",
            path: format!("/proxies/T/delay?url={}&timeout=0", url_q()),
            expected_status: StatusCode::BAD_REQUEST,
            expected_body: None,
        },
        Case {
            label: "b5 unknown proxy is 404 resource not found",
            path: format!("/proxies/NOPE/delay?url={}&timeout=1000", url_q()),
            expected_status: StatusCode::NOT_FOUND,
            expected_body: Some(br#"{"message":"resource not found"}"#),
        },
    ];

    let mut failures: Vec<String> = Vec::new();
    for case in cases {
        let adapter = TestAdapter::new(
            "T",
            DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
        )
        .into_proxy();
        let state = state_with_proxies(vec![("T", adapter)]);
        let app = create_router(state);
        let resp = delay_req(app, case.path.clone()).await;
        let status = resp.status();
        if status != case.expected_status {
            failures.push(format!(
                "[{}] GET {}: expected status {}, got {status}",
                case.label, case.path, case.expected_status
            ));
        }
        if let Some(expected_body) = case.expected_body {
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            if &bytes[..] != expected_body {
                failures.push(format!(
                    "[{}] GET {}: expected body {}, got {}",
                    case.label,
                    case.path,
                    String::from_utf8_lossy(expected_body),
                    String::from_utf8_lossy(&bytes)
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "delay error-surface cases failed:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn b6_immediate_error_is_503() {
    let adapter = TestAdapter::new("T", DialBehavior::ImmediateError).into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        br#"{"message":"An error occurred in the delay test"}"#
    );
}

#[tokio::test]
async fn b7_dial_exceeds_timeout_is_504() {
    // Post-M1.G-2b: `url_test` now distinguishes `UrlTestError::Timeout` from
    // transport errors, so a dial that overshoots the probe budget surfaces
    // as 504 "Timeout" — matching upstream `hub/route/proxies.go::getProxyDelay`
    // which renders `ErrRequestTimeout` → `http.StatusGatewayTimeout`.
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(500)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/proxies/T/delay?url={}&timeout=50", url_q())).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], br#"{"message":"Timeout"}"#);
}

// ── D: group happy path ──────────────────────────────────────────────

#[tokio::test]
async fn d1_group_delay_ok_all_members_reported() {
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let b = TestAdapter::new(
        "B",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let c = TestAdapter::new(
        "C",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a), Arc::clone(&b), Arc::clone(&c)]);
    let state = state_with_proxies(vec![("A", a), ("B", b), ("C", c), ("G", group)]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    let obj = body.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    for k in ["A", "B", "C"] {
        let v = obj.get(k).and_then(serde_json::Value::as_u64).unwrap();
        assert!(v > 0, "member {k} should have positive delay");
    }
}

#[tokio::test]
async fn d2_d3_group_delay_404_table() {
    // (case_label, target_name, expect_body_check)
    //
    // `non_group` (was d2): upstream findProxyByName rejects a *known*
    // non-group name with 404 for the group route — `group.members()` is
    // None. Body message is asserted exactly, as the original d2 did.
    // `unknown_group` (was d3): the name is absent from the proxies map
    // entirely. These are two distinct 404 branches in `get_group_delay`;
    // both must stay covered.
    let cases: [(&str, &str, bool); 2] =
        [("non_group", "A", true), ("unknown_group", "NOPE", false)];

    for (case_label, target_name, expect_body_check) in cases {
        let a = TestAdapter::new("A", DialBehavior::InstantOk).into_proxy();
        let state = state_with_proxies(vec![("A", a)]);
        let app = create_router(state);
        let resp = delay_req(
            app,
            format!("/group/{target_name}/delay?url={}&timeout=1000", url_q()),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "case {case_label}: expected 404"
        );
        if expect_body_check {
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                &bytes[..],
                br#"{"message":"resource not found"}"#,
                "case {case_label}: unexpected error body"
            );
        }
    }
}

#[tokio::test]
async fn d4_group_delay_timeout_hits_504() {
    // Every member sleeps past the group-wide deadline → 504 Timeout.
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(500)),
    )
    .into_proxy();
    let b = TestAdapter::new(
        "B",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(500)),
    )
    .into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a), Arc::clone(&b)]);
    let state = state_with_proxies(vec![("A", a), ("B", b), ("G", group)]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=50", url_q())).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], br#"{"message":"Timeout"}"#);
}

#[tokio::test]
async fn d5_group_delay_records_into_each_member_history() {
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let b = TestAdapter::new(
        "B",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a), Arc::clone(&b)]);
    let state = state_with_proxies(vec![
        ("A", Arc::clone(&a)),
        ("B", Arc::clone(&b)),
        ("G", group),
    ]);
    let app = create_router(state);
    let _ = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(a.delay_history().len(), 1);
    assert_eq!(b.delay_history().len(), 1);
}

/// Issue #543 item 1: `use:` / `include-all` members live in the group's
/// provider slots, not in the proxies map. The endpoint used to resolve
/// `members()` names through the map, so those members were silently
/// dropped from the probe and the response.
#[tokio::test]
async fn d6_group_delay_reports_provider_slot_members() {
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let p = TestAdapter::new(
        "P",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let slot: meow_common::ProviderSlot = Arc::new(RwLock::new(vec![Arc::clone(&p)]));
    let group: Arc<dyn Proxy> = Arc::new(meow_proxy::FallbackGroup::new_with_providers(
        "G",
        vec![Arc::clone(&a)],
        vec![slot],
    ));
    // `P` is deliberately absent from the registry, like a provider node.
    let state = state_with_proxies(vec![("A", Arc::clone(&a)), ("G", group)]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    let obj = body.as_object().unwrap();
    assert_eq!(obj.len(), 2, "static and provider members both reported");
    for k in ["A", "P"] {
        let v = obj.get(k).and_then(serde_json::Value::as_u64).unwrap();
        assert!(v > 0, "member {k} should have positive delay");
    }
    assert_eq!(a.delay_history().len(), 1);
    assert_eq!(
        p.delay_history().len(),
        1,
        "provider-slot member must be probed (issue #543)"
    );
}

/// A member whose probe fails is left out of the answer, which stays a 200
/// as long as another member passed: a transport error and a status
/// outside `expected` both count as failing. Their failures still land in
/// their histories.
#[tokio::test]
async fn d7_group_delay_leaves_out_failed_members() {
    let ok = TestAdapter::new("ok", DialBehavior::InstantOk).into_proxy();
    let refused = TestAdapter::new("refused", DialBehavior::ImmediateError).into_proxy();
    let bad_status =
        TestAdapter::new("bad-status", DialBehavior::InstantStatus(500, "Oops")).into_proxy();
    let group = fallback_group(
        "G",
        vec![
            Arc::clone(&ok),
            Arc::clone(&refused),
            Arc::clone(&bad_status),
        ],
    );
    let state = state_with_proxies(vec![
        ("ok", Arc::clone(&ok)),
        ("refused", Arc::clone(&refused)),
        ("bad-status", Arc::clone(&bad_status)),
        ("G", group),
    ]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    let obj = body.as_object().unwrap();
    assert_eq!(
        obj.keys().collect::<Vec<_>>(),
        ["ok"],
        "only the member that passed is reported: {body}"
    );
    assert!(obj["ok"].as_u64().unwrap() >= 1);
    for (label, failed) in [("refused", &refused), ("bad-status", &bad_status)] {
        let history = failed.delay_history();
        assert_eq!(history.len(), 1, "{label}: failure recorded");
        assert_eq!(history[0].delay, 0, "{label}: recorded as down");
    }
}

/// The batch shares one deadline: a member still probing when it passes is
/// left out, and the members that passed before it are the answer.
#[tokio::test]
async fn d8_group_delay_at_the_deadline_reports_the_members_that_passed() {
    let fast = TestAdapter::new(
        "fast",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let slow = TestAdapter::new(
        "slow",
        DialBehavior::SleepThenOk(std::time::Duration::from_secs(5)),
    )
    .into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&fast), Arc::clone(&slow)]);
    let state = state_with_proxies(vec![("fast", fast), ("slow", slow), ("G", group)]);
    let app = create_router(state);
    let start = std::time::Instant::now();
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=200", url_q())).await;
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    let obj = body.as_object().unwrap();
    assert_eq!(
        obj.keys().collect::<Vec<_>>(),
        ["fast"],
        "the member still probing at the deadline is left out: {body}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "the answer comes at the deadline, not when the slow member ends: {elapsed:?}"
    );
}

/// No member passing is the one 504, whether the members failed outright
/// or ran out of time, and an empty group has none that could.
#[tokio::test]
async fn d9_group_delay_is_504_when_no_member_passes() {
    struct Case {
        label: &'static str,
        members: Vec<(&'static str, DialBehavior)>,
        timeout_ms: u16,
    }
    let cases = [
        Case {
            label: "every member fails",
            members: vec![
                ("refused", DialBehavior::ImmediateError),
                ("bad-status", DialBehavior::InstantStatus(500, "Oops")),
            ],
            timeout_ms: 1000,
        },
        Case {
            label: "failed and timed-out members",
            members: vec![
                ("refused", DialBehavior::ImmediateError),
                (
                    "slow",
                    DialBehavior::SleepThenOk(std::time::Duration::from_secs(5)),
                ),
            ],
            timeout_ms: 100,
        },
        Case {
            label: "empty group",
            members: vec![],
            timeout_ms: 1000,
        },
    ];
    for case in cases {
        let members: Vec<(&str, Arc<dyn Proxy>)> = case
            .members
            .into_iter()
            .map(|(name, behavior)| (name, TestAdapter::new(name, behavior).into_proxy()))
            .collect();
        let group = fallback_group("G", members.iter().map(|(_, p)| Arc::clone(p)).collect());
        let mut named = members;
        named.push(("G", group));
        let app = create_router(state_with_proxies(named));
        let resp = delay_req(
            app,
            format!("/group/G/delay?url={}&timeout={}", url_q(), case.timeout_ms),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::GATEWAY_TIMEOUT,
            "{}: expected 504",
            case.label
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            &bytes[..],
            br#"{"message":"Timeout"}"#,
            "{}: unexpected body",
            case.label
        );
    }
}

// ── C: auth gating on the two new endpoints ──────────────────────────
//
// Delay endpoints live under the gated `api` subrouter; these cases lock
// that wiring in so a future refactor can't accidentally expose them.

#[tokio::test]
async fn c1_get_proxy_delay_missing_auth_401() {
    let adapter = TestAdapter::new("T", DialBehavior::InstantOk).into_proxy();
    let state = state_with_proxies_and_secret(vec![("T", adapter)], "hunter2");
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn c2_get_proxy_delay_wrong_auth_401() {
    let adapter = TestAdapter::new("T", DialBehavior::InstantOk).into_proxy();
    let state = state_with_proxies_and_secret(vec![("T", adapter)], "hunter2");
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get(format!("/proxies/T/delay?url={}&timeout=1000", url_q()))
                .header("authorization", "Bearer wrong")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn c3_get_proxy_delay_correct_auth_200() {
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let state = state_with_proxies_and_secret(vec![("T", adapter)], "hunter2");
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get(format!("/proxies/T/delay?url={}&timeout=1000", url_q()))
                .header("authorization", "Bearer hunter2")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn c4_get_group_delay_missing_auth_401() {
    let a = TestAdapter::new("A", DialBehavior::InstantOk).into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a)]);
    let state = state_with_proxies_and_secret(vec![("A", a), ("G", group)], "hunter2");
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── E: group endpoint — concurrency and timeout semantics ────────────
//
// The batch shares one deadline, as in mihomo. Members that passed by
// then make up the answer; a failed member, or one still probing, is left
// out (no `0` entries), and the endpoint is a 504 only when none passed.
// E3 of docs/specs/api-delay-endpoints-test-plan.md is d8; E4 is d4.
//
// Memory note on timing: tokio::time::pause() virtualises tokio::sleep
// and tokio::time::timeout, but `url_test` uses std::time::Instant which
// is real wall time. Using pause() would collapse measured delays to ~0
// regardless of adapter behaviour. So these tests use real wall time with
// generous slack per feedback_tokio_pause_syscalls.md.

#[tokio::test]
async fn e1_group_delay_dials_all_members_concurrently() {
    // 5 members, each sleeps 100ms. If dispatched in parallel the 5 dial
    // starts must cluster within a narrow window; serial dispatch would
    // space them ~100ms apart.
    let mut starts_vec = Vec::new();
    let mut members: Vec<Arc<dyn meow_common::Proxy>> = Vec::new();
    let mut named: Vec<(&'static str, Arc<dyn meow_common::Proxy>)> = Vec::new();
    let names = ["A", "B", "C", "D", "E"];
    for n in names {
        let adapter = TestAdapter::new(
            n,
            DialBehavior::SleepThenOk(std::time::Duration::from_millis(100)),
        );
        let starts = Arc::clone(&adapter.dial_starts);
        starts_vec.push(starts);
        let p = adapter.into_proxy();
        members.push(Arc::clone(&p));
        named.push((n, p));
    }
    let group = fallback_group("G", members);
    named.push(("G", group));
    let state = state_with_proxies(named);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let mut first_starts: Vec<std::time::Instant> = starts_vec
        .iter()
        .map(|s| *s.lock().unwrap().first().expect("each member dialed once"))
        .collect();
    first_starts.sort();
    let spread = first_starts
        .last()
        .unwrap()
        .duration_since(*first_starts.first().unwrap());
    // 50ms slack is comfortably under the 100ms per-member sleep floor that
    // serial dispatch would produce, and well above any realistic scheduler
    // jitter on CI.
    assert!(
        spread < std::time::Duration::from_millis(50),
        "dial starts should be concurrent, spread was {spread:?}"
    );
}

#[tokio::test]
async fn e1b_group_delay_limits_large_group_inflight_probes() {
    // 17 members with the production group limit of 16. The first 16 may
    // start immediately, but the final member must wait for an earlier probe
    // to finish instead of creating an unbounded burst.
    let mut starts_vec = Vec::new();
    let mut members: Vec<Arc<dyn meow_common::Proxy>> = Vec::new();
    let mut named: Vec<(&str, Arc<dyn meow_common::Proxy>)> = Vec::new();
    let names: Vec<String> = (0..17).map(|i| format!("P{i:02}")).collect();

    for name in &names {
        let adapter = TestAdapter::new(
            name,
            DialBehavior::SleepThenOk(std::time::Duration::from_millis(120)),
        );
        starts_vec.push(Arc::clone(&adapter.dial_starts));
        let p = adapter.into_proxy();
        members.push(Arc::clone(&p));
        named.push((name.as_str(), p));
    }

    let group = fallback_group("G", members);
    named.push(("G", group));
    let state = state_with_proxies(named);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let mut first_starts: Vec<std::time::Instant> = starts_vec
        .iter()
        .map(|s| *s.lock().unwrap().first().expect("each member dialed once"))
        .collect();
    first_starts.sort();
    let spread = first_starts
        .last()
        .unwrap()
        .duration_since(*first_starts.first().unwrap());
    assert!(
        spread >= std::time::Duration::from_millis(80),
        "17th dial should wait behind the 16-probe group limit, spread was {spread:?}"
    );
}

#[tokio::test]
async fn e2_group_delay_total_walltime_bounded_by_timeout() {
    // 3 instant-ok members with a generous budget; total wall time should
    // be well under 100ms. Guards against accidental serial dispatch (which
    // would still be fast here, but guards the floor).
    let a = TestAdapter::new("A", DialBehavior::InstantOk).into_proxy();
    let b = TestAdapter::new("B", DialBehavior::InstantOk).into_proxy();
    let c = TestAdapter::new("C", DialBehavior::InstantOk).into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a), Arc::clone(&b), Arc::clone(&c)]);
    let state = state_with_proxies(vec![("A", a), ("B", b), ("C", c), ("G", group)]);
    let app = create_router(state);
    let start = std::time::Instant::now();
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        elapsed < std::time::Duration::from_millis(200),
        "group probe with 3 instant members should finish fast, took {elapsed:?}"
    );
}

#[tokio::test]
async fn e5_group_delay_url_test_no_reselection() {
    // UrlTestGroup::current() is driven by pick_for_dial(), which is
    // called only from its own dial_tcp — not from the delay endpoint
    // (which walks members directly). Probing the group must NOT change
    // `current`, even if a later member would win a reselection. Locks in
    // the spec's "records, does not reselect" contract.
    // upstream: hub/route/proxies.go::getGroupDelay — it calls
    // group.URLTest which writes history but does not flip `selected`.
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(50)),
    )
    .into_proxy();
    let b = TestAdapter::new(
        "B",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let group = url_test_group("G", vec![Arc::clone(&a), Arc::clone(&b)]);
    assert_eq!(group.current().as_deref(), Some("A"));
    let state = state_with_proxies(vec![("A", a), ("B", b), ("G", Arc::clone(&group))]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        group.current().as_deref(),
        Some("A"),
        "delay probe must not trigger UrlTestGroup reselection"
    );
}

// ── G: routing and mounting ──────────────────────────────────────────

#[tokio::test]
async fn g1_get_proxy_delay_route_is_under_proxies_tree() {
    // Regression guard: the handler must be reachable at /proxies/:name/delay,
    // NOT under /api/proxies/... (which was the wrong tree in an early draft).
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "correct tree must 200");
}

#[tokio::test]
async fn g2_get_group_delay_route_is_singular_group_not_groups() {
    // Upstream mihomo uses singular `/group/:name/delay`, NOT `/groups/...`.
    // Dashboards expect this exact path — matching it byte-for-byte is the
    // whole point of this feature.
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a)]);
    let state = state_with_proxies(vec![("A", a), ("G", group)]);
    let app = create_router(state);
    // Singular form reaches the handler.
    let resp_ok = delay_req(
        app.clone(),
        format!("/group/G/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp_ok.status(), StatusCode::OK);
    // Plural form must 404 (route not mounted).
    let resp_miss = delay_req(app, format!("/groups/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp_miss.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn g3_get_proxy_delay_url_encoded_name() {
    // Axum path decodes %20 → space before matching. Proxy name with a space
    // must round-trip.
    let adapter = TestAdapter::new(
        "my proxy",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("my proxy", adapter)]);
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/my%20proxy/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── H: M1.G-2b (task #29) url_test HTTP-GET upgrade ──────────────────
//
// These cover the probe-quality half of M1.G-2. The test `CannedConn`
// responds with a configurable HTTP/1.1 status line, so we can drive the
// `expected`-param path and the "bad status → 503" contract without a
// real socket. Upstream: `hub/route/proxies.go::getProxyDelay` + the
// `httpHealthCheck` helper in `component/proxydialer/http.go`.

#[tokio::test]
async fn h_series_expected_status_table() {
    // Merge of h1..h4: identical setup (one `TestAdapter` whose canned HTTP
    // response carries a configurable status line, probed via
    // `/proxies/T/delay`), varying only the canned status, the `expected`
    // query param, and the resulting HTTP status / body. Every case is
    // labelled and every case runs even if an earlier one fails, so a single
    // run reports all mismatches.
    struct Case {
        label: &'static str,
        canned_status: u16,
        canned_reason: &'static str,
        expected_param: Option<&'static str>,
        want_http: StatusCode,
        want_body: Option<&'static [u8]>,
    }

    const ERR_BODY: &[u8] = br#"{"message":"An error occurred in the delay test"}"#;

    let cases = [
        Case {
            // h1: no `expected` query param; response is 204 -> success.
            label: "h1_default_expected_accepts_2xx",
            canned_status: 204,
            canned_reason: "No Content",
            expected_param: None,
            want_http: StatusCode::OK,
            want_body: None,
        },
        Case {
            // h2: 500 -> default expected (2xx) misses -> transport error -> 503.
            label: "h2_default_expected_rejects_non_2xx",
            canned_status: 500,
            canned_reason: "Server Error",
            expected_param: None,
            want_http: StatusCode::SERVICE_UNAVAILABLE,
            want_body: Some(ERR_BODY),
        },
        Case {
            // h3: 301 is outside 2xx but within the explicit range the caller
            // asked for.
            label: "h3_expected_range_accepts_member",
            canned_status: 301,
            canned_reason: "Moved",
            expected_param: Some("200,301-399"),
            want_http: StatusCode::OK,
            want_body: None,
        },
        Case {
            // h4: 204 is inside 2xx but the caller restricted to 200 exactly.
            label: "h4_expected_range_rejects_out_of_range",
            canned_status: 204,
            canned_reason: "No Content",
            expected_param: Some("200"),
            want_http: StatusCode::SERVICE_UNAVAILABLE,
            want_body: None,
        },
    ];

    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        let adapter = TestAdapter::new(
            "T",
            DialBehavior::InstantStatus(case.canned_status, case.canned_reason),
        )
        .into_proxy();
        let state = state_with_proxies(vec![("T", adapter)]);
        let app = create_router(state);
        let path = match case.expected_param {
            Some(expected) => format!(
                "/proxies/T/delay?url={}&timeout=1000&expected={expected}",
                url_q()
            ),
            None => format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
        };
        let resp = delay_req(app, path).await;
        let got_http = resp.status();
        if got_http != case.want_http {
            failures.push(format!(
                "[{}] status: want {}, got {got_http}",
                case.label, case.want_http
            ));
        }
        if let Some(want_body) = case.want_body {
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            if &bytes[..] != want_body {
                failures.push(format!(
                    "[{}] body: want {:?}, got {:?}",
                    case.label,
                    String::from_utf8_lossy(want_body),
                    String::from_utf8_lossy(&bytes)
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "delay `expected` cases failed:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn h5_group_member_bad_status_is_left_out() {
    // A group member whose HTTP response is 500 is missing from the map,
    // next to a successful member: a per-member failure is neither a
    // top-level error nor a `0` entry, as in mihomo.
    let good = TestAdapter::new("good", DialBehavior::InstantOk).into_proxy();
    let bad = TestAdapter::new("bad", DialBehavior::InstantStatus(500, "Oops")).into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&good), Arc::clone(&bad)]);
    let state = state_with_proxies(vec![("good", good), ("bad", bad), ("G", group)]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body.get("bad").is_none(), "failed member left out: {body}");
    assert!(body["good"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn h6_sleep_then_transport_error_is_503() {
    // Dial takes a real-but-bounded amount of time and then errors — tests
    // that a transport failure which does NOT overshoot the probe budget
    // still produces 503, not 504. Distinguishes the two error axes now
    // that `url_test` classifies them separately (M1.G-2b contract).
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenError(std::time::Duration::from_millis(20)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        br#"{"message":"An error occurred in the delay test"}"#
    );
}

// ── Chain health: GET /proxies/{name}/chain-health ───────────────────

struct ChainHealthFixture {
    state: Arc<AppState>,
    /// The proxies a check dials.
    probed: Vec<Arc<dyn Proxy>>,
    front: Arc<dyn Proxy>,
}

/// `daniel`, a chained outbound at `snell.example.com:8443`, and the front
/// group `third-fast`: `HK` carries it, `SG` refuses its port, `JP` is
/// down, `Auto` is a group, and `daniel` is a member too.
fn chain_health_fixture() -> ChainHealthFixture {
    let daniel = TestAdapter::new("daniel", DialBehavior::InstantOk)
        .at("snell.example.com:8443")
        .relaying()
        .into_proxy();
    let hk = TestAdapter::new("HK", DialBehavior::InstantOk)
        .at("10.0.0.1:443")
        .into_proxy();
    let sg = TestAdapter::new("SG", DialBehavior::RefusesPort(8443))
        .at("10.0.0.2:443")
        .into_proxy();
    let jp = TestAdapter::new("JP", DialBehavior::ImmediateError)
        .at("10.0.0.3:443")
        .into_proxy();
    let auto = url_test_group("Auto", vec![Arc::clone(&hk)]);
    let hy2 = TestAdapter::new("hy2", DialBehavior::InstantOk)
        .at("hy2.example.com:8443")
        .into_proxy();
    let direct = TestAdapter::new("direct", DialBehavior::InstantOk).into_proxy();
    let front = fallback_group(
        "third-fast",
        vec![
            Arc::clone(&hk),
            Arc::clone(&sg),
            Arc::clone(&jp),
            Arc::clone(&auto),
            Arc::clone(&daniel),
        ],
    );
    let probed = vec![Arc::clone(&daniel), Arc::clone(&hk), Arc::clone(&sg)];
    let state = state_with_proxies(vec![
        ("daniel", daniel),
        ("HK", hk),
        ("SG", sg),
        ("JP", jp),
        ("Auto", auto),
        ("hy2", hy2),
        ("direct", direct),
        ("third-fast", Arc::clone(&front)),
    ]);
    ChainHealthFixture {
        state,
        probed,
        front,
    }
}

fn chain_health_path(name: &str, dialer: &str) -> String {
    format!(
        "/proxies/{name}/chain-health?dialer={dialer}&url={}&timeout=1000",
        url_q()
    )
}

/// Each member of the front group gets a verdict, in the group's order,
/// and nothing is recorded: no delay, no chain verdict.
#[tokio::test]
async fn chain_health_gives_each_member_a_verdict() {
    let ChainHealthFixture {
        state,
        probed,
        front,
    } = chain_health_fixture();
    let app = create_router(Arc::clone(&state));
    let resp = delay_req(app, chain_health_path("daniel", "third-fast")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = body_json(resp).await;
    // Delays vary; each that is there must be positive.
    for member in body["members"].as_array_mut().unwrap() {
        for key in ["delay", "member-delay"] {
            if let Some(delay) = member.get_mut(key) {
                assert!(delay.as_u64().unwrap() > 0, "{key}: {delay}");
                *delay = serde_json::json!(1);
            }
        }
    }
    assert_eq!(
        body,
        serde_json::json!({
            "proxy": "daniel",
            "server": "snell.example.com:8443",
            "dialer": "third-fast",
            "members": [
                {"name": "HK", "verdict": "reached", "delay": 1, "member-delay": 1},
                {"name": "SG", "verdict": "failed", "member-delay": 1,
                 "reason": "connection refused"},
                {"name": "JP", "verdict": "down", "reason": "connection failed"},
                {"name": "Auto", "verdict": "skipped", "reason": "a group"},
                {"name": "daniel", "verdict": "skipped", "reason": "the proxy itself"},
            ],
        })
    );
    for proxy in probed {
        assert!(proxy.delay_history().is_empty(), "{}", proxy.name());
    }
    assert!(front.chain_health().unwrap().targets().is_empty());
}

/// A single proxy serves as the dialer too.
#[tokio::test]
async fn chain_health_takes_a_single_proxy_as_the_dialer() {
    let state = chain_health_fixture().state;
    let resp = delay_req(create_router(state), chain_health_path("daniel", "SG")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["dialer"], "SG");
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    // With no member reaching the server, SG's failure is not its own.
    assert_eq!(members[0]["verdict"], "inconclusive");
}

#[tokio::test]
async fn chain_health_refuses_what_it_cannot_probe() {
    struct Case {
        path: String,
        status: StatusCode,
        message: &'static str,
    }
    let case = |path: String, status, message| Case {
        path,
        status,
        message,
    };
    let cases = [
        case(
            format!("/proxies/daniel/chain-health?url={}&timeout=1000", url_q()),
            StatusCode::BAD_REQUEST,
            "Body invalid",
        ),
        case(
            "/proxies/daniel/chain-health?dialer=HK&timeout=1000".into(),
            StatusCode::BAD_REQUEST,
            "Body invalid",
        ),
        case(
            chain_health_path("nope", "HK"),
            StatusCode::NOT_FOUND,
            "no proxy named 'nope'",
        ),
        case(
            chain_health_path("daniel", "nope"),
            StatusCode::NOT_FOUND,
            "no proxy or group named 'nope'",
        ),
        case(
            chain_health_path("third-fast", "HK"),
            StatusCode::BAD_REQUEST,
            "'third-fast' is a group; name one of its proxies",
        ),
        case(
            chain_health_path("direct", "HK"),
            StatusCode::BAD_REQUEST,
            "'direct' has no server to dial through 'HK'",
        ),
        case(
            chain_health_path("hy2", "HK"),
            StatusCode::UNPROCESSABLE_ENTITY,
            "'hy2' cannot run over another proxy's stream, so it cannot be chained",
        ),
    ];
    let state = chain_health_fixture().state;
    let mut failures = Vec::new();
    for case in cases {
        let resp = delay_req(create_router(Arc::clone(&state)), case.path.clone()).await;
        let status = resp.status();
        let body = body_json(resp).await;
        if status != case.status || body["message"] != case.message {
            failures.push(format!("{}: {status} {body}", case.path));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn chain_health_needs_the_secret() {
    let daniel = TestAdapter::new("daniel", DialBehavior::InstantOk)
        .at("snell.example.com:8443")
        .relaying()
        .into_proxy();
    let state = state_with_proxies_and_secret(vec![("daniel", daniel)], "hunter2");
    let resp = delay_req(create_router(state), chain_health_path("daniel", "DIRECT")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Connection management tests ──────────────────────────────────

/// DELETE /connections/{id} removes the named connection and returns 204.
/// `GET /connections/{id}` serves a connection's notes while it is live and,
/// because notes are on, after it closes; the list keeps its shape.
#[tokio::test]
async fn get_connection_by_id_returns_notes_live_and_after_close() {
    use meow_common::{ConnType, Metadata, Network};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let state = test_state_default();
    let rule =
        meow_rules::parse_rule("MATCH,DIRECT", &meow_rules::ParserContext::default()).unwrap();
    state.tunnel.update_routing(
        HashMap::new(),
        vec![rule],
        HashMap::new(),
        Default::default(),
    );
    state.tunnel.set_connection_notes(true);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            socket.write_all(&buf[..n]).await.unwrap();
        }
    });
    let meta = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        dst_ip: Some(server.ip()),
        dst_port: server.port(),
        ..Default::default()
    };
    let (mut client, mut inbound) = tokio::io::duplex(1024);
    let inner = Arc::clone(state.tunnel.inner());
    let flow = tokio::spawn(async move {
        meow_tunnel::route_inbound_tcp(&inner, &mut inbound, meta, &[]).await;
    });
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.unwrap();

    let get = |uri: String| {
        let app = create_router(Arc::clone(&state));
        async move {
            app.oneshot(Request::get(uri).body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap()
        }
    };

    let json = body_json(get("/connections".into()).await).await;
    let conns = json["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1);
    assert!(conns[0].get("notes").is_none(), "{conns:?}");
    let id = conns[0]["id"].as_str().unwrap().to_owned();

    let resp = get(format!("/connections/{id}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let live = body_json(resp).await;
    assert_eq!(live["id"], id.as_str());
    assert_eq!(live["closed"], false);
    assert!(live.get("end").is_none());
    let texts = |detail: &serde_json::Value| -> Vec<String> {
        detail["notes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|note| note["text"].as_str().unwrap().to_owned())
            .collect()
    };
    let notes = texts(&live);
    assert!(
        notes.contains(&"Matched rule #1 MATCH → DIRECT".to_owned()),
        "{notes:?}"
    );
    assert!(
        notes.iter().any(|note| note.starts_with("Connected in ")),
        "{notes:?}"
    );
    assert_eq!(live["notes"][0]["kind"], "connection");

    drop(client);
    flow.await.unwrap();

    let resp = get(format!("/connections/{id}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let closed = body_json(resp).await;
    assert_eq!(closed["closed"], true);
    assert!(closed["end"].is_string());
    assert_eq!(closed["upload"], 4);
    assert_eq!(closed["download"], 4);
    let notes = texts(&closed);
    assert_eq!(notes.last().unwrap(), "Closed: 4 B up, 4 B down");

    let resp = get(format!("/connections/{}", uuid::Uuid::new_v4())).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = get("/connections/not-a-uuid".into()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_connection_by_id_returns_204_and_removes_entry() {
    use meow_common::{ConnType, Metadata, Network};
    let state = test_state_default();

    // Inject a synthetic connection directly via the statistics layer so the
    // test does not require a live proxy dial.
    let meta = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        host: "example.com".into(),
        dst_port: 80,
        ..Default::default()
    };
    let conn_id = state.tunnel.statistics().track_connection(
        meta,
        smol_str::SmolStr::new_static("DOMAIN"),
        smol_str::SmolStr::new_static("example.com"),
        smallvec![Arc::from("DIRECT")],
    );

    // Verify the connection shows up in GET /connections.
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let conns = json["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0]["id"], conn_id.to_string());

    // DELETE the specific connection.
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/connections/{conn_id}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Confirm it is gone.
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert!(json["connections"].as_array().unwrap().is_empty());
}

/// DELETE /connections (no path param) closes every active connection.
#[tokio::test]
async fn delete_all_connections_clears_all() {
    use meow_common::{ConnType, Metadata, Network};
    let state = test_state_default();

    let stats = state.tunnel.statistics();
    let meta = || Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        host: "a.test".into(),
        dst_port: 80,
        ..Default::default()
    };
    stats.track_connection(
        meta(),
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::default(),
        smallvec![Arc::from("DIRECT")],
    );
    stats.track_connection(
        meta(),
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::default(),
        smallvec![Arc::from("DIRECT")],
    );

    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert!(json["connections"].as_array().unwrap().is_empty());
}

// ── DNS query endpoint tests ─────────────────────────────────────

/// Build a test state whose resolver has a hosts-trie entry for
/// `test.local → 192.0.2.1` so DNS query tests get a deterministic answer
/// without touching the network.
fn test_state_with_hosts_entry() -> Arc<AppState> {
    use std::net::IpAddr;
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
    hosts.insert("test.local", vec![ip].into());

    let resolver = Arc::new(Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        hosts,
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let mut raw = test_raw_config();
    raw.dns = Some(serde_saphyr::from_str("enable: true").unwrap());
    let meow_config::RebuildResult {
        proxies,
        rules,
        sub_rules,
        ..
    } = meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies, Default::default());
    tunnel.update_rules_with_sub_rules(rules, sub_rules);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    std::mem::forget(dir);

    Arc::new(AppState {
        tunnel,
        secret: None,
        config_path: Some(config_path),
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        proxy_providers: Arc::new(DashMap::new()),
        provider_dialer_registry: Default::default(),
        ntp_reconcile: None,
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        rule_provider_refresh: Default::default(),
        proxy_provider_refresh: Default::default(),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
        dns_server: Default::default(),
        ui_storage: Default::default(),
        listener_gate: None,
        cors: Default::default(),
    })
}

/// POST /dns/query resolves a hosts-trie entry and returns the IP in the
/// `answer` field.
#[tokio::test]
async fn post_dns_query_returns_known_host() {
    let state = test_state_with_hosts_entry();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/query")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"test.local"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "test.local");
    assert_eq!(json["answer"], "192.0.2.1");
}

/// POST /dns/query for an unknown name returns `answer: null`.
#[tokio::test]
async fn post_dns_query_unknown_name_returns_null_answer() {
    // Keep this no-answer case upstream-free: intercepted DNS can synthesize
    // an address even for .invalid.
    let state = test_state_with_hosts_entry();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/query")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"no-such-host.invalid"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "no-such-host.invalid");
    assert!(json["answer"].is_null());
}

/// GET /dns/query?name=test.local resolves via the hosts trie.
#[tokio::test]
async fn get_dns_query_returns_known_host() {
    let state = test_state_with_hosts_entry();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/dns/query?name=test.local")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["Status"], 0);
    assert_eq!(json["Question"][0]["Name"], "test.local.");
    assert_eq!(json["Answer"][0]["data"], "192.0.2.1");
}

/// GET /dns/query with a non-address `type` relays the upstream `Message`
/// — response code, flags, and all three record sections — instead of
/// answering from the address-only A/AAAA pipeline (#632).
#[tokio::test]
async fn get_dns_query_txt_relays_upstream_sections_and_flags() {
    use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::TXT;
    use hickory_proto::rr::{Name, RData, Record};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

    // Loopback upstream answering the TXT query with an answer, an
    // authority SOA, and an additional glue record, so all three
    // relayed sections are observable.
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
        let request = Message::from_bytes(&buf[..len]).unwrap();
        // The API must forward the FQDN form of the queried name.
        assert_eq!(
            request.queries[0].name.to_utf8(),
            "api.test.",
            "upstream must see the fqdn-built Name"
        );
        let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        response.add_queries(request.queries.iter().cloned());
        response.metadata.response_code = ResponseCode::NoError;
        response.metadata.authentic_data = true;
        response.metadata.recursion_available = true;
        response.add_answer(Record::from_rdata(
            Name::from_ascii("api.test.").unwrap(),
            60,
            RData::TXT(TXT::new(vec!["api-relay".to_string()])),
        ));
        response.add_authority(Record::from_rdata(
            Name::from_ascii("api.test.").unwrap(),
            300,
            RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_ascii("ns.api.test.").unwrap(),
                Name::from_ascii("hostmaster.api.test.").unwrap(),
                7,
                7200,
                3600,
                1209600,
                300,
            )),
        ));
        response.add_additional(Record::from_rdata(
            Name::from_ascii("ns.api.test.").unwrap(),
            60,
            RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 99)),
        ));
        upstream
            .send_to(&response.to_bytes().unwrap(), peer)
            .await
            .unwrap();
    });

    let resolver = Arc::new(Resolver::new(
        vec![upstream_addr],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let mut raw = test_raw_config();
    raw.dns = Some(serde_saphyr::from_str("enable: true").unwrap());
    let meow_config::RebuildResult {
        proxies,
        rules,
        sub_rules,
        ..
    } = meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies, Default::default());
    tunnel.update_rules_with_sub_rules(rules, sub_rules);
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    std::mem::forget(dir);
    let state = Arc::new(AppState {
        tunnel,
        secret: None,
        config_path: Some(config_path),
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        proxy_providers: Arc::new(DashMap::new()),
        provider_dialer_registry: Default::default(),
        ntp_reconcile: None,
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        rule_provider_refresh: Default::default(),
        proxy_provider_refresh: Default::default(),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
        dns_server: Default::default(),
        ui_storage: Default::default(),
        listener_gate: None,
        cors: Default::default(),
    });

    let resp = create_router(state)
        .oneshot(
            Request::get("/dns/query?name=api.test&type=TXT")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["Status"], 0, "upstream NOERROR relayed");
    assert_eq!(json["RA"], true, "upstream flag relayed");
    // `forward_generic` returns the upstream Message verbatim — the AD
    // gate lives on the wire path (`handle_generic_forward`), so the API
    // presents the upstream's AD as-is.
    assert_eq!(json["AD"], true, "upstream AD relayed");
    assert_eq!(json["Question"][0]["Name"], "api.test.");
    assert_eq!(json["Question"][0]["Qtype"], 16);
    assert_eq!(json["Answer"][0]["data"], "api-relay");
    assert_eq!(json["Answer"][0]["TTL"], 60);
    assert_eq!(
        json["Authority"][0]["type"], 6,
        "the authority section relays too, not just answers"
    );
    assert_eq!(
        json["Additional"][0]["data"], "192.0.2.99",
        "the additional section relays too, not just answers"
    );
}

/// GET /dns/query with a non-address `type` and no reachable upstream
/// returns 500 — `forward_generic` yields `None` when every nameserver
/// pool is empty. An empty-nameserver resolver short-circuits
/// instantly; no timeout wait is needed.
#[tokio::test]
async fn get_dns_query_txt_without_upstream_returns_500() {
    // `test_state_default` deliberately points at 8.8.8.8 — use a
    // state whose resolver has NO nameservers instead.
    let state = test_state_with_hosts_entry();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/dns/query?name=test.local&type=TXT")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = body_json(resp).await;
    assert_eq!(json["message"], "DNS query failed");
}

// ── DNS cache flush ───────────────────────────────────────────────

/// POST /cache/dns/flush returns 204.
#[tokio::test]
async fn flush_dns_cache_returns_no_content() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/cache/dns/flush")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ── Prometheus metrics ────────────────────────────────────────────

/// GET /metrics returns Prometheus text exposition format.
/// Checks: correct content-type prefix and presence of the traffic counter
/// and active-connections gauge metric names.
#[tokio::test]
async fn get_metrics_returns_prometheus_text() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/metrics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Content-type must start with text/plain (Prometheus scrape requirement).
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/plain"),
        "unexpected content-type: {ct}"
    );

    let body = body_string(resp).await;
    assert!(
        body.contains("meow_traffic_bytes"),
        "missing meow_traffic_bytes in metrics output"
    );
    assert!(
        body.contains("meow_connections_active"),
        "missing meow_connections_active in metrics output"
    );
}

/// GET /connections serialises entries with the documented camelCase shape
/// (id/upload/download/start/chains/rule/rulePayload). Guards the
/// borrow-based `ActiveConnectionsView` serialize path (audit M8), which
/// replaced the per-entry `serde_json::json!` tree.
#[tokio::test]
async fn get_connections_entry_has_camel_case_shape() {
    use meow_common::{ConnType, Metadata, Network};
    let state = test_state_default();

    let meta = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        host: "example.com".into(),
        dst_port: 80,
        ..Default::default()
    };
    let conn_id = state.tunnel.statistics().track_connection(
        meta,
        smol_str::SmolStr::new_static("DOMAIN"),
        smol_str::SmolStr::new_static("example.com"),
        smallvec![Arc::from("DIRECT")],
    );

    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let conn = &json["connections"].as_array().unwrap()[0];

    assert_eq!(conn["id"], conn_id.to_string());
    assert_eq!(conn["rule"], "DOMAIN");
    assert_eq!(conn["rulePayload"], "example.com", "must stay camelCase");
    assert_eq!(conn["chains"], serde_json::json!(["DIRECT"]));
    assert_eq!(conn["upload"], 0);
    assert_eq!(conn["download"], 0);
    assert!(conn["start"].is_string());
    // issue #241: metadata is now serialised (mihomo-compatible) so panels can
    // render `host:port` as the connection title instead of the rule type.
    let metadata = conn.get("metadata").expect("metadata is serialised");
    assert_eq!(metadata["host"], "example.com");
    assert_eq!(metadata["destinationPort"], 80);
    assert_eq!(metadata["network"], "tcp");
    assert_eq!(metadata["type"], "Http");
    assert!(
        conn.get("rule_payload").is_none(),
        "snake_case key must not appear"
    );
}

/// `ConnType::WireGuard` serialises as `"wireguard"` in `/connections`
/// `metadata.type` — errata U4 pins the lowercase spelling even though
/// the other conn types keep their CamelCase variant names.
#[tokio::test]
async fn get_connections_wireguard_metadata_type() {
    use meow_common::{ConnType, Metadata, Network};
    let state = test_state_default();

    let meta = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::WireGuard,
        host: "10.0.0.2".into(),
        dst_port: 443,
        ..Default::default()
    };
    state.tunnel.statistics().track_connection(
        meta,
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::default(),
        smallvec![Arc::from("DIRECT")],
    );

    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let conn = &json["connections"].as_array().unwrap()[0];
    assert_eq!(conn["metadata"]["type"], "wireguard");
    assert_eq!(conn["metadata"]["network"], "tcp");
}

/// `metadata.dscp` is always a number in `/connections`, as mihomo panels
/// read it: `0` for a flow whose inbound saw no DSCP (every listener but
/// TProxy), the value otherwise.
#[tokio::test]
async fn get_connections_metadata_always_carries_dscp() {
    use meow_common::Metadata;
    let state = test_state_default();
    let stats = state.tunnel.statistics();
    let track = |host: &str, dscp| {
        stats.track_connection(
            Metadata {
                host: host.into(),
                dst_port: 443,
                dscp,
                ..Default::default()
            },
            smol_str::SmolStr::new_static("MATCH"),
            smol_str::SmolStr::default(),
            smallvec![Arc::from("DIRECT")],
        )
    };
    let unmarked = track("unmarked.example", None);
    let marked = track("marked.example", Some(46));

    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let dscp_of = |id: uuid::Uuid| {
        json["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|conn| conn["id"] == id.to_string())
            .map(|conn| conn["metadata"]["dscp"].clone())
            .expect("connection listed")
    };
    assert_eq!(dscp_of(unmarked), serde_json::json!(0), "no DSCP is 0");
    assert_eq!(dscp_of(marked), serde_json::json!(46));
}

/// `format` in `GET /providers/rules` is mihomo's name for the format a
/// provider's rules come in (`YamlRule` / `TextRule` / `MrsRule`), which
/// panels switch on: the declared `format:` in any case, `YamlRule` when
/// none is declared, and `MrsRule` for an MRS payload whatever was
/// declared, since the bytes decide how it parses.
#[tokio::test]
async fn rule_provider_format_uses_mihomo_names() {
    use meow_config::raw::RawRuleProvider;
    use meow_rules::mrs_parser::{write_ruleset_mrs, TYPE_DOMAIN};

    let dir = tempfile::tempdir().unwrap();
    let yaml = dir.path().join("rules.yaml");
    std::fs::write(&yaml, "payload:\n  - '+.example.com'\n").unwrap();
    let text = dir.path().join("rules.txt");
    std::fs::write(&text, "+.example.com\n").unwrap();
    let mrs = dir.path().join("rules.mrs");
    std::fs::write(
        &mrs,
        write_ruleset_mrs(TYPE_DOMAIN, &["example.com"]).unwrap(),
    )
    .unwrap();
    let file = |path: &std::path::Path, format: Option<&str>| RawRuleProvider {
        provider_type: "file".into(),
        behavior: "domain".into(),
        format: format.map(Into::into),
        url: None,
        path: Some(path.to_string_lossy().into_owned()),
        interval: None,
        proxy: None,
        header: None,
        payload: None,
        extra: Default::default(),
    };
    let cases = [
        ("yaml", file(&yaml, Some("yaml")), "YamlRule"),
        ("text", file(&text, Some("text")), "TextRule"),
        ("mrs", file(&mrs, Some("mrs")), "MrsRule"),
        ("absent", file(&yaml, None), "YamlRule"),
        ("upper-case", file(&text, Some("TEXT")), "TextRule"),
        ("mixed-case", file(&mrs, Some("Mrs")), "MrsRule"),
        ("mrs-undeclared", file(&mrs, None), "MrsRule"),
        (
            "inline",
            RawRuleProvider {
                provider_type: "inline".into(),
                path: None,
                payload: Some(vec!["+.example.com".into()]),
                ..file(&yaml, None)
            },
            "YamlRule",
        ),
    ];
    let raw: HashMap<String, RawRuleProvider> = cases
        .iter()
        .map(|(name, cfg, _)| ((*name).to_string(), cfg.clone()))
        .collect();
    let providers = meow_config::rule_provider::load_providers(
        &raw,
        Some(dir.path()),
        &meow_rules::ParserContext::default(),
        None,
        true,
    )
    .expect("every provider loads");
    let state = test_state_default();
    *state.rule_providers.write() = providers;

    let get = |uri: String| {
        create_router(Arc::clone(&state))
            .oneshot(Request::get(uri).body(axum::body::Body::empty()).unwrap())
    };
    let list = body_json(get("/providers/rules".into()).await.unwrap()).await;
    for (name, _, expected) in &cases {
        assert_eq!(
            list["providers"][*name]["format"], *expected,
            "list: {name}"
        );
        let one = body_json(get(format!("/providers/rules/{name}")).await.unwrap()).await;
        assert_eq!(one["format"], *expected, "one: {name}");
    }
}

// Exercise actual sockets: an empty statistics map alone cannot prove closure.
async fn live_connection(
    state: &Arc<AppState>,
) -> (
    tokio::net::TcpStream,
    tokio::net::TcpStream,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dst = upstream.local_addr().unwrap();
    let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(inbound.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = inbound.accept().await.unwrap();
    let inner = Arc::clone(state.tunnel.inner());
    let task = tokio::spawn(async move {
        meow_tunnel::tcp::handle_tcp(
            &inner,
            Box::new(server),
            meow_common::Metadata {
                dst_ip: Some(dst.ip()),
                dst_port: dst.port(),
                ..Default::default()
            },
        )
        .await;
    });
    let (mut remote, _) = upstream.accept().await.unwrap();
    client.write_all(b"before close").await.unwrap();
    let mut buf = [0; 12];
    remote.read_exact(&mut buf).await.unwrap();
    remote.write_all(&buf).await.unwrap();
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"before close");
    (client, remote, task)
}

async fn assert_socket_closed(stream: &mut tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut [0; 1]))
        .await
        .expect("connection still open after close request");
    match result {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("expected EOF or RST, got {other:?}"),
    }
}

#[tokio::test]
async fn delete_connection_terminates_only_selected_stream() {
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let (mut client, mut remote, task) = live_connection(&state).await;
    let id = state.tunnel.statistics().active_connections()[0].id;
    let (mut survivor, mut survivor_remote, survivor_task) = live_connection(&state).await;
    let response = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/connections/{id}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_socket_closed(&mut client).await;
    assert_socket_closed(&mut remote).await;
    task.await.unwrap();
    assert_eq!(state.tunnel.statistics().active_connection_count(), 1);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    survivor.write_all(b"ok").await.unwrap();
    let mut buf = [0; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        survivor_remote.read_exact(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buf, b"ok");
    state.tunnel.statistics().close_all_connections();
    survivor_task.await.unwrap();
}

#[tokio::test]
async fn delete_all_connections_terminates_both_stream_directions() {
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let mut streams = Vec::new();
    for _ in 0..2 {
        streams.push(live_connection(&state).await);
    }
    let response = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    for (mut client, mut remote, task) in streams {
        assert_socket_closed(&mut client).await;
        assert_socket_closed(&mut remote).await;
        task.await.unwrap();
    }
    assert_eq!(state.tunnel.statistics().active_connection_count(), 0);
}

#[tokio::test]
async fn cold_reload_terminates_live_stream_without_drain_delay() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let (mut client, mut remote, task) = live_connection(&state).await;
    use base64::Engine as _;
    let payload =
        base64::engine::general_purpose::STANDARD.encode("mode: rule\nrules:\n  - MATCH,REJECT\n");
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        ),
    )
    .await
    .expect("cold reload must not wait for live connections to finish")
    .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_socket_closed(&mut client).await;
    assert_socket_closed(&mut remote).await;
    task.await.unwrap();
    let metadata = meow_common::Metadata {
        dst_ip: Some("127.0.0.1".parse().unwrap()),
        dst_port: 12345,
        ..Default::default()
    };
    let ResolvedTarget {
        adapter: proxy,
        route: _route,
        ..
    } = state.tunnel.inner().resolve_proxy(&metadata).await.unwrap();
    assert_eq!(
        proxy.name(),
        "REJECT",
        "new connections must see the reloaded policy"
    );
}

/// Force the real routing/DNS await to straddle two completed PUT requests.
/// Before #510, this flow registers only after close_all and dials DIRECT
/// using the old IP-CIDR rule, even though the active policy is now REJECT.
#[tokio::test]
async fn cold_reload_rejects_tcp_setup_waiting_for_dns() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    use hickory_proto::{
        op::Message,
        rr::{rdata::A, RData, Record, RecordType},
    };
    use meow_common::{Metadata, Network};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::{timeout, Duration};

    timeout(Duration::from_secs(5), async {
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut state = test_state(RawConfig {
            rules: Some(vec![
                "IP-CIDR,127.0.0.0/8,DIRECT".into(),
                "MATCH,REJECT".into(),
            ]),
            ..Default::default()
        });
        let raw = state.raw_config.read().clone();
        let tunnel = Tunnel::new(Arc::new(Resolver::new(
            vec![dns.local_addr().unwrap()],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            false,
        )));
        let meow_config::RebuildResult {
            proxies,
            rules,
            sub_rules,
            ..
        } = meow_config::rebuild_from_raw(&raw).unwrap();
        tunnel.update_proxies(proxies, Default::default());
        tunnel.update_rules_with_sub_rules(rules, sub_rules);
        Arc::get_mut(&mut state).unwrap().tunnel = tunnel;

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = origin.local_addr().unwrap();
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = inbound.accept().await.unwrap();
        let inner = Arc::clone(state.tunnel.inner());
        let task = tokio::spawn(async move {
            meow_tunnel::tcp::handle_tcp(
                &inner,
                Box::new(server),
                Metadata {
                    host: "reload.test".into(),
                    dst_port: destination.port(),
                    network: Network::Tcp,
                    ..Default::default()
                },
            )
            .await;
        });

        let mut packet = [0; 512];
        let (len, peer) = dns.recv_from(&mut packet).await.unwrap();
        let query = Message::from_vec(&packet[..len]).unwrap();
        assert_eq!(query.queries[0].query_type, RecordType::A);
        assert_eq!(state.tunnel.statistics().active_connection_count(), 0);
        let payload = base64::engine::general_purpose::STANDARD
            .encode("mode: rule\nrules:\n  - MATCH,REJECT\n");
        for _ in 0..2 {
            let response = create_router(Arc::clone(&state))
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/configs")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            serde_json::json!({"payload": payload}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        let mut response = Message::response(query.metadata.id, query.metadata.op_code);
        response.metadata.recursion_desired = true;
        response.metadata.recursion_available = true;
        response
            .add_queries(query.queries.iter().cloned())
            .add_answer(Record::from_rdata(
                query.queries[0].name.clone(),
                60,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
        dns.send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();

        tokio::select! {
            biased;
            _ = origin.accept() => panic!("old-policy TCP setup escaped reload and dialed DIRECT"),
            result = task => result.unwrap(),
        }
        assert_socket_closed(&mut client).await;
        assert_eq!(state.tunnel.statistics().active_connection_count(), 0);
        // A new real connection observes REJECT, rather than being blocked
        // by a forgotten admission flag or using the previous DIRECT rule.
        let mut fresh_client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let (fresh_server, _) = inbound.accept().await.unwrap();
        let metadata = Metadata {
            dst_ip: Some(destination.ip()),
            dst_port: destination.port(),
            network: Network::Tcp,
            ..Default::default()
        };
        let ResolvedTarget {
            adapter: proxy,
            route: _route,
            ..
        } = state.tunnel.inner().resolve_proxy(&metadata).await.unwrap();
        assert_eq!(proxy.name(), "REJECT");
        let inner = Arc::clone(state.tunnel.inner());
        let fresh_task = tokio::spawn(async move {
            meow_tunnel::tcp::handle_tcp(&inner, Box::new(fresh_server), metadata).await;
        });
        tokio::select! {
            biased;
            _ = origin.accept() => panic!("new TCP setup used the old DIRECT policy"),
            () = assert_socket_closed(&mut fresh_client) => {},
        }
        // REJECT supplies a read EOF; close the upload half too before
        // waiting for the bidirectional relay task to finish.
        drop(fresh_client);
        fresh_task.await.unwrap();
    })
    .await
    .expect("DNS-delayed setup escaped cold reload or admission did not recover");
}

/// Issue #514: `PUT /configs` must swap the running DNS resolver, not just
/// persist the new `dns:` section. Before the fix the resolver was fixed at
/// `Tunnel::new`, so the tunnel, the built-in DIRECT adapter, and the
/// host-resolver hook all kept the startup generation forever.
#[tokio::test]
async fn put_configs_swaps_running_dns_resolver() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let old_resolver = state.tunnel.resolver();
    assert!(
        old_resolver.fake_ip_v4_net().is_none(),
        "stub resolver has no fake-ip pool"
    );

    // New config: dns enabled + fake-ip mode — the dns section differs.
    let payload = base64::engine::general_purpose::STANDARD.encode(
        "mode: rule\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver:\n    - 127.0.0.1\nrules:\n  - MATCH,DIRECT\n",
    );
    let response = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let new_resolver = state.tunnel.resolver();
    assert!(
        !std::sync::Arc::ptr_eq(&new_resolver, &old_resolver),
        "resolver generation must be swapped"
    );
    assert!(
        new_resolver.fake_ip_v4_net().is_some(),
        "new resolver must have a fake-ip pool"
    );

    // The route map's DIRECT adapter must track the swap too — it shares
    // the tunnel's resolver slot, so a hostname dial allocates a fake-IP
    // entry in the *new* generation's pool (the dial itself fails: the
    // allocated 198.18.x.x address is unroutable).
    let direct = state
        .tunnel
        .route_snapshot()
        .proxies
        .get("DIRECT")
        .cloned()
        .expect("map has DIRECT");
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        direct.dial_tcp(&meow_common::Metadata {
            host: "probe.invalid".into(),
            dst_port: 80,
            ..Default::default()
        }),
    )
    .await;
    assert!(
        new_resolver.fake_ip_active_for("probe.invalid"),
        "map DIRECT must resolve through the hot-swapped resolver generation"
    );

    // Restore a dns-free config so the process-global host-resolver hook
    // installed above does not leak into other tests in this binary.
    let restore =
        base64::engine::general_purpose::STANDARD.encode("mode: rule\nrules:\n  - MATCH,DIRECT\n");
    let restore_resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": restore}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        restore_resp.status(),
        StatusCode::NO_CONTENT,
        "restore PUT must succeed so the host-resolver hook is cleared"
    );
}

#[tokio::test]
async fn put_configs_requires_restart_to_change_the_controller_secret() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;

    let state = test_state_with_secret("startup-override");
    state.raw_config.write().secret = Some("original-yaml-value".into());
    let app = create_router(Arc::clone(&state));

    for (uri, candidate, status) in [
        (
            "/configs?force=true",
            "mode: global\nsecret: new-yaml-value\n",
            StatusCode::BAD_REQUEST,
        ),
        ("/configs", "mode: global\n", StatusCode::BAD_REQUEST),
        (
            "/configs",
            "mode: direct\nsecret: original-yaml-value\n",
            StatusCode::NO_CONTENT,
        ),
    ] {
        let payload = base64::engine::general_purpose::STANDARD.encode(candidate);
        let response = app
            .clone()
            .oneshot(
                Request::put(uri)
                    .header("authorization", "Bearer startup-override")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "payload": payload }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        if status == StatusCode::BAD_REQUEST {
            assert_eq!(
                body_json(response).await["message"],
                "changing the controller secret requires a restart"
            );
            assert_eq!(state.raw_config.read().mode.as_deref(), Some("rule"));
        }
        assert_eq!(
            state.raw_config.read().secret.as_deref(),
            Some("original-yaml-value")
        );
    }
    assert_eq!(state.raw_config.read().mode.as_deref(), Some("direct"));
}

/// A `PUT /configs` parse failure surfaces the tree error through the 400
/// body: `{"message": "config parse error: line N column M: port: invalid
/// u16"}`. The `line`/`column` prefix plus the dotted field path are the
/// contract `-t` shares with the API, but only `yaml_tree`'s own tests
/// asserted them — this pins the cross-crate body so a regression in the
/// location/path plumbing shows up at the HTTP boundary.
#[tokio::test]
async fn put_configs_parse_error_reports_line_column_and_path() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let payload = base64::engine::general_purpose::STANDARD
        .encode("mode: rule\nport: abc\nrules:\n  - MATCH,DIRECT\n");
    let response = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    let message = json["message"]
        .as_str()
        .expect("a parse failure must carry a message");
    assert!(
        message.contains("config parse error"),
        "expected the parse-error prefix, got: {message}"
    );
    assert!(
        message.contains("line 2 column 7"),
        "expected the value node's line/column, got: {message}"
    );
    assert!(
        message.contains("port: invalid u16"),
        "expected the field path and typed message, got: {message}"
    );
}

/// Issue #561: a `PUT /configs` whose `proxy-groups:` declares a duplicate
/// name hits the declaration-level check — 400 and neither the committed
/// raw config nor the route table changes. `?force=true` cannot push it
/// through either: the check is unconditional, so the lenient retry fails
/// identically and force lands in the "persist the raw, keep the previous
/// routing" branch (204 with the old map retained).
#[tokio::test]
async fn put_configs_duplicate_group_names_rejected() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let yaml = concat!(
        "mode: rule\n",
        "proxy-groups:\n",
        "  - name: dup\n",
        "    type: select\n",
        "    proxies: [DIRECT]\n",
        "  - name: dup\n",
        "    type: select\n",
        "    proxies: [REJECT]\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);

    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("duplicate name")),
        "the 400 must come from the duplicate-group check, got: {body}"
    );
    assert!(
        state.raw_config.read().proxy_groups.is_none(),
        "a rejected PUT must not commit the raw config"
    );
    assert!(
        !state.tunnel.route_snapshot().proxies.contains_key("dup"),
        "a rejected PUT must not touch the route table"
    );

    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs?force=true")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        !state.tunnel.route_snapshot().proxies.contains_key("dup"),
        "force keeps the previous routing when the candidate cannot build"
    );
    assert!(
        state
            .raw_config
            .read()
            .proxy_groups
            .as_ref()
            .is_some_and(|g| g.len() == 2),
        "the force contract still persists the raw config"
    );
}

/// Issue #640: a `PUT /configs` document that keeps a subscription by
/// name+URL but omits its `applied-*` bookkeeping fields must carry the
/// tracking forward — otherwise the next refresh treats the tracked
/// nodes as local and they can never be removed. Entries whose URL
/// changed start with empty tracking (different feed, different
/// contribution).
#[tokio::test]
async fn put_configs_carries_subscription_tracking_forward() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    let mut node = std::collections::HashMap::new();
    node.insert(
        "name".to_string(),
        serde_json::Value::String("node-1".into()),
    );
    node.insert("type".to_string(), serde_json::Value::String("http".into()));
    node.insert(
        "server".to_string(),
        serde_json::Value::String("127.0.0.1".into()),
    );
    node.insert("port".to_string(), serde_json::Value::from(9));
    raw.proxies = Some(vec![node]);
    raw.subscriptions = Some(vec![
        RawSubscription {
            name: "s".into(),
            url: "https://a.example.com/".into(),
            interval: None,
            last_updated: None,
            proxy: None,
            applied_proxies: vec!["node-1".into()],
            applied_groups: Vec::new(),
            applied_rules: Vec::new(),
            extra: Default::default(),
        },
        RawSubscription {
            name: "t".into(),
            url: "https://t.example.com/".into(),
            interval: None,
            last_updated: None,
            proxy: None,
            applied_proxies: vec!["t-node".into()],
            applied_groups: Vec::new(),
            applied_rules: Vec::new(),
            extra: Default::default(),
        },
    ]);
    let state = test_state(raw);

    // Same name+URL for `s` but no applied-* fields; `t` keeps its name
    // but changes URL — its tracking must NOT carry over.
    let yaml = concat!(
        "mode: rule\n",
        "proxies:\n",
        "  - { name: node-1, type: http, server: 127.0.0.1, port: 9 }\n",
        "subscriptions:\n",
        "  - { name: s, url: \"https://a.example.com/\" }\n",
        "  - { name: t, url: \"https://new-t.example.com/\" }\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let subs = raw.subscriptions.as_ref().unwrap();
    let s = subs.iter().find(|x| x.name == "s").unwrap();
    assert_eq!(
        s.applied_proxies,
        vec!["node-1".to_string()],
        "kept name+URL must inherit the live tracking set"
    );
    let t = subs.iter().find(|x| x.name == "t").unwrap();
    assert!(
        t.applied_proxies.is_empty(),
        "a changed URL must not inherit the old feed's tracking"
    );
}

/// Issue #562: a `PUT /configs` whose `proxy-groups:` declares a cycle
/// hits the declaration-level DFS — 400 and neither the committed raw
/// config nor the route table changes. `?force=true` cannot push it
/// through either: the check is unconditional, so the lenient retry
/// fails identically and force lands in the "persist the raw, keep the
/// previous routing" branch (204 with the old map retained).
#[tokio::test]
async fn put_configs_group_cycle_rejected() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let yaml = concat!(
        "mode: rule\n",
        "proxy-groups:\n",
        "  - name: A\n",
        "    type: select\n",
        "    proxies: [B, DIRECT]\n",
        "  - name: B\n",
        "    type: select\n",
        "    proxies: [A]\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);

    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("proxy-group cycle detected")),
        "the 400 must come from the cycle check, got: {body}"
    );
    assert!(
        state.raw_config.read().proxy_groups.is_none(),
        "a rejected PUT must not commit the raw config"
    );
    assert!(
        !state.tunnel.route_snapshot().proxies.contains_key("A"),
        "a rejected PUT must not touch the route table"
    );

    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs?force=true")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        !state.tunnel.route_snapshot().proxies.contains_key("A"),
        "force keeps the previous routing when the candidate cannot build"
    );
    assert!(
        state
            .raw_config
            .read()
            .proxy_groups
            .as_ref()
            .is_some_and(|g| g.len() == 2),
        "the force contract still persists the raw config"
    );
}

/// A port bindable over BOTH UDP and TCP — what `DnsServer::bind` needs.
/// Windows can exclude a port per protocol (Hyper-V/WINNAT), so either
/// protocol's allocator can walk into the other's exclusion band;
/// alternate which one picks the :0 port so both allocators sample
/// independent counter positions.
fn dual_proto_port() -> u16 {
    for attempt in 0..16u32 {
        if attempt % 2 == 0 {
            let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let candidate = sock.local_addr().unwrap().port();
            if std::net::UdpSocket::bind(("127.0.0.1", candidate)).is_ok() {
                return candidate;
            }
        } else {
            let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let candidate = sock.local_addr().unwrap().port();
            if std::net::TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
                return candidate;
            }
        }
    }
    panic!("no port bindable over both UDP and TCP after 16 alternating attempts");
}

/// Issue #514 review: a `dns.listen` change whose new socket FAILS to bind
/// must keep the old listener alive — the config is already committed, and
/// dropping the only working DNS server would silently break resolution
/// until the next dns-changing PUT.
#[tokio::test]
async fn put_configs_dns_rebind_failure_keeps_old_listener() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let put = |yaml: &str| {
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
    };

    let port_a = dual_proto_port();
    let yaml_a = format!(
        "mode: rule\ndns:\n  enable: true\n  listen: 127.0.0.1:{port_a}\n  nameserver:\n    - 127.0.0.1\nrules:\n  - MATCH,DIRECT\n"
    );
    assert_eq!(put(&yaml_a).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert!(
        state
            .dns_server
            .read()
            .as_ref()
            .is_some_and(|h| h.listen.port() == port_a && !h.task.is_finished()),
        "first PUT must leave a live listener on port {port_a}"
    );

    // Occupy a second port so the next PUT's bind fails with EADDRINUSE.
    let blocker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port_b = blocker.local_addr().unwrap().port();
    let yaml_b = format!(
        "mode: rule\ndns:\n  enable: true\n  listen: 127.0.0.1:{port_b}\n  nameserver:\n    - 127.0.0.1\nrules:\n  - MATCH,DIRECT\n"
    );
    // The PUT itself still commits the config (204) — the listener simply
    // keeps the old socket rather than dying with nothing bound.
    assert_eq!(put(&yaml_b).await.unwrap().status(), StatusCode::NO_CONTENT);
    let guard = state.dns_server.read();
    let h = guard
        .as_ref()
        .expect("listener handle must survive a failed rebind");
    assert_eq!(
        h.listen.port(),
        port_a,
        "failed rebind must keep the old socket"
    );
    assert!(!h.task.is_finished(), "old listener task must stay alive");
    drop(guard);
    drop(blocker);
}

/// A `dns.listen` disable → re-enable cycle on the SAME address must
/// rebind cleanly: a retired listener's task aborts asynchronously and an
/// in-flight reply can hold the socket briefly past its death, so the
/// next plan must wait for actual socket release — task joined AND weak
/// ref dead — before binding, or the re-enable dies on EADDRINUSE
/// (Codex review).
#[tokio::test]
async fn put_configs_dns_disable_reenable_same_addr_rebinds() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let put = |yaml: &str| {
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
    };

    let port = dual_proto_port();
    let yaml_on = format!(
        "mode: rule\ndns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  nameserver:\n    - 127.0.0.1\nrules:\n  - MATCH,DIRECT\n"
    );
    assert_eq!(
        put(&yaml_on).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        state
            .dns_server
            .read()
            .as_ref()
            .is_some_and(|h| h.listen.port() == port && !h.task.is_finished()),
        "first PUT must leave a live listener on port {port}"
    );

    // Disable: the listener retires — its socket release is proven, not
    // synchronous.
    let yaml_off = "mode: rule\nrules:\n  - MATCH,DIRECT\n";
    assert_eq!(
        put(yaml_off).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        state.dns_server.read().is_none(),
        "disable must retire the listener handle"
    );

    // Re-enable on the same address: the bind must succeed over the
    // just-released socket — not race the retired one into EADDRINUSE.
    assert_eq!(
        put(&yaml_on).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let guard = state.dns_server.read();
    let h = guard
        .as_ref()
        .expect("the re-enabled listener must be bound");
    assert_eq!(h.listen.port(), port);
    assert!(
        !h.task.is_finished(),
        "the re-enabled listener must actually serve"
    );
    drop(guard);
}

/// Issue #514 review: `nameserver-policy` `rule-set:` keys must resolve
/// against the CANDIDATE's `rule-providers:` — a PUT that adds a provider
/// and references it in the same payload is valid (startup accepts it), so
/// it must not 400 against the startup-frozen provider registry.
#[tokio::test]
async fn put_configs_rule_set_policy_uses_candidate_providers() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let put = |yaml: &str| {
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
    };

    let yaml = concat!(
        "mode: rule\n",
        "dns:\n",
        "  enable: true\n",
        "  nameserver:\n",
        "    - 127.0.0.1\n",
        "  nameserver-policy:\n",
        "    rule-set:doms: 127.0.0.1\n",
        "rule-providers:\n",
        "  doms:\n",
        "    type: inline\n",
        "    behavior: domain\n",
        "    payload:\n",
        "      - '+.example.com'\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    assert_eq!(
        put(yaml).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "rule-set: policy referencing a provider declared in the same PUT must be accepted"
    );

    // The loaded providers are swapped into the live registry — otherwise
    // `PUT /providers/rules/{name}` and name-resolved refresh loops would
    // operate on orphaned startup-era objects (issue #514 review).
    assert!(
        state.rule_providers.read().contains_key("doms"),
        "commit must publish the loaded provider into the live registry"
    );

    // A MIXED key — the `rule-set:` prefix on a non-leading
    // comma-separated segment must still trigger provider loading
    // (`"+.corp.example,rule-set:doms"`).
    let yaml_mixed = concat!(
        "mode: rule\n",
        "dns:\n",
        "  enable: true\n",
        "  nameserver:\n",
        "    - 127.0.0.1\n",
        "  nameserver-policy:\n",
        "    '+.corp.example,rule-set:doms': 127.0.0.1\n",
        "rule-providers:\n",
        "  doms:\n",
        "    type: inline\n",
        "    behavior: domain\n",
        "    payload:\n",
        "      - '+.example.com'\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    assert_eq!(
        put(yaml_mixed).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "mixed key with a non-leading rule-set: segment must load providers too"
    );

    // Same policy key with NO matching provider in the candidate → 400,
    // proving resolution ran against the candidate's declarations rather
    // than any pre-existing registry.
    let yaml_missing = concat!(
        "mode: rule\n",
        "dns:\n",
        "  enable: true\n",
        "  nameserver:\n",
        "    - 127.0.0.1\n",
        "  nameserver-policy:\n",
        "    rule-set:gone: 127.0.0.1\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    assert_eq!(
        put(yaml_missing).await.unwrap().status(),
        StatusCode::BAD_REQUEST,
        "rule-set: policy referencing a provider absent from the candidate must be rejected"
    );
    // The rejected commit must not have swapped the live registry — the
    // candidate carried no providers, so a hoisted commit would silently
    // empty it (issue #533 review).
    assert!(
        state.rule_providers.read().contains_key("doms"),
        "a rejected commit must leave the live provider registry untouched"
    );
}

/// Issue #533 review: a `dns:` section whose nameservers carry `#name`
/// proxy tags must force a resolver rebuild on EVERY commit — a retained
/// resolver's captured `#name` adapters hold `Weak`s into the OLD registry
/// cell, which dies at the route swap. Two PUTs with identical `dns:` but
/// a changed rule must still swap the resolver generation.
#[tokio::test]
async fn put_configs_rebuilds_resolver_when_dns_uses_runtime_refs() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let put = |yaml: &str| {
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
    };

    let yaml = concat!(
        "mode: rule\n",
        "dns:\n",
        "  enable: true\n",
        "  nameserver:\n",
        "    - tcp://127.0.0.1:9#hop\n",
        "proxies:\n",
        "  - {name: hop, type: socks5, server: 127.0.0.1, port: 11080}\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    assert_eq!(
        put(yaml).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "config with a `#hop` nameserver must commit"
    );
    let first = state.tunnel.resolver();

    // Second commit: identical `dns:` section, a different rule. The
    // runtime `#hop` ref must still force a resolver rebuild — a retained
    // resolver would keep resolving through the registry cell that just
    // died with the route swap.
    let yaml2 = yaml.replace(
        "rules:\n  - MATCH,DIRECT\n",
        "rules:\n  - DOMAIN,example.com,DIRECT\n  - MATCH,DIRECT\n",
    );
    assert_eq!(put(&yaml2).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert!(
        !Arc::ptr_eq(&first, &state.tunnel.resolver()),
        "a `#name`-tagged dns section must force a resolver rebuild on every commit"
    );
}

/// A provider payload entry this build cannot parse must not reject the
/// candidate. The node binds a dead placeholder instead — which is what
/// closes the fall-through-to-DIRECT hole — so one unsupported entry in a
/// third-party feed, refetched on a timer, is not a daemon-wide kill switch
/// in that feed operator's hands. Credentials never reach a response.
#[tokio::test]
async fn put_configs_trusttunnel_provider_binds_a_placeholder_instead_of_rejecting() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let directory = tempfile::tempdir_in(
        std::path::Path::new(state.config_path.as_deref().unwrap())
            .parent()
            .unwrap(),
    )
    .unwrap();
    let bad_path = directory.path().join("bad.yaml");
    // `bad` lacks `username`, so every feature set rejects it: a
    // `quic: true` node alone parses under `trusttunnel-h3`, which the
    // `--all-features` coverage run enables.
    std::fs::write(&bad_path, "proxies:\n  - {name: sibling, type: direct}\n  - {name: bad, type: trusttunnel, server: vpn.example.test, port: 443, password: test-only}\n").unwrap();
    let document = format!("mode: rule\nproxy-providers:\n  p:\n    type: file\n    path: {}\nproxy-groups:\n  - name: PROXY\n    type: select\n    use: [p]\nrules: ['MATCH,PROXY']\n", bad_path.display());
    let response = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": base64::engine::general_purpose::STANDARD.encode(&document)})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(!body.contains("test-only"), "{body}");
    assert!(state.tunnel.proxy("PROXY").is_some());

    // The first acquisition is detached (an awaited download would stall the
    // `CONFIG_MUTATION` lane), so wait for the payload to land.
    let provider = Arc::clone(state.proxy_providers.get("p").unwrap().value());
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while provider.proxies().len() < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the detached acquisition must publish the fetched payload");
    let nodes = provider.proxies();
    let bad = nodes
        .iter()
        .find(|proxy| proxy.name() == "bad")
        .expect("the unparseable node keeps its slot");
    assert!(!bad.alive(), "a placeholder must never look usable");
    // Listed as the type it declared, dead — not as `Reject`, which would
    // make a misconfigured node indistinguishable from one the operator
    // rejected on purpose in every consumer of the type: this listing, the
    // tunnel's match statistics, and a group's dial-failure exemptions.
    assert_eq!(
        bad.adapter_type().to_string(),
        "TrustTunnel",
        "the placeholder must name the node's own type"
    );
    let error = bad
        .dial_tcp(&meow_common::Metadata::default())
        .await
        .err()
        .expect("a placeholder must fail the dial instead of leaking it direct")
        .to_string();
    assert!(error.contains("bad"), "{error}");
    assert!(!error.contains("test-only"), "{error}");
}

/// An unavailable TrustTunnel node must fail a UDP flow closed through rule
/// resolution, not only at `dial_udp`. The rule engine skips a UDP target
/// that does not support UDP, and an exhausted scan dials DIRECT — so a
/// placeholder that declined UDP sent the flow's UDP/QUIC out in the clear
/// while the same flow's TCP failed closed: directly under `MATCH`, and
/// through a group with nothing live to prefer over the node.
#[tokio::test]
async fn unavailable_trusttunnel_node_fails_udp_closed_through_rule_resolution() {
    // Unavailable on every build: without `--features trusttunnel` the
    // protocol is missing, and with it `fingerprint` is a TLS policy the
    // parser refuses.
    let node = "{name: TT, type: trusttunnel, server: vpn.example.test, port: 443, \
                username: fixture, password: test-only, udp: true, fingerprint: '00'}";
    for (groups, target) in [
        ("", "TT"),
        (
            "proxy-groups:\n  - {name: G, type: select, proxies: [TT]}\n",
            "G",
        ),
        (
            "proxy-groups:\n  - {name: G, type: fallback, proxies: [TT]}\n",
            "G",
        ),
        (
            "proxy-groups:\n  - {name: G, type: url-test, proxies: [TT]}\n",
            "G",
        ),
    ] {
        let yaml =
            format!("mode: rule\nproxies:\n  - {node}\n{groups}rules:\n  - MATCH,{target}\n");
        let state = test_state(meow_config::parse_raw_yaml(&yaml).unwrap());
        let metadata = meow_common::Metadata {
            host: "example.test".into(),
            dst_port: 443,
            network: meow_common::Network::Udp,
            ..Default::default()
        };
        let ResolvedTarget {
            adapter, rule_name, ..
        } = state.tunnel.inner().resolve_proxy(&metadata).await.unwrap();
        assert_eq!(
            rule_name, "Match",
            "{target}: the UDP flow was skipped past the unavailable node"
        );
        assert_eq!(adapter.name(), target);
        let error = adapter
            .dial_udp(&metadata)
            .await
            .err()
            .unwrap_or_else(|| panic!("{target}: the UDP dial must fail closed"))
            .to_string();
        assert!(error.contains("TT"), "{target}: {error}");
        assert!(!error.contains("test-only"), "{target}: {error}");
    }
}

/// PUT /configs commits must publish the rebuilt rule-provider map into the
/// live registry — previously only the DNS reconcile path wrote the
/// registry, so this PUT left `GET /providers/rules` and
/// `PUT /providers/rules/{name}` operating on startup-era objects (or
/// nothing) while the matchers referenced a detached generation (#543).
#[tokio::test]
async fn put_configs_publishes_rule_provider_registry_changes() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let put = |yaml: &str| {
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
    };

    // Add a provider with no `dns:` section — DNS inputs are unchanged, so
    // the publish can only have come from the routing rebuild.
    let yaml = concat!(
        "mode: rule\n",
        "rule-providers:\n",
        "  doms:\n",
        "    type: inline\n",
        "    behavior: domain\n",
        "    payload:\n",
        "      - '+.example.com'\n",
        "rules:\n",
        "  - RULE-SET,doms,REJECT\n",
        "  - MATCH,DIRECT\n",
    );
    assert_eq!(
        put(yaml).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "PUT adding a rule-provider must commit"
    );
    assert!(
        state.rule_providers.read().contains_key("doms"),
        "registry must publish the rebuilt provider even without a DNS change"
    );

    // `GET /providers/rules` reads the same registry — it must reflect the
    // commit, not a startup-era snapshot.
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .uri("/providers/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["providers"]["doms"].is_object(),
        "GET /providers/rules must list the committed provider: {json}"
    );

    // A failed PUT (a `dialer-proxy` referencing a missing name hard-fails
    // the rebuild) must leave the committed registry untouched.
    let bad = concat!(
        "mode: rule\n",
        "proxies:\n",
        "  - name: p\n",
        "    type: http\n",
        "    server: 127.0.0.1\n",
        "    port: 8080\n",
        "    dialer-proxy: ghost\n",
        "rules:\n",
        "  - MATCH,p\n",
    );
    assert_eq!(
        put(bad).await.unwrap().status(),
        StatusCode::BAD_REQUEST,
        "a candidate that fails validation must be rejected"
    );
    assert!(
        state.rule_providers.read().contains_key("doms"),
        "a failed PUT must not clobber the live provider registry"
    );
    assert!(
        !state
            .raw_config
            .read()
            .proxies
            .as_ref()
            .is_some_and(|p| { p.iter().any(|e| e.get("dialer-proxy").is_some()) }),
        "a failed PUT must not commit the candidate's raw either"
    );

    // Removal publishes an empty registry — and `GET` reflects it too.
    let yaml_removed = "mode: rule\nrules:\n  - MATCH,DIRECT\n";
    assert_eq!(
        put(yaml_removed).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        state.rule_providers.read().is_empty(),
        "removing the provider must clear it from the registry"
    );
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .uri("/providers/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["providers"]
            .as_object()
            .is_some_and(serde_json::Map::is_empty),
        "GET /providers/rules must show an empty registry after removal: {json}"
    );
}

/// Issue #543 — one `PUT /configs` commit must fetch each rule-provider
/// payload exactly once: the routing rebuild's prefetched bytes are shared
/// with the DNS rebuild instead of being fetched a second time inside
/// `CONFIG_MUTATION`. A counting HTTP listener makes a second fetch
/// observable. The provider has no on-disk cache to start from, so every
/// fetch hits the wire.
#[tokio::test]
async fn put_configs_fetches_rule_provider_payload_once() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let server = {
        let hits = Arc::clone(&hits);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        hits.fetch_add(1, Ordering::SeqCst);
                        // The accepted stream can inherit the listener's
                        // nonblocking flag; force blocking for read/write,
                        // with a timeout so a connect-but-silent client
                        // can't park this thread past the loop deadline.
                        stream.set_nonblocking(false).unwrap();
                        let rw_timeout = Duration::from_secs(2);
                        let _ = stream.set_read_timeout(Some(rw_timeout));
                        let _ = stream.set_write_timeout(Some(rw_timeout));
                        let mut buf = [0_u8; 2048];
                        let _ = stream.read(&mut buf);
                        let body = "payload:\n  - '+.example.com'\n";
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        })
    };

    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    // `rule-set:p` in nameserver-policy makes the DNS rebuild resolve
    // providers — the second fetch path this guards against.
    let yaml = format!(
        "mode: rule\ndns:\n  enable: true\n  nameserver:\n    - 127.0.0.1\n  nameserver-policy:\n    rule-set:p: 127.0.0.1\nrule-providers:\n  p:\n    type: http\n    behavior: domain\n    url: http://{addr}/rules.yaml\nrules:\n  - MATCH,DIRECT\n"
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "one commit must fetch the provider payload exactly once"
    );
}

/// A stand-in live TUN listener whose pending task holds a drop flag:
/// `stop_tun`'s abort drops the future, so `stopped` flips iff the
/// handle was actually reaped — a spawn-independent "was restarted"
/// probe (a *successful* respawn leaves `has_tun()` true either way,
/// so post-state alone can't distinguish a no-op from a working
/// restart under a privileged listener-tun build).
fn fake_tun_handle() -> (meow_tunnel::TunHandle, Arc<std::sync::atomic::AtomicBool>) {
    let (handle, flag) = fake_tun_handle_owned(meow_tunnel::TunOwner::TopLevel);
    (handle, flag)
}

/// [`fake_tun_handle`] with an explicit [`TunOwner`] — named-owner
/// variants pin the top-level reconcile off the slot (spec §3).
fn fake_tun_handle_owned(
    owner: meow_tunnel::TunOwner,
) -> (meow_tunnel::TunHandle, Arc<std::sync::atomic::AtomicBool>) {
    struct Flag(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = meow_tunnel::TunHandle {
        task: tokio::spawn({
            let flag = Arc::clone(&flag);
            async move {
                let _flag = Flag(flag);
                std::future::pending::<()>().await;
            }
        }),
        owner,
        core_done: None,
        udp_flows: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };
    (handle, flag)
}

/// Issue #543: a `tun:` parameter change while `enable` stays true must
/// restart the listener — previously only enable transitions (and, after
/// #544, fake-IP input changes) reconciled, so committed `mtu`/
/// `auto-route`/`dns-hijack`/address changes silently diverged from the
/// running stack.
///
/// A pending task stands in for the live listener so the restart's
/// `stop_tun` reaps a real slot; without the `listener-tun` feature
/// `spawn_tun_from_raw` then fails, which rolls `tun.enable` back — the
/// flip to `false` is observable proof the restart fired. A build *with*
/// the feature exercises the same code path against a real spawn instead
/// of this stub.
#[cfg(not(feature = "listener-tun"))]
#[tokio::test]
async fn put_configs_tun_param_change_reconciles_running_listener() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;
    assert!(state.tunnel.has_tun());

    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: true\n",
        "  mtu: 9000\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| !t.enable),
        "the param-change restart must have fired and rolled `enable` back \
         after the spawn failure — a silently ignored change would leave \
         it true"
    );
    assert!(
        stopped.load(Ordering::SeqCst),
        "the restart must reap the old listener handle"
    );
    assert!(
        !state.tunnel.has_tun(),
        "stop_tun must have reaped the listener slot, not just the flag"
    );
    // Committed-state contract: the new params persist — only `enable`
    // rolls back (routes.rs doc).
    let tun = state.raw_config.read().tun.clone().unwrap();
    assert_eq!(tun.mtu, Some(9000));
}

/// Companion invariant: a semantically identical `tun:` section must NOT
/// restart — the committed config spells `mtu: 1500` explicitly while the
/// candidate omits it (same parsed default), which the `TunConfig` diff
/// treats as unchanged.
#[tokio::test]
async fn put_configs_tun_unchanged_does_not_reconcile() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: true\n",
        "rules:\n",
        "  - MATCH,DIRECT\n"
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| t.enable),
        "an unchanged tun: section must not touch the listener"
    );
    assert!(
        !stopped.load(Ordering::SeqCst),
        "the old handle must not be reaped — spawn-independent no-restart proof"
    );
    assert!(
        state.tunnel.has_tun(),
        "the fake handle must still be running"
    );
}

/// Without `inet4-address` the device address derives from
/// `dns.fake-ip-range`, so a reload that changes only the range is a real
/// parameter change even when no fake-IP pool runs (none here: DNS is
/// off), which leaves the resolver-side restart trigger quiet.
#[cfg(not(feature = "listener-tun"))]
#[tokio::test]
async fn put_configs_fake_ip_range_change_moves_the_default_tun_address() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    let yaml = concat!(
        "mode: rule\n",
        "dns:\n",
        "  enable: false\n",
        "  fake-ip-range: 28.0.0.1/8\n",
        "tun:\n",
        "  enable: true\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        stopped.load(Ordering::SeqCst),
        "the device address moved from 198.18.0.1/30 to 28.0.0.1/30: the \
         listener must restart"
    );
    // The restart's spawn fails without the feature and rolls back.
    assert!(state
        .raw_config
        .read()
        .tun
        .as_ref()
        .is_some_and(|t| !t.enable));
}

/// A `tun:` section the listener cannot parse is rejected at admission —
/// committing it would let the reconcile restart tear down a healthy
/// listener before the spawn-side parse fails (issue #543 review).
#[tokio::test]
async fn put_configs_invalid_tun_rejected_before_commit() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    // mtu below the IPv6 floor (1280) fails `parse_tun_config`.
    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: true\n",
        "  mtu: 100\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("tun config error")),
        "the 400 must come from the tun admission check, got: {body}"
    );
    let tun = state.raw_config.read().tun.clone().unwrap();
    assert_eq!(
        (tun.enable, tun.mtu),
        (true, Some(1500)),
        "the invalid section must not have been committed"
    );
    assert!(
        !stopped.load(Ordering::SeqCst),
        "the running listener must survive untouched"
    );
    assert!(state.tunnel.has_tun(), "the running listener must survive");
}

/// Same admission contract for `sniffer:` (review #887): the TUN carries
/// the sniffer it was spawned with, so a section `spawn_tun_from_raw`
/// cannot parse must be rejected before commit — admitted unchecked, the
/// reconcile would stop a healthy listener and only then fail the
/// spawn-side parse, leaving TUN down on a 204. The `tun:` change in the
/// body is what would have fired that restart, so the still-running
/// handle proves the gate ran before the reconcile.
#[tokio::test]
async fn put_configs_invalid_sniffer_rejected_keeps_running_tun() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;
    assert!(state.tunnel.has_tun());

    // Two malformed shapes: `enable: true` with no `sniff:` map, and an
    // out-of-range `timeout` on an otherwise valid section.
    for sniffer in [
        "sniffer:\n  enable: true\n",
        "sniffer:\n  enable: true\n  timeout: 0\n  sniff:\n    TLS:\n      ports: [443]\n",
    ] {
        let yaml = format!(
            "mode: rule\ntun:\n  enable: true\n  mtu: 9000\n{sniffer}rules:\n  - MATCH,DIRECT\n"
        );
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        let resp = create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"payload": payload}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "sniffer {sniffer:?} must be rejected at admission"
        );
        let body = body_json(resp).await;
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("sniffer config error")),
            "the 400 must come from the sniffer admission check, got: {body}"
        );
    }
    let committed = state.raw_config.read();
    assert_eq!(
        committed.tun.as_ref().map(|t| t.mtu),
        Some(Some(1500)),
        "the rejected document must not have been committed"
    );
    assert!(committed.sniffer.is_none());
    drop(committed);
    assert!(
        !stopped.load(Ordering::SeqCst),
        "the running listener must survive the rejected PUT"
    );
    assert!(state.tunnel.has_tun(), "the running listener must survive");
}

/// Semantic diff (review #887): a `sniffer:` respelled with reordered or
/// duplicated ports/domains parses to the same `SnifferConfig` and must
/// NOT restart the running listener — only a real change may.
#[cfg(not(feature = "listener-tun"))]
#[tokio::test]
async fn put_configs_sniffer_respelling_does_not_reconcile() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true").unwrap());
    raw.sniffer = Some(
        serde_saphyr::from_str(
            "enable: true\nsniff:\n  TLS:\n    ports: [443, 8443]\nskip-domain: [b.example, a.example]\n",
        )
        .unwrap(),
    );
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    // Same sniffer spelled differently: port and domain order swapped,
    // duplicates added — all normalize away at parse.
    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: true\n",
        "sniffer:\n",
        "  enable: true\n",
        "  sniff:\n",
        "    TLS:\n",
        "      ports: [8443, 443, 8443]\n",
        "  skip-domain: [a.example, b.example, a.example]\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        !stopped.load(Ordering::SeqCst),
        "a semantically identical sniffer must not restart the listener"
    );
    assert!(state.tunnel.has_tun());

    // Counterpoint: a real port change restarts — under this build the
    // spawn fails and `enable` rolls back, proving the diff ran.
    let yaml = yaml.replace("ports: [8443, 443, 8443]", "ports: [443, 4430]");
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        stopped.load(Ordering::SeqCst),
        "a real sniffer diff must restart the running listener"
    );
    assert!(
        state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| !t.enable),
        "the restart's spawn failure rolls `enable` back on this build"
    );
}

/// A disabled sniffer's remaining fields are dead config — changing
/// `timeout` or the port lists while `enable: false` is not a restart-
/// worthy diff (review #887).
#[tokio::test]
async fn put_configs_disabled_sniffer_field_change_does_not_reconcile() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true").unwrap());
    raw.sniffer = Some(
        serde_saphyr::from_str("enable: false\ntimeout: 100\nsniff:\n  TLS:\n    ports: [443]\n")
            .unwrap(),
    );
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: true\n",
        "sniffer:\n",
        "  enable: false\n",
        "  timeout: 900\n",
        "  sniff:\n",
        "    TLS:\n",
        "      ports: [443, 8443]\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        !stopped.load(Ordering::SeqCst),
        "dead-field churn under `enable: false` must not restart the listener"
    );
    assert!(state.tunnel.has_tun());
    assert!(
        state
            .raw_config
            .read()
            .sniffer
            .as_ref()
            .is_some_and(|s| s.timeout == Some(900)),
        "the respelled section still commits — only the restart is skipped"
    );
}

/// Same admission contract for `listeners:` — an entry the startup parser
/// would reject must not be committed into `raw_config`, where the next
/// `load_config` would hard-error on boot (issue #564 review).
#[tokio::test]
async fn put_configs_invalid_listeners_rejected_before_commit() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());

    // `udp: true` without `firewall: false` fails `build_named_listeners`.
    let yaml = concat!(
        "mode: rule\n",
        "listeners:\n",
        "  - name: tp\n",
        "    type: tproxy\n",
        "    port: 7895\n",
        "    udp: true\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("listeners config error")),
        "the 400 must come from the listeners admission check, got: {body}"
    );
    assert!(
        state.raw_config.read().listeners.is_none(),
        "the invalid section must not have been committed"
    );
}

/// `lan-allowed-ips`/`lan-disallowed-ips` are hard admission errors even
/// under `?force=true`: a malformed CIDR or a `listeners:`-nested key is
/// a 400 that commits nothing, since persisting a broken access policy
/// would leave the next boot's guarded listeners enforcing the wrong
/// (or no) ACL. A valid PUT commits the raw fields for the next boot
/// without hot-applying anything.
#[tokio::test]
async fn put_configs_lan_acl_rejected_before_commit() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());

    for (yaml, force) in [
        ("lan-allowed-ips: [10.0.0.1]\n", ""), // bare IP, not a CIDR
        ("lan-allowed-ips: [10.0.0.1]\n", "?force=true"),
        ("lan-disallowed-ips: bogus\n", "?force=true"),
        (
            concat!(
                "lan-allowed-ips: [10.0.0.0/8]\n",
                "listeners:\n",
                "  - name: lan\n",
                "    type: http\n",
                "    port: 8081\n",
                "    lan-disallowed-ips: [10.9.0.0/16]\n", // misplaced
            ),
            "?force=true",
        ),
    ] {
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        let resp = create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/configs{force}"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"payload": payload}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{yaml} (force={force}) must be rejected"
        );
        assert!(
            state.raw_config.read().lan_allowed_ips.is_none(),
            "the rejected ACL must not have been committed"
        );
    }

    // A valid ACL commits verbatim — for the next boot only; nothing
    // about the running listeners changes.
    let yaml = "lan-allowed-ips: [10.0.0.0/8, fd00::/8]\nlan-disallowed-ips: [10.9.0.0/16]\n";
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    {
        let raw = state.raw_config.read();
        assert_eq!(
            raw.lan_allowed_ips.as_deref(),
            Some(&["10.0.0.0/8".to_string(), "fd00::/8".to_string()][..])
        );
        assert_eq!(
            raw.lan_disallowed_ips.as_deref(),
            Some(&["10.9.0.0/16".to_string()][..])
        );
    }

    // PATCH is not an ACL surface (the ACL is a startup snapshot): the
    // keys are simply not modeled by the patch schema, so this is a
    // no-op that leaves the committed document alone.
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"lan-allowed-ips": ["1.2.3.0/24"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    {
        let raw = state.raw_config.read();
        assert_eq!(
            raw.lan_allowed_ips.as_deref(),
            Some(&["10.0.0.0/8".to_string(), "fd00::/8".to_string()][..]),
            "PATCH must not touch the committed ACL"
        );
    }
}

/// mihomo spells the named SOCKS inbound `type: socks` — a full PUT must
/// admit it through the same `resolve_named_listeners` gate, store the
/// spelling verbatim, and not rebind anything (listeners stay a startup
/// snapshot). A malformed entry still 400s before commit.
#[tokio::test]
async fn put_configs_socks_listener_alias_admitted() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());

    let yaml = concat!(
        "mode: rule\n",
        "listeners:\n",
        "  - name: s\n",
        "    type: socks\n",
        "    listen: 127.0.0.1:17891\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    {
        let raw = state.raw_config.read();
        let listeners = raw.listeners.as_deref().unwrap_or(&[]);
        assert_eq!(listeners.len(), 1, "the alias must commit verbatim");
        assert_eq!(listeners[0].listener_type, "socks");
    }
    assert!(
        state.listeners.is_empty(),
        "admission must not rebind the running listeners"
    );

    // A malformed entry still 400s before commit.
    let yaml = yaml.replace("type: socks", "type: socks4");
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("unknown listener type")),
        "the 400 must name the bad listener type, got: {body}"
    );
    assert!(
        state.raw_config.read().listeners.as_deref().unwrap_or(&[])[0].listener_type == "socks",
        "the rejected PUT must not have overwritten the committed section"
    );
}

/// Same admission contract for the geo schedule: an invalid effective
/// interval (`geo-update-interval: 0`, or a nested `auto-update-interval`
/// `0` with no valid nested override) must be rejected before commit —
/// the running auto-update loop is a startup snapshot, so a committed
/// `0` would only fail the NEXT boot's `build_config`. Even `?force=true`
/// cannot push it through.
#[tokio::test]
async fn put_configs_geo_interval_rejected_before_commit() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());

    for (yaml, force) in [
        ("geo-update-interval: 0\n", ""),
        ("geo-update-interval: 0\n", "?force=true"),
        (
            "geo-update-interval: 6\ngeodata:\n  auto-update-interval: 0\n",
            "",
        ),
    ] {
        let yaml = format!("mode: rule\n{yaml}rules:\n  - MATCH,DIRECT\n");
        let payload = base64::engine::general_purpose::STANDARD.encode(&yaml);
        let resp = create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/configs{force}"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"payload": payload}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{yaml} (force={force:?}) must be rejected"
        );
        let body = body_json(resp).await;
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("update-interval")),
            "the 400 must name the interval key, got: {body}"
        );
    }

    // A valid flat schedule validates and commits — stored for the next
    // restart without replacing the running schedule (the auto-update
    // loop is a startup snapshot, so nothing here observes a reschedule).
    let yaml = concat!(
        "mode: rule\n",
        "geo-auto-update: true\n",
        "geo-update-interval: 6\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let raw = state.raw_config.read();
    assert_eq!(raw.geo_auto_update, Some(true));
    assert_eq!(raw.geo_update_interval, Some(6));
}

/// Same admission contract for `tcp-keepalive*`: values `build_config`
/// would hard-error on at boot (0 / >127 probes / over-ceiling seconds)
/// must be rejected before commit — the rebuild never sees general
/// fields, so without the gate a PUT could persist a config the next
/// `load_config` refuses.
#[tokio::test]
async fn put_configs_invalid_tcp_keepalive_rejected_before_commit() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());

    for (line, needle) in [
        ("tcp-keepalive-probes: 0\n", "tcp-keepalive-probes"),
        ("tcp-keepalive-probes: 128\n", "tcp-keepalive-probes"),
        ("tcp-keepalive-idle: 0\n", "tcp-keepalive-idle"),
        ("tcp-keepalive-interval: 0\n", "tcp-keepalive-interval"),
    ] {
        let yaml = format!("mode: rule\n{line}rules:\n  - MATCH,DIRECT\n");
        let payload = base64::engine::general_purpose::STANDARD.encode(&yaml);
        let resp = create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"payload": payload}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{line}must be rejected"
        );
        let body = body_json(resp).await;
        assert!(
            body["message"].as_str().is_some_and(|m| m.contains(needle)),
            "{line}— the 400 must name the rejected key, got: {body}"
        );
    }
    let raw = state.raw_config.read();
    assert!(
        raw.tcp_keepalive_idle.is_none()
            && raw.tcp_keepalive_interval.is_none()
            && raw.tcp_keepalive_probes.is_none(),
        "no rejected keepalive key may have been committed"
    );
}

/// Same admission contract for `tcp-idle-timeout`: a value over the
/// `Instant + Duration` ceiling `build_config` enforces must be rejected
/// before commit — the rebuild never sees general fields, so without the
/// gate a PUT could persist a config the next `load_config` refuses.
#[tokio::test]
async fn put_configs_invalid_tcp_idle_timeout_rejected_before_commit() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());

    let yaml = "mode: rule\ntcp-idle-timeout: 315360001\nrules:\n  - MATCH,DIRECT\n";
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("tcp-idle-timeout")),
        "the 400 must name the rejected key, got: {body}"
    );
    assert!(
        state.raw_config.read().tcp_idle_timeout.is_none(),
        "the rejected value must not have been committed"
    );
}

/// `tcp-idle-timeout` is the one `tcp-*` knob that IS hot-applied: a PUT
/// commits the document AND replays the resolved bound into the running
/// tunnel (`set_tcp_idle_timeout`), where `0` disables it.
#[tokio::test]
async fn put_configs_tcp_idle_timeout_hot_applies() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());

    for (line, expected) in [
        (
            "tcp-idle-timeout: 1800\n",
            Some(std::time::Duration::from_secs(1800)),
        ),
        ("tcp-idle-timeout: 0\n", None),
    ] {
        let yaml = format!("mode: rule\n{line}rules:\n  - MATCH,DIRECT\n");
        let payload = base64::engine::general_purpose::STANDARD.encode(&yaml);
        let resp = create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"payload": payload}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "{line}must commit");
        assert_eq!(
            state.tunnel.inner().tcp_idle_timeout(),
            expected,
            "{line}must replay into the running bound"
        );
    }
}

/// `?force` keeps the running bound on an invalid `tcp-idle-timeout` —
/// and rewrites the committed field to that bound. The warm-path commits
/// (`commit_raw_candidate`) re-resolve the field on every mutation, so
/// persisting the invalid value would 400 every later unrelated PATCH.
#[tokio::test]
async fn put_configs_force_tcp_idle_timeout_normalizes_commit() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    state
        .tunnel
        .set_tcp_idle_timeout(Some(std::time::Duration::from_secs(1800)));

    let yaml = "mode: rule\ntcp-idle-timeout: 315360001\nrules:\n  - MATCH,DIRECT\n";
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs?force=true")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        state.raw_config.read().tcp_idle_timeout,
        Some(1800),
        "the committed field is normalized to the running bound, not the invalid value"
    );
    assert_eq!(
        state.tunnel.inner().tcp_idle_timeout(),
        Some(std::time::Duration::from_secs(1800)),
        "the running bound is kept"
    );

    // The poison check: a warm-path mutation on the committed document
    // must succeed — the normalized value re-resolves cleanly.
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"rules":["DOMAIN-SUFFIX,example.com,DIRECT","MATCH,REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a forced commit must not poison later warm-path mutations"
    );

    // Running bound disabled → committed `Some(0)`, which re-resolves to
    // `None` — the same disabled bound an absent key resolves to, kept
    // explicit so the committed doc says what it means.
    state.tunnel.set_tcp_idle_timeout(None);
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs?force=true")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        state.raw_config.read().tcp_idle_timeout,
        Some(0),
        "a disabled running bound normalizes to explicit 0, not absent"
    );
    assert_eq!(state.tunnel.inner().tcp_idle_timeout(), None);
}

/// The force early-return arm — the rebuild failing under BOTH strict
/// and lenient modes — also commits `raw_config`; the normalize must
/// have run before it or the verbatim invalid value lands in the
/// committed document anyway (sniffer.timeout is rejected
/// unconditionally, so it fails the lenient retry too).
#[tokio::test]
async fn put_configs_force_early_return_still_normalizes_tcp_idle_timeout() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    state
        .tunnel
        .set_tcp_idle_timeout(Some(std::time::Duration::from_secs(1800)));

    let yaml = "mode: rule\ntcp-idle-timeout: 315360001\nsniffer:\n  timeout: 0\nrules:\n  - MATCH,DIRECT\n";
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs?force=true")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    {
        let committed = state.raw_config.read();
        assert_eq!(
            committed.tcp_idle_timeout,
            Some(1800),
            "the early-return arm commits the normalized field too"
        );
        // Proof the unbuildable document committed verbatim apart from
        // the normalize — i.e. the early-return arm really ran (a normal
        // commit would have rebuilt and this assertion is moot).
        assert_eq!(
            committed.sniffer.as_ref().unwrap().timeout,
            Some(0),
            "the unbuildable sniffer section still committed verbatim"
        );
    }
    assert_eq!(
        state.tunnel.inner().tcp_idle_timeout(),
        Some(std::time::Duration::from_secs(1800)),
        "the early-return arm never reapplies, so the running bound is kept"
    );
}

/// `?force` degrades the `tun:` admission check to a warn: the unparsable
/// section commits, the reconcile restart hits the spawn-side parse
/// error, and `enable` rolls back — a 204 that still tears the healthy
/// listener down (deliberate force semantics, issue #543 review).
/// Deterministic under both feature sets: `mtu: 100` fails
/// `parse_tun_config` at spawn regardless of privileges.
#[tokio::test]
async fn put_configs_force_invalid_tun_commits_and_rolls_back() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: true\n",
        "  mtu: 100\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs?force=true")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let tun = state.raw_config.read().tun.clone().unwrap();
    assert_eq!(
        (tun.enable, tun.mtu),
        (false, Some(100)),
        "the forced commit persists; only `enable` rolls back"
    );
    assert!(
        stopped.load(Ordering::SeqCst),
        "the restart must reap the old handle"
    );
    assert!(!state.tunnel.has_tun());
}

/// Top-level `max-connections` is inherited into `TunConfig`, so changing
/// it while TUN runs is a real parameter change (issue #543 review).
#[cfg(not(feature = "listener-tun"))]
#[tokio::test]
async fn put_configs_max_connections_change_reconciles_tun() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    let yaml = concat!(
        "mode: rule\n",
        "max-connections: 512\n",
        "tun:\n",
        "  enable: true\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        !state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| t.enable),
        "the max-connections restart must have fired and rolled `enable` \
         back after the spawn failure"
    );
    assert!(
        stopped.load(Ordering::SeqCst),
        "the restart must reap the old listener handle"
    );
}

/// off→on still takes the spawn arm — a fresh `enable: true` spawns; the
/// no-feature spawn failure rolls `enable` back (gated: under the feature
/// a privileged host could spawn a real device).
#[cfg(not(feature = "listener-tun"))]
#[tokio::test]
async fn put_configs_tun_enable_on_attempts_spawn() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());

    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: true\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| !t.enable),
        "off→on must spawn, and the no-feature failure must roll `enable` back"
    );
    assert!(
        !state.tunnel.has_tun(),
        "a failed spawn must leave no listener handle behind"
    );
}

/// on→off still stops the listener: dropping the `tun:` section takes the
/// stop arm. Deterministic under both feature sets — `stop_tun` needs no
/// device.
#[tokio::test]
async fn put_configs_tun_enable_off_stops_listener() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    let yaml = "mode: rule\nrules:\n  - MATCH,DIRECT\n";
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(state.raw_config.read().tun.is_none());
    assert!(
        stopped.load(Ordering::SeqCst),
        "the stop arm must reap the old listener handle"
    );
    assert!(
        !state.tunnel.has_tun(),
        "dropping the tun: section must stop the listener"
    );
}

/// A missing handle does not suppress the reconcile: enabled + a real
/// param change with no stored handle still attempts the respawn, and
/// the failure rolls `enable` back — the deliberate no-`has_tun()`-gate
/// semantics (issue #543 review).
#[cfg(not(feature = "listener-tun"))]
#[tokio::test]
async fn put_configs_tun_param_change_without_handle_rolls_back() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);

    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: true\n",
        "  mtu: 9000\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| !t.enable),
        "the respawn attempt must roll `enable` back after the spawn failure"
    );
    assert!(
        !state.tunnel.has_tun(),
        "stop_tun must have reaped the listener slot, not just the flag"
    );
}

/// `enable: false` → `enable: false` with a param change must NOT touch
/// the listener slot — `old_enable` gates the restart arm. The live fake
/// handle stands in for a listener that must not be stopped.
#[tokio::test]
async fn put_configs_tun_disabled_param_change_no_restart() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: false\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: false\n",
        "  mtu: 9000\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        !stopped.load(Ordering::SeqCst),
        "a disabled-section param change must not reap the handle"
    );
    assert!(
        state.tunnel.has_tun(),
        "a disabled-section param change must not reach the listener"
    );
}

/// The fake-IP disjunct alone still fires the restart (issue #544 trigger
/// preserved): an unchanged `tun:` section plus a `dns:` change that
/// introduces fake-ip swaps the resolver and restarts the listener.
#[cfg(not(feature = "listener-tun"))]
#[tokio::test]
async fn put_configs_tun_fake_ip_change_restarts_listener() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    let yaml = concat!(
        "mode: rule\n",
        "dns:\n",
        "  enable: true\n",
        "  enhanced-mode: fake-ip\n",
        "  nameserver:\n",
        "    - 127.0.0.1\n",
        "tun:\n",
        "  enable: true\n",
        "  mtu: 1500\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| !t.enable),
        "the fake-IP restart must have fired and rolled `enable` back"
    );
    assert!(
        stopped.load(Ordering::SeqCst),
        "the restart must reap the old listener handle"
    );
    assert!(
        !state.tunnel.has_tun(),
        "stop_tun must have reaped the listener slot, not just the flag"
    );
    assert!(state.tunnel.resolver().fake_ip_v4_net().is_some());

    // Restore a dns-free config so the process-global host-resolver hook
    // installed above does not leak into other tests in this binary.
    let restore =
        base64::engine::general_purpose::STANDARD.encode("mode: rule\nrules:\n  - MATCH,DIRECT\n");
    let restore_resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": restore}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        restore_resp.status(),
        StatusCode::NO_CONTENT,
        "restore PUT must succeed so the host-resolver hook is cleared"
    );
}

/// `PATCH /configs` with `body`, as a GUI's TUN switch sends it.
async fn patch_configs(state: &Arc<AppState>, body: serde_json::Value) -> axum::response::Response {
    create_router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn get_configs_json(state: &Arc<AppState>) -> serde_json::Value {
    let resp = create_router(Arc::clone(state))
        .oneshot(
            Request::get("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

/// A GUI's TUN switch (Clash Party, zashboard, …) sends
/// `PATCH /configs {"tun":{"enable":false}}` and never restarts the core:
/// the patch must stop the running listener, land in the committed config
/// and show in `GET /configs`, where those GUIs read the switch from.
/// Deterministic under both feature sets — `stop_tun` needs no device.
#[tokio::test]
async fn patch_configs_tun_disable_stops_listener_and_round_trips() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;
    // Let the stand-in listener start: its drop flag exists only once polled.
    tokio::task::yield_now().await;

    let before = get_configs_json(&state).await;
    assert_eq!(
        before["tun"],
        serde_json::json!({"enable": true, "mtu": 1500})
    );
    assert_eq!(before["tun-enable"], true);

    // Re-sending the current state is a no-op: the listener keeps running.
    let resp = patch_configs(&state, serde_json::json!({"tun": {"enable": true}})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(!stopped.load(Ordering::SeqCst));
    assert!(state.tunnel.has_tun());

    let resp = patch_configs(&state, serde_json::json!({"tun": {"enable": false}})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        stopped.load(Ordering::SeqCst),
        "disabling TUN must reap the running listener"
    );
    assert!(!state.tunnel.has_tun());
    let tun = state.raw_config.read().tun.clone().unwrap();
    assert!(!tun.enable, "the committed config must say TUN is off");
    assert_eq!(tun.mtu, Some(1500), "keys the patch omits are kept");

    let after = get_configs_json(&state).await;
    assert_eq!(
        after["tun"],
        serde_json::json!({"enable": false, "mtu": 1500})
    );
    assert_eq!(after["tun-enable"], false);
}

/// Without the `listener-tun` feature a `tun` patch turning TUN on fails
/// the way `PUT /configs` does — `enable` rolls back, the other patched
/// keys stay — but the PATCH answers with an error instead of 204, since
/// the TUN change was the request. Mode is not applied either.
#[cfg(not(feature = "listener-tun"))]
#[tokio::test]
async fn patch_configs_tun_enable_without_listener_tun_fails_and_rolls_back() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    assert_eq!(
        get_configs_json(&state).await["tun"],
        serde_json::json!({"enable": false}),
        "no tun: section still reports the switch"
    );

    // The socket policy starts at the default (enabled) posture.
    assert!(meow_common::outbound_tcp_keepalive().enabled);
    let resp = patch_configs(
        &state,
        serde_json::json!({
            "mode": "direct",
            "tun": {"enable": true, "mtu": 1400},
            "tcp-concurrent": false,
            "find-process-mode": "off",
            "disable-keep-alive": true,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let message = body_json(resp).await["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        message.contains("listener-tun"),
        "the error must say why TUN did not start: {message}"
    );
    assert!(!state.tunnel.has_tun());
    let tun = state.raw_config.read().tun.clone().unwrap();
    assert!(!tun.enable, "a failed start must roll `enable` back");
    assert_eq!(tun.mtu, Some(1400));
    // Riding the same swap, the live globals it commits before the
    // fallible reconcile must be restored too — not just `tun.enable`
    // (issue #974 review).
    {
        let raw = state.raw_config.read();
        assert_eq!(
            raw.tcp_concurrent, None,
            "the riding tcp-concurrent must not commit"
        );
        assert_eq!(
            raw.find_process_mode, None,
            "the riding find-process-mode must not commit"
        );
    }
    assert_eq!(
        state.tunnel.process_lookup_mode(),
        meow_common::ProcessLookupMode::Strict,
        "the live find-process-mode must be restored"
    );
    // The riding `disable-keep-alive` must not reach the socket policy
    // either — the keepalive resolves from `final_doc`, which is the
    // pre-patch document on a failed TUN reconcile (issue #974 review).
    assert!(
        meow_common::outbound_tcp_keepalive().enabled,
        "a failed TUN patch must leave the socket keepalive posture alone"
    );
    assert_eq!(
        state.raw_config.read().disable_keep_alive,
        None,
        "the committed document must not carry the rolled-back key"
    );
    let configs = get_configs_json(&state).await;
    assert_eq!(configs["tun"]["enable"], false);
    assert_eq!(
        configs["mode"], "rule",
        "a failed TUN patch must not apply the rest of the body"
    );
}

/// A patch without `enable` keeps the current state, so a parameter change
/// under a running listener restarts it like a `PUT /configs` `tun:` diff;
/// without the feature the respawn fails, which rolls `enable` back and
/// fails the PATCH.
#[cfg(not(feature = "listener-tun"))]
#[tokio::test]
async fn patch_configs_tun_param_change_restarts_running_listener() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;
    // Let the stand-in listener start: its drop flag exists only once polled.
    tokio::task::yield_now().await;

    let resp = patch_configs(&state, serde_json::json!({"tun": {"mtu": 9000}})).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        stopped.load(Ordering::SeqCst),
        "the restart must reap the old listener handle"
    );
    assert!(!state.tunnel.has_tun());
    let tun = state.raw_config.read().tun.clone().unwrap();
    assert!(!tun.enable);
    assert_eq!(tun.mtu, Some(9000));
}

/// The `keep-alive-*` PATCH fields deserialize as raw `Value` so a number
/// that is not an unsigned u64 reaches the semantic gate as a 400 — not a
/// 422 JSON extraction failure (Codex review).
#[tokio::test]
async fn patch_configs_rejects_malformed_keepalive_values() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    for (key, value) in [
        ("keep-alive-idle", serde_json::json!(-1)),
        ("keep-alive-interval", serde_json::json!(-5)),
        ("keep-alive-idle", serde_json::json!(1.5)),
        ("keep-alive-interval", serde_json::json!("30")),
        // serde_json stores a past-u64 integer as f64 — still not a u64.
        ("keep-alive-idle", serde_json::json!(1e30)),
        ("keep-alive-interval", serde_json::json!(true)),
    ] {
        let resp = patch_configs(&state, serde_json::json!({key: value})).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{key}={value} must be a semantic 400, not a 422 extraction failure"
        );
    }
    // A well-formed value still commits — and `null` stays "absent".
    let resp = patch_configs(&state, serde_json::json!({"keep-alive-idle": 30})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(meow_common::outbound_tcp_keepalive().idle.as_secs(), 30);
    let resp = patch_configs(&state, serde_json::json!({"keep-alive-idle": null})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(meow_common::outbound_tcp_keepalive().idle.as_secs(), 30);
    // Ordered cleanup under the lane, as the other keepalive tests do.
    let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
    meow_common::set_outbound_tcp_keepalive(meow_common::OutboundTcpKeepalive::default());
}

/// Keys are merged over the committed section: a key the patch omits, or
/// sends as `null`, keeps its value.
#[tokio::test]
async fn patch_configs_tun_merges_over_committed_section() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.tun = Some(
        serde_saphyr::from_str("enable: false\ndevice: utun9\nmtu: 1500\ndns-hijack: [any:53]")
            .unwrap(),
    );
    let state = test_state(raw);

    let resp = patch_configs(
        &state,
        serde_json::json!({"tun": {"mtu": 1400, "device": null, "auto-route": "global"}}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let tun = state.raw_config.read().tun.clone().unwrap();
    assert!(!tun.enable, "an omitted `enable` keeps TUN off");
    assert_eq!(tun.device.as_deref(), Some("utun9"));
    assert_eq!(tun.mtu, Some(1400));
    assert_eq!(tun.dns_hijack, Some(vec!["any:53".to_string()]));
    assert_eq!(
        get_configs_json(&state).await["tun"],
        serde_json::json!({
            "enable": false,
            "device": "utun9",
            "mtu": 1400,
            "auto-route": "global",
            "dns-hijack": ["any:53"],
        })
    );
}

/// `inet4-address` may be committed in mihomo's list form (#885), but
/// `GET /configs` always reports the string form the field's contract
/// declares — the first entry, the one `parse_tun_config` assigns the
/// device. Echoing the committed array would break `string | null`
/// clients; `[]` is unset and reports absent, not an empty array.
#[tokio::test]
async fn get_configs_tun_inet4_address_reports_the_string_form() {
    let mut raw = test_raw_config();
    raw.tun = Some(
        serde_saphyr::from_str("enable: false\ninet4-address: [10.9.0.1/30, 10.8.0.1/30]").unwrap(),
    );
    let state = test_state(raw);
    assert_eq!(
        get_configs_json(&state).await["tun"]["inet4-address"],
        serde_json::json!("10.9.0.1/30"),
        "the list form must report its first entry as a string"
    );

    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: false\ninet4-address: []").unwrap());
    let state = test_state(raw);
    let tun = get_configs_json(&state).await["tun"].clone();
    assert!(
        tun.get("inet4-address").is_none(),
        "[] is unset: the key must be absent, got {tun}"
    );
}

/// PATCH accepts the list form too: the committed section keeps the
/// spelling the client sent while `GET /configs` still reports a string.
#[tokio::test]
async fn patch_configs_tun_inet4_address_accepts_string_and_list_forms() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: false").unwrap());
    let state = test_state(raw);

    let resp = patch_configs(
        &state,
        serde_json::json!({"tun": {"inet4-address": ["10.9.0.1/30", "10.8.0.1/30"]}}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        state.raw_config.read().tun.as_ref().unwrap().inet4_address,
        Some(serde_json::json!(["10.9.0.1/30", "10.8.0.1/30"])),
        "the committed section keeps the list spelling"
    );
    assert_eq!(
        get_configs_json(&state).await["tun"]["inet4-address"],
        serde_json::json!("10.9.0.1/30"),
    );

    let resp = patch_configs(
        &state,
        serde_json::json!({"tun": {"inet4-address": "10.7.0.1/30"}}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        get_configs_json(&state).await["tun"]["inet4-address"],
        serde_json::json!("10.7.0.1/30"),
    );
}

/// A `PUT /configs` document in the list form commits and reports the
/// string, like a config file load would.
#[tokio::test]
async fn put_configs_tun_inet4_address_list_form_reports_the_string_form() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let state = test_state(test_raw_config());
    let yaml = concat!(
        "mode: rule\n",
        "tun:\n",
        "  enable: false\n",
        "  inet4-address: [10.9.0.1/30]\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        get_configs_json(&state).await["tun"]["inet4-address"],
        serde_json::json!("10.9.0.1/30"),
    );
}

/// `?force` commits a `tun:` section `parse_tun_config` rejected, garbage
/// `inet4-address` included — and `GET /configs` still never reports a
/// non-string: an unreportable committed value is absent, while a
/// committed string (invalid CIDR or not) is echoed verbatim as a string.
#[tokio::test]
async fn put_configs_force_garbage_inet4_address_never_reports_non_string() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    let put = |inet4: &str| {
        let yaml = format!(
            "mode: rule\ntun:\n  enable: false\n  inet4-address: {inet4}\nrules:\n  - MATCH,DIRECT\n"
        );
        base64::engine::general_purpose::STANDARD.encode(yaml)
    };
    let state = test_state(test_raw_config());
    for (payload, want) in [
        (put("[7]"), serde_json::Value::Null),
        (put("{a: 1}"), serde_json::Value::Null),
        // A committed string reports verbatim — the contract is
        // `string | absent`, not `valid CIDR | absent`.
        (put("not-a-cidr"), serde_json::json!("not-a-cidr")),
    ] {
        let resp = create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/configs?force=true")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"payload": payload}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let tun = get_configs_json(&state).await["tun"].clone();
        if want.is_null() {
            assert!(
                tun.get("inet4-address").is_none(),
                "an unreportable committed value must be absent, got {tun}"
            );
        } else {
            assert_eq!(tun["inet4-address"], want);
        }
    }
}

/// Unknown keys — mihomo's upstream-only `tun` keys and other top-level
/// sections (Clash Party sends `dns` with its TUN switch) — are ignored,
/// not stored and not rejected.
#[tokio::test]
async fn patch_configs_tun_ignores_unknown_keys() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());

    let resp = patch_configs(
        &state,
        serde_json::json!({
            "tun": {
                "enable": false,
                "device": "utun9",
                "strict-route": true,
                "auto-detect-interface": true,
                "not-a-key": 1,
            },
            "dns": {"enable": true},
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let tun = state.raw_config.read().tun.clone().unwrap();
    assert_eq!(tun.device.as_deref(), Some("utun9"));
    assert!(tun.strict_route.is_none());
    assert!(tun.auto_detect_interface.is_none());
    assert!(state.raw_config.read().dns.is_none());
}

/// `stack` is an implemented `tun:` key, not an upstream-only leftover:
/// a PATCH carrying it commits the value and `GET /configs` echoes it.
/// A fallback spelling (`gvisor` → lwIP) commits verbatim like the file
/// section — on a running listener it parses to the stack already
/// running, so the parsed diff does not restart it. Deterministic under
/// both feature sets: no `enable` transition, no respawn.
#[tokio::test]
async fn patch_configs_tun_stack_commits_and_echoes() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;
    // Let the stand-in listener start: its drop flag exists only once polled.
    tokio::task::yield_now().await;

    // `gvisor` warns and parses to lwIP — the committed section gains the
    // key while the running listener is left alone.
    let resp = patch_configs(&state, serde_json::json!({"tun": {"stack": "gvisor"}})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        !stopped.load(Ordering::SeqCst),
        "a stack spelling that parses to the running one must not restart"
    );
    assert!(state.tunnel.has_tun());
    assert_eq!(
        state.raw_config.read().tun.as_ref().unwrap().stack,
        Some(serde_json::json!("gvisor")),
        "the committed section keeps the client's spelling"
    );
    assert_eq!(
        get_configs_json(&state).await["tun"]["stack"],
        "gvisor",
        "GET /configs echoes the committed value"
    );

    // Turning TUN off while switching `stack` commits both keys and
    // stops the listener — no spawn is attempted on an on→off.
    let resp = patch_configs(
        &state,
        serde_json::json!({"tun": {"enable": false, "stack": "system"}}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(stopped.load(Ordering::SeqCst));
    assert!(!state.tunnel.has_tun());
    let tun = state.raw_config.read().tun.clone().unwrap();
    assert!(!tun.enable);
    assert_eq!(tun.stack, Some(serde_json::json!("system")));
    assert_eq!(
        get_configs_json(&state).await["tun"],
        serde_json::json!({"enable": false, "mtu": 1500, "stack": "system"}),
    );
}

/// A patch without `tun` leaves the section and the running listener
/// alone.
#[tokio::test]
async fn patch_configs_without_tun_leaves_tun_untouched() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let before = state.raw_config.read().tun.clone();
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;
    // Let the stand-in listener start: its drop flag exists only once polled.
    tokio::task::yield_now().await;

    let resp = patch_configs(&state, serde_json::json!({"mode": "direct"})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(state.raw_config.read().tun, before);
    assert!(!stopped.load(Ordering::SeqCst));
    assert!(state.tunnel.has_tun());
    assert_eq!(get_configs_json(&state).await["mode"], "direct");
}

/// A `tun` section the listener cannot parse is rejected before anything
/// is applied, like a `PUT /configs` one: the running listener, the
/// committed section and the rest of the body stay as they were.
#[tokio::test]
async fn patch_configs_tun_rejects_invalid_section() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let before = state.raw_config.read().tun.clone();
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;
    // Let the stand-in listener start: its drop flag exists only once polled.
    tokio::task::yield_now().await;

    let resp = patch_configs(
        &state,
        serde_json::json!({"mode": "direct", "tun": {"mtu": 1000}}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let message = body_json(resp).await["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(message.contains("tun.mtu"), "{message}");
    assert_eq!(state.raw_config.read().tun, before);
    assert!(!stopped.load(Ordering::SeqCst));
    assert!(state.tunnel.has_tun());
    assert_eq!(get_configs_json(&state).await["mode"], "rule");
}

/// A newly declared provider whose origin never answers must not hold the
/// `CONFIG_MUTATION` lane. The commit lands on its own, the initial fetch
/// runs detached, and the next writer is not queued behind a blackholed
/// subscription URL — the same rule that keeps ECH preresolution out of
/// `apply_raw_to_tunnel` (issue #533 review).
#[tokio::test]
async fn put_configs_does_not_await_provider_downloads_in_the_mutation_lane() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    use tokio::io::AsyncReadExt as _;
    let state = test_state(test_raw_config());
    let directory = tempfile::tempdir_in(
        std::path::Path::new(state.config_path.as_deref().unwrap())
            .parent()
            .unwrap(),
    )
    .unwrap();
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    // Accept the request and then stall forever. An awaited fetch would
    // pin the lane until the internal HTTP read timeout (60 s).
    let server = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut buffer = [0; 2048];
        let _ = stream.read(&mut buffer).await;
        std::future::pending::<()>().await;
    });
    let yaml = format!(
        "mode: rule\nproxy-providers:\n  pending:\n    type: http\n    url: http://{address}/proxies.yaml\n    proxy: front\n    path: {}\nproxy-groups: [{{name: front, type: select, proxies: [DIRECT]}}]\nrules: ['MATCH,DIRECT']\n",
        directory.path().join("pending.yaml").display()
    );
    let request = Request::builder()
        .method("PUT")
        .uri("/configs")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({
                "payload": base64::engine::general_purpose::STANDARD.encode(yaml)
            })
            .to_string(),
        ))
        .unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        create_router(Arc::clone(&state)).oneshot(request),
    )
    .await
    .expect("the commit must not wait on the provider download")
    .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(state.proxy_providers.contains_key("pending"));
    assert!(state.tunnel.proxy("front").is_some());

    // The lane is free immediately, while that fetch is still outstanding.
    let update = create_router(Arc::clone(&state)).oneshot(
        Request::builder()
            .method("PATCH")
            .uri("/configs")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"mode":"direct"}"#))
            .unwrap(),
    );
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), update)
        .await
        .expect("CONFIG_MUTATION remained locked")
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    server.abort();
}

/// Same lane discipline without a `proxy:` indirection. The test above
/// exits `fetch_source` early via `deferred_initial`, so it would not
/// catch a regression that loads *every* vehicle on the lane — a
/// direct-dialed blackhole would stall there. Only `file:` providers may
/// ever load synchronously during materialize (`is_file_vehicle`).
#[tokio::test]
async fn put_configs_does_not_fetch_remote_providers_in_the_mutation_lane() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    use tokio::io::AsyncReadExt as _;
    let state = test_state(test_raw_config());
    let directory = tempfile::tempdir_in(
        std::path::Path::new(state.config_path.as_deref().unwrap())
            .parent()
            .unwrap(),
    )
    .unwrap();
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    // Accept the request and then stall forever, so an on-lane fetch
    // would pin the commit behind the internal HTTP read timeout.
    let server = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut buffer = [0; 2048];
        let _ = stream.read(&mut buffer).await;
        std::future::pending::<()>().await;
    });
    let yaml = format!(
        "mode: rule\nproxy-providers:\n  pending:\n    type: http\n    url: http://{address}/proxies.yaml\n    path: {}\nrules: ['MATCH,DIRECT']\n",
        directory.path().join("pending.yaml").display()
    );
    let request = Request::builder()
        .method("PUT")
        .uri("/configs")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({
                "payload": base64::engine::general_purpose::STANDARD.encode(yaml)
            })
            .to_string(),
        ))
        .unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        create_router(Arc::clone(&state)).oneshot(request),
    )
    .await
    .expect("the commit must not fetch a remote provider on the lane")
    .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(state.proxy_providers.contains_key("pending"));
    server.abort();
}

/// `GET /logbook` and `DELETE /logbook`. The logbook is process-global and
/// other tests in this binary may record into it while it is installed, so
/// every read filters on this test's subject.
#[tokio::test]
async fn logbook_lists_filters_and_clears_entries() {
    let _globals_lane = process_globals_lane().await;
    use meow_common::logbook;

    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let get = |uri: &str| {
        let app = app.clone();
        let request = Request::get(uri).body(axum::body::Body::empty()).unwrap();
        async move { app.oneshot(request).await.unwrap() }
    };

    let off = body_json(get("/logbook").await).await;
    assert_eq!(off["enabled"], false);
    assert_eq!(off["entries"], serde_json::json!([]));

    let dir = tempfile::tempdir().unwrap();
    logbook::install(dir.path(), logbook::Options::default()).unwrap();

    // An API mutation records itself once committed.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/proxy-groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"LogbookGroup","type":"select","proxies":["DIRECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    for message in ["first", "second"] {
        logbook::event(
            logbook::kind::PROXY_PROVIDER_UPDATE,
            logbook::Level::Warning,
            message,
        )
        .subject("LogbookGroup")
        .coalesce()
        .record();
    }

    let page = body_json(get("/logbook?subject=LogbookGroup").await).await;
    assert_eq!(page["enabled"], true);
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "{page}");
    assert_eq!(entries[0]["kind"], "proxy-provider.update");
    assert_eq!(entries[0]["message"], "second", "the fold keeps the latest");
    assert_eq!(entries[0]["count"], 2);
    assert_eq!(entries[1]["kind"], "config.change");
    assert_eq!(entries[1]["message"], "Created proxy group 'LogbookGroup'");

    let warnings = body_json(get("/logbook?subject=LogbookGroup&level=warning").await).await;
    assert_eq!(warnings["entries"].as_array().unwrap().len(), 1);
    let area = body_json(get("/logbook?subject=LogbookGroup&kind=config").await).await;
    assert_eq!(area["entries"][0]["kind"], "config.change");
    let paged = body_json(get("/logbook?subject=LogbookGroup&limit=1").await).await;
    assert_eq!(paged["entries"].as_array().unwrap().len(), 1);
    assert_eq!(paged["more"], true);

    let bad = get("/logbook?level=loud").await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    let resp = app
        .clone()
        .oneshot(
            Request::delete("/logbook")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let cleared = body_json(get("/logbook?subject=LogbookGroup").await).await;
    assert_eq!(cleared["entries"], serde_json::json!([]));
    let marker = body_json(get("/logbook?kind=logbook.cleared").await).await;
    assert_eq!(marker["entries"].as_array().unwrap().len(), 1);

    logbook::uninstall();
    assert_eq!(body_json(get("/logbook").await).await["enabled"], false);
}

/// `GET /traffic/ledger` and `DELETE /traffic/ledger`. The ledger is
/// process-global and other tests in this binary may record into it while
/// it is installed, so every read narrows to this test's host.
#[tokio::test]
async fn traffic_ledger_groups_drills_and_clears() {
    let _globals_lane = process_globals_lane().await;
    use meow_common::traffic_ledger;

    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let get = |uri: &str| {
        let app = app.clone();
        let request = Request::get(uri).body(axum::body::Body::empty()).unwrap();
        async move { app.oneshot(request).await.unwrap() }
    };

    let off = body_json(get("/traffic/ledger").await).await;
    assert_eq!(off["enabled"], false);
    assert_eq!(off["rows"], serde_json::json!([]));

    let dir = tempfile::tempdir().unwrap();
    traffic_ledger::install(dir.path(), traffic_ledger::Options::default()).unwrap();
    let direct = traffic_ledger::Route::from("DIRECT");
    // A node that reaches its server through a `dialer-proxy`.
    let node = traffic_ledger::Route {
        policy: Arc::from("Ledger API Node"),
        via: Some(Arc::from("Ledger API Front")),
    };
    let browser = "org.example.browser".into();
    traffic_ledger::add(
        &"www.ledger-api.example".into(),
        &browser,
        &direct,
        10,
        100,
        1,
    );
    traffic_ledger::add(
        &"cdn.ledger-api.example".into(),
        &"".into(),
        &node,
        20,
        2000,
        2,
    );

    let hosts = body_json(get("/traffic/ledger?host=ledger-api.example").await).await;
    assert_eq!(hosts["enabled"], true);
    assert_eq!(hosts["by"], "host");
    let rows = hosts["rows"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "subdomains fold into the registrable domain: {hosts}"
    );
    assert_eq!(rows[0]["name"], "ledger-api.example");
    assert_eq!(rows[0]["requests"], 3);

    let policies = body_json(get("/traffic/ledger?by=policy&host=ledger-api.example").await).await;
    let rows = policies["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{policies}");
    // The front member counts the hop it carried, the node its flows.
    assert_eq!(rows[0]["name"], "Ledger API Front", "largest first");
    assert_eq!(rows[0]["download"], 2000);
    assert_eq!(rows[0]["via_download"], 2000);
    assert_eq!(rows[0]["via_requests"], 2);
    assert_eq!(rows[1]["name"], "Ledger API Node");
    assert_eq!(rows[1]["download"], 2000);
    assert_eq!(rows[1]["via_download"], 0);
    assert_eq!(rows[2]["name"], "DIRECT");
    // Each flow once in the totals.
    assert_eq!(policies["download"], 2100);
    assert_eq!(policies["requests"], 3);

    let carried =
        body_json(get("/traffic/ledger?host=ledger-api.example&policy=Ledger%20API%20Front").await)
            .await;
    assert_eq!(carried["download"], 2000, "{carried}");

    let drilled =
        body_json(get("/traffic/ledger?by=interface&host=ledger-api.example&policy=DIRECT").await)
            .await;
    assert_eq!(drilled["upload"], 10);
    assert_eq!(drilled["download"], 100);

    let apps = body_json(get("/traffic/ledger?by=app&host=ledger-api.example").await).await;
    assert_eq!(apps["by"], "app");
    let rows = apps["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{apps}");
    assert_eq!(rows[0]["name"], "", "flows of no known app");
    assert_eq!(rows[1]["name"], "org.example.browser");
    let browser = body_json(get("/traffic/ledger?by=policy&app=org.example.browser").await).await;
    let rows = browser["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{browser}");
    assert_eq!(rows[0]["name"], "DIRECT");

    let today = traffic_ledger::date_of_day(traffic_ledger::today());
    let span = body_json(
        get(&format!(
            "/traffic/ledger?from={today}&to={today}&host=ledger-api.example"
        ))
        .await,
    )
    .await;
    assert_eq!(span["from"], today.as_str());
    assert_eq!(span["requests"], 3);

    assert_eq!(
        get("/traffic/ledger?from=yesterday").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get("/traffic/ledger?by=port").await.status(),
        StatusCode::BAD_REQUEST
    );
    // Only `to`, before today: `from` (today) comes after it.
    assert_eq!(
        get("/traffic/ledger?to=2026-01-01").await.status(),
        StatusCode::BAD_REQUEST
    );

    let resp = app
        .clone()
        .oneshot(
            Request::delete("/traffic/ledger")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let cleared = body_json(get("/traffic/ledger?host=ledger-api.example").await).await;
    assert_eq!(cleared["rows"], serde_json::json!([]));

    traffic_ledger::uninstall();
    assert_eq!(
        body_json(get("/traffic/ledger").await).await["enabled"],
        false
    );
}

// ── Proxy-provider subscriptionInfo ──────────────────────────────

/// What [`UserinfoOrigin`] answers every request with.
#[derive(Clone, Copy)]
struct OriginReply {
    status: u16,
    /// The `subscription-userinfo` header value, sent when `Some`.
    userinfo: Option<&'static str>,
    body: &'static str,
}

const USERINFO_PAYLOAD: &str = "proxies:\n  - {name: n1, type: direct}\n";

/// A proxy-provider origin the test steers: counts requests and answers
/// each with the current [`OriginReply`].
struct UserinfoOrigin {
    url: String,
    reply: Arc<parking_lot::Mutex<OriginReply>>,
    hits: Arc<std::sync::atomic::AtomicUsize>,
}

impl UserinfoOrigin {
    async fn spawn(reply: OriginReply) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/sub.yaml", listener.local_addr().unwrap());
        let reply = Arc::new(parking_lot::Mutex::new(reply));
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (task_reply, task_hits) = (Arc::clone(&reply), Arc::clone(&hits));
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                task_hits.fetch_add(1, Ordering::SeqCst);
                let reply = *task_reply.lock();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    // Mixed case on purpose: the header name is
                    // case-insensitive.
                    let userinfo = reply
                        .userinfo
                        .map(|value| format!("Subscription-Userinfo: {value}\r\n"))
                        .unwrap_or_default();
                    let response = format!(
                        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n{userinfo}\r\n{}",
                        reply.status,
                        reply.body.len(),
                        reply.body
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        Self { url, reply, hits }
    }

    fn set(&self, reply: OriginReply) {
        *self.reply.lock() = reply;
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// Load `providers` (name → YAML declaration) the way startup does, with
/// `dir` as the provider cache directory, and serve them from a fresh
/// [`AppState`].
async fn state_with_providers(
    providers: &[(&str, String)],
    dir: &std::path::Path,
) -> Arc<AppState> {
    let raw: HashMap<String, meow_config::raw::RawProxyProvider> = providers
        .iter()
        .map(|(name, yaml)| ((*name).to_string(), serde_saphyr::from_str(yaml).unwrap()))
        .collect();
    let state = test_state_default();
    // Share the tunnel's dns-outbound cell like production provider
    // loading — `type: dns` leaves in these providers bind the same
    // live-resolver slot the tunnel republishes (issue #974).
    let dns_cell = state.tunnel.dns_outbound_cell();
    let loaded = meow_config::proxy_provider::load_proxy_providers_within(
        &raw,
        Some(dir),
        false,
        false,
        &Default::default(),
        None,
        None,
        Some(&dns_cell),
        &mut meow_config::DroppedProviders::default(),
    )
    .await
    .unwrap();
    for (name, provider) in loaded {
        state.proxy_providers.insert(name, provider);
    }
    state
}

async fn api_call(state: &Arc<AppState>, method: &str, uri: &str) -> axum::response::Response {
    create_router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// `subscriptionInfo` of provider `name` as `GET /providers/proxies` lists
/// it, checked against `GET /providers/proxies/{name}`; `None` when absent.
async fn listed_subscription_info(state: &Arc<AppState>, name: &str) -> Option<serde_json::Value> {
    let list = body_json(api_call(state, "GET", "/providers/proxies").await).await;
    let one = api_call(state, "GET", &format!("/providers/proxies/{name}")).await;
    assert_eq!(one.status(), StatusCode::OK);
    let one = body_json(one).await;
    assert_eq!(list["providers"][name], one, "list and detail agree");
    assert_eq!(
        one["proxies"].as_array().map(Vec::len),
        Some(1),
        "the payload loaded: {one}"
    );
    one.as_object().unwrap().get("subscriptionInfo").cloned()
}

/// An HTTP provider whose response carries `subscription-userinfo` reports
/// it as mihomo's `subscriptionInfo`; one without the header, and a `file`
/// provider, leave the field out.
#[tokio::test]
async fn proxy_providers_report_subscription_userinfo() {
    let with = UserinfoOrigin::spawn(OriginReply {
        status: 200,
        userinfo: Some("upload=1234; download=5678; total=1073741824; expire=1700000000"),
        body: USERINFO_PAYLOAD,
    })
    .await;
    let without = UserinfoOrigin::spawn(OriginReply {
        status: 200,
        userinfo: None,
        body: USERINFO_PAYLOAD,
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("local.yaml"), USERINFO_PAYLOAD).unwrap();
    let state = state_with_providers(
        &[
            ("usage", format!("type: http\nurl: {}\n", with.url)),
            ("plain", format!("type: http\nurl: {}\n", without.url)),
            ("local", "type: file\npath: local.yaml\n".to_string()),
        ],
        dir.path(),
    )
    .await;

    assert_eq!(
        listed_subscription_info(&state, "usage").await,
        Some(serde_json::json!({
            "Upload": 1234,
            "Download": 5678,
            "Total": 1_073_741_824_u64,
            "Expire": 1_700_000_000_u64,
        }))
    );
    assert_eq!(listed_subscription_info(&state, "plain").await, None);
    assert_eq!(listed_subscription_info(&state, "local").await, None);
}

/// The usage is persisted next to the provider cache, so a restart that
/// serves the cache without touching the network reports it at once; each
/// later fetch the provider accepts replaces it, even when the payload is
/// unchanged, a failed fetch keeps it, and a fetch without the header
/// clears it.
#[tokio::test]
async fn proxy_provider_subscription_info_survives_restart_and_follows_fetches() {
    let _globals_lane = process_globals_lane().await;
    let origin = UserinfoOrigin::spawn(OriginReply {
        status: 200,
        userinfo: Some("upload=1; download=2; total=1000"),
        body: USERINFO_PAYLOAD,
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let decl = [("usage", format!("type: http\nurl: {}\n", origin.url))];
    let sidecar = dir.path().join("provider_usage.yaml.subscription-userinfo");
    let first = serde_json::json!({"Upload": 1, "Download": 2, "Total": 1000, "Expire": 0});

    let state = state_with_providers(&decl, dir.path()).await;
    assert_eq!(
        listed_subscription_info(&state, "usage").await,
        Some(first.clone())
    );
    assert!(sidecar.exists(), "persisted next to the cache");
    drop(state);

    // Restart with the feed down: the cache and its usage are served
    // before (and without) any request.
    origin.set(OriginReply {
        status: 503,
        userinfo: None,
        body: "",
    });
    let hits = origin.hits();
    let state = state_with_providers(&decl, dir.path()).await;
    assert_eq!(
        origin.hits(),
        hits,
        "a cached provider starts without a fetch"
    );
    assert_eq!(
        listed_subscription_info(&state, "usage").await,
        Some(first.clone())
    );

    // The usage moved; the payload did not.
    origin.set(OriginReply {
        status: 200,
        userinfo: Some("upload=10; download=20; total=1000; expire=1800000000"),
        body: USERINFO_PAYLOAD,
    });
    let refreshed = api_call(&state, "PUT", "/providers/proxies/usage").await;
    assert_eq!(refreshed.status(), StatusCode::NO_CONTENT);
    let second = serde_json::json!({"Upload": 10, "Download": 20, "Total": 1000, "Expire": 1_800_000_000_u64});
    assert_eq!(
        listed_subscription_info(&state, "usage").await,
        Some(second.clone())
    );

    origin.set(OriginReply {
        status: 503,
        userinfo: Some("upload=99; download=99; total=99"),
        body: "",
    });
    let failed = api_call(&state, "PUT", "/providers/proxies/usage").await;
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(failed).await["message"],
        "Proxy provider refresh failed; the last valid proxies are unchanged"
    );
    assert_eq!(
        listed_subscription_info(&state, "usage").await,
        Some(second.clone()),
        "a failed fetch keeps the last accepted usage"
    );

    // A restart now reports the refetched usage, not the first one.
    drop(state);
    let state = state_with_providers(&decl, dir.path()).await;
    assert_eq!(
        listed_subscription_info(&state, "usage").await,
        Some(second)
    );

    origin.set(OriginReply {
        status: 200,
        userinfo: None,
        body: USERINFO_PAYLOAD,
    });
    let cleared = api_call(&state, "PUT", "/providers/proxies/usage").await;
    assert_eq!(cleared.status(), StatusCode::NO_CONTENT);
    assert_eq!(listed_subscription_info(&state, "usage").await, None);
    assert!(!sidecar.exists(), "nothing left to restore");
    drop(state);

    origin.set(OriginReply {
        status: 503,
        userinfo: None,
        body: "",
    });
    let state = state_with_providers(&decl, dir.path()).await;
    assert_eq!(listed_subscription_info(&state, "usage").await, None);
}

// ── Option C: PUT /configs validates local `file:` provider payloads ──

/// Commit `yaml` through `PUT /configs` (`?force=true` when `force`),
/// returning the response status.
async fn put_config_yaml(state: &Arc<AppState>, yaml: &str, force: bool) -> StatusCode {
    use base64::Engine as _;
    let uri = if force {
        "/configs?force=true"
    } else {
        "/configs"
    };
    create_router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "payload": base64::engine::general_purpose::STANDARD.encode(yaml)
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// The directory that backs `test_state`'s `config_path` — `file:`/`http:`
/// provider `path:` entries resolve inside it.
fn backing_dir(state: &Arc<AppState>) -> std::path::PathBuf {
    std::path::Path::new(state.config_path.as_deref().unwrap())
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Issue #533 Option C: a `file:` proxy-provider payload is operator-authored
/// local content — under `strict` a malformed payload must reject the PUT
/// with 400 and leave the live registry and raw config untouched (no
/// `spawn_initial_fetch` side-effects, nothing recorded for a candidate
/// that never commits). `?force=true` keeps the lenient escape: the bad
/// node is warn-skipped and the provider commits empty.
#[tokio::test]
async fn put_configs_strict_rejects_malformed_file_provider_payload() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    let dir = backing_dir(&state);
    std::fs::write(
        dir.join("bad.yaml"),
        "proxies:\n  - {name: bad, type: nosuchtype}\n",
    )
    .unwrap();
    let yaml = "strict: true\nmode: rule\nproxy-providers:\n  local:\n    type: file\n    path: bad.yaml\nproxy-groups:\n  - {name: G, type: select, use: [local]}\nrules: ['MATCH,G']\n";

    let status = put_config_yaml(&state, yaml, false).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a strict file-payload defect must reject the candidate"
    );
    assert!(
        state.proxy_providers.is_empty(),
        "the rejected candidate must not register the provider"
    );
    assert!(
        state.tunnel.proxy("G").is_none(),
        "the route map must be untouched"
    );
    assert_eq!(
        state.raw_config.read().rules.as_deref(),
        Some(
            [
                "DOMAIN,example.com,DIRECT".to_string(),
                "MATCH,REJECT".to_string()
            ]
            .as_slice()
        ),
        "the live raw config must be untouched"
    );

    // `?force=true` retries the same candidate leniently: the malformed
    // node is warn-skipped and the provider commits (empty content).
    let status = put_config_yaml(&state, yaml, true).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "force retains the lenient escape"
    );
    let provider = state.proxy_providers.get("local").unwrap();
    assert!(
        provider.proxies().is_empty(),
        "lenient skips the unparseable node"
    );
}

/// `strict: false` — the same malformed `file:` payload commits directly:
/// the node is warn-skipped and the provider registers empty.
#[tokio::test]
async fn put_configs_lenient_commits_malformed_file_provider() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    let dir = backing_dir(&state);
    std::fs::write(
        dir.join("bad.yaml"),
        "proxies:\n  - {name: bad, type: nosuchtype}\n",
    )
    .unwrap();
    let yaml = "mode: rule\nproxy-providers:\n  local:\n    type: file\n    path: bad.yaml\nproxy-groups:\n  - {name: G, type: select, use: [local]}\nrules: ['MATCH,G']\n";

    let status = put_config_yaml(&state, yaml, false).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let provider = state.proxy_providers.get("local").unwrap();
    assert!(provider.proxies().is_empty());
}

/// A well-formed `file:` payload commits with its nodes already loaded —
/// the pre-commit load validates *and* populates (no second read needed),
/// so `use:` groups have members the moment the PUT returns.
#[tokio::test]
async fn put_configs_commits_valid_file_provider_payload() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    let dir = backing_dir(&state);
    std::fs::write(
        dir.join("nodes.yaml"),
        "proxies:\n  - {name: n1, type: direct}\n",
    )
    .unwrap();
    let yaml = "strict: true\nmode: rule\nproxy-providers:\n  local:\n    type: file\n    path: nodes.yaml\nproxy-groups:\n  - {name: G, type: select, use: [local]}\nrules: ['MATCH,G']\n";

    let status = put_config_yaml(&state, yaml, false).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a valid strict file payload must commit"
    );
    let provider = state.proxy_providers.get("local").unwrap();
    assert_eq!(
        provider.proxies().len(),
        1,
        "the pre-commit load already populated the provider"
    );
}

/// A malformed *remote* (`http:`) payload under `strict` must NOT reject
/// the PUT: remote bytes are third-party content, so the provider commits
/// empty and the detached acquisition retries it — no 400.
#[tokio::test]
async fn put_configs_strict_remote_payload_defect_commits_empty() {
    let _globals_lane = process_globals_lane().await;
    let origin = UserinfoOrigin::spawn(OriginReply {
        status: 200,
        userinfo: None,
        body: "proxies:\n  - {name: bad, type: nosuchtype}\n",
    })
    .await;
    let state = test_state(test_raw_config());
    let yaml = format!(
        "strict: true\nmode: rule\nproxy-providers:\n  remote:\n    type: http\n    url: {}\nproxy-groups:\n  - {{name: G, type: select, use: [remote]}}\nrules: ['MATCH,G']\n",
        origin.url
    );

    let status = put_config_yaml(&state, &yaml, false).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a remote payload defect must degrade, not reject the PUT"
    );
    let provider = Arc::clone(state.proxy_providers.get("remote").unwrap().value());
    assert!(
        provider.proxies().is_empty(),
        "the rejected remote payload registers the provider empty"
    );
    // The commit owes the detached initial fetch: the origin sees the
    // first fetch plus a retry.
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while origin.hits() < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the committed provider must retry the bad payload in background");
}

/// Missing/malformed provider content must not erase last-good rules, and
/// the failure response must not disclose its private source or payload.
#[tokio::test]
async fn rule_provider_refresh_failure_is_readable_and_preserves_last_good() {
    use meow_config::raw::RawRuleProvider;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-source-token.yaml");
    let good = "payload:\n  - '+.example.com'\n";
    std::fs::write(&path, good).unwrap();
    let raw = HashMap::from([(
        "fixture".into(),
        RawRuleProvider {
            provider_type: "file".into(),
            behavior: "domain".into(),
            format: Some("yaml".into()),
            url: None,
            path: Some(path.to_string_lossy().into_owned()),
            interval: None,
            proxy: None,
            header: None,
            payload: None,
            extra: Default::default(),
        },
    )]);
    let state = test_state_default();
    *state.rule_providers.write() = meow_config::rule_provider::load_providers(
        &raw,
        Some(dir.path()),
        &meow_rules::ParserContext::default(),
        None,
        true,
    )
    .unwrap();
    let before = body_json(api_call(&state, "GET", "/providers/rules/fixture").await).await;
    for malformed in [false, true] {
        if malformed {
            std::fs::write(&path, "payload: [private-payload-secret").unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        let failed = api_call(&state, "PUT", "/providers/rules/fixture").await;
        assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
        let message = body_json(failed).await;
        assert_eq!(
            message["message"],
            "Rule provider refresh failed; the last valid rules are unchanged"
        );
        assert!(!message.to_string().contains("private-"));
        let after = body_json(api_call(&state, "GET", "/providers/rules/fixture").await).await;
        assert_eq!(
            before, after,
            "failed refresh must retain last-good metadata"
        );
    }
    std::fs::write(
        &path,
        "payload:\n  - '+.example.com'\n  - '+.second.test'\n",
    )
    .unwrap();
    let recovered = api_call(&state, "PUT", "/providers/rules/fixture").await;
    assert_eq!(recovered.status(), StatusCode::NO_CONTENT);
    assert_eq!(state.rule_providers.read()["fixture"].rule_count(), 2);
    let missing = api_call(&state, "PUT", "/providers/rules/missing").await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

// ── PR #882 review: storage endpoint semantics ──────────────────

async fn storage_get(state: &Arc<AppState>, key: &str) -> String {
    let resp = create_router(Arc::clone(state))
        .oneshot(
            Request::get(format!("/storage/{key}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    body_string(resp).await
}

/// mihomo's `/storage/{key}` contract: GET answers `null` for an unset
/// key, a stored JSON value echoes back verbatim, and invalid JSON fails
/// 400 even when the body is also over the 1 MiB value cap (validity is
/// checked before size, same order as upstream).
#[tokio::test]
async fn storage_get_put_delete_and_json_order() {
    let state = test_state_default();
    let send = |method: &str, uri: &str, body: String| {
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
    };

    // Unset key -> JSON `null`.
    let resp = send("GET", "/storage/zashboard", String::new())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "null");

    // PUT a JSON body, GET it back verbatim.
    let resp = send("PUT", "/storage/zashboard", r#"{"theme":"dark"}"#.into())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = send("GET", "/storage/zashboard", String::new())
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, r#"{"theme":"dark"}"#);

    // Invalid JSON is 400 — and that check precedes the 1 MiB size cap,
    // so an oversized *invalid* body still answers 400, not 413.
    let big_invalid = "x".repeat((1 << 20) + 1);
    let resp = send("PUT", "/storage/big", big_invalid).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A valid oversized body is the 413 case.
    let big_valid = format!("\"{}\"", "x".repeat((1 << 20) + 1));
    let resp = send("PUT", "/storage/big", big_valid).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let resp = send("GET", "/storage/big", String::new()).await.unwrap();
    assert_eq!(body_string(resp).await, "null");

    // DELETE removes.
    let resp = send("DELETE", "/storage/zashboard", String::new())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = send("GET", "/storage/zashboard", String::new())
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "null");
}

/// Upstream quirk (verified against `hub/route/storage.go`): a key past
/// 64 bytes is silently accepted — PUT answers 204 but stores nothing,
/// and GET still answers `null`.
#[tokio::test]
async fn storage_overlong_key_is_a_silent_noop() {
    let state = test_state_default();
    let long_key = "k".repeat(65);
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::put(format!("/storage/{long_key}"))
                .body(axum::body::Body::from("1"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = create_router(state)
        .oneshot(
            Request::get(format!("/storage/{long_key}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "null");
}

/// The ~1 MiB aggregate budget evicts the least recently WRITTEN key —
/// an existing key's rewrite refreshes its recency.
#[tokio::test]
async fn storage_byte_budget_evicts_oldest_write() {
    let state = test_state_default();
    let send = |method: &str, uri: &str, body: String| {
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
    };
    // 2/5 of the ~1 MiB budget each: two entries fit, the third must
    // evict.
    let val = format!("\"{}\"", "v".repeat(2 * (1 << 20) / 5));
    for key in ["a", "b"] {
        let resp = send("PUT", &format!("/storage/{key}"), val.clone())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
    // Rewriting "a" with a different value makes it the newest write;
    // the third key then evicts "b" (the oldest write now), not "a".
    let val_a = format!("\"{}\"", "w".repeat(2 * (1 << 20) / 5));
    let resp = send("PUT", "/storage/a", val_a.clone()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = send("PUT", "/storage/c", val.clone()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        storage_get(&state, "b").await,
        "null",
        "oldest write evicts first"
    );
    assert_eq!(storage_get(&state, "a").await, val_a, "rewritten key stays");
    assert_eq!(storage_get(&state, "c").await, val, "newest write stays");
}

// ── PR #882 review: PATCH /rules/disable body shapes ────────────

/// `PATCH /rules/disable` tolerates mihomo's loose body contract: a
/// literal `null` is an empty patch, and `{"0":null}` reads as "rule 0
/// enabled" the way Go's `map[int]bool` JSON decode treats it.
#[tokio::test]
async fn disable_rules_accepts_null_body_and_null_values() {
    let state = test_state_default();
    let patch = |body: &'static str| {
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/rules/disable")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
    };
    // Disable rule 0 first so the null-value flip has something to undo.
    assert_eq!(
        patch(r#"{"0":true}"#).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    // Literal null = empty patch.
    assert_eq!(
        patch("null").await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    // {"0":null} -> rule 0 enabled again (serde `Option<bool>` -> false).
    assert_eq!(
        patch(r#"{"0":null}"#).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let resp = create_router(state)
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let rules = body_json(resp).await["rules"].as_array().unwrap().clone();
    assert_eq!(rules[0]["extra"]["disabled"], false);
}

// ── PR #882 review: POST /rules/append validation ───────────────

/// An appended line that fails to parse must not answer 204 while it
/// silently never lands — the route dry-parses first and names the line.
#[tokio::test]
async fn append_rule_rejects_unparsable_line() {
    let state = test_state_default();
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::post("/rules/append")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"rule":"NOSUCHRULETYPE,foo,DIRECT"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let message = body_string(resp).await;
    assert!(
        message.contains("NOSUCHRULETYPE,foo,DIRECT"),
        "error names the rejected line: {message}"
    );
    // Nothing landed in the config.
    assert_eq!(state.raw_config.read().rules.as_ref().unwrap().len(), 2);
}

// ── PR #882 review: /configs sniffing resolution ────────────────

/// `/configs.sniffing` reports the resolved sniffer, matching how the
/// config build resolves it — the deprecated `tproxy-sni` alias
/// synthesises an enabled sniffer, and an explicit `sniffer:` block wins.
#[tokio::test]
async fn configs_sniffing_uses_resolved_sniffer() {
    let get_sniffing = |state: &Arc<AppState>| {
        let state = Arc::clone(state);
        async move {
            let resp = create_router(state)
                .oneshot(
                    Request::get("/configs")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            body_json(resp).await["sniffing"].as_bool().unwrap()
        }
    };

    // tproxy-sni alone -> sniffing on.
    let mut raw = test_raw_config();
    raw.tproxy_sni = Some(true);
    let state = test_state(raw.clone());
    assert!(get_sniffing(&state).await, "tproxy-sni alias enables");

    // An explicit `sniffer:` block wins over the alias.
    raw.sniffer = Some(meow_config::raw::RawSniffer {
        enable: Some(false),
        ..Default::default()
    });
    let state = test_state(raw);
    assert!(!get_sniffing(&state).await, "explicit sniffer wins");
}

#[tokio::test]
async fn response_rules_reload_order_provider_generation_and_rejection() {
    let _globals_lane = process_globals_lane().await;
    use base64::Engine as _;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};

    async fn code(resolver: &Resolver, name: &str) -> ResponseCode {
        let mut query = Message::new(42, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii(name).unwrap(),
            RecordType::HTTPS,
        ));
        let wire = meow_dns::DnsServer::handle_query(&query.to_vec().unwrap(), resolver)
            .await
            .unwrap();
        Message::from_vec(&wire).unwrap().metadata.response_code
    }

    let state = test_state(test_raw_config());
    let put = |yaml: &str| {
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
    };
    let first = r#"mode: rule
rules: ['MATCH,DIRECT']
rule-providers:
  selected: {type: inline, behavior: domain, payload: [one.test]}
dns:
  enable: true
  use-system-hosts: false
  nameserver: [rcode://refused]
  response-rules:
    - {match: 'rule-set:selected', action: refused}
    - {match: '*', action: nodata}
"#;
    assert_eq!(put(first).await.unwrap().status(), StatusCode::NO_CONTENT);
    let original = state.tunnel.resolver();
    assert_eq!(code(&original, "one.test").await, ResponseCode::Refused);
    assert_eq!(code(&original, "two.test").await, ResponseCode::NoError);

    let second = first.replace("payload: [one.test]", "payload: [two.test]");
    assert_eq!(put(&second).await.unwrap().status(), StatusCode::NO_CONTENT);
    let current = state.tunnel.resolver();
    assert!(!Arc::ptr_eq(&original, &current));
    assert_eq!(code(&current, "one.test").await, ResponseCode::NoError);
    assert_eq!(code(&current, "two.test").await, ResponseCode::Refused);
    assert_eq!(code(&original, "one.test").await, ResponseCode::Refused);

    // Identical raw input still binds the newly built provider generation.
    assert_eq!(put(&second).await.unwrap().status(), StatusCode::NO_CONTENT);
    let current = state.tunnel.resolver();
    let invalid = second.replace("action: nodata", "action: fake-ip");
    assert_eq!(
        put(&invalid).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(Arc::ptr_eq(&current, &state.tunnel.resolver()));
    assert_eq!(
        code(&state.tunnel.resolver(), "two.test").await,
        ResponseCode::Refused
    );

    let reordered = second.replace(
        "    - {match: 'rule-set:selected', action: refused}\n    - {match: '*', action: nodata}",
        "    - {match: '*', action: nodata}\n    - {match: 'rule-set:selected', action: refused}",
    );
    assert_eq!(
        put(&reordered).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        code(&state.tunnel.resolver(), "two.test").await,
        ResponseCode::NoError
    );
    // Pure domain rules must also detect a reorder without runtime references.
    let plain = reordered.replace("rule-set:selected", "+.test");
    assert_eq!(put(&plain).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(
        code(&state.tunnel.resolver(), "two.test").await,
        ResponseCode::NoError
    );
    let reversed = plain.replace(
        "    - {match: '*', action: nodata}\n    - {match: '+.test', action: refused}",
        "    - {match: '+.test', action: refused}\n    - {match: '*', action: nodata}",
    );
    assert_eq!(
        put(&reversed).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        code(&state.tunnel.resolver(), "two.test").await,
        ResponseCode::Refused
    );
    assert_eq!(
        put("rules: ['MATCH,DIRECT']\n").await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
}

/// Issue #974 (TV-2): a `PUT /configs` rebuild re-emits unknown-key
/// warnings — they are not one-shot startup noise. The rebuild runs inside
/// the request handler on this test's runtime, so a scoped subscriber sees
/// the warns.
#[test]
fn put_configs_warns_on_unknown_keys() {
    use base64::Engine as _;

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
    let status = tracing::subscriber::with_default(subscriber, || {
        let state = test_state_default();
        let payload = base64::engine::general_purpose::STANDARD
            .encode("api-bogus-key: 1\nrules:\n  - MATCH,DIRECT\n");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let _globals_lane = process_globals_lane().await;
                create_router(Arc::clone(&state))
                    .oneshot(
                        Request::builder()
                            .method("PUT")
                            .uri("/configs")
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(
                                serde_json::json!({"payload": payload}).to_string(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
                    .status()
            })
    });
    assert_eq!(status, StatusCode::NO_CONTENT);
    let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    assert!(
        logs.contains("unknown keys in top-level config: api-bogus-key"),
        "PUT rebuild must re-emit the unknown-key warn: {logs}"
    );
}

// ─── Named `type: tun` listeners (spec §3) ─────────────────────────────

/// PUT a base64 YAML payload into `/configs`; `query` carries `?force`
/// & friends.
async fn put_configs_payload(
    state: &Arc<AppState>,
    yaml: &str,
    query: &str,
) -> axum::response::Response {
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
    create_router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/configs{query}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Store a stand-in *named* `type: tun` device in the slot — the owner
/// the startup path publishes (`spec §3`); the pending task is what
/// owner-aware paths must not reap.
async fn install_named_tun(
    state: &Arc<AppState>,
    name: &str,
) -> Arc<std::sync::atomic::AtomicBool> {
    let (handle, stopped) = fake_tun_handle_owned(meow_tunnel::TunOwner::Named(name.to_string()));
    state.tunnel.set_tun_handle(handle).await;
    stopped
}

/// A `tun.enable` candidate must never pass admission while a named
/// `type: tun` device holds the slot — and the named device stays up.
#[tokio::test]
async fn put_configs_tun_enable_while_named_tun_owns_slot_rejected() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    let stopped = install_named_tun(&state, "edge-tun").await;
    // The request even *removes* the listeners section — the slot stays
    // owned until a restart, so the enable still rejects.
    for query in ["", "?force=true"] {
        let resp = put_configs_payload(
            &state,
            "tun:\n  enable: true\nrules:\n  - MATCH,DIRECT\n",
            query,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query {query}");
        assert!(
            body_json(resp).await["message"]
                .as_str()
                .unwrap()
                .contains("edge-tun"),
            "the error must name the owning listener, query {query}"
        );
    }
    assert!(
        !stopped.load(Ordering::SeqCst),
        "the named device must keep running"
    );
    assert!(state.tunnel.has_tun());
    assert!(
        !state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| t.enable),
        "nothing may persist"
    );
}

/// Same contract when the enable arrives inside a doc that *declares* a
/// named TUN: refused before binding/mutation/persist, `force` included
/// (the listeners-gate bail alone would be force-degradable).
#[tokio::test]
async fn put_configs_tun_enable_with_named_tun_entry_rejected() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    for query in ["", "?force=true"] {
        let resp = put_configs_payload(
            &state,
            "tun:\n  enable: true\nlisteners:\n  - name: n-tun\n    type: tun\nrules:\n  - MATCH,DIRECT\n",
            query,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query {query}");
        assert!(
            body_json(resp).await["message"]
                .as_str()
                .unwrap()
                .contains("tun.enable"),
            "the error must explain the one-effective-TUN rule, query {query}"
        );
    }
    assert!(
        !state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| t.enable),
        "nothing may persist"
    );
}

/// PATCHing `tun.enable` on is refused while a named device owns the
/// slot or the committed document still stages a named entry — a PATCH
/// cannot drop `listeners:`.
#[tokio::test]
async fn patch_configs_tun_enable_while_named_tun_rejected() {
    let _globals_lane = process_globals_lane().await;
    // (a) slot owned by a live named device
    let state = test_state(test_raw_config());
    let stopped = install_named_tun(&state, "edge-tun").await;
    let resp = patch_configs(&state, serde_json::json!({"tun": {"enable": true}})).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(!stopped.load(Ordering::SeqCst));

    // (b) no live device, but the committed document stages a named TUN
    let mut raw = test_raw_config();
    raw.listeners = Some(vec![
        serde_saphyr::from_str("name: n-tun\ntype: tun").unwrap()
    ]);
    let state = test_state(raw);
    let resp = patch_configs(&state, serde_json::json!({"tun": {"enable": true}})).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        !state
            .raw_config
            .read()
            .tun
            .as_ref()
            .is_some_and(|t| t.enable),
        "nothing may persist"
    );
}

/// The allowed shape: a PUT that disables the running top-level TUN and
/// stages a named `type: tun` entry — the former may stop, the named
/// device starts only at next boot.
#[tokio::test]
async fn put_configs_tun_disable_plus_named_tun_staged_ok() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.tun = Some(serde_saphyr::from_str("enable: true\nmtu: 1500").unwrap());
    let state = test_state(raw);
    let (handle, stopped) = fake_tun_handle();
    state.tunnel.set_tun_handle(handle).await;

    let resp = put_configs_payload(
        &state,
        "tun:\n  enable: false\nlisteners:\n  - name: n-tun\n    type: tun\nrules:\n  - MATCH,DIRECT\n",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        stopped.load(Ordering::SeqCst),
        "the running top-level device may stop"
    );
    assert!(
        !state.tunnel.has_tun(),
        "the staged named TUN must not start — next boot only"
    );
    let committed = state.raw_config.read().clone();
    assert!(
        committed
            .listeners
            .as_deref()
            .unwrap()
            .iter()
            .any(|l| l.listener_type == "tun"),
        "the named entry persists for next boot"
    );
}

/// `GET /configs` `tun-enable` reports the top-level section's device
/// only — a live named device does not read as `tun.enable`.
#[tokio::test]
async fn get_configs_tun_enable_ignores_named_tun() {
    let state = test_state(test_raw_config());
    install_named_tun(&state, "edge-tun").await;
    let json = get_configs_json(&state).await;
    assert_eq!(json["tun-enable"], serde_json::json!(false));
    assert_eq!(json["tun"]["enable"], serde_json::json!(false));
}

/// A resolver rebuild that would move the fake-IP pool while a named
/// `type: tun` device runs is refused wholesale; an unrelated resolver
/// change keeps the device alive.
#[tokio::test]
async fn put_configs_fake_ip_move_while_named_tun_runs_rejected() {
    let _globals_lane = process_globals_lane().await;
    let mut raw = test_raw_config();
    raw.dns = Some(
        serde_saphyr::from_str(
            "enable: true\nenhanced-mode: fake-ip\nfake-ip-range: 198.18.0.0/16\nnameserver: [1.1.1.1]",
        )
        .unwrap(),
    );
    let state = test_state(raw);
    let stopped = install_named_tun(&state, "edge-tun").await;
    // Give the tunnel a resolver generation carrying the committed
    // fake-IP pool (the startup would have built it the same way).
    {
        let committed = state.raw_config.read().clone();
        let dns = meow_config::parse_dns_from_raw(
            &committed,
            None,
            &Default::default(),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("dns builds");
        state
            .tunnel
            .set_resolver(Arc::clone(&dns.resolver), dns.enabled);
    }
    let pool_before = state.tunnel.resolver().fake_ip_v4_net();
    assert!(pool_before.is_some(), "the pin needs a live pool");

    // Moving `fake-ip-range` → refused, device untouched.
    let resp = put_configs_payload(
        &state,
        "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 28.0.0.0/8\n  nameserver: [1.1.1.1]\nrules:\n  - MATCH,DIRECT\n",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        !stopped.load(Ordering::SeqCst),
        "the named device must keep running"
    );
    assert_eq!(
        state.tunnel.resolver().fake_ip_v4_net(),
        pool_before,
        "the rejected pool must never publish"
    );

    // An unrelated resolver change (nameserver swap, same pool) → the
    // device is not pinned against it.
    let resp = put_configs_payload(
        &state,
        "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.0/16\n  nameserver: [9.9.9.9]\nrules:\n  - MATCH,DIRECT\n",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(state.tunnel.resolver().fake_ip_v4_net(), pool_before);
    assert!(!stopped.load(Ordering::SeqCst));
}

/// `GET /listeners` reports a `type: tun` entry's name and type without
/// port/listen — it owns no socket.
#[tokio::test]
async fn get_listeners_named_tun_reports_no_socket() {
    use meow_config::{ListenerSpec, NamedListener};
    let mut state = test_state(test_raw_config());
    Arc::get_mut(&mut state)
        .unwrap()
        .listeners
        .push(NamedListener {
            name: "edge-tun".into(),
            spec: ListenerSpec::Tun(meow_config::TunConfig::default()),
            port: 0,
            listen: String::new(),
            max_connections: 256,
            route_override: None,
            routing_mark: None,
        });
    let resp = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/listeners")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let items = body_json(resp).await;
    assert_eq!(items[0]["name"], serde_json::json!("edge-tun"));
    assert_eq!(items[0]["type"], serde_json::json!("tun"));
    assert!(
        items[0].get("port").is_none() && items[0].get("listen").is_none(),
        "a TUN owns no socket endpoint: {items}"
    );
}

/// A PUT that drops a still-running listener's forced proxy must be
/// refused even though the candidate also removes the listener — the
/// running inbound keeps its `proxy:` reference across the route swap
/// and would strand on the missing name. `?force` cannot push past it.
#[tokio::test]
async fn put_configs_refuses_dropping_running_listener_dependency() {
    use base64::Engine as _;
    use meow_config::{ListenerSpec, NamedListener};

    let raw: RawConfig = meow_config::parse_raw_yaml(concat!(
        "listeners:\n",
        "  - name: edge\n",
        "    type: mixed\n",
        "    port: 0\n",
        "    proxy: sel\n",
        "proxy-groups:\n",
        "  - name: sel\n",
        "    type: select\n",
        "    proxies: [DIRECT]\n",
        "rules:\n",
        "  - MATCH,DIRECT\n",
    ))
    .unwrap();
    let mut state = test_state(raw);
    Arc::get_mut(&mut state).unwrap().listeners = vec![NamedListener {
        name: "edge".into(),
        spec: ListenerSpec::Mixed,
        port: 0,
        listen: "127.0.0.1".into(),
        max_connections: 256,
        route_override: meow_common::InboundRouteOverride::new(Some("sel"), None),
        routing_mark: None,
    }];

    // The candidate removes the listener AND its forced group — the
    // running inbound still holds `proxy: sel`.
    let payload =
        base64::engine::general_purpose::STANDARD.encode("mode: rule\nrules:\n  - MATCH,DIRECT\n");
    for uri in ["/configs", "/configs?force=true"] {
        let resp = create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"payload": payload}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{uri} must refuse to strand the running listener's forced proxy"
        );
    }
    // Nothing committed: the group and the listener stay in the document.
    let committed = state.raw_config.read();
    assert!(
        committed
            .proxy_groups
            .as_deref()
            .is_some_and(|g| g.iter().any(|g| g.name == "sel")),
        "the refused PUT must not persist"
    );
    drop(committed);
    assert!(state.tunnel.route_snapshot().proxies.contains_key("sel"));
}

/// A `listeners[].proxy` naming nothing the document declares — or a
/// `proxy-providers:` key — is a document-shape defect: provider members
/// are not registry keys, so the name can never resolve. `?force` cannot
/// persist it the way it persists a declared name that merely failed to
/// build (environment degradation).
#[tokio::test]
async fn put_configs_refuses_undeclared_listener_proxy_under_force() {
    use base64::Engine as _;

    for (decl, needle) in [("ghost", "no declared proxy"), ("feed", "proxy-provider")] {
        let raw: RawConfig = meow_config::parse_raw_yaml("rules:\n  - MATCH,DIRECT\n").unwrap();
        let state = test_state(raw);
        let yaml = format!(
            "proxy-providers:\n  feed:\n    type: file\n    path: p.yaml\nlisteners:\n  - name: edge\n    type: mixed\n    port: 0\n    proxy: {decl}\nrules:\n  - MATCH,DIRECT\n"
        );
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        for uri in ["/configs", "/configs?force=true"] {
            let resp = create_router(Arc::clone(&state))
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            serde_json::json!({"payload": payload}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{uri} with proxy: {decl} must be refused"
            );
            let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                body["message"].as_str().is_some_and(|m| m.contains(needle)),
                "{uri} with proxy: {decl} must explain the refusal: {body}"
            );
        }
        assert!(
            state.raw_config.read().listeners.is_none(),
            "the refused PUT must not persist ({decl})"
        );
    }
}

// ─── `type: rematch` / `REMATCH-NAME` API surface (issue #974) ─────────

fn rematch_state() -> Arc<AppState> {
    let raw: RawConfig = meow_config::parse_raw_yaml(
        "proxies:\n\
         \x20 - {name: inspect, type: rematch, target-rematch-name: stage1, target-sub-rule: blk}\n\
         rules:\n\
         \x20 - DOMAIN-SUFFIX,example.test,inspect\n\
         \x20 - REMATCH-NAME,stage1/alternative,REJECT\n\
         \x20 - MATCH,DIRECT\n",
    )
    .unwrap();
    test_state(raw)
}

/// `/proxies` reports the control leaf like any node — `type: Rematch`,
/// `udp: true` (the capability gate never preempts a transition), the
/// ordinary alive/history fields — and never the action fields, which
/// are routing directives, not transport facts.
#[tokio::test]
async fn rematch_node_shows_on_proxies() {
    let state = rematch_state();
    let (status, json) = get_json(&state, "/proxies").await;
    assert_eq!(status, StatusCode::OK);
    let node = &json["proxies"]["inspect"];
    assert_eq!(node["type"], "Rematch");
    assert_eq!(node["udp"], true, "capability display matches mihomo");
    assert_eq!(node["name"], "inspect");
    assert!(
        node.get("target-rematch-name").is_none() && node.get("target-sub-rule").is_none(),
        "action fields are not transport fields: {node}"
    );
    // No built-in `REMATCH` node appeared — rematch is a node type, not
    // a reserved registry name.
    assert!(json["proxies"].get("REMATCH").is_none());

    let (status, one) = get_json(&state, "/proxies/inspect").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(one["type"], "Rematch");
}

/// `/rules` reports the API spelling `RematchName` with the raw payload
/// preserved.
#[tokio::test]
async fn rematch_name_rule_shows_on_rules() {
    let state = rematch_state();
    let (status, json) = get_json(&state, "/rules").await;
    assert_eq!(status, StatusCode::OK);
    let rules = json["rules"].as_array().unwrap();
    let rematch = rules
        .iter()
        .find(|r| r["type"] == "RematchName")
        .expect("the REMATCH-NAME rule must be listed");
    assert_eq!(rematch["payload"], "stage1/alternative");
    assert_eq!(rematch["proxy"], "REJECT");
}

/// A delay probe of the control leaf fails through ordinary transport
/// failure — no socket opens, no rule scan runs, no routing side
/// effects. mihomo reports it as a generic delay-test error (503).
#[tokio::test]
async fn rematch_leaf_delay_fails_as_transport_error() {
    let state = rematch_state();
    let (status, _) = get_json(
        &state,
        "/proxies/inspect/delay?url=http://cp.cloudflare.com&timeout=2000",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the leaf's control-outbound dial error maps to mihomo's delay-test 503"
    );
}

/// A structurally unsafe rematch document must never commit verbatim:
/// under `?force`, an environmentally unbuildable candidate retains the
/// old live routing — but only after the verbatim store is gated. Both
/// shapes below (malformed node, malformed predicate) are *shape*, so
/// the fallback refuses them and the committed document does not move
/// (issue #974).
#[tokio::test]
async fn put_configs_force_gates_malformed_rematch() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    // Duplicate group names fail strict AND lenient — the verbatim
    // fallback is the only path the candidates below can reach.
    const UNBUILDABLE: &str = "proxy-groups:\n\
         \x20 - {name: dup, type: select, proxies: [DIRECT]}\n\
         \x20 - {name: dup, type: select, proxies: [REJECT]}\n";

    // A rematch node with neither target field.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n  - {{name: inspect, type: rematch}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A `dialer-proxy` on a rematch node — same class of shape defect.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n  - {{name: inspect, type: rematch, target-rematch-name: x, dialer-proxy: front}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The reverse edge fails the same gate: a transport node chaining
    // through a rematch leaf is the build's hard `dialer-proxy` error —
    // a rematch cannot carry a transport hop (issue #974).
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n\
             \x20 - {{name: front, type: rematch, target-rematch-name: x}}\n\
             \x20 - {{name: node, type: direct, dialer-proxy: front}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A malformed REMATCH-NAME predicate (empty alternative) — no
    // `sub-rules:` section needed for the gate to see it.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             rules:\n  - REMATCH-NAME,a//b,REJECT\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A relay's static `proxies:` member naming a rematch leaf — the
    // build's relay-membership hard error: a rematch can never carry a
    // transport hop (issue #974).
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             \x20 - {{name: chain, type: relay, proxies: [DIRECT, inspect]}}\n\
             proxies:\n  - {{name: inspect, type: rematch, target-rematch-name: x}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The `include-all-proxies` expansion is a static membership too —
    // it would absorb the declared leaf.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             \x20 - {{name: chain, type: relay, include-all-proxies: true}}\n\
             proxies:\n  - {{name: inspect, type: rematch, target-rematch-name: x}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The same predicate nested inside a `sub-rules:` block — the gate
    // reaches predicate leaves through the block map too.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             rules:\n  - SUB-RULE,(DOMAIN-SUFFIX,x.test),blk\n  - MATCH,DIRECT\n\
             sub-rules:\n  blk:\n    - REMATCH-NAME,,REJECT\n    - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        state.raw_config.read().rules.as_deref()
            == Some(&[
                "DOMAIN,example.com,DIRECT".to_string(),
                "MATCH,REJECT".to_string()
            ]),
        "the rejected documents must not replace the committed rules"
    );

    // Structurally sound rematch content still commits verbatim.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n  - {{name: inspect, type: rematch, target-rematch-name: stage1}}\n\
             rules:\n  - REMATCH-NAME,stage1,REJECT\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "sound rematch shape commits even when the live build cannot"
    );
    {
        let raw = state.raw_config.read();
        assert!(
            raw.proxies.as_deref().is_some_and(|p| p
                .iter()
                .any(|n| n.get("type").and_then(|t| t.as_str()) == Some("rematch"))),
            "the committed document keeps the rematch node"
        );
    }

    // …but the live route table is untouched — the verbatim commit
    // must not report the rematch graph as installed.
    let (status, json) = get_json(&state, "/proxies").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        json["proxies"].get("inspect").is_none(),
        "live routing still runs the retained generation: {json}"
    );
    let (status, json) = get_json(&state, "/rules").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        json["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["type"] != "RematchName"),
        "live rules are still the retained generation's: {json}"
    );

    // A *group* member is a dynamic pick — not gated: the build leaves
    // its rematch selection to the probe, so the verbatim gate does too.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             \x20 - {{name: chain, type: relay, proxies: [DIRECT, sel]}}\n\
             \x20 - {{name: sel, type: select, proxies: [inspect]}}\n\
             proxies:\n  - {{name: inspect, type: rematch, target-rematch-name: x}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a group member's dynamic rematch pick is not a static-membership defect"
    );

    // The gate judges the edges that will actually bind, like the
    // build: a shadowed duplicate's raw `dialer-proxy` never becomes an
    // edge — the last declaration wins — so the candidate commits
    // rather than tripping the rematch-edge check (issue #974).
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n\
             \x20 - {{name: inspect, type: rematch, target-rematch-name: x}}\n\
             \x20 - {{name: node, type: direct, dialer-proxy: inspect}}\n\
             \x20 - {{name: node, type: direct}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a shadowed duplicate's dialer-proxy is no edge the build binds"
    );

    // Same for a leaf shadowing a built-in: the build drops the entry,
    // so its `dialer-proxy` never becomes an edge either.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n\
             \x20 - {{name: inspect, type: rematch, target-rematch-name: x}}\n\
             \x20 - {{name: DIRECT, type: direct, dialer-proxy: inspect}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a built-in-shadowed node's dialer-proxy is no edge the build binds"
    );

    // The name side is last-wins too: a rematch declaration shadowed by
    // a same-named transport never becomes the leaf a member binds —
    // the build's map holds `x` as direct, so the candidate commits
    // rather than tripping the relay-membership check (issue #974).
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             \x20 - {{name: chain, type: relay, proxies: [DIRECT, x]}}\n\
             proxies:\n\
             \x20 - {{name: x, type: rematch, target-rematch-name: s}}\n\
             \x20 - {{name: x, type: direct}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a shadowed rematch declaration is not the leaf the relay member binds"
    );

    // Same shadow on the dialer edge: `dialer-proxy: x` binds the
    // shadowing transport, not the dropped rematch declaration.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n\
             \x20 - {{name: x, type: rematch, target-rematch-name: s}}\n\
             \x20 - {{name: x, type: direct}}\n\
             \x20 - {{name: node, type: direct, dialer-proxy: x}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a shadowed rematch declaration is not the edge's target either"
    );

    // And a built-in shadow: `name: DIRECT` never binds — the built-in
    // stays, so relay member DIRECT is legal whatever the entry's type.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             \x20 - {{name: chain, type: relay, proxies: [DIRECT, REJECT]}}\n\
             proxies:\n  - {{name: DIRECT, type: rematch, target-rematch-name: s}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a built-in-shadowed rematch declaration binds no member either"
    );
}

/// The same verbatim-commit obligation for `type: dns` (issue #974
/// review): the force path never ran the build's structural gate, so
/// shape defects the next boot would hard-fail — a nameless dns node, a
/// transport chaining a dialer hop through a dns leaf, a relay member
/// or `include-all-proxies` naming one — are refused rather than
/// committed. The name set is the CONSERVATIVE `declared_dns_names`
/// view: any raw dns declaration marks the name, since a later shadow
/// may warn-drop and leave the dns binding standing.
#[tokio::test]
async fn put_configs_force_gates_malformed_dns_nodes() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    // Duplicate group names fail strict AND lenient — the verbatim
    // fallback is the only path the candidates below can reach.
    const UNBUILDABLE: &str = "proxy-groups:\n\
         \x20 - {name: dup, type: select, proxies: [DIRECT]}\n\
         \x20 - {name: dup, type: select, proxies: [REJECT]}\n";

    // A dns node without a `name` is the one structural defect the type
    // has — everything else it tolerates by contract.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n  - {{type: dns}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The reverse edge is the build's hard error: a transport node
    // chaining through a dns leaf — the leaf answers in-process, it
    // never dials a hop.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n\
             \x20 - {{name: dns-out, type: dns}}\n\
             \x20 - {{name: node, type: direct, dialer-proxy: dns-out}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The conservative half of the name set: the same edge is still
    // refused when a LATER same-named transport shadows the dns decl —
    // lenient parse can warn-drop the shadow and leave the dns binding
    // effective, so the verbatim lane cannot trust last-wins.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n\
             \x20 - {{name: x, type: dns}}\n\
             \x20 - {{name: x, type: direct}}\n\
             \x20 - {{name: node, type: direct, dialer-proxy: x}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A relay's static `proxies:` member naming a dns leaf — the leaf
    // can never carry a transport hop.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             \x20 - {{name: chain, type: relay, proxies: [DIRECT, dns-out]}}\n\
             proxies:\n  - {{name: dns-out, type: dns}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // `include-all-proxies` would absorb the declared leaf — a static
    // membership too.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             \x20 - {{name: chain, type: relay, include-all-proxies: true}}\n\
             proxies:\n  - {{name: dns-out, type: dns}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A built-in shadow never binds the leaf: `name: DIRECT` typed dns
    // stays the built-in, so relay member DIRECT is legal.
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             \x20 - {{name: chain, type: relay, proxies: [DIRECT, REJECT]}}\n\
             proxies:\n  - {{name: DIRECT, type: dns}}\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Sound dns content still commits verbatim — including the leaf's
    // own `dialer-proxy`, which binds no edge and is ignored by contract
    // (the committed document keeps the node).
    let resp = put_configs_payload(
        &state,
        &format!(
            "mode: rule\n{UNBUILDABLE}\
             proxies:\n  - {{name: dns-out, type: dns, dialer-proxy: front}}\n\
             rules:\n  - DST-PORT,53,dns-out\n  - MATCH,DIRECT\n"
        ),
        "?force=true",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a well-formed dns node commits even when the live build cannot"
    );
    {
        let raw = state.raw_config.read();
        assert!(
            raw.proxies.as_deref().is_some_and(|p| p
                .iter()
                .any(|n| n.get("type").and_then(|t| t.as_str()) == Some("dns"))),
            "the committed document keeps the dns node"
        );
    }
}

/// A plain `PUT /configs` (no `force`) rebuilds rematch content live:
/// the node is dialed by the route engine and the rule is listed in
/// the new generation.
#[tokio::test]
async fn put_configs_reloads_rematch_live() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    let resp = put_configs_payload(
        &state,
        "mode: rule\n\
         proxies:\n  - {name: inspect, type: rematch, target-rematch-name: stage1, target-sub-rule: blk}\n\
         rules:\n  - DOMAIN-SUFFIX,example.test,inspect\n  - REMATCH-NAME,stage1,REJECT\n  - MATCH,DIRECT\n\
         sub-rules:\n  blk:\n    - REMATCH-NAME,stage1,REJECT\n    - MATCH,DIRECT\n",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let (status, json) = get_json(&state, "/proxies/inspect").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["type"], "Rematch");
    let (status, json) = get_json(&state, "/rules").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        json["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["type"] == "RematchName" && r["payload"] == "stage1"),
        "the rebuilt generation installs the predicate: {json}"
    );
}

/// Issue #974 review: a `type: dns` leaf surfaces on `/proxies/{name}`
/// like any route-table entry — `type: "Dns"`, `udp: true` (the leaf
/// serves framed UDP exchanges in-process), and no endpoint address:
/// `addr()` is `""` and the JSON shape carries no server field a client
/// could misread as dialable.
#[tokio::test]
async fn get_proxy_reports_dns_leaf_shape() {
    let _globals_lane = process_globals_lane().await;
    let state = test_state(test_raw_config());
    let resp = put_configs_payload(
        &state,
        "mode: rule\n\
         proxies:\n  - {name: dns-out, type: dns}\n\
         rules:\n  - DST-PORT,53,dns-out\n  - MATCH,DIRECT\n",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let (status, json) = get_json(&state, "/proxies/dns-out").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["name"], "dns-out");
    assert_eq!(json["type"], "Dns");
    assert_eq!(json["udp"], true);
    assert!(
        json.get("server").is_none() && json.get("address").is_none(),
        "a dns leaf advertises no endpoint: {json}"
    );
}

/// A group delay round probes a rematch member like any other — it is
/// scheduled, fails through the ordinary transport-error path, is left
/// out of the result map, and records the failed probe. mihomo has no
/// rematch-type exclusion in its health check; the leaf's own control
/// error is what stops the dial — no socket, rule scan, or DNS lookup
/// runs for it.
#[tokio::test]
async fn rematch_member_group_delay_reports_failed_probe() {
    let ok = TestAdapter::new("ok", DialBehavior::InstantOk).into_proxy();
    let rematch: Arc<dyn Proxy> = Arc::new(meow_config::proxy_parser::WrappedProxy::new(Box::new(
        meow_proxy::RematchAdapter::new("inspect", Some("stage1"), None),
    )));
    let group = fallback_group("G", vec![Arc::clone(&rematch), Arc::clone(&ok)]);
    let state = state_with_proxies(vec![
        ("inspect", Arc::clone(&rematch)),
        ("ok", Arc::clone(&ok)),
        ("G", group),
    ]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    assert_eq!(
        body.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["ok"],
        "the rematch member's probe fails and is left out: {body}"
    );
    let history = rematch.delay_history();
    assert_eq!(history.len(), 1, "the failed probe is still recorded");
    assert_eq!(history[0].delay, 0, "recorded as down");
}
