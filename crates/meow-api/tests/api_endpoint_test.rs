//! Issue #974 — the extended controller surface: `external-controller-tls`,
//! `external-controller-unix`, `external-controller-pipe` and
//! `external-controller-cors`. Wire-level tests for the configured-path
//! CORS middleware and the TLS/Unix endpoint transports.

use axum::http::{header, Request, StatusCode};
use dashmap::DashMap;
use meow_api::routes::{create_router, AppState};
use meow_common::DnsMode;
use meow_config::raw::RawConfig;
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower::ServiceExt;

fn test_raw_config() -> RawConfig {
    RawConfig {
        mixed_port: Some(7890),
        mode: Some("rule".into()),
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    }
}

fn test_state(cors: meow_config::ApiCorsConfig, secret: Option<&str>) -> Arc<AppState> {
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

    Arc::new(AppState {
        tunnel,
        secret: secret.map(str::to_owned),
        config_path: None,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: broadcast::channel(16).0,
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
        cors,
    })
}

async fn body_string(resp: axum::response::Response) -> String {
    use http_body_util::BodyExt;
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn vary_values(resp: &axum::response::Response) -> Vec<String> {
    resp.headers()
        .get_all(header::VARY)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

fn preflight(
    origin: &str,
    method: &str,
    req_headers: Option<&str>,
    pna: bool,
) -> Request<axum::body::Body> {
    let mut b = Request::builder()
        .method("OPTIONS")
        .uri("/")
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, method);
    if let Some(h) = req_headers {
        b = b.header(header::ACCESS_CONTROL_REQUEST_HEADERS, h);
    }
    if pna {
        b = b.header("access-control-request-private-network", "true");
    }
    b.body(axum::body::Body::empty()).unwrap()
}

// ── absent map → configured defaults ────────────────────────────────
//
// Probe-corrected (issue #974): under a configured secret an absent
// `external-controller-cors:` map serves the configured `cors.New` path
// on `["*"]`/`true` defaults — upstream's permissive AllowAll fires only
// on an explicit `secret: ""`, which meow serves no CORS for at all.

#[tokio::test]
async fn cors_absent_map_preflight_uses_configured_defaults() {
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight(
            "https://dashboard.example",
            "GET",
            Some("authorization, content-type"),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    // The resolved defaults are `["*"]`/`true`, so the allow-all `*`
    // rides `ACAO` — but everything else is the configured shape.
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_METHODS], "GET");
    assert_eq!(
        h[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "Authorization, Content-Type"
    );
    assert_eq!(h[header::ACCESS_CONTROL_MAX_AGE], "300");
    assert_eq!(
        vary_values(&resp),
        vec![
            "origin",
            "access-control-request-method",
            "access-control-request-headers"
        ]
    );
}

#[tokio::test]
async fn cors_absent_map_preflight_denies_unlisted_request_header() {
    // The configured-path header allowlist applies even to absent-map
    // defaults — `x-anything` denies the whole grant.
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight(
            "https://dashboard.example",
            "GET",
            Some("authorization, x-anything"),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert!(!h.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert!(!h.contains_key(header::ACCESS_CONTROL_ALLOW_METHODS));
    assert_eq!(
        vary_values(&resp),
        vec![
            "origin",
            "access-control-request-method",
            "access-control-request-headers"
        ]
    );
}

#[tokio::test]
async fn cors_absent_map_actual_request_uses_defaults() {
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::ORIGIN, "https://dashboard.example")
                .header(header::AUTHORIZATION, "Bearer s3cret")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert_eq!(vary_values(&resp), vec!["origin"]);
}

#[tokio::test]
async fn cors_no_secret_mode_emits_no_grants() {
    // Deliberate divergence (issue #974): without a controller secret the
    // CORS middleware is not mounted at all — the origin guard answers a
    // cross-origin preflight with 403 and no CORS headers ride.
    let state = test_state(configured(&["*"], true), None);
    let resp = create_router(state)
        .oneshot(preflight("https://any.example", "GET", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(!resp
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert!(vary_values(&resp).is_empty());
}

#[tokio::test]
async fn cors_absent_map_no_origin_gets_vary_only() {
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer s3cret")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert_eq!(vary_values(&resp), vec!["origin"]);
}

// ── configured-map path ─────────────────────────────────────────────

fn configured(origins: &[&str], pna: bool) -> meow_config::ApiCorsConfig {
    meow_config::ApiCorsConfig {
        allow_origins: origins.iter().map(ToString::to_string).collect(),
        allow_private_network: pna,
    }
}

#[tokio::test]
async fn cors_configured_echoes_origin_and_mirrors_request() {
    let state = test_state(configured(&["https://ok.example"], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight(
            "https://ok.example",
            "put",
            Some("authorization,content-type"),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://ok.example");
    // The one requested method, uppercased.
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_METHODS], "PUT");
    // Requested headers echoed canonicalized, in request order.
    assert_eq!(
        h[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "Authorization, Content-Type"
    );
    assert_eq!(h[header::ACCESS_CONTROL_MAX_AGE], "300");
    assert_eq!(h["access-control-allow-private-network"], "true");
    assert_eq!(
        vary_values(&resp),
        vec![
            "origin",
            "access-control-request-method",
            "access-control-request-headers"
        ]
    );
}

#[tokio::test]
async fn cors_configured_denied_origin_preflight() {
    let state = test_state(configured(&["https://ok.example"], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight("https://evil.example", "GET", None, false))
        .await
        .unwrap();
    // Denied preflights still answer 200 — but only the vary trio rides.
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert!(!resp
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS));
    assert!(!resp.headers().contains_key(header::ACCESS_CONTROL_MAX_AGE));
    assert_eq!(
        vary_values(&resp),
        vec![
            "origin",
            "access-control-request-method",
            "access-control-request-headers"
        ]
    );
}

#[tokio::test]
async fn cors_configured_head_method_denied() {
    let state = test_state(configured(&["*"], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight("https://any.example", "HEAD", None, false))
        .await
        .unwrap();
    // The allowed-methods set has no HEAD — denied like a foreign origin.
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}

#[tokio::test]
async fn cors_configured_head_actual_gets_no_acao() {
    // Upstream gates the actual request on the same allowlist as the
    // preflight: an allowed origin doing an actual HEAD still earns no
    // Access-Control-Allow-Origin (issue #974).
    let state = test_state(configured(&["https://ok.example"], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/")
                .header(header::ORIGIN, "https://ok.example")
                .header(header::AUTHORIZATION, "Bearer s3cret")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert_eq!(vary_values(&resp), vec!["origin"]);
}

#[tokio::test]
async fn cors_configured_denied_request_header_denies_whole_preflight() {
    // `AllowedHeaders` upstream is {content-type, authorization, origin};
    // one unsupported requested header denies the whole grant — it is
    // not trimmed to the allowed subset (issue #974).
    let state = test_state(configured(&["*"], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight(
            "https://any.example",
            "GET",
            Some("content-type,x-custom-header"),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert!(!resp
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_HEADERS));
    assert_eq!(
        vary_values(&resp),
        vec![
            "origin",
            "access-control-request-method",
            "access-control-request-headers"
        ]
    );

    // Case-insensitive allowlist: `ORIGIN` passes like `origin`.
    let state = test_state(configured(&["*"], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight(
            "https://any.example",
            "GET",
            Some("ORIGIN,Authorization"),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert_eq!(
        resp.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "Origin, Authorization"
    );
}

#[tokio::test]
async fn cors_configured_wildcard_replies_star() {
    let state = test_state(configured(&["*"], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight("https://any.example", "GET", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    // Max-Age 300 rides the configured path even for `*`.
    assert_eq!(resp.headers()[header::ACCESS_CONTROL_MAX_AGE], "300");
    assert_eq!(
        vary_values(&resp),
        vec![
            "origin",
            "access-control-request-method",
            "access-control-request-headers"
        ]
    );
}

#[tokio::test]
async fn cors_configured_empty_origins_means_allow_all() {
    // Weird-but-real, probe-verified: `allow-origins: []` is allow-all,
    // not deny-all.
    let state = test_state(configured(&[], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight("https://any.example", "GET", None, false))
        .await
        .unwrap();
    assert_eq!(resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
}

#[tokio::test]
async fn cors_configured_glob_origin_match() {
    let state = test_state(configured(&["https://*.example.com"], true), Some("s3cret"));
    let resp = create_router(Arc::clone(&state))
        .oneshot(preflight("https://a.example.com", "GET", None, false))
        .await
        .unwrap();
    assert_eq!(
        resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://a.example.com"
    );
    // …and the same glob denies a non-suffix origin, case-insensitively.
    let resp = create_router(state)
        .oneshot(preflight("https://a.Example.Com", "GET", None, false))
        .await
        .unwrap();
    assert_eq!(
        resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://a.Example.Com"
    );
}

#[tokio::test]
async fn cors_configured_pna_requires_request_header() {
    let state = test_state(configured(&["*"], true), Some("s3cret"));
    // Flag on but the preflight did not ask for private-network access.
    let resp = create_router(Arc::clone(&state))
        .oneshot(preflight("https://any.example", "GET", None, false))
        .await
        .unwrap();
    assert!(!resp
        .headers()
        .contains_key("access-control-allow-private-network"));
    // Flag off → never emitted even when the request asks.
    let state = test_state(configured(&["*"], false), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight("https://any.example", "GET", None, true))
        .await
        .unwrap();
    assert!(!resp
        .headers()
        .contains_key("access-control-allow-private-network"));
}

#[tokio::test]
async fn cors_bare_options_reaches_router_as_405() {
    // No Origin + no requested method → not a preflight, falls through to
    // the router, which has no OPTIONS handler on `/`.
    let state = test_state(configured(&["*"], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer s3cret")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ── `Allow` header (upstream wire parity, issue #974) ───────────────
//
// chi emits `Allow` only on a real 405 — one header line per registered
// method — while axum's method router attaches a combined `allow:` (with
// the implicit `HEAD`) to every response through its method fallback,
// preflights and auth rejections included. `create_router` wraps the
// routes in a response map that strips it off non-405s and rewrites the
// 405 into chi's shape.

#[tokio::test]
async fn allow_header_absent_on_preflights() {
    // Allowed preflight (absent map → configured defaults).
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight("https://any.example", "GET", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp.headers().contains_key(header::ALLOW));

    // Denied configured preflight answers 200 too — also no `allow`.
    let state = test_state(configured(&["https://ok.example"], true), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(preflight("https://evil.example", "GET", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp.headers().contains_key(header::ALLOW));
}

#[tokio::test]
async fn allow_header_absent_on_auth_rejection() {
    // A bare OPTIONS with no token is answered by the auth middleware's
    // 401 — upstream's wire carries no `allow` there either.
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(!resp.headers().contains_key(header::ALLOW));
}

#[tokio::test]
async fn allow_header_405_uses_chi_per_method_lines() {
    // `/configs` registers GET+PUT+PATCH — the 405 emits one `Allow:` line
    // per method in upstream's order, and no implicit `HEAD`.
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/configs")
                .header(header::AUTHORIZATION, "Bearer s3cret")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    let allows: Vec<String> = resp
        .headers()
        .get_all(header::ALLOW)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(allows, vec!["GET", "PUT", "PATCH"]);
    // chi's CORS middleware's `vary: Origin` rides its 405s too.
    assert_eq!(vary_values(&resp), vec!["origin"]);

    // A non-OPTIONS unhandled method takes the same fallback path — same
    // shape on `/`, which registers only GET.
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer s3cret")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    let allows: Vec<String> = resp
        .headers()
        .get_all(header::ALLOW)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(allows, vec!["GET"]);
}

#[tokio::test]
async fn connect_without_valid_upgrade_gets_405_not_route_body() {
    // CONNECT is registered on the WS routes only to carry an RFC 8441
    // upgrade — anything else is upstream's 405 for the GET-only route,
    // never the JSON body (which would fake a tunnel) (issue #974).
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method("CONNECT")
                .uri("/memory")
                .header(header::AUTHORIZATION, "Bearer s3cret")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    let allows: Vec<String> = resp
        .headers()
        .get_all(header::ALLOW)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(allows, vec!["GET"]);

    // Same answer when the request *tries* to look like an upgrade but
    // cannot complete one (HTTP/1.1 CONNECT is never upgradable).
    let state = test_state(Default::default(), Some("s3cret"));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method("CONNECT")
                .uri("/memory")
                .header(header::AUTHORIZATION, "Bearer s3cret")
                .header(header::UPGRADE, "websocket")
                .header(header::SEC_WEBSOCKET_VERSION, "13")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ── TLS endpoint (cfg(feature = "api-tls")) ─────────────────────────

// The whole section needs `boring`/`tokio_boring`, which are optional
// deps of the crate — present only when `api-tls` compiled the endpoint
// (issue #974).
#[cfg(feature = "api-tls")]
mod tls {
    use super::*;

    #[tokio::test]
    async fn tls_endpoint_serves_https_and_negotiates_alpn() {
        let state = test_state(Default::default(), Some("s3cret"));
        // Ephemeral identity — no tls.certificate/tls.private-key.
        let endpoint = meow_api::endpoint::bind_tls("127.0.0.1:0", None, None)
            .await
            .unwrap();
        let addr = endpoint.addr();
        tokio::spawn(async move { axum::serve(endpoint, create_router(state)).await });

        // h2-only offer: the acceptor must negotiate it (upstream probe
        // verified ALPN advertises `h2` first, then `http/1.1`) — and axum's
        // `http2` feature must actually serve a real HTTP/2 request, not
        // just negotiate the protocol.
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut builder =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
        builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        builder.set_alpn_protos(b"\x02h2").unwrap();
        let connector = builder.build();
        let tls = tokio_boring::connect(connector.configure().unwrap(), "localhost", stream)
            .await
            .unwrap();
        assert_eq!(tls.ssl().selected_alpn_protocol(), Some(b"h2".as_slice()));
        let (client, conn) = h2::client::handshake(tls).await.unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let req = axum::http::Request::builder()
            .uri("https://localhost/")
            .header(header::AUTHORIZATION, "Bearer s3cret")
            .body(())
            .unwrap();
        let (resp_fut, _send) = client
            .ready()
            .await
            .unwrap()
            .send_request(req, true)
            .unwrap();
        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let mut body = resp.into_body();
        let mut payload = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            let _ = body.flow_control().release_capacity(chunk.len());
            payload.extend_from_slice(&chunk);
        }
        assert_eq!(String::from_utf8(payload).unwrap(), "{\"hello\":\"meow\"}");

        // http/1.1-only offer: negotiated http/1.1 and a real request answers
        // the shared router — auth enforced like every other transport.
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut builder =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
        builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        builder.set_alpn_protos(b"\x08http/1.1").unwrap();
        let connector = builder.build();
        let mut tls = tokio_boring::connect(connector.configure().unwrap(), "localhost", stream)
            .await
            .unwrap();
        assert_eq!(
            tls.ssl().selected_alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tls.write_all(
        b"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer s3cret\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("{\"hello\":\"meow\"}"), "{text}");
    }

    #[tokio::test]
    async fn tls_endpoint_h2_extended_connect_serves_websocket() {
        // axum::serve advertises SETTINGS_ENABLE_CONNECT_PROTOCOL on h2
        // with no opt-out (hardwired in its connection builder), so the WS
        // routes must serve real RFC 8441 extended CONNECT upgrades:
        // `:protocol: websocket` + `?token` auth → 200, then WS frames
        // flow on the stream's DATA (issue #974).
        let state = test_state(Default::default(), Some("s3cret"));
        let endpoint = meow_api::endpoint::bind_tls("127.0.0.1:0", None, None)
            .await
            .unwrap();
        let addr = endpoint.addr();
        tokio::spawn(async move { axum::serve(endpoint, create_router(state)).await });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut builder =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
        builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        builder.set_alpn_protos(b"\x02h2").unwrap();
        let connector = builder.build();
        let tls = tokio_boring::connect(connector.configure().unwrap(), "localhost", stream)
            .await
            .unwrap();
        let (client, conn) = h2::client::handshake(tls).await.unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });

        async fn ws_connect(
            client: &h2::client::SendRequest<bytes::Bytes>,
            uri: &str,
        ) -> (h2::client::ResponseFuture, h2::SendStream<bytes::Bytes>) {
            let mut req = axum::http::Request::builder()
                .method(axum::http::Method::CONNECT)
                .uri(uri)
                .header("sec-websocket-version", "13")
                .body(())
                .unwrap();
            req.extensions_mut()
                .insert(h2::ext::Protocol::from_static("websocket"));
            client
                .clone()
                .ready()
                .await
                .unwrap()
                .send_request(req, false)
                .unwrap()
        }

        // Bearer still gates extended CONNECT — no credential → 401.
        let (resp_fut, _send) = ws_connect(&client, "https://localhost/memory").await;
        assert_eq!(resp_fut.await.unwrap().status(), StatusCode::UNAUTHORIZED);

        // `?token=` is honored on h2 CONNECT like the HTTP/1.1 upgrade
        // path (browser WS clients cannot set headers on either).
        let (resp_fut, _send) = ws_connect(&client, "https://localhost/memory?token=s3cret").await;
        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // /memory's WS arm writes its first frame immediately — the
        // upgraded stream's DATA must carry a real WebSocket text frame.
        let mut recv = resp.into_body();
        let mut payload = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !payload.windows(5).any(|w| w == b"inuse") {
                let Some(chunk) = recv.data().await else {
                    break;
                };
                let chunk = chunk.unwrap();
                let _ = recv.flow_control().release_capacity(chunk.len());
                payload.extend_from_slice(&chunk);
            }
        })
        .await
        .expect("timed out waiting for the websocket frame");
        assert!(payload.windows(5).any(|w| w == b"inuse"), "{payload:?}");
    }

    #[tokio::test]
    async fn tls_endpoint_marks_https_scheme_for_origin_guard() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // No secret → the browser origin guard (not Bearer) gates requests.
        // `serve_tls_on` inserts the TlsTransport marker so a same-origin
        // `https://` dashboard over HTTP/1.1 is not rejected as cross-scheme
        // (issue #974); `http://` still is.
        let state = test_state(Default::default(), None);
        let endpoint = meow_api::endpoint::bind_tls("127.0.0.1:0", None, None)
            .await
            .unwrap();
        let addr = endpoint.addr();
        let app = create_router(state).layer(axum::middleware::from_fn(
            meow_api::routes::mark_tls_transport,
        ));
        tokio::spawn(async move { axum::serve(endpoint, app).await });

        async fn https_get(addr: std::net::SocketAddr, origin: &str) -> String {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut builder =
                boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
            builder.set_verify(boring::ssl::SslVerifyMode::NONE);
            let connector = builder.build();
            let mut tls =
                tokio_boring::connect(connector.configure().unwrap(), "localhost", stream)
                    .await
                    .unwrap();
            tls.write_all(
                format!(
                "GET / HTTP/1.1\r\nHost: {addr}\r\nOrigin: {origin}\r\nConnection: close\r\n\r\n"
            )
                .as_bytes(),
            )
            .await
            .unwrap();
            let mut buf = Vec::new();
            tls.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        }

        let resp = https_get(addr, &format!("https://{addr}")).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("{\"hello\":\"meow\"}"), "{resp}");
        let resp = https_get(addr, &format!("http://{addr}")).await;
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    }

    #[tokio::test]
    async fn tls_endpoint_configured_pem_pair() {
        // A configured inline-PEM identity loads instead of the ephemeral one.
        let (cert_pem, key_pem) = self_signed_pem();
        let cert = String::from_utf8(cert_pem).unwrap();
        let key = String::from_utf8(key_pem).unwrap();
        meow_api::endpoint::bind_tls("127.0.0.1:0", Some(&cert), Some(&key))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn tls_endpoint_rebinds_through_time_wait() {
        // SO_REUSEADDR on the raw dual-stack socket: the `[::]` path
        // binds through socket2, which unlike std's TcpListener::bind
        // does not set the flag — without it a restart overlapping
        // TIME_WAIT sockets on the port gets EADDRINUSE (issue #974).
        let endpoint = meow_api::endpoint::bind_tls(":0", None, None)
            .await
            .unwrap();
        let port = endpoint.addr().port();
        // A real handshake first — the accepted SslStream lands in the
        // endpoint's ready queue. Dropping the endpoint then drops the
        // queued stream, so the server side closes first with an
        // orderly FIN — the only close that parks the accepted socket
        // in TIME_WAIT (a failed-handshake RST would not).
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut builder =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
        builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        let connector = builder.build();
        let mut client = tokio_boring::connect(connector.configure().unwrap(), "localhost", stream)
            .await
            .unwrap();
        drop(endpoint);
        // The server's FIN must actually arrive: read until EOF, then
        // answer with the client's own close to finish the exchange —
        // the accepted socket is TIME_WAIT only once both FINs cross.
        use tokio::io::AsyncReadExt;
        let eof = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut buf = [0u8; 64];
            loop {
                match client.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(eof.is_ok(), "server kept the conn open");
        drop(client);
        // A beat for the last FIN+ACK to land server-side.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        #[cfg(unix)]
        {
            // Prove the premise before crediting SO_REUSEADDR: a socket
            // without the flag still gets EADDRINUSE — the TIME_WAIT is
            // really there. (Winsock binds over TIME_WAIT by default, so
            // this probe is unix-shaped only.)
            let probe =
                socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None).unwrap();
            probe.set_only_v6(false).unwrap();
            let bind_addr: std::net::SocketAddr = format!("[::]:{port}").parse().unwrap();
            let err = probe.bind(&socket2::SockAddr::from(bind_addr)).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::AddrInUse,
                "no TIME_WAIT on the port — the orderly close did not happen"
            );
        }
        let rebound = meow_api::endpoint::bind_tls(&format!(":{port}"), None, None)
            .await
            .expect("rebind must succeed over lingering TIME_WAIT");
        // The dual-stack candidate itself bound — a v4 fallback could
        // not produce a v6 address, so this proves reuse on the raw
        // socket rather than a silently degraded bind.
        assert!(rebound.addr().is_ipv6());
    }

    #[tokio::test]
    async fn tls_endpoint_localhost_binds_v4() {
        // Hostname listen addresses resolve v4-first (issue #974): the
        // bound endpoint lands on 127.0.0.1, not ::1.
        let endpoint = meow_api::endpoint::bind_tls("localhost:0", None, None)
            .await
            .unwrap();
        assert!(endpoint.addr().is_ipv4(), "{}", endpoint.addr());
    }

    #[tokio::test]
    async fn tls_endpoint_bad_pair_and_bad_addr_fail() {
        // One-sided pairs are endpoint-local failures upstream (config build
        // and `-t` stay shape-only, issue #974) — the endpoint bind refuses.
        assert!(meow_api::endpoint::bind_tls(
            "127.0.0.1:0",
            Some("-----BEGIN CERTIFICATE-----"),
            None
        )
        .await
        .is_err());
        // Garbage PEM bytes fail the acceptor build.
        assert!(meow_api::endpoint::bind_tls(
            "127.0.0.1:0",
            Some("-----BEGIN CERTIFICATE-----\nbogus\n-----END CERTIFICATE-----"),
            Some("-----BEGIN PRIVATE KEY-----\nbogus\n-----END PRIVATE KEY-----")
        )
        .await
        .is_err());
        // An unresolvable listen address fails the same way.
        assert!(
            meow_api::endpoint::bind_tls("no-such-host.invalid:0", None, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn tls_endpoint_mixed_inline_and_path_fails_without_leaking_material() {
        // A mixed pair (one inline PEM, one file path) is rejected before
        // path resolution — upstream refuses it and the error must never
        // embed the inline PEM text as if it were a filesystem path
        // (issue #974).
        let err = meow_api::endpoint::bind_tls(
            "127.0.0.1:0",
            Some("-----BEGIN CERTIFICATE-----\nbogus-cert\n-----END CERTIFICATE-----"),
            Some("keys/private.pem"),
        )
        .await
        .err()
        .expect("mixed pair must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("both inline PEM or both file paths"),
            "unexpected error: {msg}"
        );
        assert!(
            !msg.contains("bogus-cert"),
            "error leaked PEM material: {msg}"
        );

        // The mirror image — path cert + inline key — same refusal.
        let err = meow_api::endpoint::bind_tls(
            "127.0.0.1:0",
            Some("certs/server.pem"),
            Some("-----BEGIN PRIVATE KEY-----\nbogus-key\n-----END PRIVATE KEY-----"),
        )
        .await
        .err()
        .expect("mixed pair must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("both inline PEM or both file paths"),
            "unexpected error: {msg}"
        );
        assert!(
            !msg.contains("bogus-key"),
            "error leaked PEM material: {msg}"
        );
    }

    /// A throwaway self-signed cert/key pair in PEM form — what
    /// `tls.certificate`/`tls.private-key` inline values carry.
    fn self_signed_pem() -> (Vec<u8>, Vec<u8>) {
        use boring::{
            asn1::{Asn1Integer, Asn1Time},
            bn::BigNum,
            ec::{EcGroup, EcKey},
            hash::MessageDigest,
            nid::Nid,
            pkey::PKey,
            x509::{X509Name, X509},
        };
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name_b = X509Name::builder().unwrap();
        name_b.append_entry_by_text("CN", "meow-test").unwrap();
        let name = name_b.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let bn = BigNum::from_u32(3).unwrap();
        let serial = Asn1Integer::from_bn(&bn).unwrap();
        b.set_serial_number(&serial).unwrap();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(30).unwrap();
        b.set_not_before(&not_before).unwrap();
        b.set_not_after(&not_after).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = b.build();
        (
            cert.to_pem().unwrap(),
            key.ec_key().unwrap().private_key_to_pem().unwrap(),
        )
    }
}

// ── Unix endpoint (cfg(unix)) ───────────────────────────────────────

#[cfg(unix)]
mod unix {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn unix_get(path: &std::path::Path, auth: Option<&str>) -> String {
        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
        let auth = auth
            .map(|s| format!("Authorization: Bearer {s}\r\n"))
            .unwrap_or_default();
        stream
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn unix_endpoint_serves_and_keeps_bearer_auth() {
        // Deliberate meow divergence: upstream's unix socket is
        // unauthenticated — meow keeps the same Bearer auth as TCP.
        let state = test_state(Default::default(), Some("s3cret"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let (endpoint, guard) = meow_api::endpoint::bind_unix(path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(guard.path(), path.as_path());
        tokio::spawn(async move { axum::serve(endpoint, create_router(state)).await });
        let resp = unix_get(&path, Some("s3cret")).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("{\"hello\":\"meow\"}"), "{resp}");
        let resp = unix_get(&path, None).await;
        assert!(resp.starts_with("HTTP/1.1 401"), "{resp}");
        // The bound socket is owner-only — never upstream's 0666.
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Dropping the guard removes the daemon's own socket file.
        drop(guard);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn unix_endpoint_binds_owner_only_under_permissive_umask() {
        // `bind_unix` binds a pid-unique sibling, chmods it 0600 and
        // renames it into place, so even umask(0) cannot produce a
        // world-accessible socket at the configured path (issue #974).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("masked.sock");
        let old = unsafe { libc::umask(0) };
        let result = meow_api::endpoint::bind_unix(path.to_str().unwrap()).await;
        unsafe { libc::umask(old) };
        let (_endpoint, _guard) = result.unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn unix_endpoint_relative_path_resolves_under_home() {
        // `set_home_dir` is process-global one-shot (`-d` semantics), so
        // a relative configured path lands under that home — not the
        // caller's CWD — and missing parents are created (issue #974).
        let dir = tempfile::tempdir().unwrap();
        meow_common::set_home_dir(dir.path().to_path_buf());
        let (_endpoint, guard) = meow_api::endpoint::bind_unix("sub/rel.sock").await.unwrap();
        assert_eq!(guard.path(), dir.path().join("sub/rel.sock").as_path());
        assert!(dir.path().join("sub/rel.sock").exists());
        drop(guard);
    }

    #[tokio::test]
    async fn unix_endpoint_cleanup_only_removes_its_own_socket() {
        // The guard must not unlink a path that was swapped behind its
        // back: cleanup re-checks the file is still a socket *and* still
        // the same (dev, ino) it bound (issue #974).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap.sock");
        let (_endpoint, guard) = meow_api::endpoint::bind_unix(path.to_str().unwrap())
            .await
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"not the daemon's socket").unwrap();
        drop(guard);
        assert_eq!(std::fs::read(&path).unwrap(), b"not the daemon's socket");
    }

    #[tokio::test]
    async fn unix_endpoint_reclaims_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stale.sock");
        // A dropped listener leaves a dead socket file — a live process
        // reconnecting gets ECONNREFUSED, i.e. "stale".
        drop(tokio::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        let (_endpoint, _guard) = meow_api::endpoint::bind_unix(path.to_str().unwrap())
            .await
            .unwrap();
        assert!(path.exists());
    }

    #[tokio::test]
    async fn unix_endpoint_full_accept_queue_does_not_stall_bind() {
        // A live listener whose accept queue is full can stall a
        // blocking connect() indefinitely — the stale-socket probe is
        // bounded, so `bind_unix` must give up on the socket instead of
        // hanging startup (issue #974). And refusing is all it may do:
        // wherever the probe's answer is ambiguous (BSD refuses a
        // saturated queue like a dead one), the socket at the path is
        // still a *live* listener — reclaim must leave it untouched.
        fn dev_ino(path: &std::path::Path) -> (u64, u64) {
            use std::os::unix::fs::MetadataExt;
            let md = std::fs::symlink_metadata(path).unwrap();
            (md.dev(), md.ino())
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("full.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let original = dev_ino(&path);
        // Fill the accept backlog without accepting: once a connect
        // fails or times out, the queue is provably full.
        let mut pending = Vec::new();
        for _ in 0..300 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                tokio::net::UnixStream::connect(&path),
            )
            .await
            {
                Ok(Ok(stream)) => pending.push(stream),
                _ => break,
            }
        }
        let started = std::time::Instant::now();
        let first = meow_api::endpoint::bind_unix(path.to_str().unwrap()).await;
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        // The full-queue answer is platform-dependent (EAGAIN on
        // Linux, ECONNREFUSED on BSD/macOS) but the verdict is not:
        // a live socket is never reclaimed. The path must still name
        // the same socket file it started with.
        assert!(first.is_err(), "bind over a live socket must refuse");
        assert_eq!(dev_ino(&path), original, "the live socket was replaced");
        // Once the backlog drains, a socket at the path is genuinely
        // live — a follow-up attempt must refuse it the same way.
        drop(pending);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let second = meow_api::endpoint::bind_unix(path.to_str().unwrap()).await;
        assert!(second.is_err());
        assert_eq!(dev_ino(&path), original);
    }

    #[tokio::test]
    async fn unix_endpoint_refuses_overlong_path_by_name() {
        // sun_path caps a filesystem socket at 103/107 usable bytes —
        // an over-limit config must fail by name before any filesystem
        // work, and a near-limit path must also leave room for the
        // staging sibling it is bound under (issue #974).
        let cap = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
            .sun_path
            .len()
            - 1;
        let dir = tempfile::tempdir().unwrap();
        let too_long = dir.path().join("x".repeat(cap));
        let err = meow_api::endpoint::bind_unix(too_long.to_str().unwrap())
            .await
            .err()
            .expect("over-limit path must fail");
        assert!(
            format!("{err}").contains("socket path limit"),
            "unexpected error: {err}"
        );
        // Resolved exactly at the cap: itself legal, but the staging
        // name cannot fit alongside it — same named refusal.
        let name_len = cap - dir.path().as_os_str().len() - 1;
        let near = dir.path().join("y".repeat(name_len));
        assert!(near.as_os_str().len() <= cap);
        let err = meow_api::endpoint::bind_unix(near.to_str().unwrap())
            .await
            .err()
            .expect("near-limit path must fail");
        assert!(
            format!("{err}").contains("socket path limit"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn unix_endpoint_refuses_live_socket_and_non_socket() {
        let dir = tempfile::tempdir().unwrap();
        // A live listener at the path → refuse, upstream would clobber.
        let live = dir.path().join("live.sock");
        let _listener = tokio::net::UnixListener::bind(&live).unwrap();
        assert!(meow_api::endpoint::bind_unix(live.to_str().unwrap())
            .await
            .is_err());
        // A regular file → refuse; the file must survive untouched
        // (upstream's unconditional unlink is the documented divergence).
        let file = dir.path().join("regular.txt");
        std::fs::write(&file, b"not a socket").unwrap();
        assert!(meow_api::endpoint::bind_unix(file.to_str().unwrap())
            .await
            .is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"not a socket");
    }
}

// ── PUT /configs persistence ────────────────────────────────────────

#[tokio::test]
async fn put_configs_persists_controller_surface_without_binding() {
    use base64::Engine as _;
    let state = test_state(Default::default(), None);
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("put.sock");
    let document = format!(
        "mode: rule\n\
         external-controller-tls: 127.0.0.1:9443\n\
         external-controller-unix: {}\n\
         external-controller-pipe: '\\\\.\\pipe\\meow'\n\
         tls:\n  certificate: /nonexistent/cert.pem\n  private-key: /nonexistent/key.pem\n\
         external-controller-cors:\n  allow-origins: ['https://ok.example']\n\
         rules:\n  - MATCH,DIRECT\n",
        sock.display()
    );
    let resp = create_router(Arc::clone(&state))
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
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "{}",
        body_string(resp).await
    );
    // Committed verbatim — the keys survive the raw round-trip so a
    // restart picks them up; GET /configs and PATCH never see them.
    {
        let committed = state.raw_config.read();
        assert_eq!(
            committed.external_controller_tls.as_deref(),
            Some("127.0.0.1:9443")
        );
        assert_eq!(
            committed.external_controller_unix.as_deref(),
            Some(sock.to_str().unwrap())
        );
        assert_eq!(
            committed.external_controller_pipe.as_deref(),
            Some("\\\\.\\pipe\\meow")
        );
        let cors = committed.external_controller_cors.as_ref().unwrap();
        assert_eq!(
            cors.allow_origins.as_deref(),
            Some(&["https://ok.example".to_string()][..])
        );
        assert_eq!(
            committed.tls.as_ref().unwrap().certificate.as_deref(),
            Some("/nonexistent/cert.pem")
        );
    }
    // The PUT never bound or created anything: no socket file, no PEM
    // read (the nonexistent path would have failed a read), no listener.
    assert!(!sock.exists());
    #[cfg(unix)]
    assert!(tokio::net::UnixStream::connect(&sock).await.is_err());
    assert!(tokio::net::TcpStream::connect("127.0.0.1:9443")
        .await
        .is_err());
}

#[tokio::test]
async fn get_configs_never_echoes_controller_tls_keys() {
    let mut raw = test_raw_config();
    raw.external_controller_tls = Some("127.0.0.1:9443".into());
    raw.tls = Some(meow_config::raw::RawTls {
        private_key: Some("SECRET-KEY-MATERIAL".into()),
        certificate: Some("CERT".into()),
        ..Default::default()
    });
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let state = Arc::new(AppState {
        tunnel,
        secret: None,
        config_path: None,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: broadcast::channel(16).0,
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
        cors: Default::default(),
    });
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .uri("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(!body.contains("SECRET-KEY-MATERIAL"), "{body}");
    assert!(!body.contains("private-key"), "{body}");
    assert!(!body.contains("external-controller-tls"), "{body}");
}
