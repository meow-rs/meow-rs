use axum::{
    body::Body,
    extract::ws::{Message, WebSocketUpgrade},
    extract::{FromRequestParts, Path, Query, Request, State},
    http::{header, request::Parts, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use dashmap::DashMap;
use meow_common::TunnelMode;
use meow_config::{
    proxy_provider::ProxyProvider,
    raw::{RawConfig, RawProxyGroup, RawSubscription},
    rule_provider::RuleProvider,
    NamedListener,
};
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use tower_http::cors::CorsLayer;
use tracing::{debug, info, warn};

#[cfg(feature = "listener-tun")]
use meow_listener::TunListener;

use crate::log_stream::{parse_log_level, LogMessage};
use crate::ui;

struct MaybeWebSocket(Option<WebSocketUpgrade>);

impl<S> FromRequestParts<S> for MaybeWebSocket
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let is_websocket = parts
            .headers
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        if !is_websocket {
            return Ok(Self(None));
        }
        Ok(Self(
            WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .ok(),
        ))
    }
}
#[derive(Default)]
pub struct TrafficFeed {
    sender: std::sync::Mutex<Option<broadcast::Sender<Arc<str>>>>,
}

pub struct AppState {
    pub tunnel: Tunnel,
    /// Optional Bearer token enforced by `require_auth`. `None` or empty disables auth.
    pub secret: Option<String>,
    pub config_path: String,
    pub raw_config: Arc<RwLock<RawConfig>>,
    /// Fan-out channel for log events. Each WS client subscribes a Receiver.
    pub log_tx: broadcast::Sender<LogMessage>,
    /// Live proxy-provider registry — refreshed by background task and PUT endpoint.
    pub proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
    /// The cell provider-sourced `dialer-proxy` targets resolve against.
    /// Newly declared providers materialized by a `PUT /configs` rebuild
    /// must share it — it is the registry the tunnel republishes the route
    /// map into (issue #489).
    pub provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
    /// Live rule-provider registry — swapped wholesale to the committed
    /// build's provider set on every successful config commit, so `RULE-SET`
    /// rules, DNS `rule-set:` matchers, and `PUT /providers/rules/{name}`
    /// refreshes all share one object per provider (issue #533 review).
    pub rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
    /// Owns the per-provider interval refresh tasks — reconciled on every
    /// commit that swaps `rule_providers` so providers added, removed, or
    /// re-`interval`ed by a reload gain/lose their task (issue #543).
    pub rule_provider_refresh: Arc<meow_config::rule_provider_refresh::RefreshSupervisor>,
    /// Owns the per-provider `interval` refresh tasks for
    /// `proxy_providers` — reconciled by [`commit_proxy_providers`] on
    /// every commit so added/removed/re-`interval`ed providers gain/lose
    /// their task (issue #625).
    pub proxy_provider_refresh:
        Arc<meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor>,
    /// Snapshot of active named listeners (read-only, startup-time only in M1).
    pub listeners: Vec<NamedListener>,
    /// Validated directory for a third-party web UI. When `Some`, it is served
    /// at `/ui`; when `None`, the built-in panel is served (issue #223).
    pub external_ui: Option<std::path::PathBuf>,
    /// Shared on-demand traffic sampler. No timer runs until a client
    /// subscribes to `/traffic`.
    pub traffic_feed: TrafficFeed,
    /// Running standalone DNS server (config `dns.listen`), if bound. The
    /// shared `Arc` is handed in by the embedder (main.rs), which fills it
    /// after spawning the server; `PUT /configs` hot-swaps the resolver
    /// slot or rebinds the socket on a `dns.listen` change (issue #514).
    pub dns_server: Arc<RwLock<Option<DnsServerHandle>>>,
}

/// Handle to the running standalone DNS server (config `dns.listen`).
pub struct DnsServerHandle {
    /// Bound listen address — a `dns.listen` change triggers a rebind.
    pub listen: std::net::SocketAddr,
    /// Serve task — abort releases the socket promptly (the serve loop is
    /// the socket's only strong owner).
    pub task: tokio::task::JoinHandle<()>,
    /// Slot the serve workers read per query — write the rebuilt resolver
    /// here to hot-swap without rebinding.
    pub resolver_slot: meow_dns::ResolverSlot,
}

/// The API server owns one raw/runtime configuration, so all mutation
/// endpoints share one commit lane. Reads remain independent.
///
/// `pub` so `meow-app`'s subscription refresh loop serializes on the same
/// lane: without it a refresh commit could interleave between a `PUT
/// /configs` rebuild and its raw-config write, silently reverting the
/// subscription-owned sections (issue #514).
pub static CONFIG_MUTATION: Mutex<()> = Mutex::const_new(());

impl AppState {
    fn auth_required(&self) -> bool {
        self.secret.as_deref().is_some_and(|s| !s.is_empty())
    }
}

/// Auth middleware for all API routes. Accepts `Authorization: Bearer <secret>`
/// header. For WebSocket upgrade requests, also accepts `?token=<secret>` query
/// param (browser WebSocket clients cannot set custom headers).
async fn require_auth_ws(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HashMap<String, String>>,
    req: Request,
    next: Next,
) -> Response {
    if !state.auth_required() {
        return next.run(req).await;
    }
    let expected = state.secret.as_deref().unwrap_or("");

    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let is_websocket = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let token_param = if is_websocket {
        query.get("token").map(std::string::String::as_str)
    } else {
        None
    };
    let provided = bearer.or(token_param);

    let ok = match provided {
        Some(t) if t.len() == expected.len() => {
            use subtle::ConstantTimeEq;
            t.as_bytes().ct_eq(expected.as_bytes()).into()
        }
        _ => false,
    };
    if ok {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"message": "Unauthorized"})),
        )
            .into_response()
    }
}

pub fn create_router(state: Arc<AppState>) -> Router {
    // WS routes — accept header or ?token= query param for browser dashboard compat.
    // REST API routes gated behind the Bearer middleware (header-only).
    let api = Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route("/proxies", get(get_proxies))
        .route(
            "/proxies/{name}",
            get(get_proxy).put(update_proxy).delete(unfix_proxy),
        )
        .route("/proxies/{name}/delay", get(get_proxy_delay))
        .route("/group", get(get_groups))
        .route("/group/{name}", get(get_group))
        .route("/group/{name}/delay", get(get_group_delay))
        .route(
            "/rules",
            get(get_rules).post(replace_rules).put(update_rule_at_index),
        )
        .route("/rules/{index}", delete(delete_rule))
        .route("/rules/reorder", post(reorder_rules))
        .route("/connections", get(get_connections))
        .route("/connections/{id}", delete(close_connection))
        .route("/connections", delete(close_all_connections))
        .route(
            "/configs",
            get(get_configs).patch(update_configs).put(put_configs),
        )
        .route("/metrics", get(get_metrics))
        .route("/traffic", get(get_traffic))
        .route("/logs", get(get_logs))
        .route("/memory", get(get_memory))
        .route("/dns/results", get(get_dns_results))
        .route("/dns/query", get(dns_query_get).post(dns_query))
        .route("/cache/dns/flush", post(flush_dns_cache))
        .route("/cache/fakeip/flush", post(flush_fakeip_cache))
        // Config save
        .route("/api/config/save", post(save_config))
        // Subscriptions
        .route(
            "/api/subscriptions",
            get(get_subscriptions).post(add_subscription),
        )
        .route("/api/subscriptions/{name}", delete(delete_subscription))
        .route(
            "/api/subscriptions/{name}/refresh",
            post(refresh_subscription),
        )
        // Proxy groups
        .route(
            "/api/proxy-groups",
            get(get_proxy_groups).post(create_proxy_group),
        )
        .route(
            "/api/proxy-groups/{name}",
            put(update_proxy_group).delete(delete_proxy_group),
        )
        .route(
            "/api/proxy-groups/{name}/select",
            put(select_proxy_in_group),
        )
        // Proxy providers
        .route("/providers/proxies", get(get_providers))
        .route(
            "/providers/proxies/{name}",
            get(get_provider).put(refresh_provider),
        )
        .route(
            "/providers/proxies/{name}/healthcheck",
            get(provider_healthcheck),
        )
        .route(
            "/providers/proxies/{provider_name}/{proxy_name}",
            get(get_provider_proxy),
        )
        .route(
            "/providers/proxies/{provider_name}/{proxy_name}/healthcheck",
            get(provider_proxy_healthcheck),
        )
        // Rule providers
        .route("/providers/rules", get(get_rule_providers))
        .route(
            "/providers/rules/{name}",
            get(get_rule_provider).put(refresh_rule_provider),
        )
        // Listeners (read-only list)
        .route("/listeners", get(get_listeners))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth_ws,
        ));

    // Web UI is intentionally unauthenticated so dashboards can load and then
    // present a token prompt; this matches upstream mihomo behaviour.
    //
    // When `external-ui` is configured (issue #223) the static directory is
    // served at `/ui` via tower-http's `ServeDir`; otherwise the built-in
    // single-page panel is served.
    let router = api;
    let router = if let Some(dir) = state.external_ui.clone() {
        // `ServeDir` resolves `index.html` for the directory root and serves
        // any nested asset; `nest_service("/ui", …)` strips the `/ui` prefix so
        // both `/ui` and `/ui/<asset>` resolve. Dashboards (metacubexd, yacd)
        // use hash routing, so no server-side SPA fallback is required.
        router.nest_service("/ui", tower_http::services::ServeDir::new(dir))
    } else {
        router
            .route("/ui", get(ui::serve_ui))
            .route("/ui/{*rest}", get(ui::serve_ui))
    };

    router.layer(CorsLayer::permissive()).with_state(state)
}

// ── Basic endpoints ──────────────────────────────────────────────────

#[derive(Serialize)]
struct HelloResponse {
    hello: &'static str,
}

async fn hello() -> Json<HelloResponse> {
    Json(HelloResponse { hello: "meow" })
}

#[derive(Serialize)]
struct VersionResponse {
    version: String,
    meta: bool,
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: format!("v{}", env!("CARGO_PKG_VERSION")),
        meta: true,
    })
}

#[derive(Serialize)]
struct ProxyInfo {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    alive: bool,
    history: Vec<meow_common::DelayHistory>,
    udp: bool,
    /// Group-only: ordered list of member proxy names.
    #[serde(skip_serializing_if = "Option::is_none")]
    all: Option<Vec<String>>,
    /// Group-only: name of the currently active member.
    #[serde(skip_serializing_if = "Option::is_none")]
    now: Option<String>,
    /// Automatic-group user pin. `Some("")` means automatic mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed: Option<String>,
    #[serde(rename = "testUrl", skip_serializing_if = "Option::is_none")]
    test_url: Option<String>,
    #[serde(rename = "expectedStatus", skip_serializing_if = "Option::is_none")]
    expected_status: Option<String>,
    /// Last measured delay in ms; omitted until a probe has succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    delay: Option<u16>,
}

impl ProxyInfo {
    fn from_proxy(proxy: &Arc<dyn meow_common::Proxy>) -> Self {
        let members = proxy.members();
        let current = proxy.current();
        debug!(
            name = proxy.name(),
            proxy_type = %proxy.adapter_type(),
            member_count = members.as_ref().map(std::vec::Vec::len),
            current = ?current,
            "building ProxyInfo",
        );
        let delay = Some(proxy.last_delay()).filter(|&d| d > 0);
        Self {
            name: proxy.name().to_string(),
            proxy_type: proxy.adapter_type().to_string(),
            alive: proxy.alive(),
            history: proxy.delay_history(),
            udp: proxy.support_udp(),
            all: members,
            now: current,
            fixed: proxy
                .selection()
                .and_then(meow_common::ProxySelection::fixed),
            test_url: proxy.test_url().map(str::to_string),
            expected_status: proxy.expected_status().map(str::to_string),
            delay,
        }
    }
}

#[derive(Serialize)]
struct ProxiesResponse {
    proxies: std::collections::HashMap<String, ProxyInfo>,
}

async fn get_proxies(State(state): State<Arc<AppState>>) -> Json<ProxiesResponse> {
    let route = state.tunnel.route_snapshot();
    let mut result = std::collections::HashMap::new();
    for (name, proxy) in route.proxies.iter() {
        result.insert(name.to_string(), ProxyInfo::from_proxy(proxy));
    }
    Json(ProxiesResponse { proxies: result })
}

async fn get_proxy(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<ProxyInfo>, StatusCode> {
    let route = state.tunnel.route_snapshot();
    let proxy = route
        .proxies
        .get(name.as_str())
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ProxyInfo::from_proxy(proxy)))
}

#[derive(Deserialize)]
struct UpdateProxyRequest {
    name: String,
}

async fn update_proxy(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
    Json(body): Json<UpdateProxyRequest>,
) -> Response {
    let route = state.tunnel.route_snapshot();
    let Some(proxy) = route.proxies.get(group_name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    let Some(selection) = proxy.selection() else {
        return msg_err(StatusCode::BAD_REQUEST, "Must be a Selector");
    };
    match selection.set(&body.name).await {
        Ok(()) => {
            info!("Proxy group '{}' switched to '{}'", group_name, body.name);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message": format!("Selector update error: {e}")})),
        )
            .into_response(),
    }
}

async fn unfix_proxy(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
) -> Response {
    let route = state.tunnel.route_snapshot();
    let Some(proxy) = route.proxies.get(group_name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    let Some(selection) = proxy.selection() else {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    };
    if !selection.can_unfix() {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    }
    selection.force_set(None);
    StatusCode::NO_CONTENT.into_response()
}

async fn get_groups(State(state): State<Arc<AppState>>) -> Json<ProxiesResponse> {
    let route = state.tunnel.route_snapshot();
    let proxies = route
        .proxies
        .iter()
        .filter(|(_, proxy)| proxy.members().is_some())
        .map(|(name, proxy)| (name.to_string(), ProxyInfo::from_proxy(proxy)))
        .collect();
    Json(ProxiesResponse { proxies })
}

async fn get_group(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let route = state.tunnel.route_snapshot();
    match route.proxies.get(name.as_str()) {
        Some(proxy) if proxy.members().is_some() => {
            Json(ProxyInfo::from_proxy(proxy)).into_response()
        }
        _ => msg_err(StatusCode::NOT_FOUND, "Resource not found"),
    }
}

#[derive(Serialize)]
struct RuleInfo<'a> {
    index: usize,
    #[serde(rename = "type")]
    rule_type: &'static str,
    payload: &'a str,
    proxy: &'a str,
    size: i64,
}

#[derive(Serialize)]
struct RulesResponse<'a> {
    rules: Vec<RuleInfo<'a>>,
}

async fn get_rules(State(state): State<Arc<AppState>>) -> Response {
    // Serialise straight off the route snapshot — the old rules_info()
    // accessor built 3 Strings per rule per call (audit #182).
    let route = state.tunnel.route_snapshot();
    let result: Vec<RuleInfo> = route
        .rules
        .iter()
        .enumerate()
        .map(|(index, r)| RuleInfo {
            index,
            rule_type: r.rule_type().as_str(),
            payload: r.payload(),
            proxy: r.adapter(),
            size: -1,
        })
        .collect();
    Json(RulesResponse { rules: result }).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionsResponse<'a> {
    upload_total: i64,
    download_total: i64,
    memory: u64,
    /// Serialised straight from the live table — no per-connection
    /// `serde_json::Value` tree, no cloned snapshot Vec (audit M8). The
    /// JSON shape (id/upload/download/start/chains/rule/rulePayload) comes
    /// from `ConnectionInfo`'s `Serialize` derive.
    connections: meow_tunnel::statistics::ActiveConnectionsView<'a>,
}

#[derive(Deserialize)]
struct ConnectionsParams {
    interval: Option<String>,
}

/// Floor for the `/connections` WebSocket push interval. Each tick
/// re-serializes the whole connection table while holding DashMap shard
/// read-guards, so a sub-100ms interval is a self-DoS lever on the API
/// worker rather than a useful refresh rate. Out-of-range values are
/// clamped, not rejected: `0` stays a 400 (upstream contract), anything
/// else is a well-formed request that just asked for too much.
const MIN_CONNECTIONS_INTERVAL_MS: u64 = 100;

/// Parse the `interval` query param: `None` on `0` / non-numeric input
/// (rendered as `400 Body invalid` by the caller), otherwise the value in
/// milliseconds, defaulted to 1000 and clamped to
/// [`MIN_CONNECTIONS_INTERVAL_MS`].
fn parse_connections_interval(raw: Option<&str>) -> Option<u64> {
    match raw {
        Some(raw) => match raw.parse::<u64>() {
            Ok(0) | Err(_) => None,
            Ok(value) => Some(value.max(MIN_CONNECTIONS_INTERVAL_MS)),
        },
        None => Some(1000),
    }
}

async fn connections_json(state: &AppState) -> String {
    let stats = state.tunnel.statistics();
    let (up, down) = stats.snapshot();
    let memory = read_rss_bytes().await;
    #[allow(
        clippy::unnecessary_cast,
        reason = "no-op on 64-bit; widens i32 on targets without 64-bit atomics"
    )]
    let upload = up as i64;
    #[allow(
        clippy::unnecessary_cast,
        reason = "no-op on 64-bit; widens i32 on targets without 64-bit atomics"
    )]
    let download = down as i64;
    serde_json::to_string(&ConnectionsResponse {
        upload_total: upload,
        download_total: download,
        memory,
        connections: stats.active_connections_view(),
    })
    .unwrap_or_else(|_| {
        "{\"uploadTotal\":0,\"downloadTotal\":0,\"memory\":0,\"connections\":[]}".into()
    })
}

async fn get_connections(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ConnectionsParams>,
    MaybeWebSocket(ws): MaybeWebSocket,
) -> Response {
    let Some(interval_ms) = parse_connections_interval(params.interval.as_deref()) else {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    };

    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            if socket
                .send(Message::Text(connections_json(&state).await.into()))
                .await
                .is_err()
            {
                return;
            }
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if socket
                    .send(Message::Text(connections_json(&state).await.into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    let body = connections_json(&state).await;
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn close_connection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => {
            state.tunnel.statistics().close_connection(uuid);
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

#[derive(Serialize)]
struct ConfigResponse {
    mode: String,
    #[serde(rename = "log-level")]
    log_level: String,
    #[serde(rename = "mixed-port", skip_serializing_if = "Option::is_none")]
    mixed_port: Option<u16>,
    #[serde(rename = "socks-port", skip_serializing_if = "Option::is_none")]
    socks_port: Option<u16>,
    #[serde(rename = "port", skip_serializing_if = "Option::is_none")]
    http_port: Option<u16>,
    #[serde(rename = "redir-port")]
    redir_port: u16,
    #[serde(rename = "tproxy-port")]
    tproxy_port: u16,
    #[serde(
        rename = "external-controller",
        skip_serializing_if = "Option::is_none"
    )]
    external_controller: Option<String>,
    #[serde(rename = "allow-lan")]
    allow_lan: bool,
    #[serde(rename = "bind-address")]
    bind_address: String,
    #[serde(rename = "ipv6")]
    ipv6: bool,
    /// Whether the TUN listener is currently running (issue #326).
    /// Mirrors `tun.enable` from the raw config and reflects actual
    /// runtime state so nyanpasu can correctly render its toggle.
    #[serde(rename = "tun-enable")]
    tun_enable: bool,
}

async fn get_configs(State(state): State<Arc<AppState>>) -> Json<ConfigResponse> {
    let raw = state.raw_config.read();
    Json(ConfigResponse {
        mode: state.tunnel.mode().to_string(),
        log_level: raw.log_level.clone().unwrap_or_else(|| "info".to_string()),
        mixed_port: raw.mixed_port,
        socks_port: raw.socks_port,
        http_port: raw.port,
        redir_port: 0,
        tproxy_port: raw.tproxy_port.unwrap_or(0),
        external_controller: raw.external_controller.clone(),
        allow_lan: raw.allow_lan.unwrap_or(false),
        bind_address: raw
            .bind_address
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string()),
        ipv6: meow_config::effective_ipv6(raw.ipv6),
        tun_enable: state.tunnel.has_tun(),
    })
}

#[derive(Deserialize)]
struct UpdateConfigRequest {
    mode: Option<String>,
    #[serde(rename = "log-level")]
    log_level: Option<String>,
}

async fn update_configs(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateConfigRequest>,
) -> Response {
    // Validate both fields first so we never partially apply on error.
    let mode = body.mode.map(|s| s.parse::<TunnelMode>());
    if let Some(Err(_)) = mode {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    }
    if let Some(ref level) = body.log_level {
        if !matches!(
            level.to_ascii_lowercase().as_str(),
            "debug" | "info" | "warning" | "warn" | "error" | "silent"
        ) {
            return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
        }
    }

    // Both valid — apply atomically. Enter the shared mutation lane first:
    // a bare `raw_config.write()` here would race a concurrent PUT
    // /configs, whose candidate swap would clobber the patched fields
    // (issue #514).
    let _mutation = CONFIG_MUTATION.lock().await;
    // Apply the fallible side first — committing mode before a failed
    // log-level reload would partially apply the PATCH (issue #514).
    if let Some(level) = body.log_level.as_deref() {
        if let Err(e) = crate::log_stream::reload_log_level(level) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message": e})),
            )
                .into_response();
        }
    }
    let mut raw = state.raw_config.write();
    if let Some(Ok(parsed_mode)) = mode {
        state.tunnel.set_mode(parsed_mode);
        raw.mode = Some(parsed_mode.to_string());
        info!("Mode changed to {}", parsed_mode);
    }
    if let Some(level) = body.log_level {
        raw.log_level = Some(level);
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
struct TrafficResponse {
    up: i64,
    down: i64,
    #[serde(rename = "upTotal")]
    up_total: i64,
    #[serde(rename = "downTotal")]
    down_total: i64,
}

fn traffic_json(state: &AppState) -> String {
    let (up, down, up_total, down_total) = state.tunnel.statistics().traffic_snapshot();
    #[allow(
        clippy::useless_conversion,
        reason = "identity on 64-bit; widens i32 on targets without 64-bit atomics"
    )]
    serde_json::to_string(&TrafficResponse {
        up: up.into(),
        down: down.into(),
        up_total: up_total.into(),
        down_total: down_total.into(),
    })
    .unwrap_or_default()
}

fn subscribe_traffic_feed(state: &Arc<AppState>) -> broadcast::Receiver<Arc<str>> {
    let mut guard = state
        .traffic_feed
        .sender
        .lock()
        .expect("traffic feed lock poisoned");
    if let Some(tx) = guard.as_ref() {
        return tx.subscribe();
    }

    let (tx, rx) = broadcast::channel(2);
    *guard = Some(tx.clone());
    drop(guard);

    // Establish a baseline before the first one-second window. Otherwise all
    // traffic accumulated while nobody was subscribed would be reported as
    // the first frame's instantaneous rate.
    state.tunnel.statistics().sample_traffic();

    let state = Arc::clone(state);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if tx.receiver_count() == 0 {
                let mut guard = state
                    .traffic_feed
                    .sender
                    .lock()
                    .expect("traffic feed lock poisoned");
                if tx.receiver_count() == 0 {
                    *guard = None;
                    break;
                }
            }
            state.tunnel.statistics().sample_traffic();
            let frame: Arc<str> = Arc::from(traffic_json(&state));
            let _ = tx.send(frame);
        }
    });
    rx
}

async fn get_traffic(
    State(state): State<Arc<AppState>>,
    MaybeWebSocket(ws): MaybeWebSocket,
) -> Response {
    let feed = subscribe_traffic_feed(&state);
    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            let mut feed = feed;
            loop {
                let frame = match feed.recv().await {
                    Ok(frame) => frame,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if socket
                    .send(Message::Text(frame.as_ref().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    let stream = futures::stream::unfold(feed, |mut feed| async move {
        loop {
            match feed.recv().await {
                Ok(frame) => {
                    return Some((
                        Ok::<String, std::convert::Infallible>(format!("{frame}\n")),
                        feed,
                    ));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("valid traffic stream response")
}

#[derive(Deserialize)]
struct DnsQueryRequest {
    name: String,
    #[serde(rename = "type")]
    qtype: Option<String>,
}

#[derive(Deserialize)]
struct DnsResultsQuery {
    search: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct DnsResultEntry {
    name: String,
    ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_server: Option<String>,
    ttl: u64,
}

async fn get_dns_results(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DnsResultsQuery>,
) -> Json<Vec<DnsResultEntry>> {
    let limit = params.limit.unwrap_or(256).min(1024);
    let results = state
        .tunnel
        .resolver()
        .dns_results(params.search.as_deref(), limit)
        .into_iter()
        .map(|entry| DnsResultEntry {
            name: entry.name,
            ips: entry.ips.into_iter().map(|ip| ip.to_string()).collect(),
            from_server: entry.source,
            ttl: entry.ttl.as_secs(),
        })
        .collect();
    Json(results)
}

async fn dns_query(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DnsQueryRequest>,
) -> Json<serde_json::Value> {
    let resolver = state.tunnel.resolver();
    let result = resolver.resolve_ip(&body.name).await;
    let _ = body.qtype;
    Json(serde_json::json!({ "name": body.name, "answer": result.map(|ip| ip.to_string()) }))
}

// upstream: hub/route/dns.go — GET alias added alongside existing POST.
// Class B per ADR-0002: POST kept for back-compat; GET matches upstream's current form.
async fn dns_query_get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DnsQueryRequest>,
) -> Response {
    let enabled = state
        .raw_config
        .read()
        .dns
        .as_ref()
        .is_some_and(|dns| dns.enable.unwrap_or(false));
    if !enabled {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": "DNS section is disabled"})),
        )
            .into_response();
    }

    use hickory_proto::rr::RecordType;
    let qtype_text = params.qtype.as_deref().unwrap_or("A").to_ascii_uppercase();
    let Ok(record_type) = qtype_text.parse::<RecordType>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message": "invalid query type"})),
        )
            .into_response();
    };

    let resolver = state.tunnel.resolver();
    let fqdn = if params.name.ends_with('.') {
        params.name.clone()
    } else {
        format!("{}.", params.name)
    };
    let question = serde_json::json!({
        "Name": fqdn,
        "Qtype": u16::from(record_type),
        "Qclass": 1,
    });

    let mut response = serde_json::Map::new();
    response.insert("Status".into(), 0.into());
    response.insert("Question".into(), serde_json::Value::Array(vec![question]));
    response.insert("TC".into(), false.into());
    response.insert("RD".into(), true.into());
    response.insert("RA".into(), true.into());
    response.insert("AD".into(), false.into());
    response.insert("CD".into(), false.into());

    if matches!(record_type, RecordType::A | RecordType::AAAA) {
        let ips = resolver.resolve_ips(&params.name).await.unwrap_or_default();
        let answers: Vec<_> = ips
            .into_iter()
            .filter(|ip| {
                matches!(record_type, RecordType::A) && ip.is_ipv4()
                    || matches!(record_type, RecordType::AAAA) && ip.is_ipv6()
            })
            .map(|ip| {
                serde_json::json!({
                    "name": fqdn,
                    "type": u16::from(record_type),
                    "TTL": 60,
                    "data": ip.to_string(),
                })
            })
            .collect();
        if !answers.is_empty() {
            response.insert("Answer".into(), serde_json::Value::Array(answers));
        }
    } else if let Some(message) = {
        let Ok(query_name) = fqdn.parse::<hickory_proto::rr::Name>() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message": "DNS query failed"})),
            )
                .into_response();
        };
        resolver
            .forward_generic(&params.name, &query_name, record_type)
            .await
    } {
        let metadata = &message.metadata;
        response.insert("Status".into(), u16::from(metadata.response_code).into());
        response.insert("TC".into(), metadata.truncation.into());
        response.insert("RD".into(), metadata.recursion_desired.into());
        response.insert("RA".into(), metadata.recursion_available.into());
        response.insert("AD".into(), metadata.authentic_data.into());
        response.insert("CD".into(), metadata.checking_disabled.into());
        insert_dns_records(&mut response, "Answer", &message.answers);
        insert_dns_records(&mut response, "Authority", &message.authorities);
        insert_dns_records(&mut response, "Additional", &message.additionals);
    } else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": "DNS query failed"})),
        )
            .into_response();
    }

    Json(serde_json::Value::Object(response)).into_response()
}

fn insert_dns_records(
    target: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    records: &[hickory_proto::rr::Record],
) {
    if records.is_empty() {
        return;
    }
    target.insert(
        key.to_string(),
        serde_json::Value::Array(
            records
                .iter()
                .map(|record| {
                    serde_json::json!({
                        "name": record.name.to_string(),
                        "type": u16::from(record.record_type()),
                        "TTL": record.ttl,
                        "data": record.data.to_string(),
                    })
                })
                .collect(),
        ),
    );
}

async fn flush_dns_cache(State(state): State<Arc<AppState>>) -> StatusCode {
    state.tunnel.resolver().clear_cache();
    StatusCode::NO_CONTENT
}

/// `POST /cache/fakeip/flush` — clear every fake-IP allocation. Mirrors
/// upstream `hub/route/cache.go::flushFakeIPPool`. Returns 204 on success,
/// 400 with a JSON `{message: ...}` body if persistence flushing fails.
async fn flush_fakeip_cache(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    match state.tunnel.resolver().flush_fake_ip() {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": e.to_string() })),
        )),
    }
}

async fn close_all_connections(State(state): State<Arc<AppState>>) -> StatusCode {
    state.tunnel.statistics().close_all_connections();
    StatusCode::NO_CONTENT
}

// ── Config save ──────────────────────────────────────────────────────

async fn save_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Hold the lane so the snapshot cannot land mid-commit — between the
    // raw swap and a possible `tun.enable` rollback — and persist a state
    // the runtime immediately reverts (issue #543).
    let _mutation = CONFIG_MUTATION.lock().await;
    let raw = state.raw_config.read().clone();
    meow_config::save_raw_config_async(&state.config_path, &raw)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"message": "config saved"})))
}

// ── Helper: rebuild proxies/rules from raw and apply to tunnel ───────

/// Pre-resolve DNS-sourced ECH then rebuild proxies/rules from `raw` and
/// apply to the live tunnel. Takes the config *by value* so callers
/// clone-and-drop their `parking_lot` guard before awaiting — those guards
/// are not Send and would otherwise break the axum Handler bound.
///
/// Returns the rebuilt [`meow_config::DnsConfig`] (when its inputs changed)
/// plus the resolver generation that was live before the early install —
/// the caller passes it to [`swap_config_and_reconcile_tun`] so the TUN
/// fake-IP comparison sees the true old state (issue #533 review).
///
/// Callers must hold the `CONFIG_MUTATION` lane (issue #543).
async fn apply_raw_to_tunnel(
    raw: RawConfig,
    state: &AppState,
) -> Result<(Option<meow_config::DnsConfig>, Arc<meow_dns::Resolver>), (StatusCode, String)> {
    debug_assert!(
        CONFIG_MUTATION.try_lock().is_err(),
        "caller must hold the CONFIG_MUTATION lane"
    );
    let expected_groups: Vec<String> = raw
        .proxy_groups
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|group| group.name.clone())
        .collect();
    // Defect-check only, no DNS: every writer preresolves ECH into the
    // stored raw before the lane (PUT /configs, subscription add/refresh),
    // so remaining work here would be retrying a previously-failed lookup —
    // an async network call that would serialize every other commit behind
    // it (issue #533 review).
    if let Some(ps) = raw.proxies.as_ref() {
        meow_config::ech_dns::check_ech_defects(ps, raw.strict.unwrap_or(false))
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e} (strict mode)")))?;
    }
    let providers = state
        .proxy_providers
        .iter()
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect();
    // Same provider-cache directory the daemon loaded its startup config
    // with — this is a trusted rebuild of the daemon's own running config,
    // not an untrusted candidate, so relative rule-provider paths must keep
    // resolving instead of hard-failing with `cache_dir: None` (issue #429
    // follow-up).
    let cache_dir = meow_config::resource_cache_dir_for_config_path(&state.config_path);
    // Share the tunnel's resolver slot so the rebuilt map's DIRECT adapter
    // tracks later `set_resolver` swaps (issue #514).
    let resolver_slot = state.tunnel.resolver_slot();
    // A rebuild failure is a defect in the candidate config the caller
    // supplied — 400, not 500 (issue #533 review).
    let result = rebuild_from_raw_runtime_async(
        raw.clone(),
        resolver_slot,
        providers,
        cache_dir,
        state.provider_dialer_registry.clone(),
    )
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let meow_config::RebuildResult {
        proxies,
        rules,
        dialer_registry,
        rule_providers,
        proxy_providers,
        prefetched_payloads,
    } = result;
    if let Some(missing) = expected_groups
        .iter()
        .find(|name| !proxies.contains_key(name.as_str()))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proxy group '{missing}' failed validation"),
        ));
    }
    // Issue #514: a changed `dns:`/`hosts:`/`ipv6:`/`geodata:` section must
    // rebuild the resolver, not just land in the persisted config. Parse
    // against the freshly rebuilt proxy registry so circular
    // `proxy-server-nameserver` detection sees current names; a parse
    // failure rejects the whole mutation before anything is published.
    let dns = reconcile_dns_config(
        &state.raw_config,
        &raw,
        &state.config_path,
        &proxies,
        Some(&rule_providers),
        Some(&prefetched_payloads),
        Some(state.tunnel.resolver()),
        Some(&dialer_registry),
    )
    .await?;
    // Snapshot the resolver being replaced BEFORE the early install below
    // — `swap_config_and_reconcile_tun` compares its fake-IP inputs against
    // the new generation's; reading `tunnel.resolver()` there would already
    // see the candidate and never detect a change (issue #533 review).
    let prior_resolver = state.tunnel.resolver();
    // Publish the rebuilt resolver to every consumer before the route swap
    // drops the old registry cell: a `#name` upstream still resolving
    // through the standalone DNS server's or host hook's OLD resolver
    // would fail closed in the gap until `publish_dns` runs (issue #533
    // review). Idempotent — `publish_dns` installs the same Arc again.
    if let Some(dns) = &dns {
        install_resolver_everywhere(&state.tunnel, state.dns_server.as_ref(), dns);
    }
    state.tunnel.update_routing(proxies, rules, dialer_registry);
    // Commit point reached: every fallible check passed. The candidate's
    // provider sets become the live registries — the rules and DNS
    // `rule-set:` matchers installed above already reference these Arcs
    // (issue #533 review). `commit_registry` publishes the map *and*
    // reconciles the interval refresh loops so providers added, removed,
    // or re-intervalled by this commit gain/lose their task (issue #543).
    state
        .rule_provider_refresh
        .commit_registry(&state.rule_providers, rule_providers);
    commit_proxy_providers(
        &state.proxy_providers,
        &proxy_providers,
        raw.strict.unwrap_or(false),
        raw.proxy_providers.as_ref(),
        &state.proxy_provider_refresh,
    );
    Ok((dns, prior_resolver))
}

/// Rebuild routing + DNS from `candidate`, then commit it as the new raw
/// config and reconcile the TUN listener. Callers must hold the
/// `CONFIG_MUTATION` lane — it is the sole serialisation of the
/// read-old → write-new → reconcile sequence (issue #543).
async fn commit_raw_candidate(
    state: &AppState,
    candidate: RawConfig,
) -> Result<(), (StatusCode, String)> {
    debug_assert!(
        CONFIG_MUTATION.try_lock().is_err(),
        "caller must hold the CONFIG_MUTATION lane"
    );
    let (dns, prior_resolver) = apply_raw_to_tunnel(candidate.clone(), state).await?;
    swap_config_and_reconcile_tun(state, candidate, dns, prior_resolver).await;
    Ok(())
}

/// Commit a validated candidate proxy-provider set into the live registry.
/// Call only after the rebuild's commit point — the groups installed by the
/// routing swap already reference these Arcs (still-declared names reuse the
/// live objects; new declarations are fresh empty providers).
///
/// Insert-before-prune ordering: a concurrent `use:`/refresh lookup never
/// observes a declared provider missing. Each committed provider adopts the
/// candidate generation's `strict` flag so reused objects follow the new
/// config (issue #533 review). Providers whose object is new — newly
/// declared names, or re-declared names whose definition changed — get a
/// detached initial fetch so `use:` groups populate without a manual
/// refresh; acquisition failure is a runtime condition, not a config defect.
///
/// Callers must hold the `CONFIG_MUTATION` lane (issue #543) — the
/// insert/prune ordering below is only meaningful when no sibling commit
/// can interleave a registry swap.
///
/// `raws` is the *candidate's* `proxy-providers:` declarations (the same
/// map `candidate` was materialized from) and `refresh` the shared
/// supervisor: after the registry swap, `reconcile` diffs them so
/// providers added, removed, or re-`interval`ed by this commit gain/lose
/// their background refresh task without a restart (issue #625). Pass
/// `None` for `raws` only when the candidate carried no
/// `proxy-providers:` section.
pub fn commit_proxy_providers(
    registry: &Arc<DashMap<String, Arc<ProxyProvider>>>,
    candidate: &std::collections::HashMap<String, Arc<ProxyProvider>>,
    strict: bool,
    raws: Option<&std::collections::HashMap<String, meow_config::raw::RawProxyProvider>>,
    refresh: &meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor,
) {
    debug_assert!(
        CONFIG_MUTATION.try_lock().is_err(),
        "caller must hold the CONFIG_MUTATION lane"
    );
    for (name, provider) in candidate {
        provider.set_strict(strict);
        // Reused providers may carry dead derived slots from failed
        // candidate builds — prune now that the committed groups hold their
        // views alive (issue #533 review).
        provider.prune_dead_derived();
        // Fetch when the committed object is *not* the one already live —
        // a newly declared name inserts fresh, and a re-declared name whose
        // definition changed carries a rebuilt provider that has never
        // fetched (issue #533 review).
        let needs_fetch = match registry.insert(name.clone(), Arc::clone(provider)) {
            Some(prev) => !Arc::ptr_eq(&prev, provider),
            None => true,
        };
        if needs_fetch {
            let provider = Arc::clone(provider);
            let name = name.clone();
            // `acquire_initial`, not `refresh`: a freshly committed
            // provider has an empty slot, so the on-disk cache fallback
            // (offline bootstrap) applies — refresh ticks deliberately
            // skip it to keep the in-memory last-good set.
            tokio::spawn(async move {
                if let Err(e) = provider.acquire_initial().await {
                    tracing::warn!("proxy-provider '{name}': initial fetch failed: {e}");
                }
            });
        } else if provider.take_deferred_initial() {
            // A reused provider whose `proxy:` could not resolve before
            // this commit's map was published — the name may resolve now,
            // so retry once. `refresh`, not `acquire_initial`: the cache
            // fallback already ran at startup, and rewinding a populated
            // slot to a staler cache would be a regression (issue #625
            // review).
            let provider = Arc::clone(provider);
            let name = name.clone();
            tokio::spawn(async move {
                if let Err(e) = provider.refresh().await {
                    tracing::warn!("proxy-provider '{name}': deferred fetch failed: {e}");
                }
            });
        }
    }
    registry.retain(|name, _| candidate.contains_key(name));
    // Publish first, then supervise — the interval refresh loops follow
    // the committed declarations: a provider added or re-`interval`ed by
    // this commit gains/respawns its task, a removed one loses it
    // (issue #625).
    refresh.reconcile(registry, raws);
}

/// `true` when the `dns:` section references runtime objects outside
/// itself: `#name`-tagged nameservers capture `Arc<dyn Proxy>` snapshots
/// at resolver-build time, and `rule-set:` nameserver-policy keys resolve
/// against the rule-provider registry. When either config references
/// them, a proxies/groups/rule-providers change must also rebuild DNS —
/// otherwise the resolver keeps dialing through adapters the new route
/// table no longer owns (issue #514 review).
fn dns_uses_runtime_refs(raw: &RawConfig) -> bool {
    dns_uses_proxy_refs(raw) || meow_config::dns_parser::dns_needs_rule_providers(raw)
}

/// `true` when the `dns:` section names a proxy adapter (`#name` tags) —
/// the subset of runtime refs that capture `Arc<dyn Proxy>` at build time.
/// Unlike `rule-set:` policy matchers (whose providers live in
/// `state.rule_providers` and refresh independently), a retained resolver
/// must be rebuilt whenever the route table's registry generation is
/// replaced, so this subset forces a rebuild on every commit (issue #533).
fn dns_uses_proxy_refs(raw: &RawConfig) -> bool {
    let Some(dns) = raw.dns.as_ref() else {
        return false;
    };
    let tagged = |s: &String| s.contains('#');
    let urls_tagged =
        |urls: &Option<Vec<String>>| urls.as_deref().is_some_and(|us| us.iter().any(tagged));
    urls_tagged(&dns.nameserver)
        || urls_tagged(&dns.fallback)
        || urls_tagged(&dns.default_nameserver)
        || urls_tagged(&dns.proxy_server_nameserver)
        || dns.nameserver_policy.as_ref().is_some_and(|m| {
            m.iter()
                .any(|(_k, v)| v.as_urls().iter().any(|u| u.contains('#')))
        })
}

/// `true` when two raw configs carry identical DNS-relevant inputs —
/// `dns:` plus `hosts:`, `ipv6`, and `geodata`, which all feed the
/// resolver build. Compared structurally (the `Raw*` types derive
/// `PartialEq`; map sections are order-insensitive, list sections keep
/// list order — same semantics the JSON comparison had, without building
/// a DOM per commit). When a `dns:` section references
/// proxies/rule-providers (`#name` nameserver tags, `rule-set:` policy
/// keys), those sections join the comparison — the resolver snapshots
/// them at build time.
fn dns_inputs_equal(a: &RawConfig, b: &RawConfig) -> bool {
    let base = a.dns == b.dns && a.hosts == b.hosts && a.ipv6 == b.ipv6 && a.geodata == b.geodata;
    if !base || !(dns_uses_runtime_refs(a) || dns_uses_runtime_refs(b)) {
        return base;
    }
    a.proxies == b.proxies
        && a.proxy_groups == b.proxy_groups
        && a.rule_providers == b.rule_providers
}

/// Decide whether `candidate` requires a DNS rebuild, and if so parse it.
/// `raw_config` must still hold the PRE-commit raw when this runs — the
/// comparison is old-vs-candidate. Shared by the API commit paths and the
/// subscription refresh loop (issue #514). `None` means unchanged — the
/// running resolver stays — which is only possible when neither side uses
/// `#name`/`rule-set:` runtime refs: those capture adapters whose registry
/// generation dies with the route swap, so they force a rebuild even on
/// unrelated changes (issue #533). `Err` rejects the whole mutation (issue
/// #514): a broken dns section must fail the PUT, not silently persist
/// while the process keeps resolving through the old resolver.
/// `rule_providers` is the CANDIDATE build's provider set
/// (`RebuildResult::rule_providers`) — `rule-set:` policy matchers clone
/// these Arcs so the resolver shares one provider object with the rules
/// and the live registry the commit installs (issue #533 review).
/// `prefetched_payloads` is the same build's payload snapshot
/// (`RebuildResult::prefetched_payloads`) — the DNS geo scan and private
/// provider load reuse those bytes instead of re-fetching them (issue
/// #543). Pass `None` only when no routing rebuild ran for this commit.
/// `prior_resolver` is the resolver generation being replaced — the
/// tunnel's live resolver — so the rebuild can carry the fake-IP pool
/// over when the range and store identity (in-memory vs the same
/// backing file) are unchanged (issue #514 review follow-up).
/// `dialer_registry` is the registry generation `proxies` was published
/// into — the candidate build's own cell. Provider fetch contexts built
/// here retain it so chained download adapters keep resolving after later
/// rebuilds (issue #533).
///
/// Callers must hold the `CONFIG_MUTATION` lane — the old-vs-candidate
/// comparison is only meaningful while no sibling commit can interleave
/// (issue #543).
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct piece of one commit's rebuild context"
)]
pub async fn reconcile_dns_config(
    raw_config: &RwLock<RawConfig>,
    candidate: &RawConfig,
    config_path: &str,
    proxies: &std::collections::HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
    rule_providers: Option<&HashMap<String, Arc<meow_config::rule_provider::RuleProvider>>>,
    prefetched_payloads: Option<&Arc<meow_config::rule_provider::PrefetchedPayloads>>,
    prior_resolver: Option<Arc<meow_dns::Resolver>>,
    dialer_registry: Option<&meow_proxy::dialer::ProxyRegistry>,
) -> Result<Option<meow_config::DnsConfig>, (StatusCode, String)> {
    debug_assert!(
        CONFIG_MUTATION.try_lock().is_err(),
        "caller must hold the CONFIG_MUTATION lane"
    );
    let unchanged = {
        let old = raw_config.read();
        // `#name`/`rule-set:` references capture objects whose identity is
        // generation-bound: proxy Arcs die with this commit's registry
        // cell, and a retained resolver's provider matchers would orphan
        // the moment the commit swaps `state.rule_providers` — they would
        // keep working but miss every later `PUT /providers/rules/{name}`
        // refresh (issue #533 review). Rebuild whenever either side has
        // them, even when the raw inputs compare equal.
        dns_inputs_equal(&old, candidate)
            && !dns_uses_runtime_refs(&old)
            && !dns_uses_runtime_refs(candidate)
    };
    if unchanged {
        return Ok(None);
    }
    let cache_dir = meow_config::resource_cache_dir_for_config_path(config_path);
    meow_config::parse_dns_from_raw(
        candidate,
        Some(&cache_dir),
        proxies,
        rule_providers,
        prefetched_payloads,
        prior_resolver.as_deref(),
        dialer_registry,
    )
    .await
    .map(Some)
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("dns config rebuild failed: {e}"),
        )
    })
}

/// Publish `dns.resolver` to every consumer that must not lag a route
/// swap: the tunnel slot, the process-wide host-resolver hook, and a live
/// standalone `dns.listen` server's resolver slot.
///
/// Commit paths call this BEFORE `update_routing`/`reload_routing` — the
/// swap drops the old `RouteTable` and its dialer-registry cell, so a
/// consumer still serving the old resolver would see its chained `#name`
/// upstreams fail closed until `publish_dns` ran (issue #533 review).
/// Idempotent: `publish_dns` re-runs the same installs (and additionally
/// handles listener rebinds). Writing the slot of a soon-to-be-rebound
/// server is harmless — it either keeps serving on the new generation or
/// is torn down moments later.
///
/// Callers must hold the `CONFIG_MUTATION` lane (issue #543) — the slot
/// swap must be ordered against the commit that produced `dns`.
pub fn install_resolver_everywhere(
    tunnel: &Tunnel,
    dns_server: &RwLock<Option<DnsServerHandle>>,
    dns: &meow_config::DnsConfig,
) {
    debug_assert!(
        CONFIG_MUTATION.try_lock().is_err(),
        "caller must hold the CONFIG_MUTATION lane"
    );
    tunnel.set_resolver(Arc::clone(&dns.resolver));

    // Same host-resolver policy as `main.rs` startup: installed whenever
    // DNS is enabled, unconditionally on VPN platforms where it is the
    // only thing keeping proxy-server lookups off libc `getaddrinfo`.
    const VPN_PLATFORM: bool = cfg!(any(target_os = "android", target_os = "ios"));
    if dns.enabled || VPN_PLATFORM {
        meow_common::set_host_resolver(Arc::new(
            meow_dns::ResolverHostHook::new_with_proxy_resolver(
                Arc::clone(&dns.resolver),
                dns.proxy_resolver.clone(),
            ),
        ));
    } else {
        meow_common::clear_host_resolver();
    }

    if let Some(h) = dns_server.read().as_ref() {
        *h.resolver_slot.write() = Arc::clone(&dns.resolver);
    }
}

/// Publish a rebuilt [`meow_config::DnsConfig`]: swap the tunnel's resolver
/// slot (routing lookups + built-in DIRECT), refresh the standalone DNS
/// server (in-place resolver swap when the listen addr is unchanged,
/// rebind otherwise), and re-install the process-wide host-resolver hook
/// under the same policy startup uses (issue #514). Callers must hold
/// the `CONFIG_MUTATION` lane (issue #543).
pub async fn publish_dns(
    tunnel: &Tunnel,
    dns_server: &RwLock<Option<DnsServerHandle>>,
    dns: &meow_config::DnsConfig,
) {
    debug_assert!(
        CONFIG_MUTATION.try_lock().is_err(),
        "caller must hold the CONFIG_MUTATION lane"
    );
    install_resolver_everywhere(tunnel, dns_server, dns);

    // Standalone `dns.listen` server keep-decision: `keep` also requires a
    // live serve task — the slot was already swapped above, so an
    // unchanged listen addr with a live task needs nothing more.
    {
        let guard = dns_server.read();
        if let Some(h) = guard.as_ref() {
            if dns.enabled && dns.listen_addr == Some(h.listen) && !h.task.is_finished() {
                info!("DNS resolver hot-swapped on unchanged listen socket");
                return;
            }
        }
    }

    // Listen addr changed, server toggled, or its task died: bind the new
    // socket BEFORE tearing the old listener down — a failed bind must not
    // strand the running server (the config is already committed; the old
    // listener is the only working path left).
    let new_bound = if dns.enabled {
        match dns.listen_addr {
            Some(addr) => {
                let server = meow_dns::DnsServer::new(Arc::clone(&dns.resolver), addr);
                let slot = server.resolver_slot();
                match server.bind().await {
                    Ok(bound) => Some((bound, slot)),
                    Err(e) => {
                        warn!("dns.listen {addr} bind failed after config reload: {e}");
                        None
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };
    match new_bound {
        Some((bound, slot)) => {
            let task = tokio::spawn(async move {
                if let Err(e) = bound.run().await {
                    warn!("DNS server error: {e}");
                }
            });
            // Install the new handle BEFORE tearing the old listener down:
            // `replace` commits the swap synchronously, so a cancellation
            // in the abort/await below can never leave the slot empty with
            // zero DNS listeners (issue #621).
            let old = dns_server.write().replace(DnsServerHandle {
                listen: dns.listen_addr.unwrap(),
                task,
                resolver_slot: slot,
            });
            if let Some(old) = old {
                old.task.abort();
                let _ = old.task.await;
            }
        }
        None => {
            // No new listener. Two sub-cases: the config turned the server
            // OFF (`!dns.enabled || listen_addr: None`) — tear the old one
            // down — or a rebind FAILED while the config still wants one —
            // keep the old listener alive (a live-but-stale listener beats
            // none; the config is already committed). All parking_lot guard
            // work stays inside the block — only the Send-able handle
            // escapes, so the abort/await below keeps this future Send.
            let old = {
                let mut guard = dns_server.write();
                let wanted = dns.enabled && dns.listen_addr.is_some();
                match guard.take() {
                    Some(old) if wanted && !old.task.is_finished() => {
                        warn!(
                            "dns.listen rebind failed; keeping existing listener on {}",
                            old.listen
                        );
                        // The socket stays, but the resolver generation
                        // must still follow — `tunnel.set_resolver` already
                        // swapped routing; leaving the kept listener on its
                        // old slot would serve a stale generation
                        // (issue #514 review).
                        *old.resolver_slot.write() = Arc::clone(&dns.resolver);
                        *guard = Some(old);
                        None
                    }
                    other => other,
                }
            };
            if let Some(old) = old {
                old.task.abort();
                let _ = old.task.await;
            }
        }
    }
}

async fn rebuild_from_raw_runtime_async(
    raw: RawConfig,
    resolver_slot: meow_dns::ResolverSlot,
    providers: HashMap<String, Arc<ProxyProvider>>,
    cache_dir: std::path::PathBuf,
    provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
) -> Result<meow_config::RebuildResult, String> {
    tokio::task::spawn_blocking(move || {
        meow_config::rebuild_from_raw_runtime(
            &raw,
            Some(&resolver_slot),
            &providers,
            Some(&cache_dir),
            &provider_dialer_registry,
        )
    })
    .await
    .map_err(|e| format!("config rebuild task failed: {e}"))?
    .map_err(|e| e.to_string())
}

// ── Subscriptions ────────────────────────────────────────────────────
// Subscriptions replace local proxies/groups/rules with the remote data as-is.

#[derive(Serialize)]
struct SubscriptionInfo {
    name: String,
    url: String,
    interval: Option<u64>,
    last_updated: Option<i64>,
    proxy: Option<String>,
    proxy_count: usize,
    group_count: usize,
    rule_count: usize,
}

async fn get_subscriptions(State(state): State<Arc<AppState>>) -> Json<Vec<SubscriptionInfo>> {
    let raw = state.raw_config.read();
    let subs = raw.subscriptions.as_deref().unwrap_or(&[]);
    let result: Vec<SubscriptionInfo> = subs
        .iter()
        .map(|s| SubscriptionInfo {
            name: s.name.clone(),
            url: s.url.clone(),
            interval: s.interval,
            last_updated: s.last_updated,
            proxy: s.proxy.clone(),
            proxy_count: raw.proxies.as_ref().map_or(0, std::vec::Vec::len),
            group_count: raw.proxy_groups.as_ref().map_or(0, std::vec::Vec::len),
            rule_count: raw.rules.as_ref().map_or(0, std::vec::Vec::len),
        })
        .collect();
    Json(result)
}

#[derive(Deserialize)]
struct AddSubscriptionRequest {
    name: String,
    url: String,
    interval: Option<u64>,
    proxy: Option<String>,
}

async fn add_subscription(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddSubscriptionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // `strict` follows the daemon's live config — the subscription payload
    // doesn't carry the flag (issue #533).
    let strict = state.raw_config.read().strict.unwrap_or(false);
    // `proxy:` resolves against the live route map — an unknown name fails
    // the request instead of silently fetching direct (issue #625).
    let download_proxy = meow_config::internal_http::resolve_download_proxy(
        &state.provider_dialer_registry,
        body.proxy.as_deref(),
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let mut fetched =
        meow_config::subscription::fetch_subscription(&body.url, strict, download_proxy.as_ref())
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("fetch failed: {e}")))?;
    // Resolve DNS-sourced ECH configs BEFORE the mutation lane — this is
    // async network I/O and must not serialize other config commits; the
    // stored snapshot then carries inline `ech-opts.config` so the in-lane
    // preresolve in `apply_raw_to_tunnel` is a no-op scan (issue #533).
    meow_config::ech_dns::preresolve_ech(&mut fetched.proxies, strict)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e} (strict mode)")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let pc = fetched.proxies.len();
    let gc = fetched.proxy_groups.len();
    let rc = fetched.rules.len();

    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();

        if let Some(ref subs) = raw.subscriptions {
            if subs.iter().any(|s| s.name == body.name) {
                return Err((
                    StatusCode::CONFLICT,
                    "subscription name already exists".into(),
                ));
            }
        }

        let sub = RawSubscription {
            name: body.name.clone(),
            url: body.url.clone(),
            interval: body.interval,
            last_updated: Some(now),
            proxy: body
                .proxy
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        };
        raw.subscriptions.get_or_insert_with(Vec::new).push(sub);

        // Replace proxies, groups, and rules with remote data as-is
        raw.proxies = Some(fetched.proxies);
        raw.proxy_groups = Some(fetched.proxy_groups);
        raw.rules = Some(fetched.rules);

        raw
    };
    commit_raw_candidate(&state, snapshot.clone()).await?;

    // Auto-save so subscription data is cached on disk
    meow_config::save_raw_config_async(&state.config_path, &snapshot)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "message": "subscription added",
        "proxy_count": pc, "group_count": gc, "rule_count": rc
    })))
}

async fn delete_subscription(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();

        if let Some(ref mut subs) = raw.subscriptions {
            let before = subs.len();
            subs.retain(|s| s.name != name);
            if subs.len() == before {
                return Err((StatusCode::NOT_FOUND, "subscription not found".into()));
            }
        } else {
            return Err((StatusCode::NOT_FOUND, "no subscriptions".into()));
        }

        // Clear everything from the remote subscription
        raw.proxies = Some(Vec::new());
        raw.proxy_groups = Some(Vec::new());
        raw.rules = Some(Vec::new());

        raw
    };
    commit_raw_candidate(&state, snapshot.clone()).await?;
    meow_config::save_raw_config_async(&state.config_path, &snapshot)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn refresh_subscription(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (url, proxy_name, strict) = {
        let raw = state.raw_config.read();
        let (url, proxy_name) = raw
            .subscriptions
            .as_ref()
            .and_then(|subs| subs.iter().find(|s| s.name == name))
            .map(|s| (s.url.clone(), s.proxy.clone()))
            .ok_or_else(|| (StatusCode::NOT_FOUND, "subscription not found".into()))?;
        (url, proxy_name, raw.strict.unwrap_or(false))
    };

    let download_proxy = meow_config::internal_http::resolve_download_proxy(
        &state.provider_dialer_registry,
        proxy_name.as_deref(),
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let mut fetched =
        meow_config::subscription::fetch_subscription(&url, strict, download_proxy.as_ref())
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("fetch failed: {e}")))?;
    // Same pre-lane ECH resolution as `add_subscription` (issue #533).
    meow_config::ech_dns::preresolve_ech(&mut fetched.proxies, strict)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e} (strict mode)")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let pc = fetched.proxies.len();
    let gc = fetched.proxy_groups.len();
    let rc = fetched.rules.len();

    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();

        // The subscription may have been deleted while the fetch ran —
        // re-verify inside the lane so a removed subscription's payload
        // cannot resurrect (issue #543).
        let sub = raw
            .subscriptions
            .as_mut()
            .and_then(|subs| subs.iter_mut().find(|s| s.name == name))
            .ok_or_else(|| (StatusCode::NOT_FOUND, "subscription not found".into()))?;
        // A same-name re-add (or `PUT /configs` rewrite) with a different
        // URL must not inherit the payload fetched from the old one
        // (issue #543 review).
        if sub.url != url {
            return Err((
                StatusCode::CONFLICT,
                "subscription changed while refresh was in flight".into(),
            ));
        }
        sub.last_updated = Some(now);

        raw.proxies = Some(fetched.proxies);
        raw.proxy_groups = Some(fetched.proxy_groups);
        raw.rules = Some(fetched.rules);

        raw
    };
    commit_raw_candidate(&state, snapshot.clone()).await?;

    // Auto-save so subscription data is cached on disk
    meow_config::save_raw_config_async(&state.config_path, &snapshot)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "message": "subscription refreshed",
        "proxy_count": pc, "group_count": gc, "rule_count": rc
    })))
}

// ── Proxy Groups ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct ProxyGroupInfo {
    name: String,
    #[serde(rename = "type")]
    group_type: String,
    proxies: Vec<String>,
    now: Option<String>,
    url: Option<String>,
    interval: Option<u64>,
    tolerance: Option<u16>,
}

async fn get_proxy_groups(State(state): State<Arc<AppState>>) -> Json<Vec<ProxyGroupInfo>> {
    let raw = state.raw_config.read();
    let groups = raw.proxy_groups.as_deref().unwrap_or(&[]);
    let route = state.tunnel.route_snapshot();
    let tunnel_proxies = &route.proxies;

    let result: Vec<ProxyGroupInfo> = groups
        .iter()
        .map(|g| {
            let runtime = tunnel_proxies.get(g.name.as_str());
            let now = runtime.and_then(|p| p.current());
            let proxies = runtime
                .and_then(|p| p.members())
                .unwrap_or_else(|| g.proxies.clone().unwrap_or_default());
            ProxyGroupInfo {
                name: g.name.clone(),
                group_type: g.group_type.clone(),
                proxies,
                now,
                url: g.url.clone(),
                interval: g.interval,
                tolerance: g.tolerance,
            }
        })
        .collect();
    Json(result)
}

#[derive(Deserialize)]
struct CreateProxyGroupRequest {
    name: String,
    #[serde(rename = "type")]
    group_type: String,
    proxies: Vec<String>,
    url: Option<String>,
    interval: Option<u64>,
    tolerance: Option<u16>,
}

async fn create_proxy_group(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateProxyGroupRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let group_name = body.name.clone();
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        if let Some(ref groups) = raw.proxy_groups {
            if groups.iter().any(|g| g.name == body.name) {
                return Err((StatusCode::CONFLICT, "group name already exists".into()));
            }
        }
        let group = RawProxyGroup {
            name: body.name,
            group_type: body.group_type,
            proxies: Some(body.proxies),
            url: body.url,
            interval: body.interval,
            tolerance: body.tolerance,
            ..Default::default()
        };
        raw.proxy_groups.get_or_insert_with(Vec::new).push(group);
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(Json(
        serde_json::json!({"message": "group created", "name": group_name}),
    ))
}

async fn update_proxy_group(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<CreateProxyGroupRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        let group = raw
            .proxy_groups
            .as_mut()
            .and_then(|groups| groups.iter_mut().find(|g| g.name == name))
            .ok_or_else(|| (StatusCode::NOT_FOUND, "group not found".into()))?;
        group.group_type = body.group_type;
        group.proxies = Some(body.proxies);
        group.url = body.url;
        group.interval = body.interval;
        group.tolerance = body.tolerance;
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_proxy_group(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        if let Some(ref mut groups) = raw.proxy_groups {
            let before = groups.len();
            groups.retain(|g| g.name != name);
            if groups.len() == before {
                return Err((StatusCode::NOT_FOUND, "group not found".into()));
            }
        } else {
            return Err((StatusCode::NOT_FOUND, "no groups".into()));
        }
        if let Some(ref mut rules) = raw.rules {
            rules.retain(|r| {
                let parts: Vec<&str> = r.split(',').collect();
                parts.last().is_none_or(|target| target.trim() != name)
            });
        }
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct SelectProxyRequest {
    name: String,
}

async fn select_proxy_in_group(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
    Json(body): Json<SelectProxyRequest>,
) -> StatusCode {
    let route = state.tunnel.route_snapshot();
    let Some(proxy) = route.proxies.get(group_name.as_str()).cloned() else {
        return StatusCode::NOT_FOUND;
    };
    let Some(selection) = proxy.selection() else {
        return StatusCode::BAD_REQUEST;
    };
    match selection.set(&body.name).await {
        Ok(()) => {
            info!("Proxy group '{}' switched to '{}'", group_name, body.name);
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

// ── Rules CRUD ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ReplaceRulesRequest {
    rules: Vec<String>,
}

async fn replace_rules(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ReplaceRulesRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        raw.rules = Some(body.rules);
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct UpdateRuleRequest {
    index: usize,
    rule: String,
}

async fn update_rule_at_index(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateRuleRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        let rules = raw.rules.get_or_insert_with(Vec::new);
        if body.index >= rules.len() {
            return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
        }
        rules[body.index] = body.rule;
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        let rules = raw.rules.get_or_insert_with(Vec::new);
        if index >= rules.len() {
            return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
        }
        rules.remove(index);
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ReorderRulesRequest {
    from: usize,
    to: usize,
}

async fn reorder_rules(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ReorderRulesRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        let rules = raw.rules.get_or_insert_with(Vec::new);
        if body.from >= rules.len() || body.to >= rules.len() {
            return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
        }
        let rule = rules.remove(body.from);
        rules.insert(body.to, rule);
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Delay probe endpoints ────────────────────────────────────────────
//
// Matches upstream mihomo `hub/route/proxies.go::getProxyDelay` and
// `hub/route/groups.go::getGroupDelay`. Error bodies are byte-exact copies
// of upstream's `ErrBadRequest` / `ErrNotFound` / `ErrRequestTimeout` /
// `newError("An error occurred in the delay test")`.

#[derive(Deserialize)]
struct DelayParams {
    url: Option<String>,
    timeout: Option<String>,
    expected: Option<String>,
}

#[derive(Serialize)]
struct DelayResp {
    delay: u16,
}

/// `{"message": "..."}` body matching upstream's error render.
fn msg_err(status: StatusCode, message: &'static str) -> Response {
    (status, Json(serde_json::json!({ "message": message }))).into_response()
}

/// Validate `url` and `timeout`. Returns `timeout` as `Duration` on success,
/// or the `400 Body invalid` response on any validation failure — matching
/// upstream's single "ErrBadRequest" shape for all parse errors.
fn parse_delay_params(params: &DelayParams) -> Result<Duration, Box<Response>> {
    // upstream: hub/route/proxies.go::getProxyDelay — url is not strictly
    // validated upstream, but an empty host would panic our prober.
    let url = params.url.as_deref().unwrap_or("").trim();
    if url.is_empty() {
        return Err(Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")));
    }

    // upstream parses `timeout` as int16 and treats parse failure as
    // ErrBadRequest. We reject 0 as well (a zero-budget probe is never useful).
    let timeout_str = params
        .timeout
        .as_deref()
        .ok_or_else(|| Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")))?;
    let timeout_ms: u16 = timeout_str
        .trim()
        .parse()
        .map_err(|_| Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")))?;
    if timeout_ms == 0 {
        return Err(Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")));
    }
    Ok(Duration::from_millis(timeout_ms as u64))
}

/// Probe a single adapter and record the result into its health handle.
/// On success records the measured delay; on any failure records `0` so
/// the proxy's `last_delay` tracks the most recent outcome.
async fn probe_and_record(
    proxy: &Arc<dyn meow_common::Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<u16, meow_proxy::health::UrlTestError> {
    meow_proxy::health::probe_and_record(proxy, url, expected, timeout).await
}

async fn get_proxy_delay(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<DelayParams>,
) -> Response {
    let timeout = match parse_delay_params(&params) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    let url = params.url.as_deref().unwrap_or("").to_string();
    let expected = params.expected.clone();

    let route = state.tunnel.route_snapshot();
    // upstream: hub/route/proxies.go::getProxyDelay — findProxyByName middleware
    let Some(proxy) = route.proxies.get(name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };
    // `route` stays alive across the probe — it owns this generation's
    // dialer registry, and a mid-probe route swap would fail a chained
    // member closed and report a live node dead (issue #533).

    match probe_and_record(&proxy, &url, expected.as_deref(), timeout).await {
        Ok(delay) => Json(DelayResp { delay }).into_response(),
        // upstream: `render.Status(r, http.StatusGatewayTimeout)` → 504.
        Err(meow_proxy::health::UrlTestError::Timeout) => {
            msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout")
        }
        // upstream: `newError("An error occurred in the delay test")` → 503.
        Err(meow_proxy::health::UrlTestError::Transport(_)) => msg_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred in the delay test",
        ),
    }
}

async fn get_group_delay(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<DelayParams>,
) -> Response {
    let route = state.tunnel.route_snapshot();
    let Some(group) = route.proxies.get(name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };
    // upstream: findProxyByName rejects non-groups with 404 for this route.
    // Resolved through the group rather than the proxies map so `use:` /
    // `include-all` provider members — which are not registry keys — are
    // probed and reported too (issue #543 item 1).
    let Some(member_proxies) = group.member_proxies() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };

    let timeout = match parse_delay_params(&params) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };

    // mihomo clears a URLTest/Fallback user pin before every group-wide
    // health check. Moved after query validation so a malformed request
    // does not silently clear user state.
    if let Some(selection) = group.selection().filter(|s| s.can_unfix()) {
        selection.force_set(None);
    }

    let url = params.url.as_deref().unwrap_or("").to_string();
    let expected = params.expected.clone();

    // The spawned tasks hold their own Arc clones, so the route snapshot
    // only needs to outlive the probe — it owns this generation's dialer
    // registry, and a mid-probe route swap would fail chained members
    // closed and report live nodes dead (issue #533).
    let members: Vec<(String, Arc<dyn meow_common::Proxy>)> = member_proxies
        .into_iter()
        .map(|p| (p.name().to_string(), p))
        .collect();

    // upstream: group probe wraps the whole batch in one context.WithTimeout,
    // not per-member. A slow member does not get its own budget.
    let collected = tokio::time::timeout(
        timeout,
        meow_proxy::health::probe_many_bounded_detailed(
            members,
            &url,
            expected.as_deref(),
            timeout,
            meow_proxy::health::GROUP_DELAY_CONCURRENCY,
        ),
    )
    .await;

    let Ok(pairs) = collected else {
        // upstream: 504 "Timeout". Even if some members completed before the
        // deadline, upstream still returns the timeout error — we match.
        return msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout");
    };

    let mut result: BTreeMap<String, u16> = BTreeMap::new();
    for pair in pairs {
        if matches!(pair.error, Some(meow_proxy::health::UrlTestError::Timeout)) {
            return msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout");
        }
        result.insert(pair.name, pair.delay);
    }
    Json(result).into_response()
}

// ── Config reload (M1.G-10) ──────────────────────────────────────────
// upstream: hub/server.go::patchConfig
// Class B per ADR-0002: payload must be base64 — a deliberate divergence
// from upstream, which consistently takes raw YAML bytes in `payload`;
// YAML parse errors always return 400 even with force=true; NOT upstream
// silent broken-config apply.

/// Spawn a TUN listener from a raw config and wait for device readiness.
/// Returns `Ok(Some(handle))` on success — the [`TunHandle`] carries the
/// lwIP core's done signal so `stop_tun` can await real teardown
/// (issue #514) — `Ok(None)` when `tun.enable` is false, or `Err(msg)`
/// when startup fails (permission denied, device-name conflict, timeout,
/// or the `listener-tun` feature is not compiled in).
#[cfg(feature = "listener-tun")]
async fn spawn_tun_from_raw(
    tunnel: &Tunnel,
    raw: &RawConfig,
) -> Result<Option<meow_tunnel::TunHandle>, String> {
    let tun_cfg = match meow_config::parse_tun_config(raw.tun.as_ref(), raw.max_connections) {
        Ok(c) => c,
        Err(e) => {
            return Err(format!("tun config parse error: {e}"));
        }
    };
    if !tun_cfg.enable {
        return Ok(None);
    }

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let listener = TunListener::new(
        tunnel.clone(),
        crate::tun_config_to_listener_config(&tun_cfg),
        "meow-tun".to_string(),
    )
    .with_readiness_signal(ready_tx);

    let handle = tokio::spawn(async move {
        if let Err(e) = listener.run().await {
            tracing::error!("TUN listener error: {e}");
        }
    });

    // Await the readiness signal so we don't store a dead JoinHandle when
    // device creation fails (e.g. os error 5 / permission denied). The
    // timeout guards against a genuinely stuck startup path; immediate
    // failures are reported through `TunReady::Failed` without delay.
    let (core_done, udp_flows) =
        match tokio::time::timeout(crate::TUN_STARTUP_TIMEOUT, ready_rx).await {
            Ok(Ok(meow_listener::TunReady::Ready {
                core_done,
                udp_flows,
            })) => (core_done, udp_flows),
            Ok(Ok(meow_listener::TunReady::Failed(msg))) => {
                tracing::error!(
                    "TUN listener failed to start: {msg} \
                 (check permissions / admin / CAP_NET_ADMIN)"
                );
                handle.abort();
                return Err(msg);
            }
            Ok(Err(_)) => {
                // Should not happen with ReadyNotifier, but handle defensively.
                tracing::error!("TUN listener readiness signal dropped unexpectedly");
                handle.abort();
                return Err("TUN listener readiness signal dropped unexpectedly".into());
            }
            Err(_) => {
                let msg = format!(
                    "TUN listener startup timed out after {} s",
                    crate::TUN_STARTUP_TIMEOUT.as_secs()
                );
                tracing::error!("{msg}");
                handle.abort();
                return Err(msg);
            }
        };

    Ok(Some(meow_tunnel::TunHandle {
        task: handle,
        core_done: Some(core_done),
        udp_flows,
    }))
}

#[cfg(not(feature = "listener-tun"))]
async fn spawn_tun_from_raw(
    _tunnel: &Tunnel,
    raw: &RawConfig,
) -> Result<Option<meow_tunnel::TunHandle>, String> {
    if raw.tun.as_ref().is_some_and(|t| t.enable) {
        // Err (not Ok(None)) so the off→on reconcile path rolls
        // `tun.enable` back — otherwise the stored config would claim TUN
        // is enabled while nothing can ever run.
        return Err("this build lacks the 'listener-tun' feature".into());
    }
    Ok(None)
}

/// Commit `candidate` as the new raw config and reconcile the TUN listener
/// against the `tun:` diff: an `enable` transition starts/stops it, and an
/// unchanged `enable: true` with any other parameter change (or changed
/// fake-IP inputs) restarts it so the running stack matches the committed
/// raw (issue #543). The whole sequence runs inside the
/// `CONFIG_MUTATION` lane every caller already holds, so two concurrent
/// mutations cannot interleave their TUN start/stop operations — without
/// that a disable→stop could run before a sibling enable→start has stored
/// its handle, leaving a running device behind an `enable=false` config.
///
/// On an off→on transition, if the TUN listener fails to start the stored
/// config is rolled back (`tun.enable` set to `false`) to prevent state
/// inconsistency (the HTTP API would report TUN as enabled but nothing is
/// actually running).  The HTTP response is still 204 — the error is
/// logged but not surfaced to the caller.
///
/// `dns` is the candidate's rebuilt [`meow_config::DnsConfig`] when its
/// DNS-relevant inputs changed (`Some`), already validated by the caller —
/// publishing it here keeps the swap inside the same lane (issue #514).
/// `prior_resolver` is the resolver generation that was live BEFORE the
/// caller early-installed the candidate's — the fake-IP comparison must
/// read its inputs, not `tunnel.resolver()` (which already serves the new
/// generation and would always compare equal) (issue #533 review).
async fn swap_config_and_reconcile_tun(
    state: &AppState,
    candidate: RawConfig,
    dns: Option<meow_config::DnsConfig>,
    prior_resolver: Arc<meow_dns::Resolver>,
) {
    debug_assert!(
        CONFIG_MUTATION.try_lock().is_err(),
        "caller must hold the CONFIG_MUTATION lane"
    );
    let new_enable = candidate.tun.as_ref().is_some_and(|t| t.enable);
    // Snapshot the candidate (only on an off→on transition, before it is
    // moved into the lock) so the parking_lot write guard — which is
    // !Send — is dropped before the first .await below.
    let (old_enable, tun_changed, snapshot, specs) = {
        let mut guard = state.raw_config.write();
        let old = guard.tun.as_ref().is_some_and(|t| t.enable);
        // Semantic diff (issue #543): compare the PARSED `TunConfig`s so
        // any real listener-parameter change (`mtu`, `auto-route`,
        // `dns-hijack`, addresses, inherited `max-connections`, …)
        // restarts a running listener while no-op respellings
        // (`auto-route: true` vs `fake-ip`, explicit defaults) and
        // warn-only ignored fields (`stack`, `strict-route`, …) do not.
        // When either side fails to parse, fall back to the raw diff —
        // a broken candidate stays conservative: restart → spawn fails
        // → `enable` rolls back.
        let tun_changed = if guard.tun == candidate.tun
            && guard.max_connections == candidate.max_connections
        {
            // Fast path: identical raw sections cannot differ
            // semantically — and skipping the parse avoids re-warn!ing
            // on upstream-only fields (`stack:`, `strict-route:`, …) on
            // every commit that never touched `tun:`.
            false
        } else {
            match (
                meow_config::parse_tun_config(guard.tun.as_ref(), guard.max_connections),
                meow_config::parse_tun_config(candidate.tun.as_ref(), candidate.max_connections),
            ) {
                (Ok(o), Ok(n)) => o != n,
                // Raw sections already known to differ — a broken
                // candidate stays conservative: restart → spawn fails
                // → `enable` rolls back.
                _ => true,
            }
        };
        let snapshot = (new_enable && !old).then(|| candidate.clone());
        // Extract health-check specs straight from the candidate before it
        // is moved into the lock — no second read of `raw_config` and no
        // deep clone of the group section (issue #514 review).
        let specs = meow_config::extract_health_check_specs(
            candidate.proxy_groups.as_deref().unwrap_or(&[]),
        );
        *guard = candidate;
        (old, tun_changed, snapshot, specs)
    };

    // Reconcile health-check tasks with the committed proxy-group section
    // — groups added get a check, removed abort, changed specs respawn
    // (issue #514). Sync; spawns under the lane lock are cheap.
    state.tunnel.reconcile_health_checks(&specs);

    // Publish the rebuilt DNS runtime — independent of TUN transitions, so
    // it must run before the equal-state early return (issue #514).
    // The fake-IP inputs of the resolver being replaced come from
    // `prior_resolver` — the caller already early-installed the candidate's
    // resolver, so `tunnel.resolver()` would read the NEW generation and
    // the on→on `fake_ip_changed` check below could never fire
    // (issue #533 review).
    let old_fake_ip = dns.is_some().then(|| {
        (
            prior_resolver.fake_ip_v4_net(),
            prior_resolver.fake_ip_v4_gateway(),
        )
    });
    if let Some(dns) = dns {
        publish_dns(&state.tunnel, &state.dns_server, &dns).await;
    }
    // The TUN listener snapshots `fake_ip_v4_net`/`fake_ip_v4_gateway`/
    // DnsGuard when the stack is built; after a resolver swap those are
    // stale — restart the listener so fake-ip-range/enhanced-mode changes
    // take effect instead of blackholing the new pool (issue #514).
    let fake_ip_changed = old_fake_ip.is_some_and(|(net, gw)| {
        let r = state.tunnel.resolver();
        r.fake_ip_v4_net() != net || r.fake_ip_v4_gateway() != gw
    });

    if old_enable == new_enable {
        // on → on with changed fake-IP inputs or any real `tun:` parameter
        // change: restart the listener so the running stack matches the
        // committed raw (issue #543). No `has_tun()` gate — a dead
        // but-enabled listener must attempt a respawn too, and a failed
        // one rolls `enable` back so it self-limits to one attempt.
        if old_enable && (fake_ip_changed || tun_changed) {
            state.tunnel.stop_tun().await;
            let raw = state.raw_config.read().clone();
            match spawn_tun_from_raw(&state.tunnel, &raw).await {
                Ok(Some(handle)) => {
                    state.tunnel.set_tun_handle(handle).await;
                    info!(
                        fake_ip_changed,
                        tun_changed, "TUN listener restarted via config reload"
                    );
                }
                // Unreachable like the off→on arm — `enable` is still true
                // in the committed raw. Roll back the same way rather than
                // persist `enable: true` with nothing running.
                Ok(None) => {
                    warn!("TUN listener restart returned no handle (config rolled back)");
                    if let Some(ref mut tun) = state.raw_config.write().tun {
                        tun.enable = false;
                    }
                }
                Err(e) => {
                    warn!("TUN listener failed to restart: {e} (config rolled back)");
                    if let Some(ref mut tun) = state.raw_config.write().tun {
                        tun.enable = false;
                    }
                }
            }
        }
        return;
    }
    if let Some(snapshot) = snapshot {
        // off → on. Defensive: if a handle somehow outlives a raw config
        // that already says `enable: false`, stop it first — the new
        // listener must never build a second lwIP core over a live one
        // (its PREVIOUS_CORE gate hard-fails the spawn after a 10 s
        // teardown timeout rather than stack two generations).
        state.tunnel.stop_tun().await;
        match spawn_tun_from_raw(&state.tunnel, &snapshot).await {
            Ok(Some(handle)) => {
                state.tunnel.set_tun_handle(handle).await;
                info!("TUN listener started via config reload");
            }
            Ok(None) => {
                // Unreachable today — `spawn_tun_from_raw` only yields
                // `Ok(None)` when `tun.enable` is false and this arm only
                // runs for off→on. Roll back like the `Err` arm rather
                // than persist `enable: true` with nothing running.
                warn!("TUN listener spawn returned no handle on off→on (config rolled back)");
                if let Some(ref mut tun) = state.raw_config.write().tun {
                    tun.enable = false;
                }
            }
            Err(e) => {
                // TUN failed to start — roll back tun.enable to false so
                // nyanpasu / the dashboard don't show TUN as active when
                // nothing is actually running.
                warn!("TUN listener failed to start: {e} (config rolled back)");
                if let Some(ref mut tun) = state.raw_config.write().tun {
                    tun.enable = false;
                }
            }
        }
    } else {
        // on → off
        state.tunnel.stop_tun().await;
        info!("TUN listener stopped via config reload");
    }
}

#[derive(Deserialize)]
struct PutConfigsBody {
    path: Option<String>,
    payload: Option<String>,
}

async fn put_configs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<PutConfigsBody>,
) -> Response {
    let force = params.get("force").is_some_and(|v| v == "true");

    let yaml =
        match (body.path, body.payload) {
            (Some(p), _) => match tokio::fs::read_to_string(&p).await {
                Ok(s) => s,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message": e.to_string()})),
                    )
                        .into_response()
                }
            },
            (_, Some(b64)) => {
                use base64::engine::general_purpose::STANDARD;
                use base64::Engine as _;
                let Ok(bytes) = STANDARD.decode(&b64) else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message": "payload is not valid base64"})),
                    )
                        .into_response();
                };
                match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"message": "payload is not valid UTF-8"})),
                        )
                            .into_response()
                    }
                }
            }
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"message": "request body must contain 'path' or 'payload'"}),
                ),
            )
                .into_response(),
        };

    // YAML syntax check — always 400 even with force=true (per spec)
    let mut raw_config: RawConfig = match serde_yaml::from_str(&yaml) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": format!("config parse error: {e}")})),
            )
                .into_response()
        }
    };

    // Pre-resolve any DNS-sourced ECH configs into inline base64. Under
    // `force`, a strict-ECH defect is retried leniently so it degrades the
    // same way as every other strict defect class (issue #533 review).
    if let Some(ps) = raw_config.proxies.as_mut() {
        if let Err(e) =
            meow_config::ech_dns::preresolve_ech(ps, raw_config.strict.unwrap_or(false)).await
        {
            if !force {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"message": format!("{e} (strict mode)")})),
                )
                    .into_response();
            }
            tracing::warn!("config reload: {e}; retrying ECH preresolve leniently under force");
            let _ = meow_config::ech_dns::preresolve_ech(ps, false).await;
        }
    }

    let _mutation = CONFIG_MUTATION.lock().await;

    // Semantic rebuild (proxy/rule parsing). Share the tunnel's resolver
    // slot so the rebuilt map's DIRECT adapter tracks later
    // `set_resolver` swaps (issue #514).
    let resolver_slot = state.tunnel.resolver_slot();
    let providers: std::collections::HashMap<_, _> = state
        .proxy_providers
        .iter()
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect();
    let cache_dir = meow_config::resource_cache_dir_for_config_path(&state.config_path);
    // When the strict rebuild fails and `force` retries leniently, the
    // DNS reconcile below must parse with the SAME effective strictness —
    // a `#name` reference to a proxy the lenient build dropped is a hard
    // error under `strict: true` but resolvable under the mode that
    // actually built `proxies` (issue #533 review).
    let mut dns_raw: Option<RawConfig> = None;
    let result = match rebuild_from_raw_runtime_async(
        raw_config.clone(),
        Arc::clone(&resolver_slot),
        providers.clone(),
        cache_dir.clone(),
        state.provider_dialer_registry.clone(),
    )
    .await
    {
        Ok(r) => Some(r),
        Err(e) => {
            if force {
                // `force` overrides `strict`: retry the rebuild leniently so
                // a strict-only defect doesn't wipe routing with an empty
                // `Default` result (issue #533 review). The retry prefetches
                // rule-provider payloads a second time — the failed build's
                // snapshot is discarded with it, so "one fetch per commit"
                // holds per *build*, not per request (issue #543 review).
                tracing::error!(
                    "config reload: rebuild failed ({e}); retrying leniently under force"
                );
                let mut lenient = raw_config.clone();
                lenient.strict = Some(false);
                match rebuild_from_raw_runtime_async(
                    lenient.clone(),
                    resolver_slot,
                    providers,
                    cache_dir,
                    state.provider_dialer_registry.clone(),
                )
                .await
                {
                    Ok(r) => {
                        dns_raw = Some(lenient);
                        Some(r)
                    }
                    Err(e2) => {
                        tracing::error!(
                            "forced config reload still failed: {e2}; keeping previous routing"
                        );
                        None
                    }
                }
            } else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"message": format!("config validation error: {e}")})),
                )
                    .into_response();
            }
        }
    };
    let Some(result) = result else {
        // The force contract accepts the config even when nothing in it
        // builds — persist the raw config but keep the previous routing,
        // resolver, and provider registries untouched. Refresh tasks
        // intentionally follow the *retained* registry (its providers
        // still back the live route table), so no reconcile runs here.
        let prior_resolver = state.tunnel.resolver();
        swap_config_and_reconcile_tun(&state, raw_config, None, prior_resolver).await;
        return StatusCode::NO_CONTENT.into_response();
    };
    let meow_config::RebuildResult {
        proxies,
        rules,
        dialer_registry,
        rule_providers,
        proxy_providers,
        prefetched_payloads,
    } = result;

    // A `tun:` section the listener cannot parse must be rejected before
    // commit (issue #543): admitted unchecked, the reconcile's restart
    // would tear down a healthy listener and only then fail the spawn-side
    // parse — leaving TUN down on a 204. `force` degrades to an error log
    // like the dns arm; the restart's rollback still prevents a false
    // `enable`.
    // Checked before `reconcile_dns_config` so a doomed PUT cannot trigger
    // that path's provider-registry side effects.
    if let Err(e) =
        meow_config::parse_tun_config(raw_config.tun.as_ref(), raw_config.max_connections)
    {
        if force {
            tracing::error!("config reload forced despite tun config error: {e}");
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": format!("tun config error: {e}")})),
            )
                .into_response();
        }
    }

    // Same contract for `listeners:` — an entry the startup parser rejects
    // (bad type, duplicate port, `udp: true` + managed firewall, IPv6 UDP
    // bind, …) must not be committed into `raw_config`: the next
    // `load_config` would hard-error on boot. Listeners are still a
    // startup snapshot (no hot-reload), this only gates persistence.
    if let Err(e) = meow_config::validate_named_listeners(&raw_config) {
        if force {
            tracing::error!("config reload forced despite listeners config error: {e}");
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": format!("listeners config error: {e}")})),
            )
                .into_response();
        }
    }

    // Issue #514: rebuild the DNS runtime too when its inputs changed —
    // failing here rejects the PUT before `reload_routing` publishes
    // anything (under `force` a broken dns section degrades to warn +
    // fallback, matching how force tolerates proxy errors).
    let dns = match reconcile_dns_config(
        &state.raw_config,
        dns_raw.as_ref().unwrap_or(&raw_config),
        &state.config_path,
        &proxies,
        Some(&rule_providers),
        Some(&prefetched_payloads),
        Some(state.tunnel.resolver()),
        Some(&dialer_registry),
    )
    .await
    {
        Ok(d) => d,
        Err((status, msg)) => {
            if force {
                tracing::error!("config reload forced despite dns rebuild error: {msg}");
                // Keeping the old resolver is only safe when it references
                // no runtime objects — `#name`/`rule-set:` adapters capture
                // refs whose registry/provider generation dies with the
                // route swap below. In that case fall back to a dns-less
                // candidate: a default resolver beats a dead one under the
                // force contract (issue #533 review).
                if dns_uses_runtime_refs(&state.raw_config.read()) {
                    let mut stripped = dns_raw.clone().unwrap_or_else(|| raw_config.clone());
                    stripped.dns = None;
                    stripped.strict = Some(false);
                    reconcile_dns_config(
                        &state.raw_config,
                        &stripped,
                        &state.config_path,
                        &proxies,
                        Some(&rule_providers),
                        Some(&prefetched_payloads),
                        Some(state.tunnel.resolver()),
                        Some(&dialer_registry),
                    )
                    .await
                    .unwrap_or_else(|(status2, msg2)| {
                        tracing::error!(
                            "dns-stripped reconcile failed ({status2}: {msg2}); \
                             keeping previous resolver"
                        );
                        None
                    })
                } else {
                    None
                }
            } else {
                return (status, Json(serde_json::json!({"message": msg}))).into_response();
            }
        }
    };

    // Prepare routing before the synchronous admission/cancellation boundary.
    // No old-policy setup can register after this cold reload completes.
    let mode = raw_config
        .mode
        .as_deref()
        .and_then(|mode| mode.parse().ok());
    // Snapshot the resolver being replaced BEFORE the early install — the
    // TUN reconcile compares its fake-IP inputs against the new
    // generation's (issue #533 review).
    let prior_resolver = state.tunnel.resolver();
    // Same early-install as the warm path: `reload_routing` drops the old
    // route table — and its registry cell — before `publish_dns` runs
    // below, so every resolver consumer (tunnel, host hook, live
    // `dns.listen` server) must be on the new generation first.
    if let Some(dns) = &dns {
        install_resolver_everywhere(&state.tunnel, state.dns_server.as_ref(), dns);
    }
    let dropped = state
        .tunnel
        .reload_routing(proxies, rules, mode, dialer_registry);
    if dropped > 0 {
        tracing::warn!(
            connections_dropped = dropped,
            "connection closure requested for cold reload"
        );
    }
    // Commit point: install the candidate's provider sets — the rules and
    // DNS `rule-set:` matchers above already reference these Arcs
    // (issue #533 review). `commit_registry` publishes the map *and*
    // reconciles the interval refresh loops in one step (issue #543).
    state
        .rule_provider_refresh
        .commit_registry(&state.rule_providers, rule_providers);
    commit_proxy_providers(
        &state.proxy_providers,
        &proxy_providers,
        raw_config.strict.unwrap_or(false),
        raw_config.proxy_providers.as_ref(),
        &state.proxy_provider_refresh,
    );

    swap_config_and_reconcile_tun(&state, raw_config, dns, prior_resolver).await;

    StatusCode::NO_CONTENT.into_response()
}

// ── Prometheus metrics (M1.H-2) ──────────────────────────────────────
// upstream: N/A — meow-rs enhancement; Go mihomo has no native /metrics endpoint.

async fn get_metrics(State(_state): State<Arc<AppState>>) -> Response {
    // prometheus-client 0.22 requires AtomicU64/AtomicI64. On targets without
    // 64-bit atomics (e.g. MIPS32) these types don't exist in std, so we
    // return 501. cfg(target_has_atomic) is the correct gate — i686 Windows
    // is 32-bit-pointer but DOES have AtomicU64 via CMPXCHG8B.
    #[cfg(not(target_has_atomic = "64"))]
    {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "metrics require 64-bit atomic support",
        )
            .into_response();
    }

    #[cfg(target_has_atomic = "64")]
    {
        use prometheus_client::encoding::text::encode;
        use prometheus_client::metrics::counter::Counter;
        use prometheus_client::metrics::family::Family;
        use prometheus_client::metrics::gauge::Gauge;
        use prometheus_client::registry::Registry;
        use std::sync::atomic::{AtomicI64, AtomicU64};

        let mut registry = Registry::default();
        let stats = _state.tunnel.statistics();
        let (upload_total, download_total) = stats.snapshot();

        // meow_traffic_bytes — counter{direction}
        let traffic = Family::<Vec<(String, String)>, Counter<u64, AtomicU64>>::default();
        traffic
            .get_or_create(&vec![("direction".to_string(), "upload".to_string())])
            .inc_by(upload_total.max(0) as u64);
        traffic
            .get_or_create(&vec![("direction".to_string(), "download".to_string())])
            .inc_by(download_total.max(0) as u64);
        registry.register(
            "meow_traffic_bytes",
            "Cumulative bytes transferred since process start",
            traffic,
        );

        // meow_connections_active — gauge
        let connections_active = Gauge::<i64, AtomicI64>::default();
        connections_active.set(stats.active_connection_count() as i64);
        registry.register(
            "meow_connections_active",
            "Number of currently open connections",
            connections_active,
        );

        // meow_proxy_alive and meow_proxy_delay_ms — gauge{proxy_name,adapter_type}
        let proxy_alive = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        let proxy_delay = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        let route = _state.tunnel.route_snapshot();
        for (name, proxy) in route.proxies.iter() {
            let labels = vec![
                ("proxy_name".to_string(), name.to_string()),
                ("adapter_type".to_string(), proxy.adapter_type().to_string()),
            ];
            proxy_alive
                .get_or_create(&labels)
                .set(if proxy.alive() { 1 } else { 0 });
            // Omit delay series entirely when no health check has run (empty history).
            // NOT -1, NOT 0 — absence is the correct Prometheus signal for "unknown".
            if !proxy.delay_history().is_empty() {
                proxy_delay
                    .get_or_create(&labels)
                    .set(proxy.last_delay() as i64);
            }
        }
        registry.register(
            "meow_proxy_alive",
            "Proxy alive status (1=alive, 0=dead)",
            proxy_alive,
        );
        registry.register(
            "meow_proxy_delay_ms",
            "Last measured proxy round-trip delay in milliseconds",
            proxy_delay,
        );

        // meow_rules_matched — counter{rule_type,action}
        let rules_matched = Family::<Vec<(String, String)>, Counter<u64, AtomicU64>>::default();
        for ((rule_type, action), count) in stats.rule_match.snapshot() {
            rules_matched
                .get_or_create(&vec![
                    ("rule_type".to_string(), rule_type.to_string()),
                    ("action".to_string(), action.to_string()),
                ])
                .inc_by(count);
        }
        registry.register(
            "meow_rules_matched",
            "Cumulative rule matches by type and action",
            rules_matched,
        );

        // meow_memory_rss_bytes — gauge
        let memory_rss = Gauge::<i64, AtomicI64>::default();
        memory_rss.set(read_rss_bytes().await as i64);
        registry.register(
            "meow_memory_rss_bytes",
            "Current process RSS in bytes",
            memory_rss,
        );

        // meow_info — gauge{version,mode} always = 1
        let info = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        info.get_or_create(&vec![
            ("version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
            ("mode".to_string(), _state.tunnel.mode().to_string()),
        ])
        .set(1);
        registry.register("meow_info", "meow-rs runtime info", info);

        let mut body = String::new();
        encode(&mut body, &registry).expect("prometheus text encoding is infallible");
        (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response()
    }
}

// ── WebSocket: log stream ────────────────────────────────────────────

#[derive(Deserialize)]
struct LogsParams {
    level: Option<String>,
    format: Option<String>,
}

fn parse_requested_log_level(
    value: Option<&str>,
) -> Result<crate::log_stream::LogLevel, Box<Response>> {
    let value = value.unwrap_or("info");
    match value.to_ascii_lowercase().as_str() {
        "debug" | "info" | "warning" | "warn" | "error" | "silent" => Ok(parse_log_level(value)),
        _ => Err(Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid"))),
    }
}

fn log_json(msg: &LogMessage, structured: bool) -> String {
    if !structured {
        return serde_json::json!({"type": msg.level.as_str(), "payload": msg.payload}).to_string();
    }
    let level = if msg.level.as_str() == "warning" {
        "warn"
    } else {
        msg.level.as_str()
    };
    let t = msg.time.time();
    serde_json::json!({
        "time": format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second()),
        "level": level,
        "message": msg.payload,
        "fields": [],
    })
    .to_string()
}

// upstream: hub/route/logs.go::getLogs
async fn get_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogsParams>,
    MaybeWebSocket(ws): MaybeWebSocket,
) -> Response {
    let level = match parse_requested_log_level(params.level.as_deref()) {
        Ok(level) => level,
        Err(response) => return *response,
    };
    let structured = params.format.as_deref() == Some("structured");
    let mut rx = state.log_tx.subscribe();
    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            loop {
                match rx.recv().await {
                    Ok(msg) if msg.level >= level => {
                        if socket
                            .send(Message::Text(log_json(&msg, structured).into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    let stream = futures::stream::unfold(rx, move |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(msg) if msg.level >= level => {
                    return Some((
                        Ok::<String, std::convert::Infallible>(format!(
                            "{}\n",
                            log_json(&msg, structured)
                        )),
                        rx,
                    ));
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("valid log stream response")
}

// ── WebSocket: memory stream ─────────────────────────────────────────

// upstream: hub/route/memory.go
//
// One process-wide sampler task reads RSS + limit and serialises the JSON
// frame once per tick; every connected socket forwards the shared string
// (audit M8 — previously each socket sampled and serialised independently,
// per-socket per-tick). The sampler starts with the first subscriber and
// exits once the last socket disconnects, so an idle API server pays nothing.
// Model: the log websocket's single-serialisation broadcast fan-out.
static MEMORY_FEED: std::sync::Mutex<Option<broadcast::Sender<Arc<str>>>> =
    std::sync::Mutex::new(None);

fn subscribe_memory_feed() -> broadcast::Receiver<Arc<str>> {
    let mut guard = MEMORY_FEED.lock().expect("memory feed lock poisoned");
    if let Some(tx) = guard.as_ref() {
        // Sampler still alive (it clears the slot under this lock on exit).
        return tx.subscribe();
    }
    let (tx, rx) = broadcast::channel(2);
    *guard = Some(tx.clone());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            if tx.receiver_count() == 0 {
                // Re-check under the lock so a subscriber arriving right now
                // either sees the live sender or a cleared slot — never a
                // sender whose sampler has already exited.
                let mut guard = MEMORY_FEED.lock().expect("memory feed lock poisoned");
                if tx.receiver_count() == 0 {
                    *guard = None;
                    break;
                }
            }
            let inuse = read_rss_bytes().await;
            let oslimit = read_os_memory_limit().await;
            let msg: Arc<str> = Arc::from(format!("{{\"inuse\":{inuse},\"oslimit\":{oslimit}}}"));
            let _ = tx.send(msg);
        }
    });
    rx
}

async fn get_memory(
    State(_state): State<Arc<AppState>>,
    MaybeWebSocket(ws): MaybeWebSocket,
) -> Response {
    let first: Arc<str> = Arc::from("{\"inuse\":0,\"oslimit\":0}");
    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            if socket
                .send(Message::Text(first.as_ref().into()))
                .await
                .is_err()
            {
                return;
            }
            let mut feed = subscribe_memory_feed();
            loop {
                let msg = match feed.recv().await {
                    Ok(msg) => msg,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if socket
                    .send(Message::Text(msg.as_ref().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    let feed = subscribe_memory_feed();
    let stream = futures::stream::unfold((Some(first), feed), |(first, mut feed)| async move {
        if let Some(first) = first {
            return Some((
                Ok::<String, std::convert::Infallible>(format!("{first}\n")),
                (None, feed),
            ));
        }
        loop {
            match feed.recv().await {
                Ok(msg) => {
                    return Some((
                        Ok::<String, std::convert::Infallible>(format!("{msg}\n")),
                        (None, feed),
                    ));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("valid memory stream response")
}

async fn read_rss_bytes() -> u64 {
    tokio::task::spawn_blocking(|| {
        use sysinfo::{Pid, ProcessesToUpdate, System};
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
        sys.process(pid).map_or(0, sysinfo::Process::memory)
    })
    .await
    .unwrap_or(0)
}

async fn read_os_memory_limit() -> u64 {
    #[cfg(target_os = "linux")]
    {
        read_os_memory_limit_linux().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(target_os = "linux")]
async fn read_os_memory_limit_linux() -> u64 {
    // Try cgroup v2 memory limit first, fall back to rlimit.
    if let Ok(s) = tokio::fs::read_to_string("/sys/fs/cgroup/memory.max").await {
        if let Ok(n) = s.trim().parse::<u64>() {
            return n;
        }
    }
    // rlimit RLIMIT_AS (virtual address space) as a proxy; RLIMIT_RSS is deprecated.
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_AS, &mut rl) == 0 && rl.rlim_cur != libc::RLIM_INFINITY {
            #[cfg(target_pointer_width = "32")]
            {
                return rl.rlim_cur as u64;
            }
            #[cfg(not(target_pointer_width = "32"))]
            {
                return rl.rlim_cur;
            }
        }
    }
    0
}

// ── Proxy providers ───────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderInfo {
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    vehicle_type: String,
    proxies: Vec<ProxyInfo>,
    #[serde(rename = "testUrl")]
    test_url: String,
    #[serde(rename = "expectedStatus")]
    expected_status: String,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

fn unix_rfc3339(seconds: u64) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    (seconds > 0)
        .then(|| time::OffsetDateTime::from_unix_timestamp(seconds as i64).ok())
        .flatten()
        .and_then(|time| time.format(&Rfc3339).ok())
}

fn provider_to_info(name: &str, provider: &ProxyProvider) -> ProviderInfo {
    let proxies = provider
        .proxies()
        .iter()
        .map(ProxyInfo::from_proxy)
        .collect();
    ProviderInfo {
        name: name.to_string(),
        provider_type: "Proxy".to_string(),
        vehicle_type: provider.vehicle_type.to_string(),
        proxies,
        test_url: provider
            .health_check
            .as_ref()
            .map_or_else(String::new, |hc| hc.url.clone()),
        expected_status: provider
            .health_check
            .as_ref()
            .map_or_else(String::new, |hc| hc.expected_status.clone()),
        updated_at: unix_rfc3339(provider.updated_at_secs()),
    }
}

async fn get_providers(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut map = serde_json::Map::new();
    for entry in state.proxy_providers.iter() {
        let info = provider_to_info(entry.key(), entry.value());
        map.insert(
            entry.key().clone(),
            serde_json::to_value(info).unwrap_or_default(),
        );
    }
    Json(serde_json::json!({ "providers": map }))
}

async fn get_provider(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    match state.proxy_providers.get(&name) {
        Some(entry) => Json(provider_to_info(&name, entry.value())).into_response(),
        None => msg_err(StatusCode::NOT_FOUND, "resource not found"),
    }
}

async fn refresh_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    let provider = match state.proxy_providers.get(&name) {
        Some(entry) => Arc::clone(entry.value()),
        None => return msg_err(StatusCode::NOT_FOUND, "resource not found"),
    };
    match provider.refresh().await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"message": e})),
        )
            .into_response(),
    }
}

/// Trigger a health check for all proxies in the named provider.
/// Accepts the same `url` and `timeout` query params as `GET /proxies/:name/delay`.
async fn provider_healthcheck(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    let provider = match state.proxy_providers.get(&name) {
        Some(entry) => Arc::clone(entry.value()),
        None => return msg_err(StatusCode::NOT_FOUND, "resource not found"),
    };

    let Some(health) = provider.health_check.as_ref() else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let timeout = Duration::from_millis(health.timeout.max(1));
    let url = health.url.clone();
    let expected = (!health.expected_status.is_empty()).then(|| health.expected_status.clone());

    let members = provider
        .proxies()
        .into_iter()
        .map(|proxy| (proxy.name().to_string(), proxy))
        .collect();

    let _ = meow_proxy::health::probe_many_bounded(
        members,
        &url,
        expected.as_deref(),
        timeout,
        meow_proxy::health::PROVIDER_HEALTHCHECK_CONCURRENCY,
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

async fn get_provider_proxy(
    State(state): State<Arc<AppState>>,
    Path((provider_name, proxy_name)): Path<(String, String)>,
) -> Response {
    let Some(provider) = state.proxy_providers.get(&provider_name) else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    match provider
        .proxies()
        .into_iter()
        .find(|p| p.name() == proxy_name)
    {
        Some(proxy) => Json(ProxyInfo::from_proxy(&proxy)).into_response(),
        None => msg_err(StatusCode::NOT_FOUND, "Resource not found"),
    }
}

async fn provider_proxy_healthcheck(
    State(state): State<Arc<AppState>>,
    Path((provider_name, proxy_name)): Path<(String, String)>,
    Query(params): Query<DelayParams>,
) -> Response {
    let timeout = match parse_delay_params(&params) {
        Ok(timeout) => timeout,
        Err(response) => return *response,
    };
    let Some(provider) = state.proxy_providers.get(&provider_name) else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    let Some(proxy) = provider
        .proxies()
        .into_iter()
        .find(|p| p.name() == proxy_name)
    else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    match probe_and_record(
        &proxy,
        params.url.as_deref().unwrap_or(""),
        params.expected.as_deref(),
        timeout,
    )
    .await
    {
        Ok(delay) => Json(DelayResp { delay }).into_response(),
        Err(meow_proxy::health::UrlTestError::Timeout) => {
            msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout")
        }
        Err(meow_proxy::health::UrlTestError::Transport(_)) => msg_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred in the delay test",
        ),
    }
}

// ── Rule Providers ────────────────────────────────────────────────────

#[derive(Serialize)]
struct RuleProviderInfo {
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    behavior: String,
    format: String,
    #[serde(rename = "ruleCount")]
    rule_count: usize,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    #[serde(rename = "vehicleType")]
    vehicle_type: String,
}

impl RuleProviderInfo {
    fn from_provider(p: &Arc<RuleProvider>, format: Option<&str>) -> Self {
        let vehicle_type = match p.provider_type {
            meow_config::rule_provider::ProviderType::Http => "HTTP",
            meow_config::rule_provider::ProviderType::File => "File",
            meow_config::rule_provider::ProviderType::Inline => "Inline",
        };
        Self {
            name: p.name.clone(),
            provider_type: "Rule".to_string(),
            behavior: p.behavior.to_string(),
            format: format.unwrap_or("yaml").to_string(),
            rule_count: p.rule_count(),
            updated_at: unix_rfc3339(p.updated_at_secs()).unwrap_or_default(),
            vehicle_type: vehicle_type.to_string(),
        }
    }
}

#[derive(Serialize)]
struct RuleProvidersResponse {
    providers: HashMap<String, RuleProviderInfo>,
}

async fn get_rule_providers(State(state): State<Arc<AppState>>) -> Json<RuleProvidersResponse> {
    let providers = state.rule_providers.read();
    let raw = state.raw_config.read();
    let map: HashMap<String, RuleProviderInfo> = providers
        .iter()
        .map(|(name, p): (&String, &Arc<RuleProvider>)| {
            let format = raw
                .rule_providers
                .as_ref()
                .and_then(|all| all.get(name))
                .and_then(|provider| provider.format.as_deref());
            (name.clone(), RuleProviderInfo::from_provider(p, format))
        })
        .collect();
    Json(RuleProvidersResponse { providers: map })
}

async fn get_rule_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<RuleProviderInfo>, StatusCode> {
    let providers = state.rule_providers.read();
    let p = providers.get(&name).ok_or(StatusCode::NOT_FOUND)?;
    let raw = state.raw_config.read();
    let format = raw
        .rule_providers
        .as_ref()
        .and_then(|all| all.get(&name))
        .and_then(|provider| provider.format.as_deref());
    Ok(Json(RuleProviderInfo::from_provider(p, format)))
}

async fn refresh_rule_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> StatusCode {
    let provider = {
        let providers = state.rule_providers.read();
        providers.get(&name).cloned()
    };
    let Some(p) = provider else {
        return StatusCode::NOT_FOUND;
    };
    // The provider re-parses in its own load-time ParserContext, so a
    // classical payload with GEOIP/GEOSITE entries survives the refresh
    // (issue #533 review).
    match p.refresh().await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::warn!(provider = %name, "rule-provider refresh failed: {:#}", e);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

// ── Listeners ─────────────────────────────────────────────────────────

async fn get_listeners(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let items: Vec<serde_json::Value> = state
        .listeners
        .iter()
        .map(|l| {
            let mut item = serde_json::json!({
                "name": l.name,
                "type": l.spec.type_name(),
                "port": l.port,
                "listen": l.listen,
            });
            // TProxy listeners disclose who owns the redirect rules — a
            // deployer checking whether the table/anchor they installed is
            // supposed to coexist with a meow-managed one reads this field
            // (issue #563). `udp`/`udp-timeout` are disclosed for the same
            // reason: external TPROXY rules are only useful if the UDP
            // path is actually enabled (issue #564).
            if let meow_config::ListenerSpec::TProxy {
                firewall,
                udp,
                udp_timeout,
                ..
            } = &l.spec
            {
                item["firewall"] = serde_json::json!(firewall);
                item["udp"] = serde_json::json!(udp);
                item["udp-timeout"] = serde_json::json!(udp_timeout);
            }
            item
        })
        .collect();
    Json(serde_json::json!(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connections_interval_rejects_zero_and_garbage() {
        // `0` and non-numeric input stay a 400 at the handler — the parser
        // signals both with `None`.
        assert_eq!(parse_connections_interval(Some("0")), None);
        assert_eq!(parse_connections_interval(Some("abc")), None);
        assert_eq!(parse_connections_interval(Some("-1")), None);
        assert_eq!(parse_connections_interval(Some("")), None);
    }

    #[test]
    fn connections_interval_clamps_to_floor() {
        assert_eq!(parse_connections_interval(Some("1")), Some(100));
        assert_eq!(parse_connections_interval(Some("99")), Some(100));
        assert_eq!(parse_connections_interval(Some("100")), Some(100));
    }

    #[test]
    fn connections_interval_passes_through_above_floor() {
        assert_eq!(parse_connections_interval(Some("101")), Some(101));
        assert_eq!(parse_connections_interval(Some("5000")), Some(5000));
        assert_eq!(parse_connections_interval(None), Some(1000));
    }

    /// Issue #533: a `#name` nameserver captures adapters whose registry
    /// generation dies with every route swap, and a `rule-set:` policy key
    /// captures provider Arcs whose identity dies when the commit swaps
    /// `state.rule_providers` — a retained resolver would keep matching
    /// against orphaned objects. When either ref exists the resolver must
    /// rebuild on EVERY commit; "unchanged" is only valid without them
    /// (issue #533 review).
    #[test]
    fn runtime_refs_force_dns_rebuild_on_identical_inputs() {
        let raw_with_tag: RawConfig =
            serde_yaml::from_str("dns:\n  enable: true\n  nameserver:\n    - tcp://1.1.1.1#P\n")
                .unwrap();
        // Identical raw on both sides — dns_inputs_equal says unchanged, but
        // the proxy ref must override (its adapters' cell died in the swap).
        assert!(dns_inputs_equal(&raw_with_tag, &raw_with_tag));
        assert!(dns_uses_proxy_refs(&raw_with_tag));

        let unchanged = dns_inputs_equal(&raw_with_tag, &raw_with_tag)
            && !dns_uses_runtime_refs(&raw_with_tag)
            && !dns_uses_runtime_refs(&raw_with_tag);
        assert!(!unchanged, "a `#name` nameserver must force a rebuild");

        // rule-set: policy refs also force a rebuild — the matcher holds
        // provider Arcs that must track the committed generation's set.
        let raw_with_ruleset: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  nameserver-policy:\n    'rule-set:cn':\n      - 223.5.5.5\nrule-providers:\n  cn:\n    type: inline\n    behavior: domain\n    payload: [example.cn]\n",
        )
        .unwrap();
        assert!(!dns_uses_proxy_refs(&raw_with_ruleset));
        assert!(dns_uses_runtime_refs(&raw_with_ruleset));
        let unchanged = dns_inputs_equal(&raw_with_ruleset, &raw_with_ruleset)
            && !dns_uses_runtime_refs(&raw_with_ruleset)
            && !dns_uses_runtime_refs(&raw_with_ruleset);
        assert!(!unchanged, "a `rule-set:` policy ref must force a rebuild");

        let raw_plain: RawConfig =
            serde_yaml::from_str("dns:\n  enable: true\n  nameserver:\n    - 223.5.5.5\n").unwrap();
        assert!(!dns_uses_runtime_refs(&raw_plain));
        assert!(
            dns_inputs_equal(&raw_plain, &raw_plain)
                && !dns_uses_runtime_refs(&raw_plain)
                && !dns_uses_runtime_refs(&raw_plain)
        );
    }

    /// Issue #533 review: `swap_config_and_reconcile_tun` compares the TUN
    /// listener's fake-IP inputs against the resolver generation being
    /// REPLACED — captured before the caller's early `set_resolver`. Reading
    /// `tunnel.resolver()` at that point would see the new generation and
    /// `fake_ip_changed` could never fire. Pin the building blocks: the
    /// comparison reads `prior_resolver`'s accessors, and a changed pool
    /// range must compare unequal.
    #[test]
    fn fake_ip_inputs_come_from_the_prior_resolver() {
        let mk = |net: &str| {
            let mut r = meow_dns::Resolver::new(
                vec![],
                vec![],
                meow_common::DnsMode::FakeIp,
                meow_trie::DomainTrie::new(),
                true,
                true,
            );
            r.set_fakeip_v4(Arc::new(
                meow_dns::Pool::new(
                    net.parse().unwrap(),
                    Arc::new(meow_dns::MemoryStore::new(1024)),
                )
                .unwrap(),
            ));
            r
        };
        let prior = mk("198.18.0.0/16");
        let candidate_same = mk("198.18.0.0/16");
        let candidate_changed = mk("198.19.0.0/16");

        let inputs = |r: &meow_dns::Resolver| (r.fake_ip_v4_net(), r.fake_ip_v4_gateway());
        assert_eq!(inputs(&prior), inputs(&candidate_same));
        assert_ne!(
            inputs(&prior),
            inputs(&candidate_changed),
            "a fake-IP range change must be visible across generations"
        );
    }

    /// Issue #533 review: committing a candidate provider set must reuse the
    /// SAME Arc for still-declared names (provider slots bound into rebuilt
    /// groups keep tracking the live object), install newly declared ones,
    /// drop removed ones, and propagate the generation's `strict` flag onto
    /// every committed provider.
    #[tokio::test]
    async fn commit_proxy_providers_swaps_registry_membership() {
        use meow_config::proxy_provider::ProxyProvider;
        use meow_config::raw::RawProxyProvider;

        let mk = |name: &str| {
            let def: RawProxyProvider =
                serde_yaml::from_str("type: http\nurl: http://127.0.0.1:1/x.yaml").unwrap();
            Arc::new(
                ProxyProvider::new(name, &def, None, false, false, Default::default()).unwrap(),
            )
        };
        let registry: Arc<DashMap<String, Arc<ProxyProvider>>> = Arc::new(DashMap::new());
        let keep = mk("keep");
        registry.insert("keep".to_string(), Arc::clone(&keep));
        registry.insert("gone".to_string(), mk("gone"));
        let refresh =
            meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor::default();

        // `commit_proxy_providers` asserts the caller holds the lane.
        let _lane = CONFIG_MUTATION.lock().await;

        let candidate: HashMap<String, Arc<ProxyProvider>> = HashMap::from([
            ("keep".to_string(), Arc::clone(&keep)), // reused Arc
            ("fresh".to_string(), mk("fresh")),
        ]);
        commit_proxy_providers(&registry, &candidate, true, None, &refresh);

        assert!(Arc::ptr_eq(registry.get("keep").unwrap().value(), &keep));
        assert!(registry.contains_key("fresh"));
        assert!(!registry.contains_key("gone"), "removed decls are pruned");

        // A candidate with no providers at all clears the registry.
        commit_proxy_providers(&registry, &HashMap::new(), false, None, &refresh);
        assert!(registry.is_empty());
    }

    /// Issue #625: the commit must wire the interval supervisor end to end —
    /// a committed `file` provider with `interval: 1` must tick-refresh its
    /// slot without any manual PUT. Driven on a real file + real clock so a
    /// missing `reconcile` call fails the assertion outright.
    ///
    /// The provider is pre-seeded into the registry so the commit's
    /// `needs_fetch` is false — otherwise the detached initial fetch (which
    /// polls on the test's first `.await`, after the file is rewritten)
    /// satisfies the assertion even with `reconcile` stubbed out.
    #[tokio::test]
    async fn commit_proxy_providers_reconciles_interval_tasks() {
        use meow_config::proxy_provider::ProxyProvider;
        use meow_config::raw::RawProxyProvider;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.yaml");
        std::fs::write(&path, "proxies: []\n").unwrap();
        let raw = RawProxyProvider {
            provider_type: "file".to_string(),
            url: None,
            path: Some("p.yaml".to_string()),
            interval: Some(1),
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: None,
            override_: None,
            proxy: None,
            dialer_proxy: None,
        };
        let provider = Arc::new(
            ProxyProvider::new(
                "p",
                &raw,
                Some(dir.path()),
                false,
                false,
                Default::default(),
            )
            .unwrap(),
        );
        assert_eq!(provider.proxies().len(), 0);

        let registry: Arc<DashMap<String, Arc<ProxyProvider>>> = Arc::new(DashMap::new());
        // Pre-seed: same Arc ⇒ `needs_fetch` false ⇒ no detached initial
        // fetch — the interval task is the only refresher in this test.
        registry.insert("p".to_string(), Arc::clone(&provider));
        let refresh =
            meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor::default();
        let _lane = CONFIG_MUTATION.lock().await;
        let candidate: HashMap<String, Arc<ProxyProvider>> =
            HashMap::from([("p".to_string(), Arc::clone(&provider))]);
        let raws: HashMap<String, RawProxyProvider> = HashMap::from([("p".to_string(), raw)]);
        commit_proxy_providers(&registry, &candidate, false, Some(&raws), &refresh);
        drop(_lane);

        // Write a node; the next tick must pick it up with no manual
        // refresh. Generous bound for loaded CI machines.
        std::fs::write(&path, "proxies:\n  - {name: a, type: direct}\n").unwrap();
        for _ in 0..50 {
            if provider.proxies().len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(
            provider.proxies().len(),
            1,
            "the committed interval task must refresh the provider"
        );
    }

    /// Issue #625: a provider whose `proxy:` name could not resolve at
    /// startup carries `deferred_initial`; when a later commit reuses the
    /// same provider object (`needs_fetch` false) the commit must still
    /// consume the flag and spawn `refresh()` — otherwise a provider with
    /// no `interval` would stay empty forever once its proxy appears.
    #[tokio::test]
    async fn commit_proxy_providers_retries_deferred_reused_provider() {
        use meow_common::{
            AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn,
            ProxyHealth, ProxyPacketConn,
        };
        use meow_config::proxy_provider::ProxyProvider;
        use meow_config::raw::RawProxyProvider;

        // Passthrough outbound: the provider payload can only arrive if
        // the fetch dialed through this hop.
        struct Front {
            health: ProxyHealth,
        }
        #[async_trait::async_trait]
        impl ProxyAdapter for Front {
            fn name(&self) -> &str {
                "ghost"
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
                let stream = tokio::net::TcpStream::connect((m.host.as_str(), m.dst_port))
                    .await
                    .map_err(MeowError::Io)?;
                Ok(Box::new(stream))
            }
            async fn dial_udp(
                &self,
                _m: &Metadata,
            ) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
                unimplemented!("no udp")
            }
            fn health(&self) -> &ProxyHealth {
                &self.health
            }
        }
        impl Proxy for Front {
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

        // Origin serving a one-node provider payload.
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = origin.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Read the request first — closing with unread client
                // bytes resets the connection before the response lands.
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = "proxies:\n  - {name: n1, type: direct}\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });

        let dialer_registry = meow_proxy::dialer::ProxyRegistry::default();
        let def: RawProxyProvider = serde_yaml::from_str(&format!(
            "type: http\nurl: http://127.0.0.1:{port}/x.yaml\nproxy: ghost"
        ))
        .unwrap();
        let provider = Arc::new(
            ProxyProvider::new("p", &def, None, false, false, dialer_registry.clone()).unwrap(),
        );

        // Startup fetch: `ghost` is not published — resolution fails
        // closed and arms the deferred flag inside `fetch_source`.
        provider
            .acquire_initial()
            .await
            .expect_err("unresolvable proxy must fail closed");
        assert!(provider.proxies().is_empty());

        // A later commit republishes the route map — `ghost` resolves now.
        let front = Arc::new(Front {
            health: ProxyHealth::new(),
        });
        dialer_registry.publish(Arc::new(std::collections::HashMap::from([(
            smol_str::SmolStr::from("ghost"),
            Arc::clone(&front) as Arc<dyn Proxy>,
        )])));

        let registry: Arc<DashMap<String, Arc<ProxyProvider>>> = Arc::new(DashMap::new());
        registry.insert("p".to_string(), Arc::clone(&provider));
        let refresh =
            meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor::default();
        let _lane = CONFIG_MUTATION.lock().await;
        // Same Arc in the candidate ⇒ `needs_fetch` is false ⇒ only the
        // deferred arm can populate this provider.
        let candidate: HashMap<String, Arc<ProxyProvider>> =
            HashMap::from([("p".to_string(), Arc::clone(&provider))]);
        commit_proxy_providers(&registry, &candidate, false, None, &refresh);
        drop(_lane);

        for _ in 0..50 {
            if provider.proxies().len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(
            provider.proxies().len(),
            1,
            "the commit must consume deferred_initial and refresh through the now-resolvable proxy"
        );
    }
}
