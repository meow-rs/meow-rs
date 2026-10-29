# Spec: REST API completeness — logs, memory, and trivial endpoints (M1.G-3/G-4/G-7/G-8/G-9)

Status: Approved (architect 2026-04-11, qa kickoff authorized)
Owner: pm
Tracks roadmap items: **M1.G-3** (`GET /logs` websocket), **M1.G-4**
(`GET /memory` websocket), **M1.G-7** (`DELETE /connections` bulk),
**M1.G-8** (`GET /dns/query` alignment), **M1.G-9** (`POST /cache/dns/flush`).
Depends on: existing `AppState`, `Tunnel`, `tracing_subscriber`.
See also: [`docs/specs/api-delay-endpoints.md`](api-delay-endpoints.md) —
same routes file, same auth middleware.

## Motivation

Clash dashboards (Yacd, Metacubexd) use these five endpoint groups to
display the live log stream, memory usage, and DNS state. Without them,
the dashboard renders an empty log pane, no memory graph, and cannot
flush the DNS cache. G-3 and G-4 are WebSocket streams — they require
a `tracing` layer that fans events to connected clients (for logs) and a
periodic memory poll (for memory). G-7, G-8, G-9 are each under 10 LOC.

All five are compatible with the existing `AppState` shape — no new
crate deps beyond `axum-extra` (WebSocket) and `sysinfo` (RSS,
non-Linux only), both
of which already appear in the Rust ecosystem and are zero-unsafe-code
wrappers.

## Scope

In scope:

1. **`GET /logs` WebSocket** (M1.G-3) — streams `tracing` events as
   JSON to each connected client. Level filter via `?level=` query param.
2. **`GET /memory` WebSocket** (M1.G-4) — emits periodic RSS + limit
   snapshots while the client is connected.
3. **`DELETE /connections`** (M1.G-7) — closes all active connections.
4. **`GET /dns/query`** (M1.G-8) — adds a GET alias for the existing
   `POST /dns/query` endpoint. Keep POST for back-compat.
5. **`POST /cache/dns/flush`** (M1.G-9) — flushes the DNS cache.

Out of scope:

- **`GET/PUT /providers/rules`** and **`GET/PUT /providers/proxies`**
  (M1.G-5/G-6) — blocked on M1.D-5 (rule-provider upgrade) and M1.H-1
  (proxy-providers) landing. Own spec when those unblock.
- **`PUT /configs`** (M1.G-10) — hot-reload complexity; own spec.
- **Persistent log ring-buffer.** Clients that connect after startup
  do not receive historical log lines. Only events emitted after the
  WebSocket upgrade are delivered. If a ring-buffer is needed, add it
  in M2; it requires careful bounded memory and is a separate concern.

## User-facing API

### G-3: `GET /logs` — log stream WebSocket

```
GET /logs?level=info
Upgrade: websocket
```

Query params:

| Param | Default | Meaning |
|-------|---------|---------|
| `level` | `info` | Minimum log level. Accepted values (case-insensitive): `debug`, `info`, `warning`, `error`, `silent`. `silent` suppresses all logs. |

Server pushes one JSON text frame per log event, then keeps the
connection open. Client sends nothing (read-only stream). Server
closes when the client disconnects.

**Frame format** (matches upstream `hub/route/logs.go`):

```json
{"type": "info", "payload": "Config loaded from config.yaml", "time": "2026-04-11T12:00:00.000Z"}
```

| Field | Type | Meaning |
|-------|------|---------|
| `type` | string | Log level: `"debug"`, `"info"`, `"warning"`, `"error"` |
| `payload` | string | The formatted log message (no ANSI codes, no timestamp prefix) |
| `time` | string | RFC3339 timestamp with millisecond precision (UTC) |

**Level mapping:**

| tracing level | JSON `type` field |
|--------------|------------------|
| `TRACE` | `"debug"` (collapse — upstream does not expose TRACE) |
| `DEBUG` | `"debug"` |
| `INFO` | `"info"` |
| `WARN` | `"warning"` |
| `ERROR` | `"error"` |

**Level filter:** a client requesting `?level=warning` receives only
`warning` and `error` events. Events below the requested level are
dropped at the broadcast fan-out layer (before serialization), not
after — do not serialize then filter.

**Multiple clients:** each connected client gets its own
`tokio::sync::broadcast::Receiver`. The sender is a
`broadcast::Sender<LogMessage>` in `AppState`. If a client's receive
buffer overflows (too many unread events), its subscription is silently
dropped for the overflowing events — the `broadcast::Receiver::recv`
`Lagged` error is handled by skipping the missed events and continuing,
not by closing the connection.

### G-4: `GET /memory` — memory stream WebSocket

```
GET /memory
Upgrade: websocket
```

No query params.

Server pushes one JSON text frame per second while the client is
connected. Frame format (matches upstream `hub/route/memory.go`):

```json
{"inuse": 12345678, "oslimit": 0}
```

| Field | Type | Meaning |
|-------|------|---------|
| `inuse` | integer | Current RSS (resident set size) in bytes |
| `oslimit` | integer | OS memory limit for the process in bytes; `0` if not determinable |

**RSS source:** platform-split. On Linux, read `VmRSS:` from
`/proc/self/status` — the same kernel counter `sysinfo` reports — so the
shipped Linux binary carries no `sysinfo` dep at all. On non-Linux
platforms, use the `sysinfo` crate (cross-platform, no unsafe); the
example below applies to that path only:

```rust
use sysinfo::{Pid, Process, System};
let mut sys = System::new();
sys.refresh_process(Pid::from_u32(std::process::id()));
let rss = sys.process(Pid::from_u32(std::process::id()))
    .map(|p| p.memory())   // sysinfo returns bytes
    .unwrap_or(0);
```

The RSS read runs in a single shared sampler task, not per connection:
the first `/memory` subscriber spawns it, it reads RSS once per second —
one `/proc/self/status` read on Linux, a fresh `System` on non-Linux —
and broadcasts the frame to every connected socket; when the last socket
disconnects, the sampler exits and cleans up after itself. The total cost
is one read per second no matter how many WS connections are open;
optimize only if profiling shows cost.

`oslimit`: On Linux, read `/proc/self/cgroup` or `rlimit(RLIMIT_RSS)`.
On other platforms, return `0`. A helper `fn process_memory_limit() ->
u64` in a platform-cfg block. If reading fails for any reason, return
`0` (not an error — `oslimit` is informational).

**Poll interval:** 1 second. Use `tokio::time::interval(Duration::from_secs(1))`.
This matches upstream's 1 Hz memory stream.

### G-7: `DELETE /connections` — bulk close

```
DELETE /connections
```

Close all active connections tracked by `Tunnel::statistics()`. Mirrors
the per-connection `DELETE /connections/{id}` that already exists, but
operates on the whole set.

Response: `204 No Content`.

Implementation: `state.tunnel.statistics().close_all_connections()` —
add this method to `ConnectionStats` if not present. The method drains
the active-connections map and signals each connection's close handle.

### G-8: `GET /dns/query` — GET alias

```
GET /dns/query?name=example.com&type=A
```

Functionally identical to the existing `POST /dns/query`. The `type`
query param is parsed but currently unused (same as the POST body's
`type` field). The GET form matches upstream's `hub/route/dns.go`.

Keep `POST /dns/query` working unchanged. Add the GET route alongside
it in `create_router`:

```rust
.route("/dns/query", get(dns_query_get).post(dns_query))
```

The GET handler reads `name` and `type` from query params instead of
a JSON body. Response JSON is identical to the POST handler.

**Divergence from upstream** (Class B per ADR-0002): upstream switched
from POST to GET in an early version; our POST is a legacy path from the
initial implementation. Keeping POST is additive back-compat, not a
routing change — any client that relied on POST continues to work.

### G-9: `POST /cache/dns/flush`

```
POST /cache/dns/flush
```

Clears the DNS resolver's in-memory cache. Response: `204 No Content`.

Implementation: add `fn flush_cache(&self)` to `DnsResolver`
(or expose it from `Tunnel` via `tunnel.resolver().flush_cache()`).
The `DnsResolver` wraps `hickory_resolver::TokioAsyncResolver` — call
`resolver.clear_cache()` (hickory provides this method on
`TokioAsyncResolver`). If hickory does not expose it, iterate and
expire the internal cache via the handle; **do not** restart the
resolver (that would lose the configured nameservers and require
re-initialization — too disruptive for a cache flush).

## Internal design

### Log broadcast channel — `AppState` extension

Add to `AppState`:

```rust
pub struct AppState {
    pub tunnel: Tunnel,
    pub secret: Option<String>,
    pub config_path: String,
    pub raw_config: Arc<RwLock<RawConfig>>,
    /// Fan-out channel for log events. Each WS client subscribes a Receiver.
    pub log_tx: tokio::sync::broadcast::Sender<LogMessage>,
}
```

Channel capacity: **128 messages**. At 1 kB per message, that is 128 kB
of buffer per subscriber at maximum fill — bounded and predictable. A
slow client that can't drain in time gets `Lagged` errors; events are
dropped for that client, not buffered indefinitely. Startup burst is a
non-issue: no WS subscribers exist at `main.rs` boot, so the channel
drops everything until the first `GET /logs` connection attaches.

Revisit capacity after soak test (#25) measures lag-frame frequency
under realistic subscriber load. If lag frames appear more than once
per subscriber per minute, bump to 512. Not before.

### `LogMessage` struct

```rust
#[derive(Clone)]
pub struct LogMessage {
    pub level: LogLevel,
    pub payload: String,
    pub time: time::OffsetDateTime,  // UTC; use time crate (already in dep graph via hickory-server)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}
```

`LogLevel` derives `PartialOrd`/`Ord` so filtering is a single `>=`
comparison: `msg.level >= requested_level`.

Timestamp: `time::OffsetDateTime::now_utc()` — always UTC. Do NOT use
local-zone timestamps: the server-side TZ is irrelevant to dashboard
clients. Use `time`'s `well_known::Rfc3339` format with millisecond
precision.

Serialization for the WebSocket frame:

```rust
impl Serialize for LogMessage {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_struct("LogMessage", 3)?;
        m.serialize_field("type", self.level.as_str())?;
        m.serialize_field("payload", &self.payload)?;
        // Format as RFC3339 with millisecond precision, e.g. "2026-04-11T12:00:00.000Z"
        let ts = self.time.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        m.serialize_field("time", &ts)?;
        m.end()
    }
}
```

### Custom `tracing::Layer`

A custom `tracing_subscriber::Layer` is installed alongside
`tracing_subscriber::fmt()` in `main.rs`. It captures each event and
publishes to the broadcast channel.

**Filter ordering decision:** the broadcast layer is added to the
registry *without* an `EnvFilter` wrapper. It sees every event at
`DEBUG` level and above (TRACE collapsed to DEBUG), regardless of
`RUST_LOG`. The `?level=` query param on each WS connection then
filters on the client side. This means: a dashboard requesting
`?level=info` sees info/warn/error even if `RUST_LOG=warn`. The
alternative (env-filter wrapping the broadcast layer) would make
`?level=debug` on the dashboard ineffective unless `RUST_LOG=debug` —
which is user-hostile. **Chosen: broadcast layer is upstream of env
filtering.** This is a Class B divergence from upstream if upstream
respects env filter first — dashboards should see what they ask for.

**Non-blocking guarantee:** `on_event` is sync-only (no `.await`, no
`blocking_send`). `broadcast::Sender::send` is the only call — it is
synchronous and non-blocking, returning `Err(SendError)` if no
subscribers or the channel is full. Never use `blocking_send` or any
`async` call inside a tracing layer.

```rust
pub struct LogBroadcastLayer {
    tx: broadcast::Sender<LogMessage>,
}

impl<S: Subscriber> Layer<S> for LogBroadcastLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: layer::Context<'_, S>) {
        let level = match *event.metadata().level() {
            tracing::Level::TRACE | tracing::Level::DEBUG => LogLevel::Debug,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::WARN => LogLevel::Warning,
            tracing::Level::ERROR => LogLevel::Error,
        };
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let msg = LogMessage {
            level,
            payload: visitor.0,
            time: time::OffsetDateTime::now_utc(),
        };
        // Non-blocking send. Err = no subscribers or channel full; both are fine.
        let _ = self.tx.send(msg);
    }
}
```

`MessageVisitor` records the `message` field (the argument to `info!`
etc.) into a `String`. It does NOT include span fields or target — those
are internal and would clutter the dashboard log view. Match upstream's
format: message text only.

```rust
struct MessageVisitor(String);
impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
}
```

**Initialization in `main.rs`:**

```rust
let (log_tx, _) = tokio::sync::broadcast::channel::<LogMessage>(128);
let log_layer = LogBroadcastLayer { tx: log_tx.clone() };

tracing_subscriber::registry()
    .with(tracing_subscriber::fmt::layer().with_env_filter(env_filter))
    .with(log_layer)  // NOT wrapped in EnvFilter — sees all events; WS ?level= filters
    .init();
```

Pass `log_tx` to `ApiServer::new` and store in `AppState`.

**`ApiServer::new` signature change:** add `log_tx:
broadcast::Sender<LogMessage>` parameter. This is a breaking change on
`ApiServer::new` — update call sites in `main.rs` and test setups.

### WebSocket handler (`GET /logs`)

Axum's WebSocket support lives in `axum::extract::ws`. No extra crate
needed — `axum` already includes WebSocket via the `ws` feature flag
(confirm it's enabled in `axum` workspace dep).

```rust
async fn get_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogsParams>,
    ws: WebSocketUpgrade,
) -> Response {
    let level = parse_log_level(&params.level);
    let mut rx = state.log_tx.subscribe();
    ws.on_upgrade(move |mut socket| async move {
        loop {
            match rx.recv().await {
                Ok(msg) if msg.level >= level => {
                    let json = serde_json::to_string(&msg).unwrap_or_default();
                    if socket.send(Message::Text(json.into())).await.is_err() {
                        break;  // client disconnected
                    }
                }
                Ok(_) => {}  // below requested level, skip
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Slow client: n events missed. Emit a lagged frame, then continue.
                    // Do NOT close the connection — lagging is recoverable.
                    let lag_msg = format!("{{\"type\":\"lagged\",\"missed\":{}}}", n);
                    if socket.send(Message::Text(lag_msg.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}
```

### WebSocket handler (`GET /memory`)

```rust
async fn get_memory(
    State(_state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(|mut socket| async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let inuse = read_rss_bytes();
            let oslimit = read_os_memory_limit();
            let msg = serde_json::json!({"inuse": inuse, "oslimit": oslimit});
            if socket.send(Message::Text(msg.to_string().into())).await.is_err() {
                break;
            }
        }
    })
}
```

### WebSocket auth — `require_auth_ws`

**Browser WS clients cannot set request headers** during the WebSocket
upgrade (`new WebSocket(url)` API has no `headers` option). Clash
dashboards (Yacd, metacubexd, Clash Dashboard) all use `?token=<secret>`
query-param fallback on WS connections. Upstream Go mihomo accepts both.

The current `require_auth` middleware accepts only `Authorization: Bearer
<secret>`. Shipping `/logs` and `/memory` behind `require_auth` means
no browser dashboard can connect on an authenticated deployment — the
WebSocket upgrade fails with 401 before the first frame.

**Add `require_auth_ws`** as a sibling to `require_auth`:

```rust
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

    // Check Authorization: Bearer header first
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")));

    // Fall back to ?token= query param (WS browser clients)
    let token_param = query.get("token").map(|s| s.as_str());

    let provided = bearer.or(token_param);
    match provided {
        Some(t) if t == expected => next.run(req).await,
        _ => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
}
```

**Scoping rule:** `?token=` is accepted ONLY on WS upgrade routes
(`/logs`, `/memory`). REST handlers keep `require_auth` (header-only).
Tokens in REST URLs end up in access logs and browser history — do not
widen plain REST to accept query params.

**Constant-time comparison:** task #33 covers adding constant-time
comparison to `require_auth`. When that lands, apply the same fix to
`require_auth_ws` — both comparison sites must be updated together.
Flag this in the PR that implements `require_auth_ws`.

### Route registration

Two middleware stacks — WS routes get `require_auth_ws`, REST routes
keep `require_auth`:

```rust
// WS routes — header or ?token= auth
let ws_routes = Router::new()
    .route("/logs", get(get_logs))
    .route("/memory", get(get_memory))
    .route_layer(middleware::from_fn_with_state(state.clone(), require_auth_ws));

// REST + trivial endpoints — header-only auth (existing block)
let api = Router::new()
    // ... existing routes ...
    .route("/connections", delete(close_all_connections))   // add alongside /{id}
    .route("/dns/query", get(dns_query_get).post(dns_query))  // extend existing
    .route("/cache/dns/flush", post(flush_dns_cache))
    .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

api.merge(ws_routes).merge(ui).layer(CorsLayer::permissive()).with_state(state)
```

### New Cargo dependencies

**`meow-api/Cargo.toml`:**

```toml
# RSS polling; per-crate (only used here). Non-Linux targets only —
# Linux reads VmRSS from /proc/self/status and ships no sysinfo dep.
[target.'cfg(not(target_os = "linux"))'.dependencies]
sysinfo = { version = "0.32", default-features = false, features = ["system"] }
# No chrono — use time 0.3.x which is already in the dep graph via hickory-server.
# Enable the formatting feature for RFC3339 timestamp formatting.
time = { version = "0.3", features = ["formatting"] }
```

`time` is already pulled transitively from `hickory-server`. If it is
not already declared at workspace level, add it to the workspace
`[dependencies]` so the feature can be added explicitly. If it IS
already declared (likely), add `features = ["formatting"]` to the
workspace entry and reference `time = { workspace = true }` in
`meow-api/Cargo.toml`. Do NOT add a new `chrono` dep.

**`axum` workspace dep:** confirm `features = ["ws"]` is included.
If not, add it. WebSocket support is gated behind the `ws` feature.

**`tokio` workspace dep:** confirm `sync` feature is included
(needed for `broadcast`). It typically is in multi-threaded setups.

No `async-tungstenite` or `tokio-tungstenite` — axum's built-in WS is
sufficient and avoids a duplicate dep.

## Divergences from upstream

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | No historical log ring-buffer on connect | B | Upstream buffers recent events; we stream forward-only. Clients see new events immediately; dashboard just starts from "now". Add ring-buffer in M2 if user-requested. |
| 2 | `POST /dns/query` kept alongside new `GET /dns/query` | B | Back-compat; our POST was the first impl. No routing change. |
| 3 | `TRACE` level collapsed to `"debug"` in JSON `type` field | B | Upstream does not expose TRACE to dashboard clients. Matches upstream output. |
| 4 | Platform RSS read (Linux: `/proc/self/status` `VmRSS:`; `sysinfo` elsewhere) vs upstream's `runtime.ReadMemStats` (Go) | B | Different language, different API. RSS is the equivalent observable: total resident memory. `oslimit` = 0 on non-Linux is acceptable. |
| 5 | Broadcast layer upstream of `EnvFilter` (sees all events ≥ DEBUG regardless of `RUST_LOG`) | B | Dashboard `?level=info` works without needing `RUST_LOG=info`. Upstream may respect env filter first — not confirmed. User hostile to require env-var cooperation to see dashboard logs. |
| 6 | WS auth accepts `?token=` query param (REST does not) | B | Browser WebSocket API cannot set headers; upstream Go mihomo accepts `?token=`. REST-only paths keep header-only auth to avoid tokens in access logs. |

## Acceptance criteria

1. A WebSocket client connecting to `GET /logs?level=info` receives
   `{"type":"info","payload":"...","time":"..."}` frames for each
   `info!` / `warn!` / `error!` event emitted while connected.
2. `?level=warning` suppresses `debug` and `info` frames.
3. A client connecting to `GET /logs?level=silent` receives no frames.
4. Two simultaneous `/logs` clients each receive the same events
   independently (fan-out via broadcast).
5. A slow client that can't drain its receiver gets a `{"type":"lagged",
   "missed":N}` frame, then continues streaming — no connection close,
   no panic.
6. `GET /memory` emits a frame approximately once per second. Frame
   contains `"inuse"` > 0 and `"oslimit"` ≥ 0.
7. `DELETE /connections` returns `204` and subsequent `GET /connections`
   shows an empty `connections` array.
8. `GET /dns/query?name=example.com` returns the same JSON shape as
   `POST /dns/query` with `{"name":"example.com"}` body.
9. `POST /cache/dns/flush` returns `204`. Subsequent DNS resolution
   misses the in-process cache (verify with a mock resolver or by
   observing the cache-hit counter reset).
10. WS upgrade (`/logs`, `/memory`) with `Authorization: Bearer <secret>`
    succeeds when secret is configured.
11. WS upgrade with `?token=<secret>` query param succeeds — browser
    dashboard auth path.
12. WS upgrade with neither header nor `?token=` returns `401` before
    the upgrade completes.
13. `GET /logs` (plain REST, not WS) with `?token=<secret>` and no Bearer
    header returns `401` — `?token=` is not accepted on REST routes.
14. `cargo test -p meow-api` passes with no regressions.

## Test plan (starting point — qa owns final shape)

**Unit/integration (`crates/meow-api/tests/api_test.rs`):**

*Log stream:*
- `logs_ws_emits_info_events` — connect WS to `/logs?level=info`;
  emit an `info!` event; assert one frame received with `"type":"info"`.
  Upstream: `hub/route/logs.go::getLogs`. NOT polling — real push.
- `logs_ws_level_filter_suppresses_debug` — connect with `?level=info`;
  emit `debug!`; assert no frame received within 200 ms.
  Class B per ADR-0002 (TRACE → debug collapse is benign).
- `logs_ws_silent_receives_nothing` — `?level=silent`; emit info; no frame.
- `logs_ws_two_clients_both_receive` — two simultaneous WS connections;
  emit one event; both clients receive it.
- `logs_ws_lagged_client_continues` — fill channel to capacity; assert
  slow client receives a `{"type":"lagged","missed":N}` frame and
  continues streaming (no panic, no close). NOT connection-terminating.
  NOT silent — the lagged frame is observable.
- `ws_accepts_bearer_header` — `Authorization: Bearer <secret>` on WS
  upgrade succeeds when secret is configured.
  Upstream: `hub/route/logs.go` auth middleware.
- `ws_accepts_token_query_param` — `?token=<secret>` on WS upgrade
  succeeds. This is the browser dashboard path. NOT header-only.
  Upstream: Go mihomo accepts `?token=` for WS.
- `ws_rejects_no_auth_401` — WS upgrade with neither header nor
  `?token=` returns 401 before upgrade completes.
- `rest_rejects_token_query_param` — `GET /logs` (non-WS GET) with
  `?token=<secret>` and no Bearer header returns 401. NOT accepted on
  REST routes — only on WS upgrade paths.

*Memory stream:*
- `memory_ws_emits_periodically` — connect WS to `/memory`; wait 1.5 s;
  assert at least one frame received with `inuse > 0`.
  Upstream: `hub/route/memory.go`. NOT a one-shot HTTP response.
- `memory_ws_inuse_is_positive` — assert `inuse` field > 0 (process is
  consuming memory).

*Trivial endpoints:*
- `delete_all_connections_returns_204` — add 2 fake active connections;
  `DELETE /connections`; assert 204; assert connections list is empty.
  Upstream: `hub/route/connections.go::closeConnections`. NOT 200.
- `get_dns_query_matches_post_response` — `GET /dns/query?name=N` and
  `POST /dns/query` with `{"name":"N"}` return identical JSON shape.
  Class B per ADR-0002 (POST back-compat).
- `flush_dns_cache_returns_204` — `POST /cache/dns/flush`; assert 204.

## Implementation checklist (for engineer handoff)

- [ ] Confirm `axum` workspace dep has `features = ["ws"]`; add if missing.
- [ ] Add `sysinfo` to `meow-api/Cargo.toml` under
      `[target.'cfg(not(target_os = "linux"))'.dependencies]` (per-crate,
      not workspace; Linux reads `/proc/self/status` instead).
- [ ] Enable `features = ["formatting"]` on `time` in workspace deps
      (already in graph via hickory-server); reference as
      `time = { workspace = true }` in `meow-api/Cargo.toml`.
      Do NOT add `chrono`.
- [ ] Define `LogMessage`, `LogLevel`, `LogBroadcastLayer`, `MessageVisitor`
      in `crates/meow-api/src/log_stream.rs` (new file).
      Confirm: `on_event` uses `broadcast::Sender::send` only — no
      `.await`, no `blocking_send`.
- [ ] Extend `AppState` with `log_tx: broadcast::Sender<LogMessage>`.
- [ ] Update `ApiServer::new` signature; update `main.rs` call site.
- [ ] Install `LogBroadcastLayer` alongside `fmt::layer()` in `main.rs`
      using `tracing_subscriber::registry().with(...).with(...).init()`.
      Broadcast layer NOT wrapped in `EnvFilter` — see §Filter ordering.
- [ ] Add `require_auth_ws` in `routes.rs` (accepts header OR `?token=`).
      Update route wiring: WS routes get `require_auth_ws`; REST routes
      keep `require_auth`.
- [ ] Implement `get_logs` WS handler in `routes.rs`. Emit
      `{"type":"lagged","missed":N}` frame on `RecvError::Lagged`.
- [ ] Implement `get_memory` WS handler in `routes.rs`. Add
      `read_rss_bytes()` and `read_os_memory_limit()` helpers
      (platform-cfg for Linux rlimit).
- [ ] Add `close_all_connections()` to `ConnectionStats` in
      `meow-tunnel`. Implement as drain on the active-connections map.
- [ ] Implement `close_all_connections` handler in `routes.rs`.
- [ ] Add `GET /dns/query` handler (`dns_query_get`) in `routes.rs`
      reading from `Query<DnsQueryRequest>` instead of `Json<>`.
- [ ] Add `flush_dns_cache` handler; add `flush_cache()` to
      `DnsResolver` (verify hickory `TokioAsyncResolver::clear_cache()`
      is available in the pinned hickory version; adapt if API differs).
- [ ] Register routes: WS in `ws_routes` with `require_auth_ws`;
      REST additions in existing `api` block with `require_auth`.
- [ ] Flag `require_auth_ws` PR for task #33 (constant-time comparison
      must cover both comparison sites when that task lands).
- [ ] Update `docs/roadmap.md` M1.G-3, G-4, G-7, G-8, G-9 rows with
      merged PR link.

## Resolved questions (architect sign-off 2026-04-11)

1. **broadcast capacity 128** — approved. Startup burst non-issue (no
   subscribers exist at boot). `Lagged` = skip + emit `{"type":"lagged",
   "missed":N}` frame + continue. Revisit after soak test (#25): if
   lag frames > 1/subscriber/minute, bump to 512.

2. **`sysinfo` per-crate** — correct. Not workspace-level; only
   `meow-api` uses it, and only on non-Linux targets (Linux reads
   `VmRSS` from `/proc/self/status`). If a second crate ever needs it,
   promote then.

3. **Use `time`, not `chrono`** — `time 0.3.x` is already in the dep
   graph via `hickory-server`. Enable `features = ["formatting"]` on
   the existing workspace entry. Emit UTC timestamps (`OffsetDateTime::
   now_utc()`). Do NOT add `chrono`.

4. **Auth ordering + `?token=` gap** — middleware ordering (before WS
   upgrade) is correct. However, `require_auth` (header-only) cannot
   serve browser WS clients. Added `require_auth_ws` (header OR
   `?token=`) scoped to WS upgrade routes only. REST keeps header-only.
   See §WebSocket auth — `require_auth_ws`.
