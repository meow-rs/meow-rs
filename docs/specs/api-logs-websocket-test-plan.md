# Test Plan: API logs + memory WebSocket (M1.G-3/G-4/G-7/G-8/G-9)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #49. Companion to `docs/specs/api-logs-websocket.md` (rev 1.4).

This is the QA-owned acceptance test plan. The spec's `§Test plan` section is
PM's starting point; this document is the final shape engineer should implement
against. If the spec and this document disagree, **this document wins**; flag
to PM so the spec can be updated.

---

## Scope

**In scope:**

- `GET /logs` WebSocket: auth (`require_auth_ws`), level filter, frame format,
  fan-out, lag-frame delivery.
- `GET /memory` WebSocket: frame format, periodic emission, positive `inuse`.
- `DELETE /connections` (G-7): bulk close, 204 response.
- `GET /dns/query` alias (G-8): query-param form, response parity with POST.
- `POST /cache/dns/flush` (G-9): 204 response, cache-miss verification.
- `require_auth_ws` correctness: accepts Bearer header, accepts `?token=`
  query param, rejects neither; REST routes still reject `?token=`.
- `LogMessage` serialization: field names, level mapping, TRACE→debug collapse,
  RFC3339 timestamp format.
- `LogBroadcastLayer` structural invariant: no blocking send inside `on_event`.

**Out of scope:**

- `/providers/rules`, `/providers/proxies` (G-5/G-6) — blocked on other specs.
- `PUT /configs` hot-reload (G-10) — separate spec.
- Historical ring-buffer — deferred to M2 per spec.
- WS binary frames — spec uses text frames only.
- Load/concurrency beyond what's needed to trigger a Lagged error.

---

## Pre-flight issues (engineer must resolve before starting)

### Issue 1: `AppState` and `test_state_*` helper breakage

`AppState` gains a `log_tx: broadcast::Sender<LogMessage>` field. This breaks
every existing `test_state_with_secret()` and `test_state_default()` call site
in `api_test.rs`. Before any new test compiles:

- Update `test_state_with_secret(secret)` and `test_state_default()` to
  construct a `broadcast::channel(128)` and store `log_tx` in `AppState`.
- Add a new helper `test_state_with_log_tx(secret)` that returns
  `(Arc<AppState>, broadcast::Sender<LogMessage>)` for use in log WS tests
  that need to inject events.

The existing 60+ tests must continue to pass without change.

### Issue 2: `axum` WS feature flag

`axum` must have `features = ["ws"]` in the workspace dep. If missing, the WS
handler won't compile. Verify in `Cargo.toml` before opening the PR.

### Issue 3: `tokio-tungstenite` dev-dep for streaming tests

Tests that actually receive WS frames (§B, §C, §D, §F) need a WS client. Add:

```toml
# meow-api/Cargo.toml [dev-dependencies]
tokio-tungstenite = "0.24"
```

Auth-only tests (§A) can use `oneshot()` with manual WS handshake headers —
the auth middleware runs before the WS upgrade handler, so a 101 vs 401
distinction is observable from the HTTP response status alone.

### Issue 4: `ApiServer::new` signature change

If `ApiServer::new` is used in `main.rs` (or a test harness), adding `log_tx`
as a parameter is a breaking call-site change. Identify all call sites before
the PR touches `AppState`.

---

## Test helpers

Add a `mod ws_support` block in `api_test.rs`:

```rust
mod ws_support {
    use super::*;
    use meow_api::routes::{create_router, AppState};
    use tokio::net::TcpListener;
    use tokio::task::AbortHandle;

    /// Spawn the router on a random port. Returns (addr, AbortHandle).
    /// Drop the AbortHandle to stop the server.
    pub async fn test_ws_server(state: Arc<AppState>) -> (std::net::SocketAddr, AbortHandle) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = create_router(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        })
        .abort_handle();
        (addr, handle)
    }

    /// Connect a WS client. URL example: "ws://127.0.0.1:{port}/logs?level=info"
    pub async fn ws_connect(url: &str)
        -> (tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
            _) {
        tokio_tungstenite::connect_async(url).await.expect("ws connect")
    }
}
```

Add `test_state_with_log_tx` alongside existing helpers:

```rust
fn test_state_with_log_tx(secret: Option<&str>)
    -> (Arc<AppState>, tokio::sync::broadcast::Sender<LogMessage>) {
    let (log_tx, _rx) = tokio::sync::broadcast::channel(128);
    let state = Arc::new(AppState {
        // ... existing fields ...
        secret: secret.map(str::to_string),
        log_tx: log_tx.clone(),
    });
    (state, log_tx)
}
```

**Why inject directly into `log_tx` instead of emitting real `tracing` events?**
The broadcast layer is installed in `main.rs`, not in the test binary's
tracing registry. Tests that emit `info!()` go to the test binary's own
subscriber (if any), not through `AppState.log_tx`. Direct injection
(`log_tx.send(msg)`) is the only reliable way to drive log WS tests without
fighting tracing's global state. It also makes `logs_ws_level_filter_suppresses_debug`
independent of `RUST_LOG` — the test sends `LogLevel::Debug` directly to the
channel; the WS handler's per-client filter determines whether it is forwarded.

**Wall time in WS streaming tests:** WS tests that wait for frames use
`tokio::time::timeout` with a generous slack (500 ms for a frame that should
arrive within ~10 ms of injection). Do NOT use `tokio::time::pause()` — WS
socket reads are kernel syscalls that `pause()` does not virtualise (same rule
as sniffer tests; see `memory/feedback_tokio_pause_syscalls.md`).

---

## Case list

### A. WebSocket auth (`require_auth_ws`)

These four are the PM-specified auth bullets. A1–A3 can use `oneshot()` with
manual WS upgrade headers — the auth middleware runs before the WS handler, so
the 401 vs 101 distinction is visible in the HTTP response.

| # | Case | Asserts |
|---|------|---------|
| A1 | `ws_accepts_bearer_header` | WS upgrade to `/logs` with `Authorization: Bearer hunter2`, secret configured as `"hunter2"` → 101 Switching Protocols. NOT 401. Upstream: `hub/route/logs.go` auth middleware. |
| A2 | `ws_accepts_token_query_param` | WS upgrade to `/logs?token=hunter2`, secret configured → 101. NOT 401. <br/> This is the browser dashboard path — browser `WebSocket` API cannot set headers. <br/> Upstream: Go mihomo `?token=` fallback for WS. ADR-0002 Class B (REST keeps header-only for access-log safety). |
| A3 | `ws_rejects_no_auth_401` | WS upgrade to `/logs` with neither header nor `?token=`, secret configured → 401. Upgrade does NOT complete. |
| A4 | `rest_rejects_token_query_param` **[guard-rail]** | `GET /proxies?token=hunter2` (no Bearer header, REST route with `require_auth`) → 401. NOT 200. Asserts `?token=` widening does not leak from WS middleware to REST middleware. Upstream: REST token-in-URL increases access-log exposure — NOT accepted. |

---

### B. Log stream — frame delivery and framing (`GET /logs`)

These cases use the `ws_support` helpers (real server + WS client).

| # | Case | Asserts |
|---|------|---------|
| B1 | `logs_ws_emits_info_events` | Connect WS to `/logs?level=info`; inject `LogMessage { level: Info, payload: "hello", time: ... }` via `log_tx.send()`; assert one text frame received within 500 ms; parse as JSON; assert `frame["type"] == "info"` and `frame["payload"] == "hello"`. Upstream: `hub/route/logs.go::getLogs`. NOT polling — real push. |
| B2 | `logs_ws_emits_warning_events` | Same pattern with `level: Warning`; assert `frame["type"] == "warning"` (NOT `"warn"` — upstream uses `"warning"`). |
| B3 | `logs_ws_emits_error_events` | `level: Error` → `frame["type"] == "error"`. |
| B4 | `logs_ws_frame_has_time_field` | Injected frame contains `"time"` field; value matches RFC3339 pattern `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`. Value is UTC (`Z` suffix or `+00:00`). |
| B5 | `logs_ws_client_disconnect_stops_task` **[guard-rail]** | Connect WS, receive one frame, drop the WS client. Inject a second event. No panic, no error in the test. Server-side task should exit cleanly via the `socket.send().is_err()` break path. |

---

### C. Log stream — level filter

| # | Case | Asserts |
|---|------|---------|
| C1 | `logs_ws_level_filter_suppresses_debug` | Connect with `?level=info`; inject `LogMessage { level: Debug, ... }`; wait 200 ms; assert **no** frame received. <br/> Works regardless of `RUST_LOG` because events are injected directly into `log_tx`, not through the tracing registry. ADR-0002 Class B (broadcast layer upstream of EnvFilter). |
| C2 | `logs_ws_silent_receives_nothing` | Connect with `?level=silent`; inject `info!` equivalent (`level: Info`); wait 200 ms; no frame. |
| C3 | `logs_ws_warning_filter_passes_error` | Connect with `?level=warning`; inject `Error`-level message; assert frame received with `"type":"error"`. Guards that the `>=` filter passes higher levels. |
| C4 | `logs_ws_default_level_is_info` **[guard-rail]** | Connect with NO `?level=` param; inject `Info`-level and `Debug`-level events; assert Info frame received, Debug frame not received. Confirms the default is `info`, NOT `debug`. |

---

### D. Log stream — fan-out and lag

| # | Case | Asserts |
|---|------|---------|
| D1 | `logs_ws_two_clients_both_receive` | Two simultaneous WS connections to `/logs?level=info`; inject one event; both clients receive the same frame. Fan-out via `broadcast::Sender` semantics. |
| D2 | `logs_ws_lagged_client_continues` | Connect a slow client. Fill the broadcast channel past capacity (128 messages) by sending 130 events before the client drains. Assert: (1) client eventually receives a frame with `{"type":"lagged","missed":N}` where `N > 0`; (2) subsequent injected events are received normally (connection NOT closed); (3) no panic on the server side. <br/> Upstream: Go mihomo silently skips events on lag — we emit a lagged frame. ADR-0002 Class B: lagged frame is additive signal. <br/> NOT connection-terminating. NOT silent. |

---

### E. LogMessage serialization (`LogMessage` struct / `Serialize` impl)

Unit tests on the `LogMessage` and `LogLevel` types directly — no WS server needed.

| # | Case | Asserts |
|---|------|---------|
| E1 | `log_message_serialize_info` | `LogMessage { level: Info, payload: "msg", time: ... }` serializes to `{"type":"info","payload":"msg","time":"..."}`. Keys present; no extra fields. |
| E2 | `log_message_serialize_warning_key` | `level: Warning` serializes as `"type":"warning"`. NOT `"warn"`. Upstream: `hub/route/logs.go` uses `"warning"`. NOT same as `tracing::Level::WARN` display string. |
| E3 | `log_message_trace_collapses_to_debug` | `level: Debug` serializes as `"type":"debug"`. Guard: TRACE level (if exposed via the layer) also maps to `"debug"`, not `"trace"`. Upstream: `hub/route/logs.go` — TRACE not exposed. ADR-0002 Class B (benign collapse). |
| E4 | `log_message_time_field_is_rfc3339_utc` | Serialized `"time"` value is parseable as RFC3339; parsed offset is UTC (`+00:00` or `Z`). NOT local timezone. |
| E5 | `log_level_ordering` **[guard-rail]** | `LogLevel::Debug < Info < Warning < Error`. The `>=` filter logic in the WS handler depends on this ordering via `PartialOrd`. |

---

### F. Memory WebSocket (`GET /memory`)

Uses real server + WS client. Wall time with slack.

Status: planned — not yet implemented in `crates/meow-api/tests/` as of
2026-10-28 (that directory currently has no `/memory` WebSocket cases).

| # | Case | Asserts |
|---|------|---------|
| F1 | `memory_ws_emits_frame_within_1500ms` | Connect WS to `/memory`; wait up to 1 500 ms; assert at least one text frame received. Frame parses as JSON. Upstream: `hub/route/memory.go` — 1 Hz stream. |
| F2 | `memory_ws_inuse_is_positive` | `frame["inuse"]` is an integer > 0. The process is consuming memory; the RSS read (Linux: `/proc/self/status` `VmRSS:`; other platforms: `sysinfo`) should not return 0 for a running process. |
| F3 | `memory_ws_oslimit_is_non_negative` | `frame["oslimit"]` is an integer ≥ 0. `0` is valid (platform doesn't expose limit or read failed). |
| F4 | `memory_ws_no_extra_fields` **[guard-rail]** | Frame JSON contains exactly `"inuse"` and `"oslimit"` — no other fields. Guards against accidentally serializing internals of the RSS source (`sysinfo` on non-Linux platforms). |
| F5 | `memory_ws_auth_same_as_logs` **[guard-rail]** | `/memory` with no auth + secret configured → 401. `/memory?token=<secret>` → 101. Same `require_auth_ws` middleware. |

---

### G. `DELETE /connections` (G-7)

Uses `oneshot()`. Requires a `fake_connection` injection mechanism — engineer
should expose a test-only method on `ConnectionStats` or use the existing
`add_connection` path if one exists.

| # | Case | Asserts |
|---|------|---------|
| G1 | `delete_all_connections_returns_204` | Inject 2 fake active connections; `DELETE /connections`; assert 204 No Content. Upstream: `hub/route/connections.go::closeConnections`. NOT 200. |
| G2 | `delete_all_connections_empties_list` | After `DELETE /connections`, `GET /connections` response has `"connections": []`. |
| G3 | `delete_all_connections_idempotent` **[guard-rail]** | `DELETE /connections` on an empty connection table → 204 (no error). NOT 404 or 500. |

---

### H. `GET /dns/query` alias (G-8)

| # | Case | Asserts |
|---|------|---------|
| H1 | `get_dns_query_returns_same_shape_as_post` | `GET /dns/query?name=example.com` and `POST /dns/query` with `{"name":"example.com"}` return responses with identical JSON key structure (same field names, both 200 or both error). <br/> Upstream: `hub/route/dns.go` uses GET. ADR-0002 Class B (POST kept for back-compat). |
| H2 | `get_dns_query_post_still_works` **[guard-rail]** | `POST /dns/query` continues to return 200 after GET alias is added. NOT 405. Guards that adding `.get(handler)` on the route doesn't shadow `.post(handler)`. |
| H3 | `get_dns_query_missing_name_param` **[guard-rail]** | `GET /dns/query` (no `?name=`) → 400 or appropriate error. NOT panic. NOT 200 with empty result. |

---

### I. `POST /cache/dns/flush` (G-9)

| # | Case | Asserts |
|---|------|---------|
| I1 | `flush_dns_cache_returns_204` | `POST /cache/dns/flush` → 204 No Content. NOT 200 or 404. |
| I2 | `flush_dns_cache_idempotent` **[guard-rail]** | Two successive `POST /cache/dns/flush` calls both return 204. No panic or error on second flush of an already-empty cache. |
| I3 | `flush_dns_cache_clears_entries` | Populate resolver cache with a DNS entry (via `Tunnel.resolver().lookup()`); `POST /cache/dns/flush`; subsequent lookup does NOT hit the cache (must query upstream). Requires a mock resolver with an observable cache-hit counter, or use the existing `Resolver::stats()` if it tracks cache hits. Skip if no hook is available — mark with `#[ignore = "requires cache-hit counter on Resolver"]`. |

---

### J. Structural invariants

Grep-based tests — no server needed. These lock in implementation constraints
that are easy to violate silently.

| # | Case | Asserts |
|---|------|---------|
| J1 | `log_broadcast_layer_no_blocking_send` **[guard-rail]** | `grep -r "blocking_send" crates/meow-api/src/` → empty. `on_event` must only call `broadcast::Sender::send` (sync, non-blocking). <br/> NOT `blocking_send` — that would park the tokio thread inside a tracing event, deadlocking if called from an async context. |
| J2 | `no_catch_panic_on_api_router` **[guard-rail]** | `grep -r "CatchPanic\|catch_panic\|PanicHandler" crates/meow-api/src/` → zero matches in the `create_router` or middleware stack. NOT added as a "graceful WS error" shim — it swallows panics and defeats the soak-test panic-abort invariant (task #26). See `memory/feedback_api_no_catch_panic.md`. |
| J3 | `no_chrono_dep_in_api` **[guard-rail]** | `grep "chrono" crates/meow-api/Cargo.toml` → empty. Use `time` crate only. <br/> Upstream: timestamp crate selected per architect 2026-04-11 (resolved Q3 in spec). |
| J4 | `no_sysinfo_in_workspace_deps` **[guard-rail]** | `grep "sysinfo" Cargo.toml` (workspace root) → not present. `sysinfo` is per-crate (`meow-api/Cargo.toml` only) — it is not needed by any other crate and should not be promoted to workspace level. |

---

## Divergence table cross-reference

Acceptance mapping for the 6 spec divergence rows. Note: the row-4 cases
F2/F3 — like all section-F `/memory` WebSocket cases — are planned but
not yet implemented; `crates/meow-api/tests/` currently has no `/memory`
WebSocket cases. Summary:

| Spec row | Class | Test cases |
|----------|:-----:|------------|
| 1 — No historical ring-buffer | B | (architectural; no acceptance test needed) |
| 2 — POST /dns/query kept alongside GET | B | H2 |
| 3 — TRACE collapsed to `"debug"` | B | E3 |
| 4 — Platform-split RSS (Linux `/proc/self/status`; `sysinfo` elsewhere) vs Go `runtime.ReadMemStats` | B | F2, F3 |
| 5 — Broadcast layer upstream of EnvFilter | B | C1 (RUST_LOG-independent), C4 |
| 6 — WS accepts `?token=`; REST does not | B | A2, A4 |
