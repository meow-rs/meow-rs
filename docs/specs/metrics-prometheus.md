# Spec: Prometheus metrics endpoint (M1.H-2)

Status: Approved (architect 2026-04-11)
Owner: pm
Tracks roadmap item: **M1.H-2**
Depends on: none beyond existing `Statistics` struct and Axum router.
See also: [`docs/specs/api-logs-websocket.md`](api-logs-websocket.md) —
shares the platform-split RSS probe added in M1.G-4.
Upstream reference: `hub/server.go` (exposes `/debug/vars` + `expvar`);
note that upstream Go mihomo does NOT expose a native Prometheus `/metrics`
endpoint — Prometheus scraping is done via `clashtui` or separate exporters.
This is a meow-rs enhancement, not a parity feature.

## Motivation

Operators running meow-rs in server environments want Prometheus scraping
for traffic, connection, proxy health, and rule-match metrics without running
a separate exporter. Go mihomo has no native `/metrics` endpoint; this is a
conscious feature gap that meow-rs can fill as a differentiator.

The data already exists: `Statistics` tracks upload/download totals and
active connections; `ProxyHealth` tracks alive state and delay per proxy.
The work is adding a `/metrics` route and exposing the data in Prometheus
text format.

## Scope

In scope:

1. `GET /metrics` route returning Prometheus text exposition format
   (text/plain, version 0.0.4 as defined by the Prometheus data model).
2. Metrics exposed (see §Metric catalog):
   - Traffic bytes (upload/download totals, current rate).
   - Active connection count.
   - Per-proxy health (`alive`, `last_delay_ms`).
   - Rule-match counters by `rule_type` and `action` label.
   - Runtime RSS memory (reusing the M1.G-4 RSS read — `/proc/self/status`
     `VmRSS:` on Linux, `sysinfo` on other platforms).
3. `prometheus-client` crate for encoding. No global registry — use a
   per-request scrape that reads current state from `AppState`.
4. Auth: same `require_auth` middleware as all other REST routes. Prometheus
   scrapers can send `Authorization: Bearer <secret>` header. No separate
   auth bypass for scrapers.

Out of scope:

- **Histograms / latency percentiles** — connection setup latency, DNS query
  latency. Adding instrumentation on the hot path is M2. M1 exposes gauges
  and counters only.
- **Per-connection breakdown** — individual connection metrics. The active
  connection count and total bytes are M1; per-connection metrics are M2.
- **Push gateway** — pull-based scraping only.
- **OpenTelemetry** — separate M3 deliverable per roadmap.
- **Custom listen address for `/metrics`** — expose on the same port as the
  REST API. A dedicated metrics port is M2 if operators want firewall isolation.
- **Rule-match counters per rule name** — the label cardinality could be
  unbounded (user-defined rule names). We expose per rule_type (DOMAIN, GEOIP,
  etc.) and action (PROXY, DIRECT, REJECT) only.

## User-facing config

No new config field. The endpoint is always available when the REST API is
enabled (same `external-controller` address). Operators point Prometheus at:

```
scrape_configs:
  - job_name: meow
    static_configs:
      - targets: ["127.0.0.1:9090"]
    bearer_token: "<secret>"
    metrics_path: /metrics
```

## Metric catalog

All metrics are prefixed `meow_`.

| Registered name | Type | Labels | Description |
|-----------------|------|--------|-------------|
| `meow_traffic_bytes` | counter | `direction={upload,download}` | Cumulative bytes transferred since process start. `prometheus-client` auto-appends `_total`; wire label as a single metric with `direction` label. |
| `meow_connections_active` | gauge | — | Number of currently open connections. |
| `meow_proxy_alive` | gauge | `proxy_name`, `adapter_type` | 1 = alive, 0 = dead. One series per configured proxy/group. |
| `meow_proxy_delay_ms` | gauge | `proxy_name`, `adapter_type` | Last measured round-trip delay in milliseconds. **Omitted entirely when `last_delay = None`** (no health check has run). NOT -1. |
| `meow_rules_matched_total` | counter | `rule_type`, `action` | Cumulative rule matches by type and action. |
| `meow_memory_rss_bytes` | gauge | — | Current process RSS in bytes (Linux: `/proc/self/status` `VmRSS:`; other platforms: `sysinfo`). |
| `meow_info` | gauge | `version`, `mode` | Always 1; carries build-time labels (version string, tunnel mode). |

**Label value constraints:**

- `proxy_name`: proxy or group name from config. May contain spaces — Prometheus
  label values support arbitrary UTF-8 strings.
- `adapter_type`: serialised `AdapterType` string (e.g., `"Shadowsocks"`,
  `"Selector"`, `"Direct"`).
- `rule_type`: `"DOMAIN"`, `"DOMAIN-SUFFIX"`, `"IP-CIDR"`, `"GEOIP"`, etc.
- `action`: `"DIRECT"`, `"REJECT"`, `"PROXY"` (for all non-direct/non-reject
  actions, use `"PROXY"`).

**High-cardinality note**: `meow_proxy_alive` and `meow_proxy_delay_ms` emit
one series per proxy/group (O(num_proxies)). A typical subscription has 20–500
proxies. This is the expected cardinality for this endpoint; operators running
large subscriptions (500+) should be aware that per-scrape encoding cost scales
linearly. Per-connection labels are intentionally excluded (unbounded cardinality).

**`meow_rules_matched_total` instrumentation**: requires a new
`RuleMatchCounters` struct in `meow-tunnel/src/statistics.rs` with a
`DashMap<(&'static str, &'static str), u64>`. Keys are `&'static str` (not
`String`) — `increment()` is on the hot path (called per connection); owned
`String` keys allocate on every call. Rule type and action strings must be
`'static` constants. The tunnel's `match_engine.rs` increments the counter at
each rule match. This is the only new hot-path instrumentation in M1.

**`meow_proxy_delay_ms` omit-when-None**: when `proxy.health().last_delay()`
is `None` (no health check has run), do NOT emit a series at all — not even
`-1`. A `-1` gauge value pollutes aggregations (`avg`, `histogram_quantile`).
Absence is the correct signal: alert rules should use `absent()` or `unless`
to detect stale proxies rather than testing for a sentinel value.

## Internal design

### Crate choice

Use `prometheus-client = "0.22"` (pure Rust, no global state, async-friendly).
Do not use the older `prometheus` crate (global static registry, not compatible
with per-request scraping model).

Add to `crates/meow-api/Cargo.toml`:

```toml
prometheus-client = "0.22"
```

No workspace-level pin needed — only `meow-api` uses it.

### Route and handler

```rust
// routes.rs

pub async fn get_metrics(State(state): State<AppState>) -> Response {
    let mut registry = Registry::default();

    // Traffic counters
    let upload = <Family<Vec<(String, String)>, Counter>>::default();
    let download = <Family<Vec<(String, String)>, Counter>>::default();
    // ... populate from state.tunnel.statistics()
    registry.register("meow_traffic_bytes", "Cumulative bytes", upload.clone());

    // Active connections
    let active_conns = Gauge::<i64, AtomicI64>::default();
    active_conns.set(state.tunnel.statistics().active_connection_count() as i64);
    registry.register("meow_connections_active", "Active connections", active_conns);

    // ... additional metrics

    let mut body = String::new();
    encode(&mut body, &registry).expect("metrics encoding is infallible");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    ).into_response()
}
```

**Per-request registry** (not global): each scrape request builds and
populates a fresh `Registry` from current `AppState`. This avoids shared
mutable global state and simplifies the implementation. At realistic scrape
intervals (15–60s) the allocation overhead is negligible.

### Rule-match counter instrumentation

```rust
// crates/meow-tunnel/src/statistics.rs

pub struct RuleMatchCounters {
    /// (&'static str rule_type, &'static str action) → count
    /// Keys are 'static to avoid per-call allocation on the hot path.
    inner: DashMap<(&'static str, &'static str), u64>,
}

impl RuleMatchCounters {
    /// rule_type and action MUST be 'static string literals (e.g. "DOMAIN", "PROXY").
    /// Do NOT pass runtime-allocated strings here.
    pub fn increment(&self, rule_type: &'static str, action: &'static str) {
        *self.inner.entry((rule_type, action)).or_insert(0) += 1;
    }
    pub fn snapshot(&self) -> Vec<((&'static str, &'static str), u64)> {
        self.inner.iter().map(|e| (*e.key(), *e.value())).collect()
    }
}
```

Add `rule_match: Arc<RuleMatchCounters>` to `Statistics`. Wire into
`match_engine.rs` at the point a rule match is confirmed (after the final
rule type + target proxy are known).

`action` string: bucketed by the resolved target's adapter *type* (not its
name): the literal `DIRECT`, `Direct`-typed, and `Compatible` targets →
`"DIRECT"`; `Reject`/`RejectDrop`/`PassRule` targets (and the unreachable
missing-target fallback) → `"REJECT"`; everything else → `"PROXY"`. Do NOT
use the proxy name as the action label (unbounded cardinality).

### Auth

`GET /metrics` is registered inside the auth-wrapped router (same as
all other REST endpoints). No separate auth handling.

```rust
// routes.rs — add alongside existing routes
.route("/metrics", get(get_metrics))
```

## Divergences from upstream

Go mihomo has no native Prometheus endpoint — this entire feature is a
meow-rs addition. No ADR-0002 classification needed.

The metric names follow Prometheus naming conventions (snake_case, `_total`
suffix for counters, `_bytes`/`_ms` units). They are NOT required to match
any third-party Go mihomo exporter project — those exporters scrape the REST
API and define their own metric names.

## Acceptance criteria

1. `GET /metrics` returns `200 OK` with `Content-Type: text/plain; version=0.0.4`.
2. Response is valid Prometheus text format (parseable by `promtool check metrics`).
3. `meow_traffic_bytes_total{direction="upload"}` and `{direction="download"}`
   are present and match `GET /traffic` values.
4. `meow_connections_active` matches the count from `GET /connections`.
5. `meow_proxy_alive` has one series per proxy/group; value is 1 for alive,
   0 for dead. Label `proxy_name` matches the name from `GET /proxies`.
6. `meow_proxy_delay_ms` present for proxies with a known delay; **absent** for
   proxies where no health check has run (`last_delay = None`). NOT -1, NOT 0.
7. `meow_rules_matched_total` increments after each proxied connection.
   Unit test: route one connection through a DOMAIN rule → counter increases by 1.
8. `meow_memory_rss_bytes` is a positive integer.
9. `meow_info` always equals 1; carries `version` and `mode` labels.
10. `GET /metrics` with wrong/missing Bearer token → 401 (same as other routes).
11. No global mutable registry — two concurrent scrape requests do not race.

## Test plan (starting point — qa owns final shape)

**Unit (`routes.rs`):**

- `metrics_endpoint_returns_prometheus_text_format` — call handler with mock
  AppState; parse response with `prometheus_parse` or regex; assert
  `meow_traffic_bytes_total` present.
  Upstream: N/A (meow-rs enhancement). NOT JSON — must be Prometheus text.
- `metrics_traffic_bytes_match_statistics` — pre-populate statistics with known
  upload/download values; assert metric values match.
- `metrics_connections_active_reflects_count` — add 3 mock connections to
  statistics; assert `meow_connections_active` = 3.
- `metrics_proxy_alive_label_per_proxy` — mock tunnel with 2 proxies (one alive,
  one dead); assert two series, correct values.
- `metrics_proxy_delay_absent_when_unknown` — proxy with `last_delay = None`;
  assert NO `meow_proxy_delay_ms` series emitted for that proxy. NOT -1, NOT 0.
  Upstream: N/A (meow-rs enhancement). Omitting series is correct Prometheus
  practice; sentinel values corrupt aggregations.
- `metrics_info_label_always_one` — assert `meow_info` = 1 with version label.
- `metrics_auth_required` — no Bearer token → 401. Same as other REST routes.

**Unit (`statistics.rs`):**

- `rule_match_counter_increments` — call `increment("DOMAIN", "PROXY")` twice;
  snapshot returns count = 2.
- `rule_match_counter_separate_labels` — `("DOMAIN", "PROXY")` and
  `("GEOIP", "DIRECT")` tracked independently.

**Integration:**

- `metrics_scrape_concurrent_no_race` — two tokio tasks call `GET /metrics`
  simultaneously; both return 200 with valid content. No panic.
  NOT a single-threaded test — must exercise concurrent path.

## Implementation checklist (engineer handoff)

- [ ] Add `prometheus-client = "0.22"` to `crates/meow-api/Cargo.toml`.
- [ ] Add `RuleMatchCounters` to `meow-tunnel/src/statistics.rs`.
- [ ] Wire `rule_match.increment(...)` in `meow-tunnel/src/match_engine.rs`.
- [ ] Expose `active_connection_count()` method on `Statistics`.
- [ ] Implement `get_metrics` handler in `routes.rs`.
- [ ] Register `/metrics` route in `build_router()`.
- [ ] Update `docs/roadmap.md` M1.H-2 row with merged PR link.
