# Spec: REST API delay endpoints

Status: Approved (architect 2026-04-11, with nits folded in)
Owner: pm
Tracks roadmap item: **M1.G-2** (+ follow-up **M1.G-2b** for probe-quality)
Related gap-analysis rows: `GET /proxies/:name/delay`, `GET /group/:name/delay`
(both marked **Gap** in `docs/gap-analysis.md` §5).

## Motivation

Clash Dashboard, Yacd, and ClashX-Pro all invoke two endpoints to render
per-proxy latency bars and to trigger on-demand "test now" buttons:

- `GET /proxies/:name/delay` — probe a single proxy against a target URL.
- `GET /group/:name/delay` — probe every member of a group concurrently.

meow-rs currently exposes neither. `GET /proxies` already returns a
`history` array, but it is only populated by `UrlTestGroup`'s passive
`update_fastest` path — standalone proxies (SS, Trojan, Direct) and
`select` / `fallback` groups never accumulate history, so dashboard latency
bars are blank for them. Exposing an active probe endpoint fixes both the
"missing data" and the "manual retest" cases without any config change on
the dashboard side.

The underlying probe function already exists at
`crates/meow-proxy/src/health.rs::url_test` (connect-only; see
**Known limitation** below). This spec wires it to HTTP handlers and,
for groups, adds a parallel dispatch.

## Scope

In scope:

1. `GET /proxies/:name/delay` matching upstream's request and response
   contract (query string, JSON shape, status codes).
2. `GET /group/:name/delay` matching upstream's contract. Only proxy-group
   adapters (`select`, `url-test`, `fallback`, and future `load-balance` /
   `relay`) are valid targets; non-group names return 400.
3. Recording the probe result into `ProxyHealth.history` so the existing
   `GET /proxies` latency columns populate for all proxy types.
4. Honouring the existing API auth middleware once **M0-1** (task #16)
   lands; no new auth surface.

Out of scope (defer or separate spec):

- Upgrading `url_test` from a connect-only probe to a real
  HTTP GET — deserves its own small spec (see **Known limitation**).
- Websocket streaming of delay updates. Upstream has none; not needed for
  dashboard compat.
- A `POST /proxies/:name/delay` write form. Upstream uses `GET` with
  query params; we match.
- `GET /providers/proxies/:name/healthcheck` — handled under M1.G-6 once
  proxy providers exist (M1.H-1).

## Non-goals

- Implementing our own HTTP client for probing. Reuse whatever the proxy
  adapter gives us (a `dial_tcp` + eventual HTTP GET over it), same as
  upstream.
- Emulating upstream's exact internal goroutine pool. A tokio
  `JoinSet` for the group endpoint is sufficient.
- Adding a new config knob. Defaults already in `url-test` group config
  (`url`, `interval`, `timeout`) are enough.

## User-facing API

### `GET /proxies/:name/delay`

Query parameters:

| Parameter | Type | Required | Description |
|-----------|------|:-------:|-------------|
| `url`     | string | yes (see note) | Target URL to probe. Typical values: `http://www.gstatic.com/generate_204`, `http://cp.cloudflare.com/generate_204`. |
| `timeout` | integer (ms) | yes | Hard cap on the probe. **Range 1–65535**: out of range → 400. (Upstream parses it as `int16`, so we match that ceiling.) |
| `expected` | string | no | Comma-separated HTTP status ranges the probe treats as success (e.g. `200,204-206`). Passed through to the probe. If omitted, any 2xx is success. Matches upstream. |

> **Note on `url`**: upstream does not strictly validate `url` — it passes
> whatever it gets to the prober. We additionally reject a missing `url`
> with `400` because our prober would otherwise panic on the empty host.
> This is a documented divergence, not a bug — dashboards always send it.

Success (`200`), exactly matching upstream `render.M{"delay": delay}`:

```json
{ "delay": 123 }
```

`delay` is the measured round-trip in **milliseconds**, `u16` (matching
`ProxyHealth::last_delay` and upstream's parsed timeout width). On probe
failure the endpoint returns an error body, not `{"delay": 0}`.

Error cases (verbatim lifted from upstream `hub/route/proxies.go::getProxyDelay`):

| HTTP | Body | When | Upstream line |
|------|------|------|---------------|
| `400` | `{"message": "Body invalid"}` (= `ErrBadRequest`) | `timeout` missing, not an integer, ≤0, or >65535; or `expected` unparseable | `render.JSON(w, r, ErrBadRequest)` |
| `400` | `{"message": "Body invalid"}` | `url` missing (our stricter divergence; same body for simplicity) | — |
| `404` | `{"message": "resource not found"}` (= `ErrNotFound`) | `:name` not in the proxy registry | middleware `findProxyByName` |
| `504` | `{"message": "Timeout"}` (= `ErrRequestTimeout`) | probe exceeded `timeout` | `render.Status(r, http.StatusGatewayTimeout)` |
| `503` | `{"message": "An error occurred in the delay test"}` | probe transport error, TLS fail, unreachable, delay==0 | `newError("An error occurred in the delay test")` |

Engineer note: **504 for timeout, 503 for transport error** — these are
the upstream codes; I had 408 in the first draft and it was wrong. The
error bodies are the exact strings upstream returns from its `ErrBadRequest`,
`ErrNotFound`, `ErrRequestTimeout`, and the inline `newError(...)` call.
When implementing, paste these as inline comments next to the error sites
with a `// upstream: hub/route/proxies.go::getProxyDelay` reference.

### `GET /group/:name/delay`

Same query parameters (`url`, `timeout`, `expected`). Success (`200`):

```json
{
  "proxy-A": 123,
  "proxy-B": 245
}
```

The map holds only the members whose probe passed (matches upstream): a
member that failed, or was still probing at the deadline, has no key.
The map key is the member proxy name, **not** the group name.

**Timeout semantics — group-wide, not per-member.** Upstream runs the
entire group probe under a single `timeout` deadline. We match: one
deadline for the whole batch. A slow member does not get its own
`timeout` budget; when the deadline elapses the endpoint answers with
the members that passed by then, and members still in flight are left
out. Only a batch where no member passed is a 504 (see error cases
below). This is a deliberate upstream-compat choice — dashboards rely
on it.

**URL-test group re-selection:** the handler **only records** delay
measurements into `ProxyHealth.history` of each member. It does **not**
trigger `UrlTestGroup::update_fastest`, i.e. a manual delay test does
not cause the group's "current" proxy to switch. Passive re-selection
still happens on the group's own interval-driven probe path. Matches
upstream (`hub/route/groups.go::getGroupDelay`: only records, no
reselection). One integration test asserts this: measure a member,
observe that `GET /proxies/:group_name` still reports the same
`current`.

Error cases (verbatim from upstream `hub/route/groups.go::getGroupDelay`):

| HTTP | Body | When |
|------|------|------|
| `400` | `{"message": "Body invalid"}` | `timeout` / `expected` unparseable or out of range |
| `404` | `{"message": "resource not found"}` | `:name` not in the registry, **or** `:name` exists but is not a `ProxyGroup` — upstream returns 404 for both cases (`findProxyByName` rejects non-groups at the middleware layer for this route). We match. |
| `504` | `{"message": "Timeout"}` | no member passed its probe by the `timeout` deadline (an empty group included) |

All member probes run concurrently; the endpoint waits up to the
group-wide `timeout` before responding (no streaming).

### Route mounting

Both routes live on the upstream-compatible router in
`crates/meow-api/src/routes.rs`, under the existing `/proxies` tree —
**not** under our bespoke `/api/` namespace. Dashboards probe the former.

## Internal design sketch

### Wiring

`crates/meow-api/src/routes.rs`:

```rust
Router::new()
    .route("/proxies/:name/delay", get(get_proxy_delay))
    .route("/group/:name/delay",   get(get_group_delay))
```

`get_proxy_delay(State(app), Path(name), Query(params)) -> Result<Json<DelayResp>, ApiError>`:

1. Validate `params.url` (`Url::parse` or the minimal validator in
   `health.rs`) and `params.timeout > 0`.
2. Look up `app.tunnel.proxies().get(&name)` — 404 on miss.
3. Call `health::url_test(&*adapter, &params.url, Duration::from_millis(params.timeout))`.
4. Record into `ProxyHealth.history` so `GET /proxies` reflects the
   measurement (new helper: `adapter.health().record_delay(delay)`; see
   **Follow-up** below if the adapter doesn't currently expose `health()`).
5. On delay `== 0` → map to the `503` error shape above. Otherwise
   `Json(DelayResp { delay })`.

`get_group_delay(...)`:

1. Same validation.
2. Look up the proxy and verify `adapter_type()` is one of the group
   variants; otherwise 400.
3. `let members = group.members().ok_or(400)?;` — the `Proxy` trait
   already exposes `members() -> Option<Vec<String>>`.
4. Spawn one `tokio::spawn` per member inside a `JoinSet`, each running
   step 3–4 of `get_proxy_delay`.
5. Collect into a `BTreeMap<String, u16>` so output ordering is stable
   for snapshot tests.
6. Return `Json(map)`.

### Recording into history

`ProxyHealth::record_delay` already exists; we need `ProxyAdapter` to
surface the health handle. Add a **required** method to the trait in
`meow-common/src/adapter.rs`:

```rust
fn health(&self) -> &ProxyHealth;
```

No `Option`, no default. Every adapter owns a `ProxyHealth` instance —
SS, Trojan, Direct, Reject, Selector, UrlTestGroup, FallbackGroup (and
future VMess/VLESS, load-balance, relay). Direct/Reject get a
zero-history instance so dashboards render `0` rather than a dash,
matching upstream. Making the method infallible eliminates a whole
class of `.unwrap()` call sites in the delay handlers.

Because `health()` returns `&ProxyHealth` (not `&mut`), `record_delay`
writes must use interior mutability. `ProxyHealth` already holds its
`alive: AtomicBool` and `history: RwLock<Vec<DelayHistory>>`, so this
is already satisfied — engineer only needs to add the new trait method
and an owned `ProxyHealth` field to every concrete adapter struct.

This is the only cross-crate trait churn in the spec.

### Concurrency & fairness

For the group endpoint, the total wall time is bounded by `timeout` plus
`JoinSet::join_next` overhead. Cap the number of in-flight probes at
`members.len()` — no global throttle; groups are rarely >50 members and
the caller already chose to press "test all".

### Error surface

New `ApiError` variants (or reuse existing ones) for `BadRequest`,
`NotFound`, `RequestTimeout`, and `ServiceUnavailable`, each carrying a
`message: String` rendered as `{"message": ...}`. Keep the error shape
identical to existing endpoints so dashboard error toasts work.

### Auth

No new surface: both endpoints live behind whatever middleware M0-1
applies to the rest of the API. Spec author notes: this spec assumes
M0-1 lands first so the endpoints ship with auth from day one.

## Known limitation — tracked as M1.G-2b, must land before M1 exit

`health::url_test` currently only dials the target host/port and times
the TCP handshake. It does **not** send an HTTP `GET` or wait for a
response body. For `generate_204`-style endpoints the user-visible delay
is therefore ~30–50 % lower than what Go mihomo reports, which will make
side-by-side dashboard comparisons look suspiciously fast and generate
spurious "meow-rs is lying about latency" bug reports.

The fix is a one-day follow-up, filed as **M1.G-2b** (task #29):

- Extend `url_test` to write a minimal `GET /path HTTP/1.1\r\nHost:
  host\r\n\r\n` over the dialed connection and read the status line.
- For `https://` targets, wrap the `ProxyConn` in a client-side TLS
  handshake (via the new `meow-transport::tls::TlsLayer` once M1.A-1
  lands) before the GET.
- Honour the `expected` query param by comparing the parsed status-line
  code against the provided ranges; delay is only recorded if it passes.

**Architect decision (2026-04-11): M1.G-2b is a hard M1-exit gate, not
an M2 item.** The endpoint wiring (this spec, M1.G-2) can ship first,
but M1 cannot be declared complete until G-2b lands. The split exists
because endpoint wiring and probe quality are independent axes — both
need to happen, in either order.

## Acceptance criteria

A PR implementing this spec must:

1. Add `GET /proxies/:name/delay` returning the exact success and error
   shapes above.
2. Add `GET /group/:name/delay` returning the map-of-name-to-delay shape
   above.
3. After a successful probe, a subsequent `GET /proxies/:name` shows the
   new delay in its `history` field — verified in an integration test
   using two calls against the same `Direct` proxy.
4. Concurrent group probe: all members start within one tokio yield of
   each other (asserted by measuring `tokio::time::Instant` inside a
   test adapter) — no serial dispatch.
5. Total group probe wall time ≤ `timeout + 100 ms` when every member
   stalls past the timeout — asserted by a test adapter that sleeps
   `timeout * 2` before completing its dial.
6. Error status codes and `message` strings match upstream for: unknown
   proxy (`404` "resource not found"), bad timeout (`400` "Body invalid"),
   non-group name on group endpoint (`404` "resource not found"),
   probe timeout (**`504` "Timeout"**, not 408), probe error (**`503`
   "An error occurred in the delay test"**). Timeout out of u16 range
   is rejected as `400`.
7. Both endpoints honour the Bearer `secret` middleware from M0-1.
8. Dashboards: manual smoke test against a real Yacd or metacubexd
   instance — "test now" button on a proxy and on a group both
   populate. Documented in the PR description, not gated in CI.

## Test plan (starting point — qa owns final shape)

**Unit (`crates/meow-api/tests/api_test.rs`):**

- `get_proxy_delay_direct_ok` — spin up a small Axum server with a
  `Direct` proxy in the registry, call the endpoint, expect `200` and
  `delay > 0`.
- `get_proxy_delay_unknown_proxy_404`.
- `get_proxy_delay_missing_url_400`.
- `get_proxy_delay_missing_timeout_400`.
- `get_proxy_delay_timeout_504` using a test adapter whose `dial_tcp`
  sleeps longer than the probe timeout. Assert status = 504 and body
  exactly `{"message":"Timeout"}`.
- `get_proxy_delay_timeout_too_large_400` with `timeout=100000` →
  asserts the u16-ceiling rejection path.
- `get_proxy_delay_error_503` using a test adapter whose `dial_tcp`
  returns an error.
- `get_group_delay_fallback_ok` — build a 3-member `fallback` group,
  expect a 3-entry map.
- `get_group_delay_not_a_group_400` — call the group endpoint on a
  standalone proxy.
- `get_group_delay_concurrent_within_timeout` — 5 members, each sleeping
  `timeout/2`, assert wall time < `timeout * 1.5`.
- `get_group_delay_one_slow_member_left_out` — 3 members: 2
  fast, 1 sleeping `timeout*2`. Assert the group-wide timeout kicks in,
  the two fast members appear with non-zero delay in the map, and the
  slow member has no key. Verifies the group-wide (not per-member)
  timeout semantic from the spec.
- `get_group_delay_url_test_no_reselection` — `UrlTestGroup` with two
  members, currently selecting member A. Call group delay. Assert
  `GET /proxies/:group_name` still reports `current: A` even if member
  B measured faster. Verifies the "records, does not reselect" contract.
- `delay_recorded_in_history` — after `get_proxy_delay`, call
  `GET /proxies/:name` and assert the `history` array grew.

**Integration (no new file needed):** pull Yacd into `test-assets/`,
run `meow -f fixtures/m1g2.yaml`, open Yacd in a headless browser,
click "test all" — out of scope for M1.G-2 CI; capture in the M1 exit
soak test (qa ask).

## Implementation checklist (for engineer handoff)

- [ ] Add `health()` default method to `ProxyAdapter` trait; override in
      all concrete adapters (SS, Trojan, Direct, Reject, Selector,
      UrlTestGroup, FallbackGroup).
- [ ] Add two route handlers + their `Query` params + `DelayResp` type
      to `routes.rs`.
- [ ] Mount new routes on the upstream-compatible tree.
- [ ] Add integration tests listed above.
- [ ] Update `docs/roadmap.md` M1.G-2 row with the merged PR link.
- [ ] Open follow-up task "Upgrade url_test to send HTTP GET" (flag
      from **Known limitation**).
