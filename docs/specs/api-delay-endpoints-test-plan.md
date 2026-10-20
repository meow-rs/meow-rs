# Test Plan: REST API delay endpoints (M1.G-2)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #31. Companion to `docs/specs/api-delay-endpoints.md`.

This is the QA-owned acceptance test plan for the spec. The spec's
`§Test plan` section is PM's starting point; this document is the final
shape engineer should implement against. If the spec and this document
disagree, **this document wins for test cases**; flag the discrepancy
to PM so the spec can be updated.

## Scope and guardrails

**In scope for M1.G-2:**

- Endpoint wiring: routing, query parsing, auth, error mapping, JSON
  shapes, history recording, concurrent group dispatch.
- Determinism under a test adapter with controlled dial timing. All
  tests run against in-process fake adapters — **no real network**.

**Explicitly out of scope (tracked separately):**

- Probe **quality** / RTT accuracy: that's task **#29 / M1.G-2b**. This
  plan never asserts "delay ≈ real RTT"; it only asserts "delay > 0
  when dial succeeds" and "delay recording shape is correct". When G-2b
  lands, its own acceptance plan will layer HTTP-status-based assertions
  on top of this file without editing any case here.
- Real dashboard smoke test (Yacd / metacubexd "test now" button) —
  covered at M1 exit in the soak harness (`docs/soak-test-plan.md`,
  task #25), not here.
- Real-network integration against `generate_204` endpoints — flaky in
  CI, covered by Tier 2 of the soak test if at all.

## Test adapter contract

All cases below assume a test adapter living in
`crates/meow-api/tests/support/delay_adapter.rs` (new file,
engineer's call on exact name). It must expose:

```rust
pub struct TestAdapter {
    name: String,
    health: ProxyHealth,
    dial_behavior: DialBehavior,
    dial_starts: Arc<Mutex<Vec<Instant>>>, // for concurrency asserts
}

pub enum DialBehavior {
    InstantOk,            // returns immediately with a dummy ProxyConn
    SleepThenOk(Duration),
    SleepThenError(Duration),
    ImmediateError,
}
```

`health()` returns `&self.health` per the spec. Every `dial_tcp` call
pushes `Instant::now()` onto `dial_starts` before consulting
`dial_behavior`. The concurrency and timeout cases below read back the
Vec to assert ordering and spread.

Rationale for a test-adapter rather than a mock HTTP target: upstream's
behaviour the dashboard cares about is *shape and timing of the
endpoint response*, not which bytes the probe sent. A test adapter lets
us pin the spread between concurrent dials at a few ms under CI load,
where a real loopback target would drift. When G-2b lands and the
probe grows an HTTP layer, the adapter grows a matching hook and the
cases here keep working.

## Case list

All cases live in `crates/meow-api/tests/api_test.rs` unless marked
otherwise. Each case asserts **status code AND exact body bytes**
(not just "contains") so error-body drift is caught.

### A. Single-proxy endpoint — happy path

| # | Case | Asserts |
|---|------|---------|
| A1 | `get_proxy_delay_direct_instant_ok` | Test adapter `InstantOk`. Status `200`, body matches `{"delay":N}` where `N` is any `u16 > 0`. |
| A2 | `get_proxy_delay_timeout_edge_1ms_accepted` | `timeout=1`, adapter `InstantOk`. Status `200`. Guards the u16 low boundary. |
| A3 | `get_proxy_delay_timeout_edge_65535_accepted` | `timeout=65535`, adapter `InstantOk`. Status `200`. Guards the u16 high boundary. |
| A4 | `get_proxy_delay_records_into_history` | Call twice against the same adapter. After, `GET /proxies/:name` returns a `history` array with length ≥ 2, each entry having `time` (RFC3339 or epoch-ms, matching upstream) and `delay` fields. Asserts the wiring in step 4 of the design sketch. |
| A5 | `get_proxy_delay_content_type_json` | Response `Content-Type` header starts with `application/json`. Done once here, not repeated in every case. |

### B. Single-proxy endpoint — error surface (exact-body asserts)

Each row asserts the response body is byte-for-byte the second column
(`br#""#` string literal in the test). These are the strings lifted
from upstream; drift here breaks dashboards.

| # | Case | Status | Body |
|---|------|:------:|------|
| B1 | `get_proxy_delay_unknown_proxy_404` | `404` | `{"message":"resource not found"}` |
| B2 | `get_proxy_delay_missing_url_400` | `400` | `{"message":"Body invalid"}` |
| B3 | `get_proxy_delay_missing_timeout_400` | `400` | `{"message":"Body invalid"}` |
| B4 | `get_proxy_delay_timeout_zero_400` | `400` | `{"message":"Body invalid"}` (`timeout=0`) |
| B5 | `get_proxy_delay_timeout_negative_400` | `400` | `{"message":"Body invalid"}` (`timeout=-1`) |
| B6 | `get_proxy_delay_timeout_too_large_400` | `400` | `{"message":"Body invalid"}` (`timeout=65536`) |
| B7 | `get_proxy_delay_timeout_not_integer_400` | `400` | `{"message":"Body invalid"}` (`timeout=abc`) |
| B8 | `get_proxy_delay_expected_unparseable_400` | `400` | `{"message":"Body invalid"}` (`expected=2xx-oops`) — asserts we *parse* the param even though probe is connect-only. Future-proofs against G-2b. |
| B9 | `get_proxy_delay_probe_timeout_504` | `504` | `{"message":"Timeout"}` — adapter `SleepThenOk(2 × timeout)`. **Do not assert body matches "Gateway Timeout" — match exact upstream string.** |
| B10 | `get_proxy_delay_probe_error_503` | `503` | `{"message":"An error occurred in the delay test"}` — adapter `ImmediateError`. |
| B11 | `get_proxy_delay_delay_zero_maps_to_503` | `503` | same as B10 — adapter that dials instantly but reports 0ms (edge case called out in the spec's "delay==0" row). |

### C. Single-proxy endpoint — auth (depends on M0-1, already shipped)

Mirror the pattern from the auth tests already in `api_test.rs` (see
`auth_missing_header_rejects_with_401` etc). Both delay endpoints live
under the gated `api` subrouter, so they should inherit the existing
middleware for free — these cases prove it.

| # | Case | Asserts |
|---|------|---------|
| C1 | `get_proxy_delay_missing_auth_401` | `test_state_with_secret("hunter2")`, no `Authorization` header. Status `401`. |
| C2 | `get_proxy_delay_wrong_auth_401` | Wrong token. Status `401`. |
| C3 | `get_proxy_delay_correct_auth_200` | Correct bearer token. Status `200`. |
| C4 | `get_group_delay_missing_auth_401` | Same for group endpoint. |

If C1–C4 fail, the endpoint was mounted outside the `api` subrouter —
that's a wiring bug, not a new auth surface. Flag as a release blocker.

### D. Group endpoint — happy path

| # | Case | Asserts |
|---|------|---------|
| D1 | `get_group_delay_fallback_three_members_ok` | 3-member `fallback` group, all `InstantOk`. Status `200`. Response body is a JSON object with exactly those 3 member names as keys, all values are `u16 > 0`. |
| D2 | `get_group_delay_map_keys_are_member_names_not_group_name` | Explicit assert: the group name does **not** appear as a key. Guards against a silly bug where we accidentally echo the group. |
| D3 | `get_group_delay_ordering_stable` | Same group, called twice. Assert the **string output is byte-identical** between the two calls (proves the `BTreeMap` decision from the design sketch actually landed). If engineer uses a `HashMap`, this test fails intermittently — by design. |
| D4 | `get_group_delay_empty_group_504` | Group with 0 members. Status `504`, body `{"message":"Timeout"}`: no member passed, so upstream answers it like an all-failed group — NOT 400, and not `{}`. Covered by `d9_group_delay_is_504_when_no_member_passes`. |
| D5 | `get_group_delay_records_into_each_member_history` | After a successful group probe, `GET /proxies/:member_name` for each member shows the new delay in `history`. Verifies spec §"Recording into history" applies per-member. |

### E. Group endpoint — concurrency and timeout semantics

These are the cases that earn this spec its complexity. Use
`tokio::time::pause()` + `advance()` so they don't burn real wall time
and don't flake on loaded CI runners.

| # | Case | Asserts |
|---|------|---------|
| E1 | `get_group_delay_dials_all_members_concurrently` | 5 members, each `SleepThenOk(500ms)` under `tokio::time::pause()`. Read back `dial_starts` from each adapter; assert the max spread between the first and last dial is **< 10 ms of advanced virtual time** (not wall time). Stronger and less flaky than PM's "within one yield" phrasing. |
| E2 | `get_group_delay_total_walltime_bounded_by_timeout` | 3 members, all `InstantOk`, `timeout=1000`. Assert total elapsed virtual time < 100 ms. Guards against accidental serial dispatch. |
| E3 | `get_group_delay_one_slow_member_left_out` | 3 members under `pause()`: two `SleepThenOk(50ms)`, one `SleepThenOk(10_000ms)`. `timeout=100`. Advance virtual time by 150 ms. Assert: status `200`, map holds only the two fast members (`u16 > 0`), the slow member has no key. **Verifies group-wide (not per-member) timeout semantic from the spec.** Covered by `d8_group_delay_at_the_deadline_reports_the_members_that_passed`. |
| E4 | `get_group_delay_all_members_timeout_504` | All members sleep past the timeout. Status `504`, body `{"message":"Timeout"}`. Upstream contract: when *no* member passes by the deadline the group endpoint returns 504, not an empty map. Spec §"Error cases" row 3 asserts this — lock it down. |
| E5 | `get_group_delay_url_test_no_reselection` | Build `UrlTestGroup` with members A (fast) and B (slower). Initial `current = A`. Force A's next dial to be slow and B's to be fast. Call `GET /group/:name/delay`. Then `GET /proxies/:group_name` and assert `current` is still `A`. Locks down the spec's "records, does not reselect" contract. |

### F. Group endpoint — error surface

| # | Case | Status | Body |
|---|------|:------:|------|
| F1 | `get_group_delay_not_a_group_404` | `404` | `{"message":"resource not found"}` — call endpoint on a standalone `Direct` proxy. Upstream returns 404 here (not 400) per the spec. |
| F2 | `get_group_delay_unknown_name_404` | `404` | `{"message":"resource not found"}` |
| F3 | `get_group_delay_missing_timeout_400` | `400` | `{"message":"Body invalid"}` |
| F4 | `get_group_delay_timeout_too_large_400` | `400` | `{"message":"Body invalid"}` |

Note: F1 contradicts the initial spec draft which had this as 400. Spec
was corrected to 404 before architect ack. This case is the guard
against a regression back to 400.

### G. Routing and mounting

| # | Case | Asserts |
|---|------|---------|
| G1 | `get_proxy_delay_route_is_under_proxies_tree` | `GET /proxies/<name>/delay` reaches the handler. Regression guard against accidentally mounting under `/api/proxies/...`. |
| G2 | `get_group_delay_route_is_under_group_tree` | `GET /group/<name>/delay` (**not** `/groups/`) reaches the handler. Upstream uses the singular form. |
| G3 | `get_proxy_delay_url_encoded_name` | Proxy name containing `/` (encoded as `%2F`) or `%20` round-trips correctly. Covers path-param decoding. |

## Deferred / not tested here

- **Real HTTP probe behavior**, including the `expected` status-range
  matching: deferred to task #29 (M1.G-2b). When that lands, B8 above
  flips from "parse only" to "full round-trip". The #29 acceptance plan
  is my responsibility; I'll write it when PM hands the G-2b spec over.
- **Load / stress**: 1000-member groups, etc. Not worth CI time; if
  someone files a perf bug, we add a criterion bench at that point.
- **Dashboard integration**: covered by the M1-exit soak (§7 of
  `docs/soak-test-plan.md`) and a pre-release Tier-2 manual check.

## Exit criteria for this test plan

All cases in A–G pass on `ubuntu-latest` and `macos-latest` (which
means adding none of them to the Linux-only gate list in `test.yml` —
they're pure-Rust, no ssserver needed, so both jobs pick them up for
free once the file lives in `crates/meow-api/tests/api_test.rs`).

Zero new CI wiring required: `api_test` is already invoked on both
platforms.

## Open questions for engineer

None blocking. Two stylistic nits worth a reply before you start:

1. **Test adapter location**: `crates/meow-api/tests/support/` as a
   sibling module, or inline in `api_test.rs` next to `test_state_*`?
   I'd lean sibling module for reuse by any future adapter-needing
   test, but either is fine.
2. **Virtual time**: are you comfortable with `tokio::time::pause()`
   for cases E1–E4? If the adapter does any real syscalls that
   `pause()` can't short-circuit, let me know and I'll rework them to
   use real sleeps with wider tolerances.
