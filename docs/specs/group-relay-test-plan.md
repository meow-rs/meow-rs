# Test Plan: Relay proxy group (M1.C-2)

Status: **implemented** — owner: qa. Last updated: 2026-04-11; corrected
post-#570 (`connect_over` ships with a default `Err(NotSupported)` impl, so
the "no default impl" guard-rails below — pre-flight §, G1, G3 — are void;
the nested-relay case is implemented and runs unignored via `flatten_hops`).
Tracks: task #51. Companion to `docs/specs/group-relay.md` (rev 1.0).

This is the QA-owned acceptance test plan. The spec's `§Test plan` section is
PM's starting point; this document is the final shape engineer should implement
against. If the spec and this document disagree, **this document wins**; flag to
PM so the spec can be updated.

---

## Scope

**In scope:**

- `RelayGroup::dial_tcp` through 2- and 3-proxy chains.
- `connect_over` chain traversal: hop[0] uses `dial_tcp`, hops[1..] use
  `connect_over`.
- UDP relay: sent from the chain's exit (DIRECT hops dropped), and
  `UdpNotSupported` with no `dial_udp` call once two proxy hops remain.
- Error type: `MeowError::RelayHopFailed { hop, source }` at each hop
  boundary, NOT raw inner error.
- Parse-time errors: single proxy, empty proxies (Class A); inert
  health-check fields (`url`/`interval`/`lazy`/`tolerance`/
  `expected-status`) and provider-member fields warn-once (Class B).
- Nested relay (relay-of-relay): flattened at any position.
- `AdapterType::Relay` and `ProxyAdapter` trait method correctness.
- Structural invariants: no `anyhow` at public boundary.

**Out of scope:**

- Background health-check — relay has no sweep (spec §Out of scope).
- Real network integration — optional `#[ignore]` only.
- Protocol-specific `connect_over` implementations (VMess, VLESS, SS, Trojan) —
  covered by their own test plans; here we only test `RelayGroup`'s orchestration.

---

## Historical note: `connect_over` shipped with a default impl

The original plan called for a required method (no default). The shipped
trait instead provides a default `Err(NotSupported)` (see spec Resolved
questions §1), so a `MockProxy` that omits `connect_over` still compiles —
it just fails relay calls at runtime with `NotSupported`. Tests that rely
on `connect_over` must still implement it explicitly to pass.

---

## Test helpers

All unit tests live in `#[cfg(test)] mod tests` inside
`crates/meow-proxy/src/group/relay.rs`.

### `MockProxy`

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ProxyHealth, Metadata, ProxyConn};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A transparent hop: dial_tcp opens a NopConn; connect_over passes
    /// the stream through and records one marker byte into `visits`.
    struct MockProxy {
        name: String,
        health: ProxyHealth,
        udp: bool,
        /// Each connect_over call appends self.marker to this vec.
        visits: Arc<parking_lot::Mutex<Vec<u8>>>,
        marker: u8,
        /// If Some, connect_over returns this error instead of passing stream.
        fail_with: Option<MeowError>,
    }

    impl MockProxy {
        fn new(name: &str, marker: u8) -> Arc<Self> { ... }
        fn new_udp(name: &str, marker: u8) -> Arc<Self> { ... }
        fn no_udp(name: &str, marker: u8) -> Arc<Self> { ... }
        fn failing(name: &str, err: MeowError) -> Arc<Self> { ... }
    }

    // impl ProxyAdapter for MockProxy:
    //   dial_tcp  → returns NopConn (same pattern as api_test.rs NopConn)
    //   connect_over → appends self.marker to visits; returns passed stream (or err)
    //   support_udp → self.udp
    // impl Proxy for MockProxy: alive() → true always (health.set_alive not called)
}
```

`visits` shared across the test allows inspection of *which* mocks were called
and in which order, without needing a real byte stream.

**`NopConn`**: reuse the pattern from `api_test.rs::delay_support::NopConn` —
an `AsyncRead + AsyncWrite + ProxyConn` that accepts all bytes and returns EOF.

---

## Case list

### A. TCP relay chain — `connect_over` traversal

| # | Case | Asserts |
|---|------|---------|
| A1 | `relay_two_hop_tcp_roundtrip` | Proxies [A(marker=1), B(marker=2)], `dial_tcp(metadata)` succeeds. `A.visits` is empty (A used `dial_tcp`, not `connect_over`); `B.visits == [2]` (B's `connect_over` called exactly once). <br/> Upstream: `adapter/outbound/relay.go::DialContext`. NOT direct connection to target — A receives `metadata_for_proxy(B)` as dial target, NOT the final target. |
| A2 | `relay_three_hop_tcp_roundtrip` | Proxies [A(1), B(2), C(3)], `dial_tcp` succeeds. `A.visits == []` (dial_tcp); `B.visits == [2]`; `C.visits == [3]`. Order of calls: A.dial_tcp → B.connect_over → C.connect_over. |
| A3 | `relay_first_hop_uses_dial_tcp_not_connect_over` **[guard-rail]** | 2-hop relay; assert `A.visits` (the `connect_over` counter) is empty after a successful dial. Guards against engineer calling `connect_over` on the first hop. Only `dial_tcp` is called for hop[0]. |
| A4 | `relay_intermediate_hops_use_connect_over` **[guard-rail]** | 3-hop relay; assert `B.visits` is non-empty (connect_over was called) and `A.visits` is empty. Guards that `dial_tcp` is not called for middle hops. |
| A5 | `relay_each_hop_receives_next_hop_address` **[guard-rail]** | Extend `MockProxy` to record the `Metadata.host` it was called with. For chain [A→B→C→target]: A must be called with `B.server:B.port`; B with `C.server:C.port`; C with `target`. NOT A called with the final target directly. |

---

### B. Parse-time validation

| # | Case | Asserts |
|---|------|---------|
| B1 | `relay_single_proxy_hard_errors_at_parse` | YAML `proxies: [proxy-a]` (length 1) → parse error containing `"at least 2"`. <br/> Upstream: silently acts as passthrough. <br/> NOT a passthrough. NOT a warn. ADR-0002 Class A: user likely intended a different group type. |
| B2 | `relay_empty_proxies_hard_errors_at_parse` | YAML `proxies: []` → parse error. <br/> Upstream: panics. <br/> NOT a panic. ADR-0002 Class A. |
| B3 | `relay_url_field_warns_not_errors` | YAML with `url: https://example.com` on a relay group → a `warn!` mentioning `"url"`, captured via `capture_warns`. NOT a parse error. NOT zero warns. ADR-0002 Class B. |
| B4 | `relay_interval_field_warns_not_errors` | YAML with `interval: 300` → a `warn!` mentioning `"interval"`. |
| B5 | `relay_url_and_interval_warn_not_errors` **[guard-rail]** | Both `url:` and `interval:` present → two captured warns, one per field. NOT a combined single warn. NOT four warns (guards that warn-once is per-field, not per-call). |
| B6 | `relay_inert_health_fields_warn_not_errors` | `lazy`/`tolerance`/`expected-status` → one captured warn each (#555). |
| B7 | `relay_provider_fields_warn_not_errors` | `use:`/`include-all`/`include-all-providers`/`filter:`/`exclude-filter:`/`exclude-type:` on a relay → one captured warn each; group still builds from `proxies:` (#555). |

---

### C. UDP relay

| # | Case | Asserts |
|---|------|---------|
| C1 | `relay_udp_direct_then_proxy_exits_at_proxy` | `[DIRECT, B]`: `support_udp()` is true, and `dial_udp()` runs on B, not on DIRECT. |
| C2 | `relay_udp_two_proxy_hops_fail_closed` | `[A, B]`, both with UDP: `support_udp()` is false, `dial_udp()` → `Err(UdpNotSupported)`, and neither A's nor B's `dial_udp` (nor any TCP dial) ran. <br/> NOT sent from hop 0. ADR-0002 Class A. |
| C3 | `relay_udp_multi_hop_fails_closed_for_every_shape` | `[A, DIRECT, B]`, `[A(no UDP), B]`, `[A, B(no UDP)]`, `[A, B, C]`: all fail closed the same way, with no `dial_udp` call. |
| C4 | `relay_udp_all_direct_sends_from_direct` | `[DIRECT, DIRECT]`: `support_udp()` is true and the first DIRECT sends the UDP. |
| C5 | `relay_udp_exit_without_udp_fails_closed` | `[A(no UDP), DIRECT]` and `[DIRECT, A(no UDP)]`: `support_udp()` is false and `dial_udp()` → `Err(UdpNotSupported)` without calling A. |
| C6 | `relay_udp_group_member_resolving_to_one_hop_acts_as_leaf` | A Selector hop or a nested relay that flattens to one proxy hop behaves like that leaf; a nested relay that adds a second proxy hop fails closed. |
| C7 | `relay_support_udp_peek_does_not_touch_groups` | `support_udp()` on `[DIRECT, load-balance]` neither records usage nor advances round-robin; the next `dial_udp` does both once. |

---

### D. Error handling — `RelayHopFailed`

| # | Case | Asserts |
|---|------|---------|
| D1 | `relay_hop_failure_includes_hop_index` | Proxy[1] (second hop) is configured to return `Err(MeowError::Proxy("inner".into()))`; `relay_tcp()` → assert `matches!(err, MeowError::RelayHopFailed { hop: 1, .. })`. <br/> **Destructure the enum variant** — NOT `err.to_string().contains("hop 1")`. NOT `anyhow::Error`. |
| D2 | `relay_first_hop_failure_includes_hop_0` | Proxy[0] `dial_tcp` fails; error → `hop == 0`. Guards that hop-0 failures are also wrapped (not passed through raw). |
| D3 | `relay_last_hop_failure_includes_correct_index` | 3-proxy chain; proxy[2] (last) fails; error → `hop == 2`. |
| D4 | `relay_hop_failure_source_is_inner_error` | `RelayHopFailed.source` contains the original inner `MeowError`. Verify by destructuring: `MeowError::RelayHopFailed { hop: 1, source }` and asserting `source` matches the mock's error variant. |
| D5 | `relay_no_anyhow_at_public_boundary` **[guard-rail]** | `grep "anyhow::Context\|\.context(" crates/meow-proxy/src/group/relay.rs` → zero matches. `MeowError::RelayHopFailed` is used at every hop boundary — NOT `anyhow` wrapping at the return type. |

---

### E. Nested relay (relay-of-relay)

| # | Case | Asserts |
|---|------|---------|
| E1 | `relay_nested_relay_group` | Outer relay chain: [inner_relay, proxy_D]. Inner relay chain: [proxy_A, proxy_B, proxy_C]. Effective sequence: A.dial_tcp → B.connect_over → C.connect_over → D.connect_over (the inner group's members are spliced into the outer chain by `flatten_hops`, so the nested relay works at any position — not only hop 0). Assert: all four visit counters show one call; payload arrives at mock target. |

---

### F. `AdapterType` and `ProxyAdapter` trait methods

| # | Case | Asserts |
|---|------|---------|
| F1 | `adapter_type_is_relay` | `group.adapter_type() == AdapterType::Relay`. |
| F2 | `adapter_type_serialises_to_relay` | `serde_json::to_string(&AdapterType::Relay)` → `"\"Relay\""`. Matches REST `/proxies` JSON shape. |
| F3 | `group_name_returns_config_name` | `group.name()` returns the name supplied at construction. |
| F4 | `group_addr_returns_empty` | `group.addr()` returns `""`. Relay has no single address. |
| F5 | `group_health_accessible` | `group.health()` does not panic. Group has a `ProxyHealth` for API surface even though relay has no self-check. |

---

### G. Structural invariants

| # | Case | Asserts |
|---|------|---------|
| G1 | ~~`connect_over_is_required_no_default`~~ **void** | Superseded: the shipped trait has a default `Err(NotSupported)` impl. A `MockProxy` without `connect_over` compiles and fails relay calls at runtime; hop-failure tests (D1–D4) cover the visible behavior. |
| G2 | `relay_has_debug_assert_on_proxy_len` **[guard-rail]** | `grep "debug_assert" crates/meow-proxy/src/group/relay.rs` → non-empty. Guards that `debug_assert!(proxies.len() >= 2)` is present in `relay.rs` as specified. The parse-time hard-error (B1/B2) prevents production use; the `debug_assert` catches test-harness mistakes. |
| G3 | ~~`no_default_connect_over_in_adapter_trait`~~ **void** | Same as G1 — the default impl exists by design (hysteria2, SS external SIP003 rely on it). |

---

## Divergence table cross-reference

All 5 spec divergence rows have test coverage:

| Spec row | Class | Test cases |
|----------|:-----:|------------|
| 1 — Single-proxy relay → hard error (not passthrough) | A | B1 |
| 2 — Empty proxy list → hard error (not panic) | A | B2 |
| 3 — UDP across two or more proxy hops → `UdpNotSupported` (never sent from hop 0) | A | C2, C3, C6 |
| 4 — `url`/`interval`/`lazy`/`tolerance`/`expected-status` fields → warn-once (not error) | B | B3, B4, B5, B6 |
| 5 — `use`/`include-all*`/`filter`/`exclude-*` fields → warn-once (not error) | B | B7 |
