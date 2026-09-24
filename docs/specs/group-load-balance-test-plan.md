# Test Plan: Load-balance proxy group (M1.C-1)

Status: **superseded in part** — owner: qa. Last updated: 2026-04-11.
Tracks: task #50. Companion to `docs/specs/group-load-balance.md` (rev 1.0).

> **Issue #621 update:** §B and §D below describe the pre-#621
> consistent-hashing design (source-IP key, FNV-1a 32-bit mod the alive
> subset). The shipped implementation now follows mihomo's scheme —
> destination `getKey` (IP-literal host → host, domain → eTLD+1, else
> `dst_ip`), FNV-1a-64, `jumpHash` over the full member list. The
> implemented tests are in `load_balance.rs` (`get_key_*`,
> `jump_hash_*`, `fnv1a64_known_vectors`, `consistent_hashing_*`); the
> §B/§D entries below are retained for history only.

This is the QA-owned acceptance test plan. The spec's `§Test plan` section is
PM's starting point; this document is the final shape engineer should implement
against. If the spec and this document disagree, **this document wins**; flag to
PM so the spec can be updated.

---

## Scope

**In scope:**

- `LoadBalanceGroup::select()` correctness for both strategies: round-robin and
  consistent-hashing.
- Dead-proxy skipping under both strategies.
- `NoProxyAvailable` error path (all dead, or zero proxies).
- Consistent-hashing stability: same destination key → same proxy across
  repeated calls (mihomo `getKey`: IP literal verbatim, domain → eTLD+1,
  else `dst_ip`, else `""`) — independent of client src IP.
- Consistent-hashing with no usable destination → deterministic (`""` key).
- Round-robin alive-set flap guard (acceptance criterion #11).
- FNV-1a-64 + jump-hash correctness (known-answer vectors).
- `support_udp()` and `dial_udp()` filtering for UDP-capable proxies.
- Config parser: `strategy` field round-trip, unknown value → hard error.
- `AdapterType::LoadBalance` enum presence and serialisation.

**Out of scope:**

- `smart` strategy, bandwidth-aware, weighted, least-connections — not in spec.
- Background health-check sweep timing — covered by URLTest sweep tests; same
  infrastructure, not duplicated here.
- Integration against real network endpoints — optional §H case, `#[ignore]`.

---

## Test helpers

Unit tests live in `#[cfg(test)] mod tests` inside
`crates/meow-proxy/src/group/load_balance.rs`.

Define a `MockProxy` that wraps `ProxyHealth` and records dial calls. Pattern
mirrors `delay_support::TestAdapter` in `crates/meow-api/tests/api_test.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ProxyHealth, Metadata};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockProxy {
        name: String,
        health: ProxyHealth,
        udp: bool,
        dial_count: Arc<AtomicUsize>,
    }

    impl MockProxy {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                health: ProxyHealth::new(),
                udp: false,
                dial_count: Arc::new(AtomicUsize::new(0)),
            })
        }

        fn new_udp(name: &str) -> Arc<Self> {
            Arc::new(Self { udp: true, ..Self::new(name) })
        }

        fn mark_dead(&self) {
            self.health.set_alive(false);
        }

        fn dial_count(&self) -> usize {
            self.dial_count.load(Ordering::Relaxed)
        }
    }

    // impl Proxy + ProxyAdapter for MockProxy — see api_test.rs delay_support
    // for the full impl; dial_tcp/dial_udp increment dial_count and return NopConn.
}
```

`LoadBalanceGroup` needs a test constructor that takes a `Vec<Arc<MockProxy>>`
cast to `Vec<Arc<dyn Proxy>>` and a strategy. Expose via `pub fn new(...)` or a
`pub(crate) fn new_for_test(...)` if `new` is not public in the struct.

For selecting without an actual connection, call `group.select(&meta)` directly
and inspect the returned `Arc<dyn Proxy>` by name. Do **not** call `dial_tcp`
for strategy unit tests — that would require a real TCP stack.

---

## Case list

### A. Round-robin strategy (`LbStrategy::RoundRobin`)

| # | Case | Asserts |
|---|------|---------|
| A1 | `round_robin_cycles_through_alive_proxies` | 3 alive proxies (A, B, C); 10 consecutive `select()` calls; assert sequence of names `[A,B,C,A,B,C,A,B,C,A]`. <br/> Upstream: `adapter/outbound/loadbalance.go::RoundRobin.Addr`. <br/> NOT random; NOT skipping index on wrap — strictly sequential. |
| A2 | `round_robin_skips_dead_proxy` | 3 proxies; mark B dead; 6 `select()` calls → only A and C appear, alternating `[A,C,A,C,A,C]`. Dead proxy B must never be selected. |
| A3 | `round_robin_single_alive_always_selects_it` | 3 proxies; mark B and C dead; 5 calls → always A. |
| A4 | `round_robin_counter_wraps_correctly` **[guard-rail]** | Start counter at `usize::MAX - 1`; 4 proxies alive; two calls → indices `(usize::MAX - 1) % 4` and `usize::MAX % 4`. No panic on counter overflow. Guards against unchecked arithmetic on wrap. |
| A5 | `round_robin_handles_alive_set_flap` | 3 alive proxies; call `select()` → assert Ok result; mark proxy-1 dead immediately; call `select()` again → assert Ok result (no panic, index 0 or 2). <br/> Alive-set is rebuilt on every `select()` call — the modulo is on the current alive count, NOT a stale total. <br/> NOT out-of-bounds panic. NOT stale-index access. ADR-0002 acceptance criterion #11. |

---

### B. Consistent-hashing strategy (`LbStrategy::ConsistentHashing`)

| # | Case | Asserts |
|---|------|---------|
| B1 | `consistent_hashing_stable_for_same_dst` | Same destination key (e.g. host `example.com`), 3 alive proxies, repeated `select()` calls → all calls return the same proxy. <br/> **The proxy list must not change during this test** — stability guarantee is "fixed dst key + fixed proxy list". <br/> Upstream: `adapter/outboundgroup/loadbalance.go` `strategyConsistentHashing` (jump hash of `getKey(metadata)` over the full member list). <br/> NOT volatile — consistent-hash must be deterministic. |
| B1b | `consistent_hashing_ignores_src_ip` | Two different client `src_ip`s, same destination host → same member. Guards the mihomo-parity keying: the key derives from the **destination**, never the client. |
| B2 | `consistent_hashing_spreads_across_dst_keys` | A sweep of distinct destination hosts distributes picks across ≥2 members (jump hash spreads keys across the member list). <br/> Replaces the old src-IP spread test — divergence now happens per *destination*. |
| B3 | `consistent_hashing_retries_past_dead_member` | Mark the member a dst key's first bucket lands on as dead; `select()` returns another **alive** member — upstream retries `key+1` up to 5× then falls back to a linear alive scan. |
| B3b | `consistent_hashing_dead_member_remaps_only_its_keys` | Kill one member; assert keys that landed on live members still land on the same member (jump hash over the *full* list gives minimal reshuffle — only the dead member's keys move). |
| B4 | `consistent_hashing_absent_dst_deterministic` | `Metadata` with no host/dst_ip (key `""`), 3 alive proxies, 10 `select()` calls → all 10 return the same proxy. <br/> Empty key hashes deterministically → deterministic bucket. <br/> NOT random. NOT `NoProxyAvailable`. NOT an error. <br/> Upstream: `getKey` returns `""` when nothing is usable — same fallback. |
| B5 | `consistent_hashing_ipv6_dst_stable` | IPv6 literal destination (e.g. `2001:db8::1`), 10 calls → same proxy each time. Guards that `get_key` passes IP literals (v4 or v6) through verbatim as the key. |
| B6 | `consistent_hashing_stable_across_slots` | Provider-slot refresh mid-sequence: a dst key keeps mapping to the same member across slot updates as long as the member list is unchanged. |

---

### C. All-dead and zero-proxy error paths

| # | Case | Asserts |
|---|------|---------|
| C1 | `all_proxies_dead_round_robin_returns_no_proxy_available` | Mark all proxies dead; `select()` → `None` (or `dial_tcp()` → `Err(NoProxyAvailable)`). <br/> Upstream Go: returns the round-robin slot (a dead proxy). <br/> NOT a dial to a known-dead proxy. ADR-0002 Class A. |
| C2 | `all_proxies_dead_consistent_hashing_returns_no_proxy_available` | Same for consistent-hashing. <br/> Upstream Go panics with index-out-of-bounds. <br/> NOT a panic. ADR-0002 Class A (panic → clean error). |
| C3 | `empty_proxy_list_returns_no_proxy_available` **[guard-rail]** | Construct `LoadBalanceGroup` with an empty `proxies: vec![]`; `select()` → `None`. NOT panic. Guards against `proxies[0]` or `unwrap()` on empty vec at construction. |

---

### D. Hash + key-derivation implementation

The consistent-hashing path is `jump_hash(fnv1a64(key) + i, full_len)` for
`i in 0..5`, then a linear eligible scan — the jump hash and the `get_key`
derivation must each be pinned before the selection tests build on them.

| # | Case | Asserts |
|---|------|---------|
| D1 | `jump_hash_stays_in_range` | For a sweep of keys and bucket counts 1..64, every result `< buckets` (and `buckets == 0` returns `0` rather than `u32::MAX`). |
| D2 | `jump_hash_known_answer_vectors` | `jump_hash` matches independent reference vectors (e.g. `jump_hash(0, N)` sequence), guarding the multiply-shift constants `0x27d4eb2f165667c5` / `0x9e3779b97f4a7c15`. |
| D3 | `get_key_edge_cases` | `get_key` returns: the host verbatim for IP literals; eTLD+1 for domains (`www.bbc.co.uk` → `bbc.co.uk`); `dst_ip` when the host is absent or unusable; `""` when nothing is usable. Host strings carrying a port (`domain:443`, `[v6]:443`) fall back to `dst_ip` rather than leaking a bogus suffix lookup. |
| D4 | `get_key_falls_back_to_dst_ip_then_empty` | Domain→eTLD+1→dst_ip→`""` precedence chain asserted case-by-case. |

---

### E. UDP support

| # | Case | Asserts |
|---|------|---------|
| E1 | `support_udp_true_if_any_proxy_supports_udp` | One UDP-capable proxy, two non-UDP proxies → `group.support_udp()` is true. |
| E2 | `support_udp_false_if_none_support_udp` | All proxies have `support_udp() == false` → group returns false. |
| E3 | `dial_udp_filters_to_udp_capable_alive_proxies` | 3 proxies: A (UDP, alive), B (no UDP, alive), C (UDP, dead); `dial_udp()` → must only select A (B excluded: no UDP; C excluded: dead). NOT B, NOT C. |
| E4 | `dial_udp_all_udp_proxies_dead_returns_error` | All UDP-capable proxies dead → `dial_udp()` returns `Err(NoProxyAvailable)`. NOT a dial to a non-UDP proxy. |

---

### F. Config parser (`meow-config`)

| # | Case | Asserts |
|---|------|---------|
| F1 | `parse_load_balance_default_strategy` | YAML with no `strategy:` field → `LbStrategy::RoundRobin` selected. |
| F2 | `parse_load_balance_explicit_round_robin` | `strategy: round-robin` → `LbStrategy::RoundRobin`. |
| F3 | `parse_load_balance_consistent_hashing` | `strategy: consistent-hashing` → `LbStrategy::ConsistentHashing`. |
| F4 | `parse_load_balance_unknown_strategy_hard_errors` | `strategy: sticky` → parse error. <br/> Upstream: falls back silently to round-robin. <br/> NOT silent fallback. ADR-0002 Class A: wrong strategy means different distribution than intended. |
| F5 | `parse_load_balance_case_insensitive_strategy` **[guard-rail]** | `strategy: Round-Robin` or `ROUND-ROBIN` → either succeeds or errors consistently. Pick one behaviour and document it; do not let it panic. |
| F6 | `parse_load_balance_missing_proxies_errors` | YAML with no `proxies:` list → parse error. NOT an empty group. |
| F7 | `parse_load_balance_interval_zero_no_sweep` | `interval: 0` parses without error and produces a group with `interval == Duration::ZERO`. Group still functions for dials (LB has no manual selection); no background sweep spawned. |
| F8 | `load_balance_expected_status_reaches_probe_loop` + `lb_expected_status_reaches_probe` | `expected-status: "204"` reaches `Proxy::expected_status()` (config → group plumbing, proxy_parser); a canned 204 against `expected_status("200")` marks the member dead through the real sweep (meow-tunnel health_check). #555 |

---

### G. `AdapterType` and `ProxyAdapter` trait methods

| # | Case | Asserts |
|---|------|---------|
| G1 | `adapter_type_is_load_balance` | `group.adapter_type() == AdapterType::LoadBalance`. |
| G2 | `adapter_type_serialises_to_load_balance` | `serde_json::to_string(&AdapterType::LoadBalance)` → `"LoadBalance"`. Matches the REST `/proxies` JSON shape. |
| G3 | `adapter_type_enum_variant_exists` **[guard-rail]** | `AdapterType::LoadBalance` can be matched in a `match` arm without `#[allow(unused)]`. Guards that the variant was added to `meow-common/src/adapter_type.rs` and the `_` arm was not left to catch it. |
| G4 | `group_name_returns_config_name` | `group.name()` returns the name supplied at construction. |
| G5 | `group_addr_returns_empty` | `group.addr()` returns `""` (same as URLTest/Fallback — groups have no single address). |

---

### H. Integration — three-echo-server distribution (optional)

`#[ignore = "requires local TCP echo servers; run with --include-ignored"]`

| # | Case | Asserts |
|---|------|---------|
| H1 | `load_balance_round_robin_distributes_connections` | Bind three local TCP echo servers on three ports; construct a LoadBalanceGroup with three Direct proxies pointing at those ports; issue 9 `dial_tcp()` calls; assert each server received exactly 3 connections (strict rotation). |

---

## Divergence table cross-reference

The remaining spec divergence rows have test coverage:

| Spec row | Class | Test cases |
|----------|:-----:|------------|
| 1 — Unknown `strategy` → hard error | A | F4 |
| 2 — Consistent-hashing + all-dead → `NoProxyAvailable` (not panic / not `proxies[0]`) | A | C2 |
| 3 — All dead → `NoProxyAvailable` (not dial-dead) | B | C1, C2 |
| Sticky sessions (`sticky-sessions`) unimplemented | B | — (documented limitation, no test) |

Row 4 of the original table (modulo-hash vs ring-hash) is **closed**: the
implementation now uses the upstream jump-hash-over-full-list scheme, and
B3b pins the minimal-reshuffle property.
