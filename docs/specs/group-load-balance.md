# Spec: Load-balance proxy group (M1.C-1)

Status: Approved (architect 2026-04-11, engineer ready)
Owner: pm
Tracks roadmap item: **M1.C-1**
Depends on: none — load-balance composes existing `ProxyAdapter`
implementations via the same `Vec<Arc<dyn Proxy>>` pattern used by
URLTest/Fallback/Selector.
Related gap-analysis row: §proxy-groups "load-balance — enum variant
exists, no group impl".

> **Implementation status (2026-09, issue #485):** load-balance groups now join
> the same periodic health-check sweep as `url-test`/`fallback`.
> `meow_config::extract_health_check_specs` emits a `HealthCheckSpec` for a
> `load-balance` group, so its members are probed against `url` every
> `interval` seconds (default 300, `0` disables); `lazy: true` defers probing
> until the group next carries traffic. The `url`, `interval`, and `lazy`
> fields are therefore effective, as is `expected-status` (probes require the
> configured HTTP status since #555). `use:` / `include-all` provider members are
> supported (issue #533 item 3): they join the same pick space as static
> `proxies:` members — statics first, then each provider slot in order — and
> a provider refresh is visible to the next selection without rebuilding the
> group. Note on liveness: the periodic sweep resolves members through
> `member_proxies()` (issue #543), so provider members *are* probed and
> revived by it — identical to url-test/fallback. The group's dial-failure
> escalation (repeated member dial errors mark the member dead) is an
> additional between-sweeps signal: it dead-marks faster than `interval`,
> and a dead-marked member can still be revived by the next sweep tick, a
> provider refresh, or the on-demand
> `/providers/proxies/{name}/healthcheck` endpoint.

## Motivation

`type: load-balance` is the fourth proxy group type after Selector,
URLTest, and Fallback. Upstream Go mihomo supports three strategies:
consistent-hashing (default; sticky by *destination* via `getKey` +
`jumpHash`), round-robin, and sticky-sessions (LRU src+dst key). Our
implementation supports round-robin (our default) and consistent-hashing
with the upstream destination-key scheme — see divergence rows 10, 11
(former rows 4/6 closed by issue #621).
Real subscriptions use load-balance to distribute traffic across a
set of identically-capable peers (e.g. three SS nodes on the same
VPS network). Without it, users with load-balance groups in their
config get a parse error and no fallback, breaking the M1 "typical
subscription loads" goal.

The implementation is smaller than URLTest — it reuses the same
periodic health-check infrastructure but replaces the "fastest-wins"
selection with a counter or a hash. Estimate ~200 LOC total.

## Scope

In scope:

1. `LoadBalanceGroup` struct in `crates/meow-proxy/src/group/load_balance.rs`
   implementing `ProxyAdapter`.
2. Strategy `round-robin` (default): AtomicUsize counter, mod alive-
   proxy count. Per-request, not per-connection (so long-lived
   connections are assigned once at dial time).
3. Strategy `consistent-hashing`: the mihomo scheme — hash a
   destination-derived key (`getKey`: IP-literal host → host, domain →
   eTLD+1, else `dst_ip`) and `jumpHash` over the full member list,
   retrying `key+1` up to five times on dead members before a linear
   alive scan. Sticky by destination. Marking a member dead remaps only
   the keys that pointed at it (list size unchanged, jump-hash minimal
   reshuffle holds); a provider refresh that *shrinks or reorders* the
   member list changes `buckets` and remaps broadly — same as upstream.
4. Periodic health-check using the same `url` + `interval` probe
   mechanism as URLTest. Unhealthy proxies are skipped by both
   strategies.
5. YAML config parser in `meow-config` for the
   `proxies: [{ type: load-balance }]` group variant.
6. `AdapterType::LoadBalance` variant added to
   `crates/meow-common/src/adapter_type.rs`.
7. Integration with `ProxyHealth` and the api-delay-endpoints probe
   path.

Out of scope:

- **`smart` strategy** — upstream has a "smart" strategy that mixes
  latency-awareness with spreading; niche, underdocumented, defer.
- **`strategy: sticky-sessions`** — a real upstream strategy (LRU-cached
  src+dst key → `jumpHash` member, 10-minute TTL); unimplemented, rejected
  at parse time. See divergence 11.
- **`strategy: bandwidth-aware`** — not in upstream's mainline.
- **Weighted load-balance** — upstream does not have weights; neither
  do we.
- **Least-connections** — would require connection-count tracking on
  each proxy; not in upstream, not in scope.

## User-facing config

```yaml
proxy-groups:
  - name: lb-group
    type: load-balance
    proxies:
      - proxy-a
      - proxy-b
      - proxy-c
    url: https://www.gstatic.com/generate_204
    interval: 300          # health-check sweep interval in seconds
    strategy: round-robin  # round-robin (our default; upstream: consistent-hashing) | consistent-hashing
    lazy: false            # defer the sweep until the group carries traffic
```

Field reference:

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `proxies` | `[]string` | no* | — | Named proxies or groups to balance across. Same resolution as Selector for static names; `use:` / `include-all` provider members balance alongside them (statics first in rotation order). *Required only when neither `use:` nor `include-all` supplies members. |
| `url` | string | no | `https://www.gstatic.com/generate_204` | Health-check probe URL. Members are probed against it by the periodic sweep. |
| `interval` | integer | no | `300` | Health-check sweep interval in seconds. Each member is probed every `interval` seconds; a member whose probe fails is skipped by both strategies until it recovers. `0` disables the periodic sweep (upstream `HealthCheck.auto()`). |
| `strategy` | enum | no | `round-robin` | Selection strategy. |
| `lazy` | bool | no | `false` | When `true`, the periodic sweep is deferred until the group next carries traffic (same as `url-test`/`fallback`). Upstream defaults to `true`; see divergence 5. |
| `expected-status` | string/int | no | `2xx` | Expected HTTP status for health probes (same handling as `url-test`/`fallback`: int or `"a-b"` range list). Honored by the sweep since #555. |

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Unknown `strategy` value — upstream falls back to round-robin | A | Unknown strategy means the user may get different distribution behaviour than intended. Hard-error at parse time. |
| 2 | `strategy: consistent-hashing` with no alive proxies — upstream panics (index out of bounds) | A | We return `MeowError::NoProxyAvailable` and surface it as a clean dial error. NOT a panic. |
| 3 | All proxies dead — upstream returns the round-robin slot (dead proxy) | B | We return `NoProxyAvailable` error immediately instead of dialing a known-dead proxy. Same reachability outcome (connection fails), but our failure is fast and named. |
| 4 | ~~`strategy: consistent-hashing` diverges on key/hash/dead-member handling~~ — **resolved** (issue #621) | B | Was: we hashed the *client* `src_ip` with FNV-1a mod the alive subset (Clash-Premium-style src affinity). Now: the upstream scheme — `getKey` derives the destination key (IP-literal host → host, domain → eTLD+1 via `psl`, else `dst_ip`), hashed with FNV-1a-64 and `jumpHash`-ed over the **full** member list, retrying `key+1` up to 5× on dead members before a linear alive scan. One residual difference: upstream's `utils.MapHash` is seeded per process (assignments are not reproducible across restarts even upstream); our FNV-1a-64 is deterministic, which is strictly better for stability. |
| 5 | `lazy` defaults to `false` — upstream defaults to `true` (`GroupCommonOption{Lazy: true}`, `adapter/outboundgroup/parser.go`) | B | Pre-existing default shared with `url-test`/`fallback`; an unset `lazy` probes eagerly instead of only while the group carries traffic. Subscription-compatible either way; only background probe volume differs. Tracked in #555. |
| 6 | ~~`test_url` is not stored on `LoadBalanceGroup`~~ — **resolved** (issue #621) | B | `with_test_url` stores the configured `url` (default `https://www.gstatic.com/generate_204`); selection eligibility uses `alive_for_url(test_url)` like upstream's `AliveForTestUrl(testUrl)`, and `GET /proxies` now emits `testUrl` for LB groups. `expected-status` continues via `with_expected_status`. |
| 7 | Duplicate `use:` entries are deduped — upstream appends per entry, so `use: [A, A]` double-weights provider A | B | A duplicated provider name can only ever produce an identical member view (group `filter:`/`exclude-*` are group scalars), so double-wiring it is always a weighting accident, never intent. Static `proxies:` duplicates still double-weight, matching upstream. |
| 8 | `include-all` pulls providers only; upstream's `include-all` also pulls statics (`include-all-providers` is the providers-only alias upstream) | B | Pre-existing shared group semantics — `include-all-proxies` already covers the all-statics case, so `include-all` here equals upstream's `include-all-providers`. Combined with `use:`, `include-all` wins and `use:` is ignored — same as upstream. |
| 9 | `use:`/`include-all*`/`filter:`/`exclude-*:` on a `relay` group warns and is ignored — upstream relay *accepts* provider members (`NewRelay` takes providers) | B | A relay is a fixed static chain; provider members have no place in it (ours is static-only). |
| 10 | Default `strategy` is `round-robin` — upstream defaults to `consistent-hashing` (`case "", "consistent-hashing"` in `NewLoadBalance`) | B | Pre-existing default; kept after row 4's resolution because changing the default strategy would silently reshuffle existing deployments' assignments. `consistent-hashing` is a one-word opt-in. |
| 11 | `strategy: sticky-sessions` is rejected — upstream supports it (LRU-cached src+dst key → jumpHash member) | B | Listed here instead of the unknown-strategy catch-all: it is a real upstream value, currently unimplemented. If needed, upstream's semantics are an LRU of `(src,dst) → member index` with a 10-minute TTL. |

## Internal design

### Struct

```rust
// crates/meow-proxy/src/group/load_balance.rs

pub enum LbStrategy {
    RoundRobin,
    ConsistentHashing,
}

pub struct LoadBalanceGroup {
    name: SmolStr,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,  // live `use:`/`include-all` members
    test_url: String,                   // probe URL; also the eligibility key
    expected_status: String,            // probe acceptance set ("" = default 2xx)
    strategy: LbStrategy,
    counter: AtomicUsize,   // only used for round-robin
    health: ProxyHealth,
    usage: UsageTracker,
    dial_failures: DialFailureTracker,  // onDialFailed escalation
}
```

`AtomicUsize` (not `RwLock<usize>`) for the round-robin counter —
load-balance's selection is a hot path and the counter needs only
relaxed-ordering increments, no lock. `fetch_add(1, Relaxed)` mod
alive-count is correct: occasional races on the modulo produce
non-optimal but not incorrect distribution (two consecutive
connections to the same proxy), which is acceptable for a
load-balancer where exact fairness is not guaranteed anyway.

### Selection logic

```rust
impl LoadBalanceGroup {
    // One immutable member snapshot per pick — statics first, then each
    // provider slot's current contents. Eligibility is
    // `alive_for_url(test_url) && (!udp_only || support_udp())`.
    fn pick(&self, metadata: &Metadata, udp_only: bool, advance: bool)
        -> Option<Arc<dyn Proxy>>
    {
        let members: Vec<Arc<dyn Proxy>> = self.member_proxies().unwrap_or_default();
        match self.strategy {
            LbStrategy::RoundRobin => {
                // count eligible in the snapshot, take
                // counter % alive_count, clone the nth eligible member.
            }
            LbStrategy::ConsistentHashing => {
                // key = fnv1a64(get_key(metadata)); jump_hash over the FULL
                // snapshot, retry key+1 up to 5x on ineligible members,
                // then a linear eligible scan; None when all are dead.
            }
        }
    }
}
```

**Single-snapshot pick** — the earlier two-pass form (count eligible,
then re-walk under fresh provider-slot guards) could observe a member
death or a provider-slot swap between passes and shift the pick or yield
`None` for one dial (issue #621). Materializing the member `Vec` once per
pick removes the race at the cost of one small allocation per dial —
per-connection, not per-packet, so ADR-0008's relay-hot-path invariants
are unaffected.

**Destination-keyed consistent hashing (mihomo `getKey`)** — the key
derives from the destination, not the client: an IP-literal `host` is
used verbatim, a domain is reduced to its eTLD+1 via the `psl` crate
(`a.b.example.co.uk` → `example.co.uk`, so all hosts under one
registrable domain share a member), and anything else falls back to
`dst_ip` (empty key when neither exists — deterministic, not random).
The key is hashed with inline FNV-1a-64 and bucketed with the
Lamping–Veach `jumpHash` over the **full** member list; an ineligible
member retries `key+1` up to five times, then a linear alive scan runs
(divergence 3 keeps all-dead → `None` rather than upstream's dead pick).
Upstream's `utils.MapHash` is a per-process-seeded `maphash`, so its
bucket assignments are not reproducible across restarts even upstream;
a fixed hash gives strictly better stability for identical key→member
affinity.

**No dependency on a crate for FNV** — 8 lines of inline math. Do
not add `fnv` crate for a 1-function use. (`psl` *is* a new dependency —
the public-suffix list is not something to hand-maintain.)

### Health-check integration

`LoadBalanceGroup` participates in the same periodic health-check sweep as
`url-test`/`fallback`, driven by the `HealthCheckSupervisor` in
`crates/meow-tunnel/src/health_check.rs`:

- `meow_config::extract_health_check_specs` reads the raw group config and
  emits a `HealthCheckSpec` (`group_name`, `url`, `interval_secs`, `lazy`)
  for every `load-balance` group, using the shared defaults (`url` →
  `https://www.gstatic.com/generate_204`, `interval` → 300 s, `lazy` →
  false); `interval: 0` emits no spec. The supervisor reconciles the spec
  set on every config commit, so groups added or removed at runtime are
  picked up.
- The per-group task ticks every `interval` seconds. Each tick resolves the
  group's `member_proxies()` — statics and provider-slot members alike —
  and probes them via
  `meow_proxy::health::probe_many_bounded(members, &spec.url, …)`, which
  records each result into that member's shared `ProxyHealth`
  (`record_delay`; `alive = delay > 0`). Dial-failure escalation marks a
  failing member dead between ticks; a successful sweep probe revives it.
- `select()` reads `p.alive()` on each member — no extra locking; the sweep
  and the group hold the same `Arc<dyn Proxy>`, so a recorded probe result is
  immediately visible to selection.
- `lazy: true` gates probing on `usage_generation()`: `LoadBalanceGroup` bumps
  a `UsageTracker` on every user dial (`dial_tcp` / `dial_udp` /
  `unwrap_proxy`), and the loop skips ticks until the generation advances, so
  an idle lazy group is not probed.

### `dial_tcp` / `dial_udp`

```rust
#[async_trait]
impl ProxyAdapter for LoadBalanceGroup {
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let proxy = self.select(metadata)
            .ok_or(MeowError::NoProxyAvailable)?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        // `pick(metadata, udp_only = true)` — same single-snapshot pick with
        // the eligibility predicate narrowed to `alive_for_url(test_url)
        // && support_udp()`.
        // ... same hash/counter logic as dial_tcp
    }

    fn support_udp(&self) -> bool {
        // true if any static or provider-slot member supports UDP
        self.any_member(|p| p.support_udp())
    }
}
```

Note: `support_udp()` returns true if *any* proxy supports UDP,
matching upstream's group-level behaviour. The actual UDP dial
filters to UDP-capable alive proxies and applies the strategy over
that subset.

## Acceptance criteria

1. Round-robin distributes across alive proxies in strict rotation
   order (modulo wrapping). Unit test: 10 dials, 3 alive proxies →
   sequence [0,1,2,0,1,2,...].
2. Consistent-hashing returns the same proxy for the same destination
   key, regardless of call order. Unit test: same `Metadata.host`
   → always proxy B across 100 calls.
3. Consistent-hashing produces different assignment for two distinct
   destination keys (scan dst hosts until two land on different members).
4. Both strategies skip dead proxies. Unit test: mark proxy-B dead,
   assert round-robin never selects it.
5. All proxies dead → `NoProxyAvailable` error, not a panic or a
   dial attempt to a dead proxy. Class A per ADR-0002.
6. Unknown `strategy` value → hard parse error at config load.
   Class A per ADR-0002.
7. Health-check sweep fires after `interval` seconds; `alive()` state
   updates; subsequent selections reflect the new health state.
8. `ProxyHealth` on the group itself integrates with the api-delay-
   endpoints probe path.
9. `AdapterType::LoadBalance` is present in the enum and serialises
   to `"LoadBalance"` in JSON (for REST API `/proxies` response).
10. Consistent-hashing with no host and no `dst_ip` deterministically
    selects one proxy (not random, not `NoProxyAvailable`) — the empty
    key.
11. Round-robin does not panic or return a stale index when the alive-set
    shrinks between calls (proxy flap scenario).

## Test plan (starting point — qa owns final shape)

**Unit (`group/load_balance.rs`):**

- `round_robin_cycles_through_alive_proxies` — three alive proxies,
  10 consecutive `select()` calls, assert [0,1,2,0,1,2,0,1,2,0].
  Upstream: `adapter/outbound/loadbalance.go::RoundRobin.Addr`.
  NOT random; NOT skipping index on wrap — strictly sequential.
- `round_robin_skips_dead_proxy` — mark proxy-1 dead, assert only
  proxy-0 and proxy-2 appear in rotation.
- `consistent_hashing_stable_for_same_dst` — same dst host, 100
  calls, assert same proxy every time.
  Upstream: `adapter/outbound/loadbalance.go::strategyConsistentHashing`.
  NOT volatile — consistent-hash must be deterministic.
- `consistent_hashing_ignores_src_ip` — two different client src IPs to
  the same destination land on the same member (the key is the dst).
- `consistent_hashing_spreads_across_dst_keys` — scan dst hosts until
  two land on different members; asserts the key space spreads.
- `consistent_hashing_retries_past_dead_member` — kill the member a key
  maps to; the jump-hash retry/linear fallback returns an *alive* member.
- `consistent_hashing_dead_member_remaps_only_its_keys` — killing member
  X moves only the keys that mapped to X (jump-hash minimal reshuffle);
  keys on surviving members do not move.
- `get_key_*` — host IP literal passthrough, domain → eTLD+1
  (`a.b.example.co.uk` → `example.co.uk`, case-insensitive),
  public-suffix-only host → `dst_ip`, no host → `dst_ip`, neither → "".
- `all_proxies_dead_returns_no_proxy_available` — all dead, assert
  `Err(NoProxyAvailable)`. Class A per ADR-0002 (NOT panic, NOT
  dial-dead-proxy as upstream does).
  Upstream: Go code panics with index out of bounds in the consistent-
  hash path; we return a clean error.
- `consistent_hashing_absent_dst_deterministic` — no host, no `dst_ip`,
  assert same proxy selected across 10 calls (the empty key).
  NOT random. NOT error. Upstream hashes "" identically.
- `round_robin_handles_alive_set_flap` — 3 alive proxies; call select()
  once; mark proxy-1 dead; call select() again; assert no panic and
  returned index is valid (0 or 2). NOT stale index, NOT out-of-bounds.
  Guards against future refactor that would make modulo unsafe on
  shrinking alive-set.

**Unit (config parser):**

- `parse_load_balance_default_strategy` — no `strategy:` field →
  round-robin selected.
- `parse_load_balance_explicit_round_robin` — `strategy: round-robin`.
- `parse_load_balance_consistent_hashing` — `strategy: consistent-hashing`.
- `parse_load_balance_unknown_strategy_hard_errors` — an unrecognised
  `strategy:` value → parse error. Class A per ADR-0002: NOT silent
  fallback to round-robin. (Upstream additionally *accepts*
  `sticky-sessions` — unimplemented here, divergence 11.)

**Integration:**

- `load_balance_round_robin_distributes_connections` — real
  URLTest-style probe with a local echo server on three ports, assert
  connections spread across all three ports over 9 dials.

## Implementation checklist (for engineer handoff)

- [ ] Add `AdapterType::LoadBalance` to `meow-common/src/adapter_type.rs`.
- [ ] Implement `group/load_balance.rs` with both strategies. Inline
      FNV-1a 64-bit (no crate dep). Comment cites upstream file.
- [ ] Wire `parse_proxy_group` in `meow-config` to recognise
      `type: load-balance` and produce a `LoadBalanceGroup`.
- [ ] Spawn health-check sweep task in `main.rs` for each
      load-balance group with `interval > 0`.
- [ ] Update `docs/roadmap.md` M1.C-1 row with merged PR link.
