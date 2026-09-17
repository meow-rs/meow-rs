# Spec: Relay proxy group (M1.C-2)

Status: Approved (architect 2026-04-11, unblocked once M1.B-1 VMess lands `connect_over` trait change)
Post-M1 update: issue #570 extended `connect_over` to the full TCP outbound
set — vless, vmess, trojan, anytls, shadowsocks (built-in plugins only),
plus the existing direct/reject/http/socks5/snell. `connect_over` now means
"run the adapter's complete post-connect pipeline (its own transport/TLS
stack + protocol handshake) over the supplied stream" — mihomo's
`DialContextWithDialer` model. Hysteria2 stays first-hop-only (QUIC cannot
ride a TCP stream); SS external SIP003 plugins fail loudly since the
subprocess owns its outbound leg; mux pooling is bypassed on relay-supplied
streams (single-use, nothing to pool).
Owner: pm
Tracks roadmap item: **M1.C-2**
Depends on: none beyond the existing `ProxyAdapter` trait.
See also: [`docs/specs/group-load-balance.md`](group-load-balance.md) —
drafted concurrently; shares the M1.C milestone.

## Motivation

`type: relay` chains multiple outbounds in sequence. Traffic flows:

```
client → proxy[0] → proxy[1] → … → proxy[N-1] → target
```

This enables multi-hop topologies: a user in region A routes through
a trusted proxy in region B, which then exits through a commercial
node in region C. Common use cases: self-hosted exit nodes chained
with subscription nodes; geographically distributed double-hop for
censorship circumvention.

Relay groups appear frequently in advanced Clash Meta configs. Without
them, meow-rs silently drops the group (parse error → group absent
→ any rule referencing it matches `DIRECT` or errors, depending on
tunnel mode).

Upstream Go mihomo implements relay in ~200 LOC at
`adapter/outbound/relay.go`.

## Scope

In scope:

1. `RelayGroup` struct in `crates/meow-proxy/src/group/relay.rs`
   implementing `ProxyAdapter`.
2. TCP relay through a chain of ≥2 proxies. Each intermediate hop
   is connected via its predecessor using `ProxyAdapter::dial_tcp`
   with the *next hop's address* as the `Metadata` target — not the
   final target. The final hop dials the actual target.
3. UDP relay through a relay chain when all proxies in the chain
   support UDP and the final hop supports UDP. Returns `UdpNotSupported`
   if any chain member lacks UDP support.
4. Minimum chain length: 2 proxies. Single-proxy `relay` is a
   configuration error — hard-error at parse time.
5. `AdapterType::Relay` added to `meow-common/src/adapter_type.rs`.
6. YAML config parser for `type: relay` groups.

Out of scope:

- **Health-check on relay groups.** Upstream Go mihomo does not run
  health-check sweeps on relay groups — the group is a fixed chain,
  not a selection over alternatives. We match. If the user wants
  health-aware relay, they compose a Fallback group whose members are
  relay groups.
- **Dynamic selection inside a relay chain.** Each `proxies:` entry
  in a relay group is a fixed proxy name — NOT a group name that gets
  expanded at dial time. If the user lists a Selector group name in a
  relay chain, we forward to the Selector's currently-selected proxy
  (the Selector resolves normally). We do NOT prohibit group
  references — this matches upstream.
- **WARP-over-WARP or protocol-specific relay modes.** We relay at
  the `ProxyConn` abstraction layer; protocol internals are opaque.
- **Relay of relay (nested relay groups).** Permitted but not
  explicitly tested — if proxy[0] is itself a relay group, the chain
  nests correctly via `dial_tcp` delegation. Document in a comment.

## Non-goals

- Implementing a dedicated tunnel protocol. Relay works by composing
  existing `ProxyAdapter` implementations — no new wire format.
- Exposing partial chain results if an intermediate hop fails.
  The entire chain fails as a unit with the offending hop's error.

## User-facing config

```yaml
proxy-groups:
  - name: double-hop
    type: relay
    proxies:
      - first-hop    # connects to second-hop's address
      - second-hop   # connects to the target
```

```yaml
proxy-groups:
  - name: triple-hop
    type: relay
    proxies:
      - proxy-a      # outermost: connects to proxy-b's address
      - proxy-b      # middle: connects to proxy-c's address
      - proxy-c      # innermost: connects to the target
```

Field reference:

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `proxies` | `[]string` | yes | — | Ordered list of proxy or group names. Minimum 2 entries. Each entry is a server:port in the chain; the final entry connects to the real target. |

**No `url`, `interval`, `strategy`, or `lazy`** — relay is a fixed
chain, not a selection pool. Presence of these fields is accepted and
ignored (forward-compat, not a parse error) with a warn-once at parse
time.

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Single-proxy relay (`proxies` length 1) — upstream silently acts as a passthrough | A | A single-proxy relay is a misconfiguration: the user likely intended a different group type. Hard-error at parse time: "relay group requires at least 2 proxies; use type: selector or type: direct for a single proxy". |
| 2 | Empty `proxies` list — upstream panics | A | Hard-error at parse time. |
| 3 | UDP relay when any chain member lacks UDP — upstream silently returns a non-functional conn | A | We return `UdpNotSupported` immediately from `dial_udp` if any chain member's `support_udp()` is false. NOT a silent partial relay. |
| 4 | `url`/`interval` present on relay group — upstream ignores | B | Warn-once at parse time. No routing change. |

## Internal design

### Dial algorithm

The relay chain must be established inside-out:

```
To relay [A, B, C] → target:

1. dial_tcp(A, dest={B.server:B.port})     → conn_to_A
2. via conn_to_A: dial_tcp(B, dest={C.server:C.port})  → conn_to_B_via_A
3. via conn_to_B_via_A: dial_tcp(C, dest=target)        → conn_to_C_via_A_via_B
4. return conn_to_C_via_A_via_B (the stream the caller writes payload to)
```

Step 1 establishes a real TCP connection to proxy A. Steps 2 and 3
are proxy-level `CONNECT`-style tunnels through the already-established
stream — each `dial_tcp` call is given the next proxy's address as
the target, causing it to send a proxy-protocol header (VMess/VLESS/
Shadowsocks/etc.) that tells proxy A to forward to proxy B, and then
proxy B to forward to the real target.

This works because every `ProxyAdapter::dial_tcp` takes an arbitrary
`Metadata` target and establishes a proxied connection to that target
over whatever stream is provided. The relay implementation provides the
*prior-hop's established stream* as the underlying connection, passing
proxy addresses as the target metadata.

### Architecture decision: `connect_over` on `ProxyAdapter` (architect approved 2026-04-11)

**Option (a) — `connect_over(stream, metadata)` required method on `ProxyAdapter`.**

Signature:

```rust
async fn connect_over(
    &self,
    stream: Box<dyn ProxyConn>,
    meta: &Metadata,
) -> Result<Box<dyn ProxyConn>>;
```

Each adapter implements this to wrap the passed stream with its own
protocol header + framing, without dialing a fresh TCP socket. The
relay chain calls `dial_tcp` on the first proxy (establishes a real
TCP connection), then `connect_over` on each subsequent hop.

**Required method — no default impl.** Do NOT provide a default
implementation that falls back to `dial_tcp`. A silent default would
let adapters that forget to override appear to work in unit tests while
failing relay in production. Every adapter author must consciously
implement `connect_over`. The compiler enforces this.

**Special cases:**
- `DirectAdapter::connect_over` — returns the passed stream unchanged.
  A direct hop in a relay chain is a no-op (useful for
  `relay: [direct, ss-node]`).
- `RejectAdapter::connect_over` — returns `Err(MeowError::Rejected)`.

**Breaking change scope:** this trait change touches every
`ProxyAdapter` impl (Direct, Reject, Shadowsocks, Trojan, and M1.B
VMess/VLESS once they land). **M1.B should land before M1.C-2** so
VMess/VLESS start with `connect_over` in their shape from day one
rather than being retrofitted. If M1.C-2 lands first, pay the retrofit
cost on VMess/VLESS. See team-lead for sequencing decision.

**Relay algorithm:**

```rust
async fn relay_tcp(
    proxies: &[Arc<dyn Proxy>],
    final_target: &Metadata,
) -> Result<Box<dyn ProxyConn>> {
    debug_assert!(proxies.len() >= 2, "relay chain validated at parse time");

    // proxy[0]: real TCP connect, target = proxy[1]'s server:port
    let mut meta = metadata_for_proxy(&proxies[1]);
    let mut conn: Box<dyn ProxyConn> = proxies[0].dial_tcp(&meta).await
        .map_err(|e| MeowError::relay_hop_failed(0, e))?;

    // proxy[1..N-2]: connect_over the previous hop's established stream
    for i in 1..proxies.len() - 1 {
        meta = metadata_for_proxy(&proxies[i + 1]);
        conn = proxies[i].connect_over(conn, &meta).await
            .map_err(|e| MeowError::relay_hop_failed(i, e))?;
    }

    // proxy[N-1]: final hop connects to the actual target
    let last = proxies.len() - 1;
    conn = proxies[last].connect_over(conn, final_target).await
        .map_err(|e| MeowError::relay_hop_failed(last, e))?;
    Ok(conn)
}
```

**Nested relay groups** (relay-of-relay) work transparently:
`RelayGroup` itself implements `ProxyAdapter`, so its `connect_over`
runs the inner chain starting from the passed stream as the base
connection. No special casing needed. This is confirmed correct by
architect.

### Struct

```rust
// crates/meow-proxy/src/group/relay.rs

pub struct RelayGroup {
    name: String,
    proxies: Vec<Arc<dyn Proxy>>,  // length >= 2, validated at parse time
    health: ProxyHealth,           // for API surface; relay has no self-health-check
}

#[async_trait]
impl ProxyAdapter for RelayGroup {
    fn name(&self) -> &str { &self.name }
    fn adapter_type(&self) -> AdapterType { AdapterType::Relay }
    fn support_udp(&self) -> bool {
        self.proxies.iter().all(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        relay_tcp(&self.proxies, metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.support_udp() {
            return Err(MeowError::UdpNotSupported);
        }
        relay_udp(&self.proxies, metadata).await
    }
}
```

### Error handling

Intermediate hop failures surface wrapped in `MeowError::RelayHopFailed`:

```rust
MeowError::RelayHopFailed { hop: usize, source: Box<MeowError> }
```

Error message shape: `"relay chain failed at hop 1 (proxy-b → proxy-c): <inner error>"`.

Add `RelayHopFailed` to `MeowError` in `meow-common`. Do NOT use
`anyhow::Context::context()` at the public boundary — `MeowError`
is the error type for all `ProxyAdapter` results. Use anyhow only for
internal plumbing within the relay implementation, not at the return
boundary.

## Acceptance criteria

1. TCP relay through a 2-proxy chain delivers bytes to target. Unit
   test with mock proxy adapters.
2. TCP relay through a 3-proxy chain delivers bytes to target.
3. Single-proxy chain hard-errors at config parse time. Class A per
   ADR-0002.
4. Empty chain hard-errors at config parse time. Class A per ADR-0002.
5. UDP relay succeeds when all chain members support UDP.
6. UDP relay returns `UdpNotSupported` when any chain member lacks
   UDP support. Class A per ADR-0002: NOT a silent partial relay.
7. Intermediate hop failure surfaces with hop index and inner error
   message. Not a raw inner error with no relay context.
8. `url`/`interval` on a relay group logs exactly one `warn!` per
   field. Class B per ADR-0002.
9. `AdapterType::Relay` serialises to `"Relay"` in JSON.
10. Group-reference in relay chain (e.g. a Selector as proxy[0])
    resolves correctly at dial time via the Selector's `connect_over`.
11. Nested relay-of-relay (outer relay whose proxy[0] is itself a
    RelayGroup) delivers bytes to mock target without panicking.
12. `MeowError::RelayHopFailed { hop, source }` is used at hop
    boundaries — NOT `anyhow::Context` at the public return type.

## Test plan (starting point — qa owns final shape)

**Unit (`group/relay.rs`):**

- `relay_two_hop_tcp_roundtrip` — two mock proxy adapters that
  simply pass bytes through; assert payload arrives at mock target.
  Upstream: `adapter/outbound/relay.go::DialContext`. NOT direct
  connection to target — intermediate hops must each receive the
  next-hop address as their dial target.
- `relay_three_hop_tcp_roundtrip` — three hops, same shape.
- `relay_single_proxy_hard_errors_at_parse` — `proxies: [A]` →
  parse error naming the relay constraint.
  Class A per ADR-0002. Upstream: silently acts as passthrough.
  NOT warn-ignore — hard error.
- `relay_empty_proxies_hard_errors_at_parse` — `proxies: []`.
  Class A. Upstream: panics.
- `relay_udp_all_support_udp_succeeds` — all mock proxies have
  `support_udp = true`; assert `dial_udp` completes.
- `relay_udp_one_lacks_udp_returns_error` — one mock proxy has
  `support_udp = false`; assert `Err(UdpNotSupported)`.
  Class A per ADR-0002. Upstream: returns a non-functional conn.
  NOT a silent failure — must be `UdpNotSupported` specifically.
  Run this variant three times: lacking-UDP proxy is at position 0
  (first hop), middle position, and last position — all must error.
- `relay_hop_failure_includes_hop_index` — mock proxy[1] errors;
  assert the returned `MeowError::RelayHopFailed` contains `hop == 1`.
  NOT a raw inner error with no relay context. `anyhow` NOT at boundary.
- `relay_url_interval_fields_warn_once` — YAML with `url:` +
  `interval:` on a relay group → exactly one `warn!` per unexpected
  field. Class B per ADR-0002.
- `relay_nested_relay_group` — outer 2-hop relay where proxy[0] is
  itself a 2-hop `RelayGroup` (4 effective hops total). Assert payload
  arrives at mock target. Guards the transparent nesting property
  confirmed by architect. Acceptable to mark `#[ignore]` if it requires
  4 fully-implemented adapters not yet available in M1.

**Integration:**

- `relay_chain_routes_through_intermediate` — integration test using
  two real proxy adapters (direct or mock SS); assert the intermediate
  proxy's access log shows the request (if accessible), or assert the
  final target sees the connection from the intermediate's address.
  Acceptable to mark `#[ignore]` if it requires a real network setup.

## Implementation checklist (for engineer handoff)

**Sequencing (updated 2026-04-11):** `ProxyAdapter::connect_over` is
implemented in M1.B-3/B-4 (HTTP CONNECT + SOCKS5) — coded and reviewed,
pending push to main. Direct/Reject/SS/Trojan get a default `Err(NotSupported)`;
HTTP and SOCKS5 have full implementations.
**Once M1.B-3/B-4 merges, M1.C-2 is unblocked and can run in parallel
with VLESS.** VLESS must still add its own `connect_over` override before
a relay chain can use a VLESS hop, but that does not block the relay group
implementation or its tests (use SS/HTTP/Direct hops in tests instead).

- [ ] Add `AdapterType::Relay` to `meow-common/src/adapter_type.rs`.
- [ ] Add `connect_over(&self, stream: Box<dyn ProxyConn>, meta: &Metadata) -> Result<Box<dyn ProxyConn>>`
      to the `ProxyAdapter` trait in `meow-common`. Required method —
      no default impl. Update ALL existing adapters (Direct, Reject,
      Shadowsocks, Trojan) before implementing RelayGroup.
- [ ] Add `MeowError::RelayHopFailed { hop: usize, source: Box<MeowError> }`
      to `meow-common`.
- [ ] Implement `group/relay.rs`. Comment at top cites upstream:
      `// upstream: adapter/outbound/relay.go`.
      Add `debug_assert!(proxies.len() >= 2)` in `RelayGroup::new`.
- [ ] Wire `parse_proxy_group` in `meow-config` to recognise
      `type: relay`. Hard-errors for `proxies.len() < 2`.
- [ ] Update `docs/roadmap.md` M1.C-2 row with merged PR link.

## Resolved questions (architect sign-off 2026-04-11)

1. **Architecture: `connect_over` on `ProxyAdapter`** — Option (a)
   approved. Implemented in M1.B-3/B-4 (pending merge) with a default
   `Err(NotSupported)` impl on the trait (updated 2026-04-11 — original
   spec said "required method, no default" but the implementation uses a
   defaulted impl so existing adapters compile without override).
   `DirectAdapter` returns stream unchanged; `RejectAdapter` returns
   error; HTTP+SOCKS5 have full impls.

2. **Relay-of-relay (nested relay groups)** — works transparently.
   `RelayGroup` implements `ProxyAdapter`; its `connect_over` runs the
   inner chain from the passed stream. No special casing. Add
   `relay_nested_relay_group` test bullet.
