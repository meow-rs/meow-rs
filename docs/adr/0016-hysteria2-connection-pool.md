# ADR 0016: Hysteria2 K-way QUIC connection pooling (`quic-connections`)

- **Status:** Accepted
- **Date:** 2026-06-05
- **Related:** performance spec ITEM A (`/tmp/spec-round3.md` RANK 2)

## Context

A hysteria2 outbound multiplexes every proxied flow onto **one** QUIC
connection, driven by a single quiche driver task
(`crates/meow-proxy/src/hysteria2/driver.rs`). All recv/send crypto for
the connection serializes on that one task (~8.5–10 µs per datagram →
roughly 143 MB/s ceiling on the bench rig). Upstream mihomo (quic-go)
has the same shape — one connection, one core — so this is not a
parity gap but a shared ceiling. The community answer is K connections.

## Decision

`ReconnectableClient` (`hysteria2/client.rs`) becomes a pool of `K`
slots instead of the single `conn` cell:

```rust
type Slot = Mutex<Option<(Arc<ConnHandle>, Uint)>>;

struct ReconnectableClient {
    slots: Box<[Slot]>,
    generation: AtomicU,      // global, unchanged semantics
    next_slot: AtomicUsize,   // round-robin cursor
    // ...cfg, connect
}
```

- Each slot caches its own quiche connection + driver task +
  `PacketConnSocket`, tagged with the `generation` it was established
  under — the per-slot copy of the old `(handle, generation)` cell, so
  generation/reset semantics are unchanged.
- `handle()` claims a slot via `next_slot` round-robin, then runs the
  previous get-or-connect logic (`slot_handle`): live current-generation
  conn → return it; absent/dead/stale → dial inline.
- `tcp_connect` / `udp` share the cursor, so consecutive dials land on
  different connections.

### Edge cases

- **Slot dial failure** degrades gracefully (spec): the slot is left
  `None`, the scan falls through to the next slot, and an error surfaces
  only when *every* slot failed — the old single-connection failure
  shape, with `remember()` preserving errno classification for group
  dead-marking. A failed slot is retried on its next turn, so transient
  failures self-heal without a reset.
- **`reset()`** bumps the global generation once, then drains every
  slot (try-lock each; any contention defers the stale-only drain to a
  task — the same non-blocking contract as before). In-flight streams on
  all slots fail `ConnectionReset`; the next K claims redial.
- **UDP sessions ride slot affinity**: a session registers on the
  connection it was created on and keeps it for life — killing another
  slot leaves it alone, killing its own slot ends it.
- **`dialer-proxy`**: each slot's `prepare()` dials its own front UDP
  association — a bound `PacketConnSocket` can never serve a second
  connection.
- **Lazy fill**: unlike the spec sketch (eager `connect_bound` loop),
  slots dial on first selection. Eager fill would serialize `K` dials on
  the first claim for connections that may never be used, and lazy fill
  is what lets a failed slot heal on its next turn.

### Config knob

`quic-connections: K` on the proxy node — a meow-rs extension with no
mihomo equivalent. Absent → `DEFAULT_QUIC_CONNECTIONS` (2); parsed as an
unsigned integer (non-integer is a hard error); clamped to
`1..=MAX_QUIC_CONNECTIONS` (8) with a warn on clamp, and a warn above 4
— extra driver tasks rarely pay off past that. `1` reproduces the
legacy single-connection behaviour exactly.

Each slot authenticates independently — the server sees `K` concurrent
hysteria2 auth handshakes per password from `K` source ports. Servers
that rate-limit concurrent sessions per credential will refuse the
extra slots; the pool then degrades to the live slots (round-robin
skips dead ones until they heal), so the failure is graceful but the
aggregate win is lost. If a deployment sees fewer live slots than
configured, that's the cause — drop `quic-connections` to what the
server tolerates.

## Constraint — read this before expecting speedups

**Single-flow throughput is unchanged.** One stream rides one
connection for its whole lifetime: a single `tcp_connect` flow gets one
connection's ~143 MB/s, exactly as before. The pool widens *aggregate*
throughput across multiple flows/clients only.

## Consequences

- Aggregate throughput scales roughly K× per extra driver task (up to
  available cores), exceeding mihomo parity.
- `cargo test -p meow-proxy --lib hysteria2` covers round-robin
  distribution, per-slot death isolation + lazy heal, reset draining all
  slots, UDP affinity, per-slot front associations, and K=1 legacy
  regression against a new multi-connection in-process quiche peer.
