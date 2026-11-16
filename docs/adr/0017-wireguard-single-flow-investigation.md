# ADR-0017: WireGuard single-flow cap — measurement-gated fix

Status: accepted

## Context

A single inner-TCP flow over the userspace WireGuard path plateaued at
~10-13 MB/s on a sub-ms LAN rig while eight concurrent flows aggregated
~120 MB/s — a per-flow ceiling, not a per-adapter one. Two candidate
mechanisms were on the table:

- **Hypothesis A (window-bound):** per-flow throughput caps at
  `TCP_SOCKET_BUF / RTT` (1 MiB / RTT) — already measured on a real
  140 ms KR↔US peer: 64 KiB → ~0.5 MB/s, 256 KiB → ~1.8 MB/s,
  1 MiB → ~7.5 MB/s. Cannot explain the LAN cap (1 MiB / 0.4 ms would
  be GB/s-scale), but is the live bound on WAN paths.
- **Hypothesis B (drop-bound):** the inner UDP socket's receive depth
  (~370 KiB) tails a full-window burst (~1.1 MB of datagrams), and the
  inner TCP pays smoltcp's ≥1 s RTO floor per hole.

The batch specification made this a **measurement gate**: instrument
first, fix only what the counters prove.

## Measurement

Drop/saturation counters were added across the pump (`dropped_rx`,
`dropped_tx`, `rx_sockbuf`, `rx_chan`, `tx_buf_full`, `txq_unmoved`,
`tcp_tx_stall`, `outbox_dropped`) and snapshot-logged every 2 s per
flow. A clean single-flow run to the rig's `i-wg` leg showed:

- **Zero drops everywhere** — `dropped_*`, `rx_sockbuf`, `rx_chan`,
  `tx_buf_full`, `tx_err` all stayed 0 under sustained saturation.
  Hypothesis B is refuted; no UDP-depth change.
- `txq = 1 MiB / 1 MiB` permanently saturated, `txq_unmoved` growing
  monotonically, `can_send = false`, `timeout = None`: the socket is
  throttled by the **peer's advertised window**, not by loss.
- The bound is per-peer-implementation, not per-path: the same smoltcp
  path sustained ~8 MB/s against sing-box's userspace stack
  (`i-wg`, inner TCP terminates in gVisor-like code with a small
  window and userspace ACK cadence) but ~44 MB/s against a kernel
  TCP peer (`i-ss-via-wg`, inner TCP terminates in the kernel).
  750 MB/s on the direct non-WG control leg rules out the relay path.

## Decision

- **Ship the window increase (C1a):** `TCP_SOCKET_BUF` 1 MiB → 4 MiB.
  The bound it lifts is *our advertised receive window*, i.e. the
  **download** direction on WAN paths — the provable `buf/RTT` ceiling
  (4 MiB / 140 ms ≈ 30 MB/s). smoltcp derives the RFC 7323
  `remote_win_shift` automatically (`bit_width(capacity) - 16` = 7 at
  4 MiB), so no explicit option handling is needed.
  `TCP_READ_QUEUE` 32 → 64 keeps the `queue × 64 KiB ≥ window`
  invariant; `POLL_TX_BYTES_BUDGET` 2 → 4 MiB lets one service pass
  drain a full window.
- **Do not ship a UDP-depth increase (C1b):** the measurement refuted
  the drop hypothesis.
- **Do not fix the LAN-rig upload cap:** it is the far end's receive
  window ÷ effective RTT — a property of the *peer's* TCP stack, not
  ours. Recorded here so future investigations don't re-measure it.
- `InitReceived` response caching: verified byte-identical to
  boringtun and kernel WireGuard semantics — no change (investigation
  closed in the batch spec).

## Consequences

- Per-connection footprint: 2 × 4 MiB eager socket buffers plus a
  4 MiB read channel — ~8.5 MiB typical, ~14 MiB worst-case staged.
  At `max-connections: 256` plus the listen pool this is ~2.7 GiB
  typical / ~4.2 GiB worst case — `max-connections` is the deployment
  lever, documented in `docs/wireguard.md`.
- Download-bound WAN flows gain ~4× headroom; LAN rig numbers are
  unchanged (peer-window bound).
- The instrumentation stays: the 2 s DEBUG snapshot answers "drops or
  windows?" for the next plateau report without a rebuild.
