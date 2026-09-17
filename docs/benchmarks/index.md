# Benchmarks index

This directory holds baseline measurements and audit findings for the meow-rs
refactor/cleanup-2026-05 work (M1 + M2).

## Baseline documents

| File | Contents |
|------|----------|
| [footprint-types-baseline.md](footprint-types-baseline.md) | Struct sizes at M2 open (`-Zprint-type-sizes`): Metadata 272 B, ConnectionInfo 408 B, UdpSession 48 B, MeowError 32 B, AdapterType 1 B |
| [footprint-rss-baseline.md](footprint-rss-baseline.md) | RSS at M2 open: idle 9.2 MB, load 11.4 MB, ~35 KB/conn steady-state |
| [footprint-alloc-baseline.md](footprint-alloc-baseline.md) | dhat peak live 2.93 MB; top allocation sites: Statistics::track_connection (~36 B/conn), Metadata alloc (~24 B/conn), relay CopyBuffer (~8 KiB/conn × 2) |
| [m1-addendum-lint-probe.md](m1-addendum-lint-probe.md) | All 9 allocation lints = 0 hits at M2 open (after M1 hygiene work) |
| [smallvec-audit-findings.md](smallvec-audit-findings.md) | Task #37 null result: all candidates regress; element types ≥ 16 B make SmallVec a size loss |
| [hardware.md](hardware.md) | Reference bench host spec |
| [methodology.md](methodology.md) | Measurement methodology and workload definitions |
| [binary-size.md](binary-size.md) | Stripped binary sizes by profile + target (ADR-0007 caps); §Post-mux (#412 stack, issue #426) records the post-mux `default` size and isolates the mux-attributable delta (~173–222 KiB) on aarch64/x86_64 — no cap breached, mipsel blocked by #421 |
| [rule-engine-findings.md](rule-engine-findings.md) | Rule engine profiling notes |
| [rule-engine-footprint-2026-09.md](rule-engine-footprint-2026-09.md) | Rule-engine retained-heap pass: sealed trie 8 B/node arena, `IpRangeSet` replaces `iprange`, interned adapters, 40 B IR slots, streaming `.mrs` loaders — 100k-domain rule-set 7.6 MiB → 1.5 MiB, GEOIP CN+US 12.6 MiB → 1.7 MiB, load peaks 3–5× lower |
| [rule-ir-pi-2026-07.md](rule-ir-pi-2026-07.md) | Rule-IR series (#285–#297) on-device benchmark: Raspberry Pi 4 gateway, real 7,528-rule config — 1.8–2.9× match latency, −11.5% live slots, IR build 37.6→96.1 ms |
| [baseline-2026-04-18.json](baseline-2026-04-18.json) | Raw dhat JSON snapshot at M2 open |
| [baseline-2026-07-15.json](baseline-2026-07-15.json) | Refreshed dev-laptop harness baseline (median of 3 runs, post DNS-cache prealloc fix); supersedes 2026-04-18 for `bench/compare.py` — see [methodology.md](methodology.md) §Developer baseline refresh |

## M2 delta summary

Collated from engineer completion reports on branch `refactor/cleanup-2026-05`.

| Task | Type | Before | After | Delta | % |
|------|------|--------|-------|-------|---|
| #34 M2.layout-metadata | Struct heap | Metadata: 9 × String heap alloc/conn | 0 heap allocs for ≤23 B fields via SmolStr | — | — |
| #35 M2.layout-connection-info | Struct size | ConnectionInfo 408 B | 120 B | −288 B | −70.6% |
| #36 M2.udp-session-intern | Struct size | UdpSession 48 B | 40 B | −8 B | −16.7% |
| #37 M2.smallvec-audit | Struct size | — | null result (all candidates regress) | 0 B | — |
| #39 M2.relay-buffer-pool | Alloc count | 2 × Box<[u8;4096]> per conn (~8 KiB) | 0 heap allocs on relay setup path | −2 allocs/conn | — |
| #40 M2.dns-cache-layout | Struct size | LruEntry 80 B | 72 B | −8 B | −10.0% |
| #40 M2.dns-cache-layout | RSS at cap | 5120 entries × 80 B = 400 KiB | 5120 × 72 B = 360 KiB | −40 KiB | −10.0% |
| #41 M2.lints-deny | Lint enforcement | 9 alloc lints at `warn` | 10 lints at `deny` (incl. redundant_clone) | — | — |

The full ADR-0006/0007/0008/0011 gauntlet results (throughput, binary size, dhat re-run) are in
[m2-exit-summary.md](m2-exit-summary.md) — produced by QA task #43 at M2 close.
