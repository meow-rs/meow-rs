# ADR 0008: M2 allocator audit — zero heap allocations on the packet-forwarding hot path

- **Status:** Proposed (architect 2026-04-18, awaiting pm + engineer-a + qa review)
- **Date:** 2026-04-18
- **Author:** architect
- **Supersedes:** —
- **Related:** roadmap §M2 item 2 (allocator audit of TCP relay and UDP NAT),
  vision §M2 goal 3 ("minimal runtime allocations on the hot path"),
  [ADR-0006](0006-m2-benchmark-methodology.md) (W5 rule-match "0 allocations
  per match" row ties into §3 here),
  [ADR-0007](0007-m2-footprint-budget.md) (allocator choice also drives binary
  size)

## Context

Roadmap §M2 item 2: **"Allocator audit of TCP relay and UDP NAT hot paths.
Target: zero heap allocations per forwarded packet on the steady state."**

"Zero allocations" is a phrase the Rust ecosystem throws around loosely. If
the M2 exit criterion is "zero heap allocations per forwarded packet," we
need a falsifiable definition of:

1. **Which allocator** — Rust's heap behaviour depends on the global
   allocator. `mimalloc`, `jemalloc`, and the system glibc allocator all
   differ on fragmentation and retention; a claim measured against one is
   not automatically true against another.
2. **Which "hot path"** — the literal `poll_read → poll_write` inside the
   relay loop, or everything after `handle_connection` accepts? TLS
   handshake vs steady-state data frames? UDP NAT entry creation vs
   per-datagram forwarding?
3. **What "zero" means** — literally `malloc(3)` calls == 0, or a looser
   "no per-packet allocation"? Does logging count? Metrics counters? A
   `String::from(...)` inside a `tracing::debug!` that never fires at the
   release log level?
4. **How we measure** — instrument the allocator (`GlobalAlloc` wrapper)?
   Use `dhat-rs`? Use `heaptrack` / `bytehound`? Strace-level `malloc`
   probes? Each answers a slightly different question.
5. **How we enforce** — a one-shot M2 audit? A permanent regression
   guardrail? In CI or on the bench host only?

Without these, the audit is a reading-level exercise and "zero" is
aspirational. ADR-0006 §5 row W5 ("0 heap allocations on the match hot
path") already cites this ADR; it is load-bearing for M2 exit.

## Decision

### 1. Scope: the "packet-forwarding hot path" defined

Exactly three code paths carry the zero-allocation guarantee for M2. They
are the only steady-state paths where a dropped allocation materially
affects latency tail or RSS growth over hours.

**HP-1 — TCP relay inner loop.**

Scope: the meow-rs-side wrapping around `tokio::io::copy_bidirectional`
in `crates/meow-tunnel/src/tcp.rs` — Statistics counter increments,
drop / teardown bookkeeping, any per-chunk logging or tracing spans.
The relay itself is already zero-copy via tokio's
`copy_bidirectional` (engineer-a findings 2026-04-18); HP-1's audit
verifies the **meow-rs wrapper** doesn't allocate per-chunk, not that
tokio doesn't.

Out of scope: TCP accept, TLS handshake, SOCKS5/HTTP inbound parsing, SS
AEAD key schedule at connect time, Trojan auth header build, rule match
at dispatch time (covered by HP-3 separately). The tokio
`copy_bidirectional` internals (audited upstream; we rely on its
documented buffer-reuse behaviour). Anything that happens **once per
connection** does not belong here.

Given the tight wrapper scope, HP-1 is the **least likely** of the three
HPs to fail §3 at M1 tip. A clean pass is expected; any failure means
someone accidentally allocates in a tight teardown loop.

**HP-2 — UDP NAT per-datagram forwarding.**

Scope: the `recvfrom → NAT lookup → sendto` loop inside
`meow-tunnel::udp_nat` (and the per-adapter UDP relay in
`meow-proxy/src/*`). For an existing NAT entry, a single datagram
traversal must not allocate.

Out of scope: NAT entry creation on first packet (that IS allowed to
allocate — it creates a session struct, an `Arc`, and the NAT-expiry
timer), NAT entry eviction, DNS snooping map insertion (covered by
HP-3 only if the lookup is inline with forwarding).

**HP-3 — Rule-match dispatch per connection.**

Scope: `RuleEngine::match_(metadata) -> AdapterAction` over the full
rule-set traversal for a single `Metadata`. DOMAIN trie lookup, IP-CIDR
tree lookup, GEOIP MMDB lookup, `AND/OR/NOT` composition. This is once
per new connection, not per packet — but it's the part ADR-0006 W5
measures at 20M matches/sec, and any allocation per match is an M-scale
multiplier on aggregate GC pressure.

Out of scope: rule-provider refresh (happens on an interval timer),
rule parse at config-load (one-shot), process-name lookup (syscall-bound,
tolerates a small allocation).

**Explicit non-scope for M2.**

- DNS resolution path (the actual DNS upstream query). M2 target for
  this is "matches Go on QPS" via ADR-0006 W4; per-query allocation
  audit is deferred to M3.
- REST API handlers — mostly cold, not worth the engineering cost.
- Config reload (M1.G-10) — one-shot.
- WebSocket event broadcast (ADR-0005) — cold path.

### 2. Allocator choice: `mimalloc` as the M2 default

meow-app binds `mimalloc` as the global allocator behind a default-on
feature (`alloc-mimalloc`). Rationale:

- **Uniform measurement substrate.** All M2 benchmark numbers
  (ADR-0006) and all M2 alloc-audit numbers (this ADR) are measured
  against the same allocator. A number measured with system glibc and
  shipped with mimalloc is a lie.
- **Smaller RSS on steady-state.** mimalloc's segment reclaim is
  aggressive; in comparable proxy workloads we expect 5–15% lower
  steady-state RSS than glibc malloc, which contributes to ADR-0006 §5's
  "W3 peak RSS ≤ 0.80× Go" row.
- **Competitive with Go's allocator.** Go has a compacting GC we cannot
  match in raw Rust; mimalloc closes the gap on fragmentation.
- **Size cost is ~200–300 KiB.** Acceptable against ADR-0007's budget.

An opt-in `alloc-jemalloc` feature (M2 exits without requiring it) is
accepted for users on musl targets where mimalloc's static link has been
flaky in the past. Default remains `mimalloc`.

**What this ADR does NOT pick:** a custom per-tunnel arena, slab
allocators, or bump allocators. They are M3 territory if profiling
shows `mimalloc` is the bottleneck. In M2 we work within `mimalloc`.

### 3. "Zero" defined — the steady-state count rule

"**Zero heap allocations per forwarded packet on the steady state**"
means, for each of HP-1 / HP-2 / HP-3:

1. **Warmup-first.** After a workload-specific warmup (HP-1: first 10 KiB
   per direction; HP-2: first 10 packets per flow; HP-3: first 100 matches
   per rule-set shape), the per-iteration allocation count under the
   instrumented allocator (§4) is **< 0.5 allocations per iteration
   averaged over 10 000 iterations.**

2. **< 0.5 is the literal "zero" threshold.** It accounts for:
   - Tokio's internal task-wakeup slab (off-path reuse) occasionally
     tripping fresh allocation when a slab grows.
   - `tracing` events emitted at `trace!` / `debug!` that the release
     filter drops but still build metadata. We allow the debug-level
     instrumentation in release binaries (it is load-bearing for
     troubleshooting); a once-per-thousand allocation from it is not a
     hot-path failure.
   - `metrics` counter encoding inside `Statistics::tx_tcp()` etc., if
     any path ever allocates.

   If the average is ≥ 0.5 across the 10k sample, it is not "zero" by
   this ADR and M2 does not exit on the affected row. Review is
   mandatory, not the tolerance.

3. **Per-path budget, not program-wide.** A NAT entry creation that
   allocates is fine (HP-2 out-of-scope). A rule-provider refresh that
   allocates 10 MiB every 10 minutes is fine (not on HP-1/2/3).

4. **No byte-count threshold.** Counting bytes is fragile across
   allocator versions. The count of `GlobalAlloc::alloc` calls is the
   right signal: if you're making them, you have work to do. If you're
   not, bytes are not the metric.

### 4. Instrumentation: `dhat-rs` as the audit tool, custom counter for CI

Two-phase measurement:

**Phase A (audit, engineer-a task during M2 work).**

Use [`dhat-rs`](https://docs.rs/dhat/) with its heap profiler backend
against a reproducer binary that exercises each HP in a tight loop:

- `dhat::Profiler::new_heap()` at reproducer start.
- Warmup per §3.
- Measured section: run 10 000 iterations, capture
  `dhat::HeapStats::total_blocks` delta.
- Assert the delta against the §3 rule (per-path, warmup-filtered).

Reproducer binaries live under `crates/meow-tunnel/tests/alloc_audit/*`
(HP-1 TCP relay), `crates/meow-proxy/tests/alloc_audit/*` (HP-2 UDP NAT
via direct adapter), and `crates/meow-rules/benches/alloc_rulematch.rs`
(HP-3 — same binary as ADR-0006 W5 with `dhat` feature).

dhat output (`dhat-heap.json`) is attached to the M2-exit release as
`alloc-audit-<path>.json` for audit trail.

**Phase B (regression guardrail, qa Task #26).**

`dhat` is too heavy to run on every CI build. Phase B uses a lightweight
custom counter: a wrapping `GlobalAlloc` (feature-flagged `audit-alloc`,
off by default) that increments an `AtomicU64` on every `alloc` /
`alloc_zeroed` / `realloc`. Reproducer binaries from Phase A are
re-runnable with `--features audit-alloc` and produce a single
allocations-per-iteration number.

qa's regression guardrail runs these reproducers in CI on every PR
labelled `perf` and fails the job if any HP counter exceeds the §3
threshold. Unlike perf regression (ADR-0006 §6), this IS a hard CI gate
— an allocation on the hot path has no noise story, it's deterministic.

### 5. What the audit does NOT require

- **No syscall-level malloc probe** (`perf probe malloc`, `bpftrace`). dhat
  and the custom counter already count every `GlobalAlloc` call; going
  kernel-side adds no information.
- **No valgrind / heaptrack**. They're heavier and do not run on musl out
  of the box. dhat is enough.
- **No continuous benchmarking**. Same rationale as ADR-0006 §6: we audit
  at release and after any PR labelled `perf`. Not on every merge.

### 6. Findings handling — the M1 baseline may not pass

This ADR lands before the audit is done. The M1 tip might fail §3 on any
or all three HPs.

**Known M1-tip HP-2 failure (engineer-a findings 2026-04-18).**

`crates/meow-tunnel/src/udp.rs:30` does:

```rust
let key = format!("{}:{}", src, metadata.remote_address());
```

…on **every UDP packet**, including the fast-path lookup branch. The
NAT table (`pub type NatTable = Arc<DashMap<String, Arc<UdpSession>>>;`
at line 14) is keyed by `String`, so every `get()` and every insert
allocates. At any non-trivial UDP throughput this is a textbook HP-2
failure.

Fix direction (engineer-a picks concrete shape during Task #31):

- Option A: change `NatTable` key to `(SocketAddr, SocketAddr)` tuple.
  Zero-alloc, matches the data; requires `DashMap` key trait confirmation
  — `SocketAddr` implements `Hash + Eq + Clone + Send + Sync` so this is
  straightforward. Downside: `metadata.remote_address()` returns a
  `String` today (the dst portion); that needs a `SocketAddr`-returning
  sibling or a cached parse at metadata build-time.
- Option B: keep the String key but intern via
  `Arc<str>` cached per connection. Saves re-allocation on every packet
  of the same flow. Doesn't help first-packet or insert path; strictly
  worse than A.

**Option A is strongly preferred.** Option B is the fallback only if
Metadata restructure is scoped out of M2. If A reveals scope creep
beyond M2, amend §3 to tolerate HP-2 at a higher threshold with a
linked M3 follow-up, per the rules below.

Likely HP-3 hazards to audit first: `maxminddb`'s internal allocations
on GEOIP lookup, and any `to_string()` / `format!` inside rule-name
formatting in the match path. DOMAIN-SUFFIX trie traversal should
already be zero-alloc.

If audit shows M1 tip is not at zero:

1. Engineer-a files a perf-lane task per HP with the measured baseline.
2. Optimisation work lands against that task. Typical moves:
   - Reuse a per-connection read buffer rather than `Vec::new()` per
     iteration.
   - Pre-allocate NAT-session `SmallVec` storage at entry creation.
   - Audit `maxminddb` allocations; upstream fix or fork if hot.
3. If any HP cannot hit §3 in reasonable M2 timebox, **the ADR amends
   the threshold for that HP** with a justification — do not silently
   ship "zero-ish". Example amendment:
   > HP-1 steady-state count tolerated at ≤ 1.5 alloc/iter due to
   > `maxminddb` MMDB page-fault allocation on first lookup per thread.
   > Justification: [link to issue], timeline: M3 upstream fix.

A failed audit does not fail M2 on its own — a documented, ADR-amended
tolerance does. A silent acceptance of non-zero is blocked.

### 7. Divergence classification (per ADR-0002)

Upstream Go mihomo has no allocator audit discipline. No Class A/B rows
apply — the audit is a meow-rs-only concern.

### 8. "Adding a new hot-path feature" checklist

Future feature PRs that touch HP-1, HP-2, or HP-3 code include:

- [ ] Reviewer confirms whether the feature is on the hot path or
      amortised to connection-setup / interval refresh.
- [ ] If on the hot path: PR includes an alloc-audit run (`dhat`
      reproducer or `audit-alloc` counter) before and after the change.
- [ ] If the change adds allocations, the PR either lands with a
      buffer-reuse pattern or opens an amendment to this ADR.
- [ ] Rule-match feature (new rule type) ALSO updates ADR-0006 W5
      reproducer to exercise it.

No new ADR per feature — this one is authoritative for "what counts as
zero" and "how we measure".

## Consequences

### Positive

- **Vision-level claim becomes testable.** Anyone can run the Phase B
  reproducer and see the number.
- **CI catches a per-packet allocation** the day it lands, not six months
  later when a user reports RSS growth.
- **W5 in ADR-0006 is no longer hand-wavy.** "0 allocations per match"
  points here for its definition.
- **Allocator is unified.** Bench perf (ADR-0006), footprint
  (ADR-0007), and audit (this ADR) all sit on `mimalloc`; numbers are
  comparable across the three.

### Negative / risks

- **`dhat` is an allocator wrapper.** It serialises every allocation;
  Phase A runs are 5–10× slower wall-time. Acceptable for an audit
  binary, not for the perf benchmark harness (which runs without dhat).
- **Custom `audit-alloc` counter adds an `AtomicU64` increment to every
  alloc in `audit-alloc`-feature builds.** Release builds are unaffected
  (feature off). CI guard builds pay it; they aren't perf-sensitive.
- **The 0.5 threshold is somewhat generous.** Defensible — see §3
  rationale. If profiling shows a cleaner path exists, tighten in an
  amendment.
- **dhat on musl.** Works, but requires a static link dance. Engineer-a
  may prefer running Phase A audits on glibc and the CI guard
  (`audit-alloc` custom counter) on musl. Acceptable — the `GlobalAlloc`
  counter is allocator-agnostic.
- **Per-feature-PR alloc-audit burden.** Small teams resent it.
  Discipline is the only reason the audit stays green over years.

### Neutral

- **No arena allocators in M2.** Recorded.
- **No `#[no_alloc]` macros or compile-time checks.** Rust's ecosystem
  doesn't have a reliable one. Phase B counter is the enforcement.

## Alternatives considered

### A.1 — "Measure once, publish, move on" (no ongoing guard)

**Rejected.** The whole point is to keep the property. One-shot audits
rot within two release cycles.

### A.2 — Use `heaptrack` or `bytehound`

**Rejected.** Both are heavyweight, Linux-only, and cover more than we
need. dhat-rs integrates into the Rust test crate directly and outputs
JSON we can attach to releases.

### A.3 — Target "< 1 allocation per iteration" as "zero"

**Rejected** in favour of `< 0.5`. At 1.0 an off-path allocation
amortised over workload-average iterations could still pass with an
entire per-iteration allocation hiding in the mean. 0.5 forces the
per-iteration allocation to be genuinely amortised across hundreds of
iterations (i.e. a growable cache, not a fresh allocation).

### A.4 — Target literally zero (`< 1 over 10k iterations`)

**Rejected.** Too tight against tokio's task-slab growth, `tracing`
metadata, and `mimalloc` segment growth during warmup transitions. A
one-off cache growth in the middle of a long run would fail the gate
with no actionable fix. 0.5 is the right contract.

### A.5 — Alloc-gating via linker `--wrap`

Replace `malloc` at link time with an asserting shim, fail the process
on any hot-path alloc. **Rejected.** Tooling complexity; same result as
the GlobalAlloc counter with more moving parts.

### A.6 — Custom arena allocator per-connection

The Go runtime has escape analysis; Rust has SmallVec and pooling. **Deferred**
to M3 per §2. M2 gets zero-alloc on the three HPs via `mimalloc` + careful
buffer-reuse; M3 can flatten further if profiling demands.

## Migration

1. **Workspace change** (engineer-b, can overlap with ADR-0007
   release-profile patch): add `mimalloc = { version = "...", default-
   features = false, features = ["override"] }` to `meow-app`, bind
   `#[global_allocator]` behind a default-on feature `alloc-mimalloc`.
2. **Reproducers** (engineer-a): Phase A alloc audit binaries per HP.
   Measures M1 tip, records in `docs/benchmarks/alloc-baseline.md`.
3. **CI hook** (qa Task #26): Phase B `audit-alloc` custom counter, hard
   gate on PRs labelled `perf`.
4. **Amendment** (if needed): if M1 tip does not pass §3, engineer-a
   opens an amendment PR *before* engineer-a starts the optimisation
   work, so the "what we're fixing" is in ADR form.

**Landed adjustment (PR #912):** step 1 shipped with different posture
than written — recording the as-built contract so the ADR stays honest:

- `alloc-mimalloc` exists as the named feature, but the allocator is
  **always on for musl targets** (non-optional dep) and **opt-in via the
  feature on other Linux/Android** — not the default-on, single-gate
  shape described above. Rationale: the motivating defect (freed-page
  churn-ratchet, observed 305 MB RSS over 20 h on a musl gateway) is
  musl's allocator, so musl builds carry the fix unconditionally; glibc
  already returns freed memory, so the swap stays a deployment choice
  there. The default-on question for the M2 measurement substrate
  remains open pending M2 benchmarks.
- `features = ["v2"]`, not `["override"]`: libmimalloc-sys 0.1.49+
  vendors mimalloc v3.3.x, which carries a multi-threaded
  heap-corruption SIGSEGV (microsoft/mimalloc#1287). `override` is also
  deliberately off — on musl static links it collides with musl's own
  `malloc` symbol (microsoft/mimalloc#243), so C deps (BoringSSL) keep
  the platform allocator and only the Rust heap moves.
- `dhat-heap` still wins when both features are enabled (profiling must
  measure the system allocator).

No user-visible change from this ADR alone.

## Open questions deferred

- **jemalloc musl link story.** Engineer-b investigates in M2; if
  mimalloc causes binary-size regressions on mipsel beyond ADR-0007
  caps, evaluate a mipsel-only allocator swap.
- **Per-thread caching of `maxminddb` MMDB lookups.** If the audit
  surfaces MMDB as an HP-3 allocation source, architect decides whether
  to fix upstream, fork, or live with a §6 amendment.
- **UDP NAT eviction under memory pressure.** Not in scope for M2
  alloc audit (entry eviction is not HP-2 steady state); M3 concern.

## References

- `docs/roadmap.md` §M2 item 2 — pinned by this ADR.
- `docs/vision.md` §M2 goal 3.
- [ADR-0006](0006-m2-benchmark-methodology.md) §5 W5 row — "0 allocations
  per match" is defined here.
- [ADR-0007](0007-m2-footprint-budget.md) §3 — allocator choice is
  consistent here and there.
- `crates/meow-tunnel/src/tcp.rs` — where HP-1 inner loop lives
  (the wrapper around `tokio::io::copy_bidirectional`).
- `crates/meow-tunnel/src/udp.rs` — HP-2 target path; line 30 is
  the known-failing `format!` call (§6).
- `crates/meow-rules/src/rule_set.rs` — HP-3 target path.
- `dhat-rs` crate docs — Phase A instrumentation.
