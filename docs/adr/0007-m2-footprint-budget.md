# ADR 0007: M2 footprint budget — per-target binary-size caps

- **Status:** Proposed (architect 2026-04-18, awaiting pm + engineer-b review)
- **Date:** 2026-04-18
- **Author:** architect
- **Supersedes:** —
- **Related:** roadmap §M2 items 3 (feature flags + minimal build) and 5
  (release CI), vision §M2 goal 3 ("single static binary, minimal runtime
  allocations… aggressive feature-gating"),
  [ADR-0001](0001-meow-transport-crate.md) (feature-gating scheme),
  [ADR-0006](0006-m2-benchmark-methodology.md) (also includes a default-build
  size threshold vs Go),
  [ADR-0008](0008-m2-allocator-audit.md) (allocator choice affects binary size)

## Context

`docs/vision.md` promises "Small footprint. Single static binary… aggressive
feature-gating so builds for embedded targets (mipsel, aarch64 musl) stay
small." `docs/roadmap.md` §M2 item 3 translates that into:

> Cargo feature flags for every optional protocol/transport; minimal-build
> size budget for `aarch64-musl` and `mipsel-musl`.

M1 landed the plumbing (ADR-0001's `meow-transport` feature set, per-crate
Cargo features in every optional protocol). What's missing is the **budget**:
a concrete byte count per (target, feature-profile) that the release CI
enforces.

Without numbers, "feature flags" means only "flags exist". A user running on
a 16 MB / 32 MB flash router has no way to tell whether meow-rs fits
and the team has no target to tune against. Same unfalsifiability problem
as ADR-0006's perf claim.

The concrete decisions this ADR settles:

1. Which **build profiles** do we publish — which sets of Cargo features
   define "minimal" and "default"?
2. Which **targets** have per-profile size caps — not all four Cargo `std`
   targets carry equal weight.
3. What are the **byte values** of those caps?
4. How is the cap **measured** — stripped? LTO? panic=abort? `opt-level="z"`?
5. How is the cap **enforced** — CI gate, and what happens on overrun?
6. How is the cap **amended** over time — new features grow size; what is
   the re-baseline process?

## Decision

### 1. Two build profiles, two hard-gated targets + one soft target

meow-rs releases in M2 publish **four hard-gated binaries** —
`{minimal, default} × {aarch64-linux-musl, x86_64-linux-musl}` — and
**two soft-gated binaries** on `mipsel-linux-musl` (measured and
published, not release-blocking). See §4 for what hard vs soft means.

**M1-tip reality check (engineer-b findings 2026-04-18).**

Current `cargo build --release --no-default-features` produces the SAME
~11 MiB aarch64 binary as `--release` with defaults. Reason: SS, Direct,
Reject, rustls, and hickory-server are unconditionally compiled — no
Cargo feature gates exist around them. So "minimal build" is **not
defined in the shippable tree today**; the §2 caps below are the
**post-gating** targets, not a current measurement.

This means the §2 targets are unreachable without prerequisite work (see
§Migration step 0). The ADR commits to the numbers; engineer-b commits
to the gating that makes them reachable. If gating work reveals a number
is the wrong target, a §6 amendment adjusts the ADR, not the ambition.

**Profile: `minimal`** — the embedded-router build.

Feature set (intentionally tight; not every optional protocol):

```
--no-default-features --features "tls,ws,ss,trojan,api"
```

Rationale for the minimal feature list:

- `tls + ws + ss + trojan` — the SS+v2ray-plugin+Trojan story that shipped
  before M1. Users on cheap routers run this pairing.
- `api` — REST API + web dashboard. Without it the embedded operator
  cannot see what the binary is doing. Non-negotiable.
- **No** `grpc`, `h2`, `httpupgrade`, `vless`, `http-outbound`, `socks-outbound`,
  `sniffer`, `ech`, `utls`, `boring-tls`, `load-balance`, `relay`, `geosite`,
  `proxy-providers`, `metrics`, `geodata-autoupdate`. These are for users who
  can afford the size. Users who want them switch to the `default` binary.
- **No** DNS DoH/DoT (they pull `hickory-resolver` + rustls client for
  upstream). DNS UDP + hosts file only.

**Profile: `default`** — the desktop / VPS build.

Feature set: whatever `cargo build --release` emits with default features.
This is the "everything reasonable is on" binary that matches the typical
Clash Meta install (`tls,ws,grpc,h2,httpupgrade,vless,...`). The feature list
is defined by `meow-app/Cargo.toml`'s `[features] default = [...]`, not
here — this ADR freezes the *budget*, not the *contents* of the default set.

**Targets — why two hard, one soft:**

| Target | Gate class | Rationale |
|--------|------------|-----------|
| `aarch64-unknown-linux-musl` | **hard** | Modern routers + SBCs (EdgeRouter, RPi 4+, Mikrotik CCR). Biggest user base outside x86. |
| `x86_64-unknown-linux-musl` | **hard** | VPS + desktop Linux. Reference target for all perf work in ADR-0006. |
| `mipsel-unknown-linux-musl` | **soft** | Legacy MIPS routers (OpenWRT, budget boxes). Tightest-budget target, but no mipsel cross-compile infra at M1 tip and no QEMU smoke-test runner. CI measures and publishes size; overrun warns, does NOT block the release. Fully hard-gated in M3 if an operator asks. |

Not shipping in M2 (explicitly): `armv7-musl` (covered by aarch64 for M2
priorities), `mips-musl` (big-endian is vanishing), Windows,
macOS-universal, any glibc target. Those are future releases.

**Amendment — `armv7-musl` now ships** (PR #744, 2026-10).
`armv7-unknown-linux-musleabihf` is built and published as a static musl
binary. The M2 reason above was prioritization, but the "cannot be built
with TLS at all" note in `build.yml` did hold for the `cargo zigbuild`
path: musl 1.2.x headers declare `time_t` 64-bit on 32-bit targets
(time64/Y2038) while Rust's `libc` crate types it as `i32`, so bindgen
emits 64-bit signatures and `boring` fails to compile (E0308) — and
zig-linked static armv7 binaries were unreliable under QEMU in testing.
A real musl cross toolchain container builds the target statically; the
same time64-vs-`libc` disagreement there is bridged by a one-line cast in
`boring` (`meow-rs` never calls `set_time`). It carries no cap here —
`minimal_budget_bytes` is 0 (informational) until someone measures the
`minimal` feature set on it; if a cap is wanted, §6 applies as usual.

**Why mipsel is soft for M2:** roadmap §M2 item 3 names mipsel-musl
explicitly, but the current tree has zero mipsel build infrastructure
and no way to functionally validate a mipsel binary (no QEMU runner,
no CI cross-toolchain). Making mipsel a hard release-gate would block
every M2 release on an arch-specific rabbit hole that benefits a
shrinking user base (most new routers are aarch64). Publishing the
size and warning on overrun captures the spirit of the roadmap item
without taking a hard dependency. If the M2 soft number trends in the
right direction, M3 promotes mipsel to hard-gate with an ADR
amendment.

### 2. Byte budgets per (profile × target)

All values are **stripped binary file size** (`strip --strip-all` on Linux
targets) after release build with the workspace defaults from §3.

| Target | `minimal` cap | `default` cap |
|--------|--------------:|--------------:|
| `aarch64-unknown-linux-musl` | **8 MiB** (8 388 608 B) | **18 MiB** (18 874 368 B) |
| `mipsel-unknown-linux-musl` | **7 MiB** (7 340 032 B) | **16 MiB** (16 777 216 B) |
| `x86_64-unknown-linux-musl` | **8 MiB** (8 388 608 B) | **20 MiB** (20 971 520 B) |

Also: **default-build `x86_64-linux-musl` MUST be ≤ the current Go mihomo
release for the same target** (ADR-0006 §5 "Binary size" row — we ship one
binary; if ours is bigger we lost the small-footprint pitch). At M1 tip that
ceiling is ~23 MiB for Go's default binary; 20 MiB gives us ~3 MiB of
headroom across M2 feature growth.

**Rationale for the numbers (not pulled from thin air):**

- **mipsel `minimal` = 7 MiB.** The common legacy mipsel router flash is
  16 MiB with ~6–8 MiB free after the OpenWRT base. 7 MiB lets meow-rs
  fit with overlayfs + config + logs, matching the tightest real user target
  we have.
- **aarch64 `minimal` = 8 MiB.** Slightly looser — aarch64 codegen is ~8%
  fatter than mipsel on the same LLVM IR, and most aarch64 routers have
  ≥ 64 MiB storage. 8 MiB is headroom for one new small protocol in M2+
  without a budget amendment.
- **`default` = 16–20 MiB.** M1 current binary is ~14–17 MiB across
  x86_64 targets (engineer-b to measure and fill into
  `docs/benchmarks/hardware.md`). Budgets sit 10–20% above M1 tip to
  absorb M2 feature growth; any patch that bumps past the cap gets
  explicit ADR review.

Re-baseline process: if empirical M1-tip sizes are materially above these
caps on first measurement, engineer-b opens a one-paragraph amendment PR to
this ADR before M2 exit. We adjust once, not per-PR.

### 3. Build discipline — release profile settings

All size numbers assume the following `Cargo.toml` workspace release profile
(engineer-b's task to set at start of M2 measurement; these are the
standard "shrink Rust" knobs):

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = "symbols"           # strip on link — redundant with post-strip, cheap insurance
panic = "abort"             # removes unwind tables
overflow-checks = false
debug = false
```

Also required:

- `RUSTFLAGS="-C link-arg=-s"` (belt+suspenders strip for musl-cross).
- **Allocator:** `mimalloc` (ADR-0008 §2). Using the system allocator on musl
  makes binaries ~300 KiB smaller but loses the hot-path perf wins of
  ADR-0006. Pay the 300 KiB.
- **No `-Z build-std=panic_abort,std`**. That knob can shave another
  ~500 KiB but requires nightly Rust and is out of scope for an M2 release
  matrix. If mipsel `minimal` misses by < 500 KiB near M2 exit, engineer-b
  may enable it as an escape hatch after architect sign-off.

Post-build: `strip --strip-all` before size measurement. UPX compression
is not allowed (breaks `/proc/self/exe` on some kernels, flagged by antivirus
heuristics, hides the real binary size story).

### 4. CI enforcement — hard gate on aarch64/x86_64; soft on mipsel

Release workflow (the one that publishes artefacts) includes a step that,
per (profile, target) in §1:

1. Builds with the discipline in §3.
2. Runs `strip --strip-all`.
3. Measures file size in bytes.
4. Compares to the cap in §2.
5. Per target gate class:
   - **Hard targets (aarch64, x86_64):** on overrun, **fails the
     workflow** with:
     ```
     ERROR: binary size budget exceeded
     target=<t> profile=<p> actual=<n> cap=<c> overshoot=<n-c> bytes
     ```
     and aborts the release.
   - **Soft target (mipsel):** on overrun, emits the same message at
     `warning` level, records it in the release summary, and proceeds.

Binary size is cheap to measure deterministically — there is no noise to
false-positive on. A hard-target cap overrun is a real regression.
A soft-target overrun is a signal, not a block.

Per-PR CI also measures and posts for all three targets, but does NOT
fail the build (same as perf — feature PRs can carry temporary size
regressions that land after an optimisation PR follows).

### 5. Size attribution — `cargo-bloat` on every release

Release workflow also runs `cargo bloat --release --target <t>
--no-default-features --features <f>` for each (profile, target) and
attaches the output to the release as `bloat-<target>-<profile>.txt`. No
threshold; it's a forensic tool for the next person investigating a
regression.

### 6. Budget amendment process

A new protocol, transport, or feature that breaks a cap on a profile that
it should belong to (e.g. VLESS landing grows `default` by 800 KiB,
pushing aarch64 default-build over 18 MiB):

1. Feature PR author measures with and without the feature.
2. PR description includes the delta + which cap it threatens.
3. PR opens a companion amendment to this ADR (§2 table) with a
   one-paragraph justification and a new number.
4. Architect reviews the amendment before merging the feature.

A feature landing with no ADR amendment must not push any cap past its
current value. If it does, the PR is blocked at CI (§4) until the author
adds the amendment.

Budget *reduction* amendments (post-optimisation: "we can tighten mipsel
`minimal` to 6 MiB") are welcomed — they keep the headroom honest. Same
PR-and-amendment process.

### 7. Divergence classification (per ADR-0002)

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Minimal build omits DoH/DoT while Go mihomo's single binary includes them | — | Not a divergence — upstream has no "minimal" flavour at all. Feature set is our lever, not a behaviour change. |
| 2 | UPX compression — upstream Go mihomo does not, neither do we | — | Converged. No ADR row needed. |

No ADR-0002 rows apply — size policy doesn't affect user-visible behaviour
of a loaded config.

## Consequences

### Positive

- **Vision-level promise becomes checkable.** Anyone can run the release
  workflow against a tag and see whether footprint claim still holds.
- **Embedded users get a committed target.** mipsel `minimal` ≤ 7 MiB
  is a number a router OEM integration can budget against.
- **Regression is caught at tag time, not by an embedded user three
  weeks later.**
- **Feature PRs have a forcing function** to think about optional vs
  required. Adding to `default` is no longer free.

### Negative / risks

- **`panic = "abort"` removes unwind.** Any non-abort panic handling in
  `meow-api` (e.g. catch_unwind for per-request isolation) is blocked.
  Already ruled out by QA invariant (memory
  `feedback_api_no_catch_panic.md` — "no CatchPanic on meow-api
  router"), so this is consistent.
- **`lto = "fat"` lengthens release builds.** Maybe 3–6 minutes added on
  x86_64-linux-musl. Acceptable at release cadence; dev builds use
  default profile.
- **Feature-splitting matrix grows.** Six release binaries × test
  smoke-runs is more CI time. Constrain smoke-runs to one target per
  profile (the aarch64 pair) to keep it bounded.
- **Single-target CI runners.** mipsel cross-compile uses `cross`; the
  mipsel binary is NOT smoke-tested (no convenient QEMU in CI). Size
  measured only. Functional coverage relies on manual operator testing.
- **Go comparison reference drifts.** The "≤ current Go mihomo binary
  size" ceiling moves with upstream releases. Acceptable — re-baseline
  annually or when Go's number changes by > 10%.

### Neutral

- **No UPX.** Recorded so a future audit doesn't re-ask.
- **No `-Z build-std` by default.** Same.

## Alternatives considered

### A.1 — No per-target budget; just publish sizes

"Measure and publish, let users decide." **Rejected.** The vision says
"minimal-build under stated size budget". A published number with no
enforcement drifts within a release cycle — the M2 exit criterion
"minimal-build binary under stated size budget" becomes "under whatever
last week's build happened to be".

### A.2 — One-size-fits-all budget (single cap per profile, target-agnostic)

**Rejected.** mipsel's code density (no NEON, less efficient MIPS
calling conventions) is strictly different from aarch64's. A single
number either over-budgets mipsel or under-budgets aarch64.

### A.3 — Tighter caps, shoot for ~5 MiB `minimal`

**Rejected.** Empirical M1 tip is ~6.5 MiB mipsel minimal (per
engineer-b's scratch measurements; exact number on re-baseline). 5 MiB
would require dropping the REST API, which defeats "operational clarity"
(vision goal 4). We are not building a black box.

### A.4 — Publish only `default`, skip `minimal`

"Nobody asked for a router build." **Rejected.** Roadmap §M2 item 3
explicitly names mipsel/aarch64-musl. Users on embedded targets are a
specific, named vision constituency.

### A.5 — Soft caps (CI warns, doesn't fail)

**Rejected.** Binary size is deterministic; there is no false-positive
risk. Soft caps rot into "fail next release" every release.

### A.6 — Per-PR hard cap

Fail every PR that grows any cap. **Rejected.** Legitimate refactors
briefly grow size before a follow-up optimisation lands. Release-tag gate
is the right level (§4).

## Migration

Engineer-b (Task #28) executes:

0. **Prerequisite — feature-gate the unconditional deps** (engineer-b
   findings 2026-04-18). Today `--no-default-features` produces the same
   ~11 MiB aarch64 binary as the default build because SS, Direct, Reject,
   rustls (TLS), and hickory-server are unconditionally compiled. Before
   any §2 measurement is meaningful, add Cargo features for each:
   - `ss` (Shadowsocks + AEAD crates),
   - `trojan` (Trojan adapter — already partly gated via `meow-transport`),
   - `tls` (rustls + webpki + ALPN — may already exist via
     `meow-transport::tls`; verify),
   - `dns-server` (hickory-server; distinct from `dns-client` for DoH/DoT
     upstream, so a minimal build can keep the UDP server without pulling
     rustls into the resolver path),
   - `direct` and `reject` always-on is fine — they are trivial. No gate
     needed.
   The `minimal` profile of §1 composes these gates. Without this step,
   every §2 row is unreachable.
1. Set release profile in §3 in `Cargo.toml` workspace section. Run
   current-tip builds for all four hard (profile, target) pairs, record
   sizes in `docs/benchmarks/hardware.md`.
2. If any measurement exceeds §2 cap at M1 tip (after step 0 gating),
   open an amendment PR to this ADR with the real number +
   justification before M2 exit.
3. Wire the CI gate in §4 (hard for aarch64/x86_64; soft/warn for
   mipsel) + the `cargo-bloat` forensic output in §5.
4. Add mipsel `cross` target to CI build matrix (size measurement only,
   no runtime test). If mipsel cross-compile proves significantly
   difficult, defer the mipsel entries to M3 with an amendment PR —
   do not block M2 on mipsel toolchain work.

Feature-set tuning (which Cargo features belong to `minimal` vs
`default`) is per-crate engineer-b work in M2; the sets in §1 are the
architect commitment, the `Cargo.toml` flags are the implementation.

## Open questions deferred

- **Windows + macOS binary sizes.** Not in scope for M2 release matrix.
  Add a per-target row if M3 ships Windows/macOS artefacts.
- **Reproducible builds** (identical byte output across two machines).
  Nice-to-have; M3 ops-hardening concern, not M2 footprint.
- **Dynamic linking option** (bring-your-own-libc for glibc targets).
  We are explicitly static-musl in M2; revisit if a distro packager
  asks.

## References

- `docs/roadmap.md` §M2 items 3 + 5 — pinned by this ADR.
- `docs/vision.md` §M2 goal 3.
- [ADR-0001](0001-meow-transport-crate.md) §5 — the feature-flag
  scheme this ADR's profiles consume.
- [ADR-0006](0006-m2-benchmark-methodology.md) §5 — the default-build
  size row vs Go; this ADR's §2 absolute cap complements it.
- [ADR-0008](0008-m2-allocator-audit.md) §2 — allocator choice drives
  part of the §3 build discipline.
- `crates/meow-bench/src/bench_binary_size.rs` — existing
  file-size-via-`metadata().len()` measurement; reuse in CI gate.
- `docs/ci-status.md` — CI baseline this ADR's release workflow lands
  into.
