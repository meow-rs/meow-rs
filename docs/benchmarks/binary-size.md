# Binary size benchmarks

ADR: [ADR-0007](../adr/0007-m2-footprint-budget.md)

## Measurement methodology

```bash
# Build stripped minimal binary for a musl target
cargo zigbuild --release --locked \
  --no-default-features --features minimal \
  --target aarch64-unknown-linux-musl \
  --bin meow
# Binary already stripped by profile (strip = true); on CI use llvm-strip for ELF.
wc -c < target/aarch64-unknown-linux-musl/release/meow
```

Release profile: `lto = fat, strip = true, codegen-units = 1, panic = abort, opt-level = "z"`
(panic=abort added in M2.E per ADR-0007 §3; opt-level=z + mimalloc added in M2.E final pass.)

Feature set measured:
- **default**: `cargo build --release` (`full` bundle: ss, trojan, vless, dns-server, all listeners)
- **minimal**: `--no-default-features --features minimal`
  (`ss + trojan + dns-server + listener-mixed`)

## Size budgets (ADR-0007 §2)

| Target | Feature set | Budget | Gate |
|--------|------------|--------|------|
| `aarch64-unknown-linux-musl` | minimal | ≤ 8.5 MiB (8,912,896 B)¹ | **hard** (CI fails) |
| `mipsel-unknown-linux-musl` | minimal | ≤ 7 MiB (7,340,032 B) | **soft** (CI warns) |
| `x86_64-unknown-linux-musl` | minimal | — | informational |

¹ 8 MiB (8,388,608 B) until ADR-0007 amendment A1 (2026-10-27); the
measurements below were taken against that budget.

## Measurements

### Final (M2.E complete: mimalloc + opt-level=z + panic=abort)

Measured 2026-04-18 on macOS/Apple Silicon cross-compiling with cargo-zigbuild + zig 0.15.2.
**Note:** macOS `strip` cannot process ELF binaries; sizes reflect the `strip = true`
profile setting applied during cross-compilation. Linux CI with zig 0.13.0 may differ
slightly (typically ±2%).

| Target | Feature set | Stripped size | Budget | Status |
|--------|------------|---------------|--------|--------|
| `aarch64-unknown-linux-musl` | default (full) | 6,371,432 B (~6.07 MiB) | ≤ 20 MiB | ✓ |
| `aarch64-unknown-linux-musl` | minimal | 6,272,040 B (~5.98 MiB) | ≤ 8 MiB | **✓ under budget** |
| `x86_64-unknown-linux-musl` | default (full) | 7,788,120 B (~7.43 MiB) | ≤ 20 MiB | ✓ |
| `x86_64-unknown-linux-musl` | minimal | 7,659,928 B (~7.31 MiB) | — | informational |
| `mipsel-unknown-linux-musl` | default (full) | not measured (no macOS rustup target) | ≤ 20 MiB | — |
| `mipsel-unknown-linux-musl` | minimal | not measured | ≤ 7 MiB | — |

### Minimal vs default delta

| Target | Default | Minimal | Saved | Notes |
|--------|---------|---------|-------|-------|
| `aarch64` | 6.07 MiB | 5.98 MiB | ~100 KB | vless + relay + h2/grpc/httpupgrade excluded |

### Historical progression (aarch64 minimal)

| Profile state | Size | vs 8 MiB budget |
|--------------|------|-----------------|
| panic=abort only | 9,987,832 B (~9.5 MiB) | –1.1 MiB over |
| + opt-level="z" + mimalloc | 6,272,040 B (~5.98 MiB) | **+2.0 MiB headroom** |

The ~3.5 MiB saving came primarily from opt-level="z" (code size optimisation) and
mimalloc replacing the musl system allocator (eliminates heavy glibc-emulation code).

## Analysis

The aarch64 minimal binary is now ~5.98 MiB — **2 MiB under the 8 MiB hard budget** (ADR-0007 §2).
All three levers (panic=abort, opt-level=z, mimalloc) are applied and shipped as part of M2.E.

### Perf impact of opt-level=z (engineer-a validation, 2026-04-18)

ADR-0006 thresholds are relative to Go — engineer-a ran opt-3 vs opt-z comparisons:

| Benchmark | opt-level=3 | opt-level=z | delta | ADR-0006 |
|-----------|-------------|-------------|-------|----------|
| W1 4 KB throughput | 0.84 Gbps | 0.70 Gbps | −17% | needs Go comparison |
| W1 64 MB throughput | 6.64 Gbps | 6.30 Gbps | −5% | acceptable |
| W2 p99 latency | 471 µs | 489 µs | +4% | passes (well within ≤1.05× Go) |
| W5 rule-match n=10k | ~45 µs | ~44 µs | same | passes (>>20M evals/s) |
| W5 rule-match n=500 | 1.36 µs | 3.92 µs | 2.9× | absolute <4 µs, passes |

**Verdict**: W2 and W5 pass ADR-0006 cleanly. W1 4 KB small-packet path shows −17% vs opt-3;
ADR-0006 threshold for W1 is ≥1.10× Go throughput — cannot confirm pass/fail without a Go
reference run. The regression is in CPU-bound per-packet overhead; bulk transfer (64 MB) is
only −5%. `opt-level = "s"` is an available middle ground if the small-packet regression
becomes a reported issue in production.

**Fallback**: if W1 4 KB vs Go fails ADR-0006, change `opt-level = "z"` → `"s"` in the
release profile — expected to recover inlining budget while retaining most of the size win.

## Post-mux (#412 stack, issue #426)

Measured 2026-08-19 at commit `3b57478` (main tip after PRs #414–#418, the
`sing-mux` client-side multiplexer for SS/VMess/VLESS/Trojan plus Xray
Mux.Cool). Cross-compiled on macOS/Apple Silicon with cargo-zigbuild + zig
0.13.0, same release profile as above (`lto=fat, strip=true,
codegen-units=1, panic=abort, opt-level="z"`, mimalloc allocator). `mux` is
in the `full` bundle (`meow-app/Cargo.toml`), so it is part of every
`default` build; it is excluded from `minimal` by design (ADR-0007 §1) and
that profile is unaffected.

**mipsel-unknown-linux-musl still not measured, different reason now**:
#421 (`mux` used `std::sync::atomic::AtomicU64` directly instead of
`meow_common::atomic::AtomicU`) was fixed by #447, so the compile-time
blocker is gone — `crates/meow-proxy/src/mux/` now uses
`meow_common::atomic::AtomicU` exclusively (verified: no raw `AtomicU64`
remains under `mux/`). But the target still cannot be measured with this
repo's established method (`cargo zigbuild --release --target
mipsel-unknown-linux-musl`, same as the other targets in this doc):
`mipsel-unknown-linux-musl` is a **Tier 3** target
([rustc platform support](https://doc.rust-lang.org/rustc/platform-support.html)) —
rustup ships no prebuilt `std` for it on any host:

```
$ rustup target add mipsel-unknown-linux-musl
error: toolchain 'stable-aarch64-apple-darwin' has no prebuilt artifacts
available for target 'mipsel-unknown-linux-musl'
note: this may happen to a low-tier target as per
https://doc.rust-lang.org/nightly/rustc/platform-support.html
note: you can find instructions on that page to build the target support
from source
```

The only way to produce a `std`-linked binary for this target at all is
`-Zbuild-std` on nightly (confirmed locally: `cargo +nightly zigbuild
-Zbuild-std=std,panic_abort --release --target mipsel-unknown-linux-musl`
does start compiling `core`/`alloc`/`std` from source). That is a
materially different build — different toolchain (nightly vs. the
workspace's pinned stable), different compiler flags, and a locally-built
`std` rather than the distributed one — so a size measured that way
would not be comparable to the zigbuild+stable numbers for the other
targets in this table, and it is not this repo's established
cross-compile method (see `docs/adr/0007-m2-footprint-budget.md` §"Single-
target CI runners"). Per that ADR, mipsel is explicitly **soft-gated**
for exactly this reason ("no mipsel cross-compile infra ... and no way to
functionally validate a mipsel binary"), and CI's own `release.yml`
release matrix does not build MIPS at all (excluded together with 32-bit
musl and windows-gnu because they can't link `boring-sys`, which is part
of the shipped `default` feature set). So this is not a regression from
#412/mux or from this follow-up — mipsel `default`-profile size has never
been measured end-to-end via the documented method, #421 only removed one
blocker among several. Leaving this row `not measured` (status: toolchain
gap, not a compile failure) rather than reporting a nightly-`build-std`
number that would use a different build recipe than every other row in
this document.

### `default` profile — absolute size vs. cap

| Target | Stripped size (mux on) | Cap (ADR-0007 §2) | Headroom | Status |
|--------|------------------------|--------------------|----------|--------|
| `aarch64-unknown-linux-musl` | 11,196,256 B (~10.68 MiB) | 18 MiB (18,874,368 B) | 7,678,112 B (~7.32 MiB), 59.3% used | ✓ under cap |
| `x86_64-unknown-linux-musl` | 14,238,600 B (~13.58 MiB) | 20 MiB (20,971,520 B) | 6,732,920 B (~6.42 MiB), 67.9% used | ✓ under cap |
| `mipsel-unknown-linux-musl` | not measured (Tier 3 toolchain gap, not #421 — see above) | 16 MiB (16,777,216 B) | — | — |

No cap is breached or threatened on the two measured targets; **no
ADR-0007 amendment is required** for this change (ADR-0007 §6 only
requires an amendment when a feature pushes a cap past its current
value). The mipsel cap remains unverified either way — it was unverified
before this follow-up (blocked by #421) and remains unverified now
(blocked by the Tier 3 toolchain gap above), so this follow-up cannot
say whether the soft-gated mipsel cap holds; ADR-0007 already accounts
for this ("no way to functionally validate a mipsel binary" at M2) and
defers a hard gate to M3.

### Mux-attributable delta (mux on vs. mux off, same commit)

To isolate what the #412 stack itself costs — as opposed to the ~4 months of
unrelated feature growth since the last recorded `default` measurement below
— both targets were also built with every `full` feature except `mux`
(`--no-default-features --features
ss,trojan,vless,vless-vision,vless-encryption,vmess,snell,hysteria2,anytls,ech-tls-tunnel,dns-server,dns-encrypted,listener-http,listener-socks5,listener-tproxy,listener-mixed,listener-tun,boring-tls`),
same commit, same release profile:

| Target | mux off | mux on | Mux delta |
|--------|---------|--------|-----------|
| `aarch64-unknown-linux-musl` | 11,018,768 B (~10.51 MiB) | 11,196,256 B (~10.68 MiB) | +177,488 B (~173 KiB, +1.6%) |
| `x86_64-unknown-linux-musl` | 14,010,968 B (~13.36 MiB) | 14,238,600 B (~13.58 MiB) | +227,632 B (~222 KiB, +1.6%) |

The `mux` module itself (~5.5 kLoC across `crates/meow-proxy/src/mux/`) adds
well under 1 MiB on both hard-gated targets — small relative to the caps'
headroom. The genuinely new dependencies are `yamux` 0.14,
`nohash-hasher`, and `static_assertions` (`tokio-util` and `h2` were already
transitive deps of the axum/hyper/tonic stack before #412, confirmed via
`git diff d50e6f6..3b57478 -- Cargo.lock`).

### Delta vs. last recorded `default` baseline (2026-04-18, above)

| Target | 2026-04-18 `default` | 2026-08-19 `default` (post-mux) | Delta | % |
|--------|----------------------|----------------------------------|-------|---|
| `aarch64-unknown-linux-musl` | 6,371,432 B (~6.07 MiB) | 11,196,256 B (~10.68 MiB) | +4,824,824 B | +75.7% |
| `x86_64-unknown-linux-musl` | 7,788,120 B (~7.43 MiB) | 14,238,600 B (~13.58 MiB) | +6,450,480 B | +82.8% |

This total delta is **not** attributable to mux — per the isolated
measurement above, mux is only ~173–222 KiB of it. The remainder comes from
everything else that landed on `default` between April and August 2026
(VLESS Vision/Encryption, VMess, Snell, Hysteria2, AnyTLS, the
`ech-tls-tunnel` bundle, `dns-encrypted`, `listener-tun`, and notably
`boring-tls` joining the `default` feature set for REALITY/uTLS — issue
#377 — which statically links BoringSSL and is a much larger single
contributor than mux). None of those were measured against `default` at
the time they landed either; this section only closes the mux-specific gap
that issue #426 asked for. A follow-up audit to re-baseline `default` size
against the full feature history is out of scope here.
