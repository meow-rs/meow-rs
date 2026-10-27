# Spec: Cargo feature flags + minimal-build size budget (M2)

Status: Draft (2026-04-18, updated with ADR-0007 decisions)
Owner: engineer-b
Tracks roadmap item: **M2** (Cargo feature flags, minimal-build)
Lane: engineer-b (footprint + infra chain)
ADR: [`docs/adr/0007-m2-footprint-budget.md`](../adr/0007-m2-footprint-budget.md)
Upstream reference: Go mihomo uses build tags; not directly applicable to Rust.
This is a meow-rs capability, not a parity feature.

## Motivation

`vision.md` §Goals item 3: "aggressive feature-gating so builds for embedded
targets (mipsel, aarch64 musl) stay small."

**Engineer-b finding:** `cargo build --no-default-features` currently produces
the same ~11 MB binary as the default build because SS, Direct, Reject, and
`hickory-server` are unconditionally compiled in (not behind any feature gate).
The actual work in M2.E is making these optional — the feature flag infra doesn't
exist yet.

## Feature flag taxonomy

### Protocol features (proposed; all default-on in the `full` bundle)

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `ss` | `meow-proxy` | Shadowsocks adapter + `shadowsocks` crate dep |
| `trojan` | `meow-proxy` | Trojan adapter (TLS via `meow-transport`'s `tls` layer) |
| `vless` | `meow-proxy` | VLESS adapter (M1.B-2) |
| `http-outbound` | `meow-proxy` | HTTP CONNECT outbound |
| `socks5-outbound` | `meow-proxy` | SOCKS5 outbound |
| `load-balance` | `meow-proxy` | Load-balance group |
| `relay` | `meow-proxy` | Relay group |

### Transport features

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `transport-tls` | `meow-transport` | TLS layer (BoringSSL; `boring-tls` is a no-op alias) |
| `transport-ws` | `meow-transport` | WebSocket layer |
| `transport-grpc` | `meow-transport` | gRPC/gun layer |
| `transport-h2` | `meow-transport` | H2 + HTTP-upgrade layers |

### Inbound features

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `listener-http` | `meow-listener` | HTTP proxy inbound |
| `listener-socks5` | `meow-listener` | SOCKS5 inbound |
| `listener-tproxy` | `meow-listener` | TProxy (nftables/pf); Linux/macOS only |
| `listener-mixed` | `meow-listener` | Mixed (HTTP+SOCKS5) inbound |

### DNS features

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `dns-server` | `meow-dns` | `hickory-server` DNS server dep (currently unconditional) |

### Convenience bundles (workspace root)

| Bundle | Includes |
|--------|---------|
| `full` (default) | all features above |
| `minimal` | `ss`, `trojan`, `transport-tls`, `transport-ws`, `listener-mixed`, `dns-server` — REST API always included (not optional) |

**ADR-0007 §1 defines `minimal` as `tls,ws,ss,trojan,api`** — the "minimum useful set
for a router operator." Dropping TLS would exclude SS+v2ray-plugin+TLS+ws, the
dominant modern transport pairing for ~95% of router users. Do NOT remove `transport-tls`
or `transport-ws` from the minimal bundle to chase a smaller binary; revisit in M3
after profiling real operator usage.

## Load-bearing deps that must become conditional

Engineer-b found these are currently unconditional but must be feature-gated to
achieve the size budget:

| Dep | Currently in | Proposal |
|-----|-------------|---------|
| `shadowsocks` crate | `meow-proxy/Cargo.toml` unconditional | gate on `ss` feature |
| `hickory-server` | `meow-dns/Cargo.toml` unconditional | gate on `dns-server` feature; `minimal` includes it |
| Direct + Reject adapters | compiled unconditionally | leave unconditional — they are load-bearing stubs with near-zero size |

Direct and Reject have negligible binary contribution; do not add feature-gating
overhead for them.

## Size budget

Per ADR-0007 §2 (confirmed). Target = stripped binary, no UPX, `minimal` feature set:

| Target | Default build | Minimal build | Gate |
|--------|--------------|---------------|------|
| `aarch64-unknown-linux-musl` | ≤ 20 MiB | ≤ 8.5 MiB | **hard** — release fails if exceeded |
| `mipsel-unknown-linux-musl` | ≤ 20 MiB | ≤ 7 MiB | **soft** — release emits warning, does not fail |
| `x86_64-unknown-linux-musl` | ≤ 20 MiB | not gated | informational only |

**Budget rationale (ADR-0007 §2):**
- mipsel 7 MiB: common legacy mipsel router flash is 16 MiB with ~6–8 MiB free
  after OpenWRT base; 7 MiB fits with overlayfs + config + logs.
- aarch64 8 MiB: ~8% codegen headroom vs mipsel; aarch64 routers have ≥ 64 MiB
  storage, leaving room for one additional small-protocol addition before amendment.
  Raised to 8.5 MiB by ADR-0007 amendment A1 (2026-10-27) after the YAML backend
  migration.
- Default 16–20 MiB: no hard cap on full builds today; track via informational step.

**Step 0 prerequisite (ADR-0007 §Migration step 0):** these budgets are only
meaningful after engineer-b completes the feature-gating work that makes `ss`,
`trojan`, `transport-tls`, `transport-ws`, `hickory-server` conditional. Do NOT
add the CI size-check step until the gating compiles without errors — a 11 MiB
"minimal" build that ignores features is a false gate.

**Downward amendments** are welcome: if the real post-gating measurement on the
reference host is below budget (e.g., 6.2 MiB mipsel), open a one-paragraph
amendment PR to tighten the cap. We commit to the upper bound now; tightening
costs nothing.

Measure with:

```bash
cargo zigbuild --release --no-default-features --features minimal \
  --target aarch64-unknown-linux-musl --bin meow
llvm-strip target/aarch64-unknown-linux-musl/release/meow
ls -lh target/aarch64-unknown-linux-musl/release/meow
```

Use `cargo bloat --release --crates` to identify the largest contributors if the
budget is missed.

## Release CI integration

- Add a `minimal-size-check` step to `release.yml` after the existing build step:
  build with `--no-default-features --features minimal`, strip, measure size, fail
  if over budget.
- See `ci-quality-gates.md` §Release matrix expansion for the mipsel-musl target
  addition.

## Divergences from upstream

None — new capability.

## Acceptance criteria

1. `cargo build --no-default-features --features minimal --target aarch64-unknown-linux-musl`
   compiles without errors.
2. Stripped minimal binary for `aarch64-musl` is ≤ 8.5 MiB (hard gate — CI fails if exceeded).
3. Stripped minimal binary for `mipsel-musl` is ≤ 7 MiB (soft gate — CI emits warning, does not fail).
4. `cargo test --lib` passes for both `full` (default) and `minimal` feature sets.
5. `cargo hack --feature-powerset check` passes for `meow-proxy`,
   `meow-transport`, `meow-listener`, and `meow-dns` (wired in ci-quality-gates.md).
6. Binary sizes documented in `docs/benchmarks/binary-size.md`.
7. Step 0 prerequisite satisfied: `--no-default-features --features minimal` produces a
   meaningfully smaller binary than default before any CI gate is added.

## Implementation checklist (engineer-b handoff)

- [ ] Audit `meow-proxy/Cargo.toml`: add feature gates for `ss`, `trojan`, `vless`,
      `http-outbound`, `socks5-outbound`, `load-balance`, `relay`.
- [ ] Audit `meow-transport/Cargo.toml`: add `transport-*` feature gates.
- [ ] Audit `meow-listener/Cargo.toml`: add `listener-*` feature gates.
- [ ] Audit `meow-dns/Cargo.toml`: gate `hickory-server` dep on `dns-server` feature.
- [ ] Define `full` (default) and `minimal` bundle features at workspace root
      (`Cargo.toml` `[features]` table).
- [ ] Update `meow-app/src/main.rs`: conditionally register only enabled adapters
      and listeners using `#[cfg(feature = "...")]`.
- [ ] Add `minimal-size-check` step to `release.yml` (parameterize budget from
      env var so architect-2's numbers can be dropped in without spec edit).
- [ ] Measure stripped sizes for both targets; document in `docs/benchmarks/binary-size.md`.
- [ ] **Wait for architect-2 Task #25** before hard-coding size thresholds in CI.
