# ADR 0009 — Cleanup-2026-05 scope and policy

- Status: Accepted
- Date: 2026-05-12
- Authors: architect (team `mihomo-cleanup`)
- Branch: `refactor/cleanup-2026-05`
- Supersedes: none. Related: [ADR-0002 upstream-divergence-policy](0002-upstream-divergence-policy.md).

## Context

The `mihomo-cleanup` team is executing a three-milestone whole-project cleanup
(`M0` prune → `M1` hygiene → `M2` refactor) tracked under tasks `#1/#2/#3` with
this ADR scoped to `M0`. Two facts surface up front:

1. **CLAUDE.md is stale.** It lists 10 workspace crates. The real manifest
   (`Cargo.toml`) has **12**: the missing entries are `meow-transport` and
   `meow-bench`. CLAUDE.md must be patched as part of M0 closeout (see
   subtask "docs-claudemd"), and the lead's M0.1 brief which said "11 crates"
   is also off-by-one.
2. **The baseline is cleaner than expected.** `cargo build --workspace
   --all-targets` with default features produces **0 warnings**; with
   `--all-features` also **0 warnings**. The real signal lives in two places:
   - `cargo machete` finds **35 unused workspace deps across 10 of 12 crates**
     (full table in §"Findings" below). Each was verified by `grep` against
     `src/` — false-positive count is zero on default features.
   - `cargo check --workspace --no-default-features` surfaces **3 dead
     functions and 1 unused import** that are invisible at default-feature
     compilation. These are real and must be either re-gated or removed.

Holding the regression bar at every milestone boundary
(`cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings &&
cargo test --lib` + integration suites + tproxy Docker script) is non-negotiable.

## Decision

### What counts as "dead" (in scope for removal in M0)

1. **Unused `[dependencies]` entries.** A workspace dep is dead iff `cargo
   machete --with-metadata` reports it AND a `grep -rEn "use <name>|<name>::"`
   against the crate's `src/` (and feature-gated cfgs, and `build.rs`) finds
   zero non-comment, non-string references on **any** feature combination
   that compiles. The dep is removed from `Cargo.toml`; if it was only
   pulled in for tests, it moves to `[dev-dependencies]`.
2. **Unused functions / items** flagged by rustc `dead_code` under **any**
   feature combination the workspace supports, where the item is not part of
   a documented public API surface (re-exported from `lib.rs` or referenced
   in an ADR). Pre-existing `#[allow(dead_code)]` suppressions
   (`meow-listener/src/socks5.rs:14`,
   `meow-proxy/src/vless/vision.rs:74,89`,
   `meow-proxy/src/vless/header.rs:53`,
   `meow-config/src/lib.rs:1020`) get re-evaluated: each must be removed
   or accompanied by a comment justifying why the item stays.
3. **Unused imports** flagged under non-default features (e.g. the
   `TransportChain` import in `vless_integration.rs` under
   `--no-default-features`). Fix by `#[cfg(feature=…)]`-gating either the
   import or the test module.
4. **`cargo-machete` ignore-list noise.** Any `[package.metadata.cargo-machete]
   ignored = […]` entries added during M0 require an inline comment naming the
   feature gate or build-script reason they're a false positive.

### What stays (out of scope for M0)

- **Public API surface stability.** M0 holds the public API of every crate
  constant. Any removal of a `pub` item re-exported from a `lib.rs` is **out
  of scope** and deferred to M2. The four `#[allow(dead_code)]` items above
  fall in this bucket — they can be re-gated under `#[cfg(test)]` or feature
  cfgs but **not deleted** in M0.
- **Module reorganisation.** Renaming, moving, or splitting modules is M2
  work (task #3). M0 edits stay within a single file's `Cargo.toml` or
  `.rs` body where possible.
- **Behavioural changes.** No proxy/DNS/listener semantics may change in M0.
  The Docker tproxy script and the `trojan_integration` / `rules_test` /
  `shadowsocks_integration` test suites must all stay green at M0 close.

### Public-API stability stance

- **M0 (this milestone): no breaks.** Crates' `pub use` re-exports stay
  byte-identical. The 0.6.x semver line is held.
- **M1 (clippy + style): no breaks.** Lint-driven refactors stay
  observationally equivalent.
- **M2 (refactor): breaks allowed with a dedicated ADR.** Each removed
  public item gets cited in an M2 ADR with rationale and downstream impact
  (the bench/app binaries plus integration tests are the consumers).

### Methodology

For each crate the engineer:

1. Runs `cargo check -p <crate> --no-default-features` and
   `cargo check -p <crate> --all-features`, capturing both warning lists.
2. Applies the per-crate dep prune (subtask list below) on the
   `refactor/cleanup-2026-05` branch (no separate branches per crate —
   single linear history under that branch).
3. Re-runs `cargo machete` against the crate; expects zero hits.
4. Runs the regression bar locally before pushing.

### Cross-crate ripples to watch

- **`meow-app` removing `meow-common` / `meow-proxy` deps**: these are
  only listed transitively; the binary doesn't import them directly. Removal
  is safe but rebuild order in `cargo check -p meow-app` should be
  re-verified after the Cargo.lock churn.
- **`meow-dns` machete hits (`hickory-server`, `async-trait`, …)** are
  *probably* feature-gated false positives — `hickory-server` is
  `optional = true` behind `dep:hickory-server`. The engineer must confirm
  with `cargo check -p meow-dns --features dns-server` before removing
  any of these; expect to instead add a `[package.metadata.cargo-machete]
  ignored = […]` entry with a comment naming the feature.
- **`meow-listener` `meow-dns` dep**: zero `src/` refs; safe to remove,
  but verify against `--no-default-features --features listener-tproxy`
  (tproxy historically pulled DNS for hostname resolution before the
  Tunnel-driven refactor).
- **`meow-transport` `meow-common` dep**: crate-boundary invariants in
  `transport/src/lib.rs:14-19` explicitly forbid meow-common (transport
  must stay protocol-agnostic). The dep is safe to remove and *should* be —
  its presence violates the documented invariant.

## Findings — `cargo machete --with-metadata` (2026-05-12)

| Crate              | Unused deps to investigate                                                                       | Notes |
|--------------------|--------------------------------------------------------------------------------------------------|-------|
| `meow-common`    | `uuid`                                                                                           | 0 src refs; remove |
| `meow-transport` | `meow-common`                                                                                  | violates documented invariant; remove |
| `meow-proxy`     | `anyhow`, `dashmap`, `futures-util`, `http`, `regex`, `reqwest`, `serde`, `thiserror`, `tokio-tungstenite` | all 9 confirmed zero src refs (`anyhow` only in comments, `http` was `http_adapter` substring) |
| `meow-tunnel`    | `bytes`, `serde_json`, `thiserror`                                                               | 0 src refs each; remove |
| `meow-listener`  | `anyhow`, `bytes`, `futures`, `meow-dns`, `thiserror`                                          | 0 src refs each; tproxy edge case noted above |
| `meow-rules`     | `serde`                                                                                          | 0 src refs (no derives); remove |
| `meow-config`    | `serde_json`, `subtle`, `thiserror`                                                              | 0 src refs each; remove |
| `meow-api`       | `arc-swap`, `thiserror`                                                                          | 0 src refs each; ADR-0003 declared arc-swap usage — verify if planned-but-unused or to-be-wired |
| `meow-dns`       | `anyhow`, `async-trait`, `hickory-proto`, `hickory-server`, `serde`                              | several are feature-gated; expect machete ignore-list entries, not removals |
| `meow-app`       | `meow-common`, `meow-proxy`                                                                  | only transitively wired; safe to remove |

`meow-trie` and `meow-bench` have **no** machete hits.

## Dead-code (under `--no-default-features`)

- `crates/meow-proxy/src/lib.rs:56` — `fn transport_to_proxy_err` —
  helper unreachable without `ss` or `trojan` or `vless`. Decision:
  gate behind `#[cfg(any(feature="ss", feature="trojan", feature="vless"))]`.
- `crates/meow-config/src/proxy_parser.rs:689` — `fn parse_uuid` —
  used only by `vless`. Gate behind `#[cfg(feature="vless")]`.
- `crates/meow-config/src/proxy_parser.rs:710` — `fn serialize_plugin_opts` —
  used only by `ss` (v2ray-plugin). Gate behind `#[cfg(feature="ss")]`.
- `crates/meow-proxy/tests/vless_integration.rs:14` — `use … TransportChain`
  warning under `--no-default-features`. Gate the entire test file behind
  `#![cfg(feature="vless")]`. Same treatment owed to `trojan_integration`,
  `shadowsocks_integration`, `v2ray_plugin_integration` (their compile errors
  under `--no-default-features` are the same class of bug — tests not gated
  on the protocol feature they exercise).

## Consequences

- 35 dep entries leave their `Cargo.toml` files, with corresponding
  `Cargo.lock` churn. CI cache invalidates once.
- Compilation time on `--no-default-features` measurably improves (no
  longer pulling shadowsocks-stack for transport-only consumers).
- Several `#[cfg]` attributes appear on test files and helper fns;
  contributors must run `--no-default-features` checks before claiming a
  feature gate works.
- M2 (task #3) inherits the four `#[allow(dead_code)]` exceptions as
  candidates for genuine removal once API breaks become permissible.

## References

- `cargo machete --with-metadata` output, 2026-05-12
- `cargo check --workspace --no-default-features --all-targets`, same date
- [ADR-0001 meow-transport-crate](0001-meow-transport-crate.md) — the
  boundary invariant cited above
- [ADR-0002 upstream-divergence-policy](0002-upstream-divergence-policy.md)
- CLAUDE.md (note: pending update to list `meow-transport`/`meow-bench`)
