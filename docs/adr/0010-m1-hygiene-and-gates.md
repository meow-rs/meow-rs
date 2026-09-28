# ADR 0010 — M1 hygiene: lint set, no-default-features warnings, CI gates, test coverage

- Status: Accepted
- Date: 2026-05-12
- Authors: architect (team `mihomo-cleanup`)
- Branch: `refactor/cleanup-2026-05`
- Supersedes: none. Related: [ADR-0002](0002-upstream-divergence-policy.md),
  [ADR-0009](0009-cleanup-scope.md).

## Context

M0 (task #1) landed three commits: 35 deps pruned, four dead-but-feature-gated
items re-gated, a crate-boundary fix (`meow-transport` no longer depends on
`meow-common`), and CLAUDE.md updated to list all 12 crates. The default-
feature regression bar (`cargo fmt --all -- --check && cargo clippy --all-targets
-- -D warnings && cargo test --lib`) is green.

Two concrete diagnostics survive into M1:

1. **6 pre-existing warnings at `cargo check --workspace --no-default-features
   --all-targets`**, all unrelated to clippy:
   - `crates/meow-config/src/proxy_parser.rs:12` — `TransportChain` import
     unused without `vless` (its sole use is inside `parse_vless` at line 503).
   - `crates/meow-config/tests/ech_dns_test.rs:27,29` — `base64::Engine` and
     `meow_config::load_config_from_str` unused; this test exercises VLESS-
     ECH config parsing and only compiles meaningfully with `vless`.
   - `crates/meow-app/src/main.rs:516,517,523` — `sniffer_runtime`, `auth`,
     `addr` are dead when **all** listener features are off (each consumer is
     inside a `#[cfg(feature = "listener-*")]` block).
2. **Clippy at default features is clean (`-D warnings` passes), but no
   stricter lint group is enabled.** A `clippy::pedantic` probe surfaces 1079
   warnings; a curated subset of 12 lints surfaces 471. Most of those (291
   `uninlined_format_args`, 64 `redundant_closure`, 44 `redundant_clone`, 44
   `manual_let_else`) are mechanical fixes. Without a workspace-level lint
   config, new code can regress style without CI flagging it.

The workspace has **no** `[workspace.lints]` table; per-crate `Cargo.toml`
files have no `[lints]` table. Lint enforcement is currently command-line only.

Test coverage is uneven. Inline `#[test]` / `#[tokio::test]` counts and
integration files per crate:

| Crate              | src LOC | inline tests | integration files |
|--------------------|--------:|-------------:|------------------:|
| `meow-common`    |   1545  |          23  |                 1 |
| `meow-trie`      |    198  |           6  |                 0 |
| `meow-dns`       |   1966  |          47  |                 3 |
| `meow-rules`     |   4684  |         127  |                 1 |
| `meow-transport` |   2280  |           0  |                10 |
| `meow-proxy`     |   8643  |         149  |                 4 |
| `meow-tunnel`    |   1110  |           9  |                 2 |
| `meow-listener`  |   1878  |          15  |             **0** |
| `meow-api`       |   1832  |       **0**  |                 2 |
| `meow-config`    |   4949  |          72  |                 5 |
| `meow-app`       |    774  |       **0**  |                 1 |
| `meow-bench`     |   1013  |       **0**  |                 0 |

`meow-api`, `meow-listener`, `meow-app` are the three obvious gaps —
each is 700–1900 LOC of substantively branching code with effectively no
unit-test coverage. (`meow-bench` is excluded — it is an executable
harness whose "tests" are the bench runs themselves.)

## Decision

### 1. Workspace lint set

A single `[workspace.lints.clippy]` table in the root `Cargo.toml`, inherited
by every crate via `[lints] workspace = true` in each member `Cargo.toml`.

**Enabled at `warn` (denied via `-D warnings` in CI):**

| Lint                                 | Hits | Rationale |
|--------------------------------------|-----:|-----------|
| `uninlined_format_args`              |  291 | Mechanical, readability win, no semantic risk |
| `redundant_closure`                  |   64 | `.map(\|x\| f(x))` → `.map(f)`, eliminates an allocation |
| `redundant_clone`                    |   44 | Removes spurious `.clone()` on already-owned values |
| `manual_let_else`                    |   44 | `let Some(x) = … else { return }` clarity |
| `map_unwrap_or`                      |   15 | `.map(f).unwrap_or(d)` → `.map_or(d, f)` |
| `redundant_closure_for_method_calls` |  ~10 | `.map(\|x\| x.len())` → `.map(<str>::len)` |
| `semicolon_if_nothing_returned`      |   ~5 | Trailing-semi consistency in `()`-returning blocks |
| `explicit_iter_loop`                 |   ~5 | `for x in v.iter()` → `for x in &v` |
| `needless_pass_by_value`             |    6 | Function takes owned `T`, but body only borrows |
| `match_same_arms`                    |    7 | Genuine logic-collapse signal |
| `if_not_else`                        |   ~3 | `if !x { … } else { … }` → swap arms |
| `unnecessary_wraps`                  |    5 | `-> Result<T, E>` where every return is `Ok(_)` |
| `cloned_instead_of_copied`           |   ~3 | `.cloned()` on `&Copy` → `.copied()` |

**Selected from `clippy::pedantic` (warn-only, not enabled):**

The full `clippy::pedantic` group is **not** enabled. 1079 warnings, the vast
majority of which are either (a) style preferences the maintainers haven't
endorsed (`must_use_candidate` × 113, `missing_errors_doc` × 60,
`missing_panics_doc` × 18, `doc_markdown` × 119), or (b) genuine but
out-of-scope-for-M1 concerns (`cast_possible_truncation` × 40 +
`cast_possible_wrap` × 21 + `cast_precision_loss` × 16 — these need a
deliberate "we are intentionally truncating here" pass that is M2 work).
Re-evaluating pedantic adoption is filed as a follow-up for after M2 lands.

**`clippy::nursery`: not enabled.** Nursery lints are by definition
unstable. They may be revisited per-lint if a specific one proves valuable.

**`clippy::cargo`: not enabled in M1.** The relevant cargo lints
(`multiple_crate_versions`, `wildcard_dependencies`, `negative_feature_names`)
would surface duplicate-version churn (rustls / hyper / hickory) that is
upstream-driven and not actionable within a hygiene milestone. Defer to M2 if
a deps-consolidation effort becomes part of that scope.

**Allowed (explicit `#[allow]` in workspace.lints):**
- `clippy::module_name_repetitions` (would force renaming `proxy::ProxyAdapter`)
- `clippy::struct_excessive_bools` (config structs legitimately have many bool fields)
- `clippy::too_many_lines` (rule parser and proxy_parser are long by nature)
- `clippy::missing_errors_doc`, `clippy::missing_panics_doc` (docs scope is
  separate; tracked for later)

### 2. Fixing the 6 no-default-features warnings

Re-gate, not remove. Each is a real symbol that is exercised by a feature-
gated path; the warning is purely a missing `#[cfg]` on the import or
binding.

| Site                                              | Fix |
|---------------------------------------------------|-----|
| `proxy_parser.rs:10-13` import line             | Split `TransportChain` out of the unconditional `use meow_proxy::{…}` and re-import under `#[cfg(feature = "vless")]` (or move it into the import block right above the existing `#[cfg(feature = "vless")] use meow_proxy::{VlessAdapter, VlessFlow};`). |
| `tests/ech_dns_test.rs:27,29` imports           | Gate the **whole file** behind `#![cfg(feature = "vless")]`. It is an ECH-for-VLESS test; with `vless` off, it has nothing to exercise. Mirrors the M0 treatment of `vless_integration.rs` (ADR-0009 §"Dead-code"). |
| `main.rs:515-523` `sniffer_runtime/auth/addr` | Move the three bindings inside the `for nl in &config.listeners.named` loop, **into** the first arm that uses them (`ListenerType::Mixed \| Http \| Socks5`) under its existing `#[cfg(feature = "listener-mixed")]`. Same treatment for the other listener arms. The `addr` binding becomes a `let` inside each arm rather than at loop top. |

After these three edits, `cargo check --workspace --no-default-features
--all-targets` must report **0 warnings**. M1 makes this the new no-default-
features baseline and CI must enforce it.

### 3. CI gates

The regression bar is unchanged from M0, but **two additional invariants**
are added at M1 exit:

```
# existing (M0):
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --lib

# added (M1):
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
```

Plus the integration suites at milestone exit (unchanged):
`rules_test`, `trojan_integration`, `shadowsocks_integration`. tproxy Docker
remains CI-only.

**`cargo-deny`: deferred.** A `deny.toml` for license / advisory / duplicate
auditing is valuable but is its own design exercise (which licenses are
acceptable for an MIT project? what RUSTSEC IDs are exempted?). Filed as a
follow-up; out of scope for M1.

**`cargo-machete` in CI: yes.** M0 leaves the workspace at zero machete
hits. Adding `cargo install cargo-machete && cargo machete` to CI as a
non-fatal warning step keeps the regression bar honest. Wire it as part of
the M1 CI subtask.

### 4. Test coverage additions (Pareto pick)

Five high-value additions, scoped to fit in M1 alongside the lint pass:

1. **`meow-api` request-handler tests** (currently 0 inline tests on
   1832 LOC). Target the handlers in `src/handlers/proxies.rs` and
   `src/handlers/rules.rs`: build an `axum::Router` in a `#[tokio::test]`,
   send synthetic requests via `tower::ServiceExt::oneshot`, assert response
   shape. Aim for the 6–8 most-trafficked endpoints (list proxies, select
   proxy, list rules, query connections, traffic stream). **Not** an
   exhaustive API surface test — pareto pick.

2. **`meow-listener` per-listener acceptance tests** (currently 0
   integration files). Add `tests/socks5_handshake.rs`,
   `tests/http_connect.rs`, `tests/mixed_dispatch.rs`. Each binds to
   `127.0.0.1:0`, runs the listener against a `Tunnel` stub, and asserts
   protocol round-trip. Mirrors the structure of `meow-proxy/tests/`.

3. **`meow-app` config-loading smoke test** (currently 0 inline tests).
   A single `#[test]` that loads `examples/config.yaml` (or a fixture
   under `tests/fixtures/`) via the same `meow_config::load_config`
   path `main.rs` uses, asserting it produces a non-empty `Tunnel`-ready
   structure. Catches breakage from config-parser refactors before
   integration tests do.

4. **`meow-trie` property test for domain matching** (currently 6 tests
   on 198 LOC — small crate, but it's the hot path for rule matching).
   Add a `proptest`-based test: random domain string in/out of trie, the
   result is consistent with a naive `O(n*m)` substring-scan reference
   implementation. Catches subtle wildcard-edge bugs.

5. **`meow-tunnel` connection-statistics RAII test** (commit `0f95043`
   introduced an RAII guard for stats cleanup on aborted `handle_tcp`).
   Add a test that aborts a `handle_tcp` future mid-flight (via `select!`
   timeout) and asserts the stats entry is gone. Regression guard for
   the very fix that just landed.

Items 1–3 close the obvious "zero tests" cells in the inventory table.
Items 4–5 are targeted regression guards for hot-path and recent-fix
regions. This is **not** a coverage-percentage drive — it is five
specific tests with concrete preventive value.

### 5. Workspace lints wire-up

In root `Cargo.toml`:

```toml
[workspace.lints.clippy]
uninlined_format_args = "warn"
redundant_closure = "warn"
redundant_clone = "warn"
manual_let_else = "warn"
map_unwrap_or = "warn"
redundant_closure_for_method_calls = "warn"
semicolon_if_nothing_returned = "warn"
explicit_iter_loop = "warn"
needless_pass_by_value = "warn"
match_same_arms = "warn"
if_not_else = "warn"
unnecessary_wraps = "warn"
cloned_instead_of_copied = "warn"

# Explicit allows (rationale in ADR-0010):
module_name_repetitions = "allow"
struct_excessive_bools = "allow"
too_many_lines = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
```

In every member `crates/*/Cargo.toml`:

```toml
[lints]
workspace = true
```

This requires Rust 1.74+; the workspace MSRV is 1.89 and the repo toolchain
is pinned via `rust-toolchain.toml` — safe.

## Consequences

- ~471 clippy warnings need fixing across the workspace, broken into
  per-crate subtasks. Mechanical fixes via `cargo clippy --fix` for the
  format-args and closure-method-call lints; manual fixes for
  `manual_let_else`, `needless_pass_by_value`, `match_same_arms`.
- Public API of every crate stays observationally equivalent (ADR-0009
  §"Public-API stability stance" — M1 holds 0.6.x semver).
- CI runtime increases by ~2× (three clippy invocations instead of one).
  Acceptable; lint runs are cached.
- Five new test files / modules add ~600 LOC of test code. Test runtime
  increase expected <5 s.
- Future contributors get lint warnings inline in their IDE without
  needing to remember CLI flags. New code can't merge with these classes
  of style regression.
- Workspace becomes `lints.workspace = true`-aware; any crate added in
  the future must add the four-line `[lints] workspace = true` block.
  Documented in the CLAUDE.md "Adding new crates" section as part of the
  M1 docs subtask.

## References

- `cargo clippy --workspace --all-targets -- -W clippy::pedantic -A clippy::all`,
  2026-05-12 (1079 warnings; tally in §"Decision" §1)
- `cargo clippy …` with curated lint set above, 2026-05-12 (471 warnings)
- `cargo check --workspace --no-default-features --all-targets`, 2026-05-12
  (6 warnings; sites in §"Context")
- [ADR-0009 cleanup-scope](0009-cleanup-scope.md) — the M0/M1/M2 framing
- Commit `0f95043` — the RAII stats guard that motivates test #5
