# CI Status Report

Last updated: 2026-09-18 (owner: qa)

## Current CI Pipelines

Nine GitHub Actions workflows live under `.github/workflows/`:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `test.yml` | `push` / `pull_request` touching code, Cargo files, tests, or workflows | Required build, lint, test, feature, MSRV, macOS, and TProxy gates |
| `audit.yml` | Weekly cron, lockfile/workflow changes, manual dispatch | RustSec advisory audit |
| `coverage.yml` | Scheduled/manual coverage run | Workspace coverage signal |
| `bench-daily.yml` | Scheduled/manual benchmark run | Daily benchmark trend artifact |
| `feature-powerset-daily.yml` | Scheduled feature-matrix run | Deeper cargo-hack feature powersets |
| `toolchain-drift.yml` | Weekly cron, manual dispatch | Floating-stable lint canary for the `rust-toolchain.toml` pin |
| `release.yml` | `v*` tags and manual dispatch | Static Linux release artifacts via `cargo-zigbuild` |
| `publish.yml` | `v*` tags | crates.io publishing |
| `pages.yml` | Pushes to `main` affecting `docs/` | GitHub Pages deployment for docs |

## `test.yml`

`test.yml` is the PR gate. It is path-filtered to code, test, Cargo,
`rust-toolchain.toml`, and workflow changes; docs-only PRs do not run it
unless workflow files are touched.

### `lint`

Runs first on Ubuntu (on the `rust-toolchain.toml` pin, not floating
stable):

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo clippy --all-targets --no-default-features -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`

### `test`

Runs on Ubuntu after `lint`:

- Installs/caches `ssserver` and installs `simple-obfs`; missing integration
  binaries are treated as failures, not silent skips.
- Builds all tests with `cargo build --tests`.
- Runs workspace unit tests plus integration suites for common types, DNS cache
  and upstream parsing, config parsing/persistence, statistics, rules,
  Shadowsocks, API, systemd config, Trojan, Hysteria2 Docker, Snell Docker,
  v2ray-plugin, pre-resolve DNS, transport TLS/WS/gRPC/H2/HTTPUpgrade,
  transport crate invariants, VLESS config/integration, VLESS feature matrix,
  and DNS encrypted feature matrix.

### `features`

Runs on Ubuntu after `lint`:

- Installs `cargo-hack`.
- Runs feature-powerset checks (`--feature-powerset --depth 2 --no-dev-deps`)
  for `meow-transport`, `meow-proxy`, `meow-listener`, and `meow-dns`: the
  empty set, every single feature, and every pair — capped at depth 2 so the
  leg count stays ~n^2 instead of ~2^n per PR.
- Excludes `boring-tls` from the `meow-transport` powerset because it is a
  no-op alias of `tls` — the duplicate leg is skipped; the broader transport
  matrix still covers the normal feature combinations.
- Deeper combinations run nightly in
  `.github/workflows/feature-powerset-daily.yml` instead of on every PR: up to
  4-feature combos for `meow-proxy` and `meow-transport`, and fully
  exhaustive powersets for `meow-listener` and `meow-dns` — depths chosen so
  each crate fits a hosted runner's 360-minute job cap with margin.

### `msrv`

Runs on Ubuntu after `lint`:

- Reads the workspace `rust-version` from `Cargo.toml`.
- Installs that exact toolchain, then sets a directory `rustup override` —
  the checkout's `rust-toolchain.toml` pin would otherwise outrank
  `rustup default` and the check would silently run on the pin.
- Runs `cargo check --workspace --all-targets`.

### `macos`

Runs on `macos-latest` after `lint`:

- `cargo build --tests`
- `cargo test --lib`
- Cross-platform integration smoke tests: common types, config, rules, API,
  DNS cache, config persistence, statistics, Trojan, v2ray-plugin, and
  pre-resolve DNS.

### `tproxy`

Runs on Ubuntu after `lint`:

- `bash tests/test_tproxy_docker.sh`
- Builds a Docker test image and exercises the transparent-proxy listener
  end-to-end with nftables.

## What Is Tested Today

| Area | Location | In CI? |
|------|----------|--------|
| Formatting | `cargo fmt --all -- --check` | Yes |
| Clippy default/all/no-default features | `cargo clippy --all-targets ...` | Yes |
| Rustdoc links/warnings | `cargo doc --workspace --no-deps` with `-D warnings` | Yes |
| Workspace unit tests | `cargo test --lib` | Yes (Ubuntu + macOS) |
| Rule matching | `crates/meow-rules/tests/rules_test.rs` | Yes (Ubuntu + macOS) |
| REST API | `crates/meow-api/tests/api_test.rs` | Yes (Ubuntu + macOS) |
| Config parsing/persistence | `crates/meow-config/tests/` | Yes |
| DNS cache/upstream parser | `crates/meow-dns` tests | Yes |
| Shadowsocks + simple-obfs | `crates/meow-proxy/tests/shadowsocks_integration.rs` | Yes (Ubuntu) |
| Trojan protocol | `crates/meow-proxy/tests/trojan_integration.rs` | Yes (Ubuntu + macOS) |
| Hysteria2 Docker integration | `crates/meow-proxy/tests/hysteria2_integration.rs` | Yes (Ubuntu) |
| Snell Docker integration | `crates/meow-proxy/tests/snell_server_docker_integration.rs` | Yes (Ubuntu) |
| v2ray-plugin integration | `crates/meow-proxy/tests/v2ray_plugin_integration.rs` | Yes (Ubuntu + macOS) |
| VLESS parser/integration | `crates/meow-config/tests/vless_config_test.rs`, `vless_integration` | Yes |
| Transport layers | `meow-transport` TLS/WS/gRPC/H2/HTTPUpgrade tests | Yes |
| Feature powersets | `cargo hack check` for transport/proxy/listener crates | Yes |
| TProxy e2e | `tests/test_tproxy_docker.sh` | Yes (Ubuntu Docker) |
| MSRV | Workspace `rust-version` | Yes |
| Dependency advisories | `audit.yml` | Yes |
| Coverage | `coverage.yml` | Scheduled/manual |
| Benchmarks | `bench-daily.yml` | Scheduled/manual |
| Release artifacts | `release.yml` | Tags/manual |

## Known Gaps

- Docs-only PRs do not trigger `test.yml`; run local doc sanity checks for
  Markdown and links before publishing docs-only changes.
- `pages.yml` deploys the whole `docs/` tree. Keep internal planning notes
  clearly labeled as archived or planning-only when they remain in `docs/`.
