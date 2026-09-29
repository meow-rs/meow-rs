# Contributing to meow-rs

Thanks for your interest in meow-rs. This document describes the project's
scope and the bar every pull request has to meet. Please read it before
opening a PR; it saves review round-trips for both sides.

## Scope: meow-rs is a client-only proxy kernel

meow-rs is a Rust implementation of the [mihomo](https://github.com/MetaCubeX/mihomo)
(Clash Meta) **client** kernel. It terminates connections from local
applications (via SOCKS5/HTTP/mixed listeners, transparent proxy, or TUN),
routes them by rule, and dials **remote** proxy servers over the supported
outbound protocols.

**Server-side features are out of scope and will not be merged.** That
includes, for example:

- Outbound protocol *servers* intended to serve remote clients (a Trojan,
  VLESS, VMess, Hysteria2, AnyTLS, or similar server mode).
- Server management, user/quota accounting, or multi-tenant features.
- Anything whose primary purpose is to run meow-rs on the *server* end of a
  tunnel.

What *is* in scope:

- Inbound listeners that accept traffic from local applications or LAN
  devices (SOCKS5, HTTP, mixed, Shadowsocks inbound, TProxy, TUN). These
  exist so that other clients on the same machine or network can use meow-rs
  as their gateway, not so meow-rs can act as a public proxy server.
- Embedded servers used only by the test suite, such as the Trojan mock
  server in `tests/` or the server half of the vendored `meow-anytls` crate
  that the AnyTLS integration test spawns. These exist to make tests
  hermetic and must not be wired into the `meow` binary or its config.

If you are unsure whether a feature is client-side, open an issue first and
describe the use case.

## Follow mihomo mainline for features and config

meow-rs aims for configuration compatibility with real-world Clash Meta
subscriptions: a user's existing `config.yaml` should load, parse, and route
the same way it does in mihomo.

When adding a new feature, proxy type, rule type, or config option:

- **Match the mihomo mainline config schema.** Use the same keys, the same
  value formats, and the same defaults as upstream mihomo. Do not invent
  meow-rs-specific spellings for things mihomo already has a name for.
- **Prefer features that exist in mihomo mainline** (the `Alpha`/`Meta`
  branches of MetaCubeX/mihomo). A feature that only exists in a fork, or
  that mihomo has deprecated, needs a strong justification.
- **Diverge only deliberately.** Where meow-rs intentionally behaves
  differently from mihomo (for security or to avoid silent misrouting),
  the divergence must be classified and documented per
  [ADR-0002: Upstream divergence policy](docs/adr/0002-upstream-divergence-policy.md).
  Link the relevant upstream code or docs in the PR so reviewers can compare.

## Every PR must pass the full test bar

CI runs the checks in `.github/workflows/test.yml`. Run the same set locally
before pushing; a PR that is red on any of them will not be reviewed until it
is green.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo test -p meow-listener --all-features --lib udp_port_53

# Mirrors the "Unit + integration tests (default features)" CI step.
cargo test --lib --bin meow \
  --test socks5_udp_user \
  --test common_test --test dns_cache_test --test config_test \
  --test statistics_test --test rules_test --test api_test \
  --test raii_guard_test --test http_connection_close \
  --test config_persistence_test --test systemd_config_test \
  --test trojan_integration --test vless_config_test --test vless_integration \
  --test v2ray_plugin_integration --test pre_resolve_test \
  --test tls_test --test boring_tls_test --test ws_test --test crate_invariants_test \
  --test crate_publish_metadata_test
```

Notes:

- `cargo test --lib` alone is **not** enough: it skips every `--test` target,
  so a broken integration test passes locally and lands `main` red.
- Protocol-specific suites (Shadowsocks with `ssserver`, Hysteria2 and Snell
  under Docker, AnyTLS, the transport feature-gated tests, and the tproxy Docker
  test) also run in CI. If your change touches one of those areas, run the
  matching suite locally as well; see the [Testing](README.md#testing) section
  of the README for the commands.
- Add tests for new behaviour. A feature or bug fix without a test that fails
  before the change and passes after it is unlikely to be merged.
- Keep the target list in `CLAUDE.md` in sync with `test.yml` when you add a
  new `tests/` file.

## Follow the ADRs

Architecture decisions are recorded in [`docs/adr/`](docs/adr/). They are
binding: a PR that contradicts an accepted ADR must either update that ADR
(or add a superseding one) in the same PR, or include a measured
justification in the commit body. The ones contributors most often run into:

| ADR | What it constrains |
|-----|--------------------|
| [0001](docs/adr/0001-meow-transport-crate.md) | `meow-transport` stays protocol-agnostic with no dependency on other meow-rs crates |
| [0002](docs/adr/0002-upstream-divergence-policy.md) | How and when to diverge from mihomo behaviour |
| [0006](docs/adr/0006-m2-benchmark-methodology.md) / [0011](docs/adr/0011-m2-footprint-targets.md) | Throughput, latency, and key-type struct-size targets; byte deltas required in the commit body when touching `Metadata`, `ConnectionInfo`, `UdpSession`, or the DNS cache entries |
| [0007](docs/adr/0007-m2-footprint-budget.md) | Stripped binary size caps per profile and target |
| [0008](docs/adr/0008-m2-allocator-audit.md) | Hot-path allocation counts never increase; relay buffers stay stack-allocated |
| [0009](docs/adr/0009-cleanup-scope.md) | Crate-boundary policy for the workspace |
| [0010](docs/adr/0010-m1-hygiene-and-gates.md) | The curated clippy lint set and the three-way clippy gate |

The `CLAUDE.md` at the repo root summarises the architecture invariants and
the regression bar; it is a good quick reference even if you are not using an
AI assistant.

## Workflow

- Branch from `main`; never push directly to it. Use descriptive branch names
  such as `feat/…`, `fix/…`, or `docs/…`.
- Keep PRs focused. One feature or fix per PR makes review and bisecting
  practical.
- Use conventional commit subjects (`fix(dns): …`, `feat(proxy): …`,
  `docs: …`) and explain *why* in the body, not just what.
- Update `CHANGELOG.md` for user-visible changes.
- No silent lint suppressions: use
  `#[allow(clippy::lint_name, reason = "…")]` with a real reason.

## License

By contributing you agree that your contributions are licensed under the
project's [MIT license](LICENSE).
