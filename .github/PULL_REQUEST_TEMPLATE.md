<!--
Thanks for contributing! Please read CONTRIBUTING.md before opening this PR:
https://github.com/meow-rs/meow-rs/blob/main/CONTRIBUTING.md
-->

## Summary

<!-- What does this PR change, and why? Link the issue it closes, if any. -->

Closes #

## Scope check

- [ ] This is a **client-side** change. It does not add server-mode features (protocol servers for remote clients, user/quota management, or anything meant to run meow-rs on the server end of a tunnel).
- [ ] New config keys / behaviour follow **mihomo mainline** (same keys, formats, defaults). Upstream reference: <!-- link to the mihomo code or docs -->
- [ ] Any deliberate divergence from mihomo is classified and documented per [ADR-0002](https://github.com/meow-rs/meow-rs/blob/main/docs/adr/0002-upstream-divergence-policy.md).

## ADR compliance

- [ ] This change does not contradict an ADR in `docs/adr/`, **or** this PR updates / supersedes the affected ADR.
- [ ] If it touches `Metadata`, `ConnectionInfo`, `UdpSession`, or the DNS cache entries: before/after byte counts from `-Zprint-type-sizes` are in the commit body (ADR-0011).
- [ ] If it touches relay code (`relay.rs`, `tcp.rs`, or their `meow-listener` call sites): relay buffers stay stack-allocated and hot-path allocation counts do not increase (ADR-0008).

## Verification

<!-- Paste the commands you ran and their result. All of the following must pass locally. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo clippy --all-targets --no-default-features -- -D warnings`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
- [ ] The full "Unit + integration tests (default features)" target list from `CONTRIBUTING.md` (not just `cargo test --lib`)
- [ ] Protocol-specific suites for the areas touched (Shadowsocks, Hysteria2/Snell Docker, AnyTLS, transport feature-gated, tproxy QEMU), if applicable
- [ ] New behaviour has a test that fails before this change and passes after it
- [ ] `CHANGELOG.md` updated for user-visible changes
