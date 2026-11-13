# meow-wireguard

Vendored copy of the WireGuard Noise implementation from
[cloudflare/boringtun](https://github.com/cloudflare/boringtun) `v0.7.1`,
published as part of the meow-rs workspace at the shared workspace version.

## Why it's vendored

The `boringtun` crate on crates.io drives its Noise handshake and transport
crypto through `ring`. meow-rs keeps a single crypto back end — BoringSSL for
TLS plus the workspace RustCrypto/dalek crates — so a second TLS/crypto
provider pulled in transitively would duplicate primitives and bloat the
binary (ADR-0007). Vendoring the `noise` module in-tree lets `src/crypto.rs`
replace every `ring` call with `x25519-dalek`, `blake2`,
`chacha20poly1305`/`aead`, `rand_core` and `subtle`, all already in the
workspace lockfile.

`PATCHES.md` records the ordered patch list to replay when the vendored
snapshot is bumped; `UPSTREAM` names the exact upstream ref. Only `src/noise`
(and its `sleepyinstant` helper) is vendored — upstream's `device`, `ffi`
and `jni` modules are intentionally omitted.

## Layout

- `src/noise/` — upstream `boringtun::noise` verbatim except for the patched
  callsites listed in `PATCHES.md` (handshake, session, timers, rate limiter).
- `src/crypto.rs` — the ring-free facade: X25519 DH, BLAKE2s hash/MAC/KDF,
  ChaCha20-Poly1305 AEAD and a constant-time equality helper.
- `src/sleepyinstant/`, `src/mock_instant.rs` — upstream's clock abstraction;
  `mock-instant` swaps in the test clock for the vendored timer tests.
- The package is `meow-wireguard` and the library `meow_wireguard`; meow-proxy
  pulls it in only under the `wireguard` feature.

## License

BSD-3-Clause (see `LICENSE`), unchanged from upstream boringtun.
