# ECH + uTLS Fingerprint Initiative — Status

**Last updated:** 2026-09-20 — boring/tokio-boring 5.2 + quiche 0.30 (#572). Previous: 2026-04-25 — DNS-sourced ECH and ECH retry self-heal landed.
**Docs:** [design](ech-utls-design.md) · [test plan](ech-utls-test-plan.md)

---

## Summary

Encrypted Client Hello (ECH) and uTLS-style browser fingerprint spoofing are implemented in meow-rs's TLS transport via a new `boring-tls` cargo feature backed by BoringSSL (boring 5.2 + tokio-boring 5.2 since #572; the workspace sat on 4.22 while the published quiche still required `boring < 5`). Six fingerprint profiles ship, inline-config and DNS-sourced ECH both work end-to-end, ECH key rotation self-heals on `ech_required` rejection, and all C1–C16 tests pass against a real loopback BoringSSL server with a live ECH keypair.

---

## Scope

### In scope (v1)

- `boring-tls` cargo feature gate (optional at v1; on by default for `meow-app` since 0.20; a no-op alias of `tls` since the rustls backend was removed)
- `TlsBackend` enum dispatch (v1): boring activated when `fingerprint` or `ech` was set; rustls path unchanged. **Superseded** — see "Added since v1": the backend is now chosen at compile time and BoringSSL serves every handshake when `boring-tls` is on
- Six named fingerprint profiles: `chrome` / `chrome120`, `firefox` / `firefox120`, `safari` / `safari16`, `ios`, `android`, `edge`
- `random` meta-profile (weighted pick at `TlsLayer::new` time: chrome×6, safari×3, ios×2, firefox×1)
- `TlsConfig.ech: Option<EchOpts>` with `EchOpts::Config(Vec<u8>)` for inline ECH config list
- `EchKeyPairGenerator` — FFI-based HPKE keypair generation for tests (boring-sys `SSL_ECH_KEYS_*`)
- `spawn_ech_server()` — real server-side ECH via `SSL_CTX_set1_ech_keys`, used by C13–C15 for full end-to-end handshakes
- JA3 hash reference consts for firefox, android, edge (hardcoded; chrome uses property-based assertions; safari and ios alias at the wire level, see Key Decisions)
- Feature-gated test suite: `boring_tls_test` (20 cases including real C13–C15), plus retained rustls suite (11 cases); 31 total passing

### Added since v1

- **BoringSSL is the only TLS backend.** The rustls backend and the rustls
  `ech` feature are removed; `tls` *is* BoringSSL and `boring-tls` is a
  no-op alias. The `SslConnector` is memoised per
  `(fingerprint, alpn, skip_cert_verify)` and SNI is omitted for IP-literal
  server names. URL-test health probes, the internal HTTP fetcher (which
  replaced `reqwest`), DoT/DoH and the vendored anytls client all go
  through the same `TlsLayer`. rustls survives only as a dev-dependency for
  the loopback TLS test servers; `hysteria2` uses quiche on the same vendored
  BoringSSL.

- **DNS-sourced ECH** (`ech-opts.enable: true` with no inline `config:`) — async pre-resolution pass over the proxy YAML map (`meow_config::ech_dns::preresolve_ech`) uses `hickory-resolver` against the system DNS config to fetch the wire-format `ECHConfigList` from the HTTPS (RR 65) record, then writes it back as base64 so the sync `parse_proxy` path stays sync. Wired into `build_config`, the API config-reload handlers, the proxy-provider refresh, and the subscription auto-update path.
- **ECH retry self-heal** — when the server returns `ech_required` with fresh `retry_configs`, `BoringInner` (now holding `ech: Mutex<Option<EchOpts>>`) rotates its stored ECH bytes to the server-signed key. The current connect still fails (the inner stream is consumed by `tokio_boring::connect`), but every subsequent connect through the same `TlsLayer` uses the refreshed key. Validated end-to-end by `c16_ech_self_heal_uses_retry_configs_on_next_connect`.

### Still deferred / out of scope

| Item | Reason |
|------|--------|
| `randomized` fingerprint profile | Requires per-connection extension-list sampling |
| Deprecated fingerprints (`chrome_psk`, `chrome_pq`, `chrome_padding_psk_shuffle`, etc.) | Actively discouraged upstream; stub-warn only |
| `360`, `qq` fingerprints | Low demand; deferred |
| Windows CI verification | boring-sys Windows support untested in this repo |

---

## Milestones

| Task | Subject | Owner | Status | Commit |
|------|---------|-------|--------|--------|
| #6 | Spike: verify boring v5 ECH setter API | dev | completed | (research only) |
| #7 | Scaffold boring-tls feature + TlsBackend enum | dev | completed | `a2f6fd1` |
| #8 | Implement uTLS fingerprint profiles | dev | completed | `a2f6fd1` |
| #9 | Implement inline ECH path | dev | completed | `1e2c6f0` |
| #12 | Build test harness scaffold for ECH + uTLS | qa | completed | `1f400b8`, `1e2c6f0` |
| #11 | Write C1–C15 test cases | qa | completed | `bd75da8` |
| #13 | Baseline project status doc | pm | completed | `672f6a6` |
| #14 | Fix C2 assertion — exact distinctness + safari/ios alias | qa | completed | `a505485` |
| #15 | Implement `spawn_ech_server()` FFI wiring | dev | completed | `d31bf79` |
| #16 | Re-wire C13–C15 as real end-to-end ECH tests | dev | completed | `d31bf79` |
| #17 | DNS-sourced ECH via hickory-resolver (preresolve pass) | dev | completed | (this branch) |
| #18 | ECH self-heal — store retry_configs on rejection (C16) | dev | completed | (this branch) |

---

## Key Decisions

| Decision | Choice made | Alternatives rejected |
|----------|-------------|----------------------|
| TLS backend for ECH/uTLS | **Option A:** boring + tokio-boring | Option B (rustls extensions), Option C (FFI-only boring) |
| Feature gating | `boring-tls` cargo feature; off by default | Always-on (rejected: C toolchain requirement breaks CI workers without cmake/clang) |
| DNS-sourced ECH | Async preprocessing pass injects fetched bytes back into YAML before sync parse — keeps `parse_proxy` sync. | (a) Make `parse_proxy` async (cascades to ~10 call sites and many `#[test]`s); (b) Block on a temp runtime inside the sync parser (panics inside an outer tokio runtime). |
| ECH rejection behavior | Self-heal: rotate stored ECH bytes to the server's `retry_configs`, surface this connect's failure, future connects use the new key. | (a) Auto-fallback to plaintext SNI (rejected: defeats purpose of ECH); (b) In-call retry on a fresh TCP (rejected: TLS Layer doesn't own the dialer). |
| GREASE handling in JA3 | Strip GREASE values per Salesforce canonical spec before hashing | Include GREASE (would make chrome hash non-deterministic) |
| chrome JA3 assertion style | Property-based (cipher order + GREASE presence) — no fixed hash | Fixed hash (rejected: extension permutation makes chrome hash non-deterministic per-handshake) |
| `random` profile resolution | Resolved once at `TlsLayer::new` time (not per-connection) | Per-connection pick (deferred to design §5; divergence from Go upstream) |
| `ios` fingerprint | Intentional alias for `safari` in v1 — our boring-based translation of `HelloIOS_Auto` produces a byte-identical ClientHello to `HelloSafari_Auto` (same cipher list, curves, extensions, and `signature_algorithms`). C2 asserts exact equality so future divergence fails loudly. | Split profile (deferred: Go upstream differentiates them via subtle sigalg/extension ordering, but the user-visible delta is small for v1) |

---

## Known Limitations / Caveats

- **Boring cipher/sigalg string fidelity is a silent-drift risk.** The OpenSSL cipher strings in `apply_fingerprint()` are translated from Go `u_parrots.go` by hand. A wrong cipher name silently falls through without error; the only detection is JA3 hash mismatch. The hardcoded reference hashes in C2 guard against drift — a future profile translation bug will fail the exact-equality assertion loudly rather than pass silently.
- **Binary size increase.** Enabling `boring-tls` adds approximately 8–12 MB to the release binary (BoringSSL static lib via boring-sys cmake).
- **`android` and `edge` not in the `random` weighted set.** This matches design doc §5 intentionally, but is not obvious to operators who may expect all v1 profiles to be reachable via `random`.
- **The first connect after an ECH key rotation still fails.** When the server returns `ech_required` with fresh `retry_configs`, the kernel updates its in-memory ECH config but cannot re-handshake on the consumed inner stream. Subsequent connects auto-use the new key. Operators do not need to do anything; the second connect (driven by URLTest, retry, or the next user request) succeeds. C16 covers this end to end.

---

## Cross-References

- Design doc: `docs/specs/ech-utls-design.md`
- Test plan: `docs/specs/ech-utls-test-plan.md`
- Branch: `feat/tls-ech-utls`
- Primary code: `crates/meow-transport/src/tls.rs`
- Test file: `crates/meow-transport/tests/boring_tls_test.rs`
- Harness: `crates/meow-transport/tests/support/loopback.rs`
