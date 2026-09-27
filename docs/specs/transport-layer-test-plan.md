# Test Plan: `meow-transport` crate (M1.A-1..4)

Status: **draft** — owner: qa. Last updated: 2026-04-11 (A8 reworded: SNI fallback in meow-config not TlsLayer; B8 split: layer trusts input, config-side clamp cases deferred to config_test.rs).
Tracks: task #35. Companion to `docs/specs/transport-layer.md` and ADR-0001.

This is the QA-owned acceptance test plan. The spec's §Test plan is PM's
starting point; this document is the final shape engineer should
implement against. If spec and plan disagree, **this document wins for
test cases** — flag the discrepancy so the spec can be updated.

## Scope and guardrails

**In scope:**

- Per-layer unit tests: `tls`, `ws`, `grpc` (gun), `h2`, `httpupgrade`.
- Crate-level invariants: no outbound deps on `meow-proxy`/`dns`/
  `config`, feature-gate compile matrix, no server-side code.
- Integration-regression gates: `trojan_integration` after M1.A-1.migrate,
  `v2ray_plugin_integration` after M1.A-2.migrate. These must stay green
  **without being edited**; an edit to either integration binary during
  the migration PRs is a red flag and reviewer must bounce it.
- Log-capture tests for the accept-and-warn paths (fingerprint,
  skip-verify, ws Host conflict).

**Out of scope (forbidden per spec §Forbidden scope):**

- **Any server-side code.** Acceptance criterion #8 forbids
  `accept`/`bind`/`listen`/`Server`/`Acceptor`/`TcpListener` inside
  `meow-transport` outside `tests/`. Tests that need a loopback
  server must put the server code in `tests/support/` and name it
  clearly (e.g. `tests/support/loopback.rs`) so the grep-check can
  whitelist `tests/**`.
- Reality / SMUX / mux — not in this spec, not in this plan. ShadowTLS
  and restls have since landed (`shadow_tls.rs`, `restls/`); their tests
  live beside them rather than in this plan. If engineer asks about the
  remaining items, bounce to architect.
- Server-side `Transport::accept` trait method. If it appears in any
  M1.A PR, fail the review.
- Touching `crates/meow-proxy/src/simple_obfs.rs`. Any diff against
  that file in an M1.A PR is a scope bug.
- uTLS fingerprint spoofing behaviour. We accept, we warn, we do
  nothing. No test asserts "handshake bytes look like Chrome".
- RTT / performance / throughput. The M2 benchmark harness owns that.
- Real-network tests against external CDNs. All tests use in-process
  loopback servers.

## Dependencies and structure

```
crates/meow-transport/
  src/
    lib.rs            # Transport trait, TransportError, Stream blanket impl
    tls.rs
    ws.rs
    grpc.rs
    h2.rs
    httpupgrade.rs
  tests/
    support/
      loopback.rs     # tiny loopback servers (whitelisted from grep)
      reference_gun.rs  # 50-LOC upstream framer port (grpc only)
      log_capture.rs  # wraps tracing-test for once-per-value asserts
    tls_test.rs
    ws_test.rs
    grpc_test.rs
    h2_test.rs
    httpupgrade_test.rs
    crate_invariants_test.rs
```

Each layer gets its own test binary so the test job can filter
individually. `support/` is shared via `mod support;` at the top of each
test binary.

## Log-capture strategy

Three of the crate-wide invariants need to assert "a `warn!` was
emitted exactly once per distinct value":

- `client-fingerprint` — ws and tls tests
- `skip-cert-verify = true` — tls test
- ws Host header conflict — ws test

Use `tracing-subscriber::fmt::test_writer` layered with a custom
`MakeWriter` that appends to an `Arc<Mutex<Vec<String>>>`. Put this in
`tests/support/log_capture.rs` so every test binary can reuse it;
`tracing-test` itself is fine too but has known issues with multiple
test binaries sharing process-global state. Either way, document the
choice inline in the support module so a future contributor doesn't
reintroduce the broken pattern.

## Case list

### A. `tls` layer (`tests/tls_test.rs`)

Uses an in-process rustls server in `tests/support/loopback.rs`
producing a self-signed cert on demand.

| # | Case | Asserts |
|---|------|---------|
| A1 | `tls_connect_cert_ok` | Loopback rustls server with a self-signed cert; client trusts cert via `rustls-pemfile`; `TlsLayer::connect` returns `Ok`, peer_addr matches the server. |
| A2 | `tls_connect_bad_cert_errs` | Same server, client does not trust cert, `skip_cert_verify = false`; `connect` returns `Err(TransportError::Tls(_))`. Assert the error **Display** contains "handshake" or an equivalent marker so downstream log greps stay useful. |
| A3 | `tls_skip_verify_connects` | Flip `skip_cert_verify = true`; `connect` returns `Ok`; log capture shows exactly one `warn!` containing `"skip-cert-verify"`. This is a footgun knob; we want loud telemetry. |
| A4 | `tls_alpn_negotiated_h2` | Server offers `["h2","http/1.1"]`; client prefers `["h2","http/1.1"]`; assert negotiated ALPN == `h2`. |
| A5 | `tls_alpn_fallback_http11` | Server offers `["http/1.1"]` only; client prefers `["h2","http/1.1"]`; assert negotiated ALPN == `http/1.1`. Guards against an "h2 or bust" bug. |
| A6 | `tls_alpn_empty_config` | `alpn = []`; assert the ClientHello omits the ALPN extension entirely (not `alpn: [""]`). |
| A7 | `tls_sni_override` | `sni = Some("cdn.example.com")`, dial address `127.0.0.1:port`; server captures `server_name`, assert it equals `cdn.example.com`. |
| A8 | `tls_sni_from_config_hostname` | `TlsConfig { sni: Some("hostname.example.com"), … }` (fallback already resolved in `meow-config` before layer construction — NOT in `TlsLayer`); assert the loopback server's captured `server_name` equals `"hostname.example.com"`. Guards against anyone adding SNI-fallback logic inside `TlsLayer`. Upstream: `adapter/outbound/trojan.go::DialContext` resolves SNI in proxy construction — NOT in transport layer. ADR-0002 Class A (meow-rs mirrors upstream: SNI resolved before layer construction, never inside the layer). |
| A9 | `tls_sni_is_ip_omitted` | `sni = None`, dial to `127.0.0.1`; assert **no** SNI extension in the ClientHello (sending an IP as SNI is a protocol violation). |
| A10 | `tls_client_cert_accepted` | Configure `ClientCert { cert_pem, key_pem }` with a test CA the server trusts; assert the loopback server observed the expected client-cert CN. |
| A11 | `tls_fingerprint_warn_once_per_value` | Build two `TlsLayer`s with `fingerprint = Some("chrome")`; assert log capture shows **exactly one** `warn!` with the verbatim text from spec §"Fingerprint warn text" and substring `"chrome"`. |
| A12 | `tls_fingerprint_warn_twice_for_distinct_values` | Build two layers, one with `Some("chrome")` and one with `Some("firefox")`; assert log capture shows **exactly two** warns, one per value. Dedup must be by value, not globally suppressed. |
| A13 | `tls_fingerprint_none_no_warn` | `fingerprint = None`; assert log capture shows zero fingerprint warns. |

### B. `ws` layer (`tests/ws_test.rs`)

Loopback server built on `tokio-tungstenite` in `tests/support/loopback.rs`.

| # | Case | Asserts |
|---|------|---------|
| B1 | `ws_handshake_upgrade_ok` | Loopback ws server; client connects with `path = "/ws"` and two custom headers; assert the server observed both headers. |
| B2 | `ws_host_header_override` | `host_header = Some("cdn.example.com")`, dial address `127.0.0.1:port`; assert the server's received `Host` header == `cdn.example.com`. |
| B3 | `ws_host_fallback_to_dial_target` | `host_header = None`, dial to a hostname; assert the server's received `Host` header == the dial hostname. |
| B4 | `ws_host_conflict_warns_and_host_header_wins` | Both `host_header = Some("A")` and `extra_headers` contains `("Host","B")`; assert **exactly one** warn logged with substring `"Host"`/`"host_header"`, and the server observed `Host: A`. Locks the spec's "prefer `host_header`" contract. |
| B5 | `ws_path_forwarded` | Client path is `/custom/path?x=1`; assert the server saw the same path verbatim (no normalization). |
| B6 | `ws_early_data_zero_no_protocol_header` | `max_early_data = 0`; write 100 bytes after the handshake; assert server received them as a **data frame**, not via `Sec-WebSocket-Protocol`. Locks the "0 disables entirely" default. |
| B7 | `ws_early_data_encoded_in_protocol_header` | `max_early_data = 32`; write 16 bytes before the handshake completes; assert the server's received `Sec-WebSocket-Protocol` header is the base64url-no-padding encoding of those 16 bytes. |
| B8 | `ws_early_data_clamps_at_layer_and_parse` | **Superseded by #648**: the layer now clamps at `connect` (an unbounded programmatic `WsConfig` would otherwise emit an unbounded `Sec-WebSocket-Protocol` header) and `meow-config` clamps at parse with a `warn!`. Covered by `ws_max_early_data_clamps_to_ceiling` in `crates/meow-config/src/proxy_parser.rs` (absent→0, at-cap ok, 99999/`u64::MAX`→2048). The original "layer trusts input verbatim" assertion no longer holds — clamping is byte-preserving: excess early bytes are sent as normal frames post-handshake. |
| B9 | `ws_handshake_failure_surfaces_websocket_error` | Loopback server closes the TCP socket before completing the upgrade; assert `connect` returns `Err(TransportError::WebSocket(_))`. |

### C. `grpc` layer (`tests/grpc_test.rs`) — the anti-regression wall

This is the most important test suite in the crate. The gun framing is
hand-rolled, the upstream wire format is the ground truth, and **this is
the one place where byte-for-byte equality is non-negotiable**. Under no
circumstances should any test here be softened to a "structural" or
"semantic" equivalence check without architect approval.

Reference implementation: `tests/support/reference_gun.rs` is a ~50 LOC
port of upstream `transport/gun/gun.go`'s framer. Engineer copies
upstream verbatim (keeping Go idioms) and translates line-by-line — the
whole point is that the reference is untouched from upstream so any
drift is ours. Include an `// UPSTREAM: transport/gun/gun.go@<commit>`
header comment with the exact commit SHA ported, so a future reviewer
can diff upstream if they need to.

| # | Case | Asserts |
|---|------|---------|
| C1 | `grpc_framing_encode_matches_upstream` | Encode a 1 KiB payload via `GrpcLayer`; decode with `reference_gun::decode`; assert byte-for-byte equality. |
| C2 | `grpc_framing_decode_matches_upstream` | Encode via `reference_gun::encode`; decode via `GrpcLayer`; assert byte-for-byte equality. |
| C3 | `grpc_framing_empty_payload` | Zero-length payload; round-trip via C1 and C2; assert empty payload decodes as empty (not "EOF error on empty frame"). |
| C4 | `grpc_framing_large_payload_4mib` | 4 MiB payload; round-trip via C1 and C2; assert equality. Exercises multi-frame chunking. |
| C5 | `grpc_framing_fragmented_reader` | Feed the decoder byte-at-a-time through a `BufReader` that splits at every byte; assert the decoded output equals the encoded input. Guards against implicit assumptions that one `read()` returns a whole frame. |
| C6 | `grpc_service_name_in_path` | Build a layer with `service_name = "GunService"`; capture the HTTP/2 `:path` pseudo-header on the loopback server; assert it equals `/GunService/Tun` (upstream convention). |
| C7 | `grpc_content_type_header` | Assert `content-type: application/grpc` appears on the request headers. |
| C8 | `grpc_round_trip_loopback` | Full loopback (h2 server + GrpcLayer client); round-trip 4 MiB of random bytes; assert equality. Integration-style but still in-process. |

### D. `h2` layer (`tests/h2_test.rs`)

| # | Case | Asserts |
|---|------|---------|
| D1 | `h2_round_trip_1mib` | Loopback h2 server, `hosts = ["example.com"]`, round-trip 1 MiB, assert equality. |
| D2 | `h2_host_selection_is_uniform` | 1000 connections with `hosts = ["a","b","c","d"]`; capture the `:authority` (or `Host`) pseudo-header on each connect; assert **every host appears at least once**. Cheap deflake of "stuck on index 0" without asserting distribution shape. **Do not add ±3σ or chi-square distributional checks** — PM and architect agreed they flake under CI scheduler noise. |
| D3 | `h2_single_host_no_randomness_needed` | `hosts = ["example.com"]`; 10 connections; every one hits `example.com`; no panic or modulo-by-zero. |
| D4 | `h2_path_forwarded` | `path = "/custom"`; assert the `:path` pseudo-header equals `/custom`. |
| D5 | `h2_empty_hosts_errs_at_config` | `hosts = []` — **this is a config-layer rejection**, so the test lives in `config_test.rs` (not here). We just document that `H2Config { hosts: vec![] }` is a precondition violation at the layer level and is never constructed; `debug_assert!(!hosts.is_empty())` in the layer constructor. |

### E. `httpupgrade` layer (`tests/httpupgrade_test.rs`)

| # | Case | Asserts |
|---|------|---------|
| E1 | `httpupgrade_101_switching_protocols_ok` | Loopback mock server returns `101 Switching Protocols` with `Upgrade:` header matching the request; raw bytes round-trip after the upgrade. |
| E2 | `httpupgrade_non_101_fails` | Server returns `200 OK`; assert `Err(TransportError::HttpUpgrade(_))` with a message containing the received status code. |
| E3 | `httpupgrade_missing_upgrade_header_fails` | Server returns `101` but without `Upgrade:` header; assert error. |
| E4 | `httpupgrade_custom_headers_forwarded` | `extra_headers = [("X-Custom","foo")]`; assert the server received the header. |
| E5 | `httpupgrade_host_header_override` | `host_header = Some("cdn.example.com")`; assert the server received that `Host` header. |

### F. Crate-level invariants (`tests/crate_invariants_test.rs`)

These are the structural guardrails. If any of them break, the crate
has drifted from ADR-0001.

| # | Case | Asserts |
|---|------|---------|
| F1 | `no_proxy_dep` | Shell-out via `cargo tree -p meow-transport --edges normal`; parse output; assert no line mentions `meow-proxy`, `meow-dns`, or `meow-config`. Allowed workspace crates: `meow-common` only. Failure message includes the offending line for triage. |
| F2 | `no_server_side_symbols_in_src` | Walk `crates/meow-transport/src/**/*.rs` and grep for `\baccept\b`, `\bbind\b`, `\blisten\b`, `\bServer\b`, `\bAcceptor\b`, `\bTcpListener\b`. Fail with the exact file + line for any match. **Must be a test, not a reviewer checklist item** — PM specifically asked for this to be mechanically enforced. |
| F3 | `transport_error_is_non_exhaustive` | `TransportError` is marked `#[non_exhaustive]` (or otherwise guarded) so adding variants is not a breaking change. Assert via a compile-fail doc-test or a `match` that includes a wildcard arm. Lightweight but catches a future silent-break. |
| F4 | `no_anyhow_at_boundary` | Walk `src/**/*.rs` and assert no `use anyhow` or `anyhow::` reference in any public function's signature. Private helpers may use anyhow internally (engineer's call), but `TransportError` is the only thing that crosses the crate boundary. |

`F2` is a small script in Rust using `walkdir` + `regex`; keep it in a
test so it fails the test job, not a lint job, because PR reviewers
watch test results more closely than lint clean-up commits.

### G. Feature-gate compile matrix

These live in CI (`.github/workflows/test.yml`), not in `cargo test`,
because `cargo check` is the right tool. Add three rows to the existing
`test` job **or** a new `transport-feature-matrix` job (engineer's
call):

| # | Command | Asserts |
|---|---------|---------|
| G1 | `cargo check -p meow-transport --no-default-features` | Crate builds with zero features — trait + error type only. |
| G2 | `cargo check -p meow-transport --no-default-features --features "tls"` | `tls` alone compiles. |
| G3 | `cargo check -p meow-transport --no-default-features --features "tls,ws"` | Default-minus-h2/grpc compiles. |
| G4 | `cargo check -p meow-transport --no-default-features --features "grpc"` | `grpc` alone compiles (pulls in `h2` crate transitively; guard against accidentally depending on `ws`). |
| G5 | `cargo check -p meow-transport --no-default-features --features "h2"` | `h2` alone compiles. |
| G6 | `cargo check -p meow-transport --no-default-features --features "httpupgrade"` | `httpupgrade` alone compiles (cheap, catches a forgotten `cfg_if`). |
| G7 | `cargo check -p meow-transport --all-features` | Union compiles. |

Total wall-time impact: six `cargo check` calls after the first build
warms the cache — under 30s added to CI, worth it.

### H. Integration-regression gates (must stay green across migration)

Not new tests — existing suites that **must not be edited** during the
M1.A-1.migrate and M1.A-2.migrate PRs. If these go red, the migration
changed Trojan or v2ray-plugin observable behaviour and must be
reverted / fixed, not worked around.

| # | Gate | After |
|---|------|-------|
| H1 | `cargo test --test trojan_integration` | M1.A-1.migrate (Trojan on `TlsLayer`) |
| H2 | `cargo test --test v2ray_plugin_integration` | M1.A-2.migrate (v2ray-plugin on `[TlsLayer, WsLayer]`) |

**Reviewer rule**: if either integration binary has a diff in the
migration PR, bounce the PR and ask engineer to justify the diff.
Legitimate reasons (e.g. a timing adjustment that's also required by
the existing code) are fine but must be called out separately from the
migration; illegitimate reasons ("I had to relax the assertion to make
it pass") are scope bugs.

## Deferred / not tested here

- **Server-side `Transport::accept`** — future ADR.
- **uTLS fingerprint spoofing handshake bytes** — we accept the knob
  and warn; no test asserts handshake shape.
- **Reality / SMUX / mux** — future ADRs. (ShadowTLS and restls landed
  as SIP003 transports; their wire formats are documented in their module
  docs and exercised by `shadow_tls_test` / `restls_e2e`.)
- **Performance benchmarks** — M2 owns.
- **Cross-layer stacking beyond the existing pairs** — only `tls+ws` and
  the gun stack are exercised. If VMess/VLESS specs later introduce
  `tls + httpupgrade` or `tls + h2 + custom`, each new combo gets its
  own case added here at that spec's test-plan time.
- **Fuzzing the grpc framer** — the byte-for-byte round-trip against
  reference_gun is sufficient for M1; revisit if upstream reports a
  framing CVE.

## Open questions for engineer (none blocking)

1. ~~**`ws` early-data clamp location.**~~ **Resolved** — twice: originally "config-side only" (B8's layer-trusts-input assertion), then #648 added a connect-time clamp inside `WsLayer` as the programmatic-config backstop. See B8's updated row; parse-side coverage is `ws_max_early_data_clamps_to_ceiling` in `proxy_parser.rs`.
2. **Loopback server hosting**. `tests/support/loopback.rs` will
   contain `TcpListener::bind` — that's the one case where the §F2
   grep-check needs a `tests/` whitelist. Make sure the grep walks
   `src/` only, not the whole crate. I wrote F2 accordingly; confirm
   the walkdir scope.
3. **`tracing-test` vs home-rolled**. I prefer a home-rolled
   `MakeWriter` in `tests/support/log_capture.rs` because
   `tracing-test` has known issues across multiple test binaries, but
   if you've used it successfully recently and have a pattern, use
   that. Just document the choice in `log_capture.rs` so a future
   contributor doesn't re-break it.

## Exit criteria for this test plan

- All cases in §A–F pass on `ubuntu-latest` and `macos-latest`. None of
  them touch OS-specific APIs, so the existing `macos` job in
  `test.yml` should pick them up by default if added to the per-suite
  invocation list.
- §G feature-matrix jobs green in CI.
- §H integration gates stay green without edits during the two migration
  PRs.
- `cargo tree -p meow-transport` shows only `meow-common` from the
  workspace (§F1 already asserts this; repeating as the human gate).

## CI wiring required

Three additions to `.github/workflows/test.yml`:

1. Add `tls_test`, `ws_test`, `grpc_test`, `h2_test`, `httpupgrade_test`,
   and `crate_invariants_test` to the per-suite invocation list in the
   `test` job **and** the `macos` job. They're pure-Rust and loopback
   only.
2. Add the six `cargo check` rows from §G — either as steps in the
   existing `test` job or as a new `transport-feature-matrix` job.
3. Nothing for §H — those suites are already wired (`trojan_integration`
   was always in CI; `v2ray_plugin_integration` was wired by #1).

I'll file this CI wiring as a follow-up qa task once engineer
confirms the file layout and we know the exact binary names. No point
writing the workflow diff before the filenames are settled.
