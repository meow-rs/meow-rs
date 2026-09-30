# Test Plan: VLESS outbound (M1.B-2)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #40. Companion to `docs/specs/proxy-vless.md` (architect-approved,
amendments applied: UDP+Vision warn row #7, peek-length fix to 5 bytes,
padding range pinned to upstream constant).

This is the QA-owned acceptance test plan. The spec's `§Test plan` section
is PM's starting point; this document is the final shape engineer should
implement against. If the spec and this document disagree, **this document
wins for test cases** — flag the discrepancy so the spec can be updated.

Divergence-comment convention per memory (`feedback_spec_divergence_comments.md`):
inline `Upstream: file::fn` + `NOT X` lines on bullets that exercise a
divergence. ADR-0002 Class cite (A or B) per `feedback_adr_0002_class_cite.md`.

## Scope and guardrails

**In scope:**

- Header encoder/decoder byte-exact correctness (`vless/header.rs`).
- XTLS-Vision splice logic: 5-byte peek, ClientHello detection, padding
  header byte sequence, pass-through fallback, full-record buffering
  before send (`vless/vision.rs`).
- Config parser: all Class A hard-errors and Class B warn-once paths.
- Transport-chain composition shape (reuses VMess pattern).
- In-process mock connection wire tests.
- Feature-gate compile matrix (`vless`, `vless-vision`).
- `xray` integration tests (skip-if-absent).
- Crate invariants (no transport code in `vless/`, `AdapterType` wiring).

**Out of scope (forbidden per spec §Scope):**

- Reality transport (`reality-opts`) — hard-error tested in §D; no
  implementation to test.
- VLESS inbound / server mode.
- Mux.Cool runtime behavior — warn-ignore; only the config warn is tested.
- XTLS-RPRX-Direct / Splice runtime behavior — hard-error tested; no
  implementation to exercise at runtime.
- Performance / throughput benchmarks — M2.
- `vless-vision` compile unit when `vless-vision` feature is disabled —
  `#[cfg(feature = "vless-vision")]` gating tested in §G, not runtime.

## Divergence table (ADR-0002)

| # | Case | Class | Note |
|---|------|:-----:|------|
| 1 | `tls: false` plain VLESS — upstream silent | B | Warn-once at load. Same destination, absent crypto. |
| 2 | `flow: xtls-rprx-direct` / `xtls-rprx-splice` — upstream accepts as deprecated | A | Security downgrade vs Vision; hard-error citing "use xtls-rprx-vision". |
| 3 | `reality-opts` present — upstream routes Reality | A | Not implemented; silent ignore = plain-TLS to Reality-expecting server, no diagnostic. Hard-error with roadmap pointer. |
| 4 | Unknown `flow` value — upstream ignores | A | Unknown flow may skip expected security processing. Hard-error. |
| 5 | `encryption: <non-none>` — upstream hard-errors too | — | Match (both hard-error). Not a divergence. |
| 6 | `mux: { enabled: true }` — sing-mux multiplexing | B | Implemented (default h2mux; smux/yamux also supported) for sing-box/mihomo servers; Xray Mux.Cool (`protocol: muxcool`) for Xray servers. |
| 7 | `flow: xtls-rprx-vision` + `udp: true` — upstream UDP uses plain VLESS silently | B | Warn-once at load; UDP still routes same destination with outer-TLS. Not Class A (crypto unchanged). |

---

## Case list

### A. Header encoder unit tests (`crates/meow-proxy/src/vless/header.rs`)

Pure-Rust unit tests. No async, no network. These are byte-level
correctness tests — any deviation from the expected bytes means the
VLESS header will be misread by the server with no diagnostic.

The spec requires 100% branch coverage on the addr encoding path
(acceptance criterion #11). Every `addr_type` variant and every error
path must be exercised.

| # | Case | Asserts |
|---|------|---------|
| A1 | `header_encode_tcp_ipv4_plain` | UUID `b831381d-6324-4d53-ad4f-8cda48b30811`, target `127.0.0.1:443`, `flow: ""`. Assert wire bytes match: `version(0x00)` + 16 UUID bytes + `addon_length(0x00)` + `cmd(0x01)` + `port(0x01BB)` + `addr_type(0x01)` + `7f 00 00 01`. <br/> Upstream: `transport/vless/encoding.go::EncodeRequestHeader`. |
| A2 | `header_encode_tcp_domain_plain` | UUID + `example.com:80`, `flow: ""`. Assert: `cmd(0x01)` + `port(0x0050)` + `addr_type(0x02)` + `len(0x0B)` + `"example.com"`. <br/> NOT `addr_type` before `port` — port comes **before** addr_type, same as VMess. Test this explicitly because human-readable specs list fields in address-first order. |
| A3 | `header_encode_tcp_ipv6_plain` | UUID + `[::1]:443`, `flow: ""`. Assert: `addr_type(0x03)` + 16 bytes of `::1`. |
| A4 | `header_encode_udp_command` | Same as A1 but UDP target. Assert `cmd(0x02)` in the header bytes. Guards against copy-paste of the TCP path without flipping the command byte. |
| A5 | `header_encode_addon_empty_for_plain_flow` | `flow: ""`. Assert the addon region is exactly: `addon_length(0x00)` — no addon bytes follow. <br/> Upstream: `transport/vless/encoding.go::EncodeRequestHeader` addon block when Flow field is empty string. |
| A6 | `header_encode_addon_vision_exact_bytes` | `flow: "xtls-rprx-vision"`. Assert `addon_length(0x12)` (= 18 decimal), then addon bytes: `0x0A 0x10` + 16 UTF-8 bytes `b"xtls-rprx-vision"`. <br/> Upstream: same file, addon block with `Flow` = `"xtls-rprx-vision"`. <br/> NOT prost-generated — hardcoded 2-byte protobuf prefix + string copy, no `prost` dep. Assert `addon[0] == 0x0A` (field 1, wire type 2), `addon[1] == 0x10` (varint 16). |
| A7 | `header_encode_version_byte_is_zero` **[guard-rail]** | Assert the very first byte of any encoded header is `0x00`. Guards against engineer copy-pasting from the VMess encoder where `version = 0x01`. |
| A8 | `header_addr_domain_max_255_encodes` | Exactly 255-char hostname encodes without error. |
| A9 | `header_addr_domain_over_255_errors_at_build_time` | 256-char hostname → `Err` at adapter build time (not encode time). <br/> Upstream: `transport/vless/encoding.go` does not enforce this limit. <br/> NOT silent truncate — Class A per ADR-0002 (divergence row #3 in VMess; same issue here): wrong destination, no diagnostic. |
| A10 | `header_addr_idn_not_punycoded` **[guard-rail]** | `"例え.jp:80"` → raw UTF-8 bytes in the domain field. NOT `xn--` punycode. Match upstream behavior: let the server handle IDN. |
| A11 | `header_encode_full_round_trip_via_decode` | Encode a header then decode it; assert all fields match input. |

### B. Response decoder unit tests (`crates/meow-proxy/src/vless/header.rs`)

| # | Case | Asserts |
|---|------|---------|
| B1 | `response_decode_version_zero_ok` | Input `[0x00, 0x00]` (version + addon_length=0). Decode succeeds; no error, no log. |
| B2 | `response_decode_version_zero_with_addon` | Input `[0x00, 0x02, 0xAA, 0xBB]`. Version=0, addon_length=2, addon bytes read and discarded. Succeeds. Guards against ignoring the addon_length and misaligning the subsequent data read. |
| B3 | `response_decode_version_mismatch_warns_and_errors` | Input `[0x01, 0x00]`. Assert `Err`, and tracing capture shows exactly one `warn!` with substring `"version"` or `"mismatch"`. <br/> Upstream: `transport/vless/conn.go` closes the connection silently. <br/> NOT silent close without log — we surface the reason so users can debug "wrong UUID" / "missing TLS layer" scenarios. |
| B4 | `response_decode_truncated_buffer_errors` **[guard-rail]** | Feed a 1-byte buffer (just the version, no addon_length). Assert clean `Err`, no panic. Guards against an unbounded read on addon_length. |

### C. XTLS-Vision unit tests (`crates/meow-proxy/src/vless/vision.rs`)

These tests require the `vless-vision` Cargo feature. Use a test-mode
`VisionConn` with an observable `mode` flag and a test-writable inner
stream that can stage incoming bytes.

**Critical: the peek reads exactly 5 bytes (the TLS record header),
not 3.** This is the architect-approved amendment. All cases below
must use a 5-byte initial read. Any test using 3 bytes is wrong and
must be bounced back to engineer.

| # | Case | Asserts |
|---|------|---------|
| C1 | `vision_padding_header_matches_reference` | Call the padding-header generator with a known random seed (mock `OsRng`). Assert: byte[0] == `0x17` (AppData type), bytes[1..3] == `[0x03, 0x03]` (TLS 1.2 version), bytes[3..5] == big-endian length of the payload, payload[0] == `0x00` (Vision marker byte), payload length in range `PADDING_RANGE`. <br/> Upstream: `transport/vless/vision/vision.go::sendPaddingMessage`. <br/> NOT arbitrary bytes — byte-exact marker at payload[0]. The upstream range must be pinned in a named constant `PADDING_RANGE` at the top of `vision.rs`; if the constant is missing, bounce the PR. |
| C2 | `vision_padding_range_is_upstream_constant` **[guard-rail]** | Read `vision::PADDING_RANGE` and assert it equals the upstream value from `transport/vless/vision/vision.go`. The exact value is determined by the engineer reading the upstream source; this test then locks it down so a future refactor cannot silently widen or narrow the range. |
| C3 | `vision_detects_inner_tls_by_first_5_bytes` | Feed 5 bytes starting with `[0x16, 0x03, …]` (TLS handshake record type + legacy version major) to `VisionConn`. Assert Vision mode is entered (observable via test-mode flag). The 5-byte read is sufficient; no more than 5 bytes are consumed at detection time. |
| C4 | `vision_passthrough_on_non_tls_first_byte` | Feed 5 bytes starting with `0x47` (`G` — first byte of `GET /`). Assert pass-through mode: no padding header emitted, no further peek attempted. |
| C5 | `vision_passthrough_on_tls_type_but_wrong_version` **[guard-rail]** | Feed `[0x16, 0x04, …]` (TLS type correct, but version major `0x04`, not `0x03`). Assert pass-through, not Vision mode. Guards against checking only byte[0]. |
| C6 | `vision_passthrough_on_empty_stream` **[guard-rail]** | EOF before 5 bytes are available. Assert pass-through, not a panic or a blocking wait. |
| C7 | `vision_reads_full_clienthello_before_sending` | Stage a ClientHello arriving in two `poll_read` chunks (first 5 bytes, then remainder). Assert `VisionConn` does not emit any bytes to the underlying writer until the full record (`5 + body_length` bytes) is buffered. <br/> Upstream: `transport/vless/vision/vision.go::ReadClientHelloRecord`. <br/> NOT partial-send on the first chunk — sending a truncated ClientHello to the server breaks the inner TLS handshake with no diagnostic. |
| C8 | `vision_clienthello_body_length_from_bytes_3_4` **[guard-rail]** | Feed a ClientHello where `uint16_BE(bytes[3..5]) = 512`. Assert `VisionConn` issues a second `read_exact(512)` to buffer the body. Guards against an off-by-one that reads `bytes[4..6]` or miscounts the header-vs-body boundary. |
| C9 | `vision_sends_padding_then_clienthello_in_order` | Assert that after Vision mode is entered, the bytes written to the underlying stream are in order: padding header bytes, then ClientHello bytes. Not interleaved, not reversed. |
| C10 | `vision_udp_path_uses_plain_conn` **[guard-rail]** | Confirm that `VlessAdapter::dial_udp` when `flow = Some(XtlsRprxVision)` returns a plain `VlessConn` (not `VisionConn`). Assert no padding header is ever written on the UDP path. Guards against accidentally wrapping UDP in Vision. |
| C11 | `vision_no_inner_tls_no_log_noise` **[guard-rail]** | Feed non-TLS data in pass-through mode. Assert no `warn!` or `error!` is emitted — only a `trace!` at most. Vision's pass-through is the expected path for HTTP-over-VLESS; it must not spam logs. |

### D. Config parser unit tests (`crates/meow-config/src/proxy_parser.rs`)

All these live in `crates/meow-config/tests/config_test.rs` (or
inline tests in the parser module). Each case is `#[tokio::test]` if
`load_config_from_str` is async (per the dns-doh-dot spec amendment),
otherwise `#[test]`.

| # | Case | Asserts |
|---|------|---------|
| D1 | `parse_vless_minimal_ok` | YAML with only required fields (`name`, `type`, `server`, `port`, `uuid`). Parses to a valid `VlessAdapter`. |
| D2 | `parse_vless_all_fields_roundtrip` | YAML with every documented field. Struct has correct values. |
| D3 | `parse_vless_flow_empty_string_ok` | `flow: ""` → `VlessAdapter.flow == None`. No warn, no error. |
| D4 | `parse_vless_flow_absent_ok` | No `flow:` key → `VlessAdapter.flow == None`. Same as D3. |
| D5 | `parse_vless_flow_vision_ok` | `flow: "xtls-rprx-vision"`, `tls: true` → `VlessAdapter.flow == Some(XtlsRprxVision)`. |
| D6 | `parse_vless_flow_unknown_hard_errors` | `flow: "xtls-rprx-unknown"` → hard error. <br/> Upstream: `adapter/outbound/vless.go` ignores unknown flow strings. <br/> NOT warn-and-ignore — Class A per ADR-0002: unknown flow may skip security processing. |
| D7 | `parse_vless_flow_deprecated_direct_hard_errors` | `flow: "xtls-rprx-direct"` → hard error with message containing `"xtls-rprx-vision"` (the migration path). <br/> Upstream: `adapter/outbound/vless.go` accepts as a deprecated alias. <br/> NOT accepted — Class A per ADR-0002: security regression vs Vision. |
| D8 | `parse_vless_flow_deprecated_splice_hard_errors` | `flow: "xtls-rprx-splice"` → hard error. Same rationale as D7. |
| D9 | `parse_vless_reality_opts_hard_errors` | YAML with `reality-opts:` block → hard error with message containing `"Reality"` and roadmap pointer. <br/> Upstream: `adapter/outbound/vless.go` routes to Reality transport. <br/> NOT silent ignore — Class A per ADR-0002: user assumes Reality; without it they get plain-TLS to a Reality-expecting server with no diagnostic. |
| D10 | `parse_vless_tls_false_plain_warns_once` | `tls: false`, no `flow`, no TLS-enforcing transport → struct loads OK, tracing capture has exactly one `warn!` with substring `"tls"` or `"plaintext"`. Class B per ADR-0002. |
| D11 | `parse_vless_tls_false_no_duplicate_warn` **[guard-rail]** | Load the same YAML twice (simulate reload). Assert the warn appears exactly once per load, not once globally per process. The warn must fire on each `parse_vless` call, not be suppressed after the first process-lifetime occurrence. |
| D12 | `parse_vless_vision_without_tls_hard_errors` | `flow: "xtls-rprx-vision"`, `tls: false`, no TLS-enforcing transport → hard error with message containing `"tls"` or `"encrypting transport"`. Class A per ADR-0002: Vision without outer TLS is a no-op the user did not intend. |
| D13 | `parse_vless_vision_over_{grpc,ws,h2,httpupgrade_and_xhttp}_rejected` **[guard-rail]** | `flow: "xtls-rprx-vision"` with any `network` other than `tcp` (with or without `tls`) → hard error containing "only works over `network: tcp`". Vision's DIRECT mode needs the socket right under the outer TLS; Xray rejects these nodes (issue #495 item 5 — this used to accept grpc/h2). D13e (`parse_vless_vision_with_encryption_keeps_transport_gate`): with VLESS `encryption`, ws + `tls: true` and grpc without TLS still load, plain tcp without TLS still fails. |
| D14 | `parse_vless_encryption_non_none_hard_errors` | `encryption: "aes-128-gcm"` → hard error. <br/> Upstream: also hard-errors on non-"none" values. Match (not a divergence — both reject). |
| D15 | `parse_vless_encryption_empty_string_accepted` | `encryption: ""` → parses OK (equivalent to `"none"` per spec). |
| D16 | `parse_vless_mux_enabled_warns_and_ignores` | `mux: { enabled: true }` → parse succeeds; tracing capture has one `warn!` containing `"mux"`. Class B per ADR-0002. |
| D17 | `parse_vless_vision_udp_true_warns_once` | `flow: "xtls-rprx-vision"`, `udp: true`, `tls: true` → parse succeeds; tracing capture has one `warn!` containing `"UDP"` and `"Vision"` (or `"udp"` and `"vision"`). Class B per ADR-0002 row #7. |
| D18 | `parse_vless_uuid_hex_and_dashed_both_accepted` **[guard-rail]** | UUID in dashed form and hex-only form both parse to the same 16-byte value. |
| D19 | `parse_vless_uuid_invalid_hard_errors` **[guard-rail]** | `uuid: "not-a-uuid"` → hard error with message containing `"uuid"`. |
| D20 | `parse_vless_server_domain_over_255_errors` **[guard-rail]** | `server:` is a 256-char hostname → hard error at build time (not send time). Class A: wrong destination, no diagnostic on silent truncate. |
| D21 | `parse_vless_vision_feature_disabled_hard_errors` **[guard-rail]** | In a build compiled without `vless-vision` feature, `flow: "xtls-rprx-vision"` → hard error with message naming the `vless-vision` Cargo feature. Mirrors the `encrypted` feature pattern from dns-doh-dot. |

### E. Transport-chain composition unit tests

Mirrors the VMess test plan §E. Build adapters from YAML and inspect
the resulting `TransportChain` shape; no network required.

| # | Case | Asserts |
|---|------|---------|
| E1 | `vless_tcp_no_tls_empty_chain` | `network: tcp`, `tls: false`. Chain length 0. |
| E2 | `vless_tcp_with_tls_chain` | `network: tcp`, `tls: true`. Chain = `[TlsLayer]`. |
| E3 | `vless_ws_with_tls_chain_ordered` | `network: ws`, `tls: true`. Chain = `[TlsLayer, WsLayer]` in that order. TLS wraps TCP; WS wraps TLS. |
| E4 | `vless_grpc_transport_chain` **[guard-rail]** | `network: grpc` (implies TLS). Chain includes `GrpcLayer`. Only when `grpc` feature enabled. |
| E5 | `vless_vision_wrapped_around_vless_conn` | `flow: "xtls-rprx-vision"`, `tls: true`, `network: tcp`. `dial_tcp` returns a `VisionConn` wrapper, not a bare `VlessConn`. The Vision wrapping is inside the ProxyConn, orthogonal to the `TransportChain`. |
| E6 | `vless_udp_ignores_vision_flow` **[guard-rail]** | `flow: "xtls-rprx-vision"`, `udp: true`, `tls: true`. `dial_udp` returns a plain `VlessConn` (no `VisionConn` wrapper). Acceptance criterion §Scope: "Vision is TCP-only". |

### F. Connection wire tests (`crates/meow-proxy/src/vless/conn.rs`)

Use an in-process mock server that echoes the VLESS response header
(`[0x00, 0x00]`) and then echoes payload bytes. The mock lives in
`crates/meow-proxy/tests/support/vless_mock.rs`.

| # | Case | Asserts |
|---|------|---------|
| F1 | `vless_conn_writes_request_header_on_connect` | Connect to mock; assert mock received a valid VLESS request header starting with `0x00` (version) followed by the correct UUID bytes. |
| F2 | `vless_conn_tcp_payload_round_trips` | Send 1 KiB via `VlessConn`; mock echoes it back after the response header; assert received bytes equal sent. |
| F3 | `vless_conn_reads_and_discards_response_header` | Mock sends `[0x00, 0x00]` then payload. Assert `VlessConn` correctly discards the 2-byte response preamble and exposes only the payload to the caller. |
| F4 | `vless_conn_response_with_nonzero_addon_length` **[guard-rail]** | Mock sends `[0x00, 0x03, 0xAA, 0xBB, 0xCC]` (version=0, addon_length=3, 3 addon bytes). Assert the 3 addon bytes are discarded and the *next* read delivers real payload. Guards against misaligning the payload start when addon_length > 0. |
| F5 | `vless_conn_version_mismatch_tears_down` | Mock sends `[0x01, 0x00]` (version=1). Assert `VlessConn` errors out; the error is `ConnError::VersionMismatch`, not an opaque `UnexpectedEof`. |
| F6 | `vless_conn_server_eof_after_header` | Mock closes the connection immediately after receiving the request header (simulating wrong UUID). Assert `ConnError::ServerRejected` surfaced from `UnexpectedEof`. |
| F7 | `vless_packet_conn_cmd_byte_is_0x02` **[guard-rail]** | Inspect the request header bytes from `VlessPacketConn`; assert `cmd == 0x02` (UDP), not `0x01`. |

### G. Feature-gate compile matrix

Add as steps in the existing `test` job or a new `vless-feature-matrix` job.

| # | Command | Asserts |
|---|---------|---------|
| G1 | `cargo check -p meow-proxy --no-default-features --features vless` | Compiles without transport layers, without Vision. Acceptance criterion #1. |
| G2 | `cargo check -p meow-proxy --no-default-features --features "vless,tls"` | Compiles. |
| G3 | `cargo check -p meow-proxy --no-default-features --features "vless,tls,ws"` | Compiles. Real-world minimum. Acceptance criterion #2. |
| G4 | `cargo check -p meow-proxy --no-default-features --features "vless,tls,ws,vless-vision"` | Compiles with Vision. |
| G5 | `cargo check -p meow-proxy --no-default-features --features "vless,tls,ws,grpc,h2,httpupgrade,vless-vision"` | Full feature set compiles. |
| G6 | `cargo check -p meow-proxy --no-default-features --features vless` (no `vless-vision`) | The `vision.rs` module is excluded; the `VlessFlow::XtlsRprxVision` match arm is cfg-gated away. Compile check only — behavior tested by D21. |

### H. Integration tests (`crates/meow-proxy/tests/vless_integration.rs`)

Follow the `vmess_integration.rs` pattern exactly. Skip-if-absent,
same `xray` binary name and install hint:

> `"xray binary not found; install via: go install github.com/xtls/xray-core/main/xray@latest"`

Gate behind `MIHOMO_REQUIRE_INTEGRATION_BINS`: when `=1`, fail if `xray`
absent; when `=0` or unset, skip gracefully.

| # | Case | Asserts |
|---|------|---------|
| H1 | `vless_tcp_plain_tls_roundtrip` | Local `xray` on random port, plain VLESS + TLS (`skip-cert-verify: true`, self-signed cert). Send 1 KiB payload through VLESS+TLS to a loopback echo. Assert bidirectional bytes match. Acceptance criterion #3. |
| H2 | `vless_tcp_ws_tls_roundtrip` | `network: ws`, `tls: true`. Same round-trip assertion. Tests the transport-chain stacking at integration level. |
| H3 | `vless_udp_roundtrip` | UDP relay of a DNS query through the same xray server. Assert a valid DNS reply. Acceptance criterion #4. Skipped if xray absent or loopback DNS echo unavailable. |
| H4 | `vless_vision_roundtrip` | Local xray configured with `flow: xtls-rprx-vision`. Client sends HTTPS request (TLS-inside-VLESS). Assert round-trip. Also assert via log capture or internal counter that Vision mode was entered (padding header emitted). Acceptance criterion #5. Skip if Vision deferred to M1.B-2b. |
| H5 | `vless_wrong_uuid_fails_cleanly` | Real xray with a different UUID. Assert `ConnError::ServerRejected`, not a panic or raw `UnexpectedEof` exposed to the caller. |
| H6 | `vless_delay_probe_populates_history` | End-to-end with api-delay-endpoints handler: `GET /proxies/vless-example/delay?url=…&timeout=5000`. Then `GET /proxies/vless-example` and assert `history` array has ≥ 1 entry with `delay > 0`. Acceptance criterion #13. Cross-spec integration gate. |

### I. Crate-level invariants

| # | Case | Asserts |
|---|------|---------|
| I1 | `vless_adapter_type_is_vless` | `VlessAdapter.adapter_type()` returns `AdapterType::Vless`. Guards the enum variant wiring in `meow-common`. |
| I2 | `vless_support_udp_false_by_default` | Built with `udp: false` → `support_udp() == false`. |
| I3 | `vless_support_udp_true_when_configured` | `udp: true` → `support_udp() == true`. |
| I4 | `no_transport_code_in_vless_src` **[guard-rail]** | Walk `crates/meow-proxy/src/vless/**/*.rs`, assert no line matches `\btokio_tungstenite\b`, `\bTlsConnector\b`, or `\bClientBuilder\b`. All transport plumbing must go through `meow-transport`. Mirrors the VMess plan §J4 grep pattern. |
| I5 | `no_prost_dep_in_vless` **[guard-rail]** | Parse `crates/meow-proxy/Cargo.toml`, assert `prost` is **not** listed as a dependency. Spec §Addon encoding says "do not depend on prost — it is two hardcoded bytes." A direct dep on prost for 18 bytes would violate the footprint goal. |
| I6 | `vision_module_only_present_with_feature` **[guard-rail]** | Compile `crates/meow-proxy` without `vless-vision`; assert `crates/meow-proxy/src/vless/vision.rs` symbols are not reachable (no public export of `VisionConn` in the default build). Checked via the G6 compile step. |

---

## Deferred / not tested here

- **Reality transport** — `reality-opts` hard-error is tested in D9; no
  runtime Reality code exists to test.
- **XTLS-RPRX-Direct / Splice runtime** — hard-errors at parse time (D7,
  D8); no implementation to exercise.
- **VLESS inbound** — not in scope.
- **Mux.Cool runtime** — warn-ignore; D16 tests the config warn.
- **uTLS fingerprint** (`client-fingerprint` field) — accepted and
  forwarded to transport layer; no VLESS-specific behavior to test
  beyond what the transport-layer test plan §A11–A13 covers.
- **Throughput / per-packet allocation** — M2 benchmark harness.
- **Vision fuzzing** — byte-for-byte reference tests in §C are sufficient
  for M1.

---

## Exit criteria for this test plan

- All §A–F, §I cases pass on `ubuntu-latest` and `macos-latest`. None use
  OS-specific APIs; the existing `macos` job picks them up by default once
  the new test files are added to `test.yml`'s per-suite invocation list.
- §G feature-matrix CI jobs green.
- §H integration tests pass on `ubuntu-latest` when `xray` present; skip
  gracefully otherwise. `macos` job uses skip-if-absent, no install step.
- Vision section (§C) requires `vless-vision` feature; CI must pass both
  `--features vless` (Vision excluded) and `--features "vless,vless-vision"`
  (Vision included) to guard against feature-gating regressions.

## CI wiring required

Three additions to `.github/workflows/test.yml`:

1. Add per-suite invocations for:
   - `vless_header_test` (unit tests in `vless/header.rs`)
   - `vless_vision_test` (unit tests in `vless/vision.rs`, `vless-vision` feature)
   - `vless_conn_test` (unit tests in `vless/conn.rs`)
   to both the `test` and `macos` jobs.
2. Add `vless_integration` to the `test` job (ubuntu only), with `xray`
   install step or `MIHOMO_REQUIRE_INTEGRATION_BINS=0`. Same treatment as
   `vmess_integration` and `shadowsocks_integration`.
3. Add §G `cargo check` rows (G1–G6) — six lines, under 10s each after
   cache warms. Include at least one run with `--features vless` (no
   Vision) to guard the cfg-gating.

## Open questions for engineer (none blocking)

1. **Addr encoding dedup.** Spec says delegate to `vmess::addr` when that
   module exists, or duplicate with a TODO. If the VMess PR lands first,
   confirm the import path and remove the duplicate. If VLESS lands first,
   leave the TODO. Either way, the §A tests work against whichever module
   provides the encoding — just note in the PR which path was taken.
2. **`PADDING_RANGE` upstream value.** C2 requires the test to assert the
   exact upstream constant. Engineer must grep `transport/vless/vision/vision.go`
   for the range, pin it in `vision::PADDING_RANGE`, and add the upstream
   commit SHA cite comment. Tell me the range and I'll update C2 with the
   exact value before the PR is merged.
3. **Vision detection for `vless-vision` disabled.** When the feature is
   off, `flow: xtls-rprx-vision` in YAML hard-errors at parse (D21). But
   what happens if someone calls `dial_tcp` on an adapter that was somehow
   built with `flow = Some(XtlsRprxVision)` on a no-vision build? Should
   `#[cfg(not(feature = "vless-vision"))]` make that enum variant
   unconstructible? Architect's call — the simplest fix is to make
   `VlessFlow::XtlsRprxVision` itself cfg-gated so it cannot be
   constructed without the feature.
