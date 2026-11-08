# VLESS Reality Design and Test Plan

**Status:** draft for issue #225  
**Branch:** `fix/vless-reality`  
**Last updated:** 2026-11-07  

This document records the local implementation design and validation method for
VLESS + Reality + XTLS-Vision. The runtime test sample is
`/tmp/meow-reality-one.yml`, but this document intentionally does not include
real proxy server details.

## Redaction Rules

Do not write the following values into docs, GitHub issues, PR descriptions, or
public logs:

- Proxy `server`, `port`, `servername` / SNI, and real node names.
- `uuid`, `reality-opts.public-key`, and `reality-opts.short-id`.
- Full downloaded subscription configs or expanded provider node content.
- Raw `RUST_LOG=debug` logs that include real node fields.

Use placeholders in docs and shared logs:

```yaml
mixed-port: 18080
mode: rule
log-level: debug
ipv6: false
allow-lan: false

proxies:
  - name: reality-sample
    type: vless
    server: <redacted-host>
    port: <redacted-port>
    uuid: <redacted-uuid>
    tls: true
    client-fingerprint: chrome
    servername: <redacted-sni>
    flow: xtls-rprx-vision
    reality-opts:
      public-key: <redacted-reality-public-key>
      short-id: <redacted-short-id>
      support-x25519mlkem768: false
```

`/tmp/meow-reality-one.yml` is a local test sample and must not be committed.
Downloaded subscription configs should stay under `/tmp`, for example
`/tmp/meow-clash.yml`.

## Design Constraints

- Do not use a third-party Reality / XTLS / VLESS protocol implementation.
- Do not vendor xray or mihomo code.
- It is acceptable to reference `/Users/jiawengeng/code/mihomo` for behavior and
  wire layout, but the implementation must live in meow-rs crates.
- The Reality TLS state machine, ClientHello construction, TLS 1.3 key schedule,
  TLS record encryption/decryption, Reality certificate authentication, and
  XTLS-Vision DIRECT switching are implemented in this repository.
- Low-level cryptography uses generic primitives or existing TLS backend
  primitives: AES-GCM, HMAC-SHA256/SHA512, SHA256/SHA512, and BoringSSL X25519.
  No third-party Reality protocol library is used.
- Reality currently requires the `boring-tls` feature because config parsing
  requires `client-fingerprint`, and X25519 primitives are available through the
  existing BoringSSL feature path.

## Support Scope

Implemented scope:

- VLESS outbound.
- `tls: true` with `reality-opts`.
- TCP path for `flow: xtls-rprx-vision`.
- Default curl HTTPS smoke test, which should negotiate HTTP/2.
- `curl --http1.1` HTTPS smoke test as a comparison case.

Out of scope:

- VLESS inbound / server mode.
- Vision UDP splice. UDP still uses plain VLESS and logs a config warning.
- Mux.Cool.
- Committing the test sample or subscription nodes as repository fixtures.

## Config Entry Point

`meow-config` parses `reality-opts` in the VLESS parser:

- `public-key`: base64 RawURL without padding. The decoded value must be a
  32-byte X25519 public key.
- `short-id`: hex string up to 8 bytes. The decoded value is zero-padded to
  8 bytes.
- `support-x25519mlkem768`: boolean. Offers an X25519MLKEM768 key share (with
  its own X25519 key) ahead of X25519; Xray REALITY servers >= 26.9.8 require it.

Config constraints:

- `reality-opts` requires `tls: true`.
- `reality-opts` requires `client-fingerprint`, so users do not accidentally
  get ordinary TLS semantics while expecting Reality.
- Without `boring-tls`, `TlsLayer::new` returns a config error for Reality.
- `reality-opts` and `ech-opts` cannot be used on the same TLS layer.

Data flow:

```text
YAML VLESS proxy
  -> meow-config::parse_vless
  -> meow_transport::tls::TlsConfig { reality: Some(RealityConfig) }
  -> meow_transport::tls::TlsLayer::new
  -> RealityTlsLayer
  -> VlessConn
  -> VisionConn when flow = xtls-rprx-vision
```

## Reality TLS Implementation

Implementation file: `crates/meow-transport/src/reality_tls.rs`.

Handshake flow:

1. Generate a per-connection X25519 ephemeral private/public key pair.
2. Compute the Reality auth key from the server Reality public key.
3. Build a TLS 1.3 ClientHello:
   - SNI comes from `servername`, falling back to `server`.
   - ALPN comes from YAML `alpn`.
   - `key_share` sends X25519; with `support-x25519mlkem768: true` an
     X25519MLKEM768 share is the first real share, ahead of X25519 (a
     GREASE entry may still lead the list) — the ML-KEM-768 encapsulation
     key concatenated with a dedicated X25519 key of its own (not the
     REALITY auth share's; one key in both shares is a "not Xray"
     fingerprint tell), as current Xray REALITY servers require.
   - `session_id` contains Reality auth data: version, timestamp, and short-id,
     sealed with an AES-GCM key derived from the auth key.
4. Send the plaintext TLS handshake record.
5. Read ServerHello and validate:
   - The server echoed the ClientHello `session_id`.
   - TLS 1.3 was negotiated.
   - `key_share` is X25519, or X25519MLKEM768 when it was offered.
   - The picked cipher suite is one of `TLS_AES_128_GCM_SHA256`,
     `TLS_AES_256_GCM_SHA384` or `TLS_CHACHA20_POLY1305_SHA256`.
6. Run the handwritten TLS 1.3 handshake/application key schedule.
7. Decrypt EncryptedExtensions, Certificate, CertificateVerify, and Finished.
8. Verify the Reality certificate signature HMAC with the Reality auth key.
9. Send client Finished and enter application data record mode.

`RealityTlsStream` is responsible for:

- Application data record `poll_read` / `poll_write`.
- Ordered draining of pending encrypted records.
- `poll_write` semantics where, after user plaintext has been copied into an
  internal pending record, it returns `Ok(buf.len())`; later writes first drain
  the pending encrypted record to preserve ordering.
- Directional raw passthrough:
  - `enable_raw_read_passthrough`
  - `enable_raw_write_passthrough`

Directional read/write passthrough is required for Vision DIRECT. The write
side switches only after the local DIRECT padding frame is fully drained. The
read side switches only after the server DIRECT padding frame is fully drained.

## XTLS-Vision DIRECT Implementation

Implementation files:

- `crates/meow-proxy/src/vless/conn.rs`
- `crates/meow-proxy/src/vless/vision.rs`
- `crates/meow-proxy/src/vless_adapter.rs`

Key design points:

- `VisionConn` owns a concrete `VlessConn`, not `Box<dyn Stream>`. DIRECT needs
  to reach the underlying Reality stream and enable raw passthrough; downcasting
  through an extra trait object wrapper was not reliable.
- Client write direction:
  - Detect inner TLS ClientHello.
  - Write a Vision padding frame.
  - After inner TLS application data starts, send `COMMAND_PADDING_DIRECT` or
    `COMMAND_PADDING_END`.
  - Enable raw write passthrough after the DIRECT frame has fully drained.
- Server read direction:
  - Parse server Vision padding frames.
  - Scan the first few packets for TLS 1.3 ServerHello.
  - Allow DIRECT only when both the cipher suite and supported_versions indicate
    TLS 1.3.
  - Enable raw read passthrough after server DIRECT padding has fully drained.
- `poll_flush` and `poll_shutdown` drain pending Vision frames before forwarding
  to the inner connection.

## Why Default curl HTTP/2 Must Pass

For HTTPS, default curl often negotiates HTTP/2 through ALPN. That path reaches
inner TLS application data quickly and exercises XTLS-Vision DIRECT/raw
passthrough.

If the Reality TLS stream keeps wrapping DIRECT data in TLS records, or if
Vision switches raw read/write passthrough at the wrong time, HTTP/2 fails.
`curl --http1.1` may still pass, so testing HTTP/1.1 alone is not sufficient.

The e2e acceptance test must include default curl with HTTP/2 allowed. The
expected result is `http_code=204` and `http_version=2`.

## Unit and Build Tests

Formatting:

```bash
cargo fmt --check
```

Application build:

```bash
cargo check -p meow-app --features boring-tls
```

Reality TLS transport tests:

```bash
cargo test -p meow-transport --features boring-tls
```

VLESS Reality config parsing tests:

```bash
cargo test -p meow-config --test vless_config_test --features boring-tls
```

Vision DIRECT / ServerHello filter tests:

```bash
cargo test -p meow-proxy --features vless-vision vision --lib
```

Important coverage:

- Reality ClientHello writes a 32-byte `session_id`.
- HKDF label expansion basic length.
- `reality-opts` without `client-fingerprint` skips that proxy.
- `reality-opts` without `tls: true` skips that proxy.
- Invalid Reality public key skips that proxy.
- Invalid or overlong short-id skips that proxy.
- Valid Reality config loads with `boring-tls`.
- Vision padding frame layout.
- TLS ClientHello detection.
- TLS 1.3 ServerHello detection.
- Fragmented TLS record header handling.
- Non-TLS1.3 cipher rejection.

## Config Sample Test

`/tmp/meow-reality-one.yml` is the single-node Reality test sample. First run
config validation:

```bash
cargo run -p meow-app --features boring-tls -- -f /tmp/meow-reality-one.yml -t
```

Expected:

- Exit code is 0.
- No real node fields are printed.
- The Reality VLESS proxy is registered.

To test a user-provided full subscription, download it to `/tmp` and do not
commit it:

```bash
SUB_URL='<user-provided-subscription-url>'
curl -fsSL "$SUB_URL" -o /tmp/meow-clash.yml
cargo run -p meow-app --features boring-tls -- -f /tmp/meow-clash.yml -t
```

The full subscription may contain currently unsupported proxy types such as
`hysteria2`, and groups may warn after referenced proxies are skipped. The
acceptance focus is:

- Config loading does not panic.
- VLESS Reality nodes are no longer rejected just because `reality-opts` exists.
- Warnings do not leak real node fields.

## e2e Smoke Test

If port 18080 already has an old process, either use a sample with another
listener port or confirm the old process is the intended test process. Do not
kill a process the user may be observing without confirming it first.

Start meow:

```bash
RUST_LOG=meow=info,meow_config=warn,meow_proxy=debug,meow_tunnel=debug,meow_transport=debug \
cargo run -p meow-app --features boring-tls -- -f /tmp/meow-reality-one.yml
```

Default curl, HTTP/2 acceptance:

```bash
curl -fsS --max-time 30 \
  --proxy socks5h://127.0.0.1:18080 \
  https://www.gstatic.com/generate_204 \
  -o /tmp/meow-reality-generate-204.out \
  -w 'http_code=%{http_code} http_version=%{http_version} time_total=%{time_total}\n'
```

Expected:

```text
http_code=204 http_version=2
```

HTTP/1.1 comparison:

```bash
curl -fsS --http1.1 --max-time 30 \
  --proxy socks5h://127.0.0.1:18080 \
  https://www.gstatic.com/generate_204 \
  -o /tmp/meow-reality-generate-204-http11.out \
  -w 'http_code=%{http_code} http_version=%{http_version} time_total=%{time_total}\n'
```

Expected:

```text
http_code=204 http_version=1.1
```

Acceptance interpretation:

- Default curl passes but reports `http_version=1.1`: HTTP/2 was not covered;
  check whether the local curl supports HTTP/2 and whether the target negotiated
  h2.
- `--http1.1` passes but default curl fails: treat this as a Vision DIRECT /
  Reality raw passthrough regression.
- Both fail: the e2e smoke test fails and needs code or environment
  investigation before merge.

## Current Validation Record

Local validation during this branch:

- `cargo fmt --check` passed.
- `cargo check -p meow-app --features boring-tls` passed.
- `cargo test -p meow-proxy --features vless-vision vision --lib` passed.
- `cargo test -p meow-transport --features boring-tls` passed.
- `cargo test -p meow-config --test vless_config_test --features boring-tls` passed.
- `/tmp/meow-reality-one.yml` config validation passed.
- Running `/tmp/meow-reality-one.yml`, the default curl HTTPS smoke test returned
  `http_code=204 http_version=2`.
- The HTTP/1.1 comparison smoke test returned `http_code=204 http_version=1.1`.

Before merging, rerun the command set above, especially the default curl HTTP/2
smoke test.
