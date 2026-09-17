# Design: boring-based TLS backend for ECH + uTLS fingerprinting

**Status:** Draft — historical implementation plan. The shipped workspace is
currently pinned to `boring = 4.22.0` / `tokio-boring = 4.22.0` until a
crates.io `quiche` release newer than `0.29.3` allows `boring` 5.x; see
issue [#572](https://github.com/meow-rs/meow-rs/issues/572).  
**Author:** dev  
**Date:** 2026-04-12  
**Tracking:** issue #32 (fingerprint stub), related to transport-layer.md  

---

## 1. Decision summary

Team-lead chose **Option A**: use `boring` + `tokio-boring` (BoringSSL Rust bindings) as the
primary TLS backend for any connection that has `client-fingerprint` or `ech-opts` set.
`tokio-rustls` remains for all other connections (the common case).

---

## 2. Crate / dependency changes

### New dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `boring` | `5.0.2` | BoringSSL bindings — `SslConnectorBuilder`, cipher/curve/extension APIs |
| `tokio-boring` | `5.0.0` | Tokio async wrapper around boring — `SslConnector`, `SslStream` |

Both are Cloudflare-maintained. License: OpenSSL License + ISC (permissive; compatible with
the workspace's MIT license).

Both crates are gated behind a new cargo feature `boring-tls` (see §8). They must **not** be
pulled into the default build to avoid the C toolchain requirement on CI workers that don't need
fingerprinting.

### Existing dependencies retained

`tokio-rustls` and `rustls` remain. The boring backend activates only when `fingerprint` or
`ech` is set in `TlsConfig`. All existing callers that use neither feature continue to use the
rustls path with no code changes.

### Workspace `Cargo.toml` additions (boring-tls feature)

```toml
[features]
boring-tls = ["dep:boring", "dep:tokio-boring"]

[dependencies]
boring     = { version = "5.0.2", optional = true }
tokio-boring = { version = "5.0.0", optional = true }
```

---

## 3. `TlsConfig` struct changes

### New fields

```rust
/// `ech-opts` block from YAML.
pub ech: Option<EchOpts>,
```

`fingerprint: Option<String>` already exists (line 100 of `tls.rs`). Its semantics change from
"store and warn" to "store and act on" when the `boring-tls` feature is enabled.

### New enum

```rust
/// Source of the ECH config list. DNS sourcing is deferred (see §9).
pub enum EchOpts {
    /// Inline base64-decoded ECH config list bytes.
    /// YAML key: `ech-opts.config` (base64 string, decoded by meow-config before
    /// constructing TlsConfig).
    Config(Vec<u8>),
}
```

DNS-sourced ECH (`ech-opts.enable = true` without `ech-opts.config`) is **deferred** until
`meow-dns` gains SVCB/HTTPS record query support. The enum is defined now so the config schema
is stable.

### YAML keys (mirror Go upstream)

| YAML key | TlsConfig field | Notes |
|----------|----------------|-------|
| `ech-opts.enable` | triggers `ech: Some(EchOpts::Config(...))` when `config` also set | `enable: true` alone (DNS path) is a parse error in v1 |
| `ech-opts.config` | `EchOpts::Config(base64_decoded_bytes)` | decoded by meow-config |
| `ech-opts.query-server-name` | deferred | reserved, parse-and-ignore in v1 |
| `client-fingerprint` | `fingerprint: Option<String>` | existing field, same YAML key |

---

## 4. `TlsLayer` internals

### Backend dispatch

`TlsLayer` becomes an internal enum that the caller never sees:

```rust
pub struct TlsLayer(TlsBackend);

enum TlsBackend {
    Rustls(RustlsInner),        // existing path, unchanged
    #[cfg(feature = "boring-tls")]
    Boring(BoringInner),
}
```

`TlsLayer::new(&TlsConfig)` returns:
- `TlsBackend::Boring` if `config.fingerprint.is_some() || config.ech.is_some()` AND the
  `boring-tls` feature is compiled in.
- `TlsBackend::Rustls` otherwise (including when `boring-tls` is absent but fingerprint is set
  — the existing stub-warn path continues to run).

`Transport::connect` dispatches to the active backend. The return type is always
`Box<dyn Stream>`, so callers are unaffected.

### BoringInner construction

```
boring::ssl::SslConnector::builder(SslMethod::tls_client())?
  -> apply_common_settings()   // ALPN, SNI, skip-verify, client-cert, additional-roots
  -> apply_fingerprint()       // cipher list, curves, GREASE, permute-extensions
  -> .build()                  // SslConnector (Arc-like, cheap to clone)
```

Per-connection:
```
connector.configure()?
  -> set ECH config list (see §4b)
  -> ssl.connect(server_name, inner_stream)
  -> Box<SslStream<inner>>
```

### 4a. Boring API mapping for common TLS settings

| TlsConfig field | boring API |
|----------------|------------|
| `sni` | `connector.configure()?.set_use_server_name_indication(true)` + `ssl.connect(hostname, ...)` |
| `alpn` | `ctx_builder.set_alpn_protos(wire_format_bytes)` |
| `skip_cert_verify = true` | `ctx_builder.set_verify(SslVerifyMode::NONE)` |
| `skip_cert_verify = false` | `ctx_builder.set_verify(SslVerifyMode::PEER)` + load CA store |
| `client_cert` | `ctx_builder.set_certificate(...)` + `set_private_key(...)` |
| `additional_roots` | `ctx_builder.cert_store_mut().add_cert(...)` |

The boring crate does not have an `InsecureCertVerifier` struct — `set_verify(NONE)` replaces
our existing `InsecureCertVerifier` implementation entirely. The one-time `warn!` on
skip-cert-verify is preserved in `TlsLayer::new`.

### 4b. ECH wiring

BoringSSL exposes `SSL_set1_ech_config_list(ssl, data, len)` for client-side ECH. In the boring
Rust crate this maps to a method on `SslRef` or `ConnectConfiguration`.

**Verification required before implementation**: the boring v5.0.2 public API docs show
`SslRef::get_ech_retry_configs()` and `SslRef::ech_accepted()` (indicating ECH awareness), but
the setter `set_ech_config_list` is not confirmed wrapped. The implementation PR must verify this
against boring source at `boring/src/ssl/mod.rs` and add an `unsafe` FFI call via
`boring-sys::SSL_set1_ech_config_list` if the safe wrapper is absent.

ECH also forces TLS 1.3; boring enforces this automatically when an ECH config list is set
(matching Go upstream's `MinVersion = TLS13` enforcement in `component/ech/ech.go:24–30`).

---

## 5. ClientHello shaping strategy

boring provides three context-level knobs that together approximate the Go upstream fingerprint
profiles from `github.com/metacubex/utls` (`u_parrots.go`):

| boring API | What it controls |
|-----------|-----------------|
| `ctx_builder.set_cipher_list(s)` | TLS 1.2 cipher suite order |
| `ctx_builder.set_curves_list(s)` | supported_groups + initial key_share selection |
| `ctx_builder.set_grease_enabled(true)` | GREASE values in ciphers, extensions, and named groups; also injects ECH GREASE extension automatically |
| `ctx_builder.set_permute_extensions(true)` | randomise extension order (Chrome behaviour since v106) |
| `ctx_builder.set_sigalgs_list(s)` | signature_algorithms extension content |

These do **not** reproduce the full per-extension spec from `UTLSIdToSpec` but produce a
ClientHello that is indistinguishable from a real browser to passive observation by a DPI box,
which is the goal. Active TLS fingerprint databases (e.g. JA3) would still see the correct
cipher/curve fingerprint.

### V1 fingerprint set and boring parameters

Reference: `u_common.go` (metacubex/utls, master branch):
- `HelloChrome_Auto = HelloChrome_120` (line 600)
- `HelloFirefox_Auto = HelloFirefox_120` (line 590)
- `HelloSafari_Auto = HelloSafari_16_0` (line 640)
- `HelloIOS_Auto = HelloIOS_14` (line 629)
- `HelloAndroid_11_OkHttp` (line 634)
- `HelloEdge_Auto = HelloEdge_85` (line 636)

Reference profile: `HelloChrome_120` (`u_parrots.go` lines 665–736). That profile uses:
- Cipher suites: GREASE + TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
  TLS_CHACHA20_POLY1305_SHA256, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256,
  ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305,
  ECDHE-RSA-CHACHA20-POLY1305, ECDHE-RSA-AES128-SHA, ECDHE-RSA-AES256-SHA, AES128-GCM-SHA256,
  AES256-GCM-SHA384, AES128-SHA, AES256-SHA
- Groups: GREASE, X25519, P-256, P-384
- Extension permutation: `ShuffleChromeTLSExtensions` → `set_permute_extensions(true)`
- GREASE: throughout → `set_grease_enabled(true)`

| YAML value | boring cipher list | curves | grease | permute | sigalgs |
|-----------|-------------------|--------|--------|---------|---------|
| `chrome` / `chrome120` | Chrome 120 list (above) | `X25519:P-256:P-384` | yes | yes | P256+SHA256, RSA-PSS+SHA256/384/512, RSA+SHA256/384/512, P384+SHA384 |
| `firefox` / `firefox120` | Firefox 120 list (u_parrots.go:1197) | `X25519:P-256:P-384:P-521` | no | no | ECDSA-P256, RSA-PSS, RSA legacy order |
| `safari` / `safari16` | Safari 16 list (u_parrots.go:1851) | `X25519:P-256:P-384` | no | no | Safari sig alg order |
| `ios` | iOS 14 list (u_parrots.go:1510) | `X25519:P-256:P-384` | no | no | iOS sig alg order |
| `android` | Android 11 OkHttp list (u_parrots.go:1595) | `P-256:X25519` | no | no | OkHttp order |
| `edge` | Edge 85 = Chrome 83 base (u_parrots.go:1641) | `X25519:P-256:P-384` | yes | no | Chrome 83 order |
| `random` | pick chrome/safari/ios/firefox with weights 6:3:2:1 at construction time | per pick | per pick | per pick | per pick |

The exact cipher string, sigalgs string, and curve string per profile must be finalized during
implementation by reading the corresponding `UTLSIdToSpec` case in `u_parrots.go` and
translating to OpenSSL cipher-list syntax.

### Version-pinned aliases (v1 supported)

`chrome120` → chrome profile, `firefox120` → firefox profile, `safari16` → safari profile.
These are aliases for user convenience to pin to a specific version. Treated identically to
their `_Auto` equivalents in v1 (same boring parameters).

### Deferred fingerprints

`randomized`, `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`,
`chrome_pq_psk`, `360`, `qq` — out of scope for v1. If set, emit the existing stub warning.

---

## 6. Stream integration

`tokio_boring::SslStream<S>` implements `AsyncRead + AsyncWrite + Unpin + Send + Sync` when
`S: AsyncRead + AsyncWrite + Unpin + Send + Sync` (verified from docs.rs/tokio-boring/5.0.0).
`meow-transport`'s `Stream` trait (defined at `crates/meow-transport/src/lib.rs:53`) is a
blanket impl over exactly that bound:

```rust
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}
```

`SslStream<Box<dyn Stream>>` therefore satisfies the `Stream` trait automatically. No adapter
needed. `Transport::connect` can return `Box::new(ssl_stream)` as `Box<dyn Stream>` with no
wrapper.

---

## 7. Build system impact

`boring-sys` vendors BoringSSL source and builds it via `cmake` at compile time.

| Dimension | Impact |
|-----------|--------|
| Build toolchain | Requires cmake 3.14+, a C++ compiler (clang or gcc), and Ninja (or make) |
| macOS | Works with Xcode Command Line Tools; no extra steps |
| Linux (Ubuntu/Debian) | `apt install cmake clang` — standard in CI images |
| Windows | Requires MSVC or cross-compilation; boring-sys has Windows support but adds ~5 min build time |
| Binary size | BoringSSL static lib adds approximately 8–12 MB to the release binary |
| Compile time | Clean build adds ~2–4 min on a typical 8-core CI worker |
| Incremental builds | Not affected (boring-sys caches the cmake build artifact) |

The existing `ring`-based rustls crypto provider remains for the rustls path. There is **no
shared crypto provider** between the two backends; they each carry their own.

---

## 8. Migration plan for existing callers

Three proxy files call `TlsLayer::new`:

| File | TlsConfig fields set | Path after change |
|------|---------------------|------------------|
| `crates/meow-proxy/src/trojan.rs:55–61` | `skip_cert_verify`, `sni` | rustls (no fingerprint/ECH) — **zero change** |
| `crates/meow-proxy/src/v2ray_plugin.rs:147–151` | `skip_cert_verify`, `sni` | rustls — **zero change** |
| `crates/meow-proxy/src/vless_adapter.rs` (test helpers) | `sni` only | rustls — **zero change** |

The `TlsLayer::new` call signature does not change. The dispatch happens internally based on the
presence of `fingerprint`/`ech` fields. Existing callers need no modifications.

New proxy types (e.g. a future VLESS with fingerprint) would set `TlsConfig.fingerprint` and
automatically receive the boring backend.

---

## 9. Cargo feature gating

**Recommendation: yes, gate behind `boring-tls` feature.**

Rationale:
- `boring-sys` requires a C++ toolchain and cmake. Without gating, any `cargo build` of the
  workspace fails on machines without these tools (common in developer environments, stripped CI
  images, cross-compilation targets).
- The vast majority of proxy entries never set `client-fingerprint` or `ech-opts`. Making
  8–12 MB of BoringSSL mandatory for all builds is disproportionate.
- Feature gating is idiomatic Rust for optional heavy C dependencies (cf. `reqwest`'s
  `rustls-tls` / `native-tls` split).

Behaviour when `boring-tls` is **not** enabled and `fingerprint` or `ech` is set:
- `fingerprint`: existing `warn_fingerprint_once` stub continues to run (no regression).
- `ech`: `TlsLayer::new` returns `Err(TransportError::Config("ech-opts requires the boring-tls
  feature"))`.

Release builds shipped to end users should enable `boring-tls` by default in the release
profile or via a workspace feature.

---

## 10. What is deferred

| Item | Reason |
|------|--------|
| DNS HTTPS-record ECH config sourcing (`ech-opts.enable` without `ech-opts.config`) | Requires SVCB/HTTPS record query support in `meow-dns` (hickory-resolver HTTPS records exist but no wrapper in this repo) |
| ECH retry-on-rejection | Needs per-connection `SslConnector` rebuild with `get_ech_retry_configs()` result; complex async flow |
| `randomized` fingerprint profile | Requires per-connection weight-sampled extension list; deferred until boring extension-level API is better understood |
| `randomized` custom profiles | Requires per-connection weight-sampled extension list; deferred until boring extension-level API is better understood |
| Deprecated fingerprints (`chrome_psk`, etc.) | Actively discouraged upstream; not implemented |
| `360`, `qq` fingerprints | Low demand outside China-specific deployments; deferred |
| Windows CI build verification | boring-sys Windows support exists but untested in this repo |
