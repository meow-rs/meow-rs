# Spec: Reusable transport layer (`meow-transport` crate)

Status: Approved (architect 2026-04-18, amendments applied)
Owner: pm
Tracks roadmap item: **M1.A-1 … M1.A-4**
Architecture source of truth: [ADR-0001](../adr/0001-meow-transport-crate.md)

> **Read ADR-0001 first.** This spec deliberately does not restate the
> architectural decisions. It fills in the implementation details the ADR
> leaves to the implementation team: YAML schema mapping, per-layer config
> struct shapes, error taxonomy, and per-layer test plans.
>
> If anything in this spec contradicts ADR-0001, **ADR-0001 wins** and this
> spec must be updated. Any reordering of the build sequence requires
> architect sign-off.

## Motivation

See ADR-0001 §Context. Short version: M1 needs VMess/VLESS, and they
must reuse `tls` and `ws` instead of the current per-adapter copies in
`trojan.rs` and `v2ray_plugin.rs`.

## Scope

In scope for this spec (all four engineer steps from ADR-0001 §Build
sequence):

1. Create `crates/meow-transport` with the `Transport` trait per
   ADR-0001 §2.
2. Ship five layers — `tls`, `ws`, `grpc` (gun), `h2`, `httpupgrade` —
   with the struct shapes, YAML mapping, and tests defined below.
3. Migrate `trojan.rs` and `v2ray_plugin.rs` to consume the new crate.
4. Plumb Cargo features per ADR-0001 §5 so a minimal build can opt out
   of individual layers.

### Interaction with `simple_obfs.rs`

`crates/meow-proxy/src/simple_obfs.rs` is **not** part of M1.A. It
stays exactly where it is today, wired to Shadowsocks. Rationale:
simple-obfs has no meaningful server-side variant in our client-only
trait, the existing code is small and already tested, and sweeping it
into the move would bloat the M1.A PRs for no architectural gain.
Engineer must not touch `simple_obfs.rs` in any M1.A PR. A future ADR
may introduce `meow-transport::obfs` if server-side obfs ever enters
scope; until then, leave it alone.

### Deferred items — quoted verbatim from ADR-0001 §"Open questions deferred"

> - **Server-side transports** (for inbound VMess/VLESS listeners). Out
>   of scope for M1; the trait above is client-only. When inbound
>   protocols come, the trait becomes `Transport::accept(inner) ->
>   Stream` symmetric to `connect`. Plan for this in the API but do
>   not implement yet.
> - **Reality / ShadowTLS / SMUX** — separate ADRs if/when prioritised.

Out of scope (deferred per ADR-0001 §Open questions):

- **Server-side `Transport::accept`.** Client-only trait in M1. Any
  VMess/VLESS spec that tries to introduce inbound listener code is a
  scope bug and must be bounced back.
- **Reality, SMUX / mux.** Separate future ADRs. (`shadow-tls`, `restls`,
  `jls` and `kcptun` have since landed as SIP003 plugin transports:
  `meow-transport` owns the wire protocol, `meow-proxy` owns the
  plugin option surface.)
- **uTLS full fingerprint spoofing.** We accept a
  `client-fingerprint:` YAML key but stub it to a no-op with a
  `tracing::warn!` at startup if set. Surface the warning exactly
  once per distinct value.

## User-facing YAML schema

The upstream YAML shape for transports lives under each proxy entry.
meow-rs accepts the same shape. The table below maps each upstream
key to the layer that consumes it.

### Shared: `tls`

```yaml
proxies:
  - name: my-vmess
    type: vmess          # or trojan, vless, ss (future), ...
    server: example.com
    port: 443
    # --- TLS layer opts ---
    tls: true
    skip-cert-verify: false
    servername: cdn.example.com   # SNI override; falls back to `server`
    alpn: ["h2", "http/1.1"]
    client-fingerprint: chrome    # accepted-but-stub, warns at startup
    # (optional) client cert
    # cert: /etc/meow/client.crt
    # key:  /etc/meow/client.key
```

Rust struct (lives in `meow-transport::tls`):

```rust
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enabled: bool,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub skip_cert_verify: bool,
    pub client_cert: Option<ClientCert>,
    pub fingerprint: Option<String>, // accept-and-warn stub; see "Fingerprint warn text" below
}

#[derive(Debug, Clone)]
pub struct ClientCert {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}
```

Parsing lives in `meow-config` (not in `meow-transport`). Config
builds the `TlsConfig` and hands it to the layer constructor — the
crate boundary rule from ADR-0001 §1 says `meow-transport` never sees
YAML.

**SNI resolution (canonical, amended 2026-04-11 after M1.A-1 review):**
`meow-config` resolves `TlsConfig.sni` before construction:

| YAML `servername:` | YAML `server:` | `TlsConfig.sni`      |
|--------------------|----------------|----------------------|
| set                | any            | `Some(servername)`   |
| unset              | hostname       | `Some(hostname)`     |
| unset              | IP literal     | `Some("1.2.3.4")`    |

For the IP-literal case, `sni = Some("1.2.3.4")` — **not** `None`.
`rustls::pki_types::ServerName::try_from("1.2.3.4")` produces the
`IpAddress` variant, which rustls uses for certificate verification
but does **not** include in the TLS SNI extension (RFC 6066 §3
prohibits IP literals in SNI). This keeps `TlsLayer::new` able to
enforce the invariant `enabled → sni.is_some()` and return
`TransportError::Config` on `None`. (Engineer's M1.A-1 impl diverged
from my earlier Q2 guidance in this direction; the divergence is
correct and becomes canonical.)

**Fingerprint warn text** (verbatim, architect-approved — amended
2026-04-11 during M1.A-1 review to drop the `"on proxy <name>"`
phrase; `TlsConfig` does not carry a proxy name and adding one purely
for log text would leak identity into the transport crate):

```
client-fingerprint="<value>" set on proxy: \
uTLS fingerprint spoofing is not implemented; \
TLS handshake will use rustls defaults. \
See https://github.com/meow-rs/meow-rs/issues/32 \
for real uTLS support.
```

Dedup by distinct `<value>` so a config with 50 vmess proxies all
using `chrome` logs the warning exactly once. Including the proxy
name would be misleading anyway — dedup is by value, so only the
first offending proxy's name would appear.

### `ws` (WebSocket)

```yaml
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
        User-Agent: Mozilla/5.0 ...
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
```

```rust
#[derive(Debug, Clone)]
pub struct WsConfig {
    pub path: String,
    pub host_header: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub max_early_data: usize,
    pub early_data_header_name: Option<String>,
}
```

Notes:

- `max-early-data: 0` (default) disables early data entirely. Default
  is safe because wrong early-data encoding is a silent data-corruption
  bug; adapters that need it (e.g. VMess) flip the knob at their own
  spec's layer-config level, not at the `ws` layer default.
- **`max-early-data` is capped at 2048.** Upstream mihomo leaves it
  unbounded; 2048 follows the Xray/sing-box convention and is a
  deliberate divergence. meow-rs clamps at YAML parse time in
  `meow-config` with a `warn!`, and `WsLayer::connect` re-clamps as a
  backstop for programmatic construction. Do not silently accept 65535.
- `host_header` takes precedence over `extra_headers` with key `Host`,
  but if both are set we log a `warn!` once. The warn fires at
  `WsLayer::new()` time (not per-connect) — the conflict is
  detectable at construction and warning at that boundary avoids
  per-connection log spam on the hot path. (Amended 2026-04-11 during
  M1.A-2 review.)
- The Sec-WebSocket-Protocol early-data encoding matches upstream
  `transport/vmess/websocket.go` — base64url of the first N bytes, no
  padding, capped at `max_early_data`.

### `grpc` (gun)

```yaml
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
```

```rust
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub service_name: String, // goes into the :path pseudo-header
}
```

The layer hard-codes `content-type: application/grpc` and the framing
described in ADR-0001 §3 table. No protobuf; one unit test (below)
asserts the on-wire byte sequence matches upstream byte-for-byte.

### `h2` (plain HTTP/2 stream)

```yaml
    network: h2
    h2-opts:
      path: /
      host:
        - example.com
        - cdn.example.com
```

```rust
#[derive(Debug, Clone)]
pub struct H2Config {
    pub path: String,
    pub hosts: Vec<String>, // uniformly random per connection
}
```

**Host selection: uniform random per connection**, matching upstream
`transport/vmess/h2.go`:

```go
host := hc.cfg.Hosts[randv2.IntN(len(hc.cfg.Hosts))]
```

No shared state on `H2Layer` — each `connect()` call picks an index
via `rand::seq::SliceRandom::choose`. Round-robin was the wrong default
because an Nth-connection-always-hits-host-N-mod-M pattern leaks a
fingerprint to on-path observers; the whole point of h2 + multi-host is
browser-style camouflage.

Use `rand.workspace = true` under the `h2`/`grpc` feature gates — the
workspace already pins `rand = "0.9"`. `SliceRandom::choose` is
unchanged across 0.8→0.9 for our call site. Already in the dependency
tree via `rustls`, so zero footprint cost. (Architect correction,
2026-04-11, answering engineer Q3 — earlier "0.8" text was stale.)

### `httpupgrade`

```yaml
    network: httpupgrade
    http-upgrade-opts:
      path: /upgrade
      host: cdn.example.com
      headers:
        X-Custom: foo
```

```rust
#[derive(Debug, Clone)]
pub struct HttpUpgradeConfig {
    pub path: String,
    pub host_header: Option<String>,
    pub extra_headers: Vec<(String, String)>,
}
```

## Internal design sketch

### Trait (from ADR-0001, repeated for reference only)

```rust
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>>;
}
```

Layers compose by stacking:

```rust
let tcp: Box<dyn Stream> = tcp_connect(addr).await?;
let tls_stream = tls_layer.connect(tcp).await?;
let ws_stream  = ws_layer.connect(tls_stream).await?;
// ws_stream is the Box<dyn Stream> handed to the VMess protocol codec
```

### Error taxonomy

`meow-transport` exposes one error type:

```rust
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls handshake: {0}")]
    Tls(String),
    #[error("websocket handshake: {0}")]
    WebSocket(String),
    #[error("grpc framing: {0}")]
    Grpc(String),
    #[error("http upgrade: {0}")]
    HttpUpgrade(String),
    #[error("invalid config: {0}")]
    Config(String),
}
```

Adapters (VMess, VLESS, Trojan) convert `TransportError` into
`MeowError::Proxy(...)` at the crate boundary. The conversion lives
in `meow-proxy` (not in `meow-common` or `meow-transport`),
preserving ADR-0001 §1's leaf-crate rule.

**Form: free function, not `From` impl.** The orphan rule blocks
`impl From<TransportError> for MeowError` in `meow-proxy` because
both types are foreign to that crate. The canonical shape is:

```rust
// crates/meow-proxy/src/lib.rs
pub(crate) fn transport_to_proxy_err(e: TransportError) -> MeowError {
    MeowError::Proxy(e.to_string())
}
```

Call sites use `.map_err(transport_to_proxy_err)?` instead of `?`. The
ergonomic cost is trivial and grep-ability is higher than a `From`
impl would be. (Architect decision 2026-04-11, answering engineer Q1
and correcting an earlier suggestion that assumed the `From` impl
could live in `meow-proxy` — the orphan rule says otherwise.)

Invariants the review enforces: **no adapter constructs
`TransportError` variants by hand, and no `anyhow::Error` ever crosses
the `meow-transport` boundary**. The crate-invariants test suite
(`tests/crate_invariants_test.rs`) enforces the second one
mechanically via a grep over `src/`.

The transport crate itself never constructs `MeowError`.

### Cargo features

Default workspace feature set:

```toml
# crates/meow-transport/Cargo.toml
[features]
default = ["tls", "ws"]
tls = ["dep:tokio-rustls", "dep:rustls-pki-types", "dep:webpki-roots"]
ws  = ["dep:tokio-tungstenite"]
grpc = ["dep:h2", "dep:http", "dep:rand"]
h2   = ["dep:h2", "dep:http", "dep:rand"]
httpupgrade = ["dep:httparse"]
```

> **Intentional dep sharing:** `grpc` and `h2` both depend on the `h2`
> crate and `rand`. This is deliberate — the gun framing sits on top of
> an HTTP/2 stream, and both layers want uniform random host/path
> selection. Cargo dedupes, so a user enabling just `grpc` still pays
> for `h2` exactly once. Do not split them by accident in a future PR
> trying to "save a crate" — you can't.

`meow-app` enables `tls,ws,grpc,h2,httpupgrade` by default; router/
embedded profiles flip off whatever they don't need. The M2
minimal-build budget is measured against `--no-default-features
--features "tls,ws"`.

### Migration of existing code

Per ADR-0001 §4, the engineer does this in two steps interleaved with
the layer work:

**Step M1.A-1.migrate** (after `tls` layer lands):

- `crates/meow-proxy/src/trojan.rs`: delete its inline rustls setup;
  build a `TlsLayer` from the existing Trojan YAML fields and call
  `tls_layer.connect(tcp).await?`.
- Keep all Trojan protocol logic (password hash prefix, CRLF,
  SOCKS-style address encoding) in `trojan.rs`.
- Gate: `cargo test --test trojan_integration` stays green.

**Step M1.A-2.migrate** (after `ws` layer lands):

- `crates/meow-proxy/src/v2ray_plugin.rs`: becomes a SIP003-opts
  parser that builds `[TlsLayer, WsLayer]` and returns the resulting
  stream to the SS adapter.
- Gate: `cargo test --test v2ray_plugin_integration` stays green (this
  test is now in CI via qa's #1).

No behaviour change is allowed in either migration step — tests must
stay green without being touched.

## Acceptance criteria

Per-layer, **all of the following** must hold before the layer is
considered merged:

1. Struct shape matches the "Rust struct" block in the YAML schema
   section above.
2. YAML parsing in `meow-config` produces the struct from a fixture
   YAML file under `crates/meow-config/tests/fixtures/`.
3. Unit tests listed under **Test plan** pass.
4. Cargo feature gate works: `cargo check --no-default-features
   --features "<only this layer>"` builds, and
   `--no-default-features` (nothing) also builds (transport crate
   provides only the trait).
5. For `tls` and `ws`: the corresponding migration step from §Migration
   is complete and the relevant integration test still passes.

Crate-wide:

6. `meow-transport` has no dependency on `meow-proxy`, `meow-dns`,
   or `meow-config`. `cargo tree -p meow-transport` shows only
   `meow-common` from our workspace. Enforced by a shell test in CI
   (`grep -v` on `cargo tree` output).
7. `client-fingerprint:` YAML key is accepted, stored on `TlsConfig`,
   and emits exactly one `warn!` per distinct value at startup —
   asserted by a log-capture test.
8. **No server-side code.** Grep the merged PR for `accept`, `bind`,
   `listen`, `Server`, `Acceptor`, and `TcpListener` inside
   `meow-transport` and fail the review if any of them appear
   outside `tests/` helpers. The last one catches the
   `use tokio::net::TcpListener as _` case the other patterns would
   miss.

## Test plan (starting point — qa owns final shape)

Tests live under `crates/meow-transport/tests/`. Each layer gets its
own binary so they can be filtered individually.

### `tls`

- `tls_connect_cert_ok` — in-process rustls server with a
  self-signed cert; client uses `rustls-pemfile` to trust it; expect
  Ok and assert `peer_addr`.
- `tls_connect_bad_cert_errs` — same, but client does not trust cert
  and `skip_cert_verify = false`; expect `TransportError::Tls(_)`.
- `tls_skip_verify_connects` — flip `skip_cert_verify = true`, expect
  Ok. Assert a `warn!` is emitted (use `tracing-test`).
- `tls_alpn_negotiated` — server offers `h2`, client prefers
  `["h2","http/1.1"]`, assert the negotiated ALPN == `h2`.
- `tls_sni_override` — client sets SNI to a name different from the
  dial host, server captures `server_name`, assert match.
- `tls_fingerprint_warn_once` — set `fingerprint = Some("chrome")`
  twice with the same value, assert exactly one warn.

### `ws`

- `ws_handshake_upgrade` — tungstenite loopback server, client sends
  an Upgrade with custom headers, assert the server saw them.
- `ws_host_header_override` — assert `Host: cdn.example.com` reached
  the server when `host_header` is set.
- `ws_early_data_encoded_in_protocol_header` — set
  `max_early_data = 32`, write 16 bytes, assert the server received
  the bytes via the `Sec-WebSocket-Protocol` base64url mechanism (not
  a data frame).
- `ws_host_conflict_warns` — set both `host_header` and
  `extra_headers["Host"]`, assert one warn and that `host_header` won.

### `grpc` (gun)

- `grpc_framing_matches_upstream` — encode a 1 KiB payload via the
  layer, decode it with a reference implementation (copy upstream
  `transport/gun/gun.go`'s framer into `tests/reference_gun.rs` as
  ~50 LOC), assert byte-for-byte equality in both directions.
- `grpc_service_name_in_path` — assert the `:path` pseudo-header is
  `/{service_name}/Tun`.
- `grpc_content_type_header` — assert `application/grpc` is sent.
- `grpc_round_trip` — loopback `h2` server, round-trip 4 MiB across
  the layer, assert bytes match.

### `h2`

- `h2_round_trip` — loopback, round-trip 1 MiB.
- `h2_host_selection_is_uniform` — 1000 connections with
  `hosts = [a,b,c,d]`, assert every host appears at least once. Cheap
  deflake of "stuck on index 0" without flaking on fairness bounds. (A
  stricter ±3σ test on N=10000 is nice-to-have but flaky under CI
  scheduler noise; engineer to pick the cheaper test.)

### `httpupgrade`

- `httpupgrade_101_switching_protocols` — mock server returns `101`
  with matching `Upgrade:` header, then raw bytes; assert raw bytes
  round-trip.
- `httpupgrade_non_101_fails` — server returns `200`; expect
  `TransportError::HttpUpgrade(_)`.

### Crate-level

- `no_proxy_dep` — shell test: `cargo tree -p meow-transport 2>&1 |
  grep -qv 'meow-proxy'`. Runs in the lint job.
- `feature_minimal_builds` — CI matrix adds three `cargo check` rows:
  `--no-default-features`, `--no-default-features --features tls`, and
  `--no-default-features --features "tls,ws"`.

### Integration gates (must stay green across the migration)

- `cargo test --test trojan_integration` — Trojan over the new TLS
  layer.
- `cargo test --test v2ray_plugin_integration` — SS + v2ray-plugin over
  the new TLS + WS chain.

## Implementation checklist (for engineer handoff)

- [ ] **M1.A-1** Create `crates/meow-transport`, add to workspace,
      implement `Transport` trait + `Stream` blanket impl + shared
      `TransportError`.
- [ ] **M1.A-1** Implement `tls` layer (`TlsConfig`, `TlsLayer`).
- [ ] **M1.A-1.migrate** Rewrite `trojan.rs` to use `TlsLayer`; keep
      `trojan_integration` green.
- [ ] **M1.A-1** Land all `tls` unit tests + the `no_proxy_dep` shell
      test.
- [ ] **M1.A-2** Implement `ws` layer (`WsConfig`, `WsLayer`).
- [ ] **M1.A-2.migrate** Rewrite `v2ray_plugin.rs` to use
      `[TlsLayer, WsLayer]`; keep `v2ray_plugin_integration` green.
- [ ] **M1.A-2** Land all `ws` unit tests.
- [ ] **— VMess (M1.B-1) can start here —**
- [ ] **M1.A-3** Implement `grpc` (gun) layer behind `grpc` feature;
      land all `grpc` unit tests including the byte-for-byte framing
      test against a reference implementation.
- [ ] **M1.A-4** Implement `h2` and `httpupgrade` layers behind their
      features; land layer unit tests.
- [ ] **M1.A-4** Add the three feature-matrix `cargo check` rows to
      `test.yml`.
- [ ] Update `docs/roadmap.md` M1.A rows with merged PR links as each
      step lands.

## Forbidden scope (do not expand this spec without architect sign-off)

- Do not add a `Transport::accept` method. Server-side is a separate
  ADR, not a spec revision.
- Do not add `reality`, `smux`, or any layer not listed in ADR-0001 §3.
  (`shadow-tls`, `restls`, `jls` and `kcptun` were added later as SIP003
  plugin transports — new layers still need an ADR.)
- Do not route YAML parsing through `meow-transport`. Config lives
  in `meow-config` and hands pre-built structs across the crate
  boundary.
- Do not implement uTLS fingerprint spoofing (accept-and-warn only).
