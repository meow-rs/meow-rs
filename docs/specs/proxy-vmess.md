# Spec: VMess outbound

> **Status: DROPPED** — excluded from M1 scope by decision 2026-04-11.
> Preserved as a design record in case VMess is revisited in a future milestone.
> Do not implement against this spec without a new product decision reversing
> the drop. See `docs/roadmap.md` §M1.B for rationale.

Status: Draft (pm 2026-04-11, awaiting architect review) — *superseded by drop decision above*
Owner: pm
Tracks roadmap item: **M1.B-1**
Depends on: **M1.A-1** (tls layer), **M1.A-2** (ws layer); gRPC/H2/HTTPUpgrade
optional, gated by config. Does **not** depend on M1.A-3/M1.A-4 for a
first-shippable version.
Related gap-analysis row: VMess outbound (§1, **Gap**).

## Motivation

VMess is the native outbound protocol for v2ray/xray/mihomo subscription
ecosystems. It predates the modern Trojan/Hysteria wave but remains
ubiquitous: ~60 % of real Clash Meta subscription files sampled in the
gap-analysis exercise contain at least one VMess node. Without it,
meow-rs cannot load a "typical" user's config, which is the stated
M1 exit gate in `vision.md`.

Upstream Go mihomo implements VMess in `transport/vmess/` as a family of
files: `conn.go` (stream wrapper), `aead.go` (header encryption),
`user.go` (UUID → key derivation), `encoding.go` (request/response
format), and `vmess.go` (top-level adapter). The protocol has three
discrete sub-variants that must all work for real-world compat:

1. **AEAD header mode** — the modern default since v2ray ~4.35. Header
   is encrypted with AES-128-GCM keyed off the UUID + a 16-byte auth ID.
2. **Legacy MD5 header mode** — pre-AEAD, keyed off the UUID +
   `timestamp ± 30 s`. Still seen in older subscriptions and Iran/China
   deployments that never updated. **Behind a cargo feature flag**
   (`vmess-legacy`), off by default.
3. **AlterID > 0** — legacy multi-user header obfuscation. Deprecated
   upstream (accepted but warned). We match: accept in config, emit
   warn-once, and treat as `alterId=0` at runtime.

The protocol runs over any byte stream, so transport composition (TLS,
WS, gRPC, H2, HTTPUpgrade) happens *outside* the VMess adapter via the
`meow-transport` layer chain. The VMess adapter only frames
payload and header bytes.

## Scope

In scope:

1. New file `crates/meow-proxy/src/vmess.rs` implementing
   `VmessAdapter: ProxyAdapter`.
2. AEAD header mode (AES-128-GCM) — the default.
3. Three body cipher suites: `aes-128-gcm`, `chacha20-poly1305`, and
   `none` (plaintext, for testing and for `security: none` nodes).
4. `auto` body cipher negotiation: pick `aes-128-gcm` on CPUs with
   hardware AES, `chacha20-poly1305` otherwise. Matches upstream.
5. TCP outbound (`network: tcp` and `network: ws` via transport chain).
   gRPC/H2/HTTPUpgrade transports compile if their features are enabled
   but are not required for spec acceptance.
6. UDP-over-TCP multiplexing via the VMess `cmd: 0x02` (UDP) opcode.
   Required for DNS-over-VMess and for apps like QUIC-over-VMess that
   tunnel UDP.
7. Integration with the existing `ProxyHealth` field (per the
   api-delay-endpoints spec), connection stats, and rule matching.
8. YAML config parser in `meow-config` for the `proxies: [{ type: vmess }]`
   variant, matching upstream's field set.

Out of scope (defer to follow-ups):

- **Legacy MD5 header mode** — implemented but gated behind a cargo
  feature flag `vmess-legacy`, off by default. Spec covers the feature
  flag; the implementation is a stretch goal for the same PR and may be
  split into M1.B-1b if bandwidth is tight.
- **Mux.Cool** (`mux: { enabled: true }`) — upstream's in-band connection
  multiplexer. Out of scope for M1; defer to M1.5 or M2. Parser accepts
  the field with a warn-once ("VMess mux.cool is not implemented;
  connections will not be multiplexed") per the divergence rule.
- **XTLS** variants — reserved for VLESS, not VMess.
- **VMess inbound** — we are not shipping a VMess server. Subscription
  clients only.
- **Experimental v5 protocol** — `alpha` status upstream, no real-world
  deployments. Hard-reject at parse time.

## Non-goals

- Implementing the legacy MD5 mode on the default build path. Crypto
  surface is small but the timestamp-window code is notoriously
  fingerprintable and we don't want it hot-pathed for new users.
- Re-implementing an AEAD primitive. Use BoringSSL's `boring::aead`
  (already linked for TLS; meow-proxy `src/aead.rs`, issue #659).
- Emulating upstream's internal buffer pool (`pool.Get/Put`). Tokio's
  `BytesMut` + reuse in the read loop is sufficient.
- Config-parser-level negotiation of VMess protocol version. We only
  speak AEAD version `0x01` on the wire; config `alterId` is stripped
  to 0 at load time.

## User-facing config

YAML schema (matches upstream; divergences called out inline):

```yaml
proxies:
  - name: vmess-example
    type: vmess
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0                  # deprecated; > 0 warned and coerced to 0
    cipher: auto                # auto | aes-128-gcm | chacha20-poly1305 | none
    udp: true                   # enable UDP-over-TCP relay
    tls: true
    servername: example.com     # SNI; defaults to `server` if absent
    skip-cert-verify: false
    fingerprint: ""             # reserved; see transport-layer spec
    client-fingerprint: chrome  # accepted and warned, see transport-layer spec
    alpn: [h2, http/1.1]
    network: ws                 # tcp | ws | grpc | h2 | httpupgrade
    ws-opts:
      path: /vmess
      headers:
        Host: example.com
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
    grpc-opts:
      grpc-service-name: vmess
    h2-opts:
      host: [example.com]
      path: /
```

Field semantics (abbreviated — full table in the field-reference
subsection below):

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `uuid` | string | yes | — | RFC 4122 UUID. Used as the VMess user ID and the AEAD header key seed. Hex or dashed form both accepted. |
| `alterId` | integer | no | `0` | Deprecated. `> 0` logs a warn-once and is coerced to `0`. Non-negative integers are parsed; negative values are a parse error. |
| `cipher` | enum | no | `auto` | Body AEAD cipher. `auto` selects AES-GCM on AES-NI hardware, ChaCha20-Poly1305 otherwise. `none` uses no body encryption (payload is plaintext but header is still AEAD-encrypted). `zero` from upstream is **rejected** at parse time: it disables body encryption while the config still reads `vmess`, so a user inheriting the file has no visual cue their traffic is plaintext-over-VMess (security gap per [ADR-0002](../adr/0002-upstream-divergence-policy.md)). |
| `udp` | bool | no | `false` | Enables UDP-over-TCP framing. When true, `ProxyAdapter::support_udp()` returns true. |
| `network` | enum | no | `tcp` | Outer transport. Delegated to `meow-transport` layer chain per M1.A spec. `tcp` = naked TCP, no transport layers. |
| `tls` | bool | no | `false` | Wrap the transport in TLS via `meow-transport::tls`. Set automatically when `network` requires TLS (e.g. `ws` with `wss://`-style path). |

**Divergences from upstream**:

1. **`alterId > 0` is warn-and-coerce, not a hard error.** Upstream
   accepts legacy values; we do too for config compat, but runtime
   always treats as 0. Documented loudly so users with old subscriptions
   see *why* their nodes silently upgraded. Per the divergence rule from
   the sniffer spec: not a security gap (alterId provided zero real
   security — it was a fingerprinting obfuscator), only a code-path
   change.
2. **`cipher: zero`** (an experimental "length-only" mode from upstream)
   is hard-rejected at parse time. Per the divergence rule: silently
   ignoring would let a user assume they have a bespoke cipher
   configuration when they don't.
3. **`experimental: true`** flag (upstream v5) is hard-rejected.
4. **`mux: { enabled: true }`** is warn-and-ignore per §Scope out-of-scope.

## AEAD header format (the part that trips every port)

This section is verbose because it's where most VMess implementations
break. The wire format is fixed; any deviation causes the server to
drop the connection with no clear error.

### Key derivation

Let `UUID` be the 16-byte form of the user ID. Derive:

```
cmd_key     = MD5(UUID || "c48619fe-8f02-49e0-b9e9-edf763e17e21")   // 16 bytes
auth_id_key = KDF16("AES Auth ID Encryption", cmd_key)              // 16 bytes
header_key  = KDF16("VMess Header AEAD Key", cmd_key, connection_nonce)
header_iv   = KDF(12, "VMess Header AEAD Nonce", cmd_key, connection_nonce)
```

Where `KDF` is the upstream-defined keyed HMAC cascade:

```
KDF(L, label, ...path) -> L bytes
  HMAC-SHA256-based, with repeated hashing layers per path element
```

The upstream reference lives in `transport/vmess/aead/encrypt.go::KDF`.
**Do not reimplement this from scratch** — port it line-by-line and add
a byte-exact unit test against upstream's reference vectors (see §Test
plan, case `aead_kdf_matches_upstream_vectors`).

The 16-byte string `"c48619fe-8f02-49e0-b9e9-edf763e17e21"` is a hard
constant shared by all v2ray-compatible implementations. It is
documented in upstream comments as "a historical accident" — keep the
comment when porting so future readers don't try to parameterise it.

### Auth ID generation (8-byte request header)

```
now      = current unix timestamp (u64, little-endian? no — big-endian!)
rand4    = 4 random bytes
zero_crc = CRC32 of (now_be || rand4)
auth_id  = AES-128-ECB-encrypt(key=auth_id_key, block=(now_be || rand4 || zero_crc))
```

Total 16 bytes. Sent as the first 16 bytes of the AEAD header.

Timestamp is **big-endian 8-byte unix seconds**, not little-endian.
Upstream uses `binary.BigEndian.PutUint64`. Getting this wrong sends a
valid-looking header that the server rejects as replay; confusing
because the bytes look random either way.

### Request header layout (AEAD mode)

```
[0..16]   auth_id                                (AES-ECB, see above)
[16..18]  length_of_encrypted_header (u16 BE)
[18..34]  length_auth_tag (16 bytes, AES-GCM tag for length)
[34..N]   encrypted_header_payload               (AES-GCM)
[N..N+16] payload_auth_tag (16 bytes)
```

Where the *plaintext* header is:

```
version(1)    = 0x01
req_iv(16)    = 16 random bytes — used as body cipher IV seed
req_key(16)   = 16 random bytes — used as body cipher key seed
resp_v(1)     = 1 random byte — used to match response header
opts(1)       = bitmask: S(0x01)=standard, R(0x02)=reuse_tcp, M(0x04)=metadata_obfs, P(0x08)=padding
p(4)+sec(4)   = padding_len(4 bits) || security(4 bits)
reserved(1)   = 0x00
cmd(1)        = 0x01 TCP, 0x02 UDP
port(2)       = destination port, BE
addr_type(1)  = 0x01 IPv4, 0x02 domain, 0x03 IPv6
address       = variable, see below
random        = `padding_len` random bytes (per opts byte)
fnv1a(4)      = FNV-1a hash of everything from version(1) through random
```

Then AEAD-encrypted with `header_key` + `header_iv`.

### Address encoding (the other thing that trips every port)

This is the single most common source of "my VMess node doesn't
connect" bugs. Get this wrong and the tunnel silently opens, sends
garbage to the wrong destination, and the server tears down with no
diagnostic.

Three cases, keyed on `addr_type`:

| addr_type | Layout | Notes |
|-----------|--------|-------|
| `0x01` (IPv4) | 4 bytes, network order | Straightforward. |
| `0x02` (domain) | `len(1)` followed by `len` UTF-8 bytes | **`len` is a single u8, max 255 bytes.** Upstream enforces this. A domain > 255 chars (rare but possible with punycode) must fail at **adapter build time**, not silently truncate at send time. |
| `0x03` (IPv6) | 16 bytes, network order | Straightforward. |

**Gotchas:**

1. **No scheme prefix.** `example.com`, not `tcp://example.com`. Upstream
   strips the scheme before encoding; we do too in `parse_server_addr`.
2. **Port comes BEFORE addr_type**, not after. The order is
   `port(2) || addr_type(1) || addr_data`. Reversing produces a valid
   record that the server parses as a bogus port and drops.
3. **Domain length byte is separate from padding.** The padding opt in
   the header is a different field — do not conflate them when counting
   bytes for the FNV-1a hash input.
4. **Punycode is not automatic.** Upstream accepts raw UTF-8 and lets
   the server handle IDN. We do the same. Engineer: do not call
   `idna::to_ascii` — let the server do it. Rationale: upstream-compat.

Add `// upstream: transport/vmess/encoding.go::EncodeRequestHeader` as
an inline comment at the encoder site. When someone reports "VMess
broken for this one domain", the comment tells the debugger which file
to diff against.

### Response header format

The server replies with a 4-byte plaintext preamble:

```
resp_v(1)    = the 1 random byte from request
opts(1)      = bitmask; 0x01 = keep-alive (reserved, ignored by us)
cmd(1)       = server-side command (0x00 = none)
cmd_len(1)   = length of cmd data (0 for cmd=0x00)
```

Then body bytes follow, encrypted with the response cipher (see §Body
cipher section). The 1-byte `resp_v` match is the adapter's only
response validation — if it mismatches, tear the connection down.
Upstream does the same.

## Body cipher section

After the header AEAD, both sides switch to a body cipher for the
payload. Three variants:

### `aes-128-gcm`

There is no `"VMess Body AEAD Key"` KDF on the wire. The request
direction uses the per-connection material **directly**:

```
req_body_key = req_key            // 16 bytes, as-is
req_body_iv  = req_iv             // 16 bytes, as-is
```

The response direction hops through SHA-256:

```
resp_body_key = SHA256(req_key)[..16]
resp_body_iv  = SHA256(req_iv)[..16]
```

Payload is a sequence of length-prefixed AEAD records:

```
[len(2) BE] [ciphertext][tag(16)]
```

Per-record nonce is `counter_be16 || body_iv[2..12]` — the counter
**overwrites** the first two bytes of the IV (starts at 0, increments
per record; not an XOR). Length is the ciphertext length **including**
the tag (not just the plaintext length) — upstream compat, easy to get
wrong.

### `chacha20-poly1305`

Same record layout and the same request/response seeds; only the key
expansion differs (ChaCha wants a 32-byte key):

```
body_key = MD5(seed) || MD5(MD5(seed))   // 32 bytes, seed = req or resp key
```

The MD5-cascade body_key is a v2ray legacy quirk (v2ray derived the
32-byte ChaCha key from the 16-byte VMess key via double MD5 instead of
using KDF). Preserved for compat.

### `none`

No body encryption, but record **framing is still present** —
`OPT_STANDARD` advertises chunk streaming regardless of security type,
so the payload still carries `[len(2) BE][plaintext]` records. Used for
testing and for `security: none` nodes that rely on the outer transport
(WS+TLS) for security.

### `auto`

Runtime check: if `std::arch::is_x86_feature_detected!("aes")` or the
ARM equivalent, use `aes-128-gcm`; otherwise `chacha20-poly1305`. Match
upstream's preference order.

## Internal design sketch

### Struct + trait impl

```rust
// crates/meow-proxy/src/vmess.rs

pub struct VmessAdapter {
    name: String,
    server: String,
    port: u16,
    uuid: Uuid,
    cmd_key: [u8; 16],
    body_cipher: BodyCipher,    // Aes128Gcm | ChaCha20Poly1305 | None
    udp: bool,
    transport: TransportChain,  // from meow-transport
    health: ProxyHealth,
    dialer: Arc<dyn TcpDialer>,
}

#[async_trait]
impl ProxyAdapter for VmessAdapter {
    fn name(&self) -> &str { &self.name }
    fn adapter_type(&self) -> AdapterType { AdapterType::Vmess }
    fn addr(&self) -> &str { /* "server:port" */ }
    fn support_udp(&self) -> bool { self.udp }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let raw = self.dialer.dial(&self.server, self.port, metadata.is_internal()).await?;
        let wrapped = self.transport.connect(raw).await?;
        let conn = VmessConn::new(
            wrapped,
            &self.cmd_key,
            self.body_cipher,
            Cmd::Tcp,
            metadata,
        ).await?;
        Ok(Box::new(conn))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.udp { return Err(Error::UdpNotSupported); }
        let raw = self.dialer.dial(&self.server, self.port, metadata.is_internal()).await?;
        let wrapped = self.transport.connect(raw).await?;
        let conn = VmessPacketConn::new(
            wrapped,
            &self.cmd_key,
            self.body_cipher,
            Cmd::Udp,
            metadata,
        ).await?;
        Ok(Box::new(conn))
    }

    fn health(&self) -> &ProxyHealth { &self.health }
}
```

Note the `transport` field: VMess itself knows nothing about TLS/WS/gRPC.
The transport chain is composed at config-load time from the `network` +
`tls` + `ws-opts` etc. fields and stored as a `TransportChain` (a
`Vec<Box<dyn Transport>>` wrapper that iterates `connect` through each
layer). This is the payoff for the M1.A work — VMess becomes a 300-LOC
adapter plus a 400-LOC protocol module, zero transport code.

### File layout inside `meow-proxy/src/vmess/`

```
vmess.rs            // VmessAdapter, config parsing, trait impl (~250 LOC)
vmess/
├── mod.rs          // pub use
├── aead.rs         // KDF, auth_id, header encrypt/decrypt (~200 LOC)
├── body.rs         // BodyCipher record framing, directional AEAD schedules
├── conn.rs         // VmessConn (TCP wrapper) + VmessPacketConn (~200 LOC)
└── addr.rs         // Address encoding + decoding (~80 LOC, heavily tested)
```

Total ~1000 LOC. Legacy MD5 mode adds ~150 LOC behind the
`vmess-legacy` feature flag if bundled; otherwise 0.

### Config parsing

`meow-config/src/proxy_parser.rs::parse_vmess` grows to handle the
full field set above. The transport chain is built by calling into a
new helper `meow-config::transport_chain::build(network, opts) ->
TransportChain` which the other M1.B protocols (VLESS) will reuse.

### Error surface

Engineer note: VMess failures are almost all silent on the wire. The
server just closes the connection. Differentiate these four failure
modes in logs:

1. Transport layer error (TLS handshake, WS upgrade) — clearly
   attributable to the `network: ws` / `tls: true` stack.
2. Header AEAD encryption error at the adapter (crypto bug, our fault).
3. Body framing error (our fault; tag mismatch, length overflow).
4. Server tore down the connection (their fault; wrong UUID, wrong
   cipher, blocklisted, etc.) — this manifests as `UnexpectedEof` on
   the first `read()` after sending the header.

Log each with a distinct `tracing::debug!` message and a
`vmess::ConnError` enum variant so the user can grep the failure mode
from the log.

### Feature flag

```toml
[features]
default = ["vmess"]
vmess = ["dep:aes-gcm", "dep:chacha20poly1305", "dep:hmac", "dep:sha2", "dep:md5"]
vmess-legacy = ["vmess"]
```

`md5` is a separate dep behind the default `vmess` feature because the
modern AEAD path uses MD5 for the `cmd_key` derivation — unavoidable,
it's in the protocol spec. `vmess-legacy` adds nothing new dependency-wise
but gates the legacy-header code path.

## Acceptance criteria

A PR implementing this spec must:

1. `cargo build -p meow-proxy --no-default-features --features vmess`
   produces a working VMess outbound that compiles without `ws`, `grpc`,
   `h2`, or `httpupgrade` transports.
2. `cargo build --no-default-features --features "vmess,ws,tls"`
   produces a VMess-over-WS-over-TLS outbound. This is the minimum
   feature set needed to replace a real subscription.
3. TCP relay works against a real upstream `xray` server configured for
   VMess AEAD. Integration test at
   `crates/meow-proxy/tests/vmess_integration.rs` spawns a local
   `xray` binary (skipped in CI if binary absent, same pattern as
   `ssserver`), connects, and round-trips a payload.
4. UDP relay works via the same `xray` server for a DNS query target.
5. Body cipher `auto` picks `aes-128-gcm` on a CPU with AES-NI and
   `chacha20-poly1305` on one without. Unit test mocks the feature
   detection.
6. `cipher: none` + `tls: true` + `network: ws` round-trips traffic.
7. `alterId: 16` in config produces exactly one warn-once at load and
   does not appear in the wire header (coerced to 0).
8. `cipher: zero` hard-errors at parse time with a clear message
   citing the divergence rule.
9. Wire-format byte-exact tests against reference vectors generated by
   upstream (see §Test plan) — at least `aead_kdf_matches_upstream_vectors`
   and `header_encode_matches_upstream_for_known_uuid`.
10. A `VMess → VMess-over-WS → VMess-over-WS+TLS` config loaded from
    YAML produces three distinct `TransportChain` shapes, verified by
    unit test.
11. The adapter's `ProxyHealth` integrates with the api-delay-endpoints
    probe path (criterion lifted from that spec).
12. Address encoding has 100% branch coverage in `addr.rs` unit tests.
    This is the highest-risk module; no excuse to ship it undertested.

## Test plan (starting point — qa owns final shape)

Applying the divergence-comment convention from
`feedback_spec_divergence_comments.md` on bullets that touch
upstream-compat behaviour.

**Unit (`vmess/addr.rs`):**

- `addr_encode_ipv4` — `127.0.0.1:443` → `0x01 0x01bb 0x01 7f.00.00.01`.
  Upstream: `transport/vmess/encoding.go::EncodeRequestHeader` addr block.
  NOT `0x01 addr 0x01bb` (reversed port order — the port comes BEFORE
  addr_type, and we test this explicitly because the spec's bullet lists
  them addr-first for human readability).
- `addr_encode_ipv6` — `[::1]:443` → `0x01 0x01bb 0x03 ::1`.
- `addr_encode_domain` — `example.com:80` → `0x01 0x0050 0x02 0x0b
  e x a m p l e . c o m`. Length byte `0x0b` = 11.
- `addr_encode_domain_max_255` — exactly 255 chars succeeds.
- `addr_encode_domain_over_255_errors_at_build_time` — 256 chars fails
  at adapter build, not encode time.
  Upstream: truncates silently (we don't — that's a bug in upstream,
  we diverge towards safety). NOT a silent truncate.
- `addr_encode_domain_idn_not_punycoded` — `例え.jp` → raw UTF-8 bytes,
  not `xn--` form. Upstream: `transport/vmess/encoding.go` passes the
  host string through verbatim. We match.
- `addr_decode_round_trip` — every encoded variant round-trips
  through a decoder used in tests.

**Unit (`vmess/aead.rs`):**

- `aead_kdf_matches_upstream_vectors` — hard-coded reference vectors
  from upstream's `transport/vmess/aead/encrypt_test.go`. Byte-exact.
  Upstream: `transport/vmess/aead/encrypt.go::KDF`.
  NOT "structurally equivalent" — byte-exact or the spec is broken.
- `cmd_key_matches_upstream_for_known_uuid` — fixed UUID
  `b831381d-6324-4d53-ad4f-8cda48b30811`, assert `cmd_key` matches the
  reference value. Guards against MD5 input-ordering bugs.
- `auth_id_generates_unique_per_nonce` — 1000 calls, no collisions in
  the 8-byte timestamp-random prefix (statistical; not byte-exact).
- `auth_id_timestamp_is_big_endian` — specific test for the BE
  timestamp bug. Assert the first 8 bytes decode as a plausible
  current unix timestamp when read BE, not LE.
  Upstream: `binary.BigEndian.PutUint64`. NOT LE (most common port bug).
- `header_encode_matches_upstream_for_known_uuid` — full header encode
  with fixed UUID, fixed body_key/iv, fixed random source → exact byte
  sequence. Reference vector generated by running upstream's own
  encoder once and committing the output under
  `tests/fixtures/vmess_header_reference.bin`.
- `header_decode_round_trip` — encode then decode, match plaintext.

**Unit (`vmess/body.rs`):**

- `body_aes_128_gcm_record_round_trip`.
- `body_chacha20_poly1305_record_round_trip`.
- `body_chacha_key_derivation_uses_md5_cascade` — assert the double-MD5
  key, not a KDF-derived 32-byte key.
  Upstream: `transport/vmess/aead.go::ChaCha20Poly1305Key`.
  NOT KDF — preserved legacy quirk.
- `body_none_is_passthrough`.
- `body_record_length_includes_tag` — feed a 100-byte plaintext, assert
  the wire length prefix is `100 + 16`, not `100`.
  Upstream: `transport/vmess/aead.go::AEADAuthenticator.Write`. NOT
  plaintext length — the most common body-framing bug.
- `body_nonce_counter_increments_per_record` — three records, assert
  per-record nonce differs and follows the XOR-counter pattern.

**Unit (`vmess.rs` config parser):**

- `parse_vmess_minimal_config_ok`.
- `parse_vmess_alterid_gt_zero_warns_and_coerces` — `alterId: 16` →
  runtime struct has `alter_id: 0`, tracing capture has one warn.
  Upstream: `adapter/outbound/vmess.go` silently accepts and ignores.
  We match behaviour, add the warn as a user-visible nudge.
- `parse_vmess_cipher_zero_hard_errors` — `cipher: zero` →
  `ConfigError::UnsupportedCipher`.
  Upstream: silently accepts `zero` and runs with a length-only cipher.
  NOT silent; hard error per divergence rule (security/evasion gap —
  user assumes they have a real cipher).
- `parse_vmess_mux_enabled_warns_and_ignores` — per divergence rule.
- `parse_vmess_network_ws_builds_transport_chain` — parsed struct has
  `transport: [Tls, Ws]` in order, with the WS opts threaded through.

**Integration (`vmess_integration.rs`, new file):**

Follows the `ssserver` pattern in `shadowsocks_integration.rs` — the
skip-if-absent message names the exact binary (`xray`, not
`xray-core`) and the install hint (`go install
github.com/xtls/xray-core/main@latest` or the official release
tarball), matching the ssserver pattern.

- `vmess_tcp_roundtrip` — spawn local `xray` on a random port
  with a fixed UUID fixture, connect via `VmessAdapter`, send a
  payload to a loopback echo server through the tunnel, assert
  bidirectional bytes match. Skipped if `xray` binary missing.
- `vmess_tcp_auto_cipher_on_aesni` — same, with `cipher: auto`, on a
  CPU with AES-NI detected. Assert the auto-selected cipher is
  AES-128-GCM by inspecting `VmessAdapter.body_cipher` after build.
- `vmess_ws_tls_roundtrip` — local xray configured for VMess-over-WS-
  over-TLS with a self-signed cert, `skip-cert-verify: true`,
  transport chain `[Tls, Ws]`. Assert round-trip.
- `vmess_udp_roundtrip` — UDP relay of a DNS query to `8.8.8.8:53`.
  Skipped if `xray` or a loopback DNS server absent.
- `vmess_wrong_uuid_fails_cleanly` — real xray with a different UUID.
  Assert adapter surfaces `ConnError::ServerRejected` (mapped from
  `UnexpectedEof` on the first read), not a transport error.
- `vmess_delay_probe_populates_history` — end-to-end with the
  api-delay-endpoints handler: call `GET /proxies/vmess-example/delay`,
  assert `history` on the next `/proxies` call shows the measured
  delay. Cross-spec integration gate.

**Feature-matrix (`cargo check` rows, mirroring the transport-layer
test plan):**

- `vmess` alone — must compile without any transport layers.
- `vmess,tls` — must compile.
- `vmess,tls,ws` — must compile. This is the real-world minimum.
- `vmess,tls,ws,grpc,h2,httpupgrade` — must compile. Full feature set.
- `vmess-legacy` — if bundled with this PR, must compile and pass the
  legacy-mode test cases. If split into M1.B-1b, this row doesn't
  apply until that PR lands.

## Implementation checklist (for engineer handoff)

- [ ] Add the `vmess` feature to `crates/meow-proxy/Cargo.toml` with
      the dep list above.
- [ ] Port `KDF` from `transport/vmess/aead/encrypt.go` line-by-line.
      Add the `aead_kdf_matches_upstream_vectors` test with reference
      values committed under `tests/fixtures/`.
- [ ] Implement `addr.rs` with the encoder/decoder. 100% branch
      coverage required by criterion #12.
- [ ] Implement `aead.rs` (header encrypt/decrypt). Reference vector
      test must pass before wiring anything else.
- [ ] Implement `body.rs` (all three cipher variants). Per-record
      nonce counter, `len = cipher + 16` prefix.
- [ ] Implement `VmessConn` + `VmessPacketConn` in `conn.rs`.
- [ ] Implement `VmessAdapter` in `vmess.rs` composing the above with
      the `meow-transport` chain.
- [ ] Register `AdapterType::Vmess` variant in
      `crates/meow-common/src/adapter_type.rs`.
- [ ] Wire YAML parsing in `meow-config/src/proxy_parser.rs` with
      all divergences (warn-coerce for alterId, hard-error for
      `cipher: zero`, warn-ignore for mux).
- [ ] Add the transport-chain builder helper in
      `meow-config/src/transport_chain.rs` (new file) for reuse by
      M1.B-2 VLESS.
- [ ] Add all unit + integration tests from §Test plan.
- [ ] Grep upstream `transport/vmess/` one more time before submitting
      to catch any constant I forgot to call out in this spec. The
      reference commit should be pinned in a `// UPSTREAM: vmess@<sha>`
      header at the top of `aead.rs` and `addr.rs`, per the pattern
      from the transport-layer test plan.
- [ ] Update `docs/roadmap.md` M1.B-1 row with the merged PR link.
- [ ] Open follow-up task M1.B-1b for legacy MD5 mode if split from
      this PR.

## Open questions (architect input requested)

1. **Transport chain storage on the adapter**: the spec sketches
   `transport: TransportChain` as a field on `VmessAdapter`. Is that
   the right shape, or do you want the chain stored once on `AppState`
   and referenced by name from the adapter? The single-field approach
   is simpler and what I wrote; the shared approach avoids duplicating
   identical rustls configs across N VMess nodes on the same server.
   My read: single-field is fine for M1 — rustls configs are ~50 KB
   each and N is small. Flag for your call though.

2. **Legacy MD5 mode — bundle or split?** Spec allows either. My lean
   is bundle: it's ~150 extra LOC, uses the same AEAD primitive crate,
   and shipping "VMess but not the legacy header mode" is confusing
   for users. But if you want the feature flag policed hard, split
   into M1.B-1b and this PR lands AEAD-only first.

3. **`cipher: zero` — hard-error or warn-ignore?** I wrote hard-error
   per the divergence rule (user assumes real cipher). But upstream
   does accept it. If you'd rather match upstream, flip to warn-ignore
   and update the acceptance criterion.
