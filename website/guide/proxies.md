# Proxies

The `proxies` list defines outbound connections. Every entry needs a `name` and a
`type`; the remaining fields depend on the protocol. Names are referenced from
[proxy groups](./proxy-groups) and [rules](./rules). A name may not shadow a
built-in (`DIRECT`/`REJECT`/`REJECT-DROP`/`COMPATIBLE`/`PASS`/`PASS-RULE`); a
repeated leaf name is tolerated and the last declaration wins.

```yaml
proxies:
  - name: hk-01
    type: trojan
    server: example.com
    port: 443
    password: "•••"
```

## Built-in proxies

These always exist and need no definition:

| Name | Behavior |
| --- | --- |
| `DIRECT` | Connect straight to the destination, no proxy |
| `REJECT` | Silently close the connection |
| `REJECT-DROP` | Drop packets with no response |
| `COMPATIBLE` | Dial direct, tagged `Compatible` (mihomo compat) |
| `PASS` | As a rule target: skip the rule silently and keep matching |
| `PASS-RULE` | Inside `SUB-RULE` blocks: skip the inner rule; at top level it rejects |

## Common fields

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | — | **Required.** Unique identity |
| `type` | string | — | **Required.** Protocol (below) |
| `dialer-proxy` | string | — | Reach this server *through* another proxy/group (chained dialing). UDP-capable transports (e.g. kcptun's KCP sessions) tunnel their datagrams over the front proxy's UDP association too. Static-config cycles are rejected at load; a cycle that only forms through dynamic provider group membership fails the dial with a named error at 16 hops. Also honoured on provider-sourced nodes and via `override.dialer-proxy` on the provider; the value must name a top-level `proxies:`/`proxy-groups:` entry — provider node names are not valid targets |

Several protocols are gated behind Cargo features (`ss`, `trojan`, `vless`, `vmess`,
`hysteria2`, `snell`, `anytls`). Default builds enable the common set.

---

## Shadowsocks — `ss`

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | Hostname or IP |
| `port` | u16 | ✓ | — | 1–65535 |
| `password` | string | ✓ | — | |
| `cipher` | string | ✓ | — | e.g. `aes-256-gcm`, `chacha20-ietf-poly1305` |
| `udp` | bool | | `false` | Enable UDP relay |
| `plugin` | string | | — | `obfs`, `v2ray-plugin`, `gost-plugin`, `shadow-tls`, `restls`, `jls`, `kcptun`, `ech-tls-tunnel` (built-in, no external binary) |
| `plugin-opts` | string \| map | | — | Plugin options |

```yaml
- name: ss-obfs
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: "•••"
  udp: true
  plugin: obfs
  plugin-opts:
    mode: http        # or tls
    host: bing.com
```

`gost-plugin` runs in-process too — a WebSocket transport with optional
TLS and smux. Upstream defaults apply: `host` defaults to `bing.com` and
`mux` to `true` (a fresh smux session per connection).

```yaml
- name: ss-gost
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: "•••"
  plugin: gost-plugin
  plugin-opts:
    mode: websocket      # required
    host: cdn.example.com
    path: /ws
    tls: true
    mux: true            # default; smux session per connection
    # headers: {CF-Token: "…"}   # a Host entry also sets the TLS SNI
    # skip-cert-verify: false
    # name-cert-verify: real.example.com
    # fingerprint: "AA:BB:…"   # SHA-256 cert pin (SSL pinning), not uTLS
    # certificate: /path/client.pem   # mTLS — inline PEM or a file path
    # private-key: /path/client.key   # both or neither
```

`certificate`/`private-key` accept inline PEM or a filesystem path
(relative paths resolve against the config home, `-d`). When they name
files, meow re-stats them on every dial and hot-reloads the client
certificate when the contents change — matching upstream's fswatch
behaviour without a watcher. A corrupt or half-written reload is ignored
with a warning: the last known-good pair keeps serving, and the pair is
re-read as soon as either file changes again (any fix bumps mtime,
length, inode, or ctime). Inline PEM values are immutable, as they are
upstream.

`shadow-tls` runs in-process too — a cover-TLS record transport with all
three upstream protocol versions. `host` (cover SNI) and `version`
(1/2/3) are required; `strict-mode: true` refuses non-TLS-1.3 covers.

```yaml
- name: ss-stls
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: "•••"
  plugin: shadow-tls
  plugin-opts:
    host: cover.example.com   # required — cover server name (TLS SNI)
    version: 3                # required — 1, 2 or 3
    password: "psk"
    # alpn: h2,http/1.1       # default; explicit `alpn:` suppresses the extension
    # strict-mode: false      # v3: fail unless the cover negotiates TLS 1.3
    # skip-cert-verify: false
    # fingerprint: "AA:BB:…"  # SHA-256 cert pin, not uTLS
```

`restls` authenticates the relay inside the TLS `session_id` — the cover
handshake itself is real TLS (tls12 or tls13):

```yaml
- name: ss-restls
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: "•••"
  plugin: restls
  plugin-opts:
    host: cover.example.com    # required — cover server name (TLS SNI)
    password: "psk"            # required
    version-hint: tls13        # required — tls12 or tls13
    # restls-script: "150?0<1" # optional behavior script (validated at parse)
    # force-tls12: false       # upstream test knob — overrides version-hint to tls12
    # skip-cert-verify: false
    # name-cert-verify: ""     # verify the cert for this name instead of host
    # fingerprint: "AA:BB:…"   # SHA-256 cert pin, not uTLS
```

`jls` authenticates inside a real TLS 1.3 handshake — `ClientHello`/
`ServerHello` `random` carry an AES-256-GCM-sealed credential, so the auth
blob is part of the handshake transcript and no generic TLS stack can
speak it. Post-handshake is a plain TLS record stream (TLS 1.3 only):

```yaml
- name: ss-jls
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: "•••"
  plugin: jls
  plugin-opts:
    host: cover.example.com    # required — cover server name (TLS SNI)
    username: "user"           # required — keyed into the auth nonce
    password: "psk"            # required — keyed into the auth key
    # alpn: "h2,http/1.1"      # comma-separated, default shown
```

There is deliberately no `skip-cert-verify`: jls's random authentication
*is* the certificate check — an authenticated server random skips chain
verification (upstream `jlsAuthenticated()`), an unauthenticated one runs
full PKI and then rejects the connection.

`kcptun` tunnels the SS stream through KCP (ARQ over UDP) — crypt
envelope + optional Reed-Solomon FEC + snappy + smux v1, wire-compatible
with `xtaci/kcp-go` (which mihomo's plugin tracks). UDP is relayed via
legacy UDP-over-TCP (`uot`) on a multiplexed session, matching upstream's
forced `UDPOverTCP`:

```yaml
- name: ss-kcptun
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: "•••"
  plugin: kcptun
  plugin-opts:
    key: "session-key"      # PBKDF2 input — the crypt secret
    crypt: aes              # aes aes-128 aes-192 blowfish twofish cast5
                            # 3des xtea tea xor salsa20 aes-128-gcm none null
    mode: fast              # normal fast fast2 fast3 manual
    conn: 1                 # parallel KCP sessions (round-robin)
    datashard: 10           # FEC data shards (0 → default, as upstream)
    parityshard: 3          # FEC parity shards
    mtu: 1350
    nocomp: false           # true disables the snappy layer
    keepalive: 10           # smux NOP interval seconds
    autoexpire: 0           # session rotation seconds
    # sndwnd rcvwnd sockbuf smuxbuf framesize streambuf
    # nodelay interval resend nc ratelimit dscp scavengettl acknodelay
```

Divergences from upstream: `crypt=sm4` is a hard error (no stable Rust
SM4 crate — a silent AES fallback would never authenticate);
`smuxver != 1` errors (this build speaks smux v1 only);
`scavengettl` is advisory — dead sessions are re-dialed lazily instead
of a scavenge list; an `mtu` that leaves no segment room after envelope
overhead is a hard dial error (upstream ignores `SetMtu` failure and
silently keeps 1400). The KCP core is a vendored `kcp-go` v5.6.72 port —
`acknodelay` and every `nodelay`/`interval`/`resend`/`nc` value behave
exactly as upstream (upstream itself flattens `nodelay` to a bool).

---

## Trojan — `trojan`

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `password` | string | ✓ | — | |
| `sni` | string | | server addr | TLS SNI |
| `skip-cert-verify` | bool | | `false` | Disable cert validation |
| `udp` | bool | | `false` | UDP relay over the TLS tunnel |

---

## VLESS — `vless`

The most feature-rich protocol: TLS, REALITY, XTLS-Vision flow, and five transports.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `uuid` | string | ✓ | — | User UUID (dashed or hex) |
| `udp` | bool | | `false` | UDP relay |
| `tls` | bool | | `false` | Enable TLS |
| `servername` | string | | server addr | TLS SNI |
| `skip-cert-verify` | bool | | `false` | |
| `alpn` | list | | `[]` | e.g. `[h2, http/1.1]` |
| `network` | string | | `tcp` | `tcp` · `ws` · `grpc` · `h2` · `httpupgrade` |
| `client-fingerprint` | string | | — | uTLS profile (required for REALITY) |
| `flow` | string | | — | `xtls-rprx-vision` (needs TLS + `vless-vision` feature) |
| `encryption` | string | | `none` | Must be `none`/empty |
| `reality-opts` | map | | — | REALITY config (see below) |
| `ech-opts` | map | | — | Encrypted Client Hello (see below) |

`mux` is parsed but not implemented (warn + ignore). The deprecated flows
`xtls-rprx-direct` / `xtls-rprx-splice` are a hard error.

**REALITY** (`reality-opts`):

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `public-key` | string | ✓ | Base64url X25519 public key (32 bytes) |
| `short-id` | string | | Hex, ≤ 8 bytes (zero-padded) |
| `support-x25519mlkem768` | bool | | Hybrid key-agreement flag |

```yaml
- name: vless-reality
  type: vless
  server: 1.2.3.4
  port: 443
  uuid: 00000000-0000-0000-0000-000000000000
  tls: true
  flow: xtls-rprx-vision
  client-fingerprint: chrome
  reality-opts:
    public-key: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    short-id: "0123abcd"
```

### Transport options

These sub-blocks apply to VLESS (and, where noted, VMess) when `network` selects them:

- **`ws-opts`** — `path` (default `/`), `headers` map (`Host` defaults to server addr),
  `max-early-data`, `early-data-header-name`.
- **`grpc-opts`** — `grpc-service-name` (default `GunService`).
- **`h2-opts`** — `path` (default `/`), `host` list (authorities, must be non-empty).
- **`http-upgrade-opts`** — `path` (default `/`), `host`, extra `headers`.

```yaml
- name: vless-ws-tls
  type: vless
  server: example.com
  port: 443
  uuid: 00000000-0000-0000-0000-000000000000
  tls: true
  network: ws
  ws-opts:
    path: /ray
    headers:
      Host: example.com
```

### ECH (`ech-opts`)

Encrypted Client Hello, available with the BoringSSL backend (`boring-tls` feature):

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `enable` | bool | `false` | Turn ECH on |
| `config` | string | — | Base64 ECH config; auto-fetched from DNS HTTPS/SVCB records if omitted |

---

## VMess — `vmess`

AEAD VMess outbound (legacy `alterId` header mode is gone — `alterId` is coerced to 0).

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `uuid` | string | ✓ | — | |
| `cipher` | string | | `auto` | `auto` · `aes-128-gcm` · `chacha20-poly1305` · `none` (`zero` errors) |
| `udp` | bool | | `false` | |
| `tls` | bool | | `false` | |
| `servername` | string | | server addr | TLS SNI |
| `skip-cert-verify` | bool | | `false` | |
| `alpn` | list | | `[]` | |
| `network` | string | | `tcp` | `tcp` or `ws` |
| `client-fingerprint` | string | | — | uTLS profile |
| `ws-opts` | map | | — | Same as VLESS |

---

## Hysteria2 — `hysteria2`

QUIC-based, with Salamander obfuscation and port hopping.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `password` | string | ✓ | — | |
| `sni` | string | | — | TLS SNI |
| `skip-cert-verify` | bool | | `false` | |
| `udp` | bool | | `true` | |
| `up` / `down` | string \| u64 | | `0` | Bandwidth, e.g. `"30 Mbps"` |
| `obfs` | string | | — | `salamander` (`gecko` errors) |
| `obfs-password` | string | | — | Required when `obfs` is set |
| `ports` | string | | — | Port-hop set, e.g. `443`, `443-445`, `all` |
| `hop-interval` | string \| u64 | | — | Seconds, e.g. `5` or `5-30` |
| `fingerprint` | string | | — | Pinned cert SHA-256 (hex or base64) |
| `fast-open` | bool | | `true` | |
| `alpn` | string \| list | | `[h3]` | Only `h3` |

Server-side / unsupported options (`certificate`, `private-key`, `ech-opts`, `cwnd`,
`udp-mtu`, …) are hard errors.

---

## Snell — `snell`

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `psk` | string | ✓ | — | Pre-shared key |
| `version` | u64 \| string | | `4` | `3`, `4`, or `5` (`v3`/`v4`/`v5` accepted) |
| `udp` | bool | | `false` | UDP-over-TCP |
| `reuse` | bool | | `false` | Connection pool (v4/v5) |
| `obfs-opts` | map | | — | `mode`: `off`/`http`/`tls`; `host` (default server addr) |

---

## AnyTLS — `anytls`

Obfuscated-TLS outbound (requires the `anytls` feature).

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `password` | string | ✓ | — | |
| `sni` | string | | — | |
| `skip-cert-verify` | bool | | `false` | |
| `udp` | bool | | `false` | Enable UDP relay (sing-box udp-over-tcp v2) |

---

## HTTP — `http`

HTTP CONNECT outbound, optionally over TLS with basic auth.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `tls` | bool | | `false` | HTTPS (CONNECT over TLS) |
| `skip-cert-verify` | bool | | `false` | |
| `username` / `password` | string | | — | Basic auth (must be set together) |
| `headers` | map | | — | Extra headers on the CONNECT request |

---

## SOCKS5 — `socks5`

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `tls` | bool | | `false` | SOCKS5 over TLS |
| `skip-cert-verify` | bool | | `false` | |
| `username` / `password` | string | | — | Auth (must be set together) |
| `udp` | bool | | `false` | UDP ASSOCIATE (QUIC/HTTP3) |

---

## Direct — `direct`

A configurable direct outbound. Useful to pin specific DNS servers for a route.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `dns` | string \| list | | — | Per-proxy DNS servers as `IP:port`, e.g. `192.168.1.1:53` |

---

## TLS & privacy features

Across the TLS-capable protocols meow-rs supports:

- **rustls** by default; **BoringSSL** optionally (`boring-tls`) for ECH.
- **uTLS fingerprinting** via `client-fingerprint` — Chrome, Firefox, Safari, iOS,
  Android, Edge — to evade TLS fingerprint detection.
- **REALITY** for VLESS (see above).
- **ECH (Encrypted Client Hello)** with DNS-sourced configs (HTTPS/SVCB records).
