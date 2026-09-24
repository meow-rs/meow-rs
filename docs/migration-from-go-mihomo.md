# Migration guide: Go mihomo → meow-rs

Last updated: 2026-06-19. Tracks the current default app feature set.
Owner: pm. Tracks roadmap item: **M1.H-3**.
Review cadence: updated at each milestone exit.

This document is for operators migrating a working Go mihomo (Clash Meta)
deployment to meow-rs. It covers:

- What config surface is supported, partially supported, or not yet supported.
- Behavioral divergences and what to do about them.
- Migration steps for common subscription types.
- Feature flags equivalent to Go mihomo build tags.

If you are starting fresh (not migrating), read the main README instead.

**Scope note:** This guide describes the default `meow-app` build unless a
feature flag is called out explicitly. Features marked *M2* or later are planned
but not yet shipped.

---

## Quick compatibility check

Run meow-rs with `-t` to validate your config without starting:

```bash
meow -f config.yaml -t
```

Hard errors (Class A divergences) print the upstream field name and the
rejection reason. Warnings (Class B) print once at startup and the config
loads. If `-t` exits 0, the config will load.

---

## Quick compatibility checklist

Before migrating, scan your config for the following. Items marked ✗ will
cause problems; items marked ~ work with caveats; items marked ✓ work.

| Config section / feature | Status | Notes |
|--------------------------|:---------:|-------|
| `port`, `socks-port`, `mixed-port` | ✓ | Fully supported. |
| `allow-lan`, `bind-address` | ✓ | Fully supported. |
| `mode: rule / global / direct` | ✓ | Fully supported. |
| `log-level` | ✓ | Fully supported. |
| `external-controller` | ✓ | REST API on same port. |
| `secret` (Bearer auth) | ✓ | Enforced (security fix vs upstream). |
| `authentication` + `skip-auth-prefixes` | ✓ | Inbound proxy auth (M1.F-3). |
| `listeners:` named listeners | ✓ | Named listener array (M1.F-1). |
| `proxies:` — Shadowsocks | ✓ | Including AEAD 2022 ciphers. |
| `proxies:` — Trojan | ✓ | TLS + WebSocket transport. |
| `proxies:` — Direct, Reject | ✓ | Fully supported. |
| `proxies:` — VMess | ✓ | AEAD VMess outbound with TCP/WebSocket transports. |
| `proxies:` — VLESS | ✓ | Plain VLESS, XTLS-Vision, Reality/uTLS, and post-quantum Encryption (`mlkem768x25519plus`) in the default app build. |
| `proxies:` — HTTP CONNECT outbound | ✓ | Full parity (M1.B-3). |
| `proxies:` — SOCKS5 outbound | ✓ | Full parity (M1.B-4). |
| `proxies:` — Snell | ✓ | v3/v4/v5, UDP-over-TCP, optional HTTP/TLS obfs. |
| `proxies:` — Hysteria2 | ✓ | QUIC TCP/UDP, Salamander obfs, port hopping, bandwidth hints. |
| `proxies:` — AnyTLS | ✓ | TCP + UDP (udp-over-tcp v2, opt in with `udp: true`). In the `full` bundle, and therefore in the release binaries; excluded from `minimal`. |
| `proxies:` — TUIC / WireGuard / SSH | ✗ | Not implemented. |
| `proxy-groups:` — selector, url-test, fallback | ✓ | Fully supported. |
| `proxy-groups:` — load-balance | ✓ | round-robin + consistent-hashing (M1.C-1). |
| `proxy-groups:` — relay | ✓ | Chain multiple outbounds (M1.C-2). |
| `rules:` — DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD | ✓ | Fully supported. |
| `rules:` — IP-CIDR, IP-CIDR6 | ✓ | Fully supported. |
| `rules:` — GEOIP | ✓ | MaxMind MMDB. |
| `rules:` — GEOSITE | ✓ | mrs format only — see §Rules. |
| `rules:` — RULE-SET | ✓ | M1.D-5, mrs + yaml formats. |
| `rules:` — PROCESS-NAME | ✓ | Platform lookup wired. |
| `rules:` — IN-NAME, IN-TYPE, IN-PORT, IN-USER | ✓ | Named listeners and auth metadata are wired. |
| `rules:` — SUB-RULE | ✓ | Named rule subsets with cycle detection. |
| `rules:` — AND, OR, NOT | ✓ | Logic composition supported. |
| `rules:` — MATCH | ✓ | Fully supported. |
| `rule-providers:` — http | ✓ | With interval refresh (M1.D-5). |
| `rule-providers:` — file | ✓ | Loaded once; `interval` is ignored (warn). |
| `rule-providers:` — inline | ✓ | M1.D-5. |
| `dns:` — udp, tcp nameservers | ✓ | Fully supported. |
| `dns:` — DoH (`https://`) | ✓ | See §DNS. |
| `dns:` — DoT (`tls://`) | ✓ | See §DNS. |
| `dns:` — DoQ (`quic://`) | ✗ | Deferred to M1.E-6/M2. Hard error (not silent). |
| `dns:` — `default-nameserver` | ✓ | Bootstrap resolver for encrypted upstream hostnames. |
| `dns:` — `nameserver-policy` | ✓ | Exact, wildcard, and `geosite:` policy keys. |
| `dns:` — `fallback-filter` | ✓ | GeoIP/IP-CIDR/domain gates. |
| `dns:` — `hosts` + `use-system-hosts` | ✓ | M1.E-5, wildcards supported. |
| `dns:` — `fake-ip` mode | ✓ | v4/v6 pools, `fake-ip-filter`, `fake-ip-filter-mode`, `store-fake-ip` JSON persistence. See §fake-ip mode. |
| `tproxy-port` | ✓ | Linux nftables / macOS pf. |
| `proxy-providers:` | ✓ | http/file sources, provider filters, health checks, and group `use:`. |
| `geodata:` | ✓ | Path overrides, auto-update, interval, and download URL overrides. |
| `/metrics` Prometheus endpoint | ✓ | meow-rs enhancement (no Go upstream equiv). |

---

## Config surface parity table

### Fields accepted but with changed semantics

These fields parse without error but behave differently from Go mihomo:

| Field | Go mihomo | meow-rs | Class |
|-------|-----------|-------------|-------|
| `secret` not set | API unprotected | API unprotected (warns at startup) | Same |
| `authentication: ["user:pass"]` | Accepted | Malformed entry (no colon) is hard error | A |
| `authentication: ["user:"]` (empty password) | Accepted silently | Accepted; warn-once | B |
| `skip-auth-prefixes` | Defaults to `[]` | Always includes `127.0.0.1/32` + `::1/128` | A |
| `skip-auth-prefixes` with invalid CIDR | Silently dropped | Hard parse error | A |
| `dns.nameserver: quic://...` | Supported | Hard error with roadmap pointer | A |
| `dns.nameserver: sdns://...` | Warn-drop (silent) | Hard error | A |
| `dns.default-nameserver: tls://...` | Allowed (bootstrap loop risk) | Hard error | A |
| `dns.default-nameserver` absent with encrypted hostname upstream | Fails at first query | Hard error at load | A |
| `nameserver-policy` entry with all URLs stripped | Runtime panic | Hard parse error at load | A |
| `fallback-filter` GeoIP/CIDR gates | Only on primary failure | Also on poisoned responses (non-CN IP, bogon) | A |
| `fallback-filter.geoip: true` with no MMDB | Startup error | Warn-once, gate disabled | B |
| `nameserver-policy` key with `geosite:` prefix | Resolved via geosite DB | Same — resolved via geosite DB (needs geosite DB; warn-skip if absent) | — |
| `nameserver-policy` key with `rule-set:` prefix | Resolved via rule-provider | Same — resolved via rule-provider (domain/classical); `ipcidr` behavior and missing provider are hard errors | — |
| `IN-TYPE` with unknown value (e.g. `IN-TYPE,QUIC`) | Silently no-match | Hard parse error | A |
| `PUT /configs` in-flight connections | Graceful handover | Cold reload, connections dropped + logged | A |
| `PUT /configs` payload with raw YAML (not base64) | Accepted in some versions | 400 with helpful message | B |
| `GET /configs` response includes null Option fields | Full struct with nulls | Only non-null fields returned | B |
| `geodata-mode`, `geodata-loader`, `geoip-matcher` | Valid fields | Ignored with warn-once (M2+) | B |

### Fields that are silently ignored in Go mihomo but error in meow-rs

Go mihomo ignores many config mistakes without any feedback. meow-rs
follows the policy in [ADR-0002](adr/0002-upstream-divergence-policy.md):
security gaps and typo-likely mistakes become hard errors (Class A).

| Mistake | Go mihomo | meow-rs |
|---------|-----------|-------------|
| Duplicate listener port | Silently overwrites last | Hard parse error naming both conflicting listeners |
| Duplicate listener name | Silently overwrites last | Hard parse error |
| Unknown listener type (e.g. `type: redir`) | Silently ignored | Hard parse error |
| Shorthand port + `listeners:` entry on same port | Both accepted | Hard parse error (same as duplicate port) |
| `authentication` entry with no `:` | Silently stored with empty password | Hard parse error |
| `authentication` entry with empty username (`:pass`) | Silently accepted | Hard parse error |
| `skip-auth-prefixes` with invalid CIDR | Silently dropped | Hard parse error |
| Malformed IP in `dns.hosts` | Silently skips | Hard parse error |
| `.dat` geosite file in discovery path | Loads (protobuf) | Hard error + conversion hint (`convert-geo`) |
| `sub-rules:` cycle | May panic or loop | Hard parse error |
| `sub-rules:` reference to undefined block | Runtime no-match | Hard parse error |
| `nameserver-policy` entry with zero valid nameservers | Runtime panic at first query | Hard parse error at load |
| `IN-TYPE` with unknown protocol name | Silently no-matches all traffic of that type | Hard parse error |
| Base64 payload with URL-safe alphabet (`-`, `_`) | Accepted in some dashboard versions | 400 with decode-error message |

---

## Protocols

Protocol sections summarize the current default app build unless a feature flag
is called out explicitly.

### Shadowsocks

Fully supported including AEAD-2022 ciphers. The built-in `v2ray-plugin`
and `gost-plugin` WebSocket transports are included, along with
`shadow-tls` (all three protocol versions), `restls` (both
`version-hint` modes; `force-tls12` maps to the `tls12` path), `jls`
(hello-random authentication over a real TLS 1.3 handshake) and
`kcptun` (KCP ARQ with crypt/FEC/snappy over a smux v1 session pool;
UDP relay via UDP-over-TCP). External SIP003 plugin binaries are
supported via `plugin:` on `ss` nodes and `allow-external-plugin` on
providers.

### Trojan

Fully supported. TLS via BoringSSL. WebSocket transport via the
built-in transport layer. gRPC transport is available through the shared
transport layer.

### VLESS

Supported. Plain VLESS uses the UUID auth header and has no body cipher.
Security comes from the outer transport (`tls: true`). XTLS-Vision flow
(`flow: xtls-rprx-vision`) and Reality/uTLS paths are supported in the default
app build.

VLESS post-quantum **Encryption** (`encryption: mlkem768x25519plus…`, Xray's
ML-KEM-768 + X25519 hybrid handshake that 3x-ui now emits) is supported in the
default app build via the `vless-encryption` feature (bundled into `full`, kept
out of `minimal`). All three XOR modes (`native` / `xorpub` / `random`), 1-RTT
and 0-RTT, and multi-key relay chains interoperate with Xray-core / mihomo
servers. On a build without the feature the `encryption:` line is a hard parse
error pointing at the missing feature.

```yaml
proxies:
  - name: vless-example
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: example.com
    skip-cert-verify: false
    flow: ""                    # "" (plain) | xtls-rprx-vision
    encryption: ""              # "" / none, or mlkem768x25519plus.native.0rtt.<key>
    network: ws                 # tcp | ws | grpc | h2 | httpupgrade
    ws-opts:
      path: /vless
      headers:
        Host: example.com
    udp: true
```

**Divergences from Go mihomo:**

| Field / behaviour | Go mihomo | meow-rs |
|-------------------|-----------|-------------|
| `flow: xtls-rprx-direct` / `xtls-rprx-splice` | Accepted (deprecated upstream) | Hard parse error — use `xtls-rprx-vision` instead. |
| `encryption: mlkem768x25519plus…` (post-quantum Encryption) | Accepted | Supported with the `vless-encryption` feature (in `full`); otherwise a hard parse error naming the feature. |
| `encryption:` any other non-`""`/`"none"` value | Accepted | Hard parse error — VLESS defines no other body cipher. |
| `smux: {enabled: true}` | Multiplexes | Implemented as sing-mux (smux/yamux/h2mux; default h2mux) for sing-box/mihomo servers, plus Xray Mux.Cool (`protocol: muxcool`, VLESS/VMess) for Xray servers. Legacy `mux:` remains accepted. |
| `tls: false` with no outer encryption | Accepted silently | Warn-once at load — traffic is plaintext. |

**Deferred:** VLESS inbound.

### HTTP CONNECT outbound

Supported. HTTP/1.1 CONNECT tunnel with optional Basic auth and custom headers.
Optional TLS wrapping of the proxy connection.

```yaml
proxies:
  - name: corp-http-proxy
    type: http
    server: proxy.corp.example
    port: 8080
    username: alice             # optional; both username + password or neither
    password: s3cr3t
    tls: false                  # wraps TCP connection to the proxy in TLS
    skip-cert-verify: false     # only used when tls: true
    headers:                    # injected into the CONNECT request only
      X-Forwarded-For: "1.2.3.4"
```

**Divergences from Go mihomo:**

| Behaviour | Go mihomo | meow-rs |
|-----------|-----------|-------------|
| Only `username` set (no `password`) | Undefined | Hard parse error — orphaned credential is almost certainly a typo (ADR-0002 Class A). |
| Proxy auth schemes other than Basic (Digest, NTLM) | Supported | M1 supports Basic only. Unknown auth challenge → `Err(ProxyAuthFailed)`. |
| Proxy returns 407 | `ProxyAuthFailed` | Same, clearly named in logs: "http proxy auth failed". |

### SOCKS5 outbound

Supported. SOCKS5 TCP tunnel (CMD `0x01` CONNECT) with optional username/password
auth. Optional TLS-over-SOCKS5.

```yaml
proxies:
  - name: socks5-node
    type: socks5
    server: 10.0.0.1
    port: 1080
    username: bob               # optional; both username + password or neither
    password: hunter2
    tls: false                  # SOCKS5-over-TLS (uncommon)
    skip-cert-verify: false
    udp: false                  # accepted and ignored in M1; warn-once
```

**Divergences from Go mihomo:**

| Behaviour | Go mihomo | meow-rs |
|-----------|-----------|-------------|
| `udp: true` | UDP ASSOCIATE supported | Accepted; warn-once at parse time. `dial_udp()` returns `UdpNotSupported`. UDP ASSOCIATE deferred to M1.x. |
| Only `username` set (no `password`) | Undefined | Hard parse error (ADR-0002 Class A). |
| Server selects no-auth despite credentials offered | Accepted | Proceeds without sub-negotiation — credentials not sent. This matches upstream behaviour. |

**Domain names preferred over IPs:** if `metadata.host` is set, SOCKS5 sends
an `atyp 0x03` (domain) request. IP-only dial is used only when no hostname is
available. This preserves domain for SNI and logging on the destination server.

### Not supported in the default app build

The following protocols are not available in the default app build. Using them
in `proxies:` will produce a hard parse error unless a feature note says
otherwise:

- **TUIC** — not implemented.
- **WireGuard** — niche; deferred.
- **SSH** — niche; deferred.
- **AnyTLS** — supported. Part of the `full` bundle, so the published release
  binaries carry it; `minimal` builds leave it out (ADR-0007 binary-size caps).

---

## Proxy groups

Duplicate group names — including a group colliding with a `proxies:` entry
or a built-in — are a hard error at load time, same as upstream
(`proxy group %s: the duplicate name`). Duplicate `proxies:` leaf names are
more permissive than upstream: the last declaration wins instead of
erroring. Cyclic group declarations are likewise a hard error matching
upstream's `proxyGroupsDagSort`; meow reports the actual cycle path
(`proxy-group cycle detected: A -> B -> A`) where upstream lists only the
involved names.

### selector, url-test, fallback

Fully supported. `url-test` uses real HTTP GET (not raw TCP).
`select` accepts but ignores `url`/`interval`/`lazy`/`tolerance`/
`expected-status` — warn-once per field; it runs no probe loop (upstream
sweeps static members of every group type since v1.18.4).

### load-balance

Supported in M1.C-1. Two strategies: `round-robin` (default) and
`consistent-hashing` (sticky by destination — mihomo `getKey`: IP-literal
host verbatim, domain reduced to eTLD+1, else `dst_ip`). Periodic
health-check using the same URL-probe mechanism as `url-test`.

```yaml
proxy-groups:
  - name: lb-group
    type: load-balance
    proxies:
      - proxy-a
      - proxy-b
      - proxy-c
    url: https://www.gstatic.com/generate_204
    interval: 300               # health-check sweep, seconds (0 = disabled)
    strategy: round-robin       # round-robin (default) | consistent-hashing
    lazy: false
```

**Divergences from Go mihomo:**

| Behaviour | Go mihomo | meow-rs |
|-----------|-----------|-------------|
| Unknown `strategy` value | Falls back to round-robin silently | Hard parse error — wrong strategy means wrong distribution (ADR-0002 Class A). |
| All proxies dead | Returns a dead proxy slot; dial fails | Returns `NoProxyAvailable` immediately — fast, named failure (Class B). |
| `consistent-hashing` with no alive proxies | Panics (index out of bounds) | Returns `NoProxyAvailable` cleanly (Class A). |
| `consistent-hashing` key + hash | Destination key (`getKey`: IP-literal host → host, domain → eTLD+1) hashed with `utils.MapHash` + `jumpHash` over the **full** member list, retrying dead members up to 5× — minimal reshuffle on membership changes | Client `src_ip` bytes hashed with FNV-1a `% alive_count` over the **alive** subset — "same client → same node"; membership changes reshuffle most assignments (Class B). |

**Note on "consistent-hashing":** despite the name, meow's variant is a
modulo-hash keyed by *client source IP* — stable for a given client given
a fixed alive list, but a membership change reshuffles most assignments.
Upstream's is a jump-hash keyed by *destination* over the full member
list. See `docs/specs/group-load-balance.md` divergence row 4.

### relay

Supported in M1.C-2. Chains ≥2 outbounds in sequence:
`client → proxy[0] → proxy[1] → … → target`.

```yaml
proxy-groups:
  - name: double-hop
    type: relay
    proxies:
      - first-hop    # connects to second-hop's server address
      - second-hop   # connects to the actual target

  - name: triple-hop
    type: relay
    proxies:
      - proxy-a
      - proxy-b
      - proxy-c      # innermost hop connects to the target
```

**Divergences from Go mihomo:**

| Behaviour | Go mihomo | meow-rs |
|-----------|-----------|-------------|
| Single-proxy relay (`proxies` length 1) | Silently acts as passthrough | Hard parse error — likely misconfiguration (ADR-0002 Class A). |
| Empty `proxies` list | Panics | Hard parse error (Class A). |
| UDP relay when any chain member lacks UDP support | Returns a non-functional conn silently | Returns `UdpNotSupported` immediately (Class A). |
| `url:`/`interval:`/`lazy:`/`tolerance:`/`expected-status:` on a relay group | Probes static members (since `90bf158`, v1.18.4) | Warn-once per field; no probe loop runs (Class B). |
| `use:`/`include-all*`/`filter:`/`exclude-*:` on a relay group | Relay accepts provider members | Warn-once per field; relay is static-only (Class B). |

**UDP relay:** works only when every proxy in the chain supports UDP
(`support_udp() == true` for all hops). If any hop lacks UDP, `dial_udp()`
returns `UdpNotSupported` — it does not silently degrade to TCP.

**Error messages:** intermediate hop failures include the hop index and
the inner error, e.g.: `"relay chain failed at hop 1 (proxy-b → proxy-c): <inner error>"`.

**Group references in relay chains:** listing a Selector or URLTest group
as a relay hop is allowed. The currently-selected proxy in that group is
used at dial time. This matches upstream.

**Non-first hops** run the adapter's full post-connect pipeline — its own
TLS/WS/obfs stack to its own server, then the protocol handshake — over the
preceding hop's stream (mihomo `DialContextWithDialer` semantics).
`direct`, `reject`, `http`, `socks5`, `snell`, `vless`, `vmess`, `trojan`,
`anytls`, and `ss` (built-in obfs/v2ray-plugin/ech-tls-tunnel included) all
terminate a relay chain. Two carve-outs fail loudly instead of silently
misbehaving: `hysteria2` (QUIC/UDP cannot ride a TCP stream — first-hop
only) and `ss` with `gost-plugin`/`shadow-tls`/`restls`/`jls` or an
external SIP003 plugin (the plugin owns its outbound leg — a record-level
transport cannot be replayed over an already-proxied stream). Mux pooling
(`smux`/`yamux`/`h2mux`/`muxcool`) is bypassed on relay hops: a
relay-supplied stream is single-use and cannot be re-dialled.

**No health-check on the relay group itself.** Relay is a fixed chain, not
a pool. For health-aware relay, wrap relay groups inside a Fallback group.

---

## Rules

### Rule types

See quick checklist above for status of each rule type.

### GEOIP

Supported. Uses MaxMind MMDB format (`Country.mmdb`). Discovery chain:

```
$XDG_CONFIG_HOME/meow/Country.mmdb
$HOME/.config/meow/Country.mmdb
./meow/Country.mmdb
```

### GEOSITE

Supported (M1.D-2), **mrs format only**. If you have a `.dat` geosite file,
convert it using the MetaCubeX `convert-geo` tool before migrating:

```bash
# Convert geosite.dat → geosite.mrs
metacubex convert-geo geosite.dat -o geosite.mrs
```

Discovery chain: same pattern as GEOIP but for `geosite.mrs`.

Go mihomo supports both `.dat` and `.mrs`. meow-rs supports mrs only
(Class A divergence, ADR-0002).

### rule-providers

mrs and yaml formats both supported (M1.D-5). `inline` type supported.
`interval:` refresh supported for HTTP providers.

**Format auto-detection:** `.mrs` suffix or `Content-Type: application/x-mrs`
→ mrs parser. Anything else → YAML attempt (clear error on binary garbage).

---

## DNS

### Encrypted upstreams (DoH / DoT)

Supported in M1.E-1. URL syntax:

```yaml
nameserver:
  - https://1.1.1.1/dns-query#cloudflare-dns.com    # DoH with SNI
  - tls://8.8.8.8:853#dns.google                    # DoT with SNI
  - udp://223.5.5.5:53                               # Plain UDP (unchanged)
```

**DoQ (`quic://`) is a hard error** with a message pointing at roadmap M1.E-6.
Replace with `tls://` or `https://` equivalents.

**`default-nameserver` required when encrypted upstream uses a hostname** (not
an IP literal). If you specify `https://cloudflare-dns.com/dns-query` without
`default-nameserver`, config load fails with a clear error. Hard-coded IP
literals (`https://1.1.1.1/dns-query#cloudflare-dns.com`) do not need a
bootstrap server.

### fake-ip mode

Supported. `enhanced-mode: fake-ip` assigns each resolved host a stable
synthetic IP from the configured CIDR. The tunnel rewrites incoming
connections back to the hostname before rule matching, mirroring upstream
`tunnel/tunnel.go::preHandleMetadata`.

```yaml
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: "198.18.0.1/16"      # default if omitted
  fake-ip-filter:
    - "+.local"
    - "+.lan"
    - "example.corp"                  # plain entry = suffix match
  fake-ip-filter-mode: blacklist      # default; whitelist also accepted
  store-fake-ip: true                 # optional: persist mappings across restart
```

- **Pool layout.** Network/.1 (gateway)/.2/.3/broadcast are reserved; first
  allocatable is `network + 4`. Effective capacity = `prefix_size − 4`.
  Sequential cursor, wraps on exhaustion and evicts the oldest mapping.
- **Filter.** `BlackList` (default) routes matched hosts through the real
  resolver; `WhiteList` does the opposite. Plain entries are treated as
  suffixes (`example.com` matches `example.com` and any subdomain).
- **AAAA in v4-only configs.** Returns NOERROR-empty so clients fall back
  to IPv4 cleanly. To allocate v6 fake IPs, point `fake-ip-range` at an
  IPv6 prefix (e.g. `fc00::/64`).
- **Persistence.** `store-fake-ip: true` writes `fakeip-v4.json` /
  `fakeip-v6.json` next to the config file (atomic via tmp + rename).
  Differs from upstream's bbolt format — there is no migration path
  between the two on-disk layouts.
- **Flush.** `POST /cache/fakeip/flush` clears every allocation and resets
  cursors. 204 on success.

### hosts and use-system-hosts

Fully supported (M1.E-5). Wildcard entries:

```yaml
hosts:
  "*.corp.internal": "10.0.0.50"     # + Go syntax also accepted (see below)
  "+.corp.internal": "10.0.0.50"     # equivalent; stored identically
```

`*.example.com` is rewritten to `+.example.com` internally at parse time.
Both syntaxes work in config.

---

## Inbound authentication

```yaml
authentication:
  - alice:hunter2
  - bob:s3cr3t

skip-auth-prefixes:
  - 192.168.0.0/24
```

- Loopback (`127.0.0.1/32`, `::1/128`) is always bypassed regardless of config.
- Entry with no `:` → hard parse error (typo detection).
- SOCKS5: advertises method 0x02 when credentials configured.
- HTTP: returns 407 on CONNECT and forward-proxy requests when auth fails.
- TProxy: auth never applied.

---

## Removed features

These Go mihomo features are intentionally excluded from meow-rs. Configs
using them will produce a clear error at startup.

| Feature | Reason | Alternative |
|---------|--------|-------------|
| TUIC, WireGuard, SSH protocols | Protocol scope and dependency budget | Revisit in M2+ if users need them |
| TUN inbound | L3-device transparent proxy (issue #326) | `tun:` section with the `listener-tun` Cargo feature |

---

## meow-rs-only features

These exist in meow-rs but have no equivalent in Go mihomo. Dashboard
tools built for Go mihomo will ignore them.

| Feature | Path / Field | Notes |
|---------|-------------|-------|
| Prometheus metrics | `GET /metrics` | Native scrape endpoint; Go mihomo has no equivalent (M1.H-2) |
| Subscription management API | `GET\|POST /api/subscriptions`, `DELETE /api/subscriptions/{name}`, `POST /api/subscriptions/{name}/refresh` | meow-rs-specific |
| Extended proxy group API | `GET\|POST\|PUT\|DELETE /api/proxy-groups[/:name]` | meow-rs-specific |
| Rule CRUD API | `POST\|PUT\|DELETE /rules[/:index]` | Runtime rule editing |

Keep these under the `/api/` prefix so they do not collide with
Clash-compatible paths.

---

## Feature flags (Cargo features)

meow-rs uses Cargo feature flags where Go mihomo uses build tags:

| Go mihomo build tag / upstream | meow-rs Cargo feature | Default |
|-------------------------------|--------------------------|:-------:|
| Encrypted DNS (DoH, DoT) | `meow-dns/encrypted` | on |
| BoringSSL-backed uTLS/ECH paths | `meow-app/boring-tls` | on for `meow-app` |
| Full app bundle | `meow-app/full` | on |
| Minimal app bundle | `meow-app/minimal` | off |
| AnyTLS outbound | `meow-app/anytls` (in `full`, not in `minimal`) | on |

To build without encrypted DNS (smaller binary):

```bash
cargo build --release --no-default-features -p meow-dns
```

---

## Migration steps by subscription type

### Type 1: Standard Clash Meta subscription (SS + VLESS/VMess, rule-set)

Most common format from public providers. Typical issues:

1. **Unsupported proxy types** — TUIC, WireGuard, SSH, ShadowsocksR, and other
   niche upstream protocols still need replacement or removal. AnyTLS works
   out of the box in the release binaries; a `minimal` build needs
   `--features anytls`.
2. **`enhanced-mode: fake-ip`** — supported. Migration from a prior
   meow-rs release that warned-and-fell-back to `normal` is automatic;
   no config change required.
3. **`fake-ip-range` / `fake-ip-filter`** — honoured. Defaults to
   `198.18.0.1/16` when range is omitted; filter defaults to empty
   (`BlackList` mode never skips).
4. **GEOSITE rules with `.dat` files** — convert to mrs format:
   ```bash
   metacubex convert-geo geosite.dat -o geosite.mrs
   ```
5. **`quic://` nameservers** — replace with `tls://` or `https://` equivalents.
   `quic://` is a hard parse error with a message pointing at the roadmap.
6. Run `-t` to validate: `meow -f config.yaml -t`

### Type 2: Enterprise split-tunnel (nameserver-policy, IN-NAME rules)

1. **Named listeners** — `IN-NAME` / `IN-TYPE` rules require the `listeners:`
   array (M1.F-1). Shorthand ports (`mixed-port`, `socks-port`) get auto-names
   (`"mixed"`, `"socks"`) — `IN-NAME,mixed,...` works without changes.
2. **`nameserver-policy` with `geosite:` keys** — entries like
   `"geosite:cn": [...]` work when a geosite `.mrs` database is loaded. If no
   geosite DB is available, those policy entries are skipped with a warn-once.
3. **`authentication:`** — ensure each entry has a colon separating username and
   password. Entries without a colon are a hard parse error.
4. **`skip-auth-prefixes:`** — loopback (`127.0.0.1/32`, `::1/128`) is always
   skipped even if not listed. Invalid CIDRs are a hard parse error.

### Type 3: Transparent proxy (tproxy, Linux)

1. **TUN users** — meow-rs has a `tun:` section (feature `listener-tun`,
   fake-ip-scoped; see `docs/tun.md`), or use `tproxy-port` with nftables
   `TPROXY`/`REDIRECT` rules.
2. **`redir-port`** — not supported. Use `tproxy-port`.
3. **PROCESS-NAME / PROCESS-PATH rules** — platform lookup wired (Linux netlink,
   macOS libproc) via M1.D-1.
4. **Firewall-management polarity is reversed.** In Go mihomo the top-level
   `iptables:` block defaults **off** (the deployer owns redirect rules
   unless they opt in); in meow-rs the equivalent `firewall:` key lives on a
   `listeners:` tproxy entry and defaults **on** (managed nftables/pf table),
   and the `tproxy-port` shorthand is always managed. A config that ran
   externally-managed rules upstream must set `firewall: false` explicitly on
   the listener, or meow will install its own `inet meow_tproxy_<pid>_<seq>` /
   `com.apple/com.meow.tproxy.<pid>.<seq>` pf anchor alongside yours. A stray top-level `firewall:` key warns and is ignored —
   it is not the upstream top-level `iptables:` equivalent; the upstream
   `iptables:` block itself (`enable`/`inbound-interface`/`bypass`/
   `dns-redirect`) is likewise ignored.
5. **UDP TPROXY is opt-in and narrower than upstream.** Upstream's
   `tproxy-port` intercepts TCP **and** UDP; meow-rs's shorthand is TCP-only —
   a migrated deployer steering UDP at it silently blackholes the datagrams
   (they never reach a socket meow owns). To serve UDP, declare a
   `listeners:` tproxy entry with `udp: true`, which requires
   `firewall: false` (the managed firewall only covers host output-chain TCP
   REDIRECT) — upstream's `udp: true` + managed `iptables` combination has no
   direct equivalent. UDP is also IPv4-only (upstream does v6), Linux-only,
   and `prerouting`-scoped; see `docs/tproxy-gateway.md`.

### Type 4: Proxy provider subscription (`proxy-providers:`)

1. **`proxy-providers:`** — supported in M1.H-1 (http + file sources, health-check,
   `include-all` shorthand).
2. **`interval:` refresh** — the field is accepted for compatibility, but
   proxy providers are not refreshed on a schedule; reload via
   `PUT /providers/proxies/{name}` or restart. Scheduled refresh exists only
   for HTTP **rule** providers.
3. **`use:` in proxy groups** — wired for proxy providers. Provider filters and
   `include-all` shorthands are applied when groups are resolved.

---

## Known-good patterns

These have been tested against a real subscription and confirmed working:

- Rule-based routing with DOMAIN, DOMAIN-SUFFIX, IP-CIDR, GEOIP rules
- Shadowsocks AEAD proxies with selector group + url-test health check
- Trojan with TLS + WebSocket transport
- VLESS with TLS/WebSocket/gRPC/H2/HTTPUpgrade transports
- VMess AEAD TCP/WebSocket outbound
- Snell v3/v4/v5 outbound with UDP-over-TCP
- Hysteria2 TCP/UDP with Docker integration coverage
- Proxy providers with group `use:`
- Mixed listener on a single port with SOCKS5 + HTTP clients
- TProxy on Linux (nftables mark-based routing)
- DNS with plain UDP nameservers + fallback
- DoH/DoT upstreams, nameserver policy, fallback filter, and fake-IP mode

---

## Known-broken patterns

The following are unsupported or intentionally rejected:

- **`quic://` nameservers** — hard error; replace with `tls://` or `https://`.
- **TUIC / WireGuard / SSH / ShadowsocksR proxies** — hard error; no default-build adapter.
- **AnyTLS proxies in a `minimal` build** — hard error; the `full` bundle and
  the release binaries support them.
- **Snell v1/v2** — hard error; use Snell v3/v4/v5.
- **`vless` with `flow: xtls-rprx-direct`** — hard error; use `xtls-rprx-vision`.
- **External dashboard auto-download** (`external-ui-url`) — not performed.
  `external-ui` / `external-ui-name` *are* supported: point them at a directory
  of static files and it is served at `/ui` in place of the built-in dashboard.
  You must download/extract the dashboard yourself; the zip is not fetched
  automatically (avoids an unzip dependency against the binary-size caps).
- **`dialer-proxy`** — supported for TCP via an injected `TcpDialer`, so the
  outbound's own TLS/Reality/protocol handshake runs on the tunneled stream
  (mihomo's `proxyDialer` model). Chains through any proxy or group and nests,
  with cycle detection. Two carve-outs:
  - *Adapter types that own their transport* — `anytls` and `hysteria2` (QUIC)
    do not dial through the pluggable dialer, and `ss` with an **external**
    SIP003 plugin always reaches that plugin over loopback. These fall back to
    the relay-based wrapper, which works where `connect_over` is implemented
    (all of `direct`, `reject`, `http`, `socks5`, `snell`, `vless`, `vmess`,
    `trojan`, `anytls`, and `ss` — except `ss` with an external SIP003 plugin)
    and otherwise fails loudly at dial time (`hysteria2` stays unsupported:
    QUIC cannot ride a TCP stream). It never degrades to a silent direct dial.
  - *UDP* — associations whose datagrams ride a raw socket cannot follow the TCP
    chain (Shadowsocks plain relay, SOCKS5 UDP ASSOCIATE) and are refused
    rather than leaking the real source path. UDP carried inside a mux session
    (`smux`/`yamux`/`h2mux`) does traverse the chain and keeps working.

  `dialer-proxy` on **provider-sourced nodes** is honoured too (issue #489):
  the name resolves against the live route map at dial time — static proxies
  and groups, but not other provider nodes (they are not registry entries;
  mihomo resolves the same restricted namespace) — and is re-applied on every
  provider refresh. Provider-level `dialer-proxy` and `override.dialer-proxy`
  follow mihomo's unconditional-write precedence — `override` > provider >
  node (`OverrideSchema.Apply` writes last and always wins), and an empty
  `override.dialer-proxy: ""` clears the chain like upstream's
  unconditional write of an empty string. A node whose dialer name never
  resolves keeps loading but fails its dials loudly; a malformed value or
  a self-reference rejects the node instead of silently dialling direct.
  One divergence from upstream: a chain that recurses through dynamic
  provider group membership (invisible to the static cycle check) is
  bounded at 16 hops and fails the dial — Go's growable stacks tolerate
  unbounded recursion where Rust's fixed async frames cannot.

---

## Getting help

- File issues at the project issue tracker.
- Check `docs/roadmap.md` for the status of features you need.
- For features not yet shipped, note the milestone and subscribe to the
  tracking issue.
