# Spec: `listeners: type: vless` — VLESS Vision server inbound

Status: Implemented
Upstream references: Xray-core v26.3.27 VLESS/Vision/Mux.Cool, mihomo
`listener/inbound/vless.go` + `listener/inbound/reality.go`.
Evidence: `crates/meow-listener/tests/vless_interop_docker.rs` and the golden
vectors under `crates/meow-proxy/src/vless/testdata/` /
`crates/meow-proxy/src/mux/testdata/`.

## Scope

A production VLESS server inbound under the named `listeners:` array. The
only served flow is XTLS `xtls-rprx-vision`; the outer transport is either
standard TLS 1.3 on a configured certificate pair, or REALITY. TCP flows are
routed through the tunnel as ordinary inbound TCP. UDP is XUDP (the UDP
subset of Xray Mux.Cool) inside the same Vision connection — there is no bare
VLESS UDP socket and no generic TCP-over-Mux server.

In scope:

- multi-user `users:` entries `{username, uuid, flow}`; the authenticated
  username lands in `Metadata.in_user` for `IN-USER` rules;
- comma-separated multi-address `listen`, atomic bind, one shared
  `max-connections` quota, `proxy:`/`rule:` route overrides;
- standard TLS 1.3 with optional ALPN, or REALITY with transparent cover
  relay for unauthenticated TLS clients;
- bidirectional Vision padding, independent `END`/`DIRECT` transitions, and
  XUDP datagram routing through the normal rules engine;
- `GET /listeners` reporting bound endpoints without credentials, and the
  `PUT /configs` feature gate refusing unservable `type: vless` documents.

Out of scope: plaintext VLESS, non-Vision flows, VLESS Encryption, fallback
chains, WebSocket/gRPC/XHTTP transports, generic Mux.Cool TCP, Xray `xver`
PROXY-protocol handoff, client-version pinning, ML-DSA proofs, shape-mimicry
of the target's TLS implementation, and GlobalID session migration.

## Configuration contract

Minimal standard-TLS example:

```yaml
mode: rule
log-level: info
listeners:
  - name: vless-tls-in
    type: vless
    listen: "127.0.0.1,::1"
    port: 8443
    certificate: /path/to/chain.pem   # leaf first; both files or both inline PEM
    private-key: /path/to/key.pem
    alpn: [h2, http/1.1]              # optional; empty/absent means no ALPN
    users:
      - username: alice
        uuid: "71884bd4-d6a0-4e19-9895-3e1d8b469317"
        flow: xtls-rprx-vision
rules:
  - MATCH,DIRECT
```

Minimal REALITY example:

```yaml
mode: rule
log-level: info
listeners:
  - name: vless-reality-in
    type: vless
    listen: 0.0.0.0
    port: 443
    reality-config:
      dest: "www.example.com:443"
      private-key: "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo"
      short-id: ["0123456789abcdef"]
      server-names: ["www.example.com"]
      max-time-difference: 120000000   # microseconds; optional, this is the default
      limit-fallback-upload:
        after-bytes: 65536
        bytes-per-sec: 32768
        burst-bytes-per-sec: 65536
      limit-fallback-download:
        after-bytes: 65536
        bytes-per-sec: 32768
        burst-bytes-per-sec: 65536
    users:
      - username: alice
        uuid: "71884bd4-d6a0-4e19-9895-3e1d8b469317"
        flow: xtls-rprx-vision
rules:
  - MATCH,DIRECT
```

Generate fresh deployment values (`xray uuid`, `xray x25519`); do not reuse
the documentation UUID or private key. `reality-config.private-key` is the
server's private key; clients receive the corresponding public key.

### Listener keys

| Field | Type | Default | Behaviour |
| --- | --- | --- | --- |
| `type`, `name`, `listen`, `port` | string/u16 | — | `type: vless` and a unique non-empty `name`. `listen` follows the anytls multi-address contract: an IP literal, `host:port`, or a comma-separated list; every entry binds atomically, port `0` publishes the OS-assigned port, and every port joins the duplicate-port registry. |
| `proxy`, `rule`, `routing-mark` | — | — | Existing named-listener semantics. `proxy` and `rule` are mutually exclusive; both authenticated TCP and XUDP flows carry the override. Linux applies the mark to listener sockets. |
| `max-connections` | usize | global, itself 256 | Per-entry override falling back to the global `max-connections`; shared across all addresses of the entry. Explicit `0` disables this lifecycle cap. REALITY classification/cover still have their own hard caps below. |
| `users` | list | required | Non-empty list of exactly `{username, uuid, flow}`. Usernames are non-empty and unique; UUIDs are unique after parsing; all-zero UUID is invalid. UUID accepts the canonical dashed form or 32 bare hex digits, case-insensitively. `flow` is required and must be exactly `xtls-rprx-vision`. |
| `decryption` | string | `none` | Absent, `""` and `none` are equivalent. Any other value is a hard error; `encryption` is the outbound key and errors with a migration hint. |
| `certificate` / `private-key` | string | — | Standard-TLS mode: required together, non-empty, both inline PEM or both paths (mixed forms hard-error). Paths resolve through the home-contained safe-path rules and must be regular files of at most 1 MiB each. The chain is leaf first. Bytes are loaded and key matching is verified before sockets bind. |
| `reality-config` | map | — | REALITY mode: non-empty map, mutually exclusive with **any** flat certificate field. One of the two security modes is mandatory; there is no plaintext mode. |
| `alpn` | list | `[]` | Standard TLS only: at most 16 unique printable-ASCII protocol strings, 1–255 bytes each. Empty/absent negotiates no ALPN. In server-preference order; a client offering no overlap fails, a client offering no ALPN connects. Non-empty under REALITY is a hard error. |
| `udp` | bool | `true` | `false` rejects VLESS command `0x03` (Mux/XUDP) at the request layer — before any XUDP byte or target resolution. |
| `client-auth-type`, `client-auth-cert`, `ech-key` | string | — | Only absent or `""`; any non-empty value is unsupported and hard-errors. |
| `allow-insecure` | bool | `false` | `true` always hard-errors: there is no plaintext credential-bearing VLESS listener. |
| `shadow-tls`, `res-tls`, `jls-config`, `mux-option` | — | — | Deferred upstream/front-layer keys. Any non-null value, including an empty map, hard-errors rather than silently degrading to native TCP; explicit null carries no intent and passes. |
| `ws-path`, `xhttp-config`, `grpc-service-name` | — | — | Deferred upstream transport keys. They are not schema fields here: any appearance, even explicit null, is an unknown-key hard error with a native-TCP migration hint. |

Keys that are not mihomo VLESS-listener fields are hard errors with hints:
`tls`/`certificates` (TLS is the flat certificate pair), `network` (native
TCP only), listener-level `flow` (flow is per-user), `fallback`/`fallbacks`
(no VLESS fallback), and `reality-opts` (outbound spelling; use
`reality-config`). Unknown keys hard-error as well: this listener terminates
credentials, so a silently dead key hides a security-relevant configuration
bug. Keys belonging to other listener types (`cipher`, `password`,
`simple-obfs`, `kcp-tun`, `padding-scheme`) warn and are ignored.

### `reality-config` keys

| Key | Type | Required | Behaviour |
| --- | --- | --- | --- |
| `dest` | string | ✓ | Cover target as bare `host:port`; IPv6 must be bracketed. Port is `1..=65535`; URLs, userinfo, paths, bare ports and Unix sockets are invalid. Startup and `-t` validate shape only — no DNS or network access. `target` is Xray's spelling and hard-errors. The configured target is dialed directly. |
| `private-key` | string | ✓ | Unpadded URL-safe base64 decoding to exactly 32 bytes of X25519 private key — never PEM, hex, or a file path. |
| `short-id` | list of strings | ✓ | Non-empty list. Each item is even-length hex of at most 16 characters, decoded and right-zero-padded to 8 bytes. Empty strings and all-zero values are rejected; duplicates are compared after padding (`"ab"` and `"ab00"` collide). Runtime accepts at most 64 entries. |
| `server-names` | list of strings | ✓ | Exact-match SNI allowlist compared case-insensitively after ASCII lowercasing: non-empty ASCII DNS A-labels, no wildcards, IP literals, leading/trailing dots, or duplicates (case-insensitive). Runtime accepts at most 64 entries. The wire SNI is never rewritten. |
| `max-time-difference` | integer | — | Microseconds. Absent/null means `120_000_000` (120 seconds); explicit `0` disables the freshness check; negative or non-integer values hard-error. The wire timestamp is whole Unix seconds; the current handshake compares it against the configured duration's whole-second component. |
| `limit-fallback-upload` / `limit-fallback-download` | map | — | Optional cover-only rate limits with `after-bytes`, `bytes-per-sec`, `burst-bytes-per-sec`, all non-negative integers in bytes or bytes/second. `bytes-per-sec: 0` disables shaping for that direction. Unknown keys hard-error. A burst below the rate is raised to the rate; the current transport interface shares the larger of the two configured burst values across both directions. |
| `proxy` | — | — | Unsupported nested cover-dial control; hard-errors. The top-level listener `proxy`/`rule` still applies to authenticated VLESS flows. |
| `xver`, client-version pins, `show`, key logs, ML-DSA keys | — | — | Xray extensions meow does not serve; hard-errors. |

A literal self-loop (`dest` resolves statically back to this listener's own
bind) is rejected at config build. At runtime every resolved candidate is
checked against the live endpoints of all VLESS listener generations in the
process, with wildcard/loopback combinations treated conservatively; looping
candidates are skipped and a target with no remaining dialable address fails
closed. This does not make a domain `dest` a routing decision — the cover
target is fixed administrator configuration.

## Wire contract

### Outer transport

**Standard TLS** is BoringSSL TLS 1.3 only (minimum and maximum version).
Session tickets and the session cache are off; there is no 0-RTT, mTLS, ECH,
cipher/group config, or fingerprint emulation. ALPN is only a TLS negotiation
value: it does not turn the listener into HTTP/2.

**REALITY** classification reads and reassembles the first ClientHello before
answering. Bounds are 64 KiB, 32 records, and 16 KiB plaintext per record;
the accept path shares the listener's 15-second absolute deadline. Ordinary
TLS, malformed/non-ClientHello input, unauthenticated REALITY-looking input,
absent/disallowed SNI, wrong key/short ID/timestamp, or unusable key share
become the cover branch. Resource-limit, timeout and I/O failures close.

Authentication uses the REALITY session-id proof: X25519 with the configured
static private key, all-zero shared secrets rejected, HKDF-SHA256 with salt
`client_random[0..20]` and info `REALITY`, then AES-256-GCM open of the 32-byte
session-id field with the original ClientHello as AAD except bytes `[39..71]`
zeroed. Version/reserved bytes in the plaintext are parsed but not filtered.
Short IDs compare in constant time after padding to 8 bytes. For the
authentication ECDH the server uses a classical X25519 share first and falls
back to the X25519 suffix of a hybrid X25519+ML-KEM-768 share. For the TLS
key establishment itself it prefers the hybrid group when usable, then
classical X25519; both establishments are served. The server sends a
fresh TLS 1.3 handshake: no PSK/ticket/0-RTT, an Ed25519 leaf whose outer
X.509 signature value is `HMAC-SHA512(AuthKey, raw_ed25519_public_key)`, and a
real Ed25519 `CertificateVerify` over the transcript. Client Finished is
verified before application bytes are released.

REALITY is not a replay cache. The timestamp window limits freshness, but a
valid ClientHello can be replayed inside the window; fresh ephemeral key
exchange, transcript-bound Finished verification, no 0-RTT, and the inner
VLESS UUID are what prevent a recorded handshake from becoming a proxied
session.

### VLESS request and response

After outer TLS decryption the request is incremental and bounded by
fixed-size fields. The exported worst-case envelopes are 533 bytes for TCP
and 274 bytes for Mux (the `u8` addons-length ceiling); because this server
accepts only the exact 18-byte Vision addon, a valid Mux request is exactly
37 bytes and a valid TCP request is at most 296 bytes (255-byte domain):

```text
version:u8 = 0 | uuid[16] | addons_len:u8 | addons | command:u8 | target?

Vision addons: addons_len = 0x12, bytes = 0x0a 0x10 || "xtls-rprx-vision"
TCP command 0x01: port:u16be | atype | address
UDP command 0x02: rejected — Vision UDP uses Mux command 0x03 + XUDP
Mux command 0x03: no target bytes; XUDP frames follow as Vision content

atype: 0x01 IPv4[4] | 0x02 len:u8 + UTF-8 domain | 0x03 IPv6[16]
```

The decoder never consumes the first Vision frame. Wrong version, missing or
incorrect flow, unknown command, bare UDP, unknown address type, port `0`,
empty/invalid/non-UTF-8 domain, truncation, or a timeout closes without a
VLESS response. Unknown UUID closes without DNS resolution or target dial.
There is no probing response that would reveal the listener as a VLESS server.

On success the constant response header `00 00` is prepended to the first
downlink Vision frame — never emitted as a standalone connectivity ACK.
`Metadata` carries `network`, `conn_type = Vless`, source/destination,
listener name/port, `in_user`, and the route override. Domain targets remain
domains through rule matching and tunnel resolution.

### Vision padding, END and DIRECT

Each direction starts with a 21-byte first-frame header
(`uuid[16] | cmd | content_len:u16be | pad_len:u16be`); later frames omit the
UUID. Commands are `0x00 CONTINUE`, `0x01 END`, `0x02 DIRECT`. Padding bytes
are zero-filled and discarded through fixed scratch; receive allocation does
not follow peer-controlled lengths.

The server validates the first padding UUID. A mismatch is fatal — an
intentional hardening over Xray's pass-through behaviour. Unknown padding
commands are fatal. EOF before or inside a header, content, or padding is a
clean close: bytes already copied toward the relay remain delivered, but no
partial trailing frame is synthesized.

Inner TLS recognition is record-aligned across arbitrary TCP/TLS chunking.
The inspection budget is eight non-empty chunks shared by both directions.
`DIRECT` requires inner TLS evidence: a ServerHello carrying the TLS 1.3
`supported_versions` extension and a cipher in `0x1301..=0x1304` (`0x1305`
is recognized as TLS but is not DIRECT-eligible), plus a transport that can
switch the promised direction to raw passthrough. Downlink `DIRECT` is only
framed after complete `17 03 03` application-data records; uplink `DIRECT`
without validated evidence is fatal when the frame completes. Because frame
content streams directly into the relay buffer, that offending frame's
content may already have been delivered; the connection still closes rather
than accepting the raw-mode transition. Otherwise the direction uses `END`:
Vision framing stops there and later bytes pass as payload, but they remain
inside the outer TLS record stream rather than becoming raw TCP. XUDP mode
never treats even TLS-shaped payloads as DIRECT evidence.

The final `DIRECT` frame is still inside outer TLS. Only after it drains does
that direction switch to raw TCP; the directions may switch independently.
After a raw switch the remaining bytes are ordinary TCP payload — no Vision
framing and no outer TLS on that direction. If raw switching is impossible
the connection terminates rather than retroactively rewriting a promised
`DIRECT` into `END`.

### XUDP over Mux.Cool

XUDP frames are the UDP subset of Mux.Cool carried directly as Vision content:

```text
meta_len:u16be | sid:u16be | status:u8 | option:u8 | meta-extra
               [payload_len:u16be | payload]    iff option & 0x01

status: 1 New / 2 Keep / 3 End / 4 KeepAlive
option: 0x01 Data, 0x02 Error (Error only on End)
UDP target meta: network=0x02 | port:u16be | atype | address
UDP New optional tail: GlobalID[8]
```

`meta_len` counts the bytes after itself through the end of the target/meta
area; it excludes itself, `payload_len`, and the payload. `payload_len` is
present only when the Data bit is set.

Accepted client shapes include xray's `New+Data`, meow's bare `New` followed
by `Keep+Data`, any session id (including `0`), and per-packet target
overrides on `Keep`. The override affects only that datagram; bare Keeps use
the New target. Replies are `Keep+Data` on the same sid, never New, and carry
the real reply source when representable. For a domain target resolved
locally, the source is rewritten back to the original domain with the real
reply port. `End` removes every flow of the sid. Legal `KeepAlive` is never
answered; payload it carries is discarded. A datagram for an unknown sid is
dropped and answered with a non-error `End`, matching xray's race handling.

These shapes are connection-fatal: meta length below 4 or above 512 bytes,
payload length above 8192 bytes, unknown status/option bits, Error outside
End, End carrying Data, TCP New, a TCP/unknown network on a targeted Keep,
truncated/unknown addresses, empty or non-UTF-8 domains, trailing meta bytes
other than exactly the 8-byte GlobalID on New (or any trailing bytes on
Keep), duplicate active New, a 129th active session, or UDP on a listener
with `udp: false`. Port `0` is left to the UDP dial/routing path rather than
killing the whole connection.

Resource ownership is deliberately split into control plane and data plane:
the sid session lives for the connection, while `(sid, target)` UDP flows are
lazy and independently evictable. A dead or evicted flow respawns on the next
datagram; no blackhole-ended session is needed. Bounds per physical
connection: 128 sessions and 128 `(sid, target)` flows (LRU eviction at the
flow cap), 64 queued datagrams per flow, 128 queued egress frames, and one
4 MiB meter across both queued directions. Oversize ingress frames are fatal
before allocation; oversize UDP replies drop rather than split. Idle flows
retire after the shared UDP idle timeout (currently 60 seconds); an empty,
idle association closes rather than holding a listener slot forever. All
writer, sweeper and flow tasks are association-owned and reaped on EOF,
fatal error, idle close, cancellation or listener teardown.

## Rejection matrix

| Input | Result |
| --- | --- |
| Standard-TLS mode: non-TLS/TLS 1.2/no ALPN overlap | TLS handshake failure/close; no cover branch |
| REALITY: ordinary TLS, malformed/non-ClientHello, wrong key/short ID/time/SNI, unusable key share | transparent cover relay if a cover slot and target dial succeed; otherwise close |
| REALITY authenticated, then bad client Finished or any later VLESS/Vision/XUDP error | close — never fall back into cover after authentication |
| valid outer TLS + wrong VLESS UUID | close, no response, no DNS/dial |
| valid UUID but missing/wrong flow or non-Vision addon bytes | close at request decode, no response, no DNS/dial |
| VLESS command `0x02` bare UDP | unsupported; close |
| VLESS command `0x03` with `udp: false` | close before XUDP state/target resolution |
| generic Mux TCP New inside XUDP | connection-fatal; no TCP-over-Mux fallback |
| wrong first padding UUID or unknown padding command | connection error/close before accepting that frame |
| unjustified inbound DIRECT | connection error/close when the frame completes; its already streamed content is not recalled |
| nonexistent target/rule or failed UDP dial | that TCP flow closes or that XUDP flow dies; later datagrams may respawn the UDP flow |

## Cover relay

REALITY cover relay is transparent TCP forwarding, not TLS termination. The
exact pre-read wire prefix is written to the fixed `dest` first, byte-for-byte
and once; then both directions relay with 16 KiB buffers and half-close
support. meow neither rewrites SNI/ALPN nor fetches/copies the target's
certificate — a probing TLS client completes its handshake with the target
itself. Authenticated REALITY clients never dial the cover target.

Cover work is resource-bounded independently of `max-connections`: at most
256 concurrent REALITY classification/handshakes and 64 active cover relays.
Target dial is bounded at 3 seconds. A relay closes after 60 seconds idle or
10 minutes absolute lifetime. The upload/download limiter maps
`after-bytes` to the unthrottled prefix and `bytes-per-sec` to a directional
token bucket. Dial failure, saturation, timeout, listener cancellation or
relay error closes both sides; there is no fallback target selection.

## API, persistence and feature gating

All addresses bind eagerly and atomically at startup after the security
identity has loaded. Any TLS/REALITY parameter, bind or socket-mark failure
releases every socket and fails startup. Every address shares one listener
instance, user table, connection quota, route override and REALITY endpoint
registry. `IN-PORT` reports the actual accepting port.

`GET /listeners` reports `name`, `type: "vless"`, the first bound
`listen`/`port`, and `addresses[]` for multi-address entries. UUIDs,
usernames, REALITY private keys, short IDs, certificate/private-key material,
ClientHello bytes and handshake secrets are not exposed. Flow metadata is
stamped `ConnType::Vless`, but the current `IN-TYPE` rule parser does **not**
accept a `VLESS` payload; route these flows by `IN-NAME`, `IN-PORT`,
`IN-USER`, or the listener's `proxy:`/`rule:` override instead.

`PUT /configs` validates the same typed shape. A `type: vless` entry on a
build without the `listener-vless` feature is rejected with 400 even under
`?force=true`; listener and security identity changes are committed for the
next boot rather than hot-swapped.

`listener-vless` is in `full`/`default` and out of `minimal`. It pulls in the
server-side VLESS/Vision and REALITY transport pieces it needs; operators do
not enable `listener-anytls` or the outbound REALITY feature separately.

## Intentional differences and limitations

- **Wrong padding UUID closes.** Xray v26.3.27 degrades into passing the
  mis-framed bytes through; forwarding attacker-controlled garbage after a
  successful authentication would be worse than closing.
- **No passive fallback chain.** REALITY has exactly one fixed cover `dest`;
  standard TLS has no cover branch. There is no VLESS-level fallback after
  the outer handshake and no byte replay into arbitrary fallback targets.
- **No target shape mimicry.** The REALITY server emits meow's own standards-
  compliant TLS 1.3 flight and per-connection HMAC certificate. It does not
  sample, cache, or imitate the cover site's certificate chain, TLS library,
  record sizes, or failure behaviour. This is a deliberate v1 boundary, not a
  claim of byte-identical mimicry.
- **XUDP control/data separation.** Unlike xray freedom's one-flow-per-sid
  model, meow evaluates UDP routing per `(sid, target)`. Flows can die and
  respawn beneath a long-lived sid; this preserves per-destination routing
  and avoids blackholing bare Keeps, at the cost of not being a literal copy
  of xray session lifetime.
- **`-udp443` is not accepted.** `xtls-rprx-vision-udp443` is client-local
  policy syntax. The wire flow is the 16-byte `xtls-rprx-vision`; the server
  imposes no UDP/443 special case.
- **Short IDs are explicit credentials.** Unlike mihomo's tolerated empty
  string/all-zero forms, meow rejects them rather than minting an implicit
  credential. Padding-equivalent duplicates are rejected.
- **GlobalID is parsed but not migrated.** It does not resume or move UDP
  sessions across connections/users.
- **No generic Mux.Cool.** XUDP is the UDP subset only; TCP New is fatal.
- **No VLESS Encryption or plain flow.** The inner VLESS encryption selector
  is fixed at `decryption: none`; security belongs to the outer TLS/REALITY
  transport.
- **Startup validation is not a cover health check.** `-t` and startup do not
  resolve or dial `dest`; a dead cover does not block authenticated REALITY
  service.
- **`-t` is typed shape validation, not listener construction.** It checks
  the security-mode union, key shapes, users, bind syntax and feature gate,
  but it does not read certificate files or verify a certificate/key pair;
  those failures are startup errors before binding. REALITY's runtime
  `1..=64` short-ID/server-name cardinality is likewise enforced by listener
  construction rather than by the config-shape pass.
- **`IN-TYPE,VLESS` is not currently parseable.** VLESS flows stamp
  `ConnType::Vless` in metadata, but the rule parser's accepted inbound-type
  inventory was not extended. This is documented as the current behavior;
  use the other inbound selectors or route overrides.
- **Current time-window precision.** The config unit is microseconds, but the
  REALITY wire timestamp is whole Unix seconds and the current handshake
  compares using the duration's whole-second component. Sub-second configured
  remainders therefore do not widen acceptance.

## Interoperability evidence

`crates/meow-listener/tests/vless_listener_integration.rs` exercises the
in-process listener end to end: standard-TLS Vision echo with DIRECT and
`IN-USER` routing, negative auth/flow/plaintext/TLS 1.2 cases, REALITY
authenticated echo, transparent REALITY cover relay, and the XUDP matrix
(meow-client shape, multi-session interleave, per-packet target override and
default fallback, domain reply rewrite, IPv6, datagram boundaries, TCP-New
fatality, `udp: false`, oversize meta/payload, unknown-sid End, and teardown
scoping). It is fast and hermetic; it is not a substitute for pinned-client
interop.

`crates/meow-listener/tests/vless_interop_docker.rs` runs pinned client
images `ghcr.io/xtls/xray-core:26.3.27` and `metacubex/mihomo:v1.19.17`
against the real listener in process. On Linux, `MEOW_REQUIRE_DOCKER=1`
makes missing Docker/images a hard failure rather than a skip.

For both clients and both outer modes (standard TLS and REALITY) the matrix
asserts:

- inner TLS 1.3 echo of more than 1 MiB of patterned data each way;
- exactly one raw-read and one raw-write DIRECT transition per connection —
  the test does not mistake an END-only echo for DIRECT;
- XUDP echo datagrams of several sizes with correct reply source port and
  source-address shape (xray preserves the domain source; mihomo resolves
  before VLESS and observes the IP source);
- wrong-UUID and missing-flow clients closing without application bytes and
  without incrementing the target accept counter;
- an ordinary TLS client to the REALITY port receiving the independent cover
  site's real certificate and byte-exact HTTPS response.

Golden vectors freeze the VLESS request/first-frame shape, empty first frame,
first downlink response frame, TLS 1.3 ServerHello decision, XUDP New+Data,
Keep/End, and reply Keep+Data. They are wire fixtures, not a substitute for
the reverse-client matrix.
