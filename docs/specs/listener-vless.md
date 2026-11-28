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
      # mimic: {}                     # optional; absent/empty means the dial-first defaults below
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
| `max-time-difference` | integer | — | Microseconds. Absent/null means `120_000_000` (120 seconds); explicit `0` disables the freshness check; negative or non-integer values hard-error. The wire timestamp is whole Unix seconds, but the skew against the server clock is compared in the microsecond domain — a sub-second window keeps its precision, in either direction, and the boundary is inclusive. |
| `mimic` | map | `{}` | REALITY v2 target-handshake mirroring. Absent and `{}` both mean `mode: dial-first`, `probe-timeout-ms: 3000` (`500..=15000`), `quiescence-min-ms: 15` (`5..=200`), `quiescence-max-ms: 40` (`10..=500`), and `max-concurrent-probes: 64` (`1..=256`), with `min <= max < probe-timeout-ms`. `mode` is literal `dial-first` or `off`. Explicit `null`, non-maps, unknown/duplicate keys, non-integers and out-of-range values are hard errors; explicit numeric fields are validated even in `off`. |
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

### REALITY v2 mirror mode

With the default `mimic.mode: dial-first`, accepting a TCP connection starts
one bounded resolution/connect attempt to the fixed `dest` concurrently with
ClientHello preflight — potentially before any ClientHello byte has arrived.
After REALITY authentication and profile admission, the original pre-read
prefix is uploaded once on that same connection. A compatible target
ServerHello/CCS/encrypted-record prefix supplies only the outer record shape:
meow replaces the ServerHello random and complete key share, uses its own
REALITY certificate and transcript keys, verifies the client Finished, and
then enters VLESS. An incompatible or late target answer consumes the one
fallback decision and the same socket becomes the ordinary cover relay when
admission permits; there is no second target dial and no silent v2→v1 local
handshake downgrade.

`mode: off` is an explicit pre-handshake rollback to the v1 local REALITY
server handshake, for staged rollout and baseline comparison. It is not an
automatic error fallback. All mimic fields remain validated in that mode.

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
itself. In explicit `mimic.mode: off`, authenticated REALITY clients never
dial the cover target. In the default dial-first mode the bounded early dial
above is the deliberate exception for every admitted connection; authenticated
traffic still never selects or re-dials a different cover target.

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
stamped `ConnType::Vless`, matchable via `IN-TYPE,VLESS` as well as
`IN-NAME`, `IN-PORT`, `IN-USER`, or the listener's `proxy:`/`rule:`
override.

`PUT /configs` validates the same typed shape, including malformed mimic
values even under `?force=true`. A `type: vless` entry on a build without the
`listener-vless` feature is rejected with 400 even under `?force=true`;
listener and security identity changes are committed for the next boot rather
than hot-swapped. The comparison uses the normalized typed listener, so absent
`mimic`, `mimic: {}` and an explicit default-valued block are equivalent and
produce no restart notice; an effective change such as `mode: off` does warn
that restart is required and leaves active sockets, quotas and handshakes
untouched.

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
- **Only bounded handshake-record shape mimicry.** Default dial-first mirrors
  the target's TLS 1.3 ServerHello/CCS/encrypted-record envelope within the v2
  template rules, while replacing the random and key share and using meow's
  own certificate and keys. It does not copy the target certificate chain,
  target secrets, ALPN behaviour, timing, failure behaviour, or arbitrary TLS
  implementation quirks; incompatible templates become cover before any local
  TLS byte is emitted. `mode: off` keeps the stricter v1 local-flight boundary.
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
  resolve or dial `dest`, so a dead cover never blocks startup itself. With the
  default `dial-first` mimic mode, however, an individual authenticated
  connection's availability does depend on reaching `dest` and obtaining a
  compatible template; explicit `mode: off` restores the v1 behavior in which
  authenticated service is independent of cover reachability.
- **`-t` shares startup's security construction, files included.** Beyond
  the typed shape, feature gate, users and bind syntax, `-t` runs the same
  security-material validation startup runs. Standard TLS loads the
  certificate chain and private key — reading referenced PEM files is a
  deliberate exception to the config test's no-I/O rule, because the pair's
  syntax and key match cannot be checked from the YAML shape — parses both
  and verifies they form a pair. REALITY validates the cover `dest` shape,
  the `1..=64` short-ID/server-name cardinality, server names and normalized
  mimic contract, and constructs the REALITY acceptor. What `-t` still never
  does: bind a
  socket, resolve or dial the cover target, or touch the network.

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

`crates/meow-listener/tests/vless_interop_docker.rs` pins both client
images by immutable multi-arch index digest —
`ghcr.io/xtls/xray-core@sha256:592ec4d1…` (tag 26.3.27) and
`metacubex/mihomo@sha256:4c2495d7…` (tag v1.19.34) — and asserts the
binaries' self-reported versions before any leg runs. The mihomo pin is
v1.19.34 rather than v1.19.17: upstream `refs/tags/v1.19.34` resolves to
the frozen interop commit `0455d0d28c4526937380505153e65a843d8612e8`,
while `refs/tags/v1.19.17` resolves to a different commit and cannot
represent it. A missing Docker daemon or image skips the tests, unless
`MEOW_REQUIRE_DOCKER=1` — set in CI — makes that a hard failure.

The evidence splits across two topologies. The **in-process matrix** runs
the production listener inside the test process with pinned xray/mihomo
client containers reaching it over the client network's IPv4 bridge gateway
on Linux (`host.docker.internal` elsewhere), so the listener's own DIRECT
raw-switch counters are direct evidence rather than
inference from a successful echo. For both clients and both outer modes
(standard TLS and REALITY) this leg asserts:

- inner TLS 1.3 echo of more than 1 MiB of patterned data each way;
- exactly one raw-read and one raw-write DIRECT transition per connection —
  the test does not mistake an END-only echo for DIRECT;
- TLS 1.2, plaintext and server-first inners staying framed END — the
  DIRECT counters do not move;
- XUDP echo datagrams of several sizes with correct reply source port and
  source-address shape (xray preserves the domain source; mihomo resolves
  before VLESS and observes the IP source), never switching the Vision
  stream raw;
- wrong-UUID and missing-flow clients closing without application bytes and
  without incrementing the target accept counter;
- an ordinary TLS client to the REALITY port receiving the independent cover
  site's real certificate and byte-exact HTTPS response.

The **real-app matrix** instead containerizes the actual `meow` binary and
its echo target: the target sits on an `--internal` Docker network that
only the target and meow attach to, the clients sit on a separate
client/control network the target never joins, meow is the only container
attached to both networks, and before the matrix runs an active bypass
probe — a client-network-only container dialling the target directly —
must fail. The client/control network cannot itself be internal because
Docker unpublishes loopback-published ports on internal networks; that is
a documented control-plane deviation, not a client→target data path. For
both clients and both outer modes this leg asserts end-to-end TLS 1.3 echo
through the containerized meow and the XUDP matrix: interleaved per-packet
targets, UDP/443, and reply source ports, plus an IPv6 target on the TLS
leg when the daemon gives the target network a global IPv6 address. What
it cannot do is count DIRECT transitions — the listener is in another
container — which is exactly what the in-process leg exists for.

Golden vectors freeze the VLESS request/first-frame shape, empty first frame,
first downlink response frame, TLS 1.3 ServerHello decision, XUDP New+Data,
Keep/End, and reply Keep+Data. They are wire fixtures, not a substitute for
the reverse-client matrix.
