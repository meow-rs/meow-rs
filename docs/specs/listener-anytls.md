# Spec: `listeners: type: anytls` — AnyTLS server inbound

Status: Implemented
Upstream reference: `listener/anytls/server.go`, `transport/anytls`
(session, padding, StringMap), sing-box `udp-over-tcp.md` (UoT v2).
Companion: [listener-anytls-test-plan.md](listener-anytls-test-plan.md).

## Scope

A production AnyTLS server inbound under the named `listeners:` array,
mihomo/Clash Meta compatible in config surface and wire behaviour.

In scope:

- `type: anytls` entries with an ordered `users:` table, TLS via
  BoringSSL (the controller's `api-tls` precedent), an explicit
  plaintext opt-in (`allow-insecure`), per-listener `padding-scheme`,
  and a comma-separated multi-address `listen`.
- The AnyTLS v1/v2 session contract: auth preface, client Settings,
  server `v=2` settings + SYNACK ordering (v1 never sees either),
  Alert-on-violation close, heartbeats, stream and session teardown.
- Logical streams carrying a SOCKS5-serialized destination, routed as
  ordinary TCP through the tunnel (`route_inbound_tcp`) — rules,
  `IN-NAME`/`IN-PORT`/`IN-TYPE`/`IN-USER`, `proxy:`/`rule:` overrides.
- UDP-over-TCP v2 associations (exact destination
  `sp.v2.udp-over-tcp.arpa:0`), routed through the tunnel's UDP path —
  never direct bypass.
- `GET /listeners` reporting every bound address; the `PUT /configs`
  feature gate refusing a `type: anytls` document on builds lacking the
  `listener-anytls` cargo feature, even under `?force=true`.

Out of scope: mTLS client auth (`client-auth-type`,
`client-auth-cert`), ECH (`ech-key`), and the TLS front layers
(`shadow-tls`, `res-tls`, `jls-config`) — non-empty/enabled forms are
hard config errors, not silent ignores. The vendored `meow-anytls`
crate's rustls `server` feature stays a dev fixture.

## Configuration contract

| Field | Type | Default | Behaviour |
| --- | --- | --- | --- |
| `users` | map string→string | `{}` | Ordered at build; each password stored as `SHA256(password)` — the wire credential. Empty table = upstream's reject-all state (warn, listener still serves). Empty username/password, duplicate usernames (parser rejects duplicate mapping keys first) and duplicate password digests are hard errors. |
| `certificate` / `private-key` | string | — | Both or neither; both inline PEM (`-----BEGIN`) or both filesystem paths — mixed forms hard-error. |
| `allow-insecure` | bool | `false` | `true` is the plaintext opt-in and is only legal **without** TLS material. With no certificate pair and no `allow-insecure` the build hard-errors. |
| `padding-scheme` | string | crate default | Validated at build by `meow_common::anytls_padding` (same contract `PaddingFactory::new` enforces) so `-t`/`PUT` fail fast; `""` normalizes to the default scheme. |
| `listen` | string | `bind-address` | IP literal, `host:port`, or a comma-separated list of them. Each segment resolves through the shared `listen:port`/`port` merge — a segment port may differ from `port` only when `port` is `0`/absent; a conflict hard-errors. Empty segments hard-error. |
| `enable` | bool | `true` | `true` warns (redundant — presence enables); `false` hard-errors. |
| `udp` | bool | `true` | `true` warns (UoT always on); `false` hard-errors — there is no listener-level UoT off switch. |
| `client-auth-type` / `client-auth-cert` / `ech-key` | — | — | Any non-empty raw string (including whitespace-only) hard-errors as unsupported; only absent or `""` is empty. |
| `shadow-tls` / `res-tls` / `jls-config` | map | — | Recognized opaque blocks. `enable: true` hard-errors (an enabled front layer is a second security mode — the mutual-exclusion error fires first when a cert pair is also present); `enable: false`/absent warns and is ignored. Non-mapping shapes hard-error. |

Foreign single-purpose keys (`cipher`, `password`, `simple-obfs`,
`kcp-tun`, `mux-option`) warn and are ignored; anytls-specific keys on
other listener types warn too. Every address's port joins the
duplicate-port registry — same port on different addresses of one
entry is legal, the same port claimed by a *different* listener
hard-errors.

All addresses bind **eagerly and atomically** at startup: any TLS
identity, bind, or socket-mark failure releases every already-bound
socket and fails startup — a partial or silently skipped listener never
serves. Each socket receives `routing-mark` where the platform supports
it; all sockets share one listener instance, user table, padding
factory, `max-connections` quota and route override. `IN-PORT` on a
multi-address entry reports the actual accepting port.

## Wire contract

Authentication preface (upstream `userMap`): `SHA256(password)` 32
bytes → `u16be` padding length → padding bytes, read in bounded
chunks. Unknown digest closes the transport.

Session semantics (upstream `session.go`):

- Client `Settings` (`v`, `client`, optional `padding-md5`) arms SYN
  admission — a SYN ahead of a non-empty `Settings` is a protocol
  violation: Alert `"client did not send its settings"`, close.
- Missing/mismatched `padding-md5` (missing compares as `""`) pushes
  `UpdatePaddingScheme` with the raw scheme — before the version
  handshake, exactly like upstream.
- `v >= 2` → `peer_version`, then `ServerSettings {v: 2, …}` (server
  extras merge first so `v` can never be shadowed).
- `SYN` on a live stream id is ignored (`LoadOrStore` parity — existing
  stream continues, session stays open). Live streams are bounded at 128
  (and the accept queue at 128): excess SYNs are refused per-stream with
  a bare `FIN` (no `SynAck`), keeping the session alive.
- `handshake_success(sid)` is the only SYNACK producer: exactly one
  empty SYNACK for `v >= 2` peers, sent after the destination parses —
  before any dial — so a blocked rule lookup cannot reorder it behind
  stream data. v1 peers never receive one (they treat any frame as
  stream data).
- Heartbeats ping-pong `HeartRequest`/`HeartResponse`; the client-side
  SYN watchdog never arms on a server session or against a pre-v2 peer.

Resource bounds: 256 KiB per-stream pending input (evict just that
stream), 4 MiB session pending input (close the session), 64 queued
frames writer budget, `u16` frame payload ceiling
(`64 KiB − 7` — a relay-sized fill plus header ships as one frame).

## Stream routing

Every logical stream leads with a SOCKS5 address
(`ATYP | addr | port`).

- `sp.v2.udp-over-tcp.arpa:0` → UoT v2 association. Request
  `isConnect u8 | socks addr`; Connect packets `len u16be | payload`;
  Bind packets `<uot addr> | len u16be | payload`. **The uot address
  family table (0x00 v4 / 0x01 v6 / 0x02 domain) is not the SOCKS5
  table (0x01/0x03/0x04)** — decoding a Bind packet with the wrong
  table silently misroutes, which is why the codec lives in one
  module. IPv4-mapped IPv6 reply sources unmap to the v4 form.
- The legacy `sp.udp-over-tcp.arpa` (any port) and the v2 name on a
  non-zero port are **rejected**, never routed as TCP.
- Everything else → TCP `Metadata` → `route_inbound_tcp`.

`Metadata` is stamped `conn_type = Anytls` (matchable via
`IN-TYPE,ANYTLS`), `in_name`, actual accepting `in_port`, authenticated
`in_user`, and the optional `proxy:`/`rule:` route override. UoT
datagrams go through `pre_handle_metadata`/`resolve_udp_dst`/`dial_udp`
— the same path every other UDP inbound uses.

## API surface

`GET /listeners` reports `name`, `type: "anytls"`, the first address's
`listen`/`port` for single-address parity, plus `addresses[]` when more
than one bind target exists. Usernames, password digests, certificate
material, private keys and the padding scheme never appear.

`PUT /configs` resolves `listeners:` before any commit path; an
`type: anytls` entry on a build without `listener-anytls` is a 400
even under `?force=true` — a persisted config the next boot cannot
serve is a shape defect, not a degradable environment failure.

## Feature gating

`listener-anytls` (meow-listener → meow-app forward, in `full`/`default`,
out of `minimal`). An uncompiled build still parses the entry, then
fails `-t`/startup via `ensure_inbounds_supported` — never a silent
dead port.

## Intentional deviations

- **`udp: false` and `enable: false` hard-error** where upstream might
  warn: there is no code path that could honour them, and a silent
  dead inbound is worse than a config error.
- **`port: 0` and multi-address `listen`** follow meow's listener
  contract (per-segment `host:port` merge, duplicate-port registry),
  not upstream's single `(listen, port)` pair.
- Unsupported mTLS/ECH/front-layer keys are **errors**, matching
  meow's "declared but unservable" policy rather than upstream's
  ignore.
