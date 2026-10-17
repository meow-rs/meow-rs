# TrustTunnel outbound contribution candidate

Tracking proposal: [#727](https://github.com/meow-rs/meow-rs/issues/727).
The original H2-only scope and the runtime/test integration follow the
maintainer's
[feedback](https://github.com/meow-rs/meow-rs/issues/727#issuecomment-5964286689);
the HTTP/3 transport (§3.2 of the public specification) was added afterwards
behind its own `trusttunnel-h3` feature, together with the `user-agent` and
extra-header knobs, to close the remaining gap against Surge's
`trust-tunnel` outbound. Default-profile inclusion remains a separate
measured decision.

The client protocol follows the [public specification](https://github.com/TrustTunnel/TrustTunnel/blob/master/PROTOCOL.md).
Configuration is compared with [Mihomo's adapter](https://github.com/MetaCubeX/mihomo/blob/Alpha/adapter/outbound/trusttunnel.go)
and [pool policy](https://github.com/MetaCubeX/mihomo/blob/Alpha/transport/trusttunnel/client.go).

## Build and configuration

`trusttunnel` is an opt-in feature in `meow-proxy`, `meow-config` and
`meow-app`. `trusttunnel-h3` is a second opt-in feature on top of it, for
the HTTP/3 transport: quiche is not in an H2-only build's dependency graph
at all, so folding it in unconditionally would charge every build for a
transport most nodes do not select (ADR-0007 binary-size caps). It links no
second crypto library — quiche rides the same vendored BoringSSL as
`meow-transport`'s TLS and the hysteria2 outbound. Existing `full` and
`minimal` profile contents are unchanged pending upstream's feature/profile
decision.

```sh
cargo run -p meow-app --features trusttunnel -- -f config.yaml -t
cargo run -p meow-app --features trusttunnel-h3 -- -f config.yaml -t
```

```yaml
proxies:
  - name: TrustTunnel
    type: trusttunnel
    server: vpn.example.com
    port: 443
    username: your-user
    password: your-password
    sni: vpn.example.com
    quic: false
    udp: true
    skip-cert-verify: false
    max-connections: 8
    min-streams: 5
    # Both fields of the spec's `user-agent`; see "Client identity" below.
    platform: ios
    app-name: AdGuard
    # Re-rendered per CONNECT, placeholders re-rolled each time.
    headers:
      x-padding: <random-string(16-128)>
  - name: TrustTunnel-H3
    type: trusttunnel
    server: vpn.example.com
    port: 443
    username: your-user
    password: your-password
    quic: true          # HTTP/3 over QUIC; needs --features trusttunnel-h3
rules:
  - MATCH,TrustTunnel
```

Absent or all-zero pool fields use Mihomo's 8 connections / 5 active
streams threshold. Each pool field is applied independently: a positive
`max-connections` no longer zeroes the `min-streams` default, and a positive
`max-streams` is honoured as the per-connection ceiling rather than being
discarded. `max-streams` alone still selects Mihomo's legacy mode (below);
alongside either other field it is just the ceiling, and it is always raised
to at least `min-streams` so the two cannot contradict each other. `udp`,
`quic`, `health-check` and `skip-cert-verify`
default to false. Optional YAML nulls use these defaults; null/empty
unsupported policy declarations are inert. Nonempty unsupported policies
still fail explicitly. `sni` defaults to the server. Null or empty ALPN
lists default to the selected transport's only protocol; an explicit
nonempty list must be exactly `[h2]`, or `[h3]` when `quic: true`.
`platform`, `app-name` and `headers` are optional and documented under
"Client identity"; `quic: true` is rejected with the feature name when the
running binary was built without `trusttunnel-h3`, so a `quic` node never
silently downgrades to HTTP/2.

An unavailable TT feature, malformed TT node, or unsupported TT policy must
not be silently dropped: a group that lists the name would otherwise shift
that traffic onto a sibling member, or — once no member survives — degrade
to a direct dial, which is the plaintext leak this closes. So the name stays
bound, to a permanently dead placeholder
([`UnavailableAdapter`](../../crates/meow-proxy/src/unavailable.rs)) whose
every dial fails naming the node and the reason. Runtime rebuilds and
provider payloads apply the same rule.

The placeholder advertises UDP support even though its UDP dial always
fails. The rule engine skips a UDP target that lacks UDP support, and an
exhausted scan dials DIRECT, so a placeholder that declined UDP would let a
flow's UDP/QUIC leave in the clear while the same flow's TCP failed closed.
Groups that pick by liveness already route around it, since it is dead from
birth. `load-balance` is the one pre-existing exception: it filters picks on
liveness for every member type, so a load-balance group with no live
UDP-capable member is skipped for UDP, exactly as it is when its members are
ordinary down nodes.

The damage is deliberately scoped to the node rather than the enclosing
`proxies:` block or provider payload. Rejecting the payload closes the same
hole, but it also fires for a protocol the running binary simply does not
contain — every official `full` release is built without
`--features trusttunnel`, and no edit the operator can make to their config
repairs that — and on a third-party provider payload, refetched on a timer,
it would hand that payload's operator a daemon-wide kill switch. This
follows the existing `MALFORMED_DIALER_PREFIX` precedent in `meow-config`:
the node loads, the dial fails. `strict` remains the opt-in that *does*
reject the payload, because there the operator has asked for every defect to
be fatal.

Because no payload-level gate remains, provider acquisition keeps its
pre-existing shape: the first fetch is spawned detached, both at startup
(after the listeners are up) and on an API commit, where an awaited download
would serialize every other commit behind one slow or blackholed provider
URL inside the `CONFIG_MUTATION` lane (issue #533). Offline `-t` still
validates provider declarations without fetching remote payloads, and
transient fetch failures retain existing offline-bootstrap behavior.

## Runtime boundaries

- TLS uses the existing BoringSSL transport and pluggable dialer; the
  protocol module creates no sockets. Shared physical sessions dial with
  `internal: false`, matching other pooled adapters: a session opened by
  housekeeping can later serve user streams without a new physical dial.
  This records front-group use so lazy probing remains active during reuse.
- Authenticated CONNECT multiplexes TCP, `_check`, and `_udp2` over H2.
  TCP writes respect flow control, support half-close, and reset unfinished
  streams on drop. A GOAWAY retires admission while successful streams drain;
  the dial then re-elects another pooled connection or dials a fresh one, so
  a routine server-side recycle is not a user-visible failure. That retry is
  safe because nothing had been written — the "no automatic replay" rule
  below covers a request that reached the peer, not one that never left.
- No application request or payload is automatically replayed. Authentication
  failure retires its session. Reset invalidates in-flight pool creation.
- Retirement also stops new UDP associations. Existing associations and TCP
  streams may drain; when the last UDP association closes, the retired mux
  stops its reader/writer tasks and releases its session lease. A mux that
  was already idle is stopped by the retirement notification. This breaks
  the cached-mux lifetime cycle without requiring a network reset or closing
  unrelated TCP streams. A closed UDP association reports `BrokenPipe` even
  for an oversized payload; the oversized-drop policy applies to live flows.
  A UDP dial whose elected connection is retired before it associates —
  by a concurrent dial's unanswered CONNECT — counts that as a refused
  admission and takes the one retry, rather than surfacing the retired
  mux's `BrokenPipe`.

- A CONNECT that never receives its response headers retires the connection it
  was sent on. A connection whose peer has silently gone away (an expired NAT
  entry, a slept laptop, a half-open peer) reports nothing: admission is
  granted, the request lands in the kernel's send buffer, and only the dial
  deadline ends the wait. Left pooled it would be re-elected by the *next*
  dial — with no active streams it is the least loaded candidate — until the
  kernel's retransmit timeout finally errored the socket, and each of those
  `TimedOut` failures is exactly what `DialFailureTracker` dead-marks a
  healthy node over. The connection leaves the admission pool rather than
  being cancelled: a CONNECT can also go unanswered because the *target* is
  slow, and the streams already running on that connection are not the
  dial's business. An answered refusal (any status) keeps the connection.
  On H3, an open admitted on stale stream credit can stay queued on a
  saturated connection until the deadline and retire that connection too,
  preserving its established streams at the cost of a later handshake.
- New-connection dials are serialised: one `creating` lock covers the whole
  dial, TLS/H2 or QUIC/H3 handshake and optional `_check`, so concurrent
  dials that each need a *new* connection complete at 1×…N× handshake
  latency rather than in parallel, and that wait counts against each
  caller's own deadline. Deliberate for now — it keeps `max_connections`
  exact without counting in-flight dials — and it only applies while the
  pool has no connection able to take another stream.
- Per-pool connections are capped at 16, per-session stream counts at 512,
  and UDP associations at 128. The effective per-connection ceiling is the
  lesser of the configured one and the peer's acknowledged
  `SETTINGS_MAX_CONCURRENT_STREAMS`, sampled from the connection driver:
  h2 reports that value only on the connection handle, and `poll_ready` on a
  fresh `SendRequest` answers `Ready` whatever the limit says, so without the
  sample a dial onto a connection already at the peer's limit would queue a
  pending-open stream and park until its whole deadline expired instead of
  taking a sibling connection. Official v1.1.0 send payloads are limited to
  65,434 bytes with an empty App Name; receive payloads accept 65,508 bytes
  (36-byte header plus 65,508 = 65,544 frame bytes, excluding the length prefix).
  These are different peer bounds, not a common IPv4 packet maximum.
  UDP send queues hold 32 frames; receive
  queues hold 16 per association with a shared 4 MiB receive-payload budget.
  Slow consumers can consume the shared budget and cause other associations'
  packets to drop. Budget and unmatched-reply drops are counted and logged
  at powers of two; reader/writer failures are logged before mux teardown.
  A short caller receive buffer consumes and truncates one datagram,
  matching the existing packet-connection convention.
  The outbound queue is separate: at most 32 frames (~2 MiB at maximum
  payload), plus one writer frame and one bounded reader frame. H2 also
  send buffers up to 128 KiB per TCP stream (128 MiB at default pool limits,
  up to 1 GiB at the hard limits); there is no global TCP buffer budget.
  Explicit pool/association admission pressure is a local resource error,
  preserving healthy group members while normal socket EAGAIN keeps its
  existing classification. Typed admission markers survive io/context/relay
  boundaries without being classified as errno-backed: multi-candidate
  error precedence retains its original errno-versus-context policy.
- UDP application-name fields are empty; actual process names are not sent,
  and neither is the client's own address: each association mints its own
  wire source tuple (unspecified address, per-association virtual port), so
  a LAN client's source IP and port are never disclosed to the endpoint
  operator. The tuple's only job is reply demultiplexing, which uniqueness
  alone satisfies.
  The outer CONNECT deadline covers pool admission, TLS/H2 (or QUIC/H3)
  setup, `_check` and the requested CONNECT, with no second equal-duration
  health-check timer.
- A send larger than the endpoint's 65,434-byte limit is counted, logged at
  powers of two, and dropped — not reported as a write error, because
  `handle_udp` evicts the NAT entry on any `write_packet` failure and one
  jumbo datagram from one application must not tear down every flow sharing
  the association.
- Reply dispatch requires the reply Destination tuple to match the virtual
  source assigned to its association. Official v1.1.0 echoes this tuple.
  An endpoint that zeroes it cannot multiplex replies unambiguously; such
  replies are counted/dropped rather than guessed or broadcast. The public
  wire spec names the field without defining dispatch semantics, so this
  compatibility requirement is explicit and zero-destination endpoints
  have no interoperability claim.
- ICMP (`_icmp`) is outside this contribution candidate; HTTP/3 is
  implemented behind `trusttunnel-h3` (see "HTTP/3 transport").

## Client identity

The `user-agent` is part of what an endpoint operator — or anyone watching
the TLS-wrapped stream — can tell this client apart by, and the public
specification varies it per CONNECT target: `<platform> <app_name>` on a
tunnel (§5.1), `<platform> _udp2` on the datagram multiplexer (§6.1), and a
bare `<platform>` on `_check` (§8.2). One fixed string across all three is
itself a distinguishing mark, so the three shapes are built and sent
accordingly.

- `platform` defaults to this host's platform token, not the build target's
  marketing name, and carries no version.
- `app-name` defaults to `meow`, deliberately *unversioned*: `meow/0.22.0`
  narrowed every session to one build of one client, which is the opposite
  of what a protocol designed to look like ordinary HTTPS wants. Operators
  who need to match a specific client set both fields.
- Both are validated at config load against the header-value grammar
  (`app-name` may contain inner spaces but cannot start or end with one,
  `platform` may contain none), bounded at 64 bytes.

`headers` declares extra request headers, applied to every CONNECT. Values
may carry `<random-string(N)>` or `<random-string(MIN-MAX)>` placeholders,
re-rolled **per request**: a padding header whose value were fixed for the
connection's life would be exactly the constant it exists to avoid. Bounds
are enforced at parse time (≤ 8 headers, ≤ 8 placeholders and ≤ 8 KiB per
rendered value, ≤ 4 KiB per run), so rendering on the dial path cannot fail,
and a malformed placeholder is a configuration error rather than
padding-shaped literal text. `proxy-authorization` cannot be overridden —
that is the credential. `user-agent` deliberately *can*: overriding it
wholesale is the point of the knob, and a config that does so suppresses the
three spec-shaped values entirely rather than sending two.

Two further name rules, both enforced at config load:

- The connection-specific headers (`connection`, `keep-alive`,
  `proxy-connection`, `transfer-encoding`, `upgrade`, `te`) plus `host` and
  `content-length` are refused. They are illegal on an HTTP/2 or HTTP/3
  request (RFC 9113 §8.2.2, RFC 9114 §4.2) and neither h2 nor the HTTP/3
  encoder strips them client-side, so a receiver would treat the CONNECT as
  malformed and reset the stream — which this client reports as a dial
  failure against a node that is fine. `connection: keep-alive` is exactly
  what gets added to make a request "look like a browser", so the mistake is
  reported where it is still visible.
- A name declared twice (in any case — header names are case-insensitive) is
  refused rather than sent twice.

A value that could render with a leading or trailing space or tab is refused
as well: RFC 9110 §5.5 excludes that whitespace from a field value, and
RFC 9113 §8.2.1 has the receiver treat it as malformed. The check covers
every rendering, so a literal edge behind a placeholder whose minimum is zero
(`abc <random-string(0-8)>`) is refused too.

## HTTP/3 transport

`quic: true` selects HTTP/3 over QUIC (§3.2) instead of HTTP/2 over TLS. The
pool, the CONNECT shapes, the `_udp2` codec and every limit above are
transport-agnostic and unchanged; only the connection and stream layer
differs.

- ALPN is exactly `h3`, enforced twice: offered in the QUIC config, and
  re-checked on the established connection before HTTP/3 is created. The
  request is a CONNECT field section with `:method` and `:authority` and no
  `:scheme` or `:path` (RFC 9114 §4.4).
- An IP-literal server name — the `sni` default when `server` is an
  address — is handled as on HTTP/2: it is not sent as SNI (RFC 6066 §3),
  and the leaf is verified against its `iPAddress` SAN instead of being
  compared as a DNS name.
- The QUIC idle timeout is the spec's `2 × (connection_timeout +
  health_check_timeout)`; this client uses the one configured `timeout` for
  both, so the idle timeout is `4 × timeout`.
- HTTP/3 GOAWAY permanently stops admission on that connection. Subsequent
  stream-credit publication cannot make it reusable; the pool retires it
  before its next capacity decision and opens a fresh connection. Established
  TCP and UDP streams can still complete on the retiring connection.
- Endpoint addresses remain sequential and in resolver order. Each attempt
  has its own child cancellation token: a failed handshake cannot cancel
  later candidates, and caller cancellation stops the current attempt.
  The winner retains the session token's cancellation ancestry. The existing
  one outer CONNECT deadline is unchanged; there is no per-address deadline
  slicing or speculative parallel dial. A silent first address can still
  exhaust that total deadline before later addresses are tried. Address
  racing and blackhole fallback are separate future dial-policy work.

- All traffic rides HTTP/3 streams. QUIC DATAGRAM is *not* enabled: the
  protocol carries UDP on `_udp2` streams, so advertising the extension
  would be a capability nothing uses — and one browsers do not send.
  QUIC-bit greasing stays at quiche's default for the same reason.
- Stream credit is published to the pool (`open + queued + remaining`), so a
  connection that has spent its peer credit is *full* rather than broken:
  the dial moves to another pooled connection or dials a new one, and only
  at the connection cap does it report a typed local-resource error. A
  refusal is never a dial failure that could dead-mark a healthy member.
- The transport owns its UDP socket — QUIC has no stream seam a dialer could
  sit in — so it binds through the shared `bind_udp`, which applies the TUN
  interface binding and the Android `protect()` hook (issue #695). This is
  also why `dialer-proxy` is refused for a `quic` node: there is no TCP
  connection to route through a chained dialer.
- A handshake that fails (untrusted leaf, refused ALPN) is reported as soon
  as the connection starts draining, instead of parking the dial until its
  deadline.
- The QUIC config — including the verify store, which parses the whole webpki
  root bundle — is built once per adapter, as the HTTP/2 path builds its
  `TlsLayer` once at config load, not per dial.
- The connection's driver task is spawned *before* its handshake resolves (it
  is what drives the handshake), so a dial abandoned by its deadline must
  still cancel the token the connection was given; dropping a cancellation
  token does not cancel it. The pool guarantees that on every exit path.

## Intentional divergences (ADR-0002)

| Case | Class | Behavior and reason |
| --- | :---: | --- |
| `quic: true` without `--features trusttunnel-h3` | A | Explicit configuration error naming the feature; a node asking for HTTP/3 never downgrades to HTTP/2. |
| QUIC tuning fields (`cwnd`, `congestion-controller`, `bbr-*`) | A | Explicit configuration error; this client exposes no QUIC congestion/window knobs on either transport. |
| `quic: true` with `client-fingerprint` or `name-cert-verify` | A | Explicit error: there is no uTLS ClientHello shaping over quiche, and quiche installs one name as both the SNI and the certificate's verify hostname, so the two cannot differ. Refusing beats silently dropping a policy the operator asked for. |
| `quic: true` with `dialer-proxy` | A | Explicit error; the QUIC transport owns its UDP socket, so there is no TCP connection for a chained dialer to carry. |
| Certificate pinning, client certificate/key, ECH, custom CA YAML fields, curve preferences | A | Explicit error naming the requested policy; these fields are not yet wired into this parser. |
| ALPN containing additional protocols | A | Requires exactly `[h2]`, or `[h3]` when `quic: true`, so the adapter cannot negotiate a different transport. |
| Per-stream `user-agent` and `headers` | — | Follows the public specification's three shapes (§5.1 / §6.1 / §8.2) rather than one fixed string; `app-name` is unversioned by default. An operator-supplied `user-agent` replaces all three. |
| Mihomo's legacy unbounded pool mode (`max-streams` alone) | B | Warn with effective limits: 16 connections and `max-streams` as the spread threshold (`min-streams`), per-connection ceiling `max(128, max-streams)`, hard ceiling 512; overload returns a typed local admission error. |
| Explicit pool limits beyond the above bounds | B | Configuration error explaining invalid pool limits; no silent clamp. |
| `health-check: true` | B | Warn and check newly opened sessions only; Mihomo additionally checks idle sessions periodically. |
| Official v1.1.0 UDP `::1` decoding | A | The peer interprets this wire address as `0.0.0.1`; real-peer tests use IPv6-encoded mapped loopback. Global IPv6 interoperability remains unverified. |
| Empty or overlong credentials, username containing `:` | A | Explicit error; prevents ambiguous Basic authentication or unbounded credential headers. Credentials are never included in diagnostics. |

## Dependencies and checks

This candidate retains upstream's locked `h2 0.4.16`; the protocol feature
adds no package to `Cargo.lock` and does not change the existing version
range. The empty-DATA interoperability difference in 0.4.19 is discussed
separately with a standalone h2 reproducer in
[h2 #964](https://github.com/hyperium/h2/issues/964) and
[meow-rs #732](https://github.com/meow-rs/meow-rs/issues/732). Tests cover valid interspersed
empty DATA and an empty-frame flood without disabling flood protection.

```sh
cargo test -p meow-proxy --no-default-features --features trusttunnel --lib trusttunnel
cargo test -p meow-proxy --no-default-features --features trusttunnel --test trusttunnel_integration
cargo test -p meow-proxy --no-default-features --features trusttunnel --test trusttunnel_e2e
cargo test -p meow-config --features trusttunnel --test trusttunnel_config_test
cargo test -p meow-config --no-default-features --test trusttunnel_config_test
cargo test -p meow-api --features meow-config/trusttunnel --test api_test trusttunnel_provider
cargo test -p meow-proxy --no-default-features --features trusttunnel-h3 --lib trusttunnel
cargo test -p meow-proxy --no-default-features --features trusttunnel-h3 --test trusttunnel_e2e
cargo test -p meow-config --features trusttunnel-h3 --test trusttunnel_config_test
```

Tests use in-memory H2 peers and self-signed loopback TLS fixtures. The TLS
fixtures explicitly install their generated CA and include certificate/name
failure paths asserting actual X509 verification results. Non-TLS/socket
failures are separately checked not to be classified as certificate failures.
Tests also cover front-group use when internal TCP/UDP opens a session later
reused by user traffic, unchecked-session admission during a pending health
check, process-name privacy, pool saturation without dead-marking,
shared receive-budget drops/recovery, and a length guard independent of EOF;
examples retain normal certificate verification. The full
regression bar in `CONTRIBUTING.md` / `CLAUDE.md` is additionally required
before committing or pushing a contribution.

The HTTP/3 transport additionally runs against an in-tree quiche HTTP/3
endpoint (real certificate, BoringSSL handshake, `quiche::h3` request
handling): a 512 KiB echo through every window in the path, half-close in
each direction, stream reuse, the CONNECT field section (credential, the
three `user-agent` shapes, rendered extra headers, no `:scheme`/`:path`),
`_udp2` multiplexing over IPv4 and IPv6, a 407, stream-credit exhaustion
spreading to a second connection and then reporting a local limit, a refused
ALPN, and `reset()`.

`trusttunnel_e2e` launches the official v1.1.0 endpoint and verifies H2 TCP,
IPv4 and IPv6-encoded mapped UDP, `_check`, shared connections, half-close,
certificate/auth rejection, slow-writer isolation, reset, and concurrent payload integrity.
With `trusttunnel-h3` it also enables the endpoint's own
`[listen_protocols.quic]` listener and repeats the TCP, `_udp2`, `_check`,
connection-reuse, authentication-failure and certificate-verification legs
over HTTP/3 — the only coverage that proves our field section and UDP frames
are what the reference implementation expects on the wire.
Run `bash scripts/fetch-trusttunnel-endpoint.sh /tmp/meow-tt-peer` and set
`TRUSTTUNNEL_SERVER_BIN=/tmp/meow-tt-peer/trusttunnel_endpoint`. The missing
binary is a failure, not an ignored test. Only local runs may opt into
`MEOW_TRUSTTUNNEL_E2E_ALLOW_SKIP=1`; it is rejected when `CI` is set. CI
fetches the pinned official archive and verifies SHA-256 before every run.

The official v1.1.0 peer decodes UDP `::1` as zero-padded `0.0.0.1`, unlike
the current public specification's loopback exception. The real-peer fixture
therefore exercises IPv6 wire encoding with `::ffff:127.0.0.1`; generic IPv6
and the `::1` exception are additionally covered by the hermetic wire test.
This is not a claim of a real-peer global-IPv6 network-path test.
