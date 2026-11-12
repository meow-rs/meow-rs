# WireGuard inbound listener (`type: wireguard`)

Implementation spec for the WireGuard *responder* listener — meow as the
WG server, the mirror image of the `type: wireguard` outbound (#899).
Semantically this is "a TUN inbound carried over WireGuard" — the same
shape as sing-box's `wireguard` inbound.

Status: implemented. Feature: `listener-wireguard` (meow-app `full`,
never `minimal`).

## Motivation

A WireGuard inbound lets any stock WG client (kernel `wg`, `wg-quick`,
`wireguard-go`, Cloudflare WARP-style tooling) tunnel TCP/UDP through
meow's rule engine with zero client-side proxy awareness. Peers are
static — there is no peer provisioning protocol; each entry in
`peers:` is a pinned public key plus an inner-source ACL.

## Config schema

```yaml
listeners:
  - name: wg-in
    type: wireguard
    listen: 0.0.0.0
    port: 51820
    private-key: <base64 32-byte responder key>
    mtu: 1420               # outer wire MTU; inner IP MTU = mtu - 64
    udp: true               # false drops inner UDP silently
    udp-timeout: 60         # inner UDP flow idle seconds (nonzero)
    max-connections: 256    # combined TCP conn + UDP flow cap; 0 = unlimited
    peers:
      - name: laptop        # diagnostic label only; defaults to peer-<i>
        public-key: <base64 32-byte peer key>
        preshared-key: <base64 32-byte optional psk>
        allowed-ips: [10.0.0.2/32]   # inbound inner-source ACL, nonempty
        reserved: [0, 0, 0]          # optional WARP-style 3-byte field
```

Validation rejects: malformed/short keys, empty `peers`, empty
`allowed-ips`, duplicate peer public keys, a peer key equal to the
listener's own public key (the same key would handshake with itself),
`mtu` outside 640–9000, `udp-timeout: 0`, and `peers.len() ≥ 2^24`
(the receiver-index namespace). Unknown fields warn, not error.
`persistent-keepalive` is deliberately absent — a responder never
initiates.

## Architecture

```
peer UDP socket (one per listener, bound by the app before spawn)
        │  dedicated actor thread + current-thread tokio runtime
        ▼
PeerTable (demux.rs)
   1. shared RateLimiter::verify_packet — mac1 + handshake-rate +
      cookie replies, BEFORE any per-peer work
   2. dispatch — HandshakeInit: parse_handshake_anon → peer_by_pubkey
      (O(1)); HandshakeResponse / CookieReply / Data:
      receiver_idx >> 8 → peer slot
   3. per-peer Tunn::handle_verified_packet — authenticate+decrypt
   4. roam — a non-error result on a nonempty datagram re-learns the
      peer's endpoint
   5. ACL — inner src IP must be inside peer.allowed_ips, else silent
        ▼                                    ▼
   smoltcp Interface (AnyIP)         inner UDP flow table
   lazy (peer,dport) listen pool     (slot, src, dst) keyed
   State::Listen placeholders ≤64    bounded queues, idle-evicted
        │                                    │
        ▼                                    ▼
   route_inbound_tcp (sniff window   TunnelInner::dial_udp
   shared with TUN path)             (SOCKS5-UDP path)
```

- **Index namespace.** Each peer's `Tunn::new(slot)` puts the slot in
  the receiver index's upper bits (`index << 8` inside `Tunn::new` —
  callers pass the slot, never a pre-shifted value) and cycles sessions
  through the low byte, so `receiver_idx >> 8` is an O(1) dispatch and
  the low-byte counter may wrap freely (session ring +
  WrongIndex-checks absorb it).
- **Roaming.** Endpoints move only on authenticated, non-error,
  non-empty datagrams — the empty datagrams used to flush boringtun's
  send queue never re-learn (WG semantics: a valid packet under the
  session *is* the proof of reachability).
- **Reserved bytes.** Inbound datagrams have bytes 1..4 cleared before
  parsing (the vendored parser's strict type-word check is upstream's
  and stays). Outbound datagrams to a peer get that peer's configured
  3-byte `reserved` stamped post-encapsulation.
- **Rate limiting.** One listener-level `RateLimiter` shared across
  peers, sized `PEER_HANDSHAKE_RATE_LIMIT × peer count`; the actor calls
  `reset_count()` every ~250 ms timer tick — the limiter's own one-
  second debounce decides the roll (errata E1). Forged MACs, unknown
  peer keys, out-of-range receiver indices and malformed packets are
  silently dropped — at most a `trace!`.
- **TCP accept.** smoltcp `Interface` with `set_any_ip(true)` *and* a
  default route whose gateway is an interface-owned address (errata E2
  — both are required or ingress is dropped as unroutable). A fresh
  `SYN && !ACK` lazily mints a `State::Listen` placeholder on
  `{addr: None, port: dport}` for the owning peer; the pool is capped
  at 64 and evicts by age **only among still-`Listen` sockets**
  (errata E5 — a transitioned socket is a flow, never a pool member;
  a fully-transitioned pool refuses new dports). `max_connections`
  counts inner TCP conns + UDP flows together, enforced both at
  listener demand (`in_flight_accept`) and again at post-poll accept
  time — a SYN to an existing listener's port is accepted by smoltcp
  regardless, then RST-aborted if over cap.
- **TCP tail.** An `Established` socket becomes a `WgStream`; the route
  task runs the TUN path's sniff window (`stream_sniff.rs` — first
  payload, ClientHello/`Host` gather, `sniff_bytes`) then
  `route_inbound_tcp` with `ConnType::WireGuard`, `src` = inner source,
  `in_name`/`in_port` = the listener's.
- **UDP.** No smoltcp involvement: datagrams key a flow table on
  `(peer_slot, inner_src, inner_dst)`; each flow task resolves and
  `dial_udp`s through the tunnel (fake-IP unmap, rule match, flush
  watch — the TProxy `udp_flow` shape). Replies are hand-built inner
  IPv4/IPv6 packets with real checksums, capped at `inner_mtu`
  (oversized replies drop silently — never fragmented, never ICMP),
  then encrypted under the *originating* peer's session and sent to its
  learned endpoint.
- **MTU.** `inner_mtu = mtu - 64` (WG + UDP + IP overhead), floor 576;
  smoltcp's TCP MSS clamp follows from the interface MTU. Inner
  fragments drop — a legal inner datagram always arrives whole.

## Key hygiene

`WgListenerSpec`/`WgPeerSpec` and the config types hand-roll `Debug` to
print `[REDACTED]` for `private_key`/`preshared_key`; peer public keys
are shown (they are the demux key). `info!` records bind + per-peer
session establishment (peer label only); endpoint roam and flow
lifecycle are `debug!`; every drop path is `trace!` — no key material
ever reaches a log line.

## Concurrency model

Everything smoltcp/`Tunn` touches lives on one dedicated thread with a
current-thread runtime — the outbound pump's actor pattern reversed.
Routing tasks (`route_inbound_tcp`, UDP flow loops) are spawned back
onto the app runtime via the `Handle` captured at `spawn`, so DNS and
upstream dials never serialize behind the wire loop. All channels are
bounded: wire drain budget, per-flow TCP read/write queues, UDP payload
queue (drop-on-full), and the flow→actor inject queue (drop-on-full —
a UDP reply never stalls the loop).

## Tests

- §11.1 unit matrix: receiver-index `>>8` dispatch, pubkey-map hit/miss,
  forged mac1, response/cookie dispatch, index-namespace disjointness,
  authenticated-only roaming, v4/v6 ACLs, PSK on/off, inbound reserved
  clearing, cookie reply under load, listen-pool lazy alloc + E5
  eviction, UDP flow idle eviction + queue-full drop, IPv4/IPv6 reply
  goldens + checksums + MTU bounds (19 tests across `demux.rs`,
  `inner_udp.rs`, `actor.rs`).
- §11.2 integration (`tests/wireguard_listener.rs`): the real
  `WireGuardAdapter` as in-process client over loopback UDP — TCP echo
  v4/v6, UDP echo, multi-peer isolation + forged-source ACL drop,
  endpoint roaming via a raw `Tunn` client, unknown-peer silence,
  `max_connections` backpressure (RST refusal, survivor unaffected),
  SNI sniff → DOMAIN rule, shutdown drain.
- `meow-config` parser matrix in `wireguard_listener_config_test.rs`
  (30 tests): every rejection row, defaults, warns, serde roundtrip,
  key redaction.
- API: `GET /connections` `metadata.type == "WireGuard"` pinned in
  `api_test.rs`; `GET /listeners` `type=wireguard` falls out of
  `type_name()` for free.
- CI: the `test.yml` WG leg gains the listener clippy/nextest runs plus
  ring-free dep-tree assertions on the `meow-listener --features
  listener-wireguard` and `meow-wgstack` trees; the `minimal` assertion
  adds `meow-wgstack`.

## Acceptance (condensed)

`meow -t` and runtime parse the schema with per-field hard errors; all
five app feature combos compile; the feature gate reports
`needs feature 'listener-wireguard'` when absent; loopback handshake →
data → echo is byte-exact for TCP (v4+v6) and UDP; peers stay isolated
under `receiver_idx >> 8`; roaming only on authenticated datagrams;
ACL drops forged sources both families; over-MTU UDP replies drop;
`minimal` keeps `meow-wireguard`/`meow-wgstack`/`smoltcp` out of its
dep tree; no key material in Debug or logs.
