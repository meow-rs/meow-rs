# WireGuard outbound

Last updated: 2026-11-12. Tracks the `wireguard` Cargo feature (issue
[#899](https://github.com/madeye/meow-rs/issues/899)).
Audience: users routing traffic through a WireGuard peer — a commercial
WG VPN, Cloudflare WARP, or a self-hosted WireGuard server.

The `wireguard` proxy type is a userspace WireGuard client: meow performs
the Noise handshake and transport encryption in-process, terminates the
tunnel's IP packets in an embedded TCP/IP stack, and dials each flow's
destination from inside the tunnel — the mirror image of the `tun:`
inbound. The config surface is mihomo-compatible: a `type: wireguard`
entry copied out of a Clash Meta config loads unchanged, modulo the
Phase-1 carve-outs under [Known limitations](#known-limitations-phase-1).

Phase-1 scope is standard WireGuard only — no AmneziaWG and no kernel
mode (see below). The adapter lives behind the `wireguard` Cargo
feature: the `full` bundle — and therefore the release binaries —
includes it; `minimal` builds leave it out
([ADR-0007](adr/0007-m2-footprint-budget.md) binary-size caps). On a
build without the feature a `type: wireguard` node fails to parse with
an error naming the feature.

## How it works

Each `wireguard` node owns three pieces, built lazily on the first dial
and torn down by `reset_sessions`:

- **The Noise layer** is a vendored copy of Cloudflare's
  [`boringtun`](https://github.com/cloudflare/boringtun) 0.7.1
  (`crates/meow-wireguard`, BSD-3-Clause) with `ring` replaced by the
  workspace's RustCrypto crates — `x25519-dalek`, `blake2`,
  `chacha20poly1305`. Only the `noise/` and serialization modules are
  vendored; boringtun's device/FFI/JNI halves never enter the tree.
  Behind the optional `wireguard-boring` Cargo feature the *session*
  data-path AEAD (the per-packet ChaCha20-Poly1305) runs on BoringSSL's
  `AeadCtx` — the key schedule is built once per session instead of per
  packet, on the same vendored BoringSSL the rest of the tree already
  links — while the Noise handshake stays on RustCrypto either way.
  meow-proxy's `wireguard` feature enables it, so release builds take
  the BoringSSL path; a standalone `meow-wireguard` build without it
  keeps the pure-RustCrypto session path, and both backends produce
  identical wire bytes. See
  [Security note](#security-note) for what that ownership means.
- **The TCP/IP stack** is
  [`smoltcp`](https://github.com/smoltcp-rs/smoltcp): decapsulated IP
  packets feed a smoltcp `Interface` configured with the node's
  `ip`/`ipv6` tunnel addresses and `allowed-ips` routes, and TCP dials
  and UDP flows are smoltcp sockets. WireGuard adds 64 bytes of
  per-packet overhead, so the inner MTU is `mtu - 64` (1356 at the
  default 1420).
- **The pump** is one tokio task per adapter holding the boringtun
  `Tunn`, the smoltcp stack, and the UDP transport to the server
  endpoint — a raw socket directly, or a channel bridge to the
  `dialer-proxy` front's UDP association. It runs on the shared
  multi-thread runtime (smoltcp's types are `Send`, so the dedicated
  `std::thread` it replaced bought nothing); `block_in_place` is
  borrowed only briefly around the batched crypto joins in the wire
  drain. Every `dial_tcp`/`dial_udp` goes through a mailbox to
  that task, and all TCP streams and UDP flows multiplex over the
  single WireGuard session. The pump initiates the handshake when it
  starts: a session that is not established within 10 seconds fails the
  waiting dials; a TCP dial otherwise carries a 30-second timeout, a UDP
  bind 10 seconds.

The endpoint's UDP socket is bound through `bind_udp_for_peer`, which is
what keeps the tunnel alive under `tun.auto-route: global` — see
[Routing-loop prevention](#routing-loop-prevention).

## Configuration reference

A `proxies:` entry with `type: wireguard` takes these fields:

| YAML key | Type | Default | Validation | Notes |
|----------|------|---------|------------|-------|
| `name` | `String` | — | non-empty | standard |
| `type` | literal `"wireguard"` | — | exact match (`wireguard` or `WireGuard`) | |
| `server` | `String` | — | non-empty | hostname or IP of the WG endpoint |
| `port` | `u16` | — | 1–65535 | endpoint UDP port |
| `private-key` | base64 | — | decodes to exactly 32 bytes | your X25519 secret; wrong length is a hard error |
| `public-key` | base64 | — | decodes to exactly 32 bytes | peer's X25519 public key; wrong length is a hard error |
| `ip` | IPv4 or IPv4 CIDR | none | valid address | WG tunnel IPv4 address |
| `ipv6` | IPv6 or IPv6 CIDR | none | valid address | WG tunnel IPv6 address |
| `allowed-ips` | list of CIDRs | `["0.0.0.0/0", "::/0"]` | each entry a valid CIDR | routes into the tunnel |
| `pre-shared-key` | base64 | none | decodes to exactly 32 bytes when present | optional PSK (post-quantum hedge) |
| `reserved` | `[u8; 3]` | none | 3-element list, or base64 decoding to 3 bytes | Cloudflare WARP client identifier |
| `persistent-keepalive` | `u16` seconds | `0` | ≥ 0 | `0` disables; ~25 holds NAT state open |
| `mtu` | `u16` | `1420` | 640–9000 | outer MTU; inner = `mtu - 64` ≥ 576 |
| `udp` | `bool` | `true` | — | carry UDP flows through the tunnel |
| `remote-dns-resolve` | `bool` | `true` | — | resolve destination domains inside the tunnel |
| `dns` | list of nameservers | `[]` | **accepted but ignored** — warns once | per-node tunnel DNS is Phase-2 |
| `dialer-proxy` | proxy name | none | front must provide a UDP association | the endpoint's UDP transport rides the front hop (e.g. `direct` with routing-mark, `ss`, `socks5`); a UDP-less front fails at dial time |
| `amnezia-wg-option` | — | — | **hard error** | AmneziaWG is not in this build (Phase-3) |
| `ip-stack` | `"gvisor"` / `"system"` | none | accepted; `system` warns once, both map to smoltcp | no kernel WG mode in Phase-1 |

Field notes:

- **`ip` / `ipv6`** are the tunnel interface addresses smoltcp answers
  from. A node can run with neither (IP-literal destination flows still
  work), but TCP needs a source address — set at least one if you expect
  TCP traffic. Config load warns when both are absent and
  `remote-dns-resolve: true`.
- **`reserved`** is applied after encapsulation: bytes 1–3 of each
  outbound WireGuard packet header are overwritten with the configured
  bytes before send. Cloudflare WARP requires them; other servers can
  drop the field. Inbound, the same header bytes are *zeroed* before the
  datagram reaches the vendored noise parser — don't-care receive
  semantics, so a WARP peer that echoes non-zero identifiers back does
  not wedge the handshake.
- **`dns`** is parsed for mihomo config compatibility, stored, and
  ignored — Phase-1 resolves tunnel-side names through the injected
  resolver under `remote-dns-resolve`, not a per-node DNS list. A
  warning naming the node is logged once per config load.
- **`remote-dns-resolve: false`** restricts the node to IP-literal
  destinations: a domain-named flow fails the dial rather than leaking
  a lookup onto the local network.
- **`dialer-proxy`** routes the WG endpoint's UDP transport through the
  named front's UDP association instead of a raw socket — for a routing
  mark/binding on the egress (`direct`), or a real chained front (`ss`
  with UDP, `socks5`). A domain `server` is delegated to the front's
  own resolver (same `Name` semantics as the TCP chain); a front that
  cannot carry a domain target gets a local-resolution fallback dial
  per candidate. If the front is a group, whichever member is live at
  dial time must support UDP — a UDP-less pick fails the endpoint bind,
  closed like any other endpoint error (never a silent direct egress).
  Chaining WG *through* WG is legal but pays double crypto + MTU
  shrink — lower `mtu` accordingly. `persistent-keepalive` holds the
  front's NAT/association state open; if the front's UDP association
  still dies, the pump treats the closed proxy endpoint as terminal
  and exits, so the next dial clears the stale pump and redials the
  front hop — automatic recovery, no config reload needed. (The direct
  path without `dialer-proxy` is unchanged: socket recv errors are
  treated as transient and retried in place.)

## Example config

A complete mihomo-compatible entry (Cloudflare WARP shape — `reserved`
is what WARP needs; a private WG server can drop it together with
`pre-shared-key` and `persistent-keepalive`):

```yaml
proxies:
  - name: warp
    type: wireguard
    server: engage.cloudflareclient.com
    port: 2408
    ip: 172.16.0.2
    ipv6: fd01:5ca1:ab1e:80fa:ab63:6eea:8f63:f386
    private-key: eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=
    public-key: bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
    pre-shared-key: sWrYKUBHgEMJ9xQKbW7OpZQbCVhDfkFI4qw/iyxImIM=
    reserved: [13, 53, 133]           # or base64: "DTWF"
    persistent-keepalive: 25
    mtu: 1420
    udp: true
    remote-dns-resolve: true
    allowed-ips:
      - 0.0.0.0/0
      - "::/0"

rules:
  - MATCH,warp
```

Rules treat the node like any other outbound — `MATCH,warp`, group
membership and `GET /proxies` delay probes all apply. `udp: false`
makes the node report no UDP support, so a UDP flow skips the rule that
selects it.

## Mihomo compatibility

| mihomo field | meow-rs support | Notes |
|-------------|-----------------|-------|
| `server` | ✓ | |
| `port` | ✓ | |
| `ip` | ✓ | WG tunnel IPv4 address |
| `ipv6` | ✓ | WG tunnel IPv6 address |
| `private-key` | ✓ | base64 |
| `public-key` | ✓ | base64 |
| `pre-shared-key` | ✓ | optional |
| `reserved` | ✓ | 3-byte Cloudflare WARP identifier |
| `mtu` | ✓ | default 1420 |
| `udp` | ✓ | default true |
| `persistent-keepalive` | ✓ | |
| `allowed-ips` | ✓ | default ["0.0.0.0/0", "::/0"] |
| `remote-dns-resolve` | ✓ | default true |
| `dns` | accepted (ignored, Phase-1) | custom tunnel DNS planned for Phase-2 |
| `dialer-proxy` | ✓ (UDP fronts) | endpoint UDP rides the front's UDP association; UDP-less fronts fail at dial time |
| `ip-stack` | accepted (smoltcp) | "system" silently maps to smoltcp |
| `amnezia-wg-option` | ✗ hard reject | AmneziaWG planned for Phase-3 |

("Silently" in the `ip-stack` row describes the mapping, not the load —
`system` still logs the warn-once described under
[Known limitations](#known-limitations-phase-1).)

## Routing-loop prevention

A WireGuard endpoint is itself a UDP destination — under
`tun.auto-route: global` a naive `UdpSocket::bind` would send the
tunnel's own handshake and transport packets back into the TUN device
and strangle the session. The adapter therefore opens the endpoint
socket through `meow_common::socket_protect::bind_udp_for_peer`, the
same path hysteria2's QUIC socket and kcptun use:

- the socket takes the installed `OutboundBinding`
  (`SO_BINDTODEVICE` on Linux, `IP_BOUND_IF`/`IPV6_BOUND_IF` on macOS,
  `IP_UNICAST_IF`/`IPV6_UNICAST_IF` on Windows) before it sends, so its
  packets leave through the physical interface regardless of the route
  table;
- the socket's family follows the peer's resolved address, and a
  **loopback** endpoint is deliberately left unbound — a WG server on
  `127.0.0.1` stays reachable under global route scope.

`dialer_hop_network` reports `Network::Udp`, so load-balance groups
that key members on transport see the node for what it is.

A node-level `dialer-proxy` replaces that raw socket with the front
hop's UDP association rather than fighting the same-loop mechanism:
`direct` fronts still bind through `bind_udp_for_peer` inside their own
`dial_udp_conn`, so the interface-binding guarantee above carries over
to the chained path unchanged.

## Known limitations (Phase-1)

- **No AmneziaWG.** `amnezia-wg-option` on a node is a hard parse error
  (`'amnezia-wg-option' is not supported in this build`); the obfuscation
  fields and the `<b>`/`<t>`/`<r>` DSL are planned for Phase-3.
- **`dialer-proxy` needs a UDP-capable front** — the WG endpoint's UDP
  transport rides the front hop's UDP association (`direct` with
  routing-mark, `ss`, `socks5`, a group whose live member supports
  UDP). A TCP-only front (e.g. `trojan`, `vless` without UDP) fails the
  endpoint bind at dial time — closed, never a silent direct egress.
  Put a `fallback`/`url-test` group in front when you need failover.
- **Chain head only, never a middle hop.** A `wireguard` node's
  `dial_tcp`/`dial_udp` are complete tunnel exits, so the node can front
  another node's `dialer-proxy` chain and can sit as the first hop of a
  `relay` group — chained destinations pass the same `allowed-ips` gate
  as any dial. It cannot sit at a later relay hop: it exposes no stream
  transport for `connect_over` to run the next hop's handshake over, so
  the trait default `NotSupported` fires at dial.
- **`dns` is accepted but ignored** — parsed and stored, warned once
  per config load; `remote-dns-resolve` covers tunnel-side resolution
  in Phase-1. Per-node tunnel DNS lists are Phase-2.
- **`ip-stack` is accepted but always smoltcp.** `gvisor` maps to the
  built-in smoltcp stack; `system` logs a warn-once and uses smoltcp
  too — there is no kernel WireGuard mode in Phase-1 (a kernel WG
  device would be an OS-managed interface outside meow's adapter
  model).
- **One pump task per adapter.** Every flow through a node shares a
  single-actor event loop on the shared runtime (perf-7 moved it off
  the dedicated `std::thread`) — ample for a WARP-class exit, but one
  WG node will not scale across cores; run several nodes behind
  `load-balance` when you need more.
- **`remote-dns-resolve: false` limits the node to IP literals**, per
  the field note above.
- **Session state is rebuilt, not resumed.** `reset_sessions` (a
  config reload, an explicit session reset) aborts the pump and
  re-handshakes on the next dial; in-flight flows do not migrate.

## WireGuard inbound (`listeners: - type: wireguard`)

The mirror image of the node: meow as the WireGuard *server* — a static
multi-peer responder that decrypts inner IPv4/IPv6 traffic and feeds it
through the same route engine a `tun:` inbound uses. Semantically it is
"a TUN carried over WireGuard"; the shape follows sing-box's `wireguard`
inbound. Feature: `listener-wireguard` (meow-app `full`, never
`minimal`); a build without it reports `needs feature
'listener-wireguard'` at config validation.

```yaml
listeners:
  - name: wg-in
    type: wireguard
    listen: 0.0.0.0
    port: 51820                 # 0 = ephemeral, resolved before bind
    private-key: <base64 32-byte key>   # openssl rand -base64 32
    mtu: 1420                   # wire MTU; inner IP MTU = mtu - 64
    udp: true                   # false drops inner UDP silently
    udp-timeout: 60             # seconds an idle UDP flow survives
    max-connections: 256        # TCP conns + UDP flows combined; 0 = ∞
    peers:
      - name: laptop            # diagnostic label (logs), defaults peer-<i>
        public-key: <base64 32-byte peer key>
        preshared-key: <base64 32-byte key>   # optional
        allowed-ips: [10.0.0.2/32]            # inner-source ACL, nonempty
        reserved: [0, 0, 0]                   # optional WARP-style field
```

- `peers` is the static peer table — an unknown public key cannot even
  decrypt the handshake. `allowed-ips` is the *inbound* ACL: inner
  packets whose source IP is outside the peer's list are silently
  dropped (v4 and v6). A peer key may not equal the listener's own
  public key, and duplicates are rejected at parse.
- **Roaming** follows WireGuard semantics: a peer's remembered endpoint
  moves to whatever source address an *ACL-admitted inner packet* arrives
  from — bare handshakes, keepalives, forged or replayed packets never
  re-aim replies.
- **TCP** terminates in userspace (smoltcp, AnyIP): the first `SYN` to a
  port lazily starts listening on it — peers reach whatever they dial,
  like a TUN. New streams get the TUN path's sniff window (SNI/`Host`)
  and are routed by `route_inbound_tcp` with `ConnType::WireGuard`;
  `GET /connections` reports `metadata.type = "wireguard"`.
- **UDP** (when `udp: true`) is routed per-flow through
  `TunnelInner::dial_udp`, keyed on `(peer, inner src, inner dst)` and
  evicted after `udp-timeout`; replies are size-capped at `mtu - 64` and
  drop silently beyond that — never fragmented, never ICMP.
- **No `persistent-keepalive`** on the server side — a responder never
  initiates. Cookie replies, handshake rate limiting and mac1 checks
  are inherited from the vendored boringtun; one listener-level limiter
  is shared across peers.
- The responder shares one UDP socket per listener across all peers;
  `receiver_idx >> 8` dispatches responses/cookies/data in O(1), so
  peers stay cryptographically isolated.

**Memory budget.** Inner TCP socket buffers come from `meow-wgstack`'s
`TCP_SOCKET_BUF` — 4 MiB per direction per connection, chosen because
the rx half doubles as the advertised TCP window: per-flow inbound
throughput caps at `buf / RTT`, so 4 MiB lifts a ~140 ms-RTT peer from
~0.5 MB/s (at 64 KiB) to ~30 MB/s (1 MiB reached ~7.5 MB/s). The trade
is 8 MiB eagerly allocated per
inner conn — virtual, not resident: the zeroed Vecs only commit the
pages a flow actually fills, so idle/lightly-loaded conns cost almost
nothing and committed memory tracks real backpressure — ~8.5 MiB
typical with its channel-queue share, ~14 MiB
worst-case staged (the 4 MiB read channel plus a full write queue
and pending slots, on top of the eager buffers) — so a deployment's
budget is roughly conns × ~8.5 MiB typical, × ~14 MiB worst case,
+ ≤512 MiB of listen-pool placeholders (64 × the same 8 MiB) +
outbox/scratch slack — ~2.7 GiB typical, ~4.2 GiB worst case at the
default `max-connections: 256`. The cap is the lever: set it against
the host's memory envelope, not just the conn target — `0` disables
the limit and lets committed memory scale with active flow count
without a ceiling, which a small host should not do. The outbound
node's own dials pay the same 8 MiB apiece.

The listener's UDP socket binds eagerly at startup (`port: 0` resolves
to the real port before the actor spawns — `GET /listeners` shows it).
Config validation rejects bad/short keys, empty `peers`, empty
`allowed-ips`, `mtu` outside 640–9000, `udp-timeout: 0` and ≥2²⁴ peers;
private keys and preshared keys are `[REDACTED]` in Debug output and
never logged. Implementation details: [spec](specs/proxy-wireguard-server.md).

## Security note

The WireGuard implementation is a **vendored fork of
[`boringtun`](https://github.com/cloudflare/boringtun) 0.7.1**
(BSD-3-Clause, Cloudflare), carried in-tree as `crates/meow-wireguard`
(published under the `meow-` name like `meow-anytls`/`meow-lwip` so
`meow-proxy`'s optional `wireguard` feature resolves from crates.io; the
in-crate `LICENSE` and `UPSTREAM` files record provenance). `ring` is removed — its AEAD and constant-time-equality
call sites are patched onto the workspace's RustCrypto crates
(`x25519-dalek`, `blake2`, `chacha20poly1305`), and each replacement is
enumerated in `crates/meow-wireguard/PATCHES.md` for replay on future
vendor bumps. A CI check fails the build if `ring` ever re-enters the
crate's dependency tree, and an in-process two-peer test (handshake
plus transport round-trip, no network) gates every merge. The optional
`wireguard-boring` feature swaps the *session* data-path AEAD to the
vendored BoringSSL (`boring::aead::AeadCtx`) — still no `ring`, and the
handshake stays on RustCrypto — with a fixed known-answer test pinning
byte-identical session ciphertext across the two backends.

That also means **the team owns the fork's maintenance**: upstream
boringtun fixes do not flow in automatically — a bump is a deliberate
re-vendor plus patch replay. The fork does not change the protocol's
properties: standard Noise_IK handshake, no post-quantum protection
beyond the optional `pre-shared-key`, and the same key-handling rules
as any WG client — keep `private-key` (and `pre-shared-key`) out of
shared configs and subscriptions.
