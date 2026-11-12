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
  vendored; boringtun's device/FFI/JNI halves never enter the tree. See
  [Security note](#security-note) for what that ownership means.
- **The TCP/IP stack** is
  [`smoltcp`](https://github.com/smoltcp-rs/smoltcp): decapsulated IP
  packets feed a smoltcp `Interface` configured with the node's
  `ip`/`ipv6` tunnel addresses and `allowed-ips` routes, and TCP dials
  and UDP flows are smoltcp sockets. WireGuard adds 64 bytes of
  per-packet overhead, so the inner MTU is `mtu - 64` (1356 at the
  default 1420).
- **The pump** is one dedicated thread per adapter holding the boringtun
  `Tunn`, the smoltcp stack (which is not `Send`), and the UDP socket to
  the server endpoint — the same thread-per-session model hysteria2
  uses for quiche. Every `dial_tcp`/`dial_udp` goes through a mailbox to
  that thread, and all TCP streams and UDP flows multiplex over the
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
| `dialer-proxy` | — | — | **hard error** | WG owns its UDP endpoint socket; it cannot ride a TCP dialer |
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
  drop the field.
- **`dns`** is parsed for mihomo config compatibility, stored, and
  ignored — Phase-1 resolves tunnel-side names through the injected
  resolver under `remote-dns-resolve`, not a per-node DNS list. A
  warning naming the node is logged once per config load.
- **`remote-dns-resolve: false`** restricts the node to IP-literal
  destinations: a domain-named flow fails the dial rather than leaking
  a lookup onto the local network.

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
| `dialer-proxy` | ✗ hard reject | WireGuard cannot be carried over a TCP dialer |
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

This is also why `dialer-proxy` is a hard error rather than a silent
fallback: the endpoint socket cannot be replaced by an injected TCP
dialer.

## Known limitations (Phase-1)

- **No AmneziaWG.** `amnezia-wg-option` on a node is a hard parse error
  ("amnezia-wg is not supported in this build"); the obfuscation fields
  and the `<b>`/`<t>`/`<r>` DSL are planned for Phase-3.
- **No `dialer-proxy` on the node** — a hard parse error at load
  (`reject_unthreaded_dialer`): the WG transport owns its UDP endpoint
  socket and cannot be carried over a TCP dialer. A `wireguard` node
  likewise cannot front another node's `dialer-proxy` chain or sit as a
  hop in a `relay` group — it exposes no stream transport for the chain
  to dial through. Put a `fallback`/`url-test` group in front when you
  need failover.
- **`dns` is accepted but ignored** — parsed and stored, warned once
  per config load; `remote-dns-resolve` covers tunnel-side resolution
  in Phase-1. Per-node tunnel DNS lists are Phase-2.
- **`ip-stack` is accepted but always smoltcp.** `gvisor` maps to the
  built-in smoltcp stack; `system` logs a warn-once and uses smoltcp
  too — there is no kernel WireGuard mode in Phase-1 (a kernel WG
  device would be an OS-managed interface outside meow's adapter
  model).
- **One pump thread per adapter.** Every flow through a node shares a
  single-threaded event loop — ample for a WARP-class exit, but one WG
  node will not scale across cores; run several nodes behind
  `load-balance` when you need more.
- **`remote-dns-resolve: false` limits the node to IP literals**, per
  the field note above.
- **Session state is rebuilt, not resumed.** `reset_sessions` (a
  config reload, an explicit session reset) aborts the pump and
  re-handshakes on the next dial; in-flight flows do not migrate.

## Security note

The WireGuard implementation is a **vendored fork of
[`boringtun`](https://github.com/cloudflare/boringtun) 0.7.1**
(BSD-3-Clause, Cloudflare), carried in-tree as `crates/meow-wireguard`
(`publish = false`; the in-crate `LICENSE` and `UPSTREAM` files record
provenance). `ring` is removed — its AEAD and constant-time-equality
call sites are patched onto the workspace's RustCrypto crates
(`x25519-dalek`, `blake2`, `chacha20poly1305`), and each replacement is
enumerated in `crates/meow-wireguard/PATCHES.md` for replay on future
vendor bumps. A CI check fails the build if `ring` ever re-enters the
crate's dependency tree, and an in-process two-peer test (handshake
plus transport round-trip, no network) gates every merge.

That also means **the team owns the fork's maintenance**: upstream
boringtun fixes do not flow in automatically — a bump is a deliberate
re-vendor plus patch replay. The fork does not change the protocol's
properties: standard Noise_IK handshake, no post-quantum protection
beyond the optional `pre-shared-key`, and the same key-handling rules
as any WG client — keep `private-key` (and `pre-shared-key`) out of
shared configs and subscriptions.
