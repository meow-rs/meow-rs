# Shadowsocks inbound listener — encrypted server inbound

Tracks the `listener-shadowsocks` feature. Audience: operators running
meow-rs as a *server* (an encrypted inbound that terminates Shadowsocks
AEAD/stream ciphers and forwards the decrypted flows through the normal
routing engine).

meow-rs already speaks Shadowsocks on the *client* (outbound) side via the
`shadowsocks` crate. This inbound mirrors upstream mihomo's `type:
shadowsocks` listener — it accepts SS-encrypted TCP (and, with `udp: true`,
UDP), decrypts, reads the SOCKS target address from the SS header, and hands
the decrypted stream to the tunnel's `route_inbound_tcp` / UDP relay exactly
like the SOCKS5/HTTP/mixed inbounds. No external `ssserver` binary is
required.

## Quick start

```yaml
# config.yaml
mode: rule
ipv6: false

dns:
  enable: false

proxies:
  - name: direct-out
    type: direct

rules:
  - MATCH,direct-out

listeners:
  - name: ss-in
    type: shadowsocks        # `ss` is accepted as an alias
    listen: 0.0.0.0          # omit to use the global bind-address
    port: 8388
    cipher: aes-256-gcm
    password: your-password
    udp: true                # default true (upstream parity)
```

Run it with a release binary, or any default build (the feature is in the
app's `full` bundle):

```bash
./meow -f config.yaml
```

Any SS client (`sslocal`, the `shadowsocks` crate, or meow-rs's own outbound
`ss` adapter) pointing at `server:8388` with the same cipher/password now
tunnels through meow-rs's rules.

## Fields

| Field | Required | Default | Notes |
|-------|----------|---------|-------|
| `type` | yes | — | `shadowsocks` (or `ss`) |
| `name` | yes | — | unique listener name |
| `listen` | no | global `bind-address` / `0.0.0.0` | bind host |
| `port` | no¹ | — | bind port; `0` = OS assigns an ephemeral port |
| `cipher` | yes | — | any cipher the `shadowsocks` crate supports (`aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-256-gcm`, …) |
| `password` | yes | — | SS password |
| `udp` | no | `true` | enable the UDP relay on the same port |
| `simple-obfs` | no | disabled | see below |

¹ `port` is optional when `listen` is a `host:port` socket address; `0` (or
omitted with no port in `listen`) means the OS assigns an ephemeral port at
bind time. The TCP and UDP relays bind the *same* resolved port.

The listener keeps the `shadowsocks` crate's default replay policy, which is
also `ssserver`'s default: a replayed request is rejected under an AEAD-2022
cipher and not checked under the classic AEAD ciphers (`aes-*-gcm`,
`chacha20-ietf-poly1305`). A listener reachable from the internet should
use a `2022-blake3-*` cipher.

## simple-obfs (HTTP / TLS)

The listener can terminate [simple-obfs](https://github.com/shadowsocks/simple-obfs)
natively — no external `obfs-server` plugin. meow-rs ships both halves of the
codec in-tree (`meow-transport`'s `simple_obfs` module: the client side used by
the outbound `ss`/`snell` adapters, and a server side written here as the
exact inverse). The two are byte-compatible, so a meow-rs server interops with
the reference `obfs-local` client and vice-versa.

```yaml
listeners:
  - name: ss-in
    type: shadowsocks
    port: 8388
    cipher: aes-256-gcm
    password: your-password
    simple-obfs:
      enable: true
      mode: tls        # or `http`
```

simple-obfs is **TCP-only**. When `simple-obfs` is enabled the UDP relay is
automatically skipped (with a log warning) — UDP datagrams cannot be
obfs-framed.

## Unsupported upstream sub-options

These upstream `shadowsocks`-listener sub-options are **not yet supported** and
are *warned about and ignored* (ADR-0002: never silently ignore a mihomo flag,
but don't hard-error so mihomo configs still boot):

- `shadow-tls`
- `res-tls`
- `jls-config`
- `kcp-tun`
- `mux-option`

Remove them from a config to suppress the warnings.

## How it works

### TCP

The accept loop uses the `shadowsocks` crate's `ProxyListener`. For the
no-obfs path the accepted `TcpStream` is handed straight to
`ProxyServerStream::handshake`, which decrypts the SS header and returns the
SOCKS target `Address`. When simple-obfs is configured, the raw stream is
wrapped in the obfs **server** codec (`HttpObfsServer` / `TlsObfsServer`) via
`ProxyListener::accept_map` *before* decryption — obfs is the outer layer. The
obfs mode is fixed per listener, so the accept loop is monomorphised per
concrete stream type (bare `TcpStream` / `HttpObfsServer` / `TlsObfsServer`),
keeping the relay hot path free of dynamic dispatch.

The decrypted `ProxyServerStream` then flows through the shared
`route_inbound_tcp` helper (the same blind-tunnel router used by SOCKS5/HTTP
CONNECT), so rules, proxy groups, statistics, and the REST API behave
identically to the other inbounds.

### UDP

With `udp: true` the listener binds a `shadowsocks::ProxySocket` (server
mode) on the same resolved port. Each decrypted datagram carries a
`(peer, target)` pair; a flat `HashMap<(peer, FlowKey), UdpFlow>` dedups
outbound conns — `FlowKey` is the *unresolved* destination (literal IP or
lowercased domain + port) — mirroring the SOCKS5-UDP per-destination NAT,
but keyed by both endpoints since the socket is shared across SS clients.
Each flow is a bounded 64-datagram FIFO queue feeding a task that performs
resolve → route → `dial_udp` → ordered upstream writes and owns the reply
pump, so a slow destination can never head-of-line block the shared recv
loop (issue #625; the same restructure #619 gave SOCKS5-UDP for #515).
Idle flows are evicted after 60 s
(`meow_tunnel::udp::DEFAULT_UDP_IDLE`, the same constant SOCKS5-UDP uses;
the per-listener `udp-timeout` knob only applies to TProxy UDP and TUN
listeners, not SS). The flow table is capped at the listener's
`max-connections` value (default 256; `0` disables both the TCP and UDP
caps): each flow holds a 64 KiB reply buffer, a task, and an outbound
socket, so without a cap any password holder could exhaust memory/FDs
between idle sweeps. Datagrams for existing flows always pass; only *new*
flows are dropped (with a warn) while the table is saturated. Client UDP —
including port 53 — follows the configured routing policy (a `REJECT` rule
still applies; there is no port-53 DIRECT bypass).

For AEAD-2022 ciphers a second table maps `client_session_id` → relay
session (random server session ID, session-wide reply packet counter, and
the §3.2.4 client packet-ID replay window). It shares the same
`max-connections` bound — unseen session IDs are dropped at capacity while
known ones always pass — and each session is retained for at least 60 s
after its last datagram (the spec's "remembered for at least 60 seconds"
floor, measured independently of flow liveness so an early-dead flow cannot
take the replay window down inside the 30 s header-timestamp tolerance).

## Feature gating

`listener-shadowsocks` is part of the app's `full` bundle, so the default
build and the release binaries include it. It costs about 200 KiB of a
stripped x86_64 binary, since `full` already links the `shadowsocks` crate
for the `ss` outbound. The `minimal` bundle leaves it out: there it would
take half the room left under the 8 MiB aarch64 cap (ADR-0007). A build
without the feature, such as `minimal`, fails `-t` and startup on a
`type: shadowsocks` listener and names the feature;
`--no-default-features --features minimal,listener-shadowsocks` adds it
back. On meow-listener itself the feature stays off by default and pulls
in the `shadowsocks` workspace dep and `meow-transport/simple-obfs`.

## Differences from the other inbounds

- **No sniffer**: unlike `mixed`/`socks5`, the SS inbound is not wired into
  the TLS/HTTP sniffer — the SS header already carries a domain when the
  client sends one, which the routing engine uses directly.
- **UDP flow cap**: the `(peer, target)` flow table shares the listener's
  `max-connections` cap (see above); the SOCKS5 UDP relay's table instead
  lives and dies with its TCP control connection and is hard-bounded at
  1024 sessions with least-recently-active eviction (issue #515).
