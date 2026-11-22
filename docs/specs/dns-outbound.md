# Spec: `type: dns` outbound (issue #974)

Status: Implemented.
Upstream reference: mihomo `v1.19.34` `C.Dns` (`adapter/outbound/dns.go`),
`constant/adapters.go` — a leaf outbound that consumes the flow's DNS
payload through the kernel's own resolver instead of dialing anywhere.
The binding parity analysis lives in the issue history; this document
records the contract meow ships.

## Motivation

A `type: dns` node is an in-process resolver endpoint, not a transport.
Routing a DNS exchange to it answers the query from meow's internal
resolver — the same pipeline the standalone `dns.listen` server and the
listener/TUN DNS-hijack paths serve — so policy routing can direct DNS
traffic deliberately (`DST-PORT,53,dns-out`, rule-set exceptions,
per-listener `proxy:` overrides) without inventing a UDP socket the
payload never wanted. mihomo implements it as a control leaf: the
adapter reports an empty address, owns no transport, and answers the
exchange locally. The nominal destination is never contacted.

## Configuration contract

```yaml
proxies:
  - name: dns-out
    type: dns

rules:
  - DST-PORT,53,dns-out
```

`DST-PORT,53,dns-out` is merely a routing-rule choice — port 53 is a
property of the *flow*, not an adapter restriction. A `type: dns` leaf
imposes no port gate of its own: flows on other ports are answered (or
fail) the same way.

### `type: dns` node

- Requires `name` and `type: dns`. **No endpoint/protocol parameters**:
  the node carries no `server`, no `port`, and no `udp` meaning of its
  own.
- `server`, `port`, `udp`, and transport keys (`routing-mark`,
  `interface-name`, `ip-version`, `tfo`, `mptcp`, and the
  TLS/mux/obfs/plugin family) are **ignored, with warnings rather than
  rejection — even when ill-typed**. A `port: "banana"` on a dns node is
  not a parse error: the key never reaches a typed field.
- `dialer-proxy` **on** a dns node is ignored and creates **no edge** —
  neither at collection (`collect_dialer_edges` skips `type: dns` like
  `type: rematch`) nor at parse (the leaf is built bare, never wrapped
  in `DialerProxyAdapter`). A statically resolvable dns leaf **as** a
  dialer front is rejected at build, and the leaf's dial path fails
  closed on a `ConnType::Inner` hop if a dynamic group pick lands on it.
- Provider-sourced dns nodes behave identically: parsed bare, the
  provider-level `dialer-proxy` knobs ignored with a warning, bound to
  the same resolver cell the config commit populates.

## Serving contract

- **TCP**: the flow speaks RFC 1035 length-prefixed DNS — a two-byte
  big-endian length prefix, exactly one message per frame, requests and
  replies both framed — over an in-process stream a serve loop drains.
  A short prefix, a short body, an undecodable message or an oversize
  frame closes the stream; orderly EOF between frames closes cleanly.
  There is no per-exchange deadline: the tunnel owns connection
  lifetime.
- **UDP**: each datagram is one DNS exchange. Undecodable wire earns a
  silent drop — UDP semantics, the client retries. The reply is fit to
  the client's EDNS-advertised payload (512 without OPT, capped at
  2048): oversized answers drop whole records and set TC, which is what
  prompts a stub resolver to retry over TCP. The reply's apparent
  source is the destination the client claimed — what a bound socket to
  that resolver would report.
- The answer pipeline is the shared `DnsServer` machinery: local fast
  path (hosts, fake-IP, fresh cache) first, then the bounded upstream
  query path — DNS IDs and questions are preserved, malformed packets,
  opcodes, non-IN classes and EDNS OPT records behave exactly as on the
  standalone server.
- A shared bounded query budget caps upstream-bound queries across every
  conn the adapter hands out; locally answerable queries never draw a
  permit.
- **DNS availability honours `dns.enable`**: a disabled `dns:` section
  publishes a disabled resolver generation (`ResolverGen.enabled`), and
  a `type: dns` leaf answers SERVFAIL for it — never the stub fallback
  upstream `dns_parser` still constructs (`8.8.8.8`). An unbound leaf —
  no resolver installed yet — SERVFAILs the same way.
- **Hot swap**: the leaf reads the tunnel's shared `ResolverSlot` per
  query, so a `PUT /configs` / subscription / geodata rebuild's new
  generation — including its enabled bit — reaches conns already open.

## Invariants

- A `type: dns` leaf never opens a socket: no dial to its nominal
  destination, no dial to an upstream — the only network it can induce
  is the resolver's own upstream traffic, identical to a query the
  standalone server forwarded.
- `dialer-proxy` chains: a dns node is never a chain member in either
  direction (its own `dialer-proxy` is ignored; a statically known dns
  target is a build error; a dynamic pick fails closed).
- The standalone `dns.listen` server, listener DNS-hijack and TUN
  DNS-hijack paths are untouched: they share the same `ResolverSlot`
  payload but read only the resolver half, so `enabled` cannot flip
  their behaviour.
- `AdapterType::Dns` renders `"Dns"` on the API surface and counts UDP
  NAT sessions like any live outbound (it is not a nop).
