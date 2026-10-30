# Sniffer

The sniffer peeks at the start of a connection to recover the real destination **domain**
from the traffic itself — the TLS SNI in a ClientHello, or the `Host` header of an HTTP
request. This is what lets domain rules work for transparent flows where the client only
gave you an IP.

```yaml
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443, 8443]
    HTTP:
      ports: [80, 8080]
```

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enable` | bool | `false` | Turn the sniffer on |
| `timeout` | u64 (ms) | `100` | Max wait for app-layer bytes (1–60000) |
| `parse-pure-ip` | bool | `true` | Only sniff flows whose destination has no domain name — empty or a bare IP literal — unless the domain is in `force-domain` |
| `override-destination` | bool | `false` | Rewrite the destination itself with the sniffed domain, keeping rule matching and dialing consistent |
| `sniff` | block | — | Per-protocol port lists (**required** when `enable: true`) |
| `force-domain` | list | `[]` | Glob patterns that bypass the `parse-pure-ip` guard and opt a domain authority into routing by the sniffed name |
| `skip-domain` | list | `[]` | Glob patterns whose sniffed results are discarded |

### `sniff` block

```yaml
sniff:
  TLS:
    ports: [443, 8443, 8880]
  HTTP:
    ports: [80, 8080]
```

- **`TLS`** — extract SNI from the ClientHello on the listed ports.
- **`HTTP`** — extract the `Host` header from HTTP/1.x requests on the listed ports.
- Ports accept integers or string ranges (e.g. `"8000-8100"`).
- Enabling the sniffer with no TLS/HTTP ports configured is a hard error.

QUIC and other protocols are parsed but ignored (warning).

## How matching uses it

1. A connection arrives; meow-rs peeks up to `timeout` ms for the handshake/request.
2. If a domain is found and isn't in `skip-domain`, the sniffed name may be adopted —
   see the adoption priority below.
3. With `override-destination: true`, that domain also becomes the destination, so
   rule matching and dialing stay consistent; otherwise it's recorded alongside the
   original target for rule matching only.

## Which name wins

A sniffed name is adopted only when the flow has no routing name of its own — the
destination is empty or a bare IP literal. When the destination already carries an
explicit domain (a CONNECT target, an absolute-form URI, a SOCKS5 domain), that
authority wins and the sniff is discarded. This keeps rules and dialing consistent:
rules match on the sniffed name while the dial uses the destination, so adopting a
conflicting name would route by one host and dial the other — `GET http://evil.com/`
with `Host: good.example` would miss `DOMAIN,evil.com,REJECT` yet still dial
`evil.com`.

Two opt-ins beat that priority:

- `override-destination: true` rewrites the destination with the sniffed name —
  unconditional, and the setting most sniffer users want (it also gives outbound TLS
  adapters a real SNI instead of an IP literal).
- `force-domain` matching the destination adopts the sniffed name for rule matching
  anyway, while the dial keeps the authority — the CDN-front contract: route by the
  SNI/Host seen on the wire, dial the domain the client asked for.

## Deprecated `tproxy-sni`

The old top-level shorthand still works:

```yaml
tproxy-sni: true
```

is equivalent to:

```yaml
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443]
```

If both are present, the `sniffer` block wins and `tproxy-sni` is ignored.
