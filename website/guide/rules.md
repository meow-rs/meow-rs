# Rules

The `rules` list is meow-rs's routing table. In `rule` mode, every connection is matched
against the list **top to bottom, first match wins**, and dispatched to the named target
(a proxy, a group, or a built-in like `DIRECT` / `REJECT`).

## Syntax

```
TYPE,payload,target[,options]
```

- **TYPE** — the rule type keyword, e.g. `DOMAIN-SUFFIX`. Write it uppercase (upstream convention); `AND`/`OR`/`NOT`/`SUB-RULE` are also accepted case-insensitively, but leaf types and `MATCH`/`RULE-SET` are case-sensitive.
- **payload** — the value to match (a domain, CIDR, port set, …).
- **target** — where matching traffic goes.
- **options** — rule-specific flags, most commonly `no-resolve`.

```yaml
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
```

::: tip `no-resolve`
For IP-based rules, `no-resolve` skips DNS resolution of a hostname destination during
matching. Put `no-resolve` IP rules **before** any rule that would force a DNS lookup, so
you don't resolve names you intend to route by domain.
:::

::: tip `src`
A trailing `,src` option switches an IP rule to the **source** axis:
`IP-CIDR,10.0.0.0/8,DIRECT,src` is equivalent to `SRC-IP-CIDR`. It is
accepted on `IP-CIDR`/`IP-CIDR6`, `IP-SUFFIX`, `GEOIP`, `IP-ASN`, and
`RULE-SET` (upstream `isSrc`), and implies `no-resolve` since a source
match never needs the destination resolved. Flag names are
case-insensitive. On a `domain`-behavior rule provider `,src` has no
effect — the config still loads, but a warning is logged since the
provider can only match on the destination host.
:::

Always end the list with a catch-all `MATCH` rule so every connection has a destination.

## Domain rules

| Type | Example | Matches |
| --- | --- | --- |
| `DOMAIN` | `DOMAIN,google.com,Proxy` | Exact hostname |
| `DOMAIN-SUFFIX` | `DOMAIN-SUFFIX,google.com,Proxy` | The domain and all subdomains |
| `DOMAIN-KEYWORD` | `DOMAIN-KEYWORD,google,Proxy` | Any hostname containing the substring |
| `DOMAIN-REGEX` | `DOMAIN-REGEX,^ads?\.,Proxy` | Hostname matches a Rust regex |
| `DOMAIN-WILDCARD` | `DOMAIN-WILDCARD,*.example.com,Proxy` | Glob where `*` spans one DNS label |

## IP rules

All IP rules accept `no-resolve`. `IP-CIDR` and `IP-CIDR6` are interchangeable.

| Type | Example | Matches |
| --- | --- | --- |
| `IP-CIDR` / `IP-CIDR6` | `IP-CIDR,192.168.0.0/16,DIRECT,no-resolve` | Destination IP in range |
| `SRC-IP-CIDR` | `SRC-IP-CIDR,10.0.0.0/8,DIRECT` | Source (client) IP in range |
| `IP-SUFFIX` | `IP-SUFFIX,127.0.0.1/8,DIRECT` | Low-bit suffix match on the IP |
| `SRC-IP-SUFFIX` | `SRC-IP-SUFFIX,10.0.0.0/8,DIRECT` | Low-bit suffix match on the source IP |
| `IP-ASN` | `IP-ASN,13335,Proxy` | Destination IP's ASN (needs GeoLite2-ASN) |
| `SRC-IP-ASN` | `SRC-IP-ASN,13335,Proxy` | Source IP's ASN |

`IP-ASN` / `SRC-IP-ASN` require a configured `GeoLite2-ASN.mmdb`, or they hard-error at
load. See [Geodata](./geodata).

## Geolocation rules

| Type | Example | Matches |
| --- | --- | --- |
| `GEOIP` | `GEOIP,CN,DIRECT,no-resolve` | Destination IP's country |
| `SRC-GEOIP` | `SRC-GEOIP,US,Proxy` | Source IP's country |
| `GEOSITE` | `GEOSITE,cn,DIRECT` | Domain in a GeoSite category (e.g. `microsoft@cn`) |

`GEOIP`/`SRC-GEOIP` need a Country MMDB. `GEOSITE` tolerates a missing database (it simply
never matches), so configs that conditionally load GeoSite still parse cleanly.

## Port rules

Payloads accept a single port (`443`), a range (`8000-9000`), or a list
(`80,443,8080` / `80/443/8080`).

| Type | Example | Matches |
| --- | --- | --- |
| `DST-PORT` | `DST-PORT,443,Proxy` | Destination port |
| `SRC-PORT` | `SRC-PORT,1024-65535,Proxy` | Source port |
| `IN-PORT` | `IN-PORT,7891,DIRECT` | The inbound listener port that accepted the connection |

## Process & user rules

| Type | Example | Matches |
| --- | --- | --- |
| `PROCESS-NAME` | `PROCESS-NAME,curl,DIRECT` | Initiating process executable name |
| `PROCESS-PATH` | `PROCESS-PATH,/usr/bin/node,Proxy` | Process path — exact, `/prefix` match, or `*` glob |
| `UID` | `UID,1000,Proxy` | Unix user ID (Linux only; never matches elsewhere) |

`PROCESS-PATH` extends upstream: a leading `/` (or `\`) does a directory-prefix match, `*`
does a glob, otherwise it falls back to a filename match.

## Inbound & network rules

| Type | Example | Matches |
| --- | --- | --- |
| `NETWORK` | `NETWORK,udp,DIRECT` | `TCP` or `UDP` |
| `DSCP` | `DSCP,46,Proxy` | IP DSCP field 0–63 (TProxy only) |
| `IN-NAME` | `IN-NAME,corp,DIRECT` | Name of the inbound [listener](./listeners) |
| `IN-TYPE` | `IN-TYPE,SOCKS5,Proxy` | Inbound type: `HTTP`/`HTTPS`/`SOCKS5`/`TPROXY`/`INNER` |
| `IN-USER` | `IN-USER,alice,Proxy` | Authenticated inbound username |

`IN-TYPE,HTTP` matches both plaintext HTTP and HTTPS; use `HTTPS` for TLS only. `DSCP`
only ever matches on the TProxy listener.

## Rule sets & sub-rules

| Type | Example | Behavior |
| --- | --- | --- |
| `RULE-SET` | `RULE-SET,gfw,Proxy` | Delegates to a named [rule provider](./providers); `,src` matches the client IP (ipcidr/classical providers) |
| `SUB-RULE` | `SUB-RULE,my-block,Proxy` | Evaluates a named block from `sub-rules:` |

`SUB-RULE` blocks are declared at the top level:

```yaml
sub-rules:
  my-block:
    - DOMAIN-SUFFIX,internal.corp,Corporate
    - IP-CIDR,10.0.0.0/8,Corporate

rules:
  - SUB-RULE,my-block,Proxy
  - MATCH,DIRECT
```

## Logic rules

`AND`, `OR`, and `NOT` compose other rules. Inner rules are wrapped in balanced
parentheses; the **outer** rule's target is what gets applied (inner targets are
placeholders). They nest freely.

```yaml
rules:
  # both conditions must hold
  - AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),Proxy
  # either condition
  - OR,((DOMAIN-SUFFIX,a.com),(DOMAIN-SUFFIX,b.com)),Proxy
  # exactly one inner rule, inverted
  - NOT,((DOMAIN-SUFFIX,corp.internal)),DIRECT
```

`NOT` takes **exactly one** inner rule; more is a hard error.

## The final rule

| Type | Example | Behavior |
| --- | --- | --- |
| `MATCH` | `MATCH,Proxy` | Always matches — the default/catch-all |

If the target is omitted, `MATCH` defaults to `DIRECT`. Place it last.

## Editing rules at runtime

Rules can be inspected and changed live through the [REST API](../reference/rest-api):
`GET /rules`, `POST /rules` (replace all), `PUT /rules` (update by index),
`DELETE /rules/{index}`, and `POST /rules/reorder`.
