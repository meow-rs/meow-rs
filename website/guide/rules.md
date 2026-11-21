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

A domain payload that can never match a normalized hostname is logged as a
warning (and fails the load under `strict: true`): an empty label (`a..b`),
a leading or trailing dot (`.x.com`, `x.com.`), or a `*`/`+` spelling on
`DOMAIN`/`DOMAIN-SUFFIX` — `DOMAIN,*.x.com` compares verbatim and can never
equal a host, so use `DOMAIN-WILDCARD` instead. On `DOMAIN-WILDCARD`, `*`
is the only glob — a `+` is a literal byte no host carries, so `+.x.com`
is dead here too; only dead literal labels are otherwise flagged.
`DOMAIN-KEYWORD` is flagged only on `..` — a substring needle like `foo.`
can still match `foo.bar`. `DOMAIN-REGEX` is not checked.

One residual to know: hosts are normalized before matching (trailing dots
are stripped), so a `DOMAIN-KEYWORD,foo.` needle no longer hits the bare
`foo` — only superstrings like `foo.bar` — and an anchored
`DOMAIN-REGEX,^foo\.$` pattern can never match. These load without a
warning; write the needle/pattern against the normalized name.

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
| `PROCESS-NAME-REGEX` | `PROCESS-NAME-REGEX,^svchost,DIRECT` | Process name matched by regex (search semantics) |
| `PROCESS-PATH-REGEX` | `PROCESS-PATH-REGEX,/usr/bin/\w+,Proxy` | Full process path matched by regex |
| `PROCESS-NAME-WILDCARD` | `PROCESS-NAME-WILDCARD,Cu?l*,DIRECT` | Process name matched by `*`/`?` glob |
| `PROCESS-PATH-WILDCARD` | `PROCESS-PATH-WILDCARD,/opt/*/tool,Proxy` | Full process path matched by `*`/`?` glob |
| `UID` | `UID,1000,Proxy` | Unix user ID (Linux only; never matches elsewhere) |

`PROCESS-PATH` extends upstream: a leading `/` (or `\`) does a directory-prefix match, `*`
does a glob, otherwise it falls back to a filename match.

The `-REGEX` types compile case-insensitively by default (an inline `(?-i)` re-enables
case-sensitivity) and match unanchored — `curl` matches `mycurl`; write `^…$` to pin.
They are comma-protected like `DOMAIN-REGEX`: everything between the type and the
last comma field is the pattern, so quantifiers like `{1,3}` and literal commas are
safe. The `-WILDCARD` types match the whole field against a glob where only `*` and
`?` are metacharacters (`?` consumes exactly one byte); separators, brackets and
backslashes stay literal. A flow with no process identity never matches any of the
process rules — not even `*` or `^$`.

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
| `SUB-RULE` | `SUB-RULE,my-block` | Evaluates a named block from `sub-rules:`; the matched inner rule supplies the target |

`SUB-RULE` blocks are declared at the top level:

```yaml
sub-rules:
  my-block:
    - DOMAIN-SUFFIX,internal.corp,Corporate
    - IP-CIDR,10.0.0.0/8,Corporate

rules:
  - SUB-RULE,my-block
  - MATCH,DIRECT
```

A plain `SUB-RULE` reference takes exactly one field — the block name. A trailing
field (`SUB-RULE,my-block,Proxy`) is rejected: it was silently ignored before,
which read like a fallback target that never existed.

The **conditional form** inserts a predicate in balanced parentheses before the
block name (mihomo's form), plus a MEOW-only optional fourth field:

```yaml
rules:
  # Mihomo form — enter my-block only when the condition holds:
  - SUB-RULE,(GEOIP,CN),my-block
  # MEOW extension — if the condition held but no inner rule matched,
  # route to Fallback instead of falling through:
  - SUB-RULE,(GEOIP,CN),my-block,Fallback
```

When the condition is false the block is skipped entirely — none of its rules
evaluate, and the scan moves to the next top-level rule. When it is true the
block evaluates in order; exhaustion falls through for the three-field form or
yields the fourth-field fallback. The fallback goes through normal target
checks — it is not a block name and does not participate in cycle detection.

A condition leaf is any rule type except `MATCH` and `SUB-RULE` — the same
exclusion mihomo applies inside logic rules — so `(IP-CIDR,10.0.0.0/8)`,
`(DST-PORT,443)`, `(PROCESS-NAME,curl)` or `(RULE-SET,my-provider)` are all
legal predicates. Flag fields keep their usual meaning (`GEOIP` takes
`no-resolve`/`src`, a process leaf's glob/regex payload matches like the
top-level rule of the same name). Leaves compose with mihomo's prefix
operators — `(AND,((A),(B)))`, `(OR,((A),(B)))`, `(NOT,((A)))` — or with MEOW's
infix `&`, `|` and `!` extension (`!` binds tightest, `&` before `|`,
parentheses override; upstream parses only the prefix forms), e.g.
`SUB-RULE,((DOMAIN-SUFFIX,example.com)|!(GEOIP,CN)),my-block`.

## Rematch routing

A `type: rematch` node is a **control outbound**: it carries no address and
never opens a socket. When a rule selects it, routing re-enters the rule scan
with the fields the node names applied to the flow:

```yaml
proxies:
  - name: inspect
    type: rematch
    target-rematch-name: stage1      # stamps the flow's rematch marker
    target-sub-rule: second-pass     # and/or switches the active rule list
```

- `target-rematch-name` — stamps `Metadata.rematchName`, the value
  `REMATCH-NAME` rules compare against.
- `target-sub-rule` — makes the named `sub-rules:` block the active list;
  `""` returns the scan to the top-level `rules:`.
- At least one field is required. Omitted/`null` leaves that field untouched;
  an explicit `""` **clears** it. Values are used verbatim — no trimming or
  case folding — and must be strings (quote numbers).
- A `target-sub-rule` naming an undeclared block warns at load and falls back
  to the top-level rules at match time.

| Type | Example | Matches |
| --- | --- | --- |
| `REMATCH-NAME` | `REMATCH-NAME,stage1,REJECT` | The flow's rematch marker equals an alternative |

The payload is a `/`-separated list of alternatives — `stage1/alternative`
matches either. Each token is trimmed and compared **exactly and
case-sensitively**: there is no wildcard, regex, substring or `|` alternation
(`*` and `|` stay literal). An empty alternative is rejected, and a flow whose
marker is unset matches nothing. `REMATCH-NAME` also works inside
`AND`/`OR`/`NOT` legs and `SUB-RULE` conditions.

```yaml
proxies:
  - name: inspect
    type: rematch
    target-rematch-name: stage1
    target-sub-rule: second-pass

rules:
  - DOMAIN-SUFFIX,example.test,inspect
  - MATCH,DIRECT

sub-rules:
  second-pass:
    - REMATCH-NAME,stage1/alternative,REJECT
    - MATCH,DIRECT
```

Here `example.test` selects `inspect`, the scan re-enters inside `second-pass`
with the marker stamped `stage1`, and the first block rule sends the flow to
`REJECT`; unrelated flows take the top-level `MATCH,DIRECT`.

Re-entry is iterative with two safety guards, both terminal: selecting a
rematch node already visited in this flow — or exceeding 32 transitions —
rejects the connection rather than sliding to a later rule. A group whose
*selected* member is a rematch node transitions the same way (mere membership
does nothing), and a rematch leaf can never be a `dialer-proxy` front — it has
no transport to carry.

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
