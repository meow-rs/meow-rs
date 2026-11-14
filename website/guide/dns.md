# DNS

meow-rs ships its own caching DNS resolver and an optional DNS server. It handles
upstream selection, per-domain policy routing, FakeIP, and the IP→domain reverse table
that powers domain-based rules for transparent flows.

```yaml
dns:
  enable: true
  listen: 127.0.0.1:1053
  nameserver: [8.8.8.8, 1.1.1.1]
  fallback: [8.8.4.4, 1.0.0.1]
```

When the `dns` block is absent or `enable: false`, a minimal resolver (Google DNS) is
still used internally so rules and proxies can resolve names.

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enable` | bool | `false` | Start the built-in DNS server |
| `listen` | string | — | DNS server bind address, e.g. `127.0.0.1:53` |
| `ipv6` | bool | — | Allow AAAA answers |
| `enhanced-mode` | string | `normal` | `normal` · `fake-ip` · `redir-host` |
| `nameserver` | list | `[]` | Primary upstreams (defaults to `8.8.8.8` if empty) |
| `fallback` | list | `[]` | Fallback upstreams (gated by `fallback-filter`) |
| `default-nameserver` | list | `[]` | Bootstrap servers to resolve DoT/DoH hostnames |
| `proxy-server-nameserver` | list | `[]` | Dedicated upstreams for proxy server hostnames; when unset they use `nameserver` |
| `nameserver-policy` | map | — | Per-domain upstream routing |
| `response-rules` | ordered list | `[]` | Query-type-specific local answers (meow extension) |
| `nameserver-policy-exclusive` | bool | `false` | Confine policy-matched queries to that entry's upstreams |
| `fallback-filter` | block | — | When to use `fallback` |
| `fake-ip-range` | string | `198.18.0.1/16` | Fake-IP CIDR pool |
| `fake-ip-filter` | list | `[]` | Domains excluded/included from FakeIP |
| `fake-ip-filter-mode` | string | `blacklist` | `blacklist` or `whitelist` |
| `prefer-h3` | bool | `false` | Let every `https://` upstream prefer HTTP/3, falling back to HTTP/1.1 |
| `store-fake-ip` | bool | `false` | Persist the fake-IP map across restarts |
| `use-hosts` | bool | `true` | Honor the top-level `hosts:` map |
| `use-system-hosts` | bool | `true` | Merge the OS hosts file (`/etc/hosts`, or `%SystemRoot%\System32\drivers\etc\hosts` on Windows) |

## Ordered response rules

`dns.response-rules` is an opt-in meow extension for local DNS answers.
Use `nameserver-policy` to select upstreams and `response-rules` to select
the answer sent to a DNS client. The first matching rule wins, including
`forward`. A query with no matching rule uses the ordinary pipeline.

```yaml
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
  fake-ip-filter: [real.example.test]
  response-rules:
    - match: '+.example.test'
      types: [HTTPS, SVCB]
      action: nodata
    - match: real.example.test
      action: forward
    - match: blocked.example.test
      action: refused
    - match: static.example.test
      action: address
      address: 192.0.2.7
      ttl: 42
    - match: '+.example.test'
      action: fake-ip
```

`match` accepts the existing nameserver-policy domain patterns (exact,
`+.`, `*.`, `.`), `geosite:` and `rule-set:` conditions. `'*'` matches
every name. Matching uses loaded state synchronously. Rule providers
use `domain` or `classical` behavior and inspect only domain conditions.
Provider names are case-sensitive. Candidate configuration changes bind
the candidate's provider objects; background refreshes are visible through
those same objects.

`types` is optional. Omission matches all query types; a supplied list must
be nonempty. It accepts DNS type names such as `A`, `AAAA`, `HTTPS`, `SVCB`
and `TXT`, or `TYPE<number>` for an arbitrary 16-bit type. Names are
case-insensitive. `ANY` selects the literal ANY question type.

| Action | Wire result |
| --- | --- |
| `nodata` | NOERROR with zero answers |
| `refused` | REFUSED with zero answers |
| `address` | One A or AAAA record of the configured family; every other query type gets NODATA. Requires `address`; `ttl` defaults to 60 seconds and may be zero. |
| `fake-ip` | Allocate from the queried family's existing pool, overriding `fake-ip-filter`. An unavailable/disabled family gets NODATA. Generic types resume ordinary forwarding. Requires `enhanced-mode: fake-ip`. |
| `forward` | Stop the rule scan and resume the ordinary pipeline, including its fake-IP filter, cache and upstream selection |

Explicit hosts entries, including aliases, take priority for address
questions. Response rules run next, ahead of IPv6 suppression, fake-IP,
cache and upstream lookup. Packet validation precedes rule synthesis.
Replies echo RD/CD and, for EDNS requests, DO with a version-0 OPT advertising
1232 bytes. Duplicate OPT records get FORMERR and unsupported EDNS versions
get BADVERS. Synthesized answers contain no relayed ECH/ALPN records;
forwarded HTTPS/SVCB answers retain ADR-0013 hint filtering, including names
forced into fake-IP by a rule.

These rules apply to the UDP DNS listener and TUN DNS-hijack wire path.
Outbound hostname resolution and `GET /dns/query` use the resolver pipeline
directly. This keeps proxy-server bootstrap free of synthesized fake-IP
addresses and makes the API endpoint an upstream diagnostic.

Invalid actions, types, action fields, missing providers and unavailable
geosite databases fail configuration loading. A rejected reload retains the
live resolver and its rules. Reordering rules triggers a resolver rebuild.

## Upstream formats

Each `nameserver` / `fallback` entry is a server URL:

| Form | Protocol | Default port |
| --- | --- | --- |
| `8.8.8.8` or `udp://8.8.8.8:53` | DNS over UDP | 53 |
| `tcp://8.8.8.8:53` | DNS over TCP | 53 |
| `tls://1.1.1.1:853#cloudflare-dns.com` | DoT (SNI after `#`) | 853 |
| `https://1.1.1.1/dns-query#cloudflare-dns.com` | DoH (HTTP/2 or HTTP/1.1, as the server picks) | 443 |
| `https://dns.google/dns-query?h3=true` | DoH over HTTP/3 only | 443 |
| `quic://dns.adguard.com#dns.adguard.com` | DoQ (RFC 9250) | 853 |
| `rcode://REFUSED` | Synthetic error (testing) | — |

An encrypted entry takes `?proxy=NAME` to tunnel the exchange through a proxy, and
`?h3=` on `https://` entries. `#` is the SNI override, as everywhere in meow-rs.

## DoQ and DoH over HTTP/3

Both ride `quiche` on the same vendored BoringSSL as the rest of the process, so there is
no second crypto library and the certificate decision is the shared one (Mozilla roots,
`additional-roots`-free in production).

```yaml
dns:
  enable: true
  # Preferred: one flag for every HTTPS upstream.
  prefer-h3: true
  nameserver:
    - quic://dns.adguard.com            # DoQ, port 853
    - https://1.1.1.1/dns-query         # h3 first (prefer-h3), HTTP/1.1 fallback
    - https://dns.google/dns-query?h3=true   # h3 only, no fallback
    - https://cloudflare-dns.com/dns-query?h3=false  # opts out of prefer-h3
```

- **DoQ** follows RFC 9250: one bidirectional stream per query, the message
  length-prefixed like DNS over TCP, and the transaction ID set to `0` on the wire. One
  QUIC connection serves every query and is re-dialed transparently after an idle
  timeout, a peer close or `POST /cache/dns/flush`-adjacent connection resets.
- **DoH3** is RFC 8484 over HTTP/3: one `POST` per query, `application/dns-message` both
  ways, `:status 200` required.
- **`prefer-h3` vs `?h3=true`.** The global flag means *prefer*: HTTP/3 is tried first
  and the query falls back to HTTP/2 / HTTP/1.1 DoH when the QUIC exchange fails, with the failed
  handshake parked for ten minutes so a server without HTTP/3 does not cost a handshake
  timeout per query. `?h3=true` is mihomo's per-entry spelling and means *HTTP/3 only* —
  no fallback. `?h3=prefer` opts a single entry into the fallback behaviour without the
  global flag, and `?h3=false` turns the entry back off.
- **`?proxy=`.** A proxied DoQ/DoH3 upstream dials the adapter's UDP association; an
  adapter that cannot carry UDP fails the exchange instead of leaking around the chain.
  The `server` must be an **IP literal** in that case: a proxied hostname is resolved by
  the adapter, so the QUIC peer address is unknown until after the handshake — the config
  is refused at load rather than hanging every query.
- **Builds.** The transports live behind the `dns-quic` Cargo feature (in the `full`
  bundle, out of `minimal` for binary size). A config that asks for `quic://`, `?h3=` or
  `prefer-h3` on a build without it is a load error naming the feature — never a silent
  downgrade to plain DoH.

## Enhanced modes

- **`normal`** — standard resolution; answers are cached, and a reverse IP→domain table
  is still maintained for rule matching.
- **`redir-host`** — *DNS snooping.* Answers resolve to real IPs, and the resolver keeps
  an IP→hostname map so rules can match domains even when the proxy client connects by
  IP. Good for transparent setups without FakeIP.
- **`fake-ip`** — every A/AAAA query is answered with an allocated IP from
  `fake-ip-range`. The real address is resolved lazily after the rule decision, so domain
  rules work without leaking the real lookup. The fake IP maps back to the domain via the
  reverse table.

## Nameserver policy

Route specific domains to specific upstreams. Keys are exact names, `+.`-wildcards,
`geosite:` category selectors, or `rule-set:` provider selectors; values are a single
upstream or a list.

```yaml
dns:
  nameserver-policy:
    "geosite:cn": [223.5.5.5, 119.29.29.29]
    "rule-set:cn-domain": [223.5.5.5]   # behavior: domain (or classical)
    "+.local": 192.168.1.1
    "internal.corp": 10.0.0.1
```

`rule-set:` references a rule-provider by name. The provider behavior must be `domain`
(or `classical`, in which case only its domain rules are matched); an `ipcidr` provider or
a missing provider is a config error. The matcher reads the provider live, so background
refreshes apply automatically.

`nameserver-policy-exclusive: true` makes a match terminal: the entry's upstreams
answer or the query fails — no `fallback-filter` gates (including the `ipcidr`/GeoIP
answer check) and no `nameserver`/`fallback:` escalation, the same ordering mihomo
gives a policy hit. It also applies to `direct-nameserver` lookups when
`direct-nameserver-follow-policy` is on. The default `false` keeps the tiered
behaviour: a policy negative falls through to `nameserver`, and a policy answer the
fallback filter rejects goes to `fallback:`.

## Fallback filter

Controls when an answer from `nameserver` is distrusted and `fallback` is consulted
instead — the classic anti-pollution pattern.

```yaml
dns:
  fallback-filter:
    geoip: true
    geoip-code: CN          # if the primary answer is NOT in CN, use fallback
    ipcidr:
      - 240.0.0.0/4
    domain:
      - "+.google.com"
```

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `geoip` | bool | `false` | Use GeoIP to judge the primary answer |
| `geoip-code` | string | `CN` | Country considered "trusted" |
| `ipcidr` | list | `[]` | Answer IPs that trigger fallback |
| `domain` | list | `[]` | Domains always sent to fallback |

## FakeIP details

- Fake IPs are allocated from `fake-ip-range` (default `198.18.0.0/16`) and recycled LRU.
- `fake-ip-filter` + `fake-ip-filter-mode` decide which domains skip FakeIP (e.g. keep
  LAN names on real DNS). `blacklist` excludes the listed patterns; `whitelist` means
  *only* the listed patterns get fake IPs.
- `store-fake-ip: true` persists allocations (`fakeip-v4.json` / `fakeip-v6.json`) so the
  same domain keeps its fake IP across restarts.
- Flush at runtime with `POST /cache/fakeip/flush`.

## Proxy server hostnames

When `enable: true`, a proxy node's own `server:` hostname is resolved by this resolver
— not by the operating system. So `nameserver`, `nameserver-policy`, `fallback` and the
top-level `hosts:` map all apply to the proxy upstream itself, exactly as they do to
destination domains:

```yaml
hosts:
  hk.example.com: 203.0.113.9   # pins the node, no lookup at all

proxies:
  - { name: HK, type: trojan, server: hk.example.com, port: 443, password: … }
```

FakeIP never applies here: proxy dials always take the real address, whatever
`enhanced-mode` is set to.

With `enable: false` the resolver is an internal stub, so proxy hostnames keep going to
the OS resolver — set `enable: true` if you want the config's DNS to own them. The
Android and iOS builds are the exception: there the OS resolver's sockets would route
back through the VPN tunnel and deadlock, so node hostnames always go through the
built-in resolver, `enable` or not.

### Dedicated upstreams for nodes

`proxy-server-nameserver` gives node hostnames their own upstreams, separate from the
ones serving ordinary traffic. The usual reason is bootstrapping: the main `nameserver`
is somewhere the proxy has to reach first, so the nodes themselves need a resolver that
is reachable without a working tunnel.

```yaml
dns:
  enable: true
  nameserver: ["https://1.1.1.1/dns-query"]   # for destination domains
  proxy-server-nameserver: [223.5.5.5]        # for the nodes' own server:
```

It is a self-contained resolver, so a few things differ from the main one:

- **No fallback to `nameserver`.** Once configured it is authoritative for node
  hostnames; if it cannot answer, the dial fails rather than retrying elsewhere.
- **`nameserver-policy`, `fallback` and `fallback-filter` do not apply** — only the
  listed upstreams are consulted.
- **`hosts:` still wins**, so a pinned node never reaches these upstreams at all.
- **Always `normal` mode**, so a node can never be handed a fake IP.
- **`default-nameserver` still bootstraps it**, so a DoT/DoH entry here needs a plain
  IP-literal bootstrap server just like one in `nameserver`.
- **Ignored when `enable: false`**, along with the rest of the `dns` block.

::: tip `#PROXY` nameservers
A nameserver tagged `#PROXY` has to dial that proxy to answer a query. If the query *is*
for that proxy's own server hostname, meow-rs would be waiting on itself, so this one hop
falls back to the `hosts:` map and the DNS cache, then to the OS resolver. Pinning such
nodes in `hosts:` (or configuring them by IP) keeps them off the OS resolver entirely.

Tagging a `proxy-server-nameserver` entry is the sharpest form of this: resolving node
hostnames is the job you just gave it, so `proxy-server-nameserver: [223.5.5.5#HK]` can
only work when `HK` itself needs no lookup — an IP-literal `server:`, or one pinned in
`hosts:`. meow-rs warns at startup when the tagged node is reached by hostname (or is a
group, whose member is only picked at dial time).
:::

## Caching

- **Forward cache** (name → IP) honors response TTL (min 10s) in a sharded LRU.
- **Reverse cache** (IP → name) uses a longer floor (min 600s) so short-TTL CDN records
  don't lose their origin domain before the connection is set up.
- Both use 16 lock shards to stay fast under load.
- Flush at runtime with `POST /cache/dns/flush`.

## Querying via the API

`GET /dns/query?name=example.com` (or `POST /dns/query`) resolves a name through the
configured resolver and returns the answer set — handy for debugging policy and fallback.
