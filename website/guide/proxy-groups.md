# Proxy Groups

A proxy group bundles several proxies behind one name and a selection strategy. Groups
can themselves reference other groups, and rules target a group exactly like a single
proxy. Group names must be unique across groups, `proxies:` entries, and built-ins
(`DIRECT`, `REJECT`, `REJECT-DROP`, `COMPATIBLE`, `PASS`, `PASS-RULE`), and the
group-membership graph must be acyclic — both are hard config errors.

```yaml
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-01, jp-01, DIRECT]
```

## Common fields

Every group type accepts these:

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | — | **Required.** Referenced in rules |
| `type` | string | — | **Required.** Group type (below) |
| `proxies` | list | `[]` | Static member proxy/group names |
| `use` | list | `[]` | [Proxy-provider](./providers) names to pull members from |
| `filter` | regex | — | Include only members whose name matches |
| `exclude-filter` | regex | — | Exclude members whose name matches |
| `exclude-type` | string \| list | `[]` | Exclude member proxy types, e.g. `[ss, trojan]` |
| `include-all` | bool | `false` | Include all proxies from all providers |
| `include-all-proxies` | bool | `false` | Include all top-level `proxies:` entries, sorted by name; excludes proxy groups and built-ins |

`filter` / `exclude-filter` are most useful with providers — e.g. keep only nodes whose
name contains a region tag.

## `select` — manual selection

The user picks the active member (via the dashboard or `PUT /proxies/{name}`). The choice
is persisted across restarts. `url`, `interval`, `lazy`, `tolerance` and
`expected-status` are accepted for upstream-config compatibility but ignored (with a
warning): `select` runs no health-check task.

```yaml
- name: Proxy
  type: select
  proxies: [DIRECT, hk-01, jp-01]
  use: [airport]
```

## `url-test` — lowest latency

Periodically probes each member with an HTTP GET and auto-selects the fastest.

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `url` | string | — | Health-check URL, e.g. `https://www.gstatic.com/generate_204` |
| `interval` | u64 | — | Probe interval in seconds |
| `tolerance` | u16 | `150` | Only switch if the new node is faster by more than this (ms) |
| `lazy` | bool | `false` | Probe only when the group is in use — housekeeping traffic (provider/geodata downloads, DNS-via-proxy exchanges, probes chained through `dialer-proxy`) does not count |
| `expected-status` | string | — | Probe success expression, e.g. `204` |

```yaml
- name: Auto
  type: url-test
  proxies: [hk-01, jp-01, sg-01]
  url: https://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
```

## `fallback` — first alive

Tries members in order, using the first one that passes its health check. On failure it
moves to the next.

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `url` | string | — | Health-check URL |
| `interval` | u64 | — | Probe interval in seconds |
| `lazy` | bool | `false` | Probe only when in use — housekeeping traffic does not count |
| `expected-status` | string | — | Probe success expression, e.g. `204` |

```yaml
- name: Fallback
  type: fallback
  proxies: [primary, secondary, tertiary]
  url: https://www.gstatic.com/generate_204
  interval: 300
```

## `load-balance` — distribute

Spreads connections across members.

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `strategy` | string | `round-robin` | `round-robin` or `consistent-hashing` |
| `url` | string | `https://www.gstatic.com/generate_204` | Health-check URL |
| `interval` | u64 | — | Probe interval in seconds |
| `lazy` | bool | `false` | Probe only when in use — housekeeping traffic does not count |
| `expected-status` | string | — | Probe success expression, e.g. `204` |

`consistent-hashing` pins each *destination* to the same node (mihomo
`getKey`: an IP-literal destination is used verbatim, a domain is reduced to
its registrable eTLD+1 — so all of `example.com`'s hosts share one node).
An unknown strategy is a hard error.

```yaml
- name: Balance
  type: load-balance
  proxies: [n1, n2, n3]
  strategy: consistent-hashing
```

## `relay` — chain hops

Chains members in series: `A → B → C`. Requires **at least 2** proxies (fewer is a hard
error). `url`, `interval`, `lazy`, `tolerance` and `expected-status` are ignored (with a
warning): `relay` runs no health-check task. A relay is static-only — provider fields
(`use`, `include-all`, `include-all-providers`, `filter`, `exclude-filter`,
`exclude-type`) are ignored with a warning as well.

```yaml
- name: Relay
  type: relay
  proxies: [bridge, exit]
```

## Health checks

`url-test`, `fallback` and `load-balance` groups run a background health-check task;
`select` and `relay` do not. You can also trigger probes on demand through the REST API:

- `GET /proxies/{name}/delay` — probe one proxy.
- `GET /group/{name}/delay` — probe every member of a group.

See the [REST API reference](../reference/rest-api).
