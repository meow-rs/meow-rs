# Providers & Subscriptions

Providers let proxies and rules live **outside** your config — fetched from a URL or a
file, cached to disk, and optionally refreshed in the background. This is how you consume
airport subscriptions and shared rule sets.

## Proxy providers

`proxy-providers` is a map of named sources. A [proxy group](./proxy-groups) pulls members
from one via `use:`.

```yaml
proxy-providers:
  airport:
    type: http
    url: https://example.com/proxies.yaml
    path: ./providers/airport.yaml
    interval: 86400
    filter: "^(HK|JP)"
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300

proxy-groups:
  - name: Proxy
    type: select
    use: [airport]
```

### Common fields

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `type` | string | — | **Required.** `http` or `file` |
| `filter` | regex | — | Keep only proxies whose name matches |
| `exclude-filter` | regex | — | Drop proxies whose name matches |
| `exclude-type` | string \| list | `[]` | Drop proxy types, e.g. `[ss]` |
| `health-check` | block | — | Probe defaults for the manual `GET /providers/proxies/{name}/healthcheck` endpoint — **not periodically scheduled**; members are otherwise probed by a `use:`ing group's own health check |
| `header` | map | `{}` | Extra HTTP request headers (`http` only) |
| `dialer-proxy` | string | — | Chain every node through the named `proxies:`/`proxy-groups:` entry. Overrides node-level `dialer-proxy` fields (mihomo writes it into each node unconditionally) |
| `override` | map | — | Provider-level node defaults (mihomo `OverrideSchema`). Only `dialer-proxy` is honoured — it chains every node **unconditionally**, outranking both provider-level and node-level values; an empty string clears the chain (the node dials direct), and a non-string value rejects the provider. Other keys log a warning |
| `proxy` | string | — | Route this provider's `http` fetches through the named top-level `proxies:`/`proxy-groups:` entry, resolved against the live route map on every fetch. Absent, empty, or `DIRECT` fetches direct; an unknown or whitespace-only name fails the fetch — never a silent direct fallback (issue #625). A named value on a `file` provider warns: there is no fetch to chain |
| `allow-external-plugin` | bool | `false` | Permit `ss` nodes to launch external SIP003 plugin executables. **Security-sensitive opt-in**: provider content is remote-controlled and the plugin name reaches `Command::new`, so off means such nodes are rejected. Built-in plugins (`obfs`, `simple-obfs`, `v2ray-plugin`, `gost-plugin`, `shadow-tls`, `restls`, `jls`, `kcptun`, `ech-tls-tunnel` — all in the default feature set) are always allowed; a non-default build without one treats its name as external. meow-rs extension; absent in mihomo |

Provider nodes may also carry a per-node `dialer-proxy` field in the payload itself,
and it is re-applied on every refresh. The target must be a top-level
`proxies:`/`proxy-groups:` entry — sibling provider node names are not valid
targets (same as mihomo). A chain that loops back through dynamic group
membership (a node whose `dialer-proxy` names a group that can select the
node again) cannot be seen by the load-time cycle check — it degrades to a
named dial error at 16 hops instead.

### `type: http`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `url` | string | — | **Required.** Source URL |
| `path` | string | `provider_{name}.yaml` | Local cache (absolute or relative to config dir) |
| `interval` | u64 | `0` | Refresh period in seconds; `0` disables the timer — refresh manually with `PUT /providers/proxies/{name}` |

The cached file is the offline fallback: startup always fetches first and
writes the cache; the file is read only when that fetch fails.

### `type: file`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `path` | string | — | **Required.** Local YAML file of proxies |
| `interval` | u64 | `0` | Refresh period in seconds — the file is re-read on each tick; `0` disables the timer |

### Health check

| Field | Type | Default |
| --- | --- | --- |
| `enable` | bool | `true` |
| `url` | string | `https://www.gstatic.com/generate_204` |
| `interval` | u64 | `300` |
| `timeout` | u64 (ms) | `5000` |
| `lazy` | bool | `false` |

These fields configure probes for the **manual** healthcheck endpoint and are
stored on the provider — unlike the provider-level `interval` above, the
health-check `interval`/`lazy` are not periodically scheduled.

## Rule providers

`rule-providers` supplies external rule sets, referenced from `rules` via
`RULE-SET,<name>,<target>`.

```yaml
rule-providers:
  gfw:
    type: http
    url: https://cdn.example.com/gfw.yaml
    path: ./rules/gfw.yaml
    behavior: domain
    format: yaml
    interval: 604800

rules:
  - RULE-SET,gfw,Proxy
  - MATCH,DIRECT
```

### Common fields

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `type` | string | — | **Required.** `http` · `file` · `inline` |
| `behavior` | string | — | **Required.** `domain` · `ipcidr` · `classical` |
| `format` | string | auto | `yaml` · `text` · `mrs` (auto-detected for http/file) |
| `interval` | u64 | `0` | Refresh seconds (ignored with a warning for `file`; rejected for `inline` — the provider fails to load, fatal under `strict: true`) |

`behavior` describes the payload: `domain` (domain list), `ipcidr` (CIDR list), or
`classical` (full `TYPE,payload` rule lines). `mrs` is the compiled binary format.

### `type: http` / `file`

- `http` — needs `url`; caches to `path` (default `rule-providers/{name}.yaml`).
- `file` — needs `path`; loaded from disk, no scheduled refresh (manual
  `PUT /providers/rules/{name}` re-reads the file).

### `type: inline`

Embed the rules directly:

```yaml
rule-providers:
  internal:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,internal.corp,Corporate
      - IP-CIDR,192.168.0.0/16,Corporate
```

`interval > 0` on an inline provider is rejected (nothing to refresh) — the
provider fails to load with a warning, and `RULE-SET` entries referencing it
warn-and-skip; under `strict: true` it is a hard config error.

**Proxy providers** with a non-zero `interval` refresh on a background
timer — `http` refetches the URL (updating the `path:` cache), `file`
re-reads its file — and HTTP **rule providers** do the same; `inline`
providers never refresh. A refresh supervisor reconciles the task set on
every config commit: a provider *added* later via `PUT /configs` or a
subscription refresh gains a task, a removed one loses it, and a changed
`interval` respawns it — while an untouched provider keeps its existing
task (and countdown). Manual refresh (`PUT /providers/proxies/{name}`)
works regardless of `interval`, and a failed refresh keeps the last-good
node list.

## Subscriptions

`subscriptions:` is the blunt instrument next to providers. `proxy-providers`
entries feed *nodes* into a named pool that groups pull from via `use:` —
local `proxies:` and `rules:` stay yours. A subscription instead **replaces the
whole `proxies:` / `proxy-groups:` / `rules:` sections** with the remote
document's contents, and the result is **written back to the config file**
on every successful refresh.

```yaml
subscriptions:
  - name: airport
    url: https://example.com/clash.yaml
    interval: 86400
```

See [Configuration — Subscriptions](./configuration#subscriptions) for the
full semantics (replace-not-merge, write-back, `-t` behaviour).

Subscriptions are also managed at runtime through the
[REST API](../reference/rest-api):

- `GET /api/subscriptions` — list, with the applied proxy/group/rule counts
  and last-updated times.
- `POST /api/subscriptions` — add `{ name, url, interval?, proxy? }` and apply immediately.
- `POST /api/subscriptions/{name}/refresh` — re-fetch.
- `DELETE /api/subscriptions/{name}` — remove the entry **and empty all three
  sections** — previously-replaced local content is not restored. Note the
  delete itself saves, so `.bak` afterwards holds the *subscription-applied*
  file; the original local sections survive on disk only if no earlier
  write-back already rotated them out.
