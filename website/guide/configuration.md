# Configuration Overview

meow-rs is driven by a single YAML file (default `config.yaml`, overridable with `-f`).
The dialect is Clash / mihomo compatible. This page documents every **top-level** key;
nested blocks (proxies, DNS, rules, …) each have a dedicated page linked below.

::: tip Validate before you run
`meow -f config.yaml -t` parses and validates the whole file without starting the proxy.
Use it as a pre-flight check.
:::

## Top-level keys

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `port` | u16 | — | HTTP proxy listen port (shorthand) |
| `socks-port` | u16 | — | SOCKS5 proxy listen port (shorthand) |
| `mixed-port` | u16 | — | Mixed HTTP + SOCKS5 listen port (shorthand) |
| `tproxy-port` | u16 | — | Transparent proxy listen port (binds `127.0.0.1`) |
| `bind-address` | string | `127.0.0.1` | Default bind address for listeners |
| `allow-lan` | bool | `false` | Accept connections from non-loopback addresses |
| `mode` | string | `rule` | Tunnel mode: `rule`, `global`, or `direct` |
| `log-level` | string | `info` | `trace` · `debug` · `info` · `warn` · `error` · `off` |
| `ipv6` | bool | `false` | Enable IPv6 (AAAA) resolution |
| `strict` | bool | `false` | Fail on unparseable entries instead of warn-and-skip |
| `external-controller` | string | — | REST API listen address, e.g. `127.0.0.1:9090` |
| `secret` | string | — | API bearer-token secret (empty = no auth) |
| `external-ui` | string | — | Directory of static dashboard files served at `/ui` |
| `external-ui-name` | string | — | Sub-directory within `external-ui` holding the files |
| `external-ui-url` | string | — | URL the UI archive can be fetched from (recorded only) |
| `tproxy-sni` | bool | `true` | SNI sniffing on the TProxy listener (deprecated — use `sniffer`) |
| `routing-mark` | u32 | — | Linux `SO_MARK` for transparent-proxy loop avoidance |
| `max-connections` | usize | `256` | Global cap on concurrent inbound connections (`0` = unlimited); inherited by the TUN listener |
| `authentication` | list | `[]` | Inbound `user:pass` credentials for HTTP/SOCKS5 |
| `skip-auth-prefixes` | list | `[]` | CIDRs exempt from inbound auth |
| `hosts` | map | — | Static host → IP(s) mappings |
| `proxies` | list | — | Proxy definitions — [Proxies](./proxies) |
| `proxy-groups` | list | — | Proxy groups — [Proxy Groups](./proxy-groups) |
| `proxy-providers` | map | — | Dynamic proxy subscriptions — [Providers](./providers) |
| `rules` | list | — | Routing rules — [Rules](./rules) |
| `rule-providers` | map | — | External rule sets — [Providers](./providers) |
| `sub-rules` | map | — | Named rule blocks referenced by `SUB-RULE` |
| `subscriptions` | list | — | Remote Clash configs applied wholesale — [Subscriptions](#subscriptions) |
| `dns` | block | — | DNS resolver/server config — [DNS](./dns) |
| `sniffer` | block | — | Domain sniffing config — [Sniffer](./sniffer) |
| `listeners` | list | — | Explicit named listeners — [Listeners](./listeners) |
| `tun` | block | off | TUN inbound (Wintun on Windows) — [Transparent Proxy](./transparent-proxy) |
| `geodata` | block | — | GeoIP / ASN / GeoSite databases — [Geodata](./geodata) |

## Tunnel modes

`mode` selects how connections are routed:

- **`rule`** *(default)* — match each connection against the `rules` list.
- **`global`** — send everything through the `GLOBAL` selector, ignoring rules.
- **`direct`** — connect everything directly, ignoring proxies and rules.

The mode can be changed at runtime with `PATCH /configs` (see the
[REST API](../reference/rest-api)).

## Ports & binding

The four shorthand port keys (`mixed-port`, `port`, `socks-port`, `tproxy-port`) are the
quickest way to open listeners. `mixed-port` is usually all you need — it auto-detects
HTTP vs SOCKS5 from the first byte.

- Listeners bind to `bind-address` (default `127.0.0.1`). Set `allow-lan: true` and a
  non-loopback `bind-address` (e.g. `0.0.0.0`) to accept LAN clients.
- `tproxy-port` always binds `127.0.0.1`. For a LAN **gateway** you must declare the
  TProxy listener explicitly with a non-loopback `listen`. See
  [Transparent Proxy](./transparent-proxy).

For multiple or finer-grained listeners, use the [`listeners`](./listeners) array.

## Static hosts

`hosts` maps names to one or more IPs, consulted before upstream DNS (when
`dns.use-hosts` is on). Values may be a single string or a list, and keys support a
`+.` wildcard prefix:

```yaml
hosts:
  router.local: 192.168.1.1
  example.com: [10.0.0.1, 10.0.0.2]
  "+.internal.corp": 10.0.0.254
```

## Subscriptions

`subscriptions` declares named remote Clash-format configs to pull on a
schedule:

```yaml
subscriptions:
  - name: airport
    url: https://example.com/clash.yaml
    interval: 86400 # seconds; omit to fetch once at startup
```

Each entry takes `name`, `url`, `interval` (seconds, optional), `proxy`
(optional — a top-level proxy or group name the fetch is routed through;
absent, empty, or `DIRECT` fetches direct, and an unknown name fails the
fetch rather than leaking a direct request), and `last-updated` (a unix
timestamp the daemon writes back itself — not meant to be set by hand). The semantics differ sharply from `proxy-providers`:

- **Wholesale replace, not merge.** A refresh replaces the entire
  `proxies:`, `proxy-groups:`, and `rules:` sections with the fetched
  document's — local entries in those sections are overwritten. Everything
  else (`dns:`, `mode:`, listeners, `proxy-providers:`…) is untouched —
  and `use:`/`include-all` groups keep resolving against the declared
  `proxy-providers:` on scheduled refreshes too.
- **The config file is rewritten.** After a successful fetch and rebuild
  the daemon saves the resulting config — fetched sections plus the
  `last-updated` stamp — back to disk, so subscription data survives
  restarts. The save re-serialises the whole file: hand-written comments,
  formatting, and keys meow-rs does not model are lost (the previous file
  is kept once as `<config>.bak`). The save writes the daemon's
  **in-memory** config, so it also persists runtime mutations made through
  the API (e.g. `PATCH /configs`) — and conversely, hand-edits made to the
  file while the daemon runs are clobbered by the next save. If the file
  is not writable the refresh still applies at runtime but persists
  nothing; if the committed `dns:` section fails to rebuild, the refresh
  is not committed at all — the previous routing stays live and nothing
  is saved (though `last-updated` is still stamped in memory, so the
  failed document is not retried until `interval`).
- **Refetch cadence.** A background task polls every 60 s: an entry is
  fetched when it has no `last-updated` (first run) or when `interval`
  seconds have elapsed. An entry without `interval` fetches once at
  startup and — once `last-updated` is stamped — never again. Note that
  an explicit `interval: 0` behaves differently than on providers: it
  refetches every poll (60 s), not "never". Fetches go over a direct
  connection unless the entry sets `proxy:` to a top-level proxy or group
  name.
- **One subscription at a time.** Every entry wholesale-replaces the
  same three sections, so multiple subscriptions perpetually clobber
  each other — last refresh wins. Declaring several is almost never
  what you want.
- **Only three sections are taken from the remote document.** A remote
  `dns:`, `proxy-providers:`, `sub-rules:`, listener or `mode:` setting
  is ignored — only `proxies`, `proxy-groups`, and `rules` are applied.
  A document missing `proxy-groups:`/`rules:` *empties* those sections;
  missing `proxies:` is a fetch error instead.
- **`-t` does not fetch subscriptions.** Config-test mode validates the
  file exactly as written — including whatever a previous refresh wrote
  back — and exits before the refresh loop starts. (It is not fully
  network-free: `load_config` still fetches `proxy-providers:`,
  prefetches `rule-providers:` payloads, may download geodata, and
  performs ECH pre-resolution DNS lookups.)
- **Safety.** `ss` nodes carrying external SIP003 `plugin:` values are
  dropped at parse time: remote content must not select a local
  executable, and unlike `proxy-providers` there is no
  `allow-external-plugin` opt-in for subscriptions. Failure handling
  splits on *what* failed, not where: a **transport** failure (connect
  error, non-2xx response) leaves `last-updated` unset, so the fetch is
  retried on the next poll. Everything else — a **payload defect**
  (non-UTF-8 body, YAML that does not parse, a missing `proxies:`
  section, non-sequence sections, and under `strict: true` any shape
  defect such as a non-mapping `proxies:` entry or a malformed
  `proxy-groups:`/`rules:` item), a fetched document that **fails to
  rebuild**, a strict-mode **ECH pre-resolution** failure, and a `dns:`
  reconcile failure — stamps `last-updated` instead, so the entry is
  not retried until `interval` has elapsed (and, for an entry without
  `interval`, never). For rebuild-class failures the previous routing
  stays live throughout.

Subscriptions can also be managed at runtime via the
[REST API](../reference/rest-api) (`GET`/`POST` `/api/subscriptions`,
`DELETE /api/subscriptions/{name}`,
`POST /api/subscriptions/{name}/refresh`); those endpoints follow the same
replace-and-write-back semantics.

## A complete example

```yaml
mixed-port: 7890
allow-lan: false
bind-address: "127.0.0.1"
mode: rule
log-level: info
ipv6: false

external-controller: 127.0.0.1:9090
secret: ""

dns:
  enable: true
  listen: 127.0.0.1:1053
  nameserver: [8.8.8.8, 1.1.1.1]
  fallback: [8.8.4.4, 1.0.0.1]

proxies:
  - { name: ss-example, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: "•••", udp: true }
  - { name: trojan-example, type: trojan, server: 5.6.7.8, port: 443, password: "•••", sni: example.com, udp: true }

proxy-groups:
  - { name: Proxy, type: select, proxies: [ss-example, trojan-example, DIRECT] }
  - { name: Auto, type: url-test, proxies: [ss-example, trojan-example], url: http://www.gstatic.com/generate_204, interval: 300, tolerance: 50 }

rules:
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - DOMAIN-SUFFIX,google.com,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
```

The repository ships a fuller [`config.example.yaml`](https://github.com/meow-rs/meow-rs/blob/main/config.example.yaml)
you can copy as a starting point.

## Compatibility notes

meow-rs prefers to **fail loudly** rather than silently accept ambiguous input. Compared
to upstream mihomo, the following are hard load-time errors instead of warnings:

- Relay groups with fewer than 2 proxies.
- Unknown `load-balance` strategies or unknown listener types.
- Duplicate listener ports or names.
- Deprecated VLESS flows (`xtls-rprx-direct` / `-splice`) and VMess `cipher: zero`.
- Unsupported Hysteria2 options (`certificate`, `private-key`, server-side ECH, …).

Forward-compatibility fields that meow-rs does not implement (e.g. some `geodata`
sub-keys) are accepted and ignored with a one-time warning so upstream configs still load.

### `strict: true` — fail loudly on unparseable entries

By default an entry that fails to parse — a `proxies:` node, a `proxy-groups:` block, a
`rules:` line, a `proxy-providers:` or `rule-providers:` definition, or a node inside a
provider payload — is logged and skipped so one bad line cannot take down the whole
config. Setting `strict: true` promotes every such skip to a hard load-time error:

```yaml
strict: true
```

Strict also promotes a few related warn-and-drop behaviors: a group `proxies:` member or
`use:` provider name that resolves to nothing, a `proxies:`/`proxy-groups:` entry named
after a built-in adapter (`DIRECT`, `REJECT`, …), and a malformed `dialer-proxy` value
(which would otherwise silently drop the configured chain).

This is opt-in because it rejects real-world mihomo subscriptions that mix in node types
meow-rs does not support — under `strict`, one unsupported node fails the whole provider
load. Fetch failures stay lenient: a provider that cannot be downloaded (or a `type: file`
provider whose file is unreadable) starts empty and retries on each `interval` tick — or
via a manual `PUT /providers/proxies/{name}` refresh or restart — since a network blip is
not a config defect. The same applies to `rule-providers:`: a definition defect or an
unparseable acquired payload is fatal under strict, while a failed download is not.

Two scope notes: `PUT /configs` rebuilds apply strictness to the candidate's
`proxies:`/`proxy-groups:`/`rules:`/`rule-providers:`/`proxy-providers:` —
the two provider kinds behave differently there. `proxy-providers:` unchanged
defs are reused unvalidated (a def changed only in `interval` still counts as
unchanged), new or changed defs are constructed (and validated) on PUT, every
committed provider adopts the candidate's `strict` flag, and an
already-fetched payload is not re-validated. `rule-providers:` are rebuilt
fully on every PUT — each definition is re-constructed *and* each payload
re-fetched or re-read and re-validated under the candidate's strict flag, so
a strict PUT can be rejected by a payload a lenient load accepted. And
`strict: true` combined with `subscriptions:` means a
subscription delivering an unparseable node makes every refresh fail — the
previous config is kept, but check subscription contents before enabling
strict.
