# REST API Reference

meow-rs exposes an Axum-based REST API for runtime control, compatible with the
Clash/mihomo external-controller surface that dashboards like metacubexd and yacd expect.

## Enabling

```yaml
external-controller: 127.0.0.1:9090
secret: "a-long-random-string"
```

Without `external-controller`, the API does not start. See
[Authentication](../guide/authentication) for the auth model.

- **REST auth:** `Authorization: Bearer <secret>`.
- **WebSocket auth:** the bearer header *or* `?token=<secret>`.
- **CORS:** permissive (`Access-Control-Allow-Origin: *`).

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/proxies
```

## Dashboard

A web UI is served at **`/ui`**. By default it's the built-in panel; set
[`external-ui`](../guide/configuration#top-level-keys) to serve a third-party dashboard's
static files instead.

## Meta

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Health check — returns `{"hello":"meow"}` |
| `GET` | `/version` | `{ version, meta: true }` |

## Proxies

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/proxies` | All proxies and groups (provider nodes are listed under `/providers/proxies`) |
| `GET` | `/proxies/{name}` | One proxy/group (name, type, alive, history, udp, `provider-name`; groups add `all`, `now`, `hidden`, `icon`); also finds a provider node |
| `PUT` | `/proxies/{name}` | Select a member in a group — body `{ "name": "member" }` → 204 |
| `GET` | `/proxies/{name}/delay` | Probe delay — query `url`, `timeout`, `expected`; also probes a provider node |
| `GET` | `/group/{name}/delay` | Probe every member of a group — same query; `{ "member": delay }` for the members that passed within `timeout`, 504 when none did |

Every proxy object carries `provider-name`: the name of the proxy-provider
that supplied the node, or `""` for `proxies:` entries, groups and the
built-ins. Every group object carries `hidden` and `icon`, the group's
`hidden:` / `icon:` keys (`false` / `""` when unset); GUIs use them to leave a
group out of their list and to draw its icon.

`GET /proxies` lists the route table, as mihomo does, so the nodes a
proxy-provider supplies appear there only by name, in their groups' `all`.
`GET /proxies/{name}` and `GET /proxies/{name}/delay` still resolve such a
node (mihomo returns 404 there). When a name is both a `proxies:` entry and
a provider node, the `proxies:` entry wins; when two providers supply it,
the first provider by name wins. `/providers/proxies/{provider}/{name}`
reaches each of them.

## Rules

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/rules` | List active rules (`type`, `payload`, `proxy`) |
| `POST` | `/rules` | Replace all rules — body `{ "rules": ["...", ...] }` → 204 |
| `PUT` | `/rules` | Update one rule — body `{ "index": n, "rule": "..." }` → 204 |
| `DELETE` | `/rules/{index}` | Delete the rule at an index → 204 |
| `POST` | `/rules/reorder` | Move a rule — body `{ "from": i, "to": j }` → 204 |

## Connections

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/connections` | Snapshot: totals + per-connection `metadata`/`chains`/`rule`/`upload`/`download`/`start` (`metadata.dscp` is `0` when the inbound saw none) |
| `DELETE` | `/connections` | Close all connections → 204 |
| `DELETE` | `/connections/{id}` | Close one connection by UUID → 204 |

## Config

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/configs` | Current `mode`, `log-level`, ports, controller, `tun` |
| `PATCH` | `/configs` | Update `mode`, `log-level` and/or `tun` → 204 (below) |
| `PUT` | `/configs` | Hot-reload the whole config (below) |
| `POST` | `/api/config/save` | Persist the current config to disk (400 when the daemon was started via `--config-string` — there is no backing file) |

`PATCH /configs` with `{ "tun": { "enable": true } }` turns TUN on without a restart,
as a mihomo GUI's TUN switch expects. The `tun` keys (`enable`, `device`, `mtu`,
`inet4-address`, `inet6-address`, `auto-route`, `outbound-interface`, `dns-hijack`,
`udp-timeout`) are merged over the current `tun:` section, so an omitted key, `enable`
included, keeps its value; other keys are ignored. The listener is then started, stopped
or restarted the way a `PUT /configs` `tun:` change does it. A section the listener
cannot parse returns 400 and applies nothing; a TUN that fails to start (no permission to
create the device, or a build without the `listener-tun` feature) is turned off again and
the PATCH returns 500 `{ message }`. `GET /configs` reports `tun`, where `enable` is
whether the listener runs. Like `mode`, the change lives in memory until the config is
saved.

`PUT /configs` accepts `{ "path": "/path/to/config.yaml" }` or
`{ "payload": "<base64-yaml>" }`. Add `?force=true` to apply despite validation errors
(logged). Returns 204 on success, or 400 `{ message }` on a parse/validation failure.
For `subscriptions:` entries kept by name+URL the daemon carries its
`applied-*` contribution tracking forward — a PUT that omits those
bookkeeping fields does not orphan the subscription's tracked content.

## Traffic & metrics

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/traffic` | Cumulative `{ up, down }` bytes |
| `GET` | `/metrics` | Prometheus exposition (traffic, active connections, proxy alive/delay, rule matches, RSS, build info) |

## DNS & caches

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/dns/query` | Resolve `name` (optional `type`, default `A`) → mihomo DNS JSON `{ Status, Question, TC/RD/RA/AD/CD, Answer?, Authority?, Additional? }` — non-A/AAAA types relay the upstream response sections verbatim |
| `POST` | `/dns/query` | Legacy resolve — body `{ name, type? }` (`type` ignored) → `{ name, answer }` |
| `POST` | `/cache/dns/flush` | Clear the DNS cache → 204 |
| `POST` | `/cache/fakeip/flush` | Clear FakeIP allocations → 204 |

## Providers

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/providers/proxies` | List proxy providers |
| `GET` | `/providers/proxies/{name}` | One proxy provider |
| `PUT` | `/providers/proxies/{name}` | Refresh (re-fetch) → 204 |
| `GET` | `/providers/proxies/{name}/healthcheck` | Health-check all proxies in it |
| `GET` | `/providers/proxies/{provider}/{proxy}` | One node of a proxy provider |
| `GET` | `/providers/proxies/{provider}/{proxy}/healthcheck` | Probe one provider node's delay — query `url`, `timeout`, `expected` |
| `GET` | `/providers/rules` | List rule providers (`format` is `YamlRule`, `TextRule` or `MrsRule`) |
| `GET` | `/providers/rules/{name}` | One rule provider |
| `PUT` | `/providers/rules/{name}` | Refresh a rule provider |

An `http` proxy provider whose server sends a `subscription-userinfo`
response header (`upload=…; download=…; total=…; expire=…`) carries the
plan usage as `subscriptionInfo` in `GET /providers/proxies[/{name}]`, the
way mihomo reports it:

```json
{ "subscriptionInfo": { "Upload": 1234, "Download": 5678, "Total": 1073741824, "Expire": 1700000000 } }
```

Bytes, and Unix seconds for `Expire`; a key the header leaves out reads 0
(an `Expire` of 0 is a plan without an end date). The last fetch the
provider accepted decides: one without the header drops the field, a failed
one keeps it. The usage is kept next to the provider cache, in
`<path>.subscription-userinfo`, so a restart that starts from the cache
reports it before the first refetch. `file` providers have none.

## Proxy groups

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/proxy-groups` | List groups |
| `POST` | `/api/proxy-groups` | Create a group |
| `PUT` | `/api/proxy-groups/{name}` | Update a group → 204 |
| `DELETE` | `/api/proxy-groups/{name}` | Delete a group → 204 |
| `PUT` | `/api/proxy-groups/{name}/select` | Switch active member → 204 |

## Subscriptions

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/subscriptions` | List, with counts and last-updated |
| `POST` | `/api/subscriptions` | Add `{ name, url, interval?, proxy? }` and apply |
| `POST` | `/api/subscriptions/{name}/refresh` | Re-fetch |
| `DELETE` | `/api/subscriptions/{name}` | Remove the entry and its contributed nodes/groups/rules → 204 |

Applying a subscription **merges** it into the config rather than
replacing sections wholesale: remote proxies/groups merge by name into
`proxies:`/`proxy-groups:` (remote wins a name collision; entries it
stopped shipping are removed on the next apply) and its `rules:` are
prepended ahead of the local table. Local entries and other
subscriptions' content survive; `DELETE` removes only the contribution
the entry tracked. The `proxy_count`/`group_count`/`rule_count` fields in
add/refresh responses report the merged section totals; in `GET` they
report each subscription's own recorded contribution (`applied-*` counts).
`DELETE` shares the rebuild-and-commit path, so it can return 400 when
removing the contribution would starve a local group — fix or remove the
group first.

All three mutation endpoints auto-save the merged config to the backing
file. Under `--config-string` there is no backing file: the change still
applies in memory, the write is skipped, and add/refresh report
`"persisted": false` in the response JSON.

`POST`'s `proxy` is resolved eagerly at request time — an unknown or
whitespace-only name is a `400` and nothing is stored. That is stricter
than a `subscriptions:` entry in the config file, where the name may
forward-reference a proxy the fetched payload itself later publishes
(the file path stores it and each refresh resolves it against the live
route map).

## Listeners

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/listeners` | Active listeners (`name`, `type`, `port`, `listen`; tproxy entries also report `firewall`, `udp`, `udp-timeout`) |

## WebSocket streams

Authenticate with the bearer header or `?token=<secret>`.

| Path | Query | Stream |
| --- | --- | --- |
| `/logs` | `level=debug\|info\|warning\|error\|silent` | Log lines `{ type, payload, time }` |
| `/traffic` | — | Periodic `{ up, down }` deltas |
| `/memory` | — | Memory / RSS stats |

```bash
# tail logs over WebSocket
websocat 'ws://127.0.0.1:9090/logs?level=info&token=<secret>'
```
