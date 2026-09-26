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
| `GET` | `/proxies` | All proxies and groups |
| `GET` | `/proxies/{name}` | One proxy/group (name, type, alive, history, udp, `all`, `now`) |
| `PUT` | `/proxies/{name}` | Select a member in a group — body `{ "name": "member" }` → 204 |
| `GET` | `/proxies/{name}/delay` | Probe delay — query `url`, `timeout`, `expected` |
| `GET` | `/group/{name}/delay` | Probe every member of a group |

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
| `GET` | `/connections` | Snapshot: totals + per-connection `src`/`dst`/`chains`/`rule`/`upload`/`download`/`start` |
| `DELETE` | `/connections` | Close all connections → 204 |
| `DELETE` | `/connections/{id}` | Close one connection by UUID → 204 |

## Config

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/configs` | Current `mode`, `log-level`, ports, controller |
| `PATCH` | `/configs` | Update `mode` and/or `log-level` → 204 |
| `PUT` | `/configs` | Hot-reload the whole config (below) |
| `POST` | `/api/config/save` | Persist the current config to disk |

`PUT /configs` accepts `{ "path": "/path/to/config.yaml" }` or
`{ "payload": "<base64-yaml>" }`. Add `?force=true` to apply despite validation errors
(logged). Returns 204 on success, or 400 `{ message }` on a parse/validation failure.

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
| `GET` | `/providers/rules` | List rule providers |
| `GET` | `/providers/rules/{name}` | One rule provider |
| `PUT` | `/providers/rules/{name}` | Refresh a rule provider |

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
| `DELETE` | `/api/subscriptions/{name}` | Remove and clear its contents → 204 |

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
