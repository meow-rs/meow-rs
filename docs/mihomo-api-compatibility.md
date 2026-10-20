# Mihomo API compatibility

This document tracks the external-controller API implemented by meow-rs.
The reference contract is MetaCubeX/mihomo `Meta` commit
`cbd11db1e13a75d8e680e0fe7742c95be4cba2be` (2026-07-07).

Status meanings:

- **Compatible**: route, status codes, and panel-visible payload behavior are implemented.
- **Partial**: the route is useful, but a listed mihomo capability has no meow-rs runtime equivalent.
- **Extension**: meow-rs API with no mihomo equivalent.
- **Not implemented**: deliberately not registered; callers receive 404.

## Panel runtime API

| Route | Status | Notes |
|---|---|---|
| `GET /` | Partial | Keeps the meow-rs identity response `{"hello":"meow"}` by project decision. |
| `GET /version` | Compatible | Returns the meow-rs version with `meta: true`. |
| `GET /proxies[/{name}]` | Compatible | Includes group `all`, `now`, `fixed`, test URL, health, history, and UDP fields. |
| `PUT /proxies/{name}` | Compatible | Supports Selector, URLTest, and Fallback groups. |
| `DELETE /proxies/{name}` | Compatible | Unfixes URLTest/Fallback; Selector and leaf adapters return 400. |
| `GET /proxies/{name}/delay` | Compatible | Implements mihomo delay/error semantics. |
| `GET /group[/{name}]` | Compatible | Lists and returns groups only. |
| `GET /group/{name}/delay` | Compatible | Unfixes automatic groups before the batch probe; maps each member that passed within `timeout` to its delay, leaving out the rest, and is 504 only when none passed. |
| `GET /traffic` | Compatible | HTTP newline-delimited JSON and WebSocket, including current and total counters. |
| `GET /connections` | Partial | HTTP snapshot and WebSocket interval mode are implemented; `metadata.dscp` is always a number (`0` when the inbound saw none); UDP sessions are not tracked. |
| `DELETE /connections[/{id}]` | Compatible | Closes one or all tracked connections. |
| `GET /logs` | Compatible | HTTP/WebSocket and plain/structured formats are supported. |
| `GET /memory` | Compatible | HTTP/WebSocket; each client starts with the mihomo-compatible zero frame. |
| `GET /dns/query` | Compatible | Supports address and generic RR types with the mihomo DNS JSON shape. |
| `GET /rules` | Partial | `index`, `type`, `payload`, `proxy`, and `size` are present; rule-wrapper hit/miss data is unavailable. |
| `GET/PUT /providers/proxies[/{name}]` | Compatible | Refresh failures return 503. |
| `GET /providers/proxies/{name}/healthcheck` | Compatible | Uses provider health-check configuration and returns 204. |
| `GET /providers/proxies/{provider}/{proxy}[/healthcheck]` | Compatible | Provider member detail and delay probe. |
| `GET/PUT /providers/rules[/{name}]` | Compatible | Includes format (`YamlRule`, `TextRule` or `MrsRule`: what the payload parsed as), vehicle type, rule count, and RFC 3339 update time. |
| `GET/PATCH /configs` | Partial | Runtime mode and log level are mutable. Dynamic listeners, TUN/TUIC, and interface changes are unavailable. |
| `PUT /configs` | Partial | Reloads proxies/rules/mode while retaining providers and selection persistence; the DNS runtime is republished on input changes and the TUN listener restarts on `tun:` diffs, but ordinary listener hot replacement is unavailable. |
| `POST /cache/dns/flush` | Compatible | Clears resolver cache. |
| `POST /cache/fakeip/flush` | Compatible | Clears fake-IP allocations. |

Authentication matches mihomo: ordinary HTTP requires the exact
`Authorization: Bearer <secret>` scheme, while WebSocket upgrades may instead
use `?token=<secret>`. Authentication failures use
`{"message":"Unauthorized"}`.

## Deliberate gaps

These endpoints depend on runtime facilities that meow-rs does not currently
provide and are not represented by fake-success stubs:

| Route | Reason |
|---|---|
| `PATCH /rules/disable` | No rule-wrapper disable/hit-count runtime. |
| `POST /configs/geo` | No hot geodata replacement transaction. |
| `GET/PUT/DELETE /storage/{key}` | No controller storage database. |
| `POST /restart` | Process lifecycle belongs to the service manager. |
| `POST /upgrade`, `/upgrade/ui`, `/upgrade/geo` | No self-updater. |
| Configurable DoH controller route | No external-controller DoH mount. |
| `/debug/*` | No Go pprof equivalent. |

Provider `subscriptionInfo`, UDP connection entries, and rule hit/miss
counters are also intentionally omitted until their underlying state exists.

## Meow-rs extensions

The following routes are retained and do not collide with the mihomo surface:

- `GET /metrics`
- `/api/subscriptions/*`
- `/api/proxy-groups/*`
- `/api/config/save`
- rule CRUD extensions on `/rules`
- `GET /dns/results` and `POST /dns/query`
- `GET /listeners`
- `GET /statistics`: `uploadTotal` / `downloadTotal` (the `/traffic`
  totals) and `proxies`, the bytes each proxy carried since start, TCP and
  UDP: `{"DIRECT": {"upload": N, "download": N}, ...}`. A group's traffic
  counts at the member that carried it, and a proxy a reload removed stays
  listed; empty when the tunnel runs headless. A `dialer-proxy` front
  member also counts the hop it carries, which the totals count once, so
  `proxies` can sum past them
- `GET /connections/{id}`: one `/connections` entry plus `closed`, `end`
  and the `notes` timeline (`[{time, kind, text}]`) recorded when
  `connection-notes: true`; closed connections with notes stay readable
  for the last 256
- `GET /logbook` and `DELETE /logbook`: the persistent record of notable
  engine events (reloads, subscription and provider updates, group switches,
  unclean exits), newest first, kept for 7 days across restarts. Filters
  `level` (lowest returned), `kind` (a kind or its area), `subject`; pages
  with `before=<id>`, polls with `since=<rev>`. `logbook: {enable: false}`
  turns it off; a `minimal` build reports `enabled: false`. See
  [ADR-0014](adr/0014-logbook.md) for the event kinds

When the mihomo baseline changes, compare `hub/route` and the outbound-group
JSON marshalers against this table before marking a new release compatible.
