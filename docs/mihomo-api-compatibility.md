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
| `GET /proxies[/{name}]` | Compatible | Includes group `all`, `now`, `fixed`, test URL, health, history, and UDP fields. Every proxy carries `provider-name` (`""` outside a provider); every group carries `hidden` and `icon`. The listing holds route-table entries only, as in mihomo; provider nodes are listed under `/providers/proxies`. |
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
| `GET /rules` | Compatible | `type` is mihomo's name (`DomainSuffix`); `extra` carries `disabled`, `hitCount` and `hitAt` (connections the rule was applied to since it entered the list, and the last one's time; the epoch when none). Unlike upstream's predicate-true wrapper, a hit counts only on the applied leaf — an inner leg of an AND/OR rule that evaluated true without the group matching does not tally; `missCount` is always `0` and `missAt` the epoch since the compiled matcher never visits most rules, and UDP probes do not count. `size` is the rule's own entry count where cheaply known (GEOIP, IP-ASN, GEOSITE and RULE-SET report their set sizes), `-1` elsewhere. Lines a client rebuilds from `type,payload,proxy` parse back through `POST`/`PUT /rules` for leaf rules — logic rules and `SUB-RULE` round-trip asymmetrically (their display payload is the inner body, not the full line). |
| `PATCH /rules/disable` | Compatible | `{index: disabled}`, any content type; a `null` body is an empty patch and a `null` value reads as `false`. A disabled rule is skipped and the plan recompiled without it, so a duplicate or shadowed rule behind it matches. Negative and out-of-range indexes are skipped; a key that is not an integer fails the request with nothing applied. The switch and hit counter follow a rule across config commits and subscription refreshes by type, payload and target. |
| `GET/PUT/DELETE /storage/{key}` | Compatible | `null` when unset; a value is valid JSON of at most 1 MB (400 / 413, checked in that order). A key past 64 bytes is silently accepted but never stored — PUT answers 204 and GET still returns `null`, upstream's quirk. At most 16384 keys and about 1 MiB in aggregate, evicting the least recently written first under either cap. Kept in `ui-storage.json` beside the selector cache, persisted lazily (writes coalesce). |
| `GET/PUT /providers/proxies[/{name}]` | Compatible | Refresh failures return 503. HTTP providers report `subscriptionInfo` from the `subscription-userinfo` response header. `expectedStatus` echoes the configured spec verbatim — `""` when unset or no health-check block, where mihomo reports `"*"`. |
| `GET /providers/proxies/{name}/healthcheck` | Compatible | Uses provider health-check configuration and returns 204. |
| `GET /providers/proxies/{provider}/{proxy}[/healthcheck]` | Compatible | Provider member detail and delay probe; members carry `provider-name`. |
| `GET/PUT /providers/rules[/{name}]` | Compatible | Includes format (`YamlRule`, `TextRule` or `MrsRule`: what the payload parsed as), vehicle type, rule count, and RFC 3339 update time. |
| `GET/PATCH /configs` | Partial | Mode, log level, `routing-mark` and `tun` are mutable. A `routing-mark` patch applies `SO_MARK` to outbound sockets opened after the commit (`0` clears); it is refused with 400 while meow's managed tproxy firewall holds an exemption for the current mark, and a refused patch leaves mode/log/tun untouched. A `tun` patch is merged over the current section and the TUN listener is started, stopped or restarted from the result, matching mihomo, with two differences: an omitted `enable` keeps the current state instead of turning TUN off, and a TUN that fails to start answers 500 instead of 204. Only the `tun` keys meow implements apply; the rest are ignored. `GET` reports `tun` with `enable` as the running state. `GET` reports `sniffing` (the resolved value — the deprecated `tproxy-sni` alias counts as enabled when no `sniffer:` block overrides it) and `skip-auth-prefixes`, but a `PATCH` of them is ignored: both are wired into the listeners at startup. Ports, `allow-lan`, `bind-address`, `ipv6`, `tcp-concurrent`, `find-process-mode`, `interface-name`, TUIC and the other dynamic listeners are unavailable. |
| `PUT /configs` | Partial | Reloads proxies/rules/mode while retaining providers and selection persistence; the DNS runtime is republished on input changes and the TUN listener restarts on `tun:` diffs, but ordinary listener hot replacement is unavailable. `routing-mark` applies with the commit and is refused while a managed tproxy firewall pins the current mark (same gate as `PATCH`). A JSON config document is legal YAML 1.2 input, but map order then comes from the submitted text's literal order — meow-rs never re-sorts, so clients needing deterministic `nameserver-policy`/`hosts` order should submit YAML. |
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
| `POST /configs/geo` | No hot geodata replacement transaction. |
| `POST /restart` | Process lifecycle belongs to the service manager. |
| `POST /upgrade`, `/upgrade/ui`, `/upgrade/geo` | No self-updater. |
| Configurable DoH controller route | No external-controller DoH mount. |
| `/debug/*` | No Go pprof equivalent. |

UDP connection entries are also intentionally omitted until their
underlying tracking exists, and rule `missCount`/`missAt` stay zero/epoch
by design (the compiled matcher short-circuits, so a rule that was never
reached is not a "miss").

## Meow-rs extensions

The following routes are retained and do not collide with the mihomo surface:

- `GET /metrics`
- `GET /proxies/{name}` and `GET /proxies/{name}/delay` also resolve a
  proxy-provider node by name, where mihomo returns 404. A route-table entry
  wins over a provider node of the same name; between providers, the first
  by provider name wins. The provider route reaches any one of them
- `GET /proxies/{name}/chain-health?dialer=…`: probes proxy `name` chained
  through each member of `dialer`, and each member alone, recording
  nothing; a verdict per member (`reached`, `failed`, `inconclusive`,
  `down`, `skipped`). See the REST API reference
- `/api/subscriptions/*`
- `/api/proxy-groups/*`
- `/api/config/save`
- rule CRUD extensions on `/rules`, including `POST /rules/append`
  (`{"rule": "<line>"}`: one line after the config's rules; a line that
  fails to parse answers 400 naming it rather than a silent 204)
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
- `GET /traffic/ledger` and `DELETE /traffic/ledger`: the traffic of
  local days by host (registrable domain), app, leaf policy or interface
  label, kept for 62 days across restarts. `from` and `to` (`YYYY-MM-DD`,
  today by default), `by` (`host`, `app`, `policy`, `interface`), and
  `host`, `app`, `policy`, `interface` to drill into one group. A
  policy row counts what the node carried as a `dialer-proxy` front too
  (`via_upload`, `via_download`, `via_requests`), so `policy=` takes in
  those flows as well. `traffic-ledger: {enable: false}` turns it off;
  a `minimal` build reports `enabled: false`. See
  [ADR-0015](adr/0015-traffic-ledger.md)

When the mihomo baseline changes, compare `hub/route` and the outbound-group
JSON marshalers against this table before marking a new release compatible.
