# Mihomo API compatibility

This document tracks the external-controller API implemented by meow-rs.
The reference contract is MetaCubeX/mihomo `Meta` commit
`cbd11db1e13a75d8e680e0fe7742c95be4cba2be` (2026-07-07).

Status meanings:

- **Compatible**: route, status codes, and panel-visible payload behavior are implemented.
- **Partial**: the route is useful, but a listed mihomo capability has no meow-rs runtime equivalent.
- **Extension**: meow-rs API with no mihomo equivalent.
- **Not implemented**: deliberately not registered; callers receive 404.

## Listener transports

Every route below serves identically over each configured controller
endpoint — the plain `external-controller` TCP listener plus, like
upstream, any of these coexisting listeners (issue #974, see
[api-listener.md](specs/api-listener.md)):

| Config key / CLI flag | Status | Notes |
|---|---|---|
| `external-controller-tls` / `--ext-ctl-tls` | Compatible | HTTPS via BoringSSL, ALPN `h2` then `http/1.1` (axum serves a real h2 on the `h2` ALPN). The endpoint is the `api-tls` build feature — `full`/`default` ship it, `minimal` parses the key but warns at startup that the HTTPS controller is not compiled into the build. Identity from `tls.certificate`/`tls.private-key` — both inline PEM or both home/`SAFE_PATHS`-contained file paths (a mixed pair is refused without embedding the inline material in errors); both unset serves an ephemeral self-signed RSA-2048 cert. Identity failures are endpoint-local like upstream: `-t`/load is shape-only, a bad pair just skips the TLS listener at bind. No PEM file watching. |
| `external-controller-unix` / `--ext-ctl-unix` | Compatible | Unix socket, relative path under the daemon home. Deliberate divergences: refuses non-socket/other-user paths, reclaims only a verified stale socket, binds `0600` (not `0666`, and chmod failure fails the endpoint), keeps Bearer auth, and the cleanup guard unlinks only the exact socket it bound — re-verified by type and `(dev, ino)`. |
| `external-controller-pipe` / `--ext-ctl-pipe` | Partial | Windows named pipe, byte mode, remote clients rejected, owner-only SDDL ACL on every instance; a failed next-instance creation still serves the already-connected client. Parsed but warn-ignored on non-Windows. |
| `external-controller-cors` | Compatible | Always the configured `cors.New` wire shape: `allow-origins` (`*`/globs/echo, `[]` = allow-all), `allow-private-network` (default `true`), `Access-Control-Max-Age: 300`, `HEAD` never allowed (preflight or actual), request headers limited to `{content-type, authorization, origin}` — one bad name denies the preflight. An absent map resolves the `["*"]`/`true` defaults like upstream under a set/unset secret; upstream's permissive `AllowAll` fires only on `secret: ""`, and meow mounts no CORS layer without a secret at all, so it has no counterpart. |
| `external-controller-routing-mark` | Not implemented | Parsed and warn-ignored; no controller-socket `SO_MARK`. |
| `tls:` other members | Not implemented | `client-auth-type`, `client-auth-certificates`, `ech-key`, `custom-certifactes` (sic) parse and warn-ignore. |

The listener surface is a startup snapshot: `PUT /configs` commits these
keys to the document for the next boot and warns that a restart applies
them — it never rebinds, reads PEMs or mutates CORS live. The plain TCP
bind is the only startup-fatal endpoint; the new ones log-and-skip like
upstream, and a config where every endpoint failed to bind logs that no
controller is available.

The same holds for named `listeners:` — including `type: anytls`: a PUT
that changes the effective listener set (its own keys OR an inherited
default like `max-connections`/`bind-address`/`sniffer:` resolving
differently) is committed to the in-memory document and reported with a
restart warning; running sockets, the authenticated user table and TLS
material are untouched. The committed document is NOT written back to
the backing config file — `PUT /configs` is a reload, not a save: keep
the submitted YAML as the file the next boot reads (or run
`PUT /configs` against the persisted path), otherwise the change is lost
on restart. A `type: anytls` entry this build cannot serve (no
`listener-anytls` feature) is rejected with 400 even under `?force=true`,
so a persisted config can never strand the next boot.

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
| `GET/PATCH /configs` | Partial | Mode, log level, `routing-mark`, `interface-name`, `global-ua` and `tun` are mutable. A `routing-mark` patch applies `SO_MARK` to outbound sockets opened after the commit (`0` clears); it is refused with 400 while meow's managed tproxy firewall holds an exemption for the current mark, and a refused patch leaves mode/log/tun untouched. An `interface-name` patch binds outbound sockets opened after the commit to that interface (`""` clears); it is never pin-refused the way `routing-mark` is — no managed firewall matches on an interface — and the name resolves to an index fresh per dial (no cache to invalidate), so an interface destroyed and recreated is followed while a missing one fails the dial closed; a node's own `interface-name` still wins, and loopback peers stay exempt. A `global-ua` patch installs the `User-Agent` internal HTTP fetches and latency probes send (`""` clears to `clash.meta/<version>`); a value carrying CR/LF/NUL/control bytes is refused with 400 and the live override is untouched. `GET` also reports the live `global-ua` and the committed `global-client-fingerprint`; the fingerprint is not patchable — adapters bake it at parse, so it changes through `PUT /configs`. A `tun` patch is merged over the current section and the TUN listener is started, stopped or restarted from the result, matching mihomo, with two differences: an omitted `enable` keeps the current state instead of turning TUN off, and a TUN that fails to start answers 500 instead of 204. Only the `tun` keys meow implements apply; the rest are ignored. `GET` reports `tun` with `enable` as the running state. When the TUN device is declared as a named `listeners:` `type: tun` entry instead (startup-only, one effective TUN), a `tun.enable` patch or PUT is refused with 400 while that device owns the slot, `GET` still reports `tun-enable`/`tun.enable` from the top-level section only, and `GET /listeners` lists the entry without a port; see docs/tun.md. `GET` reports `sniffing` (the resolved value — the deprecated `tproxy-sni` alias counts as enabled when no `sniffer:` block overrides it), `skip-auth-prefixes` and the live `interface-name`, but a `PATCH` of sniffing/skip-auth-prefixes is ignored: both are wired into the listeners at startup. `tcp-concurrent` is patchable: `false` switches new candidate selections to strictly sequential dials under a shared deadline, `true` (the meow-rs default — upstream's default is `false`) restores the race; `GET` reports the live policy and an in-flight dial run keeps the policy it started with. `find-process-mode` is patchable too: `always` looks up every eligible new inbound flow's owner before mode dispatch, `strict` (the default) only at the first reached process-demanding rule, `off` never — suppressing the traffic ledger's app lookup as well; `GET` reports the live mode. A `keep-alive-idle`/`keep-alive-interval`/`disable-keep-alive` patch merges the supplied fields over the committed values and re-installs the outbound keepalive policy for dials opened after the commit (bounds `0..=32767`, `0`/absent resolves to 15 s); `GET` reports the effective live values. `GET` also reports the effective `profile:` flags as `store-selected`/`store-fake-ip` (resolved over `dns.store-fake-ip`) and the resolved `ntp` object with `write-to-system: false`; `profile:` and `ntp:` keys in a patch are ignored. Ports, `allow-lan`, `bind-address`, `ipv6`, TUIC and the other dynamic listeners are unavailable. |
| `PUT /configs` | Partial | Reloads proxies/rules/mode while retaining providers and selection persistence; the DNS runtime is republished on input changes and the TUN listener restarts on `tun:` diffs, but ordinary listener hot replacement is unavailable; `lan-allowed-ips`/`lan-disallowed-ips` are validated (hard error on malformed CIDRs even with `?force=true`) and committed for the next boot, never re-applied to running accept loops, and `PATCH` does not model them. `routing-mark` applies with the commit and is refused while a managed tproxy firewall pins the current mark (same gate as `PATCH`); `interface-name` re-applies with the commit the same way, as do the committed `global-client-fingerprint` and `global-ua` (the UA installs process-wide, `""`/absent clears). `tcp-concurrent` and `find-process-mode` likewise re-apply at the swap — a document omitting them resets to the defaults (`true` for `tcp-concurrent`, `strict` for `find-process-mode`). `keep-alive-idle`/`keep-alive-interval`/`disable-keep-alive`, `profile:` and `ntp:` resolve and validate with the committed document and install at commit (omission resets to defaults); an enabled `ntp.dialer-proxy` must name a built top-level proxy/group or `DIRECT`, and invalid `ntp:`/`keep-alive-*`/`profile:` semantics are rejected even under `?force=true`. The geo update schedule (`geo-auto-update`, `geo-update-interval`, `geodata.auto-update*`) persists through a committed document but stays a startup snapshot: a change warns that restart applies it. A JSON config document is legal YAML 1.2 input, but map order then comes from the submitted text's literal order — meow-rs never re-sorts, so clients needing deterministic `nameserver-policy`/`hosts` order should submit YAML. |
| `POST /cache/dns/flush` | Compatible | Clears resolver cache. |
| `POST /cache/fakeip/flush` | Compatible | Clears fake-IP allocations. |

With a controller secret, HTTP requires the exact `Authorization: Bearer <secret>`
scheme, and WebSocket upgrades also accept `?token=<secret>`. Authentication
failures use `{"message":"Unauthorized"}`.

Without a controller secret, use an IP address or `localhost` to access the API.
Browser API requests and WebSocket upgrades must come from the controller's own
origin.

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

One per-node dialer-option divergence is worth calling out here since it
surfaces as a dial error an API client can observe: `mptcp: true` on a
kernel without Multipath TCP (Linux <5.6, or built without
`CONFIG_MPTCP`) fails the node's dial at `socket()` with
`EPROTONOSUPPORT` — fail-closed like every other socket-option failure —
where mihomo silently degrades to plain TCP. On kernels with MPTCP the
kernel itself handles the protocol-level fallback to a non-MPTCP peer.
Likewise `tfo`, `mptcp` and `routing-mark` on non-Linux platforms warn
once and are skipped rather than failing, and `interface-name` fails
closed with `Unsupported` on platforms that have no per-socket binding —
a configured interface must never be silently ignored.

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
- `GET /listeners`: active listeners (`name`, `type`, `port`, `listen`);
  tproxy entries also report `firewall`/`udp`/`udp-timeout`, and a
  `type: anytls` entry with several `listen` addresses reports them all
  under `addresses` (`port`/`listen` stay the first address). Credentials
  — the `users` digests, certificate and private key — are never in the
  output
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
