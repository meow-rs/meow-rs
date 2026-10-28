# Spec: Geodata YAML subsection (M2+)

Status: Approved (architect 2026-04-11, M2+ implementation);
**as-shipped amendments applied 2026-10-24** (on-demand download
convergence — `proxy` key, `geox-url` alias, reference-driven startup
fetch and reference-filtered auto-update). Sections marked
*As shipped* describe the landed implementation and supersede the
original plan where they differ.
Owner: pm
Tracks roadmap item: **M2** (task #47)
Architect decision 2026-04-11: no `geodata:` YAML key in M1.
See also: [`docs/specs/rules-parser-completion.md`](rules-parser-completion.md) —
ASN file-discovery chain used in M1 for IP-ASN rule;
[`docs/specs/rule-geosite.md`](rule-geosite.md) — geosite file path also covered here.

## Motivation

Upstream Go mihomo exposes a `geodata:` (and scattered `geo-*`) config section
that lets users override DB file paths, set download URLs, and enable periodic
auto-update. In M1 meow-rs discovers DB files via a XDG-compliant path chain
and never downloads them — the user is expected to provision them manually or
via their package manager.

M2 adds the full config surface so operators can:

1. Override discovery with explicit paths (`mmdb-path`, `asn-path`, `geosite-path`).
2. Point to alternative download URLs instead of the defaults.
3. Enable background auto-update on a configurable interval.

## M1 state (no action required — document only)

In M1 meow-rs discovers each DB file at runtime in order:

| DB | Discovery chain (tried in order, first found wins) |
|----|-----------------------------------------------------|
| GeoIP MMDB | `$XDG_CONFIG_HOME/meow/Country.mmdb` → `$HOME/.config/meow/Country.mmdb` → `./meow/Country.mmdb` |
| ASN MMDB | `$XDG_CONFIG_HOME/meow/GeoLite2-ASN.mmdb` → `$HOME/.config/meow/GeoLite2-ASN.mmdb` → `./meow/GeoLite2-ASN.mmdb` |
| Geosite | `$XDG_CONFIG_HOME/meow/geosite.mrs` → `$HOME/.config/meow/geosite.mrs` → `./meow/geosite.mrs` |

If a DB is absent, any rule requiring it returns an error at rule-match time
(not at parse time), matching the error-at-use behaviour described in
`rules-parser-completion.md` §GEOIP and `rule-geosite.md` §GEOSITE.

No auto-update, no `geodata:` YAML key, no explicit-path override in M1.

## Planned M2 YAML surface

```yaml
geodata:
  # Path overrides — skip file-discovery for that DB
  mmdb-path: /etc/meow/Country.mmdb        # optional
  asn-path: /etc/meow/GeoLite2-ASN.mmdb   # optional
  geosite-path: /etc/meow/geosite.mrs      # optional

  # Auto-update
  auto-update: false            # default: false
  auto-update-interval: 24      # hours; ignored when auto-update: false

  # Download egress — which outbound DB downloads ride (as shipped)
  proxy: hk-01                  # optional; default = last MATCH target, else proxies[0]

  # Download URLs (used on demand for referenced-and-missing DBs and by
  # the auto-update tick)
  url:
    mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb"
    asn: "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"
    geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.mrs"

# Top-level mihomo alias for geodata.url.* — merged per key UNDER the
# explicit geodata.url.* values (as shipped):
geox-url:
  mmdb: "https://cdn.example.com/Country.mmdb"
  asn: "https://cdn.example.com/GeoLite2-ASN.mmdb"
  geosite: "https://cdn.example.com/geosite.dat"
```

Field reference:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `mmdb-path` | string | — | Explicit path to GeoIP MMDB. Skips discovery chain. |
| `asn-path` | string | — | Explicit path to ASN MMDB. Skips discovery chain. |
| `geosite-path` | string | — | Explicit path to geosite `.mrs` file. Skips discovery chain. |
| `auto-update` | bool | `false` | If true, background task re-downloads the *referenced* DBs on each interval. |
| `auto-update-interval` | u32 | `24` | Hours between update checks. Minimum: 1 (sub-hour polling hammers GitHub rate limits). No maximum. |
| `proxy` | string | default egress | Outbound the downloads ride — a `proxies:`/`proxy-groups:` name, or a built-in terminal name (`DIRECT`, `REJECT`, `REJECT-DROP`, `COMPATIBLE`, `PASS`, `PASS-RULE`, case-insensitive) for direct. Unset → the last top-level `MATCH,<target>` target, then `proxies[0]`; blank/unknown names warn and fall through to the same default. |
| `url.mmdb` | string | *(default above)* | Download URL for Country.mmdb. |
| `url.asn` | string | *(default above)* | Download URL for GeoLite2-ASN.mmdb. |
| `url.geosite` | string | *(default above)* | Download URL for geosite.mrs. |
| `geox-url` (top-level) | map | — | mihomo flat alias for `url.*` — keys `mmdb`/`asn`/`geosite`/`geoip`. Per-key precedence: `geodata.url.*` > `geox-url.*` > default; effective alone (no `geodata:` block). `geoip` is accepted and warned-on-ignored — upstream points it at `geoip.dat`, which has no consumer here. |

**Fields absent from upstream that we intentionally omit:**

| Upstream field | Reason omitted |
|----------------|----------------|
| `geodata-mode` | Go mihomo supports `.dat` (V2Ray binary) and `.mmdb`. We use mmdb for GeoIP/ASN and `.mrs` for geosite — no mode switch needed. |
| `geodata-loader` | Go-specific memory-vs-speed tradeoff for `.dat` loader. Not applicable. |
| `geoip-matcher` | Go-specific (`succinct` vs `aho-corasick`). We use our own trie. |

## Internal design

### Path resolution

```
fn resolve_db_path(explicit: Option<&str>, discovery: &[&str]) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(PathBuf::from(p));   // explicit wins, even if file absent
    }
    discovery.iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}
```

Explicit path override is accepted even if the file does not yet exist
(the on-demand fetch may download it before first use). Absence at
first-use is a runtime error, not a parse-time error.

### Startup download — *As shipped*: reference-driven, on demand

There is no unconditional boot-time fetch. During `build_config`,
`ensure_geodata` computes which DBs the config **references** and downloads
only those that are also **missing on disk**, before the parser context is
built (a missing referenced file is otherwise a hard error downstream):

- Rule-side references come from `collect_geo_scan_lines` — top-level
  `rules:`, `sub-rules:` blocks, logic rules, and rule-provider payloads
  (inline + prefetched `file:`/`http:`): `GEOIP`/`SRC-GEOIP` → MMDB,
  `IP-ASN`/`SRC-IP-ASN` → ASN MMDB, `GEOSITE` → geosite DB.
- DNS-side references, both gated by `dns.enable: true` (matching
  `parse_dns`'s own early return): `geosite:` nameserver-policy keys →
  geosite DB; `fallback:` non-empty with `fallback-filter.geoip` not
  `false` (default `true`) → MMDB.

A config with zero geo references downloads nothing. `-t` validation stays
fully offline (`is_offline_validate` early-returns before any fetch).
Download failure is `warn!`-only; a still-missing required DB then fails
at its own load point as before.

The verdict (`GeoDataNeeds`) is computed once by `geo_references` — the
same helper `missing_geodata_downloads` consumes — and stored on
`Config.geo_needs` for the auto-update loop. It is a **startup snapshot**:
a later `PUT /configs` that adds a geo reference does not widen it. That
reload's rebuild (`rebuild_from_raw_runtime`, also behind subscription
refresh) downloads the newly referenced DB once when it is missing — the
GeoIP/ASN parser context would otherwise hard-error and reject the reload —
but the auto-update loop does not refresh it.

A referenced geosite DB that startup failed to download (tolerated absent,
so the build succeeds) is retried in the background by
`missing_geosite_retry_loop`: back-off from one minute, doubling to an
hour, each attempt an auto-update tick scoped to geosite, until the DB is
on disk.

### Download egress — *As shipped*: `resolve_geodata_egress`

`geodata.proxy` overrides which outbound downloads ride. The result is a
`GeodataEgress`: `Direct`, `Proxy { proxy, direct_fallback }`, or
`Rejected` (no download at all). Resolution order:

1. `geodata.proxy` — a `proxies:`/`proxy-groups:` name resolves against the
   built proxy map as-is (a `select` group dials its persisted-or-first
   member; no leaf-stripping). Built-in names:
   `DIRECT`/`COMPATIBLE`/`PASS`/`PASS-RULE` mean direct,
   `REJECT`/`REJECT-DROP` mean no download. An exact built-in spelling is
   the built-in; otherwise a name present in the map is that node (a user
   proxy named `pass` is not `PASS`, as the tunnel binds it); only then does
   a case-insensitive built-in spelling count. Blank warns and is ignored;
   an unknown name warns and falls through to (2).
2. The tunnel mode's default route — the config's `mode:` at startup, the
   live mode on an auto-update tick. `direct` → direct; `global` → the
   `GLOBAL` group (direct without one, as the tunnel routes); `rule` → the
   last top-level `MATCH,<target>`, with the same built-in/`map.get`
   semantics, a miss warning and falling through to (3).
3. `proxies[0]` — the legacy `first_named_proxy` fallback.

*Direct fallback (geodata-only opt-in):* for an implied egress from (2)
or (3) — on first boot a MATCH group fed by proxy-providers has no members
yet, since their fetches are detached. Never for an explicit
`geodata.proxy`, nor for an egress that can reach a static `dialer-proxy`
chain — the proxy itself, a group listing one (recursively), an
`include-all`/`include-all-proxies` group, or a synthesized `GLOBAL` over
a config that has one (`reaches_dialer_chain`): those are deliberate
egress and fail loudly like a provider `proxy:` (#625), so where the CDN
is blocked a dead chain cannot become direct egress. Nodes from
proxy-providers are fetched content and are not seen. When the FIRST request's proxy dial fails (connect phase only,
`CONNECT_TIMEOUT` included), `internal_http::fetch_or_direct` warns and
restarts the fetch with no proxy. Post-dial failures (TLS, HTTP status,
body) and redirect-hop dials never fall back — a mid-chain failure must not
silently leak egress. Provider/subscription fetches deliberately do NOT get
this fallback.

### Auto-update task — *As shipped*

Spawned once at startup when `auto-update: true`. A single sequential loop
wakes every `auto-update-interval` hours; each tick awaits inline, so two
downloads can never overlap (the original per-DB `AtomicBool` in-flight
guard is superseded — the loop's serialization provides the same
guarantee). On each tick:

1. **Reference filter.** Only the DBs flagged in the `Config.geo_needs`
   startup snapshot are touched: `needs.asn` gates the ASN MMDB,
   `needs.geosite` gates the geosite DB. The Country MMDB is never a tick
   target — country mappings change rarely, and skipping the refresh keeps
   the parser-built `CountryIndex` alive without churn (replace the file
   on disk and restart to move GeoIP generations). An all-false snapshot
   early-returns before any dial or warn.

2. **Download, write scratch, rename.** `download_and_replace` writes to a
   unique `{base}.{pid}.{n}.tmp` scratch in the target directory, then
   atomically `rename`s over the target. The original conditional-GET plan
   (HEAD / `If-Modified-Since`, skip on 304) is **superseded — not
   implemented**: every tick performs a full body fetch; interval
   floor of 1h plus third-party CDN tolerance was judged sufficient.

3. **Commit.** After ≥1 successful download the task serializes through
   the config-mutation lane, rebuilds rules from the committed raw config
   (binding the live provider objects), re-parses DNS, and republishes the
   resolver — the in-memory generation swap the original "reload the
   `Arc<RwLock>` DB" note called for, realized via the normal
   rebuild/republish path rather than a bespoke DB swap. All-failed ticks
   warn once and skip the rebuild.

Download failure: log `warn!` (+ a `download_failed`/`reload_failed`
logbook record) and retry next interval. Do NOT abort the update task or
panic. The resolved URL is logged at INFO on each fire:
`auto-update: downloading {db} from {url}` (via `… via proxy '{name}'`
when `geodata.proxy`/the default egress resolved a proxy).

## Divergences from upstream (classified per ADR-0002)

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | `geodata-mode` / `geodata-loader` / `geoip-matcher` — present in upstream | B | Fields are silently ignored if present (forward-compat). Warn-once at parse time with names of ignored fields. |
| 2 | Auto-update download failure — upstream logs and continues | — | We match: warn! and retry next interval. Not an error. |
| 3 | `geox-url` top-level — upstream feeds `geoip.dat`/`geosite.dat`/mmdb update URLs | B | `mmdb`/`asn`/`geosite` merge per key under `geodata.url.*`; `geoip` (upstream's `geoip.dat` URL) warns-once and is ignored — meow has no geoip.dat consumer. |
| 4 | `geodata.proxy` — upstream downloads always direct | — | Extension, not a conflict: explicit egress selection plus a first-hop-dial-failure direct retry; providers/subscriptions keep their own `proxy:` semantics. |

**Design note — explicit path to absent file:** upstream Go mihomo rejects at parse time
if an explicit path doesn't exist. We accept at parse time and error at first use.
This is a deliberate accommodation for the auto-update flow: an operator can set
`geosite-path` to a not-yet-downloaded file, set `auto-update: true`, and let the
first update cycle download it before any GEOSITE rule fires. This is not a
Class A or B divergence — it is a feature interaction, not a correctness trade-off.

## Acceptance criteria (*as shipped*)

1. With no `geodata:` subsection, file-discovery chain runs as in M1.
2. `mmdb-path` set → discovery chain skipped; explicit path used.
3. `mmdb-path` absent file + GEOIP rule → error at first rule match, not at parse.
4. `auto-update: true` → background task spawned; after `auto-update-interval`
   hours, updated DB loaded without restart.
5. Download failure → `warn!` logged, retry next interval, no crash.
6. `url.mmdb` override → on-demand and auto-update fetches use custom URL.
7. Upstream-only fields (`geodata-mode`, `geodata-loader`) → parsed without
   error, `warn!` logged once per field.
8. `auto-update-interval: 0` → hard parse error ("minimum is 1 hour").
9. ~~Conditional GET~~ — **superseded, not implemented**: every tick performs
   a full body download.
10. ~~Single in-flight guard~~ — **superseded**: the single sequential update
    loop cannot overlap downloads by construction.
11. Zero geo references → zero startup downloads; a referenced-and-missing
    DB (incl. DNS-side `fallback-filter.geoip` and `geosite:` policy keys,
    both gated by `dns.enable: true`) is fetched before the parser context
    is built. `-t` stays offline.
12. `geodata.proxy` — named proxy/group rides the download; built-in
    terminal name → direct; unset → last top-level `MATCH` target, then
    `proxies[0]`; first-hop proxy-dial failure retries once direct
    (geodata-only fallback).
13. `geox-url.*` fills any `url.*` key left unset (per-key precedence
    `geodata.url` > `geox-url` > default); `geox-url.geoip` warns and is
    ignored.
14. Auto-update refreshes only referenced DBs (`Config.geo_needs` startup
    snapshot — `asn`/`geosite` flags only; the MMDB is never a tick
    target; all-false → the tick is a no-op).

## Implementation checklist (engineer handoff — M2)

> Original checklist retained for history; items 4–5 were superseded by the
> as-shipped design above (single sequential loop, no conditional GET).

- [x] Add `GeoDataConfig` struct to `meow-config` for the `geodata:` subsection.
- [x] Update `resolve_db_path()` in `meow-rules` and `meow-dns` to accept
      optional explicit path before discovery chain.
- [x] Spawn auto-update task in `main.rs` when `auto-update: true`; wrap each
      DB in `Arc<RwLock<_>>` if not already.
- [ ] ~~Add per-DB `AtomicBool` in-flight guard; skip tick with `debug!` if
      set~~ — superseded: the sequential loop serializes ticks.
- [ ] ~~Implement conditional GET (`If-Modified-Since` or HEAD + compare
      headers); skip body download on 304 / unchanged~~ — superseded:
      every tick performs a full body fetch.
- [x] Implement atomic file replace (`tempfile` + `rename`).
- [x] Warn-once on unrecognised `geodata.*` fields.

## Resolved questions (architect sign-off 2026-04-11)

1. **Nested under `geodata:` (not top-level).** Upstream's top-level scatter
   (`geoip-db:`, `geodata-mode:`) is a historical accident. Nested groups
   path-overrides, URLs, and auto-update lifecycle concerns cleanly and avoids
   a proliferation of `geo*` top-level keys. Users migrating from Go mihomo
   are reading new docs in M2 anyway.

2. **Bake default URLs in.** The 90% case is "trust MetaCubeX defaults, just
   turn auto-update on." Users who need overrides can set `url.*` explicitly.
   Document that defaults are best-effort (third-party artefacts, no SLA).
   Log the resolved URL at INFO on each fire.

3. **Do NOT fold rule-set updates into `geodata:`.** Rule-providers already have
   their own `interval:` refresh mechanism; cadences differ (rule-providers = hours,
   geodata = days). Keep them separate. `rule-provider-upgrade.md` notes:
   "geodata auto-update is a separate mechanism; see geodata-subsection.md."
