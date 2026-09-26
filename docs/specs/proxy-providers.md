# Spec: Proxy providers (M1.H-1)

Status: Approved (architect 2026-04-11, amendments applied)
Owner: pm
Tracks roadmap item: **M1.H-1**
Related roadmap: **M1.G-6** (`GET/PUT /providers/proxies[/:name]` API),
**M1.D-5** (rule-provider upgrade — shares interval-refresh and
Arc-shape patterns).
Related gap-analysis rows: §5 `/providers/proxies*` endpoints, §6
`proxy-providers` top-level key, §6 proxy-group sub-keys (`use`,
`include-all`, `filter`, `exclude-filter`, `exclude-type`).

## Motivation

A real Clash Meta subscription file almost always uses proxy-providers
rather than an inline `proxies:` list. The YAML file is a few lines;
the actual proxy list is fetched at startup from an HTTP subscription
URL. Without proxy-providers, meow-rs cannot load typical
real-world configs that point at managed subscription services — which
is the principal barrier to M1 exit.

The gap is two-sided:

1. **Config side**: the `proxy-providers:` top-level key is not
   parsed; proxy groups cannot reference providers via `use:`; group
   fields `filter`, `exclude-filter`, `exclude-type`, `include-all`
   are missing.
2. **Runtime side**: no HTTP fetch, no file watch, no background
   refresh, no health-check loop.

## Scope

In scope:

1. Parse `proxy-providers:` top-level YAML key. Provider types:
   `http` (fetch from URL) and `file` (read from disk). Same two
   types as rule-providers.
2. Fetch proxy list on startup; write fetched YAML to a local cache
   path so offline restarts can fall back to the cached copy.
3. `interval:` periodic background refresh for `http` providers.
   Unlike rule-providers (which defer interval to M1.D-5), proxy-
   providers must implement refresh in M1 — subscription tokens
   expire and proxy lists rotate, so a "loaded once at startup" model
   causes silent breakage within hours for most users.
4. `health-check:` subsection — periodic URL reachability probe for
   each proxy in the provider; results feed `ProxyHealth` (the same
   struct used by the api-delay-endpoints spec).
5. Proxy group `use:` field — reference one or more providers by name;
   proxies from those providers are merged into the group's proxy list
   at startup and re-merged on each provider refresh.
6. Proxy group `include-all:` / `include-all-proxies:` — boolean;
   when true, the group includes proxies from ALL defined providers
   (plus any explicit `proxies:` list).
7. Proxy group `filter:` and `exclude-filter:` — regex applied to
   proxy names after provider merge. `exclude-type:` — pipe-separated
   adapter type names to exclude (e.g. `"ss|vmess"`).
8. `override:` field on a provider — apply key-value config overrides
   to every proxy loaded from that provider (see §Override).
9. REST API endpoints (M1.G-6, bundled here because providers must
   exist before the API can serve them):
   - `GET /providers/proxies` — list all proxy providers with metadata.
   - `GET /providers/proxies/:name` — single provider detail + proxy list.
   - `PUT /providers/proxies/:name` — trigger a manual refresh.
   - `GET /providers/proxies/:name/healthcheck` — trigger an immediate
     health-check for all proxies in the provider.

Out of scope:

- **`inline` provider type** — upstream-only feature not used by any
  real subscription. Deferred to M1.D-5 / rule-provider-upgrade spec
  (same pattern, can be shared).
- **`mrs` binary format** — proxy providers only use YAML/text; MRS is
  a rule-provider-only format. Not applicable here.
- **`include-all-providers:`** — upstream providers-only alias for
  `include-all:`; wired identically (our `include-all` never pulls
  statics — `include-all-proxies:` covers that).
- **Signed/authenticated subscriptions** — M3 operational maturity.
- **`proxy-providers` as the source for `RULE-SET` rules** — not a
  thing; they are separate concepts.
- **Provider UDP disable** (`disable-udp: true` inside the provider's
  override map) — not implemented: `override:` honours only
  `dialer-proxy`; every other key logs a warning so the gap is visible
  rather than silently diverging (issue #489).

## Non-goals

- Implementing a subscription parser that understands non-YAML formats
  (SS-URI, Clash Premium, etc.). We parse YAML subscription payloads
  only — the same format produced by managed subscription services.
- Validating that the fetched proxy list is "trustworthy" (signing /
  cert-pinning). That is M3.
- Sharing the background-refresh tokio task structure with rule-
  providers in the same PR. The patterns are similar; dedup can happen
  naturally in M1.D-5 when the rule-provider spec absorbs the interval
  story. For now, duplicate the refresh loop in `meow-config` and
  leave a `// TODO: unify with rule-provider refresh in M1.D-5` marker.

## User-facing config

### `proxy-providers:` top-level key

```yaml
proxy-providers:
  subscription-hk:
    type: http
    url: https://sub.example.com/sub?token=xxx&target=clash
    path: ./proxy-providers/subscription-hk.yaml
    interval: 86400      # seconds; 0 or absent = no background refresh
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300      # seconds between health-check sweeps
      lazy: true         # if true, don't probe until first use
      expected-status: 204  # HTTP status code that counts as healthy
    override:            # optional; applied to every proxy in this provider
      skip-cert-verify: true
      udp: false
    filter: "^HK|香港"       # regex; only include names that match
    exclude-filter: "Premium|Trial"  # regex; exclude names that match
    exclude-type: "ssr"    # pipe-separated adapter type names to exclude

  local-backup:
    type: file
    path: ./proxy-providers/backup.yaml
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 600
```

### `proxy-groups:` additions

```yaml
proxy-groups:
  - name: auto-hk
    type: url-test
    use:
      - subscription-hk    # reference provider by name
    proxies:               # optional: mix explicit proxies with providers
      - DIRECT
    filter: "^HK"          # additional regex filter applied after use: merge
    interval: 300
    url: https://www.gstatic.com/generate_204
    include-all: false     # if true, include proxies from ALL providers

  - name: all-nodes
    type: select
    include-all: true      # merge proxies from every defined provider
```

### Field reference — proxy-providers

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `type` | `http\|file` | yes | — | Source type. |
| `url` | string | if `http` | — | Subscription URL. |
| `path` | string | yes | — | Local cache path. For `http`: write fetched YAML here. For `file`: read from here. Relative paths resolved from the config file's directory. |
| `interval` | integer | no | `0` | Refresh interval in seconds, scheduled by the refresh supervisor on every config commit. `0` or absent = no background refresh (manual `PUT /providers/proxies/{name}` still works). `file` providers re-read their file each tick — upstream instead fs-watchers file providers, so an un-`interval`ed `file` provider does not auto-reload here (divergence #2). |
| `health-check.enable` | bool | no | `false` | Enable periodic health-check probes. |
| `health-check.url` | string | if `enable` | — | URL used for reachability probes. |
| `health-check.interval` | integer | no | `300` | Health-check sweep interval in seconds. |
| `health-check.lazy` | bool | no | `false` | If true, defer first probe until the proxy is first used by a connection. (Note: provider health checks run only via the manual `/providers/proxies/{name}/healthcheck` endpoint today — nothing schedules them.) |
| `health-check.expected-status` | integer or string | no | any 2xx | HTTP status that counts as healthy: a bare code (`204`) or a range string (`"200-299"`, `"200,204"`). |
| `override` | map | no | `{}` | Key-value overrides applied to every proxy. See §Override. |
| `filter` | string | no | `""` | Regex. Include only proxies whose `name` matches. Empty = include all. |
| `exclude-filter` | string | no | `""` | Regex. Exclude proxies whose `name` matches. Applied after `filter`. |
| `exclude-type` | string | no | `""` | Pipe-separated adapter type names. Exclude proxies of those types. Case-insensitive. |
| `proxy` | string | no | `""` | Route this provider's `http` fetches through the named proxy or group, resolved against the live route map at fetch time (issue #625). `DIRECT` or absent fetches directly; an unresolvable name fails the fetch (never silently direct); whitespace-only is a build error. A named value on `file` providers warns — no fetch to chain. |
| `dialer-proxy` | string | no | `""` | Chain every node in this provider through the named front hop (issue #489). Distinct from `proxy`: that one routes the *fetch*, this one routes each node's *dials*. |

### Field reference — proxy-group additions

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `use` | `[]string` | no | `[]` | Provider names to merge into this group's proxy list. Unknown provider name = warn-once at load (not a hard error — the provider may not be defined in all config variants); under top-level `strict: true` it is a hard error. Inert on `relay` groups and under `include-all*` — an unknown name there never fails. |
| `include-all` | bool | no | `false` | If true, merge proxies from all defined providers — providers only (upstream's `include-all` also pulls statics; use `include-all-proxies` for that). Wins over `use:` when both are set. |
| `include-all-proxies` | bool | no | `false` | Merge every static `proxies:` entry into the group — NOT a provider alias. Upstream parity. |
| `filter` | string | no | `""` | Applied to provider-sourced members only (`use:` / `include-all`), matching upstream mihomo — explicit `proxies:` entries are never filtered (otherwise `proxies: [DIRECT]` + `filter: "^HK"` would drop DIRECT). |
| `exclude-filter` | string | no | `""` | Applied after `filter`. Provider-sourced members only. |
| `exclude-type` | string | no | `""` | Applied after `filter`/`exclude-filter`. Provider-sourced members only. |

#### Fetch-through-proxy (`proxy:`)

The name resolves against the **top-level** proxies/groups map —
provider-sourced node names are not reachable (upstream's
`proxies[SpecialProxy]` has the same namespace). Resolution happens per
fetch, matching upstream's `HttpRequestWithProxy` model, so a `PUT
/configs` rebuild or subscription commit that renames the target takes
effect on the next fetch without rebuilding the provider. An absent,
empty, or `DIRECT` (case-insensitive) value fetches direct; a
whitespace-only value is a build error (same posture as `dialer-proxy`);
any other name that cannot be resolved fails the fetch — never a silent
direct fallback, which would leak egress past a declared chain.

Two deliberate divergences from upstream to be aware of:

- **Absent `proxy:` fetches direct, not rule-routed.** Upstream's empty
  `SpecialProxy` runs the fetch through the rule engine (so a
  `MATCH,PROXY` config proxies provider fetches); `internal_http` has no
  rule-routing capability, so meow-rs fetches direct and requires an
  explicit `proxy:` for proxied egress. (Rule-providers diverge the other
  way: an absent `proxy` there defaults to the first `proxies:` entry.)
- **Startup ordering.** Providers are initially fetched before the first
  route map exists, so a startup `proxy:` name cannot resolve yet; the
  provider is flagged and retried once right after the map is published.
  Later fetches resolve live — no deferral needed.

Config trap: `proxy: G` where `G` is a group whose only members come from
this same provider can never resolve — the slot is empty, the group dial
fails, the fetch fails. Upstream has the same circularity; it is a
configuration error, not a code bug. Also note `DIRECT` is matched
case-insensitively, so a node literally named `direct`/`Direct` is not
reachable via `proxy:` — rename it.

#### Runtime rebuilds (`PUT /configs`, subscription refresh)

The candidate config's own `proxy-providers:` section is the `use:`/
`include-all` authority for that rebuild — not the live registry. A still-
declared name reuses its live `ProxyProvider` object (slots, fetched content,
and health state carry over); a newly declared name is constructed empty and
gets a detached initial fetch on commit; a dropped name stops resolving `use:`
(zombie-binding is impossible). A failed rebuild never mutates the live
registry. `strict` follows the committed generation: reused providers adopt
the new flag, so a `strict: true` PUT makes their next refresh strict too.

Subscription payloads only carry `proxies:`/`proxy-groups:`/`rules:` — a
`proxy-providers:` section inside a subscription is ignored (upstream parity).
Consequently, under `strict: true` a subscription group may `use:` only
providers declared in the local config; subscription-internal provider names
fail the strict `use:` check (issue #533 review).

### Override

`override:` is a free-form map whose keys are proxy config field
names. After a proxy is loaded from a provider, each key in the
override map is applied, overwriting the corresponding field in the
parsed proxy config struct.

Supported override keys in M1 (a bounded set, not arbitrary):

| Override key | Type | Applied to |
|-------------|------|-----------|
| `skip-cert-verify` | bool | All TLS-capable proxy types |
| `udp` | bool | All proxy types |
| `up-speed` / `down-speed` | integer | Ignored with warn (upstream Hysteria fields; not in scope) |
| `ip-version` | string | Ignored with warn (upstream preference field; not in scope) |
| Any unknown key | any | **warn-once, ignore.** Forward-compat. |

Override is applied at parse time, not at dial time — the override
mutates the parsed `ProxyConfig` struct before it is built into an
adapter. This avoids per-connection overhead and keeps the override
logic in one place.

**Divergence from upstream** — upstream applies overrides at adapter-
build time with reflection-like field lookup. We apply at config
parse time to a typed struct, which means only the keys we
explicitly support are honoured. Unknown keys warn and skip.
Classification: Class B per ADR-0002 — user's traffic still routes
correctly through the correct adapter; only unsupported keys are
silently no-ops (with a warn). The warn makes the gap visible.

## Internal design

### New crate: `meow-providers` or module in `meow-config`?

**Recommendation: module inside `meow-config`**, not a new crate.
Reasoning:

- The provider loading logic (HTTP fetch → YAML parse → `Vec<ProxyConfig>`)
  depends heavily on `meow-config`'s proxy parser. A separate crate
  would either depend on `meow-config` (creating a near-circular
  reference) or duplicate the parser.
- Rule-providers already live in `crates/meow-config/src/rule_provider.rs`.
  Proxy-providers are the natural sibling: `proxy_provider.rs`.
- The only new external dep is `reqwest` (HTTP client), which belongs
  in `meow-config` rather than a separate crate.

If the provider manager grows significantly in M2 (hot-reload, signed
subscriptions), extract to a crate then.

### `ProxyProvider` struct

Not a trait — proxy-providers are not polymorphic from the perspective
of the rest of the system. They are a concrete record with two
runtime variants (http, file) expressed as an enum:

```rust
// crates/meow-config/src/proxy_provider.rs

pub struct ProxyProvider {
    pub name: String,
    pub config: ProviderConfig,
    /// Current proxy list; updated atomically on refresh.
    pub proxies: Arc<RwLock<Vec<Arc<dyn ProxyAdapter>>>>,
    /// Latest health-check results, keyed by proxy name.
    pub health: Arc<RwLock<HashMap<String, ProxyHealth>>>,
}

pub enum ProviderConfig {
    Http {
        url: String,
        path: PathBuf,
        interval: Option<Duration>,
        health_check: HealthCheckConfig,
        filter: Option<Regex>,
        exclude_filter: Option<Regex>,
        exclude_types: Vec<String>,
        overrides: ProxyOverride,
    },
    File {
        path: PathBuf,
        health_check: HealthCheckConfig,
        filter: Option<Regex>,
        exclude_filter: Option<Regex>,
        exclude_types: Vec<String>,
        overrides: ProxyOverride,
    },
}
```

`Arc<RwLock<Vec<Arc<dyn ProxyAdapter>>>>` is the key shape. Proxy
groups hold an `Arc<ProxyProvider>` (not a snapshot). When the
provider refreshes, it acquires the write lock, rebuilds the proxy
list, and releases; all groups reading through the same Arc see the
new list on the next connection attempt. This is the same inner-
mutability pattern that the rule-provider `Arc<dyn RuleSet>` uses —
the connection to M1.D-5 that architect flagged.

**Open question for architect:** should `ProxyProvider` implement a
trait (`pub trait Provider { fn proxies(&self) -> Vec<..>; }`) to
allow future mock implementations in tests, or is the concrete struct
sufficient? My lean: concrete struct is fine for M1 — tests can
construct a `ProxyProvider` directly with a `file:` config pointing
at a fixture YAML. No trait needed until a third provider type forces
it. Flag for your call.

### Startup flow

```
load_config() {
  1. parse raw::RawConfig → raw_providers
  2. load_proxy_providers(raw_providers) → HashMap<String, Arc<ProxyProvider>>
     a. For each provider:
        - If http: try fetch from URL; on error, try cache path;
          on both fail, skip provider with warn (non-fatal, matching
          rule-provider "best-effort keep running" pattern).
        - If file: read from path; on error, skip with warn.
        - Parse YAML → Vec<RawProxy> → parse_proxies → Vec<Arc<dyn ProxyAdapter>>
        - Apply filter/exclude-filter/exclude-type
        - Apply override to each proxy config
        - Store in Arc<RwLock<...>>
     b. Return map: name → Arc<ProxyProvider>
  3. Resolve proxy groups: for each group, merge explicit `proxies:` list
     with referenced providers' current proxy lists (read lock).
  4. Build Tunnel with resolved groups + provider map in AppState.
  5. Spawn background tasks:
     - One refresh task per http provider with interval > 0.
     - One health-check sweep task per provider with health-check.enable.
}
```

### Background refresh task

```rust
// Spawned per http provider with interval > 0
async fn refresh_loop(provider: Arc<ProxyProvider>, app_state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip the first tick (just loaded)
    loop {
        ticker.tick().await;
        if let Err(e) = provider.refresh(&app_state).await {
            warn!(provider = %provider.name, "refresh failed: {:#}", e);
            // do not abort; next tick will retry
        }
    }
}

impl ProxyProvider {
    async fn refresh(&self, app_state: &AppState) -> Result<()> {
        // 1. Fetch new YAML from url
        // 2. Write to cache path (atomic: write tmp, rename)
        // 3. Parse into new Vec<Arc<dyn ProxyAdapter>>
        // 4. Apply filters + overrides
        // 5. Acquire write lock on both proxies and health
        // 6. Swap proxy list
        // 7. Prune health map: drop entries for proxies no longer in
        //    the new list; preserve entries for surviving proxies.
        //    Prevents unbounded map growth and stale data on GET.
        // 8. Release locks — groups read through Arc on next dial/sweep
    }
}
```

Step 6 is intentionally passive — groups hold `Arc<ProxyProvider>` and
read on each dial (or on URLTest/Fallback health-check sweep). There is
no explicit notification bus. Groups that cache their resolved proxy
list locally (e.g. for a Selector's current selection) need to detect
when their selected proxy disappears after a refresh and fall back to
the first available. **Engineer: add a `selected_still_present()` check
in `Selector::dial` that falls back if the current selection is no
longer in the provider's list.** Document this with a comment.

### Health-check task

```rust
async fn health_check_loop(provider: Arc<ProxyProvider>) {
    let mut ticker = tokio::time::interval(health_check_interval);
    if lazy {
        // first tick waits for a connection to use a proxy from this provider
        // (simplified: just sleep the first interval, do not track first-use)
        ticker.tick().await;
    }
    loop {
        ticker.tick().await;
        probe_all_proxies(&provider).await;
    }
}

async fn probe_all_proxies(provider: &ProxyProvider) {
    let proxies = provider.proxies.read().await.clone();
    // spawn one probe per proxy, bounded concurrency (max 10 concurrent)
    // update provider.health on each result
}
```

Health results are stored in `provider.health: Arc<RwLock<HashMap<String, ProxyHealth>>>`.
The API handler for `GET /providers/proxies/:name/healthcheck` reads
from this map. The `ProxyHealth` struct already defined by the
api-delay-endpoints spec is reused here — providers populate it via
the same URL probe mechanism as the delay endpoint.

### reqwest dependency

`meow-config` gains a `reqwest` dep for HTTP provider fetch:

```toml
[dependencies]
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "gzip"] }
```

> **As shipped:** the provider HTTP client is the in-tree
> `meow_config::internal_http` (no `reqwest` dependency) — the reqwest
> plan below was superseded so provider/subscription/geodata downloads
> could ride `proxy:`-named hops through `Arc<dyn Proxy>` dials
> (issue #625).

- **`rustls-tls`** — no OpenSSL; consistent with the rest of the
  workspace.
- **`gzip`** — real-world subscriptions commonly serve gzipped YAML;
  without this, reqwest won't auto-decompress and engineer would need
  to hand-roll it.
- **`default-features = false`** — blocks `cookies`, `brotli`, `zstd`,
  `charset`, `hyper-util` defaults from sneaking in.
- **No `json`** — subscription payloads are raw YAML or base64-encoded
  YAML, not JSON. The `json` feature pulls serde_json for zero benefit
  here.

Net new dep tree: ~12 crates. The `proxy-providers` feature gate allows
minimal builds to drop reqwest entirely.

**Feature gate:** `proxy-providers` feature on `meow-config` gates
the reqwest dep. Default-on. M2 footprint audit flips if the dep
tree is significant. Same pattern as `meow-dns/encrypted`.

```toml
[features]
default = ["proxy-providers"]
proxy-providers = ["dep:reqwest"]
```

When `proxy-providers` is disabled, the `proxy-providers:` YAML key
is accepted and parsed (the raw struct always exists) but loading
produces a hard-error per provider entry: "proxy-providers support
requires the 'proxy-providers' Cargo feature; rebuild with
--features proxy-providers". Class A per ADR-0002: silently ignoring
the provider would drop all proxies from the group without diagnostic.

### REST API additions

All three endpoints live in `crates/meow-api/src/routes.rs` under
the existing `/providers` router.

```
GET  /providers/proxies
→ JSON: { "providerName": { "name", "type", "vehicleType", "updatedAt",
           "subscriptionInfo", "proxies": [{ proxy detail + health }] }, … }

GET  /providers/proxies/:name
→ Same shape, single provider. 404 if unknown.

PUT  /providers/proxies/:name
→ Trigger async refresh. Returns 204 immediately; refresh happens in background.
  If provider is type=file, still returns 204 but refresh is a file re-read
  (useful after the user has manually updated the file).

GET  /providers/proxies/:name/healthcheck
→ Trigger an immediate health-check sweep for this provider. Returns 204;
  sweep runs in background. Results visible on next GET /providers/proxies/:name.
```

`AppState` grows a `proxy_providers: HashMap<String, Arc<ProxyProvider>>`
field alongside the existing `proxies` and `rules` fields. Route
handlers access providers through `State<Arc<AppState>>` as today.

## Divergences from upstream

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Unknown override key — upstream applies via reflection | B | Reflection is unavailable in Rust's type system; warn-once and ignore. User's proxy still routes correctly; only the override field is skipped. |
| 2 | `file` provider auto-reload — upstream fs-watches the file (any modification reloads immediately, regardless of `interval`) | B | We re-read on `interval` ticks instead of watching; `interval: 0`/absent means no auto-reload (manual `PUT` only). Same content model, different trigger. |
| 3 | Unknown provider name in `use:` — upstream silently skips | B | We warn-once at load: "proxy group '...' references unknown provider '...'; it will be empty". Same runtime behaviour, more operator signal. |
| 4 | `include-all-proxies:` — upstream alias | B | Warn-once "use include-all:", treat identically. No routing change. |
| 5 | Proxy-providers feature disabled, providers in config — upstream N/A (always enabled) | A | Hard-error per provider entry instead of silent empty group. Class A: silently skipping all provider proxies causes misrouting without diagnostic. |
| 6 | HTTP fetch failure at startup — upstream skips provider silently | B | We warn-once with the URL and error; matching the rule-provider "best-effort keep running" pattern but with a visible warn. No hard-error at startup because the cache path may still satisfy the load. |
| 7 | Duplicate proxy name across providers — upstream last-write-wins silently | B | We warn-once per collision naming both source providers and the winning entry. Config-file order (`proxy-providers:` key order) is the deterministic iteration order; last definition wins. Warn text: `"proxy name '<name>' is defined in both provider '<A>' and provider '<B>'; using the entry from '<B>' (later in config). Rename one to disambiguate."` Once per collision per load; new collisions introduced by a refresh also warn. |

## Acceptance criteria

A PR implementing this spec must:

1. A config with `proxy-providers:` of both `http` and `file` type
   loads successfully; proxies from each provider appear in groups
   that reference them via `use:`.
2. `filter:` and `exclude-filter:` regex are applied; proxies outside
   the regex are not visible to the group.
3. `exclude-type: "ss|vmess"` excludes proxies of those adapter types.
4. `include-all: true` on a group includes proxies from every defined
   provider.
5. HTTP provider writes the fetched YAML to the cache path. On next
   startup, if the URL is unreachable, the cache path is used. Test
   fixture: mock HTTP server that first succeeds, then returns 503.
6. Background refresh fires after `interval` seconds; old proxies are
   replaced with new ones atomically (no partial-read window). Assert
   with a mock server that serves two different proxy lists.
7. Health-check sweep calls the probe URL for every proxy; results
   appear in `GET /providers/proxies/:name` response `proxies[].history`.
8. `PUT /providers/proxies/:name` triggers a refresh and returns 204;
   subsequent `GET` reflects updated list.
9. `GET /providers/proxies/:name/healthcheck` triggers sweep and
   returns 204.
10. Unknown override key logs exactly one `warn!` per key per provider
    (not one per proxy). Class B per ADR-0002.
11. `interval:` on a `file` provider schedules a periodic re-read (see
    divergence #2 — no fs-watch; `interval: 0` = manual refresh only).
12. Unknown `use:` provider name logs exactly one `warn!` per group.
13. `crates/meow-config` with `--no-default-features` compiles; a
    config with `proxy-providers:` entries hard-errors at load with
    the "rebuild with --features proxy-providers" message.
14. Selector group falls back to the **first proxy in the provider's
    current `Vec` iteration order** (which mirrors YAML order of the
    fetched subscription) when the selected proxy is removed by a
    refresh. "First available" must be deterministic across restarts
    against the same subscription — assert with a fixture that produces
    the same fallback choice on two successive identical refreshes.
15. `GET /proxies/:selector_name` reports the **actual current proxy**
    after a Selector fallback, not the stale stored preference name.
    `PUT /proxies/:selector_name` allows selecting any proxy currently
    in the provider's list (not a cached snapshot from before the
    refresh).
16. Health HashMap is pruned on refresh: entries for proxies removed
    from the subscription are dropped; entries for surviving proxies
    are preserved. Assert `GET /providers/proxies/:name` contains no
    stale health entries after a refresh that removes a proxy.
17. URLTest and Fallback groups that reference providers via `use:`
    re-resolve from `provider.proxies.read()` on each sweep cycle —
    they do NOT cache the proxy list locally. Assert:
    `urltest_sweep_picks_up_refreshed_provider_list` — provider
    refreshes with a new list; next URLTest sweep probes the new
    proxies, not the old ones.
18. Duplicate proxy name across two providers logs exactly one warn
    per collision per load (not per-refresh cycle unless the duplicate
    is new). Warn message names both providers and the winning entry.
    Class B per ADR-0002.
19. `PUT /configs` (M1.G-10, when implemented) triggers a provider
    reload. Document the dependency in a code comment; do not block
    this PR on M1.G-10.

## Test plan (starting point — qa owns final shape)

**Unit (`crates/meow-config/src/proxy_provider.rs`):**

- `filter_regex_keeps_matching_names` — provider with `filter: "^HK"`,
  fixture YAML with 3 proxies, assert only the HK-named proxy survives.
- `exclude_filter_removes_matching_names` — `exclude-filter: "Trial"`,
  assert Trial-named proxy removed.
- `exclude_type_removes_ss_proxies` — `exclude-type: "ss"`, fixture
  with SS + Trojan proxies, assert only Trojan survives.
  Upstream: `adapter/provider/proxy.go::proxiesWithFilter`. NOT
  case-sensitive match — compare lowercased type strings.
- `override_skip_cert_verify_applied` — override `skip-cert-verify: true`,
  assert every proxy in the loaded list has `skip_cert_verify == true`.
- `override_unknown_key_warns_once` — override with an unknown key,
  assert exactly one `warn!` log regardless of proxy count in the list.
  Class B per ADR-0002: upstream applies via reflection; we warn.
  NOT one warn per proxy — one per key per provider.
- `file_provider_interval_warns` — `interval: 3600` on a file provider
  → one `warn!`. NOT silent.
- `unknown_use_provider_warns` — group `use: [nonexistent]` → one `warn!`.
  NOT a hard-error at load.
- `include_all_merges_all_providers` — two providers defined, group
  `include-all: true`, assert group proxy list = union of both provider lists.

**Unit (refresh + cache):**

- `http_provider_writes_cache_on_success` — mock HTTP server returns
  YAML, assert cache file written atomically (tmp + rename pattern).
- `http_provider_falls_back_to_cache_on_failure` — mock returns 503
  after first success, assert load uses cached file on second startup.
- `refresh_swaps_list_atomically` — mock returns two different lists;
  trigger refresh; assert list swapped without a partial-read window
  (use a concurrent reader task to verify).
- `selector_falls_back_when_selection_removed_after_refresh` — start
  with proxy A selected, refresh removes proxy A from provider list,
  assert Selector falls back to proxy B on next dial.
- `selector_fallback_is_deterministic_across_refreshes` — two
  successive refreshes that both remove proxy A produce the same
  fallback choice (first proxy in Vec iteration order). Assert
  fallback name matches for both refresh cycles.
  Upstream: upstream Selector fallback is also "first proxy"; we
  match. NOT arbitrary — must be YAML-order-stable.
- `health_map_pruned_on_refresh` — provider with proxy A + B, health
  data for both recorded; refresh removes proxy B; assert health map
  contains only proxy A's entry. NOT stale data for B.
  Upstream: no equivalent — upstream stores health by proxy name
  without pruning. Our explicit prune prevents unbounded map growth.
- `urltest_sweep_picks_up_refreshed_provider_list` — URLTest group
  references a provider; provider refreshes with a new proxy list;
  next URLTest sweep probes the new proxies. Assert sweep uses the
  post-refresh list, not the pre-refresh snapshot.
  NOT local cache — URLTest must NOT store a `Vec<Arc<dyn ProxyAdapter>>`
  field populated at construction; it must re-read `provider.proxies`
  on each sweep. This is the single most likely silent-bug vector in
  the implementation.
- `duplicate_proxy_name_warns_once_per_collision` — two providers
  both define "US-Node-1"; assert exactly one `warn!` naming both
  providers and the winner. Class B per ADR-0002. NOT per-refresh
  repeat if the collision is unchanged.

**Unit (REST API handlers):**

- `get_providers_proxies_returns_all` — two providers loaded, assert
  both appear in the JSON response with correct `name` and `type`.
- `get_providers_proxies_name_404_on_unknown` — unknown provider name
  → HTTP 404.
- `put_providers_proxies_name_triggers_refresh` — mock server, assert
  `PUT` returns 204 and the provider's proxy list is updated.
- `get_providers_proxies_name_healthcheck_returns_204` — assert 204
  and that health-check results eventually appear in the provider state.

**Integration (`crates/meow-config/tests/proxy_provider_test.rs`,
new file):**

- `load_config_with_http_provider` — starts a local HTTP server
  serving a fixture YAML, loads a full config referencing it,
  asserts proxies appear in the group proxy list.
- `load_config_with_file_provider` — points a file provider at a
  fixture YAML, asserts proxies loaded.
- `provider_disabled_feature_hard_errors` — with
  `--no-default-features`, config with `proxy-providers:` entries
  hard-errors with the feature-gate message. (Compile-time gate; this
  test may live in `Cargo.toml` as a `cfg` test or in CI rather than
  a runtime test.)

## Implementation checklist (for engineer handoff)

- [ ] Add `raw::RawProxyProvider` to `crates/meow-config/src/raw.rs`;
      add `proxy_providers: Option<HashMap<String, RawProxyProvider>>`
      to `RawConfig`.
- [ ] Add `use`, `filter`, `exclude_filter`, `exclude_type`,
      `include_all` fields to `raw::RawProxyGroup` (and the existing
      `ProxyGroup` parsed struct).
- [ ] Implement `crates/meow-config/src/proxy_provider.rs`:
      - `ProxyProvider` struct + `ProviderConfig` enum.
      - `load_proxy_providers(raw, cache_dir, proxy_parser_ctx)
         -> HashMap<String, Arc<ProxyProvider>>`.
      - HTTP fetch with `reqwest` (feature-gated); cache write
        (atomic tmp+rename); fallback-to-cache on error.
      - File read path.
      - Filter + override application.
      - `refresh()` async method.
- [ ] Wire `load_proxy_providers` into `load_config` after proxy
      parsing and before proxy group resolution.
- [ ] Update proxy group resolution in `lib.rs` to merge provider
      proxies into each group's proxy list after provider loading.
- [ ] Add `proxy_providers: HashMap<String, Arc<ProxyProvider>>` to
      `AppState` in `meow-app/src/main.rs`.
- [ ] Spawn background refresh tasks (one per http provider with
      interval > 0) and health-check tasks (one per provider with
      health-check.enable) in `main.rs`.
- [ ] Add `selector_falls_back_when_selection_removed` guard in
      `meow-proxy/src/group/selector.rs`. Fallback is deterministic:
      first proxy in provider's current Vec iteration order (YAML order).
      `GET /proxies/:name` must report actual post-fallback proxy name.
      Re-selection consults live provider list, not a cached snapshot.
      Comment references this spec.
- [ ] **URLTest and Fallback: do NOT cache the resolved proxy list.**
      These groups must call `provider.proxies.read()` (or equivalent)
      on each sweep cycle, not store a local `Vec<Arc<dyn ProxyAdapter>>`
      at construction time. Add a comment at the local-cache footgun:
      `// do not store proxy_list as a field — re-read from provider
      // on each sweep; see docs/specs/proxy-providers.md §concern-2`.
- [ ] Add REST API routes in `meow-api/src/routes.rs`:
      - `GET /providers/proxies`
      - `GET /providers/proxies/:name`
      - `PUT /providers/proxies/:name`
      - `GET /providers/proxies/:name/healthcheck`
- [ ] Add `proxy-providers` Cargo feature to `meow-config/Cargo.toml`
      gating `reqwest`. Hard-error path in `load_proxy_providers` when
      feature absent.
- [ ] Add `// TODO: unify with rule-provider refresh in M1.D-5` comment
      in the refresh loop.
- [ ] Update `docs/roadmap.md` M1.H-1 and M1.G-6 rows with merged PR link.
- [ ] Open a follow-up task "M1.G-6: proxy-provider API endpoints" if
      the REST routes are split into a second PR (acceptable if the
      config+runtime work is already large).

## Known limitations

**`Arc<RwLock<...>>` vs `ArcSwap`.** The read-mostly pattern here
(thousands of dials per second against a list that changes every N
hours) would benefit from `arc_swap::ArcSwap<Vec<Arc<dyn ProxyAdapter>>>` —
lock-free reads on the hot path, atomic write on refresh. However,
ArcSwap is one more dependency and the `RwLock` approach is correct
for M1. M2 footprint/perf audit should evaluate ArcSwap as a
drop-in optimization. Lock contention on the dial path is negligible
at realistic proxy counts (<1000 per provider) but becomes visible at
10k+. Not a correctness issue.

## Resolved questions (architect sign-off 2026-04-11)

1. **`ProxyProvider` as trait vs concrete struct → concrete struct.**
   YAGNI. Tests use file-type providers with fixture YAMLs. Refactor
   to trait when a third provider type forces it.

2. **Passive read-through vs broadcast channel → passive, with two
   requirements.** Broadcast adds complexity without benefit that
   URLTest's existing sweep cycle doesn't already provide. Passive
   read-through is the M1 shape. Requirements: (a) Selector fallback
   must be deterministic — first proxy in Vec/YAML order, not arbitrary.
   (b) `GET /proxies/:name` reports the actual post-fallback proxy;
   re-selection consults the live provider list. Both are acceptance
   criteria (#14, #15). M2 refinement if explicit notification is ever
   needed.

3. **reqwest vs ureq → reqwest.** Async context; `spawn_blocking` for
   sync ureq creates the same nested-runtime risk as the dns-doh-dot
   sync constructor. Feature set: `rustls-tls` + `gzip`,
   `default-features = false`. No `json`.

4. **Duplicate proxy name → last-write-wins + named warn.** Config-
   file order is the deterministic iteration order. Warn text must name
   both source providers and the winning entry. Once per collision per
   load; new collisions from refreshes also warn. Added as divergence
   row #7 and acceptance criterion #18.
