use crate::dropped_providers::DroppedProviders;
use crate::proxy_parser;
use crate::raw::{RawHealthCheck, RawProxyProvider};
use crate::subscription_userinfo::{self, SubscriptionUserinfo};
use dashmap::DashMap;
use meow_common::atomic::AtomicU;
use meow_common::logbook::{self, Level};
use meow_common::{ProviderSlot, Proxy};
use meow_proxy::dialer::ProxyRegistry;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// First retry delay for a provider whose background fetch failed (proxy-
/// and rule-providers share the policy).
#[cfg(not(test))]
pub(crate) const BACKGROUND_RETRY_MIN: Duration = Duration::from_secs(5);
#[cfg(test)]
pub(crate) const BACKGROUND_RETRY_MIN: Duration = Duration::from_millis(20);
/// Backoff ceiling for those retries — a provider with nothing loaded keeps
/// retrying at this pace until a fetch lands.
#[cfg(not(test))]
pub(crate) const BACKGROUND_RETRY_MAX: Duration = Duration::from_secs(300);
#[cfg(test)]
pub(crate) const BACKGROUND_RETRY_MAX: Duration = Duration::from_millis(80);
/// Failed revalidations of a cache-loaded provider before the background
/// task leaves it to the `interval` loop. Spans the first ~75 s at the
/// production backoff — long enough to outlast a mobile VPN that has no
/// network until its tunnel is up.
pub(crate) const MAX_REVALIDATION_ATTEMPTS: u32 = 5;
/// Appended to an HTTP provider's cache path to name the file that keeps
/// the plan usage its server reported (see
/// [`ProxyProvider::subscription_userinfo`]).
const USERINFO_SUFFIX: &str = ".subscription-userinfo";

pub struct HealthCheckConfig {
    /// mihomo `healthCheckSchema.URL`, stored trimmed (upstream
    /// `strings.TrimSpace`s it in `execute()`/`registerHealthCheckTask`)
    /// — empty means "no probe URL configured": upstream zeroes the
    /// interval (`NewHealthCheck`), so no periodic sweep runs and both
    /// the scheduled loop and the manual healthcheck endpoint skip
    /// probing.
    pub url: String,
    /// mihomo `healthCheckSchema.Enable` — gates only the periodic
    /// sweep; the block still feeds the manual healthcheck endpoint and
    /// the `testUrl`/`expectedStatus` API echo when false (upstream
    /// builds `HealthCheck` unconditionally).
    pub enable: bool,
    pub interval: u64,
    pub timeout: u64,
    pub expected_status: String,
    /// Upstream `Lazy` skips a tick when the provider saw no traffic in
    /// the last interval. Parsed for config compatibility only, never
    /// read: meow tracks no per-provider last-touch, so ticks are never
    /// skipped (same precedent as group `lazy` — #555, ADR-0002; an
    /// explicit `lazy: true` warns at build).
    pub lazy: bool,
}

pub struct ProxyProvider {
    pub name: String,
    pub slot: ProviderSlot,
    pub vehicle_type: &'static str,
    vehicle: Vehicle,
    filter: Option<fancy_regex::Regex>,
    exclude_filter: Option<fancy_regex::Regex>,
    exclude_type: Vec<String>,
    pub health_check: Option<HealthCheckConfig>,
    updated_at: AtomicU,
    /// Flattened custom request headers (name-sorted; one entry per value,
    /// so multi-value headers repeat the name — RFC 9110 §5.2).
    header: Vec<(String, String)>,
    ipv6: bool,
    /// Whether `plugin:` on provider-sourced nodes may name an external
    /// SIP003 executable. Provider content is remote-controlled; without the
    /// opt-in such nodes are rejected before reaching `Command::new`.
    allow_external_plugin: bool,
    /// Top-level `strict: true` (issue #533): an unparseable node in the
    /// payload fails the parse instead of being warn-skipped — at load time
    /// that rejects the whole config; on refresh it keeps the last-good set.
    /// Atomic so a committed `strict`-flip (`PUT /configs`) reaches provider
    /// objects that were reused across the rebuild.
    strict: AtomicBool,
    /// Normalized `global-client-fingerprint` committed for the config
    /// generation this provider was built under (issue #974). Nodes
    /// inherit it at parse, so a changed global must fail `matches_def`
    /// and rebuild the provider rather than reuse stale adapters.
    global_client_fingerprint: Option<String>,
    /// Registry every provider node's `dialer-proxy` resolves against
    /// (issue #489). Unlike the per-build registry handed to static proxies,
    /// this handle is republished on every routing install, so provider
    /// nodes — which outlive individual config builds — always resolve the
    /// *current* route map, matching mihomo's by-name-at-dial-time model.
    dialer_registry: ProxyRegistry,
    /// `proxy:` — the name this provider's HTTP fetches resolve against the
    /// same republished cell at fetch time (upstream resolves the vehicle's
    /// proxy per request). `None` = direct (`proxy:` absent, empty, or
    /// `DIRECT`) (issue #625).
    download_proxy: Option<smol_str::SmolStr>,
    /// The config's live-resolver indirection `type: dns` nodes bind
    /// (issue #974). Like `dialer_registry`, this provider outlives the
    /// config generation that built it — the cell is republished by the
    /// tunnel on every DNS install, so a node parsed on any later refresh
    /// resolves the current slot rather than a captured snapshot.
    dns_cell: meow_dns::DnsOutboundCell,
    /// Set when a fetch found `download_proxy` unresolvable — the startup
    /// build loads providers *before* the first route map is published, so
    /// the post-publish kick ([`spawn_deferred_initial_fetches`]) fetches
    /// those still flagged (issue #625). Cleared once the name resolves
    /// again.
    deferred_initial: AtomicBool,
    /// Set by the startup load for a provider whose remote payload has not
    /// landed yet — it started from its on-disk cache (to be revalidated),
    /// or its fetch failed or outlived the
    /// [`crate::set_provider_fetch_deadline`] budget. Consumed with
    /// `deferred_initial` by [`Self::take_deferred_initial`]. A separate
    /// flag because `fetch_source` clears `deferred_initial` as soon as the
    /// `proxy:` name resolves, which would race a straggling fetch.
    background_pending: AtomicBool,
    /// A remote payload has been committed (or matched the committed one)
    /// at least once — lets a queued background attempt skip the fetch a
    /// straggling startup fetch just completed.
    fetched_remote: AtomicBool,
    /// Signalled by [`Self::commit`] whenever the member set is replaced —
    /// the health-check sweep sleeps on it between interval ticks so a
    /// payload landing mid-interval is probed on arrival, the way
    /// mihomo's `setProxies` fires `go hc.check()` on every commit.
    /// `notify_one` leaves a stored permit when nobody is waiting, so a
    /// commit made before the sweep's first wait still wakes it.
    members_changed: tokio::sync::Notify,
    /// The committed payload was parsed without its ECH DNS preresolve —
    /// the config-mutation lane's check-only load must not look anything
    /// up, so the detached post-commit fetch owes the slot one off-lane
    /// re-parse under the full preresolve before `fetched_remote` can
    /// settle (issue #533 review).
    ech_pending: AtomicBool,
    /// `dialer-proxy` names declared by the currently loaded nodes —
    /// repopulated on every [`refresh`](Self::refresh) so a config build can
    /// warn about references the registry will never resolve.
    declared_dialers: RwLock<Vec<String>>,
    /// Provider-level `dialer-proxy` — upstream writes it into every
    /// node's mapping unconditionally, so it overrides node-level fields
    /// (issue #489).
    provider_dialer: Option<String>,
    /// `override.dialer-proxy` (mihomo `OverrideSchema`) — applied to
    /// every node unconditionally; the strongest of the three levels
    /// (override > provider > node) (issue #489).
    override_dialer: Option<String>,
    /// The rest of mihomo's `override:` block: provider-level node
    /// defaults plus the name affixes, written into every member's mapping
    /// after filtering and before parsing (`OverrideSchema.Apply`).
    node_override: NodeOverride,
    /// Serializes `refresh` so `slot`, `declared_dialers`, and `derived`
    /// can never be populated from different payload generations — the
    /// provider-refresh API endpoint is not serialized by the config
    /// mutation lane (issue #489 review).
    refresh_lock: tokio::sync::Mutex<()>,
    /// Group-level filtered views of `slot` (issue #358), re-populated on
    /// every refresh. Weak: each view is kept alive by the group built from
    /// it, so views belonging to dropped or rebuilt groups get pruned here.
    derived: RwLock<Vec<(GroupFilter, WeakSlot)>>,
    /// The declaration this provider was built from (plus the effective
    /// `ipv6` it was parsed under — not part of `def`), normalized by
    /// [`Self::def_identity`]. Runtime rebuilds reuse a live provider only
    /// when the candidate def matches; a changed `url`/`path`/`filter`/
    /// `health-check`/`allow-external-plugin` must produce a fresh
    /// provider, not silently keep fetching the old one (issue #533
    /// review).
    def: RawProxyProvider,
    /// Hash of the last committed payload plus the `strict` flag it was
    /// parsed under — upstream's `loadBuf` hash dedup: a byte-identical
    /// refresh skips parse + commit entirely, so `updated_at` tracks the
    /// last real content change and an unchanged payload doesn't rebuild
    /// every adapter and derived view each tick. A committed
    /// `strict`-flip still re-parses the same payload under the new
    /// strictness (issue #625 review).
    content_hash: Mutex<Option<(u64, bool)>>,
    /// Bytes of the last committed payload — the content counterpart of
    /// `content_hash`. A `PUT /configs` that changes only
    /// `global-client-fingerprint` rebuilds this provider (the adapters
    /// bake the profile at parse), and the rebuilt object re-parses these
    /// bytes under the new fingerprint instead of serving an empty slot
    /// until a fetch lands — with no usable on-disk cache (a
    /// `--config-string` run, or a cache the payload deadline never
    /// wrote) that gap would make provider-backed selectors answer "no
    /// proxy selected" (issue #974 review).
    last_payload: Mutex<Option<String>>,
    /// Plan usage reported with the payload this provider serves: the
    /// `subscription-userinfo` header of the last fetch it accepted (`None`
    /// when that fetch carried none), or, for a payload loaded from the
    /// on-disk cache, the usage persisted next to it. Kept from the last
    /// accepted fetch across failed ones, like the payload itself.
    subscription_userinfo: Mutex<Option<SubscriptionUserinfo>>,
}

/// Weak counterpart of [`ProviderSlot`].
type WeakSlot = std::sync::Weak<RwLock<Vec<Arc<dyn Proxy>>>>;

/// Compiled group-level member filter (issue #358): the `filter`,
/// `exclude-filter`, and `exclude-type` fields declared on a proxy-group
/// apply to the proxies that group pulls from providers (`use:` /
/// `include-all`), mirroring mihomo. Static `proxies:` members bypass the
/// filter, also matching upstream (compatible providers are not filtered).
#[derive(Clone, Debug)]
pub struct GroupFilter {
    filter: Option<fancy_regex::Regex>,
    exclude_filter: Option<fancy_regex::Regex>,
    exclude_type: Vec<String>,
}

impl GroupFilter {
    /// Compile the filter fields of a raw proxy-group. Returns `Ok(None)`
    /// when the group declares no filtering at all.
    pub fn from_raw_group(raw: &crate::raw::RawProxyGroup) -> Result<Option<Self>, String> {
        let filter = compile_opt_regex(&raw.filter, "filter")?;
        let exclude_filter = compile_opt_regex(&raw.exclude_filter, "exclude-filter")?;
        let exclude_type = split_exclude_types(raw.exclude_type.as_deref());
        if filter.is_none() && exclude_filter.is_none() && exclude_type.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            filter,
            exclude_filter,
            exclude_type,
        }))
    }

    fn keep(&self, proxy: &dyn Proxy) -> bool {
        let name = proxy.name();
        if let Some(re) = &self.filter {
            if !regex_matches(re, name) {
                return false;
            }
        }
        if let Some(re) = &self.exclude_filter {
            if regex_matches(re, name) {
                return false;
            }
        }
        !self
            .exclude_type
            .iter()
            .any(|t| adapter_type_matches(t, proxy.adapter_type()))
    }
}

/// Match an `exclude-type` token against a parsed adapter's type. Accepts
/// both the adapter display name ("Shadowsocks") and the config-file alias
/// ("ss") so either spelling works, case-insensitively.
fn adapter_type_matches(token: &str, adapter_type: meow_common::AdapterType) -> bool {
    if token.eq_ignore_ascii_case(&adapter_type.to_string()) {
        return true;
    }
    matches!(adapter_type, meow_common::AdapterType::Shadowsocks)
        && token.eq_ignore_ascii_case("ss")
}

/// `exclude-type` accepts a YAML list or a mihomo-style `|`-separated string
/// ("ss|http"); flatten both into lowercase tokens.
fn split_exclude_types(raw: Option<&[String]>) -> Vec<String> {
    raw.unwrap_or(&[])
        .iter()
        .flat_map(|s| s.split('|'))
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

enum Vehicle {
    File(PathBuf),
    Http {
        url: String,
        /// `None` = fetch to memory only (no containment root available for
        /// an on-disk cache; issue #429).
        cache_path: Option<PathBuf>,
    },
}

/// mihomo's `override:` block on a proxy-provider (`OverrideSchema`),
/// minus `dialer-proxy` (that one feeds the dialer chain and lives in
/// [`ProxyProvider::override_dialer`]).
///
/// Upstream applies it in `OverrideSchema.Apply`, which writes each field
/// into the node's mapping unconditionally — a provider-level default that
/// remote payloads cannot escape. The affixes are name rewrites, applied
/// after the map fields and in the same order mihomo uses (prefix, then
/// suffix). `proxy-name` and `override-expr` need upstream's regexp2 and
/// expression evaluator; they warn at build instead of being silently
/// ignored.
#[derive(Default, Debug, Clone)]
struct NodeOverride {
    fields: Vec<(&'static str, serde_json::Value)>,
    prefix: Option<String>,
    suffix: Option<String>,
}

impl NodeOverride {
    /// Fields mihomo writes, with the node-level key each one lands on.
    const BOOL_FIELDS: [(&'static str, &'static str); 4] = [
        ("tfo", "tfo"),
        ("mptcp", "mptcp"),
        ("udp", "udp"),
        ("skip-cert-verify", "skip-cert-verify"),
    ];
    const STRING_FIELDS: [(&'static str, &'static str); 5] = [
        ("up", "up"),
        ("down", "down"),
        ("name-cert-verify", "name-cert-verify"),
        ("interface-name", "interface-name"),
        ("ip-version", "ip-version"),
    ];

    /// Parse the block. Unknown keys, and the two constructs that need
    /// machinery meow does not carry, warn; a wrongly-typed value is a
    /// build error (upstream's YAML unmarshal rejects it too).
    fn from_raw(provider: &str, raw: &HashMap<String, serde_json::Value>) -> Result<Self, String> {
        let mut out = Self::default();
        for (key, value) in raw {
            match key.as_str() {
                // Handled by the caller (dialer chain).
                "dialer-proxy" => {}
                "additional-prefix" => {
                    out.prefix = Some(expect_string(provider, key, value)?.to_string());
                }
                "additional-suffix" => {
                    out.suffix = Some(expect_string(provider, key, value)?.to_string());
                }
                "routing-mark" => {
                    let mark = value.as_i64().ok_or_else(|| {
                        format!(
                            "proxy-provider '{provider}': override.routing-mark must be an integer"
                        )
                    })?;
                    out.fields
                        .push(("routing-mark", serde_json::Value::from(mark)));
                }
                "udp-over-tcp" | "proxy-name" | "override-expr" => {
                    warn!(
                        provider = %provider,
                        "proxy-provider override key '{key}' is not supported"
                    );
                }
                other => {
                    if let Some((_, target)) = Self::BOOL_FIELDS
                        .iter()
                        .find(|(source, _)| *source == other)
                    {
                        let flag = value.as_bool().ok_or_else(|| {
                            format!(
                                "proxy-provider '{provider}': override.{other} must be a boolean"
                            )
                        })?;
                        out.fields.push((target, serde_json::Value::Bool(flag)));
                    } else if let Some((_, target)) = Self::STRING_FIELDS
                        .iter()
                        .find(|(source, _)| *source == other)
                    {
                        let text = expect_string(provider, other, value)?;
                        out.fields
                            .push((target, serde_json::Value::String(text.to_string())));
                    } else {
                        warn!(
                            provider = %provider,
                            "proxy-provider override key '{other}' is not supported"
                        );
                    }
                }
            }
        }
        Ok(out)
    }

    fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.prefix.is_none() && self.suffix.is_none()
    }

    /// Write the defaults into `map` and rewrite its name. Returns the
    /// effective node name.
    fn apply(&self, map: &mut HashMap<String, serde_json::Value>) -> String {
        for (key, value) in &self.fields {
            map.insert((*key).to_string(), value.clone());
        }
        let mut name = map
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        if let Some(prefix) = &self.prefix {
            name = format!("{prefix}{name}");
        }
        if let Some(suffix) = &self.suffix {
            name = format!("{name}{suffix}");
        }
        map.insert("name".to_string(), serde_json::Value::String(name.clone()));
        name
    }
}

fn expect_string<'a>(
    provider: &str,
    key: &str,
    value: &'a serde_json::Value,
) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("proxy-provider '{provider}': override.{key} must be a string"))
}

impl ProxyProvider {
    pub fn new(
        name: &str,
        raw: &RawProxyProvider,
        cache_dir: Option<&Path>,
        ipv6: bool,
        strict: bool,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
    ) -> Result<Self, String> {
        Self::new_with_client_fingerprint(
            name,
            raw,
            cache_dir,
            ipv6,
            strict,
            dialer_registry,
            None,
            None,
        )
    }

    /// [`ProxyProvider::new`] under the config's top-level
    /// `global-client-fingerprint` (issue #974): provider nodes that omit
    /// `client-fingerprint` inherit it at parse time. `dns_cell` is the
    /// config's live-resolver indirection `type: dns` nodes bind —
    /// `None` leaves them unbound (SERVFAIL) for callers that have none.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is an independent provider-build input; bundling \
                  them would only rename the same list"
    )]
    pub fn new_with_client_fingerprint(
        name: &str,
        raw: &RawProxyProvider,
        cache_dir: Option<&Path>,
        ipv6: bool,
        strict: bool,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
        global_client_fingerprint: Option<&str>,
        dns_cell: Option<meow_dns::DnsOutboundCell>,
    ) -> Result<Self, String> {
        // Any on-disk location (read or write) must stay inside `cache_dir`
        // (issue #429): `path:` — and the provider *name* feeding the implicit
        // cache location — are attacker-influenced when the config document
        // does not come from a trusted on-disk file. Without a `cache_dir`
        // there is no containment root, so no caller-named path is honoured.
        let (vehicle, vehicle_type) = match raw.provider_type.as_str() {
            "file" => {
                let path_str = raw
                    .path
                    .as_deref()
                    .ok_or("file proxy-provider requires 'path'")?;
                let Some(dir) = cache_dir else {
                    return Err(format!(
                        "proxy-provider '{name}': 'path' cannot be used without a provider \
                         cache directory"
                    ));
                };
                let path = crate::safe_path::resolve_contained(dir, Path::new(path_str))
                    .map_err(|e| format!("proxy-provider '{name}': {e}"))?;
                (Vehicle::File(path), "File")
            }
            "http" => {
                let url = raw
                    .url
                    .as_deref()
                    .ok_or("http proxy-provider requires 'url'")?
                    .to_string();
                // An unparseable `url:` is a permanent defect, not a
                // transient fetch failure — under strict surface it at
                // load instead of registering an empty provider that
                // retries forever (issue #533 review).
                if strict && url::Url::parse(&url).is_err() {
                    return Err(format!(
                        "proxy-provider '{name}': invalid url '{url}' (strict mode)"
                    ));
                }
                let cache_path = match (raw.path.as_deref(), cache_dir) {
                    (Some(p), Some(dir)) => Some(
                        crate::safe_path::resolve_contained(dir, Path::new(p))
                            .map_err(|e| format!("proxy-provider '{name}': {e}"))?,
                    ),
                    (Some(_), None) => {
                        warn!(
                            provider = %name,
                            "ignoring 'path' (no provider cache directory in this context); \
                             fetching to memory without an on-disk cache"
                        );
                        None
                    }
                    (None, Some(dir)) => Some(
                        crate::safe_path::resolve_contained(
                            dir,
                            Path::new(&format!("provider_{name}.yaml")),
                        )
                        .map_err(|e| format!("proxy-provider '{name}': {e}"))?,
                    ),
                    (None, None) => None,
                };
                (Vehicle::Http { url, cache_path }, "HTTP")
            }
            t => return Err(format!("unknown proxy-provider type '{t}'")),
        };

        let filter = compile_opt_regex(&raw.filter, "filter")?;
        let exclude_filter = compile_opt_regex(&raw.exclude_filter, "exclude-filter")?;
        let exclude_type = split_exclude_types(raw.exclude_type.as_deref());

        // Probed every `interval` by `ProxyProviderRefreshSupervisor`.
        let health_check = build_health_check_config(name, raw.health_check.as_ref())
            .map_err(|e| format!("proxy-provider '{name}': health-check {e}"))?;
        let header = raw
            .header
            .as_ref()
            .map(crate::raw::flatten_header_map)
            .unwrap_or_default();

        // `proxy:` routes this provider's fetches through a named proxy or
        // group, resolved against `dialer_registry` at fetch time so the
        // binding follows every republished route map (issue #625). Absent,
        // empty, or `DIRECT` fetches direct; whitespace-only is not a usable
        // name — reject rather than silently fetch direct (same posture as
        // `dialer-proxy` below). On a `file` provider there is no fetch to
        // chain — the field is a mistaken expectation there.
        let download_proxy = match raw.proxy.as_deref() {
            Some(s) if !s.trim().is_empty() => {
                let name = s.trim();
                if name.eq_ignore_ascii_case("DIRECT") {
                    None
                } else {
                    Some(smol_str::SmolStr::from(name))
                }
            }
            // `""` = unset (upstream's `len > 0` check); `None` = absent.
            Some("") | None => None,
            Some(_) => {
                return Err(format!(
                    "proxy-provider '{name}': malformed proxy — \
                     expected a proxy/group name"
                ));
            }
        };
        if download_proxy.is_some() && raw.provider_type == "file" {
            warn!(
                provider = %name,
                "proxy-provider 'proxy' has no effect on a 'file' provider — \
                 there is no fetch to chain"
            );
        }

        // mihomo `dialer-proxy:` — chain every node through the named front
        // hop. Upstream applies it unconditionally (overriding node-level
        // fields). `""` = unset (upstream's `len > 0` check); whitespace-only
        // is not a usable name — reject rather than silently dial direct.
        let provider_dialer = match raw.dialer_proxy.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            // `""` = unset (upstream's `len > 0` check); `None` = absent.
            Some("") | None => None,
            Some(_) => {
                return Err(format!(
                    "proxy-provider '{name}': malformed dialer-proxy — \
                     expected a proxy/group name"
                ));
            }
        };

        // mihomo `override:` — provider-level node defaults. `dialer-proxy`
        // feeds the dialer chain below; the scalar fields and the name
        // affixes are collected into `node_override` and written into each
        // node's mapping at parse time (`OverrideSchema.Apply`).
        // `override.Apply` writes unconditionally — it outranks both the
        // provider-level field and node-level `dialer-proxy`.
        let mut override_dialer = None;
        let mut node_override = NodeOverride::default();
        if let Some(over) = raw.override_.as_ref() {
            node_override = NodeOverride::from_raw(name, over)?;
            match over.get("dialer-proxy") {
                // `""` is the upstream "clear the chain" knob:
                // `OverrideSchema.Apply` writes the string unconditionally,
                // so an empty override strips node- and provider-level
                // `dialer-proxy` and the node dials direct.
                Some(serde_json::Value::String(s)) if s.is_empty() => {
                    override_dialer = Some(String::new());
                }
                Some(serde_json::Value::String(s)) if !s.trim().is_empty() => {
                    override_dialer = Some(s.trim().to_string());
                }
                // `null` unmarshals to a nil `*string` upstream — no write
                // happens, so the provider/node levels still apply.
                Some(serde_json::Value::Null) | None => {}
                // A malformed override must not silently drop the operator's
                // enforced chain — fail the provider build. Whitespace-only
                // lands here too: almost surely a typo rather than a
                // deliberate clear, same treatment as the other two levels.
                Some(_) => {
                    return Err(format!(
                        "proxy-provider '{name}': malformed override.dialer-proxy — \
                         expected a proxy/group name"
                    ));
                }
            }
        }

        Ok(Self {
            name: name.to_string(),
            slot: Arc::new(RwLock::new(Vec::new())),
            vehicle_type,
            vehicle,
            filter,
            exclude_filter,
            exclude_type,
            health_check,
            updated_at: AtomicU::new(0),
            header,
            ipv6,
            allow_external_plugin: raw.allow_external_plugin.unwrap_or(false),
            strict: AtomicBool::new(strict),
            global_client_fingerprint: crate::proxy_parser::normalize_client_fingerprint(
                global_client_fingerprint,
            ),
            dialer_registry,
            download_proxy,
            dns_cell: dns_cell.unwrap_or_else(meow_dns::new_dns_outbound_cell),
            deferred_initial: AtomicBool::new(false),
            background_pending: AtomicBool::new(false),
            fetched_remote: AtomicBool::new(false),
            members_changed: tokio::sync::Notify::new(),
            ech_pending: AtomicBool::new(false),
            declared_dialers: RwLock::new(Vec::new()),
            provider_dialer,
            override_dialer,
            node_override,
            refresh_lock: tokio::sync::Mutex::new(()),
            derived: RwLock::new(Vec::new()),
            def: Self::def_identity(raw),
            content_hash: Mutex::new(None), // see field docs
            last_payload: Mutex::new(None), // see field docs
            subscription_userinfo: Mutex::new(None),
        })
    }

    /// The fields of a declaration that determine provider identity.
    /// `interval` is excluded: it configures the refresh *schedule*, not
    /// the payload source — the supervisor consumes the committed
    /// declarations directly
    /// ([`crate::proxy_provider_refresh::ProxyProviderRefreshSupervisor`]),
    /// so an interval-only change respawns the task without rebuilding the
    /// provider or refetching its payload (issue #625).
    fn def_identity(raw: &RawProxyProvider) -> RawProxyProvider {
        RawProxyProvider {
            interval: None,
            ..raw.clone()
        }
    }

    /// Update the strict flag after a committed config rebuild — providers
    /// reused across a `PUT /configs` must follow the new generation's
    /// strictness (issue #533 review).
    pub fn set_strict(&self, strict: bool) {
        self.strict.store(strict, Ordering::Relaxed);
    }

    /// `true` when this provider was built from `def` under the same
    /// effective `ipv6` and `global-client-fingerprint` — the identity
    /// check `use:`/`include-all` rebuilds apply before deciding to reuse
    /// the live object. A changed declaration rebuilds the provider
    /// instead of silently fetching the old source forever (issue #533
    /// review); a changed global fingerprint rebuilds it because the
    /// adapters it parses bake that profile in (issue #974).
    pub fn matches_def(
        &self,
        def: &RawProxyProvider,
        ipv6: bool,
        global_client_fingerprint: Option<&str>,
    ) -> bool {
        self.ipv6 == ipv6
            && self.global_client_fingerprint.as_deref()
                == crate::proxy_parser::normalize_client_fingerprint(global_client_fingerprint)
                    .as_deref()
            && self.def == Self::def_identity(def)
    }

    /// [`matches_def`](Self::matches_def) minus the
    /// `global-client-fingerprint` leg — `true` on a candidate whose
    /// `matches_def` differs *only* in the fingerprint the adapters were
    /// parsed under. That rebuild inherits the predecessor's last
    /// committed payload (`retained_payload`) instead of serving
    /// an empty slot until the post-commit fetch lands (issue #974
    /// review).
    pub fn matches_def_modulo_fingerprint(&self, def: &RawProxyProvider, ipv6: bool) -> bool {
        self.ipv6 == ipv6 && self.def == Self::def_identity(def)
    }

    /// Bytes of the last committed payload — `None` until one parses
    /// ([`Self::last_payload`]). A fingerprint-only rebuild hands them to
    /// [`ProxyProvider::adopt_transferred_payload`] on the fresh provider.
    pub(crate) fn retained_payload(&self) -> Option<String> {
        self.last_payload.lock().clone()
    }

    /// Create a live filtered view of this provider's proxies for one group
    /// (issue #358). The view is seeded from the current slot contents and
    /// re-populated on every [`refresh`](Self::refresh).
    pub fn derived_slot(&self, filter: &GroupFilter) -> ProviderSlot {
        let seeded: Vec<Arc<dyn Proxy>> = self
            .slot
            .read()
            .iter()
            .filter(|p| filter.keep(p.as_ref()))
            .map(Arc::clone)
            .collect();
        let slot: ProviderSlot = Arc::new(RwLock::new(seeded));
        self.derived
            .write()
            .push((filter.clone(), Arc::downgrade(&slot)));
        slot
    }

    fn update_derived(&self, proxies: &[Arc<dyn Proxy>]) {
        let mut derived = self.derived.write();
        derived.retain(|(filter, weak)| {
            let Some(slot) = weak.upgrade() else {
                return false;
            };
            *slot.write() = proxies
                .iter()
                .filter(|p| filter.keep(p.as_ref()))
                .map(Arc::clone)
                .collect();
            true
        });
    }

    /// Drop derived slots whose owning group is gone. Candidate builds
    /// register views on *live* reused providers before validation finishes,
    /// so a failed build leaves dead `Weak`s behind — pruning at commit
    /// keeps that bounded instead of waiting for the next refresh
    /// (issue #533 review).
    pub fn prune_dead_derived(&self) {
        self.derived
            .write()
            .retain(|(_, weak)| weak.upgrade().is_some());
    }

    /// Fetch the payload from its source — file read or HTTP GET. No
    /// on-disk cache write and no fallback: the cache is persisted only
    /// for content that *parses* ([`Self::ingest`]), matching upstream's
    /// `loadBuf` order (`vehicle.Write` runs after `parser` succeeds), so
    /// a 200-OK garbage body can't durably poison the fallback cache.
    ///
    /// An HTTP fetch also returns the plan usage the response reported in
    /// its `subscription-userinfo` header.
    async fn fetch_source(&self) -> Result<(String, Option<SubscriptionUserinfo>), String> {
        let registry = &self.dialer_registry;
        match &self.vehicle {
            Vehicle::File(path) => tokio::fs::read_to_string(path)
                .await
                .map(|text| (text, None))
                .map_err(|e| {
                    format!(
                        "proxy-provider '{}': failed to read {:?}: {}",
                        self.name, path, e
                    )
                }),
            Vehicle::Http { url, .. } => {
                let download_proxy = match crate::internal_http::resolve_download_proxy(
                    registry,
                    self.download_proxy.as_deref(),
                ) {
                    Ok(p) => {
                        self.deferred_initial.store(false, Ordering::Relaxed);
                        p
                    }
                    Err(e) => {
                        // The startup load fetches before the first route
                        // map is published — flag the deferred post-publish
                        // retry (issue #625). Afterwards an unresolvable
                        // name means a rebuild removed the proxy: fail the
                        // fetch rather than leak a direct request past a
                        // chain the config declared.
                        self.deferred_initial.store(true, Ordering::Relaxed);
                        return Err(format!("proxy-provider '{}': {e:#}", self.name));
                    }
                };
                let response = crate::internal_http::fetch_response(
                    url,
                    download_proxy.as_ref(),
                    &self.header,
                )
                .await
                .map_err(|e| e.to_string())?;
                let userinfo = response
                    .header(subscription_userinfo::HEADER)
                    .and_then(SubscriptionUserinfo::parse);
                let text = String::from_utf8(response.body)
                    .map_err(|e| format!("response body is not UTF-8: {e}"))?;
                Ok((text, userinfo))
            }
        }
    }

    /// Initial-load acquisition: [`Self::fetch_source`] with an on-disk
    /// cache fallback for HTTP providers — the offline bootstrap path.
    /// The returned [`Source`] says whether the payload came from the cache
    /// (no point rewriting it). Deliberately NOT used by refresh ticks:
    /// a failed refresh keeps the in-memory last-good set (upstream
    /// `Update` semantics) instead of rewinding the slot to whatever
    /// generation the disk happens to hold.
    ///
    /// `record_failure` suppresses the logbook write for a candidate that
    /// may still be rejected (see [`Self::initial_load_blocking`]) — the
    /// rejection itself is already reported, and the provider might never
    /// be committed under this name.
    async fn fetch_content(&self, record_failure: bool) -> Result<(String, Source), String> {
        let e = match self.fetch_source().await {
            Ok((text, userinfo)) => return Ok((text, Source::Fetched(userinfo))),
            Err(e) => e,
        };
        // Before the first route map is published a `proxy:` name cannot
        // resolve yet; that fetch is retried, not failed.
        if record_failure && !self.deferred_initial.load(Ordering::Relaxed) {
            self.logbook_failed(&e);
        }
        match &self.vehicle {
            Vehicle::Http { cache_path, .. } => {
                warn!(provider = %self.name, error = %e, "HTTP provider fetch failed, trying cache");
                read_cache(cache_path.as_deref(), &self.name)
                    .await
                    .map(|text| (text, Source::Cache))
            }
            Vehicle::File(_) => Err(e),
        }
    }

    /// Persist an accepted HTTP payload atomically for offline fallback.
    async fn write_cache(&self, text: String) {
        if let Vehicle::Http {
            cache_path: Some(cache_path),
            ..
        } = &self.vehicle
        {
            crate::private_file::write_cache(cache_path, text.into_bytes()).await;
        }
    }

    /// The file next to the on-disk cache that keeps the plan usage, so a
    /// restart serving the cache reports it before the first refetch.
    /// `None` without an on-disk cache.
    fn userinfo_path(&self) -> Option<PathBuf> {
        let Vehicle::Http {
            cache_path: Some(cache_path),
            ..
        } = &self.vehicle
        else {
            return None;
        };
        let mut name = cache_path.as_os_str().to_os_string();
        name.push(USERINFO_SUFFIX);
        Some(PathBuf::from(name))
    }

    /// Take the plan usage an accepted fetch reported (`None`: it reported
    /// none). `true` when that changed it.
    fn set_userinfo(&self, userinfo: Option<SubscriptionUserinfo>) -> bool {
        std::mem::replace(&mut *self.subscription_userinfo.lock(), userinfo) != userinfo
    }

    /// Keep the file next to the on-disk cache in step with `userinfo`,
    /// removing it when there is none.
    async fn persist_userinfo(&self, userinfo: Option<SubscriptionUserinfo>) {
        let Some(path) = self.userinfo_path() else {
            return;
        };
        match userinfo {
            Some(userinfo) => {
                crate::private_file::write_cache(&path, userinfo.to_string().into_bytes()).await;
            }
            None => {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
    }

    /// Read back the plan usage persisted with the on-disk cache, for a
    /// payload just loaded from it. `None` when nothing was persisted.
    async fn load_cached_userinfo(&self) {
        let Some(path) = self.userinfo_path() else {
            return;
        };
        let userinfo = tokio::fs::read_to_string(&path)
            .await
            .ok()
            .and_then(|text| SubscriptionUserinfo::parse(&text));
        *self.subscription_userinfo.lock() = userinfo;
    }

    /// Shared acquisition tail: dedup → parse → persist cache → commit.
    /// `Ok(false)` when the payload is byte-identical to the last commit
    /// (upstream's hash early-return — `updated_at` only advances on real
    /// content changes). `source` distinguishes a live fetch from an
    /// on-disk cache read — cache content is never written back. A fetch
    /// the provider accepts, changed or not, also sets the plan usage.
    ///
    /// `ech` selects the parse's ECH treatment; a commit made under
    /// [`EchResolution::Defer`] left the DNS preresolve unrun, so
    /// identical bytes do not dedup until the off-lane pass re-parses
    /// them (`ech_pending` below). `record` gates the logbook success
    /// entry the same way it gates [`Self::logbook_failed`] on the
    /// callers' failure paths: a not-yet-committed candidate load
    /// ([`Self::initial_load_unrecorded`]) must not write an "Updated"
    /// entry — the verdict belongs to the rebuild's return value.
    async fn ingest(
        &self,
        content: String,
        source: Source,
        ech: EchResolution,
        record: bool,
    ) -> Result<bool, anyhow::Error> {
        let strict = self.strict.load(Ordering::Relaxed);
        let hash = content_hash(&content);
        let from_remote = matches!(source, Source::Fetched(_));
        // `ech_pending` is read, not consumed: a still-owed resolve bypasses
        // the dedup so the bytes re-parse under `Resolve`, and the flag is
        // only cleared by a *successful* re-parse below. Clearing it on the
        // way in would abandon the deferral whenever that re-parse fails —
        // every later identical fetch would then dedup and the deferred
        // lookup would never land.
        if *self.content_hash.lock() == Some((hash, strict))
            && !self.ech_pending.load(Ordering::Relaxed)
        {
            if let Source::Fetched(userinfo) = source {
                self.fetched_remote.store(true, Ordering::Relaxed);
                // The usage moves on most fetches, the payload on few.
                if self.set_userinfo(userinfo) {
                    self.persist_userinfo(userinfo).await;
                }
                if record {
                    self.logbook_updated(Payload::Unchanged);
                }
            }
            return Ok(false);
        }
        let (proxies, ech_resolved) = self.parse_proxies(&content, ech).await?;
        match source {
            Source::Fetched(userinfo) => {
                self.write_cache(content.clone()).await;
                // Rewritten with the cache whether it changed or not, so
                // the two on disk always come from the same fetch.
                self.set_userinfo(userinfo);
                self.persist_userinfo(userinfo).await;
            }
            Source::Cache => self.load_cached_userinfo().await,
        }
        let payload = if self.has_content() {
            Payload::Replaced(self.slot.read().len())
        } else {
            Payload::First
        };
        self.commit(proxies);
        *self.content_hash.lock() = Some((hash, strict));
        // Committed bytes are retained for a fingerprint-only rebuild to
        // re-parse — the content counterpart of the hash above.
        *self.last_payload.lock() = Some(content);
        self.ech_pending.store(!ech_resolved, Ordering::Relaxed);
        if from_remote {
            // Not "fetched" while the preresolve is still owed — the
            // detached post-commit fetch runs it before the initial
            // retry loop may retire.
            if ech_resolved {
                self.fetched_remote.store(true, Ordering::Relaxed);
            }
            if record {
                self.logbook_updated(payload);
            }
        }
        Ok(true)
    }

    /// Logbook: a fetch from the source parsed. Recorded when it replaced a
    /// payload or ends a failure the logbook shows: a first load belongs to
    /// the start or config change that declared the provider, and an
    /// unchanged refetch is routine.
    fn logbook_updated(&self, payload: Payload) {
        let name = &self.name;
        let recovered = || logbook::failing(logbook::kind::PROXY_PROVIDER_UPDATE, name);
        let count = self.slot.read().len();
        let message = match payload {
            Payload::Replaced(previous) => {
                format!("Updated proxy provider '{name}': {count} proxies (was {previous})")
            }
            Payload::First if recovered() => {
                format!("Updated proxy provider '{name}': {count} proxies")
            }
            Payload::Unchanged if recovered() => {
                format!("Updated proxy provider '{name}': {count} proxies, unchanged")
            }
            Payload::First | Payload::Unchanged => return,
        };
        logbook::event(logbook::kind::PROXY_PROVIDER_UPDATE, Level::Info, message)
            .subject(name.as_str())
            .field("proxies", count)
            .record();
    }

    /// Logbook: fetching or parsing the payload failed. Repeats fold while
    /// the provider keeps failing.
    fn logbook_failed(&self, error: &str) {
        record_failure(&self.name, error);
    }

    /// Whether any payload generation has been committed — from the remote
    /// or from the on-disk cache.
    fn has_content(&self) -> bool {
        self.content_hash.lock().is_some()
    }

    /// Cache-first load into an empty provider: commit the on-disk copy of
    /// an HTTP payload without touching the network, the way mihomo's
    /// fetcher reads its local file before anything else. `false` when there
    /// is no cache, it cannot be read, it no longer parses, or the provider
    /// already holds a payload — the caller then fetches.
    ///
    /// The cached set is served at once and revalidated in the background
    /// ([`Self::spawn_initial_fetch`]), so a restart neither waits on the
    /// feed nor keeps a stale generation past that first refetch.
    async fn load_from_cache(&self) -> bool {
        let Vehicle::Http {
            cache_path: Some(path),
            ..
        } = &self.vehicle
        else {
            return false;
        };
        let _generation = self.refresh_lock.lock().await;
        if self.has_content() {
            return false;
        }
        let content = match tokio::fs::read_to_string(path).await {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(e) => {
                warn!(provider = %self.name, path = ?path, error = %e, "ignoring unreadable provider cache");
                return false;
            }
        };
        if let Err(e) = self
            .ingest(content, Source::Cache, EchResolution::Resolve, true)
            .await
        {
            warn!(provider = %self.name, path = ?path, error = %e, "ignoring unparseable provider cache");
            return false;
        }
        // Report the cache's age, not the load time (upstream sets
        // `UpdatedAt` to the file's mtime too).
        if let Ok(mtime) = tokio::fs::metadata(path).await.and_then(|m| m.modified()) {
            if let Ok(age) = mtime.duration_since(UNIX_EPOCH) {
                self.updated_at.store(
                    age.as_secs() as meow_common::atomic::Uint,
                    Ordering::Relaxed,
                );
            }
        }
        info!(provider = %self.name, "proxy-provider loaded from cache; refetching in the background");
        true
    }

    /// `true` when this provider reads its payload from a local `file:` —
    /// the only vehicle whose payload is operator-authored, and the only
    /// one the synchronous materialize path can validate before commit.
    pub(crate) fn is_file_vehicle(&self) -> bool {
        matches!(self.vehicle, Vehicle::File(_))
    }

    /// The startup fetch for a provider without a usable cache. `Err` only
    /// for a strict-mode rejection of a *local* (`file:`) payload, which
    /// fails the config load; `Ok(false)` when nothing could be acquired
    /// (already logged).
    ///
    /// Strict gates the *parse*, and its consequence is gated by the
    /// payload's origin: a `file:` payload is operator-authored local
    /// content, so a strict parse defect stays fail-closed. Remote bytes —
    /// an HTTP response or the on-disk cache it left behind — are a
    /// third-party feed the operator cannot fix by editing the config, so
    /// a strict parse defect there degrades to the acquisition shape
    /// (`Ok(false)`: registered empty, retried in the background) instead
    /// of handing the feed's operator a daemon-wide kill switch. The
    /// verdict therefore no longer depends on whether the fetch landed
    /// before or after the provider deadline.
    ///
    /// A transient download/read failure is likewise not a payload defect:
    /// the provider starts empty until a background retry, a scheduled
    /// tick or a manual refresh succeeds. Lenient keeps the payload's
    /// usable nodes and binds the rest to unavailable placeholders, so
    /// only a defect that stops the *whole* payload from parsing fails it.
    async fn initial_load(&self, strict: bool) -> anyhow::Result<bool> {
        self.initial_load_impl(strict, true, EchResolution::Resolve)
            .await
    }

    /// [`initial_load`] minus the logbook record — for a candidate that
    /// may still be rejected (`PUT /configs`'s 400 already lands in
    /// `CONFIG_RELOAD` via `reload_rejected`), where the verdict must be
    /// carried by the return value alone: no failure entry, and no
    /// "Updated" success entry for a provider that was never committed.
    /// Minus the ECH DNS preresolve too: the caller holds the
    /// config-mutation lane, so the parse runs [`EchResolution::Defer`] —
    /// the same strict verdict, no network I/O — and a committed
    /// provider's detached first fetch owes the deferred pass (see
    /// [`ProxyProvider::ech_pending`]).
    async fn initial_load_unrecorded(&self, strict: bool) -> anyhow::Result<bool> {
        self.initial_load_impl(strict, false, EchResolution::Defer)
            .await
    }

    async fn initial_load_impl(
        &self,
        strict: bool,
        record: bool,
        ech: EchResolution,
    ) -> anyhow::Result<bool> {
        let _generation = self.refresh_lock.lock().await;
        let (content, source) = match self.fetch_content(record).await {
            Ok(fetched) => fetched,
            Err(e) => {
                warn_initial_load_failure(self, &e);
                return Ok(false);
            }
        };
        match self.ingest(content, source, ech, record).await {
            Ok(_) => Ok(true),
            Err(e) => {
                if record {
                    self.logbook_failed(&e.to_string());
                }
                // `file:` payloads are operator-authored: strict stays
                // fail-closed on them. Remote bytes degrade to the
                // acquisition shape — the feed's owner cannot veto this
                // daemon's config by serving malformed content.
                if strict && self.is_file_vehicle() {
                    return Err(anyhow::anyhow!("proxy-provider '{}': {e}", self.name));
                }
                warn_initial_load_failure(self, &e.to_string());
                Ok(false)
            }
        }
    }

    /// [`initial_load`] for a synchronous caller — the
    /// candidate-materialize path, which runs inside
    /// `rebuild_from_raw_impl` on a `spawn_blocking` worker (and on plain
    /// threads in tests). Runs the load on a short-lived thread with a
    /// `current_thread` runtime — the same shape as
    /// [`crate::rule_provider::fetch_http_blocking`] — so it works whether
    /// or not the caller already sits inside a Tokio runtime.
    ///
    /// Only ever called on [`Vehicle::File`] providers: remote payloads
    /// keep their detached-fetch contract and never block the caller —
    /// asserted below so a future caller on an `http:` vehicle cannot
    /// reintroduce a lane-blocking `fetch_response` by mistake. The
    /// load stays network-free — `fetch_source` reads only the file and
    /// the parse runs [`EchResolution::Defer`], so no ECH DNS lookup can
    /// serialize the mutation lane; a committed provider's detached
    /// `spawn_initial_fetch` re-parses under the full preresolve, leaving
    /// the nodes it serves identical to a boot load.
    ///
    /// Two failure-shape notes: the file read is deliberately unbounded —
    /// boot reads the same path inline, so a size cap here would only
    /// fork the verdicts (operator-controlled local content, same
    /// exposure class as the config file itself). And a panic inside the
    /// load surfaces as `Err` via the join below, rejecting the candidate
    /// — where the same panic in a detached fetch task used to end only
    /// that task, here it fails the PUT loudly, which is the safer
    /// direction for a parse bug.
    pub(crate) fn initial_load_blocking(&self, strict: bool) -> anyhow::Result<bool> {
        debug_assert!(
            self.is_file_vehicle(),
            "initial_load_blocking is the file-vehicle gate; on a remote vehicle it \
             would run a real network fetch on the caller's lane"
        );
        let name = self.name.clone();
        // The scoped thread sees no caller context — carry the scoped
        // dispatcher so warns inside the load reach the subscriber in
        // effect here (same propagation
        // `spawn_blocking_with_current_dispatcher` applies).
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        std::thread::scope(|s| {
            s.spawn(|| {
                tracing::dispatcher::with_default(&dispatch, || {
                    use anyhow::Context as _;
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .context("building temporary tokio runtime for proxy-provider load")?;
                    rt.block_on(self.initial_load_unrecorded(strict))
                })
            })
            .join()
            .map_err(|payload| {
                anyhow::anyhow!(
                    "proxy-provider '{name}' load thread panicked: {}",
                    crate::rule_provider::panic_message(payload.as_ref())
                )
            })?
        })
    }

    /// [`initial_load_unrecorded`](Self::initial_load_unrecorded) minus the
    /// acquisition: re-parse `content` — the payload a
    /// fingerprint-only-rebuild predecessor last committed
    /// (`retained_payload`) — into this fresh provider under its
    /// own `global-client-fingerprint`, so a `--config-string`/no-cache
    /// rebuild serves the inherited nodes until the detached post-commit
    /// fetch lands instead of an empty slot (issue #974 review).
    ///
    /// `Source::Cache` keeps `ingest` honest about the bytes' origin:
    /// they were inherited, not fetched — nothing is written back, the
    /// persisted plan usage stays whatever the predecessor committed, and
    /// `fetched_remote` stays clear so the commit's `spawn_initial_fetch`
    /// still revalidates against the live source (finishing the ECH
    /// preresolve [`EchResolution::Defer`] owes, like the `file:` load).
    ///
    /// Returns `Err` on a parse defect — remote bytes degrade rather than
    /// reject (the `initial_load` origin split), so the caller warns and
    /// leaves the provider to the commit's detached fetch. Runs on a
    /// scoped thread + `current_thread` runtime for the same reason
    /// [`Self::initial_load_blocking`] does.
    pub(crate) fn adopt_transferred_payload(&self, content: String) -> anyhow::Result<()> {
        let name = self.name.clone();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        std::thread::scope(|s| {
            s.spawn(|| {
                tracing::dispatcher::with_default(&dispatch, || {
                    use anyhow::Context as _;
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .context("building temporary tokio runtime for proxy-provider load")?;
                    rt.block_on(async {
                        let _generation = self.refresh_lock.lock().await;
                        self.ingest(content, Source::Cache, EchResolution::Defer, false)
                            .await
                            .map(|_| ())
                    })
                })
            })
            .join()
            .map_err(|payload| {
                anyhow::anyhow!(
                    "proxy-provider '{name}' load thread panicked: {}",
                    crate::rule_provider::panic_message(payload.as_ref())
                )
            })?
        })
    }

    /// One attempt of the background fetch — `refresh` semantics: no cache
    /// fallback (the task already served the cache), and a failure keeps
    /// whatever the provider holds. Holds `refresh_lock`, so it queues
    /// behind a straggling startup fetch and sees its outcome rather than
    /// duplicating it.
    async fn background_attempt(&self) -> Result<(), String> {
        let _generation = self.refresh_lock.lock().await;
        if self.fetched_remote.load(Ordering::Relaxed) {
            return Ok(());
        }
        let result = match self.fetch_source().await {
            Ok((content, userinfo)) => self
                .ingest(
                    content,
                    Source::Fetched(userinfo),
                    EchResolution::Resolve,
                    true,
                )
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e),
        };
        if let Err(e) = &result {
            self.logbook_failed(e);
        }
        result
    }

    /// Acquire this provider's remote payload on a detached task: an empty
    /// provider first serves its on-disk cache, then the remote fetch
    /// retries with backoff while it fails — indefinitely (capped at
    /// `BACKGROUND_RETRY_MAX` between attempts) while the provider has
    /// nothing loaded, and up to `MAX_REVALIDATION_ATTEMPTS` times while it
    /// serves a cached set, after which the `interval` loop takes over. Ends
    /// early once any fetch — a tick or a manual refresh included — commits
    /// a remote payload.
    ///
    /// The task holds only a `Weak` between attempts, so a provider dropped
    /// by a config commit — or an embedder shutting down — ends it.
    pub fn spawn_initial_fetch(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(background_fetch_loop(Arc::downgrade(self)))
    }

    /// Parse a fetched provider payload into proxies.
    ///
    /// Document-level defects (malformed YAML, depth limit, merge-key
    /// failure, non-list document) are `Err` in BOTH modes — upstream
    /// `loadBuf` treats a parser failure as a failed update, so the caller
    /// keeps the last-good slot instead of committing an empty one. This
    /// matters now that refreshes are timer-driven: a 200-OK captive-portal
    /// page must not wipe the provider every tick. `strict` still gates
    /// ordinary *per-node* failures. TT transport/policy errors always
    /// reject the payload so a removed TT node cannot select a fallback.
    ///
    /// `declared_dialers` is rewritten only on the success path that will
    /// be committed: an `Err` keeps the last-good slot running, so it must
    /// keep that generation's declarations too (issue #489 review).
    ///
    /// Returns the parsed nodes plus `true` when their ECH configs are
    /// fully resolved — `false` under [`EchResolution::Defer`] when the
    /// payload still owes the DNS lookup the caller may not run.
    async fn parse_proxies(
        &self,
        content: &str,
        ech: EchResolution,
    ) -> Result<(Vec<Arc<dyn Proxy>>, bool), anyhow::Error> {
        let strict = self.strict.load(Ordering::Relaxed);
        if !crate::yaml_within_depth(content) {
            return Err(anyhow::anyhow!(
                "provider YAML exceeds the nesting-depth limit"
            ));
        }
        // `<<:` merge keys expand under `MergeKeyPolicy::Merge` (the
        // shared ingest-options default) — remote payloads legitimately
        // carry anchors, and an unexpanded merge would silently drop the
        // merged `dialer-proxy` into a literal `<<` key (the one field
        // whose loss converts to a silent direct dial). Same treatment as
        // the main config and subscription parsers: a failed merge is a
        // parse failure, so the whole payload is dropped rather than
        // risking nodes losing their chained front hop.
        //
        // A body that is not a proxy list is retried as a share-link list:
        // airports answer a `mihomo` User-Agent with base64-encoded
        // `ss://`/`vmess://`/... links instead of YAML, and mihomo's
        // provider parser has the same fallback (`convert.ConvertsV2Ray`).
        let mut proxy_maps = parse_payload_maps(content)?;

        // Pre-resolve any DNS-sourced ECH configs into inline base64 — keeps
        // `parse_proxy` itself sync. An `ech-opts.enable: true` node with no
        // query source at all is a defect — strict turns it into an error.
        // `Defer` runs the same defect gate but no lookup: the caller holds
        // the config-mutation lane, where a DNS answer can only serialize
        // other commits (issue #533 review). `ech_pending` then owes the
        // deferred pass to the detached post-commit fetch.
        let ech_resolved = match ech {
            EchResolution::Resolve => {
                crate::ech_dns::preresolve_ech(&mut proxy_maps, strict)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e} (strict mode)"))?;
                // `-t` skips the lookups entirely (`preresolve_ech`
                // short-circuits under `is_offline_validate`): report the
                // resolve as still owed rather than claiming one that
                // never ran — harmless under `-t` itself, which exits, and
                // truthful for any provider kept past validation.
                !crate::is_offline_validate() || !crate::ech_dns::needs_ech_dns(&proxy_maps)
            }
            EchResolution::Defer => {
                crate::ech_dns::check_ech_defects(&proxy_maps, strict)
                    .map_err(|e| anyhow::anyhow!("{e} (strict mode)"))?;
                !crate::ech_dns::needs_ech_dns(&proxy_maps)
            }
        };

        let mut declared = Vec::new();
        let mut result = Vec::new();
        for raw_map in &proxy_maps {
            // Get raw name/type before parsing so we can filter cheaply.
            let raw_name = raw_map.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let raw_type = raw_map
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();

            if let Some(ref re) = self.filter {
                if !regex_matches(re, raw_name) {
                    continue;
                }
            }
            if let Some(ref re) = self.exclude_filter {
                if regex_matches(re, raw_name) {
                    continue;
                }
            }
            if self.exclude_type.iter().any(|t| t == &raw_type) {
                continue;
            }

            // mihomo applies `override:` after the name filters and before
            // parsing (`provider.go`: filter, then `OverrideSchema.Apply`,
            // then `ParseProxy`), so a provider that prefixes names is still
            // filtered on the names its feed published.
            let overridden = if self.node_override.is_empty() {
                None
            } else {
                let mut map = raw_map.clone();
                self.node_override.apply(&mut map);
                Some(map)
            };
            let node_map = overridden.as_ref().unwrap_or(raw_map);
            let node_name = node_map
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(raw_name);

            match self.parse_node(node_map, node_name, &mut declared) {
                Ok(proxy) => result.push(proxy),
                Err(e) if strict => {
                    return Err(anyhow::anyhow!(
                        "node '{node_name}' failed to parse (strict mode): {e}"
                    ));
                }
                // Keep the slot entry as a dead placeholder instead of
                // dropping it: a `select` group, an explicit `MATCH` target
                // or a `dialer-proxy` chain that names this node fails the
                // dial rather than shifting the traffic to a sibling member
                // or DIRECT (liveness-checked groups skip it like any
                // unavailable member). Scoped to the node on purpose: this
                // payload is third-party and refetched on a timer, so
                // rejecting the whole feed would let its operator empty the
                // registry on every refresh — and, for a protocol or
                // built-in plugin transport missing from this build, stop
                // the daemon from starting at all.
                Err(e) => {
                    if let Some(declared) = proxy_parser::placeholder_adapter_type(node_map) {
                        let label = if node_name.is_empty() {
                            "<unnamed>"
                        } else {
                            node_name
                        };
                        warn!(provider = %self.name, proxy = label, error = %e, "keeping an unavailable node so nothing can dial past it");
                        result.push(crate::unavailable_placeholder(label, &e, declared));
                    } else {
                        warn!(provider = %self.name, proxy = node_name, error = %e, "failed to parse proxy");
                    }
                }
            }
        }
        *self.declared_dialers.write() = declared;

        Ok((result, ech_resolved))
    }

    /// Publish a freshly parsed node set — shared by `refresh` and the
    /// strict-gated initial load in [`load_proxy_providers`].
    fn commit(&self, proxies: Vec<Arc<dyn Proxy>>) {
        info!(provider = %self.name, count = proxies.len(), "proxy-provider refreshed");
        // Main slot first, then the derived views — readers can never
        // observe new derived contents against a stale main slot.
        *self.slot.write() = proxies;
        self.update_derived(&self.slot.read());
        self.updated_at.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as meow_common::atomic::Uint,
            Ordering::Relaxed,
        );
        // Wake the health-check sweep: upstream probes on `setProxies`,
        // so a committed payload is checked on arrival instead of one
        // full interval later. Probe coverage matches upstream — its
        // `loadBuf` hash-dedups an unchanged payload before `setProxies`
        // (and the attached `hc.check()`) ever runs, the same early
        // return `ingest` takes ahead of this commit.
        self.members_changed.notify_one();
    }

    /// Waitable signalled on every [`commit`](Self::commit) — the
    /// health-check sweep uses it to probe a landed payload without
    /// waiting out the rest of the current interval.
    pub(crate) fn members_changed(&self) -> &tokio::sync::Notify {
        &self.members_changed
    }

    /// Parse one provider node, honouring a declared `dialer-proxy` chain
    /// (issue #489).
    ///
    /// The chain binds *late* — a [`meow_proxy::dialer::NamedProxyDialer`]
    /// holds only the name plus this provider's registry handle and resolves
    /// on every dial, so refresh ordering and forward references to groups
    /// need no special handling here. Targets are top-level `proxies:` /
    /// `proxy-groups:` entries only — provider-sourced node names are not
    /// registry entries (mihomo resolves the same restricted namespace).
    ///
    /// Upstream precedence (`provider.go` then `OverrideSchema.Apply`):
    /// `override.dialer-proxy` > provider-level `dialer-proxy` > node-level —
    /// the stronger levels overwrite unconditionally, so `override` is an
    /// enforcement knob remote nodes cannot escape.
    ///
    /// A node whose adapter type cannot carry an injected dialer
    /// (`direct`, an `ss` node with an external SIP003 plugin) falls back to
    /// the relay-based [`meow_proxy::DialerProxyAdapter`] — the same
    /// treatment the static `proxies:` builder gives its entries,
    /// except that provider payloads keep the fallback under `strict` too:
    /// the remote-declared chain still holds, where erroring would drop
    /// every sibling node with it.
    /// A malformed `dialer-proxy` value or a self-reference rejects the node
    /// outright: warn-skipping just the edge would leave the node dialling
    /// direct, a silent misroute on remote-controlled content (ADR-0002
    /// Class A).
    fn parse_node(
        &self,
        raw_map: &HashMap<String, serde_json::Value>,
        raw_name: &str,
        declared: &mut Vec<String>,
    ) -> Result<Arc<dyn Proxy>, String> {
        // Unknown-node-key warn (issue #974) — once per node load, before
        // any early return, with the provider named for context.
        crate::validation::warn_unknown_node_keys(raw_map, Some(&self.name));
        let direct: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(meow_proxy::dialer::DirectDialer);
        // A `type: dns` node reads no transport fields at all — including
        // `dialer-proxy` in any shape, even malformed. Parse the leaf bare;
        // `parse_dns_node` emits the ignored-key warnings (issue #974).
        if raw_map.get("type").and_then(|v| v.as_str()) == Some("dns") {
            // The node-level key's warning comes from `parse_dns_node`,
            // but the two stronger dialer sources — provider-level
            // `dialer-proxy:` and `override.dialer-proxy:` — are not node
            // keys and would apply silently without one (issue #974
            // review). `override.dialer-proxy: ""` is the "clear the
            // chain" knob, not a declared front — nothing to warn on.
            let enforced = self
                .override_dialer
                .as_deref()
                .or(self.provider_dialer.as_deref())
                .filter(|dialer| !dialer.is_empty());
            if let Some(dialer) = enforced {
                warn!(
                    provider = %self.name,
                    proxy = raw_name,
                    "dns node ignores `dialer-proxy` '{dialer}' — \
                     the leaf owns no transport to chain"
                );
            }
            return proxy_parser::parse_proxy_provider_node_with_fp(
                raw_map,
                self.ipv6,
                self.allow_external_plugin,
                &direct,
                self.global_client_fingerprint.as_deref(),
                Some(&self.dns_cell),
            );
        }
        let node_dialer = match raw_map.get("dialer-proxy") {
            Some(value) => match value.as_str() {
                Some(s) if !s.trim().is_empty() => Some(s.trim()),
                // An explicit-but-empty or null `dialer-proxy:` counts as
                // unset — the provider-level `override` still applies
                // (mihomo's `len > 0` check treats `""` as unset). A
                // whitespace-only value is remote-controlled garbage, not a
                // usable name — reject the node rather than dial direct.
                // `type: rematch`/`type: dns` are the exceptions:
                // `check_rematch_node` treats blank-or-null as absent, and
                // mihomo reads no `dialer-proxy` off a dns leaf — neither
                // owns a transport to chain (issue #974).
                Some("") => None,
                None if value.is_null() => None,
                Some(s)
                    if s.trim().is_empty()
                        && matches!(
                            raw_map.get("type").and_then(|v| v.as_str()),
                            Some("rematch") | Some("dns")
                        ) =>
                {
                    None
                }
                _ => {
                    return Err(
                        "malformed `dialer-proxy` value — expected a proxy/group name".to_string(),
                    );
                }
            },
            None => None,
        };
        // Upstream precedence (provider.go / OverrideSchema.Apply):
        // `override.dialer-proxy` > provider `dialer-proxy` > node-level —
        // the stronger levels overwrite unconditionally, so `override` is
        // an enforcement knob remote nodes cannot escape.
        let Some(dialer_name) = self
            .override_dialer
            .as_deref()
            .or(self.provider_dialer.as_deref())
            .or(node_dialer)
        else {
            return proxy_parser::parse_proxy_provider_node_with_fp(
                raw_map,
                self.ipv6,
                self.allow_external_plugin,
                &direct,
                self.global_client_fingerprint.as_deref(),
                Some(&self.dns_cell),
            );
        };
        // `override.dialer-proxy: ""` is the upstream "clear the chain"
        // knob — the override wrote over both lower levels, so the node
        // dials direct by operator intent, not by a missing field.
        if dialer_name.is_empty() {
            return proxy_parser::parse_proxy_provider_node_with_fp(
                raw_map,
                self.ipv6,
                self.allow_external_plugin,
                &direct,
                self.global_client_fingerprint.as_deref(),
                Some(&self.dns_cell),
            );
        }
        // A `dialer-proxy` chain is a transport knob a `type: rematch` or
        // `type: dns` node cannot carry — parse the control/resolver leaf
        // bare rather than wrap it in `DialerProxyAdapter`, which neither
        // reports the rematch action nor would ever dial anyway (issue
        // #974). A non-blank `dialer-proxy` on a rematch node itself
        // still fails in `check_rematch_node` below.
        let node_type = raw_map.get("type").and_then(|v| v.as_str());
        if matches!(node_type, Some("rematch") | Some("dns")) {
            warn!(
                provider = %self.name,
                proxy = raw_name,
                "{node_type} node ignores `dialer-proxy` '{dialer_name}' — \
                 the leaf owns no transport to chain",
                node_type = node_type.unwrap_or("?")
            );
            return proxy_parser::parse_proxy_provider_node_with_fp(
                raw_map,
                self.ipv6,
                self.allow_external_plugin,
                &direct,
                self.global_client_fingerprint.as_deref(),
                Some(&self.dns_cell),
            );
        }
        if dialer_name == raw_name {
            return Err("`dialer-proxy` points to the node itself".to_string());
        }

        let target = meow_proxy::dialer::DialerTarget::new(dialer_name, &self.dialer_registry);
        let chained: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(meow_proxy::dialer::NamedProxyDialer::new(target.clone()).owned_by(raw_name));
        let proxy = match proxy_parser::parse_proxy_provider_node_with_fp(
            raw_map,
            self.ipv6,
            self.allow_external_plugin,
            &chained,
            self.global_client_fingerprint.as_deref(),
            Some(&self.dns_cell),
        ) {
            // The `ChainedProxy` marker pins the #969 fail-closed verdict
            // on injected entries, identical to the static `proxies:`
            // build's `parse_dialered_leaf`: an injected leaf carries no
            // `DialerProxyAdapter` to report the configured chain, so the
            // UDP probe would otherwise read it as a plain `udp: false`
            // node and slide a matched flow to a later rule.
            Ok(proxy) => Arc::new(proxy_parser::ChainedProxy::new(proxy)) as Arc<dyn Proxy>,
            Err(e) => {
                // The adapter type cannot carry an injected dialer — or the
                // node is unparseable, in which case the direct re-parse
                // surfaces the real error.
                let inner = proxy_parser::parse_proxy_provider_node_with_fp(
                    raw_map,
                    self.ipv6,
                    self.allow_external_plugin,
                    &direct,
                    self.global_client_fingerprint.as_deref(),
                    Some(&self.dns_cell),
                )?;
                warn!(
                    provider = %self.name,
                    proxy = raw_name,
                    error = %e,
                    "cannot inject dialer-proxy '{dialer_name}'; falling back \
                     to the relay-based wrapper"
                );
                Arc::new(meow_proxy::DialerProxyAdapter::new(inner, target)) as Arc<dyn Proxy>
            }
        };
        // Declare only for nodes that actually loaded, deduplicated — a
        // name pushed for a node later dropped would warn about a reference
        // nothing makes (issue #489 review).
        if !declared.iter().any(|d| d == dialer_name) {
            declared.push(dialer_name.to_string());
        }
        Ok(proxy)
    }

    /// `dialer-proxy` names declared by the nodes currently loaded in this
    /// provider — used by the config build to warn about references that
    /// will never resolve (issue #489).
    pub fn declared_dialer_names(&self) -> Vec<String> {
        self.declared_dialers.read().clone()
    }

    /// Periodic/manual refresh — upstream `Update` semantics: fetch the
    /// source, and on ANY failure (transport or document-level parse)
    /// return `Err` and keep the in-memory last-good set. There is no
    /// on-disk cache fallback here — rewinding the slot to a stale cache
    /// generation would be a silent regression (issue #625 review).
    pub async fn refresh(&self) -> Result<(), String> {
        // Hold the generation across fetch+parse+swap: two overlapping
        // refreshes could otherwise interleave slot/derived/declared_dialers
        // from different payloads.
        let _generation = self.refresh_lock.lock().await;
        match self.fetch_source().await {
            Ok((content, userinfo)) => {
                match self
                    .ingest(
                        content,
                        Source::Fetched(userinfo),
                        EchResolution::Resolve,
                        true,
                    )
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        // A torn payload keeps the last-good set instead of
                        // replacing it with nothing.
                        warn!(provider = %self.name, error = %e, "proxy-provider refresh failed");
                        self.logbook_failed(&e.to_string());
                        Err(e.to_string())
                    }
                }
            }
            Err(e) => {
                warn!(provider = %self.name, error = %e, "proxy-provider refresh failed");
                self.logbook_failed(&e);
                Err(e)
            }
        }
    }

    /// Initial acquisition, with HTTP cache fallback.
    ///
    /// Holds `refresh_lock` across fetch+parse+swap: two overlapping
    /// acquisitions could otherwise interleave `slot` / derived views /
    /// `declared_dialers` from different payloads.
    pub async fn acquire_initial(&self) -> anyhow::Result<()> {
        let _generation = self.refresh_lock.lock().await;
        let (content, source) = self.fetch_content(true).await.map_err(anyhow::Error::msg)?;
        self.ingest(content, source, EchResolution::Resolve, true)
            .await
            .map(|_| ())
            .inspect_err(|e| self.logbook_failed(&e.to_string()))
    }

    /// Consumes the deferred-initial-fetch flags: `true` once per provider
    /// whose startup load still owes a remote fetch — its `proxy:` name
    /// could not resolve before the route map was published (issue #625),
    /// it started from its on-disk cache, its fetch failed or outlived
    /// [`crate::set_provider_fetch_deadline`], or the payload it fetched
    /// was rejected by the parse (a remote-payload defect degrades to the
    /// same deferred shape in either mode). The caller fetches it now
    /// that the route map is published; [`spawn_deferred_initial_fetches`]
    /// does exactly that, with retries. `meow-app` runs it once after the
    /// first `update_routing`; embedders that drive `load_config` plus a
    /// `Tunnel` directly must do the same after their first routing
    /// install, or such a provider stays on its cache (or empty) until an
    /// interval or manual refresh.
    pub fn take_deferred_initial(&self) -> bool {
        // `|`, not `||`: both flags must be consumed.
        self.deferred_initial.swap(false, Ordering::Relaxed)
            | self.background_pending.swap(false, Ordering::Relaxed)
    }

    pub fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.slot.read().clone()
    }

    #[cfg(test)]
    fn derived_len(&self) -> usize {
        self.derived.read().len()
    }

    /// The plan usage the subscription server reported with the payload
    /// this provider serves, from the `subscription-userinfo` response
    /// header; persisted next to the on-disk cache, so a restart serving
    /// the cache reports it too. `None` when the server reported none, and
    /// always for a `file` provider.
    pub fn subscription_userinfo(&self) -> Option<SubscriptionUserinfo> {
        *self.subscription_userinfo.lock()
    }

    pub fn updated_at_secs(&self) -> u64 {
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        self.updated_at.load(Ordering::Relaxed).into()
    }
}

/// Validate every proxy-provider's on-disk path up front, so a path escaping
/// the provider cache directory fails the whole (re)build loudly — matching
/// `rule_provider::validate_paths` — instead of the provider being silently
/// warn-skipped and every group referencing it degrading (PR #444 review
/// follow-up).
///
/// Scope is containment only: paths that resolve outside `cache_dir`
/// (explicit `path:` or the implicit name-derived cache location). Other
/// per-provider problems (missing fields, unknown type, fetch failures) keep
/// their historical warn-and-skip semantics in [`ProxyProvider::new`] /
/// [`load_proxy_providers`]. Must stay in sync with the path resolution in
/// [`ProxyProvider::new`].
pub(crate) fn validate_paths(
    raw_map: &HashMap<String, RawProxyProvider>,
    cache_dir: Option<&Path>,
) -> Result<(), String> {
    // No containment root: no on-disk path is honoured at all, so there is
    // nothing to contain (`ProxyProvider::new` errors/warns per provider).
    let Some(dir) = cache_dir else {
        return Ok(());
    };
    for (name, raw) in raw_map {
        let requested = match (raw.provider_type.as_str(), raw.path.as_deref()) {
            ("file" | "http", Some(p)) => PathBuf::from(p),
            // The implicit http cache location is derived from the provider
            // *name* (a YAML map key, also attacker-influenced).
            ("http", None) => PathBuf::from(format!("provider_{name}.yaml")),
            _ => continue,
        };
        crate::safe_path::resolve_contained(dir, &requested)
            .map_err(|e| format!("proxy-provider '{name}': {e}"))?;
    }
    Ok(())
}

/// Build and load every declared proxy-provider for a startup config.
///
/// HTTP providers with a parseable on-disk cache start from it without
/// touching the network and are flagged for a background refetch. The rest
/// fetch concurrently, waited on for at most
/// [`crate::provider_fetch_deadline`]; one that fails, or is still in
/// flight at the deadline, starts empty (populating its groups if it lands
/// later) and is flagged for a background retry. The caller runs
/// [`spawn_deferred_initial_fetches`] after its first routing install to
/// serve both flags. `file` providers load inline — they are local reads.
///
/// A remote payload that fails parsing degrades to the same
/// registered-empty-and-retry shape as a fetch failure — even under
/// `strict`, which reserves its fatal verdict for operator-authored
/// content: the `file:` payloads, provider definitions and the config
/// document itself.
pub async fn load_proxy_providers(
    raw_map: &HashMap<String, RawProxyProvider>,
    cache_dir: Option<&Path>,
    ipv6: bool,
    strict: bool,
    dialer_registry: &meow_proxy::dialer::ProxyRegistry,
) -> Result<HashMap<String, Arc<ProxyProvider>>, anyhow::Error> {
    load_proxy_providers_within(
        raw_map,
        cache_dir,
        ipv6,
        strict,
        dialer_registry,
        None,
        crate::provider_fetch_deadline(),
        None,
        &mut DroppedProviders::default(),
    )
    .await
}

/// [`load_proxy_providers`] with an explicit fetch deadline instead of the
/// process-wide [`crate::provider_fetch_deadline`]. Providers left out
/// leniently go into `dropped`, for the commit to record.
/// `global_client_fingerprint` is the committed top-level
/// `global-client-fingerprint` (issue #974) the providers' nodes inherit.
/// `dns_cell` is the config's live-resolver indirection provider `type: dns`
/// leaves bind — `None` leaves them unbound (SERVFAIL) for callers that
/// have none (issue #974).
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is an independent config-build input; bundling \
              them would only rename the same list"
)]
pub async fn load_proxy_providers_within(
    raw_map: &HashMap<String, RawProxyProvider>,
    cache_dir: Option<&Path>,
    ipv6: bool,
    strict: bool,
    dialer_registry: &meow_proxy::dialer::ProxyRegistry,
    global_client_fingerprint: Option<&str>,
    deadline: Option<Duration>,
    dns_cell: Option<&meow_dns::DnsOutboundCell>,
    dropped: &mut DroppedProviders,
) -> Result<HashMap<String, Arc<ProxyProvider>>, anyhow::Error> {
    let mut result = HashMap::new();
    let mut fetches = Vec::new();
    for (name, raw) in raw_map {
        let provider = match ProxyProvider::new_with_client_fingerprint(
            name,
            raw,
            cache_dir,
            ipv6,
            strict,
            dialer_registry.clone(),
            global_client_fingerprint,
            dns_cell.cloned(),
        ) {
            Ok(provider) => Arc::new(provider),
            Err(e) if strict => {
                return Err(anyhow::anyhow!(
                    "proxy-provider '{name}' failed to load (strict mode): {e}"
                ));
            }
            Err(e) => {
                warn!(provider = %name, error = %e, "failed to create proxy-provider, skipping");
                dropped.proxy(name, e);
                continue;
            }
        };
        if matches!(provider.vehicle, Vehicle::File(_)) {
            // A `file:` payload is local, operator-authored content — it
            // must read identically under `-t` and at boot, so it loads
            // before the offline short-circuit below (mirroring the
            // rule-provider `file:`/`inline:` loads, which already run
            // offline). Its strict verdict therefore cannot differ
            // between validation and a real start.
            provider.initial_load(strict).await?;
        } else if crate::is_offline_validate() {
            // Offline validation (`meow -t`): the provider parsed and its
            // path/filters are structurally valid — that is what a config
            // test checks. Skip the network fetch so a slow or unreachable
            // subscription can't hang validation (the provider registers
            // empty, exactly as a transient fetch failure would leave it).
        } else if provider.load_from_cache().await {
            provider.background_pending.store(true, Ordering::Relaxed);
        } else {
            let fetching = Arc::clone(&provider);
            fetches.push((
                name.clone(),
                Arc::clone(&provider),
                tokio::spawn(async move { fetching.initial_load(strict).await }),
            ));
        }
        result.insert(name.clone(), provider);
    }

    // Concurrent, so startup waits for the slowest feed rather than the sum
    // of them. Every wait shares one absolute deadline.
    let deadline_at = deadline.map(|d| tokio::time::Instant::now() + d);
    for (name, provider, mut fetch) in fetches {
        let outcome = match deadline_at {
            None => Some((&mut fetch).await),
            Some(at) => tokio::time::timeout_at(at, &mut fetch).await.ok(),
        };
        match outcome {
            Some(Ok(Ok(true))) => {}
            Some(Ok(Ok(false))) => provider.background_pending.store(true, Ordering::Relaxed),
            // Defensive arm: `fetches` only holds remote providers, whose
            // payload defects `initial_load` degrades to `Ok(false)` —
            // only the `file:` vehicle stays strict-fatal, and it runs
            // synchronously above, so no remote byte can veto this load
            // by landing before the deadline while the same bytes in
            // flight could not.
            Some(Ok(Err(e))) => return Err(e),
            Some(Err(e)) => {
                warn!(provider = %name, error = %e, "proxy-provider initial fetch task failed");
                provider.background_pending.store(true, Ordering::Relaxed);
            }
            None => {
                // Left running: it populates the provider's groups if it
                // lands, and the background retry queues behind it. A
                // remote payload defect degrades to `Ok(false)` on the
                // same rules as a pre-deadline one, so the strict verdict
                // never depends on the fetch's timing.
                warn!(provider = %name,
                    "proxy-provider still fetching at the startup deadline; \
                     starting empty and finishing in the background");
                provider.background_pending.store(true, Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Ok(Err(e)) = fetch.await {
                        warn!(provider = %name, error = %e, "proxy-provider payload rejected");
                    }
                });
            }
        }
    }
    Ok(result)
}

/// Post-publish kick for the providers [`load_proxy_providers`] left owing
/// a remote fetch (see [`ProxyProvider::take_deferred_initial`]): spawns
/// [`ProxyProvider::spawn_initial_fetch`] for each. Run once after the
/// first routing install, so `proxy:` names resolve against the published
/// route map.
pub fn spawn_deferred_initial_fetches(registry: &DashMap<String, Arc<ProxyProvider>>) {
    for entry in registry {
        if entry.take_deferred_initial() {
            entry.value().spawn_initial_fetch();
        }
    }
}

/// Logbook: creating, fetching or parsing proxy provider `name` failed.
/// Repeats fold while it keeps failing.
pub(crate) fn record_failure(name: &str, error: &str) {
    // The errors name the provider already.
    let error = error
        .strip_prefix(&format!("proxy-provider '{name}': "))
        .unwrap_or(error);
    logbook::event(
        logbook::kind::PROXY_PROVIDER_UPDATE,
        Level::Error,
        format!("Updating proxy provider '{name}' failed: {error}"),
    )
    .subject(name)
    .field("error", error)
    .coalesce()
    .record();
}

/// How [`ProxyProvider::ingest`] treats DNS-sourced ECH configs while
/// parsing a payload.
#[derive(Clone, Copy)]
enum EchResolution {
    /// [`preresolve_ech`](crate::ech_dns::preresolve_ech): run the
    /// HTTPS-record lookups and inline the results — every off-lane load
    /// (boot, background fetch, refresh, cache read).
    Resolve,
    /// [`check_ech_defects`](crate::ech_dns::check_ech_defects) only —
    /// the same strict verdict with no network I/O, for the
    /// config-mutation lane's pre-commit load, where a lookup would
    /// serialize every other commit behind one name's DNS answer (the
    /// same reason `apply_raw_to_tunnel` checks instead of preresolving,
    /// issue #533 review). A commit that still owes lookups sets
    /// [`ProxyProvider::ech_pending`], and the detached post-commit fetch
    /// re-parses under [`Resolve`](Self::Resolve) so the committed nodes
    /// match a boot load.
    Defer,
}

/// Where a payload handed to [`ProxyProvider::ingest`] came from.
#[derive(Clone, Copy)]
enum Source {
    /// Read from the provider's source, with the plan usage an HTTP
    /// response reported.
    Fetched(Option<SubscriptionUserinfo>),
    /// The on-disk cache of an HTTP provider.
    Cache,
}

/// What a parsed fetch did to the provider's payload, for the logbook.
#[derive(Clone, Copy)]
enum Payload {
    /// The provider held nothing yet.
    First,
    /// Replaced a payload of this many nodes.
    Replaced(usize),
    /// Matched the committed payload byte for byte.
    Unchanged,
}

async fn background_fetch_loop(provider: Weak<ProxyProvider>) {
    // A provider a config commit just created starts empty; a startup-loaded
    // one already tried its cache (this re-check is then a no-op).
    if let Some(p) = provider.upgrade() {
        p.load_from_cache().await;
    }
    let mut delay = BACKGROUND_RETRY_MIN;
    let mut failed_revalidations = 0;
    loop {
        let Some(p) = provider.upgrade() else {
            return;
        };
        let Err(e) = p.background_attempt().await else {
            return;
        };
        if p.deferred_initial.load(Ordering::Relaxed) {
            // Unresolvable against the *published* map: a config defect,
            // not an outage. The next commit retries a flagged provider.
            warn!(provider = %p.name, error = %e,
                "proxy-provider fetch skipped: its `proxy:` does not resolve");
            return;
        }
        if p.has_content() {
            failed_revalidations += 1;
            if failed_revalidations >= MAX_REVALIDATION_ATTEMPTS {
                warn!(provider = %p.name, error = %e,
                    "proxy-provider refetch failed; keeping the cached nodes until the next refresh");
                return;
            }
        }
        warn!(provider = %p.name, error = %e, retry_in = ?delay, "proxy-provider fetch failed; retrying");
        drop(p);
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(BACKGROUND_RETRY_MAX);
    }
}

/// Warn for an initial-load failure, distinguishing a not-yet-resolvable
/// `proxy:` — retried once the route map is published (issue #625) — from
/// real fetch failures, so `-t` and startup logs don't read like a hard
/// error. The flag is set inside `fetch_source`, so it must be read after
/// the fetch attempt, not before.
fn warn_initial_load_failure(provider: &ProxyProvider, error: &str) {
    if provider.deferred_initial.load(Ordering::Relaxed) {
        warn!(provider = %provider.name, error = %error,
            "initial provider load failed (proxy not resolvable yet); \
             starting empty — will retry once the route map is published");
    } else if provider.is_file_vehicle() {
        // A `file:` read failure owes no startup background fetch —
        // `background_pending` is only set for remote vehicles — so it
        // heals on an `interval:` tick, a manual refresh, or the detached
        // first fetch a config commit spawns for a new provider.
        warn!(provider = %provider.name, error = %error,
            "initial provider load failed; starting empty until a refresh succeeds");
    } else {
        warn!(provider = %provider.name, error = %error,
            "initial provider load failed; starting empty until a background fetch succeeds");
    }
}

/// Provider payload → node maps, with the share-link fallback.
///
/// YAML is the primary format: a `proxies:` wrapper or a bare sequence. A
/// `Value::Null` document is an empty or comments-only file — an empty
/// provider rather than a parse defect, so an editor or external tool
/// mid-rewrite does not hard-fail strict mode (parity with the missing-file
/// acquisition path, issue #533).
///
/// A body that is already a YAML proxy document keeps its YAML error:
/// falling through to the share-link scanner would harvest incidental
/// `ss://` lines out of a `preview:` block (or similar) and drop fields
/// such as `dialer-proxy`. Share-link fallback runs only when the decoded
/// payload is a share-link list: every non-empty non-comment line contains
/// `://` (plain or base64 `scheme://` links, the shape airports serve to a
/// `mihomo` User-Agent via `convert.ConvertsV2Ray`). When both paths fail
/// the YAML diagnosis is the one reported — it is the format the feed most
/// likely meant to serve.
fn parse_payload_maps(
    content: &str,
) -> Result<Vec<HashMap<String, serde_json::Value>>, anyhow::Error> {
    let yaml_error = match crate::parse_yaml_value(content) {
        Ok(doc) => {
            if doc.is_null() {
                return Ok(Vec::new());
            }
            if doc.get("proxies").is_some() || doc.is_array() {
                return yaml_proxy_list(doc);
            }
            "provider content is not a proxy list: expected a sequence".to_string()
        }
        Err(e) => format!("provider YAML is malformed: {e}"),
    };
    if !crate::provider_payload::looks_like_share_link_list(content) {
        return Err(anyhow::anyhow!("{yaml_error}"));
    }
    match crate::provider_payload::parse_share_links(content) {
        Ok(maps) => Ok(maps),
        Err(link_error) => Err(anyhow::anyhow!(
            "{yaml_error}; and not a share-link list either: {link_error}"
        )),
    }
}

fn yaml_proxy_list(
    doc: serde_json::Value,
) -> Result<Vec<HashMap<String, serde_json::Value>>, anyhow::Error> {
    let list_val = match doc.get("proxies").cloned().unwrap_or(doc) {
        serde_json::Value::Null => return Ok(Vec::new()),
        value => value,
    };
    if list_val.is_array() {
        serde_json::from_value::<Vec<HashMap<String, serde_json::Value>>>(list_val)
            .map_err(|e| anyhow::anyhow!("provider content is not a proxy list: {e}"))
    } else {
        Err(anyhow::anyhow!(
            "provider content is not a proxy list: expected a sequence"
        ))
    }
}

fn compile_opt_regex(
    pattern: &Option<String>,
    field: &str,
) -> Result<Option<fancy_regex::Regex>, String> {
    match pattern.as_deref() {
        Some(p) => fancy_regex::Regex::new(p)
            .map(Some)
            .map_err(|e| format!("{field} regex error: {e}")),
        None => Ok(None),
    }
}

/// Evaluate a `filter`/`exclude-filter` fancy-regex against a node name.
///
/// fancy-regex compiles look-around assertions the way mihomo's Go regex
/// engine does, but its backtracking VM can still fail at *evaluation*
/// time (e.g. a pathological pattern overflows the backtrack limit). A
/// failure is logged and treated as a non-match: the node is kept by
/// `exclude-filter` semantics and dropped by `filter` semantics — the
/// same default `regex::Regex::is_match` gave for plain patterns, with
/// the failed case visible in the log instead of silently swallowed.
fn regex_matches(re: &fancy_regex::Regex, name: &str) -> bool {
    match re.is_match(name) {
        Ok(matched) => matched,
        Err(e) => {
            warn!(error = %e, "filter regex evaluation failed; treating as no match");
            false
        }
    }
}

/// Content hash for the unchanged-payload dedup — `DefaultHasher`
/// (SipHash) is fine here; this is a same-process dedup, not a checksum
/// persisted or compared across trust boundaries.
fn content_hash(content: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut h);
    h.finish()
}

async fn read_cache(path: Option<&Path>, name: &str) -> Result<String, String> {
    let Some(path) = path else {
        return Err(format!(
            "proxy-provider '{name}': fetch failed and no on-disk cache is configured"
        ));
    };
    tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("proxy-provider '{name}': no cache at {path:?}: {e}"))
}

fn build_health_check_config(
    name: &str,
    raw: Option<&RawHealthCheck>,
) -> Result<Option<HealthCheckConfig>, String> {
    let Some(hc) = raw else { return Ok(None) };
    // mihomo's `NewUnsignedRanges` runs before `Enable` is even read —
    // a malformed spec fails the provider build whether or not the
    // block ever probes.
    if let Some(spec) = hc.expected_status.as_deref() {
        meow_proxy::health::validate_expected_status(spec)?;
    }
    let enable = hc.enable.unwrap_or(false);
    // mihomo's `Enable` has no schema default: a bare block does not
    // probe. The disable is surfaced rather than silent — a
    // health-check block whose probes never run is almost always a
    // config mistake.
    if !enable {
        warn!(
            provider = %name,
            "proxy-provider health-check present but `enable` is not true; \
             members will not be probed periodically"
        );
    }
    // mihomo keeps no gstatic default and zeroes the interval when the
    // url is empty (`NewHealthCheck`): an undeclared url must mean "no
    // probes", and the manual endpoint skips it too. Upstream also
    // `strings.TrimSpace`s the url in `execute()`/`registerHealthCheckTask`
    // before the empty check and the probe, so store it trimmed: a
    // whitespace-only value degrades to the empty-url path instead of a
    // sweep whose every probe fails URL parsing (all members marked dead).
    let url = hc.url.as_deref().unwrap_or_default().trim().to_string();
    if enable && url.is_empty() {
        warn!(
            provider = %name,
            "proxy-provider health-check `enable` but no `url`; \
             members will not be probed"
        );
    }
    if hc.lazy == Some(true) {
        // Per provider per build — a process-global `Once` would hide
        // every offender's name but the first's.
        warn!(
            provider = %name,
            "proxy-provider health-check `lazy` is not honoured: members are probed every interval"
        );
    }
    Ok(Some(HealthCheckConfig {
        url,
        enable,
        // mihomo maps an explicit 0 to the default, never to "every tick".
        interval: match hc.interval {
            None | Some(0) => 300,
            Some(v) => v,
        },
        // `timeout` is milliseconds consumed by `tokio::time::timeout`
        // (provider healthcheck API) — mihomo's `NewHealthCheck` maps an
        // explicit 0 to 5000 like an absent one, and the value is clamped
        // to the shared duration ceiling so an absurd value degrades to
        // "probe never fires" instead of wrapping Instant arithmetic
        // (issue #648 review).
        timeout: match hc.timeout {
            None | Some(0) => 5000,
            Some(v) => v.min(meow_common::MAX_DURATION_SECS.saturating_mul(1000)),
        },
        expected_status: hc.expected_status.clone().unwrap_or_default(),
        // Upstream defaults `lazy: true` (`healthCheckSchema{Lazy: true}`,
        // parser.go) and skips ticks the provider saw no traffic during.
        // We keep `false`: meow tracks no per-provider last-touch, so
        // `lazy` could only ever mean "never probe" — parsed for compat,
        // not honoured (same precedent as group `lazy` — #555, ADR-0002).
        lazy: hc.lazy.unwrap_or(false),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::RawProxyProvider;
    use crate::test_support::{eventually, Origin, TestLogbook};

    fn raw_file_provider(path: &str) -> RawProxyProvider {
        RawProxyProvider {
            provider_type: "file".to_string(),
            url: None,
            path: Some(path.to_string()),
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: None,
            override_: None,
            proxy: None,
            dialer_proxy: None,
            extra: Default::default(),
        }
    }

    #[test]
    fn file_provider_new_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let raw = raw_file_provider("proxies.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        assert_eq!(p.name, "test");
        assert_eq!(p.vehicle_type, "File");
        assert!(p.header.is_empty());
    }

    #[test]
    fn file_provider_requires_cache_dir_for_path() {
        let raw = raw_file_provider("/tmp/proxies.yaml");
        let Err(err) = ProxyProvider::new("test", &raw, None, true, false, Default::default())
        else {
            panic!("file path without a cache dir must fail");
        };
        assert!(err.contains("cache directory"), "unexpected: {err}");
    }

    #[test]
    fn file_provider_path_escaping_cache_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for path in ["../../etc/pwned", "/etc/pwned"] {
            let raw = raw_file_provider(path);
            let Err(err) = ProxyProvider::new(
                "test",
                &raw,
                Some(dir.path()),
                true,
                false,
                Default::default(),
            ) else {
                panic!("escaping path {path} must be rejected");
            };
            assert!(err.contains("escapes"), "path {path}: unexpected: {err}");
        }
    }

    #[test]
    fn http_provider_path_escaping_cache_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let raw = RawProxyProvider {
            provider_type: "http".to_string(),
            url: Some("http://127.0.0.1:1/proxies.yaml".to_string()),
            path: Some("/etc/cron.d/pwned".to_string()),
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: None,
            override_: None,
            proxy: None,
            dialer_proxy: None,
            extra: Default::default(),
        };
        let Err(err) = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        ) else {
            panic!("escaping http cache path must be rejected");
        };
        assert!(err.contains("escapes"), "unexpected: {err}");
    }

    // PR #444 review follow-up: a proxy-provider path escaping the cache dir
    // must fail the whole rebuild loudly (rule-provider parity), not just
    // warn-skip the provider and silently degrade the groups using it.
    #[test]
    fn validate_paths_rejects_escaping_provider_paths() {
        let dir = tempfile::tempdir().unwrap();
        for path in ["../../etc/pwned", "/etc/cron.d/pwned"] {
            let mut map = HashMap::new();
            map.insert("evil".to_string(), raw_file_provider(path));
            let err = validate_paths(&map, Some(dir.path()))
                .expect_err("escaping path must fail validation");
            assert!(err.contains("evil"), "must name the provider: {err}");
            assert!(err.contains("escapes"), "path {path}: unexpected: {err}");
        }
    }

    #[test]
    fn validate_paths_accepts_contained_and_pathless_providers() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = HashMap::new();
        map.insert("f".to_string(), raw_file_provider("sub/proxies.yaml"));
        map.insert(
            "h".to_string(),
            RawProxyProvider {
                provider_type: "http".to_string(),
                url: Some("http://127.0.0.1:1/proxies.yaml".to_string()),
                path: None, // implicit cache location from the name
                interval: None,
                filter: None,
                exclude_filter: None,
                exclude_type: None,
                health_check: None,
                allow_external_plugin: None,
                header: None,
                override_: None,
                proxy: None,
                dialer_proxy: None,
                extra: Default::default(),
            },
        );
        validate_paths(&map, Some(dir.path())).expect("contained paths must validate");
        // Rootless context: nothing on disk is honoured, nothing to contain.
        validate_paths(&map, None).expect("no cache dir means nothing to validate");
    }

    #[test]
    fn http_provider_new_with_custom_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "X-Token".to_string(),
            crate::raw::StringOrList::Single("secret".to_string()),
        );
        let raw = RawProxyProvider {
            provider_type: "http".to_string(),
            url: Some("https://example.com/proxies.yaml".to_string()),
            path: None,
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: Some(headers),
            override_: None,
            proxy: None,
            dialer_proxy: None,
            extra: Default::default(),
        };
        let p = ProxyProvider::new("airport", &raw, None, true, false, Default::default()).unwrap();
        assert_eq!(p.vehicle_type, "HTTP");
        assert!(p
            .header
            .contains(&("X-Token".to_string(), "secret".to_string())));
    }

    #[test]
    fn http_provider_new_with_multi_value_headers() {
        // mihomo's canonical list form: one name, several values.
        let mut headers = HashMap::new();
        headers.insert(
            "User-Agent".to_string(),
            crate::raw::StringOrList::List(vec![
                "Clash/v1.18.0".to_string(),
                "mihomo/1.18.3".to_string(),
            ]),
        );
        headers.insert(
            "Authorization".to_string(),
            crate::raw::StringOrList::Single("token 1231231".to_string()),
        );
        let raw = RawProxyProvider {
            provider_type: "http".to_string(),
            url: Some("https://example.com/proxies.yaml".to_string()),
            path: None,
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: Some(headers),
            override_: None,
            proxy: None,
            dialer_proxy: None,
            extra: Default::default(),
        };
        let p = ProxyProvider::new("airport", &raw, None, true, false, Default::default()).unwrap();
        // Multi-value entries repeat the name (one field line per value),
        // sorted by name like Go net/http.
        assert_eq!(
            p.header,
            vec![
                ("Authorization".to_string(), "token 1231231".to_string()),
                ("User-Agent".to_string(), "Clash/v1.18.0".to_string()),
                ("User-Agent".to_string(), "mihomo/1.18.3".to_string()),
            ]
        );
    }

    // -- health-check block parsing (mihomo `healthCheckSchema` parity) --

    fn hc(
        enable: Option<bool>,
        url: Option<&str>,
        interval: Option<u64>,
        timeout: Option<u64>,
        expected_status: Option<&str>,
        lazy: Option<bool>,
    ) -> crate::raw::RawHealthCheck {
        crate::raw::RawHealthCheck {
            enable,
            url: url.map(str::to_string),
            interval,
            timeout,
            expected_status: expected_status.map(str::to_string),
            lazy,
            extra: Default::default(),
        }
    }

    /// No `health-check:` block at all → no config (the `None` early
    /// return the rest of the build depends on).
    #[test]
    fn health_check_absent_block_is_none() {
        assert!(build_health_check_config("p", None)
            .expect("absent block")
            .is_none());
    }

    /// mihomo builds `HealthCheck` unconditionally — `Enable` only zeroes
    /// the ticker interval — so an `enable: false` (or absent) block must
    /// still materialise for the manual endpoint and the `testUrl` echo.
    #[test]
    fn health_check_disabled_block_still_builds() {
        for enable in [None, Some(false)] {
            let cfg = build_health_check_config(
                "p",
                Some(&hc(
                    enable,
                    Some("https://probe.test/204"),
                    Some(60),
                    None,
                    None,
                    None,
                )),
            )
            .expect("block must parse")
            .expect("the block is kept, not dropped");
            assert!(!cfg.enable);
            assert_eq!(cfg.url, "https://probe.test/204");
        }
    }

    /// `interval`/`timeout` share mihomo's `== 0 → default` mapping —
    /// an explicit 0 never means "every tick"/"no wait".
    #[test]
    fn health_check_zero_values_map_to_defaults() {
        let cfg = build_health_check_config(
            "p",
            Some(&hc(
                Some(true),
                Some("https://probe.test/204"),
                Some(0),
                Some(0),
                None,
                None,
            )),
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.interval, 300);
        assert_eq!(cfg.timeout, 5000);
        let cfg = build_health_check_config(
            "p",
            Some(&hc(
                Some(true),
                Some("https://probe.test/204"),
                Some(42),
                Some(250),
                None,
                None,
            )),
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.interval, 42);
        assert_eq!(cfg.timeout, 250);
    }

    /// The url is stored trimmed — no gstatic fallback: mihomo zeroes
    /// the interval on an empty url, so "not declared" must mean "no
    /// probes" rather than "probe the default".
    #[test]
    fn health_check_url_keeps_empty() {
        for url in [None, Some("")] {
            let cfg =
                build_health_check_config("p", Some(&hc(Some(true), url, None, None, None, None)))
                    .unwrap()
                    .unwrap();
            assert!(cfg.url.is_empty(), "no implicit probe url: {:?}", cfg.url);
        }
    }

    /// Upstream `strings.TrimSpace`s the url in `execute()`/
    /// `registerHealthCheckTask` — the build stores it already trimmed
    /// so surrounding padding cannot reach the probe, and a
    /// whitespace-only value folds into the empty-url path (no sweep,
    /// manual endpoint 204s) instead of spawning a sweep whose every
    /// probe fails URL parsing and dead-marks every member.
    #[test]
    fn health_check_url_is_trimmed() {
        let cfg = build_health_check_config(
            "p",
            Some(&hc(
                Some(true),
                Some("  https://probe.test/204  "),
                None,
                None,
                None,
                None,
            )),
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.url, "https://probe.test/204");
        for url in [Some("   "), Some("\t \n")] {
            let cfg =
                build_health_check_config("p", Some(&hc(Some(true), url, None, None, None, None)))
                    .unwrap()
                    .unwrap();
            assert!(
                cfg.url.is_empty(),
                "whitespace-only must normalise to empty: {:?}",
                cfg.url
            );
        }
    }

    /// `expected-status` validates like upstream's `NewUnsignedRanges`,
    /// which runs before `Enable` is even read — a bad spec fails the
    /// provider build on an `enable: false` block too.
    #[test]
    fn health_check_expected_status_validates_even_when_disabled() {
        for enable in [None, Some(false), Some(true)] {
            let Err(err) = build_health_check_config(
                "p",
                Some(&hc(
                    enable,
                    Some("https://probe.test/204"),
                    None,
                    None,
                    Some("garbage"),
                    None,
                )),
            ) else {
                panic!("a malformed expected-status must fail the build")
            };
            assert!(err.contains("expected"), "unexpected: {err}");
        }
        // …and a good spec is echoed verbatim for the probe path.
        let cfg = build_health_check_config(
            "p",
            Some(&hc(None, None, None, None, Some("200-299"), None)),
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.expected_status, "200-299");
    }

    #[test]
    fn raw_proxy_provider_deserializes_header() {
        let yaml = r#"
type: http
url: "https://example.com/proxies.yaml"
header:
  Authorization: "Bearer token123"
  X-Custom: "value"
"#;
        let raw: RawProxyProvider = serde_saphyr::from_str(yaml).unwrap();
        let headers = raw.header.unwrap();
        assert_eq!(
            headers.get("Authorization"),
            Some(&crate::raw::StringOrList::Single(
                "Bearer token123".to_string()
            ))
        );
        assert_eq!(
            headers.get("X-Custom"),
            Some(&crate::raw::StringOrList::Single("value".to_string()))
        );
    }

    #[test]
    fn raw_proxy_provider_deserializes_list_header() {
        // The mihomo wiki form: sequence values under `header:`.
        let yaml = r#"
type: http
url: "https://example.com/proxies.yaml"
header:
  User-Agent:
    - "Clash/v1.18.0"
    - "mihomo/1.18.3"
  Authorization:
    - 'token 1231231'
"#;
        let raw: RawProxyProvider = serde_saphyr::from_str(yaml).unwrap();
        let headers = raw.header.unwrap();
        assert_eq!(
            headers.get("User-Agent"),
            Some(&crate::raw::StringOrList::List(vec![
                "Clash/v1.18.0".to_string(),
                "mihomo/1.18.3".to_string(),
            ]))
        );
        assert_eq!(
            headers.get("Authorization"),
            Some(&crate::raw::StringOrList::List(vec![
                "token 1231231".to_string()
            ]))
        );
    }

    #[test]
    fn raw_proxy_provider_no_header_defaults_empty() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "type: file\npath: proxies.yaml\n";
        let raw: RawProxyProvider = serde_saphyr::from_str(yaml).unwrap();
        assert!(raw.header.is_none());
        let p = ProxyProvider::new("p", &raw, Some(dir.path()), true, false, Default::default())
            .unwrap();
        assert!(p.header.is_empty());
    }

    fn group_filter(
        filter: Option<&str>,
        exclude_filter: Option<&str>,
        exclude_type: Option<&[&str]>,
    ) -> GroupFilter {
        let raw = crate::raw::RawProxyGroup {
            name: "g".to_string(),
            group_type: "select".to_string(),
            filter: filter.map(str::to_string),
            exclude_filter: exclude_filter.map(str::to_string),
            exclude_type: exclude_type.map(|v| v.iter().map(|s| (*s).to_string()).collect()),
            ..Default::default()
        };
        GroupFilter::from_raw_group(&raw).unwrap().unwrap()
    }

    fn write_provider_file(path: &std::path::Path, entries: &[(&str, &str)]) {
        use std::fmt::Write as _;
        let mut yaml = String::from("proxies:\n");
        for (name, ty) in entries {
            writeln!(
                yaml,
                "  - {{name: \"{name}\", type: {ty}, server: 127.0.0.1, port: 443, \
                 cipher: aes-128-gcm, password: pass}}"
            )
            .unwrap();
        }
        std::fs::write(path, yaml).unwrap();
    }

    fn slot_names(slot: &ProviderSlot) -> Vec<String> {
        slot.read().iter().map(|p| p.name().to_string()).collect()
    }

    async fn file_provider(path: &std::path::Path) -> ProxyProvider {
        let raw = raw_file_provider(path.to_str().unwrap());
        let cache_dir = path.parent().expect("temp file has a parent dir");
        let p = ProxyProvider::new(
            "airport",
            &raw,
            Some(cache_dir),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        p
    }

    /// A payload that is not YAML is retried as a base64 share-link list —
    /// the shape airports serve to a `mihomo` User-Agent (mihomo reaches the
    /// same nodes through `convert.ConvertsV2Ray`).
    ///
    /// Both links are `ss://` on purpose: the `ss`-only CI leg compiles no
    /// other scheme's adapter, and a node whose type is not in the build is
    /// dropped with a warning instead of parsed, so a mixed list would make
    /// this test's expected names depend on the feature set. Per-scheme
    /// mapping is covered by `provider_payload`'s own tests, which build no
    /// adapter and therefore run under every feature set.
    #[tokio::test]
    async fn provider_payload_accepts_base64_share_links() {
        use base64::Engine as _;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let links = "ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n\
                     ss://YWVzLTI1Ni1nY206c2VjcmV0@b.example.com:443#B\n";
        std::fs::write(
            tmp.path(),
            base64::engine::general_purpose::STANDARD.encode(links),
        )
        .unwrap();
        let provider = file_provider(tmp.path()).await;
        assert_eq!(slot_names(&provider.slot), ["A", "B"]);
    }

    /// A YAML provider document that fails to parse (unresolved merge) must
    /// not fall back to harvesting `ss://` lines out of a `preview:` block.
    #[test]
    fn yaml_merge_error_does_not_harvest_preview_share_link() {
        let yaml = "proxies:\n\
                    - name: real\n\
                      type: ss\n\
                      server: a.example.com\n\
                      port: 8388\n\
                      cipher: aes-128-gcm\n\
                      password: pass\n\
                      dialer-proxy: front\n\
                      <<: *missing\n\
                    preview: |\n\
                      ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n";
        let err = parse_payload_maps(yaml)
            .expect_err("an unresolved merge in a proxies: document must stay a YAML error");
        let msg = err.to_string();
        assert!(
            msg.contains("YAML")
                || msg.contains("malformed")
                || msg.contains("merge")
                || msg.contains("alias"),
            "unexpected error: {msg}"
        );
        assert!(
            !msg.contains("share-link"),
            "must not harvest incidental ss:// lines: {msg}"
        );
    }

    /// Successful ingest already accepts a bare YAML sequence (`doc.is_array()`).
    /// A malformed one (unresolved merge, no `proxies:` wrapper) must keep
    /// the YAML error instead of harvesting `ss://` out of a `preview:` block.
    #[test]
    fn yaml_bare_sequence_merge_error_does_not_harvest_preview_share_link() {
        let yaml = "- name: real\n\
                    type: ss\n\
                    server: a.example.com\n\
                    port: 8388\n\
                    cipher: aes-128-gcm\n\
                    password: pass\n\
                    dialer-proxy: front\n\
                    <<: *missing\n\
                    preview: |\n\
                      ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n";
        let err = parse_payload_maps(yaml)
            .expect_err("an unresolved merge in a bare YAML sequence must stay a YAML error");
        let msg = err.to_string();
        assert!(
            msg.contains("YAML")
                || msg.contains("malformed")
                || msg.contains("merge")
                || msg.contains("alias"),
            "unexpected error: {msg}"
        );
        assert!(
            !msg.contains("share-link"),
            "must not harvest incidental ss:// lines: {msg}"
        );
    }

    /// Same shape on refresh: last-good survives, the preview link is not imported.
    #[tokio::test]
    async fn yaml_merge_preview_refresh_keeps_last_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.yaml");
        write_provider_file(&path, &[("KeepMe", "ss")]);
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "airport",
            &raw,
            Some(dir.path()),
            true,
            true,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(slot_names(&p.slot), ["KeepMe"]);

        std::fs::write(
            &path,
            "proxies:\n\
             - name: real\n\
               type: ss\n\
               server: a.example.com\n\
               port: 8388\n\
               cipher: aes-128-gcm\n\
               password: pass\n\
               dialer-proxy: front\n\
               <<: *missing\n\
             preview: |\n\
               ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n",
        )
        .unwrap();
        p.refresh()
            .await
            .expect_err("malformed YAML with a preview share-link must fail");
        assert_eq!(
            slot_names(&p.slot),
            ["KeepMe"],
            "last-good must survive; the preview link must not be imported"
        );
    }

    /// Bare-sequence sibling of `yaml_merge_preview_refresh_keeps_last_good`.
    #[tokio::test]
    async fn yaml_bare_sequence_preview_refresh_keeps_last_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.yaml");
        write_provider_file(&path, &[("KeepMe", "ss")]);
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "airport",
            &raw,
            Some(dir.path()),
            true,
            true,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(slot_names(&p.slot), ["KeepMe"]);

        std::fs::write(
            &path,
            "- name: real\n\
             type: ss\n\
             server: a.example.com\n\
             port: 8388\n\
             cipher: aes-128-gcm\n\
             password: pass\n\
             dialer-proxy: front\n\
             <<: *missing\n\
             preview: |\n\
               ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n",
        )
        .unwrap();
        p.refresh()
            .await
            .expect_err("malformed bare YAML sequence with a preview share-link must fail");
        assert_eq!(
            slot_names(&p.slot),
            ["KeepMe"],
            "last-good must survive; the preview link must not be imported"
        );
    }

    /// Quoted `'proxies':` plus an anchored item (`- &node`) is still YAML.
    /// An unresolved merge must not fall through to harvesting the preview
    /// `ss://` line (which would drop `dialer-proxy`).
    #[test]
    fn yaml_quoted_proxies_anchor_does_not_harvest_preview_share_link() {
        let yaml = "'proxies':\n\
                    - &node\n\
                      name: real\n\
                      type: ss\n\
                      server: a.example.com\n\
                      port: 8388\n\
                      cipher: aes-128-gcm\n\
                      password: pass\n\
                      dialer-proxy: front\n\
                      <<: *missing\n\
                    preview: |\n\
                      ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n";
        let err = parse_payload_maps(yaml)
            .expect_err("an unresolved merge under a quoted proxies: key must stay a YAML error");
        let msg = err.to_string();
        assert!(
            msg.contains("YAML")
                || msg.contains("malformed")
                || msg.contains("merge")
                || msg.contains("alias"),
            "unexpected error: {msg}"
        );
        assert!(
            !msg.contains("share-link"),
            "must not harvest incidental ss:// lines: {msg}"
        );
    }

    /// Last-good node A keeps `dialer-proxy: front`; a quoted-key YAML
    /// refresh with a preview `ss://#A` must not replace it with a hop-less A.
    #[tokio::test]
    async fn yaml_quoted_proxies_preview_refresh_keeps_last_good_dialer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.yaml");
        std::fs::write(
            &path,
            "proxies:\n\
             \x20 - {name: A, type: ss, server: a.example.com, port: 8388, \
             cipher: aes-128-gcm, password: pass, dialer-proxy: front}\n",
        )
        .unwrap();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "airport",
            &raw,
            Some(dir.path()),
            true,
            true,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(slot_names(&p.slot), ["A"]);
        assert_eq!(p.declared_dialer_names(), ["front"]);

        std::fs::write(
            &path,
            "'proxies':\n\
             - &node\n\
               name: real\n\
               type: ss\n\
               server: a.example.com\n\
               port: 8388\n\
               cipher: aes-128-gcm\n\
               password: pass\n\
               dialer-proxy: front\n\
               <<: *missing\n\
             preview: |\n\
               ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n",
        )
        .unwrap();
        p.refresh()
            .await
            .expect_err("malformed quoted-key YAML with a preview share-link must fail");
        assert_eq!(slot_names(&p.slot), ["A"]);
        assert_eq!(
            p.declared_dialer_names(),
            ["front"],
            "last-good must keep dialer-proxy; harvested ss://#A would drop the front hop"
        );
    }

    /// One broken SS share-link in a mixed feed must not empty a strict
    /// provider — the valid sibling is kept.
    #[tokio::test]
    async fn strict_refresh_skips_malformed_ss_share_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.yaml");
        std::fs::write(
            &path,
            "ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n\
             ss://:@b.example.com:443#Broken\n",
        )
        .unwrap();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "airport",
            &raw,
            Some(dir.path()),
            true,
            true,
            Default::default(),
        )
        .unwrap();
        p.refresh()
            .await
            .expect("one broken SS line must not fail the whole payload");
        assert_eq!(slot_names(&p.slot), ["A"]);
    }

    /// Empty-password trojan in a mixed share-link feed is skipped; the
    /// valid SS sibling is kept even in strict mode.
    #[tokio::test]
    async fn strict_refresh_skips_empty_trojan_share_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.yaml");
        std::fs::write(
            &path,
            "ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n\
             trojan://@b.example.com:443#Broken\n",
        )
        .unwrap();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "airport",
            &raw,
            Some(dir.path()),
            true,
            true,
            Default::default(),
        )
        .unwrap();
        p.refresh()
            .await
            .expect("one empty-password trojan must not fail the whole payload");
        assert_eq!(slot_names(&p.slot), ["A"]);
    }

    fn override_map(value: serde_json::Value) -> HashMap<String, serde_json::Value> {
        serde_json::from_value(value).expect("override object")
    }

    async fn provider_with_override(
        path: &std::path::Path,
        raw: RawProxyProvider,
    ) -> ProxyProvider {
        let cache_dir = path.parent().expect("temp file has a parent dir");
        let p = ProxyProvider::new(
            "car",
            &raw,
            Some(cache_dir),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        p
    }

    #[tokio::test]
    async fn provider_override_applies_fields_and_name_affixes() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(tmp.path(), &[("US 1", "ss"), ("US 2", "ss")]);
        let mut raw = raw_file_provider(tmp.path().to_str().unwrap());
        raw.override_ = Some(override_map(serde_json::json!({
            "additional-prefix": "[Car] ",
            "additional-suffix": " ✈",
            "udp": false,
            "skip-cert-verify": true,
            "ip-version": "ipv4"
        })));
        let provider = provider_with_override(tmp.path(), raw).await;
        assert_eq!(slot_names(&provider.slot), ["[Car] US 1 ✈", "[Car] US 2 ✈"]);
    }

    /// Upstream order: the name filters run on the names the feed published,
    /// then `override` rewrites them. Filtering after the affixes would drop
    /// every node of a provider that prefixes its names.
    #[tokio::test]
    async fn provider_override_filters_on_the_original_name() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(tmp.path(), &[("Car 01", "ss"), ("Other 01", "ss")]);
        let mut raw = raw_file_provider(tmp.path().to_str().unwrap());
        raw.filter = Some("^Car".to_string());
        raw.override_ = Some(override_map(serde_json::json!({
            "additional-prefix": "[X] "
        })));
        let provider = provider_with_override(tmp.path(), raw).await;
        assert_eq!(slot_names(&provider.slot), ["[X] Car 01"]);
    }

    /// A wrongly-typed override is a build error, not a silent skip —
    /// upstream's YAML unmarshal rejects it before any fetch happens.
    #[test]
    fn provider_override_rejects_wrong_type() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut raw = raw_file_provider(tmp.path().to_str().unwrap());
        raw.override_ = Some(override_map(serde_json::json!({
            "udp": "yes"
        })));
        let cache_dir = tmp.path().parent().expect("temp file has a parent dir");
        let err = ProxyProvider::new(
            "car",
            &raw,
            Some(cache_dir),
            true,
            false,
            Default::default(),
        )
        .err()
        .expect("a wrongly-typed override must fail the build");
        assert!(err.contains("must be a boolean"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn derived_slot_applies_group_filter() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(
            tmp.path(),
            &[("US 1", "ss"), ("US 2", "ss"), ("HK 1", "ss")],
        );
        let provider = file_provider(tmp.path()).await;

        let f = group_filter(Some("(?i)us"), Some("2"), None);
        let derived = provider.derived_slot(&f);
        assert_eq!(slot_names(&derived), ["US 1"]);
        // The provider's own slot stays unfiltered.
        assert_eq!(provider.proxies().len(), 3);
    }

    #[tokio::test]
    async fn derived_slot_updates_on_refresh_and_prunes_dropped_views() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(tmp.path(), &[("US 1", "ss"), ("HK 1", "ss")]);
        let provider = file_provider(tmp.path()).await;

        let f = group_filter(Some("US"), None, None);
        let derived = provider.derived_slot(&f);
        assert_eq!(slot_names(&derived), ["US 1"]);

        write_provider_file(
            tmp.path(),
            &[("US 1", "ss"), ("US 9", "ss"), ("HK 2", "ss")],
        );
        provider.refresh().await.unwrap();
        assert_eq!(slot_names(&derived), ["US 1", "US 9"]);

        drop(derived);
        // The dedup short-circuit skips commit on byte-identical
        // payloads — a dead view is pruned on the next *changed* payload
        // (or at commit-time `prune_dead_derived`), so the refresh that
        // observes the drop must carry new content.
        write_provider_file(tmp.path(), &[("US 1", "ss"), ("HK 3", "ss")]);
        provider.refresh().await.unwrap();
        assert_eq!(provider.derived_len(), 0);
    }

    #[tokio::test]
    async fn derived_slot_exclude_type_accepts_alias_and_display_name() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(tmp.path(), &[("US ss", "ss"), ("US direct", "direct")]);
        let provider = file_provider(tmp.path()).await;

        // Note: parse_direct keeps DirectAdapter's hardcoded "DIRECT" name.
        let by_alias = provider.derived_slot(&group_filter(None, None, Some(&["ss"])));
        assert_eq!(slot_names(&by_alias), ["DIRECT"]);

        let by_display = provider.derived_slot(&group_filter(None, None, Some(&["Shadowsocks"])));
        assert_eq!(slot_names(&by_display), ["DIRECT"]);

        // mihomo-style `|`-separated string form.
        let piped = provider.derived_slot(&group_filter(None, None, Some(&["ss|direct"])));
        assert!(slot_names(&piped).is_empty());
    }

    #[test]
    fn group_filter_absent_fields_yield_none() {
        let raw = crate::raw::RawProxyGroup {
            name: "g".to_string(),
            group_type: "select".to_string(),
            ..Default::default()
        };
        assert!(GroupFilter::from_raw_group(&raw).unwrap().is_none());
    }

    #[tokio::test]
    async fn group_filter_negative_lookahead_matches_mihomo_semantics() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(
            tmp.path(),
            &[
                ("US 1", "ss"),
                ("剩余流量: 10G", "ss"),
                ("到期: 2026", "ss"),
            ],
        );
        let provider = file_provider(tmp.path()).await;

        // The exact mihomo idiom airport configs use to drop info nodes.
        let f = group_filter(Some("^(?!.*(流量|到期))"), None, None);
        let derived = provider.derived_slot(&f);
        assert_eq!(slot_names(&derived), ["US 1"]);
    }

    #[tokio::test]
    async fn provider_filter_negative_lookahead_filters_payload() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(
            tmp.path(),
            &[
                ("US 1", "ss"),
                ("剩余流量: 10G", "ss"),
                ("官网 example.com", "ss"),
            ],
        );
        let mut raw = raw_file_provider(tmp.path().to_str().unwrap());
        raw.filter = Some("^(?!.*(流量|官网))".to_string());
        let cache_dir = tmp.path().parent().expect("temp file has a parent dir");
        let p = ProxyProvider::new(
            "airport",
            &raw,
            Some(cache_dir),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(slot_names(&p.slot), ["US 1"]);
    }

    // ─── issue #489: provider-sourced nodes honour `dialer-proxy` ─────────

    /// Front-hop mock: records the metadata of every `dial_tcp` and refuses
    /// the connection. A chained node's adapter dials its *server* through
    /// this front hop, so observing the dial proves the chain was applied.
    struct RecordingFront {
        seen: std::sync::Mutex<Vec<meow_common::Metadata>>,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for RecordingFront {
        fn name(&self) -> &str {
            "front"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Socks5
        }
        fn addr(&self) -> &str {
            "127.0.0.1:1080"
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            metadata: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            self.seen.lock().unwrap().push(metadata.clone());
            Err(meow_common::MeowError::NotSupported(
                "recording front refuses connections".to_string(),
            ))
        }
        async fn dial_udp(
            &self,
            _metadata: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            unimplemented!("test mock has no UDP")
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            static H: std::sync::OnceLock<meow_common::ProxyHealth> = std::sync::OnceLock::new();
            H.get_or_init(meow_common::ProxyHealth::new)
        }
    }

    impl Proxy for RecordingFront {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            Vec::new()
        }
    }

    /// A provider node carrying `dialer-proxy: front` must dial its server
    /// through `front`, resolved by name against the registry at dial time.
    #[tokio::test]
    async fn provider_node_dialer_proxy_chains_through_registry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            // Loopback + port 1: if the chain is ever dropped the direct
            // dial refuses instantly instead of hanging on a connect
            // timeout to an unreachable TEST-NET address.
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, \
             port: 1, dialer-proxy: front}\n",
        )
        .unwrap();
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            registry.clone(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let node = p.proxies().into_iter().next().expect("node must parse");
        assert_eq!(p.declared_dialer_names(), ["front"]);

        // Publishing the front hop makes the chain resolvable; the dial
        // fails at the refusing front, but only after reaching it.
        let front = Arc::new(RecordingFront {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let front_entry = Arc::clone(&front) as Arc<dyn Proxy>;
        let mut map: HashMap<smol_str::SmolStr, Arc<dyn Proxy>> = HashMap::new();
        map.insert("front".into(), front_entry);
        registry.publish(Arc::new(map));

        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert!(node.dial_tcp(&meta).await.is_err());
        let seen = front.seen.lock().unwrap();
        let [dial] = seen.as_slice() else {
            panic!("the chained dial must reach the front hop: {seen:?}")
        };
        // The socks5 adapter dials its server through the chain — the front
        // sees the *server* as the target, not the user destination.
        assert_eq!(dial.dst_ip, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(dial.dst_port, 1);
        assert_eq!(dial.conn_type, meow_common::ConnType::Inner);
    }

    /// Malformed or self-referencing `dialer-proxy` values reject the node
    /// outright — warn-skipping just the edge would leave it dialling
    /// direct, a silent misroute on remote-controlled content.
    #[tokio::test]
    async fn provider_node_bad_dialer_proxy_rejects_node() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n\
             \x20 - {name: bad-value, type: socks5, server: 203.0.113.9, port: 1081, dialer-proxy: 7}\n\
             \x20 - {name: self-ref, type: socks5, server: 203.0.113.9, port: 1081, dialer-proxy: self-ref}\n\
             \x20 - {name: ok, type: socks5, server: 203.0.113.9, port: 1081}\n",
        )
        .unwrap();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(
            slot_names(&p.slot),
            ["ok"],
            "malformed and self-referencing chains must reject their nodes"
        );
        assert!(p.declared_dialer_names().is_empty());
    }

    /// A node whose dialer name is absent from the registry keeps building
    /// (the name may arrive with a later config) but fails loudly at dial
    /// time rather than falling back to a direct dial.
    #[tokio::test]
    async fn provider_node_unresolvable_dialer_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: n1, type: socks5, server: 203.0.113.9, \
             port: 1081, dialer-proxy: ghost}\n",
        )
        .unwrap();
        // Default registry — never published, resolves nothing.
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let node = p.proxies().into_iter().next().expect("node must parse");

        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let err = node.dial_tcp(&meta).await.err().expect("must fail");
        assert!(
            err.to_string().contains("ghost"),
            "the error must name the missing dialer: {err}"
        );
    }

    /// A node whose adapter type cannot carry an injected dialer falls back
    /// to `DialerProxyAdapter`: the front hop dials the *final destination*
    /// (relay skips the address-less `direct` hop) — observably different
    /// from the injected path, where the front sees the node server.
    #[tokio::test]
    async fn provider_node_unthreadable_type_uses_relay_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: d1, type: direct, dialer-proxy: front}\n",
        )
        .unwrap();
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            registry.clone(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let node = p.proxies().into_iter().next().expect("node must parse");

        let front = Arc::new(RecordingFront {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut map: HashMap<smol_str::SmolStr, Arc<dyn Proxy>> = HashMap::new();
        map.insert("front".into(), Arc::clone(&front) as Arc<dyn Proxy>);
        registry.publish(Arc::new(map));

        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert!(node.dial_tcp(&meta).await.is_err());
        let seen = front.seen.lock().unwrap();
        let [dial] = seen.as_slice() else {
            panic!("the relay fallback must reach the front hop: {seen:?}")
        };
        assert_eq!(dial.host, "example.com", "front must see the final target");
        assert_eq!(dial.dst_port, 443);
    }

    /// `dialer-proxy` may name a group — the group's selection is the front
    /// hop (mihomo's documented shape).
    #[tokio::test]
    async fn provider_node_dialer_proxy_resolves_a_group() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, \
             port: 1, dialer-proxy: g}\n",
        )
        .unwrap();
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            registry.clone(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let node = p.proxies().into_iter().next().expect("node must parse");

        let front = Arc::new(RecordingFront {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let group: Arc<dyn Proxy> = Arc::new(meow_proxy::SelectorGroup::new(
            "g",
            vec![Arc::clone(&front) as Arc<dyn Proxy>],
        ));
        let mut map: HashMap<smol_str::SmolStr, Arc<dyn Proxy>> = HashMap::new();
        map.insert("g".into(), group);
        registry.publish(Arc::new(map));

        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert!(node.dial_tcp(&meta).await.is_err());
        let seen = front.seen.lock().unwrap();
        let [dial] = seen.as_slice() else {
            panic!("the chain must resolve the group's selected member: {seen:?}")
        };
        assert_eq!(dial.dst_ip, Some("127.0.0.1".parse().unwrap()));
    }

    /// `override.dialer-proxy` applies unconditionally — it outranks even a
    /// node-level declaration (mihomo OverrideSchema.Apply precedence).
    #[tokio::test]
    async fn provider_override_dialer_proxy_applies_to_all_nodes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n\
             \x20 - {name: inherited, type: socks5, server: 203.0.113.9, port: 1081}\n\
             \x20 - {name: own, type: socks5, server: 203.0.113.9, port: 1081, dialer-proxy: other}\n",
        )
        .unwrap();
        let mut raw = raw_file_provider("nodes.yaml");
        raw.override_ = Some(HashMap::from([(
            "dialer-proxy".to_string(),
            serde_json::Value::String("front".to_string()),
        )]));
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let mut declared = p.declared_dialer_names();
        declared.sort();
        assert_eq!(
            declared,
            ["front"],
            "override wins unconditionally — the node's own dialer-proxy is ignored"
        );
        assert_eq!(slot_names(&p.slot).len(), 2);
    }

    /// Provider-level `dialer-proxy` outranks node-level fields but is
    /// itself overridden by `override.dialer-proxy` (upstream `provider.go`
    /// writes it into every mapping before `Apply` runs).
    #[tokio::test]
    async fn provider_level_dialer_proxy_overrides_node_level() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n\
             \x20 - {name: inherited, type: socks5, server: 203.0.113.9, port: 1081}\n\
             \x20 - {name: own, type: socks5, server: 203.0.113.9, port: 1081, dialer-proxy: other}\n",
        )
        .unwrap();
        let mut raw = raw_file_provider("nodes.yaml");
        raw.dialer_proxy = Some("front".to_string());
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(
            p.declared_dialer_names(),
            ["front"],
            "provider-level dialer-proxy must override node-level fields"
        );
    }

    /// The top of the precedence stack: `override.dialer-proxy` must beat a
    /// provider-level `dialer-proxy` too — `OverrideSchema.Apply` writes
    /// last upstream, and swapping the `or` arms would silently invert it.
    #[tokio::test]
    async fn provider_override_dialer_proxy_beats_provider_level() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, port: 1}\n",
        )
        .unwrap();
        let mut raw = raw_file_provider("nodes.yaml");
        raw.dialer_proxy = Some("p-hop".to_string());
        raw.override_ = Some(HashMap::from([(
            "dialer-proxy".to_string(),
            serde_json::Value::String("o-hop".to_string()),
        )]));
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            registry.clone(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(
            p.declared_dialer_names(),
            ["o-hop"],
            "override must outrank the provider-level field"
        );

        // Observable dial: only the o-hop front is published, so reaching
        // it proves the winner propagates to the node's injected dialer.
        let front = Arc::new(RecordingFront {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut map: HashMap<smol_str::SmolStr, Arc<dyn Proxy>> = HashMap::new();
        map.insert("o-hop".into(), Arc::clone(&front) as Arc<dyn Proxy>);
        registry.publish(Arc::new(map));
        let node = p.proxies().into_iter().next().expect("node must parse");
        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert!(node.dial_tcp(&meta).await.is_err());
        assert_eq!(
            front.seen.lock().unwrap().len(),
            1,
            "the dial must reach the override-named front hop"
        );
    }

    /// `override.dialer-proxy: ""` is upstream's "clear the chain" knob:
    /// `Apply` writes the empty string unconditionally, stripping both the
    /// provider-level field and the node's own — the node must dial
    /// *direct*, not chain to either lower-level name.
    #[tokio::test]
    async fn provider_override_empty_dialer_proxy_clears_chain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, \
             port: 1, dialer-proxy: node-hop}\n",
        )
        .unwrap();
        let mut raw = raw_file_provider("nodes.yaml");
        raw.dialer_proxy = Some("provider-hop".to_string());
        raw.override_ = Some(HashMap::from([(
            "dialer-proxy".to_string(),
            serde_json::Value::String(String::new()),
        )]));
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(
            p.declared_dialer_names(),
            Vec::<String>::new(),
            "a cleared chain declares no dialer names"
        );

        // The dial must go direct: refusal from 127.0.0.1:1, not a
        // registry miss naming either lower-level hop.
        let node = p.proxies().into_iter().next().expect("node must parse");
        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let err = node
            .dial_tcp(&meta)
            .await
            .err()
            .expect("127.0.0.1:1 refuses");
        assert!(
            !err.to_string().contains("hop"),
            "cleared chain must not resolve any dialer name: {err}"
        );
    }

    /// A whitespace-only `dialer-proxy` is remote garbage, not an unset
    /// marker — treat it as malformed (reject the node) rather than
    /// silently dialling direct. `""` and `~` stay unset (upstream's
    /// `len > 0` check).
    #[tokio::test]
    async fn provider_node_whitespace_dialer_proxy_rejects_node() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n\
             \x20 - {name: blank, type: socks5, server: 127.0.0.1, port: 1, dialer-proxy: ' '}\n\
             \x20 - {name: empty, type: socks5, server: 127.0.0.1, port: 1, dialer-proxy: ''}\n",
        )
        .unwrap();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let names: Vec<String> = p.proxies().iter().map(|n| n.name().to_string()).collect();
        assert_eq!(
            names,
            ["empty"],
            "whitespace dialer-proxy must reject the node; empty stays unset"
        );
    }

    /// A `type: rematch` node can never carry the chain — a provider-
    /// or override-level `dialer-proxy` parses it bare instead of
    /// wrapping it in `DialerProxyAdapter` (which hides the rematch
    /// action), and a blank node-level `dialer-proxy` is unset like
    /// `check_rematch_node` says, not malformed (issue #974).
    #[tokio::test]
    async fn provider_dialer_never_wraps_rematch_nodes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n\
             \x20 - {name: inspect, type: rematch, target-rematch-name: s}\n\
             \x20 - {name: blank, type: rematch, target-rematch-name: s, dialer-proxy: ' '}\n\
             \x20 - {name: bad, type: rematch, target-rematch-name: s, dialer-proxy: front}\n",
        )
        .unwrap();
        let mut raw = raw_file_provider("nodes.yaml");
        raw.dialer_proxy = Some("front".to_string());
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let members = p.proxies();
        // `bad` (a non-blank node-level `dialer-proxy`) drops on
        // `check_rematch_node`; the kept leaves report their action —
        // the provider-level chain must not have wrapped them.
        let mut names: Vec<String> = members.iter().map(|n| n.name().to_string()).collect();
        names.sort();
        assert_eq!(names, ["blank", "inspect"]);
        for member in &members {
            assert!(
                member.rematch_action().is_some(),
                "{} must keep its rematch action",
                member.name()
            );
        }
    }

    /// A hosts-only resolver answering `host` → `ip` locally — the dns
    /// leaf's local fast path needs no upstream.
    fn hosts_resolver(host: &str, ip: std::net::IpAddr) -> meow_dns::resolver::Resolver {
        let mut hosts = meow_trie::DomainTrie::new();
        hosts.insert(host, meow_dns::HostEntry::Addresses(vec![ip]));
        meow_dns::resolver::Resolver::new(
            Vec::new(),
            Vec::new(),
            meow_common::DnsMode::Normal,
            hosts,
            true,
            true,
        )
    }

    /// A `type: dns` provider node reads no transport fields at all:
    /// node-level `dialer-proxy` — of any shape, even ill-typed — the
    /// provider's own `dialer-proxy:` and `override.dialer-proxy` are all
    /// peeled before the leaf parses, so the members land as bare
    /// `AdapterType::Dns` leaves bound to the provider's dns cell
    /// (issue #974).
    #[tokio::test]
    async fn provider_dns_nodes_parse_bare_and_bind_the_provider_cell() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n\
             \x20 - {name: plain, type: dns}\n\
             \x20 - {name: chained, type: dns, dialer-proxy: front}\n\
             \x20 - {name: malformed, type: dns, dialer-proxy: [a, b]}\n\
             \x20 - {name: endpointish, type: dns, server: 8.8.8.8, port: 53, udp: false}\n",
        )
        .unwrap();
        let mut raw = raw_file_provider("nodes.yaml");
        raw.dialer_proxy = Some("front".to_string());
        raw.override_ = Some(HashMap::from([(
            "dialer-proxy".to_string(),
            serde_json::Value::String("enforced".to_string()),
        )]));
        let dns_cell = meow_dns::new_dns_outbound_cell();
        let p = ProxyProvider::new_with_client_fingerprint(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
            None,
            Some(Arc::clone(&dns_cell)),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let members = p.proxies();
        let mut names: Vec<String> = members.iter().map(|n| n.name().to_string()).collect();
        names.sort();
        // Every node survives — unlike rematch, dns tolerates even a
        // malformed `dialer-proxy`, which mihomo never reads.
        assert_eq!(names, ["chained", "endpointish", "malformed", "plain"]);
        for member in &members {
            assert_eq!(member.adapter_type(), meow_common::AdapterType::Dns);
            assert!(
                !member
                    .as_any()
                    .is_some_and(<dyn std::any::Any>::is::<meow_proxy::DialerProxyAdapter>),
                "{} must not be chain-wrapped",
                member.name()
            );
        }

        // The provider's cell is the live indirection: populating it
        // after the parse reaches the already-built leaf — a provider
        // node parsed before DNS exists still serves the generation the
        // commit installs (issue #974).
        let leaf = members
            .iter()
            .find(|m| m.name() == "plain")
            .expect("the dns leaf lands");
        let metadata = meow_common::Metadata {
            network: meow_common::Network::Tcp,
            host: "example.com".into(),
            dst_port: 53,
            ..Default::default()
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = leaf.dial_tcp(&metadata).await.expect("dial succeeds");
        let query: &[u8] = &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
        ];
        let len = (query.len() as u16).to_be_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(query).await.unwrap();
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body[3] & 0x0f, 2, "unbound cell → SERVFAIL, not a drop");

        *dns_cell.write() = Some(meow_dns::new_resolver_slot(Arc::new(hosts_resolver(
            "example.com",
            "10.9.9.9".parse().unwrap(),
        ))));
        let mut stream = leaf.dial_tcp(&metadata).await.expect("dial succeeds");
        stream.write_all(&len).await.unwrap();
        stream.write_all(query).await.unwrap();
        stream.read_exact(&mut prefix).await.unwrap();
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body[3] & 0x0f, 0, "the installed generation answers");
        assert!(body.windows(4).any(|w| w == [10, 9, 9, 9]));
    }

    /// The same shape through `parse_node` directly — the leaf the
    /// provider slot materializes. This is the parity the static
    /// `proxies:` lane's `dns_leaf_unbound_cell_fails_closed` pins.
    #[tokio::test]
    async fn provider_dns_node_unbound_cell_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: dns-out, type: dns}\n",
        )
        .unwrap();
        let p = ProxyProvider::new(
            "test",
            &raw_file_provider("nodes.yaml"),
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let leaf = &p.proxies()[0];
        assert_eq!(leaf.adapter_type(), meow_common::AdapterType::Dns);
        // `ProxyProvider::new` passes no cell — an embedder without the
        // config lane gets an unbound leaf, which fails closed.
        let metadata = meow_common::Metadata::default();
        let conn = leaf.dial_udp(&metadata).await.expect("udp dial succeeds");
        let dst = "9.9.9.9:53".parse().unwrap();
        let query: &[u8] = &[
            0x00, 0x2a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
        ];
        conn.write_packet(query, &dst).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read_packet(&mut buf),
        )
        .await
        .expect("SERVFAIL still replies")
        .unwrap();
        assert!(n >= 12);
        assert_eq!(buf[3] & 0x0f, 2);
    }

    /// `dialer-proxy` reaching a `type: dns` member from either stronger
    /// level — the provider's own `dialer-proxy:` or `override.dialer-proxy`
    /// — must warn rather than apply silently: an enforcement knob the
    /// operator believes chains the node is being dropped (issue #974
    /// review). The node-level key already warns inside `parse_dns_node`.
    #[tokio::test]
    async fn provider_dns_node_dialer_levels_warn() {
        crate::test_support::install_global_discard_subscriber();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: dns-out, type: dns, dialer-proxy: node-front}\n",
        )
        .unwrap();
        let dns_cell = meow_dns::new_dns_outbound_cell();

        // Provider-level only — the warning names the provider's front.
        let mut raw = raw_file_provider("nodes.yaml");
        raw.dialer_proxy = Some("front".to_string());
        let p = ProxyProvider::new_with_client_fingerprint(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
            None,
            Some(Arc::clone(&dns_cell)),
        )
        .unwrap();
        let cap = crate::test_support::WarnCapture::start();
        p.refresh().await.unwrap();
        let warns = cap.take();
        assert!(
            warns.contains("ignores `dialer-proxy` 'front'"),
            "the provider-level front must warn: {warns}"
        );
        assert!(
            warns.contains("`dialer-proxy` is ignored on type: dns"),
            "the node-level key must warn: {warns}"
        );

        // `override` beats the provider level — the warning names the
        // enforcement that actually reaches the node, and 'front' never
        // surfaces.
        let mut raw = raw_file_provider("nodes.yaml");
        raw.dialer_proxy = Some("front".to_string());
        raw.override_ = Some(HashMap::from([(
            "dialer-proxy".to_string(),
            serde_json::Value::String("enforced".to_string()),
        )]));
        let p = ProxyProvider::new_with_client_fingerprint(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
            None,
            Some(Arc::clone(&dns_cell)),
        )
        .unwrap();
        let cap = crate::test_support::WarnCapture::start();
        p.refresh().await.unwrap();
        let warns = cap.take();
        assert!(
            warns.contains("ignores `dialer-proxy` 'enforced'"),
            "the override front must warn: {warns}"
        );
        assert!(
            !warns.contains("`dialer-proxy` 'front'"),
            "the overridden provider front must not warn: {warns}"
        );

        // `override.dialer-proxy: ""` is the explicit clear — it overwrites
        // the provider level too, so no front reaches the node and nothing
        // warns.
        let mut raw = raw_file_provider("nodes.yaml");
        raw.dialer_proxy = Some("front".to_string());
        raw.override_ = Some(HashMap::from([(
            "dialer-proxy".to_string(),
            serde_json::Value::String(String::new()),
        )]));
        let p = ProxyProvider::new_with_client_fingerprint(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
            None,
            Some(Arc::clone(&dns_cell)),
        )
        .unwrap();
        let cap = crate::test_support::WarnCapture::start();
        p.refresh().await.unwrap();
        let warns = cap.take();
        assert!(
            !warns.contains("ignores `dialer-proxy`"),
            "an empty override must not warn as an enforced front: {warns}"
        );
    }

    /// A refresh that *changes* the `dialer-proxy` name must retarget the
    /// chain — not just re-apply or drop it.
    #[tokio::test]
    async fn provider_refresh_dialer_name_change_retargets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.yaml");
        std::fs::write(
            &path,
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, \
             port: 1, dialer-proxy: first}\n",
        )
        .unwrap();
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            registry.clone(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(p.declared_dialer_names(), ["first"]);

        std::fs::write(
            &path,
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, \
             port: 1, dialer-proxy: second}\n",
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(
            p.declared_dialer_names(),
            ["second"],
            "refresh must retarget the chain to the new name"
        );

        // The dial must resolve the NEW name — `first` stays unresolvable.
        let front = Arc::new(RecordingFront {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut map: HashMap<smol_str::SmolStr, Arc<dyn Proxy>> = HashMap::new();
        map.insert("second".into(), Arc::clone(&front) as Arc<dyn Proxy>);
        registry.publish(Arc::new(map));
        let node = p.proxies().into_iter().next().expect("node must parse");
        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert!(node.dial_tcp(&meta).await.is_err());
        assert_eq!(front.seen.lock().unwrap().len(), 1);
    }

    /// Under `strict` a malformed `dialer-proxy` fails the refresh — and the
    /// last-good generation (slot *and* declared names) must stay live,
    /// not clear to nothing.
    #[tokio::test]
    async fn provider_strict_refresh_keeps_last_good_on_bad_dialer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.yaml");
        std::fs::write(
            &path,
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, \
             port: 1, dialer-proxy: front}\n",
        )
        .unwrap();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            true,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(p.declared_dialer_names(), ["front"]);

        std::fs::write(
            &path,
            "proxies:\n  - {name: bad, type: socks5, server: 127.0.0.1, \
             port: 1, dialer-proxy: 7}\n",
        )
        .unwrap();
        p.refresh()
            .await
            .expect_err("strict refresh must fail on a malformed dialer-proxy");
        assert_eq!(
            p.proxies().len(),
            1,
            "the last-good slot must survive a strict parse failure"
        );
        assert_eq!(
            p.declared_dialer_names(),
            ["front"],
            "declared names must describe the still-live generation"
        );
    }

    /// A malformed `override.dialer-proxy` must fail the provider build —
    /// warn-skipping it would silently drop the operator's enforced chain.
    #[tokio::test]
    async fn malformed_override_dialer_proxy_rejects_provider() {
        let dir = tempfile::tempdir().unwrap();
        let mut raw = raw_file_provider("nodes.yaml");
        raw.override_ = Some(HashMap::from([(
            "dialer-proxy".to_string(),
            serde_json::Value::Number(42.into()),
        )]));
        let err = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .map(|_| ())
        .expect_err("malformed override.dialer-proxy must fail");
        assert!(
            err.contains("override.dialer-proxy"),
            "error must name the field: {err}"
        );
    }

    /// A `dialer-proxy` arriving via a YAML merge key must be honoured —
    /// without merge-key expansion the merged field lands on a literal `<<`
    /// key and the node silently dials direct.
    #[tokio::test]
    async fn provider_node_merge_key_dialer_proxy_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "chain: &chain\n  dialer-proxy: front\n\
             proxies:\n  - {name: n1, type: socks5, server: 203.0.113.9, \
             port: 1081, <<: *chain}\n",
        )
        .unwrap();
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            registry.clone(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(p.declared_dialer_names(), ["front"]);

        let front = Arc::new(RecordingFront {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut map: HashMap<smol_str::SmolStr, Arc<dyn Proxy>> = HashMap::new();
        map.insert("front".into(), Arc::clone(&front) as Arc<dyn Proxy>);
        registry.publish(Arc::new(map));

        let node = p.proxies().into_iter().next().expect("node must parse");
        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert!(node.dial_tcp(&meta).await.is_err());
        assert_eq!(
            front.seen.lock().unwrap().len(),
            1,
            "merged dialer-proxy must chain"
        );
    }

    /// Refresh re-applies `dialer-proxy` per payload generation: a refreshed
    /// payload without the field reverts the node to direct dialling, and a
    /// payload that fails to parse leaves no stale declarations.
    #[tokio::test]
    async fn provider_refresh_reapplies_dialer_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.yaml");
        std::fs::write(
            &path,
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, \
             port: 1, dialer-proxy: front}\n",
        )
        .unwrap();
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            registry.clone(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(p.declared_dialer_names(), ["front"]);

        let front = Arc::new(RecordingFront {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut map: HashMap<smol_str::SmolStr, Arc<dyn Proxy>> = HashMap::new();
        map.insert("front".into(), Arc::clone(&front) as Arc<dyn Proxy>);
        registry.publish(Arc::new(map));

        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let node = p.proxies().into_iter().next().unwrap();
        assert!(node.dial_tcp(&meta).await.is_err());
        assert_eq!(front.seen.lock().unwrap().len(), 1);

        // Generation 2 drops the field — the rebuilt node dials its server
        // directly (127.0.0.1:1 refuses fast) and the declaration clears.
        std::fs::write(
            &path,
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, port: 1}\n",
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert!(p.declared_dialer_names().is_empty());
        let node = p.proxies().into_iter().next().unwrap();
        assert!(node.dial_tcp(&meta).await.is_err());
        assert_eq!(
            front.seen.lock().unwrap().len(),
            1,
            "a node without dialer-proxy must not touch the front hop"
        );

        // Generation 3 is malformed — a document-level defect fails the
        // refresh in both modes and keeps the last-good slot (upstream
        // `loadBuf`: a parser error is a failed update, not an empty
        // commit — critical now that interval ticks make this unattended).
        std::fs::write(&path, "proxies: [unclosed\n").unwrap();
        p.refresh()
            .await
            .expect_err("a malformed payload must fail the refresh");
        assert_eq!(
            p.proxies().len(),
            1,
            "a torn refresh keeps the last-good set"
        );
    }

    /// A byte-identical payload must not churn: upstream's `loadBuf` hash
    /// early-return means `updated_at` and the committed adapters only
    /// change on real content changes — otherwise every interval tick
    /// rebuilds every node and derived view for nothing (issue #625
    /// review).
    #[tokio::test]
    async fn refresh_skips_unchanged_payload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.yaml");
        std::fs::write(
            &path,
            "proxies:\n  - {name: n1, type: socks5, server: 203.0.113.9, port: 1081}\n",
        )
        .unwrap();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let first = p.proxies();

        // Identical content (mtime-bumped rewrite) → no re-commit: the
        // adapter Arcs are literally the same objects.
        std::fs::write(
            &path,
            "proxies:\n  - {name: n1, type: socks5, server: 203.0.113.9, port: 1081}\n",
        )
        .unwrap();
        p.refresh().await.unwrap();
        let second = p.proxies();
        assert!(
            Arc::ptr_eq(&first[0], &second[0]),
            "an unchanged payload must not rebuild adapters"
        );

        // Real content change → fresh commit.
        std::fs::write(
            &path,
            "proxies:\n  - {name: n1, type: socks5, server: 203.0.113.9, port: 1081}\n\
             \x20 - {name: n2, type: direct}\n",
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert_eq!(p.proxies().len(), 2);
        assert!(
            !Arc::ptr_eq(&p.proxies()[0], &first[0]),
            "a changed payload must rebuild adapters"
        );
    }

    /// A `dialer-proxy`-carrying node dropped by the provider's own filters
    /// must not leave a declaration behind — otherwise the config build
    /// warns about a reference nothing makes (issue #489 review).
    #[tokio::test]
    async fn provider_filtered_dialer_node_declares_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: n1, type: socks5, server: 203.0.113.9, \
             port: 1081, dialer-proxy: front}\n",
        )
        .unwrap();
        let mut raw = raw_file_provider("nodes.yaml");
        raw.exclude_type = Some(vec!["socks5".to_string()]);
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        assert!(p.proxies().is_empty(), "node must be filtered out");
        assert!(
            p.declared_dialer_names().is_empty(),
            "a filtered node must not declare a dialer target"
        );
    }

    /// A chained provider node whose named front cannot be resolved must
    /// fail closed on UDP: `supports_udp()` snapshots `false` for the
    /// unresolvable front so `support_udp()` reports false, and `dial_udp`
    /// refuses rather than binding a raw socket on the real source path
    /// (enforced inside the adapter because the tunnel's UDP dispatch does
    /// not consult `support_udp`).
    #[tokio::test]
    async fn provider_chained_node_udp_fails_closed_with_missing_front() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: n1, type: socks5, server: 203.0.113.9, \
             port: 1081, udp: true, dialer-proxy: front}\n",
        )
        .unwrap();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();
        let node = p.proxies().into_iter().next().expect("node must parse");
        assert!(!node.support_udp(), "chained node must not claim UDP");
        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 53,
            network: meow_common::Network::Udp,
            ..Default::default()
        };
        assert!(
            node.dial_udp(&meta).await.is_err(),
            "UDP over a TCP front-hop chain must fail, not leak direct"
        );
    }

    /// The #969 marker on the provider path: an injected `dialer-proxy`
    /// leaf carries no `DialerProxyAdapter` to report the configured
    /// chain, so `parse_node` marks it `ChainedProxy` — the same verdict
    /// `insert_parsed_leaves`' `parse_dialered_leaf` pins on static
    /// `proxies:` entries. Without it a group whose pick lands on this
    /// node would let a matched UDP flow slide to a later rule's target.
    #[tokio::test]
    async fn provider_injected_leaf_marked_via_chainedproxy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: n1, type: socks5, server: 203.0.113.9, \
             port: 1081, udp: true, dialer-proxy: front}\n  \
             - {name: n2, type: socks5, server: 203.0.113.10, port: 1081}\n",
        )
        .unwrap();
        let raw = raw_file_provider("nodes.yaml");
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        p.refresh().await.unwrap();

        let node = p
            .proxies()
            .into_iter()
            .find(|n| n.name() == "n1")
            .expect("n1 must parse");
        assert!(
            node.is_dialer_proxy_non_transparent(),
            "the injected leaf must carry the fail-closed marker (issue #969)"
        );
        assert!(
            !node.support_udp(),
            "an unresolvable front still caps the advertisement at false"
        );
        let plain = p
            .proxies()
            .into_iter()
            .find(|n| n.name() == "n2")
            .expect("n2 must parse");
        assert!(
            !plain.is_dialer_proxy_non_transparent(),
            "an unchained node must not bear the marker — mihomo's `continue` stands"
        );
    }

    /// `Proxy` that records each `dial_tcp` target and dials the real
    /// destination — proves a provider fetch actually transits the named
    /// hop instead of going direct (issue #625).
    struct PassthroughProxy {
        seen: std::sync::Mutex<Vec<(String, u16)>>,
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for PassthroughProxy {
        fn name(&self) -> &str {
            "front"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            self.seen
                .lock()
                .unwrap()
                .push((m.host.to_string(), m.dst_port));
            let stream = tokio::net::TcpStream::connect((m.host.as_str(), m.dst_port))
                .await
                .map_err(meow_common::MeowError::Io)?;
            Ok(Box::new(stream))
        }
        async fn dial_udp(
            &self,
            _m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            unimplemented!("no udp")
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl Proxy for PassthroughProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            Vec::new()
        }
    }

    /// Serves `body` as `proxies.yaml` on a loop, returning the URL.
    async fn spawn_payload_server(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut sink = [0u8; 2048];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut sink).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
            }
        });
        format!("http://{addr}/proxies.yaml")
    }

    fn raw_http_provider(url: &str, proxy: Option<&str>) -> RawProxyProvider {
        RawProxyProvider {
            provider_type: "http".to_string(),
            url: Some(url.to_string()),
            path: None,
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: None,
            override_: None,
            proxy: proxy.map(str::to_string),
            dialer_proxy: None,
            extra: Default::default(),
        }
    }

    fn registry_with_front(front: Arc<dyn Proxy>) -> meow_proxy::dialer::ProxyRegistry {
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        registry.publish(Arc::new(HashMap::from([(
            smol_str::SmolStr::from("front"),
            front,
        )])));
        registry
    }

    /// A node this build cannot parse costs exactly that node: the rest of
    /// the payload still loads, and the bad entry stays in the slot as a
    /// dead placeholder so a `use:` group can neither quietly shrink nor,
    /// once it is the only member left, degrade to a direct dial. Rejecting
    /// the payload instead would let the feed's operator empty the registry
    /// on every refresh tick.
    #[tokio::test]
    async fn unparseable_node_becomes_a_dead_placeholder_not_a_payload_rejection() {
        // `bad` lacks `username`, so every feature set rejects it (a
        // `quic: true` node alone would parse under `trusttunnel-h3`).
        let url = spawn_payload_server(
            "proxies:\n  - {name: good, type: direct}\n  - {name: bad, type: trusttunnel, server: vpn.example.test, port: 443, password: test-only}\n",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let provider = ProxyProvider::new(
            "p",
            &raw_http_provider(&url, None),
            Some(dir.path()),
            false,
            false,
            ProxyRegistry::default(),
        )
        .unwrap();
        provider
            .acquire_initial()
            .await
            .expect("one bad node must not reject the whole payload");

        let nodes = provider.proxies();
        assert_eq!(nodes.len(), 2, "the bad node keeps its slot entry");
        let bad = nodes
            .iter()
            .find(|proxy| proxy.name() == "bad")
            .expect("the unparseable node stays addressable by name");
        assert!(!bad.alive(), "a placeholder must never look usable");
        assert!(
            bad.dial_tcp(&meow_common::Metadata::default())
                .await
                .is_err(),
            "a placeholder must fail the dial instead of leaking it direct"
        );
        // The credential fields of the rejected node must not reach the
        // diagnostic the placeholder renders into every dial error.
        let error = bad
            .dial_tcp(&meow_common::Metadata::default())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("bad"), "{error}");
        assert!(!error.contains("test-only"), "{error}");
    }

    /// Same contract as the trusttunnel placeholder above, for an `ss` node
    /// whose reserved built-in plugin's cargo feature is compiled out: the
    /// payload still loads, the node keeps its slot bound dead as
    /// `Shadowsocks`, and its dial reason is the "not compiled into this
    /// build" error — no warn-drop, no feed rejection.
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[tokio::test]
    async fn missing_plugin_node_becomes_a_dead_ss_placeholder_not_a_payload_rejection() {
        let url = spawn_payload_server(
            "proxies:\n  - {name: good, type: direct}\n  - {name: dead-ss, type: ss, server: 1.2.3.4, port: 8388, password: p, cipher: aes-128-gcm, plugin: gost-plugin}\n",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let provider = ProxyProvider::new(
            "p",
            &raw_http_provider(&url, None),
            Some(dir.path()),
            false,
            false,
            ProxyRegistry::default(),
        )
        .unwrap();
        provider
            .acquire_initial()
            .await
            .expect("a missing-plugin node must not reject the whole payload");

        let nodes = provider.proxies();
        assert_eq!(nodes.len(), 2, "the dead node keeps its slot entry");
        let dead = nodes
            .iter()
            .find(|proxy| proxy.name() == "dead-ss")
            .expect("the unbuildable node stays addressable by name");
        assert!(!dead.alive(), "a placeholder must never look usable");
        assert_eq!(
            dead.adapter_type(),
            meow_common::AdapterType::Shadowsocks,
            "a placeholder must keep the node's own type"
        );
        let error = dead
            .dial_tcp(&meow_common::Metadata::default())
            .await
            .err()
            .expect("a placeholder must fail the dial, not leak it direct")
            .to_string();
        assert!(error.contains("dead-ss"), "{error}");
        assert!(
            error.contains("not compiled into this build"),
            "the placeholder's reason must be the plugin gate error: {error}"
        );
    }

    /// The placeholder is not a one-shot of the initial load: a `refresh`
    /// re-parses the same payload through the same arm, so the dead node
    /// must still be bound dead after the second ingest — never dropped on
    /// the refresh path (which would let a `use:` group quietly shrink).
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[tokio::test]
    async fn missing_plugin_placeholder_survives_a_second_ingest() {
        let url = spawn_payload_server(
            "proxies:\n  - {name: good, type: direct}\n  - {name: dead-ss, type: ss, server: 1.2.3.4, port: 8388, password: p, cipher: aes-128-gcm, plugin: gost-plugin}\n",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let provider = ProxyProvider::new(
            "p",
            &raw_http_provider(&url, None),
            Some(dir.path()),
            false,
            false,
            ProxyRegistry::default(),
        )
        .unwrap();
        provider
            .acquire_initial()
            .await
            .expect("a missing-plugin node must not reject the whole payload");
        provider
            .refresh()
            .await
            .expect("a refresh re-parsing the same payload must keep succeeding");

        let nodes = provider.proxies();
        assert_eq!(nodes.len(), 2, "the dead node keeps its slot on refresh");
        let dead = nodes
            .iter()
            .find(|proxy| proxy.name() == "dead-ss")
            .expect("the unbuildable node stays addressable after a refresh");
        let error = dead
            .dial_tcp(&meow_common::Metadata::default())
            .await
            .err()
            .expect("the refreshed placeholder must still fail the dial")
            .to_string();
        assert!(
            error.contains("not compiled into this build"),
            "the second ingest binds the same placeholder: {error}"
        );
    }

    /// `proxy: <name>` routes the provider fetch through that registry
    /// entry — the dial lands on the named hop, not on a direct socket.
    #[tokio::test]
    async fn http_provider_proxy_fetches_through_named_hop() {
        let front = Arc::new(PassthroughProxy {
            seen: std::sync::Mutex::new(Vec::new()),
            health: meow_common::ProxyHealth::new(),
        });
        let registry = registry_with_front(Arc::<PassthroughProxy>::clone(&front));
        let url = spawn_payload_server("proxies:\n  - {name: n1, type: direct}\n").await;
        let port = url
            .trim_start_matches("http://")
            .split(':')
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let raw = raw_http_provider(&url, Some("front"));
        let p = ProxyProvider::new("test", &raw, Some(dir.path()), false, false, registry).unwrap();
        p.acquire_initial().await.expect("fetch through 'front'");
        assert_eq!(p.proxies().len(), 1, "payload must parse");
        let seen = front.seen.lock().unwrap();
        assert_eq!(
            seen.as_slice(),
            &[("127.0.0.1".to_string(), port)],
            "the fetch must dial through the named proxy"
        );
    }

    /// At startup providers load before the route map is published: an
    /// unresolvable `proxy:` fails the fetch AND flags the provider so the
    /// post-publish kick retries `acquire_initial` (issue #625).
    #[tokio::test]
    async fn http_provider_unresolvable_proxy_defers_then_retries() {
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let url = spawn_payload_server("proxies:\n  - {name: n1, type: direct}\n").await;
        let dir = tempfile::tempdir().unwrap();
        let raw = raw_http_provider(&url, Some("front"));
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            false,
            false,
            registry.clone(),
        )
        .unwrap();

        let err = p
            .acquire_initial()
            .await
            .expect_err("unresolvable proxy must fail the fetch");
        // `fetch_content`'s cache fallback surfaces the cache error when no
        // cache exists — the resolution failure itself still flagged the
        // deferred retry inside `fetch_source`.
        assert!(
            err.to_string().contains("cache") || err.to_string().contains("'front'"),
            "unexpected: {err}"
        );
        assert!(p.proxies().is_empty());
        assert!(
            p.take_deferred_initial(),
            "the failed pre-publish fetch must flag the deferred retry"
        );
        assert!(!p.take_deferred_initial(), "the flag is consumed once");

        // Simulate the startup publish: `acquire_initial` then succeeds
        // through the named hop.
        let front = Arc::new(PassthroughProxy {
            seen: std::sync::Mutex::new(Vec::new()),
            health: meow_common::ProxyHealth::new(),
        });
        registry.publish(Arc::new(HashMap::from([(
            smol_str::SmolStr::from("front"),
            Arc::<PassthroughProxy>::clone(&front) as Arc<dyn Proxy>,
        )])));
        p.acquire_initial().await.expect("fetch after publish");
        assert_eq!(p.proxies().len(), 1);
        assert!(
            !p.take_deferred_initial(),
            "a resolving fetch clears the flag"
        );
    }

    /// `proxy: DIRECT` and `proxy:` on a `file` provider keep their
    /// meanings: explicit direct fetch, and warn-but-load respectively.
    #[tokio::test]
    async fn provider_proxy_direct_and_file_variants() {
        let dir = tempfile::tempdir().unwrap();
        let url = spawn_payload_server("proxies:\n  - {name: n1, type: direct}\n").await;
        let raw = raw_http_provider(&url, Some("DIRECT"));
        let p = ProxyProvider::new(
            "test",
            &raw,
            Some(dir.path()),
            false,
            false,
            Default::default(),
        )
        .unwrap();
        p.acquire_initial().await.expect("DIRECT fetches directly");
        assert_eq!(p.proxies().len(), 1);
        assert!(!p.take_deferred_initial(), "a direct fetch never defers");

        // `proxy:` on a file provider warns but does not break the load.
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: n1, type: direct}\n",
        )
        .unwrap();
        let mut raw = raw_file_provider("nodes.yaml");
        raw.proxy = Some("front".to_string());
        let p = ProxyProvider::new(
            "filep",
            &raw,
            Some(dir.path()),
            false,
            false,
            Default::default(),
        )
        .unwrap();
        p.acquire_initial().await.expect("file load unaffected");
        assert_eq!(p.proxies().len(), 1);
    }

    /// A whitespace-only `proxy:` or `dialer-proxy:` is a typo, not a
    /// clear — build rejects it rather than silently fetching/dialing
    /// direct (issue #625 review). `""` and absent still mean unset.
    #[test]
    fn provider_new_rejects_whitespace_proxy_names() {
        let mut raw = raw_http_provider("http://127.0.0.1:1/x", Some("   "));
        let err = ProxyProvider::new("t", &raw, None, false, false, Default::default())
            .err()
            .expect("whitespace proxy: must be rejected");
        assert!(err.contains("malformed proxy"), "{err}");

        raw = raw_http_provider("http://127.0.0.1:1/x", Some(""));
        assert!(
            ProxyProvider::new("t", &raw, None, false, false, Default::default()).is_ok(),
            "empty proxy: means direct"
        );

        raw = raw_http_provider("http://127.0.0.1:1/x", None);
        raw.dialer_proxy = Some(" \t ".to_string());
        let err = ProxyProvider::new("t", &raw, None, false, false, Default::default())
            .err()
            .expect("whitespace dialer-proxy: must be rejected");
        assert!(err.contains("malformed dialer-proxy"), "{err}");
    }

    const ONE_NODE: &str = "proxies:\n  - {name: n1, type: direct}\n";
    const TWO_NODES: &str =
        "proxies:\n  - {name: n1, type: direct}\n  - {name: n2, type: direct}\n";

    async fn load_within(
        providers: &[(&str, &str)],
        dir: &Path,
        deadline: Option<Duration>,
    ) -> HashMap<String, Arc<ProxyProvider>> {
        let raw = providers
            .iter()
            .map(|(name, url)| ((*name).to_string(), raw_http_provider(url, None)))
            .collect();
        load_proxy_providers_within(
            &raw,
            Some(dir),
            false,
            false,
            &Default::default(),
            None,
            deadline,
            None,
            &mut DroppedProviders::default(),
        )
        .await
        .unwrap()
    }

    fn registry_of(
        providers: &HashMap<String, Arc<ProxyProvider>>,
    ) -> DashMap<String, Arc<ProxyProvider>> {
        providers
            .iter()
            .map(|(name, p)| (name.clone(), Arc::clone(p)))
            .collect()
    }

    /// A cached provider starts from its cache with zero requests — a
    /// subscription that is blocked or slow can no longer hold startup —
    /// and the post-publish kick then replaces the cached generation with
    /// the remote one.
    #[tokio::test]
    async fn startup_serves_cache_without_network_then_revalidates() {
        let origin = Origin::spawn(Some(TWO_NODES), true).await;
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("provider_p.yaml");
        std::fs::write(&cache, ONE_NODE).unwrap();

        let providers = load_within(&[("p", &origin.url)], dir.path(), None).await;
        let p = &providers["p"];
        assert_eq!(p.proxies().len(), 1, "the cached generation is live");
        assert_eq!(
            origin.hits(),
            0,
            "a cached provider must not wait on the network"
        );
        assert!(
            p.updated_at_secs() > 0,
            "updated_at reports the cache's age"
        );

        spawn_deferred_initial_fetches(&registry_of(&providers));
        eventually("the background revalidation", || p.proxies().len() == 2).await;
        assert_eq!(origin.hits(), 1);
        assert_eq!(std::fs::read_to_string(&cache).unwrap(), TWO_NODES);
        assert!(!p.take_deferred_initial(), "the kick consumed the flag");
    }

    /// No cache and a failing feed: startup goes on with the provider empty,
    /// and the background task keeps retrying until the feed recovers —
    /// instead of leaving its groups empty until `interval` (or forever).
    #[tokio::test]
    async fn startup_fetch_failure_starts_empty_and_retries_until_it_lands() {
        let origin = Origin::spawn(None, true).await;
        let dir = tempfile::tempdir().unwrap();

        let providers = load_within(&[("p", &origin.url)], dir.path(), None).await;
        let p = &providers["p"];
        assert!(p.proxies().is_empty());
        assert_eq!(origin.hits(), 1);

        spawn_deferred_initial_fetches(&registry_of(&providers));
        eventually("a few failed retries", || origin.hits() >= 3).await;
        assert!(p.proxies().is_empty());
        *origin.body.lock() = Some(ONE_NODE);
        eventually("the retry that lands", || p.proxies().len() == 1).await;
    }

    /// Uncached providers fetch concurrently: a gated origin sees both
    /// requests before it answers either. A sequential loader would hold
    /// the second request behind the first and never get there.
    #[tokio::test]
    async fn startup_fetches_uncached_providers_concurrently() {
        let origin = Origin::spawn(Some(ONE_NODE), false).await;
        let dir = tempfile::tempdir().unwrap();
        let url = origin.url.clone();
        let path = dir.path().to_path_buf();
        let load =
            tokio::spawn(
                async move { load_within(&[("a", &url), ("b", &url)], &path, None).await },
            );

        eventually("both requests in flight", || origin.hits() == 2).await;
        assert!(
            !load.is_finished(),
            "no deadline: startup waits for the fetches"
        );
        origin.gate.send_replace(true);
        let providers = load.await.unwrap();
        assert_eq!(providers["a"].proxies().len(), 1);
        assert_eq!(providers["b"].proxies().len(), 1);
        assert!(
            !providers["a"].take_deferred_initial(),
            "a landed fetch owes nothing"
        );
    }

    /// With an embedder deadline, startup returns while a fetch is still in
    /// flight; the straggler populates the provider when it lands, and the
    /// queued background attempt does not fetch it a second time.
    #[tokio::test]
    async fn startup_deadline_returns_before_a_stalled_fetch() {
        let origin = Origin::spawn(Some(ONE_NODE), false).await;
        let dir = tempfile::tempdir().unwrap();

        let providers = tokio::time::timeout(
            Duration::from_secs(5),
            load_within(
                &[("p", &origin.url)],
                dir.path(),
                Some(Duration::from_millis(50)),
            ),
        )
        .await
        .expect("the deadline must bound startup");
        let p = &providers["p"];
        assert!(p.proxies().is_empty(), "the straggler has not landed yet");

        spawn_deferred_initial_fetches(&registry_of(&providers));
        origin.gate.send_replace(true);
        eventually("the straggling fetch", || p.proxies().len() == 1).await;
        tokio::time::sleep(BACKGROUND_RETRY_MAX * 2).await;
        assert_eq!(
            origin.hits(),
            1,
            "the background attempt saw the straggler land"
        );
    }

    /// A provider a config commit creates (empty) serves its cache first;
    /// while the feed stays down the revalidation gives up after
    /// `MAX_REVALIDATION_ATTEMPTS`, keeping the cached nodes.
    #[tokio::test]
    async fn spawn_initial_fetch_serves_cache_and_bounds_revalidation() {
        let origin = Origin::spawn(None, true).await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("provider_p.yaml"), ONE_NODE).unwrap();
        let raw = raw_http_provider(&origin.url, None);
        let p = Arc::new(
            ProxyProvider::new(
                "p",
                &raw,
                Some(dir.path()),
                false,
                false,
                Default::default(),
            )
            .unwrap(),
        );

        tokio::time::timeout(Duration::from_secs(5), p.spawn_initial_fetch())
            .await
            .expect("revalidation retries are bounded")
            .unwrap();
        assert_eq!(
            p.proxies().len(),
            1,
            "a failed revalidation keeps the cache"
        );
        assert_eq!(origin.hits(), MAX_REVALIDATION_ATTEMPTS as usize);
    }

    /// The task holds only a `Weak` between attempts: dropping the provider
    /// (a commit removed it) ends an otherwise endless retry loop.
    #[tokio::test]
    async fn spawn_initial_fetch_ends_when_the_provider_is_dropped() {
        let origin = Origin::spawn(None, true).await;
        let raw = raw_http_provider(&origin.url, None);
        let p = Arc::new(
            ProxyProvider::new("p", &raw, None, false, false, Default::default()).unwrap(),
        );
        let task = p.spawn_initial_fetch();
        eventually("a failed attempt", || origin.hits() >= 1).await;
        drop(p);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the retry loop must end with its provider")
            .unwrap();
    }

    fn usage(upload: u64, total: u64) -> SubscriptionUserinfo {
        SubscriptionUserinfo {
            upload,
            total,
            ..SubscriptionUserinfo::default()
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn http_cache_and_usage_are_private_on_refresh() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        let origin = Origin::spawn(Some(ONE_NODE), true).await;
        *origin.userinfo.lock() = Some("upload=3; total=4");
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("provider_p.yaml");
        let sidecar = dir.path().join("provider_p.yaml.subscription-userinfo");
        let raw = raw_http_provider(&origin.url, None);
        let provider = ProxyProvider::new(
            "p",
            &raw,
            Some(dir.path()),
            false,
            false,
            Default::default(),
        )
        .unwrap();

        provider.refresh().await.unwrap();
        for path in [&cache, &sidecar] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        fs::set_permissions(&cache, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o400)).unwrap();
        *origin.body.lock() = Some(TWO_NODES);
        *origin.userinfo.lock() = Some("upload=7; total=10");
        provider.refresh().await.unwrap();
        assert_eq!(
            fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(fs::read_to_string(cache).unwrap(), TWO_NODES);
        assert_eq!(
            fs::read_to_string(sidecar).unwrap(),
            "upload=7; download=0; total=10; expire=0"
        );
    }

    /// Startup serves the usage persisted with the cache, and the
    /// background revalidation — whose payload is unchanged — replaces it
    /// with the usage the feed now reports, on disk too.
    #[tokio::test]
    async fn revalidation_of_an_unchanged_payload_updates_the_usage() {
        let origin = Origin::spawn(Some(ONE_NODE), true).await;
        *origin.userinfo.lock() = Some("upload=8; total=100");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("provider_p.yaml"), ONE_NODE).unwrap();
        let sidecar = dir.path().join("provider_p.yaml.subscription-userinfo");
        std::fs::write(&sidecar, "upload=7; total=100").unwrap();

        let providers = load_within(&[("p", &origin.url)], dir.path(), None).await;
        let p = &providers["p"];
        assert_eq!(origin.hits(), 0);
        assert_eq!(p.subscription_userinfo(), Some(usage(7, 100)));

        spawn_deferred_initial_fetches(&registry_of(&providers));
        eventually("the revalidated usage", || {
            p.subscription_userinfo() == Some(usage(8, 100))
        })
        .await;
        eventually("the persisted usage", || {
            std::fs::read_to_string(&sidecar).ok().as_deref()
                == Some("upload=8; download=0; total=100; expire=0")
        })
        .await;
    }

    /// A fetched payload is persisted together with its usage: a usage
    /// file left from an earlier payload never outlives a cache write it
    /// did not come with, and a cache-backed provider without one reports
    /// no usage.
    #[tokio::test]
    async fn a_cache_write_replaces_the_usage_left_by_an_earlier_payload() {
        let origin = Origin::spawn(Some(ONE_NODE), true).await;
        let dir = tempfile::tempdir().unwrap();
        // An unparseable cache is skipped, so startup fetches; the usage
        // file next to it is not read.
        std::fs::write(dir.path().join("provider_p.yaml"), "proxies: [").unwrap();
        let sidecar = dir.path().join("provider_p.yaml.subscription-userinfo");
        std::fs::write(&sidecar, "upload=1; total=2").unwrap();

        let providers = load_within(&[("p", &origin.url)], dir.path(), None).await;
        let p = &providers["p"];
        assert_eq!(origin.hits(), 1);
        assert_eq!(p.proxies().len(), 1);
        assert_eq!(p.subscription_userinfo(), None);
        assert!(!sidecar.exists(), "the stale usage went with the old cache");

        *origin.userinfo.lock() = Some("upload=3; total=4");
        *origin.body.lock() = Some(TWO_NODES);
        p.refresh().await.unwrap();
        assert_eq!(p.subscription_userinfo(), Some(usage(3, 4)));
        assert_eq!(
            std::fs::read_to_string(&sidecar).unwrap(),
            "upload=3; download=0; total=4; expire=0"
        );

        // Without an on-disk cache the usage lives in memory only.
        let raw = raw_http_provider(&origin.url, None);
        let memory = ProxyProvider::new("m", &raw, None, false, false, Default::default()).unwrap();
        memory.refresh().await.unwrap();
        assert_eq!(memory.subscription_userinfo(), Some(usage(3, 4)));
    }

    const BAD_NODE: &str = "proxies:\n  - {name: bad, type: nosuchtype}\n";

    /// Under `strict`, a remote payload defect used to abort the load —
    /// the feed's operator could kill the daemon by serving one bad node.
    /// It now degrades to the acquisition shape: `Ok(false)` → registered
    /// empty + `background_pending` → the retry loop fetches until the
    /// publisher fixes the payload (or the provider is dropped).
    #[tokio::test]
    async fn strict_remote_payload_degrades() {
        let origin = Origin::spawn(Some(BAD_NODE), true).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([("p".to_string(), raw_http_provider(&origin.url, None))]);
        let providers = load_proxy_providers_within(
            &raw,
            Some(dir.path()),
            false,
            true,
            &Default::default(),
            None,
            None,
            None,
            &mut DroppedProviders::default(),
        )
        .await
        .expect("a remote payload defect must degrade under strict, not fail");
        let p = Arc::clone(&providers["p"]);
        drop(providers);
        assert!(
            p.proxies().is_empty(),
            "the rejected payload registers empty"
        );
        assert!(
            p.take_deferred_initial(),
            "the degraded load owes a background fetch"
        );

        // The retry keeps fetching — a parse failure gets the same
        // acquisition-failure retry contract as a transport error.
        let task = p.spawn_initial_fetch();
        eventually("retried fetches", || origin.hits() >= 2).await;
        drop(p);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the retry loop must end with its provider")
            .unwrap();
    }

    /// A rejected remote payload never reaches the on-disk cache — the
    /// cache write runs only after a successful ingest.
    #[tokio::test]
    async fn strict_rejected_remote_bytes_never_write_the_cache() {
        let origin = Origin::spawn(Some(BAD_NODE), true).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([("p".to_string(), raw_http_provider(&origin.url, None))]);
        let providers = load_proxy_providers_within(
            &raw,
            Some(dir.path()),
            false,
            true,
            &Default::default(),
            None,
            None,
            None,
            &mut DroppedProviders::default(),
        )
        .await
        .unwrap();
        assert!(providers["p"].proxies().is_empty());
        assert!(
            !dir.path().join("provider_p.yaml").exists(),
            "the rejected payload must not be persisted"
        );
    }

    /// The `file:` vehicle is operator-authored local content — strict
    /// stays fail-closed on its payload defects, identically under `-t`
    /// and at boot (the load runs before the offline short-circuit).
    #[tokio::test]
    async fn strict_file_payload_stays_fatal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.yaml"), BAD_NODE).unwrap();
        let raw = HashMap::from([("f".to_string(), raw_file_provider("nodes.yaml"))]);
        let err = load_proxy_providers_within(
            &raw,
            Some(dir.path()),
            false,
            true,
            &Default::default(),
            None,
            None,
            None,
            &mut DroppedProviders::default(),
        )
        .await
        .err()
        .expect("a strict file payload defect must still fail the load");
        assert!(err.to_string().contains("nosuchtype"), "{err}");
    }

    /// A missing `file:` is an *acquisition* failure, not a payload
    /// defect — it stays lenient under strict: registered empty, healed
    /// by the interval/background retry.
    #[tokio::test]
    async fn strict_missing_file_stays_lenient() {
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([("f".to_string(), raw_file_provider("gone.yaml"))]);
        let providers = load_proxy_providers_within(
            &raw,
            Some(dir.path()),
            false,
            true,
            &Default::default(),
            None,
            None,
            None,
            &mut DroppedProviders::default(),
        )
        .await
        .expect("a read failure must not fail strict");
        assert!(providers["f"].proxies().is_empty());
    }

    /// `initial_load_blocking` runs the same load on a throwaway thread —
    /// callable from a plain (non-runtime) thread, which is what the
    /// candidate-materialize path needs.
    #[test]
    fn initial_load_blocking_runs_off_runtime() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.yaml"), ONE_NODE).unwrap();
        let p = ProxyProvider::new(
            "f",
            &raw_file_provider("nodes.yaml"),
            Some(dir.path()),
            false,
            true,
            Default::default(),
        )
        .unwrap();
        assert!(
            p.initial_load_blocking(true).unwrap(),
            "a valid file payload loads"
        );
        assert_eq!(p.proxies().len(), 1);

        std::fs::write(dir.path().join("bad.yaml"), BAD_NODE).unwrap();
        let p = ProxyProvider::new(
            "b",
            &raw_file_provider("bad.yaml"),
            Some(dir.path()),
            false,
            true,
            Default::default(),
        )
        .unwrap();
        assert!(
            p.initial_load_blocking(true).is_err(),
            "a strict file payload defect fails the candidate"
        );
    }

    /// Issue #974: a provider node omitting `client-fingerprint` inherits
    /// the global the provider was built under — and a changed global
    /// fails `matches_def`, so a `PUT /configs` fingerprint flip rebuilds
    /// the provider instead of reusing adapters baked under the old one.
    #[cfg(feature = "vless")]
    #[test]
    fn global_client_fingerprint_reaches_provider_nodes_and_identity() {
        const REALITY_NODE: &str = "proxies:\n  - {name: v, type: vless, server: example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, reality-opts: {public-key: hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo}}\n";
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.yaml"), REALITY_NODE).unwrap();
        let def = raw_file_provider("nodes.yaml");

        // No global: the uTLS-less REALITY node stays refused (warn-drop).
        let p = ProxyProvider::new(
            "p",
            &def,
            Some(dir.path()),
            false,
            false,
            Default::default(),
        )
        .unwrap();
        assert!(p.initial_load_blocking(false).unwrap());
        assert!(
            p.proxies().is_empty(),
            "without a global fingerprint the REALITY node must drop"
        );

        // With a global: the same payload parses through inheritance.
        let p = ProxyProvider::new_with_client_fingerprint(
            "p",
            &def,
            Some(dir.path()),
            false,
            false,
            Default::default(),
            Some("chrome"),
            None,
        )
        .unwrap();
        assert!(p.initial_load_blocking(false).unwrap());
        assert_eq!(
            p.proxies().len(),
            1,
            "the node must inherit the global fingerprint"
        );

        // Identity: only a normalized-equal global still matches.
        assert!(p.matches_def(&def, false, Some(" Chrome ")));
        assert!(p.matches_def(&def, false, Some("chrome")));
        assert!(
            !p.matches_def(&def, false, Some("firefox")),
            "a changed global fingerprint must rebuild the provider"
        );
        assert!(
            !p.matches_def(&def, false, None),
            "clearing the global fingerprint must rebuild the provider"
        );
    }

    /// A parseable node that still owes an ECH DNS lookup — `ech-opts.
    /// enable: true`, no inline `config:`, a `server:` to query. `type:
    /// direct` keeps it feature-independent; the defect/lookup gates
    /// read the raw map, not the adapter.
    const ECH_NODE: &str =
        "proxies:\n  - {name: n1, type: direct, server: ech.invalid, ech-opts: {enable: true}}\n";

    /// The candidate-materialize load performs no DNS I/O: the strict
    /// ECH gate still fires (`check_ech_defects` — same verdict as
    /// `preresolve_ech`), but the lookup is deferred so it cannot
    /// serialize the mutation lane (`ech_pending` owes it).
    #[test]
    fn initial_load_blocking_defers_ech_dns() {
        let _serial = crate::test_support::ech_dns_serial().blocking_lock();
        crate::ech_dns::ECH_LOOKUPS.store(0, Ordering::Relaxed);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ech.yaml"), ECH_NODE).unwrap();
        let p = ProxyProvider::new(
            "e",
            &raw_file_provider("ech.yaml"),
            Some(dir.path()),
            false,
            true,
            Default::default(),
        )
        .unwrap();
        assert!(
            p.initial_load_blocking(true).unwrap(),
            "a valid file payload loads"
        );
        assert_eq!(p.proxies().len(), 1, "the committed nodes are served");
        assert_eq!(
            crate::ech_dns::ECH_LOOKUPS.load(Ordering::Relaxed),
            0,
            "the mutation lane must not run the ECH DNS lookup"
        );
        assert!(
            p.ech_pending.load(Ordering::Relaxed),
            "the deferred preresolve stays owed"
        );
    }

    /// The deferred preresolve completes off-lane: a byte-identical
    /// refetch still re-parses (dedup knows the resolve half is owed),
    /// the lookup runs on the detached path the commit kicks off, and
    /// ordinary dedup resumes once the slot is fully resolved.
    #[tokio::test]
    async fn deferred_ech_resolve_completes_off_lane() {
        let _serial = crate::test_support::ech_dns_serial().lock().await;
        crate::ech_dns::ECH_LOOKUPS.store(0, Ordering::Relaxed);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ech.yaml"), ECH_NODE).unwrap();
        let p = ProxyProvider::new(
            "e",
            &raw_file_provider("ech.yaml"),
            Some(dir.path()),
            false,
            true,
            Default::default(),
        )
        .unwrap();
        assert!(p.initial_load_blocking(true).unwrap());
        assert!(p.ech_pending.load(Ordering::Relaxed));

        // `refresh` runs the same `Resolve` ingest as the detached
        // post-commit fetch — identical bytes must still re-parse, and
        // the lookup the lane skipped lands here. A bounded wait: the
        // DNS miss itself can stretch to the per-nameserver timeouts.
        tokio::time::timeout(Duration::from_secs(60), p.refresh())
            .await
            .expect("the deferred pass must not hang")
            .expect("the deferred pass succeeds");
        assert_eq!(
            crate::ech_dns::ECH_LOOKUPS.load(Ordering::Relaxed),
            1,
            "the deferred pass ran the lookup the lane skipped"
        );
        assert!(!p.ech_pending.load(Ordering::Relaxed));
        assert!(
            p.fetched_remote.load(Ordering::Relaxed),
            "only a fully resolved payload counts as fetched"
        );
        assert_eq!(p.proxies().len(), 1);

        // Resolved now — a second identical refetch dedups like always.
        p.refresh().await.expect("the resolved payload dedups");
        assert_eq!(crate::ech_dns::ECH_LOOKUPS.load(Ordering::Relaxed), 1);
    }

    /// The deferred resolve's production path is not `refresh` but the
    /// detached task `commit_proxy_providers` spawns for a new provider:
    /// `spawn_initial_fetch` → `background_attempt`. While `ech_pending`
    /// is owed, `fetched_remote` must not be treated as settled —
    /// otherwise the attempt's early-return would retire the loop having
    /// served only unresolved nodes, and a provider without `interval:`
    /// would stay that way permanently.
    #[tokio::test]
    async fn spawn_initial_fetch_completes_the_deferred_ech_resolve() {
        let _serial = crate::test_support::ech_dns_serial().lock().await;
        crate::ech_dns::ECH_LOOKUPS.store(0, Ordering::Relaxed);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ech.yaml"), ECH_NODE).unwrap();
        let p = Arc::new(
            ProxyProvider::new(
                "e",
                &raw_file_provider("ech.yaml"),
                Some(dir.path()),
                false,
                true,
                Default::default(),
            )
            .unwrap(),
        );
        assert!(p.initial_load_blocking(true).unwrap());
        assert!(p.ech_pending.load(Ordering::Relaxed));
        assert!(
            !p.fetched_remote.load(Ordering::Relaxed),
            "a payload still owing its ECH lookup is not fetched"
        );

        // The detached loop must run the owed re-parse (identical bytes
        // under `Resolve`, so the lookup fires) and only then retire.
        tokio::time::timeout(Duration::from_secs(60), p.spawn_initial_fetch())
            .await
            .expect("the detached fetch retires once the resolve lands")
            .unwrap();
        assert_eq!(
            crate::ech_dns::ECH_LOOKUPS.load(Ordering::Relaxed),
            1,
            "the detached fetch ran the lookup the lane skipped"
        );
        assert!(!p.ech_pending.load(Ordering::Relaxed));
        assert!(p.fetched_remote.load(Ordering::Relaxed));
    }

    /// A candidate load may still be rejected by the rebuild, so it must
    /// write no logbook entry at all — including the "Updated" success
    /// entry an ordinary load records when a prior same-name failure
    /// stands: a rejected PUT would otherwise falsely clear the failing
    /// state for a provider that was never committed.
    #[tokio::test]
    async fn unrecorded_candidate_load_writes_no_logbook_entry() {
        let book = TestLogbook::install();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.yaml"), ONE_NODE).unwrap();
        record_failure("unrecorded-load", "seeded failure");
        let p = ProxyProvider::new(
            "unrecorded-load",
            &raw_file_provider("nodes.yaml"),
            Some(dir.path()),
            false,
            true,
            Default::default(),
        )
        .unwrap();
        assert!(p.initial_load_blocking(true).unwrap());
        let entries = book.entries("unrecorded-load");
        assert_eq!(
            entries.len(),
            1,
            "only the seeded failure may stand — the uncommitted load records nothing: {entries:?}"
        );
        assert_eq!(entries[0].level, Level::Error, "{entries:?}");
    }

    /// A remote payload defect degrades AND records the failure — spec
    /// §9.7: every remote degrade must warn and write a logbook entry
    /// (`initial_load`'s record path, not the candidate-only
    /// `initial_load_unrecorded`).
    #[tokio::test]
    async fn strict_remote_payload_degrade_records_logbook() {
        let book = TestLogbook::install();
        let origin = Origin::spawn(Some(BAD_NODE), true).await;
        let dir = tempfile::tempdir().unwrap();
        // The subject must be unique in this binary: `TestLogbook` is
        // process-global and parallel tests keep recording into it — the
        // generic "p" is shared with rule-provider tests, whose entries
        // would pollute this assertion.
        let raw = HashMap::from([(
            "strict-degrade-pp".to_string(),
            raw_http_provider(&origin.url, None),
        )]);
        let providers = load_proxy_providers_within(
            &raw,
            Some(dir.path()),
            false,
            true,
            &Default::default(),
            None,
            None,
            None,
            &mut DroppedProviders::default(),
        )
        .await
        .expect("a remote payload defect must degrade under strict");
        assert!(providers["strict-degrade-pp"].proxies().is_empty());
        let entries = book.entries("strict-degrade-pp");
        let entries: Vec<(Level, &str)> = entries
            .iter()
            .filter(|e| e.kind.as_str() == logbook::kind::PROXY_PROVIDER_UPDATE)
            .map(|e| (e.level, e.message.as_str()))
            .collect();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].0, Level::Error, "{entries:?}");
        assert!(
            entries[0]
                .1
                .starts_with("Updating proxy provider 'strict-degrade-pp' failed: "),
            "unexpected: {}",
            entries[0].1
        );
    }

    /// Whether a bad remote payload lands before or after the fetch
    /// deadline, the strict verdict is the same: registered empty +
    /// background retry. Before the origin split, a pre-deadline defect
    /// was boot-fatal while the same bytes in flight were only warned —
    /// the verdict depended on timing, not on the defect.
    #[tokio::test]
    async fn strict_deadline_race_gone() {
        let bad = Origin::spawn(Some(BAD_NODE), true).await;
        let slow = Origin::spawn(Some(ONE_NODE), false).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([
            ("fast-bad".to_string(), raw_http_provider(&bad.url, None)),
            ("slow".to_string(), raw_http_provider(&slow.url, None)),
        ]);
        let providers = tokio::time::timeout(
            Duration::from_secs(5),
            load_proxy_providers_within(
                &raw,
                Some(dir.path()),
                false,
                true,
                &Default::default(),
                None,
                Some(Duration::from_millis(50)),
                None,
                &mut DroppedProviders::default(),
            ),
        )
        .await
        .expect("the deadline must bound the wait")
        .expect("remote payload defects must not fail strict");
        for name in ["fast-bad", "slow"] {
            let p = &providers[name];
            assert!(
                p.proxies().is_empty(),
                "{name} registers empty regardless of timing"
            );
            assert!(
                p.take_deferred_initial(),
                "{name} owes the same background fetch"
            );
        }
        slow.gate.send_replace(true);
        eventually("the late fetch lands", || {
            providers["slow"].proxies().len() == 1
        })
        .await;
    }
}
