use crate::proxy_parser;
use crate::raw::{RawHealthCheck, RawProxyProvider};
use meow_common::atomic::AtomicU;
use meow_common::{ProviderSlot, Proxy};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub struct HealthCheckConfig {
    pub url: String,
    pub interval: u64,
    pub timeout: u64,
    pub expected_status: String,
    pub lazy: bool,
}

pub struct ProxyProvider {
    pub name: String,
    pub slot: ProviderSlot,
    pub vehicle_type: &'static str,
    vehicle: Vehicle,
    filter: Option<regex::Regex>,
    exclude_filter: Option<regex::Regex>,
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
    /// Registry every provider node's `dialer-proxy` resolves against
    /// (issue #489). Unlike the per-build registry handed to static proxies,
    /// this handle is republished on every routing install, so provider
    /// nodes — which outlive individual config builds — always resolve the
    /// *current* route map, matching mihomo's by-name-at-dial-time model.
    dialer_registry: meow_proxy::dialer::ProxyRegistry,
    /// `proxy:` — the name this provider's HTTP fetches resolve against the
    /// same republished cell at fetch time (upstream resolves the vehicle's
    /// proxy per request). `None` = direct (`proxy:` absent, empty, or
    /// `DIRECT`) (issue #625).
    download_proxy: Option<smol_str::SmolStr>,
    /// Set when a fetch found `download_proxy` unresolvable — the startup
    /// build loads providers *before* the first route map is published, so
    /// the post-publish kick re-runs `acquire_initial` for providers still
    /// flagged (issue #625). Cleared once the name resolves again.
    deferred_initial: AtomicBool,
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
    filter: Option<regex::Regex>,
    exclude_filter: Option<regex::Regex>,
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
            if !re.is_match(name) {
                return false;
            }
        }
        if let Some(re) = &self.exclude_filter {
            if re.is_match(name) {
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

impl ProxyProvider {
    pub fn new(
        name: &str,
        raw: &RawProxyProvider,
        cache_dir: Option<&Path>,
        ipv6: bool,
        strict: bool,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
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

        let health_check = build_health_check_config(raw.health_check.as_ref());
        if health_check.is_some() {
            // The config is honoured by the manual
            // `GET /providers/proxies/{name}/healthcheck` endpoint, but
            // nothing probes provider members on a timer (mihomo schedules
            // the provider health-check alongside `interval`). Warn once
            // per build so the config isn't silently half-wired.
            warn!(
                provider = %name,
                "proxy-provider 'health-check' is stored but not periodically \
                 scheduled — members are probed only via the manual \
                 healthcheck endpoint or a group's own health check"
            );
        }
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

        // mihomo `override:` — provider-level node defaults. Only
        // `dialer-proxy` is honoured; every other key warns so a config
        // relying on, say, `override.udp` does not silently diverge.
        // `override.Apply` writes unconditionally — it outranks both the
        // provider-level field and node-level `dialer-proxy`.
        let mut override_dialer = None;
        if let Some(over) = raw.override_.as_ref() {
            for key in over.keys() {
                if key != "dialer-proxy" {
                    warn!(provider = %name, "proxy-provider override key '{key}' is not supported");
                }
            }
            match over.get("dialer-proxy") {
                // `""` is the upstream "clear the chain" knob:
                // `OverrideSchema.Apply` writes the string unconditionally,
                // so an empty override strips node- and provider-level
                // `dialer-proxy` and the node dials direct.
                Some(serde_yaml::Value::String(s)) if s.is_empty() => {
                    override_dialer = Some(String::new());
                }
                Some(serde_yaml::Value::String(s)) if !s.trim().is_empty() => {
                    override_dialer = Some(s.trim().to_string());
                }
                // `null` unmarshals to a nil `*string` upstream — no write
                // happens, so the provider/node levels still apply.
                Some(serde_yaml::Value::Null) | None => {}
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
            dialer_registry,
            download_proxy,
            deferred_initial: AtomicBool::new(false),
            declared_dialers: RwLock::new(Vec::new()),
            provider_dialer,
            override_dialer,
            refresh_lock: tokio::sync::Mutex::new(()),
            derived: RwLock::new(Vec::new()),
            def: Self::def_identity(raw),
            content_hash: Mutex::new(None), // see field docs
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
    /// effective `ipv6` — the identity check `use:`/`include-all` rebuilds
    /// apply before deciding to reuse the live object. A changed
    /// declaration rebuilds the provider instead of silently fetching the
    /// old source forever (issue #533 review).
    pub fn matches_def(&self, def: &RawProxyProvider, ipv6: bool) -> bool {
        self.ipv6 == ipv6 && self.def == Self::def_identity(def)
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
    async fn fetch_source(&self) -> Result<String, String> {
        match &self.vehicle {
            Vehicle::File(path) => tokio::fs::read_to_string(path).await.map_err(|e| {
                format!(
                    "proxy-provider '{}': failed to read {:?}: {}",
                    self.name, path, e
                )
            }),
            Vehicle::Http { url, .. } => {
                let download_proxy = match crate::internal_http::resolve_download_proxy(
                    &self.dialer_registry,
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
                crate::internal_http::fetch(url, download_proxy.as_ref(), &self.header)
                    .await
                    .and_then(|bytes| {
                        String::from_utf8(bytes)
                            .map_err(|e| anyhow::anyhow!("response body is not UTF-8: {e}"))
                    })
                    .map_err(|e| e.to_string())
            }
        }
    }

    /// Initial-load acquisition: [`Self::fetch_source`] with an on-disk
    /// cache fallback for HTTP providers — the offline bootstrap path.
    /// The returned flag is `false` when the payload came from the cache
    /// (no point rewriting it). Deliberately NOT used by refresh ticks:
    /// a failed refresh keeps the in-memory last-good set (upstream
    /// `Update` semantics) instead of rewinding the slot to whatever
    /// generation the disk happens to hold.
    async fn fetch_content(&self) -> Result<(String, bool), String> {
        match self.fetch_source().await {
            Ok(text) => Ok((text, true)),
            Err(e) => match &self.vehicle {
                Vehicle::Http { cache_path, .. } => {
                    warn!(provider = %self.name, error = %e, "HTTP provider fetch failed, trying cache");
                    read_cache(cache_path.as_deref(), &self.name)
                        .await
                        .map(|text| (text, false))
                }
                Vehicle::File(_) => Err(e),
            },
        }
    }

    /// Persist a parsed-and-committed HTTP payload for offline fallback —
    /// atomic write-then-rename on a unique scratch: the manual-refresh
    /// endpoint, an interval tick, and a detached initial fetch can race
    /// this write unlaned, and a torn cache would poison the next
    /// fallback read (issue #543 review).
    async fn write_cache(&self, text: &str) {
        let Vehicle::Http {
            cache_path: Some(cache_path),
            ..
        } = &self.vehicle
        else {
            return;
        };
        if let Some(parent) = cache_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        // Sweep scratch siblings a crashed writer left behind
        // (issue #621) — on the blocking pool so the dir walk never
        // stalls the worker.
        {
            let sweep_target = cache_path.clone();
            let _ = crate::spawn_blocking_with_current_dispatcher(move || {
                meow_common::fs_util::sweep_scratch_siblings(
                    &sweep_target,
                    meow_common::fs_util::SCRATCH_STALE_AGE,
                );
            })
            .await;
        }
        let tmp = crate::unique_scratch_path(cache_path);
        let saved = match tokio::fs::write(&tmp, text).await {
            Ok(()) => tokio::fs::rename(&tmp, cache_path).await.is_ok(),
            Err(_) => false,
        };
        if !saved {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
    }

    /// Shared acquisition tail: dedup → parse → persist cache → commit.
    /// `Ok(false)` when the payload is byte-identical to the last commit
    /// (upstream's hash early-return — `updated_at` only advances on real
    /// content changes). `from_remote` distinguishes a live fetch from an
    /// on-disk cache read — cache content is never written back.
    async fn ingest(&self, content: String, from_remote: bool) -> Result<bool, String> {
        let strict = self.strict.load(Ordering::Relaxed);
        let hash = content_hash(&content);
        if *self.content_hash.lock() == Some((hash, strict)) {
            return Ok(false);
        }
        let proxies = self.parse_proxies(&content).await?;
        if from_remote {
            self.write_cache(&content).await;
        }
        self.commit(proxies);
        *self.content_hash.lock() = Some((hash, strict));
        Ok(true)
    }

    /// Parse a fetched provider payload into proxies.
    ///
    /// Document-level defects (malformed YAML, depth limit, merge-key
    /// failure, non-list document) are `Err` in BOTH modes — upstream
    /// `loadBuf` treats a parser failure as a failed update, so the caller
    /// keeps the last-good slot instead of committing an empty one. This
    /// matters now that refreshes are timer-driven: a 200-OK captive-portal
    /// page must not wipe the provider every tick. `strict` still gates
    /// *per-node* failures only.
    ///
    /// `declared_dialers` is rewritten only on the success path that will
    /// be committed: an `Err` keeps the last-good slot running, so it must
    /// keep that generation's declarations too (issue #489 review).
    async fn parse_proxies(&self, content: &str) -> Result<Vec<Arc<dyn Proxy>>, String> {
        let strict = self.strict.load(Ordering::Relaxed);
        if !crate::yaml_within_depth(content) {
            return Err("provider YAML exceeds the nesting-depth limit".to_string());
        }
        let mut doc: serde_yaml::Value = serde_yaml::from_str(content)
            .map_err(|e| format!("provider YAML is malformed: {e}"))?;
        // Expand `<<:` merge keys — remote payloads legitimately carry
        // anchors, and an unexpanded merge silently drops the merged
        // `dialer-proxy` into a literal `<<` key (the one field whose loss
        // converts to a silent direct dial). Same treatment as the main
        // config and subscription parsers. A failed merge leaves the doc
        // partially expanded, so treat it like the parse failure above:
        // drop the whole payload rather than risk nodes losing their
        // chained front hop.
        doc.apply_merge()
            .map_err(|e| format!("provider YAML merge keys failed to expand: {e}"))?;

        // Accept both `proxies: [...]` wrapper and a bare list. A
        // `Value::Null` document is an empty or comments-only file — treat
        // it as an empty provider rather than a parse defect so an editor /
        // external tool mid-rewrite doesn't hard-fail strict mode
        // (parity with the missing-file acquisition path, issue #533).
        let list_val = match doc.get("proxies").cloned().unwrap_or_else(|| doc.clone()) {
            serde_yaml::Value::Null => serde_yaml::Value::Sequence(Vec::new()),
            v => v,
        };

        let mut proxy_maps: Vec<HashMap<String, serde_yaml::Value>> =
            serde_yaml::from_value(list_val)
                .map_err(|e| format!("provider content is not a proxy list: {e}"))?;

        // Pre-resolve any DNS-sourced ECH configs into inline base64 — keeps
        // `parse_proxy` itself sync. An `ech-opts.enable: true` node with no
        // query source at all is a defect — strict turns it into an error.
        crate::ech_dns::preresolve_ech(&mut proxy_maps, strict)
            .await
            .map_err(|e| format!("{e} (strict mode)"))?;

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
                if !re.is_match(raw_name) {
                    continue;
                }
            }
            if let Some(ref re) = self.exclude_filter {
                if re.is_match(raw_name) {
                    continue;
                }
            }
            if self.exclude_type.iter().any(|t| t == &raw_type) {
                continue;
            }

            match self.parse_node(raw_map, raw_name, &mut declared) {
                Ok(proxy) => result.push(proxy),
                Err(e) => {
                    if strict {
                        return Err(format!(
                            "node '{raw_name}' failed to parse (strict mode): {e}"
                        ));
                    }
                    warn!(provider = %self.name, proxy = raw_name, error = %e, "failed to parse proxy");
                }
            }
        }
        *self.declared_dialers.write() = declared;

        Ok(result)
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
    /// A node whose adapter type cannot carry an injected dialer (anytls,
    /// hysteria2, an `ss` node with an external SIP003 plugin) falls back to
    /// the relay-based [`meow_proxy::DialerProxyAdapter`] — the same
    /// treatment `apply_dialer_proxies` gives static `proxies:` entries,
    /// except that provider payloads keep the fallback under `strict` too:
    /// the remote-declared chain still holds, where erroring would drop
    /// every sibling node with it.
    /// A malformed `dialer-proxy` value or a self-reference rejects the node
    /// outright: warn-skipping just the edge would leave the node dialling
    /// direct, a silent misroute on remote-controlled content (ADR-0002
    /// Class A).
    fn parse_node(
        &self,
        raw_map: &HashMap<String, serde_yaml::Value>,
        raw_name: &str,
        declared: &mut Vec<String>,
    ) -> Result<Arc<dyn Proxy>, String> {
        let direct: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(meow_proxy::dialer::DirectDialer);
        let node_dialer = match raw_map.get("dialer-proxy") {
            Some(value) => match value.as_str() {
                Some(s) if !s.trim().is_empty() => Some(s.trim()),
                // An explicit-but-empty or null `dialer-proxy:` counts as
                // unset — the provider-level `override` still applies
                // (mihomo's `len > 0` check treats `""` as unset). A
                // whitespace-only value is remote-controlled garbage, not a
                // usable name — reject the node rather than dial direct.
                Some("") => None,
                None if value.is_null() => None,
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
            return proxy_parser::parse_proxy_provider_node(
                raw_map,
                self.ipv6,
                self.allow_external_plugin,
                &direct,
            );
        };
        // `override.dialer-proxy: ""` is the upstream "clear the chain"
        // knob — the override wrote over both lower levels, so the node
        // dials direct by operator intent, not by a missing field.
        if dialer_name.is_empty() {
            return proxy_parser::parse_proxy_provider_node(
                raw_map,
                self.ipv6,
                self.allow_external_plugin,
                &direct,
            );
        }
        if dialer_name == raw_name {
            return Err("`dialer-proxy` points to the node itself".to_string());
        }

        let target = meow_proxy::dialer::DialerTarget::new(dialer_name, &self.dialer_registry);
        let chained: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(meow_proxy::dialer::NamedProxyDialer::new(target.clone()));
        let proxy = match proxy_parser::parse_proxy_provider_node(
            raw_map,
            self.ipv6,
            self.allow_external_plugin,
            &chained,
        ) {
            Ok(proxy) => proxy,
            Err(e) => {
                // The adapter type cannot carry an injected dialer — or the
                // node is unparseable, in which case the direct re-parse
                // surfaces the real error.
                let inner = proxy_parser::parse_proxy_provider_node(
                    raw_map,
                    self.ipv6,
                    self.allow_external_plugin,
                    &direct,
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
            Ok(content) => match self.ingest(content, true).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    // A torn payload keeps the last-good set instead of
                    // replacing it with nothing.
                    warn!(provider = %self.name, error = %e, "proxy-provider refresh failed");
                    Err(e)
                }
            },
            Err(e) => {
                warn!(provider = %self.name, error = %e, "proxy-provider refresh failed");
                Err(e)
            }
        }
    }

    /// First acquisition for a freshly built provider — startup and the
    /// detached post-commit fetch. Unlike [`Self::refresh`] this DOES fall
    /// back to the on-disk cache when the remote is unreachable (offline
    /// bootstrap); the slot is empty at this point, so last-good
    /// retention is moot.
    pub async fn acquire_initial(&self) -> Result<(), String> {
        let _generation = self.refresh_lock.lock().await;
        match self.fetch_content().await {
            Ok((content, from_remote)) => self.ingest(content, from_remote).await.map(|_| ()),
            Err(e) => Err(e),
        }
    }

    /// Consumes the deferred-initial-fetch flag: `true` once per provider
    /// whose `proxy:` name could not resolve during the pre-publish startup
    /// load — the caller schedules one `acquire_initial` retry now that the
    /// route map is published (issue #625). `meow-app` runs this check once
    /// after the first `update_routing`; embedders that drive `load_config`
    /// plus a `Tunnel` directly must do the same after their first routing
    /// install, or a deferred provider stays on its cache until an interval
    /// or manual refresh.
    pub fn take_deferred_initial(&self) -> bool {
        self.deferred_initial.swap(false, Ordering::Relaxed)
    }

    pub fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.slot.read().clone()
    }

    #[cfg(test)]
    fn derived_len(&self) -> usize {
        self.derived.read().len()
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

pub async fn load_proxy_providers(
    raw_map: &HashMap<String, RawProxyProvider>,
    cache_dir: Option<&Path>,
    ipv6: bool,
    strict: bool,
    dialer_registry: &meow_proxy::dialer::ProxyRegistry,
) -> Result<HashMap<String, Arc<ProxyProvider>>, anyhow::Error> {
    let mut result = HashMap::new();
    for (name, raw) in raw_map {
        match ProxyProvider::new(name, raw, cache_dir, ipv6, strict, dialer_registry.clone()) {
            Ok(provider) => {
                let provider = Arc::new(provider);
                if strict {
                    // Strict gates the *parse*, not the fetch: a transient
                    // download failure is not a config defect, so a provider
                    // that can't be fetched still starts empty until a
                    // scheduled tick or manual refresh succeeds.
                    match provider.fetch_content().await {
                        Ok((content, from_remote)) => {
                            provider
                                .ingest(content, from_remote)
                                .await
                                .map_err(|e| anyhow::anyhow!("proxy-provider '{name}': {e}"))?;
                        }
                        Err(e) => warn_initial_load_failure(&provider, &e),
                    }
                } else if let Err(e) = provider.acquire_initial().await {
                    warn_initial_load_failure(&provider, &e);
                }
                result.insert(name.clone(), provider);
            }
            Err(e) if strict => {
                return Err(anyhow::anyhow!(
                    "proxy-provider '{name}' failed to load (strict mode): {e}"
                ));
            }
            Err(e) => {
                warn!(provider = %name, error = %e, "failed to create proxy-provider, skipping");
            }
        }
    }
    Ok(result)
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
    } else {
        warn!(provider = %provider.name, error = %error,
            "initial provider load failed; starting empty");
    }
}

fn compile_opt_regex(
    pattern: &Option<String>,
    field: &str,
) -> Result<Option<regex::Regex>, String> {
    match pattern.as_deref() {
        Some(p) => regex::Regex::new(p).map(Some).map_err(|e| {
            let hint = if ["(?!", "(?=", "(?<"].iter().any(|la| p.contains(la)) {
                "; look-around assertions are not supported — split the pattern \
                 into `filter` + `exclude-filter` instead"
            } else {
                ""
            };
            format!("{field} regex error: {e}{hint}")
        }),
        None => Ok(None),
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

fn build_health_check_config(raw: Option<&RawHealthCheck>) -> Option<HealthCheckConfig> {
    let hc = raw?;
    if !hc.enable.unwrap_or(true) {
        return None;
    }
    Some(HealthCheckConfig {
        url: hc
            .url
            .clone()
            .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_string()),
        interval: hc.interval.unwrap_or(300),
        timeout: hc.timeout.unwrap_or(5000),
        expected_status: hc.expected_status.clone().unwrap_or_default(),
        lazy: hc.lazy.unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::RawProxyProvider;

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

    #[test]
    fn raw_proxy_provider_deserializes_header() {
        let yaml = r#"
type: http
url: "https://example.com/proxies.yaml"
header:
  Authorization: "Bearer token123"
  X-Custom: "value"
"#;
        let raw: RawProxyProvider = serde_yaml::from_str(yaml).unwrap();
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
        let raw: RawProxyProvider = serde_yaml::from_str(yaml).unwrap();
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
        let raw: RawProxyProvider = serde_yaml::from_str(yaml).unwrap();
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

    #[test]
    fn group_filter_lookahead_error_carries_hint() {
        let raw = crate::raw::RawProxyGroup {
            name: "g".to_string(),
            group_type: "select".to_string(),
            filter: Some("^(?!.*expat).*US".to_string()),
            ..Default::default()
        };
        let err = GroupFilter::from_raw_group(&raw).unwrap_err();
        assert!(err.contains("look-around"), "unexpected error: {err}");
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
            serde_yaml::Value::String("front".to_string()),
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
            serde_yaml::Value::String("o-hop".to_string()),
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
            serde_yaml::Value::String(String::new()),
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
            serde_yaml::Value::Number(42.into()),
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
    /// without `apply_merge` the merged field lands on a literal `<<` key
    /// and the node silently dials direct.
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

    /// UDP on a chained provider node must be refused, not silently
    /// direct-dialled: `support_udp()` reports false and `dial_udp` errors
    /// (enforced inside the adapter because the tunnel's UDP dispatch does
    /// not consult `support_udp`).
    #[tokio::test]
    async fn provider_chained_node_udp_is_refused() {
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
            err.contains("cache") || err.contains("'front'"),
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
}
