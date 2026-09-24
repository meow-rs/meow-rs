//! Geodata DB download orchestration — startup-fetch (run unconditionally
//! when a target file is missing) and auto-update loop (periodic refresh
//! when `geodata.auto-update: true`).
//!
//! Both entry points are `pub` so downstream FFI callers that build a
//! `Tunnel` directly — bypassing `main.rs` — can wire the same behavior in
//! without reimplementing it.

use meow_common::adapter::Proxy;
use meow_config::geodata::download_and_replace;
use meow_config::proxy_provider::ProxyProvider;
use meow_config::raw::RawConfig;
use meow_config::rule_provider::RuleProvider;
use meow_config::GeoDataConfig;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// One geodata DB to consider on startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoTarget {
    pub label: &'static str,
    pub path: PathBuf,
    pub url: String,
}

/// Resolve the three geodata target paths (mmdb / asn / geosite) from `geo`,
/// applying the project-wide defaults when an explicit path was not set.
pub fn compute_targets(geo: &GeoDataConfig) -> [GeoTarget; 3] {
    let mmdb = geo
        .mmdb_path
        .clone()
        .unwrap_or_else(meow_config::default_geoip_path);
    let asn = geo
        .asn_path
        .clone()
        .unwrap_or_else(meow_config::default_asn_path);
    let geosite = geo
        .geosite_path
        .clone()
        .unwrap_or_else(meow_config::default_geosite_path);
    [
        GeoTarget {
            label: "GeoIP MMDB",
            path: mmdb,
            url: geo.mmdb_url.clone(),
        },
        GeoTarget {
            label: "ASN MMDB",
            path: asn,
            url: geo.asn_url.clone(),
        },
        GeoTarget {
            label: "geosite",
            path: geosite,
            url: geo.geosite_url.clone(),
        },
    ]
}

/// Download each target whose `path` does not yet exist. Returns the list of
/// labels that were successfully fetched (empty if nothing was missing or
/// every fetch failed). Each target is attempted independently — one failure
/// does not skip the others.
pub async fn fetch_missing(
    targets: &[GeoTarget],
    download_proxy: Option<&Arc<dyn Proxy>>,
) -> Vec<&'static str> {
    let mut downloaded = Vec::new();
    for t in targets {
        if t.path.exists() {
            continue;
        }
        info!(
            "geodata startup-fetch: {} missing at {}, downloading",
            t.label,
            t.path.display()
        );
        match download_and_replace(&t.url, &t.path, download_proxy).await {
            Ok(()) => downloaded.push(t.label),
            Err(e) => warn!(
                "geodata startup-fetch: {} download failed: {:#}",
                t.label, e
            ),
        }
    }
    downloaded
}

/// Reparse + republish the resolver after the geo DB files changed. The
/// raw config is unchanged, so `reconcile_dns_config`'s
/// old-vs-candidate gate would call this a no-op for `geosite:`-only
/// policies — parse and publish directly. The DNS rebuild borrows the
/// same routing rebuild's provider map (the live registry generation
/// these rules bind); no payload snapshot exists to forward — a shared
/// rebuild never prefetches (issue #543). A parse failure warns and
/// keeps the running resolver — the rules commit proceeds regardless.
///
/// `#name` upstreams bind the LIVE route's proxies and dialer registry,
/// not `rebuild`'s: a rules-only rebuild publishes into a transient
/// `ProxyRegistry` cell that `update_rules` never installs, so adapters
/// captured from `rebuild.proxies` would hold a dangling
/// `Weak<RegistryCell>` (and groups a stateless duplicate) once
/// `rebuild` drops.
///
/// The parse runs on a spawned task so a panic unwinds into a
/// `JoinError` we can warn-and-continue on — a panic inside the loop
/// task would silently kill auto-update until restart.
///
/// Ordering is the point of the signature taking `rules`: the DNS parse
/// is the only await before the commits, and it runs FIRST — a
/// cancellation during it leaves nothing committed (the next trigger
/// retries the whole refresh). After the parse resolves, `update_rules`
/// and `publish_dns`'s synchronous resolver swap run back to back with
/// no await between, so the two commits cannot be split (issue #621).
/// Parse inputs are invariant under `update_rules` (`route.proxies` /
/// `dialer_registry` are unchanged by it; `prior` is just the old
/// resolver), so computing them before the rules commit is equivalent.
async fn republish_dns_for_geo_dbs(
    raw: &RawConfig,
    cache_dir: &std::path::Path,
    rule_providers: &std::collections::HashMap<String, Arc<RuleProvider>>,
    rules: Vec<Box<dyn meow_common::rule::Rule>>,
    tunnel: &Tunnel,
    dns_server: &RwLock<Option<meow_api::routes::DnsServerHandle>>,
    label: &str,
) {
    debug_assert!(
        meow_api::routes::CONFIG_MUTATION.try_lock().is_err(),
        "{label}: republish outside the CONFIG_MUTATION lane"
    );
    let raw = raw.clone();
    let cache_dir = cache_dir.to_path_buf();
    let providers = rule_providers.clone();
    let prior = tunnel.resolver();
    let route = tunnel.route_snapshot();
    let parse = tokio::spawn(async move {
        meow_config::parse_dns_from_raw(
            &raw,
            Some(&cache_dir),
            &route.proxies,
            Some(&providers),
            None,
            Some(prior.as_ref()),
            Some(&route.dialer_registry),
        )
        .await
    });
    // Abort the parse if this future is cancelled while awaiting it —
    // a dropped JoinHandle would detach the task and keep the cloned
    // inputs alive until it finishes anyway.
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _abort_guard = AbortOnDrop(parse.abort_handle());
    let parsed = parse.await;
    // Commits — synchronous, adjacent, no await between.
    tunnel.update_rules(rules);
    match parsed {
        Ok(Ok(dns)) => meow_api::routes::publish_dns(tunnel, dns_server, &dns).await,
        Ok(Err(e)) => warn!("{label}: dns republish skipped: {e:#}"),
        Err(e) => warn!("{label}: dns republish task failed: {e}"),
    }
}

/// Startup-fetch entry point: download any geodata DB whose target file does
/// not yet exist, then rebuild rules so the freshly-downloaded DBs take
/// effect without a restart. Independent of `geodata.auto-update` — the goal
/// is "if the file is missing when meow boots, fetch it so rules work on
/// first run." Safe to spawn as a background task.
///
/// `rule_providers` must be the same shared registry `ApiServer` holds —
/// a private `RwLock` would fork the API-visible provider set. The
/// rebuild binds those live provider objects rather than replacing the
/// registry, so no supervisor reconcile is needed here. `dns_server` is
/// the shared DNS-server handle — after a DB download the resolver is
/// reparsed and republished so `geosite:`/`rule-set:` policy matchers
/// bind the new DB generation (issue #543).
pub async fn run_on_startup(
    geo: GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    // Live proxy providers — group `use:` names resolve against them;
    // an empty map fails every `use:` group under `strict: true`.
    proxy_providers: Arc<dashmap::DashMap<String, Arc<ProxyProvider>>>,
    dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>>,
    cache_dir: PathBuf,
) {
    let targets = compute_targets(&geo);

    let route = tunnel.route_snapshot();
    let proxies = &route.proxies;
    let download_proxy = meow_config::internal_http::first_named_proxy(
        raw_config.read().proxies.as_deref(),
        proxies,
    );

    let downloaded = fetch_missing(&targets, download_proxy.as_ref()).await;
    if downloaded.is_empty() {
        return;
    }

    // Serialize against config commits and rebuild from the raw committed
    // *inside* the lane — otherwise a download finishing after a PUT could
    // revert rules to a set built from the pre-PUT config (issue #514).
    let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
    let raw = raw_config.read().clone();
    // Share the tunnel's resolver slot so the rebuilt DIRECT adapter
    // tracks later `set_resolver` swaps (issue #514).
    let resolver = tunnel.resolver_slot();
    let rebuild = tokio::task::spawn_blocking({
        let cache_dir = cache_dir.clone();
        let raw = raw.clone();
        let rule_providers = Arc::clone(&rule_providers);
        let proxy_providers: std::collections::HashMap<_, _> = proxy_providers
            .iter()
            .map(|e| (e.key().clone(), Arc::clone(e.value())))
            .collect();
        move || {
            meow_config::rebuild_from_raw_with_resolver(
                &raw,
                Some(&resolver),
                Some(cache_dir.as_path()),
                &proxy_providers,
                // Rules-only refresh — bind the rebuilt RULE-SET rules to
                // the LIVE provider objects so the rebuild sees each
                // provider's current (possibly refreshed) content rather
                // than a fresh declaration (issue #533 review). Refreshes
                // landing after this rebuild stay visible too: the
                // matchers hold the same Arc<RuleProvider> objects the
                // refresh tasks mutate (issue #553).
                Some(rule_providers.read().clone()),
            )
        }
    })
    .await;
    match rebuild {
        Ok(Ok(rebuild)) => {
            // The republish owns the commit order: DNS parse first
            // (cancel = nothing committed), then `update_rules` and the
            // synchronous resolver swap back to back (issue #621). The
            // DNS parse borrows the rebuild's (live) provider map
            // (issue #543).
            republish_dns_for_geo_dbs(
                &raw,
                &cache_dir,
                &rebuild.rule_providers,
                rebuild.rules,
                &tunnel,
                &dns_server,
                "geodata startup-fetch",
            )
            .await;
            // No registry swap or supervisor reconcile: the rebuild bound
            // the live provider objects, so the map is unchanged and every
            // interval task is already supervised. Known limitation:
            // provider payloads embed geo entries parsed against the
            // provider's load-time ctx — a DB arriving via this fetch only
            // reaches them at the next full config commit.
            info!("geodata startup-fetch: rules reloaded with downloaded DBs");
        }
        Ok(Err(e)) => warn!(
            "geodata startup-fetch: rule rebuild failed after download: {:#}",
            e
        ),
        Err(e) => warn!(
            "geodata startup-fetch: rule rebuild task failed after download: {}",
            e
        ),
    }
}

/// Background task that periodically re-downloads the ASN and geosite DBs
/// when `geodata.auto-update: true`. After each successful download the DB
/// file is atomically replaced on disk, then rules are rebuilt and the DNS
/// resolver republished (same helper as `run_on_startup`) — all without
/// restart. Runs forever; spawn as a background task.
///
/// The GeoIP MMDB is intentionally NOT refreshed here — country-code → CIDR
/// mappings change infrequently and skipping the rebuild keeps the
/// parser-built `CountryIndex` alive without churn. Operators who need to
/// update GeoIP should replace `Country.mmdb` on disk and restart.
///
/// The tunnel is captured weakly (issue #514): an embedder that drops
/// every `Tunnel` handle stops this loop at the next tick instead of
/// pinning `TunnelInner` forever.
///
/// See [`run_on_startup`] for the `rule_providers` / `proxy_providers` /
/// `dns_server` sharing contract.
pub async fn auto_update_loop(
    geo: GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    // Same contract as `run_on_startup` — the live provider registry.
    proxy_providers: Arc<dashmap::DashMap<String, Arc<ProxyProvider>>>,
    dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>>,
    cache_dir: PathBuf,
) {
    let interval = std::time::Duration::from_secs(geo.auto_update_interval as u64 * 3600);
    let mut ticker = tokio::time::interval(interval);
    // After a suspend longer than the interval, tick once per loop turn
    // rather than bursting every missed slot (same policy as the
    // rule-provider refresh supervisor).
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // skip the immediate first tick

    let weak = tunnel.weak_inner();
    drop(tunnel);

    let asn_target = geo
        .asn_path
        .clone()
        .unwrap_or_else(meow_config::default_asn_path);
    let geosite_target = geo
        .geosite_path
        .clone()
        .unwrap_or_else(meow_config::default_geosite_path);

    loop {
        ticker.tick().await;

        let Some(inner) = weak.upgrade() else {
            info!("tunnel dropped; stopping geodata auto-update loop");
            return;
        };
        let tunnel = Tunnel::from_inner(inner);

        auto_update_tick(
            &geo,
            &tunnel,
            &raw_config,
            Arc::clone(&rule_providers),
            &proxy_providers,
            &dns_server,
            &cache_dir,
            &asn_target,
            &geosite_target,
        )
        .await;
    }
}

/// One auto-update round: download both DBs (each failure is logged and
/// skipped — a partial update still commits), then serialize through the
/// config lane to rebuild rules and republish the resolver. Split out of
/// `auto_update_loop` so the orchestration is directly testable without
/// driving the ticker (issue #543 review).
#[allow(clippy::too_many_arguments)]
async fn auto_update_tick(
    geo: &GeoDataConfig,
    tunnel: &Tunnel,
    raw_config: &RwLock<RawConfig>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    proxy_providers: &dashmap::DashMap<String, Arc<ProxyProvider>>,
    dns_server: &RwLock<Option<meow_api::routes::DnsServerHandle>>,
    cache_dir: &std::path::Path,
    asn_target: &std::path::Path,
    geosite_target: &std::path::Path,
) {
    let mut any_updated = false;

    let route = tunnel.route_snapshot();
    let proxies = &route.proxies;
    let download_proxy = meow_config::internal_http::first_named_proxy(
        raw_config.read().proxies.as_deref(),
        proxies,
    );

    if let Err(e) = download_and_replace(&geo.asn_url, asn_target, download_proxy.as_ref()).await {
        warn!("geodata auto-update: ASN MMDB download failed: {:#}", e);
    } else {
        any_updated = true;
    }

    if let Err(e) =
        download_and_replace(&geo.geosite_url, geosite_target, download_proxy.as_ref()).await
    {
        warn!("geodata auto-update: geosite download failed: {:#}", e);
    } else {
        any_updated = true;
    }

    if !any_updated {
        warn!("geodata auto-update: all downloads failed; rules not reloaded");
        return;
    }

    // Serialize against config commits and rebuild from the raw
    // committed *inside* the lane — otherwise this rebuild could
    // revert rules committed by a concurrent PUT (issue #514).
    let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
    let raw = raw_config.read().clone();
    // Share the tunnel's resolver slot so the rebuilt DIRECT adapter
    // tracks later `set_resolver` swaps (issue #514).
    let resolver = tunnel.resolver_slot();
    let rebuild = tokio::task::spawn_blocking({
        let cache_dir = cache_dir.to_path_buf();
        let raw = raw.clone();
        let rule_providers = Arc::clone(&rule_providers);
        let proxy_providers: std::collections::HashMap<_, _> = proxy_providers
            .iter()
            .map(|e| (e.key().clone(), Arc::clone(e.value())))
            .collect();
        move || {
            meow_config::rebuild_from_raw_with_resolver(
                &raw,
                Some(&resolver),
                Some(cache_dir.as_path()),
                &proxy_providers,
                // Rules-only refresh — bind the rebuilt RULE-SET rules
                // to the LIVE provider set so API/provider refreshes
                // keep reaching them (issue #533 review).
                Some(rule_providers.read().clone()),
            )
        }
    })
    .await;
    match rebuild {
        Ok(Ok(rebuild)) => {
            // Same ordering as the startup path — the republish parses
            // DNS first (cancel = nothing committed), then commits rules
            // and the resolver swap back to back (issue #621). No
            // registry write or reconcile: the rebuild bound the live
            // provider objects (issue #543).
            republish_dns_for_geo_dbs(
                &raw,
                cache_dir,
                &rebuild.rule_providers,
                rebuild.rules,
                tunnel,
                dns_server,
                "geodata auto-update",
            )
            .await;
            info!("geodata auto-update: rules reloaded with updated DBs");
        }
        Ok(Err(e)) => {
            warn!(
                "geodata auto-update: rule rebuild failed after DB download: {:#}",
                e
            );
        }
        Err(e) => {
            warn!(
                "geodata auto-update: rule rebuild task failed after DB download: {}",
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg_with_paths(
        mmdb: Option<&str>,
        asn: Option<&str>,
        geosite: Option<&str>,
    ) -> GeoDataConfig {
        GeoDataConfig {
            mmdb_path: mmdb.map(PathBuf::from),
            asn_path: asn.map(PathBuf::from),
            geosite_path: geosite.map(PathBuf::from),
            mmdb_url: "https://example.test/country.mmdb".into(),
            asn_url: "https://example.test/asn.mmdb".into(),
            geosite_url: "https://example.test/geosite.mrs".into(),
            ..GeoDataConfig::default()
        }
    }

    #[test]
    fn compute_targets_uses_explicit_paths_when_set() {
        let cfg = cfg_with_paths(
            Some("/tmp/explicit/country.mmdb"),
            Some("/tmp/explicit/asn.mmdb"),
            Some("/tmp/explicit/geosite.mrs"),
        );
        let t = compute_targets(&cfg);
        assert_eq!(t[0].label, "GeoIP MMDB");
        assert_eq!(t[0].path, PathBuf::from("/tmp/explicit/country.mmdb"));
        assert_eq!(t[1].label, "ASN MMDB");
        assert_eq!(t[1].path, PathBuf::from("/tmp/explicit/asn.mmdb"));
        assert_eq!(t[2].label, "geosite");
        assert_eq!(t[2].path, PathBuf::from("/tmp/explicit/geosite.mrs"));
    }

    #[test]
    fn compute_targets_falls_back_to_defaults_when_unset() {
        let cfg = cfg_with_paths(None, None, None);
        let t = compute_targets(&cfg);
        // Defaults are project-defined; we just assert non-empty + matching
        // file basenames so the test isn't tied to the user's home dir.
        assert_eq!(t[0].path, meow_config::default_geoip_path());
        assert_eq!(t[1].path, meow_config::default_asn_path());
        assert_eq!(t[2].path, meow_config::default_geosite_path());
    }

    #[test]
    fn compute_targets_carries_urls() {
        let cfg = cfg_with_paths(None, None, None);
        let t = compute_targets(&cfg);
        assert_eq!(t[0].url, "https://example.test/country.mmdb");
        assert_eq!(t[1].url, "https://example.test/asn.mmdb");
        assert_eq!(t[2].url, "https://example.test/geosite.mrs");
    }

    #[tokio::test]
    async fn fetch_missing_skips_existing_files() {
        // All three targets point at files that already exist → returns empty
        // and never touches the network (the URLs are unreachable).
        let dir = tempfile::tempdir().unwrap();
        let mmdb = dir.path().join("country.mmdb");
        let asn = dir.path().join("asn.mmdb");
        let geosite = dir.path().join("geosite.mrs");
        std::fs::write(&mmdb, b"existing-mmdb").unwrap();
        std::fs::write(&asn, b"existing-asn").unwrap();
        std::fs::write(&geosite, b"existing-geosite").unwrap();

        let cfg = cfg_with_paths(
            Some(mmdb.to_str().unwrap()),
            Some(asn.to_str().unwrap()),
            Some(geosite.to_str().unwrap()),
        );
        let targets = compute_targets(&cfg);
        let downloaded = fetch_missing(&targets, None).await;
        assert!(
            downloaded.is_empty(),
            "no file is missing → no download attempt"
        );
        // Files are unchanged.
        assert_eq!(std::fs::read(&mmdb).unwrap(), b"existing-mmdb");
    }

    /// Issue #543 — after the geo DB files change, the resolver must be
    /// republished even though the raw config is unchanged
    /// (`dns_inputs_equal` would call it a no-op). Observable as a new
    /// resolver generation on the tunnel.
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_swaps_resolver_generation() {
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  nameserver:\n    - 127.0.0.1\nrules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec!["127.0.0.1:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let before = tunnel.resolver();
        let dir = tempfile::tempdir().unwrap();
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));

        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            dir.path(),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        assert!(
            !Arc::ptr_eq(&before, &tunnel.resolver()),
            "a geo-DB refresh must republish the resolver generation"
        );
        // `publish_dns` installs the process-global host resolver for an
        // enabled `dns:` section — clear it so sibling tests observe a
        // clean global.
        meow_common::clear_host_resolver();
    }

    /// Issue #543 — the republish must reach a RUNNING standalone DNS
    /// server: `publish_dns` writes the rebuilt resolver into the
    /// handle's shared slot so the live `dns.listen` socket serves the
    /// new generation without a rebind.
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_swaps_live_server_slot() {
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  listen: 127.0.0.1:0\n  nameserver:\n    - 127.0.0.1\nrules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec!["127.0.0.1:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let dir = tempfile::tempdir().unwrap();
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();

        let stale = Arc::new(meow_dns::Resolver::new(
            vec!["127.0.0.1:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        let slot = meow_dns::new_resolver_slot(Arc::clone(&stale));
        // A live (never-finished) serve task keeps `publish_dns` on the
        // in-place slot-swap path rather than a rebind.
        let dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(Some(meow_api::routes::DnsServerHandle {
                listen: "127.0.0.1:0".parse().unwrap(),
                task: tokio::spawn(std::future::pending::<()>()),
                resolver_slot: Arc::clone(&slot),
            })));

        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            dir.path(),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        assert!(
            !Arc::ptr_eq(&stale, &slot.read()),
            "the running server's slot must leave the stale generation"
        );
        assert!(
            Arc::ptr_eq(&slot.read(), &tunnel.resolver()),
            "server slot and tunnel must hold the same rebuilt resolver"
        );
        meow_common::clear_host_resolver();
    }

    /// Issue #543 — the republished resolver must bind the NEW geosite DB,
    /// not merely be a fresh `Arc`. A `geosite:` nameserver-policy that
    /// missed under the old DB generation must start routing to its
    /// policy upstream once the DB containing the domain is in place.
    /// `rcode://` upstreams answer a fixed rcode with no I/O and record
    /// their label as the cache entry's `source`, which makes the tier
    /// that answered observable through `dns_results`.
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_binds_new_geosite_generation() {
        let dir = tempfile::tempdir().unwrap();
        let geosite_path = dir.path().join("geosite.mrs");
        // v1: the category exists but does not contain the probe domain —
        // the policy matcher is built yet never fires, the exact shape a
        // stale generation leaves behind.
        let v1 = meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec!["other.example".to_string()])],
        };
        std::fs::write(
            &geosite_path,
            meow_rules::mrs_parser::write_geosite_mrs(&v1).unwrap(),
        )
        .unwrap();

        let raw: RawConfig = serde_yaml::from_str(&format!(
            "geodata:\n  geosite-path: '{}'\n\
             dns:\n  enable: true\n  nameserver:\n    - rcode://success\n  \
             nameserver-policy:\n    \"geosite:testcat\": rcode://name_error\n\
             rules:\n  - MATCH,DIRECT\n",
            geosite_path.display()
        ))
        .unwrap();

        // The "before" generation is bound to v1 via the same parse path.
        let before_dns = meow_config::parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &HashMap::new(),
            Some(&HashMap::new()),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let tunnel = Tunnel::new(Arc::clone(&before_dns.resolver));
        let before = tunnel.resolver();

        tunnel.resolver().lookup_ipv4("hit.example").await;
        let results = tunnel.resolver().dns_results(Some("hit.example"), 1);
        let source = results.first().and_then(|e| e.source.as_deref());
        assert_eq!(
            source,
            Some("rcode:NoError"),
            "v1 lacks the probe domain → the main upstream must answer"
        );

        // The refresh lands: v2 contains the probe domain.
        let v2 = meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec!["hit.example".to_string()])],
        };
        std::fs::write(
            &geosite_path,
            meow_rules::mrs_parser::write_geosite_mrs(&v2).unwrap(),
        )
        .unwrap();
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));
        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            dir.path(),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        assert!(!Arc::ptr_eq(&before, &tunnel.resolver()));
        tunnel.resolver().lookup_ipv4("hit.example").await;
        let results = tunnel.resolver().dns_results(Some("hit.example"), 1);
        let source = results.first().and_then(|e| e.source.as_deref());
        assert_eq!(
            source,
            Some("rcode:NXDomain"),
            "the republished resolver must bind the v2 geosite generation"
        );
        meow_common::clear_host_resolver();
    }

    /// Issue #543 — a DNS parse failure warns and keeps the running
    /// resolver; the routing commit above is not rolled back
    /// (`rule-set:gone` has no declared provider → deterministic `Err`).
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_parse_failure_keeps_resolver() {
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  nameserver:\n    - rcode://success\n  \
             nameserver-policy:\n    \"rule-set:gone\": rcode://success\n\
             rules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec!["127.0.0.1:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let before = tunnel.resolver();
        let dir = tempfile::tempdir().unwrap();
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));

        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            dir.path(),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        assert!(
            Arc::ptr_eq(&before, &tunnel.resolver()),
            "a failed DNS rebuild must keep the running resolver"
        );
    }

    /// Issue #543 — `prior_resolver` carries the fake-IP pool across the
    /// republish so clients holding `host → fake-ip` answers keep valid
    /// reverse mappings (a `None` regression would silently strand them).
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_preserves_fake_ip_pool() {
        let dir = tempfile::tempdir().unwrap();
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  \
             fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - rcode://success\n\
             rules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        let before_dns = meow_config::parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &HashMap::new(),
            Some(&HashMap::new()),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let tunnel = Tunnel::new(Arc::clone(&before_dns.resolver));
        let before = tunnel.resolver();
        let net = before
            .fake_ip_v4_net()
            .expect("fake-ip mode gives a v4 net");
        let pool = before
            .fakeip_pool_over(net)
            .expect("fake-ip resolver holds a pool");

        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));
        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            dir.path(),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        let after = tunnel.resolver();
        assert!(
            Arc::ptr_eq(&pool, &after.fakeip_pool_over(net).unwrap()),
            "the republished resolver must reuse the prior fake-IP pool"
        );
        meow_common::clear_host_resolver();
    }

    /// `#name` upstreams must bind the LIVE route's proxies — a rules-only
    /// rebuild publishes into a transient `ProxyRegistry` that
    /// `update_rules` never installs, so adapters captured from
    /// `rebuild.proxies` would hold a dangling `Weak<RegistryCell>` once
    /// `rebuild` drops (issue #543 review).
    #[tokio::test]
    async fn republish_dns_binds_live_registry_cell_not_transient_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        // Both proxies are `type: direct` so the chained dial completes a
        // real loopback TCP connection when the front hop resolves.
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  nameserver:\n    - \"tcp://127.0.0.1:9#chained\"\n\
             proxies:\n  - {name: hop, type: direct}\n  \
             - {name: chained, type: direct, dialer-proxy: hop}\n\
             rules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();

        // The committed generation: installed on the route table, which
        // retains its registry cell for the route's lifetime.
        let committed = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let before_dns = meow_config::parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &committed.proxies,
            Some(&committed.rule_providers),
            Some(&committed.prefetched_payloads),
            None,
            Some(&committed.dialer_registry),
        )
        .await
        .unwrap();
        let tunnel = Tunnel::new(Arc::clone(&before_dns.resolver));
        tunnel.update_routing(
            committed.proxies,
            committed.rules,
            committed.dialer_registry,
        );

        // The geodata rebuild — its proxy map and dialer-registry cell are
        // transient: `update_rules` never installs them.
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));
        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            dir.path(),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;
        // `rebuild.rules` moved into the republish; drop the remaining
        // transient halves (proxy map + dialer-registry cell) so a
        // dangling Weak would be caught below.
        drop(rebuild.proxies);
        drop(rebuild.dialer_registry);
        drop(rebuild.rule_providers);

        // A dial through the captured `#chained` upstream resolves `hop`
        // via the live route's retained cell. A dead cell would fail with
        // "registry generation dropped"; a live one reaches the listener.
        let resolver = tunnel.resolver();
        let proxy = resolver
            .main_nameservers()
            .iter()
            .find_map(|c| c.proxy().cloned())
            .expect("the #chained upstream must be proxied");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let meta = meow_common::Metadata {
            host: "127.0.0.1".into(),
            dst_port: port,
            ..Default::default()
        };
        proxy
            .dial_tcp(&meta)
            .await
            .expect("the republished resolver's #chained adapter must resolve its front hop");
        meow_common::clear_host_resolver();
    }

    /// Issue #543 — the periodic tick itself (not just the startup path)
    /// must republish the resolver: `auto_update_loop`'s per-tick body is
    /// `auto_update_tick`, exercised here directly so no ticker timing is
    /// involved. A stale geosite generation misses the probe domain
    /// before the tick and answers it afterwards.
    #[tokio::test]
    async fn auto_update_tick_republishes_resolver_with_new_geosite() {
        // Origin serving the v2 geosite containing the probe domain.
        let v2 = meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec!["hit.example".to_string()])],
        };
        let body = meow_rules::mrs_parser::write_geosite_mrs(&v2).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                use std::io::{Read, Write};
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !stop.load(std::sync::atomic::Ordering::SeqCst)
                    && std::time::Instant::now() < deadline
                {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ =
                                stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                            let mut buf = [0_u8; 2048];
                            let _ = stream.read(&mut buf);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(&body);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let geosite_path = dir.path().join("geosite.mrs");
        // v1 on disk: the category exists but misses the probe domain.
        let v1 = meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec!["other.example".to_string()])],
        };
        std::fs::write(
            &geosite_path,
            meow_rules::mrs_parser::write_geosite_mrs(&v1).unwrap(),
        )
        .unwrap();
        let asn_target = dir.path().join("asn.mmdb");

        let raw: RawConfig = serde_yaml::from_str(&format!(
            "geodata:\n  geosite-path: '{}'\n\
             dns:\n  enable: true\n  nameserver:\n    - rcode://success\n  \
             nameserver-policy:\n    \"geosite:testcat\": rcode://name_error\n\
             rules:\n  - MATCH,DIRECT\n",
            geosite_path.display()
        ))
        .unwrap();

        // Bind the "before" generation to v1 through the real parse path.
        let before_dns = meow_config::parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &HashMap::new(),
            Some(&HashMap::new()),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let tunnel = Tunnel::new(Arc::clone(&before_dns.resolver));
        let before = tunnel.resolver();

        tunnel.resolver().lookup_ipv4("hit.example").await;
        let results = tunnel.resolver().dns_results(Some("hit.example"), 1);
        assert_eq!(
            results.first().and_then(|e| e.source.as_deref()),
            Some("rcode:NoError"),
            "v1 does not contain the probe domain — the main upstream must answer"
        );

        let geo = GeoDataConfig {
            geosite_url: format!("http://{addr}/geosite.mrs"),
            // Unreachable — tolerated: a partial update still commits.
            asn_url: "http://127.0.0.1:1/asn.mmdb".to_string(),
            ..GeoDataConfig::default()
        };
        let dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));

        auto_update_tick(
            &geo,
            &tunnel,
            &RwLock::new(raw),
            Arc::new(RwLock::new(HashMap::new())),
            &dashmap::DashMap::new(),
            &dns_server,
            dir.path(),
            &asn_target,
            &geosite_path,
        )
        .await;

        assert!(
            geosite_path.exists(),
            "the tick must have written the downloaded DB"
        );
        assert!(
            !Arc::ptr_eq(&before, &tunnel.resolver()),
            "the periodic tick must republish the resolver generation"
        );
        tunnel.resolver().lookup_ipv4("hit.example").await;
        let results = tunnel.resolver().dns_results(Some("hit.example"), 1);
        assert_eq!(
            results.first().and_then(|e| e.source.as_deref()),
            Some("rcode:NXDomain"),
            "after the tick the geosite policy must answer via its upstream"
        );
        meow_common::clear_host_resolver();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
