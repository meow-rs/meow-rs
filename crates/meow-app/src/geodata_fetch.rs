//! Geodata DB download orchestration — the auto-update loop (periodic
//! refresh when `geodata.auto-update: true`).
//!
//! Startup fetching of missing DBs lives inside `build_config`'s
//! `ensure_geodata` (meow-config), which downloads only the databases the
//! config actually references before the rule/parser context is built —
//! there is no unconditional boot-time sweep here. This module owns the
//! background refresh loop and the rebuild/republish choreography a
//! successful refresh commits through.
//!
//! It also owns the retry for a referenced geosite DB that startup could
//! not download (`missing_geosite_retry_loop`).
//!
//! `auto_update_loop` and `missing_geosite_retry_loop` are `pub` so
//! downstream FFI callers that build a `Tunnel` directly — bypassing
//! `main.rs` — can wire the same behavior in without reimplementing it.

use meow_common::logbook::{self, Level};
use meow_config::geodata::download_and_replace;
use meow_config::proxy_provider::ProxyProvider;
use meow_config::raw::RawConfig;
use meow_config::rule_provider::RuleProvider;
use meow_config::GeoDataConfig;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{info, warn};

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
    cache_dir: Option<&std::path::Path>,
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
    let cache_dir = cache_dir.map(std::path::Path::to_path_buf);
    let providers = rule_providers.clone();
    let prior = tunnel.resolver();
    let route = tunnel.route_snapshot();
    let parse = tokio::spawn(async move {
        meow_config::parse_dns_from_raw(
            &raw,
            cache_dir.as_deref(),
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

/// Background task that periodically re-downloads the ASN and geosite DBs
/// when `geodata.auto-update: true`. After each successful download the DB
/// file is atomically replaced on disk, then rules are rebuilt and the DNS
/// resolver republished — all without restart. Runs forever; spawn as a
/// background task.
///
/// Only the databases the startup config actually references are refreshed:
/// `needs` is the `GeoDataNeeds` snapshot `build_config` computes from the
/// rule/sub-rule/provider-payload scan plus the DNS consumers (see
/// `meow_config::geo_references`). It is a STARTUP SNAPSHOT — a later
/// `PUT /configs` that adds a geo reference does not widen it: that
/// rebuild downloads the newly referenced DB once if it is missing
/// (`rebuild_from_raw_runtime`), but this loop does not refresh it.
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
/// `rule_providers` must be the same shared registry `ApiServer` holds —
/// a private `RwLock` would fork the API-visible provider set; the
/// post-download rebuild binds those live provider objects rather than
/// replacing the registry, so no supervisor reconcile is needed here.
/// `proxy_providers` feeds group `use:` resolution inside the rebuild —
/// pass the live registry, an empty map fails every `use:` group under
/// `strict: true`. `dns_server` is the shared DNS-server handle — after a
/// DB download the resolver is reparsed and republished so
/// `geosite:`/`rule-set:` policy matchers bind the new DB generation
/// (issue #543). `cache_dir` feeds only the post-download rebuild context
/// (provider `path:` containment, fake-IP store base) — pass the same value
/// startup used so a republish cannot admit paths `-t` would have rejected.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct shared registry the post-download \
              rebuild needs; bundling them would only rename the list"
)]
pub async fn auto_update_loop(
    geo: GeoDataConfig,
    needs: meow_config::GeoDataNeeds,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    // The live provider registry — group `use:` names resolve against it.
    proxy_providers: Arc<dashmap::DashMap<String, Arc<ProxyProvider>>>,
    dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>>,
    cache_dir: Option<std::path::PathBuf>,
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
            needs,
            &tunnel,
            &raw_config,
            Arc::clone(&rule_providers),
            &proxy_providers,
            &dns_server,
            cache_dir.as_deref(),
            &asn_target,
            &geosite_target,
        )
        .await;
    }
}

/// First and last pause between [`missing_geosite_retry_loop`] attempts.
const GEOSITE_RETRY_FIRST: std::time::Duration = std::time::Duration::from_secs(60);
const GEOSITE_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(3600);

/// Background retry for a geosite DB the startup config references but
/// `build_config` could not download. Geosite is tolerated absent, so the
/// build succeeds, but until the DB lands every GEOSITE rule and
/// `geosite:` nameserver-policy key no-matches — and with
/// `geodata.auto-update` off nothing else would fetch it. Spawn it when
/// `config.geo_needs.geosite` holds and [`meow_config::geosite_db_present`]
/// does not.
///
/// Each attempt is an `auto_update_tick` scoped to geosite, so a
/// successful download rebuilds the rules and republishes the resolver
/// exactly as a scheduled refresh does. Attempts back off from one minute,
/// doubling to an hour. The loop ends once the DB is on disk — downloaded
/// here, by the auto-update loop, or put there by the operator — or when
/// every `Tunnel` handle is dropped (the tunnel is held weakly, as in
/// [`auto_update_loop`]). Arguments are [`auto_update_loop`]'s.
#[allow(
    clippy::too_many_arguments,
    reason = "the same shared registries `auto_update_loop` takes"
)]
pub async fn missing_geosite_retry_loop(
    geo: GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    proxy_providers: Arc<dashmap::DashMap<String, Arc<ProxyProvider>>>,
    dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>>,
    cache_dir: Option<std::path::PathBuf>,
) {
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
    let needs = meow_config::GeoDataNeeds {
        geosite: true,
        ..Default::default()
    };

    let mut delay = GEOSITE_RETRY_FIRST;
    loop {
        tokio::time::sleep(delay).await;
        if meow_config::geosite_db_present(&geo) {
            return;
        }
        let Some(inner) = weak.upgrade() else {
            return;
        };
        let tunnel = Tunnel::from_inner(inner);
        info!("geodata: retrying the geosite download startup could not complete");
        auto_update_tick(
            &geo,
            needs,
            &tunnel,
            &raw_config,
            Arc::clone(&rule_providers),
            &proxy_providers,
            &dns_server,
            cache_dir.as_deref(),
            &asn_target,
            &geosite_target,
        )
        .await;
        if meow_config::geosite_db_present(&geo) {
            return;
        }
        delay = (delay * 2).min(GEOSITE_RETRY_MAX);
    }
}

/// One auto-update round: download each DB the startup `needs` snapshot
/// marks as referenced (each failure is logged and skipped — a partial
/// update still commits), then serialize through the config lane to
/// rebuild rules and republish the resolver. Split out of
/// `auto_update_loop` so the orchestration is directly testable without
/// driving the ticker (issue #543 review).
#[allow(clippy::too_many_arguments)]
async fn auto_update_tick(
    geo: &GeoDataConfig,
    needs: meow_config::GeoDataNeeds,
    tunnel: &Tunnel,
    raw_config: &RwLock<RawConfig>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    proxy_providers: &dashmap::DashMap<String, Arc<ProxyProvider>>,
    dns_server: &RwLock<Option<meow_api::routes::DnsServerHandle>>,
    cache_dir: Option<&std::path::Path>,
    asn_target: &std::path::Path,
    geosite_target: &std::path::Path,
) {
    // Nothing referenced → nothing to download or rebuild. Early-return
    // keeps an all-false `needs` (e.g. GEOIP-only configs, which the tick
    // never refreshes) off the "all downloads failed" warn path below.
    if !needs.asn && !needs.geosite {
        return;
    }
    let mut updated = Vec::new();

    let route = tunnel.route_snapshot();
    let egress =
        meow_config::resolve_geodata_egress(&raw_config.read(), geo, tunnel.mode(), &route.proxies);

    if needs.asn {
        if let Err(e) = download_and_replace(&geo.asn_url, asn_target, &egress).await {
            warn!("geodata auto-update: ASN MMDB download failed: {:#}", e);
            download_failed("ASN MMDB", &e);
        } else {
            updated.push("ASN MMDB");
        }
    }

    if needs.geosite {
        if let Err(e) = download_and_replace(&geo.geosite_url, geosite_target, &egress).await {
            warn!("geodata auto-update: geosite download failed: {:#}", e);
            download_failed("geosite", &e);
        } else {
            updated.push("geosite");
        }
    }

    if updated.is_empty() {
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
        let cache_dir = cache_dir.map(std::path::Path::to_path_buf);
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
                cache_dir.as_deref(),
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
            reloaded(&updated, "Updated");
        }
        Ok(Err(e)) => {
            warn!(
                "geodata auto-update: rule rebuild failed after DB download: {:#}",
                e
            );
            reload_failed(&updated, &format!("{e:#}"));
        }
        Err(e) => {
            warn!(
                "geodata auto-update: rule rebuild task failed after DB download: {}",
                e
            );
            reload_failed(&updated, &e.to_string());
        }
    }
}

/// Logbook: downloading DB `label` failed. Each DB is its own subject, so
/// a DB that keeps failing folds into one entry.
fn download_failed(label: &'static str, error: &anyhow::Error) {
    let error = format!("{error:#}");
    logbook::event(
        logbook::kind::GEODATA_UPDATE,
        Level::Error,
        format!("Downloading {label} failed: {error}"),
    )
    .subject(label)
    .field("error", error)
    .coalesce()
    .record();
}

/// Logbook: the rules now use the downloaded DBs.
fn reloaded(labels: &[&'static str], verb: &str) {
    for label in labels {
        logbook::event(
            logbook::kind::GEODATA_UPDATE,
            Level::Info,
            format!("{verb} {label}"),
        )
        .subject(*label)
        .record();
    }
}

/// Logbook: DBs were downloaded, but rebuilding the rules on them failed,
/// so the running rules still use the previous data.
fn reload_failed(labels: &[&'static str], error: &str) {
    for label in labels {
        logbook::event(
            logbook::kind::GEODATA_UPDATE,
            Level::Error,
            format!("Downloaded {label}, but reloading the rules failed: {error}"),
        )
        .subject(*label)
        .field("error", error)
        .coalesce()
        .record();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Issue #543 — after the geo DB files change, the resolver must be
    /// republished even though the raw config is unchanged
    /// (`dns_inputs_equal` would call it a no-op). Observable as a new
    /// resolver generation on the tunnel.
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_swaps_resolver_generation() {
        let raw: RawConfig = serde_saphyr::from_str(
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
            Some(dir.path()),
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
        let raw: RawConfig = serde_saphyr::from_str(
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
            Some(dir.path()),
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

        let raw: RawConfig = serde_saphyr::from_str(&format!(
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
            Some(dir.path()),
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
        let raw: RawConfig = serde_saphyr::from_str(
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
            Some(dir.path()),
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
        let raw: RawConfig = serde_saphyr::from_str(
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
            Some(dir.path()),
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
        let raw: RawConfig = serde_saphyr::from_str(
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
            Some(dir.path()),
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

        let raw: RawConfig = serde_saphyr::from_str(&format!(
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
            // The raw's nameserver-policy references geosite — and the
            // unreachable ASN URL is exercised as a tolerated partial
            // failure, so mark both.
            meow_config::GeoDataNeeds {
                asn: true,
                geosite: true,
                ..meow_config::GeoDataNeeds::default()
            },
            &tunnel,
            &RwLock::new(raw),
            Arc::new(RwLock::new(HashMap::new())),
            &dashmap::DashMap::new(),
            &dns_server,
            Some(dir.path()),
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

    /// Serve `body` to every accepted connection until `stop` flips —
    /// returns the bound address plus a hit counter so "the tick did NOT
    /// dial this URL" is directly observable.
    fn spawn_body_server(
        body: &'static [u8],
    ) -> (
        std::net::SocketAddr,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::spawn({
            let hits = Arc::clone(&hits);
            let stop = Arc::clone(&stop);
            move || {
                use std::io::{Read, Write};
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !stop.load(std::sync::atomic::Ordering::SeqCst)
                    && std::time::Instant::now() < deadline
                {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let _ =
                                stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                            let mut buf = [0_u8; 2048];
                            let _ = stream.read(&mut buf);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(body);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            }
        });
        (addr, hits, stop)
    }

    /// The tick refreshes only the DBs the startup `needs` snapshot marks
    /// referenced — a `false` flag must not even dial that DB's URL
    /// (observable: zero hits on its origin, no file on disk) while the
    /// referenced sibling is downloaded and replaced.
    #[tokio::test]
    async fn auto_update_tick_downloads_only_referenced_dbs() {
        let (asn_addr, asn_hits, asn_stop) = spawn_body_server(b"asn");
        let v2 =
            meow_rules::mrs_parser::write_geosite_mrs(&meow_rules::mrs_parser::GeositePayload {
                categories: vec![("testcat".to_string(), vec!["hit.example".to_string()])],
            })
            .unwrap();
        let (geosite_addr, geosite_hits, geosite_stop) = spawn_body_server(v2.clone().leak());
        let dir = tempfile::tempdir().unwrap();
        let asn_target = dir.path().join("asn.mmdb");
        let geosite_path = dir.path().join("geosite.mrs");
        // v1 on disk, so the referenced download is a replacement.
        let v1 = meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec![])],
        };
        std::fs::write(
            &geosite_path,
            meow_rules::mrs_parser::write_geosite_mrs(&v1).unwrap(),
        )
        .unwrap();

        let raw: RawConfig = serde_saphyr::from_str(
            "dns:\n  enable: true\n  nameserver:\n    - rcode://success\n\
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
        let geo = GeoDataConfig {
            asn_url: format!("http://{asn_addr}/asn.mmdb"),
            geosite_url: format!("http://{geosite_addr}/geosite.mrs"),
            geosite_path: Some(geosite_path.clone()),
            ..GeoDataConfig::default()
        };
        let dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));

        auto_update_tick(
            &geo,
            // ASN is NOT referenced — its reachable URL must not be dialed.
            meow_config::GeoDataNeeds {
                geosite: true,
                ..meow_config::GeoDataNeeds::default()
            },
            &tunnel,
            &RwLock::new(raw),
            Arc::new(RwLock::new(HashMap::new())),
            &dashmap::DashMap::new(),
            &dns_server,
            Some(dir.path()),
            &asn_target,
            &geosite_path,
        )
        .await;

        assert_eq!(
            asn_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an unreferenced DB's URL must not be dialed"
        );
        assert!(!asn_target.exists(), "no ASN file may be written");
        assert_eq!(
            geosite_hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the referenced DB is fetched once"
        );
        assert_eq!(
            std::fs::read(&geosite_path).unwrap(),
            v2,
            "the referenced DB is replaced with the served generation"
        );
        asn_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        geosite_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// A referenced geosite DB missing after startup is retried in the
    /// background: the first attempt (one minute in, on the paused clock)
    /// downloads it, and the loop then ends on its own.
    #[tokio::test(start_paused = true)]
    async fn missing_geosite_retry_loop_downloads_then_stops() {
        let body =
            meow_rules::mrs_parser::write_geosite_mrs(&meow_rules::mrs_parser::GeositePayload {
                categories: vec![("testcat".to_string(), vec!["hit.example".to_string()])],
            })
            .unwrap();
        let (addr, hits, stop) = spawn_body_server(body.clone().leak());
        let dir = tempfile::tempdir().unwrap();
        let geosite_path = dir.path().join("geosite.mrs");
        let raw: RawConfig = serde_saphyr::from_str("rules:\n  - MATCH,DIRECT\n").unwrap();
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec!["127.0.0.1:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let geo = GeoDataConfig {
            geosite_url: format!("http://{addr}/geosite.mrs"),
            geosite_path: Some(geosite_path.clone()),
            ..GeoDataConfig::default()
        };
        assert!(!meow_config::geosite_db_present(&geo));

        // Skip the first back-off on the paused clock, then let the
        // download's real socket I/O run on the real one.
        let retry = tokio::spawn(missing_geosite_retry_loop(
            geo,
            tunnel.clone(),
            Arc::new(RwLock::new(raw)),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(dashmap::DashMap::new()),
            Arc::new(RwLock::new(None)),
            Some(dir.path().to_path_buf()),
        ));
        // Let the loop reach its first sleep before moving the clock.
        tokio::task::yield_now().await;
        tokio::time::advance(GEOSITE_RETRY_FIRST).await;
        tokio::time::resume();
        tokio::time::timeout(std::time::Duration::from_secs(10), retry)
            .await
            .expect("the loop ends once the DB is on disk")
            .unwrap();

        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(&geosite_path).unwrap(), body);
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// An all-false `needs` snapshot (e.g. a GEOIP-only config — the tick
    /// never refreshes the MMDB) returns before any download attempt and
    /// before the rebuild/warn path.
    #[tokio::test]
    async fn auto_update_tick_all_false_needs_is_a_noop() {
        let (addr, hits, stop) = spawn_body_server(b"x");
        let dir = tempfile::tempdir().unwrap();
        let asn_target = dir.path().join("asn.mmdb");
        let geosite_target = dir.path().join("geosite.mrs");

        let raw: RawConfig = serde_saphyr::from_str("rules:\n  - GEOIP,CN,DIRECT\n").unwrap();
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
        let geo = GeoDataConfig {
            asn_url: format!("http://{addr}/asn.mmdb"),
            geosite_url: format!("http://{addr}/geosite.mrs"),
            ..GeoDataConfig::default()
        };
        let dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));

        auto_update_tick(
            &geo,
            meow_config::GeoDataNeeds::default(), // all false
            &tunnel,
            &RwLock::new(raw),
            Arc::new(RwLock::new(HashMap::new())),
            &dashmap::DashMap::new(),
            &dns_server,
            Some(dir.path()),
            &asn_target,
            &geosite_target,
        )
        .await;

        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "all-false needs must return before any download"
        );
        assert!(!asn_target.exists() && !geosite_target.exists());
        assert!(
            Arc::ptr_eq(&before, &tunnel.resolver()),
            "no rebuild → resolver generation unchanged"
        );
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
