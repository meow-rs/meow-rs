//! Geodata DB download orchestration — startup-fetch (run unconditionally
//! when a target file is missing) and auto-update loop (periodic refresh
//! when `geodata.auto-update: true`).
//!
//! Both entry points are `pub` so downstream FFI callers that build a
//! `Tunnel` directly — bypassing `main.rs` — can wire the same behavior in
//! without reimplementing it.

use meow_common::adapter::Proxy;
use meow_config::geodata::download_and_replace;
use meow_config::raw::RawConfig;
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

/// Startup-fetch entry point: download any geodata DB whose target file does
/// not yet exist, then rebuild rules so the freshly-downloaded DBs take
/// effect without a restart. Independent of `geodata.auto-update` — the goal
/// is "if the file is missing when meow boots, fetch it so rules work on
/// first run." Safe to spawn as a background task.
pub async fn run_on_startup(
    geo: GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
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
        move || {
            meow_config::rebuild_from_raw_with_resolver(
                &raw,
                Some(resolver),
                Some(cache_dir.as_path()),
            )
        }
    })
    .await;
    match rebuild {
        Ok(Ok((_proxies, new_rules))) => {
            tunnel.update_rules(new_rules);
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
/// file is atomically replaced on disk, then rules are rebuilt in memory
/// without restart. Runs forever; spawn as a background task.
///
/// The GeoIP MMDB is intentionally NOT refreshed here — country-code → CIDR
/// mappings change infrequently and skipping the rebuild keeps the
/// parser-built `CountryIndex` alive without churn. Operators who need to
/// update GeoIP should replace `Country.mmdb` on disk and restart.
pub async fn auto_update_loop(
    geo: GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    cache_dir: PathBuf,
) {
    let interval = std::time::Duration::from_secs(geo.auto_update_interval as u64 * 3600);
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip the immediate first tick

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

        let mut any_updated = false;

        let route = tunnel.route_snapshot();
        let proxies = &route.proxies;
        let download_proxy = meow_config::internal_http::first_named_proxy(
            raw_config.read().proxies.as_deref(),
            proxies,
        );

        if let Err(e) =
            download_and_replace(&geo.asn_url, &asn_target, download_proxy.as_ref()).await
        {
            warn!("geodata auto-update: ASN MMDB download failed: {:#}", e);
        } else {
            any_updated = true;
        }

        if let Err(e) =
            download_and_replace(&geo.geosite_url, &geosite_target, download_proxy.as_ref()).await
        {
            warn!("geodata auto-update: geosite download failed: {:#}", e);
        } else {
            any_updated = true;
        }

        if !any_updated {
            warn!("geodata auto-update: all downloads failed; rules not reloaded");
            continue;
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
            let cache_dir = cache_dir.clone();
            move || {
                meow_config::rebuild_from_raw_with_resolver(
                    &raw,
                    Some(resolver),
                    Some(cache_dir.as_path()),
                )
            }
        })
        .await;
        match rebuild {
            Ok(Ok((_proxies, new_rules))) => {
                tunnel.update_rules(new_rules);
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
