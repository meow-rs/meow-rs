use crate::internal_http;
use crate::raw::RawGeoDataConfig;
use anyhow::anyhow;
use meow_common::adapter::Proxy;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};

const DEFAULT_MMDB_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb";
const DEFAULT_ASN_URL: &str =
    "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb";
const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat";

/// Validated `geodata:` config, produced by [`parse_geodata`].
#[derive(Debug, Clone)]
pub struct GeoDataConfig {
    pub mmdb_path: Option<PathBuf>,
    pub asn_path: Option<PathBuf>,
    pub geosite_path: Option<PathBuf>,
    pub auto_update: bool,
    /// Hours between update checks (≥1).
    pub auto_update_interval: u32,
    pub mmdb_url: String,
    pub asn_url: String,
    pub geosite_url: String,
}

impl Default for GeoDataConfig {
    fn default() -> Self {
        Self {
            mmdb_path: None,
            asn_path: None,
            geosite_path: None,
            auto_update: false,
            auto_update_interval: 24,
            mmdb_url: DEFAULT_MMDB_URL.to_string(),
            asn_url: DEFAULT_ASN_URL.to_string(),
            geosite_url: DEFAULT_GEOSITE_URL.to_string(),
        }
    }
}

/// Parse and validate the raw `geodata:` block. Returns `GeoDataConfig::default()`
/// when the block is absent.
pub fn parse_geodata(raw: Option<&RawGeoDataConfig>) -> Result<GeoDataConfig, anyhow::Error> {
    let Some(r) = raw else {
        return Ok(GeoDataConfig::default());
    };

    // Warn on upstream-only fields (Class B per ADR-0002 §geodata-subsection.md).
    for (name, val) in [
        ("geodata-mode", &r.geodata_mode),
        ("geodata-loader", &r.geodata_loader),
        ("geoip-matcher", &r.geoip_matcher),
    ] {
        if val.is_some() {
            warn!(
                "geodata.{}: field is not supported in meow-rs and will be ignored \
                (upstream: config.go); remove it to suppress this warning",
                name
            );
        }
    }

    let interval = r.auto_update_interval.unwrap_or(24);
    if interval == 0 {
        return Err(anyhow!(
            "geodata.auto-update-interval must be at least 1 hour (got 0)"
        ));
    }
    // Same ceiling as the rule-provider refresh supervisor
    // (`MAX_REFRESH_INTERVAL_SECS`, ~10 years): `Instant + Duration`
    // overflows — and `tokio::time::interval` panics — on absurd values.
    const MAX_AUTO_UPDATE_INTERVAL_HOURS: u32 = 10 * 365 * 24;
    let interval = interval.min(MAX_AUTO_UPDATE_INTERVAL_HOURS);
    if interval != r.auto_update_interval.unwrap_or(24) {
        warn!(
            "geodata.auto-update-interval {}h exceeds the {}h ceiling; clamped",
            r.auto_update_interval.unwrap_or(24),
            MAX_AUTO_UPDATE_INTERVAL_HOURS
        );
    }

    let urls = r.url.as_ref();
    Ok(GeoDataConfig {
        mmdb_path: r.mmdb_path.as_deref().map(PathBuf::from),
        asn_path: r.asn_path.as_deref().map(PathBuf::from),
        geosite_path: r.geosite_path.as_deref().map(PathBuf::from),
        auto_update: r.auto_update,
        auto_update_interval: interval,
        mmdb_url: urls
            .and_then(|u| u.mmdb.clone())
            .unwrap_or_else(|| DEFAULT_MMDB_URL.to_string()),
        asn_url: urls
            .and_then(|u| u.asn.clone())
            .unwrap_or_else(|| DEFAULT_ASN_URL.to_string()),
        geosite_url: urls
            .and_then(|u| u.geosite.clone())
            .unwrap_or_else(|| DEFAULT_GEOSITE_URL.to_string()),
    })
}

/// Download `url` and atomically replace `dest` via a `.tmp` sibling.
///
/// When `proxy` is `Some`, the HTTP fetch is tunneled through that proxy
/// adapter (used so GFW-blocked CDNs stay reachable on background refresh);
/// otherwise the OS handles connectivity directly.
///
/// Returns `Ok(())` on success. On failure the temp file is removed (best-
/// effort) and the original `dest` is untouched.
pub async fn download_and_replace(
    url: &str,
    dest: &Path,
    proxy: Option<&Arc<dyn Proxy>>,
) -> Result<(), anyhow::Error> {
    // Unique scratch, not `with_extension("tmp")` — same-stem targets
    // (`Country.mmdb`/`Country.yaml` → `Country.tmp`) and concurrent
    // downloaders (auto-update vs rebuild-time `ensure_geodata`) must not
    // share it (issue #543 review). Sweep scratch a crashed downloader
    // orphaned (issue #621) — on the blocking pool, off the async worker.
    {
        let sweep_target = dest.to_path_buf();
        let _ = crate::spawn_blocking_with_current_dispatcher(move || {
            meow_common::fs_util::sweep_scratch_siblings(
                &sweep_target,
                meow_common::fs_util::SCRATCH_STALE_AGE,
            );
            // The pre-#543 scratch was `with_extension("tmp")`
            // (`Country.mmdb` → `Country.tmp`) — it does not match the
            // `{base}.{pid}.{n}.tmp` sweep shape; remove it only when old
            // (a young file could be a user's own).
            let legacy = sweep_target.with_extension("tmp");
            if legacy != sweep_target {
                let old = std::fs::metadata(&legacy)
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| {
                        SystemTime::now().duration_since(t).unwrap_or_default()
                            > meow_common::fs_util::SCRATCH_STALE_AGE
                    });
                if old {
                    let _ = std::fs::remove_file(&legacy);
                }
            }
        })
        .await;
    }
    let tmp = crate::unique_scratch_path(dest);

    if let Some(p) = proxy {
        info!(
            "auto-update: downloading {} from {} via proxy '{}'",
            dest.display(),
            url,
            p.name()
        );
    } else {
        info!("auto-update: downloading {} from {}", dest.display(), url);
    }

    let bytes = internal_http::fetch(url, proxy, &[])
        .await
        .map_err(|e| anyhow!("fetching {url}: {e}"))?;

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&tmp, &bytes).await?;

    if let Err(e) = tokio::fs::rename(&tmp, dest).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(anyhow!(
            "atomic rename {} → {}: {}",
            tmp.display(),
            dest.display(),
            e
        ));
    }

    info!(
        "auto-update: {} updated ({} bytes)",
        dest.display(),
        bytes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{RawGeoDataConfig, RawGeoDataUrls};

    fn raw_defaults() -> RawGeoDataConfig {
        RawGeoDataConfig::default()
    }

    #[test]
    fn absent_block_returns_defaults() {
        let cfg = parse_geodata(None).unwrap();
        assert!(!cfg.auto_update);
        assert_eq!(cfg.auto_update_interval, 24);
        assert!(cfg.mmdb_path.is_none());
        assert!(cfg.asn_path.is_none());
        assert!(cfg.geosite_path.is_none());
        assert!(cfg.mmdb_url.contains("country.mmdb"));
        assert!(cfg.asn_url.contains("GeoLite2-ASN"));
        assert!(cfg.geosite_url.contains("geosite.dat"));
    }

    #[test]
    fn explicit_paths_override_discovery() {
        let raw = RawGeoDataConfig {
            mmdb_path: Some("/custom/Country.mmdb".to_string()),
            asn_path: Some("/custom/ASN.mmdb".to_string()),
            geosite_path: Some("/custom/geosite.mrs".to_string()),
            ..raw_defaults()
        };
        let cfg = parse_geodata(Some(&raw)).unwrap();
        assert_eq!(
            cfg.mmdb_path.unwrap().to_str().unwrap(),
            "/custom/Country.mmdb"
        );
        assert_eq!(cfg.asn_path.unwrap().to_str().unwrap(), "/custom/ASN.mmdb");
        assert_eq!(
            cfg.geosite_path.unwrap().to_str().unwrap(),
            "/custom/geosite.mrs"
        );
    }

    #[test]
    fn url_overrides_replace_defaults() {
        let raw = RawGeoDataConfig {
            url: Some(RawGeoDataUrls {
                mmdb: Some("https://example.com/country.mmdb".to_string()),
                asn: None,
                geosite: Some("https://example.com/geosite.mrs".to_string()),
            }),
            ..raw_defaults()
        };
        let cfg = parse_geodata(Some(&raw)).unwrap();
        assert_eq!(cfg.mmdb_url, "https://example.com/country.mmdb");
        assert!(cfg.asn_url.contains("GeoLite2-ASN")); // default preserved
        assert_eq!(cfg.geosite_url, "https://example.com/geosite.mrs");
    }

    #[test]
    fn interval_zero_is_hard_error() {
        let raw = RawGeoDataConfig {
            auto_update_interval: Some(0),
            ..raw_defaults()
        };
        let err = parse_geodata(Some(&raw)).unwrap_err();
        assert!(
            err.to_string().contains("at least 1 hour"),
            "error should mention minimum interval: {err}"
        );
    }

    #[test]
    fn absent_interval_defaults_to_24() {
        let raw = RawGeoDataConfig {
            auto_update: true,
            auto_update_interval: None,
            ..raw_defaults()
        };
        let cfg = parse_geodata(Some(&raw)).unwrap();
        assert_eq!(cfg.auto_update_interval, 24);
    }

    #[test]
    fn upstream_only_fields_do_not_error() {
        // geodata-mode, geodata-loader, geoip-matcher accepted without error.
        let raw = RawGeoDataConfig {
            geodata_mode: Some(serde_yaml::Value::String("memconservative".to_string())),
            geodata_loader: Some(serde_yaml::Value::String("standard".to_string())),
            geoip_matcher: Some(serde_yaml::Value::String("succinct".to_string())),
            ..raw_defaults()
        };
        // Must not error — warn-only (Class B per ADR-0002).
        parse_geodata(Some(&raw)).unwrap();
    }
}
