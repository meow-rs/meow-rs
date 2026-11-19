use crate::internal_http;
use crate::raw::{RawConfig, RawGeoDataConfig};
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
    /// `geodata.proxy` verbatim — resolved against the built proxy map by
    /// `resolve_geodata_egress` at download time (`DIRECT`/`COMPATIBLE`/
    /// `PASS` mean "fetch direct", `REJECT`/`REJECT-DROP` "don't fetch").
    pub proxy: Option<String>,
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
            proxy: None,
        }
    }
}

/// Same ceiling as the rule-provider refresh supervisor
/// (`MAX_REFRESH_INTERVAL_SECS`, ~10 years): `Instant + Duration`
/// overflows — and `tokio::time::interval` panics — on absurd values.
const MAX_AUTO_UPDATE_INTERVAL_HOURS: u32 = 10 * 365 * 24;

/// Flat-vs-nested merge, defaults and the interval clamp — no validation
/// and no warnings, so diff-only callers (PUT's restart-needed check)
/// never re-emit. An explicit nested `geodata.*` value wins over the flat
/// `geo-*`/`geosite-*`/`geodata-*` alias, which wins over the default;
/// an empty block, an unrelated nested key, or an explicit `null`
/// (folded to `None`) does not shadow a flat value.
fn resolve_fields(raw: &RawConfig) -> GeoDataConfig {
    let r = raw.geodata.as_ref();
    let geox = raw.geox_url.as_ref();

    // `geodata.url.*` wins; `geox-url.*` fills in what it leaves unset;
    // the baked-in default is last. Each key merges independently.
    let pick = |explicit: Option<&String>, alias: Option<&String>, default: &str| {
        explicit
            .or(alias)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };

    let urls = r.and_then(|g| g.url.as_ref());
    GeoDataConfig {
        mmdb_path: r.and_then(|g| g.mmdb_path.as_deref()).map(PathBuf::from),
        asn_path: r.and_then(|g| g.asn_path.as_deref()).map(PathBuf::from),
        geosite_path: r.and_then(|g| g.geosite_path.as_deref()).map(PathBuf::from),
        auto_update: r
            .and_then(|g| g.auto_update)
            .or(raw.geo_auto_update)
            .unwrap_or(false),
        auto_update_interval: effective_interval(raw)
            .0
            .min(MAX_AUTO_UPDATE_INTERVAL_HOURS),
        mmdb_url: pick(
            urls.and_then(|u| u.mmdb.as_ref()),
            geox.and_then(|g| g.mmdb.as_ref()),
            DEFAULT_MMDB_URL,
        ),
        asn_url: pick(
            urls.and_then(|u| u.asn.as_ref()),
            geox.and_then(|g| g.asn.as_ref()),
            DEFAULT_ASN_URL,
        ),
        geosite_url: pick(
            urls.and_then(|u| u.geosite.as_ref()),
            geox.and_then(|g| g.geosite.as_ref()),
            DEFAULT_GEOSITE_URL,
        ),
        proxy: r.and_then(|g| g.proxy.clone()),
    }
}

/// The effective update interval and the spelling that supplied it —
/// `geodata.auto-update-interval` > `geo-update-interval` > `24`.
fn effective_interval(raw: &RawConfig) -> (u32, &'static str) {
    let r = raw.geodata.as_ref();
    match (
        r.and_then(|g| g.auto_update_interval),
        raw.geo_update_interval,
    ) {
        (Some(v), _) => (v, "geodata.auto-update-interval"),
        (None, Some(v)) => (v, "geo-update-interval"),
        (None, None) => (24, "geodata.auto-update-interval"),
    }
}

/// Effective `(auto_update, interval_hours)` under the same merge
/// [`parse_geodata`] applies — for `PUT /configs`' restart-needed diff,
/// which compares schedules rather than re-validating.
pub fn update_schedule(raw: &RawConfig) -> (bool, u32) {
    let g = resolve_fields(raw);
    (g.auto_update, g.auto_update_interval)
}

/// Parse and validate the `geodata:` block plus its flat top-level
/// aliases. Returns `GeoDataConfig::default()` values when none are set —
/// `geox-url` or a flat `geo-*` key alone (no `geodata:` block) is enough
/// to override the corresponding field.
///
/// Precedence is per field: explicit `geodata.*` > flat alias > default
/// (`geodata.url.*` > `geox-url.*` > baked-in for the URLs).
/// `geox-url.geoip` is accepted and ignored with a warning — mihomo
/// points it at `geoip.dat` and meow-rs has no geoip.dat consumer.
pub fn parse_geodata(raw: &RawConfig) -> Result<GeoDataConfig, anyhow::Error> {
    if raw
        .geox_url
        .as_ref()
        .and_then(|g| g.geoip.as_ref())
        .is_some()
    {
        warn!(
            "geox-url.geoip: meow-rs has no geoip.dat consumer — the key is \
             ignored. To override the GeoIP MMDB download URL use \
             `geox-url.mmdb` or `geodata.url.mmdb`"
        );
    }

    // The winning interval validates even when auto-update is off:
    // upstream refuses to schedule a non-positive value rather than
    // reading `0` as "use the default". A valid nested interval shadows
    // a semantically invalid flat `0`; a wrong YAML type never reaches
    // here (serde rejects it).
    let (interval, key) = effective_interval(raw);
    if interval == 0 {
        return Err(anyhow!("{key} must be at least 1 hour (got 0)"));
    }
    if interval > MAX_AUTO_UPDATE_INTERVAL_HOURS {
        warn!("{key} {interval}h exceeds the {MAX_AUTO_UPDATE_INTERVAL_HOURS}h ceiling; clamped");
    }

    Ok(resolve_fields(raw))
}

/// Emit the geo-selector compatibility warnings for one validation pass.
/// `geodata-mode`, `geodata-loader` and `geosite-matcher` — flat or
/// nested — are recognized mihomo inputs with no meow-rs switch behind
/// them: warn-and-ignore, never an error, even under `strict: true`.
/// The legacy nested `geoip-matcher` warns independently (it is not an
/// alias of `geosite-matcher`). Called once per rebuild from
/// `validation::validate_and_warn` so each warning names the effective
/// key's path without re-firing on internal reparses or dashboard polls.
pub(crate) fn warn_geo_compat(raw: &RawConfig) {
    let Some(r) = raw.geodata.as_ref() else {
        warn_geo_selectors(raw, None);
        return;
    };
    warn_geo_selectors(raw, Some(r));
    if r.geoip_matcher.as_ref().is_some_and(|v| !v.is_null()) {
        warn!(
            "geodata.geoip-matcher: field is not supported in meow-rs and will be \
             ignored (upstream: config.go); remove it to suppress this warning"
        );
    }
}

fn warn_geo_selectors(raw: &RawConfig, r: Option<&RawGeoDataConfig>) {
    // `geodata-mode: false` is compatible with the fixed MMDB backend;
    // `true` (either spelling) or a legacy non-boolean nested value asks
    // for a backend selection meow-rs does not have.
    let mode = r
        .and_then(|g| g.geodata_mode.as_ref())
        .filter(|v| !v.is_null())
        .map(|v| (v.clone(), "geodata.geodata-mode"))
        .or_else(|| {
            raw.geodata_mode
                .map(|b| (serde_json::Value::Bool(b), "geodata-mode"))
        });
    if let Some((v, path)) = mode {
        match v {
            serde_json::Value::Bool(false) => {}
            serde_json::Value::Bool(true) => warn!(
                "{path}: `true` selects mihomo's geoip.dat backend — meow-rs has no \
                 geoip.dat consumer and always uses the Country MMDB; the value is \
                 ignored"
            ),
            _ => warn!(
                "{path}: unsupported value — meow-rs has no geodata-mode switch and \
                 always uses the Country MMDB; the value is ignored"
            ),
        }
    }

    // Loader/matcher selection have no meow-rs switch at all — even an
    // upstream-default value warns because nothing honors the selector.
    let loader = r
        .and_then(|g| g.geodata_loader.as_ref())
        .filter(|v| !v.is_null())
        .map(|v| (v.to_string(), "geodata.geodata-loader"))
        .or_else(|| {
            raw.geodata_loader
                .as_ref()
                .map(|s| (format!("\"{s}\""), "geodata-loader"))
        });
    if let Some((v, path)) = loader {
        warn!(
            "{path}: value {v} selects a DAT loader — meow-rs always uses its own \
             loader and the key is ignored"
        );
    }
    let matcher = r
        .and_then(|g| g.geosite_matcher.as_ref())
        .filter(|v| !v.is_null())
        .map(|v| (v.to_string(), "geodata.geosite-matcher"))
        .or_else(|| {
            raw.geosite_matcher
                .as_ref()
                .map(|s| (format!("\"{s}\""), "geosite-matcher"))
        });
    if let Some((v, path)) = matcher {
        warn!(
            "{path}: value {v} selects a geosite matcher — meow-rs always uses its \
             own matchers and the key is ignored"
        );
    }
}

/// The outbound a geodata download takes, as `resolve_geodata_egress`
/// picks it from the config.
#[derive(Clone)]
pub enum GeodataEgress {
    /// Fetch directly.
    Direct,
    /// Fetch through `proxy` (needed where the CDN is blocked; issue #533).
    /// `direct_fallback`: a failed FIRST dial retries direct (see
    /// `internal_http::fetch_or_direct`). Set for an implied egress (the
    /// mode's default route or `proxies[0]`); never for an explicit
    /// `geodata.proxy` or a static `dialer-proxy` chain, which fail loudly
    /// like a provider `proxy:` (#625).
    Proxy {
        proxy: Arc<dyn Proxy>,
        direct_fallback: bool,
    },
    /// The config sends the download to `REJECT`/`REJECT-DROP` (named here):
    /// skip it rather than dial out.
    Rejected(&'static str),
}

impl std::fmt::Debug for GeodataEgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => f.write_str("Direct"),
            Self::Proxy {
                proxy,
                direct_fallback,
            } => f
                .debug_struct("Proxy")
                .field("proxy", &proxy.name())
                .field("direct_fallback", direct_fallback)
                .finish(),
            Self::Rejected(name) => f.debug_tuple("Rejected").field(name).finish(),
        }
    }
}

/// Download `url` and atomically replace `dest` via a `.tmp` sibling.
///
/// `egress` picks the outbound: through a proxy adapter (so GFW-blocked
/// CDNs stay reachable), directly, or — for a `REJECT` egress — not at all,
/// which is an error so callers log it like any failed download.
///
/// Returns `Ok(())` on success. On failure the temp file is removed (best-
/// effort) and the original `dest` is untouched.
pub async fn download_and_replace(
    url: &str,
    dest: &Path,
    egress: &GeodataEgress,
) -> Result<(), anyhow::Error> {
    if let GeodataEgress::Rejected(name) = egress {
        return Err(anyhow!(
            "not fetching {url}: the config routes geodata downloads to {name}"
        ));
    }
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

    let fetched = match egress {
        GeodataEgress::Proxy {
            proxy,
            direct_fallback,
        } => {
            info!(
                "auto-update: downloading {} from {} via proxy '{}'",
                dest.display(),
                url,
                proxy.name()
            );
            if *direct_fallback {
                // A failed proxy dial retries direct — see
                // `internal_http::fetch_or_direct` for the
                // connect-phase-only contract.
                internal_http::fetch_or_direct(url, Some(proxy), &[]).await
            } else {
                internal_http::fetch(url, Some(proxy), &[]).await
            }
        }
        _ => {
            info!("auto-update: downloading {} from {}", dest.display(), url);
            internal_http::fetch(url, None, &[]).await
        }
    };
    let bytes = fetched.map_err(|e| anyhow!("fetching {url}: {e}"))?;

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
    use crate::raw::{RawGeoDataConfig, RawGeoDataUrls, RawGeoXUrl};

    fn raw_defaults() -> RawGeoDataConfig {
        RawGeoDataConfig::default()
    }

    fn parse(raw: Option<&RawGeoDataConfig>) -> Result<GeoDataConfig, anyhow::Error> {
        parse_geodata(&RawConfig {
            geodata: raw.cloned(),
            ..Default::default()
        })
    }

    #[test]
    fn absent_block_returns_defaults() {
        let cfg = parse(None).unwrap();
        assert!(!cfg.auto_update);
        assert_eq!(cfg.auto_update_interval, 24);
        assert!(cfg.mmdb_path.is_none());
        assert!(cfg.asn_path.is_none());
        assert!(cfg.geosite_path.is_none());
        assert!(cfg.mmdb_url.contains("country.mmdb"));
        assert!(cfg.asn_url.contains("GeoLite2-ASN"));
        assert!(cfg.geosite_url.contains("geosite.dat"));
        assert!(cfg.proxy.is_none());
    }

    #[test]
    fn explicit_paths_override_discovery() {
        let raw = RawGeoDataConfig {
            mmdb_path: Some("/custom/Country.mmdb".to_string()),
            asn_path: Some("/custom/ASN.mmdb".to_string()),
            geosite_path: Some("/custom/geosite.mrs".to_string()),
            ..raw_defaults()
        };
        let cfg = parse(Some(&raw)).unwrap();
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
                extra: Default::default(),
            }),
            ..raw_defaults()
        };
        let cfg = parse(Some(&raw)).unwrap();
        assert_eq!(cfg.mmdb_url, "https://example.com/country.mmdb");
        assert!(cfg.asn_url.contains("GeoLite2-ASN")); // default preserved
        assert_eq!(cfg.geosite_url, "https://example.com/geosite.mrs");
    }

    #[test]
    fn proxy_passthrough() {
        let raw = RawGeoDataConfig {
            proxy: Some("HK 01".to_string()),
            ..raw_defaults()
        };
        let cfg = parse(Some(&raw)).unwrap();
        assert_eq!(cfg.proxy.as_deref(), Some("HK 01"));
    }

    #[test]
    fn interval_zero_is_hard_error() {
        let raw = RawGeoDataConfig {
            auto_update_interval: Some(0),
            ..raw_defaults()
        };
        let err = parse(Some(&raw)).unwrap_err();
        assert!(
            err.to_string().contains("at least 1 hour"),
            "error should mention minimum interval: {err}"
        );
    }

    #[test]
    fn absent_interval_defaults_to_24() {
        let raw = RawGeoDataConfig {
            auto_update: Some(true),
            auto_update_interval: None,
            ..raw_defaults()
        };
        let cfg = parse(Some(&raw)).unwrap();
        assert_eq!(cfg.auto_update_interval, 24);
    }

    #[test]
    fn upstream_only_fields_do_not_error() {
        // geodata-mode, geodata-loader, geoip-matcher accepted without error.
        let raw = RawGeoDataConfig {
            geodata_mode: Some(serde_json::Value::String("memconservative".to_string())),
            geodata_loader: Some(serde_json::Value::String("standard".to_string())),
            geoip_matcher: Some(serde_json::Value::String("succinct".to_string())),
            ..raw_defaults()
        };
        // Must not error — warn-only (Class B per ADR-0002).
        parse(Some(&raw)).unwrap();
    }

    // ── geox-url alias ────────────────────────────────────────────

    /// `geox-url` alone (no `geodata:` block) must still take effect —
    /// the early return for a missing `geodata:` section must not skip it.
    #[test]
    fn geox_url_alone_overrides_defaults() {
        let geox = RawGeoXUrl {
            mmdb: Some("https://cdn.test/Country.mmdb".to_string()),
            asn: Some("https://cdn.test/ASN.mmdb".to_string()),
            geosite: None,
            geoip: None,
            extra: Default::default(),
        };
        let cfg = parse_geodata(&RawConfig {
            geox_url: Some(geox),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.mmdb_url, "https://cdn.test/Country.mmdb");
        assert_eq!(cfg.asn_url, "https://cdn.test/ASN.mmdb");
        assert!(
            cfg.geosite_url.contains("geosite.dat"),
            "unset keys keep the baked-in default"
        );
    }

    /// `geodata.url.*` beats `geox-url.*` per key — keys the explicit
    /// block leaves unset still fall through to the alias.
    #[test]
    fn geodata_url_wins_over_geox_per_key() {
        let raw = RawGeoDataConfig {
            url: Some(RawGeoDataUrls {
                mmdb: Some("https://explicit.test/Country.mmdb".to_string()),
                asn: None,
                geosite: None,
                extra: Default::default(),
            }),
            ..raw_defaults()
        };
        let geox = RawGeoXUrl {
            mmdb: Some("https://alias.test/Country.mmdb".to_string()),
            asn: Some("https://alias.test/ASN.mmdb".to_string()),
            geosite: Some("https://alias.test/geosite.dat".to_string()),
            geoip: None,
            extra: Default::default(),
        };
        let cfg = parse_geodata(&RawConfig {
            geodata: Some(raw),
            geox_url: Some(geox),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            cfg.mmdb_url, "https://explicit.test/Country.mmdb",
            "geodata.url.mmdb beats geox-url.mmdb"
        );
        assert_eq!(
            cfg.asn_url, "https://alias.test/ASN.mmdb",
            "asn falls through to the alias"
        );
        assert_eq!(
            cfg.geosite_url, "https://alias.test/geosite.dat",
            "geosite falls through to the alias"
        );
    }

    /// `geox-url.geoip` must be ignored, not folded into `mmdb` — upstream
    /// points it at `geoip.dat`, which has no consumer here.
    #[test]
    fn geox_url_geoip_is_ignored() {
        let geox = RawGeoXUrl {
            geoip: Some("https://alias.test/geoip.dat".to_string()),
            ..RawGeoXUrl::default()
        };
        let cfg = parse_geodata(&RawConfig {
            geox_url: Some(geox),
            ..Default::default()
        })
        .unwrap();
        assert!(
            cfg.mmdb_url.contains("country.mmdb"),
            "geoip must not leak into the mmdb URL: {}",
            cfg.mmdb_url
        );
    }

    /// An empty `geox-url:` map changes nothing.
    #[test]
    fn empty_geox_url_is_a_noop() {
        let cfg = parse_geodata(&RawConfig {
            geox_url: Some(RawGeoXUrl::default()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.mmdb_url, DEFAULT_MMDB_URL);
        assert_eq!(cfg.asn_url, DEFAULT_ASN_URL);
        assert_eq!(cfg.geosite_url, DEFAULT_GEOSITE_URL);
    }

    // ── flat `geo-*` aliases (mihomo compat) ──────────────────────────

    fn parse_yaml(yaml: &str) -> Result<GeoDataConfig, anyhow::Error> {
        let raw: RawConfig = serde_saphyr::from_str(yaml).unwrap();
        parse_geodata(&raw)
    }

    /// Flat keys alone — no `geodata:` block — feed the resolved schedule.
    #[test]
    fn flat_keys_alone_set_the_schedule() {
        let cfg = parse_yaml("geo-auto-update: true\ngeo-update-interval: 6\n").unwrap();
        assert!(cfg.auto_update);
        assert_eq!(cfg.auto_update_interval, 6);
    }

    /// Explicit nested values win over the flat aliases, per field.
    #[test]
    fn nested_beats_flat_per_field() {
        let cfg = parse_yaml(
            "geo-auto-update: true\ngeo-update-interval: 1\n\
             geodata:\n  auto-update: false\n  auto-update-interval: 6\n",
        )
        .unwrap();
        assert!(
            !cfg.auto_update,
            "nested explicit false must shadow flat true"
        );
        assert_eq!(cfg.auto_update_interval, 6);
    }

    /// Field-by-field: a nested key only shadows the flat key it sets.
    #[test]
    fn merge_is_field_by_field() {
        let cfg = parse_yaml(
            "geo-auto-update: true\ngeo-update-interval: 6\n\
             geodata:\n  auto-update: false\n",
        )
        .unwrap();
        assert!(!cfg.auto_update);
        assert_eq!(
            cfg.auto_update_interval, 6,
            "nested block without an interval must not shadow the flat one"
        );
    }

    /// An empty `geodata:` block, unrelated nested keys, explicit `null`,
    /// and reversed document order all leave the flat values effective.
    #[test]
    fn empty_null_and_unrelated_nested_do_not_shadow() {
        for geodata_block in [
            "geodata: {}\n",
            "geodata:\n  mmdb-path: /x/y.mmdb\n",
            "geodata:\n  auto-update: ~\n",
        ] {
            let cfg = parse_yaml(&format!(
                "geo-auto-update: true\ngeo-update-interval: 6\n{geodata_block}"
            ))
            .unwrap();
            assert!(
                cfg.auto_update,
                "{geodata_block}must not shadow the flat alias"
            );
            assert_eq!(cfg.auto_update_interval, 6);
        }
        // YAML order is not precedence: flat first still loses to nested.
        let cfg = parse_yaml(
            "geo-auto-update: true\n\
             geodata:\n  auto-update: false\n  auto-update-interval: 3\n\
             geo-update-interval: 6\n",
        )
        .unwrap();
        assert!(!cfg.auto_update);
        assert_eq!(cfg.auto_update_interval, 3);
    }

    /// Interval bounds: `1` accepted, `0` rejected under either spelling —
    /// including when auto-update is off — and a valid nested interval
    /// shadows a semantically invalid flat `0`.
    #[test]
    fn interval_bounds() {
        assert_eq!(
            parse_yaml("geo-update-interval: 1\n")
                .unwrap()
                .auto_update_interval,
            1
        );
        for yaml in [
            "geo-update-interval: 0\n",
            "geodata:\n  auto-update-interval: 0\n",
            "geo-auto-update: false\ngeo-update-interval: 0\n",
        ] {
            let err = parse_yaml(yaml).unwrap_err();
            assert!(
                err.to_string().contains("at least 1 hour"),
                "{yaml} — unexpected error: {err}"
            );
        }
        // Nested shadows flat — a valid `6` masks the invalid `0`.
        let cfg =
            parse_yaml("geo-update-interval: 0\ngeodata:\n  auto-update-interval: 6\n").unwrap();
        assert_eq!(cfg.auto_update_interval, 6);
    }

    /// Out-of-type interval values fail at the YAML boundary; the ceiling
    /// clamps rather than errors.
    #[test]
    fn interval_type_and_ceiling() {
        for yaml in [
            "geo-update-interval: -1\n",
            "geo-update-interval: 1.5\n",
            "geo-update-interval: abc\n",
        ] {
            assert!(
                serde_saphyr::from_str::<RawConfig>(yaml).is_err(),
                "{yaml} must fail deserialization"
            );
        }
        let cfg = parse_yaml("geo-update-interval: 90000\n").unwrap();
        assert_eq!(cfg.auto_update_interval, 10 * 365 * 24);
        let cfg = parse_yaml("geodata:\n  auto-update-interval: 87600\n").unwrap();
        assert_eq!(cfg.auto_update_interval, 87600);
    }

    // ── download_and_replace (geodata-only direct fallback) ────────────

    use crate::test_support::{serve_body, Dial, ScriptedProxy};

    /// Integration pin for the geodata-only opt-in: an implied download
    /// proxy whose connect phase fails must NOT sink the download — the
    /// fetch retries direct (`internal_http::fetch_or_direct`) and the
    /// file lands on disk.
    #[tokio::test]
    async fn download_and_replace_falls_back_to_direct_after_dial_failure() {
        let (addr, hits) = serve_body(b"abc").await;
        let egress = GeodataEgress::Proxy {
            proxy: ScriptedProxy::arc("failing", Dial::Fail),
            direct_fallback: true,
        };
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("Country.mmdb");
        download_and_replace(&format!("http://{addr}/Country.mmdb"), &dest, &egress)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A routed egress (no fallback) whose dial fails is a loud error,
    /// never a direct fetch.
    #[tokio::test]
    async fn download_and_replace_explicit_proxy_does_not_fall_back() {
        let (addr, hits) = serve_body(b"abc").await;
        let egress = GeodataEgress::Proxy {
            proxy: ScriptedProxy::arc("failing", Dial::Fail),
            direct_fallback: false,
        };
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("Country.mmdb");
        let err = download_and_replace(&format!("http://{addr}/Country.mmdb"), &dest, &egress)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("dial via proxy"), "{err:#}");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!dest.exists());
    }

    /// A `REJECT` egress downloads nothing and dials nothing.
    #[tokio::test]
    async fn download_and_replace_rejected_does_not_dial() {
        let (addr, hits) = serve_body(b"abc").await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("Country.mmdb");
        let err = download_and_replace(
            &format!("http://{addr}/Country.mmdb"),
            &dest,
            &GeodataEgress::Rejected("REJECT"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("REJECT"), "{err}");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!dest.exists());
    }

    /// A working direct fetch still lands without any proxy configured.
    #[tokio::test]
    async fn download_and_replace_direct_writes_file() {
        let (addr, _) = serve_body(b"xy").await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("geosite.dat");
        download_and_replace(
            &format!("http://{addr}/geosite.dat"),
            &dest,
            &GeodataEgress::Direct,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"xy");
    }
}
