//! `GEOSITE,<category>[,no-resolve]` rule — matches `Metadata.rule_host`
//! against a named category in the shared `GeositeDB`.
//!
//! upstream: `rules/geosite.go::Match`

use std::sync::Arc;

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

use crate::geosite::GeositeDB;

pub struct GeoSiteRule {
    /// Lower-cased category name, including any `@attribute` suffix.
    category: SmolStr,
    /// Raw payload preserved for diagnostics / API introspection.
    payload_raw: SmolStr,
    adapter: Adapter,
    /// Shared DB loaded once at startup. `None` when the DB file was not
    /// found at startup; matching always returns false.
    db: Option<Arc<GeositeDB>>,
    no_resolve: bool,
}

impl GeoSiteRule {
    /// Construct a rule. `payload` may contain an `@suffix` (e.g.
    /// `"microsoft@cn"`); the suffix is preserved and interpreted by
    /// [`GeositeDB::lookup`].
    pub fn new(payload: &str, adapter: &str, db: Option<Arc<GeositeDB>>, no_resolve: bool) -> Self {
        let category = payload.trim().to_ascii_lowercase().into();
        Self {
            category,
            payload_raw: payload.into(),
            adapter: intern_adapter(adapter),
            db,
            no_resolve,
        }
    }

    pub fn category(&self) -> &str {
        &self.category
    }

    pub fn db(&self) -> Option<&Arc<GeositeDB>> {
        self.db.as_ref()
    }
}

impl Rule for GeoSiteRule {
    fn rule_type(&self) -> RuleType {
        RuleType::GeoSite
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let Some(db) = self.db.as_ref() else {
            return false;
        };
        if self.category.is_empty() {
            return false;
        }
        let host = metadata.rule_host();
        if host.is_empty() {
            return false;
        }
        db.lookup(&self.category, host)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload_raw
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }

    fn never_matches(&self) -> bool {
        // The DB is loaded once at startup and never mutated afterwards, so
        // a missing DB, empty category name, or category absent from the DB
        // is a permanent no-match.
        self.category.is_empty()
            || self
                .db
                .as_ref()
                .is_none_or(|db| db.resolve_keys(&self.category).is_none())
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geosite::GeositeDB;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_host(host: &str) -> Metadata {
        Metadata {
            host: host.into(),
            ..Default::default()
        }
    }

    fn db_with(categories: &[(&str, &[&str])]) -> Arc<GeositeDB> {
        let mut db = GeositeDB::empty();
        for (cat, domains) in categories {
            for d in *domains {
                db.insert(cat, d);
            }
        }
        Arc::new(db)
    }

    /// A1 — known category + known domain matches.
    /// upstream: rules/geosite.go::Match
    #[test]
    fn matches_known_category_domain() {
        let db = db_with(&[("test", &["example.com"])]);
        let r = GeoSiteRule::new("test", "DIRECT", Some(db), false);
        assert!(r.match_metadata(&meta_host("example.com"), &helper()));
    }

    /// A2 — domain not in category → no match.
    #[test]
    fn no_match_domain_not_in_category() {
        let db = db_with(&[("test", &["example.com"])]);
        let r = GeoSiteRule::new("test", "DIRECT", Some(db), false);
        assert!(!r.match_metadata(&meta_host("other.com"), &helper()));
    }

    /// A3 — unknown category → no match (no error).
    #[test]
    fn no_match_unknown_category() {
        let db = db_with(&[("cn", &["baidu.com"])]);
        let r = GeoSiteRule::new("zz", "DIRECT", Some(db), false);
        assert!(!r.match_metadata(&meta_host("cn-domain.cn"), &helper()));
    }

    /// A4 — absent DB → always no-match.
    #[test]
    fn absent_db_always_no_match() {
        let r = GeoSiteRule::new("cn", "DIRECT", None, false);
        assert!(!r.match_metadata(&meta_host("example.com"), &helper()));
    }

    /// A5 — case-insensitive category match.
    /// upstream: rules/geosite.go::Match
    #[test]
    fn category_case_insensitive() {
        let db = db_with(&[("cn", &["baidu.com"])]);
        let r = GeoSiteRule::new("CN", "DIRECT", Some(db), false);
        assert!(r.match_metadata(&meta_host("baidu.com"), &helper()));
    }

    /// A6 — mixed case category.
    #[test]
    fn category_case_insensitive_mixed() {
        let db = db_with(&[("geolocation-!cn", &["google.com"])]);
        let r = GeoSiteRule::new("GeOlOcAtIoN-!CN", "REJECT", Some(db), false);
        assert!(r.match_metadata(&meta_host("google.com"), &helper()));
    }

    /// Empty host → no match.
    #[test]
    fn empty_host_no_match() {
        let db = db_with(&[("cn", &["baidu.com"])]);
        let r = GeoSiteRule::new("cn", "DIRECT", Some(db), false);
        assert!(!r.match_metadata(&meta_host(""), &helper()));
    }

    /// rule_type is GeoSite.
    #[test]
    fn rule_type_is_geosite() {
        let r = GeoSiteRule::new("cn", "DIRECT", None, false);
        assert_eq!(r.rule_type(), RuleType::GeoSite);
    }

    /// should_resolve_ip respects no-resolve flag.
    #[test]
    fn should_resolve_ip_flag() {
        let r_resolve = GeoSiteRule::new("cn", "DIRECT", None, false);
        assert!(r_resolve.should_resolve_ip());
        let r_no_resolve = GeoSiteRule::new("cn", "DIRECT", None, true);
        assert!(!r_no_resolve.should_resolve_ip());
    }

    /// @suffix is preserved for matching and payload output.
    #[test]
    fn at_suffix_preserved_for_matching() {
        let db = db_with(&[
            ("microsoft", &["global.example"]),
            ("microsoft@cn", &["cn.example"]),
        ]);
        let r = GeoSiteRule::new("microsoft@cn", "DIRECT", Some(db), false);
        assert_eq!(r.category(), "microsoft@cn");
        assert_eq!(r.payload(), "microsoft@cn");
        assert!(r.match_metadata(&meta_host("cn.example"), &helper()));
        assert!(!r.match_metadata(&meta_host("global.example"), &helper()));
    }

    /// Uses sniff_host when set, same as other domain rules.
    #[test]
    fn uses_sniff_host() {
        let db = db_with(&[("cn", &["baidu.com"])]);
        let r = GeoSiteRule::new("cn", "DIRECT", Some(db), false);
        let mut m = meta_host("fake.com");
        m.sniff_host = "baidu.com".into();
        assert!(r.match_metadata(&m, &helper()));
    }
}
