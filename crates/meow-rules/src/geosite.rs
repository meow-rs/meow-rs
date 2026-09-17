//! GEOSITE DB — category name → `DomainTrie<()>` of domains, loaded once
//! from a `geosite.mrs` file and shared via `Arc` across all `GeoSiteRule`
//! instances.
//!
//! upstream references:
//! - `rules/geosite.go` (rule application)
//! - `component/geodata/metaresource/metaresource.go::Read` (mrs geosite format)

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use meow_trie::DomainTrie;
use tracing::warn;

use crate::mrs_parser::{parse_header, stream_geosite_payload, GeositeItem, MrsError, TYPE_DOMAIN};

#[derive(Debug, thiserror::Error)]
pub enum GeositeError {
    #[error("geosite: unrecognised format (neither .mrs magic nor a parseable V2Ray .dat)")]
    WrongFormat,
    #[error("geosite: file I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("geosite: mrs parse error: {0}")]
    Mrs(#[from] MrsError),
    #[error("geosite: dat parse error: {0}")]
    Dat(#[from] crate::geosite_dat::DatError),
    #[error("geosite: mrs header type {0} is not 'domain' (expected 0)")]
    UnexpectedType(u8),
}

/// Parsed geosite database. Cheap to share via `Arc`.
pub struct GeositeDB {
    categories: HashMap<String, DomainTrie<()>>,
    counts: HashMap<String, usize>,
    /// Regex patterns are compiled at load time so matching never allocates.
    regex_compiled: HashMap<String, Vec<regex::Regex>>,
    keywords: HashMap<String, Vec<String>>,
}

impl std::fmt::Debug for GeositeDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeositeDB")
            .field("category_count", &self.categories.len())
            .finish()
    }
}

impl GeositeDB {
    /// Construct an empty DB. Mostly useful for tests.
    pub fn empty() -> Self {
        Self {
            categories: HashMap::new(),
            counts: HashMap::new(),
            regex_compiled: HashMap::new(),
            keywords: HashMap::new(),
        }
    }

    /// Insert `domain` into category `cat`. Category name is lower-cased.
    pub fn insert(&mut self, cat: &str, domain: &str) {
        let cat_key = cat.to_ascii_lowercase();
        let trie = self.categories.entry(cat_key.clone()).or_default();
        if trie.insert(&domain.to_ascii_lowercase(), ()) {
            *self.counts.entry(cat_key).or_insert(0) += 1;
        }
    }

    /// True iff `domain` is in the named category. Category match is
    /// case-insensitive. Unknown categories return `false` (no error).
    pub fn lookup(&self, category: &str, domain: &str) -> bool {
        let (base, attrs) = split_category_attrs(category);
        if !attrs.is_empty() {
            return attrs.iter().all(|attr| {
                let attr_category = format!("{base}@{attr}");
                self.lookup_one(&attr_category, domain)
            });
        }
        self.lookup_one(base, domain)
    }

    fn lookup_one(&self, category: &str, domain: &str) -> bool {
        let Some(cat) = self.category_key(category) else {
            return false;
        };

        if let Some(trie) = self.categories.get(cat) {
            if trie.search(domain).is_some() {
                return true;
            }
        }

        if let Some(kws) = self.keywords.get(cat) {
            if kws.iter().any(|kw| domain.contains(kw.as_str())) {
                return true;
            }
        }

        if let Some(compiled) = self.regex_compiled.get(cat) {
            if compiled.iter().any(|re| re.is_match(domain)) {
                return true;
            }
        }

        false
    }

    fn category_key<'a>(&'a self, category: &'a str) -> Option<&'a str> {
        if !category.bytes().any(|b| b.is_ascii_uppercase()) {
            return Some(category);
        }
        self.categories
            .keys()
            .chain(self.keywords.keys())
            .chain(self.regex_compiled.keys())
            .find(|key| key.as_bytes().eq_ignore_ascii_case(category.as_bytes()))
            .map(String::as_str)
    }

    fn bucket_exists(&self, key: &str) -> bool {
        self.categories.contains_key(key)
            || self.keywords.contains_key(key)
            || self.regex_compiled.contains_key(key)
    }

    /// Resolve a rule payload (a category, possibly with `@attr` suffixes)
    /// into canonical bucket keys — one per required attribute bucket, or a
    /// single key for a plain category.
    ///
    /// Returns `None` when any required bucket is absent from the DB: since
    /// the DB is immutable after startup, such a rule can never match and
    /// callers may prune it. The returned keys are pre-case-folded and
    /// pre-formatted so per-connection matching via
    /// [`Self::lookup_resolved`] does no splitting, case work, or
    /// allocation.
    pub fn resolve_keys(&self, category: &str) -> Option<Vec<String>> {
        let (base, attrs) = split_category_attrs(category);
        if base.is_empty() {
            return None;
        }
        let needed: Vec<String> = if attrs.is_empty() {
            vec![base.to_string()]
        } else {
            attrs.iter().map(|attr| format!("{base}@{attr}")).collect()
        };
        needed
            .into_iter()
            .map(|key| {
                let canon = self.category_key(&key)?;
                self.bucket_exists(canon).then(|| canon.to_string())
            })
            .collect()
    }

    /// Match `domain` against one pre-resolved bucket key from
    /// [`Self::resolve_keys`]. Skips the per-lookup attribute splitting and
    /// case-fold scan that [`Self::lookup`] pays.
    pub fn lookup_resolved(&self, key: &str, domain: &str) -> bool {
        if let Some(trie) = self.categories.get(key) {
            if trie.search(domain).is_some() {
                return true;
            }
        }
        if let Some(kws) = self.keywords.get(key) {
            if kws.iter().any(|kw| domain.contains(kw.as_str())) {
                return true;
            }
        }
        if let Some(compiled) = self.regex_compiled.get(key) {
            if compiled.iter().any(|re| re.is_match(domain)) {
                return true;
            }
        }
        false
    }

    /// Number of categories in the DB.
    pub fn category_count(&self) -> usize {
        self.categories.len()
    }

    /// Number of domains in the named category, or `None` if the category
    /// is absent. Intended for diagnostics / tests.
    pub fn domain_count(&self, category: &str) -> Option<usize> {
        self.counts.get(&category.to_ascii_lowercase()).copied()
    }

    pub fn from_parts(
        mut categories: HashMap<String, DomainTrie<()>>,
        counts: HashMap<String, usize>,
        regex_patterns: HashMap<String, Vec<String>>,
        keywords: HashMap<String, Vec<String>>,
    ) -> Self {
        for trie in categories.values_mut() {
            trie.seal();
        }
        let regex_compiled: HashMap<String, Vec<regex::Regex>> = regex_patterns
            .into_iter()
            .map(|(category, patterns)| {
                let compiled = patterns
                    .into_iter()
                    .filter_map(|p| regex::Regex::new(&p).ok())
                    .collect();
                (category, compiled)
            })
            .collect();
        Self {
            categories,
            counts,
            regex_compiled,
            keywords,
        }
    }

    /// Load a geosite DB from bytes. Auto-detects format:
    /// - `MRS!` magic → parsed as the upstream MetaCubeX `.mrs` binary.
    /// - anything else → parsed as a V2Ray `geosite.dat` protobuf.
    ///
    /// When `allowed` is `Some`, only the named categories are loaded;
    /// all others are skipped at the byte level. Pass `None` to load
    /// everything.
    ///
    /// Returns `WrongFormat` only when neither path produces a usable DB.
    /// **Does not log.** Callsites log with the file path.
    pub fn from_bytes(
        data: &[u8],
        allowed: Option<&HashSet<String>>,
    ) -> Result<Self, GeositeError> {
        match parse_header(data) {
            Ok((header, rest)) => {
                if header.type_tag != TYPE_DOMAIN {
                    return Err(GeositeError::UnexpectedType(header.type_tag));
                }
                // Stream straight from the zstd decoder into per-category
                // tries: neither the decompressed payload nor a per-domain
                // string list is ever held in memory.
                let decoder = zstd::stream::Decoder::new(std::io::Cursor::new(rest))
                    .map_err(MrsError::Zstd)?;
                let mut categories: HashMap<String, DomainTrie<()>> = HashMap::new();
                let mut counts: HashMap<String, usize> = HashMap::new();
                let mut current: Option<(String, DomainTrie<()>, usize)> = None;
                let finish = |current: &mut Option<(String, DomainTrie<()>, usize)>,
                              categories: &mut HashMap<String, DomainTrie<()>>,
                              counts: &mut HashMap<String, usize>| {
                    if let Some((name, mut trie, inserted)) = current.take() {
                        trie.seal();
                        counts.insert(name.clone(), inserted);
                        categories.insert(name, trie);
                    }
                };
                stream_geosite_payload(decoder, |item| match item {
                    GeositeItem::Category { name, .. } => {
                        finish(&mut current, &mut categories, &mut counts);
                        let load = allowed.is_none_or(|set| set.contains(name));
                        if load {
                            current = Some((name.to_string(), DomainTrie::new(), 0));
                        }
                        load
                    }
                    GeositeItem::Domain(domain) => {
                        if let Some((_, trie, inserted)) = current.as_mut() {
                            if trie.insert(domain, ()) {
                                *inserted += 1;
                            }
                        }
                        true
                    }
                })?;
                finish(&mut current, &mut categories, &mut counts);
                Ok(Self {
                    categories,
                    counts,
                    regex_compiled: HashMap::new(),
                    keywords: HashMap::new(),
                })
            }
            Err(MrsError::WrongFormat) => {
                // Try the V2Ray .dat protobuf format. On any dat-parse
                // error, surface `WrongFormat` so the callsite can log a
                // single actionable message without internal noise.
                crate::geosite_dat::from_dat_bytes(data, allowed)
                    .map_err(|_| GeositeError::WrongFormat)
            }
            Err(e) => Err(GeositeError::Mrs(e)),
        }
    }

    /// Load a geosite DB from a filesystem path.
    pub fn load_from_path(
        path: &Path,
        allowed: Option<&HashSet<String>>,
    ) -> Result<Self, GeositeError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes, allowed)
    }
}

fn split_category_attrs(category: &str) -> (&str, Vec<String>) {
    let mut parts = category.trim().split('@');
    let base = parts.next().unwrap_or("").trim();
    let attrs = parts
        .map(str::trim)
        .filter(|attr| !attr.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    (base, attrs)
}

/// Meow home directory for geosite discovery.
///
/// Delegates to the process-wide override set by `meow_common::set_home_dir`
/// (from `-d`), falling back to `$XDG_CONFIG_HOME/meow` or
/// `$HOME/.config/meow`.  This mirrors the logic in `meow_config::meow_config_dir`
/// without introducing a circular crate dependency.
fn geosite_config_dir() -> PathBuf {
    if let Some(d) = meow_common::meow_home_dir() {
        return d;
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("meow")
}

/// Candidate paths for the geosite DB, in priority order. Returned
/// regardless of whether the files exist; caller decides.
///
/// Both `.mrs` (MetaCubeX binary) and `.dat` (V2Ray protobuf) are accepted —
/// the loader auto-detects via magic bytes. `.mrs` is preferred when both
/// are present, since it parses ~10× faster and has no per-entry type
/// fidelity loss.
pub fn default_geosite_candidates() -> Vec<PathBuf> {
    let cfg = geosite_config_dir();
    vec![
        cfg.join("geosite.mrs"),
        cfg.join("geosite.dat"),
        PathBuf::from("./meow/geosite.mrs"),
        PathBuf::from("./meow/geosite.dat"),
    ]
}

/// Resolve the geosite DB from the default discovery chain. Returns `None`
/// and logs a warn-once if no candidate file exists. On file-present-but-
/// wrong-format, logs an `error!` with the path and conversion hint and
/// returns `None` (Class A per ADR-0002 — wrong format is actionable;
/// absent is not).
pub fn discover_and_load(allowed: Option<&HashSet<String>>) -> Option<Arc<GeositeDB>> {
    discover_and_load_from(&default_geosite_candidates(), allowed)
}

/// Load geosite DB from `explicit` path if given (skips discovery chain),
/// otherwise fall through to `candidates`. Used by the `geodata.geosite-path`
/// override. If `explicit` is set but the file is absent, returns `None` and
/// warns — same as any absent geosite DB; the auto-update task may download
/// it before the first GEOSITE rule fires.
pub fn discover_and_load_at(
    explicit: Option<&std::path::Path>,
    candidates: &[PathBuf],
    allowed: Option<&HashSet<String>>,
) -> Option<Arc<GeositeDB>> {
    if let Some(p) = explicit {
        // Explicit path given: use only that path (no fallback to discovery).
        return discover_and_load_from(&[p.to_path_buf()], allowed);
    }
    discover_and_load_from(candidates, allowed)
}

/// Same as [`discover_and_load`] but lets callers override the candidate
/// list. Used by tests and by an explicit config override in future
/// M2+ `geodata.path` support.
pub fn discover_and_load_from(
    candidates: &[PathBuf],
    allowed: Option<&HashSet<String>>,
) -> Option<Arc<GeositeDB>> {
    let Some(path) = candidates.iter().find(|p| p.exists()) else {
        warn!(
            "geosite DB not found in any of the discovery paths; GEOSITE rules will not match. \
             Place a geosite.mrs or geosite.dat file at one of: {}",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return None;
    };
    match GeositeDB::load_from_path(path, allowed) {
        Ok(db) => Some(Arc::new(db)),
        Err(GeositeError::WrongFormat) => {
            tracing::error!(
                path = %path.display(),
                "geosite file at {} is neither a valid .mrs nor a parseable V2Ray .dat",
                path.display()
            );
            None
        }
        Err(e) => {
            tracing::error!(path = %path.display(), "failed to load geosite DB: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mrs_parser::{write_geosite_mrs, GeositePayload};

    fn build_fixture() -> Vec<u8> {
        let payload = GeositePayload {
            categories: vec![
                (
                    "cn".to_string(),
                    vec![
                        "example.cn".to_string(),
                        "baidu.com".to_string(),
                        "qq.com".to_string(),
                    ],
                ),
                ("ads".to_string(), vec!["ad.example.com".to_string()]),
            ],
        };
        write_geosite_mrs(&payload).unwrap()
    }

    #[test]
    fn load_parses_categories() {
        let bytes = build_fixture();
        let db = GeositeDB::from_bytes(&bytes, None).unwrap();
        assert_eq!(db.category_count(), 2);
        assert_eq!(db.domain_count("cn"), Some(3));
        assert_eq!(db.domain_count("ads"), Some(1));
        assert_eq!(db.domain_count("zz"), None);
    }

    #[test]
    fn load_lookup_roundtrips() {
        let bytes = build_fixture();
        let db = GeositeDB::from_bytes(&bytes, None).unwrap();
        assert!(db.lookup("cn", "baidu.com"));
        assert!(db.lookup("CN", "BAIDU.COM")); // case-insensitive
        assert!(!db.lookup("cn", "google.com"));
    }

    #[test]
    fn load_unknown_category_no_match() {
        let bytes = build_fixture();
        let db = GeositeDB::from_bytes(&bytes, None).unwrap();
        assert!(!db.lookup("zz", "baidu.com"));
    }

    #[test]
    fn wrong_format_returns_error() {
        // protobuf-style header: `0x0A` is the proto wire tag for field 1 (length-delimited)
        let bytes = b"\x0a\x05hello";
        match GeositeDB::from_bytes(bytes, None) {
            Err(GeositeError::WrongFormat) => {}
            other => panic!("expected WrongFormat, got {:?}", other.err()),
        }
    }

    #[test]
    fn empty_db_valid() {
        let empty = GeositePayload { categories: vec![] };
        let bytes = write_geosite_mrs(&empty).unwrap();
        let db = GeositeDB::from_bytes(&bytes, None).unwrap();
        assert_eq!(db.category_count(), 0);
    }

    #[test]
    fn insert_and_lookup_case_insensitive() {
        let mut db = GeositeDB::empty();
        db.insert("CN", "Example.COM");
        assert!(db.lookup("cn", "example.com"));
        assert!(db.lookup("CN", "EXAMPLE.COM"));
    }

    #[test]
    fn lookup_attribute_category_requires_attribute_bucket() {
        let mut db = GeositeDB::empty();
        db.insert("microsoft", "global.example");
        db.insert("microsoft@cn", "cn.example");
        db.insert("microsoft@ms", "cn.example");
        assert!(db.lookup("microsoft", "global.example"));
        assert!(db.lookup("microsoft@cn", "cn.example"));
        assert!(db.lookup("microsoft@cn@ms", "cn.example"));
        assert!(!db.lookup("microsoft@cn", "global.example"));
    }

    #[test]
    fn discover_none_returns_none() {
        let candidates = vec![PathBuf::from("/definitely/not/a/real/path/geosite.mrs")];
        let result = discover_and_load_from(&candidates, None);
        assert!(result.is_none());
    }

    #[test]
    fn discover_finds_first_candidate() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("geosite.mrs");
        std::fs::write(&path, build_fixture()).unwrap();

        let candidates = vec![
            path,
            PathBuf::from("/definitely/not/a/real/path/geosite.mrs"),
        ];
        let db = discover_and_load_from(&candidates, None).expect("DB should load");
        assert!(db.lookup("cn", "baidu.com"));
    }

    #[test]
    fn discover_falls_through_to_second_candidate() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("geosite.mrs");
        std::fs::write(&path, build_fixture()).unwrap();

        let candidates = vec![
            PathBuf::from("/definitely/not/a/real/path/geosite.mrs"),
            path,
        ];
        let db = discover_and_load_from(&candidates, None).expect("DB should load");
        assert!(db.lookup("ads", "ad.example.com"));
    }

    #[test]
    fn discover_prefers_earlier_candidate() {
        // Two fixtures with different content; the earlier path wins.
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();
        let path1 = tmp1.path().join("geosite.mrs");
        let path2 = tmp2.path().join("geosite.mrs");

        let first = write_geosite_mrs(&GeositePayload {
            categories: vec![("first".to_string(), vec!["only-in-first.com".to_string()])],
        })
        .unwrap();
        let second = write_geosite_mrs(&GeositePayload {
            categories: vec![("second".to_string(), vec!["only-in-second.com".to_string()])],
        })
        .unwrap();

        std::fs::write(&path1, first).unwrap();
        std::fs::write(&path2, second).unwrap();

        let db = discover_and_load_from(&[path1, path2], None).unwrap();
        assert!(db.lookup("first", "only-in-first.com"));
        assert!(!db.lookup("second", "only-in-second.com"));
    }

    #[test]
    fn discover_wrong_format_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("geosite.mrs");
        std::fs::write(&path, b"\x0a\x05hello").unwrap();

        let candidates = vec![path];
        let result = discover_and_load_from(&candidates, None);
        assert!(result.is_none());
    }
}
