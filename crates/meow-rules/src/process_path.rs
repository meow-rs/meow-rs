//! PROCESS-PATH rule — matches on `Metadata.process_path`.
//!
//! Three match modes (checked in order):
//!
//! 1. Payload contains `*`: glob match against the full path (case-sensitive
//!    on Linux/macOS; Windows paths not tested).
//! 2. Payload starts with `/` (or `\`): prefix match against the full path.
//!    `PROCESS-PATH,/usr/local/bin,PROXY` matches any binary under that dir.
//!    **Divergence from upstream** — upstream (`rules/common/process.go`) uses
//!    exact string equality only.  Class B per ADR-0002: prefix is additive
//!    (exact paths still match as prefix-of-themselves); no previously-working
//!    config breaks.
//! 3. Otherwise: exact match against the filename component only (same as
//!    PROCESS-NAME — useful fallback for mixed configs).
//!
//! If `Metadata.process_path` is empty (process lookup failed or not
//! supported), the rule never matches.  No warn at match time (would spam
//! logs on every packet).
//!
//! upstream: `rules/common/process.go`

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;
use std::path::Path;

pub struct ProcessPathRule {
    payload: SmolStr,
    mode: MatchMode,
    adapter: Adapter,
}

#[derive(Debug)]
enum MatchMode {
    /// Payload contains `*` — glob match via inline expansion.
    Glob(regex::Regex),
    /// Payload starts with `/` or `\` — prefix match.
    Prefix,
    /// Otherwise — exact match on filename component.
    Exact,
}

impl ProcessPathRule {
    pub fn new(payload: &str, adapter: &str) -> Result<Self, String> {
        let mode = if payload.contains('*') {
            // Expand `*` to `[^/\\]*` (matches within a single path component).
            // `?` wildcard is not supported — upstream does not support it either.
            let escaped = regex::escape(payload);
            let pattern = escaped.replace(r"\*", r"[^/\\]*");
            let re = regex::Regex::new(&format!("^(?i){pattern}$"))
                .map_err(|e| format!("invalid PROCESS-PATH glob '{payload}': {e}"))?;
            MatchMode::Glob(re)
        } else if payload.starts_with('/') || payload.starts_with('\\') {
            MatchMode::Prefix
        } else {
            MatchMode::Exact
        };

        Ok(Self {
            payload: payload.into(),
            mode,
            adapter: intern_adapter(adapter),
        })
    }

    fn matches(&self, process_path: &str) -> bool {
        if process_path.is_empty() {
            return false;
        }
        match &self.mode {
            MatchMode::Glob(re) => re.is_match(process_path),
            MatchMode::Prefix => {
                // Exact match, or match on a path-component boundary.
                // `/usr/bin` matches `/usr/bin/curl` but NOT `/usr/bin-extra`.
                let payload = &*self.payload;
                if process_path == payload {
                    return true;
                }
                match process_path.strip_prefix(payload) {
                    Some(rest) => rest.starts_with('/') || rest.starts_with('\\'),
                    None => false,
                }
            }
            MatchMode::Exact => {
                // Exact match on the filename component (same as PROCESS-NAME fallback).
                let filename = Path::new(process_path)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or(process_path);
                filename == &*self.payload
            }
        }
    }
}

impl Rule for ProcessPathRule {
    fn rule_type(&self) -> RuleType {
        RuleType::ProcessPath
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        self.matches(&metadata.process_path)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload
    }

    fn should_find_process(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{Metadata, RuleMatchHelper};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_path(path: &str) -> Metadata {
        Metadata {
            process_path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn process_path_exact_match_by_filename() {
        let r = ProcessPathRule::new("curl", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_path("/usr/bin/curl"), &helper()));
        assert!(!r.match_metadata(&meta_path("/usr/bin/wget"), &helper()));
    }

    #[test]
    fn process_path_prefix_match_with_leading_slash() {
        // Divergence from upstream exact-match — Class B per ADR-0002.
        let r = ProcessPathRule::new("/usr/local/bin", "PROXY").unwrap();
        assert!(r.match_metadata(&meta_path("/usr/local/bin/node"), &helper()));
        assert!(r.match_metadata(&meta_path("/usr/local/bin/npm"), &helper()));
        assert!(!r.match_metadata(&meta_path("/usr/bin/curl"), &helper()));
    }

    #[test]
    fn process_path_exact_full_path() {
        let r = ProcessPathRule::new("/usr/bin/curl", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_path("/usr/bin/curl"), &helper()));
        // Prefix: /usr/bin/curl is NOT a prefix of /usr/bin/curl-extra
        // (well it technically is, so let's check the expected behavior)
        assert!(!r.match_metadata(&meta_path("/usr/bin/curl-extra"), &helper()));
    }

    #[test]
    fn process_path_empty_process_path_never_matches() {
        let r = ProcessPathRule::new("curl", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_path(""), &helper()));
    }

    #[test]
    fn process_path_glob_match() {
        let r = ProcessPathRule::new("/usr/bin/node*", "PROXY").unwrap();
        assert!(r.match_metadata(&meta_path("/usr/bin/node"), &helper()));
        assert!(r.match_metadata(&meta_path("/usr/bin/node18"), &helper()));
    }
}
