//! `PROCESS-NAME-REGEX` / `PROCESS-PATH-REGEX` /
//! `PROCESS-NAME-WILDCARD` / `PROCESS-PATH-WILDCARD` — the four process
//! pattern rules added for mihomo parity (issue #974).
//!
//! One shared entity: a name/path axis picking `Metadata::process` or
//! `Metadata::process_path`, plus a regex or byte-glob matcher built
//! once at construction. Deliberately separate from the legacy
//! `ProcessName` (exact-name) and `ProcessPath` (prefix/filename hybrid)
//! rules, whose semantics stay untouched.
//!
//! upstream: `rules/common/process.go` — regexp2 `IgnoreCase` compile for
//! the regex kinds, `wildcard.Match` (strings.ToLower of both sides) for
//! the glob kinds. Ours runs on the `regex` crate and an iterative
//! byte-wise glob; neither matcher touches the filesystem, rewrites path
//! separators, or asks the process callback again.

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use regex::RegexBuilder;
use smol_str::SmolStr;

use crate::adapter::{intern_adapter, Adapter};

/// Which process field the rule reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAxis {
    /// `Metadata::process` — the process name as the lookup reported it
    /// (usually a basename); never derived from `process_path`.
    Name,
    /// `Metadata::process_path` — the full reported path, verbatim.
    Path,
}

enum Matcher {
    Regex(regex::Regex),
    /// Case-folded pattern bytes matched whole-string, byte-wise.
    Glob(Vec<u8>),
}

pub struct ProcessPatternRule {
    rule_type: RuleType,
    axis: ProcessAxis,
    matcher: Matcher,
    /// The written pattern, for `/rules` and diagnostics.
    payload: SmolStr,
    adapter: Adapter,
}

impl ProcessPatternRule {
    /// Build a regex process rule: `rule_type` selects the axis via
    /// `RuleType::ProcessNameRegex` / `RuleType::ProcessPathRegex`.
    /// The regex compiles case-insensitive by default; an inline
    /// `(?i)`/`(?-i)` flag in the pattern overrides it.
    pub fn new_regex(rule_type: RuleType, pattern: &str, adapter: &str) -> Result<Self, String> {
        let axis = match rule_type {
            RuleType::ProcessNameRegex => ProcessAxis::Name,
            RuleType::ProcessPathRegex => ProcessAxis::Path,
            _ => unreachable!("new_regex called for {rule_type}"),
        };
        if pattern.is_empty() {
            return Err(format!("{rule_type}: empty payload"));
        }
        let regex = RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .map_err(|e| {
                let hint = regexp2_hint(pattern).map_or_else(String::new, |h| format!(" ({h})"));
                format!("invalid regex '{pattern}': {e}{hint}")
            })?;
        Ok(Self {
            rule_type,
            axis,
            matcher: Matcher::Regex(regex),
            payload: pattern.into(),
            adapter: intern_adapter(adapter),
        })
    }

    /// Build a glob process rule: `*`/`?` are the only metacharacters —
    /// `[`, `\`, `/`, `.` and everything else are literal bytes.
    pub fn new_glob(rule_type: RuleType, glob: &str, adapter: &str) -> Result<Self, String> {
        let axis = match rule_type {
            RuleType::ProcessNameWildcard => ProcessAxis::Name,
            RuleType::ProcessPathWildcard => ProcessAxis::Path,
            _ => unreachable!("new_glob called for {rule_type}"),
        };
        if glob.is_empty() {
            return Err(format!("{rule_type}: empty payload"));
        }
        Ok(Self {
            rule_type,
            axis,
            matcher: Matcher::Glob(lower_simple(glob).into_owned().into_bytes()),
            payload: glob.into(),
            adapter: intern_adapter(adapter),
        })
    }
}

/// Constructs upstream's regexp2 accepts but the `regex` crate rejects —
/// flagged in the error so a `-t`-accepted config explains its failure
/// as "needs a backtracking engine", not as a typo (issue #974 spec).
fn regexp2_hint(pattern: &str) -> Option<&'static str> {
    if pattern.contains("(?=") || pattern.contains("(?!") || pattern.contains("(?<") {
        return Some("look-around requires a backtracking engine like upstream's regexp2");
    }
    // A `\N` backreference (single digit) — `\x`/`\u` escapes never reach
    // this diagnostic because they compile fine.
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.next().is_some_and(|d| d.is_ascii_digit()) {
            return Some("backreferences require a backtracking engine like upstream's regexp2");
        }
    }
    None
}

/// Go `strings.ToLower`-style fold for glob comparison: a per-char
/// simple-case mapping, then UTF-8 bytes. Rust's `char::to_lowercase`
/// yields the *full* mapping; taking its first char gives Go's simple
/// mapping for the called-out cases (`İ` → `i`, `É` → `é`, Cyrillic,
/// CJK passthrough). The divergence — full mappings whose first char is
/// not the simple map (Greek capitals with iota subscripts) — is
/// unreachable in practice for process names.
fn lower_simple(text: &str) -> std::borrow::Cow<'_, str> {
    if text.chars().any(|c| c.to_lowercase().next() != Some(c)) {
        text.chars()
            .flat_map(|c| c.to_lowercase().take(1))
            .collect::<String>()
            .into()
    } else {
        text.into()
    }
}

/// Iterative two-pointer glob match — `?` consumes exactly one byte,
/// `*` zero or more, with no path-separator special-casing. Linear
/// backtracking on the last `*` only; never exponential.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (usize::MAX, 0usize);
    while t < text.len() {
        // `*` must be recognised before the literal-equality branch: a
        // literal star in the text (`*worker` vs `*myworker`) is
        // consumable by the wildcard, never swallowed as `* == *`
        // without recording the backtracking point.
        if p < pattern.len() && pattern[p] == b'*' {
            star_p = p;
            star_t = t;
            p += 1;
        } else if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if star_p != usize::MAX {
            p = star_p + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

impl Rule for ProcessPatternRule {
    fn rule_type(&self) -> RuleType {
        self.rule_type
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let text = match self.axis {
            ProcessAxis::Name => metadata.process.as_str(),
            ProcessAxis::Path => metadata.process_path.as_str(),
        };
        // Empty name/path never matches — not even `*` or `^$`: this
        // batch's spec fixes the field-present contract upstream's
        // regexp2 path lacks (process.go:44 reads an unguarded field).
        if text.is_empty() {
            return false;
        }
        match &self.matcher {
            Matcher::Regex(regex) => regex.is_match(text),
            Matcher::Glob(pattern) => glob_match(pattern, lower_simple(text).as_bytes()),
        }
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload
    }

    fn should_find_process(&self) -> bool {
        meow_common::process_lookup::PROCESS_LOOKUP_SUPPORTED
    }

    fn never_matches(&self) -> bool {
        // Dead only where no source — a native lookup or an inbound that
        // fills the fields — can ever populate them. The find-process
        // mode, a flow's missing fields and one failed lookup are runtime
        // states, not build-time provable deadness (issue #974 spec).
        !meow_common::process_lookup::process_info_available()
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::RuleMatchHelper;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn named(process: &str) -> Metadata {
        Metadata {
            process: process.into(),
            ..Default::default()
        }
    }

    fn pathed(path: &str) -> Metadata {
        Metadata {
            process_path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn regex_searches_unanchored_case_insensitive() {
        let r = ProcessPatternRule::new_regex(RuleType::ProcessNameRegex, "curl", "T").unwrap();
        assert!(r.match_metadata(&named("myCURL"), &helper()));
        assert!(r.match_metadata(&named("curl.exe"), &helper()));

        let anchored =
            ProcessPatternRule::new_regex(RuleType::ProcessNameRegex, "^curl$", "T").unwrap();
        assert!(!anchored.match_metadata(&named("myCURL"), &helper()));
        assert!(anchored.match_metadata(&named("CURL"), &helper()));
    }

    #[test]
    fn regex_inline_flag_overrides_default_case() {
        let r =
            ProcessPatternRule::new_regex(RuleType::ProcessNameRegex, "(?-i)^curl$", "T").unwrap();
        assert!(r.match_metadata(&named("curl"), &helper()));
        assert!(!r.match_metadata(&named("CURL"), &helper()));
    }

    #[test]
    fn regex_empty_field_never_matches_even_match_all() {
        let r = ProcessPatternRule::new_regex(RuleType::ProcessNameRegex, ".*", "T").unwrap();
        assert!(!r.match_metadata(&Metadata::default(), &helper()));
        let anchored =
            ProcessPatternRule::new_regex(RuleType::ProcessNameRegex, "^$", "T").unwrap();
        assert!(!anchored.match_metadata(&Metadata::default(), &helper()));
    }

    #[test]
    fn regex_name_axis_ignores_path_basename() {
        // Only `process_path` supplied: a name rule must not re-derive a
        // basename from the path (issue #974 spec).
        let r = ProcessPatternRule::new_regex(RuleType::ProcessNameRegex, "curl", "T").unwrap();
        assert!(!r.match_metadata(&pathed("/usr/bin/curl"), &helper()));
        let p =
            ProcessPatternRule::new_regex(RuleType::ProcessPathRegex, r"^/usr/bin/cu[rR]l$", "T")
                .unwrap();
        assert!(p.match_metadata(&pathed("/usr/bin/curl"), &helper()));
        assert!(!p.match_metadata(&pathed("curl"), &helper()));
    }

    #[test]
    fn glob_whole_string_star_and_question() {
        let r = ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "Cu?l*", "T").unwrap();
        assert!(r.match_metadata(&named("curl"), &helper()));
        assert!(r.match_metadata(&named("CURL.EXE"), &helper()));
        assert!(!r.match_metadata(&named("mycurl"), &helper()));
        // `*` consumes zero bytes: `cu*l` matches `cul`.
        let z = ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "cu*l", "T").unwrap();
        assert!(z.match_metadata(&named("cul"), &helper()));
    }

    #[test]
    fn glob_question_is_one_byte_not_one_char() {
        let one = ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "caf?", "T").unwrap();
        let two =
            ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "caf??", "T").unwrap();
        // UTF-8 `é` is two bytes: one `?` cannot cover it, two can.
        assert!(!one.match_metadata(&named("café"), &helper()));
        assert!(two.match_metadata(&named("café"), &helper()));
        assert!(one.match_metadata(&named("cafe"), &helper()));
    }

    #[test]
    fn glob_star_consumes_literal_star_in_text() {
        // A pattern `*` is a wildcard even against a text whose next byte
        // is also `*` — the equality branch must not eat it first.
        let r =
            ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "*worker", "T").unwrap();
        assert!(r.match_metadata(&named("*myworker"), &helper()));
        assert!(r.match_metadata(&named("worker"), &helper()));
        assert!(!r.match_metadata(&named("*myworkers"), &helper()));
        // A trailing literal-star comparison still works both ways.
        let lit =
            ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "work*", "T").unwrap();
        assert!(lit.match_metadata(&named("work*"), &helper()));
        assert!(lit.match_metadata(&named("worker"), &helper()));
    }

    #[test]
    fn glob_empty_field_never_matches_even_star() {
        let r = ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "*", "T").unwrap();
        assert!(!r.match_metadata(&Metadata::default(), &helper()));
        let stars =
            ProcessPatternRule::new_glob(RuleType::ProcessPathWildcard, "***", "T").unwrap();
        assert!(!stars.match_metadata(&Metadata::default(), &helper()));
    }

    #[test]
    fn glob_folds_like_go_simple_lowercase() {
        let r = ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "ÉX?T", "T").unwrap();
        assert!(r.match_metadata(&named("éxAt"), &helper()));
        // `İ` folds to `i` under Go's per-char simple lowercase.
        let dot_i = ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "İ*", "T").unwrap();
        assert!(dot_i.match_metadata(&named("ixyz"), &helper()));
    }

    #[test]
    fn glob_path_separators_are_plain_bytes() {
        let r = ProcessPatternRule::new_glob(RuleType::ProcessPathWildcard, "/opt/*/bin/tool", "T")
            .unwrap();
        assert!(r.match_metadata(&pathed("/opt/a/b/bin/tool"), &helper()));
        assert!(!r.match_metadata(&pathed("/optx/a/bin/tool"), &helper()));
        // `foo` is a whole-string match, never a suffix.
        let bare = ProcessPatternRule::new_glob(RuleType::ProcessPathWildcard, "foo", "T").unwrap();
        assert!(!bare.match_metadata(&pathed("/bin/foo"), &helper()));
    }

    #[test]
    fn glob_literal_brackets_and_backslashes() {
        let r = ProcessPatternRule::new_glob(
            RuleType::ProcessPathWildcard,
            r"C:\Apps\*\tool?.exe",
            "T",
        )
        .unwrap();
        assert!(r.match_metadata(&pathed(r"C:\Apps\x\y\tool1.exe"), &helper()));
        assert!(!r.match_metadata(&pathed(r"C:/Apps/x/tool1.exe"), &helper()));
        // `[a]` is a literal bracket, not a character class.
        let br = ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "x[a]y", "T").unwrap();
        assert!(br.match_metadata(&named("x[a]y"), &helper()));
        assert!(!br.match_metadata(&named("xay"), &helper()));
    }

    #[test]
    fn glob_matches_path_axis_only() {
        let r = ProcessPatternRule::new_glob(RuleType::ProcessPathWildcard, "*/tool", "T").unwrap();
        // Name supplied but path empty — the path rule misses.
        assert!(!r.match_metadata(&named("tool"), &helper()));
        assert!(r.match_metadata(&pathed("/usr/tool"), &helper()));
    }

    #[test]
    fn demand_and_liveness_contract() {
        let r = ProcessPatternRule::new_regex(RuleType::ProcessNameRegex, "x", "T").unwrap();
        assert_eq!(
            r.should_find_process(),
            meow_common::process_lookup::PROCESS_LOOKUP_SUPPORTED
        );
        assert!(!r.should_resolve_ip());
        assert_eq!(
            r.never_matches(),
            !meow_common::process_lookup::process_info_available()
        );
    }

    #[test]
    fn constructors_reject_empty_payload() {
        assert!(ProcessPatternRule::new_regex(RuleType::ProcessNameRegex, "", "T").is_err());
        assert!(ProcessPatternRule::new_glob(RuleType::ProcessNameWildcard, "", "T").is_err());
    }
}
