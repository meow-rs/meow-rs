//! Predicates naming the "dead" shapes a domain key can take, shared by the
//! `rules:` parser and the DNS-side `DomainTrie` surfaces (`hosts:`,
//! `nameserver-policy`, `fallback-filter.domain`, `fake-ip-filter`, and the
//! sniffer `skip-domain`/`force-domain` lists).
//!
//! The same dead-key concept is encoded in three places that must stay
//! consistent:
//!
//! - [`domain_key_defect`] here — the config-time classification callers
//!   warn (lenient) or hard-error (`strict: true`) on;
//! - `DomainTrie::insert`/`insert_overwrite` in `meow-trie` — the writes
//!   that refuse a key outright or strand it on an unreachable node;
//! - `indexable_pattern` in `meow-tunnel`'s `match_engine` — the runtime
//!   index's eligibility test, which excludes the same shapes so a dead
//!   pattern stays on the linear scan rather than owning a trie slot.
//!
//! Every check is observability only: a flagged key is still handed to its
//! consumer — the warn/error surfaces a defect instead of changing what
//! the entry matches.
//!
//! Coverage on the `rules:` surface, per rule type: `DOMAIN` and
//! `DOMAIN-SUFFIX` get [`domain_rule_payload_is_dead`] (dead label,
//! leading/trailing dot, a verbatim-dead `*`/`+` spelling);
//! `DOMAIN-WILDCARD` gets [`domain_wildcard_payload_is_dead`] (a
//! literal `+` — the matcher globs `*` only — or a dead literal
//! label); `DOMAIN-KEYWORD` gets [`domain_keyword_payload_is_dead`]
//! (`..` or a byte no normalized host can carry — a `foo.` needle
//! still matches `foo.bar` as a substring) plus
//! [`domain_keyword_payload_matches_all`] for the empty needle,
//! which is not dead but the opposite — a silent match-all.
//! `DOMAIN-REGEX` is not checked: its payload is an arbitrary
//! pattern, so whether it can match a normalized host is not
//! decidable by label inspection.

/// The defect a domain key carries on a `DomainTrie` surface, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainKeyDefect {
    /// An empty label survives normalization (`a..b`, `..x`, `+..x`): the
    /// insert "succeeds", but the node it builds is unreachable because no
    /// query name ever contains an empty label (issue #822's shape, one
    /// level up — the trailing-dot half is fixed inside
    /// `DomainTrie::insert` itself).
    DeadLabel,
    /// The normalized body is empty (`"."`, `".."`, `"+."`, `"*."`, a
    /// whitespace-only key): `DomainTrie::insert` refuses the key
    /// outright — no node is built at all.
    NotInsertable,
}

/// The label string a `DomainTrie` works on: surrounding whitespace
/// trimmed, one `+.`/`*.`/`.` wildcard prefix removed, trailing dots
/// dropped — the same normalization `insert_inner` applies before it
/// splits labels, so `x.com.` and `x.com` share the live body `x.com`.
fn domain_key_body(key: &str) -> &str {
    let key = key.trim();
    key.strip_prefix("+.")
        .or_else(|| key.strip_prefix("*."))
        .or_else(|| key.strip_prefix('.'))
        .unwrap_or(key)
        .trim_end_matches('.')
}

/// Classify `key` on a `DomainTrie` surface: `Some(_)` when the key can
/// never be produced by a domain query — either it strands an unreachable
/// node or the trie refuses it outright. Callers warn (lenient) or
/// hard-error (`strict: true`); the key is still inserted either way, so
/// the check is observability, never a semantics change.
pub fn domain_key_defect(key: &str) -> Option<DomainKeyDefect> {
    let body = domain_key_body(key);
    if body.is_empty() {
        return Some(DomainKeyDefect::NotInsertable);
    }
    body.split('.')
        .any(str::is_empty)
        .then_some(DomainKeyDefect::DeadLabel)
}

/// True when `key` holds an empty label after normalization — `a..b`,
/// `..x`, `+..x`. A trailing-dot run is *not* dead on a trie surface:
/// `insert` strips it, so `x.com.` and `x.com..` are live spellings of
/// `x.com`.
pub fn domain_key_has_dead_label(key: &str) -> bool {
    domain_key_defect(key) == Some(DomainKeyDefect::DeadLabel)
}

/// True when `key` can never match on a `DomainTrie` surface — either a
/// dead label or a body the trie refuses.
pub fn domain_key_is_dead(key: &str) -> bool {
    domain_key_defect(key).is_some()
}

/// The bytes a normalized `rule_host()` can carry: DNS-label bytes
/// (`[0-9a-zA-Z._-]` plus the `.` separators) and IP-literal bytes (`:`
/// and `[`/`]` for IPv6). Every producer of `Metadata::host`/`sniff_host`
/// passes `is_valid_host`, so a payload byte outside this alphabet can
/// never appear in what the rule compares against.
fn byte_outside_rule_host_alphabet(b: u8) -> bool {
    !matches!(
        b,
        b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'.' | b'-' | b'_' | b':' | b'[' | b']'
    )
}

/// True when a `DOMAIN`/`DOMAIN-SUFFIX` `rules:` payload can never equal
/// the normalized [`Metadata::rule_host`] it is compared against:
///
/// - a trailing dot — `rule_host()` strips trailing dots, so `x.com.` can
///   only ever name `x.com`, which no `DOMAIN,x.com.` payload matches;
/// - a leading dot — `DomainRule` compares verbatim and
///   `DomainSuffixRule` matches `host == suffix` or `.{suffix}` at a
///   label boundary, so `.x.com` would need a host starting with `.`
///   (or containing `..x.com`) — impossible on a normalized host;
/// - any byte outside the rule-host alphabet — `DomainRule`/
///   `DomainSuffixRule` compare the payload verbatim, and no normalized
///   host carries `*`, `+`, `?`, a space, or non-ASCII bytes, so
///   wildcard spellings (`DOMAIN,*.x.com`, `DOMAIN-SUFFIX,+.x.com`) and
///   impossible-byte payloads (`DOMAIN,a?b`) are dead on these rule
///   types (`*` belongs on `DOMAIN-WILDCARD`; a `DOMAIN-SUFFIX,x.com`
///   payload already covers apex plus subdomains, so `+.` adds
///   nothing); or
/// - any [`domain_key_defect`] shape (`a..b`, `"."`, `"+."`).
///
/// Caveat on the empty payload: it is dead only in the
/// never-equals-a-*named*-host sense — `rule_host()` is `""` on
/// host-less flows, so `DOMAIN,,X` and `DOMAIN-SUFFIX,,X` still match
/// every IP-literal destination (a silent host-less match-all, issue
/// #869). `domain_payload_defect` in meow-config reports that case with
/// its own catch-all-shaped warning; this predicate keeps `is_empty` in
/// the dead set because the trie/index consumers genuinely cannot key
/// it either.
///
/// [`Metadata::rule_host`]: meow_common::Metadata::rule_host
pub fn domain_rule_payload_is_dead(payload: &str) -> bool {
    let payload = payload.trim();
    payload.is_empty()
        || payload.ends_with('.')
        || payload.starts_with('.')
        || payload.bytes().any(byte_outside_rule_host_alphabet)
        || domain_key_is_dead(payload)
}

/// True when a `DOMAIN-WILDCARD` `rules:` payload can never match the
/// normalized [`Metadata::rule_host`]:
///
/// - a `+` anywhere — the matcher globs `*` only, so `regex::escape`
///   leaves `+` a literal byte no host carries (`+.wild.example` reads
///   like the mihomo DOMAIN-SUFFIX spelling but is dead here);
/// - any other byte outside the rule-host alphabet — the matcher has no
///   `?` glob either (upstream supports `*` only), so `a?b`, a space or
///   a non-ASCII byte is a literal byte no normalized host carries
///   (issue #869); or
/// - after one `*.` glob prefix is normalized away (a pure prefix does
///   not count as a literal label), any remaining label that is empty
///   names a byte run no normalized host produces — `a..b`, `.foo`,
///   `foo.`, `*.foo.`. `*`-bearing segments are globs (`[^.]+`), never
///   empty labels, and `*` is the one byte exempted from the alphabet
///   check for that reason.
///
/// [`Metadata::rule_host`]: meow_common::Metadata::rule_host
pub fn domain_wildcard_payload_is_dead(payload: &str) -> bool {
    let payload = payload.trim();
    if payload.is_empty()
        || payload
            .bytes()
            .any(|b| b != b'*' && byte_outside_rule_host_alphabet(b))
    {
        return true;
    }
    let body = payload.strip_prefix("*.").unwrap_or(payload);
    body.is_empty() || body.split('.').any(str::is_empty)
}

/// True when a `DOMAIN-KEYWORD` `rules:` payload can never match: the
/// keyword is a substring probe against `rule_host()`, whose producers
/// (`Metadata::host` at every ingress, `sniff_host` from the SNI/Host
/// sniffers) all pass `is_valid_host` — so the bytes a normalized host
/// can carry are DNS-label bytes (`[0-9a-zA-Z._-]`) and IP-literal
/// bytes (`:` and `[`/`]` for IPv6). A needle holding `..` or any byte
/// outside that alphabet (`*`, `+`, `?`, a space, non-ASCII, …) can
/// never be a substring of a rule host.
///
/// A trailing-dot keyword (`evil.com.`) is *live* and must not be
/// flagged — it still matches superstrings like `evil.com.au` where the
/// dot survives — but note it can no longer hit the bare `evil.com`
/// itself: `rule_host()` strips the host's trailing dots before the
/// substring probe, so the needle's own trailing dot only ever matches
/// inside a longer name. The same holds for an anchored
/// `DOMAIN-REGEX` like `^foo\.$`, which the check does not cover at
/// all — a documented residual of the trailing-dot normalization.
///
/// An *empty* needle is not dead either — `contains("")` is always
/// true — so it is flagged by [`domain_keyword_payload_matches_all`]
/// instead of here.
///
/// [`Metadata::rule_host`]: meow_common::Metadata::rule_host
pub fn domain_keyword_payload_is_dead(payload: &str) -> bool {
    payload.contains("..") || payload.bytes().any(byte_outside_rule_host_alphabet)
}

/// True when a `DOMAIN-KEYWORD` `rules:` payload is empty: the needle is
/// the payload verbatim (parser-trimmed before `DomainKeywordRule::new`),
/// and `host.contains("")` is always true, so the rule silently matches
/// *every* flow — host-less IP flows included — and short-circuits every
/// rule below it. Not dead, the opposite, so it gets its own flag: a
/// `DOMAIN-KEYWORD,,X` line is almost always a comma slip for `MATCH,X`
/// (issue #869).
pub fn domain_keyword_payload_matches_all(payload: &str) -> bool {
    payload.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `DomainTrie`-surface matrix: mid/leading empty labels are dead
    /// (they insert into an unreachable node), prefix-only/all-dots bodies
    /// are refused outright, and trailing dots normalize to a live key.
    #[test]
    fn domain_key_defect_matrix() {
        for key in ["a..b", "..x", "+..x", "+.a..b", "a...b", " a..b "] {
            assert_eq!(
                domain_key_defect(key),
                Some(DomainKeyDefect::DeadLabel),
                "{key:?} is a dead label"
            );
        }
        for key in [".", "..", "+.", "*.", "+..", " ", ""] {
            assert_eq!(
                domain_key_defect(key),
                Some(DomainKeyDefect::NotInsertable),
                "{key:?} is refused by insert"
            );
        }
        // A trailing-dot run is stripped by the trie (live); a mid `*`
        // stays a literal label.
        for key in [
            "x.com.", "x..", "a.*.b", "a.b", "x.com", "+.x.com", "*.x", ".x",
        ] {
            assert_eq!(domain_key_defect(key), None, "{key:?} is live");
        }
    }

    /// The `rules:` surface additionally treats a leading/trailing dot
    /// and any `*`/`+` spelling as dead: `rule_host()` normalizes dots
    /// away and no normalized host carries a `*`/`+` byte, so
    /// `DOMAIN,.x.com`, `DOMAIN,x.com.` and `DOMAIN,*.x.com` can never
    /// equal a rule host.
    #[test]
    fn domain_rule_payload_is_dead_matrix() {
        for payload in [
            "a..b",
            "x.com.",
            "x.com..",
            ".",
            "..",
            "+.",
            "",
            "  ",
            "evil.com.",
            ".x.com",
            ".foo",
            "*.x.com",
            "+.x.com",
            "a.*.b",
            "x+com",
        ] {
            assert!(
                domain_rule_payload_is_dead(payload),
                "{payload:?} is a dead rule payload"
            );
        }
        for payload in ["x.com", "evil.com"] {
            assert!(
                !domain_rule_payload_is_dead(payload),
                "{payload:?} is a live rule payload"
            );
        }
    }

    /// DOMAIN-WILDCARD dead-shape matrix: the matcher globs `*` only, so
    /// `+`/`?`/space/non-ASCII are literal bytes no host carries —
    /// `+.wild.example` reads like the DOMAIN-SUFFIX spelling but is dead
    /// here, and `a?b` is a literal `?` no host produces. A literal empty
    /// label (`..`, leading or trailing dot) can never appear in a
    /// normalized host; a `*` segment is a glob, never an empty label,
    /// though `*.` alone reduces to a glob plus a literal trailing dot.
    #[test]
    fn domain_wildcard_payload_is_dead_matrix() {
        for payload in [
            "*.foo.",
            "a..b",
            "a.*..b",
            ".foo",
            "foo.",
            ".",
            "",
            "  ",
            "*..",
            "*.",
            // `+` is literal on DOMAIN-WILDCARD — always dead.
            "+.",
            "+.foo",
            "+.wild.example",
            "a+b",
            "x+*",
            // And so is every other byte outside the host alphabet — the
            // matcher has no `?` glob, so these are literal dead bytes.
            "a?b",
            "*.a?b",
            "a b",
            "a/b",
            "a@b",
            "caf\u{e9}",
        ] {
            assert!(
                domain_wildcard_payload_is_dead(payload),
                "{payload:?} is a dead wildcard payload"
            );
        }
        for payload in [
            "*.foo",
            "*.x.com",
            "*.wild.example",
            "*",
            "*.*",
            "a.*.b",
            "f*o.com",
            "x*",
        ] {
            assert!(
                !domain_wildcard_payload_is_dead(payload),
                "{payload:?} is a live wildcard payload"
            );
        }
    }

    /// DOMAIN-KEYWORD is a substring probe: `..` and any byte outside
    /// the `is_valid_host` alphabet (`*`, `+`, `?`, space, non-ASCII)
    /// can never appear in a normalized host. `foo.` stays live — it
    /// matches `foo.bar`; `:`/`[`/`]` stay live for IPv6-literal rule
    /// hosts.
    #[test]
    fn domain_keyword_payload_is_dead_matrix() {
        for payload in [
            "a..b",
            "..x",
            "x..",
            "foo..bar",
            "*",
            "+",
            "x+y",
            "foo?",
            "a b",
            "a/b",
            "a@b",
            "caf\u{e9}",
            "a,b",
        ] {
            assert!(
                domain_keyword_payload_is_dead(payload),
                "{payload:?} is a dead keyword payload"
            );
        }
        for payload in ["foo.", ".foo", "foo.bar", "x", ":53", "[2001", "a-b_c", ""] {
            assert!(
                !domain_keyword_payload_is_dead(payload),
                "{payload:?} is a live keyword payload"
            );
        }
    }

    /// The empty needle is the opposite of dead — `contains("")` is
    /// always true, so `DOMAIN-KEYWORD,,X` silently matches every flow.
    /// It is flagged by `domain_keyword_payload_matches_all`, not by the
    /// dead check (issue #869): callers must consult *both* predicates —
    /// checking only `is_dead` would leave the match-all unseen, and
    /// checking only `matches_all` would miss every dead shape.
    #[test]
    fn domain_keyword_payload_matches_all_flags_empty_only() {
        // The combined contract: empty is match-all and *not* dead.
        assert!(domain_keyword_payload_matches_all(""));
        assert!(!domain_keyword_payload_is_dead(""));
        for payload in ["x", "foo.", " ", "*"] {
            assert!(
                !domain_keyword_payload_matches_all(payload),
                "{payload:?} is not the match-all needle"
            );
        }
    }
}
