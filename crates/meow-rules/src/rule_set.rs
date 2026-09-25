//! Rule-set (rule-provider) matchers.
//!
//! A `RuleSet` is a collection of rules loaded from an external source (file or
//! HTTP) that can be referenced from the main rule list via a single
//! `RULE-SET,<name>,<adapter>[,no-resolve][,src]` entry. Three behaviors are
//! supported:
//!
//! - `Domain` — payload is a list of domains / `+.domain` wildcards, stored
//!   in a `DomainTrie` for O(log N) lookup.
//! - `IpCidr` — payload is a list of IPv4/IPv6 CIDRs.
//! - `Classical` — payload is a list of full Clash rule strings; each line
//!   is parsed as a normal rule (adapter ignored).

use std::fmt;
use std::str::FromStr;

use ipnet::IpNet;
use meow_common::{Metadata, Rule, RuleMatchHelper};
use meow_trie::DomainTrie;
use tracing::warn;

use crate::ip_set::{IpRangeSet, IpRangeSetBuilder};
use crate::parser::{parse_rule, ParserContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetBehavior {
    Domain,
    IpCidr,
    Classical,
}

impl FromStr for RuleSetBehavior {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "domain" => Ok(Self::Domain),
            "ipcidr" | "ip-cidr" => Ok(Self::IpCidr),
            "classical" => Ok(Self::Classical),
            other => Err(format!("unknown rule-set behavior: {other}")),
        }
    }
}

impl fmt::Display for RuleSetBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain => write!(f, "Domain"),
            Self::IpCidr => write!(f, "IPCIDR"),
            Self::Classical => write!(f, "Classical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetFormat {
    Yaml,
    Text,
    Mrs,
}

impl FromStr for RuleSetFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "yaml" => Ok(Self::Yaml),
            "text" => Ok(Self::Text),
            "mrs" => Ok(Self::Mrs),
            other => Err(format!("unsupported rule-set format: {other}")),
        }
    }
}

pub trait RuleSet: Send + Sync {
    fn behavior(&self) -> RuleSetBehavior;
    fn matches(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool;
    fn len(&self) -> usize;
    fn should_resolve_ip(&self) -> bool {
        false
    }
    fn should_find_process(&self) -> bool {
        false
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Domain-only match for DNS `nameserver-policy` `rule-set:` entries.
    ///
    /// Unlike [`RuleSet::matches`], this takes a bare domain string instead of
    /// a full [`Metadata`], because DNS policy dispatch only has the query
    /// domain. IP-behavior sets return `false`; classical sets evaluate their
    /// rules against a host-only `Metadata` (IP rules never match).
    fn matches_domain(&self, _domain: &str) -> bool {
        false
    }
}

/// Build a rule-set of the given behavior from already-parsed entries.
///
/// `ctx` is only consulted when `behavior == Classical` (since classical
/// rule-set entries are full rule lines that may include context-requiring
/// types like GEOIP). Domain and IpCidr behaviors ignore it entirely.
pub fn build_rule_set(
    behavior: RuleSetBehavior,
    entries: &[String],
    ctx: &ParserContext,
) -> Box<dyn RuleSet> {
    match behavior {
        RuleSetBehavior::Domain => Box::new(DomainRuleSet::from_entries(entries)),
        RuleSetBehavior::IpCidr => Box::new(IpCidrRuleSet::from_entries(entries)),
        RuleSetBehavior::Classical => Box::new(ClassicalRuleSet::from_entries(entries, ctx)),
    }
}

/// Checked variant of [`build_rule_set`] (issue #533 `strict: true`): the
/// first malformed entry is returned as an error instead of being
/// warn-skipped, so a provider payload with corrupt lines fails the load
/// rather than silently installing a partial rule set.
pub fn build_rule_set_checked(
    behavior: RuleSetBehavior,
    entries: &[String],
    ctx: &ParserContext,
) -> Result<Box<dyn RuleSet>, String> {
    match behavior {
        RuleSetBehavior::Domain => {
            let mut builder = DomainRuleSetBuilder::new();
            for entry in entries {
                builder.push_checked(entry)?;
            }
            Ok(Box::new(builder.build()))
        }
        RuleSetBehavior::IpCidr => {
            let mut builder = IpCidrRuleSetBuilder::new();
            for entry in entries {
                builder.push_checked(entry)?;
            }
            Ok(Box::new(builder.build()))
        }
        RuleSetBehavior::Classical => {
            let mut builder = ClassicalRuleSetBuilder::new(ctx);
            for entry in entries {
                builder.push_checked(entry)?;
            }
            Ok(Box::new(builder.build()))
        }
    }
}

/// Return `true` if `bytes` starts with the MRS magic `"MRS!"`.
pub fn is_mrs_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (bytes[..4] == crate::mrs_parser::MRS_MAGIC
            || bytes[..4] == crate::mrs_parser::ZSTD_MAGIC)
}

/// Parse an MRS binary payload and return the appropriate `RuleSet`.
/// The behavior is determined by the type tag in the header.
pub fn build_rule_set_from_mrs(
    bytes: &[u8],
    ctx: &ParserContext,
) -> Result<Box<dyn RuleSet>, String> {
    build_rule_set_from_mrs_with_behavior(bytes, ctx, None, false)
}

/// Parse an MRS binary payload and optionally validate it against the
/// configured provider behavior.
///
/// Entries stream from the zstd decoder straight into the set builders: no
/// decompressed copy of the payload and no per-entry `String` list is held,
/// so the load peak is the finished set plus a small buffer.
///
/// `strict` (issue #533): the first malformed entry fails the build instead
/// of being warn-skipped — parity with [`build_rule_set_checked`] for the
/// yaml/text payload path. The streaming callbacks return `()`, so the first
/// `push_checked` error is captured and reported after the stream ends.
pub fn build_rule_set_from_mrs_with_behavior(
    bytes: &[u8],
    ctx: &ParserContext,
    expected: Option<RuleSetBehavior>,
    strict: bool,
) -> Result<Box<dyn RuleSet>, String> {
    use crate::mrs_parser::{
        parse_header, stream_ipcidr_list, stream_string_list, UpstreamRuleSetReader,
        TYPE_CLASSICAL, TYPE_DOMAIN, TYPE_IPCIDR, ZSTD_MAGIC,
    };
    if bytes.len() >= 4 && bytes[..4] == ZSTD_MAGIC {
        let reader = UpstreamRuleSetReader::open(bytes).map_err(|e| e.to_string())?;
        let actual = behavior_from_type_tag(reader.behavior())?;
        if let Some(expected) = expected {
            if expected != actual {
                return Err(format!(
                    "mrs: behavior mismatch: config says {expected}, file says {actual}"
                ));
            }
        }
        return match actual {
            RuleSetBehavior::Domain => {
                let mut builder = DomainRuleSetBuilder::new();
                let mut first_err = None;
                reader
                    .for_each_domain(|d| {
                        if first_err.is_none() {
                            if strict {
                                if let Err(e) = builder.push_checked(d) {
                                    first_err = Some(e);
                                }
                            } else {
                                builder.push(d);
                            }
                        }
                    })
                    .map_err(|e| e.to_string())?;
                if let Some(e) = first_err {
                    return Err(e);
                }
                Ok(Box::new(builder.build()))
            }
            RuleSetBehavior::IpCidr => {
                let mut builder = IpCidrRuleSetBuilder::new();
                reader
                    .for_each_net(|net| builder.push_net(net))
                    .map_err(|e| e.to_string())?;
                Ok(Box::new(builder.build()))
            }
            RuleSetBehavior::Classical => {
                Err("mrs: upstream format does not support classical behavior".to_string())
            }
        };
    }

    let (hdr, compressed) = parse_header(bytes).map_err(|e| e.to_string())?;
    let actual = behavior_from_type_tag(hdr.type_tag)?;
    if let Some(expected) = expected {
        if expected != actual {
            return Err(format!(
                "mrs: behavior mismatch: config says {expected}, file says {actual}"
            ));
        }
    }
    let decoder = zstd::stream::Decoder::new(std::io::Cursor::new(compressed))
        .map_err(|e| format!("mrs: zstd decompression failed: {e}"))?;
    let mut first_err = None;
    let result = match hdr.type_tag {
        TYPE_DOMAIN => {
            let mut builder = DomainRuleSetBuilder::new();
            stream_string_list(decoder, |entry| {
                if first_err.is_none() {
                    if strict {
                        if let Err(e) = builder.push_checked(entry) {
                            first_err = Some(e);
                        }
                    } else {
                        builder.push(entry);
                    }
                }
            })
            .map_err(|e| e.to_string())?;
            Box::new(builder.build()) as Box<dyn RuleSet>
        }
        TYPE_IPCIDR => {
            let mut builder = IpCidrRuleSetBuilder::new();
            stream_ipcidr_list(decoder, |net| builder.push_net(net)).map_err(|e| e.to_string())?;
            Box::new(builder.build()) as Box<dyn RuleSet>
        }
        TYPE_CLASSICAL => {
            let mut builder = ClassicalRuleSetBuilder::new(ctx);
            stream_string_list(decoder, |entry| {
                if first_err.is_none() {
                    if strict {
                        if let Err(e) = builder.push_checked(entry) {
                            first_err = Some(e);
                        }
                    } else {
                        builder.push(entry);
                    }
                }
            })
            .map_err(|e| e.to_string())?;
            Box::new(builder.build()) as Box<dyn RuleSet>
        }
        other => return Err(format!("mrs: unsupported type tag {other}")),
    };
    if let Some(e) = first_err {
        return Err(e);
    }
    Ok(result)
}

fn behavior_from_type_tag(type_tag: u8) -> Result<RuleSetBehavior, String> {
    use crate::mrs_parser::{TYPE_CLASSICAL, TYPE_DOMAIN, TYPE_IPCIDR};
    match type_tag {
        TYPE_DOMAIN => Ok(RuleSetBehavior::Domain),
        TYPE_IPCIDR => Ok(RuleSetBehavior::IpCidr),
        TYPE_CLASSICAL => Ok(RuleSetBehavior::Classical),
        other => Err(format!("mrs: unsupported type tag {other}")),
    }
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

pub struct DomainRuleSet {
    trie: DomainTrie<()>,
    count: usize,
}

impl DomainRuleSet {
    pub fn from_entries(entries: &[String]) -> Self {
        let mut builder = DomainRuleSetBuilder::new();
        for entry in entries {
            builder.push(entry);
        }
        builder.build()
    }
}

/// Incremental [`DomainRuleSet`] construction, so streamed payloads never
/// need an intermediate entry list.
#[derive(Default)]
pub struct DomainRuleSetBuilder {
    trie: DomainTrie<()>,
    count: usize,
}

impl DomainRuleSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, entry: &str) {
        if let Err(e) = self.push_checked(entry) {
            warn!(
                "rule-set (domain): skipping invalid entry '{}': {}",
                entry, e
            );
        }
    }

    /// Checked variant of [`push`](Self::push) — the first malformed entry
    /// returns `Err` instead of being warn-skipped (issue #533 strict mode).
    pub fn push_checked(&mut self, entry: &str) -> Result<(), String> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Ok(());
        }
        let inserted = self.trie.insert(entry, ());
        // `+.foo.com` should match both the bare `foo.com` and any
        // subdomain (upstream mihomo semantics). `DomainTrie::insert`
        // only registers the wildcards; also insert the bare host.
        let bare_inserted = if let Some(rest) = entry.strip_prefix("+.") {
            self.trie.insert(rest, ())
        } else {
            true
        };
        if inserted || bare_inserted {
            self.count += 1;
            Ok(())
        } else {
            Err(format!("'{entry}' is not a valid domain pattern"))
        }
    }

    pub fn build(mut self) -> DomainRuleSet {
        self.trie.seal();
        DomainRuleSet {
            trie: self.trie,
            count: self.count,
        }
    }
}

impl RuleSet for DomainRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::Domain
    }

    fn matches(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let host = metadata.rule_host();
        if host.is_empty() {
            return false;
        }
        self.trie.search(host).is_some()
    }

    fn len(&self) -> usize {
        self.count
    }

    fn matches_domain(&self, domain: &str) -> bool {
        self.trie.search(domain).is_some()
    }
}

// ---------------------------------------------------------------------------
// IpCidr
// ---------------------------------------------------------------------------

/// ipcidr rule-set backed by a coalesced [`IpRangeSet`] — lookup is one
/// binary search over sorted intervals instead of a linear scan over every
/// CIDR. Country/ASN providers commonly carry thousands of entries; the
/// interval form costs 8 bytes per IPv4 interval. Same structure
/// `country_index.rs` uses for GEOIP rules.
pub struct IpCidrRuleSet {
    set: IpRangeSet,
    /// Parsed-entry count, as reported by `len()`. Kept separately because
    /// building the set merges adjacent/nested networks.
    count: usize,
}

impl IpCidrRuleSet {
    pub fn from_entries(entries: &[String]) -> Self {
        let mut builder = IpCidrRuleSetBuilder::new();
        for entry in entries {
            builder.push(entry);
        }
        builder.build()
    }
}

/// Incremental [`IpCidrRuleSet`] construction.
#[derive(Default)]
pub struct IpCidrRuleSetBuilder {
    set: IpRangeSetBuilder,
    count: usize,
}

impl IpCidrRuleSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one textual CIDR; invalid entries are logged and skipped.
    pub fn push(&mut self, entry: &str) {
        if let Err(e) = self.push_checked(entry) {
            warn!(
                "rule-set (ipcidr): skipping invalid entry '{}': {}",
                entry, e
            );
        }
    }

    /// Checked variant of [`push`](Self::push) — invalid CIDRs return `Err`
    /// (issue #533 strict mode).
    pub fn push_checked(&mut self, entry: &str) -> Result<(), String> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Ok(());
        }
        match entry.parse::<IpNet>() {
            Ok(net) => {
                self.push_net(net);
                Ok(())
            }
            Err(e) => Err(format!("'{entry}': {e}")),
        }
    }

    pub fn push_net(&mut self, net: IpNet) {
        self.set.add(net);
        self.count += 1;
    }

    pub fn build(self) -> IpCidrRuleSet {
        IpCidrRuleSet {
            set: self.set.build(),
            count: self.count,
        }
    }
}

impl RuleSet for IpCidrRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::IpCidr
    }

    fn matches(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        metadata.dst_ip.is_some_and(|ip| self.set.contains(ip))
    }

    fn len(&self) -> usize {
        self.count
    }

    fn should_resolve_ip(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Classical
// ---------------------------------------------------------------------------

pub struct ClassicalRuleSet {
    rules: Vec<Box<dyn Rule>>,
}

impl ClassicalRuleSet {
    pub fn from_entries(entries: &[String], ctx: &ParserContext) -> Self {
        let mut builder = ClassicalRuleSetBuilder::new(ctx);
        for entry in entries {
            builder.push(entry);
        }
        builder.build()
    }
}

/// Incremental [`ClassicalRuleSet`] construction.
pub struct ClassicalRuleSetBuilder<'a> {
    rules: Vec<Box<dyn Rule>>,
    ctx: &'a ParserContext,
}

impl<'a> ClassicalRuleSetBuilder<'a> {
    pub fn new(ctx: &'a ParserContext) -> Self {
        Self {
            rules: Vec::new(),
            ctx,
        }
    }

    pub fn push(&mut self, entry: &str) {
        if let Err(e) = self.push_checked(entry) {
            warn!("rule-set (classical): skipping '{}': {}", entry, e);
        }
    }

    /// Checked variant of [`push`](Self::push) — the first unparseable rule
    /// returns `Err` (issue #533 strict mode).
    pub fn push_checked(&mut self, entry: &str) -> Result<(), String> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Ok(());
        }
        // Classical entries are `TYPE,PAYLOAD[,extra]` without an adapter.
        // The existing parser expects an adapter column, so splice a
        // placeholder in and discard it at match time (our wrapper owns
        // the real adapter).
        //
        // `MATCH` would splice into an always-true FinalRule and make the
        // whole provider match every connection — upstream explicitly
        // rejects MATCH/RULE-SET/SUB-RULE in classical sets (the latter
        // two already fail as unknown types here), and `payloadToRule`
        // rejects MATCH inside logic sub-rules at any depth (enforced in
        // `parse_logic_rule`).
        let mut fields = entry.splitn(3, ',');
        let first_field = fields.next().map_or("", str::trim);
        if first_field == "MATCH" {
            return Err(format!(
                "'{entry}': MATCH is not allowed in a classical rule-set"
            ));
        }
        // An empty or missing payload silently degrades to match-all for
        // the substring-match types (`DOMAIN-SUFFIX,` → ends_with(""),
        // `DOMAIN-KEYWORD,` → contains("") — same as `FinalRule`). Same
        // class as MATCH — reject loudly (Class B, ADR-0002).
        if fields.next().map_or("", str::trim).is_empty() {
            return Err(format!("'{entry}': missing payload"));
        }
        // Comma-safe upstream regex payloads cannot be spliced
        // unambiguously — the truncated payload could still be a
        // valid-but-different regex. Reject loudly (Class B, ADR-0002).
        if first_field == "DOMAIN-REGEX" && fields.next().is_some() {
            return Err(format!(
                "'{entry}': {first_field} payloads containing commas are \
                 not supported in a classical rule-set"
            ));
        }
        let patched = splice_placeholder_adapter(entry);
        match parse_rule(&patched, self.ctx) {
            Ok(rule) => {
                self.rules.push(rule);
                Ok(())
            }
            Err(e) => Err(format!("'{entry}': {e}")),
        }
    }

    pub fn build(self) -> ClassicalRuleSet {
        ClassicalRuleSet { rules: self.rules }
    }
}

impl RuleSet for ClassicalRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::Classical
    }

    fn matches(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.rules
            .iter()
            .any(|r| r.match_metadata(metadata, helper))
    }

    fn len(&self) -> usize {
        self.rules.len()
    }

    fn should_resolve_ip(&self) -> bool {
        // Dead rules can never fire — their metadata demands must not
        // leak into the aggregate (#625).
        self.rules
            .iter()
            .any(|rule| !rule.never_matches() && rule.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| !rule.never_matches() && rule.should_find_process())
    }

    fn matches_domain(&self, domain: &str) -> bool {
        // Host-only metadata: IP/port/process/rules needing a resolver won't
        // match, matching upstream's "only domain rules" semantics for
        // classical sets. dst_port stays at the default 0 so DST-PORT rules
        // never fire on a domain-only query.
        let metadata = Metadata {
            host: domain.into(),
            ..Default::default()
        };
        self.rules
            .iter()
            .any(|r| r.match_metadata(&metadata, &RuleMatchHelper))
    }
}

/// Turn `TYPE,PAYLOAD[,extra]` into `TYPE,PAYLOAD,RULE-SET-PLACEHOLDER[,extra]`
/// so it satisfies `parse_rule`'s `type,payload,adapter[,extra]` shape.
fn splice_placeholder_adapter(entry: &str) -> String {
    const PLACEHOLDER: &str = "RULE-SET-PLACEHOLDER";
    // Logic sub-rules carry their own parenthesised payload that must not
    // be split on commas — append the placeholder at the end, same as
    // `splice_inner_adapter` in parser.rs.
    if let Some((ty, _)) = entry.split_once(',') {
        let upper = ty.trim().to_ascii_uppercase();
        if matches!(upper.as_str(), "AND" | "OR" | "NOT") {
            return format!("{entry},{PLACEHOLDER}");
        }
    }
    let parts: Vec<&str> = entry.splitn(3, ',').collect();
    match parts.as_slice() {
        [ty, payload] => format!("{},{},{}", ty.trim(), payload.trim(), PLACEHOLDER),
        [ty, payload, rest] => format!(
            "{},{},{},{}",
            ty.trim(),
            payload.trim(),
            PLACEHOLDER,
            rest.trim()
        ),
        _ => entry.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::Metadata;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_host(host: &str) -> Metadata {
        Metadata {
            host: host.into(),
            dst_port: 443,
            ..Default::default()
        }
    }

    fn meta_ip(ip: &str) -> Metadata {
        Metadata {
            dst_ip: Some(ip.parse().unwrap()),
            dst_port: 443,
            ..Default::default()
        }
    }

    /// A `MATCH` entry in a classical payload must not splice into an
    /// always-true `FinalRule` — that would make the whole provider match
    /// every connection. Upstream rejects MATCH/RULE-SET/SUB-RULE in
    /// classical sets.
    #[test]
    fn classical_rule_set_rejects_match_entry() {
        let set = ClassicalRuleSet::from_entries(
            &[
                "MATCH,DIRECT".to_string(),
                "DOMAIN-SUFFIX,ok.example".to_string(),
            ],
            &ParserContext::empty(),
        );
        // The MATCH entry is dropped; only the real entry can match.
        assert!(!set.matches(&meta_host("nope.example"), &helper()));
        assert!(set.matches(&meta_host("ok.example"), &helper()));

        // Nested `MATCH` inside a logic entry must not slip through either
        // — `OR,((MATCH,x),…)` would otherwise splice the inner MATCH into
        // an always-true leg and match-all the provider anyway.
        let set = ClassicalRuleSet::from_entries(
            &[
                "OR,((MATCH,DIRECT),(DOMAIN-SUFFIX,ok.example))".to_string(),
                "DOMAIN-SUFFIX,fine.example".to_string(),
            ],
            &ParserContext::empty(),
        );
        assert_eq!(set.len(), 1, "the nested-MATCH entry must be dropped");
        assert!(!set.matches(&meta_host("nope.example"), &helper()));
        assert!(set.matches(&meta_host("fine.example"), &helper()));

        // A comma-containing DOMAIN-REGEX payload cannot be represented —
        // the entry must be rejected, not silently truncated to a
        // different regex (`DOMAIN-REGEX,a,b` → regex "a").
        let set = ClassicalRuleSet::from_entries(
            &[
                "DOMAIN-REGEX,a,b".to_string(),
                "DOMAIN-SUFFIX,ok.example".to_string(),
            ],
            &ParserContext::empty(),
        );
        assert_eq!(set.len(), 1, "the ambiguous DOMAIN-REGEX must be dropped");
        assert!(set.matches(&meta_host("ok.example"), &helper()));

        // Empty/missing payloads must not silently degrade to match-all
        // (`DOMAIN-SUFFIX,` → ends_with(""), `DOMAIN-KEYWORD,` →
        // contains("") — same as `MATCH`).
        let set = ClassicalRuleSet::from_entries(
            &[
                "DOMAIN-SUFFIX,".to_string(),
                "DOMAIN-KEYWORD,".to_string(),
                "DOMAIN-SUFFIX,ok.example".to_string(),
            ],
            &ParserContext::empty(),
        );
        assert_eq!(set.len(), 1, "empty-payload entries must be dropped");
        // `nope.example` host present but the empty-suffix member is gone —
        // without the guard the set would match every connection.
        assert!(!set.matches(&meta_host(""), &helper()));
        assert!(set.matches(&meta_host("ok.example"), &helper()));
    }

    #[test]
    fn domain_rule_set_matches_plus_wildcard() {
        let set = DomainRuleSet::from_entries(&["+.foo.com".to_string()]);
        assert!(set.matches(&meta_host("a.foo.com"), &helper()));
        assert!(set.matches(&meta_host("foo.com"), &helper()));
        assert!(!set.matches(&meta_host("bar.com"), &helper()));
    }

    #[test]
    fn ipcidr_rule_set_matches() {
        let set = IpCidrRuleSet::from_entries(&[
            "10.0.0.0/8".to_string(),
            "bogus".to_string(), // skipped
        ]);
        assert_eq!(set.len(), 1);
        assert!(set.matches(&meta_ip("10.1.2.3"), &helper()));
        assert!(!set.matches(&meta_ip("11.0.0.1"), &helper()));
    }

    #[test]
    fn ipcidr_rule_set_matches_ipv6() {
        let set = IpCidrRuleSet::from_entries(&["fd00::/8".to_string()]);
        assert_eq!(set.len(), 1);
        assert!(set.matches(&meta_ip("fd12::1"), &helper()));
        assert!(!set.matches(&meta_ip("2001:db8::1"), &helper()));
        // An IPv4 destination must not match a v6-only rule set.
        assert!(!set.matches(&meta_ip("10.1.2.3"), &helper()));
    }

    #[test]
    fn ipcidr_rule_set_matches_mixed_families() {
        let set = IpCidrRuleSet::from_entries(&["10.0.0.0/8".to_string(), "fd00::/8".to_string()]);
        assert_eq!(set.len(), 2);
        assert!(set.matches(&meta_ip("10.1.2.3"), &helper()));
        assert!(set.matches(&meta_ip("fd12::1"), &helper()));
        assert!(!set.matches(&meta_ip("11.0.0.1"), &helper()));
        assert!(!set.matches(&meta_ip("2001:db8::1"), &helper()));
    }

    #[test]
    fn ipcidr_rule_set_coalesces_adjacent_cidrs_without_semantic_change() {
        // Adjacent /24s coalesce into one interval; matching behavior must
        // be identical to checking each CIDR independently.
        let set =
            IpCidrRuleSet::from_entries(&["10.0.0.0/24".to_string(), "10.0.1.0/24".to_string()]);
        assert_eq!(set.len(), 2);
        assert!(set.matches(&meta_ip("10.0.0.128"), &helper()));
        assert!(set.matches(&meta_ip("10.0.1.128"), &helper()));
        assert!(!set.matches(&meta_ip("10.0.2.1"), &helper()));
    }

    #[test]
    fn classical_rule_set_delegates_to_parser() {
        let ctx = ParserContext::empty();
        let set = ClassicalRuleSet::from_entries(
            &[
                "DOMAIN-SUFFIX,google.com".to_string(),
                "IP-CIDR,10.0.0.0/8,no-resolve".to_string(),
            ],
            &ctx,
        );
        assert_eq!(set.len(), 2);
        assert!(set.matches(&meta_host("mail.google.com"), &helper()));
        assert!(set.matches(&meta_ip("10.1.2.3"), &helper()));
        assert!(!set.matches(&meta_host("example.org"), &helper()));
    }

    #[test]
    fn classical_rule_set_propagates_metadata_demands() {
        let ctx = ParserContext::empty();
        let set = ClassicalRuleSet::from_entries(
            &[
                "IP-CIDR,10.0.0.0/8".to_string(),
                "PROCESS-NAME,curl".to_string(),
            ],
            &ctx,
        );
        assert!(set.should_resolve_ip());
        // PROCESS-NAME demands the lookup only where find_process is real
        // (#625 — off the supported platforms the member is dead and the
        // demand is filtered).
        assert_eq!(
            set.should_find_process(),
            meow_common::process_lookup::PROCESS_LOOKUP_SUPPORTED
        );
    }

    #[test]
    fn classical_rule_set_skips_dead_member_demands() {
        use crate::domain_suffix::DomainSuffixRule;
        use crate::geoip::GeoIpRule;
        use crate::ip_set::IpRangeSetBuilder;
        use crate::logic::AndRule;
        use crate::process::ProcessRule;
        use std::sync::Arc;

        // Provably-dead members must not pin the set's demands. A GEOIP
        // whose payload is absent from the index carries an empty range
        // set (dead, but reports an IP demand); an AND tree containing it
        // is dead while its live PROCESS-NAME child still reports a
        // process demand (#625).
        let empty = Arc::new(IpRangeSetBuilder::new().build());
        let dead_geoip: Box<dyn Rule> = Box::new(GeoIpRule::new("ZZ", "", false, empty));
        let dead_and: Box<dyn Rule> = Box::new(AndRule::new(
            vec![
                Box::new(GeoIpRule::new(
                    "ZZ",
                    "",
                    false,
                    Arc::new(IpRangeSetBuilder::new().build()),
                )),
                Box::new(ProcessRule::new("curl", "")),
            ],
            "",
        ));
        assert!(dead_geoip.never_matches());
        assert!(dead_and.never_matches());

        let set = ClassicalRuleSet {
            rules: vec![
                dead_geoip,
                dead_and,
                Box::new(DomainSuffixRule::new("example.com", "")),
            ],
        };
        assert!(!set.should_resolve_ip());
        assert!(!set.should_find_process());
    }

    #[test]
    fn build_rule_set_dispatches_by_behavior() {
        let ctx = ParserContext::empty();
        let set = build_rule_set(RuleSetBehavior::Domain, &["example.com".to_string()], &ctx);
        assert_eq!(set.behavior(), RuleSetBehavior::Domain);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn domain_rule_set_matches_domain_directly() {
        let set = DomainRuleSet::from_entries(&["+.foo.com".to_string()]);
        assert!(set.matches_domain("a.foo.com"));
        assert!(set.matches_domain("foo.com"));
        assert!(!set.matches_domain("bar.com"));
        // case-insensitive, like the full Metadata path
        assert!(set.matches_domain("A.Foo.COM"));
    }

    #[test]
    fn classical_rule_set_matches_domain_only() {
        let ctx = ParserContext::empty();
        let set = ClassicalRuleSet::from_entries(
            &[
                "DOMAIN-SUFFIX,google.com".to_string(),
                "IP-CIDR,10.0.0.0/8,no-resolve".to_string(),
                // A DST-PORT rule must NOT fire on a domain-only query even
                // though DNS runs on port 53 — guard against dst_port=53
                // false positives in matches_domain.
                "DST-PORT,53".to_string(),
            ],
            &ctx,
        );
        assert!(set.matches_domain("mail.google.com"));
        // IP and port rules must not fire on a domain-only query.
        assert!(!set.matches_domain("10.0.0.1"));
        assert!(!set.matches_domain("example.org"));
    }

    #[test]
    fn ipcidr_rule_set_matches_domain_is_false() {
        let set = IpCidrRuleSet::from_entries(&["10.0.0.0/8".to_string()]);
        assert!(!set.matches_domain("10.0.0.1"));
        assert!(!set.matches_domain("foo.com"));
    }

    #[test]
    fn behavior_from_str() {
        assert_eq!(
            "domain".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::Domain
        );
        assert_eq!(
            "ipcidr".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::IpCidr
        );
        assert_eq!(
            "IPCIDR".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::IpCidr
        );
        assert_eq!(
            "classical".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::Classical
        );
        assert!("nope".parse::<RuleSetBehavior>().is_err());
    }

    /// MRS payloads take the same strict gate as yaml/text — a malformed
    /// entry inside the zstd stream fails the build instead of being
    /// warn-skipped (issue #533 review).
    #[test]
    fn mrs_strict_rejects_malformed_entry() {
        use crate::mrs_parser::{write_ruleset_mrs, TYPE_DOMAIN};
        let bytes = write_ruleset_mrs(TYPE_DOMAIN, &["ok.example", "+."]).unwrap();
        let ctx = ParserContext::default();

        // Lenient: the bad entry is warn-skipped, the good one survives.
        let set = build_rule_set_from_mrs_with_behavior(
            &bytes,
            &ctx,
            Some(RuleSetBehavior::Domain),
            false,
        )
        .expect("lenient build keeps good entries");
        assert!(set.matches(&meta_host("ok.example"), &helper()));

        // Strict: the same payload errors, naming the entry.
        let Err(err) = build_rule_set_from_mrs_with_behavior(
            &bytes,
            &ctx,
            Some(RuleSetBehavior::Domain),
            true,
        ) else {
            panic!("strict must reject a malformed mrs entry");
        };
        assert!(err.contains("+."), "unexpected: {err}");
    }
}
