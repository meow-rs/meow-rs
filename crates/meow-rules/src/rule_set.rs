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

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use ipnet::IpNet;
use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};
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

/// Return `true` if `bytes` opens a recognised mrs container: the `"MRS!"`
/// header, an upstream-format zstd frame, or a legacy zstd frame — the
/// last routes to the mrs parser so it fails with the named
/// `LegacyZstd` error rather than a format-mismatch.
pub fn is_mrs_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (bytes[..4] == crate::mrs_parser::MRS_MAGIC
            || bytes[..4] == crate::mrs_parser::ZSTD_MAGIC
            || crate::mrs_parser::legacy_zstd_version(bytes).is_some())
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
        legacy_zstd_version, parse_header, stream_ipcidr_list, stream_string_list, zstd_decoder,
        MrsError, UpstreamRuleSetReader, TYPE_CLASSICAL, TYPE_DOMAIN, TYPE_IPCIDR, ZSTD_MAGIC,
    };
    // A whole-file legacy zstd stream fails the `ZSTD_MAGIC` dispatch below
    // and would report "not an mrs file"; name it by its real format.
    if let Some(version) = legacy_zstd_version(bytes) {
        return Err(MrsError::LegacyZstd(version).to_string());
    }
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
                let skipped = reader
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
                // No provider name is reachable from this layer — the
                // refresh/parse callers in meow-config put `provider =
                // %name` on their own log lines, so this warning stays
                // generic rather than inventing a label.
                if skipped > 0 {
                    warn!("mrs: {skipped} stored keys skipped (not valid UTF-8)");
                }
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
    let decoder = zstd_decoder(compressed).map_err(|e| e.to_string())?;
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
        // `+.foo.com` covers both the bare `foo.com` and any subdomain
        // (upstream mihomo semantics) — `DomainTrie::insert` handles both
        // halves natively, no supplementary bare insert.
        if self.trie.insert(entry, ()) {
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

// A domain pattern in a classical set is literal, including '*' and leading
// dots. DomainTrie interprets these as wildcards, so it cannot index this run.
#[derive(Default)]
struct LiteralDomains {
    exact: HashSet<Box<[u8]>>,
    suffix: HashSet<Box<[u8]>>,
}

impl LiteralDomains {
    // Cover DNS names without heap-allocating to fold a query. Longer rule
    // payloads are still accepted and run through their existing matcher.
    const MAX_KEY: usize = 255;

    fn eligible(rule: &dyn Rule) -> bool {
        matches!(rule.rule_type(), RuleType::Domain | RuleType::DomainSuffix)
            && rule.payload().len() <= Self::MAX_KEY
    }

    fn insert(&mut self, rule: &dyn Rule) {
        let keys = if rule.rule_type() == RuleType::Domain {
            &mut self.exact
        } else {
            &mut self.suffix
        };
        // Both rule constructors have already canonicalized the stored key.
        keys.insert(rule.payload().as_bytes().into());
    }

    fn contains(&self, host: &str) -> bool {
        let bytes = host.as_bytes();
        let exact = bytes.len() <= Self::MAX_KEY;
        let mut key = bytes;
        if !exact {
            // Only a suffix following a literal dot can still fit this index.
            let tail = &bytes[bytes.len() - Self::MAX_KEY - 1..];
            let Some(dot) = tail.iter().position(|&b| b == b'.') else {
                return false;
            };
            key = &tail[dot + 1..];
        }
        let mut folded = [0; Self::MAX_KEY];
        if key.iter().any(u8::is_ascii_uppercase) {
            let buf = &mut folded[..key.len()];
            buf.copy_from_slice(key);
            buf.make_ascii_lowercase();
            key = buf;
        }
        if exact && self.exact.contains(key) {
            return true;
        }
        if !self.suffix.is_empty() {
            loop {
                if self.suffix.contains(key) {
                    return true;
                }
                let Some(dot) = key.iter().position(|&b| b == b'.') else {
                    break;
                };
                key = &key[dot + 1..];
            }
        }
        false
    }
}

struct IndexedRun {
    following: Vec<Box<dyn Rule>>,
    domains: LiteralDomains,
}

pub struct ClassicalRuleSet {
    head: Vec<Box<dyn Rule>>,
    runs: Vec<IndexedRun>,
    count: usize,
}

impl ClassicalRuleSet {
    fn from_rules(rules: Vec<Box<dyn Rule>>) -> Self {
        const MIN_RUN: usize = 64;
        let count = rules.len();
        let mut runs: Vec<IndexedRun> = Vec::new();
        if count < MIN_RUN {
            return Self {
                runs,
                head: rules,
                count,
            };
        }
        let mut head = Vec::new();
        let mut rules = rules.into_iter();
        while let Some(rule) = rules.next() {
            let literal = LiteralDomains::eligible(rule.as_ref());
            let ordered = runs.last_mut().map_or(&mut head, |run| &mut run.following);
            ordered.push(rule);
            if !literal {
                continue;
            }
            // Leave the first literal in place: first-entry hits stay cheap.
            let following = rules
                .as_slice()
                .iter()
                .take_while(|r| LiteralDomains::eligible(r.as_ref()))
                .count();
            let rest = rules.by_ref().take(following);
            if following < MIN_RUN - 1 {
                ordered.extend(rest);
                continue;
            }
            let mut domains = LiteralDomains::default();
            for rule in rest {
                domains.insert(rule.as_ref());
            }
            runs.push(IndexedRun {
                following: Vec::new(),
                domains,
            });
        }
        Self { head, runs, count }
    }

    fn remaining_rules(&self) -> impl Iterator<Item = &dyn Rule> {
        self.head
            .iter()
            .chain(self.runs.iter().flat_map(|run| &run.following))
            .map(Box::as_ref)
    }

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
        // Compare against the config grammar's names, the same way
        // `parse_rule` does — a mihomo API spelling must hit the guards
        // too: `Match,x` would otherwise splice into an always-true
        // `FinalRule`, and `DomainRegex,a,b` would bypass the
        // comma-preserving path below and truncate to `a`.
        let first_field = meow_common::RuleType::from_mihomo_name(first_field)
            .map_or(first_field, |t| t.as_str());
        if first_field == "MATCH" {
            return Err(format!(
                "'{entry}': MATCH is not allowed in a classical rule-set"
            ));
        }
        // Classical rules have no target column. Every byte after the first
        // comma belongs to the regex, including repetition bounds and
        // commas — same for the two process regex types (issue #974), all
        // built through the shared matcher constructors.
        if matches!(
            first_field,
            "DOMAIN-REGEX" | "PROCESS-NAME-REGEX" | "PROCESS-PATH-REGEX"
        ) {
            // This path bypasses parse_rule, but must retain its input bound
            // before allocating or compiling an untrusted provider expression.
            let max_len = crate::parser::MAX_RULE_LINE_LEN;
            if entry.len() > max_len {
                return Err(format!("rule line exceeds {max_len} bytes"));
            }
            let pattern = entry.split_once(',').map_or("", |(_, tail)| tail.trim());
            if pattern.is_empty() {
                return Err(format!("'{entry}': missing payload"));
            }
            const PH: &str = crate::parser::LOGIC_INNER_PLACEHOLDER;
            let rule: Box<dyn Rule> = match first_field {
                "DOMAIN-REGEX" => Box::new(
                    crate::domain_regex::DomainRegexRule::new(pattern, PH)
                        .map_err(|error| format!("'{entry}': invalid regex: {error}"))?,
                ),
                "PROCESS-NAME-REGEX" => Box::new(
                    crate::process_pattern::ProcessPatternRule::new_regex(
                        meow_common::RuleType::ProcessNameRegex,
                        pattern,
                        PH,
                    )
                    .map_err(|error| format!("'{entry}': {error}"))?,
                ),
                "PROCESS-PATH-REGEX" => Box::new(
                    crate::process_pattern::ProcessPatternRule::new_regex(
                        meow_common::RuleType::ProcessPathRegex,
                        pattern,
                        PH,
                    )
                    .map_err(|error| format!("'{entry}': {error}"))?,
                ),
                _ => unreachable!("first_field was matched above"),
            };
            self.rules.push(rule);
            return Ok(());
        }
        // An empty or missing payload silently degrades to match-all for
        // the substring-match types (`DOMAIN-SUFFIX,` → ends_with(""),
        // `DOMAIN-KEYWORD,` → contains("") — same as `FinalRule`). Same
        // class as MATCH — reject loudly (Class B, ADR-0002).
        if fields.next().map_or("", str::trim).is_empty() {
            return Err(format!("'{entry}': missing payload"));
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
        ClassicalRuleSet::from_rules(self.rules)
    }
}

impl RuleSet for ClassicalRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::Classical
    }

    fn matches(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        let matches =
            |rules: &[Box<dyn Rule>]| rules.iter().any(|r| r.match_metadata(metadata, helper));
        matches(&self.head)
            || self
                .runs
                .iter()
                .any(|run| run.domains.contains(metadata.rule_host()) || matches(&run.following))
    }

    fn len(&self) -> usize {
        self.count
    }

    fn should_resolve_ip(&self) -> bool {
        // Dead rules can never fire — their metadata demands must not
        // leak into the aggregate (#625).
        self.remaining_rules()
            .any(|rule| !rule.never_matches() && rule.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.remaining_rules()
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
        self.matches(&metadata, &RuleMatchHelper)
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

        // A classical regex has no target column: preserve the entire tail
        // rather than truncating it to a different expression.
        let set = ClassicalRuleSet::from_entries(
            &[
                "DOMAIN-REGEX,a,b".to_string(),
                "DOMAIN-SUFFIX,ok.example".to_string(),
            ],
            &ParserContext::empty(),
        );
        assert_eq!(set.len(), 2);
        assert!(set.matches(&meta_host("a,b"), &helper()));
        assert!(!set.matches(&meta_host("a"), &helper()));
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
    fn classical_regex_preserves_comma_payloads() {
        for (pattern, yes, no) in [
            (
                r"^api[0-9]{1,3}\.example$",
                "api123.example",
                "api1234.example",
            ),
            (r"^a,b\.example$", "a,b.example", "a.example"),
            (r",example$", "a,example", "aexample"),
            (
                r"^node[0-9]{2,}\.example$",
                "node123.example",
                "node1.example",
            ),
        ] {
            let ctx = ParserContext::empty();
            let mut builder = ClassicalRuleSetBuilder::new(&ctx);
            builder
                .push_checked(&format!("DOMAIN-REGEX,{pattern}"))
                .unwrap();
            let set = builder.build();
            assert_eq!(set.len(), 1);
            assert!(set.matches(&meta_host(yes), &helper()), "{pattern}");
            assert!(!set.matches(&meta_host(no), &helper()), "{pattern}");
        }

        // The mihomo API spelling must hit the same path — `DomainRegex`
        // would otherwise splice and truncate `a,b` to `a`.
        let ctx = ParserContext::empty();
        let mut builder = ClassicalRuleSetBuilder::new(&ctx);
        builder.push_checked("DomainRegex,a,b").unwrap();
        let set = builder.build();
        assert!(set.matches(&meta_host("a,b"), &helper()));
        assert!(!set.matches(&meta_host("a"), &helper()));
    }

    /// The process regex types are comma-protected in classical payloads
    /// too (issue #974): every byte after the first comma is the pattern —
    /// a classical entry carries no target column.
    #[test]
    fn classical_process_regex_preserves_commas() {
        let meta_proc = |name: &str| Metadata {
            process: name.into(),
            ..Default::default()
        };
        let ctx = ParserContext::empty();
        let mut builder = ClassicalRuleSetBuilder::new(&ctx);
        builder
            .push_checked("PROCESS-NAME-REGEX,^fo{1,3}$")
            .unwrap();
        builder.push_checked("PROCESS-NAME-REGEX,a,b").unwrap();
        builder
            .push_checked("ProcessPathRegex,^/opt/x,y/bin$")
            .unwrap();
        let set = builder.build();
        assert_eq!(set.len(), 3);
        assert!(set.matches(&meta_proc("foo"), &helper()));
        assert!(!set.matches(&meta_proc("foooo"), &helper()));
        assert!(set.matches(&meta_proc("a,b"), &helper()));
        assert!(!set.matches(&meta_proc("a"), &helper()));
        let meta_path = |p: &str| Metadata {
            process_path: p.into(),
            ..Default::default()
        };
        assert!(set.matches(&meta_path("/opt/x,y/bin"), &helper()));

        // Wildcard types take the ordinary splice path — `?`/`*` keep
        // working with the placeholder target.
        let mut builder = ClassicalRuleSetBuilder::new(&ctx);
        builder.push_checked("PROCESS-NAME-WILDCARD,Cu?l*").unwrap();
        let set = builder.build();
        assert!(set.matches(&meta_proc("CURL.EXE"), &helper()));
        assert!(!set.matches(&meta_proc("mycurl"), &helper()));

        // An invalid process regex surfaces the same error class as
        // DOMAIN-REGEX.
        let mut builder = ClassicalRuleSetBuilder::new(&ctx);
        for entry in [
            "PROCESS-NAME-REGEX",
            "PROCESS-NAME-REGEX,",
            "PROCESS-NAME-REGEX,[",
            "PROCESS-PATH-REGEX,a{3,2}",
        ] {
            assert!(builder.push_checked(entry).is_err(), "{entry}");
        }
    }

    #[test]
    fn classical_mihomo_spelling_still_rejects_match() {
        // `Match` normalizes to MATCH through `from_mihomo_name` — without
        // the normalized guard it would splice into an always-true
        // `FinalRule` and make the provider match every connection.
        let ctx = ParserContext::empty();
        let mut builder = ClassicalRuleSetBuilder::new(&ctx);
        assert!(builder.push_checked("Match,DIRECT").is_err());
        assert_eq!(builder.build().len(), 0);
    }

    #[test]
    fn classical_regex_enforces_rule_line_byte_limit() {
        let ctx = ParserContext::empty();
        let mut builder = ClassicalRuleSetBuilder::new(&ctx);
        // Extended-mode comments make length-boundary fixtures cheap to compile.
        let prefix = "DOMAIN-REGEX,(?x)^ok$#";
        let at_limit = format!("{prefix}{}", "a".repeat(64 * 1024 - prefix.len()));
        builder.push_checked(&at_limit).unwrap();
        for suffix in ["a", "é"] {
            let error = builder
                .push_checked(&format!("{at_limit}{suffix}"))
                .unwrap_err();
            assert_eq!(error, "rule line exceeds 65536 bytes");
        }
        let set = builder.build();
        assert_eq!(set.len(), 1);
        assert!(set.matches(&meta_host("ok"), &helper()));
        assert!(!set.matches(&meta_host("no"), &helper()));
    }

    #[test]
    fn classical_regex_rejects_empty_and_malformed_payloads() {
        let ctx = ParserContext::empty();
        let mut builder = ClassicalRuleSetBuilder::new(&ctx);
        for entry in [
            "DOMAIN-REGEX",
            "DOMAIN-REGEX,",
            "DOMAIN-REGEX,  ",
            "DOMAIN-REGEX,[",
            "DOMAIN-REGEX,a{3,2}",
        ] {
            assert!(builder.push_checked(entry).is_err(), "{entry}");
        }
        assert_eq!(builder.build().len(), 0);
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

        let set = ClassicalRuleSet::from_rules(vec![
            dead_geoip,
            dead_and,
            Box::new(DomainSuffixRule::new("example.com", "")),
        ]);
        assert!(!set.should_resolve_ip());
        assert!(!set.should_find_process());
    }

    #[test]
    fn indexed_classical_runs_match_the_ordered_rules() {
        let ctx = ParserContext::empty();
        let mut entries = (0..96)
            .map(|i| format!("DOMAIN-SUFFIX,s{i}.test"))
            .collect::<Vec<_>>();
        entries.extend(
            [
                "DOMAIN,Exact.Test",
                "DOMAIN-SUFFIX,*.literal.test",
                "DOMAIN,É.test",
                "DOMAIN-SUFFIX,.odd.test",
                "OR,((DOMAIN,compound.test),(DOMAIN,x.test))",
                "DST-PORT,443",
            ]
            .map(String::from),
        );
        entries.extend((0..96).map(|i| format!("DOMAIN,e{i}.test")));
        entries.push("DOMAIN,e0.test".into());
        let mut builder = ClassicalRuleSetBuilder::new(&ctx);
        for entry in &entries {
            builder.push_checked(entry).unwrap();
        }
        let reference = builder.rules;
        let set = ClassicalRuleSet::from_entries(&entries, &ctx);
        assert_eq!(set.len(), entries.len());
        assert_eq!(set.runs.len(), 2);
        for host in [
            "S95.TeSt.",
            "sub.s95.test",
            "nots95.test",
            "Exact.Test",
            "sub.exact.test",
            "*.literal.test",
            "a.literal.test",
            "a..odd.test",
            "é.test",
            "É.test",
            "compound.test",
            "e0.test",
            "e95.test",
            "miss.test",
            "",
            ".",
        ] {
            let mut m = Metadata {
                host: host.into(),
                ..Default::default()
            };
            let expected = |m: &Metadata| {
                reference
                    .iter()
                    .any(|r| r.match_metadata(m, &RuleMatchHelper))
            };
            assert_eq!(set.matches_domain(host), expected(&m), "{host}");
            m.sniff_host = "unknown.test".into();
            assert_eq!(set.matches(&m, &RuleMatchHelper), expected(&m), "{host}");
            m.dst_port = 443;
            assert_eq!(set.matches(&m, &RuleMatchHelper), expected(&m));
        }
    }

    #[test]
    fn indexed_domains_respect_long_names_and_label_boundaries() {
        let ctx = ParserContext::empty();
        // Leave the very first exact rule on the ordered fast path.
        let mut entries: Vec<_> = (0..64).map(|i| format!("DOMAIN,r{i}.example")).collect();
        let max = "a".repeat(LiteralDomains::MAX_KEY);
        let long = "x".repeat(LiteralDomains::MAX_KEY + 1);
        entries.extend([
            format!("DOMAIN-SUFFIX,{max}"),
            "DOMAIN,exact.example".into(),
            "DOMAIN-SUFFIX,bar.example".into(),
            format!("DOMAIN-SUFFIX,{long}"),
            "IP-CIDR,192.0.2.0/24".into(),
        ]);
        let set = ClassicalRuleSet::from_entries(&entries, &ctx);
        assert!(set.should_resolve_ip());
        assert!(!set.should_find_process());
        for (host, want) in [
            (
                format!("{}.{}", "é".repeat(200), max.to_ascii_uppercase()),
                true,
            ),
            (format!("p{max}"), false),
            (format!("{long}.EXACT.example"), false),
            (format!("{long}.BAR.example"), true),
            (format!("deep.{long}"), true),
            (format!("p{long}"), false),
        ] {
            assert_eq!(set.matches_domain(&host), want);
            let meta = Metadata {
                host: "ignored.example".into(),
                sniff_host: host.into(),
                ..Default::default()
            };
            assert_eq!(set.matches(&meta, &RuleMatchHelper), want);
        }
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

    /// Legacy zstd frames report by name at both mrs entry points: a
    /// legacy *payload* inside an `MRS!` container, and a whole-file
    /// legacy stream that fails the `ZSTD_MAGIC` dispatch.
    #[test]
    fn mrs_legacy_zstd_reports_by_name() {
        use crate::mrs_parser::{MRS_MAGIC, MRS_VERSION, TYPE_DOMAIN};
        let ctx = ParserContext::default();

        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(&MRS_MAGIC);
        wrapped.push(MRS_VERSION);
        wrapped.push(TYPE_DOMAIN);
        wrapped.extend_from_slice(&1u32.to_be_bytes());
        wrapped.extend_from_slice(&[0x26, 0xB5, 0x2F, 0xFD]); // v0.6 frame magic
        wrapped.extend_from_slice(b"garbage");
        let Err(err) = build_rule_set_from_mrs_with_behavior(&wrapped, &ctx, None, false) else {
            panic!("legacy payload must not parse");
        };
        assert!(err.contains("legacy zstd frame (v0.6"), "unexpected: {err}");

        let mut whole_file = Vec::from([0x24, 0xB5, 0x2F, 0xFD]); // v0.4 frame magic
        whole_file.extend_from_slice(b"garbage");
        assert!(is_mrs_bytes(&whole_file));
        let Err(err) = build_rule_set_from_mrs_with_behavior(&whole_file, &ctx, None, false) else {
            panic!("whole-file legacy stream must not parse");
        };
        assert!(err.contains("legacy zstd frame (v0.4"), "unexpected: {err}");
    }
}
