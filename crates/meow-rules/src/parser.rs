use std::sync::Arc;

use meow_common::Rule;

use crate::asn_index::AsnIndex;
use crate::country_index::CountryIndex;
use crate::domain::DomainRule;
use crate::domain_keyword::DomainKeywordRule;
use crate::domain_regex::DomainRegexRule;
use crate::domain_suffix::DomainSuffixRule;
use crate::domain_wildcard::DomainWildcardRule;
use crate::dscp::DscpRule;
use crate::final_rule::FinalRule;
use crate::geoip::GeoIpRule;
use crate::geosite::GeositeDB;
use crate::geosite_rule::GeoSiteRule;
use crate::in_name::InNameRule;
use crate::in_port::InPortRule;
use crate::in_type::InTypeRule;
use crate::in_user::InUserRule;
use crate::ip_asn::IpAsnRule;
use crate::ip_suffix::IpSuffixRule;
use crate::ipcidr::IpCidrRule;
use crate::logic::{AndRule, NotRule, OrRule};
use crate::network::NetworkRule;
use crate::port::PortRule;
use crate::process::ProcessRule;
use crate::process_path::ProcessPathRule;
use crate::src_geoip::SrcGeoIpRule;
use crate::uid::UidRule;

/// Shared context for `parse_rule` — carries resources that context-requiring
/// rule types (GEOIP, SRC-GEOIP, IP-ASN, GEOSITE) need in order to build
/// themselves. Callers that don't use any such rule types can pass
/// [`ParserContext::empty`].
#[derive(Clone, Default)]
pub struct ParserContext {
    /// Optional GeoIP country index — built once from the MMDB at config
    /// load (see [`CountryIndex::build`]) and shared across all GEOIP /
    /// SRC-GEOIP rules built through this context. `None` means those rules
    /// will parse-fail with a "no GeoIP database configured" error. The
    /// MMDB Reader itself is dropped after the index is built; per-rule
    /// matching is one binary search over a shared `IpRangeSet`, not an
    /// MMDB lookup.
    pub geoip: Option<Arc<CountryIndex>>,
    /// Optional GeoLite2-ASN range index for `IP-ASN` rules. `None` triggers
    /// a parse-time hard-error on any `IP-ASN` payload — silent skipping would
    /// misroute ASN-gated traffic (Class A per ADR-0002). The MMDB Reader
    /// itself is dropped after the index is built; per-rule matching is one
    /// binary search over a shared `IpRangeSet`, not an MMDB lookup.
    pub asn: Option<Arc<AsnIndex>>,
    /// Optional geosite database for `GEOSITE` rules. Unlike GEOIP/ASN,
    /// absence does NOT hard-error at parse time — per spec §Divergences
    /// #3, GEOSITE tolerates an absent DB (always-no-match) so that configs
    /// which conditionally load the DB still parse cleanly. A warn is
    /// emitted by the loader's discovery path, not here.
    pub geosite: Option<Arc<GeositeDB>>,
}

impl std::fmt::Debug for ParserContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParserContext")
            .field("geoip", &self.geoip.is_some())
            .field("asn", &self.asn.is_some())
            .field("geosite", &self.geosite.is_some())
            .finish()
    }
}

impl ParserContext {
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Bounds for rule-line parsing. Rule text reaches this parser from remote
/// surfaces (subscriptions, rule-provider payloads): a line like
/// `AND,((AND,((…` recurses one stack frame per nesting level and copies
/// the inner text per level, so an unbounded line overflows the stack and
/// amplifies transient allocation (issue #533 review).
const MAX_LOGIC_DEPTH: usize = 64;
const MAX_RULE_LINE_LEN: usize = 64 * 1024;

pub fn parse_rule(line: &str, ctx: &ParserContext) -> Result<Box<dyn Rule>, String> {
    parse_rule_depth(line, ctx, 0)
}

fn parse_rule_depth(
    line: &str,
    ctx: &ParserContext,
    logic_depth: usize,
) -> Result<Box<dyn Rule>, String> {
    if line.len() > MAX_RULE_LINE_LEN {
        return Err(format!("rule line exceeds {MAX_RULE_LINE_LEN} bytes"));
    }
    // Logic rules (AND/OR/NOT) must be detected before the naive `splitn(4, ',')`
    // below, because their payloads contain parenthesised sub-rules whose
    // commas would be split incorrectly.
    if let Some((ty, rest)) = split_once_trimmed(line, ',') {
        let upper = ty.to_ascii_uppercase();
        if matches!(upper.as_str(), "AND" | "OR" | "NOT") {
            return parse_logic_rule(&upper, rest, ctx, logic_depth);
        }
    }

    let parts: Vec<&str> = line.splitn(4, ',').collect();
    if parts.len() < 2 {
        return Err(format!("invalid rule: {line}"));
    }

    let rule_type = parts[0].trim();

    // MATCH only needs adapter
    if rule_type == "MATCH" {
        let adapter = parts.get(1).unwrap_or(&"DIRECT").trim();
        return Ok(Box::new(FinalRule::new(adapter)));
    }

    if parts.len() < 3 {
        return Err(format!("rule needs at least 3 parts: {line}"));
    }

    let payload = parts[1].trim();
    let adapter = parts[2].trim();
    let extra = parts.get(3).map(|s| s.trim());

    match rule_type {
        "DOMAIN" => Ok(Box::new(DomainRule::new(payload, adapter))),
        "DOMAIN-SUFFIX" => Ok(Box::new(DomainSuffixRule::new(payload, adapter))),
        "DOMAIN-KEYWORD" => Ok(Box::new(DomainKeywordRule::new(payload, adapter))),
        "DOMAIN-REGEX" => DomainRegexRule::new(payload, adapter)
            .map(|r| Box::new(r) as Box<dyn Rule>)
            .map_err(|e| format!("invalid regex: {e}")),
        "IP-CIDR" | "IP-CIDR6" => {
            // Trailing `,src` (upstream `ParseParams`) makes the rule
            // source-axis, matching `SRC-IP-CIDR`.
            let flags = parse_rule_flags(extra);
            IpCidrRule::new(payload, adapter, flags.is_src, flags.no_resolve)
                .map(|r| Box::new(r) as Box<dyn Rule>)
                .map_err(|e| format!("invalid CIDR: {e}"))
        }
        "SRC-IP-CIDR" => IpCidrRule::new(payload, adapter, true, true)
            .map(|r| Box::new(r) as Box<dyn Rule>)
            .map_err(|e| format!("invalid CIDR: {e}")),
        "SRC-PORT" => PortRule::new(payload, adapter, true).map(|r| Box::new(r) as Box<dyn Rule>),
        "DST-PORT" => PortRule::new(payload, adapter, false).map(|r| Box::new(r) as Box<dyn Rule>),
        "NETWORK" => NetworkRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>),
        "PROCESS-NAME" => Ok(Box::new(ProcessRule::new(payload, adapter))),
        "GEOIP" => {
            let index = ctx.geoip.as_ref().ok_or_else(|| {
                "GEOIP rule requires a GeoIP database, but none is configured".to_string()
            })?;
            let flags = parse_rule_flags(extra);
            let ranges = index.ranges_for(payload);
            if flags.is_src {
                // Upstream parity: `GEOIP,...,src` is a `SRC-GEOIP` rule.
                Ok(Box::new(SrcGeoIpRule::new(payload, adapter, ranges)))
            } else {
                Ok(Box::new(GeoIpRule::new(
                    payload,
                    adapter,
                    flags.no_resolve,
                    ranges,
                )))
            }
        }
        "SRC-GEOIP" => {
            let index = ctx.geoip.as_ref().ok_or_else(|| {
                "SRC-GEOIP rule requires a GeoIP database, but none is configured".to_string()
            })?;
            let ranges = index.ranges_for(payload);
            Ok(Box::new(SrcGeoIpRule::new(payload, adapter, ranges)))
        }
        "GEOSITE" => {
            let category = payload.split('@').next().unwrap_or("").trim();
            if category.is_empty() {
                return Err("GEOSITE rule requires a category name".to_string());
            }
            // `no-resolve` (extra) is accepted but vestigial — GEOSITE
            // matches domains only and never demands resolution (#625).
            Ok(Box::new(GeoSiteRule::new(
                payload,
                adapter,
                ctx.geosite.clone(),
            )))
        }
        "IN-PORT" => InPortRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>),
        "IN-NAME" => InNameRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>),
        "IN-TYPE" => InTypeRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>),
        "IN-USER" => InUserRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>),
        "DSCP" => DscpRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>),
        "UID" => UidRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>),
        "PROCESS-PATH" => {
            ProcessPathRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>)
        }
        "DOMAIN-WILDCARD" => {
            DomainWildcardRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>)
        }
        "IP-SUFFIX" => {
            let flags = parse_rule_flags(extra);
            IpSuffixRule::new(payload, adapter, flags.is_src, flags.no_resolve)
                .map(|r| Box::new(r) as Box<dyn Rule>)
        }
        "SRC-IP-SUFFIX" => {
            IpSuffixRule::new(payload, adapter, true, true).map(|r| Box::new(r) as Box<dyn Rule>)
        }
        "IP-ASN" => {
            let index = ctx.asn.clone().ok_or_else(|| {
                "IP-ASN rule requires an ASN database (GeoLite2-ASN.mmdb); drop the file at \
                 $XDG_CONFIG_HOME/meow/GeoLite2-ASN.mmdb, $HOME/.config/meow/GeoLite2-ASN.mmdb, \
                 or ./meow/GeoLite2-ASN.mmdb"
                    .to_string()
            })?;
            let asn = parse_asn_payload(payload)?;
            let flags = parse_rule_flags(extra);
            let ranges = index.ranges_for(asn);
            Ok(Box::new(IpAsnRule::new(
                asn,
                payload,
                adapter,
                ranges,
                flags.is_src,
                flags.no_resolve,
            )))
        }
        "SRC-IP-ASN" => {
            let index = ctx.asn.clone().ok_or_else(|| {
                "SRC-IP-ASN rule requires an ASN database (GeoLite2-ASN.mmdb); drop the file at \
                 $XDG_CONFIG_HOME/meow/GeoLite2-ASN.mmdb, $HOME/.config/meow/GeoLite2-ASN.mmdb, \
                 or ./meow/GeoLite2-ASN.mmdb"
                    .to_string()
            })?;
            let asn = parse_asn_payload(payload)?;
            let ranges = index.ranges_for(asn);
            Ok(Box::new(IpAsnRule::new(
                asn, payload, adapter, ranges, true, true,
            )))
        }
        _ => Err(format!("unknown rule type: {rule_type}")),
    }
}

fn parse_asn_payload(payload: &str) -> Result<u32, String> {
    payload
        .trim()
        .parse()
        .map_err(|e| format!("invalid IP-ASN value '{}': {}", payload.trim(), e))
}

/// Parsed trailing flags of a rule (`no-resolve`, `src`). Named fields so
/// call sites can't swap the two same-typed bools.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuleFlags {
    /// `no-resolve`: never demand destination-IP resolution for this rule.
    pub no_resolve: bool,
    /// `src`: match against the source tuple instead of the destination
    /// tuple. Implies `no_resolve` — a source-axis match never needs the
    /// destination resolved (upstream `ParseParams` does the same fold).
    pub is_src: bool,
}

/// Parse the trailing flag list of a rule — the `extra` field may itself be
/// comma-separated (`IP-CIDR,x,DIRECT,no-resolve,src`). Mirrors upstream
/// `rules/common.ParseParams`.
///
/// Unknown flags are ignored — upstream does the same for params a rule
/// type does not consume. Flag names compare case-insensitively, a
/// deliberate superset of upstream's exact-match parsing, consistent with
/// the pre-existing `no-resolve` handling here.
pub fn parse_rule_flags(extra: Option<&str>) -> RuleFlags {
    let mut flags = RuleFlags::default();
    if let Some(extra) = extra {
        for flag in extra.split(',').map(str::trim) {
            if flag.eq_ignore_ascii_case("no-resolve") {
                flags.no_resolve = true;
            } else if flag.eq_ignore_ascii_case("src") {
                flags.is_src = true;
            }
        }
    }
    flags.no_resolve |= flags.is_src;
    flags
}

fn split_once_trimmed(s: &str, sep: char) -> Option<(&str, &str)> {
    s.split_once(sep).map(|(l, r)| (l.trim(), r.trim_start()))
}

/// Parse `AND,((r1),(r2),...),ADAPTER` / `OR,(...)`, / `NOT,((r1)),ADAPTER`.
/// `rule_type` is already upper-cased; `rest` is the line content after the
/// leading `TYPE,`.
fn parse_logic_rule(
    rule_type: &str,
    rest: &str,
    ctx: &ParserContext,
    logic_depth: usize,
) -> Result<Box<dyn Rule>, String> {
    if logic_depth >= MAX_LOGIC_DEPTH {
        return Err(format!(
            "{rule_type} rule: nesting exceeds {MAX_LOGIC_DEPTH} levels"
        ));
    }
    let rest = rest.trim_start();
    if !rest.starts_with('(') {
        return Err(format!(
            "{rule_type} rule: expected '(' after rule type, got: {rest}"
        ));
    }
    // Find the matching ')' for the outer group-list parenthesis.
    let mut depth: i32 = 0;
    let mut end: Option<usize> = None;
    for (i, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end.ok_or_else(|| format!("{rule_type} rule: unbalanced parentheses"))?;
    let inner = &rest[1..end];
    let tail = rest[end + 1..].trim_start();
    // Upstream `ParseRulePayload` takes the *last* comma field as the
    // adapter on logic types (middle fields join the ignored payload
    // region). `next_back()` mirrors that exactly: `...,Proxy,src` targets
    // "src" — upstream fails the adapter lookup at config load, we warn
    // and skip at match (issue #513 continue-on-missing) — and
    // `...,src,Proxy` resolves `Proxy` like upstream. A first-field pick
    // would route the same line differently.
    let adapter = tail
        .strip_prefix(',')
        .ok_or_else(|| format!("{rule_type} rule: expected ',ADAPTER' after payload"))?
        .split(',')
        .next_back()
        .unwrap_or("")
        .trim();
    if adapter.is_empty() {
        return Err(format!("{rule_type} rule: missing adapter"));
    }

    let groups = split_logic_groups(inner).map_err(|e| format!("{rule_type} rule: {e}"))?;
    if groups.is_empty() {
        return Err(format!("{rule_type} rule: empty payload"));
    }

    let mut inner_rules: Vec<Box<dyn Rule>> = Vec::with_capacity(groups.len());
    for g in &groups {
        // Upstream `payloadToRule` rejects MATCH inside logic sub-rules —
        // it would splice into an always-true `FinalRule` leg. Nested
        // groups recurse through here, so the check covers any depth.
        let mut fields = g.splitn(3, ',');
        let first = fields.next().map_or("", str::trim);
        if first == "MATCH" {
            return Err(format!(
                "{rule_type} rule: MATCH is not allowed inside logic groups"
            ));
        }
        // An empty or missing payload silently degrades to match-all for
        // the substring-match types (`DOMAIN-SUFFIX,` → ends_with(""),
        // `DOMAIN-KEYWORD,` → contains("")) — same class as MATCH.
        // Reject loudly.
        if fields.next().map_or("", str::trim).is_empty() {
            return Err(format!("{rule_type} rule: '{g}' has no payload"));
        }
        // Upstream comma-protects regex payloads (target = last field,
        // payload = everything before it); our grammar splits payload at
        // the first comma, so an inner entry with a comma in its payload
        // would silently truncate (`DOMAIN-REGEX,a,b` → regex "a").
        // Reject loudly instead.
        if first == "DOMAIN-REGEX" && fields.next().is_some() {
            return Err(format!(
                "{rule_type} rule: {first} payloads containing commas are \
                 not supported inside logic groups"
            ));
        }
        let patched = splice_inner_adapter(g.trim());
        inner_rules.push(parse_rule_depth(&patched, ctx, logic_depth + 1)?);
    }

    match rule_type {
        "AND" => Ok(Box::new(AndRule::new(inner_rules, adapter))),
        "OR" => Ok(Box::new(OrRule::new(inner_rules, adapter))),
        "NOT" => {
            if inner_rules.len() != 1 {
                return Err(format!(
                    "NOT rule requires exactly 1 inner rule, got {}",
                    inner_rules.len()
                ));
            }
            Ok(Box::new(NotRule::new(
                inner_rules.into_iter().next().unwrap(),
                adapter,
            )))
        }
        _ => unreachable!("caller upper-cased rule_type"),
    }
}

/// Split the body of a logic payload — a sequence of `(...)` groups optionally
/// separated by commas — into the string contents of each group, preserving
/// balanced parens inside.
fn split_logic_groups(inner: &str) -> Result<Vec<String>, String> {
    let mut groups = Vec::new();
    let mut chars = inner.char_indices().peekable();
    loop {
        while let Some(&(_, c)) = chars.peek() {
            if c == ' ' || c == ',' {
                chars.next();
            } else {
                break;
            }
        }
        let Some(&(_, c)) = chars.peek() else { break };
        if c != '(' {
            return Err(format!("expected '(' starting a group, got '{c}'"));
        }
        chars.next(); // consume '('
        let start = chars.peek().map_or(inner.len(), |&(i, _)| i);
        let mut depth = 1i32;
        let mut end: Option<usize> = None;
        for (i, c) in chars.by_ref() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.ok_or_else(|| "unbalanced parentheses in logic payload".to_string())?;
        groups.push(inner[start..end].to_string());
    }
    Ok(groups)
}

/// Splice a placeholder adapter into `TYPE,PAYLOAD[,extra]` so the inner rule
/// satisfies `parse_rule`'s `TYPE,PAYLOAD,ADAPTER[,extra]` shape. The owning
/// logic/rule-set wrapper carries the real adapter; the placeholder is
/// discarded at match time.
fn splice_inner_adapter(entry: &str) -> String {
    const PLACEHOLDER: &str = "LOGIC-INNER-PLACEHOLDER";
    // Logic sub-rules carry their own parenthesised payload that must not be
    // split on commas — their "adapter" slot is appended at the end.
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
    use meow_common::{Metadata, RuleMatchHelper, RuleType};

    fn noop_helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn ctx() -> ParserContext {
        ParserContext::empty()
    }

    fn make_metadata(host: &str, dst_port: u16) -> Metadata {
        Metadata {
            host: host.into(),
            dst_port,
            ..Default::default()
        }
    }

    #[test]
    fn test_parse_domain() {
        let rule = parse_rule("DOMAIN,google.com,Proxy", &ctx()).unwrap();
        let meta = make_metadata("google.com", 443);
        assert!(rule.match_metadata(&meta, &noop_helper()));
    }

    #[test]
    fn test_parse_domain_suffix() {
        let rule = parse_rule("DOMAIN-SUFFIX,google.com,Proxy", &ctx()).unwrap();
        let meta = make_metadata("www.google.com", 443);
        assert!(rule.match_metadata(&meta, &noop_helper()));
        let meta2 = make_metadata("google.com", 443);
        assert!(rule.match_metadata(&meta2, &noop_helper()));
    }

    #[test]
    fn test_parse_match() {
        let rule = parse_rule("MATCH,DIRECT", &ctx()).unwrap();
        let meta = make_metadata("anything.com", 80);
        assert!(rule.match_metadata(&meta, &noop_helper()));
    }

    #[test]
    fn test_parse_port() {
        let rule = parse_rule("DST-PORT,80,DIRECT", &ctx()).unwrap();
        let meta = make_metadata("example.com", 80);
        assert!(rule.match_metadata(&meta, &noop_helper()));
        let meta2 = make_metadata("example.com", 443);
        assert!(!rule.match_metadata(&meta2, &noop_helper()));
    }

    #[test]
    fn test_parse_ip_cidr() {
        let rule = parse_rule("IP-CIDR,192.168.1.0/24,DIRECT,no-resolve", &ctx()).unwrap();
        let mut meta = make_metadata("", 80);
        meta.dst_ip = Some("192.168.1.100".parse().unwrap());
        assert!(rule.match_metadata(&meta, &noop_helper()));
    }

    #[test]
    fn test_parse_and_rule() {
        let rule = parse_rule(
            "AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),Proxy",
            &ctx(),
        )
        .unwrap();
        assert_eq!(rule.adapter(), "Proxy");
        let hit = make_metadata("www.example.com", 443);
        let miss_port = make_metadata("www.example.com", 80);
        let miss_host = make_metadata("other.com", 443);
        assert!(rule.match_metadata(&hit, &noop_helper()));
        assert!(!rule.match_metadata(&miss_port, &noop_helper()));
        assert!(!rule.match_metadata(&miss_host, &noop_helper()));
    }

    #[test]
    fn test_parse_or_rule() {
        let rule = parse_rule("OR,((DOMAIN,a.com),(DOMAIN,b.com)),DIRECT", &ctx()).unwrap();
        assert_eq!(rule.adapter(), "DIRECT");
        assert!(rule.match_metadata(&make_metadata("a.com", 80), &noop_helper()));
        assert!(rule.match_metadata(&make_metadata("b.com", 80), &noop_helper()));
        assert!(!rule.match_metadata(&make_metadata("c.com", 80), &noop_helper()));
    }

    #[test]
    fn test_parse_not_rule() {
        let rule = parse_rule("NOT,((DOMAIN-SUFFIX,corp.example)),DIRECT", &ctx()).unwrap();
        assert_eq!(rule.adapter(), "DIRECT");
        assert!(!rule.match_metadata(&make_metadata("host.corp.example", 80), &noop_helper()));
        assert!(rule.match_metadata(&make_metadata("other.com", 80), &noop_helper()));
    }

    #[test]
    fn test_parse_logic_nested() {
        // AND containing an OR and a NOT.
        let rule = parse_rule(
            "AND,((OR,((DOMAIN,a.com),(DOMAIN,b.com))),(NOT,((DST-PORT,80)))),Proxy",
            &ctx(),
        )
        .unwrap();
        assert!(rule.match_metadata(&make_metadata("a.com", 443), &noop_helper()));
        assert!(rule.match_metadata(&make_metadata("b.com", 443), &noop_helper()));
        assert!(!rule.match_metadata(&make_metadata("a.com", 80), &noop_helper()));
        assert!(!rule.match_metadata(&make_metadata("c.com", 443), &noop_helper()));
    }

    #[test]
    fn test_parse_logic_inner_with_flag() {
        // IP-CIDR inner rule carrying its own `no-resolve` flag — splicing must
        // insert the placeholder before the flag, not after it.
        let rule = parse_rule(
            "AND,((IP-CIDR,192.168.0.0/16,no-resolve),(DST-PORT,443)),DIRECT",
            &ctx(),
        )
        .unwrap();
        let mut meta = make_metadata("", 443);
        meta.dst_ip = Some("192.168.1.5".parse().unwrap());
        assert!(rule.match_metadata(&meta, &noop_helper()));
    }

    #[test]
    fn test_parse_not_requires_single_inner() {
        let err = parse_rule("NOT,((DOMAIN,a.com),(DOMAIN,b.com)),DIRECT", &ctx())
            .err()
            .expect("NOT with multiple inner rules must error");
        assert!(err.contains("NOT"), "unexpected error: {err}");
    }

    #[test]
    fn test_parse_and_missing_adapter_errors() {
        let err = parse_rule("AND,((DOMAIN,a.com))", &ctx())
            .err()
            .expect("missing adapter must error");
        assert!(err.contains("adapter") || err.contains("ADAPTER"));
    }

    #[test]
    fn test_parse_geoip_without_reader_errors() {
        let result = parse_rule("GEOIP,CN,Proxy", &ctx());
        let Err(err) = result else {
            panic!("GEOIP parsing must error when no reader is configured");
        };
        assert!(err.contains("GEOIP"), "unexpected error: {err}");
    }

    // ─── GEOSITE (M1.D-2) ───────────────────────────────────────────

    /// G1 — parse dispatches GEOSITE to GeoSiteRule.
    #[test]
    fn test_parse_geosite_dispatches() {
        let rule = parse_rule("GEOSITE,cn,DIRECT", &ctx()).unwrap();
        assert_eq!(rule.rule_type().to_string(), "GEOSITE");
        assert_eq!(rule.adapter(), "DIRECT");
    }

    /// G2 — `no-resolve` is still accepted, but GEOSITE never demands
    /// resolution regardless (upstream parity; regression for #625).
    #[test]
    fn test_parse_geosite_no_resolve_flag() {
        let rule = parse_rule("GEOSITE,cn,DIRECT,no-resolve", &ctx()).unwrap();
        assert!(!rule.should_resolve_ip());
        let rule = parse_rule("GEOSITE,cn,DIRECT", &ctx()).unwrap();
        assert!(!rule.should_resolve_ip());
    }

    /// G3 — empty category hard-errors.
    #[test]
    fn test_parse_geosite_missing_category_errors() {
        let err = parse_rule("GEOSITE,,DIRECT", &ctx())
            .err()
            .expect("GEOSITE with empty category must error");
        assert!(err.contains("GEOSITE"), "unexpected error: {err}");
    }

    /// G4 — missing target (no adapter slot) hard-errors.
    #[test]
    fn test_parse_geosite_missing_target_errors() {
        let err = parse_rule("GEOSITE,cn", &ctx())
            .err()
            .expect("GEOSITE without target must error");
        assert!(
            err.contains("rule needs at least 3 parts"),
            "unexpected error: {err}"
        );
    }

    /// GEOSITE parses successfully without a DB (Class A divergence from
    /// upstream — upstream errors at parse; we tolerate and warn+no-match).
    /// upstream: rules/geosite.go — errors at parse if DB absent.
    /// NOT a parse error here.
    #[test]
    fn test_parse_geosite_without_db_tolerated() {
        assert!(parse_rule("GEOSITE,cn,DIRECT", &ctx()).is_ok());
    }

    // ─── `,src` trailing flag (issue #625 item 11; upstream
    // `rules/common.ParseParams` + `Metadata.SwapSrcDst`) ────────────────

    /// `parse_rule_flags`: `src` implies `no-resolve`; both flags may
    /// appear in either order and tolerate whitespace.
    #[test]
    fn test_parse_rule_flags() {
        let dst = |no_resolve, is_src| RuleFlags { no_resolve, is_src };
        assert_eq!(parse_rule_flags(None), dst(false, false));
        assert_eq!(parse_rule_flags(Some("no-resolve")), dst(true, false));
        assert_eq!(parse_rule_flags(Some("src")), dst(true, true));
        assert_eq!(parse_rule_flags(Some("no-resolve,src")), dst(true, true));
        assert_eq!(parse_rule_flags(Some("src, no-resolve")), dst(true, true));
        // Flag names compare case-insensitively — a deliberate superset of
        // upstream's exact match, consistent with `no-resolve` handling.
        assert_eq!(parse_rule_flags(Some("SRC")), dst(true, true));
        assert_eq!(parse_rule_flags(Some("No-Resolve")), dst(true, false));
        // Unknown flags are ignored, matching upstream param handling.
        assert_eq!(parse_rule_flags(Some("bogus")), dst(false, false));
        // A `src`-looking flag in an unknown name doesn't activate src.
        assert_eq!(parse_rule_flags(Some("src2")), dst(false, false));
    }

    /// `IP-CIDR,...,src` matches the *source* IP — a ported
    /// `IP-CIDR` config previously parsed fine but still matched `dst_ip`
    /// (#625 item 11 silent misroute).
    #[test]
    fn test_parse_ip_cidr_src_flag() {
        let rule = parse_rule("IP-CIDR,192.168.0.0/16,DIRECT,src", &ctx()).unwrap();
        let mut meta = make_metadata("example.com", 443);
        meta.src_ip = Some("192.168.1.5".parse().unwrap());
        meta.dst_ip = Some("203.0.113.1".parse().unwrap());
        assert!(rule.match_metadata(&meta, &noop_helper()));
        // The same addresses on the opposite axes must NOT match.
        meta.src_ip = Some("203.0.113.1".parse().unwrap());
        meta.dst_ip = Some("192.168.1.5".parse().unwrap());
        assert!(!rule.match_metadata(&meta, &noop_helper()));
        // `src` implies `no-resolve`: no dst resolution demand.
        assert!(!rule.should_resolve_ip());
    }

    /// `IP-SUFFIX,...,src` likewise routes onto the source axis.
    /// (IP-SUFFIX masks the *low* bits: `x.x.x.1` matches `0.0.0.1/8`.)
    #[test]
    fn test_parse_ip_suffix_src_flag() {
        let rule = parse_rule("IP-SUFFIX,0.0.0.1/8,DIRECT,src", &ctx()).unwrap();
        let mut meta = make_metadata("", 80);
        meta.src_ip = Some("192.0.2.1".parse().unwrap());
        meta.dst_ip = Some("198.51.100.2".parse().unwrap());
        assert!(rule.match_metadata(&meta, &noop_helper()));
        // The same suffix on the *destination* must not match a src rule.
        meta.src_ip = Some("198.51.100.2".parse().unwrap());
        meta.dst_ip = Some("192.0.2.1".parse().unwrap());
        assert!(!rule.match_metadata(&meta, &noop_helper()));
        assert!(!rule.should_resolve_ip());
    }

    /// Logic rules take the *last* comma field after the payload as the
    /// adapter, mirroring upstream `ParseRulePayload` (`target =
    /// item[l-1]`). A trailing `,src` must not be silently dropped —
    /// upstream would look up "src" as the adapter and fail; absorbing
    /// `Proxy,src` into one name would also dead-route the rule.
    #[test]
    fn test_parse_logic_adapter_uses_last_tail_field() {
        // `...,Proxy,src` → adapter "src", exactly like upstream: the
        // target resolves at match time as missing → warn + fall through
        // (issue #513 continue-on-missing), never silently via `Proxy`.
        let rule = parse_rule(
            "AND,((DOMAIN,and.example),(DST-PORT,443)),Proxy,src",
            &ctx(),
        )
        .unwrap();
        assert_eq!(rule.adapter(), "src");

        // Middle fields are ignored like upstream — `...,src,Proxy`
        // still resolves `Proxy` and matches.
        let rule = parse_rule(
            "AND,((DOMAIN,and.example),(DST-PORT,443)),src,Proxy",
            &ctx(),
        )
        .unwrap();
        assert_eq!(rule.adapter(), "Proxy");
        let mut meta = make_metadata("and.example", 443);
        meta.dst_ip = Some("203.0.113.1".parse().unwrap());
        assert!(rule.match_metadata(&meta, &noop_helper()));
    }

    /// A `MATCH` leg inside a logic group must be rejected (upstream
    /// `payloadToRule` parity) — it would splice into an always-true
    /// `FinalRule` leg.
    #[test]
    fn test_parse_logic_rejects_inner_match() {
        assert!(parse_rule("OR,((MATCH,x),(DOMAIN,a.example)),Proxy", &ctx()).is_err());
        // And at arbitrary nesting depth.
        assert!(parse_rule("AND,((NOT,((MATCH,x))),(DOMAIN,a.example)),Proxy", &ctx()).is_err());
        // A comma-containing DOMAIN-REGEX payload cannot be represented
        // in our grammar — reject loudly rather than silently truncating
        // to a different regex.
        assert!(parse_rule("AND,((DOMAIN-REGEX,a,b),(DOMAIN,a.example)),Proxy", &ctx()).is_err());
        // A comma-free DOMAIN-REGEX leg still parses.
        assert!(parse_rule("AND,((DOMAIN-REGEX,a+),(DOMAIN,a.example)),Proxy", &ctx()).is_ok());
        // An empty-payload leg would silently become match-all
        // (`DOMAIN-SUFFIX,` → ends_with("") is true) — reject loudly.
        assert!(parse_rule("OR,((DOMAIN-SUFFIX,),(DOMAIN,a.example)),Proxy", &ctx()).is_err());
        // Trailing comma is load-bearing: `(DOMAIN-KEYWORD,)` splices to
        // an empty keyword (match-all) without the guard, while a bare
        // `(DOMAIN-KEYWORD)` errors downstream on `< 2 parts` either way.
        assert!(parse_rule("OR,((DOMAIN-KEYWORD,),(DOMAIN,a.example)),Proxy", &ctx()).is_err());
    }

    /// `IP-CIDR6,...,src` shares the IP-CIDR arm — IPv6 source axis.
    #[test]
    fn test_parse_ip_cidr6_src_flag() {
        let rule = parse_rule("IP-CIDR6,2001:db8::/32,DIRECT,src", &ctx()).unwrap();
        let mut meta = make_metadata("", 443);
        meta.src_ip = Some("2001:db8::5".parse().unwrap());
        meta.dst_ip = Some("192.0.2.9".parse().unwrap());
        assert!(rule.match_metadata(&meta, &noop_helper()));
        meta.src_ip = Some("192.0.2.9".parse().unwrap());
        meta.dst_ip = Some("2001:db8::5".parse().unwrap());
        assert!(!rule.match_metadata(&meta, &noop_helper()));
    }

    /// A dst-axis rule must not accidentally pick up `src` — plain
    /// `IP-CIDR` still matches `dst_ip` and demands resolution.
    #[test]
    fn test_parse_ip_cidr_dst_unchanged() {
        let rule = parse_rule("IP-CIDR,192.168.0.0/16,DIRECT", &ctx()).unwrap();
        let mut meta = make_metadata("", 80);
        meta.dst_ip = Some("192.168.9.9".parse().unwrap());
        assert!(rule.match_metadata(&meta, &noop_helper()));
        assert!(rule.should_resolve_ip());
    }

    /// `GEOIP,...,src` cannot bypass the GeoIP-DB requirement — the flag is
    /// parsed after the context check, like every other GEOIP arm.
    #[test]
    fn test_parse_geoip_src_flag_still_needs_db() {
        let err = parse_rule("GEOIP,CN,Proxy,src", &ctx())
            .err()
            .expect("GEOIP,src without a DB must error");
        assert!(err.contains("GEOIP"), "unexpected error: {err}");
    }

    /// Same for `IP-ASN,...,src` — the ASN DB check precedes flag use.
    #[test]
    fn test_parse_ip_asn_src_flag_still_needs_db() {
        let err = parse_rule("IP-ASN,13335,DIRECT,src", &ctx())
            .err()
            .expect("IP-ASN,src without a DB must error");
        assert!(err.contains("IP-ASN"), "unexpected error: {err}");
    }

    /// With a (possibly empty) GeoIP index the `GEOIP,...,src` arm must
    /// dispatch to `SrcGeoIpRule`, not a dst-axis `GeoIpRule` — the
    /// miss-lookup path still exercises the dispatch.
    #[test]
    fn test_parse_geoip_src_flag_dispatches_src_rule() {
        let ctx = ParserContext {
            geoip: Some(Arc::new(CountryIndex::default())),
            ..ParserContext::empty()
        };
        let rule = parse_rule("GEOIP,CN,Proxy,src", &ctx).unwrap();
        assert_eq!(rule.rule_type(), RuleType::SrcGeoIp);
        assert!(!rule.should_resolve_ip());
        // Unknown country → empty ranges → no match, upstream parity.
        let mut meta = make_metadata("", 80);
        meta.src_ip = Some("1.2.3.4".parse().unwrap());
        assert!(!rule.match_metadata(&meta, &noop_helper()));
    }

    /// `IP-ASN,...,src` dispatches to a src-axis `IpAsnRule`.
    #[test]
    fn test_parse_ip_asn_src_flag_dispatches_src_rule() {
        let ctx = ParserContext {
            asn: Some(Arc::new(AsnIndex::default())),
            ..ParserContext::empty()
        };
        let rule = parse_rule("IP-ASN,13335,DIRECT,src", &ctx).unwrap();
        assert_eq!(rule.rule_type(), RuleType::SrcIpAsn);
        assert!(!rule.should_resolve_ip());
    }
}

#[cfg(test)]
mod depth_tests {
    use super::*;

    /// Remote rule payloads (subscriptions, provider bodies) must not be
    /// able to drive unbounded recursion or per-level copying: nesting past
    /// MAX_LOGIC_DEPTH fails the line instead of overflowing the stack
    /// (issue #533 review).
    #[test]
    fn deeply_nested_logic_rule_errors_instead_of_overflowing() {
        // Each nested level is `AND,(( <inner-rule> ))` — the inner rule
        // carries no adapter (splice_inner_adapter substitutes a
        // placeholder for logic types).
        let mut line = String::new();
        for _ in 0..200 {
            line.push_str("AND,((");
        }
        line.push_str("DOMAIN,a.com");
        for _ in 0..200 {
            line.push_str("))");
        }
        line.push_str(",DIRECT");
        let Err(err) = parse_rule(&line, &ParserContext::empty()) else {
            panic!("nesting must error");
        };
        assert!(err.contains("nesting"), "unexpected error: {err}");
    }

    /// Sane nesting still parses.
    #[test]
    fn moderately_nested_logic_rule_parses() {
        let rule = parse_rule(
            "AND,((OR,((DOMAIN,a.com),(DOMAIN,b.com))),(NOT,((DOMAIN,c.com)))),DIRECT",
            &ParserContext::empty(),
        );
        assert!(rule.is_ok(), "unexpected: {}", rule.err().unwrap());
    }

    /// A single line beyond the length cap fails fast — bounds the
    /// per-level copy cost to depth × cap (issue #533 review).
    #[test]
    fn overlong_rule_line_errors() {
        let line = format!("AND,(({})),DIRECT", "x".repeat(MAX_RULE_LINE_LEN));
        let Err(err) = parse_rule(&line, &ParserContext::empty()) else {
            panic!("overlong line must error");
        };
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }
}
