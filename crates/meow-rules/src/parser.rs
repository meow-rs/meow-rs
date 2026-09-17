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

pub fn parse_rule(line: &str, ctx: &ParserContext) -> Result<Box<dyn Rule>, String> {
    // Logic rules (AND/OR/NOT) must be detected before the naive `splitn(4, ',')`
    // below, because their payloads contain parenthesised sub-rules whose
    // commas would be split incorrectly.
    if let Some((ty, rest)) = split_once_trimmed(line, ',') {
        let upper = ty.to_ascii_uppercase();
        if matches!(upper.as_str(), "AND" | "OR" | "NOT") {
            return parse_logic_rule(&upper, rest, ctx);
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
            let no_resolve = extra.is_some_and(|e| e.eq_ignore_ascii_case("no-resolve"));
            IpCidrRule::new(payload, adapter, false, no_resolve)
                .map(|r| Box::new(r) as Box<dyn Rule>)
                .map_err(|e| format!("invalid CIDR: {e}"))
        }
        "SRC-IP-CIDR" => {
            let no_resolve = extra.is_some_and(|e| e.eq_ignore_ascii_case("no-resolve"));
            IpCidrRule::new(payload, adapter, true, no_resolve)
                .map(|r| Box::new(r) as Box<dyn Rule>)
                .map_err(|e| format!("invalid CIDR: {e}"))
        }
        "SRC-PORT" => PortRule::new(payload, adapter, true).map(|r| Box::new(r) as Box<dyn Rule>),
        "DST-PORT" => PortRule::new(payload, adapter, false).map(|r| Box::new(r) as Box<dyn Rule>),
        "NETWORK" => NetworkRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>),
        "PROCESS-NAME" => Ok(Box::new(ProcessRule::new(payload, adapter))),
        "GEOIP" => {
            let index = ctx.geoip.as_ref().ok_or_else(|| {
                "GEOIP rule requires a GeoIP database, but none is configured".to_string()
            })?;
            let no_resolve = extra.is_some_and(|e| e.eq_ignore_ascii_case("no-resolve"));
            let ranges = index.ranges_for(payload);
            Ok(Box::new(GeoIpRule::new(
                payload, adapter, no_resolve, ranges,
            )))
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
            let no_resolve = extra.is_some_and(|e| e.eq_ignore_ascii_case("no-resolve"));
            Ok(Box::new(GeoSiteRule::new(
                payload,
                adapter,
                ctx.geosite.clone(),
                no_resolve,
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
            let no_resolve = extra.is_some_and(|e| e.eq_ignore_ascii_case("no-resolve"));
            IpSuffixRule::new(payload, adapter, false, no_resolve)
                .map(|r| Box::new(r) as Box<dyn Rule>)
        }
        "SRC-IP-SUFFIX" => {
            let no_resolve = extra.is_some_and(|e| e.eq_ignore_ascii_case("no-resolve"));
            IpSuffixRule::new(payload, adapter, true, no_resolve)
                .map(|r| Box::new(r) as Box<dyn Rule>)
        }
        "IP-ASN" => {
            let index = ctx.asn.clone().ok_or_else(|| {
                "IP-ASN rule requires an ASN database (GeoLite2-ASN.mmdb); drop the file at \
                 $XDG_CONFIG_HOME/meow/GeoLite2-ASN.mmdb, $HOME/.config/meow/GeoLite2-ASN.mmdb, \
                 or ./meow/GeoLite2-ASN.mmdb"
                    .to_string()
            })?;
            let asn = parse_asn_payload(payload)?;
            let no_resolve = extra.is_some_and(|e| e.eq_ignore_ascii_case("no-resolve"));
            let ranges = index.ranges_for(asn);
            Ok(Box::new(IpAsnRule::new(
                asn, payload, adapter, ranges, false, no_resolve,
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
) -> Result<Box<dyn Rule>, String> {
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
    let adapter = tail
        .strip_prefix(',')
        .ok_or_else(|| format!("{rule_type} rule: expected ',ADAPTER' after payload"))?
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
        let patched = splice_inner_adapter(g.trim());
        inner_rules.push(parse_rule(&patched, ctx)?);
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
    use meow_common::{Metadata, RuleMatchHelper};

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

    /// G2 — parser honours the no-resolve flag.
    #[test]
    fn test_parse_geosite_no_resolve_flag() {
        let rule = parse_rule("GEOSITE,cn,DIRECT,no-resolve", &ctx()).unwrap();
        assert!(!rule.should_resolve_ip());
        let rule = parse_rule("GEOSITE,cn,DIRECT", &ctx()).unwrap();
        assert!(rule.should_resolve_ip());
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
}
