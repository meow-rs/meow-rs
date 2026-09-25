use std::collections::HashMap;
use std::sync::Arc;

use meow_common::Rule;
use meow_rules::{parse_rule_flags, ParserContext, RuleSet, RuleSetBehavior, RuleSetRule};
use tracing::warn;

use crate::sub_rules_parser::{build_sub_rule_rule, parse_sub_rule_reference, SubRuleBlocks};

/// Parse rules with no rule-providers or sub-rule blocks available.
///
/// `strict` (top-level `strict: true`, issue #533) promotes an unparseable
/// rule from warn-and-skip to a hard error.
pub fn parse_rules(
    raw_rules: &[String],
    ctx: &ParserContext,
    strict: bool,
) -> Result<Vec<Box<dyn Rule>>, anyhow::Error> {
    parse_rules_with_providers(raw_rules, &HashMap::new(), ctx, strict)
}

/// Parse the `rules:` block, resolving `RULE-SET,<name>,...` entries against
/// the supplied provider map and delegating everything else to the core
/// `meow_rules::parse_rule`. Sub-rule blocks default to empty.
pub fn parse_rules_with_providers(
    raw_rules: &[String],
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
    strict: bool,
) -> Result<Vec<Box<dyn Rule>>, anyhow::Error> {
    parse_rules_full(raw_rules, providers, ctx, &HashMap::new(), strict)
}

/// Parse the `rules:` block with full resolver context — providers, ctx,
/// and pre-resolved sub-rule blocks for `SUB-RULE,<name>` entries.
///
/// `strict` (top-level `strict: true`, issue #533) promotes an unparseable
/// rule from warn-and-skip to a hard config error.
pub fn parse_rules_full(
    raw_rules: &[String],
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
    sub_rules: &SubRuleBlocks,
    strict: bool,
) -> Result<Vec<Box<dyn Rule>>, anyhow::Error> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    for line in raw_rules {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_one_rule_or_subrule(line, providers, ctx, sub_rules) {
            Ok(rule) => rules.push(rule),
            Err(e) if strict => {
                return Err(anyhow::anyhow!(
                    "rules: failed to parse '{line}' (strict mode): {e}"
                ));
            }
            Err(e) => warn!("Failed to parse rule '{}': {}", line, e),
        }
    }
    Ok(rules)
}

/// Parse a single rule line. Handles `RULE-SET,<name>,...`,
/// `SUB-RULE,<name>`, and delegates everything else to the core
/// `meow_rules::parse_rule`.
pub fn parse_one_rule_or_subrule(
    line: &str,
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
    sub_rules: &SubRuleBlocks,
) -> Result<Box<dyn Rule>, String> {
    if let Some(result) = try_parse_rule_set(line, providers) {
        return result;
    }
    if let Some(block_name) = parse_sub_rule_reference(line) {
        return build_sub_rule_rule(&block_name, sub_rules);
    }
    meow_rules::parse_rule(line, ctx)
}

/// Returns `Some(...)` only when `line` is a RULE-SET entry; `None` means
/// "not a RULE-SET, keep going down the parser chain".
fn try_parse_rule_set(
    line: &str,
    providers: &HashMap<String, Arc<dyn RuleSet>>,
) -> Option<Result<Box<dyn Rule>, String>> {
    let parts: Vec<&str> = line.splitn(4, ',').map(str::trim).collect();
    if parts.first().copied() != Some("RULE-SET") {
        return None;
    }
    if parts.len() < 3 {
        return Some(Err("RULE-SET needs <name>,<adapter>".into()));
    }
    let name = parts[1];
    let adapter = parts[2];
    let flags = parse_rule_flags(parts.get(3).copied());

    let Some(set) = providers.get(name) else {
        return Some(Err(format!("unknown rule-provider '{name}'")));
    };

    // Upstream marks `,src` as meaningful only for `ipcidr` providers: on a
    // `domain` set the src/dst swap is a no-op (the match reads the host),
    // so a ported `RULE-SET,<domain-set>,...,src` would silently never do
    // what the author intended — flag it instead of ignoring it (Class B,
    // ADR-0002).
    if flags.is_src && set.behavior() == RuleSetBehavior::Domain {
        warn!(
            "RULE-SET,{name},{adapter},src: `src` has no effect on a \
             domain-behavior rule-provider (it is meaningful only for \
             ipcidr/classical behavior)"
        );
    }

    Some(Ok(Box::new(RuleSetRule::new(
        name,
        Arc::clone(set),
        adapter,
        flags,
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::Metadata;
    use meow_rules::{build_rule_set, RuleSetBehavior};

    fn providers() -> HashMap<String, Arc<dyn RuleSet>> {
        let mut map = HashMap::new();
        let ips: Arc<dyn RuleSet> = Arc::from(build_rule_set(
            RuleSetBehavior::IpCidr,
            &["192.0.2.0/24".to_string()],
            &ParserContext::default(),
        ));
        map.insert("ips".to_string(), ips);
        let doms: Arc<dyn RuleSet> = Arc::from(build_rule_set(
            RuleSetBehavior::Domain,
            &["example.com".to_string()],
            &ParserContext::default(),
        ));
        map.insert("doms".to_string(), doms);
        map
    }

    /// `RULE-SET,...,src` (issue #625 item 11, upstream `isSrc`): the set
    /// evaluates the *source* tuple. Previously the flag parsed fine but
    /// matching still read `dst_ip` — a silent misroute for ported
    /// configs.
    #[test]
    fn rule_set_src_flag_matches_source_ip() {
        let providers = providers();
        let rule = parse_one_rule_or_subrule(
            "RULE-SET,ips,PROXY,src",
            &providers,
            &ParserContext::default(),
            &HashMap::new(),
        )
        .expect("RULE-SET,src must parse");

        let mut meta = Metadata {
            src_ip: Some("192.0.2.7".parse().unwrap()),
            dst_ip: Some("203.0.113.9".parse().unwrap()),
            ..Metadata::default()
        };
        assert!(rule.match_metadata(&meta, &meow_common::RuleMatchHelper));

        // Same addresses on the opposite axes must NOT match.
        meta.src_ip = Some("203.0.113.9".parse().unwrap());
        meta.dst_ip = Some("192.0.2.7".parse().unwrap());
        assert!(!rule.match_metadata(&meta, &meow_common::RuleMatchHelper));

        // `src` implies `no-resolve`: a source-axis set must not demand a
        // dst_ip resolution it never uses.
        assert!(!rule.should_resolve_ip());
    }

    /// Both trailing flags together parse — `no-resolve,src` is the
    /// upstream-style list.
    #[test]
    fn rule_set_src_and_no_resolve_flags_combine() {
        let providers = providers();
        let rule = parse_one_rule_or_subrule(
            "RULE-SET,ips,PROXY,no-resolve,src",
            &providers,
            &ParserContext::default(),
            &HashMap::new(),
        )
        .expect("combined flags must parse");
        let meta = Metadata {
            src_ip: Some("192.0.2.1".parse().unwrap()),
            ..Metadata::default()
        };
        assert!(rule.match_metadata(&meta, &meow_common::RuleMatchHelper));
    }

    /// Without `,src` the set still matches `dst_ip` (unchanged axis).
    #[test]
    fn rule_set_without_src_matches_dst_ip() {
        let providers = providers();
        let rule = parse_one_rule_or_subrule(
            "RULE-SET,ips,PROXY,no-resolve",
            &providers,
            &ParserContext::default(),
            &HashMap::new(),
        )
        .expect("RULE-SET must parse");
        let meta = Metadata {
            dst_ip: Some("192.0.2.7".parse().unwrap()),
            ..Metadata::default()
        };
        assert!(rule.match_metadata(&meta, &meow_common::RuleMatchHelper));
        // `no-resolve` honoured: no dst_ip resolution demand.
        assert!(!rule.should_resolve_ip());
    }

    /// `,src` on a domain-behavior provider is a warn-level no-op (the
    /// swap leaves the host untouched), not a parse error.
    #[test]
    fn rule_set_src_on_domain_provider_still_parses() {
        let providers = providers();
        let rule = parse_one_rule_or_subrule(
            "RULE-SET,doms,PROXY,src",
            &providers,
            &ParserContext::default(),
            &HashMap::new(),
        )
        .expect("src on a domain set parses (warned, not fatal)");
        let meta = Metadata {
            host: "example.com".into(),
            ..Metadata::default()
        };
        assert!(rule.match_metadata(&meta, &meow_common::RuleMatchHelper));
    }

    /// `,src` on a classical provider swaps the whole tuple: inner IP rules
    /// see `src_ip`, inner `DST-PORT` sees `src_port`, inner `DOMAIN` still
    /// sees the (unswapped) destination host — upstream `SwapSrcDst`.
    #[test]
    fn rule_set_src_flag_swaps_tuple_for_classical_provider() {
        let mut providers = HashMap::new();
        let classical: Arc<dyn RuleSet> = Arc::from(build_rule_set(
            RuleSetBehavior::Classical,
            &[
                "IP-CIDR,10.0.0.0/8".to_string(),
                "DST-PORT,8080".to_string(),
                "DOMAIN,foo.example".to_string(),
            ],
            &ParserContext::default(),
        ));
        providers.insert("cls".to_string(), classical);

        let rule = parse_one_rule_or_subrule(
            "RULE-SET,cls,PROXY,src",
            &providers,
            &ParserContext::default(),
            &HashMap::new(),
        )
        .expect("RULE-SET,src on a classical set must parse");

        // Inner IP-CIDR sees the source address.
        let meta = Metadata {
            src_ip: Some("10.1.2.3".parse().unwrap()),
            dst_ip: Some("203.0.113.9".parse().unwrap()),
            ..Metadata::default()
        };
        assert!(rule.match_metadata(&meta, &meow_common::RuleMatchHelper));

        // Inner DST-PORT sees the source port after the swap.
        let meta = Metadata {
            src_port: 8080,
            dst_port: 443,
            ..Metadata::default()
        };
        assert!(rule.match_metadata(&meta, &meow_common::RuleMatchHelper));
        // …and the real destination port does not satisfy it.
        let meta = Metadata {
            src_port: 443,
            dst_port: 8080,
            ..Metadata::default()
        };
        assert!(!rule.match_metadata(&meta, &meow_common::RuleMatchHelper));

        // Inner DOMAIN still reads the destination host (not swapped).
        let meta = Metadata {
            host: "foo.example".into(),
            ..Metadata::default()
        };
        assert!(rule.match_metadata(&meta, &meow_common::RuleMatchHelper));
    }

    /// A classical provider's `AND`/`OR`/`NOT` entries parse instead of
    /// being warn-dropped: the placeholder adapter must be appended after
    /// the parenthesised payload, not spliced mid-line (#625 review).
    #[test]
    fn classical_provider_parses_logic_entries() {
        let set = build_rule_set(
            RuleSetBehavior::Classical,
            &[
                "AND,((DOMAIN,and.example),(DST-PORT,9090))".to_string(),
                "NOT,((DOMAIN,blocked.example))".to_string(),
            ],
            &ParserContext::default(),
        );
        // Both entries must have survived — a warn-dropped entry shrinks
        // the set (an `any()` sibling can't tell entries apart).
        assert_eq!(set.len(), 2);
        let meta = Metadata {
            host: "and.example".into(),
            dst_port: 9090,
            ..Metadata::default()
        };
        assert!(set.matches(&meta, &meow_common::RuleMatchHelper));
        let meta = Metadata {
            host: "blocked.example".into(),
            ..Metadata::default()
        };
        assert!(!set.matches(&meta, &meow_common::RuleMatchHelper));

        // Prove the AND legs actually evaluate: a matching host with the
        // wrong port must not satisfy it on its own.
        let and_only = build_rule_set(
            RuleSetBehavior::Classical,
            &["AND,((DOMAIN,and.example),(DST-PORT,9090))".to_string()],
            &ParserContext::default(),
        );
        let meta = Metadata {
            host: "and.example".into(),
            dst_port: 80,
            ..Metadata::default()
        };
        assert!(!and_only.matches(&meta, &meow_common::RuleMatchHelper));
    }
}
