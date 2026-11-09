use std::collections::HashMap;
use std::sync::Arc;

use meow_common::{Rule, RuleType};
use meow_rules::{parse_rule_flags, ParserContext, RuleSet, RuleSetRule};
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
            Ok(rule) => {
                // A domain rule payload that can never equal/match the
                // normalized `Metadata::rule_host()` it is compared
                // against is dead config — the same dead-key concept the
                // DNS-side trie surfaces flag (issue #822 shape) — and an
                // empty `DOMAIN-KEYWORD` needle is the reverse defect, a
                // silent match-all (issue #869). Lenient warns and keeps
                // the rule; strict fails the load.
                if let Some(reason) = domain_payload_defect(rule.as_ref()) {
                    let message = format!("rules: '{line}' has {reason}");
                    if strict {
                        return Err(anyhow::anyhow!("{message} (strict mode)"));
                    }
                    warn!("{message}");
                }
                rules.push(rule);
            }
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

/// Classify the domain-payload defect a parsed rule carries, if any —
/// the observability pass shared by `rules:` (above) and `sub-rules:`
/// bodies (`sub_rules_parser`). Returns the warn/error descriptor for
/// the caller's message; `None` when the payload is live or unchecked.
/// Scope per rule type (meow-rules/src/domain_key.rs):
///   DOMAIN — judged against `is_valid_host` itself (the gate every
///     `host`/`sniff_host` producer passes): an empty label (`a..b`),
///     a leading/trailing dot, alphabet-impossible bytes, or any
///     unproducible host form like all-numeric `inet_aton` spellings
///     (`DOMAIN,2130706433`);
///   DOMAIN-SUFFIX — an empty label (`a..b`), a leading/trailing dot
///     (`.x.com`, `x.com.`), or alphabet-impossible bytes — an
///     all-numeric payload stays live (`x.2130706433` ends on it);
///   DOMAIN-WILDCARD — a literal `+` (the matcher globs `*` only) or a
///     dead literal label (`*.foo.`, `a..b`);
///   DOMAIN-KEYWORD — `..` or a byte no normalized host can carry (`*`,
///     `+`, `?`, space) is dead; the empty needle is flagged apart as a
///     match-all, not dead;
///   DOMAIN-REGEX — arbitrary patterns are undecidable by inspection,
///     but the *empty* pattern is decidable: `Regex::new("")` compiles
///     to a zero-width match on every host, flagged as a match-all.
/// The *empty* payload gets its own reason on each type: for
/// DOMAIN-KEYWORD it is a total match-all (`contains("")` is always
/// true), for DOMAIN/DOMAIN-SUFFIX it still silently matches every
/// host-less flow (`rule_host()` is `""` on IP-literal destinations);
/// DOMAIN-WILDCARD's matcher early-returns on an empty host, so its
/// empty payload is genuinely dead.
/// AND/OR/NOT legs carry their own payloads through the same parser, so
/// the walk recurses into logic groups and reports the first defective
/// leg against the outer line (issue #869).
pub(crate) fn domain_payload_defect(rule: &dyn Rule) -> Option<&'static str> {
    use meow_rules::logic::{AndRule, NotRule, OrRule};
    if let Some(any) = rule.as_any() {
        if let Some(and) = any.downcast_ref::<AndRule>() {
            return and
                .sub_rules()
                .iter()
                .find_map(|leg| domain_payload_defect(leg.as_ref()));
        }
        if let Some(or) = any.downcast_ref::<OrRule>() {
            return or
                .sub_rules()
                .iter()
                .find_map(|leg| domain_payload_defect(leg.as_ref()));
        }
        if let Some(not) = any.downcast_ref::<NotRule>() {
            return domain_payload_defect(not.inner());
        }
    }
    let rule_type = rule.rule_type();
    if rule.payload().is_empty() {
        match rule_type {
            RuleType::Domain | RuleType::DomainSuffix => {
                return Some(
                    "an empty payload — `rule_host()` is empty on host-less flows, so the rule \
                     silently matches every IP-literal destination; use 'IP-CIDR' or 'MATCH' \
                     to catch those",
                );
            }
            RuleType::DomainKeyword => {
                return Some(
                    "an empty DOMAIN-KEYWORD payload — `contains(\"\")` is always true, so the \
                     rule silently matches every flow; use 'MATCH' to catch all",
                );
            }
            RuleType::DomainRegex => {
                return Some(
                    "an empty DOMAIN-REGEX payload — the zero-width pattern matches every flow; \
                     use 'MATCH' to catch all",
                );
            }
            // DOMAIN-WILDCARD's matcher early-returns on an empty host,
            // so its empty payload falls through to the dead check below;
            // other types carry no domain payload at all.
            _ => {}
        }
    }
    let dead = match rule_type {
        RuleType::Domain => meow_rules::domain_exact_payload_is_dead(rule.payload()),
        RuleType::DomainSuffix => meow_rules::domain_rule_payload_is_dead(rule.payload()),
        RuleType::DomainWildcard => meow_rules::domain_wildcard_payload_is_dead(rule.payload()),
        RuleType::DomainKeyword => meow_rules::domain_keyword_payload_is_dead(rule.payload()),
        _ => false,
    };
    dead.then_some("a dead domain payload — it can never match a normalized host")
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
        // `SUB-RULE,<name>` takes exactly one field. A further comma field
        // — upstream's unsupported `SUB-RULE,(cond),name` conditional form,
        // or a typo'd `SUB-RULE,name,junk` — used to be silently dropped,
        // which routes by a different block than the author wrote (#625).
        let rest = line
            .split_once(',')
            .map(|(_, r)| r)
            .unwrap_or_default()
            .trim();
        if rest.contains(',') {
            return Err(format!(
                "SUB-RULE takes exactly <block-name> — trailing fields are \
                 not supported: '{line}'"
            ));
        }
        return build_sub_rule_rule(&block_name, sub_rules);
    }
    // Providers reach `RULE-SET` inside AND/OR/NOT groups too (mihomo parity).
    meow_rules::parse_rule_with_rule_sets(line, ctx, providers)
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

    // `,src` on a domain-behavior set is a no-op upstream — the warn lives
    // in `RuleSetRule::new` so the logic-group path in meow-rules'
    // `parse_rule_depth` flags it identically.
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

    /// Issue #625 — `SUB-RULE,<name>` takes exactly one field: a third
    /// comma field (a typo, or upstream's unsupported `(cond)` conditional
    /// form) must be rejected, not silently dropped onto the first field.
    /// A silent drop would route by a different block than written.
    #[test]
    fn sub_rule_rejects_trailing_fields() {
        use crate::sub_rules_parser::SubRuleBlocks;
        let providers = providers();
        let sub_rules: SubRuleBlocks = HashMap::from([("blk".to_string(), Arc::new(Vec::new()))]);

        let ok = parse_one_rule_or_subrule(
            "SUB-RULE,blk",
            &providers,
            &ParserContext::default(),
            &sub_rules,
        );
        assert!(ok.is_ok(), "plain SUB-RULE,blk must parse");

        for line in [
            "SUB-RULE,blk,junk",
            "SUB-RULE,(DOMAIN,a),blk",
            "SUB-RULE,blk,",
        ] {
            let err =
                parse_one_rule_or_subrule(line, &providers, &ParserContext::default(), &sub_rules)
                    .err()
                    .expect("trailing comma fields must be rejected");
            assert!(
                err.contains("trailing fields"),
                "{line}: unexpected error {err}"
            );
        }
    }

    /// Dead domain payloads can never equal/match the normalized
    /// `rule_host()` they are compared against: an empty label, a
    /// leading/trailing dot, an all-dots/prefix-only body, a
    /// verbatim-dead `*`/`+` spelling on `DOMAIN`/`DOMAIN-SUFFIX`, a
    /// literal `+` or dead literal label on `DOMAIN-WILDCARD`, or `..`
    /// on `DOMAIN-KEYWORD`. Lenient warns and keeps the rule;
    /// `strict: true` fails the load.
    #[test]
    fn dead_domain_rule_payload_warns_lenient_errors_strict() {
        use crate::test_support::WarnCapture;
        let ctx = ParserContext::default();
        for line in [
            "DOMAIN,a..b,REJECT",
            "DOMAIN-SUFFIX,a..b,REJECT",
            "DOMAIN,x.com.,REJECT",
            "DOMAIN-SUFFIX,x.com.,REJECT",
            "DOMAIN,.,REJECT",
            // `*`/`+` are verbatim-dead spellings on these rule types —
            // no normalized host carries either byte — and so is a
            // leading dot (no host leads with `.` or contains `..`).
            "DOMAIN,*.x.com,REJECT",
            "DOMAIN-SUFFIX,+.x.com,REJECT",
            "DOMAIN,a.*.b,REJECT",
            "DOMAIN-SUFFIX,.x.com,REJECT",
            "DOMAIN,.x.com,REJECT",
            // And any other byte the `is_valid_host` alphabet can never
            // produce — `?`, `@`, space, non-ASCII (issue #869).
            "DOMAIN,a?b,REJECT",
            "DOMAIN-SUFFIX,a@b,REJECT",
            "DOMAIN,bücher.example,REJECT",
            // `DOMAIN` compares verbatim, so its oracle is `is_valid_host`
            // itself: all-numeric non-IP spellings (`inet_aton` forms) are
            // hosts no listener ever produces, while `10.0.0.1`/`0x...`
            // stay live (IP-literal arm / letter-bearing names).
            "DOMAIN,2130706433,REJECT",
            "DOMAIN,0177.0.0.1,REJECT",
            "DOMAIN,123.456,REJECT",
            // DOMAIN-WILDCARD: dead literal labels (`*` segments are
            // globs and never count), and any literal byte no host
            // carries — the matcher has no `?`/`+` glob, so those are
            // literal dead bytes; an empty payload is genuinely dead too
            // (the matcher early-returns on an empty host).
            "DOMAIN-WILDCARD,*.foo.,REJECT",
            "DOMAIN-WILDCARD,a..b,REJECT",
            "DOMAIN-WILDCARD,foo.,REJECT",
            "DOMAIN-WILDCARD,+.wild.example,REJECT",
            "DOMAIN-WILDCARD,a?b,REJECT",
            "DOMAIN-WILDCARD,,REJECT",
            // DOMAIN-KEYWORD: `..` can never appear in a host, and neither
            // can any byte outside the `is_valid_host` alphabet — `*`,
            // `+`, `?`, space, `/` (issue #869).
            "DOMAIN-KEYWORD,a..b,REJECT",
            "DOMAIN-KEYWORD,x+y,REJECT",
            "DOMAIN-KEYWORD,foo?bar,REJECT",
            "DOMAIN-KEYWORD,foo*bar,REJECT",
            "DOMAIN-KEYWORD,a/b,REJECT",
        ] {
            let raw = vec![line.to_string()];
            let cap = WarnCapture::start();
            let rules = parse_rules(&raw, &ctx, false).expect("lenient mode keeps the dead rule");
            let warns = cap.take();
            assert_eq!(rules.len(), 1, "{line}: lenient mode must keep the rule");
            assert!(
                warns.contains("dead domain payload") && warns.contains(line),
                "{line}: the dead payload must be surfaced, got: {warns}"
            );
            let err = parse_rules(&raw, &ctx, true)
                .err()
                .expect("strict mode must reject a dead domain payload");
            assert!(
                err.to_string().contains("dead domain payload"),
                "{line}: unexpected error {err}"
            );
        }
    }

    /// An empty `DOMAIN`/`DOMAIN-SUFFIX` payload is not dead either:
    /// `rule_host()` is `""` on host-less flows and `"" == ""`, so the
    /// rule silently matches every IP-literal destination — a host-less
    /// match-all, reported with its own reason rather than the dead-key
    /// message (issue #869).
    #[test]
    fn empty_domain_rule_payload_warns_host_less_match_lenient_errors_strict() {
        use crate::test_support::WarnCapture;
        let ctx = ParserContext::default();
        for (line, needle) in [
            ("DOMAIN,,REJECT", "IP-literal"),
            ("DOMAIN-SUFFIX,,REJECT", "IP-literal"),
            // `DOMAIN-REGEX,,X` compiles `Regex::new("")` — a zero-width
            // pattern that matches every host, host-less flows included.
            // The defect is decidable here even though arbitrary regexes
            // are not.
            ("DOMAIN-REGEX,,REJECT", "matches every flow"),
        ] {
            let raw = vec![line.to_string()];
            let cap = WarnCapture::start();
            let rules = parse_rules(&raw, &ctx, false).expect("lenient mode keeps the rule");
            let warns = cap.take();
            assert_eq!(rules.len(), 1, "{line}: lenient mode must keep the rule");
            assert!(
                warns.contains(needle) && warns.contains(line),
                "{line}: the match-all defect must be surfaced, got: {warns}"
            );
            assert!(
                parse_rules(&raw, &ctx, true).is_err(),
                "{line}: strict mode must reject the empty payload"
            );
        }
    }

    /// An empty `DOMAIN-KEYWORD` needle is the reverse defect — not dead
    /// but a silent match-all (`contains("")` is always true, so the rule
    /// swallows every flow, host-less IP flows included, and short-
    /// circuits every rule below it). It gets its own warning naming the
    /// catch-all, not the dead-payload one (issue #869).
    #[test]
    fn empty_domain_keyword_payload_warns_match_all_lenient_errors_strict() {
        use crate::test_support::WarnCapture;
        let ctx = ParserContext::default();
        let raw = vec!["DOMAIN-KEYWORD,,REJECT".to_string()];
        let cap = WarnCapture::start();
        let rules = parse_rules(&raw, &ctx, false).expect("lenient mode keeps the rule");
        let warns = cap.take();
        assert_eq!(rules.len(), 1, "lenient mode must keep the rule");
        assert!(
            warns.contains("matches every flow") && warns.contains("DOMAIN-KEYWORD,,REJECT"),
            "the silent match-all must be surfaced, got: {warns}"
        );
        let err = parse_rules(&raw, &ctx, true)
            .err()
            .expect("strict mode must reject the empty keyword");
        assert!(
            err.to_string().contains("matches every flow"),
            "unexpected error {err}"
        );
    }

    /// The payload check recurses into AND/OR/NOT legs — a defective
    /// domain payload nested inside a logic group draws the same
    /// verdict as a top-level line, reported against the outer line
    /// (issue #869).
    #[test]
    fn dead_domain_payload_inside_logic_group_warns_lenient_errors_strict() {
        use crate::test_support::WarnCapture;
        let ctx = ParserContext::default();
        for line in [
            "AND,((DOMAIN,x.com.,DIRECT),(DST-PORT,9090)),REJECT",
            "OR,((DOMAIN-KEYWORD,x+y,DIRECT),(DST-PORT,443)),REJECT",
            "NOT,((DOMAIN,a..b,DIRECT)),REJECT",
            // A defective leg two levels deep — and not in first place —
            // still surfaces.
            "AND,((OR,((DOMAIN,.x.com,DIRECT),(NETWORK,tcp))),(DST-PORT,80)),REJECT",
            "AND,((DST-PORT,9090),(DOMAIN-KEYWORD,a/b,DIRECT)),REJECT",
        ] {
            let raw = vec![line.to_string()];
            let cap = WarnCapture::start();
            let rules = parse_rules(&raw, &ctx, false).expect("lenient mode keeps the group");
            let warns = cap.take();
            assert_eq!(rules.len(), 1, "{line}: the group must still load");
            assert!(
                warns.contains("dead domain payload") && warns.contains(line),
                "{line}: the nested defect must be surfaced, got: {warns}"
            );
            assert!(
                parse_rules(&raw, &ctx, true).is_err(),
                "{line}: strict mode must reject the nested defect"
            );
        }
    }

    /// The payload check must not false-positive: legal payloads on every
    /// domain rule type load in strict mode without a warning —
    /// including `DOMAIN-WILDCARD`'s glob segments (but not `+.`, which
    /// the matcher treats as a literal), a `DOMAIN-KEYWORD` needle that
    /// ends or leads with a dot (substring match still hits `foo.bar`),
    /// and non-empty `DOMAIN-REGEX` payloads, whose reachability the
    /// check does not attempt to decide.
    #[test]
    fn live_domain_rule_payloads_load_in_strict_mode() {
        let ctx = ParserContext::default();
        let raw = vec![
            "DOMAIN,x.com,REJECT".to_string(),
            "DOMAIN-SUFFIX,example.com,PROXY".to_string(),
            "DOMAIN-WILDCARD,*.wild.example,DIRECT".to_string(),
            "DOMAIN-WILDCARD,a.*.b,DIRECT".to_string(),
            "DOMAIN-KEYWORD,foo.,DIRECT".to_string(),
            "DOMAIN-KEYWORD,.foo,DIRECT".to_string(),
            "DOMAIN-REGEX,^a\\.\\.b$,DIRECT".to_string(),
            "DOMAIN-REGEX,x.*$,DIRECT".to_string(),
            // The host-alphabet carve-outs stay live: IPv6-literal rule
            // hosts legitimately carry `:`, `[`, `]`, and labels carry
            // `_`/`xn--`.
            "DOMAIN,::1,REJECT".to_string(),
            "DOMAIN,[::1],REJECT".to_string(),
            "DOMAIN,_dmarc.example,REJECT".to_string(),
            "DOMAIN,xn--nxasmq6b.example,REJECT".to_string(),
            "DOMAIN-SUFFIX,3.4.5.6,REJECT".to_string(),
            // IP-shaped and all-numeric payloads the exact/suffix oracles
            // must keep live: `DOMAIN,ip` matches IP-literal flows,
            // `0x7f000001` is a letter-bearing name a client can send,
            // and an all-numeric suffix can still end a mixed host
            // (`x.2130706433`).
            "DOMAIN,10.0.0.1,REJECT".to_string(),
            "DOMAIN,0x7f000001,REJECT".to_string(),
            "DOMAIN-SUFFIX,2130706433,REJECT".to_string(),
            "DOMAIN-SUFFIX,0.0.1,REJECT".to_string(),
        ];
        let rules = parse_rules(&raw, &ctx, true).expect("live payloads must load");
        assert_eq!(rules.len(), 17);
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

    /// mihomo parity: `RULE-SET` resolves inside `AND`/`OR`/`NOT` groups
    /// (a router front end routes UDP with `AND,((NETWORK,udp),(RULE-SET,x)),ProxyUDP`).
    #[test]
    fn rule_set_inside_logic_groups() {
        let providers = providers();
        let parse = |line: &str| {
            parse_one_rule_or_subrule(line, &providers, &ParserContext::default(), &HashMap::new())
        };
        let and = parse("AND,((NETWORK,udp),(RULE-SET,ips)),ProxyUDP").expect("AND must parse");
        let mut meta = Metadata {
            network: meow_common::Network::Udp,
            dst_ip: Some("192.0.2.7".parse().unwrap()),
            ..Metadata::default()
        };
        assert!(and.match_metadata(&meta, &meow_common::RuleMatchHelper));
        meta.network = meow_common::Network::Tcp;
        assert!(!and.match_metadata(&meta, &meow_common::RuleMatchHelper));

        let not = parse("NOT,((RULE-SET,doms)),DIRECT").expect("NOT must parse");
        let meta = Metadata {
            host: "example.com".into(),
            ..Metadata::default()
        };
        assert!(!not.match_metadata(&meta, &meow_common::RuleMatchHelper));

        let err = parse("OR,((RULE-SET,nope),(NETWORK,udp)),X")
            .err()
            .expect("an unknown provider inside a group must be an error");
        assert!(err.contains("unknown rule-provider 'nope'"), "{err}");
    }
}
