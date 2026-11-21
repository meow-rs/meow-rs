//! Parse the top-level `sub-rules:` YAML section into resolved
//! `Arc<Vec<Box<dyn Rule>>>` blocks keyed by block name.
//!
//! Ordering constraint: `sub-rules:` is parsed before `rules:` so that any
//! `SUB-RULE,<name>` entry in `rules:` can reference an already-resolved
//! block. Forward references from one sub-rule block to another are handled
//! by cycle detection + topological parse order.
//!
//! upstream references:
//! - `rules/logic/logic.go::matchSubRules` (lines 179–190)
//! - `rules/parser.go::parseRule` SUB-RULE case (lines 80–81) —
//!   `target` slot stores the block name, not a fallback proxy.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use meow_common::Rule;
use meow_rules::sub_rule::{SubRuleBlock, SubRuleRule};
use meow_rules::sub_rule_cond::{parse_cond, SubRuleRef};
use meow_rules::{ParserContext, RuleSet};
use tracing::warn;

use crate::rule_parser::{domain_payload_defect, parse_one_rule_or_subrule};

/// Resolved sub-rule blocks keyed by name.
pub type SubRuleBlocks = HashMap<String, SubRuleBlock>;

/// Parse all `sub-rules:` blocks into a map of name → `Arc<Vec<Box<dyn Rule>>>`.
///
/// Performs cycle detection up-front (DFS with a recursion-stack set), then
/// parses blocks in topological order so that nested `SUB-RULE,<name>`
/// references resolve against already-built blocks.
///
/// Errors:
/// - undefined block reference (Class A per ADR-0002)
/// - cycle in the reference graph (Class A per ADR-0002)
///
/// Warns (Class B; `strict: true` promotes them to errors like `rules:`):
/// - empty block (parses successfully but always falls through at match time)
/// - dead / match-all domain rule payloads inside block bodies — the same
///   `domain_payload_defect` check `rules:` applies, which previously ran
///   on top-level lines only (issue #869)
pub fn parse_sub_rules(
    raw: &HashMap<String, Vec<String>>,
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
    strict: bool,
) -> Result<SubRuleBlocks, anyhow::Error> {
    let references = build_reference_graph(raw)?;
    let order = topo_order_with_cycle_check(raw, &references)?;

    let mut resolved: SubRuleBlocks = HashMap::new();
    for block_name in order {
        let raw_rules = raw.get(&block_name).expect("block name comes from raw map");
        if raw_rules.is_empty() {
            warn!(
                block = %block_name,
                "sub-rule block '{}' has no rules; will always fall through",
                block_name
            );
        }
        let mut rules: Vec<Box<dyn Rule>> = Vec::with_capacity(raw_rules.len());
        for line in raw_rules {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let rule = parse_one_rule_or_subrule(line, providers, ctx, &resolved)
                .map_err(|e| anyhow!("sub-rule '{block_name}': {e}"))?;
            if let Some(reason) = domain_payload_defect(rule.as_ref()) {
                let message = format!("sub-rules '{block_name}': '{line}' has {reason}");
                if strict {
                    return Err(anyhow!("{message} (strict mode)"));
                }
                warn!("{message}");
            }
            rules.push(rule);
        }
        resolved.insert(block_name, Arc::new(rules));
    }
    Ok(resolved)
}

/// Build `block_name -> Vec<referenced_block_names>` from raw YAML.
/// Validates that every `SUB-RULE` reference — plain or conditional —
/// points at a defined block. The block name is the graph edge; a
/// fourth-field fallback target never is (issue #974).
fn build_reference_graph(
    raw: &HashMap<String, Vec<String>>,
) -> Result<HashMap<String, Vec<String>>, anyhow::Error> {
    let mut graph = HashMap::new();
    for (name, lines) in raw {
        let mut refs = Vec::new();
        for line in lines {
            // A malformed reference head is a hard error here the same
            // way the body parse below treats it — block bodies have no
            // lenient arm (issue #974).
            if let Some(reference) =
                parse_sub_rule_reference(line).map_err(|e| anyhow!("sub-rule '{name}': {e}"))?
            {
                if !raw.contains_key(&reference.name) {
                    return Err(anyhow!(
                        "sub-rule block '{name}' references undefined block '{}'",
                        reference.name
                    ));
                }
                refs.push(reference.name);
            }
        }
        graph.insert(name.clone(), refs);
    }
    Ok(graph)
}

/// Extract the structured reference from a `SUB-RULE` line — the shared
/// [`meow_rules::sub_rule_cond`] grammar. `Ok(None)` for any other rule
/// type; `Err` for a malformed head; `Ok(Some)` carries the name (graph
/// edges), the `(…)` condition text and the optional fallback.
pub(crate) fn parse_sub_rule_reference(line: &str) -> Result<Option<SubRuleRef>, String> {
    meow_rules::sub_rule_cond::parse_sub_rule_reference(line)
}

/// Structural validation for a `sub-rules:` document that must commit
/// without a successful build — the `PUT /configs?force` verbatim
/// fallback (issue #974 review). Runs the exact checks the rebuild
/// performs that do not depend on environment: reference-head grammar,
/// per-block body grammar (condition leaves included), undefined-block
/// references inside bodies and from top-level `rules:`, and cycles.
///
/// Provider *availability* is environment, not shape: `providers` maps
/// each declared name to a stand-in set so a `(RULE-SET,name)` cond leaf
/// or a `RULE-SET` body line resolves its name without fetching. A
/// database-dependent leaf (GEOIP/IP-ASN) likewise only needs the
/// caller's `ctx` — the API's empty-index context keeps those leaves
/// structural rather than re-running the geo probe.
///
/// Returns the resolved blocks — a top-level `SUB-RULE,(cond),<name>`
/// line's condition only parses against the built map, so the caller
/// validating `rules:` needs it (issue #974).
pub fn check_sub_rules_shape(
    raw_rules: &[String],
    sub_rules_map: &HashMap<String, Vec<String>>,
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
) -> Result<SubRuleBlocks, anyhow::Error> {
    let resolved = parse_sub_rules(sub_rules_map, providers, ctx, false)?;
    // The top-level `rules:` → `sub-rules:` undefined-block gate the
    // rebuild applies — a verbatim commit must not persist a reference
    // the next boot hard-fails on.
    for line in raw_rules {
        if let Ok(Some(reference)) = parse_sub_rule_reference(line) {
            if !sub_rules_map.contains_key(&reference.name) {
                return Err(anyhow!(
                    "rules: SUB-RULE,{} references undefined sub-rule block",
                    reference.name
                ));
            }
        }
    }
    Ok(resolved)
}

/// DFS-based topological sort with cycle detection.  Returns the order in
/// which to build blocks so that when we build `A`, every block it
/// references is already resolved.
///
/// Cycles error out with a path like `"A -> B -> A"`.
fn topo_order_with_cycle_check(
    raw: &HashMap<String, Vec<String>>,
    graph: &HashMap<String, Vec<String>>,
) -> Result<Vec<String>, anyhow::Error> {
    #[derive(PartialEq)]
    enum State {
        Fresh,
        OnStack,
        Done,
    }
    let mut state: HashMap<String, State> = raw.keys().map(|k| (k.clone(), State::Fresh)).collect();
    let mut order: Vec<String> = Vec::with_capacity(raw.len());

    // Sort roots so the traversal order (and any error-path output) is
    // deterministic across HashMap hash seeds.
    let mut roots: Vec<String> = raw.keys().cloned().collect();
    roots.sort();

    for start in &roots {
        dfs(start, graph, &mut state, &mut Vec::new(), &mut order)?;
    }

    fn dfs(
        node: &str,
        graph: &HashMap<String, Vec<String>>,
        state: &mut HashMap<String, State>,
        path: &mut Vec<String>,
        order: &mut Vec<String>,
    ) -> Result<(), anyhow::Error> {
        match state.get(node) {
            Some(State::Done) => return Ok(()),
            Some(State::OnStack) => {
                let mut cycle = path.clone();
                cycle.push(node.to_string());
                return Err(anyhow!("sub-rule cycle detected: {}", cycle.join(" -> ")));
            }
            Some(State::Fresh) => {}
            None => {
                return Err(anyhow!(
                    "sub-rule block '{node}' not defined (internal error)"
                ));
            }
        }
        state.insert(node.to_string(), State::OnStack);
        path.push(node.to_string());
        if let Some(neighbours) = graph.get(node) {
            for next in neighbours {
                dfs(next, graph, state, path, order)?;
            }
        }
        path.pop();
        state.insert(node.to_string(), State::Done);
        order.push(node.to_string());
        Ok(())
    }

    Ok(order)
}

/// Construct a `SubRuleRule` from a resolved block reference — plain,
/// conditional, or conditional with the MEOW fourth-field fallback
/// (issue #974). The condition is fully validated here: `parse_cond`'s
/// grammar and the shared inner-leg exclusion apply identically at every
/// level the line can appear (top-level `rules:`, block bodies, API
/// dry-parse). `providers` is the scope `(RULE-SET,name)` cond leaves
/// resolve against — the same scope logic legs see.
pub fn build_sub_rule_rule(
    reference: &SubRuleRef,
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
    resolved: &SubRuleBlocks,
) -> Result<Box<dyn Rule>, String> {
    let block = resolved
        .get(&reference.name)
        .ok_or_else(|| format!("sub-rule '{}' not defined", reference.name))?;
    match &reference.cond {
        None => Ok(Box::new(SubRuleRule::new(
            &reference.name,
            Arc::clone(block),
        ))),
        Some(cond_text) => {
            let expr = parse_cond(cond_text)
                .map_err(|e| format!("SUB-RULE,{cond_text},{}: {e}", reference.name))?;
            let cond = expr.build(ctx, providers)?;
            Ok(Box::new(SubRuleRule::new_conditional(
                &reference.name,
                Arc::clone(block),
                cond,
                cond_text,
                reference.fallback.as_deref(),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(entries: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    v.iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }

    #[test]
    fn parses_sub_rule_reference_line() {
        let plain = parse_sub_rule_reference("SUB-RULE,LOCAL").unwrap().unwrap();
        assert_eq!(plain.name, "LOCAL");
        assert!(plain.cond.is_none() && plain.fallback.is_none());

        let spaced = parse_sub_rule_reference("  sub-rule , FOO  ")
            .unwrap()
            .unwrap();
        assert_eq!(spaced.name, "FOO");

        // Conditional forms: the block name is the graph edge; the
        // fourth field never is (issue #974).
        let cond = parse_sub_rule_reference("SUB-RULE,(DOMAIN-SUFFIX,x),blk,T")
            .unwrap()
            .unwrap();
        assert_eq!(cond.name, "blk");
        assert_eq!(cond.cond.as_deref(), Some("(DOMAIN-SUFFIX,x)"));
        assert_eq!(cond.fallback.as_deref(), Some("T"));

        assert!(parse_sub_rule_reference("DOMAIN,example.com,DIRECT")
            .unwrap()
            .is_none());
        assert!(parse_sub_rule_reference("").unwrap().is_none());
        assert!(parse_sub_rule_reference("# SUB-RULE,X").unwrap().is_none());
        assert!(parse_sub_rule_reference("SUB-RULE").unwrap().is_none());
        // A malformed head is an error, not a silent non-reference.
        assert!(parse_sub_rule_reference("SUB-RULE,").is_err());
        assert!(parse_sub_rule_reference("SUB-RULE,name,junk").is_err());
        assert!(parse_sub_rule_reference("SUB-RULE,(DOMAIN,x").is_err());
    }

    #[test]
    fn sub_rule_trailing_fields_rejected_inside_block_body() {
        // `a` is defined so the reference graph succeeds and the body
        // parse itself must surface the trailing-field error (fatal —
        // block bodies have no lenient arm). The malformed head errors
        // out at graph build — same hard-error outcome.
        let raw_map = raw(&[
            ("a", &["DOMAIN-SUFFIX,x.test,DIRECT"]),
            ("b", &["SUB-RULE,a,junk"]),
        ]);
        let providers = HashMap::new();
        let err = parse_sub_rules(&raw_map, &providers, &ParserContext::default(), false)
            .err()
            .expect("SUB-RULE,a,junk inside a block body must fail");
        assert!(
            err.to_string().contains("trailing"),
            "unexpected error: {err}"
        );
    }

    /// Issue #974 — a conditional reference's *name* is the graph edge;
    /// the fallback target never is, and forward references are allowed.
    #[test]
    fn conditional_reference_edges_and_forward_refs() {
        let raw_map = raw(&[
            ("b", &["SUB-RULE,(DOMAIN,x),fwd,T", "DOMAIN,y,DIRECT"]),
            (
                "fwd",
                &["SUB-RULE,(DOMAIN,j),leaf,REJECT", "DOMAIN,z,DIRECT"],
            ),
            ("leaf", &["DOMAIN,w,DIRECT"]),
        ]);
        // `fwd` is referenced before its declaration — allowed. The
        // fallback names `T`/`REJECT` are targets, not edges, so no
        // "undefined block" error may fire on them.
        let providers = HashMap::new();
        let resolved = parse_sub_rules(&raw_map, &providers, &ParserContext::default(), false)
            .expect("conditional references with fallback must resolve");
        assert_eq!(resolved.len(), 3);

        // A cond pointing at an undefined block still hard-errors.
        let bad = raw(&[("a", &["SUB-RULE,(DOMAIN,x),missing,T"])]);
        let err = parse_sub_rules(&bad, &providers, &ParserContext::default(), false)
            .err()
            .expect("conditional reference to undefined block must fail");
        assert!(err.to_string().contains("missing"), "{err}");

        // A cycle through conditional edges is still a cycle.
        let cyc = raw(&[
            ("a", &["SUB-RULE,(DOMAIN,x),b"]),
            ("b", &["SUB-RULE,(DOMAIN,y),a,T"]),
        ]);
        let err = parse_sub_rules(&cyc, &providers, &ParserContext::default(), false)
            .err()
            .expect("conditional cycle must fail");
        assert!(err.to_string().contains("cycle"), "{err}");
    }

    /// Dead and match-all domain payloads inside a block body are flagged
    /// by the same `domain_payload_defect` pass `rules:` uses (issue
    /// #869): lenient keeps the block and warns, strict fails the load.
    #[test]
    fn domain_payload_defects_inside_block_warn_lenient_error_strict() {
        use crate::test_support::WarnCapture;
        let providers = HashMap::new();
        for (line, needle) in [
            ("DOMAIN,x.com.,DIRECT", "dead domain payload"),
            ("DOMAIN-KEYWORD,,DIRECT", "matches every flow"),
        ] {
            let raw_map = raw(&[("a", &[line])]);
            let cap = WarnCapture::start();
            let block = parse_sub_rules(&raw_map, &providers, &ParserContext::default(), false)
                .expect("lenient mode keeps the defective payload");
            let warns = cap.take();
            assert_eq!(block["a"].len(), 1, "{line}");
            assert!(
                warns.contains(needle) && warns.contains("sub-rules 'a'"),
                "{line}: the lenient warning must name the defect and block, got: {warns}"
            );
            let err = parse_sub_rules(&raw_map, &providers, &ParserContext::default(), true)
                .err()
                .unwrap_or_else(|| panic!("strict mode must reject {line:?}"));
            assert!(
                err.to_string().contains(needle) && err.to_string().contains("sub-rules 'a'"),
                "{line}: unexpected error {err}"
            );
        }
    }

    #[test]
    fn topo_order_handles_diamond() {
        // A -> B, A -> C, B -> D, C -> D (not a cycle, just a diamond).
        let raw_map = raw(&[
            ("A", &["SUB-RULE,B", "SUB-RULE,C"]),
            ("B", &["SUB-RULE,D"]),
            ("C", &["SUB-RULE,D"]),
            ("D", &["DOMAIN,example.com,DIRECT"]),
        ]);
        let graph = build_reference_graph(&raw_map).unwrap();
        let order = topo_order_with_cycle_check(&raw_map, &graph).unwrap();
        // D must come before B, C; B, C before A.
        let idx = |name: &str| order.iter().position(|n| n == name).unwrap();
        assert!(idx("D") < idx("B"));
        assert!(idx("D") < idx("C"));
        assert!(idx("B") < idx("A"));
        assert!(idx("C") < idx("A"));
    }

    /// One cycle topology plus the substrings its error message must contain.
    struct CycleCase {
        label: &'static str,
        blocks: &'static [(&'static str, &'static [&'static str])],
        expected: &'static [&'static str],
    }

    #[test]
    fn cycle_detected_table() {
        let cases: &[CycleCase] = &[
            CycleCase {
                label: "two-block cycle A -> B -> A",
                blocks: &[("A", &["SUB-RULE,B"]), ("B", &["SUB-RULE,A"])],
                // Path must include both A and B.
                expected: &["cycle", "A", "B"],
            },
            CycleCase {
                label: "self reference A -> A",
                blocks: &[("A", &["SUB-RULE,A"])],
                expected: &["cycle"],
            },
            CycleCase {
                label: "three-node cycle A -> B -> C -> A",
                blocks: &[
                    ("A", &["SUB-RULE,B"]),
                    ("B", &["SUB-RULE,C"]),
                    ("C", &["SUB-RULE,A"]),
                ],
                expected: &["cycle"],
            },
        ];

        // Every case runs; failures are collected so one bad topology does not
        // hide the others.
        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let label = case.label;
            let raw_map = raw(case.blocks);
            let graph = match build_reference_graph(&raw_map) {
                Ok(graph) => graph,
                Err(err) => {
                    failures.push(format!("{label}: building reference graph failed: {err}"));
                    continue;
                }
            };
            match topo_order_with_cycle_check(&raw_map, &graph) {
                Ok(order) => {
                    failures.push(format!(
                        "{label}: expected a cycle error, got order {order:?}"
                    ));
                }
                Err(err) => {
                    let msg = format!("{err}");
                    for needle in case.expected {
                        if !msg.contains(needle) {
                            failures
                                .push(format!("{label}: error message missing {needle:?}: {msg}"));
                        }
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "cycle detection failures: {failures:#?}"
        );
    }

    #[test]
    fn undefined_block_reference_errors() {
        let raw_map = raw(&[("A", &["SUB-RULE,MISSING"])]);
        let err = build_reference_graph(&raw_map).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("MISSING"), "unexpected: {msg}");
    }
}
