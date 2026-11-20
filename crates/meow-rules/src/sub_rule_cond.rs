//! Conditional `SUB-RULE` predicate syntax (issue #974).
//!
//! Three reference forms share one structured head parse
//! ([`parse_sub_rule_reference`]):
//!
//! ```text
//! SUB-RULE,<name>                    // plain reference (existing MEOW)
//! SUB-RULE,(<cond>),<name>           // mihomo's conditional form
//! SUB-RULE,(<cond>),<name>,<target>  // MEOW extension: exhaust fallback
//! ```
//!
//! `<cond>` is one parenthesised predicate expression whose *leaves* are
//! targetless `(TYPE,payload[,flag…])` atoms. Every rule type is a legal
//! leaf except `MATCH` and `SUB-RULE` — the same exclusion upstream's
//! `payloadToRule` applies to logic legs (`rules/logic/logic.go`), which
//! is where condition leaves build through (issue #974 review).
//! Combination is either mihomo's prefix form (`(AND,((a),(b)))`,
//! `(NOT,((a)))`) or MEOW's infix `&` `|` `!` extension (precedence
//! `!` > `&` > `|`, left-associative, parentheses override). The head
//! split and the expression grammar are deliberately separate passes so
//! the reference-graph builder can extract `<name>` without re-parsing
//! the whole condition.
//!
//! upstream: `rules/logic/logic.go::NewSubRule` wraps the payload in one
//! more paren pair and requires exactly one predicate; `rules/parser.go`
//! lines 80–81 store the block name in the target slot.

use meow_common::{Rule, RuleType};

use crate::logic::{AndRule, NotRule, OrRule};
use crate::parser::{
    matching_paren, parse_inner_leg, ParserContext, RuleSets, LOGIC_INNER_PLACEHOLDER,
};

/// Nesting budget shared with the logic-group parser (`MAX_LOGIC_DEPTH`):
/// every `(` group and `!` in the expression counts once.
const MAX_COND_DEPTH: usize = 64;

/// A parsed `SUB-RULE` line — the structured reference every consumer
/// (graph validation, geo discovery, rule build) shares.
#[derive(Debug)]
pub struct SubRuleRef {
    /// The referenced block name (case-sensitive).
    pub name: String,
    /// The balanced `(…)` condition text for the conditional forms.
    pub cond: Option<String>,
    /// MEOW's fourth field — the fallback target applied when a true
    /// condition's block exhausts without yielding one.
    pub fallback: Option<String>,
}

/// Parse a `SUB-RULE` line into its structured reference.
///
/// - `Ok(None)` — the line is not a `SUB-RULE` at all.
/// - `Ok(Some(_))` — a syntactically separable reference head: the block
///   name is valid for graph validation; `cond`/`fallback` still need
///   full validation by [`parse_cond`] and the caller's target policy.
/// - `Err(_)` — a malformed head: unclosed parens, junk between the
///   condition and the name field, extra or empty fields, a plain
///   `SUB-RULE,name,junk`.
pub fn parse_sub_rule_reference(line: &str) -> Result<Option<SubRuleRef>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let Some((ty, rest)) = line.split_once(',') else {
        return Ok(None);
    };
    let ty = ty.trim();
    if !matches!(
        meow_common::RuleType::from_mihomo_name(ty),
        Some(RuleType::SubRule)
    ) && !ty.eq_ignore_ascii_case("SUB-RULE")
    {
        return Ok(None);
    }
    if line.len() > crate::parser::MAX_RULE_LINE_LEN {
        return Err(format!(
            "rule line exceeds {} bytes",
            crate::parser::MAX_RULE_LINE_LEN
        ));
    }
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(format!("SUB-RULE requires a block name: '{line}'"));
    }
    if !rest.starts_with('(') {
        // Plain form: exactly one field.
        if rest.contains(',') {
            return Err(format!(
                "SUB-RULE takes <name> or (<cond>),<name>[,<target>] — \
                 trailing fields are not supported: '{line}'"
            ));
        }
        return Ok(Some(SubRuleRef {
            name: rest.to_string(),
            cond: None,
            fallback: None,
        }));
    }
    // Conditional form: the balanced region is the condition; the name
    // and optional fallback follow after its closing paren.
    let close = matching_paren(rest)
        .ok_or_else(|| format!("SUB-RULE: unbalanced parentheses in '{line}'"))?;
    // A single parenthesised, comma-free field is a plain block name that
    // happens to carry parens — `SUB-RULE,(local)` — not a condition (a
    // predicate always carries `<TYPE>,<payload>`). Anything with a tail
    // or an inner comma stays on the conditional grammar.
    if close == rest.len() - 1 && !rest[1..close].contains(',') {
        return Ok(Some(SubRuleRef {
            name: rest.to_string(),
            cond: None,
            fallback: None,
        }));
    }
    let cond_text = rest[..=close].to_string();
    let tail = rest[close + 1..].trim_start();
    let tail = tail
        .strip_prefix(',')
        .ok_or_else(|| format!("SUB-RULE: expected ',<name>' after the condition in '{line}'"))?;
    let fields: Vec<&str> = tail.split(',').map(str::trim).collect();
    let (name, fallback) = match fields.as_slice() {
        [name] => (*name, None),
        [name, target] => (*name, Some((*target).to_string())),
        _ => {
            return Err(format!(
                "SUB-RULE takes (<cond>),<name>[,<target>] — too many fields: '{line}'"
            ))
        }
    };
    if name.is_empty() {
        return Err(format!("SUB-RULE: empty block name in '{line}'"));
    }
    if fallback.as_deref().is_some_and(str::is_empty) {
        return Err(format!("SUB-RULE: empty fallback target in '{line}'"));
    }
    Ok(Some(SubRuleRef {
        name: name.to_string(),
        cond: Some(cond_text),
        fallback,
    }))
}

/// A leaf predicate `(TYPE,payload[,flag…])` — targetless by grammar.
/// `ty`/`payload` are the canonical type name and first payload field
/// (geo discovery keys on them); `entry` is the canonical-type inner
/// text fed to the shared leg grammar at [`CondExpr::build`].
#[derive(Debug)]
pub struct CondLeaf {
    /// Canonical rule-type name (`GEOIP`, `DOMAIN-SUFFIX`, `IP-ASN`, …).
    pub ty: String,
    /// The leaf's first payload field — `GEOIP,CN` → `CN`,
    /// `GEOSITE,cat@attr` → `cat@attr`, `IP-ASN,1234` → `1234`.
    pub payload: String,
    /// The `TYPE,payload[,param…]` text with the type normalized to
    /// `ty` — the shared leg grammar's `match` keys on the canonical
    /// spelling, so a `(domain-suffix,x)` leaf must not reach it
    /// verbatim; payload and params keep their exact bytes.
    entry: String,
}

/// The condition predicate tree. `And`/`Or`/`Not` mirror the logic-rule
/// semantics; leaves are any rule type except `MATCH`/`SUB-RULE`.
#[derive(Debug)]
pub enum CondExpr {
    Leaf(CondLeaf),
    And(Vec<CondExpr>),
    Or(Vec<CondExpr>),
    Not(Box<CondExpr>),
}

impl CondExpr {
    /// Iterate the condition's leaves — geo discovery, diagnostics.
    pub fn leaves(&self) -> Vec<&CondLeaf> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(node) = stack.pop() {
            match node {
                CondExpr::Leaf(leaf) => out.push(leaf),
                CondExpr::And(items) | CondExpr::Or(items) => {
                    stack.extend(items.iter());
                }
                CondExpr::Not(inner) => stack.push(inner.as_ref()),
            }
        }
        out
    }

    /// Lower the predicate tree into `Rule` objects sharing the logic
    /// composites. Leaves carry `LOGIC_INNER_PLACEHOLDER` adapters —
    /// the condition only gates a block scan, so its adapters never
    /// route, validate or account (issue #974). `rule_sets` resolves
    /// `(RULE-SET,name)` leaves against the candidate's declared
    /// rule-providers, the same scope a logic leg sees.
    pub fn build(
        &self,
        ctx: &ParserContext,
        rule_sets: &RuleSets,
    ) -> Result<Box<dyn Rule>, String> {
        match self {
            // Depth 0: the leaf is a flat `(TYPE,…)` — combinators were
            // already lifted into `CondExpr` nodes by the parser.
            CondExpr::Leaf(leaf) => parse_inner_leg(&leaf.entry, ctx, rule_sets, 0),
            CondExpr::And(items) => Ok(Box::new(AndRule::new(
                items
                    .iter()
                    .map(|item| item.build(ctx, rule_sets))
                    .collect::<Result<Vec<_>, _>>()?,
                LOGIC_INNER_PLACEHOLDER,
            ))),
            CondExpr::Or(items) => Ok(Box::new(OrRule::new(
                items
                    .iter()
                    .map(|item| item.build(ctx, rule_sets))
                    .collect::<Result<Vec<_>, _>>()?,
                LOGIC_INNER_PLACEHOLDER,
            ))),
            CondExpr::Not(inner) => Ok(Box::new(NotRule::new(
                inner.build(ctx, rule_sets)?,
                LOGIC_INNER_PLACEHOLDER,
            ))),
        }
    }
}

/// Parse a condition region — the balanced `(…)` text from
/// [`parse_sub_rule_reference`] — into its predicate tree. Full-input
/// consumption, the `MATCH`/`SUB-RULE` leaf exclusion, and the shared
/// depth budget all live here so every caller sees the same grammar.
pub fn parse_cond(text: &str) -> Result<CondExpr, String> {
    let mut parser = CondParser { text, pos: 0 };
    let expr = parser.parse_expr(0)?;
    parser.skip_ws();
    if parser.pos != text.len() {
        return Err(format!(
            "SUB-RULE condition: unexpected trailing text at byte {} in '{text}'",
            parser.pos
        ));
    }
    Ok(expr)
}

/// Recursive-descent condition parser over the balanced region. `pos`
/// walks bytes — every token boundary is an ASCII char, so multi-byte
/// payload text stays intact. `|`/`&`/`!` only carry operator meaning at
/// expression position; inside a leaf's `(TYPE,…)` region they are
/// payload bytes.
struct CondParser<'a> {
    text: &'a str,
    pos: usize,
}

impl CondParser<'_> {
    fn skip_ws(&mut self) {
        while self.pos < self.text.len() && self.text.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.text.as_bytes().get(self.pos).copied()
    }

    /// `or := and ('|' and)*` — iterative, so flat chains cost no stack.
    fn parse_expr(&mut self, depth: usize) -> Result<CondExpr, String> {
        let mut items = vec![self.parse_and_chain(depth)?];
        while self.peek() == Some(b'|') {
            self.pos += 1;
            if self.peek() == Some(b'|') {
                return Err("SUB-RULE condition: '||' is not an operator".to_string());
            }
            items.push(self.parse_and_chain(depth)?);
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap()
        } else {
            CondExpr::Or(items)
        })
    }

    /// `and := unary ('&' unary)*`
    fn parse_and_chain(&mut self, depth: usize) -> Result<CondExpr, String> {
        let mut items = vec![self.parse_unary(depth)?];
        while self.peek() == Some(b'&') {
            self.pos += 1;
            if self.peek() == Some(b'&') {
                return Err("SUB-RULE condition: '&&' is not an operator".to_string());
            }
            items.push(self.parse_unary(depth)?);
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap()
        } else {
            CondExpr::And(items)
        })
    }

    /// `unary := '!' unary | atom` — each `!` spends one depth level.
    fn parse_unary(&mut self, depth: usize) -> Result<CondExpr, String> {
        if self.peek() == Some(b'!') {
            if depth >= MAX_COND_DEPTH {
                return Err(format!(
                    "SUB-RULE condition: nesting exceeds {MAX_COND_DEPTH} levels"
                ));
            }
            self.pos += 1;
            return Ok(CondExpr::Not(Box::new(self.parse_unary(depth + 1)?)));
        }
        self.parse_atom(depth)
    }

    /// `atom := '(' expr ')' | predicate` — disambiguated by the inside
    /// text: `(TYPE,…)` opens a predicate, `(`/`!` opens a sub-expr.
    fn parse_atom(&mut self, depth: usize) -> Result<CondExpr, String> {
        if depth >= MAX_COND_DEPTH {
            return Err(format!(
                "SUB-RULE condition: nesting exceeds {MAX_COND_DEPTH} levels"
            ));
        }
        self.skip_ws();
        if self.peek_byte() != Some(b'(') {
            let found = self.peek_byte().map_or_else(
                || "end of input".to_string(),
                |b| format!("'{}'", b as char),
            );
            return Err(format!(
                "SUB-RULE condition: expected '(' at byte {}, got {found}",
                self.pos
            ));
        }
        let close = matching_paren(&self.text[self.pos..]).ok_or_else(|| {
            format!(
                "SUB-RULE condition: unbalanced parentheses in '{}'",
                self.text
            )
        })?;
        let inner = &self.text[self.pos + 1..self.pos + close];
        self.pos += close + 1;
        let inner_trim = inner.trim();
        if inner_trim.is_empty() {
            return Err("SUB-RULE condition: empty group '()'".to_string());
        }
        let first = inner_trim.as_bytes()[0];
        if first == b'(' || first == b'!' {
            // Parenthesised sub-expression — parse its contents as one
            // expression on the same depth budget.
            let mut sub = CondParser {
                text: inner_trim,
                pos: 0,
            };
            let expr = sub.parse_expr(depth + 1)?;
            sub.skip_ws();
            if sub.pos != inner_trim.len() {
                return Err(format!(
                    "SUB-RULE condition: unexpected text inside group '{inner_trim}'"
                ));
            }
            return Ok(expr);
        }
        self.parse_predicate(inner_trim, depth)
    }

    fn peek_byte(&mut self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    /// `(TYPE,…)` inside a predicate region: either a leaf
    /// `(LEAF,payload[,flag…])` — every type but `MATCH`/`SUB-RULE` — or a
    /// prefix combinator `(AND|OR,(items))` / `(NOT,(item))`.
    fn parse_predicate(&mut self, inner: &str, depth: usize) -> Result<CondExpr, String> {
        let Some((ty, tail)) = inner.split_once(',') else {
            return Err(format!(
                "SUB-RULE condition: expected '(TYPE,payload)', got '({inner})'"
            ));
        };
        let ty = meow_common::RuleType::from_mihomo_name(ty.trim()).map_or_else(
            || ty.trim().to_ascii_uppercase(),
            |t| t.as_str().to_string(),
        );
        match ty.as_str() {
            "AND" | "OR" | "NOT" => self.parse_prefix_group(&ty, tail.trim(), depth),
            // Upstream `payloadToRule` excludes exactly MATCH and
            // SUB-RULE at inner position; every other type builds through
            // the shared leg grammar at `CondExpr::build` (an unknown
            // type surfaces its error there).
            "MATCH" | "SUB-RULE" => Err(format!(
                "SUB-RULE condition: '{ty}' is not allowed as a condition leaf"
            )),
            _ => parse_cond_leaf(&ty, tail, inner),
        }
    }

    /// The `(items…)` tail of a prefix combinator: one parenthesised,
    /// comma-separated list of expressions.
    fn parse_prefix_group(
        &mut self,
        ty: &str,
        tail: &str,
        depth: usize,
    ) -> Result<CondExpr, String> {
        if depth >= MAX_COND_DEPTH {
            return Err(format!(
                "SUB-RULE condition: nesting exceeds {MAX_COND_DEPTH} levels"
            ));
        }
        let inner = tail
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .ok_or_else(|| {
                format!("SUB-RULE condition: '{ty}' expects a '(item,…)' group, got '{tail}'")
            })?;
        // Items split on commas at paren depth 0 — each item is a full
        // expression (predicate, `!`-unary or an infix chain).
        let items = split_group_items(inner)?;
        let mut exprs = Vec::with_capacity(items.len());
        for item in items {
            let mut sub = CondParser {
                text: item.trim(),
                pos: 0,
            };
            let expr = sub.parse_expr(depth + 1)?;
            sub.skip_ws();
            if sub.pos != item.trim().len() {
                return Err(format!(
                    "SUB-RULE condition: trailing text in '{ty}' item '{item}'"
                ));
            }
            exprs.push(expr);
        }
        match ty {
            "AND" | "OR" => Ok(if ty == "AND" {
                CondExpr::And(exprs)
            } else {
                CondExpr::Or(exprs)
            }),
            "NOT" => {
                if exprs.len() != 1 {
                    return Err(format!(
                        "SUB-RULE condition: NOT takes exactly 1 item, got {}",
                        exprs.len()
                    ));
                }
                Ok(CondExpr::Not(Box::new(exprs.pop().unwrap())))
            }
            _ => unreachable!("caller gates ty"),
        }
    }
}

/// Split a prefix group's inside text on commas at paren depth 0. Empty
/// items (`(a),`, `,(a)`, `(a),,(b)`) are an error — a missing operand.
/// `\`-escaped and `[...]`-class parens inside regex payloads never
/// count as structural, matching [`matching_paren`] — and, like it,
/// only inside regex-type groups.
fn split_group_items(inner: &str) -> Result<Vec<&str>, String> {
    use crate::parser::group_is_regex_payload;
    let mut items = Vec::new();
    let mut start = 0usize;
    // One flag per open group — whether its payload is regex expression
    // text; the stack's length is the paren depth.
    let mut stack: Vec<bool> = Vec::new();
    let mut in_class = false;
    let mut escaped = false;
    for (i, b) in inner.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        let in_regex = stack.last().copied().unwrap_or(false);
        match b {
            b'\\' if in_regex => escaped = true,
            b'[' if in_regex && !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class => stack.push(group_is_regex_payload(&inner[i + 1..])),
            b')' if !in_class => {
                stack.pop();
            }
            b',' if stack.is_empty() && !in_class => {
                let item = inner[start..i].trim();
                if item.is_empty() {
                    return Err(format!(
                        "SUB-RULE condition: empty item in group '({inner})'"
                    ));
                }
                items.push(item);
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = inner[start..].trim();
    if last.is_empty() {
        return Err(format!(
            "SUB-RULE condition: empty item in group '({inner})'"
        ));
    }
    items.push(last);
    Ok(items)
}

/// One leaf `(TYPE,payload[,flag…])` — payload non-empty. Trailing
/// params are validated by the shared leg grammar at build: flags a
/// leaf type does not consume are ignored there, the same way upstream
/// ignores unknown `ParseParams` entries (issue #974 review).
fn parse_cond_leaf(ty: &str, tail: &str, inner: &str) -> Result<CondExpr, String> {
    // A rule-type name is `[A-Z0-9-]+` — a head field carrying a paren,
    // operator or space was never a leaf (`| (DOMAIN,a)` splits on its
    // own inner comma into a bogus type); reject here rather than
    // surfacing a misleading "unknown rule type" at build.
    if ty.is_empty()
        || !ty
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "SUB-RULE condition: expected '(TYPE,payload)', got '({inner})'"
        ));
    }
    let payload = tail.split(',').next().map_or("", str::trim);
    if payload.is_empty() {
        return Err(format!(
            "SUB-RULE condition: '({ty},)' has an empty payload"
        ));
    }
    Ok(CondExpr::Leaf(CondLeaf {
        ty: ty.to_string(),
        payload: payload.to_string(),
        // Reassemble with the canonical type: `inner`'s head may carry a
        // spelling the case-sensitive leg match would reject
        // (`domain-suffix`), while `tail` already holds payload and
        // params verbatim.
        entry: format!("{ty},{tail}"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_head_forms() {
        let r = parse_sub_rule_reference("SUB-RULE,local").unwrap().unwrap();
        assert_eq!(r.name, "local");
        assert!(r.cond.is_none() && r.fallback.is_none());

        let r = parse_sub_rule_reference("SUB-RULE,(DOMAIN,a),local")
            .unwrap()
            .unwrap();
        assert_eq!(r.name, "local");
        assert_eq!(r.cond.as_deref(), Some("(DOMAIN,a)"));
        assert!(r.fallback.is_none());

        let r = parse_sub_rule_reference("SUB-RULE,(DOMAIN,a),local,REJECT")
            .unwrap()
            .unwrap();
        assert_eq!(r.name, "local");
        assert_eq!(r.fallback.as_deref(), Some("REJECT"));
    }

    #[test]
    fn parenthesised_block_name_without_comma() {
        let r = parse_sub_rule_reference("SUB-RULE,(local)")
            .unwrap()
            .unwrap();
        assert_eq!(r.name, "(local)");
        assert!(r.cond.is_none() && r.fallback.is_none());
    }

    #[test]
    fn reference_head_rejects() {
        for line in [
            "SUB-RULE,name,junk",
            "SUB-RULE,(DOMAIN,a",
            "SUB-RULE,(DOMAIN,a)junk,name",
            "SUB-RULE,(DOMAIN,a),",
            "SUB-RULE,(DOMAIN,a),name,",
            "SUB-RULE,(DOMAIN,a),name,x,y",
            "SUB-RULE,",
            "SUB-RULE,(a),,tgt",
        ] {
            assert!(parse_sub_rule_reference(line).is_err(), "{line} must fail");
        }
        assert!(parse_sub_rule_reference("DOMAIN,x,T").unwrap().is_none());
        assert!(parse_sub_rule_reference("SUB-RULE").unwrap().is_none());
    }

    fn leaf_ty(e: &CondExpr) -> Option<&str> {
        match e {
            CondExpr::Leaf(l) => Some(l.ty.as_str()),
            _ => None,
        }
    }

    #[test]
    fn cond_leaf_types() {
        // Every rule type except MATCH/SUB-RULE is a legal leaf — the
        // upstream `payloadToRule` exclusion set (issue #974 review).
        for (text, ty) in [
            ("(DOMAIN,a)", "DOMAIN"),
            ("(DOMAIN-SUFFIX,a.b)", "DOMAIN-SUFFIX"),
            ("(DOMAIN-KEYWORD,x)", "DOMAIN-KEYWORD"),
            ("(GEOSITE,cn)", "GEOSITE"),
            ("(GEOIP,JP)", "GEOIP"),
            ("(GEOSITE,cat@attr)", "GEOSITE"),
            ("(GEOIP,JP,no-resolve)", "GEOIP"),
            ("(GEOIP,JP,src)", "GEOIP"),
            ("(GEOSITE,cn,no-resolve)", "GEOSITE"),
            ("(RULE-SET,p)", "RULE-SET"),
            ("(PROCESS-NAME,x)", "PROCESS-NAME"),
            ("(NETWORK,tcp)", "NETWORK"),
            ("(IP-CIDR,1.1.1.1/32)", "IP-CIDR"),
            ("(DST-PORT,443)", "DST-PORT"),
            ("(IP-ASN,13335)", "IP-ASN"),
        ] {
            let e = parse_cond(text).unwrap_or_else(|err| panic!("{text}: {err}"));
            assert_eq!(leaf_ty(&e), Some(ty), "{text}");
        }
    }

    #[test]
    fn cond_leaf_rejections() {
        for text in [
            "(MATCH,x)",
            "(SUB-RULE,a)",
            "(DOMAIN,)",
            "(GEOSITE,)",
            "(AND)",
            "(FOO)",
            "(,a)",
        ] {
            assert!(parse_cond(text).is_err(), "{text} must fail");
        }
    }

    #[test]
    fn cond_leaf_build_uses_shared_leg_grammar() {
        use crate::parser::ParserContext;
        let ctx = ParserContext::empty();
        let empty: crate::parser::RuleSets = Default::default();

        // A `(GEOIP,JP,src)` leaf becomes SrcGeoIpRule through the shared
        // grammar — flags fold exactly like a logic leg.
        let cond = parse_cond("(GEOIP,JP,src)").unwrap().build(&ctx, &empty);
        // No geoip index in the empty context — the error proves the leaf
        // reached the GEOIP arm at all.
        assert!(cond.is_err(), "GEOIP leaf must reach the GEOIP builder");
        let err = cond.err().unwrap();
        assert!(err.contains("GeoIP"), "{err}");

        // Unknown leaf types surface the shared parser's error at build.
        let err = parse_cond("(FOO,a)")
            .unwrap()
            .build(&ctx, &empty)
            .err()
            .expect("unknown leaf must fail at build");
        assert!(err.contains("unknown rule type"), "{err}");

        // `(GEOSITE,@attr)` — an empty category name errors at build the
        // same way a top-level `GEOSITE,@attr,x` line does.
        let err = parse_cond("(GEOSITE,@attr)")
            .unwrap()
            .build(&ctx, &empty)
            .err()
            .expect("empty GEOSITE category must fail at build");
        assert!(err.contains("category"), "{err}");

        // `(RULE-SET,missing)` resolves against the supplied provider map.
        let err = parse_cond("(RULE-SET,missing)")
            .unwrap()
            .build(&ctx, &empty)
            .err()
            .expect("unknown provider must fail at build");
        assert!(err.contains("rule-provider"), "{err}");
    }

    #[test]
    fn cond_prefix_forms() {
        let e = parse_cond("(AND,((DOMAIN,a),(DOMAIN-SUFFIX,b)))").unwrap();
        let CondExpr::And(items) = e else {
            panic!("expected And")
        };
        assert_eq!(items.len(), 2);
        assert_eq!(leaf_ty(&items[0]), Some("DOMAIN"));
        assert_eq!(leaf_ty(&items[1]), Some("DOMAIN-SUFFIX"));

        let e = parse_cond("(OR,((DOMAIN,a),(DOMAIN-KEYWORD,k)))").unwrap();
        assert!(matches!(e, CondExpr::Or(_)));

        let e = parse_cond("(NOT,((DOMAIN,a)))").unwrap();
        let CondExpr::Not(inner) = e else {
            panic!("expected Not")
        };
        assert_eq!(leaf_ty(&inner), Some("DOMAIN"));

        assert!(parse_cond("(NOT,((DOMAIN,a),(DOMAIN,b)))").is_err());
        assert!(parse_cond("(AND,())").is_err());
        assert!(parse_cond("(AND,((a),))").is_err());
        // Nested prefix composite.
        let e = parse_cond("(AND,((OR,((DOMAIN,a),(DOMAIN,b))),(GEOIP,JP)))");
        assert!(e.is_ok(), "{e:?}");
    }

    #[test]
    fn cond_infix_forms() {
        // a | b & !c  →  a | (b & !c)
        let e = parse_cond("((DOMAIN,a) | (DOMAIN-KEYWORD,k) & !(DOMAIN-SUFFIX,g))").unwrap();
        let CondExpr::Or(items) = e else {
            panic!("expected Or")
        };
        assert_eq!(items.len(), 2);
        assert_eq!(leaf_ty(&items[0]), Some("DOMAIN"));
        let CondExpr::And(and_items) = &items[1] else {
            panic!("expected And on the right")
        };
        assert_eq!(leaf_ty(&and_items[0]), Some("DOMAIN-KEYWORD"));
        assert!(matches!(&and_items[1], CondExpr::Not(_)));

        // parens override precedence: (a | b) & c
        let e = parse_cond("(((DOMAIN,a) | (DOMAIN,b)) & (DOMAIN,c))").unwrap();
        let CondExpr::And(items) = e else {
            panic!("expected And")
        };
        assert!(matches!(&items[0], CondExpr::Or(_)));

        // double negation and chained !
        assert!(parse_cond("(!!(DOMAIN,a))").is_ok());
    }

    #[test]
    fn cond_infix_rejections() {
        for text in [
            "((DOMAIN,a) && (DOMAIN,b))",
            "((DOMAIN,a) || (DOMAIN,b))",
            "((DOMAIN,a) | )",
            "(| (DOMAIN,a))",
            "((DOMAIN,a) & )",
            "((DOMAIN,a)(DOMAIN,b))",
            "(!)",
            "()",
        ] {
            assert!(parse_cond(text).is_err(), "{text} must fail");
        }
    }

    #[test]
    fn cond_trailing_garbage_rejected() {
        for text in ["(DOMAIN,a) x", "(DOMAIN,a) (DOMAIN,b)", "(DOMAIN,a))"] {
            assert!(parse_cond(text).is_err(), "{text} must fail");
        }
    }

    #[test]
    fn cond_depth_budget() {
        let nested = |depth: usize| {
            let mut s = "(".repeat(depth);
            s.push_str("DOMAIN,a");
            s.push_str(&")".repeat(depth));
            format!("({s})")
        };
        assert!(parse_cond(&nested(63)).is_ok());
        assert!(parse_cond(&nested(65)).is_err());
        // `!` chains count too.
        let mut bangs = "!".repeat(65);
        bangs.push_str("(DOMAIN,a)");
        assert!(parse_cond(&format!("({bangs})")).is_err());
        // Flat `|`/`&` chains do not recurse.
        let flat = format!("({})", vec!["(DOMAIN,a)"; 200].join(" | "));
        assert!(parse_cond(&flat).is_ok());
    }

    #[test]
    fn cond_leaves_collect() {
        let e = parse_cond(
            "((GEOIP,JP) | (GEOSITE,cn@attr) & !(DOMAIN-SUFFIX,x) & (AND,((DOMAIN,y),(DOMAIN-KEYWORD,z))))",
        )
        .unwrap();
        assert_eq!(e.leaves().len(), 5);
    }

    /// Issue #974 review — `parse_cond` accepts a leaf's non-canonical
    /// type spelling, so build must feed the *normalized* name to the
    /// case-sensitive leg grammar: `(domain-suffix,x)` parses like
    /// `(DOMAIN-SUFFIX,x)` did before the widened leaf set.
    #[test]
    fn cond_leaf_build_normalizes_type_spelling() {
        use crate::parser::ParserContext;
        let ctx = ParserContext::empty();
        let empty: crate::parser::RuleSets = Default::default();
        for text in ["(domain-suffix,a.example)", "(DomainSuffix,a.example)"] {
            let rule = parse_cond(text)
                .unwrap_or_else(|e| panic!("{text}: {e}"))
                .build(&ctx, &empty)
                .unwrap_or_else(|e| panic!("{text}: build must succeed, got {e}"));
            let meta = meow_common::Metadata {
                host: "www.a.example".into(),
                ..Default::default()
            };
            assert!(
                rule.match_metadata(&meta, &meow_common::RuleMatchHelper),
                "{text}: the leaf must behave as DOMAIN-SUFFIX"
            );
        }
    }

    /// Issue #974 review — delimiter bytes are literal in non-regex
    /// payloads: a glob's `[` or a path's `\` must not shadow the
    /// structural paren closing a plain `(TYPE,…)` group.
    #[test]
    fn cond_literal_delimiters_in_plain_payloads() {
        // The glob `worker[*` carries a literal `[` — the group's `)`
        // must still close it.
        let e = parse_cond("(PROCESS-NAME-WILDCARD,worker[*)");
        assert!(e.is_ok(), "{e:?}");
        assert_eq!(leaf_ty(&e.unwrap()), Some("PROCESS-NAME-WILDCARD"));
        // Same inside a prefix group's item list — the comma and the
        // group's own parens are not class contents.
        let e = parse_cond("(AND,((PROCESS-NAME-WILDCARD,worker[*),(NETWORK,tcp)))");
        assert!(e.is_ok(), "{e:?}");
        // A backslash in a literal payload is just a byte — `\( ` is not
        // an escape here, so the unbalanced shape must still error.
        assert!(parse_cond("(PROCESS-PATH-WILDCARD,C:\\dir").is_err());
        // And inside a regex leaf the same bytes keep their escape/class
        // meaning — `(DOMAIN-REGEX,a\),b)` stays one group.
        let e = parse_cond("(DOMAIN-REGEX,a\\),b)");
        assert!(e.is_ok(), "{e:?}");
        let e = parse_cond("(DOMAIN-REGEX,x[(]y)");
        assert!(e.is_ok(), "{e:?}");
    }
}
