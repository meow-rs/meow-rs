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
//! targetless `(TYPE,payload[,flag…])` atoms from the whitelist
//! `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `GEOSITE` / `GEOIP`.
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

use crate::domain::DomainRule;
use crate::domain_keyword::DomainKeywordRule;
use crate::domain_suffix::DomainSuffixRule;
use crate::geoip::GeoIpRule;
use crate::geosite_rule::GeoSiteRule;
use crate::logic::{AndRule, NotRule, OrRule};
use crate::parser::{ParserContext, LOGIC_INNER_PLACEHOLDER};
use crate::src_geoip::SrcGeoIpRule;

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

/// Byte offset of the `)` closing the `(` at `text[0]`, or `None` when
/// unbalanced. Bytes scan — `(`/`)` are ASCII so UTF-8 is unaffected.
fn matching_paren(text: &str) -> Option<usize> {
    debug_assert!(text.starts_with('('));
    let mut depth = 0i32;
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// One whitelisted leaf kind inside a condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondLeafKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    GeoSite,
    GeoIp,
}

/// A leaf predicate `(TYPE,payload[,flag…])` — targetless by grammar.
#[derive(Debug)]
pub struct CondLeaf {
    pub kind: CondLeafKind,
    pub payload: String,
    pub no_resolve: bool,
    pub is_src: bool,
}

/// The condition predicate tree. `And`/`Or`/`Not` mirror the logic-rule
/// semantics; leaves are the five whitelisted types only.
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
    /// route, validate or account (issue #974).
    pub fn build(&self, ctx: &ParserContext) -> Result<Box<dyn Rule>, String> {
        match self {
            CondExpr::Leaf(leaf) => leaf.build(ctx),
            CondExpr::And(items) => Ok(Box::new(AndRule::new(
                items
                    .iter()
                    .map(|item| item.build(ctx))
                    .collect::<Result<Vec<_>, _>>()?,
                LOGIC_INNER_PLACEHOLDER,
            ))),
            CondExpr::Or(items) => Ok(Box::new(OrRule::new(
                items
                    .iter()
                    .map(|item| item.build(ctx))
                    .collect::<Result<Vec<_>, _>>()?,
                LOGIC_INNER_PLACEHOLDER,
            ))),
            CondExpr::Not(inner) => Ok(Box::new(NotRule::new(
                inner.build(ctx)?,
                LOGIC_INNER_PLACEHOLDER,
            ))),
        }
    }
}

impl CondLeaf {
    fn build(&self, ctx: &ParserContext) -> Result<Box<dyn Rule>, String> {
        match self.kind {
            CondLeafKind::Domain => Ok(Box::new(DomainRule::new(
                &self.payload,
                LOGIC_INNER_PLACEHOLDER,
            ))),
            CondLeafKind::DomainSuffix => Ok(Box::new(DomainSuffixRule::new(
                &self.payload,
                LOGIC_INNER_PLACEHOLDER,
            ))),
            CondLeafKind::DomainKeyword => Ok(Box::new(DomainKeywordRule::new(
                &self.payload,
                LOGIC_INNER_PLACEHOLDER,
            ))),
            CondLeafKind::GeoSite => Ok(Box::new(GeoSiteRule::new(
                &self.payload,
                LOGIC_INNER_PLACEHOLDER,
                ctx.geosite.clone(),
            ))),
            CondLeafKind::GeoIp => {
                let index = ctx.geoip.as_ref().ok_or_else(|| {
                    "GEOIP rule requires a GeoIP database, but none is configured".to_string()
                })?;
                let ranges = index.ranges_for(&self.payload);
                if self.is_src {
                    Ok(Box::new(SrcGeoIpRule::new(
                        &self.payload,
                        LOGIC_INNER_PLACEHOLDER,
                        ranges,
                    )))
                } else {
                    Ok(Box::new(GeoIpRule::new(
                        &self.payload,
                        LOGIC_INNER_PLACEHOLDER,
                        self.no_resolve,
                        ranges,
                    )))
                }
            }
        }
    }
}

/// Parse a condition region — the balanced `(…)` text from
/// [`parse_sub_rule_reference`] — into its predicate tree. Full-input
/// consumption, whitelist enforcement, and the shared depth budget all
/// live here so every caller sees the same grammar.
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

    /// `(TYPE,…)` inside a predicate region: either a whitelisted leaf
    /// `(LEAF,payload[,flag…])` or a prefix combinator `(AND|OR,(items))` /
    /// `(NOT,(item))`.
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
            "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "GEOSITE" | "GEOIP" => {
                parse_cond_leaf(&ty, tail)
            }
            _ => Err(format!(
                "SUB-RULE condition: '{ty}' is not allowed as a condition leaf \
                 (allowed: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, GEOSITE, GEOIP)"
            )),
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
fn split_group_items(inner: &str) -> Result<Vec<&str>, String> {
    let mut items = Vec::new();
    let (mut depth, mut start) = (0i32, 0usize);
    for (i, b) in inner.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
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

/// One whitelisted leaf `(TYPE,payload[,flag…])` — payload non-empty and
/// flags confined to what the leaf type actually consumes, so a typo'd
/// trailing field can never be swallowed as a "maybe-flag" (issue #974).
fn parse_cond_leaf(ty: &str, tail: &str) -> Result<CondExpr, String> {
    let mut fields = tail.split(',');
    let payload = fields.next().map_or("", str::trim);
    if payload.is_empty() {
        return Err(format!(
            "SUB-RULE condition: '({ty},)' has an empty payload"
        ));
    }
    let kind = match ty {
        "DOMAIN" => CondLeafKind::Domain,
        "DOMAIN-SUFFIX" => CondLeafKind::DomainSuffix,
        "DOMAIN-KEYWORD" => CondLeafKind::DomainKeyword,
        "GEOSITE" => CondLeafKind::GeoSite,
        "GEOIP" => CondLeafKind::GeoIp,
        _ => unreachable!("caller gates ty"),
    };
    let (mut no_resolve, mut is_src) = (false, false);
    for flag in fields {
        let flag = flag.trim();
        match (kind, flag.to_ascii_lowercase().as_str()) {
            // GEOSITE's `no-resolve` is a vestigial no-op, matching the
            // top-level parser.
            (CondLeafKind::GeoIp | CondLeafKind::GeoSite, "no-resolve") => no_resolve = true,
            (CondLeafKind::GeoIp, "src") => is_src = true,
            _ => {
                return Err(format!(
                    "SUB-RULE condition: '({ty},{payload},{flag})' — \
                     '{flag}' is not a valid flag for {ty}"
                ))
            }
        }
    }
    no_resolve |= is_src;
    Ok(CondExpr::Leaf(CondLeaf {
        kind,
        payload: payload.to_string(),
        no_resolve,
        is_src,
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

    fn leaf_kind(e: &CondExpr) -> Option<CondLeafKind> {
        match e {
            CondExpr::Leaf(l) => Some(l.kind),
            _ => None,
        }
    }

    #[test]
    fn cond_leaf_whitelist() {
        for (text, kind) in [
            ("(DOMAIN,a)", CondLeafKind::Domain),
            ("(DOMAIN-SUFFIX,a.b)", CondLeafKind::DomainSuffix),
            ("(DOMAIN-KEYWORD,x)", CondLeafKind::DomainKeyword),
            ("(GEOSITE,cn)", CondLeafKind::GeoSite),
            ("(GEOIP,JP)", CondLeafKind::GeoIp),
            ("(GEOSITE,cat@attr)", CondLeafKind::GeoSite),
            ("(GEOIP,JP,no-resolve)", CondLeafKind::GeoIp),
            ("(GEOIP,JP,src)", CondLeafKind::GeoIp),
            ("(GEOSITE,cn,no-resolve)", CondLeafKind::GeoSite),
        ] {
            let e = parse_cond(text).unwrap_or_else(|err| panic!("{text}: {err}"));
            assert_eq!(leaf_kind(&e), Some(kind), "{text}");
        }
        let e = parse_cond("(GEOIP,JP,src,no-resolve)").unwrap();
        let CondExpr::Leaf(l) = e else { panic!() };
        assert!(l.is_src && l.no_resolve);
    }

    #[test]
    fn cond_leaf_rejections() {
        for text in [
            "(MATCH,x)",
            "(RULE-SET,p)",
            "(SUB-RULE,a)",
            "(PROCESS-NAME,x)",
            "(NETWORK,tcp)",
            "(IP-CIDR,1.1.1.1/32)",
            "(DST-PORT,443)",
            "(DOMAIN,)",
            "(GEOSITE,)",
            "(DOMAIN,a,no-resolve)",
            "(DOMAIN-SUFFIX,a,src)",
            "(GEOIP,JP,bogus)",
            "(GEOSITE,cn,src)",
            "(FOO,a)",
            "(AND)",
        ] {
            assert!(parse_cond(text).is_err(), "{text} must fail");
        }
    }

    #[test]
    fn cond_prefix_forms() {
        let e = parse_cond("(AND,((DOMAIN,a),(DOMAIN-SUFFIX,b)))").unwrap();
        let CondExpr::And(items) = e else {
            panic!("expected And")
        };
        assert_eq!(items.len(), 2);
        assert_eq!(leaf_kind(&items[0]), Some(CondLeafKind::Domain));
        assert_eq!(leaf_kind(&items[1]), Some(CondLeafKind::DomainSuffix));

        let e = parse_cond("(OR,((DOMAIN,a),(DOMAIN-KEYWORD,k)))").unwrap();
        assert!(matches!(e, CondExpr::Or(_)));

        let e = parse_cond("(NOT,((DOMAIN,a)))").unwrap();
        let CondExpr::Not(inner) = e else {
            panic!("expected Not")
        };
        assert_eq!(leaf_kind(&inner), Some(CondLeafKind::Domain));

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
        assert_eq!(leaf_kind(&items[0]), Some(CondLeafKind::Domain));
        let CondExpr::And(and_items) = &items[1] else {
            panic!("expected And on the right")
        };
        assert_eq!(leaf_kind(&and_items[0]), Some(CondLeafKind::DomainKeyword));
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
}
