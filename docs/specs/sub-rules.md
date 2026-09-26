# Spec: SUB-RULE named rule subsets (M1.D-7)

Status: Approved (architect 2026-04-11; semantics confirmed by engineer 2026-04-11)
Owner: pm
Tracks roadmap item: **M1.D-7**
Depends on: none beyond the existing rule parser infrastructure.
Upstream reference: `rules/logic/logic.go` (not `rules/sub_rule.go` — SUB-RULE is
implemented as a logic rule), specifically:
- `matchSubRules` (lines 179–190) — block iteration; returns `(false, "")` on exhaustion.
- `Logic.Match` SUB-RULE case (lines 192–198) — gate + block dispatch.
- `rules/parser.go:80-81` `NewSubRule` — only constructor; `target` = block name.
- `tunnel/tunnel.go::match` (lines 633–664) — main dispatch loop; `matched == false`
  continues to next rule.

## Motivation

`SUB-RULE` allows a named block of rules to be referenced from the main
rule list or from other sub-rule blocks. Common use cases:

- Reusing a set of rules in multiple contexts (e.g., "always DIRECT for
  local IPs" referenced from both the global rule list and from an `AND` rule).
- Namespacing: subscription-provided rules separated from user overrides
  via separate sub-rule blocks.
- Conditional routing: `SUB-RULE,MY-BLOCK` — evaluate `MY-BLOCK`'s rules;
  if any match, return that rule's target; if none match, fall through to the
  next top-level rule.

Without `SUB-RULE`, configs that use it fail to parse or silently misroute.

## Scope

In scope:

1. `sub-rules:` top-level YAML section defining named rule blocks.
2. `SUB-RULE,<block-name>` rule type that evaluates a named block and returns
   the matched rule's target. If no rule in the block matches, SUB-RULE itself
   does not match (fall-through). There is no default-target field.
3. Recursive `SUB-RULE` references: a sub-rule block may itself contain
   `SUB-RULE` entries referencing other blocks (bounded by cycle detection).
4. Cycle detection: hard parse error if `sub-rules` reference graph has a cycle.
5. All existing rule types (`DOMAIN`, `IP-CIDR`, `GEOIP`, `MATCH`, etc.)
   are valid inside sub-rule blocks.
6. `MATCH` inside a sub-rule block: matches everything → the sub-rule block's
   MATCH action is returned as the sub-rule's result.

Out of scope:

- **Per-sub-rule `AND`/`OR` composition** — composing sub-rules via logic
  operators is an emergent property of placing `AND/OR` rules inside a
  sub-rule block; no extra work needed.
- **Dynamic sub-rule dispatch at runtime** — sub-rules are resolved at parse
  time into a static `Vec<Box<dyn Rule>>`. No runtime lookup map for each match.
- **Shared state between sub-rule invocations** — each `SUB-RULE` invocation
  evaluates its block independently; no cross-invocation state.
- **Rule-set provider inside sub-rule block** — RULE-SET inside a sub-rule
  block works if the rule type is registered; no extra work.

## User-facing config

```yaml
sub-rules:
  LOCAL-BYPASS:
    - IP-CIDR,192.168.0.0/16,DIRECT
    - IP-CIDR,10.0.0.0/8,DIRECT
    - IP-CIDR,172.16.0.0/12,DIRECT
    - IP-CIDR,127.0.0.0/8,DIRECT

  STREAMING:
    - DOMAIN-SUFFIX,netflix.com,StreamGroup
    - DOMAIN-SUFFIX,youtube.com,StreamGroup
    - DOMAIN-SUFFIX,spotify.com,StreamGroup

rules:
  - SUB-RULE,LOCAL-BYPASS    # evaluate LOCAL-BYPASS block; fall through if no match
  - SUB-RULE,STREAMING       # evaluate STREAMING block; fall through if no match
  - MATCH,Proxy
```

**Evaluation semantics (confirmed from upstream `rules/logic/logic.go`):**

```
SUB-RULE,LOCAL-BYPASS:
  → evaluate LOCAL-BYPASS rules in order
  → if IP-CIDR,192.168.0.0/16 matches: return "DIRECT" (from that rule's target)
  → if no LOCAL-BYPASS rule matches: return (false, "") — this SUB-RULE entry
     does NOT match; tunnel continues to next top-level rule
```

**There is no `<default-target>` field.** The `target` slot in `NewSubRule`
(rules/parser.go:80-81) stores the sub-rule-set name, not a fallback proxy.
When the block exhausts without a match, `matchSubRules` returns `(false, "")`,
which the main `tunnel.match` loop treats as no-match and continues. The routing
target is always the target of whichever rule *inside* the block matched.

`MATCH` inside a sub-rule block still works: `MATCH,Fallback` always matches, so
the sub-rule block always produces a result when MATCH is present.

**Resolution gate**: if any live rule inside the block needs a resolved
destination IP (`should_resolve_ip()` — `IP-CIDR`, `GEOIP`, `RULE-SET` with an
ipcidr provider, etc.) and `metadata.dst_ip` is not yet resolved, the SUB-RULE
entry reports no-match and the tunnel continues to the next top-level rule —
upstream `Logic.Match`'s `ShouldResolveIP() && !Resolved()` arm (push-resolution
baseline; the later `LogicRules` refactor pulled resolution per-rule, which our
engine does not support). On the lazy TCP path the demanding slot is flagged
`NeedsEnrichment` and re-matched strictly after DNS; on UDP paths `pre_resolve`
has already run, so the gate is unreachable there.

An inner rule whose target is the literal name `PASS-RULE`, or an adapter
(group) whose `unwrap_proxy` chain contains a `PASS-RULE`-typed adapter
(upstream's `CheckPassRule`), is skipped and the inner scan continues —
upstream `matchSubRules`' `continue`. At top level a rule targeting
`PASS-RULE` materializes the nop adapter and rejects like `REJECT`.

**YAML syntax**: the implemented form is the two-field `SUB-RULE,BLOCK-NAME`.
A third field (`SUB-RULE,blk,junk`) is a parse error — it was silently dropped
before #625, which read like a fallback target that never existed. Upstream's
parenthesized `(cond)` gate-expression form is not implemented.

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Cycle in sub-rules graph — upstream may panic or infinite-loop | A | Hard parse error: "sub-rule cycle detected: A → B → A". Detection via DFS at parse time. NOT runtime detection. |
| 2 | SUB-RULE referencing undefined block — upstream errors at runtime | A | Hard parse error: "sub-rule 'XYZ' not defined". NOT a runtime no-match. |
| 3 | Empty sub-rule block — upstream silently treats as no-match | B | Warn-once at parse time: "sub-rule 'NAME' has no rules; will always fall through". NOT an error — valid pattern for placeholder blocks. |

## Internal design

### Parse-time resolution

Sub-rules are resolved at parse time (not at dial time):

```rust
// meow-config/src/rule_parser.rs

pub struct SubRuleBlock {
    name: String,
    rules: Vec<Box<dyn Rule>>,
}

fn parse_sub_rules(raw: &HashMap<String, Vec<String>>) -> Result<HashMap<String, SubRuleBlock>> {
    // 1. Build dependency graph (block name → set of referenced block names)
    // 2. Cycle detection via DFS with a recursion-stack set:
    //      fn dfs(node, stack, visited) → cycle path or ok
    //    On revisit of a stack member: return Err("sub-rule cycle detected: A → B → A")
    //    DFS chosen over Kahn's because we only need cycle detection, not a topo sort as output.
    // 3. Topological parse order from DFS finish-order: parse leaf blocks first.
    // 4. Build the HashMap<String, Arc<Vec<Box<dyn Rule>>>> during parse so that
    //    all references to the same block name share one Arc (reference-count sharing,
    //    not semantically observable — just memory efficiency).
    // 5. Return HashMap<name, SubRuleBlock>
}
```

### SubRule struct

```rust
// meow-rules/src/sub_rule.rs

pub struct SubRule {
    block_name: String,
    block: Arc<Vec<Box<dyn Rule>>>,  // shared Arc; all SUB-RULE references to the same
                                     // block name share one Arc — reference-count sharing,
                                     // not semantically observable; just memory efficiency.
    // No default_target field — confirmed from upstream rules/parser.go:80-81 NewSubRule.
    // The target slot in Go stores the block name; there is no fallback proxy argument.
}

impl Rule for SubRule {
    fn apply(&self, metadata: &Metadata) -> Option<&str> {
        for rule in self.block.iter() {
            if let Some(target) = rule.apply(metadata) {
                // Rule in block matched — return its target.
                // Confirmed: upstream matchSubRules returns the inner rule's adapter,
                // not a separate default-target.
                return Some(target);
            }
        }
        // Block exhausted without match — confirmed: upstream returns (false, "").
        // Tunnel loop continues to next top-level rule. No default fallback.
        None
    }
}
```

### YAML structure

```yaml
sub-rules:
  BLOCK-NAME:         # map key is block name
    - DOMAIN,...      # same syntax as top-level rules: array of rule strings
    - IP-CIDR,...
```

The `sub-rules:` section is parsed before the main `rules:` section so that
`SUB-RULE` entries in `rules:` can reference already-resolved blocks.

## Acceptance criteria

1. `SUB-RULE,LOCAL-BYPASS` where LOCAL-BYPASS contains `IP-CIDR,192.168.0.0/16,DIRECT`
   → connection from 192.168.1.1 matches and returns "DIRECT" (from the inner rule).
2. No rule in block matches → SUB-RULE falls through; next rule in parent
   list evaluated.
3. Undefined block name → hard parse error at startup. Class A per ADR-0002.
4. Cycle detection: `A → B → A` → hard parse error at startup. Class A per ADR-0002.
5. Empty sub-rule block → warn-once; SUB-RULE always falls through.
   Class B per ADR-0002.
6. Nested sub-rules (block A references block B) → both blocks evaluated
   correctly.
7. `RULE-SET` inside a sub-rule block works (existing rule type dispatch).
8. `MATCH` inside a sub-rule block → always matches; block returns MATCH's
   target.

## Test plan (starting point — qa owns final shape)

**Unit (`sub_rule.rs`):**

- `sub_rule_match_returns_block_rule_target` — block contains
  `IP-CIDR,192.168.0.0/16,DIRECT`; metadata src 192.168.1.1 → returns "DIRECT"
  (from the inner rule's target, not a separate default-target).
  Upstream: `rules/logic/logic.go::matchSubRules` lines 179–190. NOT no-match.
- `sub_rule_no_match_falls_through` — no rule in block matches → apply()
  returns None. Confirmed upstream: (false, "") propagates to tunnel loop.
  NOT panic, NOT any fallback value.
- `sub_rule_nested_blocks_evaluated` — block A contains `SUB-RULE,B`;
  block B contains `DOMAIN,example.com,DIRECT`; query example.com → "DIRECT".
- `sub_rule_match_inside_block` — block contains `MATCH,Fallback`; any
  metadata → SUB-RULE matches.

**Unit (config parser):**

- `parse_sub_rules_valid` — two named blocks; both parsed correctly.
- `parse_sub_rule_undefined_block_hard_errors` — `rules:` contains
  `SUB-RULE,MISSING` with no "MISSING" in `sub-rules:` → parse error.
  Class A per ADR-0002.
- `parse_sub_rule_cycle_hard_errors` — `A → B → A` in sub-rule blocks →
  parse error. Class A per ADR-0002. NOT infinite loop.
- `parse_sub_rule_empty_block_warns` — empty `sub-rules.EMPTY: []` →
  warn-once. NOT error.

## Implementation checklist (engineer handoff)

- [ ] Add `sub-rules: Option<HashMap<String, Vec<String>>>` to `RawConfig`.
- [ ] Parse sub-rules section in config before main rules section.
- [ ] Implement cycle detection (DFS on block references) in config parser.
- [ ] **Before writing `apply()`**: paste the relevant sections from
      `rules/logic/logic.go::matchSubRules` (lines 179–190) and `Logic.Match`
      SUB-RULE case (lines 192–198) into a comment block in `sub_rule.rs`.
      Semantics are confirmed (fall-through, no default-target) but reviewer
      will use the pasted Go as the byte-for-byte reference during code review.
      Also verify the exact YAML field layout from `rules/parser.go` SUB-RULE
      case before committing the Rust parser (see §YAML syntax note above).
- [ ] Implement `SubRule` in `meow-rules/src/sub_rule.rs`.
- [ ] Implement cycle detection (DFS with recursion-stack set) in config parser.
- [ ] Register `SUB-RULE` parse dispatch in `parser.rs`.
- [ ] Update `docs/roadmap.md` M1.D-7 row with merged PR link.
