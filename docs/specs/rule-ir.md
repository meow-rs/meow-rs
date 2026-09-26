# Spec: Rule matching IR

Status: Draft (2026-06-18)
Owner: core
Related: `docs/specs/rule-engine-micro-opt.md`, ADR-0008 rule matching work

## Purpose

`meow-tunnel` routes each connection by matching `Metadata` against the ordered
`rules:` list from the active config. The public rule representation is
`Vec<Box<dyn Rule>>`, which is flexible but expensive on the hot path: a match
can require repeated virtual calls for the predicate, adapter name, rule type,
and payload.

## IR Definition

The rule IR is the immutable execution plan produced from one parsed `rules:`
list. It is represented by `CompiledRuleSet`.

The IR has three responsibilities:

1. Preserve the source rule list's first-match semantics.
2. Lower rule predicates that can be represented from public rule payload plus
   `Metadata` into native opcodes.
3. Cache stable match-result metadata so the hot path does not repeatedly call
   virtual `Rule` methods for rule type, payload, and static adapter names.

The IR does not replace the source rules. The original `Vec<Box<dyn Rule>>`
remains the semantic source of truth and is stored beside the IR in the same
route-table snapshot.

The IR is not:

- a new config format
- a new rule language
- a lossy rewrite of rule ordering
- a replacement for rules with private embedded state
- responsible for DNS resolution, process lookup, or proxy selection

### IR Terms

| term | definition |
| --- | --- |
| source rule | One parsed `Box<dyn Rule>` from the ordered config rule list. |
| compiled rule set | `CompiledRuleSet`, the immutable IR built from the full source rule list. |
| slot | `CompiledRuleSlot`, one IR entry for a source rule that survived pruning (constant-false, duplicate, and shadowed rules emit no slot). Slot order is source order. |
| opcode | `RuleOp`, a native predicate compiled from a source rule's public type and payload. |
| fallback slot | A slot whose source rule cannot be fully represented as an opcode and must call the public `Rule` trait. |
| target plan | Whether a successful slot returns the source rule's static adapter or a dynamic adapter from nested rule evaluation. |
| execution plan | The top-level strategy used by `CompiledRuleSet::match_rules`: straight ordered scan or domain-indexed scan. |
| match result | `CompiledMatchResult`, a borrowed adapter/rule-type/payload result returned to the tunnel. |

## Runtime Ownership

`Tunnel::update_rules()` receives the parsed `Vec<Box<dyn Rule>>` from
`meow-config`. It builds three rule artifacts for one route snapshot:

1. `rules: Arc<Vec<Box<dyn Rule>>>` is the original ordered rule list.
2. `domain_index: Arc<DomainIndex>` is retained for compatibility and tests.
3. `compiled_rules: Arc<CompiledRuleSet>` is the hot-path execution plan.

Those fields live together in `RouteTable`, which is published through a
`parking_lot::RwLock<Arc<RouteTable>>` cell. A routing lookup takes one short
read lock + `Arc` clone, so rules, compiled IR, and proxies are all read from
the same route-table generation.

`Tunnel::update_proxies()` does not rebuild rules. It clones the current
`rules`, `domain_index`, and `compiled_rules` arcs into the new route table and
replaces only the proxy map. Rule compilation is therefore paid on config/rule
reload, not proxy refresh. It installs the caller-supplied `dialer_registry`
alongside the map, so it must only be used with maps built under that registry
generation — a freshly rebuilt map belongs to `Tunnel::update_routing()`,
which carries the rebuild's own registry (issue #533).

## IR Data Model

`CompiledRuleSet` contains:

- `slots`: one `CompiledRuleSlot` per source rule, in source order.
- `adapter_names`: interned static adapter targets captured from top-level
  rules.
- `adapter_lookup`: reverse lookup for dynamic adapter results.
- `domain_index`: the existing DOMAIN/DOMAIN-SUFFIX trie, scoped to the same
  rule list when the selected plan uses trie probing.
- `execution_plan`: the compiler-selected plan for the rule-set shape.
- `needs_ip_resolution` and `needs_process_lookup`: aggregate rule flags
  captured at build time.

Each slot stores:

- `rule_index`: index into the original `rules` slice.
- `rule_type`: copied `RuleType`.
- `adapter_index`: interned top-level adapter.
- `target_plan`: whether the rule returns a static adapter or can return a
  nested dynamic adapter.
- `op`: lowered native predicate or `Fallback`.

The rule payload is deliberately *not* stored in the slot (footprint); the
scan re-reads it from `rules[rule_index]` only when a match is produced.

## IR Coding Spec

This section is normative for `crates/meow-tunnel/src/rule_ir.rs`.

### Construction

- `CompiledRuleSet::build(rules)` creates one slot per source rule that survives
  the clean-up passes (never-match folding, same-adapter dedup/shadow/coverage,
  and truncation after a `MATCH` whose target is predicate-guaranteed, i.e.
  `DIRECT`). Passes may only drop a rule whose outcome is provably identical
  under continue-on-missing-target semantics — a different adapter keeps the
  rule live because a dead covering target falls through to it.
- `slot.rule_index` must equal the source rule's position in `rules`.
- Slot order must remain identical to source rule order. The IR may add indexes
  or choose a different scan plan, but it must not reorder slots.
- Build-time extraction may call `Rule` methods for stable metadata:
  `rule_type()`, `adapter()`, `payload()`, `should_resolve_ip()`, and
  `should_find_process()`.
- Build-time extraction must not evaluate a rule against request metadata.
- Static adapter names should be interned in `adapter_names` and referenced by
  slot index so successful static matches do not allocate.
- A malformed or unsupported payload must compile to `Fallback`, not to a
  partial opcode.

### Opcode Rules

Add a `RuleOp` only when all of these are true:

- The rule behavior can be implemented from public rule type, public payload,
  and `Metadata`.
- The opcode preserves case sensitivity, boundary checks, platform behavior,
  and empty-field behavior of the source rule.
- The opcode does not require hidden parser state, external datasets, async I/O,
  DNS lookup, process lookup, or proxy-map access.
- Existing source-order first-match semantics are unchanged.

Keep a rule as `Fallback` when any of these are true:

- The rule owns private compiled state that is not visible through public
  payload.
- The rule delegates to nested rules and can return a nested adapter.
- The rule depends on geodata, rule-set providers, or other state outside
  `Metadata`.
- The source behavior is uncertain or cannot be covered by parity tests.

Every new lowered opcode must have unit coverage for:

- positive match
- negative match
- case and boundary behavior when relevant
- parity with the source `Rule` implementation

### Fallback Rules

Fallback slots preserve correctness for rule types that are not safe to lower.

- Static fallback slots call `rule.match_metadata()` and return the slot's
  captured adapter, rule type, and payload.
- Dynamic fallback slots call `rule.match_and_resolve()` and return the adapter
  produced by nested rule evaluation.
- `SUB-RULE` must remain dynamic unless its nested adapter semantics are
  represented explicitly in a future IR.
- Fallback is a correctness boundary, not an error path.

### Execution Plans

Execution-plan selection is a compiler optimization over the same slots.

- `LinearScan` scans every slot in source order and must not build or probe
  `DomainIndex`.
- `DomainIndexed` may use `DomainIndex` only as an early-exit hint. It must scan
  all slots before a trie hit before returning the trie result.
- A plan may skip work only when the skipped slots cannot affect first-match
  semantics.
- Changing a plan threshold requires benchmark evidence for both fixture-backed
  rules and synthetic large-rule cases.

### Runtime Contract

- `CompiledRuleSet::match_rules(metadata, rules, probe)` must be called
  with the same source rule list used to build the compiled rule set, plus a
  `&dyn TargetProbe` registry probe. A matched slot whose adapter name
  reports `TargetCheck::Missing` is warned and skipped, matching mihomo's
  `continue` in `match()`; `TargetCheck::Pass` (the target or an adapter in
  its `unwrap_proxy` chain is `PASS`-typed) skips silently — upstream's
  `continue GetRules`. A plain `Fn(&str) -> bool` still works as a probe:
  `true` maps to `Usable`, `false` to `Missing`.
- Returned `CompiledMatchResult` should borrow from the compiled rule set or the
  source rule; the successful hot path should not allocate.
- The IR must not mutate runtime state.
- The IR must not resolve DNS, perform process lookup, or inspect proxies.
- `needs_ip_resolution()` and `needs_process_lookup()` are aggregate hints
  copied from source rules. The tunnel owns the actual enrichment work.
- `match_rules_lazy(metadata, rules, probe)` is the two-phase
  variant used on the TCP hot path: the scan stops at the first slot whose
  predicate needs a field the caller has not materialized yet
  (`dst_ip`/`process`) and returns `NeedsEnrichment` instead of a silent
  non-match. Missing-target warnings are deferred inside the lazy scan and
  emitted only on a final outcome (`Matched`/`NoMatch`); on
  `NeedsEnrichment` the strict `match_rules` re-scan the caller performs
  re-derives the same skips deterministically, so each missing target
  warns exactly once per connection. A caller that treats
  `NeedsEnrichment` as terminal loses those warnings.

## Example IR Sequences

The IR is not a bytecode VM. An "IR sequence" is the ordered `slots` array plus
the selected execution plan and any side indexes needed by that plan.

### Example 1: Small Lowered Rule List

Source rules:

| index | source rule |
| ---: | --- |
| 0 | `DOMAIN-SUFFIX,example.com,Proxy` |
| 1 | `DST-PORT,443,DIRECT` |
| 2 | `MATCH,DIRECT` |

Compiled rule set:

```text
execution_plan = LinearScan
adapter_names  = ["Proxy", "DIRECT"]
domain_index   = empty

slots:
  0:
    rule_index    = 0
    rule_type     = DOMAIN-SUFFIX
    payload       = "example.com"
    adapter_index = 0  # "Proxy"
    target_plan   = StaticAdapter
    op            = RuleOp::DomainSuffix("example.com")

  1:
    rule_index    = 1
    rule_type     = DST-PORT
    payload       = "443"
    adapter_index = 1  # "DIRECT"
    target_plan   = StaticAdapter
    op            = RuleOp::DstPort(PortMatcher::Single(443))

  2:
    rule_index    = 2
    rule_type     = MATCH
    payload       = ""
    adapter_index = 1  # "DIRECT"
    target_plan   = StaticAdapter
    op            = RuleOp::Match
```

Execution for `host = "www.example.com", dst_port = 80`:

```text
scan slot 0 -> RuleOp::DomainSuffix matches
return adapter_names[0], DOMAIN-SUFFIX, "example.com", rule_index 0
```

Execution for `host = "other.test", dst_port = 443`:

```text
scan slot 0 -> no match
scan slot 1 -> RuleOp::DstPort matches
return adapter_names[1], DST-PORT, "443", rule_index 1
```

No source `Rule` method is called on the match hot path for these three slots.

### Example 2: Large Domain-Indexed Rule List

Source rules, reduced to the relevant prefix:

| index | source rule |
| ---: | --- |
| 0 | `DST-PORT,443,DIRECT` |
| 1 | `GEOSITE,github,Proxy` |
| ... | non-domain rules and other domain rules |
| 75 | `DOMAIN-SUFFIX,example.com,Proxy` |
| ... | remaining rules |
| 100 | `MATCH,DIRECT` |

Compiled rule set:

```text
execution_plan = DomainIndexed
domain_index   = { "example.com" => 75, ... }

slots[0].op   = RuleOp::DstPort(PortMatcher::Single(443))
slots[1].op   = RuleOp::Fallback  # GEOSITE owns private geosite state
slots[75].op  = RuleOp::DomainSuffix("example.com")
slots[100].op = RuleOp::Match
```

Execution for `host = "www.example.com", dst_port = 80`:

```text
trie probe host "www.example.com" -> hit T = 75
scan slots [0, 75):
  slot 0 -> port does not match
  slot 1 -> fallback GEOSITE does not match
  ...
prefix scan has no match
return static result for slot 75
```

Execution for `host = "www.example.com", dst_port = 443`:

```text
trie probe host "www.example.com" -> hit T = 75
scan slots [0, 75):
  slot 0 -> port matches
return slot 0
```

The prefix scan before returning trie hit `75` is mandatory. Without it, the
domain index would incorrectly skip the earlier `DST-PORT` rule.

### Example 3: Fallback and Dynamic Adapter

Source rules:

| index | source rule |
| ---: | --- |
| 0 | `OR,((DOMAIN-SUFFIX,corp.example),(DST-PORT,8443)),Proxy` |
| 1 | `SUB-RULE,private-block` |
| 2 | `MATCH,DIRECT` |

Compiled rule set:

```text
execution_plan = LinearScan
adapter_names  = ["Proxy", "PrivateBlock", "DIRECT"]

slots:
  0:
    rule_index    = 0
    rule_type     = OR
    payload       = "..."
    adapter_index = 0  # "Proxy"
    target_plan   = StaticAdapter
    op            = RuleOp::Fallback

  1:
    rule_index    = 1
    rule_type     = SUB-RULE
    payload       = "private-block"
    adapter_index = 1  # outer block name, not necessarily returned
    target_plan   = DynamicAdapter
    op            = RuleOp::Fallback

  2:
    rule_index    = 2
    rule_type     = MATCH
    payload       = ""
    adapter_index = 2  # "DIRECT"
    target_plan   = StaticAdapter
    op            = RuleOp::Match
```

Execution:

```text
slot 0 is static fallback:
  call rules[0].match_metadata(metadata, helper)
  if true, return captured adapter "Proxy"

slot 1 is dynamic fallback:
  call rules[1].match_and_resolve(metadata, helper)
  if it returns "Proxy-A", return adapter "Proxy-A"
  adapter_index is Some(i) only when "Proxy-A" exists in adapter_lookup

slot 2 is lowered:
  RuleOp::Match returns captured adapter "DIRECT"
```

The `SUB-RULE` slot must not return `PrivateBlock` just because that is the
outer rule adapter. Its runtime adapter is the matched nested rule's adapter, so
it stays dynamic fallback.

## Lowered Predicates

The IR currently lowers rule types whose full matching behavior is represented
by public payload plus `Metadata`:

- `DOMAIN`
- `DOMAIN-SUFFIX`
- `DOMAIN-KEYWORD`
- `DOMAIN-REGEX`
- `DOMAIN-WILDCARD`
- `IP-CIDR`
- `SRC-IP-CIDR`
- `SRC-PORT`
- `DST-PORT`
- `IN-PORT`
- `DSCP`
- `PROCESS-NAME`
- `PROCESS-PATH`
- `NETWORK`
- `UID`
- `IN-NAME`
- `IN-TYPE`
- `IN-USER`
- `MATCH`

Rules with private embedded state or composition stay as `Fallback` and call the
public `Rule` trait:

- `SUB-RULE`
- `RULE-SET` entries carrying `,src` — the src/dst swap lives on the
  `RuleSetRule` wrapper; `RuleSetRef` lowering carries only the set handle,
  so `is_src` entries stay `Fallback` (non-src entries lower to
  `RuleSetRef`)

Most other types now lower natively (`lower_native`): `GEOIP`/`SRC-GEOIP`/
`IP-ASN`/`SRC-IP-ASN` → `IpRanges`, `IP-SUFFIX`/`SRC-IP-SUFFIX` → `IpSuffix`,
`AND`/`OR`/`NOT` → `AllOf`/`AnyOf`/`NotOp`, `GEOSITE` → `GeoSite`, and
`RULE-SET` (without `,src`) → `RuleSetRef`.

This keeps the IR conservative. A rule type is lowered only when the compiled
opcode can preserve existing behavior without duplicating hidden state.

## Execution Plan Selection

The IR compiler selects one of two plans at build time:

| plan | selected when | behavior |
| --- | --- | --- |
| `LinearScan` | `rules.len() <= 64` | Scan compiled slots in source order. This avoids domain-trie probe overhead for small configs where early matches are common and straight-line execution is cheaper. |
| `DomainIndexed` | `rules.len() > 64` | Build and probe `DomainIndex`, then use the ordered prefix-scan algorithm. This avoids long scans in large rule sets. |

This is the main compiler-style optimization in the current IR: pick a cheap
straight-line plan for small rule programs, and pay indexing overhead only when
the rule set is large enough to amortize it.

## How IR Optimization Works

The rule matcher optimization has two phases: compile time and match time.

### Compile Time

`CompiledRuleSet::build(rules)` walks the source rule list once and produces a
compact ordered slot sequence.

For each source rule, the compiler:

1. Copies stable result metadata into the slot: rule index, rule type, payload,
   and top-level adapter index.
2. Interns static adapter names in `adapter_names`.
3. Chooses `TargetPlan::StaticAdapter` for normal rules or
   `TargetPlan::DynamicAdapter` for rules such as `SUB-RULE`.
4. Attempts to lower the rule into a native `RuleOp`.
5. Specializes lowered opcodes when a narrower form is available. For example,
   `DST-PORT,443` becomes `RuleOp::DstPort(PortMatcher::Single(443))` instead
   of a generic port-range loop.
6. Adds conservative regex prefilters when a required literal is known. For
   example, `DOMAIN-WILDCARD,*.example.com` stores `.example.com` as a
   case-insensitive prefilter before running the full regex.
7. Uses `RuleOp::Fallback` when lowering would be incomplete or unsafe.

Then the compiler selects the top-level execution plan:

```text
if rules.len() <= 64:
    execution_plan = LinearScan
    domain_index = empty
else:
    execution_plan = DomainIndexed
    domain_index = DomainIndex::build(rules)
```

The threshold is deliberately simple. The fixture benchmark showed that small
configs can lose more time to domain-trie probing than they save. The 10k-rule
benchmark showed that large configs still need an index-backed plan to avoid
unbounded ordered scans.

### Match Time

At runtime, `CompiledRuleSet::match_rules(metadata, rules, probe)`
creates one `MatchInput` view for the request and executes the compiled plan
without rebuilding or mutating anything.

`MatchInput` caches request fields that many opcodes need, starting with
`metadata.rule_host()`. Lowered domain opcodes and the domain-index probe share
that borrowed host view instead of repeatedly asking `Metadata` for the rule
host.

For `LinearScan`, the hot path is:

```text
for slot in slots:
    if slot.op is lowered:
        evaluate RuleOp directly against Metadata
    else if slot.target_plan is StaticAdapter:
        load rules[slot.rule_index]
        call rules[slot.rule_index].match_metadata(...)
    else:
        load rules[slot.rule_index]
        call rules[slot.rule_index].match_and_resolve(...)

    if matched:
        return cached or dynamic CompiledMatchResult
```

For `DomainIndexed`, the hot path is:

```text
host = input.host
T = domain_index.search(host)

if T exists:
    scan slots [0, T)
    if prefix matched:
        return prefix match
    return cached static result for slots[T]

scan full slot range
```

### What Gets Faster

The IR removes repeated hot-path work that was previously paid through dynamic
`Rule` trait calls:

- Lowered predicates avoid virtual `match_metadata()` dispatch.
- Static matches return interned adapter names instead of calling
  `rule.adapter()`.
- Rule type and payload are copied once at compile time instead of fetched for
  every successful match.
- `MatchInput` computes common request views once per match call.
- Lowered slots do not load from the source `rules` slice at all; source-rule
  lookup is deferred until a fallback slot needs it.
- Specialized port matchers avoid a range loop for single-port and single-range
  rules.
- Regex-heavy domain wildcard misses can skip `regex.is_match()` when the host
  does not contain the required literal.
- Small rule sets avoid domain-trie probe overhead entirely.
- Large rule sets can still use domain-index early exit before falling back to
  ordered slot scans.

### What Does Not Change

The optimizer cannot reorder rules, pre-resolve DNS, inspect proxies, or skip
fallback rules whose private state may affect the result. Every optimization is
constrained by source-order first-match semantics.

## Adapter Resolution

Most rules have a static top-level adapter. For those, a successful match returns
the interned adapter name without calling `rule.adapter()` on the hot path.

`SUB-RULE` is dynamic: the adapter comes from the matched inner rule, not the
outer block name. Dynamic slots therefore call `match_and_resolve()` and return
the adapter string from the fallback rule evaluation. If that adapter was not a
top-level adapter captured in the current IR, `adapter_index` is `None`; the
runtime still resolves it by name in the route snapshot's proxy map.

## Execution Algorithm

`CompiledRuleSet::match_rules(metadata, rules, probe)` preserves the
ordered first-match semantics of `match_engine::match_rules`, including the
shared continue-on-missing-target rule (issue #513): a matched rule whose
adapter name reports `Missing` is skipped and the scan continues — under
the indexed plan the tail scan re-evaluates trie-owned domain slots, so a
second matching domain rule after a skipped hit still resolves.

For `LinearScan`, execution is:

1. Scan slots `[0, len)` in source order.
2. Evaluate lowered opcodes directly.
3. Use fallback `Rule` calls only for non-lowered slots.
4. Return the first match.

For `DomainIndexed`, execution is:

1. Read the request host from `MatchInput`.
2. If the host is non-empty, probe the embedded `DomainIndex`.
3. If the trie returns a domain hit at index `T`, scan slots `[0, T)` in order.
   This is required because an earlier non-domain rule, or a broader domain
   rule before a more-specific trie hit, must still win.
4. If the prefix scan matched, return that result.
5. If the trie had hit `T` and the prefix did not match, return the static
   result for slot `T`.
6. If the trie missed, scan the full slot range in source order.

For each scanned slot:

- If `op` is lowered, evaluate the native predicate against `Metadata`.
- If `op` is `Fallback` and the adapter target is static, call
  `rule.match_metadata()` and return the captured static result on success.
- If `op` is `Fallback` and the adapter target is dynamic, call
  `rule.match_and_resolve()` and return the dynamic adapter result on success.

The returned `CompiledMatchResult` borrows adapter and payload strings from the
compiled rule set or source rule. It does not allocate for successful matches.

## Tunnel Hot Path

TCP connections resolve through `Tunnel::resolve_proxy_lazy()`:

1. `Direct` mode bypasses the rule engine.
2. `Global` mode resolves the `GLOBAL` proxy or falls back to DIRECT.
3. `Rule` mode loads an owned `Arc<RouteTable>` snapshot (held across any
   `.await`) and calls
   `route.compiled_rules.match_rules_lazy(metadata, route.rules, probe)`
   where the `RouteTargetProbe` checks the same route snapshot's proxy
   registry: membership, the `unwrap_proxy(metadata, false)` peek walk for
   `PASS`-typed hops, and UDP `support_udp` (with `DIRECT` hard-coded as
   always present).
4. On `Matched`/`NoMatch` the buffered dead-target warnings drain (see the
   lazy contract above) and the result materializes immediately.
5. On `NeedsEnrichment` the tunnel materializes only the demanded fields —
   process lookup works on a cloned metadata while real-IP resolution
   writes `dst_ip` on the caller's metadata — then re-runs the strict
   `match_rules`, which re-derives the same dead-target skips and warns
   each once.
6. On match, statistics are incremented from the returned `RuleType`, and the
   proxy is resolved by the returned adapter name — already proven present by
   the probe. A target that is somehow absent at materialization rejects the
   connection (fail-closed — a silent DIRECT hop is the leak class
   `dialer-proxy` exists to prevent), never falls through to direct egress.
7. On no match, the tunnel uses DIRECT.

The eager `resolve_proxy()` (process-enrich-then-scan) remains for non-TCP
paths and non-Rule modes. DNS/IP pre-resolution stays outside the IR: the IR
consumes the `Metadata` prepared by the tunnel and rule helpers; it does not
perform DNS or process lookups itself.

## Correctness Invariants

- `CompiledRuleSet` must be evaluated with the same `rules` slice it was built
  from. Runtime snapshots store both together.
- Slot order must match source rule order exactly.
- `LinearScan` must not build or probe the domain trie.
- `DomainIndexed` early-exit must scan the prefix before returning a trie hit.
- Fallback rules must remain fallback until their semantics can be represented
  only from public rule payload and `Metadata`.
- Dynamic adapter rules must not be rewritten to the outer rule adapter.
- Proxy reload must preserve the compiled rule set for the current rule
  generation.

## Benchmark Coverage

`crates/meow-tunnel/benches/rules_bench.rs` uses the complex fixture
`crates/meow-tunnel/tests/fixtures/memleak_ech_pressure_config.yaml`.
It also includes synthetic 10k-rule groups for large-rule scaling.

The bench parses that fixture through `meow-config`'s raw config rebuild path,
builds `DomainIndex` and `CompiledRuleSet`, and asserts that linear, indexed,
and IR execution return the same match for each measured case before timing.

The fixture cases cover:

- early `DOMAIN-SUFFIX` hit
- early `GEOSITE` hit
- IP-only `GEOIP` hit
- full fallthrough to `MATCH`

The synthetic cases cover:

- 10k-rule late `DOMAIN-SUFFIX` hit
- 10k-rule full fallthrough to `MATCH`
- 10k-rule `DOMAIN-WILDCARD` miss for regex-prefilter coverage

Use:

```bash
cargo bench -p meow-tunnel --bench rules_bench -- --noplot --sample-size 10 --measurement-time 2 --warm-up-time 1
```

The fixture is intentionally smaller than synthetic 10k-rule stress tests. It
measures real rule mix overhead and fallback behavior, while synthetic large-rule
benches remain useful for worst-case scan pressure.

## Memory Footprint Coverage

`crates/meow-tunnel/tests/rule_ir_footprint.rs` is an opt-in measurement test for
the same fixture. It installs a counting allocator for that integration-test
binary, resets counters around each measured phase, and prints:

- retained heap delta for fixture rule parsing
- retained heap delta for the legacy `DomainIndex`
- retained heap delta for `CompiledRuleSet`
- allocation counts for linear, indexed, and IR hot loops
- coarse RSS snapshots before/after each build phase

Use:

```bash
cargo test -p meow-tunnel --test rule_ir_footprint --release -- --ignored --nocapture
```

RSS is page-granular and includes loaded geodata, runtime state, and allocator
behavior. The counting allocator rows are the authoritative per-component signal
for the rule IR itself. The hot-loop allocation rows should remain zero for all
matchers.
