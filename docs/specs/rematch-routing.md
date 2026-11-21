# Spec: `type: rematch` and `REMATCH-NAME` (issue #974)

Status: Implemented.
Upstream reference: mihomo `C.Rematch` (a control outbound whose `Unwrap`
verdict the tunnel's match loop consumes), `Metadata.RematchName`,
`Metadata.SpecialRules`, and `rules/common/rematch.go` (`NewRematchName`).
The binding parity analysis — including what upstream accepts, what it
silently ignores, and where meow deliberately diverges — lives in the issue
history; this document records the contract meow ships.

## Motivation

Rematch is a routing *re-entry* primitive, not a transport: a rule that
selects a `type: rematch` node does not dial anything — it stamps a marker on
the flow's metadata and/or switches the active rule list, then the rule scan
restarts from the top of that list. `REMATCH-NAME` rules match the marker.
Together they express "label this flow and re-route it through a second
policy" — two-stage routing, staging pipelines, and config layouts that would
otherwise need duplicated rule lists.

## Configuration contract

```yaml
proxies:
  - name: inspect
    type: rematch
    target-rematch-name: stage1     # stamps Metadata.rematchName
    target-sub-rule: second-pass    # and/or switches the active rule list

rules:
  - DOMAIN-SUFFIX,example.test,inspect
  - MATCH,DIRECT

sub-rules:
  second-pass:
    - REMATCH-NAME,stage1/alternative,REJECT
    - MATCH,DIRECT
```

A flow for `example.test` selects `inspect`, re-enters inside `second-pass`
with `rematchName = "stage1"`, and is rejected; other flows take the
top-level `MATCH,DIRECT`.

### `type: rematch` node

- Requires `name`, `type: rematch`, and **at least one** `target-*` field.
- `target-rematch-name` / `target-sub-rule` are strings: omitted or `null`
  leaves that field unchanged; explicit `""` clears it (marker unset /
  back to the top-level rules). Verbatim — no trimming, case folding or
  splitting; numeric identifiers must be quoted.
- No `server`/`port`. `udp:` is ignored (the transition preempts the UDP
  capability check, so the leaf reports `udp: true` on `/proxies` for
  compatibility). Socket options (`routing-mark`, `interface-name`,
  `ip-version`, `tfo`, `mptcp`) warn as ignored.
- `dialer-proxy` **on** a rematch node is rejected at parse; a statically
  resolvable rematch leaf **as** a dialer front is rejected at build; a
  dynamic group pick that lands on rematch fails the chain closed at dial
  time — never a silent `DIRECT` substitute.
- Unknown `target-sub-rule` block names warn once at build and fall back to
  the top-level rules at match time (upstream `parseRules` semantics) —
  deliberately different from the listener `rule:` override's fail-closed
  contract.
- A malformed local rematch node fails the whole load in strict *and*
  lenient mode: warn-dropping it would silently remove the flow's first
  routing decision.

### `REMATCH-NAME` rule

`REMATCH-NAME,<names>,<target>[,<ignored>...]` — three required fields;
trailing parameters are ignored like other leaf types' leftovers. The
payload splits on `/` into alternatives, each trimmed, each compared to
`Metadata.rematchName` with **exact, case-sensitive** byte equality: no
wildcard, regex, substring or `|` alternation — `*` and `|` are literal.
An empty alternative rejects the rule; an unset marker matches nothing.
The raw payload text is preserved for `/rules` display and round-trip.

- Spellings: `REMATCH-NAME` in config (any case — upstream folds the type
  token through `ToUpper`), `RematchName` on the API surface and accepted
  on input through the existing API-name alias.
- Legal standalone, inside `AND`/`OR`/`NOT` legs, inside `SUB-RULE,(…)`
  conditions, and in classical rule-provider entries (the shared
  predicate grammar parses all of them).
- No GeoIP/GeoSite/ASN dependency, no IP-resolution or process demand —
  geo discovery already covers every declared block.
- A malformed `REMATCH-NAME` predicate is a structural error in both
  modes, head position or nested — same rationale as the node gate.

## Routing semantics

1. **Selection is ordinary.** A rule target resolves through the registry
   and the peeked group chain (`unwrap_proxy(metadata, false)` — no
   round-robin advance, no usage marks). Only the *selected* leaf counts:
   group membership alone never transitions.
2. **Rematch is checked before UDP capability.** The leaf advertises
   `support_udp()` precisely so the capability gate cannot preempt it;
   `RouteTargetProbe` returns `TargetCheck::Rematch`, stashing the
   candidate so the same peeked leaf commits the transition (the group is
   not reselected between detection and application).
3. **Only supplied fields apply.** `target-rematch-name` writes the marker
   (`""` clears it); `target-sub-rule` replaces the active rule list (`""`
   selects the main list). Nothing else moves — not host, addresses,
   process, `specialProxy`, or the listener's `special_route`.
4. **Iterative re-entry, never recursion.** `rule_route` loops over the
   active list — seeded from `metadata.special_rules()` for listener
   `rule:` overrides — with a per-flow visited set of rematch *adapter
   names* and a 32-transition cap. A repeat or the 33rd transition rejects
   the flow where it is: no slide to a later rule, no direct-dial
   fallback. `MATCH` is an ordinary terminal rule; `MATCH,<rematch>`
   legitimately re-triggers and hits the guards.
5. **Blocks vs listener selection.** A listener-seeded `rule:` block that
   is missing rejects (the override owns the flow's whole policy, UDP
   included). A rematch-selected missing block scans the main list
   instead, and its rules carry no top-level stats — block-local indices
   never stamp onto `/rules` counters.
6. **Lazy demand re-stages, not re-runs.** Every pass uses the same
   staged matcher; the destination-IP attempt flag and the flow's one
   process lookup (`FlowLookup` memo — hit *and* miss) carry across
   transitions, so a second pass never repeats a lookup.
7. **Mode boundaries.** `direct` mode still goes direct. `GLOBAL`, a
   forced `proxy:` override, health checks, relay hops and dialer fronts
   bypass rule matching — a rematch leaf that reaches those paths dials
   and fails closed immediately (`dial_tcp`/`dial_udp`/`connect_over`
   return the control-outbound error without opening a socket). The
   direct-resolver UDP probe resolves the route on a metadata clone, so
   probe transitions neither leak the marker onto the flow nor count hits.
8. **Accounting.** The chosen slot of each committed pass counts once on
   its own vector's stats; guard rejections bucket as REJECT. One
   aggregate routing outcome and one connection record for the final
   result; a rematch hop itself is never charged and never appears as a
   second connection.

## API surface

- `/proxies` and `/proxies/{name}`: `type: Rematch`, `udp: true`, `alive`,
  ordinary leaf fields — the two `target-*` action fields are routing
  directives, not transport fields, and are not exposed.
- `/rules`: `type: RematchName` with the original payload.
- `/proxies/{name}/delay` and group delay: the leaf is probed like any
  member — its dial fails immediately as an ordinary transport error
  (503), with no rule scan, DNS lookup or socket.
- `PUT /configs`: the verbatim-commit structural guard covers top-level
  rematch nodes and `REMATCH-NAME` lines (nested predicates included)
  even without a `sub-rules:` section — malformed shape is `400` with
  live/raw state untouched; structurally sound but environmentally
  unbuildable input keeps the usual force semantics.
- `Metadata` JSON: `rematchName` serializes flat and unconditionally
  (`""` when unset) like mihomo's `/connections`, and missing input
  defaults to unset.

## Implementation map

| Layer | Where |
|---|---|
| `RuleType::RematchName`, `AdapterType::Rematch`, `TargetCheck::Rematch`, `RematchAction`, `Metadata.rematch_name` | `crates/meow-common/src/{rule,adapter_type,adapter,metadata}.rs` |
| `RematchNameRule` + parser dispatch / `line_mentions_rematch_name` | `crates/meow-rules/src/{rematch_name,parser}.rs` |
| `RematchAdapter` (control leaf, fail-closed dials) | `crates/meow-proxy/src/rematch.rs` |
| Node dispatch, `check_rematch_node`, key inventory, dialer-front gate | `crates/meow-config/src/{proxy_parser,validation,lib}.rs` |
| `RuleOp::RematchName` + probe verdicts in both match engines | `crates/meow-tunnel/src/{rule_ir,match_engine}.rs` |
| `rule_route` transition loop, `RouteTargetProbe::rematch_leaf`, `RematchCandidate`, UDP/front-hop accounting | `crates/meow-tunnel/src/{tunnel,udp}.rs` |
| `PUT /configs` verbatim guard extension | `crates/meow-api/src/routes.rs` |

## Test coverage

- `meow-rules`: `rematch_name.rs` unit cases (exact/slash/trim/empty/unset/
  literal bytes, no demands, raw payload) and `parser.rs` cases (all
  spellings, missing target, ignored suffixes, logic legs, condition
  leaves, the mentions gate).
- `meow-config`: `check_rematch_node` gate table (missing name, no
  targets, non-string, `dialer-proxy`), verbatim field pass-through,
  `udp: false` ignored.
- `meow-proxy`: leaf invariants (no addr, `AdapterType::Rematch`,
  `support_udp`, verbatim action, every dial path fails closed).
- `meow-common`: `rematchName` JSON round-trip including missing-key
  defaults, verbatim setter, `pure()` carry-over.
- `meow-tunnel`: `tunnel.rs` `mod rematch` end-to-end cases — the spec
  example, name-only/block-only transitions, explicit clear, cycle and
  32-cap guards, unknown-block fallback, group pick vs membership, UDP
  flows, hit counts, `resolve_udp_dst` marker isolation, `SUB-RULE`
  member restart, and one-lookup-across-passes memoization.
- `meow-api`: `/proxies` + `/rules` display, delay 503, and the
  force-verbatim gate for malformed nodes/predicates vs. sound commits.

## Out of scope

`type: dns`; destination or process spoofing; rematch recursion through
health checks, bootstrap downloads or dialer hops; a new group type;
static analysis of all possible rematch cycles; any change to unrelated
`SUB-RULE`, reload, or lookup policies.
