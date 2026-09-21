use crate::match_engine::DomainIndex;
use ipnet::IpNet;
use meow_common::{ConnType, Metadata, Network, Rule, RuleMatchHelper, RuleType};
use meow_rules::{
    geoip::GeoIpRule,
    geosite::GeositeDB,
    geosite_rule::GeoSiteRule,
    ip_asn::IpAsnRule,
    ip_set::IpRangeSet,
    ip_suffix::{IpSuffixMatcher, IpSuffixRule},
    logic::{AndRule, NotRule, OrRule},
    rule_set::RuleSet,
    rule_set_rule::RuleSetRule,
    src_geoip::SrcGeoIpRule,
};
use regex::Regex;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use tracing::warn;

/// Below this size, trie probing costs more than it saves for common configs
/// with early matches. Compile small configs to straight-line ordered IR scan.
const LINEAR_SCAN_RULE_LIMIT: usize = 64;

/// Native compiled rule metadata plus indexes for hot-path matching.
///
/// This IR is intentionally hybrid: common parser-produced predicates lower to
/// native opcodes, while rules with private embedded state fall back to the
/// public `Rule` trait. Stable result metadata is captured once at build time
/// so successful matches avoid repeat `rule_type` / `payload` / top-level
/// `adapter` virtual calls.
///
/// Compilation runs four semantics-preserving clean-up passes over the rule
/// list (all rely on first-match-wins ordering):
///
/// 1. **Dead-rule elimination** — nothing after the first unconditional
///    `MATCH`/`FINAL` rule is reachable, so no slot is emitted for it and it
///    does not contribute to `needs_ip_resolution` / `needs_process_lookup`.
/// 2. **Duplicate elimination** — a later rule whose canonical predicate
///    fingerprint equals an earlier rule's can never win against its first
///    occurrence (see `dedup_fingerprint`).
/// 3. **Constant folding & constant-false pruning** — logic trees simplify
///    (never-match children erase OR arms and kill AND trees, double
///    negation cancels, single-child trees collapse); rules that provably
///    never match (a rule reporting [`Rule::never_matches`], a `UID` rule on
///    a platform without socket-UID lookup, or a logic tree folding to
///    false) are dropped from the scan plan, and a tree folding to true
///    becomes an unconditional `MATCH` terminator.
/// 4. **Shadowed-rule elimination** — a later domain-family rule whose match
///    set is fully covered by earlier DOMAIN-SUFFIX / DOMAIN-KEYWORD /
///    star-wildcard rules, or a later IP-CIDR contained in the union of
///    earlier same-axis networks, can never fire, so it is dropped
///    regardless of its adapter (see `ShadowOracle` / `CidrCoverage`).
///
/// Slots therefore form a subsequence of the source rules: each slot keeps
/// its original `rule_index` (for fallback dispatch and diagnostics), and
/// index-based lookups map rule index → slot position by binary search.
pub struct CompiledRuleSet {
    slots: Vec<CompiledRuleSlot>,
    /// Length of the rule slice this plan was compiled from. Slots may be
    /// fewer after clean-up passes; this ties the plan back to its source.
    source_rule_count: usize,
    adapter_names: Vec<SmolStr>,
    adapter_lookup: HashMap<SmolStr, usize>,
    domain_index: DomainIndex,
    execution_plan: ExecutionPlan,
    needs_ip_resolution: bool,
    needs_process_lookup: bool,
}

pub type RuleIr = CompiledRuleSet;

/// One live rule in the scan plan. Kept to 40 bytes: indices are `u32`, and
/// the rule's payload is not copied — a match borrows it from the source
/// rule via `rule_index`, so the plan stores no per-slot strings beyond
/// what the lowered `op` itself needs.
#[derive(Debug, Clone)]
pub struct CompiledRuleSlot {
    rule_index: u32,
    rule_type: RuleType,
    adapter_index: u32,
    target_plan: TargetPlan,
    /// This predicate reads `metadata.dst_ip` resolved from the hostname
    /// (the rule's `should_resolve_ip()`), so a lazy scan must stop here
    /// when `dst_ip` is missing but resolvable.
    demands_ip: bool,
    /// This predicate reads process metadata (the rule's
    /// `should_find_process()`); a lazy scan must stop here when process
    /// info is missing but discoverable.
    demands_process: bool,
    op: RuleOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetPlan {
    /// The target adapter is the top-level rule adapter captured in the IR.
    StaticAdapter,
    /// The target adapter can be returned by nested rule evaluation.
    DynamicAdapter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionPlan {
    /// Straight ordered slot scan. Best for small configs where trie overhead
    /// dominates and first-match order usually exits early.
    LinearScan,
    /// Domain trie early-exit plus ordered prefix scan. Best for large configs
    /// where avoiding long scans matters.
    DomainIndexed,
}

#[derive(Debug, Clone)]
enum RuleOp {
    Domain(Box<str>),
    DomainSuffix(Box<str>),
    DomainKeyword(Box<str>),
    DomainRegex(Box<RegexMatcher>),
    DomainWildcard(Box<WildcardMatcher>),
    IpCidr {
        net: IpNet,
        src: bool,
    },
    SrcPort(PortMatcher),
    DstPort(PortMatcher),
    InPort(PortMatcher),
    Dscp(u8),
    ProcessName(Box<str>),
    /// Boxed: two `Box<str>` variants leave no niche for the tag, so the
    /// inline op would be 24 bytes and push every slot's `RuleOp` to 32.
    ProcessPath(Box<ProcessPathOp>),
    Network(Network),
    Uid(u32),
    InName(Box<str>),
    InType(InTypeMask),
    InUser(Box<str>),
    Match,
    /// GEOSITE lowered to pre-resolved bucket handles: the category lookup,
    /// attribute splitting, and per-connection `format!` allocation all
    /// happened once at compile time.
    GeoSite(Box<GeoSiteOp>),
    /// RULE-SET lowered to its shared set handle (one virtual call into the
    /// set, no rule-level dispatch). The handle is the `RuleProvider` itself
    /// (issue #553): `refresh()` swaps the set behind it, so evaluation sees
    /// new content without an IR rebuild. Only the slot's `demands_ip` /
    /// `demands_process` flags are frozen at build time — a classical set
    /// that gains or loses IP / PROCESS entries keeps the old flags until
    /// the next config reload (the provider warns when that happens).
    RuleSetRef(RuleSetHandle),
    /// GEOIP / SRC-GEOIP / IP-ASN lowered to their shared interval sets.
    IpRanges {
        set: Arc<IpRangeSet>,
        src: bool,
    },
    /// IP-SUFFIX lowered to its Copy matcher. Boxed: the matcher carries
    /// inline u128 V6 masks (48 B) that would otherwise dominate the enum.
    IpSuffix(Box<IpSuffixOp>),
    /// AND / OR / NOT lowered to native expression trees over child ops.
    AllOf(Box<[RuleOp]>),
    AnyOf(Box<[RuleOp]>),
    NotOp(Box<RuleOp>),
    /// A DOMAIN / DOMAIN-SUFFIX / star-shaped DOMAIN-WILDCARD predicate
    /// fully owned by the domain index:
    /// the trie's min-index search proves whether it matches, so scans skip
    /// the slot without evaluating anything. The slot itself stays alive as
    /// the match-result carrier for trie hits.
    TrieOwned,
    Fallback,
}

#[derive(Debug, Clone)]
struct GeoSiteOp {
    db: Arc<GeositeDB>,
    /// Canonical bucket keys from `GeositeDB::resolve_keys` — all must
    /// contain the host (attribute categories are intersections).
    keys: Box<[Box<str>]>,
}

#[derive(Debug, Clone)]
struct IpSuffixOp {
    matcher: IpSuffixMatcher,
    src: bool,
}

#[derive(Clone)]
struct RuleSetHandle(Arc<dyn RuleSet>);

impl std::fmt::Debug for RuleSetHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSetHandle")
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
enum PortRange {
    Single(u16),
    Range(u16, u16),
}

#[derive(Debug, Clone)]
enum PortMatcher {
    Single(u16),
    Range(u16, u16),
    /// Thin-boxed so the matcher stays 16 bytes; multi-span port lists are
    /// rare and already pay one heap block for the spans.
    Multiple(Box<Box<[PortRange]>>),
}

#[derive(Debug, Clone)]
struct RegexMatcher {
    regex: Regex,
    required_literal: Option<String>,
}

#[derive(Debug, Clone)]
enum ProcessPathOp {
    Glob(Box<Regex>),
    Prefix(Box<str>),
    Exact(Box<str>),
}

#[derive(Debug, Clone, Copy)]
struct InTypeMask {
    http: bool,
    https: bool,
    socks5: bool,
    tproxy: bool,
    inner: bool,
}

struct MatchInput<'a> {
    metadata: &'a Metadata,
    host: &'a str,
}

/// Control-flow result of one scan pass over a slot range.
enum ScanOutcome<'a> {
    Matched(CompiledMatchResult<'a>),
    /// Slot at `pos` demands metadata the input does not carry yet
    /// (demand-stop scans only).
    Blocked {
        pos: usize,
    },
    Exhausted,
}

/// Result of a demand-driven (lazy) match attempt.
pub enum LazyMatchOutcome<'a> {
    /// A rule matched before any slot demanded missing metadata.
    Matched(CompiledMatchResult<'a>),
    /// The scan reached a slot whose predicate needs metadata not yet
    /// materialized. Enrich the reported fields, then re-run the strict
    /// [`CompiledRuleSet::match_rules`]. At least one flag is `true`.
    NeedsEnrichment { needs_ip: bool, needs_process: bool },
    /// No rule matched (and no slot was blocked on missing metadata).
    NoMatch,
}

/// The scan cannot evaluate this slot yet: its predicate demands a field
/// that is missing from the metadata but can still be materialized.
fn slot_blocked(slot: &CompiledRuleSlot, input: &MatchInput<'_>) -> bool {
    (slot.demands_ip && ip_missing(input))
        || (slot.demands_process && process_missing(input.metadata))
}

/// `dst_ip` is absent but resolvable: there is a hostname to resolve. With
/// no hostname either, IP predicates simply never match (the strict engine
/// behaves identically), so the scan must not stop.
fn ip_missing(input: &MatchInput<'_>) -> bool {
    input.metadata.dst_ip.is_none() && !input.host.is_empty()
}

/// Process info is absent but discoverable: a source socket exists to look
/// up. Mirrors the guards in `match_engine::maybe_enrich_with_process`.
fn process_missing(metadata: &Metadata) -> bool {
    metadata.process.is_empty() && metadata.src_ip.is_some() && metadata.src_port != 0
}

/// Log a skipped match: the rule matched but its target is absent from the
/// registry or unusable for this traffic (issue #513; mihomo's match loop
/// also `continue`s a target without UDP support on UDP flows).
/// Interpolated into the message itself because the /logs broadcast
/// forwards only the `message` field.
fn warn_missing_target(m: &CompiledMatchResult<'_>) {
    warn!(
        "rule {} matched target '{}' which is unavailable for this \
         connection (absent from the registry, or no UDP support); \
         skipping it",
        m.rule_type.as_str(),
        m.adapter_name,
    );
}

/// One borrowed result from a compiled rule-set match.
pub struct CompiledMatchResult<'a> {
    pub adapter_name: &'a str,
    pub adapter_index: Option<usize>,
    pub rule_type: RuleType,
    pub rule_payload: &'a str,
    pub rule_index: usize,
}

impl CompiledRuleSet {
    pub fn empty() -> Self {
        Self {
            slots: Vec::new(),
            source_rule_count: 0,
            adapter_names: Vec::new(),
            adapter_lookup: HashMap::new(),
            domain_index: DomainIndex::empty(),
            execution_plan: ExecutionPlan::LinearScan,
            needs_ip_resolution: false,
            needs_process_lookup: false,
        }
    }

    pub fn build(rules: &[Box<dyn Rule>]) -> Self {
        let mut slots = Vec::with_capacity(rules.len());
        let mut adapter_names = Vec::new();
        let mut adapter_lookup = HashMap::new();
        let mut needs_ip_resolution = false;
        let mut needs_process_lookup = false;
        // Under continue-on-missing-target semantics (issue #513), an
        // earlier rule no longer terminates the scan when its target is
        // absent — so the passes below may only prune a rule whose outcome
        // is *provably identical* to the covering rule's: same predicate
        // space AND same adapter (a dead covering target is skipped, then
        // the covered rule resolves — possibly to a different adapter).
        // `adapter_index` therefore feeds every prune key. Registry
        // liveness is runtime state (`update_proxies` can swap the map
        // without a rebuild), so it cannot be consulted here.
        let mut seen_ops: HashSet<(RuleType, bool, bool, String, usize)> = HashSet::new();
        let mut shadow_oracle = ShadowOracle::default();
        let mut dst_coverage: HashMap<usize, CidrCoverage> = HashMap::new();
        let mut src_coverage: HashMap<usize, CidrCoverage> = HashMap::new();
        let mut seen_ip_demand = false;
        let mut pruned_never_match = 0usize;
        let mut pruned_duplicates = 0usize;
        let mut pruned_shadowed = 0usize;
        let mut pruned_covered = 0usize;

        for (rule_index, rule) in rules.iter().enumerate() {
            let rule_type = rule.rule_type();
            let payload = rule.payload();
            let demands_ip = rule.should_resolve_ip();
            let demands_process = rule.should_find_process();
            // Payload-pure lowering first; then state-carrying native
            // lowering via downcast (Arc handles cloned once at build).
            let op = compile_op(rule_type, payload)
                .or_else(|| lower_native(rule.as_ref()))
                .unwrap_or(RuleOp::Fallback);

            // Constant-false pruning: drop rules that can never match, so
            // they neither occupy scan slots nor force metadata enrichment
            // (a dead GEOSITE rule must not force DNS pre-resolution).
            if rule.never_matches() {
                pruned_never_match += 1;
                continue;
            }

            // Constant folding: logic trees simplify (never-match children
            // erase OR arms and kill AND trees, double negation cancels).
            // A tree folding to `Never` joins the constant-false prune —
            // dropping its metadata demands with it, same as a dead GEOSITE
            // — and a tree folding to `Always` becomes an unconditional
            // MATCH terminator for the dead-rule pass below.
            let op = match fold_op(op) {
                Folded::Never => {
                    pruned_never_match += 1;
                    continue;
                }
                Folded::Always => RuleOp::Match,
                Folded::Op(op) => op,
            };

            // Intern the adapter early: every prune decision below needs the
            // rule's target identity (see the pass-invariant comment above).
            let adapter_name = SmolStr::from(rule.adapter());
            let adapter_index =
                intern_adapter(&mut adapter_names, &mut adapter_lookup, adapter_name);

            // Duplicate elimination on canonical predicate fingerprints: a
            // later rule with an identical predicate AND adapter can never
            // change the outcome — either both resolve or both are skipped
            // (issue #513 continue semantics: the adapter is part of the
            // key because a dead first target falls through to the twin).
            // Ops without a cheap canonical identity are never
            // deduplicated. The key includes the rule's enrichment demands:
            // an identical predicate carrying a *stronger* demand (a
            // resolving IP-CIDR after a no-resolve twin) must stay live as
            // the demand-stop carrier for the lazy scan — pruning it would
            // silently skip a DNS resolution whose result earlier rules
            // observe on the strict re-run.
            if let Some(fingerprint) = dedup_fingerprint(payload, &op) {
                if !seen_ops.insert((
                    rule_type,
                    demands_ip,
                    demands_process,
                    fingerprint,
                    adapter_index,
                )) {
                    pruned_duplicates += 1;
                    continue;
                }
            }

            // Shadowed-rule elimination: a domain-family predicate whose
            // match set is fully covered by earlier suffix / keyword /
            // star-wildcard rules with the SAME adapter can never change the
            // outcome — the covering rule resolves to the identical target,
            // live or skipped alike.
            if shadow_oracle.shadows(&op, payload, adapter_index) {
                pruned_shadowed += 1;
                continue;
            }
            shadow_oracle.absorb(&op, payload, adapter_index);

            // Covered-CIDR elimination: the IP analogue of shadowing, again
            // per adapter. The demand guard mirrors the dedup rule: if this
            // rule is the first to demand resolution, it must stay live as
            // the demand-stop carrier even though it can never win.
            if let RuleOp::IpCidr { net, src } = &op {
                let coverages = if *src {
                    &mut src_coverage
                } else {
                    &mut dst_coverage
                };
                let covered = coverages
                    .get(&adapter_index)
                    .is_some_and(|c| c.covers(*net));
                if covered && (!demands_ip || seen_ip_demand) {
                    pruned_covered += 1;
                    continue;
                }
                coverages
                    .entry(adapter_index)
                    .or_insert_with(CidrCoverage::new)
                    .absorb(*net);
            }

            needs_ip_resolution |= demands_ip;
            needs_process_lookup |= demands_process;
            seen_ip_demand |= demands_ip;

            let terminator = matches!(op, RuleOp::Match);

            slots.push(CompiledRuleSlot {
                rule_index: u32::try_from(rule_index).expect("rule index exceeds u32"),
                rule_type,
                adapter_index: u32::try_from(adapter_index).expect("adapter index exceeds u32"),
                target_plan: target_plan(rule_type),
                demands_ip,
                demands_process,
                op,
            });

            // Dead-rule elimination: an unconditional MATCH/FINAL ends the
            // reachable prefix — but only when its target is *guaranteed*
            // resolvable. The match-time predicate treats "DIRECT" as
            // always present (the tunnel owns the adapter), so
            // `MATCH,DIRECT` is a true terminator; any other target can be
            // skipped at match time, leaving the tail reachable
            // (issue #513).
            if terminator && rule.adapter() == "DIRECT" {
                break;
            }
        }

        if slots.len() < rules.len() {
            tracing::debug!(
                source = rules.len(),
                live = slots.len(),
                duplicates = pruned_duplicates,
                shadowed = pruned_shadowed,
                covered = pruned_covered,
                never_match = pruned_never_match,
                "rule IR clean-up passes pruned rules",
            );
        }

        let execution_plan = select_execution_plan(slots.len());
        let mut domain_index = DomainIndex::empty();
        if execution_plan == ExecutionPlan::DomainIndexed {
            // Build the index from live slots only, and hand fully-indexed
            // patterns over to the trie: an owned slot is never evaluated
            // during scans, because min-index search semantics guarantee a
            // trie hit at T proves no owned slot before T matches, and a
            // trie miss proves no owned slot matches at all.
            for slot in &mut slots {
                let owned = matches!(
                    slot.op,
                    RuleOp::Domain(_) | RuleOp::DomainSuffix(_) | RuleOp::DomainWildcard(_)
                ) && domain_index.insert_rule(
                    slot.rule_index(),
                    slot.rule_type,
                    rules[slot.rule_index()].payload(),
                );
                if owned {
                    slot.op = RuleOp::TrieOwned;
                }
            }
            domain_index.seal();
        }

        Self {
            slots,
            source_rule_count: rules.len(),
            adapter_names,
            adapter_lookup,
            domain_index,
            execution_plan,
            needs_ip_resolution,
            needs_process_lookup,
        }
    }

    /// Match metadata against the compiled plan with the same first-match
    /// semantics as `match_engine::match_rules`.
    ///
    /// `rules` must be the same rule slice this plan was built from. The plan
    /// stores rule indices rather than references so it can live beside an
    /// owned `Vec<Box<dyn Rule>>` in a route-table snapshot.
    ///
    /// `target_exists` reports whether a matched rule's target names a live
    /// registry entry (DIRECT/REJECT/GLOBAL included). A match on a missing
    /// target is skipped and the scan continues — mihomo's `match()` does
    /// `continue` on `proxies[adapter] == nil` (issue #513).
    pub fn match_rules<'a>(
        &'a self,
        metadata: &Metadata,
        rules: &'a [Box<dyn Rule>],
        target_exists: &dyn Fn(&str) -> bool,
    ) -> Option<CompiledMatchResult<'a>> {
        debug_assert_eq!(
            self.source_rule_count,
            rules.len(),
            "CompiledRuleSet must be evaluated with the rule slice it was built from",
        );

        let helper = RuleMatchHelper;
        let input = MatchInput::new(metadata);
        if self.execution_plan == ExecutionPlan::LinearScan {
            // EVAL_TRIE is inert under LinearScan (no trie, hence no owned
            // slots) — `true` keeps the scan correct if one ever appears.
            return self.scan_range::<true>(
                0..self.slots.len(),
                &input,
                rules,
                &helper,
                target_exists,
            );
        }

        let trie_hit = if input.host.is_empty() {
            None
        } else {
            self.domain_index.search(input.host)
        };

        // Preserve DomainIndex early-exit behavior: on a trie hit at rule
        // index T, scan only slots before T for an earlier match, then return
        // T. On trie miss, scan everything. The trie stores *rule* indices;
        // clean-up passes may have pruned slots, so map to a slot position by
        // binary search (slots are ordered by rule_index). A hit whose slot
        // was pruned degrades to a plain ordered scan, which stays correct:
        // the trie only ever points at a pattern's first occurrence, and a
        // hit past a MATCH terminator is preempted by the terminator slot.
        let (scan_end, hit_slot) = match trie_hit {
            Some(rule_idx) => {
                let pos = self.slots.partition_point(|s| s.rule_index() < rule_idx);
                let slot = self
                    .slots
                    .get(pos)
                    .filter(|slot| slot.rule_index() == rule_idx);
                (pos, slot)
            }
            None => (self.slots.len(), None),
        };

        // Prefix scan: EVAL_TRIE=false — the trie proved no owned slot
        // before `scan_end` matches this host.
        if let Some(matched) =
            self.scan_range::<false>(0..scan_end, &input, rules, &helper, target_exists)
        {
            return Some(matched);
        }

        // Upstream `continue` semantics: a matched trie hit with a missing
        // target is skipped and the scan resumes at the slot *after* it —
        // with EVAL_TRIE=true, because a second matching domain rule (also
        // trie-owned) may live in the tail and must be evaluated directly.
        let mut tail_start = scan_end;
        if let Some(slot) = hit_slot {
            let m = self.static_match(slot, rules);
            if target_exists(m.adapter_name) {
                return Some(m);
            }
            warn_missing_target(&m);
            tail_start += 1;
        }

        self.scan_range::<true>(
            tail_start..self.slots.len(),
            &input,
            rules,
            &helper,
            target_exists,
        )
    }

    /// Like [`Self::match_rules`], but with **demand-driven early stop**:
    /// the scan halts at the first slot whose predicate needs metadata the
    /// caller has not materialized yet (a resolved `dst_ip`, or process
    /// info), instead of evaluating it as a silent non-match.
    ///
    /// Callers use this as phase one of lazy enrichment: a connection whose
    /// match completes before any demanding slot never pays for DNS
    /// pre-resolution or a process-table walk. On
    /// [`LazyMatchOutcome::NeedsEnrichment`], materialize the reported
    /// fields and re-run [`Self::match_rules`] with the enriched metadata.
    /// Same `target_exists` contract as [`Self::match_rules`]: matched slots
    /// whose target is absent are skipped and the scan continues.
    pub fn match_rules_lazy<'a>(
        &'a self,
        metadata: &Metadata,
        rules: &'a [Box<dyn Rule>],
        target_exists: &dyn Fn(&str) -> bool,
    ) -> LazyMatchOutcome<'a> {
        debug_assert_eq!(
            self.source_rule_count,
            rules.len(),
            "CompiledRuleSet must be evaluated with the rule slice it was built from",
        );

        let helper = RuleMatchHelper;
        let input = MatchInput::new(metadata);
        if self.execution_plan == ExecutionPlan::LinearScan {
            return match self.scan_range_ctl::<true, true>(
                0..self.slots.len(),
                &input,
                rules,
                &helper,
                target_exists,
            ) {
                ScanOutcome::Matched(matched) => LazyMatchOutcome::Matched(matched),
                ScanOutcome::Blocked { pos } => self.enrichment_needs(pos, &input),
                ScanOutcome::Exhausted => LazyMatchOutcome::NoMatch,
            };
        }

        let trie_hit = if input.host.is_empty() {
            None
        } else {
            self.domain_index.search(input.host)
        };
        let (scan_end, hit_slot) = match trie_hit {
            Some(rule_idx) => {
                let pos = self.slots.partition_point(|s| s.rule_index() < rule_idx);
                let slot = self
                    .slots
                    .get(pos)
                    .filter(|slot| slot.rule_index() == rule_idx);
                (pos, slot)
            }
            None => (self.slots.len(), None),
        };

        match self.scan_range_ctl::<true, false>(0..scan_end, &input, rules, &helper, target_exists)
        {
            ScanOutcome::Matched(matched) => return LazyMatchOutcome::Matched(matched),
            // A blocked slot before the trie hit may match and beat it, so
            // enrichment is needed even though a domain rule stands ready.
            ScanOutcome::Blocked { pos } => return self.enrichment_needs(pos, &input),
            ScanOutcome::Exhausted => {}
        }

        let mut tail_start = scan_end;
        if let Some(slot) = hit_slot {
            let m = self.static_match(slot, rules);
            if target_exists(m.adapter_name) {
                return LazyMatchOutcome::Matched(m);
            }
            warn_missing_target(&m);
            tail_start += 1;
        }

        match self.scan_range_ctl::<true, true>(
            tail_start..self.slots.len(),
            &input,
            rules,
            &helper,
            target_exists,
        ) {
            ScanOutcome::Matched(matched) => LazyMatchOutcome::Matched(matched),
            ScanOutcome::Blocked { pos } => self.enrichment_needs(pos, &input),
            ScanOutcome::Exhausted => LazyMatchOutcome::NoMatch,
        }
    }

    /// Union the demands of every slot at or after `from_pos`, filtered to
    /// the fields actually missing from this connection's metadata, so one
    /// enrichment round suffices before the strict re-match.
    fn enrichment_needs(&self, from_pos: usize, input: &MatchInput<'_>) -> LazyMatchOutcome<'_> {
        let mut needs_ip = false;
        let mut needs_process = false;
        for slot in &self.slots[from_pos..] {
            needs_ip |= slot.demands_ip;
            needs_process |= slot.demands_process;
        }
        needs_ip &= ip_missing(input);
        needs_process &= process_missing(input.metadata);
        debug_assert!(
            needs_ip || needs_process,
            "scan blocked without an actionable demand",
        );
        LazyMatchOutcome::NeedsEnrichment {
            needs_ip,
            needs_process,
        }
    }

    pub fn domain_index(&self) -> &DomainIndex {
        &self.domain_index
    }

    pub fn slots(&self) -> &[CompiledRuleSlot] {
        &self.slots
    }

    pub fn adapter_names(&self) -> &[SmolStr] {
        &self.adapter_names
    }

    pub fn needs_ip_resolution(&self) -> bool {
        self.needs_ip_resolution
    }

    pub fn needs_process_lookup(&self) -> bool {
        self.needs_process_lookup
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn is_compatible_with(&self, rules: &[Box<dyn Rule>]) -> bool {
        self.source_rule_count == rules.len()
    }

    pub fn uses_linear_scan_plan(&self) -> bool {
        self.execution_plan == ExecutionPlan::LinearScan
    }

    fn scan_range<'a, const EVAL_TRIE: bool>(
        &'a self,
        range: Range<usize>,
        input: &MatchInput<'_>,
        rules: &'a [Box<dyn Rule>],
        helper: &RuleMatchHelper,
        target_exists: &dyn Fn(&str) -> bool,
    ) -> Option<CompiledMatchResult<'a>> {
        match self.scan_range_ctl::<false, EVAL_TRIE>(range, input, rules, helper, target_exists) {
            ScanOutcome::Matched(matched) => Some(matched),
            ScanOutcome::Blocked { .. } | ScanOutcome::Exhausted => None,
        }
    }

    /// `STOP_ON_DEMAND` is a const generic so the strict scan monomorphizes
    /// to the original tight loop — no per-slot demand branch, no position
    /// bookkeeping (measured: the runtime-bool version cost ~2.5x on a 10k
    /// wildcard-rule miss scan). `EVAL_TRIE` is likewise const: `false` only
    /// for the indexed plan's pre-hit prefix scan (the trie already proved
    /// those owned slots cannot match); `true` everywhere else, including
    /// post-skip tail scans where a second matching domain rule may live.
    ///
    /// A matched slot whose target is absent from the registry is warned and
    /// skipped (`continue`), matching mihomo's `match()` loop — one hash
    /// lookup per *matching* slot only, so the miss-scan hot path is
    /// unchanged (issue #513).
    fn scan_range_ctl<'a, const STOP_ON_DEMAND: bool, const EVAL_TRIE: bool>(
        &'a self,
        range: Range<usize>,
        input: &MatchInput<'_>,
        rules: &'a [Box<dyn Rule>],
        helper: &RuleMatchHelper,
        target_exists: &dyn Fn(&str) -> bool,
    ) -> ScanOutcome<'a> {
        let start = range.start;
        for (offset, slot) in self.slots[range].iter().enumerate() {
            if STOP_ON_DEMAND && slot_blocked(slot, input) {
                return ScanOutcome::Blocked {
                    pos: start + offset,
                };
            }
            let matched = match &slot.op {
                // Owned by the domain index. Prefix scans skip it — the
                // trie's min-index proof covers every owned slot consulted
                // there. Post-skip tail scans (EVAL_TRIE) must evaluate the
                // underlying rule directly: a *later* owned domain rule can
                // still match even though an earlier hit was skipped for a
                // dead target (issue #513 continue semantics).
                RuleOp::TrieOwned => {
                    if EVAL_TRIE {
                        rules.get(slot.rule_index()).and_then(|rule| {
                            rule.match_metadata(input.metadata, helper)
                                .then(|| self.static_match(slot, rules))
                        })
                    } else {
                        None
                    }
                }
                RuleOp::Fallback => {
                    let Some(rule) = rules.get(slot.rule_index()) else {
                        return ScanOutcome::Exhausted;
                    };
                    match slot.target_plan {
                        TargetPlan::StaticAdapter => rule
                            .match_metadata(input.metadata, helper)
                            .then(|| self.static_match(slot, rules)),
                        TargetPlan::DynamicAdapter => rule
                            .match_and_resolve(input.metadata, helper)
                            .map(|adapter_name| {
                                let adapter_index = self.adapter_lookup.get(adapter_name).copied();
                                self.make_match(slot, rules, adapter_name, adapter_index)
                            }),
                    }
                }
                op => matches_op(op, input, helper).then(|| self.static_match(slot, rules)),
            };
            if let Some(m) = matched {
                if target_exists(m.adapter_name) {
                    return ScanOutcome::Matched(m);
                }
                warn_missing_target(&m);
            }
        }
        ScanOutcome::Exhausted
    }

    fn static_match<'a>(
        &'a self,
        slot: &'a CompiledRuleSlot,
        rules: &'a [Box<dyn Rule>],
    ) -> CompiledMatchResult<'a> {
        self.make_match(
            slot,
            rules,
            self.adapter_names[slot.adapter_index()].as_str(),
            Some(slot.adapter_index()),
        )
    }

    fn make_match<'a>(
        &'a self,
        slot: &'a CompiledRuleSlot,
        rules: &'a [Box<dyn Rule>],
        adapter_name: &'a str,
        adapter_index: Option<usize>,
    ) -> CompiledMatchResult<'a> {
        CompiledMatchResult {
            adapter_name,
            adapter_index,
            rule_type: slot.rule_type,
            // Borrowed from the source rule: the plan keeps no payload copy.
            rule_payload: rules.get(slot.rule_index()).map_or("", |r| r.payload()),
            rule_index: slot.rule_index(),
        }
    }
}

impl<'a> MatchInput<'a> {
    fn new(metadata: &'a Metadata) -> Self {
        Self {
            metadata,
            host: metadata.rule_host(),
        }
    }
}

impl CompiledRuleSlot {
    pub fn rule_index(&self) -> usize {
        self.rule_index as usize
    }

    pub fn rule_type(&self) -> RuleType {
        self.rule_type
    }

    pub fn adapter_index(&self) -> usize {
        self.adapter_index as usize
    }

    pub fn has_dynamic_adapter(&self) -> bool {
        self.target_plan == TargetPlan::DynamicAdapter
    }

    pub fn is_lowered(&self) -> bool {
        !matches!(self.op, RuleOp::Fallback)
    }

    /// True iff the domain index fully owns this slot's match semantics.
    pub fn is_trie_owned(&self) -> bool {
        matches!(self.op, RuleOp::TrieOwned)
    }
}

fn intern_adapter(
    adapter_names: &mut Vec<SmolStr>,
    adapter_lookup: &mut HashMap<SmolStr, usize>,
    adapter_name: SmolStr,
) -> usize {
    if let Some(index) = adapter_lookup.get(&adapter_name) {
        return *index;
    }

    let index = adapter_names.len();
    adapter_names.push(adapter_name.clone());
    adapter_lookup.insert(adapter_name, index);
    index
}

fn target_plan(rule_type: RuleType) -> TargetPlan {
    match rule_type {
        // SUB-RULE returns the matched inner rule's adapter, not the outer
        // rule's adapter/block name.
        RuleType::SubRule => TargetPlan::DynamicAdapter,
        _ => TargetPlan::StaticAdapter,
    }
}

fn select_execution_plan(rule_count: usize) -> ExecutionPlan {
    if rule_count <= LINEAR_SCAN_RULE_LIMIT {
        ExecutionPlan::LinearScan
    } else {
        ExecutionPlan::DomainIndexed
    }
}

/// Canonical dedup fingerprint for a lowered predicate, or `None` for ops
/// with no cheap canonical identity (logic trees, IP-SUFFIX matchers, and
/// fallback rules with private state).
///
/// The fingerprint identifies the op's *match semantics*, not its source
/// text: domain-family payloads are case-folded (their matchers compare
/// hosts case-insensitively), CIDR host bits are truncated at compile time,
/// port lists are sorted and merged, and shared-state handles (GEOSITE /
/// RULE-SET / GEOIP tries) compare by pointer identity plus resolved keys.
/// Keyed together with `RuleType`, equal fingerprints mean equal predicates.
/// A missed dedup is only a lost optimization, never a correctness issue.
fn dedup_fingerprint(payload: &str, op: &RuleOp) -> Option<String> {
    match op {
        // These ops store their payload pre-folded / pre-canonicalized.
        RuleOp::Domain(host) | RuleOp::DomainSuffix(host) | RuleOp::DomainKeyword(host) => {
            Some(host.to_string())
        }
        RuleOp::ProcessName(_) | RuleOp::DomainWildcard(_) => Some(payload.to_ascii_lowercase()),
        RuleOp::DomainRegex(_)
        | RuleOp::ProcessPath(_)
        | RuleOp::InName(_)
        | RuleOp::InUser(_)
        | RuleOp::Match => Some(payload.to_string()),
        // `compile_op` stores the truncated network, so textual host-bit
        // variants ("10.1.2.3/8" vs "10.0.0.0/8") render identically.
        RuleOp::IpCidr { net, .. } => Some(net.to_string()),
        RuleOp::SrcPort(matcher) | RuleOp::DstPort(matcher) | RuleOp::InPort(matcher) => {
            Some(port_fingerprint(matcher))
        }
        RuleOp::Dscp(value) => Some(value.to_string()),
        RuleOp::Uid(uid) => Some(uid.to_string()),
        RuleOp::Network(network) => Some(format!("{network:?}")),
        RuleOp::InType(mask) => Some(format!(
            "{}{}{}{}{}",
            u8::from(mask.http),
            u8::from(mask.https),
            u8::from(mask.socks5),
            u8::from(mask.tproxy),
            u8::from(mask.inner)
        )),
        // Shared-state handles: pointer identity means the same immutable
        // trie/set, so the predicates are interchangeable. GEOSITE also keys
        // on its resolved bucket keys ("google" vs "GOOGLE" fold together).
        RuleOp::GeoSite(geosite) => Some(format!(
            "{:p}|{}",
            Arc::as_ptr(&geosite.db),
            geosite.keys.join(",")
        )),
        RuleOp::RuleSetRef(handle) => Some(format!("{:p}", Arc::as_ptr(&handle.0))),
        RuleOp::IpRanges { set, src } => Some(format!("{:p}|{src}", Arc::as_ptr(set))),
        RuleOp::IpSuffix(_)
        | RuleOp::AllOf(_)
        | RuleOp::AnyOf(_)
        | RuleOp::NotOp(_)
        | RuleOp::TrieOwned
        | RuleOp::Fallback => None,
    }
}

/// Serialize a canonical (sorted, merged — see [`compile_port_matcher`])
/// port matcher for dedup fingerprinting.
fn port_fingerprint(matcher: &PortMatcher) -> String {
    fn span(range: &PortRange) -> String {
        match range {
            PortRange::Single(value) => value.to_string(),
            PortRange::Range(lo, hi) => format!("{lo}-{hi}"),
        }
    }
    match matcher {
        PortMatcher::Single(value) => value.to_string(),
        PortMatcher::Range(lo, hi) => format!("{lo}-{hi}"),
        PortMatcher::Multiple(ranges) => ranges.iter().map(span).collect::<Vec<_>>().join(","),
    }
}

/// Build-time oracle for **shadowed-rule elimination** (clean-up pass 4):
/// answers whether a domain-family predicate's match set is fully covered by
/// rules seen earlier in the list. Under first-match-wins a covered rule can
/// never fire — every host it matches is claimed by an earlier rule — so it
/// is pruned regardless of its adapter, which is observation-equivalent.
///
/// Coverage sources are the three shapes with cheap byte-wise subset proofs:
/// DOMAIN-SUFFIX (covers itself and dot-boundary suffixes), star-shaped
/// `*.rest` DOMAIN-WILDCARD (covers exactly-one-extra-label hosts), and
/// DOMAIN-KEYWORD (covers any pattern containing the keyword). All entries
/// and probes are ASCII-lowercased, mirroring the matchers'
/// `eq_ignore_ascii_case` byte semantics — the proofs hold byte-for-byte
/// even for degenerate or non-ASCII payloads.
#[derive(Default)]
struct ShadowOracle {
    /// Lowered DOMAIN-SUFFIX payloads seen so far, keyed to the rule's
    /// adapter: a cover only proves the shadowed rule dead when it shares
    /// the covering rule's adapter (issue #513 continue semantics).
    suffixes: HashMap<String, usize>,
    /// Lowered `rest` of star-shaped `*.rest` DOMAIN-WILDCARD payloads.
    star_rests: HashMap<String, usize>,
    /// Lowered DOMAIN-KEYWORD payloads seen so far.
    keywords: Vec<(String, usize)>,
}

impl ShadowOracle {
    /// Record a surviving rule's coverage. Empty payloads are excluded: an
    /// empty keyword matches every host and would need MATCH-terminator
    /// treatment, not subset reasoning.
    fn absorb(&mut self, op: &RuleOp, payload: &str, adapter_index: usize) {
        match op {
            RuleOp::DomainSuffix(suffix) if !suffix.is_empty() => {
                self.suffixes.insert(suffix.to_string(), adapter_index);
            }
            RuleOp::DomainKeyword(keyword) if !keyword.is_empty() => {
                self.keywords.push((keyword.to_string(), adapter_index));
            }
            RuleOp::DomainWildcard(_) => {
                if let Some(rest) = star_rest(payload) {
                    self.star_rests.insert(rest, adapter_index);
                }
            }
            _ => {}
        }
    }

    /// True iff earlier rules WITH THIS ADAPTER cover every host this
    /// predicate matches — the only cover that is dead under
    /// continue-on-missing-target.
    fn shadows(&self, op: &RuleOp, payload: &str, adapter_index: usize) -> bool {
        match op {
            RuleOp::Domain(domain) => {
                self.suffix_covers(domain, adapter_index)
                    || self.keyword_covers(domain, adapter_index)
                    || self.star_covers(domain, adapter_index)
            }
            RuleOp::DomainSuffix(suffix) => {
                self.suffix_covers(suffix, adapter_index)
                    || self.keyword_covers(suffix, adapter_index)
            }
            RuleOp::DomainKeyword(keyword) => self.keyword_covers(keyword, adapter_index),
            // Only the star shape has an exact host-set description; every
            // other wildcard shape stays conservatively unpruned.
            RuleOp::DomainWildcard(_) => star_rest(payload).is_some_and(|rest| {
                self.suffix_covers(&rest, adapter_index)
                    || self.keyword_covers(&rest, adapter_index)
            }),
            _ => false,
        }
    }

    /// Some earlier DOMAIN-SUFFIX (with this adapter) matches every host
    /// `pattern` can match: an entry equals `pattern` or is a dot-boundary
    /// suffix of it.
    fn suffix_covers(&self, pattern: &str, adapter_index: usize) -> bool {
        if self.suffixes.is_empty() {
            return false;
        }
        let mut start = 0;
        loop {
            if self.suffixes.get(&pattern[start..]) == Some(&adapter_index) {
                return true;
            }
            match pattern[start..].find('.') {
                Some(dot) => start += dot + 1,
                None => return false,
            }
        }
    }

    /// Some earlier DOMAIN-KEYWORD (with this adapter) is a substring of
    /// `pattern`: every host containing `pattern` (or equal to it, or
    /// ending with it) contains the keyword too.
    fn keyword_covers(&self, pattern: &str, adapter_index: usize) -> bool {
        self.keywords
            .iter()
            .any(|(keyword, a)| *a == adapter_index && pattern.contains(keyword.as_str()))
    }

    /// Some earlier star wildcard `*.rest` (with this adapter) matches
    /// exactly the host `domain`: it splits as `<one non-empty label>.rest`.
    fn star_covers(&self, domain: &str, adapter_index: usize) -> bool {
        if self.star_rests.is_empty() {
            return false;
        }
        domain.split_once('.').is_some_and(|(label, rest)| {
            !label.is_empty() && self.star_rests.get(rest) == Some(&adapter_index)
        })
    }
}

/// The lowered `rest` of a star-shaped `*.rest` DOMAIN-WILDCARD payload —
/// the only wildcard shape whose host set is exactly describable (one
/// non-empty dot-free extra label, per [`GlobMatcher`] semantics). `None`
/// for every other shape.
fn star_rest(payload: &str) -> Option<String> {
    let rest = payload.strip_prefix("*.")?;
    (!rest.is_empty() && !rest.contains('*')).then(|| rest.to_ascii_lowercase())
}

/// Ops that are compile-time-provably false on this platform.
fn op_never_matches(op: &RuleOp) -> bool {
    // Socket-UID lookup only exists on Linux; `uid_matches` is a constant
    // `false` everywhere else, so the slot would burn a scan step per
    // connection without ever matching.
    matches!(op, RuleOp::Uid(_)) && cfg!(not(target_os = "linux"))
}

/// Three-valued constant-folding result for a lowered op.
enum Folded {
    /// Provably matches no metadata on this platform.
    Never,
    /// Provably matches every metadata (vacuous AND, NOT of never-match).
    Always,
    Op(RuleOp),
}

/// Constant-fold a lowered op (clean-up pass 3). Logic trees simplify
/// bottom-up: a never-match child kills an AND and vanishes from an OR, an
/// always-match child vanishes from an AND and satisfies an OR, `NOT`
/// inverts constants, and single-child trees collapse to the child. All
/// folds mirror `matches_native_op`'s `all` / `any` / `!` evaluation
/// exactly, so they are observation-equivalent; `Never` / `Always` leaves
/// come only from compile-time-constant predicates (`MATCH`, platform
/// never-match ops), never from metadata-dependent ones.
fn fold_op(op: RuleOp) -> Folded {
    if op_never_matches(&op) {
        return Folded::Never;
    }
    match op {
        RuleOp::Match => Folded::Always,
        RuleOp::AllOf(children) => {
            let mut kept = Vec::with_capacity(children.len());
            for child in children.into_vec() {
                match fold_op(child) {
                    Folded::Never => return Folded::Never,
                    Folded::Always => {}
                    Folded::Op(folded) => kept.push(folded),
                }
            }
            match kept.len() {
                0 => Folded::Always,
                1 => Folded::Op(kept.remove(0)),
                _ => Folded::Op(RuleOp::AllOf(kept.into())),
            }
        }
        RuleOp::AnyOf(children) => {
            let mut kept = Vec::with_capacity(children.len());
            for child in children.into_vec() {
                match fold_op(child) {
                    Folded::Always => return Folded::Always,
                    Folded::Never => {}
                    Folded::Op(folded) => kept.push(folded),
                }
            }
            match kept.len() {
                0 => Folded::Never,
                1 => Folded::Op(kept.remove(0)),
                _ => Folded::Op(RuleOp::AnyOf(kept.into())),
            }
        }
        RuleOp::NotOp(child) => match fold_op(*child) {
            Folded::Never => Folded::Always,
            Folded::Always => Folded::Never,
            Folded::Op(folded) => Folded::Op(RuleOp::NotOp(Box::new(folded))),
        },
        other => Folded::Op(other),
    }
}

/// Cumulative coverage of earlier IP-CIDR networks (one instance per
/// src/dst axis) for **covered-CIDR elimination** — the IP analogue of
/// `ShadowOracle`. A later network fully contained in the union of earlier
/// same-axis networks can never fire: any address it matches already
/// matched some earlier rule, and both sides share the same
/// `ip.is_some()` gate.
struct CidrCoverage {
    /// Sorted, disjoint, coalesced inclusive intervals per family.
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrCoverage {
    fn new() -> Self {
        Self {
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }

    fn covers(&self, net: IpNet) -> bool {
        match net {
            IpNet::V4(v4) => {
                interval_covers(&self.v4, u32::from(v4.network()), u32::from(v4.broadcast()))
            }
            IpNet::V6(v6) => interval_covers(
                &self.v6,
                u128::from(v6.network()),
                u128::from(v6.broadcast()),
            ),
        }
    }

    /// Insertion merges overlapping and adjacent blocks, so containment sees
    /// the true union (10.0.0.0/9 + 10.128.0.0/9 covers a later 10.0.0.0/8).
    fn absorb(&mut self, net: IpNet) {
        match net {
            IpNet::V4(v4) => interval_insert(
                &mut self.v4,
                u32::from(v4.network()),
                u32::from(v4.broadcast()),
                |a| a.checked_add(1),
            ),
            IpNet::V6(v6) => interval_insert(
                &mut self.v6,
                u128::from(v6.network()),
                u128::from(v6.broadcast()),
                |a| a.checked_add(1),
            ),
        }
    }
}

/// True iff `[start, end]` lies inside one interval of a sorted, disjoint
/// interval list.
fn interval_covers<A: Copy + Ord>(intervals: &[(A, A)], start: A, end: A) -> bool {
    let idx = intervals.partition_point(|&(s, _)| s <= start);
    idx > 0 && end <= intervals[idx - 1].1
}

/// Insert `[start, end]` into a sorted, disjoint interval list, merging
/// every interval it overlaps or touches.
fn interval_insert<A: Copy + Ord>(
    intervals: &mut Vec<(A, A)>,
    start: A,
    end: A,
    next: impl Fn(A) -> Option<A>,
) {
    // First interval that is not strictly left of (and not adjacent to) us.
    let first = intervals.partition_point(|&(_, e)| next(e).is_some_and(|n| n < start));
    // One past the last interval that starts at or before `end + 1`.
    let last = first
        + intervals[first..].partition_point(|&(s, _)| match next(end) {
            Some(n) => s <= n,
            None => true,
        });
    if first == last {
        intervals.insert(first, (start, end));
        return;
    }
    let merged_start = start.min(intervals[first].0);
    let merged_end = end.max(intervals[last - 1].1);
    intervals.drain(first + 1..last);
    intervals[first] = (merged_start, merged_end);
}

fn compile_op(rule_type: RuleType, payload: &str) -> Option<RuleOp> {
    match rule_type {
        RuleType::Domain => Some(RuleOp::Domain(payload.to_ascii_lowercase().into())),
        RuleType::DomainSuffix => Some(RuleOp::DomainSuffix(payload.to_ascii_lowercase().into())),
        RuleType::DomainKeyword => Some(RuleOp::DomainKeyword(payload.to_ascii_lowercase().into())),
        RuleType::DomainRegex => compile_domain_regex(payload).map(RuleOp::DomainRegex),
        RuleType::DomainWildcard => compile_domain_wildcard(payload).map(RuleOp::DomainWildcard),
        // Host bits are truncated at compile time: matching only consults
        // the network prefix, and the canonical form lets textual variants
        // of the same network share one dedup fingerprint.
        RuleType::IpCidr => payload.parse().ok().map(|net: IpNet| RuleOp::IpCidr {
            net: net.trunc(),
            src: false,
        }),
        RuleType::SrcIpCidr => payload.parse().ok().map(|net: IpNet| RuleOp::IpCidr {
            net: net.trunc(),
            src: true,
        }),
        RuleType::SrcPort => compile_port_matcher(payload).map(RuleOp::SrcPort),
        RuleType::DstPort => compile_port_matcher(payload).map(RuleOp::DstPort),
        RuleType::InPort => compile_in_port(payload),
        RuleType::Dscp => payload
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|v| *v <= 63)
            .map(RuleOp::Dscp),
        RuleType::ProcessName => Some(RuleOp::ProcessName(payload.into())),
        RuleType::ProcessPath => {
            compile_process_path(payload).map(|op| RuleOp::ProcessPath(Box::new(op)))
        }
        RuleType::Network => compile_network(payload),
        RuleType::Uid => payload.trim().parse::<u32>().ok().map(RuleOp::Uid),
        RuleType::InName => Some(RuleOp::InName(payload.into())),
        RuleType::InType => compile_in_type(payload).map(RuleOp::InType),
        RuleType::InUser => Some(RuleOp::InUser(payload.into())),
        RuleType::Match => Some(RuleOp::Match),
        RuleType::GeoSite
        | RuleType::GeoIp
        | RuleType::SrcGeoIp
        | RuleType::RuleSet
        | RuleType::And
        | RuleType::Or
        | RuleType::Not
        | RuleType::IpSuffix
        | RuleType::IpAsn
        | RuleType::SubRule => None,
    }
}

/// Lower a rule that `compile_op` declined, by downcasting to the concrete
/// types whose match state is cheap to share. Returns `None` for rules that
/// must stay on the virtual-dispatch fallback path.
fn lower_native(rule: &dyn Rule) -> Option<RuleOp> {
    let any = rule.as_any()?;
    if let Some(geo) = any.downcast_ref::<GeoSiteRule>() {
        let db = geo.db()?;
        // `resolve_keys` returning None means the rule can never match;
        // `never_matches` already pruned that case before lowering runs.
        let keys = db.resolve_keys(geo.category())?;
        return Some(RuleOp::GeoSite(Box::new(GeoSiteOp {
            db: Arc::clone(db),
            keys: keys.into_iter().map(String::into_boxed_str).collect(),
        })));
    }
    if let Some(rule_set) = any.downcast_ref::<RuleSetRule>() {
        return Some(RuleOp::RuleSetRef(RuleSetHandle(Arc::clone(
            rule_set.rule_set(),
        ))));
    }
    if let Some(geoip) = any.downcast_ref::<GeoIpRule>() {
        return Some(RuleOp::IpRanges {
            set: Arc::clone(geoip.ranges()),
            src: false,
        });
    }
    if let Some(src_geoip) = any.downcast_ref::<SrcGeoIpRule>() {
        return Some(RuleOp::IpRanges {
            set: Arc::clone(src_geoip.ranges()),
            src: true,
        });
    }
    if let Some(asn) = any.downcast_ref::<IpAsnRule>() {
        return Some(RuleOp::IpRanges {
            set: Arc::clone(asn.ranges()),
            src: asn.is_src(),
        });
    }
    if let Some(suffix) = any.downcast_ref::<IpSuffixRule>() {
        return Some(RuleOp::IpSuffix(Box::new(IpSuffixOp {
            matcher: suffix.matcher(),
            src: suffix.is_src(),
        })));
    }
    if let Some(and) = any.downcast_ref::<AndRule>() {
        return lower_children(and.sub_rules()).map(RuleOp::AllOf);
    }
    if let Some(or) = any.downcast_ref::<OrRule>() {
        return lower_children(or.sub_rules()).map(RuleOp::AnyOf);
    }
    if let Some(not) = any.downcast_ref::<NotRule>() {
        return lower_rule(not.inner()).map(|op| RuleOp::NotOp(Box::new(op)));
    }
    None
}

/// Lower any rule: payload-pure predicates first, then native state
/// lowering. Used for logic-rule children, where one non-lowerable child
/// keeps the whole logic rule on the fallback path.
fn lower_rule(rule: &dyn Rule) -> Option<RuleOp> {
    compile_op(rule.rule_type(), rule.payload()).or_else(|| lower_native(rule))
}

fn lower_children(rules: &[Box<dyn Rule>]) -> Option<Box<[RuleOp]>> {
    rules.iter().map(|rule| lower_rule(rule.as_ref())).collect()
}

/// Evaluate the state-carrying native ops (and logic trees, which recurse
/// back into `matches_op`). Deliberately `#[inline(never)]`: these arms are
/// fat (hash lookups, virtual calls, recursion), and folding them into
/// `matches_op` pushed it past the inline threshold — the scan loop then
/// paid an outlined call per slot even for one-comparison ops, measured as
/// a 2.3x slowdown on a 10k-rule wildcard miss scan.
#[inline(never)]
fn matches_native_op(op: &RuleOp, input: &MatchInput<'_>, helper: &RuleMatchHelper) -> bool {
    match op {
        RuleOp::GeoSite(geosite) => {
            !input.host.is_empty()
                && geosite
                    .keys
                    .iter()
                    .all(|key| geosite.db.lookup_resolved(key, input.host))
        }
        RuleOp::RuleSetRef(handle) => handle.0.matches(input.metadata, helper),
        RuleOp::IpRanges { set, src } => {
            let ip = if *src {
                input.metadata.src_ip
            } else {
                input.metadata.dst_ip
            };
            ip.is_some_and(|ip| set.contains(ip))
        }
        RuleOp::IpSuffix(suffix) => {
            let ip = if suffix.src {
                input.metadata.src_ip
            } else {
                input.metadata.dst_ip
            };
            ip.is_some_and(|addr| suffix.matcher.matches(addr))
        }
        RuleOp::AllOf(children) => children.iter().all(|op| matches_op(op, input, helper)),
        RuleOp::AnyOf(children) => children.iter().any(|op| matches_op(op, input, helper)),
        RuleOp::NotOp(child) => !matches_op(child, input, helper),
        other => matches_op(other, input, helper),
    }
}

/// `#[inline(always)]`: the workspace ships at `opt-level = "z"`, whose
/// inline threshold rejects this function once it has a full opcode match —
/// leaving the scan loop paying an outlined call per slot even for
/// one-comparison predicates (measured 2.3x on a 10k wildcard-rule scan).
/// The body is deliberately kept slim by routing every fat arm through
/// `matches_native_op`.
#[inline(always)]
fn matches_op(op: &RuleOp, input: &MatchInput<'_>, helper: &RuleMatchHelper) -> bool {
    match op {
        RuleOp::GeoSite(_)
        | RuleOp::RuleSetRef(_)
        | RuleOp::IpRanges { .. }
        | RuleOp::IpSuffix(_)
        | RuleOp::AllOf(_)
        | RuleOp::AnyOf(_)
        | RuleOp::NotOp(_) => matches_native_op(op, input, helper),
        RuleOp::Domain(domain) => input.host.eq_ignore_ascii_case(domain),
        RuleOp::DomainSuffix(suffix) => domain_suffix_matches(input.host, suffix),
        RuleOp::DomainKeyword(keyword) => domain_keyword_matches(input.host, keyword),
        RuleOp::DomainRegex(regex) => regex.matches(input.host),
        RuleOp::DomainWildcard(matcher) => matcher.matches(input.host),
        RuleOp::IpCidr { net, src } => {
            let ip = if *src {
                input.metadata.src_ip
            } else {
                input.metadata.dst_ip
            };
            ip.is_some_and(|addr| net.contains(&addr))
        }
        RuleOp::SrcPort(matcher) => matcher.matches(input.metadata.src_port),
        RuleOp::DstPort(matcher) => matcher.matches(input.metadata.dst_port),
        RuleOp::InPort(matcher) => {
            input.metadata.in_port != 0 && matcher.matches(input.metadata.in_port)
        }
        RuleOp::Dscp(value) => input.metadata.dscp == Some(*value),
        RuleOp::ProcessName(name) => input.metadata.process.eq_ignore_ascii_case(name),
        RuleOp::ProcessPath(op) => process_path_matches(op, &input.metadata.process_path),
        RuleOp::Network(network) => input.metadata.network == *network,
        RuleOp::Uid(uid) => uid_matches(input.metadata, *uid),
        RuleOp::InName(name) => {
            !input.metadata.in_name.is_empty() && input.metadata.in_name.as_str() == &**name
        }
        RuleOp::InType(mask) => in_type_matches(*mask, input.metadata.conn_type),
        RuleOp::InUser(user) => input.metadata.in_user.as_deref() == Some(&**user),
        RuleOp::Match => true,
        RuleOp::TrieOwned | RuleOp::Fallback => false,
    }
}

fn domain_suffix_matches(host: &str, suffix: &str) -> bool {
    let host = host.as_bytes();
    let suffix = suffix.as_bytes();
    if host.len() == suffix.len() {
        return host.eq_ignore_ascii_case(suffix);
    }
    if host.len() > suffix.len() {
        let dot_pos = host.len() - suffix.len() - 1;
        return host[dot_pos] == b'.' && host[dot_pos + 1..].eq_ignore_ascii_case(suffix);
    }
    false
}

fn domain_keyword_matches(host: &str, keyword: &str) -> bool {
    let host = host.as_bytes();
    let needle = keyword.as_bytes();
    if needle.is_empty() {
        return true;
    }
    if host.len() < needle.len() {
        return false;
    }
    host.windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

impl RegexMatcher {
    fn matches(&self, host: &str) -> bool {
        if let Some(required_literal) = &self.required_literal {
            if !domain_keyword_matches(host, required_literal) {
                return false;
            }
        }
        self.regex.is_match(host)
    }
}

fn compile_domain_regex(pattern: &str) -> Option<Box<RegexMatcher>> {
    Some(Box::new(RegexMatcher {
        regex: Regex::new(pattern).ok()?,
        required_literal: required_literal_from_plain_regex(pattern),
    }))
}

/// A compiled DOMAIN-WILDCARD matcher.
///
/// Almost all wildcard patterns lower to a structural [`GlobMatcher`] that
/// matches with byte comparisons and never touches the regex engine on the
/// rule hot path. The rare shape the structural matcher declines (adjacent
/// `*`, i.e. an empty interior segment) falls back to the original anchored
/// regex so semantics stay identical.
#[derive(Debug, Clone)]
enum WildcardMatcher {
    Glob(GlobMatcher),
    Regex(Box<RegexMatcher>),
}

impl WildcardMatcher {
    #[inline(always)]
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Glob(glob) => glob.matches(host),
            Self::Regex(regex) => regex.matches(host),
        }
    }
}

/// Structural matcher for DOMAIN-WILDCARD patterns.
///
/// A wildcard pattern is a list of literal pieces separated by `*`, where each
/// `*` matches one or more non-`.` bytes (a single DNS label fragment). This
/// reproduces the wildcard regex `^(?i)<escaped, \* -> [^.]+>$` exactly for the
/// ASCII hostnames that reach rule matching, but evaluates with anchored
/// byte comparisons instead of running the regex engine per connection.
#[derive(Debug, Clone)]
struct GlobMatcher {
    /// Literal pieces in pattern order. The first piece is anchored at the
    /// start of the host and the last piece at the end; every adjacent pair is
    /// separated by exactly one `*` consuming one or more non-`.` bytes. A
    /// single piece (no `*`) degenerates to an exact match.
    pieces: Box<[Box<[u8]>]>,
}

impl GlobMatcher {
    /// Compile a wildcard pattern into anchored literal pieces, or return
    /// `None` for shapes the structural matcher does not handle (adjacent `*`,
    /// which leaves an empty interior piece) so the caller can fall back to a
    /// regex.
    fn compile(pattern: &str) -> Option<Self> {
        let parts: Vec<&str> = pattern.split('*').collect();
        // An interior piece sits between two stars; since each star already
        // requires >=1 byte, an empty interior piece means adjacent stars,
        // which we leave to the regex fallback rather than special-case here.
        if parts.len() >= 3 && parts[1..parts.len() - 1].iter().any(|p| p.is_empty()) {
            return None;
        }
        let pieces = parts
            .into_iter()
            .map(|p| Box::<[u8]>::from(p.as_bytes()))
            .collect();
        Some(Self { pieces })
    }

    #[inline(always)]
    fn matches(&self, host: &str) -> bool {
        let host = host.as_bytes();
        let pieces = &self.pieces;

        // No `*`: exact, case-insensitive match.
        if pieces.len() == 1 {
            return host.eq_ignore_ascii_case(&pieces[0]);
        }

        // First piece anchored at the start.
        let first = &pieces[0];
        if host.len() < first.len() || !host[..first.len()].eq_ignore_ascii_case(first) {
            return false;
        }
        let mut pos = first.len();

        // Interior pieces float: each is preceded by a `*` that must consume a
        // non-empty, dot-free gap. Match each at its earliest valid position,
        // which leaves the most host for the remaining pieces.
        for mid in &pieces[1..pieces.len() - 1] {
            match find_after_dotfree_gap(host, pos, mid) {
                Some(start) => pos = start + mid.len(),
                None => return false,
            }
        }

        // Last piece anchored at the end, preceded by a non-empty dot-free gap.
        let last = &pieces[pieces.len() - 1];
        if host.len() < last.len() {
            return false;
        }
        let tail_start = host.len() - last.len();
        if tail_start <= pos {
            return false;
        }
        if !host[tail_start..].eq_ignore_ascii_case(last) {
            return false;
        }
        !host[pos..tail_start].contains(&b'.')
    }
}

/// Earliest `start > pos` such that `host[pos..start]` is non-empty and
/// dot-free and `needle` matches case-insensitively at `start`. Returns `None`
/// once a `.` in the gap rules out any later start, or `needle` cannot fit.
/// `needle` is always non-empty (empty interior pieces are rejected at compile
/// time).
fn find_after_dotfree_gap(host: &[u8], pos: usize, needle: &[u8]) -> Option<usize> {
    let mut start = pos + 1;
    while start + needle.len() <= host.len() {
        // The byte just added to the gap must not be a dot; once it is, no
        // later start keeps the gap dot-free either.
        if host[start - 1] == b'.' {
            return None;
        }
        if host[start..start + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(start);
        }
        start += 1;
    }
    None
}

fn compile_domain_wildcard(pattern: &str) -> Option<Box<WildcardMatcher>> {
    if let Some(glob) = GlobMatcher::compile(pattern) {
        return Some(Box::new(WildcardMatcher::Glob(glob)));
    }
    // Fallback for shapes the structural matcher declines: keep the original
    // anchored regex so wildcard semantics remain identical.
    let escaped = regex::escape(pattern);
    let expanded = escaped.replace(r"\*", r"[^.]+");
    Some(Box::new(WildcardMatcher::Regex(Box::new(RegexMatcher {
        regex: Regex::new(&format!("^(?i){expanded}$")).ok()?,
        required_literal: required_literal_from_wildcard(pattern),
    }))))
}

fn required_literal_from_plain_regex(pattern: &str) -> Option<String> {
    if pattern.is_empty() || pattern.bytes().any(is_regex_meta_byte) {
        return None;
    }
    Some(pattern.to_ascii_lowercase())
}

fn required_literal_from_wildcard(pattern: &str) -> Option<String> {
    pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .max_by_key(|part| part.len())
        .map(str::to_ascii_lowercase)
}

fn is_regex_meta_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'\\'
            | b'.'
            | b'+'
            | b'*'
            | b'?'
            | b'('
            | b')'
            | b'|'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'^'
            | b'$'
    )
}

impl PortMatcher {
    fn matches(&self, port: u16) -> bool {
        match self {
            Self::Single(value) => port == *value,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
            Self::Multiple(ranges) => ranges.iter().any(|range| range.matches(port)),
        }
    }
}

impl PortRange {
    fn matches(&self, port: u16) -> bool {
        match self {
            Self::Single(value) => port == *value,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
        }
    }
}

fn compile_port_matcher(payload: &str) -> Option<PortMatcher> {
    let mut spans: Vec<(u16, u16)> = Vec::new();
    for part in payload.split([',', '/']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = start.trim().parse().ok()?;
            let end = end.trim().parse().ok()?;
            if start > end {
                return None;
            }
            spans.push((start, end));
        } else {
            let value = part.parse().ok()?;
            spans.push((value, value));
        }
    }
    // Canonicalize: sort by low bound and merge overlapping or adjacent
    // spans. Matching is order-independent (`any`), so this is
    // semantics-preserving; it collapses textual variants ("443,80" vs
    // "80,443", "80-90/85-100" vs "80-100") onto one dedup fingerprint and
    // keeps `Multiple` scans minimal.
    spans.sort_unstable();
    let mut merged: Vec<(u16, u16)> = Vec::with_capacity(spans.len());
    for (lo, hi) in spans {
        match merged.last_mut() {
            Some((_, last_hi)) if u32::from(lo) <= u32::from(*last_hi) + 1 => {
                *last_hi = (*last_hi).max(hi);
            }
            _ => merged.push((lo, hi)),
        }
    }
    match merged.as_slice() {
        [] => None,
        [(lo, hi)] if lo == hi => Some(PortMatcher::Single(*lo)),
        [(lo, hi)] => Some(PortMatcher::Range(*lo, *hi)),
        _ => Some(PortMatcher::Multiple(Box::new(
            merged
                .into_iter()
                .map(|(lo, hi)| {
                    if lo == hi {
                        PortRange::Single(lo)
                    } else {
                        PortRange::Range(lo, hi)
                    }
                })
                .collect(),
        ))),
    }
}

fn compile_in_port(payload: &str) -> Option<RuleOp> {
    compile_port_matcher(payload).map(RuleOp::InPort)
}

fn compile_network(payload: &str) -> Option<RuleOp> {
    match payload.to_ascii_lowercase().as_str() {
        "tcp" => Some(RuleOp::Network(Network::Tcp)),
        "udp" => Some(RuleOp::Network(Network::Udp)),
        _ => None,
    }
}

fn compile_in_type(payload: &str) -> Option<InTypeMask> {
    let mut mask = InTypeMask {
        http: false,
        https: false,
        socks5: false,
        tproxy: false,
        inner: false,
    };
    match payload.to_ascii_uppercase().as_str() {
        "HTTP" => {
            mask.http = true;
            mask.https = true;
        }
        "HTTPS" => mask.https = true,
        "SOCKS5" => mask.socks5 = true,
        "TPROXY" => mask.tproxy = true,
        "INNER" => mask.inner = true,
        _ => return None,
    }
    Some(mask)
}

fn in_type_matches(mask: InTypeMask, conn_type: ConnType) -> bool {
    match conn_type {
        ConnType::Http => mask.http,
        ConnType::Https => mask.https,
        ConnType::Socks5 => mask.socks5,
        ConnType::TProxy => mask.tproxy,
        ConnType::Inner => mask.inner,
        _ => false,
    }
}

fn compile_process_path(payload: &str) -> Option<ProcessPathOp> {
    if payload.contains('*') {
        let escaped = regex::escape(payload);
        let pattern = escaped.replace(r"\*", r"[^/\\]*");
        Regex::new(&format!("^(?i){pattern}$"))
            .ok()
            .map(Box::new)
            .map(ProcessPathOp::Glob)
    } else if payload.starts_with('/') || payload.starts_with('\\') {
        Some(ProcessPathOp::Prefix(payload.into()))
    } else {
        Some(ProcessPathOp::Exact(payload.into()))
    }
}

fn process_path_matches(op: &ProcessPathOp, process_path: &str) -> bool {
    if process_path.is_empty() {
        return false;
    }
    match op {
        ProcessPathOp::Glob(regex) => regex.is_match(process_path),
        ProcessPathOp::Prefix(prefix) => {
            if process_path == &**prefix {
                return true;
            }
            process_path
                .strip_prefix(&**prefix)
                .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('\\'))
        }
        ProcessPathOp::Exact(exact) => {
            let filename = Path::new(process_path)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(process_path);
            filename == &**exact
        }
    }
}

fn uid_matches(metadata: &Metadata, uid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        metadata.uid == Some(uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (metadata, uid);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Footprint guard: a 7.5k-rule config keeps 7.5k slots resident, so
    /// the slot must stay compact (indices `u32`, no payload copy, ops with
    /// boxed strings). Widening it needs a measured justification.
    #[test]
    fn compiled_slot_stays_compact() {
        let slot = std::mem::size_of::<CompiledRuleSlot>();
        let op = std::mem::size_of::<RuleOp>();
        let port = std::mem::size_of::<PortMatcher>();
        assert!(
            slot <= 40 && op <= 24 && port <= 16,
            "slot={slot} B, op={op} B, port_matcher={port} B"
        );
    }
    use crate::match_engine::{self, DomainIndex as LegacyDomainIndex};
    use meow_common::{Metadata, Rule};
    use meow_rules::{
        domain::DomainRule,
        domain_keyword::DomainKeywordRule,
        domain_regex::DomainRegexRule,
        domain_suffix::DomainSuffixRule,
        domain_wildcard::DomainWildcardRule,
        final_rule::FinalRule,
        geosite::GeositeDB,
        geosite_rule::GeoSiteRule,
        in_port::InPortRule,
        ipcidr::IpCidrRule,
        logic::{AndRule, NotRule, OrRule},
        port::PortRule,
        rule_set::{build_rule_set, RuleSet, RuleSetBehavior},
        rule_set_rule::RuleSetRule,
        sub_rule::SubRuleRule,
        ParserContext,
    };
    use std::net::IpAddr;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    /// Naive first-match-wins reference: the semantics every compilation
    /// pass must preserve.
    fn naive_match<'a>(
        metadata: &Metadata,
        rules: &'a [Box<dyn Rule>],
    ) -> Option<(&'a str, RuleType, &'a str)> {
        let helper = RuleMatchHelper;
        rules.iter().find_map(|rule| {
            rule.match_and_resolve(metadata, &helper)
                .map(|adapter| (adapter, rule.rule_type(), rule.payload()))
        })
    }

    fn filler_suffix_rules(count: usize) -> Vec<Box<dyn Rule>> {
        (0..count)
            .map(|i| {
                Box::new(DomainSuffixRule::new(
                    &format!("s{i}.example"),
                    &format!("P{i}"),
                )) as Box<dyn Rule>
            })
            .collect()
    }

    #[test]
    fn indexed_plan_owns_domain_slots_and_matches_suffix_apex() {
        let mut rules = filler_suffix_rules(70);
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());
        assert!(
            set.slots()
                .iter()
                .filter(|s| s.rule_type() == RuleType::DomainSuffix)
                .all(CompiledRuleSlot::is_lowered),
            "suffix slots must be trie-owned, not fallback",
        );

        for (host, expected) in [
            ("s7.example", "P7"),   // apex self-match must hit via trie
            ("x.s7.example", "P7"), // subdomain
            ("a.b.s42.example", "P42"),
            ("unrelated.test", "DIRECT"),
        ] {
            let meta = Metadata {
                host: host.into(),
                dst_port: 443,
                ..Default::default()
            };
            let result = set
                .match_rules(&meta, &rules, &|_| true)
                .expect("must match");
            assert_eq!(result.adapter_name, expected, "host={host}");
        }
    }

    #[test]
    fn indexed_plan_min_index_beats_more_specific_pattern() {
        let mut rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Broad")),
            Box::new(DomainRule::new("sub.example.com", "Specific")),
        ];
        rules.extend(filler_suffix_rules(65));
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());

        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("must match");
        assert_eq!(
            result.adapter_name, "Broad",
            "min-index trie semantics: earliest matching domain rule wins",
        );
    }

    #[test]
    fn indexed_plan_earlier_non_domain_rule_beats_trie_hit() {
        let mut rules: Vec<Box<dyn Rule>> =
            vec![Box::new(PortRule::new("443", "PortFirst", false).unwrap())];
        rules.extend(filler_suffix_rules(70));
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());

        let hit_443 = Metadata {
            host: "s9.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&hit_443, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "PortFirst");

        let hit_80 = Metadata {
            host: "s9.example".into(),
            dst_port: 80,
            ..Default::default()
        };
        let result = set
            .match_rules(&hit_80, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "P9");
    }

    #[test]
    fn star_wildcards_are_trie_owned_in_indexed_plan() {
        let mut rules: Vec<Box<dyn Rule>> = (0..70)
            .map(|i| {
                Box::new(
                    DomainWildcardRule::new(&format!("*.blocked{i}.example.com"), &format!("W{i}"))
                        .unwrap(),
                ) as Box<dyn Rule>
            })
            .collect();
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());
        assert!(
            set.slots()
                .iter()
                .filter(|s| s.rule_type() == RuleType::DomainWildcard)
                .all(CompiledRuleSlot::is_trie_owned),
            "star-shaped wildcards must be owned by the trie",
        );

        for (host, expected) in [
            ("x.blocked7.example.com", "W7"),       // exactly one label
            ("blocked7.example.com", "DIRECT"),     // apex: star needs a label
            ("a.b.blocked7.example.com", "DIRECT"), // two labels: gap has a dot
            ("X.BLOCKED9.EXAMPLE.COM", "W9"),       // case-folded by lower_host
            ("unrelated.test", "DIRECT"),
        ] {
            let meta = Metadata {
                host: Metadata::lower_host(host),
                dst_port: 443,
                ..Default::default()
            };
            let result = set
                .match_rules(&meta, &rules, &|_| true)
                .expect("must match");
            assert_eq!(result.adapter_name, expected, "host={host}");
        }
    }

    #[test]
    fn non_star_wildcard_shapes_stay_on_scan_path() {
        let mut rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainWildcardRule::new("a*b.example.com", "InteriorStar").unwrap()),
            Box::new(DomainWildcardRule::new("example.*", "TrailingStar").unwrap()),
            Box::new(DomainWildcardRule::new("*.multi.*", "DoubleStar").unwrap()),
        ];
        rules.extend(filler_suffix_rules(70)); // force indexed plan
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());
        for pos in 0..3 {
            assert!(
                !set.slots()[pos].is_trie_owned(),
                "non-star shape at {pos} must stay scanned",
            );
        }

        for (host, expected) in [
            ("axxb.example.com", "InteriorStar"),
            ("example.net", "TrailingStar"),
            ("x.multi.org", "DoubleStar"),
            ("plain.test", "DIRECT"),
        ] {
            let meta = Metadata {
                host: host.into(),
                dst_port: 443,
                ..Default::default()
            };
            let result = set
                .match_rules(&meta, &rules, &|_| true)
                .expect("must match");
            assert_eq!(result.adapter_name, expected, "host={host}");
        }
    }

    #[test]
    fn shadowed_domain_family_rules_are_pruned() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Suffix")),
            Box::new(DomainKeywordRule::new("tracker", "Keyword")),
            Box::new(DomainWildcardRule::new("*.cdn.net", "Star").unwrap()),
            // Shadowed — every host each of these matches is claimed earlier
            // by a rule with the SAME adapter (issue #513: a different
            // adapter would stay live — a dead covering target falls
            // through to the covered rule):
            Box::new(DomainRule::new("www.example.com", "Suffix")), // under suffix
            Box::new(DomainRule::new("EXAMPLE.COM", "Suffix")),     // suffix apex, case-folded
            Box::new(DomainSuffixRule::new("api.example.com", "Suffix")), // nested suffix
            Box::new(DomainWildcardRule::new("*.example.com", "Suffix").unwrap()), // star ⊂ suffix
            Box::new(DomainRule::new("mytracker.io", "Keyword")),   // contains keyword
            Box::new(DomainSuffixRule::new("tracker.org", "Keyword")), // contains keyword
            Box::new(DomainKeywordRule::new("supertrackers", "Keyword")), // contains keyword
            Box::new(DomainWildcardRule::new("*.trackers.net", "Keyword").unwrap()), // rest ⊇ keyword
            Box::new(DomainRule::new("edge.cdn.net", "Star")), // one label under star
            // Covered by the suffix but with a DIFFERENT adapter — stays
            // live under continue semantics:
            Box::new(DomainRule::new("diff.example.com", "DiffAdapter")),
            // Not shadowed — must stay live:
            Box::new(DomainRule::new("a.b.cdn.net", "LiveTwoLabels")), // star = one label only
            Box::new(DomainRule::new("cdn.net", "LiveApex")),          // star needs a label
            Box::new(DomainSuffixRule::new("examples.com", "LiveNoDotBoundary")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        let live: Vec<usize> = set
            .slots()
            .iter()
            .map(CompiledRuleSlot::rule_index)
            .collect();
        assert_eq!(
            live,
            vec![0, 1, 2, 12, 13, 14, 15, 16],
            "same-adapter shadows prune; the different-adapter twin survives",
        );

        // Pruning must be observation-equivalent to the naive reference.
        for host in [
            "www.example.com",
            "example.com",
            "x.api.example.com",
            "y.example.com",
            "mytracker.io",
            "tracker.org",
            "www.supertrackers.dev",
            "x.trackers.net",
            "edge.cdn.net",
            "diff.example.com",
            "a.b.cdn.net",
            "cdn.net",
            "examples.com",
            "unrelated.test",
        ] {
            let meta = Metadata {
                host: Metadata::lower_host(host),
                dst_port: 443,
                ..Default::default()
            };
            let compiled = set
                .match_rules(&meta, &rules, &|_| true)
                .expect("must match");
            let (adapter, ..) = naive_match(&meta, &rules).expect("must match");
            assert_eq!(compiled.adapter_name, adapter, "host={host}");
        }

        // Dead covering target: the different-adapter twin is reached —
        // pruning it would have leaked the host to DIRECT.
        let meta = Metadata {
            host: "diff.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|name| name != "Suffix")
            .expect("twin must match after the covering rule is skipped");
        assert_eq!(result.adapter_name, "DiffAdapter");
    }

    #[test]
    fn canonical_fingerprints_dedup_textual_variants() {
        // Textual variants only dedup when they also share the adapter —
        // under continue semantics a dead first target falls through to a
        // twin with a different one (issue #513).
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("10.1.2.3/8", "A", false, true).unwrap()),
            Box::new(IpCidrRule::new("10.0.0.0/8", "A", false, true).unwrap()), // same network
            Box::new(IpCidrRule::new("10.0.0.0/8", "Other", false, true).unwrap()), // same net, diff adapter
            Box::new(PortRule::new("80,443", "C", false).unwrap()),
            Box::new(PortRule::new("443, 80", "C", false).unwrap()), // same port set
            Box::new(PortRule::new("70-90/85-100", "E", false).unwrap()),
            Box::new(PortRule::new("70-100", "E", false).unwrap()), // merges to the same span
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        let live: Vec<usize> = set
            .slots()
            .iter()
            .map(CompiledRuleSlot::rule_index)
            .collect();
        assert_eq!(
            live,
            vec![0, 2, 3, 5, 7],
            "same-adapter textual variants dedup; different-adapter twins stay",
        );

        for (meta, expected) in [
            (
                Metadata {
                    dst_ip: Some("10.9.9.9".parse::<IpAddr>().unwrap()),
                    dst_port: 7,
                    ..Default::default()
                },
                "A",
            ),
            (
                Metadata {
                    dst_port: 443,
                    ..Default::default()
                },
                "C",
            ),
            (
                Metadata {
                    dst_port: 95,
                    ..Default::default()
                },
                "E",
            ),
            (
                Metadata {
                    dst_port: 7,
                    ..Default::default()
                },
                "DIRECT",
            ),
        ] {
            let result = set
                .match_rules(&meta, &rules, &|_| true)
                .expect("must match");
            assert_eq!(result.adapter_name, expected);
            let (adapter, ..) = naive_match(&meta, &rules).expect("must match");
            assert_eq!(result.adapter_name, adapter);
        }
    }

    #[test]
    fn covered_cidr_rules_are_pruned() {
        // Coverage is tracked per adapter (issue #513): a covered rule
        // prunes only when the covering networks carry the same adapter —
        // otherwise a dead covering target would fall through to a rule the
        // pass removed.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("10.0.0.0/9", "A", false, true).unwrap()),
            Box::new(IpCidrRule::new("10.128.0.0/9", "A", false, true).unwrap()),
            Box::new(IpCidrRule::new("2001:db8::/32", "C", false, true).unwrap()),
            // Covered — contained in the union of earlier same-adapter nets:
            Box::new(IpCidrRule::new("10.64.0.0/10", "A", false, true).unwrap()),
            // The two /9s merge to 10.0.0.0/8, so the whole /8 is covered.
            Box::new(IpCidrRule::new("10.0.0.0/8", "A", false, true).unwrap()),
            Box::new(IpCidrRule::new("2001:db8:aa::/48", "C", false, true).unwrap()),
            // Same networks, different adapters — stay live:
            Box::new(IpCidrRule::new("10.64.0.0/10", "DiffV4", false, true).unwrap()),
            Box::new(IpCidrRule::new("2001:db8:bb::/48", "DiffV6", false, true).unwrap()),
            // Not covered — must stay live:
            Box::new(IpCidrRule::new("10.0.0.0/7", "LiveWider", false, true).unwrap()),
            Box::new(IpCidrRule::new("10.0.0.0/8", "LiveSrcAxis", true, true).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        let live: Vec<usize> = set
            .slots()
            .iter()
            .map(CompiledRuleSlot::rule_index)
            .collect();
        assert_eq!(
            live,
            vec![0, 1, 2, 6, 7, 8, 9, 10],
            "same-adapter union coverage prunes; different-adapter twins stay",
        );

        for (dst, src, expected) in [
            (Some("10.1.2.3"), None, "A"),
            (Some("10.200.0.1"), None, "A"),
            (Some("2001:db8:aa::1"), None, "C"),
            (Some("11.0.0.1"), None, "LiveWider"),
            (Some("192.0.2.1"), Some("10.5.5.5"), "LiveSrcAxis"),
            (Some("192.0.2.1"), None, "DIRECT"),
        ] {
            let meta = Metadata {
                dst_ip: dst.map(|ip| ip.parse::<IpAddr>().unwrap()),
                src_ip: src.map(|ip| ip.parse::<IpAddr>().unwrap()),
                dst_port: 443,
                ..Default::default()
            };
            let result = set
                .match_rules(&meta, &rules, &|_| true)
                .expect("must match");
            assert_eq!(result.adapter_name, expected, "dst={dst:?} src={src:?}");
            let (adapter, ..) = naive_match(&meta, &rules).expect("must match");
            assert_eq!(result.adapter_name, adapter, "dst={dst:?} src={src:?}");
        }
    }

    #[test]
    fn covered_cidr_keeps_sole_lazy_demand_carrier() {
        // The covered /16 is the only rule demanding DNS resolution: pruning
        // it would silently disable the enrichment whose result the earlier
        // no-resolve /8 observes on the strict re-run.
        // Same adapter as the covering rule — coverage is per-adapter
        // (issue #513), so a different adapter would keep the rule live for
        // an unrelated reason.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("10.0.0.0/8", "A", false, true).unwrap()),
            Box::new(IpCidrRule::new("10.1.0.0/16", "A", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);
        assert_eq!(set.slots().len(), 3, "sole demand carrier must stay live");
        assert!(set.needs_ip_resolution());

        let meta = Metadata {
            host: "db.internal".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert!(
            matches!(
                set.match_rules_lazy(&meta, &rules, &|_| true),
                LazyMatchOutcome::NeedsEnrichment { needs_ip: true, .. }
            ),
            "lazy scan must stop for resolution instead of falling through",
        );

        // With an earlier demand carrier in place, the covered rule prunes.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("192.0.2.0/24", "R", false, false).unwrap()),
            Box::new(IpCidrRule::new("10.0.0.0/8", "A", false, true).unwrap()),
            Box::new(IpCidrRule::new("10.1.0.0/16", "A", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);
        assert_eq!(
            set.slots().len(),
            3,
            "covered rule prunes once a demand carrier exists"
        );
        assert!(set.needs_ip_resolution());
    }

    #[test]
    fn dedup_keeps_stronger_demand_twins() {
        // Identical predicate + adapter, stronger demand profile: must NOT
        // dedup — and the coverage pass must spare it too, since it is the
        // sole demand carrier (issue #513 made coverage adapter-aware; the
        // same adapter here isolates the demand guard).
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("10.0.0.0/8", "A", false, true).unwrap()),
            Box::new(IpCidrRule::new("10.0.0.0/8", "A", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);
        assert_eq!(set.slots().len(), 3);
        assert!(set.needs_ip_resolution());

        // Identical predicate, identical demands, same adapter: dedups.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("10.0.0.0/8", "A", false, true).unwrap()),
            Box::new(IpCidrRule::new("10.0.0.0/8", "A", false, true).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);
        assert_eq!(set.slots().len(), 2);
        assert!(!set.needs_ip_resolution());
    }

    #[test]
    fn logic_trees_constant_fold() {
        fn never_rule() -> Box<dyn Rule> {
            // NOT(MATCH) is a compile-time-constant false.
            Box::new(NotRule::new(Box::new(FinalRule::new("X")), "X"))
        }
        let rules: Vec<Box<dyn Rule>> = vec![
            // Folds to never → pruned:
            Box::new(NotRule::new(Box::new(FinalRule::new("X")), "NeverNot")),
            // AND with a never-match child folds to never → pruned:
            Box::new(AndRule::new(
                vec![
                    Box::new(PortRule::new("443", "X", false).unwrap()),
                    never_rule(),
                ],
                "NeverAnd",
            )),
            // OR loses its never arm and collapses to the port predicate:
            Box::new(OrRule::new(
                vec![
                    never_rule(),
                    Box::new(PortRule::new("8443", "X", false).unwrap()),
                ],
                "OrPort",
            )),
            // AND of constants folds to always → unconditional terminator —
            // but only a predicate-guaranteed target ends the scan
            // (issue #513): the tail is truncated because this rule targets
            // DIRECT, which the match-time predicate treats as always live.
            Box::new(AndRule::new(
                vec![
                    Box::new(FinalRule::new("X")),
                    Box::new(NotRule::new(never_rule(), "X")),
                ],
                "DIRECT",
            )),
            // Dead: truncated by the folded terminator above.
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        let live: Vec<usize> = set
            .slots()
            .iter()
            .map(CompiledRuleSlot::rule_index)
            .collect();
        assert_eq!(
            live,
            vec![2, 3],
            "never-folds prune, always-fold on DIRECT terminates"
        );

        for (port, expected) in [(8443, "OrPort"), (80, "DIRECT")] {
            let meta = Metadata {
                dst_port: port,
                ..Default::default()
            };
            let result = set
                .match_rules(&meta, &rules, &|_| true)
                .expect("must match");
            assert_eq!(result.adapter_name, expected, "port={port}");
            let (adapter, ..) = naive_match(&meta, &rules).expect("must match");
            assert_eq!(result.adapter_name, adapter, "port={port}");
        }
    }

    #[test]
    fn shared_rule_set_handles_dedup_by_identity() {
        let entries = vec!["shared.example".to_string()];
        let set_box = build_rule_set(RuleSetBehavior::Domain, &entries, &ParserContext::default());
        let rule_set: Arc<dyn RuleSet> = Arc::from(set_box);
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(RuleSetRule::new("prov", Arc::clone(&rule_set), "A", true)),
            // Same provider handle AND adapter: the predicate is identical,
            // so the later occurrence can never change the outcome and must
            // dedup by pointer identity (issue #513: adapter is part of the
            // dedup identity — a different adapter would stay live).
            Box::new(RuleSetRule::new("prov", Arc::clone(&rule_set), "A", true)),
            // Same provider handle, DIFFERENT adapter: stays live — a dead
            // first target falls through to this twin.
            Box::new(RuleSetRule::new("prov", Arc::clone(&rule_set), "B", true)),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        assert_eq!(
            set.slots().len(),
            3,
            "same-adapter duplicate prunes; different-adapter twin stays",
        );

        let meta = Metadata {
            host: "shared.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "A");

        // Dead first target: the different-adapter twin is reached.
        let result = set
            .match_rules(&meta, &rules, &|name| name != "A")
            .expect("must match");
        assert_eq!(result.adapter_name, "B");
    }

    /// A set whose contents can be swapped behind one `Arc`, the way
    /// `RuleProvider::refresh` replaces the loaded set (issue #553).
    #[derive(Debug)]
    struct SwappableSet {
        hosts: parking_lot::RwLock<Vec<String>>,
    }

    impl RuleSet for SwappableSet {
        fn behavior(&self) -> RuleSetBehavior {
            RuleSetBehavior::Domain
        }

        fn matches(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
            self.hosts
                .read()
                .iter()
                .any(|h| h == metadata.host.as_str())
        }

        fn len(&self) -> usize {
            self.hosts.read().len()
        }
    }

    /// Issue #553: `RuleSetRef` holds the provider's `Arc<dyn RuleSet>`
    /// itself, so a refresh that swaps the set behind it must be visible to
    /// the compiled rules without a rebuild — on the strict and the lazy
    /// scan path alike. Guards against anyone re-introducing a build-time
    /// snapshot of the set.
    #[test]
    fn rule_set_ref_reads_through_to_swapped_contents() {
        let live = Arc::new(SwappableSet {
            hosts: parking_lot::RwLock::new(vec!["old.example".to_string()]),
        });
        let handle = Arc::clone(&live) as Arc<dyn RuleSet>;
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(RuleSetRule::new("prov", handle, "A", true)),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = |host: &str| Metadata {
            host: host.into(),
            dst_port: 443,
            ..Default::default()
        };
        let strict = |host: &str| -> String {
            set.match_rules(&meta(host), &rules, &|_| true)
                .expect("FINAL always matches")
                .adapter_name
                .to_string()
        };
        let lazy = |host: &str| -> String {
            match set.match_rules_lazy(&meta(host), &rules, &|_| true) {
                LazyMatchOutcome::Matched(result) => result.adapter_name.to_string(),
                LazyMatchOutcome::NeedsEnrichment { .. } => {
                    panic!("a domain set never demands enrichment")
                }
                LazyMatchOutcome::NoMatch => panic!("FINAL always matches"),
            }
        };

        assert_eq!(strict("old.example"), "A");
        assert_eq!(strict("new.example"), "DIRECT");
        assert_eq!(lazy("old.example"), "A");
        assert_eq!(lazy("new.example"), "DIRECT");

        // Simulate a provider refresh: new contents, same Arc, no rebuild.
        *live.hosts.write() = vec!["new.example".to_string()];

        assert_eq!(
            strict("new.example"),
            "A",
            "compiled IR must read the refreshed set through the shared handle"
        );
        assert_eq!(
            strict("old.example"),
            "DIRECT",
            "entries dropped by the refresh must stop matching"
        );
        assert_eq!(lazy("new.example"), "A");
        assert_eq!(lazy("old.example"), "DIRECT");
    }

    #[test]
    fn indexed_plan_unindexable_domain_payload_stays_on_scan_path() {
        // Non-ASCII payload: the trie's Unicode lowercasing diverges from
        // the op's ASCII-insensitive compare, so the pattern must not be
        // trie-owned — it stays a scanned slot and still matches literally.
        let mut rules = filler_suffix_rules(70);
        rules.push(Box::new(DomainRule::new("bücher.com", "Umlaut")));
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());

        let meta = Metadata {
            host: "bücher.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "Umlaut");
    }

    #[test]
    fn randomized_configs_match_naive_first_match_reference() {
        // Deterministic LCG so failures reproduce; no external deps.
        struct Lcg(u64);
        impl Lcg {
            fn next(&mut self) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                self.0 >> 33
            }
            fn pick<T: Copy>(&mut self, items: &[T]) -> T {
                items[(self.next() as usize) % items.len()]
            }
        }

        let names = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let tlds = ["com", "net", "org"];
        let subs = ["www", "api", "cdn"];
        let adapters = ["A", "B", "C", "DIRECT"];
        let ports = ["80", "443", "8080", "1000-2000"];

        let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);

        for &size in &[1usize, 3, 30, 63, 64, 65, 80, 150] {
            let mut rules: Vec<Box<dyn Rule>> = Vec::with_capacity(size + 1);
            for _ in 0..size {
                let host = format!("{}.{}", rng.pick(&names), rng.pick(&tlds));
                let adapter = rng.pick(&adapters);
                let rule: Box<dyn Rule> = match rng.next() % 12 {
                    0 => Box::new(DomainRule::new(&host, adapter)),
                    1 => Box::new(DomainRule::new(
                        &format!("{}.{host}", rng.pick(&subs)),
                        adapter,
                    )),
                    2 | 3 => Box::new(DomainSuffixRule::new(&host, adapter)),
                    4 => Box::new(DomainKeywordRule::new(rng.pick(&names), adapter)),
                    5 => Box::new(PortRule::new(rng.pick(&ports), adapter, false).unwrap()),
                    6 => Box::new(DomainWildcardRule::new(&format!("*.{host}"), adapter).unwrap()),
                    7 => Box::new(
                        DomainWildcardRule::new(
                            &format!("{}*.{}", rng.pick(&subs), rng.pick(&tlds)),
                            adapter,
                        )
                        .unwrap(),
                    ),
                    8 => Box::new(
                        IpCidrRule::new(
                            &format!("10.{}.0.0/16", rng.next() % 4),
                            adapter,
                            false,
                            true,
                        )
                        .unwrap(),
                    ),
                    // Overlap-heavy shapes exercising the shadowing and
                    // canonical-dedup passes; the naive reference keeps
                    // them honest.
                    9 => Box::new(DomainSuffixRule::new(
                        &format!("{}.{host}", rng.pick(&subs)),
                        adapter,
                    )),
                    10 => Box::new(DomainKeywordRule::new(&rng.pick(&names)[..3], adapter)),
                    // Same networks as arm 8 but with host bits set (must
                    // fold onto one fingerprint), or a /24 subset that the
                    // coverage pass prunes once the enclosing /16 appeared.
                    _ => {
                        let third = rng.next() % 4;
                        let prefix = if rng.next().is_multiple_of(2) { 16 } else { 24 };
                        Box::new(
                            IpCidrRule::new(
                                &format!("10.{third}.7.9/{prefix}"),
                                adapter,
                                false,
                                true,
                            )
                            .unwrap(),
                        )
                    }
                };
                rules.push(rule);
                // Occasionally drop in an early FINAL to exercise dead-rule
                // elimination against the reference.
                if rng.next().is_multiple_of(23) {
                    rules.push(Box::new(FinalRule::new("EARLY-FINAL")));
                }
            }
            rules.push(Box::new(FinalRule::new("DIRECT")));

            let set = CompiledRuleSet::build(&rules);

            for _ in 0..60 {
                let host = match rng.next() % 4 {
                    0 => format!("{}.{}", rng.pick(&names), rng.pick(&tlds)),
                    1 => format!(
                        "{}.{}.{}",
                        rng.pick(&subs),
                        rng.pick(&names),
                        rng.pick(&tlds)
                    ),
                    2 => format!("x.y.{}.{}", rng.pick(&names), rng.pick(&tlds)),
                    _ => "unmatched.invalid".to_string(),
                };
                let metadata = Metadata {
                    host: host.into(),
                    dst_port: rng.pick(&[80u16, 443, 8080, 1500, 9999]),
                    dst_ip: match rng.next() % 3 {
                        0 => None,
                        _ => Some(
                            format!("10.{}.{}.{}", rng.next() % 4, rng.next() % 256, 1)
                                .parse::<IpAddr>()
                                .unwrap(),
                        ),
                    },
                    ..Default::default()
                };

                let expected = naive_match(&metadata, &rules);
                let actual = set
                    .match_rules(&metadata, &rules, &|_| true)
                    .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
                assert_eq!(
                    actual, expected,
                    "size={size} host={} port={} ip={:?}",
                    metadata.host, metadata.dst_port, metadata.dst_ip,
                );
            }
        }
    }

    #[test]
    fn lazy_match_stops_at_ip_demanding_slot() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            host: "unresolved.test".into(),
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules, &|_| true) {
            LazyMatchOutcome::NeedsEnrichment {
                needs_ip,
                needs_process,
            } => {
                assert!(needs_ip);
                assert!(!needs_process);
            }
            _ => panic!("scan must stop at the IP-CIDR slot"),
        }
    }

    #[test]
    fn lazy_match_completes_before_demanding_slot() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "DomainProxy")),
            Box::new(IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules, &|_| true) {
            LazyMatchOutcome::Matched(m) => assert_eq!(m.adapter_name, "DomainProxy"),
            _ => panic!("domain match must complete without enrichment"),
        }
    }

    #[test]
    fn lazy_match_does_not_stop_when_ip_unresolvable() {
        // No hostname to resolve: the IP-CIDR slot evaluates as a plain
        // non-match, exactly like the strict engine.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules, &|_| true) {
            LazyMatchOutcome::Matched(m) => assert_eq!(m.adapter_name, "DIRECT"),
            _ => panic!("must fall through to FINAL without demanding enrichment"),
        }
    }

    #[test]
    fn lazy_match_respects_no_resolve() {
        // no-resolve IP-CIDR must not trigger resolution; unresolved
        // metadata simply does not match it.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, true).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            host: "unresolved.test".into(),
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules, &|_| true) {
            LazyMatchOutcome::Matched(m) => assert_eq!(m.adapter_name, "DIRECT"),
            _ => panic!("no-resolve rule must not demand enrichment"),
        }
    }

    #[test]
    fn lazy_match_stops_at_process_demanding_slot() {
        use meow_rules::process::ProcessRule;

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(ProcessRule::new("some-binary", "ProcProxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            host: "example.com".into(),
            src_ip: Some("127.0.0.1".parse::<IpAddr>().unwrap()),
            src_port: 50000,
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules, &|_| true) {
            LazyMatchOutcome::NeedsEnrichment {
                needs_ip,
                needs_process,
            } => {
                assert!(!needs_ip);
                assert!(needs_process);
            }
            _ => panic!("scan must stop at the process slot"),
        }
    }

    #[test]
    fn lazy_match_blocked_slot_preempts_trie_hit() {
        // The blocked IP slot precedes every domain rule, so even with a
        // trie hit standing ready the scan must demand enrichment first.
        let mut rules: Vec<Box<dyn Rule>> = vec![Box::new(
            IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, false).unwrap(),
        )];
        rules.extend(filler_suffix_rules(70));
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());

        let meta = Metadata {
            host: "s7.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules, &|_| true) {
            LazyMatchOutcome::NeedsEnrichment { needs_ip, .. } => assert!(needs_ip),
            _ => panic!("blocked slot before the trie hit must demand enrichment"),
        }

        // Once resolved (to a non-matching IP), the strict re-match falls
        // through to the trie hit.
        let resolved = Metadata {
            host: "s7.example".into(),
            dst_ip: Some("9.9.9.9".parse::<IpAddr>().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&resolved, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "P7");
    }

    #[test]
    fn rule_op_size_stays_bounded() {
        // New native variants must not grow the op past the pre-existing
        // maximum (Domain(String) = 24 B payload); scan cache behavior
        // depends on slot size staying put.
        let size = std::mem::size_of::<RuleOp>();
        assert!(size <= 32, "RuleOp grew to {size} B");
    }

    #[test]
    fn geosite_unknown_category_is_pruned() {
        let mut db = GeositeDB::empty();
        db.insert("cn", "cn.example");
        let rules: Vec<Box<dyn Rule>> = vec![
            // Category absent from the immutable DB: permanent no-match.
            Box::new(GeoSiteRule::new(
                "nonexistent",
                "Direct",
                Some(Arc::new(db)),
                false,
            )),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert_eq!(set.len(), 1, "unknown geosite category must be pruned");
        assert!(!set.needs_ip_resolution());
    }

    #[test]
    fn geoip_rule_lowers_to_ip_ranges_op() {
        let ranges = Arc::new(IpRangeSet::from_nets(["203.0.113.0/24".parse().unwrap()]));
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(GeoIpRule::new("CN", "GeoProxy", false, ranges)),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        assert!(set.slots()[0].is_lowered(), "GEOIP must lower natively");

        let hit = Metadata {
            dst_ip: Some("203.0.113.9".parse::<IpAddr>().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&hit, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "GeoProxy");
        assert_eq!(result.rule_type, RuleType::GeoIp);

        let miss = Metadata {
            dst_ip: Some("198.51.100.1".parse::<IpAddr>().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&miss, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "DIRECT");
    }

    #[test]
    fn ip_suffix_rule_lowers_and_matches() {
        use meow_rules::ip_suffix::IpSuffixRule;

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpSuffixRule::new("0.0.0.1/8", "SuffixProxy", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        assert!(set.slots()[0].is_lowered(), "IP-SUFFIX must lower natively");

        let hit = Metadata {
            dst_ip: Some("10.20.30.1".parse::<IpAddr>().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&hit, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "SuffixProxy");

        let miss = Metadata {
            dst_ip: Some("10.20.30.2".parse::<IpAddr>().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&miss, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "DIRECT");
    }

    #[test]
    fn logic_rules_lower_to_expression_trees() {
        use meow_rules::logic::{AndRule, NotRule};

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(AndRule::new(
                vec![
                    Box::new(DomainSuffixRule::new("example.com", "unused")),
                    Box::new(NotRule::new(
                        Box::new(PortRule::new("80", "unused", false).unwrap()),
                        "unused",
                    )),
                ],
                "LogicProxy",
            )),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        assert!(
            set.slots()[0].is_lowered(),
            "AND(suffix, NOT(port)) must lower"
        );

        let hit = Metadata {
            host: "a.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&hit, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "LogicProxy");
        assert_eq!(result.rule_type, RuleType::And);

        // Port 80 flips the NOT arm off.
        let miss = Metadata {
            host: "a.example.com".into(),
            dst_port: 80,
            ..Default::default()
        };
        let result = set
            .match_rules(&miss, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "DIRECT");
    }

    #[test]
    fn logic_rule_with_opaque_child_stays_on_fallback() {
        let counting = CountingRule::new(
            RuleType::GeoIp,
            "unused",
            "CN",
            true,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(CallCounts::default()),
        );
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(OrRule::new(
                vec![
                    Box::new(DomainRule::new("x.example", "unused")),
                    Box::new(counting),
                ],
                "MixedProxy",
            )),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        assert!(
            !set.slots()[0].is_lowered(),
            "a non-lowerable child must keep the logic rule on fallback",
        );

        let meta = Metadata {
            host: "unrelated.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        // The counting child always matches → OR matches via fallback.
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("must match");
        assert_eq!(result.adapter_name, "MixedProxy");
    }

    #[test]
    fn dead_rules_after_final_are_eliminated() {
        let mut db = GeositeDB::empty();
        db.insert("cn", "cn.example");
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
            // Unreachable: would otherwise force DNS pre-resolution.
            Box::new(GeoSiteRule::new("cn", "Direct", Some(Arc::new(db)), false)),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert_eq!(set.len(), 2, "rules after FINAL must not emit slots");
        assert!(!set.needs_ip_resolution());
        assert!(set.is_compatible_with(&rules));

        let meta = Metadata {
            host: "other.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("FINAL must match");
        assert_eq!(result.adapter_name, "DIRECT");
        assert_eq!(result.rule_type, RuleType::Match);
    }

    #[test]
    fn duplicate_lowered_rules_are_eliminated() {
        // Same predicate + same adapter: the twin can never change the
        // outcome — live together, skipped together — so it dedups.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainRule::new("dup.example.com", "First")),
            Box::new(DomainRule::new("DUP.EXAMPLE.COM", "First")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert_eq!(set.len(), 2, "identical later predicate must be dropped");

        let meta = Metadata {
            host: "dup.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("domain must match");
        assert_eq!(result.adapter_name, "First", "first occurrence wins");
    }

    /// The continue-semantics converse: an identical predicate targeting a
    /// DIFFERENT adapter must stay live — a dead first target falls through
    /// to the twin (issue #513).
    #[test]
    fn duplicate_predicates_with_different_adapters_stay_live() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainRule::new("dup.example.com", "GHOST")),
            Box::new(DomainRule::new("dup.example.com", "Second")),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);
        assert_eq!(set.len(), 3, "different-adapter twin must be kept");

        let meta = Metadata {
            host: "dup.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let present = |name: &str| name != "GHOST";
        let result = set
            .match_rules(&meta, &rules, &present)
            .expect("twin must match after the ghost is skipped");
        assert_eq!(result.adapter_name, "Second");
    }

    /// A MATCH whose target is not registry-guaranteed must NOT truncate the
    /// tail at build time: skipped at match time, the next rule wins
    /// (issue #513 — upstream `continue` semantics).
    #[test]
    fn match_with_unguaranteed_target_does_not_truncate_tail() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(FinalRule::new("GHOST")),
            Box::new(FinalRule::new("REJECT")),
        ];
        let set = CompiledRuleSet::build(&rules);
        assert_eq!(
            set.slots().len(),
            2,
            "MATCH,ghost must not eliminate the tail",
        );

        let meta = Metadata::default();
        let result = set
            .match_rules(&meta, &rules, &|name| name != "GHOST")
            .expect("second MATCH must win after the ghost is skipped");
        assert_eq!(result.adapter_name, "REJECT");

        // With the ghost present, first match wins as usual.
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("first MATCH wins when live");
        assert_eq!(result.adapter_name, "GHOST");
    }

    /// Indexed-plan tail scans must evaluate a SECOND matching domain rule
    /// after a skipped hit — its slot is trie-owned, so a plain slot scan
    /// would skip it and leak the host to DIRECT (issue #513).
    #[test]
    fn skipped_trie_hit_falls_through_to_second_domain_rule() {
        let mut rules = filler_suffix_rules(70);
        let ghost_idx = rules.len();
        rules.push(Box::new(DomainRule::new("ads.example", "GHOST")));
        rules.push(Box::new(DomainSuffixRule::new("example", "REJECT")));
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan(), "must run the indexed plan");

        let meta = Metadata {
            host: "ads.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let present = |name: &str| name != "GHOST";
        let result = set
            .match_rules(&meta, &rules, &present)
            .expect("suffix rule must win after the ghost hit is skipped");
        assert_eq!(result.adapter_name, "REJECT");
        assert_eq!(result.rule_index, ghost_idx + 1);

        // Lazy path agrees.
        match set.match_rules_lazy(&meta, &rules, &present) {
            LazyMatchOutcome::Matched(m) => assert_eq!(m.adapter_name, "REJECT"),
            LazyMatchOutcome::NeedsEnrichment { .. } | LazyMatchOutcome::NoMatch => {
                panic!("lazy path diverged")
            }
        }
    }

    #[test]
    fn never_match_geosite_rule_is_pruned() {
        let rules: Vec<Box<dyn Rule>> = vec![
            // No DB loaded: provably never matches, but without pruning its
            // `should_resolve_ip()` would force pre-resolution for every
            // connection.
            Box::new(GeoSiteRule::new("cn", "Direct", None, false)),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert_eq!(set.len(), 1);
        assert!(!set.needs_ip_resolution());

        let meta = Metadata {
            host: "cn.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("FINAL must match");
        assert_eq!(result.adapter_name, "DIRECT");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn uid_rule_is_pruned_on_platforms_without_socket_uid() {
        use meow_rules::uid::UidRule;

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(UidRule::new("1000", "UidProxy").unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert_eq!(set.len(), 1, "UID op is constant-false off Linux");
        let result = set
            .match_rules(&Metadata::default(), &rules, &|_| true)
            .expect("FINAL must match");
        assert_eq!(result.adapter_name, "DIRECT");
    }

    #[test]
    fn small_rule_sets_use_linear_scan_plan() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert!(set.uses_linear_scan_plan());
    }

    #[test]
    fn large_rule_sets_use_domain_indexed_plan() {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        for i in 0..=LINEAR_SCAN_RULE_LIMIT {
            rules.push(Box::new(DomainSuffixRule::new(
                &format!("suffix{i}.example.com"),
                "Proxy",
            )));
        }
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);

        assert!(!set.uses_linear_scan_plan());
    }

    #[test]
    fn domain_index_early_exit_skips_later_rules() {
        let later_match_count = Arc::new(AtomicUsize::new(0));
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(CountingRule::new(
                RuleType::Match,
                "DIRECT",
                "",
                true,
                Arc::clone(&later_match_count),
                Arc::new(CallCounts::default()),
            )),
        ];

        let set = CompiledRuleSet::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };

        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("domain rule must match");
        assert_eq!(result.adapter_name, "Proxy");
        assert_eq!(result.rule_type, RuleType::DomainSuffix);
        assert_eq!(result.rule_payload, "example.com");
        assert_eq!(later_match_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn earlier_rule_beats_domain_trie_hit() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(PortRule::new("443", "Direct", false).unwrap()),
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("FINAL")),
        ];

        let set = CompiledRuleSet::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };

        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("earlier port rule must match");
        assert_eq!(result.adapter_name, "Direct");
        assert_eq!(result.rule_type, RuleType::DstPort);
    }

    #[test]
    fn lowered_dst_port_slash_list_matches() {
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(
            PortRule::new("80/8080/443/8443", "PortProxy", false).unwrap(),
        )];

        let set = CompiledRuleSet::build(&rules);
        assert!(set.slots()[0].is_lowered());

        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 8080,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("port list must match");
        assert_eq!(result.adapter_name, "PortProxy");
        assert_eq!(result.rule_type, RuleType::DstPort);
    }

    #[test]
    fn lowered_in_port_slash_list_matches() {
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(
            InPortRule::new("80/8080/443/8443", "InboundProxy").unwrap(),
        )];

        let set = CompiledRuleSet::build(&rules);
        assert!(set.slots()[0].is_lowered());

        let meta = Metadata {
            host: "example.com".into(),
            in_port: 8443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("in-port list must match");
        assert_eq!(result.adapter_name, "InboundProxy");
        assert_eq!(result.rule_type, RuleType::InPort);
    }

    #[test]
    fn geosite_attribute_rule_lowers_and_matches_under_ir() {
        let mut db = GeositeDB::empty();
        db.insert("microsoft", "global.example");
        db.insert("microsoft@cn", "cn.example");
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(GeoSiteRule::new(
            "microsoft@cn",
            "Direct",
            Some(Arc::new(db)),
            false,
        ))];

        let set = CompiledRuleSet::build(&rules);
        assert!(set.slots()[0].is_lowered(), "GEOSITE must lower natively");

        let meta = Metadata {
            host: "cn.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("geosite attr fallback must match");
        assert_eq!(result.adapter_name, "Direct");
        assert_eq!(result.rule_type, RuleType::GeoSite);
    }

    #[test]
    fn geoip_rule_fallback_matches_under_ir() {
        let match_count = Arc::new(AtomicUsize::new(0));
        let counts = Arc::new(CallCounts::default());
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(CountingRule::new(
            RuleType::GeoIp,
            "GeoProxy",
            "CN",
            true,
            Arc::clone(&match_count),
            counts,
        ))];

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.slots()[0].is_lowered());

        let meta = Metadata {
            dst_ip: Some("203.0.113.9".parse::<IpAddr>().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("geoip fallback must match");
        assert_eq!(result.adapter_name, "GeoProxy");
        assert_eq!(result.rule_type, RuleType::GeoIp);
        assert_eq!(match_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rule_set_rule_lowers_and_matches_under_ir() {
        let entries = vec!["example.com".to_string()];
        let set_box = build_rule_set(RuleSetBehavior::Domain, &entries, &ParserContext::default());
        let rule_set: Arc<dyn RuleSet> = Arc::from(set_box);
        let rules: Vec<Box<dyn Rule>> =
            vec![Box::new(RuleSetRule::new("cn", rule_set, "Direct", false))];

        let compiled = CompiledRuleSet::build(&rules);
        assert!(
            compiled.slots()[0].is_lowered(),
            "RULE-SET must lower natively",
        );

        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = compiled
            .match_rules(&meta, &rules, &|_| true)
            .expect("rule-set op must match");
        assert_eq!(result.adapter_name, "Direct");
        assert_eq!(result.rule_type, RuleType::RuleSet);
    }

    #[test]
    fn broader_domain_rule_before_specific_wins_first_match() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Broad")),
            Box::new(DomainRule::new("sub.example.com", "Specific")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };

        let result = set
            .match_rules(&meta, &rules, &|_| true)
            .expect("domain rule must match");
        assert_eq!(result.adapter_name, "Broad");
        assert_eq!(result.rule_type, RuleType::DomainSuffix);
    }

    #[test]
    fn lowered_match_rule_skips_virtual_match_and_metadata_calls() {
        let match_count = Arc::new(AtomicUsize::new(0));
        let counts = Arc::new(CallCounts::default());
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(CountingRule::new(
            RuleType::Match,
            "DIRECT",
            "payload",
            true,
            Arc::clone(&match_count),
            Arc::clone(&counts),
        ))];

        let set = CompiledRuleSet::build(&rules);
        counts.reset();

        let result = set
            .match_rules(&Metadata::default(), &rules, &|_| true)
            .expect("counting rule must match");

        assert_eq!(result.adapter_name, "DIRECT");
        assert_eq!(result.rule_payload, "payload");
        assert_eq!(match_count.load(Ordering::Relaxed), 0);
        assert_eq!(counts.rule_type.load(Ordering::Relaxed), 0);
        assert_eq!(counts.adapter.load(Ordering::Relaxed), 0);
        // The payload is deliberately *not* copied into the slot (footprint):
        // a hit borrows it from the source rule with one virtual call.
        assert_eq!(counts.payload.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sub_rule_dynamic_adapter_is_preserved() {
        let block: Arc<Vec<Box<dyn Rule>>> = Arc::new(vec![Box::new(FinalRule::new("InnerProxy"))]);
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(SubRuleRule::new("block-a", block))];

        let set = CompiledRuleSet::build(&rules);
        let result = set
            .match_rules(&Metadata::default(), &rules, &|_| true)
            .expect("sub-rule inner final must match");

        assert_eq!(result.adapter_name, "InnerProxy");
        assert_eq!(result.adapter_index, None);
        assert_eq!(result.rule_type, RuleType::SubRule);
        assert_eq!(result.rule_payload, "block-a");
    }

    #[test]
    fn domain_wildcard_regex_prefilter_preserves_matches() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainWildcardRule::new("*.wild.example", "WildcardProxy").unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = LegacyDomainIndex::build(&rules);
        let compiled = CompiledRuleSet::build(&rules);

        for host in ["one.wild.example", "two.notwild.example"] {
            let metadata = Metadata {
                host: host.into(),
                dst_port: 443,
                ..Default::default()
            };
            let legacy = match_engine::match_rules(&metadata, &rules, &index, &|_| true)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
            let compiled = compiled
                .match_rules(&metadata, &rules, &|_| true)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));

            assert_eq!(compiled, legacy, "metadata host={host}");
        }
    }

    #[test]
    fn plain_domain_regex_gets_literal_prefilter_only_when_safe() {
        assert_eq!(
            required_literal_from_plain_regex("github"),
            Some("github".to_string())
        );
        assert_eq!(required_literal_from_plain_regex(r"^github\.com$"), None);

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainRegexRule::new("github", "RegexProxy").unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = LegacyDomainIndex::build(&rules);
        let compiled = CompiledRuleSet::build(&rules);

        for host in ["api.github.com", "gitlab.com"] {
            let metadata = Metadata {
                host: host.into(),
                dst_port: 443,
                ..Default::default()
            };
            let legacy = match_engine::match_rules(&metadata, &rules, &index, &|_| true)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
            let compiled = compiled
                .match_rules(&metadata, &rules, &|_| true)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));

            assert_eq!(compiled, legacy, "metadata host={host}");
        }
    }

    #[test]
    fn compiled_rules_match_legacy_engine_for_lowered_and_fallback_rules() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(PortRule::new("8443", "PortProxy", false).unwrap()),
            Box::new(DomainKeywordRule::new("video", "KeywordProxy")),
            Box::new(IpCidrRule::new("203.0.113.0/24", "CidrProxy", false, true).unwrap()),
            Box::new(DomainWildcardRule::new("*.wild.example", "WildcardProxy").unwrap()),
            Box::new(OrRule::new(
                vec![
                    Box::new(PortRule::new("9000", "unused", false).unwrap()),
                    Box::new(DomainRule::new("fallback.example", "unused")),
                ],
                "FallbackProxy",
            )),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = LegacyDomainIndex::build(&rules);
        let compiled = CompiledRuleSet::build(&rules);

        let cases = [
            Metadata {
                host: "plain.example".into(),
                dst_port: 8443,
                ..Default::default()
            },
            Metadata {
                host: "api.video.example".into(),
                dst_port: 443,
                ..Default::default()
            },
            Metadata {
                host: "cidr.example".into(),
                dst_ip: Some("203.0.113.9".parse::<IpAddr>().unwrap()),
                dst_port: 443,
                ..Default::default()
            },
            Metadata {
                host: "one.wild.example".into(),
                dst_port: 443,
                ..Default::default()
            },
            Metadata {
                host: "fallback.example".into(),
                dst_port: 443,
                ..Default::default()
            },
            Metadata {
                host: "nomatch.example".into(),
                dst_port: 443,
                ..Default::default()
            },
        ];

        for metadata in cases {
            let legacy = match_engine::match_rules(&metadata, &rules, &index, &|_| true)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
            let compiled = compiled
                .match_rules(&metadata, &rules, &|_| true)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));

            assert_eq!(compiled, legacy, "metadata host={}", metadata.host);
        }
    }

    /// Both engines must agree under continue-on-missing-target semantics —
    /// the `|_| true` run above cannot exercise the skip path (issue #513).
    /// Covers dedup twins, shadowed pairs, covered CIDRs, a dead MATCH
    /// terminator, and a second domain hit after a skipped one.
    #[test]
    fn compiled_rules_match_legacy_engine_under_missing_targets() {
        let mut rules = filler_suffix_rules(70); // force the indexed plan
        rules.extend([
            Box::new(DomainRule::new("ads.example", "GHOST")) as Box<dyn Rule>,
            Box::new(DomainSuffixRule::new("example", "REJECT")),
            Box::new(DomainRule::new("dup.example.com", "GHOST")),
            Box::new(DomainRule::new("dup.example.com", "Twin")),
            Box::new(IpCidrRule::new("10.0.0.0/8", "GHOST", false, true).unwrap()),
            Box::new(IpCidrRule::new("10.1.0.0/16", "CidrTwin", false, true).unwrap()),
            Box::new(FinalRule::new("GHOST")),
            Box::new(FinalRule::new("DIRECT")),
        ]);
        let index = LegacyDomainIndex::build(&rules);
        let compiled = CompiledRuleSet::build(&rules);
        assert!(
            !compiled.uses_linear_scan_plan(),
            "fixture must exercise the indexed plan"
        );
        let present = |name: &str| name != "GHOST";

        for metadata in [
            Metadata {
                host: "ads.example".into(),
                ..Default::default()
            },
            Metadata {
                host: "dup.example.com".into(),
                ..Default::default()
            },
            Metadata {
                dst_ip: Some("10.1.2.3".parse::<IpAddr>().unwrap()),
                ..Default::default()
            },
            Metadata {
                host: "s0.example".into(),
                ..Default::default()
            },
            Metadata::default(),
        ] {
            let legacy = match_engine::match_rules(&metadata, &rules, &index, &present)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
            let strict = compiled
                .match_rules(&metadata, &rules, &present)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
            let lazy = match compiled.match_rules_lazy(&metadata, &rules, &present) {
                LazyMatchOutcome::Matched(m) => Some((m.adapter_name, m.rule_type, m.rule_payload)),
                LazyMatchOutcome::NeedsEnrichment { .. } | LazyMatchOutcome::NoMatch => None,
            };
            assert_eq!(strict, legacy, "metadata host={}", metadata.host);
            assert_eq!(lazy, legacy, "lazy, host={}", metadata.host);
        }
    }

    #[test]
    fn glob_matcher_matches_wildcard_regex_semantics() {
        // Reference: the exact regex the legacy DomainWildcardRule compiles.
        fn reference(pattern: &str) -> Regex {
            let escaped = regex::escape(pattern);
            let expanded = escaped.replace(r"\*", r"[^.]+");
            Regex::new(&format!("^(?i){expanded}$")).unwrap()
        }

        let patterns = [
            "*.example.com",
            "example.*",
            "*example.com",
            "*.example.*",
            "*.*.example.com",
            "a*b.example.com",
            "foo*bar*baz.com",
            "www.*.example.com",
            "*.co.uk",
            "*",
            "*.*",
            "**.example.com", // adjacent stars -> regex fallback path
            "exact.example.com",
        ];
        let hosts = [
            "",
            "example.com",
            "a.example.com",
            "a.b.example.com",
            "a.b.c.example.com",
            "one.example.com",
            "example.org",
            "x.co.uk",
            "a.b.co.uk",
            "fooXbar.example.com",
            "fooXbarYbaz.com",
            "wwwy.example.com",
            "www.api.example.com",
            "www.a.b.example.com",
            "fooexample.com",
            ".example.com",
            "exact.example.com",
            "EXACT.EXAMPLE.COM",
            "ONE.EXAMPLE.COM",
        ];

        for pattern in patterns {
            let re = reference(pattern);
            let matcher = compile_domain_wildcard(pattern).expect("wildcard must compile");
            for host in hosts {
                assert_eq!(
                    matcher.matches(host),
                    re.is_match(host),
                    "pattern={pattern:?} host={host:?}",
                );
            }
        }
    }

    #[test]
    fn common_wildcards_compile_to_glob_not_regex() {
        for pattern in ["*.example.com", "example.*", "*.example.*", "a*b.com"] {
            assert!(
                matches!(
                    *compile_domain_wildcard(pattern).unwrap(),
                    WildcardMatcher::Glob(_)
                ),
                "expected structural glob for {pattern:?}",
            );
        }
        // Adjacent stars are the documented fallback to the regex engine.
        assert!(matches!(
            *compile_domain_wildcard("**.example.com").unwrap(),
            WildcardMatcher::Regex(_)
        ));
    }

    #[derive(Default)]
    struct CallCounts {
        rule_type: AtomicUsize,
        adapter: AtomicUsize,
        payload: AtomicUsize,
    }

    impl CallCounts {
        fn reset(&self) {
            self.rule_type.store(0, Ordering::Relaxed);
            self.adapter.store(0, Ordering::Relaxed);
            self.payload.store(0, Ordering::Relaxed);
        }
    }

    struct CountingRule {
        rule_type: RuleType,
        adapter: &'static str,
        payload: &'static str,
        matches: bool,
        match_count: Arc<AtomicUsize>,
        counts: Arc<CallCounts>,
    }

    impl CountingRule {
        fn new(
            rule_type: RuleType,
            adapter: &'static str,
            payload: &'static str,
            matches: bool,
            match_count: Arc<AtomicUsize>,
            counts: Arc<CallCounts>,
        ) -> Self {
            Self {
                rule_type,
                adapter,
                payload,
                matches,
                match_count,
                counts,
            }
        }
    }

    impl Rule for CountingRule {
        fn rule_type(&self) -> RuleType {
            self.counts.rule_type.fetch_add(1, Ordering::Relaxed);
            self.rule_type
        }

        fn match_metadata(&self, _metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
            self.match_count.fetch_add(1, Ordering::Relaxed);
            self.matches
        }

        fn adapter(&self) -> &str {
            self.counts.adapter.fetch_add(1, Ordering::Relaxed);
            self.adapter
        }

        fn payload(&self) -> &str {
            self.counts.payload.fetch_add(1, Ordering::Relaxed);
            self.payload
        }
    }
}
