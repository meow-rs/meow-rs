# Rule engine retained-heap reduction (2026-09)

Memory-footprint pass over the rule matching module (`meow-trie`,
`meow-rules`, and the compiled rule IR in `meow-tunnel`). Goal: minimise
the heap the rule engine *retains* after config load, and the transient
peak while loading, without regressing lookup latency.

## Method

Opt-in harnesses run each structure at realistic scale under a counting
global allocator (requested bytes only — real RSS adds ~16 B of allocator
overhead per live allocation, so the allocation-count column matters as
much as the byte column):

```bash
# meow-rules structures (+ a real config / GeoIP DB when the env vars are set)
MEOW_RULES_FIXTURE=config.yaml MEOW_GEOIP_MMDB=Country.mmdb \
  cargo test -p meow-rules --test footprint_test --release -- --ignored --nocapture

# compiled rule IR over a synthetic 7.5k-rule config
cargo test -p meow-tunnel --test rule_ir_synthetic_footprint --release -- --ignored --nocapture
```

`before` = commit `6185369` (0.21.2); `after` = this change set. Release
profile, aarch64 Linux.

## Retained heap

| Structure | Before | After | Live allocs before → after |
|---|---|---|---|
| `DomainRuleSet`, 100k entries (60% `+.`) | 7,613 KiB | 1,456 KiB | 258,256 → 3 |
| `IpCidrRuleSet`, 10k IPv4 + 2k IPv6 CIDRs | 933 KiB | 82 KiB | 59,759 → 4 |
| `GeositeDB`, 3 categories × 40k domains | 9,624 KiB | 1,964 KiB | 325,076 → 17 |
| `CountryIndex` CN + US from `Country.mmdb` | 12,601 KiB | 1,686 KiB | 806,487 → 13 |
| 7.5k parsed rules (synthetic mix) | 633 KiB | 451 KiB | 22,503 → 7,940 |
| 7,538 parsed rules (real config) | 649 KiB | 443 KiB | 22,614 → 7,753 |
| `DomainTrie<usize>` index over 7.5k rules | 1,054 KiB | 290 KiB | 18,775 → 4 |
| `CompiledRuleSet::build`, 7.5k rules (6,914 live slots) | 600 KiB | 541 KiB | 277 → 277 |

## Load-time peak (above the pre-load live size)

| Structure | Before | After |
|---|---|---|
| `DomainRuleSet`, 100k entries | 32,879 KiB | 7,200 KiB |
| `GeositeDB`, 3 × 40k domains (from `.mrs` bytes) | 23,626 KiB | 5,033 KiB |
| `CountryIndex` CN + US | 12,615 KiB | 4,593 KiB |
| `DomainTrie<usize>` index, 7.5k rules | 4,200 KiB | 1,635 KiB |

## Lookup latency (criterion medians, `meow-trie` `trie_bench`)

| Case | Before | After |
|---|---|---|
| sealed hit, 10k patterns | 176 ns | 164 ns |
| sealed miss, 10k patterns | 174 ns | 153 ns |
| unsealed hit, 10k patterns | 135 ns | 140 ns |
| seal, 10k patterns | 2.74 ms | 2.79 ms |

## Lookup latency (criterion medians, `meow-rules` `ipcidr_ruleset_bench`)

| Case | Before (`iprange` trie) | After (`IpRangeSet`) |
|---|---|---|
| hit, 10k CIDRs | 19.5 ns | 1.6 ns |
| miss, 10k CIDRs | 3.3 ns | 1.5 ns |
| build, 10k CIDRs | 1.51 ms | 0.44 ms |

## What changed

1. **Sealed `DomainTrie` layout** (`crates/meow-trie/src/trie.rs`). The
   sealed form is a breadth-first node array (8 B per node: label offset +
   first-child index with a 3-bit value mask), one contiguous label-sorted
   child run per node, one deduplicated `.`-terminated label arena, and a
   values side table addressed by a sampled rank over the masks. Four heap
   allocations total, regardless of size. The build phase is one node
   vector plus one `(parent, label-id) → child` hash map and a label
   interner, replacing a `HashMap` per node; unsealed tries still answer
   searches.
2. **`IpRangeSet`** (`crates/meow-rules/src/ip_set.rs`) replaces the
   `iprange` Patricia tries for GEOIP / SRC-GEOIP / IP-ASN rules, ipcidr
   rule-sets, and the IR's CIDR coverage oracle: sorted, coalesced
   inclusive intervals in parallel `starts` / `ends` arrays (8 B per IPv4
   interval, 32 B per IPv6 interval). Membership is one binary search.
   Sorted input (an MMDB walk) merges on insert, so the build peak is
   about the finished set. The `iprange` dependency is gone.
3. **Rule structs.** Adapter names are interned into shared `Arc<str>`
   (`crates/meow-rules/src/adapter.rs`; one block per distinct name
   instead of one `String` per rule) and payloads are inline `SmolStr`
   (97% of real-config payloads fit inline), so a parsed rule is one heap
   block. Port lists are `Box<[(u16, u16)]>`.
4. **Compiled IR slot** (`crates/meow-tunnel/src/rule_ir.rs`) is 40 B
   instead of 80 B: `u32` indices, no per-slot payload copy (a hit borrows
   the payload from the source rule), string ops as `Box<str>`, rare fat
   ops boxed. A unit test pins `CompiledRuleSlot ≤ 40 B`, `RuleOp ≤ 24 B`.
   The domain index stores `u32` rule indices.
5. **Streaming loaders.** Geosite `.mrs` and rule-provider `.mrs` payloads
   stream from the zstd decoder straight into the set builders
   (`FrameReader`, `stream_geosite_payload`, `stream_string_list`,
   `stream_ipcidr_list`, `UpstreamRuleSetReader`); neither the decompressed
   payload nor a per-entry `String` list is materialised.
