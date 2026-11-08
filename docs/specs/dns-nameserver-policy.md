# Spec: DNS nameserver-policy and fallback-filter (M1.E-3, M1.E-4)

Status: Approved (architect 2026-04-11)
Owner: pm
Tracks roadmap items: **M1.E-3** (nameserver-policy), **M1.E-4** (fallback-filter)
Depends on: M1.E-1/E-2 (`dns-doh-dot.md`) — nameserver URL parser reused here.
See also: [`docs/specs/dns-doh-dot.md`](dns-doh-dot.md) §URL parser.
Upstream reference: `dns/resolver.go`, `dns/client/client.go`.

## Motivation

`nameserver-policy` maps domain patterns to dedicated nameserver lists.
Without it, all DNS queries go to the same `nameservers:` pool, which
breaks split-horizon setups: internal `corp.internal` domains must
use the corporate resolver, while public domains use a privacy-respecting
public resolver. Real enterprise subscriptions depend on this.

`fallback-filter` controls when the `fallback:` nameservers replace the
primary `nameservers:` result. The current implementation only tries
fallback when the primary **fails** (NXDOMAIN, timeout). In practice
many censoring resolvers return fake responses (DNS poisoning) rather
than failing — so fallback is triggered only on GeoIP anomaly or bogon
IP. Without the filter, the fallback mechanism provides no censorship
protection beyond timeout handling.

Both features are listed in the gap analysis as absent and contribute
directly to the M1 "typical subscription loads and routes correctly" goal.

## Scope

In scope:

1. `nameserver_policy: { pattern: [nameservers] }` YAML field parsed
   in `meow-config/src/dns_parser.rs`.
2. Domain patterns: exact (bare) domains and the wildcard prefixes `+.`
   (apex plus any-depth subdomains), `*.` (exactly one subdomain label),
   and `.` (any-depth subdomains, apex excluded) — the same four kinds
   `DomainTrie` accepts everywhere else.
   No `geosite:` or `rule-set:` references in M1 — defer to M1.D-2
   and a later DNS-rules integration spec.
3. Nameserver URLs per policy entry: same URL syntax as M1.E-1
   (`udp://`, `tcp://`, `https://`, `tls://` — plain and encrypted).
4. Lookup order: nameserver-policy match checked before the main
   resolver pool.
5. `fallback-filter` YAML field with three gate types:
   - `geoip: bool` + `geoip-code: str` — IP not in listed country → use fallback.
   - `ipcidr: [CIDR, ...]` — IP in any listed range → use fallback (bogon gating).
   - `domain: [pattern, ...]` — domain matches pattern → always use fallback.
6. `fallback: []` remains an unconditional fallback-on-main-failure list
   unless `fallback-filter` adds additional trigger conditions.

Out of scope:

- **`geosite:` and `rule-set:` patterns in nameserver-policy** — depend on
  M1.D-2 (geosite DB) and M1.D-5 (rule-provider). Deferred.
- **`dhcp://` nameserver** — device-specific; deferred.
- **Per-policy DoH/DoT client instances with different TLS configs** — all
  policy nameservers share the global TLS config from M1.E-1.
- **`fallback-filter.geoip: true` when no MMDB installed** — treated as
  `geoip: false` (skip GeoIP gate) with a `warn!` at startup. Not an error.

## User-facing config

```yaml
dns:
  enable: true
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
  fallback:
    - 1.0.0.1
    - 8.8.4.4
  nameserver-policy:
    "+.corp.internal": [192.168.1.53, 192.168.1.54]   # corporate resolver
    "+.google.com": https://dns.google/dns-query        # single-server policy (string OK)
    "example.com": [udp://9.9.9.9, tls://1.1.1.1:853]
    "geosite:cn": [https://doh.pub/dns-query, 223.5.5.5]  # geosite category (needs geosite DB)
    "rule-set:cn-domain": [https://doh.pub/dns-query]     # rule-provider (behavior: domain/classical)
  fallback-filter:
    geoip: true               # default: true
    geoip-code: CN            # default: CN
    ipcidr:
      - 240.0.0.0/4           # CLASS E (reserved)
      - 0.0.0.0/8             # THIS network
      - 127.0.0.0/8           # loopback (unexpected from upstream DNS)
    domain:
      - "+.google.cn"         # always use fallback for these (known poisoned)
      - "+.baidu.com"
```

Field reference — `nameserver-policy`:

| Format | Meaning |
|--------|---------|
| `"exact.domain": [servers]` | Exact match on `exact.domain`. |
| `"+.sub.domain": [servers]` | Matches `sub.domain` itself and all subdomains at any depth. |
| `"*.sub.domain": [servers]` | Matches exactly one subdomain label (`a.sub.domain`); neither `sub.domain` nor `a.b.sub.domain`. |
| `".sub.domain": [servers]` | Matches subdomains at any depth (`a.sub.domain`, `a.b.sub.domain`); never `sub.domain` itself. |
| `"geosite:<cat>[,<cat>]": [servers]` | Matches domains in the geosite DB category/ies. Requires a loaded geosite DB; skipped with a warning if absent. |
| `"rule-set:<name>[,<name>]": [servers]` | Matches domains in the named rule-provider. Provider behavior must be `domain` (or `classical`, warned); `ipcidr` is a hard error; a missing provider is a hard error. |
| Value is a string | Treated as a single-element list. |
| Value is a list | Multiple nameservers for this policy; first responding wins. |

**Lookup order — document order is the priority** (mihomo
`parseNameServerPolicy` + `makePolicy` parity): the policy is a sequence of
"arms" in the order the keys are written. A run of consecutive domain keys
(`bare`, `+.`, `*.`, `.`) merges into one domain-trie arm; each
`geosite:`/`rule-set:` key appends a matcher arm and closes the open domain
block. A query walks the arms top-down and the first match wins — so a
`rule-set:` or `geosite:` key written before a domain key shadows it. Such a
shadow is reported at load: a bare or `+.` key written after a matcher arm
that already matches the domain it names, with different nameservers, logs
a warning naming both keys (move the domain key above the matcher to
override it; `*.`/`.` keys are not checked). A matcher key skipped in
lenient mode (no geosite DB, an empty name, an unsupported prefix) adds no
arm but still closes the open domain block, so the domain keys around it
keep the precedence they get once it loads. Within
one domain-trie arm the usual specificity rules decide (exact > `*.` > `.`
at the deepest node); two keys landing on the SAME trie slot — e.g. `x` and
`+.x`, which both write `x`'s exact slot — resolve to the document-last
writer (mihomo `setData` overwrite). A YAML-literal duplicate key (other
than `<<`, a merge directive the parser consumes before duplicate
detection — two `<<:` lines in one map expand both anchors) is a
hard parse error (`duplicate mapping key: …`): every ingest path
(`-f`/`-t`, `--config-string`, `PUT /configs`) funnels through
`parse_raw_yaml`, whose serde-saphyr parser rejects the document before
the policy map is built. That parse-layer check compares integer keys by
resolved value (`0x1F` and `31` collide though spelled differently) and
every other scalar kind by canonical tag plus de-quoted text — untagged
keys share the `str` tag, so `1.0` and `"1.0"` collide while `TrUe` and
`"true"` do not; keys that get past it still fail when they
deliver identical text to the `String`-keyed map — `1:` and `"1":` both
arrive as `"1"` — where the tree raises its own `duplicate mapping key`
rather than let the second entry overwrite the first. The
first-position/last-value fold (mihomo `orderedmap.Set`) only decides
duplicates from non-literal sources — a programmatically built map, or
the expanded segments of one comma-mixed key. serde-saphyr expands a
`<<:` merge key in the event
stream: the anchor's entries append at the END of the map no matter
where the `<<:` line is written, and an explicit key keeps its written
position and wins over a merged same-name key — merged entries are
therefore always the lowest-priority arms, so a merged
`rule-set:`/`geosite:` key can never shadow an explicit domain key. The
`<<:` line's own position carries no ordering weight. Bare-key lookups
are case-insensitive: the query is folded before the match.

Nameserver URL format: identical to M1.E-1 (`udp://`, `tcp://`, `https://`, `tls://`).

Field reference — `fallback-filter`:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `geoip` | bool | `true` | Enable GeoIP gate. If primary result IP is **not** in `geoip-code` country → trigger fallback. |
| `geoip-code` | string | `"CN"` | Two-letter country code checked by GeoIP gate. |
| `ipcidr` | `[]string` | `[]` | Additional IP ranges. Primary result IP in any range → trigger fallback. |
| `domain` | `[]string` | `[]` | Domain patterns (exact, `+.`, `*.`, or `.` — same kinds as `nameserver-policy` keys). Domain match → always trigger fallback, skip primary result entirely. |

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | `geosite:`/`rule-set:` patterns in nameserver-policy — upstream supports | — | **Implemented.** `geosite:` compiles into a matcher from the loaded geosite DB (issue #299 / #237). `rule-set:` compiles into a matcher from the loaded rule-providers: `Domain` behavior matches directly, `Classical` warns once and matches only its domain rules, `IpCidr` is a hard error, and a missing provider is a hard error (`not found rule-set: <name>`). The matcher snapshots the provider on each lookup, so background refreshes take effect automatically. Other unknown `:`-prefixed patterns still warn-once and skip. |
| 2 | `dhcp://` nameserver — upstream supports | B | Warn-once at parse time; entry skipped. |
| 3 | `fallback-filter.geoip: true` with no MMDB — upstream errors at startup | B | We treat as `geoip: false` with `warn!`. Single-resolver configs are valid without a GeoIP DB. NOT a startup error. |
| 4 | nameserver-policy entry with no valid nameservers (all skipped) → upstream panics | A | Hard parse error: "nameserver-policy entry 'KEY' has no valid nameservers after skipping unsupported prefixes." A policy entry with zero valid nameservers silently routes the configured domain to global nameservers — a potential DNS leakage for internal/corporate domains. Fail loudly. |
| 5 | fallback-filter `domain` pattern syntax | — | We match upstream: entries feed `DomainSetBuilder.Insert` there, `DomainTrie::insert` here — bare/`+.`/`*.`/`.` all follow the canonical matrix. Consistent with nameserver-policy patterns. |

**Upstream naming note:** upstream Go mihomo calls a similar concept `fake-ip-filter` in some contexts (for the nameserver-policy domain-bypass feature). Our `fallback-filter.domain` is the equivalent mechanism. Users grepping upstream terminology should be aware of this naming difference.

## Internal design

### Lookup flow (updated)

```
query(domain, qtype):
  1. Hosts trie lookup → hit: return
  2. Cache lookup → hit: return
  3. Nameserver-policy lookup:
     → match: use policy nameservers (parallel, first-response wins)
       → fallback-filter check (if fallback configured):
         → gated: discard policy result, try global fallback
         → not gated: return policy result
       → no fallback: return policy result (or error)
  4. Global nameservers (parallel, first-response wins)
     → fallback-filter check (if fallback configured):
       → gated: try fallback nameservers
       → not gated: return
  5. Fallback nameservers (if main fails OR filter gates)
     → return result (or error if fallback also fails)
```

Note: policy nameservers and global nameservers both pass through
fallback-filter. A domain-pattern gate in fallback-filter bypasses
steps 3 and 4 (skips primary entirely) and goes straight to step 5.

Divergence note: upstream `ipExchange` treats a policy match as terminal —
it returns before the domain gate and the IP filter. meow's default tiers
defer to `fallback-filter` even on a policy match (the flow above);
`nameserver-policy-exclusive: true` restores the upstream order for
matched domains.

### NameserverPolicy struct

```rust
// in meow-dns/src/resolver.rs

pub struct PolicyEntry {
    nameservers: Vec<TokioResolver>,   // one per URL, pre-built at startup
}

enum PolicyArm {
    // A run of consecutive domain keys merged into one trie.
    Domains(DomainTrie<PolicyEntry>),
    // One geosite:/rule-set: matcher closure.
    Matcher(MatcherPolicyEntry),
}

pub struct NameserverPolicy {
    // Document order — the lookup priority.
    arms: Vec<PolicyArm>,
}

impl NameserverPolicy {
    pub fn lookup(&self, domain: &str) -> Option<&PolicyEntry> {
        // First matching arm wins.
        self.arms.iter().find_map(|arm| match arm {
            PolicyArm::Domains(trie) => trie.search(domain),
            PolicyArm::Matcher(m) => (m.matcher)(domain).then_some(&m.entry),
        })
    }
}
```

**Trie reuse**: `DomainTrie` from `meow-trie` already supports the
`+.` wildcard semantics used in rule matching. No new trie implementation
needed — import and reuse.

### FallbackFilter struct

```rust
pub struct FallbackFilter {
    geoip_enabled: bool,
    geoip_code: String,               // "CN"
    ipcidr: Vec<IpNet>,               // parsed IP-CIDR ranges
    domain: DomainTrie<()>,           // domain patterns → always use fallback
}

impl FallbackFilter {
    /// Returns true if the main result should be discarded and fallback used.
    pub fn should_use_fallback(&self, domain: &str, addrs: &[IpAddr], mmdb: Option<&MaxMindDB>) -> bool {
        // 1. Domain gate (fastest — no IP needed)
        if self.domain.search(domain).is_some() { return true; }
        // 2. IP-CIDR gate
        for addr in addrs {
            if self.ipcidr.iter().any(|net| net.contains(addr)) { return true; }
        }
        // 3. GeoIP gate
        if self.geoip_enabled {
            if let Some(db) = mmdb {
                for addr in addrs {
                    if let Ok(country) = db.lookup_country(*addr) {
                        if country != self.geoip_code { return true; }
                    }
                }
            }
        }
        false
    }
}
```

**Fallback behaviour when both main and fallback are gated**:
return the fallback result regardless. The filter does not re-apply
to the fallback response — we trust the fallback nameservers to return
clean results (they were configured by the user for this purpose).

### Resolver struct changes

```rust
pub struct Resolver {
    main: Vec<TokioResolver>,              // was: TokioResolver (single)
    fallback: Option<Vec<TokioResolver>>,  // unchanged in shape, may gain per-fallback config later
    policy: Option<NameserverPolicy>,      // NEW
    fallback_filter: Option<FallbackFilter>, // NEW
    cache: DnsCache,
    mode: DnsMode,
    hosts: DomainTrie<Vec<IpAddr>>,
    inflight: DashMap<String, InflightTx>,
}
```

`main` changes from a single `TokioResolver` to `Vec<TokioResolver>` to
support the parallel-first-response model when multiple nameservers are
configured. This is a breaking change to the Resolver constructor — update
`dns_parser.rs` accordingly.

**Parallel resolution**: when multiple servers exist in a pool (global or policy),
send the query to all in parallel and return the first successful response.
Use `futures::future::select_ok` — it returns the first `Ok` result and
cancels remaining futures, but continues waiting if an individual future returns
`Err` (SERVFAIL from one server doesn't short-circuit the pool). This matches
upstream Go mihomo's parallel dispatch and avoids the error-vs-success filtering
boilerplate of a manual `FuturesUnordered` loop.

## Acceptance criteria

1. `nameserver-policy` exact match routes query to policy nameservers, not global.
2. `+.corp.internal` match routes `foo.corp.internal` to policy nameservers.
3. `+.corp.internal` match routes `corp.internal` itself to policy nameservers
   (the `+.` prefix includes the root, not just subdomains).
4. Non-matching domain uses global `nameservers`.
5. Policy match with `geosite:` prefix → warn-once, skip entry, use global.
   Class B per ADR-0002: NOT hard error.
6. `fallback-filter.geoip: true`, primary returns IP not in `geoip-code` country
   → fallback used.
7. `fallback-filter.ipcidr: [240.0.0.0/4]`, primary returns `240.x.x.x`
   → fallback used.
8. `fallback-filter.domain: ["+.google.cn"]`, query for `www.google.cn`
   → fallback used (primary not consulted).
9. `fallback-filter.geoip: true` with no MMDB → GeoIP gate skipped,
   `warn!` at startup. NOT a startup error. Class A per ADR-0002.
10. All three gate conditions disabled (`geoip: false`, empty `ipcidr`, empty
    `domain`) → fallback only on primary failure (existing behaviour unchanged).
11. Multiple global nameservers: parallel dispatch, first valid response returned.
12. Policy entry with all-invalid URLs → warn-once, falls through to global.
    Class A per ADR-0002.

## Test plan (starting point — qa owns final shape)

**Unit (`dns/resolver.rs`):**

- `nameserver_policy_exact_match_uses_policy_servers` — mock resolver for
  `example.com`; assert query goes to policy mock, not global mock.
  Upstream: `dns/resolver.go::PolicyResolver`. NOT global nameservers when
  exact match exists.
- `nameserver_policy_wildcard_match_subdomain` — `+.corp.internal` policy;
  query `foo.corp.internal` → policy mock used.
- `nameserver_policy_wildcard_match_root_domain` — `+.corp.internal` policy;
  query `corp.internal` → policy mock used. NOT global. (`+.` includes root.)
- `nameserver_policy_no_match_uses_global` — non-matching domain → global mock.
- `fallback_filter_geoip_gates_non_cn_response` — main returns `8.8.8.8`
  (US IP); geoip-code=CN; MMDB stub returns US → fallback triggered.
  Upstream: `dns/resolver.go::ipWithFallback`. NOT pass-through.
- `fallback_filter_ipcidr_gates_bogon_response` — main returns `240.0.0.1`;
  ipcidr includes `240.0.0.0/4` → fallback triggered.
- `fallback_filter_domain_pattern_skips_primary` — domain `+.google.cn` in
  filter; query `www.google.cn` → primary not queried; fallback queried.
  NOT primary-then-discard — skip primary entirely.
- `fallback_filter_disabled_uses_fallback_only_on_failure` — all gates off;
  main succeeds → fallback never called.
- `fallback_filter_geoip_no_mmdb_warns_and_skips` — MMDB = None; at startup
  log `warn!`; GeoIP gate never triggers. NOT startup error. Class A per ADR-0002.
- `parallel_nameservers_returns_first_response` — two mock nameservers; one
  delays 100ms, one responds immediately → fast one's result returned.
  NOT sequential (faster-first is the invariant, not server[0]-always-first).

**Unit (config parser `dns_parser.rs`):**

- `parse_nameserver_policy_exact` — single exact domain entry.
- `parse_nameserver_policy_wildcard` — `+.` prefix entry.
- `parse_nameserver_policy_string_value` — string value (single server) vs list.
- `parse_nameserver_policy_geosite_prefix_warns` — `geosite:cn` key → warn-once,
  no hard error. Class B per ADR-0002.
- `parse_fallback_filter_all_fields` — all three gate types populated.
- `parse_fallback_filter_defaults` — no `fallback-filter` in YAML → defaults
  (`geoip: true`, `geoip-code: CN`, empty ipcidr/domain).

## Implementation checklist (engineer handoff)

- [ ] Update `RawDns` in `raw.rs` to add `nameserver_policy` and `fallback_filter` fields.
- [ ] Parse `nameserver-policy` entries in `dns_parser.rs`:
      — domain key → exact (bare) or `+.`/`*.`/`.` wildcard.
      — value string OR list → Vec<String> URLs.
      — warn-once and skip unknown-prefix entries (`geosite:`, `rule-set:`).
- [ ] Parse `fallback-filter` fields in `dns_parser.rs`.
- [ ] Build `NameserverPolicy` trie in `Resolver::new()`, reusing `DomainTrie` from `meow-trie`.
- [ ] Build `FallbackFilter` in `Resolver::new()`:
      — `geoip: true` with no MMDB: warn at startup, set `geoip_enabled = false`.
- [ ] Change `main` from single `TokioResolver` to `Vec<TokioResolver>` with parallel dispatch.
- [ ] Wire new lookup flow in `do_lookup()` (policy → global → fallback, with filter).
- [ ] Update `docs/roadmap.md` M1.E-3 and M1.E-4 rows with merged PR link.

## Resolved questions (architect sign-off 2026-04-11)

1. **Parallel dispatch: use `futures::future::select_ok`** — purpose-built for
   "first success wins, cancel losers" semantics. See §Parallel resolution.

2. **fallback-filter gates both policy and global nameserver results** — confirmed
   correct. A policy nameserver can be poisoned just as easily as a global one.

3. **Fallback results are not re-filtered** — confirmed correct. Fallback is the
   user's explicitly-configured trusted alternate; re-filtering would create a
   rejection loop if both pools trip the same GeoIP/CIDR check.

4. **`Vec<TokioResolver>` change lands in M1.E-1, not this spec.** The M1.E-1
   (dns-doh-dot) spec is patched to land `main: Vec<TokioResolver>` with parallel
   `select_ok` dispatch; single-nameserver configs produce a Vec of length 1
   transparently. This spec (M1.E-3) is then purely additive with no
   `Resolver::new()` constructor churn.
