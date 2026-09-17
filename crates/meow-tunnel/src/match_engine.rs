use meow_common::{find_process, Metadata, Rule, RuleMatchHelper, RuleType};
use meow_trie::DomainTrie;
use std::net::SocketAddr;
use tracing::trace;

/// One borrowed match result. String fields point into the matched rule, so
/// rule matching itself does not allocate even for long adapter names or
/// diagnostic payloads.
pub struct MatchResult<'a> {
    pub adapter_name: &'a str,
    pub rule_type: RuleType,
    pub rule_payload: &'a str,
}

/// Index of DOMAIN and DOMAIN-SUFFIX rules keyed by the trie.
///
/// [`Self::search`] returns the **minimum rule index across every pattern
/// matching the host** (min-index semantics), not the most-specific pattern.
/// Under first-match-wins ordering this means a trie hit at `T` proves that
/// no DOMAIN/DOMAIN-SUFFIX rule earlier than `T` matches the host — and a
/// trie miss proves none matches at all. Suffix rules are indexed under both
/// `+.pattern` (subdomains) and the bare pattern (the apex domain itself), so
/// those proofs hold for every host a suffix rule can match.
///
/// The adapter and payload are borrowed from the rule slice after lookup,
/// which keeps the index compact and avoids per-match result allocation.
pub struct DomainIndex {
    /// Rule indices as `u32`: halves the trie's value table versus `usize`
    /// and no config approaches 2^32 rules.
    trie: DomainTrie<u32>,
}

impl DomainIndex {
    pub fn empty() -> Self {
        Self {
            trie: DomainTrie::new(),
        }
    }

    /// Build a sealed index from the rule list.
    pub fn build(rules: &[Box<dyn Rule>]) -> Self {
        let mut index = Self::empty();
        for (idx, rule) in rules.iter().enumerate() {
            index.insert_rule(idx, rule.rule_type(), rule.payload());
        }
        index.seal();
        index
    }

    /// Index one rule's pattern. Returns `true` iff the pattern was fully
    /// indexed — meaning the trie completely owns this rule's match
    /// semantics, so callers may skip the rule during linear scans.
    ///
    /// Only DOMAIN and DOMAIN-SUFFIX rules with plain hostname payloads are
    /// indexable. Degenerate payloads (empty, leading `.`/`*`/`+`, empty
    /// labels, non-ASCII) would change meaning under the trie's wildcard
    /// syntax, so they return `false` and stay on the scan path.
    ///
    /// Duplicate patterns keep the first (minimum) rule index: inserts happen
    /// in ascending rule order and the trie's per-slot value is first-write.
    pub fn insert_rule(&mut self, index: usize, rule_type: RuleType, payload: &str) -> bool {
        let index = u32::try_from(index).expect("rule index exceeds u32");
        match rule_type {
            RuleType::Domain => indexable_pattern(payload) && self.trie.insert(payload, index),
            RuleType::DomainSuffix => {
                if !indexable_pattern(payload) {
                    return false;
                }
                // A suffix rule matches the apex domain itself as well as any
                // subdomain; index both forms so a trie miss proves no suffix
                // rule matches.
                let subdomains = self.trie.insert(&format!("+.{payload}"), index);
                let apex = self.trie.insert(payload, index);
                subdomains && apex
            }
            RuleType::DomainWildcard => {
                // Only the dominant `*.domain` shape is expressible: the
                // trie's star kind matches exactly one extra label, which is
                // byte-for-byte the wildcard glob semantics for this shape
                // (`*` = one non-empty dot-free run). Other shapes
                // (`a*b.com`, `example.*`, interior stars) stay on the scan
                // path.
                star_wildcard_indexable(payload) && self.trie.insert(payload, index)
            }
            _ => false,
        }
    }

    pub fn seal(&mut self) {
        self.trie.seal();
    }

    /// Probe the trie for a production-normalized hostname. Returns the
    /// minimum matching DOMAIN/DOMAIN-SUFFIX rule index, or `None`.
    pub fn search(&self, host: &str) -> Option<usize> {
        self.trie.search_min_normalized(host).map(|&i| i as usize)
    }
}

/// True iff a DOMAIN-WILDCARD payload has the `*.domain` shape the trie can
/// own outright (see `DomainIndex::insert_rule`).
pub fn star_wildcard_indexable(payload: &str) -> bool {
    payload
        .strip_prefix("*.")
        .is_some_and(|rest| indexable_pattern(rest) && !rest.contains('*'))
}

/// True iff `payload` is a plain hostname pattern whose trie insertion
/// matches exactly the hosts the corresponding DOMAIN / DOMAIN-SUFFIX
/// predicate matches.
fn indexable_pattern(payload: &str) -> bool {
    !payload.is_empty()
        && payload.is_ascii()
        && !payload.starts_with(['.', '*', '+'])
        && !payload.ends_with('.')
        && !payload.contains("..")
}

/// Match metadata against rules using the domain index for early-exit.
///
/// Algorithm:
/// 1. If the trie has a hit at index `T`, only scan `rules[0..T]` for any
///    earlier non-domain rule that matches.  If found return it; otherwise
///    return the trie hit.
/// 2. If the trie misses (no matching domain rule), fall through to a full
///    linear scan of all rules — the connection is either matched by a
///    non-domain rule or falls through to FINAL.
///
/// Pre-resolution of `metadata.dst_ip` from a hostname must happen before this
/// function is called (see `TunnelInner::pre_resolve`).
///
/// `target_exists` reports whether a matched rule's target names a live
/// registry entry. A match on a missing target is skipped and the scan
/// continues — mihomo's `match()` does `continue` on `proxies[adapter] ==
/// nil` (issue #513).
pub fn match_rules<'rules>(
    metadata: &Metadata,
    rules: &'rules [Box<dyn Rule>],
    index: &DomainIndex,
    target_exists: &dyn Fn(&str) -> bool,
) -> Option<MatchResult<'rules>> {
    let helper = RuleMatchHelper;

    let host = metadata.rule_host();
    let trie_hit = if host.is_empty() {
        None
    } else {
        index.search(host)
    };

    // Determine the scan ceiling: on a trie hit at index T, only rules[0..T]
    // can contain an earlier match. `DomainIndex::search` returns the
    // minimum rule index across ALL patterns matching this host (min-index
    // semantics), so no domain rule below T matches — the prefix scan only
    // exists to catch earlier non-domain rules. It still evaluates domain
    // rules for simplicity (they are provably non-matching but harmless);
    // the compiled IR path skips them outright.
    let scan_end = trie_hit.unwrap_or(rules.len());

    for rule in &rules[..scan_end] {
        if let Some(adapter_name) = rule.match_and_resolve(metadata, &helper) {
            if target_exists(adapter_name) {
                return Some(MatchResult {
                    adapter_name,
                    rule_type: rule.rule_type(),
                    rule_payload: rule.payload(),
                });
            }
            warn_missing_target(adapter_name, rule.as_ref());
        }
    }

    // Return trie hit if it beat the linear scan. On a missing target the
    // scan resumes *after* the hit rule, as upstream `continue` does.
    let mut tail = scan_end;
    if let Some(trie_idx) = trie_hit {
        let rule = &rules[trie_idx];
        let adapter_name = rule.adapter();
        if target_exists(adapter_name) {
            return Some(MatchResult {
                adapter_name,
                rule_type: rule.rule_type(),
                rule_payload: rule.payload(),
            });
        }
        warn_missing_target(adapter_name, rule.as_ref());
        tail = trie_idx + 1;
    }

    // No match in [0..T]; continue scanning the remainder (trie miss path).
    for rule in &rules[tail..] {
        if let Some(adapter_name) = rule.match_and_resolve(metadata, &helper) {
            if target_exists(adapter_name) {
                return Some(MatchResult {
                    adapter_name,
                    rule_type: rule.rule_type(),
                    rule_payload: rule.payload(),
                });
            }
            warn_missing_target(adapter_name, rule.as_ref());
        }
    }

    None
}

/// Log a skipped match: the rule matched but its target is absent from the
/// registry or unusable for this traffic (issue #513; mihomo's match loop
/// also `continue`s a target without UDP support on UDP flows).
fn warn_missing_target(adapter_name: &str, rule: &dyn Rule) {
    tracing::warn!(
        "rule {} matched target '{adapter_name}' which is unavailable for \
         this connection (absent from the registry, or no UDP support); \
         skipping it",
        rule.rule_type().as_str(),
    );
}

pub fn maybe_enrich_with_process(metadata: &Metadata) -> Option<Metadata> {
    if !metadata.process.is_empty() {
        return None;
    }
    let src_ip = metadata.src_ip?;
    if metadata.src_port == 0 {
        return None;
    }
    let local = SocketAddr::new(src_ip, metadata.src_port);
    let info = find_process(metadata.network, local)?;
    trace!(
        name = %info.name,
        path = %info.path,
        uid = ?info.uid,
        %local,
        "match_engine: enriched metadata with process info",
    );
    let mut enriched = metadata.clone();
    enriched.process = info.name.into();
    enriched.process_path = info.path.into();
    if enriched.uid.is_none() {
        enriched.uid = info.uid;
    }
    Some(enriched)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use meow_common::{ConnType, DnsMode, Network as NetType};
    use meow_rules::{final_rule::FinalRule, process::ProcessRule};

    fn current_process_name() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_default()
    }

    fn base_metadata(src: SocketAddr) -> Metadata {
        Metadata {
            network: NetType::Tcp,
            conn_type: ConnType::Http,
            src_ip: Some(src.ip()),
            src_port: src.port(),
            dst_port: 443,
            dns_mode: DnsMode::Normal,
            ..Default::default()
        }
    }

    #[test]
    fn engine_enriches_process_and_matches_rule() {
        // Bind a real TCP listener so the kernel actually owns a socket we can
        // look up. This exercises the full /proc (Linux) or libproc (macOS)
        // path end-to-end.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();

        let proc_name = current_process_name();
        assert!(
            !proc_name.is_empty(),
            "expected a non-empty test binary name"
        );

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(ProcessRule::new(&proc_name, "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let meta = base_metadata(local);
        let index = DomainIndex::build(&rules);
        let enriched = maybe_enrich_with_process(&meta).expect("process lookup must succeed");
        let result =
            match_rules(&enriched, &rules, &index, &|_| true).expect("engine must return a match");
        assert_eq!(result.adapter_name, "Proxy");
        assert_eq!(result.rule_type.as_str(), "PROCESS-NAME");
    }

    #[test]
    fn engine_falls_through_when_lookup_misses() {
        // Bind the same listener so the lookup succeeds but with the wrong name,
        // ensuring the process rule is skipped and the MATCH rule wins.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(ProcessRule::new("definitely-not-a-real-binary", "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let meta = base_metadata(local);
        let index = DomainIndex::build(&rules);
        let enriched = maybe_enrich_with_process(&meta).expect("process lookup must succeed");
        let result =
            match_rules(&enriched, &rules, &index, &|_| true).expect("final rule should match");
        assert_eq!(result.adapter_name, "DIRECT");
        assert_eq!(result.rule_type.as_str(), "MATCH");
    }

    #[test]
    fn engine_skips_enrichment_when_no_rule_needs_process() {
        // No rule reports `should_find_process()`, so the engine must not
        // perform any process lookup — exercised by passing a src_ip that
        // wouldn't correspond to any local socket.
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("DIRECT"))];
        let index = DomainIndex::build(&rules);
        let meta = Metadata {
            network: NetType::Tcp,
            src_ip: Some("203.0.113.1".parse().unwrap()),
            src_port: 12345,
            dst_port: 443,
            ..Default::default()
        };
        let result =
            match_rules(&meta, &rules, &index, &|_| true).expect("final rule should match");
        assert_eq!(result.adapter_name, "DIRECT");
    }

    #[test]
    fn domain_index_early_exit_skips_later_rules() {
        use meow_rules::domain_suffix::DomainSuffixRule;
        // rules[0] = DOMAIN-SUFFIX .example.com → Proxy
        // rules[1] = FINAL → DIRECT
        // Trie hit at index 0 → scan [0..0] = empty → return trie hit.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = DomainIndex::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = match_rules(&meta, &rules, &index, &|_| true).expect("must match");
        assert_eq!(result.adapter_name, "Proxy");
        assert_eq!(result.rule_type.as_str(), "DOMAIN-SUFFIX");
    }

    #[test]
    fn earlier_non_domain_rule_beats_trie_hit() {
        use meow_rules::domain_suffix::DomainSuffixRule;
        use meow_rules::port::PortRule;
        // rules[0] = DST-PORT 443 → Direct  (non-domain, matches port 443)
        // rules[1] = DOMAIN-SUFFIX example.com → Proxy (trie index 1)
        // Trie hit at 1 → scan [0..1] → PortRule matches → return Direct.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(PortRule::new("443", "Direct", false).unwrap()),
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("FINAL")),
        ];
        let index = DomainIndex::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = match_rules(&meta, &rules, &index, &|_| true).expect("must match");
        assert_eq!(result.adapter_name, "Direct");
    }

    #[test]
    fn broader_domain_rule_before_specific_wins_first_match() {
        // Regression for the skip_domain correctness bug (ADR-0002 Class A):
        //
        // rules[0] = DOMAIN-SUFFIX "example.com" → "Broad"   (matches any *.example.com)
        // rules[1] = DOMAIN        "sub.example.com" → "Specific"
        //
        // Trie returns T=1 (DOMAIN exact-match is priority-1 in trie.rs).
        // Correct result: scan rules[0..1] → rules[0] DomainSuffix matches → "Broad".
        // Buggy result (if skip_domain were active): skip rules[0], return trie hit → "Specific".
        use meow_rules::domain::DomainRule;
        use meow_rules::domain_suffix::DomainSuffixRule;

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Broad")),
            Box::new(DomainRule::new("sub.example.com", "Specific")),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = DomainIndex::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = match_rules(&meta, &rules, &index, &|_| true).expect("must match");
        assert_eq!(
            result.adapter_name, "Broad",
            "first-match-wins: broader rule at lower index must take precedence"
        );
        assert_eq!(result.rule_type.as_str(), "DOMAIN-SUFFIX");
    }
}
