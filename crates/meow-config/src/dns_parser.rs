use crate::raw::{RawConfig, RawHosts};
use crate::rule_provider::RuleProvider;
use crate::DnsConfig;
use meow_common::DnsMode;
use meow_dns::fakeip::{FileStore, MemoryStore, Pool, Skipper, SkipperMode, Store};
use meow_dns::resolver::{
    FallbackFilter, HostEntry, NameserverPolicy, NameserverPolicyMatcher, PolicyEntry,
};
use meow_dns::upstream::{NameServerEntry, NameServerUrl};
use meow_dns::{DnsClient, HostOrIp, Resolver};
use meow_rules::{DomainKeyDefect, RuleSet, RuleSetBehavior};
use meow_trie::DomainTrie;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Upstream Go mihomo default for v4 fake-IP CIDR. Used when
/// `enhanced-mode: fake-ip` is set but `fake-ip-range` is omitted.
pub(crate) const DEFAULT_FAKE_IP_RANGE_V4: &str = "198.18.0.1/16";

/// `prior` is the resolver generation being replaced (config reload); its
/// fake-IP pool is carried over when the configured range and store
/// identity (in-memory vs the same backing file) are unchanged, so clients
/// holding earlier `host → fake-ip` answers keep a valid reverse mapping.
/// Pass `None` on cold start.
pub async fn parse_dns(
    raw: &RawConfig,
    mmdb_path: Option<&std::path::Path>,
    cache_dir: Option<&std::path::Path>,
    proxy_registry: &HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
    geosite: Option<Arc<meow_rules::geosite::GeositeDB>>,
    rule_providers: &HashMap<String, Arc<RuleProvider>>,
    prior: Option<&Resolver>,
) -> Result<DnsConfig, anyhow::Error> {
    // `strict` (top-level `strict: true`, issue #533): static config defects
    // become hard errors; transient resolution failures stay lenient.
    let strict = raw.strict.unwrap_or(false);
    let dns = match &raw.dns {
        Some(dns) if dns.enable.unwrap_or(false) => dns,
        _ => {
            if raw.dns.as_ref().is_some_and(|d| d.listen.is_some()) {
                warn!("dns.listen is set but dns.enable is false — no DNS listener is started");
            }
            let hosts = build_hosts_trie(raw.hosts.as_ref(), strict)?;
            let use_hosts = raw.dns.as_ref().and_then(|d| d.use_hosts).unwrap_or(true);
            let resolver = Resolver::new(
                vec!["8.8.8.8:53".parse().unwrap()],
                vec![],
                DnsMode::Normal,
                hosts,
                use_hosts,
                crate::effective_ipv6(raw.ipv6),
            );
            let resolver = Arc::new(resolver);
            return Ok(DnsConfig {
                resolver_slot: meow_dns::new_resolver_slot(Arc::clone(&resolver)),
                resolver,
                listen_addr: None,
                enabled: false,
                proxy_resolver: None,
            });
        }
    };

    let use_hosts = dns.use_hosts.unwrap_or(true);
    let use_system_hosts = dns.use_system_hosts.unwrap_or(true);

    let main_urls = parse_nameserver_entries(dns.nameserver.as_deref().unwrap_or(&[]))?;
    let fallback_urls = parse_nameserver_entries(dns.fallback.as_deref().unwrap_or(&[]))?;
    let default_ns_urls =
        parse_nameserver_entries(dns.default_nameserver.as_deref().unwrap_or(&[]))?;
    let proxy_ns_urls =
        parse_nameserver_entries(dns.proxy_server_nameserver.as_deref().unwrap_or(&[]))?;

    let mode = match dns.enhanced_mode.as_deref() {
        Some("fake-ip") => DnsMode::FakeIp,
        Some("redir-host") => DnsMode::Mapping,
        Some(other) if strict => {
            anyhow::bail!("dns.enhanced-mode: unknown value '{other}' (strict mode)");
        }
        Some(other) => {
            warn!("dns.enhanced-mode: unknown value '{other}'; using the default resolver mode");
            DnsMode::Normal
        }
        _ => DnsMode::Normal,
    };

    let listen_addr = crate::parse_optional_socket_addr("dns.listen", dns.listen.as_deref())?;
    let mut hosts = build_hosts_trie(raw.hosts.as_ref(), strict)?;

    if use_hosts && use_system_hosts {
        merge_system_hosts(&mut hosts).await;
    }

    // mihomo `proxy-server-nameserver`: a dedicated resolver used only for
    // proxy server hostnames (dns.Config.ProxyServer → ProxyServerHostResolver).
    // Normal mode — proxy server domains must never get fake IPs — and no
    // fallback/policy; hostname URLs bootstrap via default-nameserver exactly
    // like the main list. Hosts entries still apply (mihomo checks its global
    // hosts table before consulting any resolver), so it gets its own copy of
    // the hosts trie — DomainTrie is not Clone, hence the rebuild.
    let proxy_resolver = if proxy_ns_urls.is_empty() {
        None
    } else {
        for (nameserver, proxy) in circular_proxy_tags(&proxy_ns_urls, proxy_registry) {
            warn!(
                "dns.proxy-server-nameserver '{nameserver}' references proxy '{proxy}', but \
                 '{proxy}' is itself reached by hostname — resolving that hostname is what \
                 this nameserver exists to do, so the lookup re-enters the resolver, is \
                 fenced to hosts: + cache, and falls through to the system resolver on a \
                 miss. Pin the node's server in hosts:, give it an IP-literal server:, or \
                 drop the proxy tag."
            );
        }
        let mut proxy_hosts = build_hosts_trie(raw.hosts.as_ref(), strict)?;
        if use_hosts && use_system_hosts {
            merge_system_hosts(&mut proxy_hosts).await;
        }
        Some(Arc::new(
            Resolver::new_with_bootstrap_with_proxies(
                proxy_ns_urls,
                vec![],
                default_ns_urls.clone(),
                DnsMode::Normal,
                proxy_hosts,
                use_hosts,
                crate::effective_ipv6(raw.ipv6),
                None,
                None,
                proxy_registry,
                crate::is_offline_validate(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("proxy-server-nameserver: {e}"))?,
        ))
    };

    // Build nameserver-policy if configured.
    let policy = if let Some(nsp_map) = &dns.nameserver_policy {
        if nsp_map.is_empty() {
            None
        } else {
            let bootstrap_clients = build_policy_bootstrap_clients(&default_ns_urls, &main_urls);
            Some(
                build_nameserver_policy(
                    nsp_map,
                    geosite.as_ref(),
                    &bootstrap_clients,
                    proxy_registry,
                    rule_providers,
                    strict,
                )
                .await?,
            )
        }
    } else {
        None
    };

    // Build fallback-filter only when fallback nameservers are configured.
    let fallback_filter = if fallback_urls.is_empty() {
        None
    } else {
        let raw_filter = dns.fallback_filter.clone();
        let mmdb_path = mmdb_path.map(std::path::Path::to_path_buf);
        Some(
            crate::spawn_blocking_with_current_dispatcher(move || {
                build_fallback_filter(raw_filter.as_ref(), mmdb_path.as_deref(), strict)
            })
            .await
            .map_err(|e| anyhow::anyhow!("fallback-filter build task failed: {e}"))??,
        )
    };

    let mut resolver = Resolver::new_with_bootstrap_with_proxies(
        main_urls,
        fallback_urls,
        default_ns_urls,
        mode,
        hosts,
        use_hosts,
        crate::effective_ipv6(raw.ipv6),
        policy,
        fallback_filter,
        proxy_registry,
        crate::is_offline_validate(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Fake-IP wiring: only when enhanced-mode == fake-ip. Errors here are
    // fatal (Class A per ADR-0002) — a misconfigured fake-IP range would
    // silently fall back to the upstream resolver, which is a user-surprising
    // privacy regression.
    if mode == DnsMode::FakeIp {
        install_fakeip(&mut resolver, dns, cache_dir, prior, strict).await?;
    }

    let resolver = Arc::new(resolver);
    Ok(DnsConfig {
        resolver_slot: meow_dns::new_resolver_slot(Arc::clone(&resolver)),
        resolver,
        listen_addr,
        enabled: true,
        proxy_resolver,
    })
}

async fn install_fakeip(
    resolver: &mut Resolver,
    dns: &crate::raw::RawDns,
    cache_dir: Option<&std::path::Path>,
    prior: Option<&Resolver>,
    strict: bool,
) -> Result<(), anyhow::Error> {
    let range_str = dns
        .fake_ip_range
        .as_deref()
        .unwrap_or(DEFAULT_FAKE_IP_RANGE_V4);
    let prefix: ipnet::IpNet = range_str
        .parse()
        .map_err(|e| anyhow::anyhow!("dns.fake-ip-range '{range_str}' is not a valid CIDR: {e}"))?;

    let persist = dns.store_fake_ip.unwrap_or(false);

    // The file this generation would bind to, when persisting. Computed
    // before the reuse check so the check can compare store identity, not
    // just store kind.
    let wanted_store_path = persist.then(|| {
        // `cache_dir` is `None` for a `--config-string` run — the launch
        // CWD is not the daemon's to write into, so persist under the
        // resolved home (same base geodata defaults use) instead of
        // `./fakeip-*.json` (issue #717).
        let base =
            cache_dir.map_or_else(meow_common::resolved_home_dir, std::path::Path::to_path_buf);
        let suffix = match &prefix {
            ipnet::IpNet::V4(_) => "v4",
            ipnet::IpNet::V6(_) => "v6",
        };
        base.join(format!("fakeip-{suffix}.json"))
    });

    // Carry the live pool into the rebuilt resolver when the range and the
    // store identity are unchanged. The pool's store IS the fake-IP state:
    // a fresh MemoryStore strands clients still holding `host → fake-ip`
    // answers and resets the allocation cursor, which then reissues the
    // same addresses to other hosts — `pre_handle_metadata` would
    // reverse-map in-flight connections to the wrong target (issue #514
    // review follow-up). Reuse also keeps `store-fake-ip` reloads on ONE
    // FileStore instead of running two persist writers over the same file.
    // `store_path` comparison covers both the persist→memory flip (None vs
    // Some) and the persistent case where `cache_dir` moved: a pool bound
    // to the old file must not be carried into a generation configured
    // for a new one.
    let pool = match prior
        .and_then(|r| r.fakeip_pool_over(prefix))
        .filter(|p| same_store(p.store_path(), wanted_store_path.as_deref()))
    {
        Some(pool) => pool,
        None => {
            let store: Arc<dyn Store> = match wanted_store_path {
                Some(path) => {
                    let p = FileStore::open_async(path.clone()).await.map_err(|e| {
                        let disp = path.display();
                        anyhow::anyhow!("cannot open fakeip store {disp}: {e}")
                    })?;
                    Arc::new(p)
                }
                None => {
                    // Capacity bounded by prefix size, but cap at a sensible
                    // upper bound so a /8 doesn't allocate 16M cache slots
                    // up front.
                    Arc::new(MemoryStore::new(1 << 20))
                }
            };

            let pool = Pool::new(prefix, store)
                .map_err(|e| anyhow::anyhow!("cannot build fakeip pool: {e}"))?;
            Arc::new(pool)
        }
    };

    match &prefix {
        ipnet::IpNet::V4(_) => resolver.set_fakeip_v4(pool),
        ipnet::IpNet::V6(_) => resolver.set_fakeip_v6(pool),
    }

    // Skipper: fake-ip-filter patterns + optional fake-ip-filter-mode.
    let patterns = dns.fake_ip_filter.clone().unwrap_or_default();
    for p in &patterns {
        // Dead trie keys by the same shape as `hosts:` — an empty label
        // strands an unreachable node, and an all-dots/prefix-only body is
        // refused by `Skipper`'s own insert (issue #822 shape). Surface
        // both rather than let the entry sit silently dead.
        check_domain_key("dns.fake-ip-filter", p, strict)?;
    }
    let skipper_mode = match dns.fake_ip_filter_mode.as_deref() {
        Some("whitelist") | Some("white-list") => SkipperMode::WhiteList,
        Some("blacklist") | Some("black-list") | None => SkipperMode::BlackList,
        Some(other) => {
            warn!(
                "dns.fake-ip-filter-mode '{}' unknown; using 'blacklist'",
                other
            );
            SkipperMode::BlackList
        }
    };
    resolver.set_fakeip_skipper(Skipper::new(&patterns, skipper_mode));
    Ok(())
}

/// Do the existing pool's store and the store this generation would build
/// hold the same fake-IP state? `None`/`None` = both in-memory → same
/// kind, reusable. `Some`/`Some` = same backing file — compared after
/// `canonicalize` so two spellings of one file (`cache/` vs `./cache/`, a
/// symlinked dir) still count as identical — reusing is then REQUIRED to
/// avoid running a second `FileStore` writer over the same snapshot.
/// Canonicalisation failure (file not yet created) falls back to lexical
/// equality: unprovable-but-different spellings take the safe path
/// (rebuild), never a wrong reuse.
fn same_store(existing: Option<&std::path::Path>, wanted: Option<&std::path::Path>) -> bool {
    match (existing, wanted) {
        (None, None) => true,
        (Some(existing), Some(wanted)) => match (existing.canonicalize(), wanted.canonicalize()) {
            (Ok(existing), Ok(wanted)) => existing == wanted,
            _ => existing == wanted,
        },
        _ => false,
    }
}

/// Proxy-tagged (`#PROXY` / `?proxy=`) `dns.proxy-server-nameserver` entries
/// whose proxy cannot be dialled without this very resolver, as
/// `(nameserver, proxy name)` pairs.
///
/// A tag here is legitimate when the named node has an IP-literal `server:` —
/// `meow_common::resolve_addrs` short-circuits literals, so the hook is never
/// re-entered and the nameserver is genuinely reached through the proxy. It is
/// circular when the node is reached by hostname: resolving *that* hostname
/// routes back into this resolver, trips the re-entrancy fence, and degrades to
/// `resolve_ips_local` (hosts: + warm cache) with a silent system-resolver
/// fallback on a miss. Groups report an empty `addr()` because the member is
/// only chosen at dial time, so they count as circular too.
///
/// Unknown proxy names are skipped — `Resolver::new_with_bootstrap_with_proxies`
/// already rejects those with `BootstrapError::UnknownProxy`.
fn circular_proxy_tags(
    entries: &[NameServerEntry],
    proxy_registry: &HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
) -> Vec<(String, String)> {
    entries
        .iter()
        .filter_map(|entry| {
            let name = entry.proxy.as_deref()?;
            let proxy = proxy_registry.get(name)?;
            if is_ip_literal_addr(proxy.addr()) {
                return None;
            }
            Some((entry.url.to_string(), name.to_string()))
        })
        .collect()
}

/// True when a `ProxyAdapter::addr()` string (`"<server>:<port>"`) carries an
/// IP literal rather than a hostname. Anything unparseable is treated as a
/// literal so a shape we do not recognise cannot manufacture a false warning.
fn is_ip_literal_addr(addr: &str) -> bool {
    if addr.is_empty() {
        // Groups: member — and therefore its server — unknown until dial time.
        return false;
    }
    if addr.parse::<SocketAddr>().is_ok() || addr.parse::<IpAddr>().is_ok() {
        return true;
    }
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    host.parse::<IpAddr>().is_ok()
}

/// Parse nameserver strings into `NameServerEntry`s — every entry must
/// parse or load fails. No silent warn-and-drop.
fn parse_nameserver_entries(servers: &[String]) -> Result<Vec<NameServerEntry>, anyhow::Error> {
    servers
        .iter()
        .map(|s| {
            NameServerEntry::parse(s)
                .map_err(|e| anyhow::anyhow!("failed to parse nameserver '{s}': {e}"))
        })
        .collect()
}

/// Pre-`NameServerEntry` shim kept for the existing tests below that build
/// raw `NameServerUrl`s and compare against the result. New code should use
/// [`parse_nameserver_entries`].
#[cfg(test)]
fn parse_nameserver_urls(servers: &[String]) -> Result<Vec<NameServerUrl>, anyhow::Error> {
    parse_nameserver_entries(servers).map(|v| v.into_iter().map(|e| e.url).collect())
}

/// `true` when the raw `dns.nameserver-policy` section contains at least
/// one `rule-set:` key (matching the case-insensitive + trimmed expansion
/// the policy builder applies). Used by reload paths to decide
/// whether the resolver build must load the candidate's rule-providers
/// rather than a possibly-stale live registry (issue #514).
pub fn dns_needs_rule_providers(raw: &crate::raw::RawConfig) -> bool {
    raw.dns
        .as_ref()
        .and_then(|d| d.nameserver_policy.as_ref())
        .is_some_and(|m| {
            // Expand per segment like `build_nameserver_policy` — a mixed
            // key (`"+.corp.example,rule-set:x"`) puts the prefix on a
            // non-leading segment the whole-key check would miss.
            m.keys()
                .flat_map(|k| expand_policy_keys(k))
                .any(|ek| ek.to_ascii_lowercase().starts_with("rule-set:"))
        })
}

/// Build a `NameserverPolicy` from the raw YAML map.
///
/// `geosite:` patterns are compiled into matchers when a geosite DB is loaded.
/// `rule-set:` patterns are compiled into matchers from the loaded
/// rule-providers; the matcher reads through the provider object on each
/// lookup so background refreshes take effect automatically.
/// Other prefixed patterns (anything with `:`) warn once and skip.
///
/// `map` is a [`crate::raw::RawNameserverPolicy`]: its iteration order is
/// the YAML document order, which IS the lookup priority — domain keys
/// merge into the open `Domains` arm, `geosite:`/`rule-set:` keys append
/// `Matcher` arms, and the first matching arm wins (mihomo
/// `parseNameServerPolicy` + `makePolicy` parity).
///
/// An entry with no valid nameservers after skipping → hard error.
/// Class A per ADR-0002: DNS leakage risk for internal/corporate domains.
async fn build_nameserver_policy(
    map: &crate::raw::RawNameserverPolicy,
    geosite: Option<&Arc<meow_rules::geosite::GeositeDB>>,
    bootstrap_clients: &[Arc<DnsClient>],
    proxy_registry: &HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
    rule_providers: &HashMap<String, Arc<RuleProvider>>,
    // `strict` (top-level `strict: true`, issue #533): static defects in a
    // policy *value* — an unparseable URL, or a `#name` tag referencing an
    // unknown proxy — become hard errors instead of warn-and-skip.
    // Resolution-dependent skips (bootstrap lookup failed, no addresses)
    // stay lenient: those are transient, not config defects.
    strict: bool,
) -> Result<NameserverPolicy, anyhow::Error> {
    let mut policy = NameserverPolicy::new();
    let mut warned_unsupported_prefix = false;
    let mut warned_missing_geosite = false;
    let mut placed_matchers: Vec<PlacedMatcher<'_>> = Vec::new();

    for (key, value) in map {
        let mut patterns = Vec::new();
        for expanded_key in expand_policy_keys(key) {
            let key_lower = expanded_key.to_ascii_lowercase();
            if let Some(category) = key_lower.strip_prefix("geosite:") {
                let category = category.trim();
                if category.is_empty() {
                    if strict {
                        return Err(anyhow::anyhow!(
                            "nameserver-policy: 'geosite:' key has an empty category \
                             (strict mode)"
                        ));
                    }
                    patterns.push(PolicyPattern::Skipped);
                    continue;
                }
                let Some(db) = geosite else {
                    // A `geosite:` policy key with no loaded DB silently drops
                    // the whole entry — the declared domains fall back to the
                    // default nameservers, contradicting `rule-set:`'s
                    // unconditional hard error below (issue #533 review).
                    if strict {
                        return Err(anyhow::anyhow!(
                            "nameserver-policy: 'geosite:{category}' requires a loaded \
                             geosite DB (strict mode); set `geodata:` / fix the \
                             database files, or drop the key"
                        ));
                    }
                    if !warned_missing_geosite {
                        warn!(
                            "nameserver-policy: geosite: patterns require a loaded geosite DB; \
                            skipping geosite policy entries"
                        );
                        warned_missing_geosite = true;
                    }
                    patterns.push(PolicyPattern::Skipped);
                    continue;
                };
                let category = category.to_string();
                let db = Arc::clone(db);
                patterns.push(PolicyPattern::Matcher {
                    key: expanded_key.clone(),
                    matcher: Arc::new(move |domain| db.lookup(&category, domain)),
                });
                continue;
            }

            if key_lower.starts_with("rule-set:") {
                // Provider names are case-sensitive — extract from the
                // original-case `expanded_key`, not `key_lower`.
                let name = expanded_key["rule-set:".len()..].trim();
                if name.is_empty() {
                    if strict {
                        return Err(anyhow::anyhow!(
                            "nameserver-policy: 'rule-set:' key has an empty provider \
                             name (strict mode)"
                        ));
                    }
                    patterns.push(PolicyPattern::Skipped);
                    continue;
                }
                let provider = rule_providers.get(name).ok_or_else(|| {
                    anyhow::anyhow!("nameserver-policy: not found rule-set: {name}")
                })?;
                match provider.behavior {
                    RuleSetBehavior::IpCidr => {
                        anyhow::bail!(
                            "nameserver-policy: rule-set '{name}' behavior is IpCidr, \
                             expected domain or classical"
                        );
                    }
                    RuleSetBehavior::Classical => {
                        // Warn once per entry; upstream only matches domain
                        // rules inside a classical set.
                        warn!(
                            "nameserver-policy: rule-set '{name}' is classical; \
                             only domain rules within it will be matched"
                        );
                    }
                    RuleSetBehavior::Domain => {}
                }
                // The provider reads through to its current set (issue
                // #553), so refreshes are seen here without cloning a
                // snapshot `Arc` per query.
                let provider = Arc::clone(provider);
                patterns.push(PolicyPattern::Matcher {
                    key: expanded_key.clone(),
                    matcher: Arc::new(move |domain: &str| provider.matches_domain(domain)),
                });
                continue;
            }

            if key_lower.contains(':') {
                // A typo'd prefix (`geosite:`/`rule-set:` misspelled, or an
                // unknown scheme) is dead config — the entry silently routes
                // those domains to the default nameservers (issue #533 review).
                if strict {
                    return Err(anyhow::anyhow!(
                        "nameserver-policy: unsupported prefixed key '{expanded_key}' \
                         (strict mode); supported prefixes: geosite:, rule-set:"
                    ));
                }
                if !warned_unsupported_prefix {
                    warn!(
                        "nameserver-policy: unsupported prefixed patterns containing ':' \
                        will be skipped"
                    );
                    warned_unsupported_prefix = true;
                }
                patterns.push(PolicyPattern::Skipped);
                continue;
            }

            // Upstream `parseNameServerPolicy` (config_config.go) validates
            // every non-prefixed domain key with `ValidAndSplitDomain`, and
            // `makePolicy` inserts each run of them into one
            // `domainTriePolicy` (`DomainTrie.Insert`). Bare, `+.`, `*.` and
            // `.` keys all go into the open domain arm's trie the same way.
            // meow stays lenient on degenerate keys: the trie drops an empty
            // rest (`+.`), and a mid-string `*` (e.g. `a.*.b`) is a literal
            // label only an identical query matches (DR-B F4/F15 unchanged).
            if !key_lower.is_empty() {
                // As in `hosts:` — the arm still gets the pattern (its
                // node is simply unreachable, or refused outright); the
                // warn only surfaces the dead key. Strict mirrors the
                // prefixed-key rule.
                check_domain_key("nameserver-policy", &expanded_key, strict)?;
                patterns.push(PolicyPattern::Domain(key_lower));
            }
        }

        if !patterns
            .iter()
            .any(|pattern| !matches!(pattern, PolicyPattern::Skipped))
        {
            // Nothing to route, but a skipped matcher key still ends the
            // open domain arm, exactly as its own arm would have.
            if !patterns.is_empty() {
                policy.close_domain_arm();
            }
            continue;
        }

        let resolvers =
            build_policy_resolvers(key, value, bootstrap_clients, proxy_registry, strict).await?;

        let entry = PolicyEntry {
            nameservers: resolvers,
        };
        for pattern in patterns {
            match pattern {
                PolicyPattern::Domain(domain) => {
                    warn_if_shadowed(&domain, value, &placed_matchers);
                    policy.insert_wildcard(&domain, entry.clone());
                }
                PolicyPattern::Matcher { key, matcher } => {
                    policy.insert_matcher(Arc::clone(&matcher), entry.clone());
                    placed_matchers.push(PlacedMatcher {
                        key,
                        value,
                        matcher,
                    });
                }
                PolicyPattern::Skipped => policy.close_domain_arm(),
            }
        }
    }

    Ok(policy)
}

enum PolicyPattern {
    /// A domain key (bare, `+.`, `*.` or `.`) for the open domain arm.
    Domain(String),
    /// A `geosite:`/`rule-set:` key: an arm of its own.
    Matcher {
        key: String,
        matcher: NameserverPolicyMatcher,
    },
    /// A matcher-shaped key skipped in lenient mode (no geosite DB, an
    /// empty name, an unsupported prefix). It adds no arm but still ends
    /// the open domain arm, so the domain keys around it keep the
    /// precedence they have when the key loads.
    Skipped,
}

/// A matcher arm already in the policy, with the key and value it came from.
struct PlacedMatcher<'a> {
    key: String,
    value: &'a crate::raw::RawNspValue,
    matcher: NameserverPolicyMatcher,
}

/// Warn when a domain key is written below a matcher arm that already
/// matches it. The first matching arm wins, so that domain never reaches
/// the key's nameservers. Bare and `+.` keys are probed with the domain
/// they name; `*.`/`.` keys never cover it and are not checked. An earlier
/// arm with the same nameservers routes identically and stays quiet.
fn warn_if_shadowed(pattern: &str, value: &crate::raw::RawNspValue, placed: &[PlacedMatcher<'_>]) {
    if pattern.starts_with("*.") || pattern.starts_with('.') {
        return;
    }
    let domain = pattern.strip_prefix("+.").unwrap_or(pattern);
    if let Some(earlier) = placed
        .iter()
        .find(|earlier| earlier.value != value && (earlier.matcher)(domain))
    {
        warn!(
            "nameserver-policy: '{pattern}' is written after '{}', which already matches \
             '{domain}'; the first matching key wins, so move '{pattern}' above it to \
             override it",
            earlier.key
        );
    }
}

pub(crate) fn expand_policy_keys(key: &str) -> Vec<String> {
    let key = key.trim();
    let lower = key.to_ascii_lowercase();
    if lower.starts_with("geosite:") {
        return key["geosite:".len()..]
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| format!("geosite:{part}"))
            .collect();
    }
    if lower.starts_with("rule-set:") {
        return key["rule-set:".len()..]
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| format!("rule-set:{part}"))
            .collect();
    }
    key.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn build_policy_bootstrap_clients(
    default_ns: &[NameServerEntry],
    main_urls: &[NameServerEntry],
) -> Vec<Arc<DnsClient>> {
    let source = if default_ns.is_empty() {
        main_urls
    } else {
        default_ns
    };
    let empty_resolved = HashMap::new();
    source
        .iter()
        .filter(|entry| entry.proxy.is_none())
        .filter(|entry| entry.url.needs_bootstrap().is_none())
        .filter(|entry| !matches!(entry.url, NameServerUrl::RCode { .. }))
        .map(|entry| Resolver::build_single_resolver(&entry.url, &empty_resolved))
        .collect()
}

async fn build_policy_resolvers(
    key: &str,
    value: &crate::raw::RawNspValue,
    bootstrap_clients: &[Arc<DnsClient>],
    proxy_registry: &HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
    strict: bool,
) -> Result<Vec<Arc<meow_dns::DnsClient>>, anyhow::Error> {
    let url_strs = value.as_urls();
    let empty_resolved = HashMap::new();
    let mut resolvers = Vec::new();
    for url_str in &url_strs {
        match NameServerEntry::parse(url_str) {
            Ok(entry) => {
                // Migration aid identical to the main/fallback path in
                // `Resolver::new_with_bootstrap_with_proxies`: `#X` on a
                // tls:///https:// entry is SNI, so a migrated config that
                // meant it as a proxy tag warns here instead of silently
                // losing its routing intent.
                if entry.proxy.is_none() {
                    let sni = match &entry.url {
                        NameServerUrl::Tls { sni, .. } | NameServerUrl::Https { sni, .. } => {
                            sni.as_str()
                        }
                        _ => "",
                    };
                    if !sni.is_empty() && proxy_registry.contains_key(sni) {
                        warn!(
                            "nameserver-policy entry '{}': URL '{}' looks like it tags proxy \
                             '{}' with '#': `#X` on encrypted entries is SNI — did you mean \
                             `?proxy=X`?",
                            key, url_str, sni
                        );
                    }
                }
                // `#PROXY` fragment / `?proxy=` parameter: resolve the
                // tag to a registry handle *before* deciding whether to
                // skip local bootstrap — only a tag that resolved keeps
                // the remote-resolution semantics below (r15 review M3).
                // An unknown name degrades to a direct dial like the main
                // path does — under `strict` that silent downgrade is a
                // hard error instead (issue #533 review).
                let proxy = match entry.proxy.as_deref() {
                    Some(name) => match proxy_registry.get(name).cloned() {
                        Some(handle) => Some(handle),
                        None if strict => {
                            return Err(anyhow::anyhow!(
                                "nameserver-policy entry '{key}': URL '{url_str}' references \
                                 unknown proxy '{name}' (strict mode)"
                            ));
                        }
                        None => {
                            warn!(
                                "nameserver-policy entry '{}': URL '{}' references unknown \
                                proxy '{}'; ignoring the tag — resolving locally and \
                                dialing direct",
                                key, url_str, name
                            );
                            None
                        }
                    },
                    None => None,
                };
                // A proxied hostname upstream is resolved *remotely* by
                // the proxy (mihomo `newDNSDialer` semantics) — running
                // policy bootstrap on it would defeat the remote-
                // resolution intent and fail outright for names that are
                // unresolvable locally. Skip it like the main/fallback
                // path does (`Resolver` step 2) — but only when the tag
                // actually resolved to a handle: an unknown name degrades
                // to the untagged path above, so its hostname still goes
                // through bootstrap exactly like an untagged entry.
                let url = if proxy.is_some() {
                    Some(entry.url)
                } else {
                    resolve_policy_hostname_url(entry.url, key, url_str, bootstrap_clients).await
                };
                let Some(url) = url else {
                    continue;
                };
                let resolver =
                    Resolver::build_single_resolver_with_proxy(&url, &empty_resolved, proxy);
                resolvers.push(resolver);
            }
            Err(e) => {
                if strict {
                    return Err(anyhow::anyhow!(
                        "nameserver-policy entry '{key}': invalid URL '{url_str}' \
                         (strict mode): {e}"
                    ));
                }
                warn!(
                    "nameserver-policy entry '{}': skipping invalid URL '{}': {}",
                    key, url_str, e
                );
            }
        }
    }

    if resolvers.is_empty() {
        return Err(anyhow::anyhow!(
            "nameserver-policy entry '{key}' has no valid nameservers after skipping \
            unsupported entries (Class A per ADR-0002 — DNS leakage risk for \
            internal/corporate domains)"
        ));
    }

    Ok(resolvers)
}

async fn resolve_policy_hostname_url(
    url: NameServerUrl,
    key: &str,
    url_str: &str,
    bootstrap_clients: &[Arc<DnsClient>],
) -> Option<NameServerUrl> {
    match url {
        NameServerUrl::Udp {
            addr: HostOrIp::Host(host),
            port,
        } => resolve_policy_host(key, url_str, &host, bootstrap_clients)
            .await
            .map(|ip| NameServerUrl::Udp {
                addr: HostOrIp::Ip(ip),
                port,
            }),
        NameServerUrl::Tcp {
            addr: HostOrIp::Host(host),
            port,
        } => resolve_policy_host(key, url_str, &host, bootstrap_clients)
            .await
            .map(|ip| NameServerUrl::Tcp {
                addr: HostOrIp::Ip(ip),
                port,
            }),
        NameServerUrl::Tls {
            addr: HostOrIp::Host(host),
            port,
            sni,
        } => resolve_policy_host(key, url_str, &host, bootstrap_clients)
            .await
            .map(|ip| NameServerUrl::Tls {
                addr: HostOrIp::Ip(ip),
                port,
                sni,
            }),
        NameServerUrl::Https {
            addr: HostOrIp::Host(host),
            port,
            path,
            sni,
        } => resolve_policy_host(key, url_str, &host, bootstrap_clients)
            .await
            .map(|ip| NameServerUrl::Https {
                addr: HostOrIp::Ip(ip),
                port,
                path,
                sni,
            }),
        other => Some(other),
    }
}

async fn resolve_policy_host(
    key: &str,
    url_str: &str,
    host: &str,
    bootstrap_clients: &[Arc<DnsClient>],
) -> Option<IpAddr> {
    // The no-bootstrap-clients skip is a *static* property of the config
    // (IP-literal, unproxied, non-rcode entries only — see
    // `build_policy_bootstrap_clients`), so it must run before the
    // offline gate: `-t` should reproduce the runtime skip → "no valid
    // nameservers" verdict, not green-light a config that cannot start.
    if bootstrap_clients.is_empty() {
        warn!(
            "nameserver-policy entry '{}': URL '{}' uses hostname '{}' but no IP-literal \
            nameserver/default-nameserver is available for policy bootstrap; skipping",
            key, url_str, host
        );
        return None;
    }

    // Offline validation (`-t`) must not query the network (issue #716).
    // Keep the entry structurally — an unreachable placeholder stands in
    // for the bootstrap result so a valid policy doesn't error out on an
    // isolated host; the resolver is never queried before `-t` exits.
    if crate::is_offline_validate() {
        // RFC 5737 TEST-NET-1 — strictly unroutable, unlike UNSPECIFIED
        // which aliases to localhost on POSIX stacks.
        return Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)));
    }

    for client in bootstrap_clients {
        match tokio::time::timeout(Duration::from_secs(3), client.lookup_ip(host)).await {
            Ok(Ok((ips, _ttl))) => {
                if let Some(ip) = ips.into_iter().next() {
                    return Some(ip);
                }
            }
            Ok(Err(e)) => {
                warn!(
                    "nameserver-policy entry '{}': bootstrap lookup for '{}' via '{}' failed: {}",
                    key, host, url_str, e
                );
            }
            Err(_) => {
                warn!(
                    "nameserver-policy entry '{}': bootstrap lookup for '{}' timed out; \
                    trying next bootstrap nameserver",
                    key, host
                );
            }
        }
    }
    warn!(
        "nameserver-policy entry '{}': URL '{}' hostname '{}' resolved to no addresses; skipping",
        key, url_str, host
    );
    None
}

/// Build a `FallbackFilter` from the raw config.
///
/// If `geoip: true` but no MMDB is available, GeoIP gate is disabled with a
/// `warn!`. Class B per ADR-0002: NOT a startup error.
fn build_fallback_filter(
    raw: Option<&crate::raw::RawFallbackFilter>,
    explicit_mmdb_path: Option<&std::path::Path>,
    strict: bool,
) -> Result<FallbackFilter, anyhow::Error> {
    let geoip = raw.and_then(|f| f.geoip).unwrap_or(true);
    let geoip_code = raw
        .and_then(|f| f.geoip_code.clone())
        .unwrap_or_else(|| "CN".to_string());
    let ipcidr_strs = raw.and_then(|f| f.ipcidr.as_deref()).unwrap_or(&[]);
    let domain_strs = raw.and_then(|f| f.domain.as_deref()).unwrap_or(&[]);

    let mut ipcidr = Vec::new();
    for s in ipcidr_strs {
        match s.parse::<ipnet::IpNet>() {
            Ok(net) => ipcidr.push(net),
            Err(e) => {
                // An unparseable CIDR is a static config defect — under
                // strict it fails the build instead of silently weakening
                // the fallback filter (issue #533 review).
                if strict {
                    return Err(anyhow::anyhow!(
                        "fallback-filter.ipcidr: invalid CIDR '{s}': {e} (strict mode)"
                    ));
                }
                warn!(
                    "fallback-filter.ipcidr: skipping invalid CIDR '{}': {}",
                    s, e
                );
            }
        }
    }

    let mut domain: DomainTrie<()> = DomainTrie::new();
    for s in domain_strs {
        // Same dead-key shapes as `hosts:` — an empty label inserts but
        // can never match a query name, and an all-dots/prefix-only body
        // (`"."`, `"+."`) is refused by the insert below; surface both
        // rather than swallow them (issue #822 shape).
        check_domain_key("fallback-filter.domain", s, strict)?;
        if !domain.insert(s, ()) {
            // Unreachable for a config key today — every refused shape is
            // `DomainKeyDefect::NotInsertable` and already surfaced by
            // `check_domain_key` — kept as the insert's own verdict should
            // the trie's refusal set ever grow past the predicate.
            if strict {
                return Err(anyhow::anyhow!(
                    "fallback-filter.domain: '{s}' is not a valid domain pattern \
                     (strict mode)"
                ));
            }
            warn!("fallback-filter.domain: failed to insert '{s}' into trie");
        }
    }

    // Attempt to load GeoIP MMDB for the geoip gate.
    let geoip_reader = if geoip {
        let mmdb_path =
            explicit_mmdb_path.map_or_else(crate::default_geoip_path, std::path::PathBuf::from);
        match std::fs::read(&mmdb_path)
            .map_err(|e| format!("{e}"))
            .and_then(|b| maxminddb::Reader::from_source(b).map_err(|e| format!("{e}")))
        {
            Ok(reader) => Some(Arc::new(reader)),
            Err(e) => {
                warn!(
                    "fallback-filter: geoip=true but GeoIP database not available at {}: {} \
                    — GeoIP gate disabled (Class B per ADR-0002). \
                    Download Country.mmdb to enable GeoIP-based fallback filtering.",
                    mmdb_path.display(),
                    e
                );
                None
            }
        }
    } else {
        None
    };

    let geoip_enabled = geoip && geoip_reader.is_some();

    Ok(FallbackFilter {
        geoip_enabled,
        geoip_code,
        ipcidr,
        domain,
        geoip_reader,
    })
}

/// Build the hosts trie from top-level mihomo-compatible `hosts:` entries.
/// A single value may be an IP or domain alias; lists must contain only IPs.
/// Malformed values and alias cycles are hard errors (Class A per ADR-0002).
///
/// Keys iterate in YAML document order. Two keys colliding on one (node, kind)
/// slot — `x` vs `+.x` (Exact), `.x` vs `+.x` (Dot), or spelling variants that
/// normalize together (insert-side trim + lowercase, e.g. `X.com` vs `x.com`,
/// ` x.com ` vs `x.com`) — resolve to the document-last writer
/// (`insert_overwrite`, mihomo `node.setData` parity). Collisions are per-slot:
/// `+.x` writes Exact AND Dot, so `x` written *after* `+.x` wins only the Exact
/// slot — `sub.x` still resolves through `+.x`'s Dot slot.
///
/// Known pre-existing validation divergences from mihomo, kept as-is: a key
/// with a trailing dot (`x.com.`) is accepted and normalized onto the same
/// live slot as `x.com` where mihomo's `ValidAndSplitDomain` rejects it;
/// an empty mid-label (`a..b`) or an all-dots/prefix-only key (`"."`,
/// `"+."`) is likewise accepted into a slot no query can reach — or no
/// slot at all — where mihomo rejects it, but both are now surfaced as a
/// warn in lenient mode and an error under `strict:` rather than sitting
/// silently dead; whitespace-padded keys are trimmed and accepted where
/// mihomo rejects; a mid-path `*` segment (`sub.*.x`) is stored as a
/// literal label where mihomo treats it as a wildcard; an alias value
/// trims only trailing dots where mihomo trims both ends (`.foo.com`
/// differs); and mihomo seeds an implicit `localhost → 127.0.0.1` and
/// accepts the `lan` magic value (interface addresses), neither of which
/// exists here — `hosts: {x: lan}` is a hard error.
fn build_hosts_trie(
    hosts: Option<&RawHosts>,
    strict: bool,
) -> Result<DomainTrie<HostEntry>, anyhow::Error> {
    let mut trie: DomainTrie<HostEntry> = DomainTrie::new();
    let Some(hosts) = hosts else {
        return Ok(trie);
    };
    let mut aliases = Vec::new();
    for (host, value) in hosts {
        let values = value.as_slice();
        if values.is_empty() {
            // An empty `hosts:` entry is a static defect — the declared name
            // silently resolves nothing (issue #533 review).
            if strict {
                return Err(anyhow::anyhow!(
                    "hosts: entry '{host}' has no values (strict mode)"
                ));
            }
            warn!("hosts: entry '{}' has no values, skipping", host);
            continue;
        }
        let host_entry = if values.len() == 1 {
            let raw = values[0].trim();
            match raw.parse::<IpAddr>() {
                Ok(ip) => HostEntry::Addresses(vec![ip]),
                Err(_) => {
                    let alias = parse_host_alias(raw, host)?;
                    aliases.push((host.trim().to_string(), alias.clone()));
                    HostEntry::Alias(alias.into())
                }
            }
        } else {
            let mut ips = Vec::with_capacity(values.len());
            for raw in values {
                let ip = raw.parse::<IpAddr>().map_err(|e| {
                    anyhow::anyhow!(
                        "hosts: invalid IP '{raw}' for host '{host}': {e} \
                         (lists may contain only IP addresses)"
                    )
                })?;
                ips.push(ip);
            }
            HostEntry::Addresses(ips)
        };
        // Keys go in as written: `*.foo` is a single-label wildcard, `+.foo`
        // covers the apex plus any-depth subdomains, a bare key is exact.
        let key = host.trim();
        // An empty label strands a node no query can reach (queries never
        // carry one); an all-dots/prefix-only body is refused by the insert
        // below — both surfaced, never silently dead (issue #822 shape).
        check_domain_key("hosts", key, strict)?;
        if !trie.insert_overwrite(key, host_entry) {
            // As at `fallback-filter.domain`: unreachable for a config key
            // today — `DomainKeyDefect::NotInsertable` covers every refused
            // shape — kept as the insert's own verdict.
            if strict {
                return Err(anyhow::anyhow!(
                    "hosts: '{}' is not a valid domain pattern (strict mode)",
                    host.trim()
                ));
            }
            warn!("hosts: failed to insert '{}' into trie", host);
        }
    }
    reject_host_alias_cycles(&trie, &aliases)?;
    Ok(trie)
}

/// Surface a dead domain key on a `DomainTrie`-backed config surface:
/// lenient mode warns naming the key, `strict:` hard-errors — the same
/// warn/error split every domain-list consumer applies. The caller keeps
/// the entry either way (observability only, never a semantics change).
///
/// The predicate lives in `meow_rules::domain_key` so the `rules:` parser
/// and every trie surface share one dead-key definition; `match_engine`'s
/// `indexable_pattern` is the same concept's third encoding.
pub(crate) fn check_domain_key(field: &str, key: &str, strict: bool) -> Result<(), anyhow::Error> {
    let Some(defect) = meow_rules::domain_key_defect(key) else {
        return Ok(());
    };
    let why = match defect {
        DomainKeyDefect::DeadLabel => "contains an empty label",
        DomainKeyDefect::NotInsertable => "is not a valid domain pattern",
    };
    if strict {
        Err(anyhow::anyhow!("{field}: '{key}' {why} (strict mode)"))
    } else {
        warn!("{field}: '{key}' {why}; it can never match");
        Ok(())
    }
}

fn parse_host_alias(value: &str, host: &str) -> Result<String, anyhow::Error> {
    let alias = value.trim_end_matches('.').to_ascii_lowercase();
    let valid = alias.contains('.')
        && !alias.contains('*')
        && !alias.contains('+')
        && hickory_proto::rr::Name::from_ascii(&alias).is_ok();
    if !valid {
        return Err(anyhow::anyhow!(
            "hosts: value '{value}' for host '{host}' is neither an IP address nor a valid domain alias"
        ));
    }
    Ok(alias)
}

/// Reject domain-alias cycles. `aliases` are the edges recorded at WRITE
/// time, one per alias key — NOT per final trie slot: a later same-slot key
/// can overwrite the alias with a non-alias entry, leaving a dead edge that
/// still seeds `seen`. The walk can then report a cycle the final trie does
/// not contain (e.g. `{dead: loop, loop: dead, +.dead: 10.0.0.1}` — `+.dead`
/// reclaims `dead`'s Exact slot, so `loop → dead` resolves cleanly at
/// runtime, yet the recorded `dead → loop` edge still closes the loop).
/// That is a conservative over-rejection kept deliberately: a document that
/// trips it always contains a cycle among the *written* alias edges, and
/// mihomo rejects the same class — its unordered hosts map can keep the
/// cycle live — so the user-visible outcome matches. No false negatives
/// either: a live cycle is revisited no matter which edge seeds `seen`.
fn reject_host_alias_cycles(
    trie: &DomainTrie<HostEntry>,
    aliases: &[(String, String)],
) -> Result<(), anyhow::Error> {
    for (source, target) in aliases {
        let mut seen = std::collections::HashSet::new();
        seen.insert(source.to_ascii_lowercase());
        let mut current = target.as_str();
        loop {
            if !seen.insert(current.to_ascii_lowercase()) {
                return Err(anyhow::anyhow!(
                    "hosts: domain alias cycle detected starting at '{source}'"
                ));
            }
            match trie.search(current) {
                Some(HostEntry::Alias(next)) => current = next.as_str(),
                Some(HostEntry::Addresses(_)) | None => break,
            }
        }
    }
    Ok(())
}

/// Merge system hosts entries into the trie at lower priority than config entries.
async fn merge_system_hosts(trie: &mut DomainTrie<HostEntry>) {
    let entries = parse_system_hosts().await;
    for (domain, ips) in entries {
        if trie.search(&domain).is_none() {
            trie.insert(&domain, HostEntry::Addresses(ips));
        }
    }
}

/// Parse system hosts file and return (domain, ips) pairs.
/// On Unix reads `/etc/hosts`; on Windows reads `C:\Windows\System32\drivers\etc\hosts`.
async fn parse_system_hosts() -> Vec<(String, Vec<IpAddr>)> {
    let hosts_path = if cfg!(target_os = "windows") {
        std::env::var("SystemRoot").map_or_else(
            |_| std::path::PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"),
            |sr| {
                std::path::PathBuf::from(sr)
                    .join("System32")
                    .join("drivers")
                    .join("etc")
                    .join("hosts")
            },
        )
    } else {
        std::path::PathBuf::from("/etc/hosts")
    };
    let content = match tokio::fs::read_to_string(&hosts_path).await {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "use-system-hosts: cannot read {}: {}",
                hosts_path.display(),
                e
            );
            return vec![];
        }
    };
    let mut out: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(ip_str) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };
        for hostname in parts {
            let domain = hostname.trim_end_matches('.').to_lowercase();
            if domain.is_empty() {
                continue;
            }
            out.entry(domain).or_default().push(ip);
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::HostsValue;
    use std::net::Ipv4Addr;

    fn one(s: &str) -> HostsValue {
        HostsValue::One(s.to_string())
    }
    fn many(ss: &[&str]) -> HostsValue {
        HostsValue::Many(ss.iter().map(std::string::ToString::to_string).collect())
    }

    /// Build a `RawNameserverPolicy` from `(key, value)` pairs in the given
    /// document order — key order IS the lookup priority, so list them the
    /// way a YAML document would declare them.
    fn nsp_map(entries: &[(&str, crate::raw::RawNspValue)]) -> crate::raw::RawNameserverPolicy {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    use crate::test_support::WarnCapture;

    fn addresses(entry: &HostEntry) -> &[IpAddr] {
        match entry {
            HostEntry::Addresses(ips) => ips,
            HostEntry::Alias(alias) => panic!("expected addresses, got alias {alias}"),
        }
    }

    #[test]
    fn build_hosts_trie_none_is_empty() {
        let trie = build_hosts_trie(None, false).unwrap();
        assert!(trie.search("example.com").is_none());
    }

    #[tokio::test]
    async fn proxy_server_nameserver_builds_dedicated_resolver() {
        let raw: RawConfig = serde_saphyr::from_str(
            "dns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\n  proxy-server-nameserver:\n    - 223.5.5.5\n",
        )
        .unwrap();
        let cfg = parse_dns(
            &raw,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        assert!(
            cfg.proxy_resolver.is_some(),
            "proxy-server-nameserver must build a dedicated resolver"
        );
    }

    #[tokio::test]
    async fn no_proxy_server_nameserver_leaves_proxy_resolver_none() {
        let raw: RawConfig =
            serde_saphyr::from_str("dns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\n").unwrap();
        let cfg = parse_dns(
            &raw,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        assert!(cfg.proxy_resolver.is_none());
    }

    #[tokio::test]
    async fn proxy_server_nameserver_ignored_when_dns_disabled() {
        // mihomo: ProxyServerHostResolver is nil whenever the DNS section is
        // off — proxy server hostnames fall back to the system resolver.
        let raw: RawConfig = serde_saphyr::from_str(
            "dns:\n  enable: false\n  proxy-server-nameserver:\n    - 223.5.5.5\n",
        )
        .unwrap();
        let cfg = parse_dns(
            &raw,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        assert!(!cfg.enabled);
        assert!(cfg.proxy_resolver.is_none());
    }

    /// Issue #514 review follow-up: a config reload that rebuilds the
    /// resolver (e.g. a nameserver change) must carry the live fake-IP
    /// pool over when the range and store identity are unchanged —
    /// otherwise clients holding `host → fake-ip` answers lose the
    /// mapping and the fresh cursor reissues their addresses to other
    /// hosts.
    #[tokio::test]
    async fn fakeip_pool_is_carried_into_rebuilt_resolver() {
        let yaml = |ns: &str| {
            format!("dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver:\n    - {ns}\n")
        };
        let raw: RawConfig = serde_saphyr::from_str(&yaml("1.1.1.1")).unwrap();
        let cfg = parse_dns(
            &raw,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let range: ipnet::IpNet = "198.18.0.1/16".parse().unwrap();
        let old_pool = cfg.resolver.fakeip_pool_over(range).unwrap();
        let ip = old_pool.lookup("a.example");
        assert_eq!(old_pool.look_back(ip).as_deref(), Some("a.example"));

        // Reload with a different nameserver: same fake-ip range → the
        // same pool object is reused.
        let raw2: RawConfig = serde_saphyr::from_str(&yaml("8.8.8.8")).unwrap();
        let cfg2 = parse_dns(
            &raw2,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            Some(cfg.resolver.as_ref()),
        )
        .await
        .unwrap();
        let new_pool = cfg2.resolver.fakeip_pool_over(range).unwrap();
        assert!(
            Arc::ptr_eq(&old_pool, &new_pool),
            "unchanged-range reload must reuse the live pool"
        );
        assert_eq!(new_pool.look_back(ip).as_deref(), Some("a.example"));
        // Cursor carried too: the next allocation must not reissue
        // a.example's address.
        assert_ne!(new_pool.lookup("b.example"), ip);
        assert_eq!(new_pool.lookup("a.example"), ip);
    }

    /// Same reload, but the fake-ip range changed: a fresh pool must be
    /// built — old mappings do not apply to a different range.
    #[tokio::test]
    async fn fakeip_pool_not_carried_when_range_changes() {
        let yaml = |range: &str| {
            format!(
                "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: {range}\n  nameserver:\n    - 1.1.1.1\n"
            )
        };
        let raw: RawConfig = serde_saphyr::from_str(&yaml("198.18.0.1/16")).unwrap();
        let cfg = parse_dns(
            &raw,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let old_pool = cfg
            .resolver
            .fakeip_pool_over("198.18.0.1/16".parse().unwrap())
            .unwrap();
        let ip = old_pool.lookup("a.example");

        let raw2: RawConfig = serde_saphyr::from_str(&yaml("198.19.0.1/16")).unwrap();
        let cfg2 = parse_dns(
            &raw2,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            Some(cfg.resolver.as_ref()),
        )
        .await
        .unwrap();
        let new_pool = cfg2
            .resolver
            .fakeip_pool_over("198.19.0.1/16".parse().unwrap())
            .unwrap();
        assert!(new_pool.look_back(ip).is_none());
    }

    /// `store-fake-ip: true` across a reload: the persistent pool is
    /// carried over too — reuse keeps ONE `FileStore` (and its flush task)
    /// on the backing file instead of running a second writer over it.
    /// Flipping the flag must NOT reuse.
    #[tokio::test]
    async fn fakeip_pool_is_carried_with_persistent_store() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = |ns: &str, store: &str| {
            format!(
                "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  store-fake-ip: {store}\n  nameserver:\n    - {ns}\n"
            )
        };
        let range: ipnet::IpNet = "198.18.0.1/16".parse().unwrap();
        let raw: RawConfig = serde_saphyr::from_str(&yaml("1.1.1.1", "true")).unwrap();
        let cfg = parse_dns(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let old_pool = cfg.resolver.fakeip_pool_over(range).unwrap();
        assert!(old_pool.is_persistent());
        let ip = old_pool.lookup("a.example");

        // persist → persist: same pool object — no second FileStore
        // opened on fakeip-v4.json.
        let raw2: RawConfig = serde_saphyr::from_str(&yaml("8.8.8.8", "true")).unwrap();
        let cfg2 = parse_dns(
            &raw2,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &HashMap::new(),
            Some(cfg.resolver.as_ref()),
        )
        .await
        .unwrap();
        let carried = cfg2.resolver.fakeip_pool_over(range).unwrap();
        assert!(std::sync::Arc::ptr_eq(&old_pool, &carried));
        assert_eq!(carried.look_back(ip).as_deref(), Some("a.example"));

        // persist → memory: the flag flipped, so the pool must not be
        // reused.
        let raw3: RawConfig = serde_saphyr::from_str(&yaml("8.8.8.8", "false")).unwrap();
        let cfg3 = parse_dns(
            &raw3,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &HashMap::new(),
            Some(cfg2.resolver.as_ref()),
        )
        .await
        .unwrap();
        let fresh = cfg3.resolver.fakeip_pool_over(range).unwrap();
        assert!(!fresh.is_persistent());
        assert!(!std::sync::Arc::ptr_eq(&old_pool, &fresh));
        assert!(fresh.look_back(ip).is_none());
    }

    /// Boundary conditions on the reuse predicate: a *semantically* equal
    /// range reuses even when the CIDR spelling differs (non-canonical
    /// `198.18.0.1/16` vs `198.18.0.0/16`), while a different prefix length
    /// or a different address family must not — `fakeip_pool_over` keys on
    /// `network()`+`prefix_len()`, and a family switch installs into the
    /// other slot.
    #[tokio::test]
    async fn fakeip_pool_reuse_boundary_cases() {
        let yaml = |range: &str| {
            format!(
                "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: {range}\n  nameserver:\n    - 1.1.1.1\n"
            )
        };
        let raw: RawConfig = serde_saphyr::from_str(&yaml("198.18.0.1/16")).unwrap();
        let cfg = parse_dns(
            &raw,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let pool_v4 = cfg
            .resolver
            .fakeip_pool_over("198.18.0.0/16".parse().unwrap())
            .unwrap();
        let ip = pool_v4.lookup("a.example");

        // Same network+prefix, different spelling → same pool object.
        let raw2: RawConfig = serde_saphyr::from_str(&yaml("198.18.0.0/16")).unwrap();
        let cfg2 = parse_dns(
            &raw2,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            Some(cfg.resolver.as_ref()),
        )
        .await
        .unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &pool_v4,
            &cfg2
                .resolver
                .fakeip_pool_over("198.18.0.0/16".parse().unwrap())
                .unwrap()
        ));

        // Same network base, different prefix length → fresh pool.
        let raw3: RawConfig = serde_saphyr::from_str(&yaml("198.18.0.0/15")).unwrap();
        let cfg3 = parse_dns(
            &raw3,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            Some(cfg2.resolver.as_ref()),
        )
        .await
        .unwrap();
        let pool_15 = cfg3
            .resolver
            .fakeip_pool_over("198.18.0.0/15".parse().unwrap())
            .unwrap();
        assert!(!std::sync::Arc::ptr_eq(&pool_v4, &pool_15));
        assert!(pool_15.look_back(ip).is_none());

        // Family switch v4 → v6: the new resolver's v6 pool is fresh and
        // no v4 pool is installed on it (the old resolver keeps its own).
        let raw4: RawConfig = serde_saphyr::from_str(&yaml("fc00::/64")).unwrap();
        let cfg4 = parse_dns(
            &raw4,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            Some(cfg3.resolver.as_ref()),
        )
        .await
        .unwrap();
        let v6: ipnet::IpNet = "fc00::/64".parse().unwrap();
        let pool_v6 = cfg4.resolver.fakeip_pool_over(v6).unwrap();
        assert!(matches!(pool_v6.lookup("a.example"), IpAddr::V6(_)));
        assert!(
            cfg4.resolver
                .fakeip_pool_over("198.18.0.0/15".parse().unwrap())
                .is_none(),
            "a v6-range resolver must not expose a v4 pool"
        );
    }

    /// `store-fake-ip: true` but the cache dir moved: the live pool is
    /// bound to the old file and must NOT be carried over — otherwise the
    /// new generation would keep writing the old snapshot and never load
    /// the file its `cache_dir` actually names.
    #[tokio::test]
    async fn fakeip_pool_not_carried_when_persistent_dir_changes() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let yaml = "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  store-fake-ip: true\n  nameserver:\n    - 1.1.1.1\n";
        let range: ipnet::IpNet = "198.18.0.1/16".parse().unwrap();
        let raw: RawConfig = serde_saphyr::from_str(yaml).unwrap();

        let cfg = parse_dns(
            &raw,
            None,
            Some(dir_a.path()),
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let old_pool = cfg.resolver.fakeip_pool_over(range).unwrap();
        let ip = old_pool.lookup("a.example");
        let path_a = dir_a.path().join("fakeip-v4.json");
        assert_eq!(old_pool.store_path(), Some(path_a.as_path()));

        // Same range, same store-fake-ip, different cache dir → rebuild.
        let cfg2 = parse_dns(
            &raw,
            None,
            Some(dir_b.path()),
            &HashMap::new(),
            None,
            &HashMap::new(),
            Some(cfg.resolver.as_ref()),
        )
        .await
        .unwrap();
        let new_pool = cfg2.resolver.fakeip_pool_over(range).unwrap();
        assert!(!std::sync::Arc::ptr_eq(&old_pool, &new_pool));
        assert_eq!(
            new_pool.store_path(),
            Some(dir_b.path().join("fakeip-v4.json").as_path())
        );
        // The new pool is bound to the new (empty) file — the old mapping
        // does not leak across the move.
        assert!(new_pool.look_back(ip).is_none());
    }

    /// The canonicalize arm of `same_store`: the same backing file named
    /// through a different `cache_dir` spelling (`dir/sub/..`) must still
    /// reuse — rebuilding would open a SECOND `FileStore` on the same
    /// file and the two snapshot writers would clobber each other. The
    /// file must already exist for `canonicalize` to resolve the leaf.
    #[tokio::test]
    async fn fakeip_pool_is_carried_when_persistent_path_respelled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(
            dir.path().join("fakeip-v4.json"),
            r#"{"entries":{},"offset":null,"cycle":false}"#,
        )
        .unwrap();
        let yaml = "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  store-fake-ip: true\n  nameserver:\n    - 1.1.1.1\n";
        let range: ipnet::IpNet = "198.18.0.1/16".parse().unwrap();
        let raw: RawConfig = serde_saphyr::from_str(yaml).unwrap();

        let cfg = parse_dns(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let old_pool = cfg.resolver.fakeip_pool_over(range).unwrap();
        let ip = old_pool.lookup("a.example");

        // Same file, spelled via a `sub/..` indirection: lexical paths
        // differ, canonical paths are equal → reuse, one writer.
        let respelled = dir.path().join("sub").join("..");
        let cfg2 = parse_dns(
            &raw,
            None,
            Some(&respelled),
            &HashMap::new(),
            None,
            &HashMap::new(),
            Some(cfg.resolver.as_ref()),
        )
        .await
        .unwrap();
        let carried = cfg2.resolver.fakeip_pool_over(range).unwrap();
        assert!(std::sync::Arc::ptr_eq(&old_pool, &carried));
        assert_eq!(carried.look_back(ip).as_deref(), Some("a.example"));
    }

    #[test]
    fn build_hosts_trie_single_ip() {
        let mut map = RawHosts::new();
        map.insert("example.com".to_string(), one("1.2.3.4"));
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        let v = trie.search("example.com").expect("must hit");
        assert_eq!(addresses(v), &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn build_hosts_trie_many_ips() {
        let mut map = RawHosts::new();
        map.insert("dual.test".to_string(), many(&["1.1.1.1", "::1"]));
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        let v = trie.search("dual.test").expect("must hit");
        assert_eq!(addresses(v).len(), 2);
    }

    #[test]
    fn build_hosts_trie_domain_alias() {
        let mut map = RawHosts::new();
        map.insert("node.example".to_string(), one("origin.example"));
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        assert_eq!(
            trie.search("node.example"),
            Some(&HostEntry::Alias("origin.example".into()))
        );
    }

    #[test]
    fn build_hosts_trie_rejects_alias_cycle() {
        let mut map = RawHosts::new();
        map.insert("a.example".to_string(), one("b.example"));
        map.insert("b.example".to_string(), one("a.example"));
        let err = build_hosts_trie(Some(&map), false)
            .err()
            .expect("domain alias cycles must be rejected");
        assert!(err.to_string().contains("alias cycle"));
    }

    /// The dead-key classification matrix itself lives with the predicate
    /// in `meow_rules::domain_key`'s tests; this pins that `hosts:` drives
    /// it through `check_domain_key` — lenient warns and still loads the
    /// dead entry, strict hard-errors.
    #[test]
    fn build_hosts_trie_empty_label_key_warns_lenient_errors_strict() {
        let mut map = RawHosts::new();
        map.insert("a..b".to_string(), one("1.2.3.4"));
        // Lenient: warns, still inserts the (unreachable) node — no query
        // may ever see it, and `a.b` in particular must not leak to it.
        let cap = WarnCapture::start();
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        let warns = cap.take();
        assert!(
            warns.contains("a..b") && warns.contains("empty label"),
            "the dead key must be surfaced, got: {warns}"
        );
        assert!(trie.search("a.b").is_none(), "a..b must not leak to a.b");
        let err = build_hosts_trie(Some(&map), true)
            .err()
            .expect("strict must hard-error on an empty label");
        assert!(err.to_string().contains("empty label"));
    }

    #[test]
    fn build_hosts_trie_rejects_domain_in_multi_value_list() {
        let mut map = RawHosts::new();
        map.insert(
            "bad.example".to_string(),
            many(&["192.0.2.1", "origin.example"]),
        );
        let err = build_hosts_trie(Some(&map), false)
            .err()
            .expect("multi-value hosts entries may contain only IPs");
        assert!(err.to_string().contains("lists may contain only IP"));
    }

    // A value that is neither an IP nor a valid alias is a hard error.
    // Upstream: silently skips malformed IPs. NOT silent skip — Class A per ADR-0002.
    #[test]
    fn build_hosts_trie_malformed_ip_hard_error() {
        let mut map = RawHosts::new();
        map.insert("bad.test".to_string(), one("not-an-ip"));
        let result = build_hosts_trie(Some(&map), false);
        let err = result
            .err()
            .expect("malformed hosts value must be a hard error (Class A)");
        let msg = err.to_string();
        assert!(
            msg.contains("not-an-ip") && msg.contains("bad.test"),
            "error must cite both the IP and the host, got: {msg}"
        );
    }

    #[test]
    fn build_hosts_trie_wildcard_and_bare() {
        let mut map = RawHosts::new();
        map.insert("+.corp.example".to_string(), one("10.0.0.1"));
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        assert!(trie.search("host.corp.example").is_some());
        assert!(trie.search("corp.example").is_some());
    }

    // `*.foo` is a single-label wildcard (upstream mihomo `*` consumes exactly
    // one label): matches one subdomain label, neither the root nor deeper
    // subdomains.
    #[test]
    fn build_hosts_trie_star_wildcard_single_label() {
        let mut map = RawHosts::new();
        map.insert("*.corp.internal".to_string(), one("10.0.0.50"));
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        assert!(
            trie.search("foo.corp.internal").is_some(),
            "single-label subdomain of *.corp.internal must match"
        );
        assert!(
            trie.search("corp.internal").is_none(),
            "root must not match *.corp.internal"
        );
        assert!(
            trie.search("a.b.corp.internal").is_none(),
            "deep subdomain must not match *.corp.internal"
        );
    }

    // Exact entry overrides wildcard for the same domain.
    // Upstream: dns/resolver.go::hostsTable. NOT wildcard value for exact-match domain.
    #[test]
    fn build_hosts_trie_exact_overrides_wildcard() {
        let exact_ip = "10.0.0.53";
        let wild_ip = "10.0.0.50";
        let mut map = RawHosts::new();
        map.insert("*.corp.internal".to_string(), one(wild_ip));
        map.insert("dns.corp.internal".to_string(), one(exact_ip));
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        let exact = trie.search("dns.corp.internal").expect("must hit exact");
        let exact_addr: IpAddr = exact_ip.parse().unwrap();
        assert_eq!(
            addresses(exact).first().copied(),
            Some(exact_addr),
            "exact entry must override wildcard"
        );
    }

    // ─── `hosts:` same-slot collisions: document-last wins ─────────────
    //
    // `x` and `+.x` share node `x`'s Exact slot; `.x` and `+.x` share its
    // Dot slot; case/whitespace variants normalize onto the same slot at
    // insert. The ordered carrier (`RawHosts`) makes the document-last
    // writer the deterministic winner per slot (`insert_overwrite`,
    // mihomo `node.setData` parity) — collisions are per-slot, NOT
    // per-key.

    /// `x` written after `+.x` wins only the Exact slot — `sub.x` still
    /// resolves through `+.x`'s Dot slot. Reversed, `+.x` overwrites both.
    #[test]
    fn hosts_collision_bare_vs_plus_last_wins() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();

        let mut map = RawHosts::new();
        map.insert("+.slot.test".to_string(), one("10.0.0.1"));
        map.insert("slot.test".to_string(), one("10.0.0.2"));
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        assert_eq!(
            addresses(trie.search("slot.test").expect("must hit")),
            &[ip("10.0.0.2")],
            "bare key written last must win the Exact slot"
        );
        assert_eq!(
            addresses(trie.search("deep.slot.test").expect("must hit")),
            &[ip("10.0.0.1")],
            "the Dot slot keeps `+.`'s entry — collisions are per-slot"
        );

        let mut reversed = RawHosts::new();
        reversed.insert("slot.test".to_string(), one("10.0.0.2"));
        reversed.insert("+.slot.test".to_string(), one("10.0.0.1"));
        let trie = build_hosts_trie(Some(&reversed), false).unwrap();
        assert_eq!(
            addresses(trie.search("slot.test").expect("must hit")),
            &[ip("10.0.0.1")]
        );
        assert_eq!(
            addresses(trie.search("deep.slot.test").expect("must hit")),
            &[ip("10.0.0.1")]
        );
    }

    /// `.x` and `+.x` share the Dot slot only — `.x` written last leaves
    /// `+.`'s Exact slot alone; reversed, `+.x` overwrites both slots.
    #[test]
    fn hosts_collision_dot_vs_plus_last_wins() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();

        let mut map = RawHosts::new();
        map.insert("+.t.test".to_string(), one("10.0.0.1"));
        map.insert(".t.test".to_string(), one("10.0.0.3"));
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        assert_eq!(
            addresses(trie.search("x.t.test").expect("must hit")),
            &[ip("10.0.0.3")],
            "`.t.test` written last must win the Dot slot"
        );
        assert_eq!(
            addresses(trie.search("t.test").expect("must hit")),
            &[ip("10.0.0.1")],
            "`.t.test` writes no Exact slot — `+.`'s apex entry survives"
        );

        let mut reversed = RawHosts::new();
        reversed.insert(".t.test".to_string(), one("10.0.0.3"));
        reversed.insert("+.t.test".to_string(), one("10.0.0.1"));
        let trie = build_hosts_trie(Some(&reversed), false).unwrap();
        assert_eq!(
            addresses(trie.search("x.t.test").expect("must hit")),
            &[ip("10.0.0.1")]
        );
        assert_eq!(
            addresses(trie.search("t.test").expect("must hit")),
            &[ip("10.0.0.1")]
        );
    }

    /// Case-folded spellings normalize onto one slot — the document-last
    /// writer wins while the map keeps both distinct YAML keys.
    #[test]
    fn hosts_collision_casefold_last_wins() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();

        let mut map = RawHosts::new();
        map.insert("Case.test".to_string(), one("10.0.0.1"));
        map.insert("case.test".to_string(), one("10.0.0.2"));
        assert_eq!(map.len(), 2, "distinct YAML keys both live in the map");
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        assert_eq!(
            addresses(trie.search("CASE.test").expect("must hit")),
            &[ip("10.0.0.2")]
        );
    }

    /// Insert-side trim normalizes padded keys onto the same slot —
    /// document-last wins. (Keys whose *interior* whitespace fails trie
    /// validation keep the existing warn/strict path; not asserted here.)
    #[test]
    fn hosts_collision_whitespace_last_wins() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();

        let mut map = RawHosts::new();
        map.insert(" pad.test".to_string(), one("10.0.0.1"));
        map.insert("pad.test".to_string(), one("10.0.0.2"));
        let trie = build_hosts_trie(Some(&map), false).unwrap();
        assert_eq!(
            addresses(trie.search("pad.test").expect("must hit")),
            &[ip("10.0.0.2")]
        );
    }

    /// Reparsing the same document must yield the same collision winners
    /// every iteration — the ordered carrier makes iteration order
    /// deterministic, where the old `HashMap` shuffled it per process.
    #[test]
    fn hosts_document_order_is_deterministic_across_reparses() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let doc = "hosts:\n  '+.rep.test': 10.0.0.1\n  rep.test: 10.0.0.2\n  '.rep2.test': 10.0.0.3\n  '+.rep2.test': 10.0.0.4\n  '*.wild.test': 10.0.0.5\n";
        for i in 0..64 {
            let raw: RawConfig = serde_saphyr::from_str(doc).unwrap();
            let trie = build_hosts_trie(raw.hosts.as_ref(), false).unwrap();
            assert_eq!(
                addresses(trie.search("rep.test").expect("must hit")),
                &[ip("10.0.0.2")],
                "iteration {i}: bare key written after `+.` must win Exact"
            );
            assert_eq!(
                addresses(trie.search("deep.rep.test").expect("must hit")),
                &[ip("10.0.0.1")],
                "iteration {i}: `+.`'s Dot slot must survive"
            );
            assert_eq!(
                addresses(trie.search("rep2.test").expect("must hit")),
                &[ip("10.0.0.4")],
                "iteration {i}: `+.` written last must win Exact"
            );
            assert_eq!(
                addresses(trie.search("deep.rep2.test").expect("must hit")),
                &[ip("10.0.0.4")],
                "iteration {i}: `+.` written last must win Dot"
            );
            assert_eq!(
                addresses(trie.search("x.wild.test").expect("must hit")),
                &[ip("10.0.0.5")],
                "iteration {i}: non-colliding `*.` entry unaffected"
            );
        }
    }

    /// `insert_overwrite` keeps `insert`'s validation — `+.`/`.`/empty
    /// keys return `false` identically, so lenient mode warn-skips and
    /// strict mode hard-errors.
    #[test]
    fn hosts_invalid_pattern_still_warns_lenient_errors_strict() {
        for bad_key in ["+.", ".", "   "] {
            let mut map = RawHosts::new();
            map.insert(bad_key.to_string(), one("10.0.0.1"));

            let cap = WarnCapture::start();
            let trie = build_hosts_trie(Some(&map), false)
                .expect("lenient must warn-skip an invalid pattern");
            let logs = cap.take();
            assert!(
                logs.contains("failed to insert"),
                "lenient path must warn for '{bad_key}', got: {logs}"
            );
            drop(cap);
            assert!(trie.search(bad_key).is_none());

            let err = build_hosts_trie(Some(&map), true)
                .err()
                .expect("strict must reject an invalid pattern");
            assert!(
                err.to_string().contains("not a valid domain pattern"),
                "strict error for '{bad_key}' must cite the pattern check: {err}"
            );
        }
    }

    /// `proxy-server-nameserver` rebuilds its hosts trie through the same
    /// `build_hosts_trie` (`DomainTrie` is not `Clone`), so it must carry
    /// identical collision semantics — document-last wins on both copies.
    #[tokio::test]
    async fn proxy_server_nameserver_hosts_trie_matches_main() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let raw: RawConfig = serde_saphyr::from_str(
            "dns:\n  enable: true\n  use-system-hosts: false\n  nameserver:\n    - 1.1.1.1\n  proxy-server-nameserver:\n    - 8.8.8.8\nhosts:\n  '+.parity.test': 10.0.0.1\n  parity.test: 10.0.0.2\n  parity2.test: 10.0.0.3\n  '+.parity2.test': 10.0.0.4\n",
        )
        .unwrap();
        let cfg = parse_dns(
            &raw,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let proxy = cfg
            .proxy_resolver
            .as_ref()
            .expect("proxy resolver must build");
        for q in [
            "parity.test",
            "deep.parity.test",
            "parity2.test",
            "deep.parity2.test",
        ] {
            assert_eq!(
                cfg.resolver.lookup_hosts_all(q),
                proxy.lookup_hosts_all(q),
                "main and proxy resolvers must agree on '{q}'"
            );
        }
        // And the collision itself resolved document-last on both —
        // `+.` written first keeps its Dot slot while the bare key takes
        // Exact…
        assert_eq!(
            cfg.resolver.lookup_hosts_all("parity.test"),
            Some(&vec![ip("10.0.0.2")])
        );
        assert_eq!(
            cfg.resolver.lookup_hosts_all("deep.parity.test"),
            Some(&vec![ip("10.0.0.1")])
        );
        // …and `+.` written *last* wins both slots (reversed direction).
        assert_eq!(
            cfg.resolver.lookup_hosts_all("parity2.test"),
            Some(&vec![ip("10.0.0.4")])
        );
        assert_eq!(
            cfg.resolver.lookup_hosts_all("deep.parity2.test"),
            Some(&vec![ip("10.0.0.4")])
        );
    }

    // C4: quic:// in nameserver produces an error citing M1.E-6.
    #[test]
    fn parse_nameserver_urls_quic_errors() {
        let result = parse_nameserver_urls(&["quic://dns.adguard.com".to_string()]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("M1.E-6"), "error must cite M1.E-6, got: {msg}");
    }

    // C5: unknown scheme errors, not warns.
    // Upstream: parseNameServer emits warn and drops entry (silent-drop bug). NOT a warn — Class A per ADR-0002.
    #[test]
    fn parse_nameserver_urls_unknown_scheme_errors_not_warns() {
        let result = parse_nameserver_urls(&["sdns://abc".to_string()]);
        assert!(
            result.is_err(),
            "unknown scheme must produce an error, not be silently dropped"
        );
    }

    // geosite: prefix without a loaded DB → warn-once and skip.
    #[tokio::test]
    async fn parse_nameserver_policy_geosite_prefix_without_db_skips() {
        use crate::raw::RawNspValue;
        let map = nsp_map(&[(
            "geosite:cn",
            RawNspValue::One("rcode://success".to_string()),
        )]);
        let result =
            build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false).await;
        assert!(result.is_ok(), "geosite: prefix must not hard-error");
        let pol = result.unwrap();
        assert!(
            pol.lookup("anything.cn").is_none(),
            "skipped geosite entry must not match"
        );
    }

    /// A domain key with an empty label (`a..b`) is an unreachable trie
    /// node: lenient mode warns and keeps the (dead) arm, strict mode
    /// hard-errors like it does for unsupported prefixed keys.
    #[tokio::test]
    async fn parse_nameserver_policy_empty_label_key_warns_lenient_errors_strict() {
        use crate::raw::RawNspValue;
        let map = nsp_map(&[("a..b", RawNspValue::One("rcode://success".to_string()))]);
        let cap = WarnCapture::start();
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false)
            .await
            .expect("empty-label key must stay lenient");
        let warns = cap.take();
        assert!(
            warns.contains("a..b") && warns.contains("empty label"),
            "the dead key must be surfaced, got: {warns}"
        );
        assert!(
            pol.lookup("a.b").is_none(),
            "the dead node must not leak to a.b"
        );
        let result =
            build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), true).await;
        let Err(err) = result else {
            panic!("strict must hard-error on an empty-label key")
        };
        assert!(err.to_string().contains("empty label"));
    }

    #[tokio::test]
    async fn parse_nameserver_policy_geosite_prefix_matches_loaded_db() {
        use crate::raw::RawNspValue;
        let mut db = meow_rules::geosite::GeositeDB::empty();
        db.insert("cn", "example.cn");
        db.insert("private", "lan");
        let db = Arc::new(db);

        let map = nsp_map(&[(
            "geosite:cn,private",
            RawNspValue::One("rcode://success".to_string()),
        )]);
        let pol = build_nameserver_policy(
            &map,
            Some(&db),
            &[],
            &HashMap::new(),
            &HashMap::new(),
            false,
        )
        .await
        .unwrap();
        assert!(pol.lookup("example.cn").is_some());
        assert!(pol.lookup("lan").is_some());
        assert!(pol.lookup("example.com").is_none());
    }

    // All URLs invalid after skip → hard error (Class A per ADR-0002).
    // Upstream: panics. NOT a panic — hard parse error.
    #[tokio::test]
    async fn parse_nameserver_policy_all_invalid_urls_errors() {
        use crate::raw::RawNspValue;
        // quic:// is explicitly rejected by the URL parser (QuicNotSupported error).
        let map = nsp_map(&[(
            "corp.example",
            RawNspValue::Many(vec!["quic://bad.example".to_string()]),
        )]);
        let result =
            build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false).await;
        assert!(
            result.is_err(),
            "policy entry with no valid servers must be a hard error"
        );
    }

    // Wildcard policy entry matches subdomain and root.
    #[tokio::test]
    async fn parse_nameserver_policy_wildcard_inserted() {
        use crate::raw::RawNspValue;
        let map = nsp_map(&[(
            "+.corp.internal",
            RawNspValue::One("192.168.1.53".to_string()),
        )]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false)
            .await
            .unwrap();
        assert!(pol.lookup("foo.corp.internal").is_some());
        assert!(pol.lookup("corp.internal").is_some());
        assert!(pol.lookup("other.example").is_none());
    }

    // `*.` policy keys are single-label wildcards (upstream DomainTrie
    // parity): one subdomain label hits; the apex and deeper levels miss.
    #[tokio::test]
    async fn parse_nameserver_policy_star_key_single_label() {
        use crate::raw::RawNspValue;
        let map = nsp_map(&[(
            "*.corp.internal",
            RawNspValue::One("192.168.1.53".to_string()),
        )]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false)
            .await
            .unwrap();
        assert!(
            pol.lookup("foo.corp.internal").is_some(),
            "single-label subdomain of *.corp.internal must hit"
        );
        assert!(
            pol.lookup("corp.internal").is_none(),
            "apex must not match *.corp.internal"
        );
        assert!(
            pol.lookup("a.b.corp.internal").is_none(),
            "deep subdomain must not match *.corp.internal"
        );
        // (Corner: a literal `lookup("*.corp.internal")` DOES hit — the `*`
        // query label is consumed by the star slot like any label, matching
        // upstream `Search`. Not asserted here; degenerate-key coverage is
        // A3's table.)
    }

    // `.` policy keys are any-depth suffix wildcards excluding the apex.
    #[tokio::test]
    async fn parse_nameserver_policy_dot_key_any_depth_no_apex() {
        use crate::raw::RawNspValue;
        let map = nsp_map(&[(
            ".corp.internal",
            RawNspValue::One("192.168.1.53".to_string()),
        )]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false)
            .await
            .unwrap();
        assert!(pol.lookup("foo.corp.internal").is_some());
        assert!(
            pol.lookup("a.b.corp.internal").is_some(),
            "deep subdomain must match .corp.internal"
        );
        assert!(
            pol.lookup("corp.internal").is_none(),
            "apex must not match .corp.internal"
        );
    }

    // Bare policy keys stay exact-only alongside the newly wildcarded kinds.
    #[tokio::test]
    async fn parse_nameserver_policy_bare_key_stays_exact() {
        use crate::raw::RawNspValue;
        let map = nsp_map(&[(
            "corp.internal",
            RawNspValue::One("192.168.1.53".to_string()),
        )]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false)
            .await
            .unwrap();
        assert!(pol.lookup("corp.internal").is_some());
        assert!(pol.lookup("a.corp.internal").is_none());
        assert!(pol.lookup("a.b.corp.internal").is_none());
    }

    // Helper: build an inline rule-provider map from `(name, behavior, payload)`.
    fn inline_rule_providers(
        entries: &[(&str, &str, Vec<String>)],
    ) -> HashMap<String, Arc<RuleProvider>> {
        use crate::raw::RawRuleProvider;
        let mut raw = HashMap::new();
        for (name, behavior, payload) in entries {
            raw.insert(
                (*name).to_string(),
                RawRuleProvider {
                    provider_type: "inline".to_string(),
                    behavior: (*behavior).to_string(),
                    format: None,
                    url: None,
                    path: None,
                    interval: None,
                    proxy: None,
                    header: None,
                    payload: Some(payload.clone()),
                },
            );
        }
        let ctx = meow_rules::ParserContext::empty();
        crate::rule_provider::load_providers(&raw, None, &ctx, None, false).expect("load failed")
    }

    // rule-set: domain behavior compiles into a matcher that hits the
    // provider's domains.
    #[tokio::test]
    async fn parse_nameserver_policy_rule_set_domain_matches_loaded_provider() {
        use crate::raw::RawNspValue;
        let providers = inline_rule_providers(&[(
            "cn",
            "domain",
            vec!["example.cn".to_string(), "+.cn".to_string()],
        )]);
        let map = nsp_map(&[(
            "rule-set:cn",
            RawNspValue::One("rcode://success".to_string()),
        )]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers, false)
            .await
            .unwrap();
        assert!(pol.lookup("example.cn").is_some());
        assert!(pol.lookup("foo.cn").is_some());
        assert!(pol.lookup("example.com").is_none());
    }

    // rule-set: referencing a missing provider is a hard error.
    #[tokio::test]
    async fn parse_nameserver_policy_rule_set_missing_provider_errors() {
        use crate::raw::RawNspValue;
        let providers = HashMap::new();
        let map = nsp_map(&[(
            "rule-set:missing",
            RawNspValue::One("rcode://success".to_string()),
        )]);
        let result =
            build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers, false).await;
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        assert!(msg.contains("not found rule-set"), "msg was: {msg}");
    }

    // rule-set: IpCidr behavior is rejected (expect domain/classical).
    #[tokio::test]
    async fn parse_nameserver_policy_rule_set_ipcidr_behavior_errors() {
        use crate::raw::RawNspValue;
        let providers = inline_rule_providers(&[("ips", "ipcidr", vec!["10.0.0.0/8".to_string()])]);
        let map = nsp_map(&[(
            "rule-set:ips",
            RawNspValue::One("rcode://success".to_string()),
        )]);
        let result =
            build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers, false).await;
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        assert!(msg.contains("IpCidr"), "msg was: {msg}");
    }

    // rule-set: classical behavior warns but still matches domain rules.
    #[tokio::test]
    async fn parse_nameserver_policy_rule_set_classical_warns_and_matches() {
        use crate::raw::RawNspValue;
        let providers = inline_rule_providers(&[(
            "cls",
            "classical",
            vec!["DOMAIN-SUFFIX,google.com".to_string()],
        )]);
        let map = nsp_map(&[(
            "rule-set:cls",
            RawNspValue::One("rcode://success".to_string()),
        )]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers, false)
            .await
            .unwrap();
        assert!(pol.lookup("mail.google.com").is_some());
        assert!(pol.lookup("example.org").is_none());
    }

    // rule-set:a,b expands into two providers.
    #[tokio::test]
    async fn parse_nameserver_policy_rule_set_comma_expands() {
        use crate::raw::RawNspValue;
        let providers = inline_rule_providers(&[
            ("a", "domain", vec!["a.example".to_string()]),
            ("b", "domain", vec!["b.example".to_string()]),
        ]);
        let map = nsp_map(&[(
            "rule-set:a,b",
            RawNspValue::One("rcode://success".to_string()),
        )]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers, false)
            .await
            .unwrap();
        assert!(pol.lookup("a.example").is_some());
        assert!(pol.lookup("b.example").is_some());
        assert!(pol.lookup("c.example").is_none());
    }

    // rule-set: provider names are case-sensitive.
    #[tokio::test]
    async fn parse_nameserver_policy_rule_set_case_sensitive_provider_name() {
        use crate::raw::RawNspValue;
        let providers = inline_rule_providers(&[("CN", "domain", vec!["example.cn".to_string()])]);
        let map = nsp_map(&[(
            "rule-set:CN",
            RawNspValue::One("rcode://success".to_string()),
        )]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers, false)
            .await
            .unwrap();
        assert!(pol.lookup("example.cn").is_some());
    }

    // Document order IS the lookup priority: two `rule-set:` keys covering
    // the same domain resolve to the FIRST key's entry. The len probe —
    // p1 carries one URL, p2 two — identifies the winner, and building the
    // same map twice must give the same answer (HashMap iteration order
    // made this a per-startup coin toss before).
    #[tokio::test]
    async fn parse_nameserver_policy_rule_set_document_order_picks_winner() {
        use crate::raw::RawNspValue;
        let providers = inline_rule_providers(&[
            ("p1", "domain", vec!["+.shared.example".to_string()]),
            ("p2", "domain", vec!["+.shared.example".to_string()]),
        ]);
        let map = nsp_map(&[
            (
                "rule-set:p1",
                RawNspValue::One("rcode://success".to_string()),
            ),
            (
                "rule-set:p2",
                RawNspValue::Many(vec![
                    "rcode://success".to_string(),
                    "rcode://name_error".to_string(),
                ]),
            ),
        ]);
        for _ in 0..2 {
            let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers, false)
                .await
                .unwrap();
            let hit = pol.lookup("x.shared.example").expect("must match");
            assert_eq!(
                hit.nameservers.len(),
                1,
                "rule-set:p1 is written first → its single-URL entry must win"
            );
        }

        // Flipping the document order flips the winner — the reversal is
        // the proof the order is consumed, not just incidentally stable.
        let reversed = nsp_map(&[
            (
                "rule-set:p2",
                RawNspValue::Many(vec![
                    "rcode://success".to_string(),
                    "rcode://name_error".to_string(),
                ]),
            ),
            (
                "rule-set:p1",
                RawNspValue::One("rcode://success".to_string()),
            ),
        ]);
        let pol = build_nameserver_policy(&reversed, None, &[], &HashMap::new(), &providers, false)
            .await
            .unwrap();
        let hit = pol.lookup("x.shared.example").expect("must match");
        assert_eq!(
            hit.nameservers.len(),
            2,
            "rule-set:p2 written first → its two-URL entry must win"
        );
    }

    // A `rule-set:` key written BEFORE a `+.` key shadows it — matcher
    // arms rank by document order, not below domain keys (mihomo
    // `makePolicy` arm-list parity). Loading that order warns; the
    // reversed order is the override and stays quiet.
    #[tokio::test]
    async fn parse_nameserver_policy_rule_set_arm_shadows_later_domain_key() {
        use crate::raw::RawNspValue;
        let warns = WarnCapture::start();
        let providers =
            inline_rule_providers(&[("rs", "domain", vec!["+.shadow.example".to_string()])]);
        let map = nsp_map(&[
            (
                "rule-set:rs",
                RawNspValue::One("rcode://success".to_string()),
            ),
            (
                "+.shadow.example",
                RawNspValue::Many(vec![
                    "rcode://success".to_string(),
                    "rcode://name_error".to_string(),
                ]),
            ),
        ]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers, false)
            .await
            .unwrap();
        let hit = pol.lookup("x.shadow.example").expect("must match");
        assert_eq!(
            hit.nameservers.len(),
            1,
            "the earlier rule-set arm must shadow the later domain key"
        );
        let logs = warns.take();
        assert!(
            logs.contains(
                "'+.shadow.example' is written after 'rule-set:rs', which already matches \
                 'shadow.example'"
            ),
            "a shadowed domain key must warn at load, got: {logs}"
        );

        // Same keys, reversed document order: the domain arm now wins.
        let reversed = nsp_map(&[
            (
                "+.shadow.example",
                RawNspValue::Many(vec![
                    "rcode://success".to_string(),
                    "rcode://name_error".to_string(),
                ]),
            ),
            (
                "rule-set:rs",
                RawNspValue::One("rcode://success".to_string()),
            ),
        ]);
        let pol = build_nameserver_policy(&reversed, None, &[], &HashMap::new(), &providers, false)
            .await
            .unwrap();
        let hit = pol.lookup("x.shadow.example").expect("must match");
        assert_eq!(
            hit.nameservers.len(),
            2,
            "the earlier domain arm must win once order flips"
        );
        let logs = warns.take();
        assert!(
            !logs.contains("is written after"),
            "a domain key above the matcher is an override, not a shadow: {logs}"
        );

        // Shadowed but routed to the same nameservers: nothing to warn about.
        let same = nsp_map(&[
            (
                "rule-set:rs",
                RawNspValue::One("rcode://success".to_string()),
            ),
            (
                "+.shadow.example",
                RawNspValue::One("rcode://success".to_string()),
            ),
        ]);
        build_nameserver_policy(&same, None, &[], &HashMap::new(), &providers, false)
            .await
            .unwrap();
        let logs = warns.take();
        assert!(
            !logs.contains("is written after"),
            "a shadow with the same nameservers routes identically: {logs}"
        );
    }

    // A `geosite:` key skipped for want of a geosite DB still ends the
    // open domain arm: the domain keys around it keep the precedence they
    // have once the DB loads, instead of folding into one last-wins trie.
    #[tokio::test]
    async fn parse_nameserver_policy_skipped_geosite_key_still_splits_domain_arms() {
        use crate::raw::RawNspValue;
        let map = nsp_map(&[
            ("x.example", RawNspValue::One("rcode://success".to_string())),
            (
                "geosite:cn",
                RawNspValue::One("rcode://success".to_string()),
            ),
            (
                "+.x.example",
                RawNspValue::Many(vec![
                    "rcode://success".to_string(),
                    "rcode://name_error".to_string(),
                ]),
            ),
        ]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false)
            .await
            .unwrap();
        assert_eq!(
            pol.lookup("x.example")
                .expect("must match")
                .nameservers
                .len(),
            1,
            "the bare key above the skipped geosite key must keep the apex"
        );
        assert_eq!(
            pol.lookup("a.x.example")
                .expect("must match")
                .nameservers
                .len(),
            2,
            "the `+.` key below it still covers the subdomains"
        );
    }

    // A comma-mixed key expands in place: `"+.a.example,rule-set:rs"`
    // produces a domain pattern followed by a matcher — the matcher arm
    // lands BEFORE the next key's domain arm and still shadows it.
    #[tokio::test]
    async fn parse_nameserver_policy_comma_mixed_key_expands_in_place() {
        use crate::raw::RawNspValue;
        let providers = inline_rule_providers(&[("rs", "domain", vec!["+.b.example".to_string()])]);
        let map = nsp_map(&[
            (
                "+.a.example,rule-set:rs",
                RawNspValue::One("rcode://success".to_string()),
            ),
            (
                "+.b.example",
                RawNspValue::Many(vec![
                    "rcode://success".to_string(),
                    "rcode://name_error".to_string(),
                ]),
            ),
        ]);
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers, false)
            .await
            .unwrap();
        // `q.a.example` hits the first key's domain arm.
        assert_eq!(pol.lookup("q.a.example").unwrap().nameservers.len(), 1);
        // `q.b.example`: the Domains arm holding `+.a.example` misses, the
        // matcher arm from the SAME key hits → the later `+.b.example`
        // domain key (two URLs) is shadowed.
        assert_eq!(
            pol.lookup("q.b.example").unwrap().nameservers.len(),
            1,
            "the mixed key's matcher arm must shadow the later domain key"
        );
    }

    // IndexMap-layer pin: a duplicate key folds to its first position
    // with the LAST value — mihomo `OrderedMap.Set` semantics. This
    // builds the `IndexMap` programmatically on purpose: every production
    // ingest path uses `parse_raw_yaml`, whose parser rejects a literal
    // duplicate key before the map exists — the fold below is only
    // reachable from non-literal sources.
    #[tokio::test]
    async fn parse_nameserver_policy_duplicate_key_folds_last_value_wins() {
        let mut map: crate::raw::RawNameserverPolicy = indexmap::IndexMap::new();
        map.insert(
            "+.dup.example".to_string(),
            crate::raw::RawNspValue::One("rcode://success".to_string()),
        );
        map.insert(
            "+.dup.example".to_string(),
            crate::raw::RawNspValue::Many(vec![
                "rcode://success".to_string(),
                "rcode://name_error".to_string(),
            ]),
        );
        assert_eq!(map.len(), 1, "the duplicate key must fold");
        assert_eq!(
            map.get("+.dup.example").unwrap().as_urls().len(),
            2,
            "the last value must win"
        );
        // The folded entry still builds a working policy.
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false)
            .await
            .unwrap();
        assert_eq!(pol.lookup("x.dup.example").unwrap().nameservers.len(), 2);
    }

    // Save path: serializing a raw config writes the policy keys back in
    // document order — the old `HashMap` wrote them in arbitrary order,
    // permanently reshuffling the document on every save.
    #[test]
    fn nameserver_policy_key_order_survives_save_roundtrip() {
        let raw: crate::raw::RawConfig = serde_saphyr::from_str(
            "dns:\n  nameserver-policy:\n    '+.first.example': 1.1.1.1\n    'second.example': 2.2.2.2\n    'rule-set:x': 3.3.3.3\n",
        )
        .unwrap();
        let yaml = serde_saphyr::to_string_with_options(&raw, crate::yaml_ser_options()).unwrap();
        let i_first = yaml.find("+.first.example").unwrap();
        let i_second = yaml.find("second.example").unwrap();
        let i_third = yaml.find("rule-set:x").unwrap();
        assert!(
            i_first < i_second && i_second < i_third,
            "keys must serialize in document order:\n{yaml}"
        );
        // A reparse of the saved document keeps the same order.
        let raw2: crate::raw::RawConfig = serde_saphyr::from_str(&yaml).unwrap();
        let map2 = raw2.dns.unwrap().nameserver_policy.unwrap();
        let keys: Vec<&String> = map2.keys().collect();
        assert_eq!(keys, ["+.first.example", "second.example", "rule-set:x"]);
    }

    // Fallback-filter defaults when no raw config provided.
    #[test]
    fn build_fallback_filter_defaults() {
        let ff = build_fallback_filter(None, None, false).unwrap();
        assert_eq!(ff.geoip_code, "CN");
        assert!(ff.ipcidr.is_empty());
        assert!(ff.domain.search("anything").is_none());
    }

    // Fallback-filter CIDR gate.
    #[test]
    fn build_fallback_filter_ipcidr_gate() {
        use crate::raw::RawFallbackFilter;
        let raw = RawFallbackFilter {
            geoip: Some(false),
            geoip_code: None,
            ipcidr: Some(vec!["240.0.0.0/4".to_string()]),
            domain: None,
        };
        let ff = build_fallback_filter(Some(&raw), None, false).unwrap();
        let bogon: IpAddr = "240.1.2.3".parse().unwrap();
        let clean: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(ff.ip_gated(&[bogon]));
        assert!(!ff.ip_gated(&[clean]));
    }

    // Fallback-filter domain gate matches +. pattern.
    // Upstream: dns/resolver.go::ipWithFallback. NOT primary-then-discard — skip entirely.
    #[test]
    fn build_fallback_filter_domain_gate() {
        use crate::raw::RawFallbackFilter;
        let raw = RawFallbackFilter {
            geoip: Some(false),
            geoip_code: None,
            ipcidr: None,
            domain: Some(vec!["+.google.cn".to_string()]),
        };
        let ff = build_fallback_filter(Some(&raw), None, false).unwrap();
        assert!(ff.domain_gated("www.google.cn"));
        assert!(ff.domain_gated("google.cn"));
        assert!(!ff.domain_gated("www.google.com"));
    }

    // Fallback-filter domain gate: `*.foo` is a single-label wildcard
    // (upstream mihomo `*` consumes exactly one label) — one subdomain label
    // hits, neither the root nor deeper subdomains.
    #[test]
    fn build_fallback_filter_domain_gate_star_single_label() {
        use crate::raw::RawFallbackFilter;
        let raw = RawFallbackFilter {
            geoip: Some(false),
            geoip_code: None,
            ipcidr: None,
            domain: Some(vec!["*.fb.test".to_string()]),
        };
        let ff = build_fallback_filter(Some(&raw), None, false).unwrap();
        assert!(
            ff.domain_gated("a.fb.test"),
            "single-label subdomain of *.fb.test must match"
        );
        assert!(!ff.domain_gated("fb.test"), "root must not match *.fb.test");
        assert!(
            !ff.domain_gated("a.b.fb.test"),
            "deep subdomain must not match *.fb.test"
        );
    }

    // An empty-label `fallback-filter.domain` entry inserts a trie node no
    // query name can ever match — the same dead-node shape as `hosts:`
    // (issue #822). Lenient surfaces it; strict rejects it.
    #[test]
    fn build_fallback_filter_empty_label_domain_warns_lenient_errors_strict() {
        use crate::raw::RawFallbackFilter;
        let raw = RawFallbackFilter {
            geoip: Some(false),
            geoip_code: None,
            ipcidr: None,
            domain: Some(vec!["a..b".to_string(), "fine.example".to_string()]),
        };
        let cap = WarnCapture::start();
        let ff = build_fallback_filter(Some(&raw), None, false).unwrap();
        let warns = cap.take();
        assert!(
            warns.contains("a..b") && warns.contains("empty label"),
            "the dead entry must be surfaced, got: {warns}"
        );
        assert!(
            ff.domain_gated("fine.example"),
            "the good entry must still gate"
        );
        assert!(!ff.domain_gated("a.b"), "a..b must not leak to a.b");
        let err = build_fallback_filter(Some(&raw), None, true)
            .err()
            .expect("strict must hard-error on an empty label");
        assert!(err.to_string().contains("empty label"));
    }

    /// An all-dots/prefix-only `fallback-filter.domain` entry is refused by
    /// the trie outright (`DomainKeyDefect::NotInsertable`): it takes the
    /// same lenient-warn / strict-error split as an empty label instead of
    /// the old warn-only insert failure.
    #[test]
    fn build_fallback_filter_all_dots_domain_warns_lenient_errors_strict() {
        use crate::raw::RawFallbackFilter;
        for dead in [".", "..", "+.", "*."] {
            let raw = RawFallbackFilter {
                geoip: Some(false),
                geoip_code: None,
                ipcidr: None,
                domain: Some(vec![dead.to_string()]),
            };
            let cap = WarnCapture::start();
            build_fallback_filter(Some(&raw), None, false)
                .unwrap_or_else(|_| panic!("{dead:?} must load in lenient mode"));
            let warns = cap.take();
            assert!(
                warns.contains("not a valid domain pattern"),
                "{dead:?}: the refused entry must be surfaced, got: {warns}"
            );
            let err = build_fallback_filter(Some(&raw), None, true)
                .err()
                .expect("strict must hard-error on a refused domain key");
            assert!(
                err.to_string().contains("not a valid domain pattern"),
                "{dead:?}: {err}"
            );
        }
    }

    // Same dead-node observability for `dns.fake-ip-filter`: lenient warns,
    // strict hard-errors — both through the `parse_dns` fake-IP path.
    #[tokio::test]
    async fn install_fakeip_empty_label_pattern_warns_lenient_errors_strict() {
        let lenient_yaml = "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver:\n    - 1.1.1.1\n  fake-ip-filter:\n    - a..b\n    - fine.example\n";
        let raw: RawConfig = serde_saphyr::from_str(lenient_yaml).unwrap();
        let cap = WarnCapture::start();
        parse_dns(
            &raw,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .expect("lenient fake-ip-filter dead label must still load");
        let warns = cap.take();
        assert!(
            warns.contains("a..b") && warns.contains("empty label"),
            "the dead entry must be surfaced, got: {warns}"
        );

        let strict_yaml = format!("strict: true\n{lenient_yaml}");
        let raw: RawConfig = serde_saphyr::from_str(&strict_yaml).unwrap();
        let err = parse_dns(
            &raw,
            None,
            None,
            &HashMap::new(),
            None,
            &HashMap::new(),
            None,
        )
        .await
        .err()
        .expect("strict must hard-error on an empty label");
        assert!(err.to_string().contains("empty label"), "got: {err}");
    }

    // --- nameserver-policy `#PROXY` fragments -----------------------------

    /// Minimal `Proxy` stub for registry-wiring assertions. Dials error —
    /// these tests only care whether the adapter handle reached the client.
    struct PolicyStubProxy {
        health: meow_common::ProxyHealth,
        /// `"<server>:<port>"`, or empty to stand in for a group.
        addr: String,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for PolicyStubProxy {
        fn name(&self) -> &str {
            "Proxy"
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Direct
        }
        fn addr(&self) -> &str {
            &self.addr
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            _m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            Err(meow_common::MeowError::NotSupported("stub".into()))
        }
        async fn dial_udp(
            &self,
            _m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            Err(meow_common::MeowError::NotSupported("stub".into()))
        }
    }

    impl meow_common::Proxy for PolicyStubProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            vec![]
        }
    }

    #[tokio::test]
    async fn policy_resolver_attaches_registry_proxy_for_fragment() {
        let mut registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        registry.insert(
            "Proxy".into(),
            Arc::new(PolicyStubProxy {
                health: meow_common::ProxyHealth::new(),
                addr: String::new(),
            }),
        );
        let value = crate::raw::RawNspValue::One("tcp://8.8.8.8#Proxy".to_string());
        let resolvers = build_policy_resolvers("geosite:gfw", &value, &[], &registry, false)
            .await
            .expect("proxy-tagged policy entry builds");
        assert_eq!(resolvers.len(), 1);
        assert!(
            resolvers[0].is_proxied(),
            "registry adapter must be wired into the policy client"
        );
    }

    #[tokio::test]
    async fn policy_resolver_unknown_proxy_name_degrades_to_direct() {
        let registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        let value = crate::raw::RawNspValue::Many(vec![
            "tcp://8.8.8.8#NoSuchProxy".to_string(),
            "1.1.1.1#NoSuchProxy".to_string(),
        ]);
        let resolvers = build_policy_resolvers("geosite:gfw", &value, &[], &registry, false)
            .await
            .expect("unknown proxy name must not fail the policy build");
        assert_eq!(resolvers.len(), 2);
        assert!(
            resolvers.iter().all(|r| !r.is_proxied()),
            "unknown names degrade to direct dials"
        );

        // Strict: the same silent direct-dial downgrade is a hard error —
        // the upstream was proxied precisely because direct is untrusted
        // (issue #533 review).
        let Err(err) = build_policy_resolvers("geosite:gfw", &value, &[], &registry, true).await
        else {
            panic!("strict must reject an unknown #proxy reference");
        };
        assert!(err.to_string().contains("NoSuchProxy"), "unexpected: {err}");
    }

    #[tokio::test]
    async fn policy_resolver_invalid_url_fails_under_strict() {
        let registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        // A scheme the URL parser doesn't know is warn-skipped leniently…
        let value = crate::raw::RawNspValue::Many(vec![
            "bogus://8.8.8.8".to_string(),
            "1.1.1.1".to_string(),
        ]);
        let resolvers = build_policy_resolvers("example.com", &value, &[], &registry, false)
            .await
            .expect("lenient keeps the valid entries");
        assert_eq!(resolvers.len(), 1);

        // …but under strict the unparseable entry is a config defect.
        let Err(err) = build_policy_resolvers("example.com", &value, &[], &registry, true).await
        else {
            panic!("strict must reject an invalid policy URL");
        };
        assert!(err.to_string().contains("bogus"), "unexpected: {err}");
    }

    /// `geosite:` policy keys with no loaded DB silently dropped the whole
    /// entry — asymmetric with `rule-set:`'s hard error. Strict escalates
    /// (issue #533 review).
    #[tokio::test]
    async fn strict_rejects_geosite_policy_without_db() {
        let map = nsp_map(&[(
            "geosite:gfw",
            crate::raw::RawNspValue::One("8.8.8.8".to_string()),
        )]);
        // Lenient: warn + entry skipped.
        build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false)
            .await
            .expect("lenient drops geosite keys without a DB");
        // Strict: hard error naming the key.
        let Err(err) =
            build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), true).await
        else {
            panic!("strict must reject geosite: policy with no DB");
        };
        assert!(err.to_string().contains("geosite"), "unexpected: {err}");
    }

    /// A `foo:`-prefixed policy key is dead config — strict rejects it
    /// (issue #533 review).
    #[tokio::test]
    async fn strict_rejects_unsupported_policy_prefix() {
        let map = nsp_map(&[(
            "geoip:cn",
            crate::raw::RawNspValue::One("8.8.8.8".to_string()),
        )]);
        build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), false)
            .await
            .expect("lenient skips unknown prefixes");
        let Err(err) =
            build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new(), true).await
        else {
            panic!("strict must reject an unsupported policy prefix");
        };
        assert!(err.to_string().contains("geoip"), "unexpected: {err}");
    }

    /// With several defective keys strict reports the FIRST one in
    /// document order — the `IndexMap` carrier makes the error
    /// deterministic (the old HashMap carrier picked one at random).
    /// Build the same two bad keys in both orders and assert the
    /// reported key follows the document.
    #[tokio::test]
    async fn strict_policy_error_reports_first_defective_key_in_document_order() {
        let v = || crate::raw::RawNspValue::One("8.8.8.8".to_string());

        let Err(err) = build_nameserver_policy(
            &nsp_map(&[("geoip:cn", v()), ("geosite:gfw", v())]),
            None,
            &[],
            &HashMap::new(),
            &HashMap::new(),
            true,
        )
        .await
        else {
            panic!("strict must reject the defective policy");
        };
        assert!(
            err.to_string().contains("'geoip:cn'"),
            "first documented defective key must error first: {err}"
        );

        let Err(err) = build_nameserver_policy(
            &nsp_map(&[("geosite:gfw", v()), ("geoip:cn", v())]),
            None,
            &[],
            &HashMap::new(),
            &HashMap::new(),
            true,
        )
        .await
        else {
            panic!("strict must reject the defective policy");
        };
        assert!(
            err.to_string().contains("'geosite:gfw'"),
            "reversing the document must reverse the reported key: {err}"
        );
    }

    /// `fallback-filter.ipcidr` with an unparseable CIDR and a `hosts:`
    /// entry with an empty value list are static defects — strict errors
    /// (issue #533 review).
    #[test]
    fn strict_rejects_bad_fallback_cidr_and_empty_hosts() {
        use crate::raw::{HostsValue, RawFallbackFilter};
        let raw = RawFallbackFilter {
            geoip: Some(false),
            ipcidr: Some(vec!["not-a-cidr".to_string()]),
            ..Default::default()
        };
        build_fallback_filter(Some(&raw), None, false).expect("lenient skips bad CIDRs");
        assert!(
            build_fallback_filter(Some(&raw), None, true).is_err(),
            "strict must reject an invalid fallback-filter CIDR"
        );

        let mut hosts = RawHosts::new();
        hosts.insert("empty.test".to_string(), HostsValue::Many(vec![]));
        build_hosts_trie(Some(&hosts), false).expect("lenient skips empty hosts entries");
        assert!(
            build_hosts_trie(Some(&hosts), true).is_err(),
            "strict must reject an empty hosts entry"
        );
    }

    #[tokio::test]
    async fn policy_resolver_tls_fragment_stays_sni() {
        // For tls:// the fragment is SNI, not a proxy name — must keep
        // parsing as before and never consult the registry.
        let registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        let value = crate::raw::RawNspValue::One("tls://8.8.4.4#dns.google".to_string());
        let resolvers = build_policy_resolvers("example.com", &value, &[], &registry, false)
            .await
            .expect("tls entry with SNI fragment builds");
        assert_eq!(resolvers.len(), 1);
        assert!(!resolvers[0].is_proxied());
    }

    // ─── `?proxy=` on encrypted policy entries (issue #67 phase 2) ─────

    #[tokio::test]
    async fn policy_resolver_attaches_registry_proxy_for_query_param() {
        let mut registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        registry.insert(
            "Proxy".into(),
            Arc::new(PolicyStubProxy {
                health: meow_common::ProxyHealth::new(),
                addr: String::new(),
            }),
        );
        let value = crate::raw::RawNspValue::One("tls://8.8.4.4?proxy=Proxy".to_string());
        let resolvers = build_policy_resolvers("geosite:gfw", &value, &[], &registry, false)
            .await
            .expect("`?proxy=` policy entry builds");
        assert_eq!(resolvers.len(), 1);
        assert!(
            resolvers[0].is_proxied(),
            "`?proxy=` must wire the registry adapter like `#` does"
        );
    }

    /// A `?proxy=` *hostname* entry skips policy bootstrap: the name goes
    /// to the proxy for remote resolution, so an empty bootstrap-client
    /// list must not drop it (it would have been skipped before — the
    /// hostname resolution path could never produce an IP for it).
    #[tokio::test]
    async fn policy_resolver_query_proxy_hostname_skips_bootstrap() {
        let mut registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        registry.insert(
            "Proxy".into(),
            Arc::new(PolicyStubProxy {
                health: meow_common::ProxyHealth::new(),
                addr: String::new(),
            }),
        );
        let value =
            crate::raw::RawNspValue::One("tls://policy-stub.invalid?proxy=Proxy".to_string());
        let resolvers = build_policy_resolvers("geosite:gfw", &value, &[], &registry, false)
            .await
            .expect("proxied hostname policy entry builds with no bootstrap clients");
        assert_eq!(resolvers.len(), 1);
        assert!(resolvers[0].is_proxied());
    }

    /// An unknown `?proxy=` name degrades to a direct dial under the
    /// lenient path and is a hard error under strict — identical to the
    /// `#PROXY` contract.
    #[tokio::test]
    async fn policy_resolver_unknown_query_proxy_lenient_and_strict() {
        let registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        let value = crate::raw::RawNspValue::One("tls://8.8.4.4?proxy=NoSuchProxy".to_string());
        let resolvers = build_policy_resolvers("geosite:gfw", &value, &[], &registry, false)
            .await
            .expect("lenient keeps the entry as a direct client");
        assert_eq!(resolvers.len(), 1);
        assert!(!resolvers[0].is_proxied());

        let Err(err) = build_policy_resolvers("geosite:gfw", &value, &[], &registry, true).await
        else {
            panic!("strict must reject an unknown ?proxy= reference");
        };
        assert!(err.to_string().contains("NoSuchProxy"), "unexpected: {err}");
    }

    /// r15 M3 regression: a nameserver-policy *hostname* entry tagged with
    /// an **unknown** proxy must not trip the
    /// `build_single_resolver_with_proxy` debug_assert (debug panic) nor
    /// mint a dead `192.0.2.1` client (release zombie). The lenient path
    /// resolves the hostname via bootstrap — exactly like an untagged
    /// entry — and dials direct. `?proxy=` and `#PROXY` hit the same path:
    /// `entry.proxy` is spelling-agnostic.
    #[test]
    fn policy_resolver_unknown_proxy_hostname_bootstraps_and_dials_direct() {
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

        // A bare-thread `warn!` on this callsite must not be able to
        // cache `Interest::never` under the sink's scope — see the helper.
        crate::test_support::install_global_discard_subscriber();
        // Warn sink — same pattern as
        // `policy_resolver_sni_matching_proxy_name_warns`: `with_default`
        // is thread-local, so the future must be *driven* inside it.
        #[derive(Clone)]
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;
            fn make_writer(&'a self) -> Sink {
                self.clone()
            }
        }
        let sink = Sink(Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();

        let registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current_thread runtime");

        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(async {
                // UDP bootstrap stub: `A` answers 203.0.113.9, `AAAA` gets
                // an empty NOERROR (NODATA) — enough for `lookup_ip`.
                let stub = tokio::net::UdpSocket::bind("127.0.0.1:0")
                    .await
                    .expect("bind dns stub");
                let stub_addr = stub.local_addr().unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    while let Ok((len, peer)) = stub.recv_from(&mut buf).await {
                        let Ok(req) = Message::from_bytes(&buf[..len]) else {
                            continue;
                        };
                        let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                        resp.metadata.response_code = ResponseCode::NoError;
                        resp.metadata.recursion_available = true;
                        for q in &req.queries {
                            resp.add_query(q.clone());
                            if q.query_type == RecordType::A {
                                let name: Name = "policy-host.test.".parse().unwrap();
                                resp.add_answer(Record::from_rdata(
                                    name,
                                    60,
                                    RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
                                ));
                            }
                        }
                        let _ = stub.send_to(&resp.to_bytes().unwrap(), peer).await;
                    }
                });
                let bootstrap = vec![Arc::new(DnsClient::udp(stub_addr))];

                for url in [
                    "tls://policy-host.test?proxy=NoSuchProxy",
                    "tcp://policy-host.test#NoSuchProxy",
                ] {
                    let value = crate::raw::RawNspValue::One(url.to_string());
                    let clients =
                        build_policy_resolvers("geosite:gfw", &value, &bootstrap, &registry, false)
                            .await
                            .unwrap_or_else(|e| {
                                panic!("'{url}' must build under lenient policy: {e}")
                            });
                    assert_eq!(clients.len(), 1, "{url}");
                    assert!(
                        !clients[0].is_proxied(),
                        "{url}: an unknown tag must degrade to a direct client"
                    );
                    assert!(
                        clients[0].upstream_label().contains("203.0.113.9"),
                        "{url}: the hostname must be bootstrap-resolved, got label '{}'",
                        clients[0].upstream_label()
                    );
                }
            });
        });

        let captured = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
        assert!(
            captured.contains("NoSuchProxy") && captured.contains("direct"),
            "an unknown proxy must warn about the direct fallback; got: {captured}"
        );
    }

    /// The migration aid: `#X` on an encrypted entry is SNI — when `X`
    /// names a real proxy the config almost certainly meant `?proxy=X`.
    /// Assert the warn fires (scoped capture, same pattern as
    /// `duplicate_leaf_name_warns` in lib.rs). `with_default` is a
    /// thread-local scope, so the future must be *driven* inside it —
    /// `block_on` from a sync test, not `.await` on a tokio test.
    #[test]
    fn policy_resolver_sni_matching_proxy_name_warns() {
        crate::test_support::install_global_discard_subscriber();
        #[derive(Clone)]
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;
            fn make_writer(&'a self) -> Sink {
                self.clone()
            }
        }
        let sink = Sink(Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();

        let mut registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        registry.insert(
            "Proxy".into(),
            Arc::new(PolicyStubProxy {
                health: meow_common::ProxyHealth::new(),
                addr: String::new(),
            }),
        );
        let value = crate::raw::RawNspValue::One("tls://8.8.4.4#Proxy".to_string());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current_thread runtime");
        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(build_policy_resolvers(
                "geosite:gfw",
                &value,
                &[],
                &registry,
                false,
            ))
            .expect("SNI-fragment entry builds (fragment is SNI, not a proxy tag)");
        });

        let captured = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
        assert!(
            captured.contains("did you mean `?proxy=X`"),
            "SNI matching a proxy name must warn; got: {captured}"
        );
    }

    /// The same migration aid on the main path: `nameserver`,
    /// `fallback`, and `proxy-server-nameserver` all flow through
    /// `Resolver::new_with_bootstrap_with_proxies` (`parse_dns` call
    /// sites), whose `#X`-is-SNI check warns when `X` names a configured
    /// proxy. Drive a full `parse_dns` so both call sites are covered,
    /// and assert the warn fires once per offending entry — three in
    /// total. Same scoped-capture pattern as
    /// `policy_resolver_sni_matching_proxy_name_warns`.
    #[test]
    fn main_path_sni_matching_proxy_name_warns() {
        crate::test_support::install_global_discard_subscriber();
        #[derive(Clone)]
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;
            fn make_writer(&'a self) -> Sink {
                self.clone()
            }
        }
        let sink = Sink(Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();

        let mut registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        registry.insert(
            "Proxy".into(),
            Arc::new(PolicyStubProxy {
                health: meow_common::ProxyHealth::new(),
                addr: String::new(),
            }),
        );
        // One `#Proxy`-SNI encrypted entry per field — every one must
        // warn exactly once (`fallback-filter.geoip: false` only keeps
        // an unrelated missing-MMDB warn out of the capture).
        let raw: RawConfig = serde_saphyr::from_str(
            "dns:\n  enable: true\n  nameserver:\n    - tls://8.8.4.4#Proxy\n  fallback:\n    - https://8.8.4.4/dns-query#Proxy\n  fallback-filter:\n    geoip: false\n  proxy-server-nameserver:\n    - tls://1.1.1.1#Proxy\n",
        )
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current_thread runtime");
        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(parse_dns(
                &raw,
                None,
                None,
                &registry,
                None,
                &HashMap::new(),
                None,
            ))
            .expect("`#X` SNI entries still build — the warn is advisory");
        });

        let captured = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
        assert_eq!(
            captured.matches("did you mean `?proxy=X`").count(),
            3,
            "nameserver + fallback + proxy-server-nameserver must each warn once; got: {captured}"
        );
    }

    /// `?proxy=` on a `proxy-server-nameserver` entry flows through the
    /// same circularity audit as `#PROXY`: tagging a hostname-node proxy
    /// there is still circular and must warn.
    #[test]
    fn query_proxy_tag_on_hostname_node_is_circular() {
        let entries = parse_nameserver_entries(&["tls://223.5.5.5?proxy=JP".to_string()]).unwrap();
        let registry = stub_registry(&[("JP", "node.example:443")]);
        assert_eq!(circular_proxy_tags(&entries, &registry).len(), 1);
    }

    // --- proxy-server-nameserver `#PROXY` circularity ---------------------

    fn stub_registry(
        entries: &[(&str, &str)],
    ) -> HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> {
        entries
            .iter()
            .map(|(name, addr)| {
                let proxy: Arc<dyn meow_common::Proxy> = Arc::new(PolicyStubProxy {
                    health: meow_common::ProxyHealth::new(),
                    addr: (*addr).to_string(),
                });
                (smol_str::SmolStr::from(*name), proxy)
            })
            .collect()
    }

    #[test]
    fn ip_literal_addr_detection() {
        assert!(is_ip_literal_addr("1.2.3.4:443"));
        assert!(is_ip_literal_addr("[2001:db8::1]:443"));
        assert!(is_ip_literal_addr("2001:db8::1"));
        assert!(!is_ip_literal_addr("node.example:443"));
        // Groups report no address at all.
        assert!(!is_ip_literal_addr(""));
    }

    #[test]
    fn proxy_tag_on_hostname_node_is_circular() {
        let entries = parse_nameserver_entries(&["223.5.5.5#JP".to_string()]).unwrap();
        let registry = stub_registry(&[("JP", "node.example:443")]);
        assert_eq!(
            circular_proxy_tags(&entries, &registry),
            vec![("udp://223.5.5.5:53".to_string(), "JP".to_string())]
        );
    }

    #[test]
    fn proxy_tag_on_ip_literal_node_is_fine() {
        // The hook short-circuits IP literals, so this tag never re-enters
        // the resolver — it works exactly as written and must not warn.
        let entries = parse_nameserver_entries(&["223.5.5.5#JP".to_string()]).unwrap();
        let registry = stub_registry(&[("JP", "1.2.3.4:443")]);
        assert!(circular_proxy_tags(&entries, &registry).is_empty());
    }

    #[test]
    fn proxy_tag_on_group_is_circular() {
        let entries = parse_nameserver_entries(&["223.5.5.5#Auto".to_string()]).unwrap();
        let registry = stub_registry(&[("Auto", "")]);
        assert_eq!(circular_proxy_tags(&entries, &registry).len(), 1);
    }

    #[test]
    fn untagged_and_unknown_proxy_entries_are_skipped() {
        let entries =
            parse_nameserver_entries(&["223.5.5.5".to_string(), "8.8.8.8#NoSuchProxy".to_string()])
                .unwrap();
        // Unknown names are the bootstrap builder's error to raise, not ours.
        let registry = stub_registry(&[("JP", "node.example:443")]);
        assert!(circular_proxy_tags(&entries, &registry).is_empty());
    }
}
