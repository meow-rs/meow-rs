use crate::raw::{HostsValue, RawConfig};
use crate::rule_provider::RuleProvider;
use crate::DnsConfig;
use meow_common::DnsMode;
use meow_dns::fakeip::{FileStore, MemoryStore, Pool, Skipper, SkipperMode, Store};
use meow_dns::resolver::{
    FallbackFilter, HostEntry, NameserverPolicy, NameserverPolicyMatcher, PolicyEntry,
};
use meow_dns::upstream::{NameServerEntry, NameServerUrl};
use meow_dns::{DnsClient, HostOrIp, Resolver};
use meow_rules::RuleSetBehavior;
use meow_trie::DomainTrie;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Upstream Go mihomo default for v4 fake-IP CIDR. Used when
/// `enhanced-mode: fake-ip` is set but `fake-ip-range` is omitted.
const DEFAULT_FAKE_IP_RANGE_V4: &str = "198.18.0.1/16";

/// `prior` is the resolver generation being replaced (config reload); its
/// fake-IP pool is carried over when the configured range and store kind
/// are unchanged, so clients holding earlier `host → fake-ip` answers keep
/// a valid reverse mapping. Pass `None` on cold start.
pub async fn parse_dns(
    raw: &RawConfig,
    mmdb_path: Option<&std::path::Path>,
    cache_dir: Option<&std::path::Path>,
    proxy_registry: &HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
    geosite: Option<Arc<meow_rules::geosite::GeositeDB>>,
    rule_providers: &HashMap<String, Arc<RuleProvider>>,
    prior: Option<&Resolver>,
) -> Result<DnsConfig, anyhow::Error> {
    let dns = match &raw.dns {
        Some(dns) if dns.enable.unwrap_or(false) => dns,
        _ => {
            let hosts = build_hosts_trie(raw.hosts.as_ref())?;
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
        _ => DnsMode::Normal,
    };

    let listen_addr = crate::parse_optional_socket_addr("dns.listen", dns.listen.as_deref())?;
    let mut hosts = build_hosts_trie(raw.hosts.as_ref())?;

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
                "dns.proxy-server-nameserver '{nameserver}' is tagged #{proxy}, but '{proxy}' is \
                 itself reached by hostname — resolving that hostname is what this nameserver \
                 exists to do, so the lookup re-enters the resolver, is fenced to hosts: + cache, \
                 and falls through to the system resolver on a miss. Pin the node's server in \
                 hosts:, give it an IP-literal server:, or drop the #{proxy} tag."
            );
        }
        let mut proxy_hosts = build_hosts_trie(raw.hosts.as_ref())?;
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
                build_fallback_filter(raw_filter.as_ref(), mmdb_path.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("fallback-filter build task failed: {e}"))?,
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
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Fake-IP wiring: only when enhanced-mode == fake-ip. Errors here are
    // fatal (Class A per ADR-0002) — a misconfigured fake-IP range would
    // silently fall back to the upstream resolver, which is a user-surprising
    // privacy regression.
    if mode == DnsMode::FakeIp {
        install_fakeip(&mut resolver, dns, cache_dir, prior).await?;
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
) -> Result<(), anyhow::Error> {
    let range_str = dns
        .fake_ip_range
        .as_deref()
        .unwrap_or(DEFAULT_FAKE_IP_RANGE_V4);
    let prefix: ipnet::IpNet = range_str
        .parse()
        .map_err(|e| anyhow::anyhow!("dns.fake-ip-range '{range_str}' is not a valid CIDR: {e}"))?;

    let persist = dns.store_fake_ip.unwrap_or(false);

    // Carry the live pool into the rebuilt resolver when the range and the
    // store kind are unchanged. The pool's store IS the fake-IP state: a
    // fresh MemoryStore strands clients still holding `host → fake-ip`
    // answers and resets the allocation cursor, which then reissues the
    // same addresses to other hosts — `pre_handle_metadata` would
    // reverse-map in-flight connections to the wrong target (issue #514
    // review follow-up). Reuse also keeps `store-fake-ip` reloads on ONE
    // FileStore instead of running two persist writers over the same file.
    let pool = match prior
        .and_then(|r| r.fakeip_pool_over(prefix))
        .filter(|p| p.is_persistent() == persist)
    {
        Some(pool) => pool,
        None => {
            let store_path = |suffix: &str| -> std::path::PathBuf {
                let base = cache_dir.map_or_else(
                    || std::path::PathBuf::from("."),
                    std::path::Path::to_path_buf,
                );
                base.join(format!("fakeip-{suffix}.json"))
            };

            let store: Arc<dyn Store> = if persist {
                let path = store_path(match &prefix {
                    ipnet::IpNet::V4(_) => "v4",
                    ipnet::IpNet::V6(_) => "v6",
                });
                let p = FileStore::open_async(path.clone()).await.map_err(|e| {
                    let disp = path.display();
                    anyhow::anyhow!("cannot open fakeip store {disp}: {e}")
                })?;
                Arc::new(p)
            } else {
                // Capacity bounded by prefix size, but cap at a sensible upper bound
                // so a /8 doesn't allocate 16M cache slots up front.
                Arc::new(MemoryStore::new(1 << 20))
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

/// `#PROXY`-tagged `dns.proxy-server-nameserver` entries whose proxy cannot be
/// dialled without this very resolver, as `(nameserver, proxy name)` pairs.
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
/// rule-providers; the matcher snapshots the provider on each lookup so
/// background refreshes take effect automatically.
/// Other prefixed patterns (anything with `:`) warn once and skip.
///
/// An entry with no valid nameservers after skipping → hard error.
/// Class A per ADR-0002: DNS leakage risk for internal/corporate domains.
async fn build_nameserver_policy(
    map: &HashMap<String, crate::raw::RawNspValue>,
    geosite: Option<&Arc<meow_rules::geosite::GeositeDB>>,
    bootstrap_clients: &[Arc<DnsClient>],
    proxy_registry: &HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
    rule_providers: &HashMap<String, Arc<RuleProvider>>,
) -> Result<NameserverPolicy, anyhow::Error> {
    let mut policy = NameserverPolicy::new();
    let mut warned_unsupported_prefix = false;
    let mut warned_missing_geosite = false;

    for (key, value) in map {
        let mut patterns = Vec::new();
        for expanded_key in expand_policy_keys(key) {
            let key_lower = expanded_key.to_ascii_lowercase();
            if let Some(category) = key_lower.strip_prefix("geosite:") {
                let category = category.trim();
                if category.is_empty() {
                    continue;
                }
                let Some(db) = geosite else {
                    if !warned_missing_geosite {
                        warn!(
                            "nameserver-policy: geosite: patterns require a loaded geosite DB; \
                            skipping geosite policy entries"
                        );
                        warned_missing_geosite = true;
                    }
                    continue;
                };
                let category = category.to_string();
                let db = Arc::clone(db);
                patterns.push(PolicyPattern::Matcher(Arc::new(move |domain| {
                    db.lookup(&category, domain)
                })));
                continue;
            }

            if key_lower.starts_with("rule-set:") {
                // Provider names are case-sensitive — extract from the
                // original-case `expanded_key`, not `key_lower`.
                let name = expanded_key["rule-set:".len()..].trim();
                if name.is_empty() {
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
                let provider = Arc::clone(provider);
                patterns.push(PolicyPattern::Matcher(Arc::new(move |domain: &str| {
                    provider.snapshot().matches_domain(domain)
                })));
                continue;
            }

            if key_lower.contains(':') {
                if !warned_unsupported_prefix {
                    warn!(
                        "nameserver-policy: unsupported prefixed patterns containing ':' \
                        will be skipped"
                    );
                    warned_unsupported_prefix = true;
                }
                continue;
            }

            if key_lower.starts_with("+.") {
                patterns.push(PolicyPattern::Wildcard(key_lower));
            } else if !key_lower.is_empty() {
                patterns.push(PolicyPattern::Exact(key_lower));
            }
        }

        if patterns.is_empty() {
            continue;
        }

        let resolvers =
            build_policy_resolvers(key, value, bootstrap_clients, proxy_registry).await?;

        let entry = PolicyEntry {
            nameservers: resolvers,
        };
        for pattern in patterns {
            match pattern {
                PolicyPattern::Exact(domain) => policy.insert_exact(domain, entry.clone()),
                PolicyPattern::Wildcard(pattern) => policy.insert_wildcard(&pattern, entry.clone()),
                PolicyPattern::Matcher(matcher) => policy.insert_matcher(matcher, entry.clone()),
            }
        }
    }

    Ok(policy)
}

enum PolicyPattern {
    Exact(String),
    Wildcard(String),
    Matcher(NameserverPolicyMatcher),
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
) -> Result<Vec<Arc<meow_dns::DnsClient>>, anyhow::Error> {
    let url_strs = value.as_urls();
    let empty_resolved = HashMap::new();
    let mut resolvers = Vec::new();
    for url_str in &url_strs {
        match NameServerEntry::parse(url_str) {
            Ok(entry) => {
                let Some(url) =
                    resolve_policy_hostname_url(entry.url, key, url_str, bootstrap_clients).await
                else {
                    continue;
                };
                // `#PROXY` fragment: route this upstream's exchanges through
                // the named adapter, matching the nameserver/fallback entry
                // semantics (issue #67 phase 2, ADR-0012). An unknown name
                // degrades to a direct dial like the main path does, but
                // warn loudly — a policy upstream is usually proxied
                // precisely because the direct path is untrusted.
                let proxy = entry.proxy.as_deref().and_then(|name| {
                    let handle = proxy_registry.get(name).cloned();
                    if handle.is_none() {
                        warn!(
                            "nameserver-policy entry '{}': URL '{}' references unknown \
                            proxy '{}'; dialing direct",
                            key, url_str, name
                        );
                    }
                    handle
                });
                let resolver =
                    Resolver::build_single_resolver_with_proxy(&url, &empty_resolved, proxy);
                resolvers.push(resolver);
            }
            Err(e) => {
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
    if bootstrap_clients.is_empty() {
        warn!(
            "nameserver-policy entry '{}': URL '{}' uses hostname '{}' but no IP-literal \
            nameserver/default-nameserver is available for policy bootstrap; skipping",
            key, url_str, host
        );
        return None;
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
) -> FallbackFilter {
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
                warn!(
                    "fallback-filter.ipcidr: skipping invalid CIDR '{}': {}",
                    s, e
                );
            }
        }
    }

    let mut domain: DomainTrie<()> = DomainTrie::new();
    for s in domain_strs {
        let pattern = normalize_hosts_wildcard(s);
        domain.insert(&pattern, ());
        // DomainTrie's +. doesn't include the root — insert root explicitly.
        if let Some(bare) = pattern.strip_prefix("+.") {
            domain.insert(bare, ());
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

    FallbackFilter {
        geoip_enabled,
        geoip_code,
        ipcidr,
        domain,
        geoip_reader,
    }
}

/// Build the hosts trie from top-level mihomo-compatible `hosts:` entries.
/// A single value may be an IP or domain alias; lists must contain only IPs.
/// Malformed values and alias cycles are hard errors (Class A per ADR-0002).
fn build_hosts_trie(
    hosts: Option<&HashMap<String, HostsValue>>,
) -> Result<DomainTrie<HostEntry>, anyhow::Error> {
    let mut trie: DomainTrie<HostEntry> = DomainTrie::new();
    let Some(hosts) = hosts else {
        return Ok(trie);
    };
    let mut aliases = Vec::new();
    for (host, value) in hosts {
        let values = value.as_slice();
        if values.is_empty() {
            warn!("hosts: entry '{}' has no values, skipping", host);
            continue;
        }
        let host_entry = if values.len() == 1 {
            let raw = values[0].trim();
            match raw.parse::<IpAddr>() {
                Ok(ip) => HostEntry::Addresses(vec![ip]),
                Err(_) => {
                    let alias = parse_host_alias(raw, host)?;
                    aliases.push((normalize_hosts_wildcard(host.trim()), alias.clone()));
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
        // Rewrite *.foo → +.foo for DomainTrie wildcard semantics at parse time.
        let entry = normalize_hosts_wildcard(host.trim());
        if !trie.insert(&entry, host_entry.clone()) {
            warn!("hosts: failed to insert '{}' into trie", host);
        }
        // DomainTrie's +. semantics don't include the root domain itself — insert
        // it explicitly so that "corp.internal" matches "+.corp.internal".
        if let Some(bare) = entry.strip_prefix("+.") {
            trie.insert(bare, host_entry);
        }
    }
    reject_host_alias_cycles(&trie, &aliases)?;
    Ok(trie)
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

/// Convert `*.example.com` → `+.example.com` for DomainTrie wildcard semantics.
fn normalize_hosts_wildcard(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("*.") {
        format!("+.{rest}")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn one(s: &str) -> HostsValue {
        HostsValue::One(s.to_string())
    }
    fn many(ss: &[&str]) -> HostsValue {
        HostsValue::Many(ss.iter().map(std::string::ToString::to_string).collect())
    }

    fn addresses(entry: &HostEntry) -> &[IpAddr] {
        match entry {
            HostEntry::Addresses(ips) => ips,
            HostEntry::Alias(alias) => panic!("expected addresses, got alias {alias}"),
        }
    }

    #[test]
    fn build_hosts_trie_none_is_empty() {
        let trie = build_hosts_trie(None).unwrap();
        assert!(trie.search("example.com").is_none());
    }

    #[tokio::test]
    async fn proxy_server_nameserver_builds_dedicated_resolver() {
        let raw: RawConfig = serde_yaml::from_str(
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
            serde_yaml::from_str("dns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\n").unwrap();
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
        let raw: RawConfig = serde_yaml::from_str(
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
    /// pool over when the range and store kind are unchanged — otherwise
    /// clients holding `host → fake-ip` answers lose the mapping and the
    /// fresh cursor reissues their addresses to other hosts.
    #[tokio::test]
    async fn fakeip_pool_is_carried_into_rebuilt_resolver() {
        let yaml = |ns: &str| {
            format!("dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver:\n    - {ns}\n")
        };
        let raw: RawConfig = serde_yaml::from_str(&yaml("1.1.1.1")).unwrap();
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
        let raw2: RawConfig = serde_yaml::from_str(&yaml("8.8.8.8")).unwrap();
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
        let raw: RawConfig = serde_yaml::from_str(&yaml("198.18.0.1/16")).unwrap();
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

        let raw2: RawConfig = serde_yaml::from_str(&yaml("198.19.0.1/16")).unwrap();
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
        let raw: RawConfig = serde_yaml::from_str(&yaml("1.1.1.1", "true")).unwrap();
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
        let raw2: RawConfig = serde_yaml::from_str(&yaml("8.8.8.8", "true")).unwrap();
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
        let raw3: RawConfig = serde_yaml::from_str(&yaml("8.8.8.8", "false")).unwrap();
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

    #[test]
    fn build_hosts_trie_single_ip() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), one("1.2.3.4"));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        let v = trie.search("example.com").expect("must hit");
        assert_eq!(addresses(v), &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn build_hosts_trie_many_ips() {
        let mut map = HashMap::new();
        map.insert("dual.test".to_string(), many(&["1.1.1.1", "::1"]));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        let v = trie.search("dual.test").expect("must hit");
        assert_eq!(addresses(v).len(), 2);
    }

    #[test]
    fn build_hosts_trie_domain_alias() {
        let mut map = HashMap::new();
        map.insert("node.example".to_string(), one("origin.example"));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        assert_eq!(
            trie.search("node.example"),
            Some(&HostEntry::Alias("origin.example".into()))
        );
    }

    #[test]
    fn build_hosts_trie_rejects_alias_cycle() {
        let mut map = HashMap::new();
        map.insert("a.example".to_string(), one("b.example"));
        map.insert("b.example".to_string(), one("a.example"));
        let err = build_hosts_trie(Some(&map))
            .err()
            .expect("domain alias cycles must be rejected");
        assert!(err.to_string().contains("alias cycle"));
    }

    #[test]
    fn build_hosts_trie_rejects_domain_in_multi_value_list() {
        let mut map = HashMap::new();
        map.insert(
            "bad.example".to_string(),
            many(&["192.0.2.1", "origin.example"]),
        );
        let err = build_hosts_trie(Some(&map))
            .err()
            .expect("multi-value hosts entries may contain only IPs");
        assert!(err.to_string().contains("lists may contain only IP"));
    }

    // A value that is neither an IP nor a valid alias is a hard error.
    // Upstream: silently skips malformed IPs. NOT silent skip — Class A per ADR-0002.
    #[test]
    fn build_hosts_trie_malformed_ip_hard_error() {
        let mut map = HashMap::new();
        map.insert("bad.test".to_string(), one("not-an-ip"));
        let result = build_hosts_trie(Some(&map));
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
        let mut map = HashMap::new();
        map.insert("+.corp.example".to_string(), one("10.0.0.1"));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        assert!(trie.search("host.corp.example").is_some());
        assert!(trie.search("corp.example").is_some());
    }

    // *.foo is rewritten to +.foo at parse time.
    // Upstream: uses plain glob. NOT glob — we use +. semantics (consistent with nameserver-policy).
    #[test]
    fn build_hosts_trie_star_wildcard_rewritten() {
        let mut map = HashMap::new();
        map.insert("*.corp.internal".to_string(), one("10.0.0.50"));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        assert!(
            trie.search("foo.corp.internal").is_some(),
            "subdomain of *.corp.internal must match"
        );
        assert!(
            trie.search("corp.internal").is_some(),
            "root of *.corp.internal must match (+. includes root)"
        );
    }

    // Exact entry overrides wildcard for the same domain.
    // Upstream: dns/resolver.go::hostsTable. NOT wildcard value for exact-match domain.
    #[test]
    fn build_hosts_trie_exact_overrides_wildcard() {
        let exact_ip = "10.0.0.53";
        let wild_ip = "10.0.0.50";
        let mut map = HashMap::new();
        map.insert("*.corp.internal".to_string(), one(wild_ip));
        map.insert("dns.corp.internal".to_string(), one(exact_ip));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        let exact = trie.search("dns.corp.internal").expect("must hit exact");
        let exact_addr: IpAddr = exact_ip.parse().unwrap();
        assert_eq!(
            addresses(exact).first().copied(),
            Some(exact_addr),
            "exact entry must override wildcard"
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
        let mut map = HashMap::new();
        map.insert(
            "geosite:cn".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let result =
            build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new()).await;
        assert!(result.is_ok(), "geosite: prefix must not hard-error");
        let pol = result.unwrap();
        assert!(
            pol.lookup("anything.cn").is_none(),
            "skipped geosite entry must not match"
        );
    }

    #[tokio::test]
    async fn parse_nameserver_policy_geosite_prefix_matches_loaded_db() {
        use crate::raw::RawNspValue;
        let mut db = meow_rules::geosite::GeositeDB::empty();
        db.insert("cn", "example.cn");
        db.insert("private", "lan");
        let db = Arc::new(db);

        let mut map = HashMap::new();
        map.insert(
            "geosite:cn,private".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let pol = build_nameserver_policy(&map, Some(&db), &[], &HashMap::new(), &HashMap::new())
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
        let mut map = HashMap::new();
        // quic:// is explicitly rejected by the URL parser (QuicNotSupported error).
        map.insert(
            "corp.example".to_string(),
            RawNspValue::Many(vec!["quic://bad.example".to_string()]),
        );
        let result =
            build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new()).await;
        assert!(
            result.is_err(),
            "policy entry with no valid servers must be a hard error"
        );
    }

    // Wildcard policy entry matches subdomain and root.
    #[tokio::test]
    async fn parse_nameserver_policy_wildcard_inserted() {
        use crate::raw::RawNspValue;
        let mut map = HashMap::new();
        map.insert(
            "+.corp.internal".to_string(),
            RawNspValue::One("192.168.1.53".to_string()),
        );
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &HashMap::new())
            .await
            .unwrap();
        assert!(pol.lookup("foo.corp.internal").is_some());
        assert!(pol.lookup("corp.internal").is_some());
        assert!(pol.lookup("other.example").is_none());
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
                    payload: Some(payload.clone()),
                },
            );
        }
        let ctx = meow_rules::ParserContext::empty();
        crate::rule_provider::load_providers(&raw, None, &ctx, None)
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
        let mut map = HashMap::new();
        map.insert(
            "rule-set:cn".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers)
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
        let mut map = HashMap::new();
        map.insert(
            "rule-set:missing".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let result = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers).await;
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        assert!(msg.contains("not found rule-set"), "msg was: {msg}");
    }

    // rule-set: IpCidr behavior is rejected (expect domain/classical).
    #[tokio::test]
    async fn parse_nameserver_policy_rule_set_ipcidr_behavior_errors() {
        use crate::raw::RawNspValue;
        let providers = inline_rule_providers(&[("ips", "ipcidr", vec!["10.0.0.0/8".to_string()])]);
        let mut map = HashMap::new();
        map.insert(
            "rule-set:ips".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let result = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers).await;
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
        let mut map = HashMap::new();
        map.insert(
            "rule-set:cls".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers)
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
        let mut map = HashMap::new();
        map.insert(
            "rule-set:a,b".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers)
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
        let mut map = HashMap::new();
        map.insert(
            "rule-set:CN".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let pol = build_nameserver_policy(&map, None, &[], &HashMap::new(), &providers)
            .await
            .unwrap();
        assert!(pol.lookup("example.cn").is_some());
    }

    // Fallback-filter defaults when no raw config provided.
    #[test]
    fn build_fallback_filter_defaults() {
        let ff = build_fallback_filter(None, None);
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
        let ff = build_fallback_filter(Some(&raw), None);
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
        let ff = build_fallback_filter(Some(&raw), None);
        assert!(ff.domain_gated("www.google.cn"));
        assert!(ff.domain_gated("google.cn"));
        assert!(!ff.domain_gated("www.google.com"));
    }

    // normalize_hosts_wildcard converts *.foo → +.foo.
    #[test]
    fn normalize_wildcard_converts_star() {
        assert_eq!(normalize_hosts_wildcard("*.example.com"), "+.example.com");
        assert_eq!(normalize_hosts_wildcard("+.example.com"), "+.example.com");
        assert_eq!(normalize_hosts_wildcard("example.com"), "example.com");
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
        let resolvers = build_policy_resolvers("geosite:gfw", &value, &[], &registry)
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
        let resolvers = build_policy_resolvers("geosite:gfw", &value, &[], &registry)
            .await
            .expect("unknown proxy name must not fail the policy build");
        assert_eq!(resolvers.len(), 2);
        assert!(
            resolvers.iter().all(|r| !r.is_proxied()),
            "unknown names degrade to direct dials"
        );
    }

    #[tokio::test]
    async fn policy_resolver_tls_fragment_stays_sni() {
        // For tls:// the fragment is SNI, not a proxy name — must keep
        // parsing as before and never consult the registry.
        let registry: HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>> = HashMap::new();
        let value = crate::raw::RawNspValue::One("tls://8.8.4.4#dns.google".to_string());
        let resolvers = build_policy_resolvers("example.com", &value, &[], &registry)
            .await
            .expect("tls entry with SNI fragment builds");
        assert_eq!(resolvers.len(), 1);
        assert!(!resolvers[0].is_proxied());
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
