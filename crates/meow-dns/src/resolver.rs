use crate::cache::{DnsCache, DnsCacheSnapshotEntry, FamilyCacheHit, FamilyNeg, QueryFamilies};
use crate::client::{DnsClient, FamilyAnswer, FamilySet};
use crate::fakeip::{Pool, Skipper};
use crate::upstream::{HostOrIp, NameServerEntry, NameServerUrl};
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use ipnet::IpNet;
use meow_common::DnsMode;
use meow_trie::DomainTrie;
use smol_str::SmolStr;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A mihomo-compatible `hosts:` value.
///
/// A mapping may pin a host to one or more addresses, or redirect it to a
/// different domain. Domain redirects are followed before consulting the DNS
/// cache/upstreams, so they also apply to outbound proxy server resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEntry {
    Addresses(Vec<IpAddr>),
    Alias(SmolStr),
}

impl From<Vec<IpAddr>> for HostEntry {
    fn from(value: Vec<IpAddr>) -> Self {
        Self::Addresses(value)
    }
}

/// Error returned by `Resolver::new_with_bootstrap`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BootstrapError {
    #[error("default-nameserver entry '{entry}' must be a plain UDP/TCP nameserver (tls:// and https:// are not allowed here because they would create a bootstrap loop)")]
    DefaultNameserverNotPlain { entry: String },
    #[error("cannot resolve '{host}' via bootstrap nameserver: {source}")]
    CannotResolve { host: String, source: BoxError },
    #[error("failed to parse nameserver '{input}': {source}")]
    ParseError {
        input: String,
        source: crate::upstream::NameServerParseError,
    },
    #[error("nameserver '{nameserver}' references proxy '{proxy}', which is not defined")]
    UnknownProxy { nameserver: String, proxy: String },
    #[error(
        "nameserver '{nameserver}' uses proxy '{proxy}' on a tls:///https:// entry; \
        DoT/DoH routing through a proxy is not implemented yet — use plain udp:// or tcp:// \
        (issue #67 phase 2 follow-up)"
    )]
    EncryptedProxyUnsupported { nameserver: String, proxy: String },
}

/// Broadcast channel used to share a singleflight lookup result.
/// Capacity 1 is enough — subscribers call `recv()` at most once.
type InflightTx = tokio::sync::broadcast::Sender<Option<FamilySet>>;

/// Singleflight registry: one map per queried family set (keyed by
/// `Arc<str>` so lookups go through a borrowed `&str` via
/// `Arc<str>: Borrow<str>`).
///
/// Splitting by family set (review issue B: a concurrent A query
/// coalesces with other A queries, an AAAA query with other AAAA
/// queries, a genuinely different set starts its own flight) also
/// removes the old `(Arc<str>, QueryFamilies)` tuple key, which had no
/// `Borrow<(&str, QueryFamilies)>` implementation and forced an
/// `Arc::from(host)` allocation on *every* lookup — including the
/// subscriber fast path (review issue M1). With the split maps the
/// `Arc<str>` is only cloned once, when a new flight is inserted.
type InflightMap = DashMap<Arc<str>, InflightTx>;

/// Index of a family set inside [`Resolver::inflight`]. Callers must
/// ensure the set is non-empty; `run_pipeline` early-returns on
/// `QueryFamilies::NONE` (review N2), so the `unreachable!` below is a
/// defensive backstop, not a reachable branch.
fn inflight_slot(want: QueryFamilies) -> usize {
    if want == QueryFamilies::IPV4 {
        0
    } else if want == QueryFamilies::IPV6 {
        1
    } else if want == QueryFamilies::BOTH {
        2
    } else {
        unreachable!("singleflight requires a non-empty family set, got {want:?}")
    }
}

/// A single entry in `NameserverPolicy`: one or more pre-built upstream DNS
/// clients, one per configured nameserver URL.
#[derive(Clone)]
pub struct PolicyEntry {
    pub nameservers: Vec<Arc<DnsClient>>,
}

pub type NameserverPolicyMatcher = Arc<dyn Fn(&str) -> bool + Send + Sync + 'static>;

struct MatcherPolicyEntry {
    matcher: NameserverPolicyMatcher,
    entry: PolicyEntry,
}

/// Per-domain nameserver routing: exact matches and `+.` wildcard prefixes.
pub struct NameserverPolicy {
    exact: HashMap<String, PolicyEntry>,
    wildcard: DomainTrie<PolicyEntry>,
    matchers: Vec<MatcherPolicyEntry>,
}

impl Default for NameserverPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl NameserverPolicy {
    pub fn new() -> Self {
        Self {
            exact: HashMap::new(),
            wildcard: DomainTrie::new(),
            matchers: Vec::new(),
        }
    }

    pub fn insert_exact(&mut self, domain: String, entry: PolicyEntry) {
        self.exact.insert(domain, entry);
    }

    /// Insert a `+.` wildcard pattern. Also inserts an exact match for the root
    /// domain since `DomainTrie`'s `+.` semantics don't include the root itself.
    pub fn insert_wildcard(&mut self, pattern: &str, entry: PolicyEntry) {
        // Insert root domain explicitly: DomainTrie's +. doesn't match root.
        if let Some(bare) = pattern.strip_prefix("+.") {
            self.exact
                .entry(bare.to_string())
                .or_insert_with(|| entry.clone());
        }
        self.wildcard.insert(pattern, entry);
    }

    pub fn insert_matcher(&mut self, matcher: NameserverPolicyMatcher, entry: PolicyEntry) {
        self.matchers.push(MatcherPolicyEntry { matcher, entry });
    }

    pub fn lookup(&self, domain: &str) -> Option<&PolicyEntry> {
        if let Some(e) = self.exact.get(domain) {
            return Some(e);
        }
        if let Some(e) = self.wildcard.search(domain) {
            return Some(e);
        }
        self.matchers
            .iter()
            .find(|entry| (entry.matcher)(domain))
            .map(|entry| &entry.entry)
    }
}

/// Fallback-filter gates: controls when the fallback nameservers replace the
/// primary result.
pub struct FallbackFilter {
    pub geoip_enabled: bool,
    pub geoip_code: String,
    pub ipcidr: Vec<IpNet>,
    /// Domain patterns — match means skip primary entirely, go straight to fallback.
    pub domain: DomainTrie<()>,
    pub geoip_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl FallbackFilter {
    /// True if the domain pattern gate matches (primary should be skipped).
    pub fn domain_gated(&self, domain: &str) -> bool {
        self.domain.search(domain).is_some()
    }

    /// True if the resolved IPs should be discarded and fallback used.
    /// Does not re-check the domain gate (caller handles that separately).
    pub fn ip_gated(&self, addrs: &[IpAddr]) -> bool {
        for addr in addrs {
            if self.ipcidr.iter().any(|net| net.contains(addr)) {
                return true;
            }
        }
        if self.geoip_enabled {
            if let Some(reader) = &self.geoip_reader {
                for addr in addrs {
                    if let Some(record) = reader
                        .lookup(*addr)
                        .ok()
                        .and_then(|r| r.decode::<maxminddb::geoip2::Country>().ok())
                        .flatten()
                    {
                        let code = record.country.iso_code;
                        match code {
                            Some(c) if c == self.geoip_code.as_str() => {}
                            _ => return true,
                        }
                    }
                }
            }
        }
        false
    }
}

pub struct Resolver {
    main: Vec<Arc<DnsClient>>,
    fallback: Option<Vec<Arc<DnsClient>>>,
    cache: DnsCache,
    mode: DnsMode,
    hosts: DomainTrie<HostEntry>,
    use_hosts: bool,
    /// Singleflight registries, one per queried family set — see
    /// [`InflightMap`].
    inflight: [InflightMap; 3],
    policy: Option<NameserverPolicy>,
    fallback_filter: Option<FallbackFilter>,
    /// IPv4 fake-IP pool (None when fake-ip mode is disabled or only v6 is configured).
    fakeip_v4: Option<Arc<Pool>>,
    /// IPv6 fake-IP pool.
    fakeip_v6: Option<Arc<Pool>>,
    /// Optional bypass filter (BlackList by default). Hosts that match are
    /// resolved normally instead of being assigned a fake IP.
    fakeip_skipper: Option<Skipper>,
    /// TTL stamped on synthesised A/AAAA responses. Short by design so
    /// clients re-query rather than caching a fake IP after pool eviction.
    fakeip_ttl: Duration,
    /// Whether IPv6 resolution is enabled. Driven by the top-level `ipv6`
    /// config flag and fixed at construction time.
    ipv6: bool,
}

enum HostsLookup<'a> {
    Addresses(&'a Vec<IpAddr>),
    Alias(&'a str),
}

struct InflightGuard<'a> {
    map: &'a InflightMap,
    key: Arc<str>,
    _armed: (),
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.map.remove(self.key.as_ref());
    }
}

/// Default TTL stamped on synthesised fake-IP responses. Upstream Go mihomo
/// uses 1 s — same default here. Short TTL keeps clients honest after pool
/// wrap evictions.
pub const DEFAULT_FAKE_IP_TTL: Duration = Duration::from_secs(1);

/// TTL stamped on answers that have no upstream TTL to honor: hosts-trie
/// mappings. Matches the DNS server's pre-TTL-propagation default so hosts
/// answers behave exactly as before.
pub const HOSTS_ANSWER_TTL: Duration = Duration::from_secs(60);

fn clamp_ttl(raw: Duration) -> Duration {
    const MIN_TTL: Duration = Duration::from_secs(10);
    const MAX_TTL: Duration = Duration::from_secs(3600);
    raw.clamp(MIN_TTL, MAX_TTL)
}

fn host_or_ip_to_addr(addr: &HostOrIp, resolved: &HashMap<String, IpAddr>) -> IpAddr {
    match addr {
        HostOrIp::Ip(ip) => *ip,
        HostOrIp::Host(h) => *resolved
            .get(h)
            .expect("bootstrap must resolve all hostnames"),
    }
}

fn url_to_plain_socketaddr(url: &NameServerUrl) -> SocketAddr {
    match url {
        NameServerUrl::Udp { addr, port } | NameServerUrl::Tcp { addr, port } => {
            let ip = match addr {
                HostOrIp::Ip(ip) => *ip,
                HostOrIp::Host(_) => {
                    unreachable!("default_ns hostname entries should have been rejected")
                }
            };
            SocketAddr::new(ip, *port)
        }
        NameServerUrl::Tls { addr, .. } | NameServerUrl::Https { addr, .. } => {
            let ip = match addr {
                HostOrIp::Ip(ip) => *ip,
                HostOrIp::Host(_) => {
                    unreachable!("default_ns hostname entries should have been rejected")
                }
            };
            SocketAddr::new(ip, 53)
        }
        NameServerUrl::RCode { .. } => {
            unreachable!("rcode default-nameserver does not have a socket address")
        }
    }
}

/// Read the platform's configured recursive resolvers, used as bootstrap
/// nameservers when `default-nameserver` is absent but an encrypted upstream
/// (DoH/DoT) carries a hostname that must be resolved first.
///
/// Unix: parse `/etc/resolv.conf` `nameserver` lines (port 53, UDP). Other
/// platforms — or a missing / unreadable resolv.conf yielding no addresses —
/// fall back to well-known public resolvers so bootstrap still succeeds in an
/// unconfigured environment. This mirrors mihomo's behaviour and the helper of
/// the same name in `meow-config::ech_dns`; the logic is duplicated rather than
/// shared because `meow-config` depends on `meow-dns`, not the reverse.
async fn system_nameservers() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        if let Ok(contents) = tokio::fs::read_to_string("/etc/resolv.conf").await {
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                    continue;
                }
                let Some(rest) = line.strip_prefix("nameserver") else {
                    continue;
                };
                let token = rest.split_whitespace().next().unwrap_or("");
                // Strip an optional IPv6 zone identifier (`fe80::1%en0`):
                // `IpAddr::from_str` rejects the `%zone` suffix.
                let addr_str = token.split('%').next().unwrap_or(token);
                if let Ok(ip) = addr_str.parse::<IpAddr>() {
                    out.push(SocketAddr::new(ip, 53));
                }
            }
        }
    }
    if out.is_empty() {
        // Fallback: well-known public resolvers.
        out.push(SocketAddr::from(([1, 1, 1, 1], 53)));
        out.push(SocketAddr::from(([8, 8, 8, 8], 53)));
    }
    out
}

#[derive(Clone, Debug)]
pub(crate) enum AddressLookupResult {
    Answer(IpAddr, Duration),
    NoData,
    NxDomain,
    Failed,
}

impl FamilySet {
    /// True when at least one queried family has a non-empty answer — the
    /// signal that a pool/tier result is a positive resolution.
    fn has_positive(&self) -> bool {
        self.v4
            .as_ref()
            .is_some_and(|a| matches!(a, FamilyAnswer::Answer { ips, .. } if !ips.is_empty()))
            || self
                .v6
                .as_ref()
                .is_some_and(|a| matches!(a, FamilyAnswer::Answer { ips, .. } if !ips.is_empty()))
    }

    /// Every IP carried by a positive (`Answer`) family — used by the
    /// fallback-filter's `ip_gated` check and by the bootstrap path.
    fn positive_ips(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for ans in [&self.v4, &self.v6].into_iter().flatten() {
            if let FamilyAnswer::Answer { ips, .. } = ans {
                out.extend_from_slice(ips);
            }
        }
        out
    }

    /// A definitive negative **for the requested family set `want`**: no
    /// positive answer, and every requested family has a real `NoData`/`NxDomain`
    /// answer (not `None` — "never queried" — and not `Failed`). A `None`
    /// family means the client never got that far (e.g. the prefer-IPv4 path
    /// skipped AAAA after A failed, or AAAA itself errored), so the set is
    /// *not* a definitive answer for a `BOTH` query and must not short-circuit
    /// the race — another client may still supply the missing family. This is
    /// what `query_pool_set` uses to return on the first definitive negative
    /// instead of draining a dead upstream's full timeout (review issue C).
    fn is_definitive_negative(&self, want: QueryFamilies) -> bool {
        if want.is_empty() {
            return false;
        }
        let family_ok = |ans: &Option<FamilyAnswer>| {
            matches!(
                ans,
                Some(FamilyAnswer::NoData(_)) | Some(FamilyAnswer::NxDomain(_))
            )
        };
        let v4_ok = !want.contains(QueryFamilies::IPV4) || family_ok(&self.v4);
        let v6_ok = !want.contains(QueryFamilies::IPV6) || family_ok(&self.v6);
        // No positive (an `Answer` is always non-empty by construction) and
        // every requested family answered definitively.
        !self.has_positive() && v4_ok && v6_ok
    }

    /// Clamp every carried TTL into the cache's `[MIN, MAX]` window. The client
    /// returns raw upstream TTLs; the resolver owns the clamp policy so it is
    /// applied exactly once, both for the answer and the cache write.
    fn clamped(mut self) -> Self {
        for ans in [&mut self.v4, &mut self.v6].into_iter().flatten() {
            match ans {
                FamilyAnswer::Answer { ttl, .. }
                | FamilyAnswer::NoData(ttl)
                | FamilyAnswer::NxDomain(ttl) => {
                    *ttl = clamp_ttl(*ttl);
                }
                _ => {}
            }
        }
        self
    }
}

/// Grace period after receiving the first definitive negative from one
/// upstream in a tier before committing to it. A slower upstream may still
/// deliver a positive answer (split-horizon DNS, mixed upstream quality), so
/// we race the remaining futures briefly rather than cancelling them
/// immediately. The period is short enough that a truly dead upstream (5 s
/// client timeout) does not stall the lookup — the definitive-negative test
/// still completes well under 1 s.
///
/// The grace period is counted **per tier**: a lookup that runs the full
/// policy → main → fallback chain and receives a fast negative in every tier
/// accrues up to ~3× this period (≈900 ms) of extra latency before the
/// negative is returned.
const NEGATIVE_GRACE_PERIOD: Duration = Duration::from_millis(300);

/// Query a pool of clients in parallel for the requested family set `want`,
/// returning the first positive resolution or, after a short grace period, the
/// first definitive negative (review issue C: a fast NODATA/NXDOMAIN from a
/// healthy upstream no longer waits out a dead upstream's full 5 s timeout).
/// `Err` (network failure) is not definitive — keep racing the remaining
/// clients. The grace period prevents a fast negative from suppressing a slow
/// positive in split-horizon / multi-upstream configurations.
async fn query_pool_set(
    clients: &[Arc<DnsClient>],
    host: &str,
    want: QueryFamilies,
    ipv6_enabled: bool,
) -> Option<FamilySet> {
    if clients.is_empty() {
        return None;
    }
    let mut pending = FuturesUnordered::new();
    for client in clients {
        pending.push(async move {
            let result = client.lookup_set(host, want, ipv6_enabled).await;
            (client, result)
        });
    }
    let mut negative: Option<FamilySet> = None;
    let mut negative_deadline: Option<tokio::time::Instant> = None;
    loop {
        // Once we have a definitive negative, wait for the remaining futures
        // with a bounded grace period instead of blocking indefinitely on a
        // dead upstream.
        let next = if let Some(deadline) = negative_deadline {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return negative;
            }
            match tokio::time::timeout_at(deadline, pending.next()).await {
                Ok(result) => result,
                Err(_) => return negative, // grace period elapsed
            }
        } else {
            pending.next().await
        };
        let Some((client, result)) = next else {
            break;
        };
        let set = match result {
            Ok(set) => set.clamped(),
            Err(error) => {
                // Upstream failures are otherwise invisible: the pool
                // returns `None` and the caller reports "no address" with
                // no hint of which server failed or why.
                debug!(
                    host,
                    upstream = %client.upstream_label(),
                    %error,
                    "DNS upstream query failed"
                );
                continue;
            }
        };
        if set.has_positive() {
            // A positive answer always wins, regardless of grace state.
            return Some(set);
        }
        let definitive = set.is_definitive_negative(want);
        if negative.is_none() {
            // First negative — definitive or partial. Don't return yet: a
            // slower upstream in this tier may still deliver a positive
            // answer. Start the grace timer for *either* kind so we don't
            // stall on a dead upstream (review issue C + M2: a partial
            // failure used to leave the timer unset, and a later
            // definitive negative could then never enter this branch —
            // the tier would wait out every upstream's full timeout).
            negative = Some(set);
            negative_deadline = Some(tokio::time::Instant::now() + NEGATIVE_GRACE_PERIOD);
        } else if definitive
            && !negative
                .as_ref()
                .is_some_and(|kept| kept.is_definitive_negative(want))
        {
            // A definitive negative strictly improves on a partial failure
            // kept as the last-resort answer. First-wins still applies
            // between two answers of equal quality.
            negative = Some(set);
        }
    }
    negative
}

fn encrypted_upstream_label(url: &NameServerUrl) -> Option<String> {
    match url {
        NameServerUrl::Tls { addr, port, sni } => {
            let mut label = format!("tls://{}", authority_label(addr, *port, 853));
            if sni != &addr.to_string() {
                label.push('#');
                label.push_str(sni);
            }
            Some(label)
        }
        NameServerUrl::Https {
            addr,
            port,
            path,
            sni,
        } => {
            let mut label = format!("https://{}{}", authority_label(addr, *port, 443), path);
            if sni != &addr.to_string() {
                label.push('#');
                label.push_str(sni);
            }
            Some(label)
        }
        _ => None,
    }
}

fn authority_label(addr: &HostOrIp, port: u16, default_port: u16) -> String {
    let host = match addr {
        HostOrIp::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
        _ => addr.to_string(),
    };
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// Typed-record counterpart of `query_pool_set`: queries a client pool for an
/// arbitrary `RecordType` (TXT, MX, SRV, HTTPS, …) and returns the first
/// successful `Message`. Caller copies the answer section into its response.
async fn query_pool_generic(
    clients: &[Arc<DnsClient>],
    host: &str,
    record_type: RecordType,
) -> Option<Message> {
    match clients.len() {
        0 => None,
        1 => clients[0].query(host, record_type).await.ok(),
        2 => {
            let f1 = clients[0].query(host, record_type);
            let f2 = clients[1].query(host, record_type);
            tokio::pin!(f1);
            tokio::pin!(f2);
            tokio::select! {
                r = &mut f1 => r.ok().or((&mut f2).await.ok()),
                r = &mut f2 => r.ok().or((&mut f1).await.ok()),
            }
        }
        _ => {
            let futs: Vec<_> = clients
                .iter()
                .map(|c| Box::pin(async move { c.query(host, record_type).await.map_err(|_| ()) }))
                .collect();
            futures::future::select_ok(futs).await.ok().map(|(m, _)| m)
        }
    }
}

impl Resolver {
    /// Follow a mihomo-style hosts alias chain. Config parsing rejects cycles;
    /// the depth guard is a defensive backstop for programmatically-built
    /// tries passed to the public constructors.
    fn lookup_hosts_entry<'a>(&'a self, host: &str) -> Option<HostsLookup<'a>> {
        let mut current = host;
        let mut terminal_alias = None;
        for _ in 0..64 {
            match self.hosts.search(current) {
                Some(HostEntry::Addresses(ips)) => return Some(HostsLookup::Addresses(ips)),
                Some(HostEntry::Alias(alias)) => {
                    terminal_alias = Some(alias.as_str());
                    current = alias.as_str();
                }
                None => return terminal_alias.map(HostsLookup::Alias),
            }
        }
        tracing::error!(host, "hosts alias chain exceeded 64 entries");
        None
    }

    #[allow(clippy::needless_pass_by_value)] // Vec<SocketAddr> is conventional for public constructors
    pub fn new(
        main_servers: Vec<SocketAddr>,
        fallback_servers: Vec<SocketAddr>,
        mode: DnsMode,
        hosts: DomainTrie<HostEntry>,
        use_hosts: bool,
        ipv6: bool,
    ) -> Self {
        let main = Self::build_clients(&main_servers);
        let fallback = if fallback_servers.is_empty() {
            None
        } else {
            Some(Self::build_clients(&fallback_servers))
        };
        Self {
            main,
            fallback,
            cache: DnsCache::new(4096),
            mode,
            hosts,
            use_hosts,
            inflight: [DashMap::new(), DashMap::new(), DashMap::new()],
            policy: None,
            fallback_filter: None,
            fakeip_v4: None,
            fakeip_v6: None,
            fakeip_skipper: None,
            fakeip_ttl: DEFAULT_FAKE_IP_TTL,
            ipv6,
        }
    }

    /// Build one UDP `DnsClient` per address. Used by the simple `new()`
    /// constructor and tests.
    fn build_clients(servers: &[SocketAddr]) -> Vec<Arc<DnsClient>> {
        servers
            .iter()
            .map(|addr| Arc::new(DnsClient::udp(*addr)))
            .collect()
    }

    /// Build a `Resolver` from `NameServerUrl` lists with no `#PROXY`
    /// support. Equivalent to
    /// [`Resolver::new_with_bootstrap_with_proxies`] with an empty
    /// registry; convenient for tests and call sites that don't need
    /// proxy-routed DNS.
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_bootstrap(
        main_urls: Vec<NameServerUrl>,
        fallback_urls: Vec<NameServerUrl>,
        default_ns: Vec<NameServerUrl>,
        mode: DnsMode,
        hosts: DomainTrie<HostEntry>,
        use_hosts: bool,
        ipv6: bool,
        policy: Option<NameserverPolicy>,
        fallback_filter: Option<FallbackFilter>,
    ) -> Result<Self, BootstrapError> {
        Self::new_with_bootstrap_with_proxies(
            main_urls.into_iter().map(Into::into).collect(),
            fallback_urls.into_iter().map(Into::into).collect(),
            default_ns.into_iter().map(Into::into).collect(),
            mode,
            hosts,
            use_hosts,
            ipv6,
            policy,
            fallback_filter,
            &HashMap::new(),
        )
        .await
    }

    /// Build a `Resolver` from structured nameserver entries, running a
    /// bootstrap DNS lookup for any encrypted upstream that uses a
    /// hostname.
    ///
    /// `proxy_registry` resolves any `#PROXY` references on plain
    /// (`udp://`/`tcp://`) entries (issue #67 phase 2). Pass an empty map
    /// when proxies aren't yet built — entries that reference proxies
    /// will then be rejected with `BootstrapError::UnknownProxy`.
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_bootstrap_with_proxies(
        main_urls: Vec<NameServerEntry>,
        fallback_urls: Vec<NameServerEntry>,
        default_ns: Vec<NameServerEntry>,
        mode: DnsMode,
        hosts: DomainTrie<HostEntry>,
        use_hosts: bool,
        ipv6: bool,
        policy: Option<NameserverPolicy>,
        fallback_filter: Option<FallbackFilter>,
        proxy_registry: &HashMap<SmolStr, Arc<dyn meow_common::Proxy>>,
    ) -> Result<Self, BootstrapError> {
        // ── Validate proxy references up front so misconfig fails loud.
        // `default_ns` entries are forbidden from carrying #PROXY — they
        // are the bootstrap path that resolves the proxy server's own
        // hostname, so routing them through a proxy would create the
        // chicken-and-egg loop ADR-0012 warns about.
        for entry in &default_ns {
            if let Some(p) = entry.proxy.as_ref() {
                return Err(BootstrapError::UnknownProxy {
                    nameserver: entry.url.to_string(),
                    proxy: format!("{p} (default-nameserver may not use #PROXY)"),
                });
            }
        }
        for entry in main_urls.iter().chain(fallback_urls.iter()) {
            let Some(p) = entry.proxy.as_ref() else {
                continue;
            };
            if matches!(
                entry.url,
                NameServerUrl::Tls { .. } | NameServerUrl::Https { .. }
            ) {
                return Err(BootstrapError::EncryptedProxyUnsupported {
                    nameserver: entry.url.to_string(),
                    proxy: p.clone(),
                });
            }
            if !proxy_registry.contains_key(p.as_str()) {
                return Err(BootstrapError::UnknownProxy {
                    nameserver: entry.url.to_string(),
                    proxy: p.clone(),
                });
            }
        }

        // Split out the bare URLs (for the existing match-arm helpers
        // below) and a parallel proxy-handle vector (Some when the entry
        // carried a validated #PROXY tag).
        let resolve_proxy =
            |entries: &[NameServerEntry]| -> Vec<Option<Arc<dyn meow_common::Proxy>>> {
                entries
                    .iter()
                    .map(|e| {
                        e.proxy
                            .as_ref()
                            .and_then(|p| proxy_registry.get(p.as_str()).cloned())
                    })
                    .collect()
            };
        let main_proxies = resolve_proxy(&main_urls);
        let fallback_proxies = resolve_proxy(&fallback_urls);
        let main_urls: Vec<NameServerUrl> = main_urls.into_iter().map(|e| e.url).collect();
        let fallback_urls: Vec<NameServerUrl> = fallback_urls.into_iter().map(|e| e.url).collect();
        let default_ns: Vec<NameServerUrl> = default_ns.into_iter().map(|e| e.url).collect();
        // Step 1: default nameservers are themselves the bootstrap roots, so
        // every entry must use an IP literal regardless of transport.
        for ns in &default_ns {
            if ns.needs_bootstrap().is_some() {
                return Err(BootstrapError::DefaultNameserverNotPlain {
                    entry: ns.to_string(),
                });
            }
        }

        // Step 2: Collect all URLs that need bootstrap (main + fallback only).
        // Policy resolvers are pre-built by the caller with IP literals.
        let mut hostnames_needing_bootstrap: BTreeSet<String> = BTreeSet::new();
        let mut first_encrypted_with_hostname: Option<String> = None;
        for url in main_urls.iter().chain(fallback_urls.iter()) {
            if let Some(host) = url.needs_bootstrap() {
                if first_encrypted_with_hostname.is_none()
                    && matches!(url, NameServerUrl::Tls { .. } | NameServerUrl::Https { .. })
                {
                    first_encrypted_with_hostname = Some(url.to_string());
                }
                hostnames_needing_bootstrap.insert(host.to_string());
            }
        }

        // Step 3: Short-circuit if no bootstrap needed.
        let resolved_map: HashMap<String, IpAddr> = if hostnames_needing_bootstrap.is_empty() {
            HashMap::new()
        } else {
            // Step 4: Build throwaway bootstrap clients. When `default-nameserver`
            // is configured, use it. When absent, fall back to the system
            // resolvers (mihomo reads /etc/resolv.conf here rather than erroring).
            let bootstrap_clients: Vec<Arc<DnsClient>> = if default_ns.is_empty() {
                let system = system_nameservers().await;
                tracing::warn!(
                    "default-nameserver not configured; bootstrapping '{}' via system DNS ({} server(s) from /etc/resolv.conf or hardcoded fallback)",
                    first_encrypted_with_hostname.as_deref().unwrap_or("?"),
                    system.len(),
                );
                system
                    .into_iter()
                    .map(|addr| Arc::new(DnsClient::udp(addr).with_timeout(Duration::from_secs(3))))
                    .collect()
            } else {
                default_ns
                    .iter()
                    .map(|ns| {
                        let c = match ns {
                            NameServerUrl::RCode { code, .. } => DnsClient::rcode(*code),
                            NameServerUrl::Tcp { .. } => {
                                DnsClient::tcp(url_to_plain_socketaddr(ns))
                            }
                            _ => DnsClient::udp(url_to_plain_socketaddr(ns)),
                        };
                        Arc::new(c.with_timeout(Duration::from_secs(3)))
                    })
                    .collect()
            };

            // Resolve sequentially — fail-fast on first failure. Bootstrap
            // is deliberately dual-stack and **ignores the `ipv6`
            // preference** (the `true` below is not a placeholder): a
            // hostname-based encrypted upstream must be reachable at boot
            // even when its name only has an AAAA record, so filtering
            // v6 answers here by the user's `ipv6: false` would make such
            // upstreams unbootstrappable. The `ipv6` flag governs
            // resolution for proxied/direct traffic, not DNS
            // infrastructure connectivity.
            let mut map = HashMap::new();
            for host in &hostnames_needing_bootstrap {
                match query_pool_set(&bootstrap_clients, host, QueryFamilies::BOTH, true).await {
                    Some(set) => {
                        let ips = set.positive_ips();
                        if let Some(first) = ips.first() {
                            map.insert(host.clone(), *first);
                        } else {
                            return Err(BootstrapError::CannotResolve {
                                host: host.clone(),
                                source: "no addresses returned".into(),
                            });
                        }
                    }
                    None => {
                        return Err(BootstrapError::CannotResolve {
                            host: host.clone(),
                            source: "no addresses returned".into(),
                        });
                    }
                }
            }
            map
        };

        // Steps 5 & 6: Build main + fallback — one resolver per URL for parallel dispatch.
        let main: Vec<Arc<DnsClient>> = main_urls
            .iter()
            .zip(main_proxies)
            .map(|(url, proxy)| Self::build_single_resolver_with_proxy(url, &resolved_map, proxy))
            .collect();
        let fallback = if fallback_urls.is_empty() {
            None
        } else {
            Some(
                fallback_urls
                    .iter()
                    .zip(fallback_proxies)
                    .map(|(url, proxy)| {
                        Self::build_single_resolver_with_proxy(url, &resolved_map, proxy)
                    })
                    .collect(),
            )
        };

        Ok(Self {
            main,
            fallback,
            cache: DnsCache::new(4096),
            mode,
            hosts,
            use_hosts,
            inflight: [DashMap::new(), DashMap::new(), DashMap::new()],
            policy,
            fallback_filter,
            fakeip_v4: None,
            fakeip_v6: None,
            fakeip_skipper: None,
            fakeip_ttl: DEFAULT_FAKE_IP_TTL,
            ipv6,
        })
    }

    pub(crate) fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }

    /// Build a single `DnsClient` for one `NameServerUrl`, using `resolved`
    /// to substitute hostnames that needed bootstrap. Pass an empty map for
    /// IP-literal URLs (no hostname substitution needed).
    pub fn build_single_resolver(
        url: &NameServerUrl,
        resolved: &HashMap<String, IpAddr>,
    ) -> Arc<DnsClient> {
        Self::build_single_resolver_with_proxy(url, resolved, None)
    }

    /// Like [`Resolver::build_single_resolver`] but also attaches an optional
    /// proxy adapter so queries route via `proxy.dial_tcp` (issue #67
    /// phase 2). Pass `None` to get the unrouted client.
    pub fn build_single_resolver_with_proxy(
        url: &NameServerUrl,
        resolved: &HashMap<String, IpAddr>,
        proxy: Option<Arc<dyn meow_common::Proxy>>,
    ) -> Arc<DnsClient> {
        let socket_addr = match url {
            NameServerUrl::Udp { addr, port }
            | NameServerUrl::Tcp { addr, port }
            | NameServerUrl::Tls { addr, port, .. }
            | NameServerUrl::Https { addr, port, .. } => {
                SocketAddr::new(host_or_ip_to_addr(addr, resolved), *port)
            }
            NameServerUrl::RCode { code, .. } => {
                let client = DnsClient::rcode(*code);
                let client = match proxy {
                    Some(p) => client.with_proxy(p),
                    None => client,
                };
                return Arc::new(client);
            }
        };
        let label = encrypted_upstream_label(url);
        let client = match url {
            NameServerUrl::Udp { .. } => DnsClient::udp(socket_addr),
            NameServerUrl::Tcp { .. } => DnsClient::tcp(socket_addr),
            NameServerUrl::Tls { sni, .. } => {
                #[cfg(feature = "encrypted")]
                {
                    DnsClient::dot(socket_addr, sni)
                }
                #[cfg(not(feature = "encrypted"))]
                {
                    let _ = sni;
                    panic!(
                        "nameserver uses scheme 'tls' which requires the 'encrypted' \
                        Cargo feature; rebuild with --features encrypted"
                    )
                }
            }
            NameServerUrl::Https { sni, path, .. } => {
                #[cfg(feature = "encrypted")]
                {
                    DnsClient::doh(socket_addr, sni, path)
                }
                #[cfg(not(feature = "encrypted"))]
                {
                    let _ = (sni, path);
                    panic!(
                        "nameserver uses scheme 'https' which requires the 'encrypted' \
                        Cargo feature; rebuild with --features encrypted"
                    )
                }
            }
            NameServerUrl::RCode { .. } => {
                unreachable!("rcode nameservers return before socket client construction")
            }
        };
        let client = match label {
            Some(label) => client.with_upstream_label(label),
            None => client,
        };
        let client = match proxy {
            Some(p) => client.with_proxy(p),
            None => client,
        };
        Arc::new(client)
    }

    pub async fn resolve_ips(&self, host: &str) -> Option<Vec<IpAddr>> {
        let lookup_host = if self.use_hosts {
            match self.lookup_hosts_entry(host) {
                Some(HostsLookup::Addresses(ips)) => {
                    // Review issue E: a hosts entry that has no *enabled* IPs
                    // (e.g. v6-only under `ipv6: false`) must NOT short-circuit
                    // to `None` — fall through to upstream so DirectAdapter can
                    // still reach a host that the hosts file only pins for the
                    // other family.
                    if let Some(enabled) = self.filter_enabled_ips(ips) {
                        return Some(enabled);
                    }
                    host
                }
                Some(HostsLookup::Alias(alias)) => alias,
                None => host,
            }
        } else {
            host
        };
        let required = if self.ipv6 {
            QueryFamilies::BOTH
        } else {
            QueryFamilies::IPV4
        };
        // Only query the families the cache cannot already answer. Fresh
        // families (Answer or NoData) are dropped from the query set so a
        // short-TTL AAAA re-query doesn't redundantly re-fetch a still-fresh A.
        //
        // We must NOT short-circuit when *some* enabled IPs are cached but a
        // required family is still `Miss` — doing so would starve
        // `DirectAdapter` of the missing family's addresses and remove its
        // connection-fallback capability (e.g. A cached, AAAA not yet queried
        // → only IPv4 returned → IPv6 fallback lost).
        let mut want = required;
        if let Some(cached) = self.cache.get_lookup(lookup_host) {
            if cached.v4.is_fresh() && required.contains(QueryFamilies::IPV4) {
                want = want.minus(QueryFamilies::IPV4);
            }
            if cached.v6.is_fresh() && required.contains(QueryFamilies::IPV6) {
                want = want.minus(QueryFamilies::IPV6);
            }
        }
        let pipeline_set = if want.is_empty() {
            None
        } else {
            self.run_pipeline(lookup_host, want).await
        };
        // Prefer the pipeline's own result over re-reading the shared
        // cache: the entry can be LRU-evicted (1024 forward entries under
        // load) between the merge and a re-read, which would turn a
        // just-successful lookup into "host unresolvable" (review H3).
        // A full-set, definitive result covers every required family, so
        // it is returned directly; anything less definitive (a subset
        // result — some family was already fresh in the cache — or a
        // partial failure) is combined with the cache below.
        if let Some(set) = &pipeline_set {
            if want == required {
                if let Some(enabled) = self.filter_enabled_ips(&set.positive_ips()) {
                    return Some(enabled);
                }
                if set.is_definitive_negative(want) {
                    // Every required family answered definitively (no
                    // usable addresses) — the name is genuinely
                    // unresolvable.
                    return None;
                }
            }
        }
        // Re-read the cache to merge the families that were already fresh
        // (not re-queried) with the freshly queried ones.
        if let Some(cached) = self.cache.get_lookup(lookup_host) {
            if let Some(enabled) = self.filter_enabled_ips(&cached.ips) {
                return Some(enabled);
            }
            // No usable IPs. If every required family is now fresh (cached or
            // just queried), the name is genuinely unresolvable — return `None`
            // rather than looping or masking the negative as a transient fail.
            let all_required_fresh = (!required.contains(QueryFamilies::IPV4)
                || cached.v4.is_fresh())
                && (!required.contains(QueryFamilies::IPV6) || cached.v6.is_fresh());
            if all_required_fresh {
                return None;
            }
        }
        // The cache re-read missed (e.g. the entry was evicted between the
        // merge and the read). If the pipeline still produced addresses for
        // the families it queried, hand those back rather than reporting the
        // host unresolvable.
        if let Some(set) = &pipeline_set {
            if let Some(enabled) = self.filter_enabled_ips(&set.positive_ips()) {
                return Some(enabled);
            }
        }
        None
    }

    /// [`Self::resolve_ips`] restricted to answers this resolver already
    /// holds — the `hosts:` trie and the DNS cache. Never queries an
    /// upstream, so it can never dial a proxy.
    ///
    /// This is the answer offered when the host-resolver hook is re-entered
    /// (a `#PROXY` nameserver dialing the very proxy whose server hostname
    /// is being looked up). Going upstream there would re-enter the resolver
    /// and stall on its own single-flight entry; returning what is already
    /// known keeps `hosts:` mappings and warm cache entries authoritative
    /// for proxy-server hostnames even on that path.
    pub fn resolve_ips_local(&self, host: &str) -> Option<Vec<IpAddr>> {
        let lookup_host = if self.use_hosts {
            match self.lookup_hosts_entry(host) {
                Some(HostsLookup::Addresses(ips)) => {
                    if let Some(enabled) = self.filter_enabled_ips(ips) {
                        return Some(enabled);
                    }
                    host
                }
                Some(HostsLookup::Alias(alias)) => alias,
                None => host,
            }
        } else {
            host
        };
        if let Some(cached) = self.cache.get_lookup(lookup_host) {
            return self.filter_enabled_ips(&cached.ips);
        }
        None
    }

    pub async fn resolve_ip(&self, host: &str) -> Option<IpAddr> {
        self.resolve_ips(host).await?.into_iter().next()
    }

    pub async fn resolve_ip_real(&self, host: &str) -> Option<IpAddr> {
        self.resolve_ip(host).await
    }

    pub async fn lookup_ipv4(&self, host: &str) -> Option<IpAddr> {
        self.lookup_ipv4_with_ttl(host).await.map(|(ip, _)| ip)
    }

    /// Like [`Self::lookup_ipv4`], but also returns the TTL the answer should
    /// carry: the fake-IP TTL for synthesised addresses, the entry's remaining
    /// lifetime for cache hits, and the upstream's (clamped) TTL for fresh
    /// lookups. Hosts-trie hits get [`HOSTS_ANSWER_TTL`] — static mappings
    /// have no upstream TTL to honor.
    pub async fn lookup_ipv4_with_ttl(&self, host: &str) -> Option<(IpAddr, Duration)> {
        match self.lookup_ipv4_result(host).await {
            AddressLookupResult::Answer(ip, ttl) => Some((ip, ttl)),
            AddressLookupResult::NoData
            | AddressLookupResult::NxDomain
            | AddressLookupResult::Failed => None,
        }
    }

    pub(crate) async fn lookup_ipv4_result(&self, host: &str) -> AddressLookupResult {
        if self.use_hosts {
            match self.lookup_hosts_entry(host) {
                Some(HostsLookup::Addresses(ips)) => {
                    return ips
                        .iter()
                        .find(|ip| ip.is_ipv4())
                        .copied()
                        .map_or(AddressLookupResult::NoData, |ip| {
                            AddressLookupResult::Answer(ip, HOSTS_ANSWER_TTL)
                        });
                }
                Some(HostsLookup::Alias(alias)) => {
                    return self.lookup_real_with_ttl(alias, RecordType::A).await;
                }
                None => {}
            }
        }
        // Fake-IP mode: synthesise from the v4 pool unless the skipper says
        // bypass. The hosts trie above still wins — explicit user mappings
        // never get rewritten to a fake address.
        if self.mode == DnsMode::FakeIp {
            if let Some(pool) = &self.fakeip_v4 {
                if !self.skipper_bypasses(host) {
                    return AddressLookupResult::Answer(pool.lookup(host), self.fakeip_ttl);
                }
            }
        }
        self.lookup_real_with_ttl(host, RecordType::A).await
    }

    pub async fn lookup_ipv6(&self, host: &str) -> Option<IpAddr> {
        self.lookup_ipv6_with_ttl(host).await.map(|(ip, _)| ip)
    }

    /// AAAA counterpart of [`Self::lookup_ipv4_with_ttl`] — same TTL contract.
    pub async fn lookup_ipv6_with_ttl(&self, host: &str) -> Option<(IpAddr, Duration)> {
        match self.lookup_ipv6_result(host).await {
            AddressLookupResult::Answer(ip, ttl) => Some((ip, ttl)),
            AddressLookupResult::NoData
            | AddressLookupResult::NxDomain
            | AddressLookupResult::Failed => None,
        }
    }

    pub(crate) async fn lookup_ipv6_result(&self, host: &str) -> AddressLookupResult {
        if !self.ipv6 {
            return AddressLookupResult::NoData;
        }
        if self.use_hosts {
            match self.lookup_hosts_entry(host) {
                Some(HostsLookup::Addresses(ips)) => {
                    return ips
                        .iter()
                        .find(|ip| ip.is_ipv6())
                        .copied()
                        .map_or(AddressLookupResult::NoData, |ip| {
                            AddressLookupResult::Answer(ip, HOSTS_ANSWER_TTL)
                        });
                }
                Some(HostsLookup::Alias(alias)) => {
                    return self.lookup_real_with_ttl(alias, RecordType::AAAA).await;
                }
                None => {}
            }
        }
        // Fake-IP mode for AAAA: synthesise from the v6 pool if configured.
        // If only a v4 pool is configured (the common case — upstream
        // default is `198.18.0.1/16` only), report NODATA so the server emits
        // a NOERROR with zero answers and clients fall back to IPv4.
        if self.mode == DnsMode::FakeIp {
            if let Some(pool) = &self.fakeip_v6 {
                if !self.skipper_bypasses(host) {
                    return AddressLookupResult::Answer(pool.lookup(host), self.fakeip_ttl);
                }
            } else if self.fakeip_v4.is_some() && !self.skipper_bypasses(host) {
                // v4-only fake-ip config: suppress AAAA so clients fall back.
                return AddressLookupResult::NoData;
            }
        }
        self.lookup_real_with_ttl(host, RecordType::AAAA).await
    }

    /// Cache-then-upstream address lookup carrying the answer TTL. A cache hit
    /// for the queried family reports that family's own remaining lifetime
    /// (per-family expiry — review issue D); a cache miss re-queries just that
    /// family through the unified single-flight pipeline and returns the
    /// upstream's clamped TTL. NXDOMAIN is cached per RFC 2308 (aligns with
    /// mihomo `putMsgToCache`), so a cached NXDOMAIN is re-served with its real
    /// rcode instead of collapsing to NODATA — damping DGA/retry-loop load.
    async fn lookup_real_with_ttl(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> AddressLookupResult {
        let family = QueryFamilies::from_record_type(record_type);
        if family.is_empty() {
            return AddressLookupResult::Failed;
        }
        if let Some(cached) = self.cache.get_lookup(host) {
            let hit = if family == QueryFamilies::IPV4 {
                &cached.v4
            } else {
                &cached.v6
            };
            match hit {
                FamilyCacheHit::Answer(ips, ttl) => {
                    return AddressLookupResult::Answer(ips[0], *ttl);
                }
                FamilyCacheHit::NoData => return AddressLookupResult::NoData,
                FamilyCacheHit::NxDomain => return AddressLookupResult::NxDomain,
                FamilyCacheHit::Miss => {}
            }
        }

        let result = self.run_pipeline(host, family).await;
        // `run_pipeline` returns `None` either when no upstream produced an
        // answer, or when the single-flight broadcast was missed (the publisher
        // sent and closed before this subscriber subscribed). In the latter
        // case the publisher has already merged the result into the cache —
        // re-read it here so a missed broadcast doesn't surface as a transient
        // `Failed` (which would make the DNS server return SERVFAIL).
        let Some(set) = result else {
            if let Some(cached) = self.cache.get_lookup(host) {
                let hit = if family == QueryFamilies::IPV4 {
                    &cached.v4
                } else {
                    &cached.v6
                };
                return match hit {
                    FamilyCacheHit::Answer(ips, ttl) => AddressLookupResult::Answer(ips[0], *ttl),
                    FamilyCacheHit::NoData => AddressLookupResult::NoData,
                    FamilyCacheHit::NxDomain => AddressLookupResult::NxDomain,
                    FamilyCacheHit::Miss => AddressLookupResult::Failed,
                };
            }
            return AddressLookupResult::Failed;
        };
        let answer = if family == QueryFamilies::IPV4 {
            &set.v4
        } else {
            &set.v6
        };
        match answer {
            Some(FamilyAnswer::Answer { ips, ttl }) => ips
                .iter()
                .copied()
                .find(|ip| family.contains_ip(*ip))
                .map_or(AddressLookupResult::NoData, |ip| {
                    AddressLookupResult::Answer(ip, *ttl)
                }),
            Some(FamilyAnswer::NoData(_)) => AddressLookupResult::NoData,
            Some(FamilyAnswer::NxDomain(_)) => AddressLookupResult::NxDomain,
            Some(FamilyAnswer::Failed) | None => AddressLookupResult::Failed,
        }
    }

    fn skipper_bypasses(&self, host: &str) -> bool {
        self.fakeip_skipper
            .as_ref()
            .is_some_and(|s| s.should_skip(host))
    }

    fn filter_enabled_ips(&self, ips: &[IpAddr]) -> Option<Vec<IpAddr>> {
        let ips: Vec<_> = ips
            .iter()
            .copied()
            .filter(|ip| self.ipv6 || ip.is_ipv4())
            .collect();
        (!ips.is_empty()).then_some(ips)
    }

    /// Returns all IPs for `host` from the hosts trie (respecting `use_hosts`),
    /// or `None` if the domain is not in the trie.
    ///
    /// Use this in the DNS server to distinguish "no hosts match" (continue to
    /// upstream) from "hosts matched but no IPs of queried family" (return
    /// NOERROR with zero answers per DNS spec).
    pub fn lookup_hosts_all(&self, host: &str) -> Option<&Vec<IpAddr>> {
        if !self.use_hosts {
            return None;
        }
        match self.lookup_hosts_entry(host) {
            Some(HostsLookup::Addresses(ips)) => Some(ips),
            Some(HostsLookup::Alias(_)) | None => None,
        }
    }

    /// One unified resolution pipeline parameterized by the queried family set
    /// (review issue J): the old code carried two parallel pipelines —
    /// `do_lookup`/`query_pool`/`try_fallback` for the "every enabled address"
    /// path and `lookup_actual_family`/`query_pool_family`/`try_fallback_family`
    /// for the per-family DNS-server path — and they had already diverged
    /// (single-flight and negative bookkeeping existed in only one each). Both
    /// now share domain-gate → policy → main → fallback, single-flight, and
    /// symmetric negative bookkeeping.
    ///
    /// `want` selects which families to fetch: `BOTH` uses the concurrent
    /// A+AAAA client path (for `resolve_ips`); a single family uses the
    /// per-family client path (for the DNS server's A/AAAA answers, which must
    /// distinguish NXDOMAIN/NODATA). The publisher merges positives and NODATA
    /// into the cache (per-family expiry) before broadcasting; subscribers
    /// receive the same `FamilySet` with the cache already populated.
    async fn run_pipeline(&self, host: &str, want: QueryFamilies) -> Option<FamilySet> {
        use dashmap::mapref::entry::Entry;
        // Both current callers filter `want` before calling. The
        // debug_assert keeps the invariant loud in dev; the release path
        // returns instead of reaching `inflight_slot`'s `unreachable!()`,
        // which would abort the whole proxy over a future unguarded
        // call site (review N2). "Asks for nothing" maps to "no
        // dedicated result", the same answer a cache miss gives.
        debug_assert!(!want.is_empty(), "singleflight requires a non-empty set");
        if want.is_empty() {
            return None;
        }
        let inflight = &self.inflight[inflight_slot(want)];
        // Borrowed-key fast path: `Arc<str>: Borrow<str>` lets both the
        // subscriber check and the guard removal below run without ever
        // allocating — the host is only cloned into an `Arc<str>` once a
        // new flight is actually inserted (review issue M1).
        if let Some(entry) = inflight.get(host) {
            let mut rx = entry.subscribe();
            drop(entry);
            return rx.recv().await.ok().flatten();
        }
        // `entry()` consumes an owned key; keep one Arc for the guard so it
        // can remove the inflight slot on drop — the map stores a second
        // reference to the same allocation, so this is one allocation total,
        // only on the insert path.
        let guard_key: Arc<str> = Arc::from(host);
        let tx = match inflight.entry(Arc::clone(&guard_key)) {
            Entry::Occupied(existing) => {
                let mut rx = existing.get().subscribe();
                drop(existing);
                return rx.recv().await.ok().flatten();
            }
            Entry::Vacant(v) => {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                v.insert(tx.clone());
                tx
            }
        };
        let _guard = InflightGuard {
            map: inflight,
            key: guard_key,
            _armed: (),
        };
        let result = self.pipeline_inner(host, want).await;
        // Only the publisher writes to the cache; subscribers re-read it (or
        // use the broadcast FamilySet directly) after the merge has landed.
        if let Some(set) = &result {
            self.merge_set_into_cache(host, set);
        }
        let _ = tx.send(result.clone());
        result
    }

    async fn pipeline_inner(&self, host: &str, want: QueryFamilies) -> Option<FamilySet> {
        debug!(host, ?want, "DNS lookup");

        // Domain-gate: skip primary entirely, go straight to fallback.
        if let Some(ff) = &self.fallback_filter {
            if ff.domain_gated(host) {
                return self.query_fallback_set(host, want).await;
            }
        }

        // Symmetric first-wins negative bookkeeping (review issue F): the first
        // tier's definitive negative is kept and later tiers' negatives never
        // overwrite it, so the rcode the client sees depends on tier order
        // (policy → main → fallback), not on an asymmetric clobber rule.
        let mut negative: Option<FamilySet> = None;

        // Nameserver-policy lookup.
        if let Some(policy) = &self.policy {
            if let Some(entry) = policy.lookup(host) {
                if let Some(set) = query_pool_set(&entry.nameservers, host, want, self.ipv6).await {
                    if set.has_positive() {
                        if self
                            .fallback_filter
                            .as_ref()
                            .is_some_and(|ff| ff.ip_gated(&set.positive_ips()))
                        {
                            return self.query_fallback_set(host, want).await;
                        }
                        return Some(set);
                    }
                    if negative.is_none() {
                        negative = Some(set);
                    }
                }
                // Policy negative: fall through to global nameservers.
            }
        }

        // Global nameservers (parallel, first-positive / first-definitive-negative).
        if let Some(set) = query_pool_set(&self.main, host, want, self.ipv6).await {
            if set.has_positive() {
                if self
                    .fallback_filter
                    .as_ref()
                    .is_some_and(|ff| ff.ip_gated(&set.positive_ips()))
                {
                    return self.query_fallback_set(host, want).await;
                }
                return Some(set);
            }
            if negative.is_none() {
                negative = Some(set);
            }
        }

        if let Some(set) = self.query_fallback_set(host, want).await {
            if set.has_positive() {
                return Some(set);
            }
            if negative.is_none() {
                negative = Some(set);
            }
        }
        negative
    }

    async fn query_fallback_set(&self, host: &str, want: QueryFamilies) -> Option<FamilySet> {
        query_pool_set(self.fallback.as_deref()?, host, want, self.ipv6).await
    }

    /// Write a pipeline result's per-family answers into the cache. Positives,
    /// NODATA, and NXDOMAIN are all cached (per-family expiry) so repeat queries
    /// are served from cache — damping DGA/retry-loop load and preserving the
    /// NXDOMAIN rcode on a cache hit (RFC 2308, aligns with mihomo
    /// `putMsgToCache`). Only `Failed` (a transient network/timeout error, not
    /// a definitive answer) is left out, so a flapping upstream doesn't pin a
    /// name as unreachable. SERVFAIL is intentionally not cached here either —
    /// a deliberate divergence from mihomo (which caches SERVFAIL for 5 s):
    /// SERVFAIL is a server error, not an authoritative negative, and caching
    /// it would need careful handling of the multi-upstream race (a cached
    /// SERVFAIL must not short-circuit a live upstream's later success).
    fn merge_set_into_cache(&self, host: &str, set: &FamilySet) {
        for (family, answer) in [
            (QueryFamilies::IPV4, &set.v4),
            (QueryFamilies::IPV6, &set.v6),
        ] {
            let Some(answer) = answer else { continue };
            match answer {
                FamilyAnswer::Answer { ips, ttl } => {
                    self.cache.merge_family(
                        host,
                        family,
                        ips,
                        *ttl,
                        Some(&set.source),
                        FamilyNeg::None,
                    );
                }
                FamilyAnswer::NoData(ttl) => {
                    self.cache.merge_family(
                        host,
                        family,
                        &[],
                        *ttl,
                        Some(&set.source),
                        FamilyNeg::NoData,
                    );
                }
                FamilyAnswer::NxDomain(ttl) => {
                    self.cache.merge_family(
                        host,
                        family,
                        &[],
                        *ttl,
                        Some(&set.source),
                        FamilyNeg::NxDomain,
                    );
                }
                FamilyAnswer::Failed => {}
            }
        }
    }

    /// Forward a non-A/AAAA query (TXT, MX, SRV, HTTPS, SOA, PTR, …) through
    /// the same nameserver pipeline as ordinary lookups: domain-gate → policy
    /// → main → fallback. Returns the upstream `Message` so callers can
    /// re-emit the answer section verbatim in their response.
    ///
    /// Skips the `ip_gated` fallback hop — the fallback-filter's IP-CIDR /
    /// GeoIP gates only apply to address records.
    pub async fn forward_generic(&self, domain: &str, record_type: RecordType) -> Option<Message> {
        if let Some(ff) = &self.fallback_filter {
            if ff.domain_gated(domain) {
                return self.try_fallback_generic(domain, record_type).await;
            }
        }
        if let Some(policy) = &self.policy {
            if let Some(entry) = policy.lookup(domain) {
                if let Some(l) = query_pool_generic(&entry.nameservers, domain, record_type).await {
                    return Some(l);
                }
            }
        }
        if let Some(l) = query_pool_generic(&self.main, domain, record_type).await {
            return Some(l);
        }
        self.try_fallback_generic(domain, record_type).await
    }

    async fn try_fallback_generic(&self, domain: &str, record_type: RecordType) -> Option<Message> {
        let fb = self.fallback.as_deref()?;
        query_pool_generic(fb, domain, record_type).await
    }

    /// Capture the live reverse (IP → host) table with remaining lifetimes,
    /// for persistence across an engine restart. Fake-IP pool mappings are
    /// not included — the pools have their own [`crate::fakeip::Store`]
    /// persistence.
    pub fn reverse_cache_snapshot(&self) -> Vec<crate::cache::ReverseSnapshotEntry> {
        self.cache.reverse_snapshot()
    }

    /// Restore reverse (IP → host) entries captured by
    /// [`Self::reverse_cache_snapshot`] in a previous run. Call at startup,
    /// before traffic: in redir-host (Mapping) mode this is what lets
    /// connections dialed from pre-restart DNS answers still recover their
    /// hostname for rule matching.
    pub fn restore_reverse_cache(
        &self,
        entries: impl IntoIterator<Item = crate::cache::ReverseSnapshotEntry>,
    ) {
        self.cache.restore_reverse(entries);
    }

    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<SmolStr> {
        if let Some(pool) = &self.fakeip_v4 {
            if let Some(host) = pool.look_back(ip) {
                return Some(host);
            }
        }
        if let Some(pool) = &self.fakeip_v6 {
            if let Some(host) = pool.look_back(ip) {
                return Some(host);
            }
        }
        self.cache.reverse_lookup(ip)
    }

    /// True when fake-IP synthesis applies to `host` — i.e. its A/AAAA
    /// answers will be synthetic. Mirrors the gating in [`Self::lookup_ipv4`] /
    /// [`Self::lookup_ipv6`]: fake-IP mode, at least one pool configured, the
    /// host is not an explicit hosts-trie mapping, and the skipper does not
    /// bypass it.
    ///
    /// The DNS server uses this to strip `ipv4hint` / `ipv6hint` SvcParams
    /// from HTTPS/SVCB answers for the same host. Those hints carry the
    /// origin's *real* addresses; an HTTP/3 client that reads them connects
    /// straight to the real IP, bypassing the fake-IP mapping the tunnel
    /// relies on for domain-based routing and sniffing.
    pub fn fake_ip_active_for(&self, host: &str) -> bool {
        if self.mode != DnsMode::FakeIp {
            return false;
        }
        // Explicit hosts-trie mappings are never rewritten to fake IPs.
        if self.use_hosts && self.hosts.search(host).is_some() {
            return false;
        }
        (self.fakeip_v4.is_some() || self.fakeip_v6.is_some()) && !self.skipper_bypasses(host)
    }

    /// True if `ip` is an active fake-IP allocation (either family).
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        if let Some(pool) = &self.fakeip_v4 {
            if pool.is_fake_ip(ip) {
                return true;
            }
        }
        if let Some(pool) = &self.fakeip_v6 {
            if pool.is_fake_ip(ip) {
                return true;
            }
        }
        false
    }

    /// Clear every fake-IP allocation; resets cursors. No-op when fake-ip
    /// is disabled. Returns `Ok` unless persistence fails (currently
    /// infallible — failures are logged, not returned).
    pub fn flush_fake_ip(&self) -> Result<(), std::io::Error> {
        if let Some(p) = &self.fakeip_v4 {
            p.flush();
        }
        if let Some(p) = &self.fakeip_v6 {
            p.flush();
        }
        Ok(())
    }

    /// Fake-IP A/AAAA response TTL (used by the UDP DNS server).
    pub fn fake_ip_ttl(&self) -> Duration {
        self.fakeip_ttl
    }

    /// The v4 fake-IP pool prefix, when fake-IP mode is active. The TUN
    /// inbound's auto-route uses this to route only the fake range into the
    /// device (loop-free capture — real IPs never re-enter the tun).
    pub fn fake_ip_v4_net(&self) -> Option<ipnet::IpNet> {
        self.fakeip_v4.as_ref().map(|p| p.ipnet())
    }

    /// The v4 fake-IP pool gateway (network + 1, e.g. `198.18.0.1`). When
    /// `dns-hijack` is active, the OS resolver should be pointed here so
    /// that DNS queries enter the TUN and are answered with fake IPs.
    pub fn fake_ip_v4_gateway(&self) -> Option<std::net::IpAddr> {
        self.fakeip_v4.as_ref().map(|p| p.gateway())
    }

    /// The installed fake-IP pool covering exactly `prefix`, if any.
    /// Config reload uses this to carry the live mapping table into a
    /// rebuilt resolver: the pool (store + allocation cursor) IS the
    /// fake-IP state — dropping it strands clients holding
    /// `host → 198.18.x.y` answers and lets the cursor reissue their
    /// addresses to other hosts (issue #514 review follow-up).
    pub fn fakeip_pool_over(&self, prefix: ipnet::IpNet) -> Option<Arc<Pool>> {
        [&self.fakeip_v4, &self.fakeip_v6]
            .into_iter()
            .flatten()
            .find(|p| {
                // Semantic range equality: `198.18.0.1/16` and
                // `198.18.0.0/16` describe the same pool (anchors derive
                // from network()/broadcast()), but `IpNet`'s PartialEq
                // compares the stored address literally — compare the
                // network base and prefix length instead.
                let n = p.ipnet();
                n.network() == prefix.network() && n.prefix_len() == prefix.prefix_len()
            })
            .cloned()
    }

    /// Install a v4 fake-IP pool. Caller wires this after `new_with_bootstrap`.
    pub fn set_fakeip_v4(&mut self, pool: Arc<Pool>) {
        self.fakeip_v4 = Some(pool);
    }
    /// Install a v6 fake-IP pool.
    pub fn set_fakeip_v6(&mut self, pool: Arc<Pool>) {
        self.fakeip_v6 = Some(pool);
    }
    /// Install a bypass skipper.
    pub fn set_fakeip_skipper(&mut self, skipper: Skipper) {
        self.fakeip_skipper = Some(skipper);
    }
    /// Override the synthesised-answer TTL (default `DEFAULT_FAKE_IP_TTL`).
    pub fn set_fakeip_ttl(&mut self, ttl: Duration) {
        self.fakeip_ttl = ttl;
    }

    pub fn mode(&self) -> DnsMode {
        self.mode
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    pub fn dns_results(&self, search: Option<&str>, limit: usize) -> Vec<DnsCacheSnapshotEntry> {
        let search = search
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        self.cache
            .snapshot()
            .into_iter()
            .filter(|entry| {
                search.as_ref().is_none_or(|needle| {
                    entry.name.to_ascii_lowercase().contains(needle)
                        || entry.ips.iter().any(|ip| ip.to_string().contains(needle))
                        || entry
                            .source
                            .as_ref()
                            .is_some_and(|source| source.to_ascii_lowercase().contains(needle))
                })
            })
            .take(limit)
            .collect()
    }

    /// Seed the positive-resolution cache directly with a known mapping.
    ///
    /// Production lookups populate the cache from upstream queries; this is for
    /// preloading known answers (and for tests) without a round-trip. Mirrors
    /// the bound used by ordinary cached entries via `ttl`.
    pub fn preload_cache(&self, host: &str, ips: &[IpAddr], ttl: std::time::Duration) {
        self.cache.put(host, ips, ttl);
    }

    /// Seed the positive-resolution cache with a source label for API tests
    /// and callers that already know the upstream answer source.
    pub fn preload_cache_with_source(
        &self,
        host: &str,
        ips: &[IpAddr],
        ttl: std::time::Duration,
        source: Option<&str>,
    ) {
        self.cache.put_with_source(host, ips, ttl, source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA, SOA};
    use hickory_proto::rr::{RData, Record};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn one_shot_a_upstream(
        response_code: ResponseCode,
        answer: Option<Ipv4Addr>,
    ) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();
            let query = request.queries[0].clone();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.response_code = response_code;
            response.add_query(query.clone());
            if let Some(ip) = answer {
                response.add_answer(Record::from_rdata(query.name, 60, RData::A(A(ip))));
            }
            socket
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });
        addr
    }

    #[test]
    fn build_single_resolver_preserves_configured_dot_label() {
        let url = NameServerUrl::parse("tls://dns.google:853").unwrap();
        let mut resolved = HashMap::new();
        resolved.insert(
            "dns.google".to_string(),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        );

        let client = Resolver::build_single_resolver(&url, &resolved);

        assert_eq!(client.upstream_label(), "tls://dns.google");
    }

    #[test]
    fn build_single_resolver_preserves_configured_dot_sni_label() {
        let url = NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap();
        let resolved = HashMap::new();

        let client = Resolver::build_single_resolver(&url, &resolved);

        assert_eq!(client.upstream_label(), "tls://8.8.8.8#dns.google");
    }

    #[test]
    fn build_single_resolver_preserves_configured_doh_label() {
        let url = NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap();
        let resolved = HashMap::new();

        let client = Resolver::build_single_resolver(&url, &resolved);

        assert_eq!(
            client.upstream_label(),
            "https://1.1.1.1/dns-query#cloudflare-dns.com"
        );
    }

    #[tokio::test]
    async fn resolve_ip_uses_hosts_file() {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        hosts.insert("example.test", vec![real].into());
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);
        assert_eq!(resolver.resolve_ip("example.test").await, Some(real));
        assert_eq!(resolver.resolve_ip_real("example.test").await, Some(real));
    }

    #[tokio::test]
    async fn resolve_ips_preserves_all_hosts_file_addresses() {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let ips = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        ];
        hosts.insert("example.test", ips.clone().into());
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);

        assert_eq!(resolver.resolve_ips("example.test").await, Some(ips));
        assert_eq!(
            resolver.resolve_ip("example.test").await,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[tokio::test]
    async fn ipv6_disabled_filters_hosts_and_aaaa_lookup() {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let ipv4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        hosts.insert(
            "example.test",
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST), ipv4].into(),
        );
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, false);

        assert_eq!(resolver.resolve_ips("example.test").await, Some(vec![ipv4]));
        assert_eq!(resolver.lookup_ipv6("example.test").await, None);
    }

    /// Review issue E: a hosts entry that pins only the *disabled* family
    /// (v6-only under `ipv6: false`) must fall through to upstream DNS instead
    /// of short-circuiting to `None` — otherwise DirectAdapter treats the host
    /// as unresolvable even though a usable A record exists upstream. The old
    /// code returned early whenever the hosts trie matched, regardless of
    /// whether any enabled IP remained.
    #[tokio::test]
    async fn v6_only_hosts_entry_falls_through_to_upstream_when_ipv6_disabled() {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        hosts.insert("v6only.test", vec![IpAddr::V6(Ipv6Addr::LOCALHOST)].into());

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();
            let query = request.queries[0].clone();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.add_query(query.clone());
            response.add_answer(Record::from_rdata(
                query.name,
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
            ));
            socket
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });

        let resolver = Resolver::new(vec![addr], vec![], DnsMode::Normal, hosts, true, false);
        // The v6-only hosts pin is ignored for the disabled family and the
        // resolver falls through to the upstream A record.
        assert_eq!(
            resolver.resolve_ips("v6only.test").await,
            Some(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))])
        );
    }

    /// Review issue C: a definitive negative (NODATA/NXDOMAIN) from a healthy
    /// upstream must not wait out a dead upstream's full 5 s timeout. With two
    /// main upstreams — one black-holed (never responds) and one answering
    /// AAAA NODATA in ~1 ms — `query_pool_set` returns on the first definitive
    /// negative and cancels the straggler, so the whole lookup finishes in well
    /// under the per-query timeout.
    #[tokio::test]
    async fn definitive_negative_does_not_stall_on_dead_upstream() {
        // Dead upstream: bind but never answer.
        let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // Hold the socket open for the test's duration; never reply.
            let _ = dead.recv_from(&mut buf).await;
        });

        // Healthy upstream: answer AAAA with NOERROR + zero answers (NODATA).
        let healthy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let healthy_addr = healthy.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = healthy.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();
            let query = request.queries[0].clone();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.add_query(query);
            // No answers → NOERROR-empty (NODATA).
            healthy
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });

        let resolver = Resolver::new(
            vec![dead_addr, healthy_addr],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );
        let start = std::time::Instant::now();
        let result = resolver.lookup_ipv6_result("v4only.example").await;
        let elapsed = start.elapsed();
        assert!(
            matches!(result, AddressLookupResult::NoData),
            "expected NoData, got {result:?}"
        );
        // The per-query timeout is 5 s; first-definitive-negative must return
        // in well under that. 1 s is a generous upper bound for a local UDP
        // round-trip plus scheduling jitter.
        assert!(
            elapsed < Duration::from_secs(1),
            "AAAA NODATA took {elapsed:?} — definitive negative stalled on the dead upstream"
        );
    }

    /// Companion to issue C for the dual-stack (`BOTH`) path: a client whose A
    /// is NODATA and whose AAAA *errored* (so the family is `None`, never
    /// answered) is **not** a definitive negative for a `BOTH` query. The pool
    /// must keep racing instead of short-circuiting, so a second client that
    /// does return a v6 address wins. A naive "no `Failed` ⇒ definitive" rule
    /// would treat `v6 = None` as definitive and wrongly return the empty
    /// result, dropping the available v6 address.
    #[tokio::test]
    async fn both_query_keeps_racing_when_one_family_is_unknown() {
        // Client A: A -> NODATA, AAAA -> malformed reply (so AAAA errors fast,
        // yielding v4=NoData, v6=None — a *partial*, not a definitive negative).
        let client_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_a_addr = client_a.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for round in 0..2u32 {
                let (len, peer) = client_a.recv_from(&mut buf).await.unwrap();
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                if round == 0 {
                    // A: NOERROR with zero answers (NODATA).
                    let mut response =
                        Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                    response.add_query(query);
                    client_a
                        .send_to(&response.to_bytes().unwrap(), peer)
                        .await
                        .unwrap();
                } else {
                    // AAAA: garbage that fails to parse -> lookup_family Err.
                    client_a.send_to(&[0u8; 4], peer).await.unwrap();
                    break;
                }
            }
        });

        // Client B: A -> NODATA, AAAA -> v6 address (a positive for BOTH).
        let client_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_b_addr = client_b.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, peer) = client_b.recv_from(&mut buf).await.unwrap();
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(query.clone());
                if query.query_type == RecordType::AAAA {
                    response.add_answer(Record::from_rdata(
                        query.name,
                        60,
                        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                    ));
                }
                client_b
                    .send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let resolver = Resolver::new(
            vec![client_a_addr, client_b_addr],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );
        let ips = resolver.resolve_ips("v6available.example").await;
        let has_v6 = ips.as_ref().is_some_and(|v| v.iter().any(IpAddr::is_ipv6));
        assert!(
            has_v6,
            "dual-stack query must keep racing past the partial (A=NODATA, AAAA=unknown)              result and return the v6 address from the second client, got {ips:?}"
        );
    }

    #[tokio::test]
    async fn resolve_ips_follows_hosts_domain_alias_chain() {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let real = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        hosts.insert("alias.test", HostEntry::Alias("middle.test".into()));
        hosts.insert("middle.test", HostEntry::Alias("origin.test".into()));
        hosts.insert("origin.test", HostEntry::Addresses(vec![real]));
        let resolver = Resolver::new(vec![], vec![], DnsMode::FakeIp, hosts, true, true);

        assert_eq!(resolver.resolve_ips("alias.test").await, Some(vec![real]));
        assert_eq!(
            resolver.lookup_ipv4("alias.test").await,
            Some(real),
            "an explicit alias must bypass fake-IP synthesis"
        );
    }

    #[tokio::test]
    async fn dual_stack_cache_queries_missing_aaaa_family() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(query.clone());
                let record = match query.query_type {
                    RecordType::A => Record::from_rdata(
                        query.name.clone(),
                        60,
                        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
                    ),
                    RecordType::AAAA => Record::from_rdata(
                        query.name.clone(),
                        60,
                        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                    ),
                    other => panic!("unexpected query type {other:?}"),
                };
                response.add_answer(record);
                socket
                    .send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let resolver = Resolver::new(
            vec![addr],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );
        assert_eq!(
            resolver.lookup_ipv4("dual.example").await,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            resolver.lookup_ipv6("dual.example").await,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    /// Regression: `resolve_ips` must query the missing family when one family
    /// is already cached. The old code short-circuited on the first available
    /// enabled IP, so an A-only cache prevented AAAA from being queried —
    /// starving `DirectAdapter` of IPv6 fallback addresses.
    #[tokio::test]
    async fn resolve_ips_queries_missing_family_after_a_only_cache() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let query_count = Arc::new(AtomicUsize::new(0));
        let qc = Arc::clone(&query_count);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok(Ok((len, peer))) =
                    tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf))
                        .await
                else {
                    break;
                };
                qc.fetch_add(1, Ordering::SeqCst);
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(query.clone());
                match query.query_type {
                    RecordType::A => {
                        response.add_answer(Record::from_rdata(
                            query.name,
                            60,
                            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
                        ));
                    }
                    RecordType::AAAA => {
                        response.add_answer(Record::from_rdata(
                            query.name,
                            60,
                            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                        ));
                    }
                    _ => {}
                }
                socket
                    .send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let resolver = Resolver::new(
            vec![addr],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );

        // Step 1: cache only A via the single-family path.
        assert_eq!(
            resolver.lookup_ipv4("dual.example").await,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        let queries_after_ipv4 = query_count.load(Ordering::SeqCst);
        assert_eq!(queries_after_ipv4, 1, "lookup_ipv4 should query only A");

        // Step 2: resolve_ips with ipv6=true should query the missing AAAA,
        // not short-circuit on the cached A.
        let ips = resolver.resolve_ips("dual.example").await;
        let has_v6 = ips.as_ref().is_some_and(|v| v.iter().any(IpAddr::is_ipv6));
        assert!(has_v6, "resolve_ips must return both families, got {ips:?}");
        let queries_after_resolve = query_count.load(Ordering::SeqCst);
        assert!(
            queries_after_resolve > queries_after_ipv4,
            "resolve_ips must have queried the missing AAAA family"
        );
    }

    /// Regression: `resolve_ips` with `ipv6: true` must return both IPv4 and
    /// IPv6 addresses for a dual-stack domain, with IPv4 first (prefer-IPv4
    /// ordering). This is the address list `DirectAdapter::dial_tcp` iterates
    /// to try connection fallback.
    #[tokio::test]
    async fn resolve_ips_returns_both_families_for_dual_stack() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok(Ok((len, peer))) =
                    tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf))
                        .await
                else {
                    break;
                };
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(query.clone());
                match query.query_type {
                    RecordType::A => {
                        response.add_answer(Record::from_rdata(
                            query.name,
                            60,
                            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
                        ));
                    }
                    RecordType::AAAA => {
                        response.add_answer(Record::from_rdata(
                            query.name,
                            60,
                            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                        ));
                    }
                    _ => {}
                }
                socket
                    .send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let resolver = Resolver::new(
            vec![addr],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );

        let ips = resolver.resolve_ips("dual.example").await.unwrap();
        let has_v4 = ips.iter().any(IpAddr::is_ipv4);
        let has_v6 = ips.iter().any(IpAddr::is_ipv6);
        assert!(has_v4, "must include IPv4: {ips:?}");
        assert!(has_v6, "must include IPv6: {ips:?}");
        // Prefer-IPv4: the first address should be IPv4.
        assert!(
            ips.first().is_some_and(IpAddr::is_ipv4),
            "IPv4 must come first (prefer-IPv4): {ips:?}"
        );
    }

    /// Regression (P2): a fast NXDOMAIN from one upstream in a tier must not
    /// suppress a slow positive answer from another. `query_pool_set` now
    /// waits briefly (grace period) after the first definitive negative
    /// before committing, so a split-horizon upstream that returns a real
    /// address slightly later wins.
    #[tokio::test]
    async fn fast_negative_does_not_suppress_slow_positive() {
        // Fast upstream: returns NXDOMAIN immediately.
        let fast = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fast_addr = fast.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok(Ok((len, peer))) =
                    tokio::time::timeout(Duration::from_millis(500), fast.recv_from(&mut buf))
                        .await
                else {
                    break;
                };
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.response_code = ResponseCode::NXDomain;
                response.add_query(query);
                fast.send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        // Slow upstream: returns a positive A answer after a short delay.
        let slow = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let slow_addr = slow.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok(Ok((len, peer))) =
                    tokio::time::timeout(Duration::from_millis(500), slow.recv_from(&mut buf))
                        .await
                else {
                    break;
                };
                tokio::time::sleep(Duration::from_millis(50)).await;
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(query.clone());
                response.add_answer(Record::from_rdata(
                    query.name,
                    60,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
                ));
                slow.send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let resolver = Resolver::new(
            vec![fast_addr, slow_addr],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );

        let result = resolver.lookup_ipv4_result("split.example").await;
        assert!(
            matches!(result, AddressLookupResult::Answer(ip, _) if ip == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))),
            "slow positive must win over fast NXDOMAIN, got {result:?}"
        );
    }

    #[tokio::test]
    async fn nodata_family_is_cached_without_discarding_other_family() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(query.clone());
                if query.query_type == RecordType::A {
                    response.add_answer(Record::from_rdata(
                        query.name,
                        60,
                        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
                    ));
                }
                socket
                    .send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let resolver = Resolver::new(
            vec![addr],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );
        assert!(matches!(
            resolver.lookup_ipv4_result("nodata.example").await,
            AddressLookupResult::Answer(IpAddr::V4(_), _)
        ));
        assert!(matches!(
            resolver.lookup_ipv6_result("nodata.example").await,
            AddressLookupResult::NoData
        ));
        assert!(matches!(
            resolver.lookup_ipv6_result("nodata.example").await,
            AddressLookupResult::NoData
        ));
        assert!(matches!(
            resolver.lookup_ipv4_result("nodata.example").await,
            AddressLookupResult::Answer(IpAddr::V4(_), _)
        ));
    }

    #[tokio::test]
    async fn family_lookup_uses_fallback_after_primary_nxdomain() {
        let main = one_shot_a_upstream(ResponseCode::NXDomain, None).await;
        let fallback_ip = Ipv4Addr::new(192, 0, 2, 9);
        let fallback = one_shot_a_upstream(ResponseCode::NoError, Some(fallback_ip)).await;
        let resolver = Resolver::new(
            vec![main],
            vec![fallback],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );

        assert!(matches!(
            resolver.lookup_ipv4_result("fallback.example").await,
            AddressLookupResult::Answer(IpAddr::V4(ip), _) if ip == fallback_ip
        ));
    }

    #[tokio::test]
    async fn resolve_ip_returns_cached_entry() {
        let hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);
        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        resolver
            .cache
            .put("cached.test", &[real], Duration::from_secs(60));
        assert_eq!(resolver.resolve_ip("cached.test").await, Some(real));
    }

    #[tokio::test]
    async fn resolve_ips_preserves_all_cached_addresses() {
        let hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        resolver
            .cache
            .put("cached.test", &ips, Duration::from_secs(60));

        assert_eq!(resolver.resolve_ips("cached.test").await, Some(ips));
    }

    #[test]
    fn resolve_ips_local_answers_from_hosts_and_cache_only() {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let via_hosts = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        hosts.insert("node.test", vec![via_hosts].into());
        hosts.insert("alias.test", HostEntry::Alias("cached.test".into()));
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);

        let via_cache = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
        resolver
            .cache
            .put("cached.test", &[via_cache], Duration::from_secs(60));

        assert_eq!(
            resolver.resolve_ips_local("node.test"),
            Some(vec![via_hosts])
        );
        assert_eq!(
            resolver.resolve_ips_local("cached.test"),
            Some(vec![via_cache])
        );
        assert_eq!(
            resolver.resolve_ips_local("alias.test"),
            Some(vec![via_cache]),
            "a hosts alias must resolve through to the cached target"
        );
        assert_eq!(
            resolver.resolve_ips_local("unknown.test"),
            None,
            "an unknown host must not trigger an upstream query"
        );
    }

    #[test]
    fn resolve_ips_local_ignores_hosts_when_use_hosts_is_off() {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        hosts.insert(
            "node.test",
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))].into(),
        );
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, false, true);

        assert_eq!(resolver.resolve_ips_local("node.test"), None);
    }

    #[test]
    fn fake_ip_active_for_gates_on_mode_pool_and_skipper() {
        use crate::fakeip::{MemoryStore, SkipperMode};

        let new_hosts = || -> DomainTrie<HostEntry> { DomainTrie::new() };

        // Normal mode: never active.
        let normal = Resolver::new(vec![], vec![], DnsMode::Normal, new_hosts(), true, true);
        assert!(!normal.fake_ip_active_for("example.com"));

        // Fake-IP mode but no pool configured: not active.
        let no_pool = Resolver::new(vec![], vec![], DnsMode::FakeIp, new_hosts(), true, true);
        assert!(!no_pool.fake_ip_active_for("example.com"));

        // Fake-IP mode with a v4 pool: active.
        let mut faked = Resolver::new(vec![], vec![], DnsMode::FakeIp, new_hosts(), true, true);
        let pool = Arc::new(
            Pool::new(
                "198.18.0.0/16".parse().unwrap(),
                Arc::new(MemoryStore::new(1024)),
            )
            .unwrap(),
        );
        faked.set_fakeip_v4(pool);
        assert!(faked.fake_ip_active_for("example.com"));

        // A skipper-bypassed host falls back to real resolution → not faked.
        faked.set_fakeip_skipper(Skipper::new(
            &["+.direct.example".to_string()],
            SkipperMode::BlackList,
        ));
        assert!(!faked.fake_ip_active_for("api.direct.example"));
        assert!(faked.fake_ip_active_for("example.com"));
    }

    /// Dual-stack contract that the stripped-HTTPS path relies on: with the
    /// IP hints removed, the client falls back to A/AAAA, so the per-family
    /// fake synthesis must do the right thing for each pool configuration.
    #[tokio::test]
    async fn fake_ip_dual_stack_synthesis_is_per_family() {
        use crate::fakeip::MemoryStore;

        let v4_pool = || {
            Arc::new(
                Pool::new(
                    "198.18.0.0/16".parse().unwrap(),
                    Arc::new(MemoryStore::new(1024)),
                )
                .unwrap(),
            )
        };

        // v4-only pool (the common default): A synthesises a v4 fake; AAAA is
        // suppressed (None → server emits NOERROR-empty) so a dual-stack
        // client cleanly falls back to the v4 fake instead of stalling.
        let mut v4_only = Resolver::new(
            vec![],
            vec![],
            DnsMode::FakeIp,
            DomainTrie::new(),
            true,
            true,
        );
        v4_only.set_fakeip_v4(v4_pool());
        let a = v4_only.lookup_ipv4("example.com").await;
        assert!(
            a.is_some_and(|ip| ip.is_ipv4() && v4_only.is_fake_ip(ip)),
            "A must return a v4 fake IP"
        );
        assert_eq!(
            v4_only.lookup_ipv6("example.com").await,
            None,
            "v4-only pool must suppress AAAA so the client uses the v4 fake"
        );

        // Dual pool: both families synthesise → Happy Eyeballs picks between
        // two fakes, both of which route through the tunnel.
        let mut dual = Resolver::new(
            vec![],
            vec![],
            DnsMode::FakeIp,
            DomainTrie::new(),
            true,
            true,
        );
        dual.set_fakeip_v4(v4_pool());
        dual.set_fakeip_v6(Arc::new(
            Pool::new(
                "fc00::/64".parse().unwrap(),
                Arc::new(MemoryStore::new(1024)),
            )
            .unwrap(),
        ));
        let a = dual.lookup_ipv4("example.com").await;
        let aaaa = dual.lookup_ipv6("example.com").await;
        assert!(
            a.is_some_and(|ip| ip.is_ipv4() && dual.is_fake_ip(ip)),
            "A must return a v4 fake IP"
        );
        assert!(
            aaaa.is_some_and(|ip| ip.is_ipv6() && dual.is_fake_ip(ip)),
            "AAAA must return a v6 fake IP when a v6 pool is configured"
        );
    }

    #[tokio::test]
    async fn lookup_with_ttl_reports_remaining_cache_lifetime() {
        let resolver = Resolver::new(
            vec![],
            vec![],
            DnsMode::Mapping,
            DomainTrie::new(),
            true,
            true,
        );
        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        resolver
            .cache
            .put("cached.test", &[real], Duration::from_secs(300));
        let (ip, ttl) = resolver
            .lookup_ipv4_with_ttl("cached.test")
            .await
            .expect("cache hit");
        assert_eq!(ip, real);
        assert!(ttl <= Duration::from_secs(300));
        assert!(
            ttl > Duration::from_secs(295),
            "ttl {ttl:?} should be the remaining lifetime, not a constant"
        );
    }

    #[tokio::test]
    async fn lookup_with_ttl_uses_hosts_ttl_for_static_mappings() {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let pinned = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        hosts.insert("pinned.test", vec![pinned].into());
        let resolver = Resolver::new(vec![], vec![], DnsMode::Mapping, hosts, true, true);
        assert_eq!(
            resolver.lookup_ipv4_with_ttl("pinned.test").await,
            Some((pinned, HOSTS_ANSWER_TTL))
        );
    }

    #[tokio::test]
    async fn lookup_with_ttl_reports_fake_ip_ttl_for_synthesised_answers() {
        use crate::fakeip::MemoryStore;
        let mut resolver = Resolver::new(
            vec![],
            vec![],
            DnsMode::FakeIp,
            DomainTrie::new(),
            true,
            true,
        );
        resolver.set_fakeip_v4(Arc::new(
            Pool::new(
                "198.18.0.0/16".parse().unwrap(),
                Arc::new(MemoryStore::new(1024)),
            )
            .unwrap(),
        ));
        let (ip, ttl) = resolver
            .lookup_ipv4_with_ttl("example.com")
            .await
            .expect("fake-IP synthesis");
        assert!(resolver.is_fake_ip(ip));
        assert_eq!(ttl, DEFAULT_FAKE_IP_TTL);
    }

    #[test]
    fn reverse_cache_snapshot_restore_round_trips_via_resolver() {
        let resolver = Resolver::new(
            vec![],
            vec![],
            DnsMode::Mapping,
            DomainTrie::new(),
            true,
            true,
        );
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        resolver
            .cache
            .put("persist.test", &[ip], Duration::from_secs(60));
        let snap = resolver.reverse_cache_snapshot();
        assert_eq!(snap.len(), 1);

        let restarted = Resolver::new(
            vec![],
            vec![],
            DnsMode::Mapping,
            DomainTrie::new(),
            true,
            true,
        );
        assert!(restarted.reverse_lookup(ip).is_none());
        restarted.restore_reverse_cache(snap);
        assert_eq!(
            restarted.reverse_lookup(ip).as_deref(),
            Some("persist.test")
        );
    }

    #[test]
    fn clamp_ttl_table_driven() {
        // (label, raw TTL, expected clamped TTL) — MIN_TTL 10s, MAX_TTL 3600s.
        let cases: [(&str, Duration, Duration); 4] = [
            ("zero returns min", Duration::ZERO, Duration::from_secs(10)),
            (
                "below min returns min",
                Duration::from_secs(3),
                Duration::from_secs(10),
            ),
            (
                "in range returns raw",
                Duration::from_secs(120),
                Duration::from_secs(120),
            ),
            (
                "above max returns max",
                Duration::from_secs(99_999),
                Duration::from_secs(3600),
            ),
        ];

        // Collect instead of asserting inline so every case runs and all
        // mismatches are reported in one failure.
        let mut failures: Vec<String> = Vec::new();
        for (label, raw, expected) in cases {
            let got = clamp_ttl(raw);
            if got != expected {
                failures.push(format!(
                    "{label}: clamp_ttl({raw:?}) = {got:?}, expected {expected:?}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "clamp_ttl cases failed:\n{}",
            failures.join("\n")
        );
    }

    #[tokio::test]
    async fn inflight_entry_cleared_after_lookup_miss() {
        let hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);
        // `resolve_ips` routes the cache/host miss through the unified
        // single-flight pipeline; the inflight slot must be released on drop.
        let _ = resolver.resolve_ips("nonexistent.test").await;
        assert!(
            resolver.inflight.iter().all(DashMap::is_empty),
            "inflight maps must be empty after lookup, had {} entries total",
            resolver.inflight.iter().map(DashMap::len).sum::<usize>()
        );
    }

    #[tokio::test]
    async fn inflight_concurrent_callers_share_one_lookup() {
        let hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let resolver = std::sync::Arc::new(Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            true,
        ));
        let r1 = Arc::clone(&resolver);
        let r2 = Arc::clone(&resolver);
        // Two concurrent callers for the same host/family-set coalesce onto a
        // single upstream flight (keyed per family set by host — review
        // issue B) and observe the same result.
        let (a, b) = tokio::join!(
            r1.resolve_ips("concurrent.test"),
            r2.resolve_ips("concurrent.test"),
        );
        assert_eq!(a, b, "concurrent callers must see the same result");
        assert!(resolver.inflight.iter().all(DashMap::is_empty));
    }

    // B2: IP-literal upstreams → bootstrap never called, even with empty default_ns.
    // Upstream: Go mihomo still attempts bootstrap for IP-literal entries. NOT a call here.
    #[tokio::test]
    async fn bootstrap_ip_literal_shortcircuits() {
        let main = vec![
            NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap(),
            NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap(),
        ];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            main,
            vec![],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            true,
            None,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "IP-literal upstreams must not require default-nameserver"
        );
    }

    // B5: Tls hostname in default_ns → DefaultNameserverNotPlain (bootstrap loop).
    #[tokio::test]
    async fn bootstrap_rejects_encrypted_hostname_default_ns() {
        let default_ns = vec![NameServerUrl::parse("tls://dns.google:853").unwrap()];
        let hosts = DomainTrie::new();
        let err = Resolver::new_with_bootstrap(
            vec![],
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            true,
            None,
            None,
        )
        .await
        .err()
        .expect("expected error");
        assert!(
            matches!(err, BootstrapError::DefaultNameserverNotPlain { .. }),
            "expected DefaultNameserverNotPlain, got: {err}"
        );
    }

    #[tokio::test]
    async fn bootstrap_rejects_plain_hostname_default_ns() {
        let default_ns = vec![NameServerUrl::parse("dns.google").unwrap()];
        let err = Resolver::new_with_bootstrap(
            vec![NameServerUrl::parse("tls://cloudflare-dns.com").unwrap()],
            vec![],
            default_ns,
            DnsMode::Normal,
            DomainTrie::new(),
            true,
            true,
            None,
            None,
        )
        .await
        .err()
        .expect("expected error");
        assert!(matches!(
            err,
            BootstrapError::DefaultNameserverNotPlain { .. }
        ));
    }

    // B5b: Tls IP-literal in default_ns → accepted (no bootstrap loop).
    #[tokio::test]
    async fn bootstrap_accepts_encrypted_ip_literal_default_ns() {
        let default_ns = vec![NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            vec![],
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            true,
            None,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "tls:// IP-literal in default_ns must be accepted"
        );
    }

    // B6: Https hostname in default_ns → same error.
    #[tokio::test]
    async fn bootstrap_rejects_https_hostname_in_default_ns() {
        let default_ns =
            vec![NameServerUrl::parse("https://cloudflare-dns.com/dns-query").unwrap()];
        let hosts = DomainTrie::new();
        let err = Resolver::new_with_bootstrap(
            vec![],
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            true,
            None,
            None,
        )
        .await
        .err()
        .expect("expected error");
        assert!(matches!(
            err,
            BootstrapError::DefaultNameserverNotPlain { .. }
        ));
    }

    // B6b: Https IP-literal in default_ns → accepted.
    #[tokio::test]
    async fn bootstrap_accepts_https_ip_literal_default_ns() {
        let default_ns =
            vec![NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            vec![],
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            true,
            None,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "https:// IP-literal in default_ns must be accepted"
        );
    }

    // B7: tcp:// in default_ns is accepted (useful behind middleboxes blocking UDP/53).
    #[tokio::test]
    async fn bootstrap_accepts_tcp_in_default_ns() {
        let default_ns = vec![NameServerUrl::parse("tcp://8.8.8.8:53").unwrap()];
        let main = vec![NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            main,
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            true,
            None,
            None,
        )
        .await;
        assert!(result.is_ok(), "tcp in default_ns must be accepted");
    }

    // B8: encrypted hostname upstream with empty default_ns falls back to
    // system DNS (mihomo-compat, issue #201 item 3) instead of hard-erroring.
    // Outcome is network-dependent: Ok when the system resolvers answer, or
    // CannotResolve when offline. We must never see a DefaultNameserver* error.
    #[tokio::test]
    async fn bootstrap_falls_back_to_system_dns_when_encrypted_has_hostname() {
        let main = vec![NameServerUrl::parse("https://cloudflare-dns.com/dns-query").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            main,
            vec![],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            true,
            None,
            None,
        )
        .await
        .map(|_| ());
        assert!(
            matches!(result, Ok(()) | Err(BootstrapError::CannotResolve { .. })),
            "expected Ok or CannotResolve (offline), got: {result:?}"
        );
    }

    // B9: encrypted IP-literal with empty default_ns → Ok.
    #[tokio::test]
    async fn bootstrap_ok_encrypted_ip_literal_empty_default_ns() {
        let main = vec![NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            main,
            vec![],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            true,
            None,
            None,
        )
        .await;
        assert!(result.is_ok());
    }

    // C8: a fallback (not just main) encrypted hostname with empty default_ns
    // also bootstraps via system DNS rather than erroring (issue #201 item 3).
    #[tokio::test]
    async fn bootstrap_falls_back_to_system_dns_when_fallback_encrypted_has_hostname() {
        let main = vec![NameServerUrl::parse("8.8.8.8").unwrap()];
        let fallback = vec![NameServerUrl::parse("https://dns.quad9.net/dns-query").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            main,
            fallback,
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            true,
            None,
            None,
        )
        .await
        .map(|_| ());
        assert!(
            matches!(result, Ok(()) | Err(BootstrapError::CannotResolve { .. })),
            "expected Ok or CannotResolve (offline), got: {result:?}"
        );
    }

    // system_nameservers always yields at least one bootstrap address (resolv.conf
    // entries on Unix, or the hardcoded public-resolver fallback otherwise).
    #[tokio::test]
    async fn system_nameservers_never_empty() {
        let ns = system_nameservers().await;
        assert!(!ns.is_empty(), "system_nameservers must never be empty");
        assert!(
            ns.iter().all(|a| a.port() == 53),
            "bootstrap nameservers must use port 53"
        );
    }

    // use_hosts=false bypasses the hosts trie.
    // Upstream: use-hosts is always on in upstream. NOT a bypass here — Class B per ADR-0002 (deferred config option).
    #[tokio::test]
    async fn use_hosts_false_bypasses_hosts_trie() {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        let hosts_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        hosts.insert("example.test", vec![hosts_ip].into());
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, false, true);
        // With use_hosts=false, hosts lookup is bypassed, no upstream → None.
        assert_eq!(
            resolver.resolve_ip("example.test").await,
            None,
            "use_hosts=false must skip hosts trie"
        );
    }

    // lookup_hosts_all returns None when use_hosts=false.
    #[test]
    fn lookup_hosts_all_respects_use_hosts_flag() {
        let make_hosts = || {
            let mut h: DomainTrie<HostEntry> = DomainTrie::new();
            h.insert(
                "example.test",
                vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))].into(),
            );
            h
        };
        let r_on = Resolver::new(vec![], vec![], DnsMode::Normal, make_hosts(), true, true);
        let r_off = Resolver::new(vec![], vec![], DnsMode::Normal, make_hosts(), false, true);
        assert!(r_on.lookup_hosts_all("example.test").is_some());
        assert!(r_off.lookup_hosts_all("example.test").is_none());
    }

    // fallback-filter domain gate skips primary and returns None when no fallback.
    // Upstream: dns/resolver.go::ipWithFallback. NOT primary-then-discard — skip entirely.
    #[tokio::test]
    async fn fallback_filter_domain_gate_skips_primary() {
        let mut domain_trie: DomainTrie<()> = DomainTrie::new();
        domain_trie.insert("+.google.cn", ());
        let ff = FallbackFilter {
            geoip_enabled: false,
            geoip_code: "CN".to_string(),
            ipcidr: vec![],
            domain: domain_trie,
            geoip_reader: None,
        };
        let hosts = DomainTrie::new();
        let mut resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);
        resolver.fallback_filter = Some(ff);
        // No fallback configured → None returned (primary never tried).
        let result = resolver.resolve_ip("www.google.cn").await;
        assert_eq!(result, None, "domain-gated query must skip primary");
    }

    // fallback-filter CIDR gate triggers when primary returns a bogon IP.
    // Only testable via cache injection since we can't mock real resolver here.
    #[test]
    fn fallback_filter_ip_gated_cidr() {
        let cidr: IpNet = "240.0.0.0/4".parse().unwrap();
        let ff = FallbackFilter {
            geoip_enabled: false,
            geoip_code: "CN".to_string(),
            ipcidr: vec![cidr],
            domain: DomainTrie::new(),
            geoip_reader: None,
        };
        let bogon: IpAddr = "240.1.2.3".parse().unwrap();
        let clean: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(ff.ip_gated(&[bogon]), "bogon IP must be gated");
        assert!(!ff.ip_gated(&[clean]), "clean IP must not be gated");
    }

    // nameserver-policy exact match.
    // Upstream: dns/resolver.go::PolicyResolver. NOT global nameservers when exact match exists.
    #[tokio::test]
    async fn nameserver_policy_exact_match_returns_policy_result() {
        // Without a working nameserver we can only test that exact lookup hits the
        // policy entry (resolvers will return None via empty pool).
        let entry = PolicyEntry {
            nameservers: vec![],
        };
        let mut pol = NameserverPolicy::new();
        pol.insert_exact("corp.example".to_string(), entry);
        assert!(pol.lookup("corp.example").is_some(), "exact match must hit");
        assert!(pol.lookup("other.example").is_none(), "non-match must miss");
    }

    // nameserver-policy wildcard match (subdomain + root).
    // Upstream: dns/resolver.go::PolicyResolver. NOT global. `+.` includes root.
    #[test]
    fn nameserver_policy_wildcard_matches_subdomain_and_root() {
        let entry = PolicyEntry {
            nameservers: vec![],
        };
        let mut pol = NameserverPolicy::new();
        pol.insert_wildcard("+.corp.internal", entry);
        assert!(
            pol.lookup("foo.corp.internal").is_some(),
            "subdomain must match"
        );
        assert!(
            pol.lookup("corp.internal").is_some(),
            "root domain must match (+. includes root)"
        );
        assert!(pol.lookup("other.example").is_none(), "non-match must miss");
    }

    #[test]
    fn nameserver_policy_matcher_matches_domain() {
        let entry = PolicyEntry {
            nameservers: vec![],
        };
        let mut pol = NameserverPolicy::new();
        pol.insert_matcher(Arc::new(|domain| domain.ends_with(".cn")), entry);
        assert!(pol.lookup("example.cn").is_some());
        assert!(pol.lookup("example.com").is_none());
    }

    #[tokio::test]
    async fn nxdomain_is_cached_and_preserves_rcode_on_second_lookup() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let requests_task = Arc::clone(&requests);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok(Ok((len, peer))) =
                    tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf))
                        .await
                else {
                    break;
                };
                requests_task.fetch_add(1, Ordering::SeqCst);
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.response_code = ResponseCode::NXDomain;
                response.add_query(query);
                response.add_authority(Record::from_rdata(
                    "example.".parse().unwrap(),
                    60,
                    RData::SOA(SOA::new(
                        "ns.example.".parse().unwrap(),
                        "hostmaster.example.".parse().unwrap(),
                        1,
                        3600,
                        900,
                        1209600,
                        300,
                    )),
                ));
                socket
                    .send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let resolver = Resolver::new(
            vec![addr],
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        );

        // The aggregate resolve path runs first. Its NXDOMAIN must populate the
        // shared cache with the real negative kind, not fresh NODATA.
        assert_eq!(resolver.resolve_ips("missing.example").await, None);
        assert!(matches!(
            resolver.lookup_ipv4_result("missing.example").await,
            AddressLookupResult::NxDomain
        ));
        // v6 NXDOMAIN is cached from the parallel A+AAAA query — both
        // families return NXDOMAIN and are cached per-family.
        assert!(matches!(
            resolver.lookup_ipv6_result("missing.example").await,
            AddressLookupResult::NxDomain
        ));
        assert!(matches!(
            resolver.lookup_ipv4_result("missing.example").await,
            AddressLookupResult::NxDomain
        ));
        // Both A and AAAA were queried once (parallel dual-stack path);
        // subsequent lookups are served from cache.
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }
}
