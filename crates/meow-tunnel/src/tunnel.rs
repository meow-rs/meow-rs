use crate::match_engine::{self, DomainIndex};
use crate::rule_ir::{CompiledMatchResult, CompiledRuleSet, LazyMatchOutcome};
use crate::statistics::Statistics;
use crate::udp::{self, NatTable};
use meow_common::{Metadata, Network, Proxy, ProxyAdapter, Rule, TunnelMode};
use meow_dns::Resolver;
use meow_proxy::DirectAdapter;
use parking_lot::{Mutex, RwLock};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use tracing::{debug, info, warn};

/// Bundled rules + domain index + proxies map, swapped as one `Arc` on
/// config reload. Reads on the connection-setup hot path take a single
/// short `RwLock` read (an `Arc` refcount bump) — previously each
/// `resolve_proxy` call acquired three `parking_lot::RwLock` guards (rules,
/// domain_index, proxies). Swapping the whole table also guarantees rules +
/// proxies are observed as a consistent snapshot, so a connection can no
/// longer match a rule that points at a proxy not yet inserted.
///
/// The slot is a `parking_lot::RwLock<Arc<RouteTable>>` rather than
/// `arc_swap::ArcSwap`: `arc-swap`'s atomic-ordering correctness on
/// weak-memory targets (ARM) has no formal proof and reproducible UAF /
/// data-race reports exist upstream, so we prefer the well-understood lock
/// (issue #327). Route reload is rare and the read critical section is a
/// clone, so this is nowhere near a bottleneck.
///
/// `rules` and `domain_index` are themselves `Arc`-wrapped so a partial
/// update (e.g. `update_proxies` keeping the rules) is a refcount bump
/// rather than a deep clone — `Box<dyn Rule>` is not `Clone`.
pub struct RouteTable {
    pub rules: Arc<Vec<Box<dyn Rule>>>,
    pub domain_index: Arc<DomainIndex>,
    pub compiled_rules: Arc<CompiledRuleSet>,
    pub proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
    /// The registry generation `proxies` was published into. Retained so the
    /// `dialer-proxy` front-hop lookups the map's adapters perform keep
    /// resolving for exactly as long as this route table lives — the adapters
    /// hold the registry cell weakly (issue #533), so without this owner the
    /// snapshot would drop while the adapters are still dialable.
    pub dialer_registry: meow_proxy::dialer::ProxyRegistry,
}

impl RouteTable {
    fn new(
        proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
        rules: Vec<Box<dyn Rule>>,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
    ) -> Self {
        let domain_index = DomainIndex::build(&rules);
        let compiled_rules = CompiledRuleSet::build(&rules);
        Self {
            rules: Arc::new(rules),
            domain_index: Arc::new(domain_index),
            compiled_rules: Arc::new(compiled_rules),
            proxies,
            dialer_registry,
        }
    }

    fn empty() -> Self {
        Self {
            rules: Arc::new(Vec::new()),
            domain_index: Arc::new(DomainIndex::empty()),
            compiled_rules: Arc::new(CompiledRuleSet::empty()),
            proxies: HashMap::new(),
            dialer_registry: meow_proxy::dialer::ProxyRegistry::default(),
        }
    }
}

pub struct TunnelInner {
    pub mode: RwLock<TunnelMode>,
    /// Current route table (rules + domain index + proxies), replaced
    /// wholesale on config reload. Readers clone the `Arc` and drop the
    /// guard immediately; never hold the guard across an `.await`.
    pub route: RwLock<Arc<RouteTable>>,
    /// Hot-swappable resolver slot (issue #514): `PUT /configs` rebuilds
    /// the DNS resolver and publishes it via `Tunnel::set_resolver`. The
    /// slot is shared with `direct` and handed to runtime route rebuilds,
    /// so the map's `DIRECT` adapter tracks the same generation.
    resolver: meow_dns::ResolverSlot,
    /// Fallback DIRECT adapter used when no user-defined rule matches or
    /// when Direct/Global mode bypasses the proxies map. Pre-built with the
    /// internal resolver so hostname dials avoid the OS resolver; its
    /// resolver slot is swapped alongside `resolver` on reload.
    pub direct: Arc<DirectAdapter>,
    /// Immediate-reject adapter for the defence-in-depth arm in
    /// `materialize_rule_match`: a matched non-DIRECT target absent from
    /// the registry must fail closed, never fall through to direct egress
    /// (issue #533).
    reject: Arc<meow_proxy::RejectAdapter>,
    pub nat_table: NatTable,
    pub stats: Arc<Statistics>,
    /// Cold-reload admission boundary. TCP setup captures this generation
    /// before routing, then checks it under a read lock through registration.
    /// Reload holds the write lock through cancellation and route publication.
    /// Neither side holds this lock across an await or during relay.
    pub(crate) tcp_generation: RwLock<u64>,
    /// Cached: true if any rule needs the dst_ip resolved (GeoIP / IP-CIDR).
    /// Recomputed by `Tunnel::update_rules`.
    pub needs_ip_resolution: AtomicBool,
    /// Cached: true if any rule needs process-name enrichment (PROCESS-NAME /
    /// PROCESS-PATH / UID). Recomputed by `Tunnel::update_rules`. Avoids an
    /// O(n) virtual-dispatch scan of the rule list on every connection.
    pub needs_process_lookup: AtomicBool,
    /// Handle to the running TUN listener (if any). Abort + await it to
    /// stop TUN. Stored so `put_configs` can start/stop TUN at runtime.
    pub tun_handle: RwLock<Option<TunHandle>>,
    /// Health-check task set keyed by group name; reconciled on every
    /// config commit so checks appear/disappear/respawn with the config
    /// (issue #514).
    pub health_checks: Mutex<crate::health_check::HealthCheckSupervisor>,
}

/// A running TUN listener: the task plus the signal resolving once its
/// lwIP core has fully torn down.
///
/// The lwIP contract allows only one live stack generation per process;
/// the core finishes teardown only after every stack handle — including
/// the split halves inside the device pumps — is dropped. Since an aborted
/// parent task cannot await that reaping, `stop_tun`/`set_tun_handle`
/// additionally await `core_done` so a successor generation cannot overlap
/// a core still tearing down (issue #514).
pub struct TunHandle {
    /// The listener task — abort + await it to stop.
    pub task: tokio::task::JoinHandle<()>,
    /// Flips `true` once this generation's lwIP core finished teardown.
    /// `None` for non-lwIP/test handles that have no core to await.
    pub core_done: Option<tokio::sync::watch::Receiver<bool>>,
}

/// Upper bound on waiting for a torn-down lwIP core. Teardown is a
/// synchronous pcb sweep — far under a second — so this only bounds a
/// wedged core; proceeding past it logs loudly rather than hanging the
/// config-mutation lane forever.
const TUN_TEARDOWN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Await a generation's `core_done` with the wedge bound. `RecvError`
/// (sender dropped without signalling) means the core is already gone.
async fn await_core_done(mut rx: tokio::sync::watch::Receiver<bool>) {
    match tokio::time::timeout(TUN_TEARDOWN_WAIT, rx.wait_for(|done| *done)).await {
        Ok(Ok(_)) | Ok(Err(_)) => {}
        Err(_) => warn!("timed out waiting for lwIP core teardown; continuing"),
    }
}

impl TunnelInner {
    /// Snapshot the current route table: one short read lock + `Arc` clone.
    /// The returned `Arc` is safe to hold across `.await` points.
    pub fn route(&self) -> Arc<RouteTable> {
        Arc::clone(&self.route.read())
    }

    /// Snapshot the current resolver generation: one short read lock +
    /// `Arc` clone. Always reflects the latest `Tunnel::set_resolver`.
    pub fn resolver(&self) -> Arc<Resolver> {
        Arc::clone(&self.resolver.read())
    }

    /// Rewrite a fake-IP destination back to its real hostname before rule
    /// matching. Mirrors upstream `preHandleMetadata` in
    /// `tunnel/tunnel.go`. Always called from `handle_tcp` / `handle_udp`
    /// before [`Self::pre_resolve`]; outside fake-IP mode this is a no-op
    /// except for the snooping-cache hostname fill-in.
    ///
    /// After a fake-IP rewrite the metadata has:
    /// - `metadata.host` ← real domain recovered from the pool reverse map
    /// - `metadata.dst_ip` ← `None`, so `pre_resolve` (or the adapter)
    ///   re-resolves to a real address via the configured DNS path
    pub fn pre_handle_metadata(&self, metadata: &mut Metadata) {
        let Some(ip) = metadata.dst_ip else {
            return;
        };
        let resolver = self.resolver();
        if !resolver.is_fake_ip(ip) {
            // Outside fake-IP mode — also fold in a snooping-cache hostname
            // if metadata.host is currently empty. Preserves the upstream
            // `DNSMapping` mode contract used by the tproxy listener.
            if metadata.host.is_empty() {
                if let Some(host) = resolver.reverse_lookup(ip) {
                    metadata.host = host;
                }
            }
            return;
        }
        if let Some(host) = resolver.reverse_lookup(ip) {
            debug!("pre_handle_metadata: fake-ip {} → {}", ip, host);
            metadata.host = host;
            metadata.dst_ip = None;
        } else {
            // Fake IP without a reverse mapping — pool wrap evicted the
            // entry since synthesis. Leave the IP in place; the connection
            // dials to a dead address but we don't drop the metadata silently.
            debug!("pre_handle_metadata: fake-ip {} has no reverse mapping", ip);
        }
    }

    /// Pre-process metadata before rule matching: if any rule needs IP
    /// resolution and we don't yet have a destination IP, resolve
    /// `metadata.host` via the internal resolver and populate `dst_ip`.
    ///
    /// `Metadata::remote_address()` prefers `host` over `dst_ip`, so
    /// overwriting `dst_ip` here does not change which destination the proxy
    /// adapter dials.
    pub async fn pre_resolve(&self, metadata: &mut Metadata) {
        if !self.needs_ip_resolution.load(Ordering::Relaxed) {
            return;
        }
        if metadata.host.is_empty() || metadata.dst_ip.is_some() {
            return;
        }
        if let Some(real_ip) = self.resolver().resolve_ip_real(&metadata.host).await {
            debug!("pre_resolve: {} -> {}", metadata.host, real_ip);
            metadata.dst_ip = Some(real_ip);
        }
    }

    /// Resolve which proxy to use for the given metadata.
    ///
    /// Rule matching returns borrowed adapter/payload text, so the rule engine
    /// itself stays heap-allocation-free. This method materializes the public
    /// tracking payloads as `SmolStr` after matching, where short common names
    /// still remain inline.
    ///
    /// The returned [`ResolvedTarget`] retains the [`RouteTable`] snapshot the
    /// adapter was resolved from. **Hold it in scope across the dial**: the
    /// adapter may be a `dialer-proxy` chain whose front-hop lookups go
    /// through the route table's registry cell — a reload that swaps the
    /// table between resolve and dial would otherwise strand the chain on a
    /// dead generation (issue #533 review).
    pub fn resolve_proxy(&self, metadata: &Metadata) -> Option<ResolvedTarget> {
        let mode = *self.mode.read();
        match mode {
            TunnelMode::Direct => Some(ResolvedTarget {
                adapter: Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                rule_name: SmolStr::new_static("Direct"),
                rule_payload: SmolStr::default(),
                route: self.route(),
            }),
            TunnelMode::Global => {
                let route = self.route();
                let (adapter, rule_name) = if let Some(proxy) = route.proxies.get("GLOBAL") {
                    (
                        Arc::clone(proxy) as Arc<dyn ProxyAdapter>,
                        SmolStr::new_static("Global"),
                    )
                } else {
                    (
                        Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                        SmolStr::new_static("Direct"),
                    )
                };
                Some(ResolvedTarget {
                    adapter,
                    rule_name,
                    rule_payload: SmolStr::default(),
                    route,
                })
            }
            TunnelMode::Rule => {
                // One route-table snapshot — rules + index + proxies all read
                // from a consistent table. Replaces three RwLock acquisitions.
                let route = self.route();
                let needs_proc = route.compiled_rules.needs_process_lookup();
                let enriched = if needs_proc {
                    match_engine::maybe_enrich_with_process(metadata)
                } else {
                    None
                };
                let match_metadata = enriched.as_ref().unwrap_or(metadata);
                let result = route.compiled_rules.match_rules(
                    match_metadata,
                    route.rules.as_ref(),
                    &Self::target_usable(&route, match_metadata),
                );
                Some(self.materialize_rule_match(&route, result))
            }
        }
    }

    /// Rule-mode variant of [`Self::resolve_proxy`] with **lazy metadata
    /// enrichment**: DNS pre-resolution and process lookup are performed
    /// only when the rule scan actually reaches a slot that demands them —
    /// a connection matched by an earlier rule (typically a domain rule)
    /// pays for neither. Replaces the `pre_resolve` + `resolve_proxy` pair
    /// on TCP paths; may populate `metadata.dst_ip` exactly like
    /// `pre_resolve` did.
    ///
    /// UDP paths must keep calling `pre_resolve`: their NAT session key
    /// requires a resolved `dst_ip` regardless of what the rules demand.
    pub async fn resolve_proxy_lazy(&self, metadata: &mut Metadata) -> Option<ResolvedTarget> {
        let mode = *self.mode.read();
        if mode != TunnelMode::Rule {
            return self.resolve_proxy(metadata);
        }

        // Owned `Arc` snapshot: the enrichment arm holds it across an
        // `.await`, which a lock guard must never do.
        let route = self.route();
        let usable = Self::target_usable(&route, metadata);
        match route
            .compiled_rules
            .match_rules_lazy(metadata, route.rules.as_ref(), &usable)
        {
            LazyMatchOutcome::Matched(m) => Some(self.materialize_rule_match(&route, Some(m))),
            LazyMatchOutcome::NoMatch => Some(self.materialize_rule_match(&route, None)),
            LazyMatchOutcome::NeedsEnrichment {
                needs_ip,
                needs_process,
            } => {
                // Process enrichment matches `resolve_proxy`: the enriched
                // copy is used for matching only, so tracked connection
                // metadata stays byte-identical to the eager path.
                let mut enriched = if needs_process {
                    match_engine::maybe_enrich_with_process(metadata)
                } else {
                    None
                };
                if needs_ip {
                    // `needs_ip` already encodes the `pre_resolve` guards:
                    // host present, dst_ip absent.
                    if let Some(real_ip) = self.resolver().resolve_ip_real(&metadata.host).await {
                        debug!("lazy resolve: {} -> {}", metadata.host, real_ip);
                        metadata.dst_ip = Some(real_ip);
                    }
                }
                if let (Some(enriched), Some(ip)) = (enriched.as_mut(), metadata.dst_ip) {
                    enriched.dst_ip = Some(ip);
                }
                let match_metadata = enriched.as_ref().unwrap_or(metadata);
                let result = route.compiled_rules.match_rules(
                    match_metadata,
                    route.rules.as_ref(),
                    &Self::target_usable(&route, match_metadata),
                );
                Some(self.materialize_rule_match(&route, result))
            }
        }
    }

    /// Registry-membership predicate for the match engines (issue #513
    /// `continue` semantics). Mirrors mihomo's `match()` loop exactly: the
    /// scan skips a matched rule whose target is absent — and, for UDP
    /// flows, whose adapter lacks `support_udp` (upstream's second
    /// `continue` at `!adapter.SupportUDP()`). `DIRECT` is hard-coded as
    /// always usable: the tunnel owns that adapter unconditionally.
    fn target_usable<'a>(route: &'a RouteTable, metadata: &Metadata) -> impl Fn(&str) -> bool + 'a {
        let is_udp = metadata.network == Network::Udp;
        move |name| {
            name == "DIRECT"
                || route
                    .proxies
                    .get(name)
                    .is_some_and(|p| !is_udp || p.support_udp())
        }
    }

    /// Map a rule-match result to a [`ResolvedTarget`], recording match
    /// statistics; `None` falls through to DIRECT. The target retains
    /// `route` so the generation's dialer registry stays pinned across the
    /// caller's dial (see [`Self::resolve_proxy`]).
    fn materialize_rule_match(
        &self,
        route: &Arc<RouteTable>,
        result: Option<CompiledMatchResult<'_>>,
    ) -> ResolvedTarget {
        match result {
            Some(m) => {
                let target = m.adapter_name;
                let mut action = if target == "DIRECT" {
                    "DIRECT"
                } else if target.starts_with("REJECT") {
                    "REJECT"
                } else {
                    "PROXY"
                };
                let proxy: Arc<dyn ProxyAdapter> = match route.proxies.get(target).cloned() {
                    Some(p) => p as Arc<dyn ProxyAdapter>,
                    // DIRECT needs no registry entry: the tunnel owns a direct
                    // adapter for exactly this.
                    None if target == "DIRECT" => Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                    None => {
                        // Defence in depth: the rule scans (both compiled and
                        // legacy engines) already skip a match whose target is
                        // absent — mihomo's `continue` semantics — so this arm
                        // is unreachable for registry-missing targets. Keep it
                        // for any future path that resolves a match without a
                        // registry check (issue #513).
                        //
                        // Fail closed: materializing an absent target must
                        // reject the connection, never fall through to direct
                        // egress — a silent DIRECT hop is exactly the leak
                        // class `dialer-proxy` exists to prevent (issue #533).
                        //
                        // Interpolate into the message itself: the /logs
                        // broadcast keeps only the `message` field, so
                        // structured fields would never reach it.
                        warn!(
                            "rule {} matched target '{target}' which is not in \
                             the registry; rejecting",
                            m.rule_type.as_str()
                        );
                        action = "REJECT";
                        Arc::clone(&self.reject) as Arc<dyn ProxyAdapter>
                    }
                };
                self.stats
                    .rule_match
                    .increment(m.rule_type.as_str(), action);
                // `rule_type.as_str()` is a `&'static str` — wrap it
                // inline without heap.
                ResolvedTarget {
                    adapter: proxy,
                    rule_name: SmolStr::new_static(m.rule_type.as_str()),
                    rule_payload: SmolStr::from(m.rule_payload),
                    route: Arc::clone(route),
                }
            }
            None => {
                // No rule matched, use DIRECT
                ResolvedTarget {
                    adapter: Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                    rule_name: SmolStr::new_static("Final"),
                    rule_payload: SmolStr::default(),
                    route: Arc::clone(route),
                }
            }
        }
    }
}

/// The outcome of [`TunnelInner::resolve_proxy`] /
/// [`TunnelInner::resolve_proxy_lazy`]:
/// the adapter to dial, the rule that produced it, and the route-table
/// generation it was resolved from.
///
/// **Hold the value in scope across the dial.** `route` pins this
/// generation's dialer-registry cell — a config reload landing between
/// resolve and dial would otherwise strand a chained `dialer-proxy` front
/// hop on a dead generation (issue #533 review).
pub struct ResolvedTarget {
    /// The adapter that should dial `metadata`'s destination.
    pub adapter: Arc<dyn ProxyAdapter>,
    /// Rule type name for logs/metrics ("Final" on the no-match tail).
    pub rule_name: SmolStr,
    /// Rule payload text for logs/metrics.
    pub rule_payload: SmolStr,
    /// The route-table generation `adapter` was resolved from, retained for
    /// its `dialer_registry` cell. Destructure it into a scope that outlives
    /// the dial (`route: _route`) — dropping it early re-opens the reload
    /// race this type exists to close.
    pub route: Arc<RouteTable>,
}

pub struct Tunnel {
    inner: Arc<TunnelInner>,
}

impl Tunnel {
    /// New tunnel with a private resolver slot — `set_resolver` swaps are
    /// visible to `inner.direct`, but adapters rebuilt with a different
    /// slot are not. Production uses [`Self::new_with_slot`] so the slot
    /// is also shared into every runtime route rebuild (issue #514).
    pub fn new(resolver: Arc<Resolver>) -> Self {
        Self::new_with_slot(meow_dns::new_resolver_slot(resolver))
    }

    /// New tunnel sharing `resolver_slot` — the same slot must be passed
    /// to `rebuild_from_raw_*` so the map's `DIRECT` adapter and
    /// `inner.direct` observe `set_resolver` swaps identically.
    pub fn new_with_slot(resolver: meow_dns::ResolverSlot) -> Self {
        let direct = Arc::new(DirectAdapter::new().with_resolver_slot(Arc::clone(&resolver)));
        Self {
            inner: Arc::new(TunnelInner {
                mode: RwLock::new(TunnelMode::Rule),
                route: RwLock::new(Arc::new(RouteTable::empty())),
                resolver,
                direct,
                reject: Arc::new(meow_proxy::RejectAdapter::new(false)),
                nat_table: udp::new_nat_table(),
                stats: Arc::new(Statistics::new()),
                tcp_generation: RwLock::new(0),
                health_checks: Mutex::new(crate::health_check::HealthCheckSupervisor::default()),
                needs_ip_resolution: AtomicBool::new(false),
                needs_process_lookup: AtomicBool::new(false),
                tun_handle: RwLock::new(None),
            }),
        }
    }

    pub fn inner(&self) -> &Arc<TunnelInner> {
        &self.inner
    }

    /// Weak handle to the inner state — long-lived background loops
    /// (subscription refresh, geodata auto-update) capture this and
    /// upgrade per tick so dropping every `Tunnel` handle actually stops
    /// them (same contract the health-check loops and NAT sweeper use,
    /// issue #514).
    pub fn weak_inner(&self) -> Weak<TunnelInner> {
        Arc::downgrade(&self.inner)
    }

    /// Rebuild a `Tunnel` handle from an upgraded [`Self::weak_inner`].
    pub fn from_inner(inner: Arc<TunnelInner>) -> Self {
        Self { inner }
    }

    pub fn set_mode(&self, mode: TunnelMode) {
        *self.inner.mode.write() = mode;
        info!("Tunnel mode set to {}", mode);
    }

    pub fn mode(&self) -> TunnelMode {
        *self.inner.mode.read()
    }

    pub fn update_rules(&self, rules: Vec<Box<dyn Rule>>) {
        let new_index = DomainIndex::build(&rules);
        let compiled_rules = CompiledRuleSet::build(&rules);
        // Take the enrichment flags from the compiled plan rather than the
        // raw rule list: rules pruned by the IR clean-up passes (dead after
        // MATCH, provable never-match) must not force per-connection DNS
        // pre-resolution or process lookup.
        let needs_ip = compiled_rules.needs_ip_resolution();
        let needs_proc = compiled_rules.needs_process_lookup();
        // Build a new route table on top of the current proxies map. The
        // current proxies are cloned (Arc bumps for adapter handles, one
        // HashMap clone) — paid only on config-reload, not the hot path.
        // The write lock is held across the read-modify-write so a
        // concurrent `update_proxies` cannot be lost.
        {
            let mut route = self.inner.route.write();
            let new_route = RouteTable {
                rules: Arc::new(rules),
                domain_index: Arc::new(new_index),
                compiled_rules: Arc::new(compiled_rules),
                proxies: route.proxies.clone(),
                // The proxies map is unchanged, so the generation's chained
                // adapters must keep resolving through the same registry cell.
                dialer_registry: route.dialer_registry.clone(),
            };
            *route = Arc::new(new_route);
        }
        self.inner
            .needs_ip_resolution
            .store(needs_ip, Ordering::Relaxed);
        self.inner
            .needs_process_lookup
            .store(needs_proc, Ordering::Relaxed);
        info!(
            "Rules updated (needs_ip_resolution={}, needs_process_lookup={})",
            needs_ip, needs_proc
        );
    }

    /// Swap the proxies map while keeping the current rules — and the current
    /// dialer registry. Callers rebuilding a whole config should use
    /// [`Self::update_routing`], which carries the rebuild's own registry;
    /// keeping the old cell here lets a swapped-in map that still contains
    /// the previous generation's chained adapters keep resolving them.
    /// Hazard: a map built by a *new* rebuild binds its `dialer-proxy`
    /// targets to that build's own cell — pass it here and every chain fails
    /// closed the moment that build's returned registry drops. The mirror
    /// hazard: the retained cell's snapshot still names proxies the swapped
    /// map removed, so a stale front-hop name resolves instead of failing.
    /// Production paths never call this — only tests do.
    ///
    /// `dialer_registry` is the registry generation the build published
    /// `proxies` into — the route table must own it, or the map's
    /// `dialer-proxy` chains lose their cell and fail closed (issue #533
    /// review).
    pub fn update_proxies(
        &self,
        proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
    ) {
        // Preserve the current rules + index via Arc refcount bumps. Held
        // as a single write section so a concurrent `update_rules` cannot
        // be lost.
        {
            let mut route = self.inner.route.write();
            let new_route = RouteTable {
                rules: Arc::clone(&route.rules),
                domain_index: Arc::clone(&route.domain_index),
                compiled_rules: Arc::clone(&route.compiled_rules),
                proxies,
                dialer_registry,
            };
            *route = Arc::new(new_route);
        }
        info!("Proxies updated");
    }

    /// Publish a complete rules/proxies snapshot, preserving active TCP flows.
    /// Use this instead of successive partial updates for a config rebuild.
    ///
    /// `dialer_registry` is the registry the rebuild published `proxies`
    /// into; the route table owns it so the map's `dialer-proxy` chains keep
    /// resolving while this generation lives (issue #533).
    pub fn update_routing(
        &self,
        proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
        rules: Vec<Box<dyn Rule>>,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
    ) {
        drop(self.install_routing(Arc::new(RouteTable::new(proxies, rules, dialer_registry))));
        info!("Routing configuration updated");
    }

    /// Immediately cancel tracked TCP flows and publish new routing state.
    ///
    /// Compilation finishes before admission is locked. Registration either
    /// precedes cancellation, or detects the changed generation and refuses
    /// the old routing decision (including a decision delayed by DNS). New
    /// setup can capture the new generation only after publication completes.
    /// Returns closure requests for tracked TCP flows, not completed teardowns;
    /// unregistered setups are rejected later and UDP sessions are unaffected.
    ///
    /// `dialer_registry` is the registry generation the build published
    /// `proxies` into; the new route table owns it so the map's `dialer-proxy`
    /// chains keep resolving while this generation lives (issue #533).
    pub fn reload_routing(
        &self,
        proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
        rules: Vec<Box<dyn Rule>>,
        mode: Option<TunnelMode>,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
    ) -> usize {
        let route = Arc::new(RouteTable::new(proxies, rules, dialer_registry));
        let mut generation = self.inner.tcp_generation.write();
        *generation = generation.checked_add(1).expect("TCP generation exhausted");
        let closed = self.inner.stats.close_all_connections_counted();
        let old = self.install_routing(route);
        if let Some(mode) = mode {
            self.set_mode(mode);
        }
        drop(generation);
        // Releasing a large old rule set must not hold up TCP admission.
        drop(old);
        info!("Routing configuration reloaded");
        closed
    }

    fn install_routing(&self, route: Arc<RouteTable>) -> Arc<RouteTable> {
        let needs_ip = route.compiled_rules.needs_ip_resolution();
        let needs_process = route.compiled_rules.needs_process_lookup();
        let mut current = self.inner.route.write();
        self.inner
            .needs_ip_resolution
            .store(needs_ip, Ordering::Relaxed);
        self.inner
            .needs_process_lookup
            .store(needs_process, Ordering::Relaxed);
        std::mem::replace(&mut *current, route)
    }

    pub fn statistics(&self) -> &Arc<Statistics> {
        &self.inner.stats
    }

    /// Snapshot the current resolver generation (one short read lock +
    /// `Arc` clone). Reflects the latest [`Self::set_resolver`] — callers
    /// holding the returned `Arc` keep that generation; the next call picks
    /// up any swap.
    pub fn resolver(&self) -> Arc<Resolver> {
        self.inner.resolver()
    }

    /// The shared resolver slot. Pass clones to `rebuild_from_raw_*` and
    /// the TUN loopback DNS so every consumer — including each rebuilt
    /// `DIRECT` adapter — tracks `set_resolver` swaps (issue #514).
    pub fn resolver_slot(&self) -> meow_dns::ResolverSlot {
        Arc::clone(&self.inner.resolver)
    }

    /// Reconcile health-check tasks with a committed config's proxy-group
    /// specs (issue #514): new fallback/url-test groups get a task,
    /// removed groups are aborted, changed specs are respawned, dead tasks
    /// are restarted. Specs come from
    /// `meow_config::extract_health_check_specs`; call on every config
    /// commit — startup, `PUT /configs`, section mutations, subscription
    /// refresh.
    pub fn reconcile_health_checks(&self, specs: &[meow_common::HealthCheckSpec]) {
        self.inner
            .health_checks
            .lock()
            .reconcile(&self.inner, specs);
    }

    /// Publish a rebuilt DNS resolver (issue #514): routing lookups
    /// (fake-IP checks, pre-resolve, lazy resolve), the built-in DIRECT
    /// adapter's hostname resolution, and any component taking
    /// `resolver()` snapshots all pick up the new generation. Previously
    /// the resolver was fixed at `Tunnel::new`, so `PUT /configs`
    /// persisted a new `dns:` section while the process kept resolving
    /// through the old one.
    pub fn set_resolver(&self, resolver: Arc<Resolver>) {
        // One write updates the routing snapshot, `inner.direct`, and every
        // rebuilt `DIRECT` — they all share this slot.
        *self.inner.resolver.write() = resolver;
    }

    /// Snapshot of the current route table (rules + domain index + proxies).
    ///
    /// One short read lock + refcount bump; callers iterate
    /// `snapshot.proxies` / `snapshot.rules` in place. Replaces the old
    /// `proxies()` accessor, which cloned the whole proxy map on every call
    /// (audit #182).
    pub fn route_snapshot(&self) -> Arc<RouteTable> {
        self.inner.route()
    }

    pub fn proxy(&self, name: &str) -> Option<Arc<dyn Proxy>> {
        self.inner.route.read().proxies.get(name).cloned()
    }

    /// Spawn background tasks owned by the tunnel (currently just the UDP NAT
    /// sweeper). Idempotent callers should only invoke this once per process.
    pub fn spawn_background_tasks(&self) {
        udp::spawn_nat_sweeper(
            &self.inner.nat_table,
            udp::DEFAULT_UDP_IDLE,
            udp::DEFAULT_SWEEP_INTERVAL,
        );
    }

    /// Store a running TUN listener handle. If a previous TUN listener was
    /// running, it is aborted and awaited — including its lwIP core's
    /// teardown — before this returns (issue #514).
    pub async fn set_tun_handle(&self, handle: TunHandle) {
        let prev = self.inner.tun_handle.write().replace(handle);
        // parking_lot RwLock write guard is dropped here — safe to .await
        if let Some(TunHandle { task, core_done }) = prev {
            task.abort();
            // Await the parent: dropping its future drops the TaskGroup,
            // which requests abort of the child tasks holding the device.
            // The runtime reaps those tasks asynchronously — the lwIP core
            // only finishes teardown once their stack halves drop, so
            // await `core_done` too: this returns only once the previous
            // generation is truly gone.
            let _ = task.await;
            if let Some(done) = core_done {
                await_core_done(done).await;
            }
            info!("abandoned previous TUN listener");
        }
        info!("TUN listener handle stored");
    }

    /// Abort the running TUN listener, if any, and wait for teardown —
    /// including the lwIP core's `core_done`, so a successor
    /// `NetStack::new` can never overlap this generation (issue #514).
    pub async fn stop_tun(&self) {
        let handle = self.inner.tun_handle.write().take();
        // parking_lot RwLock write guard is dropped here — safe to .await
        if let Some(TunHandle { task, core_done }) = handle {
            task.abort();
            let _ = task.await;
            if let Some(done) = core_done {
                await_core_done(done).await;
            }
            info!("TUN listener stopped");
        }
    }

    /// Returns `true` when a TUN listener is currently running. A stored
    /// handle whose task has already exited (e.g. a pump failure after a
    /// successful start) counts as *not* running, so `GET /configs` never
    /// reports a dead listener as enabled.
    pub fn has_tun(&self) -> bool {
        self.inner
            .tun_handle
            .read()
            .as_ref()
            .is_some_and(|h| !h.task.is_finished())
    }
}

impl Clone for Tunnel {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::DnsMode;
    use meow_dns::Resolver;
    use meow_trie::DomainTrie;

    fn test_tunnel() -> Tunnel {
        let resolver = Arc::new(Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        ));
        Tunnel::new(resolver)
    }

    #[test]
    fn routing_rebuild_keeps_old_snapshot_until_candidate_is_ready() {
        use meow_common::{RuleMatchHelper, RuleType};
        use std::sync::mpsc::{self, Receiver, SyncSender};
        use std::time::Duration;

        // Pause real rule compilation, after the caller has supplied both
        // the replacement proxies and rules. A split publication exposes
        // new proxies with old rules during precisely this interval.
        struct PausedRule(parking_lot::Mutex<Option<(SyncSender<()>, Receiver<()>)>>);
        impl Rule for PausedRule {
            fn rule_type(&self) -> RuleType {
                RuleType::Match
            }
            fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
                true
            }
            fn adapter(&self) -> &str {
                "NEW"
            }
            fn payload(&self) -> &str {
                if let Some((entered, resume)) = self.0.lock().take() {
                    entered.send(()).unwrap();
                    resume.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                ""
            }
        }

        for cold in [false, true] {
            let tunnel = test_tunnel();
            let proxy = meow_config::rebuild_from_raw(&Default::default())
                .unwrap()
                .proxies
                .remove("DIRECT")
                .unwrap();
            tunnel.update_routing(
                HashMap::from([("OLD".into(), Arc::clone(&proxy))]),
                vec![Box::new(meow_rules::final_rule::FinalRule::new("OLD"))],
                Default::default(),
            );
            let stats = tunnel.statistics();
            let id = stats.track_connection(
                Metadata::default(),
                "MATCH".into(),
                "".into(),
                smallvec::smallvec![],
            );
            let old = tunnel.route_snapshot();
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (resume_tx, resume_rx) = mpsc::sync_channel(1);
            let candidate: Vec<Box<dyn Rule>> = vec![Box::new(PausedRule(
                parking_lot::Mutex::new(Some((entered_tx, resume_rx))),
            ))];
            std::thread::scope(|scope| {
                let writer = scope.spawn(|| {
                    let proxies = HashMap::from([("NEW".into(), proxy)]);
                    if cold {
                        assert_eq!(
                            tunnel.reload_routing(proxies, candidate, None, Default::default()),
                            1
                        );
                    } else {
                        tunnel.update_routing(proxies, candidate, Default::default());
                    }
                });
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let during_build = tunnel.route_snapshot();
                let still_tracked = stats.active_connection_count();
                // Release the compiler before asserting, including failure paths.
                resume_tx.send(()).unwrap();
                writer.join().unwrap();
                assert!(Arc::ptr_eq(&old, &during_build));
                assert_eq!(still_tracked, 1, "compilation must precede cancellation");
            });
            let new = tunnel.route_snapshot();
            assert_eq!(new.rules[0].adapter(), "NEW");
            assert!(new.proxies.contains_key("NEW"));
            assert!(!new.proxies.contains_key("OLD"));
            assert_eq!(old.rules[0].adapter(), "OLD");
            assert!(old.proxies.contains_key("OLD"));
            assert_eq!(stats.active_connection_count(), usize::from(!cold));
            stats.close_connection(id);
        }
    }

    /// Issue #533: `RouteTable` owns the registry generation its `proxies`
    /// were published into. A chained adapter's weak `DialerTarget` resolves
    /// while the route lives — including inside a snapshot held across a
    /// later swap — and fails closed once the last owner drops.
    #[test]
    fn route_table_retains_its_dialer_registry_generation() {
        use meow_proxy::dialer::{DialerTarget, ProxyRegistry};

        let tunnel = test_tunnel();
        let front = meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .proxies
            .remove("DIRECT")
            .unwrap();
        let proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::from([("FRONT".into(), front)]);

        let registry = ProxyRegistry::default();
        // Stand-in for the weak edge every chained adapter holds.
        let target = DialerTarget::new("FRONT", &registry);
        registry.publish(Arc::new(proxies.clone()));
        tunnel.update_routing(proxies, vec![], registry);
        assert!(
            target.resolve().is_some(),
            "the route table retains its registry generation"
        );

        // A held route snapshot keeps the generation alive across a later
        // swap; the new generation's (empty) registry replaces it.
        let gen1 = tunnel.route_snapshot();
        tunnel.update_routing(HashMap::new(), vec![], ProxyRegistry::default());
        assert!(
            target.resolve().is_some(),
            "a held snapshot still retains the old generation"
        );
        drop(gen1);
        assert!(
            target.resolve().is_none(),
            "with the last owner gone the weak target must fail closed"
        );
    }

    /// Sends on drop, so a test can observe that an aborted listener task
    /// was fully torn down (not merely signalled) before the store/stop
    /// call returned.
    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    fn task_handle(task: tokio::task::JoinHandle<()>) -> TunHandle {
        TunHandle {
            task,
            core_done: None,
        }
    }

    #[tokio::test]
    async fn tun_handle_lifecycle() {
        let tunnel = test_tunnel();
        assert!(!tunnel.has_tun());

        tunnel
            .set_tun_handle(task_handle(tokio::spawn(std::future::pending::<()>())))
            .await;
        assert!(tunnel.has_tun());

        tunnel.stop_tun().await;
        assert!(!tunnel.has_tun());

        // Idempotent when no listener is running.
        tunnel.stop_tun().await;
        assert!(!tunnel.has_tun());
    }

    #[tokio::test]
    async fn set_tun_handle_aborts_and_awaits_previous() {
        let tunnel = test_tunnel();

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(async move {
            let _guard = DropSignal(Some(tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        // Make sure the first task is actually running (its drop guard is
        // constructed) before it gets replaced.
        started_rx.await.unwrap();
        tunnel.set_tun_handle(task_handle(first)).await;

        tunnel
            .set_tun_handle(task_handle(tokio::spawn(std::future::pending::<()>())))
            .await;
        // set_tun_handle awaited the first task, so its drop guard has
        // already fired by the time it returns.
        assert!(rx.try_recv().is_ok());
        assert!(tunnel.has_tun());

        tunnel.stop_tun().await;
    }

    /// Issue #514: `stop_tun` must not return before the generation's
    /// `core_done` signal fires — the next `NetStack::new` depends on the
    /// previous core being fully torn down.
    #[tokio::test]
    async fn stop_tun_awaits_core_done() {
        let tunnel = test_tunnel();

        let (done_tx, done_rx) = tokio::sync::watch::channel(false);
        let (task_started_tx, task_started_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = task_started_tx.send(());
            std::future::pending::<()>().await;
        });
        task_started_rx.await.unwrap();
        tunnel
            .set_tun_handle(TunHandle {
                task,
                core_done: Some(done_rx),
            })
            .await;

        // Stop in a task so we can observe it pending on core_done.
        let stop = tokio::spawn({
            let tunnel = tunnel.clone();
            async move { tunnel.stop_tun().await }
        });
        tokio::task::yield_now().await;
        assert!(
            !stop.is_finished(),
            "stop_tun must wait on core_done, not just the parent task"
        );

        done_tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), stop)
            .await
            .expect("stop_tun must return once core_done fires")
            .unwrap();
        assert!(!tunnel.has_tun());
    }

    #[tokio::test]
    async fn has_tun_reports_dead_listener_as_stopped() {
        let tunnel = test_tunnel();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tunnel
            .set_tun_handle(task_handle(tokio::spawn(async move {
                let _ = rx.await;
            })))
            .await;
        assert!(tunnel.has_tun());

        // Let the task exit on its own (simulating a runtime crash of the
        // listener) — has_tun must flip to false without stop_tun.
        let _ = tx.send(());
        for _ in 0..100 {
            if !tunnel.has_tun() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!tunnel.has_tun());
    }
    #[tokio::test(start_paused = true)]
    async fn background_tasks_do_not_sample_traffic_without_api_subscriber() {
        let tunnel = test_tunnel();
        tunnel.statistics().add_upload(123);
        tunnel.statistics().add_download(456);
        tunnel.spawn_background_tasks();

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        assert_eq!(
            tunnel.statistics().traffic_snapshot(),
            (0, 0, 0, 0),
            "the API traffic feed owns sampling; an idle tunnel has no 1 Hz sampler"
        );
        assert_eq!(tunnel.statistics().snapshot(), (123, 456));
    }
}
