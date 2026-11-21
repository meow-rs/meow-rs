use crate::match_engine::DomainIndex;
use crate::rule_ir::{CompiledMatchResult, CompiledRuleSet, DemandGate, LazyMatchOutcome};
use crate::statistics::Statistics;
use crate::udp::{self, NatTable};
use meow_common::conn_note;
use meow_common::conn_notes::ConnNotes;
use meow_common::{
    is_valid_host, metadata_ip_literal, AdapterType, Metadata, Network, ProcessInfo,
    ProcessLookupMode, ProcessLookupPolicy, Proxy, ProxyAdapter, Rule, TargetCheck, TargetProbe,
    TunnelMode,
};
use meow_dns::Resolver;
use meow_proxy::DirectAdapter;
use parking_lot::{Mutex, RwLock};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
/// One named `sub-rules:` block as a scannable table — the shared rule
/// vector plus the compiled matcher built for it through the same engine
/// as the top-level rules (the per-block `DomainIndex` rides inside
/// `compiled` like the main set's). There is deliberately no per-index
/// disable state: blocks have no `/rules` surface of their own, so a
/// block-local index must never alias a top-level counter or switch.
pub struct SubRuleRoute {
    /// The block's rules — the same `Arc` `SUB-RULE` rule objects and the
    /// config parser's `SubRuleBlocks` map hold.
    pub rules: Arc<Vec<Box<dyn Rule>>>,
    /// The compiled matcher for `rules`.
    pub compiled: CompiledRuleSet,
}

pub struct RouteTable {
    pub rules: Arc<Vec<Box<dyn Rule>>>,
    pub domain_index: Arc<DomainIndex>,
    pub compiled_rules: Arc<CompiledRuleSet>,
    /// `sub-rules:` blocks a named listener's `rule:` override selects by
    /// name. Published inside the same snapshot as `rules`/`proxies` so a
    /// flow never observes a block and a route that disagree.
    pub sub_rules: Arc<HashMap<SmolStr, SubRuleRoute>>,
    /// Shared so routing installs can republish the map into the
    /// provider-node dialer registry (`publish_dialer_registry`) with an
    /// Arc bump instead of a full map clone (issue #489 review).
    pub proxies: Arc<HashMap<SmolStr, Arc<dyn Proxy>>>,
    /// The registry generation `proxies` was published into. Retained so the
    /// `dialer-proxy` front-hop lookups the map's adapters perform keep
    /// resolving for exactly as long as this route table lives — the adapters
    /// hold the registry cell weakly (issue #533), so without this owner the
    /// snapshot would drop while the adapters are still dialable.
    pub dialer_registry: meow_proxy::dialer::ProxyRegistry,
    /// Hit counters and disabled switches for `rules`, index for index;
    /// replaced together with `rules`, kept across a proxies-only swap.
    pub rule_stats: Arc<crate::rule_stats::RuleStats>,
}

impl RouteTable {
    /// A table for `rules`, carrying the per-rule state (disabled switch,
    /// hits) of equal rules over from `prior` — a commit or subscription
    /// refresh must not re-enable what a dashboard turned off.
    fn new(
        proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
        rules: Vec<Box<dyn Rule>>,
        sub_rules: HashMap<String, meow_rules::sub_rule::SubRuleBlock>,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
        prior: Option<&RouteTable>,
    ) -> Self {
        let rule_stats = prior.map_or_else(
            || crate::rule_stats::RuleStats::new(rules.len()),
            |p| crate::rule_stats::RuleStats::carried(&p.rules, &p.rule_stats, &rules),
        );
        let domain_index = DomainIndex::build(&rules);
        let compiled_rules = CompiledRuleSet::build_masked(&rules, |i| rule_stats.is_disabled(i));
        let sub_rules = compile_sub_rule_routes(sub_rules);
        Self {
            rule_stats: Arc::new(rule_stats),
            rules: Arc::new(rules),
            domain_index: Arc::new(domain_index),
            compiled_rules: Arc::new(compiled_rules),
            sub_rules: Arc::new(sub_rules),
            proxies: Arc::new(proxies),
            dialer_registry,
        }
    }

    fn empty() -> Self {
        Self {
            rules: Arc::new(Vec::new()),
            domain_index: Arc::new(DomainIndex::empty()),
            compiled_rules: Arc::new(CompiledRuleSet::empty()),
            sub_rules: Arc::new(HashMap::new()),
            proxies: Arc::new(HashMap::new()),
            dialer_registry: meow_proxy::dialer::ProxyRegistry::default(),
            rule_stats: Arc::default(),
        }
    }

    /// A copy with every field shared — the partial-update sites build a
    /// table via `RouteTable { changed: …, ..prior.inherit() }` so the
    /// single field list here, not three struct literals, is what a new
    /// field or init step must join (issue #882 review).
    fn inherit(&self) -> Self {
        Self {
            rules: Arc::clone(&self.rules),
            domain_index: Arc::clone(&self.domain_index),
            compiled_rules: Arc::clone(&self.compiled_rules),
            sub_rules: Arc::clone(&self.sub_rules),
            proxies: Arc::clone(&self.proxies),
            dialer_registry: self.dialer_registry.clone(),
            rule_stats: Arc::clone(&self.rule_stats),
        }
    }

    /// Whether the TOP-LEVEL rule set demands a resolved `dst_ip`.
    /// Feeds the `needs_ip_resolution` atomic `pre_resolve` consults for
    /// flows that scan the main table. A `sub-rules:` block's demand is
    /// deliberately not folded in: only a `rule:`-override flow can scan
    /// its block, so [`TunnelInner::pre_resolve`] reads the demand of the
    /// block the flow actually selected instead of holding unrelated
    /// flows on the resolver.
    fn needs_ip_resolution(&self) -> bool {
        self.compiled_rules.needs_ip_resolution()
    }
}

/// Compile each `sub-rules:` block for a route snapshot — shared by
/// [`RouteTable::new`] and the rules-only republish
/// ([`Tunnel::update_rules_with_sub_rules`]) so both produce identical
/// `SubRuleRoute`s.
fn compile_sub_rule_routes(
    sub_rules: HashMap<String, meow_rules::sub_rule::SubRuleBlock>,
) -> HashMap<SmolStr, SubRuleRoute> {
    sub_rules
        .into_iter()
        .map(|(name, block)| {
            (
                SmolStr::from(name),
                SubRuleRoute {
                    compiled: CompiledRuleSet::build(&block),
                    rules: block,
                },
            )
        })
        .collect()
}

/// Whether [`Tunnel::flush_for_outbound_interface_change`] cancels tracked
/// TCP flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackedTcp {
    /// Cancel them — the warm reload path ([`Tunnel::update_routing`])
    /// preserves tracked TCP.
    Cancel,
    /// The caller already did ([`Tunnel::reload_routing`]).
    AlreadyCancelled,
}

/// What [`Tunnel::flush_for_outbound_interface_change`] tore down.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboundFlush {
    /// Tracked TCP flows cancelled (0 for [`TrackedTcp::AlreadyCancelled`]).
    pub tcp: usize,
    /// UDP sessions closed — see [`Tunnel::close_all_udp_sessions`].
    pub udp: usize,
    /// Idle pooled upstream DNS connections of the live resolver dropped.
    pub dns: usize,
    /// Distinct adapters (groups included) whose sessions were reset.
    pub adapters: usize,
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
    /// Live `find-process-mode` (issue #974): whether routing may walk the
    /// OS socket table for a flow's owner — `always` / `strict` / `off`.
    /// Per-tunnel and shared with the traffic ledger's app-lookup lane, so
    /// `off` suppresses queued ledger scans too.
    process_policy: Arc<ProcessLookupPolicy>,
    /// Test seam: a deterministic counted replacement for the platform
    /// socket-table scan in [`Self::flow_process`]. `None` in production.
    #[cfg(test)]
    process_lookup_hook: Mutex<Option<ProcessLookupHook>>,
    /// The config's `profile.store-selected` persistence owner — set once
    /// at startup from `Config::selection`; every rebuild lane reads it so
    /// groups share one store and one enable epoch (issue #974). Empty
    /// OnceLock → `SelectionBacking::unpersisted()` semantics via the
    /// getter's fallback (tests/embedders never install one).
    selection_backing: std::sync::OnceLock<Arc<meow_proxy::SelectionBacking>>,
    /// Handle to the running TUN listener (if any). Abort + await it to
    /// stop TUN. Stored so `put_configs` can start/stop TUN at runtime.
    pub tun_handle: RwLock<Option<TunHandle>>,
    /// Health-check task set keyed by group name; reconciled on every
    /// config commit so checks appear/disappear/respawn with the config
    /// (issue #514).
    pub health_checks: Mutex<crate::health_check::HealthCheckSupervisor>,
    /// Registry that provider-sourced nodes' `dialer-proxy` targets resolve
    /// against (issue #489). Installed once at startup from `Config` (which
    /// shares the same handle into every `ProxyProvider`); every routing
    /// install republishes the live proxies map into it so provider nodes —
    /// which persist across config rebuilds — always resolve current names.
    dialer_registry: std::sync::OnceLock<meow_proxy::dialer::ProxyRegistry>,
    /// UDP flush signal (issue #695): bumped by
    /// [`Tunnel::close_all_udp_sessions`]; every listener-owned UDP flow
    /// holds a receiver ([`udp::UdpFlushWatch`]).
    udp_flush: tokio::sync::watch::Sender<u64>,
    /// Record per-connection notes — see [`Tunnel::set_connection_notes`].
    connection_notes: AtomicBool,
    /// Whole-connection relay idle timeout in seconds — see
    /// [`Tunnel::set_tcp_idle_timeout`]. `0` disables the bound. Read once
    /// per relay setup; relays already in flight keep the bound they
    /// started with (same per-connection semantics as every per-conn knob).
    tcp_idle_timeout: AtomicU64,
}

/// Which configuration surface owns a stored [`TunHandle`]: the
/// top-level `tun:` section's live reconcile (PUT/PATCH start, stop and
/// restart) or a `listeners:` `type: tun` entry — a startup-snapshot
/// object the top-level paths must never stop, replace, or report as
/// `tun.enable` (spec: one effective TUN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunOwner {
    /// Spawned from the top-level `tun:` section — the config-mutation
    /// reconcile owns its lifecycle.
    TopLevel,
    /// Spawned from the named `listeners:` entry of this name; its
    /// lifecycle belongs to process startup only.
    Named(String),
}

/// A running TUN listener: the task plus the signal resolving once its
/// lwIP core has fully torn down.
///
/// The lwIP contract allows only one live stack generation per process;
/// the core finishes teardown only after every stack handle — including
/// the split halves inside the device pumps — is dropped. Since an aborted
/// parent task cannot await that reaping, `stop_tun`/`set_tun_handle`/
/// `teardown_tun_handle` additionally await `core_done` so a successor
/// generation cannot overlap a core still tearing down (issue #514).
pub struct TunHandle {
    /// The listener task — abort + await it to stop.
    pub task: tokio::task::JoinHandle<()>,
    /// Which surface spawned this listener — gates which lifecycle paths
    /// may act on the stored slot ([`TunOwner`]).
    pub owner: TunOwner,
    /// Flips `true` once this generation's lwIP core finished teardown.
    /// `None` for non-lwIP/test handles that have no core to await.
    pub core_done: Option<tokio::sync::watch::Receiver<bool>>,
    /// Live TUN UDP flow-table occupancy (issue #515). A stub zeroed
    /// gauge for non-lwIP/test handles.
    pub udp_flows: Arc<std::sync::atomic::AtomicUsize>,
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

/// Abort a TUN listener's task and await real teardown — including the
/// lwIP core's `core_done`, so a successor `NetStack::new` can never
/// overlap this generation (issue #514). Shared by `stop_tun`,
/// `set_tun_handle`'s previous-generation teardown, and
/// `teardown_tun_handle` for handles that were never stored.
async fn teardown_tun(handle: TunHandle) {
    let TunHandle {
        task, core_done, ..
    } = handle;
    task.abort();
    // Await the parent: dropping its future drops the TaskGroup, which
    // requests abort of the child tasks holding the device. The runtime
    // reaps those tasks asynchronously — the lwIP core only finishes
    // teardown once their stack halves drop, so await `core_done` too:
    // this returns only once the generation is truly gone.
    let _ = task.await;
    if let Some(done) = core_done {
        await_core_done(done).await;
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

    /// Subscribe a UDP flow to [`Tunnel::close_all_udp_sessions`] (issue
    /// #695). Take it before dialling the flow's outbound; see
    /// [`udp::UdpFlushWatch`].
    pub fn udp_flush_watch(&self) -> udp::UdpFlushWatch {
        udp::UdpFlushWatch::new(self.udp_flush.subscribe())
    }

    /// The whole-connection relay idle bound [`Tunnel::set_tcp_idle_timeout`]
    /// installed, resolved for one relay's use: `None` when the bound is
    /// disabled (`tcp-idle-timeout: 0` or never set programmatically).
    pub fn tcp_idle_timeout(&self) -> Option<std::time::Duration> {
        match self.tcp_idle_timeout.load(Ordering::Relaxed) {
            0 => None,
            secs => Some(std::time::Duration::from_secs(secs)),
        }
    }

    /// The note log a new connection should record into: the inbound's own
    /// when it opened a [`ConnNotes`] scope, a fresh one when notes are on
    /// (see [`Tunnel::set_connection_notes`]), else `None`.
    pub fn connection_notes(&self) -> Option<ConnNotes> {
        ConnNotes::current().or_else(|| {
            (self.connection_notes.load(Ordering::Relaxed) && !self.stats.is_headless())
                .then(ConnNotes::new)
        })
    }

    /// Rewrite a fake-IP destination back to its real hostname before rule
    /// matching. Mirrors upstream `preHandleMetadata` in
    /// `tunnel/tunnel.go`. Every inbound that can dial calls this before
    /// [`Self::pre_resolve`]; outside fake-IP mode it is a no-op except
    /// for the snooping-cache hostname fill-in.
    ///
    /// After a fake-IP rewrite the metadata has:
    /// - `metadata.host` ← real domain recovered from the pool reverse map
    /// - `metadata.dst_ip` ← `None`, so `pre_resolve` (or the adapter)
    ///   re-resolves to a real address via the configured DNS path
    ///
    /// Returns [`PreHandleVerdict::Drop`] when the destination is inside a
    /// fake-IP range with no live allocation and no recoverable hostname —
    /// dialing the stale literal loops back into the TUN device and
    /// self-saturates `max-connections`; every caller must honour the
    /// verdict (issue #618, mihomo's "fake DNS record missing").
    ///
    /// Also returns [`PreHandleVerdict::Drop`] when the flow's name is not
    /// a hostname ([`is_valid_host`]): `host` as the inbound filled it, or
    /// the name a fake IP maps back to (a DNS query name is raw label
    /// bytes). Such a name matches rules differently from how an
    /// authority-shaped outbound peer parses it (`a@evil.com` misses
    /// `DOMAIN,evil.com` but reads as `evil.com` in a CONNECT line,
    /// issue #734). The listeners refuse these at ingress with their own
    /// protocol error; this is the backstop for every path that reaches
    /// the tunnel. A snooped or sniffed name that is not a hostname is
    /// simply not used.
    ///
    /// Deliberate divergences from upstream `preHandleMetadata`:
    /// - an IP literal in `host` is folded into `dst_ip` first
    ///   (`fixMetadata` parity), so a domain-typed literal (SOCKS5
    ///   `ATYP_DOMAIN "198.18.0.9"`) cannot slip past the range check;
    /// - the range check includes the pool gateway/broadcast — upstream
    ///   excludes them because its TUN device *is* the gateway, while
    ///   ours is a separate subnet and a gateway dial loops the same;
    /// - a sniffed name (`sniff_host`) rescues a stale flow — upstream
    ///   re-runs `TCPSniff` on exactly this failure; promoting the
    ///   observed name matches that rescue and additionally clears the
    ///   stale `dst_ip` upstream would keep;
    /// - the same rescue covers another resolver's fake IP: a destination
    ///   in 198.18.0.0/15 outside our range (a LAN Surge or Clash gateway
    ///   answered DNS while the tunnel was down) dials the sniffed name and
    ///   drops the literal whatever `override-destination` says, also when
    ///   the inbound already promoted that name into `host`. Upstream gets
    ///   there through its default `override-destination: true`, whose
    ///   `replaceDomain` clears the IP too; a snooped name and real
    ///   addresses keep their literal.
    pub fn pre_handle_metadata(&self, metadata: &mut Metadata) -> PreHandleVerdict {
        // `fixMetadata` parity: an IP literal in `host` IS the
        // destination, not a name — fold it into `dst_ip` so a
        // domain-typed literal cannot slip past the range check below.
        // The host is cleared even when `dst_ip` is already set — HTTP
        // `CONNECT [::1]` fills both fields, and a literal reaching
        // host-first encoders as a domain is never usable (#701).
        if let Some(ip) = metadata_ip_literal(&metadata.host) {
            if metadata.dst_ip.is_none() {
                metadata.dst_ip = Some(ip);
            }
            metadata.host = SmolStr::default();
        }
        if !metadata.host.is_empty() && !is_valid_host(&metadata.host) {
            debug!(
                "pre_handle_metadata: drop non-hostname host {:?}",
                metadata.host
            );
            conn_note!(
                Connection,
                "Destination {:?} is not a hostname; dropped",
                metadata.host
            );
            return PreHandleVerdict::Drop;
        }
        // Unmap `::ffff:a.b.c.d` so a mapped literal still hits the
        // fake-IP range check and v4 rules (`fixMetadata` parity).
        let Some(ip) = metadata.dst_ip.map(|ip| ip.to_canonical()) else {
            return PreHandleVerdict::Continue;
        };
        metadata.dst_ip = Some(ip);
        let resolver = self.resolver();
        if resolver.in_fake_ip_range(ip) {
            match resolver.reverse_lookup(ip) {
                Some(host) if !is_valid_host(&host) => {
                    debug!("pre_handle_metadata: drop fake-ip {ip} → non-hostname {host:?}");
                    conn_note!(
                        Dns,
                        "Fake IP {ip} maps to {host:?}, which is not a hostname; dropped"
                    );
                    return PreHandleVerdict::Drop;
                }
                Some(host) => {
                    debug!("pre_handle_metadata: fake-ip {ip} → {host}");
                    conn_note!(Dns, "Fake IP {ip} maps to {host}");
                    // The live allocation wins routing and the dial: a
                    // sniffed name that differs is discarded so
                    // `rule_host()` returns the mapped name rather than
                    // another domain's. A sniffed name that matches
                    // (modulo a trailing dot — its FQDN spelling) is
                    // kept verbatim for the API's sniffHost field.
                    if sniff_conflicts(&metadata.sniff_host, &host) {
                        metadata.sniff_host = Default::default();
                    }
                    metadata.host = host;
                    metadata.dst_ip = None;
                }
                None => {
                    // In range with no live allocation — a stale pool row
                    // (expired, wrap-evicted, wiped by restart) or a
                    // literal dial into the range. Rescue only via a real
                    // name — listener-supplied `host`, else a sniffed one
                    // (upstream re-runs `TCPSniff` on exactly this
                    // failure). An IP literal is the stale address in
                    // disguise and was already folded out above, so a
                    // surviving `host` here is a genuine name.
                    if metadata.host.is_empty() && is_sniffed_name(metadata) {
                        metadata.host = metadata.sniff_host.clone();
                    } else if sniff_conflicts(&metadata.sniff_host, &metadata.host) {
                        // A surviving `host` names the dial target, so a
                        // sniffed name that differs is discarded —
                        // `rule_host()` must not route the flow by a
                        // different domain than the one being dialed. An
                        // equal (modulo a trailing dot) sniffed name is
                        // kept verbatim for the API's sniffHost field.
                        metadata.sniff_host = Default::default();
                    }
                    if metadata.host.is_empty() {
                        debug!("pre_handle_metadata: drop unmapped fake-ip {ip}");
                        conn_note!(
                            Dns,
                            "Fake IP {ip} has no live mapping and the flow carries no \
                             name; dropped"
                        );
                        return PreHandleVerdict::Drop;
                    }
                    conn_note!(
                        Dns,
                        "Fake IP {ip} has no live mapping; using the name {}",
                        metadata.host
                    );
                    metadata.dst_ip = None;
                }
            }
            return PreHandleVerdict::Continue;
        }
        // Outside fake-IP mode — also fold in a snooping-cache hostname
        // if metadata.host is currently empty. Preserves the upstream
        // `DNSMapping` mode contract used by the tproxy listener.
        let mut snooped = false;
        if metadata.host.is_empty() {
            if let Some(host) = resolver.reverse_lookup(ip).filter(|h| is_valid_host(h)) {
                conn_note!(Dns, "{ip} was resolved earlier for {host}; using that name");
                metadata.host = host;
                // mihomo `DNSMapping`: the name is only a label for the
                // client-chosen address, so a DIRECT UDP dial keeps
                // `dst_ip` rather than re-resolving it via
                // `dns.direct-nameserver` (upstream `Metadata.Pure()`).
                metadata.dns_mode = meow_common::DnsMode::Mapping;
                snooped = true;
            }
        }
        // Another resolver's fake IP: a LAN gateway (Surge, a second
        // Clash) answered a DNS query while this tunnel was out of the
        // path. Only that resolver can map it back and the range is never
        // routable on the internet, so a proxy dialing the literal
        // black-holes the flow. A sniffed name is the only usable target,
        // and the literal must go even when the inbound already promoted
        // the name (`override-destination: true`, the tproxy listener):
        // DIRECT dials `dst_ip` first and `pre_resolve` skips a flow that
        // has one, so IP rules would match the fake address.
        if !snooped
            && is_benchmarking_ip(ip)
            && is_sniffed_name(metadata)
            && (metadata.host.is_empty() || metadata.host == metadata.sniff_host)
        {
            conn_note!(
                Dns,
                "{ip} is a fake IP from another resolver (198.18.0.0/15); \
                 dialing the sniffed name {} instead",
                metadata.sniff_host
            );
            metadata.host = metadata.sniff_host.clone();
            metadata.dst_ip = None;
        }
        PreHandleVerdict::Continue
    }

    /// Whether [`Self::pre_handle_metadata`] can route `metadata` only by a
    /// name sniffed from its first bytes: its destination IP is an
    /// unmapped address in our own fake-IP range (dropped otherwise) or
    /// another resolver's fake IP in 198.18.0.0/15 with no snooped name
    /// (black-holed otherwise), and the inbound has not sniffed a name
    /// yet. Every other flow already has a name, or is a real address that
    /// dials as-is. Gates the sniff in [`crate::tcp::handle_tcp`].
    pub(crate) fn needs_sniffed_name(&self, metadata: &Metadata) -> bool {
        if is_sniffed_name(metadata)
            || (!metadata.host.is_empty() && metadata_ip_literal(&metadata.host).is_none())
        {
            return false;
        }
        let Some(ip) = metadata
            .dst_ip
            .or_else(|| metadata_ip_literal(&metadata.host))
            .map(|ip| ip.to_canonical())
        else {
            return false;
        };
        let resolver = self.resolver();
        let unmapped = if resolver.in_fake_ip_range(ip) {
            // Allocation-free answer for the common case, a live mapping.
            !resolver.is_fake_ip(ip)
        } else {
            is_benchmarking_ip(ip)
        };
        unmapped && resolver.reverse_lookup(ip).is_none()
    }

    /// Pre-process metadata before rule matching: if the rule set this
    /// flow will scan needs IP resolution and we don't yet have a
    /// destination IP, resolve `metadata.host` via the internal resolver
    /// and populate `dst_ip`.
    ///
    /// The gate mirrors the scan `resolve_proxy_inner` runs: a
    /// `proxy:` override never reaches rule matching; a `rule:` override
    /// scans only its `sub-rules:` block, so that block's compiled demand
    /// — not the main table's — decides; anything else consults the main
    /// table's cached flag. A missing block resolves nothing (the flow
    /// rejects at resolve time anyway).
    ///
    /// `Metadata::remote_address()` prefers `host` over `dst_ip`, so
    /// overwriting `dst_ip` here does not change which destination the proxy
    /// adapter dials.
    pub async fn pre_resolve(&self, metadata: &mut Metadata) {
        if metadata.host.is_empty() || metadata.dst_ip.is_some() {
            return;
        }
        let needed = if !metadata.special_proxy().is_empty() {
            false
        } else if metadata.special_rules().is_empty() {
            self.needs_ip_resolution.load(Ordering::Relaxed)
        } else {
            self.route()
                .sub_rules
                .get(metadata.special_rules())
                .is_some_and(|b| b.compiled.needs_ip_resolution())
        };
        if !needed {
            return;
        }
        if let Some(real_ip) = self.resolver().resolve_ip_real(&metadata.host).await {
            debug!("pre_resolve: {} -> {}", metadata.host, real_ip);
            metadata.dst_ip = Some(real_ip);
        }
    }

    /// Fill the real `dst_ip` UDP needs for its NAT key and outbound packet
    /// API, after [`Self::pre_resolve`] (which only runs when rules demand
    /// an IP).
    ///
    /// The main nameservers answer first. When they cannot and
    /// `dns.direct-nameserver` is configured, a flow whose route ends at a
    /// DIRECT/COMPATIBLE hop resolves through the direct resolver instead:
    /// its dial never consults the main nameservers (mihomo's direct
    /// `ListenPacketContext` resolves via `DirectHostResolver`), so a
    /// main-side failure must not drop it. Other routes never reach the
    /// direct resolver, which keeps proxied names off that upstream.
    pub async fn resolve_udp_dst(&self, metadata: &mut Metadata) {
        if metadata.dst_ip.is_some() || metadata.host.is_empty() {
            return;
        }
        let resolver = self.resolver();
        metadata.dst_ip = resolver.resolve_ip_real(&metadata.host).await;
        if metadata.dst_ip.is_some() {
            return;
        }
        let Some(direct) = resolver.direct_resolver().map(Arc::clone) else {
            return;
        };
        // Probe only — "does this route end DIRECT?" — so it must not
        // record the hit `resolve_proxy` counts: every UDP caller resolves
        // for real right after (a double hit per flow), and a packet this
        // probe leaves undialling would still have tallied (issue #882
        // review). The probe runs on a clone: its rematch transitions
        // stamp `rematch_name`, which only the kept resolution may write.
        // The shared `flow_lookup` memo still carries across.
        let mut probe_metadata = metadata.clone();
        let Some(target) = self.resolve_proxy_inner(&mut probe_metadata, false).await else {
            return;
        };
        if !routes_direct(target.adapter.as_ref(), &probe_metadata) {
            return;
        }
        metadata.dst_ip = direct.resolve_ip_real(&metadata.host).await;
        if let Some(ip) = metadata.dst_ip {
            debug!(
                "resolve_udp_dst: {} -> {} via direct-nameserver",
                metadata.host, ip
            );
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
    ///
    /// `async` because the PROCESS-* enrichment runs the platform socket scan
    /// on the blocking pool — keeping it synchronous here would stall the
    /// calling worker on hosts with large socket tables (issue #515).
    ///
    /// Read-only callers get correct routing but no `always`-mode write-back:
    /// enrichment lands on the private copy, matching sees it, tracking does
    /// not. The tracked-metadata variant is [`Self::resolve_proxy_flow`].
    pub async fn resolve_proxy(&self, metadata: &Metadata) -> Option<ResolvedTarget> {
        let mut owned = metadata.clone();
        self.resolve_proxy_inner(&mut owned, true).await
    }

    /// [`Self::resolve_proxy`] on the caller's own metadata — the real
    /// dispatch entry point (upstream `resolveMetadata`): under
    /// `find-process-mode: always` the flow's owning process is looked up
    /// *before* the mode dispatch and filled into this very metadata, so
    /// `/connections` and the traffic ledger see it even when no rule
    /// consumes it. Every inbound listener should prefer this.
    pub async fn resolve_proxy_flow(&self, metadata: &mut Metadata) -> Option<ResolvedTarget> {
        self.resolve_proxy_inner(metadata, true).await
    }

    /// [`Self::resolve_proxy_flow`] with the hit bookkeeping optional:
    /// `record_hit = false` for the `resolve_udp_dst` "does this route end
    /// DIRECT" probe, whose caller resolves for real right after — counting
    /// there too would double a flow's `hitCount` (and tally packets that
    /// never dial). The probe also skips `always` mode's unconditional
    /// lookup: it only spends a scan when a reached rule predicate actually
    /// needs one, sharing the flow's lookup memo either way.
    /// The listener `proxy:` override (upstream `SpecialProxy` →
    /// `proxies[NAME]`): resolved per flow against the LIVE proxy map —
    /// a group name keeps resolving its current membership and selection
    /// across route swaps, never a startup-cached adapter. `DIRECT` is
    /// unconditional like the main dispatch; a name absent from the
    /// table fails closed ("proxy NAME not found" upstream) rather than
    /// slide to DIRECT. A UDP flow whose forced target cannot relay UDP
    /// fails the same way — it must not fall back to the main rules.
    fn resolve_listener_proxy(&self, metadata: &Metadata, record_hit: bool) -> ResolvedTarget {
        let route = self.route();
        let name = metadata.special_proxy();
        // Built-ins resolve through the map like any other name: the
        // published DIRECT carries the build's resolver slot and
        // `tcp-connect-timeout`, so a forced `proxy: DIRECT` must dial
        // with the configured adapter, not the tunnel's private one
        // (which only backstops an absent map entry).
        let (adapter, action) = match route.proxies.get(name) {
            Some(p) if metadata.network == Network::Udp && !p.support_udp() => {
                warn!("listener '{name}': forced proxy does not support UDP; rejecting flow");
                (Arc::clone(&self.reject) as Arc<dyn ProxyAdapter>, "REJECT")
            }
            Some(p) => (
                Arc::clone(p) as Arc<dyn ProxyAdapter>,
                proxy_action(p.adapter_type()),
            ),
            None if name == "DIRECT" => {
                (Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>, "DIRECT")
            }
            None => {
                warn!(
                    "listener forced proxy '{name}' is not in the route table; \
                     rejecting flow (upstream: proxy {name} not found)"
                );
                (Arc::clone(&self.reject) as Arc<dyn ProxyAdapter>, "REJECT")
            }
        };
        if record_hit {
            self.stats.rule_match.increment("ListenerProxy", action);
        }
        ResolvedTarget {
            adapter,
            rule_name: SmolStr::new_static("ListenerProxy"),
            rule_payload: SmolStr::from(name),
            route,
        }
    }

    /// Listener `rule:` override when the named `sub-rules:` block is not
    /// in the route table. Deliberate divergence from upstream (which
    /// falls back to the top-level list): a configured override that
    /// vanished must not silently change egress policy — reject.
    fn missing_block_reject(
        &self,
        route: &Arc<RouteTable>,
        metadata: &Metadata,
        record_hit: bool,
    ) -> ResolvedTarget {
        let name = metadata.special_rules();
        warn!("listener sub-rules block '{name}' is not in the route table; rejecting flow");
        if record_hit {
            self.stats.rule_match.increment("ListenerProxy", "REJECT");
        }
        ResolvedTarget {
            adapter: Arc::clone(&self.reject) as Arc<dyn ProxyAdapter>,
            rule_name: SmolStr::new_static("ListenerProxy"),
            rule_payload: SmolStr::from(name),
            route: Arc::clone(route),
        }
    }

    /// The `(rules, compiled, stats)` a rule-mode scan runs over for the
    /// active block name — the named `sub-rules` block, or the top-level
    /// set on `""`. `Err(())` = the named block is missing from the
    /// table; the caller decides the failure mode (listener-seeded
    /// selections fail closed, rematch selections re-read the main list —
    /// issue #974).
    fn rule_scan<'a>(
        route: &'a RouteTable,
        name: &str,
        fail_closed_udp: bool,
    ) -> Result<RuleScan<'a>, ()> {
        if name.is_empty() {
            return Ok(RuleScan {
                rules: route.rules.as_slice(),
                compiled: &route.compiled_rules,
                stats: Some(&route.rule_stats),
                fail_closed_udp,
            });
        }
        route
            .sub_rules
            .get(name)
            .map(|block| RuleScan {
                rules: block.rules.as_slice(),
                compiled: &block.compiled,
                // A block's rules have no /rules surface — they are never
                // disabled, and a block-local index must not alias the
                // top-level stats.
                stats: None,
                fail_closed_udp,
            })
            .ok_or(())
    }

    async fn resolve_proxy_inner(
        &self,
        metadata: &mut Metadata,
        record_hit: bool,
    ) -> Option<ResolvedTarget> {
        // Sample the live `find-process-mode` once for the whole
        // resolution — a PATCH lands on the next flow, not mid-scan
        // (issue #974).
        let process_mode = self.process_policy.get();
        // Upstream `resolveMetadata`: a nonempty `special_proxy` resolves
        // in the current proxy map BEFORE process lookup and before
        // direct/global/rule dispatch — it overrides every mode,
        // including when `rule:` is also set.
        if !metadata.special_proxy().is_empty() {
            // The `always`-mode lookup this early return skips is a real
            // skip, not "untried": record it like `maybe_lookup_flow_process`
            // does so the ledger's app lane does not queue an OS scan for
            // a flow routing already decided (issue #974 shape).
            if process_mode == ProcessLookupMode::Always {
                metadata.flow_lookup.record_process(None);
            }
            return Some(self.resolve_listener_proxy(metadata, record_hit));
        }
        if record_hit {
            self.maybe_lookup_flow_process(metadata, process_mode).await;
        }
        let mode = *self.mode.read();
        match mode {
            TunnelMode::Direct => {
                conn_note!(Rule, "Direct mode → DIRECT");
                Some(ResolvedTarget {
                    adapter: Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                    rule_name: SmolStr::new_static("Direct"),
                    rule_payload: SmolStr::default(),
                    route: self.route(),
                })
            }
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
                conn_note!(Rule, "Global mode → {}", adapter.name());
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
                // Eager callers own destination resolution (the UDP NAT key
                // is built from `resolve_udp_dst` output), so IP demand may
                // not stop the scan — only process demand may.
                Some(
                    self.rule_route(&route, metadata, false, process_mode, record_hit)
                        .await,
                )
            }
        }
    }

    /// Rule-mode variant of [`Self::resolve_proxy_flow`] with **lazy metadata
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
        // A forced `proxy:` overrides every mode upstream — it must win
        // before this early-out; the special-proxy flow then resolves
        // inside `resolve_proxy_inner` and never reaches lazy scanning.
        if mode != TunnelMode::Rule || !metadata.special_proxy().is_empty() {
            return self.resolve_proxy_flow(metadata).await;
        }
        let process_mode = self.process_policy.get();
        self.maybe_lookup_flow_process(metadata, process_mode).await;
        let route = self.route();
        Some(
            self.rule_route(&route, metadata, true, process_mode, true)
                .await,
        )
    }

    /// The iterative rematch transition loop (issue #974): each pass scans
    /// the active rule vector — the listener's `rule:` block selection
    /// first, then whatever the last committed transition named — and a
    /// matched `type: rematch` leaf applies its `target-rematch-name` /
    /// `target-sub-rule` to `metadata` and re-enters the scan. Iterative,
    /// never recursive: the flow's enrichment state (`dst_ip`, the shared
    /// process memo, the `ip_attempted` flag) carries across passes so a
    /// transition never repeats a lookup — including a failed one.
    ///
    /// Two guards make every transition finite and terminal: a
    /// re-visited *adapter name* means a routing cycle, and 32 hops is
    /// upstream's recursion budget. Either rejects the flow where it is —
    /// no slide to a later rule, no direct-dial fallback.
    ///
    /// A listener-seeded block that is absent rejects (the override owns
    /// the flow's whole policy); a rematch-selected block that is absent
    /// warns once at build and scans the main list instead.
    async fn rule_route(
        &self,
        route: &Arc<RouteTable>,
        metadata: &mut Metadata,
        allow_ip: bool,
        process_mode: ProcessLookupMode,
        record_hit: bool,
    ) -> ResolvedTarget {
        const MAX_REMATCH_TRANSITIONS: usize = 32;
        let mut active = SmolStr::from(metadata.special_rules());
        let mut listener_seeded = !active.is_empty();
        let mut ip_attempted = false;
        let mut visited: std::collections::HashSet<SmolStr> = std::collections::HashSet::new();
        loop {
            let scan = match Self::rule_scan(route, &active, listener_seeded) {
                Ok(scan) => scan,
                Err(()) if listener_seeded => {
                    return self.missing_block_reject(route, metadata, record_hit);
                }
                Err(()) => {
                    // The build warned once already; a rematch-selected
                    // name that resolves to nothing re-reads the main
                    // list (upstream `parseRules` semantics).
                    debug!("rematch target-sub-rule '{active}' is not a declared block; scanning the main rules");
                    active = SmolStr::default();
                    Self::rule_scan(route, "", false).expect("the main rule list always resolves")
                }
            };
            let (result, candidate) = self
                .match_rule_route(
                    route,
                    scan,
                    metadata,
                    allow_ip,
                    process_mode,
                    &mut ip_attempted,
                )
                .await;
            let Some(candidate) = candidate else {
                return self
                    .materialize_rule_match(route, result, record_hit, scan.stats, metadata);
            };
            let m = result.expect("a rematch verdict only rides a terminal match");
            // The chosen slot commits this pass — count it exactly like a
            // terminal match on this vector. A block-local index never
            // reaches the top-level counters.
            if record_hit {
                if let Some(stats) = scan.stats {
                    stats.record_hit(m.rule_index);
                }
            }
            conn_note!(
                Rule,
                "Rematch via '{}' (rule #{}) — re-entering rule scan",
                candidate.name,
                m.rule_index + 1
            );
            let guard_tripped =
                !visited.insert(candidate.name.clone()) || visited.len() > MAX_REMATCH_TRANSITIONS;
            if guard_tripped {
                warn!(
                    "rematch transition loop or depth limit at '{}'; rejecting flow",
                    candidate.name
                );
                if record_hit {
                    self.stats
                        .rule_match
                        .increment(m.rule_type.as_str(), "REJECT");
                }
                return ResolvedTarget {
                    adapter: Arc::clone(&self.reject) as Arc<dyn ProxyAdapter>,
                    rule_name: SmolStr::new_static(m.rule_type.mihomo_name()),
                    rule_payload: SmolStr::from(m.rule_payload),
                    route: Arc::clone(route),
                };
            }
            // Only the fields the leaf supplies move — an omitted
            // `target-sub-rule` keeps scanning the active block, and an
            // explicit "" selects the main list / clears the marker.
            if let Some(name) = candidate.rematch_name {
                metadata.set_rematch_name(&name);
            }
            if let Some(block) = candidate.sub_rule {
                active = block;
                // Whatever seeded this scan no longer owns the policy: a
                // rematch-chosen block is an ordinary list — a
                // UDP-incapable match slides like the main rules — only
                // the listener's own selection fails closed. A name-only
                // transition restarts the *same* list, so the provenance
                // must survive untouched.
                listener_seeded = false;
            }
        }
    }

    /// The rule-table scan both dispatch paths share: a demand-stop pass,
    /// materialize the *reached* slot's own demands (`dst_ip` into
    /// `metadata` when `allow_ip`, the owning process into a match-only
    /// working copy), then re-scan — until the scan matches, misses, or no
    /// gated demand remains. Dead-target warnings fire exactly once: only
    /// a terminal pass emits them (an earlier pass's skips are
    /// re-buffered, not lost).
    ///
    /// `find-process-mode` plugs in here: `always` already filled
    /// `metadata` pre-dispatch so process demand is never actionable;
    /// `strict` blocks at the first reached process slot, runs the flow's
    /// one lookup, and applies the outcome to the match-only copy —
    /// upstream's "a reached process-dependent predicate invokes it";
    /// `off` never lets process demand stop the scan at all.
    ///
    /// The second tuple item carries the rematch transition the terminal
    /// match commits — [`Self::rule_route`] consumes it; a plain match
    /// leaves it `None`. `ip_attempted` lives with the caller so a failed
    /// resolve is cached across rematch passes too.
    async fn match_rule_route<'a>(
        &self,
        route: &'a Arc<RouteTable>,
        scan: RuleScan<'a>,
        metadata: &mut Metadata,
        allow_ip: bool,
        process_mode: ProcessLookupMode,
        ip_attempted: &mut bool,
    ) -> (Option<CompiledMatchResult<'a>>, Option<RematchCandidate>) {
        // A prior pass of this flow — or its UDP route probe — may already
        // hold the one lookup's outcome: apply a hit to the match-only
        // copy so the scan sees it without a second OS walk.
        let mut enriched = stored_process_clone(metadata);
        let rematch = std::cell::Cell::new(None);
        loop {
            let input = enriched.as_ref().unwrap_or(&*metadata);
            let gate = DemandGate {
                ip: allow_ip && !*ip_attempted,
                process: process_mode != ProcessLookupMode::Off
                    && !input.flow_lookup.process_attempted(),
            };
            // Bind the outcome first: the probe's `&Cell` would otherwise
            // live as a match scrutinee temporary across the enrichment
            // awaits below, and `&Cell` is not `Send`.
            let outcome = scan.compiled.match_rules_lazy(
                input,
                scan.rules,
                &Self::target_probe(route, input, scan.stats, scan.fail_closed_udp, &rematch),
                gate,
            );
            match outcome {
                LazyMatchOutcome::Matched(m) => return (Some(m), rematch.take()),
                LazyMatchOutcome::NoMatch => return (None, rematch.take()),
                LazyMatchOutcome::NeedsEnrichment {
                    needs_ip,
                    needs_process,
                    blocked_rule,
                } => {
                    if let Some(rule) = scan.rules.get(blocked_rule) {
                        let needs = match (needs_ip, needs_process) {
                            (true, true) => "the destination IP and the owning process",
                            (true, false) => "the destination IP",
                            _ => "the owning process",
                        };
                        conn_note!(
                            Rule,
                            "Rule #{} {} needs {needs}",
                            blocked_rule + 1,
                            RuleText::new(rule.as_ref())
                        );
                    }
                    if needs_process {
                        // The first reached slot wants the owner: the flow's
                        // one lookup, applied to the match-only working copy
                        // (`strict` keeps its match-only visibility).
                        let working = enriched.get_or_insert_with(|| metadata.clone());
                        match self.flow_process(working).await {
                            Some(info) => {
                                fill_process_fields(working, &info);
                                conn_note!(Rule, "Owning process: {}", working.process);
                            }
                            None => conn_note!(Rule, "Owning process not found"),
                        }
                    }
                    if needs_ip {
                        // `needs_ip` already encodes the `pre_resolve` guards:
                        // host present, dst_ip absent. The flag lives with
                        // the caller so a miss is not re-resolved on the
                        // next rematch pass either.
                        *ip_attempted = true;
                        let started = std::time::Instant::now();
                        if let Some(real_ip) = self.resolver().resolve_ip_real(&metadata.host).await
                        {
                            debug!("lazy resolve: {} -> {}", metadata.host, real_ip);
                            conn_note!(
                                Rule,
                                "Destination IP for matching: {real_ip} ({} ms)",
                                started.elapsed().as_millis()
                            );
                            metadata.dst_ip = Some(real_ip);
                            if let Some(working) = enriched.as_mut() {
                                working.dst_ip = Some(real_ip);
                            }
                        } else {
                            conn_note!(
                                Rule,
                                "No address for {} after {} ms; IP rules cannot match",
                                metadata.host,
                                started.elapsed().as_millis()
                            );
                        }
                    }
                }
            }
        }
    }

    /// `find-process-mode: always` — the pre-dispatch lookup upstream runs
    /// in `resolveMetadata`: one scan per eligible *inbound* flow, applied
    /// to the tracked metadata itself so `/connections` and the ledger see
    /// the owner even when no rule consumes it. Skips housekeeping
    /// (internal) flows, an explicit `specialProxy` override, an owner the
    /// inbound already named, and flows without a usable source tuple; a
    /// supplied name/path/UID is never overwritten and a miss is
    /// remembered in the flow's memo like any other.
    ///
    /// Every skip is recorded too: unmarked, `process_attempted()` stays
    /// false and a later process-demanding slot could rescan a flow this
    /// pass already refused (issue #974).
    async fn maybe_lookup_flow_process(
        &self,
        metadata: &mut Metadata,
        process_mode: ProcessLookupMode,
    ) {
        if process_mode != ProcessLookupMode::Always {
            return;
        }
        if metadata.is_internal() || !metadata.special_proxy().is_empty() {
            metadata.flow_lookup.record_process(None);
            return;
        }
        if !metadata.process.is_empty() {
            // The supplied owner IS this flow's outcome — record it so a
            // reached demand pass cannot scan anyway.
            metadata.flow_lookup.record_process(Some(ProcessInfo {
                name: metadata.process.to_string(),
                path: metadata.process_path.to_string(),
                uid: metadata.uid,
            }));
            return;
        }
        if metadata.src_ip.is_none() || metadata.src_port == 0 {
            metadata.flow_lookup.record_process(None);
            return;
        }
        let Some(info) = self.flow_process(metadata).await else {
            return;
        };
        fill_process_fields(metadata, &info);
    }

    /// The flow's owning process through the shared memo: one caller runs
    /// the platform scan (on the blocking pool) while every clone holding
    /// this `FlowLookup` waits it out and consumes the same recorded
    /// outcome — the probe, a match pass and tracking can never duplicate
    /// the walk (issue #974). On platforms without a lookup this records
    /// the miss immediately; on a panic in the scan, `find_process_async`
    /// already converts to `None`.
    async fn flow_process(&self, metadata: &Metadata) -> Option<ProcessInfo> {
        metadata
            .flow_lookup
            .process_or_scan(|| self.scan_flow_process(metadata))
            .await
    }

    /// One platform socket-table scan for `metadata`'s source tuple —
    /// `#[cfg(test)]` replaces it with a deterministic counted hook.
    async fn scan_flow_process(&self, metadata: &Metadata) -> Option<ProcessInfo> {
        #[cfg(test)]
        if let Some(hook) = self.process_lookup_hook.lock().as_ref().cloned() {
            return hook(metadata);
        }
        let src_ip = metadata.src_ip?;
        if metadata.src_port == 0 {
            return None;
        }
        let local = std::net::SocketAddr::new(src_ip, metadata.src_port);
        meow_common::find_process_async(metadata.network, local).await
    }

    /// Registry probe for the match engines — upstream `match()`'s three
    /// checks between `rule.Match` and returning the adapter:
    /// `proxies[ada]` membership, the `Unwrap` walk for the `PASS`
    /// built-in (`continue GetRules`), and the UDP `SupportUDP` continue
    /// (issue #513). `DIRECT` is hard-coded as always usable: the tunnel
    /// owns that adapter unconditionally. `stats` is the scanned vector's
    /// own disable table — `None` for a `sub-rules` block, whose rules
    /// are never disabled.
    fn target_probe<'a>(
        route: &'a RouteTable,
        metadata: &'a Metadata,
        stats: Option<&'a crate::rule_stats::RuleStats>,
        fail_closed_udp: bool,
        rematch: &'a std::cell::Cell<Option<RematchCandidate>>,
    ) -> RouteTargetProbe<'a> {
        RouteTargetProbe {
            route,
            metadata,
            stats,
            fail_closed_udp,
            rematch,
        }
    }

    /// Map a rule-match result to a [`ResolvedTarget`], recording match
    /// statistics; `None` falls through to DIRECT. The target retains
    /// `route` so the generation's dialer registry stays pinned across the
    /// caller's dial (see [`Self::resolve_proxy`]). `record_hit` is false
    /// for `resolve_udp_dst`'s internal probe — only a resolution the
    /// caller keeps counts toward `hitCount`/`rule_match` (issue #882
    /// review). `hit_stats` is the scanned vector's own per-index hit
    /// counter — `None` for a `sub-rules` block match, which counts the
    /// aggregate `rule_match` metric but must not stamp a block-local
    /// index onto the top-level `/rules` counters.
    fn materialize_rule_match(
        &self,
        route: &Arc<RouteTable>,
        result: Option<CompiledMatchResult<'_>>,
        record_hit: bool,
        hit_stats: Option<&crate::rule_stats::RuleStats>,
        metadata: &Metadata,
    ) -> ResolvedTarget {
        match result {
            Some(m) => {
                let target = m.adapter_name;
                // Bucket by adapter type, not name — a `type: direct` leaf
                // or the COMPATIBLE built-in dial direct, PASS-RULE rejects.
                let mut action = match route.proxies.get(target).map(|p| p.adapter_type()) {
                    _ if target == "DIRECT" => "DIRECT",
                    Some(AdapterType::Direct | AdapterType::Compatible) => "DIRECT",
                    Some(AdapterType::Reject | AdapterType::RejectDrop | AdapterType::PassRule) => {
                        "REJECT"
                    }
                    _ => "PROXY",
                };
                let proxy: Arc<dyn ProxyAdapter> = match route.proxies.get(target).cloned() {
                    // A `sub-rules` block match on a UDP-incapable target
                    // fails closed rather than dial it: the override owns
                    // the flow's whole policy (same fail-closed contract
                    // as a forced `proxy:`), so the outcome is REJECT,
                    // not a doomed relay session.
                    Some(p)
                        if hit_stats.is_none()
                            && metadata.network == Network::Udp
                            && !p.support_udp() =>
                    {
                        action = "REJECT";
                        Arc::clone(&self.reject) as Arc<dyn ProxyAdapter>
                    }
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
                if record_hit {
                    // A `sub-rules` block match carries no stats — never
                    // stamp a block-local index onto the top-level /rules
                    // counters or switches (the spec's "no fictitious rule
                    // hit"). The aggregate metric still counts it.
                    if let Some(stats) = hit_stats {
                        stats.record_hit(m.rule_index);
                    }
                    self.stats
                        .rule_match
                        .increment(m.rule_type.as_str(), action);
                }
                conn_note!(
                    Rule,
                    "Matched rule #{} {} → {target}",
                    m.rule_index + 1,
                    RuleText::parts(m.rule_type.as_str(), m.rule_payload)
                );
                // mihomo's type name (`DomainSuffix`), a `&'static str` —
                // wrapped inline without heap.
                ResolvedTarget {
                    adapter: proxy,
                    rule_name: SmolStr::new_static(m.rule_type.mihomo_name()),
                    rule_payload: SmolStr::from(m.rule_payload),
                    route: Arc::clone(route),
                }
            }
            None => {
                // No rule matched, use DIRECT
                conn_note!(Rule, "No rule matched → DIRECT");
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

/// The test seam's replacement for the platform socket-table scan.
#[cfg(test)]
type ProcessLookupHook = Arc<dyn Fn(&Metadata) -> Option<ProcessInfo> + Send + Sync>;

/// A hit the flow's lookup memo already holds, applied to a fresh
/// match-only clone — `None` when the memo has no hit to apply (untried,
/// or a miss: the caller's own metadata evaluates just as well).
fn stored_process_clone(metadata: &Metadata) -> Option<Metadata> {
    if !metadata.process.is_empty() {
        return None;
    }
    let info = metadata.flow_lookup.process_outcome()?.as_ref()?;
    let mut enriched = metadata.clone();
    fill_process_fields(&mut enriched, info);
    Some(enriched)
}

/// Fill `metadata`'s *empty* process fields from a lookup `info` — an
/// inbound-supplied name, path or UID is never overwritten.
fn fill_process_fields(metadata: &mut Metadata, info: &ProcessInfo) {
    if metadata.process.is_empty() && !info.name.is_empty() {
        metadata.process = SmolStr::from(info.name.as_str());
    }
    if metadata.process_path.is_empty() && !info.path.is_empty() {
        metadata.process_path = SmolStr::from(info.path.as_str());
    }
    if metadata.uid.is_none() {
        metadata.uid = info.uid;
    }
}

/// `TYPE,payload` (or bare `TYPE` for payload-less rules like `MATCH`) as
/// written in the config, for notes.
struct RuleText<'a>(&'a str, &'a str);

impl<'a> RuleText<'a> {
    fn new(rule: &'a dyn Rule) -> Self {
        Self(rule.rule_type().as_str(), rule.payload())
    }

    fn parts(rule_type: &'a str, payload: &'a str) -> Self {
        Self(rule_type, payload)
    }
}

impl std::fmt::Display for RuleText<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.1.is_empty() {
            f.write_str(self.0)
        } else {
            write!(f, "{},{}", self.0, self.1)
        }
    }
}

/// A routing decision's rule as the per-connection `match` log line prints
/// it: `TYPE(payload)`, or `TYPE(target)` when the rule has no payload, so
/// `MATCH,DIRECT` logs `Match(DIRECT)` rather than an empty `Match()`. The
/// tunnel's own decisions read the same way, e.g. `Final(DIRECT)` when no
/// rule matched.
pub struct MatchedRule<'a> {
    rule: &'a str,
    payload: &'a str,
    target: &'a str,
}

impl<'a> MatchedRule<'a> {
    /// `rule` and `payload` as [`ResolvedTarget`] carries them; `target` is
    /// the name of the adapter the decision picked.
    pub fn new(rule: &'a str, payload: &'a str, target: &'a str) -> Self {
        Self {
            rule,
            payload,
            target,
        }
    }
}

impl std::fmt::Display for MatchedRule<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detail = if self.payload.is_empty() {
            self.target
        } else {
            self.payload
        };
        write!(f, "{}({detail})", self.rule)
    }
}

/// The `using` part of the per-connection `match` log line: the decision's
/// adapter, followed by the member the flow dials through in brackets when
/// that adapter is a group, e.g. `Proxy[HK-01]`. Like upstream's
/// `Chain.String()`, nested groups print only the outer group and the
/// final member.
///
/// meow logs this line before the dial (upstream logs it after), so the
/// member is the one the dial will take, peeked with
/// `unwrap_proxy(metadata, false)` the way the `/connections` `chains`
/// entry is. The peek runs only when the line is formatted, so it costs
/// nothing while INFO is off. A round-robin load-balance pick is a
/// prediction: another flow's dial may commit in between.
///
/// A relay group prints as itself, since it resolves its hops per dial and
/// offers nothing to peek (see `RelayGroup`'s `Proxy` impl). An outbound's
/// `dialer-proxy` front is not part of the line either: the brackets name
/// the outbound that reaches the destination, not the hop it dials its
/// server through.
pub struct UsingProxy<'a> {
    adapter: &'a dyn ProxyAdapter,
    metadata: &'a Metadata,
}

impl<'a> UsingProxy<'a> {
    /// `adapter` is the one the decision picked; `metadata` is the flow's.
    pub fn new(adapter: &'a dyn ProxyAdapter, metadata: &'a Metadata) -> Self {
        Self { adapter, metadata }
    }
}

impl std::fmt::Display for UsingProxy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.adapter.name())?;
        if let Some(leaf) = crate::tcp::leaf_proxy(self.adapter, self.metadata) {
            write!(f, "[{}]", leaf.name())?;
        }
        Ok(())
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

/// Verdict from [`TunnelInner::pre_handle_metadata`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a Drop verdict must abort the flow — ignoring it dials a stale fake IP (issue #618)"]
pub enum PreHandleVerdict {
    /// Proceed to rule matching and dispatch.
    Continue,
    /// Drop the flow: `dst_ip` sits inside the fake-IP range with no live
    /// allocation and no recoverable hostname — a stale or never-mapped
    /// fake IP. Dialing it loops the packet back into a fake-IP-routed
    /// inbound (TUN `auto-route`) and self-saturates `max-connections`
    /// (issue #618); mihomo drops the same class in `preHandleMetadata`.
    /// Also returned when the flow's name is not a hostname (issue #734).
    Drop,
}

/// The `(rules, compiled, stats)` a rule-mode scan runs over for `metadata`
/// — the named `sub-rules` block the active selection picks, or the
/// top-level set when unset. `Err(())` = the named block is missing from
/// the table: the caller fails the flow closed on a listener-seeded
/// selection and falls back to the main list on a rematch one (issue #974).
#[derive(Clone, Copy)]
struct RuleScan<'a> {
    rules: &'a [Box<dyn Rule>],
    compiled: &'a CompiledRuleSet,
    /// The scanned vector's own disable table — `None` for a `sub-rules`
    /// block, whose rules are never disabled and never hit-counted.
    stats: Option<&'a crate::rule_stats::RuleStats>,
    /// Fail a UDP flow closed on a matched UDP-incapable target — the
    /// listener-seeded `rule:` block selection's contract only. A
    /// rematch-selected block scan uses the ordinary skip instead
    /// (issue #974): the transition, not the listener, selected it.
    fail_closed_udp: bool,
}

/// The re-entry a matched rematch target commits (issue #974): the leaf's
/// configured fields plus its registry name — the cycle guard keys on the
/// *adapter* name, not the marker text, so two leaves sharing one
/// `target-rematch-name` chain legally while a node re-picked through a
/// group is still caught.
struct RematchCandidate {
    /// The selected rematch adapter's registry name — the visited-set key.
    name: SmolStr,
    /// `target-rematch-name` verbatim — `Some("")` clears the marker.
    rematch_name: Option<SmolStr>,
    /// `target-sub-rule` verbatim — `Some("")` returns to the main rules.
    sub_rule: Option<SmolStr>,
}

/// The rule_match metric bucket for an adapter kind — the `action` half of
/// the counters keyed by `(rule_type, action)`. Shared between the
/// forced-proxy and rule-match paths so a `ListenerProxy` line buckets
/// identically to the rule it bypassed.
fn proxy_action(t: AdapterType) -> &'static str {
    match t {
        AdapterType::Direct | AdapterType::Compatible => "DIRECT",
        AdapterType::Reject | AdapterType::RejectDrop | AdapterType::PassRule => "REJECT",
        _ => "PROXY",
    }
}

/// Route-table-backed [`TargetProbe`] for the match engines.
struct RouteTargetProbe<'a> {
    route: &'a RouteTable,
    metadata: &'a Metadata,
    /// The scanned vector's own disable table — `None` for a `sub-rules`
    /// block, whose rules have no /rules surface and are never disabled.
    stats: Option<&'a crate::rule_stats::RuleStats>,
    /// Fail a UDP flow closed on a matched UDP-incapable target — the
    /// listener-seeded `rule:` block selection's contract only. A
    /// rematch-selected block scan uses the ordinary skip instead
    /// (issue #974): the transition, not the listener, selected it.
    fail_closed_udp: bool,
    /// The rematch leaf a matched target unwrapped to — stashed so the
    /// caller can commit its re-entry after the scan returns it.
    rematch: &'a std::cell::Cell<Option<RematchCandidate>>,
}

/// `true` when `adapter` dials through a DIRECT/COMPATIBLE hop for
/// `metadata` — the adapter itself or the member its group chain selects.
/// Peeks with `unwrap_proxy(metadata, false)`, like
/// [`RouteTargetProbe::unwraps_to`], so no round-robin counter advances.
fn routes_direct(adapter: &dyn ProxyAdapter, metadata: &Metadata) -> bool {
    const MAX_UNWRAP_HOPS: usize = 16;
    let is_direct = |t: AdapterType| matches!(t, AdapterType::Direct | AdapterType::Compatible);
    if is_direct(adapter.adapter_type()) {
        return true;
    }
    let mut next = adapter.unwrap_proxy(metadata, false);
    for _ in 0..MAX_UNWRAP_HOPS {
        let Some(hop) = next else {
            return false;
        };
        if is_direct(hop.adapter_type()) {
            return true;
        }
        next = hop.unwrap_proxy(metadata, false);
    }
    false
}

impl RouteTargetProbe<'_> {
    /// Upstream `for adapter := adapter; adapter != nil; adapter =
    /// adapter.Unwrap(metadata, false)`: peek down the group chain — no
    /// round-robin advance, no usage stats — and report whether any hop
    /// carries the `want` type tag. `reject_group_membership_cycles` keeps
    /// config-declared chains acyclic, so the hop bound only guards
    /// hand-built registries; upstream's walk is unbounded.
    fn unwraps_to(&self, start: Arc<dyn Proxy>, want: AdapterType) -> bool {
        const MAX_UNWRAP_HOPS: usize = 16;
        let mut cur = start;
        for _ in 0..MAX_UNWRAP_HOPS {
            if cur.adapter_type() == want {
                return true;
            }
            match cur.unwrap_proxy(self.metadata, false) {
                Some(next) => cur = next,
                None => return false,
            }
        }
        debug!(
            "{}: unwrap chain exceeded {MAX_UNWRAP_HOPS} hops probing for {want}",
            cur.name()
        );
        false
    }

    /// The rematch leaf `start`'s pick chain ends at, if any — the same
    /// peek the `PASS` walk uses, so a group *selecting* a rematch member
    /// transitions while a group merely containing one does not
    /// (issue #974). The leaf's own `RematchAction` supplies the fields
    /// to apply.
    fn rematch_leaf(&self, start: Arc<dyn Proxy>) -> Option<RematchCandidate> {
        const MAX_UNWRAP_HOPS: usize = 16;
        let mut cur = start;
        for _ in 0..MAX_UNWRAP_HOPS {
            if let Some(action) = cur.rematch_action() {
                return Some(RematchCandidate {
                    name: SmolStr::from(cur.name()),
                    rematch_name: action.rematch_name.map(SmolStr::from),
                    sub_rule: action.sub_rule.map(SmolStr::from),
                });
            }
            cur = cur.unwrap_proxy(self.metadata, false)?;
        }
        debug!(
            "{}: unwrap chain exceeded {MAX_UNWRAP_HOPS} hops probing for rematch",
            cur.name()
        );
        None
    }
}

impl TargetProbe for RouteTargetProbe<'_> {
    fn rule_enabled(&self, rule_index: usize) -> bool {
        // A `sub-rules` block carries no disable table — every block rule
        // scans enabled (spec: blocks never inherit the top-level
        // /rules switches, and no block-local index may alias them).
        self.stats.is_none_or(|s| s.is_enabled(rule_index))
    }

    fn check(&self, name: &str) -> TargetCheck {
        // `DIRECT` resolves without a registry entry: route snapshots may
        // lack it (hand-built tables), and user entries cannot shadow it
        // (build rejects builtin names) — short-circuit is always safe.
        if name == "DIRECT" {
            return TargetCheck::Usable;
        }
        let Some(p) = self.route.proxies.get(name) else {
            return TargetCheck::Missing;
        };
        // upstream order: membership, then the Unwrap walk, then UDP.
        if self.unwraps_to(Arc::clone(p), AdapterType::Pass) {
            return TargetCheck::Pass;
        }
        // A rematch leaf redirects the scan before any transport check —
        // it claims `support_udp()` for exactly that reason, so it must be
        // unwrapped ahead of the capability gate (issue #974).
        if let Some(candidate) = self.rematch_leaf(Arc::clone(p)) {
            self.rematch.set(Some(candidate));
            return TargetCheck::Rematch;
        }
        if self.metadata.network == Network::Udp && !p.support_udp() {
            // mihomo `continue`s a UDP-incapable target: a plain node's
            // `udp: false` is a routing preference, so the scan slides
            // and a later rule can still pick the flow up. The single
            // exception is a `dialer-proxy` wrapper over a
            // non-transparent inner — the operator chained *every* flow
            // through that node, so sliding (e.g. to `MATCH,DIRECT`)
            // would silently reroute what the config pinned; the scan
            // stops on the match and the dial fails loudly (issue #969).
            if p.is_dialer_proxy_non_transparent() {
                return TargetCheck::Unusable;
            }
            // A listener-seeded `sub-rules` block scan fails closed the
            // same way: the `rule:` override replaced the whole policy
            // for this flow, so sliding past a matched rule to
            // block-exhaustion DIRECT would silently reroute what the
            // override pinned — matching the forced `proxy:` contract.
            // A rematch-selected block keeps the ordinary slide: the
            // transition, not the listener, chose that list (issue #974).
            if self.fail_closed_udp {
                return TargetCheck::Unusable;
            }
            return TargetCheck::Missing;
        }
        TargetCheck::Usable
    }

    fn is_pass_rule(&self, name: &str) -> bool {
        self.route
            .proxies
            .get(name)
            .is_some_and(|p| self.unwraps_to(Arc::clone(p), AdapterType::PassRule))
    }
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
        let stats = Arc::new(Statistics::new());
        // One live `find-process-mode` cell for the tunnel and its ledger.
        let process_policy = Arc::new(ProcessLookupPolicy::default());
        stats.set_process_lookup_policy(Arc::clone(&process_policy));
        let source: Arc<dyn meow_common::traffic_ledger::Source> = Arc::clone(&stats) as _;
        meow_common::traffic_ledger::register(Arc::downgrade(&source));
        Self {
            inner: Arc::new(TunnelInner {
                mode: RwLock::new(TunnelMode::Rule),
                route: RwLock::new(Arc::new(RouteTable::empty())),
                resolver,
                direct,
                reject: Arc::new(meow_proxy::RejectAdapter::new(false)),
                nat_table: udp::new_nat_table(),
                stats,
                tcp_generation: RwLock::new(0),
                health_checks: Mutex::new(crate::health_check::HealthCheckSupervisor::default()),
                needs_ip_resolution: AtomicBool::new(false),
                process_policy,
                #[cfg(test)]
                process_lookup_hook: Mutex::new(None),
                tun_handle: RwLock::new(None),
                dialer_registry: std::sync::OnceLock::new(),
                selection_backing: std::sync::OnceLock::new(),
                udp_flush: tokio::sync::watch::Sender::new(0),
                connection_notes: AtomicBool::new(false),
                tcp_idle_timeout: AtomicU64::new(0),
            }),
        }
    }

    /// Record per-connection notes from now on: a timestamped account of
    /// the fake-IP reversal, the DNS lookups rules needed, the matched rule,
    /// the dial and the close, served by `GET /connections/{id}` for live
    /// and recently closed connections. Off by default; each recording
    /// connection allocates its note log. Headless statistics never record:
    /// nothing could read the notes.
    pub fn set_connection_notes(&self, enabled: bool) {
        self.inner
            .connection_notes
            .store(enabled, Ordering::Relaxed);
    }

    /// Bound how long an established TCP relay may stay silent in BOTH
    /// directions before it is torn down with a `TimedOut` error — the
    /// zombie-connection bound for the case where the peer neither sends
    /// nor closes (dead LAN device, stalled netstack flow, dead upstream).
    /// `None` or a zero duration disables the bound (pre-change relay
    /// behaviour). Applied to relays that start after the call, like every
    /// per-connection knob.
    ///
    /// The bound is stored in whole seconds via `Duration::as_secs`, so a
    /// non-zero sub-second `Some(d)` truncates to `0` and *disables* the
    /// bound — programmatic callers must round up themselves if that is
    /// not the intent (config resolution only ever yields whole seconds).
    /// Any fractional part beyond whole seconds is dropped silently.
    ///
    /// # Panics (debug builds only)
    /// Asserts that a `Some` duration is either exactly zero (the
    /// documented disable) or carries at least one whole second (and no
    /// more than `MAX_DURATION_SECS`, past which the relay's
    /// `Instant + Duration` arithmetic could overflow), so both footguns
    /// surface immediately in tests rather than silently at runtime.
    pub fn set_tcp_idle_timeout(&self, d: Option<std::time::Duration>) {
        debug_assert!(
            d.is_none_or(|d| d.is_zero()
                || (d.as_secs() > 0 && d.as_secs() <= meow_common::MAX_DURATION_SECS)),
            "set_tcp_idle_timeout: Some(d) with 0 < d < 1 s truncates to 0 and \
             disables the bound (round up to Duration::from_secs(1) minimum), \
             and a Some(d) above MAX_DURATION_SECS can overflow Instant + \
             Duration in the relay's idle timer"
        );
        self.inner
            .tcp_idle_timeout
            .store(d.map_or(0, |d| d.as_secs()), Ordering::Relaxed);
    }

    pub fn inner(&self) -> &Arc<TunnelInner> {
        &self.inner
    }

    /// Install the live `find-process-mode` (issue #974): `always` runs the
    /// per-flow owner lookup before dispatch, `strict` only at a reached
    /// demanding predicate, `off` never — including the traffic ledger's
    /// app-lookup lane, which shares this cell. Applied to flows resolved
    /// after the call; no session flush or rule rebuild rides with it.
    pub fn set_process_lookup_mode(&self, mode: ProcessLookupMode) {
        self.inner.process_policy.set(mode);
    }

    /// The live `find-process-mode` currently installed.
    pub fn process_lookup_mode(&self) -> ProcessLookupMode {
        self.inner.process_policy.get()
    }

    /// Test seam: replace the platform socket-table scan with a counted,
    /// deterministic hook (issue #974).
    #[cfg(test)]
    pub fn set_process_lookup_hook(&self, hook: ProcessLookupHook) {
        *self.inner.process_lookup_hook.lock() = Some(hook);
    }

    /// Install the registry provider-sourced nodes resolve `dialer-proxy`
    /// names against (issue #489). Called once at startup with the handle
    /// `load_config` shared into every `ProxyProvider`; subsequent calls are
    /// ignored — the registry is a process-lifetime singleton by contract.
    pub fn set_dialer_registry(&self, registry: meow_proxy::dialer::ProxyRegistry) {
        if self.inner.dialer_registry.set(registry).is_err() {
            warn!(
                "dialer registry already installed — the new handle will never \
                 be published; provider-sourced `dialer-proxy` nodes built on \
                 it will fail every dial"
            );
        }
    }

    /// Install the config's selection-persistence owner (issue #974) —
    /// called once at startup with `Config::selection`; every rebuild
    /// lane then reads it via [`Self::selection_backing`] so rebuilt
    /// groups share the startup store and the commit lane's epoch bumps.
    pub fn set_selection_backing(&self, backing: Arc<meow_proxy::SelectionBacking>) {
        if self.inner.selection_backing.set(backing).is_err() {
            warn!("selection backing already installed; ignoring re-install");
        }
    }

    /// The selection-persistence owner rebuild lanes attach writers to.
    /// Before the startup install (tests, embedders that never set one)
    /// this pins an unpersisted backing — attach yields no writer, so
    /// selections simply stay in-memory like a disabled profile.
    pub fn selection_backing(&self) -> Arc<meow_proxy::SelectionBacking> {
        Arc::clone(
            self.inner
                .selection_backing
                .get_or_init(|| Arc::new(meow_proxy::SelectionBacking::unpersisted())),
        )
    }

    /// Republish the live proxies map into the provider-node dialer
    /// registry, if one was installed (issue #489). Runs on every routing
    /// install so provider-sourced `dialer-proxy` targets resolve the current
    /// route map rather than a frozen startup-era snapshot.
    ///
    /// Both registries also get this tunnel's statistics, so a
    /// `dialer-proxy` hop counts what it carries toward the member of the
    /// front that carries it.
    fn publish_dialer_registry(&self, route: &RouteTable) {
        let stats: Weak<dyn meow_common::ProxyTrafficSource> =
            Arc::<Statistics>::downgrade(&self.inner.stats);
        route
            .dialer_registry
            .count_traffic_into(Weak::clone(&stats));
        if let Some(registry) = self.inner.dialer_registry.get() {
            registry.count_traffic_into(stats);
            registry.publish(std::sync::Arc::clone(&route.proxies));
        }
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
        self.update_rules_inner(rules, None);
    }

    /// [`Self::update_rules`] plus the `sub-rules:` blocks from the same
    /// rebuild in one snapshot. Refresh paths that rebuild both (geodata)
    /// must republish both — otherwise a listener `rule:` block keeps
    /// matching the superseded DB generation while the top-level list
    /// already binds the new one.
    pub fn update_rules_with_sub_rules(
        &self,
        rules: Vec<Box<dyn Rule>>,
        sub_rules: HashMap<String, meow_rules::sub_rule::SubRuleBlock>,
    ) {
        self.update_rules_inner(rules, Some(sub_rules));
    }

    fn update_rules_inner(
        &self,
        rules: Vec<Box<dyn Rule>>,
        sub_rules: Option<HashMap<String, meow_rules::sub_rule::SubRuleBlock>>,
    ) {
        let rule_stats = {
            let prior = self.route_snapshot();
            crate::rule_stats::RuleStats::carried(&prior.rules, &prior.rule_stats, &rules)
        };
        let new_index = DomainIndex::build(&rules);
        let compiled_rules = CompiledRuleSet::build_masked(&rules, |i| rule_stats.is_disabled(i));
        // Take the enrichment flags from the compiled plan rather than the
        // raw rule list: rules pruned by the IR clean-up passes (dead after
        // MATCH, provable never-match) must not force per-connection DNS
        // pre-resolution or process lookup.
        let needs_proc = compiled_rules.needs_process_lookup();
        let sub_rules = sub_rules.map(compile_sub_rule_routes);
        // Build a new route table on top of the current proxies map. The
        // current proxies are cloned (Arc bumps for adapter handles, one
        // HashMap clone) — paid only on config-reload, not the hot path.
        // The write lock is held across the read-modify-write so a
        // concurrent `update_proxies` cannot be lost.
        let (old, needs_ip) = {
            let mut route = self.inner.route.write();
            let new_route = RouteTable {
                rule_stats: Arc::new(rule_stats),
                rules: Arc::new(rules),
                domain_index: Arc::new(new_index),
                compiled_rules: Arc::new(compiled_rules),
                sub_rules: sub_rules.map_or_else(|| Arc::clone(&route.sub_rules), Arc::new),
                ..route.inherit()
            };
            let needs_ip = new_route.needs_ip_resolution();
            self.publish_dialer_registry(&new_route);
            // Published inside the write section like `install_routing`
            // and `set_rules_disabled`: a reader between install and
            // store would otherwise see the new plan with stale hints.
            self.inner
                .needs_ip_resolution
                .store(needs_ip, Ordering::Relaxed);
            (
                std::mem::replace(&mut *route, Arc::new(new_route)),
                needs_ip,
            )
        };
        // The superseded table's destructor cascade (rules, adapters,
        // possibly the last registry cell) runs outside the lock so
        // `route()` readers are never stalled by it.
        drop(old);
        info!(
            "Rules updated (needs_ip_resolution={}, needs_process_lookup={})",
            needs_ip, needs_proc
        );
    }

    /// `PATCH /rules/disable`: switch rules on or off by index (indexes past
    /// the end are skipped) and recompile the plan without the disabled
    /// ones, so the prune passes never fold a live rule into a disabled one.
    ///
    /// The switches themselves are atomics on the shared `RuleStats`, so a
    /// read guard is enough to flip them and snapshot the Arcs — the
    /// compile (a `Regex::new` per regex rule) then runs with NO lock held
    /// rather than stalling every new connection's `route()` read for the
    /// compile duration. The write section only installs the result, and
    /// only while the snapshotted table is still installed.
    pub fn set_rules_disabled(&self, changes: impl IntoIterator<Item = (usize, bool)>) {
        let changes: Vec<(usize, bool)> = changes.into_iter().collect();
        loop {
            let (rules, stats, changed) = {
                let route = self.inner.route.read();
                let mut changed = false;
                for &(index, disabled) in &changes {
                    changed |= route.rule_stats.is_disabled(index) != disabled
                        && route.rule_stats.set_disabled(index, disabled);
                }
                (
                    Arc::clone(&route.rules),
                    Arc::clone(&route.rule_stats),
                    changed,
                )
            };
            if !changed {
                return;
            }
            let compiled = CompiledRuleSet::build_masked(&rules, |i| stats.is_disabled(i));
            let old = {
                let mut route = self.inner.route.write();
                // Rule mutations serialize on the API's CONFIG_MUTATION
                // lane, so in production the snapshotted Arcs are still
                // installed; a mismatch means a rebuild ran outside the
                // lane — our flips landed on its superseded RuleStats, so
                // drop the guard and re-apply to whatever is current.
                if !Arc::ptr_eq(&route.rules, &rules) || !Arc::ptr_eq(&route.rule_stats, &stats) {
                    drop(route);
                    continue;
                }
                let new_route = RouteTable {
                    compiled_rules: Arc::new(compiled),
                    ..route.inherit()
                };
                self.inner
                    .needs_ip_resolution
                    .store(new_route.needs_ip_resolution(), Ordering::Relaxed);
                std::mem::replace(&mut *route, Arc::new(new_route))
            };
            // Same drop-outside-lock rule as `update_rules`.
            drop(old);
            return;
        }
    }

    /// Swap the proxies map while keeping the current rules, installing
    /// `dialer_registry` alongside it. Callers rebuilding a whole config
    /// should use [`Self::update_routing`], which carries the rebuild's own
    /// registry; passing the CURRENT generation's registry here lets a
    /// swapped-in map that still contains that generation's chained
    /// adapters keep resolving them.
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
        let old = {
            let mut route = self.inner.route.write();
            let new_route = RouteTable {
                proxies: Arc::new(proxies),
                dialer_registry,
                ..route.inherit()
            };
            self.publish_dialer_registry(&new_route);
            std::mem::replace(&mut *route, Arc::new(new_route))
        };
        // Same drop-outside-lock rule as `update_rules` — the old table's
        // destructors must not stall `route()` readers.
        drop(old);
        info!("Proxies updated");
    }

    /// Publish a complete rules/proxies snapshot, preserving active TCP flows.
    /// Use this instead of successive partial updates for a config rebuild.
    ///
    /// `dialer_registry` is the registry the rebuild published `proxies`
    /// into; the route table owns it so the map's `dialer-proxy` chains keep
    /// resolving while this generation lives (issue #533). `sub_rules` is
    /// the config's `sub-rules:` map — published in the same snapshot so a
    /// listener `rule:` override never observes a block and a route that
    /// disagree.
    pub fn update_routing(
        &self,
        proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
        rules: Vec<Box<dyn Rule>>,
        sub_rules: HashMap<String, meow_rules::sub_rule::SubRuleBlock>,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
    ) {
        let route = RouteTable::new(
            proxies,
            rules,
            sub_rules,
            dialer_registry,
            Some(&self.route_snapshot()),
        );
        drop(self.install_routing(Arc::new(route)));
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
    /// `sub_rules` joins the snapshot like `update_routing`.
    pub fn reload_routing(
        &self,
        proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
        rules: Vec<Box<dyn Rule>>,
        sub_rules: HashMap<String, meow_rules::sub_rule::SubRuleBlock>,
        mode: Option<TunnelMode>,
        dialer_registry: meow_proxy::dialer::ProxyRegistry,
    ) -> usize {
        let route = Arc::new(RouteTable::new(
            proxies,
            rules,
            sub_rules,
            dialer_registry,
            Some(&self.route_snapshot()),
        ));
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

    /// Close every UDP session the tunnel can reach and return how many:
    /// the tunnel's own NAT table (drained, each conn closed) plus every
    /// listener-owned flow holding a [`udp::UdpFlushWatch`] — those end on
    /// their own once signalled, including flows still dialling. Clients'
    /// next datagrams open fresh flows with fresh dials. Issue #695.
    pub fn close_all_udp_sessions(&self) -> usize {
        let mut closed = 0;
        self.inner.nat_table.retain(|_, session| {
            let _ = session.conn.close();
            closed += 1;
            false
        });
        closed += self.inner.udp_flush.receiver_count();
        self.inner
            .udp_flush
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        closed
    }

    /// Tear down every outbound session that may ride a socket created
    /// before the outbound-interface binding changed (issue #695): under
    /// `tun.auto-route: global` such a socket is unbound and loops back into
    /// the TUN device. Call after the new binding is installed
    /// (`meow_common::outbound_iface`), so everything redialled is bound.
    ///
    /// In order: resets the cached transport sessions
    /// ([`ProxyAdapter::reset_sessions`]) of every distinct adapter
    /// reachable from the live route table and `extra_roots` (e.g.
    /// proxy-provider members no group references) — first, so the
    /// reconnects the teardown below provokes cannot reuse a stale session;
    /// drops pooled upstream DNS connections (the live resolver's now, every
    /// other resolver's on next use); cancels tracked TCP flows unless
    /// `tcp` says the caller already did; closes every UDP session
    /// ([`Self::close_all_udp_sessions`]). Logs one info line.
    ///
    /// Non-blocking and safe under concurrent dials: pools whose locks are
    /// contended defer their drain, and a dial straddling the flush is
    /// discarded rather than cached.
    pub fn flush_for_outbound_interface_change<I>(
        &self,
        tcp: TrackedTcp,
        extra_roots: I,
    ) -> OutboundFlush
    where
        I: IntoIterator<Item = Arc<dyn Proxy>>,
    {
        let route = self.inner.route();
        let adapters = meow_common::reset_sessions_reachable(
            route.proxies.values().cloned().chain(extra_roots),
        );
        drop(route);
        let dns = self.resolver().reset_connections();
        meow_dns::reset_pooled_connections();
        let tcp = match tcp {
            TrackedTcp::Cancel => self.inner.stats.close_all_connections_counted(),
            TrackedTcp::AlreadyCancelled => 0,
        };
        let udp = self.close_all_udp_sessions();
        let flush = OutboundFlush {
            tcp,
            udp,
            dns,
            adapters,
        };
        info!(
            "Outbound interface binding changed: closed {tcp} TCP connections, \
             {udp} UDP sessions, {dns} pooled DNS connections; reset sessions \
             of {adapters} adapters"
        );
        flush
    }

    fn install_routing(&self, route: Arc<RouteTable>) -> Arc<RouteTable> {
        let needs_ip = route.needs_ip_resolution();
        // Publish inside the write hold so registry and route table swap
        // linearly — a concurrent installer can otherwise leave the registry
        // naming proxies the live route map already dropped (issue #489
        // review), matching the partial updaters above.
        let mut current = self.inner.route.write();
        self.publish_dialer_registry(&route);
        self.inner
            .needs_ip_resolution
            .store(needs_ip, Ordering::Relaxed);
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

    /// Fetch one adapter by name. Hazard: the returned `Arc` is detached
    /// from its generation pin — a `dialer-proxy`-chained adapter fetched
    /// this way fails closed as soon as the route generation that built it
    /// is swapped out. Dial paths must go through
    /// `TunnelInner::resolve_proxy` (or hold a `route_snapshot()` across the
    /// dial) so the registry cell stays pinned (issue #533 review).
    /// Test-only today.
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

    /// The commit-section half of [`Self::set_tun_handle`]: store the
    /// handle synchronously and return any replaced one, whose teardown
    /// the caller detaches — a config mutation's publish section holds
    /// the document write guard and may not await (issue #974 review).
    pub fn install_tun_handle(&self, handle: TunHandle) -> Option<TunHandle> {
        self.inner.tun_handle.write().replace(handle)
    }

    /// Store a running TUN listener handle. If a previous TUN listener was
    /// running, it is aborted and awaited — including its lwIP core's
    /// teardown — before this returns (issue #514).
    pub async fn set_tun_handle(&self, handle: TunHandle) {
        let prev = self.inner.tun_handle.write().replace(handle);
        // parking_lot RwLock write guard is dropped here — safe to .await
        if let Some(prev) = prev {
            teardown_tun(prev).await;
            info!("abandoned previous TUN listener");
        }
        info!("TUN listener handle stored");
    }

    /// Tear down a TUN listener handle that was never stored in the slot —
    /// a startup that finished after the committed config already moved on
    /// (#625): `stop_tun` operates on the *stored* slot and would kill a
    /// successor a concurrent config mutation already installed. Same
    /// abort + `core_done` teardown as the stored-slot paths.
    pub async fn teardown_tun_handle(&self, handle: TunHandle) {
        teardown_tun(handle).await;
        info!("discarded a stale TUN listener");
    }

    /// Abort the running top-level `tun:` listener, if that is what the
    /// slot holds, and wait for teardown — including the lwIP core's
    /// `core_done`, so a successor `NetStack::new` can never overlap this
    /// generation (issue #514). A [`TunOwner::Named`] handle is left
    /// running: named listeners are a startup snapshot no config mutation
    /// may stop (the PUT/PATCH admission gates keep a top-level enable
    /// from ever targeting the named owner's slot).
    pub async fn stop_tun(&self) {
        let handle = {
            let mut slot = self.inner.tun_handle.write();
            match slot.as_ref() {
                Some(h) if h.owner == TunOwner::TopLevel => slot.take(),
                _ => None,
            }
        };
        // parking_lot RwLock write guard is dropped here — safe to .await
        if let Some(handle) = handle {
            teardown_tun(handle).await;
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

    /// The owner of the stored TUN listener while it runs — `None` when
    /// the slot is empty or its task already exited (a dead handle claims
    /// no ownership: `set_tun_handle` may replace it). Consumers use this
    /// to keep top-level `tun:` reconcile/status off a
    /// [`TunOwner::Named`] device.
    pub fn tun_owner(&self) -> Option<TunOwner> {
        self.inner
            .tun_handle
            .read()
            .as_ref()
            .filter(|h| !h.task.is_finished())
            .map(|h| h.owner.clone())
    }

    /// Live TUN UDP flow-table occupancy (issue #515). Zero when no TUN
    /// listener is running — a stored handle whose task already exited
    /// reports zero rather than the gauge's frozen final value.
    pub fn tun_udp_flow_count(&self) -> usize {
        self.inner.tun_handle.read().as_ref().map_or(0, |h| {
            if h.task.is_finished() {
                0
            } else {
                h.udp_flows.load(std::sync::atomic::Ordering::Relaxed)
            }
        })
    }
}

impl Clone for Tunnel {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// 198.18.0.0/15 (RFC 2544 benchmarking): never routed on the internet,
/// and the default fake-IP range of Surge, Clash/mihomo and sing-box.
/// `Ipv4Addr::is_benchmarking` is still unstable.
fn is_benchmarking_ip(ip: std::net::IpAddr) -> bool {
    matches!(ip, std::net::IpAddr::V4(v4) if v4.octets()[0] == 198 && v4.octets()[1] & 0xfe == 18)
}

/// The inbound sniffed a name (not an IP literal) from the flow's first
/// bytes.
fn is_sniffed_name(metadata: &Metadata) -> bool {
    !metadata.sniff_host.is_empty()
        && metadata_ip_literal(&metadata.sniff_host).is_none()
        && is_valid_host(&metadata.sniff_host)
}

/// Whether a sniffed name disagrees with the name that will route and
/// dial the flow: non-empty and not `host` once the sniffed name's
/// trailing dots are ignored — the normalization `rule_host()` applies,
/// so an FQDN-spelled SNI (`mapped.test.` against `mapped.test`) is a
/// match, not a conflict. `rule_host()` prefers `sniff_host` while
/// `remote_address()` dials `host`, so an unresolved conflict lets
/// rules see one domain while the adapter dials another.
fn sniff_conflicts(sniff_host: &str, host: &str) -> bool {
    !sniff_host.is_empty() && sniff_host.trim_end_matches('.') != host
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
                            tunnel.reload_routing(
                                proxies,
                                candidate,
                                Default::default(),
                                None,
                                Default::default()
                            ),
                            1
                        );
                    } else {
                        tunnel.update_routing(
                            proxies,
                            candidate,
                            Default::default(),
                            Default::default(),
                        );
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
        tunnel.update_routing(proxies, vec![], Default::default(), registry);
        assert!(
            target.resolve().is_some(),
            "the route table retains its registry generation"
        );

        // `update_rules` rebuilds the table around the SAME proxies map —
        // it must preserve the generation's registry cell, or every chained
        // adapter strands on the next geo-DB refresh (issue #533 review).
        tunnel.update_rules(vec![]);
        assert!(
            target.resolve().is_some(),
            "update_rules must preserve the registry generation"
        );

        // A held route snapshot keeps the generation alive across a later
        // swap; the new generation's (empty) registry replaces it.
        let gen1 = tunnel.route_snapshot();
        tunnel.update_routing(
            HashMap::new(),
            vec![],
            Default::default(),
            ProxyRegistry::default(),
        );
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
            owner: TunOwner::TopLevel,
            core_done: None,
            udp_flows: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Issue #515: `tun_udp_flow_count` reads the live gauge only while the
    /// listener task runs — a stored-but-finished handle reports zero, not
    /// the gauge's frozen final value.
    #[tokio::test]
    async fn tun_udp_flow_count_tracks_live_gauge() {
        let tunnel = test_tunnel();
        assert_eq!(tunnel.tun_udp_flow_count(), 0, "no handle → zero");

        let gauge = Arc::new(std::sync::atomic::AtomicUsize::new(7));
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let mut handle = task_handle(tokio::spawn(async move {
            let _ = done_rx.await;
        }));
        handle.udp_flows = Arc::clone(&gauge);
        tunnel.set_tun_handle(handle).await;
        assert_eq!(tunnel.tun_udp_flow_count(), 7);

        gauge.store(3, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(tunnel.tun_udp_flow_count(), 3, "gauge is read live");

        // The task exits while the handle stays stored — the count must
        // read zero rather than the gauge's frozen final value.
        let _ = done_tx.send(());
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(
            tunnel.tun_udp_flow_count(),
            0,
            "a finished listener reports zero even though the gauge lingers"
        );
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
                owner: TunOwner::TopLevel,
                core_done: Some(done_rx),
                udp_flows: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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

    /// Named-TUN ownership (spec §3): the top-level `stop_tun` reconcile
    /// path must never reap a `listeners: type: tun` device — it reports
    /// through `tun_owner` and stays running.
    #[tokio::test]
    async fn stop_tun_never_touches_a_named_owner() {
        let tunnel = test_tunnel();
        let mut handle = task_handle(tokio::spawn(std::future::pending::<()>()));
        handle.owner = TunOwner::Named("edge-tun".into());
        tunnel.set_tun_handle(handle).await;

        assert_eq!(tunnel.tun_owner(), Some(TunOwner::Named("edge-tun".into())));
        tunnel.stop_tun().await;
        assert!(
            tunnel.has_tun(),
            "stop_tun must not reap a named TUN's slot"
        );
        assert_eq!(tunnel.tun_owner(), Some(TunOwner::Named("edge-tun".into())));
        // Reap the stored pending task so the test leaves no stray task.
        let stored = tunnel.inner.tun_handle.write().take().unwrap();
        tunnel.teardown_tun_handle(stored).await;
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

    /// #625: a startup that finishes after the committed config moved on
    /// must tear down *its* handle — abort + `core_done` wait — without
    /// touching a handle the PUT path already stored.
    #[tokio::test]
    async fn teardown_tun_handle_leaves_stored_handle_untouched() {
        let tunnel = test_tunnel();

        // A stored listener — stands in for the successor a config
        // mutation installed while startup was still bringing up.
        let (stored_tx, stored_rx) = tokio::sync::oneshot::channel();
        tunnel
            .set_tun_handle(task_handle(tokio::spawn(async move {
                let _ = stored_rx.await;
            })))
            .await;

        // The stale startup generation: task + core_done watch. The task
        // parks on a oneshot we resolve *before* spawning teardown, so by
        // assertion time its JoinHandle is already resolved — a teardown
        // that skipped `await_core_done` would then be finished, making
        // the `!is_finished` assert pin the core_done wait strictly.
        let (done_tx, done_rx) = tokio::sync::watch::channel(false);
        let (drop_tx, mut drop_rx) = tokio::sync::oneshot::channel();
        let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<()>();
        let stale = TunHandle {
            task: tokio::spawn(async move {
                let _guard = DropSignal(Some(drop_tx));
                let _ = exit_rx.await;
            }),
            owner: TunOwner::TopLevel,
            core_done: Some(done_rx),
            udp_flows: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let _ = exit_tx.send(());
        // Let the stale task run to completion so `task.await` inside
        // teardown resolves immediately.
        let mut exited = false;
        for _ in 0..100 {
            if drop_rx.try_recv().is_ok() {
                exited = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(exited, "stale task exited");

        // Teardown in a task so we can observe it pending on core_done.
        let teardown = tokio::spawn({
            let tunnel = tunnel.clone();
            async move { tunnel.teardown_tun_handle(stale).await }
        });
        tokio::task::yield_now().await;
        assert!(
            !teardown.is_finished(),
            "teardown_tun_handle must wait on core_done"
        );
        assert!(
            tunnel.has_tun(),
            "stored successor must survive the stale teardown"
        );

        done_tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), teardown)
            .await
            .expect("teardown returns once core_done fires")
            .unwrap();
        assert!(tunnel.has_tun(), "stored successor still running");

        // Clean shutdown of the stored handle.
        let _ = stored_tx.send(());
        tunnel.stop_tun().await;
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

    /// Every routing install must republish the proxies map into the
    /// dialer registry provider-sourced `dialer-proxy` targets resolve
    /// against — including the partial `update_proxies`/`update_rules`
    /// paths, not just wholesale `update_routing` (issue #489).
    #[test]
    fn routing_installs_republish_dialer_registry() {
        let tunnel = test_tunnel();
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        tunnel.set_dialer_registry(registry.clone());
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        let mut built = res.proxies;
        let direct = built.remove("DIRECT").unwrap();
        let build_registry = res.dialer_registry;

        tunnel.update_routing(
            HashMap::from([("DIRECT".into(), Arc::clone(&direct))]),
            vec![],
            Default::default(),
            build_registry.clone(),
        );
        assert!(
            meow_proxy::dialer::DialerTarget::new("DIRECT", &registry)
                .resolve()
                .is_some(),
            "update_routing must publish the proxies map"
        );

        tunnel.update_proxies(
            HashMap::from([("RENAMED".into(), Arc::clone(&direct))]),
            build_registry.clone(),
        );
        assert!(
            meow_proxy::dialer::DialerTarget::new("RENAMED", &registry)
                .resolve()
                .is_some(),
            "update_proxies must republish"
        );
        // Publish is a wholesale replace: a name absent from the new map must
        // stop resolving, not linger as a merge leftover.
        assert!(
            meow_proxy::dialer::DialerTarget::new("DIRECT", &registry)
                .resolve()
                .is_none(),
            "a removed name must stop resolving after republish"
        );

        // Discriminating check: clobber the registry with a foreign map
        // first — `update_rules` must actively republish, not merely leave
        // the previous publish untouched.
        registry.publish(std::sync::Arc::new(HashMap::new()));
        tunnel.update_rules(vec![]);
        assert!(
            meow_proxy::dialer::DialerTarget::new("RENAMED", &registry)
                .resolve()
                .is_some(),
            "update_rules must republish the proxies map, not leave a foreign map"
        );

        tunnel.reload_routing(
            HashMap::from([("RELOADED".into(), Arc::clone(&direct))]),
            vec![],
            Default::default(),
            None,
            build_registry,
        );
        assert!(
            meow_proxy::dialer::DialerTarget::new("RELOADED", &registry)
                .resolve()
                .is_some(),
            "reload_routing must republish through install_routing"
        );
    }

    /// Routing installs hand both dialer registries this tunnel's
    /// statistics, so a `dialer-proxy` hop counts toward the per-proxy
    /// totals of the member that carries it, never toward the tunnel totals.
    #[test]
    fn routing_installs_count_dialer_hops_into_the_statistics() {
        use meow_proxy::dialer::{DialerTarget, ProxyRegistry};

        let tunnel = test_tunnel();
        let provider_registry = ProxyRegistry::default();
        tunnel.set_dialer_registry(provider_registry.clone());
        let build_registry = ProxyRegistry::default();
        tunnel.update_routing(
            HashMap::new(),
            vec![],
            Default::default(),
            build_registry.clone(),
        );

        for registry in [&build_registry, &provider_registry] {
            let traffic = DialerTarget::new("fast", registry)
                .traffic()
                .expect("a routing install must attach the statistics");
            let hk = traffic.proxy_counters("HK-01").unwrap();
            hk.add_upload(7);
            hk.add_download(11);
        }
        let stats = tunnel.statistics();
        assert_eq!(stats.proxy_traffic().get("HK-01"), Some(&(14, 22)));
        stats.sample_traffic();
        assert_eq!(stats.traffic_snapshot(), (0, 0, 0, 0));
    }

    /// Issue #533: the built-in proxies map registers PASS / PASS-RULE /
    /// COMPATIBLE, and a rule targeting PASS skips silently to the next
    /// rule — upstream `continue GetRules` in `match()`.
    #[tokio::test]
    async fn pass_builtin_skips_matched_rule() {
        use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule};

        let tunnel = test_tunnel();
        let proxies = meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .proxies;
        for name in ["PASS", "PASS-RULE", "COMPATIBLE"] {
            assert!(
                proxies.contains_key(name),
                "built-in {name} must be registered"
            );
        }
        assert_eq!(proxies["PASS"].adapter_type(), AdapterType::Pass);
        assert_eq!(
            proxies["COMPATIBLE"].adapter_type(),
            AdapterType::Compatible
        );

        tunnel.update_routing(
            proxies,
            vec![
                Box::new(DomainSuffixRule::new("example.com", "PASS")),
                Box::new(FinalRule::new("REJECT")),
            ],
            Default::default(),
            Default::default(),
        );
        let meta = Metadata {
            host: "x.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let adapter = tunnel.inner().resolve_proxy(&meta).await.unwrap().adapter;
        assert_eq!(
            adapter.name(),
            "REJECT",
            "PASS-targeted rule must be skipped"
        );
    }

    /// Issue #969: a UDP flow matched to a rule targeting a
    /// `dialer-proxy` chain over a non-transparent inner
    /// (`support_udp() == false` by construction) must NOT slide to a
    /// later rule's target the way a missing target — or a plain
    /// `udp: false` node — does. `TargetCheck::Unusable` stops the scan
    /// *on* the match: resolution returns the named outbound and the
    /// flow fails at its dial, loudly, instead of silently rerouting
    /// through DIRECT.
    #[tokio::test]
    async fn udp_flow_to_udp_incapable_target_fails_closed() {
        use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule};

        let tunnel = test_tunnel();
        let mut proxies = meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .proxies;
        // The real chain shape, not just a UDP-less leaf: the
        // `DialerProxyAdapter` wraps a non-transparent inner
        // (`RecordingFront` is Socks5-typed), which is exactly what
        // `is_dialer_proxy_non_transparent` reports.
        let front: Arc<dyn Proxy> = Arc::new(RecordingFront {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let chained = Arc::new(meow_proxy::DialerProxyAdapter::new(
            front,
            meow_proxy::dialer::DialerTarget::new("hop", &registry),
        ));
        proxies.insert("NOUDP".into(), chained);
        tunnel.update_routing(
            proxies,
            vec![
                Box::new(DomainSuffixRule::new("example.com", "NOUDP")),
                Box::new(FinalRule::new("DIRECT")),
            ],
            Default::default(),
            Default::default(),
        );
        let meta = Metadata {
            host: "x.example.com".into(),
            dst_port: 443,
            network: Network::Udp,
            ..Default::default()
        };
        let adapter = tunnel.inner().resolve_proxy(&meta).await.unwrap().adapter;
        assert_eq!(
            adapter.name(),
            "front",
            "an existing-but-UDP-incapable target must be returned, not DIRECT"
        );
        // The same flow on TCP still picks the target, so the verdict is
        // scoped to the connection class like mihomo's SupportUDP check.
        let tcp_meta = Metadata {
            host: "x.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let adapter = tunnel
            .inner()
            .resolve_proxy(&tcp_meta)
            .await
            .unwrap()
            .adapter;
        assert_eq!(adapter.name(), "front");
    }

    /// The complement: a *missing* target keeps upstream `continue`
    /// semantics — the scan warns and slides to the next rule (issue
    /// #513), so the `Unusable` verdict must not have broken it.
    #[tokio::test]
    async fn missing_target_still_slides_to_the_next_rule() {
        use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule};

        let tunnel = test_tunnel();
        tunnel.update_routing(
            meow_config::rebuild_from_raw(&Default::default())
                .unwrap()
                .proxies,
            vec![
                Box::new(DomainSuffixRule::new("example.com", "GONE")),
                Box::new(FinalRule::new("DIRECT")),
            ],
            Default::default(),
            Default::default(),
        );
        let meta = Metadata {
            host: "x.example.com".into(),
            dst_port: 443,
            network: Network::Udp,
            ..Default::default()
        };
        let adapter = tunnel.inner().resolve_proxy(&meta).await.unwrap().adapter;
        assert_eq!(
            adapter.name(),
            "DIRECT",
            "absent targets keep continue-on-missing semantics"
        );
    }

    /// A rule targeting a group whose selected member is PASS also skips —
    /// the match loop walks `unwrap_proxy(metadata, false)` for the type
    /// tag without committing selection side effects.
    #[tokio::test]
    async fn pass_inside_group_unwrap_skips_rule() {
        use meow_proxy::SelectorGroup;
        use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule};

        let tunnel = test_tunnel();
        let mut proxies = meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .proxies;
        let pass_member: Arc<dyn Proxy> = Arc::new(meow_config::proxy_parser::WrappedProxy::new(
            Box::new(meow_proxy::RejectAdapter::pass()),
        ));
        proxies.insert(
            "SEL".into(),
            Arc::new(SelectorGroup::new("SEL", vec![pass_member])),
        );
        tunnel.update_routing(
            proxies,
            vec![
                Box::new(DomainSuffixRule::new("example.com", "SEL")),
                Box::new(FinalRule::new("DIRECT")),
            ],
            Default::default(),
            Default::default(),
        );
        let meta = Metadata {
            host: "x.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let adapter = tunnel.inner().resolve_proxy(&meta).await.unwrap().adapter;
        assert_eq!(
            adapter.name(),
            "DIRECT",
            "rule matching a PASS-bearing group must fall through"
        );
    }

    /// PASS-RULE targeted at the top level behaves like REJECT — the match
    /// returns it and dialing yields immediate EOF, same as upstream's
    /// nop adapter.
    #[tokio::test]
    async fn pass_rule_at_top_level_rejects() {
        use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule};

        let tunnel = test_tunnel();
        let proxies = meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .proxies;
        tunnel.update_routing(
            proxies,
            vec![
                Box::new(DomainSuffixRule::new("example.com", "PASS-RULE")),
                Box::new(FinalRule::new("DIRECT")),
            ],
            Default::default(),
            Default::default(),
        );
        let meta = Metadata {
            host: "x.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let adapter = tunnel.inner().resolve_proxy(&meta).await.unwrap().adapter;
        assert_eq!(
            adapter.adapter_type(),
            AdapterType::PassRule,
            "top-level PASS-RULE must materialize as its own adapter"
        );
    }

    /// COMPATIBLE resolves like any real target and buckets its stats as
    /// `"DIRECT"` — it is a direct dialer, not a signal adapter.
    #[tokio::test]
    async fn compatible_resolves_and_buckets_direct() {
        use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule};

        let tunnel = test_tunnel();
        let proxies = meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .proxies;
        tunnel.update_routing(
            proxies,
            vec![
                Box::new(DomainSuffixRule::new("example.com", "COMPATIBLE")),
                Box::new(FinalRule::new("REJECT")),
            ],
            Default::default(),
            Default::default(),
        );
        let meta = Metadata {
            host: "x.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let adapter = tunnel.inner().resolve_proxy(&meta).await.unwrap().adapter;
        assert_eq!(
            adapter.adapter_type(),
            AdapterType::Compatible,
            "COMPATIBLE must materialize, not be skipped"
        );
        let stats = tunnel.inner().stats.rule_match.snapshot();
        assert!(
            stats
                .iter()
                .any(|((_, action), n)| *action == "DIRECT" && *n == 1),
            "COMPATIBLE match must bucket as DIRECT, got: {stats:?}"
        );
    }

    /// UDP needs a concrete address before routing. When the main
    /// nameservers cannot answer, a DIRECT-routed flow falls back to
    /// `dns.direct-nameserver`; any other route never reaches it.
    #[tokio::test]
    async fn resolve_udp_dst_falls_back_to_direct_resolver_for_direct_routes() {
        use meow_dns::HostEntry;
        use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule};
        use std::net::IpAddr;

        let direct_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        hosts.insert("direct.test", vec![direct_ip].into());
        hosts.insert("proxied.test", vec![direct_ip].into());
        let direct = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);
        // No upstreams and no hosts: every main lookup fails.
        let mut main = Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );
        main.set_direct_resolver(Arc::new(direct));
        let tunnel = Tunnel::new(Arc::new(main));

        let proxies = meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .proxies;
        tunnel.update_routing(
            proxies,
            vec![
                Box::new(DomainSuffixRule::new("direct.test", "DIRECT")),
                Box::new(FinalRule::new("REJECT")),
            ],
            Default::default(),
            Default::default(),
        );

        let udp = |host: &str| Metadata {
            network: Network::Udp,
            host: host.into(),
            dst_port: 443,
            ..Default::default()
        };
        let mut routed_direct = udp("direct.test");
        tunnel.inner().resolve_udp_dst(&mut routed_direct).await;
        assert_eq!(routed_direct.dst_ip, Some(direct_ip));

        let mut proxied = udp("proxied.test");
        tunnel.inner().resolve_udp_dst(&mut proxied).await;
        assert_eq!(
            proxied.dst_ip, None,
            "non-DIRECT routes stay off direct-nameserver"
        );
    }

    /// `resolve_udp_dst`'s route probe is bookkeeping-free: the flow's
    /// real `resolve_proxy` right after is what counts the hit — the pair
    /// must tally one, not two (issue #882 review).
    #[tokio::test]
    async fn resolve_udp_dst_probe_records_no_hit() {
        use meow_dns::HostEntry;
        use meow_rules::domain_suffix::DomainSuffixRule;
        use meow_rules::final_rule::FinalRule;
        use std::net::IpAddr;

        let direct_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        hosts.insert("direct.test", vec![direct_ip].into());
        let direct = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);
        // No upstreams and no hosts: every main lookup fails, so the
        // direct-resolver probe runs.
        let mut main = Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        );
        main.set_direct_resolver(Arc::new(direct));
        let tunnel = Tunnel::new(Arc::new(main));

        let proxies = meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .proxies;
        tunnel.update_routing(
            proxies,
            vec![
                Box::new(DomainSuffixRule::new("direct.test", "DIRECT")),
                Box::new(FinalRule::new("REJECT")),
            ],
            Default::default(),
            Default::default(),
        );

        let mut meta = Metadata {
            network: Network::Udp,
            host: "direct.test".into(),
            dst_port: 443,
            ..Default::default()
        };
        tunnel.inner().resolve_udp_dst(&mut meta).await;
        assert_eq!(meta.dst_ip, Some(direct_ip));
        let route = tunnel.route_snapshot();
        assert_eq!(
            route.rule_stats.view(0).hits,
            0,
            "the probe must not record a hit"
        );
        tunnel.inner().resolve_proxy(&meta).await.unwrap();
        assert_eq!(
            route.rule_stats.view(0).hits,
            1,
            "the real resolution counts once"
        );
    }

    /// Front-hop mock for the provider-dialer e2e: records every
    /// `dial_tcp`'s metadata and refuses the connection — observing the
    /// dial proves the provider node's `dialer-proxy` chain resolved.
    struct RecordingFront {
        seen: std::sync::Mutex<Vec<Metadata>>,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for RecordingFront {
        fn name(&self) -> &str {
            "front"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Socks5
        }
        fn addr(&self) -> &str {
            "127.0.0.1:1080"
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            self.seen.lock().unwrap().push(metadata.clone());
            Err(meow_common::MeowError::NotSupported(
                "recording front refuses connections".to_string(),
            ))
        }
        async fn dial_udp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            unimplemented!("test mock has no UDP")
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            static H: std::sync::OnceLock<meow_common::ProxyHealth> = std::sync::OnceLock::new();
            H.get_or_init(meow_common::ProxyHealth::new)
        }
    }

    impl Proxy for RecordingFront {
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
            Vec::new()
        }
    }

    /// Issue #489 end-to-end: a provider node's `dialer-proxy` must resolve
    /// through the *same* registry cell the tunnel republishes — the one
    /// `set_dialer_registry` installs. Any break in the
    /// `load_proxy_providers → Config::provider_dialer_registry →
    /// set_dialer_registry → update_routing` chain leaves the provider
    /// node's dialer pointing at a dead cell and the dial fails closed
    /// without ever reaching `front`.
    #[tokio::test]
    async fn provider_dialer_proxy_dials_through_published_registry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: n1, type: socks5, server: 127.0.0.1, \
             port: 1, dialer-proxy: front}\n",
        )
        .unwrap();

        let provider_registry = meow_proxy::dialer::ProxyRegistry::default();
        let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(
            "proxy-providers:\n  prov:\n    type: file\n    path: nodes.yaml\n",
        )
        .unwrap();
        let providers = meow_config::proxy_provider::load_proxy_providers(
            raw.proxy_providers.as_ref().unwrap(),
            Some(dir.path()),
            false,
            false,
            &provider_registry,
        )
        .await
        .unwrap();
        let provider = Arc::clone(&providers["prov"]);
        assert_eq!(provider.proxies().len(), 1, "file provider must load n1");

        // A group over the provider slot puts the provider node into the
        // route map's reachable set, exactly like `use: [prov]` does.
        let front = Arc::new(RecordingFront {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let group: Arc<dyn Proxy> = Arc::new(meow_proxy::SelectorGroup::new_with_providers(
            "g",
            vec![],
            vec![Arc::clone(&provider.slot)],
        ));

        let tunnel = test_tunnel();
        tunnel.set_dialer_registry(provider_registry.clone());
        tunnel.update_routing(
            HashMap::from([
                ("front".into(), Arc::clone(&front) as Arc<dyn Proxy>),
                ("g".into(), group),
            ]),
            vec![Box::new(meow_rules::final_rule::FinalRule::new("g"))],
            Default::default(),
            Default::default(),
        );

        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let adapter = tunnel.inner().resolve_proxy(&meta).await.unwrap().adapter;
        assert_eq!(adapter.name(), "g");
        // The group selects n1, whose socks5 adapter dials 127.0.0.1:1
        // through the injected `front` hop; the front records the dial and
        // refuses, so the observable signal is the recorded metadata.
        adapter
            .dial_tcp(&meta)
            .await
            .err()
            .expect("the recording front refuses");
        let seen = front.seen.lock().unwrap();
        let [dial] = seen.as_slice() else {
            panic!("the provider node's chained dial must reach the front hop: {seen:?}")
        };
        assert_eq!(dial.dst_ip, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(dial.dst_port, 1);
    }

    /// Issue #515: the PROCESS-* enrichment call inside `resolve_proxy`
    /// itself — not just the helper — must run when the compiled rule set
    /// demands it. A regression that dropped the `.await` enrichment would
    /// leave every test here green while PROCESS rules silently stop
    /// matching in production.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn resolve_proxy_invokes_process_enrichment() {
        meow_common::disable_socket_table_cache();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        let proc_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_default();
        assert!(!proc_name.is_empty(), "expected a test binary name");

        let tunnel = test_tunnel();
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        let mut proxies = res.proxies;
        let direct = Arc::clone(proxies.get("DIRECT").unwrap());
        proxies.insert("proc-target".into(), direct);
        tunnel.update_routing(
            proxies,
            vec![
                Box::new(meow_rules::process::ProcessRule::new(
                    &proc_name,
                    "proc-target",
                )) as Box<dyn Rule>,
                Box::new(meow_rules::final_rule::FinalRule::new("DIRECT")),
            ],
            Default::default(),
            res.dialer_registry,
        );

        let metadata = Metadata {
            network: Network::Tcp,
            src_ip: Some(local.ip()),
            src_port: local.port(),
            dst_port: 443,
            ..Default::default()
        };
        let resolved = tunnel
            .inner()
            .resolve_proxy(&metadata)
            .await
            .expect("rule table must resolve");
        // The adapter re-registered under "proc-target" is the DIRECT
        // instance, so `adapter.name()` stays "DIRECT" — pin the matched
        // rule instead, which is what proves the enrichment ran.
        assert_eq!(
            resolved.rule_name, "ProcessName",
            "PROCESS-NAME rule must match the enrichment done inside resolve_proxy"
        );
    }

    /// Adapter counting `reset_sessions` calls; a group when `members` is
    /// non-empty.
    struct ResetCounting {
        resets: std::sync::atomic::AtomicUsize,
        members: Vec<Arc<dyn Proxy>>,
        health: meow_common::ProxyHealth,
    }

    impl ResetCounting {
        fn new(members: Vec<Arc<dyn Proxy>>) -> Arc<Self> {
            Arc::new(Self {
                resets: std::sync::atomic::AtomicUsize::new(0),
                members,
                health: meow_common::ProxyHealth::new(),
            })
        }

        fn resets(&self) -> usize {
            self.resets.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for ResetCounting {
        fn name(&self) -> &str {
            "reset-counting"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            Err(meow_common::MeowError::NotSupported(
                "reset-counting".into(),
            ))
        }
        async fn dial_udp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            Err(meow_common::MeowError::NotSupported(
                "reset-counting".into(),
            ))
        }
        fn reset_sessions(&self) {
            self.resets.fetch_add(1, Ordering::SeqCst);
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl Proxy for ResetCounting {
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
            Vec::new()
        }
        fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
            (!self.members.is_empty()).then(|| self.members.clone())
        }
    }

    fn tracked_tcp(tunnel: &Tunnel) -> crate::ConnectionGuard<'_> {
        crate::ConnectionGuard::track(
            tunnel.statistics(),
            Metadata {
                network: meow_common::Network::Tcp,
                host: "example.com".into(),
                dst_port: 443,
                ..Default::default()
            },
            "MATCH".into(),
            "".into(),
            smallvec::smallvec![],
        )
    }

    /// Issue #695: the flush resets every distinct adapter reachable from
    /// the route table and the extra roots exactly once (a leaf shared by a
    /// group and the map included), cancels tracked TCP only when asked, and
    /// closes the tunnel's and the listeners' UDP sessions.
    #[tokio::test]
    async fn outbound_interface_flush_resets_reachable_adapters_and_closes_flows() {
        let tunnel = test_tunnel();
        let in_group = ResetCounting::new(vec![]);
        let shared = ResetCounting::new(vec![]);
        let group = ResetCounting::new(vec![
            Arc::clone(&in_group) as Arc<dyn Proxy>,
            Arc::clone(&shared) as Arc<dyn Proxy>,
        ]);
        let provider_only = ResetCounting::new(vec![]);
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert("GROUP".into(), Arc::clone(&group) as Arc<dyn Proxy>);
        proxies.insert("SHARED".into(), Arc::clone(&shared) as Arc<dyn Proxy>);
        tunnel.update_routing(proxies, vec![], Default::default(), Default::default());

        let first = tracked_tcp(&tunnel);
        let second = tracked_tcp(&tunnel);
        tunnel.inner().nat_table.insert(
            (
                "127.0.0.1:1000".parse().unwrap(),
                "198.51.100.1:443".parse().unwrap(),
            ),
            Arc::new(crate::udp::UdpSession::new(
                meow_proxy::RejectAdapter::new(false)
                    .dial_udp(&Metadata::default())
                    .await
                    .expect("reject packet conn"),
                Arc::from("test"),
            )),
        );
        let listener_flow = tunnel.inner().udp_flush_watch();

        let flush = tunnel.flush_for_outbound_interface_change(
            TrackedTcp::Cancel,
            [Arc::clone(&provider_only) as Arc<dyn Proxy>],
        );
        assert_eq!(
            flush,
            OutboundFlush {
                tcp: 2,
                udp: 2,
                dns: 0,
                adapters: 4,
            }
        );
        for adapter in [&group, &in_group, &shared, &provider_only] {
            assert_eq!(adapter.resets(), 1, "each adapter is reset exactly once");
        }
        assert!(first.run_until_closed(async {}).await.is_none());
        assert!(second.run_until_closed(async {}).await.is_none());
        assert!(tunnel.inner().nat_table.is_empty());
        assert!(listener_flow.is_flushed());
        drop((first, second, listener_flow));

        // A cold reload already cancelled TCP: the flush leaves it alone.
        let survivor = tracked_tcp(&tunnel);
        let flush = tunnel.flush_for_outbound_interface_change(TrackedTcp::AlreadyCancelled, []);
        assert_eq!((flush.tcp, flush.udp, flush.adapters), (0, 0, 3));
        assert_eq!(
            survivor.run_until_closed(async { "relay" }).await,
            Some("relay")
        );
    }

    fn fake_ip_tunnel(range: &str) -> Tunnel {
        let mut resolver = Resolver::new(
            vec![],
            vec![],
            DnsMode::FakeIp,
            DomainTrie::new(),
            true,
            true,
        );
        let pool = meow_dns::fakeip::Pool::new(
            range.parse().unwrap(),
            Arc::new(meow_dns::fakeip::MemoryStore::new(1024)),
        )
        .unwrap();
        resolver.set_fakeip_v4(Arc::new(pool));
        Tunnel::new(Arc::new(resolver))
    }

    fn tcp_flow(dst: [u8; 4], sniff_host: &str) -> Metadata {
        Metadata {
            network: Network::Tcp,
            dst_ip: Some(std::net::IpAddr::from(dst)),
            dst_port: 443,
            sniff_host: sniff_host.into(),
            ..Default::default()
        }
    }

    /// Issue #734: a name that is not a hostname never reaches rule
    /// matching or a dial — whether the inbound put it in `host`, a fake IP
    /// maps back to it (DNS query names are raw label bytes), or a sniffer
    /// produced it.
    #[test]
    fn non_hostname_names_are_dropped_or_ignored() {
        let tunnel = test_tunnel();
        let inner = tunnel.inner();
        for host in [
            "a@evil.com",
            "user:pass@evil.com",
            "evil.com/x",
            "evil.com?q",
        ] {
            let mut md = Metadata {
                network: Network::Tcp,
                host: host.into(),
                dst_port: 443,
                ..Default::default()
            };
            assert_eq!(
                inner.pre_handle_metadata(&mut md),
                PreHandleVerdict::Drop,
                "{host:?}"
            );
        }
        // Hostnames and literals still pass.
        for host in ["evil.com", "_sip._tcp.example.com", "xn--fiqs8s", "[::1]"] {
            let mut md = Metadata {
                network: Network::Tcp,
                host: host.into(),
                dst_port: 443,
                ..Default::default()
            };
            assert_eq!(
                inner.pre_handle_metadata(&mut md),
                PreHandleVerdict::Continue,
                "{host:?}"
            );
        }

        // A fake IP allocated for a non-hostname query name.
        let mut resolver = Resolver::new(
            vec![],
            vec![],
            DnsMode::FakeIp,
            DomainTrie::new(),
            true,
            true,
        );
        let pool = Arc::new(
            meow_dns::fakeip::Pool::new(
                "198.18.0.1/16".parse().unwrap(),
                Arc::new(meow_dns::fakeip::MemoryStore::new(1024)),
            )
            .unwrap(),
        );
        let bad_fake = pool.lookup("a@evil.com");
        let good_fake = pool.lookup("good.example");
        resolver.set_fakeip_v4(pool);
        let tunnel = Tunnel::new(Arc::new(resolver));
        let inner = tunnel.inner();
        let mut md = Metadata {
            network: Network::Tcp,
            dst_ip: Some(bad_fake),
            dst_port: 443,
            ..Default::default()
        };
        assert_eq!(inner.pre_handle_metadata(&mut md), PreHandleVerdict::Drop);
        let mut md = Metadata {
            network: Network::Tcp,
            dst_ip: Some(good_fake),
            dst_port: 443,
            ..Default::default()
        };
        assert_eq!(
            inner.pre_handle_metadata(&mut md),
            PreHandleVerdict::Continue
        );
        assert_eq!(md.host, "good.example");

        // A non-hostname sniffed name is not a rescue for a foreign fake IP.
        let tunnel = fake_ip_tunnel("28.0.0.0/8");
        let mut md = tcp_flow([198, 18, 1, 220], "a@evil.com");
        assert_eq!(
            tunnel.inner().pre_handle_metadata(&mut md),
            PreHandleVerdict::Continue
        );
        assert_eq!(md.host, "");
        assert_eq!(md.dst_ip, Some([198, 18, 1, 220].into()));
    }

    #[test]
    fn benchmarking_range_is_198_18_slash_15() {
        for (ip, want) in [
            ("198.17.255.255", false),
            ("198.18.0.0", true),
            ("198.18.1.220", true),
            ("198.19.255.255", true),
            ("198.20.0.0", false),
            ("28.0.0.1", false),
            ("::ffff:198.18.0.1", false),
        ] {
            assert_eq!(is_benchmarking_ip(ip.parse().unwrap()), want, "{ip}");
        }
    }

    /// A LAN gateway's fake IP (Surge / Clash, 198.18.0.0/15) outside our
    /// own range: the sniffed name replaces the literal, which no proxy can
    /// reach.
    #[test]
    fn foreign_fake_ip_dials_the_sniffed_name() {
        // Mobile clients pin 28.0.0.0/8; desktop defaults to 198.18.0.1/16,
        // which leaves Surge's upper half 198.19.0.0/16 foreign.
        for (range, dst) in [
            ("28.0.0.0/8", [198, 18, 1, 220]),
            ("198.18.0.1/16", [198, 19, 0, 5]),
        ] {
            let tunnel = fake_ip_tunnel(range);
            let inner = tunnel.inner();
            assert!(inner.needs_sniffed_name(&tcp_flow(dst, "")), "{range}");
            let mut md = tcp_flow(dst, "account.example.com");
            assert!(!inner.needs_sniffed_name(&md), "{range}");
            assert_eq!(
                inner.pre_handle_metadata(&mut md),
                PreHandleVerdict::Continue
            );
            assert_eq!(md.host, "account.example.com", "{range}");
            assert_eq!(md.dst_ip, None, "{range}");
        }
    }

    /// `override-destination: true` and the tproxy listener promote the
    /// sniffed name into `host` before the tunnel sees the flow. The
    /// foreign literal must still go: DIRECT dials `dst_ip` first and
    /// `pre_resolve` skips a flow that has one.
    #[test]
    fn foreign_fake_ip_literal_goes_when_the_inbound_promoted_the_name() {
        let tunnel = fake_ip_tunnel("28.0.0.0/8");
        let inner = tunnel.inner();
        let mut md = tcp_flow([198, 18, 1, 220], "account.example.com");
        md.host = md.sniff_host.clone();
        assert_eq!(
            inner.pre_handle_metadata(&mut md),
            PreHandleVerdict::Continue
        );
        assert_eq!(md.host, "account.example.com");
        assert_eq!(md.dst_ip, None);

        // A host that is not the sniffed name came from the client (or an
        // earlier layer) and is not ours to second-guess.
        let mut other = tcp_flow([198, 18, 1, 220], "sni.example.com");
        other.host = "client.example.com".into();
        assert_eq!(
            inner.pre_handle_metadata(&mut other),
            PreHandleVerdict::Continue
        );
        assert_eq!(other.host, "client.example.com");
        assert_eq!(other.dst_ip, Some([198, 18, 1, 220].into()));
    }

    /// Everything outside the rescue keeps its literal: a real address
    /// even with a sniffed name (`override-destination` stays the only
    /// switch for that), a foreign fake IP with nothing sniffed, a sniffed
    /// IP literal, and a snooped name, which wins over the sniffed one.
    #[test]
    fn foreign_fake_ip_rescue_leaves_other_flows_alone() {
        let tunnel = fake_ip_tunnel("28.0.0.0/8");
        let inner = tunnel.inner();

        let mut real = tcp_flow([93, 184, 216, 34], "example.com");
        assert!(!inner.needs_sniffed_name(&real));
        assert_eq!(
            inner.pre_handle_metadata(&mut real),
            PreHandleVerdict::Continue
        );
        assert_eq!(real.host, "");
        assert_eq!(real.dst_ip, Some([93, 184, 216, 34].into()));

        for sniffed in ["", "198.18.1.220"] {
            let mut md = tcp_flow([198, 18, 1, 220], sniffed);
            assert_eq!(
                inner.pre_handle_metadata(&mut md),
                PreHandleVerdict::Continue
            );
            assert_eq!(md.host, "", "sniffed {sniffed:?}");
            assert_eq!(
                md.dst_ip,
                Some([198, 18, 1, 220].into()),
                "sniffed {sniffed:?}"
            );
        }

        tunnel.resolver().preload_cache(
            "snooped.example.com",
            &[[198, 18, 1, 220].into()],
            std::time::Duration::from_secs(60),
        );
        assert!(!inner.needs_sniffed_name(&tcp_flow([198, 18, 1, 220], "")));
        // The snooped name keeps the literal even when the sniff agrees:
        // our upstream DNS answered with it, so it is reachable that way.
        for sniffed in ["sni.example.com", "snooped.example.com"] {
            let mut snooped = tcp_flow([198, 18, 1, 220], sniffed);
            assert_eq!(
                inner.pre_handle_metadata(&mut snooped),
                PreHandleVerdict::Continue
            );
            assert_eq!(snooped.host, "snooped.example.com", "{sniffed}");
            assert_eq!(snooped.dst_ip, Some([198, 18, 1, 220].into()), "{sniffed}");
            assert_eq!(
                snooped.dns_mode,
                DnsMode::Mapping,
                "a snooped name is tagged like upstream `DNSMapping` ({sniffed})"
            );
        }
        assert_eq!(real.dns_mode, DnsMode::Normal, "no snoop, no tag");
    }

    /// The sniff gate mirrors the rescue paths: an unmapped address in our
    /// own range needs a name; a mapped one, a named flow and a flow the
    /// inbound already sniffed do not.
    #[tokio::test]
    async fn needs_sniffed_name_follows_the_pool() {
        let tunnel = fake_ip_tunnel("28.0.0.0/8");
        let inner = tunnel.inner();
        assert!(inner.needs_sniffed_name(&tcp_flow([28, 0, 0, 9], "")));
        assert!(!inner.needs_sniffed_name(&tcp_flow([28, 0, 0, 9], "sni.example.com")));
        // A sniffed IP literal is no name either.
        assert!(inner.needs_sniffed_name(&tcp_flow([28, 0, 0, 9], "28.0.0.9")));

        let mapped = tunnel
            .resolver()
            .lookup_ipv4("mapped.example.com")
            .await
            .unwrap();
        let mut md = tcp_flow([0, 0, 0, 0], "");
        md.dst_ip = Some(mapped);
        assert!(!inner.needs_sniffed_name(&md));

        let mut named = tcp_flow([198, 18, 1, 220], "");
        named.host = "socks.example.com".into();
        assert!(!inner.needs_sniffed_name(&named));
        // A literal in `host` is no name.
        named.host = "198.18.1.220".into();
        named.dst_ip = None;
        assert!(inner.needs_sniffed_name(&named));
    }

    // ---- `find-process-mode` (issue #974) ------------------------------
    //
    // The platform socket-table scan is replaced by a counted hook so
    // every assertion is deterministic on every OS.

    use meow_common::{RuleMatchHelper, RuleType};
    use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule};

    /// A flow carrying a real source tuple — what an inbound hands the
    /// tunnel.
    fn flow_meta() -> Metadata {
        Metadata {
            network: Network::Tcp,
            src_ip: Some("127.0.0.1".parse().unwrap()),
            src_port: 51234,
            host: "a.example.com".into(),
            dst_port: 443,
            ..Default::default()
        }
    }

    /// The counted lookup seam: installs a hook returning `hit` (or
    /// recording a miss) and hands back the call counter.
    fn counting_hook(
        tunnel: &Tunnel,
        hit: Option<ProcessInfo>,
    ) -> Arc<std::sync::atomic::AtomicUsize> {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        tunnel.set_process_lookup_hook(Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            hit.clone()
        }));
        calls
    }

    fn scan_count(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(Ordering::SeqCst)
    }

    fn owner() -> ProcessInfo {
        ProcessInfo {
            name: "stub-owner".into(),
            path: "/usr/bin/stub-owner".into(),
            uid: Some(1000),
        }
    }

    /// A PROCESS-NAME rule with a *deterministic* demand — unlike the real
    /// `ProcessRule`, whose `should_find_process` folds to the platform,
    /// this one demands on every OS so the tests below run everywhere.
    /// (A negated variant cannot be a stub: the IR lowers `ProcessName`
    /// opaquely — negation needs a real `NotRule` around a real rule.)
    struct DemandProcess {
        name: &'static str,
        adapter: &'static str,
    }

    impl DemandProcess {
        fn new(name: &'static str, adapter: &'static str) -> Self {
            Self { name, adapter }
        }
    }

    impl Rule for DemandProcess {
        fn rule_type(&self) -> RuleType {
            RuleType::ProcessName
        }
        fn match_metadata(&self, m: &Metadata, _: &RuleMatchHelper) -> bool {
            m.process.eq_ignore_ascii_case(self.name)
        }
        fn adapter(&self) -> &str {
            self.adapter
        }
        fn payload(&self) -> &str {
            self.name
        }
        fn should_find_process(&self) -> bool {
            true
        }
    }

    /// A tunnel in Rule mode carrying `rules` over the stock proxies.
    fn rule_tunnel(rules: Vec<Box<dyn Rule>>) -> Tunnel {
        let tunnel = test_tunnel();
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        tunnel.set_mode(TunnelMode::Rule);
        tunnel.update_routing(res.proxies, rules, Default::default(), res.dialer_registry);
        tunnel
    }

    /// `always`: the pre-dispatch scan runs with NO process rule at all —
    /// and writes the owner into the tracked metadata itself (upstream
    /// fills `metadata.Process*` before dispatch).
    #[tokio::test]
    async fn always_enriches_rule_mode_without_process_rules() {
        let tunnel = rule_tunnel(vec![Box::new(FinalRule::new("DIRECT"))]);
        tunnel.set_process_lookup_mode(ProcessLookupMode::Always);
        let calls = counting_hook(&tunnel, Some(owner()));

        let mut md = flow_meta();
        let resolved = tunnel
            .inner()
            .resolve_proxy_flow(&mut md)
            .await
            .expect("FINAL always resolves");
        assert_eq!(resolved.adapter.name(), "DIRECT");
        assert_eq!(scan_count(&calls), 1);
        assert_eq!(md.process, "stub-owner", "always must write back");
        assert_eq!(md.process_path, "/usr/bin/stub-owner");
        assert_eq!(md.uid, Some(1000));
    }

    /// `always`: the same pre-dispatch scan runs in Direct and Global —
    /// the lookup precedes the mode dispatch, so it is not Rule-only.
    #[tokio::test]
    async fn always_enriches_direct_and_global_modes() {
        for mode in [TunnelMode::Direct, TunnelMode::Global] {
            let tunnel = test_tunnel();
            let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
            tunnel.update_routing(res.proxies, vec![], Default::default(), res.dialer_registry);
            tunnel.set_mode(mode);
            tunnel.set_process_lookup_mode(ProcessLookupMode::Always);
            let calls = counting_hook(&tunnel, Some(owner()));

            let mut md = flow_meta();
            tunnel
                .inner()
                .resolve_proxy_flow(&mut md)
                .await
                .expect("every mode resolves");
            assert_eq!(scan_count(&calls), 1, "{mode:?} must scan once");
            assert_eq!(md.process, "stub-owner", "{mode:?} must write back");
        }
    }

    /// `always` honors every skip: housekeeping flows, an explicit
    /// `specialProxy`, a supplied owner, and a flow without a usable
    /// source tuple cost no scan.
    #[tokio::test]
    async fn always_skips_ineligible_flows() {
        let tunnel = rule_tunnel(vec![Box::new(FinalRule::new("DIRECT"))]);
        tunnel.set_process_lookup_mode(ProcessLookupMode::Always);
        let calls = counting_hook(&tunnel, Some(owner()));

        let mut internal = flow_meta();
        internal.internal = true;
        tunnel.inner().resolve_proxy_flow(&mut internal).await;

        let mut proxied = flow_meta();
        proxied.set_special_route(Some("PROXY"), None);
        tunnel.inner().resolve_proxy_flow(&mut proxied).await;

        let mut named = flow_meta();
        named.process = "curl".into();
        tunnel.inner().resolve_proxy_flow(&mut named).await;

        let mut no_tuple = flow_meta();
        no_tuple.src_ip = None;
        tunnel.inner().resolve_proxy_flow(&mut no_tuple).await;
        let mut no_port = flow_meta();
        no_port.src_port = 0;
        tunnel.inner().resolve_proxy_flow(&mut no_port).await;

        assert_eq!(scan_count(&calls), 0, "ineligible flows must not scan");
        assert_eq!(named.process, "curl", "a supplied owner is kept");
        // Every skip is recorded on the flow's memo — unmarked, a later
        // process-demanding slot could rescan what this pass refused
        // (issue #974). `proxied` marks it too: a forced route skips the
        // lookup, but an unmarked memo would let the ledger treat the OS
        // scan as unattempted and run it downstream.
        for md in [&internal, &proxied, &named, &no_tuple, &no_port] {
            assert!(
                md.flow_lookup.process_attempted(),
                "the skip must be recorded"
            );
        }
    }

    /// `always`: a flow the pre-dispatch skip refused is marked attempted,
    /// so a process-demanding slot reached after it cannot rescan — its
    /// predicate just evaluates the still-empty fields (issue #974).
    #[tokio::test]
    async fn always_skip_marks_flow_attempted() {
        let tunnel = rule_tunnel(vec![
            Box::new(DemandProcess::new("stub-owner", "REJECT")),
            Box::new(FinalRule::new("DIRECT")),
        ]);
        tunnel.set_process_lookup_mode(ProcessLookupMode::Always);
        let calls = counting_hook(&tunnel, Some(owner()));

        let mut md = flow_meta();
        md.internal = true;
        let resolved = tunnel
            .inner()
            .resolve_proxy_flow(&mut md)
            .await
            .expect("rules resolve");
        assert_eq!(
            resolved.adapter.name(),
            "DIRECT",
            "the empty process field misses the reached slot"
        );
        assert_eq!(
            scan_count(&calls),
            0,
            "the skipped flow must not rescan at the slot"
        );
        assert!(md.flow_lookup.process_attempted());
    }

    /// `always` never overwrites fields the inbound already supplied: the
    /// lookup fills only the empty ones.
    #[tokio::test]
    async fn always_fills_only_empty_process_fields() {
        let tunnel = rule_tunnel(vec![Box::new(FinalRule::new("DIRECT"))]);
        tunnel.set_process_lookup_mode(ProcessLookupMode::Always);
        counting_hook(&tunnel, Some(owner()));

        let mut md = flow_meta();
        md.process_path = "/opt/supplied".into();
        md.uid = Some(7);
        tunnel.inner().resolve_proxy_flow(&mut md).await;
        assert_eq!(md.process, "stub-owner", "empty name is filled");
        assert_eq!(md.process_path, "/opt/supplied", "supplied path kept");
        assert_eq!(md.uid, Some(7), "supplied uid kept");
    }

    /// `strict`: a flow decided by an earlier domain rule never pays the
    /// scan — the reached slot demands nothing.
    #[tokio::test]
    async fn strict_earlier_domain_win_scans_never() {
        let tunnel = rule_tunnel(vec![
            Box::new(DomainSuffixRule::new("example.com", "REJECT")),
            Box::new(DemandProcess::new("stub-owner", "DIRECT")),
            Box::new(FinalRule::new("DIRECT")),
        ]);
        let calls = counting_hook(&tunnel, Some(owner()));

        let mut md = flow_meta();
        let resolved = tunnel
            .inner()
            .resolve_proxy_flow(&mut md)
            .await
            .expect("rules resolve");
        assert_eq!(resolved.adapter.name(), "REJECT");
        assert_eq!(scan_count(&calls), 0);
    }

    /// `strict`: a flow decided by an earlier IP rule — `dst_ip` already
    /// resolved — likewise never scans for the later process rule.
    #[tokio::test]
    async fn strict_earlier_ip_win_scans_never() {
        use meow_rules::ipcidr::IpCidrRule;
        let tunnel = rule_tunnel(vec![
            Box::new(IpCidrRule::new("203.0.113.0/24", "REJECT", false, false).unwrap()),
            Box::new(DemandProcess::new("stub-owner", "DIRECT")),
            Box::new(FinalRule::new("DIRECT")),
        ]);
        let calls = counting_hook(&tunnel, Some(owner()));

        let mut md = flow_meta();
        md.dst_ip = Some("203.0.113.9".parse().unwrap());
        let resolved = tunnel
            .inner()
            .resolve_proxy_flow(&mut md)
            .await
            .expect("rules resolve");
        assert_eq!(resolved.adapter.name(), "REJECT");
        assert_eq!(scan_count(&calls), 0);
    }

    /// `strict`: the first reached process slot runs the flow's one
    /// lookup, and the result decides the match — on BOTH the lazy and
    /// the eager scans.
    #[tokio::test]
    async fn strict_scans_at_reached_process_rule() {
        for lazy in [true, false] {
            let tunnel = rule_tunnel(vec![
                Box::new(DemandProcess::new("stub-owner", "REJECT")),
                Box::new(FinalRule::new("DIRECT")),
            ]);
            let calls = counting_hook(&tunnel, Some(owner()));

            let mut md = flow_meta();
            let resolved = if lazy {
                tunnel.inner().resolve_proxy_lazy(&mut md).await
            } else {
                tunnel.inner().resolve_proxy_flow(&mut md).await
            }
            .expect("rules resolve");
            assert_eq!(resolved.adapter.name(), "REJECT", "lazy={lazy}");
            assert_eq!(scan_count(&calls), 1, "lazy={lazy}");
            // strict keeps match-only visibility: the tracked metadata
            // does not adopt the looked-up fields.
            assert_eq!(md.process, "", "lazy={lazy}");
        }
    }

    /// `strict`: a miss is memoized — two reached process slots on one
    /// flow still cost a single scan.
    #[tokio::test]
    async fn strict_miss_does_not_rescan_for_later_process_rules() {
        let tunnel = rule_tunnel(vec![
            Box::new(DemandProcess::new("first", "REJECT")),
            Box::new(DemandProcess::new("second", "REJECT")),
            Box::new(FinalRule::new("DIRECT")),
        ]);
        let calls = counting_hook(&tunnel, None);

        let mut md = flow_meta();
        let resolved = tunnel
            .inner()
            .resolve_proxy_flow(&mut md)
            .await
            .expect("rules resolve");
        assert_eq!(resolved.adapter.name(), "DIRECT");
        assert_eq!(scan_count(&calls), 1, "a miss must not repeat the scan");
    }

    /// `strict`: the flow-local memo is shared between the non-recording
    /// UDP route probe and the real decision — one scan serves both.
    #[tokio::test]
    async fn strict_probe_and_route_share_one_scan() {
        let tunnel = rule_tunnel(vec![
            Box::new(DemandProcess::new("stub-owner", "REJECT")),
            Box::new(FinalRule::new("DIRECT")),
        ]);
        let calls = counting_hook(&tunnel, Some(owner()));

        let mut md = flow_meta();
        // The `resolve_udp_dst` "ends DIRECT?" probe — `record_hit=false`.
        let _ = tunnel.inner().resolve_proxy_inner(&mut md, false).await;
        assert_eq!(scan_count(&calls), 1, "the probe's reached slot scans once");
        let resolved = tunnel
            .inner()
            .resolve_proxy_flow(&mut md)
            .await
            .expect("rules resolve");
        assert_eq!(resolved.adapter.name(), "REJECT");
        assert_eq!(scan_count(&calls), 1, "the real decision reuses the memo");
    }

    /// `always`: the non-recording UDP route probe must not run the
    /// unconditional pre-dispatch scan — the real decision still runs it.
    #[tokio::test]
    async fn always_probe_scans_nothing() {
        let tunnel = rule_tunnel(vec![Box::new(FinalRule::new("DIRECT"))]);
        tunnel.set_process_lookup_mode(ProcessLookupMode::Always);
        let calls = counting_hook(&tunnel, Some(owner()));

        let mut md = flow_meta();
        let _ = tunnel.inner().resolve_proxy_inner(&mut md, false).await;
        assert_eq!(scan_count(&calls), 0, "a probe alone never scans");
        tunnel.inner().resolve_proxy_flow(&mut md).await;
        assert_eq!(scan_count(&calls), 1, "the real decision scans once");
    }

    /// `off`: no scan ever runs — a positive process predicate misses on
    /// empty fields while a supplied identity still matches, and a
    /// negated predicate still applies.
    #[tokio::test]
    async fn off_scans_never_and_keeps_supplied_identity() {
        // Empty fields: the positive rule misses, FINAL wins.
        let tunnel = rule_tunnel(vec![
            Box::new(DemandProcess::new("stub-owner", "REJECT")),
            Box::new(FinalRule::new("DIRECT")),
        ]);
        tunnel.set_process_lookup_mode(ProcessLookupMode::Off);
        let calls = counting_hook(&tunnel, Some(owner()));
        let mut md = flow_meta();
        let resolved = tunnel
            .inner()
            .resolve_proxy_flow(&mut md)
            .await
            .expect("rules resolve");
        assert_eq!(resolved.adapter.name(), "DIRECT");
        assert_eq!(scan_count(&calls), 0);

        // Supplied identity: the predicate evaluates it — off suppresses
        // the LOOKUP, not the match.
        let mut md = flow_meta();
        md.process = "stub-owner".into();
        let resolved = tunnel
            .inner()
            .resolve_proxy_flow(&mut md)
            .await
            .expect("rules resolve");
        assert_eq!(resolved.adapter.name(), "REJECT");
        assert_eq!(scan_count(&calls), 0);
    }

    /// `off`: a negated process predicate still fires — off suppresses
    /// lookups, not rule logic.
    #[tokio::test]
    async fn off_negated_process_rule_still_matches() {
        use meow_rules::{logic::NotRule, process::ProcessRule};
        let tunnel = rule_tunnel(vec![
            Box::new(NotRule::new(
                Box::new(ProcessRule::new("stub-owner", "DIRECT")),
                "REJECT",
            )),
            Box::new(FinalRule::new("DIRECT")),
        ]);
        tunnel.set_process_lookup_mode(ProcessLookupMode::Off);
        let calls = counting_hook(&tunnel, Some(owner()));

        let mut md = flow_meta();
        let resolved = tunnel
            .inner()
            .resolve_proxy_flow(&mut md)
            .await
            .expect("rules resolve");
        assert_eq!(resolved.adapter.name(), "REJECT", "NOT must match");
        assert_eq!(scan_count(&calls), 0);
    }

    /// The mode flips live: a strict flow pays nothing, an `always` PATCH
    /// applied through the tunnel takes effect on the next flow.
    #[tokio::test]
    async fn process_lookup_mode_switch_takes_effect_next_flow() {
        let tunnel = rule_tunnel(vec![Box::new(FinalRule::new("DIRECT"))]);
        let calls = counting_hook(&tunnel, Some(owner()));
        assert_eq!(tunnel.process_lookup_mode(), ProcessLookupMode::Strict);

        let mut strict_flow = flow_meta();
        tunnel.inner().resolve_proxy_flow(&mut strict_flow).await;
        assert_eq!(scan_count(&calls), 0, "strict scans nothing unprompted");
        assert_eq!(strict_flow.process, "");

        tunnel.set_process_lookup_mode(ProcessLookupMode::Always);
        let mut always_flow = flow_meta();
        tunnel.inner().resolve_proxy_flow(&mut always_flow).await;
        assert_eq!(scan_count(&calls), 1);
        assert_eq!(always_flow.process, "stub-owner");

        tunnel.set_process_lookup_mode(ProcessLookupMode::Off);
        let mut off_flow = flow_meta();
        tunnel.inner().resolve_proxy_flow(&mut off_flow).await;
        assert_eq!(scan_count(&calls), 1, "off scans nothing");
        assert_eq!(off_flow.process, "");
    }

    /// `type: rematch` + `REMATCH-NAME` end-to-end through the real
    /// YAML → parse → build → route pipeline (issue #974 acceptance
    /// matrix): the same `rebuild_from_raw` the boot and `PUT /configs`
    /// lanes run, so parser, registry and route-table semantics agree.
    mod rematch {
        use super::*;

        /// Build a tunnel straight from a YAML document — one literal
        /// config per case keeps parser surface covered too.
        fn rematch_tunnel(yaml: &str) -> Tunnel {
            let raw: meow_config::raw::RawConfig =
                serde_saphyr::from_str(yaml).expect("yaml parses");
            let res = meow_config::rebuild_from_raw(&raw).expect("rematch config builds");
            let tunnel = test_tunnel();
            tunnel.set_mode(TunnelMode::Rule);
            tunnel.update_routing(res.proxies, res.rules, res.sub_rules, res.dialer_registry);
            tunnel
        }

        async fn routed(tunnel: &Tunnel, host: &str) -> (String, Metadata) {
            let mut md = Metadata {
                host: host.into(),
                dst_port: 443,
                network: Network::Tcp,
                ..Default::default()
            };
            let target = tunnel
                .inner()
                .resolve_proxy_flow(&mut md)
                .await
                .expect("a route always resolves");
            (target.adapter.name().to_string(), md)
        }

        /// The spec example end-to-end: `example.test` selects `inspect`,
        /// enters `second-pass` with `rematchName = stage1`, and the
        /// `REMATCH-NAME,stage1/alternative` member sends it to REJECT.
        /// An unrelated flow walks the ordinary `MATCH,DIRECT`.
        #[tokio::test]
        async fn spec_example_rejects_via_second_pass() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1, target-sub-rule: second-pass}
rules:
  - DOMAIN-SUFFIX,example.test,inspect
  - MATCH,DIRECT
sub-rules:
  second-pass:
    - REMATCH-NAME,stage1/alternative,REJECT
    - MATCH,DIRECT
"#,
            );
            let (adapter, md) = routed(&tunnel, "example.test").await;
            assert_eq!(adapter, "REJECT");
            assert_eq!(md.rematch_name(), "stage1", "the stamped marker survives");
            let (adapter, _) = routed(&tunnel, "other.test").await;
            assert_eq!(adapter, "DIRECT");
        }

        /// `target-rematch-name` alone restarts the *active* list — the
        /// marker is visible to every predicate on the re-entry pass.
        #[tokio::test]
        async fn name_only_transition_rescans_active_list() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1}
rules:
  - REMATCH-NAME,stage1,REJECT
  - DOMAIN-SUFFIX,example.test,inspect
  - MATCH,DIRECT
"#,
            );
            let (adapter, md) = routed(&tunnel, "example.test").await;
            assert_eq!(adapter, "REJECT");
            assert_eq!(md.rematch_name(), "stage1");
        }

        /// A name-only rematch restarts the *listener-seeded* list, so
        /// its provenance survives: the `rule:` override still owns the
        /// flow's whole policy and a UDP-incapable match fails closed
        /// instead of sliding to block-exhaustion DIRECT. Clearing the
        /// flag on a transition that never named a new list would drop
        /// exactly that pin (issue #974).
        #[tokio::test]
        async fn name_only_transition_keeps_listener_fail_closed_udp() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1}
  - {name: noupd, type: socks5, server: 127.0.0.1, port: 1080, udp: false}
rules:
  - MATCH,DIRECT
sub-rules:
  blk:
    - REMATCH-NAME,stage1,noupd
    - NOT,((REMATCH-NAME,stage1)),inspect
    - MATCH,DIRECT
"#,
            );
            let mut md = Metadata {
                host: "example.test".into(),
                dst_port: 53,
                network: Network::Udp,
                ..Default::default()
            };
            md.set_special_route(None, Some("blk"));
            let target = tunnel
                .inner()
                .resolve_proxy_flow(&mut md)
                .await
                .expect("route resolves");
            // A block match on a UDP-incapable target materializes as
            // REJECT when the scan kept the listener's fail-closed
            // contract; the dropped-provenance bug slides to DIRECT.
            assert_eq!(
                target.adapter.name(),
                "REJECT",
                "the listener-owned scan must fail closed on the UDP-incapable match"
            );
        }

        /// `target-sub-rule` alone enters the block without touching the
        /// marker; an unset marker matches no `REMATCH-NAME` alternative.
        #[tokio::test]
        async fn sub_rule_only_leaves_marker_unset() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: hop, type: rematch, target-sub-rule: blk}
rules:
  - MATCH,hop
sub-rules:
  blk:
    - REMATCH-NAME,stage1,REJECT
    - MATCH,DIRECT
"#,
            );
            let (adapter, md) = routed(&tunnel, "any.test").await;
            assert_eq!(adapter, "DIRECT");
            assert_eq!(md.rematch_name(), "");
        }

        /// `target-rematch-name: ""` is the explicit clear form — a
        /// downstream `REMATCH-NAME` sees the marker as unset again.
        #[tokio::test]
        async fn explicit_empty_clears_the_marker() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: stamp, type: rematch, target-rematch-name: stage1, target-sub-rule: b1}
  - {name: clear, type: rematch, target-rematch-name: "", target-sub-rule: b2}
rules:
  - DOMAIN-SUFFIX,example.test,stamp
  - MATCH,DIRECT
sub-rules:
  b1:
    - REMATCH-NAME,stage1,clear
    - MATCH,REJECT
  b2:
    - REMATCH-NAME,stage1,REJECT
    - MATCH,DIRECT
"#,
            );
            let (adapter, md) = routed(&tunnel, "example.test").await;
            assert_eq!(
                adapter, "DIRECT",
                "cleared marker must not match b2's REMATCH-NAME"
            );
            assert_eq!(md.rematch_name(), "");
        }

        /// A re-visited adapter name is a routing cycle — terminal REJECT,
        /// never a slide to the next rule or a direct dial.
        #[tokio::test]
        async fn cycle_guard_rejects() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: loop, type: rematch, target-sub-rule: b1}
rules:
  - MATCH,loop
sub-rules:
  b1:
    - MATCH,loop
"#,
            );
            let (adapter, _) = routed(&tunnel, "any.test").await;
            assert_eq!(
                adapter, "REJECT",
                "the second pick of 'loop' must trip the guard"
            );
        }

        /// The visited set keys on the selected leaf's registry name, so
        /// a→G→b→a trips on the *third* hop even though the group's name
        /// never repeats.
        #[tokio::test]
        async fn a_b_a_through_a_group_rejects() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: a, type: rematch, target-sub-rule: b1}
  - {name: b, type: rematch, target-sub-rule: b2}
proxy-groups:
  - {name: G, type: select, proxies: [b]}
rules:
  - MATCH,a
sub-rules:
  b1:
    - MATCH,G
  b2:
    - MATCH,a
"#,
            );
            let (adapter, _) = routed(&tunnel, "any.test").await;
            assert_eq!(adapter, "REJECT", "a→G(b)→a is a routing cycle");
        }

        /// Two distinct nodes restamping the *same* marker chain freely —
        /// the guard watches adapter names, not marker values.
        #[tokio::test]
        async fn shared_marker_on_different_names_is_not_a_cycle() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: a, type: rematch, target-rematch-name: shared, target-sub-rule: blk}
  - {name: b, type: rematch, target-rematch-name: shared, target-sub-rule: done}
rules:
  - MATCH,a
sub-rules:
  blk:
    - REMATCH-NAME,shared,b
    - MATCH,DIRECT
  done:
    - MATCH,DIRECT
"#,
            );
            let (adapter, md) = routed(&tunnel, "any.test").await;
            assert_eq!(adapter, "DIRECT");
            assert_eq!(md.rematch_name(), "shared");
        }

        /// Thirty-three distinct hops exceeds upstream's recursion
        /// budget — the 33rd committed transition rejects. One shared
        /// block chains them: each hop restamps the marker the next
        /// `REMATCH-NAME` leg reads.
        #[tokio::test]
        async fn transition_cap_rejects_at_32() {
            use std::fmt::Write as _;
            let mut yaml = String::from("proxies:\n");
            for i in 1..=33 {
                let _ = writeln!(
                    yaml,
                    "  - {{name: r{i}, type: rematch, target-rematch-name: m{i}, target-sub-rule: chain}}"
                );
            }
            yaml.push_str("rules:\n  - MATCH,r1\nsub-rules:\n  chain:\n");
            for i in 1..33 {
                let _ = writeln!(yaml, "    - REMATCH-NAME,m{i},r{}", i + 1);
            }
            yaml.push_str("    - MATCH,DIRECT\n");
            let tunnel = rematch_tunnel(&yaml);
            let (adapter, _) = routed(&tunnel, "any.test").await;
            assert_eq!(adapter, "REJECT", "the 33rd transition must trip the cap");
        }

        /// A `target-sub-rule` naming no declared block warns at build and
        /// re-reads the main list — different from the listener `rule:`
        /// override's fail-closed contract.
        #[tokio::test]
        async fn unknown_block_falls_back_to_main() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: hop, type: rematch, target-rematch-name: stage1, target-sub-rule: missing}
rules:
  - MATCH,hop
  - REMATCH-NAME,stage1,REJECT
  - MATCH,DIRECT
"#,
            );
            let (adapter, md) = routed(&tunnel, "any.test").await;
            // Main list rescans in order: the now-stamped marker hits
            // REMATCH-NAME on the *second* committed pass.
            assert_eq!(adapter, "REJECT");
            assert_eq!(md.rematch_name(), "stage1");
        }

        /// Membership alone never transitions: a selector whose pick is
        /// an ordinary member dials it; a selector *picking* the rematch
        /// member re-enters — the probe peeks the pick chain.
        #[tokio::test]
        async fn group_pick_of_rematch_member_transitions() {
            let rules = r#"
rules:
  - REMATCH-NAME,stage1,REJECT
  - DOMAIN-SUFFIX,example.test,grp
  - MATCH,DIRECT
"#;
            let tunnel = rematch_tunnel(&format!(
                r#"
proxies:
  - {{name: inspect, type: rematch, target-rematch-name: stage1}}
proxy-groups:
  - {{name: grp, type: select, proxies: [inspect, DIRECT]}}
{rules}"#
            ));
            let (adapter, _) = routed(&tunnel, "example.test").await;
            assert_eq!(
                adapter, "REJECT",
                "the picked rematch member must transition"
            );

            let tunnel = rematch_tunnel(&format!(
                r#"
proxies:
  - {{name: inspect, type: rematch, target-rematch-name: stage1}}
proxy-groups:
  - {{name: grp, type: select, proxies: [DIRECT, inspect]}}
{rules}"#
            ));
            let (adapter, md) = routed(&tunnel, "example.test").await;
            // The group itself is the terminal adapter — its DIRECT pick
            // never tripped the rematch probe, and the marker stayed off.
            assert_eq!(
                adapter, "grp",
                "an unpicked rematch member must not transition"
            );
            assert_eq!(md.rematch_name(), "");
        }

        /// A relay chain is opaque to the match-time walk only for
        /// transports — a member *group* selecting a `type: rematch`
        /// leaf is the one pick it must surface so the scan transitions
        /// instead of treating the chain as a dialable target (issue
        /// #974). Here pass 2's marker steers the flow to DIRECT.
        #[tokio::test]
        async fn relay_member_group_pick_of_rematch_transitions() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1}
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, udp: true}
proxy-groups:
  - {name: sel, type: select, proxies: [inspect]}
  - {name: chain, type: relay, proxies: [node, sel]}
rules:
  - REMATCH-NAME,stage1,DIRECT
  - DOMAIN-SUFFIX,example.test,chain
  - MATCH,REJECT
"#,
            );
            let (adapter, md) = routed(&tunnel, "example.test").await;
            assert_eq!(
                adapter, "DIRECT",
                "the picked rematch hop must transition, not dial the chain"
            );
            assert_eq!(md.rematch_name(), "stage1");
        }

        /// The same chain with nothing steering the marker away: the
        /// second pass re-picks `inspect`, tripping the visited-name
        /// guard — fail-closed, the verdict the dial path's
        /// undialable-hop gate would have reached anyway (issue #974).
        #[tokio::test]
        async fn relay_rematch_repick_fails_closed_via_cycle_guard() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1}
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, udp: true}
proxy-groups:
  - {name: sel, type: select, proxies: [inspect]}
  - {name: chain, type: relay, proxies: [node, sel]}
rules:
  - MATCH,chain
"#,
            );
            let (adapter, _) = routed(&tunnel, "any.test").await;
            assert_eq!(adapter, "REJECT");
        }

        /// A UDP flow to a relay whose resolved chain ends in rematch
        /// transitions too — previously the `support_udp` peek read the
        /// undialable chain as `false` and the scan slid to a later
        /// `MATCH,DIRECT` (issue #974 fail-open).
        #[tokio::test]
        async fn udp_relay_rematch_transitions_instead_of_sliding() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1, target-sub-rule: b}
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, udp: true}
proxy-groups:
  - {name: sel, type: select, proxies: [inspect]}
  - {name: chain, type: relay, proxies: [node, sel]}
rules:
  - DOMAIN-SUFFIX,example.test,chain
  - MATCH,DIRECT
sub-rules:
  b:
    - REMATCH-NAME,stage1,REJECT
    - MATCH,DIRECT
"#,
            );
            let mut md = Metadata {
                host: "example.test".into(),
                dst_port: 53,
                network: Network::Udp,
                ..Default::default()
            };
            let target = tunnel
                .inner()
                .resolve_proxy_flow(&mut md)
                .await
                .expect("route resolves");
            assert_eq!(target.adapter.name(), "REJECT");
            assert_eq!(md.rematch_name(), "stage1");
        }

        /// A UDP flow takes the transition too — the leaf's
        /// `support_udp()` claim exists so the capability gate never
        /// preempts it — and the terminal target then applies the
        /// ordinary UDP policy.
        #[tokio::test]
        async fn udp_flow_transitions() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1, target-sub-rule: b}
rules:
  - DOMAIN-SUFFIX,example.test,inspect
  - MATCH,DIRECT
sub-rules:
  b:
    - REMATCH-NAME,stage1,REJECT
    - MATCH,DIRECT
"#,
            );
            let mut md = Metadata {
                host: "example.test".into(),
                dst_port: 53,
                network: Network::Udp,
                ..Default::default()
            };
            let target = tunnel
                .inner()
                .resolve_proxy_flow(&mut md)
                .await
                .expect("route resolves");
            assert_eq!(target.adapter.name(), "REJECT");
            assert_eq!(md.rematch_name(), "stage1");
        }

        /// Committed passes count once each on their own vector: the
        /// main-list rule that selected `inspect` records exactly one
        /// hit, and the intermediate control hop never registers a
        /// connection outcome of its own.
        #[tokio::test]
        async fn hit_counts_land_on_committed_slots() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1, target-sub-rule: b}
rules:
  - DOMAIN-SUFFIX,example.test,inspect
  - MATCH,DIRECT
sub-rules:
  b:
    - REMATCH-NAME,stage1,REJECT
    - MATCH,DIRECT
"#,
            );
            let (adapter, _) = routed(&tunnel, "example.test").await;
            assert_eq!(adapter, "REJECT");
            let route = tunnel.inner().route();
            assert_eq!(
                route.rule_stats.view(0).hits,
                1,
                "the committed main-list slot counts one hit"
            );
            assert_eq!(route.rule_stats.view(1).hits, 0, "MATCH was never reached");
        }

        /// The `resolve_udp_dst` probe resolves the route including
        /// rematch transitions — on a throwaway metadata clone, so the
        /// flow's real marker stays unset for the kept resolution.
        #[tokio::test]
        async fn udp_route_probe_keeps_marker_off_flow() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1, target-sub-rule: b}
rules:
  - DOMAIN-SUFFIX,example.test,inspect
  - MATCH,DIRECT
sub-rules:
  b:
    - REMATCH-NAME,stage1,REJECT
    - MATCH,DIRECT
"#,
            );
            let mut md = Metadata {
                host: "example.test".into(),
                dst_port: 53,
                network: Network::Udp,
                ..Default::default()
            };
            tunnel.inner().resolve_udp_dst(&mut md).await;
            assert_eq!(
                md.rematch_name(),
                "",
                "the probe's transition must not leak onto the flow"
            );
            let target = tunnel.inner().resolve_proxy_flow(&mut md).await.unwrap();
            assert_eq!(target.adapter.name(), "REJECT");
            assert_eq!(md.rematch_name(), "stage1");
        }

        /// A `SUB-RULE` reference is a predicate, not a `SpecialRules`
        /// change: its member selecting a rematch leaf without
        /// `target-sub-rule` restarts the active *outer* list.
        #[tokio::test]
        async fn sub_rule_member_rematch_restarts_outer() {
            let tunnel = rematch_tunnel(
                r#"
proxies:
  - {name: inspect, type: rematch, target-rematch-name: stage1}
rules:
  - SUB-RULE,(DOMAIN-SUFFIX,example.test),b1
  - REMATCH-NAME,stage1,REJECT
  - MATCH,DIRECT
sub-rules:
  b1:
    - MATCH,inspect
"#,
            );
            let (adapter, md) = routed(&tunnel, "example.test").await;
            assert_eq!(adapter, "REJECT");
            assert_eq!(md.rematch_name(), "stage1");
        }

        /// Demand staging persists across rematch passes: the flow's one
        /// process lookup runs once — pass two's block scan reuses the
        /// memo (hit *and* miss are cached alike), never rescanning the
        /// socket table (issue #974).
        #[tokio::test]
        async fn process_lookup_once_across_rematch_passes() {
            let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(
                "proxies:\n  - {name: inspect, type: rematch, target-sub-rule: blk}\n",
            )
            .unwrap();
            let res = meow_config::rebuild_from_raw(&raw).expect("config builds");
            let tunnel = test_tunnel();
            tunnel.set_mode(TunnelMode::Rule);
            tunnel.set_process_lookup_mode(ProcessLookupMode::Strict);
            // The block reaches its own process demand — a second scan
            // would trip the counter; the memo must answer instead.
            let sub_rules = HashMap::from([(
                "blk".to_string(),
                Arc::new(vec![
                    Box::new(DemandProcess::new("other-owner", "REJECT")) as Box<dyn Rule>,
                    Box::new(FinalRule::new("DIRECT")) as Box<dyn Rule>,
                ]) as meow_rules::sub_rule::SubRuleBlock,
            )]);
            let rules: Vec<Box<dyn Rule>> = vec![
                Box::new(DemandProcess::new("stub-owner", "inspect")),
                Box::new(FinalRule::new("DIRECT")),
            ];
            tunnel.update_routing(res.proxies, rules, sub_rules, res.dialer_registry);
            let calls = counting_hook(&tunnel, Some(owner()));
            let mut md = flow_meta();
            let target = tunnel
                .inner()
                .resolve_proxy_flow(&mut md)
                .await
                .expect("route resolves");
            // Pass 1: stub-owner → inspect → transition into blk.
            // Pass 2: the memo's stub-owner ≠ other-owner → MATCH,DIRECT.
            assert_eq!(target.adapter.name(), "DIRECT");
            assert_eq!(
                scan_count(&calls),
                1,
                "the transition must carry the lookup outcome, not rescan"
            );
        }

        /// A demand first reached on a *later* pass resolves then and
        /// only then: `ip_attempted` lives at flow scope, so pass 2's
        /// IP-CIDR rule runs the one lookup the first pass never needed.
        #[tokio::test]
        async fn ip_demand_first_reached_on_the_second_pass() {
            use meow_dns::HostEntry;
            use meow_rules::ipcidr::IpCidrRule;
            let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
            hosts.insert(
                "need-ip.test",
                vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    93, 184, 216, 34,
                ))]
                .into(),
            );
            let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true);
            let tunnel = Tunnel::new(Arc::new(resolver));
            let raw: meow_config::raw::RawConfig = serde_saphyr::from_str(
                "proxies:\n  - {name: inspect, type: rematch, target-sub-rule: blk}\n",
            )
            .unwrap();
            let res = meow_config::rebuild_from_raw(&raw).expect("config builds");
            tunnel.set_mode(TunnelMode::Rule);
            tunnel.update_routing(
                res.proxies,
                vec![
                    Box::new(DomainSuffixRule::new("need-ip.test", "inspect")),
                    Box::new(FinalRule::new("DIRECT")),
                ],
                HashMap::from([(
                    "blk".to_string(),
                    Arc::new(vec![
                        Box::new(
                            IpCidrRule::new("93.184.216.0/24", "REJECT", false, false).unwrap(),
                        ) as Box<dyn Rule>,
                        Box::new(FinalRule::new("DIRECT")) as Box<dyn Rule>,
                    ]) as meow_rules::sub_rule::SubRuleBlock,
                )]),
                res.dialer_registry,
            );
            let mut md = Metadata {
                host: "need-ip.test".into(),
                dst_port: 443,
                network: Network::Tcp,
                ..Default::default()
            };
            // The lazy TCP path: pass 1 never reached an IP slot, so the
            // resolve happens when pass 2's IP-CIDR rule gates the scan.
            let target = tunnel
                .inner()
                .resolve_proxy_lazy(&mut md)
                .await
                .expect("route resolves");
            assert_eq!(
                target.adapter.name(),
                "REJECT",
                "pass 2's IP-CIDR rule resolved the host and matched"
            );
            assert_eq!(
                md.dst_ip,
                Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    93, 184, 216, 34
                ))),
                "the lookup ran once, inside the pass that demanded it"
            );
        }
    }
}
