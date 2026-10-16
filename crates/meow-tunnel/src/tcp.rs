use crate::relay::{copy_bidirectional_buf_tracked, RELAY_BUF_SIZE};
use crate::statistics::Statistics;
use crate::tunnel::{ResolvedTarget, TunnelInner};
use meow_common::{with_dial_timeout, Metadata, ProxyAdapter, ProxyConn};
use smallvec::{smallvec, SmallVec};
use smol_str::SmolStr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

/// RAII wrapper around `Statistics::track_connection` /
/// `close_connection`. The previous implementation called
/// `close_connection` on the last line of `handle_tcp`, which is
/// unreachable when the future is dropped mid-`.await` — that happens
/// every time an embedder cancels the task (iOS tun2socks idle sweeper,
/// `JoinHandle::abort()`, tunnel shutdown, panic-unwind, etc.). Each
/// aborted flow leaked one entry in `Statistics.connections`, and the
/// `/connections` REST endpoint reads that map directly, so abort-heavy
/// embedders see the count climb without bound until process restart.
///
/// `Drop` runs on every exit path including unwind, so the entry is
/// removed regardless of how the surrounding future ends. Holding an
/// `&Statistics` is sufficient — the caller already owns an
/// `Arc<Statistics>` (via `TunnelInner.stats`) that outlives the guard.
pub struct ConnectionGuard<'a> {
    stats: &'a Statistics,
    key: ConnectionKey,
    counters: Arc<crate::statistics::ConnCounters>,
}

#[derive(Clone, Copy)]
enum ConnectionKey {
    Api(uuid::Uuid),
    Headless,
}

/// Bound on the group hops [`connection_chain`] walks.
/// `reject_group_membership_cycles` keeps config-declared groups acyclic,
/// so this only guards hand-built registries (same bound as the match
/// loop's `RouteTargetProbe::unwraps_to`).
const MAX_CHAIN_HOPS: usize = 16;

/// The `/connections` `chains` entry for a flow routed to `adapter`: the
/// leaf the dial will use first, the rule's target last — upstream's order,
/// e.g. `["HK-01", "Auto", "Proxy"]` — so a dashboard can show which member
/// each group picked rather than only the rule's group name.
///
/// Upstream builds the chain on the dialed conn (each group appends its
/// name once its member's dial returns) and registers the flow afterwards.
/// meow registers before dialing, so an in-flight dial is listed and
/// cancellable; the walk therefore peeks `unwrap_proxy(metadata, false)`,
/// which reports the member the next dial takes (Selector, URLTest and
/// Fallback deterministically; round-robin while no other dial commits in
/// between) without advancing counters or recording group use.
fn connection_chain(adapter: &dyn ProxyAdapter, metadata: &Metadata) -> SmallVec<[Arc<str>; 1]> {
    let mut chain: SmallVec<[Arc<str>; 1]> = smallvec![Arc::from(adapter.name())];
    let mut next = adapter.unwrap_proxy(metadata, false);
    while let Some(hop) = next {
        if chain.len() > MAX_CHAIN_HOPS {
            debug!(
                "{}: unwrap chain exceeded {MAX_CHAIN_HOPS} hops recording connection chain",
                adapter.name()
            );
            break;
        }
        chain.push(Arc::from(hop.name()));
        next = hop.unwrap_proxy(metadata, false);
    }
    chain.reverse();
    chain
}

impl<'a> ConnectionGuard<'a> {
    fn track_named(
        stats: &'a Statistics,
        metadata: &Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        adapter: &dyn ProxyAdapter,
    ) -> Self {
        if let Some(counters) = stats.begin_headless_connection() {
            return Self {
                stats,
                key: ConnectionKey::Headless,
                counters,
            };
        }
        let (id, counters) = stats.track_connection_with_counters(
            metadata.pure(),
            rule,
            rule_payload,
            connection_chain(adapter, metadata),
        );
        Self {
            stats,
            key: ConnectionKey::Api(id),
            counters,
        }
    }

    /// Register a connection for cancellation and, when enabled, API details.
    /// Headless tracking discards the metadata, rule and chain arguments.
    pub fn track(
        stats: &'a Statistics,
        metadata: Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        chains: SmallVec<[Arc<str>; 1]>,
    ) -> Self {
        // Obtain the handle before publishing the entry. A concurrent DELETE
        // must cancel this exact handle, even before its first poll.
        let (key, counters) = if let Some(counters) = stats.begin_headless_connection() {
            (ConnectionKey::Headless, counters)
        } else {
            let (id, counters) =
                stats.track_connection_with_counters(metadata, rule, rule_payload, chains);
            (ConnectionKey::Api(id), counters)
        };
        Self {
            stats,
            key,
            counters,
        }
    }

    /// Run the complete dial/write/relay lifetime until a close request,
    /// including an API deletion or a cold routing reload.
    /// Dropping the future releases its remote stream; callers then return to
    /// the listener so the owned inbound stream is dropped as well.
    pub async fn run_until_closed<F: std::future::Future>(&self, future: F) -> Option<F::Output> {
        tokio::select! {
            biased;
            () = self.counters.closed() => None,
            output = future => Some(output),
        }
    }

    /// API-visible ID for a fully tracked connection, or `None` for a
    /// headless connection, which has no API details or UUID.
    pub fn id(&self) -> Option<uuid::Uuid> {
        match self.key {
            ConnectionKey::Api(id) => Some(id),
            ConnectionKey::Headless => None,
        }
    }

    /// Live byte counters shared with the statistics table. Clone the `Arc`
    /// into relay progress callbacks so the hot loop never touches the map.
    pub fn counters(&self) -> &Arc<crate::statistics::ConnCounters> {
        &self.counters
    }
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        match self.key {
            ConnectionKey::Api(id) => self.stats.close_connection(id),
            ConnectionKey::Headless => self.stats.close_headless_connection(&self.counters),
        }
    }
}

/// A TCP setup's cold-reload generation, captured before reading routing state.
/// This is a value, not a held lock, so DNS enrichment may safely await.
#[must_use]
pub struct TcpAdmission<'a> {
    inner: &'a TunnelInner,
    generation: u64,
}

impl TunnelInner {
    /// Start TCP routing setup. Call before resolving the proxy, then register
    /// through the returned token so cold reload cannot miss the connection.
    pub fn tcp_admission(&self) -> TcpAdmission<'_> {
        TcpAdmission {
            inner: self,
            generation: *self.tcp_generation.read(),
        }
    }
}

impl<'a> TcpAdmission<'a> {
    /// Register a connection routed to `adapter` without constructing
    /// API-only metadata or the group chain when the application has no
    /// external controller.
    /// The read lock covers generation validation and registry insertion,
    /// so a cold reload cannot drain between them and miss this connection.
    pub fn track_named(
        self,
        metadata: &Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        adapter: &dyn ProxyAdapter,
    ) -> Option<ConnectionGuard<'a>> {
        let generation = self.inner.tcp_generation.read();
        if *generation != self.generation {
            debug!("TCP routing setup invalidated by cold reload");
            return None;
        }
        let guard =
            ConnectionGuard::track_named(&self.inner.stats, metadata, rule, rule_payload, adapter);
        drop(generation);
        Some(guard)
    }

    /// Register only if no cold reload has crossed this routing decision.
    /// The read lock covers both validation and insertion: a reload cannot
    /// close the table between these operations and leave an old flow alive.
    /// Headless tracking discards the metadata, rule and chain arguments.
    pub fn track(
        self,
        metadata: Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        chains: SmallVec<[Arc<str>; 1]>,
    ) -> Option<ConnectionGuard<'a>> {
        let generation = self.inner.tcp_generation.read();
        if *generation != self.generation {
            debug!("TCP routing setup invalidated by cold reload");
            return None;
        }
        let guard = ConnectionGuard::track(&self.inner.stats, metadata, rule, rule_payload, chains);
        drop(generation);
        Some(guard)
    }
}

pub async fn handle_tcp(tunnel: &TunnelInner, mut conn: Box<dyn ProxyConn>, metadata: Metadata) {
    route_inbound_tcp(tunnel, &mut conn, metadata, &[]).await;
}

/// Route a decrypted inbound TCP connection through the rule engine and relay
/// it to the matched proxy.
///
/// This is the shared tail of every blind-tunnel listener (SOCKS5 CONNECT,
/// HTTP CONNECT, the `handle_tcp` entry point, and — once added — the
/// shadowsocks inbound). It owns the four pieces that were previously
/// copy-pasted into each listener:
///
/// 1. fake-IP / snooping rewrite (`pre_handle_metadata`),
/// 2. lazy rule match + connection tracking,
/// 3. dial the matched proxy,
/// 4. bidirectional relay with byte counters.
///
/// `prefix` carries any bytes the listener already buffered ahead of the
/// relay (e.g. HTTP CONNECT pipelined application data); they are written to
/// the remote before the copy loop and counted as upload. Pass `&[]` when the
/// listener hands over a clean stream.
///
/// Relay scratch buffers are stack-allocated in this frame — zero
/// per-relay-setup heap allocation (ADR-0008 HP-1/HP-2/HP-3). The generic
/// parameter keeps the relay monomorphised per concrete stream type so the
/// hot copy loop stays dispatch-free.
///
/// Listeners whose relay is *not* a blind tunnel (e.g. the plain-HTTP proxy
/// path that rewrites the request line and wraps the client in a bounded
/// `SingleRequestClient`, or the TProxy path that uses eager rule
/// resolution) keep their own inline routing — this helper only targets the
/// `pre_handle_metadata` + `resolve_proxy_lazy` + blind-relay shape.
///
/// # Visibility
///
/// Exported as `pub` from `meow-tunnel` so that `meow-listener` can call it
/// directly from the SOCKS5/HTTP-CONNECT handlers. This is a workspace-internal
/// API contract: both crates are in the same workspace and share the
/// `TunnelInner` type, so the function is not intended for external consumers —
/// hence `#[doc(hidden)]`, which keeps it out of the public rustdoc surface
/// without restricting the workspace-internal call path (review low item).
///
/// The bound is the relay's actual needs (`AsyncRead + AsyncWrite + Unpin +
/// Send`) rather than `ProxyConn`: `ProxyConn` is defined in `meow-common`
/// and cannot be implemented for a foreign type like the `shadowsocks` crate's
/// `ProxyServerStream` from outside `meow-common` (orphan rule). `Sync` is not
/// required — the connection lives in a single spawned task. `handle_tcp`
/// still passes its `Box<dyn ProxyConn>`, which satisfies this bound via
/// tokio's `Box<?Sized + AsyncRead + Unpin>` impls.
#[doc(hidden)]
pub async fn route_inbound_tcp<C>(
    inner: &TunnelInner,
    conn: &mut C,
    mut metadata: Metadata,
    prefix: &[u8],
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // Fake-IP → host rewrite (no-op outside fake-IP mode aside from a
    // snooping-cache hostname fill-in). An unmapped fake-IP destination
    // is dropped — dialing it loops back into a fake-IP-routed inbound
    // (issue #618).
    if matches!(
        inner.pre_handle_metadata(&mut metadata),
        crate::tunnel::PreHandleVerdict::Drop
    ) {
        return;
    }

    let admission = inner.tcp_admission();

    // Match rules with lazy enrichment: DNS pre-resolution and process
    // lookup run only if the scan reaches a rule that demands them.
    let Some(target) = inner.resolve_proxy_lazy(&mut metadata).await else {
        warn!(
            "{} no matching rule for {}",
            metadata.conn_type,
            metadata.remote_address()
        );
        return;
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        target.rule_name,
        target.rule_payload,
        target.adapter.name()
    );

    // `route` pins this generation's dialer registry across the dial —
    // a mid-dial reload must not strand a chained `dialer-proxy` front hop
    // on a dead cell (issue #533 review). Held only until the dial
    // completes: a long-lived relay must not pin the whole generation.
    let ResolvedTarget {
        adapter: proxy,
        rule_name,
        rule_payload,
        route,
    } = target;
    let mut route = Some(route);

    // Track the connection — guard drops it on every exit path, including
    // the abort case where the manual close call below would never run.
    // API-only metadata and the proxy chain are built only when needed.
    let Some(guard) = admission.track_named(&metadata, rule_name, rule_payload, proxy.as_ref())
    else {
        return;
    };

    // Declare relay buffers on the future's stack frame — zero per-relay heap
    // allocation (ADR-0011 T6). Paid once at task-spawn, not at relay-call time.
    let mut buf_up = [0u8; RELAY_BUF_SIZE];
    let mut buf_dn = [0u8; RELAY_BUF_SIZE];

    // Dial the remote via proxy, bounded like mihomo's `C.DefaultTCPTimeout`:
    // a server that accepts and then stalls mid-handshake would otherwise pin
    // this task, its inbound socket and its stats entry forever.
    guard
        .run_until_closed(async {
            let dial = with_dial_timeout(proxy.name(), proxy.dial_tcp(&metadata)).await;
            // All chained front hops resolved during the dial — release the
            // generation pin before entering the relay loop.
            drop(route.take());
            match dial {
                Ok(mut remote) => {
                    let up = Arc::clone(guard.counters());
                    let dn = Arc::clone(guard.counters());
                    // Re-emit any bytes the listener already read past the handshake
                    // (e.g. pipelined TLS ClientHello after a CONNECT 200). Counted
                    // as upload so the connection stats stay accurate. A failure
                    // here kills the connection (the remote half is unusable), so it
                    // must be visible at `warn` — the pre-refactor code propagated
                    // it to the caller instead of swallowing it at `debug`
                    // (review M9).
                    if !prefix.is_empty() {
                        if let Err(e) = remote.write_all(prefix).await {
                            warn!(
                                "{} {} prefix write error: {}",
                                metadata.conn_type,
                                metadata.remote_address(),
                                e
                            );
                            return;
                        }
                        inner
                            .stats
                            .record_upload(&up, prefix.len() as meow_common::atomic::Int);
                    }
                    match copy_bidirectional_buf_tracked(
                        conn,
                        &mut remote,
                        &mut buf_up,
                        &mut buf_dn,
                        |n| {
                            inner
                                .stats
                                .record_upload(&up, n as meow_common::atomic::Int);
                        },
                        |n| {
                            inner
                                .stats
                                .record_download(&dn, n as meow_common::atomic::Int);
                        },
                    )
                    .await
                    {
                        Ok((up, down)) => {
                            debug!(
                                "{} {} relay closed: up={} down={}",
                                metadata.conn_type,
                                metadata.remote_address(),
                                up,
                                down
                            );
                        }
                        Err(e) => {
                            debug!(
                                "{} {} relay error: {}",
                                metadata.conn_type,
                                metadata.remote_address(),
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "{} {} dial error: {}",
                        metadata.conn_type,
                        metadata.remote_address(),
                        e
                    );
                }
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ConnType, Network};
    use meow_proxy::DirectAdapter;

    fn metadata() -> Metadata {
        Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        }
    }

    fn test_tunnel() -> crate::Tunnel {
        crate::Tunnel::new(Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            false,
        )))
    }

    #[tokio::test]
    async fn cold_reload_rejects_late_registration_and_cancels_earlier_registration() {
        let tunnel = test_tunnel();
        let inner = tunnel.inner();
        let late = inner.tcp_admission();
        let registered = inner
            .tcp_admission()
            .track(metadata(), "MATCH".into(), "".into(), smallvec![])
            .unwrap();

        assert_eq!(
            tunnel.reload_routing(Default::default(), vec![], None, Default::default()),
            1
        );
        // Same configuration and mode across multiple reloads: a boolean
        // running flag (or config equality) must not admit the old decision.
        assert_eq!(
            tunnel.reload_routing(Default::default(), vec![], None, Default::default()),
            0
        );
        assert!(late
            .track(metadata(), "MATCH".into(), "".into(), smallvec![])
            .is_none());
        assert!(registered
            .run_until_closed(async { "dial" })
            .await
            .is_none());

        let fresh = inner
            .tcp_admission()
            .track(metadata(), "MATCH".into(), "".into(), smallvec![])
            .unwrap();
        assert_eq!(fresh.run_until_closed(async { "dial" }).await, Some("dial"));
        assert_eq!(inner.stats.active_connection_count(), 1);
    }

    #[tokio::test]
    async fn headless_connections_skip_api_details_but_cold_reload_cancels_them() {
        let tunnel = test_tunnel();
        tunnel.statistics().set_headless();
        let inner = tunnel.inner();
        let guard = inner
            .tcp_admission()
            .track_named(
                &metadata(),
                "MATCH".into(),
                "".into(),
                &DirectAdapter::new(),
            )
            .unwrap();

        assert_eq!(tunnel.statistics().active_connection_count(), 0);
        assert_eq!(guard.id(), None);
        tunnel.statistics().record_upload(guard.counters(), 123);
        assert_eq!(tunnel.statistics().snapshot(), (123, 0));

        assert_eq!(
            tunnel.reload_routing(Default::default(), vec![], None, Default::default()),
            1
        );
        assert!(guard
            .run_until_closed(async { panic!("closed headless flow started dialing") })
            .await
            .is_none());
        assert_eq!(
            tunnel.reload_routing(Default::default(), vec![], None, Default::default()),
            0
        );
    }

    #[tokio::test]
    async fn headless_guard_drop_after_reload_keeps_new_connections_alive() {
        let tunnel = test_tunnel();
        let stats = tunnel.statistics();
        stats.set_headless();
        let old = tunnel
            .inner()
            .tcp_admission()
            .track_named(
                &metadata(),
                "MATCH".into(),
                "".into(),
                &DirectAdapter::new(),
            )
            .unwrap();
        assert_eq!(
            tunnel.reload_routing(Default::default(), vec![], None, Default::default()),
            1
        );
        assert!(old.run_until_closed(async { "dial" }).await.is_none());

        // The old guard still owns the drained handle. A new registration
        // must remain independent until that guard finishes dropping.
        let fresh = tunnel
            .inner()
            .tcp_admission()
            .track_named(
                &metadata(),
                "MATCH".into(),
                "".into(),
                &DirectAdapter::new(),
            )
            .unwrap();
        let completed =
            ConnectionGuard::track(stats, metadata(), "MATCH".into(), "".into(), smallvec![]);
        assert_eq!(completed.id(), None);
        drop(completed);
        drop(old);

        assert_eq!(fresh.run_until_closed(async { "dial" }).await, Some("dial"));
        assert_eq!(stats.close_all_connections_counted(), 1);
        assert!(fresh.run_until_closed(async { "dial" }).await.is_none());
        drop(fresh);
        assert_eq!(stats.close_all_connections_counted(), 0);
    }

    #[tokio::test]
    async fn concurrent_registration_cannot_escape_cold_reload() {
        for headless in [false, true] {
            let tunnel = test_tunnel();
            if headless {
                tunnel.statistics().set_headless();
            }
            for _ in 0..64 {
                let start = std::sync::Barrier::new(2);
                let admission = tunnel.inner().tcp_admission();
                // Race registration against closure on actual threads. Both
                // registries must reject the insert or close the exact handle.
                let guard = std::thread::scope(|scope| {
                    let registration = scope.spawn(|| {
                        start.wait();
                        admission.track_named(
                            &metadata(),
                            "MATCH".into(),
                            "".into(),
                            &DirectAdapter::new(),
                        )
                    });
                    start.wait();
                    tunnel.reload_routing(Default::default(), vec![], None, Default::default());
                    registration.join().unwrap()
                });
                if let Some(guard) = guard.as_ref() {
                    assert!(guard.run_until_closed(async { "dial" }).await.is_none());
                }
                // Check both maps before Drop could mask a missed drain.
                assert_eq!(tunnel.statistics().close_all_connections_counted(), 0);
                assert_eq!(tunnel.statistics().active_connection_count(), 0);
            }
        }
    }

    #[tokio::test]
    async fn close_before_first_poll_does_not_start_dial() {
        let stats = Statistics::new();
        let guard =
            ConnectionGuard::track(&stats, metadata(), "MATCH".into(), "".into(), smallvec![]);
        stats.close_connection(guard.id().expect("full tracking has an API ID"));
        assert!(guard
            .run_until_closed(async { panic!("closed connection started dialing") })
            .await
            .is_none());
    }

    #[tokio::test]
    async fn close_cancels_pending_future_and_drops_its_resources() {
        let stats = Statistics::new();
        let guard =
            ConnectionGuard::track(&stats, metadata(), "MATCH".into(), "".into(), smallvec![]);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let pending = guard.run_until_closed(async move {
            let _resource = tx;
            std::future::pending::<()>().await;
        });
        let close = async {
            tokio::task::yield_now().await;
            stats.close_connection(guard.id().expect("full tracking has an API ID"));
        };
        let (result, ()) = tokio::join!(pending, close);
        assert!(result.is_none());
        assert!(rx.await.is_err(), "cancelled future must release resources");
    }

    #[tokio::test]
    async fn close_all_counts_requests_and_cancels_each_connection() {
        let stats = Statistics::new();
        let first =
            ConnectionGuard::track(&stats, metadata(), "MATCH".into(), "".into(), smallvec![]);
        let second =
            ConnectionGuard::track(&stats, metadata(), "MATCH".into(), "".into(), smallvec![]);
        let completed =
            ConnectionGuard::track(&stats, metadata(), "MATCH".into(), "".into(), smallvec![]);
        drop(completed);

        assert_eq!(stats.close_all_connections_counted(), 2);
        assert_eq!(stats.active_connection_count(), 0);
        assert_eq!(stats.close_all_connections_counted(), 0);
        assert!(first
            .run_until_closed(async { panic!("first closed connection started dialing") })
            .await
            .is_none());
        assert!(second
            .run_until_closed(async { panic!("second closed connection started dialing") })
            .await
            .is_none());
    }

    #[test]
    fn guard_removes_entry_on_drop() {
        let stats = Statistics::new();
        {
            let _g = ConnectionGuard::track(
                &stats,
                metadata(),
                SmolStr::new_static("DOMAIN"),
                SmolStr::new_static("example.com"),
                smallvec![],
            );
            assert_eq!(stats.active_connection_count(), 1, "entry tracked");
        }
        assert_eq!(
            stats.active_connection_count(),
            0,
            "entry removed when guard goes out of scope"
        );
    }

    #[test]
    fn guard_removes_entry_on_unwind() {
        let stats = Statistics::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = ConnectionGuard::track(
                &stats,
                metadata(),
                SmolStr::new_static("DOMAIN"),
                SmolStr::new_static("example.com"),
                smallvec![],
            );
            assert_eq!(stats.active_connection_count(), 1);
            panic!("simulating mid-relay abort");
        }));
        assert!(result.is_err(), "panic must propagate");
        assert_eq!(
            stats.active_connection_count(),
            0,
            "entry removed even when the holding scope unwinds"
        );
    }

    #[test]
    fn multiple_guards_independent() {
        let stats = Statistics::new();
        let g1 = ConnectionGuard::track(
            &stats,
            metadata(),
            SmolStr::new_static("DOMAIN"),
            SmolStr::new_static("a"),
            smallvec![],
        );
        let g2 = ConnectionGuard::track(
            &stats,
            metadata(),
            SmolStr::new_static("DOMAIN"),
            SmolStr::new_static("b"),
            smallvec![],
        );
        assert_eq!(stats.active_connection_count(), 2);
        drop(g1);
        assert_eq!(stats.active_connection_count(), 1);
        drop(g2);
        assert_eq!(stats.active_connection_count(), 0);
    }

    /// Route through the tunnel and register the flow the way
    /// `route_inbound_tcp` does, returning the API-visible chain.
    async fn tracked_chain(tunnel: &crate::Tunnel) -> Vec<String> {
        let meta = metadata();
        let target = tunnel.inner().resolve_proxy(&meta).await.unwrap();
        let guard = tunnel
            .inner()
            .tcp_admission()
            .track_named(
                &meta,
                target.rule_name,
                target.rule_payload,
                target.adapter.as_ref(),
            )
            .unwrap();
        let id = guard.id().unwrap();
        tunnel
            .statistics()
            .active_connections()
            .into_iter()
            .find(|c| c.id == id)
            .unwrap()
            .chains
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// `/connections` `chains` names the member every group on the path
    /// picked, leaf first like upstream — not just the rule's group, which
    /// left a dashboard unable to tell which node a flow actually uses.
    #[tokio::test]
    async fn tracked_chain_names_each_group_selection_leaf_first() {
        let raw: meow_config::raw::RawConfig = serde_yaml::from_str(
            "proxies:
  - {name: HK-01, type: socks5, server: 127.0.0.1, port: 1}
  - {name: JP-01, type: socks5, server: 127.0.0.1, port: 2}
proxy-groups:
  - {name: Auto, type: fallback, proxies: [HK-01, JP-01], url: 'http://probe.test/204', interval: 300}
  - {name: RR, type: load-balance, strategy: round-robin, proxies: [HK-01, JP-01], url: 'http://probe.test/204', interval: 300}
  - {name: Proxy, type: select, proxies: [Auto, RR, DIRECT]}
",
        )
        .unwrap();
        let proxies = meow_config::rebuild_from_raw(&raw).unwrap().proxies;
        let tunnel = test_tunnel();
        tunnel.update_routing(
            proxies.clone(),
            vec![Box::new(meow_rules::final_rule::FinalRule::new("Proxy"))],
            Default::default(),
        );

        // Nested groups: Selector -> Fallback -> first alive leaf.
        assert_eq!(tracked_chain(&tunnel).await, ["HK-01", "Auto", "Proxy"]);
        proxies["HK-01"].health().set_alive(false);
        assert_eq!(tracked_chain(&tunnel).await, ["JP-01", "Auto", "Proxy"]);

        // Round-robin: recording peeks, so registering the flow does not
        // rotate the group, and the recorded member is the one the dial's
        // committing pick then takes.
        let selector = proxies["Proxy"].selection().unwrap();
        selector.set("RR").await.unwrap();
        let first = tracked_chain(&tunnel).await;
        assert_eq!(first[1..], ["RR", "Proxy"]);
        assert_eq!(tracked_chain(&tunnel).await, first, "peek must not rotate");
        let dialed = proxies["RR"].unwrap_proxy(&metadata(), true).unwrap();
        assert_eq!(dialed.name(), first[0]);

        // A leaf selection records just the leaf behind the group.
        selector.set("DIRECT").await.unwrap();
        assert_eq!(tracked_chain(&tunnel).await, ["DIRECT", "Proxy"]);
    }
}
