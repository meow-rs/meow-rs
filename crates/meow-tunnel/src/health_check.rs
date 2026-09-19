use crate::tunnel::TunnelInner;
use meow_common::HealthCheckSpec;
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tracing::{debug, info, warn};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Owns the set of running health-check tasks, keyed by group name.
/// `reconcile` is called on every config commit (startup, `PUT /configs`,
/// section mutations, subscription refresh): new groups get a task, removed
/// or no-longer-probing groups are aborted, changed specs (url / interval /
/// lazy) are respawned, and a task that died on its own is restarted —
/// previously checks were spawned once at startup and a reload could leave
/// stale tasks running or new groups unprobed (issue #514).
///
/// Tasks hold a `Weak<TunnelInner>` and exit when it can't be upgraded —
/// the same pattern the NAT sweeper uses — so an embedder dropping the
/// last `Tunnel` doesn't leave probes running (and pinning inner state)
/// forever.
#[derive(Default)]
pub struct HealthCheckSupervisor {
    tasks: HashMap<String, (HealthCheckSpec, tokio::task::JoinHandle<()>)>,
}

impl HealthCheckSupervisor {
    pub fn reconcile(&mut self, inner: &Arc<TunnelInner>, specs: &[HealthCheckSpec]) {
        let wanted: HashMap<&str, &HealthCheckSpec> =
            specs.iter().map(|s| (s.group_name.as_str(), s)).collect();

        // Abort tasks for removed groups, changed specs, and reap dead
        // tasks so a crashed probe loop self-heals on the next reconcile.
        self.tasks.retain(|name, (spec, task)| {
            let keep =
                matches!(wanted.get(name.as_str()), Some(s) if *s == spec) && !task.is_finished();
            if !keep {
                task.abort();
            }
            keep
        });

        // Spawn from `wanted` (last-wins), not `specs` — a caller that
        // passes conflicting duplicate names would otherwise store the
        // first spec while `wanted` compares against the last, churning
        // the task on every reconcile.
        for spec in wanted.values() {
            if self.tasks.contains_key(spec.group_name.as_str()) {
                continue;
            }
            let spec = (*spec).clone();
            let task = tokio::spawn(run_health_check_loop(Arc::downgrade(inner), spec.clone()));
            self.tasks.insert(spec.group_name.clone(), (spec, task));
        }
    }

    /// Number of tracked tasks — includes dead-but-unreaped entries that
    /// the next `reconcile` will replace (test/diagnostic surface).
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

fn should_probe(lazy: bool, generation: u64, last_probed_generation: u64) -> bool {
    !lazy || (generation != 0 && generation != last_probed_generation)
}

async fn run_health_check_loop(inner: Weak<TunnelInner>, spec: HealthCheckSpec) {
    // `interval(Duration::ZERO)` panics — extract clamps 0→300, but a
    // spec constructed directly (embedders) must not kill the task.
    let interval_secs = spec.interval_secs.max(1);
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    // `Delay` (not tokio's default `Burst`) so a probe that outlives a short
    // `interval` schedules the next tick a full interval from *now* instead
    // of firing a back-to-back burst of catch-up probes. For the common
    // `interval >= probe timeout` case (default 300 s vs 5 s) no tick is ever
    // missed and the schedule is identical to before; this also prevents a
    // missed-tick probe storm right after system suspend.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_probed_generation = 0;

    if spec.lazy {
        ticker.tick().await;
    }

    loop {
        ticker.tick().await;

        // Weak capture: a tunnel that no external handle pins means the
        // embedder dropped it — stop probing instead of keeping
        // `TunnelInner` alive forever through this task (issue #514).
        let Some(inner) = inner.upgrade() else {
            debug!(
                "health-check: tunnel dropped, stopping '{}'",
                spec.group_name
            );
            return;
        };
        let route = inner.route();
        let proxies = &route.proxies;
        let Some(group) = proxies.get(spec.group_name.as_str()).cloned() else {
            debug!(
                "health-check: group '{}' not found, skipping tick",
                spec.group_name
            );
            continue;
        };
        let generation = group.usage_generation();
        if !should_probe(spec.lazy, generation, last_probed_generation) {
            debug!(
                "health-check: lazy group '{}' has no traffic since its last probe, skipping tick",
                spec.group_name
            );
            continue;
        }
        // Resolve through the group, not the route table: `use:` /
        // `include-all` provider members are not registry keys, so a
        // name lookup found zero of them and a `use:`-only group woke
        // every interval to probe nothing (issue #543 item 1).
        let Some(member_proxies) = group.member_proxies() else {
            continue;
        };

        let members: Vec<_> = member_proxies
            .into_iter()
            .map(|p| (p.name().to_string(), p))
            .collect();
        // `expected-status` narrows the acceptance set — a periodic probe
        // must use the same set the group's set-triggered probes use,
        // otherwise the two can disagree on member health (issue #514).
        let expected_status = group.expected_status().filter(|s| !s.is_empty());
        // Keep `route` alive across the probe: it owns this generation's
        // dialer registry, and a mid-probe `update_routing` would otherwise
        // fail chained members closed and mark live nodes dead (issue #533).

        let mut alive_count = 0u32;
        let mut total_count = 0u32;
        for (name, delay) in meow_proxy::health::probe_many_bounded(
            members,
            &spec.url,
            expected_status,
            PROBE_TIMEOUT,
            meow_proxy::health::PROVIDER_HEALTHCHECK_CONCURRENCY,
        )
        .await
        {
            total_count += 1;
            if delay > 0 {
                alive_count += 1;
            } else {
                warn!(
                    "health-check: {} / {} is dead (probe failed)",
                    spec.group_name, name
                );
            }
        }

        // Record the generation only now that a probe round actually ran
        // (and only the pre-probe snapshot: any use that arrived *during*
        // the probes must still trigger the next tick).  Consuming it
        // earlier would let a tick with zero resolved members starve a
        // lazy group of its next probe.
        if total_count > 0 {
            last_probed_generation = generation;
        }

        info!(
            "health-check: {} — {}/{} alive",
            spec.group_name, alive_count, total_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Tunnel;
    use meow_common::{Metadata, Proxy, ProxyAdapter};
    use meow_config::extract_health_check_specs as extract_specs;

    fn stub_tunnel() -> Tunnel {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            false,
        ));
        Tunnel::new(resolver)
    }

    fn raw_group(
        name: &str,
        group_type: &str,
        interval: Option<u64>,
    ) -> meow_config::raw::RawProxyGroup {
        meow_config::raw::RawProxyGroup {
            name: name.into(),
            group_type: group_type.into(),
            interval,
            ..Default::default()
        }
    }

    /// Issue #514: the supervisor must spawn for added groups, abort for
    /// removed ones, respawn on spec change, and restart dead tasks —
    /// previously checks were startup-only.
    #[tokio::test]
    async fn reconcile_adds_removes_and_respawns_specs() {
        let tunnel = stub_tunnel();
        let mut sup = HealthCheckSupervisor::default();

        // Add a group → task spawned.
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[raw_group("a", "url-test", Some(3600))]),
        );
        assert_eq!(sup.task_count(), 1);
        let first = sup.tasks["a"].1.id();

        // Identical spec → no churn.
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[raw_group("a", "url-test", Some(3600))]),
        );
        assert_eq!(sup.task_count(), 1);
        assert_eq!(sup.tasks["a"].1.id(), first, "same spec keeps task");

        // Changed interval → respawn (new task identity).
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[raw_group("a", "url-test", Some(60))]),
        );
        assert_eq!(sup.task_count(), 1);
        assert_ne!(sup.tasks["a"].1.id(), first, "changed spec respawns");

        // Type change to non-probing → task removed.
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[raw_group("a", "select", None)]),
        );
        assert_eq!(sup.task_count(), 0, "non-checkable group aborts task");

        // Removed entirely → abort.
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[
                raw_group("a", "url-test", None),
                raw_group("b", "fallback", None),
            ]),
        );
        assert_eq!(sup.task_count(), 2);
        sup.reconcile(tunnel.inner(), &extract_specs(&[]));
        assert_eq!(sup.task_count(), 0, "empty group set aborts all tasks");
    }

    /// Upstream `HealthCheck.auto()` is `interval != 0`: an explicit
    /// `interval: 0` must disable periodic checks — no spec is emitted and
    /// a previously-running task is removed by reconcile.
    #[tokio::test]
    async fn interval_zero_disables_periodic_checks() {
        let tunnel = stub_tunnel();
        let mut sup = HealthCheckSupervisor::default();
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[raw_group("a", "url-test", Some(3600))]),
        );
        assert_eq!(sup.task_count(), 1);

        assert!(
            extract_specs(&[raw_group("a", "url-test", Some(0))]).is_empty(),
            "interval: 0 must not emit a probe spec"
        );
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[raw_group("a", "url-test", Some(0))]),
        );
        assert_eq!(sup.task_count(), 0, "interval 0 removes the task");
    }

    /// Issue #485: `load-balance` accepts `url`/`interval`/`lazy` and must
    /// be swept like `url-test`/`fallback` instead of silently never probing.
    #[test]
    fn extract_specs_includes_load_balance_with_defaults() {
        let specs = extract_specs(&[raw_group("lb", "load-balance", None)]);
        assert_eq!(specs.len(), 1, "load-balance must produce a probe spec");
        assert_eq!(specs[0].group_name, "lb");
        assert_eq!(specs[0].url, "https://www.gstatic.com/generate_204");
        assert_eq!(specs[0].interval_secs, 300);
        assert!(!specs[0].lazy);
    }

    /// A task that died on its own is restarted at the next reconcile.
    #[tokio::test]
    async fn reconcile_restarts_dead_tasks() {
        let tunnel = stub_tunnel();
        let mut sup = HealthCheckSupervisor::default();
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[raw_group("a", "url-test", Some(3600))]),
        );
        assert_eq!(sup.task_count(), 1);
        let first = sup.tasks["a"].1.id();
        // Simulate a crashed loop — abort only schedules cancellation, so
        // poll `is_finished` to a deadline instead of assuming one yield
        // is enough.
        sup.tasks["a"].1.abort();
        until(Duration::from_secs(5), || sup.tasks["a"].1.is_finished()).await;
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[raw_group("a", "url-test", Some(3600))]),
        );
        assert_eq!(sup.task_count(), 1, "dead task is reaped and respawned");
        assert_ne!(
            sup.tasks["a"].1.id(),
            first,
            "replacement must be a new task"
        );
        assert!(
            !sup.tasks["a"].1.is_finished(),
            "replacement task must be running"
        );
    }

    /// Duplicate group names: last spec wins, matching config build — a
    /// duplicate must not churn the task on every reconcile.
    #[tokio::test]
    async fn reconcile_dedups_duplicate_names_last_wins() {
        let tunnel = stub_tunnel();
        let mut sup = HealthCheckSupervisor::default();
        let groups = [
            raw_group("a", "url-test", Some(3600)),
            raw_group("a", "url-test", Some(60)),
        ];
        sup.reconcile(tunnel.inner(), &extract_specs(&groups));
        assert_eq!(sup.task_count(), 1);
        assert_eq!(sup.tasks["a"].0.interval_secs, 60, "last spec wins");
        let first = sup.tasks["a"].1.id();
        // Reconciling the same duplicate set must not respawn.
        sup.reconcile(tunnel.inner(), &extract_specs(&groups));
        assert_eq!(sup.tasks["a"].1.id(), first, "no churn on duplicates");
    }

    /// A checkable declaration shadowed by a same-named non-checkable one
    /// emits no spec — the builder's last-wins applies across types too,
    /// so the select group that actually got built must not be probed.
    #[test]
    fn extract_skips_checkable_shadowed_by_select() {
        let groups = [
            raw_group("a", "url-test", Some(60)),
            raw_group("a", "select", None),
        ];
        assert!(
            extract_specs(&groups).is_empty(),
            "last declaration is select — no health check"
        );
    }

    /// Probe tasks exit on their own once the tunnel is dropped — a
    /// `Weak` capture means an embedder that drops the last `Tunnel`
    /// doesn't leave check loops running forever (issue #514 review).
    #[tokio::test(start_paused = true)]
    async fn health_task_exits_when_tunnel_dropped() {
        let tunnel = stub_tunnel();
        let mut sup = HealthCheckSupervisor::default();
        sup.reconcile(
            tunnel.inner(),
            &extract_specs(&[raw_group("a", "url-test", Some(1))]),
        );
        let handle = sup.tasks.remove("a").unwrap().1;
        drop(tunnel);
        // The loop exits at the next tick when `upgrade` fails.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(handle.is_finished(), "task exits after tunnel drop");
    }

    #[test]
    fn lazy_probe_requires_new_group_use() {
        assert!(!should_probe(true, 0, 0));
        assert!(should_probe(true, 1, 0));
        assert!(!should_probe(true, 1, 1));
        assert!(should_probe(true, 2, 1));
        assert!(should_probe(false, 0, 0));
    }

    // --- End-to-end scheduler tests -------------------------------------------------
    //
    // These drive the real `run_health_check_loop` against a `Tunnel` whose
    // group members are probe-answering mocks, so the tick → generation →
    // probe/skip state machine is exercised instead of just `should_probe`.

    /// A `ProxyConn` that answers any write with a canned `204 No Content`
    /// response, so `probe_and_record` completes without network I/O — the
    /// loop stays deterministic under `start_paused`.
    struct Canned204Conn {
        reply: &'static [u8],
        pos: usize,
    }

    impl Canned204Conn {
        fn new() -> Self {
            Self {
                reply: b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                pos: 0,
            }
        }
    }

    impl tokio::io::AsyncRead for Canned204Conn {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.pos >= self.reply.len() {
                return std::task::Poll::Ready(Ok(()));
            }
            let n = buf.remaining().min(self.reply.len() - self.pos);
            let start = self.pos;
            self.pos += n;
            let reply = self.reply;
            buf.put_slice(&reply[start..start + n]);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for Canned204Conn {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl meow_common::ProxyConn for Canned204Conn {}

    /// Leaf `Proxy` whose `dial_tcp` always succeeds and counts every dial,
    /// so tests can tell probe dials apart from group-use dials.
    struct ProbeMock {
        name: String,
        health: meow_common::ProxyHealth,
        dials: std::sync::atomic::AtomicUsize,
    }

    impl ProbeMock {
        fn named(name: &str) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                name: name.to_string(),
                health: meow_common::ProxyHealth::new(),
                dials: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn dials(&self) -> usize {
            self.dials.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for ProbeMock {
        fn name(&self) -> &str {
            &self.name
        }

        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Shadowsocks
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
            self.dials
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Box::new(Canned204Conn::new()))
        }

        async fn dial_udp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            Err(meow_common::MeowError::NotSupported(
                "probe mock has no udp".into(),
            ))
        }

        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for ProbeMock {
        fn alive(&self) -> bool {
            self.health.alive()
        }

        fn alive_for_url(&self, _url: &str) -> bool {
            self.health.alive()
        }

        fn last_delay(&self) -> u16 {
            self.health.last_delay()
        }

        fn last_delay_for_url(&self, _url: &str) -> u16 {
            self.health.last_delay()
        }

        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            self.health.delay_history()
        }
    }

    /// Poll `cond` every 50 virtual ms until it holds; panic past `deadline`.
    async fn until(deadline: Duration, cond: impl Fn() -> bool) {
        let end = tokio::time::Instant::now() + deadline;
        while !cond() {
            assert!(
                tokio::time::Instant::now() < end,
                "condition not met within {deadline:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn tunnel_with_lazy_fallback(
        tunnel: &Tunnel,
        group: &std::sync::Arc<meow_proxy::group::fallback::FallbackGroup>,
        members: &[(&str, std::sync::Arc<ProbeMock>)],
    ) {
        use std::collections::HashMap;
        let mut proxies: HashMap<smol_str::SmolStr, std::sync::Arc<dyn Proxy>> = HashMap::new();
        for (name, mock) in members {
            proxies.insert((*name).into(), std::sync::Arc::<ProbeMock>::clone(mock));
        }
        proxies.insert(
            "lazy-fb".into(),
            std::sync::Arc::<meow_proxy::group::fallback::FallbackGroup>::clone(group),
        );
        tunnel.update_proxies(proxies, Default::default());
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_loop_probes_only_after_new_group_use() {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            false,
        ));
        let tunnel = Tunnel::new(resolver);
        let a = ProbeMock::named("a");
        let b = ProbeMock::named("b");
        let group = std::sync::Arc::new(meow_proxy::group::fallback::FallbackGroup::new(
            "lazy-fb",
            vec![
                std::sync::Arc::clone(&a) as std::sync::Arc<dyn Proxy>,
                std::sync::Arc::clone(&b) as std::sync::Arc<dyn Proxy>,
            ],
        ));
        tunnel_with_lazy_fallback(
            &tunnel,
            &group,
            &[
                ("a", std::sync::Arc::clone(&a)),
                ("b", std::sync::Arc::clone(&b)),
            ],
        );

        let spec = HealthCheckSpec {
            group_name: "lazy-fb".into(),
            url: "http://probe.test/204".into(),
            interval_secs: 1,
            lazy: true,
        };
        let task = tokio::spawn(run_health_check_loop(Arc::downgrade(tunnel.inner()), spec));

        // Before the first interval elapses the loop has only consumed the
        // immediate first tick — an unused lazy group must not probe.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(a.dials(), 0, "unused lazy group must not probe");
        assert_eq!(b.dials(), 0, "unused lazy group must not probe");
        assert_eq!(group.usage_generation(), 0);

        // First use: the dial itself reaches member a but is not a probe.
        let _ = group
            .dial_tcp(&Metadata::default())
            .await
            .expect("mock member dials succeed");
        assert_eq!(a.dials(), 1, "use dial hit the first alive member");
        assert_eq!(group.usage_generation(), 1, "dial records group use");

        // The next tick probes both members (use since last probe).
        until(Duration::from_secs(3), || a.dials() >= 2 && b.dials() >= 1).await;
        assert_eq!(a.dials(), 2, "one probe dial in addition to the use dial");
        assert_eq!(b.dials(), 1, "every member is probed");
        assert!(a.last_delay() >= 1, "probe result recorded into health");

        // No new use since the probe: later ticks must not probe again.
        let a_before = a.dials();
        let b_before = b.dials();
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_eq!(a.dials(), a_before, "no new use means no new probe");
        assert_eq!(b.dials(), b_before, "no new use means no new probe");

        // Use again — probing resumes at the next tick.
        let _ = group
            .dial_tcp(&Metadata::default())
            .await
            .expect("mock member dials succeed");
        assert_eq!(a.dials(), a_before + 1, "second use dial");
        until(Duration::from_secs(3), || {
            a.dials() > a_before + 1 && b.dials() > b_before
        })
        .await;
        assert_eq!(a.dials(), a_before + 2, "probe resumed after new use");
        assert_eq!(b.dials(), b_before + 1, "probe resumed after new use");

        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn eager_loop_probes_without_use() {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            false,
        ));
        let tunnel = Tunnel::new(resolver);
        let a = ProbeMock::named("a");
        let b = ProbeMock::named("b");
        let group = std::sync::Arc::new(meow_proxy::group::fallback::FallbackGroup::new(
            "lazy-fb",
            vec![
                std::sync::Arc::clone(&a) as std::sync::Arc<dyn Proxy>,
                std::sync::Arc::clone(&b) as std::sync::Arc<dyn Proxy>,
            ],
        ));
        tunnel_with_lazy_fallback(
            &tunnel,
            &group,
            &[
                ("a", std::sync::Arc::clone(&a)),
                ("b", std::sync::Arc::clone(&b)),
            ],
        );

        let spec = HealthCheckSpec {
            group_name: "lazy-fb".into(),
            url: "http://probe.test/204".into(),
            interval_secs: 1,
            lazy: false,
        };
        let task = tokio::spawn(run_health_check_loop(Arc::downgrade(tunnel.inner()), spec));

        // Non-lazy: the first tick completes immediately and probes even
        // though the group has never been used.
        until(Duration::from_secs(5), || a.dials() >= 1 && b.dials() >= 1).await;
        assert_eq!(a.dials(), 1, "immediate first tick probes unused members");
        assert!(a.last_delay() >= 1);

        task.abort();
    }

    /// Issue #543 item 1: members that come from a `use:` / `include-all`
    /// provider slot are not keys of the route table. The sweep used to
    /// resolve `members()` names through that table, so a provider-backed
    /// member was never probed and a `use:`-only group woke every interval
    /// to probe nothing.
    #[tokio::test(start_paused = true)]
    async fn eager_loop_probes_provider_slot_members() {
        let tunnel = stub_tunnel();
        let static_member = ProbeMock::named("static");
        let provider_member = ProbeMock::named("from-provider");
        let slot: meow_common::ProviderSlot =
            std::sync::Arc::new(parking_lot::RwLock::new(vec![std::sync::Arc::clone(
                &provider_member,
            )
                as std::sync::Arc<dyn Proxy>]));
        let group = std::sync::Arc::new(
            meow_proxy::group::fallback::FallbackGroup::new_with_providers(
                "use-fb",
                vec![std::sync::Arc::clone(&static_member) as std::sync::Arc<dyn Proxy>],
                vec![slot],
            ),
        );

        // Mirror a real registry: the static node and the group are keys,
        // the provider node is only reachable through the group's slot.
        let mut proxies: HashMap<smol_str::SmolStr, std::sync::Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(
            "static".into(),
            std::sync::Arc::<ProbeMock>::clone(&static_member),
        );
        proxies.insert(
            "use-fb".into(),
            std::sync::Arc::<meow_proxy::group::fallback::FallbackGroup>::clone(&group),
        );
        tunnel.update_proxies(proxies, Default::default());

        let spec = HealthCheckSpec {
            group_name: "use-fb".into(),
            url: "http://probe.test/204".into(),
            interval_secs: 1,
            lazy: false,
        };
        let task = tokio::spawn(run_health_check_loop(Arc::downgrade(tunnel.inner()), spec));

        until(Duration::from_secs(5), || {
            static_member.dials() >= 1 && provider_member.dials() >= 1
        })
        .await;
        assert_eq!(static_member.dials(), 1, "static member probed once");
        assert_eq!(
            provider_member.dials(),
            1,
            "provider-slot member must be probed by the sweep (issue #543)"
        );
        assert!(
            provider_member.last_delay() >= 1,
            "probe result recorded into the provider member's health"
        );
        assert!(
            group.alive(),
            "group becomes alive through its provider member"
        );

        task.abort();
    }
}
