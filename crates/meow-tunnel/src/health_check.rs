use crate::tunnel::TunnelInner;
use meow_common::logbook::{self, Level};
use meow_common::{AdapterType, ChainHealth, HealthCheckSpec, Metadata, Proxy};
use smol_str::SmolStr;
use std::collections::{BTreeSet, HashMap};
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
    // The ceiling matters too: `PUT /configs?force=true` persists a raw
    // candidate that `build_proxy_layer` rejected, and the reconcile
    // below still extracts its interval — clamping at the consumer
    // covers every population path (issue #648 review).
    let interval_secs = spec.interval_secs.clamp(1, meow_common::MAX_DURATION_SECS);
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    // `Delay` (not tokio's default `Burst`) so a probe that outlives a short
    // `interval` schedules the next tick a full interval from *now* instead
    // of firing a back-to-back burst of catch-up probes. For the common
    // `interval >= probe timeout` case (default 300 s vs 5 s) no tick is ever
    // missed and the schedule is identical to before; this also prevents a
    // missed-tick probe storm right after system suspend.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_probed_generation = 0;
    let mut watch = GroupWatch::resume(&spec.group_name);

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
        let mut delays = HashMap::new();
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
            delays.insert(name, delay);
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
        if total_count > 0 {
            watch.record(&spec.group_name, &group, &delays);
        }

        if let Some(chain) = group.chain_health() {
            // A block outlives the gap to the next round, which probes
            // the member again if it is still among the fastest.
            let hold = Duration::from_secs(interval_secs).saturating_mul(2);
            probe_chain_targets(&spec, &group, chain, proxies, expected_status, hold).await;
        }
    }
}

/// Probe the `dialer-proxy` chains that run through `group`, once its own
/// URL test has refreshed the member delays the probes are ordered by. See
/// [`meow_common::chain_health`].
async fn probe_chain_targets(
    spec: &HealthCheckSpec,
    group: &Arc<dyn Proxy>,
    chain: &ChainHealth,
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    expected_status: Option<&str>,
    hold: Duration,
) {
    for (target, owners) in chain.targets() {
        let Some(owner) = owners
            .iter()
            .rev()
            .find_map(|name| resolve_owner(proxies, name))
        else {
            debug!(
                "health-check: {} — no outbound left that dials {target} through it",
                spec.group_name
            );
            continue;
        };
        let report = meow_proxy::health::probe_chain_target(
            group,
            &target,
            &owner,
            &spec.url,
            expected_status,
            PROBE_TIMEOUT,
            hold,
        )
        .await;
        if !report.reached.is_empty() || !report.blocked.is_empty() {
            info!(
                "health-check: {} — dialer-proxy chain to {target} via '{}': {} reached, {} blocked",
                spec.group_name,
                owner.name(),
                report.reached.len(),
                report.blocked.len()
            );
        }
    }
}

/// What the logbook last heard about one group: its dead members and the
/// member it routes to, so a sweep is recorded only when either changes.
#[derive(Default)]
struct GroupWatch {
    /// The dead members last recorded; `None` before the first sweep.
    down: Option<BTreeSet<String>>,
    /// Members whose probe failed in the previous sweep.
    failed: BTreeSet<String>,
    /// The logbook's latest `group.health` entry for the group, when this
    /// watch started, says members are down. A loop respawned for a changed
    /// spec, or a restart, starts a new watch.
    logged_down: bool,
    pick: Option<String>,
}

/// Dead members named in a `group.health` message; the `down` field lists
/// up to [`DOWN_FIELD_NAMES`].
const DOWN_MESSAGE_NAMES: usize = 3;
const DOWN_FIELD_NAMES: usize = 20;

impl GroupWatch {
    /// A watch picking up from what the logbook last recorded for `group`.
    fn resume(group: &str) -> Self {
        Self {
            logged_down: logbook::latest_level(logbook::kind::GROUP_HEALTH, group)
                .is_some_and(|level| level > Level::Info),
            ..Self::default()
        }
    }

    /// Record a finished sweep of `group`: `delays` holds each probed
    /// member's delay, `0` when it is dead.
    fn record(&mut self, name: &str, group: &Arc<dyn Proxy>, delays: &HashMap<String, u16>) {
        if let Some((level, message, down)) = self.health(name, delays) {
            let mut event = logbook::event(logbook::kind::GROUP_HEALTH, level, message)
                .subject(name)
                .field("alive", delays.len() - down.len())
                .field("total", delays.len());
            if level == Level::Warning {
                let listed: Vec<String> = down.iter().take(DOWN_FIELD_NAMES).cloned().collect();
                event = event.field("down", listed);
            }
            event.coalesce().record();
        }

        // Only url-test and fallback route to one member. The peek
        // recomputes the pick from the fresh delays, as a dial would.
        if !matches!(
            group.adapter_type(),
            AdapterType::UrlTest | AdapterType::Fallback
        ) {
            return;
        }
        let pick = group
            .unwrap_proxy(&Metadata::default(), false)
            .map(|p| p.name().to_string());
        if let Some((from, to, message)) = self.switch(name, pick, delays) {
            logbook::event(logbook::kind::GROUP_SWITCH, Level::Info, message)
                .subject(name)
                .field("from", from)
                .field("to", to)
                .coalesce()
                .record();
        }
    }

    /// The level, message and dead members of the `group.health` entry for
    /// a sweep that probed `delays`, if the dead members changed. A member
    /// is dead from its first failed probe until it passes two sweeps in a
    /// row, so a member that flaps between sweeps is one entry, not one per
    /// sweep. A first sweep is recorded when something is down, or when
    /// nothing is and the logbook still says otherwise.
    fn health(
        &mut self,
        name: &str,
        delays: &HashMap<String, u16>,
    ) -> Option<(Level, String, BTreeSet<String>)> {
        let failed: BTreeSet<String> = delays
            .iter()
            .filter(|(_, delay)| **delay == 0)
            .map(|(member, _)| member.clone())
            .collect();
        let mut down = failed.clone();
        down.extend(
            self.failed
                .iter()
                .filter(|member| delays.contains_key(*member))
                .cloned(),
        );
        self.failed = failed;
        let changed = match &self.down {
            Some(previous) => *previous != down,
            None => !down.is_empty() || self.logged_down,
        };
        let total = delays.len();
        let event = changed.then(|| {
            if down.is_empty() {
                (
                    Level::Info,
                    format!("All {total} members of '{name}' are up again"),
                )
            } else if down.len() == total {
                (
                    Level::Error,
                    format!("All {total} members of '{name}' are down"),
                )
            } else {
                let names: Vec<String> = down
                    .iter()
                    .take(DOWN_MESSAGE_NAMES)
                    .map(|member| format!("'{member}'"))
                    .collect();
                let more = match down.len().saturating_sub(DOWN_MESSAGE_NAMES) {
                    0 => String::new(),
                    more => format!(" and {more} more"),
                };
                (
                    Level::Warning,
                    format!(
                        "{} of {total} members of '{name}' are down: {}{more}",
                        down.len(),
                        names.join(", ")
                    ),
                )
            }
        });
        self.down = Some(down.clone());
        event.map(|(level, message)| (level, message, down))
    }

    /// The previous pick, the new one and the `group.switch` message, if
    /// `pick` differs from the pick after the previous sweep. The first
    /// sweep only learns the pick.
    fn switch(
        &mut self,
        name: &str,
        pick: Option<String>,
        delays: &HashMap<String, u16>,
    ) -> Option<(String, String, String)> {
        let from = std::mem::replace(&mut self.pick, pick)?;
        let to = self.pick.clone()?;
        if from == to {
            return None;
        }
        let state = |member: &str| match delays.get(member) {
            Some(0) => " (down)".to_owned(),
            Some(delay) => format!(" ({delay} ms)"),
            None => String::new(),
        };
        let message = format!(
            "'{name}' switched from '{from}'{} to '{to}'{}",
            state(&from),
            state(&to)
        );
        Some((from, to, message))
    }
}

/// The outbound `name` names: a route-table entry, or a provider-sourced
/// member of a group there. Provider nodes that carry their own
/// `dialer-proxy` are not route-table keys.
fn resolve_owner(proxies: &HashMap<SmolStr, Arc<dyn Proxy>>, name: &str) -> Option<Arc<dyn Proxy>> {
    if let Some(proxy) = proxies.get(name) {
        return Some(Arc::clone(proxy));
    }
    proxies
        .values()
        .filter_map(|p| p.member_proxies())
        .flatten()
        .find(|p| p.name() == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Tunnel;
    use meow_common::{Metadata, Proxy, ProxyAdapter};
    use meow_config::extract_health_check_specs as extract_specs;

    /// A sweep of members `a` to `e` where `failed` did not answer.
    fn sweep(failed: &[&str]) -> HashMap<String, u16> {
        ["a", "b", "c", "d", "e"]
            .into_iter()
            .map(|m| (m.to_owned(), if failed.contains(&m) { 0 } else { 80 }))
            .collect()
    }

    fn health(watch: &mut GroupWatch, failed: &[&str]) -> Option<(Level, String)> {
        watch
            .health("G", &sweep(failed))
            .map(|(level, message, _)| (level, message))
    }

    #[test]
    fn group_health_is_recorded_when_the_dead_members_change() {
        let mut watch = GroupWatch::default();
        assert_eq!(health(&mut watch, &[]), None, "a healthy group");
        assert_eq!(
            health(&mut watch, &["a"]),
            Some((Level::Warning, "1 of 5 members of 'G' are down: 'a'".into()))
        );
        assert_eq!(health(&mut watch, &["a"]), None, "unchanged");
        assert_eq!(
            health(&mut watch, &["a", "b", "c", "d"]),
            Some((
                Level::Warning,
                "4 of 5 members of 'G' are down: 'a', 'b', 'c' and 1 more".into()
            ))
        );
        assert_eq!(
            health(&mut watch, &["a", "b", "c", "d", "e"]),
            Some((Level::Error, "All 5 members of 'G' are down".into()))
        );
        assert_eq!(
            health(&mut watch, &[]),
            None,
            "back after two healthy sweeps"
        );
        assert_eq!(
            health(&mut watch, &[]),
            Some((Level::Info, "All 5 members of 'G' are up again".into()))
        );

        let mut fresh = GroupWatch::default();
        assert_eq!(
            health(&mut fresh, &["a"]).map(|(level, _)| level),
            Some(Level::Warning),
            "a first sweep is recorded when something is down"
        );
    }

    #[test]
    fn a_flapping_member_is_one_entry() {
        let mut watch = GroupWatch::default();
        assert!(health(&mut watch, &["a"]).is_some());
        for failed in [&[][..], &["a"], &[], &["a"], &[]] {
            assert_eq!(health(&mut watch, failed), None);
        }
        assert_eq!(
            health(&mut watch, &[]).map(|(level, _)| level),
            Some(Level::Info)
        );
    }

    #[test]
    fn a_new_watch_reports_a_recovery_the_logbook_has_not_seen() {
        let mut watch = GroupWatch {
            logged_down: true,
            ..GroupWatch::default()
        };
        assert_eq!(
            health(&mut watch, &[]),
            Some((Level::Info, "All 5 members of 'G' are up again".into()))
        );
    }

    #[test]
    fn group_switch_is_recorded_when_the_pick_changes() {
        let mut watch = GroupWatch::default();
        let delays = HashMap::from([("a".to_owned(), 0), ("b".to_owned(), 120)]);
        let pick = |m: &str| Some(m.to_owned());
        assert_eq!(
            watch.switch("G", pick("a"), &delays),
            None,
            "learns the pick"
        );
        assert_eq!(watch.switch("G", pick("a"), &delays), None, "unchanged");
        assert_eq!(
            watch.switch("G", pick("b"), &delays),
            Some((
                "a".into(),
                "b".into(),
                "'G' switched from 'a' (down) to 'b' (120 ms)".into()
            ))
        );
        assert_eq!(
            watch.switch("G", pick("c"), &delays).map(|(_, _, m)| m),
            Some("'G' switched from 'b' (120 ms) to 'c'".into()),
            "a member the sweep did not probe has no state"
        );
    }

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

    /// Issue #648 review: `PUT /configs?force=true` persists raw intervals
    /// that never passed `build_proxy_layer` — the consumer-side clamp in
    /// `run_health_check_loop` must keep a `u64::MAX` spec from panicking
    /// or hanging the task's first poll. A dead `Weak` exits after the
    /// first tick regardless.
    #[tokio::test]
    async fn absurd_interval_spec_exits_cleanly() {
        let spec = HealthCheckSpec {
            group_name: "x".into(),
            url: "http://probe.test/204".into(),
            interval_secs: u64::MAX,
            lazy: false,
        };
        let dead: Weak<TunnelInner> = Weak::new();
        tokio::time::timeout(Duration::from_secs(5), run_health_check_loop(dead, spec))
            .await
            .expect("absurd interval spec must not hang or panic");
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

    /// Issue #555: `select`/`relay` accept `url`/`interval`/`lazy` in the
    /// flat `RawProxyGroup` shape but never run probes — even when the
    /// fields are set explicitly, no spec may be emitted.  Upstream
    /// sweeps static members of every group type (mihomo `90bf158`);
    /// meow warns at parse instead (Class B, ADR-0002).
    #[test]
    fn extract_specs_skips_select_and_relay_with_health_fields() {
        for group_type in ["select", "relay"] {
            let g = meow_config::raw::RawProxyGroup {
                name: "g".into(),
                group_type: group_type.into(),
                url: Some("https://example.com/204".into()),
                interval: Some(60),
                lazy: Some(true),
                tolerance: Some(100),
                expected_status: Some("204".into()),
                ..Default::default()
            };
            assert!(
                extract_specs(&[g]).is_empty(),
                "{group_type} with health fields must not emit a probe spec"
            );
        }
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

    /// Duplicate group names: last spec wins. Production rejects
    /// duplicate names at config build (issue #561), so this is the
    /// defensive contract for callers that hand `reconcile` raw
    /// declarations — including `PUT /configs?force=true` commits whose
    /// candidate failed the build but was persisted. A duplicate must
    /// not churn the task on every reconcile.
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
    /// emits no spec — the defensive last-wins resolution applies across
    /// types too, so the select group would not be probed.
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

    /// Issue #555: `expected-status` on a `load-balance` group must reach
    /// the sweep — a canned 204 answer against `expected_status("200")`
    /// marks the member dead. Without the `with_expected_status` wiring
    /// the probe would accept the default range and the member would
    /// stay alive, so this fails if the plumbing is reverted.
    #[tokio::test(start_paused = true)]
    async fn lb_expected_status_reaches_probe() {
        let tunnel = stub_tunnel();
        let a = ProbeMock::named("a");
        let group = std::sync::Arc::new(
            meow_proxy::group::load_balance::LoadBalanceGroup::new(
                "lb",
                vec![std::sync::Arc::clone(&a) as std::sync::Arc<dyn Proxy>],
                meow_proxy::group::load_balance::LbStrategy::RoundRobin,
            )
            .with_expected_status("200".to_string()),
        );

        let mut proxies: HashMap<smol_str::SmolStr, std::sync::Arc<dyn Proxy>> = HashMap::new();
        proxies.insert("a".into(), std::sync::Arc::<ProbeMock>::clone(&a));
        proxies.insert(
            "lb".into(),
            std::sync::Arc::<meow_proxy::group::load_balance::LoadBalanceGroup>::clone(&group),
        );
        tunnel.update_proxies(proxies, Default::default());

        let spec = HealthCheckSpec {
            group_name: "lb".into(),
            url: "http://probe.test/204".into(),
            interval_secs: 1,
            lazy: false,
        };
        let task = tokio::spawn(run_health_check_loop(Arc::downgrade(tunnel.inner()), spec));

        until(Duration::from_secs(5), || a.dials() >= 1).await;
        assert!(
            !a.alive(),
            "expected-status '200' must reject the canned 204 — member dead"
        );
        assert_eq!(a.last_delay(), 0, "failed probe records delay 0");

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
