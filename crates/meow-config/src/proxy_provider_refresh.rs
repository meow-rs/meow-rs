//! Interval-refresh supervision for proxy-providers.
//!
//! One background task per (`name`, `interval`) provider keeps calling
//! [`ProxyProvider::refresh`]. [`ProxyProviderRefreshSupervisor::reconcile`]
//! is invoked on every successful config commit — after the rebuilt provider
//! set has been swapped into the live registry — so providers added, removed,
//! or re-`interval`ed by a reload gain/lose their task without a restart.
//! Before this supervisor existed `RawProxyProvider.interval` was parsed but
//! never consumed: a provider's node list refreshed only on a manual
//! `PUT /providers/proxies/{name}` or a restart (issue #625).
//!
//! Unlike the rule-provider supervisor the wanted set is keyed on the
//! **committed declarations**, not the provider objects: a reused provider
//! carries its *source* identity (`ProxyProvider::def` deliberately excludes
//! `interval`), so an interval-only change must respawn the task without
//! rebuilding the provider or refetching its payload.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use crate::proxy_provider::ProxyProvider;
use crate::raw::RawProxyProvider;

/// Largest interval the supervisor will spawn a loop for (~10 years) —
/// same ceiling as the rule-provider supervisor: `RawProxyProvider.interval`
/// is an unchecked `u64` and an absurd value would overflow
/// `Instant + Duration` inside `tokio::time::interval`, panicking the task
/// on every reconcile. An over-ceiling provider is treated as
/// non-refreshable instead.
const MAX_REFRESH_INTERVAL_SECS: u64 = meow_common::MAX_DURATION_SECS;

/// Tracks the live refresh task per provider name. Cheap to share via
/// `Arc`; all mutation goes through [`reconcile`](Self::reconcile), which
/// diffs the wanted set against the running set — spawn what's missing,
/// abort what's gone or whose interval changed.
#[derive(Default)]
pub struct ProxyProviderRefreshSupervisor {
    tasks: Mutex<HashMap<String, (u64, JoinHandle<()>)>>,
}

impl ProxyProviderRefreshSupervisor {
    /// Diff the committed provider declarations against running tasks.
    ///
    /// `raws` is the candidate config's `proxy-providers:` map — the same
    /// declarations the registry swap was built from. A provider whose raw
    /// was warn-skipped at build (absent from `registry`) gets no task; a
    /// provider with `interval` absent or `0` refreshes manually only
    /// (`PUT /providers/proxies/{name}`), matching mihomo's `interval: 0`.
    ///
    /// Must be called from a tokio runtime context — it `tokio::spawn`s the
    /// per-provider loops — and under the same exclusion that serialised the
    /// registry swap (`CONFIG_MUTATION` in-tree), after the swap. Callers
    /// must not hold a `DashMap` guard — `reconcile` takes `registry` reads
    /// and the shard locks are not reentrant.
    ///
    /// Each spawned loop resolves its provider **by name** on every tick
    /// rather than pinning a `Arc<ProxyProvider>`: commits swap registry
    /// entries, and a detached startup-era `Arc` would refresh content no
    /// live group sees.
    ///
    /// Every call must pass the **same** registry `Arc` — spawned loops
    /// capture the `Weak` they were spawned with, so an embedder that
    /// replaces the whole `Arc<DashMap>` (rather than the entries inside
    /// it) strands its loops on a dead registry. In-tree the `Arc` is
    /// created once at startup and only its contents are swapped.
    ///
    /// Reaping runs only inside `reconcile`, i.e. on commits: a task that
    /// dies between commits stays dead until the next one (same semantics
    /// as the rule-provider supervisor).
    pub fn reconcile(
        &self,
        registry: &Arc<DashMap<String, Arc<ProxyProvider>>>,
        raws: Option<&HashMap<String, RawProxyProvider>>,
    ) {
        debug_assert!(
            tokio::runtime::Handle::try_current().is_ok(),
            "ProxyProviderRefreshSupervisor::reconcile must run inside a tokio runtime"
        );
        let wanted: HashMap<String, u64> = raws
            .into_iter()
            .flatten()
            .filter(|(name, _)| registry.contains_key(*name))
            .filter_map(|(name, raw)| {
                let interval = raw.interval.unwrap_or(0);
                if interval == 0 {
                    return None;
                }
                if interval > MAX_REFRESH_INTERVAL_SECS {
                    warn!(
                        provider = %name,
                        interval,
                        "proxy-provider interval exceeds the maximum; not auto-refreshing"
                    );
                    return None;
                }
                Some((name.clone(), interval))
            })
            .collect();

        let mut tasks = self.tasks.lock();
        tasks.retain(|name, (interval, task)| {
            let keep = wanted.get(name) == Some(interval) && !task.is_finished();
            if !keep {
                task.abort();
            }
            keep
        });
        for (name, interval) in wanted {
            if tasks.contains_key(&name) {
                continue;
            }
            let task = tokio::spawn(refresh_loop(
                name.clone(),
                interval,
                Arc::downgrade(registry),
            ));
            tasks.insert(name, (interval, task));
        }
    }

    /// Number of running refresh tasks (test introspection).
    #[cfg(test)]
    fn task_count(&self) -> usize {
        self.tasks.lock().len()
    }

    /// Interval a running task was spawned with (test introspection).
    #[cfg(test)]
    fn task_interval(&self, name: &str) -> Option<u64> {
        self.tasks.lock().get(name).map(|(iv, _)| *iv)
    }

    /// Identity of a running task's `JoinHandle` (test introspection) —
    /// distinguishes a respawned task from a kept one.
    #[cfg(test)]
    fn task_id(&self, name: &str) -> Option<tokio::task::Id> {
        self.tasks.lock().get(name).map(|(_, t)| t.id())
    }

    /// Insert an already-finished task — exercises the reap-and-respawn
    /// branch without racing a real panic. The spawned future is awaited
    /// to completion first, so `is_finished()` is genuinely true on a
    /// current-thread runtime (a bare `tokio::spawn` is never polled).
    #[cfg(test)]
    async fn insert_dead_task(&self, name: &str, interval: u64) {
        let mut task = tokio::spawn(async {});
        (&mut task).await.unwrap();
        debug_assert!(task.is_finished());
        self.tasks.lock().insert(name.to_string(), (interval, task));
    }
}

impl Drop for ProxyProviderRefreshSupervisor {
    /// Abort every supervised task — otherwise the `JoinHandle`s detach on
    /// drop and, while the registry is still alive, the loops keep
    /// refreshing providers nobody supervises.
    fn drop(&mut self) {
        for (_, (_, task)) in self.tasks.get_mut().drain() {
            task.abort();
        }
    }
}

async fn refresh_loop(
    name: String,
    interval_secs: u64,
    registry: Weak<DashMap<String, Arc<ProxyProvider>>>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    // `Delay` — a suspend longer than `interval` must not fire every missed
    // tick back-to-back (a refresh storm of real HTTP fetches); same policy
    // as the rule-provider supervisor.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // skip the immediate first tick
    loop {
        ticker.tick().await;
        // Weak like the rule-provider loop: a supervisor that outlives its
        // embedder's registry must not pin the map (and transitively a
        // provider's whole slot + dialer registry) forever — the task exits
        // and reconcile will not respawn it.
        let Some(registry) = registry.upgrade() else {
            return;
        };
        let Some(provider) = registry.get(&name).map(|e| Arc::clone(e.value())) else {
            debug!(provider = %name, "proxy-provider gone; refresh task idle until reconcile aborts it");
            continue;
        };
        // `refresh` serialises against a concurrent manual refresh via the
        // provider's `refresh_lock`, and a failed refresh keeps the
        // last-good slot — the loop only schedules, it never degrades the
        // provider.
        if let Err(e) = provider.refresh().await {
            error!(provider = %provider.name, "background refresh failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_provider(interval: Option<u64>) -> RawProxyProvider {
        RawProxyProvider {
            provider_type: "http".to_string(),
            url: Some("http://127.0.0.1:1/proxies.yaml".to_string()),
            path: None,
            interval,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: None,
            override_: None,
            proxy: None,
            dialer_proxy: None,
        }
    }

    /// A `File`-vehicle provider over `path` — `refresh()` re-reads it, so
    /// the loop is exercised without a real HTTP fetch. `path` must sit
    /// under `cache_dir` (`ProxyProvider::new` rejects paths without a
    /// containment root); the file itself need not exist for reconcile —
    /// it never calls refresh.
    fn file_provider(
        name: &str,
        path: &std::path::Path,
        cache_dir: &std::path::Path,
    ) -> Arc<ProxyProvider> {
        let raw = RawProxyProvider {
            provider_type: "file".to_string(),
            url: None,
            path: Some(path.display().to_string()),
            interval: None,
            ..raw_provider(None)
        };
        Arc::new(
            ProxyProvider::new(name, &raw, Some(cache_dir), true, false, Default::default())
                .expect("file provider must build"),
        )
    }

    fn registry(
        names: &[&str],
        cache_dir: &std::path::Path,
    ) -> Arc<DashMap<String, Arc<ProxyProvider>>> {
        let map = DashMap::new();
        for name in names {
            map.insert(
                name.to_string(),
                file_provider(name, &cache_dir.join(format!("{name}.yaml")), cache_dir),
            );
        }
        Arc::new(map)
    }

    fn raws(entries: &[(&str, Option<u64>)]) -> HashMap<String, RawProxyProvider> {
        entries
            .iter()
            .map(|(name, iv)| (name.to_string(), raw_provider(*iv)))
            .collect()
    }

    #[tokio::test]
    async fn reconcile_spawns_per_intervalled_provider() {
        let sup = ProxyProviderRefreshSupervisor::default();
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(&["a", "b", "no-interval", "zero", "skipped"], dir.path());
        let raw = raws(&[
            ("a", Some(3600)),
            ("b", Some(60)),
            ("no-interval", None),
            ("zero", Some(0)),
            // Declared but absent from the registry (warn-skipped at
            // build): must not spawn a task that would tick on a missing
            // provider forever.
            ("missing", Some(60)),
        ]);
        sup.reconcile(&reg, Some(&raw));
        assert_eq!(sup.task_count(), 2);
        assert_eq!(sup.task_interval("a"), Some(3600));
        assert_eq!(sup.task_interval("b"), Some(60));
        assert_eq!(sup.task_interval("no-interval"), None);
        assert_eq!(sup.task_interval("zero"), None);
        assert_eq!(sup.task_interval("missing"), None);
    }

    #[tokio::test]
    async fn reconcile_aborts_removed_and_respawns_changed_interval() {
        let sup = ProxyProviderRefreshSupervisor::default();
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(&["a", "b", "c"], dir.path());
        sup.reconcile(
            &reg,
            Some(&raws(&[
                ("a", Some(3600)),
                ("b", Some(60)),
                ("c", Some(300)),
            ])),
        );
        assert_eq!(sup.task_count(), 3);
        let kept_id = sup.task_id("c").unwrap();
        let old_a = sup.task_id("a").unwrap();

        // "b" removed from the declarations, "a" interval changed → both
        // tasks re-dispatched; the registry still carries "b" until the
        // commit swap, which is exactly the commit-time ordering.
        sup.reconcile(&reg, Some(&raws(&[("a", Some(120)), ("c", Some(300))])));
        assert_eq!(sup.task_count(), 2);
        assert_eq!(
            sup.task_interval("a"),
            Some(120),
            "the interval change must respawn the task with the new tick"
        );
        assert_ne!(
            sup.task_id("a"),
            Some(old_a),
            "the interval change must spawn a *new* task, not rewrite the old one"
        );
        assert_eq!(
            sup.task_id("c"),
            Some(kept_id),
            "an unchanged provider must keep its task — churn would restart \
             the interval countdown on every commit"
        );
        assert_eq!(sup.task_interval("b"), None);
    }

    #[tokio::test]
    async fn reconcile_reaps_and_respawns_dead_tasks() {
        let sup = ProxyProviderRefreshSupervisor::default();
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(&["a"], dir.path());
        sup.insert_dead_task("a", 3600).await;
        let dead_id = sup.task_id("a").unwrap();
        sup.reconcile(&reg, Some(&raws(&[("a", Some(3600))])));
        assert_eq!(sup.task_count(), 1);
        assert_eq!(sup.task_interval("a"), Some(3600));
        assert_ne!(
            sup.task_id("a"),
            Some(dead_id),
            "the finished task must be replaced, not kept"
        );
    }

    #[tokio::test]
    async fn reconcile_empty_declarations_abort_all() {
        let sup = ProxyProviderRefreshSupervisor::default();
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(&["a"], dir.path());
        sup.reconcile(&reg, Some(&raws(&[("a", Some(3600))])));
        sup.reconcile(&reg, Some(&HashMap::new()));
        assert_eq!(sup.task_count(), 0);
        sup.reconcile(&reg, Some(&raws(&[("a", Some(3600))])));
        assert_eq!(sup.task_count(), 1);
        // `None` (no `proxy-providers:` section) must also abort.
        sup.reconcile(&reg, None);
        assert_eq!(sup.task_count(), 0);
    }

    /// The loop itself: ticks resolve the provider *by name* so a registry
    /// swap is followed without a respawn, and `abort()` actually stops
    /// further refreshes. Driven with real temp files through a `File`
    /// vehicle (re-read on every refresh).
    #[tokio::test]
    async fn refresh_loop_follows_swaps_and_stops_on_abort() {
        let dir = tempfile::tempdir().unwrap();
        let path1 = dir.path().join("one.yaml");
        let path2 = dir.path().join("two.yaml");
        std::fs::write(&path1, "proxies:\n  - {name: a, type: direct}\n").unwrap();
        std::fs::write(
            &path2,
            "proxies:\n  - {name: b, type: direct}\n  - {name: c, type: direct}\n",
        )
        .unwrap();

        let reg: Arc<DashMap<String, Arc<ProxyProvider>>> = Arc::new(DashMap::new());
        reg.insert("p".to_string(), file_provider("p", &path1, dir.path()));

        let mut task = tokio::spawn(refresh_loop("p".to_string(), 1, Arc::downgrade(&reg)));
        // First real tick lands one interval after spawn.
        wait_proxy_count(&reg, "p", 1).await;

        // Swap a new provider object in under the same name — the running
        // task must refresh *it*, not the retired generation.
        let p2 = file_provider("p", &path2, dir.path());
        let p1 = Arc::clone(&reg.get("p").unwrap());
        reg.insert("p".to_string(), Arc::clone(&p2));
        for _ in 0..40 {
            if p2.proxies().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            p2.proxies().len(),
            2,
            "name resolution must follow the swap"
        );
        assert_eq!(
            p1.proxies().len(),
            1,
            "the retired provider must not be refreshed again"
        );

        // Abort: no further refresh even though the payload file changed.
        std::fs::write(
            &path2,
            "proxies:\n  - {name: b, type: direct}\n  - {name: c, type: direct}\n  - {name: d, type: direct}\n",
        )
        .unwrap();
        task.abort();
        assert!(
            (&mut task).await.unwrap_err().is_cancelled(),
            "the aborted task must actually terminate"
        );
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(p2.proxies().len(), 2);
    }

    async fn wait_proxy_count(reg: &DashMap<String, Arc<ProxyProvider>>, name: &str, want: usize) {
        for _ in 0..40 {
            if reg.get(name).map(|p| p.proxies().len()) == Some(want) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            reg.get(name).map(|p| p.proxies().len()),
            Some(want),
            "the tick must have refreshed the file provider"
        );
    }
}
