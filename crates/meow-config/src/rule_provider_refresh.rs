//! Interval-refresh supervision for HTTP rule-providers.
//!
//! One background task per (`name`, `interval`) HTTP provider keeps calling
//! [`RuleProvider::refresh`]. [`RefreshSupervisor::reconcile`] is invoked on
//! every successful config commit — after the rebuilt provider map has been
//! swapped into the registry — so providers added, removed, or re-
//! `interval`ed by a reload gain/lose their task without a restart (issue
//! #543). Before this supervisor existed the tasks were spawned once at
//! startup, so reloads could only ever refresh startup-era providers.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use crate::rule_provider::{ProviderType, RuleProvider};

/// Largest interval the supervisor will spawn a loop for (~10 years).
/// `RawRuleProvider.interval` is an unchecked `u64`: an absurd value
/// would overflow `Instant + Duration` inside `tokio::time::interval`
/// and panic the task on every reconcile — an over-ceiling provider is
/// treated as non-refreshable instead (issue #543 review).
const MAX_REFRESH_INTERVAL_SECS: u64 = meow_common::MAX_DURATION_SECS;

/// Tracks the live refresh task per provider name. Cheap to share via
/// `Arc`; all mutation goes through [`reconcile`](Self::reconcile), which
/// diffs the wanted set against the running set — spawn what's missing,
/// abort what's gone or whose interval changed.
#[derive(Default)]
pub struct RefreshSupervisor {
    tasks: Mutex<HashMap<String, (u64, JoinHandle<()>)>>,
}

impl RefreshSupervisor {
    /// Diff the registry's refreshable providers against running tasks.
    ///
    /// Must be called from a tokio runtime context — it `tokio::spawn`s the
    /// per-provider loops — and under the same exclusion that serialised
    /// the registry swap (`CONFIG_MUTATION` in-tree): `wanted` is
    /// snapshotted before the task map lock, so a concurrent registry write
    /// could otherwise be missed until the next reconcile.
    ///
    /// Each spawned loop resolves its provider **by name** on every tick
    /// rather than pinning a `Arc<RuleProvider>`: commits swap the registry
    /// map, and a detached startup-era `Arc` would refresh content no live
    /// matcher sees (issue #514 review).
    ///
    /// Every call must pass the **same** registry `Arc` — spawned loops
    /// capture the `Arc` they were spawned with, so an embedder that
    /// replaces the whole `Arc<RwLock<…>>` (rather than the map inside it)
    /// strands its loops on a dead registry. In-tree the `Arc` is created
    /// once at startup and only its contents are swapped.
    ///
    /// Reaping runs only inside `reconcile`, i.e. on commits: a task that
    /// dies between commits stays dead until the next one (same semantics
    /// as the health-check supervisor).
    ///
    /// Callers must not hold the registry's write guard — `reconcile`
    /// takes `registry.read()` and `parking_lot` locks are not reentrant.
    /// Commits that swap the map should prefer
    /// [`commit_registry`](Self::commit_registry), which performs the swap
    /// and this call in the only safe order.
    pub fn reconcile(&self, registry: &Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>) {
        debug_assert!(
            tokio::runtime::Handle::try_current().is_ok(),
            "RefreshSupervisor::reconcile must run inside a tokio runtime"
        );
        let wanted: HashMap<String, u64> = registry
            .read()
            .iter()
            .filter(|(_, p)| {
                if p.interval > MAX_REFRESH_INTERVAL_SECS {
                    warn!(
                        provider = %p.name,
                        interval = p.interval,
                        "rule-provider interval exceeds the maximum; not auto-refreshing"
                    );
                    return false;
                }
                p.interval > 0 && p.provider_type == ProviderType::Http
            })
            .map(|(name, p)| (name.clone(), p.interval))
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

    /// Install a rebuilt provider map and reconcile refresh tasks — the
    /// two steps every registry-mutating commit performs, in the only
    /// safe order (publish first, then supervise). Call under the same
    /// exclusion that serialised the rebuild (`CONFIG_MUTATION` in-tree).
    pub fn commit_registry(
        &self,
        registry: &Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
        map: HashMap<String, Arc<RuleProvider>>,
    ) {
        *registry.write() = map;
        self.reconcile(registry);
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

impl Drop for RefreshSupervisor {
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
    registry: Weak<RwLock<HashMap<String, Arc<RuleProvider>>>>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    // `Delay` — a suspend longer than `interval` must not fire every missed
    // tick back-to-back (a refresh storm of real HTTP fetches); same policy
    // as the health-check supervisor.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // skip the immediate first tick
    loop {
        ticker.tick().await;
        // Weak like the health-check loop: a supervisor that outlives its
        // embedder's registry must not pin the map (and transitively a
        // proxy-registry generation via `FetchContext`) forever — the
        // task exits and reconcile will not respawn it.
        let Some(registry) = registry.upgrade() else {
            return;
        };
        let Some(provider) = registry.read().get(&name).cloned() else {
            debug!(provider = %name, "rule-provider gone; refresh task idle until reconcile aborts it");
            continue;
        };
        // The provider re-parses the payload in its own load-time
        // ParserContext and declared format, so geo-dependent entries
        // survive refreshes (issue #533 review).
        if let Err(e) = provider.refresh().await {
            error!(provider = %provider.name, "background refresh failed: {:#}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_provider::test_provider;

    fn registry_map(entries: &[(&str, ProviderType, u64)]) -> HashMap<String, Arc<RuleProvider>> {
        entries
            .iter()
            .map(|(name, ty, iv)| (name.to_string(), test_provider(name, *ty, *iv)))
            .collect()
    }

    fn registry(
        entries: &[(&str, ProviderType, u64)],
    ) -> Arc<RwLock<HashMap<String, Arc<RuleProvider>>>> {
        Arc::new(RwLock::new(registry_map(entries)))
    }

    #[tokio::test]
    async fn reconcile_spawns_per_refreshable_provider() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[
            ("http-a", ProviderType::Http, 3600),
            ("http-b", ProviderType::Http, 60),
            ("no-interval", ProviderType::Http, 0),
            ("file", ProviderType::File, 3600),
            ("inline", ProviderType::Inline, 3600),
        ]);
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 2, "only http providers with interval > 0");
        assert_eq!(sup.task_interval("http-a"), Some(3600));
        assert_eq!(sup.task_interval("http-b"), Some(60));
        assert_eq!(sup.task_interval("file"), None);
        assert_eq!(sup.task_interval("inline"), None);
        assert_eq!(sup.task_interval("no-interval"), None);
    }

    #[tokio::test]
    async fn reconcile_aborts_removed_and_respawns_changed_interval() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[
            ("a", ProviderType::Http, 3600),
            ("b", ProviderType::Http, 60),
            ("c", ProviderType::Http, 300),
        ]);
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 3);
        let kept_id = sup.task_id("c").unwrap();
        let old_a = sup.task_id("a").unwrap();

        // "b" removed, "a" interval changed → both tasks re-dispatched.
        *reg.write() = registry_map(&[
            ("a", ProviderType::Http, 120),
            ("c", ProviderType::Http, 300),
        ]);
        sup.reconcile(&reg);
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
    }

    #[tokio::test]
    async fn reconcile_reaps_and_respawns_dead_tasks() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[("a", ProviderType::Http, 3600)]);
        sup.insert_dead_task("a", 3600).await;
        let dead_id = sup.task_id("a").unwrap();
        // The dead task matches the wanted interval but is finished — the
        // supervisor must reap it and spawn a live replacement.
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 1);
        assert_eq!(sup.task_interval("a"), Some(3600));
        assert_ne!(
            sup.task_id("a"),
            Some(dead_id),
            "the finished task must be replaced, not kept"
        );
    }

    #[tokio::test]
    async fn reconcile_empty_registry_aborts_all() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[("a", ProviderType::Http, 3600)]);
        sup.reconcile(&reg);
        *reg.write() = HashMap::new();
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 0);
    }

    /// The loop itself: ticks resolve the provider *by name* so a registry
    /// swap is followed without a respawn, and `abort()` actually stops
    /// further refreshes. Driven with real temp files through a `File`
    /// provider (the loop does not check `provider_type` — only
    /// `reconcile`'s wanted set does).
    #[tokio::test]
    async fn refresh_loop_follows_swaps_and_stops_on_abort() {
        use crate::rule_provider::test_provider_with_vehicle;

        let dir = tempfile::tempdir().unwrap();
        let path1 = dir.path().join("one.yaml");
        let path2 = dir.path().join("two.yaml");
        std::fs::write(&path1, "payload:\n  - 'a.example'\n").unwrap();
        std::fs::write(&path2, "payload:\n  - 'b.example'\n  - 'c.example'\n").unwrap();

        let p1 =
            test_provider_with_vehicle("p", ProviderType::File, 0, path1.display().to_string());
        let reg = registry(&[]);
        *reg.write() = HashMap::from([("p".to_string(), p1)]);

        let mut task = tokio::spawn(refresh_loop("p".to_string(), 1, Arc::downgrade(&reg)));
        // First real tick lands one interval after spawn.
        wait_rule_count(&reg, "p", 1).await;

        // Swap a new provider object in under the same name — the running
        // task must refresh *it*, not the retired generation.
        let p2 =
            test_provider_with_vehicle("p", ProviderType::File, 0, path2.display().to_string());
        let p1 = Arc::clone(&reg.read()["p"]);
        *reg.write() = HashMap::from([("p".to_string(), Arc::clone(&p2))]);
        for _ in 0..40 {
            if p2.rule_count() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(p2.rule_count(), 2, "name resolution must follow the swap");
        assert_eq!(
            p1.rule_count(),
            1,
            "the retired provider must not be refreshed again"
        );

        // Abort: no further refresh even though the payload file changed.
        std::fs::write(
            &path2,
            "payload:\n  - 'b.example'\n  - 'c.example'\n  - 'd.example'\n",
        )
        .unwrap();
        task.abort();
        assert!(
            (&mut task).await.unwrap_err().is_cancelled(),
            "the aborted task must actually terminate"
        );
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(p2.rule_count(), 2);
    }

    async fn wait_rule_count(
        reg: &RwLock<HashMap<String, Arc<RuleProvider>>>,
        name: &str,
        want: usize,
    ) {
        for _ in 0..40 {
            if reg.read()[name].rule_count() == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            reg.read()[name].rule_count(),
            want,
            "the tick must have refreshed the file provider"
        );
    }
}
