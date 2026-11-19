//! Persistent backing for `SelectorGroup` choices.
//!
//! Upstream Go mihomo stores user-picked selector targets in a BoltDB
//! `cache.db` (`adapter/outboundgroup/selector.go` → `cachefile.Cache().SetSelected`).
//! We keep the same semantics with a simpler JSON file written through on
//! every successful `select()`, so the user's pick survives process restart.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::warn;

/// Map of `{group_name → selected_proxy_name}` persisted to a JSON file.
pub struct SelectorStore {
    path: PathBuf,
    map: Mutex<HashMap<String, String>>,
    /// Serializes the disk half of `set()` — see its comment (issue #621).
    write_lock: Mutex<()>,
    /// A past `write_atomic` failed — the file is behind the map. The
    /// early-return in `set()` must not skip the retry when the value is
    /// unchanged (issue #621 review).
    dirty: std::sync::atomic::AtomicBool,
}

impl SelectorStore {
    /// Open a store at `path`. Missing / unreadable / malformed files are
    /// treated as empty (with a warn), so a fresh install just starts blank.
    pub fn open(path: PathBuf) -> Arc<Self> {
        // Remove scratch siblings left by a crash between create and
        // rename (issue #621) — best-effort, before the load.
        meow_common::fs_util::sweep_scratch_siblings(
            &path,
            meow_common::fs_util::SCRATCH_STALE_AGE,
        );
        let map = match std::fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice::<HashMap<String, String>>(&bytes).unwrap_or_else(|e| {
                    warn!(path = %path.display(), error = %e,
                        "selector store: malformed JSON, starting empty");
                    HashMap::new()
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e,
                    "selector store: read failed, starting empty");
                HashMap::new()
            }
        };
        Arc::new(Self {
            path,
            map: Mutex::new(map),
            write_lock: Mutex::new(()),
            dirty: AtomicBool::new(false),
        })
    }

    pub fn get(&self, group: &str) -> Option<String> {
        self.map.lock().get(group).cloned()
    }

    /// Update the in-memory map and flush the whole file atomically. IO
    /// errors only warn — losing the persistence side-channel must never
    /// fail the user's selection.
    pub fn set(&self, group: &str, selected: &str) {
        let _write = self.write_lock.lock();
        self.set_locked(group, selected);
    }

    /// The body of [`Self::set`] with the write serialization already held —
    /// [`SelectorWriter::set`] takes the same lock to check its epoch, so a
    /// fenced writer's check and the flush it gates share one critical
    /// section.
    fn set_locked(&self, group: &str, selected: &str) {
        use Ordering::Relaxed;
        {
            let mut g = self.map.lock();
            if g.get(group).is_some_and(|v| v == selected) && !self.dirty.load(Relaxed) {
                return;
            }
            g.insert(group.to_string(), selected.to_string());
            self.dirty.store(true, Relaxed);
        }
        // Serialize writers and take the snapshot *inside* the write lock:
        // the rename that lands last then always carries the newest
        // committed map — without this, a slow writer holding an older
        // snapshot could publish it after a newer writer, leaving the
        // persisted choice behind the last in-memory one (issue #621).
        let snapshot = self.map.lock().clone();
        match write_atomic(&self.path, &snapshot) {
            Ok(()) => self.dirty.store(false, Relaxed),
            // Re-assert dirty on failure *inside* the write lock: a
            // concurrent `set` may have committed a newer map + flag while
            // we wrote, and a successful sibling's `store(false)` can land
            // between that commit and this failed write — without the
            // re-store, a same-value retry would early-return forever and
            // the disk would stay stale (issue #621 review).
            Err(e) => {
                self.dirty.store(true, Relaxed);
                warn!(path = %self.path.display(), error = %e,
                    "selector store: persist failed");
            }
        }
    }
}

/// The epoch-fenced persistence handle a group holds — `profile.
/// store-selected`'s writer half. `get` reads the shared map (priming a
/// group's saved pick is safe under any epoch); `set` rechecks its
/// captured epoch under the store's write lock, so a stale group Arc from
/// an earlier generation can never flush through after a disable or a
/// disable→re-enable cycle — the two sides of the fence are serialized by
/// the same lock the atomic rename already required (issue #974).
#[derive(Clone)]
pub struct SelectorWriter {
    store: Arc<SelectorStore>,
    epoch: u64,
    epochs: Arc<AtomicU64>,
}

impl SelectorWriter {
    /// An unfenced writer over a bare store — tests and embedders that
    /// own persistence directly rather than through [`SelectionBacking`]'s
    /// config-scoped lifecycle. Its private epoch cell never moves, so
    /// every `set` passes the fence check.
    pub fn standalone(store: Arc<SelectorStore>) -> Self {
        Self {
            store,
            epoch: 0,
            epochs: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn get(&self, group: &str) -> Option<String> {
        self.store.get(group)
    }

    pub fn set(&self, group: &str, selected: &str) {
        let _write = self.store.write_lock.lock();
        if self.epochs.load(Ordering::Acquire) != self.epoch {
            return;
        }
        self.store.set_locked(group, selected);
    }
}

/// The config-scoped owner of the `profile.store-selected` channel —
/// replaces the former first-`open`-wins process global (issue #974).
/// Created by the config build, carried by the running `Config`/`Tunnel`,
/// and consulted on every rebuild lane (startup, PUT/PATCH commit,
/// subscription/geodata republish):
///
/// - `prepare` opens the JSON store lazily, only for an enabled
///   generation — a disabled profile never touches the file, and a
///   `None` path (`--config-string`, `load_config_from_str`) means no
///   persistence is possible at all.
/// - `attach` hands a group its writer — `None` while disabled, matching
///   upstream's "no `StoreSelected` gate ⇒ no restore and no write".
/// - `commit` is run by the publication lane with the *committed*
///   generation's resolved flag: an enable/disable transition bumps the
///   epoch, instantly fencing every writer an older group Arc still
///   holds; an unchanged flag is a no-op, so ordinary enabled rebuilds
///   keep sharing store and epoch. Rejected candidates never reach
///   `commit` — their attached writers die fenced with them.
pub struct SelectionBacking {
    /// `None` disables persistence structurally (no backing file).
    path: Option<PathBuf>,
    /// Lazily opened — `prepare` fills it on the first enabled build and
    /// it stays open across a disable so re-enable reuses one store.
    store: Mutex<Option<Arc<SelectorStore>>>,
    epoch: Arc<AtomicU64>,
    /// The last *committed* resolved flag — `attach` prices a not-yet-
    /// committed generation's epoch from it.
    enabled: AtomicBool,
}

impl SelectionBacking {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            store: Mutex::new(None),
            epoch: Arc::new(AtomicU64::new(0)),
            enabled: AtomicBool::new(false),
        }
    }

    /// A backing that can never persist — tests and `--config-string`.
    pub fn unpersisted() -> Self {
        Self::new(None)
    }

    /// Open the store if `enabled` and a path exists. Runs the fs work on
    /// a blocking thread for async callers; `prepare_sync` is the same
    /// step for callers already on a blocking thread. Idempotent — an
    /// already-open store is reused across disable/re-enable cycles.
    pub async fn prepare(&self, enabled: bool) {
        if !enabled || self.store.lock().is_some() {
            return;
        }
        let Some(path) = self.path.clone() else {
            return;
        };
        let store = tokio::task::spawn_blocking(move || SelectorStore::open(path)).await;
        if let Ok(store) = store {
            let mut guard = self.store.lock();
            if guard.is_none() {
                *guard = Some(store);
            }
        }
    }

    /// [`Self::prepare`] for callers already on a blocking thread.
    pub fn prepare_sync(&self, enabled: bool) {
        if !enabled {
            return;
        }
        let mut guard = self.store.lock();
        if guard.is_none() {
            if let Some(path) = &self.path {
                *guard = Some(SelectorStore::open(path.clone()));
            }
        }
    }

    /// Attach a writer for a group built under `enabled` — `None` when
    /// disabled or persistence is impossible. While the committed flag is
    /// still `false` the pending generation's writers price their epoch at
    /// `epoch + 1`: exactly the value [`Self::commit`] will publish for
    /// the disable→enable transition, so a rejected candidate's writers
    /// stay fenced without a wasted bump.
    pub fn attach(&self, enabled: bool) -> Option<SelectorWriter> {
        if !enabled {
            return None;
        }
        let epoch =
            self.epoch.load(Ordering::Acquire) + u64::from(!self.enabled.load(Ordering::Acquire));
        self.store.lock().as_ref().map(|store| SelectorWriter {
            store: Arc::clone(store),
            epoch,
            epochs: Arc::clone(&self.epoch),
        })
    }

    /// Called at the route commit with the candidate's resolved flag:
    /// bumps the epoch on any transition — under the store's write lock,
    /// so it serializes against a stale writer's epoch check the same way
    /// two writers already serialize their renames. Writers attached for
    /// the pending generation captured `epoch + 1` at [`Self::attach`],
    /// so an enable transition publishes exactly the epoch they fence on.
    pub fn commit(&self, enabled: bool) {
        if self.enabled.swap(enabled, Ordering::AcqRel) == enabled {
            return;
        }
        let guard = self.store.lock();
        if let Some(store) = guard.as_ref() {
            let _write = store.write_lock.lock();
            self.epoch.fetch_add(1, Ordering::AcqRel);
        } else {
            self.epoch.fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn write_atomic(path: &Path, map: &HashMap<String, String>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_vec_pretty(map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Unique scratch per call — concurrent `set()`s (API handlers plus
    // url-test/fallback auto-switch, none laned) must not share a fixed
    // tmp or one writer's rename publishes the other's splice (issue #543
    // review).
    let tmp = scratch_path(path);
    let result = std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn scratch_path(path: &Path) -> PathBuf {
    // Same unique-suffix scheme as `meow-config::unique_scratch_path`;
    // `AtomicU` resolves to AtomicU32 where 64-bit atomics are missing.
    static COUNTER: meow_common::atomic::AtomicU = meow_common::atomic::AtomicU::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{}.{}.tmp", std::process::id(), n));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_via_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sel.json");
        let s = SelectorStore::open(path.clone());
        assert!(s.get("g").is_none());
        s.set("g", "node-a");
        assert_eq!(s.get("g").as_deref(), Some("node-a"));

        // Reopen, value survives.
        drop(s);
        let s2 = SelectorStore::open(path);
        assert_eq!(s2.get("g").as_deref(), Some("node-a"));
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let s = SelectorStore::open(dir.path().join("does-not-exist.json"));
        assert!(s.get("anything").is_none());
    }

    #[test]
    fn malformed_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let s = SelectorStore::open(path);
        assert!(s.get("anything").is_none());
        // And it recovers — subsequent set() rewrites the file cleanly.
        s.set("g", "x");
        assert_eq!(s.get("g").as_deref(), Some("x"));
    }

    #[test]
    fn concurrent_sets_converge_to_latest_map_on_disk() {
        // Issue #621: writers used to snapshot+rename independently, so a
        // slow writer could land an older map last. With the serialized
        // write lock the file must always end up equal to the final map.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sel.json");
        let s = SelectorStore::open(path.clone());
        let mut handles = Vec::new();
        for t in 0..8 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                for i in 0..50 {
                    s.set(&format!("g{}", i % 4), &format!("t{t}-v{i}"));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let on_disk: HashMap<String, String> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let in_memory = s.map.lock().clone();
        assert_eq!(on_disk, in_memory);
    }

    #[test]
    fn backing_fences_writers_across_disable_and_reenable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sel.json");
        let backing = SelectionBacking::new(Some(path.clone()));

        // Disabled: no writer attaches and the file is never opened.
        assert!(backing.attach(false).is_none());
        assert!(!path.exists(), "disabled profile must not touch disk");

        // First enabled generation: the pending writer is fenced until
        // the commit publishes its epoch.
        backing.prepare_sync(true);
        let gen1 = backing.attach(true).expect("enabled attaches a writer");
        gen1.set("g", "a");
        assert!(
            backing.store.lock().as_ref().unwrap().get("g").is_none(),
            "a not-yet-committed generation must not reach the map"
        );
        backing.commit(true);
        gen1.set("g", "a");
        assert_eq!(
            backing.store.lock().as_ref().unwrap().get("g").as_deref(),
            Some("a")
        );

        // An ordinary enabled rebuild shares store and epoch.
        let gen2 = backing.attach(true).unwrap();
        backing.commit(true); // unchanged flag — no-op
        gen2.set("g2", "x");
        assert_eq!(
            backing.store.lock().as_ref().unwrap().get("g2").as_deref(),
            Some("x")
        );

        // Disable commit: every writer from earlier generations dies.
        backing.commit(false);
        gen1.set("g", "stale1");
        gen2.set("g", "stale2");
        assert_eq!(
            backing.store.lock().as_ref().unwrap().get("g").as_deref(),
            Some("a"),
            "stale group Arcs must never write after disable"
        );

        // Re-enable: the new generation's pending writer stays fenced
        // until its own commit; old writers stay dead forever.
        let gen3 = backing.attach(true).unwrap();
        gen3.set("g", "early");
        backing.commit(true);
        gen3.set("g", "d");
        gen1.set("g", "zombie1");
        gen2.set("g", "zombie2");
        assert_eq!(
            backing.store.lock().as_ref().unwrap().get("g").as_deref(),
            Some("d")
        );

        // Round-trip through disk like a restart.
        drop(backing);
        let reopened = SelectorStore::open(path);
        assert_eq!(reopened.get("g").as_deref(), Some("d"));
    }

    #[test]
    fn unpersisted_backing_never_attaches() {
        let backing = SelectionBacking::unpersisted();
        backing.prepare_sync(true);
        backing.commit(true);
        assert!(backing.attach(true).is_none());
    }

    #[test]
    fn failed_write_retries_on_next_set_even_with_unchanged_value() {
        // Issue #621 review: a failed write_atomic must leave `dirty`
        // asserted, or a later set() carrying the *same* value would
        // early-return and the disk would stay stale forever.
        let dir = tempfile::tempdir().unwrap();
        // The store's parent path is a regular FILE — create_dir_all
        // fails, so every write_atomic errors deterministically.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("sel.json");
        let s = SelectorStore::open(path.clone());
        s.set("g", "node-a");
        assert!(!path.exists(), "write through a file-parent must fail");

        // Repair the parent path: the same-value set must still persist
        // because the failed write left the store dirty.
        std::fs::remove_file(&blocker).unwrap();
        s.set("g", "node-a");
        let on_disk: HashMap<String, String> =
            serde_json::from_slice(&std::fs::read(&path).unwrap())
                .expect("dirty flag must force a rewrite despite an unchanged value");
        assert_eq!(on_disk.get("g").map(String::as_str), Some("node-a"));
    }
}
