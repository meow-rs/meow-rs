//! Persistent backing for `SelectorGroup` choices.
//!
//! Upstream Go mihomo stores user-picked selector targets in a BoltDB
//! `cache.db` (`adapter/outboundgroup/selector.go` → `cachefile.Cache().SetSelected`).
//! We keep the same semantics with a simpler JSON file written through on
//! every successful `select()`, so the user's pick survives process restart.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::warn;

static GLOBAL_STORE: std::sync::OnceLock<Arc<SelectorStore>> = std::sync::OnceLock::new();

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
        let store = Arc::new(Self {
            path,
            map: Mutex::new(map),
            write_lock: Mutex::new(()),
            dirty: std::sync::atomic::AtomicBool::new(false),
        });
        let _ = GLOBAL_STORE.set(Arc::clone(&store));
        store
    }

    /// Process-wide store used by runtime config rebuilds so rebuilt groups
    /// retain the same persistence side-channel as startup-created groups.
    ///
    /// Returns `None` until the first call to [`Self::open`]. The first
    /// `open()` call wins the process-global slot; subsequent calls still
    /// return their own `Arc<Self>` but do **not** replace the global.
    /// Tests or library users that create multiple stores should be aware
    /// that only the first store is reachable via `global()`.
    pub fn global() -> Option<Arc<Self>> {
        GLOBAL_STORE.get().cloned()
    }

    pub fn get(&self, group: &str) -> Option<String> {
        self.map.lock().get(group).cloned()
    }

    /// Update the in-memory map and flush the whole file atomically. IO
    /// errors only warn — losing the persistence side-channel must never
    /// fail the user's selection.
    pub fn set(&self, group: &str, selected: &str) {
        use std::sync::atomic::Ordering::Relaxed;
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
        let _write = self.write_lock.lock();
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
