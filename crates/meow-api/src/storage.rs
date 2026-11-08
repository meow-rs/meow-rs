//! `/storage/{key}` — a small JSON key-value store for dashboards.
//!
//! mihomo serves it from its `cache.db` (`hub/route/storage.go`); zashboard
//! syncs its settings through it after login and logs an error when the
//! route is missing. GET answers the stored JSON (`null` when unset), PUT
//! stores a body that must be valid JSON of at most 1 MB, DELETE removes it.
//! A key past 64 bytes is silently accepted but never stored — upstream's
//! quirk: PUT still answers 204 and GET still returns `null`.
//! The store keeps at most 16384 keys and about 1 MiB of *values* in all,
//! evicting the least recently WRITTEN first — upstream's limits, with one
//! divergence: write order is only tracked in memory, so a restart
//! reshuffles eviction order arbitrarily (upstream's per-entry `Time`
//! survives in bbolt).
//!
//! Persisted as one JSON file in the home directory (`ui-storage.json`, a
//! map of key → JSON text) next to `selector-cache.json`. Writes coalesce:
//! a change marks the store dirty and one detached pass drains it, so a
//! burst of PUTs costs O(1) writes rather than a tmp+rename each.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use axum::body::Bytes;
use axum::extract::{Path as UrlPath, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use tracing::warn;

use crate::routes::{msg_err, AppState};

/// mihomo's per-value cap.
const MAX_VALUE: usize = 1 << 20;
/// mihomo's `storageKeySizeLimit`.
const MAX_KEY: usize = 64;
/// mihomo's `maxStorageEntries`.
const MAX_ENTRIES: usize = 16384;
/// The ~1 MiB aggregate budget upstream evicts under alongside the entry
/// cap — counted on value bytes only, as upstream's `usedSize` does.
const MAX_TOTAL_BYTES: usize = 1 << 20;
const FILE_NAME: &str = "ui-storage.json";

pub struct UiStorage {
    path: PathBuf,
    store: Mutex<Store>,
    /// Serializes the disk writes so the last rename carries the newest map.
    write_lock: Mutex<()>,
    /// The map is ahead of the file — a persist pass is owed. Left set
    /// when a write fails too, so the next PUT or DELETE persists even
    /// when it changes nothing.
    dirty: AtomicBool,
    /// A persist pass is running or queued on the blocking pool — rapid
    /// updates coalesce behind it instead of queueing one write each.
    persist_in_flight: AtomicBool,
}

#[derive(Default)]
struct Store {
    map: HashMap<String, Entry>,
    /// `value.len()` over the whole map — what the [`MAX_TOTAL_BYTES`]
    /// budget counts (upstream's `usedSize` ignores key bytes).
    total_bytes: usize,
    /// Last-write sequence: eviction order, oldest write first.
    seq: u64,
}

struct Entry {
    value: String,
    /// `Store::seq` at the last write — rewriting refreshes recency.
    seq: u64,
}

/// Per-router slot for the store, filled on first use.
pub type UiStorageSlot = Arc<OnceLock<Arc<UiStorage>>>;

impl UiStorage {
    fn open(path: PathBuf) -> Self {
        let map: HashMap<String, String> = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                warn!(path = %path.display(), error = %e, "ui storage: malformed, starting empty");
                HashMap::new()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "ui storage: read failed, starting empty");
                HashMap::new()
            }
        };
        let mut store = Store::default();
        for (key, value) in map {
            store.seq += 1;
            store.total_bytes += value.len();
            store.map.insert(
                key,
                Entry {
                    value,
                    seq: store.seq,
                },
            );
        }
        Self {
            path,
            store: Mutex::new(store),
            write_lock: Mutex::new(()),
            dirty: AtomicBool::new(false),
            persist_in_flight: AtomicBool::new(false),
        }
    }

    fn get(&self, key: &str) -> Option<String> {
        self.store.lock().map.get(key).map(|e| e.value.clone())
    }

    /// `None` deletes. Returns whether the map changed.
    fn set(&self, key: &str, value: Option<String>) -> bool {
        // Upstream's quirk: an overlong key is silently accepted — nothing
        // is stored, the answer is still 204.
        if key.len() > MAX_KEY {
            return false;
        }
        let mut store = self.store.lock();
        match value {
            Some(v) if store.map.get(key).is_some_and(|e| e.value == v) => {
                // No content change, but upstream stamps every write —
                // refreshing the seq keeps a just-rewritten key from
                // evicting as "oldest". Nothing to persist either way.
                store.seq += 1;
                let seq = store.seq;
                if let Some(e) = store.map.get_mut(key) {
                    e.seq = seq;
                }
                false
            }
            Some(v) => {
                let exists = store.map.contains_key(key);
                let old_len = store.map.get(key).map_or(0, |e| e.value.len());
                let new_len = v.len();
                // A new key must fit the entry cap; every write must fit
                // the byte budget — evict oldest-written entries (never
                // the key being written) until both hold.
                while (!exists && store.map.len() >= MAX_ENTRIES)
                    || store.total_bytes - old_len + new_len > MAX_TOTAL_BYTES
                {
                    let Some(oldest) = store
                        .map
                        .iter()
                        .filter(|(k, _)| k.as_str() != key)
                        .min_by_key(|(_, e)| e.seq)
                        .map(|(k, _)| k.clone())
                    else {
                        // Nothing left to evict — a lone oversized entry
                        // still lands (upstream's cap is approximate too).
                        break;
                    };
                    if let Some(evicted) = store.map.remove(&oldest) {
                        store.total_bytes -= evicted.value.len();
                    }
                }
                store.seq += 1;
                let seq = store.seq;
                if let Some(old) = store.map.insert(key.to_string(), Entry { value: v, seq }) {
                    store.total_bytes -= old.value.len();
                }
                store.total_bytes += new_len;
                true
            }
            None => match store.map.remove(key) {
                Some(old) => {
                    store.total_bytes -= old.value.len();
                    true
                }
                None => false,
            },
        }
    }

    /// One synchronous write of the current map. Returns whether it FAILED.
    fn write_now(&self) -> bool {
        let _write = self.write_lock.lock();
        let snapshot: HashMap<String, String> = self
            .store
            .lock()
            .map
            .iter()
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect();
        write_atomic(&self.path, &snapshot).is_err_and(|e| {
            warn!(path = %self.path.display(), error = %e, "ui storage: persist failed");
            true
        })
    }

    #[cfg(test)]
    fn persist(&self) {
        self.dirty.store(self.write_now(), Ordering::Relaxed);
    }

    /// Mark the store dirty and schedule the drain. A change that lands
    /// while a pass runs costs no extra write — the pass re-checks `dirty`
    /// before exiting, so a burst of PUTs persists O(1) times.
    fn request_persist(self: &Arc<Self>) {
        self.dirty.store(true, Ordering::Release);
        if self.persist_in_flight.swap(true, Ordering::AcqRel) {
            return;
        }
        let store = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            // A panicking pass must hand the flag back or the store
            // wedges: every later update would see "in flight" forever.
            // The normal exit paths handle the flag themselves — this is
            // only the panic path.
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.persist_run()))
                .is_err()
            {
                store.persist_in_flight.store(false, Ordering::Release);
            }
        });
    }

    /// The detached drain: write while dirty, then hand the flag back.
    fn persist_run(&self) {
        loop {
            while self.dirty.swap(false, Ordering::AcqRel) {
                if self.write_now() {
                    // The file stays behind the map — keep dirty set so
                    // the next update owes the retry (and a no-change one
                    // still writes), rather than spinning on a failing
                    // disk inside this task.
                    self.dirty.store(true, Ordering::Release);
                    self.persist_in_flight.store(false, Ordering::Release);
                    return;
                }
            }
            self.persist_in_flight.store(false, Ordering::Release);
            // A set() landing between the last `swap` and the flag clear
            // saw `in_flight` set and skipped its spawn — without this
            // recheck its change would wait unsaved for the next update.
            if !self.dirty.load(Ordering::Acquire)
                || self.persist_in_flight.swap(true, Ordering::AcqRel)
            {
                return;
            }
        }
    }
}

impl Drop for UiStorage {
    /// The drain is best-effort while requests flow; at teardown the last
    /// holder (the detached pass keeps an `Arc`) flushes whatever the map
    /// is still owed synchronously.
    fn drop(&mut self) {
        if self.dirty.load(Ordering::Relaxed) {
            self.write_now();
        }
    }
}

fn write_atomic(path: &Path, map: &HashMap<String, String>) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(map).map_err(std::io::Error::other)?;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let result = std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The router's store, opened on first use in the directory the selector
/// cache lives in.
fn storage(state: &AppState) -> Arc<UiStorage> {
    Arc::clone(state.ui_storage.get_or_init(|| {
        let dir = state.config_path.as_deref().map_or_else(
            meow_common::resolved_home_dir,
            meow_config::resource_cache_dir_for_config_path,
        );
        Arc::new(UiStorage::open(dir.join(FILE_NAME)))
    }))
}

fn json_response(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

pub(crate) async fn get_storage(
    State(state): State<Arc<AppState>>,
    UrlPath(key): UrlPath<String>,
) -> Response {
    json_response(storage(&state).get(&key).unwrap_or_else(|| "null".into()))
}

pub(crate) async fn set_storage(
    State(state): State<Arc<AppState>>,
    UrlPath(key): UrlPath<String>,
    body: Bytes,
) -> Response {
    // Upstream's order: JSON validity (400), then size (413), then the
    // overlong key — upstream drops those inside `SetStorage` after both
    // checks, so an overlong key still sees the 400/413 a short key would.
    if serde_json::from_slice::<serde::de::IgnoredAny>(&body).is_err() {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    }
    if body.len() > MAX_VALUE {
        return msg_err(StatusCode::PAYLOAD_TOO_LARGE, "payload exceeds 1MB limit");
    }
    let Ok(value) = String::from_utf8(body.to_vec()) else {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    };
    update(&state, &key, Some(value)).await
}

pub(crate) async fn delete_storage(
    State(state): State<Arc<AppState>>,
    UrlPath(key): UrlPath<String>,
) -> Response {
    update(&state, &key, None).await
}

async fn update(state: &AppState, key: &str, value: Option<String>) -> Response {
    let store = storage(state);
    if store.set(key, value) | store.dirty.load(Ordering::Relaxed) {
        store.request_persist();
    }
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_survive_reopen_and_delete_removes_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let s = UiStorage::open(path.clone());
        assert!(s.set("zashboard", Some(r#"{"a":1}"#.into())));
        assert!(!s.set("zashboard", Some(r#"{"a":1}"#.into())), "unchanged");
        s.persist();
        let s = UiStorage::open(path.clone());
        assert_eq!(s.get("zashboard").as_deref(), Some(r#"{"a":1}"#));
        assert!(s.set("zashboard", None));
        s.persist();
        assert_eq!(UiStorage::open(path).get("zashboard"), None);
    }

    #[test]
    fn overlong_keys_are_silently_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let s = UiStorage::open(dir.path().join(FILE_NAME));
        let long = "k".repeat(MAX_KEY + 1);
        assert!(!s.set(&long, Some("1".into())), "a no-op, not an error");
        assert!(!s.set(&long, None));
        assert_eq!(s.get(&long), None);
        let max = "k".repeat(MAX_KEY);
        assert!(s.set(&max, Some("1".into())));
        assert_eq!(s.get(&max).as_deref(), Some("1"));
    }

    #[test]
    fn a_full_store_evicts_oldest_written() {
        let dir = tempfile::tempdir().unwrap();
        let s = UiStorage::open(dir.path().join(FILE_NAME));
        for i in 0..MAX_ENTRIES {
            s.set(&i.to_string(), Some("1".into()));
        }
        assert!(s.set("0", Some("2".into())), "an existing key replaces");
        assert_eq!(s.store.lock().map.len(), MAX_ENTRIES);
        // Rewriting "0" made it the newest write — the new key evicts "1",
        // the oldest write now.
        assert!(s.set("new", Some("1".into())));
        assert_eq!(s.store.lock().map.len(), MAX_ENTRIES);
        assert_eq!(s.get("new").as_deref(), Some("1"));
        assert_eq!(s.get("0").as_deref(), Some("2"), "rewritten keys stay");
        assert_eq!(s.get("1"), None, "oldest write evicts first");
    }

    #[test]
    fn the_byte_budget_evicts_oldest_written_too() {
        let dir = tempfile::tempdir().unwrap();
        let s = UiStorage::open(dir.path().join(FILE_NAME));
        // 2/5 of the budget each: two entries fit, the third must evict.
        let val = "v".repeat(2 * MAX_TOTAL_BYTES / 5);
        s.set("a", Some(val.clone()));
        s.set("b", Some(val.clone()));
        s.set("c", Some(val));
        assert_eq!(s.get("a"), None, "a evicts for the byte budget");
        assert!(s.get("b").is_some() && s.get("c").is_some());
    }
}
