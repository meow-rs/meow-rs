//! `/storage/{key}` — a small JSON key-value store for dashboards.
//!
//! mihomo serves it from its `cache.db` (`hub/route/storage.go`); zashboard
//! syncs its settings through it after login and logs an error when the
//! route is missing. GET answers the stored JSON (`null` when unset), PUT
//! stores a body that must be valid JSON of at most 1 MB, DELETE removes it.
//! Keys are at most 64 bytes and the store keeps at most 16384 of them,
//! evicting an existing key for a new one past that — upstream's limits.
//!
//! Persisted as one JSON file in the home directory (`ui-storage.json`, a
//! map of key → JSON text) next to `selector-cache.json`, written through
//! atomically on every change — dashboards PUT only on a settings change.

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
const FILE_NAME: &str = "ui-storage.json";

pub struct UiStorage {
    path: PathBuf,
    map: Mutex<HashMap<String, String>>,
    /// Serializes the disk writes so the last rename carries the newest map.
    write_lock: Mutex<()>,
    /// The file is behind the map (a write failed): the next PUT or DELETE
    /// persists even when it changes nothing.
    dirty: AtomicBool,
}

/// Per-router slot for the store, filled on first use.
pub type UiStorageSlot = Arc<OnceLock<Arc<UiStorage>>>;

impl UiStorage {
    fn open(path: PathBuf) -> Self {
        let map = match std::fs::read(&path) {
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
        Self {
            path,
            map: Mutex::new(map),
            write_lock: Mutex::new(()),
            dirty: AtomicBool::new(false),
        }
    }

    fn get(&self, key: &str) -> Option<String> {
        self.map.lock().get(key).cloned()
    }

    /// `None` deletes. Returns whether the map changed.
    fn set(&self, key: &str, value: Option<String>) -> bool {
        let mut map = self.map.lock();
        match value {
            Some(v) if map.get(key) == Some(&v) => false,
            Some(v) => {
                if map.len() >= MAX_ENTRIES && !map.contains_key(key) {
                    if let Some(old) = map.keys().next().cloned() {
                        map.remove(&old);
                    }
                }
                map.insert(key.to_string(), v);
                true
            }
            None => map.remove(key).is_some(),
        }
    }

    fn persist(&self) {
        let _write = self.write_lock.lock();
        let snapshot = self.map.lock().clone();
        let failed = write_atomic(&self.path, &snapshot).is_err_and(|e| {
            warn!(path = %self.path.display(), error = %e, "ui storage: persist failed");
            true
        });
        self.dirty.store(failed, Ordering::Relaxed);
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
    // Upstream's order: key, JSON validity, then size.
    if key.len() > MAX_KEY {
        return msg_err(StatusCode::BAD_REQUEST, "key too long");
    }
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
        let _ = tokio::task::spawn_blocking(move || store.persist()).await;
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
    fn a_full_store_evicts_for_a_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let s = UiStorage::open(dir.path().join(FILE_NAME));
        for i in 0..MAX_ENTRIES {
            s.set(&i.to_string(), Some("1".into()));
        }
        assert!(s.set("0", Some("2".into())), "an existing key replaces");
        assert_eq!(s.map.lock().len(), MAX_ENTRIES);
        assert!(s.set("new", Some("1".into())));
        assert_eq!(s.map.lock().len(), MAX_ENTRIES);
        assert_eq!(s.get("new").as_deref(), Some("1"));
    }
}
