//! Fake-IP DNS mode: synthesise a stable IP per hostname so the tunnel can
//! match hostname-based rules against connections whose destination is just
//! an IP literal.
//!
//! Mirrors upstream Go mihomo (`component/fakeip/{pool,memory,cachefile,skipper}.go`)
//! with these concrete divergences:
//!
//! - Persistence backend is a JSON snapshot file (atomic write) instead of
//!   bbolt — meow-rs has no existing bolt dependency. The exposed
//!   semantics (per-family bucket, host↔ip bidirectional, cursor + cycle
//!   sentinel survive restart) are identical.
//! - `Skipper` uses our `DomainTrie` (which already supports `+.suffix`,
//!   `*.suffix`, exact match) rather than the upstream `DomainMatcher` slice.
//! - The full "rules-mode" skipper (`UseFakeIP` / `UseRealIP` action constants)
//!   is not implemented — the BlackList domain-trie path is what every real
//!   config uses. WhiteList mode is supported.
//!
//! Invariants preserved from upstream:
//! - `.0` (network), `.1` (gateway), `.2`, `.3` reserved; first allocatable
//!   is `network + 4`. Broadcast (`last`) is excluded.
//! - Effective pool capacity = `prefix_size − 4`.
//! - Sequential cursor wraps to `first` once it passes `last`, sets
//!   `cycle = true`, evicts the prior mapping at the cursor on every step
//!   after the first wrap.
//! - All public `Pool` operations are mutex-serialised.
//! - Host is lowercased before any cache or allocation work.

use meow_trie::DomainTrie;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

use ipnet::IpNet;
use lru::LruCache;

/// Bidirectional host↔ip store backing a [`Pool`].
pub trait Store: Send + Sync {
    fn get_by_host(&self, host: &str) -> Option<IpAddr>;
    fn get_by_ip(&self, ip: IpAddr) -> Option<SmolStr>;
    /// Insert the host↔ip mapping in both directions atomically. A single
    /// method (rather than separate `put_by_host`/`put_by_ip`) so no caller
    /// can leave the two directions inconsistent or — for persistent stores —
    /// depend on a fragile call ordering for the dirty-flag flush.
    fn put(&self, host: &str, ip: IpAddr);
    fn del_by_ip(&self, ip: IpAddr);
    fn exists(&self, ip: IpAddr) -> bool;
    fn flush(&self);
    /// Persistence sentinels — used by `Pool::store_state` /
    /// `Pool::restore_state` to survive process restart. No-op for the
    /// in-memory store.
    fn put_state(&self, _offset: IpAddr, _cycle: bool) {}
    fn get_state(&self) -> Option<(IpAddr, bool)> {
        None
    }
    /// True if this store persists across restarts.
    fn is_persistent(&self) -> bool {
        false
    }
    /// The backing file for a persistent store, `None` for in-memory.
    /// Config reload keys fake-IP pool reuse on this (together with the
    /// prefix): two stores answering `is_persistent` but bound to
    /// different files are NOT the same state — carrying one into a
    /// resolver configured for the other path would keep writing the old
    /// file and never load the new one.
    fn persistent_path(&self) -> Option<&Path> {
        None
    }
}

// ----------------------------------------------------------------------------
// MemoryStore
// ----------------------------------------------------------------------------

/// Two-LRU in-memory store. Identical Size for both directions so eviction
/// pressure is symmetric. Both LRUs live under ONE mutex: they are always
/// read and written together (the reverse side is touched on every forward
/// hit to keep recency in sync), so a single lock halves the acquisitions
/// per fake-IP query and makes the paired updates atomic.
pub struct MemoryStore {
    inner: Mutex<MemoryInner>,
}

struct MemoryInner {
    by_host: LruCache<SmolStr, IpAddr>,
    by_ip: LruCache<IpAddr, SmolStr>,
    /// Pool capacity, enforced manually in `put`. The LRUs are constructed
    /// unbounded because `LruCache::new(cap)` preallocates the full hash
    /// table up front — for the default /16 fake-ip range that is two
    /// ~65k-slot tables charged at startup even if no query ever arrives.
    cap: usize,
}

impl MemoryStore {
    pub fn new(size: usize) -> Self {
        Self {
            inner: Mutex::new(MemoryInner {
                by_host: LruCache::unbounded(),
                by_ip: LruCache::unbounded(),
                cap: size.max(1),
            }),
        }
    }
}

impl Store for MemoryStore {
    fn get_by_host(&self, host: &str) -> Option<IpAddr> {
        let mut inner = self.inner.lock();
        let ip = *inner.by_host.get(host)?;
        // Touch the reverse side so both LRUs stay synchronised.
        let _ = inner.by_ip.get(&ip);
        Some(ip)
    }
    fn get_by_ip(&self, ip: IpAddr) -> Option<SmolStr> {
        let mut inner = self.inner.lock();
        let host = inner.by_ip.get(&ip).cloned()?;
        let _ = inner.by_host.get(&host);
        Some(host)
    }
    fn put(&self, host: &str, ip: IpAddr) {
        let mut inner = self.inner.lock();
        inner.by_host.put(SmolStr::from(host), ip);
        inner.by_ip.put(ip, SmolStr::from(host));
        // Manual cap enforcement (LRUs are unbounded — see `MemoryInner::cap`).
        // Evict the LRU pair from both directions so the two maps stay
        // consistent — bounded LRUs would evict each side independently.
        if inner.by_ip.len() > inner.cap {
            if let Some((evicted_ip, evicted_host)) = inner.by_ip.pop_lru() {
                // Compare-and-delete: only drop the forward entry while it
                // still points at the just-evicted ip. Same hazard as
                // `del_by_ip` — if `evicted_host` was since remapped to a
                // different address, the stale `by_ip` entry we're evicting
                // here must not destroy that live forward mapping.
                if inner.by_host.peek(&evicted_host) == Some(&evicted_ip) {
                    inner.by_host.pop(&evicted_host);
                }
            }
        }
        if inner.by_host.len() > inner.cap {
            if let Some((evicted_host, evicted_ip)) = inner.by_host.pop_lru() {
                // Mirror image of the guard above, for the reverse direction.
                if inner.by_ip.peek(&evicted_ip) == Some(&evicted_host) {
                    inner.by_ip.pop(&evicted_ip);
                }
            }
        }
    }
    fn del_by_ip(&self, ip: IpAddr) {
        let mut inner = self.inner.lock();
        if let Some(host) = inner.by_ip.pop(&ip) {
            // Compare-and-delete: only drop the forward entry while it still
            // points at `ip`. A stale reverse entry (host since remapped to a
            // different address) must not destroy the host's live mapping.
            if inner.by_host.peek(&host) == Some(&ip) {
                inner.by_host.pop(&host);
            }
        }
    }
    fn exists(&self, ip: IpAddr) -> bool {
        self.inner.lock().by_ip.contains(&ip)
    }
    fn flush(&self) {
        let mut inner = self.inner.lock();
        inner.by_host.clear();
        inner.by_ip.clear();
    }
}

// ----------------------------------------------------------------------------
// FileStore — JSON snapshot persistence
// ----------------------------------------------------------------------------

#[derive(Default, Serialize, Deserialize)]
struct PersistedSnapshot {
    /// host → ip (canonical direction). Reverse is rebuilt on load.
    entries: HashMap<String, IpAddr>,
    /// Cursor sentinel: last-allocated IP (offset), and whether the pool has
    /// wrapped at least once.
    offset: Option<IpAddr>,
    cycle: bool,
}

/// JSON-backed persistent store. One file per address family — the caller
/// supplies the path (e.g. `<workdir>/fakeip-v4.json`).
///
/// Writes are atomic via `tmp + rename`. The in-memory copy is the source of
/// truth between flushes; mutations set a dirty flag and a background tokio
/// task batches the persist after a 1 s debounce so a burst of allocations
/// from a startup-storm hits the disk once. On `Drop` (process shutdown) we
/// do one final synchronous flush so SIGTERM during the debounce window
/// doesn't lose data.
pub struct FileStore {
    path: PathBuf,
    state: Arc<Mutex<PersistedSnapshot>>,
    /// In-memory reverse map rebuilt from `state.entries` at load time and
    /// kept in sync on mutation. Kept separate so `Store::get_by_ip` is O(1).
    reverse: Mutex<HashMap<IpAddr, SmolStr>>,
    dirty: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
    /// Handle to the background debounce-flush task, aborted on drop so the
    /// task (which parks forever on `notify.notified()` and holds `Arc` clones
    /// of `state`/`dirty`/`notify`) does not outlive the store.
    flush_task: Option<tokio::task::JoinHandle<()>>,
}

impl FileStore {
    /// Open (or create) the file. Corrupt JSON is treated as "empty" with a
    /// warn — we never refuse to start because of a bad snapshot.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let snapshot = load_snapshot(&path);
        Ok(Self::from_snapshot(path, snapshot))
    }

    /// Async opener for Tokio config-load paths. Snapshot read and JSON parse
    /// run on the blocking pool because this store keeps a sync API for tests
    /// and non-Tokio callers.
    pub async fn open_async(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let snapshot = tokio::task::spawn_blocking({
            let path = path.clone();
            move || load_snapshot(&path)
        })
        .await
        .map_err(|e| io::Error::other(format!("fakeip snapshot load task failed: {e}")))?;
        Ok(Self::from_snapshot(path, snapshot))
    }

    fn from_snapshot(path: PathBuf, snapshot: PersistedSnapshot) -> Self {
        let reverse = snapshot
            .entries
            .iter()
            .map(|(h, ip)| (*ip, SmolStr::from(h.as_str())))
            .collect();

        let state = Arc::new(Mutex::new(snapshot));
        let dirty = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(tokio::sync::Notify::new());

        let flush_task = Self::spawn_flush_task(
            path.clone(),
            Arc::clone(&state),
            Arc::clone(&dirty),
            Arc::clone(&notify),
        );

        Self {
            path,
            state,
            reverse: Mutex::new(reverse),
            dirty,
            notify,
            flush_task: Some(flush_task),
        }
    }

    fn spawn_flush_task(
        path: PathBuf,
        state: Arc<Mutex<PersistedSnapshot>>,
        dirty: Arc<AtomicBool>,
        notify: Arc<tokio::sync::Notify>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                notify.notified().await;
                // Debounce: wait for more mutations to settle.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                // Relaxed is enough for the flag: it is only a "something
                // changed" hint, and the `state` mutex acquired below
                // provides the actual ordering for the snapshot data.
                if dirty.swap(false, Ordering::Relaxed) {
                    let snap = {
                        let s = state.lock();
                        serialise(&s)
                    };
                    let path = path.clone();
                    if let Err(e) =
                        tokio::task::spawn_blocking(move || persist_to_file(&path, &snap)).await
                    {
                        warn!("fakeip: persist task failed: {}", e);
                    }
                }
            }
        })
    }

    fn mark_dirty(&self) {
        // Relaxed: the flag is only a hint; data ordering comes from the
        // `state` mutex (writers mutate under it before marking dirty, the
        // flush task locks it before serialising).
        self.dirty.store(true, Ordering::Relaxed);
        self.notify.notify_one();
    }
}

impl Drop for FileStore {
    fn drop(&mut self) {
        // Final synchronous flush so any pending dirty state lands on disk
        // before the process exits. The background task may have already
        // cleared `dirty` — in that case this is a no-op. We do not wake the
        // task because it may be inside its own sleep and there is no
        // guarantee the runtime is still pumping.
        if self.dirty.swap(false, Ordering::Relaxed) {
            let snap = serialise(&self.state.lock());
            persist_to_file(&self.path, &snap);
        }
        // Abort the background flush task. It parks forever on
        // `notify.notified()` (nothing signals it after the store drops) and
        // holds `Arc` clones of `state`/`dirty`/`notify`, so without this it
        // would leak a task plus the snapshot on every `FileStore` drop —
        // e.g. once per fake-ip config reload. The final flush above already
        // persisted any pending state. `abort()` cancels at the task's next
        // await point, so an in-progress synchronous `persist_to_file` is not
        // torn.
        if let Some(handle) = self.flush_task.take() {
            handle.abort();
        }
    }
}

fn load_snapshot(path: &Path) -> PersistedSnapshot {
    if !path.exists() {
        return PersistedSnapshot::default();
    }
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<PersistedSnapshot>(&bytes).unwrap_or_else(|e| {
            warn!(
                "fakeip: corrupt snapshot {} ({}); starting fresh",
                path.display(),
                e
            );
            PersistedSnapshot::default()
        }),
        Err(e) => {
            warn!(
                "fakeip: cannot read {} ({}); starting fresh",
                path.display(),
                e
            );
            PersistedSnapshot::default()
        }
    }
}

fn persist_to_file(path: &Path, snap: &PersistedSnapshot) {
    let tmp = path.with_extension("json.tmp");
    let result = (|| -> io::Result<()> {
        let bytes = serde_json::to_vec(snap).map_err(io::Error::other)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        warn!("fakeip: persist {} failed: {}", path.display(), e);
    }
}

impl Store for FileStore {
    fn get_by_host(&self, host: &str) -> Option<IpAddr> {
        self.state.lock().entries.get(host).copied()
    }
    fn get_by_ip(&self, ip: IpAddr) -> Option<SmolStr> {
        self.reverse.lock().get(&ip).cloned()
    }
    fn put(&self, host: &str, ip: IpAddr) {
        self.reverse.lock().insert(ip, SmolStr::from(host));
        let mut s = self.state.lock();
        s.entries.insert(host.to_string(), ip);
        drop(s);
        self.mark_dirty();
    }
    fn del_by_ip(&self, ip: IpAddr) {
        let host = self.reverse.lock().remove(&ip);
        if let Some(host) = host {
            let mut s = self.state.lock();
            // Compare-and-delete — see `MemoryStore::del_by_ip`. Only mark
            // dirty when `entries` (the persisted map) actually changes —
            // `reverse` is a non-persisted in-memory rebuild aid, so a stale
            // hit there must not trigger a debounced rewrite of an
            // unchanged snapshot.
            let removed = if s.entries.get(host.as_str()) == Some(&ip) {
                s.entries.remove(host.as_str());
                true
            } else {
                false
            };
            drop(s);
            if removed {
                self.mark_dirty();
            }
        }
    }
    fn exists(&self, ip: IpAddr) -> bool {
        self.reverse.lock().contains_key(&ip)
    }
    fn flush(&self) {
        self.reverse.lock().clear();
        let mut s = self.state.lock();
        s.entries.clear();
        s.offset = None;
        s.cycle = false;
        drop(s);
        self.mark_dirty();
    }
    fn put_state(&self, offset: IpAddr, cycle: bool) {
        let mut s = self.state.lock();
        s.offset = Some(offset);
        s.cycle = cycle;
        drop(s);
        self.mark_dirty();
    }
    fn get_state(&self) -> Option<(IpAddr, bool)> {
        let s = self.state.lock();
        s.offset.map(|o| (o, s.cycle))
    }
    fn is_persistent(&self) -> bool {
        true
    }
    fn persistent_path(&self) -> Option<&Path> {
        Some(&self.path)
    }
}

fn serialise(s: &PersistedSnapshot) -> PersistedSnapshot {
    PersistedSnapshot {
        entries: s.entries.clone(),
        offset: s.offset,
        cycle: s.cycle,
    }
}

// ----------------------------------------------------------------------------
// Pool — IP allocator
// ----------------------------------------------------------------------------

/// IPv4 / IPv6 fake-IP allocator. One per address family.
pub struct Pool {
    /// Network containing the pool (e.g. `198.18.0.0/16`).
    ipnet: IpNet,
    /// network + 1 — excluded from allocation, exposed as gateway.
    gateway: IpAddr,
    /// First allocatable: network + 4.
    first: IpAddr,
    /// Last address in the prefix (broadcast for v4) — excluded.
    last: IpAddr,
    inner: Mutex<PoolInner>,
    store: Arc<dyn Store>,
}

struct PoolInner {
    /// Last-allocated IP. The next allocation is `next_addr(offset)`.
    /// Initialised to `first.prev()` so the first allocation lands on `first`.
    offset: IpAddr,
    /// True once the cursor has wrapped past `last` at least once.
    /// While `cycle == true`, every allocation evicts the prior mapping at
    /// the cursor (LRU-style oldest-first eviction).
    cycle: bool,
}

impl Pool {
    /// Build a new pool over `prefix`. `store` is either a [`MemoryStore`] or
    /// a [`FileStore`]; the pool only sees the [`Store`] trait.
    pub fn new(prefix: IpNet, store: Arc<dyn Store>) -> Result<Self, PoolError> {
        let (gateway, first, last) = anchor_addrs(&prefix)?;

        // Initial offset = first.prev() so the first call to `get` produces `first`.
        let mut initial_offset = prev_addr(first);
        let mut initial_cycle = false;
        if let Some((stored_offset, stored_cycle)) = store.get_state() {
            // Validate the persisted offset lies within the range.
            if contained_in_range(stored_offset, first, last) {
                initial_offset = stored_offset;
                initial_cycle = stored_cycle;
            } else {
                warn!(
                    "fakeip: persisted offset {} outside range; resetting",
                    stored_offset
                );
            }
        }

        Ok(Self {
            ipnet: prefix,
            gateway,
            first,
            last,
            inner: Mutex::new(PoolInner {
                offset: initial_offset,
                cycle: initial_cycle,
            }),
            store,
        })
    }

    /// Lookup or allocate a fake IP for `host`. Lowercases the host before
    /// any work — callers may pass mixed-case.
    pub fn lookup(&self, host: &str) -> IpAddr {
        let host = host.to_ascii_lowercase();
        // Hold the pool mutex across BOTH the store read and the allocation
        // (mirrors upstream Go mihomo, whose `Pool.Lookup` holds `p.mux`
        // across the store read and `p.get()`). A check-then-act gap here
        // lets two concurrent lookups for the same unmapped host both miss
        // and both allocate — burning two pool addresses and, once the
        // cursor later wraps onto the orphaned first address, destroying
        // the host's live forward mapping via `del_by_ip` (issue #434).
        let mut inner = self.inner.lock();
        if let Some(existing) = self.store.get_by_host(&host) {
            return existing;
        }
        self.allocate(&mut inner, &host)
    }

    /// Reverse lookup: host that `ip` was allocated to, if any. Excludes
    /// the gateway and broadcast addresses — they are not real allocations.
    pub fn look_back(&self, ip: IpAddr) -> Option<SmolStr> {
        if ip == self.gateway || ip == self.last {
            return None;
        }
        self.store.get_by_ip(ip)
    }

    /// True if `ip` is within the pool range AND has an active allocation
    /// (matches upstream `IsFakeIP`). Gateway and broadcast are excluded.
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        if !self.ipnet.contains(&ip) {
            return false;
        }
        if ip == self.gateway || ip == self.last {
            return false;
        }
        self.store.exists(ip)
    }

    /// True if `ip` lies within the pool prefix (looser than `is_fake_ip`).
    pub fn in_range(&self, ip: IpAddr) -> bool {
        self.ipnet.contains(&ip)
    }

    pub fn gateway(&self) -> IpAddr {
        self.gateway
    }
    pub fn broadcast(&self) -> IpAddr {
        self.last
    }
    pub fn ipnet(&self) -> IpNet {
        self.ipnet
    }

    /// Whether the backing store persists across restarts (`FileStore`)
    /// or is memory-only (`MemoryStore`). Pool reuse on config reload is
    /// keyed on the stronger [`Pool::store_path`] identity — a pool must
    /// not be carried into a resolver generation whose `store-fake-ip`
    /// flag flipped or whose persistent backing file moved.
    pub fn is_persistent(&self) -> bool {
        self.store.is_persistent()
    }

    /// The backing file of a persistent pool, `None` for an in-memory
    /// one. Stronger than [`Pool::is_persistent`] for reuse decisions:
    /// two persistent pools on *different* files hold different state.
    pub fn store_path(&self) -> Option<&Path> {
        self.store.persistent_path()
    }

    /// Clear every allocation. Subsequent `lookup` calls start fresh from `first`.
    pub fn flush(&self) {
        self.store.flush();
        let mut inner = self.inner.lock();
        inner.offset = prev_addr(self.first);
        inner.cycle = false;
        if self.store.is_persistent() {
            self.store.put_state(inner.offset, inner.cycle);
        }
    }

    /// Allocate the next cursor address for `host`. The caller must hold the
    /// pool mutex (`self.inner`) and pass the guard's contents in — taking
    /// the lock here, after `lookup`'s store read released it, is exactly
    /// the race window of issue #434.
    fn allocate(&self, inner: &mut PoolInner, host: &str) -> IpAddr {
        // Advance cursor.
        let mut candidate = next_addr(inner.offset);
        if !addr_less(candidate, self.last) {
            // Wrapped past the broadcast — reset and mark cycle.
            inner.cycle = true;
            candidate = self.first;
        }
        if inner.cycle || self.store.exists(candidate) {
            // Evict the prior mapping at the cursor (LRU-style oldest-first).
            self.store.del_by_ip(candidate);
        }
        self.store.put(host, candidate);
        inner.offset = candidate;
        if self.store.is_persistent() {
            self.store.put_state(inner.offset, inner.cycle);
        }
        debug!("fakeip: allocated {} → {}", host, candidate);
        candidate
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PoolError {
    #[error("fakeip prefix '{prefix}' is too small: at least 4 host addresses required")]
    PrefixTooSmall { prefix: IpNet },
    #[error("fakeip prefix '{prefix}' could not derive anchor addresses")]
    InvalidPrefix { prefix: IpNet },
}

// ----------------------------------------------------------------------------
// Address arithmetic helpers
// ----------------------------------------------------------------------------

/// Returns (gateway, first allocatable, last/broadcast).
fn anchor_addrs(prefix: &IpNet) -> Result<(IpAddr, IpAddr, IpAddr), PoolError> {
    let network = prefix.network();
    let last = prefix.broadcast();
    let gateway = next_addr(network);
    // first allocatable = network + 4
    let first = next_addr(next_addr(next_addr(gateway)));
    if !addr_less(first, last) {
        return Err(PoolError::PrefixTooSmall { prefix: *prefix });
    }
    if (matches!(network, IpAddr::V4(_)) != matches!(last, IpAddr::V4(_)))
        || (matches!(network, IpAddr::V4(_)) != matches!(gateway, IpAddr::V4(_)))
        || (matches!(network, IpAddr::V4(_)) != matches!(first, IpAddr::V4(_)))
    {
        return Err(PoolError::InvalidPrefix { prefix: *prefix });
    }
    Ok((gateway, first, last))
}

fn next_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let n: u32 = v4.into();
            IpAddr::V4(Ipv4Addr::from(n.wrapping_add(1)))
        }
        IpAddr::V6(v6) => {
            let n: u128 = v6.into();
            IpAddr::V6(Ipv6Addr::from(n.wrapping_add(1)))
        }
    }
}

fn prev_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let n: u32 = v4.into();
            IpAddr::V4(Ipv4Addr::from(n.wrapping_sub(1)))
        }
        IpAddr::V6(v6) => {
            let n: u128 = v6.into();
            IpAddr::V6(Ipv6Addr::from(n.wrapping_sub(1)))
        }
    }
}

fn addr_less(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u32::from(a) < u32::from(b),
        (IpAddr::V6(a), IpAddr::V6(b)) => u128::from(a) < u128::from(b),
        _ => false,
    }
}

fn contained_in_range(ip: IpAddr, first: IpAddr, last: IpAddr) -> bool {
    !addr_less(ip, first) && addr_less(ip, last)
}

// ----------------------------------------------------------------------------
// Skipper — fake-ip-filter / fake-ip-filter-mode
// ----------------------------------------------------------------------------

/// Filter mode: BlackList (default) bypasses fake-ip when the host matches;
/// WhiteList bypasses when it does NOT match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SkipperMode {
    #[default]
    BlackList,
    WhiteList,
}

/// Decides whether a hostname should bypass fake-IP synthesis and resolve
/// normally instead.
pub struct Skipper {
    trie: DomainTrie<()>,
    mode: SkipperMode,
    /// True if no patterns were configured. WhiteList with an empty trie is
    /// a foot-gun (would bypass everything) — we treat empty WhiteList as
    /// "skip nothing" and emit a warn at construction time.
    empty: bool,
}

impl Skipper {
    pub fn new(patterns: &[String], mode: SkipperMode) -> Self {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        let mut inserted = 0usize;
        for raw in patterns {
            let pat = raw.trim();
            if pat.is_empty() {
                continue;
            }
            // Plain entries are treated as suffix-match per upstream
            // (`fake-ip-filter: ["example.com"]` should skip *.example.com).
            // If the user explicitly prefixed with `+.` or `*.` or `.`,
            // pass through unchanged.
            // Plain / `+.` entries match the root domain too — this matches
            // upstream `fake-ip-filter` semantics where `example.com` skips
            // both `example.com` and `*.example.com`. `DomainTrie`'s `+.`
            // wildcard alone does NOT include the root (see
            // `NameserverPolicy::insert_wildcard`), so we insert the bare
            // domain explicitly in those cases.
            let (suffix_pattern, also_insert_bare): (String, Option<&str>) =
                if let Some(rest) = pat.strip_prefix("+.") {
                    (pat.to_string(), Some(rest))
                } else if pat.starts_with("*.") || pat.starts_with('.') {
                    (pat.to_string(), None)
                } else {
                    (format!("+.{pat}"), Some(pat))
                };
            let mut ok = trie.insert(&suffix_pattern, ());
            if let Some(bare) = also_insert_bare {
                ok = trie.insert(bare, ()) || ok;
            }
            if ok {
                inserted += 1;
            } else {
                warn!("fakeip: skipper ignoring unparsable pattern '{}'", raw);
            }
        }
        let empty = inserted == 0;
        if empty && mode == SkipperMode::WhiteList {
            warn!(
                "fakeip: fake-ip-filter-mode=whitelist with empty filter bypasses ALL hosts; \
                 treating as 'skip nothing' instead"
            );
        }
        Self { trie, mode, empty }
    }

    /// True if `host` should bypass fake-IP and go to a real resolver.
    pub fn should_skip(&self, host: &str) -> bool {
        if self.empty {
            // Empty filter ⇒ never skip (BlackList semantics by default).
            return false;
        }
        let matched = self.trie.search(host).is_some();
        match self.mode {
            SkipperMode::BlackList => matched,
            SkipperMode::WhiteList => !matched,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn make_pool_v4() -> Pool {
        let net = IpNet::from_str("198.18.0.0/16").unwrap();
        Pool::new(net, Arc::new(MemoryStore::new(1024))).unwrap()
    }

    #[test]
    fn memory_store_caps_at_size_with_paired_eviction() {
        let s = MemoryStore::new(4);
        for i in 0..10u8 {
            let key = format!("h{i}.example");
            s.put(&key, IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)));
        }
        // Oldest entries evicted from BOTH directions...
        assert!(s.get_by_host("h0.example").is_none());
        assert!(s
            .get_by_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)))
            .is_none());
        // ...newest present in both.
        assert_eq!(
            s.get_by_host("h9.example"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)))
        );
        assert_eq!(
            s.get_by_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)))
                .as_deref(),
            Some("h9.example")
        );
    }

    #[test]
    fn anchors_v4() {
        let net = IpNet::from_str("198.18.0.0/16").unwrap();
        let (gw, first, last) = anchor_addrs(&net).unwrap();
        assert_eq!(gw, IpAddr::from_str("198.18.0.1").unwrap());
        assert_eq!(first, IpAddr::from_str("198.18.0.4").unwrap());
        assert_eq!(last, IpAddr::from_str("198.18.255.255").unwrap());
    }

    #[test]
    fn anchors_v6() {
        let net = IpNet::from_str("fc00::/64").unwrap();
        let (gw, first, _last) = anchor_addrs(&net).unwrap();
        assert_eq!(gw, IpAddr::from_str("fc00::1").unwrap());
        assert_eq!(first, IpAddr::from_str("fc00::4").unwrap());
    }

    #[test]
    fn anchors_too_small() {
        // /30 has 4 addresses total (0,1,2,3): first would be .4, past broadcast.
        let net = IpNet::from_str("192.0.2.0/30").unwrap();
        assert!(matches!(
            anchor_addrs(&net),
            Err(PoolError::PrefixTooSmall { .. })
        ));
    }

    #[test]
    fn allocate_first_is_first_addr() {
        let pool = make_pool_v4();
        let ip = pool.lookup("example.com");
        assert_eq!(ip, IpAddr::from_str("198.18.0.4").unwrap());
    }

    #[test]
    fn allocate_distinct_hosts_distinct_ips() {
        let pool = make_pool_v4();
        let a = pool.lookup("example.com");
        let b = pool.lookup("other.test");
        assert_ne!(a, b);
        assert_eq!(b, IpAddr::from_str("198.18.0.5").unwrap());
    }

    #[test]
    fn allocate_idempotent_per_host() {
        let pool = make_pool_v4();
        let a = pool.lookup("Example.COM");
        let b = pool.lookup("example.com");
        assert_eq!(a, b, "lookup must lowercase before keying");
    }

    #[test]
    fn concurrent_lookup_same_host_allocates_once() {
        // Issue #434: two workers racing on the same unmapped host must not
        // both allocate. With the store read and the allocation serialised
        // under the pool mutex, every thread gets the same IP and exactly
        // one pool address is consumed.
        let pool = Arc::new(make_pool_v4());
        #[allow(
            clippy::needless_collect,
            reason = "the intermediate Vec is load-bearing: all threads must be \
                      spawned before any is joined, or the lookups run serially"
        )]
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || pool.lookup("x.example"))
            })
            .collect();
        let ips: Vec<IpAddr> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(
            ips.iter().all(|ip| *ip == ips[0]),
            "all concurrent lookups must return one IP, got {ips:?}"
        );
        assert_eq!(ips[0], IpAddr::from_str("198.18.0.4").unwrap());
        // Cursor advanced by exactly one: the next host gets the next slot,
        // proving no orphaned second allocation was burned.
        assert_eq!(
            pool.lookup("y.example"),
            IpAddr::from_str("198.18.0.5").unwrap()
        );
    }

    #[test]
    fn memory_store_del_by_ip_spares_remapped_host() {
        let s = MemoryStore::new(16);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        s.put("h.example", ip1);
        s.put("h.example", ip2); // ip1's reverse entry is now stale
        s.del_by_ip(ip1);
        assert!(s.get_by_ip(ip1).is_none(), "stale reverse entry removed");
        assert_eq!(
            s.get_by_host("h.example"),
            Some(ip2),
            "evicting a stale reverse entry must not delete the live forward mapping"
        );
        // Deleting the live pair still removes both directions.
        s.del_by_ip(ip2);
        assert!(s.get_by_host("h.example").is_none());
        assert!(s.get_by_ip(ip2).is_none());
    }

    #[test]
    fn memory_store_cap_eviction_spares_remapped_host() {
        // Same hazard as `memory_store_del_by_ip_spares_remapped_host`, but
        // triggered via the cap-eviction path in `put` rather than an
        // explicit `del_by_ip` call. cap=2: put "a"->ip1, "b"->ip2, then
        // re-put "a"->ip3. by_ip now holds 3 entries (ip1, ip2, ip3) with
        // ip1 the LRU (untouched since step 1), so the cap check evicts
        // ip1 from by_ip. Without the compare-and-delete guard this would
        // unconditionally pop by_host["a"] too — destroying the live
        // "a" -> ip3 mapping just written.
        let s = MemoryStore::new(2);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        s.put("a", ip1);
        s.put("b", ip2);
        s.put("a", ip3); // ip1's reverse entry is now stale, cap exceeded on by_ip
        assert!(s.get_by_ip(ip1).is_none(), "stale by_ip entry evicted");
        assert_eq!(
            s.get_by_host("a"),
            Some(ip3),
            "cap eviction of a stale by_ip entry must not delete the live forward mapping"
        );
        assert_eq!(s.get_by_ip(ip3).as_deref(), Some("a"));
        assert_eq!(s.get_by_host("b"), Some(ip2));
        assert_eq!(s.get_by_ip(ip2).as_deref(), Some("b"));
    }

    #[tokio::test]
    async fn file_store_del_by_ip_stale_does_not_mark_dirty() {
        // Companion to `file_store_del_by_ip_spares_remapped_host`: a
        // compare-and-delete that finds the reverse entry stale (host since
        // remapped) must leave the persisted `entries` map untouched, so it
        // must not schedule a debounced rewrite of an identical snapshot.
        let tmp = tempdir();
        let path = tmp.join("fakeip-del-dirty.json");
        let s = FileStore::open(&path).unwrap();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        s.put("h.example", ip1);
        s.put("h.example", ip2); // ip1's reverse entry is now stale
                                 // Isolate the del_by_ip call from the dirty flag set by the puts above.
        s.dirty.store(false, Ordering::Relaxed);
        s.del_by_ip(ip1); // stale — compare-and-delete must no-op
        assert!(
            !s.dirty.load(Ordering::Relaxed),
            "a no-op compare-and-delete must not mark the store dirty"
        );
        assert_eq!(s.get_by_host("h.example"), Some(ip2));
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn file_store_del_by_ip_spares_remapped_host() {
        let tmp = tempdir();
        let path = tmp.join("fakeip-del.json");
        let s = FileStore::open(&path).unwrap();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        s.put("h.example", ip1);
        s.put("h.example", ip2);
        s.del_by_ip(ip1);
        assert!(s.get_by_ip(ip1).is_none());
        assert_eq!(s.get_by_host("h.example"), Some(ip2));
        s.del_by_ip(ip2);
        assert!(s.get_by_host("h.example").is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn look_back_recovers_host() {
        let pool = make_pool_v4();
        let ip = pool.lookup("example.com");
        assert_eq!(pool.look_back(ip).as_deref(), Some("example.com"));
    }

    #[test]
    fn look_back_excludes_gateway_and_broadcast() {
        let pool = make_pool_v4();
        assert!(pool.look_back(pool.gateway()).is_none());
        assert!(pool.look_back(pool.broadcast()).is_none());
    }

    #[test]
    fn is_fake_ip_excludes_out_of_range() {
        let pool = make_pool_v4();
        let ip = pool.lookup("example.com");
        assert!(pool.is_fake_ip(ip));
        assert!(!pool.is_fake_ip(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(!pool.is_fake_ip(pool.gateway()));
    }

    #[test]
    fn flush_resets_cursor() {
        let pool = make_pool_v4();
        let _ = pool.lookup("a");
        let _ = pool.lookup("b");
        pool.flush();
        let ip = pool.lookup("c");
        assert_eq!(ip, IpAddr::from_str("198.18.0.4").unwrap());
    }

    #[test]
    fn cycle_wrap_evicts_oldest() {
        // Use a small /28 prefix: 16 addrs, first=.4, last=.15 ⇒ 11 slots (.4..=.14).
        let net = IpNet::from_str("10.0.0.0/28").unwrap();
        let pool = Pool::new(net, Arc::new(MemoryStore::new(64))).unwrap();
        let first_host = "first.test";
        let first_ip = pool.lookup(first_host);
        // Fill the pool until we wrap. Slots = first..last (exclusive) = .4..=.14 = 11 slots.
        for i in 0..11 {
            let _ = pool.lookup(&format!("h{i}"));
        }
        // After wrap, first_ip should have been re-issued to a later host (h7 or so).
        assert!(
            pool.look_back(first_ip).as_deref() != Some(first_host),
            "after wrap, original first_host mapping must be evicted"
        );
    }

    /// Table-driven merge of the former `skipper_blacklist_skips_matched`,
    /// `skipper_whitelist_skips_unmatched`, `skipper_plain_entry_is_suffix`
    /// and `skipper_empty_filter_never_skips` cases. Every row is evaluated
    /// even if an earlier one fails; all failures are reported together with
    /// their case label.
    #[test]
    fn skipper_table_driven_cases() {
        struct Case {
            label: &'static str,
            patterns: &'static [&'static str],
            mode: SkipperMode,
            host: &'static str,
            expect_skip: bool,
        }

        let cases = [
            // BlackList: a `+.` pattern matches sub-domains AND the bare root.
            Case {
                label: "blacklist/+.local/sub",
                patterns: &["+.local"],
                mode: SkipperMode::BlackList,
                host: "foo.local",
                expect_skip: true,
            },
            Case {
                label: "blacklist/+.local/root",
                patterns: &["+.local"],
                mode: SkipperMode::BlackList,
                host: "local",
                expect_skip: true,
            },
            Case {
                label: "blacklist/+.local/unrelated",
                patterns: &["+.local"],
                mode: SkipperMode::BlackList,
                host: "example.com",
                expect_skip: false,
            },
            // WhiteList inverts: matched hosts keep fake-ip, others bypass.
            Case {
                label: "whitelist/+.example.com/matched",
                patterns: &["+.example.com"],
                mode: SkipperMode::WhiteList,
                host: "foo.example.com",
                expect_skip: false,
            },
            Case {
                label: "whitelist/+.example.com/unmatched",
                patterns: &["+.example.com"],
                mode: SkipperMode::WhiteList,
                host: "other.test",
                expect_skip: true,
            },
            // A plain entry is a suffix match that also covers the root, and
            // must respect label boundaries (not a raw substring match).
            Case {
                label: "blacklist/plain/sub",
                patterns: &["example.com"],
                mode: SkipperMode::BlackList,
                host: "foo.example.com",
                expect_skip: true,
            },
            Case {
                label: "blacklist/plain/root",
                patterns: &["example.com"],
                mode: SkipperMode::BlackList,
                host: "example.com",
                expect_skip: true,
            },
            Case {
                label: "blacklist/plain/label-boundary",
                patterns: &["example.com"],
                mode: SkipperMode::BlackList,
                host: "notexample.com",
                expect_skip: false,
            },
            // Empty filter never skips — including WhiteList, where the naive
            // reading would bypass every host (defensive foot-gun guard).
            Case {
                label: "empty/blacklist",
                patterns: &[],
                mode: SkipperMode::BlackList,
                host: "foo.test",
                expect_skip: false,
            },
            Case {
                label: "empty/whitelist-defensive",
                patterns: &[],
                mode: SkipperMode::WhiteList,
                host: "foo.test",
                expect_skip: false,
            },
        ];

        let mut failures = Vec::new();
        for c in &cases {
            let patterns: Vec<String> = c.patterns.iter().copied().map(String::from).collect();
            let skipper = Skipper::new(&patterns, c.mode);
            let got = skipper.should_skip(c.host);
            if got != c.expect_skip {
                failures.push(format!(
                    "[{}] Skipper::new({:?}, {:?}).should_skip({:?}) = {got}, want {}",
                    c.label, c.patterns, c.mode, c.host, c.expect_skip
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "skipper cases failed:\n{}",
            failures.join("\n")
        );
    }

    #[tokio::test]
    async fn file_store_roundtrip() {
        let tmp = tempdir();
        let path = tmp.join("fakeip-v4.json");
        let net = IpNet::from_str("198.18.0.0/16").unwrap();
        let ip;
        {
            let store = Arc::new(FileStore::open(&path).unwrap());
            let pool = Pool::new(net, store).unwrap();
            ip = pool.lookup("example.com");
            // Wait for the debounced background persistence to complete.
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        }
        // Re-open; mapping must survive.
        {
            let store = Arc::new(FileStore::open(&path).unwrap());
            let pool = Pool::new(net, store).unwrap();
            // Same host returns same IP — no new allocation.
            let again = pool.lookup("example.com");
            assert_eq!(again, ip, "persistence must preserve host→ip mapping");
            // Reverse lookup also works.
            assert_eq!(pool.look_back(ip).as_deref(), Some("example.com"));
            // Cursor survived: next host gets the NEXT slot, not .4 again.
            let other = pool.lookup("other.test");
            assert_ne!(other, ip);
            assert_eq!(other, IpAddr::from_str("198.18.0.5").unwrap());
        }
        let _ = fs::remove_file(&path);
    }

    fn tempdir() -> PathBuf {
        let mut d = std::env::temp_dir();
        let nonce = format!(
            "meow-fakeip-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        );
        d.push(nonce);
        fs::create_dir_all(&d).unwrap();
        d
    }
}
