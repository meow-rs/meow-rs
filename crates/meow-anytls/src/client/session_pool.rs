//! Exclusive checkout-and-return session pool (issue #1015).

use crate::session::Session;
use meow_common::atomic::Uint;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, interval};
use tracing::{field, info_span};

/// Configuration for session pool
#[derive(Debug, Clone)]
pub struct SessionPoolConfig {
    /// Interval for checking idle sessions (default: 30s)
    pub check_interval: Duration,

    /// Idle timeout for sessions (default: 60s)
    pub idle_timeout: Duration,

    /// Minimum number of idle sessions to keep (default: 1)
    pub min_idle_sessions: usize,
}

impl Default for SessionPoolConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            min_idle_sessions: 1,
        }
    }
}

enum LiveState {
    Idle,
    CheckedOut(u64),
}

struct LiveEntry {
    session: Arc<Session>,
    seq: u64,
    idle_since: Instant,
    generation: Uint,
    state: LiveState,
}

struct PoolState {
    generation: Uint,
    /// All managed sessions keyed by [`Session::id`].
    live: HashMap<u64, LiveEntry>,
    /// Idle sessions only, ordered by return seq (newest last).
    idle: BTreeMap<u64, u64>,
    next_seq: u64,
    next_checkout: u64,
}

pub(crate) struct PoolInner {
    state: Mutex<PoolState>,
    config: SessionPoolConfig,
}

/// Identity of one exclusive checkout.
#[derive(Clone)]
pub struct Checkout {
    pub session: Arc<Session>,
    generation: Uint,
    session_id: u64,
    checkout_id: u64,
}

impl Checkout {
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn checkout_id(&self) -> u64 {
        self.checkout_id
    }
}

/// Shared checkout identity used by the open-window guard and owner-end
/// callback. Completing return or discard is a no-op for late duplicates.
pub(crate) struct CheckoutState {
    pool: Weak<PoolInner>,
    generation: Uint,
    session_id: u64,
    checkout_id: u64,
    session: Arc<Session>,
    completed: AtomicBool,
    done: Notify,
}

impl CheckoutState {
    pub(crate) fn from_checkout(pool: Weak<PoolInner>, checkout: Checkout) -> Arc<Self> {
        Arc::new(Self {
            pool,
            generation: checkout.generation,
            session_id: checkout.session_id,
            checkout_id: checkout.checkout_id,
            session: checkout.session,
            completed: AtomicBool::new(false),
            done: Notify::new(),
        })
    }

    pub(crate) fn session(&self) -> &Arc<Session> {
        &self.session
    }

    pub(crate) fn done(&self) -> &Notify {
        &self.done
    }

    pub(crate) fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    pub(crate) fn checkout_is_current(&self) -> bool {
        self.pool.upgrade().is_some_and(|pool| {
            pool.checkout_is_current(self.generation, self.session_id, self.checkout_id)
        })
    }

    pub(crate) fn finish_return(&self) {
        if self.completed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(pool) = self.pool.upgrade() {
            pool.return_checkout(
                self.generation,
                self.session_id,
                self.checkout_id,
                &self.session,
            );
        }
        self.done.notify_waiters();
    }

    pub(crate) fn finish_discard(&self) {
        if self.completed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(pool) = self.pool.upgrade() {
            pool.discard_checkout(self.generation, self.session_id, self.checkout_id);
        } else {
            spawn_close(Arc::clone(&self.session));
        }
        self.done.notify_waiters();
    }
}

/// SessionPool manages exclusive session checkouts with automatic idle cleanup.
pub struct SessionPool {
    inner: Arc<PoolInner>,
    cleanup_task: Mutex<Option<JoinHandle<()>>>,
}

impl Default for SessionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionPool {
    /// Create a new session pool with default configuration
    pub fn new() -> Self {
        Self::with_config(SessionPoolConfig::default())
    }

    /// Create a new session pool with custom configuration
    pub fn with_config(config: SessionPoolConfig) -> Self {
        let inner = Arc::new(PoolInner {
            state: Mutex::new(PoolState {
                generation: 0,
                live: HashMap::new(),
                idle: BTreeMap::new(),
                next_seq: 1,
                next_checkout: 1,
            }),
            config,
        });
        let pool = Self {
            inner,
            cleanup_task: Mutex::new(None),
        };
        pool.start_cleanup_task();
        pool
    }

    pub(crate) fn inner(&self) -> &Arc<PoolInner> {
        &self.inner
    }

    /// Get the next sequence number
    pub fn next_seq(&self) -> u64 {
        let mut state = self.inner.state.lock().unwrap();
        let seq = state.next_seq;
        state.next_seq = state.next_seq.wrapping_add(1);
        seq
    }

    /// Current pool generation. Capture it as a dial ticket when checkout
    /// misses; a session whose dial straddles a [`reset`](Self::reset) is
    /// never registered.
    pub fn generation(&self) -> Uint {
        self.inner.state.lock().unwrap().generation
    }

    /// Close every managed session — idle and in-use — so the next stream
    /// dials a fresh connection. Called when the host's outbound-interface
    /// binding changes (meow-rs issue #695).
    ///
    /// Linearization is the generation bump plus live drain under the pool
    /// lock. Close itself runs outside the lock.
    pub fn reset(&self) {
        let stale = self.inner.take_all(true);
        tracing::debug!("[SessionPool] Reset: closing {} sessions", stale.len());
        for session in stale {
            spawn_close(session);
        }
    }

    /// Take the newest idle session and mark it `CheckedOut`. `Err(generation)`
    /// is the dial ticket captured in the same critical section.
    pub fn checkout(&self) -> Result<Checkout, Uint> {
        self.inner.checkout()
    }

    /// Register a newly dialled session as `CheckedOut` only. Returns `None`
    /// (caller must close) if a reset ran, the session is already closed, or
    /// close won the register race.
    pub fn register_checked_out(
        &self,
        session: Arc<Session>,
        generation: Uint,
    ) -> Option<Checkout> {
        let checkout = self
            .inner
            .register_checked_out(Arc::clone(&session), generation)?;
        let inner = Arc::downgrade(&self.inner);
        let session_id = checkout.session_id;
        session.set_pool_close_notify(Box::new(move || {
            if let Some(inner) = inner.upgrade() {
                inner.unregister_session(session_id);
            }
        }));
        if session.is_closed() {
            self.inner.unregister_session(session_id);
            return None;
        }
        tracing::debug!("[SessionPool] Registered checked-out session (id={session_id})");
        Some(checkout)
    }

    /// Return a matching healthy checkout to idle. Stale/duplicate calls are
    /// no-ops. A matching but unhealthy checkout is unregistered and closed.
    pub fn return_checkout(&self, checkout: &Checkout) {
        self.inner.return_checkout(
            checkout.generation,
            checkout.session_id,
            checkout.checkout_id,
            &checkout.session,
        );
    }

    /// Unregister a matching checkout and close that session. Stale/duplicate
    /// calls are no-ops and do not close a later checkout of the same session.
    pub fn discard_checkout(&self, checkout: &Checkout) {
        self.inner.discard_checkout(
            checkout.generation,
            checkout.session_id,
            checkout.checkout_id,
        );
    }

    /// Get current number of idle sessions
    pub fn idle_count(&self) -> usize {
        self.inner.idle_count()
    }

    /// Get current number of live (idle + checked-out) sessions
    pub fn live_count(&self) -> usize {
        self.inner.live_count()
    }

    pub fn idle_len(&self) -> usize {
        self.inner.idle_count()
    }

    pub fn live_len(&self) -> usize {
        self.inner.live_count()
    }

    /// Clean up expired idle sessions
    pub async fn cleanup_expired(&self) {
        self.inner.cleanup_expired().await;
    }

    fn start_cleanup_task(&self) {
        let inner = Arc::downgrade(&self.inner);
        let check_interval = self.inner.config.check_interval;

        let handle = tokio::spawn(async move {
            let mut interval_timer = interval(check_interval);
            tracing::debug!(
                "[SessionPool] Cleanup task started (interval={:?})",
                check_interval
            );
            loop {
                interval_timer.tick().await;
                let Some(inner) = inner.upgrade() else {
                    break;
                };
                inner.cleanup_expired().await;
            }
            tracing::debug!("[SessionPool] Cleanup task stopped");
        });

        if let Ok(mut task) = self.cleanup_task.lock() {
            *task = Some(handle);
        }
    }

    /// Stop cleanup task (called on drop)
    pub async fn stop_cleanup_task(&self) {
        let handle = self.cleanup_task.lock().unwrap().take();
        if let Some(handle) = handle {
            handle.abort();
            tracing::debug!("[SessionPool] Cleanup task stopped");
        }
    }
}

impl Drop for SessionPool {
    fn drop(&mut self) {
        if let Ok(mut task) = self.cleanup_task.lock()
            && let Some(handle) = task.take()
        {
            handle.abort();
        }
        let remaining = self.inner.take_all(true);
        for session in remaining {
            spawn_close(session);
        }
    }
}

impl PoolInner {
    fn checkout(&self) -> Result<Checkout, Uint> {
        let mut stale = Vec::new();
        let result = {
            let mut state = self.state.lock().unwrap();
            let generation = state.generation;
            loop {
                let Some((seq, session_id)) =
                    state.idle.iter().next_back().map(|(&s, &id)| (s, id))
                else {
                    break Err(generation);
                };
                state.idle.remove(&seq);
                let closed_or_stale = match state.live.get(&session_id) {
                    Some(entry) => entry.session.is_closed() || entry.generation != generation,
                    None => {
                        continue;
                    }
                };
                if closed_or_stale {
                    if let Some(entry) = state.live.remove(&session_id) {
                        stale.push(entry.session);
                    }
                    continue;
                }
                let checkout_id = state.next_checkout;
                state.next_checkout = state.next_checkout.wrapping_add(1);
                let entry = state.live.get_mut(&session_id).expect("live entry");
                entry.state = LiveState::CheckedOut(checkout_id);
                tracing::debug!("[SessionPool] Checking out idle session (id={session_id})");
                break Ok(Checkout {
                    session: Arc::clone(&entry.session),
                    generation,
                    session_id,
                    checkout_id,
                });
            }
        };
        for session in stale {
            spawn_close(session);
        }
        result
    }

    fn register_checked_out(&self, session: Arc<Session>, generation: Uint) -> Option<Checkout> {
        let mut state = self.state.lock().unwrap();
        if generation != state.generation || session.is_closed() {
            return None;
        }
        let session_id = session.id();
        if state.live.contains_key(&session_id) {
            return None;
        }
        let checkout_id = state.next_checkout;
        state.next_checkout = state.next_checkout.wrapping_add(1);
        state.live.insert(
            session_id,
            LiveEntry {
                session: Arc::clone(&session),
                seq: 0,
                idle_since: Instant::now(),
                generation,
                state: LiveState::CheckedOut(checkout_id),
            },
        );
        Some(Checkout {
            session,
            generation,
            session_id,
            checkout_id,
        })
    }

    fn return_checkout(
        &self,
        generation: Uint,
        session_id: u64,
        checkout_id: u64,
        session: &Arc<Session>,
    ) {
        let to_close = {
            let mut state = self.state.lock().unwrap();
            if generation != state.generation {
                return;
            }
            let matches = match state.live.get(&session_id) {
                Some(entry) => {
                    matches!(entry.state, LiveState::CheckedOut(id) if id == checkout_id)
                }
                None => false,
            };
            if !matches {
                return;
            }
            if session.is_closed()
                || state
                    .live
                    .get(&session_id)
                    .is_some_and(|e| e.session.is_closed())
            {
                state.idle.retain(|_, id| *id != session_id);
                state.live.remove(&session_id).map(|e| e.session)
            } else {
                let seq = state.next_seq;
                state.next_seq = state.next_seq.wrapping_add(1);
                if let Some(entry) = state.live.get_mut(&session_id) {
                    entry.state = LiveState::Idle;
                    entry.idle_since = Instant::now();
                    entry.seq = seq;
                }
                state.idle.insert(seq, session_id);
                tracing::debug!(
                    "[SessionPool] Returned session to idle (id={session_id}, idle={})",
                    state.idle.len()
                );
                None
            }
        };
        if let Some(session) = to_close {
            spawn_close(session);
        }
    }

    fn discard_checkout(&self, generation: Uint, session_id: u64, checkout_id: u64) {
        let to_close = {
            let mut state = self.state.lock().unwrap();
            if generation != state.generation {
                return;
            }
            let matches = match state.live.get(&session_id) {
                Some(entry) => {
                    matches!(entry.state, LiveState::CheckedOut(id) if id == checkout_id)
                }
                None => false,
            };
            if !matches {
                return;
            }
            state.idle.retain(|_, id| *id != session_id);
            state.live.remove(&session_id).map(|e| e.session)
        };
        if let Some(session) = to_close {
            spawn_close(session);
        }
    }

    fn unregister_session(&self, session_id: u64) {
        let mut state = self.state.lock().unwrap();
        state.idle.retain(|_, id| *id != session_id);
        state.live.remove(&session_id);
    }

    fn checkout_is_current(&self, generation: Uint, session_id: u64, checkout_id: u64) -> bool {
        let state = self.state.lock().unwrap();
        if state.generation != generation {
            return false;
        }
        match state.live.get(&session_id) {
            Some(entry) => {
                !entry.session.is_closed()
                    && matches!(entry.state, LiveState::CheckedOut(id) if id == checkout_id)
            }
            None => false,
        }
    }

    fn take_all(&self, bump_generation: bool) -> Vec<Arc<Session>> {
        let mut state = self.state.lock().unwrap();
        if bump_generation {
            state.generation = state.generation.wrapping_add(1);
        }
        state.idle.clear();
        state.live.drain().map(|(_, e)| e.session).collect()
    }

    fn idle_count(&self) -> usize {
        self.state.lock().unwrap().idle.len()
    }

    fn live_count(&self) -> usize {
        self.state.lock().unwrap().live.len()
    }

    async fn cleanup_expired(&self) {
        let now = Instant::now();
        let timeout = self.config.idle_timeout;
        let min_idle = self.config.min_idle_sessions;
        let to_close = {
            let mut state = self.state.lock().unwrap();
            if state.idle.is_empty() {
                return;
            }
            let initial_count = state.idle.len();
            let cleanup_span = info_span!(
                "anytls.session_pool.cleanup",
                idle_initial = initial_count as u64,
                removed = field::Empty,
                remaining = field::Empty
            );
            let mut keep = 0usize;
            let mut remove_seqs = Vec::new();
            for (&seq, &session_id) in &state.idle {
                let Some(entry) = state.live.get(&session_id) else {
                    remove_seqs.push(seq);
                    continue;
                };
                if entry.session.is_closed() {
                    remove_seqs.push(seq);
                    continue;
                }
                if now.duration_since(entry.idle_since) < timeout {
                    keep += 1;
                    continue;
                }
                if keep < min_idle {
                    keep += 1;
                    tracing::trace!(
                        "[SessionPool] Keeping expired session (id={session_id}) to maintain min_idle={min_idle}"
                    );
                    continue;
                }
                tracing::debug!(
                    "[SessionPool] Marking session for cleanup (id={session_id}, idle_for={:.1}s)",
                    now.duration_since(entry.idle_since).as_secs_f64()
                );
                remove_seqs.push(seq);
            }
            let mut sessions = Vec::new();
            for seq in &remove_seqs {
                if let Some(session_id) = state.idle.remove(seq)
                    && let Some(entry) = state.live.remove(&session_id)
                {
                    sessions.push(entry.session);
                }
            }
            if !sessions.is_empty() {
                tracing::debug!(
                    "[SessionPool] Cleaned up {} expired sessions ({} -> {} idle)",
                    sessions.len(),
                    initial_count,
                    state.idle.len()
                );
            }
            cleanup_span.record("removed", sessions.len() as u64);
            cleanup_span.record("remaining", state.idle.len() as u64);
            sessions
        };
        for session in to_close {
            if let Err(e) = session.close().await {
                tracing::warn!("[SessionPool] Failed to close expired session: {e}");
            }
        }
    }
}

fn spawn_close(session: Arc<Session>) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                if let Err(e) = session.close().await {
                    tracing::debug!("[SessionPool] Failed to close session: {e}");
                }
            });
        }
        Err(_) => tracing::warn!(
            "[SessionPool] close requested without a tokio runtime; session may leak until drop"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[test]
    fn test_default_config() {
        let config = SessionPoolConfig::default();
        assert_eq!(config.check_interval, Duration::from_secs(30));
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
        assert_eq!(config.min_idle_sessions, 1);
    }

    #[test]
    fn test_custom_config() {
        let config = SessionPoolConfig {
            check_interval: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            min_idle_sessions: 5,
        };

        assert_eq!(config.check_interval, Duration::from_secs(10));
        assert_eq!(config.idle_timeout, Duration::from_secs(30));
        assert_eq!(config.min_idle_sessions, 5);
    }

    #[tokio::test]
    async fn test_session_pool_creation() {
        let pool = SessionPool::new();
        assert_eq!(pool.idle_count(), 0);
        assert_eq!(pool.live_count(), 0);
        pool.stop_cleanup_task().await;
    }

    #[tokio::test]
    async fn test_next_seq() {
        let pool = SessionPool::new();
        let seq1 = pool.next_seq();
        let seq2 = pool.next_seq();
        let seq3 = pool.next_seq();

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);
    }

    #[tokio::test]
    async fn test_checkout_empty() {
        let pool = SessionPool::new();
        assert!(pool.checkout().is_err());
    }

    fn test_session() -> Arc<Session> {
        Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            crate::padding::PaddingFactory::default().into_shared(),
            None,
        ))
    }

    fn register_idle(pool: &SessionPool, session: Arc<Session>) -> Checkout {
        let generation = pool.generation();
        let checkout = pool
            .register_checked_out(Arc::clone(&session), generation)
            .expect("register");
        pool.return_checkout(&checkout);
        checkout
    }

    #[tokio::test]
    async fn checkout_removes_from_idle_and_return_restores() {
        let pool = SessionPool::new();
        let session = test_session();
        register_idle(&pool, Arc::clone(&session));
        assert_eq!(pool.idle_len(), 1);
        assert_eq!(pool.live_len(), 1);

        let checkout = pool.checkout().expect("idle session");
        assert!(Arc::ptr_eq(&checkout.session, &session));
        assert_eq!(pool.idle_len(), 0);
        assert_eq!(pool.live_len(), 1);

        pool.return_checkout(&checkout);
        assert_eq!(pool.idle_len(), 1);
        assert_eq!(pool.live_len(), 1);
    }

    #[tokio::test]
    async fn exclusive_checkout_second_misses() {
        let pool = SessionPool::new();
        let session = test_session();
        register_idle(&pool, session);
        let first = pool.checkout().expect("first checkout");
        assert!(
            pool.checkout().is_err(),
            "idle must be empty while checked out"
        );
        pool.return_checkout(&first);
        assert!(pool.checkout().is_ok());
    }

    #[tokio::test]
    async fn newest_returned_is_checked_out_first() {
        let pool = SessionPool::new();
        let older = test_session();
        let newer = test_session();
        register_idle(&pool, Arc::clone(&older));
        register_idle(&pool, Arc::clone(&newer));
        let checkout = pool.checkout().expect("newest");
        assert!(Arc::ptr_eq(&checkout.session, &newer));
    }

    #[tokio::test]
    async fn stale_return_does_not_close_next_checkout() {
        let pool = SessionPool::new();
        let session = test_session();
        register_idle(&pool, Arc::clone(&session));
        let first = pool.checkout().expect("first");
        pool.return_checkout(&first);
        let second = pool.checkout().expect("second");
        pool.return_checkout(&first);
        assert!(
            !second.session.is_closed(),
            "stale return must not close the new checkout"
        );
        assert_eq!(pool.live_len(), 1);
        assert_eq!(
            pool.idle_len(),
            0,
            "stale return must not double-insert idle"
        );
        pool.return_checkout(&second);
        assert_eq!(pool.idle_len(), 1);
    }

    #[tokio::test]
    async fn duplicate_return_is_noop() {
        let pool = SessionPool::new();
        let session = test_session();
        register_idle(&pool, session);
        let checkout = pool.checkout().expect("checkout");
        pool.return_checkout(&checkout);
        pool.return_checkout(&checkout);
        assert_eq!(pool.idle_len(), 1);
        assert_eq!(pool.live_len(), 1);
    }

    #[tokio::test]
    async fn discard_unregisters_and_closes() {
        let pool = SessionPool::new();
        let session = test_session();
        let generation = pool.generation();
        let checkout = pool
            .register_checked_out(Arc::clone(&session), generation)
            .expect("register");
        pool.discard_checkout(&checkout);
        tokio::time::timeout(Duration::from_secs(5), session.wait_closed())
            .await
            .expect("discard closes the session");
        assert_eq!(pool.live_len(), 0);
        assert_eq!(pool.idle_len(), 0);
    }

    #[tokio::test]
    async fn session_close_unregisters_from_live_and_idle() {
        let pool = SessionPool::new();
        let session = test_session();
        register_idle(&pool, Arc::clone(&session));
        session.close().await.unwrap();
        assert_eq!(pool.live_len(), 0);
        assert_eq!(pool.idle_len(), 0);
    }

    /// meow-rs issue #695: reset closes idle and in-use sessions, refuses a
    /// session dialled across it, and pools post-reset sessions normally.
    #[tokio::test]
    async fn reset_closes_live_sessions_and_refuses_straddling_ones() {
        let pool = SessionPool::new();
        let idle = test_session();
        register_idle(&pool, Arc::clone(&idle));
        let busy = test_session();
        let dialled_at = pool.generation();
        let busy_checkout = pool
            .register_checked_out(Arc::clone(&busy), dialled_at)
            .expect("busy register");
        assert_eq!(pool.live_len(), 2);
        assert_eq!(pool.idle_len(), 1);

        pool.reset();
        assert!(
            pool.checkout().is_err(),
            "a pre-reset session is never handed out again"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            idle.wait_closed().await;
            busy.wait_closed().await;
        })
        .await
        .expect("the reset closes idle and in-use sessions");
        assert_eq!(pool.idle_len(), 0);
        assert_eq!(pool.live_len(), 0);

        assert!(
            pool.register_checked_out(test_session(), dialled_at)
                .is_none(),
            "a session dialled before the reset is refused"
        );
        assert_eq!(pool.idle_len(), 0);

        let fresh = test_session();
        let checkout = pool
            .register_checked_out(Arc::clone(&fresh), pool.generation())
            .expect("post-reset session registered");
        assert!(Arc::ptr_eq(&checkout.session, &fresh));
        pool.return_checkout(&busy_checkout);
        assert_eq!(
            pool.live_len(),
            1,
            "late old return must not mutate the new generation"
        );
        assert_eq!(pool.idle_len(), 0);
    }

    #[tokio::test]
    async fn idle_cleanup_skips_checked_out_sessions() {
        let pool = SessionPool::with_config(SessionPoolConfig {
            check_interval: Duration::from_secs(30),
            idle_timeout: Duration::ZERO,
            min_idle_sessions: 0,
        });
        let idle = test_session();
        register_idle(&pool, Arc::clone(&idle));
        let busy = test_session();
        let busy_checkout = pool
            .register_checked_out(Arc::clone(&busy), pool.generation())
            .expect("busy");
        pool.cleanup_expired().await;
        tokio::time::timeout(Duration::from_secs(5), idle.wait_closed())
            .await
            .expect("expired idle is closed");
        assert!(
            !busy.is_closed(),
            "cleanup must not close a checked-out session"
        );
        assert_eq!(pool.live_len(), 1);
        assert_eq!(pool.idle_len(), 0);
        pool.return_checkout(&busy_checkout);
        assert_eq!(pool.idle_len(), 1);
    }

    #[tokio::test]
    async fn concurrent_checkouts_are_exclusive() {
        let pool = Arc::new(SessionPool::new());
        for _ in 0..4 {
            register_idle(&pool, test_session());
        }
        let start = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let pool = Arc::clone(&pool);
            let start = Arc::clone(&start);
            handles.push(tokio::spawn(async move {
                start.wait().await;
                pool.checkout()
            }));
        }
        let mut seen = Vec::new();
        for handle in handles {
            let checkout = handle.await.unwrap().expect("idle available");
            seen.push(checkout.session.id());
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 4, "each checkout must be a distinct session");
        assert_eq!(pool.idle_len(), 0);
        assert_eq!(pool.live_len(), 4);
    }
}
