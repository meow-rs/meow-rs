//! Session pool for connection reuse with configurable cleanup

use crate::session::Session;
use meow_common::atomic::{AtomicU, Uint};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::{Mutex, RwLock};
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

/// Pooled session with metadata
struct PooledSession {
    seq: u64,
    session: Arc<Session>,
    idle_since: Instant,
    /// Pool generation the session was dialled under (see
    /// [`SessionPool::reset`]).
    generation: Uint,
}

/// SessionPool manages idle sessions for reuse with automatic cleanup
pub struct SessionPool {
    // Sessions stored by seq (BTreeMap for ordered access)
    idle_sessions: Arc<RwLock<BTreeMap<u64, PooledSession>>>,

    // Sequence counter (monotonically increasing)
    next_seq: Arc<AtomicU>,

    // Configuration
    config: SessionPoolConfig,

    // Cleanup task handle
    cleanup_task: Arc<Mutex<Option<JoinHandle<()>>>>,

    // Bumped by `reset`; sessions from an older generation are never handed
    // out again. Compared for equality only, so the MIPS32 wrap is harmless.
    generation: Arc<AtomicU>,
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
        let pool = Self {
            idle_sessions: Arc::new(RwLock::new(BTreeMap::new())),
            next_seq: Arc::new(AtomicU::new(1)),
            config,
            cleanup_task: Arc::new(Mutex::new(None)),
            generation: Arc::new(AtomicU::new(0)),
        };

        // Start automatic cleanup task
        pool.start_cleanup_task();

        pool
    }

    /// Get the next sequence number
    pub fn next_seq(&self) -> u64 {
        // `AtomicU` is 32-bit on targets without 64-bit atomics (MIPS32); the
        // public sequence stays u64 and simply wraps sooner there.
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        self.next_seq.fetch_add(1, Ordering::Relaxed).into()
    }

    /// Current pool generation. Capture it before dialling a session and hand
    /// it to [`add_idle_session_from`](Self::add_idle_session_from) so a
    /// session whose dial straddles a [`reset`](Self::reset) is never pooled.
    pub fn generation(&self) -> Uint {
        self.generation.load(Ordering::SeqCst)
    }

    /// Close every pooled session — streams still on them fail with
    /// `SessionClosed` — so the next stream dials a fresh connection. Called
    /// when the host's outbound-interface binding changes (meow-rs issue
    /// #695): a session's socket dialled before the binding stays unbound.
    ///
    /// Non-blocking: stale sessions stop being handed out at once, and the
    /// close itself (async) runs on a spawned task. Pooled sessions keep
    /// themselves alive through their own tasks, so dropping them from the
    /// map without `close` would leak their sockets.
    pub fn reset(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!("[SessionPool] reset without a tokio runtime; sessions stay pooled");
            return;
        };
        let idle_sessions = Arc::clone(&self.idle_sessions);
        let generation = Arc::clone(&self.generation);
        runtime.spawn(async move {
            let stale: Vec<PooledSession> = {
                let mut sessions = idle_sessions.write().await;
                let current = generation.load(Ordering::SeqCst);
                let seqs: Vec<u64> = sessions
                    .iter()
                    .filter(|(_, pooled)| pooled.generation != current)
                    .map(|(seq, _)| *seq)
                    .collect();
                seqs.iter().filter_map(|seq| sessions.remove(seq)).collect()
            };
            tracing::debug!("[SessionPool] Reset: closing {} sessions", stale.len());
            for pooled in stale {
                if let Err(e) = pooled.session.close().await {
                    tracing::debug!("[SessionPool] Failed to close reset session: {}", e);
                }
            }
        });
    }

    /// Get an idle session for reuse (the most recent live one, largest seq).
    ///
    /// The session is **left in the pool** (peek-and-touch, not remove): AnyTLS
    /// multiplexes many streams over one session, so the same session stays
    /// available for concurrent and subsequent streams and is only retired by
    /// the cleanup task once it is genuinely idle. Removing-without-returning
    /// here was the FD-leak root cause (issue meow-rs#201): a reused session
    /// became orphaned — held alive forever by its own heartbeat task — and
    /// never freed its socket, exhausting file descriptors under churn.
    ///
    /// Closed sessions encountered along the way are pruned.
    pub async fn get_idle_session(&self) -> Option<Arc<Session>> {
        let mut sessions = self.idle_sessions.write().await;

        let mut closed = Vec::new();
        let mut chosen = None;
        let generation = self.generation();
        // Iterate newest-first; reuse the first live session.
        for (seq, pooled) in sessions.iter_mut().rev() {
            if pooled.session.is_closed() {
                closed.push(*seq);
                continue;
            }
            // Pre-reset: the reset's task closes and removes it.
            if pooled.generation != generation {
                continue;
            }
            pooled.idle_since = Instant::now();
            tracing::debug!("[SessionPool] Reusing idle session (seq={})", pooled.seq);
            chosen = Some(Arc::clone(&pooled.session));
            break;
        }

        for seq in closed {
            sessions.remove(&seq);
        }

        if chosen.is_none() {
            tracing::debug!("[SessionPool] No idle sessions available");
        }
        chosen
    }

    /// Add a session to the idle pool
    pub async fn add_idle_session(&self, session: Arc<Session>) {
        self.add_idle_session_from(session, self.generation()).await;
    }

    /// Add a session dialled under `generation` to the idle pool. Returns
    /// `false` (and does not pool it) if a [`reset`](Self::reset) has run
    /// since — the caller must close it.
    pub async fn add_idle_session_from(&self, session: Arc<Session>, generation: Uint) -> bool {
        if session.is_closed() {
            tracing::debug!("[SessionPool] Session already closed, skipping add to pool");
            return true;
        }
        let seq = session.seq();

        let pooled = PooledSession {
            seq,
            session,
            idle_since: Instant::now(),
            generation,
        };

        let mut sessions = self.idle_sessions.write().await;
        // Checked under the map lock the reset's drain takes, after the
        // bump: a stale session can never slip in behind the drain.
        if generation != self.generation() {
            return false;
        }
        sessions.insert(seq, pooled);

        tracing::debug!(
            "[SessionPool] ➕ Added session to pool (seq={}, total_idle={})",
            seq,
            sessions.len()
        );
        true
    }

    /// Get current number of idle sessions
    pub async fn idle_count(&self) -> usize {
        self.idle_sessions.read().await.len()
    }

    /// Clean up expired idle sessions
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut sessions = self.idle_sessions.write().await;

        if sessions.is_empty() {
            return;
        }

        let initial_count = sessions.len();
        let cleanup_span = info_span!(
            "anytls.session_pool.cleanup",
            idle_initial = initial_count as u64,
            removed = field::Empty,
            remaining = field::Empty
        );
        // Record-only span — an Entered guard held across the awaits below
        // would leak this span onto unrelated tasks on this worker thread.
        let mut to_remove = Vec::new();
        let mut active_count = 0;

        // Iterate from oldest to newest (ascending seq order)
        for (seq, pooled) in sessions.iter() {
            let idle_duration = now.duration_since(pooled.idle_since);

            if pooled.session.is_closed() {
                to_remove.push(*seq);
                continue;
            }

            // Never retire a session that is still carrying streams — pooled
            // sessions are reused in place (see `get_idle_session`), so an
            // active long-lived stream can outlive the idle timeout.
            if pooled.session.has_active_streams().await {
                active_count += 1;
                continue;
            }

            // Keep sessions that haven't expired
            if idle_duration < self.config.idle_timeout {
                active_count += 1;
                continue;
            }

            // Keep at least min_idle_sessions
            if active_count < self.config.min_idle_sessions {
                active_count += 1;
                tracing::trace!(
                    "[SessionPool] Keeping expired session (seq={}) to maintain min_idle={}",
                    seq,
                    self.config.min_idle_sessions
                );
                continue;
            }

            // Mark for removal
            tracing::debug!(
                "[SessionPool] 🗑️ Marking session for cleanup (seq={}, idle_for={:.1}s)",
                seq,
                idle_duration.as_secs_f64()
            );
            to_remove.push(*seq);
        }

        // Remove expired sessions
        for seq in &to_remove {
            if let Some(pooled) = sessions.remove(seq) {
                // Close the session
                if let Err(e) = pooled.session.close().await {
                    tracing::warn!("[SessionPool] Failed to close session {}: {}", seq, e);
                }
            }
        }

        let removed = to_remove.len();
        if removed > 0 {
            tracing::debug!(
                "[SessionPool] Cleaned up {} expired sessions ({} -> {} idle)",
                removed,
                initial_count,
                sessions.len()
            );
        }
        cleanup_span.record("removed", removed as u64);
        cleanup_span.record("remaining", sessions.len() as u64);
    }

    /// Start automatic cleanup task
    fn start_cleanup_task(&self) {
        let idle_sessions = Arc::clone(&self.idle_sessions);
        let check_interval = self.config.check_interval;
        let idle_timeout = self.config.idle_timeout;
        let min_idle = self.config.min_idle_sessions;
        let cleanup_task_handle = Arc::clone(&self.cleanup_task);

        let handle = tokio::spawn(async move {
            let mut interval_timer = interval(check_interval);

            tracing::debug!(
                "[SessionPool] Cleanup task started (interval={:?}, timeout={:?}, min_idle={})",
                check_interval,
                idle_timeout,
                min_idle
            );

            loop {
                interval_timer.tick().await;

                // Perform cleanup
                let now = Instant::now();
                let mut sessions = idle_sessions.write().await;

                if sessions.is_empty() {
                    continue;
                }

                let mut to_remove = Vec::new();
                let mut active_count = 0;

                for (seq, pooled) in sessions.iter() {
                    let idle_duration = now.duration_since(pooled.idle_since);

                    if pooled.session.is_closed() {
                        to_remove.push(*seq);
                        continue;
                    }

                    // Don't retire a session still carrying streams.
                    if pooled.session.has_active_streams().await {
                        active_count += 1;
                        continue;
                    }

                    if idle_duration < idle_timeout {
                        active_count += 1;
                        continue;
                    }

                    if active_count < min_idle {
                        active_count += 1;
                        continue;
                    }

                    to_remove.push(*seq);
                }

                if !to_remove.is_empty() {
                    for seq in &to_remove {
                        if let Some(pooled) = sessions.remove(seq)
                            && let Err(e) = pooled.session.close().await
                        {
                            tracing::warn!("[SessionPool] Failed to close session {}: {}", seq, e);
                        }
                    }

                    tracing::debug!(
                        "[SessionPool] Auto-cleanup: removed {} expired sessions",
                        to_remove.len()
                    );
                }
            }
        });

        // Store the handle
        if let Ok(mut task) = cleanup_task_handle.try_lock() {
            *task = Some(handle);
        };
    }

    /// Stop cleanup task (called on drop)
    pub async fn stop_cleanup_task(&self) {
        let mut task_guard = self.cleanup_task.lock().await;
        if let Some(handle) = task_guard.take() {
            handle.abort();
            tracing::debug!("[SessionPool] Cleanup task stopped");
        }
    }
}

impl Drop for SessionPool {
    fn drop(&mut self) {
        // Attempt to stop cleanup task
        // Note: This is best-effort since Drop is sync
        if let Ok(mut task) = self.cleanup_task.try_lock()
            && let Some(handle) = task.take()
        {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(pool.idle_count().await, 0);
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
    async fn test_get_idle_session_empty() {
        let pool = SessionPool::new();
        let session = pool.get_idle_session().await;
        assert!(session.is_none());
    }

    fn test_session(seq: u64) -> Arc<Session> {
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            crate::padding::PaddingFactory::default().into_shared(),
            None,
        ));
        session.set_seq(seq);
        session
    }

    /// meow-rs issue #695: a reset stops handing out pooled sessions at once,
    /// closes them (they keep themselves alive otherwise), refuses a session
    /// dialled across it, and pools post-reset sessions normally.
    #[tokio::test]
    async fn reset_closes_pooled_sessions_and_refuses_straddling_ones() {
        let pool = SessionPool::new();
        let pooled = test_session(1);
        pool.add_idle_session(Arc::clone(&pooled)).await;
        assert!(pool.get_idle_session().await.is_some());
        let dialled_at = pool.generation();

        pool.reset();
        assert!(
            pool.get_idle_session().await.is_none(),
            "a pre-reset session is never handed out again"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while !pooled.is_closed() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the reset closes the pooled session");
        assert_eq!(pool.idle_count().await, 0);

        let straddling = test_session(2);
        assert!(
            !pool
                .add_idle_session_from(Arc::clone(&straddling), dialled_at)
                .await,
            "a session dialled before the reset is refused"
        );
        assert_eq!(pool.idle_count().await, 0);

        let fresh = test_session(3);
        pool.add_idle_session(Arc::clone(&fresh)).await;
        let reused = pool
            .get_idle_session()
            .await
            .expect("post-reset session pooled");
        assert!(Arc::ptr_eq(&reused, &fresh));
    }
}
