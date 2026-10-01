//! Reuse pool for snell `CommandConnectV2` sessions.
//!
//! Port of opensnell `components/snell/pool.go`. The Surge `snell-server`
//! v4 and v5 releases (4.0.0 through 5.0.1, like v6) serve any number of
//! sessions on a reuse-mode TCP connection, so a connection goes back to the
//! pool after every clean session. Idle entries age out after 15 s.
//!
//! Lifecycle of a pooled session:
//!
//! 1. `Pool::get` either pops the most-recently-returned idle conn (LIFO,
//!    warmest cache) or asks the factory to dial a fresh one.
//! 2. The caller writes the snell `CommandConnectV2` header and relays data.
//! 3. `PooledConn` returns the stream only after both peers have completed
//!    their zero-chunk half-close handshake. Incomplete sessions are dropped.

use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use meow_common::atomic::{AtomicU, Uint};
use meow_transport::Stream as TransportStream;

use super::protocol::Snell;

/// Type-erased snell stream used inside the pool. The underlying byte
/// stream may be a plain TCP connection or an obfs-wrapped one — the pool
/// doesn't care.
pub type PoolStream = Snell<Box<dyn TransportStream>>;

const DEFAULT_MAX_SIZE: usize = 10;
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(15);
struct PooledEntry {
    conn: PoolStream,
    expires_at: Instant,
}

/// Bounded LIFO pool of warm snell streams.
pub struct Pool {
    max_size: usize,
    max_age: Duration,
    items: Mutex<Vec<PooledEntry>>,
    /// Bumped by [`Pool::reset`]; a conn checked out (or dialled) under an
    /// older generation is never re-pooled. Compared for equality only, so
    /// the mips32 `u32` wrap is harmless.
    generation: AtomicU,
}

impl Pool {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_SIZE, DEFAULT_MAX_AGE)
    }

    /// A pool with custom caps: at most `max_size` idle entries, each
    /// discarded after `max_age` idle.
    pub fn with_limits(max_size: usize, max_age: Duration) -> Self {
        Self {
            max_size,
            max_age,
            items: Mutex::new(Vec::new()),
            generation: AtomicU::new(0),
        }
    }

    /// Current generation. Capture it *before* taking an idle conn or
    /// dialling a fresh one and hand it back to [`Pool::put`], so a conn
    /// that straddles a [`Pool::reset`] is dropped instead of re-pooled.
    pub fn generation(&self) -> Uint {
        self.generation.load(Ordering::SeqCst)
    }

    /// Drop every idle conn and invalidate every checked-out one, so the
    /// next dial opens a fresh socket. Called when the outbound-interface
    /// binding changes (issue #695). Returns the number of idle conns
    /// closed; checked-out conns are exclusive to their session and close
    /// when it ends (the caller cancels those relays).
    pub fn reset(&self) -> usize {
        let mut items = self
            .items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.generation.fetch_add(1, Ordering::SeqCst);
        let closed = items.len();
        items.clear();
        closed
    }

    /// Try to take a still-fresh idle entry off the pool. Returns `None` if
    /// the pool is empty or every entry has expired.
    pub fn take_idle(&self) -> Option<PoolStream> {
        let now = Instant::now();
        let mut items = self
            .items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(entry) = items.pop() {
            if now < entry.expires_at {
                return Some(entry.conn);
            }
            // Expired — drop on the floor; the underlying TCP will close
            // when the Snell wrapper is dropped.
        }
        None
    }

    /// Number of idle entries currently parked (expired entries included —
    /// they are lazily discarded by [`Pool::take_idle`]). Exposed so callers
    /// (and integration tests) can observe when a completed session has
    /// replenished the pool.
    pub fn idle_count(&self) -> usize {
        self.items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Re-insert a conn that has just finished a session. Drops the conn if
    /// the pool is full or `generation` (captured when the conn was taken
    /// or dialled) predates a [`Pool::reset`].
    pub fn put(&self, conn: PoolStream, generation: Uint) {
        let mut items = self
            .items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Checked under the lock `reset` bumps under: a put can never slip
        // a stale conn in after the reset's clear.
        if items.len() >= self.max_size || generation != self.generation() {
            return;
        }
        items.push(PooledEntry {
            conn,
            expires_at: Instant::now() + self.max_age,
        });
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Build a pool-typed snell stream over an in-memory duplex. The peer
    /// half is returned so tests can keep the underlying stream open (or
    /// wrap it in a `V4Conn` to speak the AEAD protocol from the far side).
    fn make_stream() -> (PoolStream, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(1 << 16);
        (
            Snell::new(
                Box::new(a) as Box<dyn TransportStream>,
                Arc::from(b"k".as_slice()),
            ),
            b,
        )
    }

    #[test]
    fn take_idle_on_empty_pool_is_none() {
        let pool = Pool::new();
        assert!(pool.take_idle().is_none());
    }

    #[test]
    fn pool_is_lifo() {
        let pool = Pool::new();
        // The older conn's peer is gone, so the two are told apart by
        // whether the conn still looks alive.
        let (older, peer_older) = make_stream();
        drop(peer_older);
        let (newer, _peer_newer) = make_stream();
        pool.put(older, pool.generation());
        pool.put(newer, pool.generation());

        let mut conn = pool.take_idle().expect("first take should pop an entry");
        assert!(
            conn.idle_conn_alive(),
            "most recently returned conn comes back first"
        );
        let mut conn = pool.take_idle().expect("second take should pop an entry");
        assert!(!conn.idle_conn_alive());
        assert!(pool.take_idle().is_none());
    }

    #[test]
    fn put_keeps_a_conn_after_any_number_of_sessions() {
        let pool = Pool::new();
        let (conn, _peer) = make_stream();
        pool.put(conn, pool.generation());
        for session in 0..8 {
            let conn = pool
                .take_idle()
                .unwrap_or_else(|| panic!("session {session} found no pooled conn"));
            pool.put(conn, pool.generation());
        }
        assert_eq!(pool.idle_count(), 1);
    }

    #[test]
    fn custom_limits_apply() {
        let pool = Pool::with_limits(1, Duration::from_secs(60));
        let (first, _peer_first) = make_stream();
        pool.put(first, pool.generation());
        let (extra, _peer_extra) = make_stream();
        pool.put(extra, pool.generation());
        assert_eq!(pool.idle_count(), 1, "max_size caps idle entries");
        assert!(pool.take_idle().is_some());

        let expired = Pool::with_limits(4, Duration::ZERO);
        let (conn, _peer) = make_stream();
        expired.put(conn, expired.generation());
        assert!(
            expired.take_idle().is_none(),
            "zero max_age expires at once"
        );
    }

    #[test]
    fn put_respects_max_size() {
        let pool = Pool::new();
        let mut peers = Vec::new();
        for _ in 0..11 {
            let (conn, peer) = make_stream();
            peers.push(peer);
            pool.put(conn, pool.generation());
        }
        for i in 0..10 {
            assert!(
                pool.take_idle().is_some(),
                "take {i} should pop a pooled conn"
            );
        }
        assert!(pool.take_idle().is_none(), "pool is capped at 10 entries");
    }

    /// Issue #695: a reset drops idle conns and refuses conns checked out
    /// (or dialled) before it, while post-reset conns pool normally.
    #[test]
    fn reset_drops_idle_and_refuses_stale_returns() {
        let pool = Pool::new();
        let (idle, _peer_idle) = make_stream();
        pool.put(idle, pool.generation());
        let checked_out_at = pool.generation();
        let (busy, _peer_busy) = make_stream();

        assert_eq!(pool.reset(), 1, "the idle conn is dropped");
        assert_eq!(pool.idle_count(), 0);
        pool.put(busy, checked_out_at);
        assert_eq!(pool.idle_count(), 0, "a pre-reset conn is never re-pooled");

        let (fresh, _peer_fresh) = make_stream();
        pool.put(fresh, pool.generation());
        assert_eq!(pool.idle_count(), 1, "post-reset conns pool normally");
        assert_eq!(pool.reset(), 1);
    }
}
