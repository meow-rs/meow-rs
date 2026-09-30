//! Reuse pool for snell `CommandConnectV2` sessions.
//!
//! Port of opensnell `components/snell/pool.go`. The Surge `snell-server`
//! v5.0.1 implementation closes a reuse-mode TCP connection after the second
//! session (one fresh CONNECT + one reuse), so this pool caps `uses_per_conn`
//! at 2 and discards beyond that. Idle entries also age out after 15 s.
//!
//! Lifecycle of a pooled session:
//!
//! 1. `Pool::get` either pops the most-recently-returned idle conn (LIFO,
//!    warmest cache) or asks the factory to dial a fresh one.
//! 2. The caller writes the snell `CommandConnectV2` header and relays data.
//! 3. `PooledConn` returns the stream only after both peers have completed
//!    their zero-chunk half-close handshake. Incomplete sessions are dropped.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use meow_transport::Stream as TransportStream;

use super::protocol::Snell;

/// Type-erased snell stream used inside the pool. The underlying byte
/// stream may be a plain TCP connection or an obfs-wrapped one — the pool
/// doesn't care.
pub type PoolStream = Snell<Box<dyn TransportStream>>;

const DEFAULT_MAX_SIZE: usize = 10;
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(15);
const DEFAULT_MAX_USES_PER_CONN: u32 = 2;
struct PooledEntry {
    conn: PoolStream,
    expires_at: Instant,
    /// CONNECT sessions already served by this TCP stream.
    uses: u32,
}

/// Bounded LIFO pool of warm snell streams.
pub struct Pool {
    max_size: usize,
    max_age: Duration,
    max_uses_per_conn: u32,
    items: Mutex<Vec<PooledEntry>>,
}

impl Pool {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_SIZE, DEFAULT_MAX_AGE, DEFAULT_MAX_USES_PER_CONN)
    }

    /// A pool with custom caps: at most `max_size` idle entries, each
    /// discarded after `max_age` idle or once it has served
    /// `max_uses_per_conn` sessions.
    pub fn with_limits(max_size: usize, max_age: Duration, max_uses_per_conn: u32) -> Self {
        Self {
            max_size,
            max_age,
            max_uses_per_conn,
            items: Mutex::new(Vec::new()),
        }
    }

    /// Try to take a still-fresh idle entry off the pool. Returns `None` if
    /// the pool is empty or every entry has expired.
    pub fn take_idle(&self) -> Option<(PoolStream, u32)> {
        let now = Instant::now();
        let mut items = self
            .items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(entry) = items.pop() {
            if now < entry.expires_at {
                return Some((entry.conn, entry.uses));
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
    /// the pool is full or the conn has reached its session cap.
    pub fn put(&self, conn: PoolStream, uses: u32) {
        if uses >= self.max_uses_per_conn {
            return;
        }
        let mut items = self
            .items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if items.len() >= self.max_size {
            return;
        }
        items.push(PooledEntry {
            conn,
            expires_at: Instant::now() + self.max_age,
            uses,
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
        let (conn_a, _peer_a) = make_stream();
        let (conn_b, _peer_b) = make_stream();
        pool.put(conn_a, 0);
        pool.put(conn_b, 1);

        let (_conn, uses) = pool.take_idle().expect("first take should pop an entry");
        assert_eq!(uses, 1, "most recently returned conn comes back first");
        let (_conn, uses) = pool.take_idle().expect("second take should pop an entry");
        assert_eq!(uses, 0);
        assert!(pool.take_idle().is_none());
    }

    #[test]
    fn put_discards_at_uses_cap() {
        let pool = Pool::new();
        // Surge snell-server v5.0.1 closes after the second session, so a
        // conn that has already served 2 sessions must not be pooled.
        let (capped, _peer_capped) = make_stream();
        pool.put(capped, 2);
        assert!(pool.take_idle().is_none());

        let (reusable, _peer_reusable) = make_stream();
        pool.put(reusable, 1);
        let (_conn, uses) = pool.take_idle().expect("uses=1 should be pooled");
        assert_eq!(uses, 1);
    }

    #[test]
    fn custom_limits_apply() {
        let pool = Pool::with_limits(1, Duration::from_secs(60), u32::MAX);
        let (busy, _peer_busy) = make_stream();
        pool.put(busy, 1000);
        let (extra, _peer_extra) = make_stream();
        pool.put(extra, 0);
        assert_eq!(pool.idle_count(), 1, "max_size caps idle entries");
        let (_conn, uses) = pool.take_idle().expect("uncapped uses are pooled");
        assert_eq!(uses, 1000);

        let expired = Pool::with_limits(4, Duration::ZERO, u32::MAX);
        let (conn, _peer) = make_stream();
        expired.put(conn, 0);
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
            pool.put(conn, 0);
        }
        for i in 0..10 {
            assert!(
                pool.take_idle().is_some(),
                "take {i} should pop a pooled conn"
            );
        }
        assert!(pool.take_idle().is_none(), "pool is capped at 10 entries");
    }
}
