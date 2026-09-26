//! Exponential backoff for loops that retry a fallible syscall.
//!
//! Accept/recv loops (`TcpListener::accept`, UDP `recv_from`) must not tear
//! down on a transient `EMFILE`/`ECONNABORTED`, but an unconditional `continue`
//! spins hot when the failure is persistent — fd exhaustion makes `accept`
//! return `Err` immediately forever, burning a worker and flooding the log.
//! [`ErrorBackoff`] delays retries exponentially (10 ms → doubling → 1 s cap)
//! and resets on the first success, so a recovered listener pays nothing and a
//! wedged one retries at most once per second.
//!
//! Per-connection errors are exempt: tokio surfaces `accept()` failures for
//! pending connections that were reset before the accept (`ECONNABORTED`),
//! the pending-network-error set Linux passes up through `accept(2)`
//! (`ENETUNREACH`, `EHOSTUNREACH`, `ENETDOWN`, `EOPNOTSUPP`, `EPROTO`,
//! `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET` — the man page says treat them like
//! `EAGAIN`), and ICMP async errors on UDP recv (`ECONNREFUSED` on connected
//! sockets, `WSAECONNRESET`/`WSAEHOSTUNREACH`/`WSAENETUNREACH`/`WSAENETRESET`/
//! `WSAEHOSTDOWN`/`WSAEMSGSIZE` on Windows). Each such error consumed a
//! queue entry — the call made forward progress — so sleeping would only
//! add latency under an abortive connect or ICMP flood while the socket
//! itself stays healthy. Only socket-level failures (`EMFILE`, `ENFILE`,
//! `ENOMEM`, `ENOBUFS`, …) engage the delay.

use std::io;
use std::time::Duration;

/// Delay after the first consecutive failure. Small enough that a
/// single transient error costs ~10 ms of accept throughput.
const INITIAL_DELAY: Duration = Duration::from_millis(10);
/// Ceiling on consecutive-failure delay: one retry per second, which also
/// rate-limits the per-error log line under a persistent failure.
const MAX_DELAY: Duration = Duration::from_secs(1);

/// `true` when `e` is a per-connection/per-packet error rather than a
/// socket-level failure. Each dequeues a pending queue entry — forward
/// progress — so the retry loop must not sleep on them; `Interrupted` is
/// exempt on the weaker grounds that retrying a signal interruption is free
/// (mio does not auto-retry `EINTR`). Notable non-exemptions that sleep:
/// `EPERM`/`EACCES` (`PermissionDenied`) — a persistent deny-all
/// netfilter/LSM rule must not spin; Darwin's `EPROTOTYPE` —
/// its reports straddle per-conn teardown and persistent AppProxy
/// interception; and the man page's secondary kernel list
/// (`ENOSR`/`ESOCKTNOSUPPORT`/`EPROTONOSUPPORT`/`ETIMEDOUT`) — rare and
/// unverifiable as progress, so they take the safe direction.
fn is_per_connection(e: &io::Error) -> bool {
    match e.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted
        // Part of the `accept(2)` pending set on unix *and* the async-ICMP
        // family Windows reports on unconnected UDP `recvfrom`
        // (`WSAENETUNREACH`/`WSAEHOSTUNREACH`) — per-packet progress on
        // every supported platform.
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable => true,
        // `ENETDOWN` is the only errno that decodes to `NetworkDown`, and
        // on unix it is only ever a pending accept error — while Windows
        // `WSAENETDOWN` means the network subsystem itself failed, so the
        // kind must sleep there. `EOPNOTSUPP` is handled in the errno arm
        // instead of here: its `Unsupported` kind also covers `ENOSYS`,
        // a persistent failure (seccomp/sandboxed runtimes) that must
        // keep sleeping.
        #[cfg(unix)]
        io::ErrorKind::NetworkDown => true,
        _ => is_pending_errno(e),
    }
}

/// `accept(2)` pending-error errnos that Rust maps to `Uncategorized`
/// (`EPROTO`/`ENOPROTOOPT`/`EHOSTDOWN`/`ENONET`) or to a wider-than-
/// intended `ErrorKind` (`EOPNOTSUPP` → `Unsupported`, which also covers
/// the persistent `ENOSYS`). Linux-only `ENONET` needs its own `cfg` —
/// the libc constant does not exist on other unix targets.
#[cfg(unix)]
fn is_pending_errno(e: &io::Error) -> bool {
    match e.raw_os_error() {
        Some(libc::EPROTO | libc::ENOPROTOOPT | libc::EHOSTDOWN | libc::EOPNOTSUPP) => true,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Some(libc::ENONET) => true,
        _ => false,
    }
}

/// ICMP async errors Windows reports on an unconnected UDP `recvfrom`,
/// decoded to `Uncategorized`: `WSAENETRESET` (10052) and
/// `WSAEHOSTDOWN` (10064) mark a pending per-datagram error, and
/// `WSAEMSGSIZE` (10040) means the datagram was consumed but truncated.
#[cfg(windows)]
fn is_pending_errno(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(10052 | 10040 | 10064))
}

#[cfg(not(any(unix, windows)))]
fn is_pending_errno(_: &io::Error) -> bool {
    false
}

/// Exponential backoff state for a retry loop. Call [`Self::failed`] after
/// each error and [`Self::succeeded`] after each success.
#[derive(Debug)]
pub struct ErrorBackoff {
    delay: Duration,
}

impl ErrorBackoff {
    pub const fn new() -> Self {
        Self {
            delay: INITIAL_DELAY,
        }
    }

    /// Sleep for the current delay, then double it (capped at `MAX_DELAY` —
    /// 1 s); returns `true` when the delay actually engaged. Call this when
    /// the retried operation failed. Per-connection errors (`ECONNABORTED`,
    /// `ECONNREFUSED`, `ENETUNREACH`, …) return `false` immediately without
    /// touching `delay`: they are queue progress, not socket failure —
    /// progress neither proves the socket healed (no reset) nor deepens the
    /// penalty (no growth). The return value lets a call site log loudly
    /// only for socket-level failures, keeping per-packet noise at `debug!`.
    pub async fn failed(&mut self, err: &io::Error) -> bool {
        if is_per_connection(err) {
            return false;
        }
        tokio::time::sleep(self.delay).await;
        self.delay = (self.delay * 2).min(MAX_DELAY);
        true
    }

    /// Reset to `INITIAL_DELAY`. Call this when the retried operation
    /// succeeded.
    pub fn succeeded(&mut self) {
        self.delay = INITIAL_DELAY;
    }
}

impl Default for ErrorBackoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    /// Stand-in for a socket-level failure (EMFILE/ENFILE/ENOMEM/ENOBUFS…):
    /// any kind outside the per-connection set engages the delay.
    fn socket_error() -> io::Error {
        io::Error::other("socket-level failure")
    }

    /// Errnos from the Linux `accept(2)` pending-error set that either
    /// have no `ErrorKind` name (decode to `Uncategorized`) or decode to
    /// a wider kind than intended (`EOPNOTSUPP` → `Unsupported` also
    /// covers `ENOSYS`). `ENONET` exists only on Linux-kernel targets.
    #[cfg(unix)]
    const PENDING_ERRNOS: &[i32] = &[
        libc::EPROTO,
        libc::ENOPROTOOPT,
        libc::EHOSTDOWN,
        libc::EOPNOTSUPP,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::ENONET,
    ];

    #[tokio::test(start_paused = true)]
    async fn delay_doubles_then_caps() {
        // Pin the numeric contract, not just the shape: the documented
        // 10 ms → 1 s curve is the behavior callers rely on.
        assert_eq!(INITIAL_DELAY, Duration::from_millis(10));
        assert_eq!(MAX_DELAY, Duration::from_secs(1));

        let mut backoff = ErrorBackoff::new();
        let start = Instant::now();

        backoff.failed(&socket_error()).await;
        assert_eq!(start.elapsed(), INITIAL_DELAY);
        backoff.failed(&socket_error()).await;
        // Cumulative: the second failure waited INITIAL_DELAY * 2 on top of
        // the first INITIAL_DELAY.
        assert_eq!(start.elapsed(), INITIAL_DELAY + INITIAL_DELAY * 2);

        // Drive to the cap, then confirm it stays there.
        for _ in 0..16 {
            backoff.failed(&socket_error()).await;
        }
        let at_cap = start.elapsed();
        backoff.failed(&socket_error()).await;
        assert_eq!(start.elapsed() - at_cap, MAX_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn success_resets_to_initial() {
        let mut backoff = ErrorBackoff::new();
        for _ in 0..16 {
            backoff.failed(&socket_error()).await;
        }
        backoff.succeeded();
        let start = Instant::now();
        backoff.failed(&socket_error()).await;
        assert_eq!(start.elapsed(), INITIAL_DELAY);
    }

    /// An aborted pending connection consumed a backlog slot — the accept is
    /// making progress and must not be delayed (RST-after-handshake scan
    /// floods would otherwise throttle healthy accepts toward 1/s). The
    /// Linux `accept(2)` pending-network-error set is progress too.
    #[tokio::test(start_paused = true)]
    async fn per_connection_errors_never_sleep() {
        let mut backoff = ErrorBackoff::new();
        let start = Instant::now();
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            // unix-only exemption: the same `ErrorKind` is a persistent
            // socket-level failure on Windows (`WSAENETDOWN`).
            #[cfg(unix)]
            io::ErrorKind::NetworkDown,
        ] {
            backoff.failed(&io::Error::from(kind)).await;
        }
        // The pending-error errnos with no `ErrorKind` name (decode to
        // `Uncategorized`, so `from` alone cannot pin them).
        #[cfg(unix)]
        for errno in PENDING_ERRNOS {
            backoff.failed(&io::Error::from_raw_os_error(*errno)).await;
        }
        #[cfg(windows)]
        for errno in [10052, 10040, 10064] {
            backoff.failed(&io::Error::from_raw_os_error(errno)).await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
        // And they must not grow the delay: the next socket-level error
        // still waits only INITIAL_DELAY.
        backoff.failed(&socket_error()).await;
        assert_eq!(start.elapsed(), INITIAL_DELAY);
    }

    /// Progress errors must not reset an already-raised delay either: an
    /// embryonic dequeue interleaved in an EMFILE storm does not prove the
    /// fd pressure cleared — only a successful accept/recv does.
    #[tokio::test(start_paused = true)]
    async fn per_connection_errors_do_not_reset() {
        let mut backoff = ErrorBackoff::new();
        for _ in 0..4 {
            backoff.failed(&socket_error()).await;
        }
        assert!(
            !backoff
                .failed(&io::Error::from(io::ErrorKind::ConnectionAborted))
                .await
        );
        let start = Instant::now();
        assert!(backoff.failed(&socket_error()).await);
        assert_eq!(start.elapsed(), INITIAL_DELAY * 16);
    }

    /// Deliberate non-exemptions still sleep: a persistent deny-all
    /// (`EPERM`/`WSAEACCES`) must not spin; a kind-only `Unsupported`
    /// (the `ENOSYS` class — absent syscall under seccomp/sandboxed
    /// runtimes) is persistent, not the pending `EOPNOTSUPP`; and on
    /// Windows `WSAENETDOWN` reports a dead network subsystem, not a
    /// consumed queue entry.
    #[tokio::test(start_paused = true)]
    async fn persistent_kinds_still_sleep() {
        let mut backoff = ErrorBackoff::new();
        let start = Instant::now();
        // 10 ms, delay → 20 ms.
        assert!(
            backoff
                .failed(&io::Error::from(io::ErrorKind::PermissionDenied))
                .await
        );
        // 20 ms, delay → 40 ms.
        assert!(
            backoff
                .failed(&io::Error::from(io::ErrorKind::Unsupported))
                .await
        );
        #[cfg(windows)]
        {
            // 40 ms, delay → 80 ms.
            assert!(
                backoff
                    .failed(&io::Error::from(io::ErrorKind::NetworkDown))
                    .await
            );
            assert_eq!(start.elapsed(), INITIAL_DELAY * 7);
        }
        #[cfg(not(windows))]
        assert_eq!(start.elapsed(), INITIAL_DELAY * 3);
    }
}
