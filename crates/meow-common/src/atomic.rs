//! Platform-adaptive atomic type aliases.
//!
//! On targets with 64-bit atomics (x86_64, i686 Windows, aarch64, etc.)
//! these resolve to `AtomicU64`/`AtomicI64`. On targets lacking them
//! (e.g. MIPS32) they fall back to `AtomicU32`/`AtomicI32`.
//!
//! Trade-offs on 32-bit fallback targets:
//! - Traffic/byte counters wrap at 4 GiB (`u32::MAX`). REST/metrics totals
//!   are best-effort there; rates are unaffected.
//! - Millisecond clocks stored in these types wrap every ~49.7 days.
//!   Comparisons MUST be done in the truncated domain with `wrapping_sub`
//!   (see `UdpSession::idle_for`), never widened to `u64` first.

#[cfg(target_has_atomic = "64")]
pub type AtomicU = std::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
pub type AtomicU = std::sync::atomic::AtomicU32;

#[cfg(target_has_atomic = "64")]
pub type AtomicI = std::sync::atomic::AtomicI64;
#[cfg(not(target_has_atomic = "64"))]
pub type AtomicI = std::sync::atomic::AtomicI32;

#[cfg(target_has_atomic = "64")]
pub type Uint = u64;
#[cfg(not(target_has_atomic = "64"))]
pub type Uint = u32;

#[cfg(target_has_atomic = "64")]
pub type Int = i64;
#[cfg(not(target_has_atomic = "64"))]
pub type Int = i32;

/// Atomically increments `counter` and returns the NEW value widened to the
/// wire's `u64` domain — `None` once the space is exhausted, leaving the
/// counter untouched. `Uint::MAX` is never returned: it is the replay
/// window's always-reject sentinel, so a terminal counter must not emit it.
///
/// SIP022 packet-ID allocators use this for pre-incremented IDs (the first
/// datagram carries 1). On 64-bit targets `AtomicU` is u64 and exhaustion is
/// unreachable; on 32-bit fallback targets it is u32 and `None` is the
/// end-of-session signal (the caller re-keys or re-dials) rather than
/// wrapping onto IDs the peer's window has already spent.
///
/// A hand-written compare-exchange loop rather than `fetch_update`, which
/// Rust 1.99 deprecates in favour of `try_update` — newer than the MSRV.
#[inline]
pub fn checked_increment(counter: &AtomicU) -> Option<u64> {
    use std::sync::atomic::Ordering::Relaxed;
    let mut current = counter.load(Relaxed);
    loop {
        let next = current.checked_add(1).filter(|&n| n != Uint::MAX)?;
        match counter.compare_exchange_weak(current, next, Relaxed, Relaxed) {
            Ok(_) => {
                #[allow(
                    clippy::useless_conversion,
                    reason = "identity on 64-bit; u32→u64 widening on mips32"
                )]
                return Some(u64::from(next));
            }
            Err(actual) => current = actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn checked_increment_pre_increments() {
        let counter = AtomicU::new(0);
        assert_eq!(checked_increment(&counter), Some(1));
        assert_eq!(checked_increment(&counter), Some(2));
    }

    #[test]
    fn checked_increment_never_emits_the_sentinel() {
        let counter = AtomicU::new(Uint::MAX - 2);
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; u32→u64 widening on mips32"
        )]
        let last_legit = u64::from(Uint::MAX) - 1;
        assert_eq!(checked_increment(&counter), Some(last_legit));
        assert_eq!(
            checked_increment(&counter),
            None,
            "Uint::MAX is the window's always-reject sentinel"
        );
        assert_eq!(
            counter.load(Ordering::Relaxed),
            Uint::MAX - 1,
            "a refused increment leaves the counter terminal, not wrapped"
        );
        assert_eq!(checked_increment(&counter), None);
    }
}
