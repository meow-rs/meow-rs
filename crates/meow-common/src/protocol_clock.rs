//! The NTP-adjusted protocol clock (`protocol_now()`).
//!
//! Upstream mihomo feeds `ntp.Now()` into every timestamp a proxy
//! protocol stamps on the wire. This batch deliberately wires only the
//! two consumers whose wire peers actually compare the value against
//! *their* wall clock — VMess's auth-ID window and the REALITY
//! client's timestamp field — so a skewed host clock still produces
//! acceptable headers. TLS/QUIC certificate verification, logs, cache
//! timestamps and every monotonic timer keep plain wall/monotonic
//! time (issue #974).
//!
//! The offset is a single process-wide cell published by the NTP
//! supervisor: `None` before the first successful exchange and after
//! disable, so `protocol_now()` falls back to wall time until a sample
//! lands — matching upstream's zero-offset startup semantics.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime};

/// `i64::MIN` = no published offset.
static OFFSET_NS: AtomicI64 = AtomicI64::new(i64::MIN);

/// Publish the NTP offset (`server_time - local_wall`) the protocol
/// clock adds to wall time; `None` clears back to wall time. The
/// supervisor re-publishes on every successful exchange and clears on
/// disable, so a revoked offset never lingers behind a dead worker.
pub fn set_protocol_offset_ns(offset_ns: Option<i64>) {
    OFFSET_NS.store(offset_ns.unwrap_or(i64::MIN), Ordering::Release);
}

/// `now + published_offset`, or plain `SystemTime::now()` when no
/// offset is published. An absurd offset is impossible by construction
/// — the supervisor rejects samples beyond ±24 h before publishing.
pub fn protocol_now() -> SystemTime {
    let off = OFFSET_NS.load(Ordering::Acquire);
    if off == i64::MIN {
        return SystemTime::now();
    }
    let now = SystemTime::now();
    if off >= 0 {
        now.checked_add(Duration::from_nanos(off as u64))
    } else {
        now.checked_sub(Duration::from_nanos(off.unsigned_abs()))
    }
    .unwrap_or(now)
}
