//! Shared TCP inbound options (`tcp-keepalive*` / `tcp-idle-timeout`),
//! consumed by `meow-config` (parse + validate) and `meow-listener`
//! (apply at accept time) — same crate-boundary role as
//! [`crate::SnifferConfig`].

use std::time::Duration;

/// Seconds of socket silence before the first keepalive probe — the
/// resolved default for `tcp-keepalive-idle` (`TCP_KEEPIDLE` /
/// `TCP_KEEPALIVE` / `SIO_KEEPALIVE_VALS.keepalivetime`).
pub const DEFAULT_TCP_KEEPALIVE_IDLE_SECS: u64 = 300;

/// Seconds between keepalive probes — the resolved default for
/// `tcp-keepalive-interval` (`TCP_KEEPINTVL` /
/// `SIO_KEEPALIVE_VALS.keepaliveinterval`).
pub const DEFAULT_TCP_KEEPALIVE_INTERVAL_SECS: u64 = 30;

/// Unanswered probes before the kernel declares the peer dead — the
/// resolved default for `tcp-keepalive-probes` (`TCP_KEEPCNT`). Not
/// settable on Windows (the `SIO_KEEPALIVE_VALS` API has no probe-count
/// field; the OS default applies there).
pub const DEFAULT_TCP_KEEPALIVE_PROBES: u32 = 5;

/// Ceiling for `tcp-keepalive-idle` / `tcp-keepalive-interval`, in
/// seconds: Linux's `MAX_TCP_KEEPIDLE`/`MAX_TCP_KEEPINTVL` — the kernel
/// rejects (`EINVAL`) values above it, and config validation applies the
/// strictest-platform bound uniformly so an accepted value can never
/// `EINVAL` at `setsockopt` time on any target.
pub const MAX_TCP_KEEPALIVE_SECS: u64 = 32767;

/// Reference bound for `tcp-idle-timeout`, in seconds. Not used as the
/// config parse default — an absent `tcp-idle-timeout` key resolves to
/// `None` (disabled) rather than this value, preserving pre-894
/// behaviour (no idle bound by default). Retained for callers and docs
/// that want the canonical opt-in value.
pub const DEFAULT_TCP_IDLE_TIMEOUT_SECS: u64 = 600;

/// Resolved keepalive posture applied to every TCP socket a listener
/// accepts (mixed/http/socks5/tproxy/shadowsocks inbounds; TUN netstack
/// flows have no host socket and are covered by the relay idle bound
/// instead). `Copy` so accept loops and per-connection closures capture
/// it by value.
///
/// On Linux/Android/musl the three knobs map to
/// `TCP_KEEPIDLE`/`TCP_KEEPINTVL`/`TCP_KEEPCNT` — a fully dead peer is
/// reaped at `idle + interval × probes` (450 s at the defaults). On
/// macOS/iOS `idle` maps to `TCP_KEEPALIVE` and interval/probes are
/// supported; on Windows `idle`/`interval` map into `SIO_KEEPALIVE_VALS`
/// and `probes` is ignored (not settable). On OpenBSD/Haiku `idle` is a
/// no-op — keepalive is still enabled, timing falls back to OS defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpKeepaliveConfig {
    /// `tcp-keepalive` — `false` performs no keepalive `setsockopt` at all
    /// (config-level kill switch).
    pub enabled: bool,
    /// `tcp-keepalive-idle` — silence before the first probe.
    pub idle: Duration,
    /// `tcp-keepalive-interval` — spacing between probes.
    pub interval: Duration,
    /// `tcp-keepalive-probes` — unanswered probes before the kernel drops
    /// the connection. Capped at 127 by config validation (Linux rejects
    /// higher `TCP_KEEPCNT` with `EINVAL`).
    pub probes: u32,
}

impl Default for TcpKeepaliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle: Duration::from_secs(DEFAULT_TCP_KEEPALIVE_IDLE_SECS),
            interval: Duration::from_secs(DEFAULT_TCP_KEEPALIVE_INTERVAL_SECS),
            probes: DEFAULT_TCP_KEEPALIVE_PROBES,
        }
    }
}
