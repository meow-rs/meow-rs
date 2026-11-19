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

/// mihomo's default for `keep-alive-idle`/`keep-alive-interval`, in
/// seconds — an omitted *or zero* knob resolves to it (upstream treats 0
/// as "leave the default", never as an actual zero).
pub const DEFAULT_OUTBOUND_KEEPALIVE_SECS: u64 = 15;

/// Unanswered probes before the kernel drops the connection for outbound
/// dials — mihomo's fixed 9; `keep-alive-*` has no probe-count knob.
/// Not settable on Windows (`SIO_KEEPALIVE_VALS` has no count field; the
/// OS default applies there), like [`DEFAULT_TCP_KEEPALIVE_PROBES`].
pub const OUTBOUND_KEEPALIVE_PROBES: u32 = 9;

/// Resolved keepalive posture applied to every *outbound* TCP socket
/// [`crate::socket_protect::connect_tcp`] dials — mihomo's
/// `keep-alive-idle`/`keep-alive-interval`/`disable-keep-alive`, scoped
/// to outbound only: upstream's same keys also cover accepted sockets,
/// but meow models the inbound side separately (`tcp-keepalive*` →
/// [`TcpKeepaliveConfig`]). Kept independent of `TcpKeepaliveConfig` so
/// the two policies can never alias each other's knobs or defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundTcpKeepalive {
    /// `false` when `disable-keep-alive: true` — clears `SO_KEEPALIVE`
    /// explicitly rather than inheriting the OS default.
    pub enabled: bool,
    /// `keep-alive-idle` — silence before the first probe.
    pub idle: Duration,
    /// `keep-alive-interval` — spacing between probes.
    pub interval: Duration,
    /// [`OUTBOUND_KEEPALIVE_PROBES`] — not configurable in this batch.
    pub probes: u32,
}

impl Default for OutboundTcpKeepalive {
    fn default() -> Self {
        Self {
            enabled: true,
            idle: Duration::from_secs(DEFAULT_OUTBOUND_KEEPALIVE_SECS),
            interval: Duration::from_secs(DEFAULT_OUTBOUND_KEEPALIVE_SECS),
            probes: OUTBOUND_KEEPALIVE_PROBES,
        }
    }
}

impl OutboundTcpKeepalive {
    /// Apply this posture to a just-dialed outbound stream. Best-effort:
    /// an unsupported sub-option or a failed `setsockopt` degrades to
    /// "different keepalive timing" and logs at debug — a lost keepalive
    /// must never break connectivity.
    ///
    /// Gated to the targets `Cargo.toml` gives the socket2 dep
    /// (Android/Linux/macOS/Windows) — iOS/tvOS take the libc path below
    /// and the remaining BSDs the stub.
    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    ))]
    pub fn apply(&self, stream: &tokio::net::TcpStream) {
        let sock = socket2::SockRef::from(stream);
        if let Err(e) = sock.set_keepalive(self.enabled) {
            tracing::debug!("outbound TCP keepalive setsockopt failed: {e}");
        }
        if !self.enabled {
            return;
        }
        let ka = socket2::TcpKeepalive::new().with_time(self.idle);
        // Same platform gates as the inbound apply (`meow-listener`'s
        // keepalive.rs): `with_interval`/`with_retries` exist only on
        // these socket2 cfg sets; the remaining targets engage keepalive
        // with OS-default timing.
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "windows",
            target_os = "cygwin",
        ))]
        let ka = ka.with_interval(self.interval);
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "cygwin",
        ))]
        let ka = ka.with_retries(self.probes);
        if let Err(e) = sock.set_tcp_keepalive(&ka) {
            tracing::debug!("outbound TCP keepalive setsockopt failed: {e}");
        }
    }

    /// libc path for the Darwin targets the `socket2` dep does not cover
    /// — iOS/tvOS are Darwin, so `TCP_KEEPALIVE`/`TCP_KEEPINTVL`/
    /// `TCP_KEEPCNT` exist and the upstream contract (keepalive applied
    /// where supported) holds through raw `setsockopt`.
    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    pub fn apply(&self, stream: &tokio::net::TcpStream) {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let set = |level: libc::c_int, name: libc::c_int, value: libc::c_int| {
            // SAFETY: `fd` is a live socket for the call's duration;
            // `value` is a plain int the kernel copies in.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    name,
                    (&raw const value).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                tracing::debug!(
                    "outbound TCP keepalive setsockopt({name}) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        };
        set(
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            libc::c_int::from(self.enabled),
        );
        if !self.enabled {
            return;
        }
        let secs =
            |d: Duration| libc::c_int::try_from(d.as_secs().max(1)).unwrap_or(libc::c_int::MAX);
        set(libc::IPPROTO_TCP, libc::TCP_KEEPALIVE, secs(self.idle));
        set(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, secs(self.interval));
        set(
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            libc::c_int::try_from(self.probes).unwrap_or(libc::c_int::MAX),
        );
    }

    /// Stub for the remaining targets (the BSDs without the socket2 dep):
    /// degrade to no keepalive setsockopts — the relay idle timeout still
    /// bounds the connection.
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "tvos",
        target_os = "windows"
    )))]
    pub fn apply(&self, _stream: &tokio::net::TcpStream) {}
}

/// The installed outbound keepalive policy — process-global like
/// `set_routing_mark`/`set_global_ua`, snapshot once per `connect_tcp`
/// dial and applied to the connected stream. Installed at startup and on
/// every committed `PUT`/`PATCH /configs`; the default (enabled, 15 s /
/// 15 s / 9 probes) matches mihomo's when the config never says a word.
static OUTBOUND_TCP_KEEPALIVE: parking_lot::RwLock<OutboundTcpKeepalive> =
    parking_lot::RwLock::new(OutboundTcpKeepalive {
        enabled: true,
        idle: Duration::from_secs(DEFAULT_OUTBOUND_KEEPALIVE_SECS),
        interval: Duration::from_secs(DEFAULT_OUTBOUND_KEEPALIVE_SECS),
        probes: OUTBOUND_KEEPALIVE_PROBES,
    });

/// Snapshot of the live outbound keepalive policy.
pub fn outbound_tcp_keepalive() -> OutboundTcpKeepalive {
    *OUTBOUND_TCP_KEEPALIVE.read()
}

/// Install the outbound keepalive policy every later `connect_tcp` dial
/// applies. Sockets already dialed keep the posture they were built with.
pub fn set_outbound_tcp_keepalive(policy: OutboundTcpKeepalive) {
    *OUTBOUND_TCP_KEEPALIVE.write() = policy;
}
