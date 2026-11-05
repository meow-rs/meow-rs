//! Inbound-socket TCP keepalive: every TCP socket a listener *accepts* gets
//! `SO_KEEPALIVE` plus the configured idle/interval/probe knobs applied
//! before any handshake or relay traffic, so a silently-dead LAN peer is
//! reaped by the kernel instead of pinning a connection (and its
//! `max_connections` permit) forever. Mirrors the posture Go's `net`
//! package applied implicitly to every accepted socket — lost in the
//! tokio port — restored here as a configurable knob.
//!
//! Application is best-effort: a failed `setsockopt` degrades to "no
//! keepalive" and logs at debug, never `warn` — a lost keepalive is a soft
//! degradation, not a misconfiguration.

/// Apply `cfg`'s keepalive posture to an accepted inbound `stream`.
/// `cfg.enabled == false` performs no `setsockopt` at all. `listener`
/// names the owning listener so a multi-inbound failure log stays
/// attributable.
#[cfg(any(unix, windows))]
pub(crate) fn apply(
    stream: &tokio::net::TcpStream,
    cfg: meow_common::TcpKeepaliveConfig,
    listener: &str,
) {
    if !cfg.enabled {
        return;
    }
    let ka = socket2::TcpKeepalive::new().with_time(cfg.idle);
    // `with_interval` exists only on the socket2-0.5.10 platform set below
    // (its own `#[cfg]` list, copied verbatim); on the remaining unix
    // targets (e.g. OpenBSD/Haiku) keepalive still engages with the OS
    // default interval.
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
    let ka = ka.with_interval(cfg.interval);
    // `with_retries` — the same platform set MINUS windows (probe count is
    // not settable via `SIO_KEEPALIVE_VALS`; no stub — the OS default
    // applies there). It additionally requires socket2's `all` feature,
    // which the workspace dependency always enables.
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
    let ka = ka.with_retries(cfg.probes);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&ka) {
        tracing::debug!("listener '{listener}': inbound TCP keepalive setsockopt failed: {e}");
    }
}

/// Non-unix/windows stub (mirrors the anytls gate): exotic targets degrade
/// silently to no keepalive — the relay idle timeout still bounds the
/// connection.
#[cfg(not(any(unix, windows)))]
pub(crate) fn apply(
    _stream: &tokio::net::TcpStream,
    _cfg: meow_common::TcpKeepaliveConfig,
    _listener: &str,
) {
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn apply_sets_keepalive_on_accepted_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();

        apply(
            &accepted,
            meow_common::TcpKeepaliveConfig::default(),
            "test",
        );

        let sock = socket2::SockRef::from(&accepted);
        assert!(
            sock.keepalive().unwrap(),
            "accepted socket must report SO_KEEPALIVE after apply"
        );
        // The timing getters are themselves cfg-gated (keepalive_time is
        // absent on windows/openbsd/haiku/vita); Linux is the deployment
        // target, so pin the full knob set there.
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                sock.keepalive_time().unwrap(),
                std::time::Duration::from_secs(
                    meow_common::tcp_opts::DEFAULT_TCP_KEEPALIVE_IDLE_SECS
                )
            );
            assert_eq!(
                sock.keepalive_interval().unwrap(),
                std::time::Duration::from_secs(
                    meow_common::tcp_opts::DEFAULT_TCP_KEEPALIVE_INTERVAL_SECS
                )
            );
            assert_eq!(
                sock.keepalive_retries().unwrap(),
                meow_common::tcp_opts::DEFAULT_TCP_KEEPALIVE_PROBES
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn disabled_config_writes_no_keepalive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();

        apply(
            &accepted,
            meow_common::TcpKeepaliveConfig {
                enabled: false,
                ..Default::default()
            },
            "test",
        );

        assert!(
            !socket2::SockRef::from(&accepted).keepalive().unwrap(),
            "tcp-keepalive: false must perform no keepalive setsockopt"
        );
    }
}
