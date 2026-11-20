//! Network-related utilities (TCP tuning)

use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

/// Enable `TCP_NODELAY` on a TCP stream (best-effort).
pub fn set_nodelay(stream: &TcpStream, context: &str) {
    if let Err(err) = stream.set_nodelay(true) {
        debug!(
            "[Net] Failed to enable TCP_NODELAY for {}: {}",
            context, err
        );
    }
}

/// Enable low-latency options on a TCP stream (best-effort).
///
/// Only for streams this crate dialed itself: a host-installed
/// `TcpDialer` already applied the host app's outbound keepalive policy,
/// and overwriting it here would silently fight that posture — callers
/// use [`set_nodelay`] alone on bridge-owned streams.
pub fn configure_tcp_stream(stream: &TcpStream, context: &str) {
    set_nodelay(stream, context);

    #[cfg(any(unix, windows))]
    {
        use socket2::{SockRef, TcpKeepalive};

        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(120))
            .with_interval(Duration::from_secs(30));

        if let Err(err) = SockRef::from(stream).set_tcp_keepalive(&keepalive) {
            debug!(
                "[Net] Failed to configure TCP keepalive for {}: {}",
                context, err
            );
        }
    }
}
