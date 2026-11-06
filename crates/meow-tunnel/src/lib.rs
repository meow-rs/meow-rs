//! Core routing engine for the meow-rs proxy kernel.
//!
//! TCP/UDP relay, rule-matching dispatch, and connection statistics.
//! [`Tunnel`] is the shared engine listeners hand connections to.

mod app_lookup;
pub mod health_check;
pub mod match_engine;
pub mod relay;
pub mod rule_ir;
mod sniff;
pub mod statistics;
pub mod tcp;
pub mod tunnel;
pub mod udp;

/// Called by every test that captures log lines with a scoped subscriber.
///
/// `with_default` scopes the subscriber to one thread, but callsite interest
/// and the max-level hint are process-wide. A callsite another test thread
/// hits first, with no subscriber of its own, can cache `never` while a
/// capture registers, and the capture's lines are then dropped before they
/// reach its sink. A global subscriber that answers `sometimes` for every
/// callsite and sets no level hint keeps every event checked per thread.
#[cfg(test)]
pub(crate) fn install_capture_fallback() {
    use tracing::span::{Attributes, Id, Record};
    use tracing::subscriber::Interest;
    use tracing::{Event, Metadata, Subscriber};

    struct Fallback;

    impl Subscriber for Fallback {
        fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
            Interest::sometimes()
        }
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            false
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, _: &Event<'_>) {}
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = tracing::subscriber::set_global_default(Fallback);
    });
}

pub use health_check::HealthCheckSupervisor;
pub use relay::{
    copy_bidirectional_buf, copy_bidirectional_buf_tracked, copy_bidirectional_buf_tracked_idle,
    copy_bidirectional_buf_tracked_splice, copy_bidirectional_buf_tracked_splice_idle,
    proxy_conn_tcp_view, tcp_view, TcpView, RELAY_BUF_SIZE,
};
pub use statistics::{ProxyTraffic, Statistics};
pub use tcp::{route_inbound_tcp, ConnectionGuard};
pub use tunnel::{
    MatchedRule, OutboundFlush, PreHandleVerdict, ResolvedTarget, TrackedTcp, TunHandle, Tunnel,
    TunnelInner, UsingProxy,
};
pub use udp::UdpFlushWatch;
