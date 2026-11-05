//! Core routing engine for the meow-rs proxy kernel.
//!
//! TCP/UDP relay, rule-matching dispatch, and connection statistics.
//! [`Tunnel`] is the shared engine listeners hand connections to.

mod app_lookup;
pub mod health_check;
pub mod match_engine;
pub mod relay;
pub mod rule_ir;
pub mod rule_stats;
mod sniff;
pub mod statistics;
pub mod tcp;
pub mod tunnel;
pub mod udp;

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
