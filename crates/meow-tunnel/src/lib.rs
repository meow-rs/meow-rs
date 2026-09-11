//! Core routing engine for the meow-rs proxy kernel.
//!
//! TCP/UDP relay, rule-matching dispatch, and connection statistics.
//! [`Tunnel`] is the shared engine listeners hand connections to.

pub mod health_check;
pub mod match_engine;
pub mod relay;
pub mod rule_ir;
pub mod statistics;
pub mod tcp;
pub mod tunnel;
pub mod udp;

pub use health_check::{extract_specs, HealthCheckSpec, HealthCheckSupervisor};
pub use relay::{copy_bidirectional_buf, copy_bidirectional_buf_tracked, RELAY_BUF_SIZE};
pub use statistics::Statistics;
pub use tcp::{route_inbound_tcp, ConnectionGuard};
pub use tunnel::{TunHandle, Tunnel};
