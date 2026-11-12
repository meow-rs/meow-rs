//! WireGuard outbound (`type: wireguard`) — issue #899 Phase-1.
//!
//! A userspace WireGuard client: the vendored, ring-free boringtun noise
//! session (`meow-wireguard`) encrypts for a smoltcp TCP/IP stack, both
//! owned by a single actor thread (`pump`). Standard WireGuard only —
//! AmneziaWG, the `ip-stack: system` variant and a DNS-resolved `dns:`
//! list are out of Phase-1 scope.

mod adapter;
mod config;
mod pump;

pub use adapter::WireGuardAdapter;
pub use config::WireGuardConfig;
