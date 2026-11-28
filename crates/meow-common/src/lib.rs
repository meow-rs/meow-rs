//! Core traits and types for the meow-rs proxy kernel.
//!
//! This is the workspace contract crate: [`ProxyAdapter`], [`Rule`],
//! [`Metadata`], connection types, and shared error values used by every
//! other meow crate.

/// Largest `u64` seconds value a config field may carry into
/// `Duration::from_secs` + `Instant`/`tokio`-timer arithmetic. Beyond a few
/// hundred years `Instant + Duration` overflows and panics, and the release
/// profile's `panic = "abort"` turns that into a process crash — provider or
/// subscription-controlled interval/timeout fields must never reach it
/// (issue #648). Ten years is far beyond any meaningful value while staying
/// representable on every supported platform.
pub const MAX_DURATION_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// RFC 3339 rendering of the Unix epoch — the "never happened" timestamp
/// the API reports for unset times (e.g. a never-hit rule's `hitAt`).
/// Deliberately the Unix epoch, not mihomo's `"0001-01-01T00:00:00Z"`
/// (Go's zero `time.Time`) — see the compat doc.
pub const EPOCH_RFC3339: &str = "1970-01-01T00:00:00Z";

pub mod acl;
pub mod adapter;
pub mod adapter_type;
pub mod anytls_padding;
pub mod atomic;
pub mod auth;
pub mod backoff;
pub mod chain_health;
pub mod conn;
pub mod conn_notes;
pub mod controller_file;
pub mod dial;
pub mod dns_mode;
pub mod error;
pub mod fs_util;
pub mod home_dir;
pub mod inbound;
pub mod logbook;
pub mod metadata;
pub mod network;
pub mod nftset;
pub mod outbound_iface;
pub mod process_lookup;
pub mod protocol_clock;
pub mod replay_window;
pub mod rule;
pub mod sniffer;
pub mod socket_protect;
pub mod tcp_opts;
pub mod traffic;
pub mod traffic_ledger;
pub mod tunnel_mode;
pub mod vless_reality;
// Shared YAML-ingest guard used by meow-config and meow-cli — internal
// plumbing, not part of this published crate's documented API surface.
#[doc(hidden)]
pub mod yaml;

pub use acl::LanAcl;
pub use adapter::{
    reset_sessions_reachable, DelayHistory, GroupDisplay, NodeDialerOpts, ProviderSlot, Proxy,
    ProxyAdapter, ProxyHealth, ProxySelection, ProxyState, RematchAction,
};
pub use adapter_type::{AdapterType, ConnType};
pub use auth::{AuthConfig, Credentials};
pub use backoff::ErrorBackoff;
pub use chain_health::{
    failure_reason, Blame, CarrierChange, ChainHealth, ChainTarget, ChainVerdict,
    CLOSED_BEFORE_REPLY,
};
pub use conn::{PollPacketConn, ProxyConn, ProxyPacketConn, UdpPacket, WriteBytes};
pub use dial::{with_dial_timeout, DIAL_TIMEOUT};
pub use dns_mode::DnsMode;
pub use error::{MeowError, Result};
pub use fs_util::{sweep_scratch_siblings, sweep_scratch_siblings_excluding, SCRATCH_STALE_AGE};
pub use home_dir::{meow_home_dir, resolved_home_dir, set_home_dir, xdg_home_dir};
pub use inbound::InboundRouteOverride;
pub use metadata::{is_valid_host, metadata_ip_literal, AddrDisplay, Metadata};
pub use network::Network;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use outbound_iface::apply_outbound_interface;
#[cfg(all(
    not(target_env = "ohos"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub use outbound_iface::apply_outbound_interface_for_peer;
pub use outbound_iface::{install_outbound_interface, outbound_interface, OutboundIfaceGuard};
pub use process_lookup::{
    disable_socket_table_cache, find_process, find_process_async, FlowLookup, ProcessInfo,
    ProcessLookupMode, ProcessLookupPolicy,
};
pub use protocol_clock::{protocol_now, set_protocol_offset_ns};
pub use replay_window::ReplayWindow;
pub use rule::{MatchDemand, Rule, RuleMatchHelper, RuleType, TargetCheck, TargetProbe};
pub use sniffer::SnifferConfig;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub use socket_protect::set_listener_socket_mark;
pub use socket_protect::{
    apply_ip_version_filter, bind_udp, bind_udp_for_peer, brutal_carrier_scope,
    canonical_socket_addr, connect_tcp, connect_tcp_candidates, connect_tcp_host, dialer_opts,
    dialer_opts_scope, effective_user_agent, enlarge_udp_recv_buffer, global_dialer_opts,
    global_interface_name, global_ua, is_valid_http_header_value, pin_routing_mark, resolve_host,
    resolve_host_all, resolve_host_all_via, routing_mark, routing_mark_pinned,
    set_global_interface_name, set_global_ua, set_routing_mark, BrutalCarrier, DialerOpts,
    GlobalDialerOpts, IpVersion, RoutingMarkPin, DEFAULT_USER_AGENT,
};
pub use tcp_opts::{
    outbound_tcp_keepalive, set_outbound_tcp_keepalive, OutboundTcpKeepalive, TcpKeepaliveConfig,
};
// Host-resolver hook is cross-platform (iOS installs it without a protector).
pub use socket_protect::{clear_host_resolver, host_resolver, set_host_resolver, HostResolver};
// Socket protector is Android / OpenHarmony only (raw-fd `protect(fd)`).
#[cfg(any(target_os = "android", target_env = "ohos"))]
pub use socket_protect::{
    clear_socket_protector, set_socket_protector, socket_protector, SocketProtector,
};
// OpenHarmony has no protectable system resolver; the embedder supplies one.
#[cfg(target_env = "ohos")]
pub use socket_protect::{clear_bootstrap_host_resolver, set_bootstrap_host_resolver};
pub use traffic::{ProxyTraffic, ProxyTrafficSource};
pub use tunnel_mode::TunnelMode;
pub use vless_reality::{
    VlessRealityMimicMode, VlessRealityMimicSpec, MIMIC_DEFAULT_MAX_CONCURRENT_PROBES,
    MIMIC_DEFAULT_PROBE_TIMEOUT_MS, MIMIC_DEFAULT_QUIESCENCE_MAX_MS,
    MIMIC_DEFAULT_QUIESCENCE_MIN_MS, MIMIC_MAX_CONCURRENT_PROBES_RANGE,
    MIMIC_PROBE_TIMEOUT_MS_RANGE, MIMIC_QUIESCENCE_MAX_MS_RANGE, MIMIC_QUIESCENCE_MIN_MS_RANGE,
};

pub mod health_check;
pub use health_check::HealthCheckSpec;
