//! Inbound protocol listeners for the meow-rs proxy kernel.
//!
//! Mixed, HTTP, SOCKS5, and TProxy acceptors, plus an optional TUN device
//! inbound (feature `listener-tun`).

pub mod sniffer;

// Inbound-socket TCP keepalive applied at accept time — compiled only when
// at least one TCP listener that calls it is enabled (a listener-less
// build would otherwise trip dead-code lints on it).
#[cfg(any(
    feature = "listener-mixed",
    feature = "listener-tproxy",
    feature = "listener-shadowsocks",
    feature = "listener-anytls",
    feature = "listener-vless"
))]
mod keepalive;

#[cfg(any(feature = "listener-anytls", feature = "listener-vless"))]
mod pem;

pub const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Process-wide monotonic timestamp in milliseconds. Used by UDP flow tables
/// (SOCKS5-UDP, the shadowsocks listener, AnyTLS UoT and VLESS XUDP) for
/// idle eviction. The `START` instant is lazily initialized on the first
/// call and never changes.
#[cfg(any(
    feature = "listener-socks5",
    feature = "listener-shadowsocks",
    feature = "listener-anytls",
    feature = "listener-vless"
))]
pub(crate) fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

#[cfg(feature = "listener-anytls")]
pub mod anytls;
#[cfg(feature = "listener-anytls")]
pub(crate) mod anytls_uot;
#[cfg(feature = "listener-http")]
pub mod http_proxy;
#[cfg(feature = "listener-mixed")]
pub mod mixed;
#[cfg(feature = "listener-shadowsocks")]
pub mod shadowsocks;
#[cfg(feature = "listener-socks5")]
pub mod socks5;
#[cfg(feature = "listener-socks5")]
mod socks5_udp;
#[cfg(feature = "listener-tproxy")]
pub mod tproxy;
#[cfg(feature = "listener-tun")]
pub mod tun;
#[cfg(feature = "listener-vless")]
pub mod vless;
#[cfg(feature = "listener-vless")]
pub(crate) mod vless_mimic;
#[cfg(feature = "listener-vless")]
pub(crate) mod vless_xudp;
#[cfg(feature = "listener-wireguard")]
pub mod wireguard;

/// First-payload sniff window shared by the userspace-stack inbounds
/// (TUN lwIP, WireGuard smoltcp): the client's opening bytes double as
/// the relay prefix after a TLS/HTTP sniff pass.
#[cfg(any(feature = "listener-tun", feature = "listener-wireguard"))]
pub(crate) mod stream_sniff;

#[cfg(feature = "listener-anytls")]
pub use anytls::{AnytlsListener, AnytlsListenerSpec};
#[cfg(feature = "listener-mixed")]
pub use mixed::MixedListener;
#[cfg(feature = "listener-shadowsocks")]
pub use shadowsocks::{ShadowsocksListener, SsObfsMode};
pub use sniffer::SnifferRuntime;
#[cfg(feature = "listener-tun")]
pub(crate) mod sniffer_quic;
#[cfg(feature = "listener-tproxy")]
pub use tproxy::TProxyListener;
#[cfg(feature = "listener-tun")]
pub use tun::{OutboundBinding, TunListener, TunListenerConfig, TunReady, TunRouteScope, TunStack};
#[cfg(feature = "listener-vless")]
pub use vless::{
    validate_security_spec as validate_vless_security_spec, VlessFallbackLimit, VlessListener,
    VlessListenerSpec, VlessRealityMimicMode, VlessRealityMimicSpec, VlessRealitySpec,
    VlessSecuritySpec, VlessUserSpec,
};
#[cfg(feature = "listener-vless")]
pub use vless_mimic::RealityV2MetricsSnapshot;
#[cfg(feature = "listener-wireguard")]
pub use wireguard::{WgListenerSpec, WgPeerSpec, WireGuardListener, WireGuardListenerGuard};

#[cfg(all(
    test,
    any(
        feature = "listener-socks5",
        feature = "listener-tun",
        feature = "listener-shadowsocks"
    )
))]
fn test_rule_tunnel() -> meow_tunnel::Tunnel {
    let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        meow_trie::DomainTrie::new(),
        false,
        true,
    ));
    let tunnel = meow_tunnel::Tunnel::new(resolver);
    let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
        "REJECT",
    ))]);
    tunnel
}
