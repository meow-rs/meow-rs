//! Outbound proxy protocol implementations and groups for the meow-rs kernel.
//!
//! Adapters for Shadowsocks, Trojan, VLESS, VMess, Hysteria2, Snell, AnyTLS,
//! HTTP, SOCKS5, Direct, and Reject, plus Selector, URLTest, Fallback,
//! LoadBalance, and Relay groups.

/// BoringSSL record-layer AEAD shared by Snell, VMess and VLESS encryption.
#[cfg(any(feature = "snell", feature = "vmess", feature = "vless-encryption"))]
mod aead;
pub mod dialer;
pub mod direct;
pub mod group;
pub mod health;
pub mod http_adapter;
#[cfg(feature = "mux")]
pub mod mux;
pub mod reject;
pub mod socks5_adapter;
pub mod stream_conn;
#[cfg(any(feature = "vmess", feature = "vless-encryption"))]
pub(crate) mod tasked_duplex;
pub mod transport_chain;

#[cfg(feature = "ech-tls-tunnel")]
pub mod ech_tls_tunnel;
#[cfg(feature = "ss")]
pub mod gost_plugin;
#[cfg(feature = "ss")]
pub mod jls_plugin;
#[cfg(feature = "kcptun")]
pub mod kcptun_plugin;
#[cfg(feature = "ss")]
mod plugin_util;
#[cfg(feature = "ss")]
pub mod restls_plugin;
#[cfg(feature = "ss")]
pub mod shadow_tls_plugin;
#[cfg(feature = "ss")]
pub mod shadowsocks_adapter;
#[cfg(feature = "ss")]
pub mod v2ray_plugin;

/// `uot.AddrParser` per-packet address headers — shared by the anytls and
/// kcptun UDP-over-TCP relays.
#[cfg(any(feature = "anytls", feature = "kcptun"))]
mod uot;

#[cfg(feature = "trojan")]
pub mod trojan;

#[cfg(feature = "snell")]
pub mod snell;
#[cfg(feature = "snell")]
pub use snell::{SnellAdapter, SnellObfs, SnellV6Mode, SnellVersion};

#[cfg(feature = "anytls")]
pub mod anytls_adapter;
#[cfg(feature = "anytls")]
pub use anytls_adapter::AnytlsAdapter;

#[cfg(feature = "hysteria2")]
mod hysteria2;
#[cfg(feature = "hysteria2")]
pub mod hysteria2_adapter;
#[cfg(feature = "hysteria2")]
pub use hysteria2_adapter::{Hy2Adapter, Hy2HopInterval, Hy2Obfs, Hy2Options};

#[cfg(feature = "vless")]
pub(crate) mod vless;
#[cfg(feature = "vless")]
pub mod vless_adapter;

#[cfg(feature = "vmess")]
pub mod vmess;

pub use direct::DirectAdapter;
pub use group::dialer_proxy::DialerProxyAdapter;
pub use group::fallback::FallbackGroup;
pub use group::load_balance::{LbStrategy, LoadBalanceGroup};
pub use group::relay::RelayGroup;
pub use group::selector::SelectorGroup;
pub use group::selector_store::SelectorStore;
pub use group::urltest::UrlTestGroup;
pub use http_adapter::HttpAdapter;
pub use reject::RejectAdapter;
#[cfg(feature = "ss")]
pub use shadowsocks_adapter::ShadowsocksAdapter;
pub use socks5_adapter::Socks5Adapter;
pub use stream_conn::StreamConn;
pub use transport_chain::TransportChain;
#[cfg(feature = "trojan")]
pub use trojan::TrojanAdapter;

#[cfg(feature = "vless")]
pub use vless_adapter::{VlessAdapter, VlessFlow};

#[cfg(feature = "vless-encryption")]
pub use vless::encryption::{parse_client_encryption, ClientInstance as VlessEncryptionClient};
#[cfg(feature = "vmess")]
pub use vmess::VmessAdapter;

// ─── Stream-desync poison ────────────────────────────────────────────────────

/// Drop guard shared by stream-framed UDP packet conns (trojan, vless,
/// anytls-uot, kcptun-uot, snell).
/// Unless `complete` is set, dropping the guard — via an early `?` return
/// OR the future being cancelled mid-frame — marks the conn desynced:
/// consumed read bytes cannot be un-read and a partially written frame
/// leaves the peer parsing garbage, so either way the only safe recovery
/// is to fail fast and let the tunnel tear the session down and re-dial
/// (issue #514).
#[cfg(any(
    feature = "trojan",
    feature = "vless",
    feature = "anytls",
    feature = "kcptun",
    feature = "snell"
))]
pub(crate) struct PoisonOnIncomplete<'a> {
    flag: &'a std::sync::atomic::AtomicBool,
    pub(crate) complete: bool,
}

#[cfg(any(
    feature = "trojan",
    feature = "vless",
    feature = "anytls",
    feature = "kcptun",
    feature = "snell"
))]
impl<'a> PoisonOnIncomplete<'a> {
    pub(crate) fn new(flag: &'a std::sync::atomic::AtomicBool) -> Self {
        Self {
            flag,
            complete: false,
        }
    }
}

#[cfg(any(
    feature = "trojan",
    feature = "vless",
    feature = "anytls",
    feature = "kcptun",
    feature = "snell"
))]
impl Drop for PoisonOnIncomplete<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Fail-fast check shared by the stream-framed packet conns. Every consumer
/// calls it at `read_packet`/`write_packet` entry; consumers whose parked
/// operations could otherwise miss the poison re-check after acquiring the
/// direction lock. Consumers that cannot tear their direction's framing
/// skip the re-check deliberately (e.g. snell/vless reads — the codec keeps
/// mid-frame state internally; see call sites).
#[cfg(any(
    feature = "trojan",
    feature = "vless",
    feature = "anytls",
    feature = "kcptun",
    feature = "snell"
))]
pub(crate) fn check_not_desynced(
    flag: &std::sync::atomic::AtomicBool,
) -> Result<(), meow_common::MeowError> {
    if flag.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(meow_common::MeowError::Proxy(
            "udp-over-tcp: connection desynced by an earlier incomplete frame".into(),
        ));
    }
    Ok(())
}

// ─── Error bridge ────────────────────────────────────────────────────────────

/// Convert a `TransportError` into a `MeowError`.
///
/// A `From<TransportError> for MeowError` blanket impl is not possible here
/// due to Rust's orphan rules (neither type is local to `meow-proxy`).
/// Adapters call `.map_err(transport_to_proxy_err)?` at the connection
/// boundary instead — this is the single conversion point.
///
/// ADR-0001 §1 invariants still hold:
/// - No adapter constructs `TransportError` variants by hand.
/// - No `anyhow::Error` crosses the `meow-transport` boundary.
#[cfg(any(feature = "ss", feature = "trojan", feature = "vless"))]
#[allow(clippy::needless_pass_by_value)] // used as map_err(fn) callback — must take by value
pub(crate) fn transport_to_proxy_err(e: meow_transport::TransportError) -> meow_common::MeowError {
    meow_common::MeowError::Proxy(e.to_string())
}
