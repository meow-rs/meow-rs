use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterType {
    Direct,
    Reject,
    RejectDrop,
    Selector,
    Fallback,
    UrlTest,
    LoadBalance,
    Relay,
    Shadowsocks,
    Socks5,
    Http,
    Vmess,
    Vless,
    Trojan,
    Hysteria2,
    TrustTunnel,
    Anytls,
    Snell,
    /// Userspace WireGuard outbound (issue #899): vendored boringtun noise
    /// over a smoltcp TCP/IP stack, behind meow-proxy's `wireguard` feature.
    WireGuard,
    /// Built-in nop adapter (`PASS`) — a matched rule is skipped silently
    /// by the match loop (upstream `C.Pass`).
    Pass,
    /// Built-in nop adapter (`PASS-RULE`) — inside a SUB-RULE block it
    /// skips the inner rule; at top level it rejects like `REJECT`
    /// (upstream `C.PassRule`).
    PassRule,
    /// Direct-dialing built-in named `COMPATIBLE` — upstream registers it
    /// as GLOBAL's default member (upstream `C.Compatible`).
    Compatible,
    /// `type: rematch` control outbound (issue #974) — re-enters the rule
    /// scan with `Metadata.rematch_name`/`special_rules` updated. Carries
    /// no address and can never open a socket (upstream `C.Rematch`).
    Rematch,
    /// `type: dns` outbound (issue #974, upstream `C.Dns`) — answers the
    /// flow's DNS payload from the kernel's own resolver; the nominal
    /// destination is never contacted.
    Dns,
}

impl fmt::Display for AdapterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterType::Direct => write!(f, "Direct"),
            AdapterType::Reject => write!(f, "Reject"),
            AdapterType::RejectDrop => write!(f, "RejectDrop"),
            AdapterType::Selector => write!(f, "Selector"),
            AdapterType::Fallback => write!(f, "Fallback"),
            AdapterType::UrlTest => write!(f, "URLTest"),
            AdapterType::LoadBalance => write!(f, "LoadBalance"),
            AdapterType::Relay => write!(f, "Relay"),
            AdapterType::Shadowsocks => write!(f, "Shadowsocks"),
            AdapterType::Socks5 => write!(f, "Socks5"),
            AdapterType::Http => write!(f, "Http"),
            AdapterType::Vmess => write!(f, "Vmess"),
            AdapterType::Vless => write!(f, "Vless"),
            AdapterType::Trojan => write!(f, "Trojan"),
            AdapterType::Hysteria2 => write!(f, "Hysteria2"),
            AdapterType::TrustTunnel => write!(f, "TrustTunnel"),
            AdapterType::Anytls => write!(f, "AnyTLS"),
            AdapterType::Snell => write!(f, "Snell"),
            AdapterType::WireGuard => write!(f, "WireGuard"),
            AdapterType::Pass => write!(f, "Pass"),
            AdapterType::PassRule => write!(f, "PassRule"),
            AdapterType::Compatible => write!(f, "Compatible"),
            AdapterType::Rematch => write!(f, "Rematch"),
            AdapterType::Dns => write!(f, "Dns"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnType {
    Http,
    Https,
    Socks4,
    Socks5,
    Shadowsocks,
    Vmess,
    Vless,
    Redir,
    TProxy,
    Trojan,
    Tun,
    Tunnel,
    Tuic,
    Hysteria2,
    Inner,
    /// WireGuard inbound listener (`type: wireguard`): an inner TCP/UDP
    /// flow terminated from a WG-encapsulated datagram. Serializes as
    /// `"wireguard"` in `/connections` `metadata.type` (errata U4 —
    /// pinned by an API test); the alias keeps the first shipped
    /// spelling readable on deserialize.
    #[serde(rename = "wireguard", alias = "WireGuard")]
    WireGuard,
    /// AnyTLS inbound listener (`type: anytls`): a per-SYN logical flow
    /// demuxed out of an authenticated AnyTLS session.
    Anytls,
}

impl fmt::Display for ConnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnType::Http => write!(f, "HTTP"),
            ConnType::Https => write!(f, "HTTPS"),
            ConnType::Socks4 => write!(f, "Socks4"),
            ConnType::Socks5 => write!(f, "Socks5"),
            ConnType::Shadowsocks => write!(f, "Shadowsocks"),
            ConnType::Vmess => write!(f, "Vmess"),
            ConnType::Vless => write!(f, "Vless"),
            ConnType::Redir => write!(f, "Redir"),
            ConnType::TProxy => write!(f, "TProxy"),
            ConnType::Trojan => write!(f, "Trojan"),
            ConnType::Tun => write!(f, "Tun"),
            ConnType::Tunnel => write!(f, "Tunnel"),
            ConnType::Tuic => write!(f, "Tuic"),
            ConnType::Hysteria2 => write!(f, "Hysteria2"),
            ConnType::Inner => write!(f, "Inner"),
            ConnType::WireGuard => write!(f, "WireGuard"),
            ConnType::Anytls => write!(f, "AnyTLS"),
        }
    }
}
