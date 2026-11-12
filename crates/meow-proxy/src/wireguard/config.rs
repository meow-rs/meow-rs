//! Configuration surface for the WireGuard outbound (issue #899, Phase-1).
//!
//! [`WireGuardConfig`] is the typed form of the mihomo-compatible
//! `type: wireguard` proxy block; `meow-config`'s parser constructs it.
//! Phase-1 scope (see the implementation spec): standard WireGuard only —
//! no AmneziaWG, no kernel `ip-stack: system`, and the `dns` field is
//! accepted but ignored by the parser.

use std::net::{Ipv4Addr, Ipv6Addr};

/// WireGuard framing + transport overhead subtracted from the configured
/// (outer) MTU to get the IP MTU the smoltcp stack advertises:
/// 20 (outer IPv4) + 8 (UDP) + 4 (type) + 4 (receiver idx) + 4 (sender idx)
/// + 8 (counter) + 16 (Poly1305 tag).
pub(crate) const WG_OVERHEAD: usize = 64;

/// One `type: wireguard` proxy block, validated at parse time.
///
/// `ip`/`ipv6` are the tunnel interface addresses assigned to the smoltcp
/// interface — bare addresses (a CIDR suffix in YAML is stripped by the
/// parser; the prefix is meaningless on a point-to-point WG interface and
/// is assigned /32 resp. /128 internally). `allowed_ips` is checked at
/// dial time: a destination outside every CIDR is rejected before the
/// handshake work begins, matching `AllowedIPs` routing semantics.
///
/// [`Debug`] is hand-rolled: the struct carries the client's private key,
/// which must never land in a log line.
#[derive(Clone)]
pub struct WireGuardConfig {
    /// Proxy name (the `name:` key) — used for logs and error strings.
    pub name: String,
    /// WG server hostname or IP literal.
    pub server: String,
    /// WG server UDP port.
    pub port: u16,
    /// Local static private key, base64-decoded to 32 bytes.
    pub private_key: [u8; 32],
    /// Peer (server) static public key, base64-decoded to 32 bytes.
    pub public_key: [u8; 32],
    /// Optional pre-shared symmetric key (Noise `psk` mixing).
    pub pre_shared_key: Option<[u8; 32]>,
    /// Tunnel IPv4 address (smoltcp interface address; required for IPv4
    /// TCP flows — smoltcp needs a source address for the SYN).
    pub ip: Option<Ipv4Addr>,
    /// Tunnel IPv6 address (same role for IPv6 destinations).
    pub ipv6: Option<Ipv6Addr>,
    /// CIDRs routed into the tunnel; default `["0.0.0.0/0", "::/0"]` is
    /// applied by `WireGuardAdapter` when the list is empty.
    pub allowed_ips: Vec<ipnet::IpNet>,
    /// Cloudflare WARP-style 3-byte `reserved` field. boringtun has no
    /// reserved-byte API, so the pump overwrites bytes 1..4 of every
    /// outbound WG datagram header *after* encapsulation (post-encapsulation
    /// mutation — WG header = 1 type byte + 3 reserved bytes).
    pub reserved: Option<[u8; 3]>,
    /// Outer MTU (default 1420); inner IP MTU = `mtu - 64`.
    pub mtu: u16,
    /// Whether `dial_udp` is offered (`support_udp`).
    pub udp: bool,
    /// Resolve destination hostnames via the injected/system resolver
    /// before sending them through the tunnel. `false` restricts dials to
    /// IP-literal destinations.
    pub remote_dns_resolve: bool,
    /// WG persistent-keepalive interval in seconds; 0 disables it.
    pub persistent_keepalive: u16,
    /// `dns:` entries from the proxy block — *stored* for parser
    /// round-trip completeness but **ignored** in Phase 1: endpoint and
    /// destination lookups go through the injected/global resolver instead.
    /// (The parser also rejects `amnezia-wg-option`, `ip-stack: system` and
    /// `dialer-proxy` before they reach this struct.)
    pub dns: Vec<String>,
}

impl std::fmt::Debug for WireGuardConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardConfig")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("private_key", &"<redacted>")
            .field("public_key", &"<redacted>")
            .field("pre_shared_key", &self.pre_shared_key.map(|_| "<redacted>"))
            .field("ip", &self.ip)
            .field("ipv6", &self.ipv6)
            .field("allowed_ips", &self.allowed_ips)
            .field("reserved", &self.reserved)
            .field("mtu", &self.mtu)
            .field("udp", &self.udp)
            .field("remote_dns_resolve", &self.remote_dns_resolve)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("dns", &self.dns)
            .finish()
    }
}

impl WireGuardConfig {
    /// Inner IP MTU exported by the smoltcp device (`mtu - WG_OVERHEAD`).
    /// Parser-side validation (640–9000) guarantees this stays ≥ 576.
    pub(crate) fn inner_mtu(&self) -> usize {
        usize::from(self.mtu).saturating_sub(WG_OVERHEAD)
    }

    /// The tunnel source address smoltcp stamps on outbound packets of the
    /// destination's family, if one is configured.
    pub(crate) fn tunnel_addr_for(&self, dst: std::net::IpAddr) -> Option<std::net::IpAddr> {
        match dst {
            std::net::IpAddr::V4(_) => self.ip.map(std::net::IpAddr::V4),
            std::net::IpAddr::V6(_) => self.ipv6.map(std::net::IpAddr::V6),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> WireGuardConfig {
        WireGuardConfig {
            name: "wg".into(),
            server: "wg.example.com".into(),
            port: 51820,
            private_key: [1u8; 32],
            public_key: [2u8; 32],
            pre_shared_key: None,
            ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
            ipv6: None,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            reserved: None,
            mtu: 1420,
            udp: true,
            remote_dns_resolve: true,
            persistent_keepalive: 0,
            dns: vec![],
        }
    }

    #[test]
    fn inner_mtu_subtracts_wg_overhead() {
        assert_eq!(base_config().inner_mtu(), 1420 - 64);
    }

    #[test]
    fn inner_mtu_saturates_on_tiny_mtu() {
        let cfg = WireGuardConfig {
            mtu: 10,
            ..base_config()
        };
        assert_eq!(cfg.inner_mtu(), 0);
    }

    #[test]
    fn tunnel_addr_picks_matching_family() {
        let cfg = base_config();
        assert_eq!(
            cfg.tunnel_addr_for("8.8.8.8".parse().unwrap()),
            Some(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(cfg.tunnel_addr_for("::1".parse().unwrap()), None);
    }
}
