use crate::{ConnType, DnsMode, Network};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

// M2 layout change (ADR-0011 T1/T4/T5):
//   String fields → SmolStr (inline ≤23 B, heap-backed above that)
//   Vec<String> geo-IP fields → Vec<SmolStr> (same 24-B struct, cheaper elements)
//   Option<String> in_user → Option<SmolStr>
// Breaking change permitted per ADR-0009 §"Public-API stability stance".

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub network: Network,
    #[serde(rename = "type")]
    pub conn_type: ConnType,
    #[serde(rename = "sourceIP")]
    pub src_ip: Option<IpAddr>,
    #[serde(rename = "destinationIP")]
    pub dst_ip: Option<IpAddr>,
    #[serde(rename = "sourcePort")]
    pub src_port: u16,
    #[serde(rename = "destinationPort")]
    pub dst_port: u16,
    pub host: SmolStr,
    #[serde(rename = "dnsMode")]
    pub dns_mode: DnsMode,
    pub process: SmolStr,
    #[serde(rename = "processPath")]
    pub process_path: SmolStr,
    pub uid: Option<u32>,
    /// DSCP marking from the IP header (6 bits, 0–63).
    ///
    /// `Some(n)` — set by the TProxy listener from the `IP_RECVTOS` cmsg
    /// (`ip_tos >> 2`).  `None` for all other listener types (HTTP, SOCKS5,
    /// Mixed) where the DSCP value is not available.
    ///
    /// Match semantics: `None` never matches any `DSCP` rule, including
    /// `DSCP,0`.  This prevents the previous `u8`-default-0 silent misroute
    /// where every HTTP/SOCKS5 connection matched `DSCP,0`.
    /// Class A fix per ADR-0002 (upstream: `rules/common/dscp.go`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dscp: Option<u8>,
    #[serde(rename = "sourceGeoIP")]
    pub src_geo_ip: Vec<SmolStr>,
    #[serde(rename = "destinationGeoIP")]
    pub dst_geo_ip: Vec<SmolStr>,
    #[serde(rename = "sniffHost")]
    pub sniff_host: SmolStr,
    #[serde(rename = "inboundName")]
    pub in_name: SmolStr,
    #[serde(rename = "inboundPort")]
    pub in_port: u16,
    /// Authenticated username; `None` when auth was skipped or not configured.
    #[serde(rename = "inboundUser", skip_serializing_if = "Option::is_none")]
    pub in_user: Option<SmolStr>,
    #[serde(rename = "specialProxy")]
    pub special_proxy: SmolStr,
    /// Marks housekeeping traffic that is not a user connection: health
    /// probes, provider/geodata/subscription fetches, and DNS-via-proxy
    /// exchanges.
    ///
    /// Routing, rules, and the /connections API still classify the conn by
    /// `conn_type`; the flag exists purely so usage accounting can tell
    /// internal dials apart from user traffic without abusing `conn_type`
    /// (an HTTP provider fetch is genuinely `Http`, not `Tunnel`).  Lazy
    /// proxy groups skip it so background maintenance cannot keep a group
    /// permanently "in use" — mihomo threads the same distinction via an
    /// explicit `touch` flag on its group dials.
    ///
    /// Internal only: never serialized — it is a routing hint, not a conn
    /// attribute, and external metadata (API, configs) has no business
    /// claiming it.
    #[serde(skip)]
    pub internal: bool,
}

impl Metadata {
    /// Whether this metadata describes internal housekeeping traffic rather
    /// than a user connection: either flagged `internal` or carrying the
    /// legacy `ConnType::Tunnel` probe marker.
    pub fn is_internal(&self) -> bool {
        self.internal || self.conn_type == ConnType::Tunnel
    }

    /// Swap the source and destination address fields — upstream
    /// `Metadata.SwapSrcDst` (`constant/metadata.go`). Used by
    /// `RULE-SET,...,src` so a provider's dst-axis matchers evaluate the
    /// source tuple. Upstream also swaps `SrcIPASN`/`DstIPASN` strings;
    /// `Metadata` carries no ASN pair — ASN rules range-match the IP
    /// itself.
    pub fn swap_src_dst(&mut self) {
        std::mem::swap(&mut self.src_ip, &mut self.dst_ip);
        std::mem::swap(&mut self.src_port, &mut self.dst_port);
        std::mem::swap(&mut self.src_geo_ip, &mut self.dst_geo_ip);
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            network: Network::Tcp,
            conn_type: ConnType::Http,
            src_ip: None,
            dst_ip: None,
            src_port: 0,
            dst_port: 0,
            host: SmolStr::default(),
            dns_mode: DnsMode::Normal,
            process: SmolStr::default(),
            process_path: SmolStr::default(),
            uid: None,
            dscp: None,
            src_geo_ip: Vec::new(),
            dst_geo_ip: Vec::new(),
            sniff_host: SmolStr::default(),
            in_name: SmolStr::default(),
            in_port: 0,
            in_user: None,
            special_proxy: SmolStr::default(),
            internal: false,
        }
    }
}

pub struct AddrDisplay<'a> {
    host: &'a str,
    ip: Option<IpAddr>,
    port: u16,
}

impl fmt::Debug for AddrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl PartialEq<&str> for AddrDisplay<'_> {
    fn eq(&self, other: &&str) -> bool {
        use std::fmt::Write;
        let mut buf = CompactAddrBuf::new();
        let _ = write!(buf, "{self}");
        buf.as_str() == *other
    }
}

struct CompactAddrBuf {
    buf: [u8; 64],
    len: usize,
}

impl CompactAddrBuf {
    fn new() -> Self {
        Self {
            buf: [0u8; 64],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl std::fmt::Write for CompactAddrBuf {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let remaining = self.buf.len() - self.len;
        let to_copy = s.len().min(remaining);
        self.buf[self.len..self.len + to_copy].copy_from_slice(&s.as_bytes()[..to_copy]);
        self.len += to_copy;
        Ok(())
    }
}

impl fmt::Display for AddrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.host.is_empty() {
            write!(f, "{}:{}", self.host, self.port)
        } else if let Some(ip) = self.ip {
            fmt::Display::fmt(&SocketAddr::new(ip, self.port), f)
        } else {
            write!(f, ":{}", self.port)
        }
    }
}

impl Metadata {
    pub fn remote_address(&self) -> AddrDisplay<'_> {
        AddrDisplay {
            host: &self.host,
            ip: self.dst_ip,
            port: self.dst_port,
        }
    }

    pub fn source_address(&self) -> AddrDisplay<'_> {
        AddrDisplay {
            host: "",
            ip: self.src_ip,
            port: self.src_port,
        }
    }

    /// Convert a hostname to a lowercase `SmolStr`. Avoids allocation when the
    /// input is already lowercase (common case for DNS-snooped domains).
    pub fn lower_host(s: &str) -> SmolStr {
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            SmolStr::new(s.to_ascii_lowercase())
        } else {
            SmolStr::from(s)
        }
    }

    pub fn rule_host(&self) -> &str {
        if self.sniff_host.is_empty() {
            &self.host
        } else {
            &self.sniff_host
        }
    }

    pub fn resolved(&self) -> bool {
        self.dst_ip.is_some()
    }

    pub fn pure(&self) -> Self {
        Self {
            network: self.network,
            conn_type: self.conn_type,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            host: self.host.clone(),
            dns_mode: self.dns_mode,
            process: SmolStr::default(),
            process_path: SmolStr::default(),
            uid: None,
            dscp: None,
            src_geo_ip: Vec::new(),
            dst_geo_ip: Vec::new(),
            sniff_host: SmolStr::default(),
            in_name: SmolStr::default(),
            in_port: 0,
            in_user: None,
            special_proxy: SmolStr::default(),
            internal: self.internal,
        }
    }
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.host.is_empty() {
            write!(
                f,
                "{}: --> {}:{} ({})",
                self.source_address(),
                self.host,
                self.dst_port,
                self.network
            )
        } else if let Some(ip) = self.dst_ip {
            write!(
                f,
                "{} --> {}:{} ({})",
                self.source_address(),
                ip,
                self.dst_port,
                self.network
            )
        } else {
            write!(
                f,
                "{} --> :{} ({})",
                self.source_address(),
                self.dst_port,
                self.network
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `swap_src_dst` exchanges exactly the source/destination tuple —
    /// ip, port, geo-ip — and leaves host/process/inbound fields alone,
    /// mirroring upstream `Metadata.SwapSrcDst` (there is no ASN pair to
    /// swap; ASN rules range-match the IP itself).
    #[test]
    fn swap_src_dst_swaps_only_src_dst_pairs() {
        let mut m = Metadata {
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("203.0.113.7".parse().unwrap()),
            src_port: 12345,
            dst_port: 443,
            src_geo_ip: vec!["CN".into()],
            dst_geo_ip: vec!["US".into()],
            host: "example.com".into(),
            process: "curl".into(),
            in_name: "mixed".into(),
            ..Default::default()
        };
        let before = m.clone();
        m.swap_src_dst();
        assert_eq!(m.src_ip, before.dst_ip);
        assert_eq!(m.dst_ip, before.src_ip);
        assert_eq!(m.src_port, before.dst_port);
        assert_eq!(m.dst_port, before.src_port);
        assert_eq!(m.src_geo_ip, before.dst_geo_ip);
        assert_eq!(m.dst_geo_ip, before.src_geo_ip);
        // Everything else is untouched.
        assert_eq!(m.host, before.host);
        assert_eq!(m.sniff_host, before.sniff_host);
        assert_eq!(m.process, before.process);
        assert_eq!(m.in_name, before.in_name);
        // A second swap restores the original tuple.
        m.swap_src_dst();
        assert_eq!(m.src_ip, before.src_ip);
        assert_eq!(m.dst_ip, before.dst_ip);
        assert_eq!(m.src_port, before.src_port);
        assert_eq!(m.dst_port, before.dst_port);
    }
}
