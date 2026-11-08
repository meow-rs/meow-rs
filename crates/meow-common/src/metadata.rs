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
    ///
    /// JSON always carries the key as a number, `0` for `None`: mihomo
    /// dashboards read `metadata.dscp` unconditionally. Reading JSON back,
    /// `0` (or `null`, or no key) is `None`, so serialized metadata can
    /// never come back as a flow that matches `DSCP,0`.
    #[serde(
        default,
        serialize_with = "dscp_json::serialize",
        deserialize_with = "dscp_json::deserialize"
    )]
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

/// The JSON form of [`Metadata::dscp`]: always a number, `0` when the
/// inbound saw no DSCP. JSON cannot tell an unknown DSCP from a real `0`,
/// so reading it back takes `0` for unknown: the reading that never
/// matches a `DSCP` rule.
mod dscp_json {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        dscp: &Option<u8>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(dscp.unwrap_or(0))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u8>, D::Error> {
        Ok(Option::<u8>::deserialize(deserializer)?.filter(|&dscp| dscp != 0))
    }
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

    /// A *domain-carrying* UDP association request (`dialer-proxy` inner
    /// hops, issue #657): `host` set, `dst_ip` absent.
    ///
    /// Listener-facing UDP dispatch always resolves `dst_ip` before calling
    /// `dial_udp`, so a host-only destination only ever arrives via the
    /// dialer layer asking the front to bind an association to the *name* —
    /// the front resolves it with its own (remote-server) view, matching
    /// where the chained TCP leg landed. An adapter that cannot express a
    /// domain target on the wire must answer `NotSupported` — never bind a
    /// conn whose `write_packet` stamps the caller's `SocketAddr` arg,
    /// since the caller holds no literal for a `Name` target.
    pub fn domain_udp_target(&self) -> Option<(&SmolStr, u16)> {
        (self.network == Network::Udp && self.dst_ip.is_none() && !self.host.is_empty())
            .then_some((&self.host, self.dst_port))
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

    /// The hostname the rule engine sees: `sniff_host` when the sniffer
    /// produced one, else `host` — with trailing dots stripped on both
    /// paths, so a client-supplied `evil.com.` (the fully-qualified
    /// spelling) still reads as `evil.com` to DOMAIN rules. The stored
    /// `host`/`sniff_host` keep their verbatim form, so dialing and
    /// CONNECT lines are unaffected.
    pub fn rule_host(&self) -> &str {
        if self.sniff_host.is_empty() {
            self.host.trim_end_matches('.')
        } else {
            self.sniff_host.trim_end_matches('.')
        }
    }

    pub fn resolved(&self) -> bool {
        self.dst_ip.is_some()
    }

    /// The copy the connection table keeps for `/connections`. Who opened
    /// the flow (`process` / `processPath` / `uid`) and the DSCP its
    /// packets carried stay, as upstream reports them; inbound details and
    /// per-match extras are dropped.
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
            process: self.process.clone(),
            process_path: self.process_path.clone(),
            uid: self.uid,
            dscp: self.dscp,
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

/// Parse a metadata `host`/`sniff_host`-style string as an IP literal,
/// tolerating the `[v6]` brackets HTTP listeners retain in `host`
/// (`host_to_ip` strips them for `dst_ip` only, e.g.
/// `CONNECT [fc00::5]:443`).
///
/// Shared with the inbound UDP demux loops: they apply this same cheap
/// fold to derive a flow key without touching the resolver, before any
/// `pre_handle_metadata` rewrite (issue #648).
pub fn metadata_ip_literal(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().or_else(|| {
        s.strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|s| s.parse::<IpAddr>().ok())
    })
}

/// Whether `host` is a destination the outbound side renders exactly as
/// the rule engine matched it: an IP literal (plain, or `[v6]` as the HTTP
/// listeners keep it) or a syntactically valid DNS hostname.
///
/// A hostname is ASCII letters, digits, `-` and `_` (mihomo and real-world
/// SRV/DKIM-style names use underscores), in dot-separated labels of 1-63
/// bytes, at most 253 bytes in total plus one optional trailing dot.
/// Punycode (`xn--`) IDNs pass as ordinary labels; raw non-ASCII does not.
/// A name must also carry at least one non-numeric byte (`-` and `_`
/// count): `2130706433`, `0177.0.0.1`, `123.456` are libc `inet_aton`
/// spellings of addresses, not hostnames — on a libc dial path they fold
/// into IPs the DOMAIN rules never saw (Go `net.isDomainName` makes the
/// same call). Letter-bearing spellings like `0x7f000001` still pass, as
/// they do under Go; they are only closed on dial paths that resolve
/// through the injected DNS resolver (NXDOMAIN) — a `type: direct` node
/// configured without `dns:` still dials via libc and folds them.
///
/// Everything else is refused — in particular `@`, `/`, `?`, `#`, `:`,
/// `%`, whitespace, control bytes and NUL. Those bytes make the name the
/// rules see differ from the one a peer parses out of an authority-shaped
/// destination: `a@evil.com` misses `DOMAIN,evil.com,REJECT`, yet an HTTP
/// `CONNECT a@evil.com:443` or an h2 `:authority` reads as host
/// `evil.com` on the far side (issue #734). Every ingress that fills
/// [`Metadata::host`] from client-supplied bytes checks this before the
/// flow is routed.
///
/// The empty string is not a host; callers treat it as "no name" before
/// asking.
pub fn is_valid_host(host: &str) -> bool {
    if metadata_ip_literal(host).is_some() {
        return true;
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    // `split('.')` eats the separators, so the per-byte OR sees only label
    // bytes — it must stay inside the label check: hoisting it to the
    // whole name would count `.` as non-numeric and resurrect `123.456`.
    let mut non_numeric = false;
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| {
                non_numeric |= !b.is_ascii_digit();
                b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
            })
    }) && non_numeric
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plain and bracketed IP literals parse; names and malformed
    /// brackets do not — the UDP demux fast path keys on exactly this
    /// fold (issue #648).
    #[test]
    fn metadata_ip_literal_parses_plain_and_bracketed() {
        assert_eq!(
            metadata_ip_literal("203.0.113.7"),
            Some("203.0.113.7".parse().unwrap())
        );
        assert_eq!(
            metadata_ip_literal("2001:db8::1"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            metadata_ip_literal("[2001:db8::1]"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(metadata_ip_literal("example.com"), None);
        assert_eq!(metadata_ip_literal(""), None);
        assert_eq!(metadata_ip_literal("[2001:db8::1"), None);
        assert_eq!(metadata_ip_literal("203.0.113.7]"), None);
    }

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

    #[test]
    fn is_valid_host_accepts_hostnames_and_ip_literals() {
        for host in [
            "example.com",
            "EXAMPLE.COM",
            "localhost",
            "a.b.c.d.example.co.uk",
            "example.com.",
            "xn--bcher-kva.example",
            "xn--fiqs8s",
            "_dmarc.example.com",
            "_sip._tcp.example.com",
            "my_host-1.example",
            "-leading-hyphen.example",
            // `-` and `_` count as non-numeric, so digits-and-hyphens and
            // digits-and-underscore names are hostnames, not inet_aton
            // spellings (Go isDomainName parity).
            "123-456",
            "1_2",
            // Letter-bearing numeric spellings pass the gate under Go too;
            // they stay closed only on resolver-injected dial paths
            // (NXDOMAIN) — a `type: direct` node without `dns:` can still
            // fold them via libc.
            "0x7f000001",
            "1.2.3.4",
            "255.255.255.255",
            "::1",
            "2606:2800:220:1:248:1893:25c8:1946",
            "[::1]",
            "[2606:2800:220:1:248:1893:25c8:1946]",
            "::ffff:1.2.3.4",
        ] {
            assert!(is_valid_host(host), "{host:?} must be accepted");
        }
        let label63 = "a".repeat(63);
        assert!(is_valid_host(&format!("{label63}.example")));
        // 253 bytes exactly (4 × 63 + 3 dots = 255 is over; build 253).
        let max = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(max.len(), 253);
        assert!(is_valid_host(&max));
        assert!(
            is_valid_host(&format!("{max}.")),
            "trailing dot is not counted"
        );
    }

    /// Issue #734: bytes that make an authority-shaped destination parse to
    /// a different host than the rule engine saw are refused.
    #[test]
    fn is_valid_host_rejects_authority_and_garbage_bytes() {
        for host in [
            "",
            ".",
            "a@evil.com",
            "user:pass@evil.com",
            "evil.com:443",
            "evil.com/x",
            "evil.com?q=1",
            "evil.com#frag",
            "evil%2ecom",
            "evil.com\\",
            "evil com",
            "evil.com\t",
            "evil.com\r\nHost: x",
            "evil\0.com",
            "evil\x7f.com",
            "bücher.example",
            "a..b",
            ".example.com",
            "example.com..",
            "*.example.com",
            "[::1",
            "::1]",
            "[evil.com]",
            "fe80::1%eth0",
            "[fe80::1%25eth0]",
            // Digits-and-dots spellings are inet_aton address forms a libc
            // dial path would fold into IPs, not hostnames (Go parity:
            // no non-numeric byte).
            "2130706433",
            "0177.0.0.1",
            "123.456",
            "1.2.3.4.5",
            "1.2.3.4.",
            "999",
        ] {
            assert!(!is_valid_host(host), "{host:?} must be rejected");
        }
        assert!(!is_valid_host(&format!("{}.example", "a".repeat(64))));
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(long.len(), 254);
        assert!(!is_valid_host(&long));
    }
}
