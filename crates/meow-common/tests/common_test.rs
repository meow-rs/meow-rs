use meow_common::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ============================================================
// AdapterType Display
// ============================================================

#[test]
fn test_adapter_type_display() {
    let cases = vec![
        (AdapterType::Direct, "Direct"),
        (AdapterType::Reject, "Reject"),
        (AdapterType::RejectDrop, "RejectDrop"),
        (AdapterType::Selector, "Selector"),
        (AdapterType::Fallback, "Fallback"),
        (AdapterType::UrlTest, "URLTest"),
        (AdapterType::Shadowsocks, "Shadowsocks"),
        (AdapterType::Socks5, "Socks5"),
        (AdapterType::Http, "Http"),
        (AdapterType::Vless, "Vless"),
        (AdapterType::Trojan, "Trojan"),
        (AdapterType::Hysteria2, "Hysteria2"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected, "AdapterType::{variant:?}");
    }
}

// ============================================================
// ConnType Display
// ============================================================

#[test]
fn test_conn_type_display() {
    let cases = vec![
        (ConnType::Http, "HTTP"),
        (ConnType::Https, "HTTPS"),
        (ConnType::Socks4, "Socks4"),
        (ConnType::Socks5, "Socks5"),
        (ConnType::Shadowsocks, "Shadowsocks"),
        (ConnType::Vmess, "Vmess"),
        (ConnType::Vless, "Vless"),
        (ConnType::Redir, "Redir"),
        (ConnType::TProxy, "TProxy"),
        (ConnType::Trojan, "Trojan"),
        (ConnType::Tunnel, "Tunnel"),
        (ConnType::Tuic, "Tuic"),
        (ConnType::Hysteria2, "Hysteria2"),
        (ConnType::Inner, "Inner"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected, "ConnType::{variant:?}");
    }
}

// ============================================================
// Network Display
// ============================================================

#[test]
fn test_network_display() {
    assert_eq!(Network::Tcp.to_string(), "tcp");
    assert_eq!(Network::Udp.to_string(), "udp");
}

// ============================================================
// DnsMode Display / Default
// ============================================================

#[test]
fn test_dns_mode_display() {
    assert_eq!(DnsMode::Normal.to_string(), "normal");
    assert_eq!(DnsMode::Mapping.to_string(), "redir-host");
}

#[test]
fn test_dns_mode_default() {
    assert_eq!(DnsMode::default(), DnsMode::Normal);
}

// ============================================================
// TunnelMode Display / Default / FromStr
// ============================================================

#[test]
fn test_tunnel_mode_display() {
    assert_eq!(TunnelMode::Global.to_string(), "global");
    assert_eq!(TunnelMode::Rule.to_string(), "rule");
    assert_eq!(TunnelMode::Direct.to_string(), "direct");
}

#[test]
fn test_tunnel_mode_default() {
    assert_eq!(TunnelMode::default(), TunnelMode::Rule);
}

#[test]
fn tunnel_mode_from_str_cases() {
    // Lowercase canonical spellings plus mixed/upper case: parsing is case-insensitive.
    let cases = vec![
        ("global", TunnelMode::Global),
        ("rule", TunnelMode::Rule),
        ("direct", TunnelMode::Direct),
        ("GLOBAL", TunnelMode::Global),
        ("Rule", TunnelMode::Rule),
        ("DIRECT", TunnelMode::Direct),
    ];
    for (input, expected) in cases {
        assert_eq!(
            input.parse::<TunnelMode>().unwrap(),
            expected,
            "TunnelMode::from_str({input:?})"
        );
    }
}

#[test]
fn test_tunnel_mode_from_str_invalid() {
    let err = "unknown".parse::<TunnelMode>().unwrap_err();
    assert!(err.contains("unknown tunnel mode"));
}

// ============================================================
// RuleType Display
// ============================================================

#[test]
fn test_rule_type_display() {
    let cases = vec![
        (RuleType::Domain, "DOMAIN"),
        (RuleType::DomainSuffix, "DOMAIN-SUFFIX"),
        (RuleType::DomainKeyword, "DOMAIN-KEYWORD"),
        (RuleType::DomainRegex, "DOMAIN-REGEX"),
        (RuleType::GeoSite, "GEOSITE"),
        (RuleType::GeoIp, "GEOIP"),
        (RuleType::SrcGeoIp, "SRC-GEOIP"),
        (RuleType::IpCidr, "IP-CIDR"),
        (RuleType::SrcIpCidr, "SRC-IP-CIDR"),
        (RuleType::IpSuffix, "IP-SUFFIX"),
        (RuleType::SrcIpSuffix, "SRC-IP-SUFFIX"),
        (RuleType::IpAsn, "IP-ASN"),
        (RuleType::SrcIpAsn, "SRC-IP-ASN"),
        (RuleType::SrcPort, "SRC-PORT"),
        (RuleType::DstPort, "DST-PORT"),
        (RuleType::InPort, "IN-PORT"),
        (RuleType::Dscp, "DSCP"),
        (RuleType::ProcessName, "PROCESS-NAME"),
        (RuleType::ProcessPath, "PROCESS-PATH"),
        (RuleType::Network, "NETWORK"),
        (RuleType::Uid, "UID"),
        (RuleType::Match, "MATCH"),
        (RuleType::And, "AND"),
        (RuleType::Or, "OR"),
        (RuleType::Not, "NOT"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected, "RuleType::{variant:?}");
    }
}

// ============================================================
// Metadata
// ============================================================

#[test]
fn test_metadata_default() {
    let m = Metadata::default();
    assert_eq!(m.network, Network::Tcp);
    assert_eq!(m.conn_type, ConnType::Http);
    assert!(m.src_ip.is_none());
    assert!(m.dst_ip.is_none());
    assert_eq!(m.src_port, 0);
    assert_eq!(m.dst_port, 0);
    assert!(m.host.is_empty());
    assert_eq!(m.dns_mode, DnsMode::Normal);
}

#[test]
fn metadata_remote_address_cases() {
    // host wins over dst_ip; otherwise dst_ip is formatted as a SocketAddr
    // (IPv6 bracketed); with neither, only the port is rendered.
    let cases: Vec<(&str, &str, Option<IpAddr>, u16, &str)> = vec![
        ("with host", "example.com", None, 443, "example.com:443"),
        (
            "with ipv4",
            "",
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            80,
            "1.2.3.4:80",
        ),
        (
            "with ipv6",
            "",
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            8080,
            "[::1]:8080",
        ),
        ("no host no ip", "", None, 443, ":443"),
        (
            "host takes priority over dst_ip",
            "example.com",
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            443,
            "example.com:443",
        ),
    ];
    for (label, host, dst_ip, dst_port, expected) in cases {
        let m = Metadata {
            host: host.into(),
            dst_ip,
            dst_port,
            ..Default::default()
        };
        assert_eq!(m.remote_address(), expected, "{label}");
    }
}

#[test]
fn test_metadata_source_address_cases() {
    let cases = vec![
        (
            "with src_ip",
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            12345u16,
            "192.168.1.100:12345",
        ),
        ("no src_ip", None, 12345u16, ":12345"),
    ];
    for (label, src_ip, src_port, expected) in cases {
        let m = Metadata {
            src_ip,
            src_port,
            ..Default::default()
        };
        assert_eq!(m.source_address(), expected, "case: {label}");
    }
}

#[test]
fn test_metadata_rule_host_cases() {
    // (label, host, sniff_host, expected rule_host())
    let cases = [
        (
            "sniff takes priority over host",
            "original.com",
            "sniffed.com",
            "sniffed.com",
        ),
        (
            "empty sniff falls back to host",
            "original.com",
            "",
            "original.com",
        ),
    ];
    for (label, host, sniff_host, expected) in cases {
        let m = Metadata {
            host: host.into(),
            sniff_host: sniff_host.into(),
            ..Default::default()
        };
        assert_eq!(m.rule_host(), expected, "case: {label}");
    }
}

#[test]
fn test_metadata_resolved() {
    let unresolved = Metadata::default();
    assert!(!unresolved.resolved());

    let resolved = Metadata {
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        ..Default::default()
    };
    assert!(resolved.resolved());
}

#[test]
fn test_metadata_pure_clears_extra_fields() {
    let m = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Socks5,
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        src_port: 1234,
        dst_port: 443,
        host: "example.com".into(),
        process: "curl".into(),
        process_path: "/usr/bin/curl".into(),
        uid: Some(1000),
        dscp: Some(46),
        src_geo_ip: vec!["US".into()],
        dst_geo_ip: vec!["DE".into()],
        sniff_host: "sniffed.com".into(),
        in_name: "mixed-in".into(),
        in_port: 7890,
        special_proxy: "special".into(),
        internal: true,
        ..Default::default()
    };

    let pure = m.pure();
    // Preserved fields
    assert_eq!(pure.network, Network::Udp);
    assert_eq!(pure.conn_type, ConnType::Socks5);
    assert_eq!(pure.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert_eq!(pure.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert_eq!(pure.src_port, 1234);
    assert_eq!(pure.dst_port, 443);
    assert_eq!(pure.host, "example.com");

    // Cleared fields
    assert!(pure.process.is_empty());
    assert!(pure.process_path.is_empty());
    assert!(pure.uid.is_none());
    assert!(pure.dscp.is_none());
    assert!(pure.src_geo_ip.is_empty());
    assert!(pure.dst_geo_ip.is_empty());
    assert!(pure.sniff_host.is_empty());
    assert!(pure.in_name.is_empty());
    assert_eq!(pure.in_port, 0);
    assert!(pure.special_proxy.is_empty());
    // `internal` is a property of the traffic, not the inbound — it must
    // survive the sanitizing copy so usage accounting still skips it.
    assert!(pure.internal);
}

#[test]
fn test_metadata_display_cases() {
    struct Case {
        name: &'static str,
        metadata: Metadata,
        expected_substrings: &'static [&'static str],
    }

    let cases = [
        Case {
            name: "with_host",
            metadata: Metadata {
                src_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                src_port: 1234,
                host: "example.com".into(),
                dst_port: 443,
                ..Default::default()
            },
            expected_substrings: &["example.com", "443", "tcp"],
        },
        Case {
            name: "with_ip",
            metadata: Metadata {
                dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                dst_port: 80,
                ..Default::default()
            },
            expected_substrings: &["1.2.3.4", "80"],
        },
    ];

    for case in &cases {
        let s = case.metadata.to_string();
        for expected in case.expected_substrings {
            assert!(
                s.contains(expected),
                "case `{}`: display output `{s}` is missing `{expected}`",
                case.name
            );
        }
    }
}

// ============================================================
// Metadata serialization
// ============================================================

#[test]
fn test_metadata_json_roundtrip() {
    let m = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Socks5,
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        src_port: 5000,
        dst_port: 53,
        host: "dns.google".into(),
        ..Default::default()
    };

    let json = serde_json::to_string(&m).unwrap();
    let deserialized: Metadata = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.network, Network::Udp);
    assert_eq!(deserialized.conn_type, ConnType::Socks5);
    assert_eq!(deserialized.dst_port, 53);
    assert_eq!(deserialized.host, "dns.google");
}

#[test]
fn test_metadata_json_field_rename() {
    let m = Metadata {
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        src_port: 1234,
        dst_port: 443,
        ..Default::default()
    };
    let json = serde_json::to_string(&m).unwrap();
    // Verify serde rename attributes work
    assert!(json.contains("\"sourceIP\""));
    assert!(json.contains("\"destinationIP\""));
    assert!(json.contains("\"sourcePort\""));
    assert!(json.contains("\"destinationPort\""));
    assert!(json.contains("\"dnsMode\""));
    assert!(json.contains("\"type\""));
}

#[test]
fn test_metadata_internal_never_serializes() {
    // `internal` is an in-process usage-accounting marker, not a conn
    // attribute: it must not leak onto the wire (/connections API), and a
    // forged `"internal":true` in JSON must not be honored.
    let m = Metadata {
        internal: true,
        ..Default::default()
    };
    let json = serde_json::to_string(&m).unwrap();
    assert!(!json.contains("internal"), "internal must not serialize");

    let deserialized: Metadata = serde_json::from_str(&json).unwrap();
    assert!(!deserialized.internal, "absent field defaults to false");

    // Forged input: inject `"internal":true` into a complete object.
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("internal".to_string(), serde_json::json!(true));
    let forged: Metadata = serde_json::from_value(v).unwrap();
    assert!(!forged.internal, "forged internal field is ignored");
}

// ============================================================
// MeowError
// ============================================================

#[test]
fn test_error_display() {
    let err = MeowError::Config("bad config".to_string());
    assert_eq!(err.to_string(), "Config error: bad config");

    let err = MeowError::Dns("lookup failed".to_string());
    assert_eq!(err.to_string(), "DNS error: lookup failed");

    let err = MeowError::Proxy("connection refused".to_string());
    assert_eq!(err.to_string(), "Proxy error: connection refused");

    let err = MeowError::NotSupported("udp".to_string());
    assert_eq!(err.to_string(), "Not supported: udp");

    let err = MeowError::Other("something".to_string());
    assert_eq!(err.to_string(), "something");
}

#[test]
fn test_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let err: MeowError = io_err.into();
    assert!(err.to_string().contains("not found"));
}

/// ADR-0011 footprint guard — `Metadata` is the per-connection hot type
/// (M2 baseline 272 B). Fields must land in existing tail padding; a
/// growth needs a measured justification in the commit body.
#[test]
fn metadata_stays_272_bytes() {
    assert_eq!(std::mem::size_of::<meow_common::Metadata>(), 272);
}
