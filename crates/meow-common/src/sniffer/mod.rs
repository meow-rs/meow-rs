pub mod http;
pub mod tls;

pub use http::sniff_http;
pub use tls::sniff_tls;

use smol_str::SmolStr;
use std::time::Duration;

/// Processed sniffer configuration, built by `meow-config` from the
/// `sniffer:` YAML block and stored in `Config`. Consumed by `SnifferRuntime`
/// in `meow-listener`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnifferConfig {
    pub enable: bool,
    pub timeout: Duration,
    pub parse_pure_ip: bool,
    pub override_destination: bool,
    /// Destination ports on which to try TLS SNI extraction.
    pub tls_ports: Vec<u16>,
    /// Destination ports on which to try HTTP Host extraction.
    pub http_ports: Vec<u16>,
    /// UDP destination ports on which to read the SNI of QUIC Initials.
    pub quic_ports: Vec<u16>,
    /// Glob-style domain patterns; sniffed results matching these are discarded.
    pub skip_domain: Vec<SmolStr>,
    /// Glob-style domain patterns; hosts matching these bypass `parse_pure_ip`.
    pub force_domain: Vec<SmolStr>,
}

impl Default for SnifferConfig {
    fn default() -> Self {
        Self {
            enable: false,
            timeout: Duration::from_millis(100),
            parse_pure_ip: true,
            override_destination: false,
            tls_ports: vec![443, 8443],
            http_ports: vec![80, 8080, 8880],
            quic_ports: Vec::new(),
            skip_domain: Vec::new(),
            force_domain: Vec::new(),
        }
    }
}
