use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn deserialize_string_or_seq<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    struct StringOrSeq;

    impl<'de> Visitor<'de> for StringOrSeq {
        type Value = Option<Vec<String>>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a string or list of strings")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(vec![v.to_owned()]))
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut v = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                v.push(s);
            }
            Ok(Some(v))
        }
    }

    deserializer.deserialize_any(StringOrSeq)
}

/// `expected-status` accepts either a bare integer (`204`) or a string
/// (`"204"`, `"200-299"`, `"200,204"`). The docs and upstream mihomo both
/// allow the unquoted integer form; normalize it to the string form the
/// health-check range parser consumes (issue #390).
fn deserialize_status_or_int<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct StatusOrInt;

    impl Visitor<'_> for StatusOrInt {
        type Value = Option<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an HTTP status code (integer) or status-range string")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.to_owned()))
        }
    }

    deserializer.deserialize_any(StatusOrInt)
}

/// `geodata:` YAML subsection — path overrides, download URLs, auto-update.
///
/// Fields `geodata-mode`, `geodata-loader`, and `geoip-matcher` exist in
/// upstream Go mihomo but are not meaningful here. They are accepted and
/// produce a `warn!` (Class B per ADR-0002, forward-compat).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawGeoDataConfig {
    /// Explicit path to GeoIP Country MMDB. Skips discovery chain when set.
    pub mmdb_path: Option<String>,
    /// Explicit path to GeoLite2-ASN MMDB. Skips discovery chain when set.
    pub asn_path: Option<String>,
    /// Explicit path to geosite `.mrs` file. Skips discovery chain when set.
    pub geosite_path: Option<String>,
    /// If true, spawn a background task that periodically re-downloads DBs.
    #[serde(default)]
    pub auto_update: bool,
    /// Hours between update checks. Minimum 1 (sub-hour polling hammers CDN
    /// rate limits). Hard parse error on 0.
    pub auto_update_interval: Option<u32>,
    /// Download URL overrides. Defaults baked in when absent.
    pub url: Option<RawGeoDataUrls>,
    // Upstream-only fields accepted for forward-compat; we warn-once and ignore.
    pub geodata_mode: Option<serde_yaml::Value>,
    pub geodata_loader: Option<serde_yaml::Value>,
    pub geoip_matcher: Option<serde_yaml::Value>,
}

/// `geodata.url.*` — download URL overrides.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawGeoDataUrls {
    pub mmdb: Option<String>,
    pub asn: Option<String>,
    pub geosite: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawConfig {
    pub port: Option<u16>,
    pub socks_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub allow_lan: Option<bool>,
    pub bind_address: Option<String>,
    pub mode: Option<String>,
    pub log_level: Option<String>,
    pub ipv6: Option<bool>,
    pub external_controller: Option<String>,
    /// Path to a directory of static files for a third-party web dashboard
    /// (e.g. metacubexd, yacd). When set, it is served at `/ui` instead of the
    /// built-in panel (issue #223, mihomo-compatible).
    pub external_ui: Option<String>,
    /// Optional sub-directory under `external-ui` that actually holds the UI
    /// files. Mirrors mihomo's `external-ui-name`; the served directory is
    /// `external-ui/external-ui-name` when set.
    pub external_ui_name: Option<String>,
    /// URL the UI archive can be downloaded from. Recorded for compatibility;
    /// auto-download is not performed (see issue #223 notes).
    pub external_ui_url: Option<String>,
    pub secret: Option<String>,
    pub dns: Option<RawDns>,
    pub proxies: Option<Vec<HashMap<String, serde_yaml::Value>>>,
    pub proxy_groups: Option<Vec<RawProxyGroup>>,
    pub proxy_providers: Option<HashMap<String, RawProxyProvider>>,
    pub rules: Option<Vec<String>>,
    pub rule_providers: Option<HashMap<String, RawRuleProvider>>,
    /// Named sub-rule blocks. Each key is a block name; each value is a
    /// list of rule strings parsed identically to the top-level `rules:`
    /// section. Referenced from `rules:` via `SUB-RULE,<name>`.
    pub sub_rules: Option<HashMap<String, Vec<String>>>,
    pub subscriptions: Option<Vec<RawSubscription>>,
    pub tproxy_port: Option<u16>,
    pub tproxy_sni: Option<bool>,
    pub routing_mark: Option<u32>,
    /// Wall-clock bound, in seconds, on the built-in DIRECT adapter's
    /// `TcpStream::connect`. Unset = unbounded (legacy behaviour, subject
    /// only to the OS connect timeout). Motivated by iOS/macOS
    /// scoped-routing and reachability-cache transients that can leave a
    /// direct connect hanging indefinitely — see meow-ios
    /// docs/INVESTIGATION-2026-05-18-tcp-direct-rule-disconnect.md.
    /// Explicit `type: direct` proxy blocks are NOT covered by this
    /// global; they accept their own per-proxy `connect-timeout` field.
    pub tcp_connect_timeout: Option<u64>,
    /// Static host mappings, preferred over upstream DNS lookups. Values may
    /// be a single IP, a list of IPs, or one domain-name alias.
    pub hosts: Option<HashMap<String, HostsValue>>,
    pub sniffer: Option<RawSniffer>,
    /// Named listener array. Each entry defines an explicitly-named proxy
    /// listener instance. Merged with the shorthand port fields at parse time.
    pub listeners: Option<Vec<RawListener>>,
    pub authentication: Option<Vec<String>>,
    pub skip_auth_prefixes: Option<Vec<String>>,
    pub geodata: Option<RawGeoDataConfig>,
    /// TUN inbound (issue #326) — mihomo-compatible `tun:` section.
    /// Requires a build with the `listener-tun` feature.
    pub tun: Option<RawTun>,
    /// Global default cap on concurrent in-flight inbound connections per
    /// listener. The default is 256; explicit `0` disables the cap. Individual `listeners:`
    /// entries can override this with their own `max-connections` field.
    pub max_connections: Option<usize>,
}

/// A `hosts:` map value: one IP/domain alias or a list of IP addresses.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum HostsValue {
    One(String),
    Many(Vec<String>),
}

impl HostsValue {
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            HostsValue::One(s) => vec![s.as_str()],
            HostsValue::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// `tun:` YAML section (issue #326) — mihomo-compatible TUN inbound.
///
/// Only the fields meow-rs implements are typed; upstream-only fields
/// (`stack`, `strict-route`, `auto-detect-interface`, …) are accepted and
/// produce a `warn!` (Class B per ADR-0002, forward-compat), never a parse
/// error — the same policy as [`RawGeoDataConfig`] and #328.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawTun {
    /// Master switch; the listener is spawned only when true.
    #[serde(default)]
    pub enable: bool,
    /// Device name. Default: platform-chosen (`meow` on Windows/Linux,
    /// `utunN` auto-assigned on macOS).
    pub device: Option<String>,
    /// Device MTU. Default 1500; hard parse error below 1280 (the
    /// userspace stack's minimum, RFC 8200 §5).
    pub mtu: Option<u16>,
    /// CIDR assigned to the device, e.g. `172.19.0.1/30` (default).
    pub inet4_address: Option<String>,
    /// Route installation on startup. Accepts the mihomo boolean
    /// (`true` = fake-IP scope, `false` = off) plus the #375 mode strings
    /// `fake-ip` and `global`. Default true (fake-IP scope).
    pub auto_route: Option<RawAutoRoute>,
    /// Physical interface outbound sockets bind to in `auto-route: global`
    /// mode (loop avoidance, #375). Auto-detected from the default route
    /// when omitted. Ignored outside global mode.
    pub outbound_interface: Option<String>,
    /// DNS hijack targets. meow-rs v1 hijacks all UDP :53 flows entering
    /// the device whenever this list is non-empty; entries with a port
    /// other than 53 warn and are ignored.
    pub dns_hijack: Option<Vec<String>>,
    /// UDP NAT idle timeout in seconds. Default 60.
    pub udp_timeout: Option<u64>,
    // Upstream-only fields accepted for forward-compat; warn and ignore.
    pub stack: Option<serde_yaml::Value>,
    pub strict_route: Option<serde_yaml::Value>,
    pub auto_detect_interface: Option<serde_yaml::Value>,
    pub auto_redirect: Option<serde_yaml::Value>,
    pub inet6_address: Option<serde_yaml::Value>,
    pub endpoint_independent_nat: Option<serde_yaml::Value>,
    pub mtu_v6: Option<serde_yaml::Value>,
    pub route_address: Option<serde_yaml::Value>,
    pub route_exclude_address: Option<serde_yaml::Value>,
    pub include_uid: Option<serde_yaml::Value>,
    pub exclude_uid: Option<serde_yaml::Value>,
}

/// `tun.auto-route` value: mihomo's boolean or a #375 mode string.
/// Untagged so `auto-route: true` and `auto-route: global` both parse.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawAutoRoute {
    Enabled(bool),
    Mode(String),
}

/// One entry in the `listeners:` array.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawListener {
    pub name: String,
    #[serde(rename = "type")]
    pub listener_type: String,
    /// Optional when `listen` is a `host:port` socket address. `0` (or omitted
    /// with no port in `listen`) means the OS assigns an ephemeral port at bind.
    #[serde(default)]
    pub port: Option<u16>,
    pub listen: Option<String>,
    pub tproxy_sni: Option<bool>,
    /// Per-listener override of the global `max-connections` cap. `0`
    /// disables the cap for this listener.
    pub max_connections: Option<usize>,

    // ── shadowsocks-listener fields (only meaningful when `type: shadowsocks`) ──
    pub cipher: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub udp: Option<bool>,
    pub simple_obfs: Option<RawSimpleObfs>,

    // ── upstream sub-options not yet supported by meow-rs ──
    // Captured as opaque `Value`s so their mere presence can be warned about
    // (ADR-0002: never silently ignore a mihomo flag) without modelling the
    // full schema. `None` when absent.
    pub shadow_tls: Option<serde_yaml::Value>,
    pub res_tls: Option<serde_yaml::Value>,
    pub jls_config: Option<serde_yaml::Value>,
    pub kcp_tun: Option<serde_yaml::Value>,
    pub mux_option: Option<serde_yaml::Value>,
}

/// Raw `simple-obfs:` block for a shadowsocks listener.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawSimpleObfs {
    #[serde(default)]
    pub enable: bool,
    pub mode: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct RawDns {
    pub enable: Option<bool>,
    pub listen: Option<String>,
    pub enhanced_mode: Option<String>,
    pub fake_ip_range: Option<String>,
    /// Fake-IP filter mode: `blacklist` (default) or `whitelist`. Controls
    /// how `fake_ip_filter` patterns are interpreted.
    pub fake_ip_filter_mode: Option<String>,
    /// If true, the fake-IP host↔ip map is persisted to disk and survives
    /// restarts. The on-disk file is `fakeip-v4.json` / `fakeip-v6.json`
    /// alongside the working directory.
    pub store_fake_ip: Option<bool>,
    pub default_nameserver: Option<Vec<String>>,
    pub nameserver: Option<Vec<String>>,
    pub fallback: Option<Vec<String>>,
    /// Nameservers used exclusively to resolve proxy server hostnames
    /// (mihomo `proxy-server-nameserver`). When set, proxy adapters resolve
    /// their `server:` through these instead of the main `nameserver` list.
    pub proxy_server_nameserver: Option<Vec<String>>,
    pub fake_ip_filter: Option<Vec<String>>,
    /// If false, the hosts trie lookup is skipped entirely at query time.
    pub use_hosts: Option<bool>,
    /// If true, `/etc/hosts` is read at startup and merged (lower priority than
    /// top-level `hosts` config entries). No-op + warn on Windows.
    pub use_system_hosts: Option<bool>,
    /// Per-domain nameserver routing: each key is an exact domain or a `+.`
    /// wildcard prefix; value is a single server URL or a list of URLs.
    pub nameserver_policy: Option<HashMap<String, RawNspValue>>,
    /// Controls when the `fallback:` nameservers replace the primary result.
    pub fallback_filter: Option<RawFallbackFilter>,
}

/// A nameserver-policy value: either a single URL string or a list of URLs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum RawNspValue {
    One(String),
    Many(Vec<String>),
}

impl RawNspValue {
    pub fn as_urls(&self) -> Vec<&str> {
        match self {
            RawNspValue::One(s) => vec![s.as_str()],
            RawNspValue::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// `fallback-filter` YAML block.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawFallbackFilter {
    pub geoip: Option<bool>,
    pub geoip_code: Option<String>,
    pub ipcidr: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawProxyGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: String,
    pub proxies: Option<Vec<String>>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u16>,
    #[serde(
        default,
        deserialize_with = "deserialize_status_or_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_status: Option<String>,
    pub strategy: Option<String>,
    pub lazy: Option<bool>,
    #[serde(rename = "use")]
    pub use_providers: Option<Vec<String>>,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_seq",
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_type: Option<Vec<String>>,
    pub include_all: Option<bool>,
    pub include_all_proxies: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawProxyProvider {
    #[serde(rename = "type")]
    pub provider_type: String,
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Option<u64>,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_seq",
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_type: Option<Vec<String>>,
    pub health_check: Option<RawHealthCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<std::collections::HashMap<String, String>>,
    /// Opt-in: allow `plugin:` fields on this provider's nodes to name
    /// external SIP003 executables. Off by default — provider content is
    /// remote-controlled and the plugin name reaches `Command::new`
    /// (issue #513). mihomo has no external-plugin mechanism, so no
    /// mihomo subscription relies on it.
    pub allow_external_plugin: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawHealthCheck {
    pub enable: Option<bool>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub timeout: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_status_or_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_status: Option<String>,
    pub lazy: Option<bool>,
}

/// A single entry in the top-level `rule-providers:` map.
///
/// `interval` is accepted for upstream-config compatibility but is currently
/// ignored — providers are loaded exactly once at startup.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct RawRuleProvider {
    #[serde(rename = "type")]
    pub provider_type: String, // "http" | "file" | "inline"
    pub behavior: String,       // "domain" | "ipcidr" | "classical"
    pub format: Option<String>, // "yaml" (default) | "text" | "mrs"
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Option<u64>,
    /// mihomo-compatible download policy for http providers (issue #377):
    /// the name of a proxy or group to route this provider's fetches
    /// through, or `DIRECT` to force a direct fetch. Absent = the global
    /// default (the first proxy in `proxies:`, direct when none).
    pub proxy: Option<String>,
    /// Inline payload: list of rule strings (only for type=inline).
    pub payload: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawSniffer {
    pub enable: Option<bool>,
    /// Peek timeout in milliseconds (1–60000, default 100).
    pub timeout: Option<u64>,
    pub parse_pure_ip: Option<bool>,
    pub override_destination: Option<bool>,
    /// Accepted; respected when fake-ip mode is enabled. When true and the
    /// destination IP is a fake-IP allocation, the sniffer skips peek and
    /// trusts the fake-IP reverse mapping. Currently unused (the tunnel's
    /// `pre_handle_metadata` always consults the reverse map regardless), so
    /// this flag is parsed and ignored for upstream-config compatibility.
    pub force_dns_mapping: Option<bool>,
    /// Protocol → port list map. Recognised keys: `TLS`, `HTTP`.
    pub sniff: Option<HashMap<String, RawSniffProtocol>>,
    pub force_domain: Option<Vec<String>>,
    pub skip_domain: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawSniffProtocol {
    #[serde(default, deserialize_with = "deserialize_port_list")]
    pub ports: Option<Vec<u16>>,
}

fn deserialize_port_list<'de, D>(deserializer: D) -> Result<Option<Vec<u16>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    struct PortListVisitor;

    impl<'de> Visitor<'de> for PortListVisitor {
        type Value = Option<Vec<u16>>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a list of ports or port ranges (e.g. [80, \"8080-8880\"])")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut ports = Vec::new();
            while let Some(item) = seq.next_element::<serde_yaml::Value>()? {
                match item {
                    serde_yaml::Value::Number(n) => {
                        let p = n
                            .as_u64()
                            .and_then(|v| u16::try_from(v).ok())
                            .ok_or_else(|| de::Error::custom(format!("invalid port: {n}")))?;
                        ports.push(p);
                    }
                    serde_yaml::Value::String(s) => {
                        if let Some((start_s, end_s)) = s.split_once('-') {
                            let start: u16 = start_s.trim().parse().map_err(|_| {
                                de::Error::custom(format!("invalid port range start: {start_s}"))
                            })?;
                            let end: u16 = end_s.trim().parse().map_err(|_| {
                                de::Error::custom(format!("invalid port range end: {end_s}"))
                            })?;
                            if start > end {
                                return Err(de::Error::custom(format!(
                                    "invalid port range: {start}-{end}"
                                )));
                            }
                            ports.extend(start..=end);
                        } else {
                            let p: u16 = s
                                .trim()
                                .parse()
                                .map_err(|_| de::Error::custom(format!("invalid port: {s}")))?;
                            ports.push(p);
                        }
                    }
                    other => {
                        return Err(de::Error::custom(format!(
                            "expected port number or range string, got: {other:?}"
                        )));
                    }
                }
            }
            Ok(Some(ports))
        }
    }

    deserializer.deserialize_any(PortListVisitor)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawSubscription {
    pub name: String,
    pub url: String,
    pub interval: Option<u64>,
    pub last_updated: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::{RawConfig, RawHealthCheck, RawProxyGroup};

    #[test]
    fn expected_status_accepts_integer_scalar() {
        // issue #390: docs promise `expected-status: 204` (integer); it used
        // to fail with "invalid type: integer `204`, expected a string".
        let group: RawProxyGroup =
            serde_yaml::from_str("name: auto\ntype: url-test\nexpected-status: 204\n").unwrap();
        assert_eq!(group.expected_status.as_deref(), Some("204"));

        let hc: RawHealthCheck =
            serde_yaml::from_str("enable: true\nexpected-status: 204\n").unwrap();
        assert_eq!(hc.expected_status.as_deref(), Some("204"));
    }

    #[test]
    fn expected_status_accepts_string_forms() {
        let group: RawProxyGroup =
            serde_yaml::from_str("name: auto\ntype: url-test\nexpected-status: \"200-299\"\n")
                .unwrap();
        assert_eq!(group.expected_status.as_deref(), Some("200-299"));

        let hc: RawHealthCheck =
            serde_yaml::from_str("enable: true\nexpected-status: \"204\"\n").unwrap();
        assert_eq!(hc.expected_status.as_deref(), Some("204"));
    }

    #[test]
    fn expected_status_absent_is_none() {
        let group: RawProxyGroup = serde_yaml::from_str("name: auto\ntype: url-test\n").unwrap();
        assert_eq!(group.expected_status, None);

        let hc: RawHealthCheck = serde_yaml::from_str("enable: true\n").unwrap();
        assert_eq!(hc.expected_status, None);
    }

    #[test]
    fn tcp_connect_timeout_parses_from_kebab_yaml() {
        let raw: RawConfig = serde_yaml::from_str("tcp-connect-timeout: 10\n").unwrap();
        assert_eq!(raw.tcp_connect_timeout, Some(10));
    }

    #[test]
    fn tcp_connect_timeout_defaults_to_none() {
        let raw: RawConfig = serde_yaml::from_str("mixed-port: 7890\n").unwrap();
        assert_eq!(raw.tcp_connect_timeout, None);
    }
}
