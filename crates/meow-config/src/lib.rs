//! YAML configuration parsing for the meow-rs proxy kernel.
//!
//! Turns a Clash Meta-style `config.yaml` into typed structs consumed by
//! the tunnel, listeners, DNS, and API.

pub mod auth;
pub mod dns_parser;
pub mod ech_dns;
// Force-disabled on iOS/Android: mobile apps embed their own UI and must not
// ship the unzip/download path regardless of the feature flag (issue #223).
#[cfg(all(
    feature = "external-ui-download",
    not(any(target_os = "ios", target_os = "android"))
))]
pub mod external_ui;
pub mod geodata;
pub mod internal_http;
pub mod proxy_parser;
pub mod proxy_provider;
pub mod proxy_provider_refresh;
pub mod raw;
pub mod rule_parser;
pub mod rule_provider;
pub mod rule_provider_refresh;
mod safe_path;
pub mod sub_rules_parser;
pub mod subscription;

pub use geodata::GeoDataConfig;

use meow_common::AuthConfig;
use meow_common::{AdapterType, Proxy, Rule, SnifferConfig, TunnelMode};
use meow_dns::Resolver;
use proxy_provider::ProxyProvider;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub(crate) async fn spawn_blocking_with_current_dispatcher<F, R>(
    f: F,
) -> Result<R, tokio::task::JoinError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    tokio::task::spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, f)).await
}

pub(crate) fn parse_optional_socket_addr(
    field: &str,
    value: Option<&str>,
) -> Result<Option<SocketAddr>, anyhow::Error> {
    match value {
        Some(value) if !value.is_empty() => {
            let normalized = value
                .strip_prefix(':')
                .map_or_else(|| value.to_string(), |port| format!("0.0.0.0:{port}"));
            normalized
                .parse()
                .map(Some)
                .map_err(|e| anyhow::anyhow!("invalid {field} socket address '{value}': {e}"))
        }
        _ => Ok(None),
    }
}

pub struct Config {
    pub general: GeneralConfig,
    pub dns: DnsConfig,
    pub proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
    pub proxy_providers: HashMap<String, Arc<ProxyProvider>>,
    /// Registry that provider-sourced nodes' `dialer-proxy` targets resolve
    /// against (issue #489). Unlike the per-build registry inside
    /// `rebuild_from_raw_impl`, this handle outlives a single build: the
    /// tunnel republishes the live route map into it on every routing
    /// update, so provider nodes — which persist across rebuilds — always
    /// resolve the *current* name map.
    pub provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
    pub rules: Vec<Box<dyn Rule>>,
    pub rule_providers: HashMap<String, Arc<rule_provider::RuleProvider>>,
    /// The `dialer-proxy` registry generation `proxies` was published into.
    /// Hand it to `Tunnel::update_routing` so the route table retains it —
    /// chained adapters resolve through it weakly (issue #533).
    pub dialer_registry: meow_proxy::dialer::ProxyRegistry,
    pub listeners: ListenerConfig,
    pub tun: TunConfig,
    pub api: ApiConfig,
    pub sniffer: SnifferConfig,
    pub auth: Arc<AuthConfig>,
    pub raw: raw::RawConfig,
    pub geodata: GeoDataConfig,
}

pub struct GeneralConfig {
    pub mode: TunnelMode,
    pub log_level: String,
    pub ipv6: bool,
    pub allow_lan: bool,
    pub bind_address: String,
}

/// Single source of truth for the effective `ipv6` setting of a config
/// whose `ipv6:` key is unset. The literal was previously scattered
/// across six `unwrap_or(...)` call sites (review), which is how the
/// parser and `GET /configs` ended up disagreeing in the first place.
///
/// Defaults to **`false`**, matching Go mihomo / Clash: an operator must
/// opt in to IPv6 resolution explicitly. (The temporary flip to `true`
/// was reverted to stay consistent with the upstream ecosystem; see the
/// CHANGELOG.) When `false`, AAAA lookups are skipped and the resolver
/// answers IPv4-only — set `ipv6: true` for dual-stack resolution.
pub fn effective_ipv6(raw_ipv6: Option<bool>) -> bool {
    raw_ipv6.unwrap_or(false)
}

pub struct DnsConfig {
    pub resolver: Arc<Resolver>,
    /// Shared slot wrapping `resolver` — the tunnel shares it and every
    /// `rebuild_from_raw_*` receives it, so the built-in DIRECT adapter
    /// tracks `set_resolver` swaps (issue #514).
    pub resolver_slot: meow_dns::ResolverSlot,
    pub listen_addr: Option<SocketAddr>,
    /// `dns.enable` from the config. False means `resolver` is the stub
    /// built for `DirectAdapter` (a single hard-coded upstream), not the
    /// user's DNS — callers that would otherwise impose it process-wide,
    /// such as the `meow_common::HostResolver` hook, must not install it.
    pub enabled: bool,
    /// Dedicated resolver built from `dns.proxy-server-nameserver` (mihomo
    /// `ProxyServerHostResolver`). `None` when the option is unset or DNS is
    /// disabled — proxy server hostnames then resolve via `resolver`.
    pub proxy_resolver: Option<Arc<Resolver>>,
}

/// Listener specification — the `type:` field of a `listeners:` entry together
/// with the per-type parameters that used to live as loose fields on
/// `NamedListener` (e.g. `tproxy_sni`). Carrying the data inside the variant
/// makes "a `TProxy` listener always has a `sni` flag" a compile-time invariant
/// instead of a runtime `Option::expect`, and keeps `NamedListener` from
/// accumulating one `Option<ProtoConfig>` per future listener type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerSpec {
    Mixed,
    Http,
    Socks5,
    /// Transparent-proxy listener; `sni` is the per-listener override of the
    /// global `tproxy-sni` sniffer default (resolved at config-build time).
    /// `firewall` (default `true`) selects whether meow installs and owns the
    /// platform firewall rules; `false` delegates rule management to an
    /// external system (issue #563).
    /// `udp` (default `false`) adds a Linux UDP TPROXY datagram path on the
    /// same port (issue #564); `udp_timeout` is the per-flow idle timeout in
    /// seconds (default 60).
    TProxy {
        sni: bool,
        #[serde(default = "default_tproxy_firewall")]
        firewall: bool,
        #[serde(default)]
        udp: bool,
        #[serde(default = "default_udp_timeout_secs")]
        udp_timeout: u64,
    },
    /// Shadowsocks encrypted-server inbound. The listener terminates SS
    /// encryption (TCP stream cipher / AEAD, UDP relay), reads the SOCKS
    /// target address, and hands the decrypted flow to the tunnel. Mirrors
    /// upstream mihomo's `type: shadowsocks` listener.
    Shadowsocks(SsListenerConfig),
}

/// Per-listener config for the `shadowsocks` inbound (`ListenerSpec::Shadowsocks`).
///
/// `cipher` and `password` are required and validated at config-build time.
/// `udp` defaults to `true` (matching upstream `ShadowSocksOption{UDP: true}`).
/// `simple_obfs` enables the SIP004 HTTP/TLS obfuscation wrapper; the server
/// codec lives in `meow_transport::simple_obfs::server`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsListenerConfig {
    pub cipher: String,
    pub password: String,
    #[serde(default = "default_ss_udp")]
    pub udp: bool,
    pub simple_obfs: Option<SimpleObfsConfig>,
}

fn default_ss_udp() -> bool {
    true
}

/// `ListenerSpec::TProxy::firewall` serde default: managed firewall rules
/// stay on when a persisted spec predates the field (issue #563).
fn default_tproxy_firewall() -> bool {
    true
}

/// `ListenerSpec::TProxy::udp_timeout` serde default, in seconds — matches
/// `tun.udp-timeout` and upstream's `DefaultUDPTimeout` (issue #564).
fn default_udp_timeout_secs() -> u64 {
    60
}

/// `simple-obfs` sub-config for a shadowsocks listener.
///
/// Only `mode` is needed on the server side: the HTTP/TLS obfuscation codec
/// strips fake framing without reference to a host name (the client-supplied
/// fake `Host`/SNI is discarded). The outbound adapter keeps its own
/// host-bearing obfs config in `meow-proxy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimpleObfsConfig {
    pub mode: ObfsMode,
}

/// Obfuscation mode for `simple-obfs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObfsMode {
    Http,
    Tls,
}

impl ListenerSpec {
    /// Canonical lowercase `type:` string used by the API (`GET /listeners`)
    /// and startup logs. Equivalent to the upstream mihomo `type:` value.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Mixed => "mixed",
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::TProxy { .. } => "tproxy",
            Self::Shadowsocks(_) => "shadowsocks",
        }
    }
}

impl std::fmt::Display for ListenerSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.type_name())
    }
}

/// A single resolved named-listener entry (either from `listeners:` or auto-named shorthand).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedListener {
    pub name: String,
    /// Protocol kind + per-type parameters (e.g. `TProxy { sni }`).
    pub spec: ListenerSpec,
    pub port: u16,
    pub listen: String,
    /// Cap on concurrent in-flight inbound connections for this listener.
    /// `0` explicitly disables the cap; the default is 256. Resolved from the per-listener
    /// `max-connections` field, falling back to the global `max-connections`.
    #[serde(default)]
    pub max_connections: usize,
}

/// Parsed + validated `tun:` section (issue #326). Consumed by the app
/// layer, which maps it onto `meow_listener::TunListenerConfig` when the
/// `listener-tun` feature is compiled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    pub enable: bool,
    /// Device name; `None` = platform default.
    pub device: Option<String>,
    pub mtu: u16,
    /// Address + prefix assigned to the device.
    pub inet4_address: ipnet::Ipv4Net,
    pub auto_route: bool,
    /// Which routes `auto-route` installs (#375). Only meaningful when
    /// `auto_route` is true.
    pub route_mode: TunRouteMode,
    /// Physical interface outbound sockets bind to in global mode; `None`
    /// = auto-detect from the default route at listener startup.
    pub outbound_interface: Option<String>,
    /// True when `dns-hijack` contains at least one usable (`:53`) entry.
    pub dns_hijack: bool,
    pub udp_timeout: std::time::Duration,
    /// Cap on concurrent TUN TCP flows. Inherited from the top-level
    /// `max-connections` key (default 256; `0` = unlimited). The accept
    /// loop has no listen-queue back-pressure of its own — this is what
    /// stops a reconnect storm from spawning unbounded `handle_tcp` tasks.
    pub max_connections: usize,
}

/// Scope of the routes `tun.auto-route` installs (#375).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunRouteMode {
    /// v1 behavior: route only the fake-IP range into the device. Loop-free
    /// by construction; IP-literal traffic is not captured.
    #[default]
    FakeIp,
    /// Route all IPv4 traffic into the device (split default routes) and
    /// bind outbound sockets to the physical interface for loop avoidance.
    /// Experimental; currently Linux-only.
    Global,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enable: false,
            device: None,
            mtu: 1500,
            // mihomo's default TUN subnet.
            inet4_address: "172.19.0.1/30".parse().expect("static CIDR parses"),
            auto_route: true,
            route_mode: TunRouteMode::FakeIp,
            outbound_interface: None,
            dns_hijack: false,
            udp_timeout: std::time::Duration::from_secs(60),
            max_connections: 256,
        }
    }
}

/// Minimum MTU accepted for the TUN device — the IPv6 floor (RFC 8200 §5);
/// smaller values break v6 traffic through the userspace stack.
const TUN_MIN_MTU: u16 = 1280;

/// Parse and validate the raw `tun:` block. Returns `TunConfig::default()`
/// (disabled) when the block is absent.
pub fn parse_tun_config(
    raw: Option<&raw::RawTun>,
    global_max_connections: Option<usize>,
) -> Result<TunConfig, anyhow::Error> {
    let Some(r) = raw else {
        // Keep the global-cap folding symmetric with the `Some` arm: an
        // absent section still inherits `max-connections`, so callers
        // diffing parsed configs see the same value either way.
        return Ok(TunConfig {
            max_connections: global_max_connections.unwrap_or(256),
            ..TunConfig::default()
        });
    };

    // Warn on upstream-only fields (Class B per ADR-0002; policy of #328:
    // never silently ignore a mihomo flag).
    for (name, val) in [
        ("stack", &r.stack),
        ("strict-route", &r.strict_route),
        ("auto-detect-interface", &r.auto_detect_interface),
        ("auto-redirect", &r.auto_redirect),
        ("inet6-address", &r.inet6_address),
        ("endpoint-independent-nat", &r.endpoint_independent_nat),
        ("mtu-v6", &r.mtu_v6),
        ("route-address", &r.route_address),
        ("route-exclude-address", &r.route_exclude_address),
        ("include-uid", &r.include_uid),
        ("exclude-uid", &r.exclude_uid),
    ] {
        if val.is_some() {
            warn!(
                "tun.{name}: field is not supported in meow-rs and will be ignored; \
                 remove it to suppress this warning"
            );
        }
    }

    let defaults = TunConfig::default();

    let mtu = r.mtu.unwrap_or(defaults.mtu);
    if mtu < TUN_MIN_MTU {
        return Err(anyhow::anyhow!(
            "tun.mtu: {mtu} is below the minimum {TUN_MIN_MTU} required by the userspace stack"
        ));
    }

    let inet4_address = match r.inet4_address.as_deref() {
        Some(s) => s
            .parse::<ipnet::Ipv4Net>()
            .map_err(|e| anyhow::anyhow!("tun.inet4-address: invalid CIDR '{s}': {e}"))?,
        None => defaults.inet4_address,
    };

    // v1 hijacks all UDP :53 flows when any usable entry is present.
    let mut dns_hijack = false;
    for entry in r.dns_hijack.as_deref().unwrap_or(&[]) {
        let port = entry.rsplit(':').next().and_then(|p| p.parse::<u16>().ok());
        match port {
            Some(53) => dns_hijack = true,
            _ => warn!(
                "tun.dns-hijack: entry '{entry}' is not a :53 target; meow-rs only hijacks \
                 UDP port 53 — entry ignored"
            ),
        }
    }

    let udp_timeout = std::time::Duration::from_secs(match r.udp_timeout {
        Some(0) => {
            return Err(anyhow::anyhow!(
                "tun.udp-timeout: must be at least 1 second"
            ));
        }
        Some(secs) => secs,
        None => defaults.udp_timeout.as_secs(),
    });

    // `auto-route` (#375): mihomo boolean, or a mode string selecting what
    // gets routed. `true` keeps the loop-free v1 fake-IP scope.
    let (auto_route, route_mode) = match r.auto_route.as_ref() {
        None => (defaults.auto_route, defaults.route_mode),
        Some(raw::RawAutoRoute::Enabled(on)) => (*on, TunRouteMode::FakeIp),
        Some(raw::RawAutoRoute::Mode(s)) => match s.as_str() {
            "fake-ip" => (true, TunRouteMode::FakeIp),
            "global" => (true, TunRouteMode::Global),
            other => {
                return Err(anyhow::anyhow!(
                    "tun.auto-route: unknown value '{other}' (expected true, false, \
                     fake-ip, or global)"
                ));
            }
        },
    };

    let outbound_interface = r.outbound_interface.clone().filter(|s| !s.is_empty());
    if outbound_interface.is_some() && route_mode != TunRouteMode::Global {
        warn!(
            "tun.outbound-interface: only used with 'auto-route: global'; \
             ignored in fake-ip mode"
        );
    }
    // Normalise the ignored value out: the commit path diffs parsed
    // `TunConfig`s to decide on a restart, and a field that does nothing
    // must not trigger one — a PUT touching only `outbound-interface`
    // under fake-ip scope would otherwise bounce a healthy listener
    // (issue #543 review).
    let outbound_interface = outbound_interface.filter(|_| route_mode == TunRouteMode::Global);

    Ok(TunConfig {
        enable: r.enable,
        device: r.device.clone().filter(|s| !s.is_empty()),
        mtu,
        inet4_address,
        auto_route,
        route_mode,
        outbound_interface,
        dns_hijack,
        udp_timeout,
        max_connections: global_max_connections.unwrap_or(defaults.max_connections),
    })
}

pub struct ListenerConfig {
    pub mixed_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub bind_address: String,
    pub tproxy_port: Option<u16>,
    pub tproxy_sni: bool,
    pub routing_mark: Option<u32>,
    /// All active listeners (shorthand + named), deduplicated and validated.
    pub named: Vec<NamedListener>,
}

pub struct ApiConfig {
    pub external_controller: Option<SocketAddr>,
    pub secret: Option<String>,
    /// Resolved directory of static files for a third-party web UI, served at
    /// `/ui` in place of the built-in panel. `None` keeps the built-in panel.
    /// Already joined with `external-ui-name` when that was set (issue #223).
    pub external_ui: Option<PathBuf>,
    /// Download URL recorded from `external-ui-url`; auto-download is not
    /// performed, but it is surfaced in a warning when the directory is absent.
    pub external_ui_url: Option<String>,
}

pub async fn load_config(path: &str) -> Result<Config, anyhow::Error> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read config file {path}: {e}"))?;
    // Strip an optional UTF-8 BOM, which YAML 1.2 permits but some
    // editors (especially on Windows) leave behind.
    let bytes = bytes
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(bytes.as_slice());
    let content = std::str::from_utf8(bytes).map_err(|e| {
        anyhow::anyhow!(
            "config file {path} is not valid UTF-8 at byte {}: {e}. Re-save the file with UTF-8 encoding.",
            e.valid_up_to()
        )
    })?;
    let raw: raw::RawConfig = parse_raw_yaml(content)?;
    let cache_dir = resource_cache_dir_for_config_path(path);
    build_config(raw, Some(cache_dir.as_path())).await
}

pub async fn load_config_from_str(content: &str) -> Result<Config, anyhow::Error> {
    let raw: raw::RawConfig = parse_raw_yaml(content)?;
    build_config(raw, None).await
}

/// Upper bound on YAML document nesting for remote-controlled documents.
/// `serde_yaml` deserializes `Value` recursively — a document of `[[[[…` or
/// of ever-deepening indentation recurses one stack frame per level and can
/// overflow a blocking-thread stack well inside the fetch-size caps
/// (issue #533 review). Two cheap over-approximations bound the depth:
///
/// - flow nesting: unclosed `[`/`{` count. Brackets inside scalars count
///   too — a false positive needs >128 unclosed openers in one document,
///   which no real config produces.
/// - block indentation: max leading-space count. Each block nesting level
///   contributes at least one space, so depth is bounded by the widest
///   indentation; a false positive needs a single line indented past 256
///   spaces (e.g. inside a literal block scalar), which no real config
///   produces.
const MAX_YAML_DEPTH: usize = 128;

pub(crate) fn yaml_within_depth(doc: &str) -> bool {
    let mut flow = 0usize;
    for c in doc.chars() {
        match c {
            '[' | '{' => {
                flow += 1;
                if flow > MAX_YAML_DEPTH {
                    return false;
                }
            }
            ']' | '}' => flow = flow.saturating_sub(1),
            _ => {}
        }
    }
    doc.lines()
        .all(|l| l.len() - l.trim_start_matches(' ').len() <= MAX_YAML_DEPTH * 2)
}

/// Parse a Clash/mihomo YAML document into [`raw::RawConfig`], expanding YAML
/// anchor merge keys (`<<: *anchor`) before deserialisation.
///
/// `serde_yaml` resolves anchors, but it does not by itself substitute merge
/// keys into the surrounding mapping; without [`serde_yaml::Value::apply_merge`]
/// the `<<` key reaches the typed deserialiser and the merged fields look
/// "missing". Upstream mihomo configs (e.g. `rule-anchor` patterns) rely on
/// this expansion — see meow-ios#112.
fn parse_raw_yaml(content: &str) -> Result<raw::RawConfig, anyhow::Error> {
    if !yaml_within_depth(content) {
        return Err(anyhow::anyhow!(
            "YAML document exceeds {MAX_YAML_DEPTH} levels of nesting"
        ));
    }
    let mut value: serde_yaml::Value = serde_yaml::from_str(content)?;
    value.apply_merge()?;
    Ok(serde_yaml::from_value(value)?)
}

/// Unique-per-call scratch sibling for atomic write-then-rename saves —
/// a shared `{path}.tmp` lets one writer's create+truncate land inside
/// another's `write_all`, and the victim's `rename` then publishes the
/// mixed file (issue #543). Names are `{path}.{pid}.{counter}.tmp`.
pub(crate) fn unique_scratch_path(path: &Path) -> PathBuf {
    // `AtomicU` resolves to AtomicU32 on targets without 64-bit atomics
    // (mips32-class) — u32 wrap is unreachable at any real save rate.
    static COUNTER: meow_common::atomic::AtomicU = meow_common::atomic::AtomicU::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{}.{}.tmp", std::process::id(), n));
    PathBuf::from(name)
}

/// Save a RawConfig back to disk with atomic write (.tmp → rename) and .bak backup.
///
/// Unique scratch names keep concurrent saves from tearing, but file
/// *order* is only guaranteed when callers serialize under the
/// `CONFIG_MUTATION` lane (meow-api) — an unsynchronized pair can still
/// land an older document's rename last (issue #543).
pub fn save_raw_config(path: &str, raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let yaml = serde_yaml::to_string(raw)?;
    // Scratch files orphaned by a crash between create and rename
    // accumulate forever otherwise — sweep stale ones on each save
    // (issue #621).
    meow_common::fs_util::sweep_scratch_siblings(
        Path::new(path),
        meow_common::fs_util::SCRATCH_STALE_AGE,
    );
    let tmp_path = unique_scratch_path(Path::new(path));
    let bak_path = format!("{path}.bak");
    // Unique scratch names would accumulate on repeated failures — sweep
    // the scratch on each fallible step so a chronic error (ENOSPC, a
    // denied rename) can't fill the config dir.
    if let Err(e) = std::fs::write(&tmp_path, &yaml) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    if std::path::Path::new(path).exists() {
        // Keep one backup
        let _ = std::fs::rename(path, &bak_path);
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    info!("Config saved to {}", path);
    Ok(())
}

/// Async counterpart to [`save_raw_config`] for Tokio request/background paths.
/// Same ordering contract: callers persisting a committed config should hold
/// the `CONFIG_MUTATION` lane so file order follows commit order (issue #543).
pub async fn save_raw_config_async(path: &str, raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let yaml = serde_yaml::to_string(raw)?;
    // Same crash-leftover sweep as the sync variant (issue #621), off the
    // async worker since it walks the config dir.
    {
        let dir_target = PathBuf::from(path);
        spawn_blocking_with_current_dispatcher(move || {
            meow_common::fs_util::sweep_scratch_siblings(
                &dir_target,
                meow_common::fs_util::SCRATCH_STALE_AGE,
            );
        })
        .await
        .ok();
    }
    let tmp_path = unique_scratch_path(Path::new(path));
    let bak_path = format!("{path}.bak");
    if let Err(e) = tokio::fs::write(&tmp_path, &yaml).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e.into());
    }
    if tokio::fs::metadata(path).await.is_ok() {
        let _ = tokio::fs::rename(path, &bak_path).await;
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e.into());
    }
    info!("Config saved to {}", path);
    Ok(())
}

#[cfg(test)]
mod save_scratch_tests {
    //! Issue #543: every save gets a unique scratch file, so an
    //! interleaved pair of writers can never publish a splice of two
    //! payloads — and a failed save must not leave scratch behind.
    use super::*;

    fn leftovers(dir: &std::path::Path) -> Vec<std::ffi::OsString> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn concurrent_saves_publish_a_complete_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let path_str = path.to_string_lossy().into_owned();

        let a: raw::RawConfig =
            serde_yaml::from_str("mode: rule\nlog-level: info\nrules:\n  - MATCH,DIRECT\n")
                .unwrap();
        let b: raw::RawConfig = serde_yaml::from_str(
            "mode: global\nlog-level: debug\nipv6: true\nrules:\n  - MATCH,REJECT\n",
        )
        .unwrap();
        let ser_a = serde_yaml::to_string(&a).unwrap();
        let ser_b = serde_yaml::to_string(&b).unwrap();

        std::thread::scope(|s| {
            for raw in [&a, &b] {
                let path = path_str.clone();
                s.spawn(move || {
                    for _ in 0..64 {
                        save_raw_config(&path, raw).unwrap();
                    }
                });
            }
        });

        // Whichever rename landed last, the file is one whole document —
        // never a splice (byte-exact: save writes the same serialization).
        let final_doc = std::fs::read_to_string(&path).unwrap();
        assert!(
            final_doc == ser_a || final_doc == ser_b,
            "concurrent saves must publish a complete document"
        );
        assert!(
            leftovers(dir.path()).is_empty(),
            "no scratch survives a successful save storm"
        );
    }

    #[test]
    fn failed_save_leaves_no_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let raw: raw::RawConfig = serde_yaml::from_str("mode: rule\n").unwrap();

        // Rename step fails: `as-dir.bak` is a non-empty directory, so the
        // backup rotate fails silently and `as-dir` stays put — the final
        // rename then hits EISDIR and must sweep its scratch.
        let bad = dir.path().join("as-dir");
        std::fs::create_dir(&bad).unwrap();
        std::fs::create_dir(dir.path().join("as-dir.bak")).unwrap();
        std::fs::write(dir.path().join("as-dir.bak").join("x"), "").unwrap();
        let bad = bad.to_string_lossy().into_owned();
        assert!(save_raw_config(&bad, &raw).is_err());
        assert!(
            leftovers(dir.path()).is_empty(),
            "rename failure must sweep its scratch: {:?}",
            leftovers(dir.path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_dir_leaves_no_scratch() {
        use std::os::unix::fs::PermissionsExt as _;
        // Root bypasses permission checks (CAP_DAC_OVERRIDE), so the write
        // would succeed and the assertion below would fail vacuously.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        let raw: raw::RawConfig = serde_yaml::from_str("mode: rule\n").unwrap();

        let path = ro.join("config.yaml").to_string_lossy().into_owned();
        assert!(save_raw_config(&path, &raw).is_err());
        assert!(
            leftovers(&ro).is_empty(),
            "write failure must sweep its scratch: {:?}",
            leftovers(&ro)
        );
    }
}

/// The result of rebuilding proxies and rules from a RawConfig: the proxy
/// map, the rule list, the [`meow_proxy::dialer::ProxyRegistry`] the
/// build published into, this generation's provider sets, and the
/// prefetched rule-provider payload snapshot a DNS rebuild should reuse.
///
/// The registry must reach every long-lived owner of this build's adapters
/// (`Tunnel::update_routing` / `reload_routing` take it for the route table;
/// rule-provider fetch contexts retain a clone internally) — chained
/// `dialer-proxy` adapters hold it weakly, so dropping it makes their dials
/// fail closed (issue #533).
#[derive(Default)]
pub struct RebuildResult {
    pub proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
    pub rules: Vec<Box<dyn Rule>>,
    pub dialer_registry: meow_proxy::dialer::ProxyRegistry,
    /// The rule-provider set parsed for this generation — shared by the
    /// rules, any DNS `rule-set:` policy matchers, and (once the caller
    /// commits) the live provider registry. The committing caller swaps it
    /// into `state.rule_providers` only *after* every fallible check has
    /// passed: a rejected candidate must never leave its provider objects
    /// live, since their fetch contexts pin this generation's dialer cell
    /// (issue #533 review).
    pub rule_providers: HashMap<String, Arc<rule_provider::RuleProvider>>,
    /// The proxy-provider set this build's groups resolved `use:`/
    /// `include-all` against — the candidate's own declarations
    /// materialized by `materialize_proxy_providers`: live objects reused
    /// for still-declared names, empty providers constructed for new defs.
    /// Committing callers install it into `state.proxy_providers` after all
    /// validation passes, so a removed provider's `use:` can't zombie-bind
    /// and a newly declared provider becomes refreshable (issue #533
    /// review).
    pub proxy_providers: HashMap<String, Arc<ProxyProvider>>,
    /// The file/http rule-provider payload bytes this rebuild prefetched.
    /// The same commit's DNS rebuild should reuse them rather than
    /// fetching again inside `CONFIG_MUTATION`, and its geo-scan needs
    /// them to see `GEOSITE`/`GEOIP`/`IP-ASN` rules that live only inside
    /// provider payloads (issue #543). Empty when the rebuild bound a
    /// caller-shared provider set — nothing parses payloads then.
    pub prefetched_payloads: Arc<rule_provider::PrefetchedPayloads>,
}

/// Rebuild proxies and rules from a RawConfig (used for runtime updates).
///
/// Does not resolve rule-provider cache paths; use
/// [`rebuild_from_raw_with_cache_dir`] when a working directory is available.
///
/// Provider caution: any [`RebuildResult::proxy_providers`] built here bind
/// their nodes' `dialer-proxy` targets to a throwaway registry cell that
/// nothing ever publishes — committing them leaves every chained dial
/// failing closed. Committing callers must use
/// [`rebuild_from_raw_runtime`], which takes the live
/// `Config::provider_dialer_registry` (issue #489).
pub fn rebuild_from_raw(raw: &raw::RawConfig) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(
        raw,
        None,
        None,
        &HashMap::new(),
        None,
        None,
        None,
        &meow_proxy::dialer::ProxyRegistry::default(),
        &meow_proxy::dialer::ProxyRegistry::default(),
        None,
    )
}

/// Rebuild proxies/rules and inject `resolver` into the built-in DIRECT
/// adapter so it avoids the OS resolver when dialing hostnames.
///
/// `resolver` is the tunnel's shared [`meow_dns::ResolverSlot`] — the
/// built `DIRECT` keeps reading the *live* generation, so a later
/// `Tunnel::set_resolver` swap reaches it (issue #514). Pass
/// `Some(meow_dns::new_resolver_slot(r))` for a private, fixed generation.
///
/// `cache_dir` should be the same provider-cache directory the config was
/// originally loaded with (see [`resource_cache_dir_for_config_path`]) —
/// this is a *trusted* rebuild of the daemon's own running config, not an
/// untrusted candidate, so relative rule-provider `path`s must keep
/// resolving the same way they did at startup instead of hard-failing
/// (issue #429 follow-up).
///
/// The result's [`RebuildResult::rule_providers`] carries this build's
/// provider set — a committing caller swaps it into the live registry
/// *after* all validation has passed (issue #533 review).
///
/// `shared_rule_providers` binds an already-loaded provider set into the
/// build instead of parsing `raw.rule_providers` fresh: rules-only
/// refreshes (geodata fetch/auto-update) pass a snapshot of the LIVE
/// registry so the rebuilt `RULE-SET` rules keep referencing the same
/// provider objects the API mutates, rather than a parallel set that
/// would diverge on the next refresh (issue #533 review). Committing
/// callers pass `None` — their candidate set must load fresh so a
/// rejected build never aliases live state.
///
/// `providers` is the live proxy-provider map — group `use:` names
/// resolve against it. Callers that hold no providers pass an empty map;
/// under `strict: true` every `use:` reference then fails the build
/// (there is nothing to resolve against), so background refresh callers
/// must pass the live map, not a placeholder.
///
/// `shared_rule_providers` also skips payload prefetch: bound providers
/// are never re-parsed, so the result's
/// [`RebuildResult::prefetched_payloads`] comes back empty and must not
/// be forwarded to `parse_dns_from_raw` as a shared snapshot (the DNS
/// pass does its own private load for rules-only rebuilds).
///
/// Provider caution: like [`rebuild_from_raw`], this variant binds new
/// providers to a throwaway dialer registry — do not commit
/// [`RebuildResult::proxy_providers`] from it; use
/// [`rebuild_from_raw_runtime`] for committing rebuilds (issue #489).
pub fn rebuild_from_raw_with_resolver(
    raw: &raw::RawConfig,
    resolver: Option<&meow_dns::ResolverSlot>,
    cache_dir: Option<&Path>,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    shared_rule_providers: Option<HashMap<String, Arc<rule_provider::RuleProvider>>>,
) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(
        raw,
        cache_dir,
        resolver,
        providers,
        None,
        None,
        None,
        &meow_proxy::dialer::ProxyRegistry::default(),
        &meow_proxy::dialer::ProxyRegistry::default(),
        shared_rule_providers,
    )
}

/// Runtime rebuild variant that keeps live proxy-provider slots and the
/// process-wide selection store wired into rebuilt groups.
///
/// See [`rebuild_from_raw_with_resolver`] for why `cache_dir` must be the
/// startup provider-cache directory rather than `None`, and for the
/// [`RebuildResult::rule_providers`] commit contract (issue #533 review).
pub fn rebuild_from_raw_runtime(
    raw: &raw::RawConfig,
    resolver: Option<&meow_dns::ResolverSlot>,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    cache_dir: Option<&Path>,
    // The live provider-dialer cell — providers a commit materializes for
    // newly declared defs must share the registry the tunnel republishes,
    // or their `dialer-proxy` chains never resolve (issue #489). Pass
    // `Config::provider_dialer_registry`.
    provider_dialer_registry: &meow_proxy::dialer::ProxyRegistry,
) -> Result<RebuildResult, anyhow::Error> {
    let store = meow_proxy::SelectorStore::global();
    if store.is_none() {
        // First-`open`-wins binds the global at startup; embedders that
        // never call `SelectorStore::open` (e.g. `load_config_from_str`)
        // get the unpersisted behavior — selections reset on rebuild.
        debug!(
            "rebuild_from_raw_runtime: no global SelectorStore; group selections will not persist"
        );
    }
    rebuild_from_raw_impl(
        raw,
        cache_dir,
        resolver,
        providers,
        store.as_ref(),
        None,
        None,
        &meow_proxy::dialer::ProxyRegistry::default(),
        provider_dialer_registry,
        None,
    )
}

/// Same as [`rebuild_from_raw`] but accepts a `cache_dir` used to resolve
/// relative rule-provider paths and to cache fetched HTTP payloads, and an
/// optional DNS `resolver` slot injected into the built-in DIRECT and
/// COMPATIBLE adapters.
///
/// Same provider caveat as [`rebuild_from_raw`]: committed providers need
/// [`rebuild_from_raw_runtime`]'s live registry (issue #489).
pub fn rebuild_from_raw_with_cache_dir(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    resolver: Option<&meow_dns::ResolverSlot>,
) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(
        raw,
        cache_dir,
        resolver,
        &HashMap::new(),
        None,
        None,
        None,
        &meow_proxy::dialer::ProxyRegistry::default(),
        &meow_proxy::dialer::ProxyRegistry::default(),
        None,
    )
}

/// Parse a raw config's `dns:` section into a runnable [`DnsConfig`] with
/// the same geodata context startup uses — `raw.geodata` path overrides,
/// MMDB/geosite loads keyed on the config's own geo references (incl.
/// `nameserver-policy` / `fallback-filter` entries, which the context
/// builder scans). Used by `PUT /configs` DNS hot reload (issue #514);
/// `proxy_registry` should be the freshly rebuilt map so
/// `proxy-server-nameserver` circular-detection sees current names.
///
/// `rule-set:` nameserver-policy keys resolve against the CANDIDATE's own
/// `rule-providers:` declarations — loaded here on demand — never a live
/// registry snapshot: a PUT that adds a provider and references it in the
/// same payload must succeed, and a PUT removing one must not let the old
/// matcher zombie-bind (issue #514 review).
///
/// `prior_resolver` is the resolver generation being replaced — reload
/// paths pass the tunnel's live resolver so the rebuilt one can inherit
/// the fake-IP pool when the range and store identity (in-memory vs the
/// same backing file) are unchanged (issue #514 review follow-up).
/// `None` on cold start.
/// `dialer_registry` is the registry generation `proxy_registry` was built
/// from — provider fetch contexts retain it so a chained download adapter
/// keeps resolving after later rebuilds (issue #533).
/// `rule_providers` is the provider set built alongside `proxy_registry` —
/// DNS `rule-set:` policy matchers clone these Arcs so one provider object
/// is shared by the rules, the matchers, and the live registry the caller
/// commits (issue #533 review). `None` loads `raw.rule_providers`
/// standalone (callers that never wired a rebuild, e.g. tests).
///
/// `prefetched_payloads` is the same commit's prefetched file/http
/// provider payload bytes (`RebuildResult::prefetched_payloads`) — the
/// geo-scan context needs them to see `GEOSITE`/`GEOIP`/`IP-ASN` rules
/// that live only inside provider payloads, and a private provider load
/// parses the same bytes instead of fetching again inside
/// `CONFIG_MUTATION` (issue #543). `None` builds a payload-blind context
/// and fetches on demand — the status quo for callers without a routing
/// rebuild in flight.
pub async fn parse_dns_from_raw(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    proxy_registry: &HashMap<SmolStr, Arc<dyn Proxy>>,
    rule_providers: Option<&HashMap<String, Arc<rule_provider::RuleProvider>>>,
    prefetched_payloads: Option<&Arc<rule_provider::PrefetchedPayloads>>,
    prior_resolver: Option<&meow_dns::Resolver>,
    dialer_registry: Option<&meow_proxy::dialer::ProxyRegistry>,
) -> Result<DnsConfig, anyhow::Error> {
    let geo = geodata::parse_geodata(raw.geodata.as_ref())?;
    let empty = rule_provider::PrefetchedPayloads::default();
    let payloads: &rule_provider::PrefetchedPayloads =
        prefetched_payloads.map_or(&empty, Arc::as_ref);
    let ctx = build_parser_context_from_raw(raw, payloads)?;
    let rule_providers = if dns_parser::dns_needs_rule_providers(raw) {
        match rule_providers {
            Some(shared) => shared.clone(),
            None => {
                load_rule_providers_async(
                    raw.rule_providers.clone().unwrap_or_default(),
                    cache_dir.map(Path::to_path_buf),
                    ctx.clone(),
                    internal_http::first_named_proxy(raw.proxies.as_deref(), proxy_registry),
                    proxy_registry.clone(),
                    prefetched_payloads.map_or_else(
                        || Arc::new(rule_provider::PrefetchedPayloads::default()),
                        Arc::clone,
                    ),
                    dialer_registry.cloned(),
                    raw.strict.unwrap_or(false),
                )
                .await?
            }
        }
    } else {
        HashMap::new()
    };
    let dns = dns_parser::parse_dns(
        raw,
        geo.mmdb_path.as_deref(),
        cache_dir,
        proxy_registry,
        ctx.geosite,
        &rule_providers,
        prior_resolver,
    )
    .await?;
    Ok(dns)
}

/// Prefix of the sentinel dialer target [`apply_dialer_proxies`] binds to a
/// node whose `dialer-proxy` value is malformed in lenient mode. It is never
/// registered in the proxy map, so the node's dials fail loudly ("not in the
/// proxy registry", naming the node via the suffix) instead of silently
/// dialling direct — the same "node loads, dial fails" shape mihomo gives a
/// dialer name that resolves to nothing.
const MALFORMED_DIALER_PREFIX: &str = "__malformed_dialer_proxy__";

/// Apply per-outbound `dialer-proxy` in place (issue #210).
///
/// For every proxy that declares `dialer-proxy: <name>`, its registry entry is
/// re-parsed from the raw config with a [`meow_proxy::dialer::NamedProxyDialer`]
/// injected, so the adapter dials its server through `<name>` transparently
/// (mihomo `proxyDialer` model).
///
/// `<name>` is bound *late*: the injected dialer keeps the name plus a
/// [`meow_proxy::dialer::ProxyRegistry`] handle and looks the front proxy up on
/// every dial, which is what mihomo does (`component/proxydialer/byname.go`).
/// Capturing the front `Arc` here instead freezes whatever the registry holds
/// at build time — and since this pass runs *before* groups are built, so that
/// grouped members inherit the chain (issue #513), a group-valued dialer does
/// not exist yet at that point.
///
/// Adapter types that do not establish their underlying connection through the
/// pluggable dialer — `anytls`, `hysteria2` (QUIC), and `ss` with an external
/// SIP003 plugin — reject the injected dialer at parse time. Those fall back to
/// wrapping the existing entry with a [`meow_proxy::DialerProxyAdapter`] (relay
/// chain), which works where `connect_over` is implemented (direct, reject,
/// http, socks5, snell, vless, vmess, trojan, anytls, and ss without an
/// external plugin) and fails loudly at dial time otherwise (`hysteria2`,
/// `ss` + external SIP003). The fallback never degrades to a direct dial, so
/// a configured chain cannot be silently bypassed.
///
/// UDP: paths that use a raw datagram socket bypass the TCP dialer entirely
/// (Shadowsocks plain relay, SOCKS5 UDP ASSOCIATE). Those refuse the
/// association rather than leaking the real source path; mux-based UDP rides
/// the dialer over TCP and is unaffected.
///
/// A self-referencing dialer, a reference to a name the config does not
/// declare, or a dialer cycle is a hard config error — silently falling back to
/// a direct dial would let traffic egress from the real source path past a
/// chain the user configured for policy/security reasons (Class A, ADR-0002).
/// A cycle has to be caught here in particular: late binding would turn it into
/// unbounded recursion on the first dial. Cycles *through group membership* are
/// checked separately by [`reject_group_membership_cycles`], which runs after
/// the group build where the real membership is known.
///
/// A malformed (non-string, non-null) `dialer-proxy` value rejects the whole
/// config under strict; lenient mode instead binds the node to a
/// [`MALFORMED_DIALER_PREFIX`]-prefixed sentinel target so its dials fail
/// loudly naming the node — the same "node loads, dial fails" shape mihomo
/// gives a dialer name that resolves to nothing — rather than silently
/// egressing direct.
///
/// Returns the applied `(proxy, dialer)` edges so the caller can re-validate
/// dialer targets once groups have been built (a *declared* group that failed
/// to build satisfies `dialable` but never enters the registry) and run
/// [`reject_group_membership_cycles`] against the finished registry.
fn apply_dialer_proxies(
    proxies: &mut HashMap<SmolStr, Arc<dyn Proxy>>,
    raw_proxies: &[HashMap<String, serde_yaml::Value>],
    raw_groups: &[raw::RawProxyGroup],
    registry: &meow_proxy::dialer::ProxyRegistry,
    ipv6: bool,
    strict: bool,
) -> Result<Vec<(SmolStr, SmolStr)>, anyhow::Error> {
    // Collect proxy -> dialer edges from the raw config.
    //
    // Iterate in reverse and keep only the first sighting (the *last* block in
    // the file) per name: the registry-building loop uses `insert`, so for
    // duplicate `name:` entries the last block is the effective definition.
    // Collecting edges from superseded duplicates would apply a chain the
    // effective block never declared.
    let mut edges: Vec<(SmolStr, SmolStr)> = Vec::new();
    let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for raw_proxy in raw_proxies.iter().rev() {
        let Some(name) = raw_proxy.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if !seen_names.insert(name) {
            continue;
        }
        // Entries shadowing a built-in are dropped by `insert_parsed_leaves`;
        // collecting their edge would wrap the *built-in* in a
        // `DialerProxyAdapter` (or replace it via re-parse), chaining global
        // `DIRECT`/`REJECT` traffic through the shadowed node's dialer.
        if BUILTIN_ADAPTER_NAMES.contains(&name) {
            continue;
        }
        let dialer: SmolStr = match raw_proxy.get("dialer-proxy") {
            None => continue,
            Some(v) => match v.as_str() {
                // Trimmed like the provider-node path so
                // `dialer-proxy: " front "` resolves `front` identically
                // on statics instead of missing the `dialable` check below.
                Some(s) if !s.trim().is_empty() => SmolStr::from(s.trim()),
                // `""` and `~` unset the chain in mihomo — not malformed.
                Some("") => continue,
                _ if v.is_null() => continue,
                _ if strict => {
                    anyhow::bail!("proxy '{name}': malformed dialer-proxy value (strict mode)");
                }
                // Lenient keeps the node but binds it to a target that
                // never resolves, so its dials fail loudly naming the node
                // instead of silently dialling direct past the chain the
                // operator asked for. The sentinel is exempt from the
                // `dialable` check below and never collides with a real
                // name by construction.
                _ => {
                    warn!("proxy '{name}': malformed dialer-proxy value; the node will fail its dials");
                    SmolStr::from(format!("{MALFORMED_DIALER_PREFIX}{name}"))
                }
            },
        };
        if dialer.as_str() == name {
            anyhow::bail!("proxy '{name}': dialer-proxy points to itself");
        }
        edges.push((SmolStr::from(name), dialer));
    }
    if edges.is_empty() {
        return Ok(edges);
    }

    // Names a dialer may reference. Leaf proxies are in the registry already;
    // groups are built after this pass, so only their *declared* names count
    // here, plus `GLOBAL`, which is auto-created when the config omits it.
    let dialable: std::collections::HashSet<&str> = proxies
        .keys()
        .map(SmolStr::as_str)
        .chain(raw_groups.iter().map(|group| group.name.as_str()))
        .chain(std::iter::once("GLOBAL"))
        .collect();
    for (name, dialer) in &edges {
        if !dialable.contains(dialer.as_str()) && !dialer.starts_with(MALFORMED_DIALER_PREFIX) {
            anyhow::bail!("proxy '{name}': dialer-proxy '{dialer}' not found");
        }
    }

    // Peel every edge whose dialer declares no dialer of its own. What survives
    // is on a cycle or feeds one, and late binding would recurse forever on it.
    let mut live: std::collections::HashSet<&SmolStr> = edges.iter().map(|(n, _)| n).collect();
    loop {
        let before = live.len();
        for (name, dialer) in &edges {
            if live.contains(name) && !live.contains(dialer) {
                live.remove(name);
            }
        }
        if live.is_empty() || live.len() == before {
            break;
        }
    }
    if !live.is_empty() {
        let cycle: Vec<String> = edges
            .iter()
            .filter(|(name, _)| live.contains(name))
            .map(|(name, dialer)| format!("{name} -> {dialer}"))
            .collect();
        anyhow::bail!("dialer-proxy cycle detected: {}", cycle.join(", "));
    }

    // Apply the edges. Order no longer matters — the front hop is resolved at
    // dial time — so nested chains need no deepest-first deferral pass.
    for (name, dialer) in &edges {
        let target = meow_proxy::dialer::DialerTarget::new(dialer.clone(), registry);
        // `rev()` matters: the registry-building loop above uses `insert`, so
        // for a config with duplicate `name:` entries the *last* block wins. A
        // forward `find` here would resurrect the *first* block and silently
        // swap the running definition out from under the user.
        let Some(raw) = raw_proxies
            .iter()
            .rev()
            .find(|rp| rp.get("name").and_then(|v| v.as_str()) == Some(name.as_str()))
        else {
            // Unreachable in practice — edges are only collected from blocks in
            // this same list — but refuse instead of silently dialing direct if
            // the invariant ever breaks.
            anyhow::bail!(
                "proxy '{name}': dialer-proxy '{dialer}' not applied; no raw \
                 config block found for this name"
            );
        };
        // Re-parse the raw block with the by-name dialer injected (mihomo
        // model), so the adapter's own dial + handshake runs on the tunneled
        // stream.
        let proxy_dialer: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(meow_proxy::dialer::NamedProxyDialer::new(target.clone()));
        match proxy_parser::parse_proxy_with_dialer(raw, &proxy_dialer, ipv6) {
            Ok(rebuilt) => {
                proxies.insert(name.clone(), rebuilt);
            }
            Err(e) if strict => {
                // Under `strict` the dial-time failure the relay wrapper
                // defers to is not acceptable — surface it at load.
                return Err(anyhow::anyhow!(
                    "proxy '{name}': cannot inject dialer-proxy '{dialer}' \
                     (strict mode): {e}"
                ));
            }
            Err(e) => {
                // The adapter type cannot carry an injected dialer (anytls,
                // hysteria2, SS-with-external-SIP003-plugin) or the block is
                // otherwise unparseable. Fall back to the relay-based
                // `DialerProxyAdapter`, which preserves the pre-dialer
                // behaviour: it works for the protocols that implement
                // `connect_over` (direct/reject/http/socks5/snell/vless/
                // vmess/trojan/anytls/ss-without-external-plugin) and fails
                // loudly at dial time for the rest (hysteria2, ss + external
                // SIP003) — never silently dialing direct and leaking past
                // the chain.
                //
                // The inner outbound may itself have failed to parse earlier,
                // in which case there is nothing to wrap.
                if let Some(inner) = proxies.get(name).cloned() {
                    warn!(
                        "proxy '{name}': cannot inject dialer-proxy '{dialer}' \
                         ({e}); falling back to the relay-based wrapper"
                    );
                    let wrapped: Arc<dyn Proxy> =
                        Arc::new(meow_proxy::DialerProxyAdapter::new(inner, target));
                    proxies.insert(name.clone(), wrapped);
                } else {
                    warn!(
                        "proxy '{name}': dialer-proxy '{dialer}' not applied \
                         ({e}); the outbound itself failed to parse"
                    );
                }
            }
        }
    }
    Ok(edges)
}

/// Reject cycles in the declared group-membership graph (issue #562).
///
/// Groups may name other groups as members, and the multi-pass build defers
/// a group until its declared group dependencies have built. A cyclic set
/// can never satisfy that: every member waits on another, and without this
/// check the lenient fallback silently drops the unresolved edges — the
/// built graph loses the declared cycle and the outcome depends on
/// declaration order. Detect the cycle on the *declared* graph and report
/// its path (`A -> B -> A`) before any construction, matching mihomo's
/// `proxyGroupsDagSort` rejection (which reports only the involved names).
///
/// Edges come only from explicit `proxies:` members that name a declared
/// group. Provider slots (`use:`/`include-all`) resolve to leaf nodes and
/// `include-all-proxies` expands to leaf proxies only, so neither can close
/// a cycle here. Callers must run the duplicate-name check first — this
/// function assumes each group name is declared at most once.
///
/// A declared self-reference is rejected even when `exclude-filter`
/// would have matched it — the same as upstream, whose DAG check reads
/// the raw `proxies:` member names before any filter applies (meow-rs
/// likewise never applies `exclude-filter` to static members).
fn reject_declared_group_cycles(raw_groups: &[raw::RawProxyGroup]) -> Result<(), anyhow::Error> {
    debug_assert!(
        raw_groups
            .iter()
            .map(|g| g.name.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
            == raw_groups.len(),
        "caller must run the duplicate-name check first"
    );
    let declared: std::collections::HashSet<&str> =
        raw_groups.iter().map(|g| g.name.as_str()).collect();
    let edges: HashMap<&str, Vec<&str>> = raw_groups
        .iter()
        .map(|g| {
            (
                g.name.as_str(),
                g.proxies
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(String::as_str)
                    .filter(|m| declared.contains(m))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();

    // Iterative three-colour DFS — `stack`/`progress` track the live DFS
    // path in lockstep so a back-edge reports the actual cycle.
    #[derive(Clone, Copy)]
    enum Mark {
        Visiting,
        Done,
    }
    let mut marks: HashMap<&str, Mark> = HashMap::with_capacity(raw_groups.len());
    for group in raw_groups {
        let start = group.name.as_str();
        if marks.contains_key(start) {
            continue;
        }
        marks.insert(start, Mark::Visiting);
        let mut stack: Vec<&str> = vec![start];
        let mut progress: Vec<usize> = vec![0];
        while let Some(&node) = stack.last() {
            let idx = progress.last_mut().expect("progress tracks stack");
            let children = &edges[node];
            if *idx < children.len() {
                let child = children[*idx];
                *idx += 1;
                match marks.get(child) {
                    Some(Mark::Visiting) => {
                        let pos = stack
                            .iter()
                            .position(|&n| n == child)
                            .expect("visiting node is on the DFS stack");
                        let cycle: Vec<&str> = stack[pos..]
                            .iter()
                            .copied()
                            .chain(std::iter::once(child))
                            .collect();
                        anyhow::bail!("proxy-group cycle detected: {}", cycle.join(" -> "));
                    }
                    Some(Mark::Done) => {}
                    None => {
                        marks.insert(child, Mark::Visiting);
                        stack.push(child);
                        progress.push(0);
                    }
                }
            } else {
                marks.insert(node, Mark::Done);
                stack.pop();
                progress.pop();
            }
        }
    }
    Ok(())
}

/// Reject any `dialer-proxy` edge whose target can route the front-hop dial
/// back to the chained proxy through group membership — a loop that never
/// reaches I/O: it is synchronous nested polls and exhausts the native stack
/// on the first dial (mihomo's `validateDialerProxies` only sees proxy→proxy
/// edges and has the same blind spot).
///
/// Runs after the group build so the model matches the *built* registry:
/// groups that failed to build contribute no membership edges, and a declared
/// `GLOBAL` that failed to build is backstopped by the auto-created one
/// holding every registry entry — modelling declared membership before the
/// build would miss both.
///
/// Conservative over-approximations, all fail-closed: `include-all-proxies`
/// expands to the successfully parsed top-level `proxies:` entries; relay
/// members are all
/// treated as reachable heads (only the first member's dialer can actually
/// fire); provider-slot members (`use:` / `include-all`) are dead ends —
/// provider nodes CAN carry a `dialer-proxy` (issue #489) but provider
/// membership is dynamic and unknowable here, so that recursion shape is
/// caught by the dial-time depth guard in `meow_proxy::dialer` instead.
fn reject_group_membership_cycles(
    edges: &[(SmolStr, SmolStr)],
    raw_groups: &[raw::RawProxyGroup],
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    include_all_proxy_names: &std::collections::HashSet<SmolStr>,
    global_auto_created: bool,
) -> Result<(), anyhow::Error> {
    if edges.is_empty() {
        return Ok(());
    }
    let mut members_of: HashMap<&str, Vec<&str>> = HashMap::new();
    for group in raw_groups {
        if !proxies.contains_key(group.name.as_str()) {
            // Never built — its entry is absent, so it contributes no
            // membership edges at runtime.
            continue;
        }
        let mut members: Vec<&str> = group
            .proxies
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .filter(|m| proxies.contains_key(*m))
            .collect();
        if group.include_all_proxies.unwrap_or(false) {
            members.extend(
                include_all_proxy_names
                    .iter()
                    .filter(|name| proxies.contains_key(name.as_str()))
                    .map(SmolStr::as_str),
            );
        }
        members_of
            .entry(group.name.as_str())
            .or_default()
            .extend(members);
    }
    if global_auto_created {
        // `or_default().extend` also covers the corner where a GLOBAL
        // group was declared but failed to build: its declared members
        // merged with this all-registry list. Those phantom edges are
        // safe — they can only point at the filtered built-ins
        // (PASS/REJECT-DROP/COMPATIBLE), which are dead ends in this
        // graph (built-ins are never dialer sources and have no
        // members), so the merge cannot produce a false-positive cycle.
        members_of
            .entry("GLOBAL")
            .or_default()
            .extend(proxies.keys().map(SmolStr::as_str));
    }
    // Only edges whose source actually entered the registry produce a wrapped
    // adapter; an unparseable source can never fire its chain, so following
    // its edge would be a phantom.
    let edge_map: HashMap<&str, &str> = edges
        .iter()
        .filter(|(name, _)| proxies.contains_key(name))
        .map(|(name, dialer)| (name.as_str(), dialer.as_str()))
        .collect();
    // DFS from each dialer over dialer edges and membership edges; reaching the
    // edge's source means the first dial recurses without bound.
    for (name, dialer) in edges {
        if !proxies.contains_key(name) {
            continue;
        }
        let mut stack: Vec<&str> = vec![dialer.as_str()];
        let mut visited: std::collections::HashSet<&str> = std::collections::HashSet::new();
        while let Some(node) = stack.pop() {
            if node == name.as_str() {
                anyhow::bail!(
                    "proxy '{name}': dialer-proxy '{dialer}' can route back to \
                     '{name}' through group membership, which would recurse \
                     forever on the first dial"
                );
            }
            if !visited.insert(node) {
                continue;
            }
            if let Some(next) = edge_map.get(node) {
                stack.push(next);
            }
            if let Some(members) = members_of.get(node) {
                stack.extend(members.iter().copied());
            }
        }
    }
    Ok(())
}

/// Policy names resolved internally rather than declared as usable outbounds.
/// They must not become the default member of an auto-created `GLOBAL` group:
/// choosing `DIRECT` would make global mode silently bypass every proxy.
const BUILTIN_GLOBAL_POLICIES: [&str; 8] = [
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "PASS-RULE",
    "COMPATIBLE",
    "GLOBAL",
    "BLOCK",
];

/// Built-in adapter names a `proxies:` leaf or `proxy-groups:` entry must
/// not shadow. Upstream hard-errors on the duplicate (`proxy %s is the
/// duplicate name`); meow keeps the built-in and drops the shadowing entry
/// instead — a shadowed `PASS` would silently invert "skip this rule" into
/// "proxy it" (issue #533).
const BUILTIN_ADAPTER_NAMES: [&str; 6] = [
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "COMPATIBLE",
    "PASS",
    "PASS-RULE",
];

fn is_usable_global_target(name: &str, proxies: &HashMap<SmolStr, Arc<dyn Proxy>>) -> bool {
    !BUILTIN_GLOBAL_POLICIES
        .iter()
        .any(|policy| name.eq_ignore_ascii_case(policy))
        && proxies.contains_key(name)
}

/// Find the outbound a config is built around, preserving declaration order.
/// The final valid `MATCH` target is authoritative; otherwise prefer the first
/// successfully-built group, then the first successfully-built leaf proxy.
fn primary_global_target<'a>(
    raw: &'a raw::RawConfig,
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
) -> Option<&'a str> {
    let match_target = raw
        .rules
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .rev()
        .find_map(|rule| {
            let mut parts = rule.split(',').map(str::trim);
            if !parts.next()?.eq_ignore_ascii_case("MATCH") {
                return None;
            }
            parts.next()
        });
    if let Some(target) = match_target.filter(|target| is_usable_global_target(target, proxies)) {
        return Some(target);
    }

    if let Some(group) = raw
        .proxy_groups
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|group| is_usable_global_target(&group.name, proxies))
    {
        return Some(&group.name);
    }

    raw.proxies
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|proxy| proxy.get("name").and_then(serde_yaml::Value::as_str))
        .find(|name| is_usable_global_target(name, proxies))
}

/// Post-#562 a declared group dep that stays unbuilt can only mean it
/// *failed* to build — cycles are rejected before the build loop, so
/// stalling here is never "still waiting on a cyclic dep".
fn has_unresolved_group_dependency(
    group: &raw::RawProxyGroup,
    declared_group_names: &std::collections::HashSet<&str>,
    built_group_names: &std::collections::HashSet<SmolStr>,
) -> bool {
    group.proxies.as_deref().unwrap_or(&[]).iter().any(|name| {
        declared_group_names.contains(name.as_str()) && !built_group_names.contains(name.as_str())
    })
}

/// Parse every `proxies:` leaf entry into `proxies`, keyed by its YAML `name:`
/// (`proxy.name()` only as fallback — `DirectAdapter::name()` is hardcoded to
/// "DIRECT" and would overwrite the built-in, hiding a user-named direct proxy
/// from groups). `static_proxy_names` collects the same keys so the caller can
/// distinguish static leaves from group/provider members when modelling
/// `include-all-proxies` and membership cycles. Factored out of
/// `build_proxy_layer` so the key derivation lives in exactly one place.
fn insert_parsed_leaves(
    proxies: &mut HashMap<SmolStr, Arc<dyn Proxy>>,
    static_proxy_names: &mut std::collections::HashSet<SmolStr>,
    raw_proxies: &[HashMap<String, serde_yaml::Value>],
    ipv6: bool,
    strict: bool,
) -> Result<(), anyhow::Error> {
    for raw_proxy in raw_proxies {
        match proxy_parser::parse_proxy(raw_proxy, ipv6) {
            Ok(proxy) => {
                // Prefer the YAML `name:` as the registry key. `proxy.name()`
                // is fine for SS/Trojan/VLESS (their parsers thread the name
                // into the adapter) but `DirectAdapter::name()` is hardcoded
                // to "DIRECT" and would overwrite the built-in, hiding any
                // user-named direct proxy (e.g. `name: "直连"`) from groups.
                let key: SmolStr = raw_proxy
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| proxy.name())
                    .into();
                if BUILTIN_ADAPTER_NAMES.contains(&key.as_str()) {
                    if strict {
                        return Err(anyhow::anyhow!(
                            "proxies: '{key}' shadows a built-in adapter (strict mode)"
                        ));
                    }
                    warn!(
                        "Proxy named '{key}' shadows a built-in adapter; the \
                         entry is dropped and the built-in stays"
                    );
                    continue;
                }
                static_proxy_names.insert(key.clone());
                // A repeated leaf name silently last-wins here — a
                // deliberate divergence from upstream's
                // `proxy %s is the duplicate name` hard error. Leaf
                // duplicates are safe to keep: all leaves settle before
                // any group captures members, so they cannot split the
                // registry the way group duplicates did (#561).
                proxies.insert(key, proxy);
            }
            Err(e) if strict => {
                let name = raw_proxy
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unnamed>");
                return Err(anyhow::anyhow!(
                    "proxies: failed to parse '{name}' (strict mode): {e}"
                ));
            }
            Err(e) => warn!("Failed to parse proxy: {}", e),
        }
    }
    Ok(())
}

/// Materialize the proxy-provider set for one candidate build (issue #533
/// strict-mode review): the candidate's own `proxy-providers:` declarations
/// are the `use:`/`include-all` authority — not the caller's live map.
///
/// - A name still declared with an unchanged definition reuses the live
///   [`Arc`] — provider slots, fetched content, and health state carry over
///   into the rebuilt groups. A *changed* definition rebuilds the provider:
///   reusing the old object would keep fetching the old `url`/`path` with the
///   old filters forever while the committed config claims otherwise
///   (issue #533 review).
/// - A newly declared def constructs an empty [`ProxyProvider`] (no fetch —
///   this path is sync); the committing caller installs it into the live
///   registry and spawns the initial refresh, so `use:`/`include-all` wire a
///   real slot instead of dangling until restart.
/// - A def that fails construction is warn-skipped leniently and a hard
///   error under `strict` — the same gate startup's
///   [`proxy_provider::load_proxy_providers`] applies, so a committed
///   candidate cannot carry a def that would fail the next boot.
///
/// Providers absent from the candidate's declarations drop out: `use:` of a
/// removed name then fails loudly (strict) or warns (lenient) instead of
/// silently resolving to the zombie object.
fn materialize_proxy_providers(
    raw: &raw::RawConfig,
    live: &HashMap<String, Arc<ProxyProvider>>,
    cache_dir: Option<&Path>,
    strict: bool,
    // The long-lived cell the tunnel republishes the route map into —
    // newly declared providers must share it, or their `dialer-proxy`
    // nodes can never resolve (issue #489).
    provider_dialer_registry: &meow_proxy::dialer::ProxyRegistry,
) -> Result<HashMap<String, Arc<ProxyProvider>>, anyhow::Error> {
    let Some(raw_map) = raw.proxy_providers.as_ref() else {
        return Ok(HashMap::new());
    };
    let ipv6 = effective_ipv6(raw.ipv6);
    let mut out = HashMap::with_capacity(raw_map.len());
    for (name, def) in raw_map {
        if let Some(provider) = live.get(name) {
            if provider.matches_def(def, ipv6) {
                out.insert(name.clone(), Arc::clone(provider));
                continue;
            }
        }
        match ProxyProvider::new(
            name,
            def,
            cache_dir,
            ipv6,
            strict,
            provider_dialer_registry.clone(),
        ) {
            Ok(provider) => {
                out.insert(name.clone(), Arc::new(provider));
            }
            Err(e) if strict => {
                return Err(anyhow::anyhow!(
                    "proxy-provider '{name}' failed to load (strict mode): {e}"
                ));
            }
            Err(e) => {
                warn!("failed to create proxy-provider '{name}': {e}");
            }
        }
    }
    Ok(out)
}

/// Build the complete proxy layer for one config: built-ins, `proxies:` leaf
/// adapters, `dialer-proxy` chains, proxy groups and the auto-created GLOBAL
/// selector, with every chain/cycle invariant validated. Shared between the
/// real build and the pre-registry prefetch map so a prefetch resolves
/// `dialer-proxy`/`proxy:` names against exactly the layer the runtime will
/// publish (issue #533).
///
/// `resolver` is injected into `DIRECT`/`COMPATIBLE` (pass 2 of the startup
/// build); the prefetch map and pass 1 pass `None`, matching their
/// no-resolver stage.
/// `registry` is the cell the `dialer-proxy` targets bind to weakly — the
/// caller publishes the returned map into it and must keep the cell alive
/// for as long as the adapters are used. `providers` is the candidate
/// provider set from [`materialize_proxy_providers`].
fn build_proxy_layer(
    raw: &raw::RawConfig,
    resolver: Option<&meow_dns::ResolverSlot>,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    selector_store: Option<&Arc<meow_proxy::SelectorStore>>,
    registry: &meow_proxy::dialer::ProxyRegistry,
    strict: bool,
) -> Result<HashMap<SmolStr, Arc<dyn Proxy>>, anyhow::Error> {
    let ipv6 = effective_ipv6(raw.ipv6);
    let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
    let mut static_proxy_names = std::collections::HashSet::new();
    // Built-in proxies — upstream registers DIRECT, REJECT, REJECT-DROP,
    // COMPATIBLE, PASS, PASS-RULE (`config.go` ~line 891).
    let make_direct = |compatible: bool| {
        let mut direct = if compatible {
            meow_proxy::DirectAdapter::compatible()
        } else {
            meow_proxy::DirectAdapter::new()
        };
        if let Some(mark) = raw.routing_mark {
            direct = direct.with_routing_mark(mark);
        }
        if let Some(slot) = resolver.cloned() {
            direct = direct.with_resolver_slot(slot);
        }
        if let Some(secs) = raw.tcp_connect_timeout {
            direct = direct.with_connect_timeout(std::time::Duration::from_secs(secs));
        }
        direct
    };
    proxies.insert(
        SmolStr::new_static("DIRECT"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(make_direct(
            false,
        )))),
    );
    proxies.insert(
        SmolStr::new_static("REJECT"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(
            meow_proxy::RejectAdapter::new(false),
        ))),
    );
    proxies.insert(
        SmolStr::new_static("REJECT-DROP"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(
            meow_proxy::RejectAdapter::new(true),
        ))),
    );
    // `COMPATIBLE` dials direct like DIRECT but carries its own type tag —
    // upstream uses it as GLOBAL's default member; here rules may target
    // it for an explicit direct dial.
    proxies.insert(
        SmolStr::new_static("COMPATIBLE"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(make_direct(true)))),
    );
    // `PASS` / `PASS-RULE` are Reject-shaped nops; the match engines read
    // their type tags (Pass → silent rule skip, PassRule → inner-rule skip
    // inside SUB-RULE blocks) instead of ever dialing them.
    proxies.insert(
        SmolStr::new_static("PASS"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(
            meow_proxy::RejectAdapter::pass(),
        ))),
    );
    proxies.insert(
        SmolStr::new_static("PASS-RULE"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(
            meow_proxy::RejectAdapter::pass_rule(),
        ))),
    );

    insert_parsed_leaves(
        &mut proxies,
        &mut static_proxy_names,
        raw.proxies.as_deref().unwrap_or(&[]),
        ipv6,
        strict,
    )?;

    let raw_groups = raw.proxy_groups.as_deref().unwrap_or(&[]);

    // Reject duplicate group names before construction (issue #561). The
    // multi-pass build below captures member `Arc`s eagerly: a same-named
    // group built in a later pass would replace the registry entry while
    // parents that already built keep the superseded instance, so the
    // registry and such parents would disagree about what the name resolves
    // to. Mirroring mihomo's `proxy group %s: the duplicate name` check, a
    // group name must not collide with an existing registry entry (built-in
    // or parsed proxy) or another declared group. All six built-ins —
    // DIRECT/REJECT/REJECT-DROP plus COMPATIBLE/PASS/PASS-RULE — are
    // already in `proxies`, so the registry check covers them.
    let mut seen_group_names: std::collections::HashSet<&str> =
        std::collections::HashSet::with_capacity(raw_groups.len());
    for group in raw_groups {
        anyhow::ensure!(
            !proxies.contains_key(group.name.as_str()),
            "proxy group '{}': the duplicate name — already used by a \
             proxy or reserved built-in",
            group.name
        );
        anyhow::ensure!(
            seen_group_names.insert(group.name.as_str()),
            "proxy group '{}': the duplicate name — declared more than once",
            group.name
        );
    }

    reject_declared_group_cycles(raw_groups)?;

    // Apply per-outbound `dialer-proxy` chains (issue #210) *before* groups are
    // built: groups clone their members eagerly, so a chain applied afterwards
    // would only cover direct rule references and a grouped node would silently
    // bypass it (issue #513). The front hop is resolved by name at dial time,
    // which is what lets a dialer name a group that does not exist yet here.
    let dialer_edges = apply_dialer_proxies(
        &mut proxies,
        raw.proxies.as_deref().unwrap_or(&[]),
        raw_groups,
        registry,
        ipv6,
        strict,
    )?;

    // Mihomo expands `include-all-proxies` from the top-level `proxies:`
    // entries only. Capture those adapters after dialer wrapping but before
    // any groups enter the registry, and keep mihomo's name-sorted order.
    let mut include_all_proxies: Vec<(SmolStr, Arc<dyn Proxy>)> = static_proxy_names
        .iter()
        .filter_map(|name| {
            proxies
                .get(name.as_str())
                .map(|proxy| (name.clone(), Arc::clone(proxy)))
        })
        .collect();
    include_all_proxies.sort_by(|(left, _), (right, _)| left.cmp(right));
    let include_all_proxies: Vec<Arc<dyn Proxy>> = include_all_proxies
        .into_iter()
        .map(|(_, proxy)| proxy)
        .collect();

    // Strict mode: a `use:` name that resolves to nothing is a permanent
    // miss — providers are all loaded before groups, so check upfront rather
    // than letting the lenient group passes silently drop the reference.
    if strict {
        for raw_group in raw_groups {
            // `use:` is never consulted when `include-all`/
            // `include-all-providers` supplies the membership, or when the
            // group is a `relay` (chains only static `proxies:` members —
            // the parser ignores provider slots) — don't reject a name the
            // build would never look up (issue #533 review).
            if raw_group.include_all.unwrap_or(false)
                || raw_group.include_all_providers.unwrap_or(false)
                || raw_group.group_type == "relay"
            {
                continue;
            }
            for pname in raw_group.use_providers.as_deref().unwrap_or(&[]) {
                if !providers.contains_key(pname.as_str()) {
                    return Err(anyhow::anyhow!(
                        "proxy-groups: group '{}' references unknown proxy-provider \
                         '{pname}' (strict mode)",
                        raw_group.name
                    ));
                }
            }
        }
    }

    // Multi-pass group resolution: groups can reference other groups.
    // Keep trying until no new groups are resolved.
    let declared_group_names: std::collections::HashSet<&str> =
        raw_groups.iter().map(|group| group.name.as_str()).collect();
    let mut built_group_names: std::collections::HashSet<SmolStr> =
        std::collections::HashSet::new();
    let mut remaining: Vec<&raw::RawProxyGroup> = raw_groups.iter().collect();
    let mut max_passes = remaining.len() + 1;
    while !remaining.is_empty() && max_passes > 0 {
        max_passes -= 1;
        let mut still_remaining = Vec::new();
        let mut strict_progress = false;
        for raw_group in &remaining {
            if has_unresolved_group_dependency(raw_group, &declared_group_names, &built_group_names)
            {
                still_remaining.push(*raw_group);
                continue;
            }

            match proxy_parser::parse_proxy_group_with_store(
                raw_group,
                &proxies,
                &include_all_proxies,
                providers,
                selector_store,
            ) {
                Ok(group) => {
                    let name = SmolStr::from(group.name());
                    built_group_names.insert(name.clone());
                    // The declaration-level check above already rejected
                    // every name present in `proxies` (built-ins and
                    // parsed leaves) and every repeat, so this name is
                    // fresh by construction.
                    proxies.insert(name, group);
                    strict_progress = true;
                }
                Err(_) => {
                    still_remaining.push(*raw_group);
                }
            }
        }

        if still_remaining.is_empty() {
            remaining.clear();
            break;
        }
        if strict_progress {
            remaining = still_remaining;
            continue;
        }

        // Strict member-resolution has stalled. Under `strict: true` there is
        // no lenient rescue: every group left here has a permanent failure —
        // a missing static member, an invalid definition, or a declared group
        // dependency that itself failed to build (unknown `use:` providers
        // were already rejected upfront). Re-parse each strictly so the
        // reported error names the offending member, then fail the load with
        // all of them.
        if strict {
            let mut details = Vec::new();
            for raw_group in &still_remaining {
                if let Err(e) = proxy_parser::parse_proxy_group_with_store(
                    raw_group,
                    &proxies,
                    &include_all_proxies,
                    providers,
                    selector_store,
                ) {
                    details.push(format!("'{}': {e}", raw_group.name));
                }
            }
            return Err(anyhow::anyhow!(
                "proxy-groups: strict mode rejected {} group(s): {}",
                details.len(),
                details.join("; ")
            ));
        }

        // Strict parsing stalled. Leniently build only groups whose declared
        // group dependencies are ready, then resume strict passes. This keeps
        // missing static members from blocking forward group references while
        // preserving the existing build timing for groups that can resolve
        // strictly (notably include-all-proxies registry snapshots).
        let mut lenient_remaining = Vec::new();
        let mut lenient_progress = false;
        for raw_group in &still_remaining {
            if has_unresolved_group_dependency(raw_group, &declared_group_names, &built_group_names)
            {
                lenient_remaining.push(*raw_group);
                continue;
            }

            match proxy_parser::parse_proxy_group_lenient_with_store(
                raw_group,
                &proxies,
                &include_all_proxies,
                providers,
                selector_store,
            ) {
                Ok(group) => {
                    let name = SmolStr::from(group.name());
                    built_group_names.insert(name.clone());
                    proxies.insert(name, group);
                    lenient_progress = true;
                }
                Err(_) => {
                    lenient_remaining.push(*raw_group);
                }
            }
        }

        if !lenient_progress {
            // No strict or dependency-aware lenient progress is possible.
            // Preserve meow-rs's final fallback: warn about unresolved members
            // and build each group with whatever resolved. Unlike mihomo,
            // which rejects missing static members, meow-rs does not fail the
            // entire config here.
            for raw_group in &lenient_remaining {
                match proxy_parser::parse_proxy_group_lenient_with_store(
                    raw_group,
                    &proxies,
                    &include_all_proxies,
                    providers,
                    selector_store,
                ) {
                    Ok(group) => {
                        let name = SmolStr::from(group.name());
                        proxies.insert(name, group);
                    }
                    // Unreachable under `strict` — a stalled strict pass
                    // already returned above — so no strict arm here.
                    Err(e) => warn!("Failed to parse proxy group '{}': {}", raw_group.name, e),
                }
            }
            break;
        }
        remaining = lenient_remaining;
    }

    // Defensive: `max_passes` (groups + 1) is provably sufficient — every
    // pass either shrinks `remaining` or stalls out loudly — but never let
    // an exhausted loop silently drop groups under `strict` (issue #533
    // review).
    if strict && !remaining.is_empty() {
        let names: Vec<&str> = remaining.iter().map(|g| g.name.as_str()).collect();
        return Err(anyhow::anyhow!(
            "proxy-groups: strict mode could not resolve {} group(s) after {} passes: {}",
            names.len(),
            raw_groups.len() + 1,
            names.join(", ")
        ));
    }

    // Auto-create GLOBAL selector if not defined by user (mihomo compatibility).
    // clash-nyanpasu and other frontends depend on GLOBAL to build proxy tree.
    // Keep the complete sorted list they expect, but put the config's primary
    // outbound first: SelectorGroup uses its first member when no choice has
    // been stored, and sorting every registry key previously made global mode
    // default to DIRECT or an alphabetically-first quota/expiry pseudo-node.
    let had_global = proxies.contains_key("GLOBAL");
    if !had_global {
        let mut all_proxy_names: Vec<String> = proxies
            .iter()
            // Upstream seeds the GLOBAL member provider from `proxyList` —
            // DIRECT, REJECT, user leaves and groups — so RejectDrop and
            // Compatible never appear as members (COMPATIBLE is only the
            // default selection), and the Pass/PassRule types are filtered
            // as match-loop signals (config.go ~line 967).
            .filter(|(_, p)| {
                !matches!(
                    p.adapter_type(),
                    AdapterType::Pass
                        | AdapterType::PassRule
                        | AdapterType::Compatible
                        | AdapterType::RejectDrop
                )
            })
            .map(|(name, _)| name.to_string())
            .collect();
        all_proxy_names.sort();
        let primary = primary_global_target(raw, &proxies).map(str::to_string);
        if let Some(primary) = primary.as_deref() {
            if let Some(position) = all_proxy_names.iter().position(|name| name == primary) {
                all_proxy_names.remove(position);
                all_proxy_names.insert(0, primary.to_string());
            }
        }
        let global_config = raw::RawProxyGroup {
            name: "GLOBAL".to_string(),
            group_type: "select".to_string(),
            proxies: Some(all_proxy_names),
            ..Default::default()
        };
        match proxy_parser::parse_proxy_group_with_store(
            &global_config,
            &proxies,
            &[],
            providers,
            selector_store,
        ) {
            Ok(group) => {
                proxies.insert(SmolStr::new_static("GLOBAL"), group);
                info!(
                    primary = primary.as_deref().unwrap_or("DIRECT"),
                    "Auto-created GLOBAL selector with all proxies"
                );
            }
            Err(e) => warn!("Failed to create GLOBAL selector: {}", e),
        }
    }
    // Whether `GLOBAL` is the auto-created all-registry selector or a declared
    // group changes what a `dialer-proxy: GLOBAL` edge can reach.
    let global_auto_created = !had_global && proxies.contains_key("GLOBAL");

    // `dialable` admitted *declared* group names before the group build ran;
    // a group that failed to build never entered the registry, so re-check
    // every dialer target against the finished map instead of letting the
    // first dial report it late. Lenient-mode malformed-value sentinels are
    // exempt: they are deliberately unresolvable so the node's dials fail
    // loudly at dial time rather than here at load.
    for (name, dialer) in &dialer_edges {
        if !proxies.contains_key(dialer.as_str()) && !dialer.starts_with(MALFORMED_DIALER_PREFIX) {
            anyhow::bail!(
                "proxy '{name}': dialer-proxy '{dialer}' is declared but did \
                 not build into a registry entry"
            );
        }
    }

    // Cycles that run through group membership — including a declared-but-
    // failed GLOBAL that the auto-create just backstopped — are only decidable
    // now that the registry is finished.
    reject_group_membership_cycles(
        &dialer_edges,
        raw_groups,
        &proxies,
        &static_proxy_names,
        global_auto_created,
    )?;

    Ok(proxies)
}

/// A full proxy layer for the pre-registry payload prefetch — built by the
/// same [`build_proxy_layer`] the real build uses, then published into a
/// private registry cell so chained adapters resolve their front hops during
/// the fetch (issue #533). `_registry` must stay alive for the map's whole
/// use: the adapters hold it weakly.
struct PrefetchProxies {
    map: HashMap<SmolStr, Arc<dyn Proxy>>,
    _registry: meow_proxy::dialer::ProxyRegistry,
}

fn prefetch_proxy_map(
    raw: &raw::RawConfig,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    selector_store: Option<&Arc<meow_proxy::SelectorStore>>,
) -> Result<Option<PrefetchProxies>, anyhow::Error> {
    // No `proxies:` entries means nothing to tunnel through — named `proxy:`
    // lookups and the default proxy all come back empty either way. Such a
    // config's provider `proxy:` names (a group, or GLOBAL) simply defer to
    // the load pass, which resolves them against the pass-1 registry.
    if raw.proxies.as_deref().unwrap_or(&[]).is_empty() {
        return Ok(None);
    }
    let registry = meow_proxy::dialer::ProxyRegistry::default();
    // A rejected layer (bad chain, group-declaration or membership
    // cycle) hard-fails the real build with the same error; surface it
    // now instead of letting default-proxy provider/geodata fetches
    // egress direct on a config that intends chained egress.
    let map = build_proxy_layer(
        raw,
        None,
        providers,
        selector_store,
        &registry,
        raw.strict.unwrap_or(false),
    )?;
    registry.publish(Arc::new(map.clone()));
    Ok(Some(PrefetchProxies {
        map,
        _registry: registry,
    }))
}

/// Build the prefetch proxy layer on a blocking thread — adapter and group
/// construction can spawn plugin subprocesses and read TLS material, so it
/// must not run inline on the async executor. `selector_store` is threaded
/// in so a `select` group's persisted choice resolves to the same member
/// the runtime build would pick. A rejected layer or a failed build task
/// surfaces as `Err` — the same failure pass 1 of the real build reports.
async fn prefetch_proxy_layer_async(
    raw: &raw::RawConfig,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    selector_store: Option<&Arc<meow_proxy::SelectorStore>>,
) -> Result<Option<Arc<PrefetchProxies>>, anyhow::Error> {
    let raw = raw.clone();
    let providers = providers.clone();
    let selector_store = selector_store.cloned();
    spawn_blocking_with_current_dispatcher(move || {
        prefetch_proxy_map(&raw, &providers, selector_store.as_ref())
    })
    .await
    .map_err(|e| anyhow::anyhow!("prefetch proxy-layer build task failed: {e}"))?
    .map(|o| o.map(Arc::new))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the rebuild passes every stage of one config build through; \
              bundling them would only rename the same list"
)]
fn rebuild_from_raw_impl(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    resolver: Option<&meow_dns::ResolverSlot>,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    selector_store: Option<&Arc<meow_proxy::SelectorStore>>,
    shared_ctx: Option<&meow_rules::ParserContext>,
    prefetched_payloads: Option<Arc<rule_provider::PrefetchedPayloads>>,
    // `dialer-proxy` front hops are resolved by name against this registry on
    // every dial; it is published once the build below has finished. The
    // caller supplies the cell so a multi-pass build (startup) can share one
    // registry generation across passes; it is returned in [`RebuildResult`]
    // so the generation owner can retain it (issue #533).
    registry: &meow_proxy::dialer::ProxyRegistry,
    // The cell provider-sourced `dialer-proxy` targets resolve against —
    // reused providers already hold it internally; newly declared ones are
    // constructed with it here. Callers without a long-lived cell (config
    // validation, tests) may pass a throwaway: providers built on it never
    // dial in those contexts (issue #489).
    provider_dialer_registry: &meow_proxy::dialer::ProxyRegistry,
    // An already-loaded provider set to bind into this build (startup's
    // two-pass build shares the set it loaded for DNS so rules, DNS
    // `rule-set:` matchers, and `Config.rule_providers` all reference one
    // object per provider). `None` = parse `raw.rule_providers` fresh.
    shared_providers: Option<HashMap<String, Arc<rule_provider::RuleProvider>>>,
) -> Result<RebuildResult, anyhow::Error> {
    // Top-level `strict: true` (issue #533): warn-skipped entries become
    // hard errors — proxies, proxy-groups and rules are covered inside
    // `build_proxy_layer`/`parse_rules_full`; proxy-provider definitions
    // and provider payload nodes are gated by the caller (they are async).
    let strict = raw.strict.unwrap_or(false);

    // Materialize this candidate's proxy-provider set: reuse the caller's
    // live objects for still-declared names (their slots, health state, and
    // fetched content carry over) and construct empty providers for newly
    // declared defs. The candidate's own `proxy-providers:` declarations —
    // not the caller's live map — are the `use:`/`include-all` authority:
    // a `PUT /configs` that drops a provider must not leave `use:`
    // resolving to a zombie Arc, and one adding a provider must let groups
    // wire its (initially empty) slot instead of failing "unknown
    // provider" (issue #533 review). `strict` also validates newly
    // declared defs here so a bad def can't be committed and then fail the
    // next startup.
    let candidate_providers =
        materialize_proxy_providers(raw, providers, cache_dir, strict, provider_dialer_registry)?;
    let proxies = build_proxy_layer(
        raw,
        resolver,
        &candidate_providers,
        selector_store,
        registry,
        strict,
    )?;

    // Publish the finished registry: the `dialer-proxy` chains bound during
    // the layer build resolve their front hop by name against it, and only
    // now does it hold the groups they may name (issue #513). Nothing mutates
    // `proxies` after this point, and publishing *before* the provider fetches
    // below matters: they dial through `download_proxy`, which may itself be
    // a chained node whose front hop must already resolve. A later rebuild
    // publishes into its own registry, so adapters already handed to the
    // tunnel keep resolving the snapshot they were built from — while the
    // owning generation is still retained (the cell is only held weakly by
    // the adapters, issue #533).
    // Provider-sourced nodes may also declare `dialer-proxy` (issue #489).
    // Their names cannot be hard-validated the way static edges are — the
    // payload is remote content and the dialer name may point at a group
    // built above — so warn about references that will never resolve and let
    // the by-name lookup surface a loud dial error at runtime.
    for provider in candidate_providers.values() {
        for dialer in provider.declared_dialer_names() {
            if !proxies.contains_key(dialer.as_str()) {
                warn!(
                    provider = %provider.name,
                    "provider node declares dialer-proxy '{dialer}', which is \
                     not a built proxy or group — chained dials will fail"
                );
            }
        }
    }

    registry.publish(Arc::new(proxies.clone()));

    let download_proxy = internal_http::first_named_proxy(raw.proxies.as_deref(), &proxies);
    // Per-provider `proxy:` overrides resolve against the full registry —
    // groups and provider-sourced proxies included (issue #377).
    let proxy_lookup = |name: &str| proxies.get(name).cloned();

    // Fail hard on any rule- or proxy-provider path that would escape the
    // provider cache directory — before any fetch or on-disk write happens,
    // so a hostile `PUT /configs` is rejected without touching the
    // filesystem (issue #429). Proxy-providers get the same loud failure as
    // rule-providers (PR #444 review follow-up) instead of being warn-skipped
    // with every group referencing them silently degrading.
    if let Some(map) = raw.rule_providers.as_ref() {
        rule_provider::validate_paths(map, cache_dir)?;
    }
    if let Some(map) = raw.proxy_providers.as_ref() {
        proxy_provider::validate_paths(map, cache_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // Fetch/read rule-provider payload bytes once — the parser-context build
    // scans them for geo keys (issue #277) and the provider load below parses
    // the same bytes, so nothing is fetched twice. The `Arc` is returned on
    // `RebuildResult` so the same commit's DNS rebuild can share it (issue
    // #543).
    let payloads: Arc<rule_provider::PrefetchedPayloads> = match prefetched_payloads {
        Some(p) => p,
        // `shared_providers` rebuilds bind the live provider objects — their
        // payloads are never re-parsed, so prefetching would only re-fetch
        // every http provider per geodata tick for bytes nothing reads.
        None if shared_providers.is_some() => Arc::new(HashMap::new()),
        None => Arc::new(match raw.rule_providers.as_ref() {
            Some(map) if !map.is_empty() => rule_provider::prefetch_payloads(
                map,
                cache_dir,
                download_proxy.as_ref(),
                &proxy_lookup,
            ),
            _ => HashMap::new(),
        }),
    };

    let owned_ctx;
    let ctx = match shared_ctx {
        Some(c) => c,
        None => {
            owned_ctx = build_parser_context_from_raw(raw, &payloads)?;
            &owned_ctx
        }
    };

    let rule_providers = match shared_providers {
        Some(shared) => shared,
        None => match raw.rule_providers.as_ref() {
            Some(map) if !map.is_empty() => rule_provider::load_providers_prefetched(
                map,
                cache_dir,
                ctx,
                download_proxy.as_ref(),
                &proxy_lookup,
                &payloads,
                Some(registry),
                strict,
            )?,
            _ => HashMap::new(),
        },
    };
    let ruleset_map = rule_provider::live_ruleset_map(&rule_providers);

    // Parse sub-rules before top-level rules so that SUB-RULE entries in
    // `rules:` can resolve against already-built blocks.
    let sub_rules = match raw.sub_rules.as_ref() {
        Some(map) if !map.is_empty() => sub_rules_parser::parse_sub_rules(map, &ruleset_map, ctx)?,
        _ => HashMap::new(),
    };

    let rules = rule_parser::parse_rules_full(
        raw.rules.as_deref().unwrap_or(&[]),
        &ruleset_map,
        ctx,
        &sub_rules,
        strict,
    )?;

    // Validate: any `SUB-RULE,<name>` in top-level rules must reference a
    // defined block. `parse_rules_full` warns on unknown blocks; promote
    // undefined-block to a hard error here (Class A per ADR-0002).
    if let Some(raw_rules) = raw.rules.as_deref() {
        for line in raw_rules {
            if let Some(name) = sub_rules_parser::parse_sub_rule_reference(line) {
                if !sub_rules.contains_key(&name) {
                    return Err(anyhow::anyhow!(
                        "rules: SUB-RULE,{name} references undefined sub-rule block"
                    ));
                }
            }
        }
    }

    // The provider set is returned, not swapped: the committing caller
    // publishes it into the live registry only after every fallible check
    // has passed, so a rejected candidate never leaves its fetch contexts
    // (and their pinned dialer cell) live (issue #533 review).
    Ok(RebuildResult {
        proxies,
        rules,
        dialer_registry: registry.clone(),
        rule_providers,
        proxy_providers: candidate_providers,
        prefetched_payloads: payloads,
    })
}

async fn open_selector_store_async(
    path: PathBuf,
) -> Result<Arc<meow_proxy::SelectorStore>, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || meow_proxy::SelectorStore::open(path))
        .await
        .map_err(|e| anyhow::anyhow!("selector store open task failed: {e}"))
}

async fn build_parser_context_with_geo_async(
    raw: raw::RawConfig,
    geo: GeoDataConfig,
    provider_payloads: Arc<rule_provider::PrefetchedPayloads>,
) -> Result<meow_rules::ParserContext, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || {
        build_parser_context_with_geo(&raw, &geo, &provider_payloads)
    })
    .await
    .map_err(|e| anyhow::anyhow!("parser context build task failed: {e}"))?
}

/// Prefetch every file/http rule-provider payload on a blocking thread.
/// `prefetch` is the shared pre-registry proxy layer built by
/// [`prefetch_proxy_layer_async`]; `proxy:` download names and the default
/// (first `proxies:` entry, same as [`internal_http::first_named_proxy`])
/// resolve against it with `dialer-proxy` chains applied — previously each
/// name was re-parsed straight from raw YAML, so a chained node fetched its
/// provider payload WITHOUT the configured front hop (issue #533).
async fn prefetch_rule_provider_payloads_async(
    raw: &raw::RawConfig,
    cache_dir: Option<PathBuf>,
    prefetch: Option<Arc<PrefetchProxies>>,
) -> rule_provider::PrefetchedPayloads {
    let Some(raw_providers) = raw.rule_providers.as_ref().filter(|m| !m.is_empty()) else {
        return HashMap::new();
    };
    let raw_providers = raw_providers.clone();
    let raw_proxies: Vec<HashMap<String, serde_yaml::Value>> =
        raw.proxies.clone().unwrap_or_default();
    spawn_blocking_with_current_dispatcher(move || {
        let default_proxy = prefetch
            .as_ref()
            .and_then(|m| internal_http::first_named_proxy(Some(&raw_proxies), &m.map));
        let lookup = |wanted: &str| prefetch.as_ref().and_then(|m| m.map.get(wanted).cloned());
        rule_provider::prefetch_payloads(
            &raw_providers,
            cache_dir.as_deref(),
            default_proxy.as_ref(),
            &lookup,
        )
    })
    .await
    .unwrap_or_else(|e| {
        warn!("rule-provider payload prefetch task failed: {e}");
        HashMap::new()
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors rebuild_from_raw_impl, which stays one argument list \
              per build stage"
)]
async fn rebuild_from_raw_impl_async(
    raw: raw::RawConfig,
    cache_dir: Option<PathBuf>,
    resolver: Option<meow_dns::ResolverSlot>,
    providers: HashMap<String, Arc<ProxyProvider>>,
    selector_store: Option<Arc<meow_proxy::SelectorStore>>,
    ctx: meow_rules::ParserContext,
    provider_payloads: Arc<rule_provider::PrefetchedPayloads>,
    // Caller's registry cell — shared across a multi-pass build so pass-1
    // adapters retained elsewhere (DNS `#PROXY` handles, provider fetch
    // contexts) resolve the latest published snapshot (issue #533).
    registry: meow_proxy::dialer::ProxyRegistry,
    // The live provider-dialer cell newly declared providers share
    // (issue #489) — see `rebuild_from_raw_impl`.
    provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
    // Startup's pass-2 shares the provider set already loaded for DNS so
    // rules, `rule-set:` matchers, and `Config.rule_providers` reference one
    // object per provider (issue #533 review). `None` = load fresh.
    shared_providers: Option<HashMap<String, Arc<rule_provider::RuleProvider>>>,
) -> Result<RebuildResult, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || {
        rebuild_from_raw_impl(
            &raw,
            cache_dir.as_deref(),
            resolver.as_ref(),
            &providers,
            selector_store.as_ref(),
            Some(&ctx),
            Some(provider_payloads),
            &registry,
            &provider_dialer_registry,
            shared_providers,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("config rebuild task failed: {e}"))?
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct piece of one provider's load context"
)]
async fn load_rule_providers_async(
    raw_providers: HashMap<String, raw::RawRuleProvider>,
    cache_dir: Option<PathBuf>,
    ctx: meow_rules::ParserContext,
    download_proxy: Option<Arc<dyn Proxy>>,
    proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
    provider_payloads: Arc<rule_provider::PrefetchedPayloads>,
    // Retained inside each provider's fetch context so a chained download
    // adapter keeps resolving its `dialer-proxy` front hop on refreshes that
    // outlive this route generation (issue #533).
    dialer_registry: Option<meow_proxy::dialer::ProxyRegistry>,
    strict: bool,
) -> Result<HashMap<String, Arc<rule_provider::RuleProvider>>, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || {
        let lookup = |name: &str| proxies.get(name).cloned();
        rule_provider::load_providers_prefetched(
            &raw_providers,
            cache_dir.as_deref(),
            &ctx,
            download_proxy.as_ref(),
            &lookup,
            &provider_payloads,
            dialer_registry.as_ref(),
            strict,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("rule-provider load task failed: {e}"))?
}

fn parse_sniffer_config(
    raw: &raw::RawConfig,
    strict: bool,
) -> Result<SnifferConfig, anyhow::Error> {
    // Deprecated alias: tproxy_sni (pre-spec) synthesises a minimal config.
    let has_tproxy_sni = raw.tproxy_sni.unwrap_or(false);

    match raw.sniffer.as_ref() {
        Some(rs) => {
            if has_tproxy_sni {
                warn!(
                    "`tproxy_sni` is deprecated; migrate to the top-level `sniffer:` block. \
                    `sniffer:` wins; `tproxy_sni` is ignored."
                );
            }
            // Warn-and-ignore force-dns-mapping.
            if rs.force_dns_mapping.unwrap_or(false) {
                warn!(
                    "sniffer.force-dns-mapping is accepted and ignored: meow-rs \
                    always maps fake-ip / snooped destinations back to their \
                    domain via the DNS reverse table, so the flag has no effect"
                );
            }
            let enable = rs.enable.unwrap_or(false);
            let timeout_ms = rs.timeout.unwrap_or(100);
            if !(1..=60000).contains(&timeout_ms) {
                anyhow::bail!("sniffer.timeout must be between 1 and 60000 ms, got {timeout_ms}");
            }

            // Parse per-protocol port lists.
            let mut tls_ports: Vec<u16> = Vec::new();
            let mut http_ports: Vec<u16> = Vec::new();
            if let Some(sniff_map) = rs.sniff.as_ref() {
                for (key, proto) in sniff_map {
                    match key.to_uppercase().as_str() {
                        "TLS" => {
                            tls_ports = proto.ports.clone().unwrap_or_default();
                        }
                        "HTTP" => {
                            http_ports = proto.ports.clone().unwrap_or_default();
                        }
                        "QUIC" => {
                            warn!("sniffer.sniff.QUIC is not implemented in meow-rs; ignoring");
                        }
                        // An unrecognized key is a typo'd/dead declaration —
                        // a defect under strict (issue #533 review), unlike
                        // the valid-but-unimplemented `QUIC` Class-B shim.
                        other if strict => {
                            anyhow::bail!(
                                "sniffer.sniff.{other}: unknown protocol (strict mode); \
                                 supported: TLS, HTTP"
                            );
                        }
                        other => {
                            warn!("sniffer.sniff.{}: unknown protocol, ignoring", other);
                        }
                    }
                }
                if enable && tls_ports.is_empty() && http_ports.is_empty() {
                    anyhow::bail!(
                        "sniffer.sniff is present and enable: true, but no ports are configured \
                        for any supported protocol (TLS/HTTP)"
                    );
                }
            } else if enable {
                anyhow::bail!("sniffer.enable is true but sniffer.sniff map is absent or empty");
            }

            Ok(SnifferConfig {
                enable,
                timeout: std::time::Duration::from_millis(timeout_ms),
                parse_pure_ip: rs.parse_pure_ip.unwrap_or(true),
                override_destination: rs.override_destination.unwrap_or(false),
                tls_ports,
                http_ports,
                skip_domain: rs
                    .skip_domain
                    .iter()
                    .flatten()
                    .map(|s| SmolStr::from(s.as_str()))
                    .collect(),
                force_domain: rs
                    .force_domain
                    .iter()
                    .flatten()
                    .map(|s| SmolStr::from(s.as_str()))
                    .collect(),
            })
        }
        None if has_tproxy_sni => {
            warn!(
                "`tproxy_sni` is deprecated; migrate to the top-level `sniffer:` block. \
                Accepting as `sniffer.enable: true, sniff.TLS.ports: [443]` for this release. \
                Will be removed in a future version."
            );
            Ok(SnifferConfig {
                enable: true,
                timeout: std::time::Duration::from_millis(100),
                parse_pure_ip: true,
                override_destination: false,
                tls_ports: vec![443],
                http_ports: Vec::new(),
                skip_domain: Vec::new(),
                force_domain: Vec::new(),
            })
        }
        None => Ok(SnifferConfig::default()),
    }
}

/// The geodata files this config's rules reference that are absent on disk —
/// `(url, destination)` pairs in scan order. Shared between the prefetch-map
/// gate in `build_config` and [`ensure_geodata`] so both agree on what a
/// startup actually has to download.
fn missing_geodata_downloads<'a>(
    raw: &raw::RawConfig,
    geo: &'a GeoDataConfig,
    scan_lines: &[String],
) -> Vec<(&'a String, PathBuf)> {
    let needs_geoip = scan_lines.iter().any(|l| line_references_geoip(l));
    let needs_asn = scan_lines.iter().any(|l| line_references_asn(l));
    let needs_geosite =
        scan_lines.iter().any(|l| line_references_geosite(l)) || dns_policy_uses_geosite(raw);

    if !needs_geoip && !needs_asn && !needs_geosite {
        return Vec::new();
    }

    let geoip_path = geo.mmdb_path.clone().unwrap_or_else(default_geoip_path);
    let asn_path = geo.asn_path.clone().unwrap_or_else(default_asn_path);
    let geosite_path = geo
        .geosite_path
        .clone()
        .unwrap_or_else(default_geosite_path);

    let geoip_missing = needs_geoip && !geoip_path.exists();
    let asn_missing = needs_asn && !asn_path.exists();
    let geosite_missing = needs_geosite
        && geo.geosite_path.as_ref().map_or_else(
            || {
                meow_rules::geosite::default_geosite_candidates()
                    .iter()
                    .all(|p| !p.exists())
            },
            |p| !p.exists(),
        );

    let mut downloads = Vec::new();
    if geoip_missing {
        downloads.push((&geo.mmdb_url, geoip_path));
    }
    if asn_missing {
        downloads.push((&geo.asn_url, asn_path));
    }
    if geosite_missing {
        downloads.push((&geo.geosite_url, geosite_path));
    }
    downloads
}

/// Whether the shared prefetch proxy layer is worth building. `http`
/// providers need it for the payload prefetch itself; `file` providers read
/// locally but their payloads can carry geo references whose download rides
/// the same layer. `inline` payloads sit inside `raw`, so they are covered
/// by the raw scan below. The payload-less scan is exact here: the only geo
/// references it could miss live inside fetched provider payloads, and when
/// every provider is inline there are no fetched payloads (the first clause
/// already returned true otherwise). `proxy-providers` are out of scope:
/// their fetches run before any proxy layer exists, and their `proxy:`
/// field resolves later against the published `provider_dialer_registry`
/// at fetch time (issue #625) — not through this prefetch layer.
fn prefetch_proxy_layer_needed(raw: &raw::RawConfig, geo: &GeoDataConfig) -> bool {
    // No `proxies:` entries → the layer can never exist; skip the
    // spawn_blocking hop to a deterministic `Ok(None)`.
    if raw.proxies.as_deref().unwrap_or(&[]).is_empty() {
        return false;
    }
    let has_fetchable_provider = raw
        .rule_providers
        .as_ref()
        .is_some_and(|m| m.values().any(|c| c.provider_type != "inline"));
    if has_fetchable_provider {
        return true;
    }
    let scan = collect_geo_scan_lines(raw, &HashMap::new());
    !missing_geodata_downloads(raw, geo, &scan).is_empty()
}

/// Download missing geodata files that the config's rules require.
///
/// For `GEOSITE` entries the DB is discovered separately and loaded only if
/// at least one GEOSITE rule is present (same lazy pattern as GeoIP/ASN).
/// Unlike GeoIP/ASN, the GEOSITE DB is tolerated as absent — per spec the
/// rule no-matches at query time rather than failing at parse.
///
/// Downloads ride the first configured proxy through `prefetch` — the shared
/// pre-registry proxy layer with `dialer-proxy` chains applied (needed in
/// regions where the CDN is blocked; issue #533). Fetches go direct only
/// when no layer exists — a config without `proxies:` — since a rejected
/// layer aborts the build before this runs. Download failures are logged as
/// warnings — the subsequent parser-context build hard-errors on a missing
/// GeoIP/ASN file (geosite is tolerated absent, per spec), giving a clear
/// diagnostic.
async fn ensure_geodata(
    raw: &raw::RawConfig,
    geo: &GeoDataConfig,
    scan_lines: &[String],
    prefetch: Option<&PrefetchProxies>,
) {
    let downloads = missing_geodata_downloads(raw, geo, scan_lines);
    if downloads.is_empty() {
        return;
    }

    let proxy: Option<Arc<dyn Proxy>> =
        prefetch.and_then(|m| internal_http::first_named_proxy(raw.proxies.as_deref(), &m.map));

    for (url, dest) in downloads {
        info!("geodata: downloading {} to {}", url, dest.display());
        if let Err(e) = geodata::download_and_replace(url, &dest, proxy.as_ref()).await {
            warn!("geodata: failed to download {} — {}", url, e);
        }
    }
}

/// Parse geodata paths from `raw.geodata` and build a `ParserContext` that
/// respects any explicit path overrides. Used by both `build_config` and
/// `rebuild_from_raw_impl` so all code paths honour the same config.
fn build_parser_context_from_raw(
    raw: &raw::RawConfig,
    provider_payloads: &rule_provider::PrefetchedPayloads,
) -> Result<meow_rules::ParserContext, anyhow::Error> {
    let geo = geodata::parse_geodata(raw.geodata.as_ref())?;
    build_parser_context_with_geo(raw, &geo, provider_payloads)
}

fn build_parser_context_with_geo(
    raw: &raw::RawConfig,
    geo: &GeoDataConfig,
    provider_payloads: &rule_provider::PrefetchedPayloads,
) -> Result<meow_rules::ParserContext, anyhow::Error> {
    let geoip_path = geo.mmdb_path.clone().unwrap_or_else(default_geoip_path);
    let asn_path = geo.asn_path.clone().unwrap_or_else(default_asn_path);
    build_parser_context_at(
        raw,
        &geoip_path,
        &asn_path,
        &meow_rules::geosite::default_geosite_candidates(),
        geo.geosite_path.as_deref(),
        provider_payloads,
    )
}

/// Same as [`build_parser_context`] but lets the caller override the mmdb
/// paths — used by tests and by the M2 `geodata:` config path overrides.
///
/// Scans `raw.rules` (plus sub-rules and provider payloads, via
/// [`collect_geo_scan_lines`]) for any GeoIP-backed entry (`GEOIP`,
/// `SRC-GEOIP`) or ASN-backed entry (`IP-ASN`, `SRC-IP-ASN`); if present,
/// lazy-loads the corresponding MMDB from the configured or default path and
/// builds a `ParserContext` carrying the readers. Fail-fast — the error names
/// the offending rule and the path tried — when the scan matches but the load
/// fails.
fn build_parser_context_at(
    raw: &raw::RawConfig,
    geoip_path: &Path,
    asn_path: &Path,
    geosite_candidates: &[PathBuf],
    geosite_explicit: Option<&Path>,
    provider_payloads: &rule_provider::PrefetchedPayloads,
) -> Result<meow_rules::ParserContext, anyhow::Error> {
    // Scan everything that can hold a geo rule — top-level rules, sub-rules
    // blocks, and rule-provider payloads — so a GEOIP/IP-ASN/GEOSITE key used
    // only outside `rules:` still gets binned into the indexes (issue #277).
    let lines = collect_geo_scan_lines(raw, provider_payloads);

    let geoip_trigger = lines.iter().find(|l| line_references_geoip(l));
    let geoip = match geoip_trigger {
        Some(trigger) => {
            let reader = load_mmdb_mmap(geoip_path, "GeoIP", trigger)?;
            let allowed = collect_geoip_countries(&lines);
            let index = meow_rules::country_index::CountryIndex::build(&reader, &allowed)
                .map_err(|e| anyhow::anyhow!("failed to build GeoIP country index: {e}"))?;
            // reader is mmap-backed — pages are returned to the OS on drop.
            drop(reader);
            Some(Arc::new(index))
        }
        None => None,
    };

    let asn_trigger = lines.iter().find(|l| line_references_asn(l));
    let asn = match asn_trigger {
        Some(trigger) => {
            let reader = load_mmdb_mmap(asn_path, "GeoLite2-ASN", trigger)?;
            let allowed = collect_asn_numbers(&lines);
            let index = meow_rules::asn_index::AsnIndex::build(&reader, &allowed)
                .map_err(|e| anyhow::anyhow!("failed to build ASN index: {e}"))?;
            drop(reader);
            Some(Arc::new(index))
        }
        None => None,
    };

    let geosite_trigger =
        lines.iter().any(|l| line_references_geosite(l)) || dns_policy_uses_geosite(raw);
    let geosite = if geosite_trigger {
        let mut allowed = collect_geosite_categories(&lines);
        allowed.extend(collect_dns_policy_geosite_categories(raw));
        info!(
            "Loading geosite database for {} referenced categories",
            allowed.len()
        );
        let loaded = meow_rules::geosite::discover_and_load_at(
            geosite_explicit,
            geosite_candidates,
            Some(&allowed),
        );
        if loaded.is_some() {
            info!("Loaded geosite database");
        }
        loaded
    } else {
        None
    };

    Ok(meow_rules::ParserContext {
        geoip,
        asn,
        geosite,
    })
}

/// Memory-map an MMDB file. The OS reclaims pages immediately on drop,
/// unlike `Vec<u8>` where the allocator retains the freed block.
fn load_mmdb_mmap(
    path: &Path,
    kind: &str,
    trigger: &str,
) -> Result<maxminddb::Reader<maxminddb::Mmap>, anyhow::Error> {
    // Safety: the file is read-only and not modified during the reader's
    // lifetime (dropped before the function returns to the caller).
    let reader = unsafe { maxminddb::Reader::open_mmap(path) }.map_err(|e| {
        anyhow::anyhow!(
            "Failed to load {} database at {}\n  required by rule: {}\n  underlying error: {}",
            kind,
            path.display(),
            trigger.trim(),
            e
        )
    })?;
    info!("Loaded {} database from {} (mmap)", kind, path.display());
    Ok(reader)
}

/// Scan raw rule lines and return the set of country codes referenced by
/// `GEOIP,` / `SRC-GEOIP,` payloads — including occurrences inside logic
/// rules (`AND`/`OR`/`NOT`). The returned codes are uppercased.
///
/// Used to drive a targeted [`CountryIndex`] build so we never allocate
/// per-country ranges for codes no rule cares about.
fn geoip_scan_regex() -> &'static regex::Regex {
    use std::sync::OnceLock;
    // `\bGEOIP` matches both `GEOIP,CN` and `SRC-GEOIP,CN` because the `-`
    // before `GEOIP` is a non-word boundary.
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\bGEOIP\s*,\s*([A-Za-z0-9]+)").expect("compile GEOIP scan regex")
    })
}

fn collect_geoip_countries(lines: &[String]) -> std::collections::HashSet<String> {
    let re = geoip_scan_regex();
    let mut out = std::collections::HashSet::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for cap in re.captures_iter(line) {
            out.insert(cap[1].to_ascii_uppercase());
        }
    }
    out
}

/// Scan raw rule lines and return the set of category names referenced by
/// `GEOSITE,<category>` payloads — including occurrences inside logic rules
/// (`AND`/`OR`/`NOT`). The returned names are lowercased.
///
/// Used to drive targeted geosite loading so we only parse categories that
/// are actually referenced by rules, skipping the rest at the byte level.
fn geosite_scan_regex() -> &'static regex::Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\bGEOSITE\s*,\s*([A-Za-z0-9_!\-]+)(?:@[A-Za-z0-9_!\-]+)*")
            .expect("compile GEOSITE scan regex")
    })
}

fn collect_geosite_categories(lines: &[String]) -> std::collections::HashSet<String> {
    let re = geosite_scan_regex();
    let mut out = std::collections::HashSet::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for cap in re.captures_iter(line) {
            out.insert(cap[1].to_ascii_lowercase());
        }
    }
    out
}

fn dns_policy_uses_geosite(raw: &raw::RawConfig) -> bool {
    raw.dns
        .as_ref()
        .and_then(|dns| dns.nameserver_policy.as_ref())
        .is_some_and(|policy| {
            // Expand per segment like the policy builder — a mixed key
            // (`"+.a,geosite:cn"`) puts the prefix on a non-leading segment
            // the whole-key check would miss (issue #514 review).
            policy
                .keys()
                .flat_map(|key| dns_parser::expand_policy_keys(key))
                .any(|ek| ek.to_ascii_lowercase().starts_with("geosite:"))
        })
}

fn collect_dns_policy_geosite_categories(
    raw: &raw::RawConfig,
) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let Some(policy) = raw
        .dns
        .as_ref()
        .and_then(|dns| dns.nameserver_policy.as_ref())
    else {
        return out;
    };
    for expanded in policy
        .keys()
        .flat_map(|key| dns_parser::expand_policy_keys(key))
    {
        let lower = expanded.to_ascii_lowercase();
        let Some(rest) = lower.strip_prefix("geosite:") else {
            continue;
        };
        // `expand_policy_keys` already produced one `geosite:<cat>` per
        // segment; the `@attr` suffix still needs stripping.
        let category = rest.split('@').next().unwrap_or("").trim();
        if !category.is_empty() {
            out.insert(category.to_string());
        }
    }
    out
}

/// Scan raw rule lines and return the ASN numbers referenced by `IP-ASN,` /
/// `SRC-IP-ASN,` payloads, including occurrences inside logic rules.
fn asn_scan_regex() -> &'static regex::Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\b(?:SRC-)?IP-ASN\s*,\s*(\d+)").expect("compile IP-ASN scan regex")
    })
}

fn collect_asn_numbers(lines: &[String]) -> std::collections::HashSet<u32> {
    let re = asn_scan_regex();
    let mut out = std::collections::HashSet::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for cap in re.captures_iter(line) {
            if let Ok(asn) = cap[1].parse::<u32>() {
                out.insert(asn);
            }
        }
    }
    out
}

/// True iff `line` references the GeoIP Country database anywhere — as a
/// top-level `GEOIP,`/`SRC-GEOIP,` rule or nested inside a logic rule
/// (`AND`/`OR`/`NOT`). Comment lines never match. Uses the same regex as
/// [`collect_geoip_countries`] so the trigger and the allowlist agree.
fn line_references_geoip(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with('#') && geoip_scan_regex().is_match(line)
}

/// True iff `line` references the geosite database anywhere (top-level or
/// nested inside a logic rule). Comment lines never match.
fn line_references_geosite(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with('#') && geosite_scan_regex().is_match(line)
}

/// True iff `line` references the GeoLite2-ASN database anywhere — `IP-ASN,`
/// or `SRC-IP-ASN,`, top-level or nested. Comment lines never match.
fn line_references_asn(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with('#') && asn_scan_regex().is_match(line)
}

/// Gather every rule line that can reference a geo database (issue #277):
/// top-level `rules:`, all `sub-rules:` blocks, inline rule-provider
/// payloads, and the prefetched payloads of file/http rule-providers.
/// Binary MRS payloads are skipped — the MRS format holds compiled
/// domain/ipcidr sets and can never contain GEOIP/GEOSITE/IP-ASN lines.
fn collect_geo_scan_lines(
    raw: &raw::RawConfig,
    provider_payloads: &rule_provider::PrefetchedPayloads,
) -> Vec<String> {
    let mut lines: Vec<String> = raw.rules.clone().unwrap_or_default();
    if let Some(sub_rules) = raw.sub_rules.as_ref() {
        for block in sub_rules.values() {
            lines.extend(block.iter().cloned());
        }
    }
    if let Some(providers) = raw.rule_providers.as_ref() {
        for cfg in providers.values() {
            if let Some(payload) = cfg.payload.as_ref() {
                lines.extend(payload.iter().cloned());
            }
        }
    }
    // Only payloads belonging to providers this raw actually declares are
    // scanned — a caller-supplied superset map must not trigger geo loads
    // for providers the candidate does not carry (issue #543).
    let declared = raw.rule_providers.as_ref();
    for (name, bytes) in provider_payloads {
        if !declared.is_some_and(|m| m.contains_key(name)) || meow_rules::is_mrs_bytes(bytes) {
            continue;
        }
        let text = String::from_utf8_lossy(bytes);
        lines.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from),
        );
    }
    lines
}

/// Default path for the GeoIP Country MMDB.
/// Honours `-d` (set via `meow_common::set_home_dir`), then `$XDG_CONFIG_HOME`,
/// then `$HOME/.config/meow`.
pub fn default_geoip_path() -> PathBuf {
    meow_config_dir().join("Country.mmdb")
}

/// Default path for the GeoLite2-ASN MMDB. Same discovery chain as GeoIP,
/// with the upstream-compatible filename `GeoLite2-ASN.mmdb`.
pub fn default_asn_path() -> PathBuf {
    meow_config_dir().join("GeoLite2-ASN.mmdb")
}

/// Default on-disk path for the geosite DB used by the geodata downloader.
/// Uses `geosite.dat` since upstream MetaCubeX stopped publishing the `.mrs`
/// release artifact; the loader transparently accepts either format.
pub fn default_geosite_path() -> PathBuf {
    meow_config_dir().join("geosite.dat")
}

/// Return the meow home directory.
///
/// Priority (highest first):
/// 1. Value set by `meow_common::set_home_dir` (from the `-d` CLI flag).
/// 2. `$XDG_CONFIG_HOME/meow` if `XDG_CONFIG_HOME` is set.
/// 3. `$HOME/.config/meow` if `HOME` is set.
/// 4. `.` (current working directory) as last resort.
pub fn meow_config_dir() -> PathBuf {
    meow_common::resolved_home_dir()
}

/// Resolve the provider-cache directory for a config file path — the same
/// directory [`load_config`] threads through as `cache_dir` at startup.
///
/// Trusted runtime rebuilds (subscription refresh, geodata rebuild, the
/// config-mutating API endpoints) must recompute this from the daemon's own
/// `config_path` and pass it back into [`rebuild_from_raw_with_resolver`] /
/// [`rebuild_from_raw_runtime`] rather than passing `None`, or relative
/// rule-provider `path`s that loaded fine at startup start hard-failing on
/// every rebuild (issue #429 follow-up).
pub fn resource_cache_dir_for_config_path(path: &str) -> PathBuf {
    resource_cache_dir_for_config_path_with_home(path, meow_common::meow_home_dir())
}

fn resource_cache_dir_for_config_path_with_home(path: &str, home_dir: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = home_dir {
        return dir;
    }
    std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(meow_common::xdg_home_dir, std::path::Path::to_path_buf)
}

/// Resolve a listener `listen` field plus optional `port`.
///
/// `listen` may be:
/// - an IP literal (`127.0.0.1`, `::`, `0.0.0.0`) — combined with `port`
/// - a socket address (`127.0.0.1:0`, `[::1]:7890`) — port taken from the
///   address unless it is `0` and an explicit `port` was also given
///
/// Port `0` means the OS picks an ephemeral port at bind time.
pub(crate) fn resolve_listener_bind(
    listen: &str,
    port: Option<u16>,
) -> Result<(String, u16), anyhow::Error> {
    let explicit_port = port.unwrap_or(0);

    if listen.parse::<IpAddr>().is_ok() {
        return Ok((listen.to_string(), explicit_port));
    }

    if let Ok(addr) = listen.parse::<SocketAddr>() {
        let listen_port = addr.port();
        let resolved = match (listen_port, explicit_port) {
            (0, p) => p,
            (lp, 0) => lp,
            (lp, p) if lp == p => lp,
            (lp, p) => anyhow::bail!("listen '{listen}' port {lp} conflicts with port {p}"),
        };
        return Ok((addr.ip().to_string(), resolved));
    }

    anyhow::bail!(
        "invalid bind address '{listen}': expected an IP literal or host:port (e.g. 127.0.0.1:0)"
    )
}

/// Parse `type:` string from a `listeners:` entry into a `ListenerSpec`.
/// Hard errors on unknown types (Class A per ADR-0002).
///
/// `per-listener` fields (`tproxy-sni`/`firewall`/`udp`/`udp-timeout` on the
/// raw entry, plus `global_tproxy_sni`) are folded into the `TProxy` variant
/// here so the returned spec is always complete — callers never need to
/// overwrite a placeholder value. Fields that don't apply to the listener's
/// type are ignored; `firewall`/`udp`/`udp-timeout` misuse is diagnosed by
/// the caller (which has the listener name in scope). `Shadowsocks` returns
/// a placeholder spec; `build_named_listeners`
/// completes it via `build_ss_listener_spec`.
fn parse_listener_spec(
    raw_l: &raw::RawListener,
    global_tproxy_sni: bool,
) -> Result<ListenerSpec, anyhow::Error> {
    match raw_l.listener_type.to_lowercase().as_str() {
        "mixed" => Ok(ListenerSpec::Mixed),
        "http" => Ok(ListenerSpec::Http),
        "socks5" => Ok(ListenerSpec::Socks5),
        "tproxy" => {
            // #564: `udp` is opt-in and IPv4-only in this release, and the
            // managed firewall only produces host TCP OUTPUT REDIRECT rules —
            // it cannot promise LAN UDP TPROXY policy routing, so the
            // combination is rejected rather than silently TCP-only.
            let udp = raw_l.udp.unwrap_or(false);
            let firewall = raw_l.firewall.unwrap_or_else(default_tproxy_firewall);
            if udp && firewall {
                anyhow::bail!(
                    "listeners[{}]: `udp: true` requires `firewall: false` — meow does \
                     not manage UDP TPROXY rules/policy routing (managed mode only \
                     installs host TCP REDIRECT); install the UDP rules externally",
                    raw_l.name
                );
            }
            let udp_timeout = match raw_l.udp_timeout {
                Some(0) => anyhow::bail!(
                    "listeners[{}].udp-timeout: must be at least 1 second",
                    raw_l.name
                ),
                Some(s) => s,
                None => default_udp_timeout_secs(),
            };
            Ok(ListenerSpec::TProxy {
                sni: raw_l.tproxy_sni.unwrap_or(global_tproxy_sni),
                firewall,
                udp,
                udp_timeout,
            })
        }
        "shadowsocks" | "ss" => Ok(ListenerSpec::Shadowsocks(SsListenerConfig {
            cipher: String::new(),
            password: String::new(),
            udp: true,
            simple_obfs: None,
        })),
        other => anyhow::bail!(
            "unknown listener type '{other}'; expected mixed, http, socks5, tproxy, or shadowsocks"
        ),
    }
}

/// Build a validated `SsListenerConfig` from a raw `listeners:` entry.
///
/// `cipher` and `password` are required (Class A). `udp` defaults to `true`
/// (upstream `ShadowSocksOption{UDP: true}`). Unsupported upstream sub-options
/// (`shadow-tls` / `res-tls` / `jls-config` / `kcp-tun` / `mux-option`) are
/// warned about and ignored — never silently, matching the `tun` field policy
/// (ADR-0002) — rather than hard-erroring, so mihomo configs that carry them
/// still boot.
fn build_ss_listener_spec(raw_l: &raw::RawListener) -> Result<SsListenerConfig, anyhow::Error> {
    for (name, val) in [
        ("shadow-tls", &raw_l.shadow_tls),
        ("res-tls", &raw_l.res_tls),
        ("jls-config", &raw_l.jls_config),
        ("kcp-tun", &raw_l.kcp_tun),
        ("mux-option", &raw_l.mux_option),
    ] {
        if val.is_some() {
            warn!(
                "listeners[{}].{name}: not supported in meow-rs shadowsocks listener, ignored; \
                 remove it to suppress this warning",
                raw_l.name
            );
        }
    }

    let cipher = raw_l.cipher.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "listeners[{}]: shadowsocks listener requires 'cipher'",
            raw_l.name
        )
    })?;
    let password = raw_l.password.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "listeners[{}]: shadowsocks listener requires 'password'",
            raw_l.name
        )
    })?;

    let simple_obfs = match raw_l.simple_obfs.as_ref() {
        Some(o) if o.enable => {
            let mode = o.mode.as_deref().unwrap_or("");
            Some(SimpleObfsConfig {
                mode: match mode {
                    "http" => ObfsMode::Http,
                    "tls" => ObfsMode::Tls,
                    other => anyhow::bail!(
                        "listeners[{}]: simple-obfs mode '{other}' invalid; expected http or tls",
                        raw_l.name
                    ),
                },
            })
        }
        _ => None,
    };

    Ok(SsListenerConfig {
        cipher,
        password,
        udp: raw_l.udp.unwrap_or(true),
        simple_obfs,
    })
}

/// Derive the `(default_bind, global_tproxy_sni)` inputs the listener
/// builder needs — single source so `validate_named_listeners` checks
/// exactly what `load_config` will enforce.
fn listener_bind_inputs(raw: &raw::RawConfig) -> (String, bool) {
    let bind_address = match raw.bind_address.as_deref() {
        None => "127.0.0.1".to_string(),
        Some("*" | "") => "0.0.0.0".to_string(),
        Some(addr) => addr.to_string(),
    };
    let bind_addr = if raw.allow_lan.unwrap_or(false) {
        bind_address
    } else {
        "127.0.0.1".to_string()
    };
    (bind_addr, raw.tproxy_sni.unwrap_or(true))
}

/// Validate `listeners:` exactly as `load_config` would, without
/// constructing anything — `PUT /configs` uses this to reject a section
/// that would otherwise persist silently and hard-error on next boot.
pub fn validate_named_listeners(raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let (bind_addr, global_tproxy_sni) = listener_bind_inputs(raw);
    build_named_listeners(raw, &bind_addr, global_tproxy_sni)?;
    Ok(())
}

/// Build the authoritative list of named listeners from the raw config.
/// Merges shorthand fields with the `listeners:` array and validates:
///   - No duplicate ports (Class A per ADR-0002)
///   - No duplicate names (Class A per ADR-0002)
fn build_named_listeners(
    raw: &raw::RawConfig,
    default_bind: &str,
    global_tproxy_sni: bool,
) -> Result<Vec<NamedListener>, anyhow::Error> {
    let mut result: Vec<NamedListener> = Vec::new();
    let mut used_ports: HashMap<u16, String> = HashMap::new();
    let mut used_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let global_max_conns = raw.max_connections.unwrap_or(256);

    let mut add = |name: &str,
                   spec: ListenerSpec,
                   port: u16,
                   listen: &str,
                   max_connections: usize|
     -> Result<(), anyhow::Error> {
        // Port 0 is "OS assigns an ephemeral port" — each such listener binds
        // a distinct port at runtime, so they are not duplicates of each other.
        if port != 0 {
            if let Some(existing) = used_ports.get(&port) {
                anyhow::bail!(
                    "port {port} already used by listener '{existing}' (duplicate port, Class A per ADR-0002)"
                );
            }
            used_ports.insert(port, name.to_string());
        }
        if !used_names.insert(name.to_string()) {
            anyhow::bail!(
                "listener name '{name}' already defined (duplicate name, Class A per ADR-0002)"
            );
        }
        result.push(NamedListener {
            name: name.to_string(),
            spec,
            port,
            listen: listen.to_string(),
            max_connections,
        });
        Ok(())
    };

    // Shorthand fields → auto-named listeners (inherit global max-connections).
    // Port `0` on a shorthand field means "disabled", matching upstream mihomo
    // (`mixed-port: 0` is how generated configs turn an inbound off). Ephemeral
    // ports are an explicit `listeners:`-entry opt-in only.
    if let Some(port) = raw.mixed_port.filter(|p| *p != 0) {
        add(
            "mixed",
            ListenerSpec::Mixed,
            port,
            default_bind,
            global_max_conns,
        )?;
    }
    if let Some(port) = raw.socks_port.filter(|p| *p != 0) {
        add(
            "socks",
            ListenerSpec::Socks5,
            port,
            default_bind,
            global_max_conns,
        )?;
    }
    if let Some(port) = raw.port.filter(|p| *p != 0) {
        add(
            "http",
            ListenerSpec::Http,
            port,
            default_bind,
            global_max_conns,
        )?;
    }
    if raw.firewall.is_some() {
        warn!(
            "firewall: only meaningful under a `listeners:` tproxy entry; \
             the top-level key is ignored — the `tproxy-port` shorthand \
             always stays managed (issue #563)"
        );
    }
    if raw.udp.is_some() {
        warn!(
            "udp: only meaningful under a `listeners:` entry (`tproxy`/`ss`); \
             the top-level key is ignored (issue #564)"
        );
    }
    if raw.udp_timeout.is_some() {
        warn!(
            "udp-timeout: only meaningful under a `listeners:`/`tun:` entry; \
             the top-level key is ignored (issue #564)"
        );
    }
    if let Some(port) = raw.tproxy_port.filter(|p| *p != 0) {
        add(
            "tproxy",
            ListenerSpec::TProxy {
                sni: global_tproxy_sni,
                // The shorthand keeps the managed-firewall default (issue
                // #563): external management is an explicit `listeners:`
                // opt-in only. UDP likewise stays opt-in (issue #564).
                firewall: true,
                udp: false,
                udp_timeout: default_udp_timeout_secs(),
            },
            port,
            "127.0.0.1",
            global_max_conns,
        )?;
    }

    // Explicit `listeners:` entries
    for raw_l in raw.listeners.as_deref().unwrap_or(&[]) {
        let spec = parse_listener_spec(raw_l, global_tproxy_sni)?;
        if raw_l.firewall.is_some() && !matches!(spec, ListenerSpec::TProxy { .. }) {
            warn!(
                "listeners[{}].firewall: only meaningful on `type: tproxy`, ignored; \
                 remove it to suppress this warning",
                raw_l.name
            );
        }
        if raw_l.tproxy_sni.is_some() && !matches!(spec, ListenerSpec::TProxy { .. }) {
            warn!(
                "listeners[{}].tproxy-sni: only meaningful on `type: tproxy`, ignored; \
                 remove it to suppress this warning",
                raw_l.name
            );
        }
        match (&spec, raw_l.udp_timeout) {
            (ListenerSpec::TProxy { udp: true, .. }, _) | (_, None) => {}
            (ListenerSpec::TProxy { .. }, Some(_)) => warn!(
                "listeners[{}].udp-timeout: has no effect unless `udp: true` is set; \
                 remove it to suppress this warning",
                raw_l.name
            ),
            (_, Some(_)) => warn!(
                "listeners[{}].udp-timeout: only meaningful on `type: tproxy`, ignored; \
                 remove it to suppress this warning",
                raw_l.name
            ),
        }
        // `udp` is meaningful on tproxy (issue #564) and shadowsocks; any
        // other listener type ignoring it is warned about.
        if raw_l.udp.is_some()
            && !matches!(
                spec,
                ListenerSpec::TProxy { .. } | ListenerSpec::Shadowsocks(_)
            )
        {
            warn!(
                "listeners[{}].udp: only meaningful on `type: tproxy`/`shadowsocks`, \
                 ignored; remove it to suppress this warning",
                raw_l.name
            );
        }
        let listen_raw = raw_l.listen.as_deref().unwrap_or({
            if matches!(spec, ListenerSpec::TProxy { .. }) {
                "127.0.0.1"
            } else {
                default_bind
            }
        });
        let (listen, port) = resolve_listener_bind(listen_raw, raw_l.port)?;
        // `parse_listener_spec` returns a placeholder for `Shadowsocks`; fold
        // the real cipher/password/udp/simple-obfs fields in here. TProxy's
        // `sni` is already resolved inside `parse_listener_spec`.
        let spec = match spec {
            ListenerSpec::Shadowsocks(_) => {
                ListenerSpec::Shadowsocks(build_ss_listener_spec(raw_l)?)
            }
            other => other,
        };
        // UDP TPROXY is IPv4-only in this release (issue #564): `::` is
        // dual-stack on Linux and would silently accept v6 datagrams, so
        // reject it rather than claim partial dual-stack support.
        if let ListenerSpec::TProxy { udp: true, .. } = spec {
            let v4 = listen
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_ipv4());
            if !v4 {
                anyhow::bail!(
                    "listeners[{}]: `udp: true` is IPv4-only in this release — \
                     bind an IPv4 address (`{listen}` resolves to IPv6/dual-stack)",
                    raw_l.name
                );
            }
        }
        let max_connections = raw_l.max_connections.unwrap_or(global_max_conns);
        add(&raw_l.name, spec, port, &listen, max_connections)?;
    }

    Ok(result)
}

async fn build_config(
    mut raw: raw::RawConfig,
    cache_dir: Option<&Path>,
) -> Result<Config, anyhow::Error> {
    // Pre-resolve any DNS-sourced ECH configs into inline base64 so the
    // sync `parse_proxy` path that follows can stay sync. Failures warn
    // and leave the map unchanged — except the `enable: true` with no
    // query-source defect, which `strict` promotes to an error.
    if let Some(ps) = raw.proxies.as_mut() {
        ech_dns::preresolve_ech(ps, raw.strict.unwrap_or(false))
            .await
            .map_err(|e| anyhow::anyhow!("{e} (strict mode)"))?;
    }

    // Geodata config — parse and validate early so path errors surface before
    // anything tries to load the DBs.
    let geodata = geodata::parse_geodata(raw.geodata.as_ref())?;

    // General config
    let mode = match raw.mode.as_deref().unwrap_or("rule").parse::<TunnelMode>() {
        Ok(m) => m,
        Err(e) if raw.strict.unwrap_or(false) => {
            anyhow::bail!("mode: {e} (strict mode)");
        }
        Err(e) => {
            warn!("mode: {e}; defaulting to 'rule'");
            TunnelMode::Rule
        }
    };
    let log_level = raw.log_level.clone().unwrap_or_else(|| "info".to_string());
    // mihomo (and Clash Verge output) use `bind-address: '*'` as the
    // all-interfaces wildcard; normalize it here so listeners never see the
    // raw `*`, which is not an IP literal (#388). Dual-stack wildcard stays
    // spellable as `'::'`.
    let bind_address = match raw.bind_address.as_deref() {
        None => "127.0.0.1".to_string(),
        Some("*" | "") => "0.0.0.0".to_string(),
        Some(addr) => addr.to_string(),
    };

    let general = GeneralConfig {
        mode,
        log_level,
        ipv6: effective_ipv6(raw.ipv6),
        allow_lan: raw.allow_lan.unwrap_or(false),
        bind_address,
    };

    // Registry the provider nodes' `dialer-proxy` targets resolve against
    // (issue #489). It is shared into every provider *before* they load so
    // nodes parsed during the initial refresh already hold the handle; the
    // tunnel publishes the live route map into it on every routing install.
    let provider_dialer_registry = meow_proxy::dialer::ProxyRegistry::default();

    // Load proxy providers (async: may HTTP-fetch provider files).
    let proxy_providers = if let Some(raw_pp) = raw.proxy_providers.as_ref() {
        if raw_pp.is_empty() {
            HashMap::new()
        } else {
            proxy_provider::load_proxy_providers(
                raw_pp,
                cache_dir,
                general.ipv6,
                raw.strict.unwrap_or(false),
                &provider_dialer_registry,
            )
            .await?
        }
    } else {
        HashMap::new()
    };

    // Two-pass build so DNS can see the proxy registry without a circular
    // dependency on the resolver itself (issue #67 phase 2, ADR-0012):
    //
    //   1. Build proxies with no resolver injected. Every adapter except
    //      DIRECT is fully functional here; DIRECT falls back to the OS
    //      resolver, which would loop if meow-rs were the system DNS.
    //   2. Build the DNS resolver, passing those proxies as the
    //      `#PROXY-NAME` registry. The resolver does not call back into
    //      proxies during construction, so this is safe.
    //   3. Rebuild proxies with the real resolver attached. The two
    //      passes only differ in DIRECT's resolver field; nothing else
    //      depends on the placeholder built in step 1.
    //
    // Both passes publish into ONE shared `dialer-proxy` registry: pass-1
    // adapters are retained by the DNS resolver (`#PROXY` nameservers) and
    // by rule-provider fetch contexts for the app's whole first generation,
    // and the shared cell lets them resolve the pass-2 snapshot rather than
    // a stale pass-1 map (issue #533).
    let dialer_registry = meow_proxy::dialer::ProxyRegistry::default();
    // Open the persistent selector store (one JSON file in cache_dir).
    // Missing/unreadable files yield an empty store — no fatal errors.
    let cache_dir_buf = cache_dir.map(Path::to_path_buf);
    let selector_store = match cache_dir_buf.as_ref() {
        Some(d) => Some(open_selector_store_async(d.join("selector-cache.json")).await?),
        None => None,
    };

    // One shared pre-registry proxy layer for the two startup fetches that
    // can ride a proxy (rule-provider prefetch + geodata download). Built
    // only when at least one of them could need it — a full layer costs an
    // adapter construction per `proxies:` entry (issue #533).
    let prefetch_proxies = if prefetch_proxy_layer_needed(&raw, &geodata) {
        prefetch_proxy_layer_async(&raw, &proxy_providers, selector_store.as_ref()).await?
    } else {
        None
    };

    // Fetch/read rule-provider payloads once; the geodata check, the parser
    // context build, and every provider load pass below reuse these bytes so
    // geo keys referenced only inside provider payloads are seen (issue #277)
    // and nothing is fetched twice.
    let provider_payloads = Arc::new(
        prefetch_rule_provider_payloads_async(
            &raw,
            cache_dir_buf.clone(),
            prefetch_proxies.clone(),
        )
        .await,
    );

    // Ensure geodata files exist — download any that are missing and needed
    // by the config's rules (including sub-rules and provider payloads). This
    // must happen before building the parser context, which hard-errors on
    // missing GeoIP/ASN files.
    let geo_scan_lines = collect_geo_scan_lines(&raw, &provider_payloads);
    ensure_geodata(&raw, &geodata, &geo_scan_lines, prefetch_proxies.as_deref()).await;
    drop(geo_scan_lines);
    drop(prefetch_proxies);

    // Build the parser context once and share across all passes.
    let ctx = build_parser_context_with_geo_async(
        raw.clone(),
        geodata.clone(),
        Arc::clone(&provider_payloads),
    )
    .await?;

    let (proxies, _, _) = {
        let res = rebuild_from_raw_impl_async(
            raw.clone(),
            cache_dir_buf.clone(),
            None,
            proxy_providers.clone(),
            selector_store.clone(),
            ctx.clone(),
            Arc::clone(&provider_payloads),
            dialer_registry.clone(),
            provider_dialer_registry.clone(),
            None,
        )
        .await?;
        (res.proxies, res.rules, res.dialer_registry)
    };

    // Load rule-providers before DNS so that `nameserver-policy` `rule-set:`
    // entries can resolve against them. This uses the step-1 proxy registry;
    // step-2 only differs in DIRECT's resolver field (see ADR-0012), which
    // does not affect provider `proxy:` resolution or HTTP fetches.
    let download_proxy = internal_http::first_named_proxy(raw.proxies.as_deref(), &proxies);
    let rule_providers = match raw.rule_providers.as_ref() {
        Some(map) if !map.is_empty() => {
            load_rule_providers_async(
                map.clone(),
                cache_dir_buf.clone(),
                ctx.clone(),
                download_proxy,
                proxies.clone(),
                Arc::clone(&provider_payloads),
                Some(dialer_registry.clone()),
                raw.strict.unwrap_or(false),
            )
            .await?
        }
        _ => HashMap::new(),
    };

    // DNS — pass the explicit mmdb path so fallback-filter GeoIP uses the
    // same path as the rule engine, plus the proxy registry from step 1
    // so #PROXY-tagged nameservers can resolve their referenced adapter.
    let dns_config = dns_parser::parse_dns(
        &raw,
        geodata.mmdb_path.as_deref(),
        cache_dir,
        &proxies,
        ctx.geosite.clone(),
        &rule_providers,
        None,
    )
    .await?;

    let (proxies, rules, _) = {
        let res = rebuild_from_raw_impl_async(
            raw.clone(),
            cache_dir_buf.clone(),
            Some(Arc::clone(&dns_config.resolver_slot)),
            proxy_providers.clone(),
            selector_store.clone(),
            ctx.clone(),
            Arc::clone(&provider_payloads),
            dialer_registry.clone(),
            provider_dialer_registry.clone(),
            // Share the provider set already loaded for DNS so rules,
            // `rule-set:` matchers, and `Config.rule_providers` reference
            // one object per provider (issue #533 review).
            Some(rule_providers.clone()),
        )
        .await?;
        (res.proxies, res.rules, res.dialer_registry)
    };

    // Listener config
    let (bind_addr, global_tproxy_sni) = listener_bind_inputs(&raw);

    // Build the named-listener list, checking for duplicate ports/names.
    let named_listeners = build_named_listeners(&raw, &bind_addr, global_tproxy_sni)?;

    let listeners = ListenerConfig {
        mixed_port: raw.mixed_port,
        socks_port: raw.socks_port,
        http_port: raw.port,
        bind_address: bind_addr,
        tproxy_port: raw.tproxy_port,
        tproxy_sni: global_tproxy_sni,
        routing_mark: raw.routing_mark,
        named: named_listeners,
    };

    // TUN inbound (issue #326).
    let tun = parse_tun_config(raw.tun.as_ref(), raw.max_connections)?;

    // API config
    let external_ui = raw
        .external_ui
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|base| {
            let mut dir = PathBuf::from(base);
            // mihomo nests the actual files under `external-ui-name` when present.
            if let Some(name) = raw.external_ui_name.as_deref().filter(|s| !s.is_empty()) {
                dir.push(name);
            }
            dir
        });
    let api = ApiConfig {
        external_controller: parse_optional_socket_addr(
            "external-controller",
            raw.external_controller.as_deref(),
        )?,
        secret: raw.secret.clone(),
        external_ui,
        external_ui_url: raw
            .external_ui_url
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(String::from),
    };

    // Sniffer config — also handles deprecated `tproxy_sni` alias.
    let sniffer = parse_sniffer_config(&raw, raw.strict.unwrap_or(false))?;

    // Auth config.
    let auth = auth::parse_auth_config(
        raw.authentication.as_deref(),
        raw.skip_auth_prefixes.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let auth = Arc::new(auth);

    info!(
        "Config loaded: mode={}, proxies={}, rules={}",
        mode,
        proxies.len(),
        rules.len()
    );

    Ok(Config {
        general,
        dns: dns_config,
        proxies,
        proxy_providers,
        provider_dialer_registry,
        rules,
        rule_providers,
        dialer_registry,
        listeners,
        tun,
        api,
        sniffer,
        auth,
        raw,
        geodata,
    })
}

#[cfg(test)]
mod dialer_proxy_tests {
    use super::*;

    /// TCP listener that accepts-and-drops, counting connections — the
    /// observable for "which address did the dial physically contact".
    async fn counting_listener() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&count);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        (port, count)
    }

    fn hits(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn simple_proxy(name: &str) -> Arc<dyn Proxy> {
        // A bare DIRECT adapter is enough; we only assert on registry identity.
        let direct = meow_proxy::DirectAdapter::new();
        let _ = name; // name comes from the map key, not the adapter
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(direct)))
    }

    fn raw_proxy(name: &str, dialer: Option<&str>) -> HashMap<String, serde_yaml::Value> {
        let mut m = HashMap::new();
        m.insert(
            "name".to_string(),
            serde_yaml::Value::String(name.to_string()),
        );
        if let Some(d) = dialer {
            m.insert(
                "dialer-proxy".to_string(),
                serde_yaml::Value::String(d.to_string()),
            );
        }
        m
    }

    fn registry(names: &[&str]) -> HashMap<SmolStr, Arc<dyn Proxy>> {
        names
            .iter()
            .map(|n| (SmolStr::from(*n), simple_proxy(n)))
            .collect()
    }

    /// True when the registry entry for `name` was replaced (wrapped) relative
    /// to `before`.
    fn was_wrapped(
        before: &HashMap<SmolStr, Arc<dyn Proxy>>,
        after: &HashMap<SmolStr, Arc<dyn Proxy>>,
        name: &str,
    ) -> bool {
        let b = before.get(name).expect("present before");
        let a = after.get(name).expect("present after");
        !Arc::ptr_eq(b, a)
    }

    /// Run the dialer pass against a fresh by-name registry and publish it on
    /// success, the way `rebuild_from_raw_impl` does — without the publish the
    /// chained adapters cannot resolve their front hop at dial time.
    ///
    /// Returns the registry: `DialerTarget`s hold it weakly (issue #533), so a
    /// test that actually dials must keep the handle alive for the duration.
    fn apply_chains(
        proxies: &mut HashMap<SmolStr, Arc<dyn Proxy>>,
        raw_proxies: &[HashMap<String, serde_yaml::Value>],
    ) -> Result<meow_proxy::dialer::ProxyRegistry, anyhow::Error> {
        apply_chains_with_groups(proxies, raw_proxies, &[])
    }

    /// Same as [`apply_chains`] but with declared `proxy-groups`, so tests can
    /// exercise group-valued dialers and the membership cycle check. Stands in
    /// for the group build by giving every declared group a registry entry —
    /// the cycle check models declared membership, so what the entry *is*
    /// does not matter, only that it exists.
    fn apply_chains_with_groups(
        proxies: &mut HashMap<SmolStr, Arc<dyn Proxy>>,
        raw_proxies: &[HashMap<String, serde_yaml::Value>],
        raw_groups: &[raw::RawProxyGroup],
    ) -> Result<meow_proxy::dialer::ProxyRegistry, anyhow::Error> {
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let edges = apply_dialer_proxies(proxies, raw_proxies, raw_groups, &registry, true, false)?;
        for group in raw_groups {
            proxies
                .entry(SmolStr::from(group.name.as_str()))
                .or_insert_with(|| simple_proxy(&group.name));
        }
        let global_auto_created = !proxies.contains_key("GLOBAL");
        let include_all_proxy_names = raw_proxies
            .iter()
            .filter_map(|proxy| proxy.get("name").and_then(serde_yaml::Value::as_str))
            .map(SmolStr::from)
            .collect();
        reject_group_membership_cycles(
            &edges,
            raw_groups,
            proxies,
            &include_all_proxy_names,
            global_auto_created,
        )?;
        registry.publish(Arc::new(proxies.clone()));
        Ok(registry)
    }

    /// The original #533 bug was a strong `registry → snapshot → adapter →
    /// registry` cycle: every rebuild leaked the whole prior route table.
    /// A dropped build must now free the cell — under the old edge the
    /// adapter's strong `Arc` kept the cell alive, so this upgrade would
    /// stay `Some` forever.
    #[test]
    fn dropped_build_leaves_no_registry_cycle() {
        let raw: raw::RawConfig = serde_yaml::from_str(
            "proxies:\n  - name: A\n    type: direct\n    dialer-proxy: B\n  - name: B\n    type: direct\n",
        )
        .unwrap();
        let result = rebuild_from_raw(&raw).unwrap();
        let weak = result.dialer_registry.downgrade();
        let proxies = result.proxies;
        drop(proxies);
        drop(result.dialer_registry);
        assert!(
            weak.upgrade().is_none(),
            "a strong adapter->registry edge would pin the dead generation"
        );
    }

    /// Startup's two-pass build shares one registry cell (issue #533): a
    /// `DialerTarget` bound by pass-1 resolves the *latest* published
    /// snapshot, which is what lets pass-1 adapters retained by DNS
    /// `#PROXY` nameservers and provider fetch contexts keep working.
    #[test]
    fn shared_registry_republishes_the_latest_snapshot() {
        let reg = meow_proxy::dialer::ProxyRegistry::default();
        let target = meow_proxy::dialer::DialerTarget::new("B", &reg);

        reg.publish(Arc::new(registry(&["B"])));
        let gen1 = target.resolve().expect("gen-1 published");
        reg.publish(Arc::new(registry(&["B", "C"])));
        let gen2 = target.resolve().expect("gen-2 republished");
        assert!(
            !Arc::ptr_eq(&gen1, &gen2),
            "republish must hand out the new generation's adapter"
        );
        assert!(
            target.name() == "B" && reg.downgrade().upgrade().is_some(),
            "the handle stays live while retained"
        );
    }

    /// Issue #533 item 2: the pre-registry payload prefetch resolves `proxy:`
    /// download names against the full proxy layer — `dialer-proxy` chains
    /// and groups included — built by the same `build_proxy_layer` the
    /// runtime publishes. Before this, the named node was re-parsed bare and
    /// the fetch bypassed the configured front hop entirely (silent egress).
    /// The observable is which listener the dial physically contacts.
    #[tokio::test]
    async fn prefetch_map_dials_through_the_chain() {
        async fn counting_listener() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = Arc::clone(&count);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    drop(stream);
                }
            });
            (port, count)
        }
        let (port_a, a_hits) = counting_listener().await;
        let (port_b, b_hits) = counting_listener().await;
        let (port_c, c_hits) = counting_listener().await;

        let raw: raw::RawConfig = serde_yaml::from_str(&format!(
            "proxies:\n\
             \x20 - name: A\n    type: trojan\n    server: 127.0.0.1\n    port: {port_a}\n    \
             password: x\n    dialer-proxy: B\n\
             \x20 - name: B\n    type: trojan\n    server: 127.0.0.1\n    port: {port_b}\n    \
             password: x\n\
             \x20 - name: C\n    type: trojan\n    server: 127.0.0.1\n    port: {port_c}\n    \
             password: x\n    dialer-proxy: G\n\
             proxy-groups:\n\
             \x20 - name: G\n    type: select\n    proxies: [B]\n"
        ))
        .unwrap();

        let providers = HashMap::new();
        let mini = prefetch_proxy_map(&raw, &providers, None)
            .expect("layer builds")
            .expect("proxies configured");
        let metadata = meow_common::Metadata {
            network: meow_common::Network::Tcp,
            host: "example.invalid".into(),
            dst_port: 443,
            ..Default::default()
        };

        // A dials through B: B's listener is contacted, A's own is not.
        let _ = mini.map["A"].dial_tcp(&metadata).await;
        assert!(b_hits.load(std::sync::atomic::Ordering::SeqCst) >= 1);
        assert_eq!(a_hits.load(std::sync::atomic::Ordering::SeqCst), 0);

        // C's front hop is group G (selecting B) — the prefetch layer
        // resolves it exactly as the runtime registry would, so the dial
        // still lands on B rather than failing closed or touching C.
        let before = b_hits.load(std::sync::atomic::Ordering::SeqCst);
        let _ = mini.map["C"].dial_tcp(&metadata).await;
        assert!(b_hits.load(std::sync::atomic::Ordering::SeqCst) > before);
        assert_eq!(c_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// The prefetch layer is only built when a startup fetch could ride it:
    /// any non-inline provider (http fetch, or a file payload hiding geo
    /// references) forces it on; otherwise it hinges on geodata the rules
    /// actually need being absent.
    #[test]
    fn prefetch_layer_gate_tracks_real_need() {
        let geo = GeoDataConfig::default();
        let one_proxy = "proxies:\n  - {name: p, type: direct}\n";
        let no_providers: raw::RawConfig = serde_yaml::from_str(one_proxy).unwrap();

        // Fetchable provider → build it even with no geo references.
        let with_http: raw::RawConfig = serde_yaml::from_str(&format!(
            "{one_proxy}rule-providers:\n  rs:\n    type: http\n    behavior: domain\n    url: http://x/y\n    path: ./rs.yaml"
        ))
        .unwrap();
        assert!(prefetch_proxy_layer_needed(&with_http, &geo));

        // A `file` provider counts too — its payload can carry geo keys the
        // raw scan cannot see yet.
        let with_file: raw::RawConfig = serde_yaml::from_str(&format!(
            "{one_proxy}rule-providers:\n  rs:\n    type: file\n    behavior: domain\n    path: ./rs.yaml"
        ))
        .unwrap();
        assert!(prefetch_proxy_layer_needed(&with_file, &geo));

        // Inline-only, rules free of geo references → nothing to fetch.
        let inline_only: raw::RawConfig = serde_yaml::from_str(&format!(
            "{one_proxy}rule-providers:\n  rs:\n    type: inline\n    behavior: domain\n    payload: ['.example.com']"
        ))
        .unwrap();
        assert!(!prefetch_proxy_layer_needed(&inline_only, &geo));
        assert!(!prefetch_proxy_layer_needed(&no_providers, &geo));

        // No `proxies:` at all → the layer can never exist.
        let empty_proxies: raw::RawConfig = serde_yaml::from_str(
            "rule-providers:\n  rs:\n    type: http\n    behavior: domain\n    url: http://x/y\n    path: ./rs.yaml",
        )
        .unwrap();
        assert!(!prefetch_proxy_layer_needed(&empty_proxies, &geo));

        // Inline-only but a GEOIP rule with a missing DB → the geodata
        // download needs the layer.
        let dir = tempfile::tempdir().unwrap();
        let missing_mmdb = GeoDataConfig {
            mmdb_path: Some(dir.path().join("absent.mmdb")),
            ..geo.clone()
        };
        let geoip_rules: raw::RawConfig = serde_yaml::from_str(&format!(
            "{one_proxy}rule-providers:\n  rs:\n    type: inline\n    behavior: domain\n    payload: ['.example.com']\n\
             rules:\n  - GEOIP,CN,DIRECT"
        ))
        .unwrap();
        assert!(prefetch_proxy_layer_needed(&geoip_rules, &missing_mmdb));

        // Same rules with the DB present → nothing downloads → no layer.
        let present = dir.path().join("geoip.mmdb");
        std::fs::write(&present, b"x").unwrap();
        let present_mmdb = GeoDataConfig {
            mmdb_path: Some(present),
            ..geo
        };
        assert!(!prefetch_proxy_layer_needed(&geoip_rules, &present_mmdb));
    }

    /// End-to-end wiring: a provider's `proxy:` key resolves through the
    /// shared prefetch layer, so its HTTP fetch dials the chained front
    /// hop rather than the leaf's own (or a direct) egress.
    #[tokio::test]
    async fn prefetch_payloads_fetch_rides_the_chain() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_port = listener.local_addr().unwrap().port();
        let b_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&b_hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });

        let raw: raw::RawConfig = serde_yaml::from_str(&format!(
            "proxies:\n\
             \x20 - name: A\n    type: trojan\n    server: 127.0.0.1\n    port: 9\n    \
             password: x\n    dialer-proxy: B\n\
             \x20 - name: B\n    type: trojan\n    server: 127.0.0.1\n    port: {b_port}\n    \
             password: x\n\
             rule-providers:\n\
             \x20 rs:\n    type: http\n    behavior: domain\n    \
             url: http://127.0.0.1:9/rs.yaml\n    path: ./rs.yaml\n    proxy: A\n"
        ))
        .unwrap();

        let providers = HashMap::new();
        let layer = Arc::new(
            prefetch_proxy_map(&raw, &providers, None)
                .expect("layer builds")
                .expect("proxies configured"),
        );
        // The fetch itself fails — the counting listener accepts then drops
        // — but the TCP connect to B proves `proxy: A` dialled its front hop.
        let payloads = prefetch_rule_provider_payloads_async(&raw, None, Some(layer)).await;
        assert!(payloads.is_empty());
        assert!(b_hits.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    }

    /// A provider *without* `proxy:` rides the prefetch layer through the
    /// default download proxy — `first_named_proxy` resolves `proxies[0]`
    /// inside the layer, so the fetch still dials A's chained front hop B.
    /// Reverting the default to a bare re-parse (or never building the
    /// layer) would dial A's own listener or the provider URL direct.
    #[tokio::test]
    async fn build_config_prefetch_default_rides_the_chain() {
        let (port_a, a_hits) = counting_listener().await;
        let (port_b, b_hits) = counting_listener().await;
        let (port_u, u_hits) = counting_listener().await;

        let raw: raw::RawConfig = serde_yaml::from_str(&format!(
            "proxies:\n\
             \x20 - name: A\n    type: trojan\n    server: 127.0.0.1\n    port: {port_a}\n    \
             password: x\n    dialer-proxy: B\n\
             \x20 - name: B\n    type: trojan\n    server: 127.0.0.1\n    port: {port_b}\n    \
             password: x\n\
             rule-providers:\n\
             \x20 rs:\n    type: http\n    behavior: domain\n    \
             url: http://127.0.0.1:{port_u}/rs.yaml\n    path: ./rs.yaml\n"
        ))
        .unwrap();

        // Every fetch fails (listeners accept-then-drop), and provider load
        // failures warn-and-skip — the config itself still builds.
        build_config(raw, None)
            .await
            .expect("config builds despite failed provider fetch");

        assert!(
            hits(&b_hits) >= 1,
            "the prefetch fetch must reach A's front hop B"
        );
        assert_eq!(
            hits(&a_hits),
            0,
            "a bare adapter would dial A's own listener"
        );
        assert_eq!(
            hits(&u_hits),
            0,
            "no fetch may reach the provider URL listener directly"
        );
    }

    /// A proxy layer the real build would reject must abort `build_config`
    /// BEFORE any provider fetch can egress — swallowing the layer error
    /// and continuing with a partial map would leak one direct fetch.
    #[tokio::test]
    async fn rejected_layer_fails_before_any_fetch() {
        let (port_u, u_hits) = counting_listener().await;

        let raw: raw::RawConfig = serde_yaml::from_str(&format!(
            "proxies:\n\
             \x20 - name: A\n    type: trojan\n    server: 127.0.0.1\n    port: 9\n    \
             password: x\n    dialer-proxy: ghost\n\
             rule-providers:\n\
             \x20 rs:\n    type: http\n    behavior: domain\n    \
             url: http://127.0.0.1:{port_u}/rs.yaml\n    path: ./rs.yaml\n"
        ))
        .unwrap();

        assert!(
            build_config(raw, None).await.is_err(),
            "an unknown dialer target rejects the prefetch layer"
        );
        assert_eq!(
            hits(&u_hits),
            0,
            "no fetch may egress before the config's proxy layer validates"
        );
    }

    /// `ensure_geodata` downloads missing DBs through the same prefetch
    /// layer — dropping its `prefetch` argument would fetch the MMDB URL
    /// direct, and a bare re-parse would hit A's own listener, not B's.
    #[tokio::test]
    async fn geodata_download_rides_the_chain() {
        let (port_a, a_hits) = counting_listener().await;
        let (port_b, b_hits) = counting_listener().await;
        let (port_u, u_hits) = counting_listener().await;
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.mmdb");

        let raw: raw::RawConfig = serde_yaml::from_str(&format!(
            "proxies:\n\
             \x20 - name: A\n    type: trojan\n    server: 127.0.0.1\n    port: {port_a}\n    \
             password: x\n    dialer-proxy: B\n\
             \x20 - name: B\n    type: trojan\n    server: 127.0.0.1\n    port: {port_b}\n    \
             password: x\n\
             geodata:\n\
             \x20 mmdb-path: {}\n\
             \x20 url:\n        mmdb: http://127.0.0.1:{port_u}/x.mmdb\n\
             rules:\n  - GEOIP,CN,DIRECT\n",
            missing.display()
        ))
        .unwrap();

        // The download fails (B drops the conn) and the parser-context
        // build then hard-errors on the still-missing MMDB — only the dial
        // observables matter here.
        let _ = build_config(raw, None).await;
        assert!(
            hits(&b_hits) >= 1,
            "the geodata download must reach A's front hop B"
        );
        assert_eq!(
            hits(&a_hits),
            0,
            "a bare adapter would dial A's own listener"
        );
        assert_eq!(
            hits(&u_hits),
            0,
            "the MMDB URL must not be fetched directly"
        );
    }

    #[test]
    fn wraps_proxy_with_dialer() {
        let mut proxies = registry(&["A", "fast"]);
        let before = proxies.clone();
        apply_chains(&mut proxies, &[raw_proxy("A", Some("fast"))]).expect("valid chain applies");
        assert!(was_wrapped(&before, &proxies, "A"));
        assert!(!was_wrapped(&before, &proxies, "fast"));
    }

    #[test]
    fn self_reference_is_a_config_error() {
        let mut proxies = registry(&["A"]);
        let before = proxies.clone();
        let err = apply_chains(&mut proxies, &[raw_proxy("A", Some("A"))])
            .expect_err("a self-referencing dialer must not silently dial direct");
        assert!(
            err.to_string().contains("points to itself"),
            "unexpected: {err}"
        );
        assert!(!was_wrapped(&before, &proxies, "A"));
    }

    #[test]
    fn missing_dialer_is_a_config_error() {
        let mut proxies = registry(&["A"]);
        let before = proxies.clone();
        let err = apply_chains(&mut proxies, &[raw_proxy("A", Some("ghost"))])
            .expect_err("an unknown dialer must not silently dial direct");
        assert!(err.to_string().contains("not found"), "unexpected: {err}");
        assert!(!was_wrapped(&before, &proxies, "A"));
    }

    #[test]
    fn cycle_is_a_config_error() {
        let mut proxies = registry(&["A", "B"]);
        let before = proxies.clone();
        let err = apply_chains(
            &mut proxies,
            &[raw_proxy("A", Some("B")), raw_proxy("B", Some("A"))],
        )
        .expect_err("a dialer cycle must not silently dial direct");
        assert!(err.to_string().contains("cycle"), "unexpected: {err}");
        assert!(!was_wrapped(&before, &proxies, "A"));
        assert!(!was_wrapped(&before, &proxies, "B"));
    }

    /// A cycle that only *some* of the edges sit on still has to be rejected:
    /// late binding recurses through the whole chain, so `A` feeding `B <-> C`
    /// never terminates either.
    #[test]
    fn chain_feeding_a_cycle_is_a_config_error() {
        let mut proxies = registry(&["A", "B", "C"]);
        let before = proxies.clone();
        let err = apply_chains(
            &mut proxies,
            &[
                raw_proxy("A", Some("B")),
                raw_proxy("B", Some("C")),
                raw_proxy("C", Some("B")),
            ],
        )
        .expect_err("an edge feeding a cycle must not silently dial direct");
        assert!(err.to_string().contains("cycle"), "unexpected: {err}");
        assert!(!was_wrapped(&before, &proxies, "A"));
    }

    fn raw_group(name: &str, members: &[&str]) -> raw::RawProxyGroup {
        raw::RawProxyGroup {
            name: name.to_string(),
            group_type: "select".to_string(),
            proxies: Some(members.iter().map(ToString::to_string).collect()),
            ..Default::default()
        }
    }

    /// A group-valued dialer whose membership can route back to the chained
    /// proxy recurses without ever reaching I/O — synchronous nested polls
    /// exhaust the native stack on the first dial. The combined
    /// dialer-edge + membership-edge check must reject it (mihomo's
    /// `validateDialerProxies` misses this class entirely).
    #[test]
    fn group_selecting_self_is_a_config_error() {
        let mut proxies = registry(&["A", "B"]);
        let err = apply_chains_with_groups(
            &mut proxies,
            &[raw_proxy("A", Some("G"))],
            &[raw_group("G", &["A", "B"])],
        )
        .expect_err("a dialer that can route back to its source must be rejected");
        assert!(
            err.to_string().contains("through group membership"),
            "unexpected: {err}"
        );
    }

    /// The same loop one group hop away: `G1` holds `G2`, `G2` holds `A`.
    #[test]
    fn nested_group_selecting_self_is_a_config_error() {
        let mut proxies = registry(&["A", "B"]);
        let err = apply_chains_with_groups(
            &mut proxies,
            &[raw_proxy("A", Some("G1"))],
            &[raw_group("G1", &["G2"]), raw_group("G2", &["A", "B"])],
        )
        .expect_err("a transitive self-route must be rejected");
        assert!(
            err.to_string().contains("through group membership"),
            "unexpected: {err}"
        );
    }

    /// A loop that alternates dialer edges and membership edges:
    /// `A -> G`, `G` holds `B`, `B -> A`.
    #[test]
    fn group_and_dialer_cycle_is_a_config_error() {
        let mut proxies = registry(&["A", "B"]);
        let err = apply_chains_with_groups(
            &mut proxies,
            &[raw_proxy("A", Some("G")), raw_proxy("B", Some("A"))],
            &[raw_group("G", &["B"])],
        )
        .expect_err("a membership+dialer cycle must be rejected");
        assert!(
            err.to_string().contains("through group membership"),
            "unexpected: {err}"
        );
    }

    /// The auto-created `GLOBAL` contains every registry entry, so chaining
    /// through it always routes back to the source.
    #[test]
    fn auto_global_dialer_is_a_config_error() {
        let mut proxies = registry(&["A", "B"]);
        let err = apply_chains_with_groups(&mut proxies, &[raw_proxy("A", Some("GLOBAL"))], &[])
            .expect_err("chaining through auto-GLOBAL must be rejected");
        assert!(
            err.to_string().contains("through group membership"),
            "unexpected: {err}"
        );
    }

    /// `include-all-proxies` expands to every top-level proxy — same self-route.
    #[test]
    fn include_all_proxies_group_is_a_config_error() {
        let mut proxies = registry(&["A", "B"]);
        let mut g = raw_group("G", &[]);
        g.include_all_proxies = Some(true);
        let err = apply_chains_with_groups(&mut proxies, &[raw_proxy("A", Some("G"))], &[g])
            .expect_err("an include-all-proxies dialer must be rejected");
        assert!(
            err.to_string().contains("through group membership"),
            "unexpected: {err}"
        );
    }

    /// A group-valued dialer that cannot reach back to its source is fine.
    #[test]
    fn group_not_containing_self_is_allowed() {
        let mut proxies = registry(&["A", "B"]);
        let before = proxies.clone();
        apply_chains_with_groups(
            &mut proxies,
            &[raw_proxy("A", Some("G"))],
            &[raw_group("G", &["B"])],
        )
        .expect("a group dialer that cannot route back is valid");
        assert!(was_wrapped(&before, &proxies, "A"));
    }

    /// A malformed `dialer-proxy` value is a config error — mihomo's
    /// `ParseProxy` type-asserts the field, and warn-skipping would silently
    /// direct-dial the node (upstream parity; issue #489 review).
    #[test]
    fn malformed_dialer_proxy_is_a_config_error() {
        let mut proxies = registry(&["A", "B"]);
        let mut raw = raw_proxy("A", None);
        raw.insert(
            "dialer-proxy".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(42)),
        );
        // Malformed values are a hard error under `strict` — the lenient
        // fail-at-dial sentinel arm is covered by `strict_mode_tests` at the
        // rebuild level. `apply_chains` runs the lenient path.
        let err = apply_dialer_proxies(
            &mut proxies,
            &[raw],
            &[],
            &meow_proxy::dialer::ProxyRegistry::default(),
            true,
            true,
        )
        .map(|_| ())
        .expect_err("malformed dialer-proxy must fail under strict");
        assert!(
            err.to_string().contains("malformed dialer-proxy"),
            "error must name the field: {err}"
        );
    }

    /// A padded `dialer-proxy` name resolves after trimming — the provider
    /// path trims too, so statics must not hard-fail on the same input
    /// (issue #489 review).
    #[test]
    fn padded_dialer_proxy_name_is_trimmed() {
        let mut proxies = registry(&["A", "B"]);
        let before = proxies.clone();
        let mut raw = raw_proxy("A", None);
        raw.insert(
            "dialer-proxy".to_string(),
            serde_yaml::Value::String(" B ".to_string()),
        );
        apply_chains(&mut proxies, &[raw]).expect("a padded name resolves after trim");
        assert!(was_wrapped(&before, &proxies, "A"));
    }

    /// `dialer-proxy: ""` / `~` unset the chain (mihomo parity), while a
    /// whitespace-only value is malformed — under lenient it binds the
    /// never-resolving sentinel instead of silently dialling direct.
    #[test]
    fn empty_dialer_proxy_unsets_but_whitespace_poisons() {
        let mut proxies = registry(&["A", "B", "C"]);
        let before = proxies.clone();

        let mut empty = raw_proxy("A", None);
        empty.insert(
            "dialer-proxy".to_string(),
            serde_yaml::Value::String(String::new()),
        );
        let mut null = raw_proxy("B", None);
        null.insert("dialer-proxy".to_string(), serde_yaml::Value::Null);
        let mut ws = raw_proxy("C", None);
        ws.insert(
            "dialer-proxy".to_string(),
            serde_yaml::Value::String(" ".to_string()),
        );

        apply_chains(&mut proxies, &[empty, null, ws])
            .expect("lenient tolerates empty/null and poisons whitespace");
        assert!(
            !was_wrapped(&before, &proxies, "A"),
            "`dialer-proxy: \"\"` unsets the chain"
        );
        assert!(
            !was_wrapped(&before, &proxies, "B"),
            "`dialer-proxy: ~` unsets the chain"
        );
        assert!(
            was_wrapped(&before, &proxies, "C"),
            "a whitespace-only value binds the fail-at-dial sentinel"
        );
    }

    /// Duplicate `name:` blocks: only the *last* block is the effective
    /// definition, so a `dialer-proxy` declared only by an earlier duplicate
    /// must not chain the effective block.
    #[test]
    fn stale_duplicate_dialer_edge_is_ignored() {
        let mut proxies = registry(&["A", "front"]);
        let before = proxies.clone();

        let mut first = raw_socks5_proxy("A", Some("front"), false);
        first.insert(
            "port".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(1111)),
        );
        let mut last = raw_socks5_proxy("A", None, false);
        last.insert(
            "port".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(2222)),
        );

        apply_chains(&mut proxies, &[first, last]).expect("the effective block declares no dialer");

        assert!(
            !was_wrapped(&before, &proxies, "A"),
            "the last duplicate block declares no dialer-proxy, so no chain \
             may be applied"
        );
    }

    #[test]
    fn nested_chain_wraps_every_layer() {
        // A -> B -> C: A and B are chained, C (no dialer-proxy) is untouched.
        // The front hop is resolved at dial time, so neither layer has to wait
        // for the other to reach its final form.
        let mut proxies = registry(&["A", "B", "C"]);
        let before = proxies.clone();
        apply_chains(
            &mut proxies,
            &[raw_proxy("A", Some("B")), raw_proxy("B", Some("C"))],
        )
        .expect("valid nested chain applies");
        assert!(was_wrapped(&before, &proxies, "A"));
        assert!(was_wrapped(&before, &proxies, "B"));
        assert!(!was_wrapped(&before, &proxies, "C"));
    }

    /// Raw config for a `type: socks5` proxy with optional `dialer-proxy` and
    /// `udp` fields — exercises the re-parse path (vs. the fallback
    /// `DialerProxyAdapter` wrapper used by the bare `raw_proxy` helper).
    fn raw_socks5_proxy(
        name: &str,
        dialer: Option<&str>,
        udp: bool,
    ) -> HashMap<String, serde_yaml::Value> {
        let mut m = HashMap::new();
        m.insert(
            "name".to_string(),
            serde_yaml::Value::String(name.to_string()),
        );
        m.insert(
            "type".to_string(),
            serde_yaml::Value::String("socks5".to_string()),
        );
        m.insert(
            "server".to_string(),
            serde_yaml::Value::String("127.0.0.1".to_string()),
        );
        m.insert(
            "port".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(1080)),
        );
        if udp {
            m.insert("udp".to_string(), serde_yaml::Value::Bool(true));
        }
        if let Some(d) = dialer {
            m.insert(
                "dialer-proxy".to_string(),
                serde_yaml::Value::String(d.to_string()),
            );
        }
        m
    }

    #[test]
    fn re_parse_replaces_entry_and_keeps_adapter_type() {
        // A socks5 proxy with `dialer-proxy: front` is re-parsed with a
        // ProxyDialer injected (the mihomo-model path). The entry is replaced
        // and still presents as Socks5 — a DialerProxyAdapter wrapper would
        // also report the inner type, so `chain_reaches_target_through_front`
        // below is what actually distinguishes the two paths.
        let mut proxies = registry(&["A", "front"]);
        let parsed_a = proxy_parser::parse_proxy(&raw_socks5_proxy("A", None, true), true)
            .expect("parse socks5");
        proxies.insert(SmolStr::from("A"), parsed_a);
        let before = proxies.clone();

        apply_chains(&mut proxies, &[raw_socks5_proxy("A", Some("front"), true)])
            .expect("valid chain applies");

        assert!(was_wrapped(&before, &proxies, "A"), "A should be re-parsed");
        assert!(
            !was_wrapped(&before, &proxies, "front"),
            "front is the dialer, not re-parsed"
        );
        assert_eq!(
            proxies.get("A").expect("present after").adapter_type(),
            meow_common::AdapterType::Socks5,
            "rebuilt proxy should still be Socks5"
        );
    }

    /// A raw `type: <ty>` block with a `server`/`port` and optional
    /// `dialer-proxy` — for the types that cannot carry an injected dialer.
    fn raw_typed_proxy(
        name: &str,
        ty: &str,
        dialer: Option<&str>,
    ) -> HashMap<String, serde_yaml::Value> {
        let mut m = raw_socks5_proxy(name, dialer, false);
        m.insert(
            "type".to_string(),
            serde_yaml::Value::String(ty.to_string()),
        );
        m
    }

    /// `anytls` / `hysteria2` establish their own transport and never call the
    /// pluggable dialer. Accepting the injected dialer there would silently
    /// drop the user's `dialer-proxy` and egress from the real source path, so
    /// the parser rejects it and the relay-based wrapper takes over — which
    /// fails loudly at dial time rather than dialing direct.
    #[test]
    fn types_that_cannot_carry_a_dialer_fall_back_to_the_wrapper() {
        for ty in ["anytls", "hysteria2"] {
            let mut proxies = registry(&["A", "front"]);
            let before = proxies.clone();

            apply_chains(&mut proxies, &[raw_typed_proxy("A", ty, Some("front"))])
                .expect("valid chain applies via the wrapper fallback");

            let after = proxies.get("A").expect("entry survives");
            assert!(
                was_wrapped(&before, &proxies, "A"),
                "{ty}: entry must be replaced by the relay wrapper, not left \
                 dialing direct"
            );
            assert!(
                !after.support_udp(),
                "{ty}: the wrapper must not advertise UDP over the chain"
            );
        }
    }

    /// `ss` with an *external* SIP003 plugin must not be re-parsed: the
    /// constructor spawns the plugin subprocess, so a second parse would leave
    /// two copies running whenever a group still holds the original Arc.
    #[test]
    fn external_sip003_plugin_is_not_re_parsed() {
        let mut proxies = registry(&["A", "front"]);
        let mut raw = raw_typed_proxy("A", "ss", Some("front"));
        raw.insert(
            "cipher".to_string(),
            serde_yaml::Value::String("aes-256-gcm".to_string()),
        );
        raw.insert(
            "password".to_string(),
            serde_yaml::Value::String("pw".to_string()),
        );
        // A plugin name that is not one of the built-ins → external subprocess.
        raw.insert(
            "plugin".to_string(),
            serde_yaml::Value::String("obfs-local-does-not-exist".to_string()),
        );

        // Must not panic and must not spawn: the parse is rejected before
        // `ShadowsocksAdapter::new` runs, so the fallback wrapper is used.
        apply_chains(&mut proxies, &[raw]).expect("valid chain applies via the wrapper fallback");

        assert!(
            proxies.contains_key("A"),
            "the entry must survive the rejected re-parse"
        );
    }

    /// Duplicate `name:` blocks: the registry-building loop uses `insert`, so
    /// the *last* block wins. The re-parse lookup must agree, or it resurrects
    /// the first definition and swaps the running proxy out from under the user.
    #[test]
    fn duplicate_names_re_parse_the_last_block() {
        let mut proxies = registry(&["A", "front"]);

        let mut first = raw_socks5_proxy("A", Some("front"), false);
        first.insert(
            "port".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(1111)),
        );
        let mut last = raw_socks5_proxy("A", Some("front"), false);
        last.insert(
            "port".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(2222)),
        );

        apply_chains(&mut proxies, &[first, last]).expect("valid chain applies");

        let rebuilt = proxies.get("A").expect("present after");
        assert_eq!(
            rebuilt.addr(),
            "127.0.0.1:2222",
            "the last duplicate block must win, matching registry insert order"
        );
    }

    #[test]
    fn fallback_wraps_when_re_parse_fails() {
        // A raw proxy with no `type` field cannot be re-parsed — the fallback
        // DialerProxyAdapter wrapper should be used instead. We verify this
        // by checking that support_udp is false (DialerProxyAdapter always
        // returns false, even if the inner proxy supported UDP).
        let mut proxies = registry(&["A", "front"]);
        // Give "A" a real socks5 adapter so the fallback has something to wrap.
        let parsed_a = proxy_parser::parse_proxy(&raw_socks5_proxy("A", None, true), true)
            .expect("parse socks5");
        proxies.insert(SmolStr::from("A"), parsed_a);
        let before = proxies.clone();

        // raw_proxy has no `type` → parse_proxy_with_dialer fails → fallback.
        apply_chains(&mut proxies, &[raw_proxy("A", Some("front"))])
            .expect("valid chain applies via the wrapper fallback");

        assert!(
            was_wrapped(&before, &proxies, "A"),
            "A should be wrapped via fallback"
        );
        let rebuilt = proxies.get("A").expect("present after");
        assert!(
            !rebuilt.support_udp(),
            "DialerProxyAdapter fallback should disable UDP even if inner supports it"
        );
    }

    /// End-to-end proof that the injected dialer is actually used: stand up two
    /// mock SOCKS5 servers, chain `inner` behind `front` via `dialer-proxy`,
    /// and assert `front` was asked to CONNECT to *inner's server address*
    /// (not to the final target).  This is the assertion that distinguishes the
    /// re-parse path from the relay wrapper, and it catches a silently dropped
    /// dialer that a type-only check would miss.
    #[tokio::test]
    async fn chain_dials_inner_server_through_front_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// Minimal SOCKS5 server: no-auth handshake, records the requested
        /// target, replies success, then echoes.  Returns the CONNECT target
        /// as `host:port`.
        async fn mock_socks5(
            listener: tokio::net::TcpListener,
        ) -> tokio::sync::oneshot::Receiver<String> {
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                // Greeting: VER NMETHODS METHODS…
                let mut head = [0u8; 2];
                if sock.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                if sock.read_exact(&mut methods).await.is_err() {
                    return;
                }
                // Select no-auth.
                if sock.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }
                // Request: VER CMD RSV ATYP …
                let mut req = [0u8; 4];
                if sock.read_exact(&mut req).await.is_err() {
                    return;
                }
                let target = match req[3] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        let mut port = [0u8; 2];
                        if sock.read_exact(&mut ip).await.is_err()
                            || sock.read_exact(&mut port).await.is_err()
                        {
                            return;
                        }
                        format!(
                            "{}.{}.{}.{}:{}",
                            ip[0],
                            ip[1],
                            ip[2],
                            ip[3],
                            u16::from_be_bytes(port)
                        )
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        if sock.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut host = vec![0u8; len[0] as usize];
                        let mut port = [0u8; 2];
                        if sock.read_exact(&mut host).await.is_err()
                            || sock.read_exact(&mut port).await.is_err()
                        {
                            return;
                        }
                        format!(
                            "{}:{}",
                            String::from_utf8_lossy(&host),
                            u16::from_be_bytes(port)
                        )
                    }
                    other => format!("unsupported-atyp-{other}"),
                };
                let _ = tx.send(target);
                // Success reply with a dummy BND.ADDR.
                let _ = sock
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                // Keep the conn alive long enough for the inner handshake.
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
            });
            rx
        }

        let front_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind front");
        let front_port = front_listener.local_addr().expect("addr").port();
        let front_target = mock_socks5(front_listener).await;

        // `inner`'s server address is never bound — the point is that the dial
        // is routed to `front` instead, so nothing should ever connect to it.
        let inner_port = 59_999;

        let mut raw_front = raw_socks5_proxy("front", None, false);
        raw_front.insert(
            "port".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(front_port)),
        );
        let mut raw_inner = raw_socks5_proxy("inner", Some("front"), false);
        raw_inner.insert(
            "port".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(inner_port)),
        );

        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(
            SmolStr::from("front"),
            proxy_parser::parse_proxy(&raw_front, true).expect("parse front"),
        );
        proxies.insert(
            SmolStr::from("inner"),
            proxy_parser::parse_proxy(&raw_inner, true).expect("parse inner"),
        );

        // Keep the registry alive across the dial: `inner`'s front-hop target
        // resolves through it weakly (issue #533), so dropping it here would
        // fail the dial closed before `front` is ever contacted.
        let _dialer_registry =
            apply_chains(&mut proxies, &[raw_front, raw_inner]).expect("valid chain applies");

        // Dial a final target through `inner`; `inner` must reach its own
        // server (127.0.0.1:inner_port) *via* `front`.
        let meta = meow_common::Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let _ = proxies
            .get("inner")
            .expect("inner present")
            .dial_tcp(&meta)
            .await;

        let observed = tokio::time::timeout(std::time::Duration::from_secs(5), front_target)
            .await
            .expect("front proxy should have received a CONNECT")
            .expect("front proxy task should report the target");

        assert_eq!(
            observed,
            format!("127.0.0.1:{inner_port}"),
            "front must be asked to reach inner's *server*, not the final \
             target — otherwise the injected dialer was dropped"
        );
    }

    /// Issue #554 — a `dialer-proxy` member must share ONE health handle
    /// with its registry adapter. `apply_dialer_proxies` runs before group
    /// construction (issue #513), so the adapter a group captured is the
    /// same object `route.proxies` and `group.member_proxies()` serve the
    /// sweep and API probes. Marking the registry adapter dead must move
    /// the group's selection — a second `ProxyHealth` minted after group
    /// capture would leave the group reading a default-alive private
    /// handle while probes recorded results on the other.
    #[test]
    fn dialer_proxy_member_shares_health_with_group_selection() {
        let raw: raw::RawConfig = serde_yaml::from_str(
            r#"
proxies:
  - name: member
    type: socks5
    server: 127.0.0.1
    port: 1080
    dialer-proxy: front
  - name: front
    type: socks5
    server: 127.0.0.1
    port: 1081
  - name: spare
    type: socks5
    server: 127.0.0.1
    port: 1082
proxy-groups:
  - name: fb
    type: fallback
    proxies: [member, spare]
    url: "http://www.gstatic.com/generate_204"
rules:
  - MATCH,fb
"#,
        )
        .unwrap();
        let result = rebuild_from_raw(&raw).expect("dialer-proxy config must rebuild");
        let proxies = &result.proxies;
        let group = &proxies["fb"];
        let member = &proxies["member"];

        assert_eq!(group.current().as_deref(), Some("member"));
        // The API's delay endpoints probe `route.proxies["member"]` and
        // the periodic sweep resolves `group.member_proxies()` — both
        // must land on the same `ProxyHealth`, so marking the registry
        // adapter dead must move the group's selection either way.
        // Identity first: the group must have captured the registry's
        // entry itself, not a twin sharing a health handle by accident.
        assert!(
            Arc::ptr_eq(
                &proxies["member"],
                &group.member_proxies().expect("fallback exposes members")[0]
            ),
            "the group member and the registry adapter must be one Arc"
        );
        member.health().set_alive(false);
        assert_eq!(
            group.current().as_deref(),
            Some("spare"),
            "a dead registry adapter must stop being selected — a second \
             ProxyHealth minted after group capture would stay default-alive"
        );
    }
}

#[cfg(test)]
mod geoip_context_tests {
    use super::*;

    fn raw_with_rules(rules: Vec<&str>) -> raw::RawConfig {
        raw::RawConfig {
            rules: Some(
                rules
                    .into_iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn scanner_matches_geoip_rule() {
        assert!(line_references_geoip("GEOIP,CN,DIRECT"));
        assert!(line_references_geoip("  geoip,us,proxy,no-resolve"));
        // Nested inside a logic rule (issue #277: trigger must agree with
        // the allowlist collector, which walks into AND/OR/NOT).
        assert!(line_references_geoip(
            "AND,((GEOIP,CN),(DST-PORT,443)),PROXY"
        ));
        assert!(!line_references_geoip("DOMAIN,example.com,DIRECT"));
        assert!(!line_references_geoip("# GEOIP,CN,DIRECT"));
        assert!(!line_references_geoip(""));
        // Avoid false positives on rule types that happen to contain "GEO".
        assert!(!line_references_geoip("GEOSITE,twitter,Proxy"));
        // RULE-SET names containing "geoip" must not trigger the DB load.
        assert!(!line_references_geoip("RULE-SET,geoip-cn,DIRECT"));
    }

    #[test]
    fn collect_geoip_countries_picks_up_top_level_and_logic_rules() {
        let lines = vec![
            "GEOIP,CN,DIRECT".to_string(),
            "  src-geoip,us,Proxy".to_string(),
            "AND,((GEOIP,JP,Proxy),(DST-PORT,443,Proxy)),Proxy".to_string(),
            "DOMAIN,example.com,DIRECT".to_string(),
            "# GEOIP,XX,DIRECT".to_string(),
        ];
        let got = collect_geoip_countries(&lines);
        let want: std::collections::HashSet<String> = ["CN", "US", "JP"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(got, want);
    }

    /// Regression — many `GEOIP,CN,...` lines across top-level and logic
    /// rules must collapse to a single `"CN"` entry, so the downstream
    /// `CountryIndex::build` walks the MMDB once per *country*, not once per
    /// *rule*.
    #[test]
    fn collect_geoip_countries_deduplicates_repeats() {
        let mut lines = Vec::new();
        // 50 repeats each of CN/US/JP/TW, plus mixed-case and SRC-GEOIP.
        for i in 0..50 {
            lines.push(format!("GEOIP,CN,Proxy{i}"));
            lines.push(format!("geoip,us,Proxy{i}"));
            lines.push(format!("GEOIP,JP,Proxy{i}"));
            lines.push(format!("SRC-GEOIP,TW,Proxy{i}"));
            lines.push(format!(
                "AND,((GEOIP,CN,Proxy),(DST-PORT,443,Proxy)),Proxy{i}"
            ));
        }
        let got = collect_geoip_countries(&lines);
        let want: std::collections::HashSet<String> = ["CN", "US", "JP", "TW"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(
            got, want,
            "duplicate country rules must collapse to one entry per code"
        );
    }

    /// Issue #277 — geo keys referenced only inside `sub-rules:` blocks must
    /// be seen by the scan (both for the DB-load trigger and the allowlist).
    #[test]
    fn scan_lines_include_sub_rules_blocks() {
        let mut sub_rules = HashMap::new();
        sub_rules.insert(
            "my-sub".to_string(),
            vec![
                "GEOIP,JP,PROXY".to_string(),
                "IP-ASN,13335,DIRECT".to_string(),
            ],
        );
        let raw = raw::RawConfig {
            rules: Some(vec![
                "SUB-RULE,(DOMAIN-SUFFIX,example.com),my-sub".to_string()
            ]),
            sub_rules: Some(sub_rules),
            ..Default::default()
        };
        let lines = collect_geo_scan_lines(&raw, &HashMap::new());
        let countries = collect_geoip_countries(&lines);
        assert!(
            countries.contains("JP"),
            "sub-rules GEOIP,JP must be binned"
        );
        let asns = collect_asn_numbers(&lines);
        assert!(asns.contains(&13335), "sub-rules IP-ASN must be binned");
    }

    /// Issue #277 — geo keys referenced only in an inline rule-provider
    /// payload must be seen by the scan.
    #[test]
    fn scan_lines_include_inline_provider_payloads() {
        let mut providers = HashMap::new();
        providers.insert(
            "my-provider".to_string(),
            raw::RawRuleProvider {
                provider_type: "inline".to_string(),
                behavior: "classical".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                proxy: None,
                header: None,
                payload: Some(vec!["GEOIP,KR".to_string(), "GEOSITE,youtube".to_string()]),
            },
        );
        let raw = raw::RawConfig {
            rules: Some(vec!["RULE-SET,my-provider,PROXY".to_string()]),
            rule_providers: Some(providers),
            ..Default::default()
        };
        let lines = collect_geo_scan_lines(&raw, &HashMap::new());
        assert!(collect_geoip_countries(&lines).contains("KR"));
        assert!(collect_geosite_categories(&lines).contains("youtube"));
    }

    /// Issue #277 — prefetched file/http provider payload bytes are scanned
    /// (yaml and text forms); binary MRS payloads are skipped. Payloads
    /// keyed to providers the raw does not declare are ignored (issue
    /// #543).
    #[test]
    fn scan_lines_include_prefetched_provider_payloads() {
        let provider = || raw::RawRuleProvider {
            provider_type: "file".to_string(),
            behavior: "classical".to_string(),
            format: None,
            url: None,
            path: Some("/tmp/p.yaml".to_string()),
            interval: None,
            proxy: None,
            header: None,
            payload: None,
        };
        let raw = raw::RawConfig {
            rule_providers: Some(HashMap::from([
                ("yaml-provider".to_string(), provider()),
                ("text-provider".to_string(), provider()),
                ("mrs-provider".to_string(), provider()),
            ])),
            ..Default::default()
        };
        let mut payloads: rule_provider::PrefetchedPayloads = HashMap::new();
        payloads.insert(
            "yaml-provider".to_string(),
            b"payload:\n  - 'GEOIP,BR,no-resolve'\n  - DOMAIN,example.com\n".to_vec(),
        );
        payloads.insert(
            "text-provider".to_string(),
            b"# comment GEOIP,XX\nSRC-IP-ASN,15169\n".to_vec(),
        );
        payloads.insert(
            "mrs-provider".to_string(),
            meow_rules::mrs_parser::write_ruleset_mrs(
                meow_rules::mrs_parser::TYPE_DOMAIN,
                &["example.com"],
            )
            .unwrap(),
        );
        payloads.insert("undeclared".to_string(), b"GEOIP,FR\n".to_vec());
        let lines = collect_geo_scan_lines(&raw, &payloads);
        let countries = collect_geoip_countries(&lines);
        assert!(countries.contains("BR"), "yaml payload GEOIP must be seen");
        assert!(!countries.contains("XX"), "comment lines must be skipped");
        assert!(
            !countries.contains("FR"),
            "payloads for undeclared providers must be ignored"
        );
        assert!(collect_asn_numbers(&lines).contains(&15169));
    }

    /// Issue #277 — a GEOIP rule that appears only inside a sub-rules block
    /// must trigger the mmdb load (observable here as the fail-fast error for
    /// a missing DB, which names the triggering line).
    #[test]
    fn sub_rules_only_geoip_triggers_mmdb_load() {
        let mut sub_rules = HashMap::new();
        sub_rules.insert("my-sub".to_string(), vec!["GEOIP,JP,PROXY".to_string()]);
        let raw = raw::RawConfig {
            rules: Some(vec![
                "SUB-RULE,(DOMAIN-SUFFIX,example.com),my-sub".to_string()
            ]),
            sub_rules: Some(sub_rules),
            ..Default::default()
        };
        let nonexistent = PathBuf::from("/nonexistent-test-path-277/Country.mmdb");
        let err = build_parser_context_at(
            &raw,
            &nonexistent,
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .expect_err("sub-rules GEOIP must trigger the mmdb load");
        let msg = format!("{err}");
        assert!(msg.contains("/nonexistent-test-path-277/Country.mmdb"));
        assert!(
            msg.contains("GEOIP,JP,PROXY"),
            "error must name the sub-rule line that triggered the load: {msg}"
        );
    }

    #[test]
    fn collect_geoip_countries_ignores_geosite() {
        let lines = vec![
            "GEOSITE,cn,DIRECT".to_string(),
            "DOMAIN,example.com,DIRECT".to_string(),
        ];
        assert!(collect_geoip_countries(&lines).is_empty());
    }

    fn nonexistent_asn() -> PathBuf {
        PathBuf::from("/definitely/not/a/real/path/GeoLite2-ASN.mmdb")
    }

    fn nonexistent_geosite() -> Vec<PathBuf> {
        vec![PathBuf::from("/definitely/not/a/real/path/geosite.mrs")]
    }

    #[test]
    fn no_geoip_rules_skips_mmdb_load() {
        let raw = raw_with_rules(vec![
            "DOMAIN,example.com,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
        ]);
        // Point at a path guaranteed not to exist — should be ignored.
        let nonexistent = PathBuf::from("/definitely/not/a/real/path/Country.mmdb");
        let ctx = build_parser_context_at(
            &raw,
            &nonexistent,
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .unwrap();
        assert!(ctx.geoip.is_none());
        assert!(ctx.asn.is_none());
    }

    #[test]
    fn missing_mmdb_with_geoip_rule_errors_with_path_and_rule() {
        let raw = raw_with_rules(vec!["DOMAIN,example.com,DIRECT", "GEOIP,CN,DIRECT"]);
        let nonexistent = PathBuf::from("/nonexistent-test-path-42/Country.mmdb");
        let err = build_parser_context_at(
            &raw,
            &nonexistent,
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .expect_err("must fail-fast when mmdb is missing");
        let msg = format!("{err}");
        assert!(
            msg.contains("/nonexistent-test-path-42/Country.mmdb"),
            "error must name the attempted path: {msg}"
        );
        assert!(
            msg.contains("GEOIP,CN,DIRECT"),
            "error must name the triggering rule: {msg}"
        );
    }

    #[test]
    fn corrupt_mmdb_errors_at_parse_stage() {
        let raw = raw_with_rules(vec!["GEOIP,CN,DIRECT"]);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"not a real mmdb file").unwrap();
        let err = build_parser_context_at(
            &raw,
            tmp.path(),
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .expect_err("garbage bytes must fail to parse as mmdb");
        let msg = format!("{err}");
        assert!(msg.contains("GeoIP"), "error should mention GeoIP: {msg}");
    }

    #[test]
    fn scanner_matches_src_geoip_rule() {
        // SRC-GEOIP shares the GeoIP Country database.
        assert!(line_references_geoip("SRC-GEOIP,AU,DIRECT"));
        assert!(line_references_geoip("  src-geoip,us,proxy"));
    }

    #[test]
    fn scanner_matches_ip_asn_rule() {
        assert!(line_references_asn("IP-ASN,13335,PROXY"));
        assert!(line_references_asn("  src-ip-asn,15169,DIRECT"));
        assert!(!line_references_asn("DOMAIN,example.com,DIRECT"));
        assert!(!line_references_asn("# IP-ASN,13335,PROXY"));
        assert!(!line_references_asn("GEOIP,CN,DIRECT"));
    }

    #[test]
    fn no_asn_rules_skips_asn_mmdb_load() {
        let raw = raw_with_rules(vec!["DOMAIN,example.com,DIRECT"]);
        let nonexistent_geoip = PathBuf::from("/definitely/not/a/real/path/Country.mmdb");
        let ctx = build_parser_context_at(
            &raw,
            &nonexistent_geoip,
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .unwrap();
        assert!(ctx.asn.is_none());
    }

    /// Regression for meow-ios#112: YAML anchor merge keys (`<<: *anchor`)
    /// in `rule-providers` must expand before typed deserialisation, otherwise
    /// merged fields like `type` look missing and the import fails.
    #[test]
    fn parse_raw_yaml_expands_anchor_merge_keys() {
        let yaml = r"
rule-anchor:
  domain: &domain {type: http, interval: 86400, behavior: domain, format: mrs}

rule-providers:
  cn_domain: {<<: *domain, url: 'https://example.invalid/cn.mrs'}
";
        let raw = super::parse_raw_yaml(yaml).expect("merge keys must expand");
        let providers = raw.rule_providers.expect("rule-providers present");
        let cn = providers.get("cn_domain").expect("cn_domain entry");
        // After merge expansion the anchor's `type` and `behavior` fields are
        // materialised on the typed struct — without `apply_merge` these would
        // appear missing and deserialisation would fail with `missing field`.
        assert_eq!(cn.provider_type, "http");
        assert_eq!(cn.behavior, "domain");
        assert_eq!(cn.format.as_deref(), Some("mrs"));
        assert_eq!(cn.interval, Some(86400));
        assert_eq!(cn.url.as_deref(), Some("https://example.invalid/cn.mrs"));
    }

    #[test]
    fn provider_cache_dir_prefers_home_override() {
        let home = PathBuf::from("/tmp/meow-home");
        let got = super::resource_cache_dir_for_config_path_with_home(
            "/elsewhere/config.yaml",
            Some(home.clone()),
        );
        assert_eq!(got, home);
    }

    #[test]
    fn provider_cache_dir_uses_config_parent_without_home_override() {
        let got = super::resource_cache_dir_for_config_path_with_home("/tmp/cfg/config.yaml", None);
        assert_eq!(got, PathBuf::from("/tmp/cfg"));
    }

    #[test]
    fn provider_cache_dir_does_not_fall_back_to_cwd_for_bare_config_name() {
        let got = super::resource_cache_dir_for_config_path_with_home("config.yaml", None);
        assert_eq!(got, meow_common::xdg_home_dir());
        assert_ne!(got, PathBuf::from("."));
    }

    #[test]
    fn missing_asn_mmdb_with_ip_asn_rule_errors_with_path_and_rule() {
        let raw = raw_with_rules(vec!["IP-ASN,13335,PROXY"]);
        let nonexistent_geoip = PathBuf::from("/definitely/not/a/real/path/Country.mmdb");
        let asn = PathBuf::from("/nonexistent-test-path-asn/GeoLite2-ASN.mmdb");
        let err = build_parser_context_at(
            &raw,
            &nonexistent_geoip,
            &asn,
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .expect_err("must fail-fast when ASN mmdb is missing");
        let msg = format!("{err}");
        assert!(
            msg.contains(&asn.display().to_string()),
            "error must name the attempted path: {msg}"
        );
        assert!(
            msg.contains("IP-ASN,13335,PROXY"),
            "error must name the triggering rule: {msg}"
        );
    }
}

#[cfg(test)]
mod load_config_encoding_tests {
    use super::load_config;
    use std::io::Write;

    // Minimal config body that parse_raw_yaml accepts; load_config will still
    // fail downstream on missing fields, so we only care that the read+decode
    // step succeeds (i.e. the BOM was stripped and YAML parsing started).
    const MINIMAL_YAML: &str = "port: 7890\n";

    // `tag` must be unique per test: these tests run concurrently in one
    // process, and SystemTime's clock granularity is coarse enough that two
    // tests starting in the same tick collide on a pid+nanos-only name (one
    // test then reads the other's bytes — observed as a flaky failure).
    fn write_tmp(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("meow-cfg-{tag}-{pid}-{nanos}.yaml"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[tokio::test]
    async fn invalid_utf8_yields_actionable_error() {
        // 0xFF is never valid in UTF-8.
        let path = write_tmp("invalid-utf8", b"port: 7890\nrubbish: \xFF\xFE\n");
        let Err(err) = load_config(path.to_str().unwrap()).await else {
            panic!("non-UTF-8 config must fail");
        };
        let _ = std::fs::remove_file(&path);
        let msg = format!("{err}");
        assert!(
            msg.contains("not valid UTF-8"),
            "error must mention UTF-8: {msg}"
        );
        assert!(
            msg.contains(path.to_str().unwrap()),
            "error must include the config path: {msg}"
        );
    }

    #[tokio::test]
    async fn utf8_bom_is_stripped() {
        let mut bytes = b"\xEF\xBB\xBF".to_vec();
        bytes.extend_from_slice(MINIMAL_YAML.as_bytes());
        let path = write_tmp("bom", &bytes);
        // We don't assert success of full load_config (it requires more fields),
        // but the error — if any — must NOT be the UTF-8/BOM error path.
        let result = load_config(path.to_str().unwrap()).await;
        let _ = std::fs::remove_file(&path);
        if let Err(e) = result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("not valid UTF-8"),
                "BOM-prefixed UTF-8 must not trigger encoding error: {msg}"
            );
        }
    }
}

#[cfg(test)]
mod socket_address_tests {
    use super::parse_optional_socket_addr;

    #[test]
    fn configured_socket_addresses_are_validated() {
        assert_eq!(
            parse_optional_socket_addr("dns.listen", Some("127.0.0.1:53")).unwrap(),
            Some("127.0.0.1:53".parse().unwrap())
        );
        assert!(parse_optional_socket_addr("dns.listen", Some("localhost")).is_err());
        assert!(parse_optional_socket_addr("dns.listen", Some("127.0.0.1:70000")).is_err());
        assert!(parse_optional_socket_addr("external-controller", Some("[::1]:9090")).is_ok());
        assert_eq!(
            parse_optional_socket_addr("external-controller", Some(":9090")).unwrap(),
            Some("0.0.0.0:9090".parse().unwrap())
        );
        assert_eq!(
            parse_optional_socket_addr("dns.listen", Some("127.0.0.1:0")).unwrap(),
            Some("127.0.0.1:0".parse().unwrap())
        );
        assert_eq!(
            parse_optional_socket_addr("dns.listen", None).unwrap(),
            None
        );
    }
}

#[cfg(test)]
mod listener_bind_tests {
    use super::resolve_listener_bind;

    #[test]
    fn ip_literal_plus_port() {
        assert_eq!(
            resolve_listener_bind("127.0.0.1", Some(7890)).unwrap(),
            ("127.0.0.1".into(), 7890)
        );
        assert_eq!(
            resolve_listener_bind("0.0.0.0", None).unwrap(),
            ("0.0.0.0".into(), 0)
        );
        assert_eq!(
            resolve_listener_bind("::", Some(7890)).unwrap(),
            ("::".into(), 7890)
        );
    }

    #[test]
    fn host_port_ephemeral() {
        assert_eq!(
            resolve_listener_bind("127.0.0.1:0", None).unwrap(),
            ("127.0.0.1".into(), 0)
        );
        assert_eq!(
            resolve_listener_bind("[::1]:0", None).unwrap(),
            ("::1".into(), 0)
        );
    }

    #[test]
    fn host_port_explicit() {
        assert_eq!(
            resolve_listener_bind("0.0.0.0:7891", None).unwrap(),
            ("0.0.0.0".into(), 7891)
        );
        assert_eq!(
            resolve_listener_bind("127.0.0.1:7891", Some(7891)).unwrap(),
            ("127.0.0.1".into(), 7891)
        );
        // listen :0 + explicit port uses the port field
        assert_eq!(
            resolve_listener_bind("127.0.0.1:0", Some(7890)).unwrap(),
            ("127.0.0.1".into(), 7890)
        );
    }

    #[test]
    fn host_port_conflict_errors() {
        let err = resolve_listener_bind("127.0.0.1:7891", Some(7892)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("conflicts"), "msg: {msg}");
        assert!(msg.contains("7891"), "msg: {msg}");
        assert!(msg.contains("7892"), "msg: {msg}");
    }

    #[test]
    fn hostname_is_rejected() {
        let err = resolve_listener_bind("localhost:0", None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("invalid bind address"), "msg: {msg}");
    }
}

#[cfg(test)]
mod bind_address_tests {
    use super::load_config_from_str;

    // Regression tests for #388: mihomo/Clash Verge configs use
    // `bind-address: '*'` as the all-interfaces wildcard; feeding the raw
    // `*` to the listener's IpAddr parse was a fatal startup error.

    #[tokio::test]
    async fn wildcard_star_normalizes_to_unspecified_ipv4() {
        let config = load_config_from_str("mixed-port: 7890\nallow-lan: true\nbind-address: '*'\n")
            .await
            .expect("bind-address '*' must be accepted");
        assert_eq!(config.general.bind_address, "0.0.0.0");
        assert_eq!(config.listeners.bind_address, "0.0.0.0");
    }

    #[tokio::test]
    async fn empty_bind_address_normalizes_to_unspecified_ipv4() {
        let config = load_config_from_str("allow-lan: true\nbind-address: ''\n")
            .await
            .expect("empty bind-address must be accepted");
        assert_eq!(config.general.bind_address, "0.0.0.0");
    }

    #[tokio::test]
    async fn explicit_bind_address_is_preserved() {
        let config = load_config_from_str("allow-lan: true\nbind-address: '::'\n")
            .await
            .expect("explicit bind-address must load");
        assert_eq!(config.general.bind_address, "::");
    }

    #[tokio::test]
    async fn default_bind_address_is_loopback() {
        let config = load_config_from_str("mixed-port: 7890\n")
            .await
            .expect("minimal config must load");
        assert_eq!(config.general.bind_address, "127.0.0.1");
    }
}

#[cfg(test)]
mod async_guard_tests {
    // F1: compile-time guard — load_config_from_str must remain async.
    // This test body pins the future; if load_config_from_str is ever de-async-ified
    // the `Box::pin(...)` line below will fail to compile with a type error.
    #[allow(dead_code)] // intentional: compile-time guard, never called at runtime
    fn load_config_from_str_is_async_compile_check() {
        use std::future::Future;
        use std::pin::Pin;
        let _fut: Pin<Box<dyn Future<Output = _>>> = Box::pin(super::load_config_from_str(""));
    }
}

#[cfg(test)]
mod provider_path_safety_tests {
    //! Issue #429: rule-provider `path:` containment — a hostile config (e.g.
    //! via `PUT /configs`) must fail validation before any fetch or write.
    use super::*;

    #[test]
    fn rebuild_rejects_rule_provider_path_escaping_cache_dir() {
        let dir = tempfile::tempdir().unwrap();
        let raw: raw::RawConfig = serde_yaml::from_str(
            r#"
rule-providers:
  x:
    type: http
    behavior: domain
    format: yaml
    url: "http://127.0.0.1:1/payload"
    path: "/etc/cron.d/pwned"
rules:
  - "MATCH,DIRECT"
"#,
        )
        .unwrap();
        let Err(err) = rebuild_from_raw_with_cache_dir(&raw, Some(dir.path()), None) else {
            panic!("escaping rule-provider path must fail the rebuild");
        };
        assert!(err.to_string().contains("escapes"), "unexpected: {err}");
    }

    #[test]
    fn rebuild_rejects_proxy_provider_path_escaping_cache_dir() {
        // PR #444 review follow-up: proxy-provider containment violations
        // fail the rebuild loudly (rule-provider parity) instead of the
        // provider being warn-skipped and its groups silently degrading.
        let dir = tempfile::tempdir().unwrap();
        let raw: raw::RawConfig = serde_yaml::from_str(
            r#"
proxy-providers:
  evil:
    type: http
    url: "http://127.0.0.1:1/proxies.yaml"
    path: "/etc/cron.d/pwned"
proxy-groups:
  - name: g
    type: select
    use: [evil]
rules:
  - "MATCH,DIRECT"
"#,
        )
        .unwrap();
        let Err(err) = rebuild_from_raw_with_cache_dir(&raw, Some(dir.path()), None) else {
            panic!("escaping proxy-provider path must fail the rebuild");
        };
        let msg = err.to_string();
        assert!(msg.contains("evil"), "must name the provider: {msg}");
        assert!(msg.contains("escapes"), "unexpected: {msg}");
    }

    #[test]
    fn rebuild_rejects_file_provider_path_without_cache_dir() {
        // `rebuild_from_raw` is the genuinely rootless `cache_dir = None`
        // path (FFI callers with no on-disk config, plain unit tests, …).
        // Trusted daemon rebuilds — subscription refresh, geodata rebuild,
        // and `PUT /configs` via `rebuild_from_raw_runtime` — always thread
        // the real startup provider-cache dir through instead (issue #429
        // follow-up), so they hit the `Some(cache_dir)` path below, not
        // this one.
        //
        // Here there is no containment root at all, so a caller-named file
        // path is a hard error.
        let raw: raw::RawConfig = serde_yaml::from_str(
            r#"
rule-providers:
  x:
    type: file
    behavior: domain
    path: "/etc/passwd"
rules:
  - "MATCH,DIRECT"
"#,
        )
        .unwrap();
        let Err(err) = rebuild_from_raw(&raw) else {
            panic!("file provider path without a cache dir must fail the rebuild");
        };
        assert!(
            err.to_string().contains("cache directory"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn trusted_runtime_rebuilds_keep_working_with_a_file_rule_provider() {
        // Regression for the PR #444 review finding: a config with a plain
        // file rule-provider (the repo's own
        // `test_file_rule_provider_end_to_end` shape) loads fine at startup
        // and must keep rebuilding fine on every trusted runtime path —
        // subscription refresh, geodata rebuild, and the `PUT /configs`
        // family — once the real cache dir is threaded through instead of
        // `None`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("ads.yaml"),
            "payload:\n  - '+.ads.example'\n",
        )
        .unwrap();
        let raw: raw::RawConfig = serde_yaml::from_str(
            r#"
rule-providers:
  ads:
    type: file
    behavior: domain
    format: yaml
    path: ads.yaml
rules:
  - RULE-SET,ads,REJECT
  - "MATCH,DIRECT"
"#,
        )
        .unwrap();

        // `rebuild_from_raw_with_resolver` — used by geodata_fetch's
        // rules-only rebuilds.
        let result =
            rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
                .expect(
                    "trusted rebuild with the real cache dir must not hard-fail on a file provider",
                );
        assert_eq!(result.rules.len(), 2);

        // `rebuild_from_raw_runtime` — used by meow-api's `PUT /configs`
        // family via `rebuild_from_raw_runtime_async`.
        let result = rebuild_from_raw_runtime(
            &raw,
            None,
            &HashMap::new(),
            Some(dir.path()),
            &Default::default(),
        )
        .expect(
            "trusted runtime rebuild with the real cache dir must not hard-fail on a file provider",
        );
        assert_eq!(result.rules.len(), 2);
    }

    /// Issue #533 review: the live rule-provider registry must follow the
    /// committed build — a startup-era provider retained forever would keep
    /// downloading through its own pinned dialer-registry cell even after a
    /// `PUT /configs` rotated or removed the download proxy. The rebuild
    /// therefore RETURNS the candidate provider set on `RebuildResult`;
    /// committing callers swap it into the live registry only after every
    /// validation has passed, so a rejected build never mutates live state.
    #[test]
    fn rebuild_returns_the_candidate_rule_provider_set() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("ads.yaml"),
            "payload:\n  - '+.ads.example'\n",
        )
        .unwrap();
        let raw: raw::RawConfig = serde_yaml::from_str(
            r#"
rule-providers:
  ads:
    type: file
    behavior: domain
    format: yaml
    path: ads.yaml
rules:
  - RULE-SET,ads,REJECT
  - "MATCH,DIRECT"
"#,
        )
        .unwrap();
        let live: parking_lot::RwLock<HashMap<String, Arc<rule_provider::RuleProvider>>> =
            parking_lot::RwLock::new(HashMap::new());

        // Commit path: swap the returned set in after validation succeeds.
        let result =
            rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
                .expect("rebuild ok");
        *live.write() = result.rule_providers;
        assert!(live.read().contains_key("ads"));

        // A candidate that drops `rule-providers:` empties the registry.
        let raw_bare: raw::RawConfig =
            serde_yaml::from_str("rules:\n  - \"MATCH,DIRECT\"\n").unwrap();
        let result = rebuild_from_raw_with_resolver(
            &raw_bare,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .expect("rebuild ok");
        *live.write() = result.rule_providers;
        assert!(live.read().is_empty());

        // A failing build returns Err — the caller never commits, so the
        // live registry (seeded above via a good build) stays untouched.
        let raw_ok: raw::RawConfig = serde_yaml::from_str(
            "rule-providers:\n  ads:\n    type: file\n    behavior: domain\n    format: yaml\n    path: ads.yaml\nrules:\n  - RULE-SET,ads,REJECT\n  - \"MATCH,DIRECT\"\n",
        )
        .unwrap();
        let result =
            rebuild_from_raw_with_resolver(&raw_ok, None, Some(dir.path()), &HashMap::new(), None)
                .expect("rebuild ok");
        *live.write() = result.rule_providers;
        let raw_bad: raw::RawConfig =
            serde_yaml::from_str("rules:\n  - SUB-RULE,(MATCH,DIRECT),missing\n").unwrap();
        assert!(rebuild_from_raw_with_resolver(
            &raw_bad,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None
        )
        .is_err());
        assert!(
            live.read().contains_key("ads"),
            "a failed rebuild must leave the live provider registry untouched"
        );
    }

    /// The published provider map must be the *same generation* the
    /// RULE-SET matchers hold — a separately loaded copy would diverge on
    /// refresh (issue #543). Matchers retain the provider itself as their
    /// `Arc<dyn RuleSet>` (issue #553 live read-through), so the identity
    /// check is against the provider object, not a snapshot.
    #[test]
    fn rebuild_result_rule_providers_match_the_matcher_generation() {
        let raw: raw::RawConfig = serde_yaml::from_str(
            r#"
rule-providers:
  doms:
    type: inline
    behavior: domain
    payload:
      - '+.example.com'
rules:
  - RULE-SET,doms,REJECT
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let result = rebuild_from_raw(&raw).expect("inline rule-provider must rebuild");
        assert!(result.rule_providers.contains_key("doms"));

        let ruleset_rule = result
            .rules
            .iter()
            .find_map(|r| {
                r.as_any()
                    .and_then(|a| a.downcast_ref::<meow_rules::RuleSetRule>())
            })
            .expect("RULE-SET,doms must produce a RuleSetRule");
        let provider = Arc::clone(&result.rule_providers["doms"]);
        let provider: Arc<dyn meow_rules::RuleSet> = provider;
        assert!(
            Arc::ptr_eq(ruleset_rule.rule_set(), &provider),
            "the published provider must be the instance the matcher holds"
        );
    }

    #[test]
    fn rebuild_rejects_traversal_in_rule_provider_path() {
        let dir = tempfile::tempdir().unwrap();
        let raw: raw::RawConfig = serde_yaml::from_str(
            r#"
rule-providers:
  x:
    type: http
    behavior: domain
    url: "http://127.0.0.1:1/payload"
    path: "../../outside.yaml"
"#,
        )
        .unwrap();
        let Err(err) = rebuild_from_raw_with_cache_dir(&raw, Some(dir.path()), None) else {
            panic!("`..` traversal in rule-provider path must fail the rebuild");
        };
        assert!(err.to_string().contains("escapes"), "unexpected: {err}");
    }
}

#[cfg(test)]
mod strict_mode_tests {
    //! Issue #533: top-level `strict: true` turns warn-skipped entries —
    //! unparseable `proxies:`/`proxy-groups:`/`rules:` items, a bad
    //! `proxy-providers:` definition, and bad nodes inside a provider
    //! payload — into hard config errors.
    use super::*;

    fn raw_config(yaml: &str) -> raw::RawConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    const BASE: &str = r#"
strict: {STRICT}
proxies:
  - { name: ok, type: direct }
  - { name: broken, type: nosuchtype }
proxy-groups:
  - { name: g-ok, type: select, proxies: [ok] }
  - { name: g-broken, type: nosuchgrouptype, proxies: [ok] }
rules:
  - "MATCH,DIRECT"
  - "NOSUCHRULE,x,DIRECT"
"#;

    fn build(yaml: &str) -> Result<RebuildResult, anyhow::Error> {
        let raw = raw_config(&yaml.replace("{STRICT}", "true"));
        rebuild_from_raw(&raw)
    }

    fn expect_strict_failure(yaml: &str, ctx: &str) -> anyhow::Error {
        let Err(e) = build(yaml) else {
            panic!("strict must reject {ctx}");
        };
        e
    }

    #[test]
    fn strict_rejects_unparseable_proxy_entry() {
        let yaml = BASE
            .replace(
                "  - { name: g-broken, type: nosuchgrouptype, proxies: [ok] }\n",
                "",
            )
            .replace("  - \"NOSUCHRULE,x,DIRECT\"\n", "");
        let err = expect_strict_failure(&yaml, "a bad proxies: entry");
        assert!(err.to_string().contains("broken"), "unexpected: {err}");
    }

    #[test]
    fn strict_rejects_unparseable_proxy_group() {
        let yaml = BASE
            .replace("  - { name: broken, type: nosuchtype }\n", "")
            .replace("  - \"NOSUCHRULE,x,DIRECT\"\n", "");
        let err = expect_strict_failure(&yaml, "a bad proxy-groups: entry");
        assert!(err.to_string().contains("g-broken"), "unexpected: {err}");
    }

    #[test]
    fn strict_rejects_unparseable_rule() {
        let yaml = BASE
            .replace("  - { name: broken, type: nosuchtype }\n", "")
            .replace(
                "  - { name: g-broken, type: nosuchgrouptype, proxies: [ok] }\n",
                "",
            );
        let err = expect_strict_failure(&yaml, "a bad rules: entry");
        assert!(err.to_string().contains("NOSUCHRULE"), "unexpected: {err}");
    }

    #[test]
    fn lenient_still_skips_unparseable_entries() {
        let raw = raw_config(&BASE.replace("{STRICT}", "false"));
        let RebuildResult { proxies, rules, .. } =
            rebuild_from_raw(&raw).expect("lenient mode must tolerate bad entries");
        assert!(proxies.contains_key("ok"));
        assert!(!proxies.contains_key("broken"));
        assert!(proxies.contains_key("g-ok"));
        assert!(!proxies.contains_key("g-broken"));
        assert_eq!(rules.len(), 1);
    }

    #[tokio::test]
    async fn strict_rejects_bad_proxy_provider_definition() {
        let yaml = r#"
proxy-providers:
  bad:
    type: bogusvehicle
"#;
        let raw = raw_config(yaml);
        let result = proxy_provider::load_proxy_providers(
            raw.proxy_providers.as_ref().unwrap(),
            None,
            false,
            true,
            &Default::default(),
        )
        .await;
        let Err(err) = result else {
            panic!("strict must reject a bad proxy-providers: entry");
        };
        assert!(err.to_string().contains("bad"), "unexpected: {err}");

        // Lenient keeps the provider map empty instead of failing.
        let raw = raw_config(yaml);
        let map = proxy_provider::load_proxy_providers(
            raw.proxy_providers.as_ref().unwrap(),
            None,
            false,
            false,
            &Default::default(),
        )
        .await
        .expect("lenient load never errors");
        assert!(map.is_empty());
    }

    #[tokio::test]
    async fn strict_rejects_unparseable_provider_node() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            r#"proxies:
  - { name: ok, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: x }
  - { name: broken, type: nosuchtype }
"#,
        )
        .unwrap();
        let yaml = format!(
            r#"
proxy-providers:
  airport:
    type: file
    path: '{}'
"#,
            dir.path().join("nodes.yaml").display()
        );
        let raw = raw_config(&yaml);
        let result = proxy_provider::load_proxy_providers(
            raw.proxy_providers.as_ref().unwrap(),
            Some(dir.path()),
            false,
            true,
            &Default::default(),
        )
        .await;
        let Err(err) = result else {
            panic!("strict must reject a bad node inside a provider payload");
        };
        assert!(err.to_string().contains("broken"), "unexpected: {err}");

        // Lenient keeps the parseable node and drops the broken one.
        let map = proxy_provider::load_proxy_providers(
            raw.proxy_providers.as_ref().unwrap(),
            Some(dir.path()),
            false,
            false,
            &Default::default(),
        )
        .await
        .expect("lenient load never errors");
        let provider = map.get("airport").expect("provider must still load");
        let proxies = provider.proxies();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].name(), "ok");
    }

    #[test]
    fn strict_rejects_group_with_missing_member() {
        let yaml = r#"
strict: {STRICT}
proxies:
  - { name: ok, type: direct }
proxy-groups:
  - { name: g, type: select, proxies: [ok, typo] }
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "a group with a missing member");
        assert!(err.to_string().contains("typo"), "unexpected: {err}");

        // Lenient builds the group with the resolvable members only.
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw).expect("lenient mode must tolerate a missing member");
        assert!(proxies.contains_key("g"));
    }

    #[test]
    fn strict_rejects_group_with_unknown_use_provider() {
        let yaml = r#"
strict: {STRICT}
proxies:
  - { name: ok, type: direct }
proxy-groups:
  - { name: g, type: select, proxies: [ok], use: [missing-provider] }
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "a group with an unknown use: provider");
        assert!(
            err.to_string().contains("missing-provider"),
            "unexpected: {err}"
        );

        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw).expect("lenient mode must tolerate a missing use: provider");
        assert!(proxies.contains_key("g"));
    }

    #[test]
    fn strict_rejects_forward_group_reference_that_dead_ends() {
        // `dep` has an unresolvable member; `dependent` is declared first and
        // forwards to it. Under strict both must be reported — the dependent's
        // error names the failed dep, not a phantom.
        let yaml = r#"
strict: {STRICT}
proxies:
  - { name: ok, type: direct }
proxy-groups:
  - { name: dependent, type: select, proxies: [dep] }
  - { name: dep, type: select, proxies: [ok, typo] }
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "a broken group dependency chain");
        let msg = err.to_string();
        assert!(msg.contains("typo"), "unexpected: {err}");
        assert!(msg.contains("dep"), "unexpected: {err}");

        // Lenient still resolves the chain by skipping the bad member.
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw).expect("lenient mode must resolve the chain");
        assert!(proxies.contains_key("dependent"));
        assert!(proxies.contains_key("dep"));
    }

    #[test]
    fn strict_rejects_builtin_shadowing_entry() {
        let yaml = r#"
strict: {STRICT}
proxies:
  - { name: DIRECT, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: x }
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "a proxies: entry shadowing a built-in");
        assert!(err.to_string().contains("DIRECT"), "unexpected: {err}");

        // Lenient drops the entry and keeps the built-in.
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw).expect("lenient mode must tolerate a shadowing entry");
        assert_eq!(
            proxies.get("DIRECT").unwrap().adapter_type(),
            meow_common::AdapterType::Direct
        );
    }

    #[tokio::test]
    async fn strict_rejects_malformed_dialer_proxy() {
        let yaml = r#"
strict: {STRICT}
proxies:
  - { name: front, type: direct }
  - { name: leaf, type: socks5, server: 127.0.0.1, port: 1080, dialer-proxy: 123 }
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "a malformed dialer-proxy value");
        assert!(
            err.to_string().contains("dialer-proxy"),
            "unexpected: {err}"
        );

        // Lenient keeps the node but binds it to a sentinel target that
        // never resolves — the malformed edge can no longer silently
        // degrade the leaf to a direct dial (mihomo's shape too: the node
        // loads and its dial fails "not found").
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw).expect("lenient mode must tolerate a malformed dialer-proxy");
        let leaf = proxies
            .get("leaf")
            .expect("node must be kept in lenient mode");
        let Err(err) = leaf.dial_tcp(&meow_common::Metadata::default()).await else {
            panic!("a malformed dialer-proxy must fail at dial time, not dial direct");
        };
        assert!(
            err.to_string().contains("__malformed_dialer_proxy__leaf"),
            "unexpected: {err}"
        );
    }

    /// A `dialer-proxy` on an adapter that cannot carry an injected dialer
    /// (`direct`, `anytls`, `hysteria2`, SS + external SIP003) fails the
    /// by-name re-parse. Lenient falls back to the relay-based
    /// `DialerProxyAdapter` wrapper; strict surfaces the defect at load
    /// (issue #533 review).
    #[test]
    fn strict_rejects_uninjectable_dialer_reparse() {
        let yaml = r#"
strict: {STRICT}
proxies:
  - { name: front, type: direct }
  - { name: leaf, type: direct, dialer-proxy: front }
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "a dialer-proxy on an uninjectable adapter type");
        assert!(err.to_string().contains("leaf"), "unexpected: {err}");
        assert!(
            err.to_string().contains("dialer-proxy"),
            "unexpected: {err}"
        );

        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw).expect("lenient falls back to the relay-based wrapper");
        assert!(proxies.contains_key("leaf"));
    }

    #[test]
    fn shadowed_dialer_edge_does_not_wrap_builtin() {
        // A leaf named DIRECT is dropped for shadowing; its `dialer-proxy`
        // edge must be skipped too — otherwise the *built-in* DIRECT gets
        // wrapped/re-parsed and global direct traffic is chained through the
        // shadowed node's dialer.
        let yaml = r#"
strict: false
proxies:
  - { name: front, type: direct }
  - { name: DIRECT, type: socks5, server: 127.0.0.1, port: 1080, dialer-proxy: front }
rules:
  - "MATCH,DIRECT"
"#;
        let raw = raw_config(yaml);
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw).expect("lenient build must succeed");
        // If the shadowed entry's edge were collected, `DIRECT` would be
        // re-parsed as the entry's real type (Socks5) with the dialer
        // injected — the built-in must instead stay the Direct adapter.
        assert_eq!(
            proxies
                .get("DIRECT")
                .expect("built-in DIRECT present")
                .adapter_type(),
            meow_common::AdapterType::Direct
        );
    }

    #[tokio::test]
    async fn strict_fetch_failure_stays_lenient() {
        // A `file` provider whose path does not exist is an acquisition
        // failure, not a parse defect: strict mode still starts it empty.
        let dir = tempfile::tempdir().unwrap();
        let yaml = format!(
            r#"
proxy-providers:
  gone:
    type: file
    path: '{}'
"#,
            dir.path().join("missing.yaml").display()
        );
        let raw = raw_config(&yaml);
        let map = proxy_provider::load_proxy_providers(
            raw.proxy_providers.as_ref().unwrap(),
            Some(dir.path()),
            false,
            true,
            &Default::default(),
        )
        .await
        .expect("an unfetchable provider must stay lenient even under strict");
        let provider = map.get("gone").expect("provider must be registered");
        assert!(provider.proxies().is_empty());
    }

    #[test]
    fn strict_rejects_bad_rule_provider_definition() {
        let yaml = r#"
strict: {STRICT}
rule-providers:
  bad:
    type: bogusvehicle
    behavior: domain
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "a bad rule-providers: entry");
        assert!(err.to_string().contains("bad"), "unexpected: {err}");

        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        rebuild_from_raw(&raw).expect("lenient mode must tolerate a bad rule-provider");
    }

    /// Issue #533 review: a `PUT /configs` candidate that DECLARES a new
    /// provider must satisfy `use:` under strict — the live registry is not
    /// the authority, the candidate's own `proxy-providers:` section is.
    #[test]
    fn strict_use_resolves_candidate_declared_provider() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.yaml"), "proxies: []\n").unwrap();
        let yaml = r#"
strict: true
proxy-providers:
  airport:
    type: file
    path: nodes.yaml
proxy-groups:
  - { name: g, type: select, use: [airport] }
rules:
  - "MATCH,DIRECT"
"#;
        let raw = raw_config(yaml);
        // Empty live map — the declaration itself must authorize `use:`.
        let result =
            rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
                .expect("strict must accept use: of a candidate-declared provider");
        assert!(result.proxies.contains_key("g"));
        assert!(result.proxy_providers.contains_key("airport"));
    }

    /// The mirror image: a candidate that DROPS a provider declaration must
    /// fail `use:` under strict even while the live registry still holds the
    /// object — otherwise the removal would zombie-bind for one generation.
    #[test]
    fn strict_use_fails_when_candidate_removes_provider() {
        let live_def: raw::RawProxyProvider =
            serde_yaml::from_str("type: http\nurl: http://127.0.0.1:1/x.yaml").unwrap();
        let live_provider =
            ProxyProvider::new("airport", &live_def, None, false, false, Default::default())
                .unwrap();
        let live: HashMap<String, Arc<ProxyProvider>> =
            HashMap::from([("airport".to_string(), Arc::new(live_provider))]);

        let yaml = r#"
strict: {STRICT}
proxies:
  - { name: ok, type: direct }
proxy-groups:
  - { name: g, type: select, proxies: [ok], use: [airport] }
rules:
  - "MATCH,DIRECT"
"#;
        let raw = raw_config(&yaml.replace("{STRICT}", "true"));
        let Err(err) = rebuild_from_raw_with_resolver(&raw, None, None, &live, None) else {
            panic!("use: of a removed provider must fail strict");
        };
        assert!(err.to_string().contains("airport"), "unexpected: {err}");

        // Lenient keeps the group — the zombie Arc is not consulted.
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let result = rebuild_from_raw_with_resolver(&raw, None, None, &live, None)
            .expect("lenient mode must tolerate the removal");
        assert!(result.proxies.contains_key("g"));
        assert!(
            result.proxy_providers.is_empty(),
            "the candidate must not resurrect an undeclared provider"
        );
    }

    /// A malformed `proxy-providers:` def in a CANDIDATE is a strict defect
    /// even when nothing references it — committing it would fail the next
    /// startup, so the rebuild must fail now.
    #[test]
    fn strict_rejects_malformed_candidate_provider_def() {
        let yaml = r#"
strict: {STRICT}
proxy-providers:
  bad:
    type: bogusvehicle
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "a malformed proxy-providers def");
        assert!(err.to_string().contains("bad"), "unexpected: {err}");

        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let result = rebuild_from_raw(&raw).expect("lenient mode must skip a bad provider def");
        assert!(result.proxy_providers.is_empty());
    }

    /// `use:` is never consulted under `include-all*` — an unknown name in
    /// the ignored list must not fail strict (issue #533 review).
    #[test]
    fn strict_tolerates_unknown_use_when_include_all_supplies_members() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.yaml"), "proxies: []\n").unwrap();
        for flag in ["include-all: true", "include-all-providers: true"] {
            let yaml = format!(
                r#"
strict: true
proxy-providers:
  airport:
    type: file
    path: nodes.yaml
proxy-groups:
  - {{ name: g, type: select, use: [nonexistent], {flag} }}
rules:
  - "MATCH,DIRECT"
"#
            );
            let raw = raw_config(&yaml);
            rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
                .unwrap_or_else(|e| panic!("strict must ignore inert use: under {flag}: {e}"));
        }
    }

    /// `type: relay` chains only static `proxies:` members — provider slots
    /// are dropped with a warn — so an unknown `use:` name is inert there
    /// too (issue #533 review).
    #[test]
    fn strict_tolerates_unknown_use_on_relay_group() {
        let yaml = r#"
strict: true
proxies:
  - { name: a, type: direct }
  - { name: b, type: direct }
proxy-groups:
  - { name: r, type: relay, proxies: [a, b], use: [nonexistent] }
rules:
  - "MATCH,DIRECT"
"#;
        let raw = raw_config(yaml);
        rebuild_from_raw(&raw).expect("strict must ignore inert use: on a relay group");
    }

    /// A rule-provider whose payload can't be acquired is transient — the
    /// provider registers empty in BOTH modes so `RULE-SET` references
    /// resolve and a later refresh can heal it (issue #533 review).
    #[test]
    fn strict_rule_provider_acquisition_failure_registers_empty() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
strict: {STRICT}
rule-providers:
  remote:
    type: file
    behavior: domain
    format: yaml
    path: missing.yaml
rules:
  - RULE-SET,remote,REJECT
  - "MATCH,DIRECT"
"#;
        let raw = raw_config(&yaml.replace("{STRICT}", "true"));
        let result =
            rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
                .expect("strict must keep an unreadable provider as a known-empty set");
        assert!(result.rule_providers.contains_key("remote"));
        assert_eq!(
            result.rules.len(),
            2,
            "RULE-SET must resolve to the empty set"
        );
    }

    /// An unparseable provider `url:` is a permanent defect, not a
    /// transient acquisition failure — under strict it fails the definition
    /// rather than registering an empty provider that retries the same bad
    /// URL on every interval (issue #533 review).
    #[test]
    fn strict_rejects_invalid_provider_url() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
strict: {STRICT}
proxy-providers:
  bad-proxy:
    type: http
    url: 'not a url'
rule-providers:
  bad-rule:
    type: http
    behavior: domain
    url: 'not a url'
"#;
        let raw = raw_config(&yaml.replace("{STRICT}", "true"));
        let Err(err) =
            rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
        else {
            panic!("strict must reject an unparseable provider url");
        };
        assert!(err.to_string().contains("url"), "unexpected: {err}");

        // Lenient keeps the acquisition-failure contract: the bad URL is a
        // fetch-time error → empty registered provider.
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
            .expect("lenient registers an empty provider on bad url");
    }

    /// A bad `format:` is a DEFECT in the definition, not an acquisition
    /// failure — strict rejects it even though no bytes were ever fetched.
    #[test]
    fn strict_rejects_bad_rule_provider_format() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("r.yaml"), "payload: []\n").unwrap();
        let yaml = r#"
strict: {STRICT}
rule-providers:
  bad:
    type: file
    behavior: domain
    format: bogus
    path: r.yaml
rules:
  - "MATCH,DIRECT"
"#;
        let raw = raw_config(&yaml.replace("{STRICT}", "true"));
        let Err(err) =
            rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
        else {
            panic!("a bogus format: is a defect — strict must reject");
        };
        assert!(err.to_string().contains("bad"), "unexpected: {err}");
    }

    /// A malformed line inside a provider payload fails strict instead of
    /// silently installing a partial set; lenient keeps the good lines.
    #[test]
    fn strict_rejects_malformed_rule_provider_payload_line() {
        let dir = tempfile::tempdir().unwrap();
        // A non-string `payload:` item is dropped leniently (mihomo parity)
        // but is a malformed payload under strict.
        std::fs::write(
            dir.path().join("mixed.yaml"),
            "payload:\n  - example.com\n  - 123\n",
        )
        .unwrap();
        let yaml = r#"
strict: {STRICT}
rule-providers:
  mixed:
    type: file
    behavior: domain
    format: yaml
    path: mixed.yaml
rules:
  - RULE-SET,mixed,REJECT
  - "MATCH,DIRECT"
"#;
        let raw = raw_config(&yaml.replace("{STRICT}", "true"));
        if rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
            .is_ok()
        {
            panic!("strict must reject a non-string payload item");
        }

        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let result =
            rebuild_from_raw_with_resolver(&raw, None, Some(dir.path()), &HashMap::new(), None)
                .expect("lenient drops the non-string item and keeps the provider");
        assert!(result.rule_providers.contains_key("mixed"));
    }

    /// A `file` rule-provider without `path:` must name the missing field —
    /// not an implicit name-derived location the user never wrote.
    #[test]
    fn file_rule_provider_without_path_names_the_field() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
rule-providers:
  p:
    type: file
    behavior: domain
    format: yaml
"#;
        let raw = raw_config(yaml);
        let providers = raw.rule_providers.as_ref().unwrap();
        let ctx = meow_rules::ParserContext::empty();
        let err = rule_provider::load_providers(providers, Some(dir.path()), &ctx, None, true)
            .map(|_| ())
            .expect_err("strict must reject a file provider without path");
        assert!(
            err.to_string().contains("requires a 'path'"),
            "unexpected: {err}"
        );
    }

    /// `set_strict` follows the committed generation: a provider built
    /// leniently must honor strict parsing after the flag flips — and a
    /// torn payload must keep the last-good slot contents (issue #533
    /// review).
    #[tokio::test]
    async fn provider_strict_flag_governs_refresh_parsing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - { name: ok, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: x }\n  - { name: broken, type: nosuchtype }\n",
        )
        .unwrap();
        let def: raw::RawProxyProvider = serde_yaml::from_str(&format!(
            "type: file\npath: '{}'",
            dir.path().join("nodes.yaml").display()
        ))
        .unwrap();
        let provider = ProxyProvider::new(
            "p",
            &def,
            Some(dir.path()),
            false,
            false,
            Default::default(),
        )
        .unwrap();

        // Lenient refresh: bad node skipped, good node lands.
        provider
            .refresh()
            .await
            .expect("lenient refresh tolerates a bad node");
        assert_eq!(provider.proxies().len(), 1);

        // Strict generation: the same payload now fails the refresh and the
        // last-good set is retained.
        provider.set_strict(true);
        provider
            .refresh()
            .await
            .expect_err("strict refresh must reject a bad node");
        assert_eq!(provider.proxies().len(), 1, "torn refresh keeps last-good");

        provider.set_strict(false);
        provider.refresh().await.expect("lenient again");
    }

    /// A group named the same as a `proxies:` leaf silently overwrites it —
    /// every reference then resolves to the group, not the leaf. The
    /// declaration-level check rejects the collision in both modes
    /// (issues #533, #561).
    #[test]
    fn strict_rejects_group_leaf_name_collision() {
        let yaml = r#"
strict: {STRICT}
proxies:
  - { name: dup, type: direct }
proxy-groups:
  - { name: dup, type: select, proxies: [DIRECT] }
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "a group shadowing a proxies: leaf");
        assert!(err.to_string().contains("'dup'"), "unexpected: {err}");

        // Lenient rejects too since #561 — a group shadowing a leaf makes
        // every reference resolve ambiguously in both modes.
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        match rebuild_from_raw(&raw) {
            Err(err) => assert!(err.to_string().contains("'dup'"), "unexpected: {err}"),
            Ok(_) => panic!("lenient also rejects a group shadowing a leaf"),
        }
    }

    /// `ech-opts.enable: true` with no `config:`, no `query-server-name:`,
    /// and no `server:` is a defect — strict turns it into an error while
    /// lenient just skips ECH (issue #533 review).
    #[tokio::test]
    async fn strict_rejects_ech_enable_with_no_query_source() {
        let mut proxies = vec![serde_yaml::from_str::<HashMap<String, serde_yaml::Value>>(
            "{ name: p, type: ss, ech-opts: { enable: true } }",
        )
        .unwrap()];
        let err = ech_dns::preresolve_ech(&mut proxies, true)
            .await
            .expect_err("strict must reject enable:true with no query source");
        assert!(err.contains("p"), "unexpected: {err}");

        let mut proxies = vec![serde_yaml::from_str::<HashMap<String, serde_yaml::Value>>(
            "{ name: p, type: ss, ech-opts: { enable: true } }",
        )
        .unwrap()];
        ech_dns::preresolve_ech(&mut proxies, false)
            .await
            .expect("lenient skips ECH silently");
    }

    /// Two groups with the same name: both decls build, but a dependent
    /// declared between them captures the first object while the committed
    /// map holds the second — a silent divergence (issue #533 review).
    #[test]
    fn strict_rejects_duplicate_group_name() {
        let yaml = r#"
strict: {STRICT}
proxies:
  - { name: ok, type: direct }
proxy-groups:
  - { name: dup, type: select, proxies: [ok] }
  - { name: mid, type: select, proxies: [dup] }
  - { name: dup, type: select, proxies: [ok, DIRECT] }
rules:
  - "MATCH,DIRECT"
"#;
        let err = expect_strict_failure(yaml, "duplicate group names");
        assert!(err.to_string().contains("'dup'"), "unexpected: {err}");

        // Lenient rejects too — upstream has no lenient mode for this and
        // the multi-pass capture makes duplicates ambiguous in both modes
        // (a parent may hold a different instance than the registry).
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        match rebuild_from_raw(&raw) {
            Err(err) => assert!(err.to_string().contains("'dup'"), "unexpected: {err}"),
            Ok(_) => panic!("lenient also rejects duplicates"),
        }
    }

    /// A re-declared provider whose definition changed must NOT reuse the
    /// live object — it would keep fetching the old source forever while the
    /// committed config claims otherwise (issue #533 review).
    #[test]
    fn provider_def_change_rebuilds_instead_of_reusing() {
        let yaml = r#"
strict: false
proxy-providers:
  p:
    type: file
    path: nodes.yaml
proxies:
  - { name: ok, type: direct }
rules:
  - "MATCH,DIRECT"
"#;
        let cache_dir = std::path::Path::new("/tmp");
        let raw = raw_config(yaml);
        let first = materialize_proxy_providers(
            &raw,
            &HashMap::new(),
            Some(cache_dir),
            false,
            &Default::default(),
        )
        .expect("provider materializes");
        let provider = Arc::clone(first.get("p").unwrap());

        // Unchanged def → same Arc reused.
        let again =
            materialize_proxy_providers(&raw, &first, Some(cache_dir), false, &Default::default())
                .expect("reuse");
        assert!(Arc::ptr_eq(again.get("p").unwrap(), &provider));

        // Changed def (filter added) → a new object materializes.
        let changed_yaml = yaml.replace("path: nodes.yaml", "path: nodes.yaml\n    filter: '^ok'");
        let changed_raw = raw_config(&changed_yaml);
        let rebuilt = materialize_proxy_providers(
            &changed_raw,
            &first,
            Some(cache_dir),
            false,
            &Default::default(),
        )
        .expect("changed def materializes fresh");
        assert!(
            !Arc::ptr_eq(rebuilt.get("p").unwrap(), &provider),
            "a changed provider def must not reuse the live object"
        );
    }

    /// `interval` is excluded from provider identity — it configures the
    /// refresh *schedule*, not the payload source. An interval-only
    /// `PUT /configs` must reuse the live provider (no refetch); the
    /// supervisor respawns the task from the committed declarations
    /// (issue #625). A regression that re-added `interval` to
    /// `def_identity` would silently refetch on every interval change.
    #[test]
    fn provider_interval_only_change_reuses_provider() {
        let yaml = r#"
strict: false
proxy-providers:
  p:
    type: file
    path: nodes.yaml
    interval: 60
proxies:
  - { name: ok, type: direct }
rules:
  - "MATCH,DIRECT"
"#;
        let cache_dir = std::path::Path::new("/tmp");
        let raw = raw_config(yaml);
        let first = materialize_proxy_providers(
            &raw,
            &HashMap::new(),
            Some(cache_dir),
            false,
            &Default::default(),
        )
        .expect("provider materializes");
        let provider = Arc::clone(first.get("p").unwrap());

        let changed = raw_config(&yaml.replace("interval: 60", "interval: 120"));
        let again = materialize_proxy_providers(
            &changed,
            &first,
            Some(cache_dir),
            false,
            &Default::default(),
        )
        .expect("interval-only change must reuse the provider");
        assert!(
            Arc::ptr_eq(again.get("p").unwrap(), &provider),
            "interval is a schedule knob, not provider identity"
        );
    }

    /// A malformed `proxy-groups`/`rules`/`proxies` section in a fetched
    /// subscription is remote-controlled content — under strict it fails the
    /// fetch instead of silently emptying the committed lists (issue #533
    /// review).
    #[test]
    fn strict_rejects_malformed_subscription_shape() {
        let bad_groups =
            "proxies:\n  - {name: ok, type: direct}\nproxy-groups:\n  - {name: g, proxies: [ok]}\n"; // group missing `type`
        let Err(err) = crate::subscription::parse_subscription_yaml(bad_groups, true) else {
            panic!("strict must reject a malformed proxy-groups entry");
        };
        assert!(
            err.to_string().contains("proxy-groups"),
            "unexpected: {err}"
        );
        // Lenient warn-skips the malformed entry instead of wiping all groups.
        crate::subscription::parse_subscription_yaml(bad_groups, false).expect("lenient");

        let bad_shape = "proxies:\n  - {name: ok, type: direct}\nproxy-groups: not-a-list\n";
        assert!(
            crate::subscription::parse_subscription_yaml(bad_shape, false).is_err(),
            "a non-sequence proxy-groups section is a hard error in both modes"
        );

        let bad_proxy = "proxies:\n  - {name: ok, type: direct}\n  - 42\n";
        let Err(err) = crate::subscription::parse_subscription_yaml(bad_proxy, true) else {
            panic!("non-mapping proxy entry must fail strict");
        };
        assert!(
            err.to_string().contains("not a mapping"),
            "unexpected: {err}"
        );

        // `rules:` shape defects gate the same way: a non-sequence section
        // is a hard error in both modes; a non-string entry is strict-only.
        let bad_rules = "proxies:\n  - {name: ok, type: direct}\nrules: not-a-list\n";
        assert!(
            crate::subscription::parse_subscription_yaml(bad_rules, false).is_err(),
            "a non-sequence rules section is a hard error in both modes"
        );

        let bad_entry =
            "proxies:\n  - {name: ok, type: direct}\nrules:\n  - MATCH,DIRECT\n  - 42\n";
        let Err(err) = crate::subscription::parse_subscription_yaml(bad_entry, true) else {
            panic!("non-string rule entry must fail strict");
        };
        assert!(
            err.to_string().contains("not a string"),
            "unexpected: {err}"
        );
        crate::subscription::parse_subscription_yaml(bad_entry, false)
            .expect("lenient skips a non-string rule entry");
    }

    /// An empty or comments-only provider file is `Value::Null` — treated as
    /// an empty provider (parity with the missing-file acquisition path),
    /// not a payload defect (issue #533 review).
    #[tokio::test]
    async fn empty_provider_file_is_an_empty_provider() {
        let dir = std::env::temp_dir().join(format!("meow-empty-prov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("empty.yaml"), "# nothing here\n").unwrap();
        let raw: raw::RawProxyProvider =
            serde_yaml::from_str("type: file\npath: empty.yaml\n").unwrap();
        let provider = ProxyProvider::new("p", &raw, Some(&dir), false, true, Default::default())
            .expect("file provider constructs");
        provider
            .refresh()
            .await
            .expect("a Null document refreshes to an empty provider even under strict");
        assert!(provider.proxies().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// `fallback` / `url-test` / `load-balance` proxy groups get periodic
/// health checks (load-balance since issue #485) —
/// extract their probe specs from the raw group list (issue #514). Last
/// duplicate name wins — production paths reject duplicate group names
/// before construction (issue #561), but this function takes raw
/// declarations (including `?force=true` commits whose candidate failed
/// the build but was persisted), so it keeps the last-wins resolution
/// defensively:
/// a checkable declaration followed by a same-named non-checkable one
/// must NOT emit a spec.
pub fn extract_health_check_specs(
    raw_groups: &[raw::RawProxyGroup],
) -> Vec<meow_common::HealthCheckSpec> {
    const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";
    const DEFAULT_INTERVAL_SECS: u64 = 300;
    // First pass: resolve duplicate names against every declaration
    // (last declaration wins on the name regardless of type).
    let mut last: Vec<&raw::RawProxyGroup> = Vec::new();
    for g in raw_groups {
        match last.iter_mut().find(|prev| prev.name == g.name) {
            Some(prev) => *prev = g,
            None => last.push(g),
        }
    }
    last.iter()
        .filter(|g| {
            matches!(
                g.group_type.as_str(),
                "fallback" | "url-test" | "load-balance"
            )
        })
        .filter_map(|g| {
            // Upstream `HealthCheck.auto()` is `interval != 0`: an explicit
            // `interval: 0` DISABLES periodic checks (manual/on-demand
            // probes still work). Emitting no spec here also makes
            // reconcile remove a previously-running task.
            let interval_secs = match g.interval {
                Some(0) => return None,
                Some(i) => i,
                None => DEFAULT_INTERVAL_SECS,
            };
            Some(meow_common::HealthCheckSpec {
                group_name: g.name.clone(),
                url: g.url.as_deref().unwrap_or(DEFAULT_URL).to_string(),
                interval_secs,
                // Upstream defaults `lazy: true`
                // (`GroupCommonOption{Lazy: true}`, parser.go) — groups
                // probe only after first use.  We default `false`: eager
                // probing matches this port's historical behaviour and
                // flipping it silently would change idle traffic for
                // every existing config (Class B, ADR-0002; #555).
                lazy: g.lazy.unwrap_or(false),
            })
        })
        .collect()
}

#[cfg(test)]
mod yaml_depth_tests {
    //! Remote YAML (subscriptions, provider payloads, PUT /configs) must not
    //! drive serde_yaml's recursive Value deserializer past a bounded depth —
    //! `[[[[…` or ever-deepening indentation overflows a blocking-thread
    //! stack inside the fetch-size caps (issue #533 review).
    use super::yaml_within_depth;

    #[test]
    fn deep_flow_nesting_is_rejected() {
        let doc = format!("k: {}", "[".repeat(500));
        assert!(!yaml_within_depth(&doc));
    }

    #[test]
    fn deep_block_indentation_is_rejected() {
        let mut doc = String::from("a:");
        for i in 1..200 {
            doc.push('\n');
            doc.push_str(&" ".repeat(i * 4));
            doc.push_str("a:");
        }
        assert!(!yaml_within_depth(&doc));
    }

    #[test]
    fn real_config_shapes_pass() {
        let doc = r#"
mixed-port: 7890
proxies:
  - { name: a, type: direct }
proxy-groups:
  - name: g
    type: select
    proxies: [a, DIRECT]
rules:
  - MATCH,g
"#;
        assert!(yaml_within_depth(doc));
        // Brackets inside a scalar string count toward flow depth but a few
        // balanced/unbalanced ones never reach the cap.
        let scalar = "proxies:\n  - { name: \"[weird] name {x\", type: direct }\n";
        assert!(yaml_within_depth(scalar));
    }
}

#[cfg(test)]
mod dns_provider_sharing_tests {
    use super::*;

    /// `dns:` with a `rule-set:p` nameserver-policy key (so the DNS parse
    /// needs providers) plus a file-backed `p` provider.
    fn dns_raw_with_file_provider(path: &std::path::Path, behavior: &str) -> raw::RawConfig {
        let yaml = format!(
            "dns:\n  enable: true\n  nameserver:\n    - 127.0.0.1\n  nameserver-policy:\n    rule-set:p: 127.0.0.1\nrule-providers:\n  p:\n    type: file\n    behavior: {behavior}\n    path: '{}'\nrules:\n  - MATCH,DIRECT\n",
            path.display()
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    /// Issue #543 — the DNS rebuild must share the commit's prefetched
    /// payload bytes instead of fetching again. The
    /// `(rule_providers=None, payloads=Some)` combination pinned here is
    /// defensive — commit paths pass the two in lockstep — but any caller
    /// without the shared map must still not refetch.
    ///
    /// Discrimination: under `strict`, a payload *parse* defect is a hard
    /// error while a missing file is only an acquisition failure (the
    /// provider registers empty). So a malformed shared payload must fail
    /// even while the on-disk file is valid — iff the private load
    /// consumes the shared bytes.
    #[tokio::test]
    async fn dns_rebuild_reuses_prefetched_payloads_without_refetch() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("p.yaml");
        std::fs::write(&file, b"payload:\n  - '+.example.com'\n").unwrap();
        let mut raw = dns_raw_with_file_provider(&file, "domain");
        raw.strict = Some(true);
        let proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();

        let mut payloads = rule_provider::PrefetchedPayloads::new();
        payloads.insert("p".to_string(), b"not: [valid: yaml".to_vec());
        let payloads = Arc::new(payloads);

        let err = parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &proxies,
            None, // no preloaded map → private load
            Some(&payloads),
            None,
            None,
        )
        .await
        .err()
        .expect("a malformed shared payload must fail strict parsing");
        assert!(
            format!("{err:#}").contains("rule-provider 'p'"),
            "error must name the provider whose payload failed: {err:#}"
        );

        // The same raw with no shared map parses the on-disk file fine —
        // the error above came from the shared bytes, not the config.
        parse_dns_from_raw(&raw, Some(dir.path()), &proxies, None, None, None, None)
            .await
            .expect("the on-disk payload must parse cleanly");

        // And with the file gone, a valid shared payload still satisfies
        // the load — the bytes the routing rebuild fetched are the ones
        // the DNS rebuild parses. `Ok` alone is too weak: a missing file
        // is an acquisition failure that registers the provider *empty*,
        // so assert the policy actually matches the payload's domain.
        let mut payloads = rule_provider::PrefetchedPayloads::new();
        payloads.insert("p".to_string(), std::fs::read(&file).unwrap());
        let payloads = Arc::new(payloads);
        std::fs::remove_file(&file).unwrap();
        let dns = parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &proxies,
            None,
            Some(&payloads),
            None,
            None,
        )
        .await
        .expect("shared payloads must satisfy the private provider load");
        let policy = dns
            .resolver
            .nameserver_policy()
            .expect("rule-set:p policy must be built");
        assert!(
            policy.lookup("x.example.com").is_some(),
            "the shared payload's domain must reach the nameserver policy"
        );
        assert!(policy.lookup("unrelated.test").is_none());
    }

    /// Issue #543 — the DNS rebuild's geo scan must see `GEOSITE`/`GEOIP`/
    /// `IP-ASN` rules that live only inside provider payloads. Observable
    /// as the fail-fast missing-MMDB error naming the payload line that
    /// triggered it.
    #[tokio::test]
    async fn dns_rebuild_geo_scan_sees_provider_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("p.yaml");
        std::fs::write(&file, b"payload:\n  - GEOIP,CN,DIRECT\n").unwrap();
        let mut raw = dns_raw_with_file_provider(&file, "classical");
        raw.geodata =
            Some(serde_yaml::from_str("mmdb-path: /nonexistent-543/Country.mmdb").unwrap());
        let proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();

        let mut payloads = rule_provider::PrefetchedPayloads::new();
        payloads.insert("p".to_string(), std::fs::read(&file).unwrap());
        let payloads = Arc::new(payloads);

        let err = parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &proxies,
            None,
            Some(&payloads),
            None,
            None,
        )
        .await
        .err()
        .expect("a payload GEOIP rule must trigger the mmdb load");
        let msg = format!("{err}");
        assert!(
            msg.contains("/nonexistent-543/Country.mmdb"),
            "error must name the attempted mmdb path: {msg}"
        );
        assert!(
            msg.contains("GEOIP,CN"),
            "error must name the payload line that triggered the load: {msg}"
        );

        // The payload-blind call never attempts the mmdb load — the scan
        // saw no geo reference (the provider's GEOIP rule is itself
        // warn-skipped by the classical ruleset builder with no ctx), so
        // the build succeeds on the on-disk file.
        parse_dns_from_raw(&raw, Some(dir.path()), &proxies, None, None, None, None)
            .await
            .expect("the payload-blind call must not attempt the mmdb load");
    }

    /// `shared_providers` rebuilds bind live provider objects — nothing
    /// re-parses payloads, so prefetching would only re-fetch every http
    /// provider per geodata tick for bytes nothing reads. Pin the
    /// early-out: a shared rebuild over an http provider whose URL is
    /// served by a counting listener must open zero connections and carry
    /// an empty snapshot.
    #[tokio::test]
    async fn shared_providers_rebuild_never_prefetches() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });

        let raw: raw::RawConfig = serde_yaml::from_str(&format!(
            "rule-providers:\n  p:\n    type: http\n    behavior: domain\n    url: http://127.0.0.1:{port}/p.yaml\nrules:\n  - RULE-SET,p,DIRECT\n"
        ))
        .unwrap();
        let mut shared: HashMap<String, Arc<rule_provider::RuleProvider>> = HashMap::new();
        shared.insert(
            "p".to_string(),
            rule_provider::test_provider("p", rule_provider::ProviderType::Http, 0),
        );

        let result =
            rebuild_from_raw_with_resolver(&raw, None, None, &HashMap::new(), Some(shared))
                .expect("a shared rebuild must not need the network");
        // Any would-be fetch attempt gets a beat to reach the listener.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a shared rebuild must not prefetch provider payloads"
        );
        assert!(
            result.prefetched_payloads.is_empty(),
            "a shared rebuild carries no payload snapshot"
        );
    }
}
