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
pub mod raw;
pub mod rule_parser;
pub mod rule_provider;
mod safe_path;
pub mod sub_rules_parser;
pub mod subscription;

pub use geodata::GeoDataConfig;

use meow_common::AuthConfig;
use meow_common::{Proxy, Rule, SnifferConfig, TunnelMode};
use meow_dns::Resolver;
use proxy_provider::ProxyProvider;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

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
    pub rules: Vec<Box<dyn Rule>>,
    pub rule_providers: HashMap<String, Arc<rule_provider::RuleProvider>>,
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
    TProxy {
        sni: bool,
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
#[derive(Debug, Clone)]
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
        return Ok(TunConfig::default());
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

/// Parse a Clash/mihomo YAML document into [`raw::RawConfig`], expanding YAML
/// anchor merge keys (`<<: *anchor`) before deserialisation.
///
/// `serde_yaml` resolves anchors, but it does not by itself substitute merge
/// keys into the surrounding mapping; without [`serde_yaml::Value::apply_merge`]
/// the `<<` key reaches the typed deserialiser and the merged fields look
/// "missing". Upstream mihomo configs (e.g. `rule-anchor` patterns) rely on
/// this expansion — see meow-ios#112.
fn parse_raw_yaml(content: &str) -> Result<raw::RawConfig, anyhow::Error> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(content)?;
    value.apply_merge()?;
    Ok(serde_yaml::from_value(value)?)
}

/// Save a RawConfig back to disk with atomic write (.tmp → rename) and .bak backup.
pub fn save_raw_config(path: &str, raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let yaml = serde_yaml::to_string(raw)?;
    let tmp_path = format!("{path}.tmp");
    let bak_path = format!("{path}.bak");
    std::fs::write(&tmp_path, yaml)?;
    if std::path::Path::new(path).exists() {
        // Keep one backup
        let _ = std::fs::rename(path, &bak_path);
    }
    std::fs::rename(&tmp_path, path)?;
    info!("Config saved to {}", path);
    Ok(())
}

/// Async counterpart to [`save_raw_config`] for Tokio request/background paths.
pub async fn save_raw_config_async(path: &str, raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let yaml = serde_yaml::to_string(raw)?;
    let tmp_path = format!("{path}.tmp");
    let bak_path = format!("{path}.bak");
    tokio::fs::write(&tmp_path, yaml).await?;
    if tokio::fs::metadata(path).await.is_ok() {
        let _ = tokio::fs::rename(path, &bak_path).await;
    }
    tokio::fs::rename(&tmp_path, path).await?;
    info!("Config saved to {}", path);
    Ok(())
}

/// The result of rebuilding proxies and rules from a RawConfig.
pub type RebuildResult = (HashMap<SmolStr, Arc<dyn Proxy>>, Vec<Box<dyn Rule>>);

/// Rebuild proxies and rules from a RawConfig (used for runtime updates).
///
/// Does not resolve rule-provider cache paths; use
/// [`rebuild_from_raw_with_cache_dir`] when a working directory is available.
pub fn rebuild_from_raw(raw: &raw::RawConfig) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(raw, None, None, &HashMap::new(), None, None, None)
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
pub fn rebuild_from_raw_with_resolver(
    raw: &raw::RawConfig,
    resolver: Option<meow_dns::ResolverSlot>,
    cache_dir: Option<&Path>,
) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(raw, cache_dir, resolver, &HashMap::new(), None, None, None)
}

/// Runtime rebuild variant that keeps live proxy-provider slots and the
/// process-wide selection store wired into rebuilt groups.
///
/// See [`rebuild_from_raw_with_resolver`] for why `cache_dir` must be the
/// startup provider-cache directory rather than `None`.
pub fn rebuild_from_raw_runtime(
    raw: &raw::RawConfig,
    resolver: Option<meow_dns::ResolverSlot>,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    cache_dir: Option<&Path>,
) -> Result<RebuildResult, anyhow::Error> {
    let store = meow_proxy::SelectorStore::global();
    rebuild_from_raw_impl(
        raw,
        cache_dir,
        resolver,
        providers,
        store.as_ref(),
        None,
        None,
    )
}

/// Same as [`rebuild_from_raw`] but accepts a `cache_dir` used to resolve
/// relative rule-provider paths and to cache fetched HTTP payloads, and an
/// optional DNS `resolver` slot injected into the built-in DIRECT adapter.
pub fn rebuild_from_raw_with_cache_dir(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    resolver: Option<meow_dns::ResolverSlot>,
) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(raw, cache_dir, resolver, &HashMap::new(), None, None, None)
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
/// When providers were loaded, `registry` (if given) is swapped to the
/// freshly loaded set on success — the policy matchers capture the same
/// `Arc<RuleProvider>` objects, so `PUT /providers/rules/{name}` and
/// name-resolved refresh loops keep reaching the live generation instead
/// of orphaned startup-era objects (issue #514 review).
pub async fn parse_dns_from_raw(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    proxy_registry: &HashMap<SmolStr, Arc<dyn Proxy>>,
    registry: Option<&parking_lot::RwLock<HashMap<String, Arc<rule_provider::RuleProvider>>>>,
) -> Result<DnsConfig, anyhow::Error> {
    let geo = geodata::parse_geodata(raw.geodata.as_ref())?;
    let payloads = rule_provider::PrefetchedPayloads::default();
    let ctx = build_parser_context_from_raw(raw, &payloads)?;
    let rule_providers = if dns_parser::dns_needs_rule_providers(raw) {
        Some(
            load_rule_providers_async(
                raw.rule_providers.clone().unwrap_or_default(),
                cache_dir.map(Path::to_path_buf),
                ctx.clone(),
                internal_http::first_named_proxy(raw.proxies.as_deref(), proxy_registry),
                proxy_registry.clone(),
                Arc::new(payloads),
            )
            .await?,
        )
    } else {
        None
    };
    let dns = dns_parser::parse_dns(
        raw,
        geo.mmdb_path.as_deref(),
        cache_dir,
        proxy_registry,
        ctx.geosite,
        rule_providers.as_ref().unwrap_or(&HashMap::new()),
    )
    .await?;
    if let (Some(registry), Some(loaded)) = (registry, rule_providers) {
        *registry.write() = loaded;
    }
    Ok(dns)
}

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
/// chain), which works where `connect_over` is implemented (HTTP/SOCKS5/Snell)
/// and fails loudly at dial time otherwise. The fallback never degrades to a
/// direct dial, so a configured chain cannot be silently bypassed.
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
        let dialer = match raw_proxy.get("dialer-proxy") {
            None => continue,
            Some(v) => match v.as_str() {
                Some(s) if !s.is_empty() => s,
                _ => {
                    warn!("proxy '{name}': ignoring malformed dialer-proxy value");
                    continue;
                }
            },
        };
        if dialer == name {
            anyhow::bail!("proxy '{name}': dialer-proxy points to itself");
        }
        edges.push((SmolStr::from(name), SmolStr::from(dialer)));
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
        if !dialable.contains(dialer.as_str()) {
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
        let target = meow_proxy::dialer::DialerTarget::new(dialer.clone(), registry.clone());
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
            Err(e) => {
                // The adapter type cannot carry an injected dialer (anytls,
                // hysteria2, SS-with-external-SIP003-plugin) or the block is
                // otherwise unparseable. Fall back to the relay-based
                // `DialerProxyAdapter`, which preserves the pre-dialer
                // behaviour: it works for the protocols that implement
                // `connect_over` (HTTP/SOCKS5/Snell) and fails loudly at dial
                // time for the rest — never silently dialing direct and leaking
                // past the chain.
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
/// expands to the final registry (the build itself saw a mid-pass subset);
/// duplicate group declarations are unioned (the registry keeps the last
/// *successful* build, not the last declaration); relay members are all
/// treated as reachable heads (only the first member's dialer can actually
/// fire); provider-slot members (`use:` / `include-all`) are dead ends —
/// provider nodes never carry a `dialer-proxy`.
fn reject_group_membership_cycles(
    edges: &[(SmolStr, SmolStr)],
    raw_groups: &[raw::RawProxyGroup],
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
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
            members.extend(proxies.keys().map(SmolStr::as_str));
        }
        members_of
            .entry(group.name.as_str())
            .or_default()
            .extend(members);
    }
    if global_auto_created {
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
const BUILTIN_GLOBAL_POLICIES: [&str; 7] = [
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "COMPATIBLE",
    "GLOBAL",
    "BLOCK",
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

fn rebuild_from_raw_impl(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    resolver: Option<meow_dns::ResolverSlot>,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    selector_store: Option<&Arc<meow_proxy::SelectorStore>>,
    shared_ctx: Option<&meow_rules::ParserContext>,
    prefetched_payloads: Option<&rule_provider::PrefetchedPayloads>,
) -> Result<RebuildResult, anyhow::Error> {
    let ipv6 = effective_ipv6(raw.ipv6);
    let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
    // `dialer-proxy` front hops are resolved by name against this registry on
    // every dial; it is published once the build below has finished.
    let registry = meow_proxy::dialer::ProxyRegistry::default();
    // Built-in proxies
    let mut direct = meow_proxy::DirectAdapter::new();
    if let Some(mark) = raw.routing_mark {
        direct = direct.with_routing_mark(mark);
    }
    if let Some(slot) = resolver {
        direct = direct.with_resolver_slot(slot);
    }
    if let Some(secs) = raw.tcp_connect_timeout {
        direct = direct.with_connect_timeout(std::time::Duration::from_secs(secs));
    }
    proxies.insert(
        SmolStr::new_static("DIRECT"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(direct))),
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

    for raw_proxy in raw.proxies.as_deref().unwrap_or(&[]) {
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
                proxies.insert(key, proxy);
            }
            Err(e) => warn!("Failed to parse proxy: {}", e),
        }
    }

    let raw_groups = raw.proxy_groups.as_deref().unwrap_or(&[]);

    // Apply per-outbound `dialer-proxy` chains (issue #210) *before* groups are
    // built: groups clone their members eagerly, so a chain applied afterwards
    // would only cover direct rule references and a grouped node would silently
    // bypass it (issue #513). The front hop is resolved by name at dial time,
    // which is what lets a dialer name a group that does not exist yet here.
    let dialer_edges = apply_dialer_proxies(
        &mut proxies,
        raw.proxies.as_deref().unwrap_or(&[]),
        raw_groups,
        &registry,
        ipv6,
    )?;

    // Multi-pass group resolution: groups can reference other groups.
    // Keep trying until no new groups are resolved.
    let mut remaining: Vec<&raw::RawProxyGroup> = raw_groups.iter().collect();
    let mut max_passes = remaining.len() + 1;
    while !remaining.is_empty() && max_passes > 0 {
        max_passes -= 1;
        let mut still_remaining = Vec::new();
        for raw_group in &remaining {
            match proxy_parser::parse_proxy_group_with_store(
                raw_group,
                &proxies,
                providers,
                selector_store,
            ) {
                Ok(group) => {
                    let name = SmolStr::from(group.name());
                    proxies.insert(name, group);
                }
                Err(_) => {
                    still_remaining.push(*raw_group);
                }
            }
        }
        if still_remaining.len() == remaining.len() {
            // No progress — the remaining groups reference proxies that
            // don't exist in this config at all (not a forward reference).
            // Match upstream mihomo: warn-and-skip the missing members and
            // build the group with whatever resolved.
            for raw_group in &still_remaining {
                match proxy_parser::parse_proxy_group_lenient_with_store(
                    raw_group,
                    &proxies,
                    providers,
                    selector_store,
                ) {
                    Ok(group) => {
                        let name = SmolStr::from(group.name());
                        proxies.insert(name, group);
                    }
                    Err(e) => warn!("Failed to parse proxy group '{}': {}", raw_group.name, e),
                }
            }
            break;
        }
        remaining = still_remaining;
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
            .keys()
            .map(std::string::ToString::to_string)
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
    // first dial report it late.
    for (name, dialer) in &dialer_edges {
        if !proxies.contains_key(dialer.as_str()) {
            anyhow::bail!(
                "proxy '{name}': dialer-proxy '{dialer}' is declared but did \
                 not build into a registry entry"
            );
        }
    }

    // Cycles that run through group membership — including a declared-but-
    // failed GLOBAL that the auto-create just backstopped — are only decidable
    // now that the registry is finished.
    reject_group_membership_cycles(&dialer_edges, raw_groups, &proxies, global_auto_created)?;

    // Publish the finished registry: the `dialer-proxy` chains bound above
    // resolve their front hop by name against it, and only now does it hold the
    // groups they may name (issue #513). Nothing mutates `proxies` after this
    // point, and publishing *before* the provider fetches below matters: they
    // dial through `download_proxy`, which may itself be a chained node whose
    // front hop must already resolve. A later rebuild publishes into its own
    // registry, so adapters already handed to the tunnel keep resolving the
    // snapshot they were built from.
    registry.publish(Arc::new(proxies.clone()));

    let download_proxy = internal_http::first_named_proxy(raw.proxies.as_deref(), &proxies);
    // Per-provider `proxy:` overrides resolve against the full registry —
    // groups and provider-sourced proxies included (issue #377).
    let registry_lookup = |name: &str| proxies.get(name).cloned();

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
    // the same bytes, so nothing is fetched twice.
    let owned_payloads;
    let payloads = match prefetched_payloads {
        Some(p) => p,
        None => {
            owned_payloads = match raw.rule_providers.as_ref() {
                Some(map) if !map.is_empty() => rule_provider::prefetch_payloads(
                    map,
                    cache_dir,
                    download_proxy.as_ref(),
                    &registry_lookup,
                ),
                _ => HashMap::new(),
            };
            &owned_payloads
        }
    };

    let owned_ctx;
    let ctx = match shared_ctx {
        Some(c) => c,
        None => {
            owned_ctx = build_parser_context_from_raw(raw, payloads)?;
            &owned_ctx
        }
    };

    let providers = match raw.rule_providers.as_ref() {
        Some(map) if !map.is_empty() => rule_provider::load_providers_prefetched(
            map,
            cache_dir,
            ctx,
            download_proxy.as_ref(),
            &registry_lookup,
            payloads,
        ),
        _ => HashMap::new(),
    };
    let ruleset_map = rule_provider::snapshot_ruleset_map(&providers);

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
    );

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

    Ok((proxies, rules))
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
/// Uses the first parseable proxy from the raw config for tunneled fetches
/// (same policy as [`ensure_geodata`]) since the proxy registry is not built
/// yet at this point of startup.
async fn prefetch_rule_provider_payloads_async(
    raw: &raw::RawConfig,
    cache_dir: Option<PathBuf>,
) -> rule_provider::PrefetchedPayloads {
    let Some(raw_providers) = raw.rule_providers.as_ref().filter(|m| !m.is_empty()) else {
        return HashMap::new();
    };
    let raw_providers = raw_providers.clone();
    let ipv6 = effective_ipv6(raw.ipv6);
    let raw_proxies: Vec<HashMap<String, serde_yaml::Value>> =
        raw.proxies.clone().unwrap_or_default();
    spawn_blocking_with_current_dispatcher(move || {
        let default_proxy: Option<Arc<dyn Proxy>> = raw_proxies
            .iter()
            .find_map(|raw_proxy| proxy_parser::parse_proxy(raw_proxy, ipv6).ok());
        // Pre-registry `proxy:` resolution parses the named leaf out of the
        // raw `proxies:` block; group names don't resolve here, so their
        // providers skip prefetch and fetch during the registry-backed load.
        let lookup = |wanted: &str| {
            raw_proxies
                .iter()
                .filter(|p| p.get("name").and_then(serde_yaml::Value::as_str) == Some(wanted))
                .find_map(|raw_proxy| proxy_parser::parse_proxy(raw_proxy, ipv6).ok())
        };
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

async fn rebuild_from_raw_impl_async(
    raw: raw::RawConfig,
    cache_dir: Option<PathBuf>,
    resolver: Option<meow_dns::ResolverSlot>,
    providers: HashMap<String, Arc<ProxyProvider>>,
    selector_store: Option<Arc<meow_proxy::SelectorStore>>,
    ctx: meow_rules::ParserContext,
    provider_payloads: Arc<rule_provider::PrefetchedPayloads>,
) -> Result<RebuildResult, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || {
        rebuild_from_raw_impl(
            &raw,
            cache_dir.as_deref(),
            resolver,
            &providers,
            selector_store.as_ref(),
            Some(&ctx),
            Some(&provider_payloads),
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("config rebuild task failed: {e}"))?
}

async fn load_rule_providers_async(
    raw_providers: HashMap<String, raw::RawRuleProvider>,
    cache_dir: Option<PathBuf>,
    ctx: meow_rules::ParserContext,
    download_proxy: Option<Arc<dyn Proxy>>,
    registry: HashMap<SmolStr, Arc<dyn Proxy>>,
    provider_payloads: Arc<rule_provider::PrefetchedPayloads>,
) -> Result<HashMap<String, Arc<rule_provider::RuleProvider>>, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || {
        let lookup = |name: &str| registry.get(name).cloned();
        rule_provider::load_providers_prefetched(
            &raw_providers,
            cache_dir.as_deref(),
            &ctx,
            download_proxy.as_ref(),
            &lookup,
            &provider_payloads,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("rule-provider load task failed: {e}"))
}

fn parse_sniffer_config(raw: &raw::RawConfig) -> Result<SnifferConfig, anyhow::Error> {
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

/// Scan `raw.rules` for any GeoIP-backed entry (`GEOIP`, `SRC-GEOIP`) or any
/// ASN-backed entry (`IP-ASN`, `SRC-IP-ASN`); if present, lazy-load the
/// corresponding MMDB from the default path and build a `ParserContext`
/// carrying the readers. Fail-fast (returning an error that names the
/// offending rule and the path we tried) when the scan matches but the
/// load fails.
///
/// For `GEOSITE` entries the DB is discovered separately and loaded only if
/// at least one GEOSITE rule is present (same lazy pattern as GeoIP/ASN).
/// Unlike GeoIP/ASN, the GEOSITE DB is tolerated as absent — per spec the
/// rule no-matches at query time rather than failing at parse.
/// Download missing geodata files that the config's rules require.
///
/// Parses the first proxy from the raw config for tunneled downloads (needed
/// in regions where the CDN is blocked); falls back to a direct fetch when
/// no proxy is configured. Download failures are logged as warnings — the
/// subsequent parser-context build will hard-error if the file is still
/// absent, giving a clear diagnostic.
async fn ensure_geodata(raw: &raw::RawConfig, geo: &GeoDataConfig, scan_lines: &[String]) {
    let needs_geoip = scan_lines.iter().any(|l| line_references_geoip(l));
    let needs_asn = scan_lines.iter().any(|l| line_references_asn(l));
    let needs_geosite =
        scan_lines.iter().any(|l| line_references_geosite(l)) || dns_policy_uses_geosite(raw);

    if !needs_geoip && !needs_asn && !needs_geosite {
        return;
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

    if !geoip_missing && !asn_missing && !geosite_missing {
        return;
    }

    // Build a download proxy from the first configured proxy, if any.
    let proxy: Option<Arc<dyn Proxy>> = raw
        .proxies
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find_map(|raw_proxy| proxy_parser::parse_proxy(raw_proxy, effective_ipv6(raw.ipv6)).ok());

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
    for bytes in provider_payloads.values() {
        if meow_rules::is_mrs_bytes(bytes) {
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
    if let Some(d) = meow_common::meow_home_dir() {
        return d;
    }
    default_config_dir_without_home_override()
}

fn default_config_dir_without_home_override() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("meow")
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
        .map_or_else(
            default_config_dir_without_home_override,
            std::path::Path::to_path_buf,
        )
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
/// `per_listener_sni` / `global_tproxy_sni` are folded into the `TProxy`
/// variant here so the returned spec is always complete — callers never
/// need to overwrite a placeholder `sni` value. Both parameters are ignored
/// for non-TProxy types. `Shadowsocks` returns a placeholder spec;
/// `build_named_listeners` completes it via `build_ss_listener_spec`.
fn parse_listener_spec(
    s: &str,
    per_listener_sni: Option<bool>,
    global_tproxy_sni: bool,
) -> Result<ListenerSpec, anyhow::Error> {
    match s.to_lowercase().as_str() {
        "mixed" => Ok(ListenerSpec::Mixed),
        "http" => Ok(ListenerSpec::Http),
        "socks5" => Ok(ListenerSpec::Socks5),
        "tproxy" => Ok(ListenerSpec::TProxy {
            sni: per_listener_sni.unwrap_or(global_tproxy_sni),
        }),
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
    if let Some(port) = raw.tproxy_port.filter(|p| *p != 0) {
        add(
            "tproxy",
            ListenerSpec::TProxy {
                sni: global_tproxy_sni,
            },
            port,
            "127.0.0.1",
            global_max_conns,
        )?;
    }

    // Explicit `listeners:` entries
    for raw_l in raw.listeners.as_deref().unwrap_or(&[]) {
        let spec = parse_listener_spec(&raw_l.listener_type, raw_l.tproxy_sni, global_tproxy_sni)?;
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
    // and leave the map unchanged.
    if let Some(ps) = raw.proxies.as_mut() {
        ech_dns::preresolve_ech(ps).await;
    }

    // Geodata config — parse and validate early so path errors surface before
    // anything tries to load the DBs.
    let geodata = geodata::parse_geodata(raw.geodata.as_ref())?;

    // General config
    let mode = raw
        .mode
        .as_deref()
        .unwrap_or("rule")
        .parse::<TunnelMode>()
        .unwrap_or(TunnelMode::Rule);
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

    // Load proxy providers (async: may HTTP-fetch provider files).
    let proxy_providers = if let Some(raw_pp) = raw.proxy_providers.as_ref() {
        if raw_pp.is_empty() {
            HashMap::new()
        } else {
            proxy_provider::load_proxy_providers(raw_pp, cache_dir, general.ipv6).await
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
    // Open the persistent selector store (one JSON file in cache_dir).
    // Missing/unreadable files yield an empty store — no fatal errors.
    let cache_dir_buf = cache_dir.map(Path::to_path_buf);
    let selector_store = match cache_dir_buf.as_ref() {
        Some(d) => Some(open_selector_store_async(d.join("selector-cache.json")).await?),
        None => None,
    };

    // Fetch/read rule-provider payloads once; the geodata check, the parser
    // context build, and every provider load pass below reuse these bytes so
    // geo keys referenced only inside provider payloads are seen (issue #277)
    // and nothing is fetched twice.
    let provider_payloads =
        Arc::new(prefetch_rule_provider_payloads_async(&raw, cache_dir_buf.clone()).await);

    // Ensure geodata files exist — download any that are missing and needed
    // by the config's rules (including sub-rules and provider payloads). This
    // must happen before building the parser context, which hard-errors on
    // missing GeoIP/ASN files.
    let geo_scan_lines = collect_geo_scan_lines(&raw, &provider_payloads);
    ensure_geodata(&raw, &geodata, &geo_scan_lines).await;
    drop(geo_scan_lines);

    // Build the parser context once and share across all passes.
    let ctx = build_parser_context_with_geo_async(
        raw.clone(),
        geodata.clone(),
        Arc::clone(&provider_payloads),
    )
    .await?;

    let (proxies, _) = rebuild_from_raw_impl_async(
        raw.clone(),
        cache_dir_buf.clone(),
        None,
        proxy_providers.clone(),
        selector_store.clone(),
        ctx.clone(),
        Arc::clone(&provider_payloads),
    )
    .await?;

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
    )
    .await?;

    let (proxies, rules) = rebuild_from_raw_impl_async(
        raw.clone(),
        cache_dir_buf.clone(),
        Some(Arc::clone(&dns_config.resolver_slot)),
        proxy_providers.clone(),
        selector_store.clone(),
        ctx.clone(),
        Arc::clone(&provider_payloads),
    )
    .await?;

    // Listener config
    let bind_addr = if general.allow_lan {
        general.bind_address.clone()
    } else {
        "127.0.0.1".to_string()
    };
    let global_tproxy_sni = raw.tproxy_sni.unwrap_or(true);

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
    let sniffer = parse_sniffer_config(&raw)?;

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
        rules,
        rule_providers,
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
    fn apply_chains(
        proxies: &mut HashMap<SmolStr, Arc<dyn Proxy>>,
        raw_proxies: &[HashMap<String, serde_yaml::Value>],
    ) -> Result<(), anyhow::Error> {
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
    ) -> Result<(), anyhow::Error> {
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let edges = apply_dialer_proxies(proxies, raw_proxies, raw_groups, &registry, true)?;
        for group in raw_groups {
            proxies
                .entry(SmolStr::from(group.name.as_str()))
                .or_insert_with(|| simple_proxy(&group.name));
        }
        let global_auto_created = !proxies.contains_key("GLOBAL");
        reject_group_membership_cycles(&edges, raw_groups, proxies, global_auto_created)?;
        registry.publish(Arc::new(proxies.clone()));
        Ok(())
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

    /// `include-all-proxies` expands to every registry name — same self-route.
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

    /// A malformed `dialer-proxy` value is warned about and skipped — the node
    /// keeps its direct dialer rather than dying on a typo.
    #[test]
    fn malformed_dialer_proxy_is_ignored() {
        let mut proxies = registry(&["A", "B"]);
        let before = proxies.clone();
        let mut raw = raw_proxy("A", None);
        raw.insert(
            "dialer-proxy".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(42)),
        );
        apply_chains(&mut proxies, &[raw]).expect("malformed dialer-proxy is skipped");
        assert!(
            !was_wrapped(&before, &proxies, "A"),
            "a non-string dialer-proxy must not apply a chain"
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
    /// (yaml and text forms); binary MRS payloads are skipped.
    #[test]
    fn scan_lines_include_prefetched_provider_payloads() {
        let raw = raw::RawConfig::default();
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
        let lines = collect_geo_scan_lines(&raw, &payloads);
        let countries = collect_geoip_countries(&lines);
        assert!(countries.contains("BR"), "yaml payload GEOIP must be seen");
        assert!(!countries.contains("XX"), "comment lines must be skipped");
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
        assert_eq!(got, super::default_config_dir_without_home_override());
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

        // `rebuild_from_raw_with_resolver` — used by subscription_refresh
        // and geodata_fetch.
        let (_, rules) = rebuild_from_raw_with_resolver(&raw, None, Some(dir.path())).expect(
            "trusted rebuild with the real cache dir must not hard-fail on a file provider",
        );
        assert_eq!(rules.len(), 2);

        // `rebuild_from_raw_runtime` — used by meow-api's `PUT /configs`
        // family via `rebuild_from_raw_with_resolver_async`.
        let (_, rules) = rebuild_from_raw_runtime(&raw, None, &HashMap::new(), Some(dir.path()))
            .expect(
            "trusted runtime rebuild with the real cache dir must not hard-fail on a file provider",
        );
        assert_eq!(rules.len(), 2);
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

/// `fallback` / `url-test` proxy groups get periodic health checks —
/// extract their probe specs from the raw group list (issue #514). Last
/// duplicate name wins, matching how `load_config` resolves duplicates —
/// including a checkable declaration followed by a same-named
/// non-checkable one, which must NOT emit a spec.
pub fn extract_health_check_specs(
    raw_groups: &[raw::RawProxyGroup],
) -> Vec<meow_common::HealthCheckSpec> {
    const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";
    const DEFAULT_INTERVAL_SECS: u64 = 300;
    // First pass: resolve duplicate names against every declaration
    // (load_config's builder is last-wins on the name regardless of type).
    let mut last: Vec<&raw::RawProxyGroup> = Vec::new();
    for g in raw_groups {
        match last.iter_mut().find(|prev| prev.name == g.name) {
            Some(prev) => *prev = g,
            None => last.push(g),
        }
    }
    last.iter()
        .filter(|g| matches!(g.group_type.as_str(), "fallback" | "url-test"))
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
                lazy: g.lazy.unwrap_or(false),
            })
        })
        .collect()
}
