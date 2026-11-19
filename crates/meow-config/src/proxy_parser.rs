use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, GroupDisplay, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
#[cfg(feature = "ss")]
use meow_proxy::ShadowsocksAdapter;
#[cfg(feature = "trojan")]
use meow_proxy::TrojanAdapter;
use meow_proxy::{
    DirectAdapter, FallbackGroup, HttpAdapter, LbStrategy, LoadBalanceGroup, RelayGroup,
    SelectorGroup, Socks5Adapter, UrlTestGroup,
};
#[cfg(feature = "vless")]
use meow_proxy::{TransportChain, VlessAdapter, VlessFlow};
#[cfg(feature = "wireguard")]
use meow_proxy::{WireGuardAdapter, WireGuardConfig};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::Arc;

fn required_port(
    config: &HashMap<String, serde_json::Value>,
    context: &str,
) -> std::result::Result<u16, String> {
    let raw = config
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{context}: missing port"))?;
    let port = u16::try_from(raw).map_err(|_| format!("{context}: port {raw} exceeds 65535"))?;
    if port == 0 {
        return Err(format!("{context}: port must be non-zero"));
    }
    Ok(port)
}

/// Wraps a ProxyAdapter to implement the full Proxy trait
pub struct WrappedProxy {
    adapter: Box<dyn ProxyAdapter>,
    /// The `dialer-proxy` the adapter dials its server through.
    hop: Option<DialerHop>,
    /// The `proxies:` entry's per-node dialer fields (issue #974):
    /// `routing-mark`, `interface-name`, `ip-version`, `tfo`, `mptcp`.
    /// Resolved over [`meow_common::global_dialer_opts`] at dial time and
    /// installed as the task-local [`meow_common::dialer_opts_scope`]
    /// around every adapter dial — so the socket helpers see the node's
    /// own options wherever the dial leads, including the WireGuard
    /// endpoint socket bound inside `ensure_pump`.
    node_opts: meow_common::NodeDialerOpts,
}

/// An outbound's injected `dialer-proxy` dialer, and the server it dials
/// through it.
struct DialerHop {
    dialer: Arc<dyn meow_proxy::dialer::TcpDialer>,
    host: SmolStr,
    port: u16,
}

impl WrappedProxy {
    pub fn new(adapter: Box<dyn ProxyAdapter>) -> Self {
        Self {
            adapter,
            hop: None,
            node_opts: meow_common::NodeDialerOpts::default(),
        }
    }

    /// Attach the dialer fields the leaf's `proxies:` block declared
    /// (issue #974). Every leaf parse path calls this; the built-in
    /// DIRECT/REJECT wrappers keep the default — no config block exists
    /// to parse them from.
    pub fn with_node_dialer_opts(mut self, opts: meow_common::NodeDialerOpts) -> Self {
        self.node_opts = opts;
        self
    }

    /// The node's fields resolved over the *live* globals — read per
    /// dial, so a `PATCH /configs` `interface-name`/`routing-mark` lands
    /// on the next dial rather than the next reload.
    fn effective_dialer_opts(&self) -> meow_common::DialerOpts {
        meow_common::DialerOpts::resolve(&self.node_opts, &meow_common::global_dialer_opts())
    }

    /// `self`, whose adapter the block `config` built with `dialer`
    /// injected, so [`ProxyAdapter::dialer_hop`] can name the member a
    /// `dialer-proxy` front takes.
    fn dialing_through(
        mut self,
        config: &HashMap<String, serde_json::Value>,
        dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
    ) -> Self {
        let host = config.get("server").and_then(serde_json::Value::as_str);
        let port = config
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .filter(|&port| port > 0)
            .or_else(|| {
                // A `ports`-only node (hysteria2's hopping range, which may
                // carry `port: 0` or none at all) still dials one concrete
                // endpoint: the range's first port, same as the adapter.
                config
                    .get("ports")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|ports| ports.split([',', '-']).next())
                    .and_then(|first| first.trim().parse::<u64>().ok())
                    .filter(|&port| port > 0)
            })
            .and_then(|port| u16::try_from(port).ok());
        if let (true, Some(host), Some(port)) = (dialer.is_proxy(), host, port) {
            self.hop = Some(DialerHop {
                dialer: Arc::clone(dialer),
                host: host.into(),
                port,
            });
        }
        self
    }
}

#[async_trait]
impl ProxyAdapter for WrappedProxy {
    fn name(&self) -> &str {
        self.adapter.name()
    }
    fn adapter_type(&self) -> AdapterType {
        self.adapter.adapter_type()
    }
    fn addr(&self) -> &str {
        self.adapter.addr()
    }
    fn support_udp(&self) -> bool {
        self.adapter.support_udp()
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        // The node's resolved dialer opts scope the whole adapter call:
        // server/target resolution, the TCP socket, and — for WireGuard —
        // the endpoint UDP socket bound lazily inside `ensure_pump`
        // (issue #974; `dialer_opts_scope` REPLACES on nesting, so a
        // chained front hop installs its own opts for the socket it
        // opens rather than inheriting this node's).
        meow_common::dialer_opts_scope(
            self.effective_dialer_opts(),
            self.adapter.dial_tcp(metadata),
        )
        .await
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        meow_common::dialer_opts_scope(
            self.effective_dialer_opts(),
            self.adapter.dial_udp(metadata),
        )
        .await
    }
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        meow_common::dialer_opts_scope(
            self.effective_dialer_opts(),
            self.adapter.connect_over(stream, metadata),
        )
        .await
    }

    /// Forward the peek/commit walk — a wrapped group-typed adapter would
    /// otherwise hide PASS/PASS-RULE members from the match-time probe.
    fn unwrap_proxy(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.adapter.unwrap_proxy(metadata, touch)
    }

    /// The pick of the front the injected dialer dials the server through,
    /// over the network the adapter takes there for this flow.
    fn dialer_hop(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        match &self.hop {
            Some(hop) => hop.dialer.front_hop(
                &hop.host,
                hop.port,
                self.adapter.dialer_hop_network(metadata.network),
            ),
            None => self.adapter.dialer_hop(metadata),
        }
    }

    /// Configured dependency, independent of the front group's current pick.
    fn has_configured_dialer(&self) -> bool {
        self.hop.is_some()
    }

    fn dialer_hop_network(&self, flow: meow_common::Network) -> meow_common::Network {
        self.adapter.dialer_hop_network(flow)
    }

    /// Forward the session flush (issue #695) — every parsed leaf sits behind
    /// this wrapper, so the default no-op here would hide all their pools.
    fn reset_sessions(&self) {
        self.adapter.reset_sessions();
    }

    fn health(&self) -> &ProxyHealth {
        self.adapter.health()
    }

    /// Transparent wrapper — the baked fingerprint is the leaf's.
    fn client_fingerprint(&self) -> Option<&str> {
        self.adapter.client_fingerprint()
    }
}

impl Proxy for WrappedProxy {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn alive(&self) -> bool {
        self.adapter.health().alive()
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        self.adapter.health().alive()
    }
    fn last_delay(&self) -> u16 {
        self.adapter.health().last_delay()
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        self.adapter.health().last_delay()
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.adapter.health().delay_history()
    }
}

/// Marks a `proxies:` leaf whose `dialer-proxy` was applied by *injection* —
/// its adapter threads every dial through the chained front hop itself, so
/// no `DialerProxyAdapter` wrapper exists to carry the chain signal the UDP
/// probe reads (issue #969).
///
/// Every `Proxy` / `ProxyAdapter` method delegates to `inner` verbatim — the
/// marker is observational only: `support_udp` still propagates the inner
/// advertisement (an `http` node reports `false`; a `ss`/`socks5` node folds
/// the front's live capability), `as_any` still resolves the inner concrete
/// type so existing downcasts land exactly as they did on the bare entry,
/// and the health/delay/member views are untouched.
///
/// The one override is `is_dialer_proxy_non_transparent` →
/// `!inner.support_udp()`: the #969 fail-closed verdict is exactly the
/// `support_udp` condition, matching `DialerProxyAdapter`'s
/// `!transparent`. An injected leaf whose chained transport carries UDP
/// — hysteria2 over the front's UDP association, WireGuard, or anytls
/// `udp: true` (UoT rides the chained TCP session) — is *not*
/// non-transparent: its UDP flow rides the declared chain, so there is
/// nothing to fail closed on. `type: direct` rejects the injected dialer
/// inside [`parse_proxy_with_dialer`] (`reject_unthreaded_dialer`), and
/// `ss` with an external SIP003 plugin bails on its own inline check —
/// either way the leaf lands in the relay-based
/// `DialerProxyAdapter` fallback instead, which computes its own
/// transparency — so reaching this wrapper already proves the inner owns a
/// server transport. A UDP flow matched to a rule targeting a
/// UDP-incapable chained node then fails closed on the match instead of
/// sliding to a later rule the way a plain `udp: false` node does.
pub struct ChainedProxy {
    inner: Arc<dyn Proxy>,
}

impl ChainedProxy {
    pub fn new(inner: Arc<dyn Proxy>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl ProxyAdapter for ChainedProxy {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn adapter_type(&self) -> AdapterType {
        self.inner.adapter_type()
    }
    fn addr(&self) -> &str {
        self.inner.addr()
    }
    fn support_udp(&self) -> bool {
        self.inner.support_udp()
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.inner.dial_tcp(metadata).await
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.inner.dial_udp(metadata).await
    }
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        self.inner.connect_over(stream, metadata).await
    }

    /// Forward the peek/commit walk like `WrappedProxy` — a chained entry
    /// whose inner resolved (theoretical today: injected entries are leaves)
    /// must not hide PASS/PASS-RULE members from the match-time probe.
    fn unwrap_proxy(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.inner.unwrap_proxy(metadata, touch)
    }

    /// The injected leaf answers the front hop itself; forward so the
    /// answer keeps reaching the probe through this wrapper.
    fn dialer_hop(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.inner.dialer_hop(metadata)
    }

    /// The injected leaf already reports the configured chain; forward.
    fn has_configured_dialer(&self) -> bool {
        self.inner.has_configured_dialer()
    }

    fn dialer_hop_network(&self, flow: meow_common::Network) -> meow_common::Network {
        self.inner.dialer_hop_network(flow)
    }

    /// Forward the session flush (issue #695) — a marker that hid it would
    /// strand the inner adapter's pooled transport sessions.
    fn reset_sessions(&self) {
        self.inner.reset_sessions();
    }

    fn health(&self) -> &ProxyHealth {
        self.inner.health()
    }

    /// Transparent marker — the baked fingerprint is the leaf's.
    fn client_fingerprint(&self) -> Option<&str> {
        self.inner.client_fingerprint()
    }
}

impl Proxy for ChainedProxy {
    fn alive(&self) -> bool {
        self.inner.alive()
    }
    fn alive_for_url(&self, url: &str) -> bool {
        self.inner.alive_for_url(url)
    }
    fn last_delay(&self) -> u16 {
        self.inner.last_delay()
    }
    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.inner.last_delay_for_url(url)
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.inner.delay_history()
    }

    /// Transparent to concrete-type downcasts: callers still reach the
    /// injected leaf (`WrappedProxy`, the group types) — the registry entry
    /// answers `as_any` exactly as the bare inner did before marking.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        self.inner.as_any()
    }

    /// The marker's single verdict (issue #969): an injected leaf is the
    /// non-transparent chain shape only when the chain cannot carry UDP
    /// — `!inner.support_udp()`, the same condition
    /// `DialerProxyAdapter` answers with `!transparent` and the only case
    /// the route probe consults this marker for. A leaf whose chained
    /// transport does carry UDP (injected hysteria2/WireGuard, anytls
    /// `udp: true`) answers `false` so a group pick forwarding this
    /// verdict stays truthful.
    fn is_dialer_proxy_non_transparent(&self) -> bool {
        !self.inner.support_udp()
    }

    fn members(&self) -> Option<Vec<String>> {
        self.inner.members()
    }

    fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        self.inner.member_proxies()
    }

    fn current(&self) -> Option<String> {
        self.inner.current()
    }

    fn selection(&self) -> Option<&dyn meow_common::ProxySelection> {
        self.inner.selection()
    }

    fn test_url(&self) -> Option<&str> {
        self.inner.test_url()
    }

    fn expected_status(&self) -> Option<&str> {
        self.inner.expected_status()
    }

    fn group_display(&self) -> Option<&GroupDisplay> {
        self.inner.group_display()
    }

    fn usage_generation(&self) -> u64 {
        self.inner.usage_generation()
    }

    fn chain_health(&self) -> Option<&Arc<meow_common::chain_health::ChainHealth>> {
        self.inner.chain_health()
    }
}

/// The mihomo per-node dialer fields shared by every leaf `type:`
/// (issue #974): `routing-mark`, `interface-name`, `ip-version`, `tfo`,
/// `mptcp`. Parsed once from the `proxies:` map and carried on the leaf's
/// [`WrappedProxy`]; `proxy-groups:` entries never reach here, so a group
/// cannot carry dialer fields at all — matching mihomo v1.19, which
/// removed group-level dialer options.
///
/// Normalization lands here, before [`meow_common::NodeDialerOpts`] sees
/// it: `routing-mark: 0` and an empty/`null` `interface-name` mean
/// "unset" (inherit the global); a non-string field or an unknown
/// `ip-version` is a hard parse error — mihomo fails the node the same
/// way rather than defaulting.
fn parse_node_dialer_opts(
    config: &HashMap<String, serde_json::Value>,
    name: &str,
) -> std::result::Result<meow_common::NodeDialerOpts, String> {
    let routing_mark = match config.get("routing-mark") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let raw = value
                .as_u64()
                .ok_or_else(|| format!("{name}: `routing-mark` must be a non-negative integer"))?;
            let mark = u32::try_from(raw)
                .map_err(|_| format!("{name}: `routing-mark` {raw} exceeds u32::MAX"))?;
            (mark != 0).then_some(mark)
        }
    };
    let interface_name = match config.get("interface-name") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let raw = value
                .as_str()
                .ok_or_else(|| format!("{name}: `interface-name` must be a string"))?;
            let trimmed = raw.trim();
            // A NUL is a hard error, not normalization: Linux
            // `SO_BINDTODEVICE` would silently truncate the name at it
            // and bind the wrong interface (spec §1.2).
            if trimmed.contains('\0') {
                return Err(format!(
                    "{name}: `interface-name` must not contain NUL bytes"
                ));
            }
            (!trimmed.is_empty()).then(|| std::sync::Arc::from(trimmed))
        }
    };
    let ip_version = match config.get("ip-version") {
        None | Some(serde_json::Value::Null) => meow_common::IpVersion::Dual,
        Some(value) => {
            let raw = value
                .as_str()
                .ok_or_else(|| format!("{name}: `ip-version` must be a string"))?;
            meow_common::IpVersion::from_name(raw).ok_or_else(|| {
                format!(
                    "{name}: unknown `ip-version` '{raw}' — expected \
                     dual|ipv4|ipv6|ipv4-prefer|ipv6-prefer"
                )
            })?
        }
    };
    let tfo = match config.get("tfo") {
        None | Some(serde_json::Value::Null) => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("{name}: `tfo` must be a boolean"))?,
    };
    let mptcp = match config.get("mptcp") {
        None | Some(serde_json::Value::Null) => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("{name}: `mptcp` must be a boolean"))?,
    };
    Ok(meow_common::NodeDialerOpts {
        routing_mark,
        interface_name,
        ip_version,
        tfo,
        mptcp,
    })
}

/// Normalize a raw `global-client-fingerprint` or per-node
/// `client-fingerprint` value: trim whitespace and ASCII-lowercase.
/// Empty or `"none"` returns `None` (issue #974, mihomo's `len == 0`).
pub fn normalize_client_fingerprint(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("none") {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

/// Resolve a node's `client-fingerprint` against the top-level
/// `global-client-fingerprint` (issue #974, mihomo's per-constructor
/// `option.ClientFingerprint == ""` fallback — applied at parse time):
/// absent / `null` / `""` / whitespace-only inherits the (normalized)
/// global; an explicit `none` opts out — except under `keep_none_literal`
/// (vless+REALITY, where no uTLS hello exists to send unshaped) which
/// passes `"none"` through so `HelloProfile::resolve` warns and uses
/// Chrome. Non-string values are a hard error, as `trusttunnel`/`anytls`
/// already did.
// Every consumer arm is feature-gated; a `default-features = false`
// downstream (meow-api) compiles them all out.
#[cfg_attr(
    not(any(
        feature = "ss",
        feature = "trusttunnel",
        feature = "vless",
        feature = "anytls",
        feature = "vmess"
    )),
    allow(dead_code)
)]
fn resolve_node_client_fingerprint(
    config: &HashMap<String, serde_json::Value>,
    context: &str,
    global_client_fingerprint: Option<&str>,
    keep_none_literal: bool,
) -> std::result::Result<Option<String>, String> {
    match config.get("client-fingerprint") {
        None | Some(serde_json::Value::Null) => {
            Ok(normalize_client_fingerprint(global_client_fingerprint))
        }
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(normalize_client_fingerprint(global_client_fingerprint))
            } else if trimmed.eq_ignore_ascii_case("none") {
                if keep_none_literal {
                    Ok(Some("none".to_string()))
                } else {
                    Ok(None)
                }
            } else {
                Ok(Some(trimmed.to_ascii_lowercase()))
            }
        }
        Some(_) => Err(format!("{context}: client-fingerprint must be a string")),
    }
}

pub fn parse_proxy(
    config: &HashMap<String, serde_json::Value>,
    ipv6: bool,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let dialer: std::sync::Arc<dyn meow_proxy::dialer::TcpDialer> =
        std::sync::Arc::new(meow_proxy::dialer::DirectDialer);
    parse_proxy_with_dialer_and_fp(config, &dialer, ipv6, None)
}

/// [`parse_proxy`] for a static `proxies:` entry. A `type: direct` entry
/// without its own `dns:` also follows `resolver`'s
/// `dns.direct-nameserver`, like the built-in DIRECT
/// ([`DirectAdapter::with_direct_resolver_slot`]).
/// `global_client_fingerprint` is the config's top-level
/// `global-client-fingerprint` (issue #974).
pub(crate) fn parse_static_proxy(
    config: &HashMap<String, serde_json::Value>,
    ipv6: bool,
    resolver: Option<&meow_dns::ResolverSlot>,
    global_client_fingerprint: Option<&str>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    match (config.get("type").and_then(|v| v.as_str()), resolver) {
        (Some("direct"), Some(slot)) => {
            let name = config
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or("missing proxy name")?;
            let adapter = parse_direct(name, config, ipv6, Some(slot))?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(parse_node_dialer_opts(config, name)?),
            ))
        }
        _ => {
            let dialer: std::sync::Arc<dyn meow_proxy::dialer::TcpDialer> =
                std::sync::Arc::new(meow_proxy::dialer::DirectDialer);
            parse_proxy_with_dialer_and_fp(config, &dialer, ipv6, global_client_fingerprint)
        }
    }
}

/// A TT node that fails to parse must stay *bound* even in lenient mode —
/// to a dead placeholder, never dropped. Dropping the requested transport
/// can make a group select DIRECT, i.e. send the flow out in plaintext.
/// This check deliberately remains available when the feature is disabled.
pub(crate) fn node_is_trusttunnel(config: &HashMap<String, serde_json::Value>) -> bool {
    config
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("trusttunnel"))
}

/// Whether `config` describes an `ss` node whose reserved built-in `plugin:`
/// names a cargo feature this build lacks — same class of failure as
/// [`node_is_trusttunnel`]: the node can never parse, but dropping it would
/// let a `select` group or an explicit `MATCH`/`dialer-proxy` reference
/// shift that traffic to a sibling or DIRECT, so callers keep it bound to a
/// dead placeholder instead (liveness-checked groups skip the dead entry
/// like any unavailable member). The adapter's "not compiled into this
/// build" error becomes the placeholder's reason. This check
/// deliberately remains available when the feature is disabled — it reads
/// the raw node, so it needs no error identity across the `String` boundary.
pub(crate) fn node_needs_missing_plugin(config: &HashMap<String, serde_json::Value>) -> bool {
    #[cfg(feature = "ss")]
    {
        // `type` is lenient like `node_is_trusttunnel`'s — the dispatch is
        // exact, so a `"Ss "`/`"SS"` node fails parsing anyway; keeping the
        // classifier forgiving lets the placeholder still cover the group
        // fallback hole instead of warn-dropping the node.
        config
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("ss"))
            && config
                .get("plugin")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|plugin| {
                    meow_proxy::shadowsocks_adapter::missing_plugin_feature(plugin).is_some()
                })
    }
    #[cfg(not(feature = "ss"))]
    {
        let _ = config;
        false
    }
}

/// The [`AdapterType`] a failed node's dead placeholder must keep, when
/// dropping the node would silently reroute its group's traffic: trusttunnel
/// nodes ([`node_is_trusttunnel`]) and `ss` nodes whose built-in plugin's
/// cargo feature is compiled out ([`node_needs_missing_plugin`]). `None`
/// for ordinary parse failures, which stay warn-and-drop.
pub(crate) fn placeholder_adapter_type(
    config: &HashMap<String, serde_json::Value>,
) -> Option<AdapterType> {
    if node_is_trusttunnel(config) {
        Some(AdapterType::TrustTunnel)
    } else if node_needs_missing_plugin(config) {
        Some(AdapterType::Shadowsocks)
    } else {
        None
    }
}

/// Whether `config` describes an `ss` node whose `plugin:` names an external
/// SIP003 executable — i.e. one that would reach `Command::new` during
/// adapter construction. Gates untrusted node sources (proxy-providers,
/// subscriptions) before the trusted local path (issue #513).
pub fn node_selects_external_plugin(config: &HashMap<String, serde_json::Value>) -> bool {
    #[cfg(feature = "ss")]
    {
        config.get("type").and_then(|v| v.as_str()) == Some("ss")
            && is_external_sip003_plugin(config.get("plugin").and_then(|v| v.as_str()))
    }
    #[cfg(not(feature = "ss"))]
    {
        let _ = config;
        false
    }
}

/// [`parse_proxy`] for remote-controlled input (proxy-provider payloads).
///
/// Without `allow_external_plugin`, an `ss` node whose `plugin:` names an
/// external SIP003 executable is rejected: that name reaches `Command::new`
/// during adapter construction, so provider content would select a local
/// binary (issue #513). Built-in/in-process plugins (`obfs`,
/// `simple-obfs`, `v2ray-plugin`, `gost-plugin`, `shadow-tls`, `restls`, `jls`,
/// `kcptun`, `ech-tls-tunnel`) stay allowed — mihomo
/// implements those in-process too, so gating them would diverge.  A built-in
/// name whose cargo feature is compiled out still counts as built-in here
/// (reserved name): the adapter then fails construction with a clean
/// "not compiled into this build" error instead of spawning an executable.
///
/// `dialer` is the pluggable TCP dialer the node's adapter dials its server
/// through — [`meow_proxy::dialer::DirectDialer`] for an unchained node, or a
/// [`meow_proxy::dialer::NamedProxyDialer`] when the node declares
/// `dialer-proxy` (issue #489).
pub fn parse_proxy_provider_node(
    config: &HashMap<String, serde_json::Value>,
    ipv6: bool,
    allow_external_plugin: bool,
    dialer: &std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_provider_node_with_fp(config, ipv6, allow_external_plugin, dialer, None)
}

/// [`parse_proxy_provider_node`] honoring the config's top-level
/// `global-client-fingerprint` (issue #974): the provider snapshot is
/// parsed under the fingerprint committed for that config load, so a
/// fingerprint change forces the provider adapters to rebuild.
pub fn parse_proxy_provider_node_with_fp(
    config: &HashMap<String, serde_json::Value>,
    ipv6: bool,
    allow_external_plugin: bool,
    dialer: &std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>,
    global_client_fingerprint: Option<&str>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    if !allow_external_plugin && node_selects_external_plugin(config) {
        let name = config.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let plugin = config.get("plugin").and_then(|v| v.as_str()).unwrap_or("");
        return Err(format!(
            "ss[{name}]: external SIP003 plugin '{plugin}' is not allowed on \
             provider-sourced nodes — it spawns a local executable selected by \
             remote content (issue #513); set the provider's \
             `allow-external-plugin: true` to opt in"
        ));
    }
    let _ = allow_external_plugin;
    parse_proxy_with_dialer_and_fp(config, dialer, ipv6, global_client_fingerprint)
}

/// Like [parse_proxy] but injects a custom [meow_proxy::dialer::TcpDialer]
/// into every adapter. Used by the `dialer-proxy` single-parse path in
/// `insert_parsed_leaves` — and by provider node parsing (issue #489) — to
/// inject a [meow_proxy::dialer::NamedProxyDialer] so that dialer-proxy
/// chaining works for all protocols without requiring connect_over.
pub fn parse_proxy_with_dialer(
    config: &HashMap<String, serde_json::Value>,
    dialer: &std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>,
    ipv6: bool,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_with_dialer_and_fp(config, dialer, ipv6, None)
}

/// [`parse_proxy_with_dialer`] honoring the config's top-level
/// `global-client-fingerprint` (issue #974). The fingerprint is baked
/// into the adapters this call constructs — there is no runtime global.
pub fn parse_proxy_with_dialer_and_fp(
    config: &HashMap<String, serde_json::Value>,
    dialer: &std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>,
    ipv6: bool,
    global_client_fingerprint: Option<&str>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let name = config
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("missing proxy name")?;
    let proxy_type = config
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or("missing proxy type")?;
    // The shared per-node dialer fields (issue #974) — protocol-agnostic,
    // so they parse once before the type dispatch and attach to whichever
    // wrapper the leaf produces. Provider nodes reach the same fields
    // through this single parse path.
    let node_opts = parse_node_dialer_opts(config, name)?;
    // Every consumer arm below is feature-gated; a build with none of the
    // uTLS-aware protocols compiled in would otherwise warn it unused.
    let _ = global_client_fingerprint;

    match proxy_type {
        #[cfg(feature = "trusttunnel")]
        "trusttunnel" => {
            parse_trusttunnel(name, config, dialer, node_opts, global_client_fingerprint)
        }
        #[cfg(feature = "ss")]
        "ss" => {
            let server = config
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or("missing server")?;
            let port = required_port(config, "ss")?;
            let password = config
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or("missing password")?;
            let cipher = config
                .get("cipher")
                .and_then(|v| v.as_str())
                .ok_or("missing cipher")?;
            let udp = config
                .get("udp")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            // A present-but-non-string `plugin:` is a malformed node, not
            // "no plugin": silently treating it as absent would dial a
            // plain SS while the operator asked for a transport plugin.
            // `null` is the exception — Go's `Plugin string` field
            // unmarshals null to the zero value, so `plugin: null` means
            // unset exactly like an absent key (mihomo parity).
            let plugin = match config.get("plugin") {
                None | Some(serde_json::Value::Null) => None,
                Some(value) => Some(value.as_str().ok_or("ss: `plugin` must be a string")?),
            };
            let plugin_opts_str = config.get("plugin-opts").and_then(serialize_plugin_opts);
            let client_fingerprint =
                resolve_node_client_fingerprint(config, "ss", global_client_fingerprint, false)?;

            // A SIP003 *external* plugin is a local subprocess spawned by
            // `ShadowsocksAdapter::new`, and the adapter deliberately dials it
            // over loopback without the pluggable dialer.  Bail out *before*
            // constructing so the chained parse never spawns a copy of the
            // plugin process the direct re-parse then spawns again, and so
            // the user learns their `dialer-proxy` has no effect here.
            if dialer.is_proxy() && is_external_sip003_plugin(plugin) {
                return Err(format!(
                    "ss[{name}]: `dialer-proxy` is not supported with the external \
                     SIP003 plugin '{}' — the plugin runs as a local subprocess and \
                     is always reached over loopback",
                    plugin.unwrap_or_default()
                ));
            }

            if is_external_sip003_plugin(plugin) && !crate::external_plugins_allowed() {
                return Err(format!(
                    "ss[{name}]: external plugins are disabled by process policy"
                ));
            }
            // Validation constructs adapters, but must never execute a plugin.
            let plugin = if crate::is_offline_validate() && is_external_sip003_plugin(plugin) {
                None
            } else {
                plugin
            };

            #[cfg_attr(not(feature = "mux"), allow(unused_mut))]
            let mut adapter = ShadowsocksAdapter::new(
                name,
                server,
                port,
                password,
                cipher,
                udp,
                plugin,
                plugin_opts_str.as_deref(),
                client_fingerprint.as_deref(),
                Arc::clone(dialer),
            )
            .map_err(|e| format!("ss: {e}"))?;
            #[cfg(feature = "mux")]
            if let Some(mux_options) = parse_mux_options(name, config)? {
                // muxcool rides VLESS CommandMux; shadowsocks has no
                // equivalent signaling — reject loudly instead of speaking
                // garbage frames to the server.
                if mux_options.protocol == meow_proxy::mux::Protocol::MuxCool {
                    return Err(format!(
                        "{name}: mux protocol 'muxcool' is VLESS/VMess-only; \
                         use smux/yamux/h2mux for shadowsocks nodes"
                    ));
                }
                adapter = adapter.with_mux(mux_options);
            }
            #[cfg(not(feature = "mux"))]
            parse_mux_options(name, config)?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        #[cfg(feature = "trojan")]
        "trojan" => {
            let server = config
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or("missing server")?;
            let port = required_port(config, "trojan")?;
            let password = config
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or("missing password")?;
            let sni = config.get("sni").and_then(|v| v.as_str()).unwrap_or("");
            let skip_verify = config
                .get("skip-cert-verify")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let udp = config
                .get("udp")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);

            #[cfg_attr(not(feature = "mux"), allow(unused_mut))]
            let mut adapter = TrojanAdapter::new(
                name,
                server,
                port,
                password,
                sni,
                skip_verify,
                udp,
                Arc::clone(dialer),
            );
            #[cfg(feature = "mux")]
            if let Some(mux_options) = parse_mux_options(name, config)? {
                // muxcool rides VLESS CommandMux; trojan has no equivalent
                // signaling (its CommandMux=0x7f is smux) — reject loudly
                // instead of speaking garbage frames to the server.
                if mux_options.protocol == meow_proxy::mux::Protocol::MuxCool {
                    return Err(format!(
                        "{name}: mux protocol 'muxcool' is VLESS/VMess-only; \
                         use smux/yamux/h2mux for trojan nodes"
                    ));
                }
                adapter = adapter.with_mux(mux_options);
            }
            #[cfg(not(feature = "mux"))]
            parse_mux_options(name, config)?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        #[cfg(feature = "vless")]
        "vless" => {
            let adapter = parse_vless(name, config, dialer, global_client_fingerprint)?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        "http" => {
            let adapter = parse_http(name, config, dialer)?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        "socks5" => {
            let adapter = parse_socks5(name, config, dialer)?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        "direct" => {
            reject_unthreaded_dialer(name, "direct", dialer)?;
            let adapter = parse_direct(name, config, ipv6, None)?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter)).with_node_dialer_opts(node_opts),
            ))
        }
        #[cfg(feature = "anytls")]
        "anytls" => {
            let adapter = parse_anytls(name, config, global_client_fingerprint)?;
            // WireGuard-shaped injection: a proxy dialer becomes the
            // client's per-session transport dialer — the raw chained
            // stream the client layers its own TLS + session pool on — so
            // injected sessions pool like direct ones and `udp: true` UoT
            // rides the chain. The no-op `DirectDialer` keeps the built-in
            // connect path.
            let adapter = if dialer.is_proxy() {
                adapter.with_dialer(Arc::clone(dialer))
            } else {
                adapter
            };
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        #[cfg(feature = "hysteria2")]
        "hysteria2" => {
            // A `dialer-proxy` chain carries the QUIC endpoint's UDP
            // transport through the front hop's UDP association (issue
            // #899 follow-up, the WireGuard precedent). Any proxy dialer
            // is accepted here — no `supports_udp` gate: that flag
            // answers `false` for an unresolved group target, which would
            // kill legal group fronts at parse time. A UDP-less front
            // fails `dial_udp_conn` at runtime, closed like any other
            // endpoint bind error.
            let adapter = parse_hysteria2(name, config, dialer)?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        #[cfg(feature = "vmess")]
        "vmess" => {
            let adapter = parse_vmess(name, config, dialer, global_client_fingerprint)?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        #[cfg(feature = "snell")]
        "snell" => {
            let adapter = parse_snell(name, config, dialer)?;
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        // WireGuard accepts the mihomo spellings "wireguard" and
        // "WireGuard" (docs/wireguard.md field table).
        #[cfg(feature = "wireguard")]
        "wireguard" | "WireGuard" => {
            let adapter = parse_wireguard(name, config)?;
            // A `dialer-proxy` chain carries the WG endpoint's UDP
            // transport through the front hop's UDP association (issue
            // #899). Any proxy dialer is accepted here — no
            // `supports_udp` gate: that flag answers `false` for an
            // unresolved group target, which would kill legal group
            // fronts at parse time. A UDP-less front fails
            // `dial_udp_conn` at runtime, closed like any other
            // endpoint bind error. `dialing_through` attaches the
            // DialerHop so `front_hop` metrics name the member.
            let adapter = if dialer.is_proxy() {
                adapter.with_dialer(Arc::clone(dialer))
            } else {
                adapter
            };
            Ok(Arc::new(
                WrappedProxy::new(Box::new(adapter))
                    .with_node_dialer_opts(node_opts)
                    .dialing_through(config, dialer),
            ))
        }
        #[cfg(not(feature = "trusttunnel"))]
        "trusttunnel" => Err(feature_gated_proxy_type("trusttunnel")),
        #[cfg(not(feature = "ss"))]
        "ss" => Err(feature_gated_proxy_type("ss")),
        #[cfg(not(feature = "trojan"))]
        "trojan" => Err(feature_gated_proxy_type("trojan")),
        #[cfg(not(feature = "vless"))]
        "vless" => Err(feature_gated_proxy_type("vless")),
        #[cfg(not(feature = "anytls"))]
        "anytls" => Err(feature_gated_proxy_type("anytls")),
        #[cfg(not(feature = "hysteria2"))]
        "hysteria2" => Err(feature_gated_proxy_type("hysteria2")),
        #[cfg(not(feature = "vmess"))]
        "vmess" => Err(feature_gated_proxy_type("vmess")),
        #[cfg(not(feature = "snell"))]
        "snell" => Err(feature_gated_proxy_type("snell")),
        #[cfg(not(feature = "wireguard"))]
        "wireguard" | "WireGuard" => Err(feature_gated_proxy_type("wireguard")),
        // `node_is_trusttunnel` trims and ignores case; this dispatch is
        // exact, like mihomo's. Without this arm a ` trusttunnel ` or
        // `TrustTunnel` node reports a generic "unsupported proxy type"
        // while still being *treated* as a TT node by that gate — name the
        // actual defect instead of leaving two strings to diff by eye.
        _ if proxy_type != "trusttunnel"
            && proxy_type.trim().eq_ignore_ascii_case("trusttunnel") =>
        {
            Err(format!(
                "proxy type {proxy_type:?} must be spelled exactly \"trusttunnel\" \
                 — lowercase, with no surrounding whitespace"
            ))
        }
        _ => Err(format!("unsupported proxy type: {proxy_type}")),
    }
}

/// Whether `plugin` names a SIP003 plugin that runs as an external subprocess
/// (as opposed to one of the built-in, in-process plugin implementations).
///
/// Mirrors the dispatch in `ShadowsocksAdapter::new`: anything not recognised
/// as built-in is handed to `Plugin::start`, which spawns a child process.
#[cfg(feature = "ss")]
fn is_external_sip003_plugin(plugin: Option<&str>) -> bool {
    plugin
        .filter(|p| !p.is_empty())
        .is_some_and(|p| !meow_proxy::shadowsocks_adapter::is_builtin_sip003_plugin(p))
}

/// Reject a `ProxyDialer` for adapter types that do not thread it through.
///
/// `direct` is a raw egress by definition — a resolver-threaded dial
/// belongs on the real source path — so accepting an injected dialer here
/// would silently drop the user's `dialer-proxy` and egress from the real
/// source path — a Class A silent divergence (ADR-0002).  Returning `Err`
/// instead lets the `dialer-proxy` leaf parse fall back to the
/// relay-based `DialerProxyAdapter` wrapper, which fails loudly at dial
/// time rather than pretending the chain was applied or dialing direct.
///
/// A `DirectDialer` is always accepted: it is the no-op default, so nothing
/// is lost by ignoring it.
fn reject_unthreaded_dialer(
    name: &str,
    proxy_type: &str,
    dialer: &std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<(), String> {
    if dialer.is_proxy() {
        return Err(format!(
            "{proxy_type}[{name}]: `dialer-proxy` is not supported for this \
             proxy type (its underlying connection is not established through \
             the pluggable TCP dialer)"
        ));
    }
    Ok(())
}

/// Error for a proxy type this codebase implements but which was compiled out
/// of the running binary. The generic "unsupported proxy type" message made
/// users think the protocol was missing entirely, when the actual fix is to
/// use a full-featured build (issue #390).
#[cfg(not(all(
    feature = "ss",
    feature = "trojan",
    feature = "vless",
    feature = "anytls",
    feature = "hysteria2",
    feature = "vmess",
    feature = "snell",
    feature = "trusttunnel",
    feature = "wireguard"
)))]
fn feature_gated_proxy_type(proxy_type: &str) -> String {
    if proxy_type == "trusttunnel" {
        return "proxy type 'trusttunnel' is not compiled into this build; rebuild with `--features trusttunnel` (the protocol is opt-in and excluded from full)".into();
    }
    format!(
        "proxy type '{proxy_type}' is not compiled into this build; \
         use an official release binary or rebuild with `--features full` \
         (or `--features {proxy_type}`)"
    )
}

/// Parse a `type: snell` proxy block.
///
/// Mihomo-compatible Snell outbound. v3 uses the legacy Snell AEAD stream;
/// v4/v5 use the newer Snell v4 TCP wire (v5 is client-side compatible).
///
/// YAML schema (mihomo-compatible):
///
/// ```yaml
/// - name: my-snell
///   type: snell
///   server: 1.2.3.4
///   port: 443
///   psk: shared-secret
///   version: 4         # optional; default 4. Accepts 3–6, "v3" … "v6".
///   udp: true          # optional; UDP-over-TCP relay.
///   reuse: true        # optional; CommandConnectV2 + connection pool.
///   mode: default      # v6 only; must match the server: default | unshaped | unsafe-raw
///   obfs-opts:         # optional, v3–v5 only
///     mode: http       # off (default) | http | tls
///     host: bing.com   # falls back to server when missing
/// ```
///
/// # Hard errors (Class A per ADR-0002)
///
/// - missing `server`, `port`, or `psk` — required by the protocol.
/// - `port == 0` — never a valid endpoint.
/// - empty `psk` — caught by [`meow_proxy::SnellAdapter::new`].
/// - `version` ∈ {1, 2} — this adapter does not implement those wires.
/// - `obfs-opts.mode` is not one of off / http / tls.
/// - `mode` on a version other than 6, or not one of default / unshaped /
///   unsafe-raw.
/// - an obfs mode other than off with version 6 (v6 servers have none).
#[cfg(feature = "snell")]
fn parse_snell(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<meow_proxy::SnellAdapter, String> {
    use meow_proxy::{SnellAdapter, SnellObfs, SnellV6Mode, SnellVersion};

    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("snell[{name}]: missing server"))?;
    let port = required_port(config, &format!("snell[{name}]"))?;
    let psk = config
        .get("psk")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("snell[{name}]: missing psk"))?;

    let udp = config
        .get("udp")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let reuse = config
        .get("reuse")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    // ── Version parsing ──────────────────────────────────────────────────
    let version = match config.get("version") {
        None => SnellVersion::V4,
        Some(v) => {
            // Accept ints (1..=6) or strings ("v4", "5", ...).
            let label = if let Some(n) = v.as_u64() {
                n.to_string()
            } else if let Some(s) = v.as_str() {
                s.to_string()
            } else {
                return Err(format!(
                    "snell[{name}]: version must be an integer or string (3, 4, 5 or 6)"
                ));
            };
            match label.trim().to_ascii_lowercase().as_str() {
                "3" | "v3" => SnellVersion::V3,
                "" | "4" | "v4" => SnellVersion::V4,
                "5" | "v5" => SnellVersion::V5,
                "6" | "v6" => SnellVersion::V6,
                "1" | "2" | "v1" | "v2" => {
                    return Err(format!(
                        "snell[{name}]: version '{label}' is not supported; \
                         this adapter implements Snell v3 / v4 / v5 / v6 only"
                    ));
                }
                other => {
                    return Err(format!(
                        "snell[{name}]: unknown version '{other}'; valid: 3, 4, 5, 6"
                    ));
                }
            }
        }
    };

    // ── Obfs opts ────────────────────────────────────────────────────────
    let obfs = if let Some(opts) = config.get("obfs-opts") {
        let mode = opts
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("off")
            .to_ascii_lowercase();
        // Trim for parity with the SS `plugin-opts` path (which trims each
        // `k=v` value) — `host: " bing.com "` should not hard-error.
        let host = opts
            .get("host")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map_or_else(|| server.to_string(), std::string::ToString::to_string);
        match mode.as_str() {
            "off" | "none" | "" => SnellObfs::None,
            "http" | "tls" => {
                // `host` lands verbatim in the emitted `Host:` header
                // (http) or SNI (tls) — reject injectable bytes up front
                // (issue #648). `HttpObfs::new` re-checks at wrap time.
                if !meow_transport::simple_obfs::client::is_valid_obfs_host(&host) {
                    return Err(format!(
                        "snell[{name}]: obfs-opts.host is empty, over 253 bytes, or contains whitespace/control bytes"
                    ));
                }
                match mode.as_str() {
                    "http" => SnellObfs::Http { host },
                    _ => SnellObfs::Tls { server: host },
                }
            }
            other => {
                return Err(format!(
                    "snell[{name}]: obfs-opts.mode '{other}' invalid; expected one of off, http, tls"
                ));
            }
        }
    } else {
        SnellObfs::None
    };

    // ── v6 options ───────────────────────────────────────────────────────
    let v6 = version == SnellVersion::V6;
    if v6 && !matches!(obfs, SnellObfs::None) {
        return Err(format!(
            "snell[{name}]: obfs-opts is not supported by snell v6"
        ));
    }
    let mode = match config.get("mode") {
        None => None,
        Some(_) if !v6 => {
            return Err(format!(
                "snell[{name}]: mode is a snell v6 option; set version: 6"
            ));
        }
        Some(v) => {
            let label = v
                .as_str()
                .ok_or_else(|| format!("snell[{name}]: mode must be a string"))?;
            Some(
                SnellV6Mode::parse(&label.trim().to_ascii_lowercase()).ok_or_else(|| {
                    format!(
                        "snell[{name}]: mode '{label}' invalid; expected one of default, unshaped, unsafe-raw"
                    )
                })?,
            )
        }
    };

    let adapter = SnellAdapter::new(
        name,
        server,
        port,
        psk,
        obfs,
        version,
        udp,
        reuse,
        Arc::clone(dialer),
    )
    .map_err(|e| format!("snell[{name}]: {e}"))?;
    match mode {
        Some(mode) => adapter
            .with_v6_mode(mode)
            .map_err(|e| format!("snell[{name}]: {e}")),
        None => Ok(adapter),
    }
}

/// Parse a `type: http` proxy config block into an `HttpAdapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `username` set without `password` (or vice versa) — orphaned credential.
///
/// # Notes
///
/// `headers:` entries are injected into the CONNECT request only.
///
/// upstream: `adapter/outbound/http.go`
fn parse_http(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<HttpAdapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("http: missing server")?;
    let port = required_port(config, "http")?;
    let tls = config
        .get("tls")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    // Both username and password must be set, or neither (Class A).
    let username = config.get("username").and_then(|v| v.as_str());
    let password = config.get("password").and_then(|v| v.as_str());
    let auth = match (username, password) {
        (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
        (None, None) => None,
        _ => {
            return Err("http: both 'username' and 'password' must be set, or neither".to_string());
        }
    };

    // Parse optional headers map. The entries are re-serialized into every
    // CONNECT request, so a giant provider-supplied map is attacker-chosen
    // process memory — same bound as xhttp/http-upgrade (issue #648).
    let extra_headers: Vec<(String, String)> =
        match config.get("headers").and_then(|v| v.as_object()) {
            Some(m) => {
                if m.len() > meow_transport::MAX_EXTRA_HEADERS {
                    return Err(format!(
                        "http[{name}]: headers has {} entries (max {})",
                        m.len(),
                        meow_transport::MAX_EXTRA_HEADERS
                    ));
                }
                m.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                    .collect()
            }
            None => Vec::new(),
        };

    Ok(HttpAdapter::new(
        name,
        server,
        port,
        auth,
        tls,
        skip_cert_verify,
        extra_headers,
        Arc::clone(dialer),
    ))
}

/// Parse a `type: socks5` proxy config block into a `Socks5Adapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `username` set without `password` (or vice versa) — orphaned credential.
///
/// `udp: true` enables SOCKS5 UDP ASSOCIATE (HTTP/3 / QUIC relay).
///
/// upstream: `adapter/outbound/socks5.go`
fn parse_socks5(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<Socks5Adapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("socks5: missing server")?;
    let port = required_port(config, "socks5")?;
    let tls = config
        .get("tls")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    // Both username and password must be set, or neither (Class A).
    let username = config.get("username").and_then(|v| v.as_str());
    let password = config.get("password").and_then(|v| v.as_str());
    let auth = match (username, password) {
        (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
        (None, None) => None,
        _ => {
            return Err(
                "socks5: both 'username' and 'password' must be set, or neither".to_string(),
            );
        }
    };

    let udp = config
        .get("udp")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    Ok(Socks5Adapter::new(
        name,
        server,
        port,
        auth,
        tls,
        skip_cert_verify,
        Arc::clone(dialer),
    )
    .with_udp(udp))
}

/// Parse a `type: direct` proxy block into a [`DirectAdapter`].
///
/// Accepts an optional `dns:` field — a single `host:port` string or a list
/// of them — that scopes hostname resolution for this proxy to the given DNS
/// servers (plain UDP). Closes #67: lets users route a subset of direct
/// traffic through a different DNS than the global resolver (e.g. a LAN
/// resolver for `*.local` while the global resolver handles WAN).
///
/// `dns:` entries must include an explicit port (`:53` is conventional).
/// Hard error (Class A per ADR-0002) on an unparseable address — silently
/// falling back to the global resolver would surprise the user by leaking
/// queries.
fn parse_direct(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    ipv6: bool,
    direct_slot: Option<&meow_dns::ResolverSlot>,
) -> std::result::Result<DirectAdapter, String> {
    use meow_common::DnsMode;
    use meow_dns::Resolver;
    use meow_trie::DomainTrie;
    use std::net::{IpAddr, SocketAddr};

    let mut adapter = DirectAdapter::new();

    // Optional `connect-timeout:` (seconds) — per-proxy counterpart of the
    // global `tcp-connect-timeout:` that covers the built-in DIRECT. Hard
    // error on a non-integer (Class A per ADR-0002): silently ignoring it
    // would leave the connect unbounded when the user asked for a bound.
    if let Some(v) = config.get("connect-timeout") {
        let secs = v.as_u64().ok_or_else(|| {
            format!("direct[{name}]: connect-timeout must be a non-negative integer (seconds)")
        })?;
        // The value reaches `tokio::time::timeout` — an absurd u64 overflows
        // `Instant + Duration` and, under `panic = "abort"`, crashes the
        // process on every dial (issue #648).
        if secs > meow_common::MAX_DURATION_SECS {
            return Err(format!(
                "direct[{name}]: connect-timeout {secs}s exceeds the {}s ceiling",
                meow_common::MAX_DURATION_SECS
            ));
        }
        adapter = adapter.with_connect_timeout(std::time::Duration::from_secs(secs));
    }

    if let Some(v) = config.get("dns") {
        let entries: Vec<String> = match v {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(seq) => seq
                .iter()
                .map(|e| {
                    e.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| format!("direct[{name}]: dns entries must be strings"))
                })
                .collect::<std::result::Result<_, _>>()?,
            _ => {
                return Err(format!(
                    "direct[{name}]: dns must be a string or list of strings"
                ));
            }
        };

        let mut servers: Vec<SocketAddr> = Vec::with_capacity(entries.len());
        for entry in &entries {
            // Accept `IP` (default port 53), `IP:53`, or bracketed IPv6.
            let parsed = if let Ok(sa) = entry.parse::<SocketAddr>() {
                sa
            } else if let Ok(ip) = entry.parse::<IpAddr>() {
                SocketAddr::new(ip, 53)
            } else {
                return Err(format!(
                    "direct[{name}]: dns entry '{entry}' is not a valid IP or host:port"
                ));
            };
            servers.push(parsed);
        }

        if servers.is_empty() {
            return Err(format!("direct[{name}]: dns list is empty"));
        }

        let resolver = Arc::new(Resolver::new(
            servers,
            Vec::new(),
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            ipv6,
        ));
        adapter = adapter.with_resolver(resolver);
    } else if let Some(slot) = direct_slot {
        // No per-proxy `dns:` override — follow `dns.direct-nameserver`.
        adapter = adapter.with_direct_resolver_slot(Arc::clone(slot));
    }

    Ok(adapter)
}

/// Parse the TrustTunnel schema shared by static and provider nodes.
/// Unsupported transport and TLS policies fail before adapter construction.
/// `quic: true` selects HTTP/3 and needs the `trusttunnel-h3` feature.
#[cfg(feature = "trusttunnel")]
fn parse_trusttunnel(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
    node_opts: meow_common::NodeDialerOpts,
    global_client_fingerprint: Option<&str>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let required = |key: &str| {
        config
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("trusttunnel: missing {key}"))
    };
    let boolean = |key: &str, default: bool| -> std::result::Result<bool, String> {
        match config.get(key) {
            None | Some(serde_json::Value::Null) => Ok(default),
            Some(value) => value
                .as_bool()
                .ok_or_else(|| format!("trusttunnel: {key} must be boolean")),
        }
    };
    let quic = boolean("quic", false)?;
    #[cfg(not(feature = "trusttunnel-h3"))]
    if quic {
        return Err("trusttunnel: `quic: true` selects the HTTP/3 transport, which is not compiled into this build; rebuild with `--features trusttunnel-h3`".into());
    }
    // A `quic: true` node's `dialer-proxy` chain carries the QUIC
    // endpoint's UDP transport through the front hop's UDP association
    // (issue #899 follow-up — `TrustTunnelAdapter` hands the dialer to
    // `QuicConnector::with_dialer`); H2 keeps its TCP dialer path. No
    // `supports_udp` gate: that flag answers `false` for an unresolved
    // group target, and a UDP-less front fails `dial_udp_conn` at dial,
    // closed.
    let nonempty = |field: &str| {
        config.get(field).is_some_and(|value| match value {
            serde_json::Value::Null => false,
            serde_json::Value::String(text) => !text.is_empty(),
            serde_json::Value::Array(list) => !list.is_empty(),
            serde_json::Value::Object(map) => !map.is_empty(),
            _ => true,
        })
    };
    // These TLS declarations are not wired into this adapter. Reject
    // them before construction instead of silently weakening policy.
    for field in [
        "certificate",
        "private-key",
        "fingerprint",
        "cert-fingerprint",
        "reality-opts",
        "ech-opts",
        "curve-preferences",
        "ca",
        "ca-str",
    ] {
        if nonempty(field) {
            return Err(format!(
                "trusttunnel: this client does not implement the {field} policy"
            ));
        }
    }
    for field in ["bbr-profile", "bbr-opts", "congestion-controller", "cwnd"] {
        if nonempty(field) {
            return Err(format!(
                "trusttunnel: this client does not implement the QUIC option {field}"
            ));
        }
    }
    if quic {
        // Both are TLS policies the QUIC path structurally cannot honor:
        // there is no uTLS ClientHello shaping over quiche, and quiche
        // installs one name as *both* the SNI and the certificate's verify
        // hostname, so they cannot differ. Refusing beats silently dropping
        // a policy the operator asked for.
        for field in ["client-fingerprint", "name-cert-verify"] {
            if nonempty(field) {
                return Err(format!(
                    "trusttunnel: the HTTP/3 transport cannot honor {field}"
                ));
            }
        }
    }
    let expected_alpn = if quic { "h3" } else { "h2" };
    if let Some(alpn) = config.get("alpn").filter(|value| !value.is_null()) {
        if !alpn.as_array().is_some_and(|list| {
            list.is_empty() || (list.len() == 1 && list[0].as_str() == Some(expected_alpn))
        }) {
            return Err(format!(
                "trusttunnel: selected transport requires alpn: [{expected_alpn}]"
            ));
        }
    }
    let text = |key: &str| -> std::result::Result<Option<&str>, String> {
        match config.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(value) => value
                .as_str()
                .map(Some)
                .ok_or_else(|| format!("trusttunnel: {key} must be a string")),
        }
    };
    let server = required("server")?;
    let mut tls = meow_transport::tls::TlsConfig::new(
        text("sni")?.filter(|s| !s.is_empty()).unwrap_or(server),
    );
    tls.skip_cert_verify = boolean("skip-cert-verify", false)?;
    tls.verify_name = text("name-cert-verify")?
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    // `quic: true` already rejected a per-node `client-fingerprint` above;
    // the global fallback is TCP uTLS-only and does not apply to H3 either.
    tls.fingerprint = if quic {
        None
    } else {
        resolve_node_client_fingerprint(config, "trusttunnel", global_client_fingerprint, false)?
    };
    let mut options = meow_proxy::trusttunnel::Options::new(
        required("username")?.into(),
        required("password")?.into(),
    );
    let number = |key: &str, default: usize| -> std::result::Result<usize, String> {
        match config.get(key) {
            None | Some(serde_json::Value::Null) => Ok(default),
            Some(v) => v
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| format!("trusttunnel: invalid {key}")),
        }
    };
    let max_connections = number("max-connections", 0)?;
    let min_streams = number("min-streams", 0)?;
    let max_streams = number("max-streams", 0)?;
    // Each field is independently optional: an absent or zero one keeps its
    // `Options::new` default (8 connections / 5 active streams / 128 hard
    // per-session ceiling) instead of zeroing it. A `min_streams` of 0 means
    // "only ever reuse a fully idle session", i.e. one physical TLS + H2
    // handshake per concurrent dial — so writing a field explicitly must
    // never perform worse than leaving it out.
    if max_connections != 0 {
        options.max_connections = max_connections;
    }
    if min_streams != 0 {
        options.min_streams = min_streams;
    }
    if max_streams != 0 {
        if max_connections == 0 && min_streams == 0 {
            // Mihomo's legacy mode: `max-streams` is the count past which it
            // opens another connection, and the pool then grows without a
            // cap. Map it onto the reuse threshold and bound the pool
            // explicitly, warning rather than pretending the policies match.
            options.max_connections = 16;
            options.min_streams = max_streams;
            tracing::warn!(
                name,
                max_connections = options.max_connections,
                min_streams = options.min_streams,
                "trusttunnel: legacy pool is unbounded upstream; using bounded pool"
            );
        } else {
            // Beside the modern fields there is no upstream meaning to
            // mirror, so honor it as this client's hard per-session ceiling
            // rather than dropping it on the floor.
            options.max_streams = max_streams;
        }
    }
    options.max_streams = options.max_streams.max(options.min_streams);
    // `platform` / `app-name` are the two fields of the spec's per-stream
    // `user-agent`; `headers` can replace it outright, and anything else it
    // declares rides along on every CONNECT. Values may carry
    // `<random-string(N)>` / `<random-string(MIN-MAX)>`, re-rolled per
    // request — the padding idiom Surge spells the same way.
    if let Some(platform) = text("platform")? {
        options.platform = platform.to_owned();
    }
    if let Some(app_name) = text("app-name")? {
        options.app_name = app_name.to_owned();
    }
    let declared: Vec<(String, String)> = match config.get("headers") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(value) => value
            .as_object()
            .ok_or("trusttunnel: headers must be a map of name to value")?
            .iter()
            .map(|(key, value)| {
                // serde_json::Map keys are always strings — a YAML map key
                // that isn't a string already failed deserialization.
                let name = key.as_str();
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("trusttunnel: header '{name}' must be a string"))?;
                Ok((name.to_owned(), text.to_owned()))
            })
            .collect::<std::result::Result<_, String>>()?,
    };
    options.headers =
        meow_proxy::trusttunnel::ExtraHeaders::new(&declared, meow_transport::MAX_EXTRA_HEADERS)
            .map_err(|e| format!("trusttunnel: {e}"))?;
    options.health_check = boolean("health-check", false)?;
    if options.health_check {
        tracing::warn!(
            name,
            "trusttunnel: mihomo performs idle health checks; this client currently checks only new sessions"
        );
    }
    #[cfg(feature = "trusttunnel-h3")]
    let transport = if quic {
        meow_proxy::trusttunnel::Transport::H3
    } else {
        meow_proxy::trusttunnel::Transport::H2
    };
    #[cfg(not(feature = "trusttunnel-h3"))]
    let transport = meow_proxy::trusttunnel::Transport::H2;
    let adapter = meow_proxy::trusttunnel::TrustTunnelAdapter::new(
        name,
        server,
        required_port(config, "trusttunnel")?,
        tls,
        options,
        boolean("udp", false)?,
        transport,
        Arc::clone(dialer),
    )
    .map_err(|error| error.to_string())?;
    Ok(Arc::new(
        WrappedProxy::new(Box::new(adapter))
            .with_node_dialer_opts(node_opts)
            .dialing_through(config, dialer),
    ))
}

/// Parse a `type: anytls` proxy block into an [`AnytlsAdapter`].
///
/// Required fields: `server`, `port`, `password`. Optional: `sni`,
/// `skip-cert-verify`, `fingerprint`, `name-cert-verify`, `client-fingerprint`,
/// `alpn`, `udp`. The wire protocol itself is
/// provided by the `anytls-rs` crate.
///
/// `udp` defaults to `false`, matching mihomo's `AnyTLSOption.UDP` (the
/// adapter then relays datagrams over udp-over-tcp v2).
///
/// # Hard errors (Class A per ADR-0002)
///
/// - missing `server`, `port`, or `password` — required by the protocol.
/// - `port == 0` — never a valid endpoint.
///
/// upstream: `adapter/outbound/anytls.go`
#[cfg(feature = "anytls")]
fn parse_anytls(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    global_client_fingerprint: Option<&str>,
) -> std::result::Result<meow_proxy::AnytlsAdapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("anytls[{name}]: missing server"))?;
    let port = required_port(config, &format!("anytls[{name}]"))?;
    let password = config
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("anytls[{name}]: missing password"))?;
    let sni = config.get("sni").and_then(|v| v.as_str());
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let udp = config
        .get("udp")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    reject_unsupported_anytls_options(name, config)?;

    let optional_string = |field: &str| match config.get(field) {
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(_) => Err(format!("anytls[{name}]: {field} must be a string")),
    };
    let alpn = match config.get("alpn") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("anytls[{name}]: alpn entries must be strings"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
        Some(_) => return Err(format!("anytls[{name}]: alpn must be a string list")),
    };
    let options = meow_proxy::AnytlsTlsOptions {
        sni: sni.map(str::to_string),
        skip_cert_verify,
        fingerprint: optional_string("fingerprint")?,
        name_cert_verify: optional_string("name-cert-verify")?,
        client_fingerprint: resolve_node_client_fingerprint(
            config,
            &format!("anytls[{name}]"),
            global_client_fingerprint,
            false,
        )?,
        alpn,
    };
    meow_proxy::AnytlsAdapter::new_with_tls(name, server, port, password, &options, udp)
}

/// Refuse the AnyTLS options that change security properties and that the
/// Rust backend cannot honour (issue #870), and warn once about the purely
/// behavioural mihomo fields it ignores. Mirrors hysteria2: an enabled
/// `ech-opts` or any `certificate`/`private-key` is a load error (silently
/// dropping them would leak the SNI / send no client certificate).
#[cfg(feature = "anytls")]
fn reject_unsupported_anytls_options(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
) -> std::result::Result<(), String> {
    if let Some(value) = config.get("ech-opts") {
        let enabled = value
            .as_object()
            .and_then(|map| map.get("enable"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        if enabled {
            return Err(format!(
                "anytls[{name}]: 'ech-opts' is not supported by the Rust backend \
                 (the SNI would be sent in the clear)"
            ));
        }
    }
    for key in ["certificate", "private-key"] {
        if config.contains_key(key) {
            return Err(format!(
                "anytls[{name}]: '{key}' is not supported by the Rust backend"
            ));
        }
    }
    let ignored: Vec<&str> = [
        "shadow-tls-opts",
        "restls-opts",
        "jls-opts",
        "client-metadata",
        "idle-session-check-interval",
        "idle-session-timeout",
        "min-idle-session",
        "disable-reuse",
    ]
    .into_iter()
    .filter(|key| config.get(*key).is_some_and(|v| !v.is_null()))
    .collect();
    if !ignored.is_empty() {
        tracing::warn!(
            name,
            ignored = %ignored.join(", "),
            "anytls: ignoring options not supported by the Rust backend"
        );
    }
    Ok(())
}

/// Parse a `type: hysteria2` proxy block.
///
/// Required fields: `server`, `password`, and a port source — either `port`
/// or a concrete `ports` hopping range (mihomo accepts either, and airport
/// subscriptions commonly omit `port` when `ports` is set; issue #377).
/// Optional fields follow the mihomo surface supported by the in-tree Rust
/// backend: `up`, `down`, `obfs: salamander | gecko`, `obfs-password`,
/// `obfs-min-packet-size` / `obfs-max-packet-size` (gecko only), `ports`,
/// `hop-interval`, `sni`, `skip-cert-verify`, `fingerprint`, `udp`,
/// `fast-open`, the four `*-receive-window` keys (bytes; `0`/absent
/// is unset — a present non-integer value is a hard error), and
/// `quic-connections` — a meow-rs extension with no mihomo equivalent.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - missing `server` or `password`.
/// - no usable port: `port` absent (or 0) and `ports` absent or wildcard.
/// - `port == 0` with no `ports` (mihomo: "invalid port").
/// - empty `password` — caught downstream by `Hy2Adapter::new`.
/// - gecko packet sizes outside `min <= max <= 2048`.
/// - unsupported security/transport options (mTLS, ECH, realm).
///
/// upstream: `adapter/outbound/hysteria2.go`
#[cfg(feature = "hysteria2")]
fn parse_hysteria2(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<meow_proxy::Hy2Adapter, String> {
    use meow_proxy::{Hy2HopInterval, Hy2Options};

    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("hysteria2[{name}]: missing server"))?;
    let ports = optional_nonempty_str(config, "ports");
    if let Some(ports) = &ports {
        validate_hy2_ports(name, ports)?;
    }
    let port = hy2_dial_port(name, config, ports.as_deref())?;
    let password = config
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("hysteria2[{name}]: missing password"))?;
    let sni = config.get("sni").and_then(|v| v.as_str());
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let udp = config
        .get("udp")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let up_bps = parse_hy2_bandwidth_field(name, "up", config.get("up"))?;
    let down_bps = parse_hy2_bandwidth_field(name, "down", config.get("down"))?;

    let obfs = parse_hy2_obfs(name, config)?;
    let obfs_password = optional_nonempty_str(config, "obfs-password");
    if obfs.is_some() && obfs_password.is_none() {
        return Err(format!("hysteria2[{name}]: missing obfs-password"));
    }

    let mut hop_interval = parse_hy2_hop_interval(name, config.get("hop-interval"))?;
    let mut ports = ports;
    // A `dialer-proxy` chain binds the QUIC connection to one front UDP
    // association — a connected endpoint has no second port to hop to.
    // Hopping config is legal beside it, so warn and drop it rather than
    // reject: the driver also skips `HopState` on an injected endpoint.
    if dialer.is_proxy() && (ports.is_some() || hop_interval.is_some()) {
        tracing::warn!(
            "hysteria2[{name}]: `ports`/`hop-interval` are ignored with `dialer-proxy` \
             — a front association is bound to a single peer port and cannot hop"
        );
        ports = None;
        hop_interval = None;
    }
    let fingerprint = parse_hy2_fingerprint(name, config.get("fingerprint"))?;
    let fast_open = config
        .get("fast-open")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    validate_hy2_alpn(name, config.get("alpn"))?;
    reject_unsupported_hy2_options(name, config)?;
    // mihomo treats an absent or zero window as unset; a present value of
    // the wrong type is a config error, not a silent default.
    let window = |key: &str| -> std::result::Result<Option<u64>, String> {
        let Some(value) = config.get(key).filter(|v| !v.is_null()) else {
            return Ok(None);
        };
        let n = value.as_u64().ok_or_else(|| {
            format!("hysteria2[{name}]: '{key}' must be an unsigned integer (bytes)")
        })?;
        Ok((n > 0).then_some(n))
    };
    let windows = meow_proxy::Hy2ReceiveWindows {
        initial_stream: window("initial-stream-receive-window")?,
        max_stream: window("max-stream-receive-window")?,
        initial_conn: window("initial-connection-receive-window")?,
        max_conn: window("max-connection-receive-window")?,
    };
    let quic_connections = parse_hy2_quic_connections(name, config.get("quic-connections"))?;

    meow_proxy::Hy2Adapter::new(
        Hy2Options {
            name: name.to_string(),
            server: server.to_string(),
            port,
            password: password.to_string(),
            sni: sni.map(str::to_string),
            skip_cert_verify,
            udp,
            up_bps,
            down_bps,
            obfs,
            obfs_password,
            ports,
            hop_interval: hop_interval
                .map(|(min_secs, max_secs)| Hy2HopInterval { min_secs, max_secs }),
            fingerprint,
            fast_open,
            windows,
            quic_connections,
        },
        Some(Arc::clone(dialer)),
    )
}

/// `quic-connections` (performance spec ITEM A): the K-way QUIC
/// connection-pool width — `K` independent connections, each with its own
/// quiche driver task, round-robin new streams and UDP sessions. Absent
/// resolves to [`meow_proxy::DEFAULT_QUIC_CONNECTIONS`]; a present
/// non-integer is a hard error. The value clamps to
/// `1..=`[`meow_proxy::MAX_QUIC_CONNECTIONS`], warning when the clamp
/// bites or above 4 — extra driver tasks rarely pay off past that.
///
/// Constraint worth repeating at the config surface: a single flow still
/// rides one connection — this widens *aggregate* throughput only.
#[cfg(feature = "hysteria2")]
fn parse_hy2_quic_connections(
    name: &str,
    value: Option<&serde_json::Value>,
) -> std::result::Result<Option<usize>, String> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let n = value.as_u64().ok_or_else(|| {
        format!("hysteria2[{name}]: 'quic-connections' must be an unsigned integer")
    })?;
    let n = usize::try_from(n).unwrap_or(usize::MAX);
    let clamped = n.clamp(1, meow_proxy::MAX_QUIC_CONNECTIONS);
    if clamped != n {
        tracing::warn!(
            "hysteria2[{name}]: 'quic-connections' {n} out of range, clamped to {clamped}"
        );
    }
    if clamped > 4 {
        tracing::warn!(
            "hysteria2[{name}]: 'quic-connections' {clamped} exceeds 4 — each connection \
             costs a driver task; larger pools rarely add aggregate throughput"
        );
    }
    Ok(Some(clamped))
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_obfs(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
) -> std::result::Result<Option<meow_proxy::Hy2Obfs>, String> {
    use meow_proxy::Hy2Obfs;

    match optional_nonempty_str(config, "obfs").as_deref() {
        None => Ok(None),
        Some("salamander") => Ok(Some(Hy2Obfs::Salamander)),
        Some("gecko") => Ok(Some(Hy2Obfs::Gecko {
            min_packet_size: parse_hy2_packet_size(name, config, "obfs-min-packet-size")?,
            max_packet_size: parse_hy2_packet_size(name, config, "obfs-max-packet-size")?,
        })),
        Some(other) => Err(format!("hysteria2[{name}]: unknown obfs type: {other}")),
    }
}

/// `obfs-min-packet-size` / `obfs-max-packet-size`: absent or `0` keeps the
/// default; `Hy2Adapter::new` resolves and range-checks the pair.
#[cfg(feature = "hysteria2")]
fn parse_hy2_packet_size(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    key: &str,
) -> std::result::Result<u16, String> {
    match config.get(key) {
        None | Some(serde_json::Value::Null) => Ok(0),
        Some(value) => value
            .as_u64()
            .and_then(|size| u16::try_from(size).ok())
            .ok_or_else(|| format!("hysteria2[{name}]: {key} must be a byte count, got {value}")),
    }
}

#[cfg(feature = "hysteria2")]
const HY2_MIN_HOP_INTERVAL_SECS: u64 = 5;
#[cfg(feature = "hysteria2")]
const HY2_DEFAULT_HOP_INTERVAL_SECS: u64 = 30;

#[cfg(feature = "hysteria2")]
fn optional_nonempty_str(config: &HashMap<String, serde_json::Value>, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_bandwidth_field(
    name: &str,
    field: &str,
    value: Option<&serde_json::Value>,
) -> std::result::Result<u64, String> {
    let Some(value) = value else {
        return Ok(0);
    };
    if let Some(v) = value.as_u64() {
        return Ok(mbps_to_bytes_per_second(v));
    }
    if let Some(s) = value.as_str() {
        return parse_hy2_bandwidth(s).map_err(|e| format!("hysteria2[{name}]: {field}: {e}"));
    }
    Err(format!(
        "hysteria2[{name}]: {field} must be a string like '30 Mbps' or an integer Mbps value"
    ))
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_bandwidth(input: &str) -> std::result::Result<u64, String> {
    static RATE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(\d+)\s*([KMGTkmgt]?)([Bb])ps$").expect("valid rate regex")
    });

    let s = input.trim();
    if s.is_empty() || s == "0" {
        return Ok(0);
    }
    if let Ok(mbps) = s.parse::<u64>() {
        return Ok(mbps_to_bytes_per_second(mbps));
    }

    let Some(caps) = RATE_RE.captures(s) else {
        return Err(format!(
            "invalid bandwidth '{input}', expected integer Mbps or e.g. '30 Mbps'"
        ));
    };
    let value = caps[1]
        .parse::<u64>()
        .map_err(|e| format!("invalid number: {e}"))?;
    let multiplier = match caps[2].to_ascii_uppercase().as_str() {
        "" => 1,
        "K" => 1_000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        "T" => 1_000_000_000_000,
        _ => unreachable!("regex restricts unit prefix"),
    };
    let bytes = value
        .checked_mul(multiplier)
        .ok_or_else(|| "bandwidth overflows u64".to_string())?;
    if &caps[3] == "b" {
        Ok(bytes / 8)
    } else {
        Ok(bytes)
    }
}

#[cfg(feature = "hysteria2")]
fn mbps_to_bytes_per_second(mbps: u64) -> u64 {
    mbps.saturating_mul(1_000_000) / 8
}

/// Resolve the dial port for a hysteria2 outbound. `port` wins when present
/// and non-zero; otherwise the first concrete port in the (already validated)
/// `ports` hopping spec stands in — the hopping socket rewrites every send to
/// the dial port with the current hop port, so the value is a placeholder
/// whenever hopping is active. Mirrors mihomo, which errors only when both
/// `port` and `ports` fail to yield a port (issue #377).
#[cfg(feature = "hysteria2")]
fn hy2_dial_port(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    ports: Option<&str>,
) -> std::result::Result<u16, String> {
    let explicit = match config.get("port") {
        None => None,
        Some(value) => {
            let raw = value
                .as_u64()
                .ok_or_else(|| format!("hysteria2[{name}]: missing port"))?;
            let port = u16::try_from(raw)
                .map_err(|_| format!("hysteria2[{name}]: port {raw} exceeds 65535"))?;
            if port == 0 && ports.is_none() {
                return Err(format!("hysteria2[{name}]: port must be non-zero"));
            }
            (port != 0).then_some(port)
        }
    };
    if let Some(port) = explicit {
        return Ok(port);
    }
    ports.and_then(first_hy2_port).ok_or_else(|| {
        format!("hysteria2[{name}]: missing port — set 'port' or a concrete 'ports' range")
    })
}

/// First concrete port in a validated `ports` spec; `None` for the `*`/`all`
/// wildcard, which names no dialable port.
#[cfg(feature = "hysteria2")]
fn first_hy2_port(ports: &str) -> Option<u16> {
    let ports = ports.trim();
    if ports == "*" || ports.eq_ignore_ascii_case("all") {
        return None;
    }
    let part = ports.split(',').next()?.trim();
    let first = match part.split_once('-') {
        Some((start, _)) => start.trim(),
        None => part,
    };
    first.parse::<u16>().ok().filter(|p| *p != 0)
}

/// Mirror of `HopPorts::parse`'s expansion bound (`hysteria2/obfs.rs`) —
/// the port space holds at most this many distinct values, so a spec that
/// expands past it can never dial; reject at config load (issue #648).
#[cfg(feature = "hysteria2")]
const MAX_HOP_PORT_ENTRIES: usize = u16::MAX as usize;

#[cfg(feature = "hysteria2")]
fn validate_hy2_ports(name: &str, ports: &str) -> std::result::Result<(), String> {
    let ports = ports.trim();
    if ports == "*" || ports.eq_ignore_ascii_case("all") {
        return Ok(());
    }
    let mut total = 0usize;
    for part in ports.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("hysteria2[{name}]: invalid ports '{ports}'"));
        }
        // Same bound the dial-time `HopPorts::parse` enforces — mirroring it
        // here lets `-t`/load catch specs that could never dial (issue #648).
        let span = if let Some((start, end)) = part.split_once('-') {
            let s = parse_hy2_port_part(name, start)?;
            let e = parse_hy2_port_part(name, end)?;
            if s == 0 || e == 0 {
                return Err(format!("hysteria2[{name}]: port must be non-zero"));
            }
            if s > e {
                return Err(format!("hysteria2[{name}]: invalid port range '{part}'"));
            }
            e as usize - s as usize + 1
        } else {
            if parse_hy2_port_part(name, part)? == 0 {
                return Err(format!("hysteria2[{name}]: port must be non-zero"));
            }
            1
        };
        total += span;
        if total > MAX_HOP_PORT_ENTRIES {
            return Err(format!(
                "hysteria2[{name}]: ports '{ports}' expand beyond {MAX_HOP_PORT_ENTRIES} entries"
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_port_part(name: &str, value: &str) -> std::result::Result<u16, String> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|e| format!("hysteria2[{name}]: invalid port '{value}': {e}"))
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_hop_interval(
    name: &str,
    value: Option<&serde_json::Value>,
) -> std::result::Result<Option<(u64, u64)>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let raw = if let Some(n) = value.as_u64() {
        n.to_string()
    } else {
        value
            .as_str()
            .ok_or_else(|| format!("hysteria2[{name}]: hop-interval must be a number or range"))?
            .trim()
            .to_string()
    };
    if raw.is_empty() {
        return Err(format!("hysteria2[{name}]: hop-interval must not be empty"));
    }
    if raw.contains(',') {
        return Err(format!(
            "hysteria2[{name}]: hop-interval only supports one range"
        ));
    }
    if let Some((start, end)) = raw.split_once('-') {
        let start = parse_hy2_u64(name, "hop-interval", start)?;
        let end = parse_hy2_u64(name, "hop-interval", end)?;
        Ok(Some(normalize_hy2_hop_interval(start, end)))
    } else {
        let start = parse_hy2_u64(name, "hop-interval", &raw)?;
        Ok(Some(normalize_hy2_hop_interval(start, 0)))
    }
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_u64(name: &str, field: &str, value: &str) -> std::result::Result<u64, String> {
    let n = value
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("hysteria2[{name}]: invalid {field} '{value}': {e}"))?;
    // `hop-interval` feeds `Instant + Duration` at rotate time — an
    // out-of-range u64 (provider-supplied) overflows and, with
    // `panic = "abort"`, crashes the process (issue #648).
    if n > meow_common::MAX_DURATION_SECS {
        return Err(format!(
            "hysteria2[{name}]: {field} {n}s exceeds the {}s ceiling",
            meow_common::MAX_DURATION_SECS
        ));
    }
    Ok(n)
}

#[cfg(feature = "hysteria2")]
fn normalize_hy2_hop_interval(start: u64, end: u64) -> (u64, u64) {
    let start = if start == 0 {
        HY2_DEFAULT_HOP_INTERVAL_SECS
    } else {
        start.max(HY2_MIN_HOP_INTERVAL_SECS)
    };
    let end = if end == 0 { start } else { end.max(start) };
    (start, end)
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_fingerprint(
    name: &str,
    value: Option<&serde_json::Value>,
) -> std::result::Result<Option<String>, String> {
    let Some(raw) = value.and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let raw = raw.rsplit_once('=').map_or(raw, |(_, fp)| fp.trim());
    let hex: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "hysteria2[{name}]: fingerprint must be a SHA-256 hex digest"
        ));
    }
    Ok(Some(raw.to_string()))
}

#[cfg(feature = "hysteria2")]
fn validate_hy2_alpn(
    name: &str,
    value: Option<&serde_json::Value>,
) -> std::result::Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let mut alpns = Vec::new();
    if let Some(items) = value.as_array() {
        for item in items {
            let alpn = item
                .as_str()
                .ok_or_else(|| format!("hysteria2[{name}]: alpn entries must be strings"))?;
            alpns.push(alpn);
        }
    } else if let Some(alpn) = value.as_str() {
        alpns.push(alpn);
    } else {
        return Err(format!(
            "hysteria2[{name}]: alpn must be a string or string list"
        ));
    }
    if alpns.iter().any(|alpn| *alpn != "h3") {
        return Err(format!(
            "hysteria2[{name}]: custom alpn is unsupported; only 'h3' is allowed"
        ));
    }
    Ok(())
}

#[cfg(feature = "hysteria2")]
fn reject_unsupported_hy2_options(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
) -> std::result::Result<(), String> {
    for key in ["certificate", "private-key"] {
        if config.contains_key(key) {
            return Err(format!(
                "hysteria2[{name}]: '{key}' is not supported by the Rust backend"
            ));
        }
    }
    reject_enabled_hy2_map(name, config, "ech-opts")?;
    reject_enabled_hy2_map(name, config, "realm-opts")?;
    reject_nonzero_hy2_option(name, config, "cwnd")?;
    reject_nonzero_hy2_option(name, config, "udp-mtu")?;
    if optional_nonempty_str(config, "bbr-profile").is_some() {
        return Err(format!(
            "hysteria2[{name}]: 'bbr-profile' is not supported by the Rust backend"
        ));
    }
    Ok(())
}

#[cfg(feature = "hysteria2")]
fn reject_enabled_hy2_map(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    key: &str,
) -> std::result::Result<(), String> {
    if let Some(value) = config.get(key) {
        let enabled = value
            .as_object()
            .and_then(|map| map.get("enable"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        if enabled {
            return Err(format!(
                "hysteria2[{name}]: '{key}' is not supported by the Rust backend"
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "hysteria2")]
fn reject_nonzero_hy2_option(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    key: &str,
) -> std::result::Result<(), String> {
    if let Some(value) = config.get(key) {
        let nonzero =
            value.as_u64().is_some_and(|v| v != 0) || value.as_i64().is_some_and(|v| v != 0);
        if nonzero {
            return Err(format!(
                "hysteria2[{name}]: '{key}' is not supported by the Rust backend"
            ));
        }
    }
    Ok(())
}

/// Parse a `type: wireguard` proxy block into a [`WireGuardAdapter`]
/// (issue #899 Phase-1; `WireGuard` is accepted too, per docs/wireguard.md).
///
/// Required fields: `server`, `port`, `private-key`, `public-key` (base64,
/// standard encoding, exactly 32 bytes decoded). Optional: `ip`, `ipv6`
/// (tunnel interface addresses — bare address or CIDR; the prefix is
/// meaningless on a point-to-point WG interface and is stripped),
/// `allowed-ips` (list of CIDRs; absent/empty → the adapter applies the
/// catch-all `0.0.0.0/0` + `::/0`), `pre-shared-key`, `reserved` (3-byte
/// list or base64 → 3 bytes), `mtu`, `udp`, `remote-dns-resolve`,
/// `persistent-keepalive`, `dns`, `ip-stack`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `amnezia-wg-option` present — AmneziaWG is not in this build.
/// - `dialer-proxy` — accepted since issue #899: the WG endpoint's UDP
///   transport dials through the front hop's UDP association. Any proxy
///   dialer passes the gate (a group front's UDP capability is only
///   decidable at dial time); a UDP-less front fails `dial_udp_conn` at
///   runtime, closed like any other endpoint bind error.
/// - missing `server`, `port`, `private-key`, or `public-key`.
/// - a key that is not base64, or decodes to other than 32 bytes.
/// - `ip`/`ipv6` that is neither an address nor a CIDR of that family.
/// - an `allowed-ips` entry that is not a CIDR.
/// - `reserved` that is not a 3-element list or base64 → 3 bytes.
/// - `mtu` outside 640–9000 (the floor keeps the inner IP MTU —
///   `mtu - 64` WG overhead — at or above the 576 IPv4 minimum;
///   `WireGuardAdapter::new` keeps the same floor as a backstop).
/// - `ip-stack` other than `"gvisor"`/`"system"`.
///
/// Phase-1 accepts-but-ignores: `dns` (warns once; `remote-dns-resolve`
/// covers tunnel-side lookups) and `ip-stack` (`gvisor` maps to the
/// built-in smoltcp stack; `system` warns once then does the same).
///
/// upstream: `adapter/outbound/wireguard.go`
#[cfg(feature = "wireguard")]
fn parse_wireguard(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
) -> std::result::Result<WireGuardAdapter, String> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // AmneziaWG obfuscation is Phase-3 — name the field instead of
    // silently running the standard session the operator did not ask for.
    if config
        .get("amnezia-wg-option")
        .is_some_and(|v| !v.is_null())
    {
        return Err(format!(
            "wireguard[{name}]: 'amnezia-wg-option' is not supported in this build"
        ));
    }

    let required_str = |field: &str| -> std::result::Result<&str, String> {
        config
            .get(field)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("wireguard[{name}]: missing {field}"))
    };
    let opt_str = |field: &str| -> std::result::Result<Option<&str>, String> {
        match config.get(field) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => v
                .as_str()
                .map(Some)
                .ok_or_else(|| format!("wireguard[{name}]: '{field}' must be a string")),
        }
    };
    let boolean = |field: &str, default: bool| -> std::result::Result<bool, String> {
        match config.get(field) {
            None | Some(serde_json::Value::Null) => Ok(default),
            Some(v) => v
                .as_bool()
                .ok_or_else(|| format!("wireguard[{name}]: '{field}' must be boolean")),
        }
    };
    let opt_u16 = |field: &str, default: u16| -> std::result::Result<u16, String> {
        match config.get(field) {
            None | Some(serde_json::Value::Null) => Ok(default),
            Some(v) => {
                let n = v.as_u64().ok_or_else(|| {
                    format!("wireguard[{name}]: '{field}' must be an unsigned integer")
                })?;
                u16::try_from(n)
                    .map_err(|_| format!("wireguard[{name}]: '{field}' {n} exceeds 65535"))
            }
        }
    };

    let server = required_str("server")?;
    let port = required_port(config, &format!("wireguard[{name}]"))?;
    let private_key = parse_wg_key(name, config, "private-key")?;
    let public_key = parse_wg_key(name, config, "public-key")?;
    let pre_shared_key = match opt_str("pre-shared-key")? {
        None => None,
        Some(_) => Some(parse_wg_key(name, config, "pre-shared-key")?),
    };

    // `ip`/`ipv6` are the tunnel interface addresses. A bare address or a
    // CIDR is accepted; the prefix has no meaning on a point-to-point WG
    // interface (the adapter assigns /32 resp. /128), so it is stripped.
    let parse_tunnel_addr = |field: &str| -> std::result::Result<Option<std::net::IpAddr>, String> {
        let Some(raw) = opt_str(field)? else {
            return Ok(None);
        };
        if let Ok(addr) = raw.parse::<std::net::IpAddr>() {
            return Ok(Some(addr));
        }
        if let Ok(net) = raw.parse::<ipnet::IpNet>() {
            return Ok(Some(net.addr()));
        }
        Err(format!(
            "wireguard[{name}]: '{field}' must be an IP address or CIDR"
        ))
    };
    let ip: Option<Ipv4Addr> = match parse_tunnel_addr("ip")? {
        None => None,
        Some(std::net::IpAddr::V4(a)) => Some(a),
        Some(std::net::IpAddr::V6(_)) => {
            return Err(format!("wireguard[{name}]: 'ip' must be IPv4"));
        }
    };
    let ipv6: Option<Ipv6Addr> = match parse_tunnel_addr("ipv6")? {
        None => None,
        Some(std::net::IpAddr::V6(a)) => Some(a),
        Some(std::net::IpAddr::V4(_)) => {
            return Err(format!("wireguard[{name}]: 'ipv6' must be IPv6"));
        }
    };

    let allowed_ips = parse_wg_allowed_ips(name, config)?;
    let reserved = parse_wg_reserved(name, config)?;

    let mtu = opt_u16("mtu", 1420)?;
    if !(640..=9000).contains(&mtu) {
        return Err(format!(
            "wireguard[{name}]: 'mtu' must be in 640..=9000 (outer MTU; \
             inner = mtu - 64 WG overhead must be >= 576)"
        ));
    }
    let udp = boolean("udp", true)?;
    let remote_dns_resolve = boolean("remote-dns-resolve", true)?;
    let persistent_keepalive = opt_u16("persistent-keepalive", 0)?;

    // `dns` is parsed and stored but ignored in Phase-1 — tunnel-side
    // resolution goes through `remote-dns-resolve` and the injected
    // resolver. Warn once per parse so generated mihomo configs keep
    // loading without pretending per-node tunnel DNS works.
    let dns_present = config.get("dns").is_some_and(|v| !v.is_null());
    let dns: Vec<String> = match config.get("dns") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(list)) => list
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("wireguard[{name}]: 'dns' entries must be strings"))
            })
            .collect::<std::result::Result<_, _>>()?,
        Some(_) => {
            return Err(format!(
                "wireguard[{name}]: 'dns' must be a nameserver string or list"
            ));
        }
    };
    if dns_present {
        tracing::warn!(
            "wireguard {name}: 'dns' is accepted but ignored in Phase-1 \
             (remote-dns-resolve covers tunnel-side lookups)"
        );
    }

    // Phase-1 runs one userspace stack — smoltcp. `gvisor` is the same
    // role in mihomo terms, so it is accepted silently; `system` maps to
    // smoltcp with a warn rather than a hard error so such configs keep
    // loading (docs/wireguard.md). Every other value — including
    // mihomo's `{mode, congestion-controller}` object form — is a named
    // error instead of a silent semantic change.
    match config.get("ip-stack") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(stack)) => match stack.as_str() {
            "" | "gvisor" => {}
            "system" => tracing::warn!(
                "wireguard {name}: 'ip-stack: system' maps to the built-in \
                 smoltcp stack — no kernel WireGuard mode in Phase-1"
            ),
            other => {
                return Err(format!(
                    "wireguard[{name}]: 'ip-stack' \"{other}\" is not supported — \
                     this build runs the smoltcp userspace stack \
                     (accepted: \"gvisor\", \"system\")"
                ));
            }
        },
        Some(_) => {
            return Err(format!(
                "wireguard[{name}]: 'ip-stack' must be \"gvisor\" or \"system\""
            ));
        }
    }

    WireGuardAdapter::new(WireGuardConfig {
        name: name.to_string(),
        server: server.to_string(),
        port,
        private_key,
        public_key,
        pre_shared_key,
        ip,
        ipv6,
        allowed_ips,
        reserved,
        mtu,
        udp,
        remote_dns_resolve,
        persistent_keepalive,
        dns,
    })
    .map_err(|e| format!("wireguard[{name}]: {e}"))
}

/// Decode a required WireGuard key field: base64 (standard alphabet, as
/// every WG tool emits) that must come out to exactly 32 bytes.
#[cfg(feature = "wireguard")]
fn parse_wg_key(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    field: &str,
) -> std::result::Result<[u8; 32], String> {
    use base64::Engine;
    let raw = config
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("wireguard[{name}]: missing {field}"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| format!("wireguard[{name}]: '{field}' must be base64"))?;
    bytes
        .try_into()
        .map_err(|_| format!("wireguard[{name}]: '{field}' must decode to exactly 32 bytes"))
}

/// `allowed-ips`: each entry must be a CIDR (`addr/prefix`). An absent or
/// empty list is *not* an error — [`WireGuardAdapter::new`] substitutes
/// the catch-all `0.0.0.0/0` + `::/0` default at construction.
#[cfg(feature = "wireguard")]
fn parse_wg_allowed_ips(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
) -> std::result::Result<Vec<ipnet::IpNet>, String> {
    match config.get("allowed-ips") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(list)) => list
            .iter()
            .map(|v| {
                let s = v.as_str().ok_or_else(|| {
                    format!("wireguard[{name}]: 'allowed-ips' entries must be CIDR strings")
                })?;
                s.parse::<ipnet::IpNet>().map_err(|_| {
                    format!("wireguard[{name}]: 'allowed-ips' entry '{s}' is not a valid CIDR")
                })
            })
            .collect(),
        Some(_) => Err(format!(
            "wireguard[{name}]: 'allowed-ips' must be a list of CIDR strings"
        )),
    }
}

/// `reserved` — the 3-byte Cloudflare WARP client identifier: a YAML list
/// of three bytes (`[13, 53, 133]`) or a base64 string decoding to exactly
/// 3 bytes (`"DTWF"`). The pump overwrites bytes 1–4 of each outbound WG
/// datagram with it after encapsulation.
#[cfg(feature = "wireguard")]
fn parse_wg_reserved(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
) -> std::result::Result<Option<[u8; 3]>, String> {
    use base64::Engine;
    match config.get("reserved") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Array(list)) => {
            if list.len() != 3 {
                return Err(format!(
                    "wireguard[{name}]: 'reserved' must be a list of exactly 3 bytes"
                ));
            }
            let mut out = [0u8; 3];
            for (i, v) in list.iter().enumerate() {
                let n = v.as_u64().ok_or_else(|| {
                    format!("wireguard[{name}]: 'reserved' entries must be bytes (0-255)")
                })?;
                out[i] = u8::try_from(n).map_err(|_| {
                    format!("wireguard[{name}]: 'reserved' entries must be bytes (0-255)")
                })?;
            }
            Ok(Some(out))
        }
        Some(serde_json::Value::String(s)) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|_| {
                    format!("wireguard[{name}]: 'reserved' must be a 3-byte list or base64")
                })?;
            <[u8; 3]>::try_from(bytes.as_slice())
                .map(Some)
                .map_err(|_| {
                    format!("wireguard[{name}]: 'reserved' base64 must decode to exactly 3 bytes")
                })
        }
        Some(_) => Err(format!(
            "wireguard[{name}]: 'reserved' must be a 3-byte list or base64"
        )),
    }
}

/// Parse the `strategy` field for a `load-balance` group.
///
/// Hard error on unknown values (Class A per ADR-0002): unknown strategy means
/// the user may get different distribution behaviour than intended.
/// Upstream also rejects (`errStrategy` in adapter/outboundgroup/loadbalance.go).
fn parse_lb_strategy(strategy: Option<&str>) -> std::result::Result<LbStrategy, String> {
    match strategy.unwrap_or("round-robin") {
        "round-robin" => Ok(LbStrategy::RoundRobin),
        // Upstream maps "" to consistent-hashing (`case "",
        // "consistent-hashing"` in NewLoadBalance — the same arm an
        // absent strategy falls into upstream). Our absent default stays
        // round-robin via the unwrap_or — deliberate divergence, spec
        // row 10.
        "" | "consistent-hashing" => Ok(LbStrategy::ConsistentHashing),
        other => Err(format!(
            "load-balance: unknown strategy '{other}'; valid values: \
             'round-robin' (default), 'consistent-hashing'. \
             (upstream also rejects via errStrategy — Class A ADR-0002)"
        )),
    }
}

/// Parse `ws-opts.max-early-data`: absent → `0` (disabled); a value above
/// the ceiling clamps with a warning (`meow-transport` re-clamps at
/// connect for programmatic configs — issue #648).
#[cfg(any(feature = "vless", feature = "vmess"))]
fn ws_max_early_data(ws_opts: Option<&serde_json::Value>) -> usize {
    ws_opts
        .and_then(|o| o.get("max-early-data"))
        .and_then(serde_json::Value::as_u64)
        .map_or(0, |n| {
            let v = usize::try_from(n).unwrap_or(usize::MAX);
            if v > meow_transport::ws::MAX_WS_EARLY_DATA {
                tracing::warn!(
                    "ws-opts.max-early-data {v} exceeds the {}-byte ceiling; clamped",
                    meow_transport::ws::MAX_WS_EARLY_DATA
                );
            }
            v
        })
        .min(meow_transport::ws::MAX_WS_EARLY_DATA)
}

/// Parse a `type: vless` proxy config block into a `VlessAdapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `flow: xtls-rprx-direct` / `xtls-rprx-splice` — deprecated and insecure
/// - Unknown `flow` values — may skip expected security processing
/// - `reality-opts` malformed, used without TLS, or missing `client-fingerprint`
/// - `flow: xtls-rprx-vision` + any `network` other than raw `tcp`, or
///   without `tls: true` (REALITY included) — Vision's DIRECT mode needs
///   the TLS record layer right on the socket.  With VLESS `encryption`
///   the older rule applies: `tls: true` or a grpc/h2 network
/// - `encryption: <non-empty non-"none">` — unsupported cipher
/// - `uuid` invalid
/// - `server` domain > 255 bytes
/// - `vless-vision` feature absent + `flow: xtls-rprx-vision`
/// - `flow: xtls-rprx-vision` + a `smux`/`mux` block using sing-mux
///   (`protocol: smux`/`yamux`/`h2mux`) — sing-box and Xray reject XTLS +
///   sing-mux (`protocol: muxcool` is fine)
/// - a `smux`/`mux` block with `padding: true` + `protocol: muxcool` —
///   Mux.Cool has no padding layer, so the node would go out unpadded
///
/// # Warn-once (Class B per ADR-0002)
///
/// - `tls: false` with plain VLESS — plaintext, but correct destination
/// - `mux: { enabled: true }` — sing-mux multiplexing (server must be sing-box/mihomo)
/// - `flow: xtls-rprx-vision` + `udp: true` — Vision is TCP-only; UDP rides
///   a Mux.Cool substream with the flow addon (or reports unsupported
///   without the `mux` feature)
/// - `reality-opts.short-id` given as a bare YAML number (e.g. `0x1f`) —
///   coerced to its decimal digits before hex-decoding (matching mihomo),
///   which can silently reinterpret the value; quote it to preserve the
///   literal digits
#[cfg(feature = "vless")]
fn parse_vless(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
    global_client_fingerprint: Option<&str>,
) -> std::result::Result<VlessAdapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("vless: missing server")?;
    let port = required_port(config, "vless")?;
    let uuid_str = config
        .get("uuid")
        .and_then(|v| v.as_str())
        .ok_or("vless: missing uuid")?;
    let uuid_bytes = parse_uuid(uuid_str).map_err(|e| format!("vless: {e}"))?;

    // Validate server domain length (Class A — wrong destination with no diagnostic).
    if server.len() > 255 {
        return Err(format!(
            "vless: server '{}…' domain is {} bytes; max 255 \
             (would be silently truncated — wrong destination, no diagnostic)",
            &server[..server.len().min(20)],
            server.len()
        ));
    }

    let udp = config
        .get("udp")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let tls = config
        .get("tls")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let servername = config
        .get("servername")
        .and_then(|v| v.as_str())
        .unwrap_or(server)
        .to_string();
    let alpn: Vec<String> = config
        .get("alpn")
        .and_then(|v| v.as_array())
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
        .collect();
    let network = config
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");

    // ── Reality opts ──────────────────────────────────────────────────────
    let reality = parse_vless_reality_opts(name, config)?;
    // `global-client-fingerprint` (issue #974) fills an omitted node
    // fingerprint; under REALITY an explicit `none` stays the literal
    // "none" so `HelloProfile::resolve` warns and falls back to Chrome —
    // mihomo's behavior, since no unshaped hello exists to send there.
    let client_fingerprint = resolve_node_client_fingerprint(
        config,
        "vless",
        global_client_fingerprint,
        reality.is_some(),
    )?;
    if reality.is_some() {
        if !tls {
            return Err("vless: reality-opts requires `tls: true`".into());
        }
        if client_fingerprint.is_none() {
            return Err("vless: REALITY is based on uTLS, please set a client-fingerprint".into());
        }
    }

    // ── VLESS Encryption (`mlkem768x25519plus…`) ──────────────────────────
    // "" / "none" → plain VLESS. The post-quantum Encryption layer is parsed
    // when the `vless-encryption` feature is compiled in; anything else (a real
    // cipher name, or the ML-KEM string on a build without the feature) is a
    // hard error (Class A — silently ignoring it would send unprotected bytes).
    let encryption = config
        .get("encryption")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    #[cfg(feature = "vless-encryption")]
    let vless_encryption = parse_vless_encryption(encryption)?;
    #[cfg(not(feature = "vless-encryption"))]
    parse_vless_encryption(encryption)?;

    // ── Flow parsing ──────────────────────────────────────────────────────
    let flow_str = config.get("flow").and_then(|v| v.as_str()).unwrap_or("");

    let flow: Option<VlessFlow> = match flow_str {
        "" => None,

        "xtls-rprx-vision" => {
            // Hard error if vless-vision feature is not compiled in (Class A).
            #[cfg(not(feature = "vless-vision"))]
            {
                return Err(
                    "vless: flow xtls-rprx-vision requires the `vless-vision` Cargo feature; \
                     rebuild with --features vless-vision"
                        .into(),
                );
            }
            #[cfg(feature = "vless-vision")]
            Some(VlessFlow::XtlsRprxVision)
        }

        "xtls-rprx-direct" | "xtls-rprx-splice" => {
            // Class A: upstream accepts these as deprecated aliases; we reject them.
            // upstream: adapter/outbound/vless.go — accepts deprecated flows.
            // NOT warn-ignore — security regression vs Vision if user assumes Vision protection.
            return Err(format!(
                "vless: flow '{flow_str}' is deprecated and insecure; \
                 use `flow: xtls-rprx-vision` instead. \
                 (upstream: adapter/outbound/vless.go accepts this; we reject — Class A ADR-0002)"
            ));
        }

        other => {
            // Class A: unknown flow may skip expected security processing.
            // upstream: adapter/outbound/vless.go ignores unknown flows.
            // NOT warn-ignore — unknown flow value may silently degrade security.
            return Err(format!(
                "vless: unknown flow '{other}'; valid values: '' or 'xtls-rprx-vision'. \
                 (upstream: ignores unknown flows; we reject — Class A ADR-0002)"
            ));
        }
    };

    // ── Gating: Vision requires raw TCP under TLS / REALITY (Class A) ─────
    // Vision ends by switching both directions to the socket under the
    // outer TLS (DIRECT); Xray's inbound refuses anything but TLS / REALITY
    // right on the connection, and mihomo's client refuses the same.  The
    // VLESS Encryption layer keeps its earlier gate (issue #495 item 5).
    if flow == Some(VlessFlow::XtlsRprxVision) {
        #[cfg(feature = "vless-encryption")]
        let encrypted = vless_encryption.is_some();
        #[cfg(not(feature = "vless-encryption"))]
        let encrypted = false;
        if encrypted {
            let tls_transport = network == "grpc" || network == "h2";
            if !tls && !tls_transport {
                return Err(
                    "vless: flow xtls-rprx-vision requires an encrypting transport; \
                     set `tls: true` or use a TLS-enforcing network (grpc, h2). \
                     Without outer TLS, Vision splice is a no-op and the user has no protection."
                        .into(),
                );
            }
        } else if network != "tcp" {
            return Err(format!(
                "vless: flow xtls-rprx-vision only works over `network: tcp` (got \
                 '{network}'); Vision hands the connection to the raw TLS socket, which \
                 a {network} transport does not expose, and Xray servers reject it too. \
                 Remove `flow` or `network`."
            ));
        } else if !tls {
            return Err(
                "vless: flow xtls-rprx-vision requires `tls: true` (or REALITY); \
                 without outer TLS, Vision splice is a no-op and the user has no protection."
                    .into(),
            );
        }
    }

    // ── Warn: tls: false with plain VLESS (Class B) ───────────────────────
    if !tls && flow.is_none() && network != "grpc" && network != "h2" {
        tracing::warn!(
            proxy = %name,
            "vless: tls is false and no TLS-enforcing transport is set; \
             traffic will be plaintext (correct destination, absent crypto). \
             Set `tls: true` to encrypt. (Class B divergence — upstream is silent)"
        );
    }

    // ── mux: sing-mux compatible connection multiplexing ─────────────────
    // Parsed after adapter construction below — see the `with_mux` call.

    // ── Warn: Vision + UDP (Class B) ─────────────────────────────────────
    if flow == Some(VlessFlow::XtlsRprxVision) && udp {
        tracing::warn!(
            proxy = %name,
            "flow: xtls-rprx-vision applies to TCP only; UDP relays on \
             this proxy ride a per-association Mux.Cool substream carrying \
             the flow addon (as upstream clients do — strict servers reject \
             a bare Cmd::Udp on vision accounts). Without the `mux` feature \
             this node reports `udp: false`. (Class B divergence)"
        );
    }

    // ── Build transport chain ──────────────────────────────────────────────
    let mut chain = TransportChain::empty();

    if tls {
        use meow_transport::tls::{TlsConfig, TlsLayer};
        let sni = if servername.is_empty() {
            server
        } else {
            servername.as_str()
        };
        let mut tls_cfg = TlsConfig::new(sni);
        tls_cfg.skip_cert_verify = skip_cert_verify;
        tls_cfg.alpn = default_transport_alpn(network, alpn);
        tls_cfg.fingerprint = client_fingerprint;
        tls_cfg.reality = reality;

        // ── ECH opts ────────────────────────────────────────────────────
        // DNS-sourced ECH (`enable: true` without `config:`) is resolved by
        // `ech_dns::preresolve_ech` *before* `parse_proxy` runs, which injects
        // the fetched bytes back into `ech-opts.config` as base64. By the time
        // we get here only the inline-config branch matters; a missing
        // `config:` means pre-resolution failed (already warned) and we just
        // continue without ECH.
        if let Some(ech_opts) = config.get("ech-opts") {
            let ech_enabled = ech_opts
                .get("enable")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if ech_enabled {
                use meow_transport::tls::EchOpts;
                if let Some(inline_config) = ech_opts.get("config").and_then(|v| v.as_str()) {
                    use base64::Engine;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(inline_config)
                        .map_err(|e| format!("vless: ech-opts.config base64 decode: {e}"))?;
                    tls_cfg.ech = Some(EchOpts::Config(bytes));
                }
            }
        }

        drop_ech_under_reality(name, &mut tls_cfg);

        let tls_layer =
            TlsLayer::new(&tls_cfg).map_err(|e| format!("vless: TLS layer error: {e}"))?;
        chain.push(Box::new(tls_layer));
    }

    match network {
        "tcp" => {} // no extra layer
        "ws" => {
            use meow_transport::ws::{WsConfig, WsLayer};
            let ws_opts = config.get("ws-opts");
            let path = ws_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            // host_header: user-supplied Host, or fall back to server address.
            // WsLayer::new requires Some; normalization is the config layer's job
            // (ADR-0001 §1 — transport never infers values from context).
            let host_header = ws_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.get("Host"))
                .and_then(|v| v.as_str())
                .map_or_else(|| server.to_string(), std::string::ToString::to_string);
            // `max-early-data` buffers caller writes until the upgrade
            // completes — clamped to the 2048-byte ceiling (the transport
            // layer re-clamps programmatic configs at connect; #648).
            let max_early_data = ws_max_early_data(ws_opts);
            let early_data_header_name = ws_opts
                .and_then(|o| o.get("early-data-header-name"))
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string);
            let ws_cfg = WsConfig {
                path,
                host_header: Some(host_header),
                extra_headers: vec![],
                max_early_data,
                early_data_header_name,
            };
            let ws_layer =
                WsLayer::new(ws_cfg).map_err(|e| format!("vless: ws layer error: {e}"))?;
            chain.push(Box::new(ws_layer));
        }
        "grpc" => {
            use meow_transport::grpc::{GrpcConfig, GrpcLayer};
            let grpc_opts = config.get("grpc-opts");
            let service_name = grpc_opts
                .and_then(|o| o.get("grpc-service-name"))
                .and_then(|v| v.as_str())
                .unwrap_or("GunService")
                .to_string();
            // Authority: mihomo's gun transport sets `Host` to `servername`
            // and only falls back to the dial host when `servername` is empty
            // (adapter/outbound/vless.go). Front-ends that route gRPC by
            // `:authority` are provisioned against that value, so match it
            // rather than always sending the dial host (issue #377). Resolved
            // here per ADR-0001 §1 — the transport never infers it.
            let authority = config
                .get("servername")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(server)
                .to_string();
            let grpc_cfg = GrpcConfig {
                service_name,
                authority,
            };
            chain.push(Box::new(GrpcLayer::new(grpc_cfg)));
        }
        "h2" => {
            use meow_transport::h2::{H2Config, H2Layer};
            let h2_opts = config.get("h2-opts");
            let path = h2_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            // `h2-opts.host` is a list; default to server when absent.
            // Class A: empty host list is rejected — H2Layer asserts non-empty
            // (debug) and upstream requires at least one authority value.
            let hosts: Vec<String> = h2_opts
                .and_then(|o| o.get("host"))
                .and_then(|v| v.as_array())
                .map_or_else(
                    || vec![server.to_string()],
                    |seq| {
                        seq.iter()
                            .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
                            .collect()
                    },
                );
            if hosts.is_empty() {
                return Err(format!(
                    "vless: h2-opts.host must not be empty for proxy '{name}' \
                     (H2 requires at least one authority value)"
                ));
            }
            let h2_cfg = H2Config { path, hosts };
            chain.push(Box::new(H2Layer::new(h2_cfg)));
        }
        "httpupgrade" => {
            use meow_transport::httpupgrade::{
                HttpUpgradeConfig, HttpUpgradeLayer, MAX_EXTRA_HEADERS,
            };
            let hu_opts = config.get("http-upgrade-opts");
            let path = hu_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let host_header = hu_opts
                .and_then(|o| o.get("host"))
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string)
                .or_else(|| Some(server.to_string()));
            let extra_headers: Vec<(String, String)> = match hu_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.as_object())
            {
                Some(m) => {
                    // Same remotely-supplied header-list bound as xhttp
                    // (issue #648); `connect()` re-checks it.
                    if m.len() > MAX_EXTRA_HEADERS {
                        return Err(format!(
                            "vless: http-upgrade-opts.headers has {} entries (max {MAX_EXTRA_HEADERS})",
                            m.len()
                        ));
                    }
                    m.iter()
                        .filter_map(|(k, v)| {
                            let key = k.clone();
                            let val = v.as_str()?.to_string();
                            Some((key, val))
                        })
                        .collect()
                }
                None => Vec::new(),
            };
            let hu_cfg = HttpUpgradeConfig {
                path,
                host_header,
                extra_headers,
            };
            chain.push(Box::new(HttpUpgradeLayer::new(hu_cfg)));
        }
        "xhttp" => {
            let xhttp_cfg = parse_vless_xhttp_config(config, server, &servername, tls)?;
            chain.push(Box::new(meow_transport::xhttp::XhttpLayer::new(xhttp_cfg)));
        }
        other => {
            return Err(format!(
                "vless: unsupported network '{other}'; valid values: tcp, ws, grpc, h2, httpupgrade, xhttp"
            ));
        }
    }

    #[cfg_attr(not(feature = "vless-encryption"), allow(unused_mut))]
    let mut adapter = VlessAdapter::new(
        name,
        server,
        port,
        uuid_bytes,
        flow,
        udp,
        chain,
        Arc::clone(dialer),
    );
    #[cfg(feature = "vless-encryption")]
    adapter.set_encryption(vless_encryption);

    #[cfg(feature = "mux")]
    if let Some(mux_options) = parse_mux_options(name, config)? {
        // Vision + sing-mux (smux/yamux/h2mux) is rejected by both sing-box
        // and Xray servers: the mux session dials the reserved mux
        // destination and the server tears the Vision-wrapped connection
        // down with no diagnostic — hard error at config time rather than a
        // silent dial failure. Vision + Mux.Cool (`protocol: muxcool`) is
        // the opposite case: Xray's own Mux.Cool signaling rides inside the
        // VLESS request that Vision splices, and this has been live-tested
        // against a real Xray node (see docs/specs/proxy-mux.md "Test Plan"
        // items 2-3, issue #424) — so only the sing-mux protocols are gated
        // here.
        #[cfg(feature = "vless-vision")]
        if flow == Some(VlessFlow::XtlsRprxVision)
            && mux_options.protocol != meow_proxy::mux::Protocol::MuxCool
        {
            return Err(
                "vless: flow xtls-rprx-vision is incompatible with sing-mux \
                 (smux/yamux/h2mux); sing-box and Xray reject XTLS + sing-mux. \
                 Use `protocol: muxcool` for Vision + multiplexing instead."
                    .into(),
            );
        }
        adapter = adapter.with_mux(mux_options);
    }
    #[cfg(not(feature = "mux"))]
    parse_mux_options(name, config)?;

    Ok(adapter)
}

/// Parse the optional mihomo `smux:` block shared by
/// VLESS/Trojan/Shadowsocks/VMess.  `mux:` remains accepted as a legacy alias.
///
/// Two wire protocols are available, picked by `protocol`:
///
/// * sing-mux (smux/yamux/h2mux, default h2mux) — the first proxy request
///   targets the reserved mux destination and streams carry a sing-encoded
///   Socksaddr prefix.  Server must be sing-box / mihomo based.
/// * muxcool — Xray's Mux.Cool (CommandMux 0x03 in the VLESS/VMess request
///   header, frame mux).  Server must be Xray / sing-box based; VLESS and
///   VMess support it (Trojan/Shadowsocks reject it).
///
/// `padding: true` is sing-mux session padding and is rejected with
/// `protocol: muxcool`.
///
/// Returns `None` when the block is absent or disabled; `Err` for
/// malformed values.  Only compiled when one of its call sites
/// (trojan / vless / ss / vmess parsing) exists.
#[cfg(all(
    feature = "mux",
    any(
        feature = "trojan",
        feature = "vless",
        feature = "ss",
        feature = "vmess"
    )
))]
fn parse_mux_options(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
) -> std::result::Result<Option<meow_proxy::mux::MuxOptions>, String> {
    let Some(mux_cfg) = mux_config_block(name, config)? else {
        return Ok(None);
    };
    let enabled = mux_bool_field(name, mux_cfg, "enabled", false)?;
    if !enabled {
        return Ok(None);
    }
    // Empty protocol maps to h2mux, matching mihomo's default.
    let protocol_str = match mux_cfg.get("protocol") {
        None => "h2mux",
        Some(serde_json::Value::String(s)) => s.as_str(),
        Some(other) => {
            return Err(format!(
                "{name}: mux option 'protocol' must be a string, got {other:?}"
            ));
        }
    };
    let Some(protocol) = meow_proxy::mux::Protocol::parse(protocol_str) else {
        // mihomo hard-errors on unknown protocols; do the same so a typo
        // cannot silently speak the wrong wire protocol to the server.
        return Err(format!(
            "{name}: unknown mux protocol '{protocol_str}'; valid values: smux, yamux, h2mux, muxcool"
        ));
    };
    // The shipped 4/4/4 defaults live on `MuxOptions::default` — the parse
    // fallbacks read it so the two sources can never drift apart.
    let defaults = meow_proxy::mux::MuxOptions::default();
    let max_connections =
        mux_usize_field(name, mux_cfg, "max-connections", defaults.max_connections)?;
    let min_streams = mux_usize_field(name, mux_cfg, "min-streams", defaults.min_streams)?;
    let max_streams = mux_usize_field(name, mux_cfg, "max-streams", defaults.max_streams)?;
    // All three at 0 turns off pooling across busy carriers: an idle
    // session is still reused, but one already carrying a stream is never
    // shared, so every *concurrent* stream dials its own carrier — almost
    // never what an operator wants, so say so.
    if max_connections == 0 && min_streams == 0 && max_streams == 0 {
        tracing::warn!(
            proxy = %name,
            "mux: max-connections, min-streams and max-streams are all 0 — a carrier that \
             already holds a stream is never shared, so concurrent streams each dial their \
             own connection; consider the 4/4/4 defaults"
        );
    }
    // `statistic` opts into mihomo's per-carrier traffic attribution, which
    // meow does not model — the logical-flow APIs (`GET /connections`,
    // `GET /traffic`, `GET /statistics`) already report the same totals.
    // Validate the flag so a malformed value is a node defect like every
    // other mux bool, but warn rather than fail when set: the node still
    // works, just without carrier-level accounting.
    if mux_bool_field(name, mux_cfg, "statistic", false)? {
        tracing::warn!(
            proxy = %name,
            "mux option 'statistic' is not supported in meow-rs (carrier-level traffic \
             accounting is not modeled); use GET /connections or GET /statistics for \
             per-flow counters"
        );
    }
    // `brutal-opts` (TCP Brutal, Linux-only upstream) stays warn-ignore.
    if mux_cfg.get("brutal-opts").is_some() {
        tracing::warn!(
            proxy = %name,
            "mux option 'brutal-opts' is not supported in meow-rs and will be ignored"
        );
    }
    // Padding is a sing-mux session layer; Mux.Cool has none, so honouring
    // the flag is impossible and ignoring it would send the unpadded traffic
    // shape the operator opted out of (Class A per ADR-0002).
    let padding = mux_bool_field(name, mux_cfg, "padding", false)?;
    if padding && protocol == meow_proxy::mux::Protocol::MuxCool {
        return Err(format!(
            "{name}: mux option 'padding' is sing-mux only (smux/yamux/h2mux); \
             Mux.Cool (`protocol: muxcool`) has no padding layer — remove `padding` \
             or pick a sing-mux protocol"
        ));
    }
    Ok(Some(meow_proxy::mux::MuxOptions {
        protocol,
        padding,
        max_connections,
        min_streams,
        max_streams,
        only_tcp: mux_bool_field(name, mux_cfg, "only-tcp", false)?,
    }))
}

/// No-mux builds: warn loudly instead of silently ignoring an enabled
/// `smux:`/`mux:` block (operators would otherwise think the node is multiplexed).
/// Only compiled when one of its call sites (trojan / vless / ss / vmess
/// parsing) exists.
#[cfg(all(
    not(feature = "mux"),
    any(
        feature = "trojan",
        feature = "vless",
        feature = "ss",
        feature = "vmess"
    )
))]
fn parse_mux_options(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
) -> std::result::Result<(), String> {
    if let Some(mux_cfg) = mux_config_block(name, config)? {
        let enabled = mux_cfg
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if enabled {
            tracing::warn!(
                proxy = %name,
                "mux is enabled in config but this build was compiled without the `mux` feature; the option is ignored"
            );
        }
    }
    Ok(())
}

#[cfg(any(
    feature = "trojan",
    feature = "vless",
    feature = "ss",
    feature = "vmess"
))]
fn mux_config_block<'a>(
    name: &str,
    config: &'a HashMap<String, serde_json::Value>,
) -> std::result::Result<Option<&'a serde_json::Value>, String> {
    let block = match (config.get("smux"), config.get("mux")) {
        (Some(_), Some(_)) => {
            // Migration-friendly: prefer the canonical key and say so,
            // instead of rejecting the node for a likely leftover.
            tracing::warn!(
                proxy = %name,
                "both `smux` and legacy alias `mux` are configured; using the canonical `smux` key"
            );
            config.get("smux")
        }
        (Some(config), None) | (None, Some(config)) => Some(config),
        (None, None) => None,
    };
    let Some(block) = block else {
        return Ok(None);
    };
    // A scalar like `smux: true` must not be treated as "disabled" —
    // the operator clearly tried to enable multiplexing.
    if !block.is_object() {
        return Err(format!(
            "{name}: `smux`/`mux` must be a mapping, got {block:?}"
        ));
    }
    Ok(Some(block))
}

#[cfg(all(
    feature = "mux",
    any(
        feature = "trojan",
        feature = "vless",
        feature = "ss",
        feature = "vmess"
    )
))]
fn mux_bool_field(
    name: &str,
    mux_cfg: &serde_json::Value,
    key: &str,
    default: bool,
) -> std::result::Result<bool, String> {
    match mux_cfg.get(key) {
        None => Ok(default),
        Some(serde_json::Value::Bool(b)) => Ok(*b),
        Some(other) => Err(format!(
            "{name}: mux option '{key}' must be a boolean, got {other:?}"
        )),
    }
}

#[cfg(all(
    feature = "mux",
    any(
        feature = "trojan",
        feature = "vless",
        feature = "ss",
        feature = "vmess"
    )
))]
fn mux_usize_field(
    name: &str,
    mux_cfg: &serde_json::Value,
    key: &str,
    default: usize,
) -> std::result::Result<usize, String> {
    match mux_cfg.get(key) {
        None => Ok(default),
        Some(serde_json::Value::Number(n)) if n.is_u64() => usize::try_from(n.as_u64().unwrap())
            .map_err(|_| format!("{name}: mux option '{key}' is too large")),
        Some(other) => Err(format!(
            "{name}: mux option '{key}' must be a non-negative integer, got {other:?}"
        )),
    }
}
#[cfg(feature = "vless")]
fn parse_vless_xhttp_config(
    config: &HashMap<String, serde_json::Value>,
    server: &str,
    servername: &str,
    tls: bool,
) -> std::result::Result<meow_transport::xhttp::XhttpConfig, String> {
    use meow_transport::xhttp::{XhttpConfig, MAX_EXTRA_HEADERS, MAX_X_PADDING_BYTES};

    let xhttp_opts = config.get("xhttp-opts");
    let path = xhttp_opts
        .and_then(|o| o.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("/")
        .to_string();
    let fallback_host = if servername.is_empty() {
        server
    } else {
        servername
    };
    let hosts: Vec<String> = match xhttp_opts.and_then(|o| o.get("host")) {
        None => vec![fallback_host.to_string()],
        Some(value) if value.is_string() => {
            vec![value.as_str().expect("checked string").to_string()]
        }
        Some(value) if value.is_array() => value
            .as_array()
            .expect("checked array")
            .iter()
            .map(|item| {
                item.as_str()
                    .map(std::string::ToString::to_string)
                    .ok_or_else(|| "vless: xhttp-opts.host entries must be strings".to_string())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err("vless: xhttp-opts.host must be a string or string array".into());
        }
    };
    if hosts.is_empty() {
        return Err("vless: xhttp-opts.host must not be empty".into());
    }
    // An absent `mode` keeps meow's historical stream-one default — most
    // existing xhttp nodes (non-REALITY included) carry no mode key.
    let mut mode: &str = xhttp_opts
        .and_then(|o| o.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("stream-one");
    // Xray treats an empty mode as auto, so an explicit `mode: ''`
    // resolves like `auto` below — deliberately unlike an absent mode.
    if mode.is_empty() || mode.eq_ignore_ascii_case("auto") {
        // `mode` is reassigned to the resolved value below; `requested`
        // keeps the user's spelling so `mode: ''` is not reported as 'auto'.
        let requested = mode;
        // Xray's client resolution (splithttp/dialer.go): REALITY without
        // `download-settings` is stream-one; with them stream-up, and
        // without REALITY packet-up — neither of which meow implements.
        //
        // Caller contract: parse_vless already ran parse_vless_reality_opts
        // upstream, so a present `reality-opts` key here is usable REALITY.
        let reality = config.contains_key("reality-opts");
        // `null` is no download-settings; Xray's JSON spells it camelCase.
        let split = xhttp_opts.is_some_and(|o| {
            ["download-settings", "downloadSettings"]
                .into_iter()
                .any(|k| o.get(k).is_some_and(|v| !v.is_null()))
        });
        mode = match (reality, split) {
            (true, false) => "stream-one",
            (true, true) => "stream-up",
            (false, _) => "packet-up",
        };
        if mode != "stream-one" {
            let requested = if requested.is_empty() {
                "'' (treated as 'auto')".to_string()
            } else {
                format!("'{requested}'")
            };
            return Err(format!(
                "vless: xhttp mode {requested} resolves to '{mode}' here (as in Xray); \
                 only 'stream-one' is implemented"
            ));
        }
    }
    if !mode.eq_ignore_ascii_case("stream-one") {
        return Err(format!(
            "vless: unsupported xhttp mode '{mode}'; only 'stream-one' is implemented"
        ));
    }
    let extra_headers: Vec<(String, String)> = match xhttp_opts
        .and_then(|o| o.get("headers"))
        .and_then(|h| h.as_object())
    {
        Some(m) => {
            // Bound remotely-supplied header lists — the padding cap below
            // covers the worst case, but a giant `headers` map is still
            // attacker-chosen process memory (issue #648).
            if m.len() > MAX_EXTRA_HEADERS {
                return Err(format!(
                    "vless: xhttp-opts.headers has {} entries (max {MAX_EXTRA_HEADERS})",
                    m.len()
                ));
            }
            m.iter()
                .filter_map(|(k, v)| {
                    let key = k.clone();
                    let val = v.as_str()?.to_string();
                    Some((key, val))
                })
                .collect()
        }
        None => Vec::new(),
    };
    let no_grpc_header = xhttp_opts
        .and_then(|o| o.get("no-grpc-header"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let x_padding_bytes =
        if let Some(padding_val) = xhttp_opts.and_then(|o| o.get("x-padding-bytes")) {
            if let Some(s) = padding_val.as_str() {
                let parts: Vec<&str> = s.split('-').collect();
                if parts.len() != 2 {
                    return Err(format!(
                        "vless: invalid x-padding-bytes range '{s}', expected 'min-max'"
                    ));
                }
                let min = parts[0]
                    .trim()
                    .parse::<usize>()
                    .map_err(|e| format!("vless: invalid min in x-padding-bytes '{s}': {e}"))?;
                let max = parts[1]
                    .trim()
                    .parse::<usize>()
                    .map_err(|e| format!("vless: invalid max in x-padding-bytes '{s}': {e}"))?;
                if min > max {
                    return Err(format!(
                        "vless: x-padding-bytes min ({min}) exceeds max ({max})"
                    ));
                }
                Some((min, max))
            } else if let Some(seq) = padding_val.as_array() {
                if seq.len() != 2 {
                    return Err("vless: x-padding-bytes array must have 2 elements".into());
                }
                // `try_from`, not `as usize` — on 32-bit targets a u64 that
                // exceeds usize::MAX would wrap under the cap check.
                let min = usize::try_from(
                    seq[0]
                        .as_u64()
                        .ok_or_else(|| "vless: invalid min in x-padding-bytes".to_string())?,
                )
                .map_err(|_| "vless: x-padding-bytes min out of range".to_string())?;
                let max = usize::try_from(
                    seq[1]
                        .as_u64()
                        .ok_or_else(|| "vless: invalid max in x-padding-bytes".to_string())?,
                )
                .map_err(|_| "vless: x-padding-bytes max out of range".to_string())?;
                if min > max {
                    return Err(format!(
                        "vless: x-padding-bytes min ({min}) exceeds max ({max})"
                    ));
                }
                Some((min, max))
            } else {
                return Err(
                    "vless: x-padding-bytes must be a 'min-max' string or 2-element integer array"
                        .to_string(),
                );
            }
        } else {
            Some((100, 1000))
        };
    // The padding becomes a `String` of `pad_len` bytes on every connect —
    // unbounded, a provider/subscription node could abort the process via a
    // remote health check or any routed dial (issue #648).
    if let Some((_, max)) = x_padding_bytes {
        if max > MAX_X_PADDING_BYTES {
            return Err(format!(
                "vless: x-padding-bytes max ({max}) exceeds {MAX_X_PADDING_BYTES}"
            ));
        }
    }

    Ok(XhttpConfig {
        path,
        hosts,
        scheme: if tls { "https" } else { "http" }.to_string(),
        extra_headers,
        mode: mode.to_string(),
        no_grpc_header,
        x_padding_bytes,
    })
}

/// Parse the VLESS `encryption` field.
///
/// With the `vless-encryption` feature: `""`/`"none"` → `None`, a
/// `mlkem768x25519plus…` string → a shared [`VlessEncryptionClient`], anything
/// else → error.
#[cfg(all(feature = "vless", feature = "vless-encryption"))]
fn parse_vless_encryption(
    encryption: &str,
) -> std::result::Result<Option<std::sync::Arc<meow_proxy::VlessEncryptionClient>>, String> {
    meow_proxy::parse_client_encryption(encryption)
        .map(|opt| opt.map(std::sync::Arc::new))
        .map_err(|e| format!("vless: {e}"))
}

/// Without the feature: accept only `""`/`"none"`; reject everything else with a
/// diagnostic that points at the missing feature for the ML-KEM string.
#[cfg(all(feature = "vless", not(feature = "vless-encryption")))]
fn parse_vless_encryption(encryption: &str) -> std::result::Result<(), String> {
    if encryption.is_empty() || encryption == "none" {
        return Ok(());
    }
    if encryption.starts_with("mlkem768x25519plus") {
        return Err(format!(
            "vless: encryption '{encryption}' (VLESS post-quantum Encryption) requires the \
             `vless-encryption` Cargo feature; rebuild with --features vless-encryption"
        ));
    }
    Err(format!(
        "vless: encryption '{encryption}' is not supported; set `encryption: none`, omit the \
         field, or use `mlkem768x25519plus…` on a build with the `vless-encryption` feature"
    ))
}

/// Decode a base64 raw-url string the way Go's `base64.RawURLEncoding` does:
/// no padding, and (unlike the crate's strict `URL_SAFE_NO_PAD`) tolerant of a
/// final symbol's non-canonical trailing bits. 3x-ui / Xray configs in the wild
/// carry such keys (see issue #301), so strict decoding would wrongly reject
/// otherwise-valid 32-byte X25519 keys.
#[cfg(feature = "vless")]
fn decode_raw_url_base64_lenient(s: &str) -> Option<Vec<u8>> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    use base64::{alphabet, Engine};
    let engine = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    engine.decode(s).ok()
}

/// Default the TLS ALPN by transport when the user configures none:
/// WebSocket CDNs (notably Cloudflare) route on `http/1.1`; gRPC and h2 run
/// on HTTP/2 and many servers — xray REALITY in particular — reject a client
/// that does not offer `h2` (issue #377). An explicit `alpn:` always wins.
/// upstream: mihomo forces `h2` in its gun (gRPC) transport TLS config.
#[cfg(any(feature = "vless", feature = "vmess"))]
fn default_transport_alpn(network: &str, alpn: Vec<String>) -> Vec<String> {
    if !alpn.is_empty() {
        return alpn;
    }
    match network {
        "ws" => vec!["http/1.1".to_string()],
        "grpc" | "h2" | "xhttp" => vec!["h2".to_string()],
        _ => alpn,
    }
}

/// Drop `ech-opts` from a REALITY connection. mihomo's `StreamTLSConn` takes
/// the REALITY path before it looks at ECH, so subscriptions carrying both
/// work there; the REALITY record layer refuses the pair. Nothing is exposed
/// by dropping it: the REALITY SNI is a public cover name by design.
#[cfg(feature = "vless")]
fn drop_ech_under_reality(name: &str, tls: &mut meow_transport::tls::TlsConfig) {
    if tls.reality.is_some() && tls.ech.take().is_some() {
        tracing::warn!(proxy = %name, "ech-opts is ignored because reality-opts is set");
    }
}

/// Parse VLESS `reality-opts` into transport-layer REALITY parameters.
///
/// Matches mihomo's wire-facing fields: `public-key` is base64 RawURL X25519,
/// `short-id` is hex-decoded and zero-padded to eight bytes, and
/// `support-x25519mlkem768` offers an X25519MLKEM768 key share ahead of
/// X25519 (required by Xray REALITY servers >= 26.9.8).
#[cfg(feature = "vless")]
fn parse_vless_reality_opts(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
) -> std::result::Result<Option<meow_transport::tls::RealityConfig>, String> {
    let Some(opts) = config.get("reality-opts") else {
        return Ok(None);
    };

    let public_key_str = opts
        .get("public-key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "vless: reality-opts.public-key is required".to_string())?;

    let public_key_bytes = decode_raw_url_base64_lenient(public_key_str)
        .ok_or_else(|| "vless: invalid REALITY public key".to_string())?;
    if public_key_bytes.len() != 32 {
        return Err("vless: invalid REALITY public key".into());
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_key_bytes);

    // Subscription generators (e.g. Clash Verge) emit `short-id: null` when
    // the server has no short-id; mihomo treats it as absent (#388).
    //
    // An all-decimal short-id (e.g. `short-id: 1234`, unquoted) parses as a
    // YAML integer rather than a string, so it must be reformatted back to
    // its decimal digits before hex-decoding — otherwise the `as_str()` arm
    // below rejects it and the node is silently dropped. This mirrors
    // mihomo's weakly-typed decoder, which does the same int-to-decimal-string
    // coercion (`common/structure`'s `decodeString`) before hex-decoding, so
    // a subscription that yields a valid node on mihomo yields one here too
    // (#408). Note this only round-trips cleanly when the short-id happens to
    // be all decimal digits, e.g. `0x1f` parses as the number 31 and becomes
    // `"31"`, not `"1f"` — the same lossy coercion mihomo performs. (An
    // all-decimal literal with a leading zero like `0012` resolves as the
    // float `12.0` under serde-saphyr and *does* reach this branch — but the
    // `as_u64`/`as_i64` arms reject a non-integer `Number`, so the node
    // fails `must be a hex string` rather than silently losing the leading
    // zero; quoting is the fix — verified by
    // `parse_vless_reality_opts_leading_zero_short_id_drops_unquoted`.)
    // We warn on the Number coercion (see below) so operators who wrote a
    // notation like `0x1f` expecting it to be read as literal hex digits
    // know to quote the value instead.
    let short_id_str = match opts.get("short-id") {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::Number(n)) => {
            let coerced = n
                .as_u64()
                .map(|u| u.to_string())
                .or_else(|| n.as_i64().map(|i| i.to_string()))
                .ok_or_else(|| "vless: reality-opts.short-id must be a hex string".to_string())?;
            // A bare numeric short-id (e.g. `short-id: 0x1f`) is reinterpreted
            // through YAML's own notation before we ever see it — `0x1f`
            // arrives here as the decimal integer 31, which then hex-decodes
            // to a different byte than the literal hex digits "1f" would.
            // mihomo's decoder has the same lossy behavior, so we match it
            // for the decoded value, but warn so operators who meant the
            // literal digits know to quote the value instead of leaving it
            // as a bare YAML number.
            tracing::warn!(
                proxy = %name,
                "reality-opts.short-id was given as an unquoted YAML number \
                 and coerced to its decimal digits \"{coerced}\" before hex-decoding; \
                 if you wrote a different notation (e.g. `0x1f`) expecting it to be \
                 read as literal hex digits, quote the value instead \
                 (e.g. short-id: \"1f\")"
            );
            coerced
        }
        Some(value) => value
            .as_str()
            .ok_or_else(|| "vless: reality-opts.short-id must be a hex string".to_string())?
            .to_string(),
    };
    let short_id_vec = parse_reality_short_id(&short_id_str)?;
    let mut short_id = [0u8; 8];
    short_id[..short_id_vec.len()].copy_from_slice(&short_id_vec);

    let support_x25519_mlkem768 = opts
        .get("support-x25519mlkem768")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    Ok(Some(meow_transport::tls::RealityConfig {
        public_key,
        short_id,
        support_x25519_mlkem768,
    }))
}

#[cfg(feature = "vless")]
fn parse_reality_short_id(s: &str) -> std::result::Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || s.len() / 2 > 8 {
        return Err("vless: invalid REALITY short ID".into());
    }

    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hex = std::str::from_utf8(chunk)
            .map_err(|_| "vless: invalid REALITY short ID".to_string())?;
        let byte = u8::from_str_radix(hex, 16)
            .map_err(|_| "vless: invalid REALITY short ID".to_string())?;
        out.push(byte);
    }
    Ok(out)
}

/// Parse a UUID string (dashed or hex-only) into a 16-byte array.
///
/// Accepts: `"b831381d-6324-4d53-ad4f-8cda48b30811"` or
///          `"b831381d63244d53ad4f8cda48b30811"`.
#[cfg(feature = "vless")]
fn parse_uuid(s: &str) -> std::result::Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(format!(
            "invalid uuid '{}': expected 32 hex chars (with or without dashes), got {}",
            s,
            hex.len()
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk)
            .map_err(|_| format!("invalid uuid '{s}': non-UTF8 chars"))?;
        bytes[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| format!("invalid uuid '{s}': invalid hex char at byte {i}"))?;
    }
    Ok(bytes)
}

/// Convert a YAML `plugin-opts` value to the SIP003 semicolon-separated format.
/// Accepts either a string (passed through) or a YAML map (serialized as `key=value;...`).
///
/// Nested maps are flattened: `headers` becomes repeated `header=K:V`
/// tokens (the SIP003 convention shared by `v2ray-plugin` and
/// `gost-plugin`), and any other map is dotted into its parent key
/// (`ech-opts: {enable: true}` → `ech-opts.enable=true`).
#[cfg(feature = "ss")]
fn serialize_plugin_opts(opts: &serde_json::Value) -> Option<String> {
    // `;` separates tokens and `=` separates key from value, so neither may
    // appear inside a serialized name or value — otherwise a nested map
    // could smuggle a top-level opt token (e.g. `headers: {X: "a;tls"}`
    // would emit a bare `tls` token).
    fn push_scalar(parts: &mut Vec<String>, key: &str, v: &serde_json::Value) {
        let val = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            // Sequences join on `,` — not a SIP003 separator, and the list
            // opts that exist (shadow-tls `alpn`) are comma-split downstream.
            // An element containing `,` or `;` would splice extra items or
            // a whole extra token into the serialized value, so drop it.
            serde_json::Value::Array(seq) => seq
                .iter()
                .filter_map(|i| {
                    let s = match i {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        serde_json::Value::Number(n) => n.to_string(),
                        other => {
                            tracing::warn!(
                                "plugin-opts: dropping non-scalar sequence element under '{key}': {other:?}"
                            );
                            return None;
                        }
                    };
                    if s.contains([',', ';']) {
                        tracing::warn!(
                            "plugin-opts: dropping sequence element under '{key}' containing a separator: {s:?}"
                        );
                        return None;
                    }
                    Some(s)
                })
                .collect::<Vec<_>>()
                .join(","),
            other => {
                tracing::warn!("plugin-opts: dropping non-scalar value for '{key}': {other:?}");
                return;
            }
        };
        if key.contains([';', '=']) || val.contains(';') {
            tracing::warn!(
                "plugin-opts: dropping '{key}' — ';' and '=' cannot appear in serialized opt names, nor ';' in values"
            );
            return;
        }
        parts.push(format!("{key}={val}"));
    }
    match opts {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) => {
            let mut parts: Vec<String> = Vec::new();
            for (k, v) in map {
                let key = k.as_str();
                match v {
                    serde_json::Value::Object(inner) if key.eq_ignore_ascii_case("headers") => {
                        for (hk, hv) in inner {
                            let hk = hk.as_str();
                            let hv = match hv {
                                serde_json::Value::String(s) => s.clone(),
                                serde_json::Value::Bool(b) => b.to_string(),
                                serde_json::Value::Number(n) => n.to_string(),
                                other => {
                                    tracing::warn!(
                                        "plugin-opts: dropping non-scalar value for header '{hk}': {other:?}"
                                    );
                                    continue;
                                }
                            };
                            if hk.contains([';', '=', ':']) || hv.contains(';') {
                                tracing::warn!(
                                    "plugin-opts: dropping header '{hk}' — ';', '=' and ':' cannot appear in header names, nor ';' in values"
                                );
                                continue;
                            }
                            parts.push(format!("header={hk}:{hv}"));
                        }
                    }
                    serde_json::Value::Object(inner) => {
                        for (sk, sv) in inner {
                            let sk = sk.as_str();
                            push_scalar(&mut parts, &format!("{key}.{sk}"), sv);
                        }
                    }
                    other => push_scalar(&mut parts, key, other),
                }
            }
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(";"))
            }
        }
        _ => None,
    }
}

#[cfg(feature = "vmess")]
fn parse_vmess(
    name: &str,
    config: &HashMap<String, serde_json::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
    global_client_fingerprint: Option<&str>,
) -> std::result::Result<meow_proxy::VmessAdapter, String> {
    use meow_proxy::vmess::header::Security;

    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("vmess: missing server")?;
    let port = required_port(config, "vmess")?;
    let uuid_str = config
        .get("uuid")
        .and_then(|v| v.as_str())
        .ok_or("vmess: missing uuid")?;
    let uuid_bytes = parse_uuid(uuid_str).map_err(|e| format!("vmess: {e}"))?;

    if server.len() > 255 {
        return Err(format!(
            "vmess: server domain is {} bytes; max 255",
            server.len()
        ));
    }

    // alterId: warn-and-coerce to 0
    let alter_id = config
        .get("alterId")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if alter_id > 0 {
        tracing::warn!(
            proxy = %name,
            "vmess: alterId={alter_id} is deprecated and coerced to 0; \
             AEAD header mode is always used"
        );
    }

    let cipher_str = config
        .get("cipher")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    let security = match cipher_str {
        "auto" => meow_proxy::vmess::header::auto_security(),
        "aes-128-gcm" => Security::Aes128Gcm,
        "chacha20-poly1305" => Security::ChaCha20Poly1305,
        "none" => Security::None,
        "zero" => {
            return Err(
                "vmess: cipher 'zero' is rejected — it disables body encryption \
                 with no visual cue in the config (security gap per ADR-0002)"
                    .into(),
            );
        }
        other => return Err(format!("vmess: unsupported cipher '{other}'")),
    };

    let udp = config
        .get("udp")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let tls = config
        .get("tls")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let servername = config
        .get("servername")
        .and_then(|v| v.as_str())
        .unwrap_or(server);
    let alpn: Vec<String> = config
        .get("alpn")
        .and_then(|v| v.as_array())
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
        .collect();
    let network = config
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    let client_fingerprint =
        resolve_node_client_fingerprint(config, "vmess", global_client_fingerprint, false)?;

    // Build transport chain (same pattern as VLESS)
    let mut chain = TransportChain::empty();

    if tls {
        use meow_transport::tls::{TlsConfig, TlsLayer};
        let sni = if servername.is_empty() {
            server.to_string()
        } else {
            servername.to_string()
        };
        let mut tls_cfg = TlsConfig::new(sni);
        tls_cfg.skip_cert_verify = skip_cert_verify;
        tls_cfg.alpn = default_transport_alpn(network, alpn);
        tls_cfg.fingerprint = client_fingerprint;
        let tls_layer =
            TlsLayer::new(&tls_cfg).map_err(|e| format!("vmess: TLS layer error: {e}"))?;
        chain.push(Box::new(tls_layer));
    }

    match network {
        "tcp" => {}
        "ws" => {
            use meow_transport::ws::{WsConfig, WsLayer};
            let ws_opts = config.get("ws-opts");
            let path = ws_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let host_header = ws_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.get("Host"))
                .and_then(|v| v.as_str())
                .map_or_else(|| server.to_string(), std::string::ToString::to_string);
            // `max-early-data` buffers caller writes until the upgrade
            // completes — clamped to the 2048-byte ceiling (the transport
            // layer re-clamps programmatic configs at connect; #648).
            let max_early_data = ws_max_early_data(ws_opts);
            let early_data_header_name = ws_opts
                .and_then(|o| o.get("early-data-header-name"))
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string);
            let ws_cfg = WsConfig {
                path,
                host_header: Some(host_header),
                extra_headers: vec![],
                max_early_data,
                early_data_header_name,
            };
            let ws_layer =
                WsLayer::new(ws_cfg).map_err(|e| format!("vmess: ws layer error: {e}"))?;
            chain.push(Box::new(ws_layer));
        }
        other => {
            return Err(format!(
                "vmess: unsupported network '{other}'; valid values: tcp, ws"
            ));
        }
    }

    #[cfg_attr(not(feature = "mux"), allow(unused_mut))]
    let mut adapter = meow_proxy::VmessAdapter::new(
        name,
        server,
        port,
        uuid_bytes,
        security,
        udp,
        chain,
        Arc::clone(dialer),
    );
    #[cfg(feature = "mux")]
    if let Some(mux_options) = parse_mux_options(name, config)? {
        adapter = adapter.with_mux(mux_options);
    }
    #[cfg(not(feature = "mux"))]
    parse_mux_options(name, config)?;

    Ok(adapter)
}

pub fn parse_proxy_group(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    include_all_proxies: &[Arc<dyn Proxy>],
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(
        config,
        existing_proxies,
        include_all_proxies,
        true,
        providers,
        None,
    )
}

/// Variant of [`parse_proxy_group`] that wires a persistent [`meow_proxy::SelectorStore`]
/// into any `type: select` group it builds, so user picks survive restart.
pub fn parse_proxy_group_with_store(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    include_all_proxies: &[Arc<dyn Proxy>],
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
    store: Option<&Arc<meow_proxy::SelectorStore>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(
        config,
        existing_proxies,
        include_all_proxies,
        true,
        providers,
        store,
    )
}

/// Lenient variant: unknown members are warned and skipped rather than
/// erroring out. The multi-pass group resolver uses the corresponding
/// with-store variant when strict resolution stalls and every declared group
/// dependency has been built, and again on its final fallback when no further
/// progress is possible. This preserves meow-rs's existing missing-member
/// behavior; mihomo instead rejects a group whose static member name is
/// missing.
pub fn parse_proxy_group_lenient(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    include_all_proxies: &[Arc<dyn Proxy>],
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(
        config,
        existing_proxies,
        include_all_proxies,
        false,
        providers,
        None,
    )
}

/// Lenient variant with persistent-selector wiring; see
/// [`parse_proxy_group_lenient`].
pub fn parse_proxy_group_lenient_with_store(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    include_all_proxies: &[Arc<dyn Proxy>],
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
    store: Option<&Arc<meow_proxy::SelectorStore>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(
        config,
        existing_proxies,
        include_all_proxies,
        false,
        providers,
        store,
    )
}

fn parse_proxy_group_inner(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    include_all_proxies: &[Arc<dyn Proxy>],
    strict: bool,
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
    selector_store: Option<&Arc<meow_proxy::SelectorStore>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let mut proxies: Vec<Arc<dyn Proxy>> = Vec::new();

    // Match mihomo: include only top-level `proxies:` entries, not built-ins
    // or proxy groups that happen to have entered the registry already.
    if config.include_all_proxies.unwrap_or(false) {
        for p in include_all_proxies {
            proxies.push(Arc::clone(p));
        }
    }

    let proxy_names = config.proxies.as_deref().unwrap_or(&[]);
    for name in proxy_names {
        match existing_proxies.get(name.as_str()) {
            Some(proxy) => proxies.push(Arc::clone(proxy)),
            None if strict => {
                return Err(format!(
                    "group '{}' references unknown proxy '{}'",
                    config.name, name
                ));
            }
            None => {
                tracing::warn!(
                    "Proxy '{}' not found for group '{}', skipping",
                    name,
                    config.name
                );
            }
        }
    }

    // Group-level filter/exclude-filter/exclude-type (issue #358): applies to
    // provider-sourced members only, mirroring mihomo (static `proxies:`
    // members bypass it — upstream never filters compatible providers).
    let group_filter = crate::proxy_provider::GroupFilter::from_raw_group(config)
        .map_err(|e| format!("group '{}': {e}", config.name))?;
    let provider_slot = |p: &Arc<crate::proxy_provider::ProxyProvider>| match &group_filter {
        Some(f) => p.derived_slot(f),
        None => Arc::clone(&p.slot),
    };

    // Collect provider slots: include_all wires every provider; use: wires
    // specific ones. include-all iterates the map sorted by provider name so
    // the slot order — which defines a load-balance pick space and a
    // selector's default member — is stable across restarts/rebuilds
    // instead of following HashMap iteration order.
    let include_all_providers =
        config.include_all.unwrap_or(false) || config.include_all_providers.unwrap_or(false);
    let slots: Vec<meow_common::ProviderSlot> = if include_all_providers {
        let mut sorted: Vec<_> = providers.iter().collect();
        sorted.sort_by_key(|(name, _)| name.as_str());
        sorted.into_iter().map(|(_, p)| provider_slot(p)).collect()
    } else {
        // Dedupe `use:` entries: listing the same provider twice would
        // double-count its members in a load-balance pick space (and show
        // them twice in `members()` for every group type). Static `proxies:`
        // duplicates keep their double weight — matching upstream.
        let mut seen = std::collections::HashSet::new();
        let mut slots = Vec::new();
        for pname in config.use_providers.as_deref().unwrap_or(&[]) {
            if !seen.insert(pname.as_str()) {
                continue;
            }
            match providers.get(pname.as_str()) {
                Some(p) => slots.push(provider_slot(p)),
                // Relay drops provider slots below anyway — an unknown
                // `use:` name there is inert, not a defect (issue #533).
                None if strict && config.group_type != "relay" => {
                    return Err(format!(
                        "group '{}' references unknown provider '{}'",
                        config.name, pname
                    ));
                }
                None => {
                    tracing::warn!(
                        "proxy-provider '{}' not found for group '{}', skipping",
                        pname,
                        config.name
                    );
                }
            }
        }
        slots
    };

    if proxies.is_empty() && slots.is_empty() {
        return Err(format!(
            "group '{}' has no valid proxies or providers",
            config.name
        ));
    }

    match config.group_type.as_str() {
        "select" => {
            // Class B (ADR-0002): `select` never runs a health-check loop —
            // upstream sweeps its static members since mihomo 90bf158, so
            // warn on the inert probe fields instead of ignoring silently.
            warn_inert_health_fields("select", &config.name, config);
            let mut group = SelectorGroup::new_with_providers(&config.name, proxies, slots)
                .with_display(group_display(config));
            if let Some(store) = selector_store {
                group = group.with_store(Arc::clone(store));
            }
            Ok(Arc::new(group))
        }
        "url-test" => {
            let tolerance = config.tolerance.unwrap_or(150);
            let group = UrlTestGroup::new_with_providers(&config.name, proxies, tolerance, slots)
                .with_runtime_options(
                    config
                        .url
                        .clone()
                        .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_string()),
                    config.expected_status.clone().unwrap_or_default(),
                    selector_store.cloned(),
                )
                .with_display(group_display(config));
            Ok(Arc::new(group))
        }
        "fallback" => {
            let group = FallbackGroup::new_with_providers(&config.name, proxies, slots)
                .with_runtime_options(
                    config
                        .url
                        .clone()
                        .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_string()),
                    config.expected_status.clone().unwrap_or_default(),
                    selector_store.cloned(),
                )
                .with_display(group_display(config));
            Ok(Arc::new(group))
        }
        "load-balance" => {
            let strategy = parse_lb_strategy(config.strategy.as_deref())?;
            Ok(Arc::new(
                LoadBalanceGroup::new_with_providers(&config.name, proxies, strategy, slots)
                    .with_test_url(
                        config
                            .url
                            .clone()
                            .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_string()),
                    )
                    .with_expected_status(config.expected_status.clone().unwrap_or_default())
                    .with_display(group_display(config)),
            ))
        }
        "relay" => {
            // Relay is a fixed static chain — `use:`/`include-all` provider
            // members are dropped here (upstream accepts provider members;
            // `RelayGroup` here is static-only). `parse_relay_group` warns
            // per dropped config field.
            parse_relay_group(&config.name, proxies, config)
        }
        _ => Err(format!("unsupported group type: {}", config.group_type)),
    }
}

/// Warn-once for each health-check field present on a group type that
/// never runs probes (`select`, `relay`).
///
/// Since mihomo `90bf158` (v1.18.4) upstream health-checks the static
/// members of *every* group type; meow sweeps only `fallback`,
/// `url-test`, and `load-balance` — so `url`/`interval`/`lazy`/
/// `tolerance`/`expected-status` are inert here.  Warn rather than
/// silently ignore (Class B, ADR-0002); full parity is tracked in #555.
/// (`tolerance` is `url-test`-only even upstream, so its "sweeps all
/// group types" note refers to the probe loop, not that field.)
fn warn_inert_health_fields(group_type: &str, name: &str, config: &crate::raw::RawProxyGroup) {
    for (field, present) in [
        ("url", config.url.is_some()),
        ("interval", config.interval.is_some()),
        ("lazy", config.lazy.is_some()),
        ("tolerance", config.tolerance.is_some()),
        ("expected-status", config.expected_status.is_some()),
    ] {
        if present {
            // `tolerance` is `url-test`-only even upstream — the sweep
            // note would wrongly imply upstream honors it here.
            let note = if field == "tolerance" {
                " (upstream: `tolerance` is a `url-test`-only field)"
            } else {
                " (upstream: sweeps static members of all group types since \
                 mihomo 90bf158; meow does not — Class B ADR-0002)"
            };
            tracing::warn!(
                group = name,
                "{group_type}: '{field}' is not used by {group_type} groups and will be \
                 ignored.{note}"
            );
        }
    }
}

/// `(field, present)` pairs for the provider-member fields a
/// `RawProxyGroup` can carry — shared by `warn_dropped_provider_fields`
/// and `parse_relay_group`'s empty-`proxies` diagnostic so the list
/// cannot drift between the warn and the error path.
fn provider_member_fields(config: &crate::raw::RawProxyGroup) -> [(&'static str, bool); 6] {
    [
        (
            "use",
            config
                .use_providers
                .as_deref()
                .is_some_and(|u| !u.is_empty()),
        ),
        ("include-all", config.include_all.unwrap_or(false)),
        (
            "include-all-providers",
            config.include_all_providers.unwrap_or(false),
        ),
        ("filter", config.filter.is_some()),
        ("exclude-filter", config.exclude_filter.is_some()),
        ("exclude-type", config.exclude_type.is_some()),
    ]
}

/// Warn-once for each provider-member field present on a group type that
/// never consumes provider slots (currently only `relay` — upstream
/// `NewRelay` takes providers; `RelayGroup` here is static-only).
/// `filter`/`exclude-*` act on provider members only on every group type,
/// so they are inert wherever no provider can supply members.
fn warn_dropped_provider_fields(group_type: &str, name: &str, config: &crate::raw::RawProxyGroup) {
    for (field, present) in provider_member_fields(config) {
        if present {
            tracing::warn!(
                group = name,
                "{group_type}: '{field}' is not used by {group_type} groups and will be \
                 ignored; {group_type} members come from 'proxies'/'include-all-proxies' \
                 only. (upstream: {group_type} accepts provider members — Class B ADR-0002)"
            );
        }
    }
}

/// Parse a `type: relay` group config block into a `RelayGroup`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `proxies` is empty — upstream panics; we hard-error.
/// - `proxies` has length 1 — upstream silently acts as passthrough; we
///   hard-error with a diagnostic pointing to the correct group type.
///
/// # Warn-once (Class B per ADR-0002)
///
/// - `url`/`interval`/`lazy`/`tolerance`/`expected-status` present —
///   ignored; relay has no health-check loop.
/// - `use`/`include-all`/`include-all-providers`/`filter`/`exclude-filter`/
///   `exclude-type` present — ignored; upstream relay accepts provider
///   members, ours is static-only.
///
/// upstream: adapter/outbound/relay.go
fn parse_relay_group(
    name: &str,
    proxies: Vec<Arc<dyn Proxy>>,
    config: &crate::raw::RawProxyGroup,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    // Hard-error: empty proxies list. upstream panics. NOT panic. Class A.
    // A `use:`/`include-all`-only relay reaches here on provider slots
    // alone — name the dropped fields so the user sees why the list is
    // empty instead of a bare "no proxies" error.
    if proxies.is_empty() {
        let provider_hint = if provider_member_fields(config)
            .iter()
            .any(|(_, present)| *present)
        {
            " Provider fields ('use'/'include-all*') do not supply relay \
             members — relay chains come from 'proxies'/'include-all-proxies' \
             only."
        } else {
            ""
        };
        return Err(format!(
            "relay group '{name}': proxies list is empty; \
             relay requires at least 2 proxies.{provider_hint} \
             (upstream: panics; we reject — Class A ADR-0002)"
        ));
    }

    // Hard-error: single proxy. upstream silently acts as passthrough. Class A.
    if proxies.len() < 2 {
        return Err(format!(
            "relay group '{}': requires at least 2 proxies, got {}; \
             use `type: selector` or `type: direct` for a single proxy. \
             (upstream: silently acts as passthrough; we reject — Class A ADR-0002)",
            name,
            proxies.len()
        ));
    }

    // Warn-once on inert fields (Class B — relay has no probe loop and
    // consumes no provider slots).
    warn_inert_health_fields("relay", name, config);
    warn_dropped_provider_fields("relay", name, config);

    Ok(Arc::new(
        RelayGroup::new(name, proxies).with_display(group_display(config)),
    ))
}

/// A group's `hidden:` / `icon:` keys, defaulting to shown with no icon.
fn group_display(config: &crate::raw::RawProxyGroup) -> GroupDisplay {
    GroupDisplay {
        hidden: config.hidden.unwrap_or(false),
        icon: config.icon.as_deref().unwrap_or_default().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::rdata::AAAA;
    use hickory_proto::rr::{RData, Record, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use std::net::Ipv6Addr;

    fn parse_proxy(
        config: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<Arc<dyn Proxy>, String> {
        super::parse_proxy(config, true)
    }

    fn proxy_config(yaml: &str) -> HashMap<String, serde_json::Value> {
        serde_saphyr::from_str(yaml).unwrap()
    }

    /// Omitted `smux:` pool fields resolve to `MuxOptions::default` — the
    /// parser must not carry a second copy of the 4/4/4 constants that can
    /// drift from the runtime source of truth.
    #[cfg(all(
        feature = "mux",
        any(
            feature = "trojan",
            feature = "vless",
            feature = "ss",
            feature = "vmess"
        )
    ))]
    #[test]
    fn smux_omitted_pool_fields_use_muxoptions_default() {
        let node = proxy_config(
            "name: n\ntype: trojan\nserver: s\nport: 443\npassword: p\nsmux:\n  enabled: true\n",
        );
        let opts = parse_mux_options("n", &node).unwrap().unwrap();
        assert_eq!(opts, meow_proxy::mux::MuxOptions::default());
    }

    /// A single explicit field overrides only that field; the rest still
    /// come from `MuxOptions::default`.
    #[cfg(all(
        feature = "mux",
        any(
            feature = "trojan",
            feature = "vless",
            feature = "ss",
            feature = "vmess"
        )
    ))]
    #[test]
    fn smux_partial_override_keeps_other_defaults() {
        let node = proxy_config(
            "name: n\ntype: trojan\nserver: s\nport: 443\npassword: p\nsmux:\n  enabled: true\n  max-streams: 2\n",
        );
        let opts = parse_mux_options("n", &node).unwrap().unwrap();
        let expected = meow_proxy::mux::MuxOptions {
            max_streams: 2,
            ..Default::default()
        };
        assert_eq!(opts, expected);
    }

    /// The legacy `mux:` alias feeds the same parse; `smux:` wins when both
    /// are present.
    #[cfg(all(
        feature = "mux",
        any(
            feature = "trojan",
            feature = "vless",
            feature = "ss",
            feature = "vmess"
        )
    ))]
    #[test]
    fn smux_key_takes_precedence_over_mux_alias() {
        let node = proxy_config(
            "name: n\ntype: trojan\nserver: s\nport: 443\npassword: p\n\
             smux:\n  enabled: true\n  max-streams: 2\n\
             mux:\n  enabled: true\n  max-streams: 9\n",
        );
        let opts = parse_mux_options("n", &node).unwrap().unwrap();
        assert_eq!(opts.max_streams, 2);
    }

    #[cfg(feature = "vless")]
    #[test]
    fn lenient_base64_accepts_noncanonical_trailing_bits() {
        // The REALITY public-key from issue #301 has non-canonical base64
        // trailing bits; Go decodes it, and so must we (32-byte X25519 key).
        let key = "OKkD6Wt1lC4-9avJj2t3PkvIDkvcA1Fu0b09QwJ7GGh";
        let decoded = decode_raw_url_base64_lenient(key).expect("must decode");
        assert_eq!(decoded.len(), 32);
        // Garbage is still rejected.
        assert!(decode_raw_url_base64_lenient("!!!not base64!!!").is_none());
    }

    // ─── global-client-fingerprint (issue #974) ─────────────────────────

    #[test]
    fn normalize_client_fingerprint_trims_lowercases_and_clears() {
        for (raw, expected) in [
            (None, None),
            (Some(""), None),
            (Some("   "), None),
            (Some("none"), None),
            (Some(" NoNe "), None),
            (Some(" Chrome "), Some("chrome")),
            (Some("FIREFOX120"), Some("firefox120")),
            (Some("random"), Some("random")),
        ] {
            assert_eq!(
                normalize_client_fingerprint(raw).as_deref(),
                expected,
                "{raw:?}"
            );
        }
    }

    /// The per-node resolution contract (mihomo's `ClientFingerprint == ""`
    /// fallback): absent/null/empty/whitespace inherits the normalized
    /// global, an explicit `none` opts out — literally under REALITY, where
    /// no unshaped hello exists — and an explicit value always wins.
    #[test]
    fn resolve_node_client_fingerprint_precedence() {
        let node = |extra: &str| -> HashMap<String, serde_json::Value> {
            serde_saphyr::from_str(&format!("name: n\ntype: socks5\n{extra}")).unwrap()
        };
        for cfg in [
            node(""),
            node("client-fingerprint: null\n"),
            node("client-fingerprint: \"\"\n"),
            node("client-fingerprint: \"  \"\n"),
        ] {
            assert_eq!(
                resolve_node_client_fingerprint(&cfg, "ss", Some(" Chrome "), false)
                    .unwrap()
                    .as_deref(),
                Some("chrome"),
                "{cfg:?} must inherit the global"
            );
            assert_eq!(
                resolve_node_client_fingerprint(&cfg, "ss", None, false).unwrap(),
                None,
                "{cfg:?} must stay unset with no global"
            );
        }
        let opt_out = node("client-fingerprint: none\n");
        assert_eq!(
            resolve_node_client_fingerprint(&opt_out, "ss", Some("chrome"), false).unwrap(),
            None,
            "explicit none must opt out of the global"
        );
        assert_eq!(
            resolve_node_client_fingerprint(&opt_out, "vless", Some("chrome"), true)
                .unwrap()
                .as_deref(),
            Some("none"),
            "REALITY keeps the literal so profile resolution warns + falls back"
        );
        let winner = node("client-fingerprint: Safari\n");
        assert_eq!(
            resolve_node_client_fingerprint(&winner, "ss", Some("chrome"), false)
                .unwrap()
                .as_deref(),
            Some("safari"),
            "an explicit node value wins, normalized"
        );
    }

    #[test]
    fn resolve_node_client_fingerprint_rejects_non_string() {
        let cfg: HashMap<String, serde_json::Value> =
            serde_saphyr::from_str("name: n\ntype: vmess\nclient-fingerprint: [chrome]\n").unwrap();
        assert_eq!(
            resolve_node_client_fingerprint(&cfg, "vmess", None, false).unwrap_err(),
            "vmess: client-fingerprint must be a string"
        );
    }

    /// VLESS + REALITY is the headline contract: a verbatim mihomo config
    /// declares the fingerprint only at the top level, so the node must
    /// inherit it — while the same node with neither a node nor a global
    /// fingerprint keeps the uTLS hard error.
    #[cfg(feature = "vless")]
    #[test]
    fn vless_reality_inherits_global_client_fingerprint() {
        const NODE: &str = "name: v\ntype: vless\nserver: example.com\nport: 443\nuuid: b831381d-6324-4d53-ad4f-8cda48b30811\ntls: true\nreality-opts:\n  public-key: hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\n";
        let direct: std::sync::Arc<dyn meow_proxy::dialer::TcpDialer> =
            std::sync::Arc::new(meow_proxy::dialer::DirectDialer);

        let bare = proxy_config(NODE);
        let err = parse_proxy_with_dialer_and_fp(&bare, &direct, false, None)
            .err()
            .expect("REALITY without any fingerprint must stay refused");
        assert!(
            err.contains("REALITY is based on uTLS, please set a client-fingerprint"),
            "{err}"
        );
        parse_proxy_with_dialer_and_fp(&bare, &direct, false, Some("chrome"))
            .expect("the global fingerprint must satisfy REALITY");

        // An explicit node fingerprint wins over the global; an explicit
        // `none` stays the REALITY literal (warn + Chrome fallback), which
        // counts as set for the uTLS gate.
        let own = proxy_config(&format!("{NODE}client-fingerprint: firefox\n"));
        parse_proxy_with_dialer_and_fp(&own, &direct, false, Some("chrome"))
            .expect("the node fingerprint must apply");
        let none = proxy_config(&format!("{NODE}client-fingerprint: none\n"));
        parse_proxy_with_dialer_and_fp(&none, &direct, false, Some("chrome"))
            .expect("explicit none stays the REALITY literal, not a parse error");
    }

    /// `quic: true` runs over quiche — no uTLS exists to shape, so the
    /// global must not be inherited there, while a per-node
    /// `client-fingerprint` keeps its "cannot honor" rejection.
    #[cfg(feature = "trusttunnel-h3")]
    #[test]
    fn trusttunnel_quic_ignores_global_client_fingerprint() {
        let direct: std::sync::Arc<dyn meow_proxy::dialer::TcpDialer> =
            std::sync::Arc::new(meow_proxy::dialer::DirectDialer);
        let quic = proxy_config(
            "name: t\ntype: trusttunnel\nserver: t.test\nport: 443\nusername: u\npassword: p\nquic: true\n",
        );
        let adapter = parse_proxy_with_dialer_and_fp(&quic, &direct, false, Some("chrome"))
            .expect("the global fingerprint is TCP-only — H3 must not inherit it");
        assert_eq!(
            adapter.client_fingerprint(),
            None,
            "quiche has no uTLS to shape: the adapter must report no baked fingerprint"
        );
        let with_node = proxy_config(
            "name: t\ntype: trusttunnel\nserver: t.test\nport: 443\nusername: u\npassword: p\nquic: true\nclient-fingerprint: chrome\n",
        );
        let err = parse_proxy_with_dialer_and_fp(&with_node, &direct, false, Some("chrome"))
            .err()
            .expect("a per-node fingerprint under H3 stays refused");
        assert!(err.contains("cannot honor client-fingerprint"), "{err}");
    }

    /// Hysteria2's `fingerprint` is certificate pinning, a different field —
    /// the global uTLS fallback must not reach it.
    #[cfg(feature = "hysteria2")]
    #[test]
    fn hysteria2_is_unaffected_by_global_client_fingerprint() {
        let direct: std::sync::Arc<dyn meow_proxy::dialer::TcpDialer> =
            std::sync::Arc::new(meow_proxy::dialer::DirectDialer);
        let cfg =
            proxy_config("name: h\ntype: hysteria2\nserver: h.test\nport: 443\npassword: p\n");
        parse_proxy_with_dialer_and_fp(&cfg, &direct, false, Some("chrome"))
            .expect("hysteria2 must ignore the uTLS global entirely");
    }

    /// The per-site wiring (issue #974): the normalized global must reach
    /// each protocol's own TLS config — `client_fingerprint()` reads what
    /// the adapter actually baked, so a call site that dropped the global
    /// argument cannot fake it. shadow-tls v1 keeps its upstream TLS 1.2
    /// cap: even an inherited fingerprint is dropped there.
    #[cfg(any(
        feature = "vmess",
        feature = "anytls",
        feature = "shadow-tls",
        feature = "trusttunnel"
    ))]
    #[tokio::test]
    async fn protocol_sites_inherit_global_client_fingerprint() {
        let direct: std::sync::Arc<dyn meow_proxy::dialer::TcpDialer> =
            std::sync::Arc::new(meow_proxy::dialer::DirectDialer);
        let baked = |yaml: &str, global: Option<&str>| {
            parse_proxy_with_dialer_and_fp(&proxy_config(yaml), &direct, false, global)
                .map(|proxy| proxy.client_fingerprint().map(str::to_string))
        };

        #[cfg(feature = "vmess")]
        {
            // `tls: true` — the fingerprint lands on the TLS layer.
            assert_eq!(
                baked(
                    "name: v\ntype: vmess\nserver: v.test\nport: 443\nuuid: b831381d-6324-4d53-ad4f-8cda48b30811\ntls: true\n",
                    Some(" Chrome "),
                ),
                Ok(Some("chrome".to_string())),
                "vmess: the normalized global must reach the TLS config"
            );
            // The node's own value still wins over the global.
            assert_eq!(
                baked(
                    "name: v\ntype: vmess\nserver: v.test\nport: 443\nuuid: b831381d-6324-4d53-ad4f-8cda48b30811\ntls: true\nclient-fingerprint: firefox\n",
                    Some("chrome"),
                ),
                Ok(Some("firefox".to_string()))
            );
        }
        #[cfg(feature = "anytls")]
        assert_eq!(
            baked(
                "name: a\ntype: anytls\nserver: a.test\nport: 443\npassword: p\n",
                Some("chrome"),
            ),
            Ok(Some("chrome".to_string())),
            "anytls: the global must reach the TLS config"
        );
        #[cfg(feature = "shadow-tls")]
        {
            const SS: &str = "name: s\ntype: ss\nserver: s.test\nport: 8388\ncipher: aes-256-gcm\npassword: pw\nplugin: shadow-tls\n";
            assert_eq!(
                baked(
                    &format!(
                        "{SS}plugin-opts:\n  host: cover.test\n  version: 3\n  password: psk\n"
                    ),
                    Some("chrome"),
                ),
                Ok(Some("chrome".to_string())),
                "shadow-tls: the global must reach the cover handshake"
            );
            // v1's TLS 1.2 cap drops even an inherited fingerprint.
            assert_eq!(
                baked(
                    &format!(
                        "{SS}plugin-opts:\n  host: cover.test\n  version: 1\n  password: psk\n"
                    ),
                    Some("chrome"),
                ),
                Ok(None),
            );
        }
        #[cfg(feature = "trusttunnel")]
        assert_eq!(
            baked(
                "name: t\ntype: trusttunnel\nserver: t.test\nport: 443\nusername: u\npassword: p\n",
                Some("chrome"),
            ),
            Ok(Some("chrome".to_string())),
            "trusttunnel h2: the global must reach the TLS config"
        );
    }

    /// `support-x25519mlkem768` reaches `RealityConfig` verbatim; absent
    /// or non-bool stays off — the `as_bool` fail-closed convention the
    /// other weakly-typed opts follow.
    #[cfg(feature = "vless")]
    #[test]
    fn reality_opts_support_x25519mlkem768_maps_to_config_flag() {
        const KEY: &str = "public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
        for (line, expected) in [
            ("support-x25519mlkem768: true", true),
            ("support-x25519mlkem768: false", false),
            // `as_bool` on a non-bool yields None — off, not an error.
            ("support-x25519mlkem768: \"yes\"", false),
            ("support-x25519mlkem768: 1", false),
        ] {
            let config = proxy_config(&format!("reality-opts:\n  {KEY}\n  {line}\n"));
            let reality = parse_vless_reality_opts("v", &config)
                .expect("reality-opts must parse")
                .expect("reality-opts present");
            assert_eq!(reality.support_x25519_mlkem768, expected, "{line}");
        }
        let config = proxy_config(&format!("reality-opts:\n  {KEY}\n"));
        let reality = parse_vless_reality_opts("v", &config)
            .expect("reality-opts must parse")
            .expect("reality-opts present");
        assert!(!reality.support_x25519_mlkem768, "flag defaults to off");
    }

    #[cfg(any(feature = "vless", feature = "vmess"))]
    #[test]
    fn default_alpn_follows_transport() {
        // Explicit alpn always wins.
        assert_eq!(
            default_transport_alpn("grpc", vec!["custom".to_string()]),
            vec!["custom".to_string()]
        );
        // ws → http/1.1 (CDN routing); grpc/h2 → h2 (HTTP/2 transports —
        // xray REALITY rejects clients that don't offer it, issue #377).
        assert_eq!(
            default_transport_alpn("ws", Vec::new()),
            vec!["http/1.1".to_string()]
        );
        assert_eq!(
            default_transport_alpn("grpc", Vec::new()),
            vec!["h2".to_string()]
        );
        assert_eq!(
            default_transport_alpn("h2", Vec::new()),
            vec!["h2".to_string()]
        );
        assert_eq!(
            default_transport_alpn("xhttp", Vec::new()),
            vec!["h2".to_string()]
        );
        // Plain TCP keeps ALPN absent.
        assert!(default_transport_alpn("tcp", Vec::new()).is_empty());
    }

    #[cfg(feature = "vless")]
    #[test]
    fn xhttp_config_resolves_fields_and_fallbacks() {
        let full = proxy_config(
            "name: v\ntype: vless\nserver: 203.0.113.7\nport: 443\n\
             uuid: b831381d-6324-4d53-ad4f-8cda48b30811\ntls: true\n\
             servername: cdn.example.com\nnetwork: xhttp\nxhttp-opts:\n\
             \x20 path: /testpath\n\x20 host: xhttp.example.com\n\
             \x20 mode: stream-one\n\x20 no-grpc-header: true\n\
             \x20 x-padding-bytes: 200-800\n\x20 headers:\n\x20\x20 X-Custom: Hello\n",
        );
        let parsed = parse_vless_xhttp_config(&full, "203.0.113.7", "cdn.example.com", true)
            .expect("full xhttp config");
        assert_eq!(parsed.path, "/testpath");
        assert_eq!(parsed.hosts, ["xhttp.example.com"]);
        assert_eq!(parsed.scheme, "https");
        assert_eq!(parsed.mode, "stream-one");
        assert!(parsed.no_grpc_header);
        assert_eq!(parsed.x_padding_bytes, Some((200, 800)));
        assert_eq!(parsed.extra_headers, [("X-Custom".into(), "Hello".into())]);

        let fallback = proxy_config("xhttp-opts:\n  path: /fallback\n");
        let parsed = parse_vless_xhttp_config(&fallback, "203.0.113.7", "cdn.example.com", true)
            .expect("fallback xhttp config");
        assert_eq!(parsed.hosts, ["cdn.example.com"]);
        assert_eq!(parsed.x_padding_bytes, Some((100, 1000)));

        let parsed = parse_vless_xhttp_config(&HashMap::new(), "2001:db8::1", "", false)
            .expect("h2c xhttp config");
        assert_eq!(parsed.hosts, ["2001:db8::1"]);
        assert_eq!(parsed.scheme, "http");
    }

    /// `mode: auto` resolves as Xray's client does: stream-one under REALITY
    /// without download-settings; stream-up / packet-up are refused.
    #[cfg(feature = "vless")]
    #[test]
    fn xhttp_auto_mode_resolves_like_xray() {
        let reality =
            proxy_config("reality-opts:\n  public-key: k\nxhttp-opts:\n  path: /x\n  mode: auto\n");
        let parsed = parse_vless_xhttp_config(&reality, "203.0.113.7", "cdn.example.com", true)
            .expect("auto + REALITY is stream-one");
        assert_eq!(parsed.mode, "stream-one");

        let split = proxy_config(
            "reality-opts:\n  public-key: k\nxhttp-opts:\n  mode: auto\n  download-settings:\n    path: /d\n",
        );
        let err = parse_vless_xhttp_config(&split, "203.0.113.7", "cdn.example.com", true)
            .expect_err("auto + download-settings is stream-up");
        assert!(err.contains("stream-up"), "{err}");

        for edge in [
            "reality-opts:\n  public-key: k\nxhttp-opts:\n  mode: ''\n",
            "reality-opts:\n  public-key: k\nxhttp-opts:\n  mode: auto\n  download-settings: null\n",
        ] {
            let parsed = parse_vless_xhttp_config(
                &proxy_config(edge),
                "203.0.113.7",
                "cdn.example.com",
                true,
            )
            .expect("empty mode / null download-settings is stream-one");
            assert_eq!(parsed.mode, "stream-one");
        }
        let camel = proxy_config(
            "reality-opts:\n  public-key: k\nxhttp-opts:\n  mode: auto\n  downloadSettings:\n    path: /d\n",
        );
        assert!(
            parse_vless_xhttp_config(&camel, "203.0.113.7", "cdn.example.com", true).is_err(),
            "camelCase downloadSettings is stream-up"
        );

        let tls = proxy_config("xhttp-opts:\n  mode: auto\n");
        let err = parse_vless_xhttp_config(&tls, "203.0.113.7", "cdn.example.com", true)
            .expect_err("auto without REALITY is packet-up");
        assert!(err.contains("packet-up"), "{err}");

        // `mode: ''` resolves the same way, but the error must name the
        // user's own (empty) spelling, not 'auto'.
        let empty = proxy_config("xhttp-opts:\n  mode: ''\n");
        let err = parse_vless_xhttp_config(&empty, "203.0.113.7", "cdn.example.com", true)
            .expect_err("empty mode without REALITY is packet-up");
        assert!(err.contains("mode '' (treated as 'auto')"), "{err}");
        assert!(err.contains("packet-up"), "{err}");
        assert!(!err.contains("mode 'auto'"), "{err}");
    }

    #[cfg(feature = "vless")]
    #[test]
    fn xhttp_padding_bytes_bounded() {
        // Over-cap padding is a remotely-configurable allocation — a hostile
        // provider/subscription node must not parse (issue #648).
        for opts in [
            "x-padding-bytes: 0-70000",
            "x-padding-bytes: \"9000000000000000000-9000000000000000000\"",
            "x-padding-bytes: [0, 70000]",
        ] {
            let cfg = proxy_config(&format!("xhttp-opts:\n  path: /x\n  {opts}\n"));
            let Err(err) = parse_vless_xhttp_config(&cfg, "203.0.113.7", "cdn.example.com", true)
            else {
                panic!("{opts:?} must be rejected")
            };
            assert!(err.contains("exceeds"), "{opts:?}: {err}");
        }
        for opts in [
            // Inverted range — both string and sequence forms.
            "x-padding-bytes: 800-200",
            "x-padding-bytes: [800, 200]",
            // A bare scalar is neither a "min-max" string nor a 2-seq.
            "x-padding-bytes: 100",
            // A u64 that wraps `usize` on 32-bit targets must not sneak
            // under the cap via the sequence form.
            "x-padding-bytes: [0, 18446744073709551615]",
        ] {
            let cfg = proxy_config(&format!("xhttp-opts:\n  path: /x\n  {opts}\n"));
            assert!(
                parse_vless_xhttp_config(&cfg, "203.0.113.7", "cdn.example.com", true).is_err(),
                "{opts:?} must be rejected"
            );
        }
        let ok = proxy_config("xhttp-opts:\n  path: /x\n  x-padding-bytes: 0-65536\n");
        assert!(
            parse_vless_xhttp_config(&ok, "203.0.113.7", "cdn.example.com", true).is_ok(),
            "at-cap padding must stay accepted"
        );
        // `0-0` disables padding upstream — stays accepted.
        let disabled = proxy_config("xhttp-opts:\n  path: /x\n  x-padding-bytes: 0-0\n");
        assert!(
            parse_vless_xhttp_config(&disabled, "203.0.113.7", "cdn.example.com", true).is_ok(),
            "'0-0' (disable) must stay accepted"
        );
    }

    #[cfg(feature = "vless")]
    #[test]
    fn xhttp_headers_bounded() {
        // A remote `headers` map is attacker-chosen process memory — cap the
        // count like the padding bound (issue #648).
        use meow_transport::xhttp::MAX_EXTRA_HEADERS;
        use std::fmt::Write;
        let mut opts = String::from("xhttp-opts:\n  path: /x\n  headers:\n");
        for i in 0..=MAX_EXTRA_HEADERS {
            writeln!(opts, "    X-H{i}: v").unwrap();
        }
        let cfg = proxy_config(&opts);
        let err = parse_vless_xhttp_config(&cfg, "203.0.113.7", "cdn.example.com", true)
            .expect_err("65 headers must be rejected");
        assert!(err.contains("headers"), "msg: {err}");
    }

    #[cfg(feature = "vless")]
    #[test]
    fn httpupgrade_headers_bounded() {
        // Sibling path to xhttp-opts.headers (issue #648).
        use meow_transport::httpupgrade::MAX_EXTRA_HEADERS;
        use std::fmt::Write;
        let mut opts = String::from(
            "name: v\ntype: vless\nserver: 203.0.113.7\nport: 443\n\
             uuid: b831381d-6324-4d53-ad4f-8cda48b30811\n\
             network: httpupgrade\nhttp-upgrade-opts:\n  path: /x\n  headers:\n",
        );
        for i in 0..=MAX_EXTRA_HEADERS {
            writeln!(opts, "    X-H{i}: v").unwrap();
        }
        let cfg = proxy_config(&opts);
        let Err(err) = parse_proxy(&cfg) else {
            panic!("65 headers must be rejected")
        };
        assert!(err.contains("headers"), "msg: {err}");
    }

    #[cfg(any(feature = "vless", feature = "vmess"))]
    #[test]
    fn ws_max_early_data_clamps_to_ceiling() {
        use meow_transport::ws::MAX_WS_EARLY_DATA;
        // Absent → disabled.
        assert_eq!(ws_max_early_data(None), 0);
        // Boundary: the ceiling itself survives.
        let at_cap = serde_saphyr::from_str::<serde_json::Value>(&format!(
            "max-early-data: {MAX_WS_EARLY_DATA}"
        ))
        .unwrap();
        assert_eq!(ws_max_early_data(Some(&at_cap)), MAX_WS_EARLY_DATA);
        // Above → clamped (not rejected; excess bytes flow as normal frames).
        let over = serde_saphyr::from_str::<serde_json::Value>("max-early-data: 99999").unwrap();
        assert_eq!(ws_max_early_data(Some(&over)), MAX_WS_EARLY_DATA);
        // u64::MAX must not wrap the usize conversion.
        let huge =
            serde_saphyr::from_str::<serde_json::Value>("max-early-data: 18446744073709551615")
                .unwrap();
        assert_eq!(ws_max_early_data(Some(&huge)), MAX_WS_EARLY_DATA);
    }

    #[test]
    fn parse_proxy_rejects_port_overflow() {
        let cfg = proxy_config("name: bad\ntype: http\nserver: 1.2.3.4\nport: 65536\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("overflowing port must hard-error");
        };
        assert!(err.contains("exceeds 65535"), "msg: {err}");
    }

    #[test]
    fn parse_proxy_rejects_port_zero() {
        let cfg = proxy_config("name: bad\ntype: http\nserver: 1.2.3.4\nport: 0\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("zero port must hard-error");
        };
        assert!(err.contains("port must be non-zero"), "msg: {err}");
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_map() {
        let yaml: serde_json::Value = serde_saphyr::from_str(
            r#"
mode: websocket
host: example.com
tls: true
"#,
        )
        .unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert!(result.contains("mode=websocket"));
        assert!(result.contains("host=example.com"));
        assert!(result.contains("tls=true"));
        // Verify semicolon-separated format
        assert_eq!(result.matches(';').count(), 2);
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_string_passthrough() {
        let yaml = serde_json::Value::String("obfs=http;obfs-host=example.com".to_string());
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert_eq!(result, "obfs=http;obfs-host=example.com");
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_none_cases() {
        // Every empty-ish YAML value must serialize to None. `empty mapping`
        // exercises the `parts.is_empty()` branch; `null` exercises the
        // catch-all arm of serialize_plugin_opts.
        let cases: [(&str, serde_json::Value); 2] = [
            (
                "empty mapping",
                serde_json::Value::Object(serde_json::Map::new()),
            ),
            ("null", serde_json::Value::Null),
        ];
        for (label, yaml) in cases {
            assert!(
                serialize_plugin_opts(&yaml).is_none(),
                "{label}: expected None, got {:?}",
                serialize_plugin_opts(&yaml)
            );
        }
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_number_value() {
        let yaml: serde_json::Value = serde_saphyr::from_str("port: 8080").unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert_eq!(result, "port=8080");
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_nested_maps() {
        // gost-plugin takes a `headers` map and an `ech-opts` map
        // (issue #533).  `headers` flattens to repeated `header=K:V`
        // tokens (SIP003 convention); any other nested map is dotted.
        let yaml: serde_json::Value = serde_saphyr::from_str(
            "mode: websocket\nheaders:\n  CF-Token: abc\n  Host: edge.example.com\nech-opts:\n  enable: true\n  config: QUJD\n",
        )
        .unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        // serde_json::Map is a BTreeMap — the emitted opt order is sorted by
        // key, not YAML document order. SIP003 opts are unordered anyway.
        assert_eq!(
            result,
            "ech-opts.config=QUJD;ech-opts.enable=true;header=CF-Token:abc;\
             header=Host:edge.example.com;mode=websocket"
        );
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_token_smuggling_guard() {
        // A `;`/`=`/`:` inside a serialized name or value would split into
        // extra SIP003 tokens — entries containing them are dropped.
        let yaml: serde_json::Value = serde_saphyr::from_str(
            "mode: websocket\nheaders:\n  \"x;skip-cert-verify\": true\n  Good: ok\n\
             weird;key: v\nfine: a;b\n",
        )
        .unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        let mut tokens = result.split(';');
        // BTreeMap key order: `headers` sorts before `mode`.
        assert_eq!(tokens.next(), Some("header=Good:ok"));
        assert_eq!(tokens.next(), Some("mode=websocket"));
        assert!(tokens.next().is_none(), "smuggled tokens leaked: {result}");
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_headers_case_insensitive() {
        // mapstructure decodes `Headers` onto the `headers` field — match
        // its case-insensitive key handling.
        let yaml: serde_json::Value =
            serde_saphyr::from_str("mode: websocket\nHeaders:\n  X-A: b\n").unwrap();
        // BTreeMap key order: `Headers` sorts before `mode`.
        assert_eq!(
            serialize_plugin_opts(&yaml).unwrap(),
            "header=X-A:b;mode=websocket"
        );
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_sequence_join() {
        // `alpn` arrives as a YAML sequence (upstream `alpn []string`) —
        // joined with `,`, which the shadow-tls parser splits back out.
        let yaml: serde_json::Value =
            serde_saphyr::from_str("alpn:\n  - h2\n  - http/1.1\nversion: 3\n").unwrap();
        assert_eq!(
            serialize_plugin_opts(&yaml).unwrap(),
            "alpn=h2,http/1.1;version=3"
        );
    }

    /// End-to-end junction: `plugin-opts` map → SIP003 serialization →
    /// the in-process shadow-tls parser → adapter construction, incl.
    /// the `alpn` sequence and node-level `client-fingerprint` plumbing.
    #[cfg(feature = "shadow-tls")]
    #[test]
    fn test_shadow_tls_node_parse_e2e() {
        let cfg = proxy_config(
            "name: stls\ntype: ss\nserver: 1.2.3.4\nport: 8388\n\
             cipher: aes-256-gcm\npassword: pw\nclient-fingerprint: chrome\n\
             plugin: shadow-tls\nplugin-opts:\n  host: cover.example.com\n  \
             password: psk\n  version: 3\n  alpn:\n    - h2\n    - http/1.1\n",
        );
        let adapter = parse_proxy(&cfg).expect("shadow-tls node must parse");
        assert_eq!(adapter.name(), "stls");
        assert!(
            !is_external_sip003_plugin(Some("shadow-tls")),
            "provider/subscription path must treat shadow-tls as built-in"
        );

        // An invalid opt proves the serialized string reached the
        // shadow-tls parser — a misrouted plugin would parse as a no-op.
        let cfg = proxy_config(
            "name: stls\ntype: ss\nserver: 1.2.3.4\nport: 8388\n\
             cipher: aes-256-gcm\npassword: pw\n\
             plugin: shadow-tls\nplugin-opts:\n  host: cover.example.com\n  version: 9\n",
        );
        let Err(err) = parse_proxy(&cfg) else {
            panic!("version=9 must reach the shadow-tls parser and fail");
        };
        assert!(err.contains("version"), "msg: {err}");
    }

    /// End-to-end junction: `plugin-opts` map → SIP003 serialization →
    /// the in-process restls parser → adapter construction.
    #[cfg(feature = "restls")]
    #[test]
    fn test_restls_node_parse_e2e() {
        let cfg = proxy_config(
            "name: restls\ntype: ss\nserver: 1.2.3.4\nport: 8388\n\
             cipher: aes-256-gcm\npassword: pw\n\
             plugin: restls\nplugin-opts:\n  host: cover.example.com\n  \
             password: psk\n  version-hint: tls13\n  \
             restls-script: '250?100<1'\n",
        );
        let adapter = parse_proxy(&cfg).expect("restls node must parse");
        assert_eq!(adapter.name(), "restls");
        assert!(
            !is_external_sip003_plugin(Some("restls")),
            "provider/subscription path must treat restls as built-in"
        );

        // A missing required opt proves the serialized string reached the
        // restls parser — a misrouted plugin would parse as a no-op.
        let cfg = proxy_config(
            "name: restls\ntype: ss\nserver: 1.2.3.4\nport: 8388\n\
             cipher: aes-256-gcm\npassword: pw\n\
             plugin: restls\nplugin-opts:\n  host: cover.example.com\n  password: psk\n",
        );
        let Err(err) = parse_proxy(&cfg) else {
            panic!("missing version-hint must reach the restls parser and fail");
        };
        assert!(err.contains("version-hint"), "msg: {err}");
    }

    /// End-to-end junction: `plugin-opts` map → SIP003 serialization →
    /// the in-process jls parser → adapter construction.
    #[cfg(feature = "jls")]
    #[test]
    fn test_jls_node_parse_e2e() {
        let cfg = proxy_config(
            "name: jls\ntype: ss\nserver: 1.2.3.4\nport: 8388\n\
             cipher: aes-256-gcm\npassword: pw\n\
             plugin: jls\nplugin-opts:\n  host: cover.example.com\n  \
             username: alice\n  password: psk\n  alpn: [h2, http/1.1]\n",
        );
        let adapter = parse_proxy(&cfg).expect("jls node must parse");
        assert_eq!(adapter.name(), "jls");
        assert!(
            !is_external_sip003_plugin(Some("jls")),
            "provider/subscription path must treat jls as built-in"
        );

        // A missing required opt proves the serialized string reached the
        // jls parser — a misrouted plugin would parse as a no-op.
        let cfg = proxy_config(
            "name: jls\ntype: ss\nserver: 1.2.3.4\nport: 8388\n\
             cipher: aes-256-gcm\npassword: pw\n\
             plugin: jls\nplugin-opts:\n  host: cover.example.com\n  password: psk\n",
        );
        let Err(err) = parse_proxy(&cfg) else {
            panic!("missing username must reach the jls parser and fail");
        };
        assert!(err.contains("username"), "msg: {err}");
    }

    /// End-to-end junction: `plugin-opts` map → SIP003 serialization →
    /// the in-process kcptun parser → adapter construction.
    #[cfg(feature = "kcptun")]
    #[test]
    fn test_kcptun_node_parse_e2e() {
        let cfg = proxy_config(
            "name: kcptun\ntype: ss\nserver: 1.2.3.4\nport: 8388\n\
             cipher: aes-256-gcm\npassword: pw\n\
             plugin: kcptun\nplugin-opts:\n  crypt: salsa20\n  mode: fast3\n  \
             conn: 2\n  nocomp: true\n  datashard: 6\n  parityshard: 3\n",
        );
        let adapter = parse_proxy(&cfg).expect("kcptun node must parse");
        assert_eq!(adapter.name(), "kcptun");
        assert!(
            !is_external_sip003_plugin(Some("kcptun")),
            "provider/subscription path must treat kcptun as built-in"
        );

        // A rejected opt proves the serialized string reached the kcptun
        // parser — a misrouted plugin would parse as a no-op.
        let cfg = proxy_config(
            "name: kcptun\ntype: ss\nserver: 1.2.3.4\nport: 8388\n\
             cipher: aes-256-gcm\npassword: pw\n\
             plugin: kcptun\nplugin-opts:\n  smuxver: 2\n",
        );
        let Err(err) = parse_proxy(&cfg) else {
            panic!("smuxver=2 must reach the kcptun parser and fail");
        };
        assert!(err.contains("smuxver"), "msg: {err}");
    }

    // ─── direct proxy with per-proxy DNS (issue #67) ─────────────────────────

    fn direct_config(yaml: &str) -> HashMap<String, serde_json::Value> {
        serde_saphyr::from_str(yaml).unwrap()
    }

    #[test]
    fn parse_direct_without_dns_ok() {
        let cfg = direct_config("name: my-direct\ntype: direct\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[test]
    fn parse_direct_with_single_dns_string() {
        let cfg = direct_config("name: lan\ntype: direct\ndns: 192.168.1.1\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[test]
    fn parse_direct_with_dns_list_and_explicit_port() {
        let cfg = direct_config("name: lan\ntype: direct\ndns:\n  - 192.168.1.1\n  - 8.8.8.8:53\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[tokio::test]
    async fn direct_dns_inherits_disabled_ipv6_policy() {
        let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = dns.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, peer) = dns.recv_from(&mut buf).await.unwrap();
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(query.clone());
                if query.query_type == RecordType::AAAA {
                    response.add_answer(Record::from_rdata(
                        query.name,
                        60,
                        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                    ));
                }
                dns.send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let target = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let cfg = proxy_config(&format!(
            "name: direct-v6\ntype: direct\ndns: '{dns_addr}'\n"
        ));
        let proxy = super::parse_proxy(&cfg, false).unwrap();
        let metadata = Metadata {
            host: "v6-only.example".into(),
            dst_port: target.local_addr().unwrap().port(),
            ..Default::default()
        };

        assert!(proxy.dial_tcp(&metadata).await.is_err());
    }

    #[test]
    fn parse_direct_rejects_invalid_dns_entry() {
        let cfg = direct_config("name: bad\ntype: direct\ndns: not-an-ip\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("invalid dns entry must hard-error (Class A)");
        };
        assert!(err.contains("not a valid IP or host:port"), "msg: {err}");
    }

    #[test]
    fn parse_direct_rejects_empty_dns_list() {
        let cfg = direct_config("name: bad\ntype: direct\ndns: []\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("empty dns list must hard-error (Class A)");
        };
        assert!(err.contains("dns list is empty"), "msg: {err}");
    }

    #[test]
    fn parse_direct_with_connect_timeout_wires_adapter() {
        let cfg = direct_config("name: d\ntype: direct\nconnect-timeout: 7\n");
        let adapter = parse_direct("d", &cfg, true, None).unwrap();
        assert_eq!(
            adapter.connect_timeout(),
            Some(std::time::Duration::from_secs(7))
        );
    }

    /// A static `type: direct` entry without `dns:` follows the tunnel's
    /// `dns.direct-nameserver`: its UDP socket connects to the
    /// direct-resolved address, not the caller's main-resolved one.
    #[tokio::test]
    async fn static_direct_proxy_follows_direct_nameserver() {
        use meow_common::DnsMode;
        use meow_dns::{HostEntry, Resolver};
        use meow_trie::DomainTrie;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let (n, src) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], src).await.unwrap();
        });

        let hosts_only = |ip: IpAddr| {
            let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
            hosts.insert("node.test", vec![ip].into());
            Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true, true)
        };
        let main_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut main = hosts_only(main_ip);
        main.set_direct_resolver(Arc::new(hosts_only(IpAddr::V4(Ipv4Addr::LOCALHOST))));
        let slot = meow_dns::new_resolver_slot(Arc::new(main));

        let cfg = direct_config("name: 直连\ntype: direct\n");
        let proxy = parse_static_proxy(&cfg, true, Some(&slot), None).unwrap();
        let meta = Metadata {
            network: meow_common::Network::Udp,
            host: "node.test".into(),
            dst_ip: Some(main_ip),
            dst_port: port,
            ..Default::default()
        };
        let conn = proxy.dial_udp(&meta).await.expect("dial_udp");
        conn.write_packet(b"ping", &SocketAddr::new(main_ip, port))
            .await
            .expect("write");
        let mut buf = [0u8; 16];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            conn.read_packet(&mut buf),
        )
        .await
        .expect("reply from the direct-resolved address")
        .expect("read");
        assert_eq!(&buf[..n], b"ping");
        echo_task.await.unwrap();
    }

    #[test]
    fn parse_direct_without_connect_timeout_is_unbounded() {
        let cfg = direct_config("name: d\ntype: direct\n");
        let adapter = parse_direct("d", &cfg, true, None).unwrap();
        assert_eq!(adapter.connect_timeout(), None);
    }

    #[test]
    fn parse_direct_rejects_non_integer_connect_timeout() {
        let cfg = direct_config("name: bad\ntype: direct\nconnect-timeout: fast\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("non-integer connect-timeout must hard-error (Class A)");
        };
        assert!(err.contains("connect-timeout"), "msg: {err}");
    }

    #[test]
    fn parse_direct_rejects_absurd_connect_timeout() {
        // Seconds reach `tokio::time::timeout` — an out-of-range u64 panics on
        // `Instant + Duration` at first dial (issue #648).
        let cfg = direct_config("name: bad\ntype: direct\nconnect-timeout: 18446744073709551615\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("absurd connect-timeout must hard-error");
        };
        assert!(err.contains("connect-timeout"), "msg: {err}");
        // The ceiling itself stays usable.
        let cfg = direct_config("name: ok\ntype: direct\nconnect-timeout: 315360000\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[test]
    fn http_headers_bounded() {
        // The map is re-serialized into every CONNECT request — cap the count
        // like xhttp-opts.headers (issue #648).
        use std::fmt::Write;
        let mut yaml = String::from("name: h\ntype: http\nserver: 1.2.3.4\nport: 8080\nheaders:\n");
        for i in 0..=meow_transport::MAX_EXTRA_HEADERS {
            writeln!(yaml, "  X-H{i}: v").unwrap();
        }
        let cfg = proxy_config(&yaml);
        let Err(err) = parse_proxy(&cfg) else {
            panic!("65 headers must be rejected")
        };
        assert!(err.contains("headers"), "msg: {err}");
    }

    #[test]
    fn parse_direct_rejects_wrong_dns_type() {
        let cfg = direct_config("name: bad\ntype: direct\ndns: 53\n");
        // Integer 53 is neither a string nor a list — must be rejected.
        let Err(err) = parse_proxy(&cfg) else {
            panic!("scalar non-string dns must hard-error (Class A)");
        };
        assert!(err.contains("dns must be a string or list"), "msg: {err}");
    }

    // ─── anytls proxy parser (issue #75) ─────────────────────────────────────

    #[cfg(feature = "anytls")]
    fn anytls_config(yaml: &str) -> HashMap<String, serde_json::Value> {
        serde_saphyr::from_str(yaml).unwrap()
    }

    // The upstream `anytls-rs` Client constructor spawns a background pool
    // reaper task synchronously, which requires a live tokio reactor. The
    // production code path always calls parse_proxy from inside the main
    // runtime, but tests have to opt in explicitly with #[tokio::test].

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_minimum_fields_ok() {
        let cfg =
            anytls_config("name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\npassword: secret\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_with_sni_and_skip_verify_ok() {
        let cfg = anytls_config(
            "name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\npassword: secret\nsni: example.com\nskip-cert-verify: true\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    /// mihomo's `AnyTLSOption.UDP` is `omitempty`/false by default; only an
    /// explicit `udp: true` advertises datagram support to the tunnel.
    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_udp_is_opt_in() {
        let off =
            anytls_config("name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\npassword: secret\n");
        assert!(!parse_proxy(&off).unwrap().support_udp());

        let on = anytls_config(
            "name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\npassword: secret\nudp: true\n",
        );
        assert!(parse_proxy(&on).unwrap().support_udp());
    }

    /// `dialer-proxy` injects into anytls (Batch 2): the vendored client
    /// threads every session's transport through the chained dialer, so
    /// the parse accepts it and `dialing_through` records the hop. A
    /// `NamedProxyDialer` reports `is_proxy()` without resolving — target
    /// lookup only happens at dial time.
    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_accepts_dialer_proxy_injection() {
        use meow_proxy::dialer::{DialerTarget, NamedProxyDialer, ProxyRegistry};

        let registry = ProxyRegistry::default();
        let dialer: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(NamedProxyDialer::new(DialerTarget::new("front", &registry)));

        let cfg = anytls_config(&format!("{ANYTLS_BASE}dialer-proxy: front\n"));
        let chained = super::parse_proxy_with_dialer(&cfg, &dialer, false)
            .expect("anytls must accept an injected dialer");
        assert!(chained.has_configured_dialer());

        // `udp: true` still advertises UDP over the chain — UoT rides the
        // same chained session, so it only needs the front to carry TCP.
        let cfg_udp = anytls_config(&format!("{ANYTLS_BASE}udp: true\ndialer-proxy: front\n"));
        let chained_udp = super::parse_proxy_with_dialer(&cfg_udp, &dialer, false)
            .expect("anytls + udp must accept an injected dialer");
        assert!(chained_udp.support_udp());
        assert!(chained_udp.has_configured_dialer());

        // The no-op `DirectDialer` leaves the plain parse untouched: no
        // chain is reported for an unchained node.
        let direct: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(meow_proxy::dialer::DirectDialer);
        let plain = super::parse_proxy_with_dialer(&cfg, &direct, false).expect("unchained parse");
        assert!(!plain.has_configured_dialer());
    }

    #[cfg(feature = "anytls")]
    const ANYTLS_BASE: &str =
        "name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\npassword: secret\n";

    /// Issue #870: ECH would be silently dropped, leaking the SNI.
    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_rejects_enabled_ech_opts() {
        for extra in ["ech-opts: {enable: true}\n", "ech-opts: {config: QUJD}\n"] {
            let cfg = anytls_config(&format!("{ANYTLS_BASE}{extra}"));
            let err = parse_proxy(&cfg).err().expect("must reject").to_string();
            assert!(err.contains("ech-opts"), "{err}");
        }
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_allows_disabled_ech_opts() {
        let cfg = anytls_config(&format!("{ANYTLS_BASE}ech-opts: {{enable: false}}\n"));
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_rejects_client_certificate() {
        for key in ["certificate", "private-key"] {
            let cfg = anytls_config(&format!("{ANYTLS_BASE}{key}: abc\n"));
            let err = parse_proxy(&cfg).err().expect("must reject").to_string();
            assert!(err.contains(key), "{err}");
        }
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_ignored_options_still_parse() {
        let cfg = anytls_config(&format!(
            "{ANYTLS_BASE}shadow-tls-opts: {{}}\nrestls-opts: {{}}\njls-opts: {{}}\n\
             client-metadata: {{a: b}}\nidle-session-check-interval: 30\n\
             idle-session-timeout: 30\nmin-idle-session: 1\ndisable-reuse: true\n"
        ));
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_rejects_missing_password() {
        let cfg = anytls_config("name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("missing password must hard-error (Class A)");
        };
        assert!(err.contains("missing password"), "msg: {err}");
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_rejects_zero_port() {
        let cfg =
            anytls_config("name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 0\npassword: secret\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("zero port must hard-error (Class A)");
        };
        assert!(err.contains("port must be non-zero"), "msg: {err}");
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_rejects_invalid_fingerprint() {
        for value in ["chrome", "not-hex", "abcd", "true", "[abc]", "{pin: abc}"] {
            let cfg = anytls_config(&format!(
                "name: jp\ntype: anytls\nserver: 127.0.0.1\nport: 443\npassword: secret\nfingerprint: {value}\nskip-cert-verify: true\n"
            ));
            let Err(err) = parse_proxy(&cfg) else {
                panic!("invalid fingerprint {value} must not be ignored");
            };
            assert!(err.contains("fingerprint"), "msg: {err}");
        }
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_optional_fingerprint_formats() {
        for value in [
            "null".to_string(),
            "''".to_string(),
            format!("'{}'", "ab".repeat(32)),
            format!("' {} '", ["AB"; 32].join(":")),
        ] {
            for skip_cert_verify in [false, true] {
                let cfg = anytls_config(&format!(
                    "name: jp\ntype: anytls\nserver: 127.0.0.1\nport: 443\npassword: secret\nfingerprint: {value}\nskip-cert-verify: {skip_cert_verify}\nname-cert-verify: localhost\nalpn: [h2, http/1.1]\nclient-fingerprint: chrome\n"
                ));
                assert!(parse_proxy(&cfg).is_ok(), "fingerprint: {value}");
            }
        }
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_rejects_malformed_tls_options() {
        for (field, value) in [
            ("name-cert-verify", "true"),
            ("name-cert-verify", "[localhost]"),
            ("client-fingerprint", "[chrome]"),
            ("alpn", "h2"),
            ("alpn", "[h2, 42]"),
            ("alpn", "['']"),
        ] {
            let cfg = anytls_config(&format!(
                "name: jp\ntype: anytls\nserver: 127.0.0.1\nport: 443\npassword: secret\n{field}: {value}\n"
            ));
            let Err(err) = parse_proxy(&cfg) else {
                panic!("malformed {field}: {value} must not be ignored");
            };
            assert!(err.contains(field), "msg: {err}");
        }
    }

    // ─── hysteria2 parser ────────────────────────────────────────────────────

    #[cfg(feature = "hysteria2")]
    fn hy2_config(yaml: &str) -> HashMap<String, serde_json::Value> {
        serde_saphyr::from_str(yaml).unwrap()
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_minimum_fields_ok() {
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\npassword: secret\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    /// `quic-connections` — the K-way pool knob (spec ITEM A): absent is
    /// `None` (adapter default), a present integer clamps to 1..=8, a
    /// non-integer is a hard error like the window fields.
    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_quic_connections() {
        use serde_json::json;

        let parse = |value: serde_json::Value| parse_hy2_quic_connections("t", Some(&value));
        assert_eq!(parse(json!(1)).unwrap(), Some(1));
        assert_eq!(parse(json!(4)).unwrap(), Some(4));
        assert_eq!(parse(json!(8)).unwrap(), Some(8));
        assert_eq!(
            parse(json!(0)).unwrap(),
            Some(1),
            "0 clamps up to the pool floor"
        );
        assert_eq!(
            parse(json!(42)).unwrap(),
            Some(meow_proxy::MAX_QUIC_CONNECTIONS),
            "past the ceiling clamps down"
        );
        assert!(parse(json!("two")).is_err(), "non-integer is a hard error");
        assert_eq!(
            parse_hy2_quic_connections("t", None).unwrap(),
            None,
            "absent stays unset for the adapter default"
        );

        // End to end through the proxy block.
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\npassword: secret\nquic-connections: 3\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\npassword: secret\nquic-connections: two\n",
        );
        let Err(err) = parse_proxy(&cfg) else {
            panic!("a non-integer quic-connections must not be ignored");
        };
        assert!(err.contains("quic-connections"), "msg: {err}");
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_rejects_invalid_configs() {
        // (label, yaml, expected error substring)
        let cases: &[(&str, &str, &str)] = &[
            (
                "missing password",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\n",
                "missing password",
            ),
            (
                "zero port without ports",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 0\npassword: secret\n",
                "port must be non-zero",
            ),
            (
                "missing both port and ports",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\npassword: secret\n",
                "missing port",
            ),
            (
                "wildcard ports without port",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nports: '*'\npassword: secret\n",
                "missing port",
            ),
            (
                "empty password",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\npassword: ''\n",
                "password must not be empty",
            ),
            (
                "gecko without obfs-password",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 obfs: gecko\n",
                "missing obfs-password",
            ),
            (
                "gecko min above max",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 obfs: gecko\n\
                 obfs-password: secret\n\
                 obfs-min-packet-size: 1000\n\
                 obfs-max-packet-size: 900\n",
                "min <= max",
            ),
            (
                "gecko max above 2048",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 obfs: gecko\n\
                 obfs-password: secret\n\
                 obfs-max-packet-size: 4096\n",
                "<= 2048",
            ),
            (
                "gecko non-numeric packet size",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 obfs: gecko\n\
                 obfs-password: secret\n\
                 obfs-min-packet-size: big\n",
                "obfs-min-packet-size must be a byte count",
            ),
            (
                "obfs without obfs-password",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 obfs: salamander\n",
                "missing obfs-password",
            ),
            (
                "mTLS client certificate (mihomo divergence: unsupported)",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 certificate: ./client.crt\n",
                "certificate",
            ),
            (
                "string receive window",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 initial-stream-receive-window: 32m\n",
                "must be an unsigned integer",
            ),
            (
                "negative receive window",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 max-connection-receive-window: -1\n",
                "must be an unsigned integer",
            ),
        ];

        // Collect every failure instead of asserting inline so one bad row does
        // not mask the rest of the table.
        let mut failures: Vec<String> = Vec::new();
        for &(label, yaml, expected) in cases {
            match parse_proxy(&hy2_config(yaml)) {
                Ok(_) => failures.push(format!("[{label}] must hard-error (Class A), got Ok")),
                Err(err) if !err.contains(expected) => {
                    failures.push(format!(
                        "[{label}] error must contain {expected:?}, got: {err}"
                    ));
                }
                Err(_) => {}
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_accepts_ports_without_port() {
        // Airport subscriptions commonly set only a hopping range (issue #377);
        // mihomo accepts this, so we do too — first concrete port dials.
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nports: 20000-30000\npassword: secret\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_accepts_zero_port_with_ports() {
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 0\nports: '443,8443'\npassword: secret\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    /// A `dialer-proxy` chain binds the QUIC endpoint to one front UDP
    /// association, so `ports`/`hop-interval` can never take effect: the
    /// parser warns once and drops them instead of rejecting a config the
    /// operator may share with an unchained build.
    #[cfg(feature = "hysteria2")]
    #[test]
    fn hysteria2_dialer_proxy_warns_and_drops_hopping_fields() {
        use meow_proxy::dialer::{DialerTarget, NamedProxyDialer, ProxyRegistry};

        let registry = ProxyRegistry::default();
        let dialer: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(NamedProxyDialer::new(DialerTarget::new("front", &registry)));
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nports: '443,8443'\nhop-interval: 10-30\npassword: secret\n",
        );
        let (parsed, logs) = capture_warns(|| super::parse_proxy_with_dialer(&cfg, &dialer, true));
        parsed.expect("hopping fields under dialer-proxy warn, not error");
        assert!(
            logs.contains("ports`/`hop-interval` are ignored"),
            "expected the hopping warning, got: {logs}"
        );
        // Without the chain the same fields stay: direct builds keep the
        // hop behaviour the config asked for.
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nports: '443,8443'\nhop-interval: 10-30\npassword: secret\n",
        );
        let (_, logs) = capture_warns(|| parse_proxy(&cfg).unwrap());
        assert!(
            !logs.contains("ports`/`hop-interval"),
            "an unchained node must not warn, got: {logs}"
        );
    }

    /// A `ports`-only hysteria2 node (and the `port: 0` spelling of one)
    /// has no `port` field for the hop record — but the chain still dials
    /// one endpoint, the range's first port. `dialing_through` must fall
    /// back to it or `dialer_hop`/`has_configured_dialer` lose the chain.
    #[cfg(feature = "hysteria2")]
    #[test]
    fn hysteria2_ports_only_chain_records_the_hop() {
        use meow_proxy::dialer::{DialerTarget, NamedProxyDialer, ProxyRegistry};

        let registry = ProxyRegistry::default();
        let dialer: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(NamedProxyDialer::new(DialerTarget::new("front", &registry)));
        for yaml in [
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nports: '443,8443-8446'\npassword: secret\n",
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 0\nports: '443,8443'\npassword: secret\n",
        ] {
            let cfg = hy2_config(yaml);
            let parsed = super::parse_proxy_with_dialer(&cfg, &dialer, true)
                .unwrap_or_else(|e| panic!("ports-only chain must parse: {e}"));
            assert!(
                parsed.has_configured_dialer(),
                "the declared chain must survive a `ports`-only config"
            );
            let wrapped = parsed
                .as_any()
                .and_then(|any| any.downcast_ref::<WrappedProxy>())
                .expect("a parsed leaf sits behind WrappedProxy");
            assert_eq!(
                wrapped.hop.as_ref().map(|hop| hop.port),
                Some(443),
                "the hop endpoint is the range's first port"
            );
        }
    }

    /// An explicit `port:` always wins over the `ports:` range — the hop
    /// must record the address the QUIC socket actually dials.
    #[cfg(feature = "hysteria2")]
    #[test]
    fn hysteria2_explicit_port_beats_ports_range_for_the_hop() {
        use meow_proxy::dialer::{DialerTarget, NamedProxyDialer, ProxyRegistry};

        let registry = ProxyRegistry::default();
        let dialer: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(NamedProxyDialer::new(DialerTarget::new("front", &registry)));
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 9443\nports: '443,8443'\npassword: secret\n",
        );
        let parsed = super::parse_proxy_with_dialer(&cfg, &dialer, true)
            .unwrap_or_else(|e| panic!("explicit-port chain must parse: {e}"));
        let wrapped = parsed
            .as_any()
            .and_then(|any| any.downcast_ref::<WrappedProxy>())
            .expect("a parsed leaf sits behind WrappedProxy");
        assert_eq!(wrapped.hop.as_ref().map(|hop| hop.port), Some(9443));
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_accepts_zero_and_positive_windows() {
        // mihomo treats an explicit 0 as unset — only a present value of the
        // wrong type is a hard error.
        let cfg = hy2_config(
            "name: jp-hy2\n\
             type: hysteria2\n\
             server: 1.2.3.4\n\
             port: 443\n\
             password: secret\n\
             initial-stream-receive-window: 0\n\
             max-connection-receive-window: 4194304\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_accepts_mihomo_common_fields() {
        let cfg = hy2_config(
            "name: jp-hy2\n\
             type: hysteria2\n\
             server: 1.2.3.4\n\
             port: 443\n\
             password: secret\n\
             udp: true\n\
             up: '30 Mbps'\n\
             down: 100\n\
             obfs: salamander\n\
             obfs-password: obfs-secret\n\
             ports: '443,8443-8444'\n\
             hop-interval: '15-30'\n\
             sni: example.com\n\
             skip-cert-verify: true\n\
             fingerprint: 'SHA256 Fingerprint=00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00'\n\
             alpn:\n\
               - h3\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_obfs_gecko() {
        use meow_proxy::Hy2Obfs;

        let base = "name: jp-hy2\n\
                    type: hysteria2\n\
                    server: 1.2.3.4\n\
                    port: 443\n\
                    password: secret\n\
                    obfs-password: obfs-secret\n";
        let obfs = |extra: &str| parse_hy2_obfs("jp-hy2", &hy2_config(&format!("{base}{extra}")));

        assert_eq!(
            obfs("obfs: gecko\n"),
            Ok(Some(Hy2Obfs::Gecko {
                min_packet_size: 0,
                max_packet_size: 0,
            }))
        );
        assert_eq!(
            obfs("obfs: gecko\nobfs-min-packet-size: 600\nobfs-max-packet-size: 900\n"),
            Ok(Some(Hy2Obfs::Gecko {
                min_packet_size: 600,
                max_packet_size: 900,
            }))
        );
        // mihomo reads the sizes only for gecko.
        assert_eq!(
            obfs("obfs: salamander\nobfs-min-packet-size: 600\n"),
            Ok(Some(Hy2Obfs::Salamander))
        );

        for extra in [
            "obfs: gecko\n",
            "obfs: gecko\nobfs-min-packet-size: 600\nobfs-max-packet-size: 900\n",
        ] {
            let cfg = hy2_config(&format!("{base}{extra}"));
            assert!(parse_proxy(&cfg).is_ok(), "{extra}");
        }
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_bandwidth_matches_mihomo_units() {
        assert_eq!(parse_hy2_bandwidth("8 Mbps").unwrap(), 1_000_000);
        assert_eq!(parse_hy2_bandwidth("8 MBps").unwrap(), 8_000_000);
        assert_eq!(parse_hy2_bandwidth("10").unwrap(), 1_250_000);
        assert_eq!(parse_hy2_bandwidth("").unwrap(), 0);
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_hop_interval_matches_mihomo_floor() {
        assert_eq!(parse_hy2_hop_interval("hy2", None).unwrap(), None);
        assert_eq!(
            parse_hy2_hop_interval("hy2", Some(&serde_json::Value::from(0))).unwrap(),
            Some((30, 30))
        );
        assert_eq!(
            parse_hy2_hop_interval("hy2", Some(&serde_json::Value::from("1-2"))).unwrap(),
            Some((5, 5))
        );
        // The ceiling itself stays usable.
        assert_eq!(
            parse_hy2_hop_interval("hy2", Some(&serde_json::Value::from(315360000))).unwrap(),
            Some((315360000, 315360000))
        );
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_rejects_absurd_hop_interval_and_ports() {
        // `hop-interval` seconds feed `Instant + Duration` at rotate and
        // `ports` ranges expand pre-dedup — both provider-controlled
        // (issue #648). Caught at load (`-t`), not first dial.
        for (yaml, needle) in [
            (
                "name: h\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\n\
                 password: s\nhop-interval: 18446744073709551615\n",
                "hop-interval",
            ),
            (
                "name: h\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\n\
                 password: s\nhop-interval: \"10-18446744073709551615\"\n",
                "hop-interval",
            ),
            (
                "name: h\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\n\
                 password: s\nports: \"1-65535,1-65535\"\n",
                "expand",
            ),
        ] {
            let Err(err) = parse_proxy(&hy2_config(yaml)) else {
                panic!("{yaml:?} must be rejected");
            };
            assert!(err.contains(needle), "{yaml:?} → {err}");
        }
    }

    /// The `ChainedProxy` marker forwards every `Proxy` view to the
    /// injected leaf — only `is_dialer_proxy_non_transparent` differs
    /// (issue #969). Exercised over a `SelectorGroup` inner so the member
    /// views have observable values; a leaf inner answers `None` for those
    /// either way and would prove nothing about the delegation.
    #[test]
    fn chained_proxy_delegates_alive_and_member_proxies() {
        let member: Arc<dyn Proxy> = Arc::new(WrappedProxy::new(Box::new(DirectAdapter::new())));
        let group = SelectorGroup::new("front", vec![Arc::clone(&member)]);
        let chained = ChainedProxy::new(Arc::new(group));

        assert!(chained.alive(), "delegated liveness starts alive");
        member.health().set_alive(false);
        assert!(
            !chained.alive(),
            "a dead inner must read dead through the marker"
        );
        assert!(!chained.alive_for_url("http://x"));
        member.health().record_delay(321);
        assert_eq!(chained.last_delay(), 321, "delay delegates");
        assert_eq!(chained.delay_history().len(), 1, "history delegates");

        assert_eq!(
            chained.members().expect("members delegate"),
            vec!["DIRECT".to_string()]
        );
        let members = chained.member_proxies().expect("member_proxies delegate");
        assert_eq!(members.len(), 1);
        assert!(
            Arc::ptr_eq(&members[0], &member),
            "the marker must hand back the inner's own member list"
        );
        assert_eq!(chained.current().as_deref(), Some("DIRECT"));

        // Verbatim delegation, not invention: the inner's capability,
        // group-only views and `as_any` target all survive the wrap —
        // `as_any` still resolves the *inner* concrete type.
        assert!(
            chained.support_udp(),
            "support_udp propagates the inner advertisement"
        );
        assert!(!chained.has_configured_dialer());
        assert!(chained.selection().is_some(), "selection delegates");
        assert!(
            chained
                .as_any()
                .and_then(|any| any.downcast_ref::<SelectorGroup>())
                .is_some(),
            "as_any must reach the inner SelectorGroup, not the marker"
        );

        // The marker's single verdict (issue #969): the chained entry
        // reports `!inner.support_udp()` — this inner advertises UDP, so
        // the marker is `false` (a UDP flow rides the chain; there is
        // nothing to fail closed on). A UDP-incapable inner marks `true`
        // — see the leaf-level tests for that half.
        assert!(!chained.is_dialer_proxy_non_transparent());
    }

    // ─── Load-balance strategy parser (F1-F7) ────────────────────────────────

    #[test]
    fn parse_load_balance_default_strategy() {
        // No `strategy:` field → round-robin selected.
        let s = parse_lb_strategy(None).unwrap();
        assert!(matches!(s, LbStrategy::RoundRobin));
    }

    #[test]
    fn parse_load_balance_explicit_round_robin() {
        let s = parse_lb_strategy(Some("round-robin")).unwrap();
        assert!(matches!(s, LbStrategy::RoundRobin));
    }

    #[test]
    fn parse_load_balance_consistent_hashing() {
        let s = parse_lb_strategy(Some("consistent-hashing")).unwrap();
        assert!(matches!(s, LbStrategy::ConsistentHashing));
    }

    #[test]
    fn parse_load_balance_empty_strategy_is_consistent_hashing() {
        // Upstream `case "", "consistent-hashing"` — an explicit empty
        // `strategy:` is CH, while absent/null defaults to round-robin.
        let s = parse_lb_strategy(Some("")).unwrap();
        assert!(matches!(s, LbStrategy::ConsistentHashing));
    }

    #[test]
    fn parse_load_balance_unknown_strategy_hard_errors() {
        // upstream also hard-errors (errStrategy). ADR-0002 Class A.
        let err = parse_lb_strategy(Some("sticky")).unwrap_err();
        assert!(
            err.contains("unknown strategy"),
            "error should mention unknown strategy: {err}"
        );
        assert!(
            err.contains("Class A"),
            "error should cite ADR-0002 Class A: {err}"
        );
    }

    #[test]
    fn parse_load_balance_case_insensitive_strategy() {
        // Mixed-case is an unknown value → hard error (consistent with Class A policy).
        // Do not panic.
        let err = parse_lb_strategy(Some("Round-Robin")).unwrap_err();
        assert!(!err.is_empty());
        let err2 = parse_lb_strategy(Some("ROUND-ROBIN")).unwrap_err();
        assert!(!err2.is_empty());
    }

    // ─── Relay parser tests (B1-B5) ─────────────────────────────────────────

    fn make_direct_proxy(_name: &str) -> Arc<dyn Proxy> {
        use meow_proxy::DirectAdapter;
        Arc::new(WrappedProxy::new(Box::new(DirectAdapter::new())))
    }

    fn relay_config(name: &str, proxies: Vec<String>) -> crate::raw::RawProxyGroup {
        crate::raw::RawProxyGroup {
            name: name.to_string(),
            group_type: "relay".to_string(),
            proxies: Some(proxies),
            ..Default::default()
        }
    }

    // B1: single-proxy relay → hard error containing "at least 2"
    // upstream: silently acts as passthrough. NOT passthrough. ADR-0002 Class A.
    #[test]
    fn relay_single_proxy_hard_errors_at_parse() {
        let existing = {
            let mut m = std::collections::HashMap::new();
            m.insert(SmolStr::new_static("DIRECT"), make_direct_proxy("DIRECT"));
            m
        };
        let config = relay_config("r", vec!["DIRECT".to_string()]);
        let err = parse_proxy_group(&config, &existing, &[], &Default::default())
            .err()
            .expect("single-proxy relay must error");
        assert!(
            err.contains("at least 2"),
            "error must mention 'at least 2'; got: {err}"
        );
    }

    // B2: empty proxies list → hard error (NOT parse_proxy_group_inner's generic
    // "no valid proxies" error — relay fires before that path is reached when the
    // YAML list itself is empty/missing).
    // upstream: panics. NOT panic. ADR-0002 Class A.
    #[test]
    fn relay_empty_proxies_hard_errors_at_parse() {
        // Empty existing proxies + empty config proxies list.
        let existing = std::collections::HashMap::new();
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec![]),
            ..Default::default()
        };
        // parse_proxy_group_inner will return "no valid proxies" before reaching
        // relay-specific check (0 proxies ≠ relay-specific error, but still errors).
        // Both paths must return Err.
        assert!(parse_proxy_group(&config, &existing, &[], &Default::default()).is_err());
    }

    // B3: url field on relay group → warn (NOT error). Class B per ADR-0002;
    // the capture asserts the warning actually fires (docs/specs/
    // group-relay-test-plan.md).
    #[test]
    fn relay_url_field_warns_not_errors() {
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            url: Some("https://example.com/test".to_string()),
            ..Default::default()
        };
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("relay with url must not hard-error");
        assert!(
            logs.contains("relay: 'url' is not used"),
            "expected 'url' warning, got: {logs}"
        );
    }

    // B4: interval field on relay group → warn (NOT error)
    #[test]
    fn relay_interval_field_warns_not_errors() {
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            interval: Some(300),
            ..Default::default()
        };
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("relay with interval must not hard-error");
        assert!(
            logs.contains("relay: 'interval' is not used"),
            "expected 'interval' warning, got: {logs}"
        );
    }

    // B5: both url and interval present → two separate warns, still not an error
    #[test]
    fn relay_url_and_interval_warn_not_errors() {
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            url: Some("https://example.com/test".to_string()),
            interval: Some(300),
            ..Default::default()
        };
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("relay with url+interval must not hard-error");
        for field in ["url", "interval"] {
            assert_eq!(
                logs.matches(&format!("relay: '{field}' is not used"))
                    .count(),
                1,
                "expected exactly one '{field}' warning, got: {logs}"
            );
        }
    }

    // Provider-member fields on relay → warn (Class B): upstream relay
    // consumes providers; ours is static-only, so the fields were silently
    // dropped before (#555).
    #[test]
    fn relay_provider_fields_warn_not_errors() {
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            use_providers: Some(vec!["airport".to_string()]),
            include_all: Some(true),
            include_all_providers: Some(true),
            filter: Some("hk".to_string()),
            exclude_filter: Some("tw".to_string()),
            exclude_type: Some(vec!["trojan".to_string()]),
            ..Default::default()
        };
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("relay with provider fields must not hard-error");
        for field in [
            "use",
            "include-all",
            "include-all-providers",
            "filter",
            "exclude-filter",
            "exclude-type",
        ] {
            assert!(
                logs.contains(&format!("relay: '{field}' is not used")),
                "expected '{field}' warning, got: {logs}"
            );
        }
    }

    // ─── inert health fields on select/relay (issue #555) ──────────────────

    // `lazy`/`tolerance`/`expected-status` were accepted silently before —
    // the shared helper now warns on every inert probe field.
    #[test]
    fn relay_inert_health_fields_warn_not_errors() {
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            lazy: Some(true),
            tolerance: Some(100),
            expected_status: Some("204".to_string()),
            ..Default::default()
        };
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("relay with inert health fields must not hard-error");
        for field in ["lazy", "tolerance", "expected-status"] {
            assert!(
                logs.contains(&format!("relay: '{field}' is not used")),
                "expected '{field}' warning, got: {logs}"
            );
        }
    }

    // `select` runs no probe loop — the same warn applies to all five
    // health fields (previously every one was ignored silently).
    #[test]
    fn select_with_health_fields_warns_not_errors() {
        let config = crate::raw::RawProxyGroup {
            name: "s".to_string(),
            group_type: "select".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            url: Some("https://example.com/test".to_string()),
            interval: Some(300),
            lazy: Some(true),
            tolerance: Some(100),
            expected_status: Some("204".to_string()),
            ..Default::default()
        };
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("select with inert health fields must not hard-error");
        for field in ["url", "interval", "lazy", "tolerance", "expected-status"] {
            assert!(
                logs.contains(&format!("select: '{field}' is not used")),
                "expected '{field}' warning, got: {logs}"
            );
        }
    }

    // Negative: a plain select carries no probe fields → no warning.
    #[test]
    fn select_without_health_fields_does_not_warn() {
        let config = crate::raw::RawProxyGroup {
            name: "s".to_string(),
            group_type: "select".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            ..Default::default()
        };
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("plain select must parse");
        assert!(logs.is_empty(), "plain select must not warn, got: {logs}");
    }

    // Negative: a plain relay likewise carries no inert fields → zero warns.
    #[test]
    fn relay_without_inert_fields_does_not_warn() {
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            ..Default::default()
        };
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("plain relay must parse");
        assert!(logs.is_empty(), "plain relay must not warn, got: {logs}");
    }

    // Provider fields ARE consumed on `select` (slots wire into
    // SelectorGroup) — unlike relay they must not trip the dropped-field
    // warn. `include-all*`/`filter`/`exclude-*` need no provider objects
    // to exercise the consumed path (an unknown `use:` name is a strict
    // error on select, so it stays out of this negative).
    #[test]
    fn select_with_provider_fields_does_not_warn() {
        let config = crate::raw::RawProxyGroup {
            name: "s".to_string(),
            group_type: "select".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            include_all: Some(true),
            include_all_providers: Some(true),
            filter: Some("hk".to_string()),
            exclude_filter: Some("tw".to_string()),
            exclude_type: Some(vec!["trojan".to_string()]),
            ..Default::default()
        };
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("select with provider fields must parse");
        assert!(
            !logs.contains("is not used"),
            "provider fields are consumed on select, got: {logs}"
        );
    }

    // ─── load-balance provider members (issue #533 item 3) ──────────────────

    const LB_UNKNOWN_PROVIDER_WARN: &str = "proxy-provider 'airport' not found";

    /// Scoped WARN capture — `with_default` is thread-local, so parallel tests
    /// in this binary don't see each other's lines. The discard subscriber
    /// keeps a bare-thread `warn!` from caching `Interest::never` on the
    /// callsites under capture.
    fn capture_warns<R>(f: impl FnOnce() -> R) -> (R, String) {
        crate::test_support::install_global_discard_subscriber();
        #[derive(Clone)]
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;
            fn make_writer(&'a self) -> Sink {
                self.clone()
            }
        }
        let sink = Sink(Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let captured = sink.0.lock().unwrap();
        (out, String::from_utf8_lossy(&captured).into_owned())
    }

    fn lb_config_with_providers(
        use_providers: Option<Vec<String>>,
        include_all: Option<bool>,
    ) -> crate::raw::RawProxyGroup {
        crate::raw::RawProxyGroup {
            name: "lb".to_string(),
            group_type: "load-balance".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            use_providers,
            include_all,
            ..Default::default()
        }
    }

    fn direct_reject() -> HashMap<SmolStr, Arc<dyn Proxy>> {
        let mut m = HashMap::new();
        m.insert(SmolStr::new_static("DIRECT"), make_direct_proxy("DIRECT"));
        m.insert(SmolStr::new_static("REJECT"), make_direct_proxy("REJECT"));
        m
    }

    // `use:` naming an unknown provider → strict parse hard-errors (upstream
    // `getProviders` does the same); the lenient fallback pass warns and
    // skips the slot, keeping static members (same shape as every other
    // group type).
    #[test]
    fn load_balance_use_providers_unknown_provider_warns() {
        let config = lb_config_with_providers(Some(vec!["airport".to_string()]), None);
        assert!(
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default()).is_err(),
            "strict parse must reject an unknown provider"
        );
        let (group, logs) = capture_warns(|| {
            parse_proxy_group_lenient(&config, &direct_reject(), &[], &Default::default())
        });
        let group = group.expect("lenient load-balance with use: must not hard-error");
        assert_eq!(
            group.members().unwrap_or_default().len(),
            2,
            "static members are kept"
        );
        assert!(
            logs.contains(LB_UNKNOWN_PROVIDER_WARN),
            "expected unknown-provider warning, got: {logs}"
        );
    }

    // `include-all` with no providers loaded → empty slot set; the group
    // still builds from statics alone.
    #[test]
    fn load_balance_include_all_with_no_providers_keeps_statics() {
        let config = lb_config_with_providers(None, Some(true));
        let group = parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
            .expect("load-balance with include-all must not hard-error");
        assert_eq!(
            group.members().unwrap_or_default().len(),
            2,
            "static members are kept"
        );
    }

    // `use:` provider members join the pick space — round-robin distributes
    // across statics AND slot members (issue #533 item 3).
    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn load_balance_use_providers_wires_slot_members() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "lb".to_string(),
            group_type: "load-balance".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers)
            .expect("load-balance with use: must build");
        assert_eq!(
            group.members().unwrap_or_default(),
            ["US 1", "US 2 expat", "HK 1"],
            "provider members appear in the member list"
        );
        // Round-robin over three provider members must reach each in turn.
        let meta = meow_common::Metadata::default();
        let mut seen: std::collections::HashSet<String> = Default::default();
        for _ in 0..6 {
            seen.insert(group.unwrap_proxy(&meta, true).unwrap().name().to_string());
        }
        assert_eq!(seen.len(), 3, "every provider member gets picked");
    }

    // `use: [p, p]` must not double-weight the provider: the slot is wired
    // once, so its members appear once in `members()` and get one share of
    // the pick space.
    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn load_balance_use_providers_duplicate_entry_deduped() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "lb".to_string(),
            group_type: "load-balance".to_string(),
            use_providers: Some(vec!["airport".to_string(), "airport".to_string()]),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers)
            .expect("load-balance with duplicated use: must build");
        assert_eq!(
            group.members().unwrap_or_default(),
            ["US 1", "US 2 expat", "HK 1"],
            "a duplicated use: entry wires the provider's slot once"
        );
    }

    // `use: [unknown, unknown]` warns once — dedupe happens before lookup.
    #[test]
    fn load_balance_use_providers_duplicate_unknown_warns_once() {
        let config = lb_config_with_providers(
            Some(vec!["airport".to_string(), "airport".to_string()]),
            None,
        );
        let (group, logs) = capture_warns(|| {
            parse_proxy_group_lenient(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("lenient load-balance with use: must not hard-error");
        assert_eq!(
            logs.matches(LB_UNKNOWN_PROVIDER_WARN).count(),
            1,
            "the repeated unknown provider warns once, got: {logs}"
        );
    }

    // `include-all` wires every loaded provider's slot — same coverage as
    // `use:` but through the include-all collection path.
    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn load_balance_include_all_wires_slot_members() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "lb".to_string(),
            group_type: "load-balance".to_string(),
            include_all: Some(true),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers)
            .expect("load-balance with include-all must build");
        assert_eq!(
            group.members().unwrap_or_default(),
            ["US 1", "US 2 expat", "HK 1"],
            "include-all provider members join the pick space"
        );
    }

    // `include-all-providers` is the upstream providers-only alias — wired
    // identically to `include-all` (ours never pulls statics).
    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn load_balance_include_all_providers_alias_wires_slots() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "lb".to_string(),
            group_type: "load-balance".to_string(),
            include_all_providers: Some(true),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers)
            .expect("load-balance with include-all-providers must build");
        assert_eq!(
            group.members().unwrap_or_default(),
            ["US 1", "US 2 expat", "HK 1"],
            "the upstream alias wires provider members identically"
        );
    }

    // `include-all` iterates providers sorted by name — the slot order
    // (and therefore the pick space / a selector's default member) must
    // not depend on the providers map's insertion or iteration order.
    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn load_balance_include_all_orders_slots_by_provider_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut providers = HashMap::new();
        // Deliberately insert "zeta" before "alpha".
        providers.insert(
            "zeta".to_string(),
            file_provider_named(
                &dir.path().join("z.yaml"),
                "proxies:\n  - {name: \"Z 1\", type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: p}\n",
                "zeta",
            )
            .await,
        );
        providers.insert(
            "alpha".to_string(),
            file_provider_named(
                &dir.path().join("a.yaml"),
                "proxies:\n  - {name: \"A 1\", type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: p}\n",
                "alpha",
            )
            .await,
        );

        let config = crate::raw::RawProxyGroup {
            name: "lb".to_string(),
            group_type: "load-balance".to_string(),
            include_all: Some(true),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers)
            .expect("include-all load-balance must build");
        assert_eq!(
            group.members().unwrap_or_default(),
            ["A 1", "Z 1"],
            "slots follow provider-name order, not map order"
        );
    }

    // Config-level: an unknown `use:` provider is absorbed by the
    // multi-pass group resolver's lenient fallback — the group still
    // builds from its static members and the config loads (warn + skip),
    // rather than the strict pass's error failing the whole load.
    #[tokio::test]
    async fn load_config_unknown_use_provider_warns_and_loads() {
        // A `direct` leaf normalizes to the built-in DIRECT name — use ss so
        // the static member keeps its own name in `members()`.
        let yaml = "proxies:\n  - {name: p, type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: x}\n\
            proxy-groups:\n  - {name: g, type: load-balance, proxies: [p], use: [ghost]}\n";
        let cfg = crate::load_config_from_str(yaml)
            .await
            .expect("an unknown `use:` provider must not fail the config");
        let group = cfg.proxies.get("g").expect("group builds from statics");
        assert_eq!(group.members().unwrap_or_default(), ["p"]);
    }

    // `include-all` beats `use:` — upstream `Use = AllProviders`.
    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn load_balance_include_all_overrides_use() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "lb".to_string(),
            group_type: "load-balance".to_string(),
            use_providers: Some(vec!["nonexistent".to_string()]),
            include_all: Some(true),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers)
            .expect("load-balance with include-all + use: must build");
        assert_eq!(
            group.members().unwrap_or_default(),
            ["US 1", "US 2 expat", "HK 1"],
            "include-all supplies the membership; use: is ignored"
        );
    }

    // Group-level `filter:`/`exclude-filter:` apply to LB provider members
    // through the same `derived_slot` view the siblings use (issue #358).
    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn load_balance_filter_applies_to_slot_members() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "lb".to_string(),
            group_type: "load-balance".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            filter: Some("(?i)^us".to_string()),
            exclude_filter: Some("expat".to_string()),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers)
            .expect("filtered load-balance must build");
        assert_eq!(group.members().unwrap_or_default(), ["US 1"]);
    }

    // No provider fields → no warning (the warning is keyed on the raw config).
    #[test]
    fn load_balance_without_providers_does_not_warn() {
        let config = lb_config_with_providers(None, None);
        let (group, logs) = capture_warns(|| {
            parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
        });
        group.expect("plain load-balance must parse");
        assert!(
            logs.is_empty(),
            "no provider fields must not warn, got: {logs}"
        );
    }

    // `expected-status` on load-balance reaches the probe loop — upstream
    // `GroupCommonOption` honors it on every swept group type; previously
    // it was silently dropped (#555).
    #[test]
    fn load_balance_expected_status_reaches_probe_loop() {
        let config = crate::raw::RawProxyGroup {
            expected_status: Some("204".to_string()),
            ..lb_config_with_providers(None, None)
        };
        let group = parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
            .expect("load-balance with expected-status must parse");
        assert_eq!(group.expected_status(), Some("204"));
    }

    // `url` on load-balance is the consistent-hashing eligibility probe URL
    // (`test_url`); previously the group had no such field at all (#621).
    #[test]
    fn load_balance_url_reaches_test_url() {
        let config = crate::raw::RawProxyGroup {
            url: Some("https://example.com/ping".to_string()),
            ..lb_config_with_providers(None, None)
        };
        let group = parse_proxy_group(&config, &direct_reject(), &[], &Default::default())
            .expect("load-balance with url must parse");
        assert_eq!(group.test_url(), Some("https://example.com/ping"));
        // Absent `url` → the shared generate_204 default.
        let group = parse_proxy_group(
            &lb_config_with_providers(None, None),
            &direct_reject(),
            &[],
            &Default::default(),
        )
        .expect("load-balance without url must parse");
        assert_eq!(
            group.test_url(),
            Some("https://www.gstatic.com/generate_204")
        );
    }

    // Upstream maps an explicit empty strategy to consistent-hashing
    // (`case "", "consistent-hashing"`).
    #[test]
    fn load_balance_empty_strategy_is_consistent_hashing() {
        let config = crate::raw::RawProxyGroup {
            strategy: Some("".to_string()),
            ..lb_config_with_providers(None, None)
        };
        assert!(parse_proxy_group(&config, &direct_reject(), &[], &Default::default()).is_ok());
    }

    // A `use:`-only relay (no `proxies:`) reaches `parse_relay_group` on
    // provider slots alone and hits the empty-`proxies` hard error — the
    // error must say *why*: provider fields do not supply relay members.
    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn relay_provider_only_errors_naming_dropped_fields() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            ..Default::default()
        };
        let Err(err) = parse_proxy_group(&config, &HashMap::new(), &[], &providers) else {
            panic!("provider-only relay must hard-error")
        };
        assert!(err.contains("proxies list is empty"), "got: {err}");
        assert!(
            err.contains("do not supply relay members"),
            "error must explain provider fields were dropped, got: {err}"
        );
    }

    // A `use:`-only group wires the provider slot as its whole membership —
    // previously the members were dropped at build time and only a warn
    // remained (#533 item 3).
    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn load_balance_provider_only_balances_slot_members() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;
        let config = crate::raw::RawProxyGroup {
            name: "lb".to_string(),
            group_type: "load-balance".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers)
            .expect("provider-only load-balance must build");
        assert_eq!(
            group.members().unwrap_or_default(),
            ["US 1", "US 2 expat", "HK 1"],
            "provider members join the pick space"
        );
    }

    // ─── group-level filter on provider members (issue #358) ────────────────

    #[cfg(feature = "ss")]
    async fn file_provider_named(
        path: &std::path::Path,
        entries: &str,
        name: &str,
    ) -> Arc<crate::proxy_provider::ProxyProvider> {
        std::fs::write(path, entries).unwrap();
        let raw = crate::raw::RawProxyProvider {
            provider_type: "file".to_string(),
            url: None,
            path: Some(path.to_str().unwrap().to_string()),
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            header: None,
            allow_external_plugin: None,
            override_: None,
            proxy: None,
            dialer_proxy: None,
            extra: Default::default(),
        };
        let cache_dir = path.parent().expect("temp file has a parent dir");
        let provider = crate::proxy_provider::ProxyProvider::new(
            name,
            &raw,
            Some(cache_dir),
            true,
            false,
            Default::default(),
        )
        .unwrap();
        provider.refresh().await.unwrap();
        Arc::new(provider)
    }

    #[cfg(feature = "ss")]
    async fn file_provider_with(
        path: &std::path::Path,
        entries: &str,
    ) -> HashMap<String, Arc<crate::proxy_provider::ProxyProvider>> {
        let provider = file_provider_named(path, entries, "airport").await;
        let mut providers = HashMap::new();
        providers.insert("airport".to_string(), provider);
        providers
    }

    #[cfg(feature = "ss")]
    const PROVIDER_YAML: &str = "proxies:\n\
        - {name: \"US 1\", type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: p}\n\
        - {name: \"US 2 expat\", type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: p}\n\
        - {name: \"HK 1\", type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: p}\n";

    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn group_filter_applies_to_provider_members() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "US".to_string(),
            group_type: "url-test".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            filter: Some("(?i)^us".to_string()),
            exclude_filter: Some("expat".to_string()),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers).unwrap();
        assert_eq!(group.members().unwrap(), ["US 1"]);
    }

    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn group_without_filter_sees_all_provider_members() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "ALL".to_string(),
            group_type: "select".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &[], &providers).unwrap();
        assert_eq!(group.members().unwrap(), ["US 1", "US 2 expat", "HK 1"]);
    }

    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn group_filter_invalid_regex_errors_with_group_name() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "US".to_string(),
            group_type: "select".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            filter: Some("(".to_string()),
            ..Default::default()
        };
        let err = parse_proxy_group(&config, &HashMap::new(), &[], &providers)
            .err()
            .expect("invalid filter regex must error");
        assert!(
            err.contains("group 'US'") && err.contains("filter regex error"),
            "unexpected error: {err}"
        );
    }

    // ─── snell proxy parser ───────────────────────────────────────────────────

    #[cfg(feature = "snell")]
    fn snell_config(yaml: &str) -> HashMap<String, serde_json::Value> {
        serde_saphyr::from_str(yaml).unwrap()
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_minimal_ok() {
        let cfg = snell_config("name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: secret\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_full_ok() {
        let cfg = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: secret\nversion: 5\nudp: true\nreuse: true\nobfs-opts:\n  mode: http\n  host: bing.com\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_rejects_invalid_fields() {
        // (label, yaml, expected error substring). Every row is a Class A hard
        // error: a required field is missing or invalid, and parsing must fail
        // with a message naming that field.
        let cases: &[(&str, &str, &str)] = &[
            (
                "missing psk",
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\n",
                "missing psk",
            ),
            (
                "missing server",
                "name: sn\ntype: snell\nport: 8388\npsk: secret\n",
                "missing server",
            ),
            (
                "missing port",
                "name: sn\ntype: snell\nserver: 1.2.3.4\npsk: secret\n",
                "missing port",
            ),
            (
                "port zero",
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 0\npsk: secret\n",
                "port must be non-zero",
            ),
            (
                "empty psk (caught by SnellAdapter::new)",
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: ''\n",
                "psk must not be empty",
            ),
        ];

        // Collect every failure instead of asserting inline so one bad row does
        // not mask the rest of the table.
        let mut failures: Vec<String> = Vec::new();
        for &(label, yaml, expected) in cases {
            match parse_proxy(&snell_config(yaml)) {
                Ok(_) => failures.push(format!("[{label}] must hard-error (Class A), got Ok")),
                Err(err) if !err.contains(expected) => {
                    failures.push(format!(
                        "[{label}] error must contain {expected:?}, got: {err}"
                    ));
                }
                Err(_) => {}
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_version_aliases() {
        for yaml in &[
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 3\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: v3\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 4\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: v4\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: V5\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 5\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 6\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: v6\n",
        ] {
            let cfg = snell_config(yaml);
            assert!(parse_proxy(&cfg).is_ok(), "expected Ok for yaml: {yaml}");
        }
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_v6_modes() {
        for mode in ["default", "unshaped", "unsafe-raw", "Unshaped", "''"] {
            let cfg = snell_config(&format!(
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 6\nudp: true\nreuse: true\nmode: {mode}\n"
            ));
            assert!(parse_proxy(&cfg).is_ok(), "mode {mode} must parse");
        }
        let cases: &[(&str, &str)] = &[
            ("version: 6\nmode: shaped\n", "mode 'shaped' invalid"),
            ("version: 6\nmode: 1\n", "mode must be a string"),
            ("version: 5\nmode: default\n", "mode is a snell v6 option"),
            ("mode: unshaped\n", "mode is a snell v6 option"),
            (
                "version: 6\nobfs-opts:\n  mode: http\n",
                "obfs-opts is not supported by snell v6",
            ),
        ];
        for (extra, expected) in cases {
            let cfg = snell_config(&format!(
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\n{extra}"
            ));
            let Err(err) = parse_proxy(&cfg) else {
                panic!("{extra:?} must hard-error (Class A)");
            };
            assert!(err.contains(expected), "{extra:?}: msg: {err}");
        }
        let cfg = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 6\nobfs-opts:\n  mode: off\n",
        );
        assert!(parse_proxy(&cfg).is_ok(), "obfs off is fine on v6");
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_rejects_unsupported_legacy_versions() {
        for (yaml, ver) in &[
            (
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 1\n",
                "1",
            ),
            (
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 2\n",
                "2",
            ),
            (
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: v2\n",
                "v2",
            ),
        ] {
            let cfg = snell_config(yaml);
            let Err(err) = parse_proxy(&cfg) else {
                panic!("unsupported legacy version {ver} must hard-error (Class A)");
            };
            assert!(
                err.contains("not supported"),
                "version {ver}: expected 'not supported' in msg: {err}"
            );
        }
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_rejects_unknown_version() {
        let cfg_seven = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: '7'\n",
        );
        let Err(err) = parse_proxy(&cfg_seven) else {
            panic!("unknown version '7' must hard-error (Class A)");
        };
        assert!(err.contains("unknown version"), "msg: {err}");

        let cfg_bool = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: true\n",
        );
        let Err(err) = parse_proxy(&cfg_bool) else {
            panic!("boolean version must hard-error (Class A)");
        };
        assert!(err.contains("must be an integer or string"), "msg: {err}");
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_obfs_modes() {
        let cfg_tls = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nobfs-opts:\n  mode: tls\n",
        );
        assert!(parse_proxy(&cfg_tls).is_ok(), "tls obfs mode must be Ok");

        let cfg_none = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nobfs-opts:\n  mode: none\n",
        );
        assert!(parse_proxy(&cfg_none).is_ok(), "none obfs mode must be Ok");

        let cfg_socks = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nobfs-opts:\n  mode: socks\n",
        );
        let Err(err) = parse_proxy(&cfg_socks) else {
            panic!("invalid obfs mode 'socks' must hard-error (Class A)");
        };
        assert!(err.contains("obfs-opts.mode"), "msg: {err}");
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_obfs_host_falls_back_to_server() {
        // obfs-opts with mode: http but no host key → falls back to server value.
        let cfg = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nobfs-opts:\n  mode: http\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_obfs_host_rejects_ctl() {
        // `obfs-opts.host` lands verbatim in the emitted `Host:` header —
        // provider-supplied CTLs must not parse (issue #648).
        for mode in ["http", "tls"] {
            let cfg = snell_config(&format!(
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nobfs-opts:\n  mode: {mode}\n  host: \"a\\rb\\nc\"\n"
            ));
            let Err(err) = parse_proxy(&cfg) else {
                panic!("{mode} obfs host with CRLF must hard-error");
            };
            assert!(err.contains("obfs-opts.host"), "{mode}: msg: {err}");
        }
    }

    // ─── issue #513: provider nodes cannot select a local executable ─────────

    #[cfg(feature = "ss")]
    fn direct_dialer() -> std::sync::Arc<dyn meow_proxy::dialer::TcpDialer> {
        std::sync::Arc::new(meow_proxy::dialer::DirectDialer)
    }

    #[cfg(feature = "ss")]
    fn external_plugin_ss() -> HashMap<String, serde_json::Value> {
        proxy_config(
            "name: s\ntype: ss\nserver: 1.2.3.4\nport: 8388\npassword: p\ncipher: aes-128-gcm\n\
             plugin: evil-plugin-from-provider\n",
        )
    }

    /// Default: the provider path rejects external SIP003 plugins before the
    /// adapter can reach `Command::new`. The local `proxies:` path is trusted
    /// and unaffected.
    #[cfg(feature = "ss")]
    #[test]
    fn provider_node_rejects_external_plugin_by_default() {
        let cfg = external_plugin_ss();
        let Err(err) = super::parse_proxy_provider_node(&cfg, true, false, &direct_dialer()) else {
            panic!("external plugin must be rejected without the opt-in")
        };
        assert!(err.contains("allow-external-plugin"), "msg: {err}");

        // With the opt-in the gate opens: parse proceeds and fails at the
        // *plugin spawn* boundary (the binary does not exist), proving the
        // gate — not the plugin dispatch — did the rejecting above.
        let Err(err) = super::parse_proxy_provider_node(&cfg, true, true, &direct_dialer()) else {
            panic!("with opt-in, parse must reach adapter construction")
        };
        assert!(err.contains("failed to start ss plugin"), "msg: {err}");
    }

    /// Built-in in-process plugins and non-ss nodes are untouched by the gate.
    #[cfg(all(feature = "ss", feature = "trojan"))]
    #[test]
    fn provider_node_allows_builtin_plugins_and_other_types() {
        let cfg = proxy_config(
            "name: s\ntype: ss\nserver: 1.2.3.4\nport: 8388\npassword: p\ncipher: aes-128-gcm\n\
             plugin: obfs\nplugin-opts:\n  mode: http\n",
        );
        assert!(super::parse_proxy_provider_node(&cfg, true, false, &direct_dialer()).is_ok());

        // A stray `plugin:` on a trojan node is ignored by its parser —
        // the gate must not reject it either.
        let cfg = proxy_config(
            "name: t\ntype: trojan\nserver: 1.2.3.4\nport: 443\npassword: p\nplugin: whatever\n",
        );
        assert!(super::parse_proxy_provider_node(&cfg, true, false, &direct_dialer()).is_ok());
    }

    /// v2ray-plugin is a built-in in-process plugin — the gate must let it
    /// through on provider nodes too.
    #[cfg(feature = "ss")]
    #[test]
    fn provider_node_allows_v2ray_plugin() {
        let cfg = proxy_config(
            "name: s\ntype: ss\nserver: 1.2.3.4\nport: 8388\npassword: p\ncipher: aes-128-gcm\n\
             plugin: v2ray-plugin\n",
        );
        assert!(super::parse_proxy_provider_node(&cfg, true, false, &direct_dialer()).is_ok());
    }

    /// gost-plugin is likewise built-in — the external-plugin gate must not
    /// reject it on provider nodes, and `is_external_sip003_plugin` must
    /// agree (a misclassification would silently drop subscription nodes).
    /// `mux: false` keeps the fixture valid under a `ss`-without-`mux` build.
    #[cfg(feature = "gost-plugin")]
    #[test]
    fn provider_node_allows_gost_plugin() {
        assert!(!is_external_sip003_plugin(Some("gost-plugin")));
        let cfg = proxy_config(
            "name: s\ntype: ss\nserver: 1.2.3.4\nport: 8388\npassword: p\ncipher: aes-128-gcm\n\
             plugin: gost-plugin\nplugin-opts:\n  mode: websocket\n  mux: false\n",
        );
        assert!(super::parse_proxy_provider_node(
            &cfg,
            true,
            false,
            &(std::sync::Arc::new(meow_proxy::dialer::DirectDialer)
                as std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>),
        )
        .is_ok());
    }

    /// shadow-tls is a built-in in-process plugin too — the provider gate
    /// must route it through without `allow-external-plugin`.
    #[cfg(feature = "shadow-tls")]
    #[test]
    fn provider_node_allows_shadow_tls_plugin() {
        assert!(!is_external_sip003_plugin(Some("shadow-tls")));
        let cfg = proxy_config(
            "name: s\ntype: ss\nserver: 1.2.3.4\nport: 8388\npassword: p\ncipher: aes-128-gcm\n\
             plugin: shadow-tls\nplugin-opts:\n  host: cover.example.com\n  version: 3\n",
        );
        assert!(super::parse_proxy_provider_node(
            &cfg,
            true,
            false,
            &(std::sync::Arc::new(meow_proxy::dialer::DirectDialer)
                as std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>),
        )
        .is_ok());
    }

    /// The provider opt-in key is `allow-external-plugin` (kebab-case like
    /// the rest of `RawProxyProvider`) — a rename regression would leave the
    /// gate permanently closed for users who set it.
    #[test]
    fn provider_allow_external_plugin_uses_kebab_case() {
        let raw: crate::raw::RawProxyProvider =
            serde_saphyr::from_str("type: file\npath: p.yaml\nallow-external-plugin: true\n")
                .unwrap();
        assert_eq!(raw.allow_external_plugin, Some(true));
    }

    /// Subscriptions land remote nodes in the trusted `proxies:` list —
    /// `parse_subscription_yaml` must drop external-SIP003 nodes before they
    /// reach `Command::new`, while keeping built-in plugins.
    #[cfg(feature = "ss")]
    #[test]
    fn subscription_drops_external_plugin_nodes() {
        let text = "proxies:\n\
             - name: evil\n  type: ss\n  server: 1.2.3.4\n  port: 8388\n  \
             password: p\n  cipher: aes-128-gcm\n  plugin: evil-plugin\n\
             - name: ok\n  type: ss\n  server: 1.2.3.4\n  port: 8389\n  \
             password: p\n  cipher: aes-128-gcm\n  plugin: v2ray-plugin\n\
             - name: plain\n  type: trojan\n  server: 1.2.3.4\n  port: 443\n  password: p\n";
        let data = crate::subscription::parse_subscription_yaml(text, false).unwrap();
        let names: Vec<&str> = data
            .proxies
            .iter()
            .filter_map(|p| p.get("name").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(names, ["ok", "plain"], "dropped: {names:?}");
    }

    // ─── feature-gated built-in plugins: disabled names fail cleanly ─────────
    //
    // Every name `is_builtin_sip003_plugin` lists is reserved: when its
    // feature is compiled out the adapter must return a clean Config error
    // ("not compiled into this build" — the same message that becomes the
    // runtime placeholder's dial reason), never fall through to the external
    // SIP003 `Plugin::start` spawn path. `is_external_sip003_plugin` must
    // agree — a misclassified reserved name would be treated as external
    // (spawned, or rejected/dropped by the provider gates).
    #[cfg(feature = "ss")]
    #[test]
    fn disabled_builtin_plugins_error_cleanly_and_stay_reserved() {
        for name in [
            "gost-plugin",
            "shadow-tls",
            "restls",
            "jls",
            "kcptun",
            "ech-tls-tunnel",
        ] {
            assert!(
                !is_external_sip003_plugin(Some(name)),
                "{name} stays a reserved built-in name when its feature is off"
            );
            let cfg = proxy_config(&format!(
                "name: s\ntype: ss\nserver: 1.2.3.4\nport: 8388\npassword: p\ncipher: aes-128-gcm\n\
                 plugin: {name}\n"
            ));
            match meow_proxy::shadowsocks_adapter::missing_plugin_feature(name) {
                Some(feature) => {
                    // Compiled out: the parse itself errors — that message is
                    // what the runtime placeholder renders into every dial —
                    // and the raw node must classify for the placeholder arm.
                    let Err(err) = parse_proxy(&cfg) else {
                        panic!("compiled-out {name} must not parse")
                    };
                    assert!(
                        err.contains("not compiled into this build"),
                        "{name}: msg: {err}"
                    );
                    assert!(err.contains(name), "{name}: msg: {err}");
                    assert!(err.contains(feature), "{name}: msg: {err}");
                    assert_eq!(
                        placeholder_adapter_type(&cfg),
                        Some(meow_common::AdapterType::Shadowsocks),
                        "a missing-plugin node must classify as an ss placeholder"
                    );
                }
                None => {
                    // Compiled in: construction may succeed outright (kcptun
                    // defaults suffice) or fail on the plugin's own opts
                    // validation — either way it must never report the
                    // missing-feature error or classify for the placeholder.
                    assert_eq!(placeholder_adapter_type(&cfg), None);
                    if let Err(err) = parse_proxy(&cfg) {
                        assert!(
                            !err.contains("not compiled into this build"),
                            "compiled-in {name} must not report the missing-feature error: {err}"
                        );
                    }
                }
            }
        }
    }

    /// A `plugin:` value that is not a string is a malformed node — never
    /// silently treated as "no plugin" (that would dial plain SS while the
    /// operator configured a transport plugin). `null` is the exception:
    /// Go's `Plugin string` unmarshals it to the zero value, so the key
    /// counts as unset exactly like an absent one (mihomo parity).
    #[cfg(feature = "ss")]
    #[test]
    fn non_string_plugin_value_is_a_parse_error() {
        for plugin in ["123", "true", "{mode: http}", "[obfs]"] {
            let cfg = proxy_config(&format!(
                "name: s\ntype: ss\nserver: 1.2.3.4\nport: 8388\npassword: p\ncipher: aes-128-gcm\n\
                 plugin: {plugin}\n"
            ));
            let Err(err) = parse_proxy(&cfg) else {
                panic!("plugin: {plugin} must not parse as plain ss")
            };
            assert!(
                err.contains("`plugin` must be a string"),
                "plugin: {plugin}: {err}"
            );
        }
    }

    /// Both YAML representations of an empty plugin select plain Shadowsocks.
    #[cfg(feature = "ss")]
    #[test]
    fn empty_or_null_plugin_value_means_no_plugin() {
        for value in ["null", "''"] {
            let cfg = proxy_config(&format!(
                "name: s\ntype: ss\nserver: 192.0.2.1\nport: 8388\npassword: p\ncipher: aes-128-gcm\nplugin: {value}\n"
            ));
            assert!(!node_selects_external_plugin(&cfg));
            let proxy = parse_proxy(&cfg).expect("empty plugin parses as plain ss");
            assert_eq!(proxy.name(), "s");
        }
    }

    /// The dispatch is exact (`"ss"` only, like mihomo) while
    /// [`node_needs_missing_plugin`] is forgiving like
    /// [`node_is_trusttunnel`]: a misspelled `type` plus a compiled-out
    /// plugin still classifies for the dead placeholder, so a group that
    /// names the node keeps it bound instead of warn-dropping.
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[test]
    fn misspelled_ss_type_with_missing_plugin_still_classifies() {
        let cfg = proxy_config(
            "name: s\ntype: 'Ss '\nserver: 1.2.3.4\nport: 8388\npassword: p\ncipher: aes-128-gcm\n\
             plugin: gost-plugin\n",
        );
        assert!(
            parse_proxy(&cfg).is_err(),
            "the exact dispatch still rejects the misspelled type"
        );
        assert_eq!(
            placeholder_adapter_type(&cfg),
            Some(meow_common::AdapterType::Shadowsocks),
            "the lenient classifier still lands the node on the placeholder arm"
        );
    }

    // ─── per-node dialer opts (issue #974) ─────────────────────────────────

    /// Downcast a parsed leaf to its `WrappedProxy` — every `proxies:`
    /// entry lands in one.
    fn wrapped(proxy: &Arc<dyn Proxy>) -> &WrappedProxy {
        proxy
            .as_any()
            .and_then(|any| any.downcast_ref::<WrappedProxy>())
            .expect("a parsed leaf is a WrappedProxy")
    }

    /// Every field a `proxies:` entry carries reaches the wrapper.
    #[test]
    fn node_dialer_opts_parse_onto_the_leaf_wrapper() {
        let cfg = proxy_config(
            "name: d\ntype: direct\nrouting-mark: 8888\ninterface-name: en0\n\
             ip-version: ipv4-prefer\ntfo: true\nmptcp: true\n",
        );
        let proxy = parse_proxy(&cfg).expect("dialer fields parse");
        let opts = &wrapped(&proxy).node_opts;
        assert_eq!(opts.routing_mark, Some(8888));
        assert_eq!(opts.interface_name.as_deref(), Some("en0"));
        assert_eq!(opts.ip_version, meow_common::IpVersion::Ipv4Prefer);
        assert!(opts.tfo);
        assert!(opts.mptcp);
    }

    /// `routing-mark: 0` and an empty `interface-name` normalize to
    /// "inherit the global", matching mihomo's zero-means-unset.
    #[test]
    fn node_dialer_opts_normalization() {
        for (yaml, want_mark, want_iface) in [
            ("routing-mark: 0\ninterface-name: ''\n", None, None),
            ("routing-mark: 0\n", None, None),
            ("interface-name: '  '\n", None, None),
            (
                "routing-mark: 1\ninterface-name: lo0\n",
                Some(1),
                Some("lo0"),
            ),
        ] {
            let cfg = proxy_config(&format!("name: d\ntype: direct\n{yaml}"));
            let proxy = parse_proxy(&cfg).expect("normalizing fields parse");
            let opts = &wrapped(&proxy).node_opts;
            assert_eq!(opts.routing_mark, want_mark, "{yaml}");
            assert_eq!(opts.interface_name.as_deref(), want_iface, "{yaml}");
        }
        // Absent fields keep the defaults.
        let cfg = proxy_config("name: d\ntype: direct\n");
        let binding = parse_proxy(&cfg).unwrap();
        let opts = &wrapped(&binding).node_opts;
        assert_eq!(opts.routing_mark, None);
        assert_eq!(opts.interface_name, None);
        assert_eq!(opts.ip_version, meow_common::IpVersion::Dual);
        assert!(!opts.tfo && !opts.mptcp);
    }

    /// An unknown `ip-version` is a hard parse error — mihomo fails the
    /// node the same way rather than silently keeping `dual`.
    #[test]
    fn node_dialer_opts_rejects_unknown_ip_version() {
        let cfg = proxy_config("name: d\ntype: direct\nip-version: quad\n");
        let err = parse_proxy(&cfg)
            .err()
            .expect("unknown ip-version must error");
        assert!(err.contains("unknown `ip-version`"), "{err}");
        // A non-string value is malformed the same way.
        let cfg = proxy_config("name: d\ntype: direct\nip-version: 4\n");
        assert!(parse_proxy(&cfg).is_err());
        // And each accepted spelling lands (the `from_name` table).
        for (spelling, want) in [
            ("dual", meow_common::IpVersion::Dual),
            ("ipv4", meow_common::IpVersion::Ipv4),
            ("ipv6", meow_common::IpVersion::Ipv6),
            ("ipv4-prefer", meow_common::IpVersion::Ipv4Prefer),
            ("ipv6-prefer", meow_common::IpVersion::Ipv6Prefer),
        ] {
            let cfg = proxy_config(&format!("name: d\ntype: direct\nip-version: {spelling}\n"));
            let proxy = parse_proxy(&cfg).expect(spelling);
            assert_eq!(wrapped(&proxy).node_opts.ip_version, want, "{spelling}");
        }
    }

    /// Malformed dialer fields fail the node rather than parsing past
    /// them — non-integer marks, non-string names, non-bool flags.
    #[test]
    fn node_dialer_opts_rejects_malformed_fields() {
        for yaml in [
            "routing-mark: -1\n",
            "routing-mark: 'abc'\n",
            "routing-mark: 4294967296\n",
            "interface-name: 7\n",
            "tfo: 'yes'\n",
            "mptcp: 1\n",
        ] {
            let cfg = proxy_config(&format!("name: d\ntype: direct\n{yaml}"));
            assert!(parse_proxy(&cfg).is_err(), "{yaml}");
        }
    }

    /// A NUL-bearing `interface-name` is a hard parse error, not the
    /// empty-means-unset normalization: Linux `SO_BINDTODEVICE` would
    /// silently truncate the name at the NUL and bind the *wrong*
    /// interface — the one misconfiguration worse than a missing one.
    #[test]
    fn node_dialer_opts_rejects_nul_interface_name() {
        let mut cfg = proxy_config("name: d\ntype: direct\n");
        cfg.insert(
            "interface-name".to_string(),
            serde_json::Value::String("en0\0x".to_string()),
        );
        match parse_proxy(&cfg) {
            Err(err) => assert!(err.contains("NUL"), "{err}"),
            Ok(_) => panic!("a NUL interface-name must error"),
        }
    }

    /// A `dialer-proxy` chain keeps the leaf's own opts — the wrapper
    /// carries them even when the injected dialer is a proxy. The leaf
    /// hop's socket is opened by the front under its own scope.
    #[cfg(feature = "ss")]
    #[test]
    fn node_dialer_opts_survive_dialer_proxy_parse() {
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let target = meow_proxy::dialer::DialerTarget::new("front", &registry);
        let dialer: Arc<dyn meow_proxy::dialer::TcpDialer> =
            Arc::new(meow_proxy::dialer::NamedProxyDialer::new(target));
        let cfg = proxy_config(
            "name: s\ntype: ss\nserver: 192.0.2.1\nport: 8388\npassword: p\n\
             cipher: aes-128-gcm\ndialer-proxy: front\nrouting-mark: 42\n",
        );
        let proxy =
            super::parse_proxy_with_dialer(&cfg, &dialer, true).expect("chained leaf parses");
        assert_eq!(wrapped(&proxy).node_opts.routing_mark, Some(42));
    }

    /// A `proxy-groups:` entry never carries dialer fields — mihomo
    /// removed group-level dialer options in v1.19. The group schema has
    /// no such keys at all, so they drop at deserialization and nothing
    /// calls `parse_node_dialer_opts` for a group block.
    #[test]
    fn groups_do_not_parse_dialer_opts() {
        let raw: crate::raw::RawProxyGroup = serde_saphyr::from_str(
            "name: g\ntype: select\nproxies: [a]\ninterface-name: en0\n\
             ip-version: ipv4\nrouting-mark: 7\ntfo: true\nmptcp: true\n",
        )
        .expect("unknown keys on a group block are ignored");
        let member = parse_proxy(&proxy_config("name: a\ntype: direct\n")).unwrap();
        let proxies = HashMap::from([(SmolStr::from("a"), member)]);
        let group = parse_proxy_group(&raw, &proxies, &[], &Default::default());
        assert!(group.is_ok(), "group blocks ignore dialer fields");
    }

    /// Records the [`meow_common::dialer_opts`] a dial ran under — the
    /// scope probe every `WrappedProxy`/`ChainedProxy` coverage test
    /// shares (issue #974).
    type Seen = std::sync::Arc<parking_lot::Mutex<Option<meow_common::DialerOpts>>>;

    struct Capture {
        health: ProxyHealth,
        seen: Seen,
    }

    #[async_trait::async_trait]
    impl ProxyAdapter for Capture {
        fn name(&self) -> &str {
            "capture"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn meow_common::ProxyConn>> {
            *self.seen.lock() = Some(meow_common::dialer_opts());
            Err(meow_common::MeowError::Proxy("captured".into()))
        }
        async fn dial_udp(
            &self,
            _metadata: &Metadata,
        ) -> Result<Box<dyn meow_common::ProxyPacketConn>> {
            *self.seen.lock() = Some(meow_common::dialer_opts());
            Err(meow_common::MeowError::Proxy("captured".into()))
        }
        async fn connect_over(
            &self,
            _stream: Box<dyn meow_common::ProxyConn>,
            _metadata: &Metadata,
        ) -> Result<Box<dyn meow_common::ProxyConn>> {
            *self.seen.lock() = Some(meow_common::dialer_opts());
            Err(meow_common::MeowError::Proxy("captured".into()))
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    fn scoped_leaf(seen: &Seen) -> WrappedProxy {
        WrappedProxy::new(Box::new(Capture {
            health: ProxyHealth::new(),
            seen: std::sync::Arc::clone(seen),
        }))
        .with_node_dialer_opts(meow_common::NodeDialerOpts {
            ip_version: meow_common::IpVersion::Ipv6,
            routing_mark: Some(4242),
            ..Default::default()
        })
    }

    fn test_metadata() -> Metadata {
        Metadata {
            host: "h.test".into(),
            dst_port: 443,
            ..Default::default()
        }
    }

    /// The wrapper installs its resolved opts as the task-local scope
    /// around the adapter's dial — the mechanism every socket helper
    /// reads (issue #974). The stub captures `dialer_opts()` mid-dial to
    /// prove the scope landed and did not leak past it.
    #[tokio::test]
    async fn wrapped_dial_installs_the_scope() {
        let seen: Seen = Default::default();
        let proxy = scoped_leaf(&seen);
        let metadata = test_metadata();
        // Both dial paths install the node's resolved opts.
        assert!(proxy.dial_tcp(&metadata).await.is_err());
        {
            let captured = seen.lock();
            let opts = captured.as_ref().expect("the dial ran under the scope");
            assert_eq!(opts.ip_version, meow_common::IpVersion::Ipv6);
            assert_eq!(opts.routing_mark, Some(4242));
        }
        *seen.lock() = None;
        assert!(proxy.dial_udp(&metadata).await.is_err());
        assert_eq!(
            seen.lock().as_ref().map(|o| o.ip_version),
            Some(meow_common::IpVersion::Ipv6)
        );
        // …and nothing leaks past the call.
        assert_eq!(
            meow_common::dialer_opts().ip_version,
            meow_common::IpVersion::Dual
        );
    }

    /// `connect_over` — the relay-chain dial path — installs the same
    /// scope (issue #974): an injected leaf's transport handshake and any
    /// socket it opens run under the node's fields too.
    #[tokio::test]
    async fn wrapped_connect_over_installs_the_scope() {
        let seen: Seen = Default::default();
        let proxy = scoped_leaf(&seen);
        let metadata = test_metadata();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let stream: Box<dyn meow_common::ProxyConn> = Box::new(stream);
        assert!(proxy.connect_over(stream, &metadata).await.is_err());
        let captured = seen.lock();
        let opts = captured.as_ref().expect("connect_over ran under the scope");
        assert_eq!(opts.ip_version, meow_common::IpVersion::Ipv6);
        assert_eq!(opts.routing_mark, Some(4242));
    }

    /// `ChainedProxy` is observational only: it must not install a
    /// (default) scope of its own over the inner `WrappedProxy`'s —
    /// every method delegates verbatim, so a chained dial still sees the
    /// leaf's resolved opts, never the empty defaults a re-scope would
    /// leave (issue #974 review).
    #[tokio::test]
    async fn chained_proxy_delegates_without_rescoping() {
        let seen: Seen = Default::default();
        let inner: Arc<dyn Proxy> = Arc::new(scoped_leaf(&seen));
        let chained = ChainedProxy::new(inner);
        let metadata = test_metadata();
        assert!(chained.dial_tcp(&metadata).await.is_err());
        {
            let captured = seen.lock();
            let opts = captured
                .as_ref()
                .expect("the chained dial reached the leaf's scope");
            assert_eq!(opts.ip_version, meow_common::IpVersion::Ipv6);
            assert_eq!(opts.routing_mark, Some(4242));
        }
        *seen.lock() = None;
        assert!(chained.dial_udp(&metadata).await.is_err());
        assert_eq!(
            seen.lock().as_ref().map(|o| o.ip_version),
            Some(meow_common::IpVersion::Ipv6)
        );
    }
}
