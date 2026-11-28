//! YAML configuration parsing for the meow-rs proxy kernel.
//!
//! Turns a Clash Meta-style `config.yaml` into typed structs consumed by
//! the tunnel, listeners, DNS, and API.

pub mod auth;
pub mod dns_parser;
mod dns_proxy;
mod dns_response_rules;
pub mod dropped_providers;
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
mod private_file;
mod provider_payload;
pub mod proxy_parser;
pub mod proxy_provider;
pub mod proxy_provider_refresh;
pub mod raw;
pub mod rule_parser;
pub mod rule_provider;
pub mod rule_provider_refresh;
mod safe_path;
pub use safe_path::resolve_home_contained;
pub mod sub_rules_parser;
pub mod subscription;
pub mod subscription_userinfo;
#[cfg(test)]
mod test_support;

/// Serializes tests that write `meow_common::set_global_ua` — a
/// process-global the internal-HTTP/health emitters read per request, so
/// a parallel test's setter would race a wire check. Callers must restore
/// the cleared state before returning. `#[doc(hidden)]`: reached from the
/// `global_ua_internal_http_test` integration binary, which `#[cfg(test)]`
/// helpers cannot serve — not public API.
#[doc(hidden)]
pub fn global_ua_serial() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(crate) mod validation;
mod yaml_tree;

pub use dropped_providers::DroppedProviders;
pub use geodata::{GeoDataConfig, GeodataEgress};

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
    /// Live-resolver indirection every `type: dns` leaf this build
    /// produced binds (issue #974): static `proxies:` entries parse
    /// against it directly, and `ProxyProvider`s carry it so nodes their
    /// payloads declare — parsed before DNS exists, refreshed long after
    /// — resolve the same slot. Install it on the tunnel
    /// (`Tunnel::set_dns_outbound_cell`) so `install_resolver_everywhere`
    /// republishes the tunnel's `ResolverSlot` into it; until then it
    /// stays empty and bound leaves SERVFAIL rather than guess an
    /// upstream.
    pub provider_dns_cell: meow_dns::DnsOutboundCell,
    pub rules: Vec<Box<dyn Rule>>,
    /// The `sub-rules:` blocks `listeners[].rule` selects by name —
    /// published into the route table in the same snapshot as `rules` so
    /// a listener's named scan never observes a block and a route that
    /// disagree.
    pub sub_rules: sub_rules_parser::SubRuleBlocks,
    pub rule_providers: HashMap<String, Arc<rule_provider::RuleProvider>>,
    /// Providers the load left out leniently. The embedder records them once
    /// it runs this config ([`DroppedProviders::record`]).
    pub dropped_providers: DroppedProviders,
    /// The `dialer-proxy` registry generation `proxies` was published into.
    /// Hand it to `Tunnel::update_routing` so the route table retains it —
    /// chained adapters resolve through it weakly (issue #533).
    pub dialer_registry: meow_proxy::dialer::ProxyRegistry,
    /// The config-scoped `profile.store-selected` persistence owner —
    /// install it on the `Tunnel` (`set_selection_backing`) so every
    /// runtime rebuild lane shares this build's store and epoch
    /// (issue #974).
    pub selection: std::sync::Arc<meow_proxy::SelectionBacking>,
    /// The resolved `ntp:` service configuration — the supervisor
    /// reconciles workers against it; `PUT` diffs a new resolution on
    /// this (issue #974).
    pub ntp: NtpConfig,
    pub listeners: ListenerConfig,
    pub tun: TunConfig,
    pub api: ApiConfig,
    pub sniffer: SnifferConfig,
    pub auth: Arc<AuthConfig>,
    pub raw: raw::RawConfig,
    pub geodata: GeoDataConfig,
    /// Which geodata databases this config's rules/DNS reference — computed
    /// once at build time from the same scan that gates `ensure_geodata`.
    /// The auto-update loop refreshes only these; it is a startup snapshot
    /// and does not track later `PUT /configs` changes (same freeze as the
    /// rebuild path's own geo-download semantics).
    pub geo_needs: GeoDataNeeds,
}

pub struct GeneralConfig {
    pub mode: TunnelMode,
    pub log_level: String,
    pub ipv6: bool,
    pub allow_lan: bool,
    pub bind_address: String,
    /// `connection-notes` — see `Tunnel::set_connection_notes`.
    pub connection_notes: bool,
    /// `logbook.enable` — see `meow_common::logbook::apply`.
    pub logbook: bool,
    /// `tcp-idle-timeout` — whole-connection relay idle bound handed to
    /// `Tunnel::set_tcp_idle_timeout`: an established relay silent in both
    /// directions for this long is torn down. `None` disables the bound
    /// (`tcp-idle-timeout: 0`).
    pub tcp_idle_timeout: Option<std::time::Duration>,
    /// `tcp-concurrent` — the resolved live dial policy; the process-wide
    /// value dialers consult lives in `meow_common::dial` (installed at
    /// the startup/PATCH/PUT commit points). Deliberate divergence from
    /// upstream: mihomo defaults `false`, meow-rs keeps its historical
    /// race unless the operator opts out.
    pub tcp_concurrent: bool,
    /// `find-process-mode` — the resolved live lookup policy installed on
    /// the tunnel's `meow_common::ProcessLookupPolicy` at startup/PATCH/
    /// PUT-commit (issue #974). Defaults to `strict`.
    pub find_process_mode: meow_common::ProcessLookupMode,
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

/// The effective `tcp-concurrent` of a config whose key is unset — one
/// helper so startup install, `GeneralConfig`, `GET /configs` and PUT
/// commit can never disagree. Defaults to **`true`**: omission preserves
/// meow-rs's existing candidate race (a deliberate divergence — upstream
/// mihomo defaults `false`); only an explicit `false` requests strictly
/// sequential dialing.
pub fn effective_tcp_concurrent(raw_tcp_concurrent: Option<bool>) -> bool {
    raw_tcp_concurrent.unwrap_or(true)
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
        /// TCP by real TPROXY (local address = original destination)
        /// instead of REDIRECT; requires `firewall: false`. Set by a
        /// `listeners:` `type: tproxy` entry's `transparent:` key — never
        /// by the `tproxy-port`/`redir-port` shorthands (both are
        /// REDIRECT-shaped: managed vs. deployer-owned rules).
        #[serde(default)]
        transparent: bool,
    },
    /// Shadowsocks encrypted-server inbound. The listener terminates SS
    /// encryption (TCP stream cipher / AEAD, UDP relay), reads the SOCKS
    /// target address, and hands the decrypted flow to the tunnel. Mirrors
    /// upstream mihomo's `type: shadowsocks` listener.
    Shadowsocks(SsListenerConfig),
    /// WireGuard server-side inbound (`type: wireguard`): meow is the WG
    /// responder on one UDP port serving a static peer table; inner
    /// TCP/UDP flows are routed by the tunnel — semantically a TUN inbound
    /// carried over WireGuard. The variant always parses (no config-side
    /// feature gate); servability is gated at runtime by the
    /// `listener-wireguard` build feature — the same pattern as
    /// `type: shadowsocks` vs. `listener-shadowsocks`.
    WireGuard(WgListenerConfig),
    /// Named TUN device inbound (`type: tun`): the entry's flat options
    /// resolve to the same [`TunConfig`] the top-level `tun:` section
    /// produces (its own defaults profile — the entry's presence is the
    /// enabled state, MTU 9000, UDP timeout 300 s, auto-route off). It
    /// owns no socket port (`NamedListener.port`/`listen` are inert).
    /// Servability is gated by the `listener-tun` build feature and at
    /// most one effective TUN may exist: one named entry, or the
    /// top-level section — never both (spec §3).
    Tun(TunConfig),
    /// AnyTLS server inbound (`type: anytls`, mihomo-compatible): a
    /// BoringSSL TLS termination (or an explicitly opted-in plaintext
    /// mode) carrying authenticated AnyTLS v1/v2 sessions; every SYN'd
    /// logical stream is routed through the tunnel as a normal inbound
    /// flow, UoT v2 as UDP. Always parses; servability is gated by the
    /// `listener-anytls` build feature.
    Anytls(AnytlsListenerConfig),
    /// VLESS server inbound (`type: vless`, mihomo-compatible) with the
    /// XTLS `xtls-rprx-vision` flow: an outer TLS 1.3 termination —
    /// either a standard certificate pair or a REALITY server — carrying
    /// UUID-authenticated VLESS TCP flows, plus XUDP over Mux.Cool when
    /// `udp` is on. Always parses; servability is gated by the
    /// `listener-vless` build feature — the same pattern as
    /// `type: anytls` vs. `listener-anytls`.
    Vless(VlessListenerConfig),
}

/// Per-listener config for the `anytls` inbound (`ListenerSpec::Anytls`).
///
/// Built by `build_anytls_listener_spec`, the single semantic entry
/// point shared by startup, `-t` and `PUT /configs` — no file I/O
/// happens here; `certificate`/`private_key` stay as-written (PEM
/// literal or path) for the app's bind-time resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AnytlsListenerConfig {
    /// SHA-256-keyed user table in declaration order. EMPTY is a legal
    /// shape — "authenticate nothing", the upstream reject-all state
    /// (warned once at build); the listener still serves TLS.
    pub users: Vec<AnytlsUser>,
    /// `certificate` — PEM literal or path, `None` only in the
    /// `allow-insecure` plaintext mode.
    pub certificate: Option<String>,
    /// `private-key` — same dual form; `private_key` name because the
    /// raw field is shared with `type: wireguard`.
    pub private_key: Option<String>,
    /// Explicit plaintext opt-in (`allow-insecure: true`); `false` means
    /// the certificate pair above is mandatory.
    pub allow_insecure: bool,
    /// Raw `padding-scheme` bytes as written — already validated by the
    /// shared `meow_common::anytls_padding` contract, whose MD5 the
    /// protocol layer computes itself.
    pub padding_scheme: Option<String>,
    /// Every normalized bind target in declaration order — `listen` may
    /// carry a comma-separated list; the listener binds them atomically.
    /// Always non-empty after a successful build.
    pub addresses: Vec<ListenerBind>,
}

/// One normalized `(ip, port)` bind target inside a multi-address
/// `type: anytls` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerBind {
    pub listen: String,
    pub port: u16,
}

/// One `users:` entry: the username verbatim plus its wire credential —
/// `SHA256(password)`, the key the auth preface looks up (upstream
/// `userMap` semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnytlsUser {
    pub name: String,
    #[serde(with = "digest_serde")]
    pub password_sha256: [u8; 32],
}

/// `[u8; 32]` serde as a lowercase hex string — keeps `PUT /configs`
/// round-trips and API diagnostics readable without ever carrying the
/// plaintext password.
mod digest_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(digest: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let mut hex = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        hex.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom(
                "sha256 digest must be 64 hex chars",
            ));
        }
        let mut out = [0u8; 32];
        // Slice BYTES, not `&str` — a 64-byte non-ASCII string would
        // panic splitting a multi-byte char boundary.
        let (pairs, _rest) = s.as_bytes().as_chunks::<2>();
        for (b, pair) in out.iter_mut().zip(pairs) {
            let hi = (pair[0] as char).to_digit(16);
            let lo = (pair[1] as char).to_digit(16);
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(serde::de::Error::custom("sha256 digest must be hex"));
            };
            *b = (hi * 16 + lo) as u8;
        }
        Ok(out)
    }
}

/// Per-listener config for the `vless` inbound (`ListenerSpec::Vless`).
///
/// Built by `build_vless_listener_spec`, the single semantic entry point
/// shared by startup, `-t` and `PUT /configs` — no file I/O happens here;
/// certificate material stays as-written (PEM literal or path) for the
/// app's bind-time resolution, REALITY key material stays decoded but is
/// never logged (hand-rolled redacting [`Debug`]).
/// Redaction lives in the nested types (`VlessUser`, `VlessSecurity`), so
/// the derive is safe here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessListenerConfig {
    /// User table in declaration order — always non-empty after a
    /// successful build. Usernames unique, UUIDs unique post-normalization,
    /// every flow the literal `xtls-rprx-vision` (invariant, not stored).
    pub users: Vec<VlessUser>,
    /// The outer-transport security mode: exactly one of standard TLS
    /// (certificate pair) or REALITY. There is no plaintext mode.
    pub security: VlessSecurity,
    /// `udp` — default `true`; `false` rejects Mux/XUDP (`command=0x03`)
    /// at the VLESS header layer.
    pub udp: bool,
    /// Every normalized bind target in declaration order — `listen` may
    /// carry a comma-separated list; the listener binds them atomically.
    /// Always non-empty after a successful build.
    pub addresses: Vec<ListenerBind>,
}

/// One `users:` entry of a `type: vless` listener: the username (never on
/// the wire — it feeds `Metadata.in_user` for `IN-USER` rules) plus the
/// 16-byte wire credential pre-decoded at build time.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessUser {
    pub username: String,
    #[serde(with = "uuid_serde")]
    pub uuid: [u8; 16],
}

impl std::fmt::Debug for VlessUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Usernames identify principals and UUIDs are bearer credentials;
        // the v2 diagnostic redaction list covers both.
        f.debug_struct("VlessUser")
            .field("username", &"[REDACTED]")
            .field("uuid", &"[REDACTED]")
            .finish()
    }
}

/// The outer-transport security mode of a `type: vless` listener —
/// exactly one per entry; the flat certificate pair and `reality-config`
/// are mutually exclusive and there is no plaintext mode.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VlessSecurity {
    /// Standard TLS 1.3 termination on a certificate pair.
    StandardTls {
        /// `certificate` — PEM literal or path, as written.
        certificate: String,
        /// `private-key` — same dual form, same form as `certificate`.
        private_key: String,
        /// `alpn` — validated printable-ASCII protocol list, empty when
        /// absent: no ALPN is negotiated then. An explicit list selects
        /// in server order; a client offering no overlap fails the
        /// handshake, a client offering no ALPN still connects. ALPN is
        /// only a TLS negotiation value here — it enables neither HTTP/2
        /// nor any camouflage promise.
        alpn: Vec<String>,
    },
    /// REALITY server termination (see [`VlessRealityConfig`]).
    Reality(VlessRealityConfig),
}

impl std::fmt::Debug for VlessSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StandardTls {
                certificate: _,
                private_key: _,
                alpn,
            } => f
                .debug_struct("StandardTls")
                // Both fields may be inline PEM rather than paths; redact
                // unconditionally rather than trying to distinguish the form.
                .field("certificate", &"[REDACTED]")
                .field("private_key", &"[REDACTED]")
                .field("alpn", &alpn)
                .finish(),
            Self::Reality(cfg) => f.debug_tuple("Reality").field(cfg).finish(),
        }
    }
}

/// The `reality-config` block of a `type: vless` listener — the REALITY
/// server parameters, validated at build time. `dest` stays as-written
/// (host may be a domain resolved per cover dial); the private key is
/// stored decoded and never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessRealityConfig {
    /// Cover target `host:port` as written — shape-validated (port
    /// 1..=65535, bracketed IPv6), never resolved at build time.
    pub dest: String,
    /// Host half of [`Self::dest`], split once by the config validator so
    /// the runtime does not need its own copy of the shape parser.
    pub dest_host: String,
    /// Port half of [`Self::dest`], likewise prevalidated in `1..=65535`.
    pub dest_port: u16,
    /// X25519 static private key, 32 bytes. Never logged.
    #[serde(with = "reality_key_serde")]
    pub private_key: [u8; 32],
    /// Accepted short IDs, each right-zero-padded to 8 bytes and deduped
    /// by padded value; empty strings and all-zero values are rejected
    /// at build time.
    #[serde(with = "short_ids_serde")]
    pub short_ids: Vec<[u8; 8]>,
    /// Exact-match SNI allowlist — validated ASCII DNS A-labels, no
    /// wildcards/IPs/trailing dots, deduped case-insensitively.
    pub server_names: Vec<String>,
    /// ClientHello freshness window in microseconds — the default is
    /// 120 seconds (`120_000_000`); `0` disables the freshness check.
    pub max_time_difference_us: u64,
    /// Cover-direction rate limits (upload/download independent). Zero
    /// fields disable the corresponding limiter.
    pub limit_fallback_upload: RealityLimitFallback,
    pub limit_fallback_download: RealityLimitFallback,
    /// REALITY v2 mirror orchestration, normalized at build time. The
    /// default is dial-first; `off` is the explicit v1 rollback.
    #[serde(default)]
    pub mimic: meow_common::VlessRealityMimicSpec,
}

impl std::fmt::Debug for VlessRealityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The v2 diagnostic redaction list covers the cover identity,
        // admission names, key material and short IDs; only non-identifying
        // counts and numeric limits may surface.
        f.debug_struct("VlessRealityConfig")
            .field("dest", &"[REDACTED]")
            .field("private_key", &"[REDACTED]")
            .field(
                "short_ids",
                &format_args!("[{} entries]", self.short_ids.len()),
            )
            .field(
                "server_names",
                &format_args!("[{} entries]", self.server_names.len()),
            )
            .field("max_time_difference_us", &self.max_time_difference_us)
            .field("limit_fallback_upload", &self.limit_fallback_upload)
            .field("limit_fallback_download", &self.limit_fallback_download)
            .field("mimic", &self.mimic)
            .finish()
    }
}

/// One direction of the REALITY cover-branch rate limit —
/// `after-bytes`/`bytes-per-sec`/`burst-bytes-per-sec`, all zero when
/// unset. `bytes_per_sec: 0` never engages the limiter; a burst not
/// exceeding the base rate is treated as the base rate by the runtime
/// (the config layer only validates shape, not the token bucket).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RealityLimitFallback {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes_per_sec: u64,
}

/// `[u8; 16]` UUID serde as the canonical dashed lowercase string —
/// keeps `PUT /configs` round-trips and API diagnostics in the form
/// operators recognize without ever carrying dashes on the wire.
mod uuid_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(uuid: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7], uuid[8],
            uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15],
        )
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        crate::parse_strict_uuid(&s).map_err(serde::de::Error::custom)
    }
}

/// `[u8; 32]` REALITY private-key serde as unpadded URL-safe base64 —
/// the same spelling the operator writes under `reality-config`, so a
/// persisted spec reads like the input document.
mod reality_key_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(key: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key)
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use base64::Engine;
        let s = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("reality private key must decode to 32 bytes"))
    }
}

/// `Vec<[u8; 8]>` short-ID serde as hex strings — each entry the padded
/// 8-byte form (16 lowercase hex chars), matching how operators write
/// the (shorter) input while staying unambiguous on round-trip.
mod short_ids_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(ids: &[[u8; 8]], s: S) -> Result<S::Ok, S::Error> {
        let hex: Vec<String> = ids
            .iter()
            .map(|id| {
                let mut out = String::with_capacity(16);
                for b in id {
                    use std::fmt::Write as _;
                    let _ = write!(out, "{b:02x}");
                }
                out
            })
            .collect();
        hex.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 8]>, D::Error> {
        let hexes = Vec::<String>::deserialize(d)?;
        hexes
            .iter()
            .map(|h| crate::decode_padded_short_id(h).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Parse a UUID string in exactly the two spellings the VLESS inbound
/// accepts — the canonical hyphenated form (`8-4-4-4-12` hex groups,
/// hyphens ONLY at those positions) or 32 bare hex digits; case is
/// insignificant. Unlike the outbound node's lenient parser, arbitrary
/// hyphen placement is rejected: the inbound pre-decodes holder
/// credentials and an ambiguous spelling is a configuration bug, not a
/// variant to accommodate.
pub(crate) fn parse_strict_uuid(s: &str) -> Result<[u8; 16], String> {
    let hex_digits = if s.len() == 36 {
        // Hyphenated form: dashes exactly at 8/13/18/23, hex elsewhere.
        for (i, c) in s.char_indices() {
            let expect_dash = matches!(i, 8 | 13 | 18 | 23);
            if expect_dash != (c == '-') {
                return Err(
                    "invalid uuid: hyphens must sit exactly at the 8-4-4-4-12 group boundaries"
                        .to_string(),
                );
            }
        }
        s.chars().filter(|c| *c != '-').collect::<String>()
    } else if s.len() == 32 {
        if s.contains('-') {
            return Err(
                "invalid uuid: use the canonical hyphenated form or 32 bare hex digits".to_string(),
            );
        }
        s.to_string()
    } else {
        return Err(format!(
            "invalid uuid: expected 32 hex chars (with or without hyphens), got {} chars",
            s.len()
        ));
    };
    // len is 32 in both arms by construction (36 - 4 hyphens). The
    // candidate is never echoed into the error — UUIDs are credentials
    // and parse errors are on the redaction list.
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex_digits.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| "invalid uuid".to_string())?;
        bytes[i] =
            u8::from_str_radix(pair, 16).map_err(|_| "invalid uuid: non-hex digits".to_string())?;
    }
    Ok(bytes)
}

/// Decode a REALITY short-id entry: even-length hex of at most 16 chars
/// (8 bytes), right-zero-padded to the fixed 8-byte comparison form —
/// the padding mihomo applies, which is why `"ab"` and `"ab00"` collide.
pub(crate) fn decode_padded_short_id(s: &str) -> Result<[u8; 8], String> {
    // The candidate is never echoed — short IDs are on the reality
    // spec's redaction list even when malformed (a typo'd real one).
    if !s.len().is_multiple_of(2) || s.len() > 16 {
        return Err("must be an even number of hex digits, at most 16 chars".to_string());
    }
    if s.is_empty() {
        return Err("empty".to_string());
    }
    let mut out = [0u8; 8];
    for (i, chunk) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| "not utf8".to_string())?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| "non-hex digits".to_string())?;
    }
    Ok(out)
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

/// Per-listener config for the `wireguard` inbound (`ListenerSpec::WireGuard`).
///
/// Validated at config-build time by `build_wg_listener_spec`: `private_key`
/// is the listener's static private key (base64 → exactly 32 bytes in the
/// YAML, stored decoded) and `peers` is the static peer table (never empty,
/// at most `2^24 - 1` entries — the `index << 8` demux namespace).
/// `port`/`listen`/`max_connections` live on [`NamedListener`], the same
/// split as [`SsListenerConfig`].
///
/// [`Debug`] is hand-rolled: the struct carries key material that must
/// never land in a log line (the `WireGuardConfig` outbound precedent).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgListenerConfig {
    /// Listener static private key, 32 bytes. Never logged.
    pub private_key: [u8; 32],
    /// Static peer table — at least one entry after validation.
    pub peers: Vec<WgPeerConfig>,
    /// Outer (wire) MTU; `inner_mtu = mtu - 64` stays ≥ 576. Default 1420.
    #[serde(default = "default_wg_mtu")]
    pub mtu: u16,
    /// `false` silently drops inner UDP datagrams. Default `true`.
    #[serde(default = "default_wg_udp")]
    pub udp: bool,
    /// Inner UDP flow idle timeout (default 60s; `0` is rejected at build
    /// time, matching the `tproxy`/`tun` `udp-timeout` contract).
    #[serde(default = "default_wg_udp_timeout")]
    pub udp_timeout: std::time::Duration,
}

/// One static peer of a `type: wireguard` listener.
///
/// `public_key` doubles as the handshake demux key and must be unique
/// inside the listener's peer table; `allowed_ips` is the inbound
/// inner-source-IP ACL (spoofing guard) and is never empty — an explicit
/// `0.0.0.0/0` + `::/0` is required for full openness, deliberately
/// unlike the outbound's empty-means-open default.
///
/// [`Debug`] is hand-rolled to redact `preshared_key`; `public_key` is
/// *not* redacted — a public key is safe to log and needed for diagnosis.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgPeerConfig {
    /// Peer static public key, 32 bytes.
    pub public_key: [u8; 32],
    /// Optional pre-shared symmetric key (Noise `psk` mixing). Never logged.
    pub preshared_key: Option<[u8; 32]>,
    /// Inbound inner-source-IP ACL for this peer — non-empty.
    pub allowed_ips: Vec<ipnet::IpNet>,
    /// Log/diagnostic label only (`peer-<index>` when unnamed) — never
    /// enters `Metadata`.
    pub name: SmolStr,
    /// WARP-style 3-byte `reserved` field stamped onto wire datagrams
    /// headed to this peer; inbound reserved bytes are cleared regardless.
    pub reserved: Option<[u8; 3]>,
}

impl std::fmt::Debug for WgListenerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgListenerConfig")
            .field("private_key", &"[REDACTED]")
            .field("peers", &self.peers)
            .field("mtu", &self.mtu)
            .field("udp", &self.udp)
            .field("udp_timeout", &self.udp_timeout)
            .finish()
    }
}

impl std::fmt::Debug for WgPeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeerConfig")
            .field("public_key", &self.public_key)
            .field("preshared_key", &self.preshared_key.map(|_| "[REDACTED]"))
            .field("allowed_ips", &self.allowed_ips)
            .field("name", &self.name)
            .field("reserved", &self.reserved)
            .finish()
    }
}

/// `WgListenerConfig::mtu` serde default — the usual WG baseline, same as
/// the outbound adapter's.
fn default_wg_mtu() -> u16 {
    1420
}

/// `WgListenerConfig::udp` serde default: the inner-UDP path is on.
fn default_wg_udp() -> bool {
    true
}

/// `WgListenerConfig::udp_timeout` serde default — matches the `tproxy`
/// `udp-timeout` and `tun.udp-timeout` default (60s).
fn default_wg_udp_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(default_udp_timeout_secs())
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
            Self::WireGuard(_) => "wireguard",
            Self::Tun(_) => "tun",
            Self::Anytls(_) => "anytls",
            Self::Vless(_) => "vless",
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
    /// `listeners[].proxy`/`listeners[].rule` — the named-listener route
    /// override stamped onto every flow's `Metadata` (upstream's
    /// `BaseOption` Additions). `None` on the port shorthands and on
    /// entries that declare neither key.
    #[serde(default)]
    pub route_override: Option<meow_common::InboundRouteOverride>,
    /// `listeners[].routing-mark` — `SO_MARK` on the listener socket at
    /// bind; Linux only (warned and ignored elsewhere).
    #[serde(default)]
    pub routing_mark: Option<u32>,
}

/// Parsed + validated `tun:` section (issue #326). Consumed by the app
/// layer, which maps it onto `meow_listener::TunListenerConfig` when the
/// `listener-tun` feature is compiled in. A named `listeners:`
/// `type: tun` entry resolves to the same type ([`ListenerSpec::Tun`])
/// — under its own defaults profile, never sharing the top-level ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunConfig {
    pub enable: bool,
    /// Device name; `None` = platform default.
    pub device: Option<String>,
    pub mtu: u16,
    /// Address + prefix assigned to the device. Defaults to the fake-IP
    /// range's first /30 ([`default_tun_inet4_address`]).
    pub inet4_address: ipnet::Ipv4Net,
    /// IPv6 address + prefix assigned to the device (`inet6-address`).
    /// Only ever `Some` in global route mode, where it also captures IPv6
    /// (#375); `None` = the device is IPv4-only.
    pub inet6_address: Option<ipnet::Ipv6Net>,
    pub auto_route: bool,
    /// Which routes `auto-route` installs (#375). Only meaningful when
    /// `auto_route` is true.
    pub route_mode: TunRouteMode,
    /// Physical interface outbound sockets bind to in global mode; `None`
    /// = auto-detect from the default route at listener startup.
    pub outbound_interface: Option<String>,
    /// True when `dns-hijack` is absent or contains at least one usable
    /// (`:53`) entry; an empty list turns it off.
    pub dns_hijack: bool,
    pub udp_timeout: std::time::Duration,
    /// Cap on concurrent TUN TCP flows. Inherited from the top-level
    /// `max-connections` key (default 256; `0` = unlimited). The accept
    /// loop has no listen-queue back-pressure of its own — this is what
    /// stops a reconnect storm from spawning unbounded `handle_tcp` tasks.
    pub max_connections: usize,
    /// Which stack terminates the TUN's TCP (`tun.stack`).
    pub stack: TunStack,
}

/// `tun.stack`. `system` and `mixed` hand TCP to the host
/// kernel's stack, as mihomo's system stack does (Linux; elsewhere the
/// listener falls back to lwIP); anything else (`gvisor`, `mips`, `lwip`,
/// unset) keeps the userspace lwIP stack. Under `system` UDP is handled
/// in the pump (UDP fragments and ICMP still go to lwIP; fragmented TCP
/// is dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TunStack {
    #[default]
    Lwip,
    System,
}

/// Scope of the routes `tun.auto-route` installs (#375).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunRouteMode {
    /// `auto-route: fake-ip`: route only the fake-IP range into the
    /// device. Loop-free by construction; IP-literal traffic is not
    /// captured.
    FakeIp,
    /// `auto-route: true` (or `global`): route all traffic the host
    /// originates — IPv4, and IPv6 when `inet6-address` is set — into the
    /// device, and bind outbound sockets to the physical interface for
    /// loop avoidance. Linux, macOS and Windows.
    Global,
}

impl Default for TunRouteMode {
    /// What `auto-route: true`, and an unset `auto-route`, select: global
    /// where outbound sockets can be bound to the physical interface,
    /// fake-IP elsewhere.
    fn default() -> Self {
        if cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) {
            Self::Global
        } else {
            Self::FakeIp
        }
    }
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enable: false,
            device: None,
            mtu: 1500,
            inet4_address: default_tun_inet4_address(None),
            inet6_address: None,
            auto_route: true,
            route_mode: TunRouteMode::default(),
            outbound_interface: None,
            dns_hijack: true,
            udp_timeout: std::time::Duration::from_secs(60),
            max_connections: 256,
            stack: TunStack::Lwip,
        }
    }
}

/// Minimum MTU accepted for the TUN device — the IPv6 floor (RFC 8200 §5);
/// smaller values break v6 traffic through the userspace stack.
const TUN_MIN_MTU: u16 = 1280;

/// The TUN device's address when `tun.inet4-address` is unset: the first
/// /30 of `fake_ip_range` (`dns.fake-ip-range`), its gateway as the host,
/// like mihomo. The fake-IP pool never hands out a range's first four
/// addresses, so the device cannot take a fake IP; and the default range,
/// 198.18.0.0/16, is outside every LAN and container network. A fixed
/// private subnet is not: `172.19.0.1/30`, the old default, took the
/// gateway and first containers of a Docker network on 172.19.0.0/16.
/// A range that is not IPv4, or too small for the pool, falls back to
/// the default range's /30.
pub fn default_tun_inet4_address(fake_ip_range: Option<&str>) -> ipnet::Ipv4Net {
    let from_range = |range: &str| {
        let range = range.parse::<ipnet::Ipv4Net>().ok()?;
        // The pool's first allocatable address is network + 4.
        if range.prefix_len() > 29 {
            return None;
        }
        let gateway = std::net::Ipv4Addr::from(u32::from(range.network()) + 1);
        ipnet::Ipv4Net::new(gateway, 30).ok()
    };
    fake_ip_range
        .and_then(from_range)
        .or_else(|| from_range(dns_parser::DEFAULT_FAKE_IP_RANGE_V4))
        .expect("the default fake-IP range is an IPv4 /16")
}

/// Reject capacities Tokio cannot represent before any listener starts.
fn validate_connection_limit(value: usize) -> Result<(), anyhow::Error> {
    anyhow::ensure!(
        value <= tokio::sync::Semaphore::MAX_PERMITS,
        "max-connections exceeds the runtime maximum ({})",
        tokio::sync::Semaphore::MAX_PERMITS
    );
    Ok(())
}

/// Validate the raw `global-ua` value (issue #974): `None`/empty resolves
/// to the default UA. A value with CR/LF/NUL/control bytes is a Class A
/// rejection — the emitters format it into a raw request head, so an
/// unchecked newline is header injection. The byte check runs on the
/// UNTRIMMED string: `str::trim` strips `\r`/`\n`/`\x0b`/`\x0c` at the
/// edges, which would smuggle `"evil\r\n"` past the check while callers
/// keep the untrimmed value. Only `' '`/`'\t'` — HTTP OWS — are trimmed
/// for the returned value; a bare `"\r\n"` is an error, not `None`.
pub fn validate_global_ua(raw_ua: Option<&str>) -> Result<Option<&str>, anyhow::Error> {
    let Some(raw) = raw_ua else {
        return Ok(None);
    };
    anyhow::ensure!(
        meow_common::is_valid_http_header_value(raw),
        "global-ua contains bytes that are not legal in an HTTP header \
         value (newline/NUL/control characters are rejected)"
    );
    Ok(Some(raw.trim_matches([' ', '\t'])).filter(|s| !s.is_empty()))
}

/// Parse and validate the raw `tun:` block. Returns `TunConfig::default()`
/// (disabled) when the block is absent. `fake_ip_range` is the config's
/// `dns.fake-ip-range`, which sets the default `inet4-address`.
pub fn parse_tun_config(
    raw: Option<&raw::RawTun>,
    global_max_connections: Option<usize>,
    fake_ip_range: Option<&str>,
) -> Result<TunConfig, anyhow::Error> {
    validate_connection_limit(global_max_connections.unwrap_or(256))?;
    let Some(r) = raw else {
        // Keep the global-cap folding symmetric with the `Some` arm: an
        // absent section still inherits `max-connections`, so callers
        // diffing parsed configs see the same value either way.
        return Ok(TunConfig {
            max_connections: global_max_connections.unwrap_or(256),
            inet4_address: default_tun_inet4_address(fake_ip_range),
            ..TunConfig::default()
        });
    };

    // Warn on upstream-only fields (Class B per ADR-0002; policy of #328:
    // never silently ignore a mihomo flag).
    for (name, val) in [
        ("strict-route", &r.strict_route),
        ("auto-detect-interface", &r.auto_detect_interface),
        ("auto-redirect", &r.auto_redirect),
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

    let inet4_address = match first_cidr("tun.inet4-address", "IPv4", r.inet4_address.as_ref())? {
        Some(s) => s
            .parse::<ipnet::Ipv4Net>()
            .map_err(|e| anyhow::anyhow!("tun.inet4-address: invalid CIDR '{s}': {e}"))?,
        None => default_tun_inet4_address(fake_ip_range),
    };

    // Absent: on. An empty list turns it off. Only the exact wildcard
    // :53 forms enable the UDP hijack.
    let mut dns_hijack = r.dns_hijack.is_none();
    for entry in r.dns_hijack.as_deref().unwrap_or(&[]) {
        match dns_hijack_entry(entry) {
            true => dns_hijack = true,
            false => warn!(
                "tun.dns-hijack: entry '{entry}' is not a wildcard UDP :53 target \
                 {DNS_HIJACK_FORMS}; meow-rs hijacks UDP/53 only — entry ignored",
                DNS_HIJACK_FORMS = DNS_HIJACK_FORMS
            ),
        }
    }

    let udp_timeout = std::time::Duration::from_secs(match r.udp_timeout {
        Some(0) => {
            return Err(anyhow::anyhow!(
                "tun.udp-timeout: must be at least 1 second"
            ));
        }
        // Feeds `Instant::now() + udp_timeout` in the flow idle loop — an
        // absurd u64 overflows and aborts the process (issue #648).
        Some(secs) if secs > meow_common::MAX_DURATION_SECS => {
            return Err(anyhow::anyhow!(
                "tun.udp-timeout: {secs}s exceeds the {}s ceiling",
                meow_common::MAX_DURATION_SECS
            ));
        }
        Some(secs) => secs,
        None => defaults.udp_timeout.as_secs(),
    });

    let (auto_route, route_mode) = parse_auto_route(r)?;
    let global = auto_route && route_mode == TunRouteMode::Global;

    let outbound_interface = raw_outbound_interface(r);
    if outbound_interface.is_some() && !global {
        warn!(
            "tun.outbound-interface: only used when auto-route captures all traffic \
             ('auto-route: true'); ignored"
        );
    }
    // Normalise the ignored value out: the commit path diffs parsed
    // `TunConfig`s to decide on a restart, and a field that does nothing
    // must not trigger one — a PUT touching only `outbound-interface`
    // under fake-ip scope would otherwise bounce a healthy listener
    // (issue #543 review).
    let outbound_interface = outbound_interface.filter(|_| global);

    // `inet6-address` is validated in every mode, but only global mode has
    // IPv6 routes to send into the device — elsewhere an address on the
    // device would capture nothing, so it is normalised out for the same
    // restart-diff reason as `outbound-interface` above.
    let inet6_address = parse_inet6_address("tun.inet6-address", r.inet6_address.as_ref())?;
    if inet6_address.is_some() && !global {
        warn!(
            "tun.inet6-address: only used when auto-route captures all traffic \
             ('auto-route: true'); ignored (the device stays IPv4-only)"
        );
    }
    let inet6_address = inet6_address.filter(|_| global);

    Ok(TunConfig {
        enable: r.enable,
        device: r.device.clone().filter(|s| !s.is_empty()),
        mtu,
        inet4_address,
        inet6_address,
        auto_route,
        route_mode,
        outbound_interface,
        dns_hijack,
        udp_timeout,
        max_connections: global_max_connections.unwrap_or(defaults.max_connections),
        stack: parse_tun_stack(r.stack.as_ref()),
    })
}

fn parse_tun_stack(raw: Option<&serde_json::Value>) -> TunStack {
    let Some(value) = raw else {
        return TunStack::Lwip;
    };
    match value.as_str().map(str::to_ascii_lowercase).as_deref() {
        Some("system") => TunStack::System,
        Some("mixed") => {
            warn!(
                "tun.stack: mixed is system here — kernel TCP, and UDP parsed in \
                 the pump rather than by a userspace stack"
            );
            TunStack::System
        }
        Some("gvisor") => {
            warn!("tun.stack: gvisor is not available; using the userspace (lwip) stack");
            TunStack::Lwip
        }
        Some("mips") => {
            warn!("tun.stack: mips (mihomo's own stack) is not available; using the userspace (lwip) stack");
            TunStack::Lwip
        }
        Some("lwip" | "") => TunStack::Lwip,
        _ => {
            warn!("tun.stack: unknown value {value}; using the userspace (lwip) stack");
            TunStack::Lwip
        }
    }
}

/// `listeners[]` `type: tun` defaults — the named profile, deliberately
/// distinct from the top-level section's (upstream `NewTun`/`sing_tun`
/// supplies these): the entry's presence is the enabled state, MTU 9000,
/// UDP idle timeout 300 s, `auto-route` OFF. On this path an explicit
/// `0` for `mtu`/`udp-timeout` also means "default" (upstream fills the
/// zero with the fallback).
const NAMED_TUN_MTU: u16 = 9000;
const NAMED_TUN_UDP_TIMEOUT_SECS: u64 = 300;

/// Parse and validate a `listeners:` `type: tun` entry — the flat
/// `TunOption` shape, never a nested `tun:` map. Shares the top-level
/// parser's normalization (same address forms, fake-IP-derived default
/// address, global-only IPv6, MTU floor, duration ceiling) but applies
/// the named defaults profile (`NAMED_TUN_MTU`,
/// `NAMED_TUN_UDP_TIMEOUT_SECS`, auto-route off, enabled by presence).
/// `global_max_connections`/`fake_ip_range` are the same inherited
/// inputs `parse_tun_config` takes.
///
/// Unlike the top-level parser this errors on unknown `stack` spellings —
/// upstream `-t` rejects an invalid flat `stack` (it only tolerates one
/// under the ignored nested `tun:` map).
pub fn parse_named_tun_config(
    raw_l: &raw::RawListener,
    global_max_connections: usize,
    fake_ip_range: Option<&str>,
) -> Result<TunConfig, anyhow::Error> {
    let name = &raw_l.name;
    // Warn on the upstream keys meow does not implement (Class B per
    // ADR-0002) — `auto-detect-interface` gets its specific reason: it
    // never controlled the outbound-interface binding meow installs for
    // loop protection under global route scope.
    if raw_l.auto_detect_interface.is_some() {
        warn!(
            "listeners[{name}].auto-detect-interface: meow's loop-protection \
             outbound-interface binding is not governed by this flag — ignored"
        );
    }
    for (key, val) in [
        ("dns-mode", &raw_l.dns_mode),
        ("strict-route", &raw_l.strict_route),
        ("auto-redirect", &raw_l.auto_redirect),
        ("endpoint-independent-nat", &raw_l.endpoint_independent_nat),
        ("mtu-v6", &raw_l.mtu_v6),
        ("route-address", &raw_l.route_address),
        ("route-exclude-address", &raw_l.route_exclude_address),
        ("include-uid", &raw_l.include_uid),
        ("exclude-uid", &raw_l.exclude_uid),
        ("gso", &raw_l.gso),
        ("file-descriptor", &raw_l.file_descriptor),
    ] {
        if val.is_some() {
            warn!(
                "listeners[{name}].{key}: field is not supported in meow-rs and will \
                 be ignored; remove it to suppress this warning"
            );
        }
    }

    // Explicit `0` = the named default on this path (upstream fills a
    // zero with the fallback); below the IPv6 floor is a hard error.
    let mtu = raw_l.mtu.unwrap_or(0);
    let mtu = if mtu == 0 { NAMED_TUN_MTU } else { mtu };
    if mtu < TUN_MIN_MTU {
        return Err(anyhow::anyhow!(
            "listeners[{name}].mtu: {mtu} is below the minimum {TUN_MIN_MTU} \
             required by the userspace stack"
        ));
    }

    let udp_timeout = std::time::Duration::from_secs(match raw_l.udp_timeout {
        // `0` = the 300 s named default here (the tproxy/wireguard
        // surfaces keep their `0`-is-an-error contract).
        Some(0) | None => NAMED_TUN_UDP_TIMEOUT_SECS,
        Some(secs) if secs > meow_common::MAX_DURATION_SECS => {
            return Err(anyhow::anyhow!(
                "listeners[{name}].udp-timeout: {secs}s exceeds the {}s ceiling",
                meow_common::MAX_DURATION_SECS
            ));
        }
        Some(secs) => secs,
    });

    let err_key = format!("listeners[{name}].auto-route");
    let (auto_route, route_mode) =
        parse_auto_route_value(raw_l.auto_route.as_ref(), false, &err_key)?;
    let global = auto_route && route_mode == TunRouteMode::Global;

    let outbound_interface = raw_l.outbound_interface.clone().filter(|s| !s.is_empty());
    if outbound_interface.is_some() && !global {
        warn!(
            "listeners[{name}].outbound-interface: only used when auto-route \
             captures all traffic ('auto-route: true' or 'global'); ignored"
        );
    }
    let outbound_interface = outbound_interface.filter(|_| global);

    // Absent: on. An empty list turns it off. Only the exact wildcard
    // :53 forms enable the UDP hijack — a `tcp:` target (the pump has no
    // TCP/53 diversion), a specific address, or any other shape warns and
    // is ignored rather than broadening what the device diverts.
    let mut dns_hijack = raw_l.dns_hijack.is_none();
    for entry in raw_l.dns_hijack.as_deref().unwrap_or(&[]) {
        match dns_hijack_entry(entry) {
            true => dns_hijack = true,
            false => warn!(
                "listeners[{name}].dns-hijack: entry '{entry}' is not a wildcard \
                 UDP :53 target {DNS_HIJACK_FORMS}; meow-rs hijacks UDP/53 only — \
                 entry ignored",
                DNS_HIJACK_FORMS = DNS_HIJACK_FORMS
            ),
        }
    }

    let key4 = format!("listeners[{name}].inet4-address");
    let inet4_address = match first_cidr(&key4, "IPv4", raw_l.inet4_address.as_ref())? {
        Some(s) => s
            .parse::<ipnet::Ipv4Net>()
            .map_err(|e| anyhow::anyhow!("{key4}: invalid CIDR '{s}': {e}"))?,
        // Deliberate meow behaviour: the fake-IP-range-derived /30, the
        // same default the top-level section uses.
        None => default_tun_inet4_address(fake_ip_range),
    };
    // IPv6 is honoured only in global route scope, same as the top-level
    // section — elsewhere it is normalised out so nothing capture-less
    // sits on the device.
    let key6 = format!("listeners[{name}].inet6-address");
    let inet6_address = parse_inet6_address(&key6, raw_l.inet6_address.as_ref())?;
    if inet6_address.is_some() && !global {
        warn!(
            "listeners[{name}].inet6-address: only used when auto-route \
             captures all traffic ('auto-route: true' or 'global'); ignored \
             (the device stays IPv4-only)"
        );
    }
    let inet6_address = inet6_address.filter(|_| global);

    Ok(TunConfig {
        enable: true,
        device: raw_l.device.clone().filter(|s| !s.is_empty()),
        mtu,
        inet4_address,
        inet6_address,
        auto_route,
        route_mode,
        outbound_interface,
        dns_hijack,
        udp_timeout,
        max_connections: raw_l.max_connections.unwrap_or(global_max_connections),
        stack: parse_named_tun_stack(name, raw_l.stack.as_ref())?,
    })
}

/// `listeners[].stack` for `type: tun` — like `parse_tun_stack` but
/// strict: `system`/`mixed` select the kernel TCP path, `mips`/`gvisor`
/// fold to lwIP with a warning (upstream names; meow has no such stack),
/// `lwip`/empty select lwIP, and every other value is a hard error —
/// upstream `-t` rejects an invalid flat `stack`.
fn parse_named_tun_stack(
    name: &str,
    raw: Option<&serde_json::Value>,
) -> Result<TunStack, anyhow::Error> {
    let Some(value) = raw else {
        return Ok(TunStack::Lwip);
    };
    match value.as_str().map(str::to_ascii_lowercase).as_deref() {
        Some("system") => Ok(TunStack::System),
        Some("mixed") => {
            warn!(
                "listeners[{name}].stack: mixed is system here — kernel TCP, \
                 and UDP parsed in the pump rather than by a userspace stack"
            );
            Ok(TunStack::System)
        }
        Some("gvisor") => {
            warn!(
                "listeners[{name}].stack: gvisor is not available; using the \
                 userspace (lwip) stack"
            );
            Ok(TunStack::Lwip)
        }
        Some("mips") => {
            warn!(
                "listeners[{name}].stack: mips (mihomo's own stack) is not \
                 available; using the userspace (lwip) stack"
            );
            Ok(TunStack::Lwip)
        }
        Some("lwip" | "") => Ok(TunStack::Lwip),
        _ => Err(anyhow::anyhow!(
            "listeners[{name}].stack: unknown value {value} (expected \
             system, mixed, gvisor, mips, or lwip)"
        )),
    }
}

/// The `dns-hijack` targets meow admits — the wildcard UDP/53 spellings
/// only. `tcp:`-schemed targets name a TCP diversion meow does not
/// implement; a specific host address or another port is outside the
/// hijack's "every UDP :53 flow" contract.
const DNS_HIJACK_FORMS: &str = "(0.0.0.0:53, any:53, *:53, [::]:53)";

/// Whether `entry` is one of [`DNS_HIJACK_FORMS`]' exact spellings.
fn dns_hijack_entry(entry: &str) -> bool {
    matches!(entry, "0.0.0.0:53" | "any:53" | "*:53" | "[::]:53")
}

/// The CIDR string of an `inet{4,6}-address`: a string or mihomo's list
/// form (`[]netip.Prefix`), of which the first entry is used — with a
/// warning when there are more — since the device takes a single address.
/// `''` and `[]` are "unset". A `Value::Null` is an error, not unset:
/// YAML `null` lands in the `None` arm (the `Option` layer's `visit_none`),
/// so only a non-finite float (`.nan`, `.inf`, `1e999`) — which
/// `serde_json::Value` maps to `Null` — reaches it, and those were a hard
/// error when `inet4-address` was `Option<String>` (the spelling reached
/// the CIDR parse as text). `key` is the fully qualified key name
/// (`tun.inet4-address`, `listeners[name].inet4-address`, …) used in
/// diagnostics.
fn first_cidr<'a>(
    key: &str,
    family: &str,
    raw: Option<&'a serde_json::Value>,
) -> Result<Option<&'a str>, anyhow::Error> {
    let cidr = match raw {
        None => return Ok(None),
        Some(serde_json::Value::Null) => {
            return Err(anyhow::anyhow!(
                "{key}: expected a CIDR string or a list of them, got a \
                 non-finite number (e.g. .nan, .inf)"
            ));
        }
        Some(serde_json::Value::String(s)) => s.as_str(),
        Some(serde_json::Value::Array(entries)) => {
            if entries.len() > 1 {
                warn!(
                    "{key}: {} entries given; meow-rs assigns one {family} \
                     address to the device — only the first is used",
                    entries.len()
                );
            }
            match entries.first() {
                None => return Ok(None),
                Some(serde_json::Value::String(s)) => s.as_str(),
                Some(other) => {
                    return Err(anyhow::anyhow!(
                        "{key}: expected a CIDR string, got {other:?}"
                    ));
                }
            }
        }
        Some(other) => {
            return Err(anyhow::anyhow!(
                "{key}: expected a CIDR string or a list of them, got {other:?}"
            ));
        }
    };
    Ok((!cidr.is_empty()).then_some(cidr))
}

fn parse_inet6_address(
    key: &str,
    raw: Option<&serde_json::Value>,
) -> Result<Option<ipnet::Ipv6Net>, anyhow::Error> {
    let Some(cidr) = first_cidr(key, "IPv6", raw)? else {
        return Ok(None);
    };
    cidr.parse::<ipnet::Ipv6Net>()
        .map(Some)
        .map_err(|e| anyhow::anyhow!("{key}: invalid CIDR '{cidr}': {e}"))
}

/// `auto-route` (#375): mihomo boolean, or a mode string selecting what
/// gets routed. `true` captures all traffic where that is supported
/// ([`TunRouteMode::default`]); `fake-ip` opts into the narrower
/// loop-free scope, and `global` names the full one explicitly.
/// `default_on` is the surface's absent-value policy: `true` for the
/// top-level `tun:` section, `false` for a named `type: tun` entry.
/// Shared by [`parse_tun_config`], [`parse_named_tun_config`],
/// [`global_route_outbound_interface`] and
/// [`named_tun_global_route_interface`] so the four can never disagree on
/// what selects global scope.
fn parse_auto_route_value(
    value: Option<&raw::RawAutoRoute>,
    default_on: bool,
    err_key: &str,
) -> Result<(bool, TunRouteMode), anyhow::Error> {
    let defaults = TunConfig::default();
    Ok(match value {
        None => (default_on, defaults.route_mode),
        Some(raw::RawAutoRoute::Enabled(on)) => (*on, defaults.route_mode),
        Some(raw::RawAutoRoute::Mode(s)) => match s.as_str() {
            "fake-ip" => (true, TunRouteMode::FakeIp),
            "global" => (true, TunRouteMode::Global),
            other => {
                return Err(anyhow::anyhow!(
                    "{err_key}: unknown value '{other}' (expected true, false, \
                     fake-ip, or global)"
                ));
            }
        },
    })
}

fn parse_auto_route(r: &raw::RawTun) -> Result<(bool, TunRouteMode), anyhow::Error> {
    parse_auto_route_value(
        r.auto_route.as_ref(),
        TunConfig::default().auto_route,
        "tun.auto-route",
    )
}

/// `tun.outbound-interface` with the empty string normalised to "unset".
fn raw_outbound_interface(r: &raw::RawTun) -> Option<String> {
    r.outbound_interface.clone().filter(|s| !s.is_empty())
}

/// Whether a `listeners:` `type: tun` entry selects global route scope,
/// and if so its configured `outbound-interface` (`Some(None)` =
/// auto-detect). `None` when the entry is absent, its `auto-route` is
/// unset/`false`/fake-IP, or it fails [`parse_named_tun_config`]'s
/// mode check.
///
/// Side-effect free, like [`global_route_outbound_interface`]: the binary
/// calls it on the raw document *before* [`build_config`] so a named
/// global-route TUN gets the same pre-first-dial outbound-interface
/// binding the top-level section does (issue #695 — the sole TUN must
/// be selected before the first bootstrap dial).
pub fn named_tun_global_route_interface(raw: &raw::RawConfig) -> Option<Option<String>> {
    let l = raw
        .listeners
        .as_deref()?
        .iter()
        .find(|l| l.listener_type.eq_ignore_ascii_case("tun"))?;
    match parse_auto_route_value(l.auto_route.as_ref(), false, "") {
        Ok((true, TunRouteMode::Global)) => {
            Some(l.outbound_interface.clone().filter(|s| !s.is_empty()))
        }
        _ => None,
    }
}

/// Whether `raw` selects an enabled TUN in global route scope, and if so
/// the configured `outbound-interface` (`Some(None)` = auto-detect).
/// `None` for a disabled TUN, fake-IP scope, `auto-route: false`, or a
/// section [`parse_tun_config`] would reject.
///
/// Side-effect free — no validation warnings — so the binary can call it
/// on the raw document *before* [`build_config`] to install the outbound
/// interface binding ahead of the first startup dial (issue #695): a
/// socket created before the binding exists stays unbound and loops into
/// the TUN once its split default routes go in. [`parse_tun_config`] stays
/// the authoritative validator and runs later in [`build_config`].
pub fn global_route_outbound_interface(raw: Option<&raw::RawTun>) -> Option<Option<String>> {
    let r = raw.filter(|r| r.enable)?;
    match parse_auto_route(r) {
        Ok((true, TunRouteMode::Global)) => Some(raw_outbound_interface(r)),
        _ => None,
    }
}

pub struct ListenerConfig {
    pub mixed_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub bind_address: String,
    pub tproxy_port: Option<u16>,
    pub tproxy_sni: bool,
    pub routing_mark: Option<u32>,
    /// `tcp-keepalive*` — the keepalive posture every inbound listener
    /// applies to its accepted sockets (see
    /// [`meow_common::TcpKeepaliveConfig`]). Engine-wide: per-listener
    /// overrides are deliberately not offered.
    pub tcp_keepalive: meow_common::TcpKeepaliveConfig,
    /// `lan-allowed-ips`/`lan-disallowed-ips` — the shared inbound TCP
    /// ACL the mixed/HTTP/SOCKS accept loops check the remote IP against
    /// (upstream's `ipfilter` gate). A startup snapshot, deliberately
    /// not hot-applied by `PATCH`/`PUT` — same lifecycle as the
    /// listener auth store it guards alongside.
    pub lan_acl: std::sync::Arc<meow_common::LanAcl>,
    /// All active listeners (shorthand + named), deduplicated and validated.
    pub named: Vec<NamedListener>,
}

/// The `external-controller-cors:` section resolved for serving (issue
/// #974) — a startup snapshot like the listener addresses: `PUT /configs`
/// commits the raw section but the live policy stays frozen until restart.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiCorsConfig {
    /// Resolved `allow-origins`: default `["*"]`; an explicit `[]` and a
    /// `*` entry both mean allow-all (weird-but-real, probe-verified).
    pub allow_origins: Vec<String>,
    /// Resolved `allow-private-network`: default `true`.
    pub allow_private_network: bool,
}

impl Default for ApiCorsConfig {
    /// Upstream's `cors.New` defaults — the same resolution an absent
    /// `external-controller-cors:` map gets under a configured secret.
    fn default() -> Self {
        Self {
            allow_origins: vec!["*".to_string()],
            allow_private_network: true,
        }
    }
}

impl ApiCorsConfig {
    /// Resolve the raw section. Under a configured secret, absent and
    /// present maps resolve identically on the `["*"]`/`true` defaults —
    /// upstream gates its permissive `AllowAll` middleware on an explicit
    /// `secret: ""`, not on the map's presence (issue #974).
    pub fn from_raw(raw: Option<&raw::RawCors>) -> Self {
        match raw {
            None => Self::default(),
            Some(cors) => Self {
                allow_origins: cors
                    .allow_origins
                    .clone()
                    .unwrap_or_else(|| vec!["*".to_string()]),
                allow_private_network: cors.allow_private_network.unwrap_or(true),
            },
        }
    }
}

pub struct ApiConfig {
    pub external_controller: Option<SocketAddr>,
    /// `external-controller-tls` — the HTTPS controller's listen address,
    /// still a string: `-t` validates shape only, and the endpoint may be
    /// a hostname resolved at bind time (issue #974).
    pub external_controller_tls: Option<String>,
    /// `external-controller-unix` — the Unix-domain socket path (relative
    /// resolves under the meow home at bind time).
    pub external_controller_unix: Option<String>,
    /// `external-controller-pipe` — the Windows named-pipe name; parsed
    /// on every platform, served only on Windows.
    pub external_controller_pipe: Option<String>,
    /// `tls.certificate` — inline PEM or path; used only with
    /// `external_controller_tls`. `None` (both absent) means the listener
    /// generates an ephemeral self-signed identity at bind, like mihomo.
    pub tls_certificate: Option<String>,
    /// `tls.private-key` — the `tls_certificate` pair.
    pub tls_private_key: Option<String>,
    /// `external-controller-cors` resolved for serving.
    pub cors: ApiCorsConfig,
    pub secret: Option<String>,
    /// Resolved directory of static files for a third-party web UI, served at
    /// `/ui` in place of the built-in panel. `None` keeps the built-in panel.
    /// Already joined with `external-ui-name` when that was set (issue #223).
    pub external_ui: Option<PathBuf>,
    /// Download URL recorded from `external-ui-url`; auto-download is not
    /// performed, but it is surfaced in a warning when the directory is absent.
    pub external_ui_url: Option<String>,
}

impl ApiConfig {
    /// Whether any controller endpoint is configured that this platform
    /// can serve — a Unix socket needs `cfg(unix)`, the named pipe needs
    /// Windows (issue #974). The `external-controller-tls` check reports
    /// *configured*, not *compiled*: meow-app's `api-tls` feature owns
    /// that gate and warns at startup when the binary lacks it.
    pub fn has_servable_endpoint(&self) -> bool {
        self.external_controller.is_some()
            || self.external_controller_tls.is_some()
            || (cfg!(unix) && self.external_controller_unix.is_some())
            || (cfg!(windows) && self.external_controller_pipe.is_some())
    }
}

/// When set, config loading validates structure only and performs no remote
/// proxy-provider / subscription fetch. `meow -t` sets it so a config that
/// references a slow or unreachable subscription still validates promptly
/// instead of blocking on the network — which is what a config *test* should
/// do, and what LuCI's pre-save `meow -t` validation needs (a hung fetch
/// exceeds rpcd's exec timeout and surfaces as "XHR request aborted by
/// browser" on Save). Process-global because `-t` is a one-shot; the flag is
/// never set on the live-serving path.
static OFFLINE_VALIDATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Enable offline (no remote fetch) config validation for this process. Call
/// before [`load_config`] in the `-t` path.
///
/// Hostname-bearing DNS upstreams are not resolved either — the built
/// resolver binds them to an unroutable `192.0.2.1` placeholder (RFC 5737
/// TEST-NET-1). The flag is never reset; a process that sets it must not
/// serve queries with the resulting resolver (it is meant to exit).
pub fn set_offline_validate(on: bool) {
    OFFLINE_VALIDATE.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// True when config loading must skip remote proxy-provider fetches (see
/// [`set_offline_validate`]).
pub fn is_offline_validate() -> bool {
    OFFLINE_VALIDATE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Upper bound, in milliseconds, on how long a config load waits for the
/// remote proxy- and rule-provider fetches that have no usable on-disk
/// cache. `u64::MAX` = wait for every fetch to finish (the default).
static PROVIDER_FETCH_DEADLINE_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

/// Bound how long a config load waits for provider downloads that have no
/// cache to fall back on. `None` (the default) waits for every fetch, as
/// mihomo does; `Some(d)` returns after `d` and lets the stragglers finish
/// in the background, where they populate their `use:` groups or `RULE-SET`
/// rules as they land. `Some(Duration::ZERO)` never waits.
///
/// For embedders that must not hold their own startup on a third-party feed
/// — a mobile VPN cannot establish its tunnel until `load_config` returns,
/// and with "block connections without VPN" the fetch cannot even succeed
/// before then. Proxy-providers and rule-providers each get the window in
/// turn (rule-provider downloads can ride proxies, so they start after
/// the proxy-providers), and runtime rebuilds (`PUT /configs`, subscription
/// applies) honour it for rule-providers too.
///
/// Providers the deadline leaves empty are retried in the background:
/// proxy-providers by [`proxy_provider::spawn_deferred_initial_fetches`],
/// rule-providers by [`rule_provider::RuleProvider::spawn_initial_fetch`]
/// (which [`rule_provider_refresh::RefreshSupervisor::reconcile`] runs).
/// Every embedder runs both after its first routing install anyway; they
/// also revalidate the cache-loaded providers. Cached providers never wait
/// on the network, whatever this is set to. Under `strict`, a remote
/// payload defect degrades to the same registered-empty-and-retry shape
/// whether it lands before or after the deadline — only local (`file:` /
/// `inline:`) payloads and document content keep the fatal verdict.
pub fn set_provider_fetch_deadline(deadline: Option<std::time::Duration>) {
    let ms = deadline.map_or(u64::MAX, |d| {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX - 1)
    });
    PROVIDER_FETCH_DEADLINE_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
}

/// The deadline set by [`set_provider_fetch_deadline`].
pub fn provider_fetch_deadline() -> Option<std::time::Duration> {
    match PROVIDER_FETCH_DEADLINE_MS.load(std::sync::atomic::Ordering::Relaxed) {
        u64::MAX => None,
        ms => Some(std::time::Duration::from_millis(ms)),
    }
}

/// Process policy for hosts accepting configurations from delegated users.
static EXTERNAL_PLUGINS_ALLOWED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

pub fn set_external_plugins_allowed(allowed: bool) {
    EXTERNAL_PLUGINS_ALLOWED.store(allowed, std::sync::atomic::Ordering::Relaxed);
}

pub fn external_plugins_allowed() -> bool {
    EXTERNAL_PLUGINS_ALLOWED.load(std::sync::atomic::Ordering::Relaxed)
}

pub async fn load_config(path: &str) -> Result<Config, anyhow::Error> {
    let raw = load_raw_config(path).await?;
    let cache_dir = resource_cache_dir_for_config_path(path);
    build_config(raw, Some(cache_dir.as_path())).await
}

/// Read and parse the config file at `path` into a [`raw::RawConfig`]
/// without building it — no network I/O. [`load_config`] is this followed
/// by [`build_config`]; the binary splits the two so it can act on the raw
/// document (the TUN global-route interface binding, issue #695) before
/// the build's provider / geodata / ECH fetches open their first socket.
pub async fn load_raw_config(path: &str) -> Result<raw::RawConfig, anyhow::Error> {
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
    parse_raw_yaml(content)
}

pub async fn load_config_from_str(content: &str) -> Result<Config, anyhow::Error> {
    let raw: raw::RawConfig = parse_raw_yaml(content)?;
    build_config(raw, None).await
}

/// Upper bound on YAML document nesting for remote-controlled documents.
/// `serde_saphyr` deserializes its targets recursively — both the
/// `serde_json::Value` ingest (`parse_yaml_value`) and the
/// `yaml_tree::SpannedNode` build (`parse_raw_yaml`) recurse one stack
/// frame per level, so a document of `[[[[…` or of ever-deepening
/// indentation can overflow a blocking-thread stack well inside the
/// fetch-size caps (issue #533 review). Two cheap over-approximations bound
/// the depth up front:
///
/// - flow nesting: unclosed `[`/`{` count. Brackets inside scalars count
///   too — a false positive needs >128 unclosed openers in one document,
///   which no real config produces.
/// - block indentation: max leading-space count. Each block nesting level
///   contributes at least one space, so depth is bounded by the widest
///   indentation; a false positive needs a single line indented past 256
///   spaces (e.g. inside a literal block scalar), which no real config
///   produces.
///
/// This stays a coarse pre-filter: the *effective* depth bound is the
/// `budget.max_depth` enforced by [`yaml_options`] inside the parser, and
/// the parse itself runs on a dedicated large-stack thread
/// (`meow_common::yaml::run_on_parse_stack`) so the budget always trips
/// before the descend can overflow whatever stack the caller had left.
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

/// Shared serde-saphyr options for every untrusted-document ingest point
/// (`parse_raw_yaml`, subscription/proxy-provider/rule-set payloads). Each
/// field pins the semantics the previous backend (serde_norway) provided:
///
/// - `strict_booleans`: only `true`/`false` spellings resolve as booleans —
///   saphyr's default would additionally read `yes/no/on/off/y/n` (YAML 1.1)
///   as bools, where norway kept them strings. Residual: saphyr still
///   case-folds `TrUe`/`nUll` — a divergence from *both* serde_norway
///   and mihomo's yaml.v3, whose resolve tables only accept the fixed
///   `true`/`True`/`TRUE`-style spellings and keep them strings.
/// - `reject_unsupported_tags`: a `!tag` node fails the document instead of
///   being silently detagged — norway errored the same way when a
///   `Value::Tagged` reached a `serde_json::Value`/struct target.
/// - `ignore_binary_tag_for_string`: a `!!binary`-tagged scalar still
///   delivers as a plain string, matching norway.
/// - `non_finite_float_policy: PassThrough`: `.inf`/`-.inf`/`.nan` map to
///   `null` inside `serde_json::Value` subtrees and to the IEEE values in
///   typed `f64` fields — norway's exact behaviour. Under `parse_raw_yaml`
///   the span tree keeps them as `YamlNode::Float`, so `Option<u16>: .inf`
///   is the same `invalid u16` the direct path reported rather than a
///   silent `None` (PR #827 review).
/// - `budget.max_depth`: both saphyr targets (`serde_json::Value` and the
///   `yaml_tree` node tree) deserialize recursively, one stack frame per
///   nesting level, so the depth bound must trip inside the parser before
///   the descend overflows — the value is `meow_common::yaml::MAX_DEPTH`
///   (32), the single definition meow-cli's config parse shares so every
///   front-end enforces the same contract.
///   The budget is only a real guard because every parse below runs on a
///   dedicated `meow_common::yaml::PARSE_STACK_SIZE` thread: on the 1 MiB
///   main thread the fatal depth measured ≈25 — *below* 32 — so an inline
///   parse let deep documents abort the process before the budget could
///   fire (migration review F1). `yaml_within_depth` stays as the cheap
///   pre-filter for absurd inputs.
/// - `merge_keys`/`duplicate_keys` stay at their defaults
///   (`Merge`/`Error`): merge expansion replaces `Value::apply_merge` with
///   identical precedence, and duplicate keys failing closed is deliberate
///   hardening over norway's silent last-wins.
///
/// Stays crate-private: backend types must never sit in a `pub` signature
/// (`serde_json::Value` is the public value namespace), so sibling modules
/// ingest through [`parse_yaml_value`] below.
///
/// Production ingest really does funnel through `parse_raw_yaml` and
/// `parse_yaml_value` only: the ~90 `serde_saphyr::from_str` call sites
/// left in this crate's `src/*.rs` all sit inside `#[cfg(test)]` modules
/// and deliberately pin *direct-path* semantics — the contract reference
/// the `yaml_tree` deserializer is held to. The single direct use outside
/// this crate is meow-cli's two-field `ConfigDoc` reader, which mirrors
/// this option profile by hand.
fn yaml_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        reject_unsupported_tags: true,
        ignore_binary_tag_for_string: true,
        non_finite_float_policy: serde_saphyr::NonFiniteFloatPolicy::PassThrough,
        budget: serde_saphyr::budget! { max_depth: meow_common::yaml::MAX_DEPTH },
    }
}

/// Shared YAML→[`serde_json::Value`] ingest under [`yaml_options`] —
/// subscription, provider and rule-set payloads all parse through this so
/// the option profile lives in exactly one place and no sibling module
/// names a backend type.
pub(crate) fn parse_yaml_value(content: &str) -> Result<serde_json::Value, anyhow::Error> {
    // Dedicated parse thread, same as `parse_raw_yaml`: the budget above
    // only guards depth while the descend's frames still fit — on a small
    // caller stack they do not (see `meow_common::yaml`).
    let value = meow_common::yaml::run_on_parse_stack(content, |doc| {
        serde_saphyr::from_str_with_options(doc, yaml_options())
    })
    .map_err(|e| anyhow::anyhow!("cannot spawn YAML parse thread: {e}"))?;
    Ok(value?)
}

/// Shared serde-saphyr serializer options for every config-emission point.
/// `folded_wrap_chars: usize::MAX` disables saphyr's default 80-column
/// `>`-folded block style: serde_norway never re-wrapped long scalars, and a
/// folded emission would be a noisy byte-level change to saved configs.
fn yaml_ser_options() -> serde_saphyr::SerializerOptions {
    serde_saphyr::ser_options! {
        folded_wrap_chars: usize::MAX,
    }
}

/// Parse a Clash/mihomo YAML document into [`raw::RawConfig`], expanding YAML
/// anchor merge keys (`<<: *anchor`) as part of deserialization.
///
/// `serde_saphyr` resolves anchors and, under the default
/// `MergeKeyPolicy::Merge`, substitutes merge keys into the surrounding
/// mapping with explicit keys taking precedence — the same expansion
/// `serde_yaml::Value::apply_merge` used to perform. Upstream mihomo
/// configs (e.g. `rule-anchor` patterns) rely on this — see meow-ios#112.
///
/// Shared YAML→[`raw::RawConfig`] entry — nesting-depth guard plus
/// merge-key expansion. Every untrusted config ingest point (config file,
/// subscription/provider payloads, and `PUT /configs`) must use this so a
/// remotely-supplied document can't bypass the depth bound or silently
/// lose merged fields (issue #648 review).
///
/// Deserialization is one pass over the `serde_saphyr` event stream: the
/// parser (still enforcing `<<:` merge expansion, `DuplicateKeyPolicy::Error`,
/// `reject_unsupported_tags`, `strict_booleans`,
/// `NonFiniteFloatPolicy::PassThrough`, and `budget.max_depth` via
/// `yaml_options`) materializes a `yaml_tree::YamlNode` tree inside
/// `yaml_tree::SpannedNode` wrappers — scalar type, document order and
/// every node's `line:column` retained — and `yaml_tree`'s compact
/// `serde::Deserializer` walks the tree into [`raw::RawConfig`]. Routing the
/// 17-struct/4-untagged-enum `RawConfig` tree through that small handwritten
/// deserializer, instead of `serde_saphyr`'s streaming
/// `deserialize_map`/`deserialize_struct` state machines monomorphized
/// across every `Raw*` type, keeps the `minimal` binary within the
/// ADR-0007 size budget — while restoring the scalar coercions
/// (`port: "7890"`, `secret: 123456`), `hosts`/`nameserver-policy` document
/// order, and `line {l} column {c}`/`field.path` diagnostics a
/// `serde_json::Value` intermediate had lost (PR #827).
pub fn parse_raw_yaml(content: &str) -> Result<raw::RawConfig, anyhow::Error> {
    if !yaml_within_depth(content) {
        return Err(anyhow::anyhow!(
            "YAML document exceeds {MAX_YAML_DEPTH} levels of nesting"
        ));
    }
    // The descend runs on a dedicated `PARSE_STACK_SIZE` thread so the
    // `budget.max_depth` above always trips before the recursion can
    // overflow — callers reach here on the 1 MiB main thread (config test,
    // startup, `--config-string`) where the fatal depth measured ≈25,
    // below the 32-level budget (migration review F1). The join is a
    // synchronous block on paths that already parsed inline — startup and
    // reload — so nothing downstream changes. See `meow_common::yaml`.
    let raw = meow_common::yaml::run_on_parse_stack(
        content,
        |doc| -> Result<raw::RawConfig, anyhow::Error> {
            let root: yaml_tree::SpannedNode =
                serde_saphyr::from_str_with_options(doc, yaml_options())?;
            yaml_tree::deserialize_config(&root, doc).map_err(Into::into)
        },
    )
    .map_err(|e| anyhow::anyhow!("cannot spawn YAML parse thread: {e}"))??;
    // Alias-conflict warnings are scoped to the document admission — this
    // parse — not to the rebuild passes it later fans out to (issue #974).
    validation::warn_store_fake_ip_alias(&raw);
    Ok(raw)
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

/// Save a RawConfig atomically and keep a best-effort .bak copy of the
/// previous regular file. On Unix, new files use owner-only permissions
/// and preserve any stricter owner permissions on existing files.
///
/// Unique scratch names keep concurrent saves from tearing, but file
/// *order* is only guaranteed when callers serialize under the
/// `CONFIG_MUTATION` lane (meow-api) — an unsynchronized pair can still
/// land an older document's rename last (issue #543).
///
/// The output is a full `RawConfig` serialization: serde-saphyr emits
/// `key: null` for every unset `Option` field that has no
/// `skip_serializing_if`, so a saved file is noisier than the
/// hand-edited original (pre-existing shape).
pub fn save_raw_config(path: &str, raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let yaml = serde_saphyr::to_string_with_options(raw, yaml_ser_options())?;
    private_file::save_config(Path::new(path), &yaml)?;
    info!("Config saved to {}", path);
    Ok(())
}

/// Async counterpart to [`save_raw_config`] for Tokio request/background paths.
/// Same ordering contract: callers persisting a committed config should hold
/// the `CONFIG_MUTATION` lane so file order follows commit order (issue #543).
pub async fn save_raw_config_async(path: &str, raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let yaml = serde_saphyr::to_string_with_options(raw, yaml_ser_options())?;
    private_file::save_config_async(Path::new(path), yaml).await?;
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

    #[cfg(unix)]
    #[test]
    fn save_config_and_backup_with_private_modes() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let backup = dir.path().join("config.yaml.bak");
        let raw = raw::RawConfig::default();

        save_raw_config(path.to_str().unwrap(), &raw).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::write(&path, "mode: rule\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        save_raw_config(path.to_str().unwrap(), &raw).unwrap();
        for file in [&path, &backup] {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read_to_string(&backup).unwrap(), "mode: rule\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn async_save_preserves_stricter_owner_permissions() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let backup = dir.path().join("config.yaml.bak");
        fs::write(&path, "mode: rule\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        fs::write(&backup, "mode: global\n").unwrap();
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();

        save_raw_config_async(path.to_str().unwrap(), &raw::RawConfig::default())
            .await
            .unwrap();
        for file in [&path, &backup] {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        assert_eq!(fs::read_to_string(&backup).unwrap(), "mode: rule\n");
    }

    #[test]
    fn concurrent_saves_publish_a_complete_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let path_str = path.to_string_lossy().into_owned();

        let a: raw::RawConfig =
            serde_saphyr::from_str("mode: rule\nlog-level: info\nrules:\n  - MATCH,DIRECT\n")
                .unwrap();
        let b: raw::RawConfig = serde_saphyr::from_str(
            "mode: global\nlog-level: debug\nipv6: true\nrules:\n  - MATCH,REJECT\n",
        )
        .unwrap();
        let ser_a = serde_saphyr::to_string_with_options(&a, yaml_ser_options()).unwrap();
        let ser_b = serde_saphyr::to_string_with_options(&b, yaml_ser_options()).unwrap();

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

    /// `nameserver-policy` key order is the lookup priority — saving must
    /// write it back in document order (the old `HashMap` wrote an
    /// arbitrary order and permanently reshuffled the file each save).
    #[test]
    fn save_preserves_nameserver_policy_key_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let raw: raw::RawConfig = serde_saphyr::from_str(
            "mode: rule\ndns:\n  nameserver-policy:\n    '+.first.example': 1.1.1.1\n    'second.example': 2.2.2.2\n    'rule-set:x': 3.3.3.3\nrules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        save_raw_config(path.to_str().unwrap(), &raw).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        let i_first = saved.find("+.first.example").unwrap();
        let i_second = saved.find("second.example").unwrap();
        let i_third = saved.find("rule-set:x").unwrap();
        assert!(
            i_first < i_second && i_second < i_third,
            "saved document must keep the policy key order:\n{saved}"
        );
        // And a reload of the saved file yields the same order.
        let reloaded: raw::RawConfig = serde_saphyr::from_str(&saved).unwrap();
        let map = reloaded.dns.unwrap().nameserver_policy.unwrap();
        let keys: Vec<&String> = map.keys().collect();
        assert_eq!(keys, ["+.first.example", "second.example", "rule-set:x"]);
    }

    /// `hosts:` key order is written back verbatim too — it decides
    /// same-slot collision winners, and the old `HashMap` reshuffled the
    /// section on every save.
    #[test]
    fn save_preserves_hosts_key_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let raw: raw::RawConfig = serde_saphyr::from_str(
            "mode: rule\nhosts:\n  '+.first.example': 1.1.1.1\n  'second.example': 2.2.2.2\n  '*.third.example': 3.3.3.3\nrules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        save_raw_config(path.to_str().unwrap(), &raw).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        let i_first = saved.find("+.first.example").unwrap();
        let i_second = saved.find("second.example").unwrap();
        let i_third = saved.find("*.third.example").unwrap();
        assert!(
            i_first < i_second && i_second < i_third,
            "saved document must keep the hosts key order:\n{saved}"
        );
        // And a reload of the saved file yields the same order.
        let reloaded: raw::RawConfig = serde_saphyr::from_str(&saved).unwrap();
        let map = reloaded.hosts.unwrap();
        let keys: Vec<&String> = map.keys().collect();
        assert_eq!(
            keys,
            ["+.first.example", "second.example", "*.third.example"]
        );
    }

    #[test]
    fn failed_save_leaves_no_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let raw: raw::RawConfig = serde_saphyr::from_str("mode: rule\n").unwrap();

        // The final rename cannot replace a directory with a file and
        // must remove its scratch.
        let bad = dir.path().join("as-dir");
        std::fs::create_dir(&bad).unwrap();
        assert!(save_raw_config(bad.to_str().unwrap(), &raw).is_err());
        assert!(bad.is_dir());
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
        let raw: raw::RawConfig = serde_saphyr::from_str("mode: rule\n").unwrap();

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
    /// The `sub-rules:` blocks this build parsed — passed through to
    /// `Tunnel::update_routing`/`reload_routing` so a listener's `rule:`
    /// override publishes in the same route snapshot as `rules`.
    pub sub_rules: sub_rules_parser::SubRuleBlocks,
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
    /// Providers this build left out leniently. The committing caller
    /// records them with the commit ([`DroppedProviders::record`]).
    pub dropped_providers: DroppedProviders,
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
        &meow_dns::new_dns_outbound_cell(),
        None,
        false,
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
    // The running config's selection-persistence owner — pass
    // `Tunnel::selection_backing()` for committed-state republishes so
    // rebuilt groups keep the user's persisted pick (issue #974);
    // SelectionBacking::unpersisted() otherwise.
    selection: &meow_proxy::SelectionBacking,
) -> Result<RebuildResult, anyhow::Error> {
    let store_selected = resolve_profile(raw).store_selected;
    selection.prepare_sync(store_selected);
    let writer = selection.attach(store_selected);
    // This lane hands in a live resolver slot but no long-lived dns
    // outbound cell — bind the slot so `type: dns` leaves built here
    // answer the same generation instead of sitting unbound (issue
    // #974; the geodata lane's proxies are never committed anyway).
    let dns_cell = meow_dns::new_dns_outbound_cell();
    *dns_cell.write() = resolver.cloned();
    rebuild_from_raw_impl(
        raw,
        cache_dir,
        resolver,
        providers,
        writer.as_ref(),
        None,
        None,
        &meow_proxy::dialer::ProxyRegistry::default(),
        &meow_proxy::dialer::ProxyRegistry::default(),
        &dns_cell,
        shared_rule_providers,
        false,
    )
}

/// Runtime rebuild variant that keeps live proxy-provider slots and the
/// process-wide selection store wired into rebuilt groups. It is the
/// live-reload path (`PUT /configs`, subscription refresh), so it also
/// downloads a GeoIP/ASN/geosite DB the candidate references but the disk
/// lacks, through the candidate's own egress, before the rules that need it
/// are parsed — call it from a blocking thread.
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
    // The running config's selection-persistence owner — the same
    // SelectionBacking startup built, so a rebuilt group keeps the user's
    // persisted pick and the PUT commit's epoch bump fences these groups'
    // writers correctly (issue #974). Pass
    // SelectionBacking::unpersisted() for embedders without a backing file.
    selection: &meow_proxy::SelectionBacking,
    // The live-resolver indirection `type: dns` leaves bind (issue #974) —
    // pass `Tunnel::dns_outbound_cell()` so leaves the candidate builds
    // resolve the same slot the running generation's leaves do.
    provider_dns_cell: &meow_dns::DnsOutboundCell,
) -> Result<RebuildResult, anyhow::Error> {
    // This lane always runs on a blocking thread (spawn_blocking in the
    // API/subscription callers), so the lazy store open is safe inline.
    let store_selected = resolve_profile(raw).store_selected;
    selection.prepare_sync(store_selected);
    let writer = selection.attach(store_selected);
    rebuild_from_raw_impl(
        raw,
        cache_dir,
        resolver,
        providers,
        writer.as_ref(),
        None,
        None,
        &meow_proxy::dialer::ProxyRegistry::default(),
        provider_dialer_registry,
        provider_dns_cell,
        None,
        true,
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
    let dns_cell = meow_dns::new_dns_outbound_cell();
    *dns_cell.write() = resolver.cloned();
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
        &dns_cell,
        None,
        false,
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
    dns_parser::validate_node_policy_sources(raw)?;
    let geo = geodata::parse_geodata(raw)?;
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
                // Never committed: these providers only back the matchers.
                .0
            }
        }
    } else {
        HashMap::new()
    };
    let bound_proxies =
        dialer_registry.map(|generation| dns_proxy::registry(proxy_registry, generation));
    let proxy_registry = bound_proxies.as_ref().unwrap_or(proxy_registry);
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

/// Prefix of the sentinel dialer target [`collect_dialer_edges`] binds to a
/// node whose `dialer-proxy` value is malformed in lenient mode. It is never
/// registered in the proxy map, so the node's dials fail loudly ("not in the
/// proxy registry", naming the node via the suffix) instead of silently
/// dialling direct — the same "node loads, dial fails" shape mihomo gives a
/// dialer name that resolves to nothing.
const MALFORMED_DIALER_PREFIX: &str = "__malformed_dialer_proxy__";

/// The `dialer-proxy` edges of one `proxies:` list, collected before any
/// leaf is built.
///
/// [`insert_parsed_leaves`] injects each edge into the *single* parse of the
/// block that declared it — the same shape provider nodes already use —
/// instead of building every node bare and re-parsing the chained ones
/// afterwards (issue #513 rework: one construction per block, so an `ss`
/// node on an external SIP003 plugin spawns its subprocess exactly once).
struct DialerEdges {
    /// `(proxy name, dialer name)` per effective declaration, in collection
    /// order — the same list the old post-build pass returned, feeding the
    /// post-build checks and [`seed_chain_owners`].
    declared: Vec<(SmolStr, SmolStr)>,
    /// `raw_proxies` index of each edge's *effective* block (the last block
    /// of a duplicated name) → its dialer name, so
    /// [`insert_parsed_leaves`]'s forward pass can tell which block carries
    /// the chain. A superseded duplicate must not get it: the registry
    /// insert is last-wins, and injecting the edge into a block that is
    /// about to be overwritten would both waste a construction (a second
    /// plugin subprocess for `ss` + external SIP003) and resurrect the
    /// earlier definition the file superseded.
    by_index: HashMap<usize, SmolStr>,
}

/// Collect proxy -> dialer edges from the raw `proxies:` list, before any
/// leaf is built.
///
/// Iterate in reverse and keep only the first sighting (the *last* block in
/// the file) per name: the registry-building loop uses `insert`, so for
/// duplicate `name:` entries the last block is the effective definition.
/// Collecting edges from superseded duplicates would apply a chain the
/// effective block never declared.
///
/// A self-referencing dialer is a hard config error in either mode — the
/// old post-build pass never warn-skipped it, and silently keeping the node
/// unchained would dial past the chain the user configured for
/// policy/security reasons (Class A, ADR-0002). A dialer cycle is a hard
/// error for the same reason: late binding would turn it into unbounded
/// recursion on the first dial. The cycle peel here runs on the *declared*
/// name graph — every member of a pure leaf chain must itself declare an
/// edge — so it needs no built adapters. Cycles *through group membership*
/// are checked separately by [`reject_group_membership_cycles`], which runs
/// after the group build where the real membership is known.
///
/// A malformed (non-string, non-null) `dialer-proxy` value rejects the whole
/// config under strict; lenient mode instead binds the node to a
/// [`MALFORMED_DIALER_PREFIX`]-prefixed sentinel target so its dials fail
/// loudly naming the node — the same "node loads, dial fails" shape mihomo
/// gives a dialer name that resolves to nothing — rather than silently
/// egressing direct.
fn collect_dialer_edges(
    raw_proxies: &[HashMap<String, serde_json::Value>],
    strict: bool,
) -> Result<DialerEdges, anyhow::Error> {
    let mut declared: Vec<(SmolStr, SmolStr)> = Vec::new();
    let mut by_index: HashMap<usize, SmolStr> = HashMap::new();
    let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (index, raw_proxy) in raw_proxies.iter().enumerate().rev() {
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
        // `type: rematch` owns no dialer — `check_rematch_node` already
        // rejected a non-blank `dialer-proxy`, so a leftover blank value
        // is unset, not malformed. Binding the sentinel here would wrap
        // the control leaf in `DialerProxyAdapter` and hide its rematch
        // action (issue #974). `type: dns` is the same shape: an
        // in-process resolver leaf owns no transport to chain, and
        // mihomo reads no `dialer-proxy` off it — skip the edge entirely
        // (`parse_dns_node` emits the ignored-key warning instead).
        if matches!(
            raw_proxy.get("type").and_then(|v| v.as_str()),
            Some("rematch") | Some("dns")
        ) {
            continue;
        }
        let dialer: SmolStr = match raw_proxy.get("dialer-proxy") {
            None => continue,
            Some(v) => match v.as_str() {
                // Trimmed like the provider-node path so
                // `dialer-proxy: " front "` resolves `front` identically
                // on statics instead of missing the `dialable` check in
                // [`apply_dialer_proxies_validate`].
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
        declared.push((SmolStr::from(name), dialer.clone()));
        by_index.insert(index, dialer);
    }
    if declared.is_empty() {
        return Ok(DialerEdges { declared, by_index });
    }

    // Peel every edge whose dialer declares no dialer of its own. What survives
    // is on a cycle or feeds one, and late binding would recurse forever on it.
    // The check only needs the declared name graph — a dialer naming a group
    // or a leaf that never declares an edge has no outgoing edge and peels
    // away — so it runs here, ahead of the leaf build, exactly as it did in
    // the old post-collection pass.
    let mut live: std::collections::HashSet<&SmolStr> = declared.iter().map(|(n, _)| n).collect();
    loop {
        let before = live.len();
        for (name, dialer) in &declared {
            if live.contains(name) && !live.contains(dialer) {
                live.remove(name);
            }
        }
        if live.is_empty() || live.len() == before {
            break;
        }
    }
    if !live.is_empty() {
        let cycle: Vec<String> = declared
            .iter()
            .filter(|(name, _)| live.contains(name))
            .map(|(name, dialer)| format!("{name} -> {dialer}"))
            .collect();
        anyhow::bail!("dialer-proxy cycle detected: {}", cycle.join(", "));
    }

    Ok(DialerEdges { declared, by_index })
}

/// The `dialer-proxy` edges `collect_dialer_edges` will actually bind
/// at build — the verbatim/validation view of the same graph, so a
/// shadowed duplicate's, a built-in-shadowing entry's or a rematch
/// node's raw `dialer-proxy` key is not judged as an edge it never
/// becomes (issue #974 review). Lenient collection: a malformed value
/// resolves to the sentinel target instead of erroring, matching the
/// lenient boot it would commit under.
pub fn declared_dialer_edges(
    raw_proxies: &[HashMap<String, serde_json::Value>],
) -> Result<Vec<(SmolStr, SmolStr)>, anyhow::Error> {
    collect_dialer_edges(raw_proxies, false).map(|edges| edges.declared)
}

/// The names whose final `proxies:` binding is a rematch leaf — the
/// verbatim/validation view of the map `insert_parsed_leaves` produces:
/// last-wins like its `proxies.insert` (a later same-name declaration
/// replaces the earlier type), and an entry named after a built-in
/// never binds at all (issue #974 review).
pub fn declared_rematch_names(
    raw_proxies: &[HashMap<String, serde_json::Value>],
) -> std::collections::HashSet<SmolStr> {
    let mut rematch = std::collections::HashSet::new();
    let mut seen = std::collections::HashSet::new();
    for node in raw_proxies.iter().rev() {
        let Some(name) = node.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if !seen.insert(name) || BUILTIN_ADAPTER_NAMES.contains(&name) {
            continue;
        }
        if node.get("type").and_then(|v| v.as_str()) == Some("rematch") {
            rematch.insert(SmolStr::from(name));
        }
    }
    rematch
}

/// The names a `proxies:` document could leave bound to a `type: dns`
/// leaf — the CONSERVATIVE view the verbatim lanes need (issue #974
/// review). A dns leaf answers queries in-process and never dials, so a
/// `dialer-proxy` front or relay hop that names one must be refused
/// exactly like a rematch target.
///
/// Unlike [`declared_rematch_names`]'s straight last-wins view this
/// cannot trust the last raw declaration: `insert_parsed_leaves` only
/// replaces a binding on a *successful* bind — a later same-named node
/// that lenient parsing warn-drops leaves an earlier dns binding
/// standing, and a verbatim lane (whose build failed by definition)
/// cannot prove a later decl binds. So ANY named dns declaration marks
/// the name unless it is built-in-shadowed — the built-in always wins,
/// the entry never binds.
pub fn declared_dns_names(
    raw_proxies: &[HashMap<String, serde_json::Value>],
) -> std::collections::HashSet<SmolStr> {
    let mut dns = std::collections::HashSet::new();
    for node in raw_proxies {
        let Some(name) = node.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if BUILTIN_ADAPTER_NAMES.contains(&name) {
            continue;
        }
        if node.get("type").and_then(|v| v.as_str()) == Some("dns") {
            dns.insert(SmolStr::from(name));
        }
    }
    dns
}

/// Validate the `dialer-proxy` edges [`collect_dialer_edges`] declared, now
/// that every leaf has been built — the check half of the old
/// `apply_dialer_proxies` pass. The chains themselves are already applied:
/// [`insert_parsed_leaves`] injected each edge into the single construction
/// it feeds, so nothing is parsed or replaced here.
///
/// Names a dialer may reference: leaf proxies are in the registry already;
/// groups are built after this pass, so only their *declared* names count
/// here, plus `GLOBAL`, which is auto-created when the config omits it. A
/// reference to a name the config does not declare is a hard config error —
/// silently falling back to a direct dial would let traffic egress from the
/// real source path past a chain the user configured for policy/security
/// reasons (Class A, ADR-0002). The caller re-validates every target again
/// against the finished registry once groups exist (a *declared* group that
/// failed to build satisfies `dialable` but never enters the registry) and
/// runs [`reject_group_membership_cycles`] on the same edges.
fn apply_dialer_proxies_validate(
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    dialer_edges: &[(SmolStr, SmolStr)],
    raw_groups: &[raw::RawProxyGroup],
) -> Result<(), anyhow::Error> {
    if dialer_edges.is_empty() {
        return Ok(());
    }
    let dialable: std::collections::HashSet<&str> = proxies
        .keys()
        .map(SmolStr::as_str)
        .chain(raw_groups.iter().map(|group| group.name.as_str()))
        .chain(std::iter::once("GLOBAL"))
        .collect();
    for (name, dialer) in dialer_edges {
        if !dialable.contains(dialer.as_str()) && !dialer.starts_with(MALFORMED_DIALER_PREFIX) {
            anyhow::bail!("proxy '{name}': dialer-proxy '{dialer}' not found");
        }
        // A statically resolvable rematch or dns leaf can never carry
        // the hop — a rematch's only action is a routing re-entry, and a
        // dns leaf answers in-process; neither dials (issue #974). Group
        // fronts resolve their pick at dial time, where the leaf's own
        // dial fails closed instead.
        if proxies.get(dialer.as_str()).is_some_and(|p| {
            matches!(
                p.adapter_type(),
                meow_common::AdapterType::Rematch | meow_common::AdapterType::Dns
            )
        }) {
            anyhow::bail!(
                "proxy '{name}': dialer-proxy '{dialer}' is a control/resolver \
                 leaf — it cannot carry a dialer front"
            );
        }
    }
    Ok(())
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
        // Rematch and dns leaves are routing controls / in-process resolver
        // endpoints, not dialable outbounds — they stay in the member list
        // (upstream `proxyList` semantics) but can never be the synthetic
        // GLOBAL selector's primary pick, on ANY path this predicate feeds:
        // the last-MATCH scan, the first-group scan, the leaf scan — the
        // picked name then becomes `default_position`, which is also the
        // selector's fallback for a saved/invalid selection (issue #974
        // review: an ordinary TCP flow must never default to a dns leaf).
        && proxies.get(name).is_some_and(|p| {
            !matches!(p.adapter_type(), AdapterType::Rematch | AdapterType::Dns)
        })
}

/// The target of the LAST top-level `MATCH,<target>` rule — the config's
/// default egress. A `MATCH` line can only appear at top level (the rule
/// parser rejects it inside logic rules and classical rule-sets; inside
/// `sub-rules:` it is a block-local terminator, not the default route), so
/// a scan of `raw.rules` is complete. Compared case-insensitively — the
/// rule parser lowercases the rule type before dispatch.
fn last_match_target(raw: &raw::RawConfig) -> Option<&str> {
    raw.rules
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
        })
}

/// Find the outbound a config is built around, preserving declaration order.
/// The final valid `MATCH` target is authoritative; otherwise prefer the first
/// successfully-built group, then the first successfully-built leaf proxy.
fn primary_global_target<'a>(
    raw: &'a raw::RawConfig,
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
) -> Option<&'a str> {
    let match_target = last_match_target(raw);
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
        .filter_map(|proxy| proxy.get("name").and_then(serde_json::Value::as_str))
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

/// Bind a node that failed to parse to a permanently-dead stand-in instead of
/// dropping it from the registry (see [`meow_proxy::UnavailableAdapter`]).
///
/// Used for the protocols where a *missing* member is worse than a broken one:
/// a `select` group, an explicit `MATCH`/rule target or a `dialer-proxy`
/// chain that names the node fails its dials instead of quietly shifting
/// that traffic to a sibling member or, once no member survives, degrading
/// to a direct dial. Liveness-checked groups (`fallback`, `url-test`,
/// `load-balance`) skip the dead entry exactly like any unavailable member —
/// the placeholder deliberately does not pin those.
/// Rejecting the enclosing `proxies:` block or provider payload closes the
/// same hole, but it also fires for a protocol the running binary simply does
/// not contain — which the operator cannot repair by editing anything — and on
/// a provider payload it hands a third party a daemon-wide kill switch.
/// `declared` keeps the node's own type in the registry, so the placeholder
/// reads as "the node you asked for, dead" rather than as a REJECT the
/// operator wrote on purpose.
pub(crate) fn unavailable_placeholder(
    name: &str,
    reason: &str,
    declared: meow_common::AdapterType,
) -> Arc<dyn Proxy> {
    Arc::new(proxy_parser::WrappedProxy::new(Box::new(
        meow_proxy::UnavailableAdapter::new(name, reason, declared),
    )))
}

/// What one `proxies:` block resolved to in [`insert_parsed_leaves`]: the
/// value to bind under the block's key, plus whether it is an unavailable
/// placeholder (which fills only a vacant slot) rather than a live adapter.
/// `None` means the block was skipped after its own warn.
type ParsedLeaf = Option<(Arc<dyn Proxy>, bool)>;

/// Parse the `dialer-proxy`-edged half of one `proxies:` block for
/// [`insert_parsed_leaves`] — a single construction attempt per parse path,
/// the same shape provider nodes already use.
///
/// First tries [`proxy_parser::parse_proxy_with_dialer`] with a late-bound
/// [`meow_proxy::dialer::NamedProxyDialer`] injected (mihomo `proxyDialer`
/// model): the adapter's own dial + handshake runs on the tunnelled stream.
/// `<name>` is bound *late* — the injected dialer keeps the name plus a
/// [`meow_proxy::dialer::ProxyRegistry`] handle and looks the front proxy up
/// on every dial — so a dialer may name a group or a node declared later in
/// the file, and nested chains need no ordering pass. A successful
/// injection is wrapped in [`proxy_parser::ChainedProxy`]: the marker is
/// what reports the configured chain to the UDP probe
/// (`is_dialer_proxy_non_transparent`, issue #969), since an injected leaf
/// carries no `DialerProxyAdapter` to answer for it.
///
/// Adapter types that do not establish their underlying connection through
/// the pluggable dialer — `direct` (resolver-threaded dials stay on the real
/// path) and `ss` with an external SIP003
/// plugin — reject the injected dialer at parse time. Those are re-parsed
/// *directly* — via [`proxy_parser::parse_static_proxy`] so the
/// `dns.direct-nameserver` slot wiring matches the unedged path — and
/// wrapped with a [`meow_proxy::DialerProxyAdapter`] (relay chain), which
/// works where `connect_over` is implemented and fails loudly at dial time
/// otherwise. The fallback never degrades to a direct dial, so a configured
/// chain cannot be silently bypassed.
///
/// When both parses fail, lenient mode keeps the old pass's verdicts by
/// looking up what the name already resolves to: a bound unavailable
/// placeholder stays unwrapped (a `DialerProxyAdapter` over a dead inner
/// is non-transparent, so its `support_udp()` is `false` and would hide
/// the placeholder's `true` guard that keeps a UDP rule from sliding to
/// DIRECT); a live earlier binding still takes the wrapper; an empty slot
/// gets the unavailable placeholder when the block is placeholder-eligible,
/// else a warn-drop.
///
/// Return contract mirrors the unedged match arm:
/// `Ok(Some((proxy, placeholder_bound)))` binds through the shared tail;
/// `Ok(None)` skips the block (a warn was already emitted); `Err` bails.
#[allow(clippy::too_many_arguments)]
fn parse_dialered_leaf(
    raw_proxy: &HashMap<String, serde_json::Value>,
    dialer: &SmolStr,
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    placeholder_names: &std::collections::HashSet<SmolStr>,
    resolver: Option<&meow_dns::ResolverSlot>,
    ipv6: bool,
    strict: bool,
    registry: &meow_proxy::dialer::ProxyRegistry,
    global_client_fingerprint: Option<&str>,
    dns_cell: &meow_dns::DnsOutboundCell,
) -> Result<ParsedLeaf, anyhow::Error> {
    // Edged blocks always carry `name:` — `collect_dialer_edges` only emits
    // an edge for a block whose name parses.
    let name = raw_proxy
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("<unnamed>");
    let key = SmolStr::from(name);
    let target = meow_proxy::dialer::DialerTarget::new(dialer.clone(), registry);
    let proxy_dialer: Arc<dyn meow_proxy::dialer::TcpDialer> =
        Arc::new(meow_proxy::dialer::NamedProxyDialer::new(target.clone()).owned_by(key.clone()));
    match proxy_parser::parse_proxy_with_dialer_and_fp(
        raw_proxy,
        &proxy_dialer,
        ipv6,
        global_client_fingerprint,
        Some(dns_cell),
    ) {
        // The `ChainedProxy` marker pins the #969 fail-closed verdict on
        // injected entries: unlike the relay-based wrapper below, an
        // injected leaf carries no `DialerProxyAdapter` to report the
        // configured chain, so the UDP probe would otherwise read it as a
        // plain `udp: false` node and slide a matched flow to a later rule.
        Ok(built) => Ok(Some((
            Arc::new(proxy_parser::ChainedProxy::new(built)) as Arc<dyn Proxy>,
            false,
        ))),
        Err(chain_err) if strict => {
            // Under `strict` the dial-time failure the relay wrapper defers
            // to is not acceptable — surface it at load, exactly as the old
            // post-build pass did.
            Err(anyhow::anyhow!(
                "proxy '{name}': cannot inject dialer-proxy '{dialer}' \
                 (strict mode): {chain_err}"
            ))
        }
        Err(chain_err) => match proxy_parser::parse_static_proxy(
            raw_proxy,
            ipv6,
            resolver,
            global_client_fingerprint,
            Some(dns_cell),
        ) {
            Ok(inner) => {
                warn!(
                    "proxy '{name}': cannot inject dialer-proxy '{dialer}' \
                     ({chain_err}); falling back to the relay-based wrapper"
                );
                let wrapped: Arc<dyn Proxy> =
                    Arc::new(meow_proxy::DialerProxyAdapter::new(inner, target));
                Ok(Some((wrapped, false)))
            }
            Err(parse_err) => {
                if let Some(existing) = proxies.get(&key) {
                    if placeholder_names.contains(&key) {
                        debug!(
                            "proxy '{name}': dialer-proxy '{dialer}' not applied; \
                             the node is an unavailable placeholder \
                             ({chain_err}); the block itself also failed to parse \
                             ({parse_err})"
                        );
                        Ok(None)
                    } else {
                        warn!(
                            "proxy '{name}': cannot inject dialer-proxy '{dialer}' \
                             ({chain_err}); the block itself also failed to parse \
                             ({parse_err}); falling back to the relay-based \
                             wrapper over the earlier same-name binding"
                        );
                        let wrapped: Arc<dyn Proxy> = Arc::new(
                            meow_proxy::DialerProxyAdapter::new(Arc::clone(existing), target),
                        );
                        Ok(Some((wrapped, false)))
                    }
                } else if let Some(declared) = proxy_parser::placeholder_adapter_type(raw_proxy) {
                    warn!(
                        "proxies: '{name}' failed to parse ({parse_err}); keeping the name bound \
                         to an unavailable node so no dial can fall back past it"
                    );
                    Ok(Some((
                        unavailable_placeholder(name, &parse_err, declared),
                        true,
                    )))
                } else {
                    warn!(
                        "proxy '{name}': dialer-proxy '{dialer}' not applied \
                         ({parse_err}); the outbound itself failed to parse"
                    );
                    Ok(None)
                }
            }
        },
    }
}

/// Parse every `proxies:` leaf entry into `proxies`, keyed by its YAML `name:`
/// (`proxy.name()` only as fallback — `DirectAdapter::name()` is hardcoded to
/// "DIRECT" and would overwrite the built-in, hiding a user-named direct proxy
/// from groups). `static_proxy_names` collects the same keys so the caller can
/// distinguish static leaves from group/provider members when modelling
/// `include-all-proxies` and membership cycles. Factored out of
/// `build_proxy_layer` so the key derivation lives in exactly one place.
///
/// `dialer_edges` maps each block index [`collect_dialer_edges`] assigned a
/// `dialer-proxy` edge to the dialer name; those blocks go through
/// [`parse_dialered_leaf`]'s single chained parse (plus direct re-parse
/// fallback) instead of the bare [`proxy_parser::parse_static_proxy`], so an
/// edged block is constructed at most once per parse path — never built
/// bare and then rebuilt for the chain. `registry` is the late-binding
/// handle the injected [`meow_proxy::dialer::NamedProxyDialer`]s keep; the
/// caller must publish the finished map into it or every injected dial
/// fails "not in the proxy registry".
///
/// Returns the names this pass bound as unavailable placeholders — edged
/// blocks consult it mid-loop to keep an already-bound placeholder
/// unwrapped, and tests reuse it for assertions.
#[allow(clippy::too_many_arguments)]
fn insert_parsed_leaves(
    proxies: &mut HashMap<SmolStr, Arc<dyn Proxy>>,
    static_proxy_names: &mut std::collections::HashSet<SmolStr>,
    raw_proxies: &[HashMap<String, serde_json::Value>],
    resolver: Option<&meow_dns::ResolverSlot>,
    ipv6: bool,
    strict: bool,
    registry: &meow_proxy::dialer::ProxyRegistry,
    dialer_edges: &HashMap<usize, SmolStr>,
    global_client_fingerprint: Option<&str>,
    dns_cell: &meow_dns::DnsOutboundCell,
) -> Result<std::collections::HashSet<SmolStr>, anyhow::Error> {
    let mut placeholder_names = std::collections::HashSet::new();
    for (index, raw_proxy) in raw_proxies.iter().enumerate() {
        let (proxy, placeholder_bound) = if let Some(dialer) = dialer_edges.get(&index) {
            match parse_dialered_leaf(
                raw_proxy,
                dialer,
                proxies,
                &placeholder_names,
                resolver,
                ipv6,
                strict,
                registry,
                global_client_fingerprint,
                dns_cell,
            )? {
                Some(bound) => bound,
                None => continue,
            }
        } else {
            match proxy_parser::parse_static_proxy(
                raw_proxy,
                ipv6,
                resolver,
                global_client_fingerprint,
                Some(dns_cell),
            ) {
                Ok(proxy) => (proxy, false),
                Err(e) if strict => {
                    let name = raw_proxy
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unnamed>");
                    return Err(anyhow::anyhow!(
                        "proxies: failed to parse '{name}' (strict mode): {e}"
                    ));
                }
                // Keep the slot entry as a dead placeholder instead of dropping
                // it: a `select` group, an explicit `MATCH` target or a
                // `dialer-proxy` chain that names the node fails the dial rather
                // than shifting the traffic to a sibling member or DIRECT —
                // the same contract the compiled-out `trusttunnel` type gets
                // (other compiled-out types stay warn-and-drop). The operator
                // cannot fix a missing protocol or a missing built-in plugin
                // transport by editing the config, so `-t`, boot, `PUT /configs`
                // and refreshes all read identically here.
                Err(e) => {
                    if let Some(declared) = proxy_parser::placeholder_adapter_type(raw_proxy) {
                        let name = raw_proxy
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("<unnamed>");
                        warn!(
                            "proxies: '{name}' failed to parse ({e}); keeping the name bound \
                         to an unavailable node so no dial can fall back past it"
                        );
                        (unavailable_placeholder(name, &e, declared), true)
                    } else {
                        warn!("Failed to parse proxy: {}", e);
                        continue;
                    }
                }
            }
        };
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
        // A repeated leaf name last-wins here — a deliberate
        // divergence from upstream's `proxy %s is the duplicate
        // name` hard error. Leaf duplicates are safe to keep: all
        // leaves settle before any group captures members, so they
        // cannot split the registry the way group duplicates did
        // (#561). Warn so a typo doesn't silently rebind (#625).
        let repeated = !static_proxy_names.insert(key.clone());
        if placeholder_bound {
            // Upstream dropped the unparseable duplicate outright, so it
            // never shadowed a same-named good entry; keep that contract
            // here — a dead placeholder fills only an empty slot and
            // leaves an earlier live binding alone.
            if let std::collections::hash_map::Entry::Vacant(slot) = proxies.entry(key.clone()) {
                slot.insert(proxy);
                placeholder_names.insert(key);
            } else if repeated {
                warn!(
                    "duplicate proxy name '{key}': the unparseable later \
                     entry leaves the earlier binding untouched"
                );
            }
        } else {
            if repeated {
                warn!("duplicate proxy name '{key}': the later entry replaces the earlier one");
            }
            // A *live* duplicate still wins over an earlier placeholder —
            // the normal insert replaces it, so unmark the name first or a
            // later same-named edged block would mistake it for a bound
            // placeholder and leave it unwrapped.
            placeholder_names.remove(&key);
            proxies.insert(key, proxy);
        }
    }
    Ok(placeholder_names)
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
///   (issue #533 review). A rebuild whose *only* change is
///   `global-client-fingerprint` — the adapters bake the profile at parse,
///   so the object cannot be reused — adopts the predecessor's last
///   committed payload into the fresh provider instead of serving an empty
///   slot until the detached post-commit fetch lands (issue #974 review).
/// - A newly declared def constructs an empty [`ProxyProvider`]. A `file:`
///   provider's payload is operator-authored local content, so it is read
///   and parsed right here — local I/O only, and the ECH DNS preresolve
///   runs in `Defer` mode so no lookup can serialize the lane (the same
///   discipline `apply_raw_to_tunnel` keeps, issue #533 review); a strict
///   payload defect fails the candidate before commit, the same verdict
///   boot gives it. `Ok(false)` — a read failure or a lenient
///   whole-payload failure — still registers the provider empty; the
///   committing caller then spawns a detached first acquisition that
///   retries the read — a stronger retry than boot, which leaves a failed
///   first read to the interval/manual refresh, deliberately: the commit
///   knows the provider is new — and finishes the deferred preresolve
///   off-lane so the nodes a `file:` provider serves match a boot load.
///   Remote (`http:`) payloads keep the detached-fetch contract: no fetch
///   runs on this path, so a slow or blackholed provider URL cannot hold
///   the config mutation lane, and a malformed remote payload degrades
///   (empty + retry) instead of rejecting.
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
    // The live-resolver indirection `type: dns` leaves bind (issue #974):
    // shared into every provider this call constructs so a node parsed
    // from a payload — before DNS exists, or on a refresh long after —
    // resolves the same slot the commit populates.
    provider_dns_cell: &meow_dns::DnsOutboundCell,
    dropped: &mut DroppedProviders,
) -> Result<HashMap<String, Arc<ProxyProvider>>, anyhow::Error> {
    let Some(raw_map) = raw.proxy_providers.as_ref() else {
        return Ok(HashMap::new());
    };
    let ipv6 = effective_ipv6(raw.ipv6);
    let global_fp = raw.global_client_fingerprint.as_deref();
    let mut out = HashMap::with_capacity(raw_map.len());
    for (name, def) in raw_map {
        let mut inherited: Option<String> = None;
        if let Some(provider) = live.get(name) {
            if provider.matches_def(def, ipv6, global_fp) {
                out.insert(name.clone(), Arc::clone(provider));
                continue;
            }
            // A rebuild that fails `matches_def` on the fingerprint leg
            // alone inherits the predecessor's last committed payload —
            // re-parsed under the new `global-client-fingerprint` — so
            // `use:` groups and provider-backed selectors never see the
            // empty slot a `--config-string` run (no on-disk cache) would
            // otherwise serve until the detached post-commit fetch lands
            // (issue #974 review). `None` when nothing was ever committed:
            // the provider starts empty and retries, same as today.
            if provider.matches_def_modulo_fingerprint(def, ipv6) {
                inherited = provider.retained_payload();
            }
        }
        match ProxyProvider::new_with_client_fingerprint(
            name,
            def,
            cache_dir,
            ipv6,
            strict,
            provider_dialer_registry.clone(),
            global_fp,
            Some(Arc::clone(provider_dns_cell)),
        ) {
            Ok(provider) => {
                // A new `file:` provider's payload is local content —
                // validate it now so a strict candidate cannot commit a
                // payload the next boot would refuse (PUT /configs → 400
                // leaving live state untouched). The load stays
                // network-free on this lane — the ECH preresolve is
                // deferred to the committed provider's detached first
                // fetch. `Ok(false)` — unreadable file, or a lenient
                // whole-payload failure — registers the provider empty;
                // the commit's detached acquisition retries the read.
                // Reused providers above are never reloaded; remote
                // providers never load on this path.
                if provider.is_file_vehicle() {
                    provider.initial_load_blocking(strict)?;
                } else if let Some(content) = inherited {
                    // Remote bytes degrade rather than reject — the same
                    // payload parsed under the old fingerprint, so a
                    // re-parse the new one rejects (e.g. a REALITY node
                    // left without a profile) is a feed defect, not a
                    // config defect: the commit's detached fetch retries.
                    if let Err(e) = provider.adopt_transferred_payload(content) {
                        warn!(provider = %name, error = %e,
                            "inherited proxy-provider payload failed to re-parse under \
                             the new client fingerprint; starting empty until a fetch succeeds");
                    }
                }
                out.insert(name.clone(), Arc::new(provider));
            }
            Err(e) if strict => {
                return Err(anyhow::anyhow!(
                    "proxy-provider '{name}' failed to load (strict mode): {e}"
                ));
            }
            Err(e) => {
                warn!("failed to create proxy-provider '{name}': {e}");
                dropped.proxy(name, e);
            }
        }
    }
    Ok(out)
}

/// The registry map one `build_proxy_layer` produces plus the names it
/// bound to unavailable placeholders — [`check_ntp_dialer_target`] needs
/// the set: `contains_key` alone cannot tell a placeholder (every dial
/// fails) from a live leaf.
type BuiltProxyLayer = (
    HashMap<SmolStr, Arc<dyn Proxy>>,
    std::collections::HashSet<SmolStr>,
);

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
    selection: Option<&meow_proxy::SelectorWriter>,
    registry: &meow_proxy::dialer::ProxyRegistry,
    // The live-resolver indirection static `type: dns` leaves bind
    // (issue #974) — the same handle the provider set carries, so both
    // node origins resolve one slot.
    dns_cell: &meow_dns::DnsOutboundCell,
    strict: bool,
) -> Result<BuiltProxyLayer, anyhow::Error> {
    let ipv6 = effective_ipv6(raw.ipv6);
    let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
    let mut static_proxy_names = std::collections::HashSet::new();
    // `tcp-connect-timeout` seconds feed `tokio::time::timeout` per dial —
    // an absurd u64 overflows `Instant + Duration` and aborts the process
    // (issue #648). Checked here, in the Result-returning scope, because the
    // `make_direct` closure cannot propagate.
    if let Some(secs) = raw.tcp_connect_timeout {
        anyhow::ensure!(
            secs <= meow_common::MAX_DURATION_SECS,
            "tcp-connect-timeout: {secs}s exceeds the {}s ceiling",
            meow_common::MAX_DURATION_SECS
        );
    }
    // Built-in proxies — upstream registers DIRECT, REJECT, REJECT-DROP,
    // COMPATIBLE, PASS, PASS-RULE (`config.go` ~line 891).
    let make_direct = |compatible: bool| {
        let mut direct = if compatible {
            meow_proxy::DirectAdapter::compatible()
        } else {
            meow_proxy::DirectAdapter::new()
        };
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

    // Collect `dialer-proxy` edges (issue #210) *before* any leaf is built:
    // the raw-name, self-reference, malformed-value and declared-cycle checks
    // all run on the declared name graph, so they need no adapters. The
    // collected edges then steer [`insert_parsed_leaves`]'s single chained
    // parse — the same shape provider nodes already use — instead of the old
    // build-bare-then-re-parse pass, whose double construction could spawn an
    // `ss` node's external SIP003 subprocess twice.
    let raw_proxies = raw.proxies.as_deref().unwrap_or(&[]);
    // A malformed `type: rematch` action fails the whole load in either
    // mode — warn-dropping it would silently remove the flow's first
    // routing decision (issue #974). Run the structural gate before the
    // leaf pass so `-t`, boot, PUT and provider-less rebuilds agree.
    // `type: dns` gets the same treatment: a nameless node parses away to
    // nothing under leniency, so a `PUT /configs?force=true` retry could
    // otherwise commit a document the verbatim gate — and the next
    // boot — would reject (issue #974 review).
    for raw_proxy in raw_proxies {
        match raw_proxy.get("type").and_then(|v| v.as_str()) {
            Some("rematch") => {
                if let Err(e) = proxy_parser::check_rematch_node(raw_proxy) {
                    anyhow::bail!("proxies: {e}");
                }
            }
            Some("dns") => {
                if let Err(e) = proxy_parser::check_dns_node(raw_proxy) {
                    anyhow::bail!("proxies: {e}");
                }
            }
            _ => {}
        }
    }
    let dialer_edges = collect_dialer_edges(raw_proxies, strict)?;

    // `global-client-fingerprint` (issue #974) is normalized once per
    // build and baked into each adapter that inherits it — config-threaded,
    // not a runtime global, so a `PUT /configs` flip rebuilds cleanly.
    let global_fp =
        proxy_parser::normalize_client_fingerprint(raw.global_client_fingerprint.as_deref());
    let placeholder_names = insert_parsed_leaves(
        &mut proxies,
        &mut static_proxy_names,
        raw_proxies,
        resolver,
        ipv6,
        strict,
        registry,
        &dialer_edges.by_index,
        global_fp.as_deref(),
        dns_cell,
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
        // `interval` (seconds) reaches `tokio::time::interval` in the
        // health-check supervisor — an absurd u64 overflows
        // `Instant + Duration` and, with `panic = "abort"`, kills the
        // process. Subscription-controlled groups reach the same path
        // (issue #648).
        anyhow::ensure!(
            group.interval.unwrap_or(0) <= meow_common::MAX_DURATION_SECS,
            "proxy group '{}': interval exceeds the {}s ceiling",
            group.name,
            meow_common::MAX_DURATION_SECS
        );
        anyhow::ensure!(
            seen_group_names.insert(group.name.as_str()),
            "proxy group '{}': the duplicate name — declared more than once",
            group.name
        );
    }

    reject_declared_group_cycles(raw_groups)?;

    // Validate the `dialer-proxy` targets now that every leaf is built: the
    // static contract accepts leaf names, *declared* group names and
    // `GLOBAL`, and the post-build recheck below narrows that to what
    // actually landed. The chains themselves are already applied by the
    // leaf pass — groups built afterwards clone the finished (chained or
    // wrapped) members eagerly, which is what keeps a grouped node from
    // bypassing its chain (issue #513).
    apply_dialer_proxies_validate(&proxies, &dialer_edges.declared, raw_groups)?;

    // Mihomo expands `include-all-proxies` from the top-level `proxies:`
    // entries only. Capture those adapters after dialer chaining but before
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

    // A statically known `type: rematch` or `type: dns` hop can never
    // carry a relay chain — rematch's only action is a routing re-entry
    // and a dns leaf answers in-process; neither dials a transport hop
    // (issue #974: "Rematch is not a meow relay transport hop; reject
    // statically known uses"). Both static memberships a relay can have
    // — a declared `proxies:` name resolving to the leaf, and the
    // `include-all-proxies` expansion — are checked here so the verdict
    // is a hard error in both build modes, ahead of the lenient group
    // passes that would warn-drop it. `parse_relay_group` repeats the
    // member-vec check for its own callers. A *group* member's dynamic
    // rematch pick is the probe's business instead:
    // `RelayGroup::unwrap_proxy` surfaces it and the cycle guard closes
    // the loop.
    let is_non_transport_leaf =
        |p: &Arc<dyn Proxy>| p.rematch_action().is_some() || p.adapter_type() == AdapterType::Dns;
    for group in raw_groups {
        if group.group_type != "relay" {
            continue;
        }
        for member in group.proxies.as_deref().unwrap_or(&[]) {
            if proxies
                .get(member.as_str())
                .is_some_and(&is_non_transport_leaf)
            {
                anyhow::bail!(
                    "relay group '{}': member '{member}' is a control/resolver \
                     leaf — it cannot be a relay transport hop",
                    group.name
                );
            }
        }
        if group.include_all_proxies.unwrap_or(false) {
            if let Some(hop) = include_all_proxies
                .iter()
                .find(|p| is_non_transport_leaf(p))
            {
                anyhow::bail!(
                    "relay group '{}': include-all-proxies supplies control/resolver \
                     leaf '{}' — it cannot be a relay transport hop",
                    group.name,
                    hop.name()
                );
            }
        }
    }

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
                selection,
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
                    selection,
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
                selection,
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
                    selection,
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
        // The member at index 0 is the selector's default pick: the
        // primary when it resolves, else the first non-control member —
        // a sorted-first rematch or dns leaf answers no ordinary flow
        // and can never be a dialable default (issue #974 review).
        let default_position = match primary.as_deref() {
            Some(primary) => all_proxy_names.iter().position(|name| name == primary),
            None => all_proxy_names.iter().position(|name| {
                proxies.get(name.as_str()).is_some_and(|p| {
                    !matches!(p.adapter_type(), AdapterType::Rematch | AdapterType::Dns)
                })
            }),
        };
        if let Some(position) = default_position {
            let name = all_proxy_names.remove(position);
            all_proxy_names.insert(0, name);
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
            selection,
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
    for (name, dialer) in &dialer_edges.declared {
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
        &dialer_edges.declared,
        raw_groups,
        &proxies,
        &static_proxy_names,
        global_auto_created,
    )?;

    seed_chain_owners(&dialer_edges.declared, &proxies);

    Ok((proxies, placeholder_names))
}

/// Tell each automatic group used as a `dialer-proxy` which outbounds dial
/// which server through it, so the group's first health check already
/// probes those chains (see [`meow_common::chain_health`]). Groups also
/// learn this from the dials themselves; seeding only makes it earlier.
///
/// Outbounds on the relay-based `DialerProxyAdapter` fallback are left out:
/// their front hop picks a member without the chain verdicts, so probing
/// for them would cost probes and change nothing.
fn seed_chain_owners(
    dialer_edges: &[(SmolStr, SmolStr)],
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
) {
    for (name, dialer) in dialer_edges {
        let (Some(owner), Some(front)) = (proxies.get(name), proxies.get(dialer)) else {
            continue;
        };
        if owner
            .as_any()
            .is_some_and(<dyn std::any::Any>::is::<meow_proxy::DialerProxyAdapter>)
        {
            continue;
        }
        let Some(chain) = front.chain_health() else {
            continue;
        };
        if let Some(target) = meow_common::ChainTarget::from_server_addr(owner.addr()) {
            chain.note_owner(&target, name);
        }
    }
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
    selection: Option<&meow_proxy::SelectorWriter>,
    // The cell provider-sourced nodes' `dialer-proxy` targets resolve
    // against — the same handle the providers were loaded with. The
    // layer's own `registry` covers static `proxies:` chains only, so
    // without publishing here a provider node's front hop resolves to
    // nothing during the prefetch window (issue #974 review).
    provider_dialer_registry: &meow_proxy::dialer::ProxyRegistry,
    // The same dns-outbound cell the real build binds — prefetch dns
    // leaves behave identically to the runtime map's (issue #974).
    provider_dns_cell: &meow_dns::DnsOutboundCell,
) -> Result<Option<PrefetchProxies>, anyhow::Error> {
    // No `proxies:` and no `proxy-groups:` means nothing to tunnel
    // through — named `proxy:` lookups and the default proxy all come
    // back empty either way, and provider `proxy:` names defer to the
    // load pass, which resolves them against the pass-1 registry. Groups
    // alone still justify the layer: a provider-fed group can be a
    // `geodata.proxy`/provider `proxy:` target, and one selecting a
    // provider's rematch leaf must fail the fetch loudly instead of
    // leaking it direct (issue #974).
    if raw.proxies.as_deref().unwrap_or(&[]).is_empty()
        && raw.proxy_groups.as_deref().unwrap_or(&[]).is_empty()
    {
        return Ok(None);
    }
    let registry = meow_proxy::dialer::ProxyRegistry::default();
    // A rejected layer (bad chain, group-declaration or membership
    // cycle) hard-fails the real build with the same error; surface it
    // now instead of letting default-proxy provider/geodata fetches
    // egress direct on a config that intends chained egress.
    let (map, _) = build_proxy_layer(
        raw,
        None,
        providers,
        selection,
        &registry,
        provider_dns_cell,
        raw.strict.unwrap_or(false),
    )?;
    registry.publish(Arc::new(map.clone()));
    // The same snapshot into the provider-node cell: their front hops
    // resolve against it until the first routing install publishes the
    // live map over it.
    provider_dialer_registry.publish(Arc::new(map.clone()));
    Ok(Some(PrefetchProxies {
        map,
        _registry: registry,
    }))
}

/// Build the prefetch proxy layer on a blocking thread — adapter and group
/// construction can spawn plugin subprocesses and read TLS material, so it
/// must not run inline on the async executor. `selection` is threaded
/// in so a `select` group's persisted choice resolves to the same member
/// the runtime build would pick. A rejected layer or a failed build task
/// surfaces as `Err` — the same failure pass 1 of the real build reports.
async fn prefetch_proxy_layer_async(
    raw: &raw::RawConfig,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    selection: Option<&meow_proxy::SelectorWriter>,
    provider_dialer_registry: &meow_proxy::dialer::ProxyRegistry,
    provider_dns_cell: &meow_dns::DnsOutboundCell,
) -> Result<Option<Arc<PrefetchProxies>>, anyhow::Error> {
    let raw = raw.clone();
    let providers = providers.clone();
    let selection = selection.cloned();
    let provider_dialer_registry = provider_dialer_registry.clone();
    let provider_dns_cell = Arc::clone(provider_dns_cell);
    spawn_blocking_with_current_dispatcher(move || {
        prefetch_proxy_map(
            &raw,
            &providers,
            selection.as_ref(),
            &provider_dialer_registry,
            &provider_dns_cell,
        )
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
    selection: Option<&meow_proxy::SelectorWriter>,
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
    // The live-resolver indirection `type: dns` leaves bind (issue #974) —
    // same lifetime contract as `provider_dialer_registry`: committing
    // lanes pass `Tunnel::dns_outbound_cell()` so leaves parsed here and
    // by providers resolve the running slot; a throwaway leaves them
    // unbound (SERVFAIL, never a guessed upstream).
    provider_dns_cell: &meow_dns::DnsOutboundCell,
    // An already-loaded provider set to bind into this build (startup's
    // two-pass build shares the set it loaded for DNS so rules, DNS
    // `rule-set:` matchers, and `Config.rule_providers` all reference one
    // object per provider). `None` = parse `raw.rule_providers` fresh.
    shared_providers: Option<HashMap<String, Arc<rule_provider::RuleProvider>>>,
    // Download geodata the candidate references but the disk lacks before
    // the parser context needs it — set by the live-reload path only
    // (`rebuild_from_raw_runtime`); startup ensures it in `build_config`,
    // and validation/test rebuilds must not reach the network.
    fetch_geodata: bool,
) -> Result<RebuildResult, anyhow::Error> {
    // `global-ua` gate first: an invalid UA is a Class A rejection for
    // every candidate — validate only; the live process-global is
    // installed at the commit point (issue #974). The validated value is
    // also the UA this build's own HTTP emits send: `GLOBAL_UA` still
    // holds the committed value on this lane, so the rule-provider
    // prefetch below is handed the candidate's UA explicitly instead of
    // reading the static (issue #974 review). `None` resolves to the
    // default UA, the same effective value the static would give.
    let candidate_ua =
        validate_global_ua(raw.global_ua.as_deref())?.unwrap_or(meow_common::DEFAULT_USER_AGENT);
    // `ntp:` shape/ranges resolve before any candidate network work —
    // disabled included: `-t` and PUT reject an out-of-range endpoint
    // regardless of `enable` (issue #974). The named-target reference is
    // checked against the built map below.
    let ntp_resolved = resolve_ntp(raw)?;
    dns_parser::validate_node_policy_sources(raw)?;
    // Warn-only unknown-key reporting (issue #974): classify-and-warn every
    // key the typed schema dropped. Runs on every rebuild pass — startup's
    // `-t`/load passes and `PUT`/`PATCH /configs` rebuilds all re-emit.
    validation::validate_and_warn(raw);
    // Top-level `strict: true` (issue #533): warn-skipped defects in
    // *operator-authored* content become hard errors — proxies,
    // proxy-groups and rules are covered inside
    // `build_proxy_layer`/`parse_rules_full`; provider definitions, and
    // `file:`/`inline:` provider payloads, are gated at their load sites
    // (a `file:` proxy-provider's payload is validated in
    // `materialize_proxy_providers`, the rule-provider loads are sync).
    // Remote payload bytes — http provider/subscription GETs and their
    // on-disk caches — are third-party content: under strict they degrade
    // to registered-empty + background retry instead of failing the
    // build, so a remote feed cannot veto the daemon (Option C origin
    // split).
    let strict = raw.strict.unwrap_or(false);

    // Subscription names key the `applied-*` contribution tracking (issue
    // #640): two entries sharing a name would split ownership bookkeeping —
    // an apply via one entry would credit the other's tracked set. Reject
    // duplicates the same way groups and listeners do.
    let mut seen_subscription_names: std::collections::HashSet<&str> =
        std::collections::HashSet::with_capacity(
            raw.subscriptions.as_deref().map_or(0, <[_]>::len),
        );
    for s in raw.subscriptions.as_deref().unwrap_or(&[]) {
        anyhow::ensure!(
            seen_subscription_names.insert(s.name.as_str()),
            "subscription '{}': the duplicate name — declared more than once",
            s.name
        );
    }

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
    let mut dropped = DroppedProviders::default();
    let candidate_providers = materialize_proxy_providers(
        raw,
        providers,
        cache_dir,
        strict,
        provider_dialer_registry,
        provider_dns_cell,
        &mut dropped,
    )?;
    let (proxies, placeholder_names) = build_proxy_layer(
        raw,
        resolver,
        &candidate_providers,
        selection,
        registry,
        provider_dns_cell,
        strict,
    )?;
    // An enabled `ntp.dialer-proxy` must name a BUILT target — checked
    // here so every publication lane (startup, `-t`, PUT, warm republish)
    // enforces it the same way, and removing a target together with its
    // reference in one document stays legal (issue #974).
    check_ntp_dialer_target(&ntp_resolved, &proxies, &placeholder_names)?;

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
    // A name that DOES resolve but lands on a `type: rematch`/`type: dns`
    // leaf is the opposite verdict — the same statically resolvable
    // control/resolver leaf `apply_dialer_proxies_validate` rejects on a
    // static edge; provider fronts bind late, so judge them here, against
    // the finished map, before they can commit (issue #974 review).
    for provider in candidate_providers.values() {
        for dialer in provider.declared_dialer_names() {
            match proxies.get(dialer.as_str()) {
                Some(target)
                    if matches!(
                        target.adapter_type(),
                        AdapterType::Rematch | AdapterType::Dns
                    ) =>
                {
                    anyhow::bail!(
                        "proxy-provider '{}': dialer-proxy '{dialer}' is a \
                         control/resolver leaf — it cannot carry a dialer front",
                        provider.name
                    );
                }
                None => {
                    warn!(
                        provider = %provider.name,
                        "provider node declares dialer-proxy '{dialer}', which is \
                         not a built proxy or group — chained dials will fail"
                    );
                }
                _ => {}
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
        None if shared_providers.is_some() => Arc::default(),
        None => Arc::new(match raw.rule_providers.as_ref() {
            Some(map) if !map.is_empty() => rule_provider::prefetch_payloads(
                map,
                cache_dir,
                download_proxy.as_ref(),
                &proxy_lookup,
                Some(candidate_ua),
            ),
            _ => rule_provider::PrefetchedPayloads::default(),
        }),
    };

    let owned_ctx;
    let ctx = match shared_ctx {
        Some(c) => c,
        None => {
            let geo = geodata::parse_geodata(raw)?;
            if fetch_geodata {
                ensure_geodata_blocking(
                    raw,
                    &geo,
                    &collect_geo_scan_lines(raw, &payloads),
                    &proxies,
                    &chained_provider_names(&candidate_providers),
                );
            }
            owned_ctx = build_parser_context_with_geo(raw, &geo, &payloads)?;
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
                &mut dropped,
            )?,
            _ => HashMap::new(),
        },
    };
    let ruleset_map = rule_provider::live_ruleset_map(&rule_providers);

    // Parse sub-rules before top-level rules so that SUB-RULE entries in
    // `rules:` can resolve against already-built blocks.
    let sub_rules = match raw.sub_rules.as_ref() {
        Some(map) if !map.is_empty() => {
            sub_rules_parser::parse_sub_rules(map, &ruleset_map, ctx, strict)?
        }
        _ => HashMap::new(),
    };

    let rules = rule_parser::parse_rules_full(
        raw.rules.as_deref().unwrap_or(&[]),
        &ruleset_map,
        ctx,
        &sub_rules,
        strict,
    )?;

    // Validate: any `SUB-RULE` reference in top-level rules must point at a
    // defined block — plain, conditional or fallback form alike (issue
    // #974). `parse_rules_full` warns on unknown blocks; promote
    // undefined-block to a hard error here (Class A per ADR-0002). Only a
    // well-formed reference head counts: a malformed one fails at the
    // parse stage, so skipping it here leaves exactly one error channel.
    if let Some(raw_rules) = raw.rules.as_deref() {
        for line in raw_rules {
            if let Ok(Some(reference)) = sub_rules_parser::parse_sub_rule_reference(line) {
                if !sub_rules.contains_key(&reference.name) {
                    return Err(anyhow::anyhow!(
                        "rules: SUB-RULE,{} references undefined sub-rule block",
                        reference.name
                    ));
                }
            }
        }
    }

    // A rematch node's `target-sub-rule` names a block by reference only —
    // like `SUB-RULE` references, a miss falls back to the main rule list
    // at match time, so warn once here rather than failing (issue #974).
    if let Some(raw_proxies) = raw.proxies.as_deref() {
        for node in raw_proxies {
            if node.get("type").and_then(|v| v.as_str()) != Some("rematch") {
                continue;
            }
            let Some(block) = node.get("target-sub-rule").and_then(|v| v.as_str()) else {
                continue;
            };
            if !block.is_empty() && !sub_rules.contains_key(block) {
                warn!(
                    "rematch '{}': target-sub-rule '{block}' is not a declared \
                     sub-rules block — flows selecting it fall back to the main rules",
                    node.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unnamed>")
                );
            }
        }
    }

    // `listeners[].proxy` forced targets resolve against this same map —
    // validating here makes `-t`, startup and every rebuild-driven
    // mutation reject the same dangling name identically.
    validate_listener_proxy_targets(raw, &proxies, &candidate_providers)?;

    // The provider set is returned, not swapped: the committing caller
    // publishes it into the live registry only after every fallible check
    // has passed, so a rejected candidate never leaves its fetch contexts
    // (and their pinned dialer cell) live (issue #533 review).
    Ok(RebuildResult {
        proxies,
        rules,
        sub_rules,
        dialer_registry: registry.clone(),
        rule_providers,
        proxy_providers: candidate_providers,
        dropped_providers: dropped,
        prefetched_payloads: payloads,
    })
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
        return rule_provider::PrefetchedPayloads::default();
    };
    let raw_providers = raw_providers.clone();
    let raw_proxies: Vec<HashMap<String, serde_json::Value>> =
        raw.proxies.clone().unwrap_or_default();
    // The startup `global-ua` (`build_config` already validated it, and
    // installs it before this prefetch runs) — threaded explicitly so the
    // downloads never depend on when the static was installed (issue #974
    // review).
    let user_agent = validate_global_ua(raw.global_ua.as_deref())
        .ok()
        .flatten()
        .unwrap_or(meow_common::DEFAULT_USER_AGENT)
        .to_string();
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
            Some(&user_agent),
        )
    })
    .await
    .unwrap_or_else(|e| {
        warn!("rule-provider payload prefetch task failed: {e}");
        rule_provider::PrefetchedPayloads::default()
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
    selection: Option<meow_proxy::SelectorWriter>,
    ctx: meow_rules::ParserContext,
    provider_payloads: Arc<rule_provider::PrefetchedPayloads>,
    // Caller's registry cell — shared across a multi-pass build so pass-1
    // adapters retained elsewhere (DNS `#PROXY` handles, provider fetch
    // contexts) resolve the latest published snapshot (issue #533).
    registry: meow_proxy::dialer::ProxyRegistry,
    // The live provider-dialer cell newly declared providers share
    // (issue #489) — see `rebuild_from_raw_impl`.
    provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
    // The live-resolver indirection `type: dns` leaves bind (issue #974) —
    // see `rebuild_from_raw_impl`.
    provider_dns_cell: meow_dns::DnsOutboundCell,
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
            selection.as_ref(),
            Some(&ctx),
            Some(provider_payloads),
            &registry,
            &provider_dialer_registry,
            &provider_dns_cell,
            shared_providers,
            false,
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
) -> Result<
    (
        HashMap<String, Arc<rule_provider::RuleProvider>>,
        DroppedProviders,
    ),
    anyhow::Error,
> {
    spawn_blocking_with_current_dispatcher(move || {
        let lookup = |name: &str| proxies.get(name).cloned();
        let mut dropped = DroppedProviders::default();
        rule_provider::load_providers_prefetched(
            &raw_providers,
            cache_dir.as_deref(),
            &ctx,
            download_proxy.as_ref(),
            &lookup,
            &provider_payloads,
            dialer_registry.as_ref(),
            strict,
            &mut dropped,
        )
        .map(|providers| (providers, dropped))
    })
    .await
    .map_err(|e| anyhow::anyhow!("rule-provider load task failed: {e}"))?
}

/// The `sniffer:` block of a raw config (a TUN rebuilt on an API config
/// change needs it).
pub fn sniffer_config_from_raw(raw: &raw::RawConfig) -> Result<SnifferConfig, anyhow::Error> {
    parse_sniffer_config(raw, raw.strict.unwrap_or(false))
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
            let mut quic_ports: Vec<u16> = Vec::new();
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
                            // Upstream's default port for QUIC.
                            quic_ports = proto.ports.clone().unwrap_or_else(|| vec![443]);
                        }
                        // An unrecognized key is a typo'd/dead declaration —
                        // a defect under strict (issue #533 review).
                        other if strict => {
                            anyhow::bail!(
                                "sniffer.sniff.{other}: unknown protocol (strict mode); \
                                 supported: TLS, HTTP, QUIC"
                            );
                        }
                        other => {
                            warn!("sniffer.sniff.{}: unknown protocol, ignoring", other);
                        }
                    }
                }
                if enable && tls_ports.is_empty() && http_ports.is_empty() && quic_ports.is_empty()
                {
                    anyhow::bail!(
                        "sniffer.sniff is present and enable: true, but no ports are configured \
                        for any supported protocol (TLS/HTTP/QUIC)"
                    );
                }
            } else if enable {
                anyhow::bail!("sniffer.enable is true but sniffer.sniff map is absent or empty");
            }

            // skip-domain / force-domain feed `DomainTrie`s in the sniffer
            // runtime; a dead key — an empty label that can never match a
            // query name, or an all-dots/prefix-only body the runtime's
            // insert silently refuses — is the same dead-key shape as
            // `hosts:` (issue #822). Surface it rather than swallow it.
            for (field, list) in [
                ("sniffer.skip-domain", &rs.skip_domain),
                ("sniffer.force-domain", &rs.force_domain),
            ] {
                for s in list.iter().flatten() {
                    crate::dns_parser::check_domain_key(field, s, strict)?;
                }
            }

            // Canonical order for the semantic `SnifferConfig` diff the
            // TUN reconcile runs on a config change: the runtime dedups
            // every list into a `HashMap`/`DomainTrie` anyway, so
            // `[443, 8443]` and `[8443, 443]` are the same config — sort
            // + dedup keeps a port-or-domain respelling from restarting
            // the listener (review #887).
            for ports in [&mut tls_ports, &mut http_ports, &mut quic_ports] {
                ports.sort_unstable();
                ports.dedup();
            }
            let normalize_domains = |list: &Option<Vec<String>>| {
                let mut v: Vec<SmolStr> = list
                    .iter()
                    .flatten()
                    .map(|s| SmolStr::from(s.as_str()))
                    .collect();
                v.sort_unstable();
                v.dedup();
                v
            };

            Ok(SnifferConfig {
                enable,
                timeout: std::time::Duration::from_millis(timeout_ms),
                parse_pure_ip: rs.parse_pure_ip.unwrap_or(true),
                override_destination: rs.override_destination.unwrap_or(false),
                tls_ports,
                http_ports,
                quic_ports,
                skip_domain: normalize_domains(&rs.skip_domain),
                force_domain: normalize_domains(&rs.force_domain),
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
                quic_ports: Vec::new(),
                skip_domain: Vec::new(),
                force_domain: Vec::new(),
            })
        }
        None => Ok(SnifferConfig::default()),
    }
}

/// Which geodata databases this config actually references — the union of
/// the rule-line scan (`GEOIP`/`SRC-GEOIP`, `IP-ASN`/`SRC-IP-ASN`,
/// `GEOSITE`, including logic-rule and provider-payload occurrences) and
/// the DNS-side consumers (`geosite:` nameserver-policy keys, the
/// fallback-filter geoip gate).
///
/// Shared by `missing_geodata_downloads` (startup fetch gating) and the
/// geodata auto-update tick, so "is this DB referenced" is one judgment —
/// the tick's `GeoDataNeeds` snapshot and the startup download list can
/// never drift apart.
#[derive(Debug, Clone, Copy, Default)]
pub struct GeoDataNeeds {
    /// GeoIP Country MMDB (`Country.mmdb`) — GEOIP rules or the
    /// fallback-filter geoip gate.
    pub mmdb: bool,
    /// GeoLite2-ASN MMDB — IP-ASN rules.
    pub asn: bool,
    /// geosite DB (`.dat`/`.mrs`) — GEOSITE rules or `geosite:` policy keys.
    pub geosite: bool,
}

/// Compute [`GeoDataNeeds`] from a raw config and its geo scan lines
/// ([`collect_geo_scan_lines`]). `pub(crate)` — `build_config` stores the
/// result on [`Config::geo_needs`] for the auto-update loop.
pub(crate) fn geo_references(raw: &raw::RawConfig, scan_lines: &[String]) -> GeoDataNeeds {
    GeoDataNeeds {
        mmdb: scan_lines.iter().any(|l| line_references_geoip(l))
            || dns_fallback_filter_uses_geoip(raw),
        asn: scan_lines.iter().any(|l| line_references_asn(l)),
        geosite: scan_lines.iter().any(|l| line_references_geosite(l))
            || dns_policy_uses_geosite(raw),
    }
}

/// Whether the DNS fallback filter will load the GeoIP MMDB. Mirrors the
/// `dns_parser::parse_dns` chain: the whole `dns:` block early-returns
/// unless `enable: true` (the filter is never built), the filter is built
/// only when `fallback:` nameservers exist, and its geoip gate defaults to
/// `true` when `fallback-filter` is absent.
fn dns_fallback_filter_uses_geoip(raw: &raw::RawConfig) -> bool {
    let Some(dns) = raw.dns.as_ref() else {
        return false;
    };
    if !dns.enable.unwrap_or(false) {
        return false;
    }
    if dns.fallback.as_deref().unwrap_or(&[]).is_empty() {
        return false;
    }
    dns.fallback_filter
        .as_ref()
        .and_then(|f| f.geoip)
        .unwrap_or(true)
}

/// The geodata files this config's rules reference that are absent on disk —
/// `(url, destination)` pairs in scan order. Shared between the prefetch-map
/// gate in `build_config` and [`ensure_geodata`] so both agree on what a
/// startup actually has to download. `needs` is the
/// [`geo_references`] verdict for this config — computing it once keeps the
/// "is this DB referenced" judgment in one place.
fn missing_geodata_downloads(geo: &GeoDataConfig, needs: GeoDataNeeds) -> Vec<(&String, PathBuf)> {
    if !needs.mmdb && !needs.asn && !needs.geosite {
        return Vec::new();
    }

    let geoip_path = geo.mmdb_path.clone().unwrap_or_else(default_geoip_path);
    let asn_path = geo.asn_path.clone().unwrap_or_else(default_asn_path);
    let geosite_path = geo
        .geosite_path
        .clone()
        .unwrap_or_else(default_geosite_path);

    let geoip_missing = needs.mmdb && !geoip_path.exists();
    let asn_missing = needs.asn && !asn_path.exists();
    let geosite_missing = needs.geosite && !geosite_db_present(geo);

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

/// Whether a geosite DB is on disk where the rule parser looks: the
/// explicit `geodata.geosite-path`, else any default candidate.
pub fn geosite_db_present(geo: &GeoDataConfig) -> bool {
    geo.geosite_path.as_ref().map_or_else(
        || {
            meow_rules::geosite::default_geosite_candidates()
                .iter()
                .any(|p| p.exists())
        },
        |p| p.exists(),
    )
}

/// What a name in `geodata.proxy` or a `MATCH` line points a geodata
/// download at.
enum DownloadTarget {
    /// A built-in adapter: `DIRECT`/`COMPATIBLE`/`PASS`/`PASS-RULE` fetch
    /// direct, `REJECT`/`REJECT-DROP` skip the download.
    Builtin(GeodataEgress),
    Proxy(Arc<dyn Proxy>),
    Unknown,
}

/// Classify `name` against `map` the way the tunnel binds it: an exact
/// built-in name ([`BUILTIN_ADAPTER_NAMES`], which `proxies:`/
/// `proxy-groups:` entries cannot shadow) is the built-in, any other name
/// present in `map` is that proxy or group — so a user node named `pass`
/// keeps carrying the download — and only then does a case-insensitive
/// built-in spelling (`direct`, `Reject`) count, as in the rule parser.
fn classify_download_target(name: &str, map: &HashMap<SmolStr, Arc<dyn Proxy>>) -> DownloadTarget {
    let builtin = |b: &&'static str| match *b {
        "REJECT" | "REJECT-DROP" => GeodataEgress::Rejected(b),
        _ => GeodataEgress::Direct,
    };
    if let Some(b) = BUILTIN_ADAPTER_NAMES.iter().find(|b| **b == name) {
        return DownloadTarget::Builtin(builtin(b));
    }
    if let Some(p) = map.get(name) {
        return DownloadTarget::Proxy(Arc::clone(p));
    }
    BUILTIN_ADAPTER_NAMES
        .iter()
        .find(|b| name.eq_ignore_ascii_case(b))
        .map_or(DownloadTarget::Unknown, |b| {
            DownloadTarget::Builtin(builtin(b))
        })
}

/// Resolve the outbound geodata downloads ride. `map` is whatever proxy
/// layer the caller already built — the startup prefetch map or the live
/// route table; group entries resolve as-is (a `select` group dials its
/// persisted or first member, `url-test`/`fallback` probe at dial time), so
/// `map.get(name)` is already "the selector_store choice or first member".
/// `mode` is the tunnel mode the download should follow — the config's
/// `mode:` at startup, the live one (which `PATCH /configs` can change)
/// afterwards. `chained_providers` names the proxy-providers whose current
/// nodes declare `dialer-proxy` ([`chained_provider_names`]).
///
/// Order — first hit wins:
///
/// 1. **`geodata.proxy`** (`geo.proxy`) — explicit override. A blank value
///    warns and is ignored (it's an optional key, not a hard defect); a
///    built-in name resolves as `classify_download_target` says; any
///    other name resolves against `map`. An unknown name warns and falls
///    through to the default egress — a typo must not silently leak the
///    download direct, but it also must not reject an otherwise-valid
///    config.
/// 2. **The mode's default route** — `direct` mode fetches direct;
///    `global` mode rides the `GLOBAL` group (direct without one, as the
///    tunnel does); `rule` mode takes the last top-level `MATCH,<target>`,
///    with a name missing from `map` warning and falling through.
/// 3. **`first_named_proxy`** — the legacy `proxies[0]` behavior, kept as
///    the no-MATCH/no-override fallback.
///
/// An egress from 2 or 3 is implied, not named for the download, so a failed
/// first dial through it may retry direct — on first boot a MATCH group fed
/// by proxy-providers has no members yet (their fetches are detached), and
/// without the retry every GeoIP config would fail to start. Two cases are
/// deliberate egress and never fall back, failing loudly like a provider
/// `proxy:` (#625): an explicit `geodata.proxy`, and an egress that can
/// reach a static `dialer-proxy` chain, itself or through a group
/// (`reaches_dialer_chain`) — in a region where the CDN is blocked, a dead
/// chain must not become direct egress.
pub fn resolve_geodata_egress(
    raw: &raw::RawConfig,
    geo: &GeoDataConfig,
    mode: TunnelMode,
    map: &HashMap<SmolStr, Arc<dyn Proxy>>,
    chained_providers: &std::collections::HashSet<String>,
) -> GeodataEgress {
    let named = |proxy: Arc<dyn Proxy>| GeodataEgress::Proxy {
        proxy,
        direct_fallback: false,
    };
    let implied = |name: &str, proxy: Arc<dyn Proxy>| GeodataEgress::Proxy {
        proxy,
        direct_fallback: !reaches_dialer_chain(raw, name, chained_providers),
    };

    // 1. Explicit `geodata.proxy`.
    if let Some(name) = geo.proxy.as_deref() {
        let name = name.trim();
        if name.is_empty() {
            warn!("geodata.proxy: blank value ignored; using the default egress");
        } else {
            match classify_download_target(name, map) {
                DownloadTarget::Builtin(egress) => return egress,
                DownloadTarget::Proxy(proxy) => return named(proxy),
                DownloadTarget::Unknown => warn!(
                    "geodata.proxy '{name}' is not a known proxy or group; \
                     falling back to the default egress"
                ),
            }
        }
    }

    // 2. The mode's default route.
    match mode {
        TunnelMode::Direct => return GeodataEgress::Direct,
        TunnelMode::Global => {
            return map
                .get("GLOBAL")
                .map_or(GeodataEgress::Direct, |p| implied("GLOBAL", Arc::clone(p)));
        }
        TunnelMode::Rule => {
            if let Some(target) = last_match_target(raw) {
                match classify_download_target(target, map) {
                    DownloadTarget::Builtin(egress) => return egress,
                    DownloadTarget::Proxy(proxy) => return implied(target, proxy),
                    DownloadTarget::Unknown => warn!(
                        "geodata download: MATCH target '{target}' is not a known proxy \
                         or group; falling back to the first named proxy"
                    ),
                }
            }
        }
    }

    // 3. Legacy default — first `proxies:` entry.
    let first = raw
        .proxies
        .as_deref()
        .and_then(<[_]>::first)
        .and_then(|p| p.get("name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    internal_http::first_named_proxy(raw.proxies.as_deref(), map)
        .map_or(GeodataEgress::Direct, |proxy| implied(first, proxy))
}

/// Whether the outbound `name` can dial through a static `dialer-proxy`
/// chain: a `proxies:` entry declaring a non-blank `dialer-proxy`, or a
/// `proxy-groups:` entry that can reach one — through its `proxies:` list
/// (recursively), or through `include-all`/`include-all-proxies`, which pull
/// in every static proxy (counted regardless of `filter`, erring towards no
/// fallback). A `GLOBAL` the config does not declare is synthesized over
/// every proxy, so it counts any static chain. Provider nodes are fetched
/// content, not in the raw config: a group reaches a chain through a
/// provider in `chained_providers` it names in `use:`, or through any of
/// them when `include-all`/`include-all-providers` pulls every provider in
/// (as does a synthesized `GLOBAL`).
fn reaches_dialer_chain(
    raw: &raw::RawConfig,
    name: &str,
    chained_providers: &std::collections::HashSet<String>,
) -> bool {
    let statics = raw.proxies.as_deref().unwrap_or(&[]);
    let groups = raw.proxy_groups.as_deref().unwrap_or(&[]);
    let chained = |p: &HashMap<String, serde_json::Value>| {
        p.get("dialer-proxy")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|d| !d.trim().is_empty())
    };
    let any_static_chain = || statics.iter().any(chained);
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![name];
    while let Some(name) = stack.pop() {
        if !seen.insert(name) {
            continue;
        }
        if let Some(group) = groups.iter().find(|g| g.name == name) {
            let include_all = group.include_all.unwrap_or(false);
            let pulls_statics = include_all || group.include_all_proxies.unwrap_or(false);
            if pulls_statics && any_static_chain() {
                return true;
            }
            let pulls_providers = include_all || group.include_all_providers.unwrap_or(false);
            if (pulls_providers && !chained_providers.is_empty())
                || group
                    .use_providers
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|p| chained_providers.contains(p))
            {
                return true;
            }
            stack.extend(
                group
                    .proxies
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(String::as_str),
            );
        } else if let Some(p) = statics
            .iter()
            .find(|p| p.get("name").and_then(serde_json::Value::as_str) == Some(name))
        {
            if chained(p) {
                return true;
            }
        } else if name == "GLOBAL" && (any_static_chain() || !chained_providers.is_empty()) {
            return true;
        }
    }
    false
}

/// The proxy-providers whose current nodes declare `dialer-proxy` — the
/// `chained_providers` argument of [`resolve_geodata_egress`].
pub fn chained_provider_names<'a>(
    providers: impl IntoIterator<Item = (&'a String, &'a Arc<ProxyProvider>)>,
) -> std::collections::HashSet<String> {
    providers
        .into_iter()
        .filter(|(_, p)| !p.declared_dialer_names().is_empty())
        .map(|(name, _)| name.clone())
        .collect()
}

/// The tunnel mode a config starts in — `mode:`, `rule` when absent or
/// unparseable (as `build_config` falls back).
fn configured_mode(raw: &raw::RawConfig) -> TunnelMode {
    raw.mode
        .as_deref()
        .and_then(|m| m.parse().ok())
        .unwrap_or_default()
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
    // Neither `proxies:` nor `proxy-groups:` → the layer can never
    // exist; skip the spawn_blocking hop to a deterministic `Ok(None)`.
    // Groups without `proxies:` still count — a provider-fed group can
    // resolve the `geodata.proxy`/provider `proxy:` names below.
    if raw.proxies.as_deref().unwrap_or(&[]).is_empty()
        && raw.proxy_groups.as_deref().unwrap_or(&[]).is_empty()
    {
        return false;
    }
    let has_fetchable_provider = raw
        .rule_providers
        .as_ref()
        .is_some_and(|m| m.values().any(|c| c.provider_type != "inline"));
    if has_fetchable_provider {
        return true;
    }
    let scan = collect_geo_scan_lines(raw, &rule_provider::PrefetchedPayloads::default());
    !missing_geodata_downloads(geo, geo_references(raw, &scan)).is_empty()
}

/// Download missing geodata files that the config's rules require.
///
/// For `GEOSITE` entries the DB is discovered separately and loaded only if
/// at least one GEOSITE rule is present (same lazy pattern as GeoIP/ASN).
/// Unlike GeoIP/ASN, the GEOSITE DB is tolerated as absent — per spec the
/// rule no-matches at query time rather than failing at parse.
///
/// Downloads ride the outbound [`resolve_geodata_egress`] picks through
/// `map` — the shared pre-registry proxy layer with `dialer-proxy` chains
/// applied at startup, the candidate's freshly built proxies on a rebuild
/// (needed in regions where the CDN is blocked; issue #533). When no map
/// exists — a config without `proxies:` or `proxy-groups:` — the
/// resolution runs against an empty map: named outbounds can only warn
/// and fall back, while `geodata.proxy`/`MATCH` builtins still gate the
/// download (a rejected layer aborts the build before this runs).
/// Download failures are
/// logged as warnings — the subsequent parser-context build hard-errors on
/// a missing GeoIP/ASN file (geosite is tolerated absent, per spec), giving
/// a clear diagnostic.
async fn ensure_geodata(
    raw: &raw::RawConfig,
    geo: &GeoDataConfig,
    scan_lines: &[String],
    map: Option<&HashMap<SmolStr, Arc<dyn Proxy>>>,
    chained_providers: &std::collections::HashSet<String>,
) {
    if is_offline_validate() {
        // Validate local databases when present; missing databases use empty
        // indexes for structural checks and are fetched only at real startup.
        return;
    }
    let downloads = missing_geodata_downloads(geo, geo_references(raw, scan_lines));
    if downloads.is_empty() {
        return;
    }

    // No layer means no `proxies:`/`proxy-groups:` at all, so a named
    // outbound can never resolve — but a `geodata.proxy`/`MATCH` builtin
    // (`REJECT`, `REJECT-DROP`, `DIRECT`) still must, since it needs no
    // map entry to classify (issue #974 review).
    let empty = HashMap::new();
    let egress = resolve_geodata_egress(
        raw,
        geo,
        configured_mode(raw),
        map.unwrap_or(&empty),
        chained_providers,
    );

    for (url, dest) in downloads {
        info!("geodata: downloading {} to {}", url, dest.display());
        if let Err(e) = geodata::download_and_replace(url, &dest, &egress).await {
            warn!("geodata: failed to download {} — {:#}", url, e);
        }
    }
}

/// [`ensure_geodata`] for the synchronous rebuild path, which runs on a
/// blocking thread: a `PUT /configs` or subscription refresh can reference
/// a database startup never needed, and the parser-context build that
/// follows hard-errors on a missing GeoIP/ASN file. The downloads run on a
/// temporary runtime on their own thread, like the rule-provider prefetch
/// (`rule_provider::fetch_http_blocking`); with nothing missing, no thread
/// is spawned.
fn ensure_geodata_blocking(
    raw: &raw::RawConfig,
    geo: &GeoDataConfig,
    scan_lines: &[String],
    map: &HashMap<SmolStr, Arc<dyn Proxy>>,
    chained_providers: &std::collections::HashSet<String>,
) {
    if is_offline_validate()
        || missing_geodata_downloads(geo, geo_references(raw, scan_lines)).is_empty()
    {
        return;
    }
    // Carry the scoped dispatcher onto the download thread so its warns
    // reach the caller's subscriber (same propagation
    // `spawn_blocking_with_current_dispatcher` applies).
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let joined = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tracing::dispatcher::with_default(&dispatch, || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    rt.block_on(ensure_geodata(
                        raw,
                        geo,
                        scan_lines,
                        Some(map),
                        chained_providers,
                    ));
                    Ok::<(), std::io::Error>(())
                })
            })
            .join()
    });
    match joined {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("geodata: building the download runtime failed: {e}"),
        Err(payload) => warn!(
            "geodata: download thread panicked: {}",
            rule_provider::panic_message(payload.as_ref())
        ),
    }
}

/// Parse geodata paths from `raw.geodata` and build a `ParserContext` that
/// respects any explicit path overrides. Used by both `build_config` and
/// `rebuild_from_raw_impl` so all code paths honour the same config.
fn build_parser_context_from_raw(
    raw: &raw::RawConfig,
    provider_payloads: &rule_provider::PrefetchedPayloads,
) -> Result<meow_rules::ParserContext, anyhow::Error> {
    let geo = geodata::parse_geodata(raw)?;
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
        Some(_) if is_offline_validate() && !geoip_path.exists() => {
            Some(Arc::new(meow_rules::country_index::CountryIndex::default()))
        }
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
        Some(_) if is_offline_validate() && !asn_path.exists() => {
            Some(Arc::new(meow_rules::asn_index::AsnIndex::default()))
        }
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
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `SRC-GEOIP` keys the same country index; the `^` anchor keeps
        // `GEOIP` in the type field — scan texts are type-first strings,
        // so a payload mention (`DOMAIN-KEYWORD,GEOIP,x`) is data, not a
        // declaration (issue #974).
        regex::Regex::new(r"(?i)^\s*(?:SRC-)?GEOIP\s*,\s*([A-Za-z0-9]+)")
            .expect("compile GEOIP scan regex")
    })
}

/// One raw rule line classified for geo discovery (issue #974): the text
/// segments the plain `GEOIP,`/`GEOSITE,`/`IP-ASN,` regexes may scan,
/// plus the parsed SUB-RULE condition trees — the only position cond
/// leaves can legally live. Free-form pattern fields never become scan
/// text: a `GEOIP,x` inside a regex or glob — or inside a logic-group
/// leg of those types — is process/domain text, never a declaration.
/// Malformed lines contribute nothing (the parse stage owns the error).
#[derive(Default)]
struct GeoLineScan<'a> {
    texts: Vec<&'a str>,
    conds: Vec<meow_rules::sub_rule_cond::CondExpr>,
}

fn geo_scan_targets(line: &str) -> GeoLineScan<'_> {
    let mut scan = GeoLineScan::default();
    let trimmed = line.trim();
    // The same input bound the rule parser enforces — a line it would
    // reject contributes nothing, and the bound keeps the classifier's
    // per-level work honest before the parse stage owns the error.
    if !trimmed.is_empty()
        && !trimmed.starts_with('#')
        && trimmed.len() <= meow_rules::parser::MAX_RULE_LINE_LEN
    {
        collect_geo_segments(trimmed, &mut scan, 0);
    }
    scan
}

/// Classify one rule-position text — a top-level line or a logic leg —
/// into scan segments, recursing through logic groups so a leg's own
/// type governs how its text is treated (issue #974 review: a
/// `PROCESS-*` leg's `GEOIP,x` text must not trigger a geo load).
/// `depth` mirrors the parser's `MAX_LOGIC_DEPTH` budget — this scan
/// runs *before* the parse stage, so an over-deep line must stop the
/// descent here rather than overflow the stack first.
fn collect_geo_segments<'a>(text: &'a str, scan: &mut GeoLineScan<'a>, depth: usize) {
    use meow_rules::sub_rule_cond::{parse_cond, parse_sub_rule_reference};
    let ty = text.split(',').next().map_or("", str::trim);
    let ty = meow_common::RuleType::from_mihomo_name(ty)
        .map_or_else(|| ty.to_ascii_uppercase(), |t| t.as_str().to_string());
    match ty.as_str() {
        // The pattern field is unbounded expression text: a `GEOIP,x`
        // inside a regex or glob is process-name/domain text, never a
        // geo declaration. DOMAIN-REGEX joins the class: its
        // comma-protected payload could carry `GEOIP,x` too.
        "PROCESS-NAME"
        | "PROCESS-PATH"
        | "PROCESS-NAME-REGEX"
        | "PROCESS-PATH-REGEX"
        | "PROCESS-NAME-WILDCARD"
        | "PROCESS-PATH-WILDCARD"
        | "DOMAIN-REGEX" => {}
        "SUB-RULE" => {
            if let Some(cond) = parse_sub_rule_reference(text)
                .ok()
                .flatten()
                .and_then(|r| r.cond)
                .and_then(|c| parse_cond(&c).ok())
            {
                scan.conds.push(cond);
            }
        }
        "AND" | "OR" | "NOT" => {
            // A group the parser would reject for depth can never exist
            // as a rule — stop scanning this branch rather than recursing
            // one stack frame per level (the parse stage owns the error).
            if depth >= meow_rules::parser::MAX_LOGIC_DEPTH {
                return;
            }
            // Decompose `(leg),(leg),<target>` and classify each leg on
            // its own type; a malformed shape falls back to the raw
            // text (conservative — the parse stage fails it anyway).
            let decomposed = text
                .split_once(',')
                .map(|(_, rest)| rest.trim_start())
                .filter(|rest| rest.starts_with('('))
                .and_then(|rest| {
                    let end = meow_rules::parser::matching_paren(rest)?;
                    meow_rules::parser::split_logic_groups(&rest[1..end]).ok()
                });
            match decomposed {
                Some(legs) => {
                    for leg in legs {
                        collect_geo_segments(leg.trim(), scan, depth + 1);
                    }
                }
                None => scan.texts.push(text),
            }
        }
        _ => scan.texts.push(text),
    }
}

fn collect_geoip_countries(lines: &[String]) -> std::collections::HashSet<String> {
    let re = geoip_scan_regex();
    let mut out = std::collections::HashSet::new();
    for line in lines {
        let scan = geo_scan_targets(line);
        for text in &scan.texts {
            for cap in re.captures_iter(text) {
                out.insert(cap[1].to_ascii_uppercase());
            }
        }
        for cond in &scan.conds {
            for leaf in cond.leaves() {
                // `GEOIP` covers the `,src` param form; `SRC-GEOIP` is
                // its dedicated name — both key the country index.
                if matches!(leaf.ty.as_str(), "GEOIP" | "SRC-GEOIP") {
                    out.insert(leaf.payload.to_ascii_uppercase());
                }
            }
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
        regex::Regex::new(r"(?i)^\s*GEOSITE\s*,\s*([A-Za-z0-9_!\-]+)(?:@[A-Za-z0-9_!\-]+)*")
            .expect("compile GEOSITE scan regex")
    })
}

fn collect_geosite_categories(lines: &[String]) -> std::collections::HashSet<String> {
    let re = geosite_scan_regex();
    let mut out = std::collections::HashSet::new();
    for line in lines {
        let scan = geo_scan_targets(line);
        for text in &scan.texts {
            for cap in re.captures_iter(text) {
                out.insert(cap[1].to_ascii_lowercase());
            }
        }
        for cond in &scan.conds {
            for leaf in cond.leaves() {
                if leaf.ty == "GEOSITE" {
                    // Same `category@attr` split the GeoSite leaf build
                    // performs — only the category keys the loader.
                    if let Some(cat) = leaf.payload.split('@').next() {
                        let cat = cat.trim();
                        if !cat.is_empty() {
                            out.insert(cat.to_ascii_lowercase());
                        }
                    }
                }
            }
        }
    }
    out
}

fn dns_policy_uses_geosite(raw: &raw::RawConfig) -> bool {
    // `dns.enable: false` (or absent) → `parse_dns` early-returns before the
    // nameserver-policy is built, so the geosite reference is dead and must
    // not count as a consumer (same posture as the fallback-filter gate).
    let enabled = raw.dns.as_ref().and_then(|dns| dns.enable).unwrap_or(false);
    if !enabled {
        return false;
    }
    dns_parser::dns_policy_keys(raw)
        .flat_map(dns_parser::expand_policy_keys)
        .any(|key| key.to_ascii_lowercase().starts_with("geosite:"))
}

fn collect_dns_policy_geosite_categories(
    raw: &raw::RawConfig,
) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for expanded in dns_parser::dns_policy_keys(raw).flat_map(dns_parser::expand_policy_keys) {
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
        regex::Regex::new(r"(?i)^\s*(?:SRC-)?IP-ASN\s*,\s*(\d+)")
            .expect("compile IP-ASN scan regex")
    })
}

fn collect_asn_numbers(lines: &[String]) -> std::collections::HashSet<u32> {
    let re = asn_scan_regex();
    let mut out = std::collections::HashSet::new();
    for line in lines {
        let scan = geo_scan_targets(line);
        for text in &scan.texts {
            for cap in re.captures_iter(text) {
                if let Ok(asn) = cap[1].parse::<u32>() {
                    out.insert(asn);
                }
            }
        }
        for cond in &scan.conds {
            for leaf in cond.leaves() {
                if matches!(leaf.ty.as_str(), "IP-ASN" | "SRC-IP-ASN") {
                    if let Ok(asn) = leaf.payload.trim().parse::<u32>() {
                        out.insert(asn);
                    }
                }
            }
        }
    }
    out
}

/// True iff `line` references the GeoIP Country database anywhere — as a
/// top-level `GEOIP,`/`SRC-GEOIP,` rule, nested inside a logic rule
/// (`AND`/`OR`/`NOT`), or as a SUB-RULE condition leaf (issue #974).
/// Comment lines never match. Uses the same classifier as
/// [`collect_geoip_countries`] so the trigger and the allowlist agree.
fn line_references_geoip(line: &str) -> bool {
    let scan = geo_scan_targets(line);
    scan.texts.iter().any(|t| geoip_scan_regex().is_match(t))
        || scan.conds.iter().any(|c| {
            c.leaves()
                .iter()
                .any(|l| matches!(l.ty.as_str(), "GEOIP" | "SRC-GEOIP"))
        })
}

/// True iff `line` references the geosite database anywhere (top-level,
/// nested inside a logic rule, or a SUB-RULE condition leaf). Comment
/// lines never match.
fn line_references_geosite(line: &str) -> bool {
    let scan = geo_scan_targets(line);
    scan.texts.iter().any(|t| geosite_scan_regex().is_match(t))
        || scan
            .conds
            .iter()
            .any(|c| c.leaves().iter().any(|l| l.ty == "GEOSITE"))
}

/// True iff `line` references the GeoLite2-ASN database anywhere — `IP-ASN,`
/// or `SRC-IP-ASN,`, top-level, nested in a logic rule, or a SUB-RULE
/// condition leaf. Comment lines never match.
fn line_references_asn(line: &str) -> bool {
    let scan = geo_scan_targets(line);
    scan.texts.iter().any(|t| asn_scan_regex().is_match(t))
        || scan.conds.iter().any(|c| {
            c.leaves()
                .iter()
                .any(|l| matches!(l.ty.as_str(), "IP-ASN" | "SRC-IP-ASN"))
        })
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
    for (name, bytes) in provider_payloads.iter() {
        let Some(cfg) = declared.and_then(|m| m.get(name)) else {
            continue;
        };
        if meow_rules::is_mrs_bytes(bytes) {
            continue;
        }
        let text = String::from_utf8_lossy(bytes);
        // Decode per the declared `format:` so a YAML payload's entries —
        // not its raw `- "…"` source text — feed the geo scan (issue
        // #974 review); an undecodable payload falls back to raw lines.
        match rule_provider::payload_entries_for_scan(cfg, &text) {
            Some(entries) => lines.extend(entries),
            None => lines.extend(
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from),
            ),
        }
    }
    lines
}

/// Default path for the GeoIP Country MMDB.
/// Honours `-d` (set via `meow_common::set_home_dir`), then `$XDG_CONFIG_HOME`,
/// then `$HOME/.config/meow`. An existing file is matched ignoring case, so
/// the `country.mmdb` a mihomo GUI copies into the home directory is used
/// rather than downloaded again.
pub fn default_geoip_path() -> PathBuf {
    existing_or_first(&meow_config_dir(), &["Country.mmdb"])
}

/// Default path for the GeoLite2-ASN MMDB. Same discovery chain as GeoIP,
/// with the upstream-compatible filename `GeoLite2-ASN.mmdb`; an existing
/// `ASN.mmdb`, the name mihomo GUIs copy the same database under, is used
/// when there is no `GeoLite2-ASN.mmdb`.
pub fn default_asn_path() -> PathBuf {
    existing_or_first(&meow_config_dir(), &["GeoLite2-ASN.mmdb", "ASN.mmdb"])
}

/// The first of `names`, in order, that exists in `dir` as a file, matched
/// exactly and then ignoring ASCII case; `dir/names[0]` when none does, which
/// is where the geodata downloader puts a missing database.
fn existing_or_first(dir: &Path, names: &[&str]) -> PathBuf {
    let files: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| dir.join(name).is_file())
        .collect();
    names
        .iter()
        .find_map(|want| {
            files
                .iter()
                .find(|name| name == want)
                .or_else(|| files.iter().find(|name| name.eq_ignore_ascii_case(want)))
        })
        .map_or_else(|| dir.join(names[0]), |name| dir.join(name))
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

/// Validate the UDP-TPROXY listen contract against the raw `listen`
/// spelling. This must run before [`resolve_listener_bind`], whose socket
/// normalization drops `sin6_scope_id` from `[…%N]:port`.
fn validate_tproxy_udp_listen(listen: &str, name: &str) -> Result<(), anyhow::Error> {
    let (ip, scope_id) = if let Ok(ip) = listen.parse::<IpAddr>() {
        (ip, 0)
    } else if let Ok(addr) = listen.parse::<SocketAddr>() {
        let scope = match addr {
            SocketAddr::V6(v6) => v6.scope_id(),
            SocketAddr::V4(_) => 0,
        };
        (addr.ip(), scope)
    } else {
        // Not a bind literal at all — `resolve_listener_bind` produces the
        // canonical invalid-address diagnostic just below.
        return Ok(());
    };
    let IpAddr::V6(ip) = ip else {
        return Ok(());
    };
    if listen.contains('%') || scope_id != 0 {
        anyhow::bail!(
            "listeners[{name}]: `udp: true` does not accept scoped IPv6 listen \
             address '{listen}' — UDP TPROXY v1 supports only unscoped routable \
             IPv6; use the address without a zone, or `::` for dual-stack"
        );
    }
    if ip.to_ipv4_mapped().is_some() {
        anyhow::bail!(
            "listeners[{name}]: `udp: true` does not accept IPv4-mapped IPv6 \
             listen address '{listen}' — use the IPv4 literal, or `::` for \
             dual-stack"
        );
    }
    // fe80::/10 — link-local delivery requires a scope zone end to end,
    // which the v1 UDP data plane deliberately does not carry.
    if ip.segments()[0] & 0xffc0 == 0xfe80 {
        anyhow::bail!(
            "listeners[{name}]: `udp: true` does not accept link-local IPv6 \
             listen address '{listen}' — use a routable/ULA IPv6 address, or \
             `::` for dual-stack"
        );
    }
    Ok(())
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
///
/// `sniffer_declared` says the raw config carries an explicit `sniffer:`
/// block (even `enable: false`) — the deliberate knob then defeats the
/// deprecated `tproxy-sni` synthesis on every arm that carries `sni`, or
/// `tproxy-sni: true` + `sniffer.enable: false` would still sniff (the
/// listener's synthesized runtime survives `with_sniffer`'s off state).
///
/// `TProxy` and `WireGuard` are fully resolved here; `Shadowsocks` returns
/// a placeholder the caller completes via `build_ss_listener_spec`.
fn parse_listener_spec(
    raw_l: &raw::RawListener,
    global_tproxy_sni: bool,
    sniffer_declared: bool,
) -> Result<ListenerSpec, anyhow::Error> {
    // The resolved `sni` for `TProxy`-shaped arms — deprecated `tproxy-sni`,
    // dead once a `sniffer:` section exists.
    let tproxy_shaped = matches!(
        raw_l.listener_type.to_lowercase().as_str(),
        "redir" | "tproxy"
    );
    if tproxy_shaped && sniffer_declared && raw_l.tproxy_sni.is_some() {
        warn!(
            "listeners[{}]: `tproxy-sni` is ignored — the `sniffer:` block \
             takes precedence (deprecated alias)",
            raw_l.name
        );
    }
    let sni = raw_l.tproxy_sni.unwrap_or(global_tproxy_sni) && !sniffer_declared;
    match raw_l.listener_type.to_lowercase().as_str() {
        "mixed" => Ok(ListenerSpec::Mixed),
        "http" => Ok(ListenerSpec::Http),
        // mihomo spells the named SOCKS inbound `socks`; `socks5` stays
        // the canonical meow-rs name.
        "socks" | "socks5" => Ok(ListenerSpec::Socks5),
        // mihomo's REDIRECT inbound: meow's tproxy TCP path without managed
        // rules — the deployer's REDIRECT rules steer traffic here.
        "redir" => {
            for (key, set) in [
                ("firewall", raw_l.firewall.is_some()),
                ("udp", raw_l.udp.is_some()),
                ("udp-timeout", raw_l.udp_timeout.is_some()),
                ("transparent", raw_l.transparent.is_some()),
                ("cipher", raw_l.cipher.is_some()),
                ("password", raw_l.password.is_some()),
                ("simple-obfs", raw_l.simple_obfs.is_some()),
                ("shadow-tls", raw_l.shadow_tls.is_some()),
                ("res-tls", raw_l.res_tls.is_some()),
                ("jls-config", raw_l.jls_config.is_some()),
                ("kcp-tun", raw_l.kcp_tun.is_some()),
                ("mux-option", raw_l.mux_option.is_some()),
            ] {
                if set {
                    warn!(
                        "listeners[{}]: `{key}` is ignored on `type: redir` \
                         (REDIRECT TCP, rules owned by the deployer)",
                        raw_l.name
                    );
                }
            }
            Ok(ListenerSpec::TProxy {
                sni,
                firewall: false,
                udp: false,
                udp_timeout: default_udp_timeout_secs(),
                transparent: false,
            })
        }
        "tproxy" => {
            // #564: `udp` is opt-in, and the managed firewall only produces
            // host TCP OUTPUT REDIRECT rules — it cannot promise LAN UDP
            // TPROXY policy routing, so the combination is rejected rather
            // than silently TCP-only.
            let udp = raw_l.udp.unwrap_or(false);
            let firewall = raw_l.firewall.unwrap_or_else(default_tproxy_firewall);
            if raw_l.transparent.is_none() {
                warn!(
                    "listeners[{}]: mihomo's `type: tproxy` is real TPROXY — meow \
                     defaults to REDIRECT for backward compatibility; set \
                     `transparent: true` for upstream semantics (requires \
                     `firewall: false`)",
                    raw_l.name
                );
            }
            // mihomo's `type: tproxy` is real TPROXY: `transparent: true`.
            let transparent = raw_l.transparent.unwrap_or(false);
            if transparent && firewall {
                anyhow::bail!(
                    "listeners[{}]: `transparent: true` (TCP by TPROXY) requires \
                     `firewall: false` — meow's managed rules are REDIRECT",
                    raw_l.name
                );
            }
            if transparent && !cfg!(target_os = "linux") {
                anyhow::bail!(
                    "listeners[{}]: `transparent: true` (TPROXY) is Linux-only",
                    raw_l.name
                );
            }
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
                // Same Instant+Duration overflow class as tun.udp-timeout
                // (issue #648) — the tproxy consumer happens to use
                // `checked_add` today, but the bound keeps every future
                // consumer honest.
                Some(s) if s > meow_common::MAX_DURATION_SECS => anyhow::bail!(
                    "listeners[{}].udp-timeout: {s}s exceeds the {}s ceiling",
                    raw_l.name,
                    meow_common::MAX_DURATION_SECS
                ),
                Some(s) => s,
                None => default_udp_timeout_secs(),
            };
            Ok(ListenerSpec::TProxy {
                sni,
                firewall,
                udp,
                udp_timeout,
                transparent,
            })
        }
        "shadowsocks" | "ss" => Ok(ListenerSpec::Shadowsocks(SsListenerConfig {
            cipher: String::new(),
            password: String::new(),
            udp: true,
            simple_obfs: None,
        })),
        "wireguard" => Ok(ListenerSpec::WireGuard(build_wg_listener_spec(raw_l)?)),
        // Placeholder like `Shadowsocks` — `build_named_listeners` fills
        // the real spec via `build_anytls_listener_spec`, which needs the
        // (possibly comma-listed) `listen` context.
        "anytls" => Ok(ListenerSpec::Anytls(AnytlsListenerConfig::default())),
        // Same placeholder pattern — `build_vless_listener_spec` runs in
        // `build_named_listeners` with the `listen`/bind context and either
        // replaces this wholesale or errors the build; the placeholder is
        // never observed.
        "vless" => Ok(ListenerSpec::Vless(VlessListenerConfig {
            users: Vec::new(),
            security: VlessSecurity::StandardTls {
                certificate: String::new(),
                private_key: String::new(),
                alpn: Vec::new(),
            },
            udp: true,
            addresses: vec![ListenerBind {
                listen: String::new(),
                port: 0,
            }],
        })),
        other => anyhow::bail!(
            "unknown listener type '{other}'; expected mixed, http, socks, socks5, tproxy, redir, shadowsocks, wireguard, anytls, vless, or tun"
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

/// Decode a base64 WireGuard key field into exactly 32 bytes (standard
/// alphabet — the spelling every WG tool emits; the same rule the
/// outbound parser's `parse_wg_key` enforces). `ctx` carries the field
/// path for the error, e.g. `listeners[wg].peers[0].public-key`.
fn wg_b64_key(value: Option<&str>, ctx: &str) -> Result<[u8; 32], anyhow::Error> {
    use base64::Engine;
    let raw = match value {
        None => anyhow::bail!("{ctx}: missing base64 key"),
        // A present-but-empty key names a different defect than an absent
        // one — don't call it "missing".
        Some("") => anyhow::bail!("{ctx}: must not be empty"),
        Some(s) => s,
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| anyhow::anyhow!("{ctx}: must be base64"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{ctx}: must decode to exactly 32 bytes"))
}

/// `reserved` on a `type: wireguard` peer — the 3-byte Cloudflare
/// WARP-style identifier, a YAML list of three bytes or a base64 string
/// decoding to exactly 3 bytes (the same shapes the outbound `reserved`
/// accepts). Inbound reserved bytes are cleared unconditionally; this
/// only stamps the wire datagrams meow sends to the peer.
fn wg_peer_reserved(
    value: Option<&serde_json::Value>,
    ctx: &str,
) -> Result<Option<[u8; 3]>, anyhow::Error> {
    use base64::Engine;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Array(list)) => {
            if list.len() != 3 {
                anyhow::bail!("{ctx}: must be a list of exactly 3 bytes");
            }
            let mut out = [0u8; 3];
            for (i, v) in list.iter().enumerate() {
                let n = v
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("{ctx}: entries must be bytes (0-255)"))?;
                out[i] = u8::try_from(n)
                    .map_err(|_| anyhow::anyhow!("{ctx}: entries must be bytes (0-255)"))?;
            }
            Ok(Some(out))
        }
        Some(serde_json::Value::String(s)) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|_| anyhow::anyhow!("{ctx}: must be a 3-byte list or base64"))?;
            <[u8; 3]>::try_from(bytes.as_slice())
                .map(Some)
                .map_err(|_| anyhow::anyhow!("{ctx}: base64 must decode to exactly 3 bytes"))
        }
        Some(_) => anyhow::bail!("{ctx}: must be a 3-byte list or base64"),
    }
}

/// Build a validated [`WgListenerConfig`] from a raw `listeners:` entry
/// (`type: wireguard`).
///
/// Hard errors (Class A per ADR-0002): a missing/undecodable
/// `private-key` (or the all-zero key, refused exactly like the outbound
/// adapter), missing or empty `peers`, `peers` at/over the 2^24
/// demux-namespace cap, a peer `public-key` that is missing, not
/// base64 → 32 bytes, or duplicated in the table, a `preshared-key` that
/// does not decode to 32 bytes, `allowed-ips` missing, empty, or holding
/// a non-CIDR entry, `reserved` that is not a 3-byte list or base64 → 3
/// bytes, `mtu` outside `640..=9000`, or `udp-timeout: 0` (the same
/// contract `tproxy`'s `udp-timeout` enforces).
///
/// A peer `public-key` equal to the listener's *own* public key
/// (`x25519_dalek::PublicKey::from(&StaticSecret)`) is a self-peering
/// misconfiguration: rejected here when the `wireguard` feature is
/// compiled — its `dep:x25519-dalek` puts the basepoint multiply in
/// scope — and re-checked at listener startup on every build
/// (meow-listener holds meow-wireguard's x25519), so `meow-config`
/// carries no unconditional crypto dep.
///
/// Keys the schema knows but `type: wireguard` does not consume
/// (`cipher`, the opaque upstream sub-options, …) and schema-unknown
/// keys (captured by `RawListener`'s flatten field) warn-and-ignore —
/// the same policy every other listener arm applies (ADR-0002), keeping
/// forward-compat with keys a newer schema adds. Tproxy-only keys set
/// on a WG entry (`tproxy-sni`, `firewall`, `transparent`) warn in the
/// generic arms of `build_named_listeners`, not here.
fn build_wg_listener_spec(raw_l: &raw::RawListener) -> Result<WgListenerConfig, anyhow::Error> {
    for (key, set) in [
        ("cipher", raw_l.cipher.is_some()),
        ("password", raw_l.password.is_some()),
        ("simple-obfs", raw_l.simple_obfs.is_some()),
        ("shadow-tls", raw_l.shadow_tls.is_some()),
        ("res-tls", raw_l.res_tls.is_some()),
        ("jls-config", raw_l.jls_config.is_some()),
        ("kcp-tun", raw_l.kcp_tun.is_some()),
        ("mux-option", raw_l.mux_option.is_some()),
    ] {
        if set {
            warn!(
                "listeners[{}]: `{key}` is ignored on `type: wireguard`; \
                 remove it to suppress this warning",
                raw_l.name
            );
        }
    }
    let mut unknown_keys: Vec<&String> = raw_l.extra.keys().collect();
    unknown_keys.sort();
    for key in unknown_keys {
        warn!(
            "listeners[{}]: `{key}` is not a known `type: wireguard` field, ignored",
            raw_l.name
        );
    }

    let private_key = wg_b64_key(
        raw_l.private_key.as_deref(),
        &format!("listeners[{}].private-key", raw_l.name),
    )?;
    if private_key == [0u8; 32] {
        anyhow::bail!(
            "listeners[{}].private-key: the all-zero key is not a valid WireGuard key",
            raw_l.name
        );
    }

    let mtu = match raw_l.mtu.unwrap_or_else(default_wg_mtu) {
        m if !(640..=9000).contains(&m) => anyhow::bail!(
            "listeners[{}].mtu: {m} must be in 640..=9000 (outer MTU; inner = mtu - 64)",
            raw_l.name
        ),
        m => m,
    };
    let udp_timeout = match raw_l.udp_timeout {
        Some(0) => anyhow::bail!(
            "listeners[{}].udp-timeout: must be at least 1 second",
            raw_l.name
        ),
        // Same Instant+Duration overflow class as tproxy.udp-timeout —
        // the bound keeps every future consumer honest (issue #648).
        Some(s) if s > meow_common::MAX_DURATION_SECS => anyhow::bail!(
            "listeners[{}].udp-timeout: {s}s exceeds the {}s ceiling",
            raw_l.name,
            meow_common::MAX_DURATION_SECS
        ),
        Some(s) => std::time::Duration::from_secs(s),
        None => default_wg_udp_timeout(),
    };
    // Same asymmetric-misuse diagnosis as the tproxy arm: with `udp:
    // false` the timeout binds nothing.
    if raw_l.udp == Some(false) && raw_l.udp_timeout.is_some() {
        warn!(
            "listeners[{}].udp-timeout: has no effect unless `udp: true` is set; \
             remove it to suppress this warning",
            raw_l.name
        );
    }

    let raw_peers = raw_l.peers.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "listeners[{}]: wireguard listener requires 'peers' (non-empty)",
            raw_l.name
        )
    })?;
    if raw_peers.is_empty() {
        anyhow::bail!(
            "listeners[{}].peers: must contain at least one peer",
            raw_l.name
        );
    }
    // Peer slots feed the `index << 8` demux namespace: the low 8 bits are
    // the per-peer session counter, so the table caps at 2^24 - 1.
    if raw_peers.len() >= (1 << 24) {
        anyhow::bail!(
            "listeners[{}].peers: {} peers exceeds the 2^24-1 demux-namespace cap",
            raw_l.name,
            raw_peers.len()
        );
    }

    let mut seen_keys = std::collections::HashSet::new();
    let mut peers = Vec::with_capacity(raw_peers.len());
    for (i, rp) in raw_peers.iter().enumerate() {
        let mut unknown_peer_keys: Vec<&String> = rp.extra.keys().collect();
        unknown_peer_keys.sort();
        for key in unknown_peer_keys {
            warn!(
                "listeners[{}].peers[{i}]: `{key}` is not a known wireguard peer field, ignored",
                raw_l.name
            );
        }
        let public_key = wg_b64_key(
            rp.public_key.as_deref(),
            &format!("listeners[{}].peers[{i}].public-key", raw_l.name),
        )?;
        if !seen_keys.insert(public_key) {
            anyhow::bail!(
                "listeners[{}].peers[{i}].public-key: duplicates an earlier peer",
                raw_l.name
            );
        }
        let preshared_key = match rp.preshared_key.as_deref() {
            Some(_) => Some(wg_b64_key(
                rp.preshared_key.as_deref(),
                &format!("listeners[{}].peers[{i}].preshared-key", raw_l.name),
            )?),
            None => None,
        };
        let allowed_ips = match rp.allowed_ips.as_deref() {
            None => anyhow::bail!(
                "listeners[{}].peers[{i}]: wireguard peer requires 'allowed-ips' (non-empty; \
                 write 0.0.0.0/0 and ::/0 explicitly for full openness)",
                raw_l.name
            ),
            Some([]) => anyhow::bail!(
                "listeners[{}].peers[{i}].allowed-ips: must not be empty (inbound ACL; \
                 write 0.0.0.0/0 and ::/0 explicitly for full openness)",
                raw_l.name
            ),
            Some(list) => list
                .iter()
                .map(|s| {
                    s.parse::<ipnet::IpNet>().map_err(|_| {
                        anyhow::anyhow!(
                            "listeners[{}].peers[{i}].allowed-ips: '{s}' is not a valid CIDR",
                            raw_l.name
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        let reserved = wg_peer_reserved(
            rp.reserved.as_ref(),
            &format!("listeners[{}].peers[{i}].reserved", raw_l.name),
        )?;
        peers.push(WgPeerConfig {
            public_key,
            preshared_key,
            allowed_ips,
            name: rp
                .name
                .as_deref()
                .filter(|s| !s.is_empty())
                .map_or_else(|| SmolStr::from(format!("peer-{i}")), SmolStr::from),
            reserved,
        });
    }

    #[cfg(feature = "wireguard")]
    {
        let self_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
        if let Some(i) = peers
            .iter()
            .position(|p| p.public_key == *self_public.as_bytes())
        {
            anyhow::bail!(
                "listeners[{}].peers[{i}].public-key: equals the listener's own public key \
                 (self-peering is not a valid peer)",
                raw_l.name
            );
        }
    }

    Ok(WgListenerConfig {
        private_key,
        peers,
        mtu,
        udp: raw_l.udp.unwrap_or_else(default_wg_udp),
        udp_timeout,
    })
}

/// Whether a `certificate`/`private-key` value is the inline-PEM form
/// (vs. a filesystem path) — the two halves must use the SAME form.
fn is_pem_literal(value: &str) -> bool {
    value.contains("-----BEGIN")
}

/// `shadow-tls`/`res-tls`/`jls-config` opaque-block handling for
/// `type: anytls`: present-and-enabled is a front layer (counted for
/// mutual exclusivity); present-but-disabled warns and ignores. A value
/// that is not a mapping, or whose `enable` is not a boolean, is a
/// shape error.
fn anytls_front_layer_enabled(
    raw_l: &raw::RawListener,
    key: &str,
    value: Option<&serde_json::Value>,
) -> Result<bool, anyhow::Error> {
    let Some(value) = value else {
        return Ok(false);
    };
    if value.is_null() {
        return Ok(false);
    }
    let Some(obj) = value.as_object() else {
        anyhow::bail!("listeners[{}].{key}: must be a mapping", raw_l.name);
    };
    match obj.get("enable") {
        None => {
            warn!(
                "listeners[{}].{key}: present but `enable` unset — ignored \
                 (no front layer is selected)",
                raw_l.name
            );
            Ok(false)
        }
        Some(serde_json::Value::Bool(enabled)) => {
            if !enabled {
                warn!(
                    "listeners[{}].{key}: `enable: false` selects no front layer — ignored",
                    raw_l.name
                );
            }
            Ok(*enabled)
        }
        Some(_) => anyhow::bail!("listeners[{}].{key}.enable: must be a boolean", raw_l.name),
    }
}

/// Resolve the multi-address `listen` contract shared by TCP server
/// inbounds: comma-separated segments, the entry `port` merge rules, IP
/// literal validation, and canonical duplicate detection.
fn resolve_multi_listener_binds(
    raw_l: &raw::RawListener,
    default_bind: &str,
) -> Result<Vec<ListenerBind>, anyhow::Error> {
    let listen_raw = raw_l.listen.as_deref().unwrap_or(default_bind);
    let mut addresses: Vec<ListenerBind> = Vec::new();
    for segment in listen_raw.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            anyhow::bail!(
                "listeners[{}].listen: empty address in comma-separated list '{listen_raw}'",
                raw_l.name
            );
        }
        let (listen, port) = resolve_listener_bind(segment, raw_l.port)
            .map_err(|e| anyhow::anyhow!("listeners[{}].listen: {e}", raw_l.name))?;
        addresses.push(ListenerBind { listen, port });
    }
    // `::1` and `0:0:0:0:0:0:0:1` are the same bind; comparison goes
    // through `IpAddr` so non-canonical spellings still collide.
    let mut seen = std::collections::HashSet::new();
    for b in &addresses {
        let ip = b.listen.parse::<IpAddr>().map_err(|_| {
            anyhow::anyhow!(
                "listeners[{}].listen: '{}' is not an IP literal",
                raw_l.name,
                b.listen
            )
        })?;
        if !seen.insert((ip, b.port)) {
            anyhow::bail!(
                "listeners[{}].listen: duplicate bind address '{}':{}",
                raw_l.name,
                b.listen,
                b.port
            );
        }
    }
    Ok(addresses)
}

/// Build a validated [`AnytlsListenerConfig`] from a raw `listeners:`
/// entry — the single semantic entry point for `type: anytls`, reached
/// identically by startup, `-t` and `PUT /configs` via
/// `build_named_listeners`. Performs NO file I/O: certificate material
/// stays as-written for bind-time resolution by the app.
///
/// `listen` may be ONE YAML string carrying comma-separated addresses;
/// each segment resolves through `resolve_listener_bind` in declaration
/// order (`port`/`listen:port` merge rules identical to single-address
/// listeners). `default_bind` fills an absent `listen`.
fn build_anytls_listener_spec(
    raw_l: &raw::RawListener,
    default_bind: &str,
) -> Result<AnytlsListenerConfig, anyhow::Error> {
    // Diagnostic order (spec §2.1): the security layer's SHAPE is judged
    // before any other field can return — `enable`/`udp`/users errors
    // must not mask a missing or malformed TLS declaration.
    //
    // ── certificate/private-key pairing shape — FIRST among the
    // substantive checks: whether a TLS layer exists at all decides how
    // every other key reads (`allow-insecure`, front layers, users).
    let tls_selected = match (raw_l.certificate.as_deref(), raw_l.private_key.as_deref()) {
        (Some(cert), Some(key)) => {
            if cert.trim().is_empty() || key.trim().is_empty() {
                anyhow::bail!(
                    "listeners[{}]: `certificate`/`private-key` must not be empty",
                    raw_l.name
                );
            }
            if is_pem_literal(cert) != is_pem_literal(key) {
                anyhow::bail!(
                    "listeners[{}]: `certificate`/`private-key` must use the same \
                     form — both inline PEM or both filesystem paths, not mixed",
                    raw_l.name
                );
            }
            true
        }
        (None, None) => false,
        _ => anyhow::bail!(
            "listeners[{}]: `certificate` and `private-key` must be provided \
             together",
            raw_l.name
        ),
    };

    // ── front-layer opaque blocks (shape + enabled flag type) ──
    let shadow_tls_on = anytls_front_layer_enabled(raw_l, "shadow-tls", raw_l.shadow_tls.as_ref())?;
    let res_tls_on = anytls_front_layer_enabled(raw_l, "res-tls", raw_l.res_tls.as_ref())?;
    let jls_on = anytls_front_layer_enabled(raw_l, "jls-config", raw_l.jls_config.as_ref())?;

    // ── security-mode mutual exclusivity (`allow-insecure` is excluded
    // from the count, matching upstream's TLS-layer enumeration) ──
    let mut enabled_layers: Vec<&str> = Vec::new();
    if tls_selected {
        enabled_layers.push("certificate/private-key");
    }
    if shadow_tls_on {
        enabled_layers.push("shadow-tls");
    }
    if res_tls_on {
        enabled_layers.push("res-tls");
    }
    if jls_on {
        enabled_layers.push("jls-config");
    }
    if enabled_layers.len() > 1 {
        anyhow::bail!(
            "listeners[{}]: `type: anytls` accepts at most one TLS/front layer \
             — enabled together: {}",
            raw_l.name,
            enabled_layers.join(", ")
        );
    }
    // A selected front layer is a hard gap, not an ignored key.
    for (key, on) in [
        ("shadow-tls", shadow_tls_on),
        ("res-tls", res_tls_on),
        ("jls-config", jls_on),
    ] {
        if on {
            anyhow::bail!(
                "listeners[{}].{key}: `{key}` front layers are not supported by \
                 meow's `type: anytls` inbound — remove it or terminate it \
                 upstream",
                raw_l.name
            );
        }
    }

    // ── mTLS / ECH — any non-empty RAW value is a hard error (never
    // silently ignored). Whitespace-only counts as a request: the key
    // carries a value the deployer typed, and meow cannot honour it.
    for (key, value) in [
        ("client-auth-type", raw_l.client_auth_type.as_deref()),
        ("client-auth-cert", raw_l.client_auth_cert.as_deref()),
        ("ech-key", raw_l.ech_key.as_deref()),
    ] {
        if value.is_some_and(|v| !v.is_empty()) {
            anyhow::bail!(
                "listeners[{}].{key}: `{key}` is not supported by meow's \
                 `type: anytls` inbound — remove it",
                raw_l.name
            );
        }
    }

    // ── the no-security gate ──
    let allow_insecure = raw_l.allow_insecure.unwrap_or(false);
    if !tls_selected && !allow_insecure {
        anyhow::bail!(
            "listeners[{}]: `type: anytls` requires `certificate` + `private-key` \
             (TLS), or the explicit `allow-insecure: true` plaintext opt-in",
            raw_l.name
        );
    }
    if !tls_selected && allow_insecure {
        warn!(
            "listeners[{}]: `allow-insecure: true` — the AnyTLS listener accepts \
             PLAINTEXT connections; credentials are visible to any on-path \
             observer. Use only on a trusted network or behind a tunnel",
            raw_l.name
        );
    }

    // ── `enable` — upstream-accepted but meaningless here: the entry's
    // presence is its enabled state. `false` is a hard error (silent
    // disable would be a dead config line); `true` warns redundant.
    match raw_l.enable {
        Some(false) => anyhow::bail!(
            "listeners[{}].enable: `false` is invalid — an AnyTLS listener entry \
             is enabled by existing; remove the entry to disable it",
            raw_l.name
        ),
        Some(true) => warn!(
            "listeners[{}].enable: `true` is redundant — the entry's presence \
             already enables the listener",
            raw_l.name
        ),
        None => {}
    }

    // ── `udp` — always supported, so `false` would be a lie; warn `true`.
    match raw_l.udp {
        Some(false) => anyhow::bail!(
            "listeners[{}].udp: `false` is invalid — AnyTLS inbound always \
             supports UoT v2; remove the key or set `true`",
            raw_l.name
        ),
        Some(true) => warn!(
            "listeners[{}].udp: `true` is redundant — AnyTLS inbound always \
             supports UoT v2",
            raw_l.name
        ),
        None => {}
    }

    // ── `users:` — absent/null/`{}` all mean "authenticate nothing"
    // (upstream's reject-all state): startup proceeds but warns once.
    // Usernames and passwords stay verbatim — no trimming, no
    // normalization — and empty values, duplicate keys and duplicate
    // password digests are hard errors. The LIST shape is `type: vless`'s
    // user table — a mapping is the only legal form here.
    let user_pairs: &[(String, String)] = match raw_l.users.as_ref() {
        None => &[],
        Some(raw::RawListenerUsers::Mapping(pairs)) => pairs,
        Some(raw::RawListenerUsers::List(_)) => anyhow::bail!(
            "listeners[{}].users: `type: anytls` takes a username → password MAPPING \
             (e.g. `users: {{alice: secret}}`); the list-of-entries shape belongs to \
             `type: vless` — reshape the key for the listener type you mean",
            raw_l.name
        ),
    };
    let mut digest_seen: std::collections::HashMap<[u8; 32], String> =
        std::collections::HashMap::new();
    let mut name_seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut users: Vec<AnytlsUser> = Vec::new();
    for (user, password) in user_pairs {
        if user.is_empty() {
            anyhow::bail!(
                "listeners[{}].users: empty username is not allowed",
                raw_l.name
            );
        }
        if password.is_empty() {
            anyhow::bail!(
                "listeners[{}].users: empty password for user '{user}' is not allowed",
                raw_l.name
            );
        }
        if !name_seen.insert(user.as_str()) {
            anyhow::bail!(
                "listeners[{}].users: duplicate username '{user}'",
                raw_l.name
            );
        }
        let digest = {
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            h.update(password.as_bytes());
            let out: [u8; 32] = h.finalize().into();
            out
        };
        if let Some(existing) = digest_seen.insert(digest, user.clone()) {
            anyhow::bail!(
                "listeners[{}].users: '{user}' shares a password (SHA-256 digest) \
                 with earlier user '{existing}' — users must have distinct passwords",
                raw_l.name
            );
        }
        users.push(AnytlsUser {
            name: user.clone(),
            password_sha256: digest,
        });
    }
    if users.is_empty() {
        warn!(
            "listeners[{}].users: empty/absent — the AnyTLS listener will \
             REJECT every authentication (upstream reject-all); add at \
             least one user to admit clients",
            raw_l.name
        );
    }

    // ── `padding-scheme` — shared contract with `PaddingFactory::new`;
    // validated here so `-t` and PUT fail fast, and the protocol layer
    // re-validates (it cannot fail after this gate). `""` is mihomo's
    // "no scheme" spelling — the listener normalizes it to the default.
    if let Some(scheme) = raw_l.padding_scheme.as_deref().filter(|s| !s.is_empty()) {
        meow_common::anytls_padding::validate_scheme(scheme.as_bytes())
            .map_err(|e| anyhow::anyhow!("listeners[{}].padding-scheme: {e}", raw_l.name))?;
    }

    // ── `kcp-tun`/`mux-option` — present but never consumed: warn like
    // the shadowsocks arm does. Shadowsocks-only keys get the same.
    for (key, set) in [
        ("kcp-tun", raw_l.kcp_tun.is_some()),
        ("mux-option", raw_l.mux_option.is_some()),
        ("cipher", raw_l.cipher.is_some()),
        ("password", raw_l.password.is_some()),
        ("simple-obfs", raw_l.simple_obfs.is_some()),
    ] {
        if set {
            warn!(
                "listeners[{}].{key}: `{key}` is not supported on `type: anytls`, \
                 ignored; remove it to suppress this warning",
                raw_l.name
            );
        }
    }

    let addresses = resolve_multi_listener_binds(raw_l, default_bind)?;

    Ok(AnytlsListenerConfig {
        users,
        certificate: raw_l.certificate.clone(),
        private_key: raw_l.private_key.clone(),
        allow_insecure,
        // Normalize `""` to `None`: both select `PaddingFactory::default()`
        // at bind time, so `PUT /configs` projection diffs treat them as
        // identical (F18).
        padding_scheme: raw_l
            .padding_scheme
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        addresses,
    })
}

/// Validate a REALITY `dest` string's shape: `host:port` with the port in
/// `1..=65535`, IPv6 bracketed, no URL/userinfo/path syntax. The host is
/// NOT charset-validated beyond separators — it may be a domain resolved
/// at cover-dial time, and startup/`-t` never resolve it. Returns the
/// host part and the port for the self-loop check.
fn parse_reality_dest(dest: &str, ctx: &str) -> Result<(String, u16), anyhow::Error> {
    if dest.is_empty() {
        anyhow::bail!("{ctx}: must not be empty — a REALITY server needs a cover target");
    }
    if dest.contains("://") {
        anyhow::bail!(
            "{ctx}: '{dest}' looks like a URL — use bare `host:port` (e.g. `www.example.com:443`)"
        );
    }
    if dest.contains('@') || dest.contains('/') {
        anyhow::bail!(
            "{ctx}: userinfo/path syntax is not valid here — use bare `host:port` \
             (e.g. `www.example.com:443`)"
        );
    }
    let (host, port_str) = if let Some(rest) = dest.strip_prefix('[') {
        // Bracketed IPv6: `]` then `:port`, nothing else.
        let Some((host, tail)) = rest.split_once(']') else {
            anyhow::bail!("{ctx}: bracketed IPv6 must close as `[addr]:port`");
        };
        let Some(port_str) = tail.strip_prefix(':') else {
            anyhow::bail!("{ctx}: bracketed IPv6 must be followed by `:port`");
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            anyhow::bail!("{ctx}: '{host}' inside the brackets is not an IPv6 literal");
        }
        (host.to_string(), port_str)
    } else {
        // Unbracketed: exactly one colon separates host and port — more
        // means an unbracketed IPv6 literal, none means a missing port.
        let Some((host, port_str)) = dest.rsplit_once(':') else {
            anyhow::bail!("{ctx}: missing `:port` — use `host:port`");
        };
        if host.contains(':') {
            anyhow::bail!("{ctx}: IPv6 destinations must be bracketed — `[addr]:port`");
        }
        (host.to_string(), port_str)
    };
    if host.is_empty() {
        anyhow::bail!("{ctx}: the host part must not be empty");
    }
    if host.chars().any(char::is_whitespace) {
        anyhow::bail!("{ctx}: the host must not contain whitespace");
    }
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!("{ctx}: port must be decimal digits in 1..=65535");
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("{ctx}: port must be in 1..=65535"))?;
    if port == 0 {
        anyhow::bail!("{ctx}: port 0 is not a dialable cover target — use 1..=65535");
    }
    Ok((host, port))
}

/// Split a REALITY cover `dest` with the same shape rules the config
/// builder enforces. Exposed for the runtime listener conversion so the
/// wire-format parser has one owner; no DNS or network I/O happens here.
pub fn parse_vless_reality_dest(dest: &str) -> Result<(String, u16), anyhow::Error> {
    parse_reality_dest(dest, "reality-config.dest")
}

const MAX_TLS_IDENTITY_FILE_BYTES: u64 = 1 << 20;

fn read_tls_identity_file(path: &std::path::Path, what: &str) -> Result<Vec<u8>, anyhow::Error> {
    use std::io::Read as _;

    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("{what}: cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!("{what}: {} is not a regular file", path.display());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NONBLOCK);
    let file = opts
        .open(path)
        .map_err(|e| anyhow::anyhow!("{what}: cannot open {}: {e}", path.display()))?;
    let mut buf = Vec::new();
    file.take(MAX_TLS_IDENTITY_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("{what}: cannot read {}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_TLS_IDENTITY_FILE_BYTES {
        anyhow::bail!(
            "{what}: {} exceeds {} bytes",
            path.display(),
            MAX_TLS_IDENTITY_FILE_BYTES
        );
    }
    Ok(buf)
}

/// Load a listener certificate/private-key pair exactly as the TLS-server
/// inbounds do: both inline PEM or both home-contained regular files, each
/// file capped well below any plausible certificate chain.
pub fn load_tls_identity_pair(
    cert: &str,
    key: &str,
    protocol: &str,
) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert_inline = is_pem_literal(cert);
    let key_inline = is_pem_literal(key);
    if cert_inline != key_inline {
        anyhow::bail!(
            "{protocol} certificate and private-key must be both inline PEM or both file paths"
        );
    }
    if cert_inline {
        return Ok((cert.as_bytes().to_vec(), key.as_bytes().to_vec()));
    }
    let cert_path = resolve_home_contained(std::path::Path::new(cert))
        .map_err(|e| anyhow::anyhow!("{protocol} certificate: {e}"))?;
    let key_path = resolve_home_contained(std::path::Path::new(key))
        .map_err(|e| anyhow::anyhow!("{protocol} private-key: {e}"))?;
    Ok((
        read_tls_identity_file(&cert_path, &format!("{protocol} certificate"))?,
        read_tls_identity_file(&key_path, &format!("{protocol} private-key"))?,
    ))
}

/// Read a required string out of a `reality-config`-style captured map.
/// `null` counts as missing — YAML writes it for a keyless `dest:` line,
/// and a null is never the string the operator means.
fn reality_required_string<'a>(
    map: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    ctx: &str,
) -> Result<&'a str, anyhow::Error> {
    match map.get(key) {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(s),
        Some(serde_json::Value::String(_)) => {
            anyhow::bail!("{ctx}.{key}: must not be empty")
        }
        Some(_) => anyhow::bail!("{ctx}.{key}: must be a string"),
        None => anyhow::bail!("{ctx}.{key}: required — a REALITY server cannot operate without it"),
    }
}

/// Read a required non-empty list of strings out of a captured map.
fn reality_required_string_list<'a>(
    map: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    ctx: &str,
) -> Result<&'a [serde_json::Value], anyhow::Error> {
    match map.get(key) {
        Some(serde_json::Value::Array(list)) if !list.is_empty() => Ok(list),
        Some(serde_json::Value::Array(_)) => {
            anyhow::bail!("{ctx}.{key}: must not be an empty list")
        }
        Some(_) => anyhow::bail!("{ctx}.{key}: must be a list of strings"),
        None => anyhow::bail!("{ctx}.{key}: required (a non-empty list of strings)"),
    }
}

/// Validate one `server-names` entry as an exact-match ASCII DNS A-label
/// name: no wildcard, no IP literal, no trailing/leading dot, non-empty
/// labels of `[A-Za-z0-9-]` without leading/trailing hyphens, total
/// length within the DNS wire limit.
fn validate_server_name(name: &str, ctx: &str) -> Result<(), anyhow::Error> {
    if name.is_empty() {
        anyhow::bail!("{ctx}: entries must not be empty");
    }
    if !name.is_ascii() {
        anyhow::bail!(
            "{ctx}: non-ASCII names are not accepted — write the punycode A-label \
             (e.g. `xn--…`) instead"
        );
    }
    if name.contains('*') {
        anyhow::bail!(
            "{ctx}: wildcards are not supported — server-names is an exact-match \
             allowlist; list every name explicitly"
        );
    }
    if name.ends_with('.') || name.starts_with('.') {
        anyhow::bail!("{ctx}: trailing/leading dots are not accepted — use the bare DNS name");
    }
    if name.parse::<IpAddr>().is_ok() {
        anyhow::bail!(
            "{ctx}: IP literals are not valid server-names entries — the allowlist \
             matches ClientHello SNI hostnames"
        );
    }
    if name.len() > 253 {
        anyhow::bail!("{ctx}: name exceeds the 253-byte DNS limit");
    }
    for label in name.split('.') {
        if label.is_empty() {
            anyhow::bail!("{ctx}: empty label (double dot) is not a valid DNS name");
        }
        if label.len() > 63 {
            anyhow::bail!("{ctx}: a label exceeds the 63-byte DNS limit");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            anyhow::bail!("{ctx}: labels may only contain ASCII letters, digits and hyphens");
        }
        if label.starts_with('-') || label.ends_with('-') {
            anyhow::bail!("{ctx}: labels must not start or end with a hyphen");
        }
    }
    Ok(())
}

/// Validate the config-dependent parts of a VLESS listener security
/// identity without binding sockets, resolving names, or contacting the
/// REALITY cover. Standard TLS runs the same BoringSSL certificate/key
/// pairing check as the server acceptor; REALITY checks the parsed cover
/// endpoint, cardinality, and SNI names that acceptor construction gates.
pub fn validate_vless_security_identity(security: &VlessSecurity) -> Result<(), anyhow::Error> {
    match security {
        VlessSecurity::StandardTls {
            certificate,
            private_key,
            alpn,
        } => {
            let (certificate_chain_pem, private_key_pem) =
                load_tls_identity_pair(certificate, private_key, "vless")?;
            meow_transport::tls::server::TlsServer::new(
                &meow_transport::tls::server::TlsServerConfig {
                    certificate_chain_pem,
                    private_key_pem,
                    alpn: alpn.clone(),
                },
            )
            .map_err(|e| anyhow::anyhow!("vless TLS: {e}"))?;
        }
        VlessSecurity::Reality(reality) => {
            let (dest_host, dest_port) = parse_vless_reality_dest(&reality.dest)?;
            if dest_host != reality.dest_host || dest_port != reality.dest_port {
                anyhow::bail!(
                    "reality-config.dest: structured cover host/port do not match the dest string"
                );
            }
            if reality.short_ids.is_empty() || reality.short_ids.len() > 64 {
                anyhow::bail!("reality-config.short-id: must contain 1..=64 entries");
            }
            if reality.server_names.is_empty() || reality.server_names.len() > 64 {
                anyhow::bail!("reality-config.server-names: must contain 1..=64 entries");
            }
            for (i, name) in reality.server_names.iter().enumerate() {
                validate_server_name(name, &format!("reality-config.server-names[{i}]"))?;
            }
            reality
                .mimic
                .validate()
                .map_err(|e| anyhow::anyhow!("reality-config.mimic: {e}"))?;
        }
    }
    Ok(())
}

/// Validate one `limit-fallback-{upload,download}` sub-map: optional
/// keys `after-bytes`/`bytes-per-sec`/`burst-bytes-per-sec`, non-negative
/// integers; unknown keys hard-error.
fn parse_limit_fallback(
    value: Option<&serde_json::Value>,
    ctx: &str,
) -> Result<RealityLimitFallback, anyhow::Error> {
    let mut out = RealityLimitFallback::default();
    let Some(value) = value else {
        return Ok(out);
    };
    if value.is_null() {
        return Ok(out);
    }
    let Some(obj) = value.as_object() else {
        anyhow::bail!(
            "{ctx}: must be a mapping of `after-bytes`/`bytes-per-sec`/`burst-bytes-per-sec`"
        );
    };
    for (key, val) in obj {
        let slot = match key.as_str() {
            "after-bytes" => &mut out.after_bytes,
            "bytes-per-sec" => &mut out.bytes_per_sec,
            "burst-bytes-per-sec" => &mut out.burst_bytes_per_sec,
            other => anyhow::bail!(
                "{ctx}.{other}: unknown key — the limiter only takes \
                 `after-bytes`/`bytes-per-sec`/`burst-bytes-per-sec`"
            ),
        };
        match val {
            serde_json::Value::Number(n) => {
                let Some(v) = n.as_u64() else {
                    anyhow::bail!("{ctx}.{key}: must be a non-negative integer (bytes)");
                };
                *slot = v;
            }
            _ => anyhow::bail!("{ctx}.{key}: must be a non-negative integer (bytes)"),
        }
    }
    Ok(out)
}

/// Parse `reality-config.mimic` into the normalized shared runtime spec.
/// Absent and `{}` both mean the complete default; every explicit key is
/// validated even when `mode: off` selects the v1 path.
fn parse_vless_reality_mimic(
    obj: &serde_json::Map<String, serde_json::Value>,
    ctx: &str,
) -> Result<meow_common::VlessRealityMimicSpec, anyhow::Error> {
    use meow_common::{
        VlessRealityMimicMode, VlessRealityMimicSpec, MIMIC_MAX_CONCURRENT_PROBES_RANGE,
        MIMIC_PROBE_TIMEOUT_MS_RANGE, MIMIC_QUIESCENCE_MAX_MS_RANGE, MIMIC_QUIESCENCE_MIN_MS_RANGE,
    };

    let mut out = VlessRealityMimicSpec::default();
    let Some(value) = obj.get("mimic") else {
        return Ok(out);
    };
    let mctx = format!("{ctx}.mimic");
    if value.is_null() {
        anyhow::bail!("{mctx}: explicit null is not accepted — omit it or use a mapping");
    }
    let Some(mimic) = value.as_object() else {
        anyhow::bail!("{mctx}: must be a mapping");
    };
    for key in mimic.keys() {
        if !matches!(
            key.as_str(),
            "mode"
                | "probe-timeout-ms"
                | "quiescence-min-ms"
                | "quiescence-max-ms"
                | "max-concurrent-probes"
        ) {
            anyhow::bail!("{mctx}.{key}: unknown key");
        }
    }

    if let Some(value) = mimic.get("mode") {
        let serde_json::Value::String(mode) = value else {
            anyhow::bail!("{mctx}.mode: must be exactly `dial-first` or `off`");
        };
        out.mode = match mode.as_str() {
            "dial-first" => VlessRealityMimicMode::DialFirst,
            "off" => VlessRealityMimicMode::Off,
            _ => anyhow::bail!("{mctx}.mode: must be exactly `dial-first` or `off`"),
        };
    }

    fn integer_field(
        mimic: &serde_json::Map<String, serde_json::Value>,
        key: &str,
        range: std::ops::RangeInclusive<u64>,
        ctx: &str,
    ) -> Result<Option<u64>, anyhow::Error> {
        let Some(value) = mimic.get(key) else {
            return Ok(None);
        };
        if value.is_null() {
            anyhow::bail!("{ctx}.{key}: explicit null is not accepted — omit the key");
        }
        let Some(v) = value.as_u64() else {
            anyhow::bail!("{ctx}.{key}: must be an integer in {range:?}");
        };
        if !range.contains(&v) {
            anyhow::bail!("{ctx}.{key}: outside {range:?}");
        }
        Ok(Some(v))
    }

    if let Some(v) = integer_field(
        mimic,
        "probe-timeout-ms",
        MIMIC_PROBE_TIMEOUT_MS_RANGE,
        &mctx,
    )? {
        out.probe_timeout_ms = v;
    }
    if let Some(v) = integer_field(
        mimic,
        "quiescence-min-ms",
        MIMIC_QUIESCENCE_MIN_MS_RANGE,
        &mctx,
    )? {
        out.quiescence_min_ms = v;
    }
    if let Some(v) = integer_field(
        mimic,
        "quiescence-max-ms",
        MIMIC_QUIESCENCE_MAX_MS_RANGE,
        &mctx,
    )? {
        out.quiescence_max_ms = v;
    }
    if let Some(v) = integer_field(
        mimic,
        "max-concurrent-probes",
        (*MIMIC_MAX_CONCURRENT_PROBES_RANGE.start() as u64)
            ..=(*MIMIC_MAX_CONCURRENT_PROBES_RANGE.end() as u64),
        &mctx,
    )? {
        out.max_concurrent_probes = usize::try_from(v).expect("bounded by [1,256]");
    }

    out.validate().map_err(|e| anyhow::anyhow!("{mctx}: {e}"))?;
    Ok(out)
}

/// Build the `reality-config` block of a `type: vless` listener. Every
/// key rule follows the mihomo `RealityConfig` shape as the spec
/// adjudicates it: `dest`/`private-key`/`short-id`/`server-names`
/// required, `max-time-difference` optional microseconds, the
/// limit-fallback pair optional, everything else a hard error — unknown,
/// Xray-only (`xver`, client-version pins, `show`, `masterKeyLog`), the
/// outbound spelling, or the unsupported nested `proxy`.
fn build_vless_reality_config(
    raw_l: &raw::RawListener,
    value: &serde_json::Value,
) -> Result<VlessRealityConfig, anyhow::Error> {
    let ctx = format!("listeners[{}].reality-config", raw_l.name);
    let Some(obj) = value.as_object() else {
        anyhow::bail!("{ctx}: must be a mapping — see the `type: vless` REALITY example");
    };
    if obj.is_empty() {
        anyhow::bail!(
            "{ctx}: an empty map is not a REALITY config — either fill in \
             `dest`/`private-key`/`short-id`/`server-names`, or drop the key and use \
             the `certificate` + `private-key` pair (standard TLS)"
        );
    }

    // Unknown-key gate FIRST: a typo'd key must surface before any
    // required-key complaint, or the operator fixes the wrong problem.
    // Known Xray/outbound-only spellings get their migration hint.
    for key in obj.keys() {
        match key.as_str() {
            "dest"
            | "private-key"
            | "short-id"
            | "server-names"
            | "max-time-difference"
            | "mimic"
            | "limit-fallback-upload"
            | "limit-fallback-download" => {}
            "target" => anyhow::bail!(
                "{ctx}.target: Xray's spelling — meow follows mihomo: rename it to `dest`"
            ),
            "proxy" => anyhow::bail!(
                "{ctx}.proxy: dialing the cover through a proxy is not supported — \
                 the cover `dest` is always dialed directly; remove the key"
            ),
            "xver" => anyhow::bail!(
                "{ctx}.xver: PROXY-protocol handoff to the cover target is not \
                 supported — remove the key"
            ),
            "min-client-ver" | "max-client-ver" | "minClientVer" | "maxClientVer" => {
                anyhow::bail!(
                    "{ctx}.{key}: client-version pinning is not supported — remove the key"
                )
            }
            "show" | "masterKeyLog" | "master-key-log" | "mldsa65" | "mldsa65-verify"
            | "server-name" | "short_ids" | "short-ids" => anyhow::bail!(
                "{ctx}.{key}: not a meow REALITY server key — supported keys are \
                 `dest`, `private-key`, `short-id`, `server-names`, \
                 `max-time-difference`, `mimic`, `limit-fallback-upload`, `limit-fallback-download`"
            ),
            other => anyhow::bail!(
                "{ctx}.{other}: unknown key — supported keys are `dest`, `private-key`, \
                 `short-id`, `server-names`, `max-time-difference`, `mimic`, \
                 `limit-fallback-upload`, `limit-fallback-download`"
            ),
        }
    }

    // ── dest — shape only; never resolved here (startup/`-t` do no
    // network I/O), and a literal self-loop is checked by the caller once
    // the listener's own binds are known.
    let dest = reality_required_string(obj, "dest", &ctx)?;
    let (dest_host, dest_port) = parse_reality_dest(dest, &format!("{ctx}.dest"))?;

    // ── private-key — unpadded URL-safe base64, exactly 32 bytes of
    // X25519 private key; never a PEM block or a path.
    let private_key_str = reality_required_string(obj, "private-key", &ctx)?;
    let private_key = {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(private_key_str.as_bytes())
            .map_err(|_| {
                anyhow::anyhow!(
                    "{ctx}.private-key: must be unpadded URL-safe base64 of the 32-byte \
                     X25519 private key (as `xray x25519` prints it) — not PEM, hex, \
                     or a file path"
                )
            })?;
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
            anyhow::anyhow!(
                "{ctx}.private-key: must decode to exactly 32 bytes (an X25519 private key)"
            )
        })?
    };

    // ── short-id — non-empty string list; each even hex, at most 16
    // chars, right-zero-padded to the 8-byte comparison form. Empty
    // strings and all-zero values are rejected rather than turned into
    // implicit credentials; duplicates are judged on the padded form, so
    // `ab` and `ab00` collide. Values are never echoed into errors —
    // short IDs are on the reality spec's redaction list.
    let mut short_ids: Vec<[u8; 8]> = Vec::new();
    let mut seen_ids: std::collections::HashSet<[u8; 8]> = std::collections::HashSet::new();
    for (i, entry) in reality_required_string_list(obj, "short-id", &ctx)?
        .iter()
        .enumerate()
    {
        let serde_json::Value::String(s) = entry else {
            anyhow::bail!("{ctx}.short-id[{i}]: must be a hex string (quote it)");
        };
        if s.is_empty() {
            anyhow::bail!(
                "{ctx}.short-id[{i}]: empty string is not a wildcard — meow does not \
                 mint implicit credentials; use a real hex short-id"
            );
        }
        let padded =
            decode_padded_short_id(s).map_err(|e| anyhow::anyhow!("{ctx}.short-id[{i}]: {e}"))?;
        if padded == [0u8; 8] {
            anyhow::bail!(
                "{ctx}.short-id[{i}]: the all-zero value is not accepted — meow does \
                 not mint implicit credentials; use a real hex short-id"
            );
        }
        if !seen_ids.insert(padded) {
            anyhow::bail!(
                "{ctx}.short-id[{i}]: duplicates an earlier entry after zero-padding \
                 (e.g. \"ab\" and \"ab00\" are the same id) — keep one"
            );
        }
        short_ids.push(padded);
    }
    if short_ids.len() > 64 {
        anyhow::bail!(
            "{ctx}.short-id: at most 64 entries — the REALITY acceptor cannot serve more"
        );
    }

    // ── server-names — the exact-match SNI allowlist.
    let mut server_names: Vec<String> = Vec::new();
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (i, entry) in reality_required_string_list(obj, "server-names", &ctx)?
        .iter()
        .enumerate()
    {
        let serde_json::Value::String(name) = entry else {
            anyhow::bail!("{ctx}.server-names[{i}]: must be a string");
        };
        validate_server_name(name, &format!("{ctx}.server-names[{i}]"))?;
        if !seen_names.insert(name.to_ascii_lowercase()) {
            anyhow::bail!("{ctx}.server-names[{i}]: '{name}' duplicates an earlier entry");
        }
        server_names.push(name.clone());
    }
    if server_names.len() > 64 {
        anyhow::bail!(
            "{ctx}.server-names: at most 64 entries — the REALITY acceptor cannot serve more"
        );
    }

    // ── max-time-difference — optional microseconds; absent defaults to
    // 120 s, explicit 0 disables the freshness check. Negative or
    // non-integer values hard-error.
    let max_time_difference_us = match obj.get("max-time-difference") {
        None | Some(serde_json::Value::Null) => 120_000_000,
        Some(serde_json::Value::Number(n)) => match n.as_u64() {
            Some(v) => v,
            None => anyhow::bail!(
                "{ctx}.max-time-difference: must be a non-negative integer of \
                 microseconds (0 disables the freshness check)"
            ),
        },
        Some(_) => anyhow::bail!(
            "{ctx}.max-time-difference: must be a non-negative integer of \
             microseconds (0 disables the freshness check)"
        ),
    };

    let limit_fallback_upload = parse_limit_fallback(
        obj.get("limit-fallback-upload"),
        &format!("{ctx}.limit-fallback-upload"),
    )?;
    let limit_fallback_download = parse_limit_fallback(
        obj.get("limit-fallback-download"),
        &format!("{ctx}.limit-fallback-download"),
    )?;
    let mimic = parse_vless_reality_mimic(obj, &ctx)?;

    Ok(VlessRealityConfig {
        dest: dest.to_string(),
        dest_host,
        dest_port,
        private_key,
        short_ids,
        server_names,
        max_time_difference_us,
        limit_fallback_upload,
        limit_fallback_download,
        mimic,
    })
}

/// Build a validated [`VlessListenerConfig`] from a raw `listeners:`
/// entry — the single semantic entry point for `type: vless`, reached
/// identically by startup, `-t` and `PUT /configs` via
/// `build_named_listeners`. Performs NO file I/O and NO DNS resolution:
/// certificate material stays as-written, `reality-config.dest` stays
/// as-written (shape-checked only).
///
/// The contract, per the vision-inbound spec's key-by-key adjudication:
///
/// - The outer security mode is a union: a flat `certificate` +
///   `private-key` pair (standard TLS 1.3) XOR a non-empty
///   `reality-config`. Neither present, any half pair, or both present
///   are hard errors — there is NO plaintext VLESS.
/// - `users` is a non-empty LIST of `{username, uuid, flow}` entries;
///   every field required, `flow` exactly `xtls-rprx-vision` (the
///   `-udp443` suffix is client-local and meaningless on a server),
///   usernames/UUIDs unique, UUID format strict (canonical hyphens or
///   32 bare hex), all-zero UUID rejected.
/// - `decryption` absent/`""`/`none` only; `encryption` (outbound key)
///   hard-errors with a hint.
/// - `client-auth-type`/`client-auth-cert`/`ech-key` absent or empty;
///   `allow-insecure` absent or `false` (never `true` — no plaintext).
/// - Deferred upstream keys (`ws-path`, `xhttp-config`,
///   `grpc-service-name`, `shadow-tls`, `res-tls`, `jls-config`,
///   `mux-option`) hard-error when non-null — including empty maps —
///   rather than silently degrading to bare TCP.
/// - Keys that are not mihomo `VlessOption` fields (`tls`,
///   `certificates`, `fallback(s)`, `network`, top-level `flow`,
///   `reality-opts`) hard-error with migration hints; every other
///   unknown key hard-errors — this listener terminates credentials, so
///   a silently-dead key is a security event, not forward-compat.
/// - `udp` defaults `true`; `false` rejects Mux/XUDP at the VLESS header.
/// - `alpn` is a standard-TLS-only list of printable-ASCII strings
///   (1–255 B each, unique, at most 16); non-empty under REALITY errors.
fn build_vless_listener_spec(
    raw_l: &raw::RawListener,
    default_bind: &str,
) -> Result<VlessListenerConfig, anyhow::Error> {
    // Diagnostic order: the security-mode SHAPE first — whether TLS
    // exists at all and in which form decides how every other key reads.

    // ── reality-config presence — explicit null is absent; anything
    // else (even an empty map) is a REALITY request. Judged before the
    // certificate pair so the exclusivity verdict below names the real
    // defect (two security modes at once) instead of a half pair's.
    let reality_value = raw_l
        .reality_config
        .as_ref()
        .map(|v| &v.0)
        .filter(|v| !v.is_null());

    // ── mutual exclusivity: ANY flat certificate field with REALITY is
    // a hard error (even a half pair — the spec refuses to guess whether
    // the operator meant TLS or REALITY).
    if reality_value.is_some() && (raw_l.certificate.is_some() || raw_l.private_key.is_some()) {
        anyhow::bail!(
            "listeners[{}]: `reality-config` is mutually exclusive with the flat \
             `certificate`/`private-key` pair — the outer transport is either a \
             standard TLS certificate pair or REALITY; remove one of them",
            raw_l.name
        );
    }

    // ── certificate/private-key pairing shape — the pair is validated
    // for FORM only (non-empty, same spelling); the bytes are loaded and
    // verified at bind time, where the identity is actually consumed.
    let cert_pair = match (raw_l.certificate.as_deref(), raw_l.private_key.as_deref()) {
        (Some(cert), Some(key)) => {
            if cert.trim().is_empty() || key.trim().is_empty() {
                anyhow::bail!(
                    "listeners[{}]: `certificate`/`private-key` must not be empty",
                    raw_l.name
                );
            }
            if is_pem_literal(cert) != is_pem_literal(key) {
                anyhow::bail!(
                    "listeners[{}]: `certificate`/`private-key` must use the same \
                     form — both inline PEM or both filesystem paths, not mixed",
                    raw_l.name
                );
            }
            Some((cert.to_string(), key.to_string()))
        }
        (None, None) => None,
        _ => anyhow::bail!(
            "listeners[{}]: `certificate` and `private-key` must be provided \
             together",
            raw_l.name
        ),
    };

    // ── no-security gate: there is no plaintext VLESS.
    if reality_value.is_none() && cert_pair.is_none() {
        anyhow::bail!(
            "listeners[{}]: `type: vless` has no plaintext mode — configure either a \
             `certificate` + `private-key` pair (standard TLS 1.3) or a \
             `reality-config` block",
            raw_l.name
        );
    }

    // ── REALITY mode: validate the block now so a malformed one errors
    // ahead of unrelated fields.
    let reality = match reality_value {
        Some(value) => Some(build_vless_reality_config(raw_l, value)?),
        None => None,
    };

    // ── mTLS / ECH — any non-empty raw value is a hard error; a
    // whitespace-only string still counts as a request meow cannot
    // honour (the anytls rule).
    for (key, value) in [
        ("client-auth-type", raw_l.client_auth_type.as_deref()),
        ("client-auth-cert", raw_l.client_auth_cert.as_deref()),
        ("ech-key", raw_l.ech_key.as_deref()),
    ] {
        if value.is_some_and(|v| !v.is_empty()) {
            anyhow::bail!(
                "listeners[{}].{key}: `{key}` is not supported by meow's \
                 `type: vless` inbound — remove it",
                raw_l.name
            );
        }
    }

    // ── `allow-insecure` — never a plaintext escape hatch here: only
    // absent or `false` is legal, even with a certificate pair present.
    if raw_l.allow_insecure == Some(true) {
        anyhow::bail!(
            "listeners[{}].allow-insecure: `true` is invalid on `type: vless` — the \
             inbound has no plaintext mode (VLESS credentials inside cleartext are \
             trivially harvestable); remove the key and keep TLS",
            raw_l.name
        );
    }

    // ── `decryption` — absent/`""`/`none` equivalent; anything else
    // asks for VLESS encryption meow does not serve.
    if let Some(decryption) = raw_l.decryption.as_deref() {
        if !decryption.is_empty() && decryption != "none" {
            anyhow::bail!(
                "listeners[{}].decryption: value is not supported — meow's VLESS \
                 inbound serves only `decryption: none` (the outer TLS/REALITY layer \
                 is the encryption); remove the key or set `none`",
                raw_l.name
            );
        }
    }

    // ── deferred upstream keys — non-null configuration hard-errors
    // (including empty maps): silently dropping them would degrade the
    // listener to bare TCP while the operator believes a transport or
    // front layer is in place. Explicit nulls carry no intent and pass.
    for (key, value) in [
        ("shadow-tls", raw_l.shadow_tls.as_ref()),
        ("res-tls", raw_l.res_tls.as_ref()),
        ("jls-config", raw_l.jls_config.as_ref()),
        ("mux-option", raw_l.mux_option.as_ref()),
    ] {
        if let Some(value) = value.filter(|v| !v.is_null()) {
            let _ = value;
            anyhow::bail!(
                "listeners[{}].{key}: `{key}` is a mihomo VLESS listener key meow \
                 does not serve in this release — the inbound runs on native TCP \
                 only; remove it (there is no silent fallback)",
                raw_l.name
            );
        }
    }

    // ── unknown/misplaced keys. Everything in `extra` is a hard error
    // on vless; the recognized misfits get their migration hint first.
    // Sorted for determinism; only the first defect is reported — the
    // unconditional bail below means the loop shape would never iterate
    // twice, so an explicit `first` keeps the intent obvious.
    let mut extra_keys: Vec<&String> = raw_l.extra.keys().collect();
    extra_keys.sort();
    if let Some(key) = extra_keys.first() {
        let key = key.as_str();
        let hint = match key {
            "encryption" => "`encryption` is the OUTBOUND direction's key — on a \
                 `type: vless` listener the inbound selector is `decryption`, and \
                 the only served value is `none`"
                .to_string(),
            "reality-opts" => "`reality-opts` is the outbound spelling — the \
                 inbound REALITY block is `reality-config`"
                .to_string(),
            "tls" | "certificates" => format!(
                "`{key}` is not a mihomo VLESS listener key — TLS is enabled by the \
                 flat `certificate` + `private-key` pair (or `reality-config`)"
            ),
            "fallback" | "fallbacks" => format!(
                "`{key}` is not served: meow's VLESS inbound has no fallback — \
                 unauthenticated connections get no VLESS response (REALITY mode \
                 relays them to the cover `dest` instead)"
            ),
            "network" => "`network` is not served: meow's VLESS inbound runs on \
                 native TCP only (no ws/grpc/xhttp)"
                .to_string(),
            "flow" => "`flow` is a per-user key here — write it inside each \
                 `users` entry, not at the listener level"
                .to_string(),
            "ws-path" | "xhttp-config" | "grpc-service-name" => format!(
                "`{key}` is a mihomo VLESS listener key meow does not serve in this \
                 release — the inbound runs on native TCP only; remove it"
            ),
            other => {
                // Near-misses of served keys get named before the
                // generic verdict.
                let near = match other {
                    "user" | "username" => Some("did you mean `users`?"),
                    "privatekey" | "private_key" => Some("did you mean `private-key`?"),
                    "reality" | "realityconfig" => Some("did you mean `reality-config`?"),
                    "short-id" | "short-ids" | "server-names" | "dest" => {
                        Some("REALITY keys nest under `reality-config`, not the listener")
                    }
                    _ => None,
                };
                match near {
                    Some(near) => format!("unknown key — {near}"),
                    None => "unknown key — meow's `type: vless` listener rejects keys it \
                         does not know rather than silently ignoring them (a dead key \
                         on a credential-terminating inbound hides config bugs)"
                        .to_string(),
                }
            }
        };
        anyhow::bail!("listeners[{}].{key}: {hint}", raw_l.name);
    }

    // ── `users` — a non-empty LIST of strict `{username, uuid, flow}`
    // entries. The mapping shape is anytls's — a different protocol.
    let entries: &[serde_json::Value] = match raw_l.users.as_ref() {
        Some(raw::RawListenerUsers::List(entries)) if !entries.is_empty() => entries,
        Some(raw::RawListenerUsers::List(_)) => anyhow::bail!(
            "listeners[{}].users: must not be empty — a VLESS listener without users \
             authenticates nothing; add at least one `{{username, uuid, flow}}` entry",
            raw_l.name
        ),
        Some(raw::RawListenerUsers::Mapping(_)) => anyhow::bail!(
            "listeners[{}].users: `type: vless` takes a LIST of \
             `{{username, uuid, flow}}` entries — the username → password mapping \
             shape belongs to `type: anytls`",
            raw_l.name
        ),
        None => anyhow::bail!(
            "listeners[{}]: `type: vless` requires a non-empty `users` list of \
             `{{username, uuid, flow}}` entries — the UUID is the bearer credential \
             every client authenticates with",
            raw_l.name
        ),
    };
    let mut users: Vec<VlessUser> = Vec::with_capacity(entries.len());
    let mut name_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut uuid_seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        let ctx = format!("listeners[{}].users[{i}]", raw_l.name);
        let Some(obj) = entry.as_object() else {
            anyhow::bail!("{ctx}: each user entry must be a mapping of `username`, `uuid`, `flow`");
        };
        for key in obj.keys() {
            if !matches!(key.as_str(), "username" | "uuid" | "flow") {
                anyhow::bail!(
                    "{ctx}.{key}: unknown key — a vless user entry is exactly \
                     `username`, `uuid`, `flow`"
                );
            }
        }
        let username = match obj.get("username") {
            Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
            Some(serde_json::Value::String(_)) => {
                anyhow::bail!("{ctx}.username: must not be empty — it feeds `IN-USER` rules")
            }
            Some(_) => anyhow::bail!("{ctx}.username: must be a string"),
            None => anyhow::bail!(
                "{ctx}.username: required — upstream tolerates its absence, meow does \
                 not: the username is what `IN-USER` rules match on"
            ),
        };
        if !name_seen.insert(username.clone()) {
            anyhow::bail!("{ctx}.username: '{username}' duplicates an earlier entry");
        }
        // The UUID is never echoed into the error — parse errors are on
        // the redaction list too.
        let uuid_str = match obj.get("uuid") {
            Some(serde_json::Value::String(s)) => s,
            Some(_) => anyhow::bail!("{ctx}.uuid: must be a string"),
            None => anyhow::bail!("{ctx}.uuid: required — the bearer credential"),
        };
        let uuid = parse_strict_uuid(uuid_str).map_err(|_| {
            anyhow::anyhow!(
                "{ctx}.uuid: invalid UUID — use the canonical hyphenated form \
                 (8-4-4-4-12 hex groups) or 32 bare hex digits"
            )
        })?;
        if uuid == [0u8; 16] {
            anyhow::bail!(
                "{ctx}.uuid: the all-zero UUID is not a credential — generate a real \
                 one (e.g. `xray uuid`)"
            );
        }
        if !uuid_seen.insert(uuid) {
            anyhow::bail!(
                "{ctx}.uuid: duplicates an earlier user's UUID — credentials must be \
                 distinct per user"
            );
        }
        match obj.get("flow") {
            Some(serde_json::Value::String(flow)) if flow == "xtls-rprx-vision" => {}
            Some(serde_json::Value::String(flow)) if flow == "xtls-rprx-vision-udp443" => {
                anyhow::bail!(
                    "{ctx}.flow: `xtls-rprx-vision-udp443` is client-local syntax — on \
                     the wire the flow is always the 16-char `xtls-rprx-vision` and \
                     UDP/443 gating is purely the client's own policy; write plain \
                     `xtls-rprx-vision` here"
                )
            }
            Some(serde_json::Value::String(flow)) if flow.starts_with("xtls-rprx-vision") => {
                anyhow::bail!(
                    "{ctx}.flow: only the literal `xtls-rprx-vision` is accepted — \
                     suffixes are client-local syntax and never reach the wire"
                )
            }
            Some(serde_json::Value::String(flow)) if flow.is_empty() => {
                anyhow::bail!(
                    "{ctx}.flow: empty flow means plaintext VLESS without vision \
                     padding — meow's inbound serves only `xtls-rprx-vision`"
                )
            }
            Some(serde_json::Value::String(flow)) => {
                anyhow::bail!(
                    "{ctx}.flow: '{flow}' is not supported — meow's VLESS inbound \
                     serves only `xtls-rprx-vision` (there is no plain/legacy flow)"
                )
            }
            Some(_) => anyhow::bail!("{ctx}.flow: must be a string"),
            None => anyhow::bail!(
                "{ctx}.flow: required — upstream tolerates its absence, meow does \
                 not: the only served value is `xtls-rprx-vision`"
            ),
        }
        users.push(VlessUser { username, uuid });
    }

    // ── `alpn` — standard-TLS only; a list of printable-ASCII strings,
    // 1–255 bytes each, unique, at most 16 entries. An empty list is the
    // same as absent on both modes.
    let mut alpn: Vec<String> = Vec::new();
    if let Some(raw_alpn) = raw_l.alpn.as_ref().map(|v| &v.0).filter(|v| !v.is_null()) {
        let ctx = format!("listeners[{}].alpn", raw_l.name);
        let Some(list) = raw_alpn.as_array() else {
            anyhow::bail!("{ctx}: must be a list of protocol strings (e.g. `[h2, http/1.1]`)");
        };
        if list.len() > 16 {
            anyhow::bail!("{ctx}: at most 16 entries — the TLS ALPN extension is small");
        }
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (i, entry) in list.iter().enumerate() {
            let serde_json::Value::String(proto) = entry else {
                anyhow::bail!("{ctx}[{i}]: must be a string");
            };
            if proto.is_empty() {
                anyhow::bail!("{ctx}[{i}]: must not be empty");
            }
            if proto.len() > 255 {
                anyhow::bail!("{ctx}[{i}]: exceeds the 255-byte ALPN protocol limit");
            }
            if !proto.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                anyhow::bail!(
                    "{ctx}[{i}]: must be printable ASCII (no control or non-ASCII bytes)"
                );
            }
            if !seen.insert(proto.as_str()) {
                anyhow::bail!("{ctx}[{i}]: '{proto}' duplicates an earlier entry");
            }
            alpn.push(proto.clone());
        }
    }
    if !alpn.is_empty() && reality.is_some() {
        anyhow::bail!(
            "listeners[{}].alpn: not configurable in REALITY mode — the cover branch's \
             ALPN belongs to the probe client and the target alone, and the REALITY \
             handshake offers no local override; remove it",
            raw_l.name
        );
    }

    // ── `udp` — default `true`; `false` rejects Mux/XUDP at the VLESS
    // header layer. Both spellings are meaningful, so neither warns.
    let udp = raw_l.udp.unwrap_or(true);

    // ── keys consumed by other listener types land here only by
    // mistake — schema-known, so warn-ignore (the unknown ones in
    // `extra` already hard-errored above).
    for (key, set) in [
        ("cipher", raw_l.cipher.is_some()),
        ("password", raw_l.password.is_some()),
        ("simple-obfs", raw_l.simple_obfs.is_some()),
        ("kcp-tun", raw_l.kcp_tun.is_some()),
        ("padding-scheme", raw_l.padding_scheme.is_some()),
    ] {
        if set {
            warn!(
                "listeners[{}].{key}: `{key}` is not meaningful on `type: vless`, \
                 ignored; remove it to suppress this warning",
                raw_l.name
            );
        }
    }

    let addresses = resolve_multi_listener_binds(raw_l, default_bind)?;

    // ── REALITY self-loop static gate — the certain cases only: the
    // cover `dest` is an IP literal that provably lands back on THIS
    // listener (same address, or a wildcard/loopback combination).
    // Domain dests and non-local literals are the runtime dial guard's
    // job (it checks resolution results against every listener); an
    // ephemeral `port: 0` bind can never match statically.
    if let Some(reality_cfg) = &reality {
        if let Ok(dest_ip) = reality_cfg.dest_host.parse::<IpAddr>() {
            for bind in &addresses {
                if bind.port != reality_cfg.dest_port || bind.port == 0 {
                    continue;
                }
                let Ok(bind_ip) = bind.listen.parse::<IpAddr>() else {
                    continue;
                };
                let exact = bind_ip == dest_ip;
                // Dialing a wildcard or loopback reaches a local socket
                // on every host; a wildcard bind covers loopback too.
                let wildcard_covers =
                    bind_ip.is_unspecified() && (dest_ip.is_loopback() || dest_ip.is_unspecified());
                let loopback_pair = bind_ip.is_loopback()
                    && (dest_ip.is_loopback() || dest_ip.is_unspecified())
                    && bind_ip.is_ipv4() == dest_ip.is_ipv4();
                if exact || wildcard_covers || loopback_pair {
                    anyhow::bail!(
                        "listeners[{}].reality-config.dest: points back at this \
                         listener's own bind `{bind_ip}:{port}` — every cover relay \
                         would loop into the REALITY classifier itself; pick a real \
                         cover site (a TLS server the probe client can be relayed to)",
                        raw_l.name,
                        port = bind.port
                    );
                }
            }
        }
    }

    let security = match (cert_pair, reality) {
        (Some((certificate, private_key)), None) => VlessSecurity::StandardTls {
            certificate,
            private_key,
            alpn,
        },
        (None, Some(reality_cfg)) => VlessSecurity::Reality(reality_cfg),
        // Both/neither already hard-errored above; the compiler cannot
        // see through the early bail without this arm.
        _ => unreachable!("security-mode exclusivity is enforced before this point"),
    };

    Ok(VlessListenerConfig {
        users,
        security,
        udp,
        addresses,
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
/// constructing anything. `PUT /configs` uses the richer
/// [`resolve_named_listeners`] so it can also gate on the running
/// binary's compiled feature set; this remains the structural-only
/// check.
pub fn validate_named_listeners(raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    resolve_named_listeners(raw)?;
    Ok(())
}

/// Resolve `listeners:` into the same `NamedListener` list `load_config`
/// produces, without constructing anything. `PUT /configs` uses the
/// resolved list to gate the commit not just on structural validity but
/// on runtime support — a listener type the running build did not compile
/// (`ensure_listeners_supported`) would persist and hard-error the next
/// boot.
pub fn resolve_named_listeners(raw: &raw::RawConfig) -> Result<Vec<NamedListener>, anyhow::Error> {
    let (bind_addr, global_tproxy_sni) = listener_bind_inputs(raw);
    build_named_listeners(raw, &bind_addr, global_tproxy_sni)
}

/// Why a `listeners[].proxy` name cannot force a route in this rebuilt
/// map — `None` when it resolves. Built-ins count the way
/// `resolve_listener_proxy` sees them: DIRECT/REJECT/PASS/COMPATIBLE and
/// the auto-created GLOBAL are all ordinary map entries. A proxy-provider
/// name is rejected explicitly: a provider feeds groups and is not a
/// target — naming it would check against nothing and fail closed per
/// flow. Shared by the build admission below and the API's prospective
/// route guard so every publication path diagnoses the same way.
pub fn listener_proxy_target_err(
    name: &str,
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    proxy_providers: &HashMap<String, Arc<ProxyProvider>>,
) -> Option<String> {
    if proxy_providers.contains_key(name) {
        return Some(format!(
            "'{name}' is a proxy-provider — providers feed groups and are \
             not forced-route targets"
        ));
    }
    (!proxies.contains_key(name))
        .then(|| format!("'{name}' does not name a built proxy or proxy group"))
}

/// Admission check for `listeners[].proxy`: every forced target must
/// name a proxy or group in the rebuilt map (`rule:` selects a
/// `sub-rules:` block instead — `build_named_listeners` already gates
/// that name against `raw.sub_rules`). Runs inside every
/// `rebuild_from_raw_*` pass so `-t`, startup, `PUT /configs` and every
/// warm mutation reject the same dangling reference with the same error
/// instead of committing a document the inbound would only fail closed
/// on per flow.
pub fn validate_listener_proxy_targets(
    raw: &raw::RawConfig,
    proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    proxy_providers: &HashMap<String, Arc<ProxyProvider>>,
) -> Result<(), anyhow::Error> {
    for l in raw.listeners.as_deref().unwrap_or(&[]) {
        let Some(name) = l.proxy.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        if let Some(why) = listener_proxy_target_err(name, proxies, proxy_providers) {
            anyhow::bail!("listeners[{}].proxy: {why}", l.name);
        }
    }
    Ok(())
}

/// The document-shape half of listener-proxy admission: a forced target
/// must name something the document itself declares — a `proxies:` entry,
/// a `proxy-groups:` entry, or a built-in the route table always carries.
/// Provider members are not registry keys, so a name outside the declared
/// set can never resolve; that defect is in the document, not the build —
/// `PUT /configs` refuses it even when `force` would persist a declared
/// name that merely failed to build. Returns the first offending
/// listener's message.
pub fn listener_proxy_target_shape_err(raw: &raw::RawConfig) -> Option<String> {
    for l in raw.listeners.as_deref().unwrap_or(&[]) {
        let Some(name) = l.proxy.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        if raw
            .proxy_providers
            .as_ref()
            .is_some_and(|pp| pp.contains_key(name))
        {
            return Some(format!(
                "listeners[{}].proxy: '{name}' is a proxy-provider — providers \
                 feed groups and are not forced-route targets",
                l.name
            ));
        }
        let declared = raw
            .proxies
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|p| p.get("name").and_then(serde_json::Value::as_str) == Some(name))
            || raw
                .proxy_groups
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .any(|g| g.name == name)
            || BUILTIN_ADAPTER_NAMES.contains(&name)
            || name == "GLOBAL";
        if !declared {
            return Some(format!(
                "listeners[{}].proxy: '{name}' names no declared proxy, \
                 proxy group, or built-in",
                l.name
            ));
        }
    }
    None
}

/// Resolve `tcp-keepalive*` into the [`meow_common::TcpKeepaliveConfig`]
/// every inbound listener applies to its accepted sockets, enforcing
/// `build_config`'s semantics: all three knobs are bounded at the limits
/// the strictest kernel enforces — Linux rejects (`EINVAL`)
/// `TCP_KEEPIDLE`/`TCP_KEEPINTVL` above 32767 s and `TCP_KEEPCNT` above
/// 127 — because a `setsockopt` that EINVALs is only logged at debug by
/// `keepalive::apply`, silently running with OS-default timing instead
/// of the configured posture. `tcp-keepalive: false` turns the whole
/// feature off — a parameter key still set then is dead config (loud,
/// never fatal), though an *invalid* value still errors even when
/// disabled.
///
/// `PUT /configs` calls this for validation only — the resolved posture is
/// a startup snapshot like `listeners:`, never hot-applied — so a
/// committed document cannot carry a value the next boot's `build_config`
/// would hard-error on.
pub fn resolve_tcp_keepalive(
    raw: &raw::RawConfig,
) -> Result<meow_common::TcpKeepaliveConfig, anyhow::Error> {
    let enabled = raw.tcp_keepalive.unwrap_or(true);
    let config = meow_common::TcpKeepaliveConfig {
        enabled,
        idle: std::time::Duration::from_secs(match raw.tcp_keepalive_idle {
            Some(0) => anyhow::bail!("tcp-keepalive-idle: must be at least 1 second"),
            Some(secs) if secs > meow_common::tcp_opts::MAX_TCP_KEEPALIVE_SECS => {
                anyhow::bail!(
                    "tcp-keepalive-idle: {secs}s exceeds the {}s ceiling",
                    meow_common::tcp_opts::MAX_TCP_KEEPALIVE_SECS
                )
            }
            Some(secs) => secs,
            None => meow_common::tcp_opts::DEFAULT_TCP_KEEPALIVE_IDLE_SECS,
        }),
        interval: std::time::Duration::from_secs(match raw.tcp_keepalive_interval {
            Some(0) => anyhow::bail!("tcp-keepalive-interval: must be at least 1 second"),
            Some(secs) if secs > meow_common::tcp_opts::MAX_TCP_KEEPALIVE_SECS => {
                anyhow::bail!(
                    "tcp-keepalive-interval: {secs}s exceeds the {}s ceiling",
                    meow_common::tcp_opts::MAX_TCP_KEEPALIVE_SECS
                )
            }
            Some(secs) => secs,
            None => meow_common::tcp_opts::DEFAULT_TCP_KEEPALIVE_INTERVAL_SECS,
        }),
        probes: match raw.tcp_keepalive_probes {
            Some(0) => anyhow::bail!("tcp-keepalive-probes: must be at least 1"),
            Some(n) if n > 127 => anyhow::bail!("tcp-keepalive-probes: must be at most 127"),
            Some(n) => n,
            None => meow_common::tcp_opts::DEFAULT_TCP_KEEPALIVE_PROBES,
        },
    };
    if !enabled {
        for (key, present) in [
            ("tcp-keepalive-idle", raw.tcp_keepalive_idle.is_some()),
            (
                "tcp-keepalive-interval",
                raw.tcp_keepalive_interval.is_some(),
            ),
            ("tcp-keepalive-probes", raw.tcp_keepalive_probes.is_some()),
        ] {
            if present {
                warn!(
                    "{key}: has no effect while tcp-keepalive is false; \
                     remove it to suppress this warning"
                );
            }
        }
    }
    Ok(config)
}

/// The effective `profile:` flags — what the running config and
/// `GET /configs` report (issue #974).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedProfile {
    /// `profile.store-selected` — selection persistence for `select`
    /// groups and url-test/fallback `fix` pins. Upstream default `true`.
    pub store_selected: bool,
    /// `profile.store-fake-ip` resolved over `dns.store-fake-ip` —
    /// explicit `profile` wins over explicit `dns`, which wins over the
    /// `false` default (`false` is still an explicit value; `null`
    /// falls through, matching upstream's absent-handling).
    pub store_fake_ip: bool,
}

/// Resolve `profile:` — `store-selected` defaults to upstream's `true`;
/// `store-fake-ip` follows `profile` > `dns` > `false`. When both
/// explicit spellings disagree, `profile` wins and the caller warns once
/// per admission (`validation::validate_and_warn`).
pub fn resolve_profile(raw: &raw::RawConfig) -> ResolvedProfile {
    let profile = raw.profile.as_ref();
    ResolvedProfile {
        store_selected: profile.and_then(|p| p.store_selected).unwrap_or(true),
        store_fake_ip: profile
            .and_then(|p| p.store_fake_ip)
            .or_else(|| raw.dns.as_ref().and_then(|d| d.store_fake_ip))
            .unwrap_or(false),
    }
}

/// The resolved `ntp:` service configuration (issue #974) — what
/// `Config` carries, `GET /configs` reports, and the supervisor
/// reconciles against. `write-to-system` never appears here: it is
/// warn-and-ignore at admission, not a runtime knob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpConfig {
    pub enable: bool,
    /// Host or IP literal (bracketed IPv6 unwrapped) — `time.apple.com`
    /// by upstream default.
    pub server: String,
    pub port: u16,
    /// Poll period — `interval` minutes, `1..=525600`, default 30.
    pub interval_minutes: u32,
    /// The named `dialer-proxy` target, `None` = direct dial. Admission
    /// pins it to a built top-level proxy/group name or `DIRECT` when
    /// enabled — see the check in `rebuild_from_raw_impl`.
    pub dialer_proxy: Option<String>,
}

/// Resolve `ntp:` — ranges are checked even when disabled (`-t`
/// rejects an out-of-range endpoint the same way a running load does).
/// `server` must be a bare host or IP literal: bracketed IPv6 unwraps,
/// a `host:port`/`scheme://` spelling fails; `port` and `interval`
/// hold upstream-compatible bounds.
pub fn resolve_ntp(raw: &raw::RawConfig) -> Result<NtpConfig, anyhow::Error> {
    let ntp = raw.ntp.as_ref();
    let server_raw = ntp
        .and_then(|n| n.server.as_deref())
        .unwrap_or("time.apple.com");
    let server = {
        let s = server_raw.trim();
        anyhow::ensure!(!s.is_empty(), "ntp.server must not be empty");
        // Bracketed IPv6 (`[::1]`) unwraps to the literal; anything else
        // must be a hostname — `is_valid_host` is the same byte contract
        // ingress applies, so whitespace, control bytes and every
        // authority-shaped spelling (`host:port`, `scheme://`, `a@b`,
        // `x/y`) fail here.
        let inner = s
            .strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .unwrap_or(s);
        if inner.parse::<std::net::IpAddr>().is_err() {
            anyhow::ensure!(
                meow_common::is_valid_host(inner),
                "ntp.server '{server_raw}': expected a host or IP literal, not a host:port or URI"
            );
        }
        inner.to_string()
    };
    let port = ntp.and_then(|n| n.port).unwrap_or(123);
    anyhow::ensure!(port >= 1, "ntp.port {port}: expected 1..=65535");
    let interval = ntp.and_then(|n| n.interval).unwrap_or(30);
    anyhow::ensure!(
        (1..=525_600).contains(&interval),
        "ntp.interval {interval}: expected 1..=525600 minutes"
    );
    let interval_minutes = u32::try_from(interval)
        .map_err(|_| anyhow::anyhow!("ntp.interval {interval} is out of range"))?;
    // `dialer-proxy` matches names verbatim — no trimming: `' DIRECT '`
    // is not the DIRECT built-in (issue #974). Empty means direct like
    // an absent key, and `DIRECT` normalizes to the same direct path so
    // the two spellings compare equal at reconcile and never restart an
    // unchanged worker.
    let dialer_proxy = ntp
        .and_then(|n| n.dialer_proxy.as_deref())
        .filter(|s| !s.is_empty())
        .filter(|s| *s != "DIRECT")
        .map(str::to_string);
    Ok(NtpConfig {
        enable: ntp.and_then(|n| n.enable).unwrap_or(false),
        server,
        port,
        interval_minutes,
        dialer_proxy,
    })
}

/// The `ntp.enable + dialer-proxy` reference gate every prospective
/// routing publication runs (issue #974): an enabled named target must
/// resolve to a built top-level proxy/group or `DIRECT` — provider-only
/// names and non-transport built-ins are not valid dialers. Runs against
/// the BUILT map, not the raw names, so a group dropped by lenient
/// parsing still fails and a `use:`-only name never slips through.
/// Called on every `rebuild_from_raw_impl` — startup, `-t`, PUT and the
/// subscription/geodata republish lanes all pass through it.
///
/// `placeholder_names` is [`insert_parsed_leaves`]'s set: lenient builds
/// bind a parse-failed placeholder-eligible node to an
/// `UnavailableAdapter` that stays in the map but fails every dial — the
/// same exclusion the declared-side fallback applies to `Some(true)`
/// bindings (Codex review). Group names never appear in it — the
/// duplicate-name gate keeps them disjoint — so a group whose members
/// are unusable today still passes, matching how the target actually
/// dials once membership changes (provider refresh, a re-pick).
pub(crate) fn check_ntp_dialer_target(
    cfg: &NtpConfig,
    proxies: &HashMap<SmolStr, Arc<dyn meow_common::Proxy>>,
    placeholder_names: &std::collections::HashSet<SmolStr>,
) -> Result<(), anyhow::Error> {
    // DIRECT/COMPATIBLE dial directly and GLOBAL is a real group — the
    // map carries all three; DIRECT is also spelled out for hand-built
    // `NtpConfig`s that skipped `resolve_ntp`'s normalization.
    check_ntp_dialer_target_impl(cfg, |name| {
        name == "DIRECT" || (proxies.contains_key(name) && !placeholder_names.contains(name))
    })
}

/// The same `ntp.enable + dialer-proxy` gate where no built candidate
/// exists — the forced verbatim-commit fallback (issue #974 review). The
/// name must be one the candidate's own `proxies:`/`proxy-groups:`
/// declare with a `type:` this build's dispatch can construct, or a
/// transport built-in: only those can possibly enter its built map, so
/// anything else would commit a document the next startup's built-map
/// check hard-fails — including a same-name node whose unknown `type:`
/// the lenient build drops. `use:`-only provider names fail here the
/// same way they fail there — and only a *buildable* provider counts as
/// supplying members, since `materialize_proxy_providers` warn-drops a
/// def it cannot construct.
///
/// `cache_dir` is the provider-cache directory the rebuild would use —
/// safe-path containment inside it is part of buildability. The check
/// runs the real provider constructor, which canonicalizes paths on
/// disk: callers must not hold the raw write guard and should dispatch
/// it off the async lane.
pub fn check_ntp_dialer_target_declared(
    cfg: &NtpConfig,
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
) -> Result<(), anyhow::Error> {
    check_ntp_dialer_target_impl(cfg, |name| {
        // The transports the built map always carries are spelled out —
        // there is no map to consult here.
        matches!(name, "DIRECT" | "COMPATIBLE" | "GLOBAL")
            || declared_leaf_binding(name, raw) == Some(false)
            || declared_group_lands(name, raw, cache_dir)
    })
}

/// Whether a `proxies:` declaration named `name` would land in the
/// lenient build's map — the same parse the build runs, restricted to
/// the name's own blocks (local and synchronous; a parse never dials —
/// issue #974 review). Mirrors [`insert_parsed_leaves`]: later same-name
/// blocks win a live binding; a block on a `dialer-proxy` edge goes
/// through [`parse_dialered_leaf`] against the earlier same-name
/// binding; an unparseable block fills the slot with an unavailable
/// placeholder only while nothing live is bound and its `type:` is
/// placeholder-eligible — so a `{type: socks5}` without `server` drops
/// out, while a compiled-out `trusttunnel` still binds a placeholder.
/// The placeholder counts for *group membership* (a group listing it
/// still lands) but not as the dialer target itself: it carries no
/// transport, so an NTP dialer named on it would fail every dial.
/// A build-fatal error (self-edge, a `strict` parse failure, a
/// malformed-edges bail) can never land the name.
/// Returns `Some(false)` for a live binding, `Some(true)` when only an
/// unavailable placeholder holds the slot, `None` when nothing lands.
fn declared_leaf_binding(name: &str, raw: &raw::RawConfig) -> Option<bool> {
    // A block shadowing a built-in is dropped before it binds — the
    // built-in itself was already answered by the caller's arms.
    if BUILTIN_ADAPTER_NAMES.contains(&name) {
        return None;
    }
    // This mirror runs the real constructors for their verdicts only —
    // an `ss` node's external SIP003 plugin must not spawn a local
    // subprocess just to answer "would the name land" for a candidate
    // that may still be rejected (Codex review). Every other check in
    // the arm still applies, so the verdict stays the constructor's
    // modulo the spawn itself.
    #[cfg(feature = "ss")]
    let _plugin_dry_run = proxy_parser::plugin_spawn_dry_run();
    let raw_proxies = raw.proxies.as_ref()?;
    let strict = raw.strict.unwrap_or(false);
    let Ok(edges) = collect_dialer_edges(raw_proxies, strict) else {
        // The whole build bails on the declared edges — no map exists
        // for the name to land in.
        return None;
    };
    let ipv6 = effective_ipv6(raw.ipv6);
    let fp = raw.global_client_fingerprint.as_deref();
    let registry = meow_proxy::dialer::ProxyRegistry::default();
    // Dry-run verdicts only need a throwaway cell — a `type: dns` leaf
    // lands either way; which resolver slot it would serve is runtime
    // state this mirror never consults (issue #974).
    let dns_cell = meow_dns::new_dns_outbound_cell();
    let key = SmolStr::from(name);
    // (binding, is_placeholder) — `parse_dialered_leaf` consults both.
    let mut bound: Option<(Arc<dyn Proxy>, bool)> = None;
    for (index, block) in raw_proxies.iter().enumerate() {
        if block.get("name").and_then(|v| v.as_str()) != Some(name) {
            continue;
        }
        if let Some(dialer) = edges.by_index.get(&index) {
            let mut prior = HashMap::new();
            let mut placeholder_names = std::collections::HashSet::new();
            if let Some((proxy, placeholder)) = &bound {
                prior.insert(key.clone(), Arc::clone(proxy));
                if *placeholder {
                    placeholder_names.insert(key.clone());
                }
            }
            match parse_dialered_leaf(
                block,
                dialer,
                &prior,
                &placeholder_names,
                None,
                ipv6,
                strict,
                &registry,
                fp,
                &dns_cell,
            ) {
                Ok(Some(b)) => bound = Some(b),
                // Skipped — the earlier same-name binding stands.
                Ok(None) => {}
                Err(_) => return None,
            }
            continue;
        }
        match proxy_parser::parse_static_proxy(block, ipv6, None, fp, Some(&dns_cell)) {
            Ok(proxy) => bound = Some((proxy, false)),
            Err(e) => {
                if strict {
                    return None;
                }
                if bound.is_none() {
                    if let Some(declared) = proxy_parser::placeholder_adapter_type(block) {
                        bound = Some((
                            unavailable_placeholder(name, &e.to_string(), declared),
                            true,
                        ));
                    }
                }
            }
        }
    }
    bound.map(|(_, placeholder)| placeholder)
}

/// Whether a `proxy-groups:` declaration named `name` lands in the
/// lenient build — mirroring [`proxy_parser::parse_proxy_group_inner`]'s
/// kept-verdict without fabricating provider objects: the group survives
/// when at least one static member or provider slot resolves and its
/// type-specific gates pass. Member names resolve against the set the
/// build's map carries at group-parse time — the transports (built-ins),
/// every landed leaf, and every group that already landed — settled by
/// the same multi-pass structure `build_config` uses, not a plain
/// fixpoint, so a late landing does not rescue an earlier deferred
/// dependency (Codex review).
///
/// `cache_dir` must be the provider-cache directory the rebuild would
/// use: it feeds [`declared_provider_buildable`]'s safe-path mirror, and
/// that constructor's canonicalize touches the filesystem — keep this
/// off the raw write guard and off the async lane.
fn declared_group_lands(name: &str, raw: &raw::RawConfig, cache_dir: Option<&Path>) -> bool {
    let Some(groups) = raw.proxy_groups.as_ref() else {
        return false;
    };
    let strict = raw.strict.unwrap_or(false);
    let mut resolvable: std::collections::HashSet<&str> =
        BUILTIN_ADAPTER_NAMES.iter().copied().collect();
    let mut landed_leaves = 0usize;
    let mut seen = std::collections::HashSet::new();
    for block in raw.proxies.as_deref().unwrap_or(&[]) {
        let Some(n) = block.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if !seen.insert(n) {
            continue;
        }
        // Placeholder-bound names resolve as members too — they occupy
        // the built map's slot exactly like a live adapter.
        if declared_leaf_binding(n, raw).is_some() {
            resolvable.insert(n);
            landed_leaves += 1;
        }
    }
    // Only a provider that would construct supplies member slots —
    // `materialize_proxy_providers` warn-drops a def that fails
    // `ProxyProvider::new_with_client_fingerprint` (an `http` provider
    // without `url`, a `file` one without `path` or whose `path` escapes
    // the cache dir, an unknown `type`), and the real build wires slots
    // from its materialized map, not the declared one (Codex review:
    // declared membership counted slots the construction drops).
    let providers: std::collections::HashSet<&str> = raw
        .proxy_providers
        .as_ref()
        .map(|defs| {
            defs.iter()
                .filter(|(name, def)| declared_provider_buildable(name, def, raw, cache_dir))
                .map(|(name, _)| name.as_str())
                .collect()
        })
        .unwrap_or_default();
    let declared: std::collections::HashSet<&str> =
        groups.iter().map(|g| g.name.as_str()).collect();
    let mut landed: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // Mirror the build's multi-pass settle (`build_config`'s group loop):
    // a group whose `proxies:` member names a declared-but-unlanded group
    // is deferred to a later pass — a member resolves only once its group
    // landed in an earlier pass. When a pass lands nothing, the build
    // makes one final lenient pass over what is left, in declaration
    // order and without revisiting — so a group landing late in that
    // pass does NOT rescue an earlier group's dependency on it. A plain
    // fixpoint would revisit and admit it, letting a forced commit claim
    // a `dialer-proxy` target the next boot drops (Codex review).
    let mut remaining: Vec<&raw::RawProxyGroup> = groups.iter().collect();
    loop {
        let mut still = Vec::new();
        let mut progress = false;
        for g in remaining {
            let dep_pending = g
                .proxies
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .any(|m| declared.contains(m.as_str()) && !landed.contains(m.as_str()));
            if dep_pending {
                still.push(g);
                continue;
            }
            if declared_group_would_land(g, &resolvable, &providers, landed_leaves, strict) {
                landed.insert(g.name.as_str());
                resolvable.insert(g.name.as_str());
                progress = true;
            } else {
                still.push(g);
            }
        }
        if still.is_empty() {
            break;
        }
        if !progress {
            for g in &still {
                if declared_group_would_land(g, &resolvable, &providers, landed_leaves, strict) {
                    landed.insert(g.name.as_str());
                    resolvable.insert(g.name.as_str());
                }
            }
            break;
        }
        remaining = still;
    }
    landed.contains(name)
}

/// Whether the declared `proxy-providers:` def would construct — the
/// exact gate `materialize_proxy_providers` applies when it decides
/// whether a name enters the built map (`use:`/`include-all` wire slots
/// against that map). Runs the real constructor with a throwaway dialer
/// registry and the same `ipv6`/`strict`/fingerprint resolution the
/// rebuild applies — including safe-path containment, which reads the
/// filesystem, so callers must stay off the write guard and dispatch to
/// the blocking pool.
fn declared_provider_buildable(
    name: &str,
    def: &raw::RawProxyProvider,
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
) -> bool {
    proxy_provider::ProxyProvider::new_with_client_fingerprint(
        name,
        def,
        cache_dir,
        effective_ipv6(raw.ipv6),
        raw.strict.unwrap_or(false),
        meow_proxy::dialer::ProxyRegistry::default(),
        raw.global_client_fingerprint.as_deref(),
        // Dry-run verdict only: the candidate never serves, so dns leaves
        // stay unbound here (issue #974).
        None,
    )
    .is_ok()
}

/// The kept-verdict of one group parse — see [`declared_group_lands`].
/// `resolvable` is the member-name set the built map would hold at this
/// point (transports + landed leaves + landed groups); `providers` the
/// declared `proxy-providers:` names — a slot wires for every declared
/// name `use:` references and for `include-all*` only while providers
/// exist, matching the map lookups in `parse_proxy_group_inner`.
fn declared_group_would_land(
    g: &raw::RawProxyGroup,
    resolvable: &std::collections::HashSet<&str>,
    providers: &std::collections::HashSet<&str>,
    landed_leaves: usize,
    strict: bool,
) -> bool {
    if !declared_group_type_buildable(&g.group_type) {
        return false;
    }
    // A bad group filter rejects the parse outright.
    if crate::proxy_provider::GroupFilter::from_raw_group(g).is_err() {
        return false;
    }
    let is_relay = g.group_type == "relay";
    let proxy_names = g.proxies.as_deref().unwrap_or(&[]);
    // `parse_proxy_group_inner` consults `use:` only when include-all
    // supplies no provider slots: with `include-all`/`include-all-providers`
    // set the slot list is every provider and `use:` is never iterated —
    // an unknown name there cannot fail the parse even under `strict`.
    let include_all_providers =
        g.include_all.unwrap_or(false) || g.include_all_providers.unwrap_or(false);
    // Under `strict` an unresolved static member (or a non-relay group's
    // unknown `use:`) fails the parse — and the build it belongs to.
    if strict {
        if proxy_names.iter().any(|n| !resolvable.contains(n.as_str())) {
            return false;
        }
        if !is_relay
            && !include_all_providers
            && g.use_providers
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .any(|p| !providers.contains(p.as_str()))
        {
            return false;
        }
    }
    let mut members = proxy_names
        .iter()
        .filter(|n| resolvable.contains(n.as_str()))
        .count();
    if g.include_all_proxies.unwrap_or(false) {
        members += landed_leaves;
    }
    // Provider slots never supply relay members — a `use:` there is
    // inert (issue #533) — so they count only for the other types.
    let slots = if is_relay {
        0
    } else if include_all_providers {
        providers.len()
    } else {
        let mut seen = std::collections::HashSet::new();
        g.use_providers
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter(|p| providers.contains(p.as_str()) && seen.insert(p.as_str()))
            .count()
    };
    if members == 0 && slots == 0 {
        return false;
    }
    match g.group_type.as_str() {
        "load-balance" => proxy_parser::parse_lb_strategy(g.strategy.as_deref()).is_ok(),
        // `proxies` is the only member source a relay parses — it
        // hard-errors below 2 members.
        "relay" => members >= 2,
        _ => true,
    }
}

/// The `proxy-groups:` `type:` spellings the group builder dispatches
/// on — anything else fails the parse before membership is read.
fn declared_group_type_buildable(group_type: &str) -> bool {
    matches!(
        group_type,
        "select" | "url-test" | "fallback" | "load-balance" | "relay"
    )
}

fn check_ntp_dialer_target_impl(
    cfg: &NtpConfig,
    target_exists: impl Fn(&str) -> bool,
) -> Result<(), anyhow::Error> {
    if !cfg.enable {
        return Ok(());
    }
    if let Some(name) = &cfg.dialer_proxy {
        // REJECT/REJECT-DROP/PASS/PASS-RULE sit in the built map but are
        // match-engine signals, not transports — they can never carry the
        // exchange on either lane.
        anyhow::ensure!(
            !matches!(
                name.as_str(),
                "REJECT" | "REJECT-DROP" | "PASS" | "PASS-RULE"
            ),
            "ntp.dialer-proxy '{name}': non-transport built-ins cannot carry \
             the exchange — name a built proxy/group, DIRECT, COMPATIBLE, \
             or GLOBAL"
        );
        anyhow::ensure!(
            target_exists(name.as_str()),
            "ntp.dialer-proxy '{name}': no such top-level proxy or group — \
             name a built proxy/group or DIRECT (provider-member and \
             built-in non-dialer names are not valid targets)"
        );
    }
    Ok(())
}

/// Resolve `keep-alive-idle`/`keep-alive-interval`/`disable-keep-alive`
/// — mihomo's keepalive knobs, scoped here to *outbound* dials (the
/// inbound side stays with `tcp-keepalive*` / [`resolve_tcp_keepalive`],
/// an independence upstream's shared keys did not have) — into the
/// [`meow_common::OutboundTcpKeepalive`] `connect_tcp` snapshots once per
/// dial. Omitted or `0` timings resolve to the 15 s upstream default;
/// `disable-keep-alive` defaults to `false`. Timing bounds hold at
/// 0–32767 s even when disabled, like `tcp-keepalive*` — Linux EINVALs
/// `TCP_KEEPIDLE`/`TCP_KEEPINTVL` above it. Negative values never reach
/// here: the `u64` raw fields already failed serde.
///
/// `PUT`/`PATCH /configs` gate persistence on this resolver so a
/// committed document cannot fail the next boot's `build_config`; the
/// install itself happens at the caller's commit point, not here.
pub fn resolve_outbound_tcp_keepalive(
    raw: &raw::RawConfig,
) -> Result<meow_common::OutboundTcpKeepalive, anyhow::Error> {
    let bound = |key: &str, value: Option<u64>| -> Result<u64, anyhow::Error> {
        match value {
            None | Some(0) => Ok(meow_common::tcp_opts::DEFAULT_OUTBOUND_KEEPALIVE_SECS),
            Some(secs) if secs > meow_common::tcp_opts::MAX_TCP_KEEPALIVE_SECS => {
                anyhow::bail!(
                    "{key}: {secs}s exceeds the {}s ceiling",
                    meow_common::tcp_opts::MAX_TCP_KEEPALIVE_SECS
                )
            }
            Some(secs) => Ok(secs),
        }
    };
    Ok(meow_common::OutboundTcpKeepalive {
        enabled: !raw.disable_keep_alive.unwrap_or(false),
        idle: std::time::Duration::from_secs(bound("keep-alive-idle", raw.keep_alive_idle)?),
        interval: std::time::Duration::from_secs(bound(
            "keep-alive-interval",
            raw.keep_alive_interval,
        )?),
        probes: meow_common::tcp_opts::OUTBOUND_KEEPALIVE_PROBES,
    })
}

/// `lan-allowed-ips`/`lan-disallowed-ips` nested under a `listeners:`
/// entry would land in its `extra` map and silently do nothing — an
/// access guard that never engages is worse than none, so misplacement
/// is a hard error pointing at the top level. Shared by
/// `build_named_listeners` (boot/`-t`/`PUT`) and [`resolve_lan_acl`]
/// (which `PUT /configs` additionally gates on under `force`).
fn check_listener_acl_placement(l: &raw::RawListener) -> Result<(), anyhow::Error> {
    for key in ["lan-allowed-ips", "lan-disallowed-ips"] {
        if l.extra.contains_key(key) {
            anyhow::bail!(
                "listeners[{}].{key}: the LAN ACL keys are top-level only — \
                 move '{key}' to the config root",
                l.name
            );
        }
    }
    Ok(())
}

/// `<ip>/<prefix>` with host bits accepted and normalized — the
/// `lan-*-ips` contract (mihomo's `netip.Prefix` takes host bits; bare
/// IPs and malformed prefixes are rejected).
fn parse_lan_cidr(s: &str) -> Result<ipnet::IpNet, anyhow::Error> {
    let (addr, plen) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("'{s}' is not a CIDR (expected 'addr/prefix')"))?;
    let addr: std::net::IpAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("'{s}': bad address ({e})"))?;
    let plen: u8 = plen
        .parse()
        .map_err(|_| anyhow::anyhow!("'{s}': bad prefix length '{plen}'"))?;
    ipnet::IpNet::new(addr, plen)
        .map(|n| n.trunc())
        .map_err(|e| anyhow::anyhow!("'{s}': {e}"))
}

/// Resolve `lan-allowed-ips`/`lan-disallowed-ips` into the shared
/// immutable [`meow_common::LanAcl`] the mixed/HTTP/SOCKS TCP accept
/// loops consult (mihomo's `adapter/inbound/ipfilter`): admit = at
/// least one allow match AND no deny match. An omitted allow list
/// defaults to `0.0.0.0/0` + `::/0`; explicit `[]` admits nobody on the
/// gated path. The deny list defaults to empty. Errors name the key
/// and the offending element index.
///
/// `PUT /configs` calls this for validation only — the ACL is a startup
/// snapshot like `listeners:`, never hot-applied — so a committed
/// document cannot carry a value the next boot's `build_config` would
/// hard-error on.
pub fn resolve_lan_acl(raw: &raw::RawConfig) -> Result<meow_common::LanAcl, anyhow::Error> {
    for l in raw.listeners.iter().flatten() {
        check_listener_acl_placement(l)?;
    }
    let parse_list =
        |key: &str, entries: Option<&[String]>| -> Result<Vec<ipnet::IpNet>, anyhow::Error> {
            entries
                .unwrap_or(&[])
                .iter()
                .enumerate()
                .map(|(i, s)| parse_lan_cidr(s).map_err(|e| anyhow::anyhow!("{key}[{i}]: {e}")))
                .collect()
        };
    let allowed = match raw.lan_allowed_ips.as_deref() {
        None => vec![
            "0.0.0.0/0".parse().expect("static CIDR"),
            "::/0".parse().expect("static CIDR"),
        ],
        Some(list) => parse_list("lan-allowed-ips", Some(list))?,
    };
    let denied = parse_list("lan-disallowed-ips", raw.lan_disallowed_ips.as_deref())?;
    Ok(meow_common::LanAcl::new(allowed, denied))
}

/// Resolve `tcp-idle-timeout` into the whole-connection relay idle bound,
/// enforcing `build_config`'s semantics: `0` disables the bound entirely,
/// absent also disables it (preserving pre-894 behaviour — no idle bound
/// by default), and explicit seconds feed `Instant + Duration` inside the
/// relay so they get the same ceiling as `tcp-connect-timeout` (issue #648).
///
/// `PUT /configs` calls this for both validation and hot-apply (the bound
/// is replayed into `Tunnel::set_tcp_idle_timeout` at the commit point),
/// so boot and reload can never diverge on the value.
pub fn resolve_tcp_idle_timeout(
    raw: &raw::RawConfig,
) -> Result<Option<std::time::Duration>, anyhow::Error> {
    match raw.tcp_idle_timeout {
        Some(0) | None => Ok(None),
        Some(secs) if secs > meow_common::MAX_DURATION_SECS => anyhow::bail!(
            "tcp-idle-timeout: {secs}s exceeds the {}s ceiling",
            meow_common::MAX_DURATION_SECS
        ),
        Some(secs) => Ok(Some(std::time::Duration::from_secs(secs))),
    }
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
    // An explicit `sniffer:` block — even `enable: false` — is the newer,
    // deliberate knob: the deprecated `tproxy-sni` synthesis must not
    // outlive it (its private runtime survives `with_sniffer`'s off
    // state, so a global disable would still sniff). Deadens the global
    // default for the shorthands below; per-listener `tproxy-sni` is
    // deadened inside `parse_listener_spec`.
    let sniffer_declared = raw.sniffer.is_some();
    let global_tproxy_sni = global_tproxy_sni && !sniffer_declared;
    let mut result: Vec<NamedListener> = Vec::new();
    let mut used_ports: HashMap<u16, String> = HashMap::new();
    let mut used_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let global_max_conns = raw.max_connections.unwrap_or(256);
    validate_connection_limit(global_max_conns)?;

    let mut add = |name: &str,
                   spec: ListenerSpec,
                   port: u16,
                   listen: &str,
                   max_connections: usize,
                   route_override: Option<meow_common::InboundRouteOverride>,
                   routing_mark: Option<u32>,
                   extra_ports: &[u16]|
     -> Result<(), anyhow::Error> {
        validate_connection_limit(max_connections)
            .map_err(|e| anyhow::anyhow!("listener '{name}': {e}"))?;
        // Port 0 is "OS assigns an ephemeral port" — each such listener binds
        // a distinct port at runtime, so they are not duplicates of each other.
        // `seen` dedupes candidates within one listener: an anytls entry may
        // legitimately bind the same port on several addresses.
        let mut seen = std::collections::HashSet::new();
        for candidate in std::iter::once(port).chain(extra_ports.iter().copied()) {
            if candidate != 0 && seen.insert(candidate) {
                if let Some(existing) = used_ports.get(&candidate) {
                    anyhow::bail!(
                        "port {candidate} already used by listener '{existing}' (duplicate port, Class A per ADR-0002)"
                    );
                }
                used_ports.insert(candidate, name.to_string());
            }
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
            route_override,
            routing_mark,
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
            None,
            None,
            &[],
        )?;
    }
    if let Some(port) = raw.socks_port.filter(|p| *p != 0) {
        add(
            "socks",
            ListenerSpec::Socks5,
            port,
            default_bind,
            global_max_conns,
            None,
            None,
            &[],
        )?;
    }
    if let Some(port) = raw.port.filter(|p| *p != 0) {
        add(
            "http",
            ListenerSpec::Http,
            port,
            default_bind,
            global_max_conns,
            None,
            None,
            &[],
        )?;
    }
    if raw.firewall.is_some() {
        warn!(
            "firewall: only meaningful under a `listeners:` tproxy entry; \
             the top-level key is ignored — the `tproxy-port` shorthand \
             always stays managed (issue #563); `redir-port` never installs rules"
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
    // `redir-port` means what it means in mihomo — an inbound for the
    // deployer's own REDIRECT rules (OpenWrt front-ends generate it), bound
    // like the other shorthands.
    if let Some(port) = raw.redir_port.filter(|p| *p != 0) {
        add(
            "redir",
            ListenerSpec::TProxy {
                sni: global_tproxy_sni,
                firewall: false,
                udp: false,
                udp_timeout: default_udp_timeout_secs(),
                transparent: false,
            },
            port,
            default_bind,
            global_max_conns,
            None,
            None,
            &[],
        )?;
    }
    if let Some(port) = raw.tproxy_port.filter(|p| *p != 0) {
        add(
            "tproxy",
            ListenerSpec::TProxy {
                sni: global_tproxy_sni,
                // The shorthand keeps the managed-firewall default (issue
                // #563): external management is an explicit `listeners:`
                // opt-in only. UDP likewise stays opt-in (issue #564).
                // mihomo's real-TPROXY `tproxy-port` is `listeners:` with
                // `transparent: true` here.
                firewall: true,
                udp: false,
                udp_timeout: default_udp_timeout_secs(),
                transparent: false,
            },
            port,
            "127.0.0.1",
            global_max_conns,
            None,
            None,
            &[],
        )?;
    }

    // Explicit `listeners:` entries
    let mut named_tun_seen: Option<String> = None;
    for raw_l in raw.listeners.as_deref().unwrap_or(&[]) {
        // `type: redir` lowers to a `TProxy` spec, which erases its origin —
        // the listen-default and warn-dedupe branches below still need it.
        let is_redir = raw_l.listener_type.eq_ignore_ascii_case("redir");
        // `lan-*-ips` nested under a listener would land in `extra` as a
        // silently-dead access guard — hard error before `warn_extra`
        // can mislabel them unrecognized.
        check_listener_acl_placement(raw_l)?;
        // `type: tun` — a named TUN device, not a socket listener: it owns
        // no port/listen and stays out of the socket-port registry, but it
        // does share the name-uniqueness check (upstream `parseListeners`
        // rejects duplicate names). meow admits ONE effective TUN — a
        // named entry, or an enabled top-level `tun:` — because the single
        // handle, the routes, the outbound binding, DNS hijack and the
        // lwIP generation are not isolated for concurrent devices. The
        // options are flat on the entry (upstream `TunOption`); a nested
        // `tun:` map, `enable`, `listen` or `port` are shape errors.
        if raw_l.listener_type.eq_ignore_ascii_case("tun") {
            if raw.tun.as_ref().is_some_and(|t| t.enable) {
                anyhow::bail!(
                    "listeners[{}]: `type: tun` cannot coexist with `tun.enable: true` — \
                     meow-rs runs one effective TUN; disable the top-level section \
                     or remove this listener",
                    raw_l.name
                );
            }
            if let Some(first) = named_tun_seen.replace(raw_l.name.clone()) {
                anyhow::bail!(
                    "listeners[{}]: second named `type: tun` listener ('{first}' \
                     already declares one) — meow-rs runs one effective TUN",
                    raw_l.name
                );
            }
            for (key, present) in [
                ("enable", raw_l.enable.is_some()),
                ("tun", raw_l.extra.contains_key("tun")),
                ("listen", raw_l.listen.is_some()),
                ("port", raw_l.port.is_some()),
            ] {
                if present {
                    anyhow::bail!(
                        "listeners[{}].{key}: a named `type: tun` takes its options \
                         flat on the entry — `{key}` has no meaning here (the \
                         entry itself is the enabled device; drop it, or use the \
                         top-level `tun:` section instead)",
                        raw_l.name
                    );
                }
            }
            validation::warn_extra(&format!("listener '{}'", raw_l.name), &raw_l.extra);
            // Keys meaningful only on socket listener types — including
            // the anytls-only set the shared diagnostics would warn
            // about below, which this early-`continue` arm never reaches.
            for (key, set) in [
                ("firewall", raw_l.firewall.is_some()),
                ("tproxy-sni", raw_l.tproxy_sni.is_some()),
                ("transparent", raw_l.transparent.is_some()),
                ("udp", raw_l.udp.is_some()),
                ("cipher", raw_l.cipher.is_some()),
                ("password", raw_l.password.is_some()),
                ("private-key", raw_l.private_key.is_some()),
                ("peers", raw_l.peers.is_some()),
                // No inbound socket exists to mark — the ingress
                // `routing-mark` contract does not reach a TUN device.
                ("routing-mark", raw_l.routing_mark.is_some()),
                ("users", raw_l.users.is_some()),
                ("certificate", raw_l.certificate.is_some()),
                ("client-auth-type", raw_l.client_auth_type.is_some()),
                ("client-auth-cert", raw_l.client_auth_cert.is_some()),
                ("ech-key", raw_l.ech_key.is_some()),
                ("allow-insecure", raw_l.allow_insecure.is_some()),
                ("padding-scheme", raw_l.padding_scheme.is_some()),
                ("decryption", raw_l.decryption.is_some()),
                ("alpn", raw_l.alpn.is_some()),
                ("reality-config", raw_l.reality_config.is_some()),
            ] {
                if set {
                    warn!(
                        "listeners[{}].{key}: not meaningful on `type: tun`, ignored; \
                         remove it to suppress this warning",
                        raw_l.name
                    );
                }
            }
            // Same `sub-rules:` selection contract as the socket types.
            if let Some(name) = raw_l.rule.as_deref().filter(|s| !s.is_empty()) {
                let defined = raw.sub_rules.as_ref().is_some_and(|m| m.contains_key(name));
                if !defined {
                    anyhow::bail!(
                        "listeners[{}].rule: '{name}' references undefined sub-rules block",
                        raw_l.name
                    );
                }
            }
            let route_override = meow_common::InboundRouteOverride::new(
                raw_l.proxy.as_deref(),
                raw_l.rule.as_deref(),
            );
            let tun = parse_named_tun_config(raw_l, global_max_conns, raw.fake_ip_range())?;
            add(
                &raw_l.name,
                ListenerSpec::Tun(tun),
                // No socket port exists — `0`/"" keep the entry inert for
                // the port registry (`0` never registers) and `GET
                // /listeners` (which reports name/type only for it).
                0,
                "",
                raw_l.max_connections.unwrap_or(global_max_conns),
                route_override,
                None,
                &[],
            )?;
            continue;
        }
        let spec = parse_listener_spec(raw_l, global_tproxy_sni, sniffer_declared)?;
        // `type: wireguard` entries already warned their extra keys inside
        // `build_wg_listener_spec` (peer extras too); `type: vless`
        // hard-errors every extra key inside its own builder (unknown keys
        // are fatal there, so the warn pass would be pure noise); on every
        // other type the extras would drop silently — classify-and-warn
        // here (issue #974).
        if !matches!(spec, ListenerSpec::WireGuard(_) | ListenerSpec::Vless(_)) {
            validation::warn_extra(&format!("listener '{}'", raw_l.name), &raw_l.extra);
            if let Some(obfs) = &raw_l.simple_obfs {
                validation::warn_extra(
                    &format!("listener '{}' simple-obfs", raw_l.name),
                    &obfs.extra,
                );
            }
        }
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
            // `wireguard` consumes `udp-timeout` itself (inner-UDP flow
            // idle bound) — no warning on it either.
            (ListenerSpec::TProxy { udp: true, .. }, _)
            | (ListenerSpec::WireGuard(_), _)
            | (_, None) => {}
            // `type: redir` already warned that `udp-timeout` is ignored
            // on it at spec-parse — don't warn a second time here.
            (ListenerSpec::TProxy { .. }, Some(_)) if is_redir => {}
            (ListenerSpec::TProxy { .. }, Some(_)) => warn!(
                "listeners[{}].udp-timeout: has no effect unless `udp: true` is set; \
                 remove it to suppress this warning",
                raw_l.name
            ),
            (_, Some(_)) => warn!(
                "listeners[{}].udp-timeout: only meaningful on `type: tproxy`/`wireguard`, ignored; \
                 remove it to suppress this warning",
                raw_l.name
            ),
        }
        // `udp` is meaningful on tproxy (issue #564), shadowsocks,
        // wireguard and vless (XUDP gate); `type: anytls` diagnoses the
        // key itself inside `build_anytls_listener_spec` (`true`
        // redundant, `false` a hard error). Any other listener type
        // ignoring it is warned about.
        if raw_l.udp.is_some()
            && !matches!(
                spec,
                ListenerSpec::TProxy { .. }
                    | ListenerSpec::Shadowsocks(_)
                    | ListenerSpec::WireGuard(_)
                    | ListenerSpec::Anytls(_)
                    | ListenerSpec::Vless(_)
            )
        {
            warn!(
                "listeners[{}].udp: only meaningful on `type: tproxy`/`shadowsocks`/`wireguard`/`vless`, \
                 ignored; remove it to suppress this warning",
                raw_l.name
            );
        }
        // WireGuard/TUN-only fields set on another listener type warn —
        // the same shape as the `firewall`/`tproxy-sni` checks above
        // (`type: tun` consumed them in its own arm above and never
        // reaches here).
        // `private-key` is shared with `type: anytls`/`vless` (TLS
        // material) — `mtu`/`peers` remain WG/TUN-only and warn there too.
        if raw_l.private_key.is_some()
            && !matches!(
                spec,
                ListenerSpec::WireGuard(_) | ListenerSpec::Anytls(_) | ListenerSpec::Vless(_)
            )
        {
            warn!(
                "listeners[{}].private-key: only meaningful on `type: wireguard`/`anytls`/`vless`, ignored; \
                 remove it to suppress this warning",
                raw_l.name
            );
        }
        for (key, set) in [
            ("mtu", raw_l.mtu.is_some()),
            ("peers", raw_l.peers.is_some()),
        ] {
            if set && !matches!(spec, ListenerSpec::WireGuard(_)) {
                warn!(
                    "listeners[{}].{key}: only meaningful on `type: wireguard`/`tun`, ignored; \
                     remove it to suppress this warning",
                    raw_l.name
                );
            }
        }
        // AnyTLS/VLESS-shared TLS-identity fields set on another listener
        // type warn — same shape as the wireguard check above. `users` and
        // the certificate pair are consumed by both types (in their own
        // shapes); `padding-scheme` stays AnyTLS-only.
        for (key, set) in [
            ("users", raw_l.users.is_some()),
            ("certificate", raw_l.certificate.is_some()),
            ("client-auth-type", raw_l.client_auth_type.is_some()),
            ("client-auth-cert", raw_l.client_auth_cert.is_some()),
            ("ech-key", raw_l.ech_key.is_some()),
            ("allow-insecure", raw_l.allow_insecure.is_some()),
        ] {
            if set && !matches!(spec, ListenerSpec::Anytls(_) | ListenerSpec::Vless(_)) {
                warn!(
                    "listeners[{}].{key}: only meaningful on `type: anytls`/`vless`, ignored; \
                     remove it to suppress this warning",
                    raw_l.name
                );
            }
        }
        for (key, set) in [("padding-scheme", raw_l.padding_scheme.is_some())] {
            if set && !matches!(spec, ListenerSpec::Anytls(_)) {
                warn!(
                    "listeners[{}].{key}: only meaningful on `type: anytls`, ignored; \
                     remove it to suppress this warning",
                    raw_l.name
                );
            }
        }
        // VLESS-only fields set on another listener type warn — same
        // shape. (`type: vless` validates these keys inside its own
        // builder; every other type has no use for them.)
        for (key, set) in [
            ("decryption", raw_l.decryption.is_some()),
            ("alpn", raw_l.alpn.is_some()),
            ("reality-config", raw_l.reality_config.is_some()),
        ] {
            if set && !matches!(spec, ListenerSpec::Vless(_)) {
                warn!(
                    "listeners[{}].{key}: only meaningful on `type: vless`, ignored; \
                     remove it to suppress this warning",
                    raw_l.name
                );
            }
        }
        // `enable` is meaningful on `type: anytls` (diagnosed inside its
        // builder) and hard-errors on `type: tun` above; elsewhere it is
        // a silently-dead key unless warned about here.
        if raw_l.enable.is_some() && !matches!(spec, ListenerSpec::Anytls(_)) {
            warn!(
                "listeners[{}].enable: only meaningful on `type: anytls`, ignored; \
                 remove it to suppress this warning",
                raw_l.name
            );
        }
        // Named-TUN-only fields set on another listener type warn —
        // same shape as the wireguard-field check above.
        for (key, set) in [
            ("device", raw_l.device.is_some()),
            ("stack", raw_l.stack.is_some()),
            ("dns-hijack", raw_l.dns_hijack.is_some()),
            ("auto-route", raw_l.auto_route.is_some()),
            ("outbound-interface", raw_l.outbound_interface.is_some()),
            ("inet4-address", raw_l.inet4_address.is_some()),
            ("inet6-address", raw_l.inet6_address.is_some()),
            ("dns-mode", raw_l.dns_mode.is_some()),
            ("strict-route", raw_l.strict_route.is_some()),
            (
                "auto-detect-interface",
                raw_l.auto_detect_interface.is_some(),
            ),
            ("auto-redirect", raw_l.auto_redirect.is_some()),
            (
                "endpoint-independent-nat",
                raw_l.endpoint_independent_nat.is_some(),
            ),
            ("mtu-v6", raw_l.mtu_v6.is_some()),
            ("route-address", raw_l.route_address.is_some()),
            (
                "route-exclude-address",
                raw_l.route_exclude_address.is_some(),
            ),
            ("include-uid", raw_l.include_uid.is_some()),
            ("exclude-uid", raw_l.exclude_uid.is_some()),
            ("gso", raw_l.gso.is_some()),
            ("file-descriptor", raw_l.file_descriptor.is_some()),
        ] {
            if set {
                warn!(
                    "listeners[{}].{key}: only meaningful on `type: tun`, ignored; \
                     remove it to suppress this warning",
                    raw_l.name
                );
            }
        }
        // `transparent` is tproxy-only — on `type: redir` it already
        // warned at spec-parse, so non-TProxy specs are all that remain.
        if raw_l.transparent.is_some() && !matches!(spec, ListenerSpec::TProxy { .. }) {
            warn!(
                "listeners[{}].transparent: only meaningful on `type: tproxy`, ignored; \
                 remove it to suppress this warning",
                raw_l.name
            );
        }
        let listen_raw = raw_l.listen.as_deref().unwrap_or_else(|| {
            // A `type: redir` or `transparent: true` entry only ever sees
            // PREROUTING-steered traffic, which the kernel delivers to the
            // inbound interface address — a loopback default would be a
            // dead listener, so those take the allow-lan-honoring bind the
            // port shorthands use. Other tproxy entries keep the
            // historical 127.0.0.1 default (issue #563 shape).
            let gateway_facing = is_redir
                || matches!(
                    spec,
                    ListenerSpec::TProxy {
                        transparent: true,
                        ..
                    }
                );
            if matches!(spec, ListenerSpec::WireGuard(_)) {
                // A WG responder exists to accept peers from the network —
                // the spec pins `0.0.0.0` rather than the shared
                // `default_bind` convention (spec §2.1); loopback is
                // always writable explicitly for tests.
                "0.0.0.0"
            } else if gateway_facing || !matches!(spec, ListenerSpec::TProxy { .. }) {
                default_bind
            } else {
                "127.0.0.1"
            }
        });
        // `parse_listener_spec` returns a placeholder for `Shadowsocks` and
        // `Anytls`; fold the real per-type fields in here BEFORE the bind
        // resolve — `type: anytls` may carry a comma-separated `listen`
        // list, which `resolve_listener_bind` cannot split. TProxy's
        // `sni` is already resolved inside `parse_listener_spec`.
        let spec = match spec {
            ListenerSpec::Shadowsocks(_) => {
                ListenerSpec::Shadowsocks(build_ss_listener_spec(raw_l)?)
            }
            ListenerSpec::Anytls(_) => {
                ListenerSpec::Anytls(build_anytls_listener_spec(raw_l, default_bind)?)
            }
            ListenerSpec::Vless(_) => {
                ListenerSpec::Vless(build_vless_listener_spec(raw_l, default_bind)?)
            }
            other => other,
        };
        // The UDP-TPROXY address-family contract is checked on the raw
        // spelling first: socket normalization below drops an IPv6 zone
        // (`[…%N]:port`), and scoped input must fail rather than lose it.
        if matches!(&spec, ListenerSpec::TProxy { udp: true, .. }) {
            validate_tproxy_udp_listen(listen_raw, &raw_l.name)?;
        }
        // The anytls/vless builders already normalized every bind target;
        // the first address plays `NamedListener.listen`/`port` while the
        // full `addresses` list stays on the spec.
        let (listen, port) = match &spec {
            ListenerSpec::Anytls(cfg) => (cfg.addresses[0].listen.clone(), cfg.addresses[0].port),
            ListenerSpec::Vless(cfg) => (cfg.addresses[0].listen.clone(), cfg.addresses[0].port),
            _ => resolve_listener_bind(listen_raw, raw_l.port)?,
        };
        // `listeners[].rule` selects a `sub-rules:` block BY NAME — not a
        // rule-provider and not an `IN-NAME` rule (upstream
        // `WithSpecialRules`). Requiring the block in this same document
        // is the `SUB-RULE,…` hard-error contract (Class A per ADR-0002);
        // a block a later PUT removes fails closed in the resolver.
        if let Some(name) = raw_l.rule.as_deref().filter(|s| !s.is_empty()) {
            let defined = raw.sub_rules.as_ref().is_some_and(|m| m.contains_key(name));
            if !defined {
                anyhow::bail!(
                    "listeners[{}].rule: '{name}' references undefined sub-rules block",
                    raw_l.name
                );
            }
        }
        let route_override =
            meow_common::InboundRouteOverride::new(raw_l.proxy.as_deref(), raw_l.rule.as_deref());
        // `listeners[].routing-mark` marks the LISTENER socket at bind
        // (ingress SO_MARK, upstream `InboundOption.RoutingMark`) —
        // Linux-only; the top-level `routing-mark` outbound key is a
        // different consumer and is not altered. `0` normalizes to
        // "unset" like the top-level key — a literal mark-0 `setsockopt`
        // would tag the socket 0, the firewall-exempt wildcard.
        // TPROXY (`redir` lowers to it) and WireGuard have no ingress
        // mark contract — steered/responder sockets are not marked, so
        // the key warns and ignores there.
        let routing_mark = match spec {
            ListenerSpec::TProxy { .. } | ListenerSpec::WireGuard(_) => {
                if raw_l.routing_mark.is_some() {
                    warn!(
                        "listeners[{}].routing-mark: has no effect on `type: {}` — \
                         only socket listeners with a client-facing bind honour it \
                         (mixed/socks5/http/shadowsocks); ignored",
                        raw_l.name,
                        if is_redir {
                            "redir"
                        } else {
                            raw_l.listener_type.as_str()
                        }
                    );
                }
                None
            }
            _ => raw_l.routing_mark.filter(|m| *m != 0),
        };
        // Same predicate the mark impls use (`SO_MARK` is set only under
        // `all(linux, not(ohos))`): OHOS reports `target_os = "linux"` but
        // its impl is cfg'd out, so a plain `not(linux)` guard would let an
        // OHOS mark pass silently instead of warning like other platforms.
        #[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
        if routing_mark.is_some() {
            warn!(
                "listeners[{}].routing-mark: SO_MARK is Linux-only — ignored \
                 on this platform; remove it to suppress this warning",
                raw_l.name
            );
        }
        let max_connections = raw_l.max_connections.unwrap_or(global_max_conns);
        // Every port a multi-address `type: anytls`/`type: vless` binds
        // must join the duplicate-port registry, not just the primary one.
        let extra_ports: Vec<u16> = match &spec {
            ListenerSpec::Anytls(cfg) => cfg.addresses[1..].iter().map(|a| a.port).collect(),
            ListenerSpec::Vless(cfg) => cfg.addresses[1..].iter().map(|a| a.port).collect(),
            _ => Vec::new(),
        };
        add(
            &raw_l.name,
            spec,
            port,
            &listen,
            max_connections,
            route_override,
            routing_mark,
            &extra_ports,
        )?;
    }

    Ok(result)
}

/// Build a runnable [`Config`] from an already-parsed raw document. This is
/// where startup network I/O happens (ECH pre-resolution, proxy-provider
/// and rule-provider fetches, geodata downloads). `cache_dir` is the
/// resource cache for provider/geodata files — pass
/// [`resource_cache_dir_for_config_path`] of the config file, or `None`
/// for a document with no backing file (`--config-string`).
pub async fn build_config(
    raw: raw::RawConfig,
    cache_dir: Option<&Path>,
) -> Result<Config, anyhow::Error> {
    dns_parser::validate_node_policy_sources(&raw)?;
    // `global-ua` (issue #974): validate, then install the process-global
    // *before* any provider/subscription/geodata/ECH fetch below emits a
    // `User-Agent`. Unlike `routing-mark`/`interface-name` (application
    // and API commit points install those), the install lives here so
    // library callers — `load_config`/`load_config_from_str` — also send
    // the UA on startup fetches. A `PUT`/`PATCH` candidate does not reach
    // this lane; the API's commit point re-asserts it there.
    //
    // The install is live process state, so a failed build must not keep
    // it: snapshot the installed value first and restore it on every
    // error path out of `build_config_inner` — a rejected config's UA
    // would otherwise linger on the emitters of whatever config stays
    // live (issue #974 review).
    let previous_ua = meow_common::global_ua();
    meow_common::set_global_ua(validate_global_ua(raw.global_ua.as_deref())?);
    let built = build_config_inner(raw, cache_dir).await;
    if built.is_err() {
        meow_common::set_global_ua(previous_ua.as_deref());
    }
    built
}

/// [`build_config`]'s build body, split out so the wrapper can restore the
/// previous process-global `User-Agent` on every error path — the
/// candidate's UA is installed before the fetches below, and a late `?`
/// must not leave it live (issue #974 review).
async fn build_config_inner(
    mut raw: raw::RawConfig,
    cache_dir: Option<&Path>,
) -> Result<Config, anyhow::Error> {
    // Local shape/range gates BEFORE any candidate network work (issue
    // #974): a defect in `ntp:`/`keep-alive-*`/`tcp-*`/`listeners:`/`tun:`
    // must reject the document without the ECH pre-resolution or provider
    // fetches below ever opening a socket. The resolvers are pure over
    // `raw` — nothing they read is mutated by the passes that follow.
    let ntp_resolved_for_config = resolve_ntp(&raw)?;
    // `tcp-idle-timeout` — resolution and validation live in
    // [`resolve_tcp_idle_timeout`], which `PUT /configs` also gates
    // persistence and hot-apply on so a committed document cannot fail
    // this boot path.
    let tcp_idle_timeout = resolve_tcp_idle_timeout(&raw)?;
    // `tcp-keepalive*` — the keepalive posture every inbound listener
    // applies to accepted sockets. Resolution and validation live in
    // [`resolve_tcp_keepalive`], which `PUT /configs` also gates
    // persistence on so a committed document cannot fail this boot path.
    let tcp_keepalive = resolve_tcp_keepalive(&raw)?;
    // `keep-alive-*` — the keepalive posture `connect_tcp` applies to
    // outbound dials. Validated here (and on `-t`) so a bad value fails
    // admission; the process-global install belongs to the launcher's
    // commit point — a candidate build must never mutate live policy.
    let _ = resolve_outbound_tcp_keepalive(&raw)?;
    // `lan-allowed-ips`/`lan-disallowed-ips` — the shared inbound TCP ACL.
    // Startup-only like `listeners:` (upstream live-patches the prefix
    // lists; meow deliberately matches its listener-auth lifecycle).
    let lan_acl = Arc::new(resolve_lan_acl(&raw)?);
    // The `listeners:` shape: duplicate names/ports, `rule:`/`proxy:`
    // declaration checks, the one-TUN gates — all document-local.
    let (bind_addr, global_tproxy_sni) = listener_bind_inputs(&raw);
    let named_listeners = build_named_listeners(&raw, &bind_addr, global_tproxy_sni)?;
    // TUN inbound (issue #326) — parses `tun:`/`sniffer:` off raw only.
    let tun = parse_tun_config(raw.tun.as_ref(), raw.max_connections, raw.fake_ip_range())?;
    let sniffer = parse_sniffer_config(&raw, raw.strict.unwrap_or(false))?;
    let auth = Arc::new(
        auth::parse_auth_config(
            raw.authentication.as_deref(),
            raw.skip_auth_prefixes.as_deref(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    );
    // Geodata config — `geox-url` is the mihomo top-level alias, merged
    // per-key under the explicit `geodata.url.*` values.
    let geodata = geodata::parse_geodata(&raw)?;
    // `mode` is a shape check too — under `strict` an unknown value
    // hard-fails.
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

    // `smux:`/`mux:` blocks on the static leaves are the last local
    // shape check: a malformed one must reject here, before the ECH
    // pre-resolution below opens sockets (issue #974 review). The gate
    // mirrors the parse's strictness — the rejection it orders ahead of
    // the socket work is the strict one; lenient mode warn-drops the
    // node in the real parse below instead.
    proxy_parser::check_mux_shape(&raw, raw.strict.unwrap_or(false))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // Pre-resolve any DNS-sourced ECH configs into inline base64 so the
    // sync `parse_proxy` path that follows can stay sync. Failures warn
    // and leave the map unchanged — except the `enable: true` with no
    // query-source defect, which `strict` promotes to an error.
    if let Some(ps) = raw.proxies.as_mut() {
        ech_dns::preresolve_ech(ps, raw.strict.unwrap_or(false))
            .await
            .map_err(|e| anyhow::anyhow!("{e} (strict mode)"))?;
    }

    // General config
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
        connection_notes: raw.connection_notes.unwrap_or(false),
        logbook: raw::RawLogbook::enabled(raw.logbook.as_ref()),
        tcp_idle_timeout,
        tcp_concurrent: effective_tcp_concurrent(raw.tcp_concurrent),
        find_process_mode: raw.find_process_mode.unwrap_or_default(),
    };

    // Registry the provider nodes' `dialer-proxy` targets resolve against
    // (issue #489). It is shared into every provider *before* they load so
    // nodes parsed during the initial refresh already hold the handle; the
    // tunnel publishes the live route map into it on every routing install.
    let provider_dialer_registry = meow_proxy::dialer::ProxyRegistry::default();
    // The cell `type: dns` leaves bind (issue #974) — shared into every
    // provider before it loads and every static leaf the passes below
    // build, then handed to the tunnel (`Tunnel::set_dns_outbound_cell`)
    // so `install_resolver_everywhere` republishes the live resolver
    // slot into it. `Config::provider_dns_cell` retains it like
    // `provider_dialer_registry`.
    let provider_dns_cell = meow_dns::new_dns_outbound_cell();

    // Load proxy providers (async: may HTTP-fetch provider files). The build
    // passes below leave out the same ones again; this load's are kept.
    let mut dropped_providers = DroppedProviders::default();
    let proxy_providers = if let Some(raw_pp) = raw.proxy_providers.as_ref() {
        if raw_pp.is_empty() {
            HashMap::new()
        } else {
            proxy_provider::load_proxy_providers_within(
                raw_pp,
                cache_dir,
                general.ipv6,
                raw.strict.unwrap_or(false),
                &provider_dialer_registry,
                raw.global_client_fingerprint.as_deref(),
                provider_fetch_deadline(),
                Some(&provider_dns_cell),
                &mut dropped_providers,
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
    // adapters may be retained by rule-provider fetch contexts for the
    // first generation; DNS resolves named proxies through this shared cell,
    // and the shared cell lets them resolve the pass-2 snapshot rather than
    // a stale pass-1 map (issue #533).
    let dialer_registry = meow_proxy::dialer::ProxyRegistry::default();
    // Open the persistent selector store (one JSON file in cache_dir).
    // Missing/unreadable files yield an empty store — no fatal errors.
    let cache_dir_buf = cache_dir.map(Path::to_path_buf);
    // The config-scoped selection-persistence owner: the file-backed
    // store opens lazily for an enabled `profile.store-selected` only —
    // a disabled profile never touches disk, and `-t` validation never
    // reaches this point's fs work at all (issue #974).
    let selection_backing = std::sync::Arc::new(meow_proxy::SelectionBacking::new(
        cache_dir_buf
            .as_ref()
            .map(|d| d.join("selector-cache.json")),
    ));
    let resolved_profile = resolve_profile(&raw);
    if !is_offline_validate() {
        selection_backing
            .prepare(resolved_profile.store_selected)
            .await;
    }
    let selector_writer = selection_backing.attach(resolved_profile.store_selected);

    // One shared pre-registry proxy layer for the two startup fetches that
    // can ride a proxy (rule-provider prefetch + geodata download). Built
    // only when at least one of them could need it — a full layer costs an
    // adapter construction per `proxies:` entry (issue #533).
    let prefetch_proxies = if prefetch_proxy_layer_needed(&raw, &geodata) {
        prefetch_proxy_layer_async(
            &raw,
            &proxy_providers,
            selector_writer.as_ref(),
            &provider_dialer_registry,
            &provider_dns_cell,
        )
        .await?
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
    // The same reference verdict gates the startup fetch and rides the
    // Config out to the auto-update loop — one judgment, two consumers.
    let geo_needs = geo_references(&raw, &geo_scan_lines);
    ensure_geodata(
        &raw,
        &geodata,
        &geo_scan_lines,
        prefetch_proxies.as_deref().map(|p| &p.map),
        &chained_provider_names(&proxy_providers),
    )
    .await;
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
            selector_writer.clone(),
            ctx.clone(),
            Arc::clone(&provider_payloads),
            dialer_registry.clone(),
            provider_dialer_registry.clone(),
            Arc::clone(&provider_dns_cell),
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
            let (providers, mut dropped) = load_rule_providers_async(
                map.clone(),
                cache_dir_buf.clone(),
                ctx.clone(),
                download_proxy,
                proxies.clone(),
                Arc::clone(&provider_payloads),
                Some(dialer_registry.clone()),
                raw.strict.unwrap_or(false),
            )
            .await?;
            dropped_providers.take_rule(&mut dropped);
            providers
        }
        _ => HashMap::new(),
    };

    // DNS — pass the explicit mmdb path so fallback-filter GeoIP uses the
    // same path as the rule engine, plus the proxy registry from step 1
    // so #PROXY-tagged nameservers can resolve their referenced adapter.
    // Bind DNS to the published generation rather than retaining pass-1 groups.
    // Weak targets avoid a resolver -> DIRECT -> resolver ownership cycle.
    let dns_proxies = dns_proxy::registry(&proxies, &dialer_registry);
    let dns_config = dns_parser::parse_dns(
        &raw,
        geodata.mmdb_path.as_deref(),
        cache_dir,
        &dns_proxies,
        ctx.geosite.clone(),
        &rule_providers,
        None,
    )
    .await?;
    // Bind the dns-outbound cell to the slot the embedder hands the
    // tunnel (`Tunnel::new_with_slot(config.dns.resolver_slot)`): `type:
    // dns` leaves parsed in pass 1 — and provider nodes parsed before
    // this line — now resolve the live generation from their first
    // query. A disabled `dns:` still binds: `ResolverGen.enabled` is the
    // SERVFAIL verdict, not an unbound cell. `install_resolver_everywhere`
    // re-asserts the same object on every later install (issue #974).
    *provider_dns_cell.write() = Some(Arc::clone(&dns_config.resolver_slot));

    let (proxies, rules, sub_rules, _) = {
        let res = rebuild_from_raw_impl_async(
            raw.clone(),
            cache_dir_buf.clone(),
            Some(Arc::clone(&dns_config.resolver_slot)),
            proxy_providers.clone(),
            selector_writer.clone(),
            ctx.clone(),
            Arc::clone(&provider_payloads),
            dialer_registry.clone(),
            provider_dialer_registry.clone(),
            Arc::clone(&provider_dns_cell),
            // Share the provider set already loaded for DNS so rules,
            // `rule-set:` matchers, and `Config.rule_providers` reference
            // one object per provider (issue #533 review).
            Some(rule_providers.clone()),
        )
        .await?;
        (res.proxies, res.rules, res.sub_rules, res.dialer_registry)
    };

    // Listener config — `named_listeners`, `tcp_keepalive` and `lan_acl`
    // resolved in the local-gates block above, before the ECH/provider
    // network passes (issue #974).
    let listeners = ListenerConfig {
        mixed_port: raw.mixed_port,
        socks_port: raw.socks_port,
        http_port: raw.port,
        bind_address: bind_addr,
        tproxy_port: raw.tproxy_port,
        tproxy_sni: global_tproxy_sni,
        // `Some(0)` means "unset" like `None` (`set_routing_mark` stores 0
        // for both) — normalize here so no downstream consumer can read a
        // literal mark-0 as "exempt unmarked traffic" (see
        // `FirewallGuard::setup`, which filters again defensively).
        routing_mark: raw.routing_mark.filter(|m| *m != 0),
        tcp_keepalive,
        lan_acl,
        named: named_listeners,
    };

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
    // `external-controller-{tls,unix,pipe}` keep their strings: `-t` must
    // validate shape only, and each is resolved at endpoint bind (like
    // upstream, which never parses them into SockAddrs). `""` disables.
    let external_controller_tls = raw
        .external_controller_tls
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(String::from);
    // `tls.certificate`/`tls.private-key` are the HTTPS listener's
    // identity. Like upstream, build validates *shape only*: a one-sided
    // pair, malformed inline PEM, and unreadable file paths all defer to
    // endpoint bind, where the failure logs and skips just that endpoint
    // (issue #974). Deferring keeps a broken identity from killing the
    // whole config — `-t` accepts the same documents upstream's does —
    // and no PEM material or file I/O is touched here.
    let tls_certificate = raw
        .tls
        .as_ref()
        .and_then(|t| t.certificate.as_deref())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let tls_private_key = raw
        .tls
        .as_ref()
        .and_then(|t| t.private_key.as_deref())
        .filter(|s| !s.is_empty())
        .map(String::from);
    if external_controller_tls.is_none() && (tls_certificate.is_some() || tls_private_key.is_some())
    {
        warn!(
            "tls.certificate/tls.private-key set without external-controller-tls; \
             the keys only feed the HTTPS controller listener and are ignored"
        );
    }
    let api = ApiConfig {
        external_controller: parse_optional_socket_addr(
            "external-controller",
            raw.external_controller.as_deref(),
        )?,
        external_controller_tls,
        external_controller_unix: raw
            .external_controller_unix
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(String::from),
        external_controller_pipe: raw
            .external_controller_pipe
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(String::from),
        tls_certificate,
        tls_private_key,
        cors: ApiCorsConfig::from_raw(raw.external_controller_cors.as_ref()),
        secret: raw.secret.clone(),
        external_ui,
        external_ui_url: raw
            .external_ui_url
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(String::from),
    };

    info!(
        "Config loaded: mode={}, proxies={}, rules={}",
        mode,
        proxies.len(),
        rules.len()
    );

    // Startup's route commit for the selection epoch: writers this build
    // attached priced the pending enable transition, so publishing the
    // resolved flag here is what un-fences them. A `-t` validation runs
    // the same no-op on a throwaway backing — memory only, no fs.
    selection_backing.commit(resolved_profile.store_selected);

    Ok(Config {
        general,
        dns: dns_config,
        proxies,
        proxy_providers,
        provider_dialer_registry,
        provider_dns_cell,
        rules,
        sub_rules,
        rule_providers,
        dropped_providers,
        dialer_registry,
        selection: selection_backing,
        ntp: ntp_resolved_for_config,
        listeners,
        tun,
        api,
        sniffer,
        auth,
        raw,
        geodata,
        geo_needs,
    })
}

#[cfg(test)]
mod missing_plugin_placeholder_tests {
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    use super::*;

    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    fn raw_gost_node() -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert(
            "name".to_string(),
            serde_json::Value::String("s-gost".to_string()),
        );
        m.insert(
            "type".to_string(),
            serde_json::Value::String("ss".to_string()),
        );
        m.insert(
            "server".to_string(),
            serde_json::Value::String("1.2.3.4".to_string()),
        );
        m.insert("port".to_string(), serde_json::Value::from(8388u16));
        m.insert(
            "password".to_string(),
            serde_json::Value::String("p".to_string()),
        );
        m.insert(
            "cipher".to_string(),
            serde_json::Value::String("aes-128-gcm".to_string()),
        );
        m.insert(
            "plugin".to_string(),
            serde_json::Value::String("gost-plugin".to_string()),
        );
        m
    }

    /// Every assertion below is the placeholder contract the compiled-out
    /// `trusttunnel` type already keeps: the node stays bound under its own
    /// name as a permanently dead `Shadowsocks` entry — never dropped, so a
    /// `select` group or explicit reference to it fails the dial instead of
    /// shifting the traffic to a sibling or DIRECT (liveness-checked groups
    /// skip it like any unavailable member) — and its dial reason is the
    /// adapter's "not compiled into this build" error.
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    async fn assert_dead_ss_placeholder(proxy: &Arc<dyn Proxy>) {
        assert!(!proxy.alive(), "a placeholder must never look usable");
        assert_eq!(
            proxy.adapter_type(),
            meow_common::AdapterType::Shadowsocks,
            "a placeholder must keep the node's own type"
        );
        let error = proxy
            .dial_tcp(&meow_common::Metadata::default())
            .await
            .err()
            .expect("a placeholder must fail the dial, not leak it direct")
            .to_string();
        assert!(error.contains(proxy.name()), "{error}");
        assert!(
            error.contains("not compiled into this build"),
            "the placeholder's reason must be the plugin gate error: {error}"
        );
    }

    /// The node keeps its slot instead of warn-dropping — under offline
    /// validate (`-t`) and boot alike, since the arm does not distinguish
    /// them: the whole point is `-t` and boot reading the file identically.
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[tokio::test]
    async fn missing_plugin_node_binds_a_dead_placeholder() {
        let mut proxies = HashMap::new();
        let mut names = std::collections::HashSet::new();
        insert_parsed_leaves(
            &mut proxies,
            &mut names,
            &[raw_gost_node()],
            None,
            false,
            false,
            &meow_proxy::dialer::ProxyRegistry::default(),
            &HashMap::new(),
            None,
            &meow_dns::new_dns_outbound_cell(),
        )
        .unwrap();
        let bound = proxies
            .get("s-gost")
            .expect("a missing-plugin node must stay bound, not dropped");
        assert_dead_ss_placeholder(bound).await;
    }

    /// `strict: true` still hard-errors first — the placeholder arm only
    /// covers lenient parsing, so a bad local file keeps failing loudly.
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[test]
    fn missing_plugin_node_still_hard_errors_under_strict() {
        let mut proxies = HashMap::new();
        let mut names = std::collections::HashSet::new();
        let err = insert_parsed_leaves(
            &mut proxies,
            &mut names,
            &[raw_gost_node()],
            None,
            false,
            true,
            &meow_proxy::dialer::ProxyRegistry::default(),
            &HashMap::new(),
            None,
            &meow_dns::new_dns_outbound_cell(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("strict mode"),
            "strict must still hard-error: {err}"
        );
    }

    /// End-to-end at `load_config` level: a `select` group listing only the
    /// dead node must keep it selected — dialing through the group fails
    /// with the plugin-gate error instead of sliding to DIRECT. (A
    /// `url-test`/`fallback` group would still skip the dead member by
    /// liveness — the placeholder pins references, not health probes.)
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[tokio::test]
    async fn group_listing_dead_node_cannot_slide_to_direct() {
        let raw: raw::RawConfig = serde_saphyr::from_str(
            "proxies:\n\
            \x20 - name: s-gost\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    \
             password: p\n    cipher: aes-128-gcm\n    plugin: gost-plugin\n\
             proxy-groups:\n\
            \x20 - name: G\n    type: select\n    proxies: [s-gost]\n\
             rules:\n  - MATCH,G\n",
        )
        .unwrap();
        let config = build_config(raw, None)
            .await
            .expect("a missing-plugin node must not reject the config");
        let group = config
            .proxies
            .get("G")
            .expect("group G must build around the dead node");
        let err = group
            .dial_tcp(&meow_common::Metadata::default())
            .await
            .err()
            .expect("a dial through G must fail — never fall back to DIRECT");
        assert!(
            err.to_string().contains("not compiled into this build"),
            "the group dial must surface the plugin-gate reason: {err}"
        );
    }

    /// `meow -t` reads the file exactly like boot does: the load succeeds
    /// (exit 0 equivalent) with the node bound dead. The flag is
    /// process-global and never reset, so the assertion runs in a child
    /// process (same pattern as rule_provider's
    /// `MEOW_OFFLINE_VALIDATE_CHILD`).
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[test]
    fn offline_validate_passes_with_the_node_bound_dead() {
        const CHILD: &str = "MEOW_OFFLINE_PLACEHOLDER_CHILD";
        if std::env::var_os(CHILD).is_some() {
            crate::set_offline_validate(true);
            let rt = tokio::runtime::Runtime::new().unwrap();
            let raw: raw::RawConfig = serde_saphyr::from_str(
                "proxies:\n\
                \x20 - name: s-gost\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    \
                 password: p\n    cipher: aes-128-gcm\n    plugin: gost-plugin\n\
                 proxy-groups:\n\
                \x20 - name: G\n    type: select\n    proxies: [s-gost]\n\
                 rules:\n  - MATCH,G\n",
            )
            .unwrap();
            let config = rt
                .block_on(build_config(raw, None))
                .expect("offline validate must pass with the node bound dead");
            let bound = config
                .proxies
                .get("s-gost")
                .expect("the node must stay bound under -t");
            assert!(!bound.alive(), "a placeholder must never look usable");
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe)
            .arg("--exact")
            .arg("missing_plugin_placeholder_tests::offline_validate_passes_with_the_node_bound_dead")
            .arg("--nocapture")
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success(), "child gate run failed: {status:?}");
    }

    /// An explicit `MATCH,<node>` rule is the other reference a dead
    /// placeholder must pin: the name resolves to the bound entry, so the
    /// dial fails with the plugin-gate error instead of the rule pointing
    /// at nothing — the same contract `select` gets above.
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[tokio::test]
    async fn match_rule_to_dead_node_still_fails_the_dial() {
        let raw: raw::RawConfig = serde_saphyr::from_str(
            "proxies:\n\
            \x20 - name: s-gost\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    \
             password: p\n    cipher: aes-128-gcm\n    plugin: gost-plugin\n\
             rules:\n  - MATCH,s-gost\n",
        )
        .unwrap();
        let config = build_config(raw, None)
            .await
            .expect("a missing-plugin node must not reject the config");
        let bound = config
            .proxies
            .get("s-gost")
            .expect("the MATCH target must stay bound, not vanish");
        assert_dead_ss_placeholder(bound).await;
    }

    /// A `dialer-proxy:` edge on a missing-plugin node must NOT be wrapped
    /// in `DialerProxyAdapter`: that wrapper reports `support_udp() ==
    /// false`, hiding `UnavailableAdapter`'s `true` guard that keeps a UDP
    /// rule from sliding to DIRECT. The node is dead either way, so the
    /// chain adds nothing for TCP — the placeholder stays as it is.
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[tokio::test]
    async fn missing_plugin_node_with_dialer_proxy_keeps_the_udp_guard() {
        let raw: raw::RawConfig = serde_saphyr::from_str(
            "proxies:\n\
            \x20 - name: front\n    type: direct\n    udp: true\n\
            \x20 - name: s-gost\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    \
             password: p\n    cipher: aes-128-gcm\n    plugin: gost-plugin\n    \
             dialer-proxy: front\n\
             rules:\n  - MATCH,s-gost\n",
        )
        .unwrap();
        let config = build_config(raw, None)
            .await
            .expect("a missing-plugin node must not reject the config");
        let bound = config
            .proxies
            .get("s-gost")
            .expect("the node must stay bound, not dropped");
        assert!(
            bound.support_udp(),
            "the UDP guard must survive — a DialerProxyAdapter wrap reports false"
        );
        assert_dead_ss_placeholder(bound).await;
    }

    /// A same-named unparseable duplicate must not shadow the live entry
    /// that came first — upstream dropped it, so it could never displace a
    /// working node; the placeholder fills only an empty slot. (A live
    /// duplicate still replaces an earlier placeholder, via the normal
    /// insert — and the placeholder set must forget the name so a later
    /// same-named edged block wraps it normally.)
    #[cfg(all(feature = "ss", not(feature = "gost-plugin")))]
    #[test]
    fn placeholder_duplicate_never_shadows_a_live_binding() {
        let raw_direct_dup = || {
            HashMap::from([
                (
                    "name".to_string(),
                    serde_json::Value::String("dup".to_string()),
                ),
                (
                    "type".to_string(),
                    serde_json::Value::String("direct".to_string()),
                ),
            ])
        };
        let raw_dead_dup = || {
            let mut dead = raw_gost_node();
            dead.insert(
                "name".to_string(),
                serde_json::Value::String("dup".to_string()),
            );
            dead
        };

        let mut proxies = HashMap::new();
        let mut names = std::collections::HashSet::new();
        let placeholders = insert_parsed_leaves(
            &mut proxies,
            &mut names,
            &[raw_direct_dup(), raw_dead_dup()],
            None,
            false,
            false,
            &meow_proxy::dialer::ProxyRegistry::default(),
            &HashMap::new(),
            None,
            &meow_dns::new_dns_outbound_cell(),
        )
        .unwrap();
        assert_eq!(
            proxies["dup"].adapter_type(),
            meow_common::AdapterType::Direct,
            "the earlier live binding must survive the unparseable duplicate"
        );
        assert!(
            !placeholders.contains("dup"),
            "a live-bound name must not read as a placeholder"
        );

        // The reverse order — placeholder first, live block second — keeps
        // last-wins for the live entry and unmarks the name.
        let mut proxies = HashMap::new();
        let mut names = std::collections::HashSet::new();
        let placeholders = insert_parsed_leaves(
            &mut proxies,
            &mut names,
            &[raw_dead_dup(), raw_direct_dup()],
            None,
            false,
            false,
            &meow_proxy::dialer::ProxyRegistry::default(),
            &HashMap::new(),
            None,
            &meow_dns::new_dns_outbound_cell(),
        )
        .unwrap();
        assert_eq!(
            proxies["dup"].adapter_type(),
            meow_common::AdapterType::Direct,
            "a live duplicate still replaces an earlier placeholder"
        );
        assert!(
            !placeholders.contains("dup"),
            "the replaced name must not read as a placeholder"
        );
    }
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

    fn raw_proxy(name: &str, dialer: Option<&str>) -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert(
            "name".to_string(),
            serde_json::Value::String(name.to_string()),
        );
        if let Some(d) = dialer {
            m.insert(
                "dialer-proxy".to_string(),
                serde_json::Value::String(d.to_string()),
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

    /// Run the dialer pipeline against a fresh by-name registry and publish it
    /// on success, the way `rebuild_from_raw_impl` does — without the publish
    /// the chained adapters cannot resolve their front hop at dial time.
    ///
    /// Returns the registry: `DialerTarget`s hold it weakly (issue #533), so a
    /// test that actually dials must keep the handle alive for the duration.
    fn apply_chains(
        proxies: &mut HashMap<SmolStr, Arc<dyn Proxy>>,
        raw_proxies: &[HashMap<String, serde_json::Value>],
    ) -> Result<meow_proxy::dialer::ProxyRegistry, anyhow::Error> {
        apply_chains_with_groups(proxies, raw_proxies, &[])
    }

    /// Same as [`apply_chains`] but with declared `proxy-groups`, so tests can
    /// exercise group-valued dialers and the membership cycle check. Stands in
    /// for the group build by giving every declared group a registry entry —
    /// the cycle check models declared membership, so what the entry *is*
    /// does not matter, only that it exists.
    ///
    /// Mirrors `build_proxy_layer`'s order — collect the edges, single-parse
    /// the leaves with them, validate targets, then stub groups and run the
    /// membership-cycle check — minus the real group construction.
    fn apply_chains_with_groups(
        proxies: &mut HashMap<SmolStr, Arc<dyn Proxy>>,
        raw_proxies: &[HashMap<String, serde_json::Value>],
        raw_groups: &[raw::RawProxyGroup],
    ) -> Result<meow_proxy::dialer::ProxyRegistry, anyhow::Error> {
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        let edges = collect_dialer_edges(raw_proxies, false)?;
        let mut static_proxy_names = std::collections::HashSet::new();
        let dns_cell = meow_dns::new_dns_outbound_cell();
        insert_parsed_leaves(
            proxies,
            &mut static_proxy_names,
            raw_proxies,
            None,
            true,
            false,
            &registry,
            &edges.by_index,
            None,
            &dns_cell,
        )?;
        apply_dialer_proxies_validate(proxies, &edges.declared, raw_groups)?;
        for group in raw_groups {
            proxies
                .entry(SmolStr::from(group.name.as_str()))
                .or_insert_with(|| simple_proxy(&group.name));
        }
        let global_auto_created = !proxies.contains_key("GLOBAL");
        let include_all_proxy_names = raw_proxies
            .iter()
            .filter_map(|proxy| proxy.get("name").and_then(serde_json::Value::as_str))
            .map(SmolStr::from)
            .collect();
        reject_group_membership_cycles(
            &edges.declared,
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
        let raw: raw::RawConfig = serde_saphyr::from_str(
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
    #[cfg(all(feature = "ss", feature = "trojan"))]
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

        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
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
        let mini = prefetch_proxy_map(
            &raw,
            &providers,
            None,
            &Default::default(),
            &meow_dns::new_dns_outbound_cell(),
        )
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

    /// A `MATCH,<group>` geodata egress resolves to the group adapter as
    /// built — dialing it lands on the selector's persisted choice, or the
    /// first member when the store holds nothing (D1: `map.get` is the
    /// whole answer, no leaf-stripping). The observable is which member's
    /// listener the dial physically contacts.
    #[cfg(all(feature = "ss", feature = "trojan"))]
    #[tokio::test]
    async fn geodata_match_group_dials_persisted_selection() {
        let (port_b1, b1_hits) = counting_listener().await;
        let (port_b2, b2_hits) = counting_listener().await;

        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
            "proxies:\n\
             \x20 - name: B1\n    type: trojan\n    server: 127.0.0.1\n    port: {port_b1}\n    \
             password: x\n\
             \x20 - name: B2\n    type: trojan\n    server: 127.0.0.1\n    port: {port_b2}\n    \
             password: x\n\
             proxy-groups:\n\
             \x20 - name: G\n    type: select\n    proxies: [B1, B2]\n\
             rules:\n  - MATCH,G\n"
        ))
        .unwrap();
        let providers = HashMap::new();
        let metadata = meow_common::Metadata {
            network: meow_common::Network::Tcp,
            host: "example.invalid".into(),
            dst_port: 443,
            ..Default::default()
        };

        // Persisted choice `B2` primes the group at build — the resolved
        // download proxy dials B2, never B1.
        let dir = tempfile::tempdir().unwrap();
        let store = meow_proxy::SelectorStore::open(dir.path().join("sel.json"));
        store.set("G", "B2");
        let writer = meow_proxy::SelectorWriter::standalone(store);
        let layer = prefetch_proxy_map(
            &raw,
            &providers,
            Some(&writer),
            &Default::default(),
            &meow_dns::new_dns_outbound_cell(),
        )
        .expect("layer builds")
        .expect("proxies configured");
        let geo = geodata::parse_geodata(&raw).unwrap();
        let GeodataEgress::Proxy {
            proxy: resolved, ..
        } = super::resolve_geodata_egress(
            &raw,
            &geo,
            TunnelMode::Rule,
            &layer.map,
            &std::collections::HashSet::new(),
        )
        else {
            panic!("MATCH target resolves");
        };
        let _ = resolved.dial_tcp(&metadata).await;
        assert!(
            hits(&b2_hits) >= 1,
            "persisted selection B2 must answer the dial"
        );
        assert_eq!(hits(&b1_hits), 0, "B1 must not be contacted");

        // A fresh store → the group falls back to its first member.
        let empty_dir = tempfile::tempdir().unwrap();
        let empty_store = meow_proxy::SelectorStore::open(empty_dir.path().join("sel.json"));
        let empty_writer = meow_proxy::SelectorWriter::standalone(empty_store);
        let layer = prefetch_proxy_map(
            &raw,
            &providers,
            Some(&empty_writer),
            &Default::default(),
            &meow_dns::new_dns_outbound_cell(),
        )
        .expect("layer builds")
        .expect("proxies configured");
        let geo = geodata::parse_geodata(&raw).unwrap();
        let GeodataEgress::Proxy {
            proxy: resolved, ..
        } = super::resolve_geodata_egress(
            &raw,
            &geo,
            TunnelMode::Rule,
            &layer.map,
            &std::collections::HashSet::new(),
        )
        else {
            panic!("MATCH target resolves");
        };
        let _ = resolved.dial_tcp(&metadata).await;
        assert!(
            hits(&b1_hits) >= 1,
            "no persisted choice → first member B1 answers"
        );
    }

    /// The prefetch layer is only built when a startup fetch could ride it:
    /// any non-inline provider (http fetch, or a file payload hiding geo
    /// references) forces it on; otherwise it hinges on geodata the rules
    /// actually need being absent.
    #[test]
    fn prefetch_layer_gate_tracks_real_need() {
        let geo = GeoDataConfig::default();
        let one_proxy = "proxies:\n  - {name: p, type: direct}\n";
        let no_providers: raw::RawConfig = serde_saphyr::from_str(one_proxy).unwrap();

        // Fetchable provider → build it even with no geo references.
        let with_http: raw::RawConfig = serde_saphyr::from_str(&format!(
            "{one_proxy}rule-providers:\n  rs:\n    type: http\n    behavior: domain\n    url: http://x/y\n    path: ./rs.yaml"
        ))
        .unwrap();
        assert!(prefetch_proxy_layer_needed(&with_http, &geo));

        // A `file` provider counts too — its payload can carry geo keys the
        // raw scan cannot see yet.
        let with_file: raw::RawConfig = serde_saphyr::from_str(&format!(
            "{one_proxy}rule-providers:\n  rs:\n    type: file\n    behavior: domain\n    path: ./rs.yaml"
        ))
        .unwrap();
        assert!(prefetch_proxy_layer_needed(&with_file, &geo));

        // Inline-only, rules free of geo references → nothing to fetch.
        let inline_only: raw::RawConfig = serde_saphyr::from_str(&format!(
            "{one_proxy}rule-providers:\n  rs:\n    type: inline\n    behavior: domain\n    payload: ['.example.com']"
        ))
        .unwrap();
        assert!(!prefetch_proxy_layer_needed(&inline_only, &geo));
        assert!(!prefetch_proxy_layer_needed(&no_providers, &geo));

        // No `proxies:` at all → the layer can never exist.
        let empty_proxies: raw::RawConfig = serde_saphyr::from_str(
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
        let geoip_rules: raw::RawConfig = serde_saphyr::from_str(&format!(
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

    /// Issue #974 — a config with no `proxies:` but provider-fed
    /// `proxy-groups:` still owns a prefetch layer: `geodata.proxy`
    /// naming the group must resolve. Selecting a provider's rematch
    /// leaf then fails the dial loudly (`direct_fallback: false`)
    /// instead of the download silently egressing direct off an
    /// unresolved map.
    #[tokio::test]
    async fn prefetch_layer_resolves_group_egress_without_proxies() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - { name: inspect, type: rematch, target-rematch-name: stage1 }\n",
        )
        .unwrap();
        let def: raw::RawProxyProvider = serde_saphyr::from_str(&format!(
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
        provider.refresh().await.unwrap();
        let providers: HashMap<String, Arc<ProxyProvider>> =
            [("p".to_string(), Arc::new(provider))]
                .into_iter()
                .collect();

        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
            "geodata:\n  mmdb-path: '{}'\n  proxy: G\n\
             proxy-groups:\n  - {{ name: G, type: select, use: [p] }}\n\
             rules:\n  - GEOIP,CN,DIRECT",
            dir.path().join("absent.mmdb").display()
        ))
        .unwrap();
        let geo = geodata::parse_geodata(&raw).unwrap();
        assert!(
            prefetch_proxy_layer_needed(&raw, &geo),
            "groups alone must not short-circuit the layer"
        );

        let layer = prefetch_proxy_map(
            &raw,
            &providers,
            None,
            &Default::default(),
            &meow_dns::new_dns_outbound_cell(),
        )
        .expect("layer builds")
        .expect("provider-fed groups produce a layer");
        let GeodataEgress::Proxy {
            proxy,
            direct_fallback,
        } = super::resolve_geodata_egress(
            &raw,
            &geo,
            TunnelMode::Rule,
            &layer.map,
            &std::collections::HashSet::new(),
        )
        else {
            panic!("explicit geodata.proxy must resolve to the group");
        };
        assert!(
            !direct_fallback,
            "an explicit geodata.proxy never falls back"
        );
        assert_eq!(proxy.name(), "G", "the egress binds the named group");

        // The group selects the provider's rematch leaf — the dial must
        // fail loudly rather than carry the download anywhere, and the
        // failure must be *that* one: a rematch has no socket to open.
        // Bare `is_err()` would also pass on an unrelated dial error.
        let metadata = meow_common::Metadata {
            network: meow_common::Network::Tcp,
            host: "example.invalid".into(),
            dst_port: 443,
            ..Default::default()
        };
        let err = proxy
            .dial_tcp(&metadata)
            .await
            .err()
            .expect("a rematch leaf owns no socket to dial with");
        let msg = err.to_string();
        assert!(
            msg.contains("control outbound") && msg.contains("inspect"),
            "the group dialled the provider's rematch leaf and it failed \
             as a control node: {msg}"
        );
    }

    /// A provider node's `dialer-proxy` binds the provider's registry
    /// cell, not the prefetch layer's own: the publish must reach that
    /// cell too or the node's front hop resolves to nothing and a fetch
    /// through it cannot dial (issue #974 review). The fetch itself
    /// fails — the counting listener accepts then drops — but the TCP
    /// connect to B proves `pn` dialled its front hop.
    #[cfg(all(feature = "ss", feature = "trojan"))]
    #[tokio::test]
    async fn prefetch_layer_resolves_provider_node_front_hops() {
        let (port_b, b_hits) = counting_listener().await;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - { name: pn, type: trojan, server: 127.0.0.1, port: 9, \
             password: x, dialer-proxy: B }\n",
        )
        .unwrap();
        let def: raw::RawProxyProvider = serde_saphyr::from_str(&format!(
            "type: file\npath: '{}'",
            dir.path().join("nodes.yaml").display()
        ))
        .unwrap();
        let provider_registry = meow_proxy::dialer::ProxyRegistry::default();
        let provider = ProxyProvider::new(
            "p",
            &def,
            Some(dir.path()),
            false,
            false,
            provider_registry.clone(),
        )
        .unwrap();
        provider.refresh().await.unwrap();
        let providers: HashMap<String, Arc<ProxyProvider>> =
            [("p".to_string(), Arc::new(provider))]
                .into_iter()
                .collect();

        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
            "proxies:\n\
             \x20 - {{ name: B, type: trojan, server: 127.0.0.1, port: {port_b}, password: x }}\n\
             proxy-groups:\n  - {{ name: G, type: select, use: [p] }}\n\
             rule-providers:\n\
             \x20 rs:\n    type: http\n    behavior: domain\n    \
             url: http://127.0.0.1:9/rs.yaml\n    path: ./rs.yaml\n    proxy: G\n"
        ))
        .unwrap();

        let layer = prefetch_proxy_map(
            &raw,
            &providers,
            None,
            &provider_registry,
            &meow_dns::new_dns_outbound_cell(),
        )
        .expect("layer builds")
        .expect("proxies configured");
        let payloads =
            prefetch_rule_provider_payloads_async(&raw, None, Some(Arc::new(layer))).await;
        assert_eq!(
            payloads.iter().count(),
            0,
            "the counting listener accepts then drops — the fetch ran and got nothing"
        );
        assert!(
            hits(&b_hits) >= 1,
            "the provider node's dialer-proxy front resolves via the prefetch publish"
        );
    }

    /// End-to-end wiring: a provider's `proxy:` key resolves through the
    /// shared prefetch layer, so its HTTP fetch dials the chained front
    /// hop rather than the leaf's own (or a direct) egress.
    #[cfg(all(feature = "ss", feature = "trojan"))]
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

        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
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
            prefetch_proxy_map(
                &raw,
                &providers,
                None,
                &Default::default(),
                &meow_dns::new_dns_outbound_cell(),
            )
            .expect("layer builds")
            .expect("proxies configured"),
        );
        // The fetch itself fails — the counting listener accepts then drops
        // — but the TCP connect to B proves `proxy: A` dialled its front hop.
        let payloads = prefetch_rule_provider_payloads_async(&raw, None, Some(layer)).await;
        assert_eq!(payloads.iter().count(), 0, "no payload was acquired");
        assert!(b_hits.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    }

    /// A provider *without* `proxy:` rides the prefetch layer through the
    /// default download proxy — `first_named_proxy` resolves `proxies[0]`
    /// inside the layer, so the fetch still dials A's chained front hop B.
    /// Reverting the default to a bare re-parse (or never building the
    /// layer) would dial A's own listener or the provider URL direct.
    #[cfg(all(feature = "ss", feature = "trojan"))]
    #[tokio::test]
    async fn build_config_prefetch_default_rides_the_chain() {
        let (port_a, a_hits) = counting_listener().await;
        let (port_b, b_hits) = counting_listener().await;
        let (port_u, u_hits) = counting_listener().await;

        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
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

        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
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
    /// direct-first, and a bare re-parse would hit A's own listener, not
    /// B's. A `dialer-proxy` chain is a deliberate egress, so its failed
    /// dial is never retried direct (#800 review): the URL listener sees no
    /// hit at all.
    #[cfg(all(feature = "ss", feature = "trojan"))]
    #[tokio::test]
    async fn geodata_download_rides_the_chain() {
        let (port_a, a_hits) = counting_listener().await;
        let (port_b, b_hits) = counting_listener().await;
        let (port_u, u_hits) = counting_listener().await;
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.mmdb");

        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
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

        // The chain dial fails (B drops the conn) and the parser-context
        // build hard-errors on the still-missing MMDB — only the dial
        // observables matter here.
        let _ = build_config(raw, None).await;
        assert!(
            hits(&b_hits) >= 1,
            "the geodata download must reach A's front hop B first"
        );
        assert_eq!(
            hits(&a_hits),
            0,
            "a bare adapter would dial A's own listener"
        );
        assert_eq!(
            hits(&u_hits),
            0,
            "a failed chain dial must not fall back to a direct fetch"
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

    /// A self-referencing dialer is rejected during edge collection — before
    /// any leaf is built — in *both* modes. Lenient never warn-skipped it even
    /// in the old pass: keeping the node unchained would dial past the chain
    /// the config asked for (Class A, ADR-0002).
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

        // Strict bails at the same collection stage.
        let err = collect_dialer_edges(&[raw_proxy("A", Some("A"))], true)
            .err()
            .expect("strict mode rejects a self-reference at edge collection");
        assert!(
            err.to_string().contains("points to itself"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn missing_dialer_is_a_config_error() {
        let mut proxies = registry(&["A"]);
        let err = apply_chains(&mut proxies, &[raw_proxy("A", Some("ghost"))])
            .expect_err("an unknown dialer must not silently dial direct");
        assert!(err.to_string().contains("not found"), "unexpected: {err}");
        // The leaf pass may already have wrapped A's entry in-flight — the
        // single-parse stage runs before target validation by design — but
        // the build is discarded with the error, so the wrap never ships.
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
        let mut raw = raw_proxy("A", None);
        raw.insert(
            "dialer-proxy".to_string(),
            serde_json::Value::Number(serde_json::Number::from(42)),
        );
        // Malformed values are a hard error under `strict` — the lenient
        // fail-at-dial sentinel arm is covered by `strict_mode_tests` at the
        // rebuild level. The check lives in edge collection, before any
        // leaf is built.
        let err = collect_dialer_edges(&[raw], true)
            .err()
            .expect("malformed dialer-proxy must fail under strict");
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
            serde_json::Value::String(" B ".to_string()),
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
            serde_json::Value::String(String::new()),
        );
        let mut null = raw_proxy("B", None);
        null.insert("dialer-proxy".to_string(), serde_json::Value::Null);
        let mut ws = raw_proxy("C", None);
        ws.insert(
            "dialer-proxy".to_string(),
            serde_json::Value::String(" ".to_string()),
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

    /// Issue #625 — a repeated leaf `name:` last-wins (deliberate
    /// divergence from upstream's hard error), but it must warn so a typo
    /// doesn't silently rebind a name.
    #[test]
    fn duplicate_leaf_name_warns() {
        // Scoped WARN capture — `with_default` is thread-local. The
        // discard subscriber keeps a bare-thread `warn!` from caching
        // `Interest::never` on this callsite under our scope.
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

        let raws: Vec<HashMap<String, serde_json::Value>> = serde_saphyr::from_str(
            "- name: dup\n  type: direct\n- name: dup\n  type: http\n  server: 127.0.0.1\n  port: 9\n- name: dup\n  type: socks5\n  server: 127.0.0.1\n  port: 9\n",
        )
        .unwrap();
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        let mut names = std::collections::HashSet::new();

        tracing::subscriber::with_default(subscriber, || {
            insert_parsed_leaves(
                &mut proxies,
                &mut names,
                &raws,
                None,
                false,
                false,
                &meow_proxy::dialer::ProxyRegistry::default(),
                &HashMap::new(),
                None,
                &meow_dns::new_dns_outbound_cell(),
            )
            .unwrap();
        });

        assert_eq!(proxies.len(), 1, "last-wins is unchanged");
        // Distinguishable leaf types pin *which* entry won — a first-wins
        // regression would leave the `direct` adapter behind.
        assert_eq!(
            proxies["dup"].adapter_type(),
            meow_common::AdapterType::Socks5,
            "last definition must win"
        );
        let captured = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
        // One warn per *repeat* occurrence: a 3-dup fixture yields 2 warns.
        // An inverted `insert` check would warn once on first sight instead.
        assert_eq!(
            captured.matches("duplicate proxy name 'dup'").count(),
            2,
            "expected one warn per repeat; got: {captured}"
        );
    }

    /// Duplicate `name:` blocks: only the *last* block is the effective
    /// definition, so a `dialer-proxy` declared only by an earlier duplicate
    /// must not chain the effective block.
    #[test]
    fn stale_duplicate_dialer_edge_is_ignored() {
        let mut proxies = registry(&["A", "front"]);

        let mut first = raw_socks5_proxy("A", Some("front"), false);
        first.insert(
            "port".to_string(),
            serde_json::Value::Number(serde_json::Number::from(1111)),
        );
        let mut last = raw_socks5_proxy("A", None, false);
        last.insert(
            "port".to_string(),
            serde_json::Value::Number(serde_json::Number::from(2222)),
        );

        apply_chains(&mut proxies, &[first, last]).expect("the effective block declares no dialer");

        let bound = proxies.get("A").expect("present after");
        assert!(
            !bound.has_configured_dialer(),
            "the last duplicate block declares no dialer-proxy, so no chain \
             may be applied — the single-parse pass must not leak the stale \
             block's edge into the surviving construction"
        );
        assert_eq!(
            bound.addr(),
            "127.0.0.1:2222",
            "the effective (last) block still wins the name"
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
    ) -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert(
            "name".to_string(),
            serde_json::Value::String(name.to_string()),
        );
        m.insert(
            "type".to_string(),
            serde_json::Value::String("socks5".to_string()),
        );
        m.insert(
            "server".to_string(),
            serde_json::Value::String("127.0.0.1".to_string()),
        );
        m.insert(
            "port".to_string(),
            serde_json::Value::Number(serde_json::Number::from(1080)),
        );
        if udp {
            m.insert("udp".to_string(), serde_json::Value::Bool(true));
        }
        if let Some(d) = dialer {
            m.insert(
                "dialer-proxy".to_string(),
                serde_json::Value::String(d.to_string()),
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
    /// `dialer-proxy` — for types whose dialer edge needs a dedicated
    /// assertion (injection acceptance, or the uninjectable fallback).
    fn raw_typed_proxy(
        name: &str,
        ty: &str,
        dialer: Option<&str>,
    ) -> HashMap<String, serde_json::Value> {
        let mut m = raw_socks5_proxy(name, dialer, false);
        m.insert(
            "type".to_string(),
            serde_json::Value::String(ty.to_string()),
        );
        m
    }

    /// `anytls` carries the injected dialer itself: the vendored client
    /// establishes every session's transport through it (TLS + pooling
    /// unchanged), so the leaf comes back injected — `WrappedProxy`
    /// reporting the configured hop under the `ChainedProxy` marker — not
    /// wrapped in the relay-based `DialerProxyAdapter`. `#[tokio::test]`
    /// because the adapter spawns its session-pool reaper on a reactor.
    ///
    /// The marker reports `!support_udp` (issue #969): `udp` unset is
    /// the UDP-incapable chain shape a matched UDP flow dies on; `udp:
    /// true` is not marked because its UoT rides the same chained
    /// session — the chain carries the flow, so there is nothing to
    /// fail closed on.
    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn anytls_carries_its_dialer_by_injection() {
        let mut proxies = registry(&["A", "B", "front"]);
        let before = proxies.clone();

        let mut raw_a = raw_typed_proxy("A", "anytls", Some("front"));
        raw_a.insert(
            "password".to_string(),
            serde_json::Value::String("pw".to_string()),
        );
        let mut raw_b = raw_typed_proxy("B", "anytls", Some("front"));
        raw_b.insert(
            "password".to_string(),
            serde_json::Value::String("pw".to_string()),
        );
        raw_b.insert("udp".to_string(), serde_json::Value::Bool(true));
        apply_chains(&mut proxies, &[raw_a, raw_b]).expect("anytls accepts the injected dialer");

        let after = proxies.get("A").expect("entry survives");
        assert!(
            was_wrapped(&before, &proxies, "A"),
            "the injected leaf replaces the registry entry"
        );
        assert!(
            after.has_configured_dialer(),
            "the injected leaf reports the configured chain"
        );
        // The `ChainedProxy` marker proves injection (issue #969): the
        // relay-based `DialerProxyAdapter` answers `as_any` with itself,
        // so its absence here plus the marker's verdict is the
        // injected-leaf shape. `udp` stays unset on A — the marker's
        // verdict is what fails a matched UDP flow closed.
        assert!(after.is_dialer_proxy_non_transparent());
        assert!(
            after
                .as_any()
                .and_then(|any| any.downcast_ref::<meow_proxy::DialerProxyAdapter>())
                .is_none(),
            "injection must not fall back to the relay wrapper"
        );
        assert!(
            after
                .as_any()
                .and_then(|any| any.downcast_ref::<proxy_parser::WrappedProxy>())
                .is_some(),
            "the injected leaf stays a WrappedProxy under the marker"
        );

        // `udp: true` + injection: UoT rides the chained TCP session, so
        // the leaf advertises UDP and the marker stays unset — a chained
        // leaf that can carry the flow is not the #969 fail-closed shape.
        let after_udp = proxies.get("B").expect("entry survives");
        assert!(after_udp.support_udp());
        assert!(after_udp.has_configured_dialer());
        assert!(
            !after_udp.is_dialer_proxy_non_transparent(),
            "a chained leaf whose transport carries UDP must not be marked"
        );
    }

    /// `ss` with an *external* SIP003 plugin must not reach its constructor
    /// twice: it spawns the plugin subprocess, and a second `Plugin::start`
    /// would leave two copies running. The single-parse pipeline makes that
    /// structural — the injected-dialer attempt bails before
    /// `ShadowsocksAdapter::new` (the defensive `ss` early-reject stays), the
    /// direct re-parse spawns once, and the wrapper carries the chain.
    #[test]
    fn external_sip003_plugin_is_not_re_parsed() {
        let mut proxies = registry(&["A", "front"]);
        let mut raw = raw_typed_proxy("A", "ss", Some("front"));
        raw.insert(
            "cipher".to_string(),
            serde_json::Value::String("aes-256-gcm".to_string()),
        );
        raw.insert(
            "password".to_string(),
            serde_json::Value::String("pw".to_string()),
        );
        // A plugin name that is not one of the built-ins → external subprocess.
        raw.insert(
            "plugin".to_string(),
            serde_json::Value::String("obfs-local-does-not-exist".to_string()),
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
            serde_json::Value::Number(serde_json::Number::from(1111)),
        );
        let mut last = raw_socks5_proxy("A", Some("front"), false);
        last.insert(
            "port".to_string(),
            serde_json::Value::Number(serde_json::Number::from(2222)),
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
        // by checking that support_udp is false: the wrapper only advertises
        // UDP for a *transparent* (direct-class) inner, and a socks5 inner
        // is not one.
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
            serde_json::Value::Number(serde_json::Number::from(front_port)),
        );
        let mut raw_inner = raw_socks5_proxy("inner", Some("front"), false);
        raw_inner.insert(
            "port".to_string(),
            serde_json::Value::Number(serde_json::Number::from(inner_port)),
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
    /// with its registry adapter. The chain is applied during the leaf
    /// parse, before group construction (issue #513), so the adapter a
    /// group captured is the same object `route.proxies` and
    /// `group.member_proxies()` serve the sweep and API probes. Marking
    /// the registry adapter dead must move the group's selection — a second
    /// `ProxyHealth` minted after group capture would leave the group
    /// reading a default-alive private handle while probes recorded results
    /// on the other.
    #[test]
    fn dialer_proxy_member_shares_health_with_group_selection() {
        let raw: raw::RawConfig = serde_saphyr::from_str(
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

    /// `type: direct` refuses the injected dialer (a resolver-threaded dial
    /// belongs on the real path — see `reject_unthreaded_dialer`), so a
    /// `direct` + `dialer-proxy` node takes the relay-wrapper fallback: the
    /// wrapper over a *live* Direct inner stays transparent and reports the
    /// chain. The fallback re-parses through `parse_static_proxy`, which is
    /// also what wires the `dns.direct-nameserver` slot — verified
    /// end-to-end below by dialling through the chain: the front `direct`
    /// hop (itself a `parse_static_proxy` product) resolves the final
    /// target's name through the configured slot, not the main resolver.
    #[test]
    fn direct_node_with_dialer_proxy_wraps_not_injects() {
        let mut proxies = registry(&["d", "front"]);
        let mut raw = raw_proxy("d", Some("front"));
        raw.insert(
            "type".to_string(),
            serde_json::Value::String("direct".to_string()),
        );

        apply_chains(&mut proxies, &[raw])
            .expect("direct + dialer-proxy falls back to the relay wrapper");

        let bound = proxies.get("d").expect("d survives");
        let wrapper = bound
            .as_any()
            .and_then(|any| any.downcast_ref::<meow_proxy::DialerProxyAdapter>())
            .expect(
                "a direct node cannot inject the dialer — it must be the \
                 relay wrapper",
            );
        assert_eq!(wrapper.dialer_name(), "front");
        assert_eq!(bound.adapter_type(), meow_common::AdapterType::Direct);
        assert!(
            bound.has_configured_dialer(),
            "the declared chain must be reported even through the wrapper"
        );
        // A transparent (direct-class) inner makes the wrapper transparent:
        // `support_udp` true here *proves* the inner is a live Direct
        // adapter — an unavailable placeholder or an absent parse would
        // leave it false.
        assert!(bound.support_udp());
        // ...and the probe predicate agrees: a transparent chain carries
        // UDP over the front's association, so it is NOT the #969
        // fail-closed shape.
        assert!(!bound.is_dialer_proxy_non_transparent());
    }

    /// End-to-end: the `dns.direct-nameserver` slot survives the chained
    /// build. `front` resolves `node.test` through the slot's direct
    /// resolver (hosts-mapped to loopback), so the dial through `d`'s
    /// wrapper lands on the listener — a build that dropped the slot on
    /// either direct node would fail to resolve and never connect.
    #[tokio::test]
    async fn direct_chain_keeps_the_direct_nameserver_slot() {
        use meow_dns::{HostEntry, Resolver};
        use meow_trie::DomainTrie;

        let (port, accepts) = counting_listener().await;

        let hosts_only = |ip: std::net::IpAddr| {
            let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
            hosts.insert("node.test", vec![ip].into());
            Resolver::new(
                vec![],
                vec![],
                meow_common::DnsMode::Normal,
                hosts,
                true,
                true,
            )
        };
        // The main resolver answers `node.test` with an unroutable
        // documentation-range address; the direct-nameserver resolver maps
        // it to loopback. Only the slot path can reach the listener.
        let mut main = hosts_only(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)));
        main.set_direct_resolver(Arc::new(hosts_only(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        ))));
        let slot = meow_dns::new_resolver_slot(Arc::new(main));

        let raw: raw::RawConfig = serde_saphyr::from_str(
            "proxies:\n\
             \x20 - name: d\n    type: direct\n    dialer-proxy: front\n\
             \x20 - name: front\n    type: direct\n",
        )
        .unwrap();
        let result = rebuild_from_raw_with_resolver(
            &raw,
            Some(&slot),
            None,
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
        .expect("direct chain builds");

        let metadata = meow_common::Metadata {
            network: meow_common::Network::Tcp,
            host: "node.test".into(),
            dst_port: port,
            ..Default::default()
        };
        // `result.dialer_registry` stays alive in `result` for the dial —
        // `DialerTarget`s bind it weakly (issue #533).
        let mut conn = result.proxies["d"]
            .dial_tcp(&metadata)
            .await
            .expect("the chain must resolve `node.test` through the slot");
        // TCP `connect` returns at SYN-ACK, which can precede the spawned
        // accept task by a scheduling quantum. The listener drops every
        // accepted stream after bumping the counter, so reading this conn
        // to EOF is the barrier that proves `accept()` already ran.
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), conn.read(&mut buf)).await;
        assert_eq!(
            hits(&accepts),
            1,
            "the chain must dial the slot-resolved loopback address — a \
             dropped direct-nameserver slot resolves `node.test` to the \
             unreachable main-resolver answer instead"
        );
    }

    /// Issue #969 on the injected path: an `http` node carrying
    /// `dialer-proxy` registers behind the `ChainedProxy` marker, so the
    /// UDP probe reads the configured chain
    /// (`is_dialer_proxy_non_transparent`) instead of a plain `udp: false`
    /// node that would slide a matched UDP flow to a later rule.
    #[test]
    fn injected_http_leaf_is_marked_for_udp_fail_closed() {
        let raw: raw::RawConfig = serde_saphyr::from_str(
            "proxies:\n\
             \x20 - name: front\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n\
             \x20 - name: leaf\n    type: http\n    server: 127.0.0.1\n    port: 8080\n    dialer-proxy: front\n",
        )
        .unwrap();
        let result = rebuild_from_raw(&raw).expect("http chain builds");
        let leaf = &result.proxies["leaf"];

        assert!(!leaf.support_udp(), "http cannot carry UDP");
        assert!(
            leaf.is_dialer_proxy_non_transparent(),
            "the ChainedProxy marker must pin the #969 fail-closed verdict"
        );
        assert!(
            leaf.has_configured_dialer(),
            "the declared chain must still be reported through the marker"
        );
        // The marker is transparent to the downcasts the bare leaf
        // previously answered: the injected `WrappedProxy` stays reachable.
        assert!(
            leaf.as_any()
                .and_then(|any| any.downcast_ref::<proxy_parser::WrappedProxy>())
                .is_some(),
            "as_any must keep resolving the injected WrappedProxy leaf"
        );
        // And the front it chains through is untouched — an unmarked leaf
        // keeps the trait's default `false`.
        assert!(
            !result.proxies["front"].is_dialer_proxy_non_transparent(),
            "the unchained front must not be marked"
        );
    }

    /// The `ss` twin (issue #969): `udp: true` folds the *front's* UDP
    /// capability into `support_udp` — an `http` front yields `false` —
    /// and the `ChainedProxy` marker still reports the configured chain,
    /// so a matched UDP rule fails closed instead of sliding.
    #[cfg(feature = "ss")]
    #[test]
    fn injected_ss_via_http_front_udp_fails_closed() {
        let raw: raw::RawConfig = serde_saphyr::from_str(
            "proxies:\n\
             \x20 - name: front\n    type: http\n    server: 127.0.0.1\n    port: 8080\n\
             \x20 - name: leaf\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n\
             \x20   cipher: aes-128-gcm\n    password: pw\n    udp: true\n    dialer-proxy: front\n",
        )
        .unwrap();
        let result = rebuild_from_raw(&raw).expect("ss-via-http chain builds");
        let leaf = &result.proxies["leaf"];

        assert!(
            !leaf.support_udp(),
            "the http front cannot carry UDP, so the fold must report false"
        );
        assert!(
            leaf.is_dialer_proxy_non_transparent(),
            "the ChainedProxy marker must pin the #969 fail-closed verdict"
        );
    }
}

#[cfg(test)]
mod declared_dns_names_tests {
    use super::*;

    fn node(name: Option<&str>, ty: &str) -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        if let Some(name) = name {
            m.insert(
                "name".to_string(),
                serde_json::Value::String(name.to_string()),
            );
        }
        m.insert(
            "type".to_string(),
            serde_json::Value::String(ty.to_string()),
        );
        m
    }

    /// A plain dns declaration marks its name; non-dns leaves and an
    /// empty document do not (issue #974 review).
    #[test]
    fn marks_dns_decls_and_skips_others() {
        let names = declared_dns_names(&[node(Some("dns-out"), "dns"), node(Some("web"), "ss")]);
        assert!(names.contains("dns-out"));
        assert!(!names.contains("web"));
        assert!(declared_dns_names(&[]).is_empty());
    }

    /// Last-wins still applies when the LAST declaration is the dns one —
    /// a later dns decl over an earlier transport marks the name.
    #[test]
    fn later_dns_decl_marks_the_name() {
        let names = declared_dns_names(&[node(Some("x"), "ss"), node(Some("x"), "dns")]);
        assert!(names.contains("x"));
    }

    /// The conservative half of the contract (issue #974 review): an
    /// earlier dns decl is NOT unmarked by a later same-named transport
    /// decl — that later decl may warn-drop at lenient parse and leave
    /// the dns binding effective, so the name stays suspect on lanes
    /// that cannot prove the later decl binds.
    #[test]
    fn earlier_dns_decl_survives_a_later_shadow() {
        let names = declared_dns_names(&[node(Some("x"), "dns"), node(Some("x"), "ss")]);
        assert!(
            names.contains("x"),
            "a later decl that may not bind must not unmark the dns leaf"
        );
    }

    /// A decl named after a built-in never binds a leaf — the built-in
    /// wins regardless of the declared type — so it is never a dns name.
    /// The shadow check is exact-case like `insert_parsed_leaves`: a
    /// lowercase "direct" is an ordinary leaf name.
    #[test]
    fn builtin_names_never_bind_a_dns_leaf() {
        for builtin in BUILTIN_ADAPTER_NAMES {
            let names = declared_dns_names(&[node(Some(builtin), "dns")]);
            assert!(
                !names.contains(builtin),
                "'{builtin}' is built-in-shadowed and cannot be a dns leaf"
            );
        }
        let names = declared_dns_names(&[node(Some("direct"), "dns")]);
        assert!(names.contains("direct"));
    }

    /// Decls without a usable `name` are unreferenceable — a nameless
    /// `type: dns` map and a null-named one mark nothing, while a sibling
    /// decl under another name still marks its own.
    #[test]
    fn nameless_and_unrelated_decls() {
        let names = declared_dns_names(&[node(None, "dns"), node(Some("d"), "dns")]);
        assert_eq!(names.len(), 1);
        assert!(names.contains("d"));
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

    /// Issue #974 review — the scan must read type fields only: a
    /// `GEOIP,…` in a payload slot is data, not a declaration, and must
    /// not trigger an MMDB load or an allowlist entry.
    #[test]
    fn geo_scan_ignores_payload_position_mentions() {
        let lines: Vec<String> = [
            "DOMAIN-KEYWORD,GEOIP,CN,REJECT",
            "IP-CIDR,GEOIP,x,DIRECT",
            "AND,((DOMAIN-KEYWORD,GEOIP,CN),(DST-PORT,443)),Proxy",
            "DOMAIN-SUFFIX,GEOSITE,x,DIRECT",
            "DOMAIN-KEYWORD,IP-ASN,13335,DIRECT",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert!(
            collect_geoip_countries(&lines).is_empty(),
            "payload-position GEOIP must not bin a country"
        );
        assert!(
            collect_geosite_categories(&lines).is_empty(),
            "payload-position GEOSITE must not bin a category"
        );
        assert!(
            collect_asn_numbers(&lines).is_empty(),
            "payload-position IP-ASN must not bin an ASN"
        );
        for line in &lines {
            assert!(
                !line_references_geoip(line),
                "'{line}' must not trigger GeoIP"
            );
            assert!(
                !line_references_geosite(line),
                "'{line}' must not trigger geosite"
            );
            assert!(!line_references_asn(line), "'{line}' must not trigger ASN");
        }
    }

    /// Issue #974 review — the scan descends logic nesting *before* the
    /// rule parser sees the line, so it must apply the parser's own
    /// bounds: a line over `MAX_RULE_LINE_LEN` contributes nothing, and
    /// a nesting past `MAX_LOGIC_DEPTH` stops the descent. Without them
    /// `AND,((`×N — eight bytes per level — overflows the stack here
    /// long before the parse stage reports its "nesting exceeds" error.
    #[test]
    fn geo_scan_bounds_logic_nesting_and_line_length() {
        // 8000 levels stay inside the length cap — only the depth bound
        // stops the descent. The innermost GEOIP leg sits below the cap,
        // so nothing is classified.
        let mut deep = String::new();
        for _ in 0..8000 {
            deep.push_str("AND,((");
        }
        deep.push_str("GEOIP,CN");
        for _ in 0..8000 {
            deep.push_str("))");
        }
        deep.push_str(",DIRECT");
        assert!(deep.len() <= meow_rules::parser::MAX_RULE_LINE_LEN);
        let countries = collect_geoip_countries(std::slice::from_ref(&deep));
        assert!(
            countries.is_empty(),
            "a branch the parser rejects for depth must not be scanned: {countries:?}"
        );
        // The parse stage then owns the failure — the same line errors
        // on the depth cap instead of overflowing either stack.
        let Err(err) =
            meow_rules::parser::parse_rule(&deep, &meow_rules::parser::ParserContext::empty())
        else {
            panic!("the parser must reject the over-deep line");
        };
        assert!(err.contains("nesting"), "{err}");

        // One byte past the length cap and the line contributes nothing —
        // the parser rejects it for length, so its geo keys never exist.
        let mut overlong = deep.clone();
        overlong.push_str(&"x".repeat(meow_rules::parser::MAX_RULE_LINE_LEN));
        let countries = collect_geoip_countries(&[overlong]);
        assert!(
            countries.is_empty(),
            "an over-cap line must not be scanned at all: {countries:?}"
        );

        // The bound mirrors the parser exactly: 64 nested groups is the
        // most a legal line carries — the GEOIP leaf inside still scans;
        // one level more and the whole line (and its leaves) is dead.
        let nested = |levels: usize| {
            let mut line = String::new();
            for _ in 0..levels {
                line.push_str("AND,((");
            }
            line.push_str("GEOIP,CN");
            for _ in 0..levels {
                line.push_str("))");
            }
            line.push_str(",DIRECT");
            line
        };
        let countries = collect_geoip_countries(&[nested(64)]);
        assert!(
            countries.contains("CN"),
            "a GEOIP leaf at the legal boundary must still be found: {countries:?}"
        );
        let countries = collect_geoip_countries(&[nested(65)]);
        assert!(
            countries.is_empty(),
            "a GEOIP leaf under an over-deep group must not be found: {countries:?}"
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
        let lines = collect_geo_scan_lines(&raw, &rule_provider::PrefetchedPayloads::default());
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
                extra: Default::default(),
            },
        );
        let raw = raw::RawConfig {
            rules: Some(vec!["RULE-SET,my-provider,PROXY".to_string()]),
            rule_providers: Some(providers),
            ..Default::default()
        };
        let lines = collect_geo_scan_lines(&raw, &rule_provider::PrefetchedPayloads::default());
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
            extra: Default::default(),
        };
        let raw = raw::RawConfig {
            rule_providers: Some(HashMap::from([
                ("yaml-provider".to_string(), provider()),
                ("text-provider".to_string(), provider()),
                ("mrs-provider".to_string(), provider()),
            ])),
            ..Default::default()
        };
        let mut payloads = rule_provider::PrefetchedPayloads::new();
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

    /// Issue #974 — a GEOIP key that appears only inside a condition leaf
    /// likewise triggers the mmdb load, observed as the fail-fast error
    /// naming the nonexistent DB path.
    #[test]
    fn cond_only_geoip_triggers_mmdb_load() {
        let mut sub_rules = HashMap::new();
        sub_rules.insert("blk".to_string(), vec!["DOMAIN,x.test,DIRECT".to_string()]);
        let raw = raw::RawConfig {
            rules: Some(vec!["SUB-RULE,(GEOIP,JP),blk".to_string()]),
            sub_rules: Some(sub_rules),
            ..Default::default()
        };
        let nonexistent = PathBuf::from("/nonexistent-test-path-974/Country.mmdb");
        let err = build_parser_context_at(
            &raw,
            &nonexistent,
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &rule_provider::PrefetchedPayloads::default(),
        )
        .expect_err("a cond-only GEOIP leaf must trigger the mmdb load");
        assert!(format!("{err}").contains("/nonexistent-test-path-974/Country.mmdb"));
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
            &rule_provider::PrefetchedPayloads::default(),
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

    /// Issue #974 — a GEOIP/GEOSITE key that exists only inside a
    /// `SUB-RULE,(cond),…` predicate still triggers and bins the database
    /// load, across every condition grammar form: prefix composites,
    /// infix `&`/`|`/`!`, and `category@attr` payloads.
    #[test]
    fn cond_leaves_feed_geo_discovery() {
        let lines = vec![
            "SUB-RULE,(GEOIP,JP),blk".to_string(),
            "SUB-RULE,((GEOIP,KR)|(GEOSITE,youtube@ads)),blk2,T".to_string(),
            "SUB-RULE,(AND,((GEOSITE,cn),(GEOIP,US,src))),blk3".to_string(),
            "SUB-RULE,(NOT,((GEOIP,TW))),blk4".to_string(),
            // A plain reference's block name is never a geo declaration.
            "SUB-RULE,GEOIP-fake-name".to_string(),
        ];
        let countries = collect_geoip_countries(&lines);
        for code in ["JP", "KR", "US", "TW"] {
            assert!(countries.contains(code), "missing cond country {code}");
        }
        assert_eq!(countries.len(), 4);
        let categories = collect_geosite_categories(&lines);
        // `@ads` keys the category, not the attribute — same split the
        // leaf build performs.
        assert!(categories.contains("youtube"));
        assert!(categories.contains("cn"));
        assert_eq!(categories.len(), 2);
    }

    /// A malformed condition contributes nothing — the parse stage owns
    /// that error; discovery must not read a geo declaration out of text
    /// it cannot validate (issue #974).
    #[test]
    fn malformed_cond_declares_no_geo() {
        let lines = vec![
            "SUB-RULE,(GEOIP,XX".to_string(),                 // unbalanced
            "SUB-RULE,(GEOIP,YY),blk,junk,extra".to_string(), // too many fields
            "SUB-RULE,(PROCESS-NAME,GEOIP,ZZ),blk".to_string(),
            "PROCESS-NAME-REGEX,GEOIP,XX,DIRECT".to_string(),
            "PROCESS-PATH-WILDCARD,GEOSITE-*-cn,DIRECT".to_string(),
        ];
        assert!(collect_geoip_countries(&lines).is_empty());
        assert!(collect_geosite_categories(&lines).is_empty());
        assert!(!lines.iter().any(|l| line_references_geoip(l)));
        assert!(!lines.iter().any(|l| line_references_geosite(l)));
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
            &rule_provider::PrefetchedPayloads::default(),
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
            &rule_provider::PrefetchedPayloads::default(),
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
            &rule_provider::PrefetchedPayloads::default(),
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
            &rule_provider::PrefetchedPayloads::default(),
        )
        .unwrap();
        assert!(ctx.asn.is_none());
    }

    // ── geo_references / GeoDataNeeds (the shared need verdict) ────────

    fn needs_of(yaml: &str, scan: &[&str]) -> GeoDataNeeds {
        let raw: raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
        let lines: Vec<String> = scan.iter().map(std::string::ToString::to_string).collect();
        super::geo_references(&raw, &lines)
    }

    /// Positive: enabled DNS + non-empty `fallback:` + no explicit
    /// `fallback-filter.geoip` → the filter is built with its geoip gate
    /// defaulting to true, so the MMDB is a consumer even with no GEOIP
    /// rule anywhere.
    #[test]
    fn fallback_filter_defaults_to_geoip_need() {
        let needs = needs_of(
            "dns:\n  enable: true\n  fallback:\n    - tls://8.8.8.8\n",
            &[],
        );
        assert!(needs.mmdb, "default fallback-filter.geoip is true");
        assert!(!needs.asn && !needs.geosite);
    }

    #[test]
    fn fallback_filter_geoip_disabled_dns_is_no_need() {
        // `dns.enable: false` → `parse_dns` never builds the filter — the
        // reference is dead and must not download an MMDB.
        let needs = needs_of(
            "dns:\n  enable: false\n  fallback:\n    - tls://8.8.8.8\n",
            &[],
        );
        assert!(!needs.mmdb);
        // Absent `dns:` is the same dead reference.
        let needs = needs_of("mode: rule\n", &[]);
        assert!(!needs.mmdb);
    }

    #[test]
    fn fallback_filter_geoip_empty_fallback_is_no_need() {
        // Enabled DNS with no `fallback:` nameservers → no filter is built.
        let needs = needs_of("dns:\n  enable: true\n", &[]);
        assert!(!needs.mmdb);
        let needs = needs_of("dns:\n  enable: true\n  fallback: []\n", &[]);
        assert!(!needs.mmdb);
    }

    #[test]
    fn fallback_filter_geoip_explicit_false_is_no_need() {
        let needs = needs_of(
            "dns:\n  enable: true\n  fallback:\n    - tls://8.8.8.8\n  \
             fallback-filter:\n    geoip: false\n",
            &[],
        );
        assert!(!needs.mmdb);
    }

    /// The `dns.enable` gate on the nameserver-policy consumer: a
    /// `geosite:` policy key under disabled DNS must not count, matching
    /// `parse_dns`'s early return.
    #[test]
    fn geosite_policy_disabled_dns_is_no_need() {
        let needs = needs_of(
            "dns:\n  enable: false\n  nameserver-policy:\n    \
             \"geosite:cn\": tls://8.8.8.8\n",
            &[],
        );
        assert!(!needs.geosite);
        let needs = needs_of(
            "dns:\n  enable: true\n  nameserver-policy:\n    \
             \"geosite:cn\": tls://8.8.8.8\n",
            &[],
        );
        assert!(needs.geosite);
    }

    /// Rule lines still dominate — a GEOIP rule must flag the MMDB need
    /// regardless of the DNS filter's state.
    #[test]
    fn geo_references_union_of_rules_and_dns() {
        let needs = needs_of("mode: rule\n", &["GEOIP,CN,DIRECT"]);
        assert!(needs.mmdb);
        let needs = needs_of("mode: rule\n", &["IP-ASN,13335,PROXY"]);
        assert!(needs.asn && !needs.mmdb && !needs.geosite);
        let needs = needs_of("mode: rule\n", &["GEOSITE,cn,PROXY"]);
        assert!(needs.geosite && !needs.mmdb);
    }

    /// The acceptance pin: a config whose ONLY MMDB consumer is the DNS
    /// fallback filter (`dns.enable: true` + non-empty `fallback:` +
    /// `fallback-filter.geoip` defaulting true) must produce the MMDB in
    /// `missing_geodata_downloads` — and must trip
    /// `prefetch_proxy_layer_needed` so the download can ride a proxy even
    /// with no provider configured. `mmdb-path` points into a tempdir so
    /// the file is absent.
    #[test]
    fn fallback_filter_geoip_triggers_mmdb_download_need() {
        let dir = tempfile::tempdir().unwrap();
        let missing_mmdb = dir.path().join("absent.mmdb");
        let geo = GeoDataConfig {
            mmdb_path: Some(missing_mmdb.clone()),
            ..GeoDataConfig::default()
        };
        let raw: raw::RawConfig = serde_saphyr::from_str(
            "dns:\n  enable: true\n  fallback:\n    - tls://8.8.8.8\n\
             proxies:\n  - {name: p, type: direct}\n",
        )
        .unwrap();

        let downloads = super::missing_geodata_downloads(&geo, geo_references(&raw, &[]));
        assert_eq!(
            downloads.len(),
            1,
            "expected exactly the mmdb download: {downloads:?}"
        );
        assert_eq!(downloads[0].1, missing_mmdb);
        assert_eq!(downloads[0].0, &geo.mmdb_url);
        assert!(
            prefetch_proxy_layer_needed(&raw, &geo),
            "a missing referenced DB must force the prefetch proxy layer"
        );

        // The three dead-reference shapes produce an empty download list —
        // the needs-level detail lives in the tests above; here the
        // download verdict itself must be empty.
        for yaml in [
            "dns:\n  enable: true\n  fallback:\n    - tls://8.8.8.8\n  \
             fallback-filter:\n    geoip: false\n",
            "dns:\n  enable: false\n  fallback:\n    - tls://8.8.8.8\n",
            "dns:\n  enable: true\n  fallback: []\n",
        ] {
            let raw: raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
            assert!(
                super::missing_geodata_downloads(&geo, geo_references(&raw, &[])).is_empty(),
                "{yaml} must produce no downloads"
            );
        }
    }

    /// Per-target independence at the startup-fetch level: with several
    /// referenced DBs missing, one target's failed download must warn and
    /// move on — never block the rest. The ASN origin serves a body while
    /// the MMDB URL is unreachable.
    #[tokio::test]
    async fn ensure_geodata_one_failure_does_not_block_the_rest() {
        let (asn_addr, asn_hits) = crate::test_support::serve_body(b"asn-db").await;
        let dir = tempfile::tempdir().unwrap();
        let mmdb_target = dir.path().join("absent.mmdb");
        let asn_target = dir.path().join("asn.mmdb");
        let geo = GeoDataConfig {
            mmdb_path: Some(mmdb_target.clone()),
            asn_path: Some(asn_target.clone()),
            // Unreachable — refused instantly, the failure must not leak
            // into the sibling download.
            mmdb_url: "http://127.0.0.1:1/country.mmdb".to_string(),
            asn_url: format!("http://{asn_addr}/asn.mmdb"),
            ..GeoDataConfig::default()
        };
        let raw = raw_with_rules(vec![
            "GEOIP,CN,DIRECT",
            "IP-ASN,13335,DIRECT",
            "MATCH,DIRECT",
        ]);
        let scan = collect_geo_scan_lines(&raw, &rule_provider::PrefetchedPayloads::default());
        assert_eq!(
            super::missing_geodata_downloads(&geo, geo_references(&raw, &scan)).len(),
            2,
            "both DBs are referenced and missing"
        );

        super::ensure_geodata(&raw, &geo, &scan, None, &std::collections::HashSet::new()).await;

        assert!(
            asn_hits.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the ASN origin must be dialed despite the MMDB failure"
        );
        assert_eq!(std::fs::read(&asn_target).unwrap(), b"asn-db");
        assert!(
            !mmdb_target.exists(),
            "the failed target leaves no partial file"
        );
    }

    /// With no proxy layer at all (no `proxies:`/`proxy-groups:`), a
    /// `geodata.proxy`/`MATCH` builtin still classifies: `REJECT` gates
    /// the download instead of falling back to direct egress (issue
    /// #974 review).
    #[tokio::test]
    async fn ensure_geodata_builtins_apply_without_a_proxy_map() {
        let (addr, hits) = crate::test_support::serve_body(b"mmdb").await;
        let dir = tempfile::tempdir().unwrap();
        let mmdb_target = dir.path().join("absent.mmdb");
        let geo = GeoDataConfig {
            mmdb_path: Some(mmdb_target.clone()),
            mmdb_url: format!("http://{addr}/country.mmdb"),
            proxy: Some("REJECT".to_string()),
            ..GeoDataConfig::default()
        };
        let raw = raw_with_rules(vec!["GEOIP,CN,DIRECT", "MATCH,DIRECT"]);
        let scan = collect_geo_scan_lines(&raw, &rule_provider::PrefetchedPayloads::default());
        assert_eq!(
            super::missing_geodata_downloads(&geo, geo_references(&raw, &scan)).len(),
            1,
            "the mmdb is referenced and missing"
        );

        super::ensure_geodata(&raw, &geo, &scan, None, &std::collections::HashSet::new()).await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "geodata.proxy: REJECT skips the download even without a map"
        );
        assert!(!mmdb_target.exists());

        // The same gate through the mode's default route: MATCH,REJECT.
        let geo = GeoDataConfig { proxy: None, ..geo };
        let raw = raw_with_rules(vec!["GEOIP,CN,DIRECT", "MATCH,REJECT"]);
        let scan = collect_geo_scan_lines(&raw, &rule_provider::PrefetchedPayloads::default());
        super::ensure_geodata(&raw, &geo, &scan, None, &std::collections::HashSet::new()).await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "MATCH,REJECT gates the download without a map too"
        );
    }

    /// A live reload that references a DB startup never needed downloads it
    /// before the rules that need it are parsed; a validation rebuild
    /// (`rebuild_from_raw`) never reaches the network.
    #[tokio::test(flavor = "multi_thread")]
    async fn rebuild_from_raw_runtime_downloads_newly_referenced_geosite() {
        let body =
            meow_rules::mrs_parser::write_geosite_mrs(&meow_rules::mrs_parser::GeositePayload {
                categories: vec![("testcat".to_string(), vec!["hit.example".to_string()])],
            })
            .unwrap();
        let (addr, hits) = crate::test_support::serve_body(body.clone().leak()).await;
        let dir = tempfile::tempdir().unwrap();
        let geosite = dir.path().join("geosite.mrs");
        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
            "geodata:\n  geosite-path: '{}'\n  url:\n    geosite: 'http://{addr}/geosite.mrs'\n\
             rules:\n  - GEOSITE,testcat,DIRECT\n  - MATCH,DIRECT\n",
            geosite.display()
        ))
        .unwrap();

        let validate = raw.clone();
        tokio::task::spawn_blocking(move || super::rebuild_from_raw(&validate))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!geosite.exists());

        let rebuilt = tokio::task::spawn_blocking(move || {
            super::rebuild_from_raw_runtime(
                &raw,
                None,
                &HashMap::new(),
                None,
                &meow_proxy::dialer::ProxyRegistry::default(),
                &meow_proxy::SelectionBacking::unpersisted(),
                &meow_dns::new_dns_outbound_cell(),
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(&geosite).unwrap(), body);
        assert_eq!(rebuilt.rules.len(), 2);
    }

    // ── resolve_geodata_egress ────────────────────────────────────────

    fn proxy_map(names: &[&str]) -> HashMap<SmolStr, Arc<dyn Proxy>> {
        names
            .iter()
            .map(|n| {
                // A bare DIRECT adapter wrapped in the standard registry
                // shell — identity is the map key, not the adapter name.
                let adapter = meow_proxy::DirectAdapter::new();
                (
                    SmolStr::from(*n),
                    Arc::new(proxy_parser::WrappedProxy::new(Box::new(adapter))) as Arc<dyn Proxy>,
                )
            })
            .collect()
    }

    /// Resolve the egress for `yaml` in `mode` against a map of `names`.
    fn egress_in(
        yaml: &str,
        mode: TunnelMode,
        names: &[&str],
    ) -> (GeodataEgress, HashMap<SmolStr, Arc<dyn Proxy>>) {
        egress_with(yaml, mode, names, &[])
    }

    /// [`egress_in`] with the proxy-providers in `chained` carrying
    /// `dialer-proxy` nodes.
    fn egress_with(
        yaml: &str,
        mode: TunnelMode,
        names: &[&str],
        chained: &[&str],
    ) -> (GeodataEgress, HashMap<SmolStr, Arc<dyn Proxy>>) {
        let raw: raw::RawConfig = serde_saphyr::from_str(yaml).unwrap();
        let geo = geodata::parse_geodata(&raw).unwrap();
        let map = proxy_map(names);
        let chained = chained.iter().map(ToString::to_string).collect();
        (
            super::resolve_geodata_egress(&raw, &geo, mode, &map, &chained),
            map,
        )
    }

    fn egress(yaml: &str, names: &[&str]) -> (GeodataEgress, HashMap<SmolStr, Arc<dyn Proxy>>) {
        egress_in(yaml, TunnelMode::Rule, names)
    }

    /// `egress` rides `map[name]`, with the direct fallback iff `fallback`.
    #[track_caller]
    fn assert_rides(
        egress: &GeodataEgress,
        map: &HashMap<SmolStr, Arc<dyn Proxy>>,
        name: &str,
        fallback: bool,
    ) {
        match egress {
            GeodataEgress::Proxy {
                proxy,
                direct_fallback,
            } => {
                assert!(Arc::ptr_eq(proxy, &map[name]), "expected {name}");
                assert_eq!(*direct_fallback, fallback, "direct_fallback for {name}");
            }
            other => panic!("expected a ride through {name}, got {other:?}"),
        }
    }

    /// Explicit `geodata.proxy` names a map entry → that adapter, with no
    /// direct fallback: an explicit egress fails loudly (#625).
    #[test]
    fn geodata_proxy_named_entry_wins() {
        let (e, map) = egress(
            "geodata:\n  proxy: out\nproxies:\n  - {name: p, type: direct}\n",
            &["p", "out"],
        );
        assert_rides(&e, &map, "out", false);
    }

    /// Built-in names (case-insensitive): the direct-shaped ones fetch
    /// direct, the REJECT-shaped ones skip the download.
    #[test]
    fn geodata_proxy_builtin_names() {
        for (name, rejected) in [
            ("DIRECT", None),
            ("direct", None),
            ("COMPATIBLE", None),
            ("pass", None),
            ("PASS-RULE", None),
            ("Reject", Some("REJECT")),
            ("REJECT-DROP", Some("REJECT-DROP")),
        ] {
            let yaml =
                format!("geodata:\n  proxy: \"{name}\"\nproxies:\n  - {{name: p, type: direct}}\n");
            match (egress(&yaml, &["p"]).0, rejected) {
                (GeodataEgress::Direct, None) => {}
                (GeodataEgress::Rejected(got), Some(want)) => assert_eq!(got, want, "{name}"),
                (other, _) => panic!("{name}: unexpected {other:?}"),
            }
        }
    }

    /// A user node whose name only differs in case from a built-in (`pass`)
    /// is that node — the tunnel binds it by exact name — while the exact
    /// built-in spelling stays the built-in even though the map holds it.
    #[test]
    fn geodata_proxy_exact_name_beats_case_insensitive_builtin() {
        let (e, map) = egress(
            "proxies:\n  - {name: pass, type: direct}\nrules:\n  - MATCH,pass\n",
            &["pass", "PASS"],
        );
        assert_rides(&e, &map, "pass", true);
        let (e, map) = egress("geodata:\n  proxy: pass\n", &["pass"]);
        assert_rides(&e, &map, "pass", false);
        let (e, _) = egress("rules:\n  - MATCH,PASS\n", &["pass", "PASS"]);
        assert!(matches!(e, GeodataEgress::Direct), "{e:?}");
    }

    /// Blank and unknown explicit names fall through to the default egress.
    #[test]
    fn geodata_proxy_blank_and_unknown_fall_through() {
        for val in ["\"\"", "\"   \"", "ghost"] {
            let yaml = format!(
                "geodata:\n  proxy: {val}\nproxies:\n  - {{name: p, type: direct}}\n\
                 rules:\n  - MATCH,DIRECT\n"
            );
            // MATCH,DIRECT is the default egress → direct.
            let (e, _) = egress(&yaml, &["p"]);
            assert!(
                matches!(e, GeodataEgress::Direct),
                "proxy {val} must fall through to the MATCH target, got {e:?}"
            );
        }
    }

    /// No explicit override → the LAST top-level `MATCH` target wins, and
    /// being implied it may fall back direct.
    #[test]
    fn geodata_proxy_match_target_is_default_egress() {
        let (e, map) = egress(
            "proxies:\n  - {name: p, type: direct}\n\
             rules:\n  - MATCH,early\n  - GEOIP,CN,out\n  - MATCH,out\n",
            &["p", "early", "out"],
        );
        assert_rides(&e, &map, "out", true);
    }

    /// `MATCH,<built-in>` follows the built-in; `MATCH` vs `match` is
    /// case-insensitive.
    #[test]
    fn geodata_proxy_match_builtin_targets() {
        for m in ["MATCH,DIRECT", "MATCH,PASS-RULE"] {
            let yaml = format!("proxies:\n  - {{name: p, type: direct}}\nrules:\n  - {m}\n");
            let (e, _) = egress(&yaml, &["p"]);
            assert!(
                matches!(e, GeodataEgress::Direct),
                "{m} → direct, got {e:?}"
            );
        }
        let (e, _) = egress(
            "proxies:\n  - {name: p, type: direct}\nrules:\n  - match,reject\n",
            &["p"],
        );
        assert!(
            matches!(e, GeodataEgress::Rejected("REJECT")),
            "MATCH,REJECT must not download direct, got {e:?}"
        );
    }

    /// A MATCH target absent from the built map warns and falls through to
    /// `first_named_proxy` — a typo'd egress must not strand the download.
    #[test]
    fn geodata_proxy_missing_match_target_falls_back() {
        let (e, map) = egress(
            "proxies:\n  - {name: p, type: direct}\nrules:\n  - MATCH,ghost\n",
            &["p"],
        );
        assert_rides(&e, &map, "p", true);
    }

    /// A static `dialer-proxy` chain is deliberate egress: no direct
    /// fallback, whether it is the guessed `proxies[0]` or the MATCH target.
    #[test]
    fn geodata_proxy_chained_first_named_does_not_fall_back() {
        let (e, map) = egress(
            "proxies:\n  - {name: p, type: direct, dialer-proxy: front}\n  \
             - {name: front, type: direct}\n",
            &["p", "front"],
        );
        assert_rides(&e, &map, "p", false);
        let (e, map) = egress(
            "proxies:\n  - {name: front, type: direct}\n  \
             - {name: p, type: direct, dialer-proxy: front}\nrules:\n  - MATCH,p\n",
            &["p", "front"],
        );
        assert_rides(&e, &map, "p", false);
    }

    /// A group that can reach a static chain — a member, a nested group's
    /// member, `include-all`, or the synthesized `GLOBAL` — gets no direct
    /// fallback; a group of plain members keeps it.
    #[test]
    fn geodata_proxy_group_reaching_a_chain_does_not_fall_back() {
        let proxies = "proxies:\n  - {name: front, type: direct}\n  \
                       - {name: c, type: direct, dialer-proxy: front}\n  \
                       - {name: plain, type: direct}\n";
        let names = ["front", "c", "plain", "G", "H", "GLOBAL"];
        for (groups, fallback) in [
            ("  - {name: G, type: select, proxies: [plain, c]}\n", false),
            (
                "  - {name: H, type: select, proxies: [c]}\n  \
                 - {name: G, type: select, proxies: [plain, H]}\n",
                false,
            ),
            ("  - {name: G, type: select, include-all: true}\n", false),
            ("  - {name: G, type: select, proxies: [plain]}\n", true),
            (
                "  - {name: G, type: select, proxies: [plain, G2]}\n  \
                 - {name: G2, type: select, proxies: [G]}\n",
                true,
            ),
        ] {
            let yaml = format!("{proxies}proxy-groups:\n{groups}rules:\n  - MATCH,G\n");
            let (e, map) = egress(&yaml, &names);
            assert_rides(&e, &map, "G", fallback);
        }
        let (e, map) = egress_in(proxies, TunnelMode::Global, &names);
        assert_rides(&e, &map, "GLOBAL", false);
    }

    /// A group fed by a proxy-provider whose nodes declare `dialer-proxy` —
    /// named in `use:`, or pulled in by `include-all`/`include-all-providers`
    /// or a synthesized `GLOBAL` — gets no direct fallback; a group using
    /// only chain-free providers keeps it.
    #[test]
    fn geodata_proxy_group_using_a_chained_provider_does_not_fall_back() {
        let names = ["G", "GLOBAL"];
        for (group, chained, fallback) in [
            (
                "{name: G, type: select, use: [chain]}",
                &["chain"][..],
                false,
            ),
            (
                "{name: G, type: select, use: [plain]}",
                &["chain"][..],
                true,
            ),
            (
                "{name: G, type: select, include-all-providers: true}",
                &["chain"][..],
                false,
            ),
            (
                "{name: G, type: select, include-all: true}",
                &["chain"][..],
                false,
            ),
            (
                "{name: G, type: select, include-all-providers: true}",
                &[][..],
                true,
            ),
        ] {
            let yaml = format!("proxy-groups:\n  - {group}\nrules:\n  - MATCH,G\n");
            let (e, map) = egress_with(&yaml, TunnelMode::Rule, &names, chained);
            assert_rides(&e, &map, "G", fallback);
        }
        let (e, map) = egress_with("mode: global\n", TunnelMode::Global, &names, &["chain"]);
        assert_rides(&e, &map, "GLOBAL", false);
    }

    /// No override and no MATCH → `proxies[0]` (the legacy default).
    #[test]
    fn geodata_proxy_no_match_uses_first_named() {
        let (e, map) = egress(
            "proxies:\n  - {name: p, type: direct}\n  - {name: q, type: direct}\n",
            &["p", "q"],
        );
        assert_rides(&e, &map, "p", true);

        // Empty proxies / empty map → direct.
        let (e, _) = egress("mode: rule\n", &[]);
        assert!(matches!(e, GeodataEgress::Direct), "{e:?}");
    }

    /// A group name resolves as-is against the map (the map holds the built
    /// group adapter — no leaf-stripping; the selector's persisted choice
    /// or first member dials at fetch time).
    #[test]
    fn geodata_proxy_group_name_resolves_to_group_adapter() {
        let (e, map) = egress("geodata:\n  proxy: select-group\n", &["select-group"]);
        assert_rides(&e, &map, "select-group", false);
    }

    /// The mode's default route replaces MATCH outside `rule` mode: `direct`
    /// fetches direct, `global` rides `GLOBAL` (direct without one, as the
    /// tunnel routes). An explicit `geodata.proxy` still wins.
    #[test]
    fn geodata_proxy_follows_tunnel_mode() {
        let yaml = "proxies:\n  - {name: out, type: direct}\nrules:\n  - MATCH,out\n";
        let (e, _) = egress_in(yaml, TunnelMode::Direct, &["out", "GLOBAL"]);
        assert!(matches!(e, GeodataEgress::Direct), "{e:?}");
        let (e, map) = egress_in(yaml, TunnelMode::Global, &["out", "GLOBAL"]);
        assert_rides(&e, &map, "GLOBAL", true);

        let yaml = "proxies:\n  - {name: out, type: direct}\nrules:\n  - MATCH,DIRECT\n";
        let (e, map) = egress_in(yaml, TunnelMode::Global, &["out", "GLOBAL"]);
        assert_rides(&e, &map, "GLOBAL", true);
        let (e, _) = egress_in(yaml, TunnelMode::Global, &["out"]);
        assert!(matches!(e, GeodataEgress::Direct), "{e:?}");

        let (e, map) = egress_in(
            "geodata:\n  proxy: out\nrules:\n  - MATCH,DIRECT\n",
            TunnelMode::Direct,
            &["out"],
        );
        assert_rides(&e, &map, "out", false);
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
        // materialised on the typed struct — without the parser's merge-key
        // policy these would appear missing and deserialisation would fail
        // with `missing field`.
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
            &rule_provider::PrefetchedPayloads::default(),
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
        let raw: raw::RawConfig = serde_saphyr::from_str(
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
        let raw: raw::RawConfig = serde_saphyr::from_str(
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
        let raw: raw::RawConfig = serde_saphyr::from_str(
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
        let raw: raw::RawConfig = serde_saphyr::from_str(
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
        let result = rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
        .expect("trusted rebuild with the real cache dir must not hard-fail on a file provider");
        assert_eq!(result.rules.len(), 2);

        // `rebuild_from_raw_runtime` — used by meow-api's `PUT /configs`
        // family via `rebuild_from_raw_runtime_async`.
        let result = rebuild_from_raw_runtime(
            &raw,
            None,
            &HashMap::new(),
            Some(dir.path()),
            &Default::default(),
            &meow_proxy::SelectionBacking::unpersisted(),
            &meow_dns::new_dns_outbound_cell(),
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
        let raw: raw::RawConfig = serde_saphyr::from_str(
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
        let result = rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
        .expect("rebuild ok");
        *live.write() = result.rule_providers;
        assert!(live.read().contains_key("ads"));

        // A candidate that drops `rule-providers:` empties the registry.
        let raw_bare: raw::RawConfig =
            serde_saphyr::from_str("rules:\n  - \"MATCH,DIRECT\"\n").unwrap();
        let result = rebuild_from_raw_with_resolver(
            &raw_bare,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
        .expect("rebuild ok");
        *live.write() = result.rule_providers;
        assert!(live.read().is_empty());

        // A failing build returns Err — the caller never commits, so the
        // live registry (seeded above via a good build) stays untouched.
        let raw_ok: raw::RawConfig = serde_saphyr::from_str(
            "rule-providers:\n  ads:\n    type: file\n    behavior: domain\n    format: yaml\n    path: ads.yaml\nrules:\n  - RULE-SET,ads,REJECT\n  - \"MATCH,DIRECT\"\n",
        )
        .unwrap();
        let result = rebuild_from_raw_with_resolver(
            &raw_ok,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
        .expect("rebuild ok");
        *live.write() = result.rule_providers;
        let raw_bad: raw::RawConfig =
            serde_saphyr::from_str("rules:\n  - SUB-RULE,(MATCH,DIRECT),missing\n").unwrap();
        assert!(rebuild_from_raw_with_resolver(
            &raw_bad,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
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
        let raw: raw::RawConfig = serde_saphyr::from_str(
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
        let raw: raw::RawConfig = serde_saphyr::from_str(
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
        serde_saphyr::from_str(yaml).unwrap()
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
    fn rejects_absurd_group_health_interval() {
        // `interval` seconds reach `tokio::time::interval` in the health
        // supervisor — an out-of-range u64 panics on `Instant + Duration`
        // under `panic = "abort"` (issue #648).
        let yaml = r#"
strict: true
proxies:
  - { name: p, type: direct }
proxy-groups:
  - { name: g, type: url-test, proxies: [p], url: "https://example.com/", interval: 18446744073709551615 }
rules:
  - "MATCH,DIRECT"
"#;
        let Err(err) = rebuild_from_raw(&raw_config(yaml)) else {
            panic!("absurd group interval must be rejected");
        };
        assert!(err.to_string().contains("interval"), "unexpected: {err}");
    }

    #[test]
    fn rejects_duplicate_subscription_names() {
        // Subscription names key the `applied-*` contribution tracking
        // (issue #640): a duplicate would split ownership bookkeeping
        // between entries, so the same-name apply/deletes corrupt each
        // other's tracked sets.
        let yaml = r#"
proxies:
  - { name: p, type: direct }
subscriptions:
  - { name: s, url: "https://a.example.com/" }
  - { name: s, url: "https://b.example.com/" }
rules:
  - "MATCH,DIRECT"
"#;
        let Err(err) = rebuild_from_raw(&raw_config(yaml)) else {
            panic!("duplicate subscription names must be rejected");
        };
        assert!(
            err.to_string().contains("duplicate name") && err.to_string().contains('s'),
            "unexpected: {err}"
        );
    }

    /// A `type: rematch` leaf is a routing control, never a relay
    /// transport hop (issue #974): a declared member naming one is a
    /// structural error in *both* modes — a relaxed warn-drop would
    /// silently remove the chain's fail-closed semantics.
    #[test]
    fn rejects_static_rematch_relay_member() {
        for strict in ["true", "false"] {
            let yaml = format!(
                r#"
strict: {strict}
proxies:
  - {{ name: inspect, type: rematch, target-rematch-name: stage1 }}
  - {{ name: node, type: direct }}
proxy-groups:
  - {{ name: chain, type: relay, proxies: [node, inspect] }}
rules:
  - "MATCH,chain"
"#,
            );
            let Err(err) = rebuild_from_raw(&raw_config(&yaml)) else {
                panic!("strict={strict}: a static rematch relay hop must fail the build");
            };
            assert!(
                err.to_string().contains("cannot be a relay transport hop"),
                "strict={strict}: unexpected: {err}"
            );
        }
    }

    /// The same membership arriving through `include-all-proxies` keeps
    /// the gate — the expansion feeds the member vec `parse_relay_group`
    /// checks.
    #[test]
    fn rejects_include_all_rematch_relay_member() {
        let yaml = r#"
proxies:
  - { name: inspect, type: rematch, target-rematch-name: stage1 }
  - { name: node, type: direct }
proxy-groups:
  - { name: chain, type: relay, include-all-proxies: true }
rules:
  - "MATCH,chain"
"#;
        let Err(err) = rebuild_from_raw(&raw_config(yaml)) else {
            panic!("an include-all rematch relay hop must fail the build");
        };
        assert!(
            err.to_string().contains("cannot be a relay transport hop"),
            "unexpected: {err}"
        );
    }

    /// A `type: dns` leaf beside a transport builds like any other node —
    /// and lands as `AdapterType::Dns`, never wrapped or degraded
    /// (issue #974).
    #[test]
    fn dns_leaf_builds_alongside_transports() {
        let yaml = r#"
proxies:
  - { name: dns-out, type: dns }
  - { name: node, type: direct }
rules:
  - "DST-PORT,53,dns-out"
  - "MATCH,node"
"#;
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw_config(yaml)).expect("a dns leaf beside a transport builds");
        assert_eq!(
            proxies["dns-out"].adapter_type(),
            meow_common::AdapterType::Dns
        );
    }

    /// `dialer-proxy` on a dns node collects no edge and no wrapper —
    /// mihomo reads no chain options off the leaf (issue #974).
    #[test]
    fn dns_leaf_dialer_proxy_collects_no_edge() {
        for strict in ["true", "false"] {
            let yaml = format!(
                r#"
strict: {strict}
proxies:
  - {{ name: dns-out, type: dns, dialer-proxy: front }}
  - {{ name: front, type: direct }}
rules:
  - "MATCH,dns-out"
"#,
            );
            let RebuildResult { proxies, .. } = rebuild_from_raw(&raw_config(&yaml))
                .unwrap_or_else(|e| {
                    panic!("strict={strict}: a dns leaf's dialer-proxy is ignored: {e}")
                });
            let leaf = &proxies["dns-out"];
            assert_eq!(leaf.adapter_type(), meow_common::AdapterType::Dns);
            assert!(
                !leaf
                    .as_any()
                    .is_some_and(<dyn std::any::Any>::is::<meow_proxy::DialerProxyAdapter>),
                "strict={strict}: the dns leaf must not be chain-wrapped"
            );
        }
    }

    /// A `type: dns` leaf is an in-process resolver endpoint — naming it
    /// as a `dialer-proxy` front is a structural error in *both* modes,
    /// exactly like a rematch front (issue #974).
    #[test]
    fn rejects_dns_leaf_as_dialer_front() {
        for strict in ["true", "false"] {
            let yaml = format!(
                r#"
strict: {strict}
proxies:
  - {{ name: node, type: socks5, server: 127.0.0.1, port: 1080, dialer-proxy: dns-out }}
  - {{ name: dns-out, type: dns }}
rules:
  - "MATCH,node"
"#,
            );
            let Err(err) = rebuild_from_raw(&raw_config(&yaml)) else {
                panic!("strict={strict}: a dns leaf cannot carry a dialer front");
            };
            assert!(
                err.to_string().contains("cannot carry a dialer front"),
                "strict={strict}: unexpected: {err}"
            );
        }
    }

    /// A provider node's `dialer-proxy` binds late — against the finished
    /// registry — so it cannot be shape-checked at edge-collection time.
    /// When that name resolves to a static `type: dns` leaf the verdict is
    /// the same hard failure a static edge gets (issue #974 review).
    #[test]
    fn rejects_provider_dialer_front_on_dns_leaf() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.yaml"),
            "proxies:\n  - {name: hop, type: socks5, server: 127.0.0.1, port: 1080, dialer-proxy: dns-out}\n",
        )
        .unwrap();
        let yaml = r#"
proxies:
  - { name: dns-out, type: dns }
proxy-providers:
  airport:
    type: file
    path: nodes.yaml
rules:
  - "MATCH,DIRECT"
"#;
        let Err(err) = rebuild_from_raw_with_resolver(
            &raw_config(yaml),
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        ) else {
            panic!("a provider dialer front landing on a dns leaf must fail the build");
        };
        assert!(
            err.to_string().contains("cannot carry a dialer front"),
            "unexpected: {err}"
        );
    }

    /// A `type: dns` leaf can never be a relay transport hop — a declared
    /// member naming one is a structural error in *both* modes (issue
    /// #974).
    #[test]
    fn rejects_static_dns_relay_member() {
        for strict in ["true", "false"] {
            let yaml = format!(
                r#"
strict: {strict}
proxies:
  - {{ name: dns-out, type: dns }}
  - {{ name: node, type: direct }}
proxy-groups:
  - {{ name: chain, type: relay, proxies: [node, dns-out] }}
rules:
  - "MATCH,chain"
"#,
            );
            let Err(err) = rebuild_from_raw(&raw_config(&yaml)) else {
                panic!("strict={strict}: a static dns relay hop must fail the build");
            };
            assert!(
                err.to_string().contains("cannot be a relay transport hop"),
                "strict={strict}: unexpected: {err}"
            );
        }
    }

    /// The same membership arriving through `include-all-proxies` keeps
    /// the gate — the expansion feeds the member vec `parse_relay_group`
    /// checks (issue #974).
    #[test]
    fn rejects_include_all_dns_relay_member() {
        let yaml = r#"
proxies:
  - { name: dns-out, type: dns }
  - { name: node, type: direct }
proxy-groups:
  - { name: chain, type: relay, include-all-proxies: true }
rules:
  - "MATCH,chain"
"#;
        let Err(err) = rebuild_from_raw(&raw_config(yaml)) else {
            panic!("an include-all dns relay hop must fail the build");
        };
        assert!(
            err.to_string().contains("cannot be a relay transport hop"),
            "unexpected: {err}"
        );
    }

    /// A `type: rematch` leaf must not become the synthesized GLOBAL's
    /// primary: the first member is global mode's default pick, and a
    /// control outbound cannot carry traffic. It still lists as a member
    /// (upstream `proxyList` semantics) so an explicit selection fails
    /// closed at dial (issue #974).
    #[test]
    fn auto_global_never_primes_a_rematch_leaf() {
        let yaml = r#"
proxies:
  - { name: inspect, type: rematch, target-rematch-name: stage1 }
  - { name: node, type: socks5, server: 127.0.0.1, port: 1 }
rules:
  - "MATCH,inspect"
"#;
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw_config(yaml)).expect("a rematch leaf beside a transport builds");
        let members = proxies["GLOBAL"]
            .member_proxies()
            .expect("a select group exposes members");
        let names: Vec<&str> = members.iter().map(|p| p.name()).collect();
        assert!(
            names.contains(&"inspect"),
            "the rematch leaf stays a GLOBAL member: {names:?}"
        );
        assert_eq!(names[0], "node", "the primary is a dialable outbound");
    }

    /// The same verdict for a `type: dns` leaf (issue #974 review): it
    /// is a resolver endpoint, not a dialable outbound — a `MATCH,dns-out`
    /// rule must not prime it, and the member-order fallback must skip it
    /// too. It still lists as a member so an explicit selection fails
    /// closed at dial.
    #[test]
    fn auto_global_never_primes_a_dns_leaf() {
        let yaml = r#"
proxies:
  - { name: dns-out, type: dns }
  - { name: node, type: socks5, server: 127.0.0.1, port: 1 }
rules:
  - "MATCH,dns-out"
"#;
        let RebuildResult { proxies, .. } =
            rebuild_from_raw(&raw_config(yaml)).expect("a dns leaf beside a transport builds");
        let members = proxies["GLOBAL"]
            .member_proxies()
            .expect("a select group exposes members");
        let names: Vec<&str> = members.iter().map(|p| p.name()).collect();
        assert!(
            names.contains(&"dns-out"),
            "the dns leaf stays a GLOBAL member: {names:?}"
        );
        assert_eq!(
            names[0], "node",
            "the primary is a dialable outbound even when MATCH names the dns leaf"
        );
    }

    /// A blank `dialer-proxy` on a `type: rematch` node is unset, not a
    /// malformed edge — `check_rematch_node` treats blank-or-null as
    /// absent, and binding the fail-at-dial sentinel would wrap the leaf
    /// in `DialerProxyAdapter` and hide its rematch action (issue #974).
    #[test]
    fn blank_dialer_proxy_on_rematch_node_is_unset() {
        for strict in ["true", "false"] {
            let yaml = format!(
                r#"
strict: {strict}
proxies:
  - {{ name: inspect, type: rematch, target-rematch-name: stage1, dialer-proxy: " " }}
rules:
  - "MATCH,DIRECT"
"#,
            );
            let RebuildResult { proxies, .. } = rebuild_from_raw(&raw_config(&yaml))
                .expect("a blank dialer-proxy on a rematch node is unset");
            assert!(
                proxies["inspect"].rematch_action().is_some(),
                "strict={strict}: the rematch leaf must keep its action"
            );
        }
    }

    #[test]
    fn rejects_absurd_tcp_connect_timeout() {
        // Same `Instant + Duration` class via `tokio::time::timeout`
        // (issue #648).
        let yaml = r#"
tcp-connect-timeout: 18446744073709551615
proxies:
  - { name: p, type: direct }
rules:
  - "MATCH,DIRECT"
"#;
        let Err(err) = rebuild_from_raw(&raw_config(yaml)) else {
            panic!("absurd tcp-connect-timeout must be rejected");
        };
        assert!(
            err.to_string().contains("tcp-connect-timeout"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_absurd_udp_timeouts() {
        // tun.udp-timeout feeds `Instant + udp_timeout`; the listeners:
        // variant shares the bound for consumer safety (issue #648).
        let tun = raw::RawTun {
            enable: true,
            udp_timeout: Some(u64::MAX),
            ..raw::RawTun::default()
        };
        let err = parse_tun_config(Some(&tun), None, None)
            .expect_err("absurd tun.udp-timeout must be rejected");
        assert!(err.to_string().contains("udp-timeout"), "unexpected: {err}");

        let raw_l: raw::RawListener = serde_saphyr::from_str(
            "name: t\ntype: tproxy\nport: 7893\nudp: true\nfirewall: false\n\
             udp-timeout: 18446744073709551615\n",
        )
        .unwrap();
        let err = parse_listener_spec(&raw_l, false, false)
            .expect_err("absurd listener udp-timeout must be rejected");
        assert!(err.to_string().contains("udp-timeout"), "unexpected: {err}");
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

    /// Same payload as the `file:` case above, served over HTTP: remote
    /// bytes are third-party content the operator cannot fix by editing the
    /// config, so strict registers the provider empty and owes a background
    /// retry instead of aborting the load (origin split — the `file:` twin
    /// stays fatal).
    #[tokio::test]
    async fn strict_degrades_unparseable_remote_provider_node() {
        crate::test_support::install_global_discard_subscriber();
        let origin = crate::test_support::Origin::spawn(
            Some(
                "proxies:\n  - { name: ok, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: x }\n  - { name: broken, type: nosuchtype }\n",
            ),
            true,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let yaml = format!(
            r#"
proxy-providers:
  remote:
    type: http
    url: '{}'
"#,
            origin.url
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
        .expect("a remote payload defect must degrade under strict, not fail");
        let provider = map.get("remote").expect("provider must be registered");
        assert!(
            provider.proxies().is_empty(),
            "the rejected remote payload registers the provider empty"
        );
        assert!(
            provider.take_deferred_initial(),
            "the degraded load owes a background retry"
        );
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
    /// (`direct`, SS + external SIP003) fails the
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
        let result = rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
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
            serde_saphyr::from_str("type: http\nurl: http://127.0.0.1:1/x.yaml").unwrap();
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
        let Err(err) = rebuild_from_raw_with_resolver(
            &raw,
            None,
            None,
            &live,
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        ) else {
            panic!("use: of a removed provider must fail strict");
        };
        assert!(err.to_string().contains("airport"), "unexpected: {err}");

        // Lenient keeps the group — the zombie Arc is not consulted.
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let result = rebuild_from_raw_with_resolver(
            &raw,
            None,
            None,
            &live,
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
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
            rebuild_from_raw_with_resolver(
                &raw,
                None,
                Some(dir.path()),
                &HashMap::new(),
                None,
                &meow_proxy::SelectionBacking::unpersisted(),
            )
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
        let result = rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
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
        let Err(err) = rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        ) else {
            panic!("strict must reject an unparseable provider url");
        };
        assert!(err.to_string().contains("url"), "unexpected: {err}");

        // Lenient keeps the acquisition-failure contract: the bad URL is a
        // fetch-time error → empty registered provider.
        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
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
        let Err(err) = rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        ) else {
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
        if rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
        .is_ok()
        {
            panic!("strict must reject a non-string payload item");
        }

        let raw = raw_config(&yaml.replace("{STRICT}", "false"));
        let result = rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
            &meow_proxy::SelectionBacking::unpersisted(),
        )
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
        let def: raw::RawProxyProvider = serde_saphyr::from_str(&format!(
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
        let mut proxies = vec![
            serde_saphyr::from_str::<HashMap<String, serde_json::Value>>(
                "{ name: p, type: ss, ech-opts: { enable: true } }",
            )
            .unwrap(),
        ];
        let err = ech_dns::preresolve_ech(&mut proxies, true)
            .await
            .expect_err("strict must reject enable:true with no query source");
        assert!(err.contains("p"), "unexpected: {err}");

        let mut proxies = vec![
            serde_saphyr::from_str::<HashMap<String, serde_json::Value>>(
                "{ name: p, type: ss, ech-opts: { enable: true } }",
            )
            .unwrap(),
        ];
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
            &meow_dns::new_dns_outbound_cell(),
            &mut DroppedProviders::default(),
        )
        .expect("provider materializes");
        let provider = Arc::clone(first.get("p").unwrap());

        // Unchanged def → same Arc reused.
        let again = materialize_proxy_providers(
            &raw,
            &first,
            Some(cache_dir),
            false,
            &Default::default(),
            &meow_dns::new_dns_outbound_cell(),
            &mut DroppedProviders::default(),
        )
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
            &meow_dns::new_dns_outbound_cell(),
            &mut DroppedProviders::default(),
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
            &meow_dns::new_dns_outbound_cell(),
            &mut DroppedProviders::default(),
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
            &meow_dns::new_dns_outbound_cell(),
            &mut DroppedProviders::default(),
        )
        .expect("interval-only change must reuse the provider");
        assert!(
            Arc::ptr_eq(again.get("p").unwrap(), &provider),
            "interval is a schedule knob, not provider identity"
        );
    }

    /// A `global-client-fingerprint` flip rebuilds the provider (its
    /// adapters bake the profile), but the rebuild must not serve an
    /// empty slot until a fetch lands: the predecessor's last committed
    /// payload is re-parsed under the new fingerprint instead — with no
    /// cache directory (the `--config-string` shape) there is nothing
    /// else to serve from, and `origin.hits()` proves no request ran
    /// (issue #974 review). A `vmess` `tls: true` node reports its baked
    /// fingerprint, so `client_fingerprint()` reads which global the
    /// parse ran under.
    #[cfg(feature = "vmess")]
    #[tokio::test]
    async fn fingerprint_only_rebuild_inherits_last_good_payload() {
        const PAYLOAD: &str = "proxies:\n  - {name: n1, type: vmess, server: 127.0.0.1, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, alterId: 0, cipher: auto, tls: true}\n";
        let origin = crate::test_support::Origin::spawn(Some(PAYLOAD), true).await;
        let yaml = |fp: &str| {
            format!(
                "global-client-fingerprint: {fp}\nproxy-providers:\n  p:\n    type: http\n    url: '{}'\n",
                origin.url
            )
        };
        let registry: meow_proxy::dialer::ProxyRegistry = Default::default();

        // The live provider fetches once and commits the payload.
        let raw = raw_config(&yaml("chrome"));
        let live = materialize_proxy_providers(
            &raw,
            &HashMap::new(),
            None,
            false,
            &registry,
            &meow_dns::new_dns_outbound_cell(),
            &mut DroppedProviders::default(),
        )
        .expect("provider materializes");
        live["p"]
            .acquire_initial()
            .await
            .expect("the initial fetch lands");
        assert_eq!(live["p"].proxies().len(), 1);
        assert_eq!(origin.hits(), 1);

        // Fingerprint-only candidate — identical def, new global: rebuilt,
        // but populated from the predecessor's retained payload rather
        // than serving empty until the detached post-commit fetch.
        let next = materialize_proxy_providers(
            &raw_config(&yaml("firefox")),
            &live,
            None,
            false,
            &registry,
            &meow_dns::new_dns_outbound_cell(),
            &mut DroppedProviders::default(),
        )
        .expect("fingerprint-only rebuild materializes");
        let rebuilt = &next["p"];
        assert!(
            !Arc::ptr_eq(rebuilt, &live["p"]),
            "a changed global fingerprint must rebuild the provider"
        );
        assert_eq!(
            rebuilt.proxies().len(),
            1,
            "the rebuild inherits the predecessor's payload instead of starting empty"
        );
        assert_eq!(
            rebuilt.proxies()[0].client_fingerprint(),
            Some("firefox"),
            "the payload re-parsed under the candidate fingerprint, not the old adapters"
        );
        assert_eq!(
            origin.hits(),
            1,
            "no request ran — the payload transferred without a fetch"
        );

        // A def change is not fingerprint-only: no transfer, the provider
        // keeps the detached-fetch contract (empty until one lands).
        let changed = materialize_proxy_providers(
            &raw_config(&yaml("firefox").replace(&origin.url, "http://127.0.0.1:9/dead")),
            &next,
            None,
            false,
            &registry,
            &meow_dns::new_dns_outbound_cell(),
            &mut DroppedProviders::default(),
        )
        .expect("def change materializes fresh");
        assert!(
            changed["p"].proxies().is_empty(),
            "a changed def must not inherit the predecessor's payload"
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
            serde_saphyr::from_str("type: file\npath: empty.yaml\n").unwrap();
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
    //! drive the recursive `serde_json::Value` deserializer past a bounded
    //! depth — `[[[[…` or ever-deepening indentation overflows a
    //! blocking-thread stack inside the fetch-size caps (issue #533 review).
    //! This module's `yaml_within_depth` is the cheap pre-filter; the hard
    //! bound is `yaml_options`' `budget.max_depth` inside the parser, made
    //! reachable from any caller stack by the dedicated parse thread
    //! (`meow_common::yaml::run_on_parse_stack`).
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
        serde_saphyr::from_str(&yaml).unwrap()
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
            Some(serde_saphyr::from_str("mmdb-path: /nonexistent-543/Country.mmdb").unwrap());
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

        let raw: raw::RawConfig = serde_saphyr::from_str(&format!(
            "rule-providers:\n  p:\n    type: http\n    behavior: domain\n    url: http://127.0.0.1:{port}/p.yaml\nrules:\n  - RULE-SET,p,DIRECT\n"
        ))
        .unwrap();
        let mut shared: HashMap<String, Arc<rule_provider::RuleProvider>> = HashMap::new();
        shared.insert(
            "p".to_string(),
            rule_provider::test_provider("p", rule_provider::ProviderType::Http, 0),
        );

        let result = rebuild_from_raw_with_resolver(
            &raw,
            None,
            None,
            &HashMap::new(),
            Some(shared),
            &meow_proxy::SelectionBacking::unpersisted(),
        )
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

#[cfg(test)]
mod default_geo_path_tests {
    //! The default GeoIP / ASN paths take the database a mihomo GUI copies
    //! into the home directory (`country.mmdb`, `ASN.mmdb`) instead of
    //! downloading a second copy under meow's own names.
    use super::*;

    const GEOIP: &[&str] = &["Country.mmdb"];
    const ASN: &[&str] = &["GeoLite2-ASN.mmdb", "ASN.mmdb"];

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"mmdb").unwrap();
    }

    #[test]
    fn missing_database_falls_back_to_the_download_name() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            existing_or_first(dir.path(), GEOIP),
            dir.path().join("Country.mmdb")
        );
        assert_eq!(
            existing_or_first(dir.path(), ASN),
            dir.path().join("GeoLite2-ASN.mmdb")
        );
        let gone = dir.path().join("not-there");
        assert_eq!(existing_or_first(&gone, GEOIP), gone.join("Country.mmdb"));
    }

    #[test]
    fn existing_database_is_matched_ignoring_case() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "country.mmdb");
        touch(dir.path(), "asn.mmdb");
        assert_eq!(
            existing_or_first(dir.path(), GEOIP),
            dir.path().join("country.mmdb")
        );
        assert_eq!(
            existing_or_first(dir.path(), ASN),
            dir.path().join("asn.mmdb")
        );
    }

    #[test]
    fn earlier_name_wins_over_a_later_one() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "ASN.mmdb");
        touch(dir.path(), "GeoLite2-ASN.mmdb");
        assert_eq!(
            existing_or_first(dir.path(), ASN),
            dir.path().join("GeoLite2-ASN.mmdb")
        );
    }

    #[test]
    fn exact_name_wins_over_a_case_variant() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "country.mmdb");
        touch(dir.path(), "Country.mmdb");
        // On a case-insensitive filesystem the second write lands on the
        // first file, leaving nothing to choose between.
        if std::fs::read_dir(dir.path()).unwrap().count() == 2 {
            assert_eq!(
                existing_or_first(dir.path(), GEOIP),
                dir.path().join("Country.mmdb")
            );
        }
    }

    #[test]
    fn a_directory_is_not_a_database() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("asn.mmdb")).unwrap();
        assert_eq!(
            existing_or_first(dir.path(), ASN),
            dir.path().join("GeoLite2-ASN.mmdb")
        );
    }
}

#[cfg(test)]
mod connection_limit_tests {
    use super::*;

    #[test]
    fn oversized_global_connection_limit_is_a_config_error() {
        let raw = raw::RawConfig {
            mixed_port: Some(1080),
            max_connections: Some(tokio::sync::Semaphore::MAX_PERMITS + 1),
            ..Default::default()
        };
        assert!(build_named_listeners(&raw, "127.0.0.1", false).is_err());
    }

    #[test]
    fn oversized_named_connection_limit_is_a_config_error() {
        let raw: raw::RawConfig = crate::parse_raw_yaml(&format!(
            "listeners:\n  - name: test\n    type: mixed\n    port: 0\n    max-connections: {}\n",
            tokio::sync::Semaphore::MAX_PERMITS + 1
        ))
        .unwrap();
        assert!(build_named_listeners(&raw, "127.0.0.1", false).is_err());
    }

    #[test]
    fn tun_parser_rejects_unrepresentable_connection_limit() {
        let oversized = Some(tokio::sync::Semaphore::MAX_PERMITS + 1);
        assert!(parse_tun_config(None, oversized, None).is_err());
        assert!(parse_tun_config(Some(&raw::RawTun::default()), oversized, None).is_err());
    }

    #[test]
    fn connection_limit_boundaries_preserve_existing_semantics() {
        for limit in [0, 256, tokio::sync::Semaphore::MAX_PERMITS] {
            let raw = raw::RawConfig {
                mixed_port: Some(1080),
                max_connections: Some(limit),
                ..Default::default()
            };
            let listeners = build_named_listeners(&raw, "127.0.0.1", false).unwrap();
            assert_eq!(listeners[0].max_connections, limit);
            assert_eq!(
                parse_tun_config(None, Some(limit), None)
                    .unwrap()
                    .max_connections,
                limit
            );
        }
        let raw = raw::RawConfig {
            mixed_port: Some(1080),
            ..Default::default()
        };
        assert_eq!(
            build_named_listeners(&raw, "127.0.0.1", false).unwrap()[0].max_connections,
            256
        );
        assert_eq!(
            parse_tun_config(None, None, None).unwrap().max_connections,
            256
        );
    }
}

#[cfg(test)]
mod listener_surface_tests {
    use super::*;

    fn proxies_with_direct() -> HashMap<SmolStr, Arc<dyn Proxy>> {
        HashMap::from([(
            SmolStr::from("DIRECT"),
            Arc::new(proxy_parser::WrappedProxy::new(Box::new(
                meow_proxy::DirectAdapter::new(),
            ))) as Arc<dyn Proxy>,
        )])
    }

    #[test]
    fn routing_mark_zero_normalizes_to_unset() {
        // `0` is the firewall-exempt wildcard, not a real mark — it must
        // never reach `setsockopt`.
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: m\n    type: mixed\n    port: 0\n    routing-mark: 0\n",
        )
        .unwrap();
        let listeners = build_named_listeners(&raw, "127.0.0.1", false).unwrap();
        assert_eq!(listeners[0].routing_mark, None);
    }

    #[test]
    fn routing_mark_drops_on_transparent_and_responder_listeners() {
        // Marking a TPROXY/WireGuard socket would tag the steered reply
        // packets the policy rules must route back — the key is ignored
        // there even when nonzero.
        for ty in ["tproxy", "redir"] {
            let raw: raw::RawConfig = crate::parse_raw_yaml(&format!(
                "listeners:\n  - name: t\n    type: {ty}\n    port: 0\n    routing-mark: 7\n"
            ))
            .unwrap();
            let listeners = build_named_listeners(&raw, "127.0.0.1", false).unwrap();
            assert_eq!(listeners[0].routing_mark, None, "{ty}");
        }
        // WireGuard responder: same drop arm, a real key pair is needed to
        // reach the mark resolution (RFC 7748 Alice scalar + Bob public).
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: w\n    type: wireguard\n    port: 0\n    routing-mark: 7\n    private-key: \"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=\"\n    peers:\n      - public-key: \"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=\"\n        allowed-ips: [10.0.0.0/8]\n",
        )
        .unwrap();
        let listeners = build_named_listeners(&raw, "127.0.0.1", false).unwrap();
        assert_eq!(listeners[0].routing_mark, None, "wireguard");
    }

    #[test]
    fn routing_mark_survives_on_socket_listeners() {
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: m\n    type: mixed\n    port: 0\n    routing-mark: 7\n",
        )
        .unwrap();
        let listeners = build_named_listeners(&raw, "127.0.0.1", false).unwrap();
        assert_eq!(listeners[0].routing_mark, Some(7));
    }

    #[test]
    fn routing_mark_negative_is_a_parse_error() {
        // Upstream rejected nonnumeric marks; a negative one is no "unset"
        // spelling and must not coerce — u32 decode fails outright.
        let err = crate::parse_raw_yaml(
            "listeners:\n  - name: m\n    type: mixed\n    port: 0\n    routing-mark: -1\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("routing-mark"), "{err}");
    }

    /// Admission accepts the references the listener surface supports: a
    /// `proxy:` naming a rebuilt group and a `rule:` naming a `sub-rules:`
    /// block — the pair a `-t`/startup/PUT pass must let through
    /// (spec §2).
    #[test]
    fn listener_group_and_block_references_admit() {
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "proxy-groups:\n  - name: pick\n    type: select\n    proxies: [DIRECT]\nsub-rules:\n  side:\n    - DOMAIN,example.com,DIRECT\nlisteners:\n  - name: m\n    type: mixed\n    port: 0\n    proxy: pick\n    rule: side\n",
        )
        .unwrap();
        let listeners = build_named_listeners(&raw, "127.0.0.1", false).unwrap();
        let over = listeners[0].route_override.as_ref().unwrap();
        assert_eq!(over.proxy.as_deref(), Some("pick"));
        assert_eq!(over.rule.as_deref(), Some("side"));
        // The map-level gate admits the same pair — no false positive
        // from validating `proxy` against leaf names only.
        let built = rebuild_from_raw(&raw).unwrap();
        validate_listener_proxy_targets(&raw, &built.proxies, &built.proxy_providers).unwrap();
    }

    #[test]
    fn listener_proxy_target_err_names_only_built_targets() {
        let proxies = proxies_with_direct();
        let dir = tempfile::tempdir().unwrap();
        let raw_def: raw::RawProxyProvider =
            serde_saphyr::from_str("type: file\npath: p.yaml\n").unwrap();
        let provider = ProxyProvider::new(
            "feed",
            &raw_def,
            Some(dir.path()),
            false,
            true,
            Default::default(),
        )
        .unwrap();
        let providers: HashMap<String, Arc<ProxyProvider>> =
            HashMap::from([("feed".to_string(), Arc::new(provider))]);
        // A missing name and a provider name fail; a built adapter passes.
        assert!(listener_proxy_target_err("ghost", &proxies, &providers).is_some());
        let err = listener_proxy_target_err("feed", &proxies, &providers).unwrap();
        assert!(err.contains("proxy-provider"), "{err}");
        assert!(listener_proxy_target_err("DIRECT", &proxies, &providers).is_none());
    }

    /// The PUT `force`-floor half: an undeclared name or a provider name
    /// fails at the document level, while every *declared* name — leaf,
    /// group, built-in, auto GLOBAL — is admitted so a name that merely
    /// fails to build stays force-degradable (environment, not shape).
    #[test]
    fn listener_proxy_target_shape_err_gates_undeclared_names() {
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "proxies:\n  - {name: leaf, type: direct}\nproxy-groups:\n  - name: g\n    type: select\n    proxies: [leaf]\nproxy-providers:\n  feed:\n    type: file\n    path: p.yaml\nlisteners:\n  - name: bad\n    type: mixed\n    port: 0\n    proxy: ghost\n  - name: worse\n    type: mixed\n    port: 0\n    proxy: feed\n",
        )
        .unwrap();
        for (decl, want) in [
            ("ghost", true),
            ("feed", true),
            ("leaf", false),
            ("g", false),
            ("DIRECT", false),
            ("GLOBAL", false),
        ] {
            let mut probe = raw.clone();
            probe.listeners.as_mut().unwrap()[0].proxy = Some(decl.to_string());
            probe.listeners.as_mut().unwrap()[1].proxy = None;
            assert_eq!(
                listener_proxy_target_shape_err(&probe).is_some(),
                want,
                "{decl}"
            );
        }
    }

    // ── `type: anytls` listener spec ─────────────────────────────────
    //
    // The C1/W1 config matrix of the inbound spec: user table, security
    // modes, opaque front layers, `enable`/`udp`, padding, multi-address
    // `listen`, and the duplicate-port registry's reach into extra
    // addresses.

    fn anytls_named(extra: &str) -> Result<Vec<NamedListener>, anyhow::Error> {
        let yaml = format!("listeners:\n  - name: a\n    type: anytls\n    port: 0\n{extra}");
        let raw: raw::RawConfig = crate::parse_raw_yaml(&yaml).unwrap();
        build_named_listeners(&raw, "127.0.0.1", false)
    }

    fn anytls_named_err(extra: &str) -> String {
        anytls_named(extra)
            .map(|l| format!("BUILT {l:?}"))
            .unwrap_err()
            .to_string()
    }

    const ANYTLS_USERS: &str = "    users: {alice: pw1, bob: pw2}\n";
    const ANYTLS_INSECURE: &str = "    allow-insecure: true\n";
    const ANYTLS_CERT: &str =
        "    certificate: \"-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\"\n    private-key: \"-----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----\"\n";

    #[test]
    fn anytls_users_multi_in_declaration_order() {
        let listeners = anytls_named(&format!("{ANYTLS_USERS}{ANYTLS_INSECURE}")).unwrap();
        let ListenerSpec::Anytls(cfg) = &listeners[0].spec else {
            panic!("expected anytls spec");
        };
        assert_eq!(
            cfg.users
                .iter()
                .map(|u| u.name.as_str())
                .collect::<Vec<_>>(),
            ["alice", "bob"]
        );
        assert_ne!(cfg.users[0].password_sha256, cfg.users[1].password_sha256);
        assert_eq!(cfg.users[0].password_sha256.len(), 32);
        assert!(cfg.allow_insecure);
        assert_eq!(cfg.addresses.len(), 1);
        assert_eq!(cfg.addresses[0].listen, "127.0.0.1");
    }

    #[test]
    fn anytls_users_empty_is_reject_all_not_an_error() {
        // Upstream's `userMap` empty state: the listener still serves
        // and every authentication fails — warn-only at build.
        let listeners = anytls_named(ANYTLS_INSECURE).unwrap();
        let ListenerSpec::Anytls(cfg) = &listeners[0].spec else {
            panic!("expected anytls spec");
        };
        assert!(cfg.users.is_empty());
    }

    #[test]
    fn anytls_users_empty_name_and_password_error() {
        let err = anytls_named_err(&format!("    users: {{\"\": x}}\n{ANYTLS_INSECURE}"));
        assert!(err.contains("empty username"), "{err}");
        let err = anytls_named_err(&format!("    users: {{a: \"\"}}\n{ANYTLS_INSECURE}"));
        assert!(err.contains("empty password"), "{err}");
    }

    #[test]
    fn anytls_users_duplicate_name_and_password_error() {
        // serde-saphyr's duplicate-key policy rejects a repeated
        // `users:` key at parse time, before the builder runs.
        let err = crate::parse_raw_yaml(
            "listeners:\n  - name: a\n    type: anytls\n    port: 0\n    allow-insecure: true\n    users:\n      alice: one\n      alice: two\n",
        )
        .map(|_: raw::RawConfig| "PARSED".to_string())
        .unwrap_err()
        .to_string();
        assert!(err.contains("alice"), "{err}");

        let err = anytls_named_err(&format!(
            "    users: {{alice: same, bob: same}}\n{ANYTLS_INSECURE}"
        ));
        assert!(err.contains("distinct passwords"), "{err}");
    }

    #[test]
    fn anytls_users_nonstring_password_is_parse_error() {
        assert!(crate::parse_raw_yaml(
            "listeners:\n  - name: a\n    type: anytls\n    port: 0\n    users: {a: 5}\n"
        )
        .is_err());
    }

    #[test]
    fn anytls_security_mode_matrix() {
        // Nothing at all → hard error naming both escapes.
        let err = anytls_named_err(ANYTLS_USERS);
        assert!(err.contains("certificate"), "{err}");
        assert!(err.contains("allow-insecure"), "{err}");

        // Full pair → TLS; `allow-insecure` is not counted into the
        // mode exclusivity (upstream's TLS-layer enumeration).
        let listeners =
            anytls_named(&format!("{ANYTLS_USERS}{ANYTLS_CERT}{ANYTLS_INSECURE}")).unwrap();
        let ListenerSpec::Anytls(cfg) = &listeners[0].spec else {
            panic!("expected anytls spec");
        };
        assert!(cfg.certificate.is_some() && cfg.private_key.is_some());

        // Half pairs → hard error either way.
        let err = anytls_named_err(
            "    users: {a: x}\n    certificate: \"-----BEGIN CERTIFICATE-----\\nM\\n-----END CERTIFICATE-----\"\n",
        );
        assert!(err.contains("provided together"), "{err}");
        let err = anytls_named_err(
            "    users: {a: x}\n    private-key: \"-----BEGIN PRIVATE KEY-----\\nM\\n-----END PRIVATE KEY-----\"\n",
        );
        assert!(err.contains("provided together"), "{err}");

        // PEM literal in one half, path in the other → mixed forms.
        let err = anytls_named_err(
            "    users: {a: x}\n    certificate: /etc/cert.pem\n    private-key: \"-----BEGIN PRIVATE KEY-----\\nM\\n-----END PRIVATE KEY-----\"\n",
        );
        assert!(err.contains("same"), "{err}");
    }

    #[test]
    fn anytls_mtls_and_ech_hard_error_only_when_non_empty() {
        for key in ["client-auth-type", "client-auth-cert", "ech-key"] {
            let err = anytls_named_err(&format!("{ANYTLS_USERS}{ANYTLS_CERT}    {key}: present\n"));
            assert!(err.contains(key), "{err}");
            assert!(err.contains("not supported"), "{err}");
        }
        // Emptiness is judged on the RAW value (spec §2.1): a
        // whitespace-only request is still a request meow cannot honour.
        let err = anytls_named_err(&format!(
            "{ANYTLS_USERS}{ANYTLS_CERT}    client-auth-type: \"  \"\n"
        ));
        assert!(err.contains("client-auth-type"), "{err}");
        // Literal "" IS the empty case — the build passes.
        anytls_named(&format!("{ANYTLS_USERS}{ANYTLS_CERT}    ech-key: \"\"\n")).unwrap();
    }

    #[test]
    fn anytls_front_layers_enabled_error_disabled_warn() {
        // Enabled front layer alone → exclusivity gate, then the
        // unsupported-layer hard error.
        for key in ["shadow-tls", "res-tls", "jls-config"] {
            let err = anytls_named_err(&format!(
                "{ANYTLS_USERS}{ANYTLS_CERT}    {key}: {{enable: true}}\n"
            ));
            assert!(err.contains("at most one"), "{err}");
            let err = anytls_named_err(&format!("{ANYTLS_USERS}    {key}: {{enable: true}}\n"));
            assert!(err.contains("not supported"), "{err}");
            // Disabled → warn-ignore, TLS still required.
            anytls_named(&format!(
                "{ANYTLS_USERS}{ANYTLS_CERT}    {key}: {{enable: false}}\n"
            ))
            .unwrap();
            // Non-mapping shape errors.
            let err = anytls_named_err(&format!("{ANYTLS_USERS}{ANYTLS_CERT}    {key}: 5\n"));
            assert!(err.contains("mapping"), "{err}");
        }
    }

    #[test]
    fn anytls_enable_and_udp_flags() {
        let err = anytls_named_err(&format!(
            "{ANYTLS_USERS}{ANYTLS_INSECURE}    enable: false\n"
        ));
        assert!(err.contains("enable"), "{err}");
        let err = anytls_named_err(&format!("{ANYTLS_USERS}{ANYTLS_INSECURE}    udp: false\n"));
        assert!(err.contains("udp"), "{err}");
        // `true` spellings pass with a redundancy warn.
        anytls_named(&format!(
            "{ANYTLS_USERS}{ANYTLS_INSECURE}    enable: true\n    udp: true\n"
        ))
        .unwrap();
    }

    #[test]
    fn anytls_padding_scheme_validated_by_shared_contract() {
        let listeners = anytls_named(&format!(
            "{ANYTLS_USERS}{ANYTLS_INSECURE}    padding-scheme: \"stop=9\\n0=30-30\"\n"
        ))
        .unwrap();
        let ListenerSpec::Anytls(cfg) = &listeners[0].spec else {
            panic!("expected anytls spec");
        };
        assert_eq!(cfg.padding_scheme.as_deref(), Some("stop=9\n0=30-30"));

        for bad in ["stop=abc", "0=30-30", "stop=1\\n0=0-30"] {
            let err = anytls_named_err(&format!(
                "{ANYTLS_USERS}{ANYTLS_INSECURE}    padding-scheme: \"{bad}\"\n"
            ));
            assert!(err.contains("padding-scheme"), "{err}");
        }
    }

    #[test]
    fn anytls_multi_address_listen_and_port_registry() {
        // Comma-separated `listen` — each segment resolves with the
        // entry's `port` like a single address does.
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: a\n    type: anytls\n    port: 1080\n    allow-insecure: true\n    users: {a: x}\n    listen: \"127.0.0.1,::1\"\n",
        )
        .unwrap();
        let listeners = build_named_listeners(&raw, "127.0.0.1", false).unwrap();
        let ListenerSpec::Anytls(cfg) = &listeners[0].spec else {
            panic!("expected anytls spec");
        };
        assert_eq!(cfg.addresses.len(), 2);
        assert_eq!(cfg.addresses[0].listen, "127.0.0.1");
        assert_eq!(cfg.addresses[1].listen, "::1");
        assert!(cfg.addresses.iter().all(|a| a.port == 1080));
        // NamedListener keeps the first address as its endpoint pair.
        assert_eq!(listeners[0].listen, "127.0.0.1");
        assert_eq!(listeners[0].port, 1080);

        // Different ports per segment need `port` unset — a segment's
        // explicit `listen:port` merges exactly like the single-address
        // case, and a mismatching entry `port` is a conflict error.
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: a\n    type: anytls\n    port: 0\n    allow-insecure: true\n    users: {a: x}\n    listen: \"127.0.0.1:2080,0.0.0.0:3080\"\n",
        )
        .unwrap();
        let listeners = build_named_listeners(&raw, "127.0.0.1", false).unwrap();
        let ListenerSpec::Anytls(cfg) = &listeners[0].spec else {
            panic!("expected anytls spec");
        };
        assert_eq!(cfg.addresses[0].port, 2080);
        assert_eq!(cfg.addresses[1].port, 3080);

        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: a\n    type: anytls\n    port: 1080\n    allow-insecure: true\n    users: {a: x}\n    listen: \"127.0.0.1:2080\"\n",
        )
        .unwrap();
        let err = build_named_listeners(&raw, "127.0.0.1", false)
            .map(|l| format!("BUILT {l:?}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("conflicts with port"), "{err}");

        // A secondary address's port joins the duplicate-port registry:
        // another listener on it must conflict like the primary does.
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: a\n    type: anytls\n    port: 0\n    allow-insecure: true\n    users: {a: x}\n    listen: \"127.0.0.1:2080,0.0.0.0:3080\"\n  - name: m\n    type: mixed\n    port: 3080\n",
        )
        .unwrap();
        let err = build_named_listeners(&raw, "127.0.0.1", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("3080"), "{err}");

        // An empty segment between commas is a shape error.
        let err = anytls_named_err(&format!(
            "{ANYTLS_USERS}{ANYTLS_INSECURE}    listen: \"127.0.0.1:1,,0.0.0.0:2\"\n"
        ));
        assert!(err.contains("empty address"), "{err}");
    }

    #[test]
    fn anytls_foreign_keys_and_type_name() {
        assert_eq!(
            anytls_named(&format!("{ANYTLS_USERS}{ANYTLS_INSECURE}")).unwrap()[0]
                .spec
                .type_name(),
            "anytls"
        );
        // `users:`/`certificate:` on a non-anytls type warn, not error.
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: m\n    type: mixed\n    port: 0\n    users: {a: x}\n    allow-insecure: true\n    enable: true\n",
        )
        .unwrap();
        build_named_listeners(&raw, "127.0.0.1", false).unwrap();
        // `cipher:`/`kcp-tun:` on anytls warn, not error.
        anytls_named(&format!(
            "{ANYTLS_USERS}{ANYTLS_INSECURE}    cipher: aes-256-gcm\n    kcp-tun: {{}}\n"
        ))
        .unwrap();
    }

    // ── `type: vless` listener spec ──────────────────────────────────
    //
    // The vision-inbound spec's config matrix: users list shape and
    // strictness, the TLS/REALITY security-mode union, deferred-key and
    // unknown-key rejection, ALPN, `decryption`, multi-address `listen`
    // and the static REALITY self-loop gate.

    const VLESS_USER_A: &str =
        "      - username: alice\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n";
    const VLESS_CERT: &str =
        "    certificate: \"-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\"\n    private-key: \"-----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----\"\n";
    // RFC 7748 Alice scalar — a real X25519 private key, unpadded
    // URL-safe base64 exactly as `xray x25519` prints it.
    const REALITY_KEY: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo";
    const REALITY_BLOCK: &str = "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo\"\n      short-id: [\"0123456789abcdef\"]\n      server-names: [\"example.com\"]\n";

    fn vless_yaml(extra: &str) -> String {
        format!("listeners:\n  - name: v\n    type: vless\n    port: 0\n{extra}")
    }

    fn vless_named(extra: &str) -> Result<Vec<NamedListener>, anyhow::Error> {
        let raw: raw::RawConfig = crate::parse_raw_yaml(&vless_yaml(extra))?;
        build_named_listeners(&raw, "127.0.0.1", false)
    }

    fn vless_named_err(extra: &str) -> String {
        vless_named(extra)
            .map(|l| format!("BUILT {l:?}"))
            .unwrap_err()
            .to_string()
    }

    fn vless_tls_yaml() -> String {
        format!("{VLESS_CERT}    users:\n{VLESS_USER_A}")
    }

    fn vless_reality_yaml() -> String {
        format!("{REALITY_BLOCK}    users:\n{VLESS_USER_A}")
    }

    #[test]
    fn vless_users_and_security_happy_paths() {
        // Standard TLS mode.
        let listeners = vless_named(&vless_tls_yaml()).unwrap();
        let ListenerSpec::Vless(cfg) = &listeners[0].spec else {
            panic!("expected vless spec");
        };
        assert_eq!(cfg.users.len(), 1);
        assert_eq!(cfg.users[0].username, "alice");
        assert_ne!(cfg.users[0].uuid, [0u8; 16]);
        assert!(cfg.udp, "udp defaults to true");
        assert_eq!(cfg.addresses.len(), 1);
        let VlessSecurity::StandardTls {
            certificate, alpn, ..
        } = &cfg.security
        else {
            panic!("expected standard TLS mode");
        };
        assert!(certificate.contains("BEGIN CERTIFICATE"));
        assert!(alpn.is_empty(), "alpn defaults to empty");

        // REALITY mode — defaults filled.
        let listeners = vless_named(&vless_reality_yaml()).unwrap();
        let ListenerSpec::Vless(cfg) = &listeners[0].spec else {
            panic!("expected vless spec");
        };
        let VlessSecurity::Reality(rc) = &cfg.security else {
            panic!("expected REALITY mode");
        };
        assert_eq!(rc.dest, "www.example.com:443");
        assert_eq!(rc.short_ids.len(), 1);
        assert_eq!(rc.short_ids[0], {
            let mut id = [0u8; 8];
            id[..8].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
            id
        });
        assert_eq!(rc.server_names, ["example.com"]);
        assert_eq!(rc.max_time_difference_us, 120_000_000);
        assert_eq!(rc.limit_fallback_upload, RealityLimitFallback::default());

        // `type_name` and the named-listener endpoint pair.
        assert_eq!(listeners[0].spec.type_name(), "vless");
        assert_eq!(listeners[0].listen, "127.0.0.1");
    }

    #[test]
    fn vless_no_plaintext_and_mode_exclusivity() {
        // Neither TLS nor REALITY → hard error naming both escapes.
        let err = vless_named_err(&format!("    users:\n{VLESS_USER_A}"));
        assert!(err.contains("no plaintext mode"), "{err}");
        assert!(err.contains("certificate"), "{err}");
        assert!(err.contains("reality-config"), "{err}");

        // REALITY + any flat certificate field → hard error, even a half pair.
        let err = vless_named_err(&format!(
            "{REALITY_BLOCK}    certificate: \"-----BEGIN CERTIFICATE-----\\nM\\n-----END CERTIFICATE-----\"\n    users:\n{VLESS_USER_A}"
        ));
        assert!(err.contains("mutually exclusive"), "{err}");

        // Half pairs alone → hard error.
        let err = vless_named_err(&format!(
            "    certificate: \"-----BEGIN CERTIFICATE-----\\nM\\n-----END CERTIFICATE-----\"\n    users:\n{VLESS_USER_A}"
        ));
        assert!(err.contains("provided together"), "{err}");

        // Mixed PEM/path forms → hard error.
        let err = vless_named_err(&format!(
            "    certificate: /etc/cert.pem\n    private-key: \"-----BEGIN PRIVATE KEY-----\\nM\\n-----END PRIVATE KEY-----\"\n    users:\n{VLESS_USER_A}"
        ));
        assert!(err.contains("same"), "{err}");

        // `allow-insecure: true` is never a plaintext escape — even with TLS.
        let err = vless_named_err(&format!(
            "{VLESS_CERT}    allow-insecure: true\n    users:\n{VLESS_USER_A}"
        ));
        assert!(err.contains("allow-insecure"), "{err}");
        assert!(err.contains("no plaintext"), "{err}");
        // …but `false` is accepted as the explicit default.
        vless_named(&format!(
            "{VLESS_CERT}    allow-insecure: false\n    users:\n{VLESS_USER_A}"
        ))
        .unwrap();

        // mTLS / ECH non-empty values hard-error; empty strings pass.
        for key in ["client-auth-type", "client-auth-cert", "ech-key"] {
            let err = vless_named_err(&format!(
                "{VLESS_CERT}    {key}: present\n    users:\n{VLESS_USER_A}"
            ));
            assert!(err.contains(key), "{err}");
        }
        vless_named(&format!(
            "{VLESS_CERT}    ech-key: \"\"\n    users:\n{VLESS_USER_A}"
        ))
        .unwrap();
    }

    #[test]
    fn vless_users_strictness_matrix() {
        let base = VLESS_CERT;
        // Absent users / empty list → hard error.
        let err = vless_named_err(VLESS_CERT);
        assert!(err.contains("users"), "{err}");
        let err = vless_named_err(&format!("{base}    users: []\n"));
        assert!(err.contains("must not be empty"), "{err}");
        // The anytls mapping shape on vless → hard error with the hint.
        let err = vless_named_err(&format!("{base}    users: {{alice: pw}}\n"));
        assert!(err.contains("LIST"), "{err}");

        // Missing fields.
        let err = vless_named_err(&format!(
            "{base}    users:\n      - uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n"
        ));
        assert!(err.contains("username"), "{err}");
        let err = vless_named_err(&format!(
            "{base}    users:\n      - username: a\n        flow: xtls-rprx-vision\n"
        ));
        assert!(err.contains("uuid"), "{err}");
        let err = vless_named_err(&format!(
            "{base}    users:\n      - username: a\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n"
        ));
        assert!(err.contains("flow"), "{err}");

        // Unknown user sub-key → hard error.
        let err = vless_named_err(&format!(
            "{base}    users:\n      - username: a\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n        email: x@y\n"
        ));
        assert!(err.contains("unknown key"), "{err}");

        // Duplicate username / duplicate normalized UUID (dashed vs bare).
        let dup = format!("{base}    users:\n{VLESS_USER_A}{VLESS_USER_A}");
        let err = vless_named_err(&dup);
        assert!(err.contains("duplicates an earlier entry"), "{err}");
        let err = vless_named_err(&format!(
            "{base}    users:\n      - username: a\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n      - username: b\n        uuid: \"71884BD4D6A04E1998953E1D8B469317\"\n        flow: xtls-rprx-vision\n"
        ));
        assert!(err.contains("duplicates an earlier user"), "{err}");

        // UUID strictness: bare 32-hex accepted; all-zero rejected;
        // misplaced hyphens / bad chars / wrong length rejected.
        vless_named(&format!(
            "{base}    users:\n      - username: a\n        uuid: \"71884bd4d6a04e1998953e1d8b469317\"\n        flow: xtls-rprx-vision\n"
        ))
        .unwrap();
        for bad in [
            "00000000-0000-0000-0000-000000000000",
            "71884bd4-d6a04-e19-9895-3e1d8b469317",
            "71884bd4-d6a0-4e19-9895-3e1d8b46931",
            "zz884bd4-d6a0-4e19-9895-3e1d8b469317",
        ] {
            let err = vless_named_err(&format!(
                "{base}    users:\n      - username: a\n        uuid: \"{bad}\"\n        flow: xtls-rprx-vision\n"
            ));
            assert!(err.contains("uuid"), "{err} for {bad}");
        }

        // Flow strictness: only the literal; the udp443 suffix and other
        // flows are rejected with their explanations.
        let err = vless_named_err(&format!(
            "{base}    users:\n      - username: a\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision-udp443\n"
        ));
        assert!(err.contains("client-local"), "{err}");
        let err = vless_named_err(&format!(
            "{base}    users:\n      - username: a\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: \"\"\n"
        ));
        assert!(err.contains("empty flow"), "{err}");
        let err = vless_named_err(&format!(
            "{base}    users:\n      - username: a\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-direct\n"
        ));
        assert!(err.contains("xtls-rprx-vision"), "{err}");
    }

    #[test]
    fn vless_decryption_and_deferred_keys() {
        let users = format!("    users:\n{VLESS_USER_A}");
        // decryption absent/""/none pass; anything else errors.
        vless_named(&format!("{VLESS_CERT}{users}    decryption: none\n")).unwrap();
        vless_named(&format!("{VLESS_CERT}{users}    decryption: \"\"\n")).unwrap();
        let secret = "xray_inbound_private_key_9f8e7d6c5b4a";
        let err = vless_named_err(&format!("{VLESS_CERT}{users}    decryption: {secret}\n"));
        assert!(err.contains("decryption"), "{err}");
        assert!(err.contains("`none`"), "{err}");
        assert!(
            !err.contains(secret),
            "decryption value leaked into the config error: {err}"
        );

        // `encryption` (outbound key) errors with the decryption hint.
        let err = vless_named_err(&format!("{VLESS_CERT}{users}    encryption: none\n"));
        assert!(err.contains("decryption"), "{err}");

        // Deferred upstream keys hard-error even as empty maps.
        for key in ["shadow-tls", "res-tls", "jls-config", "mux-option"] {
            let err = vless_named_err(&format!("{VLESS_CERT}{users}    {key}: {{}}\n"));
            assert!(err.contains(key), "{err}");
            let err = vless_named_err(&format!(
                "{VLESS_CERT}{users}    {key}: {{enable: false}}\n"
            ));
            assert!(err.contains("native TCP"), "{err}");
        }
        for key in ["ws-path", "xhttp-config", "grpc-service-name"] {
            let err = vless_named_err(&format!("{VLESS_CERT}{users}    {key}: x\n"));
            assert!(err.contains("native TCP"), "{err}");
        }

        // Migration-hint keys: tls/certificates/fallback/network/flow/reality-opts.
        for (key, hint) in [
            ("tls", "flat `certificate`"),
            ("fallback", "no fallback"),
            ("network", "native TCP"),
            ("flow", "per-user"),
            ("reality-opts", "reality-config"),
        ] {
            let err = vless_named_err(&format!("{VLESS_CERT}{users}    {key}: true\n"));
            assert!(err.contains(hint), "{err} for {key}");
        }

        // Truly unknown keys hard-error — no silent ignore on this inbound.
        let err = vless_named_err(&format!("{VLESS_CERT}{users}    obfs: tls\n"));
        assert!(err.contains("unknown key"), "{err}");
    }

    #[test]
    fn vless_alpn_rules() {
        let users = format!("    users:\n{VLESS_USER_A}");
        // Valid list under standard TLS.
        let listeners = vless_named(&format!(
            "{VLESS_CERT}{users}    alpn: [h2, \"http/1.1\"]\n"
        ))
        .unwrap();
        let ListenerSpec::Vless(cfg) = &listeners[0].spec else {
            panic!("expected vless spec");
        };
        let VlessSecurity::StandardTls { alpn, .. } = &cfg.security else {
            panic!("expected standard TLS");
        };
        assert_eq!(alpn, &["h2", "http/1.1"]);

        // Shape violations.
        for (alpn_yaml, hint) in [
            ("    alpn: h2\n", "list"),
            ("    alpn: [\"\"]\n", "empty"),
            ("    alpn: [h2, h2]\n", "duplicates"),
            ("    alpn: [5]\n", "string"),
            ("    alpn: [\"h2é\"]\n", "printable ASCII"),
        ] {
            let err = vless_named_err(&format!("{VLESS_CERT}{users}{alpn_yaml}"));
            assert!(err.contains(hint), "{err} for {alpn_yaml}");
        }
        // Over 16 entries.
        let many = (0..17)
            .map(|i| format!("p{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let err = vless_named_err(&format!("{VLESS_CERT}{users}    alpn: [{many}]\n"));
        assert!(err.contains("16"), "{err}");

        // Non-empty ALPN under REALITY errors; empty passes.
        let err = vless_named_err(&format!("{REALITY_BLOCK}{users}    alpn: [h2]\n"));
        assert!(err.contains("REALITY"), "{err}");
        vless_named(&format!("{REALITY_BLOCK}{users}    alpn: []\n")).unwrap();
    }

    #[test]
    fn vless_reality_config_matrix() {
        let users = format!("    users:\n{VLESS_USER_A}");
        // Empty map → hard error.
        let err = vless_named_err(&format!("    reality-config: {{}}\n{users}"));
        assert!(err.contains("empty map"), "{err}");
        // Non-map shape → hard error.
        let err = vless_named_err(&format!("    reality-config: 5\n{users}"));
        assert!(err.contains("mapping"), "{err}");

        // Missing required keys.
        for missing in ["dest", "private-key", "short-id", "server-names"] {
            let block = format!(
                "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n"
            );
            // Remove the line for `missing`.
            let block: String = block
                .lines()
                .filter(|l| !l.trim_start().starts_with(&format!("{missing}:")))
                .map(|l| format!("{l}\n"))
                .collect();
            let err = vless_named_err(&format!("{block}{users}"));
            assert!(err.contains(missing), "{err} for missing {missing}");
        }

        // `target` errors with the dest migration hint; xver/minClientVer
        // and nested proxy are explicit rejections.
        let err = vless_named_err(&format!(
            "    reality-config:\n      target: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n{users}"
        ));
        assert!(err.contains("dest"), "{err}");
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n      xver: 1\n{users}"
        ));
        assert!(err.contains("xver"), "{err}");
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n      proxy: out\n{users}"
        ));
        assert!(err.contains("proxy"), "{err}");

        // dest shape matrix.
        for (dest, hint) in [
            ("www.example.com", "missing `:port`"),
            ("www.example.com:0", "port 0"),
            ("www.example.com:99999", "1..=65535"),
            ("https://www.example.com:443", "URL"),
            ("::1:443", "bracketed"),
            ("[::1", "close"),
        ] {
            let err = vless_named_err(&format!(
                "    reality-config:\n      dest: \"{dest}\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n{users}"
            ));
            assert!(err.contains(hint), "{err} for dest {dest}");
        }
        // Bracketed IPv6 passes shape validation.
        vless_named(&format!(
            "    reality-config:\n      dest: \"[2001:db8::1]:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n{users}"
        ))
        .unwrap();

        // private-key shape: padded/base64-standard/short all rejected.
        for bad in [
            "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", // padded
            "MDEyMzQ1Njc4OTAxMjM0NQ",                       // 16 bytes
            "not base64!!!",
        ] {
            let err = vless_named_err(&format!(
                "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{bad}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n{users}"
            ));
            assert!(err.contains("private-key"), "{err} for key {bad}");
        }

        // short-id matrix: odd length, >16 chars, non-hex, empty,
        // all-zero, padded-duplicate all rejected.
        for (id, hint) in [
            ("abc", "even"),
            ("0123456789abcdef00", "at most 16"),
            ("zz", "hex"),
        ] {
            let err = vless_named_err(&format!(
                "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"{id}\"]\n      server-names: [\"example.com\"]\n{users}"
            ));
            assert!(err.contains(hint), "{err} for short-id {id}");
        }
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"\"]\n      server-names: [\"example.com\"]\n{users}"
        ));
        assert!(err.contains("empty string"), "{err}");
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"00\"]\n      server-names: [\"example.com\"]\n{users}"
        ));
        assert!(err.contains("all-zero"), "{err}");
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\", \"ab00\"]\n      server-names: [\"example.com\"]\n{users}"
        ));
        assert!(err.contains("zero-padding"), "{err}");

        // server-names matrix: wildcard, IP, trailing dot, uppercase
        // duplicate, non-ASCII all rejected.
        for (name, hint) in [
            ("*.example.com", "wildcards"),
            ("1.2.3.4", "IP literals"),
            ("example.com.", "trailing"),
            ("-bad.com", "hyphen"),
        ] {
            let err = vless_named_err(&format!(
                "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"{name}\"]\n{users}"
            ));
            assert!(err.contains(hint), "{err} for server-name {name}");
        }
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\", \"EXAMPLE.com\"]\n{users}"
        ));
        assert!(err.contains("duplicates"), "{err}");

        // max-time-difference: negative/float rejected, 0 disables,
        // large values accepted.
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n      max-time-difference: -5\n{users}"
        ));
        assert!(err.contains("non-negative integer"), "{err}");
        let listeners = vless_named(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n      max-time-difference: 0\n{users}"
        ))
        .unwrap();
        let ListenerSpec::Vless(cfg) = &listeners[0].spec else {
            panic!("expected vless spec");
        };
        let VlessSecurity::Reality(rc) = &cfg.security else {
            panic!("expected REALITY");
        };
        assert_eq!(rc.max_time_difference_us, 0);

        // limit-fallback sub-keys validate; unknown sub-key errors.
        let listeners = vless_named(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n      limit-fallback-upload:\n        after-bytes: 1024\n        bytes-per-sec: 512\n      limit-fallback-download: {{}}\n{users}"
        ))
        .unwrap();
        let ListenerSpec::Vless(cfg) = &listeners[0].spec else {
            panic!("expected vless spec");
        };
        let VlessSecurity::Reality(rc) = &cfg.security else {
            panic!("expected REALITY");
        };
        assert_eq!(rc.limit_fallback_upload.after_bytes, 1024);
        assert_eq!(rc.limit_fallback_upload.bytes_per_sec, 512);
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n      limit-fallback-upload: {{rate: 5}}\n{users}"
        ));
        assert!(err.contains("unknown key"), "{err}");
    }

    #[test]
    fn vless_reality_runtime_cardinality_is_config_shape() {
        let users = format!("    users:\n{VLESS_USER_A}");
        // 64 legal entries pass; the 65th is a hard error even though every
        // item is individually valid.
        let ids64 = (1..=64)
            .map(|i| format!("\"{i:02x}\""))
            .collect::<Vec<_>>()
            .join(", ");
        vless_named(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [{ids64}]\n      server-names: [\"example.com\"]\n{users}"
        ))
        .unwrap();
        let ids65 = (1..=65)
            .map(|i| format!("\"{i:02x}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [{ids65}]\n      server-names: [\"example.com\"]\n{users}"
        ));
        assert!(err.contains("short-id"), "{err}");
        assert!(err.contains("64"), "{err}");

        let names65 = (1..=65)
            .map(|i| format!("\"n{i}.example.com\""))
            .collect::<Vec<_>>()
            .join(", ");
        let err = vless_named_err(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [{names65}]\n{users}"
        ));
        assert!(err.contains("server-names"), "{err}");
        assert!(err.contains("64"), "{err}");
    }

    #[test]
    fn vless_reality_nonfinite_numbers_never_become_null_defaults() {
        let users = format!("    users:\n{VLESS_USER_A}");
        for block in [
            "      max-time-difference: .nan\n",
            "      max-time-difference: .inf\n",
            "      max-time-difference: 1e999\n",
            "      limit-fallback-upload: .nan\n",
            "      limit-fallback-download: .inf\n",
        ] {
            let err = vless_named_err(&format!(
                "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n{block}{users}"
            ));
            assert!(err.contains("non-finite"), "{err} for {block}");
        }

        // Explicit null remains the documented absent-equivalent spelling.
        let listeners = vless_named(&format!(
            "    reality-config:\n      dest: \"www.example.com:443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n      max-time-difference: null\n      limit-fallback-upload: null\n{users}"
        ))
        .unwrap();
        let ListenerSpec::Vless(cfg) = &listeners[0].spec else {
            panic!("expected vless spec");
        };
        let VlessSecurity::Reality(rc) = &cfg.security else {
            panic!("expected REALITY");
        };
        assert_eq!(rc.max_time_difference_us, 120_000_000);
        assert_eq!(rc.limit_fallback_upload, RealityLimitFallback::default());
    }

    #[test]
    fn vless_reality_self_loop_static_gate() {
        let users = format!("    users:\n{VLESS_USER_A}");
        // dest at the listener's own bind (exact loopback match).
        let err = vless_named_err(&format!(
            "    listen: \"127.0.0.1:8443\"\n    reality-config:\n      dest: \"127.0.0.1:8443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n{users}"
        ));
        assert!(err.contains("self"), "{err}");
        // Wildcard bind + loopback dest at the same port.
        let err = vless_named_err(&format!(
            "    listen: \"0.0.0.0:8443\"\n    reality-config:\n      dest: \"127.0.0.1:8443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n{users}"
        ));
        assert!(err.contains("cover"), "{err}");
        // Different port → not a loop, passes.
        vless_named(&format!(
            "    listen: \"127.0.0.1:8443\"\n    reality-config:\n      dest: \"127.0.0.1:9443\"\n      private-key: \"{REALITY_KEY}\"\n      short-id: [\"ab\"]\n      server-names: [\"example.com\"]\n{users}"
        ))
        .unwrap();
        // Domain dest never triggers the static gate (runtime's job).
        vless_named(&vless_reality_yaml()).unwrap();
    }

    #[test]
    fn vless_multi_address_and_foreign_keys() {
        // Comma-separated listen shares the AnyTLS resolution contract in
        // order and keeps canonical IPv6 spellings distinct only when they
        // really are distinct addresses.
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: v\n    type: vless\n    port: 1080\n    listen: \"127.0.0.1,::1\"\n    certificate: \"-----BEGIN CERTIFICATE-----\\nM\\n-----END CERTIFICATE-----\"\n    private-key: \"-----BEGIN PRIVATE KEY-----\\nM\\n-----END PRIVATE KEY-----\"\n    users:\n      - username: a\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n",
        )
        .unwrap();
        let listeners = build_named_listeners(&raw, "127.0.0.1", false).unwrap();
        let ListenerSpec::Vless(cfg) = &listeners[0].spec else {
            panic!("expected vless spec");
        };
        assert_eq!(cfg.addresses.len(), 2);
        assert_eq!(cfg.addresses[0].listen, "127.0.0.1");
        assert_eq!(cfg.addresses[1].listen, "::1");
        assert!(cfg.addresses.iter().all(|a| a.port == 1080));

        let err = vless_named_err(&format!(
            "{VLESS_CERT}    listen: \"::1,0:0:0:0:0:0:0:1\"\n    users:\n{VLESS_USER_A}"
        ));
        assert!(err.contains("duplicate bind address"), "{err}");
        let err = vless_named_err(&format!(
            "{VLESS_CERT}    listen: \"127.0.0.1:1,,0.0.0.0:2\"\n    users:\n{VLESS_USER_A}"
        ));
        assert!(err.contains("empty address"), "{err}");

        // Comma-separated listen like anytls; ports join the registry.
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: v\n    type: vless\n    port: 1080\n    listen: \"127.0.0.1,::1\"\n    certificate: \"-----BEGIN CERTIFICATE-----\\nM\\n-----END CERTIFICATE-----\"\n    private-key: \"-----BEGIN PRIVATE KEY-----\\nM\\n-----END PRIVATE KEY-----\"\n    users:\n      - username: a\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n  - name: m\n    type: mixed\n    port: 1080\n",
        )
        .unwrap();
        let err = build_named_listeners(&raw, "127.0.0.1", false)
            .map(|l| format!("BUILT {l:?}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("1080"), "{err}");

        // `udp: false` is stored (XUDP gate); default stays true.
        let listeners = vless_named(&format!(
            "{VLESS_CERT}    udp: false\n    users:\n{VLESS_USER_A}"
        ))
        .unwrap();
        let ListenerSpec::Vless(cfg) = &listeners[0].spec else {
            panic!("expected vless spec");
        };
        assert!(!cfg.udp);

        // Schema-known foreign keys warn-and-ignore instead of erroring.
        vless_named(&format!(
            "{VLESS_CERT}    cipher: aes-256-gcm\n    mtu: 1400\n    users:\n{VLESS_USER_A}"
        ))
        .unwrap();

        // vless keys on a non-vless listener warn, not error.
        let raw: raw::RawConfig = crate::parse_raw_yaml(
            "listeners:\n  - name: m\n    type: mixed\n    port: 0\n    decryption: none\n    alpn: [h2]\n    reality-config: {}\n",
        )
        .unwrap();
        build_named_listeners(&raw, "127.0.0.1", false).unwrap();
    }

    #[test]
    fn vless_users_roundtrip_and_redaction() {
        // The typed spec round-trips through serde with credentials intact
        // (persistence), while Debug redacts them (diagnostics).
        let redaction_yaml = vless_reality_yaml()
            .replace("www.example.com:443", "cover-target.invalid:443")
            .replace("\"example.com\"", "\"sni-hidden.invalid\"");
        let listeners = vless_named(&redaction_yaml).unwrap();
        let spec = listeners[0].spec.clone();
        let json = serde_json::to_string(&spec).unwrap();
        let back: ListenerSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);

        let debug = format!("{:?}", listeners[0].spec);
        assert!(
            !debug.contains("71884bd4"),
            "uuid leaked into Debug: {debug}"
        );
        assert!(
            !debug.contains("dwdtCnMY"),
            "private key leaked into Debug: {debug}"
        );
        assert!(
            !debug.contains("0123456789abcdef"),
            "short-id leaked into Debug: {debug}"
        );
        assert!(debug.contains("REDACTED"), "{debug}");
        for leaked in [
            "alice",
            "cover-target.invalid",
            "cover-target.invalid:443",
            "sni-hidden.invalid",
        ] {
            assert!(
                !debug.contains(leaked),
                "{leaked:?} leaked into Debug: {debug}"
            );
        }

        let tls_listeners = vless_named(&vless_tls_yaml()).unwrap();
        let tls_debug = format!("{:?}", tls_listeners[0].spec);
        for leaked in [
            "alice",
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----",
        ] {
            assert!(
                !tls_debug.contains(leaked),
                "{leaked:?} leaked into standard-TLS Debug: {tls_debug}"
            );
        }
    }

    #[test]
    fn strict_uuid_errors_never_echo_the_candidate() {
        for candidate in [
            "71884bd4d6a0-4e19-9895-3e1d8b469317-",
            "71884bd4-d6a04e19-9895-3e1d8b469317",
            "71884bd4-d6a0-4e19-9895-3e1d8b46931",
        ] {
            let err = parse_strict_uuid(candidate).unwrap_err();
            assert!(
                !err.contains(candidate),
                "uuid candidate leaked into parse error: {err}"
            );
        }
    }
}
