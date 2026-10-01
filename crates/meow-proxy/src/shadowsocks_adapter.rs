use crate::dialer::UdpTarget;
#[cfg(feature = "ech-tls-tunnel")]
use crate::ech_tls_tunnel::{self, EchTlsTunnelConfig};
use crate::gost_plugin;
use crate::jls_plugin;
#[cfg(feature = "kcptun")]
use crate::kcptun_plugin;
use crate::restls_plugin;
use crate::shadow_tls_plugin;
use crate::v2ray_plugin::{self, V2rayPluginConfig};
use async_trait::async_trait;
use meow_common::atomic::{checked_increment, AtomicU};
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_transport::simple_obfs::client::{HttpObfs, TlsObfs};
use meow_transport::tls::TlsLayer;
use shadowsocks::config::{Mode, ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::plugin::{Plugin, PluginConfig, PluginMode};
use shadowsocks::relay::udprelay::crypto_io::{decrypt_server_payload, encrypt_client_payload};
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket, ProxySocket};
use shadowsocks::relay::Address;
use shadowsocks::ProxyClientStream;
use smol_str::SmolStr;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;
use tracing::{debug, warn};

/// Built-in (native, no external process) simple-obfs configuration.
#[derive(Debug, Clone)]
pub enum BuiltinObfs {
    /// HTTP simple-obfs with the configured fake `Host` header.
    Http { host: String },
    /// TLS simple-obfs with the configured fake SNI server name.
    Tls { server: String },
}

/// Which plugin (if any) the adapter uses when dialing outbound.
///
/// Layered on top of the SS cipher stream:
/// * `None` — direct TCP to `server:port`.
/// * `External` — SIP003 subprocess (e.g. `obfs-local` via shadowsocks-rust's
///   `Plugin::start`); `server_config` is rewritten to point at the local
///   listener the subprocess exposes.
/// * `Obfs` — native simple-obfs codec wraps the TCP stream before SS encryption.
/// * `V2ray` — native v2ray-plugin websocket (+ optional TLS) transport wraps
///   the TCP stream before SS encryption.
/// * `Gost` — native gost-plugin websocket (+ optional TLS and single-stream
///   smux) transport wraps the TCP stream before SS encryption.
/// * `ShadowTls` — native shadow-tls v1/v2/v3 (cover-TLS record transport).
/// * `EchTlsTunnel` — `ech-tls-tunnel` plugin (TLS-in-TLS with ECH).
/// * `Restls` — native restls (record-level TLS handshake + tagged records).
/// * `Jls` — native jls (record-level TLS 1.3 with random-field auth).
/// * `Kcptun` — native kcptun (KCP-over-UDP + smux pool; UDP via UoT).
#[allow(
    clippy::large_enum_variant,
    reason = "external-plugin boxing would add an indirection to the overwhelmingly-common no-plugin arm; the variant spread is bounded by in-tree plugins"
)]
enum PluginKind {
    None,
    /// External SIP003 plugin subprocess. The `Plugin` handle keeps the
    /// subprocess alive for the adapter's lifetime.
    External(#[allow(dead_code)] Plugin),
    Obfs(BuiltinObfs),
    V2ray(V2rayPluginConfig, Option<TlsLayer>),
    /// Native gost-plugin websocket (+ optional TLS and smux) transport.
    /// `WsLayer` is built at construction so a malformed headers/path
    /// config fails once at startup, not per dial. The TLS layer is a
    /// `ReloadableTlsLayer` — file-sourced mTLS cert/key PEMs are re-stat
    /// per dial and hot-reloaded on change (issue #621).
    Gost(
        gost_plugin::GostPluginConfig,
        Option<gost_plugin::ReloadableTlsLayer>,
        meow_transport::ws::WsLayer,
    ),
    /// Native shadow-tls transport (v1/v2/v3). `TlsLayer` is built at
    /// construction so a malformed TLS config fails once at startup.
    ShadowTls(shadow_tls_plugin::ShadowTlsConfig, TlsLayer),
    /// Native restls transport — the record-level TLS client needs no
    /// `TlsLayer`; `RestlsPluginConfig` is validated at construction.
    Restls(restls_plugin::RestlsPluginConfig),
    /// Native jls transport — record-level TLS 1.3 with hello-random
    /// authentication; `JlsConfig` is validated at construction.
    Jls(jls_plugin::JlsPluginConfig),
    /// Native kcptun transport — KCP-over-UDP + smux session pool.
    /// `Arc` because the pooled client outlives a single dial.
    #[cfg(feature = "kcptun")]
    Kcptun(Arc<kcptun_plugin::KcptunClient>),
    #[cfg(feature = "ech-tls-tunnel")]
    EchTlsTunnel(EchTlsTunnelConfig, TlsLayer),
}

impl PluginKind {
    /// Why this plugin refuses UDP relay, if it does — one place so the
    /// `dial_udp` gate can't drift as variants accrete.
    fn udp_block_reason(&self) -> Option<&'static str> {
        match self {
            PluginKind::V2ray(..) => Some("v2ray-plugin does not support UDP relay"),
            PluginKind::Gost(..) => Some("gost-plugin does not support UDP relay"),
            PluginKind::ShadowTls(..) => Some("shadow-tls does not support UDP relay"),
            PluginKind::Restls(..) => Some("restls does not support UDP relay"),
            PluginKind::Jls(..) => Some("jls does not support UDP relay"),
            #[cfg(feature = "ech-tls-tunnel")]
            PluginKind::EchTlsTunnel(..) => Some("ech-tls-tunnel does not support UDP relay"),
            _ => None,
        }
    }
}

/// Dial-relevant SS state, shared (Arc) between the adapter and any mux
/// session so the SIP003 plugin handle stays alive for both.
struct SsCore {
    server: SmolStr,
    port: u16,
    server_config: ServerConfig,
    context: shadowsocks::context::SharedContext,
    plugin: PluginKind,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
}

pub struct ShadowsocksAdapter {
    name: SmolStr,
    core: Arc<SsCore>,
    addr_str: SmolStr,
    support_udp: bool,
    health: ProxyHealth,
    /// sing-mux compatible connection multiplexing (optional).
    #[cfg(feature = "mux")]
    mux: Option<Arc<crate::mux::MuxClient>>,
}

impl ShadowsocksAdapter {
    #[allow(
        clippy::too_many_arguments,
        reason = "SS node params are flat config fields; a builder adds indirection without fewer call-site args"
    )]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        cipher: &str,
        udp: bool,
        plugin_name: Option<&str>,
        plugin_opts: Option<&str>,
        // Node-level `client-fingerprint` (uTLS profile) — consumed by the
        // `shadow-tls` plugin's cover handshake; ignored by other plugins.
        client_fingerprint: Option<&str>,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Result<Self> {
        let cipher_kind = cipher
            .parse::<CipherKind>()
            .map_err(|_| MeowError::Config(format!("unknown cipher: {cipher}")))?;
        let mut server_config = ServerConfig::new((server, port), password, cipher_kind)
            .map_err(|e| MeowError::Config(format!("invalid ss config: {e}")))?;
        let context = Context::new_shared(ServerType::Local);
        let addr_str = SmolStr::from(format!("{server}:{port}"));

        let plugin = match plugin_name {
            Some(p) if is_builtin_obfs_plugin(p) => {
                let cfg = parse_obfs_opts(plugin_opts, server)?;
                debug!("SS '{}' using built-in simple-obfs ({:?})", name, cfg);
                PluginKind::Obfs(cfg)
            }
            Some("v2ray-plugin") => {
                let mut cfg = v2ray_plugin::parse_opts(plugin_opts.unwrap_or(""))?;
                if cfg.host.is_empty() {
                    cfg.host = server.to_string();
                }
                debug!(
                    "SS '{}' using built-in v2ray-plugin: tls={} host={} path={} mux={}",
                    name, cfg.tls, cfg.host, cfg.path, cfg.mux
                );
                let tls = v2ray_plugin::build_tls_layer(&cfg)?;
                PluginKind::V2ray(cfg, tls)
            }
            Some("gost-plugin") => {
                let cfg = gost_plugin::parse_opts(plugin_opts.unwrap_or(""))?;
                debug!(
                    "SS '{}' using built-in gost-plugin: tls={} host={} path={} mux={}",
                    name, cfg.tls, cfg.host, cfg.path, cfg.mux
                );
                let tls = gost_plugin::build_tls_layer(&cfg)?;
                let ws = gost_plugin::build_ws_layer(&cfg)?;
                PluginKind::Gost(cfg, tls, ws)
            }
            Some("shadow-tls") => {
                let cfg = shadow_tls_plugin::parse_opts(plugin_opts.unwrap_or(""))?;
                debug!(
                    "SS '{}' using built-in shadow-tls: host={} version={} alpn={:?}",
                    name, cfg.host, cfg.version, cfg.alpn
                );
                let tls = shadow_tls_plugin::build_tls_layer(&cfg, client_fingerprint)?;
                PluginKind::ShadowTls(cfg, tls)
            }
            Some("restls") => {
                let cfg = restls_plugin::parse_opts(plugin_opts.unwrap_or(""))?;
                debug!(
                    "SS '{}' using built-in restls: host={} version-hint={}",
                    name, cfg.host, cfg.version_hint
                );
                // `client-fingerprint` selects a uTLS profile upstream; our
                // record-level client crafts a fixed-shape ClientHello.
                if client_fingerprint.is_some() {
                    warn!("SS '{name}': client-fingerprint has no effect on restls");
                }
                PluginKind::Restls(cfg)
            }
            Some("jls") => {
                let cfg = jls_plugin::parse_opts(plugin_opts.unwrap_or(""))?;
                debug!(
                    "SS '{}' using built-in jls: host={} username={}",
                    name, cfg.host, cfg.username
                );
                // `client-fingerprint` selects a uTLS profile upstream; our
                // record-level client crafts a fixed-shape ClientHello.
                if client_fingerprint.is_some() {
                    warn!("SS '{name}': client-fingerprint has no effect on jls");
                }
                PluginKind::Jls(cfg)
            }
            #[cfg(feature = "kcptun")]
            Some("kcptun") => {
                let cfg = kcptun_plugin::parse_opts(plugin_opts.unwrap_or(""))?;
                debug!(
                    "SS '{}' using built-in kcptun: crypt={} mode={} conn={} nocomp={}",
                    name, cfg.crypt, cfg.mode, cfg.conn, cfg.no_comp
                );
                PluginKind::Kcptun(Arc::new(kcptun_plugin::KcptunClient::new(
                    cfg,
                    server,
                    port,
                    Arc::clone(&dialer),
                )))
            }
            #[cfg(feature = "ech-tls-tunnel")]
            Some("ech-tls-tunnel") => {
                let cfg = ech_tls_tunnel::parse_opts(plugin_opts.unwrap_or(""))?;
                debug!(
                    "SS '{}' using built-in ech-tls-tunnel: sni={} path={} ech_config_len={}",
                    name,
                    cfg.sni,
                    cfg.path,
                    cfg.ech_config.len()
                );
                let tls = ech_tls_tunnel::build_tls_layer(&cfg)?;
                PluginKind::EchTlsTunnel(cfg, tls)
            }
            Some(pname) => {
                // SIP003u: a `mode=tcp_and_udp` / `udp_only` token in plugin-opts
                // selects whether UDP relay is tunneled through the plugin. The
                // token is consumed here (not forwarded to the plugin process)
                // and translated to the shadowsocks plugin transport mode.
                // Default stays TcpOnly, so UDP keeps going direct to the server
                // for plugins that don't speak SIP003u (unchanged behaviour).
                let (plugin_mode, filtered_opts) = extract_sip003_plugin_mode(plugin_opts);
                let plugin_config = PluginConfig {
                    plugin: pname.to_string(),
                    plugin_opts: filtered_opts,
                    plugin_args: vec![],
                    plugin_mode,
                };
                let started =
                    Plugin::start(&plugin_config, server_config.addr(), PluginMode::Client)
                        .map_err(|e| {
                            MeowError::Config(format!("failed to start ss plugin '{pname}': {e}"))
                        })?;
                server_config.set_plugin_addr(ServerAddr::SocketAddr(started.local_addr()));
                server_config.set_plugin(plugin_config);
                debug!("SS plugin '{}' started on {}", pname, started.local_addr());
                PluginKind::External(started)
            }
            None => PluginKind::None,
        };

        let core = Arc::new(SsCore {
            server: SmolStr::from(server),
            port,
            server_config,
            context,
            plugin,
            dialer,
        });

        Ok(Self {
            name: SmolStr::from(name),
            core,
            addr_str,
            support_udp: udp,
            health: ProxyHealth::new(),
            #[cfg(feature = "mux")]
            mux: None,
        })
    }

    /// Enable sing-mux compatible connection multiplexing.  The session's
    /// SS stream targets the reserved mux destination; the server must be a
    /// sing-box / mihomo SS inbound with multiplex enabled (a plain
    /// ss-server does not speak sing-mux).  Xray Mux.Cool is VLESS-only.
    #[cfg(feature = "mux")]
    pub fn with_mux(mut self, options: crate::mux::MuxOptions) -> Self {
        use crate::mux::{MuxClient, MUX_DESTINATION_FQDN, MUX_DESTINATION_PORT};
        use std::sync::Arc as StdArc;

        let core = Arc::clone(&self.core);
        let dial: crate::mux::DialFn = StdArc::new(move || {
            let core = Arc::clone(&core);
            Box::pin(async move {
                let addr = Address::DomainNameAddress(
                    MUX_DESTINATION_FQDN.to_string(),
                    MUX_DESTINATION_PORT,
                );
                core.dial_tcp_stream(addr, false).await
            })
        });
        self.mux = Some(MuxClient::new(dial, options));
        self
    }

    /// Whether an external SIP003 plugin owns the UDP leg: `udp_external_addr`
    /// is then the plugin's local listener, whose outbound belongs to the
    /// subprocess — chaining it through `dialer-proxy` would make the *front*
    /// dial `127.0.0.1:<plugin-port>` on its own loopback while our plugin
    /// still listens locally. Same contract as the TCP path, which dials the
    /// plugin listener directly under `dialer-proxy`.
    fn plugin_owns_udp(&self) -> bool {
        matches!(self.core.plugin, PluginKind::External(_))
            && self
                .core
                .server_config
                .plugin()
                .is_some_and(|p| p.plugin_mode.enable_udp())
    }

    /// Whether the plain SS UDP association must ride the `dialer-proxy`
    /// chain — false on a direct dialer, and false when an external plugin
    /// owns the UDP leg (its endpoint is the local plugin listener, which
    /// is never chain-routed).
    fn udp_via_chain(&self) -> bool {
        self.core.dialer.is_proxy() && !self.plugin_owns_udp()
    }

    /// Dial the SS server's UDP endpoint through the `dialer-proxy` front.
    ///
    /// A [`UdpTarget::Name`] asks the front to resolve the name itself —
    /// matching the view it used for the TCP leg (issue #657). A front
    /// that cannot carry a domain target answers `ErrorKind::Unsupported`
    /// and we fall back to a locally-resolved literal per candidate — the
    /// pre-#657 behavior, still fail-closed through the same chain.
    ///
    /// Returns the conn plus the *effective* target (the literal a
    /// fallback dial bound to), which the conn uses for its source filter.
    async fn dial_udp_via_front(
        &self,
        target: UdpTarget,
        internal: bool,
    ) -> Result<(Arc<dyn ProxyPacketConn>, UdpTarget)> {
        match self
            .core
            .dialer
            .dial_udp_conn(target.clone(), internal)
            .await
        {
            Ok(conn) => Ok((conn, target)),
            // The dialer maps front `NotSupported`/`UdpNotSupported` to
            // `ErrorKind::Unsupported` — a capability refusal, not a
            // transport failure: `NotSupported` stays exempt from
            // dead-marking (a UDP-less front must not cost the node its
            // health), and every candidate would fail the same way.
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => match &target {
                UdpTarget::Addr(_) => Err(MeowError::NotSupported(format!(
                    "ss udp via dialer-proxy {target}: {e}"
                ))),
                UdpTarget::Name { host, port } => {
                    let candidates =
                        meow_common::resolve_host_all(host, *port)
                            .await
                            .map_err(|e| {
                                MeowError::io_with(&format!("ss udp lookup {host}:{port}"), e)
                            })?;
                    let mut last_err = None;
                    for remote in candidates {
                        match self
                            .core
                            .dialer
                            .dial_udp_conn(UdpTarget::Addr(remote), internal)
                            .await
                        {
                            Ok(conn) => return Ok((conn, UdpTarget::Addr(remote))),
                            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                                return Err(MeowError::NotSupported(format!(
                                    "ss udp via dialer-proxy {remote}: {e}"
                                )));
                            }
                            Err(e) => {
                                last_err = MeowError::prefer_errno(
                                    last_err,
                                    MeowError::io_with(
                                        &format!("ss udp via dialer-proxy {remote}"),
                                        e,
                                    ),
                                );
                            }
                        }
                    }
                    Err(last_err.unwrap_or_else(|| {
                        MeowError::Proxy("ss udp via dialer-proxy: no candidates".into())
                    }))
                }
            },
            Err(e) => Err(MeowError::io_with(
                &format!("ss udp via dialer-proxy {target}"),
                e,
            )),
        }
    }
}

impl SsCore {
    /// Layer the SS crypto codec for `addr` over `transport`, an established
    /// (possibly plugin-wrapped) stream to this server. Every TCP dial goes
    /// through here, so every SS connection gets [`SsConn`]'s
    /// server-first handling of the deferred request header.
    fn ss_conn<T>(&self, transport: T, addr: Address) -> Box<dyn ProxyConn>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        Box::new(SsConn::new(ProxyClientStream::from_stream(
            Arc::clone(&self.context),
            transport,
            &self.server_config,
            addr,
        )))
    }

    /// Dial a raw (or plugin-transported) TCP stream to the SS server and
    /// wrap it in the SS crypto codec for the given target address.
    ///
    /// `internal` is the caller's [`Metadata::is_internal`] marker — mux
    /// session dials pass `false` because a shared mux conn exists to serve
    /// user streams regardless of which dial triggered its establishment.
    async fn dial_tcp_stream(&self, addr: Address, internal: bool) -> Result<Box<dyn ProxyConn>> {
        match &self.plugin {
            PluginKind::Obfs(obfs) => {
                // Open a raw TCP connection to the SS server, wrap it in the
                // simple-obfs codec, then layer the SS crypto stream on top.
                let tcp = self
                    .dialer
                    .dial(&self.server, self.port, internal)
                    .await
                    .map_err(|e| MeowError::io_with("ss obfs tcp connect", e))?;

                match obfs.clone() {
                    BuiltinObfs::Http { host } => {
                        let wrapped = HttpObfs::new(tcp, host, self.port)
                            .map_err(|e| MeowError::Config(format!("ss obfs: {e}")))?;
                        Ok(self.ss_conn(wrapped, addr))
                    }
                    BuiltinObfs::Tls { server } => {
                        let wrapped = TlsObfs::new(tcp, server)
                            .map_err(|e| MeowError::Config(format!("ss obfs: {e}")))?;
                        Ok(self.ss_conn(wrapped, addr))
                    }
                }
            }
            PluginKind::V2ray(cfg, tls) => {
                let transport = v2ray_plugin::dial(
                    cfg,
                    tls.as_ref(),
                    &self.server,
                    self.port,
                    &*self.dialer,
                    internal,
                )
                .await?;
                Ok(self.ss_conn(transport, addr))
            }
            PluginKind::Gost(cfg, tls, ws) => {
                let transport = gost_plugin::dial(
                    cfg,
                    tls.as_ref(),
                    ws,
                    &self.server,
                    self.port,
                    &*self.dialer,
                    internal,
                )
                .await?;
                Ok(self.ss_conn(transport, addr))
            }
            PluginKind::ShadowTls(cfg, tls) => {
                let transport = shadow_tls_plugin::dial(
                    cfg,
                    tls,
                    &self.server,
                    self.port,
                    &*self.dialer,
                    internal,
                )
                .await?;
                Ok(self.ss_conn(transport, addr))
            }
            PluginKind::Restls(cfg) => {
                let transport =
                    restls_plugin::dial(cfg, &self.server, self.port, &*self.dialer, internal)
                        .await?;
                Ok(self.ss_conn(transport, addr))
            }
            PluginKind::Jls(cfg) => {
                let transport =
                    jls_plugin::dial(cfg, &self.server, self.port, &*self.dialer, internal).await?;
                Ok(self.ss_conn(transport, addr))
            }
            #[cfg(feature = "kcptun")]
            PluginKind::Kcptun(client) => {
                // A pooled smux stream over the KCP/UDP transport — the SS
                // crypto layer sits on top exactly like a TCP dial.
                let transport = client.open_stream().await?;
                Ok(self.ss_conn(transport, addr))
            }
            #[cfg(feature = "ech-tls-tunnel")]
            PluginKind::EchTlsTunnel(cfg, tls) => {
                let transport = ech_tls_tunnel::dial(
                    cfg,
                    tls,
                    &self.server,
                    self.port,
                    &*self.dialer,
                    internal,
                )
                .await?;
                Ok(self.ss_conn(transport, addr))
            }
            PluginKind::None => {
                // Dial the remote SS server through the pluggable dialer
                // (direct or via ``dialer-proxy``).  ``connect_tcp_host`` is
                // resolver-aware and SocketProtector-aware (Android
                // ``VpnService.protect(fd)``), and ``DirectDialer`` preserves
                // both of those properties.
                let tcp = match self.server_config.tcp_external_addr() {
                    ServerAddr::SocketAddr(sa) => self.dialer.dial_addr(*sa, internal).await,
                    ServerAddr::DomainName(host, port) => {
                        self.dialer.dial(host, *port, internal).await
                    }
                }
                .map_err(|e| MeowError::io_with("ss tcp connect", e))?;
                Ok(self.ss_conn(tcp, addr))
            }
            PluginKind::External(_) => {
                // SIP003 plugin subprocess: ``tcp_external_addr`` returns the
                // plugin's local listener (typically 127.0.0.1:<port>).
                // Always dial directly — the plugin is a local process and
                // must NOT be tunnelled through ``dialer-proxy``.
                let tcp = match self.server_config.tcp_external_addr() {
                    ServerAddr::SocketAddr(sa) => meow_common::connect_tcp(*sa).await,
                    ServerAddr::DomainName(host, port) => {
                        meow_common::connect_tcp_host(host, *port).await
                    }
                }
                .map_err(|e| MeowError::io_with("ss plugin tcp connect", e))?;
                Ok(self.ss_conn(tcp, addr))
            }
        }
    }

    /// Run the SS crypto handshake over `stream`, which must already
    /// terminate at this SS server — relay groups pass a chained stream in
    /// through `connect_over` instead of a fresh `dialer.dial`.
    async fn tcp_stream_over(
        &self,
        stream: Box<dyn meow_transport::Stream>,
        addr: Address,
    ) -> Result<Box<dyn ProxyConn>> {
        match &self.plugin {
            PluginKind::None => Ok(self.ss_conn(stream, addr)),
            PluginKind::Obfs(obfs) => {
                let stream = match obfs.clone() {
                    BuiltinObfs::Http { host } => Box::new(
                        HttpObfs::new(stream, host, self.port)
                            .map_err(|e| MeowError::Config(format!("ss obfs: {e}")))?,
                    )
                        as Box<dyn meow_transport::Stream>,
                    BuiltinObfs::Tls { server } => Box::new(
                        TlsObfs::new(stream, server)
                            .map_err(|e| MeowError::Config(format!("ss obfs: {e}")))?,
                    )
                        as Box<dyn meow_transport::Stream>,
                };
                Ok(self.ss_conn(stream, addr))
            }
            PluginKind::V2ray(cfg, tls) => {
                let transport = v2ray_plugin::handshake_over(
                    cfg,
                    tls.as_ref(),
                    &self.server,
                    self.port,
                    stream,
                )
                .await?;
                Ok(self.ss_conn(transport, addr))
            }
            #[cfg(feature = "ech-tls-tunnel")]
            PluginKind::EchTlsTunnel(cfg, tls) => {
                let transport =
                    ech_tls_tunnel::handshake_over(cfg, tls, &self.server, self.port, stream)
                        .await?;
                Ok(self.ss_conn(transport, addr))
            }
            PluginKind::Gost(..) => {
                // gost (ws+tls+smux) could terminate on a relay-supplied
                // stream once it grows a `handshake_over` split — its `dial`
                // currently owns the TCP dial itself. Until then, fail
                // loudly rather than send unwrapped traffic.
                Err(MeowError::NotSupported(
                    "ss: gost-plugin transport does not yet support \
                     terminating on a relay-supplied stream"
                        .into(),
                ))
            }
            PluginKind::ShadowTls(..) => {
                // shadow-tls could terminate on a relay-supplied stream once
                // it grows a `handshake_over` split — its `dial` currently
                // owns the TCP dial itself. Until then, fail loudly rather
                // than send unwrapped traffic.
                Err(MeowError::NotSupported(
                    "ss: shadow-tls transport does not yet support \
                     terminating on a relay-supplied stream"
                        .into(),
                ))
            }
            PluginKind::Restls(..) => {
                // restls could terminate on a relay-supplied stream once it
                // grows a `handshake_over` split — its `dial` currently owns
                // the TCP dial itself. Until then, fail loudly rather than
                // send unwrapped traffic.
                Err(MeowError::NotSupported(
                    "ss: restls transport does not yet support terminating \
                     on a relay-supplied stream"
                        .into(),
                ))
            }
            PluginKind::Jls(..) => {
                // jls could terminate on a relay-supplied stream once it
                // grows a `handshake_over` split — its `dial` currently owns
                // the TCP dial itself. Until then, fail loudly rather than
                // send unwrapped traffic.
                Err(MeowError::NotSupported(
                    "ss: jls transport does not yet support terminating on \
                     a relay-supplied stream"
                        .into(),
                ))
            }
            #[cfg(feature = "kcptun")]
            PluginKind::Kcptun(_) => {
                // KCP is UDP-only — it can never ride a relay TCP stream.
                Err(MeowError::NotSupported(
                    "ss: kcptun is a UDP transport; it cannot terminate on \
                     a relay-supplied stream"
                        .into(),
                ))
            }
            PluginKind::External(_) => {
                // A SIP003 subprocess owns its outbound leg (it dials the
                // real server itself and we only reach its local listener).
                // The relay-supplied stream already terminates at the real
                // SS server, so plugin obfuscation cannot be applied to it —
                // fail loudly rather than send un-obfuscated traffic.
                Err(MeowError::NotSupported(
                    "ss: external SIP003 plugin owns its outbound leg; \
                     it cannot terminate on a relay-supplied stream"
                        .into(),
                ))
            }
        }
    }
}

/// SIP003u: extract the plugin transport mode from SIP003 `plugin-opts`.
///
/// A `mode=tcp_and_udp` / `mode=udp_only` / `mode=tcp_only` token selects
/// whether UDP relay is tunneled through the SIP003 plugin. Any *other* `mode=`
/// value (e.g. simple-obfs `mode=tls`, v2ray-plugin `mode=quic`) is a
/// plugin-specific option and is left in place. Returns the resolved
/// [`Mode`] (default [`Mode::TcpOnly`], preserving the pre-SIP003u behaviour
/// where UDP bypasses the plugin) and the opts string with a recognised
/// transport-mode token removed so it is not forwarded to the plugin process.
fn extract_sip003_plugin_mode(opts: Option<&str>) -> (Mode, Option<String>) {
    let Some(opts) = opts else {
        return (Mode::TcpOnly, None);
    };
    let mut mode = Mode::TcpOnly;
    let mut kept: Vec<&str> = Vec::new();
    for tok in opts.split(';') {
        if let Some((k, v)) = tok.split_once('=') {
            if k.trim().eq_ignore_ascii_case("mode") {
                match v.trim().to_ascii_lowercase().as_str() {
                    "tcp_and_udp" => {
                        mode = Mode::TcpAndUdp;
                        continue;
                    }
                    "udp_only" => {
                        mode = Mode::UdpOnly;
                        continue;
                    }
                    "tcp_only" => {
                        mode = Mode::TcpOnly;
                        continue;
                    }
                    // Plugin-specific mode (obfs tls/http, v2ray quic/ws) — keep.
                    _ => {}
                }
            }
        }
        kept.push(tok);
    }
    let filtered = if kept.is_empty() {
        None
    } else {
        Some(kept.join(";"))
    };
    (mode, filtered)
}

/// Returns true if the given plugin name selects the built-in simple-obfs.
/// Accepts both `obfs` (Go mihomo's short name) and `simple-obfs` (the
/// original SIP003 binary name some users still write).
pub fn is_builtin_obfs_plugin(name: &str) -> bool {
    matches!(name, "obfs" | "simple-obfs")
}

/// Whether `name` resolves to an in-process plugin — anything else is
/// spawned as an external SIP003 subprocess.  Must stay in sync with the
/// dispatch match in `ShadowsocksAdapter::new` (single source of truth
/// for `meow-config`'s dialer-injection gate, which cannot see the
/// feature-gated `ech-tls-tunnel`/`kcptun` arms directly).
pub fn is_builtin_sip003_plugin(name: &str) -> bool {
    is_builtin_obfs_plugin(name)
        || matches!(
            name,
            "v2ray-plugin" | "gost-plugin" | "shadow-tls" | "restls" | "jls"
        )
        || (cfg!(feature = "ech-tls-tunnel") && name == "ech-tls-tunnel")
        || (cfg!(feature = "kcptun") && name == "kcptun")
}

/// Parses `plugin-opts` (already serialized to SIP003 `key=value;...` form) for
/// the built-in simple-obfs plugin.
///
/// Accepted keys (alias-tolerant — both YAML-style `mode`/`host` and SIP003
/// native `obfs`/`obfs-host` work):
///
/// * `mode` / `obfs` → `http` or `tls` (case-insensitive). REQUIRED.
/// * `host` / `obfs-host` → fake `Host:` (HTTP) or fake SNI (TLS).
///   Falls back to the SS server name if absent or empty.
///
/// Unknown keys are silently ignored to stay forward-compatible with the
/// upstream Go reference.
pub(crate) fn parse_obfs_opts(plugin_opts: Option<&str>, server: &str) -> Result<BuiltinObfs> {
    let opts = plugin_opts.unwrap_or("").trim();
    let mut mode: Option<String> = None;
    let mut host: Option<String> = None;
    for part in opts.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (part, ""),
        };
        match k {
            "obfs" | "mode" => mode = Some(v.to_ascii_lowercase()),
            "obfs-host" | "host" => host = Some(v.to_string()),
            _ => {}
        }
    }
    let mode = mode.ok_or_else(|| {
        MeowError::Config("simple-obfs plugin-opts must specify mode=http or mode=tls".to_string())
    })?;
    // An empty `host=` is treated as "not set" — fall back to the server.
    let host = host
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| server.to_string());
    // `host` lands verbatim in the emitted `Host:` header (http mode) or
    // SNI (tls mode) — reject bytes that could inject into either. The
    // opt arrives verbatim from provider payloads too (issue #648).
    if !meow_transport::simple_obfs::client::is_valid_obfs_host(&host) {
        return Err(MeowError::Config(
            "simple-obfs plugin-opts host is empty, over 253 bytes, or contains whitespace/control bytes".to_string(),
        ));
    }
    match mode.as_str() {
        "http" => Ok(BuiltinObfs::Http { host }),
        "tls" => Ok(BuiltinObfs::Tls { server: host }),
        other => Err(MeowError::Config(format!(
            "simple-obfs unsupported mode '{other}': expected 'http' or 'tls'"
        ))),
    }
}

/// How long [`SsConn`] waits for the caller's first payload before it sends
/// the Shadowsocks request header on its own.
///
/// `ProxyClientStream` defers the request header (salt/IV + target address)
/// to the first `poll_write` and coalesces it with that payload, so a
/// client-first connection opens with one chunk carrying both. A
/// server-first protocol (SMTP, FTP, POP3, IMAP, MySQL, VNC) writes nothing
/// until the server's banner arrives, and meow's relay never issues an empty
/// write — without a deadline the SS server waits for the address while the
/// client waits for the banner, forever.
///
/// 200 ms is mihomo's pre-dial client peek: `handleTCPConn` gives the client
/// 200 ms to send its first bytes, then writes whatever it got — possibly
/// nothing — to a conn that `N.NeedHandshake`, and an empty write sends the
/// SS header alone (`tunnel/tunnel.go:543-551,582-604` @ MetaCubeX/mihomo
/// 88dcbf7f). shadowsocks-rust's `sslocal` does the same with a 500 ms wait
/// and `write(&[])` (`crates/shadowsocks-service/src/local/utils.rs:40-67`
/// @ f23366dc). mihomo's window overlaps the dial; this one starts at the
/// relay's first read, after it. Only server-first connections pay it: a
/// client that writes inside the window keeps the coalesced header.
const SS_HEADER_WINDOW: Duration = Duration::from_millis(200);

/// Progress of the request header that `ProxyClientStream` defers to the
/// first `poll_write`.
enum HeaderState {
    /// Nothing written yet; the header waits for the caller's first payload.
    /// The window timer is armed by the first `poll_read` and boxed so
    /// [`SsConn`] stays `Unpin`; a connection that writes first never
    /// allocates it.
    Deferred(Option<Pin<Box<Sleep>>>),
    /// Header-only write (`poll_write(&[])`) in flight. Under backpressure
    /// the crate keeps the encrypted header in its own `Connecting` buffer
    /// and the next call resumes it.
    Writing,
    /// Header written; flushing it through plugin transports that buffer
    /// (TLS, WebSocket, shadow-tls, ...).
    Flushing,
    /// Nothing left to do: the header went out, alone or coalesced with the
    /// first payload, or the write half shut down before it was needed.
    Done,
}

/// [`ProxyConn`] over a Shadowsocks client stream that also sends the
/// deferred request header for server-first protocols: when the remote side
/// has been read for [`SS_HEADER_WINDOW`] and the caller has written
/// nothing, it writes the header alone. Like the VLESS
/// (`vless/conn.rs` `poll_flush_deferred_header`) and Snell v6
/// (`snell/v6.rs` `poll_send_request`) adapters, the deferred header is
/// flushed from `poll_read`, which the relay polls from the start.
struct SsConn<T> {
    inner: ProxyClientStream<T>,
    header: HeaderState,
}

impl<T: AsyncRead + AsyncWrite + Unpin> SsConn<T> {
    fn new(inner: ProxyClientStream<T>) -> Self {
        Self {
            inner,
            header: HeaderState::Deferred(None),
        }
    }

    /// Drive a started header-only write through write and flush. Returns
    /// `Ready(Ok(()))` straight away unless the state is `Writing` or
    /// `Flushing`.
    fn poll_send_header(&mut self, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match self.header {
                HeaderState::Writing => {
                    // An empty first write makes the crate send the salt +
                    // address (+ AEAD-2022 padding) as a chunk of its own —
                    // its documented hook for protocols that wait for a
                    // server hello (shadowsocks-rust#232). While this is
                    // pending the crate ignores the buffer argument and
                    // resumes its own.
                    ready!(Pin::new(&mut self.inner).poll_write(cx, &[]))?;
                    self.header = HeaderState::Flushing;
                }
                HeaderState::Flushing => {
                    ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
                    self.header = HeaderState::Done;
                }
                HeaderState::Deferred(_) | HeaderState::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for SsConn<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.header {
                HeaderState::Done => break,
                HeaderState::Deferred(timer) => {
                    let timer =
                        timer.get_or_insert_with(|| Box::pin(tokio::time::sleep(SS_HEADER_WINDOW)));
                    if timer.as_mut().poll(cx).is_pending() {
                        break;
                    }
                    debug!(
                        "ss: client silent for {}ms, sending request header alone",
                        SS_HEADER_WINDOW.as_millis()
                    );
                    this.header = HeaderState::Writing;
                }
                HeaderState::Writing | HeaderState::Flushing => {
                    if this.poll_send_header(cx)?.is_pending() {
                        break;
                    }
                }
            }
        }
        // Read even while the header is pending: a server close or reset
        // still surfaces, and the read waker is registered next to the
        // timer's or the header write's.
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SsConn<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        if let HeaderState::Deferred(_) = this.header {
            if !buf.is_empty() {
                // First payload: the crate coalesces the header with it.
                // Leave `Deferred` before the call, because the crate commits
                // the header to this write even when it returns `Pending`.
                // A timer-driven empty write after that would complete the
                // crate's buffered `header ‖ buf` and report 0, and the
                // caller's retry would send `buf` a second time.
                this.header = HeaderState::Done;
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            // An explicit empty write asks for the header now.
            this.header = HeaderState::Writing;
        }
        // Finish a header-only write first: until it completes the crate
        // ignores `buf` and would report it written.
        ready!(this.poll_send_header(cx))?;
        if buf.is_empty() {
            // The header is out. Forwarding would make the crate emit an
            // empty AEAD chunk.
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_send_header(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if let HeaderState::Deferred(_) = this.header {
            // The caller closed without sending anything: no header, as
            // before (sslocal also gives up on EOF). Dropping the timer
            // keeps a later read from writing after the shutdown.
            this.header = HeaderState::Done;
        }
        ready!(this.poll_send_header(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> ProxyConn for SsConn<T> {}

/// Per-association SIP022 client session for AEAD-2022 UDP (§3.2.2).
///
/// The socket's `send`/`recv` shortcuts substitute an all-zero control —
/// `client_session_id = 0` and `packet_id = 0` on every datagram — which a
/// spec-conforming 2022 server drops from the second packet on (its
/// per-session replay window is mandatory, §3.2.4). That made SS-2022 UDP
/// outbound unusable against real servers. A working association mints one
/// random session ID, counts packets up, and validates the reply direction
/// the same way the server validates us.
///
/// Ciphers outside the AEAD-2022 category carry no session fields: the
/// control is ignored on encrypt and `recv` yields `None`, so this state is
/// simply unused there.
struct SsUdpSession {
    /// Random non-zero session ID the server keys its relay session on.
    client_session_id: u64,
    /// Client→server packet counter for this session.
    next_packet_id: AtomicU,
    /// Server→client replay tracker: a sliding window over each server
    /// session's packet IDs (§3.2.4 applies to clients too). `Mutex`
    /// because `read_packet` takes `&self`.
    server: std::sync::Mutex<ServerReplyTracker>,
}

/// Interleaved replies under several live server sessions (e.g. a UDP load
/// balancer fanning one VIP out to several ssserver backends, each minting
/// its own ID for our client session, or a server-side association expiry
/// re-keying mid-association) must each keep their window — resetting one
/// shared window on every flap would re-accept replayed packet IDs. §3.2.4
/// has clients remember at least the current and previous server sessions.
#[derive(Default)]
struct ServerReplyTracker {
    /// server_session_id → its reply packet-ID window. Bounded by
    /// [`MAX_TRACKED_SERVER_SESSIONS`]: past it the *least recently used*
    /// window is evicted — never the whole table. A full `clear()` would let
    /// an on-path attacker replay N distinct recently-captured server
    /// session IDs to wipe every window at once, re-opening all of them to
    /// replays; per-entry eviction bounds that blast radius to a single
    /// session per injected datagram.
    windows: std::collections::HashMap<u64, TrackedWindow>,
    /// Monotonic access stamp feeding LRU eviction.
    tick: u64,
}

/// A replay window plus the last time it filtered a reply.
struct TrackedWindow {
    window: meow_common::ReplayWindow,
    last_used: u64,
}

const MAX_TRACKED_SERVER_SESSIONS: usize = 4;

impl SsUdpSession {
    /// Mint a fresh session. `generate_nonce` fills via `random_iv_or_salt`,
    /// which already guarantees a non-zero buffer.
    fn new(ctx: &SharedContext, method: CipherKind) -> Self {
        let mut buf = [0u8; 8];
        ctx.generate_nonce(method, &mut buf, false);
        Self {
            client_session_id: u64::from_be_bytes(buf),
            next_packet_id: AtomicU::new(0),
            server: std::sync::Mutex::new(ServerReplyTracker::default()),
        }
    }

    /// The control for the next client→server datagram, or `None` once the
    /// packet-ID space is exhausted. IDs are pre-incremented (sslocal
    /// parity: the first datagram carries 1). On 32-bit targets `AtomicU`
    /// is u32 and the space runs out after 2^32 datagrams; `checked_add`
    /// refuses the wrap rather than reusing IDs the server's replay window
    /// would drop. The caller errors the association so the next datagram
    /// re-dials under a freshly minted session — the same recovery shape
    /// as sslocal's socket reset + session renewal.
    fn send_control(&self) -> Option<UdpSocketControlData> {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client_session_id;
        control.packet_id = checked_increment(&self.next_packet_id)?;
        Some(control)
    }

    /// Validate a server→client control (§3.2.3/§3.2.4): the echoed client
    /// session ID must be ours and the server session ID non-zero (`0` is
    /// the "no session" sentinel every implementation reserves — ssserver
    /// generates IDs in a non-zero loop, sing-box uses it as the empty
    /// marker); each server session ID keeps its own replay window (server
    /// restarts legitimately re-key sessions, and interleaved sessions must
    /// not reset each other's window); the packet ID must not be a replay
    /// or older than its session's window.
    fn accept_reply(&self, control: &UdpSocketControlData) -> bool {
        if control.client_session_id != self.client_session_id || control.server_session_id == 0 {
            return false;
        }
        let mut tracker = self
            .server
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tracker.tick += 1;
        let tick = tracker.tick;
        let windows = &mut tracker.windows;
        if !windows.contains_key(&control.server_session_id)
            && windows.len() >= MAX_TRACKED_SERVER_SESSIONS
        {
            if let Some(&oldest) = windows
                .iter()
                .min_by_key(|(_, w)| w.last_used)
                .map(|(id, _)| id)
            {
                windows.remove(&oldest);
            }
        }
        windows
            .entry(control.server_session_id)
            .and_modify(|t| t.last_used = tick)
            .or_insert_with(|| TrackedWindow {
                window: meow_common::ReplayWindow::new(),
                last_used: tick,
            })
            .window
            .check_and_set(control.packet_id)
    }
}

// Wrapper for SS UDP packet transport. The crypto layer is identical on
// both arms — only how ciphertext datagrams reach the SS server's UDP
// endpoint differs.
enum SsUdpIo {
    /// Raw connected UDP socket to the server (no `dialer-proxy`).
    Raw(ProxySocket<TokioUdpDatagram>),
    /// Front-proxied UDP association — mihomo's `proxyDialer.ListenPacket`
    /// shape: `dialer-proxy` turns the SS server's UDP endpoint into the
    /// front's association destination, and the SS crypto layer runs
    /// directly over the returned `ProxyPacketConn` (no `ProxySocket`/poll
    /// bridge — `ProxySocket`'s client path only ever uses connected
    /// send/recv, which `ProxyPacketConn` already is).
    ///
    /// `remote` is the SS server's UDP endpoint: bound-at-dial conns
    /// (VLESS, mux, name-bound fronts) ignore the per-packet addr;
    /// per-packet conns (SOCKS5) encode it — either way it must be the
    /// server endpoint, not the inner SS target (that travels encrypted
    /// inside the payload). A [`UdpTarget::Name`] keeps the server domain
    /// so the front resolves it with the same view as the TCP leg.
    Chained {
        conn: Arc<dyn ProxyPacketConn>,
        remote: UdpTarget,
        context: SharedContext,
        method: CipherKind,
        key: Box<[u8]>,
        identity_keys: Arc<Vec<bytes::Bytes>>,
    },
}

struct SsPacketConn {
    io: SsUdpIo,
    session: SsUdpSession,
    /// This adapter as a *front* for a domain-carrying association request
    /// (issue #657): the SS payload's target stamps the name so the server
    /// resolves it — the caller's per-packet `SocketAddr` arg is advisory.
    write_target: Option<Address>,
}

impl SsPacketConn {
    fn chained(
        conn: Arc<dyn ProxyPacketConn>,
        remote: UdpTarget,
        core: &SsCore,
        session: SsUdpSession,
        write_target: Option<Address>,
    ) -> Self {
        Self {
            io: SsUdpIo::Chained {
                conn,
                remote,
                context: Arc::clone(&core.context),
                method: core.server_config.method(),
                key: core.server_config.key().into(),
                identity_keys: core.server_config.clone_identity_keys(),
            },
            session,
            write_target,
        }
    }
}

#[async_trait]
impl ProxyPacketConn for SsPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        match &self.io {
            SsUdpIo::Raw(socket) => {
                use shadowsocks::relay::udprelay::proxy_socket::ProxySocketError;
                loop {
                    let (n, addr, _raw_len, control) = match socket.recv_with_ctrl(buf).await {
                        Ok(v) => v,
                        // A single undecryptable / malformed datagram must not kill
                        // the association: the reply task exits on Err, forcing a
                        // redial per stray packet (an on-path attacker replaying
                        // captured ciphertexts could churn sessions). Protocol-level
                        // rejects are per-datagram — drop and keep reading, matching
                        // how sslocal survives recv errors.
                        Err(
                            e @ (ProxySocketError::ProtocolError(_)
                            | ProxySocketError::ProtocolErrorWithPeer(..)),
                        ) => {
                            debug!("ss udp: dropped malformed reply datagram: {e}");
                            continue;
                        }
                        Err(e) => return Err(MeowError::Proxy(format!("ss udp recv: {e}"))),
                    };
                    // §3.2.4: a reply stamped for another session, or a replayed /
                    // out-of-window server packet ID, is dropped — keep reading for
                    // a valid datagram instead of surfacing the junk one.
                    if let Some(c) = &control {
                        if !self.session.accept_reply(c) {
                            continue;
                        }
                    }
                    let sock_addr = match addr {
                        Address::SocketAddress(sa) => sa,
                        // A conforming server always replies with the responder's
                        // SocketAddress; a domain-typed reply (non-compliant peer)
                        // can never parse as SocketAddr — drop it rather than kill
                        // the reply task.
                        Address::DomainNameAddress(..) => continue,
                    };
                    return Ok((n, sock_addr));
                }
            }
            SsUdpIo::Chained {
                conn,
                remote,
                context,
                method,
                key,
                ..
            } => loop {
                // Transport errors propagate (the association is dead);
                // decrypt failures are per-datagram — same drop-and-continue
                // as the Raw arm's ProtocolError handling above.
                let (rn, outer_src) = conn.read_packet(buf).await?;
                // Per-packet fronts (SOCKS5 UDP) report the real wire source
                // and can deliver datagrams from arbitrary remotes — restore
                // the connected-socket filter the Raw arm had. Bound conns
                // report `remote` or an unspecified addr (no source info);
                // unspecified skips the check rather than breaking them.
                // `src_matches` compares canonically for literal targets and
                // by port only for a `Name` — a name-bound front resolved it
                // itself, so the wire source legitimately differs from any
                // local resolution (issue #657). The unspecified exemption is
                // canonical too: `::ffff:0.0.0.0` must not sneak past as a
                // "real" remote.
                if !remote.src_matches(outer_src) && !outer_src.ip().to_canonical().is_unspecified()
                {
                    debug!("ss udp: dropped chained reply from {outer_src} (expected {remote})");
                    continue;
                }
                let Ok((n, addr, control)) =
                    decrypt_server_payload(context, *method, key, &mut buf[..rn])
                else {
                    debug!("ss udp: dropped malformed reply datagram (chained)");
                    continue;
                };
                if let Some(c) = &control {
                    if !self.session.accept_reply(c) {
                        continue;
                    }
                }
                let Address::SocketAddress(sa) = addr else {
                    continue;
                };
                return Ok((n, sa));
            },
        }
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        // A front-side domain association stamps its bound name as the
        // decrypted target; otherwise the caller's per-packet addr rules.
        let arg_target;
        let target = match &self.write_target {
            Some(t) => t,
            None => {
                arg_target = Address::SocketAddress(*addr);
                &arg_target
            }
        };
        // An exhausted packet-ID space kills the association: the tunnel
        // drops the session on this error and the next datagram re-dials
        // under a fresh `SsUdpSession` — sslocal's recovery on counter
        // overflow (socket reset + session renewal).
        let Some(control) = self.session.send_control() else {
            return Err(MeowError::Proxy(
                "ss udp: client packet-ID space exhausted".into(),
            ));
        };
        match &self.io {
            SsUdpIo::Raw(socket) => {
                // ProxySocket::send_with_ctrl returns the encrypted packet size
                // (with protocol overhead), but callers expect the payload size.
                socket
                    .send_with_ctrl(target, &control, buf)
                    .await
                    .map_err(|e| MeowError::Proxy(format!("ss udp send: {e}")))?;
            }
            SsUdpIo::Chained {
                conn,
                remote,
                context,
                method,
                key,
                identity_keys,
            } => {
                // Same bytes `ProxySocket::send_with_ctrl` emits — the SS
                // header + target are inside the ciphertext; the wire
                // datagram always goes to `remote` (the SS server's UDP
                // endpoint bound by the front's association).
                let mut send_buf = bytes::BytesMut::with_capacity(buf.len() + 256);
                encrypt_client_payload(
                    context,
                    *method,
                    key,
                    target,
                    &control,
                    identity_keys,
                    buf,
                    &mut send_buf,
                );
                // AEAD-2022 overhead (header + EIH + up to 900 B padding +
                // addr + tag) can push ciphertext past u16::MAX for a legal
                // max-size UDP payload. Every stream-framed front encodes
                // datagrams with a u16 length — a wrap would desync the
                // front's stream permanently, so error the association like
                // EMSGSIZE does on the raw socket.
                if send_buf.len() > u16::MAX as usize {
                    return Err(MeowError::Proxy(format!(
                        "ss udp: chained datagram {}B exceeds u16 frame limit",
                        send_buf.len()
                    )));
                }
                // A datagram conn must be atomic — a short write means the
                // front truncated ciphertext, which no retry can repair.
                // `write_dst` is the literal for `Addr` targets and an
                // advisory placeholder for a name-bound front conn (it
                // stamps its own resolved target).
                let sent = conn.write_packet(&send_buf, &remote.write_dst()).await?;
                if sent != send_buf.len() {
                    return Err(MeowError::Proxy(format!(
                        "ss udp: front conn truncated datagram ({sent}/{} B)",
                        send_buf.len()
                    )));
                }
            }
        }
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        match &self.io {
            SsUdpIo::Raw(socket) => socket.local_addr().map_err(MeowError::Io),
            // Stream-framed front conns (VLESS/Trojan) have no bound UDP
            // socket — they report unspecified, which callers only log.
            SsUdpIo::Chained { conn, .. } => conn.local_addr(),
        }
    }

    fn close(&self) -> Result<()> {
        match &self.io {
            SsUdpIo::Raw(_) => Ok(()),
            SsUdpIo::Chained { conn, .. } => conn.close(),
        }
    }
}

/// The shadowsocks crate asserts `domain.len() <= u8::MAX` when serializing
/// a `DomainNameAddress`, so an oversized provider/config hostname panics
/// instead of erroring — refuse first. `NotSupported` also lets a chained
/// `dial_udp_conn` caller fall back to a locally-resolved `UdpTarget::Addr`
/// (issue #657).
fn parse_address(metadata: &Metadata) -> Result<Address> {
    if !metadata.host.is_empty() || metadata.dst_ip.is_none() {
        if metadata.host.len() > u8::MAX as usize {
            return Err(MeowError::NotSupported(format!(
                "ss: domain target exceeds 255 bytes ({}B)",
                metadata.host.len()
            )));
        }
        return Ok(Address::DomainNameAddress(
            metadata.host.to_string(),
            metadata.dst_port,
        ));
    }
    Ok(Address::SocketAddress(SocketAddr::new(
        metadata.dst_ip.expect("checked above"),
        metadata.dst_port,
    )))
}

#[async_trait]
impl ProxyAdapter for ShadowsocksAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Shadowsocks
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        // The plain SS UDP association rides the front proxy's own
        // `dial_udp` under `dialer-proxy` (mihomo `proxyDialer.ListenPacket`),
        // so a proxy dialer is fine *when the front advertises UDP* — a
        // point-in-time snapshot for group fronts; `dial_udp` re-checks at
        // dial and fails closed on a front that cannot carry UDP. An
        // external SIP003 plugin's UDP leg (its local listener) bypasses
        // the chain by design, same as TCP — capability is unconditional
        // there.
        //
        // Two consumers read this advertisement: the rule probe treats a
        // UDP flow matched to a `!support_udp` target as ineligible and
        // skips to the next rule (tunnel.rs `RouteTargetProbe`), and
        // LoadBalance filters members by it.  It is NOT the enforcement
        // point — `dial_udp` re-checks the chain and refuses on its own,
        // so a stale optimistic snapshot cannot open a raw socket.  Keep
        // the two in sync.
        let plain_udp_ok = self.support_udp
            && self.core.plugin.udp_block_reason().is_none()
            && (!self.udp_via_chain() || self.core.dialer.supports_udp());
        // kcptun's UDP path is UDP-over-TCP over a pooled smux stream — its
        // datagrams go through `dial_udp_endpoint`, which tunnels them under
        // `dialer-proxy` — so the chain is *safe*, but it still needs the
        // front to carry UDP at all: advertise only when it reports so.
        #[cfg(feature = "kcptun")]
        let kcptun_udp_ok = self.support_udp
            && matches!(self.core.plugin, PluginKind::Kcptun(_))
            && self.core.dialer.supports_udp();
        #[cfg(not(feature = "kcptun"))]
        let kcptun_udp_ok = false;
        plain_udp_ok || kcptun_udp_ok || {
            #[cfg(feature = "mux")]
            {
                self.mux.as_ref().is_some_and(|mux| mux.supports_udp())
            }
            #[cfg(not(feature = "mux"))]
            {
                false
            }
        }
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let addr = parse_address(metadata)?;
        debug!("SS connecting to {} via {}", addr, self.addr_str);

        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            let conn = mux.open_stream_for(metadata, "ss").await?;
            return Ok(Box::new(conn));
        }

        self.core
            .dial_tcp_stream(addr, metadata.is_internal())
            .await
    }

    /// Run the SS handshake over an existing stream (relay chain).
    ///
    /// The stream already terminates at this SS server, so the configured
    /// obfs/v2ray-plugin/ech transport still applies on top of it — only
    /// the raw dial is skipped.  Mux pooling is bypassed (single-use
    /// stream), and external SIP003 plugins fail loudly because they own
    /// their outbound leg.
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        let addr = parse_address(metadata)?;
        debug!("SS connecting to {} via relay stream", addr);

        #[cfg(feature = "mux")]
        if self.mux.is_some() {
            debug!("SS mux bypassed on relay-supplied stream (single-use)");
        }

        self.core.tcp_stream_over(Box::new(stream), addr).await
    }

    #[cfg_attr(not(feature = "mux"), allow(unused_variables))]
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            if mux.supports_udp() {
                debug!(
                    "SS mux UDP connecting to {} via {}",
                    metadata.remote_address(),
                    self.addr_str
                );
            }
            if let Some(conn) = mux.open_packet_stream_for(metadata, "ss").await? {
                return Ok(conn);
            }
        }

        // kcptun has no UDP relay on the wire — upstream forces
        // `UDPOverTCP`: one pooled smux stream carries an SS request to the
        // magic UoT target, then legacy `addr ‖ len ‖ payload` framing.
        // Safe before the `is_proxy` refusal below: the underlying KCP
        // datagrams went through `dial_udp_endpoint`, which tunnels them
        // through the front proxy's UDP relay rather than binding a raw
        // socket.
        #[cfg(feature = "kcptun")]
        if let PluginKind::Kcptun(client) = &self.core.plugin {
            // The UoT per-packet address is `SocketAddr`-keyed — a domain
            // association target cannot ride it. Refuse so the dialer layer
            // falls back to a locally-resolved `UdpTarget::Addr`, which the
            // kcptun path stamps per packet as before.
            if let Some((host, _)) = metadata.domain_udp_target() {
                return Err(MeowError::NotSupported(format!(
                    "ss kcptun: cannot carry domain UDP target {host}"
                )));
            }
            debug!(
                "SS UDP over kcptun UoT connecting to {} via {}",
                metadata.remote_address(),
                self.addr_str
            );
            let stream = client.open_stream().await?;
            let target = Address::DomainNameAddress(
                kcptun_plugin::UOT_MAGIC_HOST.to_string(),
                kcptun_plugin::UOT_MAGIC_PORT,
            );
            let ss_stream = ProxyClientStream::from_stream(
                Arc::clone(&self.core.context),
                stream,
                &self.core.server_config,
                target,
            );
            return Ok(Box::new(kcptun_plugin::UotPacketConn::new(Box::new(
                ss_stream,
            ))));
        }

        // TCP-transport plugins (v2ray/gost/shadow-tls/…) refuse UDP
        // regardless of chaining — checked before the `is_proxy` branch so
        // the refusal names the plugin, not the chain.
        if let Some(reason) = self.core.plugin.udp_block_reason() {
            return Err(MeowError::NotSupported(reason.into()));
        }

        // This adapter as a *front*: a host-only UDP destination — the
        // dialer layer's encoding of a chained `UdpTarget::Name`
        // (issue #657) — binds the association to the name: the SS
        // payload's target stamps the domain and the server resolves it
        // with its own view. The mux arm above carries it natively on
        // bound flows; the kcptun arm cannot and refuses below. The same
        // `DomainNameAddress` length contract as `parse_address` applies —
        // refuse an oversized name so the caller falls back to a literal
        // `UdpTarget::Addr` instead of tripping the crate's assert.
        let write_target = match metadata.domain_udp_target() {
            Some((host, port)) if host.len() <= u8::MAX as usize => {
                Some(Address::DomainNameAddress(host.to_string(), port))
            }
            Some((host, _)) => {
                return Err(MeowError::NotSupported(format!(
                    "ss: domain UDP target exceeds 255 bytes ({}B)",
                    host.len()
                )));
            }
            None => None,
        };

        // Snapshot pre-flight BEFORE resolving: a front that advertises no
        // UDP is a capability refusal (`NotSupported` is exempt from
        // dead-marking — the node itself isn't broken), and skipping the
        // resolve keeps a refused dial from emitting a pointless local DNS
        // lookup whose failure would masquerade as `Proxy` (dead-markable).
        // The authoritative check stays the real dial below: groups may
        // rotate members between this query and it.
        if self.udp_via_chain() && !self.core.dialer.supports_udp() {
            return Err(MeowError::NotSupported(
                "ss: `dialer-proxy` front reports no UDP support; \
                 refusing rather than leaking the real source path"
                    .into(),
            ));
        }

        // mihomo `proxyDialer.ListenPacket`: under `dialer-proxy` the SS UDP
        // association rides the front proxy's own `dial_udp` — the
        // association's wire destination is the SS server's UDP endpoint and
        // the SS crypto layer wraps the per-packet targets inside. Reached
        // after the mux branch above (which tunnels UDP over `dialer.dial()`)
        // and skipped for external plugins (their UDP endpoint is the local
        // plugin listener — never chained).
        //
        // A domain-form server address dials as `UdpTarget::Name` — the
        // front resolves it with the same view as the control/TCP leg
        // (issue #657); a front that cannot carry a domain refuses and
        // `dial_udp_via_front` falls back to a local resolution.
        //
        // Fail-closed (Class A, ADR-0002): a front that cannot carry UDP
        // surfaces its error and the raw-socket path below stays unreachable
        // on this branch — no silent real-source egress.
        if self.udp_via_chain() {
            let target = match self.core.server_config.udp_external_addr() {
                ServerAddr::SocketAddr(sa) => UdpTarget::Addr(*sa),
                ServerAddr::DomainName(host, port) => UdpTarget::named(host, *port),
            };
            let (conn, bound) = self
                .dial_udp_via_front(target, metadata.is_internal())
                .await?;
            debug!("SS UDP chained to {bound} via {}", self.addr_str);
            let session = SsUdpSession::new(&self.core.context, self.core.server_config.method());
            return Ok(Box::new(SsPacketConn::chained(
                conn,
                bound,
                &self.core,
                session,
                write_target,
            )));
        }

        // The SS server's UDP endpoint for the raw path. `udp_external_addr`
        // returns a literal `SocketAddr` for the standard path and the SIP003
        // plugin's local listener for external plugins (where the connect is
        // loopback — protect is harmless).
        let candidates = match self.core.server_config.udp_external_addr() {
            ServerAddr::SocketAddr(sa) => vec![*sa],
            ServerAddr::DomainName(host, port) => meow_common::resolve_host_all(host, *port)
                .await
                .map_err(|e| MeowError::io_with(&format!("ss udp lookup {host}:{port}"), e))?,
        };

        // Hand-roll the UDP bind+connect so the installed
        // `meow_common::SocketProtector` sees the fd before bind — otherwise
        // the upstream `shadowsocks::ProxySocket::connect` path binds via
        // plain tokio and the Android `VpnService.protect(fd)` hook never
        // fires, looping outbound UDP back into our own VPN tunnel.
        //
        // Try candidates in resolver order rather than committing to the
        // first one: on a single-stack network the resolver can still order
        // the unreachable family first (AAAA on an IPv4-only path), and a
        // UDP connect() to an unreachable family fails immediately with
        // ENETUNREACH — so falling through to the next candidate is cheap
        // and keeps UDP relay alive where TcpStream::connect's built-in
        // multi-address loop already keeps TCP alive.
        let mut connected = None;
        let mut last_err: Option<MeowError> = None;
        for remote in candidates {
            let bind_addr: SocketAddr = if remote.is_ipv4() {
                "0.0.0.0:0".parse().expect("static")
            } else {
                "[::]:0".parse().expect("static")
            };
            let udp = match meow_common::bind_udp(bind_addr).await {
                Ok(udp) => udp,
                Err(e) => {
                    last_err = MeowError::prefer_errno(
                        last_err,
                        MeowError::io_with(&format!("ss udp bind for {remote}"), e),
                    );
                    continue;
                }
            };
            match udp.connect(remote).await {
                Ok(()) => {
                    connected = Some((udp, remote));
                    break;
                }
                Err(e) => {
                    last_err = MeowError::prefer_errno(
                        last_err,
                        MeowError::io_with(&format!("ss udp connect {remote}"), e),
                    );
                }
            }
        }
        let Some((udp, remote)) = connected else {
            return Err(last_err
                .unwrap_or_else(|| MeowError::Proxy("ss udp connect: no candidates".into())));
        };
        let socket = ProxySocket::<TokioUdpDatagram>::from_socket(
            UdpSocketType::Client,
            Arc::clone(&self.core.context),
            &self.core.server_config,
            TokioUdpDatagram(udp),
        );
        // One SIP022 client session per association: a fresh random session
        // ID + packet counter, minted from the shared context's CSPRNG.
        let session = SsUdpSession::new(&self.core.context, self.core.server_config.method());
        debug!("SS UDP connected via {}", remote);
        Ok(Box::new(SsPacketConn {
            io: SsUdpIo::Raw(socket),
            session,
            write_target,
        }))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ─── Tokio UDP datagram adapter ─────────────────────────────────────────────
//
// `ProxySocket::<S>::from_socket` accepts any `S` that implements
// `DatagramSocket + DatagramSend + DatagramReceive`. The upstream
// `shadowsocks` crate ships these impls only for its own
// `shadowsocks::net::UdpSocket`, whose constructors all bind the underlying
// `tokio::net::UdpSocket` internally — bypassing our protect hook.
//
// `TokioUdpDatagram` is a thin newtype over `tokio::net::UdpSocket` that
// implements the three traits as straight delegates, so the SS UDP adapter
// can bind the fd through `meow_common::bind_udp` (firing the
// `SocketProtector`) and then hand the connected socket to the SS codec.

struct TokioUdpDatagram(tokio::net::UdpSocket);

impl DatagramSocket for TokioUdpDatagram {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl DatagramReceive for TokioUdpDatagram {
    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_recv(cx, buf)
    }
    fn poll_recv_from(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<SocketAddr>> {
        self.0.poll_recv_from(cx, buf)
    }
    fn poll_recv_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_recv_ready(cx)
    }
}

impl DatagramSend for TokioUdpDatagram {
    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }
    fn poll_send_to(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.poll_send_to(cx, buf, target)
    }
    fn poll_send_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::atomic::Uint;
    use std::sync::Mutex;

    #[test]
    fn sip003u_mode_extraction() {
        // Mode has no PartialEq; compare via its tcp/udp semantics.
        let sem = |m: Mode| (m.enable_tcp(), m.enable_udp());

        // Default: no opts → TcpOnly, nothing forwarded.
        let (m, o) = extract_sip003_plugin_mode(None);
        assert_eq!(sem(m), (true, false));
        assert_eq!(o, None);

        // No mode token → TcpOnly, opts preserved verbatim.
        let (m, o) = extract_sip003_plugin_mode(Some("host=a.com;path=/x"));
        assert_eq!(sem(m), (true, false));
        assert_eq!(o.as_deref(), Some("host=a.com;path=/x"));

        // SIP003u transport mode is consumed and translated; other opts kept.
        let (m, o) = extract_sip003_plugin_mode(Some("mode=tcp_and_udp;host=a.com"));
        assert_eq!(sem(m), (true, true));
        assert_eq!(o.as_deref(), Some("host=a.com"));

        let (m, o) = extract_sip003_plugin_mode(Some("mode=udp_only"));
        assert_eq!(sem(m), (false, true));
        assert_eq!(o, None, "a lone transport-mode token leaves empty opts");

        // A plugin-specific `mode` value (v2ray quic, obfs tls) is NOT consumed.
        let (m, o) = extract_sip003_plugin_mode(Some("mode=quic;host=a.com"));
        assert_eq!(
            sem(m),
            (true, false),
            "non-transport mode must not change Mode"
        );
        assert_eq!(o.as_deref(), Some("mode=quic;host=a.com"));
    }

    /// A dialer that reports itself as proxied but cannot carry UDP —
    /// stands in for a `ProxyDialer` whose front hop lacks UDP support.
    struct FakeProxyDialer;

    #[async_trait]
    impl crate::dialer::TcpDialer for FakeProxyDialer {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
            _internal: bool,
        ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
            Err(std::io::Error::other("test dialer never connects"))
        }

        fn is_proxy(&self) -> bool {
            true
        }
    }

    /// Loopback `ProxyPacketConn` playing the *server* side of the SS UDP
    /// protocol: `write_packet` decrypts the client datagram (real
    /// `crypto_io`, real key) and queues a server-side encrypted echo
    /// addressed from the client's target. Drives the whole `Chained` codec
    /// — encryption, session control, bound-remote contract — without a
    /// socket.
    struct FakeSsUdpServer {
        bound: SocketAddr,
        context: SharedContext,
        method: CipherKind,
        key: Vec<u8>,
        /// Server-side association ID (SIP0222 §3.2.3) — nonzero, or the
        /// client's `accept_reply` filter would drop the echo.
        server_session_id: u64,
        reply_packet_id: Mutex<u64>,
        /// Outer addrs `write_packet` was handed — must always be the SS
        /// server endpoint the association is bound to.
        outer: Mutex<Vec<SocketAddr>>,
        /// Decrypted inner targets + payloads the "server" received.
        inner: Mutex<Vec<(Address, Vec<u8>)>>,
        reply_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        reply_rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    impl FakeSsUdpServer {
        fn new(bound: SocketAddr, core: &SsCore) -> Self {
            let (reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
            Self {
                bound,
                context: Arc::clone(&core.context),
                method: core.server_config.method(),
                key: core.server_config.key().to_vec(),
                server_session_id: 0x5345_5256_4552_5349, // "SERVERSE"-ish
                reply_packet_id: Mutex::new(0),
                outer: Mutex::new(Vec::new()),
                inner: Mutex::new(Vec::new()),
                reply_tx,
                reply_rx: tokio::sync::Mutex::new(reply_rx),
            }
        }
    }

    #[async_trait]
    impl ProxyPacketConn for FakeSsUdpServer {
        async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            let pkt = self
                .reply_rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| MeowError::Proxy("fake ss server closed".into()))?;
            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok((n, self.bound))
        }

        async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
            use shadowsocks::relay::udprelay::crypto_io::{
                decrypt_client_payload, encrypt_server_payload,
            };
            self.outer.lock().unwrap().push(*addr);
            let mut pkt = buf.to_vec();
            let (n, target, control) =
                decrypt_client_payload(&self.context, self.method, &self.key, &mut pkt, None)
                    .map_err(|e| MeowError::Proxy(format!("fake server decrypt: {e}")))?;
            self.inner
                .lock()
                .unwrap()
                .push((target.clone(), pkt[..n].to_vec()));
            // Reply like ssserver: payload echoed, addressed from the
            // target. AEAD-2022 replies carry the echoed client session ID
            // (kept by `unwrap_or_default`) plus the server's own session
            // ID + a fresh packet ID; non-2022 methods ignore `control`.
            let mut ctrl = control.unwrap_or_default();
            ctrl.server_session_id = self.server_session_id;
            ctrl.packet_id = {
                let mut n = self.reply_packet_id.lock().unwrap();
                *n += 1;
                *n
            };
            let mut reply = bytes::BytesMut::new();
            encrypt_server_payload(
                &self.context,
                self.method,
                &self.key,
                &target,
                &ctrl,
                &pkt[..n],
                &mut reply,
            );
            let _ = self.reply_tx.send(reply.to_vec());
            Ok(buf.len())
        }

        fn local_addr(&self) -> Result<SocketAddr> {
            Ok(self.bound)
        }

        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    /// A front conn that replays a scripted `(bytes, reported_src)` queue —
    /// exercises the chained read path's drop-and-continue branches (junk
    /// ciphertext, foreign wire source) without sockets.
    struct ScriptedFront {
        remote: SocketAddr,
        script: Mutex<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>,
        written: Mutex<Vec<Vec<u8>>>,
        short_write: std::sync::atomic::AtomicBool,
    }

    impl ScriptedFront {
        fn new(remote: SocketAddr) -> Self {
            Self {
                remote,
                script: Mutex::new(std::collections::VecDeque::new()),
                written: Mutex::new(Vec::new()),
                short_write: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl ProxyPacketConn for ScriptedFront {
        async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            let Some((pkt, src)) = self.script.lock().unwrap().pop_front() else {
                // Script exhausted: park forever (a real conn would block on
                // the wire); tests close via `close`/drop.
                return std::future::pending().await;
            };
            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok((n, src))
        }

        async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
            assert_eq!(
                *addr, self.remote,
                "chained writes must go to the SS server endpoint"
            );
            self.written.lock().unwrap().push(buf.to_vec());
            if self.short_write.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(buf.len() / 2);
            }
            Ok(buf.len())
        }

        fn local_addr(&self) -> Result<SocketAddr> {
            Ok(self.remote)
        }

        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    /// Dialer variant that returns a [`ScriptedFront`] conn.
    struct ScriptedFrontDialer {
        front: Mutex<Option<Arc<ScriptedFront>>>,
    }

    #[async_trait]
    impl crate::dialer::TcpDialer for ScriptedFrontDialer {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
            _internal: bool,
        ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
            Err(std::io::Error::other("test dialer never connects"))
        }

        fn is_proxy(&self) -> bool {
            true
        }

        fn supports_udp(&self) -> bool {
            true
        }

        async fn dial_udp_conn(
            &self,
            _remote: UdpTarget,
            _internal: bool,
        ) -> std::io::Result<Arc<dyn ProxyPacketConn>> {
            self.front
                .lock()
                .unwrap()
                .clone()
                .map(|f| f as Arc<dyn ProxyPacketConn>)
                .ok_or_else(|| std::io::Error::other("no scripted front"))
        }
    }

    /// A `dialer-proxy` dialer whose UDP endpoint is [`FakeSsUdpServer`] —
    /// installed after adapter construction because the fake needs the
    /// adapter's crypto context.
    #[derive(Default)]
    struct FakeChainedDialer {
        server: Mutex<Option<Arc<FakeSsUdpServer>>>,
        dialed: Mutex<Vec<UdpTarget>>,
        /// Refuse `UdpTarget::Name` dials `Unsupported` (a front that cannot
        /// carry a domain) — exercises the caller's local-resolution
        /// fallback (issue #657).
        refuse_name: bool,
    }

    #[async_trait]
    impl crate::dialer::TcpDialer for FakeChainedDialer {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
            _internal: bool,
        ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
            Err(std::io::Error::other("test dialer never connects"))
        }

        fn is_proxy(&self) -> bool {
            true
        }

        fn supports_udp(&self) -> bool {
            true
        }

        async fn dial_udp_conn(
            &self,
            remote: UdpTarget,
            _internal: bool,
        ) -> std::io::Result<Arc<dyn ProxyPacketConn>> {
            if self.refuse_name && matches!(remote, UdpTarget::Name { .. }) {
                self.dialed.lock().unwrap().push(remote);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "front cannot carry domain targets",
                ));
            }
            self.dialed.lock().unwrap().push(remote);
            self.server
                .lock()
                .unwrap()
                .clone()
                .map(|s| s as Arc<dyn ProxyPacketConn>)
                .ok_or_else(|| std::io::Error::other("fake front has no server"))
        }
    }

    fn ss_adapter(udp: bool, dialer: Arc<dyn crate::dialer::TcpDialer>) -> ShadowsocksAdapter {
        ss_adapter_with(udp, "password", "aes-256-gcm", dialer)
    }

    fn ss_adapter_with(
        udp: bool,
        password: &str,
        cipher: &str,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> ShadowsocksAdapter {
        ShadowsocksAdapter::new(
            "ss-test",
            "127.0.0.1",
            8388,
            password,
            cipher,
            udp,
            None,
            None,
            None,
            dialer,
        )
        .expect("adapter builds")
    }

    /// Variant whose server is named by domain — exercises the
    /// `UdpTarget::Name` dial (issue #657).
    fn ss_adapter_named(
        udp: bool,
        server: &str,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> ShadowsocksAdapter {
        ShadowsocksAdapter::new(
            "ss-test",
            server,
            8388,
            "password",
            "aes-256-gcm",
            udp,
            None,
            None,
            None,
            dialer,
        )
        .expect("adapter builds")
    }

    /// Fail-closed: under a `dialer-proxy` chain the plain SS UDP relay must
    /// never reach the raw-socket path — a front that cannot carry UDP
    /// refuses the association instead of leaking the real source path.
    ///
    /// `dial_udp` is the enforcement point on purpose: routing probes do
    /// consult `support_udp` for target eligibility (tunnel.rs
    /// `RouteTargetProbe`), so the advertisement alone can steer a UDP
    /// flow to a later rule — but the dispatch path (`meow-tunnel/src/
    /// udp.rs`) calls `dial_udp` directly, so gating only the
    /// advertisement would leave the leak open for any rule that
    /// references the outbound by name.
    #[tokio::test]
    async fn chained_udp_fails_closed_when_front_cannot_carry() {
        let adapter = ss_adapter(true, Arc::new(FakeProxyDialer));

        // `ProxyPacketConn` is not `Debug`, so match rather than `expect_err`.
        // Assert the variant, not the text: `NotSupported` is the class that
        // keeps the refusal exempt from group dead-marking — a reworded
        // `Proxy` would silently break the exemption.
        match adapter.dial_udp(&Metadata::default()).await {
            Err(MeowError::NotSupported(msg)) => assert!(
                msg.contains("dialer-proxy"),
                "refusal should name dialer-proxy, got: {msg}"
            ),
            Err(e) => panic!("expected NotSupported refusal, got: {e:?}"),
            Ok(_) => panic!("chained UDP must fail when the front cannot carry it"),
        }

        assert!(
            !adapter.support_udp(),
            "advertised capability must agree: no UDP through a UDP-less front"
        );
    }

    /// The `dialer-proxy` UDP path: `dial_udp` must dial the SS server's UDP
    /// endpoint through the injected dialer (`dial_udp_conn`, never a raw
    /// socket) and run the SS crypto layer over the returned conn.
    #[tokio::test]
    async fn chained_udp_round_trips_ss_crypto_over_front_conn() {
        // AEAD-2022 exercises the `SsUdpSession` control path end-to-end:
        // the fake server echoes the client session ID and stamps its own
        // server session ID / packet counter, which `accept_reply` must
        // accept. (Password for 2022 is base64 of the 32-byte key.)
        for (password, cipher) in [
            ("password", "aes-256-gcm"),
            (
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
                "2022-blake3-aes-256-gcm",
            ),
        ] {
            let dialer = Arc::new(FakeChainedDialer::default());
            let adapter = ss_adapter_with(true, password, cipher, Arc::clone(&dialer) as _);
            assert!(
                adapter.support_udp(),
                "a UDP-capable front makes chained UDP advertised ({cipher})"
            );
            let server = Arc::new(FakeSsUdpServer::new(
                "127.0.0.1:8388".parse().unwrap(),
                &adapter.core,
            ));
            *dialer.server.lock().unwrap() = Some(Arc::clone(&server));

            let conn = adapter
                .dial_udp(&Metadata::default())
                .await
                .expect("chained dial_udp");

            // The dialer was handed the resolved SS server UDP endpoint.
            assert_eq!(
                dialer.dialed.lock().unwrap().as_slice(),
                &[UdpTarget::Addr("127.0.0.1:8388".parse().unwrap())],
            );

            let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
            // Two datagrams: the 2022 reply filter must accept increasing
            // server packet IDs within one server session.
            for payload in [b"hello chained udp".as_slice(), b"second".as_slice()] {
                conn.write_packet(payload, &target).await.expect("write");
                let mut buf = [0u8; 2048];
                let (n, src) = conn.read_packet(&mut buf).await.expect("read");
                assert_eq!(&buf[..n], payload, "{cipher}");
                assert_eq!(src, target, "reply source is the inner SS target");
            }

            // Wire shape: the front conn saw only the SS-server endpoint —
            // the real destination rode encrypted inside the SS payload.
            assert_eq!(
                server.outer.lock().unwrap().as_slice(),
                &[
                    "127.0.0.1:8388".parse().unwrap(),
                    "127.0.0.1:8388".parse().unwrap()
                ],
            );
            let inner = server.inner.lock().unwrap();
            assert_eq!(inner.len(), 2);
            assert_eq!(inner[0].0, Address::SocketAddress(target));
            assert_eq!(inner[0].1, b"hello chained udp");
        }
    }

    /// Chained read path: junk ciphertext and foreign wire sources drop
    /// per-datagram without killing the association — the filter then
    /// delivers the first valid reply.
    #[tokio::test]
    async fn chained_udp_drops_junk_and_foreign_sources() {
        let remote: SocketAddr = "127.0.0.1:8388".parse().unwrap();
        let front = Arc::new(ScriptedFront::new(remote));
        let adapter = ss_adapter(
            true,
            Arc::new(ScriptedFrontDialer {
                front: Mutex::new(Some(Arc::clone(&front))),
            }),
        );
        let conn = adapter
            .dial_udp(&Metadata::default())
            .await
            .expect("chained dial_udp");

        // Mint a server reply with the same crypto/context the server would
        // use, so the client arm's decrypt + session filter must accept it.
        let server = FakeSsUdpServer::new(remote, &adapter.core);
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut reply = bytes::BytesMut::new();
        shadowsocks::relay::udprelay::crypto_io::encrypt_server_payload(
            &server.context,
            server.method,
            &server.key,
            &Address::SocketAddress(target),
            &Default::default(),
            b"real-reply",
            &mut reply,
        );

        let foreign: SocketAddr = "9.9.9.9:1234".parse().unwrap();
        {
            let mut q = front.script.lock().unwrap();
            // 1. junk ciphertext from the right source → decrypt fails → drop
            q.push_back((vec![0xde, 0xad, 0xbe, 0xef], remote));
            // 2. valid ciphertext from a foreign source → source filter drops
            q.push_back((reply.to_vec(), foreign));
            // 3. the real reply from the bound remote → delivered
            q.push_back((reply.to_vec(), remote));
        }

        let mut buf = [0u8; 2048];
        let (n, src) = conn.read_packet(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"real-reply");
        assert_eq!(src, target);
    }

    /// Chained write path: ciphertext beyond u16::MAX is refused before the
    /// write (stream fronts frame with a u16 length — a wrap would desync),
    /// and a front that returns a short write is an error, never a silent
    /// truncation of ciphertext.
    #[tokio::test]
    async fn chained_udp_rejects_oversized_and_short_writes() {
        let remote: SocketAddr = "127.0.0.1:8388".parse().unwrap();
        let front = Arc::new(ScriptedFront::new(remote));
        let adapter = ss_adapter(
            true,
            Arc::new(ScriptedFrontDialer {
                front: Mutex::new(Some(Arc::clone(&front))),
            }),
        );
        let conn = adapter
            .dial_udp(&Metadata::default())
            .await
            .expect("chained dial_udp");

        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

        // Oversized: a u16::MAX payload encrypts to > u16::MAX under any
        // cipher's overhead — but the write must never reach the front.
        let big = vec![0u8; u16::MAX as usize];
        let writes_before = front.written.lock().unwrap().len();
        match conn.write_packet(&big, &target).await {
            Err(e) if front.written.lock().unwrap().len() == writes_before => {
                assert!(
                    format!("{e:?}").contains("u16"),
                    "expected u16 refusal: {e:?}"
                );
            }
            Err(e) => panic!("oversized datagram touched the front conn: {e:?}"),
            Ok(n) => panic!("oversized datagram reported success ({n})"),
        }

        // Short write: the front reports fewer bytes written.
        front
            .short_write
            .store(true, std::sync::atomic::Ordering::Relaxed);
        match conn.write_packet(b"payload", &target).await {
            Err(e) => {
                assert!(
                    format!("{e:?}").contains("truncat"),
                    "expected short-write error: {e:?}"
                );
            }
            Ok(n) => panic!("short write reported success ({n})"),
        }
    }

    /// A domain-named SS server dials the front as `UdpTarget::Name` — the
    /// front resolves the server with the same view that carried the TCP
    /// leg, closing the split-horizon/GeoDNS divergence (issue #657).
    #[tokio::test]
    async fn chained_udp_domain_server_dials_name_target() {
        let dialer = Arc::new(FakeChainedDialer::default());
        let adapter = ss_adapter_named(true, "localhost", Arc::clone(&dialer) as _);
        let server = Arc::new(FakeSsUdpServer::new(
            "127.0.0.1:8388".parse().unwrap(),
            &adapter.core,
        ));
        *dialer.server.lock().unwrap() = Some(server);

        let conn = adapter
            .dial_udp(&Metadata::default())
            .await
            .expect("chained dial_udp");

        assert_eq!(
            dialer.dialed.lock().unwrap().as_slice(),
            &[UdpTarget::Name {
                host: "localhost".into(),
                port: 8388
            }],
            "domain server must reach the front as a name, not a local resolution"
        );

        // Writes take the advisory placeholder dst; replies filtered by
        // port only (the front's resolution legitimately differs from ours).
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        conn.write_packet(b"ping", &target).await.expect("write");
        let mut buf = [0u8; 2048];
        let (n, src) = conn.read_packet(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(src, target);
    }

    /// A front that cannot carry a domain target answers `Unsupported`;
    /// the adapter resolves the name locally and redials the literal —
    /// the pre-#657 behavior, still fail-closed through the chain.
    #[tokio::test]
    async fn chained_udp_name_unsupported_falls_back_to_literal() {
        let dialer = Arc::new(FakeChainedDialer {
            refuse_name: true,
            ..Default::default()
        });
        let adapter = ss_adapter_named(true, "localhost", Arc::clone(&dialer) as _);
        let server = Arc::new(FakeSsUdpServer::new(
            "127.0.0.1:8388".parse().unwrap(),
            &adapter.core,
        ));
        *dialer.server.lock().unwrap() = Some(server);

        let _conn = adapter
            .dial_udp(&Metadata::default())
            .await
            .expect("name refusal falls back to a local literal dial");

        let dialed = dialer.dialed.lock().unwrap().clone();
        assert_eq!(dialed.len(), 2, "name attempt, then literal retry");
        assert_eq!(
            dialed[0],
            UdpTarget::Name {
                host: "localhost".into(),
                port: 8388
            }
        );
        let UdpTarget::Addr(addr) = dialed[1] else {
            panic!("fallback must dial a literal, got {:?}", dialed[1]);
        };
        assert!(addr.ip().is_loopback(), "localhost resolves loopback");
        assert_eq!(addr.port(), 8388);
    }

    /// This adapter as a *front*: host-only metadata (the dialer layer's
    /// encoding of `UdpTarget::Name`) stamps the *inner* SS payload target
    /// with the domain so the SS server resolves it — while the front
    /// conn's wire destination stays the SS server endpoint (issue #657).
    #[tokio::test]
    async fn front_udp_domain_target_encrypts_domain_inner() {
        let remote: SocketAddr = "127.0.0.1:8388".parse().unwrap();
        let front = Arc::new(ScriptedFront::new(remote));
        let adapter = ss_adapter(
            true,
            Arc::new(ScriptedFrontDialer {
                front: Mutex::new(Some(Arc::clone(&front))),
            }),
        );
        // The dialer-layer encoding of `UdpTarget::Name`: host set, no dst_ip.
        let meta = Metadata {
            network: meow_common::Network::Udp,
            host: "back.internal".into(),
            dst_port: 8388,
            ..Default::default()
        };
        let conn = adapter.dial_udp(&meta).await.expect("front dial_udp");
        // The caller holds no literal — its write arg is the placeholder.
        conn.write_packet(b"payload", &"0.0.0.0:8388".parse().unwrap())
            .await
            .expect("write");

        // One ciphertext frame went to the SS server endpoint on the wire...
        let written = front.written.lock().unwrap().clone();
        assert_eq!(written.len(), 1);
        // ...and decrypts to a *domain* target addressed to back.internal.
        use shadowsocks::relay::udprelay::crypto_io::decrypt_client_payload;
        let mut pkt = written[0].clone();
        let (n, target, _ctrl) = decrypt_client_payload(
            &adapter.core.context,
            adapter.core.server_config.method(),
            adapter.core.server_config.key(),
            &mut pkt,
            None,
        )
        .expect("frame decrypts");
        assert_eq!(&pkt[..n], b"payload");
        assert_eq!(
            target,
            Address::DomainNameAddress("back.internal".to_string(), 8388),
            "inner SS target must carry the domain, not the advisory arg"
        );
    }

    /// Every built-in TCP-only plugin must refuse `dial_udp` and name
    /// itself in the refusal — the tunnel's UDP dispatch never consults
    /// `support_udp`, so this is the enforcement seam.
    ///
    /// `mux=false` on the gost fixture keeps it valid under a
    /// `ss`-without-`mux` build (the upstream mux default is a parse
    /// error there).
    #[tokio::test]
    async fn builtin_tcp_plugins_refuse_udp() {
        for (plugin, opts, tag) in [
            ("v2ray-plugin", "host=cdn.example.com", "v2ray-plugin"),
            (
                "gost-plugin",
                "mode=websocket;mux=false;host=cdn.example.com",
                "gost-plugin",
            ),
            (
                "shadow-tls",
                "host=cover.example.com;password=p;version=2",
                "shadow-tls",
            ),
            (
                "restls",
                "host=cover.example.com;password=p;version-hint=tls13",
                "restls",
            ),
            ("jls", "host=cover.example.com;username=u;password=p", "jls"),
        ] {
            let adapter = ShadowsocksAdapter::new(
                "ss-test",
                "127.0.0.1",
                8388,
                "password",
                "aes-256-gcm",
                true,
                Some(plugin),
                Some(opts),
                None,
                Arc::new(crate::dialer::DirectDialer),
            )
            .unwrap_or_else(|e| panic!("{plugin} adapter builds: {e}"));
            assert!(
                !adapter.support_udp(),
                "{plugin} must not advertise UDP it will refuse"
            );
            match adapter.dial_udp(&Metadata::default()).await {
                Err(MeowError::NotSupported(m)) => assert!(
                    m.contains(tag),
                    "{plugin} refusal should name itself, got: {m}"
                ),
                Err(e) => panic!("{plugin} must refuse UDP with NotSupported, got: {e}"),
                Ok(_) => panic!("{plugin} must refuse UDP, got Ok"),
            }
        }
    }

    /// A relay-supplied stream already terminates at the real SS server —
    /// a built-in transport that owns its TCP dial (shadow-tls) must fail
    /// loudly on `connect_over` rather than send unwrapped SS traffic
    /// through the front hop.
    #[tokio::test]
    async fn shadow_tls_refuses_relay_supplied_stream() {
        let adapter = ShadowsocksAdapter::new(
            "ss-test",
            "127.0.0.1",
            8388,
            "password",
            "aes-256-gcm",
            true,
            Some("shadow-tls"),
            Some("host=cover.example.com;password=p;version=2"),
            None,
            Arc::new(crate::dialer::DirectDialer),
        )
        .expect("shadow-tls adapter builds");
        let (stream, _peer) = tokio::io::duplex(64);
        let stream = crate::stream_conn::StreamConn(Box::new(stream));
        match adapter
            .connect_over(Box::new(stream), &Metadata::default())
            .await
        {
            Err(MeowError::NotSupported(m)) => {
                assert!(m.contains("shadow-tls"), "refusal names itself: {m}");
            }
            Err(e) => panic!("expected NotSupported, got: {e}"),
            Ok(_) => panic!("shadow-tls must refuse a relay-supplied stream"),
        }
    }

    /// SIP022 §3.2.2/§3.2.4: a client session mints a non-zero ID, counts
    /// packets up, and filters replies — echo match, replay drop, and
    /// server-session rotation resetting the window.
    #[test]
    fn ss_udp_session_allocates_ids_and_filters_replies() {
        let ctx = Context::new_shared(ServerType::Local);
        let session = SsUdpSession::new(&ctx, "2022-blake3-aes-256-gcm".parse().unwrap());
        assert_ne!(session.client_session_id, 0);

        let c0 = session.send_control().unwrap();
        let c1 = session.send_control().unwrap();
        assert_eq!(c0.client_session_id, session.client_session_id);
        assert_eq!(
            c0.packet_id, 1,
            "packet IDs are pre-incremented, sslocal-style"
        );
        assert_eq!(c1.packet_id, 2, "client packet IDs count up per session");

        let mut reply = UdpSocketControlData::default();
        reply.client_session_id = session.client_session_id;
        reply.server_session_id = 77;
        reply.packet_id = 0;
        assert!(session.accept_reply(&reply));
        assert!(
            !session.accept_reply(&reply),
            "replayed server packet dropped"
        );

        let mut foreign = reply.clone();
        foreign.client_session_id = 0xdead_beef;
        foreign.packet_id = 9;
        assert!(
            !session.accept_reply(&foreign),
            "an echo for a different client session is not ours"
        );
        // A foreign echo must not have touched session 77's window.
        reply.packet_id = 9;
        assert!(session.accept_reply(&reply));

        // Server-session rotation (a restart legitimately re-keys): a fresh
        // ID gets its own window — reusing packet IDs is legal under it.
        reply.server_session_id = 88;
        reply.packet_id = 0;
        assert!(session.accept_reply(&reply));

        // Interleaved sessions keep independent windows: flapping back to
        // 77 must NOT re-accept its already-seen packet IDs.
        reply.server_session_id = 77;
        reply.packet_id = 0;
        assert!(
            !session.accept_reply(&reply),
            "session 77's window survives the flap"
        );
        reply.packet_id = 10;
        assert!(session.accept_reply(&reply));

        // `server_session_id == 0` is the reserved "no session" sentinel:
        // it never opens a window.
        reply.server_session_id = 0;
        reply.packet_id = 42;
        assert!(
            !session.accept_reply(&reply),
            "the 0 sentinel is rejected outright"
        );
    }

    /// The client packet-ID space is terminal rather than wrapping:
    /// `send_control` returns `None` once exhausted (32-bit targets run out
    /// at 2^32 datagrams) so the caller can error the association and the
    /// next datagram re-dials under a fresh session — and the space never
    /// emits `Uint::MAX`, the window's always-reject sentinel.
    #[test]
    fn send_control_none_on_exhaustion() {
        let ctx = Context::new_shared(ServerType::Local);
        let session = SsUdpSession::new(&ctx, "2022-blake3-aes-256-gcm".parse().unwrap());
        session
            .next_packet_id
            .store(Uint::MAX - 1, std::sync::atomic::Ordering::Relaxed);
        assert!(
            session.send_control().is_none(),
            "an exhausted packet-ID space errors the association"
        );
        assert_eq!(
            session
                .next_packet_id
                .load(std::sync::atomic::Ordering::Relaxed),
            Uint::MAX - 1,
            "the counter stays terminal rather than wrapping to 0"
        );
    }

    /// §3.2.4: reaching [`MAX_TRACKED_SERVER_SESSIONS`] evicts the least
    /// recently used window only — never clears the table. A `clear()`
    /// would let an on-path attacker replay N distinct captured
    /// server-session IDs to re-open every window at once; per-entry
    /// eviction bounds the damage to the single evicted session.
    #[test]
    fn server_reply_tracker_evicts_lru_not_all() {
        let ctx = Context::new_shared(ServerType::Local);
        let session = SsUdpSession::new(&ctx, "2022-blake3-aes-256-gcm".parse().unwrap());
        let reply = |ssid: u64, pid: u64| {
            let mut c = UdpSocketControlData::default();
            c.client_session_id = session.client_session_id;
            c.server_session_id = ssid;
            c.packet_id = pid;
            c
        };

        // Fill the table: server sessions 1..=4 each record packet ID 5.
        for s in 1..=MAX_TRACKED_SERVER_SESSIONS as u64 {
            assert!(session.accept_reply(&reply(s, 5)));
        }

        // A fifth distinct session ID evicts exactly the LRU entry
        // (session 1) — every other window must keep its state.
        assert!(session.accept_reply(&reply(5, 5)));
        for s in 2..=4u64 {
            assert!(
                !session.accept_reply(&reply(s, 5)),
                "session {s}'s window must survive the LRU eviction"
            );
        }

        // The evicted session is the only one whose recorded IDs are
        // re-accepted — the bounded blast radius of per-entry eviction.
        assert!(
            session.accept_reply(&reply(1, 5)),
            "only the evicted LRU window forgets its IDs"
        );
    }

    /// The same adapter with the default direct dialer keeps advertising UDP —
    /// the guard must not regress the non-chained path.
    #[test]
    fn plain_udp_still_advertised_under_direct_dialer() {
        assert!(ss_adapter(true, Arc::new(crate::dialer::DirectDialer)).support_udp());
        assert!(!ss_adapter(false, Arc::new(crate::dialer::DirectDialer)).support_udp());
    }

    #[test]
    fn test_is_builtin_obfs_plugin_accepts_aliases() {
        assert!(is_builtin_obfs_plugin("obfs"));
        assert!(is_builtin_obfs_plugin("simple-obfs"));
        assert!(!is_builtin_obfs_plugin("v2ray-plugin"));
        assert!(!is_builtin_obfs_plugin("gost-plugin"));
        assert!(!is_builtin_obfs_plugin("OBFS"));
        assert!(!is_builtin_obfs_plugin(""));
    }

    #[test]
    fn test_parse_obfs_opts_http_yaml_keys() {
        // YAML map form serializes to `mode=http;host=foo`.
        let got = parse_obfs_opts(Some("mode=http;host=bing.com"), "1.2.3.4").unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "bing.com"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_tls_yaml_keys() {
        let got = parse_obfs_opts(Some("mode=tls;host=gateway.icloud.com"), "1.2.3.4").unwrap();
        match got {
            BuiltinObfs::Tls { server } => assert_eq!(server, "gateway.icloud.com"),
            _ => panic!("expected Tls"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_sip003_alias_keys() {
        // Native SIP003 keys (`obfs`/`obfs-host`).
        let got = parse_obfs_opts(Some("obfs=http;obfs-host=cloudflare.com"), "1.2.3.4").unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "cloudflare.com"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_rejects_ctl_host() {
        // `host` lands verbatim in the emitted `Host:` header (http) or SNI
        // (tls) — provider-supplied CTLs and oversized names must not parse
        // (issue #648). An embedded `;`/`=` is already unusable as a value
        // (the tokenizer splits there), so CTLs are the injection vector.
        for opts in [
            "mode=http;host=a\rb\nc",
            "mode=tls;obfs-host=a\0b",
            "mode=http;host=a\tb",
        ] {
            assert!(
                parse_obfs_opts(Some(opts), "1.2.3.4").is_err(),
                "{opts:?} must be rejected"
            );
        }
        let overlong = format!("mode=http;host={}", "a".repeat(254));
        assert!(parse_obfs_opts(Some(&overlong), "1.2.3.4").is_err());
        let at_limit = format!("mode=http;host={}", "a".repeat(253));
        assert!(parse_obfs_opts(Some(&at_limit), "1.2.3.4").is_ok());
    }

    #[test]
    fn test_parse_obfs_opts_mode_is_case_insensitive() {
        let http = parse_obfs_opts(Some("mode=HTTP;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(http, BuiltinObfs::Http { .. }));
        let tls = parse_obfs_opts(Some("mode=TLS;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(tls, BuiltinObfs::Tls { .. }));
        let mixed = parse_obfs_opts(Some("mode=TlS;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(mixed, BuiltinObfs::Tls { .. }));
    }

    #[test]
    fn test_parse_obfs_opts_extra_whitespace() {
        // Tolerate whitespace around `;` and `=`, similar to the Go reference.
        let got = parse_obfs_opts(Some("  mode = http ;  host = bing.com  "), "1.2.3.4").unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "bing.com"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_unknown_keys_ignored() {
        // Forward-compat: unknown keys must be silently dropped.
        let got = parse_obfs_opts(
            Some("mode=http;host=foo;fastopen=1;something=else"),
            "1.2.3.4",
        )
        .unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "foo"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_missing_host_falls_back_to_server() {
        let got = parse_obfs_opts(Some("mode=http"), "ss.example.org").unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "ss.example.org"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_empty_host_falls_back_to_server() {
        let got = parse_obfs_opts(Some("mode=tls;host="), "ss.example.org").unwrap();
        match got {
            BuiltinObfs::Tls { server } => assert_eq!(server, "ss.example.org"),
            _ => panic!("expected Tls"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_missing_mode_errors() {
        let err = parse_obfs_opts(Some("host=bing.com"), "1.2.3.4").unwrap_err();
        match err {
            MeowError::Config(msg) => assert!(
                msg.contains("mode=http") || msg.contains("mode=tls"),
                "error message should mention valid modes: {msg}"
            ),
            _ => panic!("expected Config error"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_empty_opts_errors() {
        // Empty / missing opts is also "no mode" — must error.
        assert!(parse_obfs_opts(None, "1.2.3.4").is_err());
        assert!(parse_obfs_opts(Some(""), "1.2.3.4").is_err());
        assert!(parse_obfs_opts(Some("   "), "1.2.3.4").is_err());
    }

    #[test]
    fn test_parse_obfs_opts_invalid_mode_errors() {
        let err = parse_obfs_opts(Some("mode=quic;host=foo"), "1.2.3.4").unwrap_err();
        match err {
            MeowError::Config(msg) => {
                assert!(msg.contains("quic"), "error should mention bad mode: {msg}");
                assert!(
                    msg.contains("http") && msg.contains("tls"),
                    "error should hint valid modes: {msg}"
                );
            }
            _ => panic!("expected Config error"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_yaml_overrides_sip003_when_both_present() {
        // If both `mode=` and `obfs=` are passed (unusual but legal), the last
        // one wins after iteration order. Document the behavior so future
        // changes notice if it breaks: with the current parser, `obfs` and
        // `mode` are aliases, so the latter parsed wins.
        let got = parse_obfs_opts(Some("mode=http;obfs=tls;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(got, BuiltinObfs::Tls { .. }));
        let got = parse_obfs_opts(Some("obfs=tls;mode=http;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(got, BuiltinObfs::Http { .. }));
    }

    /// The shadowsocks crate `assert!`s `domain.len() <= u8::MAX` while
    /// serializing — a >255-byte target must error, never panic (issue #657
    /// review; the TCP `parse_address` hole predates the UDP path).
    #[test]
    fn parse_address_rejects_oversized_domain() {
        let meta = Metadata {
            host: "a".repeat(256).into(),
            dst_port: 443,
            ..Default::default()
        };
        let Err(e) = parse_address(&meta) else {
            panic!("256-byte domain must error");
        };
        assert!(matches!(e, MeowError::NotSupported(_)), "{e:?}");

        // 255 stays encodable.
        let meta = Metadata {
            host: "a".repeat(255).into(),
            dst_port: 443,
            ..Default::default()
        };
        assert!(matches!(
            parse_address(&meta),
            Ok(Address::DomainNameAddress(..))
        ));
    }

    /// Front role: a chained `UdpTarget::Name` arrives as host-only UDP
    /// metadata — an oversized name must refuse `NotSupported` (so the
    /// caller falls back to a literal `Addr`) rather than trip the crate's
    /// assert during packet encode.
    #[tokio::test]
    async fn front_udp_refuses_oversized_domain_target() {
        let adapter = ss_adapter_named(true, "127.0.0.1", Arc::new(FakeProxyDialer));
        let meta = Metadata {
            network: meow_common::Network::Udp,
            host: "a".repeat(256).into(),
            dst_port: 8388,
            ..Default::default()
        };
        let Err(e) = adapter.dial_udp(&meta).await else {
            panic!("oversized domain target must error");
        };
        assert!(matches!(e, MeowError::NotSupported(_)), "{e:?}");
    }
}

/// [`SsConn`]'s deferred-header handling against an in-process
/// `ProxyServerStream` over an in-memory duplex. The clock is paused, so it
/// only moves when every task is idle (or on `advance`): the window expires
/// at exactly [`SS_HEADER_WINDOW`] of virtual time.
#[cfg(test)]
mod ss_conn_tests {
    use super::*;
    use shadowsocks::relay::tcprelay::proxy_stream::ProxyServerStream;
    use std::io;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::time::{timeout, Instant};

    type Cipher = (&'static str, &'static str);
    const AEAD: Cipher = ("aes-128-gcm", "server-first-test");
    /// 16-byte iPSK ("1234567890123456"), base64.
    const AEAD_2022: Cipher = ("2022-blake3-aes-128-gcm", "MTIzNDU2Nzg5MDEyMzQ1Ng==");
    const BANNER: &[u8] = b"220 smtp.test ESMTP ready\r\n";
    /// Virtual-time bound for an exchange: without a header the client
    /// waits forever, and the paused clock jumps straight to this.
    const DEADLINE: Duration = Duration::from_secs(5);

    fn target() -> Address {
        Address::DomainNameAddress("smtp.test".into(), 25)
    }

    fn server_config((method, key): Cipher) -> ServerConfig {
        ServerConfig::new(("127.0.0.1", 8388), key, method.parse().unwrap()).unwrap()
    }

    fn server_stream(cipher: Cipher, io: DuplexStream) -> ProxyServerStream<DuplexStream> {
        let cfg = server_config(cipher);
        ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server),
            io,
            cfg.method(),
            cfg.key(),
        )
    }

    /// Transport under the SS codec: records the size of every completed
    /// write, i.e. each encrypted chunk (or chunk prefix) put on the wire.
    struct Recorder {
        inner: DuplexStream,
        writes: Arc<Mutex<Vec<usize>>>,
    }

    impl AsyncRead for Recorder {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let res = Pin::new(&mut self.inner).poll_write(cx, buf);
            if let Poll::Ready(Ok(n)) = res {
                self.writes.lock().unwrap().push(n);
            }
            res
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct Pair {
        client: SsConn<Recorder>,
        writes: Arc<Mutex<Vec<usize>>>,
        server: ProxyServerStream<DuplexStream>,
    }

    /// A client `SsConn` and the matching server stream over a duplex pipe
    /// holding at most `capacity` bytes per direction.
    fn pair(cipher: Cipher, capacity: usize) -> Pair {
        let (c, s) = tokio::io::duplex(capacity);
        let writes = Arc::new(Mutex::new(Vec::new()));
        let transport = Recorder {
            inner: c,
            writes: Arc::clone(&writes),
        };
        let client = SsConn::new(ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local),
            transport,
            &server_config(cipher),
            target(),
        ));
        Pair {
            client,
            writes,
            server: server_stream(cipher, s),
        }
    }

    fn recorded(writes: &Mutex<Vec<usize>>) -> Vec<usize> {
        writes.lock().unwrap().clone()
    }

    /// Poll the client's read side exactly once, like one relay turn.
    async fn poll_read_once<R: AsyncRead + Unpin>(conn: &mut R) -> Poll<io::Result<usize>> {
        let mut storage = [0u8; 64];
        std::future::poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut storage);
            Poll::Ready(
                Pin::new(&mut *conn)
                    .poll_read(cx, &mut rb)
                    .map_ok(|()| rb.filled().len()),
            )
        })
        .await
    }

    /// SMTP-like server: greets as soon as the request header names the
    /// target, before the client sent a byte, then answers one line.
    async fn smtp_server(mut server: ProxyServerStream<DuplexStream>) -> io::Result<()> {
        let addr = server.handshake().await?;
        assert_eq!(addr, target());
        server.write_all(BANNER).await?;
        server.flush().await?;
        let mut line = [0u8; 6];
        server.read_exact(&mut line).await?;
        assert_eq!(&line, b"QUIT\r\n");
        server.write_all(b"221 bye\r\n").await?;
        server.flush().await
    }

    /// shadowsocks 1.24 draws the AEAD-2022 padding of a payload-less
    /// header from `0..=900` (`relay/mod.rs` `get_aead_2022_padding_size`),
    /// while its own server rejects a payload-less header with zero padding
    /// — 1 in 901 header-only requests fails upstream. Not this adapter's
    /// bug: tests re-run that exchange rather than flake.
    fn is_zero_padding_reject(e: &io::Error) -> bool {
        e.to_string().contains("padding is 0")
    }

    /// One server-first exchange through `conn`, which has written nothing
    /// yet. `None`: the server hit the upstream zero-padding reject.
    async fn banner_exchange<C: AsyncRead + AsyncWrite + Unpin>(
        conn: &mut C,
        server: tokio::task::JoinHandle<io::Result<()>>,
        writes: Option<&Mutex<Vec<usize>>>,
    ) -> Option<()> {
        let start = Instant::now();
        let mut banner = vec![0u8; BANNER.len()];
        let read = timeout(DEADLINE, conn.read_exact(&mut banner))
            .await
            .expect("banner never arrived: the SS request header was never sent");
        let elapsed = start.elapsed();
        if read.is_err() {
            match server.await.unwrap() {
                Err(e) if is_zero_padding_reject(&e) => return None,
                other => panic!("banner read failed: {read:?}; server: {other:?}"),
            }
        }
        assert_eq!(banner, BANNER);
        assert!(
            elapsed >= SS_HEADER_WINDOW,
            "header must wait out the window for a first payload: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(2), "banner took {elapsed:?}");
        if let Some(w) = writes {
            assert_eq!(recorded(w).len(), 1, "the header goes out as one write");
            // Once the header is out, an empty write is a no-op on the wire.
            assert_eq!(conn.write(&[]).await.unwrap(), 0);
            assert_eq!(
                recorded(w).len(),
                1,
                "an empty write after the header must not emit an empty AEAD chunk"
            );
        }
        conn.write_all(b"QUIT\r\n").await.unwrap();
        conn.flush().await.unwrap();
        let mut bye = [0u8; 9];
        conn.read_exact(&mut bye).await.unwrap();
        assert_eq!(&bye, b"221 bye\r\n");
        if let Some(w) = writes {
            assert_eq!(recorded(w).len(), 2, "QUIT is a chunk of its own");
        }
        server.await.unwrap().unwrap();
        Some(())
    }

    /// The client never writes before the banner (SMTP/FTP/IMAP/MySQL...):
    /// the header goes out alone once the window expires, the banner
    /// arrives, and the connection carries data both ways afterwards.
    async fn server_first(cipher: Cipher) {
        for _ in 0..3 {
            let Pair {
                mut client,
                writes,
                server,
            } = pair(cipher, 64 * 1024);
            let server = tokio::spawn(smtp_server(server));
            if banner_exchange(&mut client, server, Some(&writes))
                .await
                .is_some()
            {
                return;
            }
        }
        panic!("three zero-padding rejects in a row");
    }

    #[tokio::test(start_paused = true)]
    async fn server_first_banner_arrives_after_window_aead() {
        server_first(AEAD).await;
    }

    #[tokio::test(start_paused = true)]
    async fn server_first_banner_arrives_after_window_aead_2022() {
        server_first(AEAD_2022).await;
    }

    /// The relay reads the remote side first, which arms the window; a
    /// first payload inside it still carries the header in the same single
    /// write, and the expired window adds nothing afterwards.
    async fn client_first(cipher: Cipher) {
        let Pair {
            mut client,
            writes,
            mut server,
        } = pair(cipher, 64 * 1024);
        const HELLO: &[u8] = b"EHLO client-first\r\n";
        let echo = tokio::spawn(async move {
            assert_eq!(server.handshake().await?, target());
            let mut buf = [0u8; 64];
            let n = server.read(&mut buf).await?;
            server.write_all(&buf[..n]).await?;
            server.flush().await?;
            // Nothing else may arrive before the client's EOF.
            server.read(&mut buf).await
        });

        assert!(poll_read_once(&mut client).await.is_pending());
        tokio::time::advance(SS_HEADER_WINDOW / 2).await;
        client.write_all(HELLO).await.unwrap();
        client.flush().await.unwrap();
        assert_eq!(
            recorded(&writes).len(),
            1,
            "header and first payload must leave in one write"
        );
        let mut back = [0u8; HELLO.len()];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(back, HELLO);

        tokio::time::advance(SS_HEADER_WINDOW * 5).await;
        assert!(poll_read_once(&mut client).await.is_pending());
        assert_eq!(client.write(&[]).await.unwrap(), 0);
        assert_eq!(
            recorded(&writes).len(),
            1,
            "no header-only or empty chunk after the coalesced first write"
        );
        client.shutdown().await.unwrap();
        assert_eq!(echo.await.unwrap().unwrap(), 0, "server saw extra bytes");
    }

    #[tokio::test(start_paused = true)]
    async fn client_first_payload_coalesces_header_aead() {
        client_first(AEAD).await;
    }

    #[tokio::test(start_paused = true)]
    async fn client_first_payload_coalesces_header_aead_2022() {
        client_first(AEAD_2022).await;
    }

    /// An explicit empty write still asks for the header (the crate's
    /// documented hook), once; a second one must not put an empty AEAD
    /// chunk on the wire.
    #[tokio::test(start_paused = true)]
    async fn explicit_empty_write_sends_header_once() {
        let Pair {
            mut client,
            writes,
            mut server,
        } = pair(AEAD, 64 * 1024);
        assert_eq!(client.write(&[]).await.unwrap(), 0);
        client.flush().await.unwrap();
        assert_eq!(
            recorded(&writes).len(),
            1,
            "empty first write sends the header"
        );
        assert_eq!(client.write(&[]).await.unwrap(), 0);
        client.flush().await.unwrap();
        assert_eq!(
            recorded(&writes).len(),
            1,
            "a second empty write must not emit an empty AEAD chunk"
        );
        assert_eq!(server.handshake().await.unwrap(), target());
    }

    /// The header-only write stalls on a full pipe and the caller's first
    /// payload arrives meanwhile. While stalled the crate ignores the buffer
    /// it is handed and would report the payload written — it must instead
    /// go out intact after the header.
    #[tokio::test(start_paused = true)]
    async fn stalled_header_write_keeps_first_payload() {
        // 16 bytes cannot hold even the AEAD salt plus the length chunk.
        let Pair {
            mut client,
            writes,
            mut server,
        } = pair(AEAD, 16);
        assert!(poll_read_once(&mut client).await.is_pending());
        tokio::time::advance(SS_HEADER_WINDOW).await;
        assert!(poll_read_once(&mut client).await.is_pending());
        assert_eq!(
            recorded(&writes),
            [16],
            "the expired window starts the header-only write"
        );

        let srv = tokio::spawn(async move {
            let addr = server.handshake().await?;
            let mut buf = [0u8; 7];
            server.read_exact(&mut buf).await?;
            io::Result::Ok((addr, buf))
        });
        client.write_all(b"payload").await.unwrap();
        client.flush().await.unwrap();
        let (addr, got) = timeout(DEADLINE, srv)
            .await
            .expect("first payload was swallowed by the stalled header write")
            .unwrap()
            .unwrap();
        assert_eq!(addr, target());
        assert_eq!(&got, b"payload");
    }

    /// A caller that closes without writing sends no header, as before, and
    /// the expired window must not write after the shutdown (that would
    /// fail the read side with a write error).
    #[tokio::test(start_paused = true)]
    async fn shutdown_before_first_write_sends_nothing() {
        let Pair {
            mut client,
            writes,
            mut server,
        } = pair(AEAD, 64 * 1024);
        assert!(poll_read_once(&mut client).await.is_pending());
        client.shutdown().await.unwrap();
        tokio::time::advance(SS_HEADER_WINDOW * 2).await;
        assert!(poll_read_once(&mut client).await.is_pending());
        assert!(recorded(&writes).is_empty());
        assert!(server.handshake().await.is_err(), "EOF before any header");
    }

    /// Relay-chain last hop: `connect_over` must return the same
    /// server-first-aware conn as a direct dial.
    #[tokio::test(start_paused = true)]
    async fn connect_over_sends_header_for_server_first() {
        let adapter = ShadowsocksAdapter::new(
            "ss-test",
            "127.0.0.1",
            8388,
            AEAD.1,
            AEAD.0,
            false,
            None,
            None,
            None,
            Arc::new(crate::dialer::DirectDialer),
        )
        .unwrap();
        let meta = Metadata {
            host: "smtp.test".into(),
            dst_port: 25,
            ..Default::default()
        };
        let (c, s) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(smtp_server(server_stream(AEAD, s)));
        let mut conn = adapter
            .connect_over(Box::new(crate::stream_conn::StreamConn(Box::new(c))), &meta)
            .await
            .unwrap();
        assert!(banner_exchange(&mut conn, server, None).await.is_some());
    }
}
