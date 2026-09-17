#[cfg(feature = "ech-tls-tunnel")]
use crate::ech_tls_tunnel::{self, EchTlsTunnelConfig};
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
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket, ProxySocket};
use shadowsocks::relay::Address;
use shadowsocks::ProxyClientStream;
use smol_str::SmolStr;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::debug;

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
#[allow(clippy::large_enum_variant)]
enum PluginKind {
    None,
    /// External SIP003 plugin subprocess. The `Plugin` handle keeps the
    /// subprocess alive for the adapter's lifetime.
    External(#[allow(dead_code)] Plugin),
    Obfs(BuiltinObfs),
    V2ray(V2rayPluginConfig, Option<TlsLayer>),
    #[cfg(feature = "ech-tls-tunnel")]
    EchTlsTunnel(EchTlsTunnelConfig, TlsLayer),
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        cipher: &str,
        udp: bool,
        plugin_name: Option<&str>,
        plugin_opts: Option<&str>,
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
                core.dial_tcp_stream(addr).await
            })
        });
        self.mux = Some(MuxClient::new(dial, options));
        self
    }
}

impl SsCore {
    /// Dial a raw (or plugin-transported) TCP stream to the SS server and
    /// wrap it in the SS crypto codec for the given target address.
    async fn dial_tcp_stream(&self, addr: Address) -> Result<Box<dyn ProxyConn>> {
        match &self.plugin {
            PluginKind::Obfs(obfs) => {
                // Open a raw TCP connection to the SS server, wrap it in the
                // simple-obfs codec, then layer the SS crypto stream on top.
                let tcp = self
                    .dialer
                    .dial(&self.server, self.port)
                    .await
                    .map_err(|e| MeowError::Proxy(format!("ss obfs tcp connect: {e}")))?;

                match obfs.clone() {
                    BuiltinObfs::Http { host } => {
                        let wrapped = HttpObfs::new(tcp, host, self.port);
                        let stream = ProxyClientStream::from_stream(
                            Arc::clone(&self.context),
                            wrapped,
                            &self.server_config,
                            addr,
                        );
                        Ok(Box::new(SsConn(stream)))
                    }
                    BuiltinObfs::Tls { server } => {
                        let wrapped = TlsObfs::new(tcp, server);
                        let stream = ProxyClientStream::from_stream(
                            Arc::clone(&self.context),
                            wrapped,
                            &self.server_config,
                            addr,
                        );
                        Ok(Box::new(SsConn(stream)))
                    }
                }
            }
            PluginKind::V2ray(cfg, tls) => {
                let transport =
                    v2ray_plugin::dial(cfg, tls.as_ref(), &self.server, self.port, &*self.dialer)
                        .await?;
                let stream = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    transport,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(stream)))
            }
            #[cfg(feature = "ech-tls-tunnel")]
            PluginKind::EchTlsTunnel(cfg, tls) => {
                let transport =
                    ech_tls_tunnel::dial(cfg, tls, &self.server, self.port, &*self.dialer).await?;
                let stream = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    transport,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(stream)))
            }
            PluginKind::None => {
                // Dial the remote SS server through the pluggable dialer
                // (direct or via ``dialer-proxy``).  ``connect_tcp_host`` is
                // resolver-aware and SocketProtector-aware (Android
                // ``VpnService.protect(fd)``), and ``DirectDialer`` preserves
                // both of those properties.
                let tcp = match self.server_config.tcp_external_addr() {
                    ServerAddr::SocketAddr(sa) => self.dialer.dial_addr(*sa).await,
                    ServerAddr::DomainName(host, port) => self.dialer.dial(host, *port).await,
                }
                .map_err(|e| MeowError::Proxy(format!("ss tcp connect: {e}")))?;
                let stream = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    tcp,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(stream)))
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
                .map_err(|e| MeowError::Proxy(format!("ss plugin tcp connect: {e}")))?;
                let stream = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    tcp,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(stream)))
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
            PluginKind::None => {
                let s = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    stream,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(s)))
            }
            PluginKind::Obfs(obfs) => {
                let stream = match obfs.clone() {
                    BuiltinObfs::Http { host } => Box::new(HttpObfs::new(stream, host, self.port))
                        as Box<dyn meow_transport::Stream>,
                    BuiltinObfs::Tls { server } => {
                        Box::new(TlsObfs::new(stream, server)) as Box<dyn meow_transport::Stream>
                    }
                };
                let s = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    stream,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(s)))
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
                let s = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    transport,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(s)))
            }
            #[cfg(feature = "ech-tls-tunnel")]
            PluginKind::EchTlsTunnel(cfg, tls) => {
                let transport =
                    ech_tls_tunnel::handshake_over(cfg, tls, &self.server, self.port, stream)
                        .await?;
                let s = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    transport,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(s)))
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
    match mode.as_str() {
        "http" => Ok(BuiltinObfs::Http { host }),
        "tls" => Ok(BuiltinObfs::Tls { server: host }),
        other => Err(MeowError::Config(format!(
            "simple-obfs unsupported mode '{other}': expected 'http' or 'tls'"
        ))),
    }
}

// Wrapper for the SS proxy stream
struct SsConn<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync>(S);

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> tokio::io::AsyncRead
    for SsConn<S>
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> tokio::io::AsyncWrite
    for SsConn<S>
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> Unpin for SsConn<S> {}
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static> ProxyConn
    for SsConn<S>
{
}

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

// Wrapper for SS UDP ProxySocket
struct SsPacketConn<S: DatagramSend + DatagramReceive + DatagramSocket + Send + Sync + 'static> {
    socket: ProxySocket<S>,
    session: SsUdpSession,
}

#[async_trait]
impl<S: DatagramSend + DatagramReceive + DatagramSocket + Send + Sync + 'static> ProxyPacketConn
    for SsPacketConn<S>
{
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        use shadowsocks::relay::udprelay::proxy_socket::ProxySocketError;
        loop {
            let (n, addr, _raw_len, control) = match self.socket.recv_with_ctrl(buf).await {
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

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let target = Address::SocketAddress(*addr);
        // An exhausted packet-ID space kills the association: the tunnel
        // drops the session on this error and the next datagram re-dials
        // under a fresh `SsUdpSession` — sslocal's recovery on counter
        // overflow (socket reset + session renewal).
        let Some(control) = self.session.send_control() else {
            return Err(MeowError::Proxy(
                "ss udp: client packet-ID space exhausted".into(),
            ));
        };
        // ProxySocket::send_with_ctrl returns the encrypted packet size (with
        // protocol overhead), but callers expect the payload size.
        self.socket
            .send_with_ctrl(&target, &control, buf)
            .await
            .map_err(|e| MeowError::Proxy(format!("ss udp send: {e}")))?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(MeowError::Io)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

fn parse_address(metadata: &Metadata) -> Address {
    if !metadata.host.is_empty() {
        Address::DomainNameAddress(metadata.host.to_string(), metadata.dst_port)
    } else if let Some(ip) = metadata.dst_ip {
        Address::SocketAddress(SocketAddr::new(ip, metadata.dst_port))
    } else {
        Address::DomainNameAddress(metadata.host.to_string(), metadata.dst_port)
    }
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
        // SS UDP relay uses a raw UDP socket that bypasses the TCP dialer.
        // When a `ProxyDialer` is installed (dialer-proxy), raw UDP would
        // leak traffic past the chain — advertise the plain UDP path as
        // unsupported.  Mux UDP is safe because it rides the mux TCP session
        // through `dialer.dial()`, so it is unaffected.
        //
        // This is the *advertised* capability only (LoadBalance member
        // filtering, the `udp` field in `GET /proxies`).  It is NOT the
        // enforcement point: `meow-tunnel`'s UDP path calls `dial_udp`
        // directly without consulting `support_udp`, so the refusal is
        // re-checked there.  Keep the two in sync.
        let plain_udp_ok = self.support_udp && !self.core.dialer.is_proxy();
        plain_udp_ok || {
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
        let addr = parse_address(metadata);
        debug!("SS connecting to {} via {}", addr, self.addr_str);

        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            let conn = mux.open_stream_for(metadata, "ss").await?;
            return Ok(Box::new(conn));
        }

        self.core.dial_tcp_stream(addr).await
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
        let addr = parse_address(metadata);
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

        // Enforcement point for the dialer-proxy UDP leak (not `support_udp`,
        // which the tunnel's UDP dispatch never consults).  The plain SS UDP
        // relay below binds a raw socket and connects straight to the SS
        // server, so with a `ProxyDialer` installed it would egress from the
        // real source path while TCP goes through the front proxy.  Refuse
        // loudly (Class A, ADR-0002) instead of leaking.  Reached only after
        // the mux branch above, which tunnels UDP over `dialer.dial()` and is
        // therefore safe.
        if self.core.dialer.is_proxy() {
            return Err(MeowError::NotSupported(
                "ss: plain UDP relay bypasses `dialer-proxy` (raw socket); \
                 refusing to leak the real source path — enable `smux`/`yamux` \
                 mux for UDP over the chain"
                    .into(),
            ));
        }

        if matches!(self.core.plugin, PluginKind::V2ray(..)) {
            return Err(MeowError::NotSupported(
                "v2ray-plugin does not support UDP relay".into(),
            ));
        }
        #[cfg(feature = "ech-tls-tunnel")]
        if matches!(self.core.plugin, PluginKind::EchTlsTunnel(..)) {
            return Err(MeowError::NotSupported(
                "ech-tls-tunnel does not support UDP relay".into(),
            ));
        }

        // Hand-roll the UDP bind+connect so the installed
        // `meow_common::SocketProtector` sees the fd before bind — otherwise
        // the upstream `shadowsocks::ProxySocket::connect` path binds via
        // plain tokio and the Android `VpnService.protect(fd)` hook never
        // fires, looping outbound UDP back into our own VPN tunnel.
        //
        // `udp_external_addr` returns a literal `SocketAddr` for the standard
        // path and the SIP003 plugin's local listener for external plugins
        // (where the connect is loopback — protect is harmless).
        let candidates = match self.core.server_config.udp_external_addr() {
            ServerAddr::SocketAddr(sa) => vec![*sa],
            ServerAddr::DomainName(host, port) => meow_common::resolve_host_all(host, *port)
                .await
                .map_err(|e| MeowError::Proxy(format!("ss udp lookup {host}:{port}: {e}")))?,
        };
        // Try candidates in resolver order rather than committing to the
        // first one: on a single-stack network the resolver can still order
        // the unreachable family first (AAAA on an IPv4-only path), and a
        // UDP connect() to an unreachable family fails immediately with
        // ENETUNREACH — so falling through to the next candidate is cheap
        // and keeps UDP relay alive where TcpStream::connect's built-in
        // multi-address loop already keeps TCP alive.
        let mut connected = None;
        let mut last_err = None;
        for remote in candidates {
            let bind_addr: SocketAddr = if remote.is_ipv4() {
                "0.0.0.0:0".parse().expect("static")
            } else {
                "[::]:0".parse().expect("static")
            };
            let udp = match meow_common::bind_udp(bind_addr).await {
                Ok(udp) => udp,
                Err(e) => {
                    last_err = Some(format!("ss udp bind for {remote}: {e}"));
                    continue;
                }
            };
            match udp.connect(remote).await {
                Ok(()) => {
                    connected = Some((udp, remote));
                    break;
                }
                Err(e) => last_err = Some(format!("ss udp connect {remote}: {e}")),
            }
        }
        let Some((udp, remote)) = connected else {
            return Err(MeowError::Proxy(
                last_err.unwrap_or_else(|| "ss udp connect: no candidates".into()),
            ));
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
        Ok(Box::new(SsPacketConn { socket, session }))
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

    /// A dialer that reports itself as proxied without needing a real front
    /// proxy — stands in for `ProxyDialer` in the leak-refusal tests.
    struct FakeProxyDialer;

    #[async_trait]
    impl crate::dialer::TcpDialer for FakeProxyDialer {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
        ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
            Err(std::io::Error::other("test dialer never connects"))
        }

        fn is_proxy(&self) -> bool {
            true
        }
    }

    fn ss_adapter(udp: bool, dialer: Arc<dyn crate::dialer::TcpDialer>) -> ShadowsocksAdapter {
        ShadowsocksAdapter::new(
            "ss-test",
            "127.0.0.1",
            8388,
            "password",
            "aes-256-gcm",
            udp,
            None,
            None,
            dialer,
        )
        .expect("adapter builds")
    }

    /// Regression: the plain SS UDP relay binds a raw socket and connects
    /// straight to the SS server, bypassing the TCP dialer. With a proxy dialer
    /// installed it must refuse, not egress from the real source path.
    ///
    /// `dial_udp` is the enforcement point on purpose: the tunnel's UDP
    /// dispatch (`meow-tunnel/src/udp.rs`) calls it directly and never consults
    /// `support_udp()`, so gating only the latter would leave the leak open for
    /// any rule that references the outbound by name.
    #[tokio::test]
    async fn plain_udp_is_refused_under_proxy_dialer() {
        let adapter = ss_adapter(true, Arc::new(FakeProxyDialer));

        // `ProxyPacketConn` is not `Debug`, so match rather than `expect_err`.
        match adapter.dial_udp(&Metadata::default()).await {
            Err(MeowError::NotSupported(m)) => assert!(
                m.contains("dialer-proxy"),
                "refusal should name dialer-proxy, got: {m}"
            ),
            Err(other) => panic!("expected NotSupported, got: {other:?}"),
            Ok(_) => panic!("plain UDP must be refused under a proxy dialer"),
        }

        assert!(
            !adapter.support_udp(),
            "advertised capability must agree with the refusal"
        );
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
}
