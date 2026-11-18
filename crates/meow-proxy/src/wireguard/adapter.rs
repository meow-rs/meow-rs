//! `WireGuardAdapter` — the [`ProxyAdapter`] face of the WireGuard outbound
//! (issue #899, Phase-1).
//!
//! The adapter itself is deliberately thin: it validates dials against the
//! allowed-IPs table, resolves the WG server endpoint, owns one pump actor
//! ([`super::pump`]) lazily spawned on first use, and relays
//! dial/bind/shutdown over the actor mailbox. All smoltcp/boringtun state
//! lives inside the pump task.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use meow_common::{
    AdapterType, HostResolver, MeowError, Metadata, Network, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use meow_wgstack::{BridgedEndpoint, Endpoint, ProxyEndpoint};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::dialer::{TcpDialer, UdpTarget};

use super::config::WireGuardConfig;
use super::pump::{self, ActorMsg};

/// Outer dial deadline (spec §4.2): the pump answers a `DialTcp` well
/// inside this — `Established`, refusal, or its own 10 s/25 s in-pump
/// deadlines — so a timeout here means "the actor is gone or stuffed".
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Live pump actor: the mailbox plus the task handle. The task exits on
/// its own once `Shutdown` lands or the mailbox closes, so the handle is
/// never awaited — dropping it detaches (a `JoinHandle` drop is *not* an
/// abort), the same reaping semantics the throwaway join thread gave the
/// `std::thread` pump (perf-7 P7-2).
struct PumpHandle {
    tx: mpsc::Sender<ActorMsg>,
    task: Option<tokio::task::JoinHandle<()>>,
    /// Whether the pump's endpoint is a `dialer-proxy` front conn. Only
    /// a proxy endpoint has a *terminal* recv failure (the front conn
    /// dying exits the pump task), so only its handles are checked for
    /// a dead task on the `ensure_pump` fast path — batch endpoints
    /// keep the unchecked fast path they always had.
    is_proxy: bool,
}

impl PumpHandle {
    /// `true` when this handle wraps a proxy endpoint and the pump
    /// task has already exited — a stale handle `ensure_pump` must not
    /// return as live (the front conn is dead; handing out the mailbox
    /// would let callers queue dials into a void). Batch endpoints
    /// return `false` unconditionally: their pump survives socket recv
    /// errors by contract, so the check stays off the hot path.
    fn is_proxy_dead(&self) -> bool {
        if !self.is_proxy {
            return false;
        }
        self.task
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
    }
}

impl Drop for PumpHandle {
    fn drop(&mut self) {
        // Sender close is the guaranteed terminator — the pump exits
        // on `Disconnected`/`is_closed` even when this `try_send` drops
        // `Shutdown` against a full mailbox; the send is only the fast
        // path. Queued items that outlive this sender are refused by
        // the pump's `is_closed` guard rather than serviced into
        // dead-on-arrival conns.
        let _ = self.tx.try_send(ActorMsg::Shutdown);
        drop(self.task.take());
    }
}

/// WireGuard userspace outbound. Constructed per proxy entry by the
/// config parser via [`Self::new`] (+ [`Self::with_resolver`] when a
/// resolver hook should beat the global one); boxed as `Arc<dyn
/// ProxyAdapter>` from there.
pub struct WireGuardAdapter {
    config: WireGuardConfig,
    /// `server:port` display form for `addr()` — IP literals normalized so
    /// a v6 endpoint shows `[::1]:51820`.
    addr: String,
    /// Effective allowed-IPs (config's, or the catch-all default applied
    /// by `new` when the list is empty). Shared with each `WgPacketConn`.
    allowed: Arc<Vec<ipnet::IpNet>>,
    /// Optional resolver hook injected by the wiring layer; the global
    /// `meow_common` resolver hook + `getaddrinfo` is the fallback.
    resolver: Option<Arc<dyn HostResolver>>,
    /// Optional `dialer-proxy` dialer the endpoint's UDP transport dials
    /// through (issue #899 — e.g. a `direct` with routing-mark, SS UDP,
    /// SOCKS5-UDP front). `None` binds a raw socket via `bind_endpoint`;
    /// `Some(d)` builds a [`ProxyEndpoint`] over `d.dial_udp_conn` instead.
    /// Only ever a real chain — the parser injects it solely when the
    /// dialer `is_proxy()`, so a `DirectDialer` keeps the raw path.
    dialer: Option<Arc<dyn TcpDialer>>,
    /// The actor, lazily spawned. `reset_sessions` clears the slot so the
    /// next dial rebuilds endpoint + stack + session from scratch.
    pump: Mutex<Option<Arc<PumpHandle>>>,
    /// Serializes cold-start spawns: a burst of concurrent first dials must
    /// open exactly one endpoint socket, smoltcp stack, and WG session —
    /// without it every racer would send a real handshake initiation to
    /// the peer (and trip rate limits like Cloudflare WARP's).
    spawn_lock: tokio::sync::Mutex<()>,
    /// Bumped by `reset_sessions`; a spawn that began before the bump
    /// discards its handle rather than resurrecting a killed session.
    pump_gen: std::sync::atomic::AtomicU64,
    health: ProxyHealth,
}

impl WireGuardAdapter {
    /// Build the adapter from a parsed config. The parser validates key
    /// material and field ranges; `new` adds the few checks whose failure
    /// would be a runtime panic rather than a clean error (unspecified
    /// tunnel addrs panic `update_ip_addrs`; an inner MTU under 576 would
    /// make the device unable to carry a minimal IPv4 datagram — the
    /// parser's `mtu ≥ 640` floor reaches that first, this is the
    /// backstop).
    pub fn new(mut config: WireGuardConfig) -> std::result::Result<Self, String> {
        if config.server.trim().is_empty() {
            return Err("wireguard: server must not be empty".into());
        }
        if config.port == 0 {
            return Err("wireguard: port must be non-zero".into());
        }
        if config.private_key == [0u8; 32] {
            return Err("wireguard: private_key must not be all-zero".into());
        }
        if config.public_key == [0u8; 32] {
            return Err("wireguard: public_key must not be all-zero".into());
        }
        if let Some(ip) = config.ip {
            if ip.is_unspecified() {
                return Err("wireguard: ip must be a unicast tunnel address".into());
            }
        }
        if let Some(ip) = config.ipv6 {
            if ip.is_unspecified() {
                return Err("wireguard: ipv6 must be a unicast tunnel address".into());
            }
        }
        if config.ip.is_none() && config.ipv6.is_none() {
            warn!(
                "wireguard {}: no ip/ipv6 tunnel address configured — TCP dials will fail \
                 (smoltcp cannot pick a source address)",
                config.name
            );
        }
        if config.inner_mtu() < 576 {
            return Err(format!(
                "wireguard: mtu {} leaves inner MTU {} (< 576)",
                config.mtu,
                config.inner_mtu()
            ));
        }
        if config.allowed_ips.is_empty() {
            config.allowed_ips = vec![
                "0.0.0.0/0".parse().expect("static cidr"),
                "::/0".parse().expect("static cidr"),
            ];
        }
        let addr = match config.server.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, config.port).to_string(),
            Err(_) => format!("{}:{}", config.server, config.port),
        };
        let allowed = Arc::new(config.allowed_ips.clone());
        Ok(Self {
            config,
            addr,
            allowed,
            resolver: None,
            dialer: None,
            pump: Mutex::new(None),
            spawn_lock: tokio::sync::Mutex::new(()),
            pump_gen: std::sync::atomic::AtomicU64::new(0),
            health: ProxyHealth::new(),
        })
    }

    /// Inject the host resolver used for the WG endpoint's hostname and
    /// for `remote_dns_resolve` destination lookups. Mirrors
    /// `DirectAdapter::with_resolver`: builder style so the wiring layer
    /// can chain it at construction.
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Inject the `dialer-proxy` dialer the WG endpoint's UDP transport
    /// dials through (issue #899). The parser attaches this only for a
    /// real chain (`is_proxy()`); there is deliberately no
    /// `supports_udp` gate — `NamedProxyDialer::supports_udp` answers
    /// `false` for an unresolved group target, which would reject legal
    /// group fronts at parse time. A UDP-less front simply fails
    /// `dial_udp_conn` at runtime, closed like every other endpoint
    /// bind error — never a silent direct egress.
    pub fn with_dialer(mut self, dialer: Arc<dyn TcpDialer>) -> Self {
        self.dialer = Some(dialer);
        self
    }

    /// Resolve `host:port` through the injected hook, else the installed
    /// global hook, else `getaddrinfo`. The injected path goes through
    /// `resolve_host_all_via` so the lookup runs under the same
    /// `IN_HOST_RESOLVER` re-entrancy scope the global path uses — an
    /// unscoped call would let a `#PROXY`-tagged nameserver inside the hook
    /// re-enter this very dial and deadlock on the resolver's
    /// single-flight map.
    async fn resolve_all(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        if let Some(resolver) = &self.resolver {
            return meow_common::resolve_host_all_via(resolver.as_ref(), host, port).await;
        }
        meow_common::resolve_host_all(host, port).await
    }

    /// `resolve_all` with the hysteria2 errno-preserving classification
    /// (issue #668): errno-bearing io failures keep `Io` so the errno
    /// survives; context-only failures become `Dns`.
    async fn resolve_checked(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        self.resolve_all(host, port).await.map_err(|e| {
            if meow_common::MeowError::io_errno_backed(&e) {
                MeowError::Io(e)
            } else {
                MeowError::Dns(format!("{host}:{port}: {e}"))
            }
        })
    }

    /// Resolve the dial destination to a literal `SocketAddr`. `dst_ip`
    /// always wins (sniffed/pre-resolved targets); a bare-IP `host` parses
    /// directly; a domain needs `remote_dns_resolve` + a resolvable hook.
    async fn resolve_destination(&self, metadata: &Metadata) -> Result<SocketAddr> {
        if let Some(ip) = metadata.dst_ip {
            return Ok(SocketAddr::new(ip, metadata.dst_port));
        }
        let host = metadata.host.as_str();
        if let Some(ip) = meow_common::metadata_ip_literal(host) {
            return Ok(SocketAddr::new(ip, metadata.dst_port));
        }
        if !self.config.remote_dns_resolve {
            return Err(MeowError::Dns(format!(
                "wireguard {}: domain target {host} but remote-dns-resolve is off",
                self.config.name
            )));
        }
        if host.is_empty() {
            return Err(MeowError::Dns(format!(
                "wireguard {}: empty dial destination",
                self.config.name
            )));
        }
        // The node's `ip-version` governs the endpoint socket, not the
        // destination the tunnel carries (issue #974): `resolve_all`'s
        // shared scope filter would otherwise refuse a v6 target under a
        // v4-preferring node even with a v6 tunnel address configured.
        // Clear just the family filter for this one lookup — the mark and
        // interface options stay (a nameserver socket still honors them).
        let unfiltered = meow_common::DialerOpts {
            ip_version: meow_common::IpVersion::Dual,
            ..meow_common::dialer_opts()
        };
        meow_common::dialer_opts_scope(unfiltered, self.resolve_checked(host, metadata.dst_port))
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| {
                MeowError::Dns(format!(
                    "wireguard {}: {host} resolved to no addresses",
                    self.config.name
                ))
            })
    }

    /// Reject a destination IP outside `allowed-ips` or of a family with no
    /// configured tunnel address — before any handshake work (spec §3.5).
    fn check_tunnel_target(&self, addr: SocketAddr) -> Result<()> {
        let ip = addr.ip();
        if !self.allowed.iter().any(|net| net.contains(&ip)) {
            return Err(MeowError::Proxy(format!(
                "wireguard {}: {ip} outside allowed-ips",
                self.config.name
            )));
        }
        if self.config.tunnel_addr_for(ip).is_none() {
            return Err(MeowError::NotSupported(format!(
                "wireguard {}: no {} tunnel address configured",
                self.config.name,
                if ip.is_ipv4() { "IPv4" } else { "IPv6" }
            )));
        }
        Ok(())
    }

    /// Bind + connect the endpoint socket through the outbound chokepoint.
    /// `bind_udp_for_peer` (never a raw `UdpSocket::bind`) applies the TUN
    /// global-route interface binding and Android `protect()` before the
    /// first handshake leaves — without it our datagrams loop back into
    /// the device (issue #695 precedent).
    async fn bind_endpoint(&self, addr: SocketAddr) -> std::io::Result<Endpoint> {
        let peer = meow_common::canonical_socket_addr(addr);
        let socket = meow_common::bind_udp_for_peer(peer.ip()).await?;
        meow_wgstack::enlarge_recv_buffer(&socket);
        // Symmetric: a `poll_burst` pass can stage MiBs of wire-bound
        // datagrams, flushed to the kernel as `WIRE_DRAIN_BUDGET`-sized
        // batches back to back — the platform default `SO_SNDBUF`
        // (9 KiB on macOS) drops the tail of every burst on ENOBUFS.
        meow_wgstack::enlarge_send_buffer(&socket);
        let std_sock = socket.into_std()?;
        std_sock.connect(peer)?;
        std_sock.set_nonblocking(true)?;
        Ok(Endpoint::Batch(BridgedEndpoint::connected(
            tokio::net::UdpSocket::from_std(std_sock)?,
            peer,
        )))
    }

    /// The `dialer-proxy` arm of `ensure_pump` (issue #899): open a UDP
    /// association to the endpoint through the injected dialer and wrap
    /// it in a [`ProxyEndpoint`]. Returns `(endpoint, endpoint_addr)` —
    /// the addr the TX bridge stamps on each `write_packet`
    /// ([`UdpTarget::write_dst`]; per-packet conns like SS UDP put it in
    /// their relay header, bound conns ignore it).
    ///
    /// `UdpTarget::named` collapses an IP-literal `server` to `Addr` and
    /// delegates a domain to the front hop's own resolver view (issue
    /// #657 semantics — the view its TCP/control leg already picked).
    /// A front that cannot carry a domain refuses `Unsupported` and the
    /// documented caller fallback applies: resolve locally, redial each
    /// literal candidate.
    ///
    /// `endpoint_addr` is always a *real* address, never `write_dst`'s
    /// `0.0.0.0:port` placeholder for a `Name` target: a bound conn
    /// ignores the stamped arg, but it still lands in the TX bridge's
    /// defensive write arg and the pump's warn logs. For a name-bound
    /// conn it comes from a local resolution of the endpoint — strictly
    /// cosmetic: the front resolved the name with its own view and the
    /// conn's `write_packet` disregards the arg.
    async fn bind_via_dialer(&self, dialer: &Arc<dyn TcpDialer>) -> Result<(Endpoint, SocketAddr)> {
        let target = UdpTarget::named(&self.config.server, self.config.port);
        // `internal` stays false on every dial below: this endpoint
        // association is the only dial signal a lazy front hop sees for
        // the WG tunnel's whole lifetime — marking it internal would
        // leave the front permanently "unused" while user traffic flows
        // (issue #555 boundary — the same rule `ProxyDialer`'s kcptun
        // `dial_udp_endpoint` arm documents in dialer.rs).
        let (conn, endpoint_addr) = match dialer.dial_udp_conn(target.clone(), false).await {
            Ok(conn) => {
                let endpoint_addr = match &target {
                    UdpTarget::Addr(addr) => *addr,
                    UdpTarget::Name { .. } => {
                        // The front resolved the endpoint with its own
                        // view and bound the conn to it — its
                        // `write_packet` ignores the stamped addr, so this
                        // never reaches the wire. It still feeds the TX
                        // bridge's defensive arg and the pump's warn logs,
                        // so stamp a real candidate from a local
                        // resolution rather than `write_dst`'s unspecified
                        // placeholder. A failed local lookup must not
                        // unbind a dial that succeeded — the placeholder
                        // is inert on a bound conn; warn and keep it.
                        match self
                            .resolve_checked(&self.config.server, self.config.port)
                            .await
                        {
                            Ok(addrs) => match addrs.into_iter().next() {
                                Some(addr) => addr,
                                None => {
                                    warn!(
                                        "wireguard {}: front bound {target} but local \
                                         resolution returned no address — endpoint_addr \
                                         stays unspecified (inert on the bound conn)",
                                        self.config.name
                                    );
                                    target.write_dst()
                                }
                            },
                            Err(e) => {
                                warn!(
                                    "wireguard {}: front bound {target} but local \
                                     resolution failed ({e}) — endpoint_addr stays \
                                     unspecified (inert on the bound conn)",
                                    self.config.name
                                );
                                target.write_dst()
                            }
                        }
                    }
                };
                (conn, endpoint_addr)
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::Unsupported
                    && matches!(target, UdpTarget::Name { .. }) =>
            {
                let endpoints = self
                    .resolve_checked(&self.config.server, self.config.port)
                    .await?;
                let mut last_err: Option<std::io::Error> = None;
                let mut bound = None;
                for addr in endpoints {
                    // `internal` false here too — same association, same
                    // lazy-front accounting rule as the `Name` dial above.
                    match dialer.dial_udp_conn(UdpTarget::Addr(addr), false).await {
                        Ok(conn) => {
                            bound = Some((conn, addr));
                            break;
                        }
                        Err(e) => last_err = MeowError::prefer_errno_io(last_err, e),
                    }
                }
                match bound {
                    Some(v) => v,
                    None => {
                        return Err(match last_err {
                            Some(e) => MeowError::Io(e),
                            None => MeowError::Proxy(format!(
                                "wireguard {}: no usable endpoint address",
                                self.config.name
                            )),
                        });
                    }
                }
            }
            Err(e) => return Err(MeowError::Io(e)),
        };
        let local_addr = conn.local_addr().unwrap_or_else(|_| {
            warn!(
                "wireguard {}: front conn reports no local_addr — using unspecified",
                self.config.name
            );
            SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                endpoint_addr.port(),
            )
        });
        Ok((
            Endpoint::Proxy(ProxyEndpoint::new(conn, endpoint_addr, local_addr)),
            endpoint_addr,
        ))
    }

    /// Publish a spawned pump under the mutex — the loser of a
    /// double-spawn race takes the winner's handle, and a spawn that
    /// began before `reset_sessions` bumps the generation discards its
    /// handle rather than resurrecting the killed session.
    fn install_pump(
        &self,
        gen: u64,
        is_proxy: bool,
        tx: mpsc::Sender<ActorMsg>,
        task: tokio::task::JoinHandle<()>,
    ) -> Result<Arc<PumpHandle>> {
        let handle = Arc::new(PumpHandle {
            tx,
            task: Some(task),
            is_proxy,
        });
        let mut guard = self
            .pump
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.pump_gen.load(std::sync::atomic::Ordering::Relaxed) != gen {
            // reset_sessions ran while this spawn was in flight — do
            // not resurrect the session it meant to kill.
            return Err(MeowError::Proxy(format!(
                "wireguard {}: sessions reset during startup",
                self.config.name
            )));
        }
        if let Some(existing) = guard.as_ref() {
            return Ok(Arc::clone(existing));
        }
        *guard = Some(Arc::clone(&handle));
        Ok(handle)
    }

    /// The live pump, lazily spawned: resolve endpoint → bind+connect →
    /// spawn actor task → publish under the mutex. Losers of a
    /// double-spawn race drop their handle, which shuts that pump down via
    /// [`PumpHandle::drop`].
    async fn ensure_pump(&self) -> Result<Arc<PumpHandle>> {
        {
            let guard = self
                .pump
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(h) = guard.as_ref() {
                // A proxy pump that already exited must not be handed
                // out as live — fall through to respawn; the stale slot
                // is cleared inside the spawn-lock critical section so
                // a racing respawner cannot double-dial the front.
                if !h.is_proxy_dead() {
                    return Ok(Arc::clone(h));
                }
            }
        }
        // One spawn in flight at a time; losers re-check and take the
        // winner's handle instead of emitting a second handshake.
        let _spawn_guard = self.spawn_lock.lock().await;
        {
            let mut guard = self
                .pump
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.take() {
                Some(h) if !h.is_proxy_dead() => {
                    *guard = Some(Arc::clone(&h));
                    return Ok(h);
                }
                // Stale proxy handle — the pump exited on the dead
                // front conn — or an empty slot: either way the respawn
                // below installs fresh. Dropping a stale `h` here runs
                // `PumpHandle::drop` (a `Shutdown` the dead mailbox can
                // no longer deliver, then detach). `pump_gen`
                // deliberately does NOT bump for this: the gen is
                // config-reload semantics — it invalidates spawns that
                // began before a reset — while a connectivity-driven
                // respawn keeps the same gen, so a spawn another caller
                // still has in flight installs legally instead of
                // erroring.
                _ => {}
            }
        }
        let gen = self.pump_gen.load(std::sync::atomic::Ordering::Relaxed);

        // `dialer-proxy` path: a single UDP association through the
        // front hop — no local endpoint resolution (the front resolves
        // a `Name` target itself; the `Unsupported` fallback inside
        // `bind_via_dialer` resolves when it must).
        if let Some(dialer) = &self.dialer {
            let (endpoint, addr) = self.bind_via_dialer(dialer).await?;
            let (tx, task) = pump::spawn_pump(&self.config, endpoint, addr);
            return self.install_pump(gen, true, tx, task);
        }

        let endpoints = self
            .resolve_checked(&self.config.server, self.config.port)
            .await?;
        let mut last_err: Option<std::io::Error> = None;
        for addr in endpoints {
            match self.bind_endpoint(addr).await {
                Ok(endpoint) => {
                    let (tx, task) = pump::spawn_pump(&self.config, endpoint, addr);
                    return self.install_pump(gen, false, tx, task);
                }
                Err(e) => last_err = MeowError::prefer_errno_io(last_err, e),
            }
        }
        Err(match last_err {
            Some(e) => MeowError::Io(e),
            None => MeowError::Proxy(format!(
                "wireguard {}: no usable endpoint address",
                self.config.name
            )),
        })
    }

    fn dead_pump() -> MeowError {
        MeowError::Proxy("wireguard: pump actor stopped".into())
    }
}

#[async_trait::async_trait]
impl ProxyAdapter for WireGuardAdapter {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::WireGuard
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn support_udp(&self) -> bool {
        self.config.udp
    }

    /// Every flow's hop to the peer travels as a WireGuard-encapsulated UDP
    /// datagram, TCP flows included — the same whole-transport shape as
    /// kcptun. Unconditional `Udp`, not the flow's own network.
    fn dialer_hop_network(&self, _flow: Network) -> Network {
        Network::Udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let remote = self.resolve_destination(metadata).await?;
        self.check_tunnel_target(remote)?;
        let handle = self.ensure_pump().await?;
        let (reply_tx, reply_rx) = oneshot::channel();
        handle
            .tx
            .send(ActorMsg::DialTcp {
                remote,
                display: metadata.host.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Self::dead_pump())?;
        match tokio::time::timeout(DIAL_TIMEOUT, reply_rx).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(_)) => Err(Self::dead_pump()),
            Err(_) => Err(MeowError::Proxy(format!(
                "wireguard {}: dial timed out after {DIAL_TIMEOUT:?}",
                self.config.name
            ))),
        }
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.config.udp {
            return Err(MeowError::UdpNotSupported);
        }
        // smoltcp sockets take literal endpoints; a domain-only UDP target
        // (`domain_udp_target`) cannot be expressed — the contract says an
        // adapter answers NotSupported rather than binding a conn whose
        // `write_packet` would stamp an address the caller never had.
        if metadata.domain_udp_target().is_some() {
            return Err(MeowError::NotSupported(format!(
                "wireguard {}: domain UDP target",
                self.config.name
            )));
        }
        // Early check when the destination is already literal: a UDP dial
        // for an address the tunnel can never reach should fail here, not
        // at first `write_packet`.
        if let Some(ip) = metadata.dst_ip {
            self.check_tunnel_target(SocketAddr::new(ip, metadata.dst_port))?;
        }
        let handle = self.ensure_pump().await?;
        let (reply_tx, reply_rx) = oneshot::channel();
        handle
            .tx
            .send(ActorMsg::UdpBind {
                allowed: Arc::clone(&self.allowed),
                has_v4: self.config.ip.is_some(),
                has_v6: self.config.ipv6.is_some(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Self::dead_pump())?;
        match tokio::time::timeout(DIAL_TIMEOUT, reply_rx).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(_)) => Err(Self::dead_pump()),
            Err(_) => Err(MeowError::Proxy(format!(
                "wireguard {}: udp bind timed out after {DIAL_TIMEOUT:?}",
                self.config.name
            ))),
        }
    }

    /// Drop the actor: in-flight conns die with it, and the next dial
    /// respawns endpoint binding + smoltcp + the WG session.
    fn reset_sessions(&self) {
        // Bump first: a spawn already in flight discards its handle on
        // landing instead of resurrecting the session being killed here.
        self.pump_gen
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let handle = self
            .pump
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // `PumpHandle::drop` sends Shutdown and detaches the task.
        drop(handle);
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    //! `dialer-proxy` recovery chain (issue #899 follow-up): a dead
    //! front conn must stop the pump — terminal `ConnectionReset`, not
    //! a warn+sleep spin — and the next `ensure_pump` must detect the
    //! stale handle, clear the slot and redial the front hop.
    //!
    //! T-recover-3 note (spec §5.5): the `Endpoint::Batch` arm shares
    //! the terminal verdict — its `BridgedEndpoint` reports
    //! `ConnectionReset` when the socket bridge task dies, exactly
    //! like `Endpoint::Proxy`'s front conn — asserted by code review
    //! plus the unchanged direct-path integration tests.

    use super::*;

    use std::collections::VecDeque;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use bytes::Bytes;
    use meow_transport::Stream;
    use tokio::sync::mpsc;

    use crate::dialer::UdpTarget;

    /// Fixed key material — any 32 bytes form a valid unclamped secret;
    /// the peer key is arbitrary since no handshake ever completes.
    const INITIATOR_PRIVATE: [u8; 32] = [0x11u8; 32];
    const RESPONDER_PUBLIC: [u8; 32] = [0x22u8; 32];

    /// An IP-literal endpoint keeps `UdpTarget::named` on the `Addr`
    /// path — nothing in these tests touches DNS.
    const TEST_ENDPOINT: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51820);

    /// Serializes the two kill-the-conn tests: both emit the same
    /// `endpoint dead` warn, and the warn-counting test would
    /// leak counts into a concurrently-running sibling. A tokio Mutex
    /// because the guard must live across `.await`s.
    static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// WARN sightings of the proxy-dead message — installed as a global
    /// tracing layer by [`install_warn_counter`].
    static PROXY_DEAD_WARNS: AtomicUsize = AtomicUsize::new(0);
    static SUBSCRIBER_OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    /// Best-effort global WARN counter scoped to the exact "endpoint
    /// dead" message. Returns `false` when another subscriber
    /// already owns the process-global default (the caller then
    /// degrades to the task-finish assertion — which is itself the
    /// no-spin proof, since a warn+sleep loop never terminates).
    fn install_warn_counter() -> bool {
        struct Count;
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Count {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if *event.metadata().level() != tracing::Level::WARN {
                    return;
                }
                struct Contains(bool);
                impl tracing::field::Visit for Contains {
                    fn record_debug(
                        &mut self,
                        _f: &tracing::field::Field,
                        v: &dyn std::fmt::Debug,
                    ) {
                        if format!("{v:?}").contains("endpoint dead") {
                            self.0 = true;
                        }
                    }
                    fn record_str(&mut self, _f: &tracing::field::Field, v: &str) {
                        if v.contains("endpoint dead") {
                            self.0 = true;
                        }
                    }
                }
                let mut c = Contains(false);
                event.record(&mut c);
                if c.0 {
                    PROXY_DEAD_WARNS.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;
        *SUBSCRIBER_OK.get_or_init(|| {
            tracing_subscriber::registry()
                .with(Count)
                .try_init()
                .is_ok()
        })
    }

    /// A `ProxyPacketConn` the test kills on demand: `kill()` flips the
    /// flag and drops the inbound feed so a parked `read_packet` wakes
    /// into the error instead of hanging on the channel.
    struct FakeConn {
        killed: AtomicBool,
        closed: AtomicBool,
        inbound: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
        outbound: mpsc::Sender<(Bytes, SocketAddr)>,
        local: SocketAddr,
        remote: SocketAddr,
    }

    #[async_trait::async_trait]
    impl ProxyPacketConn for FakeConn {
        async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            match self.inbound.lock().await.recv().await {
                Some(pkt) if !self.killed.load(Ordering::Relaxed) => {
                    let n = pkt.len().min(buf.len());
                    buf[..n].copy_from_slice(&pkt[..n]);
                    Ok((n, self.remote))
                }
                _ => Err(MeowError::Proxy("fake conn: dead".into())),
            }
        }

        async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
            if self.closed.load(Ordering::Relaxed) {
                return Err(MeowError::Proxy("fake conn: closed".into()));
            }
            self.outbound
                .send((Bytes::copy_from_slice(buf), *addr))
                .await
                .map_err(|_| MeowError::Proxy("fake conn: outbox gone".into()))?;
            Ok(buf.len())
        }

        fn local_addr(&self) -> Result<SocketAddr> {
            Ok(self.local)
        }

        fn close(&self) -> Result<()> {
            self.closed.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    /// `FakeConn` plus the halves the test drives: `in_tx` injects
    /// datagrams (dropped by [`FakeWire::kill`]), `out_rx` observes
    /// every `write_packet` with its stamped address.
    struct FakeWire {
        conn: Arc<FakeConn>,
        in_tx: Option<mpsc::Sender<Bytes>>,
        out_rx: mpsc::Receiver<(Bytes, SocketAddr)>,
    }

    fn fake_wire() -> FakeWire {
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(8);
        let (out_tx, out_rx) = mpsc::channel::<(Bytes, SocketAddr)>(64);
        FakeWire {
            conn: Arc::new(FakeConn {
                killed: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                inbound: tokio::sync::Mutex::new(in_rx),
                outbound: out_tx,
                local: "192.0.2.4:41000".parse().unwrap(),
                remote: TEST_ENDPOINT,
            }),
            in_tx: Some(in_tx),
            out_rx,
        }
    }

    impl FakeWire {
        /// The conn as the trait object `dial_udp_conn` returns.
        #[allow(
            clippy::clone_on_ref_ptr,
            reason = "the Arc<FakeConn> → Arc<dyn ProxyPacketConn> unsize cannot ride Arc::clone(&_) — its generic T is pinned by the argument's concrete type"
        )]
        fn proxy_conn(&self) -> Arc<dyn ProxyPacketConn> {
            self.conn.clone()
        }

        /// Simulate front-conn death: `read_packet` errs on the flag,
        /// and dropping the feed wakes a read already parked on the
        /// channel.
        fn kill(&mut self) {
            self.conn.killed.store(true, Ordering::Relaxed);
            drop(self.in_tx.take());
        }

        fn close_called(&self) -> bool {
            self.conn.closed.load(Ordering::Relaxed)
        }
    }

    /// A `TcpDialer` that hands out a queue of pre-built conns, one per
    /// `dial_udp_conn` — the redial counter for the recovery tests.
    struct FakeDialer {
        conns: Mutex<VecDeque<Arc<dyn ProxyPacketConn>>>,
        dial_count: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl TcpDialer for FakeDialer {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
            _internal: bool,
        ) -> io::Result<Box<dyn Stream>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fake dialer: no TCP",
            ))
        }

        async fn dial_udp_conn(
            &self,
            _remote: UdpTarget,
            _internal: bool,
        ) -> io::Result<Arc<dyn ProxyPacketConn>> {
            self.dial_count.fetch_add(1, Ordering::Relaxed);
            self.conns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "fake dialer: no conns left",
                    )
                })
        }

        fn is_proxy(&self) -> bool {
            true
        }
    }

    fn test_config() -> WireGuardConfig {
        WireGuardConfig {
            name: "wg-test".into(),
            server: TEST_ENDPOINT.ip().to_string(),
            port: TEST_ENDPOINT.port(),
            private_key: INITIATOR_PRIVATE,
            public_key: RESPONDER_PUBLIC,
            pre_shared_key: None,
            ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
            ipv6: None,
            allowed_ips: vec![],
            reserved: None,
            mtu: 1420,
            udp: true,
            remote_dns_resolve: true,
            persistent_keepalive: 0,
            dns: vec![],
        }
    }

    /// Poll `cond` until it holds or the deadline passes.
    async fn wait_until(cond: impl Fn() -> bool, what: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !cond() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    /// T-recover-1: front conn dies → pump exits on the terminal
    /// `ConnectionReset` → the next `ensure_pump` clears the stale
    /// slot and redials — the full recovery chain the blocker review
    /// found missing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dead_proxy_endpoint_redials_front() {
        let _serial = TEST_LOCK.lock().await;
        let mut wire_a = fake_wire();
        let mut wire_b = fake_wire();
        let dialer = Arc::new(FakeDialer {
            conns: Mutex::new(VecDeque::from([wire_a.proxy_conn(), wire_b.proxy_conn()])),
            dial_count: AtomicUsize::new(0),
        });
        #[allow(
            clippy::clone_on_ref_ptr,
            reason = "the Arc<FakeDialer> → Arc<dyn TcpDialer> unsize cannot ride Arc::clone(&_) — its generic T is pinned by the argument's concrete type"
        )]
        let dialer_dyn: Arc<dyn TcpDialer> = dialer.clone();
        let adapter = WireGuardAdapter::new(test_config())
            .expect("valid config")
            .with_dialer(dialer_dyn);

        let h1 = adapter.ensure_pump().await.expect("first pump");
        assert_eq!(dialer.dial_count.load(Ordering::Relaxed), 1);
        assert!(!h1.is_proxy_dead());

        // The front conn dies → the bridge RX task exits → endpoint
        // recv reports `ConnectionReset` → the pump must stop, not
        // warn+sleep spin (a spinning arm would never reach
        // `is_finished`, so the deadline below doubles as the
        // no-warn-storm assertion).
        wire_a.kill();
        wait_until(|| h1.is_proxy_dead(), "pump exit on conn death").await;

        // `ensure_pump` detects the stale handle, clears the slot and
        // redials the front hop — a fresh handle, same `pump_gen`.
        let h2 = adapter.ensure_pump().await.expect("respawned pump");
        assert_eq!(
            dialer.dial_count.load(Ordering::Relaxed),
            2,
            "a dead proxy pump must redial the front"
        );
        assert!(!Arc::ptr_eq(&h1, &h2), "fresh handle, not the stale one");
        assert!(!h2.is_proxy_dead(), "the respawned pump is running");

        // conn_a's lifecycle is properly closed by the TX bridge on
        // the way out of the dead endpoint.
        wait_until(|| wire_a.close_called(), "TX bridge conn.close").await;

        // The new pump is wired to conn_b: its kick-handshake datagram
        // lands on conn_b's outbox stamped with the endpoint address.
        let (pkt, addr) = tokio::time::timeout(Duration::from_secs(5), wire_b.out_rx.recv())
            .await
            .expect("new pump must emit its handshake within 5s")
            .expect("conn_b outbox open");
        assert_eq!(addr, TEST_ENDPOINT, "write_packet stamps the endpoint addr");
        assert!(pkt.len() >= 4, "a WG datagram has a type+reserved word");

        adapter.reset_sessions();
    }

    /// T-recover-2: the terminal arm warns exactly once — the pump
    /// exits, so there is no storm to rate-limit. When the process
    /// already has a global tracing subscriber the count cannot be
    /// installed and the test degrades to the task-finish assertion
    /// (which alone proves no spin: a warn+sleep loop never exits).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dead_proxy_endpoint_warns_once_then_exits() {
        let _serial = TEST_LOCK.lock().await;
        let counting = install_warn_counter();
        let before = PROXY_DEAD_WARNS.load(Ordering::Relaxed);

        let mut wire = fake_wire();
        let dialer = Arc::new(FakeDialer {
            conns: Mutex::new(VecDeque::from([wire.proxy_conn()])),
            dial_count: AtomicUsize::new(0),
        });
        #[allow(
            clippy::clone_on_ref_ptr,
            reason = "the Arc<FakeDialer> → Arc<dyn TcpDialer> unsize cannot ride Arc::clone(&_) — its generic T is pinned by the argument's concrete type"
        )]
        let dialer_dyn: Arc<dyn TcpDialer> = dialer.clone();
        let adapter = WireGuardAdapter::new(test_config())
            .expect("valid config")
            .with_dialer(dialer_dyn);

        let h = adapter.ensure_pump().await.expect("pump");
        wire.kill();
        wait_until(|| h.is_proxy_dead(), "pump exit on conn death").await;
        // Give any would-be storm a few IDLE_SLEEP beats — if the arm
        // still slept-and-retired, several more warns would land here.
        tokio::time::sleep(Duration::from_millis(100)).await;

        if counting {
            assert_eq!(
                PROXY_DEAD_WARNS.load(Ordering::Relaxed) - before,
                1,
                "the terminal arm warns exactly once before break"
            );
        }
        adapter.reset_sessions();
    }

    /// A resolver hook returning fixed answers — pins the endpoint's
    /// local resolution so a name-bound conn gets a real `endpoint_addr`.
    struct FixedResolver(Vec<IpAddr>);

    #[async_trait::async_trait]
    impl meow_common::HostResolver for FixedResolver {
        async fn resolve(&self, _host: &str) -> io::Result<IpAddr> {
            self.0
                .first()
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))
        }
        async fn resolve_all(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    /// Like [`FakeDialer`] but records every [`UdpTarget`] it is asked
    /// for, so the test can prove the `Name` dial was attempted before
    /// any literal fallback.
    struct CapturingDialer {
        conns: Mutex<VecDeque<Arc<dyn ProxyPacketConn>>>,
        targets: Mutex<Vec<UdpTarget>>,
    }

    #[async_trait::async_trait]
    impl TcpDialer for CapturingDialer {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
            _internal: bool,
        ) -> io::Result<Box<dyn Stream>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "capturing dialer: no TCP",
            ))
        }

        async fn dial_udp_conn(
            &self,
            remote: UdpTarget,
            _internal: bool,
        ) -> io::Result<Arc<dyn ProxyPacketConn>> {
            self.targets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(remote);
            self.conns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "capturing dialer: no conns left",
                    )
                })
        }
    }

    /// T-D3: a `Name` endpoint succeeds through the front's own resolver
    /// view (issue #657 semantics kept — the `Name` dial is attempted
    /// first), yet `endpoint_addr` must be a *real* address: the first
    /// local candidate, never `write_dst`'s `0.0.0.0:port` placeholder
    /// the TX bridge would stamp and pump warns would print.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn name_bound_endpoint_addr_uses_local_resolution() {
        let wire = fake_wire();
        let dialer = Arc::new(CapturingDialer {
            conns: Mutex::new(VecDeque::from([wire.proxy_conn()])),
            targets: Mutex::new(Vec::new()),
        });
        #[allow(
            clippy::clone_on_ref_ptr,
            reason = "the Arc<CapturingDialer> → Arc<dyn TcpDialer> unsize cannot ride Arc::clone(&_) — its generic T is pinned by the argument's concrete type"
        )]
        let dialer_dyn: Arc<dyn TcpDialer> = dialer.clone();
        let resolved: IpAddr = "198.51.100.5".parse().unwrap();
        let adapter = WireGuardAdapter::new(WireGuardConfig {
            server: "wg.test".into(),
            ..test_config()
        })
        .expect("valid config")
        .with_resolver(Arc::new(FixedResolver(vec![resolved])));

        let (endpoint, endpoint_addr) = adapter
            .bind_via_dialer(&dialer_dyn)
            .await
            .expect("a name-bound front conn must bind");

        // The `Name` was delegated to the front first — a capable front
        // resolves the endpoint with its own view (issue #657).
        assert!(
            matches!(
                dialer
                    .targets
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_slice(),
                [UdpTarget::Name { .. }]
            ),
            "the endpoint dial delegates the name before any literal fallback"
        );
        // …but the stamped endpoint addr is the locally-resolved real
        // address, not the unspecified placeholder — per-packet conns
        // stamp it into their relay header, and bound conns keep it for
        // the TX bridge's defensive arg and warn logs.
        assert_eq!(
            endpoint_addr,
            SocketAddr::new(resolved, TEST_ENDPOINT.port()),
            "endpoint_addr must be a real address, not 0.0.0.0:port"
        );
        drop(endpoint);
    }

    /// Issue #974: the dial scope's `ip-version` filters the *endpoint*
    /// lookup (`resolve_checked` → `resolve_all` → the shared hook
    /// filter), but a `remote_dns_resolve` destination inside the tunnel
    /// keeps both families — the option governs the endpoint socket, not
    /// the tunneled target (the tunnel address check stays in charge).
    #[tokio::test]
    async fn resolve_destination_ignores_scope_ip_version() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9));
        let adapter = WireGuardAdapter::new(WireGuardConfig {
            server: "wg.test".into(),
            ..test_config()
        })
        .expect("valid config")
        .with_resolver(Arc::new(FixedResolver(vec![v6])));

        let metadata = Metadata {
            host: "dest.test".into(),
            dst_port: 443,
            ..Default::default()
        };
        let scoped = meow_common::DialerOpts {
            ip_version: meow_common::IpVersion::Ipv4,
            ..Default::default()
        };
        // The destination inside the tunnel is family-free…
        let got =
            meow_common::dialer_opts_scope(scoped.clone(), adapter.resolve_destination(&metadata))
                .await
                .expect("a v6 target resolves under an ipv4 scope");
        assert_eq!(got, SocketAddr::new(v6, 443));
        // …while the endpoint's own lookup honors the filter and fails
        // closed when no candidate of the family remains.
        assert!(
            meow_common::dialer_opts_scope(scoped, adapter.resolve_checked("wg.test", 51820),)
                .await
                .is_err(),
            "endpoint lookup keeps the scope's ip-version filter"
        );
    }
}
