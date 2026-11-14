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
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

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
        self.resolve_checked(host, metadata.dst_port)
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
    async fn bind_endpoint(&self, addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
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
        Ok(std_sock)
    }

    /// The live pump, lazily spawned: resolve endpoint → bind+connect →
    /// spawn actor task → publish under the mutex. Losers of a
    /// double-spawn race drop their handle, which shuts that pump down via
    /// [`PumpHandle::drop`].
    async fn ensure_pump(&self) -> Result<Arc<PumpHandle>> {
        if let Some(h) = self
            .pump
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            return Ok(Arc::clone(h));
        }
        // One spawn in flight at a time; losers re-check and take the
        // winner's handle instead of emitting a second handshake.
        let _spawn_guard = self.spawn_lock.lock().await;
        if let Some(h) = self
            .pump
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            return Ok(Arc::clone(h));
        }
        let gen = self.pump_gen.load(std::sync::atomic::Ordering::Relaxed);
        let endpoints = self
            .resolve_checked(&self.config.server, self.config.port)
            .await?;
        let mut last_err: Option<std::io::Error> = None;
        for addr in endpoints {
            match self.bind_endpoint(addr).await {
                Ok(sock) => match pump::spawn_pump(&self.config, sock, addr) {
                    Ok((tx, task)) => {
                        let handle = Arc::new(PumpHandle {
                            tx,
                            task: Some(task),
                        });
                        let mut guard = self
                            .pump
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if self.pump_gen.load(std::sync::atomic::Ordering::Relaxed) != gen {
                            // reset_sessions ran while this spawn was in
                            // flight — do not resurrect the session it
                            // meant to kill.
                            return Err(MeowError::Proxy(format!(
                                "wireguard {}: sessions reset during startup",
                                self.config.name
                            )));
                        }
                        if let Some(existing) = guard.as_ref() {
                            return Ok(Arc::clone(existing));
                        }
                        *guard = Some(Arc::clone(&handle));
                        return Ok(handle);
                    }
                    Err(e) => last_err = MeowError::prefer_errno_io(last_err, e),
                },
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
