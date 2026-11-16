//! `ReconnectableClient`: the public entry point. Owns a pool of `K`
//! connection handles (each a spawned quiche driver) and lazily (re)connects
//! every slot on demand, then round-robins proxied TCP streams and UDP
//! sessions across the live slots. A stream or session rides the connection
//! it was opened on for its whole lifetime: pooling widens aggregate
//! throughput across flows — a single flow still gets one connection.

use super::config::Config;
use super::driver::{self, Cmd, ConnHandle, DriverSocket};
use super::proto;
use super::tcp::DuplexStream;
use super::udp::UdpSession;
use super::{Error, Result};
use crate::dialer::{PacketConnSocket, TcpDialer, UdpTarget};
use meow_common::atomic::{AtomicU, Uint};
use meow_common::ProxyPacketConn;
use meow_transport::datagram::SocketIo;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{timeout, Duration};
use tracing::warn;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Pool width when `quic-connections` is unset: two connections double
/// the per-driver crypto throughput a single connection caps at (each
/// driver serializes quiche recv/send on its own task).
pub const DEFAULT_QUIC_CONNECTIONS: usize = 2;
/// Hard ceiling for `quic-connections`; the parser warns past 4 — extra
/// driver tasks and dial cost rarely pay off — and clamps to this bound.
pub const MAX_QUIC_CONNECTIONS: usize = 8;

/// How the client's QUIC connection reaches the server.
enum Connect {
    /// Direct: local DNS + a bound `UdpSocket` per attempt (the default).
    Raw,
    /// `dialer-proxy`: each slot's QUIC connection rides a front UDP
    /// association of its own. Every (re)connect must `dial_udp_conn`
    /// again — a dead `PacketConnSocket` can never be handed a second
    /// connection, so the dialer is stored here and consulted inside
    /// `slot_handle()`.
    Dialer(Arc<dyn TcpDialer>),
}

/// One pool slot: the cached connection and the
/// [`generation`](ReconnectableClient::generation) it was established
/// under — the per-slot copy of the old single `conn` cell. `None`
/// means lazy: the slot dials on its next selection.
type Slot = Mutex<Option<(Arc<ConnHandle>, Uint)>>;

pub struct ReconnectableClient {
    cfg: Arc<Config>,
    connect: Connect,
    /// The connection pool — see [`Slot`]. A slot connects lazily on its
    /// first selection; a slot whose dial fails stays `None` until its
    /// next turn.
    slots: Box<[Slot]>,
    /// Bumped by [`reset`](Self::reset); a connection from an older
    /// generation is never handed out again — on any slot. Compared for
    /// equality only, so the mips32 `u32` wrap is harmless.
    generation: AtomicU,
    /// Round-robin cursor: each [`handle`](Self::handle) claim starts its
    /// scan at `next_slot % slots.len()` and advances it, so consecutive
    /// dials land on different QUIC connections.
    next_slot: AtomicUsize,
}

impl ReconnectableClient {
    /// `connections` is the pool width (`quic-connections`): 1 reproduces
    /// the legacy behaviour — every stream and UDP session multiplexes on
    /// one QUIC connection.
    pub fn new(cfg: Config, connections: usize) -> Self {
        Self::with_connect(cfg, Connect::Raw, connections)
    }

    /// A client whose QUIC datagrams ride the `dialer-proxy` front's UDP
    /// association instead of a bound `UdpSocket` (issue #899 follow-up —
    /// the WireGuard `with_dialer` contract). Every slot dials its own
    /// association — a bound `PacketConnSocket` can never serve a second
    /// connection.
    pub fn with_dialer(cfg: Config, dialer: Arc<dyn TcpDialer>, connections: usize) -> Self {
        Self::with_connect(cfg, Connect::Dialer(dialer), connections)
    }

    fn with_connect(cfg: Config, connect: Connect, connections: usize) -> Self {
        let connections = connections.clamp(1, MAX_QUIC_CONNECTIONS);
        Self {
            cfg: Arc::new(cfg),
            connect,
            slots: (0..connections).map(|_| Mutex::new(None)).collect(),
            generation: AtomicU::new(0),
            next_slot: AtomicUsize::new(0),
        }
    }

    fn generation(&self) -> Uint {
        self.generation.load(Ordering::SeqCst)
    }

    /// Drop every cached QUIC connection so the next dial reconnects on a
    /// fresh UDP socket. Called when the outbound-interface binding changes
    /// (issue #695): the cached connections' sockets may predate the binding.
    ///
    /// The slots hold the only long-lived `Arc<ConnHandle>`s (streams and
    /// UDP sessions hold just the command channel), so dropping them aborts
    /// the drivers: in-flight streams fail with `ConnectionReset` and UDP
    /// sessions with `Closed`. Non-blocking: each slot lock is held across
    /// a connect, so when any is contended the drop is deferred to a task,
    /// and a connect that straddles the reset is discarded and redialled.
    /// Returns whether a connection was dropped synchronously.
    pub fn reset(self: &Arc<Self>) -> bool {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let mut dropped = false;
        let mut contended = false;
        for slot in &self.slots {
            match slot.try_lock() {
                Ok(mut guard) => dropped |= guard.take().is_some(),
                Err(_) => contended = true,
            }
        }
        if !contended {
            return dropped;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let client = Arc::clone(self);
            runtime.spawn(async move {
                for slot in &client.slots {
                    let mut guard = slot.lock().await;
                    if guard
                        .as_ref()
                        .is_some_and(|(_, generation)| *generation != client.generation())
                    {
                        guard.take();
                    }
                }
            });
        }
        dropped
    }

    pub async fn tcp_connect(&self, target: &str) -> Result<DuplexStream> {
        let handle = self.handle().await?;
        let first_frame = proto::encode_tcp_request(target, &[])?;
        let (reply_tx, reply_rx) = oneshot::channel();
        timeout(CONNECT_TIMEOUT, async {
            handle
                .cmd_tx
                .send(Cmd::OpenTcp {
                    first_frame,
                    fast_open: self.cfg.fast_open,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| Error::Closed)?;
            let mut stream = reply_rx.await.map_err(|_| Error::Closed)??;
            stream.wait_connected().await?;
            Ok(stream)
        })
        .await
        .map_err(|_| Error::Quic(format!("TCP connect timeout after {CONNECT_TIMEOUT:?}")))?
    }

    pub async fn udp(&self) -> Result<UdpSession> {
        let handle = self.handle().await?;
        if !handle.udp_enabled {
            return Err(Error::protocol("UDP disabled by hysteria2 server"));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        handle
            .cmd_tx
            .send(Cmd::RegisterUdp { reply: reply_tx })
            .await
            .map_err(|_| Error::Closed)?;
        let (session_id, rx) = reply_rx.await.map_err(|_| Error::Closed)?;
        Ok(UdpSession::new(session_id, handle.cmd_tx.clone(), rx))
    }

    /// Round-robin over the pool and hand out the claimed slot's live
    /// connection, dialing the slot first when it is empty or dead. A
    /// slot whose dial fails is left empty — `None` means "lazy" — and
    /// the scan falls through to the next slot (the spec's graceful
    /// degradation); an error surfaces only when every slot failed, the
    /// old single-connection failure shape. Each dial therefore carries
    /// at most `CONNECT_TIMEOUT`, bounded by the pool width.
    async fn handle(&self) -> Result<Arc<ConnHandle>> {
        let num_slots = self.slots.len();
        let start = self.next_slot.fetch_add(1, Ordering::Relaxed) % num_slots;
        let mut last_error = None;
        for offset in 0..num_slots {
            let idx = (start + offset) % num_slots;
            match self.slot_handle(idx).await {
                Ok(handle) => return Ok(handle),
                Err(e) => {
                    warn!("hysteria2: connection slot {idx}/{num_slots} failed: {e}");
                    last_error = remember(last_error, e);
                }
            }
        }
        Err(last_error.unwrap_or(Error::Closed))
    }

    /// Slot `idx`'s cached connection, reconnecting it when absent,
    /// stale-generation or dead — the old `handle()` body, scoped to one
    /// slot so its connect lock serializes only this slot's dial.
    async fn slot_handle(&self, idx: usize) -> Result<Arc<ConnHandle>> {
        for _ in 0..2 {
            let generation;
            {
                let mut guard = self.slots[idx].lock().await;
                generation = self.generation();
                if let Some((handle, cached_generation)) = guard.as_ref() {
                    if *cached_generation == generation && handle.is_active() {
                        return Ok(Arc::clone(handle));
                    }
                }
                // Release a stale driver before resolving or opening a socket.
                guard.take();
            }
            // Endpoint DNS may itself dial this pool — and the
            // `dialer-proxy` arm's `dial_udp_conn` re-enters the registry
            // and the host resolver. Do not hold this slot's connect lock
            // until the outbound step has completed: a nested lookup needs
            // to reach the existing host-resolver reentry fence first.
            let prepared = self.prepare().await;
            let mut guard = self.slots[idx].lock().await;
            if self.generation() != generation {
                continue;
            }
            // A nested DNS dial or concurrent caller may have populated the
            // cache while resolution was pending. Never replace that driver.
            if let Some((handle, cached_generation)) = guard.as_ref() {
                if *cached_generation == generation && handle.is_active() {
                    return Ok(Arc::clone(handle));
                }
            }
            // A failed concurrent lookup does not invalidate a usable cache.
            guard.take();
            let handle = match prepared {
                Prepared::Direct(resolved) => {
                    let (server, addrs) = resolved?;
                    Arc::new(connect_new(Arc::clone(&self.cfg), server, addrs).await?)
                }
                Prepared::Dialer(bound) => {
                    let (server, conn, peer) = bound?;
                    Arc::new(connect_bound(Arc::clone(&self.cfg), &server, conn, peer).await?)
                }
            };
            if self.generation() != generation {
                continue;
            }
            *guard = Some((Arc::clone(&handle), generation));
            return Ok(handle);
        }
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "hysteria2: connection reset during setup",
        )))
    }

    /// The outbound work done *outside* the connect lock — same shape as
    /// `resolve_server`, extended for the `dialer-proxy` arm: parse the
    /// endpoint and open the front's UDP association, so the lock only
    /// ever spans the quiche connect itself.
    async fn prepare(&self) -> Prepared {
        match &self.connect {
            Connect::Raw => Prepared::Direct(resolve_server(&self.cfg).await),
            Connect::Dialer(dialer) => {
                let result = async {
                    let server = ServerTarget::parse(&self.cfg.server_addr)?;
                    let (conn, peer) = dial_server_association(&server, dialer).await?;
                    Ok((server, conn, peer))
                };
                Prepared::Dialer(result.await)
            }
        }
    }
}

#[cfg(test)]
impl ReconnectableClient {
    /// Whether slot `idx` currently caches a connection (live or dead —
    /// a dead one is replaced on its next selection).
    pub(crate) async fn slot_live(&self, idx: usize) -> bool {
        self.slots[idx].lock().await.is_some()
    }

    /// Drop slot `idx`'s cached connection: the pool-side equivalent of
    /// the connection dying — the driver is aborted and the slot goes
    /// back to lazy.
    pub(crate) async fn drop_slot(&self, idx: usize) {
        self.slots[idx].lock().await.take();
    }
}

/// A finished [`ReconnectableClient::prepare`] — endpoint resolution plus
/// whatever the connect step needs, produced lock-free.
enum Prepared {
    Direct(Result<(ServerTarget, Vec<SocketAddr>)>),
    Dialer(Result<(ServerTarget, Arc<dyn ProxyPacketConn>, SocketAddr)>),
}

async fn resolve_server(cfg: &Config) -> Result<(ServerTarget, Vec<SocketAddr>)> {
    let server = ServerTarget::parse(&cfg.server_addr)?;
    let addrs = resolve_server_host(&server).await?;
    Ok((server, addrs))
}

async fn connect_new(
    cfg: Arc<Config>,
    server: ServerTarget,
    addrs: Vec<SocketAddr>,
) -> Result<ConnHandle> {
    let server_name = if cfg.server_name.trim().is_empty() {
        server.host.clone()
    } else {
        cfg.server_name.trim().to_string()
    };

    let mut last_error = None;
    for addr in addrs {
        match timeout(
            CONNECT_TIMEOUT,
            connect_addr(&cfg, addr, &server_name, driver::AckCoalesce::default()),
        )
        .await
        {
            Ok(Ok(handle)) => return Ok(handle),
            Ok(Err(e)) => last_error = remember(last_error, e),
            Err(_) => {
                last_error = remember(
                    last_error,
                    Error::Quic(format!("connect timeout after {CONNECT_TIMEOUT:?}")),
                );
            }
        }
    }
    Err(last_error.unwrap_or_else(|| Error::Resolve("no address resolved".into())))
}

/// `last_error` accumulation for the multi-address dial loop: an
/// errno-bearing io failure (e.g. EMFILE on the UDP bind — local
/// exhaustion, not member health, issue #668) outranks context-only
/// errors like a later candidate's timeout, which would otherwise mask
/// the classification dead-marking reads.
fn remember(prev: Option<Error>, next: Error) -> Option<Error> {
    let next_errno = matches!(next, Error::Io(ref e) if meow_common::MeowError::io_errno_backed(e));
    let prev_errno =
        matches!(prev, Some(Error::Io(ref e)) if meow_common::MeowError::io_errno_backed(e));
    if next_errno || !prev_errno {
        Some(next)
    } else {
        prev
    }
}

/// The `dialer-proxy` arm of [`Prepared`]: open a UDP association to the
/// server through the injected dialer — the WireGuard `bind_via_dialer`
/// contract (issue #899) carried onto the hysteria2 endpoint.
///
/// `UdpTarget::named` collapses an IP-literal `server` to `Addr` and
/// delegates a domain to the front hop's own resolver view (issue #657);
/// a front that cannot carry a domain refuses `Unsupported` and the
/// documented fallback applies: resolve locally, redial each literal.
///
/// The returned `SocketAddr` is what quiche records as this path's peer:
/// a real address, never `write_dst`'s `0.0.0.0:port` placeholder — for a
/// `Name` target it comes from a local resolution, strictly cosmetic (a
/// bound conn ignores the write arg), so a failed lookup warns and keeps
/// the inert placeholder rather than unbinding a dial that succeeded.
async fn dial_server_association(
    server: &ServerTarget,
    dialer: &Arc<dyn TcpDialer>,
) -> Result<(Arc<dyn ProxyPacketConn>, SocketAddr)> {
    let target = UdpTarget::named(&server.host, server.port);
    // `internal` stays false on every dial below: this association is the
    // only dial signal a lazy front hop sees for the QUIC connection's
    // whole lifetime — marking it internal would leave the front
    // permanently "unused" while user traffic flows (issue #555 boundary,
    // the same rule `ProxyDialer::dial_udp_endpoint` documents).
    match dialer.dial_udp_conn(target.clone(), false).await {
        Ok(conn) => {
            let peer = match &target {
                UdpTarget::Addr(addr) => *addr,
                UdpTarget::Name { .. } => match resolve_server_host(server).await {
                    Ok(addrs) => match addrs.into_iter().next() {
                        Some(addr) => addr,
                        None => {
                            warn!(
                                "hysteria2: front bound {target} but local resolution \
                                     returned no address — peer addr stays unspecified \
                                     (inert on the bound conn)"
                            );
                            target.write_dst()
                        }
                    },
                    Err(e) => {
                        warn!(
                            "hysteria2: front bound {target} but local resolution \
                                 failed ({e}) — peer addr stays unspecified (inert on \
                                 the bound conn)"
                        );
                        target.write_dst()
                    }
                },
            };
            Ok((conn, peer))
        }
        Err(e)
            if e.kind() == std::io::ErrorKind::Unsupported
                && matches!(target, UdpTarget::Name { .. }) =>
        {
            let addrs = resolve_server_host(server).await?;
            let mut last_err: Option<std::io::Error> = None;
            let mut bound = None;
            for addr in addrs {
                match dialer.dial_udp_conn(UdpTarget::Addr(addr), false).await {
                    Ok(conn) => {
                        bound = Some((conn, addr));
                        break;
                    }
                    Err(e) => last_err = meow_common::MeowError::prefer_errno_io(last_err, e),
                }
            }
            bound.ok_or_else(|| match last_err {
                Some(e) => Error::Io(e),
                None => Error::Resolve(format!(
                    "hysteria2: {}:{} resolved to no address",
                    server.host, server.port
                )),
            })
        }
        Err(e) => Err(Error::Io(e)),
    }
}

/// `resolve_host_all` on the server endpoint with the same errno-preserving
/// classification [`resolve_server`] applies (issue #668).
async fn resolve_server_host(server: &ServerTarget) -> Result<Vec<SocketAddr>> {
    meow_common::resolve_host_all(&server.host, server.port)
        .await
        .map_err(|e| {
            if meow_common::MeowError::io_errno_backed(&e) {
                Error::Io(e)
            } else {
                Error::Resolve(format!("{}:{}: {e}", server.host, server.port))
            }
        })
}

/// Connect through an already-bound front association: bridge it into a
/// [`DriverSocket::Io`] and run the ordinary quiche connect + driver over
/// it. Reconnect is handled by `handle()` — a fresh `dial_udp_conn` every
/// time, never a resurrected socket.
async fn connect_bound(
    cfg: Arc<Config>,
    server: &ServerTarget,
    conn: Arc<dyn ProxyPacketConn>,
    peer: SocketAddr,
) -> Result<ConnHandle> {
    let server_name = if cfg.server_name.trim().is_empty() {
        server.host.clone()
    } else {
        cfg.server_name.trim().to_string()
    };
    let socket = PacketConnSocket::new(conn, peer);
    timeout(
        CONNECT_TIMEOUT,
        connect_addr_with_io(
            &cfg,
            peer,
            &server_name,
            driver::AckCoalesce::default(),
            Some(Box::new(socket)),
        ),
    )
    .await
    .map_err(|_| Error::Quic(format!("connect timeout after {CONNECT_TIMEOUT:?}")))?
}

/// `pub(super)` so `driver_tests` can dial a driver with non-default
/// `coalesce` thresholds — the [`ReconnectableClient`] path above always
/// takes [`driver::AckCoalesce`]'s default.
pub(super) async fn connect_addr(
    cfg: &Config,
    server_addr: SocketAddr,
    server_name: &str,
    coalesce: driver::AckCoalesce,
) -> Result<ConnHandle> {
    connect_addr_with_io(cfg, server_addr, server_name, coalesce, None).await
}

/// `connect_addr` generalized: `Some(io)` runs the connection over an
/// injected connected endpoint (a `dialer-proxy` front association), `None`
/// binds a `UdpSocket` for `server_addr` exactly as the direct path always
/// has. For `Io`, `local` comes from the endpoint's [`SocketIo::local_addr_hint`]
/// — the association may report none, in which case quiche gets an
/// unspecified `to` of the peer's family (cosmetic: a bound association
/// owns no dialable local tuple).
pub(super) async fn connect_addr_with_io(
    cfg: &Config,
    server_addr: SocketAddr,
    server_name: &str,
    coalesce: driver::AckCoalesce,
    socket_io: Option<Box<dyn SocketIo>>,
) -> Result<ConnHandle> {
    // The socket's family follows the canonical server address.
    let server_addr = meow_common::canonical_socket_addr(server_addr);
    let (socket, local, mtu_hint) = match socket_io {
        Some(io) => {
            let local = io.local_addr_hint().unwrap_or_else(|| {
                SocketAddr::new(
                    if server_addr.is_ipv6() {
                        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                    } else {
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    },
                    0,
                )
            });
            // An injected endpoint knows its path's safe payload size:
            // a front proxy's per-packet encapsulation on top of the
            // stock 1452 send cap fragments the wire datagram (see
            // [`SocketIo::mtu_hint`]), and a lost fragment drops the
            // whole QUIC packet.
            let mtu_hint = io.mtu_hint();
            (
                DriverSocket::Io {
                    io,
                    peer: server_addr,
                },
                local,
                mtu_hint,
            )
        }
        None => {
            // Through the outbound-socket chokepoint, never a raw bind: it applies
            // the TUN global-route interface binding (`meow_common::outbound_iface`)
            // and the Android `protect()` hook before the first QUIC Initial leaves —
            // otherwise the datagrams follow the TUN's split default routes back
            // into the device and loop (issue #695). A loopback server is left
            // unbound, where the binding would make every send fail.
            let socket = meow_common::bind_udp_for_peer(server_addr.ip())
                .await
                .map_err(Error::Io)?;
            meow_common::enlarge_udp_recv_buffer(&socket);
            let local = socket.local_addr().map_err(Error::Io)?;
            (DriverSocket::Raw(socket), local, None)
        }
    };

    let mut config = super::tls::build_quiche_config(cfg)?;
    if let Some(mtu) = mtu_hint {
        config.set_max_send_udp_payload_size(mtu);
    }
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    for b in &mut scid {
        *b = rand::random();
    }
    let scid = quiche::ConnectionId::from_ref(&scid);
    let conn = quiche::connect(Some(server_name), &scid, local, server_addr, &mut config)
        .map_err(|e| Error::Quic(format!("connect start: {e}")))?;

    driver::spawn(cfg, socket, local, server_addr, conn, coalesce).await
}

struct ServerTarget {
    host: String,
    port: u16,
}

impl ServerTarget {
    fn parse(addr: &str) -> Result<Self> {
        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            return Ok(Self {
                host: socket_addr.ip().to_string(),
                port: socket_addr.port(),
            });
        }
        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| Error::config(format!("server address has no port: {addr}")))?;
        if host.is_empty() || host.contains(':') {
            return Err(Error::config(format!(
                "invalid server address, bracket IPv6 literals: {addr}"
            )));
        }
        let port = port
            .parse::<u16>()
            .map_err(|e| Error::config(format!("invalid server port in '{addr}': {e}")))?;
        if port == 0 {
            return Err(Error::config("server port must be non-zero"));
        }
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `dial_udp_conn` recorder: refuses `Name` targets `Unsupported`
    /// like a front that cannot carry domains, binds every literal `Addr`
    /// to a parked conn, and notes `internal` on each attempt. The
    /// recording is shared so the test keeps a handle after the
    /// `Arc<dyn TcpDialer>` unsize.
    type DialLog = Arc<std::sync::Mutex<Vec<(UdpTarget, bool)>>>;

    struct FallbackDialer {
        seen: DialLog,
    }

    struct ParkedConn;
    #[async_trait::async_trait]
    impl ProxyPacketConn for ParkedConn {
        async fn read_packet(&self, _: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        async fn write_packet(&self, buf: &[u8], _: &SocketAddr) -> meow_common::Result<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok("192.0.2.9:4444".parse().unwrap())
        }
        fn close(&self) -> meow_common::Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl TcpDialer for FallbackDialer {
        async fn dial(
            &self,
            _: &str,
            _: u16,
            _: bool,
        ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
            unreachable!("QUIC transport never TCP-dials")
        }
        fn is_proxy(&self) -> bool {
            true
        }
        async fn dial_udp_conn(
            &self,
            remote: UdpTarget,
            internal: bool,
        ) -> std::io::Result<Arc<dyn ProxyPacketConn>> {
            self.seen.lock().unwrap().push((remote.clone(), internal));
            match remote {
                UdpTarget::Name { .. } => Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "front resolves no domains",
                )),
                UdpTarget::Addr(_) => Ok(Arc::new(ParkedConn)),
            }
        }
    }

    /// A domain `server` asks the front to carry the name first (issue
    /// #657); `Unsupported` redials the locally resolved literals — every
    /// attempt `internal = false`, the #555 lazy-front rule.
    #[tokio::test]
    async fn domain_association_falls_back_to_literal_dials() {
        let seen: DialLog = Default::default();
        let dialer: Arc<dyn TcpDialer> = Arc::new(FallbackDialer {
            seen: Arc::clone(&seen),
        });
        // `localhost` stays a `Name` target (not an IP literal) and
        // resolves through the system resolver without a fixture.
        let server = ServerTarget::parse("localhost:4443").unwrap();
        let (_, peer) = dial_server_association(&server, &dialer)
            .await
            .expect("the literal fallback must bind");
        let seen = seen.lock().unwrap().clone();
        let (first, rest) = seen.split_first().unwrap();
        assert_eq!(
            *first,
            (
                UdpTarget::Name {
                    host: "localhost".into(),
                    port: 4443,
                },
                false
            ),
            "the front gets the domain target first, non-internal"
        );
        assert!(
            !rest.is_empty()
                && rest
                    .iter()
                    .all(|(t, internal)| matches!(t, UdpTarget::Addr(_)) && !internal),
            "every fallback dial is a non-internal literal: {rest:?}"
        );
        assert!(
            peer.port() == 4443 && !peer.ip().is_unspecified(),
            "the bound peer is a resolved literal, not the placeholder: {peer}"
        );
    }

    #[test]
    fn parses_domain_server_target() {
        let target = ServerTarget::parse("example.com:443").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parses_bracketed_ipv6_server_target() {
        let target = ServerTarget::parse("[::1]:443").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn remember_prefers_errno_over_context_only_errors() {
        let emfile = Error::Io(std::io::Error::from_raw_os_error(1));
        let timeout_err = Error::Quic("connect timeout".into());
        // errno first, timeout second: errno survives.
        let acc = remember(Some(emfile), timeout_err);
        assert!(matches!(acc, Some(Error::Io(_))));
        // timeout first, errno second: errno replaces it.
        let acc = remember(
            Some(Error::Quic("connect timeout".into())),
            Error::Io(std::io::Error::from_raw_os_error(1)),
        );
        assert!(matches!(acc, Some(Error::Io(_))));
        // Two context-only errors: the last one wins (historical shape).
        let acc = remember(
            Some(Error::Quic("first".into())),
            Error::Quic("second".into()),
        );
        assert!(matches!(acc, Some(Error::Quic(ref s)) if s == "second"));
        // An io error without errno does not gain precedence — neither
        // as `next` (last-wins takes it, same as any context error)…
        let acc = remember(
            Some(Error::Quic("first".into())),
            Error::Io(std::io::Error::other("ctx")),
        );
        assert!(matches!(acc, Some(Error::Io(_))));
        // …nor as `prev`: `driver.rs` synthesizes errno-less io errors
        // ("quiche send: {e}"), and they must not veto a later candidate
        // — this is the discriminating direction.
        let acc = remember(
            Some(Error::Io(std::io::Error::other("ctx"))),
            Error::Quic("second".into()),
        );
        assert!(matches!(acc, Some(Error::Quic(ref s)) if s == "second"));
    }
}
