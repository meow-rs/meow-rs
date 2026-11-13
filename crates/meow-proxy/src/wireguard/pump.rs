//! The WireGuard pump: a single-actor loop that owns the boringtun `Tunn`
//! noise session, the smoltcp `Interface`/`SocketSet`, the channel-backed
//! `Device` between them, and the endpoint UDP socket to the WG peer.
//!
//! Spec §3/§4.5: smoltcp's `Interface`/`SocketSet` are confined to one
//! dedicated `std::thread` running a current-thread tokio runtime (the
//! hysteria2/quiche non-`Send` precedent). Everything cross-thread travels
//! over tokio mpsc channels: [`ActorMsg`] for dial/bind/shutdown, per-conn
//! channels for stream/datagram payload, and a shared `wake` channel a conn
//! nudges after enqueueing so a sleeping pump picks the item up at once.
//!
//! The actor owns `Tunn` outright — the loop itself is the serialization
//! point, so there is no `Mutex<Tunn>` (deviation from spec §3.3, which
//! sketched one before §4.5 settled on actor-serialized access).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use bytes::{Buf, Bytes};
use meow_common::{MeowError, ProxyConn, ProxyPacketConn, Result};
use meow_wgstack::{
    ChannelDevice, StreamEvent, TcpIo, WgStream, TCP_READ_QUEUE, TCP_SOCKET_BUF, TCP_WRITE_QUEUE,
    WG_TIMER_INTERVAL, WIRE_DRAIN_BUDGET,
};
use meow_wireguard::{x25519, Tunn, TunnResult};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use super::config::WireGuardConfig;

/// Mailbox capacity: a burst of parallel dials stays non-blocking well
/// beyond realistic fan-out (spec §3.3).
const ACTOR_MAILBOX: usize = 64;
/// pump→conn datagrams per UDP association.
const UDP_READ_QUEUE: usize = 256;
/// conn→pump datagrams per UDP association.
const UDP_WRITE_QUEUE: usize = 128;
/// Shared wake channel: every conn enqueues a nudge after each item so a
/// pump sleeping in `select!` services the new work immediately.
const WAKE_QUEUE: usize = 64;

/// smoltcp UDP packet buffer: packet slots and payload arena.
const UDP_SOCKET_PACKETS: usize = 64;
const UDP_SOCKET_BYTES: usize = 65536;

/// Read chunk handed to `socket.recv`. One 16 KiB item drains through a
/// relay's bulk-tier 32 KiB ReadBuf in ~2 channel hops (or four 4 KiB
/// hops before the bulk upgrade) instead of four times as many 4 KiB
/// items, without letting one socket monopolise a service pass.
const TCP_READ_CHUNK: usize = 16384;

/// Idle `select!` sleep when smoltcp reports no `poll_delay`: inbound WG
/// datagrams, mailbox messages and conn wakes all break the sleep early, so
/// this only bounds the smoltcp housekeeping cadence.
const IDLE_SLEEP: Duration = Duration::from_millis(10);

/// Spec §3.7: a WG handshake that has not completed within 10 s fails all
/// dials still waiting on it.
const HANDSHAKE_DIAL_LIMIT: Duration = Duration::from_secs(10);
/// Once the WG session is up, a TCP connect may wait out the adapter's
/// outer 30 s dial deadline (spec §4.2); the pump gives up one step earlier
/// so the reply error beats the caller's timeout.
const TCP_CONNECT_LIMIT: Duration = Duration::from_secs(25);

/// Ephemeral port range for tunnel-local sockets; smoltcp does not allocate
/// ephemeral ports for us.
const EPHEMERAL_PORT_BASE: u16 = 49152;
const EPHEMERAL_PORT_SPAN: u16 = 16384;

/// Messages into the pump actor.
pub(crate) enum ActorMsg {
    /// Open a smoltcp TCP socket toward `remote`; the reply fires once the
    /// connection reaches `Established` or definitively fails.
    DialTcp {
        remote: SocketAddr,
        display: String,
        reply: oneshot::Sender<Result<Box<dyn ProxyConn>>>,
    },
    /// Allocate a smoltcp UDP socket and hand back its packet conn.
    UdpBind {
        /// Shared allowed-IPs table for per-datagram egress checks.
        allowed: Arc<Vec<ipnet::IpNet>>,
        /// Whether a tunnel address of each family exists (write-time
        /// pre-check so the caller gets an error instead of a silent drop).
        has_v4: bool,
        has_v6: bool,
        reply: oneshot::Sender<Result<Box<dyn ProxyPacketConn>>>,
    },
    /// Stop the pump; in-flight conns die with it (`reset_sessions`).
    Shutdown,
}

/// conn→pump UDP items.
pub(crate) enum UdpIo {
    SendTo {
        data: Bytes,
        addr: SocketAddr,
    },
    /// Conn dropped or `close()`d: remove the socket.
    Close,
}

type TcpDialReply = oneshot::Sender<Result<Box<dyn ProxyConn>>>;

/// A TCP flow still waiting on `Established` — or on the WG handshake to
/// finish so the SYN can leave at all.
struct PendingTcp {
    reply: TcpDialReply,
    read_rx: mpsc::Receiver<StreamEvent>,
    write_tx: mpsc::Sender<TcpIo>,
    drain_notify: Arc<tokio::sync::Notify>,
    display: String,
    created: StdInstant,
}

struct TcpState {
    pending: Option<PendingTcp>,
    /// The ephemeral port `dial_tcp` bound this socket to. Kept in state
    /// because smoltcp clears a socket's `tuple` when its terminal RST is
    /// processed (peer RST in, or our own abort's RST out): past that
    /// point `local_endpoint()` is `None` — exactly when dead-socket
    /// cleanup needs the port back — and reading it there would leak the
    /// port for good.
    local_port: u16,
    read_tx: mpsc::Sender<StreamEvent>,
    write_rx: mpsc::Receiver<TcpIo>,
    /// Signalled after the `out` backlog shrinks; a `WgStream` whose
    /// `poll_write` met a full channel parks on this instead of a timeout.
    drain_notify: Arc<tokio::sync::Notify>,
    /// Ordered conn→socket items not yet accepted by `send_slice`
    /// (shutdown/close markers ride the same queue to stay ordered).
    out: VecDeque<TcpIo>,
    /// Socket→conn chunks the conn channel had no room for; flushed ahead
    /// of new `recv` pulls so ordering survives.
    pending_read: VecDeque<StreamEvent>,
    eof_sent: bool,
    /// A `Shutdown` was already consumed: the FIN is flowing, so a later
    /// conn-drop must not downgrade the close to `abort()` and RST the
    /// peer mid-drain.
    graceful_close: bool,
}

impl Drop for TcpState {
    /// A `WgStream` parked on a full write channel waits on
    /// `drain_notify` — dropping the state without waking it would pin
    /// the conn task forever (the channel-close wake in
    /// `WgStream::poll_write_wait` is the second safety net). Fire all
    /// waiters so the writer's next `try_send` sees `Closed` and exits.
    fn drop(&mut self) {
        self.drain_notify.notify_waiters();
    }
}

struct UdpState {
    read_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    write_rx: mpsc::Receiver<UdpIo>,
    /// Datagrams stalled on `SendError::BufferFull`; UDP items are atomic,
    /// so each entry is a whole datagram.
    out: VecDeque<(Bytes, SocketAddr)>,
    local: SocketAddr,
}

/// The smoltcp/boringtun actor. Constructed inside [`spawn_pump`]'s thread
/// so nothing smoltcp touches ever crosses a thread boundary.
struct WgPump {
    name: String,
    tunn: Tunn,
    iface: Interface,
    device: ChannelDevice,
    sockets: SocketSet<'static>,
    endpoint: tokio::net::UdpSocket,
    endpoint_addr: SocketAddr,
    rx: mpsc::Receiver<ActorMsg>,
    wake_tx: mpsc::Sender<()>,
    wake_rx: mpsc::Receiver<()>,
    tcp: HashMap<SocketHandle, TcpState>,
    udp: HashMap<SocketHandle, UdpState>,
    used_ports: HashSet<u16>,
    next_port: u16,
    /// WG datagrams to write to the endpoint socket; drained by `try_send`
    /// so a stuffed kernel buffer only ever delays, never wedges the actor.
    outbox: VecDeque<Vec<u8>>,
    reserved: Option<[u8; 3]>,
    /// Tunnel source addresses for `UdpMetadata.local_address`, per family.
    src_v4: Option<IpAddress>,
    src_v6: Option<IpAddress>,
    recv_buf: Vec<u8>,
    /// Scratch for `Tunn::{encapsulate,decapsulate,update_timers,...}` —
    /// kept outside `self` during calls so the `TunnResult`'s borrow of it
    /// never fights the `&mut self` the enqueue paths need.
    work: Vec<u8>,
    udp_scratch: Vec<u8>,
    last_timer: StdInstant,
}

impl WgPump {
    fn new(
        config: &WireGuardConfig,
        std_sock: std::net::UdpSocket,
        endpoint_addr: SocketAddr,
        rx: mpsc::Receiver<ActorMsg>,
    ) -> std::io::Result<Self> {
        std_sock.set_nonblocking(true)?;
        let endpoint = tokio::net::UdpSocket::from_std(std_sock)?;

        let tunn = Tunn::new(
            x25519::StaticSecret::from(config.private_key),
            x25519::PublicKey::from(config.public_key),
            config.pre_shared_key,
            (config.persistent_keepalive > 0).then_some(config.persistent_keepalive),
            rand::random(),
            None,
        );

        // The device advertises the inner MTU; smoltcp clamps TCP's MSS to
        // it. Floor at the IPv4 minimum so a degenerate `mtu` config cannot
        // make every egress packet unrepresentable.
        let inner_mtu = config.inner_mtu().max(576);
        let mut device = ChannelDevice::new(inner_mtu);
        let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            if let Some(ip) = config.ip {
                let _ = addrs.push(IpCidr::new(ip.into(), 32));
            }
            if let Some(ip) = config.ipv6 {
                let _ = addrs.push(IpCidr::new(ip.into(), 128));
            }
        });
        // Note: no routes are programmed. `Medium::Ip` egress never consults
        // the route table (route lookup exists for neighbor media), and
        // `connect()`'s source-address selection reads `ip_addrs`, not
        // routes — so allowed-ips policy lives at the adapter's
        // dial/write-time check, where it can produce an error instead of
        // a silent drop.

        let buf_size = usize::from(config.mtu).max(2048) + 64;
        let (wake_tx, wake_rx) = mpsc::channel(WAKE_QUEUE);
        Ok(Self {
            name: config.name.clone(),
            tunn,
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            endpoint,
            endpoint_addr,
            rx,
            wake_tx,
            wake_rx,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            used_ports: HashSet::new(),
            next_port: EPHEMERAL_PORT_BASE + rand::random::<u16>() % EPHEMERAL_PORT_SPAN,
            outbox: VecDeque::new(),
            reserved: config.reserved,
            src_v4: config.ip.map(Into::into),
            src_v6: config.ipv6.map(Into::into),
            recv_buf: vec![0u8; buf_size],
            work: vec![0u8; buf_size],
            udp_scratch: vec![0u8; inner_mtu],
            last_timer: StdInstant::now(),
        })
    }

    /// Overwrite the reserved bytes of an outbound WG datagram (byte 0 is
    /// the message type; 1..4 are the reserved field Cloudflare WARP uses)
    /// and queue it for the endpoint socket. boringtun has no reserved-byte
    /// API — this is the post-encapsulation mutation the spec requires on
    /// *every* `WriteToNetwork` output, handshake messages included.
    fn enqueue_wg(&mut self, pkt: &[u8]) {
        let mut v = pkt.to_vec();
        if let Some(reserved) = self.reserved {
            if v.len() >= 4 {
                v[1..4].copy_from_slice(&reserved);
            }
        }
        self.outbox.push_back(v);
    }

    /// Feed one inbound datagram through `Tunn`, chaining the
    /// empty-datagram calls boringtun's contract requires to flush packets
    /// queued behind a handshake (`decapsulate` doc: repeat until the
    /// result is not `WriteToNetwork`).
    fn decapsulate_wire(&mut self, n: usize) {
        // Move the buffer out of `self` so the loop body can take `&mut
        // self` freely — same pattern as `self.work`, restored below.
        // Zero alloc, zero copy per inbound datagram.
        let mut pkt_in = std::mem::take(&mut self.recv_buf);
        debug_assert!(n <= pkt_in.len(), "n is a byte count read into this buffer");
        // WG header bytes 1..4 are reserved-zero on the wire — but peers
        // like Cloudflare WARP stamp non-zero identifiers there, and
        // vendored boringtun's `parse_incoming_packet` checks type and
        // reserved as one LE u32, so an unscrubbed datagram is rejected
        // wholesale. Zero the field on receipt — don't-care semantics,
        // the same treatment mihomo applies for wireguard-go — rather
        // than patching the vendored parser.
        if n >= 4 {
            pkt_in[1..4].fill(0);
        }
        let mut datagram: &[u8] = &pkt_in[..n];
        let mut work = std::mem::take(&mut self.work);
        loop {
            match self.tunn.decapsulate(None, datagram, &mut work) {
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    debug!("wireguard {}: decapsulate error: {e:?}", self.name);
                    break;
                }
                TunnResult::WriteToNetwork(b) => {
                    self.enqueue_wg(b);
                    // Chained call with an empty datagram flushes the queue.
                    datagram = &[];
                }
                TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                    self.device.rx_queue.push_back(b.to_vec());
                    break;
                }
            }
        }
        self.work = work;
        self.recv_buf = pkt_in;
    }

    fn drain_wire(&mut self) {
        for _ in 0..WIRE_DRAIN_BUDGET {
            match self.endpoint.try_recv(&mut self.recv_buf) {
                Ok(n) => self.decapsulate_wire(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!("wireguard {}: endpoint recv error: {e}", self.name);
                    break;
                }
            }
        }
    }

    /// Egress: `device.tx_queue` → `Tunn::encapsulate` → outbox. A queued
    /// inner packet resurfaces here once the handshake completes.
    fn drain_device_tx(&mut self) {
        let mut work = std::mem::take(&mut self.work);
        while let Some(pkt) = self.device.tx_queue.pop_front() {
            // `Tunn::encapsulate` *panics* on an undersized dst — guard
            // rather than trust the MTU accounting.
            if pkt.len() + meow_wireguard::DATA_OVERHEAD_SZ > work.len() {
                warn!(
                    "wireguard {}: dropping {}B inner packet (work buffer {}B)",
                    self.name,
                    pkt.len(),
                    work.len()
                );
                continue;
            }
            if let TunnResult::WriteToNetwork(b) = self.tunn.encapsulate(&pkt, &mut work) {
                self.enqueue_wg(b);
            }
        }
        self.work = work;
    }

    /// boringtun's housekeeping — rekey, session expiry, persistent
    /// keepalive — all inside `update_timers` (spec §3.8's manual
    /// keepalive-deadline is subsumed by it).
    fn tick_timers(&mut self) {
        let mut work = std::mem::take(&mut self.work);
        match self.tunn.update_timers(&mut work) {
            TunnResult::WriteToNetwork(b) => {
                self.enqueue_wg(b);
                self.work = work;
                // boringtun's contract: packets queued behind the handshake
                // a rekey just triggered flush via chained empty-datagram
                // `decapsulate` calls — the same drain loop
                // `decapsulate_wire` runs for real datagrams. Skipping
                // this drops every inner packet parked while the old
                // session was rekeying.
                self.decapsulate_wire(0);
            }
            TunnResult::Err(e) => {
                // `update_timers` reports `ConnectionExpired` once the
                // handshake has been `Expired` for good (REKEY_ATTEMPT_TIME
                // of unanswered initiations, REJECT_AFTER_TIME * 3 of
                // silence). An `if let` used to drop the error on the
                // floor and leave a dead session: `encapsulate` kept
                // queueing inner packets behind a handshake that would
                // never retry, and every new dial ate the full handshake
                // timeout. boringtun's own recovery is a forced
                // initiation — the same call `update_timers` makes on a
                // rekey timeout (`format_handshake_initiation(dst, true)`)
                // — which moves the handshake out of `Expired` and starts
                // a fresh one.
                warn!(
                    "wireguard {}: session error {e:?}; forcing re-handshake",
                    self.name
                );
                match self.tunn.format_handshake_initiation(&mut work, true) {
                    TunnResult::WriteToNetwork(b) => {
                        self.enqueue_wg(b);
                        self.work = work;
                        self.decapsulate_wire(0);
                    }
                    TunnResult::Err(err) => {
                        warn!(
                            "wireguard {}: forced re-handshake failed: {err:?}",
                            self.name
                        );
                        self.work = work;
                    }
                    _ => self.work = work,
                }
            }
            _ => self.work = work,
        }
    }

    /// Kick off the WireGuard handshake immediately so it overlaps the
    /// first dial instead of starting when the first SYN needs encrypting.
    fn kick_handshake(&mut self) {
        let mut work = std::mem::take(&mut self.work);
        if let TunnResult::WriteToNetwork(b) =
            self.tunn.format_handshake_initiation(&mut work, false)
        {
            self.enqueue_wg(b);
        }
        self.work = work;
    }

    fn flush_outbox(&mut self) {
        while let Some(pkt) = self.outbox.pop_front() {
            match self.endpoint.try_send(&pkt) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.outbox.push_front(pkt);
                    break;
                }
                Err(e) => {
                    warn!(
                        "wireguard {}: endpoint send to {} failed: {e}",
                        self.name, self.endpoint_addr
                    );
                }
            }
        }
    }

    fn alloc_port(&mut self) -> Option<u16> {
        for _ in 0..EPHEMERAL_PORT_SPAN {
            let port = self.next_port;
            // Range is [49152, 65535]: `checked_add` wraps the u16 top back
            // to the base; the filter re-enters the range if a corrupt
            // `next_port` ever slipped below it.
            self.next_port = self
                .next_port
                .checked_add(1)
                .filter(|p| *p >= EPHEMERAL_PORT_BASE)
                .unwrap_or(EPHEMERAL_PORT_BASE);
            if self.used_ports.insert(port) {
                return Some(port);
            }
        }
        None
    }

    fn session_up(&self) -> bool {
        self.tunn.time_since_last_handshake().is_some()
    }

    fn dial_tcp(&mut self, remote: SocketAddr, display: String, reply: TcpDialReply) {
        let Some(port) = self.alloc_port() else {
            let _ = reply.send(Err(MeowError::Proxy(format!(
                "wireguard {}: ephemeral ports exhausted",
                self.name
            ))));
            return;
        };
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]),
            tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]),
        );
        // TCP_NODELAY: a proxy stream wants latency over tinygram batching.
        socket.set_nagle_enabled(false);
        let connect = socket.connect(
            self.iface.context(),
            IpEndpoint::from(remote),
            IpListenEndpoint::from(port),
        );
        if let Err(e) = connect {
            self.used_ports.remove(&port);
            let _ = reply.send(Err(MeowError::Proxy(format!(
                "wireguard {}: tcp connect {remote}: {e}",
                self.name
            ))));
            return;
        }
        let (read_tx, read_rx) = mpsc::channel(TCP_READ_QUEUE);
        let (write_tx, write_rx) = mpsc::channel(TCP_WRITE_QUEUE);
        let drain_notify = Arc::new(tokio::sync::Notify::new());
        let handle = self.sockets.add(socket);
        self.tcp.insert(
            handle,
            TcpState {
                local_port: port,
                pending: Some(PendingTcp {
                    reply,
                    read_rx,
                    write_tx,
                    drain_notify: Arc::clone(&drain_notify),
                    display,
                    created: StdInstant::now(),
                }),
                read_tx,
                write_rx,
                drain_notify,
                out: VecDeque::new(),
                pending_read: VecDeque::new(),
                eof_sent: false,
                graceful_close: false,
            },
        );
    }

    fn udp_bind(
        &mut self,
        allowed: Arc<Vec<ipnet::IpNet>>,
        has_v4: bool,
        has_v6: bool,
        reply: oneshot::Sender<Result<Box<dyn ProxyPacketConn>>>,
    ) {
        let Some(port) = self.alloc_port() else {
            let _ = reply.send(Err(MeowError::Proxy(format!(
                "wireguard {}: ephemeral ports exhausted",
                self.name
            ))));
            return;
        };
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_SOCKET_PACKETS],
                vec![0; UDP_SOCKET_BYTES],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_SOCKET_PACKETS],
                vec![0; UDP_SOCKET_BYTES],
            ),
        );
        // Wildcard bind: a flow's packets may leave on either tunnel
        // family; per-datagram `local_address` pins the source instead.
        if let Err(e) = socket.bind(IpListenEndpoint::from(port)) {
            self.used_ports.remove(&port);
            let _ = reply.send(Err(MeowError::Proxy(format!(
                "wireguard {}: udp bind :{port}: {e}",
                self.name
            ))));
            return;
        }
        let (read_tx, read_rx) = mpsc::channel(UDP_READ_QUEUE);
        let (write_tx, write_rx) = mpsc::channel(UDP_WRITE_QUEUE);
        let handle = self.sockets.add(socket);
        let local = SocketAddr::new(
            self.src_v4
                .map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), IpAddr::from),
            port,
        );
        self.udp.insert(
            handle,
            UdpState {
                read_tx,
                write_rx,
                out: VecDeque::new(),
                local,
            },
        );
        let conn = WgPacketConn {
            local,
            rx: tokio::sync::Mutex::new(read_rx),
            tx: write_tx,
            wake: self.wake_tx.clone(),
            closed: AtomicBool::new(false),
            allowed,
            has_v4,
            has_v6,
        };
        let _ = reply.send(Ok(Box::new(conn) as Box<dyn ProxyPacketConn>));
    }

    fn handle_msg(&mut self, msg: ActorMsg) {
        match msg {
            ActorMsg::DialTcp {
                remote,
                display,
                reply,
            } => self.dial_tcp(remote, display, reply),
            ActorMsg::UdpBind {
                allowed,
                has_v4,
                has_v6,
                reply,
            } => self.udp_bind(allowed, has_v4, has_v6, reply),
            ActorMsg::Shutdown => {} // handled by the run loop's drains
        }
    }

    /// Per-socket service pass: conn→socket writes, socket→conn reads, and
    /// lifecycle (connect completion, EOF, teardown). Runs once per loop.
    fn service_sockets(&mut self) {
        let session_up = self.session_up();
        let wake_tx = self.wake_tx.clone();
        let src_v4 = self.src_v4;
        let src_v6 = self.src_v6;
        let mut dead_tcp: Vec<SocketHandle> = Vec::new();
        let mut dead_udp: Vec<SocketHandle> = Vec::new();

        for (handle, st) in &mut self.tcp {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);

            // ── pending dial resolution ────────────────────────────
            if let Some(p) = st.pending.as_ref() {
                let state = socket.state();
                let failed = match state {
                    tcp::State::Established => false,
                    tcp::State::Closed => true,
                    _ => {
                        let limit = if session_up {
                            TCP_CONNECT_LIMIT
                        } else {
                            HANDSHAKE_DIAL_LIMIT
                        };
                        p.created.elapsed() >= limit
                    }
                };
                if failed {
                    let reason = if state == tcp::State::Closed {
                        "connection refused/reset"
                    } else {
                        "timed out"
                    };
                    let p = st.pending.take().expect("pending checked is_some above");
                    let _ = p.reply.send(Err(MeowError::Proxy(format!(
                        "wireguard {}: connect {reason}",
                        self.name
                    ))));
                    socket.abort();
                    dead_tcp.push(*handle);
                    continue;
                }
                if state == tcp::State::Established {
                    debug!("wireguard {}: TCP {handle:?} established", self.name);
                    let p = st.pending.take().expect("pending checked is_some above");
                    let stream = WgStream {
                        remote: p.display,
                        rx: p.read_rx,
                        tx: p.write_tx,
                        wake: wake_tx.clone(),
                        drain_notify: p.drain_notify,
                        pending_read: None,
                        pending_write: None,
                        read_eof: false,
                        write_done: false,
                    };
                    let _ = p.reply.send(Ok(Box::new(stream) as Box<dyn ProxyConn>));
                }
            }

            // ── conn→pump drain (channel disconnect = conn dropped),
            // gated on `out` headroom: once the backlog reaches
            // TCP_WRITE_QUEUE the channel itself must be the stall
            // point — draining it regardless moved the bound into an
            // unbounded VecDeque, letting a stalled socket
            // (`can_send()` = false on a full tx window) grow `out`
            // forever while the writer never saw `Full`.
            while st.out.len() < TCP_WRITE_QUEUE {
                match st.write_rx.try_recv() {
                    Ok(io) => st.out.push_back(io),
                    Err(_) => break,
                }
            }
            // `is_closed` + `is_empty`, not the drain's `Disconnected`:
            // a conn that dropped while `out` sat at the cap never
            // surfaces `Disconnected` to a capped drain — and the
            // emptiness check keeps `Close` ordered behind whatever
            // the channel already held. The back-of-queue dedup stops
            // a still-closed channel pushing one `Close` per pass.
            let conn_gone = st.write_rx.is_closed() && st.write_rx.is_empty();
            if conn_gone
                && !st.graceful_close
                && !matches!(st.out.back(), Some(TcpIo::Close | TcpIo::Shutdown))
            {
                debug!("wireguard {}: TCP {handle:?} conn_gone → Close", self.name);
                st.out.push_back(TcpIo::Close);
            }

            // ── ordered writes into the smoltcp socket ─────────────
            // `drain_notify` is only worth re-arming when this pass did
            // write-side work a parked writer could join: items the
            // conn→pump drain just moved off the channel, a backlog left
            // over from a previous stall, or a `Close` push — any of them
            // means `out` is non-empty here. The permit may buy nothing
            // (a stalled socket pops nothing new), which is harmless;
            // what it must not do is fire unconditionally on an idle
            // socket, where a stored permit is a guaranteed spurious wake.
            let had_out = !st.out.is_empty();
            while let Some(front) = st.out.front_mut() {
                match front {
                    TcpIo::Data(b) => {
                        if !socket.can_send() {
                            break;
                        }
                        match socket.send_slice(b) {
                            Ok(0) | Err(_) => {
                                debug!(
                                    "wireguard {}: TCP {handle:?} send_slice failed (state {:?})",
                                    self.name,
                                    socket.state()
                                );
                                break;
                            }
                            Ok(n) => {
                                b.advance(n);
                                if b.is_empty() {
                                    st.out.pop_front();
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    TcpIo::Shutdown => {
                        socket.close();
                        st.graceful_close = true;
                        st.out.pop_front();
                    }
                    TcpIo::Close => {
                        // A `Close` queued behind an un-consumed
                        // `Shutdown` reaches the front only after the FIN
                        // went out — aborting here would downgrade that
                        // graceful close to an RST and drop tail bytes.
                        if !st.graceful_close {
                            socket.abort();
                        }
                        st.out.pop_front();
                    }
                }
            }
            // Re-arm a writer parked on a full queue (one stored permit;
            // spurious wakes just retry the send).
            if had_out {
                st.drain_notify.notify_one();
            }

            // ── socket→conn reads ──────────────────────────────────
            while let Some(ev) = st.pending_read.pop_front() {
                match st.read_tx.try_send(ev) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(ev)) => {
                        st.pending_read.push_front(ev);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
            while socket.can_recv() && st.pending_read.is_empty() {
                let chunk = socket.recv(|data| {
                    let n = data.len().min(TCP_READ_CHUNK);
                    (n, StreamEvent::Data(Bytes::copy_from_slice(&data[..n])))
                });
                match chunk {
                    Ok(ev) => match st.read_tx.try_send(ev) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(ev)) => {
                            st.pending_read.push_back(ev);
                            break;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    },
                    Err(_) => break,
                }
            }

            // ── EOF + teardown ─────────────────────────────────────
            // `pending.is_none()` guards pre-Established states: in
            // SynSent `may_recv` is already false, so an unchecked EOF
            // here would queue `Closed` before the conn even exists.
            if !st.eof_sent && st.pending.is_none() && !socket.can_recv() && !socket.may_recv() {
                debug!(
                    "wireguard {}: TCP {handle:?} eof (state {:?})",
                    self.name,
                    socket.state()
                );
                match st.read_tx.try_send(StreamEvent::Closed) {
                    Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => st.eof_sent = true,
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                }
            }
            if !socket.is_open() {
                debug!(
                    "wireguard {}: TCP {handle:?} dead (state {:?})",
                    self.name,
                    socket.state()
                );
                dead_tcp.push(*handle);
            }
        }

        for (handle, st) in &mut self.udp {
            let socket = self.sockets.get_mut::<udp::Socket>(*handle);
            let mut conn_gone = false;
            // Same gate as the TCP drain above: once the backlog reaches
            // UDP_WRITE_QUEUE the channel itself must be the stall point,
            // or a socket wedged on `BufferFull` grows `out` without
            // bound while the conn never sees backpressure.
            while st.out.len() < UDP_WRITE_QUEUE {
                match st.write_rx.try_recv() {
                    Ok(UdpIo::SendTo { data, addr }) => st.out.push_back((data, addr)),
                    Ok(UdpIo::Close) | Err(mpsc::error::TryRecvError::Disconnected) => {
                        conn_gone = true;
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }
            while socket.can_send() {
                let Some((data, addr)) = st.out.front() else {
                    break;
                };
                let local_address = match addr.ip() {
                    IpAddr::V4(_) => src_v4,
                    IpAddr::V6(_) => src_v6,
                };
                let meta = udp::UdpMetadata {
                    endpoint: (*addr).into(),
                    local_address,
                    meta: Default::default(),
                };
                match socket.send_slice(data, meta) {
                    Err(udp::SendError::BufferFull) => break,
                    // Unaddressable et al.: the conn's write_packet checks
                    // make those unreachable; drop the datagram rather than
                    // wedge the queue behind a permanently-failing one.
                    Ok(()) | Err(_) => {
                        st.out.pop_front();
                    }
                }
            }
            while socket.can_recv() {
                match socket.recv_slice(&mut self.udp_scratch) {
                    Ok((n, meta)) => {
                        let src = SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port);
                        let data = Bytes::copy_from_slice(&self.udp_scratch[..n]);
                        // Full → drop: datagram loss is the UDP contract.
                        let _ = st.read_tx.try_send((data, src));
                    }
                    Err(_) => break,
                }
            }
            // Same fallback as the TCP conn_gone probe above: a conn that
            // dropped while `out` sat at the cap never surfaces
            // `Disconnected` to the gated drain — and a socket wedged on
            // `BufferFull` would pin the flow, its socket and its port
            // forever.
            conn_gone |= st.write_rx.is_closed();
            if conn_gone {
                dead_udp.push(*handle);
            }
        }

        for handle in dead_tcp {
            if let Some(st) = self.tcp.remove(&handle) {
                // The port comes from `TcpState`, not the socket: smoltcp
                // cleared the socket's `tuple` the moment its terminal RST
                // was processed, so `local_endpoint()` is `None` on the
                // peer-RST path — the one place the port must not leak.
                self.used_ports.remove(&st.local_port);
                self.sockets.remove(handle);
                let mut st = st;
                if let Some(p) = st.pending.take() {
                    let _ = p.reply.send(Err(MeowError::Proxy(format!(
                        "wireguard {}: connect aborted",
                        self.name
                    ))));
                }
            }
        }
        for handle in dead_udp {
            if let Some(st) = self.udp.remove(&handle) {
                self.sockets.remove(handle);
                self.used_ports.remove(&st.local.port());
            }
        }
    }

    /// How long `select!` may sleep before smoltcp's timers or the WG tick
    /// need service. Mailbox, endpoint and wake events all interrupt it —
    /// and they are the only wake sources the backlog paths need: conn
    /// writes nudge `wake_rx`, conn-write backlogs stalled on smoltcp tx
    /// capacity unblock on inbound ACKs (`endpoint.recv`), outbox retries
    /// ride this very timer cadence. Nothing sleeps with work only it can
    /// drain, so no busy-wait override is needed.
    fn sleep_duration(&mut self, now: SmolInstant) -> Duration {
        let smol_delay = self
            .iface
            .poll_delay(now, &self.sockets)
            .map_or(IDLE_SLEEP, |d| Duration::from_millis(d.total_millis()));
        smol_delay.min(WG_TIMER_INTERVAL.saturating_sub(self.last_timer.elapsed()))
    }

    async fn run(mut self) {
        self.kick_handshake();
        self.flush_outbox();
        'outer: loop {
            // 1. endpoint → tunn → device (bounded nonblocking drain).
            self.drain_wire();
            // 2. mailbox drain.
            loop {
                match self.rx.try_recv() {
                    Ok(ActorMsg::Shutdown) | Err(mpsc::error::TryRecvError::Disconnected) => {
                        break 'outer
                    }
                    Ok(msg) => self.handle_msg(msg),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }
            // 3. conn queues, smoltcp poll, tunnel egress, WG timers.
            self.service_sockets();
            let now = SmolInstant::now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            self.drain_device_tx();
            if self.last_timer.elapsed() >= WG_TIMER_INTERVAL {
                self.tick_timers();
                self.last_timer = StdInstant::now();
            }
            self.flush_outbox();

            let delay = self.sleep_duration(now);
            tokio::select! {
                biased;
                msg = self.rx.recv() => match msg {
                    None | Some(ActorMsg::Shutdown) => break 'outer,
                    Some(m) => self.handle_msg(m),
                },
                r = self.endpoint.recv(&mut self.recv_buf) => match r {
                    Ok(n) => self.decapsulate_wire(n),
                    Err(e) => {
                        warn!("wireguard {}: endpoint recv error: {e}", self.name);
                        // A dead socket must not spin the loop.
                        tokio::time::sleep(IDLE_SLEEP).await;
                    }
                },
                _ = self.wake_rx.recv() => {},
                _ = tokio::time::sleep(delay) => {},
            }
        }
        debug!("wireguard {}: pump stopped", self.name);
    }
}

/// Spawn the pump thread for one WireGuard adapter. Everything smoltcp
/// touches is built inside the thread (spec §4.3 Option A); only the
/// `Send`-safe parts — the connected std socket, the config, the mailbox —
/// cross over.
pub(crate) fn spawn_pump(
    config: &WireGuardConfig,
    std_sock: std::net::UdpSocket,
    endpoint_addr: SocketAddr,
) -> std::io::Result<(mpsc::Sender<ActorMsg>, std::thread::JoinHandle<()>)> {
    let (tx, rx) = mpsc::channel::<ActorMsg>(ACTOR_MAILBOX);
    let config = config.clone();
    let thread_name = format!("wg-pump-{}", config.name);
    let handle = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    warn!("wireguard {}: tokio runtime build failed: {e}", config.name);
                    return;
                }
            };
            rt.block_on(async move {
                match WgPump::new(&config, std_sock, endpoint_addr, rx) {
                    Ok(pump) => pump.run().await,
                    Err(e) => warn!("wireguard {}: pump init failed: {e}", config.name),
                }
            });
        })?;
    Ok((tx, handle))
}

/// `ProxyPacketConn` shim for a smoltcp UDP socket. `write_packet` enqueues
/// a datagram for the pump after allowed-IPs / family pre-checks;
/// `read_packet` drains the pump's recv channel.
pub(crate) struct WgPacketConn {
    local: SocketAddr,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
    tx: mpsc::Sender<UdpIo>,
    wake: mpsc::Sender<()>,
    closed: AtomicBool,
    allowed: Arc<Vec<ipnet::IpNet>>,
    has_v4: bool,
    has_v6: bool,
}

#[async_trait::async_trait]
impl ProxyPacketConn for WgPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some((data, addr)) => {
                // Nudge the pump: popping frees channel room it may have a
                // stalled write drain waiting on.
                let _ = self.wake.try_send(());
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, addr))
            }
            None => Err(MeowError::Proxy("wireguard udp: session closed".into())),
        }
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(MeowError::Proxy("wireguard udp: session closed".into()));
        }
        let ip = addr.ip();
        let family_ok = match ip {
            IpAddr::V4(_) => self.has_v4,
            IpAddr::V6(_) => self.has_v6,
        };
        if !family_ok {
            return Err(MeowError::NotSupported(format!(
                "wireguard udp: no {} tunnel address configured",
                if ip.is_ipv4() { "IPv4" } else { "IPv6" }
            )));
        }
        if !self.allowed.iter().any(|net| net.contains(&ip)) {
            return Err(MeowError::Proxy(format!(
                "wireguard udp: {ip} outside allowed-ips"
            )));
        }
        let len = buf.len();
        self.tx
            .send(UdpIo::SendTo {
                data: Bytes::copy_from_slice(buf),
                addr: *addr,
            })
            .await
            .map_err(|_| MeowError::Proxy("wireguard udp: session closed".into()))?;
        let _ = self.wake.try_send(());
        Ok(len)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local)
    }

    fn close(&self) -> Result<()> {
        if !self.closed.swap(true, Ordering::Relaxed) {
            let _ = self.tx.try_send(UdpIo::Close);
            let _ = self.wake.try_send(());
        }
        Ok(())
    }
}

impl Drop for WgPacketConn {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    //! Channel-level tests for the conn shims — no pump, no wire. They pin
    //! the backpressure/ordering machinery the service loop relies on:
    //! `pending_write` FIFO, `drain_notify` re-arm, `TcpIo` ordering, and
    //! `WgPacketConn`'s pre-send policy checks.
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use meow_wgstack::{TcpIo, WgStream};
    use tokio::io::AsyncWrite;

    use super::*;

    fn stream_pair(cap: usize) -> (WgStream, mpsc::Receiver<TcpIo>) {
        let (tx, rx) = mpsc::channel(cap);
        let (_read_tx, read_rx) = mpsc::channel(4);
        let (wake_tx, _wake_rx) = mpsc::channel(4);
        (
            WgStream {
                remote: "t".into(),
                rx: read_rx,
                tx,
                wake: wake_tx,
                drain_notify: Arc::new(tokio::sync::Notify::new()),
                pending_read: None,
                pending_write: None,
                read_eof: false,
                write_done: false,
            },
            rx,
        )
    }

    #[test]
    fn poll_write_parks_on_full_queue_and_resumes_after_drain() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let (mut stream, mut rx) = stream_pair(2);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"aa"),
            Poll::Ready(Ok(2))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"bb"),
            Poll::Ready(Ok(2))
        ));
        // Queue full → the item is stashed, the poll parks on drain_notify.
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"cc"),
            Poll::Pending
        ));
        assert!(stream.pending_write.is_some());
        // The pump drains both queued items, then re-arms the writer.
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Data(_))));
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Data(_))));
        stream.drain_notify.notify_one();
        // The stashed "cc" goes first; the new write follows in order.
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"dd"),
            Poll::Ready(Ok(2))
        ));
        match rx.try_recv() {
            Ok(TcpIo::Data(b)) => assert_eq!(&b[..], b"cc"),
            other => panic!("expected Data(cc), got {other:?}"),
        }
        match rx.try_recv() {
            Ok(TcpIo::Data(b)) => assert_eq!(&b[..], b"dd"),
            other => panic!("expected Data(dd), got {other:?}"),
        }
    }

    #[test]
    fn poll_shutdown_orders_behind_pending_data() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let (mut stream, mut rx) = stream_pair(2);
        // Data then shutdown with room: Data precedes Shutdown on the wire.
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"aa"),
            Poll::Ready(Ok(2))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Data(_))));
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Shutdown)));

        // Full queue: the FIN waits, it is never dropped silently.
        let (mut stream, mut rx) = stream_pair(1);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"x"),
            Poll::Ready(Ok(1))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Pending
        ));
        assert!(rx.try_recv().is_ok());
        stream.drain_notify.notify_one();
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Shutdown)));
    }

    #[test]
    fn drop_sends_close_while_write_side_open() {
        let (stream, mut rx) = stream_pair(4);
        drop(stream);
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Close)));
    }

    #[test]
    fn drop_after_shutdown_sends_nothing() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let (mut stream, mut rx) = stream_pair(4);
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Shutdown)));
        drop(stream);
        // write_done is set — Drop must not queue a Close behind the FIN.
        assert!(rx.try_recv().is_err());
    }

    /// A minimal client-side config: `client_secret`/`server_public` are
    /// the WG static keys; the pump's `Tunn` plays the client side.
    fn test_config(
        client_secret: &x25519::StaticSecret,
        server_public: &x25519::PublicKey,
    ) -> WireGuardConfig {
        WireGuardConfig {
            name: "wg-test".into(),
            server: "127.0.0.1".into(),
            port: 9,
            private_key: client_secret.to_bytes(),
            public_key: server_public.to_bytes(),
            pre_shared_key: None,
            ip: Some(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            ipv6: None,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            reserved: None,
            mtu: 1420,
            udp: true,
            remote_dns_resolve: true,
            persistent_keepalive: 0,
            dns: vec![],
        }
    }

    /// A pump on a bound-but-idle loopback endpoint socket.
    /// `WgPump::new` registers the socket with the current reactor, so
    /// call this only inside a `#[tokio::test]` runtime.
    fn pump_for_test(cfg: &WireGuardConfig) -> WgPump {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
        let (_tx, rx) = mpsc::channel(4);
        let endpoint: SocketAddr = "127.0.0.1:9".parse().unwrap();
        WgPump::new(cfg, std_sock, endpoint, rx).expect("pump build")
    }

    /// A real handshake initiation from the peer, but with WARP-style
    /// non-zero reserved bytes. boringtun's `parse_incoming_packet`
    /// checks type+reserved as one LE u32, so an unscrubbed datagram is
    /// `InvalidPacket` — the pump must zero the field before
    /// `decapsulate` sees it, the same don't-care treatment mihomo gives
    /// the wireguard-go parser.
    #[tokio::test(flavor = "current_thread")]
    async fn decapsulate_wire_zeroes_inbound_reserved_bytes() {
        let client_secret = x25519::StaticSecret::from([0x11; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0x22; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let mut server = Tunn::new(server_secret, client_public, None, None, 7, None);
        let mut buf = vec![0u8; 2048];
        let mut datagram = match server.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            other => panic!("expected WriteToNetwork, got {other:?}"),
        };
        // Cloudflare WARP's identifier — non-zero, stamped into the
        // reserved field of every inbound header.
        datagram[1..4].copy_from_slice(&[13, 53, 133]);

        pump.recv_buf[..datagram.len()].copy_from_slice(&datagram);
        pump.decapsulate_wire(datagram.len());

        // A valid initiation produces a HANDSHAKE_RESP (type 2) queued
        // for the wire. Without the scrub the parser rejects the
        // datagram and the outbox stays empty.
        assert_eq!(pump.outbox.len(), 1, "handshake response queued");
        assert_eq!(pump.outbox[0][0], 2, "response is a WG handshake response");
        // The taken recv_buf must be restored — an empty buffer left
        // behind would make every later endpoint.recv/try_recv a 0-byte
        // read.
        assert!(!pump.recv_buf.is_empty(), "recv_buf restored after take");
    }

    /// smoltcp clears a socket's `tuple` the moment its terminal RST is
    /// dispatched — after that `local_endpoint()` is `None`, so dead-sock
    /// port bookkeeping must come from `TcpState`, not the socket. This
    /// is the state a peer-RST'd socket is already in when cleanup runs
    /// (`process()` lands `Closed` with the tuple gone).
    #[tokio::test(flavor = "current_thread")]
    async fn dead_tcp_releases_port_after_tuple_cleared() {
        let client_secret = x25519::StaticSecret::from([0x33; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x44; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, _reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);
        assert_eq!(pump.used_ports.len(), 1);
        let port = *pump.used_ports.iter().next().unwrap();
        let handle = *pump.tcp.keys().next().unwrap();

        // Abort + one interface poll: the dispatch emits the RST, then
        // clears the tuple — `local_endpoint()` is `None` from here on.
        pump.sockets.get_mut::<tcp::Socket>(handle).abort();
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        assert!(
            pump.sockets
                .get::<tcp::Socket>(handle)
                .local_endpoint()
                .is_none(),
            "tuple must be gone for this test to mean anything"
        );

        pump.service_sockets();
        assert!(!pump.tcp.contains_key(&handle));
        assert!(
            !pump.used_ports.contains(&port),
            "ephemeral port {port} leaked"
        );
    }

    /// An idle socket must not accumulate a drain permit: `notify_one`
    /// stores one when nobody is waiting, and the next real writer would
    /// burn its wake on a permit that bought nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn idle_socket_stores_no_drain_permit() {
        let client_secret = x25519::StaticSecret::from([0x55; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x66; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, _reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);
        let handle = *pump.tcp.keys().next().unwrap();
        let notify = Arc::clone(&pump.tcp[&handle].drain_notify);

        pump.service_sockets();

        let mut notified = std::pin::pin!(notify.notified());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(notified.as_mut().poll(&mut cx), Poll::Pending));
    }

    /// …and the complement: write items that actually moved off the
    /// conn→pump channel this pass must still leave a permit behind, or
    /// a writer parked on the full channel never wakes.
    #[tokio::test(flavor = "current_thread")]
    async fn drained_write_stores_drain_permit() {
        let client_secret = x25519::StaticSecret::from([0x77; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x88; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, _reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);
        let handle = *pump.tcp.keys().next().unwrap();
        let notify = Arc::clone(&pump.tcp[&handle].drain_notify);
        pump.tcp[&handle]
            .pending
            .as_ref()
            .expect("pending dial")
            .write_tx
            .try_send(TcpIo::Data(Bytes::from_static(b"x")))
            .expect("channel has room");

        pump.service_sockets();

        let mut notified = std::pin::pin!(notify.notified());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(notified.as_mut().poll(&mut cx), Poll::Ready(())));
    }

    /// The UDP conn→pump drain must stop pulling once `out` reaches
    /// UDP_WRITE_QUEUE — the channel is the stall point, exactly like
    /// the TCP gate. Without it a socket wedged on `BufferFull` moved
    /// the bound into an unbounded VecDeque.
    #[tokio::test(flavor = "current_thread")]
    async fn udp_out_queue_bounded_on_send_stall() {
        let client_secret = x25519::StaticSecret::from([0x99; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0xaa; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, reply_rx) = oneshot::channel();
        pump.udp_bind(
            Arc::new(vec!["0.0.0.0/0".parse().unwrap()]),
            true,
            false,
            reply_tx,
        );
        let conn = reply_rx
            .await
            .expect("bind reply")
            .expect("udp_bind succeeds");
        let handle = *pump.udp.keys().next().expect("one udp flow");
        let dst: SocketAddr = "10.9.9.9:53".parse().unwrap();

        // Stall the socket: a full smoltcp tx buffer is what a congested
        // egress leaves behind (`can_send()` = `!tx_buffer.is_full()`).
        let socket = pump.sockets.get_mut::<udp::Socket>(handle);
        let meta = udp::UdpMetadata {
            endpoint: dst.into(),
            local_address: pump.src_v4,
            meta: Default::default(),
        };
        for _ in 0..UDP_SOCKET_PACKETS {
            socket.send_slice(b"x", meta).expect("tx buffer has room");
        }
        assert!(!socket.can_send(), "tx buffer must be full for the stall");

        // The backlog the stall piled up, plus ten datagrams still
        // channel-side (capacity 128 — sends never block).
        let st = pump.udp.get_mut(&handle).expect("udp state");
        for _ in 0..UDP_WRITE_QUEUE {
            st.out.push_back((Bytes::from_static(b"x"), dst));
        }
        for _ in 0..10 {
            conn.write_packet(b"y", &dst)
                .await
                .expect("channel has room");
        }

        pump.service_sockets();

        let st = &pump.udp[&handle];
        assert_eq!(
            st.out.len(),
            UDP_WRITE_QUEUE,
            "capped drain must not over-enqueue"
        );
        assert_eq!(
            st.write_rx.len(),
            10,
            "overflow stays channel-side as backpressure"
        );
    }

    /// The boundary form: `out` starts *below* UDP_WRITE_QUEUE and the
    /// drain must stop exactly at the cap — pulling only the headroom,
    /// never a datagram more.
    #[tokio::test(flavor = "current_thread")]
    async fn udp_out_drain_stops_at_cap_boundary() {
        let client_secret = x25519::StaticSecret::from([0xbb; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0xcc; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, reply_rx) = oneshot::channel();
        pump.udp_bind(
            Arc::new(vec!["0.0.0.0/0".parse().unwrap()]),
            true,
            false,
            reply_tx,
        );
        let conn = reply_rx
            .await
            .expect("bind reply")
            .expect("udp_bind succeeds");
        let handle = *pump.udp.keys().next().expect("one udp flow");
        let dst: SocketAddr = "10.9.9.9:53".parse().unwrap();

        // Same wedge as above: a full tx buffer blocks every send, so
        // the pass is a pure drain-cap exercise.
        let socket = pump.sockets.get_mut::<udp::Socket>(handle);
        let meta = udp::UdpMetadata {
            endpoint: dst.into(),
            local_address: pump.src_v4,
            meta: Default::default(),
        };
        for _ in 0..UDP_SOCKET_PACKETS {
            socket.send_slice(b"x", meta).expect("tx buffer has room");
        }
        assert!(!socket.can_send(), "tx buffer must be full for the stall");

        let st = pump.udp.get_mut(&handle).expect("udp state");
        for _ in 0..UDP_WRITE_QUEUE - 8 {
            st.out.push_back((Bytes::from_static(b"x"), dst));
        }
        for _ in 0..20 {
            conn.write_packet(b"y", &dst)
                .await
                .expect("channel has room");
        }

        pump.service_sockets();

        let st = &pump.udp[&handle];
        assert_eq!(
            st.out.len(),
            UDP_WRITE_QUEUE,
            "drain tops the backlog off at the cap, no further"
        );
        assert_eq!(
            st.write_rx.len(),
            12,
            "the 8 pulled in are the only channel items consumed"
        );
    }

    #[tokio::test]
    async fn packet_conn_enforces_allowed_ips_family_and_close() {
        let (_rtx, rrx) = mpsc::channel(4);
        let (wtx, _wrx) = mpsc::channel(4);
        let (waketx, _wakerx) = mpsc::channel(4);
        let conn = WgPacketConn {
            local: "10.0.0.2:1000".parse().unwrap(),
            rx: tokio::sync::Mutex::new(rrx),
            tx: wtx,
            wake: waketx,
            closed: AtomicBool::new(false),
            allowed: Arc::new(vec!["10.0.0.0/8".parse().unwrap(), "::/0".parse().unwrap()]),
            has_v4: true,
            has_v6: false,
        };
        let outside = "8.8.8.8:53".parse().unwrap();
        let err = conn.write_packet(b"x", &outside).await.unwrap_err();
        assert!(err.to_string().contains("outside allowed-ips"), "{err}");

        let v6 = "[fd00::1]:53".parse().unwrap();
        let err = conn.write_packet(b"x", &v6).await.unwrap_err();
        assert!(matches!(err, MeowError::NotSupported(_)), "{err:?}");

        let inside = "10.9.9.9:53".parse().unwrap();
        assert_eq!(conn.write_packet(b"x", &inside).await.unwrap(), 1);

        conn.close().unwrap();
        let err = conn.write_packet(b"x", &inside).await.unwrap_err();
        assert!(err.to_string().contains("session closed"), "{err}");
    }
}
