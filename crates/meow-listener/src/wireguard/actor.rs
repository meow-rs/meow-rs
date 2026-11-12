//! The single-threaded actor: endpoint socket, peer table, smoltcp
//! interface, lazy listen pool, inner-UDP flow table — all owned by one
//! current-thread runtime so no lock ever crosses a smoltcp or `Tunn`
//! boundary.
//!
//! Loop order mirrors the outbound pump (`meow-proxy/src/wireguard/
//! pump.rs`) with the directions reversed:
//!
//! 1. `drain_wire` — pull up to [`WIRE_DRAIN_BUDGET`] datagrams off the
//!    endpoint, run them through the [`PeerTable`] (verify → dispatch →
//!    authenticate → roam), and sink `Action::Inner` packets: TCP feeds
//!    `device.rx_queue`, UDP feeds the flow table.
//! 2. `service_tcp` — conn↔socket plumbing for established flows (the
//!    pump's `service_sockets` shape, minus dial-pending, plus the
//!    Established→route-task handoff).
//! 3. `iface.poll` — smoltcp consumes the rx queue (SYNs accept,
//!    segments deliver, emits go to `device.tx_queue`).
//! 4. `post_poll` — sweep listen-pool entries whose socket left
//!    `State::Listen` (errata E5: only `Listen` sockets are pool
//!    occupants) and register fresh flow sockets, recording each
//!    socket's owning peer from the listener that accepted it.
//! 5. `drain_device_tx` — every emitted packet's 4-tuple maps back to
//!    the flow it belongs to, hence to the peer that owns the session
//!    it encrypts under (a stray RST the demux never matched takes the
//!    `rst_hint` its trigger recorded).
//! 6. timer pass — [`RateLimiter::reset_count`] every tick (errata E1:
//!    the limiter's own debounce decides), per-peer `update_timers`,
//!    UDP-flow liveness sweep.
//! 7. `flush_outbox` — nonblocking sends; a full socket backs off to
//!    the next pass rather than stalling the loop.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use meow_common::{ConnType, Metadata, Network};
use meow_tunnel::TunnelInner;
use meow_wgstack::{
    enlarge_recv_buffer, ChannelDevice, StreamEvent, TcpIo, WgStream, TCP_READ_QUEUE,
    TCP_SOCKET_BUF, TCP_WRITE_QUEUE, WG_TIMER_INTERVAL, WIRE_DRAIN_BUDGET,
};
use meow_wireguard::{TunnResult, DATA_OVERHEAD_SZ};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time::{timeout_at, Instant as TokioInstant};
use tracing::{debug, info, trace, warn};

use super::demux::{Action, PeerTable};
use super::inner_udp::{self, UdpFlow, UdpFlowKey};
use crate::sniffer::SnifferRuntime;
use crate::stream_sniff::{sniff_first_payload, STREAM_SNIFF_GATHER_MAX};
use crate::wireguard::WireGuardListener;

/// The lazy listen pool's bound: one placeholder socket per
/// (peer, dport) pair in demand, at most this many. Eviction only ever
/// removes sockets still in `State::Listen` (errata E5 — a socket that
/// already transitioned is a flow, not a pool member).
const LISTEN_POOL_CAP: usize = 64;

/// Bytes drained per `socket.recv` call — sized to a full inner-MTU TCP
/// segment so `read_tx` items stay packet-shaped.
const TCP_READ_CHUNK: usize = 4096;

/// Idle `select!` sleep when smoltcp reports no `poll_delay` — the
/// pump's own fallback (its comment in `sleep_duration` explains why
/// nothing else needs to wake us).
const IDLE_SLEEP: Duration = Duration::from_millis(50);

/// Bounded inject queue (UDP reply packets built by flow tasks back to
/// the actor). Full → the flow drops its reply (UDP drop semantics).
const INJECT_QUEUE: usize = 256;

/// Original-direction inner TCP tuple — `(client_ip, client_port,
/// target_ip, target_port)` as the peer wrote it. Reply packets reverse
/// it back to this key, so one map serves both directions.
type InnerTuple = (IpAddr, u16, IpAddr, u16);

/// One pool occupant: a smoltcp socket parked in `State::Listen` on a
/// dport, owned by the peer slot whose SYN created it.
struct ListenEntry {
    handle: smoltcp::iface::SocketHandle,
    slot: usize,
    created: Instant,
}

/// Actor-side state of one inner TCP connection — the pump's `TcpState`
/// minus dial-pending, plus the pre-Established channel parking.
struct TcpFlow {
    slot: usize,
    /// The flow's tuple key (client→target direction) — removed from
    /// `tcp_by_tuple` when the socket dies.
    key: InnerTuple,
    read_tx: mpsc::Sender<StreamEvent>,
    /// Held until the route task spawns at `Established` — a
    /// SYN-flood'd socket that never completes costs two dead channels,
    /// never a routed task.
    read_rx: Option<mpsc::Receiver<StreamEvent>>,
    write_tx: Option<mpsc::Sender<TcpIo>>,
    write_rx: mpsc::Receiver<TcpIo>,
    drain_notify: Arc<tokio::sync::Notify>,
    out: VecDeque<TcpIo>,
    pending_read: VecDeque<StreamEvent>,
    eof_sent: bool,
    graceful_close: bool,
    spawned: bool,
}

/// Parsed inner-packet view used by the demux→stack bridge.
struct InnerView<'a> {
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    l4: &'a [u8],
}

struct TcpView {
    sport: u16,
    dport: u16,
    syn: bool,
    ack: bool,
}

pub(super) struct WgActor {
    name: String,
    endpoint: tokio::net::UdpSocket,
    bound_port: u16,
    table: PeerTable,
    device: ChannelDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    /// Reusable work buffers — `work` for tunn crypto (wire MTU sized),
    /// `recv_buf`/`select_buf` for datagrams.
    work: Vec<u8>,
    recv_buf: Vec<u8>,
    outbox: VecDeque<(SocketAddr, Vec<u8>)>,

    tcp: HashMap<smoltcp::iface::SocketHandle, TcpFlow>,
    tcp_by_tuple: HashMap<InnerTuple, smoltcp::iface::SocketHandle>,
    /// ≥ one entry per demanded dport, each tagged with the peer whose
    /// SYN owns it — the cross-peer ambiguity a shared-per-port pool
    /// would introduce (a listener can't tell which peer's SYN it
    /// accepted) is resolved by replacing a still-`Listen` entry when a
    /// different peer needs the port.
    listen_pool: HashMap<u16, ListenEntry>,
    /// The peer a just-created listener belongs to: consumed when its
    /// socket leaves `Listen` and becomes a flow.
    listener_owner: HashMap<smoltcp::iface::SocketHandle, usize>,
    /// Reversed-tuple → peer slot for emitted RSTs the demux didn't
    /// match (refused SYNs, strays). Populated at feed time, drained
    /// with `tx_queue`, cleared each pass — the emission is same-poll.
    rst_hint: HashMap<InnerTuple, usize>,
    /// SYNs fed to smoltcp since the last `post_poll` — the in-flight
    /// half of the connection cap so a same-batch burst can't overshoot.
    in_flight_accept: usize,

    udp_flows: HashMap<UdpFlowKey, UdpFlow>,
    udp_enabled: bool,
    udp_timeout: Duration,
    inner_mtu: usize,
    max_connections: usize,
    last_timer: Instant,

    shutdown_rx: mpsc::Receiver<()>,
    wake_tx: mpsc::Sender<()>,
    wake_rx: mpsc::Receiver<()>,
    inject_rx: mpsc::Receiver<(usize, Bytes)>,
    inject_tx: mpsc::Sender<(usize, Bytes)>,

    inner: Arc<TunnelInner>,
    sniffer: Option<Arc<SnifferRuntime>>,
    main_rt: tokio::runtime::Handle,
}

impl WgActor {
    /// Build the actor inside its thread: the smoltcp `Interface` is
    /// AnyIP (arbitrary inner destinations reach our lazy listeners —
    /// errata E2 requires both `set_any_ip(true)` *and* a route whose
    /// gateway is an interface-owned address, or ingress packets are
    /// dropped as unroutable before socket demux).
    pub fn new(
        listener: WireGuardListener,
        std_sock: std::net::UdpSocket,
        shutdown_rx: mpsc::Receiver<()>,
        main_rt: tokio::runtime::Handle,
    ) -> io::Result<Self> {
        let WireGuardListener {
            tunnel,
            cfg,
            name,
            max_connections,
            sniffer,
        } = listener;

        let table = PeerTable::new(&cfg).map_err(io::Error::other)?;

        // MTU math per spec §6: the configured value is the *outer* wire
        // MTU; the inner stack gets `mtu - 64` (WireGuard + UDP + IP
        // overhead), floor 576.
        let mtu = usize::from(cfg.mtu);
        let inner_mtu = mtu.saturating_sub(64).max(576);

        let endpoint = tokio::net::UdpSocket::from_std(std_sock)?;
        enlarge_recv_buffer(&endpoint);
        let bound_port = endpoint.local_addr()?.port();

        // AnyIP needs a route resolving to an interface-owned address —
        // both the v4 and v6 defaults point at the interface's own IPs,
        // which is what makes "gateway owned by the interface" hold.
        let mut device = ChannelDevice::new(inner_mtu);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = rand::random();
        let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::now());
        let any_v4 = smoltcp::wire::Ipv4Address::new(0, 0, 0, 1);
        let any_v6 = smoltcp::wire::Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(any_v4.into(), 32));
            let _ = addrs.push(IpCidr::new(any_v6.into(), 128));
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(any_v4)
            .map_err(|e| io::Error::other(format!("smoltcp v4 route: {e}")))?;
        iface
            .routes_mut()
            .add_default_ipv6_route(any_v6)
            .map_err(|e| io::Error::other(format!("smoltcp v6 route: {e}")))?;
        iface.set_any_ip(true);

        let (wake_tx, wake_rx) = mpsc::channel(1);
        let (inject_tx, inject_rx) = mpsc::channel(INJECT_QUEUE);

        Ok(Self {
            bound_port,
            table,
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            work: vec![0u8; mtu + 256],
            recv_buf: vec![0u8; mtu + 256],
            outbox: VecDeque::new(),
            tcp: HashMap::new(),
            tcp_by_tuple: HashMap::new(),
            listen_pool: HashMap::new(),
            listener_owner: HashMap::new(),
            rst_hint: HashMap::new(),
            in_flight_accept: 0,
            udp_flows: HashMap::new(),
            udp_enabled: cfg.udp,
            udp_timeout: cfg.udp_timeout,
            inner_mtu,
            max_connections,
            last_timer: Instant::now(),
            shutdown_rx,
            wake_tx,
            wake_rx,
            inject_rx,
            inject_tx,
            inner: Arc::clone(tunnel.inner()),
            sniffer,
            main_rt,
            name,
            endpoint,
        })
    }

    // ── main loop ────────────────────────────────────────────────────

    pub async fn run(mut self) {
        info!(
            "wireguard listener '{}': bound :{} ({} peers, inner mtu {})",
            self.name,
            self.bound_port,
            self.table.peers().len(),
            self.inner_mtu
        );
        loop {
            self.service();

            let delay = self.next_delay();
            tokio::select! {
                biased;
                _ = self.shutdown_rx.recv() => break,
                r = self.endpoint.recv_from(&mut self.recv_buf) => {
                    match r {
                        Ok((n, src)) => self.demux_one(src, n),
                        Err(e) => debug!("wireguard {}: endpoint recv error: {e}", self.name),
                    }
                }
                item = self.inject_rx.recv() => {
                    if let Some((slot, pkt)) = item {
                        self.handle_inject(slot, &pkt);
                    }
                    // None ⇒ all flow tasks gone — keep looping.
                }
                _ = self.wake_rx.recv() => {}
                _ = tokio::time::sleep(delay) => {}
            }
        }
        debug!("wireguard listener '{}': actor stopped", self.name);
    }

    /// One service pass: drain → service → poll → register → emit →
    /// timers → flush.
    fn service(&mut self) {
        self.drain_wire();
        self.service_tcp();
        self.sweep_udp_flows();
        let now = SmolInstant::now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.post_poll();
        self.drain_device_tx();
        if self.last_timer.elapsed() >= WG_TIMER_INTERVAL {
            self.last_timer = Instant::now();
            // Errata E1: reset_count is called every tick; the
            // limiter's own ~1s debounce decides whether the window
            // actually rolled.
            self.table.reset_rate_limit();
            let mut work = std::mem::take(&mut self.work);
            for action in self.table.tick(&mut work) {
                self.apply_action(action);
            }
            self.work = work;
            for peer in self.table.peers_mut() {
                if !peer.session_logged && peer.tunn.time_since_last_handshake().is_some() {
                    info!(
                        "wireguard {}: peer '{}' session established",
                        self.name, peer.label
                    );
                    peer.session_logged = true;
                }
            }
        }
        self.flush_outbox();
    }

    /// The next sleep bound — the pump's `sleep_duration` shape:
    /// smoltcp's own poll delay wins, capped by the WG tick so the
    /// timer pass never runs late.
    fn next_delay(&mut self) -> Duration {
        let smol_delay = self
            .iface
            .poll_delay(SmolInstant::now(), &self.sockets)
            .map_or(IDLE_SLEEP, |d| Duration::from_millis(d.total_millis()));
        smol_delay.min(
            WG_TIMER_INTERVAL
                .checked_sub(self.last_timer.elapsed())
                .unwrap_or(Duration::ZERO),
        )
    }

    // ── wire ingress ─────────────────────────────────────────────────

    /// Nonblocking drain of everything the endpoint already has, up to
    /// [`WIRE_DRAIN_BUDGET`] — the burst bound the pump shares.
    fn drain_wire(&mut self) {
        for _ in 0..WIRE_DRAIN_BUDGET {
            match self.endpoint.try_recv_from(&mut self.recv_buf) {
                Ok((n, src)) => self.demux_one(src, n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    debug!("wireguard {}: endpoint recv error: {e}", self.name);
                    break;
                }
            }
        }
    }

    /// One wire datagram through the peer table. The recv buffer is
    /// `mem::take`n so the demux borrows plain values, and **inbound
    /// reserved bytes 1..4 are cleared before parsing** — peers that
    /// stamp a WARP-style field must not corrupt the type/index check.
    ///
    /// The buffer keeps its full length — only `&pkt[..n]` goes to the
    /// demux. Truncating the Vec instead would shrink the slice the next
    /// `recv_from` writes into, silently dropping every datagram larger
    /// than the last one received (a 32-byte keepalive would cap the
    /// whole session at 32 bytes).
    fn demux_one(&mut self, src: SocketAddr, n: usize) {
        let mut pkt = std::mem::take(&mut self.recv_buf);
        if n >= 4 {
            pkt[1..4].fill(0);
        }
        let mut work = std::mem::take(&mut self.work);
        for action in self.table.process_datagram(src, &pkt[..n], &mut work) {
            self.apply_action(action);
        }
        self.work = work;
        self.recv_buf = pkt;
    }

    /// Fold a demux action into socket/flow work.
    fn apply_action(&mut self, action: Action) {
        match action {
            Action::ToWire { addr, bytes, .. } => self.outbox.push_back((addr, bytes)),
            Action::Inner { slot, v6, bytes } => self.handle_inner(slot, &bytes, v6),
        }
    }

    // ── inner packet → stack ─────────────────────────────────────────

    /// The inner-packet entry point: parse the L3/L4 headers and route
    /// to TCP (smoltcp) or UDP (flow table). Fragments drop — the inner
    /// MTU guarantee means a whole datagram always arrives; a fragment
    /// signals a peer violating its own MTU.
    fn handle_inner(&mut self, slot: usize, pkt: &[u8], v6: bool) {
        let Some(view) = parse_inner(pkt, v6) else {
            trace!("wireguard {}: malformed/fragmented inner packet", self.name);
            return;
        };
        match view.proto {
            6 => self.inner_tcp(slot, pkt, &view),
            17 if self.udp_enabled => self.inner_udp(slot, &view),
            _ => {}
        }
    }

    /// Feed a TCP segment to smoltcp. A fresh `SYN` (no ACK) is the only
    /// packet that can demand a listener — an existing flow socket's
    /// retransmitted SYN demuxes to it directly, and anything else
    /// either hits a tuple or draws an RST we route back via
    /// `rst_hint`.
    fn inner_tcp(&mut self, slot: usize, pkt: &[u8], view: &InnerView) {
        let Some(tcpv) = parse_tcp(view.l4) else {
            return;
        };
        let key: InnerTuple = (view.src, tcpv.sport, view.dst, tcpv.dport);
        if tcpv.syn
            && !tcpv.ack
            && !self.tcp_by_tuple.contains_key(&key)
            && !self.at_capacity()
            && self.ensure_listener(slot, tcpv.dport)
        {
            self.in_flight_accept += 1;
        }
        if !self.tcp_by_tuple.contains_key(&key) {
            // No flow claims this packet — if smoltcp answers with an
            // RST it carries the reversed tuple, which maps back via
            // this hint to the peer that must encrypt it.
            self.rst_hint.insert(key, slot);
        }
        self.device.rx_queue.push_back(pkt.to_vec());
    }

    /// Hand a UDP datagram's payload to its flow, creating the flow on
    /// first use. The flow key carries the peer slot, so two peers with
    /// identical inner tuples keep separate sessions and replies.
    fn inner_udp(&mut self, slot: usize, view: &InnerView) {
        let Some((sport, dport)) = parse_udp_ports(view.l4) else {
            return;
        };
        let payload = &view.l4[8..];
        let client = SocketAddr::new(view.src, sport);
        let target = SocketAddr::new(view.dst, dport);
        let key = UdpFlowKey {
            slot,
            src: client,
            dst: target,
        };
        if let Some(flow) = self.udp_flows.get_mut(&key) {
            flow.last_active = Instant::now();
            // Full → UDP drop semantics (bounded queue, same as TProxy).
            let _ = flow.tx.try_send(Bytes::copy_from_slice(payload));
            return;
        }
        if self.at_capacity() {
            return; // conn cap counts TCP conns + UDP flows together
        }
        let (tx, rx) = mpsc::channel(inner_udp::UDP_FLOW_QUEUE);
        let args = inner_udp::FlowArgs {
            inner: Arc::clone(&self.inner),
            in_name: self.name.clone().into(),
            in_port: self.bound_port,
            slot,
            client,
            orig_dst: target,
            udp_timeout: self.udp_timeout,
            inner_mtu: self.inner_mtu,
            inject_tx: self.inject_tx.clone(),
        };
        // Routing tasks run on the main runtime — the actor's
        // current-thread rt only ever polls the wire loop.
        self.main_rt.spawn(async move {
            if let Err(e) = inner_udp::run_flow(args, rx).await {
                debug!("wireguard UDP flow {client} -> {target}: {e}");
            }
        });
        let _ = tx.try_send(Bytes::copy_from_slice(payload));
        self.udp_flows.insert(
            key,
            UdpFlow {
                tx,
                last_active: Instant::now(),
            },
        );
    }

    /// A flow task's finished inner packet — encrypt under the owning
    /// peer's session and send to its endpoint.
    fn handle_inject(&mut self, slot: usize, pkt: &[u8]) {
        let mut work = std::mem::take(&mut self.work);
        if pkt.len() + DATA_OVERHEAD_SZ <= work.len() {
            if let Some(peer) = self.table.peers_mut().get_mut(slot) {
                if let TunnResult::WriteToNetwork(b) = peer.tunn.encapsulate(pkt, &mut work) {
                    if let Some(addr) = peer.endpoint {
                        let mut buf = b.to_vec();
                        peer.stamp_reserved(&mut buf);
                        self.outbox.push_back((addr, buf));
                    }
                }
            }
        }
        self.work = work;
    }

    // ── listen pool + flow registration ──────────────────────────────

    /// Combined TCP+UDP cap (`max-connections`; `0` = unlimited).
    fn at_capacity(&self) -> bool {
        self.max_connections > 0
            && self.tcp.len() + self.in_flight_accept + self.udp_flows.len() >= self.max_connections
    }

    /// Ensure a `State::Listen` socket exists for `(slot, dport)` and
    /// that this peer's SYN owns it. Returns false when the SYN should
    /// be dropped: the pool is full *and* no `Listen`-state socket is
    /// evictable (errata E5), or smoltcp refused the listen.
    fn ensure_listener(&mut self, slot: usize, dport: u16) -> bool {
        if let Some(entry) = self.listen_pool.get(&dport) {
            let socket = self.sockets.get::<tcp::Socket>(entry.handle);
            if socket.state() == tcp::State::Listen && entry.slot == slot {
                return true;
            }
            // Stale (already transitioned → it's a flow now) or owned by
            // a different peer: a still-Listen socket holds no per-peer
            // state, so replacing it costs nothing and keeps accept
            // peer-affine.
            self.sockets.remove(entry.handle);
            self.listener_owner.remove(&entry.handle);
            self.listen_pool.remove(&dport);
        }
        if self.listen_pool.len() >= LISTEN_POOL_CAP && !self.evict_oldest_listener() {
            // Errata E5: nothing Listen-state to evict — the new SYN is
            // dropped, silently (it will still be fed; smoltcp may RST,
            // which is the §4.2 pool-exhausted answer).
            return false;
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]),
            tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]),
        );
        if socket
            .listen(IpListenEndpoint {
                addr: None,
                port: dport,
            })
            .is_err()
        {
            return false;
        }
        let handle = self.sockets.add(socket);
        self.listener_owner.insert(handle, slot);
        self.listen_pool.insert(
            dport,
            ListenEntry {
                handle,
                slot,
                created: Instant::now(),
            },
        );
        true
    }

    /// Evict the oldest pool occupant still in `State::Listen`. Returns
    /// false when no occupant qualifies — the E5 "no evictable" case.
    fn evict_oldest_listener(&mut self) -> bool {
        let oldest = self
            .listen_pool
            .iter()
            .filter(|(_, e)| {
                self.sockets.get::<tcp::Socket>(e.handle).state() == tcp::State::Listen
            })
            .min_by_key(|(_, e)| e.created)
            .map(|(p, _)| *p);
        let Some(port) = oldest else {
            return false;
        };
        let entry = self.listen_pool.remove(&port).expect("entry checked above");
        self.sockets.remove(entry.handle);
        self.listener_owner.remove(&entry.handle);
        true
    }

    /// After `iface.poll`: listeners that accepted a SYN left the pool
    /// (their socket is now a flow in `SynReceived`+); register fresh
    /// flow sockets with the owning peer from `listener_owner`.
    fn post_poll(&mut self) {
        self.in_flight_accept = 0;
        let mut stale = Vec::new();
        for (port, entry) in &self.listen_pool {
            if self.sockets.get::<tcp::Socket>(entry.handle).state() != tcp::State::Listen {
                stale.push(*port);
            }
        }
        for port in stale {
            self.listen_pool.remove(&port);
        }

        let mut new_flows = Vec::new();
        for (handle, socket) in self.sockets.iter_mut() {
            let smoltcp::socket::Socket::Tcp(t) = socket else {
                continue;
            };
            match t.state() {
                tcp::State::Listen | tcp::State::Closed => {}
                _ => {
                    if self.tcp.contains_key(&handle) {
                        continue;
                    }
                    if let (Some(local), Some(remote)) = (t.local_endpoint(), t.remote_endpoint()) {
                        new_flows.push((handle, local, remote));
                    }
                }
            }
        }
        for (handle, local, remote) in new_flows {
            // The listener that accepted this SYN recorded the peer that
            // created it — the only place peer affinity exists, since a
            // 4-tuple can't disambiguate overlapping peers.
            let Some(slot) = self.listener_owner.remove(&handle) else {
                // A flow with no recorded owner can't be routed back —
                // refuse it rather than guess.
                self.sockets.get_mut::<tcp::Socket>(handle).abort();
                continue;
            };
            // Second capacity gate: `inner_tcp`'s `in_flight_accept`
            // only stops *new listener demand* — a SYN to a port whose
            // listener already exists is accepted by smoltcp no matter
            // how full we are. Refuse it here so `max_connections`
            // holds across the whole accept surface (the abort is the
            // RST refusal §11.2's backpressure test expects).
            if self.at_capacity() {
                self.sockets.get_mut::<tcp::Socket>(handle).abort();
                continue;
            }
            self.register_tcp_flow(handle, slot, local, remote);
        }
    }

    /// Channels + table entries for a newly accepted socket. The route
    /// task itself waits for `Established` — a socket that never
    /// completes the handshake never spawns one.
    fn register_tcp_flow(
        &mut self,
        handle: smoltcp::iface::SocketHandle,
        slot: usize,
        local: IpEndpoint,
        remote: IpEndpoint,
    ) {
        let (read_tx, read_rx) = mpsc::channel(TCP_READ_QUEUE);
        let (write_tx, write_rx) = mpsc::channel(TCP_WRITE_QUEUE);
        let client = SocketAddr::new(remote.addr.into(), remote.port);
        let target = SocketAddr::new(local.addr.into(), local.port);
        debug!(
            "wireguard {}: TCP flow {client} -> {target} accepted (peer '{}')",
            self.name,
            self.table.peers()[slot].label
        );
        self.tcp_by_tuple.insert(
            (client.ip(), client.port(), target.ip(), target.port()),
            handle,
        );
        self.tcp.insert(
            handle,
            TcpFlow {
                slot,
                key: (client.ip(), client.port(), target.ip(), target.port()),
                read_tx,
                read_rx: Some(read_rx),
                write_tx: Some(write_tx),
                write_rx,
                drain_notify: Arc::new(tokio::sync::Notify::new()),
                out: VecDeque::new(),
                pending_read: VecDeque::new(),
                eof_sent: false,
                graceful_close: false,
                spawned: false,
            },
        );
    }

    // ── TCP plumbing (the pump's service_sockets, inbound shape) ──────

    fn service_tcp(&mut self) {
        let mut dead: Vec<smoltcp::iface::SocketHandle> = Vec::new();
        // Spawns are collected, not run inline: `spawn_route_task`
        // borrows `&self`, which can't happen while the socket borrow
        // below is live.
        let mut to_spawn: Vec<(usize, WgStream, IpEndpoint, IpEndpoint)> = Vec::new();
        let wake_tx = self.wake_tx.clone();
        for (handle, st) in &mut self.tcp {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);

            // Established → hand the conn to a route task, once.
            if !st.spawned && socket.state() == tcp::State::Established {
                st.spawned = true;
                let (Some(read_rx), Some(write_tx)) = (st.read_rx.take(), st.write_tx.take())
                else {
                    dead.push(*handle);
                    continue;
                };
                let stream = WgStream {
                    remote: format!("{:?}", socket.remote_endpoint()),
                    rx: read_rx,
                    tx: write_tx,
                    wake: wake_tx.clone(),
                    drain_notify: Arc::clone(&st.drain_notify),
                    pending_read: None,
                    pending_write: None,
                    read_eof: false,
                    write_done: false,
                };
                let (Some(local), Some(remote)) =
                    (socket.local_endpoint(), socket.remote_endpoint())
                else {
                    dead.push(*handle);
                    continue;
                };
                to_spawn.push((st.slot, stream, local, remote));
            }

            // conn→actor drain (channel disconnect = conn dropped).
            let mut conn_gone = false;
            loop {
                match st.write_rx.try_recv() {
                    Ok(io) => st.out.push_back(io),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        conn_gone = true;
                        break;
                    }
                }
            }
            if conn_gone && !st.graceful_close {
                st.out.push_back(TcpIo::Close);
            }

            // Ordered writes into the socket (pump semantics: only
            // re-arm drain_notify when this pass did write work).
            let had_out = !st.out.is_empty();
            while let Some(front) = st.out.front_mut() {
                match front {
                    TcpIo::Data(b) => {
                        if !socket.can_send() {
                            break;
                        }
                        match socket.send_slice(b) {
                            Ok(0) | Err(_) => break,
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
                        if !st.graceful_close {
                            socket.abort();
                        }
                        st.out.pop_front();
                    }
                }
            }
            if had_out {
                st.drain_notify.notify_one();
            }

            // socket→conn reads.
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

            // EOF + teardown.
            if !st.eof_sent && st.spawned && !socket.can_recv() && !socket.may_recv() {
                match st.read_tx.try_send(StreamEvent::Closed) {
                    Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => st.eof_sent = true,
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                }
            }
            if !socket.is_open() {
                dead.push(*handle);
            }
        }
        for handle in dead {
            self.remove_tcp_flow(handle);
        }
        for (slot, stream, local, remote) in to_spawn {
            self.spawn_route_task(slot, stream, local, remote);
        }
    }

    /// Spawn the routing task on the main runtime: the TUN path's
    /// sniff-window → gather → `sniff_bytes` → `route_inbound_tcp`
    /// shape, with `ConnType::WireGuard` metadata and the listener's
    /// bound port as `in_port`.
    fn spawn_route_task(
        &self,
        slot: usize,
        mut stream: WgStream,
        local: IpEndpoint,
        remote: IpEndpoint,
    ) {
        let client = SocketAddr::new(remote.addr.into(), remote.port);
        let target = SocketAddr::new(local.addr.into(), local.port);
        let inner = Arc::clone(&self.inner);
        let sniffer = self.sniffer.clone();
        let in_name: Arc<str> = self.name.clone().into();
        let in_port = self.bound_port;
        let peer_label = self.table.peers()[slot].label.clone();
        self.main_rt.spawn(async move {
            let prefix = match sniff_first_payload(&mut stream).await {
                Ok(p) => {
                    if p.is_empty() {
                        debug!("wireguard {in_name}: TCP {client} -> {target} silent in window");
                    }
                    p
                }
                Err(e) => {
                    debug!(
                        "wireguard {in_name}: dropping TCP {client} -> {target} \
                         before payload: {e}"
                    );
                    return;
                }
            };
            let mut metadata = Metadata {
                network: Network::Tcp,
                conn_type: ConnType::WireGuard,
                src_ip: Some(client.ip()),
                src_port: client.port(),
                dst_ip: Some(target.ip()),
                dst_port: target.port(),
                in_name: in_name.as_ref().into(),
                in_port,
                ..Default::default()
            };
            let mut prefix = prefix;
            if let Some(rt) = &sniffer {
                crate::sniffer::prefill_host(&inner.resolver(), &mut metadata);
                let deadline = TokioInstant::now() + rt.timeout();
                let mut chunk = [0u8; 2048];
                while prefix.len() < STREAM_SNIFF_GATHER_MAX
                    && crate::sniffer::tls_record_incomplete(&prefix)
                {
                    match timeout_at(deadline, stream.read(&mut chunk)).await {
                        Ok(Ok(n)) if n > 0 => prefix.extend_from_slice(&chunk[..n]),
                        _ => break,
                    }
                }
                rt.sniff_bytes(&prefix, &mut metadata);
            }
            let _ = peer_label; // diagnostics only; never enters Metadata
            meow_tunnel::tcp::route_inbound_tcp(&inner, &mut stream, metadata, &prefix).await;
        });
    }

    /// Remove a dead socket and its bookkeeping — socket handle, flow
    /// entry, tuple map (and any listener owner entry, defensively).
    fn remove_tcp_flow(&mut self, handle: smoltcp::iface::SocketHandle) {
        if let Some(st) = self.tcp.remove(&handle) {
            self.tcp_by_tuple.remove(&st.key);
        }
        self.listener_owner.remove(&handle);
        if self.sockets.iter().any(|(h, _)| h == handle) {
            self.sockets.remove(handle);
        }
    }

    // ── device tx → wire ─────────────────────────────────────────────

    /// Encrypt each emitted packet under its owning peer's session. The
    /// packet's reversed tuple locates the flow (hence peer slot); an
    /// unmatched packet — an RST for a refused SYN or stray — consults
    /// the `rst_hint` its ingress recorded.
    fn drain_device_tx(&mut self) {
        let mut work = std::mem::take(&mut self.work);
        while let Some(pkt) = self.device.tx_queue.pop_front() {
            let Some(slot) = self.route_tx_packet(&pkt) else {
                trace!("wireguard {}: unroutable inner tx packet", self.name);
                continue;
            };
            if pkt.len() + DATA_OVERHEAD_SZ > work.len() {
                warn!(
                    "wireguard {}: dropping {}B inner tx packet (work {}B)",
                    self.name,
                    pkt.len(),
                    work.len()
                );
                continue;
            }
            let Some(peer) = self.table.peers_mut().get_mut(slot) else {
                continue;
            };
            if let TunnResult::WriteToNetwork(b) = peer.tunn.encapsulate(&pkt, &mut work) {
                let Some(addr) = peer.endpoint else {
                    continue;
                };
                let mut buf = b.to_vec();
                peer.stamp_reserved(&mut buf);
                self.outbox.push_back((addr, buf));
            }
        }
        self.work = work;
        // RST hints only live for the poll that produced them — a stale
        // entry could misroute a same-tuple RST of a later packet.
        self.rst_hint.clear();
    }

    /// Map an emitted inner packet back to its peer slot.
    fn route_tx_packet(&self, pkt: &[u8]) -> Option<usize> {
        let v6 = pkt.first().is_some_and(|b| b >> 4 == 6);
        let view = parse_inner(pkt, v6)?;
        let t = parse_tcp(view.l4)?;
        // The reply's (src:port → dst:port) reverses the flow key.
        let key = (view.dst, t.dport, view.src, t.sport);
        self.tcp_by_tuple
            .get(&key)
            .and_then(|h| self.tcp.get(h).map(|f| f.slot))
            .or_else(|| self.rst_hint.get(&key).copied())
    }

    /// Nonblocking sends; a full socket defers the tail to the next
    /// pass rather than stalling the loop.
    fn flush_outbox(&mut self) {
        while let Some((addr, pkt)) = self.outbox.pop_front() {
            match self.endpoint.try_send_to(&pkt, addr) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.outbox.push_front((addr, pkt));
                    break;
                }
                Err(e) => {
                    debug!(
                        "wireguard {}: endpoint send to {addr} failed: {e}",
                        self.name
                    );
                }
            }
        }
    }

    // ── UDP flow liveness ────────────────────────────────────────────

    /// Prune dead/idle UDP flows: a task that evicted itself drops its
    /// `rx`, making `tx` report closed; the liveness stamp catches the
    /// remainder.
    fn sweep_udp_flows(&mut self) {
        let timeout = self.udp_timeout;
        self.udp_flows
            .retain(|_, flow| !flow.tx.is_closed() && flow.last_active.elapsed() <= timeout);
    }
}

// ── inner packet parsing ──────────────────────────────────────────────

/// Parse just enough of an inner IP packet to demux and key flows:
/// addresses, protocol, L4 start. Returns `None` for malformed packets
/// and — deliberately — for fragments: the inner-MTU contract means a
/// legal inner datagram always arrives whole.
fn parse_inner(pkt: &[u8], v6: bool) -> Option<InnerView<'_>> {
    if v6 {
        if pkt.len() < 40 || pkt[0] >> 4 != 6 {
            return None;
        }
        let src = IpAddr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
        let dst = IpAddr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
        // Walk extension headers: hop-by-hop (0), routing (43), dest
        // options (60) use the (len+1)*8 form; fragment (44) drops.
        let mut nh = pkt[6];
        let mut off = 40usize;
        for _ in 0..8 {
            match nh {
                0 | 43 | 60 => {
                    let ext = pkt.get(off..off + 2)?;
                    nh = ext[0];
                    let len = (usize::from(ext[1]) + 1) * 8;
                    off = off.checked_add(len)?;
                }
                44 => return None, // fragment header
                _ => break,
            }
        }
        Some(InnerView {
            src,
            dst,
            proto: nh,
            l4: pkt.get(off..)?,
        })
    } else {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return None;
        }
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        if ihl < 20 || pkt.len() < ihl {
            return None;
        }
        // MF flag or nonzero fragment offset → drop (spec §6).
        if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff != 0 {
            return None;
        }
        let src = IpAddr::from(<[u8; 4]>::try_from(&pkt[12..16]).ok()?);
        let dst = IpAddr::from(<[u8; 4]>::try_from(&pkt[16..20]).ok()?);
        Some(InnerView {
            src,
            dst,
            proto: pkt[9],
            l4: pkt.get(ihl..)?,
        })
    }
}

/// The TCP fields the demux needs — ports and the SYN/ACK bits at the
/// fixed flag offset.
fn parse_tcp(l4: &[u8]) -> Option<TcpView> {
    if l4.len() < 20 {
        return None;
    }
    let flags = l4[13];
    Some(TcpView {
        sport: u16::from_be_bytes([l4[0], l4[1]]),
        dport: u16::from_be_bytes([l4[2], l4[3]]),
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
    })
}

/// UDP source/dest ports (the payload starts at offset 8).
fn parse_udp_ports(l4: &[u8]) -> Option<(u16, u16)> {
    if l4.len() < 8 {
        return None;
    }
    Some((
        u16::from_be_bytes([l4[0], l4[1]]),
        u16::from_be_bytes([l4[2], l4[3]]),
    ))
}

#[cfg(test)]
mod tests {
    //! §11.1 actor rows — the listen pool, UDP flow liveness and queue
    //! bounds that have no demux-level equivalent.
    use super::*;
    use crate::wireguard::{WgListenerSpec, WgPeerSpec};
    use meow_dns::Resolver;
    use meow_trie::DomainTrie;
    use meow_tunnel::Tunnel;
    use smol_str::SmolStr;
    use std::net::Ipv4Addr;

    fn test_actor() -> WgActor {
        let resolver = Arc::new(Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let spec = WgListenerSpec {
            private_key: [0x5E; 32],
            peers: vec![WgPeerSpec {
                public_key: [0xA0; 32],
                preshared_key: None,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                name: SmolStr::new(""),
                reserved: None,
            }],
            mtu: 1420,
            udp: true,
            udp_timeout: Duration::from_secs(60),
        };
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let (_tx, rx) = mpsc::channel(1);
        WgActor::new(
            WireGuardListener::new(tunnel, spec, "wg-test".into()),
            sock,
            rx,
            tokio::runtime::Handle::current(),
        )
        .expect("actor builds")
    }

    /// A checksummed inner IPv4 SYN `src:sport` → `dst:dport` — smoltcp
    /// only transitions the listen socket for a packet whose checksums
    /// verify, so the test builds them for real.
    fn syn_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ip_sum = !inner_udp::checksum_fold(&p[..20]);
        p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..28].copy_from_slice(&100u32.to_be_bytes()); // seq
        p[32] = 0x50; // data offset 5
        p[33] = 0x02; // SYN
        p[34..36].copy_from_slice(&0xffffu16.to_be_bytes()); // window
        let mut pseudo = Vec::with_capacity(32);
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&20u16.to_be_bytes());
        pseudo.extend_from_slice(&p[20..]);
        let tcp_sum = !inner_udp::checksum_fold(&pseudo);
        p[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
        p
    }

    /// `tcp_listen_pool_lazy_alloc`: listeners are created per new
    /// dport, reused for the same dport, and the pool's cap evicts the
    /// oldest still-`Listen` occupant.
    #[tokio::test]
    async fn tcp_listen_pool_lazy_alloc() {
        let mut actor = test_actor();
        assert!(actor.ensure_listener(0, 80));
        assert!(actor.ensure_listener(0, 443));
        assert_eq!(actor.listen_pool.len(), 2);
        // Same (peer, dport) → the existing listener serves.
        assert!(actor.ensure_listener(0, 80));
        assert_eq!(actor.listen_pool.len(), 2);

        // Fill the pool to its cap, then one more dport must evict the
        // oldest entry (port 80 was created first).
        for port in 1000..1000 + (LISTEN_POOL_CAP - 2) as u16 {
            assert!(actor.ensure_listener(0, port), "dport {port} listens");
        }
        assert_eq!(actor.listen_pool.len(), LISTEN_POOL_CAP);
        assert!(actor.ensure_listener(0, 65000));
        assert_eq!(actor.listen_pool.len(), LISTEN_POOL_CAP);
        assert!(actor.listen_pool.contains_key(&65000));
        assert!(
            !actor.listen_pool.contains_key(&80),
            "oldest Listen entry evicted first"
        );
    }

    /// Errata E5: the LRU eviction only ever removes sockets still in
    /// `State::Listen` — a pool whose every entry already transitioned
    /// (SYN accepted → `SynReceived`) has nothing evictable, so the
    /// next dport's `ensure_listener` refuses instead of stealing a
    /// live flow socket.
    #[tokio::test]
    async fn listen_pool_evicts_only_listen_state() {
        let mut actor = test_actor();
        let ports: Vec<u16> = (2000..2000 + LISTEN_POOL_CAP as u16).collect();
        for &port in &ports {
            assert!(actor.ensure_listener(0, port));
        }
        // SYN into every listener → sockets leave `Listen` for
        // `SynReceived`; they are flows now, not pool placeholders.
        for (i, &port) in ports.iter().enumerate() {
            let pkt = syn_v4(
                "10.0.0.2".parse().unwrap(),
                "203.0.113.9".parse().unwrap(),
                40000 + i as u16,
                port,
            );
            actor.device.rx_queue.push_back(pkt);
        }
        let now = SmolInstant::now();
        actor.iface.poll(now, &mut actor.device, &mut actor.sockets);
        for entry in actor.listen_pool.values() {
            assert_ne!(
                actor.sockets.get::<tcp::Socket>(entry.handle).state(),
                tcp::State::Listen
            );
        }
        assert!(
            !actor.evict_oldest_listener(),
            "a fully-transitioned pool has no Listen socket to evict"
        );
        assert!(
            !actor.ensure_listener(0, 65000),
            "no evictable socket → the new dport's SYN is refused"
        );
    }

    /// `inner_udp_flow_idle_evict`: the actor-side sweep drops flows
    /// whose `last_active` passed `udp_timeout` (the task itself also
    /// self-evicts — this is the pruning aid for a task that wedged).
    #[tokio::test]
    async fn inner_udp_flow_idle_evict() {
        let mut actor = test_actor();
        let fresh = UdpFlowKey {
            slot: 0,
            src: "10.0.0.2:1111".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        let stale = UdpFlowKey {
            slot: 0,
            src: "10.0.0.2:2222".parse().unwrap(),
            dst: "1.1.1.1:53".parse().unwrap(),
        };
        let (tx_fresh, _rx_f) = mpsc::channel(1);
        let (tx_stale, _rx_s) = mpsc::channel(1);
        actor.udp_flows.insert(
            fresh,
            UdpFlow {
                tx: tx_fresh,
                last_active: Instant::now(),
            },
        );
        actor.udp_flows.insert(
            stale,
            UdpFlow {
                tx: tx_stale,
                last_active: Instant::now() - actor.udp_timeout - Duration::from_secs(1),
            },
        );
        actor.sweep_udp_flows();
        assert!(actor.udp_flows.contains_key(&fresh));
        assert!(
            !actor.udp_flows.contains_key(&stale),
            "idle flow swept past udp_timeout"
        );
    }

    /// `inner_udp_queue_full_drop`: the per-flow payload queue is
    /// bounded — a datagram arriving with a full queue drops silently
    /// (UDP semantics), never grows the queue, never panics.
    #[tokio::test]
    async fn inner_udp_queue_full_drop() {
        let mut actor = test_actor();
        let key = UdpFlowKey {
            slot: 0,
            src: "10.0.0.2:1111".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        let (tx, _rx) = mpsc::channel(inner_udp::UDP_FLOW_QUEUE);
        actor.udp_flows.insert(
            key,
            UdpFlow {
                tx,
                last_active: Instant::now(),
            },
        );
        // UDP header src=1111 dst=53 len=8+payload, cksum 0.
        let l4 = {
            let mut b = Vec::with_capacity(8);
            b.extend_from_slice(&1111u16.to_be_bytes());
            b.extend_from_slice(&53u16.to_be_bytes());
            b.extend_from_slice(&8u16.to_be_bytes());
            b.extend_from_slice(&0u16.to_be_bytes());
            b
        };
        let view = InnerView {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            proto: 17,
            l4: &l4,
        };
        // Overflow the queue well past its bound; the excess drops.
        for _ in 0..inner_udp::UDP_FLOW_QUEUE + 20 {
            actor.inner_udp(0, &view);
        }
        let flow = actor.udp_flows.get(&key).expect("flow survives");
        assert_eq!(
            flow.tx.capacity(),
            0,
            "queue stays bounded — overflow datagrams dropped"
        );
        assert_eq!(actor.udp_flows.len(), 1);
    }
}
