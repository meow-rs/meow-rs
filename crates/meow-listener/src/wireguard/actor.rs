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
//!    occupants) and register fresh flow sockets, resolving each
//!    socket's owning peer from the `pending_syn` tuple its SYN
//!    recorded at feed time; then reap ownerless `Closed` sockets.
//! 5. `drain_device_tx` — every emitted packet's 4-tuple maps back to
//!    the flow it belongs to, hence to the peer that owns the session
//!    it encrypts under (a stray RST the demux never matched takes the
//!    `rst_hint` its trigger recorded).
//! 6. timer pass — [`RateLimiter::reset_count`] every tick (errata E1:
//!    the limiter's own debounce decides), per-peer `update_timers`,
//!    UDP-flow liveness sweep.
//! 7. `flush_outbox` — nonblocking sends; a full socket backs off to
//!    the next pass rather than stalling the loop.

use std::collections::{HashMap, HashSet, VecDeque};
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

/// Wire outbox bound — on sustained `WouldBlock` (endpoint send buffer
/// full) the queue drops the *oldest* pending datagram rather than
/// growing without limit: the same lossy-tail semantics UDP tolerates,
/// bounded per §10.2's "no unbounded queue" posture.
const OUTBOX_CAP: usize = 1024;

/// Original-direction inner TCP tuple — `(client_ip, client_port,
/// target_ip, target_port)` as the peer wrote it. Reply packets reverse
/// it back to this key, so one map serves both directions.
type InnerTuple = (IpAddr, u16, IpAddr, u16);

/// One pool occupant: a smoltcp socket parked in `State::Listen` on a
/// `(peer_slot, dport)` key — the requesting peer is part of the key so
/// same-batch same-dport SYNs from different peers each get a
/// placeholder (flow ownership itself comes from `pending_syn`, not
/// from the socket that happened to accept).
struct ListenEntry {
    handle: smoltcp::iface::SocketHandle,
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

impl Drop for TcpFlow {
    /// A `WgStream` parked on a full write channel waits on
    /// `drain_notify` — dropping the flow without waking it would pin
    /// the route task forever (the channel-close wake in
    /// `WgStream::poll_write_wait` is the second safety net). Fire all
    /// waiters so the writer's next `try_send` sees `Closed` and exits.
    fn drop(&mut self) {
        self.drain_notify.notify_waiters();
    }
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
    /// ≥ one entry per demanded `(peer_slot, dport)`. A listener
    /// carries no per-peer state — `accepts()` matches port only — so
    /// the flow's real owner is recovered from `pending_syn`, never
    /// from which placeholder took the SYN.
    listen_pool: HashMap<(usize, u16), ListenEntry>,
    /// Mirror of `listen_pool`'s socket handles, kept in lockstep at
    /// every pool insert/remove — the orphan reaper's ownership check
    /// is O(1) instead of a values() scan.
    listen_pool_handles: HashSet<smoltcp::iface::SocketHandle>,
    /// First-fed-wins `tuple → peer slot` for every unclaimed SYN
    /// pushed to smoltcp this pass: `post_poll` looks the accepted
    /// socket's tuple up here to learn the real owning peer (same-dport
    /// SYNs from two peers in one batch can't be told apart by which
    /// listener accepted them). Cleared at the end of `post_poll` —
    /// smoltcp accepts queued SYNs in receive order, so the earliest
    /// recorded SYN is the one a listener took.
    pending_syn: HashMap<InnerTuple, usize>,
    /// Reversed-tuple → peer slot for emitted RSTs the demux didn't
    /// match (refused SYNs, strays). Populated at feed time, drained
    /// with `tx_queue`, cleared each pass — the emission is same-poll.
    rst_hint: HashMap<InnerTuple, usize>,
    /// `Closed` sockets awaiting removal — deferred one pass so a
    /// queued RST (a cap-gate abort's refusal, or a conn-dead
    /// `TcpIo::Close` abort) dispatches before the socket leaves the
    /// set (removing it at abort time would silently eat the reset).
    pending_close: Vec<smoltcp::iface::SocketHandle>,
    /// Flows torn down but whose socket is still deferred in
    /// `pending_close` — `handle → (slot, tuple)` so the abort's RST
    /// emitted on the deferred pass still routes to the owning peer
    /// (`route_tx_packet` consults this once `self.tcp` no longer
    /// holds the flow) and the tuple entry dies with the socket.
    tcp_dying: HashMap<smoltcp::iface::SocketHandle, (usize, InnerTuple)>,
    /// Handles whose `tcp_dying`/`tcp_by_tuple` entries die on the
    /// *next* reap pass — a conn aborted in this pass has its RST
    /// emitted by this pass's `iface.poll`, but `drain_device_tx` only
    /// routes it after `reap_orphaned_sockets` has run; erasing the
    /// tables at removal time would strand that RST unroutable. One
    /// deferred pass covers the drain window.
    dead_dying: Vec<smoltcp::iface::SocketHandle>,
    /// Tuples whose SYN demanded (and got) a listener since the last
    /// `post_poll` — the in-flight half of the connection cap so a
    /// same-batch burst can't overshoot; deduped by tuple so a
    /// retransmitted SYN can't double-count.
    in_flight_syns: HashSet<InnerTuple>,

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
            listen_pool_handles: HashSet::new(),
            pending_syn: HashMap::new(),
            rst_hint: HashMap::new(),
            pending_close: Vec::new(),
            tcp_dying: HashMap::new(),
            dead_dying: Vec::new(),
            in_flight_syns: HashSet::new(),
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
                        Err(e) => {
                            // A persistent socket error would busy-spin
                            // the loop — back off before retrying (the
                            // pump's recv-error arm does the same).
                            debug!("wireguard {}: endpoint recv error: {e}", self.name);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
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
        self.drain_inject();
        self.service_tcp();
        self.sweep_udp_flows();
        let now = SmolInstant::now();
        // `post_poll`'s bookkeeping only has work when the poll could
        // have changed anything it tracks — fresh inner packets fed to
        // smoltcp, packets emitted (an accept's SYN-ACK), or same-pass
        // bookkeeping outstanding. A quiet pass skips its O(sockets)
        // sweeps entirely: no accept, no abort, no orphan can appear
        // out of nothing (timer-driven deaths of owned flows are
        // already caught by `service_tcp`'s own iteration).
        let had_rx = !self.device.rx_queue.is_empty();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        if had_rx
            || !self.device.tx_queue.is_empty()
            || !self.pending_syn.is_empty()
            || !self.in_flight_syns.is_empty()
            || !self.pending_close.is_empty()
        {
            self.post_poll();
        }
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
            Action::ToWire { addr, bytes, .. } => self.enqueue_outbox(addr, bytes),
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
        if let Some(&handle) = self.tcp_by_tuple.get(&key) {
            // The tuple's owning flow pins the peer: a segment for it
            // arriving over a *different* peer's session is an
            // injection — overlapping allowed_ips legitimately lets
            // two peers claim the same inner addresses, so the demux
            // alone can't tell them apart. Drop before smoltcp's own
            // tuple demux feeds it into the victim's socket.
            if self.tcp.get(&handle).is_none_or(|f| f.slot != slot) {
                trace!(
                    "wireguard {}: cross-peer TCP segment on owned tuple {key:?} dropped",
                    self.name
                );
                return;
            }
        }
        let claimed = self.tcp_by_tuple.contains_key(&key);
        if tcpv.syn && !tcpv.ack && !claimed {
            // Record the owner unconditionally — BEFORE the capacity
            // decision, not inside it: the SYN is fed to smoltcp
            // regardless (the cap only gates *new listener demand*),
            // so a placeholder that already exists may still accept it
            // and `post_poll` needs this entry both to attribute the
            // flow and to refuse it at the second cap gate. A SYN
            // accepted by *any* placeholder (including a stale one
            // another peer created) must resolve to the peer that
            // actually sent it. First-fed wins: smoltcp accepts queued
            // SYNs in receive order, so the earliest recorded SYN is
            // the one a listener took.
            self.pending_syn.entry(key).or_insert(slot);
            if !self.at_capacity() && self.ensure_listener(slot, tcpv.dport) {
                self.in_flight_syns.insert(key);
            }
        }
        if !claimed {
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
        // current-thread rt only ever polls the wire loop. `spawn`
        // panics if `main_rt` is already mid-shutdown (tokio Handle
        // semantics): that window only exists during listener teardown
        // racing an in-flight SYN, and the fallout is a loud "actor
        // panicked" line at `wait()`, not corrupt state — a deliberate
        // trade-off over silently dropping a routed flow.
        self.main_rt.spawn(async move {
            if let Err(e) = inner_udp::run_flow(args, rx).await {
                debug!("wireguard UDP flow {client} -> {target}: {e}");
            }
        });
        let _ = tx.try_send(Bytes::copy_from_slice(payload));
        self.udp_flows.insert(key, UdpFlow { tx });
    }

    /// Nonblocking batch drain of flow-task replies — mirrors
    /// `drain_wire`: under a sustained wire flood the `select!` arm
    /// only ever consumed one inject item per iteration, so a backed-up
    /// queue starved behind wire datagrams. Bounded by the inject
    /// channel's own capacity.
    fn drain_inject(&mut self) {
        while let Ok((slot, pkt)) = self.inject_rx.try_recv() {
            self.handle_inject(slot, &pkt);
        }
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
                        self.enqueue_outbox(addr, buf);
                    }
                }
            }
        } else {
            // Unreachable while `work` is MTU-sized — `build_reply`
            // caps the inner packet at inner_mtu = mtu - 64, and
            // `work` is mtu + 256, so headroom always covers the WG
            // overhead. The debug_assert pins that contract; the
            // drop+log stays as the spec §6 release-mode guard rather
            // than a silent oversize swallow.
            debug_assert!(
                pkt.len() + DATA_OVERHEAD_SZ <= work.len(),
                "inject packet {}B + {DATA_OVERHEAD_SZ}B overhead exceeds \
                 MTU-sized work buffer {}B",
                pkt.len(),
                work.len()
            );
            debug!(
                "wireguard {}: dropping {}B inject packet (work {}B)",
                self.name,
                pkt.len(),
                work.len()
            );
        }
        self.work = work;
    }

    // ── listen pool + flow registration ──────────────────────────────

    /// Combined TCP+UDP cap (`max-connections`; `0` = unlimited).
    fn at_capacity(&self) -> bool {
        self.max_connections > 0
            && self.tcp.len() + self.in_flight_syns.len() + self.udp_flows.len()
                >= self.max_connections
    }

    /// Ensure a `State::Listen` socket exists for `(slot, dport)`.
    /// Returns false when the SYN should be dropped: the pool is full
    /// *and* no `Listen`-state socket is evictable (errata E5), or
    /// smoltcp refused the listen. The placeholder itself is peer-blind
    /// — `pending_syn` carries ownership — so a live entry serves the
    /// same peer again while a different peer's same-dport SYN simply
    /// gets its own key.
    fn ensure_listener(&mut self, slot: usize, dport: u16) -> bool {
        if let Some(entry) = self.listen_pool.get(&(slot, dport)) {
            if self.sockets.get::<tcp::Socket>(entry.handle).state() == tcp::State::Listen {
                return true;
            }
            // Stale bookkeeping: the socket already left `Listen` — it
            // is a flow (or a reaped orphan) owned elsewhere now, so
            // only the pool entry is ours to drop. The socket itself is
            // *not* removed here: mid-flight it may be registered this
            // very pass, and terminating it would kill a live conn.
            if let Some(entry) = self.listen_pool.remove(&(slot, dport)) {
                self.listen_pool_handles.remove(&entry.handle);
            }
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
        self.listen_pool_handles.insert(handle);
        self.listen_pool.insert(
            (slot, dport),
            ListenEntry {
                handle,
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
            .map(|(k, _)| *k);
        let Some(key) = oldest else {
            return false;
        };
        let entry = self.listen_pool.remove(&key).expect("entry checked above");
        self.listen_pool_handles.remove(&entry.handle);
        self.sockets.remove(entry.handle);
        true
    }

    /// After `iface.poll`: listeners that accepted a SYN left the pool
    /// (their socket is now a flow in `SynReceived`+); register fresh
    /// flow sockets with the owning peer recovered from `pending_syn`,
    /// then bury any socket that died with no owner.
    fn post_poll(&mut self) {
        self.in_flight_syns.clear();
        let mut stale = Vec::new();
        for (key, entry) in &self.listen_pool {
            if self.sockets.get::<tcp::Socket>(entry.handle).state() != tcp::State::Listen {
                stale.push(*key);
            }
        }
        for key in stale {
            if let Some(entry) = self.listen_pool.remove(&key) {
                self.listen_pool_handles.remove(&entry.handle);
            }
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
            // The flow's real peer is the one whose SYN the socket
            // accepted — recorded at feed time, since a placeholder
            // listener carries no per-peer state and can accept another
            // peer's same-dport SYN.
            let key: InnerTuple = (
                remote.addr.into(),
                remote.port,
                local.addr.into(),
                local.port,
            );
            let Some(slot) = self.pending_syn.get(&key).copied() else {
                // A flow with no recorded owner can't be routed back —
                // refuse it rather than guess.
                self.sockets.get_mut::<tcp::Socket>(handle).abort();
                continue;
            };
            // Second capacity gate: `inner_tcp`'s `in_flight_syns`
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
        self.pending_syn.clear();
        self.reap_orphaned_sockets();
    }

    /// Bury sockets that died with no owner — a `!is_open()` socket is
    /// terminal (`Closed`, or `TimeWait` with nothing left to send
    /// that could still route), and one that is neither a registered
    /// flow nor a pool member has nothing left to do once its final
    /// packets dispatch. Each candidate defers one pass so a queued
    /// RST (the cap-gate abort's refusal) emits on the intervening
    /// poll; without this step every refused accept and every same-poll
    /// teardown orphaned ~512KiB of socket buffers forever.
    fn reap_orphaned_sockets(&mut self) {
        // Handles deferred last pass — re-validated because smoltcp
        // recycles freed slots: a reused handle pointing at a live
        // socket fails `is_orphan_dead` and is left alone.
        // Entries deferred last pass: their RST drained on the
        // intervening `drain_device_tx`, so the tables can go now.
        for handle in std::mem::take(&mut self.dead_dying) {
            if let Some((_, key)) = self.tcp_dying.remove(&handle) {
                self.tcp_by_tuple.remove(&key);
            }
        }
        let pending = std::mem::take(&mut self.pending_close);
        for handle in pending {
            if self.is_orphan_dead(handle) {
                self.sockets.remove(handle);
                // The socket dies now but its RST is queued in
                // `device.tx_queue` and routes via `tcp_dying` in the
                // `drain_device_tx` that runs right after this pass's
                // `post_poll` — defer the table erase one pass.
                if self.tcp_dying.contains_key(&handle) {
                    self.dead_dying.push(handle);
                }
            }
        }
        for (handle, socket) in self.sockets.iter() {
            let smoltcp::socket::Socket::Tcp(t) = socket else {
                continue;
            };
            if t.is_open() {
                continue;
            }
            if self.tcp.contains_key(&handle) || self.listen_pool_handles.contains(&handle) {
                continue;
            }
            self.pending_close.push(handle);
        }
    }

    /// The handle still refers to a dead socket nobody owns — checked
    /// at removal time, not when it was deferred (see the note on
    /// handle recycling in [`Self::reap_orphaned_sockets`]).
    fn is_orphan_dead(&self, handle: smoltcp::iface::SocketHandle) -> bool {
        if self.tcp.contains_key(&handle) || self.listen_pool_handles.contains(&handle) {
            return false;
        }
        self.sockets.iter().any(|(h, s)| {
            h == handle && matches!(s, smoltcp::socket::Socket::Tcp(t) if !t.is_open())
        })
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
        let mut to_spawn: Vec<(WgStream, IpEndpoint, IpEndpoint)> = Vec::new();
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
                to_spawn.push((stream, local, remote));
            }

            // conn→actor drain, gated on `out` headroom: once the
            // backlog reaches TCP_WRITE_QUEUE the channel itself must
            // be the stall point — draining it regardless moved the
            // bound into an unbounded VecDeque, letting a stalled
            // socket (`can_send()` = false on a full tx window) grow
            // `out` forever while the writer never saw `Full`.
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
        for (stream, local, remote) in to_spawn {
            self.spawn_route_task(stream, local, remote);
        }
    }

    /// Spawn the routing task on the main runtime: the TUN path's
    /// sniff-window → gather → `sniff_bytes` → `route_inbound_tcp`
    /// shape, with `ConnType::WireGuard` metadata and the listener's
    /// bound port as `in_port`.
    fn spawn_route_task(&self, mut stream: WgStream, local: IpEndpoint, remote: IpEndpoint) {
        let client = SocketAddr::new(remote.addr.into(), remote.port);
        let target = SocketAddr::new(local.addr.into(), local.port);
        let inner = Arc::clone(&self.inner);
        let sniffer = self.sniffer.clone();
        let in_name: Arc<str> = self.name.clone().into();
        let in_port = self.bound_port;
        // Same `spawn`-on-shutdown note as `inner_udp`: a mid-teardown
        // `main_rt` panics the actor thread — teardown noise, not a
        // correctness hole.
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
            meow_tunnel::tcp::route_inbound_tcp(&inner, &mut stream, metadata, &prefix).await;
        });
    }

    /// Remove a dead socket's flow bookkeeping — and defer the socket
    /// itself one pass. A conn-dead `TcpIo::Close` abort queues an RST
    /// that only dispatches on the *next* `iface.poll`; dropping the
    /// socket immediately ate it (the cap-gate abort already defers
    /// through `pending_close` — this aligns the conn-dead path). The
    /// tuple entry survives in `tcp_dying` so the emitted RST still
    /// routes to the owning peer, then both die with the socket.
    fn remove_tcp_flow(&mut self, handle: smoltcp::iface::SocketHandle) {
        if let Some(st) = self.tcp.remove(&handle) {
            self.tcp_dying.insert(handle, (st.slot, st.key));
            drop(st); // Drop fires drain_notify for parked writers.
            self.pending_close.push(handle);
        } else if self.sockets.iter().any(|(h, _)| h == handle) {
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
                self.enqueue_outbox(addr, buf);
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
            .and_then(|h| {
                self.tcp
                    .get(h)
                    .map(|f| f.slot)
                    .or_else(|| self.tcp_dying.get(h).map(|(slot, _)| *slot))
            })
            .or_else(|| self.rst_hint.get(&key).copied())
    }

    /// Queue a wire datagram, bounded: past [`OUTBOX_CAP`] the oldest
    /// pending datagram is dropped (newest-wins lossy tail — a stale
    /// queued packet is worth less than the one that just arrived).
    fn enqueue_outbox(&mut self, addr: SocketAddr, pkt: Vec<u8>) {
        if self.outbox.len() >= OUTBOX_CAP {
            self.outbox.pop_front();
            trace!(
                "wireguard {}: outbox full — dropped oldest datagram",
                self.name
            );
        }
        self.outbox.push_back((addr, pkt));
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

    /// Prune dead UDP flows: a task that evicted itself drops its `rx`,
    /// making `tx` report closed. Idle timing is owned entirely by the
    /// flow task — it resets on client→remote writes *and* relayed
    /// replies, so a one-direction-idle flow is still legitimately
    /// alive and must not be actor-swept (the TProxy precedent —
    /// `tproxy/udp.rs` prunes dead tasks only).
    fn sweep_udp_flows(&mut self) {
        self.udp_flows.retain(|_, flow| !flow.tx.is_closed());
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
        // `total_length` bounds the datagram — bytes the buffer carries
        // past it are padding, not payload, and must not reach the L4
        // checksum/demux (the WG decapsulator already clips, but this
        // parser must not rely on that upstream contract).
        let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
        let end = total_len.min(pkt.len());
        if ihl >= end {
            return None;
        }
        let src = IpAddr::from(<[u8; 4]>::try_from(&pkt[12..16]).ok()?);
        let dst = IpAddr::from(<[u8; 4]>::try_from(&pkt[16..20]).ok()?);
        Some(InnerView {
            src,
            dst,
            proto: pkt[9],
            l4: pkt.get(ihl..end)?,
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
        test_actor_peers(1)
    }

    /// An actor whose table has `n` peers — `inner_tcp` takes the slot
    /// directly, so the peers need only occupy table positions.
    fn test_actor_peers(n: usize) -> WgActor {
        let spec = WgListenerSpec {
            private_key: [0x5E; 32],
            peers: (0..n)
                .map(|i| WgPeerSpec {
                    public_key: [0xA0 + i as u8; 32],
                    preshared_key: None,
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    name: SmolStr::new(""),
                    reserved: None,
                })
                .collect(),
            mtu: 1420,
            udp: true,
            udp_timeout: Duration::from_secs(60),
        };
        actor_with_spec(spec)
    }

    /// An actor built on a caller-supplied spec — needed when a test
    /// must run real `Tunn` clients (the peer `public_key` has to be a
    /// derived key, not a byte pattern) or toggle `udp`.
    fn actor_with_spec(spec: WgListenerSpec) -> WgActor {
        let resolver = Arc::new(Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            DomainTrie::new(),
            false,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
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

    /// A checksummed inner IPv4 TCP segment `src:sport` → `dst:dport`
    /// with arbitrary flags — smoltcp only accepts a packet whose
    /// checksums verify, so the test builds them for real.
    fn seg_v4(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
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
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[28..32].copy_from_slice(&ack.to_be_bytes());
        p[32] = 0x50; // data offset 5
        p[33] = flags;
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

    /// A checksummed inner IPv4 SYN `src:sport` → `dst:dport`.
    fn syn_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        seg_v4(src, dst, sport, dport, 100, 0, 0x02)
    }

    /// Feed `pkt` through `inner_tcp` as peer `slot` — the feed half of
    /// a service pass, without wire framing.
    fn feed_tcp(actor: &mut WgActor, slot: usize, pkt: &[u8]) {
        let view = parse_inner(pkt, false).expect("test packet parses");
        actor.inner_tcp(slot, pkt, &view);
    }

    /// The poll half of a service pass: smoltcp consumes the rx queue,
    /// then post_poll does registration/cleanup.
    fn poll_once(actor: &mut WgActor) {
        actor
            .iface
            .poll(SmolInstant::now(), &mut actor.device, &mut actor.sockets);
        actor.post_poll();
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
        assert!(actor.listen_pool.contains_key(&(0, 65000)));
        assert!(
            !actor.listen_pool.contains_key(&(0, 80)),
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

    /// M2 — `inner_udp_flow_dead_task_evict`: idle timing belongs to
    /// the flow task (it resets on client→remote writes *and* relayed
    /// replies), so the actor sweep must only reap flows whose channel
    /// died with the task — never a one-direction-idle but live flow.
    #[tokio::test]
    async fn inner_udp_flow_dead_task_evict() {
        let mut actor = test_actor();
        let live = UdpFlowKey {
            slot: 0,
            src: "10.0.0.2:1111".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        let dead = UdpFlowKey {
            slot: 0,
            src: "10.0.0.2:2222".parse().unwrap(),
            dst: "1.1.1.1:53".parse().unwrap(),
        };
        let (tx_live, _rx_live) = mpsc::channel(1);
        let (tx_dead, rx_dead) = mpsc::channel::<Bytes>(1);
        drop(rx_dead); // the task exited — its send half reports closed
        actor.udp_flows.insert(live, UdpFlow { tx: tx_live });
        actor.udp_flows.insert(dead, UdpFlow { tx: tx_dead });
        actor.sweep_udp_flows();
        assert!(
            actor.udp_flows.contains_key(&live),
            "live one-direction-idle flow must not be actor-swept"
        );
        assert!(
            !actor.udp_flows.contains_key(&dead),
            "dead task's flow is reaped"
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
        actor.udp_flows.insert(key, UdpFlow { tx });
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

    // ── u3-review regressions ────────────────────────────────────────

    /// S2 — two peers racing SYNs to the same inner dport inside one
    /// poll: each accepted flow must be owned by the peer that fed its
    /// SYN, never by whichever placeholder socket accepted it.
    #[tokio::test]
    async fn tcp_same_dport_cross_peer_attribution() {
        let mut actor = test_actor_peers(2);
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();
        let a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let syn_a = syn_v4(a, target, 40000, 443);
        let syn_b = syn_v4(b, target, 40001, 443);
        feed_tcp(&mut actor, 0, &syn_a);
        feed_tcp(&mut actor, 1, &syn_b);
        poll_once(&mut actor);

        let h_a = actor.tcp_by_tuple[&(a.into(), 40000, target.into(), 443)];
        assert_eq!(actor.tcp[&h_a].slot, 0, "A's flow must be owned by peer A");
        let h_b = actor.tcp_by_tuple[&(b.into(), 40001, target.into(), 443)];
        assert_eq!(actor.tcp[&h_b].slot, 1, "B's flow must be owned by peer B");
    }

    /// S3 — an accepted tuple belongs to the peer that opened it: a
    /// segment for that exact 4-tuple arriving over a *different*
    /// peer's session is an injection and must never reach smoltcp
    /// (overlapping `allowed_ips` legitimately shares inner addresses).
    #[tokio::test]
    async fn tcp_cross_peer_tuple_injection_dropped() {
        let mut actor = test_actor_peers(2);
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();
        let a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        // Peer A opens a flow.
        let syn = syn_v4(a, target, 40000, 443);
        feed_tcp(&mut actor, 0, &syn);
        poll_once(&mut actor);
        assert_eq!(actor.tcp.len(), 1);

        // Peer B replays A's exact tuple — silently refused.
        let queued = actor.device.rx_queue.len();
        let forged = seg_v4(a, target, 40000, 443, 101, 1, 0x10); // ACK
        feed_tcp(&mut actor, 1, &forged);
        assert_eq!(
            actor.device.rx_queue.len(),
            queued,
            "cross-peer segment on an owned tuple must not be fed"
        );
    }

    /// S1 — a socket closed with no flow/pool ownership must be reaped:
    /// each cap-gate abort used to orphan ~512KiB of socket buffers
    /// forever. The refusal RST still gets its dispatch first.
    #[tokio::test]
    async fn closed_orphan_sockets_reaped() {
        let mut actor = test_actor();
        actor.max_connections = 1;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();

        for round in 0..4u16 {
            // A placeholder that never accepts: the fed SYN's checksum
            // is deliberately broken, so smoltcp drops it and the
            // socket stays `Listen` while the cap fills elsewhere.
            let mut bad = syn_v4(client, target, 41000 + round, 443);
            bad[37] ^= 0xff;
            feed_tcp(&mut actor, 0, &bad);
            poll_once(&mut actor);

            // A legit conn on another dport fills the cap.
            let good = syn_v4(client, target, 42000 + round, 80);
            feed_tcp(&mut actor, 0, &good);
            poll_once(&mut actor);
            assert_eq!(actor.tcp.len(), 1);

            // A valid SYN to the held dport accepts on the stale
            // listener and is aborted at the cap — an orphaned
            // `Closed` socket the reaper must bury.
            let refused = syn_v4(client, target, 43000 + round, 443);
            feed_tcp(&mut actor, 0, &refused);
            poll_once(&mut actor);
            actor.drain_device_tx();

            // Conn churn: the next round starts under the cap again.
            let h = *actor.tcp.keys().next().expect("one flow live");
            actor.remove_tcp_flow(h);
            // One more pass so a deferred removal can land.
            poll_once(&mut actor);
        }

        let closed = actor
            .sockets
            .iter()
            .filter(|(_, s)| {
                matches!(s, smoltcp::socket::Socket::Tcp(t) if t.state() == tcp::State::Closed)
            })
            .count();
        assert!(
            closed <= 1,
            "orphaned Closed sockets must be reaped — {closed} still in the set"
        );
        assert!(
            actor.sockets.iter().count() <= 3,
            "socket set stays bounded — {}",
            actor.sockets.iter().count()
        );
    }

    /// F3 — the IPv4 `total_length` field bounds the L4 slice: bytes a
    /// buffer carries past it are link padding, not payload, and must
    /// not reach the demux/checksum path.
    #[test]
    fn parse_inner_v4_total_length_clips_l4() {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes()); // 20B hdr + 8B UDP
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // The 20-byte padding tail must not leak into `l4`.
        let view = parse_inner(&pkt, false).expect("parses");
        assert_eq!(view.proto, 17);
        assert_eq!(view.l4.len(), 8);

        // A total_length shorter than the header itself is malformed.
        pkt[2..4].copy_from_slice(&16u16.to_be_bytes());
        assert!(parse_inner(&pkt, false).is_none());
    }

    /// M4 — a retransmitted SYN counts once toward the cap: the
    /// in-flight half of `max_connections` dedups by tuple.
    #[tokio::test]
    async fn in_flight_syn_retransmit_dedup() {
        let mut actor = test_actor();
        actor.max_connections = 2;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();

        // The same SYN fed twice (a retransmit) must not double-count.
        let syn = syn_v4(client, target, 40000, 443);
        feed_tcp(&mut actor, 0, &syn);
        feed_tcp(&mut actor, 0, &syn);
        assert_eq!(actor.listen_pool.len(), 1);

        // A second dport still gets its placeholder — the cap was not
        // spent on the duplicate.
        let other = syn_v4(client, target, 40001, 444);
        feed_tcp(&mut actor, 0, &other);
        assert_eq!(
            actor.listen_pool.len(),
            2,
            "a retransmitted SYN must not consume the in-flight cap"
        );
    }

    // ── prfix2 coverage pins ─────────────────────────────────────────

    /// `parse_inner`'s silent-drop matrix — fragments, truncations and
    /// version mismatches all return `None`. A first fragment reaching
    /// the demux would be misread as a UDP/TCP header into a flow.
    #[test]
    fn parse_inner_drops_malformed_and_fragments() {
        // Baseline: a plain v4 UDP datagram parses.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        assert!(parse_inner(&pkt, false).is_some());

        // v4 MF flag and nonzero fragment offset both drop.
        let mut frag = pkt.clone();
        frag[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(parse_inner(&frag, false).is_none(), "v4 MF fragment");
        frag[6..8].copy_from_slice(&0x0040u16.to_be_bytes());
        assert!(parse_inner(&frag, false).is_none(), "v4 offset fragment");

        // IHL < 20, header truncated below IHL, wrong version nibble.
        let mut ihl = pkt.clone();
        ihl[0] = 0x44;
        assert!(parse_inner(&ihl, false).is_none(), "ihl < 20");
        assert!(parse_inner(&pkt[..10], false).is_none(), "short v4 header");
        let mut ver = pkt.clone();
        ver[0] = 0x65;
        assert!(parse_inner(&ver, false).is_none(), "v6 nibble in v4 path");

        // v6 with a fragment header (nexthdr 44) drops; a short packet
        // or a v4 nibble in the v6 path drops too.
        let mut v6 = vec![0u8; 48];
        v6[0] = 0x60;
        v6[6] = 17;
        v6[8] = 0xfd;
        v6[24] = 0xfd;
        assert!(parse_inner(&v6, true).is_some());
        v6[6] = 44;
        assert!(parse_inner(&v6, true).is_none(), "v6 fragment header");
        assert!(parse_inner(&v6[..30], true).is_none(), "short v6 header");
        let mut v6v = v6.clone();
        v6v[0] = 0x45;
        assert!(parse_inner(&v6v, true).is_none(), "v4 nibble in v6 path");

        // A hop-by-hop chain deeper than the 8-header walk bound stops
        // walking — it must not surface as TCP/UDP to the demux.
        let mut deep = vec![0u8; 40 + 9 * 8];
        deep[0] = 0x60;
        deep[6] = 0; // hop-by-hop, each 8B header pointing at the next
        for i in 0..9 {
            deep[40 + i * 8] = 0;
            deep[40 + i * 8 + 1] = 0;
        }
        let deep_view = parse_inner(&deep, true);
        assert!(
            deep_view.is_none_or(|v| v.proto != 6 && v.proto != 17),
            "an over-deep ext chain must not demux as TCP/UDP"
        );
    }

    /// `udp: false` must drop inner UDP datagrams before any flow
    /// spawns — the `udp_enabled` switch semantics (spawn_listener
    /// e2e only ever runs `udp: true`).
    #[tokio::test]
    async fn udp_disabled_drops_inner_udp() {
        let mut actor = test_actor();
        actor.udp_enabled = false;
        // v4 UDP 10.0.0.2:1111 → 8.8.8.8:53.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&1111u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes());
        actor.handle_inner(0, &pkt, false);
        assert!(actor.udp_flows.is_empty(), "udp:false must not open a flow");

        // Same packet with udp:true opens the flow — polarity pin.
        actor.udp_enabled = true;
        actor.handle_inner(0, &pkt, false);
        assert_eq!(actor.udp_flows.len(), 1, "udp:true opens the flow");
    }

    /// `demux_one` scrubs inbound reserved bytes 1..4 *before* the
    /// demux sees them (a WARP-style stamped init must still process)
    /// and restores `recv_buf` to full length — a truncated buffer
    /// would silently cap every later datagram at the last size.
    #[tokio::test]
    async fn demux_one_scrubs_reserved_and_restores_buffer() {
        use meow_wireguard::x25519;
        let server_secret = x25519::StaticSecret::from([0x5E; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let client_secret = x25519::StaticSecret::from([0xA0; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let spec = WgListenerSpec {
            private_key: server_secret.to_bytes(),
            peers: vec![WgPeerSpec {
                public_key: client_public.to_bytes(),
                preshared_key: None,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                name: SmolStr::new(""),
                reserved: None,
            }],
            mtu: 1420,
            udp: true,
            udp_timeout: Duration::from_secs(60),
        };
        let mut actor = actor_with_spec(spec);
        let mut client =
            meow_wireguard::Tunn::new(client_secret, server_public, None, None, 0, None);
        let mut work = vec![0u8; 4096];
        let TunnResult::WriteToNetwork(init) = client.format_handshake_initiation(&mut work, false)
        else {
            panic!("init formats");
        };
        let mut datagram = init.to_vec();
        // WARP-style stamp over bytes 1..4 — the actor must erase it
        // before the demux's type/index check.
        datagram[1..4].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        let n = datagram.len();
        actor.recv_buf[..n].copy_from_slice(&datagram);
        let src: SocketAddr = "127.0.0.1:51001".parse().unwrap();
        actor.demux_one(src, n);
        assert!(
            matches!(actor.outbox.front(), Some((addr, _)) if *addr == src),
            "the scrubbed init must produce a handshake response: {:?}",
            actor.outbox.front()
        );
        assert_eq!(
            actor.recv_buf.len(),
            1420 + 256,
            "recv_buf keeps its full length for the next datagram"
        );
    }

    /// `OUTBOX_CAP` drop-oldest: past the cap the *oldest* queued
    /// datagram is evicted, the queue stays bounded, and nothing
    /// panics — the m4 bounded-outbox pin.
    #[tokio::test]
    async fn outbox_cap_drops_oldest() {
        let mut actor = test_actor();
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        for i in 0..OUTBOX_CAP + 5 {
            actor.enqueue_outbox(addr, vec![i as u8]);
        }
        assert_eq!(actor.outbox.len(), OUTBOX_CAP, "outbox stays bounded");
        assert_eq!(
            actor.outbox.front().expect("nonempty").1,
            vec![5u8],
            "the oldest entries were evicted"
        );
    }

    /// `rst_hint` peer attribution: an unmatched TCP segment triggers
    /// smoltcp's rst_reply, which must be encrypted under the peer
    /// whose session fed the segment — a two-peer table makes a
    /// misroute observable via the outbox destination.
    #[tokio::test]
    async fn rst_hint_routes_stray_rst_to_feeding_peer() {
        let mut actor = test_actor_peers(2);
        let ep_b: SocketAddr = "192.0.2.1:51002".parse().unwrap();
        // Peer 1 is the only one with a learned endpoint — a reply
        // routed to it proves the hint, not the tuple, picked slot 1.
        actor.table.peers_mut()[1].endpoint = Some(ep_b);
        // An ACK to a tuple nothing claims — smoltcp answers RST.
        let seg = seg_v4(
            "10.0.0.3".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
            41000,
            9999,
            1,
            1,
            0x10,
        );
        feed_tcp(&mut actor, 1, &seg);
        let now = SmolInstant::now();
        actor.iface.poll(now, &mut actor.device, &mut actor.sockets);
        actor.drain_device_tx();
        assert_eq!(
            actor.outbox.len(),
            1,
            "the stray segment produced one RST: {:?}",
            actor.outbox
        );
        assert_eq!(
            actor.outbox[0].0, ep_b,
            "the RST must encrypt under peer 1's session toward its endpoint"
        );
    }
}
