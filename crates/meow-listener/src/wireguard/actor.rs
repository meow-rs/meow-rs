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
//!    segments deliver, emits go to `device.tx_queue`), looped via
//!    [`poll_burst`] as the bounded-budget backstop (smoltcp 0.13
//!    drains socket egress inside one poll already; the burst bounds
//!    a permanently-progressing pass).
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
    enlarge_recv_buffer, enlarge_send_buffer, poll_burst, reset_scratch, BatchEndpoint,
    ChannelDevice, StreamEvent, TcpIo, WgStream, TCP_READ_QUEUE, TCP_SOCKET_BUF, TCP_WRITE_QUEUE,
    WG_TIMER_INTERVAL, WIRE_DRAIN_BUDGET,
};
use meow_wireguard::{
    CryptoJob, CryptoPool, SessionHandle, TunnResult, TxCryptoJob, DATA_OVERHEAD_SZ,
    DATA_PAYLOAD_OFF,
};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time::{timeout_at, Instant as TokioInstant};
use tracing::{debug, info, trace, warn};

use super::demux::{Action, PeerTable, Verdict};
use super::inner_udp::{self, UdpFlow, UdpFlowKey};
use crate::sniffer::SnifferRuntime;
use crate::stream_sniff::{sniff_first_payload, STREAM_SNIFF_GATHER_MAX};
use crate::wireguard::WireGuardListener;

/// The lazy listen pool's bound: one placeholder socket per
/// (peer, dport) pair in demand, at most this many. Eviction only ever
/// removes sockets still in `State::Listen` (errata E5 — a socket that
/// already transitioned is a flow, not a pool member).
const LISTEN_POOL_CAP: usize = 64;

/// Bytes drained per `socket.recv` call — the pump's 64 KiB chunk: a
/// hot flow costs a quarter of the `recv`/`try_send` rounds 16 KiB
/// items needed, and a `TCP_READ_QUEUE` of them covers the 1 MiB rx
/// window without one socket monopolising a service pass.
const TCP_READ_CHUNK: usize = 65536;

/// Once a socket's owning route task is gone on both channel halves the
/// flow has no consumer left. `conn_gone` can never enqueue `Close`
/// once `graceful_close` holds — the FIN is already out and
/// `TcpIo::Close` is deliberately suppressed so the peer's tail bytes
/// survive — and a peer that never closes back pins the socket forever:
/// smoltcp has no FinWait-2 timeout and `discard_socket_rx` keeps the
/// receive window open, so the peer's stream keeps arriving to
/// /dev/null. The grace covers the real teardown (FIN handshake, `out`
/// flush at socket pace); a peer still open past it was never going to
/// close.
const TCP_ORPHAN_GRACE: Duration = Duration::from_secs(2);

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
///
/// Sizing must cover one service pass's worst-case production, not just
/// a send-side backlog: `drain_device_tx` encapsulates every inner
/// packet smoltcp egressed this pass *before* `flush_outbox` runs, and a
/// single saturated TCP flow egresses up to its whole advertised window
/// — `TCP_SOCKET_BUF / ~1400` datagrams (~750 at 1 MiB). `1024` dropped
/// the tail of every two-flow 768 KiB+ burst onto the inner TCP as a
/// hole, which smoltcp's ≥1 s RTO floor turned into multi-second stalls
/// (measured: macOS loopback two-flow collapse to ~0–30 KB/s). 4× the
/// full-window burst covers a handful of saturated flows per pass while
/// staying a hard bound (~6 MB of staged datagrams at 1 MiB).
const OUTBOX_CAP: usize = 4 * TCP_SOCKET_BUF / 1400;

/// Retained crypto-scratch buffers. Demand is a handful of live dsts
/// between `flush_outbox` passes, so the cap only bounds the memory a
/// send-side burst leaves behind — past it the Vecs free, exactly what
/// happened to them pre-pool.
const SCRATCH_POOL_CAP: usize = 128;

/// Original-direction inner TCP tuple — `(client_ip, client_port,
/// target_ip, target_port)` as the peer wrote it. Reply packets reverse
/// it back to this key, so one map serves both directions.
type InnerTuple = (IpAddr, u16, IpAddr, u16);

/// One pool entry: the `State::Listen` placeholders parked on a
/// `(peer_slot, dport)` key. A smoltcp listener has no accept queue —
/// it takes exactly one SYN and leaves `Listen` — so a same-batch
/// burst of N same-dport SYNs needs N sockets or the tail draws RSTs.
/// The requesting peer is part of the key so bursts from different
/// peers each get their own placeholders (flow ownership itself comes
/// from `pending_syn`, not from the socket that happened to accept).
struct ListenEntry {
    handles: Vec<smoltcp::iface::SocketHandle>,
    /// The first placeholder's creation time — the eviction ordering
    /// key; handles added to the same entry later ride its age.
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
    out: VecDeque<TcpIo>,
    pending_read: VecDeque<StreamEvent>,
    eof_sent: bool,
    graceful_close: bool,
    spawned: bool,
    /// Armed when both conn channel halves report the route task gone;
    /// the [`TCP_ORPHAN_GRACE`] deadline after which the socket is
    /// aborted regardless of `graceful_close` — the bound that keeps a
    /// peer that never closes back from pinning the socket forever.
    dead_since: Option<Instant>,
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
    /// The unconnected listen socket, wrapped for batched `sendmmsg`
    /// I/O on Linux (a `try_send_to` loop elsewhere). Receive stays
    /// per-datagram — the demux needs each packet's source.
    endpoint: BatchEndpoint,
    bound_port: u16,
    table: PeerTable,
    device: ChannelDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    /// Recycled dst buffers for the `Tunn` calls — replaces the single
    /// fixed `work` scratch: a produced wire datagram keeps its buffer
    /// for `outbox` (`truncate` + move, no copy) and `flush_outbox`
    /// returns spent buffers here. Bounded by [`SCRATCH_POOL_CAP`]
    /// (plus whatever the outbox holds in flight).
    scratch_pool: VecDeque<Vec<u8>>,
    /// The size a checked-out scratch is reset to (`mtu + 256`, the old
    /// fixed `work` buffer's size).
    scratch_len: usize,
    recv_buf: Vec<u8>,
    /// PATCH(18): the batch drain's receive slots — the pump's
    /// `rx_slots` shape: [`WIRE_DRAIN_BUDGET`] independent
    /// `mtu + 256`-byte buffers so a DATA packet's datagram can move
    /// into the crypto pool (and onward into `rx_queue` as `Bytes`)
    /// without ever copying the payload. Unlike the pump's
    /// capacity-only slots these stay fully sized — the listener's
    /// unconnected socket reads each datagram with
    /// `try_recv_from(&mut [u8])`, which needs the whole slice.
    rx_slots: Vec<Vec<u8>>,
    outbox: VecDeque<(SocketAddr, Vec<u8>)>,

    tcp: HashMap<smoltcp::iface::SocketHandle, TcpFlow>,
    tcp_by_tuple: HashMap<InnerTuple, smoltcp::iface::SocketHandle>,
    /// ≥ one `State::Listen` placeholder per demanded `(peer_slot,
    /// dport)` — an entry holds one handle per in-flight same-dport
    /// SYN in the batch (smoltcp listeners have no accept queue). A
    /// listener carries no per-peer state — `accepts()` matches port
    /// only — so the flow's real owner is recovered from
    /// `pending_syn`, never from which placeholder took the SYN.
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
    /// Flow → actor work-available signal, shared by every routed
    /// stream. `Notify` pulse-merges: nudges while the actor is mid-pass
    /// collapse to one stored permit — the same "one pending wake" the
    /// capacity-1 mpsc approximated.
    wake: Arc<tokio::sync::Notify>,
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

        // MTU math per the spec's MTU contract: the configured value
        // is the *outer* wire MTU; the inner stack gets `mtu - 64`
        // (WireGuard + UDP + IP overhead), floor 576.
        let mtu = usize::from(cfg.mtu);
        let inner_mtu = mtu.saturating_sub(64).max(576);

        let endpoint = tokio::net::UdpSocket::from_std(std_sock)?;
        enlarge_recv_buffer(&endpoint);
        // Symmetric: a `poll_burst` pass can stage MiBs of wire-bound
        // datagrams, flushed to the kernel as `WIRE_DRAIN_BUDGET`-sized
        // batches back to back — the platform default `SO_SNDBUF`
        // (9 KiB on macOS) drops the tail of every burst on ENOBUFS.
        enlarge_send_buffer(&endpoint);
        let bound_port = endpoint.local_addr()?.port();
        let endpoint = BatchEndpoint::unconnected(endpoint);

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

        let wake = Arc::new(tokio::sync::Notify::new());
        let (inject_tx, inject_rx) = mpsc::channel(INJECT_QUEUE);

        Ok(Self {
            bound_port,
            table,
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            scratch_pool: VecDeque::new(),
            scratch_len: mtu + 256,
            recv_buf: vec![0u8; mtu + 256],
            rx_slots: (0..WIRE_DRAIN_BUDGET)
                .map(|_| vec![0u8; mtu + 256])
                .collect(),
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
            wake,
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
                        Ok((n, src)) => {
                            self.demux_one(src, n);
                            // Opportunistic batch drain: a burst usually
                            // arrives together — squeeze what's already
                            // queued through the demux before the next
                            // service pass instead of paying one select
                            // cycle per datagram. Same `try_recv_from`
                            // loop `service()` opens with, same budget.
                            self.drain_wire();
                        }
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
                _ = self.wake.notified() => {}
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
        self.poll_stack();
        self.drain_device_tx();
        if self.last_timer.elapsed() >= WG_TIMER_INTERVAL {
            self.last_timer = Instant::now();
            // Errata E1: reset_count is called every tick; the
            // limiter's own ~1s debounce decides whether the window
            // actually rolled.
            self.table.reset_rate_limit();
            let mut dst = self.take_scratch();
            let mut recharge = || {
                reset_scratch(
                    self.scratch_pool.pop_back().unwrap_or_default(),
                    self.scratch_len,
                )
            };
            for action in self.table.tick(&mut dst, &mut recharge) {
                self.apply_action(action);
            }
            self.return_scratch(dst);
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

    /// The smoltcp half of a service pass: burst-poll the interface,
    /// then `post_poll`'s registration/cleanup when the pass could
    /// have moved anything it tracks. Its own method so `service`'s
    /// poll step and the T1 burst pin drive the exact same code —
    /// under smoltcp 0.13 one `poll` drains egress internally, so the
    /// burst loop is the bounded-budget backstop rather than the
    /// throughput path; the pin still wants the production entry.
    fn poll_stack(&mut self) {
        let now = SmolInstant::now();
        // `post_poll`'s bookkeeping only has work when the poll could
        // have changed anything it tracks — fresh inner packets fed to
        // smoltcp, packets emitted (an accept's SYN-ACK), or same-pass
        // bookkeeping outstanding. A quiet pass skips its O(sockets)
        // sweeps entirely: no accept, no abort, no orphan can appear
        // out of nothing (timer-driven deaths of owned flows are
        // already caught by `service_tcp`'s own iteration).
        let had_rx = !self.device.rx_queue.is_empty();
        // Burst, not a single poll. Before smoltcp 0.13 a socket
        // egressed at most one TCP segment per `poll`, so one call per
        // pass capped a bulk flow at ~1 segment per inner-RTT wake
        // (~285 KB/s measured); the loop was the throughput critical
        // path. 0.13's `poll` now drains socket egress internally
        // (upstream #1059), so `poll_burst` stays only as the
        // bounded-budget safety net, looping until the stack goes
        // quiet.
        poll_burst(&mut self.iface, now, &mut self.device, &mut self.sockets);
        if had_rx
            || !self.device.tx_queue.is_empty()
            || !self.pending_syn.is_empty()
            || !self.in_flight_syns.is_empty()
            || !self.pending_close.is_empty()
            || !self.dead_dying.is_empty()
        {
            self.post_poll();
        }
    }

    /// A crypto dst buffer for the next `Tunn` call: a pooled one reset
    /// to `scratch_len`, or a fresh allocation when the pool is empty.
    /// [`reset_scratch`] carries the safety contract — *length*, not
    /// capacity, is what `Tunn` sees.
    fn take_scratch(&mut self) -> Vec<u8> {
        reset_scratch(
            self.scratch_pool.pop_back().unwrap_or_default(),
            self.scratch_len,
        )
    }

    /// Return a spent buffer to the pool. Only full-size buffers are
    /// kept — an undersized one (e.g. a demux-produced `to_vec`
    /// datagram) would force a realloc at the next checkout anyway, so
    /// it frees as it did pre-pool. Anything past [`SCRATCH_POOL_CAP`]
    /// frees too.
    fn return_scratch(&mut self, buf: Vec<u8>) {
        if buf.capacity() >= self.scratch_len && self.scratch_pool.len() < SCRATCH_POOL_CAP {
            self.scratch_pool.push_back(buf);
        }
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
    /// [`WIRE_DRAIN_BUDGET`], as the PATCH(18) three-phase pass:
    ///
    ///   A. **Serial demux** — `try_recv_from` into `rx_slots`, then
    ///      reserved-scrub + `classify_datagram` per slot in wire order
    ///      (the shared limiter/mac1 verify and peer dispatch the fused
    ///      `process_datagram` ran — ordering contract unchanged). DATA
    ///      packets become `CryptoJob`s flattened across peers: the slot
    ///      Vec itself travels into the job, so the worker opens it in
    ///      place and the same buffer becomes the `Bytes` the stack
    ///      consumes — zero-copy end to end. Non-DATA packets —
    ///      handshakes, cookie replies, drops — finish inline through
    ///      `finish_verified` in arrival order.
    ///   B. **Worker pass** — `CryptoPool::run_shared(&mut jobs)` on
    ///      the process-wide pool (resolved lazily — `jobs <= 2` stays
    ///      inline and never spawns it): a multi-peer burst
    ///      parallelises across all the peers it spans, not just
    ///      per-peer.
    ///   C. **Serial post-pass** — in wire order:
    ///      `handle_decrypted_data` replays the session/timer/validate
    ///      bookkeeping, `admit_data` runs the ACL + roam gate, and the
    ///      slot's `Bytes` view moves into `handle_inner`.
    ///
    /// Reordering vs the serial drain is confined to disjoint sinks: an
    /// interleaved non-DATA datagram's `ToWire` actions land before a
    /// DATA packet's `Inner`, and each sink — the wire socket and the
    /// smoltcp feed — still sees its own inputs in order (the pump's
    /// drain_wire carries the same contract).
    ///
    /// Two bounded divergences inside a batch remain, both confined to
    /// ordering-sensitive state: (a) a DATA packet's `timer_tick`/
    /// `set_current_session` lands in Phase C, *after* a same-batch
    /// non-DATA packet's output — the `want_keepalive`/`want_handshake`
    /// liveness pair's last writer can differ (the numeric timestamps a
    /// tick writes are order-free), and one flushed queued packet may
    /// seal under the pre-batch `current` session; (b)
    /// `finish_verified`'s chained flush resolves the peer's `endpoint`
    /// in Phase A, before Phase C's `admit_data` can roam it — a batch
    /// that both roams a peer and triggers its flush can send that
    /// flush to the previous address; the roam still lands and the
    /// next batch's output already uses it.
    fn drain_wire(&mut self) {
        let mut slots = std::mem::take(&mut self.rx_slots);
        let mut jobs: Vec<CryptoJob> = Vec::new();
        // (rx-slot index, datagram source, peer slot) per job — the
        // post-pass replays them back in the same wire order.
        let mut ctxs: Vec<(usize, SocketAddr, usize)> = Vec::new();
        // Phase-A actions — `finish_verified` can only emit `ToWire`
        // for a non-DATA packet (handshake response, its chained
        // flush, or the under-load cookie reply): inner packets can
        // only come out of the DATA arm, which phase C owns.
        let mut actions: Vec<Action> = Vec::new();
        let mut dst = self.take_scratch();
        // `recharge` refills `dst` from the pool each time a produced
        // wire datagram consumes it — the `demux_one` field-precise
        // capture trick: `self.table` stays borrowable while the
        // closure owns `scratch_pool`/`scratch_len`. The scope ends its
        // borrow before the `&mut self` calls below it.
        {
            let mut recharge = || {
                reset_scratch(
                    self.scratch_pool.pop_back().unwrap_or_default(),
                    self.scratch_len,
                )
            };
            for (i, slot) in slots.iter_mut().enumerate() {
                // `slots` stays `WIRE_DRAIN_BUDGET` long — the recv loop
                // just stops early on WouldBlock/error.
                let (n, src) = match self.endpoint.try_recv_from(slot) {
                    Ok(x) => x,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        debug!("wireguard {}: endpoint recv error: {e}", self.name);
                        break;
                    }
                };
                let mut pkt = std::mem::take(slot);
                // Inbound reserved bytes 1..4 zero before parse — the same
                // scrub `demux_one` documents (WARP peers stamp the field;
                // the vendored parser checks it as part of the LE type).
                if n >= 4 {
                    pkt[1..4].fill(0);
                }
                match self.table.classify_datagram(src, &pkt[..n]) {
                    Verdict::Data {
                        slot: peer_slot,
                        packet,
                    } => {
                        let (receiver_idx, counter) = (packet.receiver_idx, packet.counter());
                        // `Arc` the session crypto while `&mut self.table`
                        // is free — the job carries it to the worker; a
                        // mid-batch re-handshake replacing the ring slot
                        // can't strand the open.
                        let crypto = self.table.peers()[peer_slot]
                            .tunn
                            .session_handle_for(receiver_idx);
                        // The job's own context tag — the post-pass
                        // lands each result on its (slot, source, peer)
                        // exactly, even if a lost chunk ever shifted
                        // the return positions.
                        jobs.push(CryptoJob::new(
                            pkt,
                            n,
                            receiver_idx,
                            counter,
                            crypto,
                            ctxs.len(),
                        ));
                        ctxs.push((i, src, peer_slot));
                    }
                    Verdict::Other {
                        slot: peer_slot,
                        packet,
                    } => {
                        self.table.finish_verified(
                            peer_slot,
                            src,
                            packet,
                            &mut actions,
                            &mut dst,
                            &mut recharge,
                        );
                        *slot = pkt;
                    }
                    Verdict::CookieReply(bytes) => {
                        actions.push(Action::ToWire { addr: src, bytes });
                        *slot = pkt;
                    }
                    Verdict::Drop => *slot = pkt,
                }
            }
        }
        // Phase-A wire output first — socket sends land before the
        // crypto results rejoin, exactly as the serial drain emitted
        // them.
        for action in actions {
            self.apply_action(action);
        }
        self.return_scratch(dst);

        // Phase B — the batch's AEAD opens, in place inside the job
        // bufs. `run_shared` fills every `job.result`, preserving job
        // order — and its `n <= 2` shortcut runs *before* the shared
        // pool is resolved, so a small batch never spawns the workers.
        CryptoPool::run_shared(&mut jobs);

        // Phase C — serial post-pass in wire order. The demux's serial
        // contract drops DATA decrypt/auth errors silently; the fused
        // path's `handle_result` `_` arm did the same, so no log.
        for job in jobs {
            let (i, src, peer_slot) = ctxs[job.tag];
            let mut pkt = job.buf;
            slots[i] = match job.result {
                Some(Ok(pt_len)) => {
                    let produced = match self.table.peers_mut()[peer_slot]
                        .tunn
                        .handle_decrypted_data(job.receiver_idx, pt_len, &mut pkt[..job.wire_len])
                    {
                        TunnResult::WriteToTunnelV4(b, ip) => Some((b.len(), IpAddr::V4(ip))),
                        TunnResult::WriteToTunnelV6(b, ip) => Some((b.len(), IpAddr::V6(ip))),
                        // Keepalive (Done) / malformed-inner / the
                        // session bookkeeping paths — all silent.
                        _ => None,
                    };
                    match produced {
                        Some((len, src_ip)) => {
                            // The pump's `Bytes` hand-off: bound the Vec
                            // to the datagram, take over the allocation,
                            // publish only the plaintext view.
                            pkt.truncate(job.wire_len);
                            let bytes =
                                Bytes::from(pkt).slice(DATA_PAYLOAD_OFF..DATA_PAYLOAD_OFF + len);
                            if let Some(action) =
                                self.table.admit_data(peer_slot, src, src_ip, bytes)
                            {
                                self.apply_action(action);
                            }
                            // Consumed slot — back-fill a fresh
                            // full-size buffer for the next drain.
                            vec![0u8; self.scratch_len]
                        }
                        None => pkt,
                    }
                }
                Some(Err(_)) | None => pkt,
            };
        }
        // A worker-lost chunk leaves its slots `mem::take`n — capacity-0
        // husks whose `try_recv_from` would read zero bytes forever.
        // Back-fill them at full size; a loss-free pass heals nothing.
        let mut healed = 0usize;
        for slot in &mut slots {
            if slot.capacity() == 0 {
                *slot = vec![0u8; self.scratch_len];
                healed += 1;
            }
        }
        debug_assert_eq!(healed, 0, "crypto pool lost a chunk's buffers");
        self.rx_slots = slots;
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
        let mut dst = self.take_scratch();
        // `recharge` refills `dst` from the pool each time a produced
        // wire datagram consumes it — field-precise captures keep
        // `self.table` (call) and `self` (apply_action) borrowable.
        let mut recharge = || {
            reset_scratch(
                self.scratch_pool.pop_back().unwrap_or_default(),
                self.scratch_len,
            )
        };
        for action in self
            .table
            .process_datagram(src, &pkt[..n], &mut dst, &mut recharge)
        {
            self.apply_action(action);
        }
        self.return_scratch(dst);
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
    /// signals a peer violating its own MTU. The packet arrives as
    /// `Bytes` so the TCP path feeds `rx_queue` with a refcount clone.
    fn handle_inner(&mut self, slot: usize, pkt: &Bytes, v6: bool) {
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
    fn inner_tcp(&mut self, slot: usize, pkt: &Bytes, view: &InnerView) {
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
            // Counted *before* the capacity decision: `needed` below
            // reads the in-flight set, so this SYN must be in it —
            // which means `at_capacity` counts it too. That errs on
            // the conservative side: an over-cap SYN still spends an
            // in-flight slot for the rest of this pass (the second
            // gate in `post_poll` aborts its accept anyway).
            self.in_flight_syns.insert(key);
            if !self.at_capacity() {
                // One `Listen` placeholder per in-flight same-dport
                // SYN owned by this peer — a smoltcp listener has no
                // accept queue, so N same-batch SYNs to one port need
                // N sockets or the tail draws RSTs. `pending_syn`
                // carries each tuple's owning slot, so a different
                // peer's same-dport burst counts toward its own key.
                let needed = self
                    .in_flight_syns
                    .iter()
                    .filter(|t| {
                        t.3 == tcpv.dport && self.pending_syn.get(t).is_some_and(|&s| s == slot)
                    })
                    .count();
                self.ensure_listener_n(slot, tcpv.dport, needed);
            }
        }
        if !claimed {
            // No flow claims this packet — if smoltcp answers with an
            // RST it carries the reversed tuple, which maps back via
            // this hint to the peer that must encrypt it.
            self.rst_hint.insert(key, slot);
        }
        self.device.rx_queue.push_back(pkt.clone());
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
    ///
    /// PATCH(19): the same three-phase shape `drain_device_tx` carries —
    /// items whose peer holds a current session flatten into one
    /// `TxCryptoJob` batch across all peers (each `Bytes` item is
    /// copied into the job's `inner` Vec — flow replies are small and
    /// the AEAD seal dominates); items whose peer has no session keep
    /// the serial [`handle_inject`](Self::handle_inject) arm, which is
    /// where `queue_packet` + the handshake chain live. Counter
    /// reservation is per item (`reserve_tx_counters(1)`) — unlike
    /// `drain_device_tx`'s contiguous block this queue keys counters
    /// per packet, which stays correct because counters need
    /// uniqueness, not contiguity.
    fn drain_inject(&mut self) {
        let mut jobs: Vec<TxCryptoJob> = Vec::new();
        let mut ctxs: Vec<usize> = Vec::new();
        let mut handles: HashMap<usize, Option<SessionHandle>> = HashMap::new();
        while let Ok((slot, pkt)) = self.inject_rx.try_recv() {
            let crypto = handles
                .entry(slot)
                .or_insert_with(|| {
                    self.table
                        .peers()
                        .get(slot)
                        .and_then(|p| p.tunn.current_session_handle())
                })
                .clone();
            match crypto {
                Some(handle) => {
                    if pkt.len() + DATA_OVERHEAD_SZ > self.scratch_len {
                        // `build_reply` caps the inner packet at
                        // inner_mtu = mtu - 64 — a breach is a flow-task
                        // bug; the debug_assert pins the contract while
                        // the drop keeps release-mode posture.
                        debug_assert!(
                            pkt.len() + DATA_OVERHEAD_SZ <= self.scratch_len,
                            "inject packet {}B + {DATA_OVERHEAD_SZ}B overhead exceeds \
                             MTU-sized scratch buffer {}B",
                            pkt.len(),
                            self.scratch_len
                        );
                        debug!(
                            "wireguard {}: dropping {}B inject packet (scratch {}B)",
                            self.name,
                            pkt.len(),
                            self.scratch_len
                        );
                        continue;
                    }
                    jobs.push(TxCryptoJob::new(
                        pkt.to_vec(),
                        self.take_scratch(),
                        handle.reserve_tx_counters(1),
                        handle,
                        ctxs.len(),
                    ));
                    ctxs.push(slot);
                }
                None => self.handle_inject(slot, &pkt),
            }
        }

        CryptoPool::run_tx_shared(&mut jobs);
        // Inner copies aren't `tx_queue` buffers — `pool_inner: false`
        // drops them with the job, exactly as the serial arm dropped
        // the `Bytes`.
        self.finish_tx_jobs(jobs, &ctxs, false);
    }

    /// A flow task's finished inner packet — encrypt under the owning
    /// peer's session and send to its endpoint. The serial arm of
    /// [`drain_inject`](Self::drain_inject): peers with no established
    /// session take this path so `encapsulate`'s `queue_packet` +
    /// handshake-initiation chain still runs.
    fn handle_inject(&mut self, slot: usize, pkt: &[u8]) {
        let mut dst = self.take_scratch();
        if pkt.len() + DATA_OVERHEAD_SZ <= dst.len() {
            if let Some(peer) = self.table.peers_mut().get_mut(slot) {
                if let TunnResult::WriteToNetwork(b) = peer.tunn.encapsulate(pkt, &mut dst) {
                    if let Some(addr) = peer.endpoint {
                        let len = b.len();
                        dst.truncate(len);
                        peer.stamp_reserved(&mut dst);
                        self.enqueue_outbox(addr, dst);
                        return;
                    }
                }
            }
        } else {
            // Unreachable while `dst` is MTU-sized — `build_reply`
            // caps the inner packet at inner_mtu = mtu - 64, and
            // `dst` is mtu + 256, so headroom always covers the WG
            // overhead. The debug_assert pins that contract; the
            // drop+log stays as the release-mode guard the spec's
            // oversize-drop posture calls for, rather than a silent
            // oversize swallow.
            debug_assert!(
                pkt.len() + DATA_OVERHEAD_SZ <= dst.len(),
                "inject packet {}B + {DATA_OVERHEAD_SZ}B overhead exceeds \
                 MTU-sized scratch buffer {}B",
                pkt.len(),
                dst.len()
            );
            debug!(
                "wireguard {}: dropping {}B inject packet (scratch {}B)",
                self.name,
                pkt.len(),
                dst.len()
            );
        }
        self.return_scratch(dst);
    }

    // ── listen pool + flow registration ──────────────────────────────

    /// Combined TCP+UDP cap (`max-connections`; `0` = unlimited).
    fn at_capacity(&self) -> bool {
        self.max_connections > 0
            && self.tcp.len() + self.in_flight_syns.len() + self.udp_flows.len()
                >= self.max_connections
    }

    /// Single-demand form of [`Self::ensure_listener_n`] — kept for
    /// tests that assert a placeholder's presence rather than a batch
    /// count (`inner_tcp` always calls the counted form).
    #[cfg(test)]
    fn ensure_listener(&mut self, slot: usize, dport: u16) -> bool {
        self.ensure_listener_n(slot, dport, 1)
    }

    /// Ensure `(slot, dport)` holds at least `needed` `State::Listen`
    /// placeholders. Returns false when demand can't be met: the pool
    /// is full *and* no `Listen`-state socket is evictable (errata E5),
    /// or smoltcp refused the listen. The placeholder itself is
    /// peer-blind beyond the key's slot — `pending_syn` carries
    /// ownership — so one entry serves a peer's whole same-dport burst
    /// while a different peer's SYNs get their own key.
    fn ensure_listener_n(&mut self, slot: usize, dport: u16, needed: usize) -> bool {
        // Drop handles whose socket already left `Listen` — it is a
        // flow (or a reaped orphan) owned elsewhere now, so only the
        // pool bookkeeping is ours to clear. The socket itself is
        // *not* removed here: mid-flight it may be registered this
        // very pass, and terminating it would kill a live conn.
        if let Some(entry) = self.listen_pool.get_mut(&(slot, dport)) {
            let mut stale = Vec::new();
            entry.handles.retain(|&h| {
                let keep = self.sockets.get::<tcp::Socket>(h).state() == tcp::State::Listen;
                if !keep {
                    stale.push(h);
                }
                keep
            });
            for h in stale {
                self.listen_pool_handles.remove(&h);
            }
            if entry.handles.is_empty() {
                self.listen_pool.remove(&(slot, dport));
            }
        }
        let mut have = self
            .listen_pool
            .get(&(slot, dport))
            .map_or(0, |e| e.handles.len());
        while have < needed {
            // `protect` keeps the filling key out of the candidate set:
            // evicting it would drop placeholders `have` still counts
            // (the entry would resurface under `or_insert` with a single
            // handle while the count kept climbing — returning true on
            // fewer than `needed` sockets).
            if self.listen_pool_handles.len() >= LISTEN_POOL_CAP
                && !self.evict_oldest_listener((slot, dport))
            {
                // Errata E5: nothing Listen-state to evict — the new
                // SYN is dropped, silently (it will still be fed;
                // smoltcp may RST, which is the §4.2 pool-exhausted
                // answer).
                return false;
            }
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]),
                tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]),
            );
            // TCP_NODELAY — the placeholder is itself the socket a SYN
            // transitions into a conn (smoltcp listeners have no accept
            // queue to swap identities), so the flag carries onto the
            // accepted flow. A proxy stream wants latency over tinygram
            // batching; the pump's `dial_tcp` sets the same.
            socket.set_nagle_enabled(false);
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
            self.listen_pool
                .entry((slot, dport))
                .or_insert_with(|| ListenEntry {
                    handles: Vec::new(),
                    created: Instant::now(),
                })
                .handles
                .push(handle);
            have += 1;
        }
        true
    }

    /// Evict the oldest pool entry still holding a `State::Listen`
    /// socket — the whole key goes, every placeholder it parked.
    /// `protect` exempts one key from candidacy: `ensure_listener_n`
    /// passes the key it is filling, whose placeholders must survive
    /// the very eviction that makes their room. Returns false when no
    /// other occupant qualifies — the E5 "no evictable" case.
    fn evict_oldest_listener(&mut self, protect: (usize, u16)) -> bool {
        let oldest = self
            .listen_pool
            .iter()
            .filter(|(k, e)| {
                **k != protect
                    && e.handles
                        .iter()
                        .any(|&h| self.sockets.get::<tcp::Socket>(h).state() == tcp::State::Listen)
            })
            .min_by_key(|(_, e)| e.created)
            .map(|(k, _)| *k);
        let Some(key) = oldest else {
            return false;
        };
        let entry = self.listen_pool.remove(&key).expect("entry checked above");
        for h in entry.handles {
            // Only a socket still in `Listen` is ours to close — one
            // that already transitioned is a flow owned elsewhere.
            if self.sockets.get::<tcp::Socket>(h).state() == tcp::State::Listen {
                self.sockets.remove(h);
            }
            self.listen_pool_handles.remove(&h);
        }
        true
    }

    /// After `iface.poll`: listeners that accepted a SYN left the pool
    /// (their socket is now a flow in `SynReceived`+); register fresh
    /// flow sockets with the owning peer recovered from `pending_syn`,
    /// then bury any socket that died with no owner.
    fn post_poll(&mut self) {
        self.in_flight_syns.clear();
        // Pool sweep, per handle: a placeholder that took a SYN left
        // `Listen` and is a flow now — drop just that handle; the key
        // itself goes once no socket still listens on it. Removed
        // handles collect in `stale_handles` so `listen_pool_handles`
        // isn't borrowed while the map iterates.
        let mut stale_handles = Vec::new();
        let mut empty_keys = Vec::new();
        for (key, entry) in &mut self.listen_pool {
            entry.handles.retain(|&h| {
                let keep = self.sockets.get::<tcp::Socket>(h).state() == tcp::State::Listen;
                if !keep {
                    stale_handles.push(h);
                }
                keep
            });
            if entry.handles.is_empty() {
                empty_keys.push(*key);
            }
        }
        for h in stale_handles {
            self.listen_pool_handles.remove(&h);
        }
        for key in empty_keys {
            self.listen_pool.remove(&key);
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
                // Erase only the mapping this dead entry owned: the
                // key may already point at a rebuilt same-tuple claim
                // (smoltcp recycles handles, so an unconditional
                // remove could take the new mapping down with the
                // old).
                if self.tcp_by_tuple.get(&key) == Some(&handle) {
                    self.tcp_by_tuple.remove(&key);
                }
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
                out: VecDeque::new(),
                pending_read: VecDeque::new(),
                eof_sent: false,
                graceful_close: false,
                spawned: false,
                dead_since: None,
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
        let wake = Arc::clone(&self.wake);
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
                    wake: Arc::clone(&wake),
                    pending_read: None,
                    pending_write: None,
                    write_reserve: None,
                    write_permit: None,
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

            // Ordered writes into the socket.
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

            // socket→conn reads.
            while let Some(ev) = st.pending_read.pop_front() {
                match st.read_tx.try_send(ev) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(ev)) => {
                        st.pending_read.push_front(ev);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        discard_socket_rx(st, socket);
                        break;
                    }
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
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            discard_socket_rx(st, socket);
                            break;
                        }
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
            // Orphan bound: both channel halves closed means the route
            // task released the stream entirely — the socket's output
            // has no consumer and its input is discard-drained. Unlike
            // `conn_gone` the arm needs no `write_rx.is_empty()`: a
            // jammed closed channel is equally dead, and the grace
            // abort covers it. Give a graceful close the grace to
            // finish, then abort whatever is still open: without it a
            // FinWait socket under a peer that keeps streaming lives
            // until session teardown.
            if st.write_rx.is_closed() && st.read_tx.is_closed() {
                match st.dead_since {
                    None => st.dead_since = Some(Instant::now()),
                    Some(t) if t.elapsed() >= TCP_ORPHAN_GRACE => {
                        debug!(
                            "wireguard {}: TCP {handle:?} conn dead past grace (state {:?}) → abort",
                            self.name,
                            socket.state()
                        );
                        socket.abort();
                    }
                    _ => {}
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
            // Box as `dyn ProxyConn` so the tunnel's inbound
            // `WriteBytesView` probe (an `Any` downcast) finds the
            // `WgStream` underneath and bulk-relays into it with owned
            // `Bytes`, not a per-fill `copy_from_slice` (perf-7 P7-1).
            let mut stream: Box<dyn meow_common::ProxyConn> = Box::new(stream);
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
            drop(st); // Dropping `write_rx` closes the writer's channel.
            self.pending_close.push(handle);
        } else if self.sockets.iter().any(|(h, _)| h == handle) {
            self.sockets.remove(handle);
        }
    }

    // ── device tx → wire ─────────────────────────────────────────────

    /// Encrypt each emitted packet under its owning peer's session —
    /// the PATCH(19) three-phase shape `drain_wire` carries on the RX
    /// side:
    ///
    ///   A. **Serial setup** — the packet's reversed tuple locates the
    ///      flow (hence peer slot); an unmatched packet — an RST for a
    ///      refused SYN or stray — consults the `rst_hint` its ingress
    ///      recorded. Each peer's `current_session_handle` is captured
    ///      once into a slot cache, so the batch's per-peer `Arc` clone
    ///      happens while `&mut Tunn` is reachable; jobs flatten across
    ///      peers into one vector, each keyed to its peer's slot through
    ///      the `ctxs` side-table (`job.tag` indexes it — the same
    ///      opaque-tag pattern `drain_wire`'s `CryptoJob`s use). A peer
    ///      with no established session takes the serial
    ///      [`encapsulate_tx_packet`](Self::encapsulate_tx_packet) arm
    ///      inline — that is where `queue_packet` + the
    ///      handshake-initiation chain live — so the only reordering is
    ///      onto disjoint sinks (different peers' sockets, or a
    ///      handshake landing ahead of a same-peer DATA, which is the
    ///      order WireGuard wants anyway). Counters reserve per packet
    ///      in queue order — per-peer counters stay monotone in that
    ///      peer's emit order.
    ///   B. **Worker pass** — `CryptoPool::run_tx_shared(&mut jobs)`:
    ///      the batch's AEAD seals off-thread (inline when
    ///      `jobs <= 2`, lazily resolved like the RX entry point).
    ///   C. **Serial post-pass** —
    ///      [`finish_tx_jobs`](Self::finish_tx_jobs) walks jobs in
    ///      order: per-peer `handle_sent_data`, `stamp_reserved`,
    ///      endpoint lookup, outbox enqueue — job order = each peer's
    ///      counter order = the emit order the serial loop produced.
    ///      Every `inner` Vec returns to `device.tx_pool` regardless
    ///      of outcome; failed `wire` bufs return to `scratch_pool`.
    ///
    /// A peer with no endpoint still runs `handle_sent_data` — the
    /// serial path's accounting lived inside `encapsulate`, before the
    /// endpoint check dropped the produced datagram — and its sealed
    /// `wire` buf returns to `scratch_pool` rather than the outbox.
    fn drain_device_tx(&mut self) {
        let mut dst = self.take_scratch();
        let mut jobs: Vec<TxCryptoJob> = Vec::new();
        let mut ctxs: Vec<usize> = Vec::new();
        let mut handles: HashMap<usize, Option<SessionHandle>> = HashMap::new();
        while let Some(pkt) = self.device.tx_queue.pop_front() {
            let Some(slot) = self.route_tx_packet(&pkt) else {
                trace!("wireguard {}: unroutable inner tx packet", self.name);
                self.device.return_tx_buf(pkt);
                continue;
            };
            let crypto = handles
                .entry(slot)
                .or_insert_with(|| {
                    self.table
                        .peers()
                        .get(slot)
                        .and_then(|p| p.tunn.current_session_handle())
                })
                .clone();
            match crypto {
                Some(handle) => {
                    if pkt.len() + DATA_OVERHEAD_SZ > self.scratch_len {
                        warn!(
                            "wireguard {}: dropping {}B inner tx packet (scratch {}B)",
                            self.name,
                            pkt.len(),
                            self.scratch_len
                        );
                        self.device.return_tx_buf(pkt);
                        continue;
                    }
                    jobs.push(TxCryptoJob::new(
                        pkt,
                        self.take_scratch(),
                        handle.reserve_tx_counters(1),
                        handle,
                        ctxs.len(),
                    ));
                    ctxs.push(slot);
                }
                None => {
                    self.encapsulate_tx_packet(slot, &pkt, &mut dst);
                    self.device.return_tx_buf(pkt);
                }
            }
        }
        self.return_scratch(dst);

        // Phase B — the batch's AEAD seals inside the job `wire` bufs.
        CryptoPool::run_tx_shared(&mut jobs);

        // Phase C — serial post-pass in job order.
        self.finish_tx_jobs(jobs, &ctxs, true);

        // RST hints only live for the poll that produced them — a stale
        // entry could misroute a same-tuple RST of a later packet.
        self.rst_hint.clear();
    }

    /// The serial half of `drain_device_tx`: one inner packet through
    /// `encapsulate` — the no-session arm (where `queue_packet` + the
    /// handshake-initiation chain live) and `encapsulate`'s own
    /// non-DATA output. `dst` is the caller-owned scratch: a produced
    /// datagram consumes it and the caller refills on the next call.
    /// The inner packet's `tx_pool` return stays with the caller —
    /// every path returns it exactly once.
    fn encapsulate_tx_packet(&mut self, slot: usize, pkt: &[u8], dst: &mut Vec<u8>) {
        if pkt.len() + DATA_OVERHEAD_SZ > dst.len() {
            warn!(
                "wireguard {}: dropping {}B inner tx packet (scratch {}B)",
                self.name,
                pkt.len(),
                dst.len()
            );
            return;
        }
        let Some(peer) = self.table.peers_mut().get_mut(slot) else {
            return;
        };
        if let TunnResult::WriteToNetwork(b) = peer.tunn.encapsulate(pkt, dst) {
            if let Some(addr) = peer.endpoint {
                let len = b.len();
                dst.truncate(len);
                peer.stamp_reserved(dst);
                let out = std::mem::replace(dst, self.take_scratch());
                self.enqueue_outbox(addr, out);
            }
        }
    }

    /// The Phase-C post-pass both TX drains share: walk each job's
    /// result in order, replay the peer's bookkeeping on its own
    /// `Tunn`, stamp its reserved bytes, and enqueue to its endpoint.
    /// `ctxs[job.tag]` is the job's peer slot. `pool_inner` routes the
    /// inner Vec: `true` returns it to `device.tx_pool` (a drained
    /// `tx_queue` buffer); `false` drops it (an inject copy that was
    /// never pool-owned). A job the pool failed or never resolved
    /// returns its `wire` buf to `scratch_pool` unmodified — still
    /// full-size, so the pool accepts it.
    fn finish_tx_jobs(&mut self, jobs: Vec<TxCryptoJob>, ctxs: &[usize], pool_inner: bool) {
        for job in jobs {
            let slot = ctxs[job.tag];
            let inner_len = job.inner.len();
            if pool_inner {
                self.device.return_tx_buf(job.inner);
            }
            let mut wire = job.wire;
            match job.result {
                Some(Ok(_)) => match self.table.peers_mut().get_mut(slot) {
                    Some(peer) => {
                        // The serial path's accounting lived inside
                        // `encapsulate` — it ran on every produced
                        // datagram, including one the endpoint check
                        // then dropped — so it replays before the
                        // endpoint gate here too.
                        peer.tunn.handle_sent_data(inner_len);
                        match peer.endpoint {
                            Some(addr) => {
                                peer.stamp_reserved(&mut wire);
                                self.enqueue_outbox(addr, wire);
                            }
                            None => self.return_scratch(wire),
                        }
                    }
                    // A peer slot the table no longer holds can't
                    // happen (the table is static) — drop like the
                    // serial arm's `get_mut` miss.
                    None => self.return_scratch(wire),
                },
                Some(Err(e)) => {
                    debug!("wireguard {}: encapsulate error: {e:?}", self.name);
                    self.return_scratch(wire);
                }
                None => {
                    debug_assert!(false, "crypto pool resolves every job");
                    self.return_scratch(wire);
                }
            }
        }
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
    /// The evicted buffer still goes back to the scratch pool.
    fn enqueue_outbox(&mut self, addr: SocketAddr, pkt: Vec<u8>) {
        if self.outbox.len() >= OUTBOX_CAP {
            if let Some((_, dropped)) = self.outbox.pop_front() {
                self.return_scratch(dropped);
            }
            trace!(
                "wireguard {}: outbox full — dropped oldest datagram",
                self.name
            );
        }
        self.outbox.push_back((addr, pkt));
    }

    /// Nonblocking sends, a [`WIRE_DRAIN_BUDGET`]-bounded batch at a
    /// time — one `sendmmsg` (a destination per `mmsghdr`, so roaming
    /// peers keep per-packet addressing) on Linux, one `sendmsg_x`
    /// (same, per `msghdr_x`) on macOS, a `try_send_to`
    /// loop elsewhere. A batch that stops short leaves the boundary
    /// datagram at the head of `staged`: replaying it surfaces the
    /// errno the mmsg call folded into the short count — `WouldBlock`
    /// requeues the remainder verbatim (a full socket defers the tail
    /// to the next pass), any other error logs and drops that one
    /// datagram while the rest of the batch continues — the same
    /// semantics as the per-packet loop. Sent and failed buffers both
    /// go back to the scratch pool.
    fn flush_outbox(&mut self) {
        let mut staged: VecDeque<(SocketAddr, Vec<u8>)> =
            VecDeque::with_capacity(WIRE_DRAIN_BUDGET);
        while !self.outbox.is_empty() {
            for _ in 0..self.outbox.len().min(WIRE_DRAIN_BUDGET) {
                staged.push_back(self.outbox.pop_front().expect("bounded by len"));
            }
            loop {
                // `refs` borrows `staged` — scoped inside the loop so
                // the shared borrow ends before `staged` shrinks.
                let refs: Vec<(SocketAddr, &[u8])> =
                    staged.iter().map(|(a, p)| (*a, p.as_slice())).collect();
                let sent = self.endpoint.send_batch_to(&refs);
                for (_, pkt) in staged.drain(..sent) {
                    self.return_scratch(pkt);
                }
                if staged.is_empty() {
                    break;
                }
                let (addr, pkt) = staged.pop_front().expect("non-empty after partial batch");
                match self.endpoint.try_send_to(&pkt, addr) {
                    Ok(_) => self.return_scratch(pkt),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Requeue the rest of the batch ahead of
                        // whatever the outbox already held, then the
                        // boundary datagram itself — it must stay
                        // ahead of its successors.
                        while let Some(tail) = staged.pop_back() {
                            self.outbox.push_front(tail);
                        }
                        self.outbox.push_front((addr, pkt));
                        return;
                    }
                    Err(e) => {
                        debug!(
                            "wireguard {}: endpoint send to {addr} failed: {e}",
                            self.name
                        );
                        self.return_scratch(pkt);
                    }
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

/// Conn dead → drain the socket's rx to /dev/null instead of leaving
/// it full. An undrained rx keeps the advertised window pinned at 0:
/// the peer's smoltcp then holds `remote_win_len == 0`, its tx buffer
/// never flushes, the queued `TcpIo::Close` sits behind undrainable
/// `Data`, and both ends zombify (measured: `CloseWait`/`FinWait2`
/// pairs accumulating one per killed download, each pinning ~2 MiB).
/// With the buffer emptied the next ACK advertises a live window, the
/// peer flushes its backlog, its queued abort runs, and both sockets
/// reach `Closed` — a memmove-free drain since `recv` only consumes.
fn discard_socket_rx(st: &mut TcpFlow, socket: &mut tcp::Socket<'_>) {
    st.pending_read.clear();
    while socket.can_recv() {
        if socket.recv(|data| (data.len(), ())).is_err() {
            break;
        }
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
        seg_v4_data(src, dst, sport, dport, seq, ack, flags, &[])
    }

    /// `seg_v4` carrying `payload` after the 20-octet TCP header — the
    /// wire form of bytes a peer's TCP delivered to the inner socket.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per wire field; a struct would only rename the list"
    )]
    fn seg_v4_data(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut p = vec![0u8; 40 + payload.len()];
        let total_len = p.len() as u16;
        p[0] = 0x45;
        p[2..4].copy_from_slice(&total_len.to_be_bytes());
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
        p[40..].copy_from_slice(payload);
        let mut pseudo = Vec::with_capacity(32 + payload.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(20u16 + payload.len() as u16).to_be_bytes());
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
        actor.inner_tcp(slot, &Bytes::copy_from_slice(pkt), &view);
    }

    /// The poll half of a service pass, driven through the same
    /// `poll_stack` `service` itself runs: smoltcp consumes the rx
    /// queue under the burst loop, then the gated `post_poll` does
    /// registration/cleanup. Tests never re-spell a `poll_burst` call
    /// of their own — the binding under test is the production poll
    /// path, not the helper.
    fn poll_once(actor: &mut WgActor) {
        actor.poll_stack();
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
            actor.device.rx_queue.push_back(pkt.into());
        }
        let now = SmolInstant::now();
        actor.iface.poll(now, &mut actor.device, &mut actor.sockets);
        for entry in actor.listen_pool.values() {
            for &h in &entry.handles {
                assert_ne!(
                    actor.sockets.get::<tcp::Socket>(h).state(),
                    tcp::State::Listen
                );
            }
        }
        assert!(
            !actor.evict_oldest_listener((0, 65000)),
            "a fully-transitioned pool has no Listen socket to evict"
        );
        assert!(
            !actor.ensure_listener(0, 65000),
            "no evictable socket → the new dport's SYN is refused"
        );
    }

    /// Self-eviction regression: when the key being filled is itself the
    /// oldest evictable occupant, the fill loop must not evict it out
    /// from under `have` — the pre-fix loop dropped the entry, recreated
    /// it via `or_insert` with a single handle, and still counted the
    /// snapshot upward, returning true on fewer placeholders than
    /// demanded. The fix exempts the filling key from candidacy, so the
    /// demand is met against other victims (or refused, E5-style).
    #[tokio::test]
    async fn ensure_listener_n_never_evicts_its_own_key() {
        let mut actor = test_actor();
        // The filling key parks one placeholder first, then the rest of
        // the pool fills behind newer entries.
        assert!(actor.ensure_listener(0, 80));
        for port in 1000..1000 + (LISTEN_POOL_CAP - 1) as u16 {
            assert!(actor.ensure_listener(0, port), "dport {port} listens");
        }
        assert_eq!(actor.listen_pool_handles.len(), LISTEN_POOL_CAP);
        // Pin (0, 80) as the unique LRU front — `Instant` resolution can
        // tie entries created in one burst, and `min_by_key` breaks ties
        // on HashMap order.
        actor
            .listen_pool
            .get_mut(&(0, 80))
            .expect("filling key parked")
            .created = Instant::now() - Duration::from_secs(60);

        assert!(
            actor.ensure_listener_n(0, 80, 3),
            "other occupants are evictable — the demand must be met"
        );
        let entry = actor
            .listen_pool
            .get(&(0, 80))
            .expect("filling key survives its own fill");
        assert_eq!(
            entry.handles.len(),
            3,
            "every demanded placeholder really parked"
        );
        for &h in &entry.handles {
            assert_eq!(
                actor.sockets.get::<tcp::Socket>(h).state(),
                tcp::State::Listen
            );
        }
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
        // Cap 2 while connections set up: the in-flight set counts the
        // *current* SYN before the gate, so a fully-used cap would
        // never allow fresh listener demand — the refused leg below
        // tightens the cap *after* setup instead.
        actor.max_connections = 2;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();

        for round in 0..4u16 {
            // A placeholder that never accepts: the fed SYN's IPv4
            // `total_len` claims more than the datagram carries, so
            // smoltcp drops it at IP parse and the socket stays
            // `Listen` while the cap fills elsewhere. (A broken
            // checksum used to be the trigger; `ChannelDevice` now
            // skips RX verification — the AEAD open already proved
            // integrity — so the malformed-length path is the drop
            // that still exists.)
            let mut bad = syn_v4(client, target, 41000 + round, 443);
            bad[2..4].copy_from_slice(&200u16.to_be_bytes());
            feed_tcp(&mut actor, 0, &bad);
            poll_once(&mut actor);

            // A legit conn on another dport takes one cap slot.
            let good = syn_v4(client, target, 42000 + round, 80);
            feed_tcp(&mut actor, 0, &good);
            poll_once(&mut actor);
            assert_eq!(actor.tcp.len(), 1);

            // Tighten the cap under the established conn: a valid SYN
            // to the held dport accepts on the stale listener and is
            // aborted at the second gate — an orphaned `Closed`
            // socket the reaper must bury.
            actor.max_connections = 1;
            let refused = syn_v4(client, target, 43000 + round, 443);
            feed_tcp(&mut actor, 0, &refused);
            poll_once(&mut actor);
            actor.drain_device_tx();
            actor.max_connections = 2;

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

    /// wgsrv-fix-1 §I-1 — a killed flow parks its tuple in `tcp_dying`
    /// for one extra pass so the final RST still routes; the deferred
    /// erase in `dead_dying` must then dirty the post-poll gate on its
    /// own — a quiet pass that skips `post_poll` would strand the stale
    /// tuple mapping (and its `tcp_dying` entry) forever, dropping
    /// every same-tuple reconnect at the ownership check. The erase
    /// itself is also scoped to the handle the dead entry owned, so a
    /// rebuilt claim on the tuple can never be taken down with it.
    #[tokio::test]
    async fn dead_flow_tuple_rebuild_survives_deferred_erase() {
        let mut actor = test_actor();
        actor.max_connections = 4;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();
        let key: InnerTuple = (client.into(), 44000, target.into(), 443);

        // A live conn on the tuple.
        let syn = syn_v4(client, target, 44000, 443);
        feed_tcp(&mut actor, 0, &syn);
        poll_once(&mut actor);
        let h1 = actor.tcp_by_tuple[&key];

        // Conn death: `service_tcp` moves it to `tcp_dying` +
        // `pending_close`; the abort's RST emits on the next poll.
        actor.sockets.get_mut::<tcp::Socket>(h1).abort();
        actor.service_tcp();
        assert!(!actor.tcp.contains_key(&h1));
        assert!(actor.tcp_dying.contains_key(&h1));

        // The reap pass buries the socket and defers the table erase
        // one pass via `dead_dying`; drain the emitted RST here.
        poll_once(&mut actor);
        actor.drain_device_tx();
        assert_eq!(actor.dead_dying, vec![h1]);
        assert_eq!(actor.tcp_by_tuple.get(&key), Some(&h1));

        // The quiet pass: nothing fed, nothing queued to emit — the
        // deferred erase alone must still pull `post_poll` (the §I-1
        // dirty-gate bug left these entries stranded forever).
        assert!(actor.device.rx_queue.is_empty());
        assert!(actor.device.tx_queue.is_empty());
        actor.service();
        assert!(
            actor.dead_dying.is_empty() && actor.tcp_dying.is_empty(),
            "deferred erase drains on a pass with no other dirty signal"
        );
        assert!(!actor.tcp_by_tuple.contains_key(&key));

        // Same-tuple rebuild: a fresh SYN claims the tuple cleanly and
        // the already-run erase can't reach the new mapping.
        let syn2 = syn_v4(client, target, 44000, 443);
        feed_tcp(&mut actor, 0, &syn2);
        poll_once(&mut actor);
        let h2 = actor.tcp_by_tuple[&key];
        assert_eq!(actor.tcp[&h2].slot, 0);

        // If a rebuilt claim ever lands while a deferred erase is
        // still queued, the drain must skip it: the erase only removes
        // a mapping that still points at the dead entry's own handle.
        // (A fresh listener handle stands in for the dead flow's —
        // socket handles are unique, so `hx` can't equal `h2`.)
        assert!(actor.ensure_listener(0, 65000));
        let hx = *actor
            .listen_pool_handles
            .iter()
            .next()
            .expect("the 65000 listener's handle");
        actor.tcp_dying.insert(hx, (0, key));
        actor.dead_dying.push(hx);
        actor.reap_orphaned_sockets();
        assert_eq!(
            actor.tcp_by_tuple.get(&key),
            Some(&h2),
            "a queued erase must not take a rebuilt mapping down"
        );
        assert!(actor.tcp.contains_key(&h2));
    }

    /// `discard_socket_rx` — the dead-conn drain, inbound shape: the
    /// route task half-closed the flow (FIN flowing → `graceful_close`),
    /// then died while the peer still had tail bytes in flight — the
    /// `FinWait` zombie pair the fn's doc names. The pinned observables,
    /// all through the real `service_tcp` pass: the `Closed` channel arm
    /// calls the discard, the socket's rx residue empties (the advertised
    /// window un-pins on the next ACK), and the events parked in
    /// `pending_read` go with it. The socket itself survives — a
    /// graceful close never aborts — so the drain, not teardown, is
    /// what the assertions see.
    #[tokio::test]
    async fn discard_socket_rx_drains_residue_on_dead_conn() {
        let mut actor = test_actor();
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();
        let key: InnerTuple = (client.into(), 40000, target.into(), 443);

        feed_tcp(&mut actor, 0, &syn_v4(client, target, 40000, 443));
        poll_once(&mut actor);
        let handle = actor.tcp_by_tuple[&key];
        let syn_ack = actor
            .device
            .tx_queue
            .back()
            .expect("the accept emitted a SYN-ACK");
        let server_isn = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());

        // Handshake ACK → Established.
        let ack = seg_v4(
            client,
            target,
            40000,
            443,
            101,
            server_isn.wrapping_add(1),
            0x10,
        );
        feed_tcp(&mut actor, 0, &ack);
        poll_once(&mut actor);
        assert_eq!(
            actor.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );

        // The route task already spawned (`spawned`), sends its FIN —
        // a real `TcpIo::Shutdown` down the conn channel — then dies:
        // both ends it was handed close (`read_rx`/`write_tx` are the
        // stream's own ends pre-spawn, so dropping them is the conn
        // death, not bookkeeping noise).
        {
            let st = actor.tcp.get_mut(&handle).expect("flow state");
            st.spawned = true;
            st.write_tx
                .as_ref()
                .expect("pre-spawn flow still holds write_tx")
                .try_send(TcpIo::Shutdown)
                .expect("channel has room");
        }
        actor.service_tcp(); // consumes Shutdown → close() + graceful_close
        assert_eq!(
            actor.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::FinWait1
        );
        {
            let st = actor.tcp.get_mut(&handle).expect("flow state");
            drop(st.read_rx.take());
            drop(st.write_tx.take());
            // Two events parked behind the dead channel — `clear()`'s
            // half of the drain.
            st.pending_read
                .push_back(StreamEvent::Data(Bytes::from_static(b"x")));
            st.pending_read
                .push_back(StreamEvent::Data(Bytes::from_static(b"y")));
        }

        // Residue: tail data lands after the conn is gone.
        let data = seg_v4_data(
            client,
            target,
            40000,
            443,
            101,
            server_isn.wrapping_add(1),
            0x18,
            b"dead-conn residue",
        );
        feed_tcp(&mut actor, 0, &data);
        poll_once(&mut actor);
        assert!(
            actor.sockets.get::<tcp::Socket>(handle).recv_queue() > 0,
            "rx residue must be present for the drain to matter"
        );

        actor.service_tcp();

        let socket = actor.sockets.get::<tcp::Socket>(handle);
        assert_eq!(
            socket.recv_queue(),
            0,
            "the discard must empty the rx buffer so the window un-pins"
        );
        assert!(!socket.can_recv());
        assert!(actor.tcp[&handle].pending_read.is_empty());
        assert!(
            actor.tcp.contains_key(&handle),
            "a graceful close never aborts — the drain emptied rx, not teardown"
        );
    }

    /// The other half of the zombie: the route task died *after* its
    /// FIN went out (`graceful_close`), and the peer never closes back
    /// — it keeps streaming into the discard drain. `conn_gone` can
    /// never enqueue `Close` while `graceful_close` holds, and
    /// smoltcp's FinWait has no timeout of its own, so without
    /// [`TCP_ORPHAN_GRACE`] the socket outlives the whole session. The
    /// bound pins both sides of it: the socket must survive inside the
    /// grace (a real close may still complete) and must be aborted
    /// past it.
    #[tokio::test]
    async fn orphan_grace_aborts_socket_past_deadline() {
        let mut actor = test_actor();
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();
        let key: InnerTuple = (client.into(), 40000, target.into(), 443);

        feed_tcp(&mut actor, 0, &syn_v4(client, target, 40000, 443));
        poll_once(&mut actor);
        let handle = actor.tcp_by_tuple[&key];
        let syn_ack = actor
            .device
            .tx_queue
            .back()
            .expect("the accept emitted a SYN-ACK");
        let server_isn = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());

        // Handshake ACK → Established.
        let ack = seg_v4(
            client,
            target,
            40000,
            443,
            101,
            server_isn.wrapping_add(1),
            0x10,
        );
        feed_tcp(&mut actor, 0, &ack);
        poll_once(&mut actor);
        assert_eq!(
            actor.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );

        // Graceful half-close (FIN out), then the route task dies —
        // both ends it was handed close.
        {
            let st = actor.tcp.get_mut(&handle).expect("flow state");
            st.spawned = true;
            st.write_tx
                .as_ref()
                .expect("pre-spawn flow still holds write_tx")
                .try_send(TcpIo::Shutdown)
                .expect("channel has room");
        }
        actor.service_tcp(); // consumes Shutdown → close() + graceful_close
        assert_eq!(
            actor.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::FinWait1
        );
        {
            let st = actor.tcp.get_mut(&handle).expect("flow state");
            drop(st.read_rx.take());
            drop(st.write_tx.take());
        }

        // The first pass only arms the deadline: inside the grace the
        // socket must survive — a real close may still be completing.
        actor.service_tcp();
        assert!(actor.tcp.contains_key(&handle));
        assert!(actor.tcp[&handle].dead_since.is_some());

        // The peer keeps streaming instead of closing: the discard
        // drain eats its segment — the zombie window-stays-open case —
        // and the socket still survives while grace has not elapsed.
        let data = seg_v4_data(
            client,
            target,
            40000,
            443,
            101,
            server_isn.wrapping_add(1),
            0x18,
            b"peer that never closes",
        );
        feed_tcp(&mut actor, 0, &data);
        poll_once(&mut actor);
        actor.service_tcp();
        assert_eq!(actor.sockets.get::<tcp::Socket>(handle).recv_queue(), 0);
        assert!(
            actor.tcp.contains_key(&handle),
            "inside the grace the socket must not be torn down"
        );

        // Grace expiry → abort: the flow is reaped and the abort's RST
        // goes out on the next dispatch so the peer's stream stops.
        actor.tcp.get_mut(&handle).expect("flow state").dead_since =
            Some(Instant::now() - TCP_ORPHAN_GRACE);
        actor.service_tcp();
        assert!(
            !actor.tcp.contains_key(&handle),
            "the orphaned socket must be reaped once grace expires"
        );

        // The reap machinery finishes what the abort started — the
        // `pending_close` → `dead_dying` deferred-erase chain
        // `dead_flow_tuple_rebuild_survives_deferred_erase` pins: the
        // RST dispatches on this poll while the socket is buried, the
        // drain routes it through `tcp_dying`, and the next pass
        // erases the dying/tuple entries together.
        actor.poll_stack();
        actor.drain_device_tx();
        actor.poll_stack();
        assert!(
            !actor.tcp_dying.contains_key(&handle),
            "the reaped flow's dying entry must be erased"
        );
        assert!(
            !actor.tcp_by_tuple.contains_key(&key),
            "the reaped flow's tuple mapping must be erased"
        );
        assert!(
            actor.pending_close.is_empty() && actor.dead_dying.is_empty(),
            "the deferred close bookkeeping must drain with the socket"
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

    /// mac-perf regression (T1) — one service pass must emit more than a
    /// single TCP segment per flow. Before smoltcp 0.13, `Interface::
    /// poll` egressed at most one segment per socket per call, so the
    /// old single-poll pass capped a bulk flow at ~1 segment per
    /// inner-RTT wake (~285 KB/s measured on a real peer); 0.13's poll
    /// drains socket egress internally, which makes this the smoke pin
    /// that a queued multi-segment write lands in `tx_queue` as one
    /// burst inside a pass. The count is asserted mid-service —
    /// `drain_device_tx` always empties `tx_queue`, so between the
    /// poll and the drain is the only place it is visible. The
    /// poll-count budget itself is pinned in `meow-wgstack`'s
    /// `poll_burst_budgeted` tests.
    #[tokio::test]
    async fn service_pass_egresses_a_segment_burst() {
        let mut actor = test_actor();
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();
        let key: InnerTuple = (client.into(), 40000, target.into(), 443);

        // SYN → SYN-ACK: learn the accepted socket's ISN off the wire
        // (it is chosen from the interface's random seed).
        feed_tcp(&mut actor, 0, &syn_v4(client, target, 40000, 443));
        poll_once(&mut actor);
        let handle = actor.tcp_by_tuple[&key];
        let syn_ack = actor
            .device
            .tx_queue
            .back()
            .expect("the accept emitted a SYN-ACK");
        let server_isn = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());

        // The listener placeholder carries TCP_NODELAY onto the
        // accepted socket — same object, no accept queue — the
        // server-side twin of the pump's dial-time `set_nagle_enabled`.
        assert!(
            !actor.sockets.get::<tcp::Socket>(handle).nagle_enabled(),
            "accepted flow must inherit the listener's TCP_NODELAY"
        );

        // The handshake ACK (client's SYN was seq 100) → Established.
        let ack = seg_v4(
            client,
            target,
            40000,
            443,
            101,
            server_isn.wrapping_add(1),
            0x10,
        );
        feed_tcp(&mut actor, 0, &ack);
        poll_once(&mut actor);
        assert_eq!(
            actor.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );
        actor.device.tx_queue.clear(); // count data segments only

        // 32 KiB ≈ 61 segments at the 536-octet DEFAULT_MSS the
        // optionless test SYN negotiates — far past one segment and
        // inside the peer's 65535-octet window.
        actor
            .tcp
            .get_mut(&handle)
            .expect("flow registered")
            .out
            .push_back(TcpIo::Data(Bytes::from(vec![0xAB; 32 * 1024])));
        actor.service_tcp(); // the conn→socket drain fills the tx buffer
                             // The same poll step `service()` runs — the pin is on the
                             // service-pass poll loop, not on `poll_burst` the helper.
        actor.poll_stack();
        assert!(
            actor.device.tx_queue.len() >= 10,
            "one pass must burst a multi-segment write, got {}",
            actor.device.tx_queue.len()
        );
    }

    /// wgsrv-fix-1 §I-3 — a same-batch burst of same-dport SYNs each
    /// needs its own `Listen` placeholder: a smoltcp listener has no
    /// accept queue (one SYN leaves `Listen`), so a single shared
    /// placeholder RST'd every tail SYN of the burst.
    #[tokio::test]
    async fn concurrent_syns_same_dport_all_get_placeholder() {
        let mut actor = test_actor();
        actor.max_connections = 10;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();
        for sport in 40001..=40003 {
            let syn = syn_v4(client, target, sport, 443);
            feed_tcp(&mut actor, 0, &syn);
        }
        assert_eq!(actor.in_flight_syns.len(), 3);
        assert_eq!(
            actor.listen_pool_handles.len(),
            3,
            "one placeholder per same-batch in-flight SYN"
        );

        poll_once(&mut actor);
        assert_eq!(actor.tcp.len(), 3, "every SYN in the batch accepts");
        for sport in 40001..=40003 {
            let key: InnerTuple = (client.into(), sport, target.into(), 443);
            let h = actor.tcp_by_tuple[&key];
            assert_eq!(actor.tcp[&h].slot, 0);
        }
    }

    /// wgsrv-fix-1 §I-3 — a retransmitted SYN dedups in
    /// `in_flight_syns`, so the batch count asks for no second
    /// placeholder; a genuinely different sport does ask.
    #[tokio::test]
    async fn concurrent_syns_retransmit_no_extra_placeholder() {
        let mut actor = test_actor();
        actor.max_connections = 10;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();

        let syn = syn_v4(client, target, 40001, 443);
        feed_tcp(&mut actor, 0, &syn);
        feed_tcp(&mut actor, 0, &syn);
        assert_eq!(
            actor.in_flight_syns.len(),
            1,
            "a retransmitted SYN dedups by tuple"
        );
        assert_eq!(actor.listen_pool_handles.len(), 1);

        let other = syn_v4(client, target, 40002, 443);
        feed_tcp(&mut actor, 0, &other);
        assert_eq!(actor.in_flight_syns.len(), 2);
        assert_eq!(actor.listen_pool_handles.len(), 2);
    }

    /// M4 — a retransmitted SYN counts once toward the cap: the
    /// in-flight half of `max_connections` dedups by tuple.
    #[tokio::test]
    async fn in_flight_syn_retransmit_dedup() {
        let mut actor = test_actor();
        // Cap 3: the in-flight set counts the *current* SYN before
        // the gate, so each distinct tuple needs its own slot of
        // headroom to demand a listener.
        actor.max_connections = 3;
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
        actor.handle_inner(0, &pkt.clone().into(), false);
        assert!(actor.udp_flows.is_empty(), "udp:false must not open a flow");

        // Same packet with udp:true opens the flow — polarity pin.
        actor.udp_enabled = true;
        actor.handle_inner(0, &pkt.into(), false);
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
        // WARP-style stamp over bytes 1..4 — the actor must erase it
        // before the demux's type/index check.
        init[1..4].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        let n = init.len();
        actor.recv_buf[..n].copy_from_slice(init);
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

    // ── flush_outbox / scratch-pool pins ─────────────────────────

    /// Arm the endpoint's cached *writable* readiness through the only
    /// public async call `BatchEndpoint` forwards — `recv_from` for
    /// this unconnected endpoint. The poll never resolves (nothing
    /// ever arrives), but while it parks the reactor reports the
    /// socket's ready bits and `try_send_to` stops short-circuiting
    /// `WouldBlock` so it reaches the real syscall.
    async fn arm_writable(endpoint: &BatchEndpoint) {
        let mut buf = [0u8; 16];
        let _ =
            tokio::time::timeout(Duration::from_millis(250), endpoint.recv_from(&mut buf)).await;
    }

    /// Drain `expected` datagrams off a receiver, in wire order.
    /// Loopback delivery is not synchronous with the sender's `send` —
    /// on Linux each datagram crosses a softirq backlog first, so keep
    /// polling until the count is met or the deadline passes.
    async fn drain_received(receiver: &tokio::net::UdpSocket, expected: usize) -> Vec<Vec<u8>> {
        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut buf = vec![0u8; 65536];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while got.len() < expected {
            match tokio::time::timeout_at(deadline, receiver.readable()).await {
                Ok(r) => r.expect("receiver readable"),
                Err(_) => break,
            }
            while let Ok(n) = receiver.try_recv(&mut buf) {
                got.push(buf[..n].to_vec());
            }
        }
        got
    }

    /// F1 regression pin — a `send_batch_to` that stops short replays
    /// the boundary datagram, sees `WouldBlock`, and must requeue
    /// `[boundary, successors…]` *ahead* of whatever the outbox already
    /// held, losing nothing (per-destination addressing preserved).
    ///
    /// Deterministic boundary without timing tricks: the staged batch
    /// carries one oversized datagram at `BOUNDARY`, so the kernel
    /// stops the batch exactly there — `sendmmsg`/`sendmsg_x` report
    /// the short count on the batch-syscall platforms, the fallback
    /// `try_send_to` loop stops at its first error elsewhere. The
    /// `WouldBlock` verdict then comes
    /// from tokio's *cold* readiness gate: this `current_thread` test
    /// awaits nothing before the first flush, so the driver never
    /// polled the fresh socket and the replay `try_send_to` short-
    /// circuits `WouldBlock` without reaching the kernel — on every
    /// platform. (A small `SO_SNDBUF` cannot produce the short batch
    /// instead: transmitted UDP skbs orphan their wmem charge at xmit,
    /// so a loopback send queue never fills.)
    ///
    /// The second flush runs with the gate armed: the oversized
    /// boundary now reaches the kernel, takes the `EMSGSIZE` drop arm
    /// (pinned separately below), and every other datagram lands on
    /// the wire in queue order.
    #[tokio::test(flavor = "current_thread")]
    async fn flush_outbox_wouldblock_requeue_preserves_order() {
        let receiver_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver_std
            .set_nonblocking(true)
            .expect("receiver nonblocking");
        let peer = receiver_std.local_addr().expect("receiver addr");
        let mut actor = actor_with_spec(WgListenerSpec {
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
        });

        // A full staged batch (tags 0..BUDGET, oversized at BOUNDARY)
        // ahead of two older queued datagrams (tags 0xF0/0xF1) the
        // outbox already held — all addressed to the same peer. Each
        // Vec carries `scratch_len` capacity so `return_scratch`
        // pools it; the tag byte makes content order observable.
        const STAGED: usize = WIRE_DRAIN_BUDGET;
        const BOUNDARY: usize = 3;
        const BOUNDARY_TAG: u8 = 0xEE;
        const OLD: [u8; 2] = [0xF0, 0xF1];
        let tag_of = |i: usize| {
            if i == BOUNDARY {
                BOUNDARY_TAG
            } else {
                i as u8
            }
        };
        let scratch_len = actor.scratch_len;
        let tag = move |t: u8| {
            let mut v = Vec::with_capacity(scratch_len);
            v.push(t);
            v
        };
        for i in 0..STAGED {
            let v = if i == BOUNDARY {
                vec![BOUNDARY_TAG; 70_000] // > 65 507 max UDP payload; first byte is the tag
            } else {
                tag(tag_of(i))
            };
            actor.outbox.push_back((peer, v));
        }
        for t in OLD {
            actor.outbox.push_back((peer, tag(t)));
        }

        actor.flush_outbox();

        // Path proof: with the batched syscalls (`sendmmsg`/`sendmsg_x`)
        // the batch genuinely stopped at the oversized index inside
        // the kernel; on the fallback the cold gate stopped the
        // `try_send_to` loop at index 0.
        let sent = STAGED + OLD.len() - actor.outbox.len();
        if BatchEndpoint::BATCHED_SYSCALLS {
            assert_eq!(
                sent, BOUNDARY,
                "the batched send stops at the EMSGSIZE index"
            );
        } else {
            assert_eq!(sent, 0, "cold readiness stops the fallback loop at index 0");
        }

        // The pre-F1 bug pushed the boundary first, then its
        // successors ahead of it — [s1..s63, b, old]. The contract is
        // [b, s1..s63, old]: a strictly consecutive tag run at the
        // front (staged[sent] onward), then the old tail.
        let expected: Vec<u8> = (sent..STAGED).map(tag_of).chain(OLD).collect();
        let got: Vec<u8> = actor.outbox.iter().map(|(_, v)| v[0]).collect();
        assert_eq!(
            got, expected,
            "requeue must keep the boundary datagram ahead of its successors, ahead of the old tail"
        );
        assert!(
            actor.outbox.iter().all(|(a, _)| *a == peer),
            "per-datagram destinations survive the requeue"
        );

        // The successors stay behind the boundary on the wire too:
        // arm the gate, flush once more, and the receiver must see
        // every datagram in queue order — the earlier partial send
        // first, the oversized boundary dropped by the error arm.
        arm_writable(&actor.endpoint).await;
        actor.flush_outbox();
        assert!(actor.outbox.is_empty(), "armed socket drains the requeue");

        let receiver = tokio::net::UdpSocket::from_std(receiver_std).expect("tokio receiver");
        let got = drain_received(&receiver, STAGED + OLD.len() - 1).await;
        let expected: Vec<Vec<u8>> = (0..STAGED)
            .filter(|&i| i != BOUNDARY)
            .map(|i| vec![tag_of(i)])
            .chain(OLD.iter().map(|&t| vec![t]))
            .collect();
        assert_eq!(
            got, expected,
            "wire order must match queue order across the requeue"
        );
    }

    /// The other boundary arm: a datagram whose replay reports a real
    /// errno (not `WouldBlock`) is dropped — exactly that one — while
    /// the rest of the staged batch continues, and every spent buffer
    /// (sent or dropped) returns to the scratch pool. The trigger is
    /// an oversized datagram: `send*` answers `EMSGSIZE` determinist-
    /// ically on every platform.
    #[tokio::test]
    async fn flush_outbox_boundary_error_drops_only_that_datagram() {
        let receiver_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver_std
            .set_nonblocking(true)
            .expect("receiver nonblocking");
        let peer = receiver_std.local_addr().expect("receiver addr");
        let mut actor = test_actor();

        // Arm the reactor readiness: `try_send_to` must reach the
        // kernel for EMSGSIZE rather than WouldBlock-ing on a cold
        // gate.
        arm_writable(&actor.endpoint).await;

        let oversized = vec![0xEE; 70_000]; // > 65 507 max UDP payload
        let scratch_len = actor.scratch_len;
        let tag = move |t: u8| {
            let mut v = Vec::with_capacity(scratch_len);
            v.push(t);
            v
        };
        actor.outbox.push_back((peer, tag(0)));
        actor.outbox.push_back((peer, tag(1)));
        actor.outbox.push_back((peer, oversized));
        actor.outbox.push_back((peer, tag(3)));

        actor.flush_outbox();

        assert!(actor.outbox.is_empty(), "batch completes past the error");
        assert_eq!(
            actor.scratch_pool.len(),
            4,
            "sent and dropped buffers all return to the scratch pool"
        );
        let receiver = tokio::net::UdpSocket::from_std(receiver_std).expect("tokio receiver");
        let got = drain_received(&receiver, 3).await;
        assert_eq!(
            got,
            vec![vec![0u8], vec![1], vec![3]],
            "exactly the failing datagram is dropped; successors continue in order"
        );
    }

    /// `return_scratch` is a bounded, full-size-only recycler: an
    /// undersized buffer (capacity below `scratch_len`) frees instead
    /// of pooling, and residency never passes `SCRATCH_POOL_CAP`.
    #[tokio::test]
    async fn return_scratch_rejects_undersize_and_caps_pool() {
        let mut actor = test_actor();

        let undersized = Vec::with_capacity(actor.scratch_len - 1);
        actor.return_scratch(undersized);
        assert!(
            actor.scratch_pool.is_empty(),
            "capacity < scratch_len must not pool — a checkout would realloc anyway"
        );

        actor.return_scratch(Vec::with_capacity(actor.scratch_len));
        assert_eq!(actor.scratch_pool.len(), 1, "full-size buffer pools");

        for _ in 0..SCRATCH_POOL_CAP + 1 {
            actor.return_scratch(Vec::with_capacity(actor.scratch_len));
        }
        assert_eq!(
            actor.scratch_pool.len(),
            SCRATCH_POOL_CAP,
            "pool residency is capped — past it the Vec frees"
        );
    }

    /// PATCH(18): `drain_wire`'s parallel path end to end — a real
    /// handshake over the actor's own socket, then a DATA burst run
    /// through `classify_datagram` → `CryptoPool` → `handle_decrypted_data`
    /// + `admit_data`. Each burst's first datagram rides `recv_from` →
    /// `demux_one` — the production select arm's shape, which also arms
    /// the reactor readiness the `try_*` calls gate on — and the rest
    /// batch through the crypto pool. Order is asserted off `rx_queue`:
    /// every admitted inner TCP segment lands there in wire order.
    #[tokio::test(flavor = "current_thread")]
    async fn drain_wire_parallel_decrypts_in_wire_order() {
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
        let actor_addr: SocketAddr = format!("127.0.0.1:{}", actor.bound_port).parse().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("client socket");
        let client_addr = sender.local_addr().unwrap();
        let mut work = vec![0u8; 4096];

        /// The production receive arm: async `recv_from` for the
        /// datagram that woke the reactor (feeds `demux_one` serially
        /// and arms the `try_*` readiness), then `drain_wire` for
        /// whatever else is already queued.
        async fn feed_pending(actor: &mut WgActor) {
            let (n, src) = actor
                .endpoint
                .recv_from(&mut actor.recv_buf)
                .await
                .expect("datagram ready");
            actor.demux_one(src, n);
            actor.drain_wire();
        }

        // A real handshake across the socket: init → response → the
        // client's keepalive → established.
        let init = {
            let TunnResult::WriteToNetwork(b) =
                client.format_handshake_initiation(&mut work, false)
            else {
                panic!("initiation formats");
            };
            b.to_vec()
        };
        sender.send_to(&init, actor_addr).expect("send init");
        feed_pending(&mut actor).await;
        let (resp_addr, resp) = actor
            .outbox
            .pop_front()
            .expect("init produces a handshake response");
        assert_eq!(resp_addr, client_addr);
        let keepalive = {
            let TunnResult::WriteToNetwork(b) =
                client.decapsulate(Some(client_addr.ip()), &resp, &mut work)
            else {
                panic!("client consumes the response");
            };
            b.to_vec()
        };
        sender
            .send_to(&keepalive, actor_addr)
            .expect("send keepalive");
        feed_pending(&mut actor).await;
        assert!(actor.outbox.is_empty(), "the keepalive answers nothing");

        // Eight DATA datagrams — inner TCP segments whose seq and last
        // payload byte mark wire order (`seg_v4_data` checksums for
        // real, which smoltcp requires).
        const N: usize = 8;
        let client_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target_ip: Ipv4Addr = "203.0.113.9".parse().unwrap();
        for i in 0..N {
            let inner = seg_v4_data(
                client_ip,
                target_ip,
                40000,
                443,
                1000 + i as u32,
                0,
                0x18,
                &[i as u8],
            );
            let wire = {
                let TunnResult::WriteToNetwork(b) = client.encapsulate(&inner, &mut work) else {
                    panic!("encapsulate yields wire data");
                };
                b.to_vec()
            };
            sender.send_to(&wire, actor_addr).expect("send data");
        }
        feed_pending(&mut actor).await;

        // Every admitted segment reached smoltcp in wire order — the
        // first through `demux_one`'s serial path, the rest through the
        // pool pass.
        assert_eq!(
            actor.device.rx_queue.len(),
            N,
            "every DATA datagram produced an inner packet"
        );
        for (i, pkt) in actor.device.rx_queue.iter().enumerate() {
            assert_eq!(
                u32::from_be_bytes(pkt[24..28].try_into().unwrap()),
                1000 + i as u32,
                "rx_queue order must match wire order"
            );
            assert_eq!(pkt.last(), Some(&(i as u8)));
        }
        // An ACL-admitted inner moved the peer's endpoint to the
        // datagram source — the roam gate still runs post-decrypt.
        assert_eq!(actor.table.peers()[0].endpoint, Some(client_addr));
        // Consumed slots were back-filled at full size — the next
        // drain's `try_recv_from` still sees the whole window.
        let full = actor.scratch_len;
        assert!(
            actor.rx_slots.iter().all(|s| s.len() == full),
            "every rx_slot returns at full size"
        );
    }

    /// PATCH(19): `drain_device_tx`'s parallel arm end to end — the
    /// listener-side twin of the pump test. A real handshake over the
    /// actor's own socket gives the peer a session (the endpoint is
    /// armed directly, the slot roaming would teach it); eight inner
    /// TCP replies routed through `rst_hint` flatten into one
    /// `TxCryptoJob` batch past the `n <= 2` inline cutoff. Every
    /// outbox datagram must decrypt at the client back to its inner
    /// *in emit order* — job order = counter order = wire order — and
    /// every drained `tx_queue` buffer returns to `tx_pool`.
    #[tokio::test(flavor = "current_thread")]
    async fn drain_device_tx_parallel_seals_in_job_order() {
        use meow_wireguard::x25519;

        let server_secret = x25519::StaticSecret::from([0x6E; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let client_secret = x25519::StaticSecret::from([0xA1; 32]);
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
        let actor_addr: SocketAddr = format!("127.0.0.1:{}", actor.bound_port).parse().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("client socket");
        let client_addr = sender.local_addr().unwrap();
        let mut work = vec![0u8; 4096];

        /// The production receive arm — same shape as the RX test's:
        /// async `recv_from` for the datagram that woke the reactor,
        /// then `drain_wire` for whatever else is queued.
        async fn feed_pending(actor: &mut WgActor) {
            let (n, src) = actor
                .endpoint
                .recv_from(&mut actor.recv_buf)
                .await
                .expect("datagram ready");
            actor.demux_one(src, n);
            actor.drain_wire();
        }

        // The real handshake — init → response → keepalive —
        // establishes the peer's responder session on the actor.
        let init = {
            let TunnResult::WriteToNetwork(b) =
                client.format_handshake_initiation(&mut work, false)
            else {
                panic!("initiation formats");
            };
            b.to_vec()
        };
        sender.send_to(&init, actor_addr).expect("send init");
        feed_pending(&mut actor).await;
        let (resp_addr, resp) = actor
            .outbox
            .pop_front()
            .expect("init produces a handshake response");
        assert_eq!(resp_addr, client_addr);
        let keepalive = {
            let TunnResult::WriteToNetwork(b) =
                client.decapsulate(Some(client_addr.ip()), &resp, &mut work)
            else {
                panic!("client consumes the response");
            };
            b.to_vec()
        };
        sender
            .send_to(&keepalive, actor_addr)
            .expect("send keepalive");
        feed_pending(&mut actor).await;
        assert!(actor.outbox.is_empty(), "the keepalive answers nothing");

        // The peer's endpoint — armed the way an ACL-admitted roam
        // would leave it (the drain's post-pass must resolve it
        // per job).
        actor.table.peers_mut()[0].endpoint = Some(client_addr);

        // Eight inner replies `443 → 40000` routed to peer 0 through
        // `rst_hint` — the drain's unmatched-tuple fallback. The last
        // payload byte marks queue position.
        let client_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target_ip: Ipv4Addr = "203.0.113.9".parse().unwrap();
        actor
            .rst_hint
            .insert((client_ip.into(), 40000, target_ip.into(), 443), 0);
        const N: usize = 8;
        let mut inners = Vec::new();
        for i in 0..N {
            let inner = seg_v4_data(
                target_ip,
                client_ip,
                443,
                40000,
                7000 + i as u32,
                1000,
                0x18,
                &[i as u8],
            );
            inners.push(inner.clone());
            actor.device.tx_queue.push_back(inner);
        }
        actor.drain_device_tx();

        assert_eq!(actor.outbox.len(), N, "every sealed job emitted a datagram");
        assert_eq!(
            actor.device.tx_pool.len(),
            N,
            "every drained inner returned to tx_pool"
        );

        let mut prev: Option<u64> = None;
        for (i, (addr, datagram)) in actor.outbox.iter().enumerate() {
            assert_eq!(*addr, client_addr);
            assert_eq!(
                u32::from_le_bytes(datagram[0..4].try_into().unwrap()),
                4,
                "datagram {i} is WG data"
            );
            let counter = u64::from_le_bytes(datagram[8..16].try_into().unwrap());
            if let Some(p) = prev {
                assert_eq!(counter, p + 1, "counters stay consecutive in emit order");
            }
            prev = Some(counter);
            match client.decapsulate(Some(client_addr.ip()), datagram, &mut work) {
                TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                    assert_eq!(&b[..], &inners[i][..], "datagram {i} decrypts to inner {i}");
                }
                other => panic!("client must decrypt datagram {i}, got {other:?}"),
            }
        }
    }

    /// PATCH(19): `drain_inject`'s parallel arm end to end — the
    /// flow-reply twin of the `tx_queue` drain test above. A real
    /// handshake gives peer 0 a session; eight `(slot, Bytes)` inject
    /// items past the `n <= 2` inline cutoff flatten into one
    /// `TxCryptoJob` batch whose per-item `reserve_tx_counters(1)`
    /// keeps counters consecutive in queue order. Every outbox
    /// datagram must decrypt at the client back to its reply *in emit
    /// order*, and nothing returns to `tx_pool` — inject inners are
    /// `Bytes` copies that drop with their job (`pool_inner: false`).
    #[tokio::test(flavor = "current_thread")]
    async fn drain_inject_parallel_seals_in_job_order() {
        use meow_wireguard::x25519;

        let server_secret = x25519::StaticSecret::from([0x7E; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let client_secret = x25519::StaticSecret::from([0xB1; 32]);
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
        let actor_addr: SocketAddr = format!("127.0.0.1:{}", actor.bound_port).parse().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("client socket");
        let client_addr = sender.local_addr().unwrap();
        let mut work = vec![0u8; 4096];

        /// The production receive arm — same shape as the sibling
        /// test's: async `recv_from` for the datagram that woke the
        /// reactor, then `drain_wire` for whatever else is queued.
        async fn feed_pending(actor: &mut WgActor) {
            let (n, src) = actor
                .endpoint
                .recv_from(&mut actor.recv_buf)
                .await
                .expect("datagram ready");
            actor.demux_one(src, n);
            actor.drain_wire();
        }

        // The real handshake — init → response → keepalive — arms peer
        // 0's responder session, which `drain_inject`'s Phase-A handle
        // cache then resolves per slot.
        let init = {
            let TunnResult::WriteToNetwork(b) =
                client.format_handshake_initiation(&mut work, false)
            else {
                panic!("initiation formats");
            };
            b.to_vec()
        };
        sender.send_to(&init, actor_addr).expect("send init");
        feed_pending(&mut actor).await;
        let (resp_addr, resp) = actor
            .outbox
            .pop_front()
            .expect("init produces a handshake response");
        assert_eq!(resp_addr, client_addr);
        let keepalive = {
            let TunnResult::WriteToNetwork(b) =
                client.decapsulate(Some(client_addr.ip()), &resp, &mut work)
            else {
                panic!("client consumes the response");
            };
            b.to_vec()
        };
        sender
            .send_to(&keepalive, actor_addr)
            .expect("send keepalive");
        feed_pending(&mut actor).await;
        assert!(actor.outbox.is_empty(), "the keepalive answers nothing");

        // The peer's endpoint — the post-pass resolves it per job.
        actor.table.peers_mut()[0].endpoint = Some(client_addr);

        // Eight flow-task replies queue on the inject channel — past
        // the pool's inline cutoff, so the seals ride real workers.
        // The last payload byte marks queue position.
        const N: usize = 8;
        let client_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target_ip: Ipv4Addr = "203.0.113.9".parse().unwrap();
        let mut inners = Vec::new();
        for i in 0..N {
            let inner = seg_v4_data(
                target_ip,
                client_ip,
                443,
                40000,
                9000 + i as u32,
                1000,
                0x18,
                &[i as u8],
            );
            inners.push(inner.clone());
            actor
                .inject_tx
                .try_send((0, Bytes::from(inner)))
                .expect("inject queue has room");
        }
        actor.drain_inject();

        assert_eq!(
            actor.outbox.len(),
            N,
            "every sealed inject job emitted a datagram"
        );
        assert!(
            actor.device.tx_pool.is_empty(),
            "inject inners are copies — they drop with the job, never pool"
        );

        let mut prev: Option<u64> = None;
        for (i, (addr, datagram)) in actor.outbox.iter().enumerate() {
            assert_eq!(*addr, client_addr);
            assert_eq!(
                u32::from_le_bytes(datagram[0..4].try_into().unwrap()),
                4,
                "datagram {i} is WG data"
            );
            let counter = u64::from_le_bytes(datagram[8..16].try_into().unwrap());
            if let Some(p) = prev {
                assert_eq!(counter, p + 1, "counters stay consecutive in emit order");
            }
            prev = Some(counter);
            match client.decapsulate(Some(client_addr.ip()), datagram, &mut work) {
                TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                    assert_eq!(&b[..], &inners[i][..], "datagram {i} decrypts to inner {i}");
                }
                other => panic!("client must decrypt datagram {i}, got {other:?}"),
            }
        }
    }
}
