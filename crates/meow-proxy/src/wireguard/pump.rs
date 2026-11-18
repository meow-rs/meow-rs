//! The WireGuard pump: a single-actor loop that owns the boringtun `Tunn`
//! noise session, the smoltcp `Interface`/`SocketSet`, the channel-backed
//! `Device` between them, and the endpoint UDP socket to the WG peer.
//!
//! Spec §3/§4.5: smoltcp's `Interface`/`SocketSet` are confined to one
//! actor *task* on the shared runtime (perf-7 P7-2). The dedicated
//! `std::thread` + current-thread runtime this replaced was a hysteria2/
//! quiche precedent — `quiche::Connection` holds a `*mut` FFI handle and
//! is `!Send`; smoltcp 0.13's types are pure-Rust `Send`, so the thread
//! bought nothing but an OS futex round-trip on every `Notify` nudge,
//! which is the wake path's hot cost. `WgPump: Send` is proven at compile
//! time below. Everything cross-task still travels over tokio mpsc
//! channels: [`ActorMsg`] for dial/bind/shutdown, per-conn channels for
//! stream/datagram payload, and a shared `Notify` a conn pulses after
//! enqueueing so a sleeping pump picks the item up at once — now an
//! in-runtime wake instead of a context switch.
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
    note_count, note_drop, reset_scratch, udp_dst_port, ChannelDevice, DropStats, Endpoint,
    StreamEvent, TcpIo, WgStream, CHAINED_TCP_SOCK_BUF, POLL_BURST, POLL_TX_BYTES_BUDGET,
    TCP_READ_QUEUE, TCP_SOCKET_BUF, TCP_WRITE_QUEUE, TX_DRAIN_BUDGET, WG_TIMER_INTERVAL,
    WIRE_DRAIN_BUDGET,
};
use meow_wireguard::noise::Packet;
use meow_wireguard::{
    x25519, CryptoJob, CryptoPool, Tunn, TunnResult, TxCryptoJob, WireClass, WireGuardError,
};
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
/// smoltcp UDP packet buffer: packet slots and payload arena. Raised
/// 64/64 KiB → 256/256 KiB with [`WIRE_DRAIN_BUDGET`] (wg-perf): a
/// 64-slot buffer dropped every wire batch that out-paced the conn
/// drain past 64 datagrams; 256 covers a full drain's inner output.
const UDP_SOCKET_PACKETS: usize = 256;
const UDP_SOCKET_BYTES: usize = 262144;

/// Retained crypto-scratch buffers. Demand is a handful of live dsts
/// between `flush_outbox` passes, so the cap only bounds the memory a
/// send-side burst leaves behind — past it the Vecs free, exactly what
/// happened to them pre-pool.
const SCRATCH_POOL_CAP: usize = 128;

/// Read chunk handed to `socket.recv`. One 64 KiB item drains through a
/// relay's bulk-tier 32 KiB ReadBuf in ~2 channel hops — a quarter of the
/// hop count 16 KiB items needed — and a `TCP_READ_QUEUE` of them still
/// covers the 4 MiB rx window, without letting one socket monopolise a
/// service pass.
const TCP_READ_CHUNK: usize = 65536;
// A full read queue must cover the advertised rx window — the layering
// `tcp_read_chunk_covers_rx_window` also pins, here at compile time.
const _: () = assert!(TCP_READ_QUEUE * TCP_READ_CHUNK >= TCP_SOCKET_BUF);

/// Idle `select!` sleep when smoltcp reports no `poll_delay`: inbound WG
/// datagrams, mailbox messages and conn wakes all break the sleep early, so
/// this only bounds the smoltcp housekeeping cadence.
const IDLE_SLEEP: Duration = Duration::from_millis(10);

/// Per-pass livelock bound on `run`'s RX-flood `drain_wire` loop — not
/// the drain's everyday exit (that is a short batch reporting the
/// endpoint quiet). A wire datagram lost to a full kernel buffer is an
/// unrecoverable inner-TCP hole, so RX must always outpace TX: every TX
/// backlog form is lossless, a lost RX datagram is not. The cap only
/// guarantees the pass eventually reaches mailbox/service/TX work; the
/// next pass re-enters the flood loop immediately.
const RX_PASS_CAP: usize = 8 * WIRE_DRAIN_BUDGET;

/// D3 — the longest any synchronous stretch may run without servicing
/// the wire-RX bridge channel. Once the channel is full the bridge
/// parks and arrivals pile into `SO_RCVBUF`: ~8 MiB (macOS) ÷ ~1.5 GB/s
/// loopback wire rate ≈ 5 ms of slack; half a millisecond keeps ~10×
/// margin. Every long loop — socket service, the poll burst, the
/// mailbox drain — calls [`WgPump::rx_heartbeat`] between iterations;
/// the check itself is one `Instant::now`.
const RX_SERVICE_INTERVAL: Duration = Duration::from_micros(500);

/// Worker-fairness bound on a *task* pump (perf-7 P7-2): one service pass
/// is synchronous start to finish, so a flow moving this much payload in
/// rolling accumulation yields the tokio worker once — sibling tasks
/// (other adapters' pumps on the same worker among them) get scheduled.
/// The counter rolls across passes, not per-pass: a steady 900 KB/pass
/// flow still yields every ~1.2 passes rather than never. Every payload
/// path counts — TCP and UDP socket service in both directions, inbound
/// wire datagrams, sealed inner packets, flushed outbox datagrams — so
/// no unbounded non-parking workload skips the yield.
const SERVICE_YIELD_THRESHOLD: usize = 1024 * 1024;

/// The byte counter's low-volume backstop: a flood of *small* datagrams
/// moves little payload per pass yet still costs real work per pass
/// (verify, crypto, bookkeeping), so a byte-only threshold would let a
/// sustained small-packet flood pin a shared worker far longer than
/// intended. Every pass counts — parked or not — which is coarser than
/// "non-parking passes" but strictly stronger on the bounding side.
const SERVICE_YIELD_PASS_LIMIT: usize = 32;

/// Spec §3.7: a WG handshake that has not completed within 10 s fails all
/// dials still waiting on it.
const HANDSHAKE_DIAL_LIMIT: Duration = Duration::from_secs(10);
/// Once the WG session is up, a TCP connect may wait out the adapter's
/// outer 30 s dial deadline (spec §4.2); the pump gives up one step earlier
/// so the reply error beats the caller's timeout.
const TCP_CONNECT_LIMIT: Duration = Duration::from_secs(25);

/// Once a socket's owning conn is gone on both channel halves the flow has
/// no consumer left. `conn_gone` can never enqueue `Close` once
/// `graceful_close` holds — the FIN is already out and `TcpIo::Close` is
/// deliberately suppressed so the peer's tail bytes survive — and a peer
/// that never closes back pins the socket forever: smoltcp has no
/// FinWait-2 timeout and `discard_socket_rx` keeps the receive window
/// open, so the peer's stream keeps arriving to /dev/null. The grace
/// covers the real teardown (FIN handshake, `out` flush at socket pace);
/// a peer still open past it was never going to close.
const TCP_ORPHAN_GRACE: Duration = Duration::from_secs(2);

/// Floor between desync-triggered handshake initiations — WG's own
/// REKEY_TIMEOUT (the wireguard paper's 5 s initiation-retry floor,
/// `timers.rs` in meow-wireguard; the constant is crate-private, so it
/// is mirrored here). `format_handshake_initiation(_, false)` dedups
/// only while a handshake is in flight: once a response lands the
/// dedup is gone, and a flood of data datagrams with a forged
/// `receiver_idx` — DATA carries no mac1, so `NoCurrentSession`/
/// `WrongIndex` are both forgeable at line rate — would mint a fresh
/// initiation every RTT (~200/s on a 5 ms path), each reply spending
/// the responder's 2×DH+2×AEAD. The floor is independent of handshake
/// state so it holds across completions: a genuine epoch desync still
/// heals on the first error (~1 RTT) while a forged flood is clamped
/// to 0.2 initiations/s.
const DESYNC_KICK_INTERVAL: Duration = Duration::from_secs(5);

/// Ephemeral port range for tunnel-local sockets; smoltcp does not allocate
/// ephemeral ports for us.
const EPHEMERAL_PORT_BASE: u16 = 49152;
const EPHEMERAL_PORT_SPAN: u16 = 16384;

/// ITEM C1 snapshot cadence for [`WgPump::log_socket_stats`]: 2 s is
/// fine enough to see a 1 s min-RTO stall as consecutive unmoved
/// `send_queue` samples without spamming the DEBUG stream.
const STATS_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(2);

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
    /// Armed when both conn channel halves report the flow task gone;
    /// the [`TCP_ORPHAN_GRACE`] deadline after which the socket is
    /// aborted regardless of `graceful_close` — the bound that keeps a
    /// peer that never closes back from pinning the socket forever.
    dead_since: Option<StdInstant>,
    /// ITEM C1 stall detector: `send_queue()` at the last snapshot and
    /// when it last moved. smoltcp 0.13 exposes no retransmit/RTO
    /// counter, so an unmoved nonzero `send_queue` across snapshot
    /// intervals is the observable 1 s min-RTO signature.
    snap_txq: usize,
    snap_txq_at: StdInstant,
}

struct UdpState {
    read_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    write_rx: mpsc::Receiver<UdpIo>,
    /// Datagrams stalled on `SendError::BufferFull`; UDP items are atomic,
    /// so each entry is a whole datagram.
    out: VecDeque<(Bytes, SocketAddr)>,
    local: SocketAddr,
    /// ITEM C1 offered-vs-dequeued bookkeeping — smoltcp's
    /// `udp::Socket::process` drops on a full rx buffer silently (no
    /// error upstack), so `account_udp_drops` derives the count:
    /// `rx_offered` (pre-poll scan) − `rx_dequeued` (drain) −
    /// `rx_sockbuf_dropped` (confirmed) = datagrams in flight or lost.
    rx_offered: u64,
    rx_dequeued: u64,
    /// The `rx_sockbuf_dropped` subset confirmed for this socket.
    rx_sockbuf_dropped: u64,
}

/// The smoltcp/boringtun actor. Constructed by [`spawn_pump`] *before*
/// the `tokio::spawn` so init failures reach the caller's endpoint-
/// fallback loop; the `Send` proof below is what makes the move into
/// the task legal (spec §4.3's "nothing smoltcp touches crosses a task
/// boundary" predates `Send` being proven).
struct WgPump {
    name: String,
    tunn: Tunn,
    iface: Interface,
    device: ChannelDevice,
    sockets: SocketSet<'static>,
    /// The connected peer socket (a [`BatchEndpoint`] wrapped for
    /// batched `sendmmsg`/`recvmmsg` I/O on Linux and
    /// `sendmsg_x`/`recvmsg_x` on macOS, a `try_*` loop elsewhere) or —
    /// on a `dialer-proxy` chain — the channel pair bridged to the front
    /// hop's `ProxyPacketConn` (issue #899). Same method surface either
    /// way: enum dispatch, no trait object on the drain/flush path.
    endpoint: Endpoint,
    endpoint_addr: SocketAddr,
    rx: mpsc::Receiver<ActorMsg>,
    /// Conn → pump work-available signal, shared by every stream and
    /// packet conn. `Notify` pulse-merges: nudges while the pump is
    /// mid-pass collapse to one stored permit — the same "one pending
    /// wake" bound the bounded mpsc channel it replaced approximated.
    wake: Arc<tokio::sync::Notify>,
    tcp: HashMap<SocketHandle, TcpState>,
    udp: HashMap<SocketHandle, UdpState>,
    used_ports: HashSet<u16>,
    next_port: u16,
    /// WG datagrams to write to the endpoint socket; drained by `try_send`
    /// so a stuffed kernel buffer only ever delays, never wedges the actor.
    /// Entries are the crypto dst buffers themselves — a `Tunn` call
    /// writes straight into one, gets `truncate`d to the datagram, and
    /// moves here with no copy; `flush_outbox` returns spent buffers to
    /// `scratch_pool`.
    outbox: VecDeque<Vec<u8>>,
    reserved: Option<[u8; 3]>,
    /// Tunnel source addresses for `UdpMetadata.local_address`, per family.
    src_v4: Option<IpAddress>,
    src_v6: Option<IpAddress>,
    recv_buf: Vec<u8>,
    /// The batch drain's receive slots: [`WIRE_DRAIN_BUDGET`] independent
    /// `buf_size`-capacity `Vec`s, persistent across passes so a quiet
    /// loop pays nothing. `recv_batch` advertises each slot's whole
    /// capacity as the window and rewrites a filled slot's len to its
    /// datagram — capacity, never len, is what carries over. A slot a
    /// DATA packet consumed leaves inside `rx_queue` as
    /// `Bytes::from(Vec)` — the refcounted slice keeps the Vec's whole
    /// ~`buf_size` allocation (~2 KiB), not just the datagram's span:
    /// queue residency stays bounded in count, at a slightly larger
    /// per-packet footprint — the price of the zero-copy handoff.
    rx_slots: Vec<Vec<u8>>,
    /// Recycled dst buffers for `Tunn::{encapsulate,decapsulate,
    /// update_timers,...}` — replaces the single fixed `work` scratch:
    /// a produced wire datagram keeps its buffer for `outbox` instead
    /// of being copied out of a shared one. Bounded by
    /// [`SCRATCH_POOL_CAP`] (plus whatever the outbox holds in flight).
    scratch_pool: VecDeque<Vec<u8>>,
    /// The size a checked-out scratch is reset to — the old fixed
    /// `work` buffer's size (wire MTU + headroom).
    scratch_len: usize,
    udp_scratch: Vec<u8>,
    last_timer: StdInstant,
    /// When the last desync-triggered initiation was emitted — the
    /// [`DESYNC_KICK_INTERVAL`] floor's stamp, `None` until the first
    /// kick. Set only on `WriteToNetwork`: a kick suppressed by an
    /// in-flight handshake must not consume budget it never spent, or
    /// a flood arriving inside one handshake would push the floor's
    /// zero point past that handshake's completion.
    last_desync_kick: Option<StdInstant>,
    /// Payload bytes the last service passes moved through the pump —
    /// `send_slice` accepts and `recv` payloads on the socket paths,
    /// inbound wire datagrams, sealed inner packets, flushed outbox
    /// datagrams — accumulated rolling across passes. The `run()` loop
    /// yields the worker once it crosses [`SERVICE_YIELD_THRESHOLD`],
    /// so a saturated flow cannot pin a shared tokio worker through
    /// back-to-back synchronous passes.
    last_service_bytes: usize,
    /// Passes serviced since the last yield — the backstop
    /// [`SERVICE_YIELD_PASS_LIMIT`] trips on when per-pass payload is
    /// too small for the byte counter to notice.
    last_service_passes: usize,
    /// ITEM C1 measurement-gate counters (observability only — no
    /// behavior change): the inner-UDP drop/saturation signals the
    /// chained-WG hypothesis hunts. See [`DropStats`].
    stats: DropStats,
    /// `rx_queue` head entries already attributed by
    /// [`scan_udp_offered`](Self::scan_udp_offered) — poll may stop
    /// mid-queue on the egress budget, and a re-scan must not
    /// double-offer the carry-over prefix.
    rx_scan_pending: usize,
    /// When the last [`STATS_SNAPSHOT_INTERVAL`] snapshot ran.
    last_stats: StdInstant,
    /// Stamp of the last `drain_wire_flood` — the RX-service heartbeat
    /// ([`RX_SERVICE_INTERVAL`]): every long synchronous loop checks it
    /// so the bridge channel is serviced at a bounded interval no
    /// matter how expensive one pass's socket/stack work becomes.
    rx_last_service: StdInstant,
}

// The pump rides the shared tokio worker pool (perf-7 P7-2): if any
// field ever turns `!Send` — a `Rc`/`Cell`/raw pointer sneaking into a
// smoltcp or boringtun type — this file stops compiling here, at zero
// runtime cost. See the module docs for why `Send` holds.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<WgPump>();
};

impl WgPump {
    fn new(
        config: &WireGuardConfig,
        endpoint: Endpoint,
        endpoint_addr: SocketAddr,
        rx: mpsc::Receiver<ActorMsg>,
    ) -> Self {
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
        let wake = Arc::new(tokio::sync::Notify::new());
        Self {
            name: config.name.clone(),
            tunn,
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            endpoint,
            endpoint_addr,
            rx,
            wake,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            used_ports: HashSet::new(),
            next_port: EPHEMERAL_PORT_BASE + rand::random::<u16>() % EPHEMERAL_PORT_SPAN,
            outbox: VecDeque::new(),
            reserved: config.reserved,
            src_v4: config.ip.map(Into::into),
            src_v6: config.ipv6.map(Into::into),
            recv_buf: vec![0u8; buf_size],
            rx_slots: (0..WIRE_DRAIN_BUDGET)
                .map(|_| Vec::with_capacity(buf_size))
                .collect(),
            scratch_pool: VecDeque::new(),
            scratch_len: buf_size,
            udp_scratch: vec![0u8; inner_mtu],
            last_timer: StdInstant::now(),
            last_desync_kick: None,
            last_service_bytes: 0,
            last_service_passes: 0,
            stats: DropStats::default(),
            rx_scan_pending: 0,
            last_stats: StdInstant::now(),
            rx_last_service: StdInstant::now(),
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
    /// kept — an undersized one would force a realloc at the next
    /// checkout anyway. Anything past [`SCRATCH_POOL_CAP`] frees, the
    /// same fate every outbox Vec had before pooling.
    fn return_scratch(&mut self, buf: Vec<u8>) {
        if buf.capacity() >= self.scratch_len && self.scratch_pool.len() < SCRATCH_POOL_CAP {
            self.scratch_pool.push_back(buf);
        }
    }

    /// Overwrite the reserved bytes of an outbound WG datagram (byte 0 is
    /// the message type; 1..4 are the reserved field Cloudflare WARP uses)
    /// and queue it for the endpoint socket. boringtun has no reserved-byte
    /// API — this is the post-encapsulation mutation the spec requires on
    /// *every* `WriteToNetwork` output, handshake messages included. The
    /// datagram arrives as its own crypto dst buffer — moved, not copied.
    fn enqueue_wg(&mut self, mut pkt: Vec<u8>) {
        if let Some(reserved) = self.reserved {
            if pkt.len() >= 4 {
                pkt[1..4].copy_from_slice(&reserved);
            }
        }
        self.outbox.push_back(pkt);
    }

    /// `decapsulate_wire`'s `Err` arm, factored so the batch drain's
    /// post-pass runs the identical handling on a crypto-pool result
    /// (a DATA packet whose off-actor open failed is the same class of
    /// error a serial `decapsulate_in_place` produces).
    fn wire_error(&mut self, e: &WireGuardError, dst: &mut Vec<u8>) {
        debug!("wireguard {}: decapsulate error: {e:?}", self.name);
        if matches!(
            e,
            WireGuardError::NoCurrentSession | WireGuardError::WrongIndex
        ) {
            // A data datagram addressed to a session index
            // this ring does not hold — or to a different
            // generation in its slot — proves the peer's
            // noise state diverged from ours: it is
            // encrypting replies under a session we cannot
            // read and will keep doing so until it sees a
            // newer session of ours (the responder's
            // `current` follows the newest session that
            // sent it a data packet). boringtun's own
            // recovery is the `want_handshake` ladder —
            // KEEPALIVE+REKEY_TIMEOUT (~15 s) of one-way
            // traffic before a re-initiation — and every
            // pending dial burns its deadline inside that
            // window. Kick the handshake at the first such
            // error instead.
            //
            // Two independent bounds keep the kick cheap:
            // `force=false` dedups against a handshake
            // already in flight, and `desync_kick_due`
            // floors *re-arms* at REKEY_TIMEOUT — the dedup
            // alone ends the moment a response lands, so
            // without the floor a flood of forged
            // `receiver_idx` datagrams (DATA carries no
            // mac1; both errors above are forgeable at
            // line rate) would mint an initiation every
            // RTT and spend the responder's 2×DH+2×AEAD
            // per reply. `InvalidAeadTag`/`InvalidCounter`
            // et al. stay pure drops — they prove nothing
            // about session identity and a forged datagram
            // must not buy a handshake.
            if self.desync_kick_due() {
                if let TunnResult::WriteToNetwork(b) =
                    self.tunn.format_handshake_initiation(dst, false)
                {
                    self.last_desync_kick = Some(StdInstant::now());
                    let len = b.len();
                    dst.truncate(len);
                    self.enqueue_wg(std::mem::take(dst));
                    *dst = self.take_scratch();
                }
            }
        }
    }

    /// boringtun's chained empty-datagram flush: after any
    /// `WriteToNetwork` the protocol requires re-calling with an empty
    /// datagram until it stops producing (inner packets queued behind
    /// a handshake flush here). The tail of `decapsulate_wire`'s loop,
    /// factored so the batch drain's non-DATA and cookie arms reach it.
    fn flush_queue_chain(&mut self, dst: &mut Vec<u8>) {
        loop {
            match self.tunn.decapsulate_in_place(None, &mut [], dst) {
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    self.wire_error(&e, dst);
                    break;
                }
                TunnResult::WriteToNetwork(b) => {
                    let len = b.len();
                    dst.truncate(len);
                    self.enqueue_wg(std::mem::take(dst));
                    *dst = self.take_scratch();
                }
                TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                    unreachable!("an empty datagram only flushes the send queue")
                }
            }
        }
    }

    /// The batch drain's non-DATA arm: `handle_verified_packet` on the
    /// classified `Packet` (handshake init/response, cookie reply —
    /// everything but DATA), then the chained flush a `WriteToNetwork`
    /// mandates — `decapsulate_wire`'s non-DATA iterations verbatim.
    fn handle_verified_wire(&mut self, packet: Packet<'_>, dst: &mut Vec<u8>) {
        match self.tunn.handle_verified_packet(packet, dst) {
            TunnResult::Done => {}
            TunnResult::Err(e) => self.wire_error(&e, dst),
            TunnResult::WriteToNetwork(b) => {
                let len = b.len();
                dst.truncate(len);
                self.enqueue_wg(std::mem::take(dst));
                *dst = self.take_scratch();
                self.flush_queue_chain(dst);
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                unreachable!("non-DATA packets never produce tunnel writes")
            }
        }
    }

    /// Feed one inbound wire datagram through `Tunn`, chaining the
    /// empty-datagram calls boringtun's contract requires to flush packets
    /// queued behind a handshake (`decapsulate` doc: repeat until the
    /// result is not `WriteToNetwork`).
    ///
    /// The datagram arrives inside an *owned* receive buffer `slot`
    /// (its first `wire_len` bytes — an rx-slot Vec, the select arm's
    /// `recv_buf`, or a bare test datagram) because a DATA packet is
    /// opened *in place* inside it (PATCH(17)): the plaintext lands at
    /// `slot[DATA_PAYLOAD_OFF..]` and the whole Vec then moves into
    /// `device.rx_queue` as `Bytes`, so the decrypt-into-scratch copy
    /// plus the `Bytes::copy_from_slice` allocation the dst path needed
    /// are both gone. `Some(slot)` hands the buffer back for reuse
    /// (handshake/cookie/error traffic and keepalives, which decrypt to
    /// empty plaintext); `None` means the decrypted packet owns it and
    /// the caller back-fills a fresh buffer.
    fn decapsulate_wire(&mut self, mut slot: Vec<u8>, wire_len: usize) -> Option<Vec<u8>> {
        // WG header bytes 1..4 are reserved-zero on the wire — but peers
        // like Cloudflare WARP stamp non-zero identifiers there, and
        // vendored boringtun's `parse_incoming_packet` checks type and
        // reserved as one LE u32, so an unscrubbed datagram is rejected
        // wholesale. Zero the field on receipt — don't-care semantics,
        // the same treatment mihomo applies for wireguard-go — rather
        // than patching the vendored parser.
        if wire_len >= 4 {
            slot[1..4].fill(0);
        }
        let mut dst = self.take_scratch();
        // `Some(len)` once a DATA packet has decrypted inside `slot`:
        // the plaintext is `slot[DATA_PAYLOAD_OFF..DATA_PAYLOAD_OFF +
        // len]` and the in-place path may not touch `slot` again after
        // that, so the produced length is carried out of the borrow
        // scope this way and the Vec moves below.
        let mut plaintext_len = None;
        {
            let mut datagram: &mut [u8] = &mut slot[..wire_len];
            loop {
                match self.tunn.decapsulate_in_place(None, datagram, &mut dst) {
                    TunnResult::Done => break,
                    TunnResult::Err(e) => {
                        self.wire_error(&e, &mut dst);
                        break;
                    }
                    TunnResult::WriteToNetwork(b) => {
                        // Every `WriteToNetwork` slice starts at dst[0], so
                        // the produced datagram is exactly the truncated
                        // buffer — moved into the outbox, not copied.
                        let len = b.len();
                        dst.truncate(len);
                        self.enqueue_wg(dst);
                        // Chained call with an empty datagram flushes the queue.
                        dst = self.take_scratch();
                        datagram = &mut [];
                    }
                    TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                        // PATCH(17): `b` is the plaintext the AEAD open
                        // left inside `slot` at `DATA_PAYLOAD_OFF` —
                        // record the produced length and let the borrow
                        // die with the loop so the slot Vec itself can
                        // move on. A chained empty-datagram flush can
                        // only produce `WriteToNetwork`/`Done`/`Err`,
                        // never this arm.
                        plaintext_len = Some(b.len());
                        break;
                    }
                }
            }
        }
        self.return_scratch(dst);
        match plaintext_len {
            // DATA decrypted in place: bound the Vec to the datagram,
            // then `Bytes::from(Vec)` takes the whole allocation over —
            // no copy — and only the plaintext view is published.
            Some(len) => {
                slot.truncate(wire_len);
                let start = meow_wireguard::DATA_PAYLOAD_OFF;
                // `push_rx`: the D3 per-poll ingress bound — overflow
                // stages in `rx_hold`, `poll_stack`'s burst promotes it.
                self.device
                    .push_rx(Bytes::from(slot).slice(start..start + len));
                None
            }
            // The slot holds nothing a consumer needs — reuse it.
            None => Some(slot),
        }
    }

    /// One batch read into the persistent slots — a `recvmmsg` on
    /// Linux, a `recvmsg_x` on macOS, a `try_recv_buf` loop elsewhere —
    /// then the PATCH(18) three-phase pass over the filled slots:
    ///
    ///   A. **Serial demux** — scrub + `classify_incoming` per slot in
    ///      wire order (the same verify half `decapsulate_in_place`
    ///      ran). DATA packets become `CryptoJob`s whose `buf` is the
    ///      slot Vec itself (the worker opens it in place — zero copy
    ///      is preserved exactly as `decapsulate_wire` arranged); every
    ///      non-DATA packet — handshake, cookie reply, drop — is fully
    ///      handled inline in arrival order, as is its `WriteToNetwork`
    ///      output and chained flush.
    ///   B. **Worker pass** — `CryptoPool::run_shared(&mut jobs)`: the
    ///      batch's AEAD opens on the process-wide resident pool
    ///      (inline when `jobs <= 2` — resolved lazily, so a small
    ///      batch never spawns it — or the pool is single-threaded).
    ///   C. **Serial post-pass** — in job order: `handle_decrypted_data`
    ///      replays the `set_current_session`/timer/validate
    ///      bookkeeping `handle_data_in_place` would have run, then the
    ///      slot's `Bytes` hand-off into `rx_queue` — the same publish
    ///      order the serial drain produced.
    ///
    /// The only reordered observable is *when* a DATA packet's
    /// bookkeeping runs relative to a later non-DATA packet's
    /// `WriteToNetwork` — a chained flush cannot depend on an inner
    /// packet's side effects, and `set_current_session` is guarded by
    /// session generation (`session_timers[new] >= [cur]`), so a
    /// mid-batch re-handshake can never be regressed by a stale
    /// packet's bookkeeping.
    ///
    /// "Reordered" is not "indistinguishable": one bounded divergence
    /// remains inside a batch. A DATA packet's `timer_tick`/
    /// `set_current_session` lands in Phase C, *after* a same-batch
    /// non-DATA packet's output — so where the serial drain leaves the
    /// non-DATA's `TimeLastPacketSent` tick last (`want_handshake`
    /// set), this drain leaves the DATA `TimeLastPacketReceived` last
    /// (`want_keepalive`): a last-writer-wins difference confined to
    /// the liveness arm, since every numeric timestamp a tick writes is
    /// order-free. The same deferral can seal one flushed queued packet
    /// under the pre-batch `current` session — still a live session,
    /// and the generation guard above still forbids a regression.
    /// `run_crypto` is the Phase-B batch strategy — `run` hands it the
    /// `block_in_place` offload (the pool join must not park the shared
    /// worker), tests the direct pool call (they run on current-thread
    /// runtimes, where `block_in_place` panics).
    /// Pulls up to [`WIRE_DRAIN_BUDGET`] wire datagrams and returns how
    /// many arrived — `run`'s RX-flood loop repeats the call while full
    /// batches come back (a returned-short batch means the endpoint
    /// went quiet mid-drain).
    fn drain_wire(&mut self, run_crypto: impl FnOnce(&mut Vec<CryptoJob>)) -> usize {
        let mut slots = std::mem::take(&mut self.rx_slots);
        let n = self.endpoint.recv_batch(&mut slots, WIRE_DRAIN_BUDGET);
        // Wire bytes count toward the service-yield budget whether a
        // datagram turns out DATA, handshake, or garbage — the verify +
        // demux + crypto work below is paid per datagram either way.
        self.last_service_bytes += slots[..n].iter().map(Vec::len).sum::<usize>();

        // Phase A — serial demux: DATA slots become jobs (the Vec
        // travels into the job); everything else is handled inline.
        let mut jobs: Vec<CryptoJob> = Vec::new();
        let mut dst = self.take_scratch();
        for (i, slot) in slots[..n].iter_mut().enumerate() {
            // `recv_batch` rewrote the filled slot's len to its
            // datagram — that length is the wire bound.
            let mut pkt = std::mem::take(slot);
            let wire_len = pkt.len();
            // The WARP-reserved scrub `decapsulate_wire` applies —
            // bytes 1..4 zero before parse.
            if wire_len >= 4 {
                pkt[1..4].fill(0);
            }
            match self
                .tunn
                .classify_incoming(None, &pkt[..wire_len], &mut dst)
            {
                WireClass::Data(p) => {
                    let (receiver_idx, counter) = (p.receiver_idx, p.counter());
                    // `Arc` the session's crypto while `&mut self.tunn`
                    // is free — the job carries it to the worker.
                    let crypto = self.tunn.session_handle_for(receiver_idx);
                    // The job's own context tag — the post-pass lands
                    // each result on its source slot exactly, even if a
                    // lost chunk ever shifted the return positions.
                    jobs.push(CryptoJob::new(
                        pkt,
                        wire_len,
                        receiver_idx,
                        counter,
                        crypto,
                        i,
                    ));
                }
                WireClass::Other(packet) => {
                    self.handle_verified_wire(packet, &mut dst);
                    *slot = pkt;
                }
                WireClass::CookieReply(len) => {
                    dst.truncate(len);
                    self.enqueue_wg(std::mem::take(&mut dst));
                    dst = self.take_scratch();
                    self.flush_queue_chain(&mut dst);
                    *slot = pkt;
                }
                WireClass::Drop(e) => {
                    self.wire_error(&e, &mut dst);
                    *slot = pkt;
                }
            }
        }

        // Phase B — the batch's AEAD opens, in place inside the job
        // bufs. `run_crypto` fills every `job.result`, preserving job
        // order — and `run_shared`'s `n <= 2` shortcut runs *before*
        // the shared pool is resolved, so a small batch never spawns
        // the workers.
        run_crypto(&mut jobs);

        // Phase C — serial post-pass in wire order.
        for job in jobs {
            let i = job.tag;
            // The replay mark lives here, not in the worker's open —
            // this loop is the wire-order sequence the window must
            // advance in. `mark_received` only runs on a successful
            // open, exactly where the serial path marks.
            let mark = match &job.result {
                Some(Ok(_)) => Some(job.mark_received()),
                _ => None,
            };
            let mut pkt = job.buf;
            slots[i] = match job.result {
                Some(Ok(pt_len)) => {
                    let produced = match mark.unwrap() {
                        Err(e) => {
                            self.wire_error(&e, &mut dst);
                            None
                        }
                        Ok(()) => match self.tunn.handle_decrypted_data(
                            job.receiver_idx,
                            pt_len,
                            &mut pkt[..job.wire_len],
                        ) {
                            TunnResult::WriteToTunnelV4(b, _)
                            | TunnResult::WriteToTunnelV6(b, _) => Some(b.len()),
                            TunnResult::Done => None,
                            TunnResult::Err(e) => {
                                self.wire_error(&e, &mut dst);
                                None
                            }
                            TunnResult::WriteToNetwork(_) => {
                                unreachable!("data post-pass never emits wire output")
                            }
                        },
                    };
                    match produced {
                        Some(len) => {
                            // The same `Bytes` hand-off
                            // `decapsulate_wire` makes: the Vec becomes
                            // the plaintext view, no copy.
                            pkt.truncate(job.wire_len);
                            let start = meow_wireguard::DATA_PAYLOAD_OFF;
                            // `push_rx`, not `rx_queue.push_back`: the
                            // D3 per-poll ingress bound — overflow
                            // stages in `rx_hold`, `poll_stack`'s burst
                            // promotes it between polls.
                            self.device
                                .push_rx(Bytes::from(pkt).slice(start..start + len));
                            Vec::with_capacity(self.scratch_len)
                        }
                        None => pkt,
                    }
                }
                Some(Err(e)) => {
                    self.wire_error(&e, &mut dst);
                    pkt
                }
                None => {
                    debug_assert!(false, "crypto pool resolves every job");
                    pkt
                }
            };
        }
        // A worker-lost chunk leaves its slots `mem::take`n — capacity-0
        // husks `recv_batch` would read nothing into. Re-arm them (the
        // pool's slots key on *capacity*, not len); a loss-free pass
        // heals nothing.
        let mut healed = 0usize;
        for slot in &mut slots {
            if slot.capacity() == 0 {
                *slot = Vec::with_capacity(self.scratch_len);
                healed += 1;
            }
        }
        debug_assert_eq!(healed, 0, "crypto pool lost a chunk's buffers");
        self.return_scratch(dst);
        self.rx_slots = slots;
        n
    }

    /// Egress: `device.tx_queue` → WG DATA datagrams → outbox — the TX
    /// twin of `drain_wire`'s three-phase shape (PATCH(19)):
    ///
    ///   A. **Serial setup** — `current_session_handle` once: an `Arc`
    ///      clone of the outbound session's crypto, read off the same
    ///      ring slot `encapsulate` consults. `None` means no
    ///      established session, and the whole batch falls back to the
    ///      serial `encapsulate` loop — the only path that may produce
    ///      non-DATA output here, since `queue_packet` + the
    ///      handshake-initiation chain need `&mut Tunn`. With a
    ///      session, `reserve_tx_counters(n)` block-reserves the
    ///      batch's nonces in one `fetch_add` and each inner packet
    ///      moves into a [`TxCryptoJob`]: the `tx_queue` Vec travels
    ///      into the job as `inner`, a `take_scratch()` Vec is its
    ///      `wire` buffer.
    ///   B. **Worker pass** — `CryptoPool::run_tx_shared(&mut jobs)`:
    ///      the batch's AEAD seals off-thread (inline when
    ///      `jobs <= 2` — resolved lazily, so a small batch never
    ///      spawns the pool).
    ///   C. **Serial post-pass** — in job order, which is also counter
    ///      order and the order `encapsulate` would have emitted (the
    ///      same triple-coincidence `drain_wire`'s positional merge
    ///      gives the open direction): each sealed `wire` Vec goes to
    ///      `enqueue_wg`, then `handle_sent_data` replays the
    ///      timer/`tx_bytes` bookkeeping `encapsulate` ran inline —
    ///      deferred past Phase B exactly like the DATA bookkeeping on
    ///      the RX side, the same bounded last-writer-wins divergence
    ///      on the liveness arm only. Every `inner` Vec returns to
    ///      `device.tx_pool` regardless of outcome; a failed job's
    ///      `wire` Vec returns to `scratch_pool`.
    ///
    /// Divergence map vs the serial path, all bounded inside a pass:
    /// a packet that arrives between the `current_session_handle`
    /// snapshot and Phase C seals under the captured session even if
    /// `current` rotated mid-pass — a live session the peer still
    /// accepts, the same window the serial path's per-packet re-read
    /// had. Undersize packets take the serial arm's `warn!` + drop,
    /// never the panic `format_packet_data` carries.
    ///
    /// `run_crypto` is the Phase-B seal strategy — `run` hands it the
    /// `block_in_place` offload, tests the direct pool call (see
    /// [`drain_wire`](Self::drain_wire)).
    fn drain_device_tx(&mut self, run_crypto: impl FnOnce(&mut Vec<TxCryptoJob>)) {
        let Some(crypto) = self.tunn.current_session_handle() else {
            // No established session — the serial arm: `encapsulate`
            // queues each inner packet and drives the handshake chain.
            let mut dst = self.take_scratch();
            while let Some(pkt) = self.device.tx_queue.pop_front() {
                self.last_service_bytes += pkt.len();
                // `Tunn::encapsulate` *panics* on an undersized dst —
                // guard rather than trust the MTU accounting.
                if pkt.len() + meow_wireguard::DATA_OVERHEAD_SZ > dst.len() {
                    warn!(
                        "wireguard {}: dropping {}B inner packet (scratch buffer {}B)",
                        self.name,
                        pkt.len(),
                        dst.len()
                    );
                    self.device.return_tx_buf(pkt);
                    continue;
                }
                if let TunnResult::WriteToNetwork(b) = self.tunn.encapsulate(&pkt, &mut dst) {
                    let len = b.len();
                    dst.truncate(len);
                    self.enqueue_wg(dst);
                    dst = self.take_scratch();
                }
                self.device.return_tx_buf(pkt);
            }
            self.return_scratch(dst);
            return;
        };

        // Phase A — `n` snapshots the queue: packets pushed during the
        // pass are for the next iteration. The block reservation keys
        // each job's nonce to `base + i`; a packet dropped at the
        // undersize guard simply skips its counter (counters need
        // uniqueness, not contiguity). The snapshot is additionally
        // capped at [`TX_DRAIN_BUDGET`]: anything deeper rides the next
        // pass — see the constant for why unbounded admission flooded
        // every downstream UDP buffer.
        let n = self.device.tx_queue.len().min(TX_DRAIN_BUDGET);
        let base = crypto.reserve_tx_counters(n);
        let mut jobs: Vec<TxCryptoJob> = Vec::with_capacity(n);
        for i in 0..n {
            let pkt = self.device.tx_queue.pop_front().expect("n was snapshotted");
            self.last_service_bytes += pkt.len();
            if pkt.len() + meow_wireguard::DATA_OVERHEAD_SZ > self.scratch_len {
                warn!(
                    "wireguard {}: dropping {}B inner packet (scratch buffer {}B)",
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
                base + i as u64,
                crypto.clone(),
                i,
            ));
        }

        // Phase B — the batch's AEAD seals inside the job `wire` bufs.
        // `run_crypto` fills every `job.result`, preserving job order —
        // and `run_tx_shared`'s `n <= 2` shortcut runs *before* the
        // shared pool is resolved, so a small batch never spawns the
        // workers.
        run_crypto(&mut jobs);

        // Phase C — serial post-pass in job order = counter order =
        // the wire-emit order `encapsulate` would have produced.
        for job in jobs {
            let inner_len = job.inner.len();
            self.device.return_tx_buf(job.inner);
            match job.result {
                Some(Ok(_)) => {
                    self.enqueue_wg(job.wire);
                    self.tunn.handle_sent_data(inner_len);
                }
                Some(Err(e)) => {
                    debug!("wireguard {}: encapsulate error: {e:?}", self.name);
                    self.return_scratch(job.wire);
                }
                None => {
                    debug_assert!(false, "crypto pool resolves every job");
                    self.return_scratch(job.wire);
                }
            }
        }
    }

    /// boringtun's housekeeping — rekey, session expiry, persistent
    /// keepalive — all inside `update_timers` (spec §3.8's manual
    /// keepalive-deadline is subsumed by it).
    fn tick_timers(&mut self) {
        let mut dst = self.take_scratch();
        match self.tunn.update_timers(&mut dst) {
            TunnResult::WriteToNetwork(b) => {
                let len = b.len();
                dst.truncate(len);
                self.enqueue_wg(dst);
                // boringtun's contract: packets queued behind the handshake
                // a rekey just triggered flush via chained empty-datagram
                // `decapsulate` calls — the same drain loop
                // `decapsulate_wire` runs for real datagrams. Skipping
                // this drops every inner packet parked while the old
                // session was rekeying. An empty slot is the empty
                // datagram; it comes back unused.
                let _ = self.decapsulate_wire(Vec::new(), 0);
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
                match self.tunn.format_handshake_initiation(&mut dst, true) {
                    TunnResult::WriteToNetwork(b) => {
                        let len = b.len();
                        dst.truncate(len);
                        self.enqueue_wg(dst);
                        let _ = self.decapsulate_wire(Vec::new(), 0);
                    }
                    TunnResult::Err(err) => {
                        warn!(
                            "wireguard {}: forced re-handshake failed: {err:?}",
                            self.name
                        );
                        self.return_scratch(dst);
                    }
                    _ => self.return_scratch(dst),
                }
            }
            _ => self.return_scratch(dst),
        }
    }

    /// Whether the service loop owes the shared worker a yield —
    /// `run()` consults this between passes. Two independent bounds so
    /// *no* unbounded non-parking workload skips it: a rolling payload
    /// count ([`SERVICE_YIELD_THRESHOLD`]) catches saturated bulk
    /// flows, while a rolling pass count ([`SERVICE_YIELD_PASS_LIMIT`])
    /// catches high-rate small-datagram floods whose per-pass payload
    /// the byte counter barely notices but whose per-datagram work —
    /// verify, demux, crypto — is real.
    fn service_yield_due(&self) -> bool {
        self.last_service_bytes >= SERVICE_YIELD_THRESHOLD
            || self.last_service_passes >= SERVICE_YIELD_PASS_LIMIT
    }

    /// Whether the desync floor permits another initiation: the first
    /// error always may; later ones wait [`DESYNC_KICK_INTERVAL`] out.
    /// The in-flight dedup stays inside `format_handshake_initiation(_,
    /// false)` — this only caps how often the window reopens after a
    /// handshake completes.
    fn desync_kick_due(&self) -> bool {
        self.last_desync_kick
            .is_none_or(|t| t.elapsed() >= DESYNC_KICK_INTERVAL)
    }

    /// Kick off the WireGuard handshake immediately so it overlaps the
    /// first dial instead of starting when the first SYN needs encrypting.
    fn kick_handshake(&mut self) {
        let mut dst = self.take_scratch();
        if let TunnResult::WriteToNetwork(b) =
            self.tunn.format_handshake_initiation(&mut dst, false)
        {
            let len = b.len();
            dst.truncate(len);
            self.enqueue_wg(dst);
        } else {
            self.return_scratch(dst);
        }
    }

    /// Nonblocking sends, a [`WIRE_DRAIN_BUDGET`]-bounded batch at a
    /// time — one `sendmmsg`/`sendmsg_x` on Linux/macOS, a `try_send`
    /// loop elsewhere.
    /// A batch that stops short leaves the boundary datagram at the
    /// head of `staged`: replaying it with `try_send` is how the
    /// `WouldBlock`/`errno` split the old per-packet loop had is
    /// recovered (`sendmmsg` folds a post-partial error into the
    /// returned count). `WouldBlock` requeues the remainder verbatim
    /// and backs off; any other error logs and drops that one
    /// datagram while the rest of the batch continues — the same
    /// semantics as the per-packet loop. `ConnectionReset` is the one
    /// terminal verdict (a closed TX bridge channel — `Endpoint::Proxy`'s
    /// front conn or `Endpoint::Batch`'s socket task is dead): the
    /// outbox clears wholesale rather than warn-per-packet while the
    /// pump's `endpoint.recv` arm is on its way to the same verdict
    /// and the actor's exit.
    fn flush_outbox(&mut self) {
        let mut staged: VecDeque<Vec<u8>> = VecDeque::with_capacity(WIRE_DRAIN_BUDGET);
        while !self.outbox.is_empty() {
            self.rx_heartbeat();
            for _ in 0..self.outbox.len().min(WIRE_DRAIN_BUDGET) {
                staged.push_back(self.outbox.pop_front().expect("bounded by len"));
            }
            loop {
                // `refs` borrows `staged` — scoped inside the loop so
                // the shared borrow ends before `staged` shrinks.
                let refs: Vec<&[u8]> = staged.iter().map(Vec::as_slice).collect();
                let sent = self.endpoint.send_batch(&refs, self.endpoint_addr);
                for pkt in staged.drain(..sent) {
                    self.last_service_bytes += pkt.len();
                    self.return_scratch(pkt);
                }
                if staged.is_empty() {
                    break;
                }
                let pkt = staged.pop_front().expect("non-empty after partial batch");
                match self.endpoint.try_send(&pkt) {
                    Ok(_) => {
                        self.last_service_bytes += pkt.len();
                        self.return_scratch(pkt);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Requeue the rest of the batch ahead of
                        // whatever the outbox already held, then the
                        // boundary datagram itself — it must stay
                        // ahead of its successors.
                        while let Some(tail) = staged.pop_back() {
                            self.outbox.push_front(tail);
                        }
                        self.outbox.push_front(pkt);
                        return;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                        // A closed TX bridge channel — both variants
                        // only report `ConnectionReset` when their
                        // bridge task is gone (`Endpoint::Proxy`'s
                        // front conn, `Endpoint::Batch`'s socket task):
                        // terminal, not the transient WSAECONNRESET a
                        // raw socket could once report — and the pump's
                        // next `endpoint.recv` returns the same verdict
                        // and stops the actor. Drop the whole queue in
                        // one return; WG tolerates the loss and the
                        // redial re-sends what matters — warn-per-packet
                        // until the recv arm gets there would only storm.
                        self.stats.outbox_dropped += self.outbox.len() as u64 + 1;
                        self.outbox.clear();
                        self.return_scratch(pkt);
                        return;
                    }
                    Err(e) => {
                        self.stats.outbox_dropped += 1;
                        warn!(
                            "wireguard {}: endpoint send to {} failed: {e}",
                            self.name, self.endpoint_addr
                        );
                        self.return_scratch(pkt);
                    }
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
        // A WG iface carries exactly one address per family, so the
        // same-family tunnel address is the only local endpoint this
        // dial could ever use — pin it instead of letting smoltcp's
        // RFC 6724 source selection run: for an IPv6 *loopback*
        // destination that selection returns `::1`, which smoltcp 0.13
        // (#1113) then closes on the first dispatch because `::1` is not
        // in `ip_addrs`. A family the tunnel has no address for can never
        // carry the flow at all — fail it here, the same contract the
        // UDP conn's `has_v4`/`has_v6` pre-check gives, rather than let
        // a dead-end auto-selection surface a bare "refused" after the
        // socket's first dispatch (or the full connect limit).
        let local_addr = match remote.ip() {
            IpAddr::V4(_) => self.src_v4,
            IpAddr::V6(_) => self.src_v6,
        };
        let Some(local_addr) = local_addr else {
            let _ = reply.send(Err(MeowError::NotSupported(format!(
                "wireguard {}: no {} tunnel address configured for {remote}",
                self.name,
                if remote.is_ipv4() { "IPv4" } else { "IPv6" },
            ))));
            return;
        };
        let Some(port) = self.alloc_port() else {
            let _ = reply.send(Err(MeowError::Proxy(format!(
                "wireguard {}: ephemeral ports exhausted",
                self.name
            ))));
            return;
        };
        // A chained endpoint's socket buffers bound the burst in both
        // directions — advertised window inbound, in-flight data
        // outbound — so `CHAINED_TCP_SOCK_BUF` keeps each under the
        // front-relay association queues measured to drop them (see the
        // constant).
        let sock_buf = if matches!(self.endpoint, Endpoint::Proxy(_)) {
            CHAINED_TCP_SOCK_BUF
        } else {
            TCP_SOCKET_BUF
        };
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; sock_buf]),
            tcp::SocketBuffer::new(vec![0; sock_buf]),
        );
        // TCP_NODELAY: a proxy stream wants latency over tinygram batching.
        socket.set_nagle_enabled(false);
        // Delayed-ACK at 1 ms (wg-perf): smoltcp's 10 ms default holds
        // each ACK for a full pass cadence, so a request/response flow
        // ate it twice — first segment and FIN — on every connection.
        socket.set_ack_delay(Some(smoltcp::time::Duration::from_millis(1)));
        let connect = socket.connect(
            self.iface.context(),
            IpEndpoint::from(remote),
            IpListenEndpoint {
                addr: Some(local_addr),
                port,
            },
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
        let handle = self.sockets.add(socket);
        self.tcp.insert(
            handle,
            TcpState {
                local_port: port,
                pending: Some(PendingTcp {
                    reply,
                    read_rx,
                    write_tx,
                    display,
                    created: StdInstant::now(),
                }),
                read_tx,
                write_rx,
                out: VecDeque::new(),
                pending_read: VecDeque::new(),
                eof_sent: false,
                graceful_close: false,
                dead_since: None,
                snap_txq: 0,
                snap_txq_at: StdInstant::now(),
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
                rx_offered: 0,
                rx_dequeued: 0,
                rx_sockbuf_dropped: 0,
            },
        );
        let conn = WgPacketConn {
            local,
            rx: tokio::sync::Mutex::new(read_rx),
            tx: write_tx,
            wake: Arc::clone(&self.wake),
            closed: AtomicBool::new(false),
            allowed,
            has_v4,
            has_v6,
        };
        let _ = reply.send(Ok(Box::new(conn) as Box<dyn ProxyPacketConn>));
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
    fn discard_socket_rx(st: &mut TcpState, socket: &mut tcp::Socket<'_>) {
        st.pending_read.clear();
        while socket.can_recv() {
            if socket.recv(|data| (data.len(), ())).is_err() {
                break;
            }
        }
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
        let wake = Arc::clone(&self.wake);
        let src_v4 = self.src_v4;
        let src_v6 = self.src_v6;
        let mut dead_tcp: Vec<SocketHandle> = Vec::new();
        let mut dead_udp: Vec<SocketHandle> = Vec::new();

        // Collected-handle iteration (D3): `rx_heartbeat` needs `&mut
        // self` between sockets, which a live `&mut self.tcp` borrow
        // forbids. Every socket is still serviced each pass — the
        // heartbeat only interleaves wire-RX drains, never skips work.
        let tcp_order: Vec<SocketHandle> = self.tcp.keys().copied().collect();
        for handle in tcp_order {
            self.rx_heartbeat();
            let Some(st) = self.tcp.get_mut(&handle) else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);

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
                    dead_tcp.push(handle);
                    continue;
                }
                if state == tcp::State::Established {
                    debug!("wireguard {}: TCP {handle:?} established", self.name);
                    let p = st.pending.take().expect("pending checked is_some above");
                    let stream = WgStream {
                        remote: p.display,
                        rx: p.read_rx,
                        tx: p.write_tx,
                        wake: Arc::clone(&wake),
                        pending_read: None,
                        pending_write: None,
                        write_reserve: None,
                        write_permit: None,
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
            while let Some(front) = st.out.front_mut() {
                match front {
                    TcpIo::Data(b) => {
                        if !socket.can_send() {
                            // ITEM C1: send-side stall — tx buffer full
                            // or remote window 0; the signature a
                            // retransmit/RTO stall pins.
                            note_count(
                                &mut self.stats.tcp_tx_stall,
                                1,
                                format_args!(
                                    "wireguard {}: TCP {handle:?} send stalled \
                                     (txq={}/{})",
                                    self.name,
                                    socket.send_queue(),
                                    socket.send_capacity()
                                ),
                            );
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
                                self.last_service_bytes += n;
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
            // ── socket→conn reads ──────────────────────────────────
            while let Some(ev) = st.pending_read.pop_front() {
                match st.read_tx.try_send(ev) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(ev)) => {
                        st.pending_read.push_front(ev);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        Self::discard_socket_rx(st, socket);
                        break;
                    }
                }
            }
            while socket.can_recv() && st.pending_read.is_empty() {
                let chunk = socket.recv(|data| {
                    let n = data.len().min(TCP_READ_CHUNK);
                    // STRUCTURAL COPY (perf-7 memcpy #6): smoltcp's `recv`
                    // closure yields a `&[u8]` view of the socket's ring
                    // buffer; its lifetime is bound to the SocketSet
                    // borrow, so the bytes cannot be moved, taken, or
                    // handed to the conn channel — only copied out.
                    // Elimination needs a smoltcp owned-buffer take API
                    // (e.g. `recv_owned(&mut self) -> Bytes`), which
                    // smoltcp 0.13.1 does not provide. Do NOT replace with
                    // an unsafe pointer cast: smoltcp's buffer management
                    // assumes the closure never retains the slice.
                    (n, StreamEvent::Data(Bytes::copy_from_slice(&data[..n])))
                });
                match chunk {
                    Ok(ev) => {
                        // Count the payload toward the service-yield budget
                        // whether or not the conn channel takes it — the
                        // smoltcp→conn copy already happened.
                        if let StreamEvent::Data(b) = &ev {
                            self.last_service_bytes += b.len();
                        }
                        match st.read_tx.try_send(ev) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(ev)) => {
                                st.pending_read.push_back(ev);
                                break;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                Self::discard_socket_rx(st, socket);
                                break;
                            }
                        }
                    }
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
            // Orphan bound: both channel halves closed means the flow
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
                    None => st.dead_since = Some(StdInstant::now()),
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
                debug!(
                    "wireguard {}: TCP {handle:?} dead (state {:?})",
                    self.name,
                    socket.state()
                );
                dead_tcp.push(handle);
            }
        }

        // Same collected-handle shape as the TCP loop above — `rx_heartbeat`
        // needs `&mut self` between sockets.
        let udp_order: Vec<SocketHandle> = self.udp.keys().copied().collect();
        for handle in udp_order {
            self.rx_heartbeat();
            let Some(st) = self.udp.get_mut(&handle) else {
                continue;
            };
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
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
            // ITEM C1: outer→inner no-socket-space — queued datagrams
            // facing a full smoltcp tx buffer is the enqueue-side
            // saturation the hypothesis hunts (backpressure, not loss:
            // `out` holds the datagram for the next pass).
            if !st.out.is_empty() && !socket.can_send() {
                self.stats.tx_buf_full += 1;
                note_drop(
                    &self.stats.dropped_tx,
                    1,
                    format_args!(
                        "wireguard {}: UDP {handle:?} tx socket buffer full \
                         ({}B/{}B queued)",
                        self.name,
                        socket.send_queue(),
                        socket.payload_send_capacity()
                    ),
                );
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
                    Ok(()) => {
                        self.last_service_bytes += data.len();
                        st.out.pop_front();
                    }
                    Err(udp::SendError::BufferFull) => {
                        // `can_send` already gates this — the arm stays
                        // as the belt-and-suspenders count if a race
                        // ever fires it.
                        self.stats.tx_buf_full += 1;
                        note_drop(
                            &self.stats.dropped_tx,
                            1,
                            format_args!(
                                "wireguard {}: UDP {handle:?} send_slice BufferFull",
                                self.name
                            ),
                        );
                        break;
                    }
                    // Unaddressable et al.: the conn's write_packet checks
                    // make those unreachable; drop the datagram rather than
                    // wedge the queue behind a permanently-failing one.
                    Err(e) => {
                        self.stats.tx_err_dropped += 1;
                        note_drop(
                            &self.stats.dropped_tx,
                            1,
                            format_args!(
                                "wireguard {}: UDP {handle:?} send_slice error \
                                 {e} — datagram dropped",
                                self.name
                            ),
                        );
                        self.last_service_bytes += data.len();
                        st.out.pop_front();
                    }
                }
            }
            // ITEM C1: post-poll rx occupancy — a buffer within one
            // datagram of capacity means smoltcp's `process` dropped
            // inbound datagrams this ingress (the hypothesis-B drop
            // point); `account_udp_drops` counts them exactly.
            let occ = socket.recv_queue();
            self.stats.rx_occ_max = self.stats.rx_occ_max.max(occ);
            if occ >= socket.payload_recv_capacity().saturating_sub(2048) {
                note_count(
                    &mut self.stats.rx_buf_full_obs,
                    1,
                    format_args!(
                        "wireguard {}: UDP {handle:?} rx socket buffer at \
                         capacity ({}B/{}B) — in-poll drops probable",
                        self.name,
                        occ,
                        socket.payload_recv_capacity()
                    ),
                );
            }
            while socket.can_recv() {
                match socket.recv_slice(&mut self.udp_scratch) {
                    Ok((n, meta)) => {
                        st.rx_dequeued += 1;
                        self.last_service_bytes += n;
                        let src = SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port);
                        // STRUCTURAL COPY (perf-7 memcpy #6, UDP twin of
                        // the TCP `recv` note above): `recv_slice` fills
                        // `udp_scratch` — the datagram lands in the pump's
                        // scratch Vec — and the conn channel needs an
                        // owned payload, so `copy_from_slice` is the hand
                        // off. smoltcp 0.13.1 exposes no owned-buffer take
                        // for UDP sockets either (`recv` yields the same
                        // borrowed slice the TCP path shows). No unsafe
                        // pointer casts — smoltcp owns the storage.
                        let data = Bytes::copy_from_slice(&self.udp_scratch[..n]);
                        // Full → drop: datagram loss is the UDP contract.
                        match st.read_tx.try_send((data, src)) {
                            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                            // ITEM C1: the conn-channel-full arm of the
                            // inner→outer drain — counted exactly.
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                self.stats.rx_chan_dropped += 1;
                                note_drop(
                                    &self.stats.dropped_rx,
                                    1,
                                    format_args!(
                                        "wireguard {}: UDP {handle:?} conn \
                                         channel full — datagram dropped",
                                        self.name
                                    ),
                                );
                            }
                        }
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
                dead_udp.push(handle);
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

    /// The crypto-batch strategy `run` hands both drains: the pool join
    /// blocks its caller on `mpsc::recv` until the workers return, which
    /// must not park a shared tokio worker — so a parallel-sized batch
    /// rides `block_in_place` and the wait moves off the worker set.
    /// `> 2` mirrors [`CryptoPool`]'s own serial cutoff: smaller batches
    /// resolve inline either way, and a dry pass — the pump's steady
    /// state — never pays the migration.
    ///
    /// `block_in_place` is legal only on the multi-thread flavor — it
    /// panics under `current_thread`, and `Handle::current` itself
    /// panics outside any runtime. `spawn_pump`'s host is the shared
    /// multi-thread runtime, but nothing forces an embedder to spawn
    /// the handle's calls there — so the flavor is checked rather than
    /// assumed, and a `current_thread` (or runtimeless) host runs the
    /// same `> 2` batch serially: the inline `mpsc::recv` then parks
    /// that runtime's one thread, which hosts nothing else to starve.
    /// Tests drive the drains on `current_thread` runtimes — this is
    /// what keeps them off the panic.
    fn offload_crypto<T>(jobs: &mut Vec<T>, run: fn(&mut Vec<T>)) {
        let offload = jobs.len() > 2
            && tokio::runtime::Handle::try_current()
                .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
        if offload {
            tokio::task::block_in_place(|| run(jobs));
        } else {
            run(jobs);
        }
    }

    /// How long `select!` may sleep before smoltcp's timers or the WG tick
    /// need service. Mailbox, endpoint and wake events all interrupt it —
    /// and they are the only wake sources the backlog paths need: conn
    /// writes pulse `wake`, conn-write backlogs stalled on smoltcp tx
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

    /// The interface-poll step of a service pass — its own method so
    /// `run`'s poll and the T1 burst pin drive the exact same code.
    /// Under smoltcp 0.13 one `poll` drains socket egress internally,
    /// so `poll_burst`'s extra iterations are the bounded-budget
    /// backstop rather than the throughput path — the pin still wants
    /// the production entry point, not a helper re-spelled.
    fn poll_stack(&mut self, now: SmolInstant) {
        // Burst, not a single poll — see `poll_burst`'s doc for the
        // smoltcp 0.13 rationale. The loop lives caller-side (D3) so two
        // things the shared helper can't reach still happen between
        // iterations: `fill_rx_queue` promotes held packets into the
        // bounded [`RX_INGRESS_CAP`] window each poll drains, and
        // `rx_heartbeat` keeps the wire-RX channel serviced while a
        // deep burst runs. An ingress-only poll reports
        // `PollResult::None`, so the quiet exit must also check
        // `rx_hold` — leftover holds resume next iteration instead of
        // waiting a pass.
        let mut tx_bytes = 0usize;
        let mut tx_len_before = self.device.tx_queue.len();
        for _ in 0..POLL_BURST {
            self.device.fill_rx_queue();
            match self.iface.poll(now, &mut self.device, &mut self.sockets) {
                smoltcp::iface::PollResult::SocketStateChanged => {
                    for pkt in self.device.tx_queue.iter().skip(tx_len_before) {
                        tx_bytes += pkt.len();
                    }
                    tx_len_before = self.device.tx_queue.len();
                    if tx_bytes > POLL_TX_BYTES_BUDGET {
                        break;
                    }
                }
                smoltcp::iface::PollResult::None if self.device.rx_hold.is_empty() => {
                    break;
                }
                smoltcp::iface::PollResult::None => {}
            }
            self.rx_heartbeat();
        }
    }

    /// ITEM C1 pre-poll offer scan: attribute every newly arrived UDP
    /// datagram in `device.rx_queue` to a bound socket by destination
    /// port — the same `dst_port` demux smoltcp's `accepts` applies
    /// (the dst-addr check it also does is skipped: every inner packet
    /// is addressed to this iface, and `rx_udp_unclaimed` would expose
    /// a misattribution).
    ///
    /// The accounting contract the scan/poll/tally trio maintains:
    /// `offered = dequeued + dropped + (in_flight | still_queued |
    /// in_socket)` — every datagram offered here resolves to a conn
    /// drain, a confirmed drop inside poll, or a live residency
    /// `account_udp_drops` can exclude. `rx_scan_pending`'s `skip()`
    /// is what keeps the offered count honest: poll may stop
    /// mid-queue on the egress budget, and a re-scan must not
    /// double-offer the carry-over prefix (poll consumes
    /// front-to-back, so carry-over is always a prefix).
    fn scan_udp_offered(&mut self) {
        self.stats.rx_queue_max = self.stats.rx_queue_max.max(self.device.rx_queue.len());
        for pkt in self.device.rx_queue.iter().skip(self.rx_scan_pending) {
            let Some(port) = udp_dst_port(pkt) else {
                continue;
            };
            match self.udp.values_mut().find(|st| st.local.port() == port) {
                Some(st) => st.rx_offered += 1,
                None => {
                    note_count(
                        &mut self.stats.rx_udp_unclaimed,
                        1,
                        format_args!(
                            "wireguard {}: inner UDP datagram for :{port} \
                             has no bound socket",
                            self.name
                        ),
                    );
                }
            }
        }
    }

    /// ITEM C1 post-service drop tally — the exact in-poll loss count
    /// smoltcp's `udp::Socket::process` performs silently (its rx
    /// `PacketBuffer::enqueue` failure returns no error upstack). Per
    /// socket, `offered − dequeued − confirmed` is in flight or lost;
    /// datagrams still waiting in `rx_queue` or bounded inside the
    /// socket's rx buffer are excluded, so only real drops confirm.
    fn account_udp_drops(&mut self) {
        for (handle, st) in &mut self.udp {
            let unaccounted = st
                .rx_offered
                .saturating_sub(st.rx_dequeued)
                .saturating_sub(st.rx_sockbuf_dropped);
            if unaccounted == 0 {
                continue;
            }
            let still_queued = self
                .device
                .rx_queue
                .iter()
                .filter(|pkt| udp_dst_port(pkt) == Some(st.local.port()))
                .count() as u64;
            let socket = self.sockets.get::<udp::Socket>(*handle);
            // An upper bound on datagrams alive inside the rx buffer:
            // slot count, or payload bytes (each datagram ≥ 1 B).
            // Only the excess over both queues is a confirmed drop —
            // the bound never over-counts, so the gate under-reports
            // rather than invents loss.
            let in_socket = if socket.can_recv() {
                socket.packet_recv_capacity().min(socket.recv_queue()) as u64
            } else {
                0
            };
            let confirmed = unaccounted
                .saturating_sub(still_queued)
                .saturating_sub(in_socket);
            if confirmed > 0 {
                st.rx_sockbuf_dropped += confirmed;
                self.stats.rx_sockbuf_dropped += confirmed;
                note_drop(
                    &self.stats.dropped_rx,
                    confirmed,
                    format_args!(
                        "wireguard {}: UDP {handle:?} rx socket buffer full — \
                         {confirmed} datagram(s) dropped inside poll",
                        self.name
                    ),
                );
            }
        }
        // Everything left in `rx_queue` was offered already.
        self.rx_scan_pending = self.device.rx_queue.len();
    }

    /// ITEM C1 periodic DEBUG snapshot. smoltcp 0.13 exposes no TCP
    /// retransmit/RTO counter, so the RTO proxy is public state: a
    /// nonzero `send_queue` unmoved across snapshots (`snap_txq_at`)
    /// is the ~1 s min-RTO stall signature, next to `timeout()` and
    /// the window/occupancy surfaces the spec asks for.
    fn log_socket_stats(&mut self) {
        if self.last_stats.elapsed() < STATS_SNAPSHOT_INTERVAL {
            return;
        }
        self.last_stats = StdInstant::now();
        debug!(
            "wireguard {}: C1 gate dropped_rx={} dropped_tx={} \
             (rx_sockbuf={} rx_chan={} rx_buf_full_obs={} rx_occ_max={}B \
             rxq_max={} | tx_buf_full={} tx_err={}) unclaimed={} \
             tcp_tx_stall={} outbox_dropped={}",
            self.name,
            self.stats.dropped_rx.load(Ordering::Relaxed),
            self.stats.dropped_tx.load(Ordering::Relaxed),
            self.stats.rx_sockbuf_dropped,
            self.stats.rx_chan_dropped,
            self.stats.rx_buf_full_obs,
            self.stats.rx_occ_max,
            self.stats.rx_queue_max,
            self.stats.tx_buf_full,
            self.stats.tx_err_dropped,
            self.stats.rx_udp_unclaimed,
            self.stats.tcp_tx_stall,
            self.stats.outbox_dropped,
        );
        for (handle, st) in &mut self.tcp {
            let socket = self.sockets.get::<tcp::Socket>(*handle);
            let txq = socket.send_queue();
            if txq != st.snap_txq {
                st.snap_txq = txq;
                st.snap_txq_at = StdInstant::now();
            }
            debug!(
                "wireguard {}: TCP {handle:?} {:?} peer={:?} \
                 txq={}B/{}B rxq={}B/{}B can_send={} may_send={} \
                 can_recv={} txq_unmoved={:?} timeout={:?} \
                 out_items={} read_backlog={}",
                self.name,
                socket.state(),
                socket.remote_endpoint(),
                txq,
                socket.send_capacity(),
                socket.recv_queue(),
                socket.recv_capacity(),
                socket.can_send(),
                socket.may_send(),
                socket.can_recv(),
                (txq > 0).then(|| st.snap_txq_at.elapsed()),
                socket.timeout(),
                st.out.len(),
                st.pending_read.len(),
            );
        }
        for (handle, st) in &self.udp {
            let socket = self.sockets.get::<udp::Socket>(*handle);
            debug!(
                "wireguard {}: UDP {handle:?} local={} \
                 rxq={}B/{}B txq={}B/{}B offered={} dequeued={} \
                 out_backlog={}",
                self.name,
                st.local,
                socket.recv_queue(),
                socket.payload_recv_capacity(),
                socket.send_queue(),
                socket.payload_send_capacity(),
                st.rx_offered,
                st.rx_dequeued,
                st.out.len(),
            );
        }
        // The occupancy peaks are per-window maxima — reset so each
        // snapshot reports this interval's worst case, not the
        // historical one.
        self.stats.rx_occ_max = 0;
        self.stats.rx_queue_max = 0;
    }

    /// ITEM C1 test accessor — read the gate counters after a driven
    /// pass; the snapshot struct lives in `meow-wgstack`.
    #[cfg(test)]
    pub(crate) fn stats(&self) -> &DropStats {
        &self.stats
    }

    /// The RX flood loop `run` opens every pass with, factored so
    /// `service_pass` can re-run it mid-pass: drain the endpoint channel
    /// until it goes quiet — a dropped wire datagram is an unrecoverable
    /// inner-TCP hole (≥1 s RTO), while every TX backlog form waits
    /// safely. `RX_PASS_CAP` only bounds the pass against livelock.
    fn drain_wire_flood(&mut self) -> usize {
        let mut spent = 0usize;
        loop {
            let got = self.drain_wire(|jobs| Self::offload_crypto(jobs, CryptoPool::run_shared));
            spent += got;
            if got < WIRE_DRAIN_BUDGET || spent >= RX_PASS_CAP {
                self.rx_last_service = StdInstant::now();
                return spent;
            }
        }
    }

    /// D3 — re-service the wire-RX channel when the last drain is
    /// [`RX_SERVICE_INTERVAL`] stale. Long synchronous loops
    /// (`service_sockets`, the poll burst, the mailbox drain) call this
    /// between iterations so the bridge channel is drained at a bounded
    /// interval regardless of how expensive one pass's socket or stack
    /// work becomes: a wire datagram lost to a full kernel buffer is an
    /// inner-TCP hole, every other backlog form waits losslessly — RX
    /// service frequency is the invariant.
    fn rx_heartbeat(&mut self) {
        if self.rx_last_service.elapsed() >= RX_SERVICE_INTERVAL {
            self.drain_wire_flood();
        }
    }

    /// The conn-facing half of a service pass as one method — socket
    /// service, the fairness yield, the interface poll, a second socket
    /// service, then the egress seal — so `run` and the same-pass pin
    /// drive the identical sequence.
    ///
    /// `service_sockets` runs twice (wg-perf R1): the first drains
    /// conn→socket writes and hands the conns what the *previous*
    /// pass's poll stacked; `poll_stack` then moves this pass's inbound
    /// plaintext `rx_queue` → sockets, and the second service delivers
    /// it *this* pass. Without it inbound plaintext waited a full loop
    /// plus the `select!` park (up to `IDLE_SLEEP`) for the next pass's
    /// service — the 12.7 ms RTT cadence the latency fix removes.
    ///
    /// `run_crypto` is `drain_device_tx`'s seal strategy — see
    /// [`offload_crypto`](Self::offload_crypto).
    async fn service_pass(&mut self, run_crypto: impl FnOnce(&mut Vec<TxCryptoJob>)) {
        self.service_sockets();
        // A service pass is synchronous end to end; on the shared
        // worker pool a saturated flow would otherwise monopolise a
        // thread between `select!` parks. Yield once per rolling MiB
        // moved — or per pass limit, the low-volume backstop — so
        // co-located tasks stay schedulable.
        self.last_service_passes += 1;
        if self.service_yield_due() {
            tokio::task::yield_now().await;
            self.last_service_bytes = 0;
            self.last_service_passes = 0;
        }
        // ITEM C1 hooks bracket the poll/service pair: the scan sees
        // what poll is offered, the tally sees what a full rx buffer
        // dropped, and the snapshot reports the interval's state.
        self.scan_udp_offered();
        // Mid-pass RX drain (D2): everything below is the pass's longest
        // RX-silent stretch — under duplex it would leave the bridge
        // channel unserviced for the full pass and let a peer burst
        // overflow `SO_RCVBUF`. Draining here halves the window, and
        // the just-admitted data still reaches `poll_stack` this pass —
        // the FIFO channel and the crypto pool's in-order merge keep
        // the work identical to a second pass, only sooner.
        self.drain_wire_flood();
        self.poll_stack(SmolInstant::now());
        self.service_sockets();
        self.account_udp_drops();
        self.drain_device_tx(run_crypto);
        self.log_socket_stats();
    }

    /// `run`'s pass-end park decision (wg-perf R1): a pass that moved
    /// payload — `last_service_bytes` advanced past the `pass_bytes`
    /// snapshot `run` took at loop top — may have follow-on work
    /// already queued (a full wire drain, a just-fed conn channel, a
    /// window an inbound ACK just opened), so the loop must not park:
    /// `ZERO` still runs the `select!`'s other arms one nonblocking
    /// poll before the next pass. A quiet pass sleeps exactly what
    /// `sleep_duration` reports.
    fn pass_delay(&mut self, pass_bytes: usize) -> Duration {
        // A quiet pass may still hold staged inner packets: `rx_hold`
        // entries are one `fill_rx_queue` away from the stack —
        // sleeping would strand them on a timer.
        if self.last_service_bytes == pass_bytes && self.device.rx_hold.is_empty() {
            self.sleep_duration(SmolInstant::now())
        } else {
            Duration::ZERO
        }
    }

    async fn run(mut self) {
        self.kick_handshake();
        self.flush_outbox();
        'outer: loop {
            // Progress guard for the pass-end park — see `pass_delay`.
            // Snapshot before `drain_wire`, the pass's first byte mover;
            // a mid-pass yield resets the counter and the inequality
            // still reports progress.
            let pass_bytes = self.last_service_bytes;
            // 1. endpoint → tunn → device (bounded nonblocking drain).
            //    `drain_wire`'s Phase-B crypto pass joins the pool's
            //    resident workers on a blocking `mpsc::recv` while
            //    holding the pool's pass mutex — `offload_crypto` moves
            //    that wait off this shared worker, but only once the
            //    demux actually produced a parallel-sized batch.
            //    Under flood the drain loops until the endpoint goes
            //    quiet: a dropped wire datagram is an unrecoverable
            //    inner-TCP loss (≥1 s RTO), while every form of TX
            //    backlog — `tx_queue`, `outbox`, the sockets' own send
            //    buffers — waits safely. RX starvation is the one
            //    failure this loop cannot defer; `RX_PASS_CAP` is only
            //    the livelock guard, the select's recv arm keeps the
            //    loop turning regardless.
            self.drain_wire_flood();
            // 2. mailbox drain.
            loop {
                self.rx_heartbeat();
                match self.rx.try_recv() {
                    Ok(ActorMsg::Shutdown) | Err(mpsc::error::TryRecvError::Disconnected) => {
                        break 'outer
                    }
                    // The sole `ActorMsg` sender lives in `PumpHandle`,
                    // so `is_closed` fires the moment the handle drops —
                    // while queued items still drain ahead of the
                    // `Disconnected` verdict. A dial drained now would
                    // build a conn on a pump that exits this pass (dead
                    // on arrival); dropping the item instead lets its
                    // reply channel report the failure. This is the
                    // full-mailbox hole `PumpHandle::drop`'s best-effort
                    // `try_send(Shutdown)` leaves.
                    Ok(_) if self.rx.is_closed() => break 'outer,
                    Ok(msg) => self.handle_msg(msg),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }
            // 3. conn queues, smoltcp poll, tunnel egress, WG timers.
            self.service_pass(|jobs| Self::offload_crypto(jobs, CryptoPool::run_tx_shared))
                .await;
            if self.last_timer.elapsed() >= WG_TIMER_INTERVAL {
                self.tick_timers();
                self.last_timer = StdInstant::now();
            }
            self.flush_outbox();

            let delay = self.pass_delay(pass_bytes);
            tokio::select! {
                biased;
                msg = self.rx.recv() => match msg {
                    None | Some(ActorMsg::Shutdown) => break 'outer,
                    // The dead-on-arrival guard above, on the parked
                    // path: queued items that outlive the last sender
                    // are refused, not serviced.
                    Some(_) if self.rx.is_closed() => break 'outer,
                    Some(m) => self.handle_msg(m),
                },
                r = self.endpoint.recv(&mut self.recv_buf) => match r {
                    Ok(n) => {
                        self.last_service_bytes += n;
                        // `decapsulate_wire` consumes the datagram
                        // buffer: a DATA packet decrypts in place and
                        // the buffer leaves with its plaintext `Bytes`,
                        // so a fresh full-size one replaces it (the
                        // batch drain uses pooled slots instead).
                        let pkt = std::mem::take(&mut self.recv_buf);
                        self.recv_buf = self
                            .decapsulate_wire(pkt, n)
                            .unwrap_or_else(|| vec![0u8; self.scratch_len]);
                    }
                    Err(e) => {
                        // Both endpoint flavours reach `recv` through an
                        // RX bridge channel now — `Proxy` explicitly,
                        // `Batch` via `BridgedEndpoint` — so an error
                        // here is always a closed channel: the RX task
                        // exits only on conn/socket death (or endpoint
                        // drop, which cannot happen while the pump owns
                        // it). `ConnectionReset` is therefore terminal,
                        // not transient: spinning cannot revive the
                        // wire and would only warn-storm at ~100 Hz
                        // while outbound datagrams blackhole. Stop the
                        // pump; `ensure_pump` sees the dead task via
                        // `is_proxy_dead`, clears the slot and redials.
                        warn!(
                            "wireguard {}: endpoint dead ({e}), stopping pump",
                            self.name
                        );
                        break 'outer;
                    }
                },
                _ = self.wake.notified() => {},
                _ = tokio::time::sleep(delay) => {},
            }
        }
        debug!("wireguard {}: pump stopped", self.name);
    }
}

/// Spawn the pump actor for one WireGuard adapter as a `tokio` task on
/// the caller's runtime (perf-7 P7-2 — the dedicated `std::thread` +
/// current-thread runtime it replaces was a `!Send` quiche precedent;
/// smoltcp is `Send`, proven by the const assert above). The pump is
/// built *synchronously* and is infallible: socket reactor/nonblocking
/// setup moved out to the adapter's endpoint binding with the
/// `Endpoint` split, so `ensure_pump`'s endpoint-fallback loop only
/// ever retries bind/connect failures upstream of this call.
/// Needs a multi-thread runtime context twice over: `tokio::spawn`
/// itself, and `run`'s `block_in_place` crypto joins — the production
/// runtime is one.
pub(crate) fn spawn_pump(
    config: &WireGuardConfig,
    endpoint: Endpoint,
    endpoint_addr: SocketAddr,
) -> (mpsc::Sender<ActorMsg>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<ActorMsg>(ACTOR_MAILBOX);
    let pump = WgPump::new(config, endpoint, endpoint_addr, rx);
    (tx, tokio::spawn(pump.run()))
}

/// `ProxyPacketConn` shim for a smoltcp UDP socket. `write_packet` enqueues
/// a datagram for the pump after allowed-IPs / family pre-checks;
/// `read_packet` drains the pump's recv channel.
pub(crate) struct WgPacketConn {
    local: SocketAddr,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
    tx: mpsc::Sender<UdpIo>,
    wake: Arc<tokio::sync::Notify>,
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
                self.wake.notify_one();
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
        self.wake.notify_one();
        Ok(len)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local)
    }

    fn close(&self) -> Result<()> {
        if !self.closed.swap(true, Ordering::Relaxed) {
            let _ = self.tx.try_send(UdpIo::Close);
            self.wake.notify_one();
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
    //! `pending_write` FIFO, `TcpIo` ordering, and
    //! `WgPacketConn`'s pre-send policy checks.
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use meow_wgstack::{BridgedEndpoint, TcpIo, WgStream};
    use tokio::io::AsyncWrite;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    fn stream_pair(cap: usize) -> (WgStream, mpsc::Receiver<TcpIo>, Arc<tokio::sync::Notify>) {
        let (tx, rx) = mpsc::channel(cap);
        let (_read_tx, read_rx) = mpsc::channel(4);
        let wake = Arc::new(tokio::sync::Notify::new());
        (
            WgStream {
                remote: "t".into(),
                rx: read_rx,
                tx,
                wake: Arc::clone(&wake),
                pending_read: None,
                pending_write: None,
                write_reserve: None,
                write_permit: None,
                read_eof: false,
                write_done: false,
            },
            rx,
            wake,
        )
    }

    #[test]
    fn poll_write_parks_on_full_queue_and_resumes_after_drain() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let (mut stream, mut rx, _) = stream_pair(2);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"aa"),
            Poll::Ready(Ok(2))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"bb"),
            Poll::Ready(Ok(2))
        ));
        // Queue full → the item is stashed, the poll parks on a channel
        // reservation (`write_reserve`).
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"cc"),
            Poll::Pending
        ));
        assert!(stream.pending_write.is_some());
        // The pump drains both queued items — freed capacity is the wake
        // the reservation waits on; no separate notify exists.
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Data(_))));
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Data(_))));
        // AsyncWrite contract: a `Pending` write is retried with the SAME
        // buf — the stash already carries its bytes, so the flush must
        // deliver them exactly once.
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"cc"),
            Poll::Ready(Ok(2))
        ));
        match rx.try_recv() {
            Ok(TcpIo::Data(b)) => assert_eq!(&b[..], b"cc"),
            other => panic!("expected Data(cc), got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "a same-buf retry must not duplicate the stashed payload"
        );
        // A fresh write with room proceeds normally.
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"dd"),
            Poll::Ready(Ok(2))
        ));
        match rx.try_recv() {
            Ok(TcpIo::Data(b)) => assert_eq!(&b[..], b"dd"),
            other => panic!("expected Data(dd), got {other:?}"),
        }
    }

    #[test]
    fn poll_shutdown_orders_behind_pending_data() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let (mut stream, mut rx, _) = stream_pair(2);
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
        let (mut stream, mut rx, _) = stream_pair(1);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"x"),
            Poll::Ready(Ok(1))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Pending
        ));
        assert!(rx.try_recv().is_ok());
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Shutdown)));
    }

    /// P4 — the conn→pump wake is the shared `Notify`, pulse-merging:
    /// a write's nudge stores a permit even with no waiter parked (the
    /// `notified()` future created *after* the pulse still resolves —
    /// the select arm can never miss a nudge the way a non-polled
    /// `try_send` could drop past a full queue), and merged pulses
    /// leave exactly one permit.
    #[test]
    fn stream_write_pulses_shared_notify() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let (mut stream, _rx, wake) = stream_pair(4);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"aa"),
            Poll::Ready(Ok(2))
        ));
        let mut notified = std::pin::pin!(wake.notified());
        assert!(
            matches!(notified.as_mut().poll(&mut cx), Poll::Ready(())),
            "the write's nudge must wake a parked actor"
        );
        let mut again = std::pin::pin!(wake.notified());
        assert!(
            matches!(again.as_mut().poll(&mut cx), Poll::Pending),
            "a single nudge is one permit, not a queue of items"
        );
    }

    #[test]
    fn drop_sends_close_while_write_side_open() {
        let (stream, mut rx, _) = stream_pair(4);
        drop(stream);
        assert!(matches!(rx.try_recv(), Ok(TcpIo::Close)));
    }

    #[test]
    fn drop_after_shutdown_sends_nothing() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let (mut stream, mut rx, _) = stream_pair(4);
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

    /// Wrap a test socket as the direct-path `Endpoint` — the same
    /// `set_nonblocking` + `from_std` + `connected` dance
    /// `WireGuardAdapter::bind_endpoint` performs. `peer` stamps the
    /// bridge's channel items — pass the address the socket connects
    /// to.
    fn test_endpoint(std_sock: std::net::UdpSocket, peer: SocketAddr) -> Endpoint {
        std_sock.set_nonblocking(true).expect("nonblocking");
        Endpoint::Batch(BridgedEndpoint::connected(
            tokio::net::UdpSocket::from_std(std_sock).expect("tokio socket"),
            peer,
        ))
    }

    /// A pump on a bound-but-idle loopback endpoint socket.
    /// `test_endpoint` registers the socket with the current reactor, so
    /// call this only inside a `#[tokio::test]` runtime.
    fn pump_for_test(cfg: &WireGuardConfig) -> WgPump {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
        let (_tx, rx) = mpsc::channel(4);
        let endpoint: SocketAddr = "127.0.0.1:9".parse().unwrap();
        WgPump::new(cfg, test_endpoint(std_sock, endpoint), endpoint, rx)
    }

    /// `pump_for_test` over a caller-prepared endpoint socket — the
    /// outbox-flush tests need a socket connected to a real receiver
    /// so datagrams are observable on the wire.
    fn pump_with_socket(
        cfg: &WireGuardConfig,
        std_sock: std::net::UdpSocket,
        endpoint: SocketAddr,
    ) -> WgPump {
        let (_tx, rx) = mpsc::channel(4);
        WgPump::new(cfg, test_endpoint(std_sock, endpoint), endpoint, rx)
    }

    /// An outbox-ready Vec: capacity at least `scratch_len` (so
    /// `return_scratch` pools it) with `tag` as its only payload byte —
    /// content order is observable via `v[0]` down the whole test.
    fn tagged_outbox_vec(tag: u8, scratch_len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(scratch_len);
        v.push(tag);
        v
    }

    /// Arm the endpoint's cached *writable* readiness through the only
    /// public async call `Endpoint` forwards — `recv`. The poll
    /// never resolves (nothing ever arrives), but while it parks the
    /// reactor reports the socket's ready bits and `try_send` stops
    /// short-circuiting `WouldBlock` so it reaches the real syscall.
    async fn arm_writable(endpoint: &mut Endpoint) {
        let mut buf = [0u8; 16];
        let _ = tokio::time::timeout(Duration::from_millis(250), endpoint.recv(&mut buf)).await;
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
        let n = match server.format_handshake_initiation(&mut buf, false) {
            // Cloudflare WARP's identifier — non-zero, stamped into the
            // reserved field of every inbound header.
            TunnResult::WriteToNetwork(b) => {
                b[1..4].copy_from_slice(&[13, 53, 133]);
                b.len()
            }
            other => panic!("expected WriteToNetwork, got {other:?}"),
        };

        pump.recv_buf[..n].copy_from_slice(&buf[..n]);
        // `decapsulate_wire` consumes the datagram buffer like the
        // select arm does — take it out of `self`, then restore what
        // it hands back (a non-data packet never consumes the slot).
        let pkt = std::mem::take(&mut pump.recv_buf);
        pump.recv_buf = pump
            .decapsulate_wire(pkt, n)
            .expect("a handshake packet returns the slot");

        // A valid initiation produces a HANDSHAKE_RESP (type 2) queued
        // for the wire. Without the scrub the parser rejects the
        // datagram and the outbox stays empty.
        assert_eq!(pump.outbox.len(), 1, "handshake response queued");
        assert_eq!(pump.outbox[0][0], 2, "response is a WG handshake response");
        // The taken recv_buf must be restored — an empty buffer left
        // behind would make every later endpoint.recv a 0-byte read.
        assert!(!pump.recv_buf.is_empty(), "recv_buf restored after take");
    }

    /// Tests feed datagrams as bare Vecs — the Vec's own length is the
    /// wire bound — and the slot `decapsulate_wire` hands back is
    /// dropped (a non-data result never consumes it anyway).
    fn feed_wire(pump: &mut WgPump, datagram: Vec<u8>) {
        let n = datagram.len();
        pump.decapsulate_wire(datagram, n);
    }

    /// Drive one handshake between `pump.tunn` (initiator) and `server`
    /// (responder) entirely through `decapsulate_wire`, so the outbox
    /// ends holding the client's post-response keepalive — which this
    /// helper drains back into `server` to complete the session on both
    /// sides. Returns nothing; panics on any protocol deviation.
    fn session_up(pump: &mut WgPump, server: &mut Tunn) {
        let mut wire = vec![0u8; 2048];
        let init = {
            let TunnResult::WriteToNetwork(b) =
                pump.tunn.format_handshake_initiation(&mut wire, false)
            else {
                panic!("initiator formats an initiation");
            };
            b.to_vec()
        };
        let resp = {
            let TunnResult::WriteToNetwork(b) = server.decapsulate(None, &init, &mut wire) else {
                panic!("responder answers the initiation");
            };
            b.to_vec()
        };
        feed_wire(pump, resp);
        let keepalive = pump
            .outbox
            .pop_front()
            .expect("response yields a keepalive");
        let res = server.decapsulate(None, &keepalive, &mut wire);
        assert!(
            matches!(res, TunnResult::Done),
            "responder consumes the keepalive, got {res:?}"
        );
    }

    /// A data datagram `pump`'s session ring cannot map: `server`
    /// encapsulates under a *second* initiator session minted with the
    /// pump's own static key, which flipped the responder's `current`
    /// to the newest session — the same rule that makes an established
    /// peer roam. The rogue's sender index ends in a low byte the
    /// pump's own first session also uses, so the `receiver_idx` lands
    /// on a ring slot the pump holds under a different generation:
    /// `WrongIndex`, deterministically — undecryptable noise-state
    /// divergence, not a crypto failure.
    fn desync_datagram(
        client_secret: &x25519::StaticSecret,
        server_public: &x25519::PublicKey,
        server: &mut Tunn,
    ) -> Vec<u8> {
        // A same-key second initiator: its session indices live in a
        // namespace the pump's ring never held.
        let mut rogue = Tunn::new(
            x25519::StaticSecret::from(client_secret.to_bytes()),
            *server_public,
            None,
            None,
            9,
            None,
        );
        let mut wire = vec![0u8; 2048];
        let rogue_init = {
            let TunnResult::WriteToNetwork(b) = rogue.format_handshake_initiation(&mut wire, false)
            else {
                panic!("rogue formats an initiation");
            };
            b.to_vec()
        };
        let rogue_resp = {
            let TunnResult::WriteToNetwork(b) = server.decapsulate(None, &rogue_init, &mut wire)
            else {
                panic!("responder answers the rogue initiation");
            };
            b.to_vec()
        };
        let rogue_keepalive = {
            let TunnResult::WriteToNetwork(b) = rogue.decapsulate(None, &rogue_resp, &mut wire)
            else {
                panic!("rogue consumes the response");
            };
            b.to_vec()
        };
        // The responder's `current` flips to the newest session on the
        // first data packet it decrypts from it.
        let res = server.decapsulate(None, &rogue_keepalive, &mut wire);
        assert!(matches!(res, TunnResult::Done), "got {res:?}");

        // Replies now leave under the rogue session.
        let TunnResult::WriteToNetwork(b) = server.encapsulate(&[], &mut wire) else {
            panic!("responder encapsulates under the newest session");
        };
        b.to_vec()
    }

    /// A data datagram addressed to a session this initiator never
    /// completed — here, one the responder minted for a *second*
    /// initiator instance sharing the static key, which flipped the
    /// responder's `current` to the newest session — proves the noise
    /// state has diverged: every reply keeps arriving under indices the
    /// ring cannot map (`NoCurrentSession`/`WrongIndex`) until a newer
    /// session of ours exists. boringtun's own recovery is the
    /// KEEPALIVE+REKEY_TIMEOUT ladder — ~15 s of one-way traffic before
    /// `want_handshake` fires, long past every pending dial's deadline.
    /// The pump must instead kick a fresh handshake on the first such
    /// error; the kick itself is bounded by the in-flight dedup and
    /// the [`DESYNC_KICK_INTERVAL`] floor, both pinned below.
    #[tokio::test(flavor = "current_thread")]
    async fn desync_data_packet_kicks_handshake() {
        let client_secret = x25519::StaticSecret::from([0x51; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0x52; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));
        let mut server = Tunn::new(server_secret, client_public, None, None, 0, None);
        session_up(&mut pump, &mut server);
        pump.outbox.clear();

        let datagram = desync_datagram(&client_secret, &server_public, &mut server);
        feed_wire(&mut pump, datagram);

        assert!(
            pump.outbox.iter().any(|d| d.len() == 148 && d[0] == 1),
            "a diverged-session datagram must kick a fresh handshake initiation"
        );
    }

    /// The in-flight bound: while the kicked handshake is still
    /// unanswered, a flood of diverged datagrams mints no further
    /// initiation — `format_handshake_initiation(_, false)` returns
    /// `Done` until a response lands (and the floor, stamped by the
    /// first kick, has not elapsed either). One initiation is the
    /// whole point of the kick; the flood buys nothing while it is
    /// in flight.
    #[tokio::test(flavor = "current_thread")]
    async fn desync_flood_dedups_while_in_flight() {
        let client_secret = x25519::StaticSecret::from([0x57; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0x58; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));
        let mut server = Tunn::new(server_secret, client_public, None, None, 0, None);
        session_up(&mut pump, &mut server);
        pump.outbox.clear();

        let desync = desync_datagram(&client_secret, &server_public, &mut server);
        for _ in 0..4 {
            feed_wire(&mut pump, desync.clone());
        }

        let inits = pump
            .outbox
            .iter()
            .filter(|d| d.len() == 148 && d[0] == 1)
            .count();
        assert_eq!(
            inits, 1,
            "an in-flight handshake must dedup the flood to one initiation"
        );
    }

    /// The floor bound — the cap the in-flight dedup cannot give:
    /// once the kicked handshake *completes*, `is_in_progress` is
    /// gone, so a flood of forged `receiver_idx` datagrams (DATA
    /// carries no mac1) would mint a fresh initiation every RTT —
    /// ~200/s on a 5 ms path — each reply spending the responder's
    /// 2×DH+2×AEAD. With the floor, a second diverged datagram
    /// inside [`DESYNC_KICK_INTERVAL`] mints nothing: the sustained
    /// ceiling is 0.2 initiations/s while a genuine desync still
    /// kicks on the first error.
    #[tokio::test(flavor = "current_thread")]
    async fn desync_kick_rate_floor_holds_across_handshakes() {
        let client_secret = x25519::StaticSecret::from([0x59; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0x5a; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));
        let mut server = Tunn::new(server_secret, client_public, None, None, 0, None);
        session_up(&mut pump, &mut server);
        pump.outbox.clear();

        let desync = desync_datagram(&client_secret, &server_public, &mut server);

        // Kick #1: the first error always fires.
        feed_wire(&mut pump, desync.clone());
        let init = pump.outbox.pop_front().expect("first desync kicks");
        assert!(
            init.len() == 148 && init[0] == 1,
            "the kick is a handshake initiation"
        );
        pump.outbox.clear();

        // Answer that initiation so `is_in_progress` clears — the
        // exact state the forged flood reopens at every RTT.
        let mut wire = vec![0u8; 2048];
        let resp = {
            let TunnResult::WriteToNetwork(b) = server.decapsulate(None, &init, &mut wire) else {
                panic!("responder answers the kicked initiation");
            };
            b.to_vec()
        };
        feed_wire(&mut pump, resp);
        pump.outbox.clear(); // the post-response keepalive

        // A second diverged datagram inside the floor mints nothing.
        feed_wire(&mut pump, desync);
        assert!(
            !pump.outbox.iter().any(|d| d.len() == 148 && d[0] == 1),
            "a second desync inside REKEY_TIMEOUT must not mint another initiation"
        );
    }

    /// The `NoCurrentSession` arm: a datagram whose `receiver_idx`
    /// names a ring slot the pump never filled takes the same kick
    /// path as `WrongIndex`. It is forgeable at line rate — a DATA
    /// packet's `receiver_idx` rides in the clear, unauthenticated —
    /// which is exactly why the floor above has to exist.
    #[tokio::test(flavor = "current_thread")]
    async fn desync_empty_slot_kicks_handshake() {
        let client_secret = x25519::StaticSecret::from([0x5b; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0x5c; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));
        let mut server = Tunn::new(server_secret, client_public, None, None, 0, None);
        session_up(&mut pump, &mut server);
        pump.outbox.clear();

        // A real reply datagram carries the pump's live `receiver_idx`
        // in cleartext; +1 lands on a slot the single-session ring
        // never filled — `NoCurrentSession`, not `WrongIndex`.
        let mut wire = vec![0u8; 2048];
        let mut forged = {
            let TunnResult::WriteToNetwork(b) = server.encapsulate(&[], &mut wire) else {
                panic!("responder encapsulates under the current session");
            };
            b.to_vec()
        };
        let live_idx = u32::from_le_bytes(forged[4..8].try_into().unwrap());
        forged[4..8].copy_from_slice(&live_idx.wrapping_add(1).to_le_bytes());

        feed_wire(&mut pump, forged);

        assert!(
            pump.outbox.iter().any(|d| d.len() == 148 && d[0] == 1),
            "an empty-slot datagram must kick a fresh handshake initiation"
        );
    }

    /// The complement of the desync pin: ordinary crypto noise — here
    /// a corrupted data datagram from the *current* session — must not
    /// kick anything. Otherwise a spoofed garbage datagram could drive
    /// endless initiations at the endpoint's rate.
    #[tokio::test(flavor = "current_thread")]
    async fn corrupt_data_packet_does_not_kick_handshake() {
        let client_secret = x25519::StaticSecret::from([0x53; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0x54; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));
        let mut server = Tunn::new(server_secret, client_public, None, None, 0, None);
        session_up(&mut pump, &mut server);

        // One data packet pump→server flips the responder's `current`
        // to the shared session, so its reply datagrams carry an index
        // the pump does hold — corrupting a payload byte then exercises
        // the AEAD-failure path, which is not divergence.
        let probe = {
            let mut wire = vec![0u8; 2048];
            let TunnResult::WriteToNetwork(b) = pump.tunn.encapsulate(&[], &mut wire) else {
                panic!("initiator encapsulates a keepalive");
            };
            b.to_vec()
        };
        let mut wire = vec![0u8; 2048];
        let res = server.decapsulate(None, &probe, &mut wire);
        assert!(matches!(res, TunnResult::Done), "got {res:?}");

        let mut forged = {
            let TunnResult::WriteToNetwork(b) = server.encapsulate(&[], &mut wire) else {
                panic!("responder encapsulates under the current session");
            };
            b.to_vec()
        };
        let last = forged.len() - 1;
        forged[last] ^= 0x5a;
        pump.outbox.clear();
        feed_wire(&mut pump, forged);

        assert!(
            !pump.outbox.iter().any(|d| d.len() == 148 && d[0] == 1),
            "an AEAD failure must not trigger a handshake"
        );
    }

    /// PATCH(20) at the pump seam — the "UDP never recovers after
    /// session expiry" mechanism end to end. With an initiation in
    /// flight and unanswered, once that initiation is REKEY_TIMEOUT
    /// old the next inner datagram must push a *new* initiation onto
    /// the outbox (`encapsulate`'s stale re-arm — the kernel's
    /// `wg_packet_send_queued_handshake_initiation`), not sit queued
    /// behind a dedup'd handshake. The responder's answer then
    /// establishes the session and flushes every queued datagram.
    ///
    /// The wait is the real clock: the predicate is the in-flight
    /// init's `time_sent` age on `sleepyinstant` (CLOCK_MONOTONIC /
    /// CLOCK_BOOTTIME) — tokio's paused clock cannot touch it, no
    /// `mock_instant` offset reaches this crate's build, and
    /// fabricating a past Instant would need new constructors on all
    /// three Instant backends just for tests. One 5.2 s sleep is the
    /// honest crossing of the 5 s REKEY_TIMEOUT.
    #[tokio::test(flavor = "current_thread")]
    async fn stale_in_flight_initiation_rearms_on_data() {
        let client_secret = x25519::StaticSecret::from([0xa1; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0xa2; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));
        let mut server = Tunn::new(server_secret, client_public, None, None, 0, None);
        let mut wire = vec![0u8; 2048];

        // An initiation in flight with no session behind it — the
        // state every post-expiry re-handshake generation sits in.
        let TunnResult::WriteToNetwork(_) = pump.tunn.format_handshake_initiation(&mut wire, false)
        else {
            panic!("initiator formats an initiation");
        };

        // The inner shape the tunnel only inspects for version
        // nibble, total length and source — last byte tags order.
        let inner = |tag: u8| -> Vec<u8> {
            vec![
                0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 10, 0, 0,
                2, 10, 0, 0, 9, 0xde, 0xad, 0xbe, tag,
            ]
        };

        // Fresh: the in-flight dedup holds — the datagram queues
        // inside `tunn` and nothing reaches the outbox.
        pump.device.tx_queue.push_back(inner(0));
        pump.drain_device_tx(CryptoPool::run_tx_shared);
        assert!(
            pump.outbox.is_empty(),
            "a fresh in-flight initiation must still dedup packet pressure"
        );

        // Cross REKEY_TIMEOUT (5 s, crate-private constant) on the
        // real clock — the in-flight initiation is now stale.
        tokio::time::sleep(Duration::from_secs_f64(5.2)).await;

        pump.device.tx_queue.push_back(inner(1));
        pump.drain_device_tx(CryptoPool::run_tx_shared);
        let resent = pump
            .outbox
            .pop_front()
            .expect("a stale in-flight initiation must re-arm on packet pressure");
        assert!(
            resent.len() == 148 && resent[0] == 1,
            "the re-armed output is a handshake initiation, got {}B type {}",
            resent.len(),
            resent[0]
        );
        // The resend re-stamps the flight: one more datagram right
        // behind it dedups again — the re-arm is per-REKEY_TIMEOUT,
        // not per-packet.
        pump.device.tx_queue.push_back(inner(2));
        pump.drain_device_tx(CryptoPool::run_tx_shared);
        assert!(
            pump.outbox.is_empty(),
            "the just-resent initiation must dedup again"
        );

        // The responder answers the *resent* initiation; the session
        // establishes and every queued datagram flushes in order:
        // keepalive (32 B empty DATA) + the three inner packets.
        let resp = {
            let TunnResult::WriteToNetwork(b) = server.decapsulate(None, &resent, &mut wire) else {
                panic!("responder answers the re-armed initiation");
            };
            b.to_vec()
        };
        feed_wire(&mut pump, resp);

        assert_eq!(
            pump.outbox.len(),
            4,
            "keepalive plus three queued datagrams flush post-handshake"
        );
        assert!(
            pump.outbox[0].len() == 32 && pump.outbox[0][0] == 4,
            "first flush item is the empty keepalive DATA datagram"
        );
        for (i, datagram) in pump.outbox.iter().skip(1).enumerate() {
            match server.decapsulate(None, datagram, &mut wire) {
                TunnResult::WriteToTunnelV4(b, _) => {
                    assert_eq!(
                        &b[..],
                        &inner(i as u8)[..],
                        "datagram {i} decrypts to the queued inner"
                    );
                }
                other => panic!("responder must decapsulate datagram {i}, got {other:?}"),
            }
        }
    }

    /// PATCH(17): an inbound DATA datagram decrypts *inside* its receive
    /// slot and the slot's Vec moves into `rx_queue` as `Bytes` — the
    /// `decapsulate`-into-scratch copy plus the `Bytes::copy_from_slice`
    /// allocation are gone, so `decapsulate_wire` returns `None` (the
    /// caller back-fills a fresh buffer) and the queued item is the
    /// plaintext IP packet bounded to it. A keepalive's plaintext is
    /// empty — `Done`, not `WriteToTunnel` — so its slot comes back.
    #[tokio::test(flavor = "current_thread")]
    async fn decapsulate_wire_moves_data_slot_into_rx_queue() {
        let client_secret = x25519::StaticSecret::from([0x61; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0x62; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));
        let mut server = Tunn::new(server_secret, client_public, None, None, 0, None);
        session_up(&mut pump, &mut server);
        pump.outbox.clear();
        pump.device.rx_queue.clear();

        // A real IPv4 packet from the responder: 20-byte header + 4
        // payload bytes (the shape `wg_vectors` uses — the tunnel only
        // inspects the version nibble, total-length and source).
        let inner: &[u8] = &[
            0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 10, 0, 0, 2,
            10, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef,
        ];
        let mut wire = vec![0u8; 2048];
        let datagram = {
            let TunnResult::WriteToNetwork(b) = server.encapsulate(inner, &mut wire) else {
                panic!("responder encapsulates the inner packet");
            };
            b.to_vec()
        };
        let n = datagram.len();

        // `None` says the decrypted packet owns the slot now; the queued
        // `Bytes` is a view into its allocation, not a copy.
        assert!(
            pump.decapsulate_wire(datagram, n).is_none(),
            "a DATA packet consumes its receive slot"
        );
        let packet = pump
            .device
            .rx_queue
            .pop_front()
            .expect("decrypted packet queued");
        assert_eq!(
            &packet[..],
            inner,
            "the plaintext IP packet arrives byte-identical"
        );

        // A keepalive decrypts to zero-length plaintext — `Done`, not
        // `WriteToTunnel`, so the slot is handed back for reuse.
        let keepalive = {
            let TunnResult::WriteToNetwork(b) = server.encapsulate(&[], &mut wire) else {
                panic!("responder encapsulates a keepalive");
            };
            b.to_vec()
        };
        let n = keepalive.len();
        let returned = pump
            .decapsulate_wire(keepalive, n)
            .expect("a keepalive does not consume the slot");
        assert_eq!(returned.len(), n);
    }

    /// `drain_wire`'s parallel path end to end with a real WireGuard
    /// session and a pre-queued burst. The first datagram rides
    /// `endpoint.recv` → `decapsulate_wire`, and the rest batch through `recv_batch` →
    /// `classify_incoming` → the crypto pool → `handle_decrypted_data`.
    /// Order is asserted off `rx_queue` (every decrypted inner lands in
    /// wire order) and the consumed slots come back at full capacity.
    #[tokio::test(flavor = "current_thread")]
    async fn drain_wire_parallel_decrypts_in_wire_order() {
        let client_secret = x25519::StaticSecret::from([0x91; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0x92; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);

        let (sent, _sent_rx) = mpsc::channel(1);
        let peer = SocketAddr::from(([203, 0, 113, 7], 51820));
        let local_addr = SocketAddr::from(([192, 0, 2, 4], 41000));
        let conn = Arc::new(RecordingPacketConn::new(sent, local_addr));
        let endpoint = Endpoint::Proxy(meow_wgstack::ProxyEndpoint::new(
            Arc::<RecordingPacketConn>::clone(&conn),
            peer,
            local_addr,
        ));
        let (_tx, rx) = mpsc::channel(4);
        let mut pump = WgPump::new(
            &test_config(&client_secret, &server_public),
            endpoint,
            peer,
            rx,
        );
        let mut server = Tunn::new(server_secret, client_public, None, None, 0, None);
        session_up(&mut pump, &mut server);

        // Eight DATA datagrams under consecutive counters — more than
        // the pool's `n <= 2` inline cutoff, so the batch must run the
        // worker arm for real. Each inner is the same 20-byte-header +
        // 4-payload IPv4 shape the in-place test uses (the tunnel only
        // inspects the version nibble, total length and source); the
        // last payload byte marks wire order.
        const N: usize = 8;
        let mut wire = vec![0u8; 2048];
        let mut inners = Vec::new();
        for i in 0..N {
            let inner = vec![
                0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 10, 0, 0,
                2, 10, 0, 0, 1, 0xde, 0xad, 0xbe, i as u8,
            ];
            let datagram = {
                let TunnResult::WriteToNetwork(b) = server.encapsulate(&inner, &mut wire) else {
                    panic!("responder encapsulates the inner packet");
                };
                b.to_vec()
            };
            inners.push(inner);
            conn.incoming.lock().push_back(datagram);
        }

        // The next read request proves the bridge has enqueued the entire
        // burst. Receiving the first packet alone cannot prove that.
        tokio::time::timeout(Duration::from_secs(5), conn.incoming_drained.notified())
            .await
            .expect("RX bridge must enqueue the burst");
        let n = pump
            .endpoint
            .recv(&mut pump.recv_buf)
            .await
            .expect("first datagram ready");
        let pkt = std::mem::take(&mut pump.recv_buf);
        pump.recv_buf = pump
            .decapsulate_wire(pkt, n)
            .unwrap_or_else(|| vec![0u8; pump.scratch_len]);
        pump.drain_wire(|jobs| {
            assert_eq!(jobs.len(), N - 1, "the burst must reach the worker path");
            CryptoPool::run_shared(jobs);
        });

        // Every decrypted inner reached smoltcp in wire order — the
        // first through the serial arm, the rest through the pool pass.
        assert_eq!(
            pump.device.rx_queue.len(),
            N,
            "every DATA datagram produced an inner packet"
        );
        for (i, pkt) in pump.device.rx_queue.iter().enumerate() {
            assert_eq!(
                &pkt[..],
                &inners[i][..],
                "rx_queue order must match wire order"
            );
        }
        // Consumed slots were re-armed at full capacity — the next
        // batch's `recv_batch` still sees the whole window.
        assert!(
            pump.rx_slots
                .iter()
                .all(|s| s.capacity() == pump.scratch_len),
            "every rx_slot returns at full capacity"
        );
    }

    /// PATCH(19): `drain_device_tx`'s parallel arm end to end — a real
    /// session (`session_up`), then a burst of inner packets through
    /// `tx_queue` → `TxCryptoJob` → `run_tx_shared`. The burst exceeds
    /// the `n <= 2` inline cutoff, so the pass rides real workers;
    /// every outbox datagram must decrypt at the responder back to its
    /// inner *in emit order* — job order = counter order = wire order —
    /// and every drained `tx_queue` buffer must land back in `tx_pool`.
    #[tokio::test(flavor = "current_thread")]
    async fn drain_device_tx_parallel_seals_in_job_order() {
        let client_secret = x25519::StaticSecret::from([0x93; 32]);
        let client_public = x25519::PublicKey::from(&client_secret);
        let server_secret = x25519::StaticSecret::from([0x94; 32]);
        let server_public = x25519::PublicKey::from(&server_secret);
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));
        let mut server = Tunn::new(server_secret, client_public, None, None, 0, None);
        session_up(&mut pump, &mut server);
        pump.outbox.clear();
        let pool_before = pump.device.tx_pool.len();

        // Eight inner packets — past the pool's `n <= 2` inline
        // cutoff, so the seal pass must ride real workers. The last
        // byte marks the queue position the wire order must mirror.
        const N: usize = 8;
        let mut inners = Vec::new();
        for i in 0..N {
            let inner = vec![
                0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 10, 0, 0,
                2, 10, 0, 0, 1, 0xde, 0xad, 0xbe, i as u8,
            ];
            inners.push(inner.clone());
            pump.device.tx_queue.push_back(inner);
        }
        pump.drain_device_tx(CryptoPool::run_tx_shared);

        assert_eq!(pump.outbox.len(), N, "every sealed job emitted a datagram");
        assert_eq!(
            pump.device.tx_pool.len() - pool_before,
            N,
            "every drained inner returned to tx_pool"
        );

        let mut wire = vec![0u8; 2048];
        let mut prev: Option<u64> = None;
        for (i, datagram) in pump.outbox.iter().enumerate() {
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
            match server.decapsulate(None, datagram, &mut wire) {
                TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                    assert_eq!(&b[..], &inners[i][..], "datagram {i} decrypts to inner {i}");
                }
                other => panic!("responder must decrypt datagram {i}, got {other:?}"),
            }
        }
    }

    /// `offload_crypto`'s runtime gate: a parallel-sized batch outside
    /// the multi-thread flavor must run the same `> 2` jobs serially —
    /// `block_in_place` panics under `current_thread` and
    /// `Handle::current` panics runtimeless, so neither arm may reach
    /// it. The runtimeless case is this plain `#[test]`.
    #[test]
    fn offload_crypto_runs_serially_without_a_runtime() {
        // `> 2` — the same cutoff the multi-thread arm rides past.
        let mut jobs = vec![0u32; 4];
        WgPump::offload_crypto(&mut jobs, |jobs| {
            jobs.iter_mut().for_each(|j| *j += 1);
        });
        assert_eq!(jobs, [1; 4]);
    }

    /// The same fallback with a handle present: the flavor check, not
    /// the absence of a runtime, keeps `block_in_place` off here.
    #[tokio::test(flavor = "current_thread")]
    async fn offload_crypto_runs_serially_on_current_thread() {
        let mut jobs = vec![0u32; 4];
        WgPump::offload_crypto(&mut jobs, |jobs| {
            jobs.iter_mut().for_each(|j| *j += 1);
        });
        assert_eq!(jobs, [1; 4]);
    }

    /// The positive arm — `#[tokio::test]`'s default multi-thread
    /// runtime still rides `block_in_place`, so the gate can't
    /// over-broaden into always-serial.
    #[tokio::test]
    async fn offload_crypto_offloads_on_multi_thread() {
        let mut jobs = vec![0u32; 4];
        WgPump::offload_crypto(&mut jobs, |jobs| {
            jobs.iter_mut().for_each(|j| *j += 1);
        });
        assert_eq!(jobs, [1; 4]);
    }

    /// A dial to a family the tunnel has no address for fails *inside*
    /// `dial_tcp` — before a port, socket or `connect` exists — so the
    /// caller gets a named error instead of the 25 s connect-limit burn
    /// the `addr: None` auto-selection path left behind (smoltcp 0.13
    /// then RST'd the socket on first dispatch anyway). The adapter's
    /// `check_tunnel_target` normally rejects these first; this is the
    /// in-pump backstop, symmetric with the UDP conn's `has_v4`/`has_v6`
    /// write-time check.
    #[tokio::test(flavor = "current_thread")]
    async fn dial_tcp_missing_family_fails_fast() {
        let client_secret = x25519::StaticSecret::from([0x45; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x46; 32]));
        // test_config carries `ip` only — the tunnel has no IPv6 address.
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, mut reply_rx) = oneshot::channel();
        pump.dial_tcp("[fd00::1]:443".parse().unwrap(), "t".into(), reply_tx);

        // `try_recv` resolves only if the Err was queued inside the call
        // itself — no service pass, no timer, no 25 s wait.
        let err = match reply_rx.try_recv() {
            Ok(Err(e)) => e,
            Ok(Ok(_)) => panic!("a v6 dial on a v4-only tunnel must fail"),
            Err(e) => panic!("the early Err must be queued inside dial_tcp: {e}"),
        };
        assert!(
            matches!(err, MeowError::NotSupported(_)),
            "a family miss is NotSupported, matching the udp pre-check: {err:?}"
        );
        assert!(
            err.to_string().contains("IPv6 tunnel address"),
            "the failure names the missing family: {err}"
        );
        // Nothing leaked: no socket was created and no port was taken.
        assert!(pump.tcp.is_empty(), "no TCP socket may be allocated");
        assert!(pump.used_ports.is_empty(), "no ephemeral port may be held");
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

    /// `discard_socket_rx` — the dead-conn drain: the conn half-closed
    /// gracefully (FIN flowing, `graceful_close` set), then died while
    /// the peer still had tail bytes in flight — the `FinWait` zombie
    /// case the fn's doc names. The pinned observables, all through
    /// the real `service_sockets` pass: the `Closed` channel arm calls
    /// the discard, the socket's rx residue empties (window un-pins on
    /// the next ACK), and the events parked in `pending_read` go with
    /// it. The socket itself survives — a graceful close never aborts —
    /// so the drain, not teardown, is what the assertions see.
    #[tokio::test(flavor = "current_thread")]
    async fn discard_socket_rx_drains_residue_on_dead_conn() {
        let client_secret = x25519::StaticSecret::from([0x77; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x78; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, mut reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);
        let handle = *pump.tcp.keys().next().unwrap();

        // SYN → our ISN/ephemeral port off the wire packet; the peer's
        // SYN-ACK (seq 5000) → Established.
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        let syn = pump.device.tx_queue.back().expect("the dial emitted a SYN");
        let local_port = u16::from_be_bytes([syn[20], syn[21]]);
        let isn = u32::from_be_bytes(syn[24..28].try_into().unwrap());
        let syn_ack = tcp_seg_v4(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5000,
            isn.wrapping_add(1),
            0x12,
        );
        pump.device.push_rx(Bytes::from(syn_ack));
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        assert_eq!(
            pump.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );

        // The dial resolves — the WgStream's channels are the conn ends.
        pump.service_sockets();
        let mut conn = match reply_rx.try_recv() {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => panic!("dial failed: {e}"),
            Err(e) => panic!("dial did not resolve in one pass: {e}"),
        };

        // Graceful half-close first — the FIN is flowing — then the
        // conn dies mid-tail.
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Pin::new(&mut *conn).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        pump.service_sockets(); // consumes Shutdown → close() + graceful_close
        assert_eq!(
            pump.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::FinWait1
        );
        drop(conn); // read_rx + write_tx close — the conn is dead

        // Residue: a data segment lands after the conn is gone, and two
        // events are parked in `pending_read` behind the dead channel.
        let data = tcp_seg_v4_data(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5001,
            isn.wrapping_add(1),
            0x18,
            b"dead-conn residue",
        );
        pump.device.push_rx(Bytes::from(data));
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        assert!(
            pump.sockets.get::<tcp::Socket>(handle).recv_queue() > 0,
            "rx residue must be present for the drain to matter"
        );
        let st = pump.tcp.get_mut(&handle).expect("flow state");
        st.pending_read
            .push_back(StreamEvent::Data(Bytes::from_static(b"x")));
        st.pending_read
            .push_back(StreamEvent::Data(Bytes::from_static(b"y")));

        pump.service_sockets();

        let socket = pump.sockets.get::<tcp::Socket>(handle);
        assert_eq!(
            socket.recv_queue(),
            0,
            "the discard must empty the rx buffer so the window un-pins"
        );
        assert!(!socket.can_recv());
        assert!(pump.tcp[&handle].pending_read.is_empty());
        assert!(
            pump.tcp.contains_key(&handle),
            "a graceful close never aborts — the drain emptied rx, not teardown"
        );
    }

    /// The other half of the zombie: the conn died *after* its FIN went
    /// out (`graceful_close`), and the peer never closes back — it keeps
    /// streaming into the discard drain. `conn_gone` can never enqueue
    /// `Close` while `graceful_close` holds, and smoltcp's FinWait has
    /// no timeout of its own, so without [`TCP_ORPHAN_GRACE`] the socket
    /// outlives the whole session. The bound pins both sides of it: the
    /// socket must survive inside the grace (a real close may still
    /// complete) and must be aborted past it.
    #[tokio::test(flavor = "current_thread")]
    async fn orphan_grace_aborts_socket_past_deadline() {
        let client_secret = x25519::StaticSecret::from([0x79; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x80; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, mut reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);
        let handle = *pump.tcp.keys().next().unwrap();
        let port = *pump.used_ports.iter().next().unwrap();

        // SYN → SYN-ACK → Established, then the dial resolves.
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        let syn = pump.device.tx_queue.back().expect("the dial emitted a SYN");
        let local_port = u16::from_be_bytes([syn[20], syn[21]]);
        let isn = u32::from_be_bytes(syn[24..28].try_into().unwrap());
        let syn_ack = tcp_seg_v4(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5000,
            isn.wrapping_add(1),
            0x12,
        );
        pump.device.push_rx(Bytes::from(syn_ack));
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        assert_eq!(
            pump.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );
        pump.service_sockets();
        let mut conn = match reply_rx.try_recv() {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => panic!("dial failed: {e}"),
            Err(e) => panic!("dial did not resolve in one pass: {e}"),
        };

        // Graceful half-close (FIN out), then the conn dies entirely —
        // kill -9's shape when the kernel FIN'd the user socket before
        // the flow task unwound.
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Pin::new(&mut *conn).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        pump.service_sockets(); // consumes Shutdown → close() + graceful_close
        assert_eq!(
            pump.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::FinWait1
        );
        drop(conn); // read_rx + write_tx close — the conn is dead

        // The first pass only arms the deadline: inside the grace the
        // socket must survive — a real close may still be completing.
        pump.service_sockets();
        assert!(pump.tcp.contains_key(&handle));
        assert!(pump.tcp[&handle].dead_since.is_some());

        // The peer keeps streaming instead of closing: the discard
        // drain eats its segment — the zombie window-stays-open case —
        // and the socket still survives while grace has not elapsed.
        let data = tcp_seg_v4_data(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5001,
            isn.wrapping_add(1),
            0x18,
            b"peer that never closes",
        );
        pump.device.push_rx(Bytes::from(data));
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        pump.service_sockets();
        assert_eq!(pump.sockets.get::<tcp::Socket>(handle).recv_queue(), 0);
        assert!(
            pump.tcp.contains_key(&handle),
            "inside the grace the socket must not be torn down"
        );

        // Grace expiry → abort: the socket is reaped, the ephemeral
        // port comes back, and the peer's stream actually stops — the
        // socket is out of the set, so its next segment draws the
        // no-socket RST from the iface.
        pump.tcp.get_mut(&handle).expect("flow state").dead_since =
            Some(StdInstant::now() - TCP_ORPHAN_GRACE);
        pump.service_sockets();
        assert!(
            !pump.tcp.contains_key(&handle),
            "the orphaned socket must be reaped once grace expires"
        );
        assert!(
            !pump.used_ports.contains(&port),
            "ephemeral port {port} leaked"
        );
        let late = tcp_seg_v4_data(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5010,
            isn.wrapping_add(1),
            0x18,
            b"still streaming",
        );
        pump.device.push_rx(Bytes::from(late));
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        let tail = pump
            .device
            .tx_queue
            .back()
            .expect("a segment for a dead tuple must draw an RST");
        assert_eq!(
            tail[33] & 0x04,
            0x04,
            "the peer's next segment must be answered with an RST"
        );
    }

    /// The jammed half of the bound: the conn dies with its write
    /// channel still full — a peer that stopped ACKing pinned the
    /// socket's tx buffer, `out` sits at the [`TCP_WRITE_QUEUE`] cap,
    /// and the channel itself never drains. `conn_gone`'s `is_empty`
    /// arm can never fire — no `Close` is enqueued — but a jammed
    /// closed channel is exactly as dead as a drained one, so
    /// `dead_since` must arm on `is_closed` alone, and past
    /// [`TCP_ORPHAN_GRACE`] the socket is reaped all the same.
    #[tokio::test(flavor = "current_thread")]
    async fn conn_dropped_with_full_channel() {
        let client_secret = x25519::StaticSecret::from([0x81; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x82; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, mut reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);
        let handle = *pump.tcp.keys().next().unwrap();
        let port = *pump.used_ports.iter().next().unwrap();

        // SYN → SYN-ACK → Established, then the dial resolves.
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        let syn = pump.device.tx_queue.back().expect("the dial emitted a SYN");
        let local_port = u16::from_be_bytes([syn[20], syn[21]]);
        let isn = u32::from_be_bytes(syn[24..28].try_into().unwrap());
        let syn_ack = tcp_seg_v4(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5000,
            isn.wrapping_add(1),
            0x12,
        );
        pump.device.push_rx(Bytes::from(syn_ack));
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        assert_eq!(
            pump.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );
        pump.service_sockets();
        let mut conn = match reply_rx.try_recv() {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => panic!("dial failed: {e}"),
            Err(e) => panic!("dial did not resolve in one pass: {e}"),
        };

        // Jam the socket: a window's worth of payload fills the 1 MiB
        // tx buffer and no ACK ever lands to drain it — the
        // zero-window stand-in that holds `can_send` false forever.
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let window_fill = vec![0xAB; TCP_SOCKET_BUF];
        assert!(matches!(
            Pin::new(&mut *conn).poll_write(&mut cx, &window_fill),
            Poll::Ready(Ok(_))
        ));
        pump.service_sockets();
        assert!(
            !pump.sockets.get::<tcp::Socket>(handle).can_send(),
            "the full tx buffer must pin can_send — the jam's socket half"
        );

        // Fill `out` to the drain cap, then the channel itself: the
        // backlog spans both queues — the shape a conn drop on a
        // stalled socket leaves behind.
        let chunk = [0xCD; 1024];
        while matches!(
            Pin::new(&mut *conn).poll_write(&mut cx, &chunk),
            Poll::Ready(Ok(_))
        ) {}
        pump.service_sockets();
        assert_eq!(
            pump.tcp.get(&handle).expect("flow state").out.len(),
            TCP_WRITE_QUEUE,
            "`out` must sit at the cap so the channel can never drain"
        );
        while matches!(
            Pin::new(&mut *conn).poll_write(&mut cx, &chunk),
            Poll::Ready(Ok(_))
        ) {}

        // The conn dies mid-jam: its drop-side `Close` cannot even win
        // a channel slot — both halves close with items still queued.
        drop(conn);
        pump.service_sockets();
        let st = pump.tcp.get(&handle).expect("flow state");
        assert!(
            !st.write_rx.is_empty(),
            "the jam must pin — a full channel can never go is_empty"
        );
        assert!(
            st.out.iter().all(|io| matches!(io, TcpIo::Data(_))),
            "conn_gone's is_empty arm must never have queued a Close"
        );
        assert!(
            st.dead_since.is_some(),
            "a jammed closed channel is equally dead — the arm needs no is_empty"
        );

        // Past the grace the socket is reaped anyway — state → dead,
        // port released — exactly the drained-channel outcome.
        pump.tcp.get_mut(&handle).expect("flow state").dead_since =
            Some(StdInstant::now() - TCP_ORPHAN_GRACE);
        pump.service_sockets();
        assert!(
            !pump.tcp.contains_key(&handle),
            "the jammed orphan must be reaped once grace expires"
        );
        assert!(
            !pump.used_ports.contains(&port),
            "ephemeral port {port} leaked"
        );
    }

    /// The negative half of the arm: a conn with both channel halves
    /// still held is a live flow, not an orphan — even once its FIN is
    /// out. `graceful_close` alone must never set `dead_since`; the
    /// bound only exists for a conn that is actually gone.
    #[tokio::test(flavor = "current_thread")]
    async fn live_conn_does_not_arm_dead_since() {
        let client_secret = x25519::StaticSecret::from([0x83; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x84; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, mut reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);
        let handle = *pump.tcp.keys().next().unwrap();

        // SYN → SYN-ACK → Established, then the dial resolves.
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        let syn = pump.device.tx_queue.back().expect("the dial emitted a SYN");
        let local_port = u16::from_be_bytes([syn[20], syn[21]]);
        let isn = u32::from_be_bytes(syn[24..28].try_into().unwrap());
        let syn_ack = tcp_seg_v4(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5000,
            isn.wrapping_add(1),
            0x12,
        );
        pump.device.push_rx(Bytes::from(syn_ack));
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        pump.service_sockets();
        let mut conn = match reply_rx.try_recv() {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => panic!("dial failed: {e}"),
            Err(e) => panic!("dial did not resolve in one pass: {e}"),
        };
        assert!(
            pump.tcp[&handle].dead_since.is_none(),
            "an established conn is a live flow — nothing to arm"
        );

        // Graceful half-close: FIN out, `graceful_close` set — but the
        // conn is still held, so both halves stay open and the arm
        // must not fire on the close's shape alone.
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Pin::new(&mut *conn).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        pump.service_sockets();
        assert_eq!(
            pump.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::FinWait1
        );
        assert!(
            pump.tcp[&handle].graceful_close,
            "the shutdown pass must have set graceful_close for this test to mean anything"
        );
        assert!(
            pump.tcp[&handle].dead_since.is_none(),
            "a live conn's FIN is not an orphan — dead_since stays unarmed"
        );
    }

    /// A `WgStream` parked on a full conn→pump channel waits on the
    /// channel's own capacity semaphore (`reserve_owned`), not a notify:
    /// once `service_sockets` moves the queued items into `out`, the
    /// writer's reservation resolves — this is the wake the old
    /// `drain_notify` permit tried (and intermittently failed) to be.
    #[tokio::test(flavor = "current_thread")]
    async fn writer_resumes_when_pump_drains_channel() {
        let client_secret = x25519::StaticSecret::from([0x55; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x66; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, _reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);
        let handle = *pump.tcp.keys().next().unwrap();
        let write_tx = pump.tcp[&handle]
            .pending
            .as_ref()
            .expect("pending dial")
            .write_tx
            .clone();
        write_tx
            .try_send(TcpIo::Data(Bytes::from_static(b"x")))
            .expect("channel has room");

        pump.service_sockets();

        assert_eq!(
            pump.tcp[&handle].out.len(),
            1,
            "the queued item must move from the channel into `out`"
        );
        assert!(
            write_tx
                .try_send(TcpIo::Data(Bytes::from_static(b"y")))
                .is_ok(),
            "capacity freed by the drain is the writer's wake"
        );
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

    /// ITEM C1 gate: overflow the inner UDP socket in both directions
    /// and the counters must tally the loss exactly.
    /// * inner→outer: a burst larger than the 256-slot/256 KiB rx
    ///   buffer drops the tail inside `Interface::poll` —
    ///   `rx_sockbuf_dropped` tallies it; a second round with the conn
    ///   channel still unread adds `rx_chan_dropped`. The invariants
    ///   `offered == dequeued + dropped` and
    ///   `dropped_rx == sockbuf + chan` hold exactly.
    /// * outer→inner: a full tx buffer with staged `out` datagrams
    ///   counts `tx_buf_full` and bumps `dropped_tx` — saturation
    ///   (backpressure), not a lost datagram.
    #[tokio::test(flavor = "current_thread")]
    async fn c1_udp_drop_counters_tally_socket_overflow() {
        let client_secret = x25519::StaticSecret::from([0x77; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x88; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, reply_rx) = oneshot::channel();
        pump.udp_bind(
            Arc::new(vec!["0.0.0.0/0".parse().unwrap()]),
            true,
            false,
            reply_tx,
        );
        let _conn = reply_rx
            .await
            .expect("bind reply")
            .expect("udp_bind succeeds");
        let handle = *pump.udp.keys().next().expect("one udp flow");
        let local = pump.udp[&handle].local;
        assert_eq!(local.ip(), std::net::IpAddr::from([10, 0, 0, 2]));

        // ── inner→outer, round 1: burst past the rx buffer; poll
        //    drops the tail, the conn channel absorbs the rest.
        //    Payload must fit `udp_scratch` (inner_mtu = 1356) or the
        //    drain's `recv_slice` errors instead of delivering.
        let payload = 1330usize; // 262144/1330 = 197 fill by bytes
        let offered = UDP_SOCKET_PACKETS + 64;
        let offer = |pump: &mut WgPump, base: u16| {
            for i in 0..offered {
                pump.device.push_rx(Bytes::from(udp_dgram_v4(
                    std::net::Ipv4Addr::new(10, 9, 9, 9),
                    std::net::Ipv4Addr::new(10, 0, 0, 2),
                    base + i as u16,
                    local.port(),
                    payload,
                )));
            }
        };
        offer(&mut pump, 40_000);
        pump.scan_udp_offered();
        pump.poll_stack(SmolInstant::now());
        pump.service_sockets();
        pump.account_udp_drops();

        let s = pump.stats();
        assert!(s.rx_sockbuf_dropped > 0, "poll dropped a tail");
        assert_eq!(s.rx_chan_dropped, 0, "channel had room in round 1");
        assert_eq!(
            s.dropped_rx.load(Ordering::Relaxed),
            s.rx_sockbuf_dropped,
            "dropped_rx == sockbuf drops so far"
        );
        let st = &pump.udp[&handle];
        assert_eq!(
            st.rx_offered,
            st.rx_dequeued + s.rx_sockbuf_dropped,
            "offered == dequeued + dropped inside poll"
        );
        assert!(s.rx_buf_full_obs > 0, "drain saw a saturated buffer");
        assert!(s.rx_occ_max > 0);

        // ── inner→outer, round 2: the conn channel is still unread
        //    (256 cap), so the tail falls out at try_send.
        offer(&mut pump, 50_000);
        pump.scan_udp_offered();
        pump.poll_stack(SmolInstant::now());
        pump.service_sockets();
        pump.account_udp_drops();

        let s = pump.stats();
        assert!(
            s.rx_chan_dropped > 0,
            "an unread conn channel must take drops"
        );
        assert_eq!(
            s.dropped_rx.load(Ordering::Relaxed),
            s.rx_sockbuf_dropped + s.rx_chan_dropped,
            "headline counter is the exact sum of its drop points"
        );
        let st = &pump.udp[&handle];
        assert_eq!(
            st.rx_offered,
            st.rx_dequeued + s.rx_sockbuf_dropped,
            "every offered datagram is delivered or tallied"
        );

        // ── outer→inner: wedge the tx buffer, stage `out`, and the
        //    service pass counts the no-socket-space stall.
        let dst: SocketAddr = "10.9.9.9:53".parse().unwrap();
        let socket = pump.sockets.get_mut::<udp::Socket>(handle);
        let meta = udp::UdpMetadata {
            endpoint: dst.into(),
            local_address: pump.src_v4,
            meta: Default::default(),
        };
        while socket.can_send() {
            socket.send_slice(b"x", meta).expect("tx buffer has room");
        }
        let st = pump.udp.get_mut(&handle).expect("udp state");
        st.out.push_back((Bytes::from_static(b"z"), dst));

        pump.service_sockets();

        let s = pump.stats();
        assert_eq!(s.tx_buf_full, 1, "the stalled enqueue counts once");
        assert_eq!(
            s.dropped_tx.load(Ordering::Relaxed),
            1,
            "tx saturation surfaces on the tx headline counter"
        );
        assert_eq!(
            pump.udp[&handle].out.len(),
            1,
            "BufferFull is backpressure — the datagram still waits"
        );
    }

    #[tokio::test]
    async fn packet_conn_enforces_allowed_ips_family_and_close() {
        let (_rtx, rrx) = mpsc::channel(4);
        let (wtx, _wrx) = mpsc::channel(4);
        let waketx = Arc::new(tokio::sync::Notify::new());
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

    // ── poll-burst regression ────────────────────────────────────

    /// RFC 1071 checksum over `data` — the listener-side `seg_v4`
    /// builder uses the same fold. (The device skips rx checksum
    /// verification, but a fed packet that needs no special pleading
    /// keeps the test honest.)
    fn seg_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for w in data.chunks(2) {
            let word = if w.len() == 2 {
                u16::from_be_bytes([w[0], w[1]])
            } else {
                u16::from(w[0]) << 8
            };
            sum += u32::from(word);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// A checksummed inner IPv4 TCP segment `src:sport` → `dst:dport`
    /// with arbitrary flags — the peer-side half of an in-iface
    /// handshake, fed to `device.rx_queue`.
    fn tcp_seg_v4(
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
        tcp_seg_v4_data(src, dst, sport, dport, seq, ack, flags, &[])
    }

    /// `tcp_seg_v4` carrying `payload` after the 20-octet TCP header —
    /// the wire form of bytes the peer's smoltcp delivered to ours.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per wire field; a struct would only rename the list"
    )]
    fn tcp_seg_v4_data(
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
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
        let ip_sum = seg_checksum(&p[..20]);
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
        let tcp_sum = seg_checksum(&pseudo);
        p[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
        p
    }

    /// A checksummed inner IPv4 UDP datagram `src:sport` → `dst:dport`
    /// with `payload_len` zero bytes — the wire form of wire-decrypted
    /// packets `device.rx_queue` feeds `Interface::poll`.
    fn udp_dgram_v4(
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
        sport: u16,
        dport: u16,
        payload_len: usize,
    ) -> Vec<u8> {
        let mut p = vec![0u8; 28 + payload_len];
        let total_len = p.len() as u16;
        p[0] = 0x45;
        p[2..4].copy_from_slice(&total_len.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ip_sum = seg_checksum(&p[..20]);
        p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..26].copy_from_slice(&(8u16 + payload_len as u16).to_be_bytes());
        let mut pseudo = Vec::with_capacity(28 + payload_len);
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&(8u16 + payload_len as u16).to_be_bytes());
        pseudo.extend_from_slice(&p[20..]);
        let udp_sum = seg_checksum(&pseudo);
        p[26..28].copy_from_slice(&udp_sum.to_be_bytes());
        p
    }

    /// mac-perf T1, client side — the smoke half of the listener's
    /// burst pin: a queued bulk write must land in `tx_queue` as a
    /// multi-segment burst inside one service pass, not one segment
    /// per pass. Under smoltcp 0.13 the drain happens inside a single
    /// `poll`, so the pin is the post-pass segment count — asserted
    /// between the poll and `drain_device_tx` (which always empties
    /// the queue); the poll-count budget itself is pinned in
    /// `meow-wgstack`'s `poll_burst_budgeted` tests.
    #[tokio::test(flavor = "current_thread")]
    async fn poll_burst_egresses_queued_segments() {
        let client_secret = x25519::StaticSecret::from([0x71; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x72; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, _reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);
        let handle = *pump.tcp.keys().next().unwrap();

        // The first poll emits the SYN; our ISN and ephemeral port come
        // straight off the wire packet.
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        let syn = pump.device.tx_queue.back().expect("the dial emitted a SYN");
        let local_port = u16::from_be_bytes([syn[20], syn[21]]);
        let isn = u32::from_be_bytes(syn[24..28].try_into().unwrap());

        // The peer's SYN-ACK (seq 5000, ack'ing our SYN) → Established.
        let syn_ack = tcp_seg_v4(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5000,
            isn.wrapping_add(1),
            0x12,
        );
        pump.device.push_rx(Bytes::from(syn_ack));
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        assert_eq!(
            pump.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );
        pump.device.tx_queue.clear(); // count data segments only

        // 32 KiB ≈ 61 segments at the 536-octet DEFAULT_MSS the
        // optionless SYN-ACK negotiates — far past one segment and
        // inside the peer's 65535-octet window.
        pump.tcp
            .get_mut(&handle)
            .expect("tcp state")
            .out
            .push_back(TcpIo::Data(Bytes::from(vec![0xAB; 32 * 1024])));
        pump.service_sockets(); // the conn→socket drain fills the tx buffer
                                // The same poll step `run()` executes — the pin is on the
                                // service-pass poll loop, not on `poll_burst` the helper.
        pump.poll_stack(SmolInstant::now());
        assert!(
            pump.device.tx_queue.len() >= 10,
            "one pass must burst a multi-segment write, got {}",
            pump.device.tx_queue.len()
        );
    }

    /// wg-perf R1 pass-order pin — `service_pass` runs
    /// `service_sockets` again after `poll_stack`, so a data segment
    /// the poll just delivered reaches the conn in the SAME pass:
    /// before the second service, inbound plaintext waited a whole
    /// loop plus the `select!` park for the next pass's service. The
    /// pin is that delivery is already complete when the pass ends —
    /// a bare `poll_read` finds it, no waiting.
    #[tokio::test(flavor = "current_thread")]
    async fn service_pass_delivers_polled_rx_same_pass() {
        let client_secret = x25519::StaticSecret::from([0x73; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x74; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let (reply_tx, reply_rx) = oneshot::channel();
        pump.dial_tcp("203.0.113.1:443".parse().unwrap(), "t".into(), reply_tx);

        // SYN out, peer's SYN-ACK in — the established-socket dance
        // `poll_burst_egresses_queued_segments` uses.
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        let syn = pump.device.tx_queue.back().expect("the dial emitted a SYN");
        let local_port = u16::from_be_bytes([syn[20], syn[21]]);
        let isn = u32::from_be_bytes(syn[24..28].try_into().unwrap());
        pump.device.push_rx(Bytes::from(tcp_seg_v4(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5000,
            isn.wrapping_add(1),
            0x12,
        )));
        pump.iface
            .poll(SmolInstant::now(), &mut pump.device, &mut pump.sockets);
        pump.device.tx_queue.clear();

        // A peer data segment lands in `rx_queue` — the wire→device
        // direction's output exactly as `drain_wire` leaves it. One
        // `service_pass` must take it poll → socket → conn.
        pump.device.push_rx(Bytes::from(tcp_seg_v4_data(
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            local_port,
            5001,
            isn.wrapping_add(1),
            0x18,
            b"hello",
        )));
        pump.service_pass(CryptoPool::run_tx_shared).await;

        let mut conn = reply_rx.await.expect("reply").expect("dial resolves");
        // Same pass, no further service call: the payload must already
        // sit on the conn — a bare `poll_read` is Ready, not Pending.
        let mut buf = [0u8; 16];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut rb = tokio::io::ReadBuf::new(&mut buf);
        assert!(
            matches!(
                Pin::new(&mut *conn).poll_read(&mut cx, &mut rb),
                Poll::Ready(Ok(()))
            ),
            "polled rx must reach the conn inside the same service pass"
        );
        assert_eq!(rb.filled(), b"hello");
    }

    /// wg-perf R1 progress-guard pin — `pass_delay` reports `ZERO` when
    /// the pass moved payload (follow-on work may already be queued),
    /// and defers to `sleep_duration` only when the pass was quiet.
    #[tokio::test(flavor = "current_thread")]
    async fn pass_delay_zeroes_only_on_progress() {
        let client_secret = x25519::StaticSecret::from([0x75; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x76; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        // A quiet pass parks on `sleep_duration` — nonzero.
        assert_ne!(pump.pass_delay(0), Duration::ZERO);
        // Moved payload → the loop must not park.
        pump.last_service_bytes = 1;
        assert_eq!(pump.pass_delay(0), Duration::ZERO);
        // The snapshot consumed → the next quiet pass parks again.
        assert_ne!(pump.pass_delay(1), Duration::ZERO);
    }

    // ── flush_outbox / scratch-pool pins ─────────────────────────

    struct RecordingPacketConn {
        sent: mpsc::Sender<Vec<u8>>,
        incoming: parking_lot::Mutex<VecDeque<Vec<u8>>>,
        incoming_drained: tokio::sync::Notify,
        local_addr: SocketAddr,
    }

    impl RecordingPacketConn {
        fn new(sent: mpsc::Sender<Vec<u8>>, local_addr: SocketAddr) -> Self {
            Self {
                sent,
                incoming: Default::default(),
                incoming_drained: Default::default(),
                local_addr,
            }
        }
    }

    #[async_trait::async_trait]
    impl ProxyPacketConn for RecordingPacketConn {
        async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            let packet = self.incoming.lock().pop_front();
            if let Some(packet) = packet {
                buf[..packet.len()].copy_from_slice(&packet);
                return Ok((packet.len(), self.local_addr));
            }
            self.incoming_drained.notify_one();
            std::future::pending().await
        }

        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
            self.sent
                .send(buf.to_vec())
                .await
                .map_err(|_| MeowError::Proxy("recording receiver closed".into()))?;
            Ok(buf.len())
        }

        fn local_addr(&self) -> Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    /// F1 regression pin — a `send_batch` that stops short replays the
    /// boundary datagram, sees `WouldBlock`, and must requeue
    /// `[boundary, successors…]` *ahead* of whatever the outbox already
    /// held, losing nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn flush_outbox_wouldblock_requeue_preserves_order() {
        let client_secret = x25519::StaticSecret::from([0x99; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0xAA; 32]));

        // Both endpoint variants use the same bounded TX queue. Record
        // its output without relying on the loopback UDP receive buffer.
        let peer = SocketAddr::from(([203, 0, 113, 7], 51820));
        let local_addr = SocketAddr::from(([192, 0, 2, 4], 41000));
        let (sent, mut received) = mpsc::channel(WIRE_DRAIN_BUDGET);
        let conn = Arc::new(RecordingPacketConn::new(sent, local_addr));
        let endpoint = Endpoint::Proxy(meow_wgstack::ProxyEndpoint::new(conn, peer, local_addr));
        let (_tx, rx) = mpsc::channel(4);
        let mut pump = WgPump::new(
            &test_config(&client_secret, &server_public),
            endpoint,
            peer,
            rx,
        );

        // Prime part of the channel so it fills mid-batch. With no
        // awaits, the bridge cannot consume from this runtime yet.
        const QUEUE: usize = 4 * WIRE_DRAIN_BUDGET;
        const PRIMED: usize = 16;
        const STAGED: usize = QUEUE + WIRE_DRAIN_BUDGET;
        const OLD: [u8; 2] = [0xF0, 0xF1];
        let tag_of = |i: usize| (i as u16).to_be_bytes();
        for i in 0..PRIMED {
            pump.endpoint.try_send(&tag_of(i)).expect("prime channel");
        }
        for i in PRIMED..STAGED {
            let mut v = Vec::with_capacity(pump.scratch_len);
            v.extend_from_slice(&tag_of(i));
            pump.outbox.push_back(v);
        }
        for tag in OLD {
            let v = tagged_outbox_vec(tag, pump.scratch_len);
            pump.outbox.push_back(v);
        }

        pump.flush_outbox();

        let expected: Vec<Vec<u8>> = (0..STAGED)
            .map(|i| tag_of(i).to_vec())
            .chain(OLD.map(|tag| vec![tag]))
            .collect();
        assert!(
            pump.outbox.iter().eq(&expected[QUEUE..]),
            "outbox keeps the boundary, its successors, and the old tail in order"
        );

        // Receiving the first queue-full is the signal to flush again.
        // Check the complete order across the requeue at the receiver.
        tokio::time::timeout(Duration::from_secs(5), async {
            for (i, want) in expected.iter().enumerate() {
                if i == QUEUE {
                    pump.flush_outbox();
                    assert!(pump.outbox.is_empty(), "drained channel takes the requeue");
                }
                assert_eq!(received.recv().await.as_ref(), Some(want), "datagram {i}");
            }
        })
        .await
        .expect("TX bridge must deliver both flushes");
    }

    /// A datagram the kernel refuses (oversized → `EMSGSIZE` on every
    /// platform) is dropped — exactly that one — while its successors
    /// continue in order. Under the `BridgedEndpoint` the verdict now
    /// lands inside the TX bridge's boundary retry: the channel accepts
    /// every datagram (so the whole outbox drains and every buffer
    /// pools), and the wire observes the same outcome — only the
    /// failing datagram missing.
    #[tokio::test(flavor = "current_thread")]
    async fn flush_outbox_boundary_error_drops_only_that_datagram() {
        let client_secret = x25519::StaticSecret::from([0xBB; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0xCC; 32]));

        let receiver_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver_std
            .set_nonblocking(true)
            .expect("receiver nonblocking");
        let peer = receiver_std.local_addr().expect("receiver addr");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        sender.connect(peer).expect("connect sender");
        let mut pump = pump_with_socket(&test_config(&client_secret, &server_public), sender, peer);

        // Arm the reactor readiness: `try_send` must reach the kernel
        // for EMSGSIZE rather than WouldBlock-ing on a cold gate.
        arm_writable(&mut pump.endpoint).await;

        let oversized = vec![0xEE; 70_000]; // > 65 507 max UDP payload
        for v in [
            tagged_outbox_vec(0, pump.scratch_len),
            tagged_outbox_vec(1, pump.scratch_len),
            oversized,
            tagged_outbox_vec(3, pump.scratch_len),
        ] {
            pump.outbox.push_back(v);
        }

        let pool_before = pump.scratch_pool.len();
        pump.flush_outbox();

        assert!(pump.outbox.is_empty(), "batch completes past the error");
        assert!(
            pump.scratch_pool.len() >= pool_before + 4,
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
    #[tokio::test(flavor = "current_thread")]
    async fn return_scratch_rejects_undersize_and_caps_pool() {
        let client_secret = x25519::StaticSecret::from([0xDD; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0xEE; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        let undersized = Vec::with_capacity(pump.scratch_len - 1);
        pump.return_scratch(undersized);
        assert!(
            pump.scratch_pool.is_empty(),
            "capacity < scratch_len must not pool — a checkout would realloc anyway"
        );

        let exact = Vec::with_capacity(pump.scratch_len);
        pump.return_scratch(exact);
        assert_eq!(pump.scratch_pool.len(), 1, "full-size buffer pools");

        for _ in 0..SCRATCH_POOL_CAP + 1 {
            pump.return_scratch(Vec::with_capacity(pump.scratch_len));
        }
        assert_eq!(
            pump.scratch_pool.len(),
            SCRATCH_POOL_CAP,
            "pool residency is capped — past it the Vec frees"
        );
    }

    /// C1a's flow-budget math: the 64 KiB read chunk is what a bulk
    /// relay drains in ~2 hops, and `TCP_READ_QUEUE` of them covers the
    /// 4 MiB smoltcp rx window (4 MiB of per-flow backpressure) —
    /// pinned so a "harmless" constant bump can't quietly break the
    /// layering.
    #[test]
    fn tcp_read_chunk_covers_rx_window() {
        assert_eq!(TCP_READ_CHUNK, 65536);
        const {
            assert!(
                TCP_READ_QUEUE * TCP_READ_CHUNK >= TCP_SOCKET_BUF,
                "read-queue depth must cover the advertised window"
            );
        }
    }

    /// The service-yield contract is two independent bounds, not just
    /// payload bytes: a flood of small datagrams moves little payload
    /// per pass but still costs per-datagram work (verify, demux,
    /// crypto), so the pass counter must trip `service_yield_due` on
    /// its own — a byte-only gate would let that flood pin a shared
    /// worker indefinitely.
    #[tokio::test(flavor = "current_thread")]
    async fn service_yield_has_a_pass_backstop() {
        let client_secret = x25519::StaticSecret::from([0x81; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x82; 32]));
        let mut pump = pump_for_test(&test_config(&client_secret, &server_public));

        pump.last_service_bytes = SERVICE_YIELD_THRESHOLD;
        assert!(pump.service_yield_due(), "the byte arm trips alone");
        pump.last_service_bytes = 0;
        assert!(!pump.service_yield_due());
        pump.last_service_passes = SERVICE_YIELD_PASS_LIMIT;
        assert!(
            pump.service_yield_due(),
            "the pass arm trips alone — the small-datagram backstop"
        );
    }

    /// P7-2's `WgPump: Send` proof is the module-level `const _` assert
    /// next to the struct — it fails compilation, so it can never go
    /// stale silently. This test re-states it in-suite so a regression
    /// also surfaces in `cargo test` output.
    #[test]
    fn _wg_pump_send_const_assert() {
        fn assert_send<T: Send>() {}
        assert_send::<WgPump>();
    }

    /// P7-3 §3.3: the `STRUCTURAL COPY` rationale blocks sit next to the
    /// smoltcp receive sites they explain (TCP `recv` and UDP
    /// `recv_slice`) — pin the anchors so the notes cannot rot away from
    /// the code. Both copies are structural, not eliminated work.
    #[test]
    fn structural_recv_copy_comment_exists() {
        let src = include_str!("pump.rs");
        assert!(
            src.matches("STRUCTURAL COPY").count() >= 2,
            "TCP and UDP smoltcp-receive copies must each carry a STRUCTURAL COPY note"
        );
    }

    // ── P1 regression: flush_outbox on a dead proxy endpoint ──────

    /// A `ProxyPacketConn` whose write fails immediately — the trigger
    /// datagram kills the endpoint's TX bridge, which (post-fix) takes
    /// the RX bridge with it, so the endpoint's TX channel reports
    /// `ConnectionReset` to `flush_outbox`. `read_packet` parks and
    /// `close()` is a no-op — the Raw-conn shape the P1 defect leaked.
    struct DeadWriteConn;

    #[async_trait::async_trait]
    impl ProxyPacketConn for DeadWriteConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        async fn write_packet(&self, _buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
            Err(MeowError::Proxy("dead write conn".into()))
        }
        fn local_addr(&self) -> Result<SocketAddr> {
            Ok("192.0.2.4:41000".parse().unwrap())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    /// A subscriber layer counting WARN events — the observable split
    /// between the old warn-per-packet drain and the terminal
    /// clear-and-return.
    struct CountWarns(Arc<std::sync::atomic::AtomicUsize>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CountWarns {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// `flush_outbox` on an `Endpoint::Proxy` whose TX channel is
    /// closed takes the `ConnectionReset` arm: the whole outbox clears
    /// in one return — the staged batch included — and nothing warns;
    /// the pump's `endpoint.recv` arm is the single place the death is
    /// logged. Pre-fix this looped the generic errno arm and warned
    /// once per staged datagram while still draining.
    #[tokio::test(flavor = "current_thread")]
    async fn flush_outbox_proxy_connection_reset_clears_outbox() {
        let client_secret = x25519::StaticSecret::from([0x55; 32]);
        let server_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x66; 32]));

        let endpoint_addr: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let local_addr: SocketAddr = "192.0.2.4:41000".parse().unwrap();
        let endpoint = Endpoint::Proxy(meow_wgstack::ProxyEndpoint::new(
            Arc::new(DeadWriteConn),
            endpoint_addr,
            local_addr,
        ));
        endpoint.try_send(b"trigger").expect("queued");
        // Wait for the write error to actually kill the TX bridge —
        // `Closed` on the channel is the `ConnectionReset` verdict.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match endpoint.try_send(b"probe") {
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
                    _ => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("TX bridge must exit on the write error");

        let (_tx, rx) = mpsc::channel(4);
        let mut pump = WgPump::new(
            &test_config(&client_secret, &server_public),
            endpoint,
            endpoint_addr,
            rx,
        );
        // Ten queued datagrams: the pre-fix path warned once per staged
        // replay; the fix returns after the first ConnectionReset.
        for tag in 0..10u8 {
            pump.outbox
                .push_back(tagged_outbox_vec(tag, pump.scratch_len));
        }

        let warns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(CountWarns(Arc::clone(&warns)));
        tracing::subscriber::with_default(subscriber, || pump.flush_outbox());

        assert!(
            pump.outbox.is_empty(),
            "ConnectionReset clears the queued tail in one return"
        );
        assert_eq!(
            warns.load(Ordering::Relaxed),
            0,
            "a dead proxy endpoint must not warn-per-packet"
        );
    }
}
