//! Per-flow UDP handling for the TUN inbound.
//!
//! lwIP surfaces UDP as one packet-level socket yielding
//! `(payload, src, dst)` tuples — there are no per-flow streams and no
//! built-in NAT, so this module owns the flow table: the reader loop
//! dispatches datagrams to per-flow tasks keyed by the (src, dst) tuple,
//! and each flow task dials the outbound once, pumps both directions, and
//! evicts itself after `udp-timeout` of silence.
//!
//! Routing mirrors `meow_tunnel::udp::handle_udp`: fake-IP rewrite →
//! pre-resolve → port-53 handling → rule match → `dial_udp`. Port 53 is
//! special two ways: with `dns-hijack` enabled each query is answered
//! in-process by `DnsServer::handle_query` — statelessly, no flow entry
//! (required for fake-IP mode — point the OS resolver at any address
//! inside the routed range); without it the flow follows ordinary routing
//! rules, including REJECT and proxy selection.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::{FutureExt, StreamExt};
use ipnet::{Ipv4Net, Ipv6Net};
use lwip::UdpSocket;
use meow_common::{ConnType, Metadata, Network};
use meow_dns::server::{hex_prefix, DnsServer, LocalAnswer};
use meow_tunnel::{MatchedRule, ResolvedTarget, Tunnel, UsingProxy};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use tracing::{debug, info, warn};

/// One datagram payload cap. UDP over IPv4 tops out below 64 KiB.
const DATAGRAM_BUF: usize = 65535;
/// Per-flow upstream queue — buffers datagrams while the flow task is
/// still routing/dialing; overflow is dropped (UDP semantics).
const FLOW_QUEUE: usize = 64;
/// Queue feeding the single stack-writer task (the netstack write half is
/// a `Sink` and cannot be cloned into per-flow tasks).
const REPLY_QUEUE: usize = 512;

/// Hard bound on live flow-table entries (issue #515). At cap the
/// least-recently-active flow is evicted to admit the new tuple —
/// dropping the evicted sender closes that flow task's queue, which
/// tears it down through the ordinary shutdown path.
const MAX_FLOWS: usize = 1024;
/// Bound on concurrent in-process DNS answers (`dns-hijack`). Beyond it,
/// queries are dropped and counted — UDP semantics: the client retries.
/// Without a bound, a query flood could spawn an unbounded number of
/// tasks here (issue #515).
const HIJACK_IN_FLIGHT: usize = 64;

/// Most client datagrams a QUIC sniff holds back before routing the flow.
const QUIC_SNIFF_PACKETS: usize = 4;

/// Sweep dead flow-table entries every this many datagrams.
const SWEEP_INTERVAL: u32 = 256;

/// `(payload, packet source, packet destination)` — the netstack `UdpMsg`
/// layout, so a reply to a flow is sent as `(payload, dst, src)`.
pub(super) type ReplyMsg = (Vec<u8>, SocketAddr, SocketAddr);

/// A client datagram: `(payload, client source, destination)`.
pub(super) type UdpPkt = lwip::UdpPkt;

/// Where the TUN's UDP comes from and its replies go.
pub(super) enum UdpIo {
    /// lwIP's packet-level UDP socket.
    Lwip(Box<UdpSocket>),
    /// Straight from and to the device pumps (`tun.stack: system`): the
    /// inbound pump parses each datagram off the device, the outbound pump
    /// builds the reply packets — no netstack in between.
    Direct {
        incoming: mpsc::Receiver<UdpPkt>,
        replies: mpsc::Sender<ReplyMsg>,
    },
}

/// The datagram source of [`run_udp`].
enum Incoming {
    Lwip(lwip::UdpRecvHalf),
    Direct(mpsc::Receiver<UdpPkt>),
}

impl Incoming {
    async fn next(&mut self) -> Option<UdpPkt> {
        match self {
            Self::Lwip(r) => r.next().await,
            Self::Direct(r) => r.recv().await,
        }
    }
}

/// Capacity of the pump → [`run_udp`] datagram queue (system stack); a
/// full queue drops the datagram, as a socket buffer would.
pub(super) const DIRECT_QUEUE: usize = 1024;
/// Capacity of the [`run_udp`] → pump reply queue (system stack).
pub(super) const DIRECT_REPLY_QUEUE: usize = REPLY_QUEUE;

/// `(client source, packet destination)` — the flow-table key.
type FlowKey = (SocketAddr, SocketAddr);

/// Epoch for flow activity stamps. `Instant` cannot be shared atomically
/// between the reader loop and flow tasks, so activity is recorded as
/// elapsed milliseconds since this base — monotonic for the process
/// lifetime and comparable across entries.
static ACTIVITY_EPOCH: std::sync::LazyLock<std::time::Instant> =
    std::sync::LazyLock::new(std::time::Instant::now);

fn activity_ms() -> u64 {
    ACTIVITY_EPOCH.elapsed().as_millis() as u64
}

/// Live flow-table entry. `last_activity` is stamped by the reader loop on
/// every client datagram AND by the flow task on each upstream reply it
/// successfully enqueues — a reply-mostly flow (e.g. a QUIC download
/// mid-stream) must not look idle to the LRU eviction at `MAX_FLOWS`.
/// A reply dropped on a full queue does not stamp.
struct FlowEntry {
    tx: mpsc::Sender<Vec<u8>>,
    last_activity: Arc<AtomicU64>,
}

/// One loop's flow table bundled with its share of the shared occupancy
/// gauge (`TunReady::Ready.udp_flows`, issue #515): every mutation applies
/// its gauge delta here so the two can never drift, and `Drop` returns the
/// remaining count even when the loop's future is aborted mid-park
/// (listener shutdown) — a tail `fetch_sub` never ran in that case and
/// the gauge kept a dead loop's flows.
struct FlowTable {
    map: HashMap<FlowKey, FlowEntry>,
    gauge: Arc<AtomicUsize>,
}

impl FlowTable {
    fn new(gauge: Arc<AtomicUsize>) -> Self {
        Self {
            map: HashMap::new(),
            gauge,
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn get(&self, key: &FlowKey) -> Option<&FlowEntry> {
        self.map.get(key)
    }

    fn iter(&self) -> impl Iterator<Item = (&FlowKey, &FlowEntry)> {
        self.map.iter()
    }

    /// A fresh key is the only growth: replacing an entry keeps the
    /// count rather than leaking one.
    fn insert(&mut self, key: FlowKey, entry: FlowEntry) {
        if self.map.insert(key, entry).is_none() {
            self.gauge.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn remove(&mut self, key: &FlowKey) {
        if self.map.remove(key).is_some() {
            self.sub(1);
        }
    }

    /// `map.retain` plus the gauge delta of however many entries it shed.
    fn retain(&mut self, f: impl FnMut(&FlowKey, &mut FlowEntry) -> bool) {
        let before = self.map.len();
        self.map.retain(f);
        self.sub(before - self.map.len());
    }

    /// Saturating subtract: a delta missed by a future change must never
    /// wrap the shared gauge to `usize::MAX`.
    fn sub(&self, n: usize) {
        let _ = self
            .gauge
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(n))
            });
    }
}

impl Drop for FlowTable {
    fn drop(&mut self) {
        // The loop may end without draining (aborted while parked on
        // `incoming.next()`): give this table's share back either way.
        self.sub(self.map.len());
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the listener's UDP knobs, passed once"
)]
pub(super) async fn run_udp(
    tunnel: Tunnel,
    io: UdpIo,
    dns_hijack: bool,
    udp_timeout: Duration,
    in_name: String,
    tun_net: TunNets,
    live_flows: Arc<AtomicUsize>,
    sniffer: Option<Arc<crate::sniffer::SnifferRuntime>>,
) {
    let (reply_tx, mut incoming) = match io {
        UdpIo::Lwip(socket) => {
            let (write_half, read_half) = socket.split();
            let (reply_tx, mut reply_rx) = mpsc::channel::<ReplyMsg>(REPLY_QUEUE);
            tokio::spawn(async move {
                while let Some((data, src, dst)) = reply_rx.recv().await {
                    // `send_to(data, src, dst)`: appear as `src`, deliver to `dst`.
                    if let Err(e) = write_half.send_to(&data, &src, &dst) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            continue;
                        }
                        debug!("tun UDP write half closed: {e}");
                        break;
                    }
                }
            });
            (reply_tx, Incoming::Lwip(read_half))
        }
        UdpIo::Direct { incoming, replies } => (replies, Incoming::Direct(incoming)),
    };

    // Flow table, touched only by this loop — its `Drop` returns the
    // gauge share however this future ends. A flow task signals its own
    // death by closing its queue; the entry is evicted lazily — on the
    // next datagram for the tuple, by the periodic sweep, or by LRU
    // eviction when the table reaches MAX_FLOWS (issue #515).
    let mut flows = FlowTable::new(live_flows);
    let mut sweep_countdown = SWEEP_INTERVAL;
    let hijack_permits = Arc::new(tokio::sync::Semaphore::new(HIJACK_IN_FLIGHT));
    let hijack_dropped = Arc::new(AtomicU64::new(0));

    while let Some((data, src, dst)) = incoming.next().await {
        // The TCP NAT's trust boundary holds for UDP too: the peer
        // addresses are assigned to nothing, so a datagram claiming one
        // as its source is forged (a LAN peer forwarded in under loose
        // rp_filter) and must not mint a flow — its replies would only
        // route back into the device and die on `is_looping_dst` anyway.
        if tun_net.nat.is_some_and(|a| a.is_peer(src.ip())) {
            debug!("tun UDP: dropping datagram forged from NAT peer {src} -> {dst}");
            continue;
        }
        if dns_hijack && dst.port() == 53 {
            let resolver = tunnel.resolver();
            debug!(
                "tun dns-hijack: recv {} bytes from {src} to {dst} | {}",
                data.len(),
                hex_prefix(&data, 48),
            );
            // Locally-decidable queries (hosts, fake-IP, fresh cache) are
            // answered inline — they never spend a hijack permit or a task
            // spawn, so a warm cache can't queue behind slow upstreams.
            match DnsServer::try_answer_local(&data, &resolver) {
                LocalAnswer::Answer(response) => {
                    if reply_tx.try_send((response, dst, src)).is_err() {
                        note_hijack_drop(&hijack_dropped);
                    }
                    continue;
                }
                // Malformed or a response packet — nothing to forward
                // upstream either.
                LocalAnswer::Drop => continue,
                LocalAnswer::Upstream => {}
            }
            match Arc::clone(&hijack_permits).try_acquire_owned() {
                Ok(permit) => {
                    let reply_tx = reply_tx.clone();
                    let hijack_dropped = Arc::clone(&hijack_dropped);
                    tokio::spawn(async move {
                        let _permit = permit;
                        // Panic guard — parity with the serve loop in
                        // meow-dns: a panicked task would silently drop the
                        // query otherwise.
                        let outcome = AssertUnwindSafe(DnsServer::handle_query(&data, &resolver))
                            .catch_unwind()
                            .await;
                        match outcome {
                            Ok(Ok(response)) => {
                                debug!(
                                    "tun dns-hijack: reply {} bytes -> {src} | {}",
                                    response.len(),
                                    hex_prefix(&response, 48),
                                );
                                match reply_tx.try_send((response, dst, src)) {
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        note_hijack_drop(&hijack_dropped);
                                    }
                                    // A closed queue means the stack writer is gone (listener
                                    // shutdown); the task ends here either way.
                                    Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                                }
                            }
                            Ok(Err(e)) => {
                                debug!("tun dns-hijack: unanswerable query from {src}: {e}");
                            }
                            Err(_) => {
                                warn!("tun dns-hijack: query task survived a panic");
                            }
                        }
                    });
                }
                Err(_) => note_hijack_drop(&hijack_dropped),
            }
            continue;
        }

        if is_looping_dst(dst.ip(), tun_net) {
            debug!("tun UDP: dropping non-routable dst {dst} (from {src})");
            continue;
        }

        sweep_countdown -= 1;
        if sweep_countdown == 0 {
            sweep_countdown = SWEEP_INTERVAL;
            // `FlowTable` applies the gauge delta of whatever it sheds —
            // and on `Drop` for whatever is left.
            flows.retain(|_, e| !e.tx.is_closed());
        }

        let key = (src, dst);
        let data = match flows.get(&key) {
            Some(entry) => {
                entry.last_activity.store(activity_ms(), Ordering::Relaxed);
                match entry.tx.try_send(data) {
                    // Delivered — or queue full: the flow is alive but slow,
                    // so the datagram is dropped (UDP semantics).
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                    // Flow task ended (idle timeout or error): evict and fall
                    // through to re-create the flow with this datagram.
                    Err(mpsc::error::TrySendError::Closed(data)) => {
                        flows.remove(&key);
                        data
                    }
                }
            }
            None => data,
        };

        // A destination inside the fake-IP range with no live allocation
        // would spawn a flow that immediately drops — drop the datagram
        // here instead of churning a spawn+evict per packet under a stale
        // flood (issue #618). Runs only when a flow is about to be
        // (re)created: an established flow already pinned its resolved
        // destination at creation, and the flow task re-checks the verdict
        // there too, so probing per datagram was dead resolver work on the
        // hit path (issue #648).
        let mut probe = Metadata {
            network: Network::Udp,
            dst_ip: Some(dst.ip()),
            dst_port: dst.port(),
            ..Default::default()
        };
        if matches!(
            tunnel.inner().pre_handle_metadata(&mut probe),
            meow_tunnel::PreHandleVerdict::Drop
        ) {
            debug!("tun udp: drop datagram to unmapped fake-ip {dst}");
            continue;
        }

        // Admission bound: reclaim dead entries first, then evict the
        // least-recently-active live flow.
        if flows.len() >= MAX_FLOWS {
            evict_for_admission(&mut flows);
        }

        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        tx.try_send(data).expect("fresh flow queue has capacity");
        let last_activity = Arc::new(AtomicU64::new(activity_ms()));
        flows.insert(
            key,
            FlowEntry {
                tx,
                last_activity: Arc::clone(&last_activity),
            },
        );
        tokio::spawn(flow_task(
            tunnel.clone(),
            FlowSpec {
                rx,
                reply_tx: reply_tx.clone(),
                key,
                udp_timeout,
                in_name: in_name.clone(),
                last_activity,
                sniffer: sniffer.clone(),
            },
        ));
    }
    // `flows` drops here, returning this table's share of the gauge —
    // also when the future is aborted mid-loop and never reaches this line.
}

/// Per-flow state handed to the spawned flow task.
struct FlowSpec {
    rx: mpsc::Receiver<Vec<u8>>,
    reply_tx: mpsc::Sender<ReplyMsg>,
    /// `(client source, packet destination)` — same layout as `FlowKey`.
    key: FlowKey,
    udp_timeout: Duration,
    in_name: String,
    last_activity: Arc<AtomicU64>,
    /// The configured sniffer; its QUIC ports name a flow from the
    /// client's Initials before it is routed.
    sniffer: Option<Arc<crate::sniffer::SnifferRuntime>>,
}

/// Count a dropped hijack response and warn on a power-of-two cadence so
/// sustained floods stay visible without a log storm (issue #515). Covers
/// both drop shapes: in-flight cap saturation and a full reply queue.
fn note_hijack_drop(counter: &AtomicU64) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        warn!(
            "tun dns-hijack saturated: {n} responses dropped \
             ({HIJACK_IN_FLIGHT} in-flight cap or reply queue full)"
        );
    }
}

/// Make room for one new flow entry (issue #515): dead entries are
/// reclaimed first — closing their queue is how a finished flow task
/// reports itself — then, if the table is still at `MAX_FLOWS`, the
/// least-recently-active live flow is evicted. Dropping the evicted
/// sender closes that flow's queue; its task exits through the ordinary
/// `rx.recv() == None` shutdown path. The gauge deltas ride along inside
/// [`FlowTable`]'s `retain`/`remove`.
fn evict_for_admission(flows: &mut FlowTable) {
    flows.retain(|_, e| !e.tx.is_closed());
    if flows.len() >= MAX_FLOWS {
        if let Some(victim) = flows
            .iter()
            .min_by_key(|(_, e)| e.last_activity.load(Ordering::Relaxed))
            .map(|(k, _)| *k)
        {
            debug!("tun UDP flow table full: evicting LRU flow {victim:?}");
            flows.remove(&victim);
        }
    }
}

async fn flow_task(tunnel: Tunnel, spec: FlowSpec) {
    let (src, dst) = spec.key;
    if let Err(e) = relay_flow(&tunnel, spec).await {
        debug!("tun UDP {src} -> {dst}: {e}");
    }
}

/// Route the flow, dial the outbound, then pump datagrams both ways until
/// `udp_timeout` passes with no traffic in either direction. `last_activity`
/// is the table entry's shared stamp — upstream replies it successfully
/// enqueues onto `reply_tx` refresh it so a reply-mostly flow is not
/// mistaken for idle by LRU eviction (a reply dropped on a full queue does
/// not stamp).
async fn relay_flow(tunnel: &Tunnel, spec: FlowSpec) -> Result<(), String> {
    let FlowSpec {
        mut rx,
        reply_tx,
        key: (src, dst),
        udp_timeout,
        in_name,
        last_activity,
        sniffer,
    } = spec;
    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Tun,
        src_ip: Some(src.ip()),
        src_port: src.port(),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        in_name: in_name.into(),
        ..Default::default()
    };

    // QUIC sniff: hold the first datagrams until their Initials yield the
    // server name, at most `sniffer.timeout` and a few packets; they are
    // sent upstream first once the flow is dialed.
    let mut held: Vec<Vec<u8>> = Vec::new();
    if let Some(rt) = sniffer.as_deref().filter(|rt| rt.wants_quic(&metadata)) {
        let deadline = Instant::now() + rt.timeout();
        let mut quic = crate::sniffer_quic::QuicSniffer::default();
        while held.len() < QUIC_SNIFF_PACKETS {
            let Ok(Some(data)) = tokio::time::timeout_at(deadline, rx.recv()).await else {
                break;
            };
            let step = quic.feed(&data);
            held.push(data);
            match step {
                crate::sniffer_quic::QuicSniffStep::Name(name) => {
                    rt.maybe_apply_sniff(&name, &mut metadata);
                    break;
                }
                crate::sniffer_quic::QuicSniffStep::More => {}
                crate::sniffer_quic::QuicSniffStep::Done => break,
            }
        }
    }

    let inner = tunnel.inner();
    if matches!(
        inner.pre_handle_metadata(&mut metadata),
        meow_tunnel::PreHandleVerdict::Drop
    ) {
        return Err("unmapped fake-ip destination".into());
    }
    // UDP keeps the eager pre_resolve (no lazy enrichment): the outbound
    // packet API below needs a resolved dst_ip regardless of what the rules
    // demand — including after a fake-IP was rewritten back to a hostname.
    inner.pre_resolve(&mut metadata).await;
    inner.resolve_udp_dst(&mut metadata).await;
    let Some(dst_ip) = metadata.dst_ip else {
        return Err(format!(
            "dst_ip not resolved for {}",
            metadata.remote_address()
        ));
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);

    // Non-hijacked client traffic follows the same policy on every port.
    let Some(ResolvedTarget {
        adapter: proxy,
        rule_name,
        rule_payload,
        route: _route,
    }) = inner.resolve_proxy(&metadata).await
    else {
        return Err(format!(
            "no matching rule for {}",
            metadata.remote_address()
        ));
    };
    info!(
        "UDP {} --> {} match {} using {}",
        src,
        metadata.remote_address(),
        MatchedRule::new(&rule_name, &rule_payload, proxy.name()),
        UsingProxy::new(proxy.as_ref(), &metadata)
    );

    // Taken before the dial so a flush landing mid-dial still ends the flow
    // (issue #695): its socket may predate the new outbound binding.
    let mut flush = inner.udp_flush_watch();
    let conn: std::sync::Arc<dyn meow_common::ProxyPacketConn> = std::sync::Arc::from(
        inner
            .dial_udp(proxy.as_ref(), &metadata)
            .await
            .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?,
    );
    // `_route` exists to pin the route-table generation across the dial
    // only — a long-lived flow must not keep its dial-time generation
    // alive across config reloads.
    drop(_route);

    // Upstream replies are pumped by a dedicated reader task holding one
    // persistent buffer: reads are never cancelled, so a stream-framed
    // conn (e.g. Trojan UoT) cannot lose a partially consumed frame to a
    // dropped mid-flight read (issue #514). Each reply is copied out and
    // forwarded through `up_rx` so the select loop below sees downstream
    // traffic for its idle deadline — the same per-datagram `to_vec`
    // profile the pre-#514 pump had.
    let (up_tx, mut up_rx) = mpsc::channel::<Vec<u8>>(FLOW_QUEUE);
    let mut reply_task = tokio::spawn({
        let conn = std::sync::Arc::clone(&conn);
        async move {
            let mut rbuf = vec![0u8; DATAGRAM_BUF];
            loop {
                match conn.read_packet(&mut rbuf).await {
                    Ok((n, _from)) => {
                        if up_tx.send(rbuf[..n].to_vec()).await.is_err() {
                            return Ok(()); // flow gone
                        }
                    }
                    Err(e) => return Err(format!("downstream read: {e}")),
                }
            }
        }
    });

    // Select over client datagrams (queued by the reader loop), upstream
    // replies, and the idle deadline. Reply source addresses are not
    // rewritten: the tun flow is locked to one (src, dst) tuple, so every
    // reply is delivered as coming from `dst`.
    for data in held {
        conn.write_packet(&data, &dst_addr)
            .await
            .map_err(|e| format!("upstream write {dst_addr}: {e}"))?;
    }

    let idle = sleep_until(next_deadline(udp_timeout));
    tokio::pin!(idle);
    let result = loop {
        tokio::select! {
            () = &mut idle => break Ok(()), // idle-timeout eviction
            // Outbound sessions flushed (issue #695): end the flow; the
            // client's next datagram opens a fresh one with a fresh dial.
            () = flush.flushed() => break Ok(()),
            queued = rx.recv() => match queued {
                Some(data) => {
                    // Drive write_packet in a nested select! so idle
                    // expiry, flush and a dead reply reader can cancel
                    // a blocked write (PR #893 pattern: write_packet
                    // must not park the flow's termination signals).
                    let write_result = tokio::select! {
                        () = &mut idle => break Ok(()), // idle-timeout during write
                        () = flush.flushed() => break Ok(()), // flush during write
                        done = &mut reply_task => break Err(match done {
                            Ok(Err(e)) => e,
                            Ok(Ok(())) => "downstream reader exited".into(),
                            Err(e) => format!("downstream reader task: {e}"),
                        }),
                        r = conn.write_packet(&data, &dst_addr) => r,
                    };
                    match write_result {
                        Ok(n) if n == data.len() => {
                            idle.as_mut().reset(next_deadline(udp_timeout));
                        }
                        Ok(n) => {
                            break Err(format!(
                                "upstream write {dst_addr}: short write {n}/{}",
                                data.len()
                            ));
                        }
                        Err(e) => {
                            break Err(format!("upstream write {dst_addr}: {e}"));
                        }
                    }
                }
                None => break Ok(()), // reader loop gone — listener shutdown
            },
            received = up_rx.recv() => match received {
                Some(data) => {
                    // UDP drop semantics on backpressure: a full reply queue
                    // drops the datagram rather than parking the flow (and
                    // its idle timer) on a slow lwIP stack writer — same
                    // policy as tproxy (which already used try_send).
                    match reply_tx.try_send((data, dst, src)) {
                        Ok(()) => {
                            last_activity.store(activity_ms(), Ordering::Relaxed);
                            idle.as_mut().reset(next_deadline(udp_timeout));
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // Drop this reply; the client will retransmit if
                            // it needs the data.
                            debug!("tun UDP reply queue full: dropping reply to {src} (from {dst})");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            break Ok(()); // stack writer gone — listener shutdown
                        }
                    }
                }
                // The reader task exited — it owns the only `up_tx`. The
                // borrow-await keeps the handle usable for the abort below.
                None => break Err(match (&mut reply_task).await {
                    Ok(Err(e)) => e,
                    Ok(Ok(())) => "downstream reader exited".into(),
                    Err(e) => format!("downstream reader task: {e}"),
                }),
            },
        }
    };

    reply_task.abort();
    let _ = conn.close();
    result
}

/// `Instant + Duration` panics when the deadline leaves the
/// representable range — clamp absurd `udp-timeout` values to a
/// far-future deadline instead of crashing the flow task.
fn next_deadline(udp_timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(udp_timeout)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(86400 * 30))
}

/// The subnets assigned to the TUN device: `inet4-address`, plus
/// `inet6-address` when the device carries IPv6 (global route scope).
/// `nat` is the system stack's peer set (`tun.stack: system`), filled in
/// once the stack binds — the forged-source drop in [`run_udp`]; `None`
/// under the plain lwIP stack, where no NAT peer exists.
#[derive(Debug, Clone, Copy)]
pub(super) struct TunNets {
    pub(super) v4: Ipv4Net,
    pub(super) v6: Option<Ipv6Net>,
    pub(super) nat: Option<super::system::NatAddrs>,
}

/// True when a dial to `dst` could only route back into the TUN device —
/// its own subnet (on-link, including the device address and the subnet
/// broadcast), the IPv4 limited broadcast, or multicast. Relaying such a
/// destination re-enters the device and spawns a fresh flow from a new
/// source port each round: an amplification loop. Windows NetBIOS
/// name-service broadcasts to the subnet broadcast address (e.g.
/// `198.18.0.3:137` for the default `198.18.0.1/30`) trigger exactly this,
/// exhausting ephemeral ports within seconds of TUN start.
pub(super) fn is_looping_dst(dst: std::net::IpAddr, tun_net: TunNets) -> bool {
    match dst {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || tun_net.v4.contains(&v4),
        IpAddr::V6(v6) => v6.is_multicast() || tun_net.v6.is_some_and(|n| n.contains(&v6)),
    }
}

#[cfg(test)]
mod tests {
    use super::{evict_for_admission, is_looping_dst, FlowEntry, FlowTable, TunNets, MAX_FLOWS};
    use std::net::{IpAddr, SocketAddr};

    /// Build a flow table holding `live` live entries plus `dead` entries
    /// whose receiver was dropped (channel closed). Live entries are kept
    /// alive via `keepers`. Activity stamps increase with the loop index —
    /// index 0 is the least recently active.
    fn seeded_table(
        live: usize,
        dead: usize,
    ) -> (FlowTable, Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>) {
        let mut flows = FlowTable::new(std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)));
        let mut keepers = Vec::new();
        for i in 0..(live + dead) {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            if i < live {
                keepers.push(rx);
            } // dead entries: receiver dropped immediately
            let src: SocketAddr = ([10, 0, 0, 1], 10000 + i as u16).into();
            let dst: SocketAddr = ([8, 8, 8, 8], 53).into();
            flows.insert(
                (src, dst),
                FlowEntry {
                    tx,
                    last_activity: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(i as u64)),
                },
            );
        }
        (flows, keepers)
    }

    #[test]
    fn evict_for_admission_reclaims_dead_before_touching_live() {
        let (mut flows, _keepers) = seeded_table(MAX_FLOWS - 1, 3);
        evict_for_admission(&mut flows);
        assert_eq!(flows.len(), MAX_FLOWS - 1, "only dead entries removed");
    }

    #[test]
    fn evict_for_admission_evicts_least_recently_active() {
        let (mut flows, _keepers) = seeded_table(MAX_FLOWS, 0);
        // seeded_table stamps index 0 as least-recently-active.
        let oldest_key: super::FlowKey = (([10, 0, 0, 1], 10000).into(), ([8, 8, 8, 8], 53).into());
        evict_for_admission(&mut flows);
        assert_eq!(flows.len(), MAX_FLOWS - 1);
        assert!(
            flows.get(&oldest_key).is_none(),
            "the least-recently-active live flow must be the victim"
        );
        // A live flow whose shared stamp is refreshed by an upstream reply
        // must outrank a stale one (issue #515: reply-side activity counts).
        // At cap with the OLDEST entry stamped fresh, the victim must move
        // to the next-oldest — below cap this assertion would be vacuous.
        let (mut flows, _keepers) = seeded_table(MAX_FLOWS, 0);
        let next_oldest_key: super::FlowKey =
            (([10, 0, 0, 1], 10001).into(), ([8, 8, 8, 8], 53).into());
        flows
            .get(&oldest_key)
            .unwrap()
            .last_activity
            .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
        evict_for_admission(&mut flows);
        assert!(flows.get(&oldest_key).is_some(), "refreshed flow survives");
        assert!(
            flows.get(&next_oldest_key).is_none(),
            "the new least-recently-active flow is evicted instead"
        );
    }

    #[test]
    fn evicted_flow_sender_close_tears_down_task() {
        // The eviction mechanism contract: removing the entry drops the
        // Sender, which ends the flow task's `rx.recv()` — the existing
        // shutdown path; no separate kill signal is needed.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        assert!(tx.try_send(vec![1]).is_ok());
        drop(tx);
        assert_eq!(
            rx.try_recv().unwrap().as_slice(),
            &[1],
            "queued datagram drains first"
        );
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }

    /// The system stack runs two `run_udp` loops (direct + lwIP
    /// leftovers) on one gauge: each applies only its own table's deltas,
    /// so readers see the sum, and a loop that exits gives its share back.
    #[tokio::test]
    async fn shared_gauge_sums_both_flow_tables() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let gauge = Arc::new(AtomicUsize::new(0));
        let spawn = || {
            let (tx, incoming) = tokio::sync::mpsc::channel(4);
            let (replies, _rx) = tokio::sync::mpsc::channel(4);
            let task = tokio::spawn(super::run_udp(
                crate::test_rule_tunnel(),
                super::UdpIo::Direct { incoming, replies },
                false,
                Duration::from_secs(60),
                "tun".to_string(),
                net(),
                Arc::clone(&gauge),
            ));
            (tx, task)
        };
        let (tx1, t1) = spawn();
        let (tx2, t2) = spawn();

        let pkt = |port: u16| {
            (
                b"x".to_vec(),
                SocketAddr::from(([10, 0, 0, 1], port)),
                SocketAddr::from(([8, 8, 8, 8], 53)),
            )
        };
        tx1.send(pkt(1)).await.unwrap();
        tx2.send(pkt(2)).await.unwrap();

        async fn wait_gauge(gauge: &AtomicUsize, want: usize) {
            let polled = tokio::time::timeout(Duration::from_secs(5), async {
                while gauge.load(Ordering::Relaxed) != want {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await;
            assert!(polled.is_ok(), "gauge never reached {want}");
        }
        wait_gauge(&gauge, 2).await;

        // Each loop returns only its own table's count on exit.
        drop(tx1);
        t1.await.unwrap();
        wait_gauge(&gauge, 1).await;

        // An aborted loop (listener shutdown) returns its share too —
        // `FlowTable`'s `Drop`, not a tail statement, gives it back.
        let (tx3, t3) = spawn();
        tx3.send(pkt(3)).await.unwrap();
        wait_gauge(&gauge, 2).await;
        t3.abort();
        let _ = t3.await;
        wait_gauge(&gauge, 1).await;

        drop(tx2);
        t2.await.unwrap();
        assert_eq!(gauge.load(Ordering::Relaxed), 0);
    }

    /// The TCP NAT's trust boundary holds on the UDP side too
    /// (`system.rs`): the peer addresses are assigned to nothing, so a
    /// datagram claiming one as its source is forged and must not mint
    /// a flow — however it arrived (direct pump, or lwIP behind the
    /// fragments / extension headers the direct path does not carry).
    #[tokio::test]
    async fn udp_forged_nat_peer_source_mints_no_flow() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let net = TunNets {
            v4: "172.31.0.1/30".parse().unwrap(),
            v6: Some("fdfe:dcba:9876::1/126".parse().unwrap()),
            nat: Some(crate::tun::system::NatAddrs {
                a4: "172.31.0.1".parse().unwrap(),
                b4: "172.31.0.2".parse().unwrap(),
                port4: 40000,
                v6: Some((
                    "fdfe:dcba:9876::1".parse().unwrap(),
                    "fdfe:dcba:9876::2".parse().unwrap(),
                    40001,
                )),
            }),
        };
        let gauge = Arc::new(AtomicUsize::new(0));
        let (tx, incoming) = tokio::sync::mpsc::channel(4);
        let (replies, _rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(super::run_udp(
            crate::test_rule_tunnel(),
            super::UdpIo::Direct { incoming, replies },
            false,
            Duration::from_secs(60),
            "tun".to_string(),
            net,
            Arc::clone(&gauge),
        ));

        let pkt = |src: SocketAddr| (b"x".to_vec(), src, SocketAddr::from(([8, 8, 8, 8], 1234)));
        // Forged peer sources, v4 and v6. The channel is FIFO, so the
        // legit datagram below is always processed after them.
        tx.send(pkt("172.31.0.2:1234".parse().unwrap()))
            .await
            .unwrap();
        tx.send(pkt("[fdfe:dcba:9876::2]:1234".parse().unwrap()))
            .await
            .unwrap();
        // The device's own address is a legal client source and mints
        // the loop's one and only flow — had a forged datagram minted
        // one too, the gauge would land above 1.
        tx.send(pkt("192.168.1.10:5000".parse().unwrap()))
            .await
            .unwrap();
        let polled = tokio::time::timeout(Duration::from_secs(5), async {
            while gauge.load(Ordering::Relaxed) < 1 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await;
        assert!(polled.is_ok(), "the legit flow never minted");
        tokio::task::yield_now().await;
        assert_eq!(
            gauge.load(Ordering::Relaxed),
            1,
            "a forged peer-sourced datagram must not mint a flow"
        );
        drop(tx);
        task.await.unwrap();
        assert_eq!(gauge.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn udp_port_53_obeys_reject_rule_without_hijack() {
        let tunnel = crate::test_rule_tunnel();
        for port in [53, 5353] {
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            let (reply_tx, _reply_rx) = tokio::sync::mpsc::channel(1);
            let result = super::relay_flow(
                &tunnel,
                super::FlowSpec {
                    rx,
                    reply_tx,
                    key: (
                        "127.0.0.1:12345".parse().unwrap(),
                        ([127, 0, 0, 1], port).into(),
                    ),
                    udp_timeout: std::time::Duration::from_millis(100),
                    in_name: "tun".to_string(),
                    last_activity: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    sniffer: None,
                },
            )
            .await;
            assert!(result.unwrap_err().contains("rejected"));
        }
    }

    /// The default device subnet: the fake-IP pool's reserved first /30.
    fn net() -> TunNets {
        TunNets {
            v4: "198.18.0.1/30".parse().unwrap(),
            v6: None,
            nat: None,
        }
    }

    fn dual_net() -> TunNets {
        TunNets {
            v6: Some("fdfe:dcba:9876::1/126".parse().unwrap()),
            ..net()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn drops_tun_subnet_broadcast_and_multicast() {
        // The NetBIOS storm case: subnet broadcast of the /30.
        assert!(is_looping_dst(ip("198.18.0.3"), net()));
        // The device's own address and anything else on-link. The DNS
        // guard's resolver, `198.18.0.2`, is one: dns-hijack answers its
        // :53 flows before this check.
        assert!(is_looping_dst(ip("198.18.0.1"), net()));
        assert!(is_looping_dst(ip("198.18.0.2"), net()));
        // Limited broadcast and multicast (mDNS/SSDP/LLMNR).
        assert!(is_looping_dst(ip("255.255.255.255"), net()));
        assert!(is_looping_dst(ip("224.0.0.251"), net()));
        assert!(is_looping_dst(ip("ff02::fb"), net()));
        // The IPv6 device subnet, when the device carries one (#375).
        assert!(is_looping_dst(ip("fdfe:dcba:9876::1"), dual_net()));
        assert!(is_looping_dst(ip("fdfe:dcba:9876::3"), dual_net()));
        assert!(is_looping_dst(ip("198.18.0.3"), dual_net()));
    }

    #[test]
    fn keeps_routable_destinations() {
        // Fake-IP range traffic — the whole point of the TUN — from the
        // first address the pool hands out, just outside the /30.
        assert!(!is_looping_dst(ip("198.18.0.4"), net()));
        assert!(!is_looping_dst(ip("198.18.0.5"), net()));
        // Ordinary unicast, v4 and v6.
        assert!(!is_looping_dst(ip("8.8.8.8"), net()));
        assert!(!is_looping_dst(ip("2001:db8::1"), net()));
        // An IPv4-only device has no IPv6 subnet to guard; a dual-stack one
        // guards exactly its /126.
        assert!(!is_looping_dst(ip("fdfe:dcba:9876::1"), net()));
        assert!(!is_looping_dst(ip("fdfe:dcba:9876::4"), dual_net()));
        assert!(!is_looping_dst(ip("2001:db8::1"), dual_net()));
    }
}
