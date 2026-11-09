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
use meow_dns::server::{hex_prefix, DnsServer, LocalAnswer, LocalResponse};
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
type FlowOwners = HashMap<tokio::task::Id, (FlowKey, Arc<AtomicU64>)>;

fn reap_flow(flows: &mut FlowTable, owners: &mut FlowOwners, id: tokio::task::Id) {
    if let Some((key, identity)) = owners.remove(&id) {
        // The timestamp allocation belongs to this incarnation of the flow.
        // An old completion must not remove a replacement with the same key.
        if flows
            .get(&key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.last_activity, &identity))
        {
            flows.remove(&key);
        }
    }
}

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
    /// Owning task's id — every entry removal must also drop this slot
    /// from `flow_owners` so slow-winding evictees cannot accumulate
    /// stale owner records (`None` only in test fixtures).
    task_id: Option<tokio::task::Id>,
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
    // One owner for the loop's cancellable async work: flows, DNS queries
    // and the lwIP reply pump. Blocking nftset hooks are handled separately.
    let mut tasks = tokio::task::JoinSet::new();
    let (reply_tx, mut incoming) = match io {
        UdpIo::Lwip(socket) => {
            let (write_half, read_half) = socket.split();
            let (reply_tx, mut reply_rx) = mpsc::channel::<ReplyMsg>(REPLY_QUEUE);
            tasks.spawn(async move {
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
    // gauge share however this future ends. Completions remove their own
    // entries even without another datagram. The closed-queue, sweep and LRU
    // paths remain admission backstops (issue #515).
    let mut flows = FlowTable::new(live_flows);
    let mut flow_owners = FlowOwners::new();
    let mut sweep_countdown = SWEEP_INTERVAL;
    let hijack_permits = Arc::new(tokio::sync::Semaphore::new(HIJACK_IN_FLIGHT));
    let hijack_dropped = Arc::new(AtomicU64::new(0));

    loop {
        let packet = tokio::select! {
            packet = incoming.next() => packet,
            done = tasks.join_next_with_id(), if !tasks.is_empty() => {
                let id = match done {
                    Some(Ok((id, ()))) => id,
                    Some(Err(error)) => {
                        if error.is_panic() {
                            // Flow tasks own a table entry; helpers (hijack
                            // queries, the reply pump) do not — the owner map
                            // distinguishes which subsystem panicked.
                            if flow_owners.contains_key(&error.id()) {
                                warn!("tun UDP flow task survived a panic: {error}");
                            } else {
                                warn!("tun UDP helper task survived a panic: {error}");
                            }
                        } else {
                            debug!("tun UDP worker: {error}");
                        }
                        error.id()
                    }
                    None => continue,
                };
                reap_flow(&mut flows, &mut flow_owners, id);
                // Reap completions even with no incoming packets; otherwise
                // finished task records accumulate for the listener lifetime.
                continue;
            }
        };
        let Some((data, src, dst)) = packet else {
            break;
        };
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
                LocalAnswer::Answer(LocalResponse { response, hook }) => {
                    match hook {
                        // `dns.nftset` ordering, same as the serve loop:
                        // the (blocking) element add finishes before this
                        // answer is queued for the stack writer.
                        Some(work) => {
                            let reply_tx = reply_tx.clone();
                            let hijack_dropped = Arc::clone(&hijack_dropped);
                            tokio::task::spawn_blocking(move || {
                                work.run();
                                if reply_tx.try_send((response, dst, src)).is_err() {
                                    note_hijack_drop(&hijack_dropped);
                                }
                            });
                        }
                        None => {
                            if reply_tx.try_send((response, dst, src)).is_err() {
                                note_hijack_drop(&hijack_dropped);
                            }
                        }
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
                    tasks.spawn(async move {
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
            // and on `Drop` for whatever is left. Shed entries drop their
            // `flow_owners` slot too: the completion will find nothing to
            // reap and skip harmlessly.
            flows.retain(|_, e| {
                if e.tx.is_closed() {
                    if let Some(id) = e.task_id {
                        flow_owners.remove(&id);
                    }
                    false
                } else {
                    true
                }
            });
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
                        let task_id = entry.task_id;
                        flows.remove(&key);
                        if let Some(id) = task_id {
                            flow_owners.remove(&id);
                        }
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
            evict_for_admission(&mut flows, &mut flow_owners);
        }

        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        tx.try_send(data).expect("fresh flow queue has capacity");
        let last_activity = Arc::new(AtomicU64::new(activity_ms()));
        let identity = Arc::clone(&last_activity);
        let task = tasks.spawn(flow_task(
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
        let task_id = task.id();
        flows.insert(
            key,
            FlowEntry {
                tx,
                last_activity: Arc::clone(&identity),
                task_id: Some(task_id),
            },
        );
        flow_owners.insert(task_id, (key, identity));
    }
    // Stop flows parked in dial/write and DNS queries waiting for upstream.
    // Each flow owns its reply reader, which is cancelled with it; also stop
    // the reply pump instead of waiting for every cloned sender to disappear.
    drop(flows);
    tasks.shutdown().await;
    // On external cancellation the table and set also clean up via Drop.
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
fn evict_for_admission(flows: &mut FlowTable, owners: &mut FlowOwners) {
    flows.retain(|_, e| {
        if e.tx.is_closed() {
            if let Some(id) = e.task_id {
                owners.remove(&id);
            }
            false
        } else {
            true
        }
    });
    if flows.len() >= MAX_FLOWS {
        if let Some((victim, task_id)) = flows
            .iter()
            .min_by_key(|(_, e)| e.last_activity.load(Ordering::Relaxed))
            .map(|(k, e)| (*k, e.task_id))
        {
            debug!("tun UDP flow table full: evicting LRU flow {victim:?}");
            flows.remove(&victim);
            if let Some(id) = task_id {
                owners.remove(&id);
            }
        }
    }
}

async fn flow_task(tunnel: Tunnel, spec: FlowSpec) {
    let (src, dst) = spec.key;
    if let Err(e) = relay_flow(&tunnel, spec).await {
        debug!("tun UDP {src} -> {dst}: {e}");
    }
}

/// Map a completed reply-reader join to the flow's exit error — the
/// reader owns the only `up_tx`, so any reader exit ends the flow.
/// `None` (empty set) is unreachable today — every earlier `join_next`
/// breaks out — and folds into the clean-exit message.
fn reply_reader_exit(done: Option<Result<Result<(), String>, tokio::task::JoinError>>) -> String {
    match done {
        Some(Ok(Err(e))) => e,
        Some(Ok(Ok(()))) | None => "downstream reader exited".into(),
        Some(Err(e)) => format!("downstream reader task: {e}"),
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
    // Capture the generation before any await, including sniffing and DNS.
    // A refresh must cancel establishment, not just a connected relay.
    let mut flush = tunnel.inner().udp_flush_watch();
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

    // Flush and error returns below exit before `held` is flushed to the
    // conn: say so when that drops datagrams — the client sent its
    // Initials and otherwise waits out its idle timeout for answers that
    // were never forwarded.
    let drop_held = |held: &[Vec<u8>]| {
        if !held.is_empty() {
            debug!(
                "tun UDP {src} -> {dst}: dropping {} held QUIC Initial datagram(s) unsent",
                held.len()
            );
        }
    };

    if sniffer.is_some() {
        crate::sniffer::prefill_host(&tunnel.inner().resolver(), &mut metadata);
    }
    if let Some(rt) = sniffer.as_deref().filter(|rt| rt.wants_quic(&metadata)) {
        let deadline = Instant::now() + rt.timeout();
        let mut quic = crate::sniffer_quic::QuicSniffer::default();
        while held.len() < QUIC_SNIFF_PACKETS {
            let packet = tokio::select! {
                biased;
                () = flush.flushed() => {
                    drop_held(&held);
                    return Ok(());
                }
                packet = tokio::time::timeout_at(deadline, rx.recv()) => packet,
            };
            let Ok(Some(data)) = packet else { break };
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
        drop_held(&held);
        return Err("unmapped fake-ip destination".into());
    }
    // UDP keeps the eager pre_resolve (no lazy enrichment): the outbound
    // packet API below needs a resolved dst_ip regardless of what the rules
    // demand — including after a fake-IP was rewritten back to a hostname.
    tokio::select! {
        biased;
        () = flush.flushed() => {
            drop_held(&held);
            // A flush between pre_resolve and resolve_udp_dst can leave
            // metadata half-resolved; it is never read after this return.
            return Ok(());
        }
        () = async {
            inner.pre_resolve(&mut metadata).await;
            inner.resolve_udp_dst(&mut metadata).await;
        } => {}
    }
    let Some(dst_ip) = metadata.dst_ip else {
        drop_held(&held);
        return Err(format!(
            "dst_ip not resolved for {}",
            metadata.remote_address()
        ));
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);

    // Non-hijacked client traffic follows the same policy on every port.
    let target = tokio::select! {
        biased;
        () = flush.flushed() => {
            drop_held(&held);
            return Ok(());
        }
        target = inner.resolve_proxy(&metadata) => target,
    };
    let Some(ResolvedTarget {
        adapter: proxy,
        rule_name,
        rule_payload,
        route: _route,
    }) = target
    else {
        drop_held(&held);
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

    // Prioritize an already-pending flush even if the dial is ready too.
    // Invariant: dial_udp must not spawn detached tasks — cancellation via
    // future drop must release every socket the dial opened.
    let dialed = tokio::select! {
        biased;
        () = flush.flushed() => {
            drop_held(&held);
            return Ok(());
        }
        result = inner.dial_udp(proxy.as_ref(), &metadata) => result,
    };
    let conn: std::sync::Arc<dyn meow_common::ProxyPacketConn> = match dialed {
        Ok(conn) => std::sync::Arc::from(conn),
        Err(e) => {
            drop_held(&held);
            return Err(format!("dial_udp via {}: {e}", proxy.name()));
        }
    };
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
    // A one-task set keeps the reader owned by this flow on cancellation,
    // and lets normal exits wait for its in-flight read and buffer to drop.
    let mut reply_task = tokio::task::JoinSet::new();
    reply_task.spawn({
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
    let idle = sleep_until(next_deadline(udp_timeout));
    tokio::pin!(idle);
    let result = 'flow: {
        // The held Initials go upstream first — through the same nested
        // select! the steady-state loop below uses: a stream-framed conn
        // (Trojan/VLESS UoT) can park write_packet for up to
        // `connection_timeout`, and idle expiry, a config-reload flush or
        // a dead reply reader must still be able to end the flow.
        for data in held {
            let write_result = tokio::select! {
                () = &mut idle => break 'flow Ok(()), // idle-timeout during write
                () = flush.flushed() => break 'flow Ok(()), // flush during write
                done = reply_task.join_next() => break 'flow Err(reply_reader_exit(done)),
                r = conn.write_packet(&data, &dst_addr) => r,
            };
            match write_result {
                Ok(n) if n == data.len() => {
                    idle.as_mut().reset(next_deadline(udp_timeout));
                }
                Ok(n) => {
                    break 'flow Err(format!(
                        "upstream write {dst_addr}: short write {n}/{}",
                        data.len()
                    ));
                }
                Err(e) => {
                    break 'flow Err(format!("upstream write {dst_addr}: {e}"));
                }
            }
        }
        loop {
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
                            done = reply_task.join_next() => break Err(reply_reader_exit(done)),
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
                    // set removes its completed task, so shutdown will not poll it twice.
                    None => break Err(reply_reader_exit(reply_task.join_next().await)),
                },
            }
        }
    };

    reply_task.shutdown().await;
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
                    task_id: None,
                },
            );
        }
        (flows, keepers)
    }

    #[test]
    fn evict_for_admission_reclaims_dead_before_touching_live() {
        let (mut flows, _keepers) = seeded_table(MAX_FLOWS - 1, 3);
        evict_for_admission(&mut flows, &mut super::FlowOwners::new());
        assert_eq!(flows.len(), MAX_FLOWS - 1, "only dead entries removed");
    }

    #[test]
    fn evict_for_admission_evicts_least_recently_active() {
        let (mut flows, _keepers) = seeded_table(MAX_FLOWS, 0);
        // seeded_table stamps index 0 as least-recently-active.
        let oldest_key: super::FlowKey = (([10, 0, 0, 1], 10000).into(), ([8, 8, 8, 8], 53).into());
        evict_for_admission(&mut flows, &mut super::FlowOwners::new());
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
        evict_for_admission(&mut flows, &mut super::FlowOwners::new());
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
                super::cleanup_tests::live_tunnel(),
                super::UdpIo::Direct { incoming, replies },
                false,
                Duration::from_secs(60),
                "tun".to_string(),
                net(),
                Arc::clone(&gauge),
                None,
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
            super::cleanup_tests::live_tunnel(),
            super::UdpIo::Direct { incoming, replies },
            false,
            Duration::from_secs(60),
            "tun".to_string(),
            net,
            Arc::clone(&gauge),
            None,
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

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use meow_common::{Proxy, ProxyAdapter, ProxyHealth, ProxyPacketConn};
    use std::sync::atomic::AtomicBool;
    use tokio::sync::Notify;

    #[derive(Default)]
    struct Probe {
        reading: Notify,
        dialing: Notify,
        stall_dial: AtomicBool,
        dial_dropped: AtomicBool,
        writing: Notify,
        release_read: Notify,
        read_dropped: AtomicBool,
        conn_dropped: Notify,
        closed_while_reading: AtomicBool,
    }
    struct DialGuard(Arc<Probe>);
    impl Drop for DialGuard {
        fn drop(&mut self) {
            self.0.dial_dropped.store(true, Ordering::SeqCst);
        }
    }
    struct Conn(Arc<Probe>);
    impl Drop for Conn {
        fn drop(&mut self) {
            self.0.conn_dropped.notify_one();
        }
    }
    struct ReadGuard(Arc<Probe>);
    impl Drop for ReadGuard {
        fn drop(&mut self) {
            self.0.read_dropped.store(true, Ordering::SeqCst);
        }
    }
    #[async_trait::async_trait]
    impl ProxyPacketConn for Conn {
        async fn read_packet(&self, _: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            let _guard = ReadGuard(Arc::clone(&self.0));
            self.0.reading.notify_one();
            self.0.release_read.notified().await;
            Err(std::io::Error::other("fixture reader ended").into())
        }
        async fn write_packet(&self, _: &[u8], _: &SocketAddr) -> meow_common::Result<usize> {
            self.0.writing.notify_one();
            std::future::pending().await
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok(([127, 0, 0, 1], 0).into())
        }
        fn close(&self) -> meow_common::Result<()> {
            self.0.closed_while_reading.store(
                !self.0.read_dropped.load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
            Ok(())
        }
    }
    struct FixtureProxy {
        probe: Arc<Probe>,
        health: ProxyHealth,
    }
    #[async_trait::async_trait]
    impl ProxyAdapter for FixtureProxy {
        fn name(&self) -> &str {
            "cleanup-fixture"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            true
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
        async fn dial_tcp(
            &self,
            _: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            Err(meow_common::MeowError::NotSupported("no tcp".into()))
        }
        async fn dial_udp(&self, _: &Metadata) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
            if self.probe.stall_dial.load(Ordering::SeqCst) {
                let _guard = DialGuard(Arc::clone(&self.probe));
                self.probe.dialing.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(Box::new(Conn(Arc::clone(&self.probe))))
        }
    }
    impl Proxy for FixtureProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            vec![]
        }
    }
    fn fixture() -> (Tunnel, FlowSpec, mpsc::Sender<Vec<u8>>, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        let tunnel = crate::test_rule_tunnel();
        let mut config = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        config.proxies.insert(
            "cleanup-fixture".into(),
            Arc::new(FixtureProxy {
                probe: Arc::clone(&probe),
                health: ProxyHealth::new(),
            }),
        );
        tunnel.update_proxies(config.proxies, config.dialer_registry);
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "cleanup-fixture",
        ))]);
        let (tx, rx) = mpsc::channel(1);
        let (reply_tx, _reply_rx) = mpsc::channel(1);
        let spec = FlowSpec {
            rx,
            reply_tx,
            key: (([10, 0, 0, 2], 12345).into(), ([192, 0, 2, 1], 443).into()),
            udp_timeout: Duration::from_secs(60),
            in_name: "tun".into(),
            last_activity: Arc::new(AtomicU64::new(0)),
            sniffer: None,
        };
        (tunnel, spec, tx, probe)
    }

    // Occupancy tests must keep an actual flow alive: REJECT completes
    // immediately and is now correctly removed by the completion branch.
    pub(super) fn live_tunnel() -> Tunnel {
        fixture().0
    }

    #[tokio::test]
    async fn old_completion_preserves_same_key_replacement_even_on_panic() {
        for panic in [false, true] {
            let gauge = Arc::new(AtomicUsize::new(0));
            let mut flows = FlowTable::new(Arc::clone(&gauge));
            let mut owners = FlowOwners::new();
            let key = (([10, 0, 0, 2], 12345).into(), ([192, 0, 2, 1], 443).into());
            let old = Arc::new(AtomicU64::new(0));
            let fresh = Arc::new(AtomicU64::new(0));
            let mut tasks = tokio::task::JoinSet::new();
            let id = tasks
                .spawn(async move {
                    assert!(!panic, "fixture panic");
                })
                .id();
            owners.insert(id, (key, old));
            let (tx, _rx) = mpsc::channel(1);
            flows.insert(
                key,
                FlowEntry {
                    tx,
                    last_activity: Arc::clone(&fresh),
                    task_id: Some(id),
                },
            );
            let completed = match tasks.join_next_with_id().await.unwrap() {
                Ok((id, ())) => id,
                Err(error) => error.id(),
            };
            reap_flow(&mut flows, &mut owners, completed);
            assert_eq!(gauge.load(Ordering::Relaxed), 1);
            assert!(Arc::ptr_eq(&flows.get(&key).unwrap().last_activity, &fresh));
            assert!(owners.is_empty());
            // A completion of the current incarnation removes it exactly
            // once — the second call no-ops because the owner slot was
            // already consumed by the first (early-return on `None`), not
            // because the identity check rejects it again.
            owners.insert(id, (key, fresh));
            reap_flow(&mut flows, &mut owners, id);
            reap_flow(&mut flows, &mut owners, id);
            assert_eq!(gauge.load(Ordering::Relaxed), 0);
            assert_eq!(flows.len(), 0);
        }
    }

    #[tokio::test]
    async fn finished_flow_reclaims_table_without_more_packets() {
        let (tunnel, spec, _tx, probe) = fixture();
        let (tx, incoming) = mpsc::channel(1);
        let (replies, _rx) = mpsc::channel(1);
        let gauge = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_udp(
            tunnel,
            UdpIo::Direct { incoming, replies },
            false,
            Duration::from_secs(60),
            "tun".into(),
            TunNets {
                v4: "198.18.0.1/30".parse().unwrap(),
                v6: None,
                nat: None,
            },
            Arc::clone(&gauge),
            None,
        ));
        tx.send((vec![1], spec.key.0, spec.key.1)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), probe.reading.notified())
            .await
            .unwrap();
        assert_eq!(gauge.load(Ordering::Relaxed), 1);
        probe.release_read.notify_one();
        tokio::time::timeout(Duration::from_secs(2), probe.conn_dropped.notified())
            .await
            .unwrap();
        let reclaimed = tokio::time::timeout(Duration::from_secs(1), async {
            while gauge.load(Ordering::Relaxed) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        drop(tx);
        task.await.unwrap();
        assert!(
            reclaimed.is_ok(),
            "completed flow stayed in table without new packets"
        );
    }

    async fn stop_loop_with_pending_dns(abort: bool) {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec![upstream.local_addr().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        let (tx, incoming) = mpsc::channel(1);
        let (replies, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(run_udp(
            Tunnel::new(resolver),
            UdpIo::Direct { incoming, replies },
            true,
            Duration::from_secs(60),
            "tun".into(),
            TunNets {
                v4: "198.18.0.1/30".parse().unwrap(),
                v6: None,
                nat: None,
            },
            Arc::new(AtomicUsize::new(0)),
            None,
        ));
        // Standard recursive TXT question for example.com, with no local answer.
        let query = b"\x00\x2a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x10\x00\x01".to_vec();
        tx.send((
            query,
            ([10, 0, 0, 2], 12345).into(),
            ([8, 8, 8, 8], 53).into(),
        ))
        .await
        .unwrap();
        let mut packet = [0u8; 4096];
        let (n, peer) =
            tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        // The real query is now in flight, not merely queued for the loop.
        if abort {
            task.abort();
        }
        drop(tx);
        let done = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap();
        if abort {
            assert!(done.unwrap_err().is_cancelled());
        } else {
            done.unwrap();
        }
        let closed = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
        // Release the baseline's detached query as well: a valid NOERROR,
        // empty response. Cleanup must not depend on this delayed response.
        packet[2] = 0x81;
        packet[3] = 0x80;
        upstream.send_to(&packet[..n], peer).await.unwrap();
        assert!(
            matches!(closed, Ok(None)),
            "stopped UDP loop retained a DNS reply sender"
        );
    }

    #[tokio::test]
    async fn tun_dns_query_cancelled_on_loop_eof() {
        stop_loop_with_pending_dns(false).await;
    }

    #[tokio::test]
    async fn tun_dns_query_cancelled_on_loop_abort() {
        stop_loop_with_pending_dns(true).await;
    }

    #[tokio::test]
    async fn flush_cancels_pending_udp_dial() {
        let (tunnel, spec, _tx, probe) = fixture();
        probe.stall_dial.store(true, Ordering::SeqCst);
        let worker_tunnel = tunnel.clone();
        let mut task = tokio::spawn(async move { relay_flow(&worker_tunnel, spec).await });
        tokio::time::timeout(Duration::from_secs(2), probe.dialing.notified())
            .await
            .unwrap();
        assert_eq!(tunnel.close_all_udp_sessions(), 1);
        let done = tokio::time::timeout(Duration::from_secs(1), &mut task).await;
        if done.is_err() {
            task.abort();
            let _ = task.await;
        }
        assert!(done.is_ok(), "flush left the old outbound dial pending");
        assert!(done.unwrap().unwrap().is_ok());
        assert!(probe.dial_dropped.load(Ordering::SeqCst));
        assert_eq!(tunnel.close_all_udp_sessions(), 0, "watch was released");
    }

    #[tokio::test]
    async fn flush_cancels_pending_udp_sniff() {
        let (tunnel, mut spec, tx, _probe) = fixture();
        spec.sniffer = Some(Arc::new(crate::sniffer::SnifferRuntime::new(
            meow_common::sniffer::SnifferConfig {
                enable: true,
                quic_ports: vec![443],
                timeout: Duration::from_secs(60),
                ..Default::default()
            },
        )));
        let relay = relay_flow(&tunnel, spec);
        tokio::pin!(relay);
        // Feed one packet so the first poll lands inside the sniff-loop
        // select, not at the function entry — the flush arm under test is
        // the loop's, and a second recv parks there awaiting packet two.
        // A v1 0-RTT long-header with a zero-length payload feeds `More`
        // (not Initial): the loop stays parked on `rx.recv()`.
        tx.try_send(vec![0xd0, 0, 0, 0, 1, 0, 0, 0]).unwrap();
        assert!(futures::poll!(&mut relay).is_pending());
        let count = tunnel.close_all_udp_sessions();
        let done = tokio::time::timeout(Duration::from_secs(1), &mut relay).await;
        assert!(done.is_ok(), "flush left the QUIC gather pending");
        assert!(done.unwrap().is_ok());
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn flush_cancels_pending_udp_resolution() {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let raw = meow_config::parse_raw_yaml(&format!(
            "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: ['{}']\n",
            upstream.local_addr().unwrap()
        ))
        .unwrap();
        let dns =
            meow_config::parse_dns_from_raw(&raw, None, &HashMap::new(), None, None, None, None)
                .await
                .unwrap();
        let resolver = dns.resolver;
        let fake = resolver.lookup_ipv4("pending.example").await.unwrap();
        let (tunnel, mut spec, _tx, probe) = fixture();
        tunnel.set_resolver(resolver);
        spec.key.1.set_ip(fake);
        let worker_tunnel = tunnel.clone();
        let mut task = tokio::spawn(async move { relay_flow(&worker_tunnel, spec).await });
        let mut packet = [0u8; 4096];
        tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        let count = tunnel.close_all_udp_sessions();
        let done = tokio::time::timeout(Duration::from_secs(1), &mut task).await;
        if done.is_err() {
            task.abort();
            let _ = task.await;
        }
        assert!(done.is_ok(), "flush left pre-dial DNS resolution pending");
        assert!(done.unwrap().unwrap().is_ok());
        assert_eq!(count, 1, "resolving flows must already hold a flush watch");
        assert!(!probe.read_dropped.load(Ordering::SeqCst));
    }

    async fn loop_stop_releases_blocked_flow(abort: bool) {
        let (tunnel, spec, _keepalive_tx, probe) = fixture();
        let flush = tunnel.clone();
        let (incoming_tx, incoming) = mpsc::channel(1);
        let (replies, _reply_rx) = mpsc::channel(1);
        let gauge = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_udp(
            tunnel,
            UdpIo::Direct { incoming, replies },
            false,
            Duration::from_secs(60),
            "tun".into(),
            TunNets {
                v4: "198.18.0.1/30".parse().unwrap(),
                v6: None,
                nat: None,
            },
            Arc::clone(&gauge),
            None,
        ));
        incoming_tx
            .send((vec![1], spec.key.0, spec.key.1))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            probe.reading.notified().await;
            probe.writing.notified().await;
        })
        .await
        .unwrap();
        assert_eq!(gauge.load(Ordering::Relaxed), 1);
        if abort {
            task.abort();
        }
        drop(incoming_tx);
        let outcome = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap();
        if abort {
            assert!(outcome.unwrap_err().is_cancelled());
        } else {
            outcome.unwrap();
        }
        assert_eq!(gauge.load(Ordering::Relaxed), 0);
        let released =
            tokio::time::timeout(Duration::from_secs(2), probe.conn_dropped.notified()).await;
        // Clean up the unfixed baseline too; the assertion must not rely on
        // this external flush or the 60-second idle deadline.
        flush.close_all_udp_sessions();
        probe.release_read.notify_one();
        assert!(
            released.is_ok(),
            "UDP loop stopped but its blocked flow retained the connection"
        );
        assert!(probe.read_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tun_udp_loop_eof_releases_blocked_flow() {
        loop_stop_releases_blocked_flow(false).await;
    }

    #[tokio::test]
    async fn tun_udp_loop_abort_releases_blocked_flow() {
        loop_stop_releases_blocked_flow(true).await;
    }

    #[tokio::test]
    async fn tun_udp_exit_joins_reader_before_closing_conn() {
        let (tunnel, spec, tx, probe) = fixture();
        let stop = async {
            probe.reading.notified().await;
            drop(tx);
        };
        // Poll the real relay in this task: after it returns, the assertion
        // runs before a detached reader can incidentally get scheduled.
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(relay_flow(&tunnel, spec), stop)
        })
        .await
        .unwrap();
        assert!(result.is_ok());
        assert!(
            !probe.closed_while_reading.load(Ordering::SeqCst),
            "connection closed while the reader still owned an in-flight read"
        );
        assert!(probe.read_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tun_udp_cancel_does_not_detach_reader() {
        let (tunnel, spec, _tx, probe) = fixture();
        let flow = tokio::spawn(async move { relay_flow(&tunnel, spec).await });
        tokio::time::timeout(Duration::from_secs(2), probe.reading.notified())
            .await
            .unwrap();
        flow.abort();
        assert!(flow.await.unwrap_err().is_cancelled());
        let released =
            tokio::time::timeout(Duration::from_secs(2), probe.conn_dropped.notified()).await;
        // Also release the baseline's leaked task, so a red test leaves no
        // fixture task waiting indefinitely.
        probe.release_read.notify_one();
        assert!(
            released.is_ok(),
            "cancelled flow detached its reader and packet connection"
        );
    }

    #[tokio::test]
    async fn tun_udp_flush_during_write_joins_reader() {
        let (tunnel, spec, tx, probe) = fixture();
        tx.send(vec![1]).await.unwrap();
        let flush = async {
            probe.reading.notified().await;
            probe.writing.notified().await;
            tunnel.close_all_udp_sessions();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(relay_flow(&tunnel, spec), flush)
        })
        .await
        .unwrap();
        assert!(result.is_ok());
        assert!(!probe.closed_while_reading.load(Ordering::SeqCst));
        assert!(probe.read_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tun_udp_reader_error_finishes_without_rejoining_consumed_task() {
        let (tunnel, spec, tx, probe) = fixture();
        tx.send(vec![1]).await.unwrap(); // pending write must not hide reader death
        let finish = async {
            probe.reading.notified().await;
            probe.release_read.notify_one();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(relay_flow(&tunnel, spec), finish)
        })
        .await
        .unwrap();
        assert!(result.unwrap_err().contains("fixture reader ended"));
        assert!(!probe.closed_while_reading.load(Ordering::SeqCst));
    }
}
