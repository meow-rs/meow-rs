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
use ipnet::Ipv4Net;
use lwip::UdpSocket;
use meow_common::{with_dial_timeout, ConnType, Metadata, Network};
use meow_dns::server::{hex_prefix, DnsServer, LocalAnswer};
use meow_tunnel::{ResolvedTarget, Tunnel};
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};
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

/// Sweep dead flow-table entries every this many datagrams.
const SWEEP_INTERVAL: u32 = 256;

/// `(payload, packet source, packet destination)` — the netstack `UdpMsg`
/// layout, so a reply to a flow is sent as `(payload, dst, src)`.
type ReplyMsg = (Vec<u8>, SocketAddr, SocketAddr);

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
/// every client datagram AND by the flow task on every upstream reply —
/// a reply-mostly flow (e.g. a QUIC download mid-stream) must not look
/// idle to the LRU eviction at `MAX_FLOWS`.
struct FlowEntry {
    tx: mpsc::Sender<Vec<u8>>,
    last_activity: Arc<AtomicU64>,
}

pub(super) async fn run_udp(
    tunnel: Tunnel,
    socket: Box<UdpSocket>,
    dns_hijack: bool,
    udp_timeout: Duration,
    in_name: String,
    tun_net: Ipv4Net,
    live_flows: Arc<AtomicUsize>,
) {
    let (write_half, mut read_half) = socket.split();

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

    // Flow table, touched only by this loop. A flow task signals its own
    // death by closing its queue; the entry is evicted lazily — on the next
    // datagram for the tuple, by the periodic sweep, or by LRU eviction
    // when the table reaches MAX_FLOWS (issue #515).
    let mut flows: HashMap<FlowKey, FlowEntry> = HashMap::new();
    let mut sweep_countdown = SWEEP_INTERVAL;
    let hijack_permits = Arc::new(tokio::sync::Semaphore::new(HIJACK_IN_FLIGHT));
    let hijack_dropped = AtomicU64::new(0);

    while let Some((data, src, dst)) = read_half.next().await {
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
                                let _ = reply_tx.send((response, dst, src)).await;
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
            flows.retain(|_, e| !e.tx.is_closed());
            live_flows.store(flows.len(), Ordering::Relaxed);
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
                        live_flows.store(flows.len(), Ordering::Relaxed);
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
        live_flows.store(flows.len(), Ordering::Relaxed);
        tokio::spawn(flow_task(
            tunnel.clone(),
            FlowSpec {
                rx,
                reply_tx: reply_tx.clone(),
                key,
                udp_timeout,
                in_name: in_name.clone(),
                last_activity,
            },
        ));
    }
    live_flows.store(0, Ordering::Relaxed);
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
/// `rx.recv() == None` shutdown path.
fn evict_for_admission(flows: &mut HashMap<FlowKey, FlowEntry>) {
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
/// is the table entry's shared stamp — every upstream reply refreshes it so
/// a reply-mostly flow is not mistaken for idle by LRU eviction.
async fn relay_flow(tunnel: &Tunnel, spec: FlowSpec) -> Result<(), String> {
    let FlowSpec {
        mut rx,
        reply_tx,
        key: (src, dst),
        udp_timeout,
        in_name,
        last_activity,
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
    if metadata.dst_ip.is_none() && !metadata.host.is_empty() {
        metadata.dst_ip = inner.resolver().resolve_ip_real(&metadata.host).await;
    }
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
        "UDP {} --> {} match {}({}) using {}",
        src,
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    // Taken before the dial so a flush landing mid-dial still ends the flow
    // (issue #695): its socket may predate the new outbound binding.
    let mut flush = inner.udp_flush_watch();
    let conn: std::sync::Arc<dyn meow_common::ProxyPacketConn> = std::sync::Arc::from(
        with_dial_timeout(proxy.name(), proxy.dial_udp(&metadata))
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
    let idle = sleep(udp_timeout);
    tokio::pin!(idle);
    let result = loop {
        tokio::select! {
            () = &mut idle => break Ok(()), // idle-timeout eviction
            // Outbound sessions flushed (issue #695): end the flow; the
            // client's next datagram opens a fresh one with a fresh dial.
            () = flush.flushed() => break Ok(()),
            queued = rx.recv() => match queued {
                Some(data) => {
                    if let Err(e) = conn.write_packet(&data, &dst_addr).await {
                        break Err(format!("upstream write {dst_addr}: {e}"));
                    }
                    idle.as_mut().reset(Instant::now() + udp_timeout);
                }
                None => break Ok(()), // reader loop gone — listener shutdown
            },
            received = up_rx.recv() => match received {
                Some(data) => {
                    if reply_tx.send((data, dst, src)).await.is_err() {
                        break Ok(()); // stack writer gone — listener shutdown
                    }
                    last_activity.store(activity_ms(), Ordering::Relaxed);
                    idle.as_mut().reset(Instant::now() + udp_timeout);
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

/// True when a dial to `dst` could only route back into the TUN device —
/// its own subnet (on-link, including the device address and the subnet
/// broadcast), the IPv4 limited broadcast, or multicast. Relaying such a
/// destination re-enters the device and spawns a fresh flow from a new
/// source port each round: an amplification loop. Windows NetBIOS
/// name-service broadcasts to the subnet broadcast address (e.g.
/// `172.19.0.3:137` for the default `172.19.0.1/30`) trigger exactly this,
/// exhausting ephemeral ports within seconds of TUN start.
pub(super) fn is_looping_dst(dst: std::net::IpAddr, tun_net: Ipv4Net) -> bool {
    match dst {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || tun_net.contains(&v4),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::{evict_for_admission, is_looping_dst, FlowEntry, MAX_FLOWS};
    use ipnet::Ipv4Net;
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};

    /// Build a flow table holding `live` live entries plus `dead` entries
    /// whose receiver was dropped (channel closed). Live entries are kept
    /// alive via `keepers`. Activity stamps increase with the loop index —
    /// index 0 is the least recently active.
    fn seeded_table(
        live: usize,
        dead: usize,
    ) -> (
        HashMap<super::FlowKey, FlowEntry>,
        Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    ) {
        let mut flows = HashMap::new();
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
            !flows.contains_key(&oldest_key),
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
        assert!(flows.contains_key(&oldest_key), "refreshed flow survives");
        assert!(
            !flows.contains_key(&next_oldest_key),
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
                },
            )
            .await;
            assert!(result.unwrap_err().contains("rejected"));
        }
    }

    fn net() -> Ipv4Net {
        "172.19.0.1/30".parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn drops_tun_subnet_broadcast_and_multicast() {
        // The NetBIOS storm case: subnet broadcast of the /30.
        assert!(is_looping_dst(ip("172.19.0.3"), net()));
        // The device's own address and anything else on-link.
        assert!(is_looping_dst(ip("172.19.0.1"), net()));
        assert!(is_looping_dst(ip("172.19.0.2"), net()));
        // Limited broadcast and multicast (mDNS/SSDP/LLMNR).
        assert!(is_looping_dst(ip("255.255.255.255"), net()));
        assert!(is_looping_dst(ip("224.0.0.251"), net()));
        assert!(is_looping_dst(ip("ff02::fb"), net()));
    }

    #[test]
    fn keeps_routable_destinations() {
        // Fake-IP range traffic — the whole point of the TUN.
        assert!(!is_looping_dst(ip("198.18.0.5"), net()));
        // Ordinary unicast, v4 and v6.
        assert!(!is_looping_dst(ip("8.8.8.8"), net()));
        assert!(!is_looping_dst(ip("2001:db8::1"), net()));
        // Just outside the /30.
        assert!(!is_looping_dst(ip("172.19.0.4"), net()));
    }
}
