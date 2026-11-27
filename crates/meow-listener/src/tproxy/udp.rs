//! UDP TPROXY datagram path for the `tproxy` listener (issue #564).
//!
//! Linux-only and opt-in (`listeners[].udp: true`); requires
//! `firewall: false` — meow never installs the PREROUTING TPROXY rules,
//! the matching `ip rule`/`local` route table, or any sysctl. The
//! deployment contract is in `docs/tproxy-gateway.md`.
//!
//! Plane layout:
//!
//! ```text
//! LAN client ──udp──▶ kernel TPROXY ──▶ listener socket (IP_TRANSPARENT
//!                                        + IP_RECVORIGDSTADDR)
//!      ▲                                   │ recvmsg: (payload, client,
//!      │                                   │           original_dst)
//!      │                                   ▼
//!      │                            flow table (client, orig_dst)
//!      │                                   │  per-flow task: metadata →
//!      │                                   │  rules → dial_udp → pump
//!      │                                   ▼
//!      └─── transparent reply socket ◄── reply dispatch task
//!           bound to orig_dst (one          (shared cache, one bound
//!           per original destination)        socket per orig_dst)
//! ```
//!
//! The reply path cannot reuse the listener socket: `IP_PKTINFO` can pick
//! the source *address* but not an arbitrary source *port*, and the client
//! expects replies from `original_dst` exactly (incl. a fake-IP). So each
//! distinct original destination gets one `IP_TRANSPARENT` socket bound to
//! it, shared across clients. Those sockets never collide with the TPROXY
//! lookup — the kernel keys that lookup on `--on-port`, i.e. the listener
//! port — and they are write-only (nothing reads them; anything routed to
//! them is genuinely addressed to that destination).
//!
//! Flow machinery (`relay_udp_flow`, queue bounds) is platform-neutral and
//! unit-tested on every OS; the socket/`recvmsg` layer is `cfg(linux)`.

/// Per-flow routing/relay machinery — platform-neutral so the unit tests
/// below exercise it on every OS. In production it is only reachable from
/// the Linux socket layer.
#[cfg(any(target_os = "linux", test))]
pub(super) mod flow {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use meow_common::{ConnType, Metadata, Network};
    use meow_tunnel::{MatchedRule, Tunnel, UsingProxy};
    use tokio::sync::mpsc;
    use tokio::time::{sleep_until, Instant};
    use tracing::{debug, info};

    /// One datagram payload cap. UDP tops out below 64 KiB.
    pub(super) const DATAGRAM_BUF: usize = 65535;
    /// Per-flow upstream queue in datagrams — buffers while the flow task
    /// is routing/dialing; overflow is dropped (UDP semantics).
    pub(super) const FLOW_QUEUE: usize = 64;

    /// `(payload, original_dst, client)` — a reply is sent to `client`
    /// with `original_dst` as its source identity.
    pub(super) type ReplyMsg = (Vec<u8>, SocketAddr, SocketAddr);

    /// Everything a flow needs that is not the channels — the tuple key,
    /// its idle timeout, and the listener identity for metadata.
    pub(super) struct FlowCtx {
        pub client: SocketAddr,
        pub orig_dst: SocketAddr,
        pub udp_timeout: Duration,
        pub in_name: String,
        pub in_port: u16,
        /// The named listener's `proxy:`/`rule:` route override, shared
        /// with every sibling flow (Arc bump per flow).
        pub route_override: Option<Arc<meow_common::InboundRouteOverride>>,
    }

    /// Route `orig_dst` through the tunnel, dial the outbound, then pump
    /// datagrams both ways until `udp_timeout` of silence. Mirrors the TUN
    /// `relay_flow` shape; replies go through `reply_tx` so the caller
    /// decides how the client-facing transport materialises `original_dst`
    /// as source.
    ///
    /// `queued_bytes` tracks this flow's share of the inbound queue; it is
    /// decremented as datagrams are dequeued and dies with the flow.
    pub(super) async fn relay_udp_flow(
        tunnel: Tunnel,
        mut rx: mpsc::Receiver<Vec<u8>>,
        queued_bytes: Arc<AtomicUsize>,
        reply_tx: mpsc::Sender<ReplyMsg>,
        ctx: FlowCtx,
    ) -> Result<(), String> {
        let FlowCtx {
            client,
            orig_dst,
            udp_timeout,
            in_name,
            in_port,
            route_override,
        } = ctx;
        // The flow key and metadata dst are the ORIGINAL destination — which
        // may be a fake-IP — never the post-resolution address: two fake-IPs
        // that resolve to the same real service must keep separate reply
        // identities (issue #564 §2).
        let mut metadata = Metadata {
            network: Network::Udp,
            conn_type: ConnType::TProxy,
            src_ip: Some(client.ip()),
            src_port: client.port(),
            dst_ip: Some(orig_dst.ip()),
            dst_port: orig_dst.port(),
            in_name: in_name.into(),
            in_port,
            ..Default::default()
        };
        // The named listener's `proxy:`/`rule:` override stamps before
        // the fake-IP guard and the route scan (upstream Additions order)
        // — shared, not cloned: the ctx Arc is dead after this point.
        metadata.special_route = route_override;

        let inner = tunnel.inner();
        if matches!(
            inner.pre_handle_metadata(&mut metadata),
            meow_tunnel::PreHandleVerdict::Drop
        ) {
            return Err("unmapped fake-ip destination".into());
        }
        // UDP keeps the eager pre_resolve (no lazy enrichment): transports
        // dial `dst_ip` regardless of what the rules demand — including
        // after a fake-IP was rewritten back to a hostname.
        inner.pre_resolve(&mut metadata).await;
        let probed = inner.resolve_udp_dst(&mut metadata).await;

        // Port 53 follows ordinary routing — no implicit DNS hijack here
        // (external rules feed queries to the standalone DNS server if
        // wanted). A `REJECT` verdict resolves to the REJECT adapter, whose
        // `dial_udp` succeeds with a conn that errors on first read — the
        // flow dies and the datagrams drop; a UDP-incapable outbound errors
        // at dial. Either way datagrams are never silently diverted to
        // DIRECT.
        // When `resolve_udp_dst` probed it produced the committed
        // decision — use it so the direct-nameserver verdict and the
        // route agree (issue #974).
        let resolved = match probed {
            Some(target) => Some(target),
            None => inner.resolve_proxy_flow(&mut metadata).await,
        };
        let Some(meow_tunnel::ResolvedTarget {
            adapter: proxy,
            rule_name,
            rule_payload,
            route: _route,
        }) = resolved
        else {
            return Err(format!(
                "no matching rule for {}",
                metadata.remote_address()
            ));
        };
        // A `type: dns` leaf never contacts the destination — its conn only
        // echoes this addr back as the reply source, so mandatory
        // pre-resolution must not gate it and the ORIGINAL destination is
        // what gets stamped (issue #974 review). Transports keep requiring
        // `dst_ip` — they actually dial it.
        let dst_addr = if proxy.adapter_type() == meow_common::AdapterType::Dns {
            metadata.dns_udp_dst(Some(orig_dst))
        } else {
            let Some(dst_ip) = metadata.dst_ip else {
                return Err(format!(
                    "dst_ip not resolved for {}",
                    metadata.remote_address()
                ));
            };
            SocketAddr::new(dst_ip, metadata.dst_port)
        };
        info!(
            "UDP {client} --> {orig_dst} match {} using {}",
            MatchedRule::new(&rule_name, &rule_payload, proxy.name()),
            UsingProxy::new(proxy.as_ref(), &metadata)
        );

        // Taken before the dial so a flush landing mid-dial still ends the
        // flow (issue #695): its socket may predate the new outbound binding.
        let mut flush = inner.udp_flush_watch();
        let conn: Arc<dyn meow_common::ProxyPacketConn> = Arc::from(
            inner
                .dial_udp(proxy.as_ref(), &metadata)
                .await
                .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?,
        );
        // `_route` exists to pin the route-table generation across the
        // dial only — a long-lived flow must not keep its dial-time
        // generation alive across config reloads (same contract as the
        // TCP path).
        drop(_route);

        // Dedicated reader task holding one persistent buffer — reads are
        // never cancelled, so a stream-framed conn (e.g. Trojan UoT) cannot
        // lose a partially consumed frame to a dropped mid-flight read
        // (issue #514 pattern, same as the TUN path).
        let (up_tx, mut up_rx) = mpsc::channel::<Vec<u8>>(FLOW_QUEUE);
        let mut reply_task = tokio::spawn({
            let conn = Arc::clone(&conn);
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
                        queued_bytes.fetch_sub(data.len(), Ordering::Relaxed);
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
                    // recv loop gone — listener shutdown.
                    None => break Ok(()),
                },
                received = up_rx.recv() => match received {
                    Some(data) => {
                        // UDP drop semantics on backpressure: a full reply
                        // queue drops the datagram rather than stalling the
                        // flow (and its idle timer) on a slow dispatcher.
                        match reply_tx.try_send((data, orig_dst, client)) {
                            Ok(()) => idle.as_mut().reset(next_deadline(udp_timeout)),
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                debug!("tproxy UDP reply queue full: dropping reply to {client}");
                            }
                            // Dispatcher gone — listener shutdown.
                            Err(mpsc::error::TrySendError::Closed(_)) => break Ok(()),
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
}

#[cfg(target_os = "linux")]
mod linux {
    use super::flow::{self, ReplyMsg, DATAGRAM_BUF, FLOW_QUEUE};
    use meow_common::{Metadata, Network};
    use meow_tunnel::Tunnel;
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::Interest;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::Instant;
    use tracing::{debug, warn};

    /// First socket-level receive retry delay; doubles to one second. This
    /// mirrors `ErrorBackoff`'s curve, but the multiplexer stores absolute
    /// deadlines instead of awaiting inside a selectable branch.
    const RECV_BACKOFF_INITIAL: Duration = Duration::from_millis(10);
    const RECV_BACKOFF_MAX: Duration = Duration::from_secs(1);

    /// Per-flow queued-byte cap, independent of the datagram count — a flood
    /// of max-size datagrams cannot pin more than ~1 MiB of queue per flow.
    const FLOW_QUEUE_BYTES: usize = 1 << 20;
    /// Queue feeding the reply dispatcher (flow → client direction).
    const REPLY_QUEUE: usize = 512;
    /// Sweep dead flow-table entries every this many received datagrams.
    const SWEEP_INTERVAL: u32 = 256;
    /// Backoff before retrying a failed transparent-reply bind for the same
    /// destination, so a bad address cannot spin the datagram loop.
    const REPLY_BIND_BACKOFF: Duration = Duration::from_secs(1);
    /// Bound on distinct transparent-reply sockets (one FD per original
    /// destination) — beyond this, replies for new destinations are dropped.
    const MAX_REPLY_SOCKETS: usize = 1024;
    /// Reply sockets idle longer than this are evicted — long-running
    /// gateways see unbounded distinct destinations otherwise.
    const REPLY_SOCKET_IDLE: Duration = Duration::from_secs(300);
    /// Sweep idle reply sockets / stale bind-failure entries every this
    /// many replies — the cap-only sweep would let a quiet gateway pin
    /// every FD it ever bound.
    const REPLY_SWEEP_INTERVAL: u32 = 256;
    /// Hard bound on the bind-failure backoff map — a spray of failing
    /// destinations must not grow it at inbound rate.
    const MAX_REPLY_BIND_FAILURES: usize = 256;

    /// Flow-table entry. `queued_bytes` is shared with the flow task so the
    /// byte cap survives across channel enqueues (decremented on dequeue).
    struct FlowEntry {
        tx: mpsc::Sender<Vec<u8>>,
        queued_bytes: Arc<AtomicUsize>,
    }

    /// The flow table and inbound dispatch, owned by `run_udp`'s loop so no
    /// locking is needed.
    struct FlowDispatch {
        flows: HashMap<(SocketAddr, SocketAddr), FlowEntry>,
        reply_tx: mpsc::Sender<ReplyMsg>,
        max_flows: usize,
        udp_timeout: Duration,
        in_name: String,
        in_port: u16,
        /// Shared `proxy:`/`rule:` override carried into every spawned
        /// flow's `FlowCtx`.
        route_override: Option<Arc<meow_common::InboundRouteOverride>>,
        sweep_countdown: u32,
        /// Last time a flow-cap drop was `warn!`-logged — rate-limited so a
        /// saturated `max-connections` is visible at default log levels
        /// without one warn per dropped datagram.
        cap_warned_at: Option<std::time::Instant>,
    }

    impl FlowDispatch {
        fn new(
            reply_tx: mpsc::Sender<ReplyMsg>,
            max_flows: usize,
            udp_timeout: Duration,
            in_name: String,
            in_port: u16,
            route_override: Option<Arc<meow_common::InboundRouteOverride>>,
        ) -> Self {
            Self {
                flows: HashMap::new(),
                reply_tx,
                max_flows,
                udp_timeout,
                in_name,
                in_port,
                route_override,
                sweep_countdown: SWEEP_INTERVAL,
                cap_warned_at: None,
            }
        }

        /// Route one inbound datagram to its flow, creating the flow if
        /// needed. Returns `false` when the datagram was dropped by a bound
        /// (flow cap, queue full) — the caller logs the drop decision.
        fn dispatch(
            &mut self,
            tunnel: &Tunnel,
            data: Vec<u8>,
            client: SocketAddr,
            orig_dst: SocketAddr,
        ) -> bool {
            let key = (client, orig_dst);

            self.sweep_countdown -= 1;
            if self.sweep_countdown == 0 {
                self.sweep_countdown = SWEEP_INTERVAL;
                self.flows.retain(|_, f| !f.tx.is_closed());
            }

            if let Some(entry) = self.flows.get(&key) {
                // A dead flow keeps its last byte count — check liveness
                // first or a saturated dead entry blackholes the tuple
                // until the periodic sweep.
                if entry.tx.is_closed() {
                    self.flows.remove(&key);
                    return self.dispatch_new(tunnel, data, key);
                }
                let len = data.len();
                // Both bounds are explicit: datagram count AND queued bytes.
                if entry.queued_bytes.load(Ordering::Relaxed) + len > FLOW_QUEUE_BYTES {
                    return false;
                }
                // Account BEFORE enqueue: the flow task can dequeue and
                // subtract before try_send returns, so adding after would
                // underflow the counter and permanently trip the cap.
                entry.queued_bytes.fetch_add(len, Ordering::Relaxed);
                match entry.tx.try_send(data) {
                    Ok(()) => return true,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        entry.queued_bytes.fetch_sub(len, Ordering::Relaxed);
                        return false;
                    }
                    // Flow task ended: evict and re-create below.
                    Err(mpsc::error::TrySendError::Closed(data)) => {
                        entry.queued_bytes.fetch_sub(len, Ordering::Relaxed);
                        self.flows.remove(&key);
                        return self.dispatch_new(tunnel, data, key);
                    }
                }
            }
            self.dispatch_new(tunnel, data, key)
        }

        fn dispatch_new(
            &mut self,
            tunnel: &Tunnel,
            data: Vec<u8>,
            key: (SocketAddr, SocketAddr),
        ) -> bool {
            // A destination inside the fake-IP range with no live
            // allocation would spawn a flow that immediately drops —
            // drop the datagram here instead of churning a spawn+evict
            // per packet under a stale flood (issue #618). The flow task
            // re-checks the verdict; the call is idempotent.
            let mut probe = Metadata {
                network: Network::Udp,
                dst_ip: Some(key.1.ip()),
                dst_port: key.1.port(),
                ..Default::default()
            };
            if matches!(
                tunnel.inner().pre_handle_metadata(&mut probe),
                meow_tunnel::PreHandleVerdict::Drop
            ) {
                debug!("tproxy udp: drop datagram to unmapped fake-ip {}", key.1);
                return false;
            }
            // `max_flows == 0` means explicitly unlimited (SS
            // `max-connections` precedent); a pending dial occupies its
            // budget too, so concurrent first packets of a new tuple always
            // fold into exactly one flow.
            if self.max_flows != 0 && self.flows.len() >= self.max_flows {
                // Reap dead flows first so a just-evicted tuple doesn't
                // keep charging against the cap until the periodic sweep.
                self.flows.retain(|_, f| !f.tx.is_closed());
                if self.flows.len() >= self.max_flows {
                    if self
                        .cap_warned_at
                        .is_none_or(|t| t.elapsed() > Duration::from_secs(60))
                    {
                        warn!(
                            "tproxy UDP '{}': flow cap {} reached — inbound \
                             datagrams are being dropped",
                            self.in_name, self.max_flows
                        );
                        self.cap_warned_at = Some(std::time::Instant::now());
                    }
                    return false;
                }
            }
            let (tx, rx) = mpsc::channel(FLOW_QUEUE);
            let queued_bytes = Arc::new(AtomicUsize::new(data.len()));
            tx.try_send(data).expect("fresh flow queue has capacity");
            self.flows.insert(
                key,
                FlowEntry {
                    tx,
                    queued_bytes: Arc::clone(&queued_bytes),
                },
            );
            let ctx = flow::FlowCtx {
                client: key.0,
                orig_dst: key.1,
                udp_timeout: self.udp_timeout,
                in_name: self.in_name.clone(),
                in_port: self.in_port,
                route_override: self.route_override.clone(),
            };
            spawn_flow(tunnel.clone(), rx, queued_bytes, self.reply_tx.clone(), ctx);
            true
        }
    }

    /// Spawn the per-flow task; kept separate so the recv loop stays tiny.
    /// Dropping the returned `JoinHandle` detaches the task — eviction is
    /// via the closed channel, not the handle, so no orphan can outlive a
    /// dead channel entry.
    fn spawn_flow(
        tunnel: Tunnel,
        rx: mpsc::Receiver<Vec<u8>>,
        queued_bytes: Arc<AtomicUsize>,
        reply_tx: mpsc::Sender<ReplyMsg>,
        ctx: flow::FlowCtx,
    ) {
        let client = ctx.client;
        let orig_dst = ctx.orig_dst;
        tokio::spawn(async move {
            if let Err(e) = flow::relay_udp_flow(tunnel, rx, queued_bytes, reply_tx, ctx).await {
                debug!("tproxy UDP {client} -> {orig_dst}: {e}");
            }
        });
    }

    /// Dispatch client-bound replies through the transparent-reply socket
    /// cache — one `IP_TRANSPARENT` socket per distinct original
    /// destination, shared across clients. Owned by this task.
    async fn reply_dispatch(mut rx: mpsc::Receiver<ReplyMsg>) {
        // (socket, last_used) — idle entries are evicted so a long-running
        // gateway doesn't pin one FD per historical destination forever.
        let mut sockets: HashMap<SocketAddr, (Arc<UdpSocket>, Instant)> = HashMap::new();
        let mut failed: HashMap<SocketAddr, Instant> = HashMap::new();
        let mut sweep_countdown = REPLY_SWEEP_INTERVAL;
        while let Some((data, orig_dst, client)) = rx.recv().await {
            // Periodic idle sweep — otherwise a gateway that never reaches
            // the socket cap would pin every FD it ever bound forever.
            sweep_countdown -= 1;
            if sweep_countdown == 0 {
                sweep_countdown = REPLY_SWEEP_INTERVAL;
                sockets.retain(|_, (_, t)| t.elapsed() < REPLY_SOCKET_IDLE);
                failed.retain(|_, t| t.elapsed() < REPLY_BIND_BACKOFF * 4);
            }
            let sock = match sockets.get_mut(&orig_dst) {
                Some(entry) => {
                    entry.1 = Instant::now();
                    Some(Arc::clone(&entry.0))
                }
                None => {
                    if failed
                        .get(&orig_dst)
                        .is_some_and(|t| t.elapsed() < REPLY_BIND_BACKOFF)
                    {
                        None
                    } else {
                        if sockets.len() >= MAX_REPLY_SOCKETS {
                            // Reclaim the idle-expired before dropping —
                            // destinations from an hour ago are almost
                            // certainly dead flows.
                            sockets.retain(|_, (_, t)| t.elapsed() < REPLY_SOCKET_IDLE);
                        }
                        if sockets.len() >= MAX_REPLY_SOCKETS {
                            warn!(
                                "tproxy UDP: reply socket cache full ({MAX_REPLY_SOCKETS}); \
                                 dropping reply to {client} from {orig_dst}"
                            );
                            None
                        } else {
                            match bind_reply_socket(orig_dst) {
                                Ok(s) => {
                                    let s = Arc::new(s);
                                    sockets.insert(orig_dst, (Arc::clone(&s), Instant::now()));
                                    failed.remove(&orig_dst);
                                    Some(s)
                                }
                                Err(e) => {
                                    warn!(
                                        "tproxy UDP: cannot bind transparent reply socket to \
                                         {orig_dst} (replies to {client} dropped): {e}"
                                    );
                                    // Keep the backoff map bounded — a
                                    // spray of failing destinations must
                                    // not grow it at inbound rate.
                                    if failed.len() < MAX_REPLY_BIND_FAILURES {
                                        failed.insert(orig_dst, Instant::now());
                                    }
                                    None
                                }
                            }
                        }
                    }
                }
            };
            if let Some(sock) = sock {
                if let Err(e) = sock.send_to(&data, client).await {
                    debug!("tproxy UDP reply {orig_dst} -> {client}: {e}");
                }
            }
        }
    }

    /// One bound ingress socket plus the address captured at preparation
    /// time. Carrying the latter avoids a per-packet `getsockname` and the
    /// old IPv4-wildcard fallback when it fails.
    pub(super) struct UdpIngress {
        socket: UdpSocket,
        local_addr: SocketAddr,
        /// Unit-test script used to prove multiplexer fairness without
        /// requiring a kernel TPROXY path; production constructors leave it unset.
        #[cfg(test)]
        scripted: Option<ScriptedRecv>,
    }

    /// The ingress sockets selected by the configured listen address. At
    /// most one socket exists per family; a `[::]` listener uses both.
    pub(in crate::tproxy) struct UdpIngresses {
        v4: Option<UdpIngress>,
        v6: Option<UdpIngress>,
    }

    /// Bind the UDP TPROXY listener socket(s): transparent mode makes each
    /// socket visible to the TPROXY lookup for packets the deployer steers
    /// via `--on-port` + fwmark/policy-routing, and `RECVORIGDSTADDR` asks
    /// for the original destination in ancillary data. `0.0.0.0` or a
    /// specific IPv4 address binds IPv4 only; a specific IPv6 address binds
    /// IPv6 only; `[::]` binds a V6ONLY IPv6 socket plus the IPv4 wildcard
    /// socket on the same port. Either socket creation failure drops the
    /// other one — a listener never publishes half of the dual-stack pair.
    ///
    /// Transparency requires `CAP_NET_ADMIN`/`CAP_NET_RAW` — a failure here
    /// is the explicit permission diagnostic the issue asks for.
    pub fn bind_transparent(addr: SocketAddr) -> io::Result<UdpIngresses> {
        // Validate before any branch rebuilds the address: `SocketAddr::new`
        // drops a v6 scope id, and the programmatic contract must reject it.
        validate_udp_socket_addr(addr)?;
        match addr.ip() {
            IpAddr::V4(ip) => Ok(UdpIngresses {
                v4: Some(bind_ingress(SocketAddr::new(IpAddr::V4(ip), addr.port()))?),
                v6: None,
            }),
            IpAddr::V6(ip) if ip.is_unspecified() => {
                let v6 = bind_ingress(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    addr.port(),
                ))?;
                // `prepare` normally passes the TCP socket's resolved port.
                // For a programmatic port-0 caller, keep the pair on the
                // port the first bind actually received instead of letting
                // the second socket pick an unrelated ephemeral port.
                let port = if addr.port() == 0 {
                    v6.local_addr.port()
                } else {
                    addr.port()
                };
                let v4 = bind_ingress(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))?;
                Ok(UdpIngresses {
                    v4: Some(v4),
                    v6: Some(v6),
                })
            }
            IpAddr::V6(ip) => Ok(UdpIngresses {
                v4: None,
                v6: Some(bind_ingress(SocketAddr::new(IpAddr::V6(ip), addr.port()))?),
            }),
        }
    }

    fn bind_ingress(addr: SocketAddr) -> io::Result<UdpIngress> {
        let std_sock = transparent_udp_socket(addr, true)?;
        let local_addr = std_sock.local_addr().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("getsockname UDP transparent listener {addr}: {e}"),
            )
        })?;
        let socket = UdpSocket::from_std(std_sock)?;
        Ok(UdpIngress {
            socket,
            local_addr,
            #[cfg(test)]
            scripted: None,
        })
    }

    /// Bind the client-facing reply socket to `orig_dst` so replies leave
    /// with the original destination as source address AND port.
    /// `SO_REUSEADDR` is deliberately absent — a genuine bind conflict
    /// (local service on that address:port) must surface as an error, not
    /// silently share the endpoint.
    pub fn bind_reply_socket(orig_dst: SocketAddr) -> io::Result<UdpSocket> {
        let std_sock = transparent_udp_socket(orig_dst, false)?;
        UdpSocket::from_std(std_sock)
    }

    fn invalid_udp_addr(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message.into())
    }

    /// The v1 UDP data plane accepts only native-family, unscoped,
    /// non-link-local IPv6 endpoints. Scope rejection must happen before a
    /// `SocketAddr` is flattened into `Metadata` (which has no zone field).
    fn validate_udp_socket_addr(addr: SocketAddr) -> io::Result<()> {
        let SocketAddr::V6(v6) = addr else {
            return Ok(());
        };
        let ip = v6.ip();
        if ip.to_ipv4_mapped().is_some() {
            return Err(invalid_udp_addr(format!(
                "IPv4-mapped IPv6 address {ip} is not valid for UDP TPROXY; use native IPv4"
            )));
        }
        if v6.scope_id() != 0 {
            return Err(invalid_udp_addr(format!(
                "scoped IPv6 address {v6} is not valid for UDP TPROXY v1"
            )));
        }
        if is_ipv6_link_local(ip) {
            return Err(invalid_udp_addr(format!(
                "link-local IPv6 address {ip} is not valid for UDP TPROXY v1"
            )));
        }
        Ok(())
    }

    fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
        ip.segments()[0] & 0xffc0 == 0xfe80
    }

    fn transparent_udp_socket(
        addr: SocketAddr,
        recv_orig_dst: bool,
    ) -> io::Result<std::net::UdpSocket> {
        validate_udp_socket_addr(addr)?;
        unsafe {
            let (domain, family) = match addr {
                SocketAddr::V4(_) => (libc::AF_INET, "ipv4"),
                SocketAddr::V6(_) => (libc::AF_INET6, "ipv6"),
            };
            let fd = libc::socket(
                domain,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // From here on the fd is owned by `sock` — early returns close it.
            let sock = std::net::UdpSocket::from_raw_fd(fd);

            let set_opt = |level, opt, opt_name: &'static str| {
                let one: libc::c_int = 1;
                if libc::setsockopt(
                    fd,
                    level,
                    opt,
                    &one as *const _ as *const libc::c_void,
                    mem::size_of_val(&one) as libc::socklen_t,
                ) == 0
                {
                    Ok(())
                } else {
                    let e = io::Error::last_os_error();
                    Err(io::Error::new(
                        e.kind(),
                        format!("setsockopt {family}/{opt_name}: {e}"),
                    ))
                }
            };

            let (level, transparent, recv_orig) = match addr {
                SocketAddr::V4(_) => (libc::SOL_IP, libc::IP_TRANSPARENT, libc::IP_RECVORIGDSTADDR),
                SocketAddr::V6(_) => {
                    // Never depend on net.ipv6.bindv6only: the v6 half of a
                    // dual-stack listener must leave IPv4 to its own socket.
                    set_opt(libc::SOL_IPV6, libc::IPV6_V6ONLY, "IPV6_V6ONLY")?;
                    (
                        libc::SOL_IPV6,
                        libc::IPV6_TRANSPARENT,
                        libc::IPV6_RECVORIGDSTADDR,
                    )
                }
            };
            set_opt(
                level,
                transparent,
                if addr.is_ipv4() {
                    "IP_TRANSPARENT"
                } else {
                    "IPV6_TRANSPARENT"
                },
            )?;
            if recv_orig_dst {
                set_opt(
                    level,
                    recv_orig,
                    if addr.is_ipv4() {
                        "IP_RECVORIGDSTADDR"
                    } else {
                        "IPV6_RECVORIGDSTADDR"
                    },
                )?;
            }

            let bind_result = match addr {
                SocketAddr::V4(v4) => {
                    let sa = libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: addr.port().to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(v4.ip().octets()),
                        },
                        sin_zero: [0; 8],
                    };
                    libc::bind(
                        fd,
                        &sa as *const _ as *const libc::sockaddr,
                        mem::size_of_val(&sa) as libc::socklen_t,
                    )
                }
                SocketAddr::V6(v6) => {
                    let sa = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: addr.port().to_be(),
                        sin6_flowinfo: 0,
                        sin6_addr: libc::in6_addr {
                            s6_addr: v6.ip().octets(),
                        },
                        // Zero today by the validation above; propagate the
                        // field rather than baking that assumption into the
                        // sockaddr construction.
                        sin6_scope_id: v6.scope_id(),
                    };
                    libc::bind(
                        fd,
                        &sa as *const _ as *const libc::sockaddr,
                        mem::size_of_val(&sa) as libc::socklen_t,
                    )
                }
            };
            if bind_result != 0 {
                let e = io::Error::last_os_error();
                return Err(io::Error::new(
                    e.kind(),
                    format!("bind UDP transparent {family} socket {addr}: {e}"),
                ));
            }
            Ok(sock)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RecvDrop {
        Truncated,
        BadSource,
        MissingOrigDst,
        /// An IPv4-mapped address appeared on the IPv6 ingress. That shape
        /// must never become a flow key: the dual-socket design keys only
        /// native-family endpoints.
        MappedV6,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RecvOutcome {
        Datagram {
            len: usize,
            client: SocketAddr,
            orig_dst: SocketAddr,
        },
        Drop(RecvDrop),
    }

    /// Receive one datagram plus its original destination. Returns a drop
    /// outcome for truncation, missing/malformed ancillary data, or an
    /// unusable source — never fall back to treating the listener address
    /// as the destination.
    async fn recv_dgram(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        let fd = socket.as_raw_fd();
        loop {
            // Unlike `readable()`, `poll_recv_ready` participates in tokio's
            // task coop budget, so a continuously-ready datagram flood cannot
            // pin a runtime worker inside one task poll.
            std::future::poll_fn(|cx| socket.poll_recv_ready(cx)).await?;
            match socket.try_io(Interest::READABLE, || unsafe {
                recvmsg_with_orig_dst(fd, buf)
            }) {
                Ok(r) => return Ok(r),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// `cmsg_len`/`msg_controllen` are `usize` under glibc and `u32` under
    /// musl. Routing the conversion through a generic helper keeps both ABI
    /// widths compiling without a same-type `as usize` cast (see 25962cb1).
    fn ffi_usize<T: TryInto<usize>>(value: T) -> Option<usize> {
        value.try_into().ok()
    }

    /// Raw `recvmsg` on `fd`: payload into `buf`, source address from
    /// `msg_name`, original destination from either the v4 or v6
    /// `ORIGDSTADDR` cmsg. Every shape check the issue calls out is
    /// enforced here — malformed metadata means "drop the datagram", never
    /// "guess".
    unsafe fn recvmsg_with_orig_dst(fd: RawFd, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        let mut name: libc::sockaddr_storage = mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buf.len(),
        };
        // 64 bytes holds one v6 ORIGDSTADDR cmsg (48 bytes on a 64-bit
        // ABI, 40 on 32-bit) with room for the small leading unknown-cmsg
        // cases the parser tests exercise. The parser reads integer fields
        // byte-wise, but aligned storage also keeps the header itself at
        // the kernel's natural alignment.
        let mut cbuf = [0u64; 8];
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_name = (&mut name as *mut libc::sockaddr_storage).cast::<libc::c_void>();
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = mem::size_of_val(&cbuf) as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // A truncated payload is unusable — the tail bytes are lost — and a
        // truncated cmsg could parse a wrong orig_dst; drop both.
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Ok(RecvOutcome::Drop(RecvDrop::Truncated));
        }

        let client = match sockaddr_to_addr(&name, msg.msg_namelen) {
            Ok(client) => client,
            Err(EndpointReject::MappedV6) => {
                return Ok(RecvOutcome::Drop(RecvDrop::MappedV6));
            }
            Err(_) => return Ok(RecvOutcome::Drop(RecvDrop::BadSource)),
        };
        // Byte view over the control buffer — no copy.
        let cbuf_bytes =
            std::slice::from_raw_parts(cbuf.as_ptr().cast::<u8>(), mem::size_of_val(&cbuf));
        let controllen = ffi_usize(msg.msg_controllen).unwrap_or(0);
        match scan_orig_dst(cbuf_bytes, controllen) {
            OrigDstScan::Found(orig_dst) => Ok(RecvOutcome::Datagram {
                len: n as usize,
                client,
                orig_dst,
            }),
            OrigDstScan::Rejected(EndpointReject::MappedV6) => {
                Ok(RecvOutcome::Drop(RecvDrop::MappedV6))
            }
            OrigDstScan::Missing | OrigDstScan::Rejected(_) => {
                Ok(RecvOutcome::Drop(RecvDrop::MissingOrigDst))
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum EndpointReject {
        Truncated,
        UnsupportedFamily,
        WrongFamily,
        MappedV6,
        ScopedV6,
        LinkLocalV6,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OrigDstScan {
        Missing,
        Found(SocketAddr),
        Rejected(EndpointReject),
    }

    /// Kernel/ABI control-message alignment: `sizeof(long)` on the target
    /// Linux ABI (the same rule backing libc's private `CMSG_ALIGN`).
    fn cmsg_align(len: usize) -> Option<usize> {
        let mask = mem::size_of::<usize>() - 1;
        len.checked_add(mask).map(|v| v & !mask)
    }

    /// Scan a control buffer for either original-destination cmsg:
    /// `(SOL_IP, IP_ORIGDSTADDR)` carrying `sockaddr_in`, or `(SOL_IPV6,
    /// IPV6_ORIGDSTADDR)` carrying `sockaddr_in6`. `controllen` is the
    /// kernel-reported byte count; every payload-length check is against
    /// the bytes remaining after the current header offset, never against
    /// the whole buffer.
    fn scan_orig_dst(cbuf: &[u8], controllen: usize) -> OrigDstScan {
        let controllen = controllen.min(cbuf.len());
        let hdr_size = mem::size_of::<libc::cmsghdr>();
        let mut offset = 0usize;
        while offset + hdr_size <= controllen {
            // `read_unaligned` keeps synthetic test buffers safe too; the
            // production cbuf is naturally aligned. `cmsghdr` is plain
            // integer fields with no padding on the supported Linux ABIs.
            let hdr = unsafe {
                std::ptr::read_unaligned(cbuf.as_ptr().add(offset).cast::<libc::cmsghdr>())
            };
            let Some(cmsg_len) = ffi_usize(hdr.cmsg_len) else {
                return OrigDstScan::Rejected(EndpointReject::Truncated);
            };
            if cmsg_len < hdr_size {
                return OrigDstScan::Rejected(EndpointReject::Truncated);
            }
            let data_len = cmsg_len - hdr_size;
            let data_start = offset + hdr_size;
            let Some(data_end) = data_start.checked_add(data_len) else {
                return OrigDstScan::Rejected(EndpointReject::Truncated);
            };
            if data_end > controllen {
                return OrigDstScan::Rejected(EndpointReject::Truncated);
            }
            let payload = &cbuf[data_start..data_end];
            if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == libc::IP_ORIGDSTADDR {
                return match decode_sockaddr_in(payload) {
                    Ok(addr) => OrigDstScan::Found(addr),
                    Err(reject) => OrigDstScan::Rejected(reject),
                };
            }
            if hdr.cmsg_level == libc::SOL_IPV6 && hdr.cmsg_type == libc::IPV6_ORIGDSTADDR {
                return match decode_sockaddr_in6(payload) {
                    Ok(addr) => OrigDstScan::Found(addr),
                    Err(reject) => OrigDstScan::Rejected(reject),
                };
            }

            let Some(step) = cmsg_align(cmsg_len) else {
                return OrigDstScan::Rejected(EndpointReject::Truncated);
            };
            let Some(next) = offset.checked_add(step) else {
                return OrigDstScan::Rejected(EndpointReject::Truncated);
            };
            if next <= offset {
                return OrigDstScan::Rejected(EndpointReject::Truncated);
            }
            offset = next;
        }
        OrigDstScan::Missing
    }

    /// Decode the fixed Linux `sockaddr_in` wire layout byte-wise. Ports
    /// are network-endian; the family field is host-endian.
    fn decode_sockaddr_in(bytes: &[u8]) -> Result<SocketAddr, EndpointReject> {
        if bytes.len() < mem::size_of::<libc::sockaddr_in>() {
            return Err(EndpointReject::Truncated);
        }
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family as i32 != libc::AF_INET {
            return Err(EndpointReject::WrongFamily);
        }
        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    }

    /// Decode the fixed Linux `sockaddr_in6` layout: family at 0..2, port
    /// at 2..4, flowinfo at 4..8 (not part of flow identity), address at
    /// 8..24, scope at 24..28. A scope zone cannot survive into `Metadata`,
    /// so a nonzero zone and link-local addressing are rejects rather than
    /// data silently dropped by the conversion.
    fn decode_sockaddr_in6(bytes: &[u8]) -> Result<SocketAddr, EndpointReject> {
        if bytes.len() < mem::size_of::<libc::sockaddr_in6>() {
            return Err(EndpointReject::Truncated);
        }
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family as i32 != libc::AF_INET6 {
            return Err(EndpointReject::WrongFamily);
        }
        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes[8..24]);
        let ip = Ipv6Addr::from(octets);
        if ip.to_ipv4_mapped().is_some() {
            return Err(EndpointReject::MappedV6);
        }
        if bytes[24..28].iter().any(|b| *b != 0) {
            return Err(EndpointReject::ScopedV6);
        }
        if is_ipv6_link_local(&ip) {
            return Err(EndpointReject::LinkLocalV6);
        }
        Ok(SocketAddr::new(IpAddr::V6(ip), port))
    }

    /// Decode `msg_name` as either socket family. Only the first `namelen`
    /// bytes are read; short or foreign-family names are rejects.
    fn sockaddr_to_addr(
        name: &libc::sockaddr_storage,
        namelen: libc::socklen_t,
    ) -> Result<SocketAddr, EndpointReject> {
        let namelen = (namelen as usize).min(mem::size_of::<libc::sockaddr_storage>());
        if namelen < mem::size_of::<libc::sa_family_t>() {
            return Err(EndpointReject::Truncated);
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (name as *const libc::sockaddr_storage).cast::<u8>(),
                namelen,
            )
        };
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family as i32 == libc::AF_INET {
            decode_sockaddr_in(bytes)
        } else if family as i32 == libc::AF_INET6 {
            decode_sockaddr_in6(bytes)
        } else {
            Err(EndpointReject::UnsupportedFamily)
        }
    }

    use super::super::is_safe_orig_dst;

    /// Binds a spawned task's lifetime to a scope: when the owning task's
    /// frame is dropped (abort/cancellation — `run_udp` itself never
    /// returns), the guard aborts the reply dispatcher, which otherwise
    /// lingered until every flow channel closed, up to `udp_timeout`
    /// (issue #621).
    struct AbortOnDrop(tokio::task::AbortHandle);

    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// Per-ingress retry state. Unlike `ErrorBackoff`, the delay is an
    /// absolute deadline recorded before the select loop continues: a
    /// sleep branch cancelled by the sibling socket must not discard the
    /// penalty or leave the delay ungrown.
    struct IngressBackoff {
        delay: Duration,
        retry_at: Option<Instant>,
    }

    impl IngressBackoff {
        fn new() -> Self {
            Self {
                delay: RECV_BACKOFF_INITIAL,
                retry_at: None,
            }
        }

        fn waiting_until(&self, now: Instant) -> Option<Instant> {
            self.retry_at.filter(|deadline| *deadline > now)
        }

        /// Record one failure. Returns `true` for socket-level failures,
        /// matching `ErrorBackoff`'s loud-log contract; per-datagram ICMP/
        /// queue-progress errors neither sleep nor grow the delay.
        fn failed(&mut self, err: &io::Error, now: Instant) -> bool {
            if is_per_datagram_error(err) {
                return false;
            }
            self.retry_at = Some(now + self.delay);
            self.delay = (self.delay * 2).min(RECV_BACKOFF_MAX);
            true
        }

        fn succeeded(&mut self) {
            self.delay = RECV_BACKOFF_INITIAL;
            self.retry_at = None;
        }
    }

    /// Linux `recvmsg` errors that consumed a datagram or report a pending
    /// per-peer error. They are progress, not socket failure — the same
    /// classification `ErrorBackoff` documents, reproduced here because the
    /// multiplexer cannot use that helper's internally-sleeping API.
    fn is_per_datagram_error(e: &io::Error) -> bool {
        match e.kind() {
            io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::Interrupted
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown => true,
            _ => matches!(
                e.raw_os_error(),
                Some(
                    libc::EPROTO
                        | libc::ENOPROTOOPT
                        | libc::EHOSTDOWN
                        | libc::EOPNOTSUPP
                        | libc::ENONET
                )
            ),
        }
    }

    struct IngressState {
        socket: UdpSocket,
        local_addr: SocketAddr,
        buf: Vec<u8>,
        backoff: IngressBackoff,
        mapped_v6_drops: u64,
        #[cfg(test)]
        scripted: Option<ScriptedRecv>,
    }

    #[cfg(test)]
    enum ScriptedRecv {
        Queue(std::collections::VecDeque<RecvOutcome>),
        Repeat(RecvOutcome),
    }

    impl IngressState {
        fn new(ingress: UdpIngress) -> Self {
            Self {
                socket: ingress.socket,
                local_addr: ingress.local_addr,
                buf: vec![0u8; DATAGRAM_BUF],
                backoff: IngressBackoff::new(),
                mapped_v6_drops: 0,
                #[cfg(test)]
                scripted: ingress.scripted,
            }
        }

        async fn recv_one(&mut self) -> io::Result<RecvOutcome> {
            #[cfg(test)]
            if let Some(scripted) = &mut self.scripted {
                return match scripted {
                    ScriptedRecv::Queue(queue) => match queue.pop_front() {
                        Some(outcome) => Ok(outcome),
                        None => std::future::pending().await,
                    },
                    ScriptedRecv::Repeat(outcome) => Ok(*outcome),
                };
            }
            recv_dgram(&self.socket, &mut self.buf).await
        }
    }

    /// A datagram is valid only when its source and original destination
    /// are both in the ingress socket's family. This rejects a foreign or
    /// normalized-mapped endpoint before it can enter the native-family
    /// flow key space.
    fn ingress_family_consistent(
        ingress_is_v4: bool,
        client: SocketAddr,
        orig_dst: SocketAddr,
    ) -> bool {
        client.is_ipv4() == ingress_is_v4
            && orig_dst.is_ipv4() == ingress_is_v4
            && client.is_ipv4() == orig_dst.is_ipv4()
    }

    /// A repeated scripted ingress has no real readiness object, so charge
    /// the same coop budget a real socket would have spent in `recv_dgram`.
    /// Charging only when the outer receive branch completes keeps the flood
    /// test discriminating: an implementation that retries filtered drops in
    /// its inner loop never reaches this point.
    #[cfg(test)]
    async fn scripted_repeat_progress(is_repeat: bool) {
        if !is_repeat {
            return;
        }
        std::future::poll_fn(|cx| {
            let coop = std::task::ready!(tokio::task::coop::poll_proceed(cx));
            coop.made_progress();
            std::task::Poll::Ready(())
        })
        .await;
    }

    /// Receive and validate at most one datagram from one ingress. Even a
    /// filtered datagram completes the selectable branch (`None`), so a
    /// malformed-packet flood cannot keep this future permanently ready and
    /// starve the sibling family; the outer loop may immediately poll this
    /// ingress again after giving the sibling its chance. Error `None` has
    /// already been classified by the socket-error backoff helper; ordinary
    /// filter drops never touch that backoff.
    async fn recv_ingress(
        state: Option<&mut IngressState>,
        in_name: &str,
        local_addrs: Option<&HashSet<IpAddr>>,
    ) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        let state = state.expect("recv branch polled while disabled");
        let local_addr = state.local_addr;
        let ingress_is_v4 = local_addr.is_ipv4();
        let family = if ingress_is_v4 { "ipv4" } else { "ipv6" };

        let result = match state.recv_one().await {
            Err(e) => {
                if state.backoff.failed(&e, Instant::now()) {
                    warn!("tproxy UDP '{in_name}' {family} recv error: {e}");
                } else {
                    debug!("tproxy UDP '{in_name}' {family} recv error: {e}");
                }
                None
            }
            Ok(RecvOutcome::Drop(reason)) => {
                match reason {
                    RecvDrop::Truncated => debug!(
                        "tproxy UDP '{in_name}' {family}: dropping truncated datagram"
                    ),
                    RecvDrop::BadSource => debug!(
                        "tproxy UDP '{in_name}' {family}: dropping datagram with invalid source addr"
                    ),
                    RecvDrop::MissingOrigDst => debug!(
                        "tproxy UDP '{in_name}' {family}: dropping datagram without usable ORIGDSTADDR cmsg"
                    ),
                    RecvDrop::MappedV6 => {
                        state.mapped_v6_drops += 1;
                        let total = state.mapped_v6_drops;
                        debug!(
                            "tproxy UDP '{in_name}' {family}: dropping IPv4-mapped endpoint \
                             (total {total}); dual-socket flow keys are native-family"
                        );
                    }
                }
                None
            }
            Ok(RecvOutcome::Datagram {
                len,
                client,
                orig_dst,
            }) => {
                state.backoff.succeeded();
                if !ingress_family_consistent(ingress_is_v4, client, orig_dst) {
                    debug!(
                        "tproxy UDP '{in_name}' {family}: dropping family-inconsistent \
                         datagram {client} -> {orig_dst}"
                    );
                    None
                } else if !is_safe_orig_dst(orig_dst, local_addr, local_addrs) {
                    // Sanity-guard the recovered destination before it ever
                    // reaches a flow — see `is_safe_orig_dst`.
                    debug!(
                        "tproxy UDP '{in_name}' {family}: dropping datagram to unsafe orig_dst {orig_dst}"
                    );
                    None
                } else {
                    // Zero-length datagrams are legal UDP — copied and forwarded
                    // like any other.
                    Some((state.buf[..len].to_vec(), client, orig_dst))
                }
            }
        };
        #[cfg(test)]
        scripted_repeat_progress(matches!(state.scripted, Some(ScriptedRecv::Repeat(_)))).await;
        result
    }

    async fn wait_retry(deadline: Instant) {
        tokio::time::sleep_until(deadline).await;
    }

    fn dispatch_received(
        tunnel: &Tunnel,
        dispatch: &mut FlowDispatch,
        received: Option<(Vec<u8>, SocketAddr, SocketAddr)>,
    ) {
        if let Some((data, client, orig_dst)) = received {
            if !dispatch.dispatch(tunnel, data, client, orig_dst) {
                debug!("tproxy UDP: dropped {client} -> {orig_dst} (flow/queue bound)");
            }
        }
    }

    /// Single-family listeners keep the pre-dual-stack receive shape: no
    /// select branches or sibling backoff bookkeeping in the hot loop. The
    /// receive/validate/dispatch steps are the same helpers the dual-path
    /// uses, so filtering semantics cannot drift apart.
    async fn run_single_ingress(
        tunnel: &Tunnel,
        state: &mut IngressState,
        dispatch: &mut FlowDispatch,
        in_name: &str,
        local_addrs: Option<&HashSet<IpAddr>>,
    ) {
        loop {
            // `retry_at` is empty on the hot path; only a socket-error backoff
            // pays for the clock read.
            if let Some(deadline) = state
                .backoff
                .retry_at
                .filter(|deadline| *deadline > Instant::now())
            {
                wait_retry(deadline).await;
                continue;
            }
            let received = recv_ingress(Some(&mut *state), in_name, local_addrs).await;
            dispatch_received(tunnel, dispatch, received);
        }
    }

    /// The UDP receive multiplexer: one or two ingress sockets → one flow
    /// table and one reply dispatcher. Runs until the task is aborted.
    /// Socket errors retry with per-ingress exponential backoff rather than
    /// terminate; a degraded IPv6 ingress cannot stop IPv4 receives, and a
    /// persistent failure still surfaces via the backoff-rate-limited
    /// `warn!`. Idle-flow eviction is lazy (channel-close observed on the
    /// next datagram, or the periodic sweep).
    ///
    /// `local_addrs` is the listener's interface-address snapshot — the
    /// self-target half of `is_safe_orig_dst`; `None` keeps the
    /// conservative same-port rule.
    #[allow(
        clippy::too_many_arguments,
        reason = "the listener's UDP knobs, passed once at task spawn"
    )]
    pub async fn run_udp(
        tunnel: Tunnel,
        ingresses: UdpIngresses,
        udp_timeout: Duration,
        max_flows: usize,
        in_name: String,
        in_port: u16,
        local_addrs: Option<Arc<HashSet<IpAddr>>>,
        route_override: Option<meow_common::InboundRouteOverride>,
    ) {
        let (reply_tx, reply_rx) = mpsc::channel::<ReplyMsg>(REPLY_QUEUE);
        let _dispatcher = AbortOnDrop(tokio::spawn(reply_dispatch(reply_rx)).abort_handle());

        let mut dispatch = FlowDispatch::new(
            reply_tx,
            max_flows,
            udp_timeout,
            in_name.clone(),
            in_port,
            route_override.map(Arc::new),
        );
        let mut v4 = ingresses.v4.map(IngressState::new);
        let mut v6 = ingresses.v6.map(IngressState::new);
        if v4.is_none() && v6.is_none() {
            warn!("tproxy UDP '{in_name}': no ingress sockets; UDP dataplane disabled");
            return;
        }
        let local_addrs = local_addrs.as_deref();

        if v4.is_some() != v6.is_some() {
            let ((Some(state), None) | (None, Some(state))) = (v4.as_mut(), v6.as_mut()) else {
                unreachable!("exactly one ingress checked above");
            };
            run_single_ingress(&tunnel, state, &mut dispatch, &in_name, local_addrs).await;
            return;
        }

        loop {
            let now = Instant::now();
            let v4_wait = v4
                .as_ref()
                .and_then(|state| state.backoff.waiting_until(now));
            let v6_wait = v6
                .as_ref()
                .and_then(|state| state.backoff.waiting_until(now));
            let v4_active = v4.is_some() && v4_wait.is_none();
            let v6_active = v6.is_some() && v6_wait.is_none();

            tokio::select! {
                received = recv_ingress(v4.as_mut(), &in_name, local_addrs), if v4_active => {
                    dispatch_received(&tunnel, &mut dispatch, received);
                }
                received = recv_ingress(v6.as_mut(), &in_name, local_addrs), if v6_active => {
                    dispatch_received(&tunnel, &mut dispatch, received);
                }
                // The deadline is already persisted in `IngressState`; when
                // a sibling datagram cancels this sleep nothing is lost.
                () = wait_retry(v4_wait.unwrap_or(now)), if v4_wait.is_some() => {}
                () = wait_retry(v6_wait.unwrap_or(now)), if v6_wait.is_some() => {}
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::tproxy::udp::tests::{mk_tunnel, RecordingProxy, CLIENT, ORIG_DST};

        fn dispatch_with(max_flows: usize) -> (FlowDispatch, mpsc::Receiver<ReplyMsg>) {
            let (reply_tx, reply_rx) = mpsc::channel(8);
            (
                FlowDispatch::new(
                    reply_tx,
                    max_flows,
                    Duration::from_secs(60),
                    "t".into(),
                    7894,
                    None,
                ),
                reply_rx,
            )
        }

        fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
            SocketAddr::from(([a, b, c, d], port))
        }

        fn dummy_udp_socket() -> UdpSocket {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            UdpSocket::from_std(socket).unwrap()
        }

        /// A scripted ingress never reads its dummy socket; it exists only so
        /// the production multiplexer can be exercised without a kernel
        /// TPROXY path or capabilities.
        fn scripted_ingress(local_addr: SocketAddr, outcomes: Vec<RecvOutcome>) -> UdpIngress {
            UdpIngress {
                socket: dummy_udp_socket(),
                local_addr,
                scripted: Some(ScriptedRecv::Queue(outcomes.into_iter().collect())),
            }
        }

        fn repeating_drop_ingress(local_addr: SocketAddr, drop: RecvDrop) -> UdpIngress {
            UdpIngress {
                socket: dummy_udp_socket(),
                local_addr,
                scripted: Some(ScriptedRecv::Repeat(RecvOutcome::Drop(drop))),
            }
        }

        /// A programmatic scoped v6 bind must be rejected before any branch
        /// rebuilds the address and loses `scope_id` — no capabilities are
        /// needed because validation precedes socket creation.
        #[test]
        fn bind_transparent_rejects_scoped_v6_before_reconstruction() {
            let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
            let addr = SocketAddr::V6(std::net::SocketAddrV6::new(ip, 7893, 0, 7));
            let Err(err) = bind_transparent(addr) else {
                panic!("scoped v6 bind must be rejected");
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("scoped IPv6"), "got: {err}");
        }

        /// The selectable receive future consumes at most one ingress packet
        /// per outer poll, even when that packet is filtered.
        #[tokio::test]
        async fn recv_ingress_returns_after_one_filtered_datagram() {
            let local = v4(0, 0, 0, 0, 7893);
            let ingress = scripted_ingress(
                local,
                vec![
                    RecvOutcome::Drop(RecvDrop::MissingOrigDst),
                    RecvOutcome::Drop(RecvDrop::MissingOrigDst),
                ],
            );
            let mut state = IngressState::new(ingress);
            let received = tokio::time::timeout(
                Duration::from_millis(100),
                recv_ingress(Some(&mut state), "t", None),
            )
            .await
            .expect("filtered datagram did not complete the receive branch");
            assert!(received.is_none());
            let ScriptedRecv::Queue(queue) = state.scripted.as_ref().unwrap() else {
                panic!("test ingress uses a queue");
            };
            assert_eq!(
                queue.len(),
                1,
                "the second queued drop belongs to the next outer poll"
            );
            assert!(
                state.backoff.waiting_until(Instant::now()).is_none(),
                "ordinary filter drops must not become socket-error backoff"
            );
        }

        /// Draining a continuously-ready production receive path must spend
        /// tokio's finite task budget before the finite kernel backlog is gone.
        ///
        /// The arithmetic is deliberately relative to a measured backlog. A
        /// 1-byte loopback datagram costs roughly a kilobyte of skb truesize,
        /// so the common 212992-byte `rmem_max` admits only about 369 packets
        /// even when a larger buffer is requested. Correct coop behaviour is
        /// one 128-poll budget window, or two in the least favourable task
        /// spawn order (~256). Requiring 320 initial packets therefore leaves
        /// at least 32 packets of regression margin; a non-cooperative drain
        /// observes essentially the entire measured backlog before the probe.
        #[test]
        fn production_udp_receive_spends_coop_budget() {
            const MIN_INITIAL_BACKLOG: usize = 320;
            const REGRESSION_MARGIN: usize = 32;
            const MIN_PROBE_PROGRESS: usize = 100;

            let receiver = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap();
            receiver.set_recv_buffer_size(4 * 1024 * 1024).unwrap();
            receiver
                .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
                .unwrap();
            receiver.set_nonblocking(true).unwrap();
            let addr = receiver.local_addr().unwrap().as_socket().unwrap();
            let receiver: std::net::UdpSocket = receiver.into();
            let receiver_clone = receiver.try_clone().unwrap();
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.set_nonblocking(true).unwrap();
            for _ in 0..2048 {
                let _ = sender.send_to(&[0], addr);
            }

            // Send success is not enqueue evidence. Wait until at least one
            // datagram is visibly queued; the exact initial backlog is still
            // measured below rather than inferred from send or peek success.
            let mut peeked = false;
            let peek_deadline = std::time::Instant::now() + Duration::from_millis(500);
            while std::time::Instant::now() < peek_deadline {
                if receiver_clone.peek(&mut [0]).is_ok() {
                    peeked = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(peeked, "no prefilled datagram entered the UDP queue");

            let probe_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let probe_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let thread = std::thread::spawn({
                let probe_done = Arc::clone(&probe_done);
                let probe_count = Arc::clone(&probe_count);
                let count = Arc::clone(&count);
                let stop = Arc::clone(&stop);
                move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    rt.block_on(async move {
                        let socket = UdpSocket::from_std(receiver).unwrap();
                        let hog_count = Arc::clone(&count);
                        tokio::spawn(async move {
                            let mut buf = vec![0; 64];
                            while !stop.load(Ordering::Relaxed) {
                                if recv_dgram(&socket, &mut buf).await.is_ok() {
                                    hog_count.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        });
                        let probe_source = Arc::clone(&count);
                        tokio::spawn(async move {
                            tokio::task::yield_now().await;
                            probe_count
                                .store(probe_source.load(Ordering::SeqCst), Ordering::SeqCst);
                            probe_done.store(true, Ordering::SeqCst);
                        });
                        let _ = shutdown_rx.await;
                    });
                }
            });

            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(2) && !probe_done.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(2));
            }
            let ran = probe_done.load(Ordering::SeqCst);
            let probe_observed = probe_count.load(Ordering::SeqCst);
            stop.store(true, Ordering::SeqCst);
            let _ = shutdown_tx.send(());
            thread.join().unwrap();

            // No sender remains active. Everything not consumed by the hog is
            // still in the cloned receive queue, so consumed + remaining is
            // the real initial backlog rather than an optimistic send count.
            let hog_total = count.load(Ordering::SeqCst);
            let mut remaining = 0usize;
            let mut empty_polls = 0usize;
            let mut drain_buf = [0u8; 64];
            loop {
                match receiver_clone.recv_from(&mut drain_buf) {
                    Ok(_) => {
                        remaining += 1;
                        empty_polls = 0;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        empty_polls += 1;
                        if empty_polls == 20 {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("drain cloned receiver: {e}"),
                }
            }
            let initial = hog_total + remaining;
            assert!(
                initial >= MIN_INITIAL_BACKLOG,
                "environment provided initial UDP backlog {initial} \
                 (hog {hog_total}, remaining {remaining}); need at least \
                 {MIN_INITIAL_BACKLOG} for coop regression margins"
            );
            assert!(ran, "production receive path did not yield");
            assert!(
                probe_observed >= MIN_PROBE_PROGRESS,
                "probe ran before meaningful production drain progress ({probe_observed})"
            );
            assert!(
                probe_observed + REGRESSION_MARGIN < initial,
                "probe observed {probe_observed} of {initial} drained datagrams; \
                 non-cooperative drain leaves less than {REGRESSION_MARGIN} packets of margin"
            );
        }

        /// A one-family listener takes the direct receive loop and still
        /// reaches the ordinary flow dispatcher.
        #[tokio::test]
        async fn single_ingress_fast_path_dispatches_valid_datagram() {
            let proxy = RecordingProxy::new(false);
            let tunnel = mk_tunnel(Some(Arc::clone(&proxy)));
            let ingresses = UdpIngresses {
                v4: Some(scripted_ingress(
                    v4(0, 0, 0, 0, 7893),
                    vec![RecvOutcome::Datagram {
                        len: 4,
                        client: CLIENT,
                        orig_dst: ORIG_DST,
                    }],
                )),
                v6: None,
            };
            let task = tokio::spawn(run_udp(
                tunnel,
                ingresses,
                Duration::from_secs(60),
                0,
                "t".into(),
                7893,
                None,
                None,
            ));
            tokio::time::timeout(Duration::from_secs(2), async {
                while proxy.dial_count() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("single ingress did not dispatch its valid datagram");
            task.abort();
        }

        /// With one ingress producing an unbroken filtered-datagram stream,
        /// the sibling's valid datagram still reaches the ordinary flow path.
        #[tokio::test]
        async fn sibling_valid_datagram_progresses_during_drop_flood() {
            let proxy = RecordingProxy::new(false);
            let tunnel = mk_tunnel(Some(Arc::clone(&proxy)));
            let client6 = v6(0x2001, 0xdb8, 0, 7, 41234);
            let dst6 = v6(0x2001, 0xdb8, 0, 53, 53);
            let ingresses = UdpIngresses {
                v4: Some(repeating_drop_ingress(
                    v4(0, 0, 0, 0, 7893),
                    RecvDrop::MissingOrigDst,
                )),
                v6: Some(scripted_ingress(
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 7893),
                    vec![RecvOutcome::Datagram {
                        len: 4,
                        client: client6,
                        orig_dst: dst6,
                    }],
                )),
            };
            let task = tokio::spawn(run_udp(
                tunnel,
                ingresses,
                Duration::from_secs(60),
                0,
                "t".into(),
                7893,
                None,
                None,
            ));
            tokio::time::timeout(Duration::from_secs(2), async {
                while proxy.dial_count() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("valid sibling datagram starved behind filtered flood");
            task.abort();
        }

        /// The flow key is `(client, orig_dst)` — the same client port
        /// talking to two different original destinations must never share
        /// a flow (issue #564 §3: reply identities would cross).
        #[tokio::test]
        async fn distinct_orig_dst_gets_distinct_flows() {
            let tunnel = mk_tunnel(Some(RecordingProxy::new(false)));
            let (mut d, _rx) = dispatch_with(0);
            let other_dst = v4(203, 0, 113, 5, 53);
            assert!(d.dispatch(&tunnel, b"a".to_vec(), CLIENT, ORIG_DST));
            assert!(d.dispatch(&tunnel, b"b".to_vec(), CLIENT, other_dst));
            assert_eq!(d.flows.len(), 2);
        }

        /// Concurrent first packets of one tuple fold into exactly one
        /// flow — the second datagram lands on the existing queue.
        #[tokio::test]
        async fn same_tuple_folds_into_one_flow() {
            let tunnel = mk_tunnel(Some(RecordingProxy::new(false)));
            let (mut d, _rx) = dispatch_with(0);
            assert!(d.dispatch(&tunnel, b"a".to_vec(), CLIENT, ORIG_DST));
            assert!(d.dispatch(&tunnel, b"b".to_vec(), CLIENT, ORIG_DST));
            assert_eq!(d.flows.len(), 1);
        }

        /// `max_flows` bounds live+pending flows; `0` is unlimited.
        #[tokio::test]
        async fn max_flows_cap_bounds_new_tuples() {
            let tunnel = mk_tunnel(Some(RecordingProxy::new(false)));
            let (mut d, _rx) = dispatch_with(1);
            assert!(d.dispatch(&tunnel, b"a".to_vec(), CLIENT, ORIG_DST));
            assert!(
                !d.dispatch(&tunnel, b"b".to_vec(), v4(192, 0, 2, 8, 1000), ORIG_DST),
                "a second tuple past max_flows must be dropped"
            );
            // The existing flow still accepts its own datagrams.
            assert!(d.dispatch(&tunnel, b"c".to_vec(), CLIENT, ORIG_DST));
            assert_eq!(d.flows.len(), 1);
        }

        /// The queued-byte bound drops datagrams independently of the
        /// datagram-count bound — a flow holding a full byte budget cannot
        /// take even a 1-byte datagram.
        #[tokio::test]
        async fn queued_byte_cap_drops() {
            let tunnel = mk_tunnel(Some(RecordingProxy::new(false)));
            let (mut d, _rx) = dispatch_with(0);
            assert!(d.dispatch(&tunnel, b"a".to_vec(), CLIENT, ORIG_DST));
            let entry = d.flows.get(&(CLIENT, ORIG_DST)).unwrap();
            entry
                .queued_bytes
                .store(FLOW_QUEUE_BYTES, Ordering::Relaxed);
            assert!(
                !d.dispatch(&tunnel, b"x".to_vec(), CLIENT, ORIG_DST),
                "datagram must be dropped once the byte cap is saturated"
            );
        }

        /// A flow whose task ended (channel closed) is evicted and a new
        /// flow created on the next datagram — timeouts/errors permit
        /// recreation (issue #564 §3).
        #[tokio::test]
        async fn closed_flow_is_recreated() {
            let tunnel = mk_tunnel(Some(RecordingProxy::new(false)));
            let (mut d, _rx) = dispatch_with(0);
            // Insert a stale entry whose receiver is already dropped.
            let (tx, rx) = mpsc::channel::<Vec<u8>>(FLOW_QUEUE);
            drop(rx);
            d.flows.insert(
                (CLIENT, ORIG_DST),
                FlowEntry {
                    tx,
                    queued_bytes: Arc::new(AtomicUsize::new(0)),
                },
            );
            assert!(d.dispatch(&tunnel, b"a".to_vec(), CLIENT, ORIG_DST));
            assert!(
                !d.flows.get(&(CLIENT, ORIG_DST)).unwrap().tx.is_closed(),
                "the closed entry must have been replaced by a live flow"
            );
        }

        fn v6(a: u16, b: u16, c: u16, d: u16, port: u16) -> SocketAddr {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 1)), port)
        }

        fn sockaddr_in_payload(family: libc::sa_family_t, ip: [u8; 4], port: u16) -> Vec<u8> {
            let mut bytes = vec![0u8; mem::size_of::<libc::sockaddr_in>()];
            bytes[0..2].copy_from_slice(&family.to_ne_bytes());
            bytes[2..4].copy_from_slice(&port.to_be_bytes());
            bytes[4..8].copy_from_slice(&ip);
            bytes
        }

        fn sockaddr_in6_payload(
            family: libc::sa_family_t,
            ip: Ipv6Addr,
            port: u16,
            flowinfo: u32,
            scope: u32,
        ) -> Vec<u8> {
            let mut bytes = vec![0u8; mem::size_of::<libc::sockaddr_in6>()];
            bytes[0..2].copy_from_slice(&family.to_ne_bytes());
            bytes[2..4].copy_from_slice(&port.to_be_bytes());
            bytes[4..8].copy_from_slice(&flowinfo.to_ne_bytes());
            bytes[8..24].copy_from_slice(&ip.octets());
            bytes[24..28].copy_from_slice(&scope.to_ne_bytes());
            bytes
        }

        fn bytes_mut(words: &mut [u64]) -> &mut [u8] {
            unsafe {
                std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), words.len() * 8)
            }
        }

        fn cmsg_bytes(words: &[u64]) -> &[u8] {
            unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 8) }
        }

        /// Write one control message at `offset` and return the aligned
        /// offset of the next one. The backing store is `u64` words, so the
        /// first header is naturally aligned on every supported ABI.
        fn put_cmsg(
            words: &mut [u64],
            offset: usize,
            level: libc::c_int,
            ty: libc::c_int,
            cmsg_len: usize,
            payload: &[u8],
        ) -> usize {
            let hdr_size = mem::size_of::<libc::cmsghdr>();
            let bytes = bytes_mut(words);
            // musl's 64-bit cmsghdr carries endian-dependent padding around
            // its u32 length field, so zero-initialize and assign the public
            // fields rather than using a literal whose shape varies by ABI.
            let mut hdr: libc::cmsghdr = unsafe { mem::zeroed() };
            // musl types this u32 while glibc uses usize; `as _` fits
            // whichever ABI the test target declares.
            hdr.cmsg_len = cmsg_len as _;
            hdr.cmsg_level = level;
            hdr.cmsg_type = ty;
            unsafe {
                std::ptr::write_unaligned(
                    bytes.as_mut_ptr().add(offset).cast::<libc::cmsghdr>(),
                    hdr,
                );
            }
            bytes[offset + hdr_size..offset + hdr_size + payload.len()].copy_from_slice(payload);
            offset + cmsg_align(cmsg_len).unwrap()
        }

        fn one_cmsg(
            level: libc::c_int,
            ty: libc::c_int,
            cmsg_len: usize,
            payload: &[u8],
        ) -> (Vec<u64>, usize) {
            let mut words = vec![0u64; 8];
            let next = put_cmsg(&mut words, 0, level, ty, cmsg_len, payload);
            (words, next)
        }

        fn cmsg_len_for(payload_len: usize) -> usize {
            mem::size_of::<libc::cmsghdr>() + payload_len
        }

        /// Both kernel cmsg families recover their embedded address/port;
        /// nonzero IPv6 flowinfo is ignored as part of flow identity.
        #[test]
        fn scan_orig_dst_parses_valid_ipv4_and_ipv6_cmsgs() {
            let payload4 = sockaddr_in_payload(libc::AF_INET as _, [203, 0, 113, 9], 5353);
            let len4 = cmsg_len_for(payload4.len());
            let (words, _) = one_cmsg(libc::SOL_IP, libc::IP_ORIGDSTADDR, len4, &payload4);
            assert_eq!(
                scan_orig_dst(cmsg_bytes(&words), len4),
                OrigDstScan::Found(v4(203, 0, 113, 9, 5353))
            );

            let ip6: Ipv6Addr = "2001:db8::53".parse().unwrap();
            let payload6 = sockaddr_in6_payload(libc::AF_INET6 as _, ip6, 53, 0x1234, 0);
            let len6 = cmsg_len_for(payload6.len());
            let (words, _) = one_cmsg(libc::SOL_IPV6, libc::IPV6_ORIGDSTADDR, len6, &payload6);
            assert_eq!(
                scan_orig_dst(cmsg_bytes(&words), len6),
                OrigDstScan::Found(SocketAddr::new(IpAddr::V6(ip6), 53))
            );
        }

        /// A valid unknown control message before the target is skipped at
        /// its aligned boundary, not mistaken for the original destination.
        #[test]
        fn scan_orig_dst_skips_unknown_cmsg_then_finds_target() {
            let mut words = vec![0u64; 12];
            let hdr_size = mem::size_of::<libc::cmsghdr>();
            // hdr+1 is deliberately unaligned: skipping must round up to the
            // next CMSG boundary before the target header can be found.
            let off = put_cmsg(
                &mut words,
                0,
                libc::SOL_IP,
                libc::IP_PKTINFO,
                hdr_size + 1,
                &[0x5a],
            );
            let payload = sockaddr_in6_payload(
                libc::AF_INET6 as _,
                "2001:db8::5353".parse().unwrap(),
                5353,
                0,
                0,
            );
            let len = cmsg_len_for(payload.len());
            let end = put_cmsg(
                &mut words,
                off,
                libc::SOL_IPV6,
                libc::IPV6_ORIGDSTADDR,
                len,
                &payload,
            );
            assert_eq!(
                scan_orig_dst(cmsg_bytes(&words), end),
                OrigDstScan::Found("[2001:db8::5353]:5353".parse().unwrap())
            );
        }

        /// Malformed or mismatched control data fails closed. In particular
        /// the payload bound is checked against the bytes remaining after
        /// this message's offset, not against the whole control buffer.
        #[test]
        fn scan_orig_dst_rejects_malformed_and_mismatched() {
            let payload4 = sockaddr_in_payload(libc::AF_INET as _, [203, 0, 113, 9], 53);
            let good_len = cmsg_len_for(payload4.len());

            // Right level/type but a non-IPv4 payload family.
            let bad = sockaddr_in_payload(libc::AF_INET6 as _, [203, 0, 113, 9], 53);
            let (words, end) = one_cmsg(libc::SOL_IP, libc::IP_ORIGDSTADDR, good_len, &bad);
            assert_eq!(
                scan_orig_dst(cmsg_bytes(&words), end),
                OrigDstScan::Rejected(EndpointReject::WrongFamily)
            );

            // cmsg_len too small to hold a sockaddr_in.
            let (words, end) =
                one_cmsg(libc::SOL_IP, libc::IP_ORIGDSTADDR, good_len - 4, &payload4);
            assert_eq!(
                scan_orig_dst(cmsg_bytes(&words), end),
                OrigDstScan::Rejected(EndpointReject::Truncated)
            );

            // A different ancillary type is skipped, not misread.
            let (words, end) = one_cmsg(libc::SOL_IP, libc::IP_PKTINFO, good_len, &payload4);
            assert_eq!(scan_orig_dst(cmsg_bytes(&words), end), OrigDstScan::Missing);

            // controllen shorter than one cmsghdr finds nothing.
            let (words, _) = one_cmsg(libc::SOL_IP, libc::IP_ORIGDSTADDR, good_len, &payload4);
            assert_eq!(
                scan_orig_dst(cmsg_bytes(&words), mem::size_of::<libc::cmsghdr>() - 1),
                OrigDstScan::Missing
            );

            // A valid first message followed by a second whose payload runs
            // beyond controllen is rejected at the current offset boundary.
            let mut words = vec![0u64; 8];
            let hdr_size = mem::size_of::<libc::cmsghdr>();
            let off = put_cmsg(&mut words, 0, libc::SOL_IP, libc::IP_PKTINFO, hdr_size, &[]);
            put_cmsg(
                &mut words,
                off,
                libc::SOL_IP,
                libc::IP_ORIGDSTADDR,
                good_len,
                &payload4,
            );
            let short_end = off + hdr_size + 2;
            assert_eq!(
                scan_orig_dst(cmsg_bytes(&words), short_end),
                OrigDstScan::Rejected(EndpointReject::Truncated)
            );
        }

        /// Scoped, link-local, and IPv4-mapped IPv6 control data is rejected
        /// before a zone-less `SocketAddr` can enter a flow key.
        #[test]
        fn scan_orig_dst_rejects_unsupported_ipv6_shapes() {
            for (ip, scope, want) in [
                ("2001:db8::53", 2, EndpointReject::ScopedV6),
                ("fe80::53", 0, EndpointReject::LinkLocalV6),
                ("::ffff:203.0.113.9", 0, EndpointReject::MappedV6),
            ] {
                let ip: Ipv6Addr = ip.parse().unwrap();
                let payload = sockaddr_in6_payload(libc::AF_INET6 as _, ip, 53, 0, scope);
                let len = cmsg_len_for(payload.len());
                let (words, end) = one_cmsg(libc::SOL_IPV6, libc::IPV6_ORIGDSTADDR, len, &payload);
                assert_eq!(
                    scan_orig_dst(cmsg_bytes(&words), end),
                    OrigDstScan::Rejected(want),
                    "ip={ip} scope={scope}"
                );
            }
        }

        fn storage_with(bytes: &[u8]) -> (libc::sockaddr_storage, libc::socklen_t) {
            let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (&mut storage as *mut libc::sockaddr_storage).cast::<u8>(),
                    bytes.len(),
                );
            }
            (storage, bytes.len() as libc::socklen_t)
        }

        /// `msg_name` decoding is dual-family and rejects short/scoped or
        /// otherwise unsupported v6 source addresses.
        #[test]
        fn sockaddr_to_addr_parses_both_families_and_rejects_bad_v6() {
            let p4 = sockaddr_in_payload(libc::AF_INET as _, [192, 0, 2, 7], 41234);
            let (storage, len) = storage_with(&p4);
            assert_eq!(sockaddr_to_addr(&storage, len), Ok(v4(192, 0, 2, 7, 41234)));

            let ip6: Ipv6Addr = "2001:db8::7".parse().unwrap();
            let p6 = sockaddr_in6_payload(libc::AF_INET6 as _, ip6, 41234, 0, 0);
            let (storage, len) = storage_with(&p6);
            assert_eq!(
                sockaddr_to_addr(&storage, len),
                Ok(SocketAddr::new(IpAddr::V6(ip6), 41234))
            );

            let (storage, len) = storage_with(&p6[..p6.len() - 1]);
            assert_eq!(
                sockaddr_to_addr(&storage, len),
                Err(EndpointReject::Truncated)
            );

            let scoped = sockaddr_in6_payload(libc::AF_INET6 as _, ip6, 41234, 0, 3);
            let (storage, len) = storage_with(&scoped);
            assert_eq!(
                sockaddr_to_addr(&storage, len),
                Err(EndpointReject::ScopedV6)
            );
        }

        /// The flow table is family-neutral: distinct v6 destinations are
        /// isolated, a repeated v6 tuple folds, and v4/v6 tuples share the
        /// same configured flow cap rather than doubling it.
        #[tokio::test]
        async fn v6_flow_keys_and_shared_cap() {
            let tunnel = mk_tunnel(Some(RecordingProxy::new(false)));
            let client6 = v6(0x2001, 0xdb8, 0, 7, 41234);
            let dst6 = v6(0x2001, 0xdb8, 0, 53, 53);
            let other6 = v6(0x2001, 0xdb8, 0, 54, 53);
            let (mut d, _rx) = dispatch_with(0);
            assert!(d.dispatch(&tunnel, b"a".to_vec(), client6, dst6));
            assert!(d.dispatch(&tunnel, b"b".to_vec(), client6, dst6));
            assert!(d.dispatch(&tunnel, b"c".to_vec(), client6, other6));
            assert_eq!(d.flows.len(), 2);

            let (mut capped, _rx) = dispatch_with(1);
            assert!(capped.dispatch(&tunnel, b"a".to_vec(), CLIENT, ORIG_DST));
            assert!(
                !capped.dispatch(&tunnel, b"b".to_vec(), client6, dst6),
                "the v6 tuple must charge against the same cap as v4"
            );
        }

        /// Every cross-family combination is rejected before the shared
        /// flow table; only native v4↔v4 and v6↔v6 tuples pass.
        #[test]
        fn ingress_family_consistent_rejects_mixed_families() {
            let c4 = v4(192, 0, 2, 7, 41234);
            let d4 = v4(203, 0, 113, 9, 53);
            let c6 = v6(0x2001, 0xdb8, 0, 7, 41234);
            let d6 = v6(0x2001, 0xdb8, 0, 53, 53);
            assert!(ingress_family_consistent(true, c4, d4));
            assert!(ingress_family_consistent(false, c6, d6));
            for (ingress_is_v4, client, dst) in [
                (true, c6, d6),
                (true, c4, d6),
                (true, c6, d4),
                (false, c4, d4),
                (false, c6, d4),
                (false, c4, d6),
            ] {
                assert!(
                    !ingress_family_consistent(ingress_is_v4, client, dst),
                    "ingress_is_v4={ingress_is_v4} client={client} dst={dst}"
                );
            }
        }

        /// The absolute-deadline backoff keeps growing even if the select
        /// sleep is cancelled by sibling ingress traffic; only a successful
        /// receive resets it.
        #[test]
        fn ingress_backoff_state_survives_cancelled_sleep() {
            let err = io::Error::other("socket pressure");
            let now = Instant::now();
            let mut backoff = IngressBackoff::new();
            assert!(backoff.failed(&err, now));
            let first = backoff.waiting_until(now).unwrap();
            assert!(backoff
                .waiting_until(now + Duration::from_millis(1))
                .is_some());
            assert!(backoff.failed(&err, now + Duration::from_millis(2)));
            assert!(backoff.waiting_until(now).unwrap() > first);
            backoff.succeeded();
            assert!(backoff.failed(&err, now));
            assert_eq!(
                backoff.waiting_until(now).unwrap() - now,
                Duration::from_millis(10)
            );
        }

        /// The recovered-destination sanity filter: plausible LAN targets
        /// pass; self-target, port 0, and non-unicast addresses are rejected.
        #[test]
        fn is_safe_orig_dst_filters() {
            let local = "127.0.0.1:7895".parse::<SocketAddr>().unwrap();
            let wild = "0.0.0.0:7895".parse::<SocketAddr>().unwrap();
            let ok = "203.0.113.9:443".parse::<SocketAddr>().unwrap();
            let none: Option<&std::collections::HashSet<IpAddr>> = None;
            assert!(is_safe_orig_dst(ok, local, none));
            assert!(is_safe_orig_dst(ok, wild, none));
            // Self-target: exact endpoint, and — without an address
            // snapshot — any same-port dst on wildcard (conservative).
            assert!(!is_safe_orig_dst(local, local, none));
            assert!(!is_safe_orig_dst(
                "203.0.113.9:7895".parse().unwrap(),
                wild,
                none
            ));
            // With the interface snapshot, same-port self-target means a
            // LOCAL address at the listener port — a remote service that
            // merely shares the port number now passes.
            let addrs: std::collections::HashSet<IpAddr> = ["192.0.2.1".parse::<IpAddr>().unwrap()]
                .into_iter()
                .collect();
            let set = Some(&addrs);
            assert!(!is_safe_orig_dst(
                "192.0.2.1:7895".parse().unwrap(),
                wild,
                set
            ));
            assert!(is_safe_orig_dst(
                "198.51.100.7:7895".parse().unwrap(),
                wild,
                set
            ));
            // Different-port dst on a specific bind is NOT self (but this
            // particular dst is loopback, so still filtered overall).
            assert!(!is_safe_orig_dst(
                "127.0.0.1:80".parse().unwrap(),
                local,
                none
            ));
            // Port 0 / unspecified / multicast / broadcast.
            for bad in [
                "203.0.113.9:0",
                "0.0.0.0:53",
                "224.0.0.1:53",
                "255.255.255.255:53",
            ] {
                assert!(!is_safe_orig_dst(bad.parse().unwrap(), wild, none), "{bad}");
            }
            assert!(!is_safe_orig_dst("[::1]:53".parse().unwrap(), wild, none));
            assert!(!is_safe_orig_dst(
                "[ff00::1]:53".parse().unwrap(),
                wild,
                none
            ));
            assert!(!is_safe_orig_dst("[::]:53".parse().unwrap(), wild, none));
            let wild6 = "[::]:7895".parse::<SocketAddr>().unwrap();
            assert!(!is_safe_orig_dst(
                "[2001:db8::1]:7895".parse().unwrap(),
                wild6,
                none
            ));
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) use linux::{bind_transparent, run_udp, UdpIngresses};

#[cfg(test)]
mod tests {
    use super::flow;
    use async_trait::async_trait;
    use meow_common::adapter::ProxyAdapter;
    use meow_common::error::Result as MeowResult;
    use meow_common::{
        AdapterType, DelayHistory, DnsMode, MeowError, Metadata, Proxy, ProxyConn, ProxyHealth,
        ProxyPacketConn, TunnelMode,
    };
    use meow_tunnel::Tunnel;
    use smol_str::SmolStr;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::{mpsc, Notify};

    /// `(payload, addr)` pairs a conn has seen via `write_packet`.
    type WriteLog = Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>;

    /// Shared, observable state of one `dial_udp` product — the test holds
    /// this handle to push scripted replies and inspect writes/close.
    pub(super) struct ConnHandle {
        writes: WriteLog,
        wrote: Arc<Notify>,
        closed: Arc<AtomicBool>,
        reply_tx: mpsc::Sender<Vec<u8>>,
    }

    /// Optional stalls on a produced conn: `write` parks `write_packet`
    /// (a stalled upstream), `fail_read` fails `read_packet` (a dead
    /// reply reader) — both wait on `Notify`s the test fires at will.
    #[derive(Default, Clone)]
    pub(super) struct ConnGates {
        write: Option<Arc<Notify>>,
        fail_read: Option<Arc<Notify>>,
    }

    struct RecordingConn {
        writes: WriteLog,
        wrote: Arc<Notify>,
        closed: Arc<AtomicBool>,
        replies: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        gates: ConnGates,
    }

    #[async_trait]
    impl ProxyPacketConn for RecordingConn {
        async fn read_packet(&self, buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            let recv = async {
                let mut rx = self.replies.lock().await;
                match rx.recv().await {
                    Some(data) => {
                        let n = data.len().min(buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        Ok((n, "0.0.0.0:0".parse().unwrap()))
                    }
                    // The test stopped scripting replies — park until the
                    // flow aborts this reader, never spin into an error storm.
                    None => std::future::pending().await,
                }
            };
            match &self.gates.fail_read {
                None => recv.await,
                Some(gate) => tokio::select! {
                    v = recv => v,
                    () = gate.notified() => Err(MeowError::Proxy("injected read failure".into())),
                },
            }
        }
        async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> MeowResult<usize> {
            self.writes.lock().unwrap().push((buf.to_vec(), *addr));
            self.wrote.notify_one();
            if let Some(gate) = &self.gates.write {
                gate.notified().await;
            }
            Ok(buf.len())
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// UDP-capable adapter handing out `RecordingConn`s; `dial_udp` records
    /// every attempt so tests can assert zero-dial on REJECT/error paths.
    pub(super) struct RecordingProxy {
        dials: AtomicUsize,
        conns: Mutex<Vec<ConnHandle>>,
        /// `remote_address()` of every `dial_udp` metadata — lets tests pin
        /// the host the outbound actually saw (fake-IP rewrite check).
        meta_log: Mutex<Vec<String>>,
        health: ProxyHealth,
        fail_dial: bool,
        gates: ConnGates,
    }

    impl RecordingProxy {
        pub(super) fn new(fail_dial: bool) -> Arc<Self> {
            Self::build(fail_dial, ConnGates::default())
        }

        /// Same as [`Self::new`] but produced conns honour `gates`.
        pub(super) fn new_gated(fail_dial: bool, gates: ConnGates) -> Arc<Self> {
            Self::build(fail_dial, gates)
        }

        fn build(fail_dial: bool, gates: ConnGates) -> Arc<Self> {
            Arc::new(Self {
                dials: AtomicUsize::new(0),
                conns: Mutex::new(Vec::new()),
                meta_log: Mutex::new(Vec::new()),
                health: ProxyHealth::new(),
                fail_dial,
                gates,
            })
        }

        #[cfg(target_os = "linux")]
        pub(super) fn dial_count(&self) -> usize {
            self.dials.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProxyAdapter for RecordingProxy {
        fn name(&self) -> &str {
            "recording"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            true
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
            Err(MeowError::NotSupported("recording: tcp".into()))
        }
        async fn dial_udp(&self, metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            self.meta_log
                .lock()
                .unwrap()
                .push(metadata.remote_address().to_string());
            if self.fail_dial {
                return Err(MeowError::NotSupported("recording: udp".into()));
            }
            let (reply_tx, replies) = mpsc::channel(8);
            let conn = ConnHandle {
                writes: Arc::new(Mutex::new(Vec::new())),
                wrote: Arc::new(Notify::new()),
                closed: Arc::new(AtomicBool::new(false)),
                reply_tx,
            };
            let packet_conn = RecordingConn {
                writes: Arc::clone(&conn.writes),
                wrote: Arc::clone(&conn.wrote),
                closed: Arc::clone(&conn.closed),
                replies: tokio::sync::Mutex::new(replies),
                gates: self.gates.clone(),
            };
            self.conns.lock().unwrap().push(conn);
            Ok(Box::new(packet_conn))
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for RecordingProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
    }

    pub(super) fn mk_tunnel(proxy: Option<Arc<RecordingProxy>>) -> Tunnel {
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        if let Some(p) = proxy {
            tunnel.set_mode(TunnelMode::Global);
            let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
            proxies.insert("GLOBAL".into(), p as Arc<dyn Proxy>);
            let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
            tunnel.update_proxies(proxies, res.dialer_registry);
            tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
                "GLOBAL",
            ))]);
        }
        tunnel
    }

    fn ctx(timeout_secs: u64) -> flow::FlowCtx {
        flow::FlowCtx {
            client: CLIENT,
            orig_dst: ORIG_DST,
            udp_timeout: Duration::from_secs(timeout_secs),
            in_name: "tproxy".into(),
            in_port: 7894,
            route_override: None,
        }
    }

    pub(super) const CLIENT: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7)),
        41234,
    );
    pub(super) const ORIG_DST: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9)),
        53,
    );

    /// Both directions flow through one `dial_udp`, replies carry the
    /// original-destination identity, and dropping the queue shuts the
    /// whole flow down (conn closed, reader task gone).
    #[tokio::test]
    async fn flow_relays_both_directions_and_closes_clean() {
        let proxy = RecordingProxy::new(false);
        let tunnel = mk_tunnel(Some(Arc::clone(&proxy)));
        let (flow_tx, flow_rx) = mpsc::channel::<Vec<u8>>(flow::FLOW_QUEUE);
        let (reply_tx, mut reply_rx) = mpsc::channel::<flow::ReplyMsg>(8);
        let queued = Arc::new(AtomicUsize::new(0));

        let task = tokio::spawn(flow::relay_udp_flow(
            tunnel,
            flow_rx,
            Arc::clone(&queued),
            reply_tx,
            ctx(60),
        ));

        // Client → upstream: one datagram must reach write_packet at the
        // original destination, and queued_bytes must drain to zero.
        // `queued` mirrors the FlowDispatch accounting contract: enqueue
        // adds len, dequeue subtracts it.
        queued.fetch_add(5, Ordering::SeqCst);
        flow_tx.send(b"hello".to_vec()).await.unwrap();
        let conn = loop {
            if let Some(c) = proxy.conns.lock().unwrap().first() {
                break ConnHandle {
                    writes: Arc::clone(&c.writes),
                    wrote: Arc::clone(&c.wrote),
                    closed: Arc::clone(&c.closed),
                    reply_tx: c.reply_tx.clone(),
                };
            }
            tokio::time::timeout(Duration::from_secs(2), tokio::task::yield_now())
                .await
                .expect("dial_udp never ran");
        };
        tokio::time::timeout(Duration::from_secs(2), conn.wrote.notified())
            .await
            .expect("write_packet never saw the datagram");
        {
            let writes = conn.writes.lock().unwrap();
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0].0, b"hello");
            assert_eq!(writes[0].1, ORIG_DST);
        }
        assert_eq!(queued.load(Ordering::SeqCst), 0);

        // Upstream → client: the reply rides reply_tx with the ORIGINAL
        // destination — the dispatcher, not the flow, decides how that
        // identity materialises on the wire.
        conn.reply_tx.send(b"world".to_vec()).await.unwrap();
        let (data, src, dst) = tokio::time::timeout(Duration::from_secs(2), reply_rx.recv())
            .await
            .expect("reply never arrived")
            .expect("reply channel closed");
        assert_eq!(data, b"world");
        assert_eq!(src, ORIG_DST);
        assert_eq!(dst, CLIENT);

        // Listener teardown = flow queue closed → flow exits Ok and the
        // outbound session is closed, not leaked.
        drop(flow_tx);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("flow did not exit")
            .expect("flow task panicked")
            .expect("flow returned error");
        assert!(conn.closed.load(Ordering::SeqCst));
    }

    /// Fake-IP original destination: `pre_handle_metadata` must reverse the
    /// fake IP back to its hostname for rule matching/dialing and resolve a
    /// real `dst_ip` for the outbound, while the flow key and the reply
    /// identity stay the fake IP — the client sees responses sourced from
    /// the exact address it sent to.
    #[tokio::test]
    async fn flow_fake_ip_dst_rewrites_and_keeps_reply_identity() {
        // Deterministic resolution: the hosts trie answers "example.com"
        // with a real IP instead of exercising the upstream DNS path.
        let real_ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let mut hosts = meow_trie::DomainTrie::new();
        hosts.insert("example.com", meow_dns::HostEntry::Addresses(vec![real_ip]));
        let pool = Arc::new(
            meow_dns::fakeip::Pool::new(
                "198.18.0.0/16".parse().unwrap(),
                Arc::new(meow_dns::fakeip::MemoryStore::new(1024)),
            )
            .unwrap(),
        );
        let fake_ip = pool.lookup("example.com");
        let mut resolver =
            meow_dns::Resolver::new(vec![], vec![], DnsMode::FakeIp, hosts, true, true);
        resolver.set_fakeip_v4(pool);
        let tunnel = Tunnel::new(Arc::new(resolver));

        let proxy = RecordingProxy::new(false);
        tunnel.set_mode(TunnelMode::Global);
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert("GLOBAL".into(), Arc::clone(&proxy) as Arc<dyn Proxy>);
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        tunnel.update_proxies(proxies, res.dialer_registry);
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "GLOBAL",
        ))]);

        let fake_dst = SocketAddr::new(fake_ip, 443);
        let (flow_tx, flow_rx) = mpsc::channel::<Vec<u8>>(flow::FLOW_QUEUE);
        let (reply_tx, mut reply_rx) = mpsc::channel::<flow::ReplyMsg>(8);
        let queued = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(flow::relay_udp_flow(
            tunnel,
            flow_rx,
            Arc::clone(&queued),
            reply_tx,
            flow::FlowCtx {
                client: CLIENT,
                orig_dst: fake_dst,
                udp_timeout: Duration::from_secs(60),
                in_name: "tproxy-fake".into(),
                in_port: 7895,
                route_override: None,
            },
        ));

        // The outbound must see the recovered hostname and dial the REAL
        // resolved address — never the fake IP itself.
        queued.fetch_add(5, Ordering::SeqCst);
        flow_tx.send(b"hello".to_vec()).await.unwrap();
        let conn = loop {
            if let Some(c) = proxy.conns.lock().unwrap().first() {
                break ConnHandle {
                    writes: Arc::clone(&c.writes),
                    wrote: Arc::clone(&c.wrote),
                    closed: Arc::clone(&c.closed),
                    reply_tx: c.reply_tx.clone(),
                };
            }
            tokio::time::timeout(Duration::from_secs(2), tokio::task::yield_now())
                .await
                .expect("dial_udp never ran");
        };
        tokio::time::timeout(Duration::from_secs(2), conn.wrote.notified())
            .await
            .expect("write_packet never saw the datagram");
        assert_eq!(proxy.meta_log.lock().unwrap()[0], "example.com:443");
        {
            let writes = conn.writes.lock().unwrap();
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0].1, SocketAddr::new(real_ip, 443));
        }

        // The reply keeps the FAKE-IP identity — that's the whole point of
        // keying flows on orig_dst: the client believes it talks to the
        // address it originally sent to.
        conn.reply_tx.send(b"world".to_vec()).await.unwrap();
        let (data, src, dst) = tokio::time::timeout(Duration::from_secs(2), reply_rx.recv())
            .await
            .expect("reply never arrived")
            .expect("reply channel closed");
        assert_eq!(data, b"world");
        assert_eq!(src, fake_dst);
        assert_eq!(dst, CLIENT);

        drop(flow_tx);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("flow did not exit")
            .expect("flow task panicked")
            .expect("flow returned error");
        assert!(conn.closed.load(Ordering::SeqCst));
    }

    /// The fake-IP identity contract is family-neutral: a fake AAAA is
    /// resolved back to its hostname/real v6 address for the outbound,
    /// while the client-facing reply source remains the original fake v6
    /// endpoint.
    #[tokio::test]
    async fn flow_fake_ip_v6_dst_rewrites_and_keeps_reply_identity() {
        let real_ip: std::net::IpAddr = "2001:db8::7".parse().unwrap();
        let mut hosts = meow_trie::DomainTrie::new();
        hosts.insert("example.com", meow_dns::HostEntry::Addresses(vec![real_ip]));
        let pool = Arc::new(
            meow_dns::fakeip::Pool::new(
                "fc00::/64".parse().unwrap(),
                Arc::new(meow_dns::fakeip::MemoryStore::new(1024)),
            )
            .unwrap(),
        );
        let fake_ip = pool.lookup("example.com");
        assert!(fake_ip.is_ipv6(), "fc00::/64 must allocate a v6 fake");
        let mut resolver =
            meow_dns::Resolver::new(vec![], vec![], DnsMode::FakeIp, hosts, true, true);
        resolver.set_fakeip_v6(pool);
        let tunnel = Tunnel::new(Arc::new(resolver));

        let proxy = RecordingProxy::new(false);
        tunnel.set_mode(TunnelMode::Global);
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert("GLOBAL".into(), Arc::clone(&proxy) as Arc<dyn Proxy>);
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        tunnel.update_proxies(proxies, res.dialer_registry);
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "GLOBAL",
        ))]);

        let client: SocketAddr = "[2001:db8:1::7]:41234".parse().unwrap();
        let fake_dst = SocketAddr::new(fake_ip, 443);
        let (flow_tx, flow_rx) = mpsc::channel::<Vec<u8>>(flow::FLOW_QUEUE);
        let (reply_tx, mut reply_rx) = mpsc::channel::<flow::ReplyMsg>(8);
        let queued = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(flow::relay_udp_flow(
            tunnel,
            flow_rx,
            Arc::clone(&queued),
            reply_tx,
            flow::FlowCtx {
                client,
                orig_dst: fake_dst,
                udp_timeout: Duration::from_secs(60),
                in_name: "tproxy-fake6".into(),
                in_port: 7895,
                route_override: None,
            },
        ));

        queued.fetch_add(5, Ordering::SeqCst);
        flow_tx.send(b"hello6".to_vec()).await.unwrap();
        let conn = loop {
            if let Some(c) = proxy.conns.lock().unwrap().first() {
                break ConnHandle {
                    writes: Arc::clone(&c.writes),
                    wrote: Arc::clone(&c.wrote),
                    closed: Arc::clone(&c.closed),
                    reply_tx: c.reply_tx.clone(),
                };
            }
            tokio::time::timeout(Duration::from_secs(2), tokio::task::yield_now())
                .await
                .expect("dial_udp never ran");
        };
        tokio::time::timeout(Duration::from_secs(2), conn.wrote.notified())
            .await
            .expect("write_packet never saw the datagram");
        assert_eq!(proxy.meta_log.lock().unwrap()[0], "example.com:443");
        {
            let writes = conn.writes.lock().unwrap();
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0].1, SocketAddr::new(real_ip, 443));
        }

        conn.reply_tx.send(b"world6".to_vec()).await.unwrap();
        let (data, src, dst) = tokio::time::timeout(Duration::from_secs(2), reply_rx.recv())
            .await
            .expect("reply never arrived")
            .expect("reply channel closed");
        assert_eq!(data, b"world6");
        assert_eq!(src, fake_dst);
        assert_eq!(dst, client);

        drop(flow_tx);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("flow did not exit")
            .expect("flow task panicked")
            .expect("flow returned error");
        assert!(conn.closed.load(Ordering::SeqCst));
    }

    /// A `REJECT` verdict must route to the REJECT-named adapter — never a
    /// silent DIRECT fallback (the issue's hard requirement). The map key
    /// is what `resolve_proxy_flow` looks up, so the recording stub stands in
    /// for the real reject adapter; a DIRECT fallback leaves the dial
    /// counter at zero, while the reject path dials it exactly once and
    /// then parks on the drop conn until idle eviction.
    #[tokio::test(start_paused = true)]
    async fn flow_reject_verdict_dials_reject_adapter() {
        let proxy = RecordingProxy::new(false);
        let tunnel = mk_tunnel(None);
        tunnel.set_mode(TunnelMode::Rule);
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert("REJECT".into(), Arc::clone(&proxy) as Arc<dyn Proxy>);
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        tunnel.update_proxies(proxies, res.dialer_registry);
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "REJECT",
        ))]);
        let (_flow_tx, flow_rx) = mpsc::channel::<Vec<u8>>(flow::FLOW_QUEUE);
        let (reply_tx, _reply_rx) = mpsc::channel::<flow::ReplyMsg>(8);

        // Idle eviction under the paused clock ends the flow quickly.
        flow::relay_udp_flow(
            tunnel,
            flow_rx,
            Arc::new(AtomicUsize::new(0)),
            reply_tx,
            ctx(30),
        )
        .await
        .expect("rejected flow must exit cleanly");
        assert_eq!(proxy.dials.load(Ordering::SeqCst), 1);
    }

    /// A UDP-incapable outbound (dial_udp error) kills the flow — packets
    /// are dropped, never diverted to DIRECT.
    #[tokio::test]
    async fn flow_unsupported_outbound_dies() {
        let proxy = RecordingProxy::new(true);
        let tunnel = mk_tunnel(Some(Arc::clone(&proxy)));
        let (_flow_tx, flow_rx) = mpsc::channel::<Vec<u8>>(flow::FLOW_QUEUE);
        let (reply_tx, _reply_rx) = mpsc::channel::<flow::ReplyMsg>(8);

        let err = flow::relay_udp_flow(
            tunnel,
            flow_rx,
            Arc::new(AtomicUsize::new(0)),
            reply_tx,
            ctx(60),
        )
        .await
        .expect_err("unsupported udp must error, not fall back");
        assert!(err.contains("dial_udp"));
    }

    /// Idle timeout evicts the flow — `start_paused` advances the clock
    /// without real waiting.
    #[tokio::test(start_paused = true)]
    async fn flow_idle_timeout_evicts() {
        let proxy = RecordingProxy::new(false);
        let tunnel = mk_tunnel(Some(Arc::clone(&proxy)));
        let (_flow_tx, flow_rx) = mpsc::channel::<Vec<u8>>(flow::FLOW_QUEUE);
        let (reply_tx, _reply_rx) = mpsc::channel::<flow::ReplyMsg>(8);

        flow::relay_udp_flow(
            tunnel,
            flow_rx,
            Arc::new(AtomicUsize::new(0)),
            reply_tx,
            ctx(30),
        )
        .await
        .expect("idle eviction is a clean exit");
    }

    /// PR #900 review: a `write_packet` that never completes must not park
    /// the flow's termination signals — an outbound-session flush ends the
    /// flow immediately and closes the conn.
    #[tokio::test(start_paused = true)]
    async fn pending_write_does_not_block_flush() {
        let gate = Arc::new(Notify::new());
        let proxy = RecordingProxy::new_gated(
            false,
            ConnGates {
                write: Some(Arc::clone(&gate)),
                ..Default::default()
            },
        );
        let tunnel = mk_tunnel(Some(Arc::clone(&proxy)));
        let (flow_tx, flow_rx) = mpsc::channel::<Vec<u8>>(flow::FLOW_QUEUE);
        let (reply_tx, _reply_rx) = mpsc::channel::<flow::ReplyMsg>(8);
        let queued = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(flow::relay_udp_flow(
            tunnel.clone(),
            flow_rx,
            Arc::clone(&queued),
            reply_tx,
            ctx(3600),
        ));

        queued.fetch_add(6, Ordering::SeqCst);
        flow_tx.send(b"parked".to_vec()).await.unwrap();
        let conn = loop {
            if let Some(c) = proxy.conns.lock().unwrap().first() {
                break ConnHandle {
                    writes: Arc::clone(&c.writes),
                    wrote: Arc::clone(&c.wrote),
                    closed: Arc::clone(&c.closed),
                    reply_tx: c.reply_tx.clone(),
                };
            }
            tokio::time::timeout(Duration::from_secs(2), tokio::task::yield_now())
                .await
                .expect("dial_udp never ran");
        };
        tokio::time::timeout(Duration::from_secs(2), conn.wrote.notified())
            .await
            .expect("write_packet never entered");

        assert_eq!(tunnel.close_all_udp_sessions(), 1);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("flush did not end the parked-write flow")
            .expect("flow task panicked")
            .expect("flow returned error");
        assert!(conn.closed.load(Ordering::SeqCst));
    }

    /// Same gate, opposite signal: advancing the clock past `udp_timeout`
    /// must evict the flow while `write_packet` is still parked.
    #[tokio::test(start_paused = true)]
    async fn pending_write_does_not_block_idle_eviction() {
        let gate = Arc::new(Notify::new());
        let proxy = RecordingProxy::new_gated(
            false,
            ConnGates {
                write: Some(Arc::clone(&gate)),
                ..Default::default()
            },
        );
        let tunnel = mk_tunnel(Some(Arc::clone(&proxy)));
        let (flow_tx, flow_rx) = mpsc::channel::<Vec<u8>>(flow::FLOW_QUEUE);
        let (reply_tx, _reply_rx) = mpsc::channel::<flow::ReplyMsg>(8);
        let queued = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(flow::relay_udp_flow(
            tunnel,
            flow_rx,
            Arc::clone(&queued),
            reply_tx,
            ctx(30),
        ));

        queued.fetch_add(6, Ordering::SeqCst);
        flow_tx.send(b"parked".to_vec()).await.unwrap();
        let conn = loop {
            if let Some(c) = proxy.conns.lock().unwrap().first() {
                break ConnHandle {
                    writes: Arc::clone(&c.writes),
                    wrote: Arc::clone(&c.wrote),
                    closed: Arc::clone(&c.closed),
                    reply_tx: c.reply_tx.clone(),
                };
            }
            tokio::time::timeout(Duration::from_secs(2), tokio::task::yield_now())
                .await
                .expect("dial_udp never ran");
        };
        tokio::time::timeout(Duration::from_secs(2), conn.wrote.notified())
            .await
            .expect("write_packet never entered");

        // Paused clock auto-advances: idle eviction fires during the parked
        // write; regression (write holds the loop) shows up as the timeout.
        tokio::time::timeout(Duration::from_secs(120), task)
            .await
            .expect("idle eviction did not end the parked-write flow")
            .expect("flow task panicked")
            .expect("flow returned error");
        assert!(conn.closed.load(Ordering::SeqCst));
    }

    /// The `done = &mut reply_task` arm added in this batch: a dead
    /// downstream reader during a parked write must surface immediately
    /// (same error text the `up_rx` `None` arm produces), not on idle.
    #[tokio::test(start_paused = true)]
    async fn pending_write_does_not_block_reader_death() {
        let gate = Arc::new(Notify::new());
        let fail_read = Arc::new(Notify::new());
        let proxy = RecordingProxy::new_gated(
            false,
            ConnGates {
                write: Some(Arc::clone(&gate)),
                fail_read: Some(Arc::clone(&fail_read)),
            },
        );
        let tunnel = mk_tunnel(Some(Arc::clone(&proxy)));
        let (flow_tx, flow_rx) = mpsc::channel::<Vec<u8>>(flow::FLOW_QUEUE);
        let (reply_tx, _reply_rx) = mpsc::channel::<flow::ReplyMsg>(8);
        let queued = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(flow::relay_udp_flow(
            tunnel,
            flow_rx,
            Arc::clone(&queued),
            reply_tx,
            ctx(3600),
        ));

        queued.fetch_add(6, Ordering::SeqCst);
        flow_tx.send(b"parked".to_vec()).await.unwrap();
        let conn = loop {
            if let Some(c) = proxy.conns.lock().unwrap().first() {
                break ConnHandle {
                    writes: Arc::clone(&c.writes),
                    wrote: Arc::clone(&c.wrote),
                    closed: Arc::clone(&c.closed),
                    reply_tx: c.reply_tx.clone(),
                };
            }
            tokio::time::timeout(Duration::from_secs(2), tokio::task::yield_now())
                .await
                .expect("dial_udp never ran");
        };
        tokio::time::timeout(Duration::from_secs(2), conn.wrote.notified())
            .await
            .expect("write_packet never entered");

        fail_read.notify_one();
        let err = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("reader death did not end the parked-write flow")
            .expect("flow task panicked")
            .expect_err("a dead reader must surface as an error");
        assert!(err.contains("downstream read"), "unexpected: {err}");
        assert!(conn.closed.load(Ordering::SeqCst));
    }
}
