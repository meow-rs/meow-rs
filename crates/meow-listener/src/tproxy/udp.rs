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

    use meow_common::{with_dial_timeout, ConnType, Metadata, Network};
    use meow_tunnel::Tunnel;
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

        let inner = tunnel.inner();
        if matches!(
            inner.pre_handle_metadata(&mut metadata),
            meow_tunnel::PreHandleVerdict::Drop
        ) {
            return Err("unmapped fake-ip destination".into());
        }
        // UDP keeps the eager pre_resolve (no lazy enrichment): the outbound
        // packet API needs a resolved dst_ip regardless of what the rules
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

        // Port 53 follows ordinary routing — no implicit DNS hijack here
        // (external rules feed queries to the standalone DNS server if
        // wanted). A `REJECT` verdict resolves to the REJECT adapter, whose
        // `dial_udp` succeeds with a conn that errors on first read — the
        // flow dies and the datagrams drop; a UDP-incapable outbound errors
        // at dial. Either way datagrams are never silently diverted to
        // DIRECT.
        let Some(meow_tunnel::ResolvedTarget {
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
            "UDP {client} --> {orig_dst} match {rule_name}({rule_payload}) using {}",
            proxy.name()
        );

        let conn: Arc<dyn meow_common::ProxyPacketConn> = Arc::from(
            with_dial_timeout(proxy.name(), proxy.dial_udp(&metadata))
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
                queued = rx.recv() => match queued {
                    Some(data) => {
                        queued_bytes.fetch_sub(data.len(), Ordering::Relaxed);
                        if let Err(e) = conn.write_packet(&data, &dst_addr).await {
                            break Err(format!("upstream write {dst_addr}: {e}"));
                        }
                        idle.as_mut().reset(next_deadline(udp_timeout));
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
    use std::collections::HashMap;
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::Interest;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::Instant;
    use tracing::{debug, warn};

    const IP_TRANSPARENT: libc::c_int = 19;
    /// Ask for the original destination in `IP_ORIGDSTADDR` ancillary data.
    const IP_RECVORIGDSTADDR: libc::c_int = 20;
    const IP_ORIGDSTADDR: libc::c_int = 20;

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
        ) -> Self {
            Self {
                flows: HashMap::new(),
                reply_tx,
                max_flows,
                udp_timeout,
                in_name,
                in_port,
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

    /// Bind the UDP TPROXY listener socket: `IP_TRANSPARENT` (so the socket
    /// is visible to the TPROXY socket lookup for packets the deployer
    /// steers via `--on-port` + fwmark/policy-routing) and
    /// `IP_RECVORIGDSTADDR` (so each datagram carries its original
    /// destination in ancillary data). IPv4 only in this release.
    ///
    /// `IP_TRANSPARENT` requires `CAP_NET_ADMIN`/`CAP_NET_RAW` — a failure
    /// here is the explicit permission diagnostic the issue asks for.
    pub fn bind_transparent(addr: SocketAddr) -> io::Result<UdpSocket> {
        let IpAddr::V4(ip) = addr.ip() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tproxy udp listener is IPv4-only in this release",
            ));
        };
        let std_sock = transparent_udp_socket(ip, addr.port(), true)?;
        UdpSocket::from_std(std_sock)
    }

    /// Bind the client-facing reply socket to `orig_dst` so replies leave
    /// with the original destination as source address AND port.
    /// `SO_REUSEADDR` is deliberately absent — a genuine bind conflict
    /// (local service on that address:port) must surface as an error, not
    /// silently share the endpoint.
    pub fn bind_reply_socket(orig_dst: SocketAddr) -> io::Result<UdpSocket> {
        let IpAddr::V4(ip) = orig_dst.ip() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tproxy udp reply destination is IPv4-only",
            ));
        };
        let std_sock = transparent_udp_socket(ip, orig_dst.port(), false)?;
        UdpSocket::from_std(std_sock)
    }

    fn transparent_udp_socket(
        ip: Ipv4Addr,
        port: u16,
        recv_orig_dst: bool,
    ) -> io::Result<std::net::UdpSocket> {
        unsafe {
            let fd = libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // From here on the fd is owned by `sock` — early returns close it.
            let sock = std::net::UdpSocket::from_raw_fd(fd);

            let one: libc::c_int = 1;
            let opts: &[libc::c_int] = if recv_orig_dst {
                &[IP_TRANSPARENT, IP_RECVORIGDSTADDR]
            } else {
                &[IP_TRANSPARENT]
            };
            for &opt in opts {
                if libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    opt,
                    &one as *const _ as *const libc::c_void,
                    mem::size_of_val(&one) as libc::socklen_t,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }

            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(ip.octets()),
                },
                sin_zero: [0; 8],
            };
            if libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of_val(&sa) as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(sock)
        }
    }

    /// Receive one datagram plus its `IP_ORIGDSTADDR` original destination.
    ///
    /// Returns `Ok(None)` when the datagram must be dropped: truncation,
    /// missing/malformed ancillary data, or a non-IPv4 source — never fall
    /// back to treating the listener address as the destination.
    async fn recv_dgram(
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<Option<(usize, SocketAddr, SocketAddr)>> {
        let fd = socket.as_raw_fd();
        loop {
            socket.readable().await?;
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

    /// Raw `recvmsg` on `fd`: payload into `buf`, source address from
    /// `msg_name`, original destination from the `IP_ORIGDSTADDR` cmsg.
    /// Every shape check the issue calls out is enforced here — malformed
    /// metadata means "drop the datagram", never "guess".
    unsafe fn recvmsg_with_orig_dst(
        fd: RawFd,
        buf: &mut [u8],
    ) -> io::Result<Option<(usize, SocketAddr, SocketAddr)>> {
        let mut name: libc::sockaddr_storage = mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buf.len(),
        };
        // Aligned storage: `CMSG_DATA` yields `&sockaddr_in` below, which
        // requires 4-byte alignment a `[u8; N]` stack slot doesn't guarantee.
        let mut cbuf = [0u64; 8]; // 64 bytes, comfortably holds one sockaddr_in cmsg
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_name = (&mut name as *mut libc::sockaddr_storage).cast::<libc::c_void>();
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast::<libc::c_void>();
        // `msg_controllen` is `usize` on glibc but `u32` on musl — `as _`
        // adapts to whichever the target libc declares.
        msg.msg_controllen = mem::size_of_val(&cbuf) as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // A truncated payload is unusable — the tail bytes are lost — and a
        // truncated cmsg could parse a wrong orig_dst; drop both.
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            debug!("tproxy UDP: dropping truncated datagram ({} bytes)", n);
            return Ok(None);
        }

        let Some(client) = sockaddr_in_to_addr(&name, msg.msg_namelen) else {
            debug!("tproxy UDP: dropping datagram with non-IPv4/short source addr");
            return Ok(None);
        };
        // Byte view over the aligned control buffer — no copy.
        let cbuf_bytes =
            std::slice::from_raw_parts(cbuf.as_ptr().cast::<u8>(), mem::size_of_val(&cbuf));
        let Some(orig_dst) = extract_orig_dst(cbuf_bytes, msg.msg_controllen as _) else {
            debug!("tproxy UDP: dropping datagram without IP_ORIGDSTADDR cmsg");
            return Ok(None);
        };

        Ok(Some((n as usize, client, orig_dst)))
    }

    /// Scan a control buffer for the `IP_ORIGDSTADDR` `sockaddr_in`.
    /// `controllen` is the kernel-reported byte count, so a truncated cmsg
    /// never reads out of bounds.
    fn extract_orig_dst(cbuf: &[u8], controllen: usize) -> Option<SocketAddr> {
        let controllen = controllen.min(cbuf.len());
        // `msg_controllen`/`cmsg_len` are `usize` on glibc but `u32` on
        // musl — `as _` casts adapt to whichever type the target libc
        // declares (a concrete `as usize` would trip clippy on the
        // same-type side). Field assignment (not `..zeroed()` in the
        // literal) because musl's `msghdr` has private padding fields.
        let mut hdr0: libc::msghdr = unsafe { mem::zeroed() };
        hdr0.msg_control = cbuf.as_ptr() as *mut libc::c_void;
        hdr0.msg_controllen = controllen as _;
        let fake_msghdr = || hdr0;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&fake_msghdr());
            while !cmsg.is_null() {
                let hdr = &*cmsg;
                if hdr.cmsg_level == libc::SOL_IP
                    && hdr.cmsg_type == IP_ORIGDSTADDR
                    && hdr.cmsg_len >= libc::CMSG_LEN(mem::size_of::<libc::sockaddr_in>() as _) as _
                    && hdr.cmsg_len <= controllen as _
                {
                    let sa = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in);
                    if sa.sin_family as i32 == libc::AF_INET {
                        return Some(sockaddr_to_v4(sa));
                    }
                    // Right level/type but wrong family — malformed.
                    return None;
                }
                cmsg = libc::CMSG_NXTHDR(&fake_msghdr(), cmsg);
            }
            None
        }
    }

    fn sockaddr_in_to_addr(
        name: &libc::sockaddr_storage,
        namelen: libc::socklen_t,
    ) -> Option<SocketAddr> {
        if (namelen as usize) < mem::size_of::<libc::sockaddr_in>() {
            return None;
        }
        let sa = unsafe { &*(name as *const _ as *const libc::sockaddr_in) };
        if sa.sin_family as i32 != libc::AF_INET {
            return None;
        }
        Some(sockaddr_to_v4(sa))
    }

    fn sockaddr_to_v4(sa: &libc::sockaddr_in) -> SocketAddr {
        // `s_addr`'s memory bytes are network order: on little-endian hosts
        // the u32 *value* is octet-reversed, so go through `from_be` (the
        // same convention `orig_dest.rs` uses for SO_ORIGINAL_DST).
        let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
        SocketAddr::new(IpAddr::V4(ip), u16::from_be(sa.sin_port))
    }

    /// Whether a kernel-recovered `orig_dst` is a plausible client
    /// destination. Self-targeting: a datagram aimed at the listener's
    /// own endpoint (stray direct traffic, or a deployer who also
    /// steers OUTPUT) would otherwise self-reinject — the outbound
    /// write lands back in this socket and each round spawns a fresh
    /// flow until the cap. On a wildcard listen we cannot enumerate
    /// local addresses, so ANY orig_dst sharing the listener port is
    /// treated as self — a conservative over-block: a remote UDP
    /// service on the same port number is unreachable through a
    /// `0.0.0.0`-bound `udp: true` listener. Port 0, unspecified,
    /// loopback, multicast, and broadcast can never be a real
    /// LAN-client destination either.
    fn is_safe_orig_dst(orig_dst: SocketAddr, local_addr: SocketAddr) -> bool {
        let dst_ip = orig_dst.ip();
        let self_target = orig_dst.port() == local_addr.port()
            && (orig_dst == local_addr || local_addr.ip().is_unspecified());
        !(orig_dst.port() == 0
            || self_target
            || dst_ip.is_unspecified()
            || dst_ip.is_loopback()
            || dst_ip.is_multicast()
            || dst_ip == IpAddr::V4(Ipv4Addr::BROADCAST))
    }

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

    /// The UDP receive loop: socket → flow dispatch. Runs until the task
    /// is aborted — socket errors retry with `ErrorBackoff` rather than
    /// terminate, since the reachable failures are transient `ENOBUFS`/
    /// `ENOMEM` pressure and a permanent degrade behind one error would
    /// be silent (the spawn discards the JoinHandle); a persistent
    /// failure still surfaces via the backoff-rate-limited `warn!`.
    /// Idle-flow eviction is lazy (channel-close observed on the next
    /// datagram, or the periodic sweep).
    pub async fn run_udp(
        tunnel: Tunnel,
        socket: UdpSocket,
        udp_timeout: Duration,
        max_flows: usize,
        in_name: String,
        in_port: u16,
    ) {
        let (reply_tx, reply_rx) = mpsc::channel::<ReplyMsg>(REPLY_QUEUE);
        let _dispatcher = AbortOnDrop(tokio::spawn(reply_dispatch(reply_rx)).abort_handle());

        let mut dispatch =
            FlowDispatch::new(reply_tx, max_flows, udp_timeout, in_name.clone(), in_port);
        let mut buf = vec![0u8; DATAGRAM_BUF];
        let local_addr = socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), in_port));
        // Retry-and-backoff rationale: see `run_udp`'s doc comment.
        let mut recv_backoff = meow_common::ErrorBackoff::new();

        loop {
            let (n, client, orig_dst) = match recv_dgram(&socket, &mut buf).await {
                Ok(Some(v)) => {
                    recv_backoff.succeeded();
                    v
                }
                // A dropped datagram is not proof of socket health — the
                // delay stays elevated while errors still interleave.
                Ok(None) => continue,
                Err(e) => {
                    if recv_backoff.failed(&e).await {
                        warn!("tproxy UDP '{in_name}' recv error: {e}");
                    } else {
                        debug!("tproxy UDP '{in_name}' recv error: {e}");
                    }
                    continue;
                }
            };
            // Sanity-guard the recovered destination before it ever reaches
            // a flow — see `is_safe_orig_dst`.
            if !is_safe_orig_dst(orig_dst, local_addr) {
                debug!("tproxy UDP: dropping datagram to unsafe orig_dst {orig_dst}");
                continue;
            }
            // Zero-length datagrams are legal UDP — forwarded like any other.
            if !dispatch.dispatch(&tunnel, buf[..n].to_vec(), client, orig_dst) {
                debug!("tproxy UDP: dropped {client} -> {orig_dst} (flow/queue bound)");
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
                ),
                reply_rx,
            )
        }

        fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
            SocketAddr::from(([a, b, c, d], port))
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

        /// Lay out one `cmsghdr` + `sockaddr_in` exactly as the kernel does
        /// for `IP_ORIGDSTADDR`. The backing store is `u64` words so the
        /// header's `usize` fields stay naturally aligned — a `Vec<u8>`
        /// would not guarantee that.
        fn build_cmsg(
            level: libc::c_int,
            ty: libc::c_int,
            cmsg_len: usize,
            family: libc::sa_family_t,
            ip: [u8; 4],
            port: u16,
        ) -> Vec<u64> {
            let sa_len = mem::size_of::<libc::sockaddr_in>();
            let space: usize = unsafe { libc::CMSG_SPACE(sa_len as _) } as _;
            let mut words = vec![0u64; space.div_ceil(8)];
            let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
            sa.sin_family = family;
            sa.sin_port = port.to_be();
            // Memory bytes must be the network-order octets.
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(ip),
            };
            unsafe {
                let hdr = words.as_mut_ptr() as *mut libc::cmsghdr;
                std::ptr::write(
                    hdr,
                    libc::cmsghdr {
                        cmsg_len,
                        cmsg_level: level,
                        cmsg_type: ty,
                    },
                );
                std::ptr::copy_nonoverlapping(
                    &sa as *const _ as *const u8,
                    libc::CMSG_DATA(hdr),
                    sa_len,
                );
            }
            words
        }

        fn cmsg_bytes(words: &[u64]) -> &[u8] {
            unsafe { std::slice::from_raw_parts(words.as_ptr() as *const u8, words.len() * 8) }
        }

        /// A well-formed `IP_ORIGDSTADDR` message recovers the embedded
        /// IPv4 address/port.
        #[test]
        fn extract_orig_dst_parses_valid_ipv4_cmsg() {
            let sa_len = mem::size_of::<libc::sockaddr_in>();
            let (len, space) = unsafe {
                (
                    libc::CMSG_LEN(sa_len as _) as _,
                    libc::CMSG_SPACE(sa_len as _) as _,
                )
            };
            let words = build_cmsg(
                libc::SOL_IP,
                IP_ORIGDSTADDR,
                len,
                libc::AF_INET as _,
                [203, 0, 113, 9],
                5353,
            );
            assert_eq!(
                extract_orig_dst(cmsg_bytes(&words), space),
                Some(v4(203, 0, 113, 9, 5353))
            );
        }

        /// Malformed or mismatched control data must be rejected, never
        /// guessed — the parser fails closed to `None`.
        #[test]
        fn extract_orig_dst_rejects_malformed() {
            let sa_len = mem::size_of::<libc::sockaddr_in>();
            let (good_len, space) = unsafe {
                (
                    libc::CMSG_LEN(sa_len as _) as _,
                    libc::CMSG_SPACE(sa_len as _) as _,
                )
            };

            // Right level/type but a non-IPv4 payload.
            let words = build_cmsg(
                libc::SOL_IP,
                IP_ORIGDSTADDR,
                good_len,
                libc::AF_INET6 as _,
                [203, 0, 113, 9],
                53,
            );
            assert_eq!(extract_orig_dst(cmsg_bytes(&words), space), None);

            // cmsg_len too small to hold a sockaddr_in — skipped.
            let words = build_cmsg(
                libc::SOL_IP,
                IP_ORIGDSTADDR,
                good_len - 4,
                libc::AF_INET as _,
                [203, 0, 113, 9],
                53,
            );
            assert_eq!(extract_orig_dst(cmsg_bytes(&words), space), None);

            // A different ancillary type is skipped, not misread.
            let words = build_cmsg(
                libc::SOL_IP,
                libc::IP_PKTINFO,
                good_len,
                libc::AF_INET as _,
                [203, 0, 113, 9],
                53,
            );
            assert_eq!(extract_orig_dst(cmsg_bytes(&words), space), None);

            // controllen shorter than one cmsghdr — FIRSTHDR yields null.
            let words = build_cmsg(
                libc::SOL_IP,
                IP_ORIGDSTADDR,
                good_len,
                libc::AF_INET as _,
                [203, 0, 113, 9],
                53,
            );
            let buf = cmsg_bytes(&words);
            assert_eq!(
                extract_orig_dst(buf, mem::size_of::<libc::cmsghdr>() - 1),
                None
            );
        }

        /// The recovered-destination sanity filter: plausible LAN targets
        /// pass; self-target, port 0, and non-unicast addresses are rejected.
        #[test]
        fn is_safe_orig_dst_filters() {
            let local = "127.0.0.1:7895".parse::<SocketAddr>().unwrap();
            let wild = "0.0.0.0:7895".parse::<SocketAddr>().unwrap();
            let ok = "203.0.113.9:443".parse::<SocketAddr>().unwrap();
            assert!(is_safe_orig_dst(ok, local));
            assert!(is_safe_orig_dst(ok, wild));
            // Self-target: exact endpoint, and any same-port dst on wildcard.
            assert!(!is_safe_orig_dst(local, local));
            assert!(!is_safe_orig_dst("203.0.113.9:7895".parse().unwrap(), wild));
            // Different-port dst on a specific bind is NOT self (but this
            // particular dst is loopback, so still filtered overall).
            assert!(!is_safe_orig_dst("127.0.0.1:80".parse().unwrap(), local));
            // Port 0 / unspecified / multicast / broadcast.
            for bad in [
                "203.0.113.9:0",
                "0.0.0.0:53",
                "224.0.0.1:53",
                "255.255.255.255:53",
            ] {
                assert!(!is_safe_orig_dst(bad.parse().unwrap(), wild), "{bad}");
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{bind_transparent, run_udp};

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

    struct RecordingConn {
        writes: WriteLog,
        wrote: Arc<Notify>,
        closed: Arc<AtomicBool>,
        replies: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    #[async_trait]
    impl ProxyPacketConn for RecordingConn {
        async fn read_packet(&self, buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            let mut rx = self.replies.lock().await;
            match rx.recv().await {
                Some(data) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, "0.0.0.0:0".parse().unwrap()))
                }
                // The test stopped scripting replies — park until the flow
                // aborts this reader, never spin into an error storm.
                None => std::future::pending().await,
            }
        }
        async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> MeowResult<usize> {
            self.writes.lock().unwrap().push((buf.to_vec(), *addr));
            self.wrote.notify_one();
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
    }

    impl RecordingProxy {
        pub(super) fn new(fail_dial: bool) -> Arc<Self> {
            Arc::new(Self {
                dials: AtomicUsize::new(0),
                conns: Mutex::new(Vec::new()),
                meta_log: Mutex::new(Vec::new()),
                health: ProxyHealth::new(),
                fail_dial,
            })
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

    /// A `REJECT` verdict must route to the REJECT-named adapter — never a
    /// silent DIRECT fallback (the issue's hard requirement). The map key
    /// is what `resolve_proxy` looks up, so the recording stub stands in
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
}
