//! UoT v2 association for the `type: anytls` inbound — sing-box
//! udp-over-tcp carried on a normal AnyTLS logical stream whose SOCKS
//! destination is exactly `sp.v2.udp-over-tcp.arpa:0`.
//!
//! Wire contract (`meow_anytls::uot` owns the codec): once per stream,
//! `isConnect u8 | <socks addr>`; then per packet —
//! Connect: `len u16be | payload`, one fixed destination;
//! Bind: `<uot addr> | len u16be | payload`, a destination per packet
//! (the uot family table `0x00/0x01/0x02`, NOT the SOCKS5 one).
//!
//! Every destination gets a bounded session routed like SOCKS5-UDP's:
//! `pre_handle_metadata` → `pre_resolve` → `resolve_udp_dst` → counted
//! `TunnelInner::dial_udp`, with the rule snapshot pinned across the
//! dial, an outbound-binding flush watch, LRU-idle eviction and a
//! bounded per-session packet queue. Replies write back onto the same
//! logical stream through a single ordered writer — the UoT stream is
//! the association's whole lifetime scope; when it dies every session
//! is torn down with it.

use anytls_rs::session::StreamIo;
use anytls_rs::uot::{self, UotAddr};
use bytes::Bytes;
use meow_common::atomic::{AtomicU, Uint};
use meow_common::{Metadata, ProxyPacketConn};
use meow_tunnel::{MatchedRule, ResolvedTarget, TunnelInner, UsingProxy};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Bounded session table per UoT stream — a Bind association may name a
/// fresh destination per packet, so the table must not grow without
/// limit (saturating targets evict the least-recently-active session,
/// the same policy the SOCKS5 NAT applies globally).
const MAX_UOT_SESSIONS: usize = 128;
/// Packets queued per session while its outbound conn is still
/// establishing (resolve + route + `dial_udp`); overflow drops the
/// datagram — the same `SESSION_QUEUE` bound SOCKS5-UDP uses.
const SESSION_QUEUE: usize = 64;
/// Shared byte ceiling across every session's ingress queue on one UoT
/// stream. The per-queue count alone bounds 128 × 64 datagrams of up to
/// 64 KiB — ~512 MiB parked against a stalled writer; the byte meter
/// keeps the association's whole backlog proportional.
const SESSION_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// Session-idle sweep period (the SOCKS5 sweeper's cadence). Idle
/// eviction runs ONLY on this timer — an O(table) scan per packet is
/// needless work on every datagram (F14).
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Session-table key: canonicalized `ip:port` for address-form targets,
/// `host:port` for domain-form (lowercased — `Metadata::lower_host`
/// already ran), so a target named two ways never merges flows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum UotKey {
    Addr(SocketAddr),
    Host(SmolStr, u16),
}

impl UotKey {
    fn of(addr: &UotAddr) -> Self {
        match addr {
            UotAddr::Ip(sa) => UotKey::Addr(*sa),
            UotAddr::Domain(host, port) => UotKey::Host(Metadata::lower_host(host), *port),
        }
    }
}

/// How this association encodes a reply onto the logical stream —
/// Connect replies carry only `len | payload`; Bind replies prepend the
/// real source in uot address form.
#[derive(Debug, Clone, Copy)]
enum ReplyForm {
    Connect,
    Bind,
}

/// One queued datagram: the payload plus its share of the association's
/// byte meter, released on Drop whatever path consumed it.
struct QueuedPacket {
    bytes: Bytes,
    meter: Arc<AtomicUsize>,
}

impl Drop for QueuedPacket {
    fn drop(&mut self) {
        self.meter.fetch_sub(self.bytes.len(), Ordering::Relaxed);
    }
}

/// Millisecond timestamps stored in the platform atomic — truncates to
/// `Uint`'s width, and every comparison uses `wrapping_sub` so the 32-bit
/// fallback's ~49.7-day wrap stays correct (see `meow_common::atomic`).
fn now_ms() -> Uint {
    crate::monotonic_ms() as Uint
}

fn idle_ms() -> Uint {
    meow_tunnel::udp::DEFAULT_UDP_IDLE.as_millis() as Uint
}

fn touch_activity(stamp: &AtomicU) {
    stamp.store(now_ms(), Ordering::Release);
}

/// Sample `stamp` BEFORE reading the monotonic clock so a concurrent
/// `touch_activity` can never make `last` newer than `now` and wrap the
/// subtraction into `Uint::MAX` (N03).
fn elapsed_since(stamp: &AtomicU) -> Uint {
    let last = stamp.load(Ordering::Acquire);
    now_ms().wrapping_sub(last)
}

/// One live outbound UDP session: the bounded ingress queue plus the
/// activity/deadness bookkeeping the sweeper and teardown need.
struct UotSession {
    tx: mpsc::Sender<QueuedPacket>,
    last_activity: Arc<AtomicU>,
    /// Set by eviction/teardown so the session task's flush-watch
    /// select exits even between datagrams.
    dead: Arc<AtomicBool>,
    /// Session task abort — teardown must not wait for the idle bound.
    task: tokio::task::AbortHandle,
}

/// The listener-side context stamped onto every session's `Metadata` —
/// grouped so the spawn path isn't a positional-argument list (F15).
struct UotFlowCtx<'a> {
    peer: SocketAddr,
    in_name: &'a str,
    in_port: u16,
    user: &'a SmolStr,
    route_override: Option<&'a meow_common::InboundRouteOverride>,
}

/// `Metadata` for one UoT target — `Network::Udp`, the authenticated
/// user and the route override stamped exactly like the TCP path.
fn build_udp_metadata(
    dst_ip: Option<std::net::IpAddr>,
    host: SmolStr,
    dst_port: u16,
    ctx: &UotFlowCtx<'_>,
) -> (Metadata, Option<SocketAddr>) {
    let claimed = dst_ip
        .or_else(|| meow_common::metadata_ip_literal(&host))
        .map(|ip| SocketAddr::new(ip.to_canonical(), dst_port));
    let mut metadata = Metadata {
        network: meow_common::Network::Udp,
        conn_type: meow_common::ConnType::Anytls,
        src_ip: Some(ctx.peer.ip()),
        src_port: ctx.peer.port(),
        dst_ip,
        dst_port,
        host,
        in_name: ctx.in_name.into(),
        in_port: ctx.in_port,
        in_user: Some(ctx.user.clone()),
        ..Default::default()
    };
    if let Some(ov) = ctx.route_override {
        ov.apply(&mut metadata);
    }
    (metadata, claimed)
}

/// Drive one UoT v2 association until the stream ends. `io` has already
/// consumed the SOCKS destination (the v2 marker) and the SynAck the
/// caller queued; the UoT request line is read here.
pub(crate) async fn run_uot_stream(
    mut io: StreamIo,
    inner: Arc<TunnelInner>,
    flow: &crate::anytls::FlowCtx,
) {
    let peer = flow.peer;
    let (is_connect, request_dest) = match tokio::time::timeout(
        crate::DEFAULT_HANDSHAKE_TIMEOUT,
        uot::read_uot_request(&mut io),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            if !uot::is_eof(&e) {
                debug!("anytls uot stream {}: bad request: {e}", io.id());
            }
            return;
        }
        Err(_) => {
            debug!("anytls uot stream {}: request read timed out", io.id());
            return;
        }
    };
    let reply_form = if is_connect {
        ReplyForm::Connect
    } else {
        ReplyForm::Bind
    };
    debug!(
        "anytls uot stream {} from {peer}: {} association",
        io.id(),
        if is_connect { "connect" } else { "bind" }
    );

    // Single ordered writer: session reply tasks enqueue encoded UoT
    // packets here so frame interleaving is impossible. Bounded — a
    // stalled stream must not let replies pile up unbounded (the
    // session queue's budget already covers the datagrams themselves).
    // `Bytes` moves the codec's output straight to the writer — no copy.
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(SESSION_QUEUE * 2);
    let writer = {
        let mut w = io.clone();
        tokio::spawn(async move {
            while let Some(pkt) = out_rx.recv().await {
                if w.write_all(&pkt).await.is_err() {
                    break;
                }
            }
            let _ = w.flush().await;
            w
        })
    };

    let sessions: Arc<parking_lot::Mutex<HashMap<UotKey, UotSession>>> =
        Arc::new(parking_lot::Mutex::new(HashMap::new()));
    // Association-wide datagram-byte meter — every session ingress
    // queue's `QueuedPacket` charges and releases here.
    let pending_bytes = Arc::new(AtomicUsize::new(0));
    let sweeper = tokio::spawn({
        let sessions = Arc::clone(&sessions);
        async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            tick.tick().await; // first tick fires immediately — skip it
            loop {
                tick.tick().await;
                let idle = idle_ms();
                let mut table = sessions.lock();
                table.retain(|_, s| {
                    if elapsed_since(&s.last_activity) < idle {
                        return true;
                    }
                    s.dead.store(true, Ordering::Relaxed);
                    s.task.abort();
                    false
                });
            }
        }
    });
    // The association OWNS its spawned tasks (N04): dropping this guard
    // — the normal tail below OR a cancelled `run_uot_stream` — kills
    // every session task (which in turn drops their in-scope reply arms
    // and conn guards), the sweeper, and the ordered writer. Nothing
    // may outlive the association detached.
    let mut guard = AssociationGuard {
        sessions: Arc::clone(&sessions),
        writer,
        sweeper,
    };

    // Connect format fixes the association's one destination up front —
    // every datagram goes to it; its own request address is the only
    // target ever created. Bind's request address is a layout-only
    // placeholder (already consumed) — no destination exists to key.
    let connect_key = if is_connect {
        request_dest.as_ref().map(UotKey::of)
    } else {
        None
    };
    let ctx = UotFlowCtx {
        peer: flow.peer,
        in_name: &flow.in_name,
        in_port: flow.in_port,
        user: &flow.user,
        route_override: flow.route_override.as_ref(),
    };

    // Per-association read loop: decode packets, dispatch to (possibly
    // new) per-target sessions. `sessions` is only mutated here plus the
    // sweeper — the lock hand-off is momentary both ways.
    let read_result: Result<(), ()> = async {
        loop {
            let (key, payload) = if is_connect {
                let payload = match uot::read_uot_packet(&mut io).await {
                    Ok(p) => p,
                    Err(e) => {
                        if !uot::is_eof(&e) {
                            debug!("anytls uot stream {}: packet read: {e}", io.id());
                        }
                        return Err(());
                    }
                };
                (connect_key.clone().expect("connect key set"), payload)
            } else {
                // Bind: `<uot addr> | len | payload`. A bad address ends
                // the association — the stream has no resync boundary.
                let addr = match uot::read_uot_addr(&mut io).await {
                    Ok(a) => a,
                    Err(e) => {
                        if !uot::is_eof(&e) {
                            debug!("anytls uot stream {}: addr read: {e}", io.id());
                        }
                        return Err(());
                    }
                };
                let payload = match uot::read_uot_packet(&mut io).await {
                    Ok(p) => p,
                    Err(e) => {
                        if !uot::is_eof(&e) {
                            debug!("anytls uot stream {}: packet read: {e}", io.id());
                        }
                        return Err(());
                    }
                };
                (UotKey::of(&addr), payload)
            };

            // The target for a (possibly new) session — `dest` is the
            // wire address; domain targets resolve inside the session
            // task so a slow lookup cannot stall this read loop.
            let dest_for_new = if is_connect {
                request_dest.clone().expect("connect carries a destination")
            } else {
                match &key {
                    UotKey::Addr(sa) => UotAddr::Ip(*sa),
                    UotKey::Host(host, port) => UotAddr::Domain(host.to_string(), *port),
                }
            };

            // Deliver or spawn.
            let deliver = {
                let table = sessions.lock();
                table.get(&key).map(|s| {
                    touch_activity(&s.last_activity);
                    s.tx.clone()
                })
            };
            let tx = match deliver {
                Some(tx) => tx,
                None => {
                    // Cap: evict the least-recently-active session before
                    // spawning a new one — same LRU policy the sweeper
                    // applies on a timer. Find and remove under one lock.
                    let evicted = {
                        let mut table = sessions.lock();
                        if table.len() >= MAX_UOT_SESSIONS {
                            let oldest = table
                                .iter()
                                .max_by_key(|(_, s)| elapsed_since(&s.last_activity))
                                .map(|(k, _)| k.clone());
                            oldest.and_then(|k| table.remove(&k))
                        } else {
                            None
                        }
                    };
                    if let Some(old) = evicted {
                        old.dead.store(true, Ordering::Relaxed);
                        old.task.abort();
                    }
                    let session = spawn_uot_session(
                        Arc::clone(&inner),
                        &dest_for_new,
                        &ctx,
                        out_tx.clone(),
                        reply_form,
                    );
                    let tx = session.tx.clone();
                    sessions.lock().insert(key.clone(), session);
                    tx
                }
            };

            // Charge the shared byte meter BEFORE enqueueing. Only this
            // read loop mutates it upward, so check-then-add is
            // race-free; `QueuedPacket::Drop` releases it on pop,
            // eviction, or teardown.
            let new_pending = pending_bytes.load(Ordering::Relaxed) + payload.len();
            if new_pending > SESSION_QUEUE_BYTES {
                debug!(
                    "anytls uot stream {}: queued byte budget exhausted, dropping datagram",
                    io.id()
                );
                continue;
            }
            pending_bytes.fetch_add(payload.len(), Ordering::Relaxed);
            match tx.try_send(QueuedPacket {
                bytes: payload,
                meter: Arc::clone(&pending_bytes),
            }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(queued)) => {
                    // Queue saturated — drop this datagram (UDP semantics:
                    // never block the stream for one target's backlog).
                    drop(queued);
                    debug!(
                        "anytls uot stream {}: session queue full, dropping datagram",
                        io.id()
                    );
                }
                Err(mpsc::error::TrySendError::Closed(queued)) => {
                    // Session died between lookup and send — remove the
                    // corpse so the next packet respawns it.
                    drop(queued);
                    sessions.lock().remove(&key);
                }
            }
        }
    }
    .await;

    let _ = read_result;
    // Teardown: kill every session, stop accepting replies, then drain
    // the writer so the last replies still reach the wire before the
    // stream's FIN. The guard's Drop repeats the aborts — cheap and
    // idempotent — and covers the cancelled/cancel arm with no code path.
    {
        let mut table = guard.sessions.lock();
        for (_, s) in table.drain() {
            s.dead.store(true, Ordering::Relaxed);
            s.task.abort();
        }
    }
    guard.sweeper.abort();
    drop(out_tx);
    if let Ok(w) = (&mut guard.writer).await {
        w.close();
    }
}

/// The association's owned tasks — ordered writer, idle sweeper and the
/// session table (N04). `run_uot_stream`'s cleanup tail used to do this
/// only on the normal path; a cancelled association would detach the
/// writer and leave the sweeper scanning an emptied table forever.
/// Dropping the guard aborts every owned task — the session tasks'
/// in-scope reply arms and conn guards die with them.
struct AssociationGuard {
    sessions: Arc<parking_lot::Mutex<HashMap<UotKey, UotSession>>>,
    writer: tokio::task::JoinHandle<StreamIo>,
    sweeper: tokio::task::JoinHandle<()>,
}

impl Drop for AssociationGuard {
    fn drop(&mut self) {
        for (_, s) in self.sessions.lock().drain() {
            s.dead.store(true, Ordering::Relaxed);
            s.task.abort();
        }
        self.sweeper.abort();
        self.writer.abort();
    }
}

/// Spawn one destination's outbound session: resolve → route →
/// `dial_udp`, then the packet writer and the reply reader. Mirrors
/// `socks5_udp::run_session` — same metadata pipeline, same flush watch,
/// same `dial_udp` counting path.
fn spawn_uot_session(
    inner: Arc<TunnelInner>,
    dest: &UotAddr,
    ctx: &UotFlowCtx<'_>,
    out_tx: mpsc::Sender<Bytes>,
    reply_form: ReplyForm,
) -> UotSession {
    let (tx, rx) = mpsc::channel::<QueuedPacket>(SESSION_QUEUE);
    let last_activity = Arc::new(AtomicU::new(now_ms()));
    let dead = Arc::new(AtomicBool::new(false));

    let (dst_ip, host, dst_port) = match dest {
        UotAddr::Ip(sa) => (Some(sa.ip()), SmolStr::default(), sa.port()),
        UotAddr::Domain(h, p) => (None, Metadata::lower_host(h), *p),
    };
    let (metadata, claimed) = build_udp_metadata(dst_ip, host, dst_port, ctx);

    let task = tokio::spawn(run_uot_session(
        inner,
        metadata,
        claimed,
        UotSessionIo {
            rx,
            out_tx,
            reply_form,
            last_activity: Arc::clone(&last_activity),
            dead: Arc::clone(&dead),
        },
    ));

    UotSession {
        tx,
        last_activity,
        dead,
        task: task.abort_handle(),
    }
}

/// The halves a UoT session task owns — its datagram queue, the
/// association's ordered writer, its liveness stamps — grouped so the
/// task signature isn't a positional-argument list.
struct UotSessionIo {
    rx: mpsc::Receiver<QueuedPacket>,
    out_tx: mpsc::Sender<Bytes>,
    reply_form: ReplyForm,
    last_activity: Arc<AtomicU>,
    dead: Arc<AtomicBool>,
}

/// The session task itself: metadata pipeline (pre-handle, pre-resolve,
/// route) → `dial_udp` → writer + reply loops with the outbound-binding
/// flush watch — the SOCKS5-UDP session task's shape on a UoT stream.
async fn run_uot_session(
    inner: Arc<TunnelInner>,
    mut metadata: Metadata,
    claimed: Option<SocketAddr>,
    io: UotSessionIo,
) {
    let UotSessionIo {
        mut rx,
        out_tx,
        reply_form,
        last_activity,
        dead,
    } = io;
    struct DeadOnExit(Arc<AtomicBool>);
    impl Drop for DeadOnExit {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let _dead_guard = DeadOnExit(Arc::clone(&dead));
    let mut flush = inner.udp_flush_watch();

    let outcome = async {
        if matches!(
            inner.pre_handle_metadata(&mut metadata),
            meow_tunnel::PreHandleVerdict::Drop
        ) {
            return Err("unmapped fake-ip destination".into());
        }
        inner.pre_resolve(&mut metadata).await;
        let probed = inner.resolve_udp_dst(&mut metadata).await;
        let resolved = match probed {
            Some(target) => Some(target),
            None => inner.resolve_proxy_flow(&mut metadata).await,
        };
        let Some(ResolvedTarget {
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
        let dst_addr = if proxy.adapter_type() == meow_common::AdapterType::Dns {
            metadata.dns_udp_dst(claimed)
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
            "UDP {} --> {} match {} using {}",
            metadata.source_address(),
            metadata.remote_address(),
            MatchedRule::new(&rule_name, &rule_payload, proxy.name()),
            UsingProxy::new(proxy.as_ref(), &metadata)
        );
        let conn: Arc<dyn ProxyPacketConn> = Arc::from(
            inner
                .dial_udp(proxy.as_ref(), &metadata)
                .await
                .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?,
        );
        Ok((conn, dst_addr))
    }
    .await;

    let (conn, dst_addr) = match outcome {
        Ok(v) => v,
        Err(e) => {
            debug!("anytls uot session to {}: {e}", metadata.remote_address());
            return;
        }
    };

    // Reply reader, writer, flush watch and idle deadline — ALL polled
    // as plain futures inside THIS task (N01/F08): whichever ends first
    // retires the session, and a task abort drops BOTH arms plus the
    // conn guard — no JoinHandle survives to double-await or detach
    // holding the UDP conn (N04).
    let _conn_guard = ConnGuard(Arc::clone(&conn));
    let mut rbuf = vec![0u8; 65535];
    let reply = async {
        while let Ok((m, src)) = conn.read_packet(&mut rbuf).await {
            let pkt = match reply_form {
                ReplyForm::Connect => uot::encode_uot_packet_simple(&rbuf[..m]),
                ReplyForm::Bind => uot::encode_uot_packet_from(&rbuf[..m], &src),
            };
            let Ok(pkt) = pkt else { break };
            if out_tx.send(pkt).await.is_err() {
                break;
            }
            touch_activity(&last_activity);
        }
    };
    tokio::pin!(reply);
    let writer = async {
        loop {
            // The idle arm derives from the SHARED activity stamp — a
            // receive-only-but-active target's replies refresh it the
            // same as sends do (N03).
            let elapsed = elapsed_since(&last_activity);
            let idle_left = idle_ms().saturating_sub(elapsed);
            tokio::select! {
                biased;
                _ = flush.flushed() => {
                    debug!("anytls uot session to {dst_addr}: outbound binding flushed; session retires");
                    break;
                }
                msg = rx.recv() => match msg {
                    None => break,
                    Some(packet) => {
                        let payload = &packet.bytes;
                        // The write itself races the flush watch — a
                        // suspended `write_packet` must not starve a
                        // binding teardown (F08).
                        let res = tokio::select! {
                            biased;
                            _ = flush.flushed() => {
                                debug!("anytls uot session to {dst_addr}: flushed mid-write; session retires");
                                break;
                            }
                            res = conn.write_packet(payload, &dst_addr) => res,
                        };
                        match res {
                            Ok(n) if n == payload.len() => {
                                touch_activity(&last_activity);
                            }
                            Ok(n) => {
                                debug!(
                                    "anytls uot session to {dst_addr}: short upstream write {n}/{}; session retires",
                                    payload.len()
                                );
                                break;
                            }
                            Err(e) => {
                                debug!("anytls uot session to {dst_addr}: upstream write: {e}; session retires");
                                break;
                            }
                        }
                    }
                },
                _ = tokio::time::sleep(Duration::from_millis(idle_left as u64)) => {
                    if elapsed_since(&last_activity) < idle_ms() {
                        continue;
                    }
                    break;
                }
            }
        }
    };
    tokio::pin!(writer);
    tokio::select! {
        _ = &mut reply => {}
        _ = &mut writer => {}
    }
    // `_conn_guard` drops here — or earlier on abort — closing the UDP
    // conn; both direction futures drop with their `rx`/`out_tx` refs.
}

/// RAII owner for a UoT session's `ProxyPacketConn`: session teardown —
/// normal return or task abort — closes the conn exactly once, never
/// leaving a dialed UDP socket parked on a dead task (N04/F08).
struct ConnGuard(Arc<dyn ProxyPacketConn>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize as StdAtomicUsize;

    /// Packet conn reporting `close()` through a shared probe; each
    /// direction's behavior is chosen at construction:
    ///  - `Dying`: read fails instantly, write parks — the N01 shape.
    ///    The reply arm terminating FIRST used to leave `run_uot_session`
    ///    awaiting an already-consumed reply `JoinHandle` (panic, and an
    ///    abort under `panic = "abort"`).
    ///  - `Parked`: both directions park — the N04 shape; aborting the
    ///    session task mid-life must still run `close`.
    struct ProbeConn {
        closed: AtomicBool,
        probe: Arc<AtomicBool>,
        reply_dies: bool,
    }

    #[async_trait::async_trait]
    impl ProxyPacketConn for ProbeConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            if self.reply_dies {
                return Err(meow_common::MeowError::Proxy("upstream closed".into()));
            }
            std::future::pending().await
        }
        async fn write_packet(
            &self,
            _buf: &[u8],
            _addr: &SocketAddr,
        ) -> meow_common::Result<usize> {
            std::future::pending().await
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
        fn close(&self) -> meow_common::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            self.probe.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// One proxy whose every `dial_udp` hands back a fresh `ProbeConn`.
    struct ProbeUdpProxy {
        reply_dies: bool,
        probe: Arc<AtomicBool>,
        dials: StdAtomicUsize,
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for ProbeUdpProxy {
        fn name(&self) -> &str {
            "probe-udp"
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
        async fn dial_tcp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            Err(meow_common::MeowError::NotSupported("no tcp".into()))
        }
        async fn dial_udp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
            self.dials.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(ProbeConn {
                closed: AtomicBool::new(false),
                probe: Arc::clone(&self.probe),
                reply_dies: self.reply_dies,
            }))
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for ProbeUdpProxy {
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
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            Vec::new()
        }
    }

    fn tunnel_to(proxy: &Arc<ProbeUdpProxy>) -> meow_tunnel::Tunnel {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        let tunnel = meow_tunnel::Tunnel::new(resolver);
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        let mut proxies = res.proxies;
        proxies.insert(
            "probe-udp".into(),
            Arc::clone(proxy) as Arc<dyn meow_common::Proxy>,
        );
        tunnel.update_proxies(proxies, res.dialer_registry);
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "probe-udp",
        ))]);
        tunnel
    }

    fn udp_metadata() -> Metadata {
        Metadata {
            network: meow_common::Network::Udp,
            conn_type: meow_common::ConnType::Anytls,
            dst_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))),
            dst_port: 443,
            ..Default::default()
        }
    }

    fn harness(reply_dies: bool) -> (Arc<ProbeUdpProxy>, meow_tunnel::Tunnel, Arc<AtomicBool>) {
        let probe = Arc::new(AtomicBool::new(false));
        let proxy = Arc::new(ProbeUdpProxy {
            reply_dies,
            probe: Arc::clone(&probe),
            dials: StdAtomicUsize::new(0),
            health: meow_common::ProxyHealth::new(),
        });
        let tunnel = tunnel_to(&proxy);
        (proxy, tunnel, probe)
    }

    /// N01 regression: reply-side termination must retire the session
    /// cleanly — the directions are in-scope futures, so the winner is
    /// never awaited a second time — and the conn guard must still
    /// close the upstream socket.
    #[tokio::test]
    async fn reply_side_death_retires_session_and_closes_conn() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (_proxy, tunnel, probe) = harness(true);
            let (_tx, rx) = mpsc::channel::<QueuedPacket>(4);
            let (out_tx, _out_rx) = mpsc::channel::<Bytes>(4);
            let dead = Arc::new(AtomicBool::new(false));
            run_uot_session(
                Arc::clone(tunnel.inner()),
                udp_metadata(),
                None,
                UotSessionIo {
                    rx,
                    out_tx,
                    reply_form: ReplyForm::Connect,
                    last_activity: Arc::new(AtomicU::new(now_ms())),
                    dead: Arc::clone(&dead),
                },
            )
            .await;
            assert!(dead.load(Ordering::SeqCst), "dead flag not set");
            assert!(probe.load(Ordering::SeqCst), "conn never closed");
        })
        .await
        .expect("run_uot_session did not retire on reply death");
    }

    /// N04: a session task aborted mid-life must still close its conn —
    /// the guard's Drop covers cancellation, not only the normal tail.
    #[tokio::test]
    async fn aborted_session_task_still_closes_conn() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (proxy, tunnel, probe) = harness(false);
            let (_tx, rx) = mpsc::channel::<QueuedPacket>(4);
            let (out_tx, _out_rx) = mpsc::channel::<Bytes>(4);
            let dead = Arc::new(AtomicBool::new(false));
            let task = tokio::spawn(run_uot_session(
                Arc::clone(tunnel.inner()),
                udp_metadata(),
                None,
                UotSessionIo {
                    rx,
                    out_tx,
                    reply_form: ReplyForm::Connect,
                    last_activity: Arc::new(AtomicU::new(now_ms())),
                    dead,
                },
            ));
            // Wait until the session actually dialed (conn exists to
            // close), then abort mid-life.
            let dialed = tokio::time::timeout(Duration::from_secs(2), async {
                while proxy.dials.load(Ordering::Relaxed) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            assert!(dialed.is_ok(), "session never dialed");
            task.abort();
            let _ = task.await;
            assert!(
                probe.load(Ordering::SeqCst),
                "aborted session left its conn open"
            );
        })
        .await
        .expect("abort test timed out");
    }
}
