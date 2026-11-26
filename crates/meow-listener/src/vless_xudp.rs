//! XUDP association driver for the VLESS Vision server inbound — the
//! UDP-over-Vision session machine wired into the tunnel.
//!
//! Wire shape: XUDP frames (Xray Mux.Cool's UDP subset) ride the Vision
//! padding content byte stream directly, with no mux session layer in
//! between; `meow_proxy::mux::xudp` owns the codec and the per-connection
//! session machine. This module owns everything the codec deliberately
//! does not: tunnel routing, per-target flows, queue budgets, reply
//! encoding, idle eviction and teardown.
//!
//! # Session model
//!
//! xray fuses the two concepts this driver separates: its mux session IS
//! the freedom flow, so a dead flow forces the session id's teardown and
//! the End frame is the client's only protection against blackholed bare
//! Keeps. Here the XUDP session (`sid` → default target, owned by
//! [`XudpServer`]) is a cheap control-plane object that lives for the
//! whole connection, while the data plane is one UDP flow per
//! `(sid, target)` — required because meow's routing evaluates rules per
//! destination, unlike xray freedom's single link with per-packet write
//! destinations. Consequences:
//!
//! * A datagram for a live session whose flow died (idle eviction,
//!   upstream error, flush) simply respawns the flow — the session state
//!   still resolves bare Keeps to the default target, so nothing
//!   blackholes and no End needs to be sent. This is the UDP NAT
//!   philosophy every other meow inbound follows.
//! * The only server-initiated End is the codec's unknown-sid answer
//!   ([`XudpAction::ReplyEnd`], xray server.go:305-312 parity) — the one
//!   case where the client truly cannot be served.
//!
//! # Budgets (spec §2.3)
//!
//! Per physical connection: at most [`MAX_XUDP_FLOWS`] `(sid, target)`
//! flows (LRU-evicted at the cap, codec caps session ids at the same
//! number), at most [`FLOW_QUEUE`] datagrams queued per flow, and one
//! shared byte meter covering BOTH directions' queued bytes — ingress
//! datagrams parked in flow queues plus egress frames parked in the
//! writer queue — capped at [`CONN_QUEUE_BYTES`]. Overflow drops the
//! datagram/reply; nothing about the pressure grows task or queue counts.
//!
//! # Lifecycle
//!
//! The association is the Vision connection's lifetime scope exactly like
//! the UoT stream is for AnyTLS: the read loop, the ordered writer task,
//! the idle sweeper and every flow task are owned here, and teardown —
//! peer EOF, connection-fatal codec error, idle close, or task cancel —
//! reaps all of them through the [`AssociationGuard`], with each flow's
//! UDP conn closed by its own guard.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use meow_common::atomic::{AtomicU, Uint};
use meow_common::{Metadata, ProxyPacketConn};
use meow_proxy::mux::xudp::{
    encode_end, encode_reply_keep_data, reply_source, XudpAction, XudpDecoder, XudpServer,
    XudpTarget,
};
use meow_proxy::vless_inbound::VisionServerConn;
use meow_tunnel::{MatchedRule, ResolvedTarget, TunnelInner, UsingProxy};
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info};

/// `(sid, target)` flow cap per physical connection — spec §2.3. The
/// codec independently refuses a 129th session id; this cap bounds the
/// flow table under target spraying within a single sid (a fullcone
/// client may name a fresh target per packet). At the cap the
/// least-recently-active flow is evicted, the same LRU policy the
/// sweeper applies on a timer.
const MAX_XUDP_FLOWS: usize = 128;
/// Datagrams queued per flow while its outbound conn is establishing or
/// its upstream write arm is busy; overflow drops the datagram (UDP
/// semantics — the client retries), same bound SOCKS5-UDP/UoT use.
const FLOW_QUEUE: usize = 64;
/// Connection-wide byte ceiling across BOTH directions' queues (spec
/// §2.3's 4 MiB both-ways budget): ingress datagrams parked in flow
/// queues plus egress frames parked in the writer queue. Without it the
/// count bounds alone park 128 × 64 datagrams plus 128 reply frames of
/// up to 8 KiB against a stalled peer.
const CONN_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// Egress writer queue depth in frames. Replies are small and the byte
/// meter is the real budget; the count bound keeps a writer-stalled
/// connection from queueing without end even under a flood of tiny
/// datagrams the meter would otherwise admit.
const EGRESS_QUEUE: usize = 128;
/// Idle-eviction sweep cadence — the SOCKS5/UoT sweeper's.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Vision content read chunk. XUDP frames cross chunk boundaries freely
/// (the decoder is incremental); the size only bounds per-read copies.
const READ_BUF: usize = 16 * 1024;

/// Millisecond timestamps in the platform atomic — see anytls_uot.
fn now_ms() -> Uint {
    crate::monotonic_ms() as Uint
}

fn idle_ms() -> Uint {
    meow_tunnel::udp::DEFAULT_UDP_IDLE.as_millis() as Uint
}

fn touch_activity(stamp: &AtomicU) {
    stamp.store(now_ms(), Ordering::Release);
}

/// Sample `stamp` BEFORE reading the clock so a concurrent touch can
/// never wrap the subtraction (N03 in anytls_uot).
fn elapsed_since(stamp: &AtomicU) -> Uint {
    let last = stamp.load(Ordering::Acquire);
    now_ms().wrapping_sub(last)
}

/// Flow-table key: the session id plus the target in canonical form —
/// `ip:port` for address-form targets, lowercased `host:port` for
/// domain-form, so a target named two ways never merges flows while the
/// two casings of one name do. Domain keys are lowercased exactly once
/// at key construction; `Metadata::lower_host` is idempotent on the
/// already-lowercase copy the metadata build applies independently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TargetKey {
    Addr(SocketAddr),
    Host(SmolStr, u16),
}

impl TargetKey {
    fn of(target: &XudpTarget) -> Self {
        let (ip, host, port) = target.metadata_parts();
        match ip {
            Some(ip) => TargetKey::Addr(SocketAddr::new(ip.to_canonical(), port)),
            None => TargetKey::Host(Metadata::lower_host(host), port),
        }
    }
}

type FlowKey = (u16, TargetKey);

/// One queued ingress datagram: the payload plus its share of the
/// association's byte meter, released on Drop whatever path consumed it.
struct QueuedPacket {
    bytes: Bytes,
    meter: Arc<AtomicUsize>,
}

impl Drop for QueuedPacket {
    fn drop(&mut self) {
        self.meter.fetch_sub(self.bytes.len(), Ordering::Relaxed);
    }
}

/// One queued egress frame — same meter discipline as the ingress side:
/// the spec's 4 MiB budget is one sum across both directions.
struct EgressFrame {
    bytes: Bytes,
    meter: Arc<AtomicUsize>,
}

impl EgressFrame {
    /// Charge the shared meter and bundle the frame, or refuse when the
    /// budget is exhausted — the caller drops the datagram (and counts
    /// it) rather than letting a stalled writer park unbounded memory.
    fn charged(bytes: Bytes, meter: &Arc<AtomicUsize>) -> Option<Self> {
        let new_pending = meter.load(Ordering::Relaxed) + bytes.len();
        if new_pending > CONN_QUEUE_BYTES {
            return None;
        }
        meter.fetch_add(bytes.len(), Ordering::Relaxed);
        Some(Self {
            bytes,
            meter: Arc::clone(meter),
        })
    }
}

impl Drop for EgressFrame {
    fn drop(&mut self) {
        self.meter.fetch_sub(self.bytes.len(), Ordering::Relaxed);
    }
}

/// One live outbound UDP flow: the bounded ingress queue plus the
/// activity/deadness bookkeeping the sweeper and teardown need.
struct XudpFlow {
    tx: mpsc::Sender<QueuedPacket>,
    last_activity: Arc<AtomicU>,
    /// Set by eviction/teardown AND by the flow task itself on exit —
    /// the next datagram for this key respawns rather than queueing
    /// behind a corpse.
    dead: Arc<AtomicBool>,
    task: tokio::task::AbortHandle,
}

/// The listener-side context stamped onto every flow's `Metadata`.
pub(crate) struct XudpFlowCtx<'a> {
    pub peer: SocketAddr,
    pub in_name: &'a str,
    pub in_port: u16,
    pub user: &'a SmolStr,
    pub route_override: Option<&'a meow_common::InboundRouteOverride>,
}

/// `Metadata` for one XUDP flow target — `Network::Udp`, `ConnType::Vless`,
/// the authenticated user and the route override stamped exactly like the
/// TCP path. The domain stays as the wire carried it (modulo
/// `lower_host`); resolution is the tunnel's business downstream.
fn build_udp_metadata(
    dst_ip: Option<std::net::IpAddr>,
    host: SmolStr,
    dst_port: u16,
    ctx: &XudpFlowCtx<'_>,
) -> (Metadata, Option<SocketAddr>) {
    let claimed = dst_ip
        .or_else(|| meow_common::metadata_ip_literal(&host))
        .map(|ip| SocketAddr::new(ip.to_canonical(), dst_port));
    let mut metadata = Metadata {
        network: meow_common::Network::Udp,
        conn_type: meow_common::ConnType::Vless,
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

/// Drive one XUDP association — one authenticated Vision Mux connection —
/// until the peer closes, a frame violates the codec contract, or the
/// connection idles out. `conn` is already wrapped in the server Vision
/// codec in XUDP mode (never DIRECT); the VLESS request is consumed and
/// the response header rides the first downlink frame automatically.
///
/// `first_frame_deadline` bounds the wait for the first XUDP frame: the
/// spec shares the handshake's absolute-deadline philosophy so a peer
/// that authenticated and then falls silent cannot occupy a listener
/// slot indefinitely.
pub(crate) async fn run_xudp_conn(
    conn: VisionServerConn,
    inner: Arc<TunnelInner>,
    ctx: XudpFlowCtx<'_>,
    first_frame_deadline: tokio::time::Instant,
) {
    let peer = ctx.peer;
    let (mut reader, writer) = tokio::io::split(conn);

    // Single ordered writer: reply frames from every flow task plus the
    // read loop's End answers interleave freely at encode time but must
    // serialize onto the Vision stream — frame interleaving is impossible
    // through one queue. Bounded; the byte meter is the real budget.
    let (out_tx, out_rx) = mpsc::channel::<EgressFrame>(EGRESS_QUEUE);
    let writer = tokio::spawn(writer_loop(writer, out_rx));

    let flows: Arc<parking_lot::Mutex<HashMap<FlowKey, XudpFlow>>> =
        Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let pending_bytes = Arc::new(AtomicUsize::new(0));

    // Connection-level idle close (xray `CloseIfNoSessionAndIdle`
    // parity): with no live flows and no frames for the UDP idle window
    // the association has nothing left to serve — an authenticated peer
    // holding silence must not occupy a listener slot forever. Frame
    // arrival touches the stamp; the flow table staying non-empty
    // suppresses the close regardless (receive-only flows count as
    // activity through their own stamps).
    let conn_activity = Arc::new(AtomicU::new(now_ms()));
    let close_notify = Arc::new(Notify::new());
    let sweeper = tokio::spawn({
        let flows = Arc::clone(&flows);
        let conn_activity = Arc::clone(&conn_activity);
        let close_notify = Arc::clone(&close_notify);
        async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            tick.tick().await; // first tick fires immediately — skip it
            loop {
                tick.tick().await;
                let idle = idle_ms();
                let mut table = flows.lock();
                table.retain(|_, f| {
                    if elapsed_since(&f.last_activity) < idle {
                        return true;
                    }
                    f.dead.store(true, Ordering::Relaxed);
                    f.task.abort();
                    false
                });
                let empty = table.is_empty();
                drop(table);
                if empty && elapsed_since(&conn_activity) >= idle {
                    close_notify.notify_one();
                    return;
                }
            }
        }
    });

    // The association OWNS its spawned tasks: dropping this guard — the
    // normal tail below OR a cancelled `run_xudp_conn` — kills every
    // flow task (whose in-scope conn guards close the UDP sockets), the
    // sweeper and the writer. Nothing may outlive the association
    // detached.
    let mut guard = AssociationGuard {
        flows: Arc::clone(&flows),
        writer,
        sweeper,
    };

    let mut decoder = XudpDecoder::new();
    let mut server = XudpServer::new(true);
    let mut buf = vec![0u8; READ_BUF];
    let mut seen_first_frame = false;

    loop {
        // Before the first frame the read is deadline-bounded; after it,
        // only the idle-close notification races the read. The vision
        // read is cancel-safe: bytes land in the caller's buffer only on
        // completion, partial frame progress lives in the codec scratch.
        let read_step = async {
            tokio::select! {
                biased;
                _ = close_notify.notified() => None,
                res = reader.read(&mut buf) => Some(res),
            }
        };
        let stepped = if seen_first_frame {
            read_step.await
        } else {
            match tokio::time::timeout_at(first_frame_deadline, read_step).await {
                Ok(v) => v,
                Err(_) => {
                    debug!("vless xudp {peer}: first frame not seen within the handshake deadline");
                    break;
                }
            }
        };
        let Some(read) = stepped else {
            debug!("vless xudp {peer}: association idle-closed");
            break;
        };
        let n = match read {
            Ok(0) => {
                if decoder.mid_frame() {
                    debug!(
                        "vless xudp {peer}: EOF mid XUDP frame; truncated datagram never emitted"
                    );
                }
                break;
            }
            Ok(n) => n,
            Err(e) => {
                debug!("vless xudp {peer}: vision read: {e}");
                break;
            }
        };
        if let Err(e) = decoder.feed(&buf[..n]) {
            // Every codec error is connection-fatal: the frame stream can
            // no longer be trusted and there is no frame-level recovery
            // in Mux.Cool.
            debug!("vless xudp {peer}: fatal frame error: {e}");
            break;
        }
        let mut fatal = None;
        while let Some(frame) = decoder.next_frame() {
            seen_first_frame = true;
            touch_activity(&conn_activity);
            let action = match server.handle_frame(frame) {
                Ok(action) => action,
                Err(e) => {
                    fatal = Some(e);
                    break;
                }
            };
            match action {
                // A New carrying its first datagram and a Keep's datagram
                // are the same delivery: spawn-or-enqueue for the
                // effective target. A bare New spawns nothing — the
                // control-plane session state already lives in the
                // machine, and the flow is created lazily when the first
                // datagram arrives.
                Some(
                    XudpAction::NewSession {
                        session_id,
                        target,
                        first_datagram: Some(payload),
                        ..
                    }
                    | XudpAction::Datagram {
                        session_id,
                        target,
                        payload,
                    },
                ) => {
                    deliver_or_spawn(
                        &flows,
                        &inner,
                        session_id,
                        &target,
                        payload,
                        &ctx,
                        &out_tx,
                        &pending_bytes,
                        peer,
                    );
                }
                Some(XudpAction::SessionEnd { session_id, .. }) => {
                    // Peer-initiated teardown: reap every flow of the
                    // session silently — the peer already knows.
                    let mut table = flows.lock();
                    let keys: Vec<FlowKey> = table
                        .keys()
                        .filter(|(sid, _)| *sid == session_id)
                        .cloned()
                        .collect();
                    for key in keys {
                        if let Some(flow) = table.remove(&key) {
                            flow.dead.store(true, Ordering::Relaxed);
                            flow.task.abort();
                        }
                    }
                }
                Some(XudpAction::ReplyEnd { session_id }) => {
                    // xray's unknown-sid answer: an End frame for the
                    // session, the datagram already dropped. Best-effort —
                    // a saturated writer must not block the read loop.
                    let frame = encode_end(session_id, false);
                    if let Some(charged) = EgressFrame::charged(frame, &pending_bytes) {
                        let _ = out_tx.try_send(charged);
                    }
                }
                Some(XudpAction::NewSession { .. }) | None => {}
            }
        }
        if let Some(e) = fatal {
            debug!("vless xudp {peer}: fatal session error: {e}");
            break;
        }
    }

    // Teardown: kill every flow, stop accepting replies, then drain the
    // writer so the last replies still reach the wire before close. The
    // guard's Drop repeats the aborts — cheap and idempotent — and covers
    // the cancel path with no extra code.
    {
        let mut table = guard.flows.lock();
        for (_, flow) in table.drain() {
            flow.dead.store(true, Ordering::Relaxed);
            flow.task.abort();
        }
    }
    guard.sweeper.abort();
    drop(out_tx);
    if let Ok(mut w) = (&mut guard.writer).await {
        // Polite close: the vision write half's shutdown propagates the
        // outer TLS close_notify. Bounded — a dead peer must not stall
        // teardown.
        let _ = tokio::time::timeout(Duration::from_millis(500), w.shutdown()).await;
    }
}

/// The writer half of the split Vision conn pumps encoded frames in
/// queue order. Flushes are batched: everything already queued goes out
/// in one flush so a reply burst costs one TLS record push rather than
/// one per frame.
async fn writer_loop(
    mut writer: tokio::io::WriteHalf<VisionServerConn>,
    mut rx: mpsc::Receiver<EgressFrame>,
) -> tokio::io::WriteHalf<VisionServerConn> {
    while let Some(frame) = rx.recv().await {
        if writer.write_all(&frame.bytes).await.is_err() {
            break;
        }
        drop(frame);
        // Drain everything immediately available before flushing once.
        while let Ok(frame) = rx.try_recv() {
            if writer.write_all(&frame.bytes).await.is_err() {
                return writer;
            }
            drop(frame);
        }
        if writer.flush().await.is_err() {
            break;
        }
    }
    writer
}

/// The association's owned tasks — ordered writer, idle sweeper and the
/// flow table. Dropping the guard aborts every owned task; the flow
/// tasks' in-scope conn guards close their UDP conns with them.
struct AssociationGuard {
    flows: Arc<parking_lot::Mutex<HashMap<FlowKey, XudpFlow>>>,
    writer: tokio::task::JoinHandle<tokio::io::WriteHalf<VisionServerConn>>,
    sweeper: tokio::task::JoinHandle<()>,
}

impl Drop for AssociationGuard {
    fn drop(&mut self) {
        for (_, flow) in self.flows.lock().drain() {
            flow.dead.store(true, Ordering::Relaxed);
            flow.task.abort();
        }
        self.sweeper.abort();
        self.writer.abort();
    }
}

/// Deliver one datagram to the flow for `(sid, target)`, spawning the
/// flow when none exists or the previous one died. Never blocks the read
/// loop: resolution, routing and the dial all happen inside the flow
/// task.
#[allow(
    clippy::too_many_arguments,
    reason = "the dispatch context is one logical unit"
)]
fn deliver_or_spawn(
    flows: &Arc<parking_lot::Mutex<HashMap<FlowKey, XudpFlow>>>,
    inner: &Arc<TunnelInner>,
    sid: u16,
    target: &XudpTarget,
    payload: Bytes,
    ctx: &XudpFlowCtx<'_>,
    out_tx: &mpsc::Sender<EgressFrame>,
    meter: &Arc<AtomicUsize>,
    peer: SocketAddr,
) {
    let key: FlowKey = (sid, TargetKey::of(target));
    let existing = {
        let table = flows.lock();
        table.get(&key).and_then(|f| {
            if f.dead.load(Ordering::Relaxed) {
                None
            } else {
                touch_activity(&f.last_activity);
                Some(f.tx.clone())
            }
        })
    };
    let tx = match existing {
        Some(tx) => tx,
        None => {
            // Drop the corpse (if any) and enforce the flow cap with
            // LRU eviction — find and remove under one lock, abort
            // outside it.
            let evicted = {
                let mut table = flows.lock();
                let corpse = table.remove(&key);
                let lru = if table.len() >= MAX_XUDP_FLOWS {
                    table
                        .iter()
                        .max_by_key(|(_, f)| elapsed_since(&f.last_activity))
                        .map(|(k, _)| k.clone())
                        .and_then(|k| table.remove(&k))
                } else {
                    None
                };
                corpse.into_iter().chain(lru).collect::<Vec<_>>()
            };
            for flow in evicted {
                flow.dead.store(true, Ordering::Relaxed);
                flow.task.abort();
            }
            let flow = spawn_xudp_flow(
                Arc::clone(inner),
                sid,
                target,
                ctx,
                out_tx.clone(),
                Arc::clone(meter),
            );
            let tx = flow.tx.clone();
            flows.lock().insert(key, flow);
            tx
        }
    };

    // Charge the shared byte meter BEFORE enqueueing; only the read loop
    // mutates it upward on the ingress side so check-then-add is
    // race-free within one direction, and both directions together
    // cannot exceed the budget by more than one frame's width.
    let new_pending = meter.load(Ordering::Relaxed) + payload.len();
    if new_pending > CONN_QUEUE_BYTES {
        debug!("vless xudp {peer}: queued byte budget exhausted, dropping datagram");
        return;
    }
    meter.fetch_add(payload.len(), Ordering::Relaxed);
    match tx.try_send(QueuedPacket {
        bytes: payload,
        meter: Arc::clone(meter),
    }) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(queued)) => {
            drop(queued);
            debug!("vless xudp {peer}: flow queue full, dropping datagram");
        }
        Err(mpsc::error::TrySendError::Closed(queued)) => {
            // The flow died between lookup and send — rare since the
            // dead-flag check just ran, but aborts race. The datagram
            // drops; the next one respawns the flow.
            drop(queued);
        }
    }
}

/// Spawn one target's outbound flow: resolve → route → `dial_udp`, then
/// the packet writer and the reply reader. Mirrors `run_uot_session` —
/// same metadata pipeline, same flush watch, same counted dial path.
fn spawn_xudp_flow(
    inner: Arc<TunnelInner>,
    sid: u16,
    target: &XudpTarget,
    ctx: &XudpFlowCtx<'_>,
    out_tx: mpsc::Sender<EgressFrame>,
    meter: Arc<AtomicUsize>,
) -> XudpFlow {
    let (tx, rx) = mpsc::channel::<QueuedPacket>(FLOW_QUEUE);
    let last_activity = Arc::new(AtomicU::new(now_ms()));
    let dead = Arc::new(AtomicBool::new(false));

    let (dst_ip, host, dst_port) = target.metadata_parts();
    let host = if host.is_empty() {
        SmolStr::default()
    } else {
        Metadata::lower_host(host)
    };
    let (metadata, claimed) = build_udp_metadata(dst_ip, host, dst_port, ctx);

    let task = tokio::spawn(run_xudp_flow(
        inner,
        metadata,
        claimed,
        XudpFlowIo {
            rx,
            out_tx,
            meter,
            sid,
            target: target.clone(),
            last_activity: Arc::clone(&last_activity),
            dead: Arc::clone(&dead),
        },
    ));

    XudpFlow {
        tx,
        last_activity,
        dead,
        task: task.abort_handle(),
    }
}

/// The halves an XUDP flow task owns — its datagram queue, the
/// association's ordered writer, the reply-encoding inputs — grouped so
/// the task signature isn't a positional-argument list.
struct XudpFlowIo {
    rx: mpsc::Receiver<QueuedPacket>,
    out_tx: mpsc::Sender<EgressFrame>,
    meter: Arc<AtomicUsize>,
    sid: u16,
    /// The flow's own target, kept with the exact wire domain casing for
    /// the reply-source rewrite; the metadata pipeline only ever sees
    /// the lowercased key form.
    target: XudpTarget,
    last_activity: Arc<AtomicU>,
    dead: Arc<AtomicBool>,
}

/// The flow task: metadata pipeline (pre-handle, pre-resolve, route) →
/// `dial_udp` → writer + reply loops with the outbound-binding flush
/// watch — the UoT session task's shape on an XUDP session.
async fn run_xudp_flow(
    inner: Arc<TunnelInner>,
    mut metadata: Metadata,
    claimed: Option<SocketAddr>,
    io: XudpFlowIo,
) {
    let XudpFlowIo {
        mut rx,
        out_tx,
        meter,
        sid,
        target,
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
            debug!("vless xudp flow to {}: {e}", metadata.remote_address());
            return;
        }
    };
    // The IP the dial actually used locally, for the reply-source domain
    // rewrite: a proxied outbound resolves remotely and the real source
    // goes on the wire unchanged, exactly the xray freedom rule.
    let dialed_ip = metadata.dst_ip;

    // Reply reader, writer, flush watch and idle deadline — ALL polled
    // as plain futures inside THIS task: whichever ends first retires
    // the flow, and a task abort drops BOTH arms plus the conn guard —
    // nothing survives to double-await or detach holding the UDP conn.
    let _conn_guard = ConnGuard(Arc::clone(&conn));
    let mut rbuf = vec![0u8; 65535];
    let reply = async {
        while let Ok((m, src)) = conn.read_packet(&mut rbuf).await {
            let wire_source = reply_source(&target, dialed_ip, src);
            let Some(frame) = encode_reply_keep_data(sid, Some(&wire_source), &rbuf[..m]) else {
                // Oversize (never split) or unrepresentable source —
                // counted through the meter of ordinary drops in logs.
                debug!(
                    "vless xudp flow to {dst_addr}: dropping unencodable reply ({} bytes)",
                    m
                );
                continue;
            };
            let Some(charged) = EgressFrame::charged(frame, &meter) else {
                debug!("vless xudp flow to {dst_addr}: byte budget exhausted, dropping reply");
                continue;
            };
            // Blocking send — bounded by EGRESS_QUEUE frames — applies
            // per-flow backpressure when the client stalls reading; the
            // write arm parking with it is the UoT cascade by design.
            if out_tx.send(charged).await.is_err() {
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
            // same as sends do.
            let elapsed = elapsed_since(&last_activity);
            let idle_left = idle_ms().saturating_sub(elapsed);
            tokio::select! {
                biased;
                _ = flush.flushed() => {
                    debug!("vless xudp flow to {dst_addr}: outbound binding flushed; flow retires");
                    break;
                }
                msg = rx.recv() => match msg {
                    None => break,
                    Some(packet) => {
                        let payload = &packet.bytes;
                        // The write itself races the flush watch — a
                        // suspended `write_packet` must not starve a
                        // binding teardown.
                        let res = tokio::select! {
                            biased;
                            _ = flush.flushed() => {
                                debug!("vless xudp flow to {dst_addr}: flushed mid-write; flow retires");
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
                                    "vless xudp flow to {dst_addr}: short upstream write {n}/{}; flow retires",
                                    payload.len()
                                );
                                break;
                            }
                            Err(e) => {
                                debug!("vless xudp flow to {dst_addr}: upstream write: {e}; flow retires");
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

/// RAII owner for a flow's `ProxyPacketConn`: flow teardown — normal
/// return or task abort — closes the conn exactly once, never leaving a
/// dialed UDP socket parked on a dead task.
struct ConnGuard(Arc<dyn ProxyPacketConn>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}
