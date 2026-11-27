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
//! peer EOF, connection-fatal codec error, idle close, writer death, or
//! task cancel — reaps all of them through the [`AssociationGuard], with
//! each flow's UDP conn closed by its own guard.
//!
//! # Cross-crate interface needs (known gaps)
//!
//! Two correctness gaps cannot be closed inside this crate:
//!
//! * F11 — stream-framed [`ProxyPacketConn`]s (plain VLESS UoT, mux)
//!   consume an oversized inbound datagram whole before reporting that it
//!   did not fit the caller's buffer. That error is recoverable — framing
//!   is intact — but indistinguishable from a fatal transport error
//!   through the current `MeowError` surface, so the flow retires and the
//!   client must re-send to respawn it. Needs a matchable error variant
//!   (e.g. `MeowError::UdpPacketTooLarge { packet_len, buffer_len }`) in
//!   meow-common, produced by meow-proxy's framed readers only after the
//!   datagram was fully consumed, and transparently forwarded by
//!   meow-tunnel's counted wrapper.
//! * F12 — the reply-source domain rewrite keys on `metadata.dst_ip`,
//!   the pre-dial resolution, but a DIRECT outbound with
//!   `dns.direct-nameserver` re-resolves and connect()s elsewhere.
//!   Needs an object-safe capability on `ProxyPacketConn` (e.g.
//!   `local_udp_destination(requested) -> Option<SocketAddr>`) answered
//!   by the final DIRECT/COMPATIBLE conn with the peer its socket is
//!   actually bound to (`None` for remote-resolution/proxied paths),
//!   forwarded by meow-tunnel's counted wrapper.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use meow_common::atomic::{AtomicU, Uint};
use meow_common::{Metadata, ProxyPacketConn};
use meow_proxy::mux::xudp::{
    encode_end, encode_reply_keep_data, encoded_reply_keep_data_len, reply_source, XudpAction,
    XudpAddr, XudpDecoder, XudpServer, XudpTarget, MAX_PAYLOAD_LEN,
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

/// Smallest read size that still exposes every oversize payload: a
/// cap-sized datagram fills MAX_PAYLOAD_LEN bytes, so any byte beyond
/// that means "drop" rather than "truncate and forward".
const PAYLOAD_PROBE_LEN: usize = MAX_PAYLOAD_LEN + 1;
/// Conservative allowance for UDP encapsulation headers when the selected
/// outbound is a raw-datagram transport. SOCKS5 adds at most 22 bytes and
/// Shadowsocks UDP at most roughly 110 bytes for its AEAD-2022 header,
/// nonce/tag and socket-address prefix; chained dialers can repeat such a
/// hop up to the engine's 16-hop chain bound. 4 KiB is comfortably above
/// that worst-case sum, while still an order of magnitude below the old
/// 64 KiB per-flow allocation. Stream-framed transports do not consume
/// this allowance because they reassemble a complete datagram before
/// copying it into the caller buffer.
const RAW_ENCAPSULATION_HEADROOM: usize = 4 * 1024;
const RAW_ENCAPSULATED_REPLY_READ_BUF: usize = PAYLOAD_PROBE_LEN + RAW_ENCAPSULATION_HEADROOM;
const _: () = assert!(PAYLOAD_PROBE_LEN > MAX_PAYLOAD_LEN);
const _: () = assert!(RAW_ENCAPSULATED_REPLY_READ_BUF <= 13 * 1024);

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
            None => {
                let XudpAddr::Domain(original) = &target.addr else {
                    unreachable!("ip-less XUDP target is always domain-form")
                };
                // The per-packet key lookup must not reallocate long domain
                // names: the decoder already owns them in a SmolStr, so an
                // already-lowercase key is only an Arc refcount bump.
                let host = if host.bytes().any(|b| b.is_ascii_uppercase()) {
                    Metadata::lower_host(host)
                } else {
                    original.clone()
                };
                TargetKey::Host(host, port)
            }
        }
    }
}

type FlowKey = (u16, TargetKey);

/// A byte reservation against the association-wide queue meter. The
/// reservation is atomic — concurrent ingress and egress charges can never
/// slip a check-then-add pair past one another — and is released on Drop
/// whichever queueing path owns it by then.
struct MeterCharge {
    bytes: usize,
    meter: Arc<AtomicUsize>,
}

impl MeterCharge {
    fn acquire(meter: &Arc<AtomicUsize>, bytes: usize) -> Option<Self> {
        meter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
                let charged = pending.checked_add(bytes)?;
                (charged <= CONN_QUEUE_BYTES).then_some(charged)
            })
            .ok()?;
        Some(Self {
            bytes,
            meter: Arc::clone(meter),
        })
    }
}

impl Drop for MeterCharge {
    fn drop(&mut self) {
        self.meter.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// One queued ingress datagram: the payload plus its share of the
/// association's byte meter, released on Drop whatever path consumed it.
struct QueuedPacket {
    bytes: Bytes,
    _charge: MeterCharge,
}

/// One accepted XUDP session generation. Every `New` the codec accepts
/// installs a fresh token for the sid; the matching `End` invalidates it
/// BEFORE the session's flows are reaped. Queued downlink frames carry
/// the token so a sid reused by a later `New` never inherits replies the
/// dead generation produced — the writer re-checks it until the frame's
/// first byte has been accepted onto the wire.
struct SessionGen(AtomicBool);

type SessionGens = Arc<parking_lot::Mutex<HashMap<u16, Arc<SessionGen>>>>;

/// What the writer must validate before committing a frame to the wire.
enum EgressKind {
    /// Session data: valid only while its generation is live.
    Data { gen: Arc<SessionGen> },
    /// The unknown-sid End answer: valid only while the sid is still
    /// unopened — a `New` arriving before the write makes it stale.
    End { sid: u16 },
}

/// One queued egress frame — same meter discipline as the ingress side:
/// the spec's 4 MiB budget is one sum across both directions.
struct EgressFrame {
    bytes: Bytes,
    kind: EgressKind,
    _charge: MeterCharge,
}

impl EgressFrame {
    /// Charge the shared meter and bundle the frame, or refuse when the
    /// budget is exhausted — the caller drops the datagram (and counts
    /// it) rather than letting a stalled writer park unbounded memory.
    fn charged(bytes: Bytes, kind: EgressKind, meter: &Arc<AtomicUsize>) -> Option<Self> {
        let charge = MeterCharge::acquire(meter, bytes.len())?;
        Some(Self::precharged(bytes, kind, charge))
    }

    fn precharged(bytes: Bytes, kind: EgressKind, charge: MeterCharge) -> Self {
        Self {
            bytes,
            kind,
            _charge: charge,
        }
    }

    /// Send-time validity. Checked on every writer poll until the frame's
    /// first byte is accepted; a frame already mid-write always completes
    /// so the wire never sees a truncated frame boundary.
    fn live(&self, gens: &SessionGens) -> bool {
        match &self.kind {
            EgressKind::Data { gen } => gen.0.load(Ordering::Acquire),
            EgressKind::End { sid } => !gens.lock().contains_key(sid),
        }
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
    let gens: SessionGens = Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let mut writer = tokio::spawn(writer_loop(writer, out_rx, Arc::clone(&gens)));
    let writer_abort = writer.abort_handle();

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
    let guard = AssociationGuard {
        flows: Arc::clone(&flows),
        writer: writer_abort,
        sweeper,
    };

    let mut decoder = XudpDecoder::new();
    let mut server = XudpServer::new(true);
    let mut buf = vec![0u8; READ_BUF];
    let mut seen_first_frame = false;
    // Set once the writer task finishes — its completion is a teardown
    // trigger, so at teardown time the handle must not be re-joined.
    let mut writer_done = false;

    loop {
        // Before the first frame the read is deadline-bounded; after it,
        // only the idle-close notification races the read. The vision
        // read is cancel-safe: bytes land in the caller's buffer only on
        // completion, partial frame progress lives in the codec scratch.
        // The writer's death joins the same select: an association whose
        // downlink is broken must not keep accepting uplink datagrams it
        // can never answer.
        enum Step {
            IdleClose,
            WriterDead,
            Read(std::io::Result<usize>),
        }
        let read_step = async {
            tokio::select! {
                biased;
                _ = close_notify.notified() => Step::IdleClose,
                res = &mut writer => {
                    match res {
                        Ok(Ok(_)) => debug!("vless xudp {peer}: writer exited while the read side is live"),
                        Ok(Err(e)) => debug!("vless xudp {peer}: writer io: {e}"),
                        Err(e) => debug!("vless xudp {peer}: writer task: {e}"),
                    }
                    Step::WriterDead
                }
                res = reader.read(&mut buf) => Step::Read(res),
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
        let read = match stepped {
            Step::IdleClose => {
                debug!("vless xudp {peer}: association idle-closed");
                break;
            }
            Step::WriterDead => {
                writer_done = true;
                break;
            }
            Step::Read(read) => read,
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
                Some(XudpAction::NewSession {
                    session_id,
                    target,
                    first_datagram,
                    ..
                }) => {
                    // Every accepted New installs a fresh generation: the
                    // codec rejects duplicate New for a live sid, so this
                    // sid is by construction opening anew — any replies a
                    // previous incarnation still has queued are now stale.
                    let gen = Arc::new(SessionGen(AtomicBool::new(true)));
                    gens.lock().insert(session_id, Arc::clone(&gen));
                    if let Some(payload) = first_datagram {
                        deliver_or_spawn(
                            &flows,
                            &inner,
                            session_id,
                            &target,
                            payload,
                            &ctx,
                            &out_tx,
                            &pending_bytes,
                            gen,
                            peer,
                        );
                    }
                }
                Some(XudpAction::Datagram {
                    session_id,
                    target,
                    payload,
                }) => {
                    // The codec only emits this for a live session, so the
                    // generation must exist; a missing one means the End
                    // already landed and the datagram is as stale as the
                    // replies it could produce.
                    if let Some(gen) = gens.lock().get(&session_id).cloned() {
                        deliver_or_spawn(
                            &flows,
                            &inner,
                            session_id,
                            &target,
                            payload,
                            &ctx,
                            &out_tx,
                            &pending_bytes,
                            gen,
                            peer,
                        );
                    }
                }
                Some(XudpAction::SessionEnd { session_id, .. }) => {
                    // Peer-initiated teardown. Invalidate the generation
                    // FIRST: every reply this session still has queued —
                    // in any flow task or in the writer — becomes stale
                    // before the flows are reaped, so a reused sid never
                    // inherits them. The peer-initiated teardown itself
                    // stays silent — the peer already knows.
                    if let Some(gen) = gens.lock().remove(&session_id) {
                        gen.0.store(false, Ordering::Release);
                    }
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
                    // a saturated writer must not block the read loop. The
                    // writer re-validates the still-unknown sid at send
                    // time so a New that already landed never receives a
                    // stale End.
                    let frame = encode_end(session_id, false);
                    if let Some(charged) = EgressFrame::charged(
                        frame,
                        EgressKind::End { sid: session_id },
                        &pending_bytes,
                    ) {
                        let _ = out_tx.try_send(charged);
                    }
                }
                None => {}
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
    // The writer drains what is already queued before it exits, but a peer
    // that stopped reading can park that drain in write/flush forever.
    // Bound the JOIN, not just the closeNotify below; on timeout the guard
    // aborts the writer and the association's connection slot is still
    // released. A writer that already finished — the teardown trigger in
    // the read loop — is neither re-joined nor drained.
    if !writer_done {
        match tokio::time::timeout(Duration::from_millis(500), &mut writer).await {
            Ok(Ok(Ok(mut w))) => {
                // Polite close: the vision write half's shutdown propagates
                // the outer TLS close_notify. Bounded — a dead peer must
                // not stall teardown.
                let _ = tokio::time::timeout(Duration::from_millis(500), w.shutdown()).await;
            }
            Ok(Ok(Err(_))) | Ok(Err(_)) => {}
            Err(_) => writer.abort(),
        }
    }
}

/// Write one frame whole, or drop it whole. Until the first byte is
/// accepted the send-time validity is re-checked on every poll — a frame
/// whose generation died while the write was parked never reaches the
/// wire; once any byte is accepted the frame always completes, because a
/// truncated frame would corrupt every frame boundary after it.
async fn write_frame_once(
    writer: &mut tokio::io::WriteHalf<VisionServerConn>,
    frame: EgressFrame,
    gens: &SessionGens,
) -> std::io::Result<()> {
    use std::task::Poll;
    use tokio::io::AsyncWrite;
    let mut pos = 0;
    std::future::poll_fn(|cx| {
        while pos < frame.bytes.len() {
            if pos == 0 && !frame.live(gens) {
                return Poll::Ready(Ok(()));
            }
            match std::pin::Pin::new(&mut *writer).poll_write(cx, &frame.bytes[pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    })
    .await
}

/// The writer half of the split Vision conn pumps encoded frames in
/// queue order. Flushes are batched: everything already queued goes out
/// in one flush so a reply burst costs one TLS record push rather than
/// one per frame. A write/flush failure is returned, not swallowed: the
/// association's read loop treats the writer's exit as teardown.
async fn writer_loop(
    mut writer: tokio::io::WriteHalf<VisionServerConn>,
    mut rx: mpsc::Receiver<EgressFrame>,
    gens: SessionGens,
) -> std::io::Result<tokio::io::WriteHalf<VisionServerConn>> {
    while let Some(frame) = rx.recv().await {
        write_frame_once(&mut writer, frame, &gens).await?;
        // Drain everything immediately available before flushing once.
        while let Ok(frame) = rx.try_recv() {
            write_frame_once(&mut writer, frame, &gens).await?;
        }
        writer.flush().await?;
    }
    Ok(writer)
}

/// The association's owned tasks — ordered writer, idle sweeper and the
/// flow table. Dropping the guard aborts every owned task; the flow
/// tasks' in-scope conn guards close their UDP conns with them.
struct AssociationGuard {
    flows: Arc<parking_lot::Mutex<HashMap<FlowKey, XudpFlow>>>,
    writer: tokio::task::AbortHandle,
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
    gen: Arc<SessionGen>,
    peer: SocketAddr,
) {
    // Charge the shared byte meter atomically BEFORE anything else.
    // Ingress is serialized on this read loop, but egress flow tasks
    // charge the same meter concurrently — a load/check/add sequence
    // here would let the two directions overrun the 4 MiB budget
    // together. A datagram the budget refuses must not mutate the flow
    // table at all: no LRU eviction, no resolve/dial side effects, no
    // activity refresh for a packet that can never be queued.
    let payload_len = payload.len();
    let Some(charge) = MeterCharge::acquire(meter, payload_len) else {
        debug!("vless xudp {peer}: queued byte budget exhausted, dropping datagram");
        return;
    };

    let key: FlowKey = (sid, TargetKey::of(target));
    let existing = {
        let table = flows.lock();
        table.get(&key).and_then(|f| {
            if f.dead.load(Ordering::Relaxed) {
                None
            } else {
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
            // The outbound-binding flush watch is taken synchronously
            // BEFORE the spawn: a flush landing between the spawn and
            // the task's first poll must still be observed.
            let flush = inner.udp_flush_watch();
            let flow = spawn_xudp_flow(
                Arc::clone(inner),
                sid,
                target,
                ctx,
                out_tx.clone(),
                Arc::clone(meter),
                gen,
                flush,
            );
            let tx = flow.tx.clone();
            flows.lock().insert(key.clone(), flow);
            tx
        }
    };

    match tx.try_send(QueuedPacket {
        bytes: payload,
        _charge: charge,
    }) {
        Ok(()) => {
            // Activity is admission, not arrival: only a datagram that
            // actually made the queue refreshes the flow's idle stamp.
            let table = flows.lock();
            if let Some(f) = table.get(&key) {
                touch_activity(&f.last_activity);
            }
        }
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
#[allow(
    clippy::too_many_arguments,
    reason = "the dispatch context is one logical unit"
)]
fn spawn_xudp_flow(
    inner: Arc<TunnelInner>,
    sid: u16,
    target: &XudpTarget,
    ctx: &XudpFlowCtx<'_>,
    out_tx: mpsc::Sender<EgressFrame>,
    meter: Arc<AtomicUsize>,
    gen: Arc<SessionGen>,
    flush: meow_tunnel::udp::UdpFlushWatch,
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
            gen,
            flush,
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
    gen: Arc<SessionGen>,
    flush: meow_tunnel::udp::UdpFlushWatch,
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
        gen,
        mut flush,
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

    let establish = async {
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
        // Direct and the in-process DNS responder hand back complete
        // payload datagrams. Every other outbound may be (or sit above) a
        // raw UDP encapsulation whose wire header shares this same caller
        // buffer, so reserve the bounded headroom for those paths.
        let raw_encapsulated = !matches!(
            proxy.adapter_type(),
            meow_common::AdapterType::Direct
                | meow_common::AdapterType::Compatible
                | meow_common::AdapterType::Dns
        );
        let conn: Arc<dyn ProxyPacketConn> = Arc::from(
            inner
                .dial_udp(proxy.as_ref(), &metadata)
                .await
                .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?,
        );
        // The conn is guarded the instant it exists: if the flush race
        // below discards this completed establishment — or any later
        // teardown path fires — the socket closes exactly once rather
        // than leaking inside a dropped future output.
        let guard = ConnGuard(Arc::clone(&conn));
        Ok((conn, guard, dst_addr, raw_encapsulated))
    };
    // The flush watch — taken synchronously before this task was spawned —
    // pre-empts the WHOLE establishment, biased so a flush observed at any
    // point retires the flow before its first packet I/O, even when the
    // dial completed in the same instant.
    let outcome = tokio::select! {
        biased;
        _ = flush.flushed() => {
            debug!("vless xudp flow to {}: outbound binding flushed during establishment", metadata.remote_address());
            return;
        }
        outcome = establish => outcome,
    };

    let (conn, _conn_guard, dst_addr, raw_encapsulated) = match outcome {
        Ok(v) => v,
        Err(e) => {
            debug!("vless xudp flow to {}: {e}", metadata.remote_address());
            return;
        }
    };
    // Best listener-side approximation of the dial address for the
    // reply-source domain rewrite. `metadata.dst_ip` is the PRE-dial
    // resolution: a DIRECT outbound with `dns.direct-nameserver` may
    // re-resolve the domain to a different address and connect() its
    // socket there, making the rewrite attribute replies to the wrong
    // source. The exact answer requires the outbound conn to expose its
    // bound peer — see the F12 interface note in the module docs; until
    // then the pre-dial IP is the closest available evidence, correct
    // whenever the dial truly used it and for every remote-resolution
    // proxy (whose real source goes on the wire unchanged anyway).
    let dialed_ip = metadata.dst_ip;

    // Reply reader, writer, flush watch and idle deadline — ALL polled
    // as plain futures inside THIS task: whichever ends first retires
    // the flow, and a task abort drops BOTH arms plus the conn guard —
    // nothing survives to double-await or detach holding the UDP conn.
    // One byte past the wire cap is the oversize probe. Raw UDP
    // encapsulations receive their wire headers in this same buffer, so
    // those paths add bounded headroom: a cap-sized payload still fits
    // complete and a kernel-truncated oversize one cannot re-enter below
    // the cap. Stream-framed conns reassemble complete datagrams and use
    // only the probe size.
    let read_buf_len = if raw_encapsulated {
        RAW_ENCAPSULATED_REPLY_READ_BUF
    } else {
        PAYLOAD_PROBE_LEN
    };
    let mut rbuf = vec![0u8; read_buf_len];
    let reply = async {
        while let Ok((m, src)) = conn.read_packet(&mut rbuf).await {
            // NOTE(F11): stream-framed conns (plain VLESS, mux) consume an
            // oversized datagram WHOLE before erroring, so their error
            // here is recoverable — the framing is intact and only this
            // packet should drop. `ProxyPacketConn` currently exposes no
            // way to distinguish that case from a fatal transport error,
            // so every error retires the flow; the next uplink datagram
            // respawns it. The cross-crate interface needed is documented
            // in the module docs.
            let wire_source = reply_source(&target, dialed_ip, src);
            // Reserve exactly the frame's bytes before allocating/copying
            // it; encoding first would pay the allocation while the meter
            // is already full.
            let Some(frame_len) = encoded_reply_keep_data_len(Some(&wire_source), m) else {
                debug!(
                    "vless xudp flow to {dst_addr}: dropping unencodable reply ({} bytes)",
                    m
                );
                continue;
            };
            let Some(charge) = MeterCharge::acquire(&meter, frame_len) else {
                debug!("vless xudp flow to {dst_addr}: byte budget exhausted, dropping reply");
                continue;
            };
            let Some(frame) = encode_reply_keep_data(sid, Some(&wire_source), &rbuf[..m]) else {
                continue;
            };
            debug_assert_eq!(frame.len(), frame_len);
            // Blocking send — bounded by EGRESS_QUEUE frames — applies
            // per-flow backpressure when the client stalls reading; the
            // write arm parking with it is the UoT cascade by design.
            if out_tx
                .send(EgressFrame::precharged(
                    frame,
                    EgressKind::Data {
                        gen: Arc::clone(&gen),
                    },
                    charge,
                ))
                .await
                .is_err()
            {
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

#[cfg(test)]
mod tests {
    use super::*;
    use meow_proxy::mux::xudp::XudpFrame;
    use meow_proxy::vless_inbound::VisionServerMode;

    #[test]
    fn meter_reserve_is_exact_and_refuses_beyond_the_shared_budget() {
        let meter = Arc::new(AtomicUsize::new(0));
        let first = MeterCharge::acquire(&meter, CONN_QUEUE_BYTES - 7).unwrap();
        assert_eq!(meter.load(Ordering::Relaxed), CONN_QUEUE_BYTES - 7);
        assert!(MeterCharge::acquire(&meter, 8).is_none());
        let second = MeterCharge::acquire(&meter, 7).unwrap();
        assert_eq!(meter.load(Ordering::Relaxed), CONN_QUEUE_BYTES);
        assert!(MeterCharge::acquire(&meter, 1).is_none());
        drop(first);
        assert_eq!(meter.load(Ordering::Relaxed), 7);
        drop(second);
        assert_eq!(meter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn meter_reserve_stays_bounded_under_concurrent_charges() {
        let meter = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let meter = Arc::clone(&meter);
            threads.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    if let Some(charge) = MeterCharge::acquire(&meter, 1024) {
                        assert!(
                            meter.load(Ordering::Relaxed) <= CONN_QUEUE_BYTES,
                            "concurrent reservations overran the byte budget"
                        );
                        drop(charge);
                    }
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(meter.load(Ordering::Relaxed), 0);
    }

    // --- in-memory association harness -------------------------------------
    //
    // A VisionServerConn cannot tell TLS apart from a duplex pipe: the
    // codec only needs an AsyncRead+AsyncWrite stream. Joining two
    // independent duplex pairs gives the test one-directional control no
    // real socket offers — the server→client direction can die while the
    // client→server direction verifiably stays open, which is exactly the
    // failure asymmetry the association supervisor must handle.

    struct Joined<R, W> {
        r: R,
        w: W,
    }

    impl<R: tokio::io::AsyncRead + Unpin, W: Unpin> tokio::io::AsyncRead for Joined<R, W> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.r).poll_read(cx, buf)
        }
    }

    impl<R: Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Joined<R, W> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.w).poll_write(cx, data)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.w).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.w).poll_shutdown(cx)
        }
    }

    const HARNESS_UUID: [u8; 16] = [0x11; 16];

    /// The client end of the harness: writes vision-framed XUDP upstream,
    /// reads (or deliberately drops) the downlink.
    struct HarnessClient {
        up: tokio::io::DuplexStream,
        down: Option<tokio::io::DuplexStream>,
        first_sent: bool,
    }

    fn xudp_harness(pipe: usize) -> (VisionServerConn, HarnessClient) {
        let (client_up, server_up) = tokio::io::duplex(pipe);
        let (server_down, client_down) = tokio::io::duplex(pipe);
        let stream: Box<dyn meow_transport::Stream> = Box::new(Joined {
            r: server_up,
            w: server_down,
        });
        let conn = VisionServerConn::new(stream, HARNESS_UUID, VisionServerMode::Xudp);
        (
            conn,
            HarnessClient {
                up: client_up,
                down: Some(client_down),
                first_sent: false,
            },
        )
    }

    impl HarnessClient {
        /// Send one batch of XUDP bytes as a single CONTINUE vision frame
        /// (zero padding — legal on the wire).
        async fn send_xudp(&mut self, xudp: &[u8]) -> std::io::Result<()> {
            let mut frame = Vec::new();
            if !self.first_sent {
                frame.extend_from_slice(&HARNESS_UUID);
                self.first_sent = true;
            }
            frame.push(0x00);
            frame.extend_from_slice(&(xudp.len() as u16).to_be_bytes());
            frame.extend_from_slice(&0u16.to_be_bytes());
            frame.extend_from_slice(xudp);
            self.up.write_all(&frame).await?;
            self.up.flush().await
        }

        /// Kill ONLY the server→client direction: the server's writes
        /// fail while its reads keep flowing — the asymmetric teardown
        /// trigger real sockets cannot reproduce in-process.
        fn drop_downlink(&mut self) {
            self.down.take();
        }

        /// Deframe everything readable until `quiet` passes with no new
        /// bytes, returning the decoded XUDP frames.
        async fn collect_frames(&mut self, quiet: Duration) -> Vec<XudpFrame> {
            let mut frames = Vec::new();
            let mut deframer = HarnessDeframer::new();
            let mut decoder = XudpDecoder::new();
            let Some(down) = self.down.as_mut() else {
                return frames;
            };
            loop {
                let mut buf = [0u8; 8192];
                match tokio::time::timeout(quiet, down.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let mut content = Vec::new();
                        deframer.feed(&buf[..n], &mut content);
                        if !content.is_empty() && decoder.feed(&content).is_ok() {
                            while let Some(f) = decoder.next_frame() {
                                frames.push(f);
                            }
                        }
                    }
                    _ => break,
                }
            }
            frames
        }
    }

    /// The downlink vision deframer: strips the two response bytes, the
    /// uuid, per-frame headers and padding, passing content through.
    struct HarnessDeframer {
        resp_left: usize,
        uuid_left: usize,
        hdr: [u8; 5],
        hdr_filled: usize,
        cmd: u8,
        content_left: usize,
        pad_left: usize,
        raw: bool,
    }

    impl HarnessDeframer {
        fn new() -> Self {
            Self {
                resp_left: 2,
                uuid_left: 16,
                hdr: [0; 5],
                hdr_filled: 0,
                cmd: 0,
                content_left: 0,
                pad_left: 0,
                raw: false,
            }
        }

        fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
            while !input.is_empty() {
                if self.raw {
                    out.extend_from_slice(input);
                    return;
                }
                if self.resp_left > 0 {
                    let take = self.resp_left.min(input.len());
                    self.resp_left -= take;
                    input = &input[take..];
                    continue;
                }
                if self.uuid_left > 0 {
                    let take = self.uuid_left.min(input.len());
                    self.uuid_left -= take;
                    input = &input[take..];
                    continue;
                }
                if self.hdr_filled < 5 {
                    let take = (5 - self.hdr_filled).min(input.len());
                    self.hdr[self.hdr_filled..self.hdr_filled + take]
                        .copy_from_slice(&input[..take]);
                    self.hdr_filled += take;
                    input = &input[take..];
                    if self.hdr_filled == 5 {
                        self.cmd = self.hdr[0];
                        self.content_left = u16::from_be_bytes([self.hdr[1], self.hdr[2]]) as usize;
                        self.pad_left = u16::from_be_bytes([self.hdr[3], self.hdr[4]]) as usize;
                    }
                    continue;
                }
                if self.content_left > 0 {
                    let take = self.content_left.min(input.len());
                    out.extend_from_slice(&input[..take]);
                    self.content_left -= take;
                    input = &input[take..];
                    continue;
                }
                if self.pad_left > 0 {
                    let take = self.pad_left.min(input.len());
                    self.pad_left -= take;
                    input = &input[take..];
                    continue;
                }
                if self.cmd != 0 {
                    self.raw = true;
                }
                self.hdr_filled = 0;
            }
        }
    }

    // --- client-side XUDP frame crafting (the integration harness shapes) ---

    fn xudp_frame(
        sid: u16,
        status: u8,
        option: u8,
        extra_meta: &[u8],
        payload: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut meta = Vec::new();
        meta.extend_from_slice(&sid.to_be_bytes());
        meta.push(status);
        meta.push(option);
        meta.extend_from_slice(extra_meta);
        let mut out = Vec::new();
        out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
        out.extend_from_slice(&meta);
        if let Some(p) = payload {
            out.extend_from_slice(&(p.len() as u16).to_be_bytes());
            out.extend_from_slice(p);
        }
        out
    }

    fn v4_target_bytes(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut m = vec![0x02];
        m.extend_from_slice(&port.to_be_bytes());
        m.push(0x01);
        m.extend_from_slice(&ip);
        m
    }

    fn new_data(sid: u16, target_meta: &[u8], payload: &[u8]) -> Vec<u8> {
        xudp_frame(sid, 0x01, 0x01, target_meta, Some(payload))
    }

    fn keep_data(sid: u16, payload: &[u8]) -> Vec<u8> {
        xudp_frame(sid, 0x02, 0x01, &[], Some(payload))
    }

    fn end_frame(sid: u16) -> Vec<u8> {
        xudp_frame(sid, 0x03, 0x00, &[], None)
    }

    // --- probe outbound ----------------------------------------------------

    struct HarnessProbe {
        dials: AtomicUsize,
        closes: AtomicUsize,
        writes: AtomicUsize,
        inject: tokio::sync::broadcast::Sender<(Bytes, SocketAddr)>,
    }

    struct HarnessProbeConn {
        probe: Arc<HarnessProbe>,
        replies: tokio::sync::broadcast::Receiver<(Bytes, SocketAddr)>,
    }

    #[async_trait::async_trait]
    impl ProxyPacketConn for HarnessProbeConn {
        async fn read_packet(&self, buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            let mut replies = self.replies.resubscribe();
            loop {
                match replies.recv().await {
                    Ok((bytes, src)) => {
                        if bytes.len() > buf.len() {
                            continue;
                        }
                        buf[..bytes.len()].copy_from_slice(&bytes);
                        return Ok((bytes.len(), src));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return std::future::pending().await;
                    }
                }
            }
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> meow_common::Result<usize> {
            self.probe.writes.fetch_add(1, Ordering::Relaxed);
            Ok(buf.len())
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
        fn close(&self) -> meow_common::Result<()> {
            self.probe.closes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct HarnessProbeProxy {
        probe: Arc<HarnessProbe>,
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for HarnessProbeProxy {
        fn name(&self) -> &str {
            "harness-probe"
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
            self.probe.dials.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(HarnessProbeConn {
                probe: Arc::clone(&self.probe),
                replies: self.probe.inject.subscribe(),
            }))
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for HarnessProbeProxy {
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

    fn harness_probe() -> (Arc<HarnessProbe>, meow_tunnel::Tunnel) {
        let probe = Arc::new(HarnessProbe {
            dials: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            inject: tokio::sync::broadcast::channel(64).0,
        });
        let resolver = Arc::new(meow_dns::Resolver::new(
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
            "harness-probe".into(),
            Arc::new(HarnessProbeProxy {
                probe: Arc::clone(&probe),
                health: meow_common::ProxyHealth::new(),
            }) as Arc<dyn meow_common::Proxy>,
        );
        tunnel.update_proxies(proxies, res.dialer_registry);
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "harness-probe",
        ))]);
        (probe, tunnel)
    }

    /// The context borrows strings, so the static association task needs
    /// statics behind them — leaking a few bytes once per test binary.
    fn harness_ctx() -> XudpFlowCtx<'static> {
        XudpFlowCtx {
            peer: "10.0.0.2:51000".parse().unwrap(),
            in_name: "vless-harness",
            in_port: 1443,
            user: Box::leak(Box::new(SmolStr::from("alice"))),
            route_override: None,
        }
    }

    async fn wait_for(cond: impl Fn() -> bool, what: &str) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn harness_positive_control_new_data_dials() {
        let (conn, mut client) = xudp_harness(4096);
        let (probe, tunnel) = harness_probe();
        let _assoc = tokio::spawn(run_xudp_conn(
            conn,
            Arc::clone(tunnel.inner()),
            harness_ctx(),
            tokio::time::Instant::now() + Duration::from_secs(60),
        ));
        client
            .send_xudp(&new_data(5, &v4_target_bytes([127, 0, 0, 1], 15353), b"hi"))
            .await
            .unwrap();
        wait_for(
            || probe.dials.load(Ordering::Relaxed) == 1,
            "the control flow's dial",
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_death_tears_down_the_association() {
        let (conn, mut client) = xudp_harness(4096);
        let (probe, tunnel) = harness_probe();
        let mut assoc = tokio::spawn(run_xudp_conn(
            conn,
            Arc::clone(tunnel.inner()),
            harness_ctx(),
            tokio::time::Instant::now() + Duration::from_secs(60),
        ));

        // The downlink is alive: an unknown-sid datagram is answered and
        // written without error.
        client.send_xudp(&keep_data(77, b"x")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!assoc.is_finished(), "association must be live");

        // Kill only the server→client direction, then give the writer a
        // frame to fail on.
        client.drop_downlink();
        let _ = client.send_xudp(&keep_data(78, b"x")).await;
        tokio::time::sleep(Duration::from_millis(250)).await;

        // The deterministic signal: the association task itself must
        // retire promptly once its downlink is unwritable — not at the
        // 30s idle sweep, not at peer EOF. The uplink side is verifiably
        // still open (the writes above succeeded), so retirement can only
        // come from supervising the writer.
        tokio::time::timeout(Duration::from_secs(2), &mut assoc)
            .await
            .expect("association survived its dead writer — uplink work would be accepted but never answered")
            .unwrap();

        // And the mechanism-level consequence: a fresh New+Data finds no
        // living association, so nothing ever dials.
        let _ = client
            .send_xudp(&new_data(5, &v4_target_bytes([127, 0, 0, 1], 15353), b"hi"))
            .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            probe.dials.load(Ordering::Relaxed),
            0,
            "association kept accepting uplink datagrams after its downlink writer died"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_generation_replies_never_reach_a_reused_sid() {
        let (conn, mut client) = xudp_harness(2048);
        let (probe, tunnel) = harness_probe();
        let _assoc = tokio::spawn(run_xudp_conn(
            conn,
            Arc::clone(tunnel.inner()),
            harness_ctx(),
            tokio::time::Instant::now() + Duration::from_secs(60),
        ));
        let target_meta = v4_target_bytes([127, 0, 0, 1], 15353);
        let target_addr: SocketAddr = "127.0.0.1:15353".parse().unwrap();

        // First generation: one flow, one uplink write.
        client
            .send_xudp(&new_data(5, &target_meta, b"uplink1"))
            .await
            .unwrap();
        wait_for(
            || probe.writes.load(Ordering::Relaxed) == 1,
            "the first flow write",
        )
        .await;

        // A big reply overfills the small downlink pipe, parking the
        // writer mid-frame; the stale reply queues behind it.
        probe
            .inject
            .send((Bytes::from(vec![0x42u8; 6000]), target_addr))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        probe
            .inject
            .send((Bytes::from_static(b"stale"), target_addr))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // End the session and immediately reopen the same sid with the
        // same target: generation two, one fresh flow.
        client.send_xudp(&end_frame(5)).await.unwrap();
        client
            .send_xudp(&new_data(5, &target_meta, b"uplink2"))
            .await
            .unwrap();
        wait_for(
            || probe.writes.load(Ordering::Relaxed) == 2,
            "the second generation's flow write",
        )
        .await;
        probe
            .inject
            .send((Bytes::from_static(b"fresh"), target_addr))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let frames = client.collect_frames(Duration::from_millis(500)).await;
        let payloads: Vec<&[u8]> = frames
            .iter()
            .filter_map(|f| match f {
                XudpFrame::Keep {
                    payload: Some(p), ..
                } => Some(p.as_ref()),
                _ => None,
            })
            .collect();
        assert!(
            payloads.iter().any(|p| *p == b"fresh"),
            "the live generation's reply must arrive: {payloads:?}"
        );
        assert!(
            !payloads.iter().any(|p| *p == b"stale"),
            "a reply the dead generation queued before End must never reach the reused sid"
        );
        assert!(
            payloads.iter().any(|p| p.len() == 6000),
            "the frame already mid-write when End landed must complete intact: lengths {:?}",
            payloads.iter().map(|p| p.len()).collect::<Vec<_>>()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn byte_budget_refusal_neither_spawns_nor_dials() {
        let (probe, tunnel) = harness_probe();
        let flows: Arc<parking_lot::Mutex<HashMap<FlowKey, XudpFlow>>> =
            Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let meter = Arc::new(AtomicUsize::new(0));
        let (out_tx, _out_rx) = mpsc::channel::<EgressFrame>(EGRESS_QUEUE);
        let ctx = harness_ctx();
        let peer = ctx.peer;
        let target = XudpTarget {
            addr: XudpAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            port: 15353,
        };
        let gen = Arc::new(SessionGen(AtomicBool::new(true)));

        // With the shared meter fully charged, a datagram for a brand-new
        // (sid, target) must drop without touching the flow table at all.
        let filler = MeterCharge::acquire(&meter, CONN_QUEUE_BYTES).unwrap();
        deliver_or_spawn(
            &flows,
            tunnel.inner(),
            7,
            &target,
            Bytes::from_static(b"x"),
            &ctx,
            &out_tx,
            &meter,
            Arc::clone(&gen),
            peer,
        );
        assert!(
            flows.lock().is_empty(),
            "a datagram the byte budget refused still spawned a flow"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            probe.dials.load(Ordering::Relaxed),
            0,
            "a datagram the byte budget refused still triggered a dial"
        );

        // Releasing the budget admits the same delivery: one spawn, one dial.
        drop(filler);
        deliver_or_spawn(
            &flows,
            tunnel.inner(),
            7,
            &target,
            Bytes::from_static(b"x"),
            &ctx,
            &out_tx,
            &meter,
            gen,
            peer,
        );
        assert_eq!(flows.lock().len(), 1);
        wait_for(
            || probe.dials.load(Ordering::Relaxed) == 1,
            "the admitted flow's dial",
        )
        .await;
    }

    #[test]
    fn target_key_merges_domain_case_without_rewriting_addresses() {
        let port = 53;
        let lower = XudpTarget {
            addr: XudpAddr::Domain("echo.test".into()),
            port,
        };
        let mixed = XudpTarget {
            addr: XudpAddr::Domain("EcHo.TeSt".into()),
            port,
        };
        assert_eq!(TargetKey::of(&lower), TargetKey::of(&mixed));

        let v4 = XudpTarget {
            addr: XudpAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            port,
        };
        assert_ne!(TargetKey::of(&lower), TargetKey::of(&v4));
    }
}
