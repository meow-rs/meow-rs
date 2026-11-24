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
    let mut writer = {
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
                let now = now_ms();
                let idle = idle_ms();
                let mut table = sessions.lock();
                table.retain(|_, s| {
                    let keep = now.wrapping_sub(s.last_activity.load(Ordering::Relaxed)) < idle;
                    if !keep {
                        s.dead.store(true, Ordering::Relaxed);
                        s.task.abort();
                    }
                    keep
                });
            }
        }
    });

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
                    s.last_activity.store(now_ms(), Ordering::Relaxed);
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
                                .min_by_key(|(_, s)| s.last_activity.load(Ordering::Relaxed))
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
    // stream's FIN.
    {
        let mut table = sessions.lock();
        for (_, s) in table.drain() {
            s.dead.store(true, Ordering::Relaxed);
            s.task.abort();
        }
    }
    sweeper.abort();
    drop(out_tx);
    if let Ok(w) = (&mut writer).await {
        w.close();
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

    // Reply reader: `read_packet` → UoT-encode → ordered writer. The
    // encode carries the real source for Bind and nothing extra for
    // Connect. A read failure is session death (issue #514's shape).
    let reply = tokio::spawn({
        let conn = Arc::clone(&conn);
        let last_activity = Arc::clone(&last_activity);
        async move {
            let mut rbuf = vec![0u8; 65535];
            while let Ok((m, src)) = conn.read_packet(&mut rbuf).await {
                let pkt = match reply_form {
                    ReplyForm::Connect => uot::encode_uot_packet_simple(&rbuf[..m]),
                    ReplyForm::Bind => uot::encode_uot_packet_from(&rbuf[..m], &src),
                };
                let Ok(pkt) = pkt else { break };
                if out_tx.send(pkt).await.is_err() {
                    break;
                }
                last_activity.store(now_ms(), Ordering::Relaxed);
            }
        }
    });

    // Writer: queued datagrams → `write_packet` at the resolved dst.
    // Receive, send and the flush watch sit in ONE cancellation scope:
    // whichever direction ends first retires the whole session and the
    // other direction is reaped below — a dead reply reader must not
    // leave the writer parked on `rx` holding the UDP conn.
    let writer = async {
        loop {
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
                        match conn.write_packet(payload, &dst_addr).await {
                            Ok(n) if n == payload.len() => {
                                last_activity.store(now_ms(), Ordering::Relaxed);
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
                _ = tokio::time::sleep(meow_tunnel::udp::DEFAULT_UDP_IDLE) => {
                    // Own idle deadline — the sweeper is a backstop;
                    // sleeping sessions must still retire so the next
                    // datagram re-dials.
                    break;
                }
            }
        }
    };
    let _ = &dead; // read by the dispatcher; this task exits via its own arms
    tokio::pin!(writer);
    let mut reply = reply;
    tokio::select! {
        _ = &mut reply => {}
        _ = &mut writer => {}
    }
    // Reap the surviving direction: abort then join so the UDP conn and
    // its senders drop inside this task's teardown, not at some lazy GC
    // point.
    reply.abort();
    let _ = reply.await;
    let _ = conn.close();
}
