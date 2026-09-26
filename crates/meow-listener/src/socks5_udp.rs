//! SOCKS5 inbound `CMD UDP ASSOCIATE` (RFC 1928 §7) — relays client UDP
//! (incl. QUIC / HTTP/3) through the tunnel's routing engine.
//!
//! Lifecycle: the association is bound to the TCP control connection. We bind a
//! UDP relay socket on the same local IP the client reached us on, return its
//! address in the reply, then relay until the control connection closes (at
//! which point this future returns and every per-destination outbound conn +
//! reply task is dropped).
//!
//! Routing mirrors `meow_tunnel::udp::handle_udp`: fake-IP rewrite → pre-resolve
//! → rule match → `dial_udp`. A bounded per-association
//! NAT (`SessionKey -> session`, keying on address or hostname) dedups outbound
//! conns; each session task performs its own dial then writes queued datagrams
//! in order while a nested reply task pumps server→client traffic back.

use meow_common::atomic::AtomicU;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use meow_common::{with_dial_timeout, ConnType, Metadata, Network};
use meow_tunnel::{ResolvedTarget, Tunnel, TunnelInner};
use smallvec::SmallVec;
use smol_str::SmolStr;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::monotonic_ms;

const SOCKS5_VERSION: u8 = 0x05;
const REP_SUCCESS: u8 = 0x00;
const RESERVED: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const NAT_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Per-session client→upstream queue. Datagrams arriving while a session is
/// still establishing (resolve + route + `dial_udp`) queue here; overflow is
/// dropped (UDP semantics — the client retries).
const SESSION_QUEUE: usize = 64;
/// Bound on concurrent outbound sessions per association. A unique-tuple
/// flood must not grow the NAT map without bound; at the cap the
/// least-recently-active session is evicted (same LRU-idle policy the
/// sweeper applies on a timer).
const MAX_SESSIONS: usize = 1024;

/// NAT key for a per-destination session. Literal-IP destinations key by
/// socket address (zero allocation on the per-datagram path); domain-form
/// destinations key by the already-lowercased `SmolStr` host plus port —
/// cloning it is an inline copy or refcount bump, not a `format!` alloc.
/// Resolution happens inside the session task, so a slow lookup can no
/// longer stall the read loop.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SessionKey {
    Addr(SocketAddr),
    Host(SmolStr, u16),
}

/// Per-destination outbound session within one association. The read loop
/// never awaits a dial or an upstream write: payloads are queued onto `tx`
/// and the session task performs resolution, routing, `dial_udp`, and the
/// ordered write loop off-loop (issue #515 — a slow destination must not
/// head-of-line block the whole association).
struct Session {
    tx: mpsc::Sender<SmallVec<[u8; 1500]>>,
    last_activity_ms: Arc<AtomicU>,
    /// Set when the session task exits for any reason: the session can no
    /// longer deliver traffic either way, so it must be re-dialed rather
    /// than kept (issue #514).
    dead: Arc<AtomicBool>,
    /// Session task (establish → writer loop; owns the reply reader).
    task: tokio::task::AbortHandle,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Handle a SOCKS5 UDP ASSOCIATE request. `control` is the TCP control
/// connection (request already consumed by the caller). An advertised source
/// endpoint is honored when compatible with the authenticated TCP peer;
/// otherwise the first valid UDP datagram locks the association endpoint.
/// `inbound` carries the listener identity and authenticated username for the
/// association. Cloning its SmolStr fields never allocates per datagram.
pub async fn handle_udp_associate(
    tunnel: &Tunnel,
    mut control: TcpStream,
    src_addr: SocketAddr,
    requested_ip: Option<IpAddr>,
    requested_port: u16,
    inbound: &Metadata,
) -> io::Result<()> {
    // Bind the relay on the same local IP the client reached us on, so the
    // address we hand back is reachable by the client.
    let local_ip = control.local_addr()?.ip();
    let relay = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    let bnd = relay.local_addr()?;

    write_associate_reply(&mut control, bnd).await?;
    debug!("SOCKS5 UDP ASSOCIATE from {src_addr}: relay bound on {bnd}");

    let inner = Arc::clone(tunnel.inner());
    let mut nat: HashMap<SessionKey, Session> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut ctrl_buf = [0u8; 16];
    let requested_ip = requested_ip.filter(|ip| !ip.is_unspecified());
    let mut client_endpoint = match (requested_ip, requested_port) {
        (Some(ip), port) if ip == src_addr.ip() && port != 0 => Some(SocketAddr::new(ip, port)),
        (None, port) if port != 0 => Some(SocketAddr::new(src_addr.ip(), port)),
        _ => None,
    };
    let mut sweeper = tokio::time::interval(NAT_SWEEP_INTERVAL);
    sweeper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // A persistent recv failure must not spin the select; the in-arm sleep
    // stalls the sibling arms at most ~1s while a persistently-erroring
    // socket can do no useful work anyway. Per-packet errors (ICMP async
    // delivery) skip the delay inside `failed`.
    let mut recv_backoff = meow_common::ErrorBackoff::new();

    loop {
        tokio::select! {
            // The association ends when the control connection closes.
            r = control.read(&mut ctrl_buf) => {
                match r {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {} // ignore unexpected control-channel bytes
                }
            }
            r = relay.recv_from(&mut buf) => {
                let (n, client) = match r {
                    Ok(v) => {
                        recv_backoff.succeeded();
                        v
                    }
                    Err(e) => {
                        // Loud only when the backoff engaged — per-packet
                        // async-ICMP errors stay at debug!.
                        if recv_backoff.failed(&e).await {
                            warn!("SOCKS5 UDP recv error: {e}");
                        } else {
                            debug!("SOCKS5 UDP recv error: {e}");
                        }
                        continue;
                    }
                };
                if client.ip() != src_addr.ip() {
                    debug!("SOCKS5 UDP ignoring source {client}: TCP peer is {src_addr}");
                    continue;
                }
                match client_endpoint {
                    Some(expected) if client != expected => {
                        debug!("SOCKS5 UDP ignoring source {client}: association is bound to {expected}");
                        continue;
                    }
                    None => {
                        // Do not let a malformed packet claim the association.
                        if let Err(e) = parse_udp_request(&buf[..n]) {
                            debug!("SOCKS5 UDP datagram from {client}: {e}");
                            continue;
                        }
                        client_endpoint = Some(client);
                    }
                    Some(_) => {}
                }
                // Never `.await` here: session establishment (resolve → route
                // → `dial_udp`) runs inside the per-destination session task,
                // so one slow or black-holed destination cannot head-of-line
                // block the rest of the association (issue #515).
                if let Err(e) =
                    handle_client_datagram(&inner, &relay, &mut nat, &buf[..n], client, inbound)
                {
                    debug!("SOCKS5 UDP datagram from {client}: {e}");
                }
            }
            _ = sweeper.tick() => {
                let idle_ms = meow_tunnel::udp::DEFAULT_UDP_IDLE.as_millis() as u64;
                nat.retain(|_, session| {
                    // A dead session (task exited — dial failure, write
                    // error, or reply-reader death) is evicted promptly
                    // instead of waiting for its next datagram.
                    if session.dead.load(Ordering::Relaxed) {
                        return false;
                    }
                    let now = monotonic_ms() as meow_common::atomic::Uint;
                    let last = session.last_activity_ms.load(Ordering::Relaxed);
                    #[allow(
                        clippy::useless_conversion,
                        reason = "identity on 64-bit; u32→u64 widening on mips32"
                    )]
                    let elapsed = u64::from(now.wrapping_sub(last));
                    elapsed < idle_ms
                });
            }
        }
    }

    debug!(
        "SOCKS5 UDP ASSOCIATE from {src_addr} closed; tearing down {} sessions",
        nat.len()
    );
    Ok(())
}

/// Parse one inbound datagram and hand its payload to the per-destination
/// session — creating that session's task on first use. Runs synchronously
/// on the read loop: it never awaits resolution, routing, or `dial_udp`
/// (issue #515). Per-destination ordering is preserved because every
/// payload for a destination travels the same FIFO queue.
fn handle_client_datagram(
    inner: &Arc<TunnelInner>,
    relay: &Arc<UdpSocket>,
    nat: &mut HashMap<SessionKey, Session>,
    datagram: &[u8],
    client: SocketAddr,
    inbound: &Metadata,
) -> Result<(), String> {
    let (dst_ip, host, dst_port, data_off) = parse_udp_request(datagram)?;
    if dst_ip.is_none() && host.is_empty() {
        return Err("UDP request with neither IP nor domain".into());
    }
    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Socks5,
        src_ip: Some(client.ip()),
        src_port: client.port(),
        dst_ip,
        dst_port,
        host: Metadata::lower_host(&host),
        in_name: inbound.in_name.clone(),
        in_port: inbound.in_port,
        in_user: inbound.in_user.clone(),
        ..Default::default()
    };

    // Drop an unmapped fake-IP destination before it spawns a session —
    // a stale-datagram flood would otherwise churn a spawn+evict per
    // packet (issue #618). The call also folds a domain-typed literal
    // (`ATYP_DOMAIN "198.18.0.9"`) into `dst_ip` and rescues via a
    // surviving name; it is idempotent, and the session task re-checks.
    if matches!(
        inner.pre_handle_metadata(&mut metadata),
        meow_tunnel::PreHandleVerdict::Drop
    ) {
        debug!("socks5 udp: drop datagram to unmapped fake-ip {dst_ip:?}:{dst_port}");
        return Ok(());
    }

    // Domain-form destinations key the session by `host:port`: resolution
    // happens inside the session task, so a slow lookup cannot stall the
    // read loop, and the session pins the resolved address for its life
    // (the old per-datagram resolution could churn connections on DNS
    // round-robin — pinning is what QUIC wants). Two names resolving to
    // one address now get independent sessions — same routing semantics,
    // slightly finer dedup granularity. The key is built from the
    // lowercased `metadata.host` so `EXAMPLE.com` and `example.com` share
    // one session.
    let key = match metadata.dst_ip {
        Some(ip) => SessionKey::Addr(SocketAddr::new(ip, dst_port)),
        None => SessionKey::Host(metadata.host.clone(), dst_port),
    };

    if let Some(session) = nat.get(&key) {
        // A dead session (task exited — dial failure, write error, or
        // upstream close) is evicted so this datagram starts a fresh one
        // (issue #514).
        if session.dead.load(Ordering::Relaxed) {
            nat.remove(&key);
        } else {
            // Check capacity before copying the payload onto the queue —
            // a flooded session drops the datagram without paying the copy.
            if session.tx.capacity() == 0 {
                debug!("SOCKS5 UDP session queue full: dropping datagram");
                return Ok(());
            }
            match session
                .tx
                .try_send(SmallVec::from_slice(&datagram[data_off..]))
            {
                Ok(()) => {
                    session.last_activity_ms.store(
                        monotonic_ms() as meow_common::atomic::Uint,
                        Ordering::Relaxed,
                    );
                }
                // Queue filled between the capacity check and the send:
                // drop the datagram (UDP semantics — the client retries; a
                // flooded session must not grow memory unboundedly).
                Err(mpsc::error::TrySendError::Full(_)) => {
                    debug!("SOCKS5 UDP session queue full: dropping datagram");
                }
                // The task exited between the dead check and the send:
                // evict and start a fresh session with this datagram.
                Err(mpsc::error::TrySendError::Closed(payload)) => {
                    nat.remove(&key);
                    return start_session(inner, relay, nat, key, client, metadata, payload);
                }
            }
            return Ok(());
        }
    }

    start_session(
        inner,
        relay,
        nat,
        key,
        client,
        metadata,
        SmallVec::from_slice(&datagram[data_off..]),
    )
}

/// Insert a new session for `key` whose task performs resolution, routing,
/// `dial_udp`, and the ordered client→upstream write loop off the read loop.
/// `first` is the payload that triggered the session (already copied).
fn start_session(
    inner: &Arc<TunnelInner>,
    relay: &Arc<UdpSocket>,
    nat: &mut HashMap<SessionKey, Session>,
    key: SessionKey,
    client: SocketAddr,
    metadata: Metadata,
    first: SmallVec<[u8; 1500]>,
) -> Result<(), String> {
    // Capacity bound: a unique-destination flood must not grow the table
    // without bound.
    if nat.len() >= MAX_SESSIONS {
        evict_for_admission(nat);
    }

    let (tx, rx) = mpsc::channel(SESSION_QUEUE);
    tx.try_send(first)
        .map_err(|_| "fresh session queue rejected payload".to_string())?;

    let last_activity_ms = Arc::new(AtomicU::new(monotonic_ms() as meow_common::atomic::Uint));
    let dead = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn(run_session(
        Arc::clone(inner),
        Arc::clone(relay),
        metadata,
        client,
        rx,
        Arc::clone(&last_activity_ms),
        Arc::clone(&dead),
    ))
    .abort_handle();

    nat.insert(
        key,
        Session {
            tx,
            last_activity_ms,
            dead,
            task,
        },
    );
    Ok(())
}

/// Make room for one new session (issue #515): dead entries are reclaimed
/// first — a dead session can no longer deliver traffic either way — then,
/// if the table is still at `MAX_SESSIONS`, the least-recently-active live
/// session is evicted (the same LRU-idle policy the sweeper applies on a
/// timer). Dropping the evicted `Session` aborts its task, which tears
/// down the reply reader and the outbound conn.
fn evict_for_admission(nat: &mut HashMap<SessionKey, Session>) {
    nat.retain(|_, s| !s.dead.load(Ordering::Relaxed));
    if nat.len() >= MAX_SESSIONS {
        if let Some(oldest) = nat
            .iter()
            .min_by_key(|(_, s)| s.last_activity_ms.load(Ordering::Relaxed))
            .map(|(k, _)| k.clone())
        {
            nat.remove(&oldest);
        }
    }
}

/// One destination's outbound session: resolve → route → `dial_udp`, then
/// write queued client datagrams in order while a reply task pumps
/// server→client traffic back. Exiting for any reason marks `dead` so the
/// next datagram re-establishes (issue #514).
async fn run_session(
    inner: Arc<TunnelInner>,
    relay: Arc<UdpSocket>,
    mut metadata: Metadata,
    client: SocketAddr,
    mut rx: mpsc::Receiver<SmallVec<[u8; 1500]>>,
    last_activity_ms: Arc<AtomicU>,
    dead: Arc<AtomicBool>,
) {
    // Guard: whatever happens below, mark the session dead on exit so the
    // read loop evicts it instead of queueing into a closed channel.
    struct DeadOnExit(Arc<AtomicBool>);
    impl Drop for DeadOnExit {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let _dead_guard = DeadOnExit(Arc::clone(&dead));

    let outcome = async {
        if matches!(
            inner.pre_handle_metadata(&mut metadata),
            meow_tunnel::PreHandleVerdict::Drop
        ) {
            return Err("unmapped fake-ip destination".into());
        }
        // UDP keeps the eager pre_resolve (no lazy enrichment): the writer
        // needs a resolved dst_ip regardless of what the rules demand.
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

        // Client UDP follows the configured routing policy, including port 53.
        // `_route` pins this generation's dialer registry across `dial_udp`
        // (issue #533 review).
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
            client,
            metadata.remote_address(),
            rule_name,
            rule_payload,
            proxy.name()
        );

        let conn: Arc<dyn meow_common::ProxyPacketConn> = Arc::from(
            with_dial_timeout(proxy.name(), proxy.dial_udp(&metadata))
                .await
                .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?,
        );
        Ok((conn, dst_addr))
    }
    .await;

    let (conn, dst_addr) = match outcome {
        Ok(v) => v,
        Err(e) => {
            // Computed after enrichment so a fake-IP destination logs its
            // recovered hostname rather than the 198.18.x.x literal.
            debug!("SOCKS5 UDP session to {}: {e}", metadata.remote_address());
            return;
        }
    };

    // Reply reader: server→client. Wraps each datagram in the SOCKS5 UDP
    // header and sends it back to the client's UDP source address. The
    // `select!` below treats its exit as session death (a conn that cannot
    // deliver replies must be re-dialed, issue #514); the AbortOnDrop guard
    // kills it if the session task is aborted first.
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut reply_task = tokio::spawn({
        let conn = Arc::clone(&conn);
        let last_activity_ms = Arc::clone(&last_activity_ms);
        async move {
            let mut rbuf = vec![0u8; 65535];
            while let Ok((m, src)) = conn.read_packet(&mut rbuf).await {
                let mut out: SmallVec<[u8; 1500]> = SmallVec::new();
                encode_udp_header(&mut out, &src);
                out.extend_from_slice(&rbuf[..m]);
                if relay.send_to(&out, client).await.is_err() {
                    break;
                }
                last_activity_ms.store(
                    monotonic_ms() as meow_common::atomic::Uint,
                    Ordering::Relaxed,
                );
            }
        }
    });
    let _reply_guard = AbortOnDrop(reply_task.abort_handle());

    // Writer loop: drain the queue in FIFO order until the session is
    // evicted (all senders gone), the upstream write fails, or the reply
    // reader dies (one-way conn — re-dial on next datagram, issue #514).
    loop {
        tokio::select! {
            queued = rx.recv() => match queued {
                Some(payload) => {
                    if let Err(e) = conn.write_packet(&payload, &dst_addr).await {
                        debug!("SOCKS5 UDP session to {dst_addr}: upstream write: {e}");
                        return;
                    }
                    last_activity_ms.store(
                        monotonic_ms() as meow_common::atomic::Uint,
                        Ordering::Relaxed,
                    );
                }
                None => return, // all senders dropped — session evicted
            },
            done = &mut reply_task => {
                let reason = match done {
                    Ok(()) => "reply reader exited".to_string(),
                    Err(e) => format!("reply reader task: {e}"),
                };
                debug!("SOCKS5 UDP session to {dst_addr}: {reason}; next datagram re-dials");
                return;
            }
        }
    }
}

/// Write the `CMD UDP ASSOCIATE` success reply carrying the relay endpoint.
async fn write_associate_reply(control: &mut TcpStream, bnd: SocketAddr) -> io::Result<()> {
    let mut reply: SmallVec<[u8; 22]> = SmallVec::new();
    reply.extend_from_slice(&[SOCKS5_VERSION, REP_SUCCESS, RESERVED]);
    match bnd.ip() {
        IpAddr::V4(v4) => {
            reply.push(ATYP_IPV4);
            reply.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            reply.push(ATYP_IPV6);
            reply.extend_from_slice(&v6.octets());
        }
    }
    reply.extend_from_slice(&bnd.port().to_be_bytes());
    control.write_all(&reply).await?;
    Ok(())
}

/// Parse a SOCKS5 UDP request header (RFC 1928 §7):
/// `RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT DATA`. Returns
/// `(dst_ip, host, port, data_offset)` — exactly one of `dst_ip`/`host` is set.
fn parse_udp_request(buf: &[u8]) -> Result<(Option<IpAddr>, String, u16, usize), String> {
    if buf.len() < 4 {
        return Err("short UDP request".into());
    }
    // RSV(2) ignored. FRAG must be 0 — we don't reassemble fragments.
    if buf[2] != 0 {
        return Err("fragmented UDP datagram not supported".into());
    }
    let atyp = buf[3];
    let mut pos = 4;
    let (dst_ip, host) = match atyp {
        ATYP_IPV4 => {
            if buf.len() < pos + 4 + 2 {
                return Err("truncated v4 UDP request".into());
            }
            let ip = IpAddr::from([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
            pos += 4;
            (Some(ip), String::new())
        }
        ATYP_IPV6 => {
            if buf.len() < pos + 16 + 2 {
                return Err("truncated v6 UDP request".into());
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            (Some(IpAddr::from(o)), String::new())
        }
        ATYP_DOMAIN => {
            let dlen = *buf.get(4).ok_or("missing domain length")? as usize;
            pos = 5;
            if buf.len() < pos + dlen + 2 {
                return Err("truncated domain UDP request".into());
            }
            let host = std::str::from_utf8(&buf[pos..pos + dlen])
                .map_err(|_| "non-utf8 domain".to_string())?
                .to_string();
            pos += dlen;
            (None, host)
        }
        other => return Err(format!("unknown atyp {other:#04x}")),
    };
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Ok((dst_ip, host, port, pos))
}

/// Encode a SOCKS5 UDP reply header for `addr` (RFC 1928 §7):
/// `RSV(2)=0 FRAG(1)=0 ATYP SRC.ADDR SRC.PORT`. DATA is appended by the caller.
fn encode_udp_header(out: &mut SmallVec<[u8; 1500]>, addr: &SocketAddr) {
    out.extend_from_slice(&[0, 0, 0]); // RSV(2) + FRAG(1)
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock `Proxy` counting `dial_udp` calls; each dial yields a conn whose
    /// reads fail immediately so its reply task exits right away.
    struct FlakyUdpProxy {
        dials: std::sync::atomic::AtomicUsize,
        health: meow_common::ProxyHealth,
    }

    struct DeadReadConn;

    #[async_trait::async_trait]
    impl meow_common::ProxyPacketConn for DeadReadConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            Err(meow_common::MeowError::Proxy("upstream closed".into()))
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> meow_common::Result<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
        fn close(&self) -> meow_common::Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for FlakyUdpProxy {
        fn name(&self) -> &str {
            "flaky-udp"
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
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            self.dials.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(DeadReadConn))
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for FlakyUdpProxy {
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

    /// Spin until `cond` holds or `dur` elapses (for assertions on state
    /// mutated by the spawned session tasks).
    async fn eventually(dur: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + dur;
        while tokio::time::Instant::now() < deadline {
            if cond() {
                return true;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        cond()
    }

    /// Issue #514: when the session task dies (upstream read failure) the
    /// next datagram to that destination must evict it and re-dial rather
    /// than queue into a conn that can never answer.
    #[tokio::test]
    async fn dead_reply_task_session_is_evicted_and_redialed() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let proxy = Arc::new(FlakyUdpProxy {
                dials: std::sync::atomic::AtomicUsize::new(0),
                health: meow_common::ProxyHealth::new(),
            });
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
                "flaky-udp".into(),
                Arc::clone(&proxy) as Arc<dyn meow_common::Proxy>,
            );
            tunnel.update_proxies(proxies, res.dialer_registry);
            tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
                "flaky-udp",
            ))]);

            let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let inner = Arc::clone(tunnel.inner());
            let mut nat: HashMap<SessionKey, Session> = HashMap::new();
            let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();
            let inbound = Metadata::default();
            let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
            let key = SessionKey::Addr(dst);
            let mut packet: SmallVec<[u8; 1500]> = SmallVec::new();
            encode_udp_header(&mut packet, &dst);
            packet.extend_from_slice(b"payload");

            handle_client_datagram(&inner, &relay, &mut nat, &packet, client, &inbound).unwrap();
            assert!(nat.contains_key(&key));
            // The dial runs inside the session task now — wait for it.
            assert!(
                eventually(Duration::from_secs(2), || {
                    proxy.dials.load(Ordering::Relaxed) == 1
                })
                .await,
                "session task never dialed"
            );

            // The reply reader observes the upstream read error and exits;
            // the session task treats that as session death.
            assert!(
                eventually(Duration::from_secs(2), || {
                    nat.get(&key).is_none_or(|s| s.dead.load(Ordering::Relaxed))
                })
                .await,
                "dead flag never set"
            );

            // The next datagram to the same destination must re-dial rather
            // than queue into the dead session.
            handle_client_datagram(&inner, &relay, &mut nat, &packet, client, &inbound).unwrap();
            assert!(
                eventually(Duration::from_secs(2), || {
                    proxy.dials.load(Ordering::Relaxed) == 2
                })
                .await,
                "datagram to a dead session must re-dial"
            );
            assert!(nat.contains_key(&key));
        })
        .await
        .expect("session re-dial timed out");
    }

    /// Mock `Proxy` whose `dial_udp` for port 4443 blocks on a gate while
    /// every other destination dials instantly — reproduces the issue #515
    /// repro where one slow destination stalled the whole association.
    struct GatedDialProxy {
        gate: tokio::sync::Notify,
        dialed_ports: std::sync::Mutex<Vec<u16>>,
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for GatedDialProxy {
        fn name(&self) -> &str {
            "gated-udp"
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
            metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            if metadata.dst_port == 4443 {
                self.gate.notified().await; // slow destination: parks until released
            }
            self.dialed_ports.lock().unwrap().push(metadata.dst_port);
            Ok(Box::new(DeadReadConn))
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for GatedDialProxy {
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

    /// Issue #515: with session establishment off the read loop, a datagram
    /// to a fast destination must complete its dial while a slow
    /// destination's dial is still in flight. Previously
    /// `handle_client_datagram` was awaited inline and dst2 blocked behind
    /// dst1's 2 s `dial_udp`.
    #[tokio::test]
    async fn slow_destination_does_not_block_other_destinations() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let proxy = Arc::new(GatedDialProxy {
                gate: tokio::sync::Notify::new(),
                dialed_ports: std::sync::Mutex::new(Vec::new()),
                health: meow_common::ProxyHealth::new(),
            });
            let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
                vec![],
                vec![],
                meow_common::DnsMode::Normal,
                meow_trie::DomainTrie::new(),
                false,
                true,
            ));
            let tunnel = meow_tunnel::Tunnel::new(resolver);
            let rebuilt = meow_config::rebuild_from_raw(&Default::default()).unwrap();
            let mut proxies = rebuilt.proxies;
            proxies.insert(
                "gated-udp".into(),
                Arc::clone(&proxy) as Arc<dyn meow_common::Proxy>,
            );
            tunnel.update_proxies(proxies, rebuilt.dialer_registry);
            tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
                "gated-udp",
            ))]);

            let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let inner = Arc::clone(tunnel.inner());
            let mut nat: HashMap<SessionKey, Session> = HashMap::new();
            let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();
            let inbound = Metadata::default();

            let slow: SocketAddr = "1.2.3.4:4443".parse().unwrap();
            let fast: SocketAddr = "5.6.7.8:443".parse().unwrap();
            for dst in [slow, fast] {
                let mut packet: SmallVec<[u8; 1500]> = SmallVec::new();
                encode_udp_header(&mut packet, &dst);
                packet.extend_from_slice(b"payload");
                // Synchronous dispatch — must return immediately even while
                // the slow session's dial is parked on the gate.
                handle_client_datagram(&inner, &relay, &mut nat, &packet, client, &inbound)
                    .unwrap();
            }

            // The fast destination's session task dials promptly even though
            // the slow one's dial is still gated.
            assert!(
                eventually(Duration::from_secs(2), || {
                    proxy.dialed_ports.lock().unwrap().contains(&443)
                })
                .await,
                "fast destination's dial blocked behind the slow one"
            );

            proxy.gate.notify_waiters();
            assert!(
                eventually(Duration::from_secs(2), || {
                    proxy.dialed_ports.lock().unwrap().contains(&4443)
                })
                .await,
                "slow destination never dialed after the gate opened"
            );
        })
        .await
        .expect("HOL-blocking regression test timed out");
    }

    #[tokio::test]
    async fn udp_port_53_obeys_reject_rule() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::time::timeout(Duration::from_secs(2), async {
            let tunnel = crate::test_rule_tunnel();
            let stats = Arc::clone(tunnel.statistics());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut control = TcpStream::connect(addr).await.unwrap();
            let (server, peer) = listener.accept().await.unwrap();
            let task = tokio::spawn(async move {
                crate::socks5::handle_socks5(
                    &tunnel,
                    server,
                    peer,
                    None,
                    None,
                    "socks",
                    addr.port(),
                )
                .await;
            });
            control.write_all(&[5, 1, 0]).await.unwrap();
            let mut greeting = [0; 2];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut bound = [0; 10];
            control.read_exact(&mut bound).await.unwrap();
            assert_eq!(&bound[..4], &[5, 0, 0, 1]);
            let relay = SocketAddr::from((
                [bound[4], bound[5], bound[6], bound[7]],
                u16::from_be_bytes([bound[8], bound[9]]),
            ));
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for port in [53, 5353] {
                let mut packet = SmallVec::new();
                encode_udp_header(&mut packet, &SocketAddr::from(([127, 0, 0, 1], port)));
                packet.extend_from_slice(b"not a DNS query");
                client.send_to(&packet, relay).await.unwrap();
            }
            while stats.rule_match.snapshot() != vec![(("MATCH", "REJECT"), 2)] {
                tokio::task::yield_now().await;
            }
            drop(control);
            task.await.unwrap();
        })
        .await
        .expect("both destinations must reach MATCH,REJECT");
    }

    /// (label, datagram, expected ip, expected host, expected port, expected payload)
    type ParseUdpRequestCase = (
        &'static str,
        &'static [u8],
        Option<IpAddr>,
        &'static str,
        u16,
        &'static [u8],
    );

    #[test]
    fn parse_udp_request_cases() {
        let cases: &[ParseUdpRequestCase] = &[
            (
                "ipv4",
                // RSV FRAG ATYP=1 1.2.3.4 :443 "hi"
                &[0, 0, 0, ATYP_IPV4, 1, 2, 3, 4, 0x01, 0xBB, b'h', b'i'],
                Some(IpAddr::from([1, 2, 3, 4])),
                "",
                443,
                b"hi",
            ),
            (
                "domain",
                // RSV FRAG ATYP=3 len=3 "a.b" :53 "q"
                &[0, 0, 0, ATYP_DOMAIN, 3, b'a', b'.', b'b', 0x00, 0x35, b'q'],
                None,
                "a.b",
                53,
                b"q",
            ),
        ];
        for (label, dg, want_ip, want_host, want_port, want_payload) in cases {
            let (ip, host, port, off) =
                parse_udp_request(dg).unwrap_or_else(|e| panic!("{label}: parse failed: {e}"));
            assert_eq!(ip, *want_ip, "{label}: ip");
            assert_eq!(host, *want_host, "{label}: host");
            assert_eq!(port, *want_port, "{label}: port");
            assert_eq!(&dg[off..], *want_payload, "{label}: payload");
        }
    }

    #[test]
    fn parse_udp_request_rejects_fragment_and_short() {
        assert!(parse_udp_request(&[0, 0, 1, ATYP_IPV4, 1, 2, 3, 4, 0, 80]).is_err());
        assert!(parse_udp_request(&[0, 0]).is_err());
    }

    #[test]
    fn encode_udp_header_roundtrips_with_request_parser() {
        let mut out: SmallVec<[u8; 1500]> = SmallVec::new();
        let src: SocketAddr = "9.9.9.9:53".parse().unwrap();
        encode_udp_header(&mut out, &src);
        out.extend_from_slice(b"data");
        let (ip, _host, port, off) = parse_udp_request(&out).unwrap();
        assert_eq!(ip, Some(src.ip()));
        assert_eq!(port, src.port());
        assert_eq!(&out[off..], b"data");
    }

    /// Insert `n` stub sessions into `nat`; `dead` marks the last `dead`
    /// entries dead. Activity stamps are `index + 1` (index 0 is the least
    /// recently active) so tests can insert a strictly-older stamp-0 entry.
    fn stub_nat(n: usize, dead: usize) -> HashMap<SessionKey, Session> {
        let mut nat = HashMap::new();
        for i in 0..n {
            let (tx, _rx) = mpsc::channel(1);
            nat.insert(
                SessionKey::Addr(SocketAddr::from(([10, 0, 0, 1], 20000 + i as u16))),
                Session {
                    tx,
                    last_activity_ms: Arc::new(AtomicU::new((i + 1) as meow_common::atomic::Uint)),
                    dead: Arc::new(AtomicBool::new(i >= n - dead)),
                    task: tokio::spawn(std::future::pending::<()>()).abort_handle(),
                },
            );
        }
        nat
    }

    /// Capacity bound (issue #515): admission at `MAX_SESSIONS` reclaims
    /// dead entries before touching live ones.
    #[tokio::test]
    async fn evict_for_admission_reclaims_dead_sessions_first() {
        let mut nat = stub_nat(MAX_SESSIONS, 5);
        evict_for_admission(&mut nat);
        assert_eq!(nat.len(), MAX_SESSIONS - 5, "only dead entries removed");
        assert!(nat.values().all(|s| !s.dead.load(Ordering::Relaxed)));
    }

    /// With no dead entries to reclaim, the least-recently-active live
    /// session is the eviction victim.
    #[tokio::test]
    async fn evict_for_admission_evicts_lru_session() {
        let mut nat = stub_nat(MAX_SESSIONS, 0);
        let oldest = SessionKey::Addr(SocketAddr::from(([10, 0, 0, 1], 20000)));
        evict_for_admission(&mut nat);
        assert_eq!(nat.len(), MAX_SESSIONS - 1);
        assert!(
            !nat.contains_key(&oldest),
            "the least-recently-active session must be the victim"
        );
    }

    /// Dropping the evicted `Session` aborts its task — verify via the
    /// JoinHandle resolving as cancelled.
    #[tokio::test]
    async fn evicted_session_aborts_its_task() {
        let task = tokio::spawn(std::future::pending::<()>());
        let mut nat = stub_nat(MAX_SESSIONS - 1, 0);
        let (tx, _rx) = mpsc::channel(1);
        let key = SessionKey::Addr(SocketAddr::from(([10, 9, 9, 9], 53)));
        nat.insert(
            key.clone(),
            Session {
                tx,
                last_activity_ms: Arc::new(AtomicU::new(0)), // oldest → victim
                dead: Arc::new(AtomicBool::new(false)),
                task: task.abort_handle(),
            },
        );
        evict_for_admission(&mut nat);
        assert!(!nat.contains_key(&key));
        let outcome = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("evicted session's task never finished")
            .expect_err("evicted session's task must be cancelled");
        assert!(outcome.is_cancelled());
    }

    /// Issue #515: the `nat.len() >= MAX_SESSIONS` admission guard inside
    /// `start_session` itself — remove it and this fails even though the
    /// `evict_for_admission` unit tests still pass.
    #[tokio::test]
    async fn start_session_admission_holds_the_table_cap() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
                vec![],
                vec![],
                meow_common::DnsMode::Normal,
                meow_trie::DomainTrie::new(),
                false,
                true,
            ));
            let tunnel = meow_tunnel::Tunnel::new(resolver);
            let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let inner = Arc::clone(tunnel.inner());

            let mut nat = stub_nat(MAX_SESSIONS, 0);
            let key = SessionKey::Addr(SocketAddr::from(([192, 0, 2, 1], 443)));
            let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();
            start_session(
                &inner,
                &relay,
                &mut nat,
                key.clone(),
                client,
                Metadata::default(),
                SmallVec::from_slice(b"payload"),
            )
            .unwrap();

            assert!(
                nat.len() <= MAX_SESSIONS,
                "admission must not grow the table past MAX_SESSIONS"
            );
            assert!(nat.contains_key(&key), "the new session was admitted");
        })
        .await
        .expect("admission test timed out");
    }

    /// Mock conn whose `read_packet` pends forever (keeping the session
    /// alive) and whose `write_packet` records payloads once `write_gate`
    /// opens — the session's FIFO drain and queue bound are observable
    /// through `writes`.
    struct RecordingConn {
        writes: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        write_gate: tokio::sync::watch::Receiver<bool>,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyPacketConn for RecordingConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> meow_common::Result<usize> {
            let mut gate = self.write_gate.clone();
            while !*gate.borrow_and_update() {
                if gate.changed().await.is_err() {
                    break;
                }
            }
            self.writes.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
        fn close(&self) -> meow_common::Result<()> {
            Ok(())
        }
    }

    /// `dial_udp` parks until `dial_gate` opens, then yields a
    /// [`RecordingConn`] — letting a test queue datagrams deterministically
    /// before any write can run.
    struct GatedRecordingProxy {
        dial_gate: tokio::sync::watch::Receiver<bool>,
        write_gate: tokio::sync::watch::Receiver<bool>,
        writes: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for GatedRecordingProxy {
        fn name(&self) -> &str {
            "gated-recording"
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
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            let mut gate = self.dial_gate.clone();
            while !*gate.borrow_and_update() {
                if gate.changed().await.is_err() {
                    break;
                }
            }
            Ok(Box::new(RecordingConn {
                writes: Arc::clone(&self.writes),
                write_gate: self.write_gate.clone(),
            }))
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for GatedRecordingProxy {
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

    /// Issue #515's core claims made observable: datagrams queued while the
    /// session dials are written in FIFO order, and a full 64-deep queue
    /// drops extras without killing the session.
    #[tokio::test]
    async fn session_queue_preserves_order_and_bounds() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (dial_open, dial_gate) = tokio::sync::watch::channel(false);
            let (write_open, write_gate) = tokio::sync::watch::channel(true);
            let writes = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
            let proxy = Arc::new(GatedRecordingProxy {
                dial_gate,
                write_gate,
                writes: Arc::clone(&writes),
                health: meow_common::ProxyHealth::new(),
            });
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
                "gated-recording".into(),
                Arc::clone(&proxy) as Arc<dyn meow_common::Proxy>,
            );
            tunnel.update_proxies(proxies, res.dialer_registry);
            tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
                "gated-recording",
            ))]);

            let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let inner = Arc::clone(tunnel.inner());
            let mut nat: HashMap<SessionKey, Session> = HashMap::new();
            let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();
            let inbound = Metadata::default();
            let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
            let key = SessionKey::Addr(dst);
            let packet = |payload: &[u8]| {
                let mut p: SmallVec<[u8; 1500]> = SmallVec::new();
                encode_udp_header(&mut p, &dst);
                p.extend_from_slice(payload);
                p
            };

            // Phase 1 — ordering: the dial is parked, so every datagram
            // queues; once released they must reach the conn in FIFO order.
            for payload in [b"p1".as_slice(), b"p2", b"p3"] {
                handle_client_datagram(
                    &inner,
                    &relay,
                    &mut nat,
                    &packet(payload),
                    client,
                    &inbound,
                )
                .unwrap();
            }
            assert!(nat.contains_key(&key));
            dial_open.send(true).unwrap();
            assert!(
                eventually(Duration::from_secs(2), || {
                    writes.lock().unwrap().len() == 3
                })
                .await,
                "queued datagrams never reached the conn"
            );
            assert_eq!(
                writes.lock().unwrap().as_slice(),
                &[b"p1".as_slice(), b"p2", b"p3"],
                "per-destination ordering must be preserved through establishment"
            );

            // Phase 2 — the bound: park the write path, refill the queue to
            // its full 64-datagram depth, then send extras that must drop.
            write_open.send(false).unwrap();
            handle_client_datagram(
                &inner,
                &relay,
                &mut nat,
                &packet(b"parked"),
                client,
                &inbound,
            )
            .unwrap();
            // Wait until the writer consumed "parked" into write_packet —
            // the queue is empty again at that point (capacity back to 64).
            assert!(
                eventually(Duration::from_secs(2), || {
                    nat.get(&key).unwrap().tx.capacity() == SESSION_QUEUE
                })
                .await,
                "writer never consumed the parked datagram"
            );
            for i in 0..SESSION_QUEUE {
                let payload = vec![b'q', i as u8];
                handle_client_datagram(
                    &inner,
                    &relay,
                    &mut nat,
                    &packet(&payload),
                    client,
                    &inbound,
                )
                .unwrap();
            }
            assert_eq!(
                nat.get(&key).unwrap().tx.capacity(),
                0,
                "queue must be full"
            );
            // Five more datagrams: all dropped, session alive.
            for _ in 0..5 {
                handle_client_datagram(&inner, &relay, &mut nat, &packet(b"x"), client, &inbound)
                    .unwrap();
            }
            write_open.send(true).unwrap();
            // The parked write + the 64 queued drain; the 5 extras are gone.
            let want_total = 3 + 1 + SESSION_QUEUE;
            assert!(
                eventually(Duration::from_secs(2), || {
                    writes.lock().unwrap().len() == want_total
                })
                .await,
                "queue must drain exactly its capacity, extras dropped"
            );
            let recorded = writes.lock().unwrap();
            assert_eq!(recorded[3].as_slice(), b"parked");
            assert_eq!(recorded[4].as_slice(), b"q\x00".as_slice());
            assert_eq!(recorded[4 + SESSION_QUEUE - 1].as_slice(), &[b'q', 63]);
            assert!(
                nat.contains_key(&key),
                "a full queue must not kill the session"
            );
        })
        .await
        .expect("queue ordering/bounds test timed out");
    }

    /// Issue #514/#515: evicting a session while its task is parked inside
    /// `dial_udp` must abort the task, not let the establishment complete
    /// and leak a detached conn.
    #[tokio::test]
    async fn evict_during_dial_aborts_the_task() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (dial_open, dial_gate) = tokio::sync::watch::channel(false);
            let (_write_open, write_gate) = tokio::sync::watch::channel(true);
            let proxy = Arc::new(GatedRecordingProxy {
                dial_gate,
                write_gate,
                writes: Arc::new(std::sync::Mutex::new(Vec::new())),
                health: meow_common::ProxyHealth::new(),
            });
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
                "gated-recording".into(),
                Arc::clone(&proxy) as Arc<dyn meow_common::Proxy>,
            );
            tunnel.update_proxies(proxies, res.dialer_registry);
            tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
                "gated-recording",
            ))]);

            let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let inner = Arc::clone(tunnel.inner());
            let mut nat: HashMap<SessionKey, Session> = HashMap::new();
            let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();
            let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
            let key = SessionKey::Addr(dst);
            let mut packet: SmallVec<[u8; 1500]> = SmallVec::new();
            encode_udp_header(&mut packet, &dst);
            packet.extend_from_slice(b"payload");

            handle_client_datagram(
                &inner,
                &relay,
                &mut nat,
                &packet,
                client,
                &Metadata::default(),
            )
            .unwrap();
            // Give the task a scheduling slot to reach the parked dial.
            tokio::task::yield_now().await;
            let session = nat.remove(&key).expect("session must exist");
            let handle = session.task.clone();
            drop(session);
            assert!(
                eventually(Duration::from_secs(2), || handle.is_finished()).await,
                "evicting mid-dial must abort the session task"
            );
            // Releasing the dial gate afterwards must not resurrect anything.
            dial_open.send(true).unwrap();
        })
        .await
        .expect("mid-dial eviction test timed out");
    }
}
