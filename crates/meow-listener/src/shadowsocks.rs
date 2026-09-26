//! Shadowsocks encrypted-server inbound listener.
//!
//! Terminates SS encryption on an inbound TCP (and, with `udp: true`, UDP)
//! flow, reads the SOCKS target address from the decrypted header, and hands
//! the decrypted stream to the tunnel via [`route_inbound_tcp`]. Mirrors
//! upstream mihomo's `type: shadowsocks` listener.
//!
//! The cipher / AEAD decryption is delegated to the `shadowsocks` crate's
//! server-side [`ProxyListener`] / [`ProxyServerStream`] (the same crate the
//! outbound `ss` adapter uses on the client side), so this module contains no
//! crypto of its own — only accept-loop orchestration, target-address →
//! `Metadata` mapping, and the optional simple-obfs wrapper injection.
//!
//! # obfs injection
//!
//! `simple-obfs` wraps the *raw* TCP stream before SS decryption (it is the
//! outer layer). [`ProxyListener::accept_map`] lets us hand the accepted
//! `TcpStream` to a closure that applies the obfs codec before
//! `ProxyServerStream` reads the SS header — exactly the right order. The
//! obfs mode is fixed per listener, so the accept loop is monomorphised per
//! concrete stream type (`TcpStream` / `HttpObfsServer` / `TlsObfsServer`)
//! rather than type-erased, keeping the relay hot path dispatch-free.

use meow_common::{ConnType, Metadata, Network};
use meow_transport::simple_obfs::server::{HttpObfsServer, TlsObfsServer};
use meow_tunnel::{route_inbound_tcp, ResolvedTarget, Tunnel};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::TcpListener as SsTcpListener;
use shadowsocks::relay::tcprelay::{ProxyListener, ProxyServerStream};
use shadowsocks::relay::Address;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::DEFAULT_HANDSHAKE_TIMEOUT;

/// `simple-obfs` mode for the SS listener (mirrors `meow_config::ObfsMode`
/// without pulling meow-config into this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsObfsMode {
    Http,
    Tls,
}

/// Convenience alias for the listener-wide obfs setting.
type ObfsKind = Option<SsObfsMode>;

/// Default cap on in-flight inbound connections (and, with `udp: true`,
/// concurrent UDP flows) per listener when the listener config doesn't set
/// `max-connections` (mirrors `mixed::DEFAULT_MAX_CONNECTIONS` — kept as a
/// separate constant rather than an import so `listener-shadowsocks` stays
/// usable without `listener-mixed` enabled, same rationale as tproxy's
/// copy). `0` explicitly disables the cap.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

pub struct ShadowsocksListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    name: String,
    svr_cfg: Arc<ServerConfig>,
    /// Raw password + cipher kept separately so the UDP relay can rebuild a
    /// `ServerConfig` bound to the *resolved* TCP port (the TCP listener may
    /// bind `port: 0` and receive an ephemeral port; UDP must share that port).
    password: String,
    method: CipherKind,
    ctx: shadowsocks::context::SharedContext,
    udp: bool,
    obfs: ObfsKind,
    max_connections: usize,
}

impl ShadowsocksListener {
    /// Build a listener. `cipher` must be a string the `shadowsocks` crate
    /// recognises (e.g. `aes-256-gcm`, `2022-blake3-aes-256-gcm`, `chacha20-ietf-poly1305`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        name: String,
        cipher: &str,
        password: &str,
        udp: bool,
        obfs: ObfsKind,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let method = cipher.parse::<CipherKind>().map_err(|_| {
            meow_common::MeowError::Config(format!("ss listener: unknown cipher '{cipher}'"))
        })?;
        let svr_cfg = ServerConfig::new(listen_addr, password, method).map_err(|e| {
            meow_common::MeowError::Config(format!("ss listener: invalid config: {e}"))
        })?;
        let ctx = Context::new_shared(ServerType::Server);
        Ok(Self {
            tunnel,
            listen_addr,
            name,
            svr_cfg: Arc::new(svr_cfg),
            password: password.to_string(),
            method,
            ctx,
            udp,
            obfs,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        })
    }

    /// Override the concurrent-inbound cap (default
    /// [`DEFAULT_MAX_CONNECTIONS`]). `0` disables the cap. The same value
    /// caps the UDP relay's concurrent `(peer, target)` flows.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Bind the UDP relay socket on the resolved `bound` port — the fallible
    /// half of startup split from [`Self::run_on`] (issue #641): a spawning
    /// caller can bind eagerly so a UDP failure (`EADDRINUSE`, sandbox deny)
    /// surfaces before the task is detached, instead of dropping the
    /// already-bound TCP socket when the task exits. Returns `None` when
    /// `udp: false` or obfs is set (simple-obfs is TCP-only, with a warn).
    pub async fn bind_udp(
        &self,
        bound: SocketAddr,
    ) -> Result<
        Option<shadowsocks::ProxySocket<shadowsocks::net::UdpSocket>>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        if !self.udp {
            return Ok(None);
        }
        if self.obfs.is_some() {
            warn!(
                "ss listener '{}': simple-obfs is TCP-only; UDP relay disabled",
                self.name
            );
            return Ok(None);
        }
        let udp_cfg = ServerConfig::new(bound, self.password.clone(), self.method)
            .map_err(|e| meow_common::MeowError::Config(format!("ss udp bind: {e}")))?;
        let udp_sock = shadowsocks::ProxySocket::bind(Arc::clone(&self.ctx), &udp_cfg)
            .await
            .map_err(|e| format!("ss listener '{}': udp bind failed: {e}", self.name))?;
        info!(
            "Shadowsocks listener '{}' UDP on {} (cipher={})",
            self.name, bound, self.method
        );
        Ok(Some(udp_sock))
    }

    /// Serve on an already-bound TCP socket — binds the UDP relay socket
    /// internally via [`Self::bind_udp`]. Callers that spawn this in a
    /// detached task should instead bind eagerly and use
    /// [`Self::run_on_udp`] so a UDP failure surfaces at spawn time.
    pub async fn run_on(
        &self,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bound = listener.local_addr().unwrap_or(self.listen_addr);
        let udp_sock = self.bind_udp(bound).await?;
        self.run_on_udp(listener, udp_sock).await
    }

    /// Serve on an already-bound TCP socket with the UDP relay socket from
    /// [`Self::bind_udp`]. `bind_udp` must have been given this socket's
    /// `local_addr()` — binding UDP on a different port than the TCP
    /// listener accepts on would split the listener across ports.
    pub async fn run_on_udp(
        &self,
        listener: TcpListener,
        udp_sock: Option<shadowsocks::ProxySocket<shadowsocks::net::UdpSocket>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bound = listener.local_addr().unwrap_or(self.listen_addr);
        info!(
            "Shadowsocks listener '{}' on {} (cipher={}, udp={}, obfs={:?})",
            self.name,
            bound,
            self.svr_cfg.method(),
            self.udp,
            self.obfs,
        );

        let proxy_listener = {
            // Convert the already-bound tokio listener into the shadowsocks
            // crate's listener wrapper (preserves the OS-assigned port for
            // `port: 0` ephemeral listeners). AcceptOpts::default() keeps the
            // system TCP defaults (no TFO/MPTCP forcing).
            let ss_listener =
                SsTcpListener::from_listener(listener, shadowsocks::net::AcceptOpts::default())?;
            ProxyListener::from_listener(Arc::clone(&self.ctx), ss_listener, self.svr_cfg.as_ref())
        };

        // The UDP relay task shares the TCP accept loop's lifetime — both
        // run for the process lifetime, so a plain detached spawn suffices.
        if let Some(udp_sock) = udp_sock {
            let tunnel = self.tunnel.clone();
            let name = self.name.clone();
            let in_port = bound.port();
            let max_flows = self.max_connections;
            // SIP022 §3.2.2 requires the *server* to mint its own random
            // session ID per relay session, so the relay draws from the
            // cipher context's CSPRNG instead of a plain counter.
            let session_ids = ServerSessionIds::new(Arc::clone(&self.ctx), self.method);
            tokio::spawn(async move {
                run_udp_relay(tunnel, udp_sock, session_ids, name, in_port, max_flows).await;
            });
        }

        let sem: Option<Arc<Semaphore>> =
            (self.max_connections > 0).then(|| Arc::new(Semaphore::new(self.max_connections)));

        // simple-obfs wraps the *raw* TCP stream before SS decryption (it is
        // the outer layer). `ProxyListener::accept_map` lets us hand the
        // accepted TcpStream to a closure that applies the obfs codec first.
        // The obfs mode is fixed per listener, so the accept loop is
        // monomorphised per concrete stream type (no dyn dispatch on the relay
        // hot path). UDP is TCP-only for obfs and was warned about above.
        let in_port = bound.port();
        match self.obfs {
            None => {
                // No obfs: the accepted stream is a bare TcpStream.
                self.accept_loop::<TcpStream, _>(proxy_listener, |t| t, sem, in_port)
                    .await
            }
            Some(SsObfsMode::Http) => {
                self.accept_loop::<HttpObfsServer<TcpStream>, _>(
                    proxy_listener,
                    HttpObfsServer::new,
                    sem,
                    in_port,
                )
                .await
            }
            Some(SsObfsMode::Tls) => {
                self.accept_loop::<TlsObfsServer<TcpStream>, _>(
                    proxy_listener,
                    TlsObfsServer::new,
                    sem,
                    in_port,
                )
                .await
            }
        }
    }

    /// Generic accept loop. `map` wraps each accepted `TcpStream` (e.g. in an
    /// obfs codec) before `ProxyServerStream` decrypts the SS header. The
    /// closure is `Fn + Clone` so it can be handed to `accept_map` per
    /// iteration; it captures nothing for the obfs modes we support, so the
    /// clone is free.
    async fn accept_loop<S, F>(
        &self,
        pl: ProxyListener,
        map: F,
        sem: Option<Arc<Semaphore>>,
        in_port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
        F: Fn(TcpStream) -> S + Clone + Send + Sync + 'static,
    {
        let mut warned_saturated = false;
        // A persistent accept failure (fd exhaustion) must not spin the loop
        // or flood the log; a transient one must not be delayed meaningfully.
        let mut accept_backoff = meow_common::ErrorBackoff::new();
        loop {
            // Acquire a concurrency slot (back-pressures the listen queue when
            // the cap is reached), mirroring MixedListener.
            let permit = if let Some(sem) = &sem {
                let sem = Arc::clone(sem);
                if sem.available_permits() == 0 && !warned_saturated {
                    warn!(
                        "ss listener '{}' saturated at {} concurrent connections; new clients will queue",
                        self.name, self.max_connections
                    );
                    warned_saturated = true;
                }
                match sem.acquire_owned().await {
                    Ok(p) => {
                        if warned_saturated {
                            debug!("ss listener '{}' has free capacity again", self.name);
                            warned_saturated = false;
                        }
                        Some(p)
                    }
                    Err(_) => return Ok(()), // semaphore closed → shutdown
                }
            } else {
                None
            };

            let (ss, peer) = match pl.accept_map(map.clone()).await {
                Ok(v) => {
                    accept_backoff.succeeded();
                    v
                }
                Err(e) => {
                    drop(permit);
                    // Loud only when the backoff engaged — per-connection
                    // errors are queue progress and stay at debug!.
                    if accept_backoff.failed(&e).await {
                        error!("ss listener '{}' accept error: {}", self.name, e);
                    } else {
                        debug!("ss listener '{}' accept error: {}", self.name, e);
                    }
                    continue;
                }
            };

            let tunnel = self.tunnel.clone();
            let name = self.name.clone();
            tokio::spawn(async move {
                handle_ss_conn(ss, peer, tunnel, name, in_port).await;
                drop(permit);
            });
        }
    }
}

/// Per-connection handler: SS handshake (decrypt + read target address) then
/// route+relay. Generic over the inner stream type `S` (bare `TcpStream` or
/// an obfs wrapper) so the relay is monomorphised per concrete type.
async fn handle_ss_conn<S: AsyncRead + AsyncWrite + Unpin + Send + Sync>(
    mut ss: ProxyServerStream<S>,
    peer: SocketAddr,
    tunnel: Tunnel,
    in_name: String,
    in_port: u16,
) {
    // ProxyServerStream::handshake decrypts the SS header and returns the
    // SOCKS target address. Bound the wait so a silent peer can't hold a
    // concurrency slot forever.
    let target = match tokio::time::timeout(DEFAULT_HANDSHAKE_TIMEOUT, ss.handshake()).await {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => {
            debug!("ss listener handshake from {peer} failed: {e}");
            return;
        }
        Err(_) => {
            debug!("ss listener handshake from {peer} timed out");
            return;
        }
    };

    let metadata = build_metadata(peer, &target, &in_name, in_port);
    debug!("ss listener {} -> {}", peer, metadata.remote_address());

    let inner = tunnel.inner();
    route_inbound_tcp(inner, &mut ss, metadata, &[]).await;
}

/// Map an SS target `Address` + peer into a `Metadata` for the tunnel.
fn build_metadata(peer: SocketAddr, target: &Address, in_name: &str, in_port: u16) -> Metadata {
    let (host, dst_ip, dst_port) = match target {
        // Lowercase only when needed — `SmolStr::from` on an
        // already-lowercase name is inline (≤22 B) with no String
        // round-trip.
        Address::DomainNameAddress(d, port) => (
            if d.bytes().any(|b| b.is_ascii_uppercase()) {
                SmolStr::from(d.to_lowercase())
            } else {
                SmolStr::from(d.as_str())
            },
            None,
            *port,
        ),
        Address::SocketAddress(sa) => (SmolStr::default(), Some(sa.ip()), sa.port()),
    };
    Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Shadowsocks,
        src_ip: Some(peer.ip()),
        src_port: peer.port(),
        dst_ip,
        dst_port,
        host,
        in_name: in_name.into(),
        in_port,
        ..Default::default()
    }
}

// ──────────────────────────────── UDP relay ────────────────────────────────
//
// The SS UDP relay shares one `ProxySocket` (the decrypted inbound socket)
// across all SS clients. Each decrypted datagram carries a `(peer, target)`
// pair: `peer` is the SS client's source address, `target` is the SOCKS
// destination encoded in the SS header. We maintain a flat
// `HashMap<(peer, FlowKey), UdpFlow>` so datagrams from different clients (or to
// different destinations from the same client) get distinct outbound conns —
// mirroring the SOCKS5-UDP per-destination NAT, but keyed by both endpoints
// since the socket is shared.
//
// Each flow is a bounded FIFO queue plus a task that performs resolve →
// route → `dial_udp` → ordered writes and owns the reply pump — the recv
// loop never awaits any of that (issue #625; the same restructure #619
// gave the SOCKS5-UDP listener for issue #515).
//
// Idle eviction reuses `meow_tunnel::udp::DEFAULT_UDP_IDLE`; a flow on which
// neither direction has touched `last_activity_ms` within the idle window is
// dropped, aborting its task and freeing the outbound conn.

use meow_common::atomic::{checked_increment, AtomicU, Uint};
use meow_common::{with_dial_timeout, ProxyPacketConn, ReplayWindow};
use meow_tunnel::udp::DEFAULT_UDP_IDLE;
use meow_tunnel::TunnelInner;
use shadowsocks::context::SharedContext;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use shadowsocks::relay::udprelay::proxy_socket::ProxySocketError;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend};
use smallvec::SmallVec;
use smol_str::SmolStr;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::monotonic_ms;

const UDP_NAT_SWEEP: Duration = Duration::from_secs(30);

/// SIP022 §3.2.4: "Each relay session MUST be remembered for at least 60
/// seconds." The floor is measured from the last datagram that carried the
/// session's client ID — not from flow liveness — so a flow dying early
/// (dead upstream conn) cannot take the replay window down inside the
/// crate's 30-second header-timestamp tolerance: a captured-but-still-valid
/// replay must keep hitting the old window instead of minting a fresh
/// session that would re-forward it upstream.
const SESSION_MIN_RETAIN: Duration = Duration::from_secs(60);

/// Mints server-side UDP session IDs for the AEAD-2022 relay.
///
/// SIP022 §3.2.2: the server session ID "MUST be randomly generated" and must
/// differ from the client's. The ID travels in cleartext in every reply, so it
/// is a session discriminator rather than a secret — but strict clients key
/// their reply-decryption state off it, and `0` is exactly the sentinel
/// sing-box uses for "no reply session seen yet" (it then dereferences a nil
/// cipher and panics). So: draw from the cipher context's CSPRNG (already a
/// dependency), whose fill is already guaranteed non-zero.
struct ServerSessionIds {
    ctx: SharedContext,
    method: CipherKind,
}

impl ServerSessionIds {
    fn new(ctx: SharedContext, method: CipherKind) -> Self {
        Self { ctx, method }
    }

    /// Random, non-zero server session ID for one relay session.
    fn next(&self) -> u64 {
        let mut buf = [0u8; 8];
        // `unique: false` — this is not a cipher nonce, so it needs no replay
        // bookkeeping, only unpredictability and non-zero-ness. The fill is
        // `random_iv_or_salt`, which loops until the buffer is non-zero.
        self.ctx.generate_nonce(self.method, &mut buf, false);
        u64::from_be_bytes(buf)
    }
}

/// The server side of one AEAD-2022 relay session (SIP022 §3.2.2/§3.2.4).
///
/// Sessions are scoped to a client session ID — *not* to a `(peer, target)`
/// flow — so a client multiplexing several targets over one session sees a
/// single server session ID and a single, session-wide reply packet-ID
/// counter. `Arc`-shared between the relay loop (which owns it in
/// [`UdpRelayState::sessions`]) and every reply task sending under it.
struct ServerSession {
    /// Our randomly generated session ID, echoed in every reply header.
    server_session_id: u64,
    /// Reply packet-ID allocator for the whole session. Strict clients keep
    /// a replay window per server session, so IDs must stay unique across
    /// all of the session's flows — hence shared state rather than a
    /// per-task counter.
    next_packet_id: AtomicU,
}

/// The relay loop's view of a client session: the shared [`ServerSession`]
/// plus the sliding-window filter over this session's client→server packet
/// IDs (§3.2.4 mandates replay rejection per session).
struct ClientSession {
    server: Arc<ServerSession>,
    window: ReplayWindow,
    /// Stamp of the last datagram that carried this client session ID, in
    /// the same `Uint`-domain `monotonic_ms` units the flow activity stamps
    /// use. Drives the [`SESSION_MIN_RETAIN`] floor independently of flow
    /// references.
    last_seen_ms: Uint,
}

/// Mutable state owned by [`run_udp_relay`]'s loop: the `(peer, FlowKey)`
/// flow table plus the AEAD-2022 client-session table.
#[derive(Default)]
struct UdpRelayState {
    flows: HashMap<(SocketAddr, FlowKey), UdpFlow>,
    /// Relay sessions keyed by client session ID — the spec's session
    /// discriminator (§3.2.4: "Servers MUST route packets based on client
    /// session ID, not packet source address"). Non-2022 ciphers carry no
    /// session ID and never touch this map.
    ///
    /// The bare-ID key matches ssserver's `NatKey::SessionId`: this listener
    /// terminates a single PSK (no EIH multi-user), so two datagrams sharing
    /// a client session ID are indistinguishable from one client re-using
    /// the ID — there is no second identity a malicious "other user" could
    /// collide against.
    ///
    /// Bounded by the same `max_flows` value as the flow table: an uncapped
    /// session map is the only unbounded state this relay adds — any key
    /// holder could otherwise pin ~400 B per forged client session ID
    /// between sweeps.
    sessions: HashMap<u64, ClientSession>,
}

/// Build the server→client control template for a new flow (SIP022 §3.2.3):
/// echo the client's session ID — `cloned()` also carries the EIH `user`
/// key through, which `send_to_with_ctrl` uses to select the reply
/// encryption key — and stamp our server session ID. The reply task
/// allocates packet IDs per send from the session's shared counter.
///
/// Ciphers outside the AEAD-2022 category carry no client control (`server`
/// is then `None`) and ignore the control when encrypting, so the all-zero
/// default is harmless for them.
fn build_reply_control(
    client: Option<&UdpSocketControlData>,
    server: Option<&ServerSession>,
) -> UdpSocketControlData {
    // A client control without a session would stamp server_session_id = 0
    // — exactly the value that panics sing-box's clientPacketConn. The
    // caller guarantees the session entry exists for any AEAD-2022 datagram.
    debug_assert!(client.is_none() || server.is_some());
    let mut control = client.cloned().unwrap_or_default();
    control.server_session_id = server.map_or(0, |s| s.server_session_id);
    control.packet_id = 0;
    control
}

/// Per-destination flow key — the *unresolved* destination, because
/// resolution itself moved off the recv loop (issue #625). Literal-IP
/// targets key by socket address (no allocation on the per-datagram path);
/// domain-form targets key by the already-lowercased `SmolStr` host. Two
/// names resolving to one address now get separate flows — same routing
/// semantics, slightly finer dedup granularity (the same trade-off
/// socks5_udp took in #619).
#[derive(Debug, PartialEq, Eq, Hash)]
enum FlowKey {
    Addr(SocketAddr),
    Host(SmolStr, u16),
}

/// Per-flow client→upstream queue bound. Datagrams arriving while the flow
/// task is still establishing (resolve + route + `dial_udp`) queue here;
/// overflow is dropped (UDP semantics — the client retries), mirroring
/// socks5_udp's `SESSION_QUEUE`.
const UDP_FLOW_QUEUE: usize = 64;

/// One `(peer, target)` outbound flow: a bounded FIFO queue feeding a task
/// that performs resolve → route → `dial_udp` → ordered upstream writes and
/// owns the reply pump. The recv loop only queues onto `tx` — it never
/// awaits a dial or a write, so one slow destination can no longer
/// head-of-line block every SS client on the shared socket (issue #625).
struct UdpFlow {
    tx: mpsc::Sender<SmallVec<[u8; 1500]>>,
    last_activity_ms: Arc<AtomicU>,
    /// Set when the flow task exits for any reason (dial failure, upstream
    /// write/read error, eviction) — the next datagram re-dials instead of
    /// queueing into a dead channel (issue #514, same class as the
    /// SOCKS5-UDP fix).
    dead: Arc<std::sync::atomic::AtomicBool>,
    /// Filled by the flow task once `dial_udp` returns — lets tests observe
    /// the established conn (previously reachable as `flow.conn`).
    #[allow(
        dead_code,
        reason = "written by the flow task; read only by tests observing establishment"
    )]
    established: Arc<tokio::sync::OnceCell<Arc<dyn ProxyPacketConn>>>,
    /// The client session ID this flow echoes in replies (`0` for ciphers
    /// outside AEAD-2022). A datagram carrying a *different* ID on the same
    /// `(peer, target)` key is a new relay session per SIP022 §3.2.4 — the
    /// flow must be torn down and re-dialed, not reused with a stale echo.
    client_session_id: u64,
    /// Flow task (establish → writer loop + reply pump); aborted on evict.
    task: AbortHandle,
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The sweeper's session predicate: retain while a flow can still answer
/// under the session (`strong_count` > 1 — the map holds one `Arc`, each
/// live reply task another) OR while the session is inside the
/// [`SESSION_MIN_RETAIN`] floor measured from `last_seen_ms`. Extracted for
/// unit testing — the arithmetic is the same wrap-safe `Uint` subtraction
/// the flow idle check uses.
fn session_is_live(session: &ClientSession, now: Uint) -> bool {
    if Arc::strong_count(&session.server) > 1 {
        return true;
    }
    #[allow(
        clippy::useless_conversion,
        reason = "identity on 64-bit; u32→u64 widening on mips32"
    )]
    let elapsed = u64::from(now.wrapping_sub(session.last_seen_ms));
    elapsed < SESSION_MIN_RETAIN.as_millis() as u64
}

/// Run the SS UDP relay: decrypt inbound datagrams, route each through the
/// tunnel (rule match → `dial_udp`), and relay replies back encrypted to the
/// originating peer. Runs until the task is aborted (process lifetime) —
/// socket-level recv errors retry with `ErrorBackoff` rather than terminate.
///
/// `max_flows` caps the concurrent `(peer, target)` flow table (`0` =
/// uncapped), mirroring the TCP accept loop's `max_connections` — each flow
/// holds a bounded 64-datagram queue, a 64 KiB reply buffer, two tasks
/// (flow loop + reply pump), and an outbound socket, so an unbounded table
/// is a memory/FD exhaustion vector on an internet-exposed listener. The same value bounds the AEAD-2022 session table: each entry
/// is only ~400 B, but the map is otherwise the relay's only unbounded
/// state — a key holder could grow it by one entry per forged client
/// session ID between sweeps. Saturated new flows *and* unseen session IDs
/// are dropped with a warn-once log (recovery logs at debug), exactly like
/// the TCP saturation path; existing flows and sessions are never capped.
///
/// Generic over the inner socket type `S` so the concrete type returned by
/// `ProxySocket::bind` (`ShadowUdpSocket`) flows in by inference — the relay
/// logic is identical for any `DatagramSend + DatagramReceive` socket.
///
/// Replies go out through `send_to_with_ctrl` with a control built from the
/// per-client-session [`ServerSession`]: `recv_from_with_ctrl` hands us the
/// client's session ID, which selects (or creates) the session supplying the
/// server session ID and reply packet-ID counter. The crate's 4-tuple
/// `recv_from` / 3-arg `send_to` convenience forms silently substitute an
/// all-zero control, which violates SIP022 §3.2.3 in two ways (the server
/// session ID must be random, and the reply header must echo the client
/// session ID) and makes strict clients — sing-box's `clientPacketConn` —
/// drop or panic on every reply. Ciphers outside the 2022 category ignore
/// the control field entirely, so they are unaffected either way.
///
/// `handle_ss_udp_datagram` runs synchronously on the loop — the AEAD-2022
/// session bookkeeping, replay check, and flow-table check-then-insert all
/// happen inline, so a retransmitted first datagram can never create a
/// duplicate flow — then the payload is queued onto the flow's bounded
/// channel. Resolution, routing, `dial_udp`, and the ordered upstream
/// writes run inside the per-flow task, so one client's slow dial can no
/// longer stall decrypt→dispatch for every SS client on the shared socket
/// (issue #625; mirrors the SOCKS5-UDP restructure in #619).
async fn run_udp_relay<S>(
    tunnel: Tunnel,
    sock: shadowsocks::ProxySocket<S>,
    session_ids: ServerSessionIds,
    in_name: String,
    in_port: u16,
    max_flows: usize,
) where
    S: DatagramSend + DatagramReceive + Send + Sync + 'static,
{
    let inner = tunnel.inner();
    let sock = Arc::new(sock);
    let mut state = UdpRelayState::default();
    // The crate asks for ≥65536 bytes of intermediate storage — the full
    // decrypted datagram plus the AEAD-2022 header it is parsed from.
    let mut buf = vec![0u8; 65536];
    let mut sweeper = tokio::time::interval(UDP_NAT_SWEEP);
    sweeper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let idle_ms = DEFAULT_UDP_IDLE.as_millis() as u64;
    let mut warned_saturated = false;
    // A persistent recv failure must not spin the select; the in-arm sleep
    // stalls the sweeper arm at most ~1s while a persistently-erroring
    // socket can do no useful work anyway. Per-packet errors (protocol
    // decode failures, ICMP async delivery) skip the delay — each consumed
    // a datagram, so the loop is still making progress.
    let mut recv_backoff = meow_common::ErrorBackoff::new();

    loop {
        // No `biased`: the recv arm is permanently ready under sustained
        // inbound traffic, and a biased poll would starve the sweeper — the
        // flow table would pin at `max_flows` with no idle eviction.
        tokio::select! {
            r = sock.recv_from_with_ctrl(&mut buf) => {
                let (n, peer, target, _recv_total, control) = match r {
                    Ok(v) => {
                        recv_backoff.succeeded();
                        v
                    }
                    Err(e) => {
                        // `IoError` is the socket-level variant — warn! only
                        // when the backoff actually slept (per-packet
                        // async-ICMP errors ride the same variant, and each
                        // protocol/decode failure already consumed a
                        // datagram = progress): both stay at debug!.
                        let socket_failed = match &e {
                            ProxySocketError::IoError(io_err) => {
                                recv_backoff.failed(io_err).await
                            }
                            _ => false,
                        };
                        if socket_failed {
                            warn!("ss udp '{}' recv error: {e}", in_name);
                        } else {
                            debug!("ss udp '{}' recv error: {e}", in_name);
                        }
                        continue;
                    }
                };
                let payload = &buf[..n];
                match handle_ss_udp_datagram(
                    inner,
                    &sock,
                    &mut state,
                    payload,
                    peer,
                    &target,
                    control.as_ref(),
                    &session_ids,
                    &in_name,
                    in_port,
                    max_flows,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        if !warned_saturated {
                            warn!(
                                "ss udp '{}' capacity reached ({} max flows/sessions); new flows and unseen client session IDs are dropped until eviction",
                                in_name, max_flows
                            );
                            warned_saturated = true;
                        }
                    }
                    Err(e) => debug!("ss udp '{}' datagram from {peer}: {e}", in_name),
                }
            }
            _ = sweeper.tick() => {
                let now = monotonic_ms() as Uint;
                state.flows.retain(|_, f| {
                    // Dead reply task → the conn can never answer; evict so
                    // the next datagram redials (issue #514).
                    if f.dead.load(std::sync::atomic::Ordering::Relaxed) {
                        return false;
                    }
                    let last = f.last_activity_ms.load(std::sync::atomic::Ordering::Relaxed);
                    #[allow(
                        clippy::useless_conversion,
                        reason = "identity on 64-bit; u32→u64 widening on mips32"
                    )]
                    let elapsed = u64::from(now.wrapping_sub(last));
                    elapsed < idle_ms
                });
                // A session survives while a flow can still answer under it
                // (`strong_count` > 1 — the last reply task's Arc) OR while
                // it is inside the §3.2.4 60-second retention floor measured
                // from `last_seen_ms`. A client resuming on a GC'd session
                // ID simply gets a fresh server session — §3.2.4 requires
                // clients to tolerate that.
                state.sessions.retain(|_, s| session_is_live(s, now));
                if warned_saturated
                    && state.flows.len() < max_flows
                    && state.sessions.len() < max_flows
                {
                    debug!("ss udp '{}' tables have free capacity again", in_name);
                    warned_saturated = false;
                }
            }
        }
    }
}

/// Decrypt is already done by `ProxySocket`; here we run the AEAD-2022
/// session bookkeeping + replay check, resolve the *flow* (not the target —
/// that happens inside the flow task), and queue the payload onto the
/// flow's bounded channel — creating the flow's task on first use. Runs
/// synchronously on the shared recv loop and never awaits resolution,
/// routing, `dial_udp`, or an upstream write (issue #625: a slow
/// destination must not head-of-line block every SS client on the socket).
/// Per-flow ordering is preserved because every payload for a destination
/// travels the same FIFO queue.
///
/// `control` is the client's per-datagram control as decrypted by
/// `recv_from_with_ctrl` (`None` for ciphers outside the AEAD-2022 category,
/// which carry no session IDs). For AEAD-2022 the client session ID owns an
/// entry in `state.sessions` — created on first sight — that supplies the
/// server session ID + reply packet counter for every flow of the session
/// and the replay window the datagram's packet ID is checked against.
///
/// Returns `Ok(true)` when the datagram was consumed — queued onto an
/// existing or new flow, or dropped on a full queue (UDP semantics) —
/// `Ok(false)` when it was dropped because the flow or session table is at
/// `max_flows` (cap on *new* entries only — datagrams for existing flows
/// and known session IDs always pass), and `Err` with a reason for
/// per-datagram failures.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors socks5_udp::handle_client_datagram's parameter set plus the shared socket, the flow/session caps, and the AEAD-2022 reply-control inputs"
)]
fn handle_ss_udp_datagram<S>(
    inner: &Arc<TunnelInner>,
    sock: &Arc<shadowsocks::ProxySocket<S>>,
    state: &mut UdpRelayState,
    payload: &[u8],
    peer: SocketAddr,
    target: &Address,
    control: Option<&UdpSocketControlData>,
    session_ids: &ServerSessionIds,
    in_name: &str,
    in_port: u16,
    max_flows: usize,
) -> Result<bool, String>
where
    S: DatagramSend + DatagramReceive + Send + Sync + 'static,
{
    // SIP022 §3.2.4: the client session ID — not the source address — is the
    // session discriminator, and every received packet's ID must pass the
    // session's replay window *before* anything is forwarded upstream. The
    // window consumes the ID even when the datagram is dropped later (rules,
    // saturation, dial failure): a received-and-validated ID is spent.
    let client_session_id = control.map_or(0, |c| c.client_session_id);
    if let Some(c) = control {
        // The session table shares the listener's `max_flows` budget: left
        // uncapped, any key holder could grow it by one ~400 B entry per
        // forged client session ID between sweeps. At capacity, unseen
        // session IDs are dropped; sessions already in the table (the only
        // ones that can still pass a window check) are never capped out.
        if max_flows > 0
            && state.sessions.len() >= max_flows
            && !state.sessions.contains_key(&c.client_session_id)
        {
            return Ok(false);
        }
        let now = monotonic_ms() as Uint;
        // ssserver refreshes the session's TTL on every datagram carrying
        // the ID — including ones the window will reject — so retention
        // tracks traffic, not flow references.
        let session = state
            .sessions
            .entry(c.client_session_id)
            .and_modify(|s| s.last_seen_ms = now)
            .or_insert_with(|| ClientSession {
                server: Arc::new(ServerSession {
                    server_session_id: session_ids.next(),
                    next_packet_id: AtomicU::new(0),
                }),
                window: ReplayWindow::new(),
                last_seen_ms: now,
            });
        if !session.window.check_and_set(c.packet_id) {
            return Err(format!(
                "replayed/out-of-window packet_id {} for session {:#x}",
                c.packet_id, c.client_session_id
            ));
        }
    }

    let (host, dst_ip, dst_port) = match target {
        // Lowercase only when needed — `SmolStr::from` on an
        // already-lowercase name is inline (≤22 B) with no String
        // round-trip; longer names still heap-allocate once (the flow key
        // then clones by refcount).
        Address::DomainNameAddress(d, port) => (
            if d.bytes().any(|b| b.is_ascii_uppercase()) {
                SmolStr::from(d.to_lowercase())
            } else {
                SmolStr::from(d.as_str())
            },
            None,
            *port,
        ),
        Address::SocketAddress(sa) => (SmolStr::default(), Some(sa.ip()), sa.port()),
    };

    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Shadowsocks,
        src_ip: Some(peer.ip()),
        src_port: peer.port(),
        dst_ip,
        dst_port,
        host,
        in_name: in_name.into(),
        in_port,
        ..Default::default()
    };

    // Drop an unmapped fake-IP destination before it spawns a flow — a
    // stale-datagram flood would otherwise churn a spawn+evict per packet
    // (issue #618, same guard as socks5_udp). The flow task re-checks.
    if matches!(
        inner.pre_handle_metadata(&mut metadata),
        meow_tunnel::PreHandleVerdict::Drop
    ) {
        return Err("unmapped fake-ip destination".into());
    }

    // Key by the unresolved destination — `metadata.dst_ip` after
    // `pre_handle_metadata` (which folds domain-typed IP literals into
    // dst_ip), else the lowercased host. Resolution happens inside the flow
    // task, so a slow lookup cannot stall the recv loop, and the flow pins
    // the resolved address for its life (what QUIC wants; the old key used
    // the resolved address anyway, so no flow ever re-resolved).
    let key = (
        peer,
        match metadata.dst_ip {
            Some(ip) => FlowKey::Addr(SocketAddr::new(ip, metadata.dst_port)),
            None if !metadata.host.is_empty() => {
                FlowKey::Host(metadata.host.clone(), metadata.dst_port)
            }
            None => return Err("UDP datagram with neither IP nor domain".into()),
        },
    );

    // Fast path: existing flow. Two reasons to evict and fall through to a
    // fresh dial instead of reusing it:
    //   * a dead task means the conn can never answer (issue #514);
    //   * a changed client session ID on the same `(peer, target)` is a new
    //     relay session per SIP022 §3.2.4 — replies must echo the new ID,
    //     which only a freshly built flow can do.
    let mut first_payload: Option<SmallVec<[u8; 1500]>> = None;
    if let Some(flow) = state.flows.get(&key) {
        if flow.dead.load(std::sync::atomic::Ordering::Relaxed)
            || flow.client_session_id != client_session_id
        {
            state.flows.remove(&key);
        } else {
            // `try_send` alone discriminates all three outcomes — no
            // capacity pre-check: a closed channel with a *full* queue
            // would read capacity 0 and drop without evicting, widening
            // the dead-flow race window (#625 review).
            match flow.tx.try_send(SmallVec::from_slice(payload)) {
                Ok(()) => {
                    flow.last_activity_ms
                        .store(monotonic_ms() as Uint, std::sync::atomic::Ordering::Relaxed);
                    return Ok(true);
                }
                // Queue full — drop the datagram (UDP semantics — the
                // client retries).
                Err(mpsc::error::TrySendError::Full(_)) => {
                    debug!("ss udp flow queue full: dropping datagram");
                    return Ok(true);
                }
                // The task exited between the dead check and the send:
                // evict and start a fresh flow, reusing the datagram the
                // dead channel handed back instead of re-copying it.
                Err(mpsc::error::TrySendError::Closed(returned)) => {
                    state.flows.remove(&key);
                    first_payload = Some(returned);
                }
            }
        }
    }

    // Flow-table cap: a new flow costs a queue, a task, a 64 KiB reply
    // buffer, and an outbound socket; without a cap any password holder
    // could exhaust memory/FDs between idle sweeps. `0` disables the cap.
    if max_flows > 0 && state.flows.len() >= max_flows {
        // Admission-time reclaim (socks5_udp's evict_for_admission): a
        // flood of distinct fast-failing destinations could otherwise pin
        // the table at cap for up to a sweep interval.
        state
            .flows
            .retain(|_, f| !f.dead.load(std::sync::atomic::Ordering::Relaxed));
        if state.flows.len() >= max_flows {
            return Ok(false);
        }
    }

    // The session created (or found) above supplies the server session ID
    // and the reply packet-ID allocator; `build_reply_control` echoes this
    // datagram's client session ID and carries its EIH user key through.
    // Both are computed here — the session table lives on the loop — and
    // moved into the task.
    let server_session = control.and_then(|c| {
        state
            .sessions
            .get(&c.client_session_id)
            .map(|s| Arc::clone(&s.server))
    });
    let reply_control = build_reply_control(control, server_session.as_deref());

    let (tx, rx) = mpsc::channel(UDP_FLOW_QUEUE);
    tx.try_send(first_payload.unwrap_or_else(|| SmallVec::from_slice(payload)))
        .map_err(|_| "fresh flow queue rejected payload".to_string())?;

    let last_activity_ms = Arc::new(AtomicU::new(monotonic_ms() as Uint));
    let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let established = Arc::new(tokio::sync::OnceCell::new());
    let task = tokio::spawn(run_ss_udp_flow(
        Arc::clone(inner),
        Arc::clone(sock),
        rx,
        metadata,
        peer,
        reply_control,
        server_session,
        Arc::clone(&established),
        Arc::clone(&last_activity_ms),
        Arc::clone(&dead),
    ))
    .abort_handle();

    state.flows.insert(
        key,
        UdpFlow {
            tx,
            last_activity_ms,
            dead,
            established,
            client_session_id,
            task,
        },
    );
    Ok(true)
}

/// One flow's outbound task: resolve → route → `dial_udp`, then write
/// queued client datagrams in order while a reply pump ships
/// server→client datagrams back. Exiting for any reason marks `dead` so
/// the next datagram on the key re-establishes (issue #514); the reply
/// pump's death also ends the session — a conn that cannot deliver replies
/// must be re-dialed — and an abort drops the `AbortOnDrop` guard that
/// kills the pump.
#[allow(
    clippy::too_many_arguments,
    reason = "moved state: the reply-control template, server session, and observability handles are all computed on the loop where the session table lives"
)]
async fn run_ss_udp_flow<S>(
    inner: Arc<TunnelInner>,
    sock: Arc<shadowsocks::ProxySocket<S>>,
    mut rx: mpsc::Receiver<SmallVec<[u8; 1500]>>,
    mut metadata: Metadata,
    peer: SocketAddr,
    reply_control: UdpSocketControlData,
    server_session: Option<Arc<ServerSession>>,
    established: Arc<tokio::sync::OnceCell<Arc<dyn ProxyPacketConn>>>,
    last_activity_ms: Arc<AtomicU>,
    dead: Arc<std::sync::atomic::AtomicBool>,
) where
    S: DatagramSend + DatagramReceive + Send + Sync + 'static,
{
    // Whatever happens below, mark the flow dead on exit so the recv loop
    // evicts it instead of queueing into a closed channel.
    struct DeadOnExit(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DeadOnExit {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let _dead_guard = DeadOnExit(Arc::clone(&dead));

    // Re-run the fake-IP gate — idempotent, and it catches a fake-IP pool
    // state change in the loop→task gap (socks5_udp parity, #625 review).
    if matches!(
        inner.pre_handle_metadata(&mut metadata),
        meow_tunnel::PreHandleVerdict::Drop
    ) {
        return;
    }
    // UDP keeps the eager pre_resolve (no lazy enrichment): the writer
    // needs a resolved dst_ip regardless of what the rules demand.
    inner.pre_resolve(&mut metadata).await;
    if metadata.dst_ip.is_none() && !metadata.host.is_empty() {
        metadata.dst_ip = inner.resolver().resolve_ip_real(&metadata.host).await;
    }
    let Some(dst_ip) = metadata.dst_ip else {
        debug!(
            "ss udp flow: dst_ip not resolved for {}",
            metadata.remote_address()
        );
        return;
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);

    // Client UDP follows the configured routing policy, including port 53.
    // `route` pins this generation's dialer registry across `dial_udp`
    // (issue #533 review) — block-scoped so a long-lived flow doesn't
    // retain a stale route table (or adapter/rule Arcs) for its whole
    // idle window.
    let conn: Arc<dyn ProxyPacketConn> = {
        let Some(ResolvedTarget {
            adapter: proxy,
            rule_name,
            rule_payload,
            route: _route,
        }) = inner.resolve_proxy(&metadata).await
        else {
            debug!(
                "ss udp flow: no matching rule for {}",
                metadata.remote_address()
            );
            return;
        };
        info!(
            "UDP {peer} --> {} match {rule_name}({rule_payload}) using {}",
            metadata.remote_address(),
            proxy.name()
        );
        match with_dial_timeout(proxy.name(), proxy.dial_udp(&metadata)).await {
            Ok(conn) => Arc::from(conn),
            Err(e) => {
                debug!(
                    "ss udp flow to {dst_addr}: dial_udp via {}: {e}",
                    proxy.name()
                );
                return;
            }
        }
    };

    // Reply pump: server→client. Same logic as the pre-#625 per-flow reply
    // task — wraps each datagram in the SS UDP reply header (echoing the
    // client session ID + allocating a session-wide reply packet ID) and
    // sends it back to the originating peer. The `select!` below treats its
    // exit as flow death (a conn that cannot deliver replies must be
    // re-dialed, issue #514); `AbortOnDrop` kills it if the flow task is
    // aborted first.
    struct AbortOnDrop(AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut reply_task = tokio::spawn({
        let sock = Arc::clone(&sock);
        let conn = Arc::clone(&conn);
        let last_activity_ms = Arc::clone(&last_activity_ms);
        let mut control = reply_control;
        async move {
            let mut rbuf = vec![0u8; 65536];
            // Warn-once: an exhausted counter (32-bit targets, after 2^32
            // replies) makes every later reply hit this branch.
            let mut exhaustion_warned = false;
            while let Ok((m, src)) = conn.read_packet(&mut rbuf).await {
                if let Some(s) = &server_session {
                    // The reply packet-ID space belongs to the *session*, not
                    // this flow — a client multiplexing targets still sees a
                    // strictly increasing stream (SIP022 §3.2.3). The counter
                    // is pre-incremented, matching ssserver: IDs start at 1.
                    // On exhaustion the reply is skipped — reusing IDs would
                    // only get them dropped by the client's replay window —
                    // and the stalled session lets the client re-key, the
                    // recovery ssserver relies on.
                    match checked_increment(&s.next_packet_id) {
                        Some(id) => control.packet_id = id,
                        None => {
                            if !exhaustion_warned {
                                warn!(
                                    "ss udp reply packet-ID space exhausted for session {:#x}; dropping replies",
                                    s.server_session_id
                                );
                                exhaustion_warned = true;
                            }
                            continue;
                        }
                    }
                }
                // The reply's inner address is the responder's real socket
                // address (matching ssserver), not the request's target:
                // stamping the request's domain form would mislabel every
                // datagram that didn't create the flow.
                let reply_addr = Address::SocketAddress(src);
                if sock
                    .send_to_with_ctrl(peer, &reply_addr, &control, &rbuf[..m])
                    .await
                    .is_err()
                {
                    break;
                }
                last_activity_ms
                    .store(monotonic_ms() as Uint, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });
    let _reply_guard = AbortOnDrop(reply_task.abort_handle());

    // Expose the established conn for tests (previously `flow.conn`) —
    // set once the reply pump is up so an observer also implies "replies
    // are being pumped".
    let _ = established.set(Arc::clone(&conn));

    // Writer loop: drain the queue in FIFO order until the flow is evicted
    // (all senders gone), the upstream write fails, or the reply pump dies
    // (one-way conn — re-dial on next datagram, issue #514).
    loop {
        tokio::select! {
            queued = rx.recv() => match queued {
                Some(payload) => {
                    if let Err(e) = conn.write_packet(&payload, &dst_addr).await {
                        debug!("ss udp flow to {dst_addr}: upstream write: {e}");
                        return;
                    }
                    last_activity_ms
                        .store(monotonic_ms() as Uint, std::sync::atomic::Ordering::Relaxed);
                }
                None => return, // all senders dropped — flow evicted
            },
            done = &mut reply_task => {
                let reason = match done {
                    Ok(()) => "reply pump exited".to_string(),
                    Err(e) => format!("reply pump task: {e}"),
                };
                debug!("ss udp flow to {dst_addr}: {reason}; next datagram re-dials");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Like [`crate::test_rule_tunnel`] but routing everything to DIRECT:
    /// the outbound conn is a real UDP socket whose `read_packet` simply
    /// blocks (nothing replies to the synthetic targets), so the flow's
    /// `dead` flag stays false and session-rotation tests exercise the
    /// session-ID branch rather than the dead-conn one.
    fn direct_rule_tunnel() -> Tunnel {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        tunnel.update_proxies(res.proxies, res.dialer_registry);
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "DIRECT",
        ))]);
        tunnel
    }

    /// Shared harness: a bound server-side `ProxySocket` + its session-ID
    /// minter for the given cipher.
    async fn server_sock_and_ids(
        method: &str,
    ) -> (
        Arc<shadowsocks::ProxySocket<shadowsocks::net::UdpSocket>>,
        ServerSessionIds,
    ) {
        // AEAD-2022 keys must be base64 iPSKs; older ciphers take any
        // password string.
        let key = if method.starts_with("2022-") {
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
        } else {
            "synthetic-test-password"
        };
        let config = shadowsocks::config::ServerConfig::new(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            key,
            method.parse().unwrap(),
        )
        .unwrap();
        let context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
        let session_ids = ServerSessionIds::new(Arc::clone(&context), config.method());
        let sock = Arc::new(
            shadowsocks::ProxySocket::bind(context, &config)
                .await
                .unwrap(),
        );
        (sock, session_ids)
    }

    fn client_control(client_session_id: u64, packet_id: u64) -> UdpSocketControlData {
        let mut c = UdpSocketControlData::default();
        c.client_session_id = client_session_id;
        c.packet_id = packet_id;
        c
    }

    /// Wait for the flow task to dial and publish its conn (previously the
    /// synchronous `flow.conn` — the dial moved off the recv loop, #625).
    async fn flow_conn(
        state: &UdpRelayState,
        key: &(SocketAddr, FlowKey),
    ) -> Arc<dyn ProxyPacketConn> {
        for _ in 0..500 {
            if let Some(conn) = state.flows[key].established.get() {
                return Arc::clone(conn);
            }
            tokio::task::yield_now().await;
        }
        panic!("flow task never established a conn for {key:?}");
    }

    #[tokio::test]
    async fn udp_port_53_obeys_reject_rule() {
        let tunnel = crate::test_rule_tunnel();
        let (sock, session_ids) = server_sock_and_ids("aes-256-gcm").await;
        let mut state = UdpRelayState::default();
        let peer = "127.0.0.1:12345".parse().unwrap();
        for port in [53, 5353] {
            let dst = SocketAddr::from(([127, 0, 0, 1], port));
            let key = (peer, FlowKey::Addr(dst));
            assert!(handle_ss_udp_datagram(
                tunnel.inner(),
                &sock,
                &mut state,
                b"not a DNS query",
                peer,
                &Address::SocketAddress(dst),
                None,
                &session_ids,
                "ss",
                8388,
                8,
            )
            .unwrap());
            assert!(
                flow_conn(&state, &key).await.local_addr().is_err(),
                "must use REJECT, not DIRECT"
            );
        }
    }

    /// Regression (SIP022 §3.2.2/§3.2.3): the control attached to a new flow's
    /// replies must echo the client's session ID and carry the server session
    /// ID minted for that client session. The crate's 3-arg `send_to`
    /// substitutes an all-zero control, which makes sing-box's
    /// `clientPacketConn` treat the reply as belonging to the "no session
    /// seen yet" state it initialised with, select a nil cipher, and panic
    /// on every reply.
    #[test]
    fn ss_udp_reply_control_echoes_client_and_mints_server_session_id() {
        let client_session_id = 0x0123_4567_89ab_cdef_u64;
        let inbound = client_control(client_session_id, 7);

        let server = ServerSession {
            server_session_id: 0xdead_beef,
            next_packet_id: AtomicU::new(0),
        };
        let reply = build_reply_control(Some(&inbound), Some(&server));
        assert_eq!(
            reply.client_session_id, client_session_id,
            "the reply header must echo the client session ID"
        );
        assert_eq!(
            reply.server_session_id, 0xdead_beef,
            "the reply carries the session's server session ID"
        );
        assert_ne!(
            reply.server_session_id, client_session_id,
            "the server session ID must not reuse the client's"
        );
        assert_eq!(
            reply.packet_id, 0,
            "reply packet IDs are allocated per send, not at flow creation"
        );

        // Ciphers outside the 2022 category carry no client control: the
        // template stays all-zero (those ciphers ignore it when encrypting).
        let no_control = build_reply_control(None, None);
        assert_eq!(no_control.client_session_id, 0);
        assert_eq!(no_control.server_session_id, 0);
    }

    /// The server session ID is per client session, must be random, and must
    /// never be `0`.
    #[test]
    fn server_session_ids_are_random_and_non_zero() {
        let context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
        let session_ids =
            ServerSessionIds::new(context, "2022-blake3-aes-256-gcm".parse().unwrap());
        let first = session_ids.next();
        let second = session_ids.next();
        assert_ne!(first, 0);
        assert_ne!(second, 0);
        assert_ne!(first, second, "each client session needs its own ID");
    }

    /// SIP022 §3.2.4: one client session spanning several `(peer, target)`
    /// flows shares a single server session (one ID, one reply packet
    /// counter) — the spec's session discriminator is the client session ID,
    /// not the NAT tuple.
    #[tokio::test]
    async fn flows_of_one_client_session_share_the_server_session() {
        let tunnel = direct_rule_tunnel();
        let (sock, session_ids) = server_sock_and_ids("2022-blake3-aes-256-gcm").await;
        let mut state = UdpRelayState::default();
        let peer = "127.0.0.1:12345".parse().unwrap();
        let csid = 0x0bad_f00d_u64;

        for (i, port) in [443u16, 853].into_iter().enumerate() {
            let dst = SocketAddr::from(([127, 0, 0, 1], port));
            let control = client_control(csid, i as u64);
            assert!(handle_ss_udp_datagram(
                tunnel.inner(),
                &sock,
                &mut state,
                b"payload",
                peer,
                &Address::SocketAddress(dst),
                Some(&control),
                &session_ids,
                "ss",
                8388,
                8,
            )
            .unwrap());
            // Wait for the flow's reply pump to come up — it is what holds
            // the extra `Arc<ServerSession>` reference below.
            flow_conn(&state, &(peer, FlowKey::Addr(dst))).await;
        }

        assert_eq!(state.flows.len(), 2, "each target keeps its own flow");
        assert_eq!(
            state.sessions.len(),
            1,
            "one client session ID = one server session"
        );
        let session = &state.sessions[&csid];
        assert_eq!(
            Arc::strong_count(&session.server),
            3,
            "sessions map + one reply task per flow hold the session"
        );
    }

    /// The session table shares the `max_flows` bound: at capacity a
    /// datagram carrying an *unseen* client session ID is dropped, while a
    /// known session ID still passes.
    #[tokio::test]
    async fn session_table_cap_drops_unseen_ids_only() {
        let tunnel = direct_rule_tunnel();
        let (sock, session_ids) = server_sock_and_ids("2022-blake3-aes-256-gcm").await;
        let mut state = UdpRelayState::default();
        let peer = "127.0.0.1:12345".parse().unwrap();
        let target = Address::SocketAddress(SocketAddr::from(([127, 0, 0, 1], 443)));

        // Fill the session table to the cap of 1 *without* a flow — sessions
        // outlive flows by design, so the cap must hold with an empty flow
        // table (isolating the session bound from the flow bound).
        state.sessions.insert(
            0xaaaa_1111,
            ClientSession {
                server: Arc::new(ServerSession {
                    server_session_id: session_ids.next(),
                    next_packet_id: AtomicU::new(0),
                }),
                window: ReplayWindow::new(),
                last_seen_ms: monotonic_ms() as Uint,
            },
        );

        // An unseen session ID is rejected at the cap — `Ok(false)`, the
        // same saturation signal the flow cap returns.
        let control = client_control(0xbbbb_2222, 0);
        let verdict = handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"forged session",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            1,
        );
        assert!(
            matches!(verdict, Ok(false)),
            "unseen session ID must be dropped at the sessions cap: {verdict:?}"
        );
        assert_eq!(state.sessions.len(), 1, "no new entry was created");
        assert!(state.flows.is_empty(), "the drop preceded flow creation");

        // The known session ID is not subject to the cap: it passes the
        // (fresh) window and gets its flow.
        let control = client_control(0xaaaa_1111, 0);
        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"known session",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            1,
        )
        .unwrap());
        assert_eq!(state.flows.len(), 1);
    }

    /// §3.2.4's 60-second retention floor, decoupled from flow references:
    /// a session stays while a reply task can still answer under it OR
    /// while inside the floor measured from `last_seen_ms` — a flow dying
    /// early can no longer take the replay window down inside the header
    /// timestamp tolerance.
    #[test]
    fn session_retention_floor_outlives_flow_references() {
        let retain_ms = SESSION_MIN_RETAIN.as_millis() as Uint;
        let mk = |last_seen_ms: Uint| ClientSession {
            server: Arc::new(ServerSession {
                server_session_id: 1,
                next_packet_id: AtomicU::new(0),
            }),
            window: ReplayWindow::new(),
            last_seen_ms,
        };
        let now: Uint = retain_ms * 10;

        // Unreferenced (the map holds the only Arc) but inside the floor:
        // retained — this is the case an early-dead flow used to lose.
        let fresh = mk(now - retain_ms + 1);
        assert!(session_is_live(&fresh, now));

        // Unreferenced and exactly at the floor boundary: evicted.
        let stale = mk(now - retain_ms);
        assert!(!session_is_live(&stale, now));

        // Far past the floor but still referenced by a live reply task:
        // retained — replies may legitimately still go out under it.
        let ancient = mk(0);
        let _reply_task_handle = Arc::clone(&ancient.server);
        assert!(session_is_live(&ancient, now));

        // The Uint-domain subtraction is wrap-safe across the 32-bit
        // ~49.7-day monotonic boundary.
        let across_wrap = mk(Uint::MAX - 10);
        let now_after_wrap: Uint = 10;
        assert!(session_is_live(&across_wrap, now_after_wrap));
    }

    /// SIP022 §3.2.4: a changed client session ID on an existing `(peer,
    /// target)` key is a new relay session — the old flow must be replaced,
    /// not reused to echo the stale ID.
    #[tokio::test]
    async fn rotated_client_session_id_forces_a_new_flow() {
        let tunnel = direct_rule_tunnel();
        let (sock, session_ids) = server_sock_and_ids("2022-blake3-aes-256-gcm").await;
        let mut state = UdpRelayState::default();
        let peer = "127.0.0.1:12345".parse().unwrap();
        let dst = SocketAddr::from(([127, 0, 0, 1], 443));
        let target = Address::SocketAddress(dst);
        let key = (peer, FlowKey::Addr(dst));

        let old_csid = 0xaaaa_0001_u64;
        let control = client_control(old_csid, 0);
        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"first",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap());
        let old_conn = flow_conn(&state, &key).await;
        let old_server = Arc::clone(&state.sessions[&old_csid].server);

        // Same (peer, target), new client session ID: the flow must be
        // re-dialed so its replies echo the new ID.
        let new_csid = 0xbbbb_0002_u64;
        let control = client_control(new_csid, 0);
        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"second",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap());

        let flow = &state.flows[&key];
        assert_eq!(
            flow.client_session_id, new_csid,
            "the live flow must echo the new session ID"
        );
        let new_conn = flow_conn(&state, &key).await;
        assert!(
            !Arc::ptr_eq(&new_conn, &old_conn),
            "rotation must re-dial, not reuse the stale flow's conn"
        );
        assert_eq!(
            state.sessions.len(),
            2,
            "both client sessions keep their own server session"
        );
        assert_ne!(
            state.sessions[&old_csid].server.server_session_id,
            state.sessions[&new_csid].server.server_session_id,
            "each client session owns a distinct server session ID"
        );

        // Rotating back to A while A's session is still mapped: A's retained
        // replay window is reused — its already-seen packet ID 0 stays
        // dropped — and the flow re-dials back under session A.
        let control = client_control(old_csid, 0);
        let err = handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"replay of A",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap_err();
        assert!(err.contains("replay"), "A's window must persist: {err}");

        let control = client_control(old_csid, 1);
        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"back to A",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap());
        assert_eq!(state.flows[&key].client_session_id, old_csid);
        assert!(
            Arc::ptr_eq(&state.sessions[&old_csid].server, &old_server),
            "returning to a live session must reuse its server session"
        );
    }

    /// SIP022 §3.2.4: a re-sent datagram with an already-seen packet ID is
    /// replay — dropped before any forwarding work.
    #[tokio::test]
    async fn replayed_client_packet_id_is_dropped() {
        let tunnel = direct_rule_tunnel();
        let (sock, session_ids) = server_sock_and_ids("2022-blake3-aes-256-gcm").await;
        let mut state = UdpRelayState::default();
        let peer = "127.0.0.1:12345".parse().unwrap();
        let target = Address::SocketAddress(SocketAddr::from(([127, 0, 0, 1], 443)));
        let control = client_control(0xcccc_0003, 42);

        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"first",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap());

        // Same session + same packet ID → replay.
        let err = handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"retransmitted",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap_err();
        assert!(err.contains("replay"), "unexpected drop reason: {err}");

        // Same session + an *older* but still in-window packet ID →
        // accepted (real UDP reorders; the window is not strict-FIFO).
        let control = client_control(0xcccc_0003, 41);
        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"reordered",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap());

        // Same session + a fresh packet ID on the same flow → accepted.
        let control = client_control(0xcccc_0003, 43);
        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"next",
            peer,
            &target,
            Some(&control),
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap());
        assert_eq!(state.flows.len(), 1, "the replay never touched the table");
    }

    /// Issue #514 regression: when a flow's reply task dies (upstream conn
    /// gone), the flow is dead weight — the next datagram on the same
    /// `(peer, target)` must evict and re-dial, not write into a conn that
    /// can never answer.
    #[tokio::test]
    async fn dead_reply_task_evicts_flow_for_redial() {
        // REJECT conns' `read_packet` errors immediately, so the spawned
        // reply task sets `dead` as soon as it is polled.
        let tunnel = crate::test_rule_tunnel();
        let (sock, session_ids) = server_sock_and_ids("aes-256-gcm").await;
        let mut state = UdpRelayState::default();
        let peer = "127.0.0.1:12345".parse().unwrap();
        let target = Address::SocketAddress(SocketAddr::from(([127, 0, 0, 1], 443)));
        let key = (peer, FlowKey::Addr(SocketAddr::from(([127, 0, 0, 1], 443))));

        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"first",
            peer,
            &target,
            None,
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap());
        let dead_flow_conn = flow_conn(&state, &key).await;

        // Let the reply task run to its read error and mark the flow dead.
        for _ in 0..10 {
            tokio::task::yield_now().await;
            if state.flows[&key]
                .dead
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                break;
            }
        }
        assert!(
            state.flows[&key]
                .dead
                .load(std::sync::atomic::Ordering::Relaxed),
            "the reply task must mark the flow dead on upstream read error"
        );

        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"second",
            peer,
            &target,
            None,
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap());
        let redialed = flow_conn(&state, &key).await;
        assert!(
            !Arc::ptr_eq(&redialed, &dead_flow_conn),
            "a dead flow must be evicted and re-dialed, not reused"
        );
    }

    /// Issue #625 regression: the recv loop must never await a flow's
    /// resolve/route/dial — payloads queue onto a bounded per-flow channel
    /// and dispatch moves on. Under the old inline-await shape, a slow
    /// `dial_udp` stalled decrypt→dispatch for every client on the shared
    /// socket; here the proof is that with zero yields (the flow task has
    /// never been polled — no conn exists yet) datagrams still queue for
    /// the pending flow, a *different* destination gets its own flow
    /// immediately, and queue overflow drops without erroring.
    #[tokio::test]
    async fn datagrams_queue_off_loop_while_flow_establishes() {
        let tunnel = direct_rule_tunnel();
        let (sock, session_ids) = server_sock_and_ids("aes-256-gcm").await;
        let mut state = UdpRelayState::default();
        let peer = "127.0.0.1:12345".parse().unwrap();
        let dst = SocketAddr::from(([127, 0, 0, 1], 443));
        let target = Address::SocketAddress(dst);
        let key = (peer, FlowKey::Addr(dst));

        // Fill the queue past its bound while the task has never run —
        // every datagram is still "handled" (surplus drops silently).
        for _ in 0..UDP_FLOW_QUEUE + 10 {
            assert!(handle_ss_udp_datagram(
                tunnel.inner(),
                &sock,
                &mut state,
                b"payload",
                peer,
                &target,
                None,
                &session_ids,
                "ss",
                8388,
                8,
            )
            .unwrap());
        }
        assert_eq!(state.flows.len(), 1, "all datagrams share one flow");
        assert!(
            state.flows[&key].established.get().is_none(),
            "dispatch must not have waited on the flow's establish"
        );

        // A different destination on the same peer gets its own queued
        // flow without waiting for the first task either.
        let dst2 = SocketAddr::from(([127, 0, 0, 1], 853));
        assert!(handle_ss_udp_datagram(
            tunnel.inner(),
            &sock,
            &mut state,
            b"other",
            peer,
            &Address::SocketAddress(dst2),
            None,
            &session_ids,
            "ss",
            8388,
            8,
        )
        .unwrap());
        assert_eq!(state.flows.len(), 2);
        assert!(state.flows[&(peer, FlowKey::Addr(dst2))]
            .established
            .get()
            .is_none());

        // Once scheduled, each task dials and drains its queue in order.
        flow_conn(&state, &key).await;
        flow_conn(&state, &(peer, FlowKey::Addr(dst2))).await;
    }
}
