//! DNS over QUIC (RFC 9250) and DNS over HTTPS over HTTP/3 (`prefer-h3`).
//!
//! Both ride `quiche`, which links the same vendored BoringSSL as
//! `meow-transport` (via the `boring` crate), so the upstream certificate
//! decision is the shared one: chain and hostname validation against the
//! bundled Mozilla roots, through the same distrust-aware verify callback the
//! DoT/DoH path uses. No second crypto library joins the process and no
//! rustls client config is created.
//!
//! ## Architecture
//!
//! A [`QuicUpstream`] owns one long-lived QUIC connection per nameserver entry
//! and multiplexes every exchange over it. The connection is driven by a
//! background task that owns the socket and the [`quiche::Connection`];
//! callers hand it a serialized query and await a `oneshot` reply. A burst of
//! A/AAAA lookups therefore rides one connection instead of paying a
//! handshake each, and the task re-dials by itself after an idle timeout, a
//! peer close or a network change — the next query pays the handshake once
//! and the ones behind it share it.
//!
//! - **DoQ** follows RFC 9250: one bidirectional stream per query, the DNS
//!   message preceded by a two-octet length (the RFC 1035 §4.2.2 TCP
//!   framing), and the DNS transaction ID set to 0 on the wire — the peer
//!   MUST answer with ID 0, and the caller's real ID is restored before the
//!   shared response validation runs.
//! - **DoH3** is RFC 8484 over HTTP/3: one POST per query on its own request
//!   stream, `application/dns-message` both ways, `:status 200` required.
//!   `prefer-h3` is a preference, not a hard requirement: an exchange that
//!   fails at the QUIC layer falls back to the HTTP/2 / HTTP/1.1 DoH path in
//!   `client.rs`, and a failed handshake parks HTTP/3 for
//!   [`H3_RETRY_COOLDOWN`] so a server that does not speak HTTP/3 does not
//!   cost a handshake timeout on every query.
//!
//! Everything here is compiled only under the `quic-dns` feature, which
//! implies `encrypted` (the h1 fallback and certificate handling are shared
//! with DoH/DoT).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
use parking_lot::Mutex as SyncMutex;
use quiche::h3;
use quiche::h3::NameValue as _;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::client::{ClientError, DnsProxy, MAX_DOH_RESPONSE_BYTES};

/// Largest UDP datagram we build for one QUIC packet.
const MAX_DATAGRAM_SIZE: usize = 1350;
/// QUIC idle timeout: long enough that a bursty resolver keeps one connection
/// across quiet windows, short enough that a dead path is re-dialed promptly.
const IDLE_TIMEOUT_MS: u64 = 60_000;
const STREAM_RECEIVE_WINDOW: u64 = 1 << 20;
const CONN_RECEIVE_WINDOW: u64 = STREAM_RECEIVE_WINDOW * 4;
const MAX_CONCURRENT_STREAMS: u64 = 256;
/// ALPN for DNS over QUIC (RFC 9250 §4.1.1).
const ALPN_DOQ: &[u8] = b"doq";
/// How long a failed HTTP/3 handshake parks h3 for this upstream. mihomo
/// probes h3 and falls back to h1/h2 when QUIC is unavailable; parking the
/// attempt keeps that fallback from costing one handshake timeout per query.
const H3_RETRY_COOLDOWN: Duration = Duration::from_secs(600);

/// Which application protocol a [`QuicUpstream`] speaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum QuicMode {
    /// DNS over QUIC, RFC 9250.
    Doq,
    /// DNS over HTTPS over HTTP/3 (RFC 8484 over RFC 9114).
    Doh3 { path: Arc<str> },
}

impl QuicMode {
    fn alpn(&self) -> &'static [&'static [u8]] {
        match self {
            Self::Doq => &[ALPN_DOQ],
            Self::Doh3 { .. } => h3::APPLICATION_PROTOCOL,
        }
    }
}

/// A command handed to the connection driver task.
enum Cmd {
    Query {
        wire: Vec<u8>,
        reply: ReplySender,
    },
    /// Close the live connection; the next query re-dials.
    Reset {
        ack: oneshot::Sender<()>,
    },
}

/// The channel a dispatched query answers on.
type ReplySender = oneshot::Sender<Result<Vec<u8>, ClientError>>;

/// A stream id plus the exchange it now carries.
type Dispatched = (u64, Pending);

/// A dispatch failure together with the reply channel it still owns: the
/// caller fails that one query and leaves the connection running.
type DispatchError = (ClientError, ReplySender);

/// In-flight exchange waiting on the driver task.
struct Pending {
    reply: oneshot::Sender<Result<Vec<u8>, ClientError>>,
    /// Accumulates incoming response bytes (DoQ stream body / HTTP/3 DATA
    /// frames) until the stream finishes.
    buf: Vec<u8>,
    /// Bytes of the outgoing POST body not yet accepted by quiche (flow-control
    /// limited).  Non-empty only between a `send_body` → `h3::Error::Done`
    /// and the next successful flush of the connection.  Empty for DoQ entries.
    unsent: Vec<u8>,
}

impl Pending {
    fn new(reply: ReplySender) -> Self {
        Self {
            reply,
            buf: Vec::new(),
            unsent: Vec::new(),
        }
    }
}

enum IoKind {
    /// A connected UDP socket.
    Udp(UdpSocket),
    /// The proxy's UDP association for `?proxy=`.
    Proxied(Box<dyn meow_common::ProxyPacketConn>),
}

/// One socket's worth of packet I/O for a QUIC connection: a connected UDP
/// socket for a direct upstream, or the proxy's datagram association for
/// `?proxy=`.
struct Io {
    kind: IoKind,
    /// The dial target — also the only source a reply may come from. Both
    /// sides are canonicalised (`bind_udp_for_peer`'s contract), so an
    /// IPv4-mapped reply is not filtered out and quiche sees one path.
    peer: SocketAddr,
}

impl Io {
    fn local_addr(&self) -> SocketAddr {
        match &self.kind {
            IoKind::Udp(socket) => socket
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
            IoKind::Proxied(conn) => conn
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<()> {
        match &self.kind {
            IoKind::Udp(socket) => socket.send(buf).await.map(|_| ()),
            IoKind::Proxied(conn) => conn
                .write_packet(buf, &self.peer)
                .await
                .map(|_| ())
                // An adapter's `MeowError` carries the transport detail; the
                // QUIC driver only needs an io error to report the exchange.
                .map_err(|e| io::Error::other(e.to_string())),
        }
    }

    /// Read one datagram and report its source. quiche drops packets whose
    /// source is not a known path, so the real source — not the dial target —
    /// is what the caller must pass to `RecvInfo`.
    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.kind {
            IoKind::Udp(socket) => socket.recv(buf).await.map(|n| (n, self.peer)),
            IoKind::Proxied(conn) => loop {
                let (n, from) = conn
                    .read_packet(buf)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                // Per-packet conns report the real wire source (the address we
                // asked the proxy for); bound conns report an unspecified
                // address. Anything else belongs to another peer and must not
                // reach this connection.
                let mapped_unspecified = from.ip().to_canonical().is_unspecified();
                if mapped_unspecified || meow_common::canonical_socket_addr(from) == self.peer {
                    return Ok((n, from));
                }
            },
        }
    }
}

/// DNS over QUIC / DoH3 for one nameserver entry.
pub(crate) struct QuicUpstream {
    mode: QuicMode,
    server: SocketAddr,
    sni: Arc<str>,
    /// Extra CA roots (DER) for the handshake — empty in production; the
    /// integration tests inject a self-signed chain here instead of disabling
    /// verification (mirrors `DnsClient::with_tls_additional_roots`).
    /// Widening the set retires the live connection: it was verified against
    /// the old store.
    extra_roots: SyncMutex<Vec<Vec<u8>>>,
    /// Proxy adapter (`?proxy=`), attached by the sync builder before the
    /// first exchange; a `parking_lot` lock so `DnsClient::with_proxy` can
    /// stay a plain builder method.
    proxy: SyncMutex<Option<DnsProxy>>,
    proxy_target: SyncMutex<Option<(Arc<str>, u16)>>,
    /// The live driver task, spawned on first use.
    driver: Mutex<Option<Driver>>,
    /// Set by `reset_connections` / a proxy attach: the live connection was
    /// dialed under the old configuration and must not be reused.
    stale: AtomicBool,
    /// Before this instant HTTP/3 must not be attempted again (DoH3 only).
    h3_parked_until: SyncMutex<Option<std::time::Instant>>,
}

struct Driver {
    tx: mpsc::UnboundedSender<Cmd>,
    /// Set by the driver task when it exits; a caller that sees it drops the
    /// stale handle and redials.
    closed: Arc<AtomicBool>,
}

impl std::fmt::Debug for QuicUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicUpstream")
            .field("mode", &self.mode)
            .field("server", &self.server)
            .field("sni", &self.sni)
            .finish_non_exhaustive()
    }
}

impl QuicUpstream {
    pub(crate) fn new(mode: QuicMode, server: SocketAddr, sni: Arc<str>) -> Self {
        // `bind_udp_for_peer` canonicalises its peer and expects the caller to
        // `connect()` the canonical form; keeping one canonical address here
        // means the socket, `quiche::connect` and the reply filter agree (an
        // IPv4-mapped upstream would otherwise get an IPv4 socket dialled at a
        // V6-mapped address).
        let server = meow_common::canonical_socket_addr(server);
        Self {
            mode,
            server,
            sni,
            extra_roots: SyncMutex::new(Vec::new()),
            proxy: SyncMutex::new(None),
            proxy_target: SyncMutex::new(None),
            driver: Mutex::new(None),
            stale: AtomicBool::new(false),
            h3_parked_until: SyncMutex::new(None),
        }
    }

    /// Trust `der` in addition to the bundled roots — test hook, compiled
    /// only into test/debug builds like its DoT/DoH counterpart.
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn add_extra_root(&self, der: Vec<u8>) {
        self.extra_roots.lock().push(der);
        self.mark_stale();
    }

    pub(crate) fn set_proxy(&self, proxy: DnsProxy) {
        *self.proxy.lock() = Some(proxy);
        // A connection built before the proxy was attached dialed direct;
        // retire it so the next query goes through the adapter.
        self.mark_stale();
    }

    pub(crate) fn set_proxy_target(&self, host: Arc<str>, port: u16) {
        *self.proxy_target.lock() = Some((host, port));
    }

    /// Retire the live connection without waiting: the next exchange dials a
    /// fresh one. The synchronous counterpart of [`DnsClient::reset_connections`].
    pub(crate) fn mark_stale(&self) {
        self.stale.store(true, Ordering::Release);
        if let Ok(guard) = self.driver.try_lock() {
            if let Some(driver) = guard.as_ref() {
                driver.closed.store(true, Ordering::Release);
                driver
                    .tx
                    .send(Cmd::Reset {
                        ack: oneshot::channel().0,
                    })
                    .ok();
            }
        }
    }

    /// One exchange. `wire` is a serialized DNS message; DoQ zeroes its
    /// transaction ID on the wire (RFC 9250 §4.2.1) and restores the caller's
    /// before returning, so the response passes the shared validation.
    pub(crate) async fn exchange(&self, wire: &[u8]) -> Result<Vec<u8>, ClientError> {
        if wire.len() < 2 {
            return Err(ClientError::Protocol("query shorter than its ID"));
        }
        let original = u16::from_be_bytes([wire[0], wire[1]]);
        let mut request = wire.to_vec();
        if self.mode == QuicMode::Doq {
            request[0] = 0;
            request[1] = 0;
        }

        let mut response = self.exchange_once(&request).await?;

        if self.mode == QuicMode::Doq {
            if response.len() < 2 {
                return Err(ClientError::Protocol("response shorter than its ID"));
            }
            response[0..2].copy_from_slice(&original.to_be_bytes());
        }
        Ok(response)
    }

    /// One exchange, retried once on a connection-level failure: the driver
    /// task re-dials on the next command, so the second attempt reaches a
    /// fresh connection. Certificate failures are never retried (they would
    /// only fail again) and never trigger the h1 fallback in `client.rs`.
    async fn exchange_once(&self, wire: &[u8]) -> Result<Vec<u8>, ClientError> {
        let mut last: Option<ClientError> = None;
        for attempt in 0..2 {
            let tx = self.driver().await?;
            let (reply, rx) = oneshot::channel();
            if tx
                .send(Cmd::Query {
                    wire: wire.to_vec(),
                    reply,
                })
                .is_err()
            {
                self.drop_driver().await;
                if attempt == 1 {
                    return Err(last.unwrap_or_else(driver_gone));
                }
                continue;
            }
            match rx.await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(err)) => {
                    let retryable = matches!(err, ClientError::Io(_) | ClientError::Timeout(_));
                    if !retryable {
                        return Err(err);
                    }
                    self.drop_driver().await;
                    last = Some(err);
                }
                // The driver answered nothing (it shut down mid-flight).
                Err(_) => self.drop_driver().await,
            }
        }
        Err(last.unwrap_or_else(driver_gone))
    }

    /// Whether this upstream should currently attempt HTTP/3. Only meaningful
    /// for [`QuicMode::Doh3`]; `false` while a failed handshake is parked.
    pub(crate) fn h3_available(&self) -> bool {
        if !matches!(self.mode, QuicMode::Doh3 { .. }) {
            return false;
        }
        match *self.h3_parked_until.lock() {
            Some(until) => std::time::Instant::now() >= until,
            None => true,
        }
    }

    /// Park (or unpark) HTTP/3 after a handshake verdict.
    pub(crate) fn park_h3(&self, park: bool) {
        let mut parked = self.h3_parked_until.lock();
        *parked = park.then(|| std::time::Instant::now() + H3_RETRY_COOLDOWN);
    }

    async fn drop_driver(&self) {
        let mut slot = self.driver.lock().await;
        if let Some(driver) = slot.take() {
            driver.closed.store(true, Ordering::Release);
            // Tell the task to close its connection and exit. Without this the
            // old task keeps its socket and `quiche::Connection` alive while a
            // retry spawns a second one — two connections for one upstream.
            driver
                .tx
                .send(Cmd::Reset {
                    ack: oneshot::channel().0,
                })
                .ok();
        }
    }

    /// The live sender, spawning the driver task on first use (or after a
    /// [`Self::mark_stale`] retirement).
    async fn driver(&self) -> Result<mpsc::UnboundedSender<Cmd>, ClientError> {
        let mut slot = self.driver.lock().await;
        let stale = self.stale.swap(false, Ordering::AcqRel);
        if let Some(driver) = slot.as_ref() {
            if !stale && !driver.closed.load(Ordering::Acquire) {
                return Ok(driver.tx.clone());
            }
        }
        if let Some(old) = slot.take() {
            old.closed.store(true, Ordering::Release);
            old.tx
                .send(Cmd::Reset {
                    ack: oneshot::channel().0,
                })
                .ok();
        }
        let proxy = self.proxy.lock().clone();
        let proxy_target = self.proxy_target.lock().clone();
        let extra_roots = self.extra_roots.lock().clone();
        let (tx, rx) = mpsc::unbounded_channel();
        let closed = Arc::new(AtomicBool::new(false));
        let task = DriverTask {
            mode: self.mode.clone(),
            server: self.server,
            sni: Arc::clone(&self.sni),
            extra_roots,
            proxy,
            proxy_target,
            closed: Arc::clone(&closed),
        };
        tokio::spawn(task.run(rx));
        *slot = Some(Driver {
            tx: tx.clone(),
            closed,
        });
        Ok(tx)
    }
}

/// Owns the socket and the QUIC connection for the lifetime of one
/// connection generation.
struct DriverTask {
    mode: QuicMode,
    server: SocketAddr,
    sni: Arc<str>,
    extra_roots: Vec<Vec<u8>>,
    proxy: Option<DnsProxy>,
    proxy_target: Option<(Arc<str>, u16)>,
    closed: Arc<AtomicBool>,
}

impl DriverTask {
    async fn run(self, mut rx: mpsc::UnboundedReceiver<Cmd>) {
        // One connection generation per loop iteration; the next queued
        // command starts a new one. Commands that arrived while the previous
        // generation was dying wait here, so a redial serves them instead of
        // dropping them on the floor.
        let mut backlog: VecDeque<Cmd> = VecDeque::new();
        loop {
            let first = match backlog.pop_front() {
                Some(cmd) => cmd,
                None => match rx.recv().await {
                    Some(cmd) => cmd,
                    None => break,
                },
            };
            if let Cmd::Reset { ack } = first {
                let _ = ack.send(());
                continue;
            }
            if let Err(err) = self.serve(first, &mut rx, &mut backlog).await {
                // Every query this generation could not answer — including
                // the ones still queued behind a failed handshake — gets the
                // real reason, so the caller's retry sees `Tls`/`Io` (which
                // decides the DoH3 fallback) instead of a dropped channel.
                tracing::debug!(
                    server = %self.server,
                    %err,
                    "DNS-over-QUIC connection ended; the next query re-dials"
                );
                fail_commands(&mut backlog, &err);
            }
            if rx.is_closed() && backlog.is_empty() {
                break;
            }
        }
        self.closed.store(true, Ordering::Release);
    }

    /// Run one connection generation, starting with `first` as the first
    /// command. Returns after the connection dies. Unanswered in-flight
    /// queries are failed with the generation's error before returning.
    async fn serve(
        &self,
        first: Cmd,
        rx: &mut mpsc::UnboundedReceiver<Cmd>,
        backlog: &mut VecDeque<Cmd>,
    ) -> Result<(), ClientError> {
        let mut pending: HashMap<u64, Pending> = HashMap::new();
        let result = self.serve_conn(first, rx, backlog, &mut pending).await;
        if let Err(err) = &result {
            fail_all(std::mem::take(&mut pending), err);
        }
        result
    }

    /// The connection loop proper: `pending` is owned by [`Self::serve`] so
    /// an error path cannot strand an in-flight query.
    async fn serve_conn(
        &self,
        first: Cmd,
        rx: &mut mpsc::UnboundedReceiver<Cmd>,
        backlog: &mut VecDeque<Cmd>,
        pending: &mut HashMap<u64, Pending>,
    ) -> Result<(), ClientError> {
        let io = self.open_socket().await?;
        let local = io.local_addr();
        let mut config = build_config(&self.mode, &self.extra_roots)?;
        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        rand::rng().fill_bytes(&mut scid);
        let scid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quiche::connect(Some(&self.sni), &scid, local, self.server, &mut config)
            .map_err(quic_error)?;

        let mut h3_conn: Option<h3::Connection> = None;
        let mut next_stream_id: u64 = 0;
        let mut buf = vec![0u8; 65_535];
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        // Shared read scratch for stream bodies: the driver's hot loop must
        // not allocate per datagram batch.
        let mut tmp = vec![0u8; 4096];
        backlog.push_back(first);

        loop {
            // Dispatch queued commands once the handshake is complete.
            while conn.is_established() {
                let cmd = match backlog.pop_front() {
                    Some(cmd) => cmd,
                    None => match rx.try_recv() {
                        Ok(cmd) => cmd,
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            conn.close(false, 0, b"shutdown").ok();
                            let _ = flush(&mut conn, &io, &mut out).await;
                            return Ok(());
                        }
                    },
                };
                match cmd {
                    Cmd::Reset { ack } => {
                        let _ = ack.send(());
                        conn.close(false, 0, b"reset").ok();
                        let _ = flush(&mut conn, &io, &mut out).await;
                        fail_all(std::mem::take(pending), &closed_error());
                        return Ok(());
                    }
                    Cmd::Query { wire, reply } => {
                        if reply.is_closed() {
                            continue;
                        }
                        if h3_conn.is_none() && matches!(self.mode, QuicMode::Doh3 { .. }) {
                            let h3_config = h3::Config::new().map_err(h3_error)?;
                            h3_conn = Some(
                                h3::Connection::with_transport(&mut conn, &h3_config)
                                    .map_err(h3_error)?,
                            );
                        }
                        // A dispatch failure means "no stream capacity right
                        // now" (`Error::Done` / `StreamLimit`), not a broken
                        // connection: fail only this query. Propagating it
                        // with `?` would tear the generation down and fail up
                        // to 255 unrelated in-flight exchanges.
                        match h3_conn.as_mut() {
                            Some(h3_conn) => match send_h3_request(
                                &self.mode, &self.sni, h3_conn, &mut conn, wire, reply,
                            ) {
                                Ok((id, entry)) => pending.insert(id, entry),
                                Err((err, reply)) => {
                                    let _ = reply.send(Err(err));
                                    None
                                }
                            },
                            None => {
                                match send_doq_query(&mut conn, &mut next_stream_id, &wire, reply) {
                                    Ok((id, entry)) => pending.insert(id, entry),
                                    Err((err, reply)) => {
                                        let _ = reply.send(Err(err));
                                        None
                                    }
                                }
                            }
                        };
                    }
                }
            }

            flush(&mut conn, &io, &mut out).await?;
            // Retry any DoH3 body bytes that were flow-control limited in
            // send_h3_request or a previous iteration.  After flush, quiche
            // has drained the send buffer and may accept more data.
            if let Some(h3) = h3_conn.as_mut() {
                for (id, entry) in pending.iter_mut() {
                    if entry.unsent.is_empty() {
                        continue;
                    }
                    loop {
                        match h3.send_body(&mut conn, *id, &entry.unsent, true) {
                            Ok(written) => {
                                entry.unsent.drain(..written);
                                if entry.unsent.is_empty() {
                                    break;
                                }
                            }
                            Err(h3::Error::Done) => break,
                            Err(_) => {
                                // Stream-level error: poison the entry so
                                // drain_h3 will pick up the Reset event and
                                // fail the query.
                                entry.unsent.clear();
                                break;
                            }
                        }
                    }
                }
            }
            drain(&self.mode, &mut conn, h3_conn.as_mut(), pending, &mut tmp);
            prune_abandoned(&self.mode, &mut conn, pending);

            if conn.is_closed() || conn.is_timed_out() {
                // A verdict, not a redial: report it so queued queries get
                // the reason (a TLS failure in particular must not be retried
                // into an endless reconnect loop).
                fail_all(std::mem::take(pending), &closed_error());
                return Err(closed_error());
            }

            let timeout = conn.timeout();
            tokio::select! {
                biased;
                cmd = rx.recv() => match cmd {
                    Some(Cmd::Reset { ack }) => {
                        let _ = ack.send(());
                        conn.close(false, 0, b"reset").ok();
                        let _ = flush(&mut conn, &io, &mut out).await;
                        fail_all(std::mem::take(pending), &closed_error());
                        return Ok(());
                    }
                    Some(cmd) => backlog.push_back(cmd),
                    None => {
                        conn.close(false, 0, b"shutdown").ok();
                        let _ = flush(&mut conn, &io, &mut out).await;
                        fail_all(std::mem::take(pending), &closed_error());
                        return Ok(());
                    }
                },
                r = io.recv(&mut buf) => {
                    // The real source, not the dial target: quiche drops
                    // packets whose path it does not know, and a proxied
                    // association may answer from the address it resolved.
                    let (n, from) = r?;
                    let info = quiche::RecvInfo { to: local, from };
                    match conn.recv(&mut buf[..n], info) {
                        Ok(_) | Err(quiche::Error::Done) => {}
                        Err(e) => {
                            // Includes `TlsFail`: the certificate/handshake
                            // verdict belongs to the query that opened the
                            // connection, not to a retry loop.
                            return Err(quic_error(e));
                        }
                    }
                }
                _ = sleep_opt(timeout) => conn.on_timeout(),
            }
        }
    }

    /// Open the datagram socket: direct (socket family and outbound-interface
    /// binding follow the peer, Android `protect()` applied) or the proxy's
    /// UDP association for `?proxy=`.
    async fn open_socket(&self) -> Result<Io, ClientError> {
        match &self.proxy {
            Some(proxy) => {
                use meow_common::{ConnType, Metadata, Network};
                // A proxied *hostname* upstream is resolved by the proxy, so
                // the peer address is unknown until after the handshake — but
                // quiche needs it *before* (it drops packets from an unknown
                // path), so this combination cannot work. Refuse it instead of
                // hanging until the query timeout; the config layer rejects it
                // at load, this is the belt-and-braces guard.
                if self.proxy_target.is_some() {
                    return Err(ClientError::Protocol(
                        "DNS over QUIC through a proxy needs an IP-literal server address: \
                         the QUIC peer must be known before the handshake, and a proxied \
                         hostname is resolved remotely",
                    ));
                }
                let dst_ip = self.server.ip();
                let host = smol_str::SmolStr::from(dst_ip.to_string());
                let dst_port = self.server.port();
                let metadata = Metadata {
                    network: Network::Udp,
                    conn_type: ConnType::Inner,
                    host,
                    dst_ip: Some(dst_ip),
                    dst_port,
                    // Resolver housekeeping: a `lazy` group serving this dial
                    // must not count it as use (ADR-0012).
                    internal: true,
                    ..Default::default()
                };
                let conn = meow_common::socket_protect::dns_via_proxy_dial_scope(
                    proxy.dial_udp(&metadata),
                )
                .await
                .map_err(|e| ClientError::Io(e.into_io_error("dns-via-proxy udp dial")))?;
                Ok(Io {
                    kind: IoKind::Proxied(conn),
                    peer: self.server,
                })
            }
            None => {
                let socket = meow_common::bind_udp_for_peer(self.server.ip()).await?;
                socket.connect(self.server).await?;
                Ok(Io {
                    kind: IoKind::Udp(socket),
                    peer: self.server,
                })
            }
        }
    }
}

/// Wait for quiche's next timer, or park forever when none is pending (the
/// command arm of the `select!` still makes progress).
async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(timeout) => tokio::time::sleep(timeout).await,
        None => std::future::pending().await,
    }
}

async fn flush(conn: &mut quiche::Connection, io: &Io, out: &mut [u8]) -> Result<(), ClientError> {
    loop {
        match conn.send(out) {
            Ok((write, _info)) => {
                if write > 0 {
                    io.send(&out[..write]).await?;
                }
                if write < MAX_DATAGRAM_SIZE {
                    return Ok(());
                }
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => return Err(quic_error(e)),
        }
    }
}

/// Put one DoQ query on a fresh bidirectional stream, length-prefixed.
///
/// The error arm hands the reply channel back so the caller can fail *that*
/// query without touching the connection.
fn send_doq_query(
    conn: &mut quiche::Connection,
    next_stream_id: &mut u64,
    wire: &[u8],
    reply: ReplySender,
) -> Result<Dispatched, DispatchError> {
    if wire.len() > u16::MAX as usize {
        return Err((
            ClientError::Protocol("query larger than 65535 octets"),
            reply,
        ));
    }
    let id = *next_stream_id;
    *next_stream_id += 4; // next client-initiated bidirectional stream
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    framed.extend_from_slice(wire);
    match conn.stream_send(id, &framed, true) {
        Ok(_) => Ok((id, Pending::new(reply))),
        Err(e) => Err((quic_error(e), reply)),
    }
}

/// Put one DoH3 query on its own request stream.
fn send_h3_request(
    mode: &QuicMode,
    sni: &str,
    h3_conn: &mut h3::Connection,
    conn: &mut quiche::Connection,
    wire: Vec<u8>,
    reply: ReplySender,
) -> Result<Dispatched, DispatchError> {
    let QuicMode::Doh3 { path } = mode else {
        unreachable!("send_h3_request on a non-HTTP/3 mode");
    };
    let headers = [
        h3::Header::new(b":method", b"POST"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", sni.as_bytes()),
        h3::Header::new(b":path", path.as_bytes()),
        h3::Header::new(b"accept", b"application/dns-message"),
        h3::Header::new(b"content-type", b"application/dns-message"),
        h3::Header::new(b"user-agent", b"meow-rs"),
    ];
    let id = match h3_conn.send_request(conn, &headers, false) {
        Ok(id) => id,
        Err(e) => return Err((h3_error(e), reply)),
    };
    let mut body = wire;
    loop {
        match h3_conn.send_body(conn, id, &body, true) {
            Ok(written) => {
                body.drain(..written);
                if body.is_empty() {
                    break;
                }
            }
            // Flow-control: quiche cannot accept more data right now.  Store
            // the remaining bytes so the driver loop can retry after the next
            // flush drains the congestion window.  This is not EOF — the
            // stream is still open and the peer has not seen the FIN yet.
            Err(h3::Error::Done) => {
                let mut entry = Pending::new(reply);
                entry.unsent = body;
                return Ok((id, entry));
            }
            // The request is already on the stream; a body-level failure is
            // this query's verdict, and the stream is left for the peer to
            // reset (`drain_h3` reports it).
            Err(e) => return Err((h3_error(e), reply)),
        }
    }
    Ok((id, Pending::new(reply)))
}

/// Collect whatever the peer has already delivered for the in-flight
/// exchanges: DoQ stream bytes, or HTTP/3 events and body.
fn drain(
    mode: &QuicMode,
    conn: &mut quiche::Connection,
    mut h3_conn: Option<&mut h3::Connection>,
    pending: &mut HashMap<u64, Pending>,
    tmp: &mut [u8],
) {
    if pending.is_empty() {
        return;
    }
    match (mode, h3_conn.as_mut()) {
        (QuicMode::Doq, _) => drain_doq(conn, pending, tmp),
        (QuicMode::Doh3 { .. }, Some(h3_conn)) => drain_h3(conn, h3_conn, pending, tmp),
        (QuicMode::Doh3 { .. }, None) => {}
    }
}

/// Drop exchanges the caller abandoned (outer timeout, dropped future) and
/// release their streams. A long-lived connection would otherwise accumulate
/// one entry per timed-out query until `MAX_CONCURRENT_STREAMS` is exhausted.
fn prune_abandoned(
    mode: &QuicMode,
    conn: &mut quiche::Connection,
    pending: &mut HashMap<u64, Pending>,
) {
    if pending.is_empty() {
        return;
    }
    pending.retain(|id, entry| {
        if !entry.reply.is_closed() {
            return true;
        }
        if matches!(mode, QuicMode::Doq) {
            let _ = conn.stream_shutdown(*id, quiche::Shutdown::Read, 0);
        }
        false
    });
}

fn drain_doq(conn: &mut quiche::Connection, pending: &mut HashMap<u64, Pending>, tmp: &mut [u8]) {
    let mut finished: Vec<u64> = Vec::new();
    for (id, entry) in pending.iter_mut() {
        let mut broken = false;
        loop {
            match conn.stream_recv(*id, tmp) {
                Ok((n, fin)) => {
                    entry.buf.extend_from_slice(&tmp[..n]);
                    if fin || doq_frame_complete(&entry.buf) {
                        finished.push(*id);
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(_) => {
                    broken = true;
                    break;
                }
            }
        }
        if broken {
            finished.push(*id);
        }
    }
    for id in finished {
        let Some(entry) = pending.remove(&id) else {
            continue;
        };
        // Strip the two-octet length prefix; the body is the DNS message.
        if entry.buf.len() < 2 {
            let _ = entry
                .reply
                .send(Err(ClientError::Protocol("truncated DoQ response")));
            continue;
        }
        let len = usize::from(u16::from_be_bytes([entry.buf[0], entry.buf[1]]));
        if entry.buf.len() < len + 2 {
            let _ = entry
                .reply
                .send(Err(ClientError::Protocol("truncated DoQ response")));
            continue;
        }
        let body = entry.buf[2..2 + len].to_vec();
        let _ = entry.reply.send(Ok(body));
    }
}

/// A DoQ response is complete once its two-octet length and body arrived.
fn doq_frame_complete(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    buf.len() >= len + 2
}

fn drain_h3(
    conn: &mut quiche::Connection,
    h3_conn: &mut h3::Connection,
    pending: &mut HashMap<u64, Pending>,
    tmp: &mut [u8],
) {
    loop {
        let (stream_id, event) = match h3_conn.poll(conn) {
            Ok(event) => event,
            Err(h3::Error::Done) => return,
            Err(e) => {
                fail_all(std::mem::take(pending), &h3_error(e));
                return;
            }
        };
        if !pending.contains_key(&stream_id) {
            continue;
        }
        match event {
            h3::Event::Headers { list, .. } => {
                let status = list
                    .iter()
                    .find(|h| h.name() == b":status")
                    .map(|h| h.value().to_vec());
                if status.as_deref() != Some(b"200") {
                    if let Some(entry) = pending.remove(&stream_id) {
                        let _ = entry.reply.send(Err(ClientError::Protocol(
                            "DoH3 upstream returned a non-200 status",
                        )));
                    }
                }
            }
            h3::Event::Data => {
                let mut overflowed = false;
                while let Some(entry) = pending.get_mut(&stream_id) {
                    match h3_conn.recv_body(conn, stream_id, tmp) {
                        Ok(n) => {
                            entry.buf.extend_from_slice(&tmp[..n]);
                            // Same bound as the HTTP/1.1 DoH path: a hostile
                            // upstream must not drive unbounded growth.
                            if entry.buf.len() > MAX_DOH_RESPONSE_BYTES {
                                overflowed = true;
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                if overflowed {
                    if let Some(entry) = pending.remove(&stream_id) {
                        let _ = entry.reply.send(Err(ClientError::Protocol(
                            "DoH3 response exceeds the maximum DNS message size",
                        )));
                    }
                }
            }
            h3::Event::Finished => {
                let Some(entry) = pending.remove(&stream_id) else {
                    continue;
                };
                if entry.buf.len() > MAX_DOH_RESPONSE_BYTES {
                    let _ = entry.reply.send(Err(ClientError::Protocol(
                        "DoH3 response exceeds the maximum DNS message size",
                    )));
                } else if entry.buf.is_empty() {
                    let _ = entry
                        .reply
                        .send(Err(ClientError::Protocol("empty DoH3 response body")));
                } else {
                    let _ = entry.reply.send(Ok(entry.buf));
                }
            }
            h3::Event::Reset(_) => {
                if let Some(entry) = pending.remove(&stream_id) {
                    let _ = entry
                        .reply
                        .send(Err(ClientError::Protocol("DoH3 stream reset by peer")));
                }
            }
            _ => {}
        }
    }
}

/// Fail every command still waiting for a connection.
fn fail_commands(backlog: &mut VecDeque<Cmd>, err: &ClientError) {
    for cmd in backlog.drain(..) {
        if let Cmd::Query { reply, .. } = cmd {
            let _ = reply.send(Err(same_error(err)));
        }
    }
}

fn fail_all(pending: HashMap<u64, Pending>, err: &ClientError) {
    for (_, entry) in pending {
        let _ = entry.reply.send(Err(same_error(err)));
    }
}

/// Rebuild a `ClientError` so one verdict can be handed to several callers.
fn same_error(err: &ClientError) -> ClientError {
    match err {
        ClientError::Io(e) => ClientError::Io(io::Error::new(e.kind(), e.to_string())),
        ClientError::Timeout(d) => ClientError::Timeout(*d),
        ClientError::Protocol(m) => ClientError::Protocol(m),
        ClientError::Tls(m) => ClientError::Tls(m.clone()),
        other => ClientError::Protocol(match other {
            ClientError::Rcode(_) => "upstream rcode",
            ClientError::Proto(_) => "dns proto error",
            ClientError::Decode(_) => "dns decode error",
            _ => "dns upstream error",
        }),
    }
}

fn driver_gone() -> ClientError {
    ClientError::Io(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "DNS-over-QUIC driver task exited",
    ))
}

fn closed_error() -> ClientError {
    ClientError::Io(io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "QUIC connection closed",
    ))
}

fn build_config(mode: &QuicMode, extra_roots: &[Vec<u8>]) -> Result<quiche::Config, ClientError> {
    let mut ssl = SslContextBuilder::new(SslMethod::tls()).map_err(tls_error)?;
    seed_roots(&mut ssl, extra_roots)?;
    // quiche installs the SNI as the verify-param hostname per connection and
    // never calls `verify_peer`, so the mode set here is what BoringSSL
    // enforces (same contract as the hysteria2 QUIC client).
    ssl.set_verify_callback(
        SslVerifyMode::PEER,
        meow_transport::tls::distrust::verify_callback,
    );
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl)
        .map_err(tls_error)?;
    config
        .set_application_protos(mode.alpn())
        .map_err(tls_error)?;
    config.set_max_idle_timeout(IDLE_TIMEOUT_MS);
    config.set_initial_max_data(CONN_RECEIVE_WINDOW);
    config.set_initial_max_stream_data_bidi_local(STREAM_RECEIVE_WINDOW);
    config.set_initial_max_stream_data_bidi_remote(STREAM_RECEIVE_WINDOW);
    config.set_initial_max_stream_data_uni(STREAM_RECEIVE_WINDOW);
    config.set_initial_max_streams_bidi(MAX_CONCURRENT_STREAMS);
    config.set_initial_max_streams_uni(MAX_CONCURRENT_STREAMS);
    config.set_disable_active_migration(true);
    Ok(config)
}

/// Seed the BoringSSL verify store with the Mozilla bundle (plus any
/// test-only extra roots).
fn seed_roots(ssl: &mut SslContextBuilder, extra_roots: &[Vec<u8>]) -> Result<(), ClientError> {
    let mut store = boring::x509::store::X509StoreBuilder::new()
        .map_err(|e| ClientError::Tls(format!("X509StoreBuilder: {e}")))?;
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        let x509 = boring::x509::X509::from_der(cert.as_ref())
            .map_err(|e| ClientError::Tls(format!("root cert parse: {e}")))?;
        store
            .add_cert(x509)
            .map_err(|e| ClientError::Tls(format!("root store add_cert: {e}")))?;
    }
    for der in extra_roots {
        let x509 = boring::x509::X509::from_der(der)
            .map_err(|e| ClientError::Tls(format!("extra root parse: {e}")))?;
        store
            .add_cert(x509)
            .map_err(|e| ClientError::Tls(format!("extra root add_cert: {e}")))?;
    }
    ssl.set_cert_store_builder(store);
    Ok(())
}

fn tls_error(e: impl std::fmt::Display) -> ClientError {
    ClientError::Tls(format!("quiche: {e}"))
}

fn quic_error(e: quiche::Error) -> ClientError {
    match e {
        quiche::Error::TlsFail => ClientError::Tls("QUIC handshake failed".to_string()),
        other => ClientError::Io(io::Error::other(format!("quiche: {other}"))),
    }
}

fn h3_error(e: h3::Error) -> ClientError {
    ClientError::Io(io::Error::other(format!("DoH3: {e}")))
}
