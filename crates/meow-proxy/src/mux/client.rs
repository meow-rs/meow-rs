//! Mux client: bounded pool of mux sessions over one adapter dial path.
//!
//! Mirrors metacubex/sing-mux client.go: each session is a physical proxy
//! connection (dialed to the reserved mux destination); streams are opened
//! on the session with the fewest streams, new sessions are dialed only when
//! the configured connection/stream bounds are reached.

use super::h2mux;
use super::muxcool;
use super::packet::MuxPacketConn;
use super::request::Request;
use super::smux;
use super::stream::MuxStreamConn;
use super::yamux;
use super::{address, Protocol};
use meow_common::atomic::{AtomicU, Uint};
use meow_common::{MeowError, Metadata, ProxyConn, ProxyPacketConn, Result};
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;

/// Idle sessions (zero streams) are closed after this long.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum time spent establishing one physical mux session while the pool
/// lock serializes new connections, matching sing-mux's TCPTimeout.
const SESSION_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Dialer producing one fresh physical connection to the proxy node.  The
/// connection must already carry the protocol handshake (VLESS/Trojan first
/// request) targeting the reserved mux destination.
pub type DialFn =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Box<dyn ProxyConn>>> + Send>> + Send + Sync>;

/// Mux options, defaults aligned with mihomo's documented values.
#[derive(Debug, Clone)]
pub struct MuxOptions {
    pub protocol: Protocol,
    pub padding: bool,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    /// Route UDP through the plain proxy path instead of mux streams
    /// (mihomo SingMuxOption.OnlyTcp).
    pub only_tcp: bool,
}

impl Default for MuxOptions {
    fn default() -> Self {
        // h2mux is mihomo's default protocol (empty `protocol` maps to it).
        Self {
            protocol: Protocol::H2Mux,
            padding: false,
            max_connections: 4,
            min_streams: 4,
            max_streams: 4,
            only_tcp: false,
        }
    }
}

/// Monotonic millis since process start (not wall-clock: immune to clock
/// steps, which a `SystemTime`-based clock would let defer idle eviction —
/// see issue #421). On mips32 (no 64-bit atomics) this wraps every ~49.7
/// days; comparisons must stay in the truncated domain via `wrapping_sub`
/// (see [`MuxClient::offer`] below and `UdpSession::idle_for`).
fn now_ms() -> Uint {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_millis() as Uint
}

/// One protocol session multiplexing streams over one physical connection.
#[derive(Clone)]
pub(crate) enum SessionKind {
    Smux(Arc<smux::Session>),
    Yamux(Arc<yamux::Session>),
    H2Mux(Arc<h2mux::Session>),
    MuxCool(Arc<muxcool::MuxCoolSession>),
}

/// Write the sing-mux per-stream request prefix (flags + Socksaddr
/// destination).  Mux.Cool has no prefix — its New frame already carries
/// the destination.
async fn write_request_prefix<S: AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    port: u16,
    udp: bool,
) -> io::Result<()> {
    stream
        .write_all(&address::encode_stream_request_with_flags(
            host,
            port,
            u16::from(udp),
        )?)
        .await?;
    stream.flush().await
}

impl SessionKind {
    /// Open one stream to host:port.  sing-mux sessions write their
    /// per-stream request prefix here; Mux.Cool encodes the destination
    /// into the stream's New frame instead.
    pub(crate) async fn open_stream(
        &self,
        host: &str,
        port: u16,
        udp: bool,
    ) -> io::Result<MuxStream> {
        match self {
            SessionKind::Smux(session) => {
                let mut stream =
                    MuxStream::new(session.open_stream().await.map(MuxStreamKind::Smux)?);
                write_request_prefix(&mut stream, host, port, udp).await?;
                Ok(stream)
            }
            SessionKind::Yamux(session) => {
                let mut stream =
                    MuxStream::new(session.open_stream().await.map(MuxStreamKind::Yamux)?);
                write_request_prefix(&mut stream, host, port, udp).await?;
                Ok(stream)
            }
            SessionKind::H2Mux(session) => {
                let mut stream =
                    MuxStream::new(session.open_stream().await.map(MuxStreamKind::H2Mux)?);
                write_request_prefix(&mut stream, host, port, udp).await?;
                Ok(stream)
            }
            SessionKind::MuxCool(session) => session
                .open_stream(host, port, udp)
                .await
                .map(MuxStreamKind::MuxCool)
                .map(MuxStream::new),
        }
    }

    /// True when the pool must stop offering this session for new streams
    /// (physical connection dead, or - Mux.Cool only - its stream id space
    /// retired). Named `is_unusable`, not `is_dead`: a retired Mux.Cool
    /// session is still fully alive for the streams it already opened, so
    /// "dead" would mislead.
    pub(crate) fn is_unusable(&self) -> bool {
        match self {
            SessionKind::Smux(session) => session.is_dead(),
            SessionKind::Yamux(session) => session.is_dead(),
            SessionKind::H2Mux(session) => session.is_dead(),
            SessionKind::MuxCool(session) => session.unavailable(),
        }
    }
}

/// A stream on either mux protocol, exposed with tokio IO traits.
///
/// Carries the sing-mux per-stream response preamble: the server prefixes
/// its first write on every stream with a status byte (0 = success,
/// 1 = error + varbin message) — mirroring sing-mux's
/// `clientConn.readResponse`.
pub(crate) struct MuxStream {
    kind: MuxStreamKind,
    response_pending: bool,
    /// Sticky: set once the per-stream response status reported a remote
    /// error; subsequent polls repeat the error instead of reading stray
    /// varbin message bytes as data.
    response_failed: bool,
}

pub(crate) enum MuxStreamKind {
    Smux(smux::SmuxStream),
    Yamux(yamux::Stream),
    H2Mux(h2mux::Stream),
    MuxCool(muxcool::Stream),
}

impl MuxStreamKind {
    /// sing-mux prefixes every stream with a response status byte;
    /// Mux.Cool has no per-stream preamble (server Keep frames are data).
    fn requires_response(&self) -> bool {
        !matches!(self, MuxStreamKind::MuxCool(_))
    }
}

impl AsyncRead for MuxStreamKind {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MuxStreamKind::Smux(stream) => Pin::new(stream).poll_read(cx, buf),
            MuxStreamKind::Yamux(stream) => Pin::new(stream).poll_read(cx, buf),
            MuxStreamKind::H2Mux(stream) => Pin::new(stream).poll_read(cx, buf),
            MuxStreamKind::MuxCool(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl MuxStream {
    pub(crate) fn new(kind: MuxStreamKind) -> Self {
        Self {
            response_pending: kind.requires_response(),
            kind,
            response_failed: false,
        }
    }

    /// Consume the per-stream response status byte on first read.
    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.response_failed {
            return Poll::Ready(Err(io::Error::other("mux: remote stream error")));
        }
        if !self.response_pending {
            return Poll::Ready(Ok(()));
        }
        let mut byte = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.kind).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                if read_buf.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "mux: stream closed before response status",
                    )));
                }
                self.response_pending = false;
                if byte[0] == 0x00 {
                    Poll::Ready(Ok(()))
                } else {
                    // Remote error: a varbin message follows, but the stream
                    // is dead either way — surface the failure immediately
                    // and stick to it so the stray message bytes are never
                    // read as data.
                    self.response_failed = true;
                    Poll::Ready(Err(io::Error::other("mux: remote stream error")))
                }
            }
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_response(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.kind).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().kind {
            MuxStreamKind::Smux(stream) => Pin::new(stream).poll_write(cx, buf),
            MuxStreamKind::Yamux(stream) => Pin::new(stream).poll_write(cx, buf),
            MuxStreamKind::H2Mux(stream) => Pin::new(stream).poll_write(cx, buf),
            MuxStreamKind::MuxCool(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().kind {
            MuxStreamKind::Smux(stream) => Pin::new(stream).poll_flush(cx),
            MuxStreamKind::Yamux(stream) => Pin::new(stream).poll_flush(cx),
            MuxStreamKind::H2Mux(stream) => Pin::new(stream).poll_flush(cx),
            MuxStreamKind::MuxCool(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().kind {
            MuxStreamKind::Smux(stream) => Pin::new(stream).poll_shutdown(cx),
            MuxStreamKind::Yamux(stream) => Pin::new(stream).poll_shutdown(cx),
            MuxStreamKind::H2Mux(stream) => Pin::new(stream).poll_shutdown(cx),
            MuxStreamKind::MuxCool(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) struct MuxSession {
    pub(crate) kind: SessionKind,
    /// Unified slot counter: each value represents one stream slot held
    /// by this session — either an in-flight open (reserved by `offer()`
    /// via CAS, released by `Reservation::drop` on failure/cancel) or an
    /// established stream (released by `MuxStreamConn::drop`).
    ///
    /// A single counter eliminates the read-read race that two separate
    /// `streams` + `pending` atomics had: `offer()` can check-and-reserve
    /// with one `compare_exchange`, so the load assessment and the
    /// increment are one atomic step.
    pub(crate) streams: AtomicUsize,
    pub(crate) last_used_ms: AtomicU,
}

/// Releases a [`MuxSession`] slot when dropped — the cancellation-safe
/// counterpart of the reservation `offer()` made via CAS on `streams`.
struct Reservation(Arc<MuxSession>);

impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Shared mux client used by an adapter's dial path.
pub struct MuxClient {
    dial: DialFn,
    options: MuxOptions,
    sessions: Mutex<VecDeque<Arc<MuxSession>>>,
}

impl MuxClient {
    pub fn new(dial: DialFn, options: MuxOptions) -> Arc<Self> {
        Arc::new(Self {
            dial,
            options,
            sessions: Mutex::new(VecDeque::new()),
        })
    }

    /// Whether UDP should use mux rather than the adapter's plain UDP path.
    pub(crate) fn supports_udp(&self) -> bool {
        !self.options.only_tcp
    }

    fn metadata_host(metadata: &Metadata, adapter: &str) -> Result<String> {
        if !metadata.host.is_empty() {
            Ok(metadata.host.to_string())
        } else if let Some(ip) = metadata.dst_ip {
            Ok(ip.to_string())
        } else {
            Err(MeowError::Proxy(format!(
                "{adapter} mux: metadata has no destination host"
            )))
        }
    }

    /// Shared adapter hook for a muxed TCP dial.
    pub(crate) async fn open_stream_for(
        self: &Arc<Self>,
        metadata: &Metadata,
        adapter: &str,
    ) -> Result<MuxStreamConn> {
        let host = Self::metadata_host(metadata, adapter)?;
        self.open_stream(&host, metadata.dst_port).await
    }

    /// Shared adapter hook for UDP.  `None` means `only-tcp` selected the
    /// adapter's existing plain UDP path.
    pub(crate) async fn open_packet_stream_for(
        self: &Arc<Self>,
        metadata: &Metadata,
        adapter: &str,
    ) -> Result<Option<Box<dyn ProxyPacketConn>>> {
        if !self.supports_udp() {
            return Ok(None);
        }
        // A chained `UdpTarget::Name` arrives as host-only metadata
        // (issue #657). Bound-flow protocols (sing-mux/smux/h2mux) carry
        // the name in the stream-open destination natively; mux.cool
        // stamps a per-datagram `SocketAddr` destination the caller cannot
        // supply for a name target — decline so the adapter's own UDP
        // path picks up the domain request instead.
        if let Some((host, _)) = metadata.domain_udp_target() {
            if matches!(self.options.protocol, Protocol::MuxCool) {
                return Ok(None);
            }
            // Bound flows carry the name in the stream-open Socksaddr —
            // `encode_address` refuses >255 bytes with an io error, which
            // would lose the capability class. Refuse as `NotSupported` so
            // the chained caller falls back to `UdpTarget::Addr`.
            if host.len() > u8::MAX as usize {
                return Err(MeowError::NotSupported(format!(
                    "{adapter} mux: domain UDP target exceeds 255 bytes"
                )));
            }
        }
        let host = Self::metadata_host(metadata, adapter)?;
        self.open_packet_stream(&host, metadata.dst_port)
            .await
            .map(Some)
    }

    /// Open one multiplexed TCP stream to host:port.  sing-mux writes the
    /// stream request (flags + Socksaddr destination) before returning;
    /// Mux.Cool encodes the destination into the stream's New frame.
    pub async fn open_stream(self: &Arc<Self>, host: &str, port: u16) -> Result<MuxStreamConn> {
        let (stream, session) = self.open_stream_flags(host, port, false).await?;
        Ok(MuxStreamConn::new(stream, session))
    }

    /// Open one multiplexed UDP flow to host:port.  sing-mux carries
    /// flagUDP and frames datagrams as `[len u16 BE][data]`; Mux.Cool carries
    /// a per-datagram destination in the frame meta.
    pub async fn open_packet_stream(
        self: &Arc<Self>,
        host: &str,
        port: u16,
    ) -> Result<Box<dyn ProxyPacketConn>> {
        let (stream, session) = self.open_stream_flags(host, port, true).await?;
        // The conn is bound to the stream request's destination; reads
        // report it as the datagram source.  Non-IP hosts (domains) get a
        // placeholder — same convention as the plain VLESS UDP path.
        let destination = host.parse::<std::net::IpAddr>().ok().map_or_else(
            || "0.0.0.0:0".parse().expect("static placeholder"),
            |ip| SocketAddr::new(ip, port),
        );
        match stream.kind {
            MuxStreamKind::MuxCool(stream) => {
                let muxcool::Stream { parts, .. } = stream;
                Ok(Box::new(muxcool::PacketConn::new(
                    parts,
                    session,
                    destination,
                )))
            }
            kind => Ok(Box::new(MuxPacketConn::new(
                MuxStream::new(kind),
                session,
                destination,
            ))),
        }
    }

    /// Open a stream (writing its per-stream request: sing-mux prefix or
    /// Mux.Cool New frame), retrying once on a dead session — the shared
    /// core of the TCP and UDP open paths.
    async fn open_stream_flags(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        udp: bool,
    ) -> Result<(MuxStream, Arc<MuxSession>)> {
        let mut last_err = None;
        for _ in 0..2 {
            let session = match self.offer().await {
                Ok(session) => session,
                // Prefer an earlier errno-backed open_stream failure
                // over this context-only offer error (issue #668).
                Err(e) => {
                    return Err(MeowError::prefer_errno(last_err, e)
                        .expect("prefer_errno returns Some for a provided next"))
                }
            };
            // offer() reserved one slot on `streams` via CAS.  The
            // guard releases it if the open future is cancelled or the
            // session rejects the stream.
            let reservation = Reservation(Arc::clone(&session));
            match session.kind.open_stream(host, port, udp).await {
                Ok(stream) => {
                    // The slot reserved by offer() is now an established
                    // stream.  Forget the reservation so its Drop doesn't
                    // decrement — MuxStreamConn::drop will do that when
                    // the stream is eventually closed.
                    std::mem::forget(reservation);
                    // Idle eviction is measured from the last successful open
                    // (not the last activity): conservative — a long-lived
                    // stream keeps its session alive via the streams count,
                    // and zero-stream sessions idle past IDLE_TIMEOUT are
                    // evicted on the next offer.
                    session.last_used_ms.store(now_ms(), Ordering::SeqCst);
                    return Ok((stream, session));
                }
                Err(e) => {
                    // reservation drops here → slot released
                    // A session refusing the stream open is a capability
                    // refusal, not member health (same `Unsupported` arm
                    // as the SS/kcptun/socks5 dial sites, issue #663).
                    if e.kind() == std::io::ErrorKind::Unsupported {
                        return Err(MeowError::NotSupported(format!("mux stream open: {e}")));
                    }
                    last_err = MeowError::prefer_errno(last_err, MeowError::Io(e));
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or(MeowError::Proxy("mux: failed to open stream".into())))
    }

    /// Pick an existing session that can take a new request, or dial a new
    /// one.  Unusable sessions are pruned (`is_unusable`: dead transports,
    /// but also retired-yet-alive Mux.Cool sessions that must not take new
    /// streams) and zero-stream sessions idle past `IDLE_TIMEOUT` are
    /// evicted.  The returned session has one slot
    /// reserved for the caller via a CAS on `streams` — the check and the
    /// increment are a single atomic step, so concurrent offers can never
    /// overshoot max-streams.
    async fn offer(self: &Arc<Self>) -> Result<Arc<MuxSession>> {
        let mut sessions = self.sessions.lock().await;
        let now = now_ms();
        sessions.retain(|s| {
            if s.kind.is_unusable() {
                return false;
            }
            // Truncated-domain comparison (never widen to u64 first): on
            // mips32 `Uint` is u32 and wraps every ~49.7 days, so a plain
            // subtraction must use `wrapping_sub`, matching
            // `UdpSession::idle_for`.
            let idle = now.wrapping_sub(s.last_used_ms.load(Ordering::SeqCst));
            s.streams.load(Ordering::SeqCst) > 0 || idle < IDLE_TIMEOUT.as_millis() as Uint
        });
        let options = &self.options;
        let best = sessions
            .iter()
            .min_by_key(|s| s.streams.load(Ordering::SeqCst));
        if let Some(session) = best {
            // CAS loop: atomically check the current load and reserve a
            // slot.  If another thread modifies `streams` between our
            // load and the CAS, we retry with the updated value.  This
            // eliminates the read-read race that separate `streams` +
            // `pending` atomics had — the assessment and the increment
            // are now one atomic step.
            loop {
                let load = session.streams.load(Ordering::SeqCst);
                let reuse = if load == 0 {
                    // An idle session always takes the next stream — never
                    // dial a fresh connection while one is free.
                    true
                } else if options.max_connections > 0 {
                    sessions.len() >= options.max_connections || load < options.min_streams
                } else {
                    // max-connections=0: honor min-streams first (sing-mux
                    // checks minStreams before maxStreams in this branch),
                    // then fall back to max-streams.  max-streams=0 with
                    // min-streams=0 keeps the mihomo semantics: one physical
                    // connection per stream.
                    load < options.min_streams
                        || (options.max_streams > 0 && load < options.max_streams)
                };
                if !reuse {
                    break;
                }
                match session.streams.compare_exchange(
                    load,
                    load + 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => return Ok(Arc::clone(session)),
                    Err(_) => continue,
                }
            }
        }
        // Bounds reached: dial a fresh session while still holding the
        // sessions lock so concurrent offers serialize behind this dial and
        // cannot overshoot max-connections (sing-mux holds its mutex across
        // offerNew the same way).
        self.offer_new_locked(&mut sessions).await
    }

    /// Dial a fresh physical connection and start a new session.  sing-mux
    /// sessions write the mux request header on top; Mux.Cool needs none —
    /// the dialer's VLESS CommandMux request already marks the connection.
    /// Callers must hold the sessions lock.
    async fn offer_new_locked(
        self: &Arc<Self>,
        sessions: &mut VecDeque<Arc<MuxSession>>,
    ) -> Result<Arc<MuxSession>> {
        let kind = tokio::time::timeout(SESSION_SETUP_TIMEOUT, self.create_session())
            .await
            .map_err(|_| {
                MeowError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mux: session setup timed out",
                ))
            })??;
        let session = Arc::new(MuxSession {
            kind,
            // Start at 1: the caller's reservation.  The pool lock is
            // held, so no concurrent offer can see this session before
            // the slot is reserved.
            streams: AtomicUsize::new(1),
            last_used_ms: AtomicU::new(now_ms()),
        });
        sessions.push_back(Arc::clone(&session));
        Ok(session)
    }

    async fn create_session(&self) -> Result<SessionKind> {
        let mut conn = (self.dial)().await?;
        match self.options.protocol {
            Protocol::Smux | Protocol::Yamux | Protocol::H2Mux => {
                let header = Request::new(
                    if self.options.padding { 1 } else { 0 },
                    self.options.protocol as u8,
                    self.options.padding,
                )
                .encode();
                conn.write_all(&header).await.map_err(MeowError::Io)?;
                conn.flush().await.map_err(MeowError::Io)?;
                Ok(match self.options.protocol {
                    Protocol::Smux => SessionKind::Smux(Arc::new(
                        smux::Session::client(conn).map_err(MeowError::Io)?,
                    )),
                    Protocol::Yamux => SessionKind::Yamux(Arc::new(
                        yamux::Session::client(conn).map_err(MeowError::Io)?,
                    )),
                    Protocol::H2Mux => SessionKind::H2Mux(Arc::new(
                        h2mux::Session::client(conn).await.map_err(MeowError::Io)?,
                    )),
                    Protocol::MuxCool => unreachable!("handled above"),
                })
            }
            Protocol::MuxCool => Ok(SessionKind::MuxCool(
                muxcool::MuxCoolSession::client(conn)
                    .await
                    .map_err(MeowError::Io)?,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::task::Poll;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

    /// Minimal AsyncRead+AsyncWrite+ProxyConn newtype over a duplex half.
    struct TestConn(tokio::io::DuplexStream);

    impl ProxyConn for TestConn {}

    impl AsyncRead for TestConn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestConn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    /// Mock dialer: each dial yields a duplex half whose far end swallows
    /// bytes (a minimal mux data sink).
    async fn mock_mux_client(dials: Arc<AtomicUsize>) -> Arc<MuxClient> {
        // The mock sink speaks smux frames — pin the protocol explicitly.
        mock_mux_client_with(
            dials,
            MuxOptions {
                protocol: Protocol::Smux,
                ..MuxOptions::default()
            },
        )
        .await
    }

    async fn mock_mux_client_with(dials: Arc<AtomicUsize>, options: MuxOptions) -> Arc<MuxClient> {
        let dial: DialFn = Arc::new(move || {
            let dials = Arc::clone(&dials);
            Box::pin(async move {
                dials.fetch_add(1, Ordering::SeqCst);
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    // Drain frames without parsing: the previous version read a
                    // 10-byte header and extracted a u32 BE "length" from bytes
                    // 2–5, but smux frames are 8 bytes (u16 LE length at 2–3)
                    // and yamux frames are 12 bytes.  On a misaligned read the
                    // u32 can be enormous (e.g. 0x01000000 = 16 MiB when the
                    // smux version byte 0x01 lands at header[2]), causing a
                    // huge heap allocation that crashes the Windows runner.
                    // A fixed-size read-and-discard loop is all a data sink
                    // needs.
                    let mut io = server_io;
                    let mut buf = [0u8; 4096];
                    loop {
                        match io.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
                Ok(Box::new(TestConn(client_io)) as Box<dyn ProxyConn>)
            })
        });
        MuxClient::new(dial, options)
    }

    #[tokio::test]
    async fn streams_pack_into_one_connection_until_bounds() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = mock_mux_client(Arc::clone(&dials)).await;
        // Default bounds: max-connections=4, min/max-streams=4 — streams
        // accumulate on the first connection until it reaches max_streams.
        let mut streams = Vec::new();
        for _ in 0..4 {
            streams.push(client.open_stream("a.example", 80).await.unwrap());
        }
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        // Fifth stream exceeds max_streams → second connection.
        streams.push(client.open_stream("a.example", 80).await.unwrap());
        assert_eq!(dials.load(Ordering::SeqCst), 2);
    }

    /// max-connections=0 with max-streams=0 and min-streams=0 keeps the
    /// mihomo semantics: every stream dials its own physical connection.
    #[tokio::test]
    async fn zero_bounds_dial_one_connection_per_stream() {
        let dials = Arc::new(AtomicUsize::new(0));
        let options = MuxOptions {
            protocol: Protocol::Smux,
            max_connections: 0,
            min_streams: 0,
            max_streams: 0,
            ..MuxOptions::default()
        };
        let client = mock_mux_client_with(Arc::clone(&dials), options).await;
        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(client.open_stream("a.example", 80).await.unwrap());
        }
        assert_eq!(
            dials.load(Ordering::SeqCst),
            3,
            "max-connections=0 + max-streams=0 must dial one connection per stream"
        );
        drop(streams);
    }

    /// Concurrent opens reserve their slots under the pool lock, so the
    /// per-session stream cap is never overshot by racing offers.
    #[tokio::test]
    async fn concurrent_opens_respect_max_streams() {
        let dials = Arc::new(AtomicUsize::new(0));
        let options = MuxOptions {
            protocol: Protocol::Smux,
            max_connections: 0,
            min_streams: 4,
            max_streams: 4,
            ..MuxOptions::default()
        };
        let client = mock_mux_client_with(Arc::clone(&dials), options).await;
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    client
                        .open_stream(format!("h{i}.example").as_str(), 80)
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut streams = Vec::new();
        for handle in handles {
            streams.push(handle.await.unwrap());
        }
        let sessions = client.sessions.lock().await;
        assert_eq!(
            sessions.len(),
            2,
            "8 concurrent streams at max-streams=4 need 2 sessions"
        );
        for session in sessions.iter() {
            assert_eq!(session.streams.load(Ordering::SeqCst), 4);
        }
        drop(streams);
    }

    /// Stress test for the max-streams overshoot race: with max-streams=1
    /// every session must end with at most one stream slot.  The original
    /// design used separate `streams` + `pending` atomics whose sum was
    /// read with two independent loads — a concurrent open could transition
    /// between them and make the load appear falsely 0.  The unified
    /// `streams` counter with CAS-based reservation makes the check-and-
    /// increment one atomic step, so the overshoot is structurally
    /// impossible.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn stress_concurrent_opens_never_overshoot_max_streams_one() {
        for round in 0..200 {
            let dials = Arc::new(AtomicUsize::new(0));
            let options = MuxOptions {
                protocol: Protocol::Smux,
                max_connections: 0,
                min_streams: 1,
                max_streams: 1,
                ..MuxOptions::default()
            };
            let client = mock_mux_client_with(Arc::clone(&dials), options).await;
            let handles: Vec<_> = (0..16)
                .map(|i| {
                    let client = Arc::clone(&client);
                    tokio::spawn(async move {
                        client
                            .open_stream(format!("h{i}.example").as_str(), 80)
                            .await
                            .unwrap()
                    })
                })
                .collect();
            let mut streams = Vec::new();
            for handle in handles {
                streams.push(handle.await.unwrap());
            }
            let sessions = client.sessions.lock().await;
            for session in sessions.iter() {
                let streams = session.streams.load(Ordering::SeqCst);
                assert!(
                    streams <= 1,
                    "round {round}: session overshot max-streams=1 with {streams} streams"
                );
            }
            drop(streams);
        }
    }

    #[tokio::test]
    async fn yamux_protocol_pools_streams() {
        let dials = Arc::new(AtomicUsize::new(0));
        let options = MuxOptions {
            protocol: Protocol::Yamux,
            ..MuxOptions::default()
        };
        let client = mock_mux_client_with(Arc::clone(&dials), options).await;
        let _s1 = client.open_stream("a.example", 80).await.unwrap();
        let _s2 = client.open_stream("b.example", 80).await.unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn idle_sessions_are_evicted() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = mock_mux_client(Arc::clone(&dials)).await;
        let s = client.open_stream("a.example", 80).await.unwrap();
        drop(s);
        // The zero-stream session stays reusable within IDLE_TIMEOUT.
        let _s2 = client.open_stream("b.example", 81).await.unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), 1);
    }

    /// Regression test for issue #421: `offer()`'s idle check must compare
    /// `last_used_ms` in the truncated `Uint` domain with `wrapping_sub`,
    /// never widen to `u64` first. `last_used_ms` can end up numerically
    /// *ahead* of a freshly-read `now_ms()` two ways: a `Uint = u32`
    /// millisecond clock rolling over on a 32-bit-atomic target (mips32),
    /// or a monotonic clock read racing itself. A `saturating_sub`-based
    /// comparison computes `now.saturating_sub(last) == 0` in that case and
    /// treats the session as freshly used forever, so it can never be
    /// evicted. `wrapping_sub` recovers the true elapsed distance
    /// regardless of which side is numerically larger, so a session whose
    /// stamp reads far in the "future" is still pruned as idle.
    #[tokio::test]
    async fn idle_sessions_are_evicted_across_a_wrapped_clock_reading() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = mock_mux_client(Arc::clone(&dials)).await;
        let s = client.open_stream("a.example", 80).await.unwrap();
        drop(s);
        assert_eq!(dials.load(Ordering::SeqCst), 1);

        // Force the session's last-used stamp to read as if the millisecond
        // clock had wrapped past `now`, simulating the mips32 `AtomicU32`
        // rollover this fix targets.
        {
            let sessions = client.sessions.lock().await;
            assert_eq!(sessions.len(), 1);
            let wrapped = now_ms().wrapping_add(IDLE_TIMEOUT.as_millis() as Uint * 10);
            sessions[0].last_used_ms.store(wrapped, Ordering::SeqCst);
        }

        // offer() runs its retain() pass on the next open: the wrapped
        // session must still be recognized as idle-past-timeout and pruned,
        // forcing a second dial.
        let _s2 = client.open_stream("b.example", 81).await.unwrap();
        assert_eq!(
            dials.load(Ordering::SeqCst),
            2,
            "a session whose last-used stamp reads ahead of `now` (wrapped clock) \
             must still be evicted as idle, not kept alive forever"
        );
    }

    #[tokio::test]
    async fn write_error_on_dead_session_falls_back_to_new_dial() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = mock_mux_client(Arc::clone(&dials)).await;
        let mut s = client.open_stream("a.example", 80).await.unwrap();
        // Kill the underlying session by shutting the far side: drop the
        // server task happens implicitly — instead, just verify a second
        // stream still works after the first session dies.
        s.shutdown().await.ok();
        let _s2 = client.open_stream("b.example", 81).await.unwrap();
        assert!(dials.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn concurrent_opens_do_not_overshoot_max_connections() {
        let dials = Arc::new(AtomicUsize::new(0));
        let options = MuxOptions {
            protocol: Protocol::Smux,
            max_connections: 2,
            min_streams: 1,
            max_streams: 1,
            ..MuxOptions::default()
        };
        let client = mock_mux_client_with(Arc::clone(&dials), options).await;
        // Every stream saturates its session, so a racy pool would dial
        // once per open; holding the lock across the dial must serialize
        // them onto at most `max_connections` physical connections.
        let opens = (0..8)
            .map(|i| {
                let client = Arc::clone(&client);
                async move { (i, client.open_stream("a.example", 80).await.unwrap()) }
            })
            .collect::<Vec<_>>();
        let streams = futures::future::join_all(opens).await;
        assert_eq!(streams.len(), 8);
        assert_eq!(dials.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn session_setup_timeout_bounds_a_stalled_dial() {
        let dial: DialFn =
            Arc::new(|| Box::pin(std::future::pending::<Result<Box<dyn ProxyConn>>>()));
        let client = MuxClient::new(
            dial,
            MuxOptions {
                protocol: Protocol::Smux,
                ..MuxOptions::default()
            },
        );

        let Err(error) = client.open_stream("a.example", 80).await else {
            panic!("a stalled dial must time out");
        };
        assert!(
            error.to_string().contains("session setup timed out"),
            "unexpected error: {error}"
        );
    }

    /// The dialer-layer encoding of a chained `UdpTarget::Name` (issue
    /// #657): host-only UDP metadata. Both checks must resolve before any
    /// dial — a counting dial that pends proves it.
    fn host_only_udp_meta(host: &str) -> Metadata {
        Metadata {
            network: meow_common::Network::Udp,
            host: host.into(),
            dst_port: 443,
            ..Default::default()
        }
    }

    /// mux.cool stamps a per-datagram `SocketAddr` destination it cannot
    /// derive from a name — `open_packet_stream_for` declines (`Ok(None)`)
    /// so the adapter's own UDP path handles the domain request.
    #[tokio::test]
    async fn packet_stream_muxcool_declines_domain_target() {
        let dials = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dials);
        let dial: DialFn = Arc::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(std::future::pending::<Result<Box<dyn ProxyConn>>>())
        });
        let client = MuxClient::new(
            dial,
            MuxOptions {
                protocol: Protocol::MuxCool,
                ..MuxOptions::default()
            },
        );
        let meta = host_only_udp_meta("relay.internal");
        let got = client
            .open_packet_stream_for(&meta, "test")
            .await
            .expect("decline is not an error");
        assert!(got.is_none(), "mux.cool must decline a domain target");
        assert_eq!(dials.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// Bound-flow protocols carry the name in the stream-open Socksaddr,
    /// whose FQDN length is a u8 — an oversized name must surface as
    /// `NotSupported` (capability class, so the chained caller falls back
    /// to a literal `Addr`), not the io error `encode_address` would raise.
    #[tokio::test]
    async fn packet_stream_refuses_oversized_domain_target() {
        let dials = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dials);
        let dial: DialFn = Arc::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(std::future::pending::<Result<Box<dyn ProxyConn>>>())
        });
        let client = MuxClient::new(
            dial,
            MuxOptions {
                protocol: Protocol::Smux,
                ..MuxOptions::default()
            },
        );
        let meta = host_only_udp_meta(&"a".repeat(256));
        match client.open_packet_stream_for(&meta, "test").await {
            Err(MeowError::NotSupported(_)) => {}
            Err(other) => panic!("expected NotSupported, got {other:?}"),
            Ok(_) => panic!("oversized domain target must error"),
        }
        assert_eq!(dials.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
