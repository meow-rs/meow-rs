//! In-process `kcptun` SIP003 plugin client (issue #533) — wire-compatible
//! with mihomo's `transport/kcptun`: KCP-over-UDP carrying the kcp-go
//! crypt/FEC envelope, optional snappy stream compression, and smux v1
//! multiplexing, with a `conn`-sized session pool and `autoexpire`
//! rotation.
//!
//! Per-stream layout (upstream `NewClient` → `openStream`):
//!
//! ```text
//! SS stream ─ smux stream ─ [snappy CompStream] ─ KcpStream ─ UDP socket
//! ```
//!
//! The transport halves (`KcpStream`, crypt, FEC) live in
//! `meow_transport::kcptun`; this file adds option parsing, the session
//! pool, and the legacy UDP-over-TCP relay upstream forces for this plugin.
//!
//! upstream: mihomo `adapter/outbound/shadowsocks.go` +
//! `transport/kcptun` (kcp-go fork), xtaci/kcptun client flags.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use meow_common::error::{MeowError, Result};
use meow_common::ProxyPacketConn;
use meow_transport::kcptun::{comp_stream, KcpConfig, KcpStream};
use meow_transport::Stream;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::{debug, warn};

use crate::dialer::TcpDialer;
use crate::mux::smux;
use crate::plugin_util::{parse_bool, parse_bool_strict, sip003_opts};
use crate::uot::{encode_uot_addr, read_uot_addr};

/// Legacy UDP-over-TCP magic destination (sing-box `uot` v1 / mihomo
/// `UDPOverTCP`): an SS stream opened here is a datagram pipe — each packet
/// is `uot-AddrParser addr ‖ u16be len ‖ payload`.
pub(crate) const UOT_MAGIC_HOST: &str = "sp.udp-over-tcp.arpa";
pub(crate) const UOT_MAGIC_PORT: u16 = 0;

/// How many dead sessions `open_stream` evicts and redials before giving
/// up — bounds the retry loop when the UDP path is permanently broken.
const MAX_SESSION_ATTEMPTS: usize = 3;

/// xtaci/smux `DefaultConfig.KeepAliveTimeout` — kcptun overrides only the
/// interval (`keepalive`), so the silence window stays at the library
/// default rather than scaling with it.
const SMUX_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Parse one numeric option into its target type — `u64::from_str`-style
/// overflow errors keep e.g. `conn=99999` a config error instead of a
/// silent truncation.
fn num<T>(v: &str, what: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    v.parse::<T>()
        .map_err(|e| MeowError::Config(format!("kcptun: bad {what} '{v}': {e}")))
}

/// Parsed `plugin: kcptun` options — SIP003 `key=value;…` tokens carrying
/// the upstream `kcptun.Config` fields (kcptun CLI flags, lowercase with no
/// separators). Unknown keys warn and are ignored, matching the other
/// in-process plugins.
///
/// upstream keys: `key crypt mode conn autoexpire scavengettl mtu
/// ratelimit sndwnd rcvwnd datashard parityshard dscp nocomp acknodelay
/// nodelay interval resend nc sockbuf smuxver smuxbuf framesize streambuf
/// keepalive`.
pub(crate) fn parse_opts(opts: &str) -> Result<KcpConfig> {
    // `blank`, not `default`: upstream decodes options into a zeroed
    // `Config` and runs `FillDefaults` once. `default()` would already
    // have applied the `fast` preset, so `mode=manual` would keep
    // `interval=30/resend=2/nc=1` leftovers instead of upstream's
    // `50/0/0` zero-state fills.
    let mut cfg = KcpConfig::blank();
    for (k, v) in sip003_opts(opts) {
        match k.as_str() {
            "key" => cfg.key = v,
            "crypt" => cfg.crypt = v.to_ascii_lowercase(),
            "mode" => cfg.mode = v.to_ascii_lowercase(),
            "conn" => cfg.conn = num(&v, "conn")?,
            "autoexpire" => cfg.auto_expire = num(&v, "autoexpire")?,
            "scavengettl" => cfg.scavenge_ttl = num(&v, "scavengettl")?,
            "mtu" => cfg.mtu = num(&v, "mtu")?,
            "ratelimit" => cfg.rate_limit = num(&v, "ratelimit")?,
            "sndwnd" => cfg.snd_wnd = num(&v, "sndwnd")?,
            "rcvwnd" => cfg.rcv_wnd = num(&v, "rcvwnd")?,
            "datashard" => cfg.data_shard = num(&v, "datashard")?,
            "parityshard" => cfg.parity_shard = num(&v, "parityshard")?,
            "dscp" => {
                let dscp: u32 = num(&v, "dscp")?;
                if dscp > u8::MAX as u32 {
                    return Err(MeowError::Config(format!(
                        "kcptun: dscp {dscp} exceeds the TOS byte"
                    )));
                }
                cfg.dscp = dscp;
            }
            // A mistyped value silently toggles the snappy layer — the
            // wire either compresses or it does not, so this must error.
            "nocomp" => cfg.no_comp = parse_bool_strict(&v, "kcptun", "nocomp")?,
            "acknodelay" => cfg.ack_nodelay = parse_bool(&v, "kcptun", "acknodelay"),
            "nodelay" => cfg.nodelay = num(&v, "nodelay")?,
            "interval" => cfg.interval = num(&v, "interval")?,
            "resend" => cfg.resend = num(&v, "resend")?,
            "nc" => cfg.nc = num(&v, "nc")?,
            "sockbuf" => cfg.sock_buf = num(&v, "sockbuf")?,
            "smuxver" => cfg.smux_ver = num(&v, "smuxver")?,
            "smuxbuf" => cfg.smux_buf = num(&v, "smuxbuf")?,
            "framesize" => cfg.frame_size = num(&v, "framesize")?,
            "streambuf" => cfg.stream_buf = num(&v, "streambuf")?,
            "keepalive" => cfg.keep_alive = num(&v, "keepalive")?,
            other => warn!("kcptun: ignoring unknown option '{other}'"),
        }
    }
    // `FillDefaults` again so the mode preset clobbers explicit
    // nodelay/interval/resend/nc under any non-manual mode — the same
    // ordering upstream applies after decoding the JSON option map.
    cfg.fill_defaults();

    // Upstream accepts any `mode`/`crypt` string (`_ => {}` / default
    // AES-256-CFB); a typo silently changes the wire, so warn loudly.
    match cfg.mode.as_str() {
        "normal" | "fast" | "fast2" | "fast3" | "manual" => {}
        other => warn!("kcptun: unrecognized mode '{other}' — KCP knobs stay as configured"),
    }
    match cfg.crypt.as_str() {
        "aes" | "aes-256" | "aes-128" | "aes-192" | "aes-128-gcm" | "salsa20" | "none" | "null"
        | "xor" | "tea" | "xtea" | "blowfish" | "twofish" | "cast5" | "3des" | "sm4" => {}
        other => warn!("kcptun: unrecognized crypt '{other}' maps to aes-256 (upstream default)"),
    }

    if cfg.smux_ver != 1 {
        return Err(MeowError::Config(format!(
            "kcptun: smuxver={} is not supported (this build speaks smux v1 only)",
            cfg.smux_ver
        )));
    }
    if cfg.crypt == "sm4" {
        // Upstream supports sm4 via gmsm; no stable Rust crate exists, and
        // silently substituting AES would guarantee a dead session.
        return Err(MeowError::Config(
            "kcptun: crypt=sm4 is not supported by this build".into(),
        ));
    }
    // `saturating_add`: `datashard=usize::MAX` must trip the guard, not
    // wrap past it (a wrapped sum would also panic debug builds here).
    if cfg.data_shard.saturating_add(cfg.parity_shard) > 256 {
        warn!(
            "kcptun: datashard={} + parityshard={} exceeds the Reed-Solomon \
             256-shard limit; parity is disabled on encode and the decoder \
             falls back to pass-through",
            cfg.data_shard, cfg.parity_shard
        );
    }
    Ok(cfg)
}

/// A live pooled session: the smux session plus the `autoexpire` deadline
/// after which it stops receiving new streams (its existing streams run to
/// completion on the shared `Arc`, same as upstream).
struct Pooled {
    session: Arc<smux::Session>,
    expire_at: Option<Instant>,
}

/// The kcptun client — one per SS adapter, pooling KCP/smux sessions so
/// successive `dial_tcp` calls round-robin across `conn` UDP sessions
/// (upstream `Client.chaxconn` / `openStream`).
pub(crate) struct KcptunClient {
    cfg: KcpConfig,
    server: String,
    port: u16,
    dialer: Arc<dyn TcpDialer>,
    pool: Mutex<Vec<Pooled>>,
    /// Round-robin cursor over `pool`.
    rr: AtomicUsize,
}

impl KcptunClient {
    pub(crate) fn new(cfg: KcpConfig, server: &str, port: u16, dialer: Arc<dyn TcpDialer>) -> Self {
        Self {
            cfg,
            server: server.to_string(),
            port,
            dialer,
            pool: Mutex::new(Vec::new()),
            rr: AtomicUsize::new(0),
        }
    }

    /// Open a stream to the SS server: pick (or dial) a pooled session,
    /// then open a smux stream on it. Dead sessions are evicted and
    /// redialed up to [`MAX_SESSION_ATTEMPTS`] times; a live session's
    /// stream error is returned as-is.
    ///
    /// Equivalent to upstream `openStream`, except sessions are dialed
    /// lazily on first use rather than all `conn` up front.
    pub(crate) async fn open_stream(&self) -> Result<Box<dyn Stream>> {
        for _ in 0..MAX_SESSION_ATTEMPTS {
            let session = self.pick().await?;
            match session.open_stream().await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(e) if session.is_dead() => {
                    self.evict(&session);
                    debug!("kcptun: pooled session died ({e}); redialing");
                }
                Err(e) => {
                    return Err(MeowError::Proxy(format!("kcptun: smux open_stream: {e}")));
                }
            }
        }
        Err(MeowError::Proxy(
            "kcptun: pooled sessions keep dying; giving up".into(),
        ))
    }

    /// Drop `session` if it is still pooled (it may already be gone —
    /// `pick`'s retain pass purges dead entries too).
    fn evict(&self, session: &Arc<smux::Session>) {
        self.pool
            .lock()
            .retain(|p| !Arc::ptr_eq(&p.session, session));
    }

    /// Round-robin over live, unexpired sessions; dials a fresh one while
    /// the pool is under `conn`. The lock never spans an `.await`: eviction
    /// and the pick happen under it, the dial after release, and re-entry
    /// re-validates before pushing (a concurrent dial may have filled the
    /// pool meanwhile — the extra session is then used unpooled rather than
    /// exceeding `conn`).
    async fn pick(&self) -> Result<Arc<smux::Session>> {
        {
            let mut pool = self.pool.lock();
            pool.retain(Self::usable);
            // `conn` is clamped ≥1 by `fill_defaults`, but a hand-built
            // `KcpConfig::blank()` can still carry 0 — `.max(1)` keeps the
            // empty-pool modulo unreachable.
            if pool.len() >= (self.cfg.conn as usize).max(1) {
                let i = self.rr.fetch_add(1, Ordering::Relaxed) % pool.len();
                return Ok(Arc::clone(&pool[i].session));
            }
        }

        let session = self.dial().await?;
        let expire_at = (self.cfg.auto_expire > 0)
            .then(|| {
                // A deadline beyond the clock's range simply never expires.
                Instant::now().checked_add(Duration::from_secs(self.cfg.auto_expire as u64))
            })
            .flatten();
        let mut pool = self.pool.lock();
        pool.retain(Self::usable);
        if pool.len() < self.cfg.conn as usize {
            pool.push(Pooled {
                session: Arc::clone(&session),
                expire_at,
            });
        }
        Ok(session)
    }

    /// Dead, or past its `autoexpire` deadline (upstream `x_sess.expire`).
    /// `scavengettl`'s client-side linger (keeping a closed session around
    /// to absorb late datagrams) is a no-op here: a dead smux session is
    /// already torn down, and its streams hold their own `Arc` while alive.
    fn usable(p: &Pooled) -> bool {
        !p.session.is_dead() && p.expire_at.is_none_or(|t| Instant::now() < t)
    }

    /// `kcp.DialWithOptions` + `newSmuxSession` upstream: resolve the
    /// server, open the UDP endpoint through the dialer (raw socket for
    /// direct, front-proxy UDP relay under `dialer-proxy` — never a leak),
    /// wrap the KCP stream in snappy unless `nocomp`, start the smux
    /// session.
    async fn dial(&self) -> Result<Arc<smux::Session>> {
        let candidates = self.resolve().await?;
        let mut last_err = None;
        for remote in candidates {
            let socket = match self.dialer.dial_udp_endpoint(remote).await {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(format!("kcptun: udp endpoint for {remote}: {e}"));
                    continue;
                }
            };
            // A session-construction failure (bad crypt name, impossible
            // MTU) is config-level and will fail identically for the other
            // addresses — but endpoint-specific ones (socket errors) may
            // not, so try the rest of the resolution list anyway.
            match self.start_session(socket) {
                Ok(session) => return Ok(session),
                Err(e) => {
                    last_err = Some(format!("kcptun: session via {remote}: {e}"));
                }
            }
        }
        Err(MeowError::Proxy(
            last_err.unwrap_or_else(|| "kcptun: no server address".into()),
        ))
    }

    async fn resolve(&self) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = self.server.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, self.port)]);
        }
        meow_common::resolve_host_all(&self.server, self.port)
            .await
            .map_err(|e| {
                MeowError::Proxy(format!(
                    "kcptun: resolve {}:{}: {e}",
                    self.server, self.port
                ))
            })
    }

    /// KCP stream → optional snappy → smux session with the configured
    /// per-stream buffer, frame size, session receive window and keepalive
    /// (upstream `smux.DefaultConfig` + kcptun's overrides).
    fn start_session(
        &self,
        socket: Box<dyn meow_transport::kcptun::SocketIo>,
    ) -> Result<Arc<smux::Session>> {
        let conv = rand::random::<u32>();
        let kcp = KcpStream::connect(socket, conv, &self.cfg)
            .map_err(|e| MeowError::Proxy(format!("kcptun: kcp connect: {e}")))?;
        let io: Box<dyn Stream> = if self.cfg.no_comp {
            Box::new(kcp)
        } else {
            Box::new(comp_stream(kcp))
        };
        smux::Session::client_kcptun(
            io,
            self.cfg.stream_buf as usize,
            Duration::from_secs(self.cfg.keep_alive as u64),
            // kcptun overrides only `KeepAliveInterval`; `KeepAliveTimeout`
            // stays at xtaci/smux's 30s default.
            SMUX_KEEPALIVE_TIMEOUT,
            self.cfg.frame_size as usize,
            self.cfg.smux_buf as usize,
        )
        .map(Arc::new)
        .map_err(|e| MeowError::Proxy(format!("kcptun: smux session: {e}")))
    }
}

/// A `ProxyPacketConn` speaking legacy UDP-over-TCP framing over one SS
/// stream (upstream `uot.NewLazyConn` against `sp.udp-over-tcp.arpa:0`).
/// Datagram layout per packet, both directions:
///
/// ```text
/// | ATYP | Address | Port  | Length | Payload |
/// | u8   | var     | u16be | u16be  | var     |   ← uot.AddrParser bytes
/// ```
///
/// Split halves behind mutexes because `ProxyPacketConn` takes `&self`:
/// a blocked `read_packet` must never hold up `write_packet`.
pub(crate) struct UotPacketConn {
    reader: tokio::sync::Mutex<ReadHalf<Box<dyn Stream>>>,
    writer: tokio::sync::Mutex<WriteHalf<Box<dyn Stream>>>,
    /// Set once any frame op is torn by cancellation — after a partial
    /// read or write the stream's framing is unrecoverable, so every
    /// later packet op must fail fast rather than misdeliver (issue #514).
    poisoned: std::sync::atomic::AtomicBool,
}

impl UotPacketConn {
    pub(crate) fn new(stream: Box<dyn Stream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: tokio::sync::Mutex::new(reader),
            writer: tokio::sync::Mutex::new(writer),
            poisoned: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl ProxyPacketConn for UotPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        crate::check_not_desynced(&self.poisoned)?;
        let mut reader = self.reader.lock().await;
        // Re-check post-lock: a read parked behind a cancelled mid-frame
        // read must not consume the torn remainder.
        crate::check_not_desynced(&self.poisoned)?;
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);
        let addr = read_uot_addr(&mut *reader).await?;
        let mut lenb = [0u8; 2];
        reader.read_exact(&mut lenb).await.map_err(MeowError::Io)?;
        let len = u16::from_be_bytes(lenb) as usize;
        if len <= buf.len() {
            reader
                .read_exact(&mut buf[..len])
                .await
                .map_err(MeowError::Io)?;
            guard.complete = true;
            return Ok((len, addr));
        }
        // Datagram truncation semantics: read the whole frame (bounded by
        // the u16 length) so the stream stays aligned, serve what fits,
        // drop the rest.
        let mut pkt = vec![0u8; len];
        reader.read_exact(&mut pkt).await.map_err(MeowError::Io)?;
        buf.copy_from_slice(&pkt[..buf.len()]);
        guard.complete = true;
        Ok((buf.len(), addr))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        crate::check_not_desynced(&self.poisoned)?;
        if buf.len() > u16::MAX as usize {
            return Err(MeowError::Proxy(format!(
                "kcptun uot: datagram too large ({})",
                buf.len()
            )));
        }
        let mut frame = Vec::with_capacity(buf.len() + 24);
        encode_uot_addr(&mut frame, addr);
        frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        frame.extend_from_slice(buf);
        let mut writer = self.writer.lock().await;
        crate::check_not_desynced(&self.poisoned)?;
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);
        writer.write_all(&frame).await.map_err(MeowError::Io)?;
        // `write_all` fully buffers the frame through smux's writer
        // channel; a cancelled flush cannot tear the framing.
        guard.complete = true;
        writer.flush().await.map_err(MeowError::Io)?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        // Tunneled — no meaningful local UDP address exists.
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        // UoT framing has no close handshake — upstream
        // `uot.LazyConn.Close` likewise just releases the stream.
        // Dropping the halves closes the smux stream, which queues a FIN
        // and releases the session's stream entry.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_upstream() {
        let cfg = parse_opts("").unwrap();
        assert_eq!(cfg.key, "it's a secrect");
        assert_eq!(cfg.crypt, "aes");
        assert_eq!(cfg.mode, "fast");
        assert_eq!(cfg.conn, 1);
        assert_eq!(cfg.scavenge_ttl, 600);
        assert_eq!(cfg.mtu, 1350);
        assert_eq!(cfg.snd_wnd, 128);
        assert_eq!(cfg.rcv_wnd, 512);
        assert_eq!(cfg.data_shard, 10);
        assert_eq!(cfg.parity_shard, 3);
        assert_eq!(cfg.sock_buf, 4194304);
        assert_eq!(cfg.smux_ver, 1);
        assert_eq!(cfg.smux_buf, 4194304);
        assert_eq!(cfg.frame_size, 8192);
        assert_eq!(cfg.stream_buf, 2097152);
        assert_eq!(cfg.keep_alive, 10);
        // fast preset
        assert_eq!(
            (cfg.nodelay, cfg.interval, cfg.resend, cfg.nc),
            (0, 30, 2, 1)
        );
    }

    #[test]
    fn manual_mode_keeps_knobs() {
        let cfg = parse_opts("mode=manual;nodelay=1;interval=20;resend=5;nc=0").unwrap();
        assert_eq!(
            (cfg.nodelay, cfg.interval, cfg.resend, cfg.nc),
            (1, 20, 5, 0)
        );
        // interval is clamped into upstream's [10, 5000] even under manual
        let cfg = parse_opts("mode=manual;interval=7").unwrap();
        assert_eq!(cfg.interval, 10);
        let cfg = parse_opts("mode=manual;interval=9999").unwrap();
        assert_eq!(cfg.interval, 5000);
        // preset modes clobber them, matching upstream FillDefaults order
        let cfg = parse_opts("nodelay=1;interval=7;mode=fast3").unwrap();
        assert_eq!(
            (cfg.nodelay, cfg.interval, cfg.resend, cfg.nc),
            (1, 10, 2, 1)
        );
        // manual with unset knobs inherits the zero-state fills
        // (`interval`→50, `resend`/`nc` stay 0), not the `fast` preset —
        // upstream fills a zeroed Config once.
        let cfg = parse_opts("mode=manual").unwrap();
        assert_eq!(
            (cfg.nodelay, cfg.interval, cfg.resend, cfg.nc),
            (0, 50, 0, 0)
        );
    }

    #[test]
    fn rejects_bad_numbers_and_smuxver() {
        assert!(parse_opts("conn=notanumber").is_err());
        assert!(parse_opts("conn=99999").is_err()); // u16 overflow
        assert!(parse_opts("smuxver=2").is_err());
        assert!(parse_opts("dscp=256").is_err());
        // `sm4` must fail loudly — silently substituting AES guarantees a
        // dead session against a real sm4 peer.
        assert!(parse_opts("crypt=sm4").is_err());
        // Reed-Solomon shard counts that would overflow a usize add must
        // still parse (the guard is a saturating warn, not a panic).
        assert!(parse_opts(&format!("datashard={};parityshard=1", usize::MAX)).is_ok());
    }

    #[test]
    fn bools_and_unknowns() {
        let cfg = parse_opts("nocomp=true;bogus=1").unwrap();
        assert!(cfg.no_comp);
        let cfg = parse_opts("nocomp=yes").unwrap();
        assert!(cfg.no_comp);
    }

    // Session-pool tests — a scripted `SocketIo` is enough to keep a smux
    // session alive (or kill it) without any wire traffic.

    use meow_transport::kcptun::SocketIo;
    use std::io;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    /// Swallows outbound datagrams, never receives — a live-but-silent
    /// endpoint the smux session's reader parks on.
    struct SilentSocket;
    impl SocketIo for SilentSocket {
        fn poll_send(&mut self, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_recv(&mut self, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// `poll_recv` errors immediately — the smux reader exits on the first
    /// poll and the session is marked dead.
    struct FailSocket;
    impl SocketIo for FailSocket {
        fn poll_send(&mut self, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_recv(&mut self, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("fail")))
        }
    }

    struct SilentDialer;
    #[async_trait]
    impl TcpDialer for SilentDialer {
        async fn dial(&self, _: &str, _: u16, _: bool) -> io::Result<Box<dyn Stream>> {
            Err(io::Error::other("unused in pool tests"))
        }
        async fn dial_udp_endpoint(&self, _: SocketAddr) -> io::Result<Box<dyn SocketIo>> {
            Ok(Box::new(SilentSocket))
        }
    }

    /// Fails once then serves `SilentSocket`s — used to observe dead-session
    /// eviction and redial.
    struct FailOnceDialer(AtomicUsize);
    #[async_trait]
    impl TcpDialer for FailOnceDialer {
        async fn dial(&self, _: &str, _: u16, _: bool) -> io::Result<Box<dyn Stream>> {
            Err(io::Error::other("unused in pool tests"))
        }
        async fn dial_udp_endpoint(&self, _: SocketAddr) -> io::Result<Box<dyn SocketIo>> {
            if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(Box::new(FailSocket))
            } else {
                Ok(Box::new(SilentSocket))
            }
        }
    }

    fn client(opts: &str, dialer: Arc<dyn TcpDialer>) -> KcptunClient {
        // A literal IP skips DNS entirely; the fake dialer never touches it.
        KcptunClient::new(parse_opts(opts).unwrap(), "127.0.0.1", 8388, dialer)
    }

    #[tokio::test]
    async fn pool_grows_to_conn_then_round_robins() {
        let c = client("conn=2;nocomp=true", Arc::new(SilentDialer));
        let a = c.pick().await.unwrap();
        let b = c.pick().await.unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        // Pool is full — subsequent picks rotate over the pooled sessions.
        assert!(Arc::ptr_eq(&c.pick().await.unwrap(), &a));
        assert!(Arc::ptr_eq(&c.pick().await.unwrap(), &b));
    }

    #[tokio::test]
    async fn dead_session_is_evicted_and_redialed() {
        let c = client(
            "conn=1;nocomp=true",
            Arc::new(FailOnceDialer(AtomicUsize::new(0))),
        );
        let dead = c.pick().await.unwrap();
        // Let the smux reader task observe the socket error and mark dead —
        // poll for it instead of racing a fixed sleep on a loaded runner.
        for _ in 0..50 {
            if dead.is_dead() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(dead.is_dead());
        let live = c.pick().await.unwrap();
        assert!(!Arc::ptr_eq(&dead, &live));
        assert!(!live.is_dead());
        assert_eq!(c.pool.lock().len(), 1);
    }

    #[tokio::test]
    async fn autoexpire_rotates_session() {
        let c = client("conn=1;nocomp=true;autoexpire=1", Arc::new(SilentDialer));
        let first = c.pick().await.unwrap();
        assert!(Arc::ptr_eq(&c.pick().await.unwrap(), &first));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let second = c.pick().await.unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
    }
}
