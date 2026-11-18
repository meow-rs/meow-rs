//! AnyTLS outbound (issue #75).
//!
//! Thin wrapper over the `anytls-rs` crate's `Client`. The protocol itself
//! — TLS handshake, password auth, session multiplexing, padding scheme —
//! lives upstream; this file only translates between meow-rs's `ProxyAdapter`
//! trait and `anytls_rs`'s `Client::create_proxy_stream` / `Session` API,
//! plus the sing-box udp-over-tcp v2 framing that carries UDP (see the `uot`
//! section below).
//!
//! `tests/anytls_integration.rs` covers TCP and UDP end to end against an
//! in-process `anytls_rs::server::Server`; no external anytls server needed.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anytls_rs::client::Client as AnytlsClient;
use anytls_rs::client::UDP_OVER_TCP_MAGIC_ADDR;
use anytls_rs::padding::PaddingFactory;
use anytls_rs::session::{Session, Stream as AnytlsStream};
use anytls_rs::{AsyncStream, SyncStream, TlsConnect, TlsConnectFuture};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::Transport as _;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
    Result, WriteBytes,
};

use crate::certificate_pin::parse_cert_pin;
use crate::uot::{encode_uot_addr, encode_uot_addr_domain, read_uot_addr};

/// Optional TLS settings using mihomo's AnyTLS field names and defaults.
#[derive(Debug, Clone, Default)]
pub struct AnytlsTlsOptions {
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub fingerprint: Option<String>,
    pub name_cert_verify: Option<String>,
    pub client_fingerprint: Option<String>,
    pub alpn: Vec<String>,
}

impl AnytlsTlsOptions {
    fn tls_config(&self, name: &str, server: &str) -> std::result::Result<TlsConfig, String> {
        if self.alpn.iter().any(|s| s.is_empty() || s.len() > 255) {
            return Err(format!(
                "anytls[{name}]: alpn entries must contain 1 to 255 bytes"
            ));
        }
        let effective_sni = self
            .sni
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(server);
        let server_name =
            normalize_server_name(effective_sni).map_err(|e| format!("anytls[{name}]: {e}"))?;
        let verify_name = self
            .name_cert_verify
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|value| normalize_name(value, "name-cert-verify"))
            .transpose()
            .map_err(|e| format!("anytls[{name}]: {e}"))?;
        let cert_pin = self
            .fingerprint
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|value| parse_cert_pin(value, &format!("anytls[{name}]")))
            .transpose()
            .map_err(|e| e.to_string())?;
        // Profile names are matched case-insensitively (upstream lowercases
        // before its lookup); `Chrome` must not silently fall back to the
        // default ClientHello.
        let fingerprint = self
            .client_fingerprint
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty() && s != "none");
        // Mihomo's explicit verification name overrides skip-cert-verify;
        // a configured pin owns verification independently of that flag.
        let skip_cert_verify = self.skip_cert_verify && verify_name.is_none() && cert_pin.is_none();
        if self.skip_cert_verify && !skip_cert_verify {
            // Say so once at load rather than let a user believe
            // verification is off when it is not (hysteria2 parity).
            tracing::warn!(
                "anytls[{name}]: skip-cert-verify is ignored because fingerprint \
                 or name-cert-verify is set; the server certificate is verified"
            );
        }
        Ok(TlsConfig {
            verify_name,
            cert_pin,
            fingerprint,
            alpn: self.alpn.clone(),
            skip_cert_verify,
            ..TlsConfig::new(server_name)
        })
    }
}

/// AnyTLS outbound adapter.
pub struct AnytlsAdapter {
    name: String,
    addr: String,
    health: ProxyHealth,
    client: AnytlsClient,
    /// The adapter's own TLS layer, `Arc`-shared with the `TlsConnect` hook
    /// given to the anytls client. `connect_over` runs it directly on the
    /// relay-supplied stream because `TlsConnect::connect` is typed on
    /// `TcpStream` while a relay stream is a generic `meow_transport::Stream`;
    /// an injected `dialer-proxy` reaches the same layer through
    /// `TlsConnect::connect_stream` inside the client.
    tls_layer: Arc<TlsLayer>,
    udp: bool,
}

impl AnytlsAdapter {
    /// Build a new adapter.
    ///
    /// `server`/`port` is the AnyTLS server's TLS endpoint. `password` is the
    /// shared secret. `sni` is the SNI sent during the TLS handshake; pass
    /// `None` to default to `server`. When `skip_cert_verify` is set, the TLS
    /// stack accepts any certificate — useful for self-signed dev servers and
    /// matches the `skip-cert-verify` semantics of the trojan/vless adapters.
    /// `udp` mirrors mihomo's `udp:` option (`AnyTLSOption.UDP`, default
    /// `false`): when unset, [`ProxyAdapter::support_udp`] reports `false` and
    /// the tunnel routes UDP elsewhere.
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        skip_cert_verify: bool,
        udp: bool,
    ) -> std::result::Result<Self, String> {
        let options = AnytlsTlsOptions {
            sni: sni.map(str::to_string),
            skip_cert_verify,
            ..Default::default()
        };
        Self::new_with_tls(name, server, port, password, &options, udp)
    }

    /// Build an adapter with certificate verification and ClientHello options.
    pub fn new_with_tls(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        options: &AnytlsTlsOptions,
        udp: bool,
    ) -> std::result::Result<Self, String> {
        let tls_config = options.tls_config(name, server)?;
        Self::build(name, server, port, password, &tls_config, udp)
    }

    fn build(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        tls_config: &TlsConfig,
        udp: bool,
    ) -> std::result::Result<Self, String> {
        // Bridge meow_common's outbound-socket hooks (resolver-aware TCP
        // dialer + Android `SocketProtector`) into anytls-rs's separate
        // registries exactly once — see `install_anytls_bridges`.
        install_anytls_bridges();

        let server_addr = format!("{server}:{port}");

        // Same BoringSSL TlsLayer every other TLS outbound uses; the
        // SSL_CTX is shared across proxies with the same shaping key.
        // `Arc`-shared with `MeowTlsConnect` so `connect_over` can run the
        // identical handshake on a relay-supplied stream.
        let tls_layer = Arc::new(
            TlsLayer::new(tls_config).map_err(|e| format!("anytls[{name}]: tls config: {e}"))?,
        );
        let tls: Arc<dyn TlsConnect> = Arc::new(MeowTlsConnect {
            layer: Arc::clone(&tls_layer),
        });

        let padding = PaddingFactory::default();

        let client = AnytlsClient::new(password, server_addr.clone(), tls, padding);

        Ok(Self {
            name: name.to_string(),
            addr: server_addr,
            health: ProxyHealth::new(),
            client,
            tls_layer,
            udp,
        })
    }

    /// Inject the `dialer-proxy` dialer every AnyTLS session's transport
    /// is established through (Batch-2 parity with WireGuard/hysteria2).
    ///
    /// The config layer attaches this only for a real chain
    /// (`dialer.is_proxy()`); the no-op `DirectDialer` keeps the client's
    /// own `connect_tcp_host` path. The dialer returns the raw chained
    /// stream — the vendored client then runs its usual TLS handshake
    /// (`connect_stream`), auth and session setup on top, and the session
    /// pools like a direct one (the client holds one transport class, so
    /// pooled sessions can never be mixed across paths). `udp: true`
    /// UoT rides the same chained session, so injected UDP works — it
    /// only needs the front to carry TCP.
    ///
    /// `connect_over` is unaffected: it bypasses both the dialer and the
    /// pool, staying the unpooled single-purpose path it always was.
    pub fn with_dialer(mut self, dialer: Arc<dyn crate::dialer::TcpDialer>) -> Self {
        self.client
            .set_transport_dialer(Arc::new(ChainedTransportDialer(dialer)));
        self
    }
}

#[async_trait]
impl ProxyAdapter for AnytlsAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Anytls
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let host = anytls_tcp_destination(metadata)?;
        let port = metadata.dst_port;
        let (stream, session) = self
            .client
            .create_proxy_stream((host, port))
            .await
            .map_err(|e| anytls_err("dial", e))?;
        Ok(Box::new(AnytlsConn::new(stream, session)))
    }

    /// Run TLS + the AnyTLS session handshake over an existing stream
    /// (relay chain).
    ///
    /// The vendored client's pool path dials its own transport, so the
    /// adapter runs its shared `TlsLayer` itself and hands the handshaken
    /// stream to `create_proxy_stream_on_tls`. The session that comes
    /// back is **not** pooled — pooling it would let a later `dial_tcp`
    /// silently reuse the relay channel — so the returned conn owns it
    /// and closes it on drop. The injected `dialer-proxy` path is
    /// different: there the *client* dials the chain itself, so those
    /// sessions pool normally.
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        let host = anytls_tcp_destination(metadata)?;
        let port = metadata.dst_port;
        let tls_stream = self
            .tls_layer
            .connect(Box::new(stream))
            .await
            .map_err(|e| match e {
                meow_transport::TransportError::Io(e) => MeowError::Io(e),
                other => MeowError::Proxy(format!("anytls relay tls: {other}")),
            })?;
        let (stream, session) = self
            .client
            .create_proxy_stream_on_tls(tls_stream, (host, port))
            .await
            .map_err(|e| anytls_err("relay dial", e))?;
        Ok(Box::new(AnytlsConn::new_owned(stream, session)))
    }

    /// Open a udp-over-tcp v2 relay stream (issue #75 follow-up).
    ///
    /// Mirrors mihomo `adapter/outbound/anytls.go: ListenPacketContext`: a
    /// plain proxy stream to the magic destination, then sing-box's `uot`
    /// framing on top of it. The uot request rides the open's first flush:
    /// sing-box's inbound reads it before reporting handshake success
    /// (issue #535), and since the open no longer waits for SYNACK that
    /// ordering can no longer deadlock — the eager write is a latency
    /// measure over upstream's lazy `uot.NewLazyConn` shape.
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.udp {
            return Err(MeowError::NotSupported(
                "anytls: UDP is disabled for this proxy (set `udp: true`)".to_string(),
            ));
        }
        // This adapter as a *front*: a host-only UDP destination — the
        // dialer layer's encoding of a chained `UdpTarget::Name`
        // (issue #657) — stamps each datagram's uot address with the domain
        // so the server resolves it with its own view.
        let write_target = match metadata.domain_udp_target() {
            Some((host, port)) if host.len() <= u8::MAX as usize => Some((host.clone(), port)),
            Some(_) => {
                return Err(MeowError::NotSupported(
                    "anytls: domain UDP target exceeds uot length prefix".into(),
                ));
            }
            None => None,
        };
        let (stream, session) = self
            .client
            .create_proxy_stream_with_payload(
                (UDP_OVER_TCP_MAGIC_ADDR.to_string(), 0),
                Some(Bytes::from(encode_uot_request(metadata))),
            )
            .await
            .map_err(|e| anytls_err("udp dial", e))?;
        Ok(Box::new(AnytlsPacketConn::new(
            stream,
            session,
            write_target,
        )))
    }

    /// Issue #695: close every pooled AnyTLS session so the next dial opens a
    /// fresh, interface-bound connection (see `SessionPool::reset`). The
    /// unpooled `connect_over` sessions belong to their relay stream.
    fn reset_sessions(&self) {
        self.client.reset_sessions();
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }

    fn client_fingerprint(&self) -> Option<&str> {
        self.tls_layer.fingerprint()
    }
}

/// An `AnyTlsError::Io` carries the real io error — `raw_os_error` survives
/// for `DialFailureTracker`'s local-resource classification (issue #668);
/// stringifying it would dead-mark the member for EMFILE & friends.
fn anytls_err(context: &str, e: anytls_rs::AnyTlsError) -> MeowError {
    match e {
        anytls_rs::AnyTlsError::Io(e) => MeowError::Io(e),
        other => MeowError::Proxy(format!("anytls {context}: {other}")),
    }
}

/// Select the actual TCP dial target without substituting a sniffed rule host.
///
/// IP-only inbounds leave `host` empty, so fall back to `dst_ip`.  A sniffed
/// hostname is useful for rule matching but must not silently replace the
/// address the client actually requested.
fn anytls_tcp_destination(metadata: &Metadata) -> Result<String> {
    if !metadata.host.is_empty() {
        return Ok(metadata.host.to_string());
    }
    metadata
        .dst_ip
        .map(|ip| ip.to_string())
        .ok_or_else(|| MeowError::Proxy("anytls dial: missing destination host and IP".to_string()))
}

/// Bridge `(Arc<Stream>, Arc<Session>)` into a `ProxyConn`-shaped value.
///
/// The upstream `Stream` impls `AsyncRead`/`AsyncWrite` on `Pin<&mut Self>`,
/// but `create_proxy_stream` only hands us an `Arc<Stream>` — we can never
/// obtain `&mut Stream`. So we re-implement the traits against its public
/// reader and cancellation-safe writer-channel APIs.
// The pending read future is `Send` but not `Sync`; `ProxyConn` requires
// `Sync`, so it is wrapped in `parking_lot::Mutex`. Its output is the
// scratch Vec (returned for reuse) plus the read result.
type PendingRead = Pin<Box<dyn std::future::Future<Output = (Vec<u8>, io::Result<usize>)> + Send>>;

struct AnytlsConn {
    stream: Arc<AnytlsStream>,
    // Keep the owning session alive even if the adapter is dropped while
    // this connection is still in use.
    session: Arc<Session>,
    /// `true` when the session was built for this conn alone (relay
    /// `connect_over`) and is not shared through the client's pool — it is
    /// closed when the conn drops rather than living until the transport
    /// dies (the heartbeat only reaps sessions whose peer stops answering).
    session_owned: bool,
    pending_read: Mutex<Option<PendingRead>>,
    /// Buffer the contended-path read future fills; it is handed back on
    /// completion so the next pending read reuses the allocation.
    read_scratch: Arc<Mutex<Vec<u8>>>,
}

impl AnytlsConn {
    fn new(stream: Arc<AnytlsStream>, session: Arc<Session>) -> Self {
        Self {
            stream,
            session,
            session_owned: false,
            pending_read: Mutex::new(None),
            read_scratch: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Construct a conn that owns its session outright (relay `connect_over`
    /// path — the session is deliberately unpooled).
    fn new_owned(stream: Arc<AnytlsStream>, session: Arc<Session>) -> Self {
        Self {
            stream,
            session,
            session_owned: true,
            pending_read: Mutex::new(None),
            read_scratch: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Best-effort FIN for just this stream, idempotent across `poll_shutdown`
    /// and `Drop`. Emits a `Fin` control frame so the server releases the
    /// proxied target connection and evicts the per-stream map entry (issue
    /// #201 item 4). The session is pooled and multiplexes other streams, so
    /// this must never close the session itself.
    fn fin_stream(&self) {
        // `Stream::close` uses the same FIFO as `send_data`, so all accepted
        // data is written before FIN. It is synchronous and idempotent.
        self.stream.close();
    }
}

impl AsyncRead for AnytlsConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut guard = self.pending_read.lock();
        if guard.is_none() {
            // Fast path: the stream's reader mutex is uncontended (a conn
            // is its only reader in practice) — poll the StreamReader
            // straight into the caller's ReadBuf: no scratch alloc, no
            // boxed future, no copy. The channel waker the reader
            // registers persists inside the receiver, so an unlock never
            // loses the wakeup.
            if let Ok(mut reader) = self.stream.reader().try_lock() {
                return Pin::new(&mut *reader).poll_read(cx, buf);
            }

            // Contended (another handle reads this stream): park a
            // lock+read future, filling the persistent scratch instead of
            // a per-read `vec![0; n]`.
            let reader = Arc::clone(self.stream.reader());
            let scratch = Arc::clone(&self.read_scratch);
            let cap = buf.remaining();
            let fut = async move {
                let mut g = reader.lock().await;
                let mut tmp = std::mem::take(&mut *scratch.lock());
                tmp.clear();
                tmp.resize(cap, 0);
                let result = g.read(&mut tmp).await;
                (tmp, result)
            };
            *guard = Some(Box::pin(fut));
        }
        let fut = guard.as_mut().expect("just set");
        let (mut tmp, result) = std::task::ready!(fut.as_mut().poll(cx));
        *guard = None;
        let n = match result {
            Ok(n) => n.min(tmp.len()),
            Err(e) => {
                *self.read_scratch.lock() = tmp;
                return Poll::Ready(Err(io::Error::other(format!("anytls read: {e}"))));
            }
        };
        let fit = n.min(buf.remaining());
        buf.put_slice(&tmp[..fit]);
        if fit < n {
            // A caller that re-polls a Pending read with a *smaller* buf
            // must not lose the tail: re-park it as an immediately-ready
            // pending read.
            let rest = tmp.split_off(fit);
            let rest_len = rest.len();
            *guard = Some(Box::pin(async move { (rest, Ok(rest_len)) }));
        }
        tmp.clear();
        *self.read_scratch.lock() = tmp;
        Poll::Ready(Ok(()))
    }
}

/// The relay's owned-buffer write path: the `BytesMut` region moves into
/// the anytls frame payload via `split_to` — the `copy_from_slice`
/// `poll_write` would pay is gone on this direction. The conn declares
/// the frame's headroom want so the relay leads every fill with the
/// 7-byte reserved prefix the stream overlays its header into: one fill
/// becomes one contiguous wire frame.
impl WriteBytes for AnytlsConn {
    fn poll_write_bytes(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut Option<BytesMut>,
    ) -> Poll<io::Result<()>> {
        // WriteBytes-contract gate (debug/test builds only): a presented
        // slot MUST lead with `want_write_headroom()` zero bytes — the
        // stream tolerates a bare payload via its Split fallback, which
        // would silently mask the lost contiguity. `None` and empty
        // slots are the slot protocol's legal early-out shapes, not
        // violations.
        let headroom = self.stream.want_write_headroom();
        debug_assert!(
            bytes.as_ref().is_none_or(|b| {
                b.is_empty() || (b.len() >= headroom && b[..headroom].iter().all(|v| *v == 0))
            }),
            "WriteBytes slot arrived without the reserved zeroed headroom \
             prefix — callers must reserve want_write_headroom() bytes; \
             the stream's Split fallback masks the perf loss"
        );
        self.stream.poll_write_bytes_data(cx, bytes)
    }

    fn want_write_headroom(&self) -> usize {
        self.stream.want_write_headroom()
    }
}

impl AsyncWrite for AnytlsConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stream.poll_write_data(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_flush_data(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_shutdown_data(cx)
    }
}

impl Drop for AnytlsConn {
    fn drop(&mut self) {
        // Belt-and-suspenders: the relay path that drops the boxed `ProxyConn`
        // without first calling `poll_shutdown` (e.g. on a copy error) must
        // still FIN the stream so the proxied connection and map entry are
        // released. `fin_stream` is idempotent with `poll_shutdown`.
        self.fin_stream();

        // An owned (unpooled, relay-created) session holds the whole relay
        // stream — close it now instead of leaving it to the heartbeat,
        // which is a liveness probe (not an idle reaper) and would keep a
        // live-server session alive indefinitely. The queued FIN above may
        // never reach the wire here — `close` tears down the writer before
        // draining the frame queue — but that's benign: closing the session
        // releases every server-side stream anyway. `Session::close` is
        // idempotent, so a session that already failed is a no-op. Without
        // a runtime handle (conn dropped off-runtime or mid-shutdown) the
        // session persists until its transport dies — no other watchdog
        // exists; acceptable because conns are dropped on runtime tasks.
        if self.session_owned {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let session = Arc::clone(&self.session);
                handle.spawn(async move {
                    if let Err(e) = session.close().await {
                        tracing::debug!("anytls: owned session close failed: {e}");
                    }
                });
            }
        }
    }
}

impl ProxyConn for AnytlsConn {
    fn write_bytes(&mut self) -> Option<&mut dyn WriteBytes> {
        Some(self)
    }
}

// ─── udp-over-tcp v2 (sing-box `uot`) ────────────────────────────────────────
//
// AnyTLS carries UDP the same way sing-box and mihomo do: a normal proxy
// stream opened to the magic destination `sp.v2.udp-over-tcp.arpa:0`, then
// sing-box's `uot` framing inside it.
//
//   request (once, before the first datagram):
//       | isConnect | ATYP | Address | Port  |
//       | u8        | u8   | var     | u16be |   ← SOCKS5 family bytes
//
//   datagram (repeated, non-connect mode):
//       | ATYP | Address | Port  | Length | Payload |
//       | u8   | var     | u16be | u16be  | var     |   ← uot family bytes
//
// Beware the asymmetry: upstream serializes the *request* address with
// `M.SocksaddrSerializer` (SOCKS5 bytes 0x01/0x03/0x04) but every *per-packet*
// address with `uot.AddrParser` (its own 0x00/0x01/0x02). Reusing one table
// for both is silently wrong on the wire.
//
// Like mihomo we run in non-connect mode (`uot.Request{Destination: …}` leaves
// `IsConnect` false), so each datagram carries its own address and replies
// carry the real source address — which is what `ProxyPacketConn` needs to
// hand back to the SOCKS5/TUN listeners.
//
// upstream: sing `common/uot/{protocol,conn,server}.go`,
// mihomo `adapter/outbound/anytls.go: ListenPacketContext`

/// SOCKS5 address-family bytes — the **request** header only.
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// One anytls data frame carries a `u16` length, so a datagram plus its uot
/// header must fit in 64 KiB. The largest possible IPv6 header is
/// ATYP(1) + addr(16) + port(2) + length(2) = 21 bytes, which still leaves
/// room for a maximum-size (65507-byte) UDP payload.
const MAX_UOT_FRAME: usize = u16::MAX as usize;

/// Encode the one-shot uot request: `isConnect = 0` followed by the session's
/// nominal destination in SOCKS5 form. In non-connect mode the server ignores
/// this address (it routes per packet), but upstream still sends it and its
/// serializer rejects an empty address, so mirror mihomo and send the
/// resolved destination — falling back to the hostname when the metadata has
/// no IP yet.
fn encode_uot_request(metadata: &Metadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    buf.push(0); // isConnect = false
    match metadata.dst_ip {
        Some(IpAddr::V4(v4)) => {
            buf.push(SOCKS5_ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => {
                buf.push(SOCKS5_ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            None => {
                buf.push(SOCKS5_ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        },
        None => {
            // No resolved IP: send the hostname, truncated to the 255-byte
            // ceiling the length prefix allows. An empty host degrades to
            // 0.0.0.0 rather than an unencodable address.
            let host = metadata.host.as_bytes();
            if host.is_empty() || host.len() > 255 {
                buf.push(SOCKS5_ATYP_IPV4);
                buf.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            } else {
                buf.push(SOCKS5_ATYP_DOMAIN);
                buf.push(host.len() as u8);
                buf.extend_from_slice(host);
            }
        }
    }
    buf.extend_from_slice(&metadata.dst_port.to_be_bytes());
    buf
}

/// UDP-over-AnyTLS packet connection.
///
/// Each datagram becomes exactly one anytls data frame, so the framing the
/// server reassembles never interleaves with another task's packet. Reads
/// borrow the stream's own reader mutex. The uot request is already on the
/// wire — `dial_udp` sends it on the open path (issue #535) — so writes are
/// plain per-datagram frames.
struct AnytlsPacketConn {
    stream: Arc<AnytlsStream>,
    // See `AnytlsConn::session`.
    _session: Arc<Session>,
    /// Set once a frame read is torn by cancellation or error — the
    /// stream's framing is then unrecoverable, so every later packet op must fail
    /// fast rather than misdeliver (issue #514).
    poisoned: std::sync::atomic::AtomicBool,
    /// A chained `UdpTarget::Name` binds every datagram's uot address to the
    /// domain (`UOT_ATYP_DOMAIN`) so the server resolves it (issue #657).
    /// `None` keeps per-packet `SocketAddr` stamping.
    write_target: Option<(smol_str::SmolStr, u16)>,
}

impl AnytlsPacketConn {
    fn new(
        stream: Arc<AnytlsStream>,
        session: Arc<Session>,
        write_target: Option<(smol_str::SmolStr, u16)>,
    ) -> Self {
        Self {
            stream,
            _session: session,
            poisoned: std::sync::atomic::AtomicBool::new(false),
            write_target,
        }
    }

    /// Idempotent per-stream FIN, identical in intent to [`AnytlsConn::fin_stream`]:
    /// release the server's UDP socket and the session's stream-map entry
    /// without tearing down the pooled session.
    fn fin_stream(&self) {
        self.stream.close();
    }
}

#[async_trait]
impl ProxyPacketConn for AnytlsPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        crate::check_not_desynced(&self.poisoned)?;
        let mut reader = self.stream.reader().lock().await;
        // Re-check post-lock: a read parked behind a cancelled mid-frame
        // read must not consume the torn remainder.
        crate::check_not_desynced(&self.poisoned)?;
        // `guard` must be declared AFTER `reader`: locals drop in reverse
        // order, so the guard's poison store runs while the mutex is still
        // held — the unlock then gives the parked reader's re-check the
        // happens-before edge it needs.
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);

        let addr = read_uot_addr(&mut *reader).await?;

        let mut len_bytes = [0u8; 2];
        reader
            .read_exact(&mut len_bytes)
            .await
            .map_err(MeowError::Io)?;
        let length = u16::from_be_bytes(len_bytes) as usize;

        // Copy what fits and drain the rest, so an undersized caller buffer
        // truncates one datagram instead of desynchronizing the stream.
        let to_copy = length.min(buf.len());
        if to_copy > 0 {
            reader
                .read_exact(&mut buf[..to_copy])
                .await
                .map_err(MeowError::Io)?;
        }
        // Drain the tail through a fixed stack scratch — a peer could
        // otherwise force a ~64 KiB alloc/dealloc cycle per read by
        // declaring max-size datagrams (issue #621). The frame length is
        // a u16, so the loop terminates after at most ~8 iterations.
        let mut remaining = length - to_copy;
        if remaining > 0 {
            let mut sink = [0u8; 8192];
            while remaining > 0 {
                let chunk = remaining.min(sink.len());
                reader
                    .read_exact(&mut sink[..chunk])
                    .await
                    .map_err(MeowError::Io)?;
                remaining -= chunk;
            }
        }
        guard.complete = true;
        Ok((to_copy, addr))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        // `send_data` queues the frame atomically, so a cancelled write
        // cannot tear framing — but a conn poisoned on the read side is
        // dead regardless; fail fast rather than feed it.
        crate::check_not_desynced(&self.poisoned)?;
        let mut frame = Vec::with_capacity(21 + buf.len());
        match &self.write_target {
            Some((host, port)) => encode_uot_addr_domain(&mut frame, host, *port),
            None => encode_uot_addr(&mut frame, addr),
        }
        let Ok(length) = u16::try_from(buf.len()) else {
            return Err(MeowError::Proxy(format!(
                "anytls udp: packet too large ({} > {})",
                buf.len(),
                u16::MAX
            )));
        };
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(buf);

        // The AnyTLS frame header is a u16 too; reject oversized datagrams.
        if frame.len() > MAX_UOT_FRAME {
            return Err(MeowError::Proxy(format!(
                "anytls udp: framed packet too large ({} > {MAX_UOT_FRAME})",
                frame.len()
            )));
        }

        self.stream
            .send_data(Bytes::from(frame))
            .await
            .map_err(|e| anytls_err("udp write", e))?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        // Diagnostics only: the datagrams ride a multiplexed TLS stream, there
        // is no local UDP socket to report.
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        self.fin_stream();
        Ok(())
    }
}

impl Drop for AnytlsPacketConn {
    fn drop(&mut self) {
        // NAT eviction drops the boxed conn without calling `close()`, so FIN
        // here too; `fin_stream` is idempotent across both paths.
        self.fin_stream();
    }
}

/// Normalise the SNI / verification name: trim whitespace and IPv6 brackets;
/// an IP literal is verified against the certificate's `iPAddress` SAN and
/// (per RFC 6066 §3) not sent as SNI — `TlsLayer` handles both.
fn normalize_server_name(value: &str) -> std::result::Result<String, String> {
    normalize_name(value, "SNI")
}

/// [`normalize_server_name`] with the field named in the error.
fn normalize_name(value: &str, field: &str) -> std::result::Result<String, String> {
    let normalized = value.trim().trim_start_matches('[').trim_end_matches(']');
    if normalized.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(normalized.to_string())
}

/// Bridges `meow_transport::tls::TlsLayer` into anytls-rs's [`TlsConnect`]
/// hook so the vendored client links no TLS library of its own.
struct MeowTlsConnect {
    layer: Arc<TlsLayer>,
}

impl TlsConnect for MeowTlsConnect {
    fn connect(&self, tcp: TcpStream) -> TlsConnectFuture<'_> {
        Box::pin(async move {
            let stream = self.layer.connect(Box::new(tcp)).await.map_err(|e| {
                // Keep the socket io error verbatim — `anytls_err` maps
                // `Io` back to `MeowError::Io`, so errno survives to the
                // group dead-mark classifiers (issue #668); same arm the
                // `connect_over` path takes.
                match e {
                    meow_transport::TransportError::Io(e) => anytls_rs::AnyTlsError::Io(e),
                    other => anytls_rs::AnyTlsError::Tls(format!("TLS handshake failed: {other}")),
                }
            })?;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }

    /// The `dialer-proxy` leg of the same hook: the client's transport
    /// dialer already connected the stream (through the front proxy), so
    /// the identical `TlsLayer` handshake runs over it — the exact path
    /// `connect_over` proves on a relay-supplied stream.
    fn connect_stream(&self, stream: Box<dyn SyncStream>) -> TlsConnectFuture<'_> {
        Box::pin(async move {
            let stream = self
                .layer
                .connect(Box::new(stream))
                .await
                .map_err(|e| match e {
                    meow_transport::TransportError::Io(e) => anytls_rs::AnyTlsError::Io(e),
                    other => anytls_rs::AnyTlsError::Tls(format!("TLS handshake failed: {other}")),
                })?;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }
}

/// Bridges the injected `dialer-proxy`
/// [`TcpDialer`](crate::dialer::TcpDialer) into the vendored client's
/// per-client `TransportDialer` hook: its `dial` already returns
/// `Box<dyn meow_transport::Stream>`, which satisfies `SyncStream` (that
/// stream contract requires `Send + Sync + Unpin`), so the bridge is a
/// pure repackage — no wrapper stream to frame or downcast through.
///
/// `internal` stays `false`: an AnyTLS session is the outbound's shared
/// long-lived transport — it multiplexes whichever streams the pool hands
/// it, so its establishment is user-traffic plumbing, not housekeeping
/// (the front group's usage accounting treats it as the outbound's own).
struct ChainedTransportDialer(Arc<dyn crate::dialer::TcpDialer>);

impl anytls_rs::TransportDialer for ChainedTransportDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> anytls_rs::TransportDialFuture<'a> {
        Box::pin(async move {
            let stream = self.0.dial(host, port, false).await?;
            Ok(Box::new(stream) as Box<dyn SyncStream>)
        })
    }
}

// ─── meow_common ⇄ anytls_rs protector bridge ────────────────────────────────
//
// `anytls_rs` can't depend on `meow_common` (or vice-versa), so each ships
// its own outbound-socket hook registries. These bridges — installed exactly
// once via the `Once` guard reached from `AnytlsAdapter::build` — re-publish
// meow_common's hooks into the `anytls-rs` registries:
//
// - `TcpDialer` (all targets): routes the client-side session dial through
//   `meow_common::connect_tcp_host`, i.e. the installed `HostResolver` +
//   `SocketProtector` stack. Without it `anytls-rs` resolves the server
//   hostname with `tokio::net::lookup_host` (the system resolver), which
//   inside a meow VPN is the in-process fake-IP DNS — the protected socket
//   then dials an unroutable fake IP and times out (the loop-routing
//   failure mode described in `meow_common::socket_protect`).
//
// - `SocketProtector` (Android): covers the remaining direct socket sites
//   in `anytls-rs` (the per-stream UDP relay's `bind_udp`), which don't go
//   through the dialer.
fn install_anytls_bridges() {
    use std::sync::Once;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        struct DialBridge;
        impl anytls_rs::TcpDialer for DialBridge {
            fn dial<'a>(
                &'a self,
                host: &'a str,
                port: u16,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = std::io::Result<tokio::net::TcpStream>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(meow_common::connect_tcp_host(host, port))
            }
        }
        anytls_rs::set_tcp_dialer(Arc::new(DialBridge));

        #[cfg(any(target_os = "android", target_env = "ohos"))]
        {
            struct Bridge;
            impl anytls_rs::SocketProtector for Bridge {
                fn protect(&self, fd: std::os::fd::RawFd) -> std::io::Result<()> {
                    match meow_common::socket_protector() {
                        Some(p) => p.protect(fd),
                        // No protector installed on the meow_common side —
                        // match the off-Android no-protector behaviour.
                        None => Ok(()),
                    }
                }
            }
            anytls_rs::set_socket_protector(Arc::new(Bridge));
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::uot::UOT_ATYP_IPV4;
    use anytls_rs::protocol::{Command, HEADER_OVERHEAD_SIZE};
    use meow_common::Network;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    #[test]
    fn tls_options_absent_keep_legacy_defaults() {
        let cfg = AnytlsTlsOptions {
            skip_cert_verify: true,
            ..Default::default()
        }
        .tls_config("n", "example.com")
        .unwrap();
        assert_eq!(cfg.sni.as_deref(), Some("example.com"));
        assert!(cfg.skip_cert_verify, "no pin/name: skip-cert-verify kept");
        assert!(cfg.cert_pin.is_none());
        assert!(cfg.verify_name.is_none());
        assert!(cfg.fingerprint.is_none());
        assert!(cfg.alpn.is_empty());
    }

    #[test]
    fn tls_options_pin_and_name_override_skip_cert_verify() {
        let pin = "AB:".repeat(32);
        let cfg = AnytlsTlsOptions {
            skip_cert_verify: true,
            fingerprint: Some(pin[..95].to_string()),
            ..Default::default()
        }
        .tls_config("n", "example.com")
        .unwrap();
        assert_eq!(cfg.cert_pin, Some([0xab; 32]));
        assert!(!cfg.skip_cert_verify, "a pin must not be bypassed");

        let cfg = AnytlsTlsOptions {
            skip_cert_verify: true,
            name_cert_verify: Some("real.example.com".into()),
            ..Default::default()
        }
        .tls_config("n", "example.com")
        .unwrap();
        assert_eq!(cfg.verify_name.as_deref(), Some("real.example.com"));
        assert!(
            !cfg.skip_cert_verify,
            "name-cert-verify forces verification"
        );
    }

    #[test]
    fn tls_options_reject_bad_values_and_normalize_profile() {
        for bad in ["chrome", "zz", "  "] {
            let err = AnytlsTlsOptions {
                fingerprint: Some(bad.into()),
                ..Default::default()
            }
            .tls_config("n", "example.com")
            .unwrap_err();
            assert!(err.contains("fingerprint"), "{bad:?}: {err}");
        }
        let err = AnytlsTlsOptions {
            name_cert_verify: Some(" ".into()),
            ..Default::default()
        }
        .tls_config("n", "example.com")
        .unwrap_err();
        assert!(err.contains("name-cert-verify"), "{err}");

        let cfg = AnytlsTlsOptions {
            client_fingerprint: Some(" Chrome ".into()),
            ..Default::default()
        }
        .tls_config("n", "example.com")
        .unwrap();
        assert_eq!(cfg.fingerprint.as_deref(), Some("chrome"));
        let cfg = AnytlsTlsOptions {
            client_fingerprint: Some("NONE".into()),
            ..Default::default()
        }
        .tls_config("n", "example.com")
        .unwrap();
        assert!(cfg.fingerprint.is_none());
    }

    async fn test_session() -> (Arc<Session>, DuplexStream) {
        let (io, peer) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(io);
        // Server sessions skip padding, making the wire assertions exact.
        let session = Arc::new(Session::new_server(
            reader,
            writer,
            PaddingFactory::default(),
        ));
        let writer_session = Arc::clone(&session);
        tokio::spawn(async move {
            writer_session.process_stream_data().await.unwrap();
        });
        // `new_server` does not start the inbound frame reader — the
        // real server spawns `recv_loop` per session (server.rs). Tests
        // that feed peer→session frames need it running.
        let reader_session = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = reader_session.recv_loop().await;
        });
        (session, peer)
    }

    async fn wire_frame(peer: &mut DuplexStream) -> (Command, u32, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut header = [0; 7];
            peer.read_exact(&mut header).await.unwrap();
            let mut data = vec![0; u16::from_be_bytes([header[5], header[6]]) as usize];
            peer.read_exact(&mut data).await.unwrap();
            (
                Command::from(header[0]),
                u32::from_be_bytes(header[1..5].try_into().unwrap()),
                data,
            )
        })
        .await
        .expect("writer stalled")
    }

    fn metadata_for(host: &str, ip: Option<IpAddr>, port: u16) -> Metadata {
        Metadata {
            network: Network::Udp,
            host: smol_str::SmolStr::from(host),
            dst_ip: ip,
            dst_port: port,
            ..Default::default()
        }
    }

    #[test]
    fn tcp_destination_uses_original_host_then_ip() {
        let mut metadata =
            metadata_for("requested.example", Some("192.0.2.1".parse().unwrap()), 443);
        metadata.network = Network::Tcp;
        metadata.sniff_host = smol_str::SmolStr::from("sniffed.example");
        assert_eq!(
            anytls_tcp_destination(&metadata).unwrap(),
            "requested.example",
            "a sniffed rule host must not replace the requested dial target"
        );

        metadata.host = smol_str::SmolStr::default();
        assert_eq!(anytls_tcp_destination(&metadata).unwrap(), "192.0.2.1");

        metadata.dst_ip = Some("2001:db8::1".parse().unwrap());
        assert_eq!(anytls_tcp_destination(&metadata).unwrap(), "2001:db8::1");

        metadata.dst_ip = None;
        assert!(anytls_tcp_destination(&metadata)
            .unwrap_err()
            .to_string()
            .contains("missing destination host and IP"));
    }

    #[tokio::test]
    async fn tcp_drop_during_partial_frame_preserves_other_streams() {
        let (session, mut peer) = test_session().await;
        let (first, _) = session.open_stream().await.unwrap();
        let first_id = first.id();
        let (second, _) = session.open_stream().await.unwrap();
        let second_id = second.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        let mut first = AnytlsConn::new(first, Arc::clone(&session));
        let mut second = AnytlsConn::new(second, Arc::clone(&session));
        first.write_all(&[42; 512]).await.unwrap();

        // A 64-byte duplex cannot fit this frame. Seeing its prefix proves
        // the writer has started, while the rest is still backpressured.
        let mut prefix = [0; 4];
        peer.read_exact(&mut prefix).await.unwrap();
        drop(first);
        second.write_all(b"still-aligned").await.unwrap();

        let mut remainder = vec![0; 7 + 512 - prefix.len()];
        peer.read_exact(&mut remainder).await.unwrap();
        let mut full_frame = prefix.to_vec();
        full_frame.extend_from_slice(&remainder);
        assert_eq!(full_frame[0], u8::from(Command::Push));
        assert_eq!(
            u32::from_be_bytes(full_frame[1..5].try_into().unwrap()),
            first_id
        );
        assert_eq!(&full_frame[7..], &[42; 512]);
        assert_eq!(
            wire_frame(&mut peer).await,
            (Command::Fin, first_id, vec![])
        );
        assert_eq!(
            wire_frame(&mut peer).await,
            (Command::Push, second_id, b"still-aligned".to_vec())
        );
        drop(second);
        assert_eq!(
            wire_frame(&mut peer).await,
            (Command::Fin, second_id, vec![])
        );
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn udp_data_and_fin_use_the_stream_writer_fifo() {
        let (session, mut peer) = test_session().await;
        let (stream, _) = session.open_stream().await.unwrap();
        let id = stream.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        let conn = AnytlsPacketConn::new(stream, Arc::clone(&session), None);
        let destination: SocketAddr = "192.0.2.2:53".parse().unwrap();

        assert_eq!(conn.write_packet(b"udp", &destination).await.unwrap(), 3);
        drop(conn);
        let (cmd, stream_id, data) = wire_frame(&mut peer).await;
        assert_eq!((cmd, stream_id), (Command::Push, id));
        // One datagram is one frame: uot addr + u16 length + payload, with no
        // request prefix — in production the request was already flushed by
        // `create_proxy_stream_with_payload` before the stream is handed
        // back (issue #535); this harness builds the conn directly so no
        // request exists on the wire here at all.
        assert_eq!(
            data,
            [UOT_ATYP_IPV4, 192, 0, 2, 2, 0, 53, 0, 3, b'u', b'd', b'p']
        );
        assert_eq!(wire_frame(&mut peer).await, (Command::Fin, id, vec![]));
        session.close().await.unwrap();
    }

    /// Push one data frame into the session from the peer end.
    async fn push_frame(peer: &mut DuplexStream, stream_id: u32, data: &[u8]) {
        let mut frame = Vec::with_capacity(7 + data.len());
        frame.push(Command::Push as u8);
        frame.extend_from_slice(&stream_id.to_be_bytes());
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        peer.write_all(&frame).await.unwrap();
    }

    /// Issue #543: same class as the trojan poison — a `read_packet`
    /// cancelled mid-frame releases the reader lock with the stream
    /// mid-datagram and every later read silently parses garbage. The
    /// conn must poison itself so the tunnel re-dials instead.
    #[tokio::test]
    async fn udp_cancelled_read_poisons_packet_conn() {
        let (session, mut peer) = test_session().await;
        let (stream, _) = session.open_stream().await.unwrap();
        let id = stream.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        let conn = AnytlsPacketConn::new(stream, Arc::clone(&session), None);
        let mut buf = [0u8; 2048];

        // A lone ATYP byte: the address read stalls mid-frame.
        push_frame(&mut peer, id, &[UOT_ATYP_IPV4]).await;
        let cancelled =
            tokio::time::timeout(Duration::from_millis(50), conn.read_packet(&mut buf)).await;
        assert!(cancelled.is_err(), "read must have timed out mid-addr");

        // The peer then completes the datagram — the conn must not
        // resume mid-stream.
        push_frame(&mut peer, id, &[9, 9, 9, 9, 0, 53, 0, 1, b'x']).await;
        let err = conn.read_packet(&mut buf).await.unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "expected desync error after cancelled read, got {err:?}"
        );

        // Writes fail fast on the desynced conn too — the tunnel
        // re-dials rather than emitting datagrams whose replies can
        // never be parsed.
        let destination: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let err = conn.write_packet(b"x", &destination).await.unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "write on a desynced conn must fail fast, got {err:?}"
        );
        session.close().await.unwrap();
    }

    /// A read parked on the reader mutex while another is cancelled
    /// mid-frame must fail fast at the post-lock re-check instead of
    /// resuming the torn frame.
    #[tokio::test]
    async fn udp_parked_read_after_cancelled_read_fails_fast() {
        let (session, mut peer) = test_session().await;
        let (stream, _) = session.open_stream().await.unwrap();
        let id = stream.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        let conn = Arc::new(AnytlsPacketConn::new(stream, Arc::clone(&session), None));

        // read1 stalls mid-addr while holding the reader lock.
        push_frame(&mut peer, id, &[UOT_ATYP_IPV4]).await;
        let conn1 = Arc::clone(&conn);
        let first = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            conn1.read_packet(&mut buf).await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        // read2 parks on the mutex behind it.
        let conn2 = Arc::clone(&conn);
        let queued = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            conn2.read_packet(&mut buf).await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        first.abort();
        // A trailing datagram keeps a regressed implementation honest:
        // without the post-lock re-check, read2 would parse these bytes
        // as the start of a fresh frame and *succeed* — the assert below
        // fails — rather than parking forever on an empty stream.
        push_frame(
            &mut peer,
            id,
            &[UOT_ATYP_IPV4, 9, 9, 9, 9, 0, 53, 0, 1, b'x'],
        )
        .await;
        let err = tokio::time::timeout(Duration::from_secs(2), queued)
            .await
            .expect("queued read must resolve, not hang")
            .unwrap()
            .unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "queued read must fail fast after the poisoned first read, got {err:?}"
        );
        session.close().await.unwrap();
    }

    /// A read cancelled while parked on the reader mutex consumed no
    /// bytes — it must NOT poison the conn. Pins the invariant that the
    /// guard arms only after the lock is held.
    #[tokio::test]
    async fn udp_parked_read_cancellation_does_not_poison() {
        let (session, mut peer) = test_session().await;
        let (stream, _) = session.open_stream().await.unwrap();
        let id = stream.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        let conn = Arc::new(AnytlsPacketConn::new(stream, Arc::clone(&session), None));

        // read1 stalls mid-addr holding the lock; read2 parks behind it.
        push_frame(&mut peer, id, &[UOT_ATYP_IPV4]).await;
        let conn1 = Arc::clone(&conn);
        let first = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            conn1.read_packet(&mut buf).await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let conn2 = Arc::clone(&conn);
        let parked = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            conn2.read_packet(&mut buf).await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        parked.abort();
        let _ = parked.await;

        // read1's datagram completes cleanly once the rest lands, and the
        // conn still serves the following datagram — no poison.
        push_frame(&mut peer, id, &[9, 9, 9, 9, 0, 53, 0, 1, b'a']).await;
        tokio::time::timeout(Duration::from_secs(2), first)
            .await
            .expect("read1 must resolve, not hang")
            .unwrap()
            .unwrap();
        push_frame(
            &mut peer,
            id,
            &[UOT_ATYP_IPV4, 8, 8, 8, 8, 0, 53, 0, 1, b'b'],
        )
        .await;
        let mut buf = [0u8; 2048];
        tokio::time::timeout(Duration::from_secs(2), conn.read_packet(&mut buf))
            .await
            .expect("read after parked-cancel must resolve")
            .unwrap();
        session.close().await.unwrap();
    }

    /// The same poison fires on a parse error after bytes were consumed
    /// (unknown atyp) — not only on future cancellation.
    #[tokio::test]
    async fn udp_errored_read_poisons_packet_conn() {
        let (session, mut peer) = test_session().await;
        let (stream, _) = session.open_stream().await.unwrap();
        let id = stream.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        let conn = AnytlsPacketConn::new(stream, Arc::clone(&session), None);
        let mut buf = [0u8; 2048];

        push_frame(&mut peer, id, &[0x7f]).await;
        let err = tokio::time::timeout(Duration::from_secs(2), conn.read_packet(&mut buf))
            .await
            .expect("errored read must resolve")
            .unwrap_err();
        assert!(err.to_string().contains("address type"), "got {err:?}");

        // The peer then sends a valid datagram — the conn must not
        // resume mid-stream.
        push_frame(
            &mut peer,
            id,
            &[UOT_ATYP_IPV4, 9, 9, 9, 9, 0, 53, 0, 1, b'x'],
        )
        .await;
        let err = tokio::time::timeout(Duration::from_secs(2), conn.read_packet(&mut buf))
            .await
            .expect("poisoned read must fail fast")
            .unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "second read must fail fast on poisoned conn, got {err:?}"
        );
        session.close().await.unwrap();
    }

    /// A datagram larger than the caller buffer is truncated, not torn:
    /// `read_packet`'s `length > to_copy` sink-drain keeps the stream
    /// aligned so the next datagram still parses.
    #[tokio::test]
    async fn udp_undersized_buffer_truncates_without_desync() {
        let (session, mut peer) = test_session().await;
        let (stream, _) = session.open_stream().await.unwrap();
        let id = stream.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        let conn = AnytlsPacketConn::new(stream, Arc::clone(&session), None);
        let src: SocketAddr = "192.0.2.9:53".parse().unwrap();

        // 4-byte payload into a 2-byte buffer — 2 bytes must drain.
        let mut datagram = Vec::new();
        encode_uot_addr(&mut datagram, &src);
        datagram.extend_from_slice(&4u16.to_be_bytes());
        datagram.extend_from_slice(&[1, 2, 3, 4]);
        push_frame(&mut peer, id, &datagram).await;

        let mut buf = [0u8; 2];
        let (n, addr) = tokio::time::timeout(Duration::from_secs(2), conn.read_packet(&mut buf))
            .await
            .expect("truncated read must resolve")
            .unwrap();
        assert_eq!(addr, src);
        assert_eq!(&buf[..n], &[1, 2]);

        // The following datagram still parses — the drain kept framing.
        let mut datagram2 = Vec::new();
        encode_uot_addr(&mut datagram2, &src);
        datagram2.extend_from_slice(&1u16.to_be_bytes());
        datagram2.extend_from_slice(&[9]);
        push_frame(&mut peer, id, &datagram2).await;

        let mut buf2 = [0u8; 2048];
        let (n2, addr2) = tokio::time::timeout(Duration::from_secs(2), conn.read_packet(&mut buf2))
            .await
            .expect("post-truncation read must resolve")
            .unwrap();
        assert_eq!(addr2, src);
        assert_eq!(&buf2[..n2], &[9]);
        session.close().await.unwrap();
    }

    /// A drain larger than one 8 KiB sink pass: the loop must iterate and
    /// still leave framing aligned (issue #621 review — single-pass drains
    /// alone don't prove the loop).
    #[tokio::test]
    async fn udp_oversized_drain_iterates_sink() {
        let (session, mut peer) = test_session().await;
        let (stream, _) = session.open_stream().await.unwrap();
        let id = stream.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        let conn = AnytlsPacketConn::new(stream, Arc::clone(&session), None);
        let src: SocketAddr = "192.0.2.9:53".parse().unwrap();

        // 20 KiB payload into a 1-byte buffer → 19999 bytes drained over
        // three 8 KiB sink passes.
        let mut datagram = Vec::new();
        encode_uot_addr(&mut datagram, &src);
        datagram.extend_from_slice(&20000u16.to_be_bytes());
        datagram.extend_from_slice(&vec![0xAB; 20000]);
        push_frame(&mut peer, id, &datagram).await;

        let mut buf = [0u8; 1];
        let (n, addr) = tokio::time::timeout(Duration::from_secs(2), conn.read_packet(&mut buf))
            .await
            .expect("oversized read must resolve")
            .unwrap();
        assert_eq!(addr, src);
        assert_eq!(&buf[..n], &[0xAB]);

        let mut datagram2 = Vec::new();
        encode_uot_addr(&mut datagram2, &src);
        datagram2.extend_from_slice(&2u16.to_be_bytes());
        datagram2.extend_from_slice(&[7, 7]);
        push_frame(&mut peer, id, &datagram2).await;

        let mut buf2 = [0u8; 2048];
        let (n2, _) = tokio::time::timeout(Duration::from_secs(2), conn.read_packet(&mut buf2))
            .await
            .expect("post-drain read must resolve")
            .unwrap();
        assert_eq!(&buf2[..n2], &[7, 7]);
        session.close().await.unwrap();
    }

    /// Happy-path guard: a completed datagram read must not poison.
    #[tokio::test]
    async fn udp_completed_read_leaves_conn_usable() {
        let (session, mut peer) = test_session().await;
        let (stream, _) = session.open_stream().await.unwrap();
        let id = stream.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        let conn = AnytlsPacketConn::new(stream, Arc::clone(&session), None);
        let mut buf = [0u8; 2048];
        let src: SocketAddr = "192.0.2.9:53".parse().unwrap();

        for i in 0u8..2 {
            // uot addr + u16 len + payload, exactly what the server sends.
            let mut datagram = Vec::new();
            encode_uot_addr(&mut datagram, &src);
            datagram.extend_from_slice(&3u16.to_be_bytes());
            datagram.extend_from_slice(&[i, i, i]);
            push_frame(&mut peer, id, &datagram).await;

            let (n, addr) =
                tokio::time::timeout(Duration::from_secs(2), conn.read_packet(&mut buf))
                    .await
                    .expect("completed read must resolve")
                    .unwrap();
            assert_eq!(addr, src);
            assert_eq!(&buf[..n], &[i, i, i]);
        }
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn udp_cancelled_admission_preserves_close_order() {
        let (session, mut peer) = test_session().await;
        let (stream, _) = session.open_stream().await.unwrap();
        let id = stream.id();
        assert_eq!(wire_frame(&mut peer).await.0, Command::Syn);
        // Fill the session budget while the first frame blocks on the wire.
        for _ in 0..64 {
            stream.send_data(Bytes::from(vec![42; 512])).await.unwrap();
        }
        let conn = AnytlsPacketConn::new(stream, Arc::clone(&session), None);
        let destination: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let mut write = Box::pin(conn.write_packet(b"cancelled", &destination));
        assert!(futures::poll!(&mut write).is_pending());
        drop(write);

        let mut write = Box::pin(conn.write_packet(b"closed", &destination));
        assert!(futures::poll!(&mut write).is_pending());
        conn.close().unwrap();
        assert!(write.await.is_err(), "close must wake blocked admission");
        for _ in 0..64 {
            assert_eq!(
                wire_frame(&mut peer).await,
                (Command::Push, id, vec![42; 512])
            );
        }
        assert_eq!(wire_frame(&mut peer).await, (Command::Fin, id, vec![]));
        session.close().await.unwrap();
    }

    /// The request header uses SOCKS5 family bytes, *not* the uot ones.
    #[test]
    fn request_encodes_socks5_family_bytes() {
        let v4 = encode_uot_request(&metadata_for("", Some("8.8.8.8".parse().unwrap()), 53));
        assert_eq!(v4, vec![0, SOCKS5_ATYP_IPV4, 8, 8, 8, 8, 0, 53]);

        let v6 = encode_uot_request(&metadata_for(
            "",
            Some("2001:4860:4860::8888".parse().unwrap()),
            53,
        ));
        assert_eq!(v6[0], 0, "isConnect must be false (Bind format)");
        assert_eq!(v6[1], SOCKS5_ATYP_IPV6);
        assert_eq!(v6.len(), 1 + 1 + 16 + 2);

        let domain = encode_uot_request(&metadata_for("example.com", None, 443));
        assert_eq!(domain[0], 0);
        assert_eq!(domain[1], SOCKS5_ATYP_DOMAIN);
        assert_eq!(domain[2], 11);
        assert_eq!(&domain[3..14], b"example.com");
        assert_eq!(u16::from_be_bytes([domain[14], domain[15]]), 443);
    }

    /// A resolved IPv4-mapped destination goes out as plain IPv4, matching
    /// upstream's `Socksaddr` normalization.
    #[test]
    fn request_unmaps_v4_mapped_destination() {
        let mapped = encode_uot_request(&metadata_for(
            "",
            Some("::ffff:1.2.3.4".parse().unwrap()),
            8080,
        ));
        assert_eq!(mapped, vec![0, SOCKS5_ATYP_IPV4, 1, 2, 3, 4, 0x1f, 0x90]);
    }

    /// Metadata with neither an IP nor a host must still produce an address
    /// the upstream serializer accepts.
    #[test]
    fn request_falls_back_to_unspecified_without_address() {
        let empty = encode_uot_request(&metadata_for("", None, 1234));
        assert_eq!(empty, vec![0, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0x04, 0xd2]);
    }

    /// `poll_write_bytes_data` slots carrying the 7-byte headroom contract
    /// must produce wire Push payloads byte-identical to the caller's
    /// payload — a single stray 0x00 means the headroom prefix leaked
    /// onto the wire.
    #[tokio::test]
    async fn write_bytes_headroom_wire_payload_is_exact() {
        use std::future::poll_fn;

        let (io, mut peer) = tokio::io::duplex(4 * 1024 * 1024);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(anytls_rs::session::Session::new_client(
            reader,
            writer,
            PaddingFactory::default().into_shared(),
            None,
        ));
        let worker = Arc::clone(&session);
        tokio::spawn(async move { worker.process_stream_data().await });
        let (stream, _ack) = session.open_stream().await.unwrap();
        let _ = wire_frame(&mut peer).await; // SYN

        let total = 512 * 1024usize;
        let mut sent = 0usize;
        while sent < total {
            let mut slot = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + 65536);
            slot.extend_from_slice(&[0u8; HEADER_OVERHEAD_SIZE]);
            let n = (total - sent).min(65536 - HEADER_OVERHEAD_SIZE);
            slot.extend_from_slice(&vec![0x41u8; n]);
            sent += n;
            let mut opt = Some(slot);
            poll_fn(|cx| stream.poll_write_bytes_data(cx, &mut opt))
                .await
                .unwrap();
            assert!(opt.is_none(), "slot must be fully drained at <=4MiB");
        }
        poll_fn(|cx| stream.poll_flush_data(cx)).await.unwrap();
        drop(stream);
        session.close().await.unwrap();

        // Decode every wire frame; every Push payload byte must be 0x41.
        let mut pushes = 0usize;
        loop {
            let mut header = [0u8; HEADER_OVERHEAD_SIZE];
            match tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut header)).await {
                Ok(Err(_)) | Err(_) => break,
                Ok(Ok(_)) => {}
            }
            let cmd = header[0];
            let len = u16::from_be_bytes([header[5], header[6]]) as usize;
            let mut data = vec![0u8; len];
            peer.read_exact(&mut data).await.unwrap();
            if cmd == Command::Push as u8 {
                pushes += 1;
                assert!(
                    data.iter().all(|&b| b == 0x41),
                    "Push frame #{pushes} (len={len}) contains non-0x41 bytes: {:02x?}",
                    &data[..data.len().min(32)]
                );
            }
        }
        assert!(pushes > 0, "expected Push frames on the wire");
    }

    /// Session-writer stress: 4 streams × 1 MiB headroom slots against a
    /// slow transport (permit contention + batch drains). The peer decodes
    /// every frame — Push payloads must stay pure 0x41 end to end.
    struct NonVectored<W>(W);
    impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for NonVectored<W> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_bytes_backpressure_payload_is_exact() {
        use std::future::poll_fn;
        let (io, mut peer) = tokio::io::duplex(8 * 1024);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(anytls_rs::session::Session::new_client(
            reader,
            Box::new(NonVectored(writer)) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
            PaddingFactory::default().into_shared(),
            None,
        ));
        let worker = Arc::clone(&session);
        tokio::spawn(async move { worker.process_stream_data().await });

        // 慢速解码对端：按帧读并校验 payload 纯度
        let verifier = tokio::spawn(async move {
            let mut bad = 0usize;
            let mut pushes = 0usize;
            let mut payload_total = 0usize;
            while payload_total < 4 * 1024 * 1024 {
                let mut header = [0u8; 7];
                match tokio::time::timeout(Duration::from_secs(30), peer.read_exact(&mut header))
                    .await
                {
                    Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(_)) => {}
                }
                let cmd = header[0];
                let len = u16::from_be_bytes([header[5], header[6]]) as usize;
                let mut data = vec![0u8; len];
                peer.read_exact(&mut data).await.unwrap();
                if cmd == Command::Push as u8 {
                    pushes += 1;
                    payload_total += len;
                    if !data.iter().all(|&b| b == 0x41) {
                        bad += 1;
                        let z = data.iter().filter(|&&b| b != 0x41).count();
                        eprintln!("CORRUPT push len={len} alien={z} head={:02x?}", &data[..16]);
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            (pushes, bad)
        });

        let mut feeders = Vec::new();
        for _ in 0..4 {
            let s = Arc::clone(&session);
            feeders.push(tokio::spawn(async move {
                let (stream, _ack) = s.open_stream().await.unwrap();
                let mut sent = 0usize;
                while sent < 1024 * 1024 {
                    let mut slot = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + 65536);
                    slot.extend_from_slice(&[0u8; HEADER_OVERHEAD_SIZE]);
                    let n = (1024 * 1024 - sent).min(65536 - HEADER_OVERHEAD_SIZE);
                    slot.extend_from_slice(&vec![0x41u8; n]);
                    sent += n;
                    let mut opt = Some(slot);
                    poll_fn(|cx| stream.poll_write_bytes_data(cx, &mut opt))
                        .await
                        .unwrap();
                }
            }));
        }
        for f in feeders {
            f.await.unwrap();
        }
        let (pushes, bad) = verifier.await.unwrap();
        session.close().await.unwrap();
        assert_eq!(bad, 0, "{bad} corrupt push frames of {pushes}");
    }
}
