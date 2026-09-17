//! SOCKS5 outbound proxy adapter (M1.B-4).
//!
//! Implements `ProxyAdapter` for `type: socks5` config entries.  Supports:
//! - Auth method negotiation: no-auth (0x00) and username/password (0x02).
//! - `CMD CONNECT` (0x01) — TCP tunnel.
//! - `atyp` 0x03 (domain) preferred when `metadata.host` is set;
//!   0x01 (IPv4) or 0x04 (IPv6) otherwise.
//! - Optional TLS-wrapping of the TCP control connection to the proxy server.
//! - `CMD UDP ASSOCIATE` (0x03) when `udp: true` — relays UDP (incl. QUIC /
//!   HTTP/3) via a side UDP socket, wrapping each datagram in the RFC 1928 §7
//!   header. The TCP control connection is held open for the association's
//!   lifetime. The UDP relay path is plain (not TLS-wrapped), per the SOCKS5
//!   spec.
//!
//! upstream: `adapter/outbound/socks5.go`

use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use smallvec::SmallVec;
use smol_str::SmolStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::debug;

use crate::stream_conn::StreamConn;

// ─── SOCKS5 constants ─────────────────────────────────────────────────────────

const VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const RESERVED: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;
const REPLY_SUCCESS: u8 = 0x00;

// ─── Adapter ─────────────────────────────────────────────────────────────────

/// SOCKS5 outbound proxy adapter.
///
/// upstream: `adapter/outbound/socks5.go` — `Socks5`
pub struct Socks5Adapter {
    name: SmolStr,
    server: SmolStr,
    port: u16,
    /// `"server:port"` — returned by `addr()` for relay metadata building.
    addr_str: SmolStr,
    /// `Some((username, password))` — both present or neither (ADR-0002 Class A).
    auth: Option<(String, String)>,
    /// Built once at construction (rustls ClientConfig + root store are
    /// expensive); `TlsLayer::connect` is safe to call concurrently.
    tls_layer: Option<meow_transport::tls::TlsLayer>,
    /// Whether `udp: true` was configured — gates UDP ASSOCIATE.
    udp: bool,
    health: ProxyHealth,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
}

impl Socks5Adapter {
    /// Create a `Socks5Adapter`. UDP ASSOCIATE is disabled by default; call
    /// [`Self::with_udp`] to enable it (set from `udp: true` in config).
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        auth: Option<(String, String)>,
        tls: bool,
        skip_cert_verify: bool,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Self {
        // Hoisted out of the dial path: TlsLayer::new clones the webpki root
        // store and builds verifier + crypto provider — per-adapter, not
        // per-connection (same pattern as TrojanAdapter::new).
        let tls_layer = tls.then(|| {
            use meow_transport::tls::{TlsConfig, TlsLayer};
            let tls_cfg = TlsConfig {
                skip_cert_verify,
                ..TlsConfig::new(server)
            };
            TlsLayer::new(&tls_cfg)
                .expect("Socks5Adapter: failed to build TlsLayer — check TLS config")
        });

        Self {
            name: SmolStr::from(name),
            addr_str: SmolStr::from(format!("{server}:{port}")),
            server: SmolStr::from(server),
            port,
            auth,
            tls_layer,
            udp: false,
            health: ProxyHealth::new(),
            dialer,
        }
    }

    /// Enable SOCKS5 UDP ASSOCIATE (HTTP/3 / QUIC relay). Off by default.
    #[must_use]
    pub fn with_udp(mut self, udp: bool) -> Self {
        self.udp = udp;
        self
    }

    /// Dial TCP to the proxy server, optionally wrapping in TLS.
    async fn dial_stream(&self) -> Result<Box<dyn meow_transport::Stream>> {
        let tcp = self
            .dialer
            .dial(&self.server, self.port)
            .await
            .map_err(MeowError::Io)?;
        self.wrap_tls(tcp).await
    }

    /// Apply the configured TLS layer to `stream` if `tls: true`.
    /// `stream` must already terminate at this SOCKS5 server — `dial_tcp`
    /// obtains it from `dialer.dial`, `connect_over` receives it from the
    /// relay chain.
    async fn wrap_tls(
        &self,
        stream: Box<dyn meow_transport::Stream>,
    ) -> Result<Box<dyn meow_transport::Stream>> {
        if let Some(tls_layer) = &self.tls_layer {
            use meow_transport::Transport;
            tls_layer
                .connect(Box::new(stream))
                .await
                .map_err(|e| MeowError::Proxy(e.to_string()))
        } else {
            Ok(stream)
        }
    }

    /// Run the full SOCKS5 handshake (auth negotiation + CONNECT) over `stream`.
    ///
    /// `target_host` — destination hostname (used as `atyp 0x03` when non-empty).
    /// `target_ip`   — destination IP (used as `atyp 0x01`/`0x04` when host is empty).
    /// `target_port` — destination port.
    async fn run_handshake<S>(
        &self,
        stream: &mut S,
        target_host: &str,
        target_ip: Option<IpAddr>,
        target_port: u16,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // SOCKS5 ATYP 0x03 encodes the hostname length as a single byte (0–255).
        // Casting `len() as u8` when len > 255 silently truncates and produces a
        // malformed frame; we reject early instead.
        // ADR-0002 Class A divergence: upstream socks5.go does not guard these.
        if !target_host.is_empty() && target_host.len() > 255 {
            return Err(MeowError::Proxy(format!(
                "socks5: hostname too long ({} bytes, max 255 per protocol)",
                target_host.len()
            )));
        }

        self.negotiate_and_auth(stream).await?;

        // ── Step 3: CONNECT request ───────────────────────────────────────────
        //
        // Prefer domain name (atyp 0x03) when metadata.host is set;
        // fall back to IPv4/IPv6 literal otherwise.
        // upstream: socks5.go — uses hostname when available, NOT IP-only dial.
        let mut req_buf = [0u8; 262];
        req_buf[0] = VERSION;
        req_buf[1] = CMD_CONNECT;
        req_buf[2] = RESERVED;
        let mut pos = 3;

        if target_host.is_empty() {
            match target_ip {
                Some(IpAddr::V4(v4)) => {
                    req_buf[pos] = ATYP_IPV4;
                    pos += 1;
                    req_buf[pos..pos + 4].copy_from_slice(&v4.octets());
                    pos += 4;
                }
                Some(IpAddr::V6(v6)) => {
                    req_buf[pos] = ATYP_IPV6;
                    pos += 1;
                    req_buf[pos..pos + 16].copy_from_slice(&v6.octets());
                    pos += 16;
                }
                None => {
                    return Err(MeowError::Proxy(
                        "socks5: no destination address in metadata".into(),
                    ));
                }
            }
        } else {
            let host_bytes = target_host.as_bytes();
            req_buf[pos] = ATYP_DOMAIN;
            pos += 1;
            req_buf[pos] = host_bytes.len() as u8;
            pos += 1;
            req_buf[pos..pos + host_bytes.len()].copy_from_slice(host_bytes);
            pos += host_bytes.len();
        }

        req_buf[pos] = (target_port >> 8) as u8;
        req_buf[pos + 1] = (target_port & 0xFF) as u8;
        pos += 2;
        stream
            .write_all(&req_buf[..pos])
            .await
            .map_err(MeowError::Io)?;

        // ── Step 4: CONNECT response ──────────────────────────────────────────
        // [0x05, rep, 0x00, atyp, bnd_addr..., bnd_port_hi, bnd_port_lo]
        let mut resp_hdr = [0u8; 4];
        stream
            .read_exact(&mut resp_hdr)
            .await
            .map_err(MeowError::Io)?;

        if resp_hdr[1] != REPLY_SUCCESS {
            return Err(MeowError::Socks5ConnectFailed(resp_hdr[1]));
        }

        // Drain the bound address (we don't use it for TCP relay).
        drain_socks5_addr(stream, resp_hdr[3]).await?;

        Ok(())
    }

    /// Method negotiation + optional RFC 1929 username/password sub-negotiation.
    /// Shared by CONNECT ([`Self::run_handshake`]) and UDP ASSOCIATE
    /// ([`Self::run_udp_associate`]).
    async fn negotiate_and_auth<S>(&self, stream: &mut S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // RFC 1929 §2 encodes username/password lengths as single bytes.
        if let Some((user, pass)) = &self.auth {
            if user.len() > 255 {
                return Err(MeowError::Proxy(format!(
                    "socks5: username too long ({} bytes, max 255 per RFC 1929)",
                    user.len()
                )));
            }
            if pass.len() > 255 {
                return Err(MeowError::Proxy(format!(
                    "socks5: password too long ({} bytes, max 255 per RFC 1929)",
                    pass.len()
                )));
            }
        }

        // ── Step 1: Method negotiation ────────────────────────────────────────
        let methods: &[u8] = if self.auth.is_some() {
            &[METHOD_NO_AUTH, METHOD_USER_PASS]
        } else {
            &[METHOD_NO_AUTH]
        };

        let greeting_len = 2 + methods.len();
        let mut greeting = [0u8; 4];
        greeting[0] = VERSION;
        greeting[1] = methods.len() as u8;
        greeting[2..greeting_len].copy_from_slice(methods);
        stream
            .write_all(&greeting[..greeting_len])
            .await
            .map_err(MeowError::Io)?;

        let mut server_choice = [0u8; 2];
        stream
            .read_exact(&mut server_choice)
            .await
            .map_err(MeowError::Io)?;

        if server_choice[0] != VERSION {
            return Err(MeowError::Proxy(format!(
                "socks5: unexpected version byte {:#04x} in method selection",
                server_choice[0]
            )));
        }

        let chosen = server_choice[1];
        if chosen == METHOD_NO_ACCEPTABLE {
            return Err(MeowError::NoAcceptableMethod);
        }

        // ── Step 2: Username/password sub-negotiation (if server chose 0x02) ──
        //
        // upstream: socks5.go::handshake — if the server picks no-auth even when
        // credentials were offered, proceed WITHOUT sub-negotiation.
        if chosen == METHOD_USER_PASS {
            let (user, pass) = self
                .auth
                .as_ref()
                .expect("auth set when METHOD_USER_PASS offered");

            let auth_len = 3 + user.len() + pass.len();
            let mut auth_buf = [0u8; 515];
            auth_buf[0] = AUTH_VERSION;
            auth_buf[1] = user.len() as u8;
            auth_buf[2..2 + user.len()].copy_from_slice(user.as_bytes());
            auth_buf[2 + user.len()] = pass.len() as u8;
            auth_buf[3 + user.len()..auth_len].copy_from_slice(pass.as_bytes());
            stream
                .write_all(&auth_buf[..auth_len])
                .await
                .map_err(MeowError::Io)?;

            let mut auth_resp = [0u8; 2];
            stream
                .read_exact(&mut auth_resp)
                .await
                .map_err(MeowError::Io)?;

            if auth_resp[1] != AUTH_SUCCESS {
                return Err(MeowError::ProxyAuthFailed);
            }
        }

        Ok(())
    }

    /// Run a UDP ASSOCIATE handshake over the (already TLS-wrapped, if
    /// configured) control stream and return the relay endpoint the proxy
    /// expects UDP datagrams on.
    ///
    /// The DST.ADDR/DST.PORT in the request is the wildcard `0.0.0.0:0`: per
    /// RFC 1928 it advertises the address the client will send from, which we
    /// don't know ahead of the first packet — `0.0.0.0:0` tells the server not
    /// to restrict the association to a specific source.
    ///
    /// A `BND.ADDR` of `0.0.0.0` / `::` (some servers return the wildcard
    /// meaning "same host as this control connection") is rewritten to the
    /// proxy server's own address.
    async fn run_udp_associate<S>(&self, stream: &mut S) -> Result<SocketAddr>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.negotiate_and_auth(stream).await?;

        // Request: VER CMD RSV ATYP(v4) 0.0.0.0 0
        let req = [
            VERSION,
            CMD_UDP_ASSOCIATE,
            RESERVED,
            ATYP_IPV4,
            0,
            0,
            0,
            0, // DST.ADDR 0.0.0.0
            0,
            0, // DST.PORT 0
        ];
        stream.write_all(&req).await.map_err(MeowError::Io)?;

        // Response header: VER REP RSV ATYP
        let mut resp_hdr = [0u8; 4];
        stream
            .read_exact(&mut resp_hdr)
            .await
            .map_err(MeowError::Io)?;
        if resp_hdr[1] != REPLY_SUCCESS {
            return Err(MeowError::Socks5ConnectFailed(resp_hdr[1]));
        }

        let relay = read_socks5_addr(stream, resp_hdr[3]).await?;
        // Rewrite a wildcard bound address to the proxy server's own address.
        if relay.ip().is_unspecified() {
            let candidates = meow_common::resolve_host_all(&self.server, relay.port())
                .await
                .map_err(MeowError::Io)?;
            return candidates.into_iter().next().ok_or_else(|| {
                MeowError::Proxy(format!("socks5: cannot resolve relay host {}", self.server))
            });
        }
        Ok(relay)
    }
}

/// Read and discard the bound address + port from a SOCKS5 response.
///
/// `atyp` is the address-type byte already read from the response header.
async fn drain_socks5_addr<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    atyp: u8,
) -> Result<()> {
    let addr_len: usize = match atyp {
        ATYP_IPV4 => 4,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(MeowError::Io)?;
            len[0] as usize
        }
        ATYP_IPV6 => 16,
        other => {
            return Err(MeowError::Proxy(format!(
                "socks5: unknown atyp {other:#04x} in response"
            )));
        }
    };
    // addr bytes + 2-byte port
    let mut discard = vec![0u8; addr_len + 2];
    stream
        .read_exact(&mut discard)
        .await
        .map_err(MeowError::Io)?;
    Ok(())
}

/// Read a SOCKS5 address (`atyp` already consumed) into a concrete
/// `SocketAddr`. A domain `atyp` is resolved via the protected resolver; this
/// is only used for the UDP-ASSOCIATE bound address, which servers normally
/// return as an IP literal.
async fn read_socks5_addr<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    atyp: u8,
) -> Result<SocketAddr> {
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await.map_err(MeowError::Io)?;
            let ip = IpAddr::from([b[0], b[1], b[2], b[3]]);
            Ok(SocketAddr::new(ip, u16::from_be_bytes([b[4], b[5]])))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await.map_err(MeowError::Io)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            Ok(SocketAddr::new(
                IpAddr::from(o),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(MeowError::Io)?;
            let mut dbuf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut dbuf).await.map_err(MeowError::Io)?;
            let host = std::str::from_utf8(&dbuf[..len[0] as usize])
                .map_err(|_| MeowError::Proxy("socks5: non-utf8 bound domain".into()))?;
            let port = u16::from_be_bytes([dbuf[len[0] as usize], dbuf[len[0] as usize + 1]]);
            meow_common::resolve_host_all(host, port)
                .await
                .map_err(MeowError::Io)?
                .into_iter()
                .next()
                .ok_or_else(|| MeowError::Proxy(format!("socks5: cannot resolve bound {host}")))
        }
        other => Err(MeowError::Proxy(format!(
            "socks5: unknown atyp {other:#04x} in response"
        ))),
    }
}

/// Encode a SOCKS5 UDP request header for `addr` into `out` (RFC 1928 §7):
/// `RSV(2)=0 FRAG(1)=0 ATYP DST.ADDR DST.PORT`. The DATA is appended by the
/// caller.
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

/// Parse a received SOCKS5 UDP datagram in place: validate the header, return
/// the source `SocketAddr`, and shift the DATA portion to the front of `buf`.
/// Returns `(data_len, src)`.
fn decode_udp_datagram(buf: &mut [u8], n: usize) -> Result<(usize, SocketAddr)> {
    if n < 4 {
        return Err(MeowError::Proxy("socks5: short UDP datagram".into()));
    }
    // RSV(2) ignored. FRAG must be 0 — we don't reassemble fragments.
    if buf[2] != 0 {
        return Err(MeowError::Proxy(
            "socks5: fragmented UDP datagram not supported".into(),
        ));
    }
    let (src, header_len) = match buf[3] {
        ATYP_IPV4 => {
            if n < 10 {
                return Err(MeowError::Proxy("socks5: truncated v4 UDP header".into()));
            }
            let ip = IpAddr::from([buf[4], buf[5], buf[6], buf[7]]);
            (
                SocketAddr::new(ip, u16::from_be_bytes([buf[8], buf[9]])),
                10,
            )
        }
        ATYP_IPV6 => {
            if n < 22 {
                return Err(MeowError::Proxy("socks5: truncated v6 UDP header".into()));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[4..20]);
            (
                SocketAddr::new(IpAddr::from(o), u16::from_be_bytes([buf[20], buf[21]])),
                22,
            )
        }
        // Domain-form source in a reply is degenerate (servers echo the IP).
        other => {
            return Err(MeowError::Proxy(format!(
                "socks5: unsupported UDP reply atyp {other:#04x}"
            )));
        }
    };
    let data_len = n - header_len;
    buf.copy_within(header_len..n, 0);
    Ok((data_len, src))
}

// ─── ProxyAdapter ─────────────────────────────────────────────────────────────

#[async_trait]
impl ProxyAdapter for Socks5Adapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Socks5
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        // UDP ASSOCIATE sends datagrams to the server-provided relay endpoint
        // over a raw socket that bypasses the TCP dialer, so it cannot ride a
        // `dialer-proxy` chain — see `dial_udp` for the enforcement.
        self.udp && !self.dialer.is_proxy()
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "socks5: CONNECT {}:{} via {}:{}",
            metadata.host, metadata.dst_port, self.server, self.port
        );

        let mut stream = self.dial_stream().await?;
        self.run_handshake(
            &mut stream,
            &metadata.host,
            metadata.dst_ip,
            metadata.dst_port,
        )
        .await?;
        Ok(Box::new(StreamConn(stream)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.udp {
            return Err(MeowError::NotSupported(
                "socks5: UDP ASSOCIATE not enabled (set `udp: true`)".into(),
            ));
        }

        // Only the TCP control connection below goes through `self.dialer`.
        // The datagram socket is bound raw and connected straight to the
        // relay endpoint the server advertises, so with a `ProxyDialer`
        // installed the UDP payload would egress from the real source path
        // while TCP rides the front proxy.  Refuse rather than leak
        // (Class A, ADR-0002).  Enforced here because the tunnel's UDP
        // dispatch calls `dial_udp` without consulting `support_udp`.
        if self.dialer.is_proxy() {
            return Err(MeowError::NotSupported(
                "socks5: UDP ASSOCIATE bypasses `dialer-proxy` (raw relay \
                 socket); refusing to leak the real source path"
                    .into(),
            ));
        }

        // The UDP association is bound to the lifetime of this TCP control
        // connection (RFC 1928 §7): the server tears the association down when
        // the control conn closes. We keep it open via `ControlGuard`.
        let mut control = self.dial_stream().await?;
        let relay = self.run_udp_associate(&mut control).await?;
        debug!(
            "socks5: UDP ASSOCIATE via {}:{} → relay {}",
            self.server, self.port, relay
        );

        let bind: SocketAddr = if relay.is_ipv4() {
            "0.0.0.0:0".parse().expect("static")
        } else {
            "[::]:0".parse().expect("static")
        };
        let socket = meow_common::bind_udp(bind).await.map_err(MeowError::Io)?;
        socket.connect(relay).await.map_err(MeowError::Io)?;

        Ok(Box::new(Socks5UdpConn {
            socket,
            _control: ControlGuard::spawn(control),
        }))
    }

    /// Run the SOCKS5 handshake over an already-established stream.
    ///
    /// The stream already terminates at this SOCKS5 server — it carries
    /// whichever outer transport the relay's preceding hop established, so
    /// the adapter's own TLS layer (when `tls: true`) still applies before
    /// the SOCKS5 negotiation.
    ///
    /// upstream: `adapter/outbound/socks5.go` — `DialContextWithDialer`
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "socks5: CONNECT (relay) {}:{} over existing stream",
            metadata.host, metadata.dst_port
        );
        let mut stream = self.wrap_tls(Box::new(stream)).await?;
        self.run_handshake(
            &mut stream,
            &metadata.host,
            metadata.dst_ip,
            metadata.dst_port,
        )
        .await?;
        Ok(Box::new(StreamConn(stream)))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ─── UDP ASSOCIATE relay conn ──────────────────────────────────────────────────

/// Keeps the SOCKS5 UDP-ASSOCIATE control connection open for the lifetime of
/// the relay. RFC 1928 §7 ties the association to the control conn, so the
/// task holds it and drains anything the server sends; dropping the guard
/// aborts the task, closing the conn and ending the association.
struct ControlGuard(tokio::task::AbortHandle);

impl ControlGuard {
    fn spawn(control: Box<dyn meow_transport::Stream>) -> Self {
        let handle = tokio::spawn(async move {
            let mut control = control;
            let mut sink = [0u8; 16];
            // Block until the proxy closes the control conn (or we're aborted).
            loop {
                match control.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {} // ignore unexpected control-channel bytes
                }
            }
        });
        ControlGuard(handle.abort_handle())
    }
}

impl Drop for ControlGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A SOCKS5 UDP-ASSOCIATE relay socket. Each datagram is wrapped/unwrapped in
/// the RFC 1928 §7 UDP request header; the socket is `connect()`ed to the
/// proxy's relay endpoint.
struct Socks5UdpConn {
    socket: UdpSocket,
    _control: ControlGuard,
}

#[async_trait]
impl ProxyPacketConn for Socks5UdpConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let n = self.socket.recv(buf).await.map_err(MeowError::Io)?;
        decode_udp_datagram(buf, n)
    }

    async fn write_packet(&self, data: &[u8], addr: &SocketAddr) -> Result<usize> {
        let mut pkt: SmallVec<[u8; 1500]> = SmallVec::new();
        encode_udp_header(&mut pkt, addr);
        pkt.extend_from_slice(data);
        self.socket.send(&pkt).await.map_err(MeowError::Io)?;
        Ok(data.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(MeowError::Io)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use meow_common::MeowError;

    // ─── Mock SOCKS5 server ───────────────────────────────────────────────────

    enum AuthMode {
        NoAuth,
        UserPass {
            user: &'static str,
            pass: &'static str,
        },
        ForceNoAuth, // advertise only 0x00 even when client offers 0x02
        NoAcceptable,
    }

    enum ConnectResult {
        Success,
        Fail(u8),
    }

    struct MockServer {
        auth_mode: AuthMode,
        connect_result: ConnectResult,
    }

    impl MockServer {
        fn new_no_auth() -> Self {
            Self {
                auth_mode: AuthMode::NoAuth,
                connect_result: ConnectResult::Success,
            }
        }
        fn new_user_pass(user: &'static str, pass: &'static str) -> Self {
            Self {
                auth_mode: AuthMode::UserPass { user, pass },
                connect_result: ConnectResult::Success,
            }
        }
        fn new_no_acceptable() -> Self {
            Self {
                auth_mode: AuthMode::NoAcceptable,
                connect_result: ConnectResult::Success,
            }
        }
        fn new_force_no_auth() -> Self {
            Self {
                auth_mode: AuthMode::ForceNoAuth,
                connect_result: ConnectResult::Success,
            }
        }
        fn with_connect_fail(mut self, rep: u8) -> Self {
            self.connect_result = ConnectResult::Fail(rep);
            self
        }

        async fn spawn(self) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let handle = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut captured_req = Vec::new();

                // Method negotiation
                let mut hdr = [0u8; 2];
                s.read_exact(&mut hdr).await.unwrap();
                let n_methods = hdr[1] as usize;
                let mut methods = vec![0u8; n_methods];
                s.read_exact(&mut methods).await.unwrap();
                captured_req.extend_from_slice(&hdr);
                captured_req.extend_from_slice(&methods);

                let chosen = match &self.auth_mode {
                    AuthMode::NoAuth | AuthMode::ForceNoAuth => METHOD_NO_AUTH,
                    AuthMode::UserPass { .. } => METHOD_USER_PASS,
                    AuthMode::NoAcceptable => METHOD_NO_ACCEPTABLE,
                };
                s.write_all(&[VERSION, chosen]).await.unwrap();

                if chosen == METHOD_NO_ACCEPTABLE {
                    return captured_req;
                }

                // Sub-negotiation (if chosen = 0x02)
                if chosen == METHOD_USER_PASS {
                    let mut auth_hdr = [0u8; 2];
                    s.read_exact(&mut auth_hdr).await.unwrap();
                    let ulen = auth_hdr[1] as usize;
                    let mut user_bytes = vec![0u8; ulen];
                    s.read_exact(&mut user_bytes).await.unwrap();
                    let mut plen_buf = [0u8; 1];
                    s.read_exact(&mut plen_buf).await.unwrap();
                    let plen = plen_buf[0] as usize;
                    let mut pass_bytes = vec![0u8; plen];
                    s.read_exact(&mut pass_bytes).await.unwrap();

                    let ok = match &self.auth_mode {
                        AuthMode::UserPass { user, pass } => {
                            user_bytes == user.as_bytes() && pass_bytes == pass.as_bytes()
                        }
                        _ => false,
                    };
                    let status = if ok { AUTH_SUCCESS } else { 0x01u8 };
                    s.write_all(&[AUTH_VERSION, status]).await.unwrap();
                    if !ok {
                        return captured_req;
                    }
                }

                // CONNECT request
                let mut req_hdr = [0u8; 4];
                s.read_exact(&mut req_hdr).await.unwrap();
                captured_req.extend_from_slice(&req_hdr);
                let atyp = req_hdr[3];
                let addr_len = match atyp {
                    ATYP_IPV4 => 4,
                    ATYP_DOMAIN => {
                        let mut l = [0u8; 1];
                        s.read_exact(&mut l).await.unwrap();
                        captured_req.push(l[0]);
                        l[0] as usize
                    }
                    ATYP_IPV6 => 16,
                    _ => 0,
                };
                let mut addr_port = vec![0u8; addr_len + 2];
                s.read_exact(&mut addr_port).await.unwrap();
                captured_req.extend_from_slice(&addr_port);

                // Reply
                let rep = match &self.connect_result {
                    ConnectResult::Success => REPLY_SUCCESS,
                    ConnectResult::Fail(r) => *r,
                };
                // Bound addr: IPv4 0.0.0.0:0
                s.write_all(&[VERSION, rep, RESERVED, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();

                if rep == REPLY_SUCCESS {
                    // Echo payload
                    let mut buf = [0u8; 256];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = s.write_all(&buf[..n]).await;
                            }
                        }
                    }
                }

                captured_req
            });

            (addr, handle)
        }
    }

    fn make_adapter(server: &str, port: u16, auth: Option<(String, String)>) -> Socks5Adapter {
        Socks5Adapter::new(
            server,
            server,
            port,
            auth,
            false,
            false,
            Arc::new(crate::dialer::DirectDialer),
        )
    }

    /// Reports itself as proxied without needing a real front proxy.
    struct FakeProxyDialer;

    #[async_trait]
    impl crate::dialer::TcpDialer for FakeProxyDialer {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
        ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
            Err(std::io::Error::other("test dialer never connects"))
        }

        fn is_proxy(&self) -> bool {
            true
        }
    }

    /// Regression: only the TCP control connection follows the dialer. The
    /// datagram socket is bound raw and connected to the server-advertised
    /// relay, so under a proxy dialer the association must be refused rather
    /// than egressing from the real source path.
    ///
    /// Enforced in `dial_udp` because the tunnel's UDP dispatch calls it
    /// directly without consulting `support_udp()`.
    #[tokio::test]
    async fn udp_associate_is_refused_under_proxy_dialer() {
        let adapter = Socks5Adapter::new(
            "front",
            "127.0.0.1",
            1080,
            None,
            false,
            false,
            Arc::new(FakeProxyDialer),
        )
        .with_udp(true);

        // `ProxyPacketConn` is not `Debug`, so match rather than `expect_err`.
        match adapter.dial_udp(&meta_with_host("example.com", 443)).await {
            Err(MeowError::NotSupported(m)) => assert!(
                m.contains("dialer-proxy"),
                "refusal should name dialer-proxy, got: {m}"
            ),
            Err(other) => panic!("expected NotSupported, got: {other:?}"),
            Ok(_) => panic!("UDP ASSOCIATE must be refused under a proxy dialer"),
        }

        assert!(
            !adapter.support_udp(),
            "advertised capability must agree with the refusal"
        );
    }

    #[test]
    fn udp_still_advertised_under_direct_dialer() {
        assert!(make_adapter("127.0.0.1", 1080, None)
            .with_udp(true)
            .support_udp());
    }

    fn meta_with_host(host: &str, port: u16) -> Metadata {
        Metadata {
            host: host.into(),
            dst_port: port,
            ..Default::default()
        }
    }

    fn meta_with_ipv4(ip: Ipv4Addr, port: u16) -> Metadata {
        Metadata {
            dst_ip: Some(IpAddr::V4(ip)),
            dst_port: port,
            ..Default::default()
        }
    }

    // ─── socks5_no_auth_connects ──────────────────────────────────────────────
    // upstream: adapter/outbound/socks5.go::DialContext

    #[tokio::test]
    async fn socks5_no_auth_connects() {
        let (addr, _) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let meta = meta_with_host("example.com", 443);
        adapter
            .dial_tcp(&meta)
            .await
            .expect("socks5 no-auth connect");
    }

    // ─── socks5_user_pass_auth_succeeds ───────────────────────────────────────

    #[tokio::test]
    async fn socks5_user_pass_auth_succeeds() {
        let (addr, _) = MockServer::new_user_pass("bob", "hunter2").spawn().await;
        let adapter = make_adapter(
            "127.0.0.1",
            addr.port(),
            Some(("bob".into(), "hunter2".into())),
        );
        let meta = meta_with_host("example.com", 443);
        adapter
            .dial_tcp(&meta)
            .await
            .expect("socks5 user-pass auth");
    }

    // ─── socks5_no_acceptable_method_returns_error ────────────────────────────
    // NOT retry. NOT fallback to no-auth.

    #[tokio::test]
    async fn socks5_no_acceptable_method_returns_error() {
        let (addr, _) = MockServer::new_no_acceptable().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MeowError::NoAcceptableMethod),
            "0xFF must map to NoAcceptableMethod; got {err:?}"
        );
    }

    // ─── socks5_server_chooses_no_auth_despite_creds_configured ──────────────
    // Server may prefer no-auth even when client offers user/pass.
    // NOT Err(NoAcceptableMethod). NOT sending auth sub-negotiation.
    // upstream: socks5.go::handshake

    #[tokio::test]
    async fn socks5_server_chooses_no_auth_despite_creds_configured() {
        let (addr, _) = MockServer::new_force_no_auth().spawn().await;
        let adapter = make_adapter(
            "127.0.0.1",
            addr.port(),
            Some(("bob".into(), "hunter2".into())),
        );
        let meta = meta_with_host("example.com", 443);
        // Must succeed — server chose no-auth, skip sub-negotiation.
        adapter
            .dial_tcp(&meta)
            .await
            .expect("server chose no-auth despite creds configured");
    }

    // ─── socks5_auth_failure_returns_proxy_auth_failed ────────────────────────

    #[tokio::test]
    async fn socks5_auth_failure_returns_proxy_auth_failed() {
        // Server expects different credentials → auth status != 0x00.
        let (addr, _) = MockServer::new_user_pass("correct", "correct")
            .spawn()
            .await;
        let adapter = make_adapter(
            "127.0.0.1",
            addr.port(),
            Some(("wrong".into(), "wrong".into())),
        );
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MeowError::ProxyAuthFailed),
            "auth failure must map to ProxyAuthFailed; got {err:?}"
        );
    }

    // ─── socks5_connect_failure_returns_socks5_connect_failed ────────────────
    // rep=0x02 = CONN_NOT_ALLOWED

    #[tokio::test]
    async fn socks5_connect_failure_returns_socks5_connect_failed() {
        let (addr, _) = MockServer::new_no_auth()
            .with_connect_fail(0x02)
            .spawn()
            .await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MeowError::Socks5ConnectFailed(0x02)),
            "rep=0x02 must map to Socks5ConnectFailed(0x02); got {err:?}"
        );
    }

    // ─── socks5_domain_name_preferred_over_ip ────────────────────────────────
    // metadata has both host and dst_ip; assert wire frame uses atyp 0x03 (domain).
    // NOT atyp 0x01 (IPv4) when domain is available.

    #[tokio::test]
    async fn socks5_domain_name_preferred_over_ip() {
        let (addr, handle) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);

        // Metadata has BOTH host and dst_ip.
        let meta = Metadata {
            host: "example.com".into(),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            dst_port: 80,
            ..Default::default()
        };
        adapter.dial_tcp(&meta).await.expect("dial_tcp");

        let captured = handle.await.unwrap();
        // captured_req layout:
        //   [0] = 0x05 (VERSION from greeting)  [1] = n_methods  [2..] = methods
        //   then CONNECT: [0]=VER [1]=CMD [2]=RSV [3]=ATYP ...
        // The CONNECT header starts at offset 2 + n_methods.
        let n_methods = captured[1] as usize;
        let connect_start = 2 + n_methods;
        let atyp = captured[connect_start + 3];
        assert_eq!(
            atyp, ATYP_DOMAIN,
            "atyp must be 0x03 (domain) when metadata.host is set; got {atyp:#04x}"
        );
    }

    // ─── socks5_ipv4_used_when_no_hostname ────────────────────────────────────
    // metadata has dst_ip only; assert atyp 0x01 frame.

    #[tokio::test]
    async fn socks5_ipv4_used_when_no_hostname() {
        let (addr, handle) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let meta = meta_with_ipv4(Ipv4Addr::new(10, 0, 0, 1), 8080);
        adapter.dial_tcp(&meta).await.expect("dial_tcp");

        let captured = handle.await.unwrap();
        let n_methods = captured[1] as usize;
        let connect_start = 2 + n_methods;
        let atyp = captured[connect_start + 3];
        assert_eq!(
            atyp, ATYP_IPV4,
            "atyp must be 0x01 (IPv4) when only dst_ip is set; got {atyp:#04x}"
        );
    }

    // ─── socks5_hostname_too_long_returns_error ───────────────────────────────
    // Pre-VLESS hardening (M1.B-4): hostname > 255 bytes → Proxy error.
    // NOT silently truncated. NOT protocol frame sent.
    // ADR-0002 Class A divergence from upstream socks5.go.

    #[tokio::test]
    async fn socks5_hostname_too_long_returns_error() {
        let (addr, _) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let long_host = "a".repeat(256); // 256 bytes > 255 limit
        let meta = meta_with_host(&long_host, 80);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MeowError::Proxy(ref msg) if msg.contains("hostname too long")),
            "hostname > 255 bytes must return Proxy error; got {err:?}"
        );
    }

    // ─── socks5_auth_username_too_long_returns_error ──────────────────────────
    // RFC 1929 §2: username length field is 1 byte (max 255).
    // NOT silently truncated.

    #[tokio::test]
    async fn socks5_auth_username_too_long_returns_error() {
        let (addr, _) = MockServer::new_user_pass("ignored", "ignored")
            .spawn()
            .await;
        let long_user = "u".repeat(256);
        let adapter = make_adapter("127.0.0.1", addr.port(), Some((long_user, "pass".into())));
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MeowError::Proxy(ref msg) if msg.contains("username too long")),
            "username > 255 bytes must return Proxy error; got {err:?}"
        );
    }

    // ─── socks5_auth_password_too_long_returns_error ──────────────────────────
    // RFC 1929 §2: password length field is 1 byte (max 255).
    // NOT silently truncated.

    #[tokio::test]
    async fn socks5_auth_password_too_long_returns_error() {
        let (addr, _) = MockServer::new_user_pass("ignored", "ignored")
            .spawn()
            .await;
        let long_pass = "p".repeat(256);
        let adapter = make_adapter("127.0.0.1", addr.port(), Some(("user".into(), long_pass)));
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MeowError::Proxy(ref msg) if msg.contains("password too long")),
            "password > 255 bytes must return Proxy error; got {err:?}"
        );
    }

    // ─── UDP ASSOCIATE: disabled by default ────────────────────────────────────

    #[tokio::test]
    async fn socks5_udp_disabled_by_default() {
        let adapter = make_adapter("127.0.0.1", 1080, None);
        assert!(
            !adapter.support_udp(),
            "udp must be off unless with_udp(true)"
        );
        let meta = meta_with_host("example.com", 53);
        let err = adapter
            .dial_udp(&meta)
            .await
            .err()
            .expect("dial_udp should return Err when udp disabled");
        assert!(
            matches!(err, MeowError::NotSupported(_)),
            "dial_udp must return NotSupported when disabled; got {err:?}"
        );
    }

    #[test]
    fn with_udp_toggles_support() {
        let off = make_adapter("127.0.0.1", 1080, None);
        assert!(!off.support_udp());
        let on = make_adapter("127.0.0.1", 1080, None).with_udp(true);
        assert!(on.support_udp());
    }

    // ─── UDP datagram header codec (RFC 1928 §7) ───────────────────────────────

    #[test]
    fn udp_header_roundtrip_v4_and_v6() {
        for target in [
            "1.2.3.4:443".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
        ] {
            let mut pkt: SmallVec<[u8; 1500]> = SmallVec::new();
            encode_udp_header(&mut pkt, &target);
            pkt.extend_from_slice(b"payload");
            // Datagram is RSV(2)=0 FRAG(1)=0 then atyp/addr/port/data.
            assert_eq!(&pkt[0..3], &[0, 0, 0]);

            let mut buf = pkt.to_vec();
            let n = buf.len();
            let (data_len, src) = decode_udp_datagram(&mut buf, n).unwrap();
            assert_eq!(src, target);
            assert_eq!(&buf[..data_len], b"payload");
        }
    }

    #[test]
    fn udp_decode_rejects_fragments_and_short() {
        // FRAG != 0 → unsupported.
        let mut frag = vec![0, 0, 1, ATYP_IPV4, 1, 2, 3, 4, 0, 80];
        let n = frag.len();
        assert!(decode_udp_datagram(&mut frag, n).is_err());
        // Too short for even the fixed header.
        let mut short = vec![0, 0];
        assert!(decode_udp_datagram(&mut short, 2).is_err());
    }

    // ─── UDP ASSOCIATE end-to-end against a mock relay ─────────────────────────

    #[tokio::test]
    async fn socks5_udp_associate_round_trip() {
        use tokio::net::UdpSocket;
        use tokio::time::{timeout, Duration};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctrl_addr = listener.local_addr().unwrap();

        // Mock SOCKS5 server: no-auth negotiation, UDP ASSOCIATE, then a UDP
        // relay that echoes each datagram verbatim (header + data) back to the
        // client — standing in for a remote that echoes.
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Method negotiation.
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[VERSION, METHOD_NO_AUTH]).await.unwrap();
            // UDP ASSOCIATE request: VER CMD RSV ATYP(v4) addr(4) port(2).
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req[1], CMD_UDP_ASSOCIATE);

            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let rport = relay.local_addr().unwrap().port();
            s.write_all(&[
                VERSION,
                REPLY_SUCCESS,
                RESERVED,
                ATYP_IPV4,
                127,
                0,
                0,
                1,
                (rport >> 8) as u8,
                (rport & 0xFF) as u8,
            ])
            .await
            .unwrap();

            // Echo loop. Hold `s` (control conn) alive by keeping it in scope.
            let mut buf = [0u8; 2048];
            loop {
                let (n, peer) = relay.recv_from(&mut buf).await.unwrap();
                relay.send_to(&buf[..n], peer).await.unwrap();
            }
        });

        let adapter = make_adapter("127.0.0.1", ctrl_addr.port(), None).with_udp(true);
        assert!(adapter.support_udp());
        let conn = adapter
            .dial_udp(&Metadata::default())
            .await
            .expect("dial_udp");

        let target: SocketAddr = "1.2.3.4:443".parse().unwrap();
        conn.write_packet(b"quic-hello", &target)
            .await
            .expect("write_packet");

        let mut buf = [0u8; 256];
        let (n, src) = timeout(Duration::from_secs(2), conn.read_packet(&mut buf))
            .await
            .expect("read timed out")
            .expect("read_packet");
        assert_eq!(&buf[..n], b"quic-hello");
        assert_eq!(src, target, "decoded source must be the datagram target");
    }

    // ─── socks5_connect_over_relay ────────────────────────────────────────────
    // Pass mock ProxyConn stream; assert handshake runs over it.
    // NOT fresh TCP connect.

    #[tokio::test]
    async fn socks5_connect_over_relay() {
        let (addr, _) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);

        // Establish the "outer" connection.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let outer: Box<dyn ProxyConn> = Box::new(tcp);

        let meta = meta_with_host("example.com", 443);
        let mut conn = adapter
            .connect_over(outer, &meta)
            .await
            .expect("connect_over");

        // Tunnel is live — echo works.
        conn.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
    }
}
