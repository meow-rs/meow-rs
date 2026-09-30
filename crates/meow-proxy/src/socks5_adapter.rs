//! SOCKS5 outbound proxy adapter (M1.B-4).
//!
//! Implements `ProxyAdapter` for `type: socks5` config entries.  Supports:
//! - Auth method negotiation: no-auth (0x00) and username/password (0x02).
//! - `CMD CONNECT` (0x01) — TCP tunnel.
//! - `atyp` 0x03 (domain) preferred when `metadata.host` is set;
//!   0x01 (IPv4) or 0x04 (IPv6) otherwise.
//! - Optional TLS-wrapping of the TCP control connection to the proxy server.
//! - `CMD UDP ASSOCIATE` (0x03) when `udp: true` — relays UDP (incl. QUIC /
//!   HTTP/3) via a side UDP transport, wrapping each datagram in the RFC 1928
//!   §7 header. The TCP control connection is held open for the association's
//!   lifetime. The UDP relay path is plain (not TLS-wrapped), per the SOCKS5
//!   spec. Under `dialer-proxy` the relay datagrams ride the front proxy's
//!   own `dial_udp` association to the advertised relay endpoint (mihomo
//!   `proxyDialer.ListenPacket`); a UDP-less front fails closed.
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

use crate::dialer::UdpTarget;
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
/// ATYP_DOMAIN carries a one-byte length — a longer name cannot ride the
/// wire and the requester falls back to a literal resolution.
const MAX_DOMAIN_LEN: usize = u8::MAX as usize;

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
    async fn dial_stream(&self, internal: bool) -> Result<Box<dyn meow_transport::Stream>> {
        let tcp = self
            .dialer
            .dial(&self.server, self.port, internal)
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
                .map_err(|e| match e {
                    meow_transport::TransportError::Io(e) => MeowError::Io(e),
                    other => MeowError::Proxy(other.to_string()),
                })
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
    /// meaning "same host as this control connection") comes back as
    /// [`RelayAddr::Server`]; a domain BND stays a name. The caller picks
    /// the resolution side — local for the raw path, the front's resolver
    /// view via [`UdpTarget::Name`] under `dialer-proxy`.
    async fn run_udp_associate<S>(&self, stream: &mut S) -> Result<RelayAddr>
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

        let relay = read_relay_addr(stream, resp_hdr[3]).await?;
        // A zero BND port is not a usable relay endpoint (mihomo rejects it
        // as a malformed server address) — refuse rather than blackhole.
        let port = match &relay {
            RelayAddr::Addr(a) => a.port(),
            RelayAddr::Server { port, .. } | RelayAddr::Domain { port, .. } => *port,
        };
        if port == 0 {
            return Err(MeowError::Proxy(format!(
                "socks5: server advertised unusable relay {relay:?}"
            )));
        }
        Ok(relay)
    }

    /// Resolve a [`RelayAddr`] to a concrete `SocketAddr` locally — the raw
    /// (unchained) path, and the chained fallback when the front cannot
    /// carry a domain target.
    ///
    /// A wildcard BND prefers a candidate in the wildcard's own family:
    /// `0.0.0.0` means "same host, on this v4 socket" — a dual-stack
    /// hostname must not substitute a v6 address the relay never bound
    /// (mihomo resolves with the node's IPv4-prefer for the same reason).
    async fn resolve_relay(&self, relay: &RelayAddr) -> Result<SocketAddr> {
        match relay {
            RelayAddr::Addr(addr) => Ok(*addr),
            RelayAddr::Server { port, v6 } => {
                let candidates = meow_common::resolve_host_all(&self.server, *port)
                    .await
                    .map_err(MeowError::Io)?;
                candidates
                    .iter()
                    .find(|c| c.is_ipv6() == *v6)
                    .or_else(|| candidates.first())
                    .copied()
                    .ok_or_else(|| {
                        MeowError::Proxy(format!(
                            "socks5: cannot resolve relay host {}",
                            self.server
                        ))
                    })
            }
            RelayAddr::Domain { host, port } => meow_common::resolve_host_all(host, *port)
                .await
                .map_err(MeowError::Io)?
                .into_iter()
                .next()
                .ok_or_else(|| MeowError::Proxy(format!("socks5: cannot resolve bound {host}"))),
        }
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

/// Where the SOCKS5 server said its UDP relay lives — the `BND` of a
/// UDP-ASSOCIATE reply, kept in its wire form so a `dialer-proxy` front can
/// resolve a name with its own view instead of ours (issue #657).
#[derive(Debug)]
enum RelayAddr {
    /// Literal IP endpoint.
    Addr(SocketAddr),
    /// Domain endpoint — the server named its relay by domain.
    Domain { host: smol_str::SmolStr, port: u16 },
    /// Wildcard BND (`0.0.0.0`/`::`): "same host as this control
    /// connection". `v6` remembers the wildcard's address family so a
    /// local resolution can prefer it; when the endpoint is delegated to a
    /// front as `UdpTarget::Name` the hint is lost and the front's resolver
    /// picks the family — a narrow divergence accepted for issue #657.
    Server { port: u16, v6: bool },
}

impl RelayAddr {
    /// The [`UdpTarget`] this endpoint dials under `dialer-proxy`:
    /// literals pass through, while wildcard/domain forms hand the name to
    /// the front so *its* resolver picks the backend the control leg used.
    /// A "name" that is actually an IP literal collapses to [`UdpTarget::Addr`]
    /// — the stricter source filter stays available and no resolution is
    /// needed anywhere.
    fn to_udp_target(&self, server: &str) -> UdpTarget {
        match self {
            RelayAddr::Addr(addr) => UdpTarget::Addr(*addr),
            RelayAddr::Server { port, .. } => UdpTarget::named(server, *port),
            RelayAddr::Domain { host, port } => UdpTarget::named(host, *port),
        }
    }
}

/// Read a SOCKS5 address (`atyp` already consumed) into its wire form —
/// domain `atyp` is *kept as a name*; resolution is the caller's choice
/// (local for the raw path, delegated to the front under `dialer-proxy`).
async fn read_relay_addr<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    atyp: u8,
) -> Result<RelayAddr> {
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await.map_err(MeowError::Io)?;
            let ip = IpAddr::from([b[0], b[1], b[2], b[3]]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            if ip.is_unspecified() {
                return Ok(RelayAddr::Server { port, v6: false });
            }
            Ok(RelayAddr::Addr(SocketAddr::new(ip, port)))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await.map_err(MeowError::Io)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            let ip = IpAddr::from(o);
            let port = u16::from_be_bytes([b[16], b[17]]);
            if ip.is_unspecified() {
                return Ok(RelayAddr::Server { port, v6: true });
            }
            Ok(RelayAddr::Addr(SocketAddr::new(ip, port)))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(MeowError::Io)?;
            // A zero-length name cannot name a relay — treat it as a
            // malformed reply rather than binding a degenerate association.
            if len[0] == 0 {
                return Err(MeowError::Proxy(
                    "socks5: empty domain in UDP associate reply".into(),
                ));
            }
            let mut dbuf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut dbuf).await.map_err(MeowError::Io)?;
            let host = std::str::from_utf8(&dbuf[..len[0] as usize])
                .map_err(|_| MeowError::Proxy("socks5: non-utf8 bound domain".into()))?;
            let port = u16::from_be_bytes([dbuf[len[0] as usize], dbuf[len[0] as usize + 1]]);
            Ok(RelayAddr::Domain {
                host: smol_str::SmolStr::new(host),
                port,
            })
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

/// Same header for a domain destination — the association's bound name
/// when this adapter fronts a chained UDP request (issue #657). The
/// server resolves `host` with its own view; `host.len()` was validated
/// against `MAX_DOMAIN_LEN` at dial time.
fn encode_udp_header_domain(out: &mut SmallVec<[u8; 1500]>, host: &str, port: u16) {
    out.extend_from_slice(&[0, 0, 0]); // RSV(2) + FRAG(1)
    out.push(ATYP_DOMAIN);
    out.push(u8::try_from(host.len()).expect("domain length validated at dial"));
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
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
        // The UDP-ASSOCIATE datagrams ride the front proxy's own `dial_udp`
        // under `dialer-proxy` (mihomo `proxyDialer.ListenPacket`), so a
        // proxy dialer is fine *when the front advertises UDP* — a
        // point-in-time snapshot for group fronts; `dial_udp` re-checks at
        // dial time and fails closed on a front that cannot carry UDP.
        //
        // Two consumers read this advertisement: the rule probe treats a
        // UDP flow matched to a `!support_udp` target as ineligible and
        // skips to the next rule (tunnel.rs `RouteTargetProbe`), and
        // LoadBalance filters members by it.  It is NOT the enforcement
        // point — `dial_udp` refuses on its own, so a stale optimistic
        // snapshot cannot open a raw socket.
        self.udp && (!self.dialer.is_proxy() || self.dialer.supports_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "socks5: CONNECT {}:{} via {}:{}",
            metadata.host, metadata.dst_port, self.server, self.port
        );

        let mut stream = self.dial_stream(metadata.is_internal()).await?;
        self.run_handshake(
            &mut stream,
            &metadata.host,
            metadata.dst_ip,
            metadata.dst_port,
        )
        .await?;
        Ok(Box::new(StreamConn(stream)))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.udp {
            return Err(MeowError::NotSupported(
                "socks5: UDP ASSOCIATE not enabled (set `udp: true`)".into(),
            ));
        }

        // Fail-closed (Class A, ADR-0002): a front that cannot carry UDP
        // refuses here — *before* the control connection is spent — with
        // `NotSupported`, the capability-refusal class exempt from group
        // dead-marking.  The raw-socket path below stays unreachable under
        // `dialer-proxy`: no silent real-source egress.  Enforced here
        // because the tunnel's UDP dispatch calls `dial_udp` without
        // consulting `support_udp`.
        if self.dialer.is_proxy() && !self.dialer.supports_udp() {
            return Err(MeowError::NotSupported(format!(
                "socks5: `dialer-proxy` front cannot carry UDP (unsupported \
                 or unresolvable); refusing to leak the real source path ({})",
                self.addr_str
            )));
        }

        // This adapter as a *front*: a host-only UDP destination (set by
        // the dialer layer for a chained `UdpTarget::Name`, issue #657)
        // binds the association to the name — every datagram's SOCKS5 DST
        // field carries the domain, and the server resolves it with its
        // own view. The write arg becomes advisory.
        let write_target = match metadata.domain_udp_target() {
            Some((host, port)) if host.len() <= MAX_DOMAIN_LEN => Some((host.clone(), port)),
            Some(_) => {
                return Err(MeowError::NotSupported(
                    "socks5: domain UDP target exceeds ATYP_DOMAIN length".into(),
                ))
            }
            None => None,
        };

        // The UDP association is bound to the lifetime of this TCP control
        // connection (RFC 1928 §7): the server tears the association down when
        // the control conn closes. We keep it open via `ControlGuard`.
        let mut control = self.dial_stream(metadata.is_internal()).await?;
        let relay = self.run_udp_associate(&mut control).await?;
        debug!(
            "socks5: UDP ASSOCIATE via {}:{} → relay {:?}",
            self.server, self.port, relay
        );

        // mihomo `proxyDialer.ListenPacket`: under `dialer-proxy` the relay
        // datagrams ride the front proxy's own `dial_udp` association bound
        // to the advertised relay endpoint — the SOCKS5 UDP header still
        // wraps the per-packet destinations, the front only sees `relay`.
        // Wildcard/domain BND forms dial as `UdpTarget::Name` so the front
        // resolves them itself; a front that cannot carry a domain refuses
        // with `Unsupported` and we fall back to a local resolution —
        // the pre-#657 behavior, still fail-closed.
        if self.dialer.is_proxy() {
            let target = relay.to_udp_target(&self.server);
            let internal = metadata.is_internal();
            // The dialer maps front `NotSupported`/`UdpNotSupported` to
            // `ErrorKind::Unsupported` — a capability refusal, not a
            // transport failure: keep the class so the node is not
            // dead-marked over a UDP-less front.
            let map_err = |target: &UdpTarget, e: std::io::Error| {
                if e.kind() == std::io::ErrorKind::Unsupported {
                    MeowError::NotSupported(format!("socks5 udp via dialer-proxy {target}: {e}"))
                } else {
                    MeowError::Io(e)
                }
            };
            let (conn, bound) = match self.dialer.dial_udp_conn(target.clone(), internal).await {
                Ok(conn) => (conn, target),
                Err(e)
                    if e.kind() == std::io::ErrorKind::Unsupported
                        && matches!(target, UdpTarget::Name { .. }) =>
                {
                    // The front cannot carry a domain target — resolve
                    // locally and redial the literal (pre-#657 behavior,
                    // still fail-closed through the same chain).
                    let addr = self.resolve_relay(&relay).await?;
                    match self
                        .dialer
                        .dial_udp_conn(UdpTarget::Addr(addr), internal)
                        .await
                    {
                        Ok(conn) => (conn, UdpTarget::Addr(addr)),
                        Err(e) => return Err(map_err(&UdpTarget::Addr(addr), e)),
                    }
                }
                Err(e) => return Err(map_err(&target, e)),
            };
            debug!("socks5: UDP chained to relay {bound} via {}", self.addr_str);
            return Ok(Box::new(Socks5UdpConn {
                transport: Socks5UdpTransport::Chained(conn),
                relay: bound,
                write_target,
                _control: ControlGuard::spawn(control),
            }));
        }

        let relay_addr = self.resolve_relay(&relay).await?;
        let bind: SocketAddr = if relay_addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("static")
        } else {
            "[::]:0".parse().expect("static")
        };
        let socket = meow_common::bind_udp(bind).await.map_err(MeowError::Io)?;
        socket.connect(relay_addr).await.map_err(MeowError::Io)?;

        Ok(Box::new(Socks5UdpConn {
            transport: Socks5UdpTransport::Raw(socket),
            relay: UdpTarget::Addr(relay_addr),
            write_target,
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
/// the RFC 1928 §7 UDP request header; the transport is `connect()`ed to the
/// proxy's relay endpoint — a raw socket directly, or the front proxy's own
/// `dial_udp` association under `dialer-proxy`.
enum Socks5UdpTransport {
    Raw(UdpSocket),
    Chained(Arc<dyn ProxyPacketConn>),
}

struct Socks5UdpConn {
    transport: Socks5UdpTransport,
    /// The advertised relay endpoint: chained datagrams are written to it
    /// and chained reads are filtered against it (connected-socket parity).
    /// A [`UdpTarget::Name`] is bound by the front — reads then match on
    /// port only, since the wire source legitimately differs from any
    /// local resolution of the name (issue #657).
    relay: UdpTarget,
    /// Set when this adapter fronts a domain-carrying association request:
    /// every datagram's SOCKS5 DST field stamps the name instead of the
    /// caller's addr arg.
    write_target: Option<(SmolStr, u16)>,
    _control: ControlGuard,
}

#[async_trait]
impl ProxyPacketConn for Socks5UdpConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        // A malformed relay datagram is per-datagram: it is already
        // consumed from the transport, so skip it instead of letting one
        // junk packet kill the whole association (mihomo propagates the
        // decode error and tears the session down; dropping is strictly
        // more resilient and matches this crate's SS arm).
        loop {
            let n = match &self.transport {
                Socks5UdpTransport::Raw(socket) => socket.recv(buf).await.map_err(MeowError::Io)?,
                Socks5UdpTransport::Chained(conn) => {
                    let (rn, outer_src) = conn.read_packet(buf).await?;
                    // Per-packet fronts report the real wire source and can
                    // deliver datagrams from arbitrary remotes — restore the
                    // connected-socket filter the Raw arm has.  Bound conns
                    // report `relay` or an unspecified addr (no source info);
                    // unspecified skips the check rather than breaking them.
                    // A `Name` relay was resolved by the front: only the port
                    // is comparable, since the wire source legitimately
                    // differs from any local resolution.
                    if !self.relay.src_matches(outer_src)
                        && !outer_src.ip().to_canonical().is_unspecified()
                    {
                        debug!(
                            "socks5 udp: dropped chained datagram from {outer_src} (expected {})",
                            self.relay
                        );
                        continue;
                    }
                    rn
                }
            };
            match decode_udp_datagram(buf, n) {
                Ok(ok) => return Ok(ok),
                Err(e) => debug!("socks5 udp: dropping malformed relay datagram: {e}"),
            }
        }
    }

    async fn write_packet(&self, data: &[u8], addr: &SocketAddr) -> Result<usize> {
        let mut pkt: SmallVec<[u8; 1500]> = SmallVec::new();
        if let Some((host, port)) = &self.write_target {
            encode_udp_header_domain(&mut pkt, host, *port);
        } else {
            encode_udp_header(&mut pkt, addr);
        }
        pkt.extend_from_slice(data);
        match &self.transport {
            Socks5UdpTransport::Raw(socket) => {
                socket.send(&pkt).await.map_err(MeowError::Io)?;
            }
            Socks5UdpTransport::Chained(conn) => {
                // The wire destination is always the relay endpoint — the
                // caller's `addr` already went inside the SOCKS5 header.
                // For a `Name` relay the write dst is an advisory
                // placeholder; the name-bound conn stamps its own target.
                // Reject frames a stream-framed front could not carry
                // (u16 length prefix) and verify datagram atomicity.
                if pkt.len() > u16::MAX as usize {
                    return Err(MeowError::Proxy(format!(
                        "socks5 udp: {}B datagram exceeds the u16 frame limit",
                        pkt.len()
                    )));
                }
                let n = conn.write_packet(&pkt, &self.relay.write_dst()).await?;
                if n != pkt.len() {
                    return Err(MeowError::Proxy(format!(
                        "socks5 udp: short write on chained conn ({n} < {})",
                        pkt.len()
                    )));
                }
            }
        }
        Ok(data.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        match &self.transport {
            Socks5UdpTransport::Raw(socket) => socket.local_addr().map_err(MeowError::Io),
            Socks5UdpTransport::Chained(conn) => conn.local_addr(),
        }
    }

    fn close(&self) -> Result<()> {
        // Closing the control conn ends the association server-side
        // (RFC 1928 §7) — mihomo's `packetConn.Close()` does the same.
        self._control.0.abort();
        match &self.transport {
            Socks5UdpTransport::Chained(conn) => conn.close(),
            Socks5UdpTransport::Raw(_) => Ok(()),
        }
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

    /// "command not supported" — only the refusal test needs it.
    const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

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
            _internal: bool,
        ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
            Err(std::io::Error::other("test dialer never connects"))
        }

        fn is_proxy(&self) -> bool {
            true
        }
    }

    /// Fail-closed under `dialer-proxy`: a front that cannot carry UDP must
    /// refuse the association — `NotSupported`, the capability-refusal class
    /// exempt from group dead-marking — rather than egressing the relay
    /// datagrams from a raw socket on the real source path.
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

    /// Captures the `internal` flag the adapter hands to its dialer —
    /// proves `dial_tcp` maps `Metadata::is_internal()` through, which is
    /// what keeps probes/housekeeping chained via `dialer-proxy` from
    /// counting as use of a lazy front-hop group (#555).
    struct CaptureFlagDialer {
        seen: std::sync::Mutex<Option<bool>>,
    }

    #[async_trait]
    impl crate::dialer::TcpDialer for CaptureFlagDialer {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
            internal: bool,
        ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
            *self.seen.lock().unwrap() = Some(internal);
            Err(std::io::Error::other("test dialer never connects"))
        }
    }

    #[tokio::test]
    async fn dial_tcp_forwards_internal_marker_to_dialer() {
        let dialer = Arc::new(CaptureFlagDialer {
            seen: std::sync::Mutex::new(None),
        });
        let adapter = Socks5Adapter::new(
            "front",
            "127.0.0.1",
            1080,
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        );

        // Probe-shaped metadata (the `ConnType::Tunnel` marker) must reach
        // the dialer as `internal: true`.
        let probe = Metadata {
            conn_type: meow_common::ConnType::Tunnel,
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let _ = adapter.dial_tcp(&probe).await;
        assert_eq!(
            *dialer.seen.lock().unwrap(),
            Some(true),
            "probe dial must propagate internal=true"
        );

        // User-shaped metadata keeps `internal: false`.
        let _ = adapter.dial_tcp(&meta_with_host("example.com", 443)).await;
        assert_eq!(
            *dialer.seen.lock().unwrap(),
            Some(false),
            "user dial must propagate internal=false"
        );
    }

    // ─── Chained UDP (`dialer-proxy`) ────────────────────────────────────────

    /// Mock SOCKS5 server that answers `UDP ASSOCIATE` with a fixed
    /// `BND.ADDR`, then holds the control connection open until the client
    /// drops it (association lifetime, RFC 1928 §7).
    async fn spawn_associate_server(
        bnd: SocketAddr,
        rep: u8,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Method negotiation → no-auth.
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[VERSION, METHOD_NO_AUTH]).await.unwrap();
            // Request header; assert it is UDP ASSOCIATE.
            let mut req = [0u8; 4];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], VERSION);
            assert_eq!(req[1], CMD_UDP_ASSOCIATE);
            drain_socks5_addr(&mut s, req[3]).await.unwrap();
            // Reply VER REP RSV ATYP BND.ADDR BND.PORT.
            let mut resp = vec![VERSION, rep, RESERVED];
            match bnd.ip() {
                IpAddr::V4(v4) => {
                    resp.push(ATYP_IPV4);
                    resp.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    resp.push(ATYP_IPV6);
                    resp.extend_from_slice(&v6.octets());
                }
            }
            resp.extend_from_slice(&bnd.port().to_be_bytes());
            s.write_all(&resp).await.unwrap();
            // Hold the control conn open until the client hangs up.
            let mut sink = [0u8; 64];
            while s.read(&mut sink).await.unwrap_or(0) > 0 {}
        });
        (addr, handle)
    }

    /// Variant answering `BND.ADDR` as a domain — servers that relay on a
    /// named interface. Exercises the `RelayAddr::Domain` → `UdpTarget::Name`
    /// path (issue #657).
    async fn spawn_associate_server_domain(
        bnd_host: &str,
        bnd_port: u16,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let host = bnd_host.to_string();
        let handle = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[VERSION, METHOD_NO_AUTH]).await.unwrap();
            let mut req = [0u8; 4];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req[1], CMD_UDP_ASSOCIATE);
            drain_socks5_addr(&mut s, req[3]).await.unwrap();
            let mut resp = vec![VERSION, REPLY_SUCCESS, RESERVED, ATYP_DOMAIN];
            resp.push(u8::try_from(host.len()).unwrap());
            resp.extend_from_slice(host.as_bytes());
            resp.extend_from_slice(&bnd_port.to_be_bytes());
            s.write_all(&resp).await.unwrap();
            let mut sink = [0u8; 64];
            while s.read(&mut sink).await.unwrap_or(0) > 0 {}
        });
        (addr, handle)
    }

    /// Scripted front `ProxyPacketConn`: reads yield injected
    /// `(datagram, wire-src)` pairs, writes record `(frame, wire-dst)`.
    struct ScriptedFront {
        inbound: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
        written: std::sync::Mutex<Vec<(Vec<u8>, SocketAddr)>>,
        bound: SocketAddr,
        /// Truncate every `write_packet` to half the frame — exercises the
        /// datagram-atomicity check on the chained arm.
        short_write: std::sync::atomic::AtomicBool,
        /// Set by `close()` — proves the Chained arm delegates teardown.
        closed: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl ProxyPacketConn for ScriptedFront {
        async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            let (data, src) = self
                .inbound
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| MeowError::Proxy("scripted front closed".into()))?;
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok((n, src))
        }

        async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
            self.written.lock().unwrap().push((buf.to_vec(), *addr));
            if self.short_write.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(buf.len() / 2);
            }
            Ok(buf.len())
        }

        fn local_addr(&self) -> Result<SocketAddr> {
            Ok(self.bound)
        }

        fn close(&self) -> Result<()> {
            self.closed
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    /// `dialer-proxy` fake: the TCP control conn is a real connection to the
    /// mock SOCKS5 server; `dial_udp_conn` returns the scripted front conn —
    /// or a scripted error, for the stale-capability-snapshot arm.
    struct ChainedDialer {
        server_addr: std::net::SocketAddr,
        front: std::sync::Mutex<Option<Arc<ScriptedFront>>>,
        udp_dialed: std::sync::Mutex<Vec<crate::dialer::UdpTarget>>,
        udp_ok: bool,
        /// When set, `dial_udp_conn` fails with this `ErrorKind` — models a
        /// group front that rotated to a UDP-less member between the
        /// `supports_udp()` snapshot and the dial.
        dial_udp_err: Option<std::io::ErrorKind>,
        /// When set, `UdpTarget::Name` dials fail `Unsupported` (a front
        /// that cannot carry a domain) while literal `Addr` dials succeed —
        /// exercises the caller's local-resolution fallback (issue #657).
        refuse_name_targets: bool,
        /// `internal` flags seen on `dial_udp_conn` — proves metadata
        /// propagation through the chained leg.
        seen_internal: std::sync::Mutex<Vec<bool>>,
    }

    #[async_trait]
    impl crate::dialer::TcpDialer for ChainedDialer {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
            _internal: bool,
        ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
            Ok(Box::new(TcpStream::connect(self.server_addr).await?))
        }

        fn is_proxy(&self) -> bool {
            true
        }

        fn supports_udp(&self) -> bool {
            self.udp_ok
        }

        async fn dial_udp_conn(
            &self,
            remote: crate::dialer::UdpTarget,
            internal: bool,
        ) -> std::io::Result<Arc<dyn ProxyPacketConn>> {
            self.seen_internal.lock().unwrap().push(internal);
            if let Some(kind) = self.dial_udp_err {
                return Err(std::io::Error::new(kind, "scripted dial_udp_conn failure"));
            }
            if self.refuse_name_targets && matches!(remote, crate::dialer::UdpTarget::Name { .. }) {
                self.udp_dialed.lock().unwrap().push(remote);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "front cannot carry domain targets",
                ));
            }
            self.udp_dialed.lock().unwrap().push(remote);
            self.front
                .lock()
                .unwrap()
                .clone()
                .map(|f| f as Arc<dyn ProxyPacketConn>)
                .ok_or_else(|| std::io::Error::other("no scripted front"))
        }
    }

    fn encode_socks5_datagram(src: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut pkt: SmallVec<[u8; 1500]> = SmallVec::new();
        encode_udp_header(&mut pkt, &src);
        pkt.extend_from_slice(payload);
        pkt.to_vec()
    }

    /// The chained dial must reach the *advertised* relay endpoint — the
    /// inner datagram target stays inside the SOCKS5 UDP header.
    #[tokio::test]
    async fn chained_udp_dials_front_to_advertised_relay() {
        let relay: SocketAddr = "10.200.1.1:5300".parse().unwrap();
        let (srv, server) = spawn_associate_server(relay, REPLY_SUCCESS).await;
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: relay,
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        assert!(adapter.support_udp(), "capable front must advertise UDP");

        let conn = adapter
            .dial_udp(&meta_with_host("example.com", 443))
            .await
            .expect("dial_udp");
        assert_eq!(
            dialer.udp_dialed.lock().unwrap().as_slice(),
            &[crate::dialer::UdpTarget::Addr(relay)],
            "the front association must be bound to the advertised relay"
        );
        assert_eq!(
            dialer.seen_internal.lock().unwrap().as_slice(),
            &[false],
            "user metadata must propagate internal=false to the front dial"
        );

        // Write: wire dst is `relay`; the caller's target lives in the header.
        let target: SocketAddr = "1.2.3.4:443".parse().unwrap();
        conn.write_packet(b"payload", &target).await.unwrap();
        let (frame, wire_dst) = front.written.lock().unwrap().remove(0);
        assert_eq!(wire_dst, relay);
        let mut dec = frame.clone();
        let (data_len, inner_src) = decode_udp_datagram(&mut dec, frame.len()).unwrap();
        assert_eq!(inner_src, target);
        assert_eq!(&dec[..data_len], b"payload");

        // Read: a well-formed reply from the relay decodes back to the target.
        tx.send((encode_socks5_datagram(target, b"pong"), relay))
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, src) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(src, target);
        assert_eq!(&buf[..n], b"pong");

        // close() delegates to the front conn and aborts the control-conn
        // guard; the drop path then finishes the teardown chain — the mock
        // server observes EOF and exits (RFC 1928 §7 association teardown).
        conn.close().unwrap();
        assert!(
            front.closed.load(std::sync::atomic::Ordering::Relaxed),
            "close() must delegate to the front conn"
        );
        drop(conn);
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("server must observe control-conn EOF")
            .expect("server task");
    }

    /// A server-side ASSOCIATE refusal (`rep != 0`) surfaces as
    /// `Socks5ConnectFailed` — same on the chained arm — and the control
    /// conn is dropped so the server sees the teardown.
    #[tokio::test]
    async fn chained_udp_associate_refusal_is_connect_failed() {
        let relay: SocketAddr = "10.200.1.9:5300".parse().unwrap();
        let (srv, server) = spawn_associate_server(relay, REPLY_COMMAND_NOT_SUPPORTED).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: relay,
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);

        match adapter.dial_udp(&meta_with_host("example.com", 443)).await {
            Err(MeowError::Socks5ConnectFailed(REPLY_COMMAND_NOT_SUPPORTED)) => {}
            Err(e) => panic!("expected Socks5ConnectFailed, got: {e:?}"),
            Ok(_) => panic!("a refused ASSOCIATE must not produce a conn"),
        }
        assert!(
            dialer.udp_dialed.lock().unwrap().is_empty(),
            "no front association may be spent on a refused ASSOCIATE"
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("server must observe control-conn EOF")
            .expect("server task");
    }

    /// Chained reads restore the connected-socket filter: datagrams whose
    /// wire source is a specified address other than the relay — and
    /// malformed relay datagrams — are per-datagram drops, never fatal.
    #[tokio::test]
    async fn chained_udp_drops_foreign_source_and_junk() {
        let relay: SocketAddr = "10.200.1.2:5300".parse().unwrap();
        let (srv, _server) = spawn_associate_server(relay, REPLY_SUCCESS).await;
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: relay,
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            dialer as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        let conn = adapter
            .dial_udp(&meta_with_host("example.com", 443))
            .await
            .expect("dial_udp");

        let target: SocketAddr = "5.6.7.8:53".parse().unwrap();
        // Foreign wire source → dropped.
        let foreign: SocketAddr = "9.9.9.9:9999".parse().unwrap();
        tx.send((encode_socks5_datagram(target, b"spoof"), foreign))
            .await
            .unwrap();
        // Malformed relay datagram → dropped.
        tx.send((b"\xde\xad".to_vec(), relay)).await.unwrap();
        // FRAG ≠ 0 (we do not reassemble) → dropped.
        let mut frag = encode_socks5_datagram(target, b"frag");
        frag[2] = 1;
        tx.send((frag, relay)).await.unwrap();
        // Bound conns report no wire source (`0.0.0.0:0` — e.g. a VLESS
        // UoT front): the filter must skip the check, not wedge them.
        let unspecified: SocketAddr = "0.0.0.0:0".parse().unwrap();
        tx.send((encode_socks5_datagram(target, b"ok"), unspecified))
            .await
            .unwrap();

        let mut buf = [0u8; 256];
        let (n, src) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            conn.read_packet(&mut buf),
        )
        .await
        .expect("read must skip junk, not hang")
        .unwrap();
        assert_eq!(src, target);
        assert_eq!(&buf[..n], b"ok");
    }

    /// A `0.0.0.0` BND address ("same host as the control connection") is
    /// rewritten to the server endpoint before the front is dialed — as
    /// `UdpTarget::Name` of the server name (which collapses to `Addr`
    /// here because this test's server is an IP literal). Matches mihomo's
    /// unspecified-BND substitution, extended by issue #657 to keep the
    /// domain form for domain-named servers.
    #[tokio::test]
    async fn chained_udp_wildcard_bnd_rewritten_to_server_ip() {
        let relay: SocketAddr = "0.0.0.0:5301".parse().unwrap();
        let (srv, _server) = spawn_associate_server(relay, REPLY_SUCCESS).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: "127.0.0.1:5301".parse().unwrap(),
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        let _conn = adapter
            .dial_udp(&meta_with_host("example.com", 443))
            .await
            .expect("dial_udp");
        let dialed = dialer.udp_dialed.lock().unwrap().clone();
        assert_eq!(dialed.len(), 1);
        assert_eq!(
            dialed[0],
            crate::dialer::UdpTarget::Addr("127.0.0.1:5301".parse().unwrap()),
        );
    }

    /// Stale capability snapshot: `supports_udp()` passed, but the front
    /// refuses at dial time (e.g. a group rotated to a UDP-less member).
    /// The dialer's `ErrorKind::Unsupported` must reconstitute
    /// `MeowError::NotSupported` — the exact variant that stays exempt from
    /// group dead-marking.
    #[tokio::test]
    async fn chained_udp_maps_unsupported_to_notsupported() {
        let relay: SocketAddr = "10.200.1.3:5300".parse().unwrap();
        let (srv, _server) = spawn_associate_server(relay, REPLY_SUCCESS).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: relay,
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: Some(std::io::ErrorKind::Unsupported),
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            dialer as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);

        match adapter.dial_udp(&meta_with_host("example.com", 443)).await {
            Err(MeowError::NotSupported(_)) => {}
            Err(e) => panic!("expected NotSupported, got: {e:?}"),
            Ok(_) => panic!("a front refusal must not produce a live conn"),
        }
    }

    /// Chained writes must reject a frame that exceeds the u16 limit a
    /// stream-framed front could carry, and any short write on the front
    /// conn (datagram atomicity — a torn SOCKS5 datagram would desync).
    #[tokio::test]
    async fn chained_udp_rejects_oversized_and_short_writes() {
        let relay: SocketAddr = "10.200.1.4:5300".parse().unwrap();
        let (srv, _server) = spawn_associate_server(relay, REPLY_SUCCESS).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: relay,
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            dialer as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        let conn = adapter
            .dial_udp(&meta_with_host("example.com", 443))
            .await
            .expect("dial_udp");
        let target: SocketAddr = "1.2.3.4:443".parse().unwrap();

        // header(10) + u16::MAX payload already overflows the frame limit.
        let huge = vec![0u8; u16::MAX as usize];
        assert!(
            conn.write_packet(&huge, &target).await.is_err(),
            "oversized frame must be rejected, not wrapped into the stream"
        );

        front
            .short_write
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            conn.write_packet(b"payload", &target).await.is_err(),
            "short write on the front conn must error"
        );
    }

    /// A domain-form BND (`RelayAddr::Domain`) dials the front as
    /// `UdpTarget::Name` — the front resolves the relay with the same view
    /// that answered the control leg (issue #657).
    #[tokio::test]
    async fn chained_udp_domain_bnd_dials_name_target() {
        let (srv, _server) = spawn_associate_server_domain("relay.internal", 5300).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: "127.0.0.1:5300".parse().unwrap(),
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        let _conn = adapter
            .dial_udp(&meta_with_ipv4(Ipv4Addr::new(8, 8, 8, 8), 53))
            .await
            .expect("dial_udp");
        assert_eq!(
            dialer.udp_dialed.lock().unwrap().as_slice(),
            &[crate::dialer::UdpTarget::Name {
                host: "relay.internal".into(),
                port: 5300
            }],
            "domain BND must reach the front as a name, not a local resolution"
        );
    }

    /// A wildcard BND on a *domain-named* server dials `UdpTarget::Name` of
    /// the server name — "same host as the control connection" must mean
    /// the front's resolution of that name, not ours (issue #657).
    #[tokio::test]
    async fn chained_udp_wildcard_bnd_domain_server_dials_name() {
        let relay: SocketAddr = "0.0.0.0:5301".parse().unwrap();
        let (srv, _server) = spawn_associate_server(relay, REPLY_SUCCESS).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: "127.0.0.1:5301".parse().unwrap(),
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "localhost",
            srv.port(),
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        let _conn = adapter
            .dial_udp(&meta_with_ipv4(Ipv4Addr::new(8, 8, 8, 8), 53))
            .await
            .expect("dial_udp");
        assert_eq!(
            dialer.udp_dialed.lock().unwrap().as_slice(),
            &[crate::dialer::UdpTarget::Name {
                host: "localhost".into(),
                port: 5301
            }],
        );
    }

    /// A front that cannot carry a domain target answers `Unsupported`;
    /// the adapter resolves the name locally and redials the literal —
    /// the pre-#657 behavior, still fail-closed through the chain.
    #[tokio::test]
    async fn chained_udp_name_unsupported_falls_back_to_local_literal() {
        let relay: SocketAddr = "0.0.0.0:5301".parse().unwrap();
        let (srv, _server) = spawn_associate_server(relay, REPLY_SUCCESS).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: "127.0.0.1:5301".parse().unwrap(),
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: true,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "localhost",
            srv.port(),
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        let _conn = adapter
            .dial_udp(&meta_with_ipv4(Ipv4Addr::new(8, 8, 8, 8), 53))
            .await
            .expect("name refusal falls back to a local literal dial");
        let dialed = dialer.udp_dialed.lock().unwrap().clone();
        assert_eq!(dialed.len(), 2, "name attempt, then literal retry");
        assert_eq!(
            dialed[0],
            crate::dialer::UdpTarget::Name {
                host: "localhost".into(),
                port: 5301
            }
        );
        let crate::dialer::UdpTarget::Addr(addr) = dialed[1] else {
            panic!("fallback must dial a literal, got {:?}", dialed[1]);
        };
        assert!(addr.ip().is_loopback(), "localhost resolves loopback");
        assert_eq!(addr.port(), 5301);
    }

    /// For a name-bound association the wire source filter is port-only —
    /// the front resolved the name with its own view, so the relay source
    /// IP legitimately differs from any local resolution (issue #657).
    #[tokio::test]
    async fn chained_udp_name_relay_src_filter_is_port_only() {
        let (srv, _server) = spawn_associate_server_domain("relay.internal", 5300).await;
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: "127.0.0.1:5300".parse().unwrap(),
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        let conn = adapter
            .dial_udp(&meta_with_ipv4(Ipv4Addr::new(8, 8, 8, 8), 53))
            .await
            .expect("dial_udp");

        // A datagram arriving from the *front's* resolution of
        // relay.internal — a different IP than any local answer, same port.
        let inner: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut frame: SmallVec<[u8; 1500]> = SmallVec::new();
        encode_udp_header(&mut frame, &inner);
        frame.extend_from_slice(b"reply");
        tx.send((frame.to_vec(), "198.51.100.99:5300".parse().unwrap()))
            .await
            .unwrap();
        // A foreign source on the wrong port must be dropped.
        let mut junk: SmallVec<[u8; 1500]> = SmallVec::new();
        encode_udp_header(&mut junk, &inner);
        junk.extend_from_slice(b"junk");
        tx.send((junk.to_vec(), "198.51.100.99:9999".parse().unwrap()))
            .await
            .unwrap();

        let mut buf = [0u8; 128];
        // The wrong-port datagram may arrive first; the reader must skip it.
        let (n, src) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read_packet(&mut buf),
        )
        .await
        .expect("no read timeout")
        .unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert_eq!(src, inner);
    }

    /// This adapter as a *front*: host-only metadata (the dialer layer's
    /// encoding of `UdpTarget::Name`) stamps every datagram's SOCKS5 DST
    /// field with ATYP_DOMAIN — the server resolves the name (issue #657).
    #[tokio::test]
    async fn front_udp_domain_target_stamps_domain_header() {
        let relay: SocketAddr = "127.0.0.1:5300".parse().unwrap();
        let (srv, _server) = spawn_associate_server(relay, REPLY_SUCCESS).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: relay,
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(Arc::clone(&front))),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        // The dialer-layer encoding of `UdpTarget::Name`: host set, no dst_ip.
        let meta = Metadata {
            network: meow_common::Network::Udp,
            host: "back.internal".into(),
            dst_port: 8388,
            ..Default::default()
        };
        let conn = adapter.dial_udp(&meta).await.expect("dial_udp");
        conn.write_packet(b"payload", &"0.0.0.0:8388".parse().unwrap())
            .await
            .unwrap();

        let written = front.written.lock().unwrap().clone();
        assert_eq!(written.len(), 1);
        let (frame, dst) = &written[0];
        // RSV(2) FRAG(1) ATYP_DOMAIN LEN host PORT — then payload.
        assert_eq!(&frame[..4], &[0, 0, 0, ATYP_DOMAIN]);
        assert_eq!(frame[4] as usize, "back.internal".len());
        assert_eq!(&frame[5..5 + 13], b"back.internal");
        assert_eq!(
            u16::from_be_bytes([frame[18], frame[19]]),
            8388,
            "domain header port"
        );
        assert_eq!(&frame[20..], b"payload");
        // The wire destination is the relay, not the domain placeholder.
        assert_eq!(*dst, relay);
    }

    /// A host-only destination longer than 255 bytes cannot be encoded as
    /// ATYP_DOMAIN — refuse with `NotSupported` so the dialer layer falls
    /// back to a locally-resolved literal (issue #657).
    #[tokio::test]
    async fn front_udp_overlong_domain_refused() {
        let relay: SocketAddr = "127.0.0.1:5300".parse().unwrap();
        let (srv, _server) = spawn_associate_server(relay, REPLY_SUCCESS).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let front = Arc::new(ScriptedFront {
            inbound: tokio::sync::Mutex::new(rx),
            written: std::sync::Mutex::new(Vec::new()),
            bound: relay,
            short_write: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let dialer = Arc::new(ChainedDialer {
            server_addr: srv,
            front: std::sync::Mutex::new(Some(front)),
            udp_dialed: std::sync::Mutex::new(Vec::new()),
            udp_ok: true,
            dial_udp_err: None,
            refuse_name_targets: false,
            seen_internal: std::sync::Mutex::new(Vec::new()),
        });
        let adapter = Socks5Adapter::new(
            "s",
            "127.0.0.1",
            srv.port(),
            None,
            false,
            false,
            Arc::clone(&dialer) as Arc<dyn crate::dialer::TcpDialer>,
        )
        .with_udp(true);
        let meta = Metadata {
            network: meow_common::Network::Udp,
            host: "x".repeat(256).into(),
            dst_port: 8388,
            ..Default::default()
        };
        match adapter.dial_udp(&meta).await {
            Err(MeowError::NotSupported(_)) => {}
            Err(e) => panic!("overlong domain must refuse NotSupported, got {e}"),
            Ok(_) => panic!("overlong domain must refuse NotSupported"),
        }
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

    /// A zero-length `ATYP_DOMAIN` BND cannot name a relay — it is a
    /// malformed reply, not a degenerate name-bound association (issue
    /// #657 review).
    #[tokio::test]
    async fn relay_addr_rejects_empty_domain() {
        // atyp=DOMAIN, len=0, port=0x1F90 — the port bytes are present but
        // must never be read into a valid RelayAddr.
        let mut wire: &[u8] = &[0x00, 0x1f, 0x90];
        let Err(e) = read_relay_addr(&mut wire, ATYP_DOMAIN).await else {
            panic!("empty domain BND must error");
        };
        assert!(e.to_string().contains("empty domain"), "{e}");
    }
}
