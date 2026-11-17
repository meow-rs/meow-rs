//! The HTTP/3 transport (`quic: true`, PROTOCOL.md §3.2): the same
//! CONNECT-per-flow protocol over QUIC instead of TLS-over-TCP.
//!
//! Unlike the HTTP/2 transport this one owns its socket — QUIC has no stream
//! seam a dialer could sit in — so the direct path binds through
//! `meow_common::bind_udp_for_peer`, which applies the TUN interface binding
//! and the Android `protect()` hook (issue #695). A `dialer-proxy` chain is
//! honoured differently: the whole QUIC connection rides one front UDP
//! association (issue #899 parity with hysteria2), bridged into the driver
//! by `PacketConnSocket` as a connected [`driver::Socket::Io`].

mod driver;
mod stream;
#[cfg(test)]
mod tests;
mod tls;

pub(super) use stream::H3Stream;

use super::{Admission, Connection, Opener, StreamKind};
use crate::dialer::{PacketConnSocket, TcpDialer, UdpTarget};
use async_trait::async_trait;
use driver::{Cmd, Shared, Socket};
use http::{Request, StatusCode};
use meow_common::ProxyPacketConn;
use meow_transport::datagram::SocketIo;
use quiche::h3;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// Dials QUIC connections to one TrustTunnel endpoint.
pub struct QuicConnector {
    host: String,
    port: u16,
    /// SNI, and the name the certificate is verified against: quiche binds
    /// the two together, which is why `name-cert-verify` is refused here.
    /// `None` for an IP literal, which RFC 6066 §3 keeps out of SNI and
    /// which is verified against an `iPAddress` SAN instead (see
    /// [`tls::build`]) — the same split the HTTP/2 path's `TlsLayer` makes.
    server_name: Option<String>,
    /// `dialer-proxy` front, when one is configured: the QUIC connection
    /// rides its UDP association instead of a bound `UdpSocket`.
    dialer: Option<Arc<dyn TcpDialer>>,
    /// Built once, as the H2 path builds its `TlsLayer` once at config load:
    /// seeding the verify store parses the whole webpki root bundle (~120 DER
    /// certificates) into a fresh `X509Store`, which is not work a dial
    /// should repeat. `quiche::connect` needs `&mut Config` but holds no
    /// reference afterwards, so one mutex over the whole call is enough.
    config: std::sync::Mutex<quiche::Config>,
}

impl QuicConnector {
    /// `tls` is the same policy the HTTP/2 path hands its `TlsLayer`; of it,
    /// this transport reads the server name (`sni`, else `host`), the
    /// `skip-cert-verify` switch and the extra roots. The parser refuses the
    /// fields quiche cannot honor for a `quic` node.
    ///
    /// `timeout` is the per-dial deadline the pool enforces; the spec derives
    /// the QUIC idle timeout from it as
    /// `2 × (connection_timeout + health_check_timeout)` (§3.2), and this
    /// client uses the one configured timeout for both of those.
    pub fn new(
        host: &str,
        port: u16,
        tls: &meow_transport::tls::TlsConfig,
        timeout: Duration,
    ) -> io::Result<Self> {
        let name = tls.sni.as_deref().unwrap_or(host);
        // `server: 1.2.3.4` defaults `sni` to the literal. Handed to quiche
        // as a server name it would go out as SNI and be compared as a DNS
        // name, failing a certificate the HTTP/2 transport accepts.
        let ip = meow_common::metadata_ip_literal(name);
        let config = tls::build(
            tls.skip_cert_verify,
            ip,
            &tls.additional_roots,
            timeout.saturating_mul(4),
        )?;
        Ok(Self {
            host: host.to_owned(),
            port,
            server_name: ip.is_none().then(|| name.to_owned()),
            dialer: None,
            config: std::sync::Mutex::new(config),
        })
    }

    /// The `dialer-proxy` variant: every QUIC connection this connector
    /// dials rides a fresh front UDP association — the WireGuard/hysteria2
    /// `with_dialer` contract (issue #899 follow-up).
    pub fn with_dialer(
        host: &str,
        port: u16,
        tls: &meow_transport::tls::TlsConfig,
        timeout: Duration,
        dialer: Arc<dyn TcpDialer>,
    ) -> io::Result<Self> {
        let mut connector = Self::new(host, port, tls, timeout)?;
        connector.dialer = Some(dialer);
        Ok(connector)
    }

    /// Bind the endpoint's front UDP association — the WireGuard
    /// `bind_via_dialer` contract. `UdpTarget::named` collapses an
    /// IP-literal `host` to `Addr` and delegates a domain to the front
    /// hop's own resolver view (issue #657); a front that cannot carry a
    /// domain refuses `Unsupported` and the documented fallback applies:
    /// resolve locally, redial each literal.
    ///
    /// The returned `SocketAddr` is what quiche records as this path's
    /// peer: a real address, never `write_dst`'s `0.0.0.0:port`
    /// placeholder — for a `Name` target it comes from a local resolution,
    /// strictly cosmetic (a bound conn ignores the write arg), so a failed
    /// lookup warns and keeps the inert placeholder rather than unbinding
    /// a dial that succeeded.
    async fn bind_association(&self) -> io::Result<(Arc<dyn ProxyPacketConn>, SocketAddr)> {
        let dialer = self
            .dialer
            .as_ref()
            .expect("bind_association is only called with a dialer");
        let target = UdpTarget::named(&self.host, self.port);
        // `internal` stays false on every dial below: this association is
        // the dial signal a lazy front hop sees for the pooled connection's
        // whole lifetime — marking it internal would leave the front
        // permanently "unused" while user traffic flows (issue #555
        // boundary, the same rule hysteria2's association dial documents).
        match dialer.dial_udp_conn(target.clone(), false).await {
            Ok(conn) => {
                let peer = match &target {
                    UdpTarget::Addr(addr) => *addr,
                    UdpTarget::Name { .. } => match self.resolve_peers().await {
                        Ok(peers) => match peers.into_iter().next() {
                            Some(addr) => addr,
                            None => {
                                warn!(
                                    "trusttunnel-h3: front bound {target} but local \
                                     resolution returned no address — peer addr stays \
                                     unspecified (inert on the bound conn)"
                                );
                                target.write_dst()
                            }
                        },
                        Err(e) => {
                            warn!(
                                "trusttunnel-h3: front bound {target} but local \
                                 resolution failed ({e}) — peer addr stays unspecified \
                                 (inert on the bound conn)"
                            );
                            target.write_dst()
                        }
                    },
                };
                Ok((conn, peer))
            }
            Err(e)
                if e.kind() == io::ErrorKind::Unsupported
                    && matches!(target, UdpTarget::Name { .. }) =>
            {
                let peers = self.resolve_peers().await?;
                let mut last: Option<io::Error> = None;
                let mut bound = None;
                for peer in peers {
                    match dialer.dial_udp_conn(UdpTarget::Addr(peer), false).await {
                        Ok(conn) => {
                            bound = Some((conn, peer));
                            break;
                        }
                        Err(e) => last = meow_common::MeowError::prefer_errno_io(last, e),
                    }
                }
                bound.ok_or_else(|| {
                    last.unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "TrustTunnel endpoint resolved to no address",
                        )
                    })
                })
            }
            Err(e) => Err(e),
        }
    }

    async fn resolve_peers(&self) -> io::Result<Vec<SocketAddr>> {
        meow_common::resolve_host_all(&self.host, self.port).await
    }

    /// `dial` generalized: `Some(io)` runs the connection over an injected
    /// connected endpoint (a `dialer-proxy` front association), `None`
    /// binds a `UdpSocket` for `peer` exactly as the direct path always
    /// has. For `Io`, `local` comes from the endpoint's
    /// [`SocketIo::local_addr_hint`] — the association may report none, in
    /// which case quiche gets an unspecified `to` of the peer's family
    /// (cosmetic: a bound association owns no dialable local tuple).
    async fn dial(
        &self,
        peer: SocketAddr,
        socket_io: Option<Box<dyn SocketIo>>,
        cancel: CancellationToken,
    ) -> io::Result<Box<dyn Connection>> {
        // The socket's family follows the canonical peer; a loopback peer is
        // left outside the TUN global-route interface binding.
        let peer = meow_common::canonical_socket_addr(peer);
        let (socket, local, mtu_hint) = match socket_io {
            Some(io) => {
                let local = io.local_addr_hint().unwrap_or_else(|| {
                    SocketAddr::new(
                        if peer.is_ipv6() {
                            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                        } else {
                            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                        },
                        0,
                    )
                });
                // The front's per-packet encapsulation makes the stock
                // send cap unsafe — same [`SocketIo::mtu_hint`] contract
                // the hysteria2 client applies.
                let mtu_hint = io.mtu_hint();
                (Socket::Io { io, peer }, local, mtu_hint)
            }
            None => {
                let socket = meow_common::bind_udp_for_peer(peer.ip()).await?;
                // Same receive-buffer headroom as the hysteria2 raw path:
                // a full 208 KiB default drops datagrams quiche must then
                // detect and resend.
                meow_common::enlarge_udp_recv_buffer(&socket);
                let local = socket.local_addr()?;
                (Socket::Raw(socket), local, None)
            }
        };
        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        for byte in &mut scid {
            *byte = rand::random();
        }
        let conn = {
            let mut config = self
                .config
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(mtu) = mtu_hint {
                config.set_max_send_udp_payload_size(mtu);
            }
            quiche::connect(
                self.server_name.as_deref(),
                &quiche::ConnectionId::from_ref(&scid),
                local,
                peer,
                &mut config,
            )
            .map_err(|e| io::Error::other(format!("TrustTunnel QUIC setup: {e}")))?
        };
        let (cmd_tx, shared) =
            driver::spawn(socket, local, conn, driver::AckCoalesce::default(), cancel).await?;
        Ok(Box::new(H3Connection { cmd_tx, shared }))
    }
}

#[async_trait]
impl super::Connector for QuicConnector {
    async fn connect(&self, cancel: CancellationToken) -> io::Result<Box<dyn Connection>> {
        if self.dialer.is_some() {
            // One association per pooled connection attempt — like the
            // WireGuard endpoint bind, a dead conn is never resurrected.
            // A failed driver cancels only this attempt; the guard also
            // stops the driver if the caller drops this await.
            let attempt = cancel.child_token();
            let guard = attempt.clone().drop_guard();
            let result = match self.bind_association().await {
                Ok((conn, peer)) => {
                    let socket = PacketConnSocket::new(conn, peer);
                    self.dial(peer, Some(Box::new(socket)), attempt).await
                }
                Err(e) => Err(e),
            };
            return match result {
                Ok(connection) => {
                    guard.disarm();
                    Ok(connection)
                }
                Err(error) => Err(error),
            };
        }
        let peers = self.resolve_peers().await?;
        let mut last = None;
        for peer in peers {
            if cancel.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "TrustTunnel QUIC dial was cancelled",
                ));
            }
            // A failed driver cancels only this address's attempt. The
            // session token must remain live for the next address. The
            // guard also stops the driver if the caller drops this await.
            let attempt = cancel.child_token();
            let guard = attempt.clone().drop_guard();
            match self.dial(peer, None, attempt).await {
                Ok(connection) => {
                    guard.disarm();
                    return Ok(connection);
                }
                Err(error) => last = meow_common::MeowError::prefer_errno_io(last, error),
            }
        }
        Err(last.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "TrustTunnel endpoint resolved to no address",
            )
        }))
    }
}

struct H3Connection {
    cmd_tx: mpsc::Sender<Cmd>,
    shared: Arc<Shared>,
}

#[async_trait]
impl Connection for H3Connection {
    fn is_reusable(&self) -> bool {
        self.shared.accepting.load(Ordering::Acquire)
            && !self.shared.closed.load(Ordering::Relaxed)
            && !self.cmd_tx.is_closed()
    }

    async fn admit(&self) -> Admission {
        if !self.is_reusable() {
            return Admission::Closed;
        }
        // Out of stream credit: the connection is healthy, so it stays
        // pooled and the caller tries another one. The driver still queues
        // an open that loses the race against a concurrent dial, so this
        // only has to be right often enough to keep the pool spreading.
        if self.shared.credit.load(Ordering::Relaxed) == 0 {
            return Admission::Full;
        }
        Admission::Granted(Box::new(H3Opener(self.cmd_tx.clone())))
    }

    fn stream_ceiling(&self) -> usize {
        self.shared.ceiling.load(Ordering::Relaxed)
    }
}

struct H3Opener(mpsc::Sender<Cmd>);

#[async_trait]
impl Opener for H3Opener {
    async fn open(
        self: Box<Self>,
        request: Request<()>,
        end: bool,
    ) -> io::Result<(StatusCode, StreamKind)> {
        let headers = encode(&request)?;
        let (reply, response) = oneshot::channel();
        self.0
            .send(Cmd::Open {
                headers,
                fin: end,
                reply,
            })
            .await
            .map_err(|_| closed())?;
        let (status, stream) = response.await.map_err(|_| closed())??;
        Ok((status, StreamKind::H3(stream)))
    }
}

fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "TrustTunnel H3 connection closed",
    )
}

/// Turn the shared CONNECT request into an HTTP/3 field section.
///
/// A CONNECT request carries `:method` and `:authority` and no `:scheme` or
/// `:path` (RFC 9114 §4.4) — the one structural difference from the HTTP/2
/// request the same [`super::Client`] builds.
fn encode(request: &Request<()>) -> io::Result<Vec<h3::Header>> {
    let authority = request.uri().authority().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TrustTunnel CONNECT has no authority",
        )
    })?;
    let mut headers = Vec::with_capacity(2 + request.headers().len());
    headers.push(h3::Header::new(b":method", b"CONNECT"));
    headers.push(h3::Header::new(
        b":authority",
        authority.as_str().as_bytes(),
    ));
    for (name, value) in request.headers() {
        headers.push(h3::Header::new(name.as_str().as_bytes(), value.as_bytes()));
    }
    Ok(headers)
}
