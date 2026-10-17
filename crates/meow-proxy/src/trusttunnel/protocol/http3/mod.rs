//! The HTTP/3 transport (`quic: true`, PROTOCOL.md §3.2): the same
//! CONNECT-per-flow protocol over QUIC instead of TLS-over-TCP.
//!
//! Unlike the HTTP/2 transport this one owns its socket — QUIC has no stream
//! seam a dialer could sit in — so it binds through `meow_common::bind_udp`,
//! which applies the TUN interface binding and the Android `protect()` hook
//! (issue #695). That is also why `dialer-proxy` is refused for a `quic`
//! node at config load: there is no TCP connection to route through it.

mod driver;
mod stream;
#[cfg(test)]
mod tests;
mod tls;

pub(super) use stream::H3Stream;

use super::{Admission, Connection, Opener, StreamKind};
use async_trait::async_trait;
use driver::{Cmd, Shared};
use http::{Request, StatusCode};
use quiche::h3;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

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
    /// Built once, as the H2 path builds its `TlsLayer` once at config load:
    /// seeding the verify store parses the whole webpki root bundle (~140 DER
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
            config: std::sync::Mutex::new(config),
        })
    }

    async fn dial(
        &self,
        peer: SocketAddr,
        cancel: CancellationToken,
    ) -> io::Result<Box<dyn Connection>> {
        let bind = if peer.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = meow_common::bind_udp(bind).await?;
        let local = socket.local_addr()?;
        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        for byte in &mut scid {
            *byte = rand::random();
        }
        let conn = {
            let mut config = self
                .config
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            quiche::connect(
                self.server_name.as_deref(),
                &quiche::ConnectionId::from_ref(&scid),
                local,
                peer,
                &mut config,
            )
            .map_err(|e| io::Error::other(format!("TrustTunnel QUIC setup: {e}")))?
        };
        let (cmd_tx, shared) = driver::spawn(socket, local, conn, cancel).await?;
        Ok(Box::new(H3Connection { cmd_tx, shared }))
    }
}

#[async_trait]
impl super::Connector for QuicConnector {
    async fn connect(&self, cancel: CancellationToken) -> io::Result<Box<dyn Connection>> {
        let peers = meow_common::resolve_host_all(&self.host, self.port).await?;
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
            match self.dial(peer, attempt).await {
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
