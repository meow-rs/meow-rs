//! `ReconnectableClient`: the public entry point. Owns the current connection
//! handle (a spawned quiche driver) and lazily (re)connects on demand, then
//! opens proxied TCP streams and UDP sessions through it.

use super::config::Config;
use super::driver::{self, Cmd, ConnHandle};
use super::proto;
use super::tcp::DuplexStream;
use super::udp::UdpSession;
use super::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{timeout, Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ReconnectableClient {
    cfg: Arc<Config>,
    conn: Mutex<Option<Arc<ConnHandle>>>,
}

impl ReconnectableClient {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(cfg),
            conn: Mutex::new(None),
        }
    }

    pub async fn tcp_connect(&self, target: &str) -> Result<DuplexStream> {
        let handle = self.handle().await?;
        let first_frame = proto::encode_tcp_request(target, &[])?;
        let (reply_tx, reply_rx) = oneshot::channel();
        timeout(CONNECT_TIMEOUT, async {
            handle
                .cmd_tx
                .send(Cmd::OpenTcp {
                    first_frame,
                    fast_open: self.cfg.fast_open,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| Error::Closed)?;
            let mut stream = reply_rx.await.map_err(|_| Error::Closed)??;
            stream.wait_connected().await?;
            Ok(stream)
        })
        .await
        .map_err(|_| Error::Quic(format!("TCP connect timeout after {CONNECT_TIMEOUT:?}")))?
    }

    pub async fn udp(&self) -> Result<UdpSession> {
        let handle = self.handle().await?;
        if !handle.udp_enabled {
            return Err(Error::protocol("UDP disabled by hysteria2 server"));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        handle
            .cmd_tx
            .send(Cmd::RegisterUdp { reply: reply_tx })
            .await
            .map_err(|_| Error::Closed)?;
        let (session_id, rx) = reply_rx.await.map_err(|_| Error::Closed)?;
        Ok(UdpSession::new(session_id, handle.cmd_tx.clone(), rx))
    }

    async fn handle(&self) -> Result<Arc<ConnHandle>> {
        let mut guard = self.conn.lock().await;
        if let Some(handle) = guard.as_ref() {
            if handle.is_active() {
                return Ok(Arc::clone(handle));
            }
        }
        let handle = Arc::new(connect_new(Arc::clone(&self.cfg)).await?);
        *guard = Some(Arc::clone(&handle));
        Ok(handle)
    }
}

async fn connect_new(cfg: Arc<Config>) -> Result<ConnHandle> {
    let server = ServerTarget::parse(&cfg.server_addr)?;
    let addrs = meow_common::resolve_host_all(&server.host, server.port)
        .await
        .map_err(|e| {
            // errno-bearing failures (e.g. EMFILE opening the resolver
            // socket under local fd pressure) keep the `Io` arm so the
            // errno survives to `MeowError::Io`; context-only errors keep
            // the `Resolve` shape (issue #668).
            if meow_common::MeowError::io_errno_backed(&e) {
                Error::Io(e)
            } else {
                Error::Resolve(format!("{}:{}: {e}", server.host, server.port))
            }
        })?;
    let server_name = if cfg.server_name.trim().is_empty() {
        server.host.clone()
    } else {
        cfg.server_name.trim().to_string()
    };

    let mut last_error = None;
    for addr in addrs {
        match timeout(CONNECT_TIMEOUT, connect_addr(&cfg, addr, &server_name)).await {
            Ok(Ok(handle)) => return Ok(handle),
            Ok(Err(e)) => last_error = remember(last_error, e),
            Err(_) => {
                last_error = remember(
                    last_error,
                    Error::Quic(format!("connect timeout after {CONNECT_TIMEOUT:?}")),
                );
            }
        }
    }
    Err(last_error.unwrap_or_else(|| Error::Resolve("no address resolved".into())))
}

/// `last_error` accumulation for the multi-address dial loop: an
/// errno-bearing io failure (e.g. EMFILE on the UDP bind — local
/// exhaustion, not member health, issue #668) outranks context-only
/// errors like a later candidate's timeout, which would otherwise mask
/// the classification dead-marking reads.
fn remember(prev: Option<Error>, next: Error) -> Option<Error> {
    let next_errno = matches!(next, Error::Io(ref e) if meow_common::MeowError::io_errno_backed(e));
    let prev_errno =
        matches!(prev, Some(Error::Io(ref e)) if meow_common::MeowError::io_errno_backed(e));
    if next_errno || !prev_errno {
        Some(next)
    } else {
        prev
    }
}

async fn connect_addr(
    cfg: &Config,
    server_addr: SocketAddr,
    server_name: &str,
) -> Result<ConnHandle> {
    let bind_addr = if server_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    // Through the outbound-socket chokepoint, never a raw bind: it applies
    // the TUN global-route interface binding (`SO_BINDTODEVICE`) and the
    // Android `protect()` hook before the first QUIC Initial leaves —
    // otherwise the datagrams follow the TUN's split default routes back
    // into the device and loop (issue #695).
    let socket = meow_common::bind_udp(bind_addr).await.map_err(Error::Io)?;
    let local = socket.local_addr().map_err(Error::Io)?;

    let mut config = super::tls::build_quiche_config(cfg)?;
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    for b in &mut scid {
        *b = rand::random();
    }
    let scid = quiche::ConnectionId::from_ref(&scid);
    let conn = quiche::connect(Some(server_name), &scid, local, server_addr, &mut config)
        .map_err(|e| Error::Quic(format!("connect start: {e}")))?;

    driver::spawn(cfg, socket, local, server_addr, conn).await
}

struct ServerTarget {
    host: String,
    port: u16,
}

impl ServerTarget {
    fn parse(addr: &str) -> Result<Self> {
        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            return Ok(Self {
                host: socket_addr.ip().to_string(),
                port: socket_addr.port(),
            });
        }
        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| Error::config(format!("server address has no port: {addr}")))?;
        if host.is_empty() || host.contains(':') {
            return Err(Error::config(format!(
                "invalid server address, bracket IPv6 literals: {addr}"
            )));
        }
        let port = port
            .parse::<u16>()
            .map_err(|e| Error::config(format!("invalid server port in '{addr}': {e}")))?;
        if port == 0 {
            return Err(Error::config("server port must be non-zero"));
        }
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_server_target() {
        let target = ServerTarget::parse("example.com:443").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parses_bracketed_ipv6_server_target() {
        let target = ServerTarget::parse("[::1]:443").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn remember_prefers_errno_over_context_only_errors() {
        let emfile = Error::Io(std::io::Error::from_raw_os_error(1));
        let timeout_err = Error::Quic("connect timeout".into());
        // errno first, timeout second: errno survives.
        let acc = remember(Some(emfile), timeout_err);
        assert!(matches!(acc, Some(Error::Io(_))));
        // timeout first, errno second: errno replaces it.
        let acc = remember(
            Some(Error::Quic("connect timeout".into())),
            Error::Io(std::io::Error::from_raw_os_error(1)),
        );
        assert!(matches!(acc, Some(Error::Io(_))));
        // Two context-only errors: the last one wins (historical shape).
        let acc = remember(
            Some(Error::Quic("first".into())),
            Error::Quic("second".into()),
        );
        assert!(matches!(acc, Some(Error::Quic(ref s)) if s == "second"));
        // An io error without errno does not gain precedence — neither
        // as `next` (last-wins takes it, same as any context error)…
        let acc = remember(
            Some(Error::Quic("first".into())),
            Error::Io(std::io::Error::other("ctx")),
        );
        assert!(matches!(acc, Some(Error::Io(_))));
        // …nor as `prev`: `driver.rs` synthesizes errno-less io errors
        // ("quiche send: {e}"), and they must not veto a later candidate
        // — this is the discriminating direction.
        let acc = remember(
            Some(Error::Io(std::io::Error::other("ctx"))),
            Error::Quic("second".into()),
        );
        assert!(matches!(acc, Some(Error::Quic(ref s)) if s == "second"));
    }
}
