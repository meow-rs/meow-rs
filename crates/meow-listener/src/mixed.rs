use crate::http_proxy;
use crate::sniffer::SnifferRuntime;
use crate::socks5;
use meow_common::{AuthConfig, InboundRouteOverride, LanAcl, TcpKeepaliveConfig};
use meow_tunnel::Tunnel;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Default cap on in-flight inbound connections per listener.
/// `0` explicitly disables the cap. Set a positive value (via the
/// `max-connections` config key, top-level or per-listener) to back-pressure
/// the TCP listen queue and bound RSS under burst load: each live
/// VLESS+WS+TLS+ECH tunnel costs ~90 KB of userland memory, so a cap of 256
/// holds RSS to ~50 MB on top of an ~18 MB idle baseline.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

pub struct MixedListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
    auth: Option<Arc<AuthConfig>>,
    max_connections: usize,
    /// Keepalive posture applied to every accepted socket (see
    /// [`crate::keepalive`]); `enabled: false` writes no sockopts.
    tcp_keepalive: TcpKeepaliveConfig,
    /// `lan-allowed-ips`/`lan-disallowed-ips` — the shared inbound ACL
    /// checked against the remote IP right after `accept` (upstream's
    /// `ipfilter` gate). `None` = no ACL configured (e.g. tests that
    /// build the listener directly).
    lan_acl: Option<Arc<LanAcl>>,
    /// `listeners[].proxy`/`rule` — the named-listener route override
    /// stamped onto every flow's `Metadata` (upstream `BaseOption`
    /// Additions). `None` = plain routing.
    route_override: Option<InboundRouteOverride>,
    /// `listeners[].routing-mark` — carried to the SOCKS5 UDP-associate
    /// relay socket this listener binds per association (the TCP listen
    /// socket itself is marked by the caller at bind; accepted sockets
    /// inherit it, the separately bound UDP relay does not). Linux only.
    routing_mark: Option<u32>,
}

impl MixedListener {
    pub fn new(tunnel: Tunnel, listen_addr: SocketAddr, name: String) -> Self {
        Self {
            tunnel,
            listen_addr,
            sniffer: None,
            name,
            auth: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            tcp_keepalive: TcpKeepaliveConfig::default(),
            lan_acl: None,
            route_override: None,
            routing_mark: None,
        }
    }

    /// Override the cap on in-flight inbound connections (default
    /// [`DEFAULT_MAX_CONNECTIONS`]). `0` disables the cap.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Override the TCP keepalive posture applied to every accepted socket
    /// (default [`TcpKeepaliveConfig::default`]). `enabled: false` performs
    /// no keepalive `setsockopt` at all.
    pub fn with_tcp_keepalive(mut self, cfg: TcpKeepaliveConfig) -> Self {
        self.tcp_keepalive = cfg;
        self
    }

    pub fn with_sniffer(mut self, sniffer: Arc<SnifferRuntime>) -> Self {
        if sniffer.is_enabled() {
            self.sniffer = Some(sniffer);
        }
        self
    }

    pub fn with_auth(mut self, auth: Arc<AuthConfig>) -> Self {
        if !auth.credentials.is_empty() {
            self.auth = Some(auth);
        }
        self
    }

    /// Install the shared LAN CIDR ACL (top-level
    /// `lan-allowed-ips`/`lan-disallowed-ips`). Deliberately independent
    /// of [`Self::with_auth`]: the check runs whether or not the global
    /// credential store holds any credentials.
    pub fn with_lan_acl(mut self, acl: Arc<LanAcl>) -> Self {
        self.lan_acl = Some(acl);
        self
    }

    /// Install the named listener's `proxy:`/`rule:` route override —
    /// stamped onto every accepted flow's `Metadata` before routing.
    pub fn with_route_override(mut self, ov: Option<InboundRouteOverride>) -> Self {
        self.route_override = ov;
        self
    }

    /// `listeners[].routing-mark` for the UDP-associate relay socket —
    /// the only socket this listener binds itself (the caller marks the
    /// TCP listen socket). Linux only; `None` writes no sockopt.
    pub fn with_routing_mark(mut self, mark: Option<u32>) -> Self {
        self.routing_mark = mark;
        self
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        self.run_on(listener).await
    }

    /// Serve on an already-bound socket. Lets the caller bind first (e.g. to
    /// resolve a `port: 0` ephemeral listener to its OS-assigned port before
    /// the API snapshot is taken) and hand the socket over.
    pub async fn run_on(
        &self,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bound_addr = listener.local_addr().unwrap_or(self.listen_addr);
        if self.max_connections == 0 {
            info!(
                "Mixed listener '{}' on {} (max_connections=unlimited)",
                self.name, bound_addr
            );
        } else {
            info!(
                "Mixed listener '{}' on {} (max_connections={})",
                self.name, bound_addr, self.max_connections
            );
        }

        // Bound the number of in-flight connection-handler tasks so RSS stays
        // capped under burst load. The semaphore is None when max=0
        // (cap disabled).
        let conn_limit: Option<Arc<Semaphore>> = if self.max_connections > 0 {
            Some(Arc::new(Semaphore::new(self.max_connections)))
        } else {
            None
        };
        let mut warned_saturated = false;
        // A persistent accept failure (fd exhaustion) must not spin the loop
        // or flood the log; a transient one must not be delayed meaningfully.
        let mut accept_backoff = meow_common::ErrorBackoff::new();

        loop {
            // Acquire a slot before accepting — back-pressures the TCP listen
            // queue when the cap is reached rather than spawning unbounded
            // tasks and bloating RSS.
            let permit = if let Some(sem) = &conn_limit {
                let sem = Arc::clone(sem);
                if sem.available_permits() == 0 && !warned_saturated {
                    warn!(
                        "Mixed listener '{}' saturated at {} concurrent connections; new clients will queue",
                        self.name, self.max_connections
                    );
                    warned_saturated = true;
                }
                match sem.acquire_owned().await {
                    Ok(p) => {
                        if warned_saturated {
                            debug!("Mixed listener '{}' has free capacity again", self.name);
                            warned_saturated = false;
                        }
                        Some(p)
                    }
                    Err(_) => return Ok(()), // semaphore closed → shutdown
                }
            } else {
                None
            };

            let (stream, src_addr) = match listener.accept().await {
                Ok(v) => {
                    accept_backoff.succeeded();
                    v
                }
                Err(e) => {
                    drop(permit);
                    // Loud only when the backoff engaged — per-connection
                    // errors (a reset embryo, a pending network error) are
                    // queue progress and stay at debug!.
                    if accept_backoff.failed(&e).await {
                        error!("Mixed listener '{}' accept error: {}", self.name, e);
                    } else {
                        debug!("Mixed listener '{}' accept error: {}", self.name, e);
                    }
                    continue;
                }
            };

            // `lan-allowed-ips`/`lan-disallowed-ips` (upstream
            // `IsRemoteAddrDisAllowed`): the ACL runs inside the accept
            // loop — before keepalive, sniffing, auth, protocol peek and
            // the spawn — and only against the real remote IP. A denied
            // peer gets no protocol response; the socket and permit drop
            // with the iteration.
            if let Some(acl) = &self.lan_acl {
                if !acl.allows(src_addr.ip()) {
                    debug!(
                        "Mixed listener '{}' dropped {src_addr}: outside lan-allowed-ips",
                        self.name
                    );
                    continue;
                }
            }

            // Earliest point in the accepted socket's life: keepalive must
            // be set before protocol peek/handshake/relay so a dead peer is
            // reaped even if the conn stalls mid-handshake.
            crate::keepalive::apply(&stream, self.tcp_keepalive, &self.name);

            let tunnel = self.tunnel.clone();
            let sniffer = self.sniffer.clone();
            let name = self.name.clone();
            let port = bound_addr.port();
            let auth = self.auth.clone();
            let route_override = self.route_override.clone();
            let routing_mark = self.routing_mark;
            tokio::spawn(async move {
                handle_connection(
                    tunnel,
                    stream,
                    src_addr,
                    sniffer,
                    name,
                    port,
                    auth,
                    route_override,
                    routing_mark,
                )
                .await;
                drop(permit);
            });
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is an independent inbound-scoped value the \
              handler forwards; bundling them only renames the list"
)]
async fn handle_connection(
    tunnel: Tunnel,
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
    port: u16,
    auth: Option<Arc<AuthConfig>>,
    route_override: Option<InboundRouteOverride>,
    routing_mark: Option<u32>,
) {
    // Peek the first byte to determine protocol
    let mut peek = [0u8; 1];
    match tokio::time::timeout(crate::DEFAULT_HANDSHAKE_TIMEOUT, stream.peek(&mut peek)).await {
        Err(_) => {
            debug!("Protocol detection timed out for {src_addr}");
            return;
        }
        Ok(Ok(0)) => return,
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            debug!("Peek error: {}", e);
            return;
        }
    }

    if peek[0] == 0x05 {
        // SOCKS5
        socks5::handle_socks5(
            &tunnel,
            stream,
            src_addr,
            sniffer.as_deref(),
            auth.as_deref(),
            &name,
            port,
            route_override.as_ref(),
            routing_mark,
        )
        .await;
    } else {
        // HTTP proxy
        http_proxy::handle_http(
            &tunnel,
            stream,
            src_addr,
            sniffer.as_deref(),
            auth.as_deref(),
            &name,
            port,
            route_override.as_ref(),
        )
        .await;
    }
}
