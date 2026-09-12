use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_dns::Resolver;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

pub struct DirectAdapter {
    routing_mark: Option<u32>,
    /// Optional internal DNS resolver. When set, `dial_tcp` resolves
    /// hostnames via this resolver instead of the OS resolver — this is
    /// important when meow-rs *is* the system DNS, because routing a direct
    /// DNS query back through the OS would loop the query back into meow-rs.
    /// Behind a slot so `Tunnel::set_resolver` can hot-swap the generation
    /// on `PUT /configs` without rebuilding the adapter (issue #514). When
    /// built via `with_resolver_slot` the slot is shared with the tunnel,
    /// so map `DIRECT` and `TunnelInner.direct` track one generation.
    resolver: Option<meow_dns::ResolverSlot>,
    /// Wall-clock bound on `TcpStream::connect`. iOS / macOS scoped-routing
    /// and reachability-cache transients can leave a `connect()` hanging
    /// indefinitely against a destination whose route is in flux (Wi-Fi
    /// assoc churn, IPv6 RA churn, post-wake route reassessment). Without
    /// this bound the dial holds whatever upstream scheduling resource the
    /// caller allocated to it until the OS gives up (~75 s on iOS BSD-style
    /// SYN retransmit grid). `None` preserves the legacy unbounded
    /// behaviour for downstream consumers that haven't opted in.
    connect_timeout: Option<Duration>,
    health: ProxyHealth,
}

impl DirectAdapter {
    pub fn new() -> Self {
        Self {
            routing_mark: None,
            resolver: None,
            connect_timeout: None,
            health: ProxyHealth::new(),
        }
    }

    pub fn with_routing_mark(mut self, routing_mark: u32) -> Self {
        self.routing_mark = Some(routing_mark);
        self
    }

    /// Wrap `resolver` in a fresh private slot — this adapter will not
    /// follow later `Tunnel::set_resolver` swaps. Prefer
    /// [`Self::with_resolver_slot`] when a shared generation is intended.
    pub fn with_resolver(mut self, resolver: Arc<Resolver>) -> Self {
        self.resolver = Some(meow_dns::new_resolver_slot(resolver));
        self
    }

    /// Share an existing resolver slot — writes to the slot (e.g.
    /// `Tunnel::set_resolver`) are observed by this adapter on every dial
    /// (issue #514).
    pub fn with_resolver_slot(mut self, slot: meow_dns::ResolverSlot) -> Self {
        self.resolver = Some(slot);
        self
    }

    /// Bound `TcpStream::connect` on `dial_tcp`. Returns `MeowError::Io`
    /// with `ErrorKind::TimedOut` if the connect exceeds `timeout`. See
    /// the `connect_timeout` field doc for the motivating failure mode
    /// (iOS routing-cache transients) and meow-ios'
    /// `docs/INVESTIGATION-2026-05-18-tcp-direct-rule-disconnect.md` for
    /// the device-side trace.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Read back the configured connect bound. `None` = unbounded. Lets
    /// config-layer tests assert the `tcp-connect-timeout` /
    /// `connect-timeout` wiring without dialing anything.
    pub fn connect_timeout(&self) -> Option<Duration> {
        self.connect_timeout
    }

    /// Determine the concrete `SocketAddr` candidates to dial for `metadata`,
    /// avoiding the OS resolver whenever possible.
    async fn resolve_targets(&self, metadata: &Metadata) -> Result<Vec<SocketAddr>> {
        // 1. Destination already resolved (e.g. by rule-matching pre_resolve,
        //    or when the client supplied an IP literal).
        if let Some(ip) = metadata.dst_ip {
            return Ok(vec![SocketAddr::new(ip, metadata.dst_port)]);
        }

        // 2. `host` is an IP literal — no DNS needed.
        if let Ok(ip) = metadata.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, metadata.dst_port)]);
        }

        // 3. Resolve via meow-rs's internal resolver if available. Falls back
        //    to the OS resolver only when no resolver was injected (tests,
        //    standalone usage).
        if !metadata.host.is_empty() {
            if let Some(resolver) = &self.resolver {
                let resolver = Arc::clone(&resolver.read());
                return match resolver.resolve_ips(&metadata.host).await {
                    Some(ips) if !ips.is_empty() => Ok(ips
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, metadata.dst_port))
                        .collect()),
                    None => Err(MeowError::Dns(format!(
                        "direct: failed to resolve {}",
                        metadata.host
                    ))),
                    Some(_) => Err(MeowError::Dns(format!(
                        "direct: no address for {}",
                        metadata.host
                    ))),
                };
            }

            // Legacy fallback: let tokio use getaddrinfo. Only reachable when
            // no resolver was injected — production code paths always inject.
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((&*metadata.host, metadata.dst_port))
                    .await
                    .map_err(MeowError::Io)?
                    .collect();
            if addrs.is_empty() {
                return Err(MeowError::Dns(format!(
                    "direct: no address for {}:{}",
                    metadata.host, metadata.dst_port
                )));
            }
            return Ok(addrs);
        }

        Err(MeowError::Proxy(
            "direct: metadata has no destination".into(),
        ))
    }
}

impl Default for DirectAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// Wrapper for TcpStream that implements ProxyConn
struct DirectConn(TcpStream);

impl tokio::io::AsyncRead for DirectConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for DirectConn {
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

impl Unpin for DirectConn {}
impl ProxyConn for DirectConn {}

// UDP wrapper
struct DirectPacketConn(UdpSocket);

#[async_trait]
impl ProxyPacketConn for DirectPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await.map_err(MeowError::Io)
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        self.0.send_to(buf, addr).await.map_err(MeowError::Io)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr().map_err(MeowError::Io)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Wrap a connect future in the adapter-configured timeout. Returns the
/// stream on success, or a `MeowError::Io(TimedOut)` whose message identifies
/// the destination and the budget that elapsed when the budget is hit.
///
/// Lives next to `dial_tcp` rather than inline so the timeout behaviour can
/// be exercised in tests against a deterministic future (e.g. `pending()`)
/// instead of relying on a real-network black-hole — see the unit tests at
/// the bottom of this file.
async fn apply_connect_timeout<F>(
    connect: F,
    timeout: Option<Duration>,
    dest: SocketAddr,
) -> Result<TcpStream>
where
    F: std::future::Future<Output = std::io::Result<TcpStream>>,
{
    match timeout {
        Some(t) => match tokio::time::timeout(t, connect).await {
            Ok(res) => res.map_err(MeowError::Io),
            Err(_) => Err(MeowError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("direct: connect to {dest} timed out after {t:?}"),
            ))),
        },
        None => connect.await.map_err(MeowError::Io),
    }
}

/// Create a TCP socket with an optional routing mark (SO_MARK on Linux)
/// set BEFORE connecting, so the SYN packet is already marked. On Android
/// the installed `meow_common::SocketProtector` is applied to the socket
/// fd (also pre-connect) so the dial bypasses VpnService when meow-rs runs
/// inside a VPN app.
async fn connect_with_mark(
    dest: SocketAddr,
    routing_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    #[cfg(target_os = "linux")]
    if let Some(mark) = routing_mark {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if dest.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_mark(mark)?;
        // TUN global-route loop avoidance (#375): this branch bypasses
        // `meow_common::connect_tcp`, so apply the outbound-interface
        // binding here too (no-op when none is installed).
        meow_common::apply_outbound_interface(&socket)?;
        socket.set_nonblocking(true)?;

        match socket.connect(&dest.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }

        let std_stream: std::net::TcpStream = socket.into();
        return TcpStream::from_std(std_stream);
    }

    #[cfg(not(target_os = "linux"))]
    let _ = routing_mark;

    meow_common::connect_tcp(dest).await
}

#[async_trait]
impl ProxyAdapter for DirectAdapter {
    fn name(&self) -> &str {
        "DIRECT"
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let dests = self.resolve_targets(metadata).await?;
        let mut last_err = None;

        for dest in dests {
            match apply_connect_timeout(
                connect_with_mark(dest, self.routing_mark),
                self.connect_timeout,
                dest,
            )
            .await
            {
                Ok(stream) => return Ok(Box::new(DirectConn(stream))),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or_else(|| MeowError::Proxy("direct: no reachable address".into())))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        // Bind the reply socket in the destination's address family. Hardcoding
        // an IPv4 (`0.0.0.0:0`) bind here broke QUIC/HTTP3 direct connections:
        // HTTP/3 origins are almost always dual-stack and the client prefers
        // IPv6 (Happy Eyeballs), so `send_to()` to a v6 destination failed on
        // the AF_INET socket. `handle_udp`'s initial write then errored and the
        // NAT session was never inserted, so no reply reader could ever form —
        // server→app QUIC replies had no socket to arrive on.
        //
        // The NAT key in `handle_udp` is `(src, dst)`, so a single direct UDP
        // session only ever targets one destination → one address family; we
        // can bind the matching family up front. Falls back to IPv4 when the
        // destination family is unknown (preserves the legacy behaviour).
        let dst_is_v6 = match metadata.dst_ip {
            Some(ip) => ip.is_ipv6(),
            None => metadata.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()),
        };
        let bind_addr = if dst_is_v6 { "[::]:0" } else { "0.0.0.0:0" };
        let socket = meow_common::bind_udp(bind_addr)
            .await
            .map_err(MeowError::Io)?;
        Ok(Box::new(DirectPacketConn(socket)))
    }

    /// Pass the stream through unchanged.
    ///
    /// A direct hop in a relay chain is a no-op — useful for
    /// `relay: [direct, ss-node]` topologies where the first hop is a
    /// plain TCP connection without any proxy framing.
    ///
    /// upstream: adapter/outbound/direct.go — no DialContextWithDialer defined;
    /// relay skips direct hops by convention.  Class A ADR-0002: we make it
    /// explicit so the compiler enforces the override.
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Ok(stream)
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::DnsMode;
    use meow_dns::HostEntry;
    use meow_trie::DomainTrie;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn fake_dest() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1)
    }

    fn udp_metadata(dst_ip: IpAddr) -> Metadata {
        Metadata {
            dst_ip: Some(dst_ip),
            dst_port: 443,
            ..Default::default()
        }
    }

    fn tcp_metadata(host: &str, port: u16) -> Metadata {
        Metadata {
            host: host.into(),
            dst_port: port,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn dial_tcp_tries_next_resolved_address_after_first_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        hosts.insert(
            "multi.test",
            vec![
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ]
            .into(),
        );
        let resolver = Arc::new(Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            true,
        ));
        let adapter = DirectAdapter::new()
            .with_resolver(resolver)
            .with_connect_timeout(Duration::from_secs(2));

        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let conn = adapter
            .dial_tcp(&tcp_metadata("multi.test", port))
            .await
            .expect("second resolved address should connect");
        let _ = accept.await.unwrap();
        drop(conn);
    }

    /// Regression for QUIC/HTTP3 direct: `dial_udp` must bind the reply socket
    /// in the destination's address family. A v6 destination on an AF_INET
    /// socket cannot be written, so the NAT session — and thus the reply
    /// reader — never forms. We only assert the *bound family* here so the
    /// test is independent of host IPv6 routing.
    #[tokio::test]
    async fn dial_udp_binds_v6_socket_for_v6_destination() {
        let adapter = DirectAdapter::new();
        let conn = adapter
            .dial_udp(&udp_metadata(IpAddr::V6(Ipv6Addr::LOCALHOST)))
            .await
            .expect("dial_udp must succeed for a v6 destination");
        let local = conn.local_addr().expect("local_addr");
        assert!(
            local.is_ipv6(),
            "v6 destination must bind a v6 socket, got {local}"
        );
    }

    #[tokio::test]
    async fn dial_udp_binds_v4_socket_for_v4_destination() {
        let adapter = DirectAdapter::new();
        let conn = adapter
            .dial_udp(&udp_metadata(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .await
            .expect("dial_udp must succeed for a v4 destination");
        let local = conn.local_addr().expect("local_addr");
        assert!(
            local.is_ipv4(),
            "v4 destination must bind a v4 socket, got {local}"
        );
    }

    /// Full bidirectional round-trip over IPv6: prove server→app replies flow
    /// back through the direct UDP conn. Skipped when the host has no IPv6
    /// loopback (some minimal CI sandboxes).
    #[tokio::test]
    async fn dial_udp_v6_round_trip_delivers_reply() {
        let Ok(echo) = tokio::net::UdpSocket::bind("[::1]:0").await else {
            eprintln!("no IPv6 loopback available; skipping v6 round-trip test");
            return;
        };
        let echo_addr = echo.local_addr().unwrap();

        let adapter = DirectAdapter::new();
        let conn = adapter
            .dial_udp(&udp_metadata(echo_addr.ip()))
            .await
            .expect("dial_udp v6");

        // app → server
        conn.write_packet(b"ping", &echo_addr)
            .await
            .expect("write_packet to v6 destination must succeed");

        // server receives and replies
        let mut sbuf = [0u8; 16];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut sbuf))
            .await
            .expect("echo recv timed out")
            .expect("echo recv");
        assert_eq!(&sbuf[..n], b"ping");
        echo.send_to(b"pong", from).await.expect("echo reply");

        // server → app: the reply must flow back through the same conn
        let mut cbuf = [0u8; 16];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), conn.read_packet(&mut cbuf))
            .await
            .expect("reply read timed out")
            .expect("read_packet");
        assert_eq!(&cbuf[..n], b"pong");
    }

    /// Drive `apply_connect_timeout` against a future that never completes,
    /// using `tokio::time::pause()` so the timeout fires in virtual time.
    /// Deterministic — no real network, no wall-clock dependence on test-net
    /// blackholing.
    #[tokio::test(start_paused = true)]
    async fn apply_connect_timeout_fires_on_pending_future() {
        let pending = std::future::pending::<std::io::Result<TcpStream>>();
        let task = tokio::spawn(apply_connect_timeout(
            pending,
            Some(Duration::from_millis(500)),
            fake_dest(),
        ));
        // Advance past the budget; the timeout must now have fired.
        tokio::time::advance(Duration::from_millis(501)).await;
        let res = task.await.expect("join");
        let err = res.expect_err("must surface TimedOut");
        match err {
            MeowError::Io(io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
                let msg = io.to_string();
                assert!(
                    msg.contains("192.0.2.1") && msg.contains("500"),
                    "error message should name the destination and budget: {msg}"
                );
            }
            other => panic!("expected MeowError::Io(TimedOut), got {other:?}"),
        }
    }

    /// With `timeout = None`, the helper awaits the inner future to
    /// completion. Verify it does not preempt a fast-succeeding connect.
    #[tokio::test]
    async fn apply_connect_timeout_none_passes_through_success() {
        // Build a satisfied future by dialling a real local listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            // Hold open so the client's connect completes; drop after.
            drop(s);
        });
        let connect = TcpStream::connect(addr);
        let res = apply_connect_timeout(connect, None, addr).await;
        assert!(res.is_ok(), "no timeout configured → must pass through");
        let _ = accept.await;
    }

    /// With `timeout = Some(..)` but the inner future is ready immediately,
    /// we must NOT spuriously surface TimedOut.
    #[tokio::test]
    async fn apply_connect_timeout_does_not_fire_when_connect_is_fast() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let connect = TcpStream::connect(addr);
        let res = apply_connect_timeout(connect, Some(Duration::from_secs(5)), addr).await;
        assert!(
            res.is_ok(),
            "successful local connect must not race the timeout"
        );
        let _ = accept.await;
    }

    /// When the inner connect itself errors (e.g. `ECONNREFUSED` from a
    /// closed port), the helper surfaces the real IO error rather than
    /// disguising it as a timeout.
    #[tokio::test]
    async fn apply_connect_timeout_propagates_io_error() {
        // Bind a listener to claim a port, then drop it so connects RST.
        let port = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let dest: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let connect = TcpStream::connect(dest);
        let res = apply_connect_timeout(connect, Some(Duration::from_secs(5)), dest).await;
        let Err(MeowError::Io(io)) = res else {
            panic!("expected MeowError::Io(_), got {res:?}");
        };
        // The exact kind is OS-dependent (ConnectionRefused on most systems)
        // — just assert it isn't TimedOut, which would be a wrong-bucket bug.
        assert_ne!(
            io.kind(),
            std::io::ErrorKind::TimedOut,
            "real IO error must not be relabeled as TimedOut: {io}"
        );
    }
}
