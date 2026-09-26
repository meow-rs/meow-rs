//! Pluggable TCP dialer for proxy chaining (mihomo `dialer-proxy` model).
//!
//! Each proxy adapter holds an `Arc<dyn TcpDialer>` and calls `dial()` to
//! obtain the raw underlying stream to its server.  The default
//! [`DirectDialer`] uses `meow_common::connect_tcp_host` (resolver-aware,
//! SocketProtector-aware).  When `dialer-proxy` is configured, a
//! [`ProxyDialer`] is injected instead — it tunnels through another proxy,
//! making chaining transparent to the adapter's TLS + protocol handshake.
//!
//! upstream: mihomo `component/proxydialer` + `BasicOption.NewDialer`.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use parking_lot::RwLock;

use async_trait::async_trait;
use meow_common::{ConnType, Metadata, Network, Proxy, ProxyConn};
use meow_transport::Stream;
use smol_str::SmolStr;

/// A pluggable dialer for the underlying connection to a proxy server.
///
/// Mirrors mihomo's `C.Dialer` interface.  Adapters call `dial()` instead of
/// `meow_common::connect_tcp_host()` directly so that `dialer-proxy` can
/// inject a proxied connection transparently.
///
/// # Performance note (review M10)
///
/// Every outbound connection pays two extra heap allocations versus the old
/// direct `connect_tcp_host` path: this trait is `#[async_trait]` (the
/// future is boxed) and it returns `Box<dyn Stream>`.  The direct path
/// previously allocated nothing.  This is accepted for now — ADR-0008's
/// allocation discipline tracks per-connection overhead via the conn-rate
/// benchmark (`cargo run -p meow-bench -- --only connrate`); if that
/// benchmark regresses, the candidate fix is replacing `#[async_trait]`
/// with RPITIT (`impl Future` in the trait) and/or an unboxed stream
/// return, at the cost of the vtable-style plugin seam.
#[async_trait]
pub trait TcpDialer: Send + Sync {
    /// Dial `host:port` and return a duplex stream.
    ///
    /// `internal` is [`Metadata::is_internal`] from the caller's metadata —
    /// `true` for housekeeping traffic (health probes, provider fetches).
    /// [`ProxyDialer`] copies it onto the reconstructed metadata so a lazy
    /// front-hop group does not count internal chained dials as user
    /// traffic; dialers with no metadata to construct ignore it.
    async fn dial(&self, host: &str, port: u16, internal: bool) -> io::Result<Box<dyn Stream>>;

    /// Dial an already-resolved [`SocketAddr`].
    ///
    /// Callers holding a literal address should prefer this over
    /// `dial(&addr.ip().to_string(), addr.port())`, which allocates a `String`
    /// only for the callee to parse it straight back into an `IpAddr`.
    /// The default implementation does exactly that round-trip, so
    /// implementors that can dial an address directly should override it.
    async fn dial_addr(&self, addr: SocketAddr, internal: bool) -> io::Result<Box<dyn Stream>> {
        self.dial(&addr.ip().to_string(), addr.port(), internal)
            .await
    }

    /// Whether this dialer tunnels through another proxy (vs. direct).
    ///
    /// Adapters whose UDP path uses a raw socket that bypasses `dial()`
    /// (e.g. Shadowsocks UDP relay) should check this and disable UDP when a
    /// proxy dialer is installed, so UDP traffic does not leak past the
    /// `dialer-proxy` chain.
    fn is_proxy(&self) -> bool {
        false
    }

    /// Connected UDP datagram endpoint for transports layered over UDP
    /// (kcptun). Equivalent to mihomo's `dialer.ListenPacket`: the direct
    /// dialer binds a real socket; a proxy dialer tunnels datagrams through
    /// the front proxy's UDP relay instead of leaking the real source path.
    ///
    /// The default errors — implementations without UDP simply cannot carry
    /// a UDP transport.
    #[cfg(feature = "kcptun")]
    async fn dial_udp_endpoint(
        &self,
        _remote: SocketAddr,
    ) -> io::Result<Box<dyn meow_transport::kcptun::SocketIo>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "dialer cannot provide a UDP endpoint",
        ))
    }
}

/// Direct TCP dialer — the default, equivalent to mihomo's `dialer.NewDialer()`.
///
/// Uses `meow_common::connect_tcp_host` which is resolver-aware and
/// SocketProtector-aware (Android `VpnService.protect(fd)` etc.).
pub struct DirectDialer;

#[async_trait]
impl TcpDialer for DirectDialer {
    async fn dial(&self, host: &str, port: u16, _internal: bool) -> io::Result<Box<dyn Stream>> {
        let tcp = meow_common::connect_tcp_host(host, port).await?;
        // Preserve TCP_NODELAY (disable Nagle) — all call sites that
        // previously called `tcp.set_nodelay(true)` on the raw
        // `TcpStream` now rely on the dialer to do it once here.
        let _ = tcp.set_nodelay(true);
        Ok(Box::new(tcp))
    }

    async fn dial_addr(&self, addr: SocketAddr, _internal: bool) -> io::Result<Box<dyn Stream>> {
        // Skip the default's `to_string()` + re-parse: `connect_tcp` takes the
        // `SocketAddr` as-is and keeps the SocketProtector hook.
        let tcp = meow_common::connect_tcp(addr).await?;
        let _ = tcp.set_nodelay(true);
        Ok(Box::new(tcp))
    }

    #[cfg(feature = "kcptun")]
    async fn dial_udp_endpoint(
        &self,
        remote: SocketAddr,
    ) -> io::Result<Box<dyn meow_transport::kcptun::SocketIo>> {
        // Same bind-family + protect-hook dance as the SS UDP relay path:
        // `bind_udp` routes the fd through the installed SocketProtector
        // (Android VpnService.protect) before `connect`.
        let bind_addr: SocketAddr = if remote.is_ipv4() {
            "0.0.0.0:0".parse().expect("static")
        } else {
            "[::]:0".parse().expect("static")
        };
        let udp = meow_common::bind_udp(bind_addr).await?;
        udp.connect(remote).await?;
        Ok(Box::new(udp))
    }
}

/// Proxy dialer — tunnels through another proxy.  Equivalent to mihomo's
/// `proxyDialer.DialContext()`.
///
/// Calls `proxy.dial_tcp()` with metadata targeting `host:port`, then adapts
/// the returned `ProxyConn` into a `Stream` for the caller's transport chain.
///
/// This is the *unguarded* inner of the by-name path: it carries no
/// `scoped_chain_dial` depth accounting, so nothing should be built on it
/// that can re-enter by-name resolution — use [`NamedProxyDialer`] for a
/// `dialer-proxy` chain edge (issue #489).
pub struct ProxyDialer {
    proxy: Arc<dyn Proxy>,
}

impl ProxyDialer {
    pub fn new(proxy: Arc<dyn Proxy>) -> Self {
        Self { proxy }
    }

    /// Dial the front proxy with a fully-formed [`Metadata`] target.
    async fn dial_metadata(&self, meta: Metadata) -> io::Result<Box<dyn Stream>> {
        let conn = self
            .proxy
            .dial_tcp(&meta)
            .await
            .map_err(|e| io::Error::other(format!("dialer-proxy: {e}")))?;
        // `Box<dyn ProxyConn>` is unsized (!Sized), so it cannot satisfy
        // the `Any` bound required by the blanket `Stream` impl.  `ConnStream`
        // is a sized newtype that forwards `AsyncRead`/`AsyncWrite` through
        // the boxed conn, bridging `ProxyConn` → `Stream`.
        Ok(Box::new(ConnStream(conn)))
    }
}

#[cfg(feature = "kcptun")]
mod packet_conn_socket {
    //! `SocketIo` over a front proxy's UDP relay — the `dialer-proxy`
    //! counterpart of `DirectDialer`'s raw `UdpSocket`. `ProxyPacketConn`
    //! is async rather than poll-based, so two pump tasks bridge it to
    //! bounded channels; the poll side then carries ordinary channel
    //! backpressure semantics. Both tasks exit — and the association
    //! closes — when the socket drops.

    use std::io;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use meow_transport::kcptun::SocketIo;
    use tokio::io::ReadBuf;
    use tokio::sync::mpsc;
    use tokio_util::sync::PollSender;

    /// Datagram queue depth either way — sized like a socket buffer, not a
    /// stream queue: a full queue drops a datagram and KCP retransmits.
    const QUEUE: usize = 256;

    pub struct PacketConnSocket {
        /// `Mutex` only because `Receiver`/`PollSender` are `!Sync`;
        /// `&mut` poll methods go through `get_mut`, never the lock.
        inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
        outbound: Mutex<PollSender<Vec<u8>>>,
        /// Aborted on drop: the read task parks inside `read_packet` and
        /// would otherwise outlive the socket, pinning the front-proxy UDP
        /// association open across KCP session churn. The write pump exits
        /// on its own once the `PollSender` side closes — but only after
        /// the in-flight `write_packet` completes, so a wedged front-proxy
        /// conn would pin it indefinitely; abort that one too.
        read_task: tokio::task::JoinHandle<()>,
        write_task: tokio::task::JoinHandle<()>,
    }

    impl Drop for PacketConnSocket {
        fn drop(&mut self) {
            self.read_task.abort();
            self.write_task.abort();
        }
    }

    impl PacketConnSocket {
        pub fn new(conn: Arc<dyn meow_common::ProxyPacketConn>, remote: SocketAddr) -> Self {
            let (in_tx, inbound) = mpsc::channel(QUEUE);
            let (outbound, mut out_rx) = mpsc::channel::<Vec<u8>>(QUEUE);

            let reader = Arc::clone(&conn);
            let read_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                // try_send drops on a full queue: KCP retransmits, same as
                // a full kernel socket buffer upstream.
                while let Ok((n, _src)) = reader.read_packet(&mut buf).await {
                    let _ = in_tx.try_send(buf[..n].to_vec());
                }
                let _ = reader.close();
            });
            let write_task = tokio::spawn(async move {
                while let Some(pkt) = out_rx.recv().await {
                    if conn.write_packet(&pkt, &remote).await.is_err() {
                        break;
                    }
                }
                let _ = conn.close();
            });

            Self {
                inbound: Mutex::new(inbound),
                outbound: Mutex::new(PollSender::new(outbound)),
                read_task,
                write_task,
            }
        }
    }

    impl SocketIo for PacketConnSocket {
        fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let sender = self.outbound.get_mut().unwrap();
            match sender.poll_reserve(cx) {
                // `send_item` after a successful reserve cannot fail to
                // enqueue — the permit is already held.
                Poll::Ready(Ok(())) => match sender.send_item(buf.to_vec()) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(_) => Poll::Ready(Err(closed())),
                },
                Poll::Ready(Err(_)) => Poll::Ready(Err(closed())),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.inbound.get_mut().unwrap().poll_recv(cx) {
                // Datagram semantics: an oversized packet truncates.
                Poll::Ready(Some(pkt)) => {
                    let n = pkt.len().min(buf.remaining());
                    buf.put_slice(&pkt[..n]);
                    Poll::Ready(Ok(()))
                }
                // The read pump exited — the association is gone.
                Poll::Ready(None) => Poll::Ready(Err(closed())),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    fn closed() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "udp endpoint closed")
    }
}

#[cfg(feature = "kcptun")]
use packet_conn_socket::PacketConnSocket;

/// Build the `Metadata` for a chained front-hop dial by `host`/`port`.
///
/// An IP-literal `host` becomes a typed `dst_ip` so the front proxy encodes
/// an IP address rather than a domain name that happens to look like one.
/// `conn_type` is explicit `Inner`: `Metadata::default()` would yield
/// `ConnType::Http` (the first enum variant), but this is an internal
/// chained-relay dial — the front proxy's rules, /connections list, and
/// stats must not classify it as an HTTP inbound.
///
/// `internal` carries the caller's usage-accounting marker through the
/// reconstruction — otherwise a probe or fetch chained through
/// `dialer-proxy` would reach a lazy front-hop group as ordinary `Inner`
/// traffic and be counted as use, keeping the group's probe loop awake
/// forever (issue #555).
fn inner_dial_metadata(host: &str, port: u16, internal: bool) -> Metadata {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            dst_ip: Some(ip),
            dst_port: port,
            internal,
            ..Default::default()
        },
        Err(_) => Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            host: host.into(),
            dst_port: port,
            internal,
            ..Default::default()
        },
    }
}

/// Same as [`inner_dial_metadata`] for a typed `SocketAddr`: carries the
/// literal in `dst_ip` rather than rendering it into `host`, so adapters
/// emit an IP-typed address — what mihomo does and what SOCKS5/Trojan/VLESS
/// address encoding expects.
fn inner_dial_metadata_at(addr: SocketAddr, internal: bool) -> Metadata {
    Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        dst_ip: Some(addr.ip()),
        dst_port: addr.port(),
        internal,
        ..Default::default()
    }
}

#[async_trait]
impl TcpDialer for ProxyDialer {
    async fn dial(&self, host: &str, port: u16, internal: bool) -> io::Result<Box<dyn Stream>> {
        self.dial_metadata(inner_dial_metadata(host, port, internal))
            .await
    }

    async fn dial_addr(&self, addr: SocketAddr, internal: bool) -> io::Result<Box<dyn Stream>> {
        self.dial_metadata(inner_dial_metadata_at(addr, internal))
            .await
    }

    fn is_proxy(&self) -> bool {
        true
    }

    #[cfg(feature = "kcptun")]
    async fn dial_udp_endpoint(
        &self,
        remote: SocketAddr,
    ) -> io::Result<Box<dyn meow_transport::kcptun::SocketIo>> {
        // `proxyDialer.ListenPacket` upstream: the datagram endpoint is the
        // front proxy's UDP relay association to `remote`. `ConnType::Inner`
        // like `dial()` — this is infrastructure traffic, not user inbound.
        // `internal` stays false by the same rule as mux session
        // establishment: the pooled kcptun session is the ONLY dial signal
        // a lazy front hop sees for this chain — per-stream `open_stream`
        // calls never re-dial while a session lives — so marking it
        // internal would leave the front hop permanently "unused" while
        // user traffic flows (issue #555 boundary).
        let meta = Metadata {
            network: Network::Udp,
            conn_type: ConnType::Inner,
            dst_ip: Some(remote.ip()),
            dst_port: remote.port(),
            ..Default::default()
        };
        let conn = self
            .proxy
            .dial_udp(&meta)
            .await
            .map_err(|e| io::Error::other(format!("dialer-proxy udp: {e}")))?;
        Ok(Box::new(PacketConnSocket::new(Arc::from(conn), remote)))
    }
}

/// An immutable snapshot of a finished config build, shared with every
/// `dialer-proxy` bound from it.
pub type ProxySnapshot = Arc<HashMap<SmolStr, Arc<dyn Proxy>>>;

/// Shared cell a [`ProxyRegistry`] publishes into and [`DialerTarget`]s
/// resolve through. The cell is the *generation anchor*: keeping it alive
/// keeps the published snapshot — and every adapter inside it — alive.
pub type RegistryCell = RwLock<Option<ProxySnapshot>>;

/// The proxies built from one config, published when the build completes and
/// consulted by name on every chained dial.
///
/// mihomo resolves `dialer-proxy` the same way (`component/proxydialer/byname.go`).
/// Capturing the front proxy as an `Arc` while the config is still being built
/// freezes a stale entry instead: proxy groups clone their members before the
/// dialer pass replaces them, and a group-valued dialer does not exist yet when
/// the outbound chaining through it is built (issue #513).
///
/// # Ownership (issue #533)
///
/// [`DialerTarget`] holds the cell **weakly** — a strong edge would close
/// `registry → snapshot → adapter → registry` into a reference cycle that
/// leaks every superseded route generation. Whoever retains adapters built
/// from a build must therefore also retain this handle for as long as those
/// adapters may dial: the tunnel keeps it inside `RouteTable`, and provider
/// fetch contexts keep a clone so a retained download adapter still resolves
/// its front hop after later rebuilds. When the last handle drops, chained
/// adapters of that generation fail closed at dial time.
#[derive(Clone, Default)]
pub struct ProxyRegistry {
    proxies: Arc<RegistryCell>,
}

impl ProxyRegistry {
    /// Publish the finished registry. Called once per config build, after every
    /// leaf proxy and group exists; a rebuild publishes into its own registry,
    /// so adapters from a previous config keep resolving their own snapshot.
    pub fn publish(&self, proxies: ProxySnapshot) {
        // Swap under the lock but drop the superseded snapshot — which runs
        // every adapter destructor — outside it.
        let old = self.proxies.write().replace(proxies);
        drop(old);
    }

    /// The weak edge [`DialerTarget`] stores. An upgrade succeeds only while
    /// some [`ProxyRegistry`] clone still owns the cell.
    pub fn downgrade(&self) -> Weak<RegistryCell> {
        Arc::downgrade(&self.proxies)
    }

    /// Resolve `name` against the currently published snapshot — `None` when
    /// no generation has been published yet or the name is absent. For
    /// one-shot lookups (provider `proxy:` / subscription fetches); adapters
    /// that dial repeatedly keep a [`DialerTarget`] instead.
    pub fn resolve_name(&self, name: &str) -> Option<Arc<dyn Proxy>> {
        self.proxies
            .read()
            .as_ref()
            .and_then(|map| map.get(name).cloned())
    }
}

impl std::fmt::Debug for ProxyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The snapshot holds `Arc<dyn Proxy>` handles — not Debug — so report
        // only whether a generation is published, not its contents.
        f.debug_struct("ProxyRegistry")
            .field("published", &self.proxies.read().is_some())
            .finish()
    }
}

/// The front hop of a `dialer-proxy` chain, addressed by name.
#[derive(Clone)]
pub struct DialerTarget {
    name: SmolStr,
    registry: Weak<RegistryCell>,
}

impl DialerTarget {
    pub fn new(name: impl Into<SmolStr>, registry: &ProxyRegistry) -> Self {
        Self {
            name: name.into(),
            registry: registry.downgrade(),
        }
    }

    /// Registry key of the front proxy, as written in the config.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `None` when the registry generation is gone, has not been published
    /// yet, or no longer holds the name. Callers must fail loudly — falling
    /// back to a direct dial would leak past a chain the user configured for
    /// policy reasons.
    pub fn resolve(&self) -> Option<Arc<dyn Proxy>> {
        self.registry.upgrade().and_then(|cell| {
            cell.read()
                .as_ref()
                .and_then(|map| map.get(&self.name).cloned())
        })
    }

    /// Error for an unresolvable target, worded for the two error types the
    /// chained dial paths report through. Distinguishes a name absent from a
    /// live registry (config names a nonexistent hop — a config bug) from a
    /// dropped generation (the route table that owned the cell was swapped —
    /// a reload crossed an in-flight dial, issue #533).
    pub fn missing_error(&self) -> String {
        if self.registry.upgrade().is_none() {
            format!(
                "dialer-proxy '{}': registry generation dropped (config reloaded mid-dial)",
                self.name
            )
        } else {
            format!("dialer-proxy '{}' is not in the proxy registry", self.name)
        }
    }
}

/// [`TcpDialer`] for a `dialer-proxy` front hop that is resolved by name at
/// dial time. Equivalent to mihomo's `proxydialer.NewByNameDialer`.
pub struct NamedProxyDialer {
    target: DialerTarget,
}

impl NamedProxyDialer {
    pub fn new(target: DialerTarget) -> Self {
        Self { target }
    }

    async fn dial_front(&self, meta: Metadata) -> io::Result<Box<dyn Stream>> {
        let front = self
            .target
            .resolve()
            .ok_or_else(|| io::Error::other(self.target.missing_error()))?;
        ProxyDialer::new(front).dial_metadata(meta).await
    }
}

tokio::task_local! {
    /// Depth of nested `dialer-proxy` chained dials on the current task.
    ///
    /// Static configs are cycle-checked at build time
    /// (`reject_group_membership_cycles`), but a *provider-sourced* node may
    /// also carry `dialer-proxy`, and group membership over provider slots is
    /// dynamic — `node → dialer G → G selects node` recurses in one task's
    /// poll chain and would exhaust the native stack. The counter lives on
    /// the task rather than in `Metadata` because every hop rebuilds the
    /// metadata it passes down (issue #489).
    static DIALER_CHAIN_DEPTH: usize;
}

/// Bound on nested `dialer-proxy` hops: the chain recurses inside one
/// task's poll chain, so an unbounded chain would exhaust the native
/// stack. 16 is far above any sane front-hop depth.
pub(crate) const MAX_DIALER_CHAIN_DEPTH: usize = 16;

/// Run `f` as one nested `dialer-proxy` hop; `over_limit` produces the
/// caller's error type when the chain exceeds [`MAX_DIALER_CHAIN_DEPTH`].
/// Every by-name dial entry point — [`NamedProxyDialer`]'s TCP and UDP
/// endpoint paths and `DialerProxyAdapter`'s relay path — funnels through
/// this so a cycle that only becomes reachable through dynamic group
/// membership degrades to a dial error instead of unbounded same-task
/// recursion.
///
/// Mux-enabled nodes are the one shape that never reaches this guard: the
/// nested dial pends on the session mutex the outer frame holds and
/// surfaces as a session-setup timeout instead — bounded, but diagnosed as
/// a timeout rather than a cycle.
pub(crate) async fn scoped_chain_dial<F, T, E>(
    target_name: &str,
    over_limit: impl FnOnce(&str) -> E,
    f: F,
) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let depth = DIALER_CHAIN_DEPTH.try_with(|d| *d).unwrap_or(0);
    if depth >= MAX_DIALER_CHAIN_DEPTH {
        return Err(over_limit(target_name));
    }
    DIALER_CHAIN_DEPTH.scope(depth + 1, f).await
}

impl NamedProxyDialer {
    async fn dial_inner(&self, meta: Metadata) -> io::Result<Box<dyn Stream>> {
        scoped_chain_dial(
            self.target.name(),
            |name| {
                io::Error::other(format!(
                    "dialer-proxy '{name}': chain exceeds {MAX_DIALER_CHAIN_DEPTH} hops; \
                     a provider member or group is routing the dial back into itself"
                ))
            },
            self.dial_front(meta),
        )
        .await
    }
}

#[async_trait]
impl TcpDialer for NamedProxyDialer {
    async fn dial(&self, host: &str, port: u16, internal: bool) -> io::Result<Box<dyn Stream>> {
        self.dial_inner(inner_dial_metadata(host, port, internal))
            .await
    }

    async fn dial_addr(&self, addr: SocketAddr, internal: bool) -> io::Result<Box<dyn Stream>> {
        self.dial_inner(inner_dial_metadata_at(addr, internal))
            .await
    }

    fn is_proxy(&self) -> bool {
        true
    }

    #[cfg(feature = "kcptun")]
    async fn dial_udp_endpoint(
        &self,
        remote: SocketAddr,
    ) -> io::Result<Box<dyn meow_transport::kcptun::SocketIo>> {
        // Same guard as `dial_inner`: a kcptun node's session setup calls
        // this through the injected dialer, so `node → group → node` cycles
        // recurse here without ever touching `dial`/`dial_addr`.
        scoped_chain_dial(
            self.target.name(),
            |name| {
                io::Error::other(format!(
                    "dialer-proxy '{name}': chain exceeds {MAX_DIALER_CHAIN_DEPTH} hops; \
                     a provider member or group is routing the dial back into itself"
                ))
            },
            async {
                let front = self
                    .target
                    .resolve()
                    .ok_or_else(|| io::Error::other(self.target.missing_error()))?;
                ProxyDialer::new(front).dial_udp_endpoint(remote).await
            },
        )
        .await
    }
}

/// Wrap a `Box<dyn ProxyConn>` as a `meow_transport::Stream`.
///
/// `Stream` requires `Sized + Any`; `Box<dyn ProxyConn>` is `!Sized`, so it
/// cannot use the blanket `Stream` impl.  This newtype forwards
/// `AsyncRead`/`AsyncWrite` through the boxed conn.
///
/// Downcast-based optimizations are unaffected: the transport layers wrap
/// whatever they are handed in their own concrete type (e.g.
/// `RealityTlsStream` holds its inner stream as a `Box<dyn Stream>`), so
/// `as_any_mut()` still sees that outer type and the Reality raw-passthrough
/// shortcut fires the same whether the bottom of the stack is a `TcpStream` or
/// a `ConnStream`.
pub struct ConnStream(pub Box<dyn ProxyConn>);

impl tokio::io::AsyncRead for ConnStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ConnStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Unpin for ConnStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{
        AdapterType, DelayHistory, ProxyAdapter, ProxyHealth, ProxyPacketConn, Result as MeowResult,
    };
    use std::sync::Mutex;

    /// Front-proxy mock: captures the [`Metadata`] of every `dial_tcp` call
    /// and refuses the connection. The captured metadata is what the front
    /// proxy's rule engine, `/connections` list, and stats would see.
    struct CapturingProxy {
        seen: Mutex<Vec<Metadata>>,
    }

    #[async_trait]
    impl ProxyAdapter for CapturingProxy {
        fn name(&self) -> &str {
            "front"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Socks5
        }
        fn addr(&self) -> &str {
            "127.0.0.1:1080"
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(&self, metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
            self.seen.lock().unwrap().push(metadata.clone());
            Err(meow_common::MeowError::NotSupported(
                "test mock refuses connections".to_string(),
            ))
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
            unimplemented!("test mock has no UDP")
        }
        fn health(&self) -> &ProxyHealth {
            static H: std::sync::OnceLock<ProxyHealth> = std::sync::OnceLock::new();
            H.get_or_init(ProxyHealth::new)
        }
    }

    impl Proxy for CapturingProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
    }

    fn last_seen(mock: &CapturingProxy) -> Metadata {
        let seen = mock.seen.lock().unwrap();
        seen.last()
            .expect("a dial must reach the front proxy")
            .clone()
    }

    #[tokio::test]
    async fn proxy_dialer_dials_are_inner_tcp_connections() {
        // Review B2: `Metadata::default()` carries `ConnType::Http` (the
        // first enum variant), but a dialer-proxy chained relay is an
        // internal connection. The front proxy must see `ConnType::Inner`
        // + `Network::Tcp` so its rules route it as infrastructure traffic
        // and `/connections`/stats don't mislabel it as an HTTP inbound.
        let mock = Arc::new(CapturingProxy {
            seen: Mutex::new(Vec::new()),
        });
        let dialer = ProxyDialer::new(Arc::clone(&mock) as Arc<dyn Proxy>);

        // Hostname target — dial() must produce host + port metadata.
        let _ = dialer.dial("chain.example", 443, false).await;
        let meta = last_seen(&mock);
        assert_eq!(meta.conn_type, ConnType::Inner);
        assert_eq!(meta.network, Network::Tcp);
        assert_eq!(meta.host.as_str(), "chain.example");
        assert_eq!(meta.dst_port, 443);
        assert!(!meta.internal);

        // Internal traffic keeps the `Inner` conn_type but carries the
        // marker through the reconstruction, so a lazy front-hop group
        // would not count this dial as user traffic.
        let _ = dialer.dial("chain.example", 443, true).await;
        let meta = last_seen(&mock);
        assert_eq!(meta.conn_type, ConnType::Inner);
        assert!(meta.internal);

        // IP-literal target through dial() — typed dst_ip, no host string.
        let _ = dialer.dial("192.0.2.9", 853, false).await;
        let meta = last_seen(&mock);
        assert_eq!(meta.conn_type, ConnType::Inner);
        assert_eq!(meta.network, Network::Tcp);
        assert_eq!(meta.dst_ip, Some("192.0.2.9".parse().unwrap()));
        assert_eq!(meta.dst_port, 853);
        assert!(!meta.internal);

        // The internal arm of the same IP-literal path — the marker rides
        // the `Ok(ip)` rebuild branch too.
        let _ = dialer.dial("192.0.2.9", 853, true).await;
        let meta = last_seen(&mock);
        assert_eq!(meta.conn_type, ConnType::Inner);
        assert_eq!(meta.dst_ip, Some("192.0.2.9".parse().unwrap()));
        assert!(meta.internal);

        // SocketAddr target through dial_addr() — typed dst_ip + marker.
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let _ = dialer.dial_addr(addr, true).await;
        let meta = last_seen(&mock);
        assert_eq!(meta.conn_type, ConnType::Inner);
        assert_eq!(meta.network, Network::Tcp);
        assert_eq!(meta.dst_ip, Some(addr.ip()));
        assert!(meta.internal);
        assert_eq!(meta.dst_port, 443);

        assert_eq!(mock.seen.lock().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn named_proxy_dialer_forwards_internal_marker() {
        // `NamedProxyDialer` is the dialer every `dialer-proxy` adapter
        // actually receives — the production path for #555. It must
        // forward `internal` into `ProxyDialer`'s reconstruction, or the
        // lazy front-hop group counts housekeeping dials as use while
        // every `ProxyDialer` test still passes.
        let registry = ProxyRegistry::default();
        let mock = Arc::new(CapturingProxy {
            seen: Mutex::new(Vec::new()),
        });
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(SmolStr::from("front"), Arc::clone(&mock) as Arc<dyn Proxy>);
        registry.publish(Arc::new(proxies));

        let dialer = NamedProxyDialer::new(DialerTarget::new("front", &registry));
        let _ = dialer.dial("chain.example", 443, true).await;
        let meta = last_seen(&mock);
        assert_eq!(meta.conn_type, ConnType::Inner);
        assert!(meta.internal, "internal must survive NamedProxyDialer");

        let _ = dialer.dial("chain.example", 443, false).await;
        assert!(!last_seen(&mock).internal, "user dials stay unmarked");

        let addr: SocketAddr = "192.0.2.10:8443".parse().unwrap();
        let _ = dialer.dial_addr(addr, true).await;
        assert!(last_seen(&mock).internal, "dial_addr forwards it too");
    }

    #[tokio::test]
    async fn internal_marker_survives_reconstruction_for_lazy_groups() {
        // #555: housekeeping dials chained through `dialer-proxy` reach the
        // front hop as `ConnType::Inner` — the `internal` flag must carry
        // the usage-accounting marker across the reconstruction, or a lazy
        // front-hop group counts every probe/fetch as use and its probe
        // loop never goes idle.
        use crate::group::fallback::FallbackGroup;
        use crate::group::test_support::MockProxy;

        let member = MockProxy::new("member");
        let group = Arc::new(FallbackGroup::new("lazy-fb", vec![member]));
        let dialer = ProxyDialer::new(Arc::clone(&group) as Arc<dyn Proxy>);

        // Housekeeping dial (probe/fetch) — the marker reaches the group.
        let _ = dialer.dial("chain.example", 443, true).await;
        assert_eq!(
            group.usage_generation(),
            0,
            "internal chained dial must not record group use"
        );

        // Real user traffic through the same chain still counts.
        let _ = dialer.dial("chain.example", 443, false).await;
        assert_eq!(
            group.usage_generation(),
            1,
            "user chained dial records group use"
        );
    }

    /// `DialerTarget` holds the registry cell weakly (issue #533): it resolves
    /// while a `ProxyRegistry` clone keeps the generation alive and fails
    /// closed once the last owner drops — the cycle the strong edge used to
    /// pin forever now dies with its generation.
    #[test]
    fn target_resolves_while_owned_and_fails_closed_after_drop() {
        let registry = ProxyRegistry::default();
        let target = DialerTarget::new("front", &registry);
        // Unpublished cell: alive but empty.
        assert!(target.resolve().is_none());

        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(
            SmolStr::from("front"),
            Arc::new(CapturingProxy {
                seen: Mutex::new(Vec::new()),
            }),
        );
        registry.publish(Arc::new(proxies));
        assert!(target.resolve().is_some());

        // A clone keeps the cell alive; dropping one handle is not enough.
        let retained = registry.clone();
        drop(registry);
        assert!(target.resolve().is_some());
        drop(retained);
        assert!(target.resolve().is_none());
    }

    /// `NamedProxyDialer` is the chained path most adapters take — its
    /// fail-closed arm must surface the dead-registry error, never fall
    /// through to direct egress (issue #533 review).
    #[tokio::test]
    async fn named_proxy_dialer_fails_closed_when_registry_drops() {
        let registry = ProxyRegistry::default();
        let dialer = NamedProxyDialer::new(DialerTarget::new("ghost", &registry));
        drop(registry);

        let err = dialer
            .dial("example.com", 443, false)
            .await
            .err()
            .expect("a dead registry must fail the dial");
        assert!(
            err.to_string().contains("registry generation dropped"),
            "expected the dead-cell error, got: {err}"
        );
    }

    /// A `dialer-proxy` cycle that static analysis cannot see — here a
    /// provider-member-style loop where `loop`'s own dial re-enters the
    /// by-name dialer — must degrade to a dial error at
    /// [`MAX_DIALER_CHAIN_DEPTH`] instead of recursing until the native
    /// stack overflows (issue #489).
    #[tokio::test]
    async fn named_dialer_recursion_is_depth_bounded() {
        struct LoopProxy {
            dialer: NamedProxyDialer,
        }

        #[async_trait]
        impl ProxyAdapter for LoopProxy {
            fn name(&self) -> &str {
                "loop"
            }
            fn adapter_type(&self) -> AdapterType {
                AdapterType::Socks5
            }
            fn addr(&self) -> &str {
                "127.0.0.1:1"
            }
            fn support_udp(&self) -> bool {
                false
            }
            async fn dial_tcp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
                // Re-enter the by-name chain — the loop only terminates via
                // the depth guard.
                self.dialer
                    .dial("127.0.0.1", 1, false)
                    .await
                    .map_err(|e| meow_common::MeowError::Proxy(e.to_string()))?;
                Err(meow_common::MeowError::NotSupported(
                    "unreachable past the depth bound".to_string(),
                ))
            }
            async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
                unimplemented!("test mock has no UDP")
            }
            fn health(&self) -> &ProxyHealth {
                static H: std::sync::OnceLock<ProxyHealth> = std::sync::OnceLock::new();
                H.get_or_init(ProxyHealth::new)
            }
        }

        impl Proxy for LoopProxy {
            fn alive(&self) -> bool {
                true
            }
            fn alive_for_url(&self, _url: &str) -> bool {
                true
            }
            fn last_delay(&self) -> u16 {
                0
            }
            fn last_delay_for_url(&self, _url: &str) -> u16 {
                0
            }
            fn delay_history(&self) -> Vec<DelayHistory> {
                Vec::new()
            }
        }

        let registry = ProxyRegistry::default();
        let target = DialerTarget::new("loop", &registry);
        let looper: Arc<dyn Proxy> = Arc::new(LoopProxy {
            dialer: NamedProxyDialer::new(target),
        });
        registry.publish(Arc::new(HashMap::from([(SmolStr::from("loop"), looper)])));

        // Dial through the chain; recursion must stop at the bound with a
        // named error, not a stack overflow.
        let dialer = NamedProxyDialer::new(DialerTarget::new("loop", &registry));
        let err = dialer
            .dial("203.0.113.1", 443, false)
            .await
            .err()
            .expect("the cycle must surface as an error");
        assert!(
            err.to_string().contains("exceeds"),
            "depth bound must be the surfaced error: {err}"
        );
    }

    /// The bound is pinned to exactly [`MAX_DIALER_CHAIN_DEPTH`] hops: a
    /// self-looping front must be entered that many times before the guard
    /// fires — a bound of 1 or 2 would still produce an "exceeds" error
    /// while breaking legitimate multi-hop chains.
    #[tokio::test]
    async fn named_dialer_recursion_hops_are_counted() {
        struct CountingLoop {
            dialer: NamedProxyDialer,
            dials: Arc<std::sync::atomic::AtomicUsize>,
        }

        #[async_trait]
        impl ProxyAdapter for CountingLoop {
            fn name(&self) -> &str {
                "loop"
            }
            fn adapter_type(&self) -> AdapterType {
                AdapterType::Socks5
            }
            fn addr(&self) -> &str {
                "127.0.0.1:1"
            }
            fn support_udp(&self) -> bool {
                false
            }
            async fn dial_tcp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
                self.dials
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.dialer
                    .dial("127.0.0.1", 1, false)
                    .await
                    .map_err(|e| meow_common::MeowError::Proxy(e.to_string()))?;
                Err(meow_common::MeowError::NotSupported(
                    "unreachable past the depth bound".to_string(),
                ))
            }
            async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
                unimplemented!("test mock has no UDP")
            }
            fn health(&self) -> &ProxyHealth {
                static H: std::sync::OnceLock<ProxyHealth> = std::sync::OnceLock::new();
                H.get_or_init(ProxyHealth::new)
            }
        }

        impl Proxy for CountingLoop {
            fn alive(&self) -> bool {
                true
            }
            fn alive_for_url(&self, _url: &str) -> bool {
                true
            }
            fn last_delay(&self) -> u16 {
                0
            }
            fn last_delay_for_url(&self, _url: &str) -> u16 {
                0
            }
            fn delay_history(&self) -> Vec<DelayHistory> {
                Vec::new()
            }
        }

        let registry = ProxyRegistry::default();
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let looper: Arc<dyn Proxy> = Arc::new(CountingLoop {
            dialer: NamedProxyDialer::new(DialerTarget::new("loop", &registry)),
            dials: Arc::clone(&dials),
        });
        registry.publish(Arc::new(HashMap::from([(SmolStr::from("loop"), looper)])));

        let dialer = NamedProxyDialer::new(DialerTarget::new("loop", &registry));
        dialer
            .dial("127.0.0.1", 1, false)
            .await
            .err()
            .expect("the cycle must surface as an error");
        assert_eq!(
            dials.load(std::sync::atomic::Ordering::Relaxed),
            MAX_DIALER_CHAIN_DEPTH,
            "the guard must admit exactly MAX_DIALER_CHAIN_DEPTH hops"
        );
    }

    /// The flip side of the bound: a *legal* multi-hop chain must dial
    /// end to end. A → B → C exercises the depth counter on the success
    /// path — an off-by-one that rejects depth ≥ 2 would fail here.
    #[tokio::test]
    async fn named_dialer_legal_multi_hop_chain_dials() {
        /// A front that forwards to another named hop, or records the dial
        /// when built without one.
        struct Hop {
            name: &'static str,
            next: Option<NamedProxyDialer>,
            seen: Mutex<Vec<Metadata>>,
        }

        #[async_trait]
        impl ProxyAdapter for Hop {
            fn name(&self) -> &str {
                self.name
            }
            fn adapter_type(&self) -> AdapterType {
                AdapterType::Socks5
            }
            fn addr(&self) -> &str {
                "127.0.0.1:1"
            }
            fn support_udp(&self) -> bool {
                false
            }
            async fn dial_tcp(&self, metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
                if let Some(dialer) = &self.next {
                    // `dial` yields a transport `Stream`, not a `ProxyConn` —
                    // the terminal always refuses, so this only ever
                    // propagates the downstream error.
                    dialer
                        .dial("127.0.0.1", 1, false)
                        .await
                        .map_err(|e| meow_common::MeowError::Proxy(e.to_string()))?;
                    return Err(meow_common::MeowError::NotSupported(
                        "unreachable: the terminal always refuses".to_string(),
                    ));
                }
                self.seen.lock().unwrap().push(metadata.clone());
                Err(meow_common::MeowError::NotSupported(
                    "terminal hop refuses".to_string(),
                ))
            }
            async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
                unimplemented!("test mock has no UDP")
            }
            fn health(&self) -> &ProxyHealth {
                static H: std::sync::OnceLock<ProxyHealth> = std::sync::OnceLock::new();
                H.get_or_init(ProxyHealth::new)
            }
        }

        impl Proxy for Hop {
            fn alive(&self) -> bool {
                true
            }
            fn alive_for_url(&self, _url: &str) -> bool {
                true
            }
            fn last_delay(&self) -> u16 {
                0
            }
            fn last_delay_for_url(&self, _url: &str) -> u16 {
                0
            }
            fn delay_history(&self) -> Vec<DelayHistory> {
                Vec::new()
            }
        }

        let registry = ProxyRegistry::default();
        let terminal = Arc::new(Hop {
            name: "c",
            next: None,
            seen: Mutex::new(Vec::new()),
        });
        let hop_b = Arc::new(Hop {
            name: "b",
            next: Some(NamedProxyDialer::new(DialerTarget::new("c", &registry))),
            seen: Mutex::new(Vec::new()),
        });
        let hop_a = Arc::new(Hop {
            name: "a",
            next: Some(NamedProxyDialer::new(DialerTarget::new("b", &registry))),
            seen: Mutex::new(Vec::new()),
        });
        registry.publish(Arc::new(HashMap::from([
            (SmolStr::from("a"), hop_a as Arc<dyn Proxy>),
            (SmolStr::from("b"), hop_b as Arc<dyn Proxy>),
            (SmolStr::from("c"), Arc::clone(&terminal) as Arc<dyn Proxy>),
        ])));

        let dialer = NamedProxyDialer::new(DialerTarget::new("a", &registry));
        dialer
            .dial("127.0.0.1", 1, false)
            .await
            .err()
            .expect("the terminal hop refuses");
        assert_eq!(
            terminal.seen.lock().unwrap().len(),
            1,
            "a 3-hop chain must reach the terminal front"
        );
    }

    /// `NamedProxyDialer` must produce the same `Inner`/`Tcp` metadata the
    /// `ProxyDialer` path produces — a regression would misclassify chained
    /// dials in the front proxy's rules, /connections, and stats.
    #[tokio::test]
    async fn named_dialer_metadata_matches_proxy_dialer() {
        let registry = ProxyRegistry::default();
        let front = Arc::new(CapturingProxy {
            seen: Mutex::new(Vec::new()),
        });
        registry.publish(Arc::new(HashMap::from([(
            SmolStr::from("front"),
            Arc::clone(&front) as Arc<dyn Proxy>,
        )])));

        let dialer = NamedProxyDialer::new(DialerTarget::new("front", &registry));
        // Hostname → `host` field; IP literal → typed `dst_ip`.
        let _ = dialer.dial("example.com", 443, false).await;
        let _ = dialer.dial("203.0.113.7", 8443, false).await;
        let _ = dialer
            .dial_addr("[2001:db8::1]:1080".parse().unwrap(), false)
            .await;

        let seen = front.seen.lock().unwrap();
        let [host_meta, ip_meta, v6_meta] = seen.as_slice() else {
            panic!("three dials must reach the front: {seen:?}")
        };
        assert_eq!(host_meta.host, "example.com");
        assert_eq!(host_meta.dst_ip, None);
        assert_eq!(host_meta.dst_port, 443);
        assert_eq!(ip_meta.dst_ip, Some("203.0.113.7".parse().unwrap()));
        assert!(ip_meta.host.is_empty());
        assert_eq!(v6_meta.dst_ip, Some("2001:db8::1".parse().unwrap()));
        for m in seen.iter() {
            assert_eq!(m.conn_type, ConnType::Inner);
            assert_eq!(m.network, Network::Tcp);
        }
    }

    /// The relay-wrapper entry point needs the same bound: a
    /// `DialerProxyAdapter` registered under the very name it resolves
    /// recurses through `relay_tcp` on every hop (issue #489).
    #[tokio::test]
    async fn dialer_proxy_adapter_recursion_is_depth_bounded() {
        let registry = ProxyRegistry::default();
        let target = DialerTarget::new("x", &registry);
        let inner: Arc<dyn Proxy> = Arc::new(CapturingProxy {
            seen: Mutex::new(Vec::new()),
        });
        let dpa: Arc<dyn Proxy> = Arc::new(crate::DialerProxyAdapter::new(inner, target));
        registry.publish(Arc::new(HashMap::from([(
            SmolStr::from("x"),
            Arc::clone(&dpa),
        )])));

        let err = dpa
            .dial_tcp(&Metadata::default())
            .await
            .err()
            .expect("the self-referencing wrapper must fail");
        assert!(
            err.to_string().contains("exceeds"),
            "depth bound must be the surfaced error: {err}"
        );
    }
}
