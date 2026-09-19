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
    async fn dial(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>>;

    /// Dial an already-resolved [`SocketAddr`].
    ///
    /// Callers holding a literal address should prefer this over
    /// `dial(&addr.ip().to_string(), addr.port())`, which allocates a `String`
    /// only for the callee to parse it straight back into an `IpAddr`.
    /// The default implementation does exactly that round-trip, so
    /// implementors that can dial an address directly should override it.
    async fn dial_addr(&self, addr: SocketAddr) -> io::Result<Box<dyn Stream>> {
        self.dial(&addr.ip().to_string(), addr.port()).await
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
}

/// Direct TCP dialer — the default, equivalent to mihomo's `dialer.NewDialer()`.
///
/// Uses `meow_common::connect_tcp_host` which is resolver-aware and
/// SocketProtector-aware (Android `VpnService.protect(fd)` etc.).
pub struct DirectDialer;

#[async_trait]
impl TcpDialer for DirectDialer {
    async fn dial(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        let tcp = meow_common::connect_tcp_host(host, port).await?;
        // Preserve TCP_NODELAY (disable Nagle) — all call sites that
        // previously called `tcp.set_nodelay(true)` on the raw
        // `TcpStream` now rely on the dialer to do it once here.
        let _ = tcp.set_nodelay(true);
        Ok(Box::new(tcp))
    }

    async fn dial_addr(&self, addr: SocketAddr) -> io::Result<Box<dyn Stream>> {
        // Skip the default's `to_string()` + re-parse: `connect_tcp` takes the
        // `SocketAddr` as-is and keeps the SocketProtector hook.
        let tcp = meow_common::connect_tcp(addr).await?;
        let _ = tcp.set_nodelay(true);
        Ok(Box::new(tcp))
    }
}

/// Proxy dialer — tunnels through another proxy.  Equivalent to mihomo's
/// `proxyDialer.DialContext()`.
///
/// Calls `proxy.dial_tcp()` with metadata targeting `host:port`, then adapts
/// the returned `ProxyConn` into a `Stream` for the caller's transport chain.
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

#[async_trait]
impl TcpDialer for ProxyDialer {
    async fn dial(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        // An IP-literal `host` becomes a typed `dst_ip` so the front proxy
        // encodes an IP address rather than a domain name that happens to look
        // like one.
        //
        // `network` / `conn_type` are explicit: `Metadata::default()` yields
        // `ConnType::Http` (the first enum variant), but this is an internal
        // chained-relay dial — the front proxy's rules, /connections list,
        // and stats must classify it as `Inner`, not as an HTTP inbound
        // (review B2).
        let meta = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => Metadata {
                network: Network::Tcp,
                conn_type: ConnType::Inner,
                dst_ip: Some(ip),
                dst_port: port,
                ..Default::default()
            },
            Err(_) => Metadata {
                network: Network::Tcp,
                conn_type: ConnType::Inner,
                host: host.into(),
                dst_port: port,
                ..Default::default()
            },
        };
        self.dial_metadata(meta).await
    }

    async fn dial_addr(&self, addr: SocketAddr) -> io::Result<Box<dyn Stream>> {
        // Carry the literal address in `dst_ip` instead of rendering it into
        // `host`: adapters that encode the target for the front proxy then emit
        // an IP-typed address rather than a domain-typed one holding a
        // dotted-quad, which is what mihomo does and what SOCKS5/Trojan/VLESS
        // address encoding expects.
        // Explicit Inner conn_type — see `dial()` (review B2).
        let meta = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            dst_ip: Some(addr.ip()),
            dst_port: addr.port(),
            ..Default::default()
        };
        self.dial_metadata(meta).await
    }

    fn is_proxy(&self) -> bool {
        true
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
}

#[async_trait]
impl TcpDialer for NamedProxyDialer {
    async fn dial(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        let front = self
            .target
            .resolve()
            .ok_or_else(|| io::Error::other(self.target.missing_error()))?;
        ProxyDialer::new(front).dial(host, port).await
    }

    async fn dial_addr(&self, addr: SocketAddr) -> io::Result<Box<dyn Stream>> {
        let front = self
            .target
            .resolve()
            .ok_or_else(|| io::Error::other(self.target.missing_error()))?;
        ProxyDialer::new(front).dial_addr(addr).await
    }

    fn is_proxy(&self) -> bool {
        true
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
        let _ = dialer.dial("chain.example", 443).await;
        let meta = last_seen(&mock);
        assert_eq!(meta.conn_type, ConnType::Inner);
        assert_eq!(meta.network, Network::Tcp);
        assert_eq!(meta.host.as_str(), "chain.example");
        assert_eq!(meta.dst_port, 443);

        // IP-literal target through dial() — typed dst_ip, no host string.
        let _ = dialer.dial("192.0.2.9", 853).await;
        let meta = last_seen(&mock);
        assert_eq!(meta.conn_type, ConnType::Inner);
        assert_eq!(meta.network, Network::Tcp);
        assert_eq!(meta.dst_ip, Some("192.0.2.9".parse().unwrap()));
        assert_eq!(meta.dst_port, 853);

        // SocketAddr target through dial_addr() — typed dst_ip.
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let _ = dialer.dial_addr(addr).await;
        let meta = last_seen(&mock);
        assert_eq!(meta.conn_type, ConnType::Inner);
        assert_eq!(meta.network, Network::Tcp);
        assert_eq!(meta.dst_ip, Some(addr.ip()));
        assert_eq!(meta.dst_port, 443);

        assert_eq!(mock.seen.lock().unwrap().len(), 3);
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
}
