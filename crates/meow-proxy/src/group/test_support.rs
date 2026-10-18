//! Test-only fakes for proxy-group unit tests.
//!
//! Shared across `selector`, `urltest`, and `fallback` so each module can
//! exercise its routing logic without standing up real adapters.

use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Minimal `Proxy` impl that records dial attempts and reflects whatever
/// alive / delay the test wires up via [`set_alive`](Self::set_alive) and
/// [`set_delay`](Self::set_delay).
///
/// `dial_tcp` / `dial_udp` deliberately return an error — the group tests
/// only care about *which* member the group selected, not about completing
/// the dial.
pub struct MockProxy {
    name: String,
    health: ProxyHealth,
    udp: bool,
    adapter_type: AdapterType,
    dial_error: Option<String>,
    udp_unsupported: bool,
    pub dial_count: AtomicUsize,
    reset_count: AtomicUsize,
}

impl MockProxy {
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            health: ProxyHealth::new(),
            udp: false,
            adapter_type: AdapterType::Direct,
            dial_error: None,
            udp_unsupported: false,
            dial_count: AtomicUsize::new(0),
            reset_count: AtomicUsize::new(0),
        })
    }

    pub fn new_udp(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            health: ProxyHealth::new(),
            udp: true,
            adapter_type: AdapterType::Direct,
            dial_error: None,
            udp_unsupported: false,
            dial_count: AtomicUsize::new(0),
            reset_count: AtomicUsize::new(0),
        })
    }

    /// Mock that fails every dial with `error` and reports `adapter_type`.
    ///
    /// The dial-failure escalation tests need a non-exempt adapter type
    /// (Direct / Reject members are exempt from failure tracking) and an
    /// error message they control — e.g. one containing "connection refused"
    /// to exercise mihomo's immediate-escalation path.
    pub fn new_failing(name: &str, adapter_type: AdapterType, error: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            health: ProxyHealth::new(),
            udp: false,
            adapter_type,
            dial_error: Some(error.to_string()),
            udp_unsupported: false,
            dial_count: AtomicUsize::new(0),
            reset_count: AtomicUsize::new(0),
        })
    }

    /// Same as [`new_failing`](Self::new_failing) but UDP-capable, so the
    /// failure counts through `dial_udp` escalation paths too.
    pub fn new_failing_udp(name: &str, adapter_type: AdapterType, error: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            health: ProxyHealth::new(),
            udp: true,
            adapter_type,
            dial_error: Some(error.to_string()),
            udp_unsupported: false,
            dial_count: AtomicUsize::new(0),
            reset_count: AtomicUsize::new(0),
        })
    }

    /// Mock whose `dial_udp` returns the structural
    /// [`MeowError::UdpNotSupported`] that relay chains and dialer-proxy
    /// members produce when they cannot carry UDP. Such errors describe a
    /// capability, not health, and must never mark the member dead.
    pub fn new_udp_unsupported(name: &str, adapter_type: AdapterType) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            health: ProxyHealth::new(),
            udp: false,
            adapter_type,
            dial_error: None,
            udp_unsupported: true,
            dial_count: AtomicUsize::new(0),
            reset_count: AtomicUsize::new(0),
        })
    }

    pub fn set_alive(&self, alive: bool) {
        self.health.set_alive(alive);
    }

    /// Drives `last_delay` via the underlying history. `0` would flip the
    /// proxy to dead because `ProxyHealth::record_delay` interprets 0 as
    /// "down" — pass at least 1.
    pub fn set_delay(&self, delay: u16) {
        self.health.record_delay(delay);
    }

    pub fn dials(&self) -> usize {
        self.dial_count.load(Ordering::Relaxed)
    }

    /// `reset_sessions` calls so far.
    pub fn resets(&self) -> usize {
        self.reset_count.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl ProxyAdapter for MockProxy {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        self.adapter_type
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        self.udp
    }
    async fn dial_tcp(&self, _m: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.dial_count.fetch_add(1, Ordering::Relaxed);
        match &self.dial_error {
            Some(err) => Err(MeowError::Proxy(err.clone())),
            None => Err(MeowError::Proxy(format!("mock {} dial_tcp", self.name))),
        }
    }
    async fn dial_udp(&self, _m: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.dial_count.fetch_add(1, Ordering::Relaxed);
        if self.udp_unsupported {
            return Err(MeowError::UdpNotSupported);
        }
        match &self.dial_error {
            Some(err) => Err(MeowError::Proxy(err.clone())),
            None => Err(MeowError::Proxy(format!("mock {} dial_udp", self.name))),
        }
    }
    fn reset_sessions(&self) {
        self.reset_count.fetch_add(1, Ordering::Relaxed);
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for MockProxy {
    fn alive(&self) -> bool {
        self.health.alive()
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        self.health.alive()
    }
    fn last_delay(&self) -> u16 {
        self.health.last_delay()
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        self.health.last_delay()
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.health.delay_history()
    }
}

/// One end of an in-memory pipe as a [`ProxyConn`].
pub struct DuplexConn(pub tokio::io::DuplexStream);

impl tokio::io::AsyncRead for DuplexConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for DuplexConn {
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

impl ProxyConn for DuplexConn {}

/// What a [`StreamProxy`]'s server answers to the first request on a
/// stream: an HTTP 204, after which it keeps the stream open.
pub const REPLY: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

/// Leaf whose TCP dials succeed at once, like a lazy front: the server
/// reads the first request, then answers [`REPLY`], or, for a stream to
/// the port it audits, closes without a byte. `connect_over` passes the
/// stream through, so it also serves as the chained outbound of a relay.
pub struct StreamProxy {
    name: String,
    addr: String,
    health: ProxyHealth,
    audits: Option<u16>,
    relays: bool,
    pub dial_count: AtomicUsize,
}

impl StreamProxy {
    pub fn new(name: &str, addr: &str) -> Arc<Self> {
        Self::build(name, addr, None, true)
    }

    /// Member that closes every stream to `port` after its first request.
    pub fn auditing(name: &str, addr: &str, port: u16) -> Arc<Self> {
        Self::build(name, addr, Some(port), true)
    }

    /// Outbound whose `connect_over` is unsupported, like hysteria2.
    pub fn without_relay(name: &str, addr: &str) -> Arc<Self> {
        Self::build(name, addr, None, false)
    }

    fn build(name: &str, addr: &str, audits: Option<u16>, relays: bool) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            addr: addr.to_string(),
            health: ProxyHealth::new(),
            audits,
            relays,
            dial_count: AtomicUsize::new(0),
        })
    }

    /// See [`MockProxy::set_delay`].
    pub fn set_delay(&self, delay: u16) {
        self.health.record_delay(delay);
    }

    pub fn dials(&self) -> usize {
        self.dial_count.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl ProxyAdapter for StreamProxy {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Vless
    }
    fn addr(&self) -> &str {
        &self.addr
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        self.dial_count.fetch_add(1, Ordering::Relaxed);
        let audited = self.audits == Some(metadata.dst_port);
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if !matches!(server.read(&mut buf).await, Ok(n) if n > 0) || audited {
                return;
            }
            if server.write_all(REPLY).await.is_err() {
                return;
            }
            while matches!(server.read(&mut buf).await, Ok(n) if n > 0) {}
        });
        Ok(Box::new(DuplexConn(client)))
    }
    async fn dial_udp(&self, _m: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::UdpNotSupported)
    }
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        if !self.relays {
            return Err(MeowError::NotSupported(format!(
                "{}: connect_over not supported",
                self.name
            )));
        }
        Ok(stream)
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for StreamProxy {
    fn alive(&self) -> bool {
        self.health.alive()
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        self.health.alive()
    }
    fn last_delay(&self) -> u16 {
        self.health.last_delay()
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        self.health.last_delay()
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.health.delay_history()
    }
}
