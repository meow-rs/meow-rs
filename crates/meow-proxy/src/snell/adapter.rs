//! Snell outbound adapter — implements `ProxyAdapter` for `type: snell`.
//!
//! Wires together the v3/v4/v6 codecs, the optional simple-obfs (http/tls)
//! layer (v3–v5 only), the snell request/response framing, and the optional
//! reuse pool (`CommandConnectV2`, v4 and later).

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_transport::Stream as TransportStream;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use meow_transport::simple_obfs::client::{HttpObfs, TlsObfs};

use super::pool::{Pool, PoolStream};
use super::protocol::{connect_request, write_header, write_udp_header, Snell, UDP_REQUEST};
use super::udp::SnellPacketConn;
use super::v6::{SnellV6Mode, V6Codec};

/// What Snell version label the adapter uses. v5 servers are
/// backward-compatible with the v4 TCP client wire, matching mihomo. v6 has
/// its own record layer ([`super::v6`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnellVersion {
    V3,
    V4,
    V5,
    V6,
}

impl SnellVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            SnellVersion::V3 => "v3",
            SnellVersion::V4 => "v4",
            SnellVersion::V5 => "v5",
            SnellVersion::V6 => "v6",
        }
    }

    fn supports_reuse(self) -> bool {
        matches!(self, SnellVersion::V4 | SnellVersion::V5 | SnellVersion::V6)
    }
}

/// v6 servers serve any number of sessions per connection and kept idle
/// ones open for minutes in testing. A minute of pooling stays well inside
/// that, and [`Snell::idle_conn_alive`] catches earlier closes.
const V6_POOL_MAX_IDLE: usize = 10;
const V6_POOL_MAX_AGE: Duration = Duration::from_secs(60);

/// Optional simple-obfs wrapping the underlying TCP. Mirrors the SS adapter's
/// `BuiltinObfs` enum, but kept private to the snell module so the two
/// adapters stay independent at the type level.
#[derive(Debug, Clone)]
pub enum SnellObfs {
    None,
    Http { host: String },
    Tls { server: String },
}

pub struct SnellAdapter {
    name: String,
    server: String,
    port: u16,
    addr_str: String,
    psk: Arc<[u8]>,
    obfs: SnellObfs,
    support_udp: bool,
    pool: Option<Arc<Pool>>,
    version: SnellVersion,
    /// v6 record framing; `None` for v3–v5.
    v6: Option<V6Codec>,
    health: ProxyHealth,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
}

impl SnellAdapter {
    #[allow(
        clippy::too_many_arguments,
        reason = "snell config surface is wide; struct-of-args adds no clarity here"
    )]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        psk: &str,
        obfs: SnellObfs,
        version: SnellVersion,
        udp: bool,
        reuse: bool,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Result<Self> {
        if psk.is_empty() {
            return Err(MeowError::Config(format!(
                "snell[{name}]: psk must not be empty"
            )));
        }
        if port == 0 {
            return Err(MeowError::Config(format!(
                "snell[{name}]: port must be non-zero"
            )));
        }
        if server.is_empty() {
            return Err(MeowError::Config(format!(
                "snell[{name}]: server must not be empty"
            )));
        }
        if version == SnellVersion::V6 && !matches!(obfs, SnellObfs::None) {
            return Err(MeowError::Config(format!(
                "snell[{name}]: v6 has no obfs support"
            )));
        }
        let psk_bytes: Arc<[u8]> = Arc::from(psk.as_bytes());
        let effective_reuse = reuse && version.supports_reuse();
        debug!(
            "snell '{}' configured: version={} reuse={} udp={} obfs={}",
            name,
            version.as_str(),
            effective_reuse,
            udp,
            match &obfs {
                SnellObfs::None => "off",
                SnellObfs::Http { .. } => "http",
                SnellObfs::Tls { .. } => "tls",
            }
        );
        Ok(Self {
            name: name.to_string(),
            server: server.to_string(),
            port,
            addr_str: format!("{server}:{port}"),
            psk: psk_bytes,
            obfs,
            support_udp: udp,
            pool: match (effective_reuse, version) {
                (false, _) => None,
                (true, SnellVersion::V6) => Some(Arc::new(Pool::with_limits(
                    V6_POOL_MAX_IDLE,
                    V6_POOL_MAX_AGE,
                    u32::MAX,
                ))),
                (true, _) => Some(Arc::new(Pool::new())),
            },
            version,
            v6: (version == SnellVersion::V6)
                .then(|| V6Codec::new(SnellV6Mode::Default, psk.as_bytes())),
            health: ProxyHealth::new(),
            dialer,
        })
    }

    /// Match the v6 server's `mode` (the adapter starts in `default`).
    /// Errors for other versions.
    pub fn with_v6_mode(mut self, mode: SnellV6Mode) -> Result<Self> {
        let Some(codec) = &mut self.v6 else {
            return Err(MeowError::Config(format!(
                "snell[{}]: mode needs version 6",
                self.name
            )));
        };
        if codec.mode() != mode {
            *codec = V6Codec::new(mode, &self.psk);
        }
        debug!("snell '{}' v6 mode={}", self.name, mode.as_str());
        Ok(self)
    }

    /// Open a fresh underlying byte stream (TCP, optionally wrapped in obfs)
    /// and Snell-wrap it. No CONNECT header is sent yet.
    async fn dial_fresh(&self) -> Result<PoolStream> {
        let tcp = self
            .dialer
            // Deliberately `false` (same shape as mux/kcptun sessions): a
            // pooled conn serves a later stream with no fresh dial, so the
            // establishing dial is the only signal a lazy front hop ever
            // sees — marking it internal would hide real reuse traffic.
            .dial(&self.server, self.port, false)
            .await
            .map_err(MeowError::Io)?;
        let inner: Box<dyn TransportStream> = Box::new(tcp);
        self.wrap_stream(inner)
    }

    /// Apply Snell's optional simple-obfs layer and AEAD codec to any already
    /// connected byte stream.
    fn wrap_stream(&self, inner: Box<dyn TransportStream>) -> Result<PoolStream> {
        let inner: Box<dyn TransportStream> = match &self.obfs {
            SnellObfs::None => inner,
            SnellObfs::Http { host } => Box::new(
                HttpObfs::new(inner, host.clone(), self.port)
                    .map_err(|e| MeowError::Config(format!("snell obfs: {e}")))?,
            ),
            SnellObfs::Tls { server } => Box::new(
                TlsObfs::new(inner, server.clone())
                    .map_err(|e| MeowError::Config(format!("snell obfs: {e}")))?,
            ),
        };
        Ok(match (&self.v6, self.version) {
            (Some(codec), _) => Snell::new_v6(inner, Arc::clone(&self.psk), codec.clone()),
            (None, SnellVersion::V3) => Snell::new_v3(inner, Arc::clone(&self.psk)),
            (None, _) => Snell::new(inner, Arc::clone(&self.psk)),
        })
    }

    /// v6 TCP dial. The request (always `CommandConnectV2`: v6 servers keep
    /// every connection reusable) is deferred into the session's first
    /// record, so a pooled conn is vetted with a liveness probe instead of
    /// a header write.
    async fn dial_tcp_v6(&self, host: &str, port: u16) -> Result<Box<dyn ProxyConn>> {
        let request = connect_request(host, port, true).map_err(MeowError::Io)?;
        if let Some(pool) = &self.pool {
            while let Some((mut snell, prev_uses)) = pool.take_idle() {
                if !snell.idle_conn_alive() {
                    debug!("snell v6: dropping pooled conn closed while idle");
                    continue;
                }
                snell.reset_reply_state();
                snell.defer_request(request).map_err(MeowError::Io)?;
                return Ok(Box::new(PooledConn::new(
                    snell,
                    Some(Arc::clone(pool)),
                    prev_uses + 1,
                )));
            }
        }
        let mut snell = self.dial_fresh().await?;
        snell.defer_request(request).map_err(MeowError::Io)?;
        Ok(Box::new(PooledConn::new(
            snell,
            self.pool.as_ref().map(Arc::clone),
            1,
        )))
    }

    /// Number of idle connections currently parked in the reuse pool.
    /// Returns 0 when reuse is disabled. Exposed so integration tests can
    /// synchronize with the pool return that runs after a session completes,
    /// instead of sleeping.
    pub fn idle_pool_size(&self) -> usize {
        self.pool.as_ref().map_or(0, |pool| pool.idle_count())
    }

    fn extract_dest(metadata: &Metadata) -> Result<(String, u16)> {
        let port = metadata.dst_port;
        if !metadata.host.is_empty() {
            return Ok((metadata.host.to_string(), port));
        }
        if let Some(ip) = metadata.dst_ip {
            return Ok((ip.to_string(), port));
        }
        Err(MeowError::Proxy(
            "snell: metadata has neither host nor dst_ip".into(),
        ))
    }
}

#[async_trait]
impl ProxyAdapter for SnellAdapter {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Snell
    }
    fn addr(&self) -> &str {
        &self.addr_str
    }
    fn support_udp(&self) -> bool {
        self.support_udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let (host, port) = Self::extract_dest(metadata)?;
        debug!(
            "snell connecting to {}:{} via {} (reuse={})",
            host,
            port,
            self.addr_str,
            self.pool.is_some()
        );
        if self.v6.is_some() {
            return self.dial_tcp_v6(&host, port).await;
        }

        // Pool-first path — opensnell client.go DialTCP semantics.
        if let Some(pool) = &self.pool {
            // Two tries: a pooled conn may have been silently closed by the
            // server between sessions, in which case the header write fails
            // and we try the next/dial fresh.
            for attempt in 0..2u32 {
                let Some((mut snell, prev_uses)) = pool.take_idle() else {
                    break;
                };
                snell.reset_reply_state();
                if let Err(e) = write_header(&mut snell, &host, port, true).await {
                    debug!("snell pool conn write failed (attempt {attempt}): {e}");
                    continue;
                }
                return Ok(Box::new(PooledConn::new(
                    snell,
                    Some(Arc::clone(pool)),
                    prev_uses + 1,
                )));
            }
        }

        let mut snell = self.dial_fresh().await?;
        let reuse = self.pool.is_some();
        write_header(&mut snell, &host, port, reuse)
            .await
            .map_err(MeowError::Io)?;
        Ok(Box::new(PooledConn::new(
            snell,
            self.pool.as_ref().map(Arc::clone),
            1,
        )))
    }

    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        let (host, port) = Self::extract_dest(metadata)?;
        debug!(
            "snell connecting to {}:{} via {} over existing stream",
            host, port, self.addr_str
        );

        let inner: Box<dyn TransportStream> = Box::new(stream);
        let mut snell = self.wrap_stream(inner)?;
        if self.v6.is_some() {
            let request = connect_request(&host, port, true).map_err(MeowError::Io)?;
            snell.defer_request(request).map_err(MeowError::Io)?;
        } else {
            write_header(&mut snell, &host, port, false)
                .await
                .map_err(MeowError::Io)?;
        }
        Ok(Box::new(PooledConn::new(snell, None, 1)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.support_udp {
            return Err(MeowError::NotSupported(
                "snell UDP is disabled for this proxy (set `udp: true`)".into(),
            ));
        }
        let mut snell = self.dial_fresh().await?;
        if self.v6.is_some() {
            // Datagrams are one record each, so the request goes alone.
            snell
                .defer_request(UDP_REQUEST.to_vec())
                .map_err(MeowError::Io)?;
            snell.flush().await.map_err(MeowError::Io)?;
        } else {
            write_udp_header(&mut snell).await.map_err(MeowError::Io)?;
        }
        if self.version.supports_reuse() {
            snell.read_reply().await.map_err(MeowError::Io)?;
        }
        Ok(Box::new(SnellPacketConn::new(snell)))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ─── PooledConn ──────────────────────────────────────────────────────────────

/// `ProxyConn` that returns its underlying snell stream to a pool on drop
/// (when the pool is configured). Behaves as a transparent passthrough
/// otherwise — the v4 zero-chunk → EOF mapping happens inside `Snell` itself.
struct PooledConn {
    inner: Option<PoolStream>,
    pool: Option<Arc<Pool>>,
    uses: u32,
    local_half_close: LocalHalfClose,
    reuse_failed: bool,
}

#[derive(Clone, Copy)]
enum LocalHalfClose {
    Open,
    WritingZero,
    FlushingZero,
    Sent,
    ClosingTransport,
    Closed,
    Failed,
}

impl PooledConn {
    fn new(snell: PoolStream, pool: Option<Arc<Pool>>, uses: u32) -> Self {
        Self {
            inner: Some(snell),
            pool,
            uses,
            local_half_close: LocalHalfClose::Open,
            reuse_failed: false,
        }
    }
}

/// Finish the protocol-level half-close after the peer has already sent its
/// zero-chunk. `WritingZero` may represent either a partially-written zero
/// frame or an older pending payload frame, so keep polling empty writes until
/// the codec reports that the zero-byte input itself completed.
async fn finish_local_half_close(snell: &mut PoolStream, state: LocalHalfClose) -> io::Result<()> {
    match state {
        LocalHalfClose::Open | LocalHalfClose::WritingZero => {
            loop {
                let n =
                    std::future::poll_fn(|cx| Pin::new(&mut *snell).poll_write(cx, &[])).await?;
                if n == 0 {
                    break;
                }
            }
            snell.flush().await
        }
        LocalHalfClose::FlushingZero => snell.flush().await,
        LocalHalfClose::Sent => Ok(()),
        LocalHalfClose::ClosingTransport | LocalHalfClose::Closed | LocalHalfClose::Failed => Err(
            io::Error::other("snell: pooled connection cannot finish protocol half-close"),
        ),
    }
}

impl AsyncRead for PooledConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let inner = self
            .inner
            .as_mut()
            .expect("PooledConn::poll_read after take");
        let result = Pin::new(inner).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.reuse_failed = true;
        }
        result
    }
}

impl AsyncWrite for PooledConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let inner = self
            .inner
            .as_mut()
            .expect("PooledConn::poll_write after take");
        let result = Pin::new(inner).poll_write(cx, buf);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.reuse_failed = true;
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let inner = self
            .inner
            .as_mut()
            .expect("PooledConn::poll_flush after take");
        let result = Pin::new(inner).poll_flush(cx);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.reuse_failed = true;
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            match this.local_half_close {
                LocalHalfClose::Open => {
                    this.local_half_close = LocalHalfClose::WritingZero;
                }
                LocalHalfClose::WritingZero => {
                    let inner = this
                        .inner
                        .as_mut()
                        .expect("PooledConn::poll_shutdown after take");
                    match Pin::new(inner).poll_write(cx, &[]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            this.local_half_close = LocalHalfClose::Failed;
                            return Poll::Ready(Err(e));
                        }
                        // A non-zero result completes an older buffered
                        // payload. Poll once more to stage the zero-chunk.
                        Poll::Ready(Ok(n)) if n > 0 => continue,
                        Poll::Ready(Ok(_)) => {
                            this.local_half_close = LocalHalfClose::FlushingZero;
                        }
                    }
                }
                LocalHalfClose::FlushingZero => {
                    let inner = this
                        .inner
                        .as_mut()
                        .expect("PooledConn::poll_shutdown after take");
                    match Pin::new(inner).poll_flush(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            this.local_half_close = LocalHalfClose::Failed;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            this.local_half_close = LocalHalfClose::Sent;
                        }
                    }
                }
                LocalHalfClose::Sent
                    if this.pool.is_some()
                        || this
                            .inner
                            .as_ref()
                            .is_some_and(PoolStream::half_close_keeps_transport) =>
                {
                    return Poll::Ready(Ok(()));
                }
                LocalHalfClose::Sent => {
                    // Non-pooled v3/v4 sessions still need the underlying
                    // write side closed after their protocol zero-chunk is
                    // flushed.
                    this.local_half_close = LocalHalfClose::ClosingTransport;
                }
                LocalHalfClose::ClosingTransport => {
                    let inner = this
                        .inner
                        .as_mut()
                        .expect("PooledConn::poll_shutdown after take");
                    match Pin::new(inner).poll_shutdown(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            this.local_half_close = LocalHalfClose::Failed;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            this.local_half_close = LocalHalfClose::Closed;
                        }
                    }
                }
                LocalHalfClose::Closed => return Poll::Ready(Ok(())),
                LocalHalfClose::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "snell: previous shutdown attempt failed",
                    )));
                }
            }
        }
    }
}

impl Unpin for PooledConn {}
impl ProxyConn for PooledConn {}

impl Drop for PooledConn {
    fn drop(&mut self) {
        let (Some(snell), Some(pool)) = (self.inner.take(), self.pool.take()) else {
            return;
        };
        let uses = self.uses;

        // A raw TCP EOF or unread server tail is not reusable. In particular,
        // never drain arbitrary bytes here: doing so can swallow an old
        // session and then feed the next CONNECT_V2 header into that session.
        if self.reuse_failed || !snell.peer_half_closed() {
            return;
        }

        if matches!(self.local_half_close, LocalHalfClose::Sent) {
            let mut snell = snell;
            snell.reset_reply_state();
            pool.put(snell, uses);
            return;
        }

        let state = self.local_half_close;
        if matches!(
            state,
            LocalHalfClose::ClosingTransport | LocalHalfClose::Closed | LocalHalfClose::Failed
        ) {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        tokio::spawn(async move {
            let mut snell = snell;
            if finish_local_half_close(&mut snell, state).await.is_err() {
                return;
            }
            snell.reset_reply_state();
            pool.put(snell, uses);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::time::Duration;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::super::protocol::{COMMAND_CONNECT, HEADER_VERSION, RESPONSE_TUNNEL};
    use super::super::v3::V3Conn;

    struct TestProxyConn(DuplexStream);

    impl AsyncRead for TestProxyConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestProxyConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl ProxyConn for TestProxyConn {}

    async fn within<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("test future timed out")
    }

    #[tokio::test]
    async fn connect_over_writes_v3_connect_header_on_existing_stream() {
        let adapter = SnellAdapter::new(
            "snell",
            "unused.invalid",
            8443,
            "test-psk",
            SnellObfs::None,
            SnellVersion::V3,
            false,
            false,
            Arc::new(crate::dialer::DirectDialer),
        )
        .unwrap();
        let metadata = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Metadata::default()
        };
        let (client, server) = tokio::io::duplex(1 << 16);

        let client_fut = adapter.connect_over(Box::new(TestProxyConn(client)), &metadata);
        let server_fut = async {
            let mut server = V3Conn::new(server, Arc::from(b"test-psk".as_slice()));

            let mut got = [0u8; 17];
            server.read_exact(&mut got).await.unwrap();
            let mut expected = vec![HEADER_VERSION, COMMAND_CONNECT, 0, 11];
            expected.extend_from_slice(b"example.com");
            expected.extend_from_slice(&443u16.to_be_bytes());
            assert_eq!(&got[..], &expected[..]);

            server.write_all(&[RESPONSE_TUNNEL]).await.unwrap();
            server.write_all(b"ok").await.unwrap();
            server.flush().await.unwrap();
        };

        let (conn, ()) = within(async { tokio::join!(client_fut, server_fut) }).await;
        let mut conn = conn.unwrap();
        let mut body = [0u8; 2];
        within(conn.read_exact(&mut body)).await.unwrap();
        assert_eq!(&body, b"ok");
    }

    /// A v6 server tears the session down on transport EOF, so a
    /// half-close must stop at the zero chunk: the upstream's late reply
    /// still has to reach the client.
    #[tokio::test]
    async fn v6_half_close_keeps_the_transport_open_for_the_reply() {
        use super::super::protocol::is_zero_chunk;
        use super::super::v6::V6Conn;
        use std::task::Waker;

        let adapter = SnellAdapter::new(
            "snell",
            "unused.invalid",
            8443,
            "test-psk",
            SnellObfs::None,
            SnellVersion::V6,
            false,
            false,
            Arc::new(crate::dialer::DirectDialer),
        )
        .unwrap();
        let metadata = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Metadata::default()
        };
        let (client, server) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let mut peer = V6Conn::new(server, psk, V6Codec::new(SnellV6Mode::Default, b"test-psk"));

        let mut conn = within(adapter.connect_over(Box::new(TestProxyConn(client)), &metadata))
            .await
            .unwrap();
        within(conn.write_all(b"ping")).await.unwrap();
        within(conn.shutdown()).await.unwrap();

        let mut expected = connect_request("example.com", 443, true).unwrap();
        expected.extend_from_slice(b"ping");
        let mut got = vec![0u8; expected.len()];
        within(peer.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, expected);
        let err = within(peer.read(&mut [0u8; 1])).await.unwrap_err();
        assert!(is_zero_chunk(&err), "expected the zero chunk, got {err}");
        let mut probe = [0u8; 1];
        let polled = Pin::new(&mut peer).poll_read(
            &mut Context::from_waker(Waker::noop()),
            &mut ReadBuf::new(&mut probe),
        );
        assert!(polled.is_pending(), "half-close sent a transport FIN");

        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"late")).await.unwrap();
        within(peer.write(&[])).await.unwrap();
        within(peer.flush()).await.unwrap();
        let mut reply = Vec::new();
        within(conn.read_to_end(&mut reply)).await.unwrap();
        assert_eq!(reply, b"late");
    }
}
