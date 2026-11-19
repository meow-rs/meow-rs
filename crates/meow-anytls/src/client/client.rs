//! AnyTLS Client implementation

use crate::client::{SessionPool, SessionPoolConfig};
use crate::padding::{PaddingFactory, SharedPaddingFactory};
use crate::session::{Session, SessionHeartbeatConfig};
use crate::util::{
    AnyTlsError, Result, TlsConnect, TransportDialer, hash_password, send_authentication,
};
use bytes::Bytes;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// Client manages connections to AnyTLS servers
///
/// TLS is supplied by the host through [`TlsConnect`]; the client dials TCP,
/// hands the socket to the hook, and speaks AnyTLS over whatever stream
/// comes back. With a [`TransportDialer`] installed the same handshake runs
/// over the chained stream that dialer returns (meow-rs `dialer-proxy`).
pub struct Client {
    password_hash: [u8; 32],
    server_addr: String,
    tls: Arc<dyn TlsConnect>,
    /// Per-client transport dialer (meow-rs `dialer-proxy` chaining).
    /// `None` dials the server with the global [`crate::util::TcpDialer`] /
    /// connect path; `Some` hands session establishment to the injected
    /// dialer. Because it is fixed per client, every session the pool
    /// hands out was established the same way — pooled sessions can never
    /// be mixed across the two transport classes.
    transport_dialer: Option<Arc<dyn TransportDialer>>,
    /// Padding factory in force for this server, shared with every session the
    /// client opens so an `UpdatePaddingScheme` push outlives the session that
    /// received it.
    padding: SharedPaddingFactory,
    session_pool: Arc<SessionPool>,
    pool_config: SessionPoolConfig,
}

impl Client {
    /// Create a new client with default session pool configuration
    pub fn new(
        password: &str,
        server_addr: String,
        tls: Arc<dyn TlsConnect>,
        padding: Arc<PaddingFactory>,
    ) -> Self {
        Self::with_pool_config(
            password,
            server_addr,
            tls,
            padding,
            crate::client::SessionPoolConfig::default(),
        )
    }

    /// Create a new client with custom session pool configuration
    pub fn with_pool_config(
        password: &str,
        server_addr: String,
        tls: Arc<dyn TlsConnect>,
        padding: Arc<PaddingFactory>,
        pool_config: crate::client::SessionPoolConfig,
    ) -> Self {
        let password_hash = hash_password(password);
        let session_pool = Arc::new(SessionPool::with_config(pool_config.clone()));

        tracing::debug!("[Client] Creating new client for server: {}", server_addr);

        Self {
            password_hash,
            server_addr,
            tls,
            transport_dialer: None,
            padding: padding.into_shared(),
            session_pool,
            pool_config,
        }
    }

    /// Install the per-client [`TransportDialer`] sessions are
    /// established through — meow-rs's `dialer-proxy` edge: the dialer
    /// returns an already-connected stream tunnelled through the front
    /// proxy, and the client runs its usual TLS handshake
    /// ([`TlsConnect::connect_stream`]) plus AnyTLS auth/session on top.
    ///
    /// Call before the first dial. Because the field is fixed for the
    /// client's life, the session pool carries exactly one transport
    /// class — chained sessions pool and reuse exactly like direct ones,
    /// and a pooled session can never be handed out against the other
    /// path. `reset_sessions` flushes either class identically.
    pub fn set_transport_dialer(&mut self, dialer: Arc<dyn TransportDialer>) {
        self.transport_dialer = Some(dialer);
    }

    /// Create a new stream by establishing or reusing a session
    /// Returns (stream, session) so the caller can use session.write_data_frame for writing
    pub async fn create_proxy_stream(
        &self,
        destination: (String, u16),
    ) -> Result<(Arc<crate::session::Stream>, Arc<crate::session::Session>)> {
        self.create_proxy_stream_with_payload(destination, None)
            .await
    }

    /// Create a new stream like [`Client::create_proxy_stream`], but write
    /// `payload` to the wire right after the destination address.
    ///
    /// Used for udp-over-tcp: sing-box's anytls inbound reads the UoT
    /// request inside `RouteConnectionEx` and only reports handshake success
    /// (SYNACK) once it has it (meow-rs issue #535). Opening no longer waits
    /// for SYNACK, so that ordering can no longer deadlock; the eager write
    /// just keeps the request in the stream's first flush.
    pub async fn create_proxy_stream_with_payload(
        &self,
        destination: (String, u16),
        payload: Option<Bytes>,
    ) -> Result<(Arc<crate::session::Stream>, Arc<crate::session::Session>)> {
        tracing::debug!(
            "[Client] create_proxy_stream: {}:{}",
            destination.0,
            destination.1
        );

        // Get or create a session
        let session = self.create_stream().await?;
        tracing::debug!("[Client] Got session for proxy stream");

        let stream = Self::open_proxy_stream(&session, destination, payload).await?;
        Ok((stream, session))
    }

    /// Open a proxy stream on an already-established session: open the
    /// stream, write the SOCKS5-form destination and the optional eager
    /// payload, and return without waiting for SYNACK.
    async fn open_proxy_stream(
        session: &Arc<Session>,
        destination: (String, u16),
        payload: Option<Bytes>,
    ) -> Result<Arc<crate::session::Stream>> {
        // Open a new stream in the session
        let (stream, synack_rx) = session.open_stream().await?;
        let mut guard = crate::session::stream::OpeningStreamGuard::new(Arc::clone(&stream));
        tracing::debug!("[Client] Opened stream {} in session", stream.id());

        // Write destination address to stream (SOCKS5 format)
        // Use session's write_data_frame to send data without needing to unwrap Arc<Stream>
        tracing::debug!(
            "[Client] Writing destination address to stream {}: {}:{}",
            stream.id(),
            destination.0,
            destination.1
        );

        // Prepare the SOCKS5 address bytes
        let (addr, port) = destination;
        let mut addr_bytes = Vec::new();

        if let Ok(ipv4) = addr.parse::<Ipv4Addr>() {
            // IPv4
            tracing::trace!("[Client] Writing IPv4 address: {:?}", ipv4);
            addr_bytes.push(0x01); // ATYP_IPV4
            addr_bytes.extend_from_slice(&ipv4.octets());
        } else if let Ok(ipv6) = addr.parse::<Ipv6Addr>() {
            // IPv6
            tracing::trace!("[Client] Writing IPv6 address: {:?}", ipv6);
            addr_bytes.push(0x04); // ATYP_IPV6
            addr_bytes.extend_from_slice(&ipv6.octets());
        } else {
            // Domain name
            tracing::trace!("[Client] Writing domain name: {}", addr);
            let domain_bytes = addr.as_bytes();
            if domain_bytes.len() > 255 {
                return Err(AnyTlsError::Protocol("Domain name too long".to_string()));
            }
            addr_bytes.push(0x03); // ATYP_DOMAIN
            addr_bytes.push(domain_bytes.len() as u8);
            addr_bytes.extend_from_slice(domain_bytes);
        }

        // Write port (2 bytes, big-endian)
        tracing::trace!("[Client] Writing port: {}", port);
        addr_bytes.extend_from_slice(&port.to_be_bytes());

        // Queue the address bytes through the session's single FIFO
        // writer — fire-and-forget like upstream anytls-go (`streamWrite`
        // never awaited the wire write). The SYN the open just enqueued
        // precedes it on the wire; awaiting the queue round-trip here was
        // pure latency on every stream open.
        let stream_id = stream.id();
        tracing::debug!(
            "[Client] Writing destination address ({} bytes) to stream {}",
            addr_bytes.len(),
            stream_id
        );

        // Queue the address bytes while `buffering` still holds, then a
        // Flush marker immediately behind them in the session FIFO — the
        // queue-ordered form of upstream's `buffering = false` after the
        // address write. The marker, not a plain `disable_buffering()`
        // here, is what pins the atomic image: while the flag holds, the
        // session writer accumulates [Settings+SYN+addr] without touching
        // the wire, and the marker's drain clears the flag inside the
        // batch so the whole image goes out as ONE padded packet —
        // independent of how drains interleaved. The eager payload
        // (below) queues behind the marker and rides the same batch.
        session
            .enqueue_data_frame(stream_id, Bytes::from(addr_bytes))
            .await?;

        // Fire-and-forget barrier: the marker's own waiter resolves when
        // the batch is written; the open needs only its FIFO position.
        session.enqueue_flush_marker()?;

        tracing::debug!(
            "[Client] Successfully queued destination address for stream {}",
            stream_id
        );

        // Eager payload (e.g. the udp-over-tcp request) goes out in its own
        // frame — same byte order on the wire as the reference client's
        // lazy first write.
        if let Some(payload) = payload
            && !payload.is_empty()
        {
            tracing::debug!(
                "[Client] Writing {} eager payload bytes to stream {}",
                payload.len(),
                stream_id
            );
            session.enqueue_data_frame(stream_id, payload).await?;
        }
        // Hand the stream back now rather than after SYNACK, as the
        // reference clients do (anytls-go / sing-anytls / mihomo
        // `CreateProxy`: write the address, return the conn). Waiting here
        // made every stream pay one extra round trip before the caller
        // could send its first byte. A refused open still closes the
        // stream: the session's SynAck arm evicts and closes it on an
        // error payload, so the caller's next read sees EOF and its next
        // write fails; the `open_stream` watchdog bounds a silent peer
        // only for v2+ sessions at sid >= 2 — any SynAck disarms it, so a
        // sid-1 or sibling-disarmed open has no session-level bound
        // (upstream `synDone` parity).
        guard.disarm();
        drop(synack_rx);
        tracing::debug!(
            "[Client] Stream {} opened, not waiting for SYNACK",
            stream_id
        );
        Ok(stream)
    }

    /// Create a new stream by establishing or reusing a session
    pub async fn create_stream(&self) -> Result<Arc<Session>> {
        // Try to get an idle session from pool
        if let Some(session) = self.session_pool.get_idle_session().await {
            tracing::debug!("[Client] Reusing idle session from pool");
            return Ok(session);
        }

        tracing::debug!("[Client] No idle session found, creating new session");
        // A pool reset landing mid-dial discards the new session (its socket
        // may predate the host's new outbound binding); redial once.
        for _ in 0..2 {
            if let Some(session) = self.create_new_session().await? {
                return Ok(session);
            }
        }
        Err(AnyTlsError::SessionClosed)
    }

    /// Close every pooled session so the next stream dials a fresh
    /// connection (see [`SessionPool::reset`]). Non-blocking.
    pub fn reset_sessions(&self) {
        self.session_pool.reset();
    }

    /// Create a new session with the server. `None` when a pool reset ran
    /// while it was being dialled: the session was closed, not pooled.
    async fn create_new_session(&self) -> Result<Option<Arc<Session>>> {
        tracing::debug!("[Client] Creating new session to {}", self.server_addr);
        let generation = self.session_pool.generation();

        // Establish the transport to the server, then run TLS on it. Two
        // shapes produce the same `Box<dyn AsyncStream>` for
        // `session_over_transport`:
        //
        // - the default dial below (global `TcpDialer` / system connect +
        //   protector) yields a `TcpStream`, handed to
        //   `TlsConnect::connect`;
        // - an injected `TransportDialer` (meow-rs `dialer-proxy`) yields
        //   an already-connected chained stream, handed to
        //   `TlsConnect::connect_stream` — TLS stays the client's so SNI,
        //   ALPN, pins and fingerprints are identical on both paths, and
        //   the session is pooled just like a direct one.
        let tls_stream = match &self.transport_dialer {
            Some(dialer) => {
                tracing::trace!(
                    "[Client] Dialling {} through the transport dialer",
                    self.server_addr
                );
                let (host, port) = crate::util::socket_protect::split_host_port(&self.server_addr)
                    .ok_or_else(|| {
                        AnyTlsError::Protocol(format!(
                            "malformed server address {} (expected host:port)",
                            self.server_addr
                        ))
                    })?;
                // The injected dialer owns reachability — resolution,
                // binding, the chain itself — so the resolve/connect
                // troubleshooting arm below does not apply here.
                let transport = dialer.dial(host, port).await.map_err(|e| {
                    tracing::error!(
                        "[Client] Transport dialer failed for {}: {}",
                        self.server_addr,
                        e
                    );
                    AnyTlsError::Io(e)
                })?;
                tracing::debug!(
                    "[Client] Chained transport established to {}",
                    self.server_addr
                );
                tracing::trace!("[Client] Starting TLS handshake over the chained stream");
                self.tls.connect_stream(transport).await.map_err(|e| {
                    tracing::error!("[Client] TLS handshake failed: {}", e);
                    e
                })?
            }
            None => {
                tracing::trace!(
                    "[Client] Connecting TCP to {} (this may trigger DNS lookup)",
                    self.server_addr
                );
                // Dial via the socket-protect helper: an installed `TcpDialer`
                // (host-app bridge, e.g. meow-common's resolver + protector stack)
                // takes the whole resolve+connect path; otherwise the fallback
                // applies the `SocketProtector` (Android) around a system-resolver
                // dial, degrading to plain `TcpStream::connect` off-Android. The
                // dialer hook matters inside VPN apps whose system DNS is a fake-IP
                // server — `lookup_host` there returns unroutable fake IPs.
                let tcp_stream = match crate::util::socket_protect::connect_tcp_addr(
                    &self.server_addr,
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::error!(
                            "[Client] Failed to connect to {}: {}",
                            self.server_addr,
                            e
                        );

                        // Provide helpful error messages
                        let error_str = format!("{}", e);
                        if error_str.contains("lookup")
                            || error_str.contains("DNS")
                            || error_str.contains("Try again")
                        {
                            tracing::error!(
                                "[Client] DNS resolution failed for '{}'",
                                self.server_addr
                            );
                            tracing::error!("[Client] Troubleshooting steps:");
                            tracing::error!(
                                "[Client]   1. Check if server address is correct: {}",
                                self.server_addr
                            );
                            tracing::error!(
                                "[Client]   2. Try using IP address instead of hostname"
                            );
                            tracing::error!(
                                "[Client]   3. Test DNS: nslookup $(echo {} | cut -d: -f1)",
                                self.server_addr
                            );
                            tracing::error!(
                                "[Client]   4. Test TCP connection: nc -zv $(echo {} | cut -d: -f1) $(echo {} | cut -d: -f2)",
                                self.server_addr,
                                self.server_addr
                            );
                        } else if error_str.contains("Connection refused") {
                            tracing::error!(
                                "[Client] Connection refused. Server may not be running or not listening on {}",
                                self.server_addr
                            );
                        } else if error_str.contains("Connection timed out") {
                            tracing::error!(
                                "[Client] Connection timed out. Check network connectivity and firewall settings"
                            );
                        }

                        return Err(AnyTlsError::Io(e));
                    }
                };
                // `connect_tcp_addr` already tuned the stream at the
                // dispatch: bridge-owned dials keep the host's keepalive
                // posture plus NODELAY; the standalone fallback got this
                // crate's defaults.
                tracing::debug!(
                    "[Client] TCP connection established to {}",
                    self.server_addr
                );

                // Perform TLS handshake through the host-supplied hook
                tracing::trace!("[Client] Starting TLS handshake");
                self.tls.connect(tcp_stream).await.map_err(|e| {
                    tracing::error!("[Client] TLS handshake failed: {}", e);
                    e
                })?
            }
        };
        tracing::debug!("[Client] TLS handshake successful");

        let session = self.session_over_transport(tls_stream).await?;

        // The session's background tasks keep it alive on their own, so
        // dropping this future while the pool-add is still pending would
        // orphan a running session that no reaper owns. Close it on drop.
        let mut guard = SessionCloseGuard::new(session.clone());

        // Store in pool
        if !self
            .session_pool
            .add_idle_session_from(session.clone(), generation)
            .await
        {
            tracing::debug!("[Client] Pool reset during dial; closing the new session");
            return Ok(None);
        }
        guard.disarm();
        tracing::debug!("[Client] Session added to pool");

        Ok(Some(session))
    }

    /// Build and start a client session on an already-handshaken TLS
    /// stream: split it, send authentication, create and start the session.
    ///
    /// Does **not** touch the session pool — callers decide whether the
    /// session is poolable (`create_new_session`) or single-purpose
    /// ([`create_proxy_stream_on_tls`]).
    async fn session_over_transport<S>(&self, tls_stream: S) -> Result<Arc<Session>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        // Send authentication
        // Split TLS stream into reader and writer
        let (reader, mut writer) = tokio::io::split(tls_stream);
        tracing::trace!("[Client] Sending authentication");
        let padding = {
            let guard = self.padding.read().await;
            Arc::clone(&guard)
        };
        send_authentication(&mut writer, &self.password_hash, &padding).await?;
        tracing::debug!("[Client] Authentication sent successfully");

        // Create session with reader and writer
        let heartbeat_config = SessionHeartbeatConfig {
            interval: self.pool_config.check_interval,
            timeout: self.pool_config.idle_timeout,
        };
        let session = Arc::new(Session::new_client(
            reader,
            writer,
            Arc::clone(&self.padding),
            Some(heartbeat_config),
        ));

        // Set sequence number for pool ordering (use timestamp-based counter)
        static SEQ_COUNTER: meow_common::atomic::AtomicU = meow_common::atomic::AtomicU::new(0);
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        let seq: u64 = SEQ_COUNTER
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .into();
        session.set_seq(seq);
        tracing::debug!("[Client] Session created with seq={}", seq);

        // Start session (send settings and start loops)
        tracing::trace!("[Client] Starting client session");
        session.clone().start_client().await?;
        tracing::debug!("[Client] Client session started successfully");

        Ok(session)
    }

    /// Open a proxy stream on a caller-supplied, already-handshaken TLS
    /// stream to this server.
    ///
    /// Used by relay chaining (`ProxyAdapter::connect_over`): the preceding
    /// hop's stream already terminates at this server and carries whatever
    /// outer transport the chain established, so only the AnyTLS
    /// authentication + session setup run here.
    ///
    /// The created session is deliberately **not** added to the shared pool:
    /// it is bound to the passed stream's lifetime, and pooling it would let
    /// a later direct `dial_tcp` silently reuse the relay channel. The
    /// caller owns the returned `Arc<Session>` and should close it when the
    /// stream is dropped.
    ///
    /// Cancellation-safe: if the host's dial timeout (5 s) drops this future
    /// mid-open, the guard — not the `Err` branch — is what closes the
    /// session.
    pub async fn create_proxy_stream_on_tls<S>(
        &self,
        tls_stream: S,
        destination: (String, u16),
    ) -> Result<(Arc<crate::session::Stream>, Arc<Session>)>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let session = self.session_over_transport(tls_stream).await?;
        // Once `start_client` has run, the session's background tasks hold
        // `Arc<Session>` references of their own: dropping this future no
        // longer destroys it. The unpooled session is invisible to the pool
        // reaper and a live server keeps answering heartbeats, so without a
        // guard it leaks (with the whole relay leg) indefinitely.
        let mut guard = SessionCloseGuard::new(session.clone());
        // No inline `session.close()` on `Err`: `Session::close` sets
        // `is_closed` in its first poll, so a close that is itself
        // cancelled mid-flight (same dial timeout) would leave the flag
        // set with the teardown half-done — and the guard's retry would
        // then early-return on `already_closed`. Dropping the armed guard
        // instead spawns a detached close that runs to completion.
        let stream = Self::open_proxy_stream(&session, destination, None).await?;
        guard.disarm();
        Ok((stream, session))
    }

    /// Stop the background cleanup task in the session pool (primarily for tests)
    pub async fn stop_session_pool_cleanup(&self) {
        self.session_pool.stop_cleanup_task().await;
    }
}

/// Close a session whose ownership has not been handed off yet if the
/// owning future is dropped.
///
/// `Session::start_client` spawns background tasks (recv loop, stream
/// writer, heartbeat) that each retain an `Arc<Session>`: once they exist,
/// dropping the caller's handle no longer destroys the session. When the
/// host's dial timeout cancels the open, or an early `?` returns, this
/// guard closes the session so the transport and tasks die with it.
///
/// `Drop` cannot `.await`, so the close is spawned — the same pattern
/// `AnytlsConn`'s `Drop` uses for its owned session. Without a runtime
/// handle the session persists until its transport dies; every caller runs
/// inside one.
struct SessionCloseGuard(Option<Arc<Session>>);

impl SessionCloseGuard {
    fn new(session: Arc<Session>) -> Self {
        Self(Some(session))
    }

    /// Ownership successfully handed to the caller/pool: leave the session
    /// running.
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for SessionCloseGuard {
    fn drop(&mut self) {
        let Some(session) = self.0.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(e) = session.close().await {
                        tracing::debug!("[Client] guarded session close failed: {e}");
                    }
                });
            }
            // Every caller runs inside a runtime; if one ever doesn't,
            // don't leave the leak silent.
            Err(_) => tracing::warn!(
                "[Client] session guard dropped without a tokio runtime; unpooled session leaks"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{AnyTlsError, TlsConnectFuture};
    use std::future::Future;
    use std::task::{Context, Waker};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;
    use tokio::time::Duration;

    /// `create_proxy_stream_on_tls` never touches the TLS hook (the caller
    /// supplies an already-handshaken stream), so a stub suffices.
    struct NoTls;

    impl TlsConnect for NoTls {
        fn connect(&self, _tcp: TcpStream) -> TlsConnectFuture<'_> {
            Box::pin(async { Err(AnyTlsError::Protocol("NoTls stub".into())) })
        }
    }

    /// Regression: a cancelled unpooled open must close its session — and
    /// with it the transport. The dial timeout can drop the open future
    /// after `start_client` has spawned the session's recv/writer/heartbeat
    /// tasks but before the stream is handed back; without
    /// `SessionCloseGuard` those tasks keep the session (and the whole
    /// relay leg underneath) alive indefinitely.
    ///
    /// The open's SYN/address frames are fire-and-forget now, so the last
    /// mid-open park is the session writer's 64-permit budget. The test
    /// saturates it on a wire the peer never drains, then drops the same
    /// composite `create_proxy_stream_on_tls` builds — an armed guard
    /// around the in-flight `open_proxy_stream` future.
    #[tokio::test]
    async fn cancelled_unpooled_open_closes_session_and_transport() {
        let client = Client::new(
            "password",
            "127.0.0.1:1".to_string(),
            Arc::new(NoTls),
            PaddingFactory::default(),
        );

        // A pipe the peer never drains: the 64-byte auth record goes out,
        // then the session writer stalls mid-write and releases no
        // permits.
        let (tls_half, mut peer) = tokio::io::duplex(160);
        let session = client.session_over_transport(tls_half).await.unwrap();

        // While `buffering` holds, classified frames fold into the
        // session buffer without a wire write — the queue drains freely
        // and its permits release at once, so the budget can never
        // saturate. Queue the same flush marker a real open gets (a
        // bare `disable_buffering` would also work, but the FIFO path is
        // what production uses). Fire-and-forget: the marker's batch
        // stalls on the small pipe mid-Settings-write, so its barrier
        // never resolves — what matters is that classification disables
        // buffering before any later-enqueued data frame is classified.
        session.enqueue_flush_marker().unwrap();

        // One queued frame holds one budget permit; queueing while the
        // stalled write releases none empties the budget, so the next
        // open's SYN enqueue parks — the in-flight point a dial-timeout
        // drop lands on. Saturation is proven by a `send_data` that can
        // no longer take a permit rather than a fixed count, so the
        // interleave between the writer drain and this task can't shift
        // where the budget runs out.
        let (first_stream, _synack_rx) = session.open_stream().await.unwrap();
        let mut queued = 0;
        loop {
            let r = tokio::time::timeout(
                Duration::from_millis(100),
                first_stream.send_data(Bytes::from_static(&[7u8; 256])),
            )
            .await;
            match r {
                Ok(Ok(())) => queued += 1,
                Ok(Err(e)) => panic!("send_data failed while saturating: {e}"),
                Err(_) => break, // permit acquire pending: budget exhausted
            }
        }
        assert!(queued > 0, "the stream must queue frames before saturating");

        {
            // `create_proxy_stream_on_tls`'s armed guard + open future.
            let _dial_guard = SessionCloseGuard::new(session.clone());
            let open = Client::open_proxy_stream(&session, ("example.com".into(), 443), None);
            tokio::pin!(open);

            // The SYN enqueue must park on the saturated budget — this is
            // the in-flight point a cancelled dial leaves behind.
            let mut cx = Context::from_waker(Waker::noop());
            match open.as_mut().poll(&mut cx) {
                std::task::Poll::Pending => {}
                std::task::Poll::Ready(Ok(_)) => {
                    panic!("open must park on the saturated session writer budget; got Ready(Ok)")
                }
                std::task::Poll::Ready(Err(e)) => panic!(
                    "open must park on the saturated session writer budget; got Ready(Err({e}))"
                ),
            }
            // `open` and the armed `_dial_guard` drop at scope end:
            // the cancellation.
        }

        // The guard must close the session: writer shutdown propagates EOF
        // to the peer. Without the fix this read pends forever.
        let mut drained = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut drained))
            .await
            .expect("session close must propagate EOF to the transport")
            .expect("read_to_end must succeed once the transport closes");
        assert!(
            !drained.is_empty(),
            "auth + settings + SYN bytes must have reached the peer"
        );
    }

    /// The injected [`crate::util::TransportDialer`] path (meow-rs
    /// `dialer-proxy`): the client dials the supplied chained stream —
    /// never a `TcpStream` — runs `TlsConnect::connect_stream` on it, and
    /// pools the session exactly like a direct one: a second open reuses
    /// it without redialling, `reset_sessions` flushes it, and the next
    /// open dials a fresh chained transport.
    #[tokio::test]
    async fn transport_dialer_sessions_pool_and_reset() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Returns the client half of a duplex pair per dial and counts;
        /// the peer half is retained so session writes never stall.
        struct DuplexDialer {
            dials: AtomicUsize,
            peers: tokio::sync::Mutex<Vec<tokio::io::DuplexStream>>,
        }

        impl crate::util::TransportDialer for DuplexDialer {
            fn dial<'a>(
                &'a self,
                host: &'a str,
                port: u16,
            ) -> crate::util::TransportDialFuture<'a> {
                Box::pin(async move {
                    assert_eq!((host, port), ("anytls.test", 443));
                    self.dials.fetch_add(1, Ordering::SeqCst);
                    let (client_half, peer_half) = tokio::io::duplex(64 * 1024);
                    self.peers.lock().await.push(peer_half);
                    Ok(Box::new(client_half) as Box<dyn crate::util::SyncStream>)
                })
            }
        }

        /// Passthrough TLS over the chained stream — reaching
        /// `connect_stream` (rather than `connect`) is itself part of the
        /// assertion.
        struct PlainTls;
        impl TlsConnect for PlainTls {
            fn connect(&self, _tcp: TcpStream) -> TlsConnectFuture<'_> {
                Box::pin(async {
                    Err(AnyTlsError::Protocol(
                        "PlainTls: TcpStream path must not be reached".into(),
                    ))
                })
            }

            fn connect_stream(
                &self,
                stream: Box<dyn crate::util::SyncStream>,
            ) -> TlsConnectFuture<'_> {
                Box::pin(async move { Ok(Box::new(stream) as Box<dyn crate::util::AsyncStream>) })
            }
        }

        let dialer = Arc::new(DuplexDialer {
            dials: AtomicUsize::new(0),
            peers: tokio::sync::Mutex::new(Vec::new()),
        });
        let mut client = Client::new(
            "password",
            "anytls.test:443".to_string(),
            Arc::new(PlainTls),
            PaddingFactory::default(),
        );
        client.set_transport_dialer(Arc::clone(&dialer) as Arc<dyn crate::util::TransportDialer>);

        client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .expect("the first stream opens over the injected dialer");
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);

        // The chained session is pooled: a second stream reuses it
        // without consulting the dialer again.
        client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .expect("the second stream reuses the pooled chained session");
        assert_eq!(
            dialer.dials.load(Ordering::SeqCst),
            1,
            "a pooled chained session must not redial the transport"
        );

        // `reset_sessions` flushes the pool whichever transport class it
        // holds; the next stream establishes a fresh chained session.
        client.reset_sessions();
        client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .expect("a post-reset stream opens a fresh session");
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
    }
}
