//! AnyTLS Client implementation

use crate::client::session_pool::{Checkout, CheckoutState, SessionPool, SessionPoolConfig};
use crate::padding::{PaddingFactory, SharedPaddingFactory};
use crate::session::stream::OwnerEnd;
use crate::session::{Session, SessionHeartbeatConfig, Stream};
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
    #[cfg(test)]
    pre_publish: tokio::sync::Mutex<Option<PrePublishPark>>,
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
            #[cfg(test)]
            pre_publish: tokio::sync::Mutex::new(None),
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

    /// Create a new stream by establishing or reusing a session.
    ///
    /// The returned [`PooledStream`] exclusively holds one TLS session until
    /// the stream ends and the session is returned to idle — or until the
    /// handle is dropped without FIN cleanup, which closes the session.
    pub async fn create_proxy_stream(&self, destination: (String, u16)) -> Result<PooledStream> {
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
    ) -> Result<PooledStream> {
        tracing::debug!(
            "[Client] create_proxy_stream: {}:{}",
            destination.0,
            destination.1
        );

        let checkout = self.create_stream().await?;
        tracing::debug!("[Client] Got session for proxy stream");
        let state =
            CheckoutState::from_checkout(Arc::downgrade(self.session_pool.inner()), checkout);
        let mut open_guard = CheckoutGuard::new(Arc::clone(&state));
        let session = Arc::clone(state.session());
        let stream = Self::open_proxy_stream(&session, destination, payload).await?;
        if !self.install_owner_end(&state, &stream).await {
            return Err(AnyTlsError::SessionClosed);
        }
        open_guard.disarm();
        Ok(PooledStream::from_checkout(stream, session, state))
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

    /// Create a new stream by establishing or reusing a session.
    ///
    /// At most one new dial per open: a reset that lands mid-dial closes the
    /// unpublished session and fails this call rather than starting another.
    /// Internal: callers must go through [`create_proxy_stream`] so a
    /// [`CheckoutGuard`] owns the exclusive checkout.
    async fn create_stream(&self) -> Result<Checkout> {
        match self.session_pool.checkout() {
            Ok(checkout) => {
                tracing::debug!("[Client] Reusing idle session from pool");
                Ok(checkout)
            }
            Err(generation) => {
                tracing::debug!("[Client] No idle session found, creating new session");
                self.create_new_session(generation)
                    .await?
                    .ok_or(AnyTlsError::SessionClosed)
            }
        }
    }

    async fn install_owner_end(&self, state: &Arc<CheckoutState>, stream: &Arc<Stream>) -> bool {
        let callback_state = Arc::clone(state);
        let callback = Box::new(move |end: OwnerEnd| match end {
            OwnerEnd::LocalFinCommitted | OwnerEnd::RemoteFin => {
                if callback_state.session().is_closed() {
                    callback_state.finish_discard();
                } else {
                    callback_state.finish_return();
                }
            }
            OwnerEnd::Discard => callback_state.finish_discard(),
        });
        let confirm_state = Arc::clone(state);
        state
            .session()
            .try_install_owner_end(stream, callback, move || {
                confirm_state.checkout_is_current()
            })
            .await
            .is_ok()
    }

    /// Close every pooled session so the next stream dials a fresh
    /// connection (see [`SessionPool::reset`]). Non-blocking.
    pub fn reset_sessions(&self) {
        self.session_pool.reset();
    }

    /// Create a new session with the server. `None` when a pool reset ran
    /// while it was being dialled: the session was closed, not pooled.
    async fn create_new_session(
        &self,
        generation: meow_common::atomic::Uint,
    ) -> Result<Option<Checkout>> {
        tracing::debug!("[Client] Creating new session to {}", self.server_addr);

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
        // dropping this future while the session is unpublished would
        // orphan a running session that no reaper owns. Close it on drop.
        let mut guard = SessionCloseGuard::new(session.clone());

        #[cfg(test)]
        if let Some(park) = self.pre_publish.lock().await.take() {
            park.entered.wait().await;
            let _ = park.release.await;
        }

        let Some(checkout) = self
            .session_pool
            .register_checked_out(session.clone(), generation)
        else {
            tracing::debug!("[Client] Pool reset during dial; closing the new session");
            return Ok(None);
        };
        guard.disarm();
        tracing::debug!("[Client] Session registered as checked out");

        Ok(Some(checkout))
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

    /// Session pool used by this client. Tests in other crates observe
    /// live/idle counts through this accessor.
    pub fn session_pool(&self) -> &SessionPool {
        &self.session_pool
    }

    #[cfg(test)]
    async fn set_pre_publish_park(
        &self,
        entered: Arc<tokio::sync::Barrier>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        *self.pre_publish.lock().await = Some(PrePublishPark { entered, release });
    }
}

#[cfg(test)]
struct PrePublishPark {
    entered: Arc<tokio::sync::Barrier>,
    release: tokio::sync::oneshot::Receiver<()>,
}

/// Pooled proxy stream: exclusive checkout plus a Drop fallback that closes
/// the session if FIN cleanup never starts.
pub struct PooledStream {
    stream: Arc<Stream>,
    session: Arc<Session>,
    guard: Option<CheckoutGuard>,
}

impl PooledStream {
    fn from_checkout(
        stream: Arc<Stream>,
        session: Arc<Session>,
        state: Arc<CheckoutState>,
    ) -> Self {
        Self {
            stream,
            session,
            guard: Some(CheckoutGuard::new(state)),
        }
    }

    pub fn id(&self) -> u32 {
        self.stream.id()
    }

    pub fn stream(&self) -> &Arc<Stream> {
        &self.stream
    }

    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }

    /// Enqueue FIN and keep the checkout guard alive until owner-end.
    /// A later Drop of this handle is then a no-op.
    pub fn start_close(&mut self) {
        self.stream.close();
        let Some(guard) = self.guard.take() else {
            return;
        };
        let Some(state) = guard.state_arc() else {
            return;
        };
        let handle = self
            .session
            .runtime_handle()
            .cloned()
            .or_else(|| tokio::runtime::Handle::try_current().ok());
        match handle {
            Some(handle) => {
                handle.spawn(async move {
                    let notified = state.done().notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if !state.is_completed() {
                        tokio::select! {
                            biased;
                            () = notified => {}
                            () = state.session().wait_closed() => {
                                state.finish_discard();
                            }
                        }
                    }
                    drop(guard);
                });
            }
            None => drop(guard),
        }
    }

    /// FIN the stream and wait until the checkout is returned or discarded.
    /// Cancelling this future discards the checkout (closes the session).
    pub async fn close(self) {
        let state = self.guard.as_ref().and_then(CheckoutGuard::state_arc);
        self.stream.close();
        if let Some(state) = state {
            let notified = state.done().notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !state.is_completed() {
                notified.await;
            }
        }
    }
}

/// Covers create_stream → successful open_proxy_stream. Drop discards the
/// checkout and closes the session.
struct CheckoutGuard(Option<Arc<CheckoutState>>);

impl CheckoutGuard {
    fn new(state: Arc<CheckoutState>) -> Self {
        Self(Some(state))
    }

    fn state_arc(&self) -> Option<Arc<CheckoutState>> {
        self.0.clone()
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for CheckoutGuard {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            state.finish_discard();
        }
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
/// `Drop` cannot `.await`, so the close is spawned on the session's
/// stored runtime Handle.
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
        session.spawn_close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{AnyTlsError, TlsConnectFuture};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
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

    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf as IoReadBuf};
    use tokio::sync::{Barrier, Mutex as TokioMutex};

    struct DialStats {
        dials: AtomicUsize,
        drops: AtomicUsize,
        shutdowns: AtomicUsize,
        /// Peer write halves: tests inject remote FINs here.
        peers: TokioMutex<Vec<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
        /// Drain tasks holding the matching read halves so session writes
        /// cannot fill the 64 KiB duplex and trip CONTROL_WRITE_TIMEOUT.
        drain_handles: TokioMutex<Vec<tokio::task::JoinHandle<()>>>,
        /// Held unread peer read halves when [`Self::drain_reads`] is false.
        undrained_reads: TokioMutex<Vec<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
        /// Drain peer reads by default so sequential churn cannot stall.
        drain_reads: AtomicBool,
        /// 1-based dial index to park on, or 0.
        block_on: AtomicUsize,
        block_entered: TokioMutex<Option<Arc<Barrier>>>,
        block_release: TokioMutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        pause_writes: AtomicBool,
        pause_waker: std::sync::Mutex<Option<Waker>>,
        saw_pause: tokio::sync::Notify,
        /// Inject a write error on the client transport (FIN-write failure).
        fail_writes: AtomicBool,
    }

    impl DialStats {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                dials: AtomicUsize::new(0),
                drops: AtomicUsize::new(0),
                shutdowns: AtomicUsize::new(0),
                peers: TokioMutex::new(Vec::new()),
                drain_handles: TokioMutex::new(Vec::new()),
                undrained_reads: TokioMutex::new(Vec::new()),
                drain_reads: AtomicBool::new(true),
                block_on: AtomicUsize::new(0),
                block_entered: TokioMutex::new(None),
                block_release: TokioMutex::new(None),
                pause_writes: AtomicBool::new(false),
                pause_waker: std::sync::Mutex::new(None),
                saw_pause: tokio::sync::Notify::new(),
                fail_writes: AtomicBool::new(false),
            })
        }
    }

    struct CountedStream {
        inner: tokio::io::DuplexStream,
        stats: Arc<DialStats>,
    }

    impl Drop for CountedStream {
        fn drop(&mut self) {
            self.stats.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl AsyncRead for CountedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut IoReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for CountedStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.stats.fail_writes.load(Ordering::SeqCst) {
                return Poll::Ready(Err(std::io::Error::other("injected write failure")));
            }
            if self.stats.pause_writes.load(Ordering::SeqCst) {
                *self.stats.pause_waker.lock().unwrap() = Some(cx.waker().clone());
                self.stats.saw_pause.notify_waiters();
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            if self.stats.fail_writes.load(Ordering::SeqCst) {
                return Poll::Ready(Err(std::io::Error::other("injected write failure")));
            }
            if self.stats.pause_writes.load(Ordering::SeqCst) {
                *self.stats.pause_waker.lock().unwrap() = Some(cx.waker().clone());
                self.stats.saw_pause.notify_waiters();
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.stats.shutdowns.fetch_add(1, Ordering::SeqCst);
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct DuplexDialer {
        stats: Arc<DialStats>,
    }

    impl crate::util::TransportDialer for DuplexDialer {
        fn dial<'a>(&'a self, host: &'a str, port: u16) -> crate::util::TransportDialFuture<'a> {
            Box::pin(async move {
                assert_eq!((host, port), ("anytls.test", 443));
                let n = self.stats.dials.fetch_add(1, Ordering::SeqCst) + 1;
                if n == self.stats.block_on.load(Ordering::SeqCst) {
                    if let Some(entered) = self.stats.block_entered.lock().await.clone() {
                        entered.wait().await;
                    }
                    if let Some(release) = self.stats.block_release.lock().await.take() {
                        let _ = release.await;
                    }
                }
                let (client_half, peer_half) = tokio::io::duplex(64 * 1024);
                let (peer_read, peer_write) = tokio::io::split(peer_half);
                if self.stats.drain_reads.load(Ordering::SeqCst) {
                    let drain = tokio::spawn(async move {
                        let mut peer_read = peer_read;
                        let mut buf = [0u8; 4096];
                        loop {
                            match tokio::io::AsyncReadExt::read(&mut peer_read, &mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    });
                    self.stats.drain_handles.lock().await.push(drain);
                } else {
                    self.stats.undrained_reads.lock().await.push(peer_read);
                }
                self.stats.peers.lock().await.push(peer_write);
                Ok(Box::new(CountedStream {
                    inner: client_half,
                    stats: Arc::clone(&self.stats),
                }) as Box<dyn crate::util::SyncStream>)
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

        fn connect_stream(&self, stream: Box<dyn crate::util::SyncStream>) -> TlsConnectFuture<'_> {
            Box::pin(async move { Ok(Box::new(stream) as Box<dyn crate::util::AsyncStream>) })
        }
    }

    fn pooled_client(stats: &Arc<DialStats>) -> Client {
        let mut client = Client::new(
            "password",
            "anytls.test:443".to_string(),
            Arc::new(PlainTls),
            PaddingFactory::default(),
        );
        client.set_transport_dialer(Arc::new(DuplexDialer {
            stats: Arc::clone(stats),
        }) as Arc<dyn crate::util::TransportDialer>);
        client
    }

    async fn wait_pool(client: &Client, live: usize, idle: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if client.session_pool().live_len() == live
                    && client.session_pool().idle_len() == idle
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "pool did not reach live={live} idle={idle} (live={} idle={})",
                client.session_pool().live_len(),
                client.session_pool().idle_len()
            )
        });
    }

    /// The injected [`crate::util::TransportDialer`] path (meow-rs
    /// `dialer-proxy`): concurrent streams each own a session; sequential
    /// reuse skips the handshake; reset forces a new dial.
    #[tokio::test]
    async fn transport_dialer_sessions_pool_and_reset() {
        let stats = DialStats::new();
        let client = Arc::new(pooled_client(&stats));
        const N: usize = 4;
        let hold = Arc::new(Barrier::new(N + 1));
        let mut handles = Vec::new();
        for _ in 0..N {
            let client = Arc::clone(&client);
            let hold = Arc::clone(&hold);
            handles.push(tokio::spawn(async move {
                let stream = client
                    .create_proxy_stream(("example.com".into(), 443))
                    .await
                    .expect("concurrent open");
                hold.wait().await;
                stream
            }));
        }
        hold.wait().await;
        assert_eq!(stats.dials.load(Ordering::SeqCst), N);
        assert_eq!(client.session_pool().live_len(), N);
        assert_eq!(client.session_pool().idle_len(), 0);
        let mut session_ids = Vec::new();
        let mut streams = Vec::new();
        for handle in handles {
            let stream = handle.await.unwrap();
            session_ids.push(stream.session().id());
            streams.push(stream);
        }
        session_ids.sort_unstable();
        session_ids.dedup();
        assert_eq!(
            session_ids.len(),
            N,
            "concurrent streams use distinct sessions"
        );

        for stream in streams {
            stream.close().await;
        }
        wait_pool(&client, N, N).await;
        assert_eq!(
            stats.dials.load(Ordering::SeqCst),
            N,
            "return must not redial"
        );

        let first = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .expect("serial open");
        let first_id = first.session().id();
        first.close().await;
        wait_pool(&client, N, N).await;
        let second = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .expect("serial reuse");
        assert_eq!(second.session().id(), first_id);
        assert_eq!(stats.dials.load(Ordering::SeqCst), N);
        second.close().await;
        wait_pool(&client, N, N).await;

        client.reset_sessions();
        wait_pool(&client, 0, 0).await;
        client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .expect("a post-reset stream opens a fresh session")
            .close()
            .await;
        assert_eq!(stats.dials.load(Ordering::SeqCst), N + 1);
        wait_pool(&client, 1, 1).await;
    }

    #[tokio::test]
    async fn bare_drop_closes_transport_without_pooling() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let stream = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        drop(stream);
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.drops.load(Ordering::SeqCst) == 0
                && stats.shutdowns.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bare drop must close the transport");
    }

    #[tokio::test]
    async fn late_drop_after_return_does_not_close_next_checkout() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let mut first = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        first.start_close();
        wait_pool(&client, 1, 1).await;
        let second = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        let second_id = second.session().id();
        drop(first);
        assert_eq!(client.session_pool().live_len(), 1);
        assert!(!second.session().is_closed());
        assert_eq!(second.session().id(), second_id);
        second.close().await;
        wait_pool(&client, 1, 1).await;
        assert_eq!(stats.dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn local_fin_does_not_idle_before_writer_commit() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let stream = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        wait_pool(&client, 1, 0).await;
        stats.pause_writes.store(true, Ordering::SeqCst);
        let mut stream = stream;
        stream.start_close();
        tokio::time::timeout(Duration::from_secs(5), stats.saw_pause.notified())
            .await
            .expect("FIN must reach the paused writer");
        assert_eq!(
            client.session_pool().idle_len(),
            0,
            "must not idle before FIN commit"
        );
        assert_eq!(client.session_pool().live_len(), 1);
        stats.pause_writes.store(false, Ordering::SeqCst);
        if let Some(waker) = stats.pause_waker.lock().unwrap().take() {
            waker.wake();
        }
        wait_pool(&client, 1, 1).await;
        assert_eq!(stats.dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn writer_fail_during_fin_unregisters() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let stream = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        stats.fail_writes.store(true, Ordering::SeqCst);
        stream.close().await;
        wait_pool(&client, 0, 0).await;
    }

    #[tokio::test]
    async fn remote_fin_returns_healthy_session() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let stream = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        let sid = stream.id();
        {
            let mut peers = stats.peers.lock().await;
            let peer = peers.last_mut().expect("peer");
            let mut fin = [0u8; 7];
            fin[0] = u8::from(crate::protocol::Command::Fin);
            fin[1..5].copy_from_slice(&sid.to_be_bytes());
            tokio::io::AsyncWriteExt::write_all(peer, &fin)
                .await
                .unwrap();
        }
        wait_pool(&client, 1, 1).await;
        drop(stream);
        wait_pool(&client, 1, 1).await;
        assert_eq!(stats.dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn open_stream_failure_does_not_leak() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let first = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        let session = Arc::clone(first.session());
        session.fail_next_open_stream();
        first.close().await;
        wait_pool(&client, 1, 1).await;
        assert!(
            !session.is_closed(),
            "injected open_stream failure must hit a live session"
        );
        let err = client
            .create_proxy_stream(("example.com".into(), 443))
            .await;
        assert!(
            err.is_err(),
            "create_proxy_stream must surface open_stream failure"
        );
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.drops.load(Ordering::SeqCst) == 0
                && stats.shutdowns.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("open_stream failure must close the transport");
    }

    #[tokio::test]
    async fn open_proxy_stream_failure_discards_checkout() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let err = client.create_proxy_stream(("x".repeat(256), 443)).await;
        assert!(err.is_err());
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.drops.load(Ordering::SeqCst) == 0
                && stats.shutdowns.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed open must close the transport");
    }

    #[tokio::test]
    async fn unpublished_session_cancel_does_not_leak() {
        let stats = DialStats::new();
        let client = Arc::new(pooled_client(&stats));
        let entered = Arc::new(Barrier::new(2));
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        client
            .set_pre_publish_park(Arc::clone(&entered), release_rx)
            .await;
        let task = {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                client
                    .create_proxy_stream(("example.com".into(), 443))
                    .await
            })
        };
        entered.wait().await;
        task.abort();
        drop(release_tx);
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.drops.load(Ordering::SeqCst) == 0
                && stats.shutdowns.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("unpublished cancel must close the transport");
    }

    #[tokio::test]
    async fn reset_closes_busy_idle_and_inflight_old_generation() {
        let stats = DialStats::new();
        let client = Arc::new(pooled_client(&stats));
        let busy = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        wait_pool(&client, 1, 0).await;

        // Park the old-generation dial while idle is still empty so checkout
        // misses and the inflight future actually dials. Opening idle first
        // would let inflight steal that session and never reach the barrier.
        let entered = Arc::new(Barrier::new(2));
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        stats.block_on.store(2, Ordering::SeqCst);
        *stats.block_entered.lock().await = Some(Arc::clone(&entered));
        *stats.block_release.lock().await = Some(release_rx);

        let inflight = {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                client
                    .create_proxy_stream(("example.com".into(), 443))
                    .await
            })
        };
        entered.wait().await;
        assert_eq!(stats.dials.load(Ordering::SeqCst), 2);

        let idle = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        idle.close().await;
        wait_pool(&client, 2, 1).await;
        assert_eq!(stats.dials.load(Ordering::SeqCst), 3);

        client.reset_sessions();
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), busy.session().wait_closed())
            .await
            .expect("reset closes the busy session");
        drop(release_tx);
        let result = inflight.await.expect("join");
        assert!(
            result.is_err(),
            "old-generation dial must not deliver a stream"
        );
        wait_pool(&client, 0, 0).await;

        let fresh = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .expect("new-generation dial works");
        assert_eq!(client.session_pool().live_len(), 1);
        drop(busy);
        wait_pool(&client, 1, 0).await;
        fresh.close().await;
        wait_pool(&client, 1, 1).await;
    }

    #[tokio::test]
    async fn ten_thousand_short_streams_reuse_one_session() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        for i in 0..10_000 {
            let stream = client
                .create_proxy_stream(("example.com".into(), 443))
                .await
                .unwrap_or_else(|e| panic!("stream {i}: {e}"));
            assert!(
                client.session_pool().live_len() <= 1,
                "live grew to {} at {i}",
                client.session_pool().live_len()
            );
            assert!(
                client.session_pool().idle_len() <= 1,
                "idle grew to {} at {i}",
                client.session_pool().idle_len()
            );
            stream.close().await;
            wait_pool(&client, 1, 1).await;
        }
        assert_eq!(stats.dials.load(Ordering::SeqCst), 1);
        client.reset_sessions();
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let dials = stats.dials.load(Ordering::SeqCst);
                let drops = stats.drops.load(Ordering::SeqCst);
                let shutdowns = stats.shutdowns.load(Ordering::SeqCst);
                if drops >= dials || shutdowns >= dials {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reset must close the remaining transport");
        assert_eq!(client.session_pool().live_len(), 0);
        assert_eq!(client.session_pool().idle_len(), 0);
    }

    #[tokio::test]
    async fn create_proxy_stream_on_tls_does_not_touch_the_pool() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let (tls_half, mut peer) = tokio::io::duplex(64 * 1024);
        let (stream, session) = client
            .create_proxy_stream_on_tls(tls_half, ("example.com".into(), 443))
            .await
            .unwrap();
        assert_eq!(client.session_pool().live_len(), 0);
        assert_eq!(client.session_pool().idle_len(), 0);
        assert_eq!(stats.dials.load(Ordering::SeqCst), 0);
        drop(stream);
        session.close().await.unwrap();
        let mut drained = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut drained))
            .await
            .expect("unpooled session close must shut the transport")
            .unwrap();
        assert_eq!(client.session_pool().live_len(), 0);
        assert_eq!(client.session_pool().idle_len(), 0);
    }

    #[tokio::test]
    async fn open_proxy_stream_cancel_discards_checkout() {
        let stats = DialStats::new();
        stats.drain_reads.store(false, Ordering::SeqCst);
        let client = Arc::new(pooled_client(&stats));
        let first = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        let session = Arc::clone(first.session());
        first.close().await;
        wait_pool(&client, 1, 1).await;

        // Fill the writer budget so the next SYN enqueue parks inside
        // production `open_proxy_stream` (fire-and-forget frames do not
        // wait on pause_writes).
        session.enqueue_flush_marker().unwrap();
        let (extra, _synack_rx) = session.open_stream().await.unwrap();
        loop {
            let r = tokio::time::timeout(
                Duration::from_millis(100),
                extra.send_data(Bytes::from_static(&[7u8; 256])),
            )
            .await;
            match r {
                Ok(Ok(())) => {}
                Ok(Err(e)) => panic!("send_data failed while saturating: {e}"),
                Err(_) => break,
            }
        }

        let task = {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                client
                    .create_proxy_stream(("example.com".into(), 443))
                    .await
            })
        };
        wait_pool(&client, 1, 0).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !task.is_finished() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("create_proxy_stream must stay pending in open_proxy_stream");
        task.abort();
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.drops.load(Ordering::SeqCst) == 0
                && stats.shutdowns.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled create_proxy_stream must close the transport");
    }

    #[tokio::test]
    async fn synack_error_discards_pooled_session() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let stream = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        let sid = stream.id();
        wait_pool(&client, 1, 0).await;
        {
            let mut peers = stats.peers.lock().await;
            let peer = peers.last_mut().expect("peer");
            let msg = b"refused";
            let mut synack_err = Vec::with_capacity(7 + msg.len());
            synack_err.push(u8::from(crate::protocol::Command::SynAck));
            synack_err.extend_from_slice(&sid.to_be_bytes());
            synack_err.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            synack_err.extend_from_slice(msg);
            tokio::io::AsyncWriteExt::write_all(peer, &synack_err)
                .await
                .unwrap();
        }
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.drops.load(Ordering::SeqCst) == 0
                && stats.shutdowns.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("SynAck-error eviction must close the transport");
        drop(stream);
        wait_pool(&client, 0, 0).await;
        assert_eq!(stats.dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropped_create_stream_checkout_closes_session() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let checkout = client.create_stream().await.expect("dialled checkout");
        assert_eq!(client.session_pool().live_len(), 1);
        assert_eq!(client.session_pool().idle_len(), 0);
        drop(checkout);
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.drops.load(Ordering::SeqCst) == 0
                && stats.shutdowns.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped Checkout must close the transport");
    }

    #[tokio::test]
    async fn off_runtime_drop_closes_transport() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let stream = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        wait_pool(&client, 1, 0).await;
        let joined = std::thread::spawn(move || {
            drop(stream);
        })
        .join();
        assert!(joined.is_ok(), "off-runtime Drop must not panic");
        wait_pool(&client, 0, 0).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.drops.load(Ordering::SeqCst) == 0
                && stats.shutdowns.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("off-runtime Drop must close the transport");
    }

    #[tokio::test]
    async fn close_await_then_immediate_open_reuses_session() {
        let stats = DialStats::new();
        let client = pooled_client(&stats);
        let first = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .unwrap();
        let first_id = first.session().id();
        first.close().await;
        let second = client
            .create_proxy_stream(("example.com".into(), 443))
            .await
            .expect("immediate open after close().await");
        assert_eq!(
            second.session().id(),
            first_id,
            "close().await must settle idle before returning"
        );
        assert_eq!(stats.dials.load(Ordering::SeqCst), 1);
        assert_eq!(client.session_pool().live_len(), 1);
        assert_eq!(client.session_pool().idle_len(), 0);
        second.close().await;
        wait_pool(&client, 1, 1).await;
    }
}
