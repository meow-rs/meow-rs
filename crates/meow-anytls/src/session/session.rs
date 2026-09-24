//! Session implementation for AnyTLS protocol

use crate::padding::{PaddingFactory, SharedPaddingFactory};
use crate::protocol::{Command, Frame, FrameCodec};
use crate::session::Stream;
use crate::session::writer::{StreamWriter, WriteRequest};
use crate::util::{AnyTlsError, Result, StringMap};
use bytes::{Bytes, BytesMut};
use md5;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, RwLock, mpsc};
use tokio::time::{self, Duration, Instant, MissedTickBehavior};
use tracing::{field, info_span};

static SESSION_COUNTER: meow_common::atomic::AtomicU = meow_common::atomic::AtomicU::new(1);
use tokio_util::codec::Decoder;

/// Type alias for new stream callback channel
type NewStreamCallback =
    Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<Arc<Stream>>>>>;

#[derive(Clone)]
pub struct SessionHeartbeatConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

struct HeartbeatState {
    interval: Duration,
    timeout: Duration,
    last_received: tokio::sync::Mutex<Instant>,
}

/// Session manages multiple streams over a single TLS connection
type StreamDataReceiver = mpsc::UnboundedReceiver<WriteRequest>;

pub struct Session {
    id: u64,
    // Connection reader and writer (split TLS stream)
    reader: Arc<tokio::sync::Mutex<Box<dyn AsyncRead + Send + Unpin>>>,
    writer: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,

    // Stream management - using Arc for sharing
    streams: Arc<RwLock<HashMap<u32, Arc<Stream>>>>,
    stream_id: Arc<std::sync::atomic::AtomicU32>,

    // Channel for receiving data from streams
    stream_data_tx: StreamWriter,
    stream_data_rx: Arc<tokio::sync::Mutex<Option<StreamDataReceiver>>>,

    // Channel for sending data to streams (stream_id -> sender)
    stream_receive_tx: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<Bytes>>>>,

    // Session state
    is_closed: Arc<std::sync::atomic::AtomicBool>,

    // Padding factory in force for this session. Client sessions share the
    // client's cell, so a server-pushed scheme reaches sessions opened later.
    padding: SharedPaddingFactory,

    // Client/Server specific
    is_client: bool,
    send_padding: bool,
    pkt_counter: Arc<std::sync::atomic::AtomicU32>,

    // Peer version
    #[allow(dead_code)]
    peer_version: Arc<std::sync::atomic::AtomicU8>,

    // Session sequence number (for pool ordering)
    seq: Arc<meow_common::atomic::AtomicU>,

    // Buffering state
    buffering: Arc<std::sync::atomic::AtomicBool>,
    buffer: Arc<tokio::sync::Mutex<Vec<u8>>>,

    // Server callback for new streams (optional)
    on_new_stream: Option<NewStreamCallback>,

    // Optional server settings to send to client
    server_settings: Option<StringMap>,

    // Heartbeat configuration (client side)
    heartbeat: Option<Arc<HeartbeatState>>,
    close_notify: Arc<Notify>,
}

impl Session {
    async fn handle_io_error(&self, context: &str, error: std::io::Error) -> AnyTlsError {
        tracing::error!(
            session_id = self.id(),
            ctx = context,
            "[Session] IO error during {}: {}",
            context,
            error
        );
        if let Err(close_err) = self.close().await {
            tracing::warn!(
                session_id = self.id(),
                "[Session] Failed to close session after IO error: {}",
                close_err
            );
        }
        AnyTlsError::Io(error)
    }

    /// Create a new client session
    pub fn new_client<R, W>(
        reader: R,
        writer: W,
        padding: SharedPaddingFactory,
        heartbeat: Option<SessionHeartbeatConfig>,
    ) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (stream_data_tx, stream_data_rx) = StreamWriter::channel();
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        let id: u64 = SESSION_COUNTER
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .into();
        let heartbeat_state = heartbeat.map(|cfg| {
            Arc::new(HeartbeatState {
                interval: cfg.interval,
                timeout: cfg.timeout,
                last_received: tokio::sync::Mutex::new(Instant::now()),
            })
        });

        Self {
            id,
            reader: Arc::new(tokio::sync::Mutex::new(Box::new(reader))),
            writer: Arc::new(tokio::sync::Mutex::new(Box::new(writer))),
            streams: Arc::new(RwLock::new(HashMap::new())),
            stream_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            stream_data_tx,
            stream_data_rx: Arc::new(tokio::sync::Mutex::new(Some(stream_data_rx))),
            stream_receive_tx: Arc::new(RwLock::new(HashMap::new())),
            is_closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            padding,
            is_client: true,
            send_padding: true,
            pkt_counter: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            peer_version: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            seq: Arc::new(meow_common::atomic::AtomicU::new(0)),
            buffering: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            on_new_stream: None,
            server_settings: None,
            heartbeat: heartbeat_state,
            close_notify: Arc::new(Notify::new()),
        }
    }

    /// Create a new server session
    pub fn new_server<R, W>(reader: R, writer: W, padding: Arc<PaddingFactory>) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (stream_data_tx, stream_data_rx) = StreamWriter::channel();
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        let id: u64 = SESSION_COUNTER
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .into();

        Self {
            id,
            reader: Arc::new(tokio::sync::Mutex::new(Box::new(reader))),
            writer: Arc::new(tokio::sync::Mutex::new(Box::new(writer))),
            streams: Arc::new(RwLock::new(HashMap::new())),
            stream_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            stream_data_tx,
            stream_data_rx: Arc::new(tokio::sync::Mutex::new(Some(stream_data_rx))),
            stream_receive_tx: Arc::new(RwLock::new(HashMap::new())),
            is_closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            padding: padding.into_shared(),
            is_client: false,
            send_padding: false,
            pkt_counter: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            peer_version: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            seq: Arc::new(meow_common::atomic::AtomicU::new(0)),
            buffering: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            on_new_stream: None,
            server_settings: None,
            heartbeat: None,
            close_notify: Arc::new(Notify::new()),
        }
    }

    /// Session identifier (unique per runtime)
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Set callback for new streams (server side only)
    pub fn set_stream_callback(
        &mut self,
        callback: tokio::sync::mpsc::UnboundedSender<Arc<Stream>>,
    ) {
        if !self.is_client {
            self.on_new_stream = Some(Arc::new(tokio::sync::Mutex::new(Some(callback))));
        }
    }

    /// Set server settings to send back to clients during handshake (server side)
    pub fn set_server_settings(&mut self, settings: Option<StringMap>) {
        self.server_settings = settings;
    }

    /// Check if session is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the session currently carries any open streams.
    ///
    /// Used by the session pool's cleanup task to avoid closing a pooled
    /// session that is still serving traffic (e.g. a long-running download).
    /// Accurate now that client streams are evicted on close (`Stream::close`
    /// emits a FIN and removes the maps).
    pub async fn has_active_streams(&self) -> bool {
        !self.streams.read().await.is_empty()
    }

    /// Close the session
    pub async fn close(&self) -> Result<()> {
        let already_closed = self
            .is_closed
            .swap(true, std::sync::atomic::Ordering::Relaxed);
        if already_closed {
            return Ok(());
        }
        self.stream_data_tx.close();
        self.close_notify.notify_waiters();

        // Close stream data receiver so process_stream_data exits
        // Close all streams and notify pending waiters. The two map
        // writes are the only awaits; `close_with_error`/`notify_synack`
        // are synchronous, so eviction + close + wakeup is one atomic
        // step — no cancellation point can orphan a waiter on an
        // already-evicted stream (issue #621).
        {
            let mut streams = self.streams.write().await;
            let mut receive_map = self.stream_receive_tx.write().await;
            for (stream_id, stream) in streams.drain() {
                stream.close_with_error(AnyTlsError::SessionClosed);
                stream.notify_synack(Err(AnyTlsError::SessionClosed));
                receive_map.remove(&stream_id);
            }
        }

        // Attempt to shutdown writer gracefully
        {
            let mut writer = self.writer.lock().await;
            match time::timeout(Duration::from_secs(1), writer.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::debug!(
                        session_id = self.id,
                        "[Session] Writer shutdown failed during close: {}",
                        e
                    );
                }
                Err(_) => {
                    tracing::debug!(
                        session_id = self.id,
                        "[Session] Writer shutdown timed out during close"
                    );
                }
            }
        }

        Ok(())
    }

    /// Start the receive loop (should be run in a tokio task)
    pub async fn recv_loop(&self) -> Result<()> {
        let session_id = self.id();
        let role = if self.is_client { "client" } else { "server" };
        let recv_span = info_span!(
            "anytls.session.recv",
            session_id,
            role = %role,
            bytes_in = field::Empty,
            iterations = field::Empty
        );
        let _recv_guard = recv_span.enter();
        tracing::debug!(
            session_id = session_id,
            is_client = self.is_client,
            "[Session] recv_loop started"
        );
        let mut codec = FrameCodec;
        let mut buffer = BytesMut::with_capacity(8192);
        let mut iteration = 0u64;
        let mut total_bytes_in: usize = 0;

        loop {
            iteration += 1;
            if self.is_closed() {
                tracing::debug!(
                    session_id = session_id,
                    "[Session] recv_loop: Session closed (iteration {})",
                    iteration
                );
                break;
            }

            // Read data from connection
            tracing::trace!(
                session_id = session_id,
                "[Session] recv_loop: Acquiring reader lock (iteration {})",
                iteration
            );
            let mut reader = self.reader.lock().await;
            tracing::trace!(
                session_id = session_id,
                "[Session] recv_loop: Reader lock acquired, calling read_buf (iteration {})",
                iteration
            );
            let n = match reader.read_buf(&mut buffer).await {
                Ok(n) => {
                    tracing::trace!(
                        session_id = session_id,
                        "[Session] recv_loop: read_buf returned {} bytes (iteration {})",
                        n,
                        iteration
                    );
                    n
                }
                Err(e) => {
                    // Check if this is a "close_notify" error (common and harmless)
                    let error_msg = e.to_string();
                    let is_close_notify_error = error_msg.contains("close_notify")
                        || error_msg.contains("unexpected EOF")
                        || e.kind() == std::io::ErrorKind::UnexpectedEof;

                    if is_close_notify_error {
                        // This is a normal connection close without TLS close_notify
                        // Many clients (especially HTTP clients) do this
                        tracing::debug!(
                            session_id = session_id,
                            "[Session] recv_loop: Connection closed by peer (no close_notify) - this is normal (iteration {})",
                            iteration
                        );
                        let _ = self.close().await;
                        break;
                    } else {
                        // This is a real error
                        let err = self.handle_io_error("recv_loop_read", e).await;
                        return Err(err);
                    }
                }
            };
            drop(reader);
            tracing::trace!(
                session_id = session_id,
                "[Session] recv_loop: Reader lock released (iteration {})",
                iteration
            );

            if n == 0 {
                // Connection closed
                tracing::debug!(
                    session_id = session_id,
                    "[Session] recv_loop: Connection closed (read 0 bytes, iteration {})",
                    iteration
                );
                let _ = self.close().await;
                break;
            }

            tracing::debug!(
                session_id = session_id,
                "[Session] recv_loop: Read {} bytes, buffer size={} (iteration {})",
                n,
                buffer.len(),
                iteration
            );

            total_bytes_in += n;

            // Decode frames
            let mut frame_count = 0u32;
            let buffer_before_decode = buffer.len();
            while let Some(frame) = codec.decode(&mut buffer)? {
                frame_count += 1;
                tracing::debug!(
                    session_id = session_id,
                    "[Session] recv_loop: Decoded frame #{}: cmd={:?}, stream_id={}, data_len={} (iteration {}, buffer before={}, after={})",
                    frame_count,
                    frame.cmd,
                    frame.stream_id,
                    frame.data.len(),
                    iteration,
                    buffer_before_decode,
                    buffer.len()
                );
                self.handle_frame(frame).await?;
            }
            if frame_count == 0 && n > 0 {
                tracing::debug!(
                    session_id = session_id,
                    "[Session] recv_loop: No frames decoded from {} bytes read (iteration {}, buffer size={})",
                    n,
                    iteration,
                    buffer.len()
                );
                tracing::trace!(
                    session_id = session_id,
                    "[Session] recv_loop: Buffer contents (first 50 bytes): {:?}",
                    if buffer.len() >= 50 {
                        &buffer[..50]
                    } else {
                        &buffer[..]
                    }
                );
            }
        }

        tracing::debug!(
            session_id = session_id,
            "[Session] recv_loop: Exiting after {} iterations",
            iteration
        );
        tracing::debug!(
            session_id = session_id,
            bytes_in = total_bytes_in as u64,
            iterations = iteration,
            "[Session] recv_loop completed"
        );
        recv_span.record("bytes_in", total_bytes_in as u64);
        recv_span.record("iterations", iteration);
        Ok(())
    }

    /// Handle an incoming frame from connection
    async fn handle_frame(&self, frame: Frame) -> Result<()> {
        let session_id = self.id();
        tracing::debug!(
            session_id = session_id,
            "[Session] handle_frame: Processing frame cmd={:?}, stream_id={}, data_len={}",
            frame.cmd,
            frame.stream_id,
            frame.data.len()
        );
        match frame.cmd {
            Command::Push => {
                // Data frame - forward to stream
                let data_len = frame.data.len();
                tracing::debug!(
                    session_id = session_id,
                    "[Session] handle_frame: Received PSH frame for stream {}, length={}",
                    frame.stream_id,
                    data_len
                );

                let receive_map = self.stream_receive_tx.read().await;
                tracing::trace!(
                    session_id = session_id,
                    "[Session] handle_frame: Acquired stream_receive_tx read lock for stream {}",
                    frame.stream_id
                );

                if let Some(tx) = receive_map.get(&frame.stream_id) {
                    tracing::trace!(
                        session_id = session_id,
                        "[Session] handle_frame: Found receiver for stream {}, sending {} bytes",
                        frame.stream_id,
                        data_len
                    );
                    match tx.send(frame.data.clone()) {
                        Ok(_) => {
                            tracing::debug!(
                                session_id = session_id,
                                "[Session] handle_frame: Successfully sent {} bytes to stream {} via channel",
                                data_len,
                                frame.stream_id
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                session_id = session_id,
                                "[Session] handle_frame: Failed to send {} bytes to stream {} via channel: {}",
                                data_len,
                                frame.stream_id,
                                e
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        session_id = session_id,
                        "[Session] handle_frame: No receiver found for stream {} (available streams: {:?})",
                        frame.stream_id,
                        receive_map.keys().collect::<Vec<_>>()
                    );
                }
                drop(receive_map);
                tracing::trace!(
                    session_id = session_id,
                    "[Session] handle_frame: Released stream_receive_tx read lock"
                );
            }
            Command::Syn => {
                // Stream open (server side)
                if !self.is_client {
                    let stream_id = frame.stream_id;
                    tracing::debug!(
                        session_id = session_id,
                        "[Session] Received SYN for stream {} (server side)",
                        stream_id
                    );

                    let (receive_tx, receive_rx) = mpsc::unbounded_channel();

                    // 创建 StreamReader
                    let reader = crate::session::StreamReader::new(stream_id, receive_rx);

                    // Server side: create stream without waiting for SYNACK
                    // The receiver is discarded since server doesn't need it
                    let (stream, _synack_rx) =
                        Stream::new(stream_id, reader, self.stream_data_tx.clone());

                    let stream = Arc::new(stream);

                    // Acquire both locks before mutating either map, in
                    // close()'s order — and recheck `is_closed` inside so a
                    // concurrent close() can't leave a registered stream
                    // behind on a dead session (issue #621 review).
                    {
                        let mut streams = self.streams.write().await;
                        let mut receive_map = self.stream_receive_tx.write().await;
                        if self.is_closed() {
                            return Ok(());
                        }
                        receive_map.insert(stream_id, receive_tx);
                        streams.insert(stream_id, stream.clone());
                    }

                    tracing::trace!(
                        session_id = session_id,
                        "[Session] Stream {} stored and ready for callback",
                        stream_id
                    );

                    // Notify callback if set
                    if let Some(callback_guard) = &self.on_new_stream {
                        let callback = callback_guard.lock().await;
                        if let Some(tx) = callback.as_ref() {
                            tracing::debug!(
                                session_id = session_id,
                                "[Session] Sending stream {} to callback",
                                stream_id
                            );
                            let _ = tx.send(stream.clone());
                        } else {
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] No callback set for stream {}",
                                stream_id
                            );
                        }
                    } else {
                        tracing::warn!(
                            session_id = session_id,
                            "[Session] No callback guard for stream {}",
                            stream_id
                        );
                    }
                } else {
                    tracing::warn!(
                        session_id = session_id,
                        "[Session] Received SYN on client side (unexpected)"
                    );
                }
            }
            Command::SynAck => {
                // Server acknowledges stream open (client side)
                if self.is_client {
                    tracing::debug!(
                        session_id = session_id,
                        "[Session] Received SYNACK for stream {}",
                        frame.stream_id
                    );

                    // If data is present it's an error message — the peer
                    // refused the stream. Evict + close + notify like the
                    // Fin arm: an `open_stream` caller that already dropped
                    // `synack_rx` would otherwise leak the map entries
                    // forever and the peer never sees a Fin (issue #543
                    // review; upstream's closeWithError deletes the stream
                    // inline too).
                    if !frame.data.is_empty() {
                        let error_msg = String::from_utf8_lossy(&frame.data).to_string();
                        tracing::error!(
                            session_id = session_id,
                            "[Session] Stream {} error from server: {}",
                            frame.stream_id,
                            error_msg
                        );
                        // Acquire both locks before mutating either map —
                        // the same order `open_stream`/`close` use — so no
                        // observer can see the stream evicted from one map
                        // but present in the other (issue #621 review).
                        let removed = {
                            let mut streams = self.streams.write().await;
                            let mut receive_map = self.stream_receive_tx.write().await;
                            let removed = streams.remove(&frame.stream_id);
                            receive_map.remove(&frame.stream_id);
                            removed
                        };
                        if let Some(stream) = removed {
                            let error =
                                AnyTlsError::Protocol(format!("Server error: {}", error_msg));
                            stream.close_with_error(AnyTlsError::StreamClosed);
                            stream.notify_synack(Err(error));
                        } else {
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] Received SYNACK for unknown stream {}",
                                frame.stream_id
                            );
                        }
                    } else {
                        let streams = self.streams.read().await;
                        if let Some(stream) = streams.get(&frame.stream_id) {
                            tracing::info!(
                                session_id = session_id,
                                "[Session] Stream {} SYNACK received (success) - stream is ready",
                                frame.stream_id
                            );
                            // Notify stream about success
                            stream.notify_synack(Ok(()));
                        } else {
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] Received SYNACK for unknown stream {}",
                                frame.stream_id
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        session_id = session_id,
                        "[Session] Received SYNACK on server side (unexpected)"
                    );
                }
            }
            Command::Fin => {
                // Stream close
                tracing::debug!(
                    session_id = session_id,
                    "[Session] FIN received for stream {}, closing",
                    frame.stream_id
                );
                // Both locks before either mutation — same order as
                // `open_stream`/`close` — so the two-map eviction is atomic
                // to observers (issue #621 review).
                let removed = {
                    let mut streams = self.streams.write().await;
                    let mut receive_map = self.stream_receive_tx.write().await;
                    let removed = streams.remove(&frame.stream_id);
                    receive_map.remove(&frame.stream_id);
                    removed
                };
                // A FIN can arrive before the SynAck — the peer refusing
                // the stream instead of SynAck-erroring it. Mark the
                // stream closed locally (no Fin reply — upstream
                // `closeLocally`) so a retained `Arc<Stream>` cannot
                // `send_data` for a dead stream, and wake the pending
                // synack-waiter: without it the client keeps `Arc<Stream>`
                // so `synack_tx` stays alive and `synack_rx` pends until
                // the internal bound instead of failing the dial
                // immediately (issue #543). `notify_synack` no-ops once
                // the SynAck landed.
                if let Some(stream) = removed {
                    stream.close_with_error(AnyTlsError::StreamClosed);
                    stream.notify_synack(Err(AnyTlsError::StreamClosed));
                }
            }
            Command::Settings => {
                // Client settings (server side)
                if !self.is_client && !frame.data.is_empty() {
                    let settings = StringMap::from_bytes(&frame.data);

                    // Check padding-md5
                    if let Some(client_md5) = settings.get("padding-md5") {
                        let padding_guard = self.padding.read().await;
                        let server_md5 = padding_guard.md5();
                        if client_md5 != server_md5 {
                            // Send UpdatePaddingScheme
                            tracing::debug!(
                                "[Session] Client padding-md5 mismatch, sending update"
                            );
                            let raw_scheme = padding_guard.raw_scheme();
                            let update_frame = Frame::with_data(
                                Command::UpdatePaddingScheme,
                                0,
                                Bytes::copy_from_slice(raw_scheme),
                            );
                            self.write_frame(update_frame).await?;
                        }
                    }

                    // Check client version
                    if let Some(v_str) = settings.get("v")
                        && let Ok(v) = v_str.parse::<u8>()
                        && v >= 2
                    {
                        self.peer_version
                            .store(v, std::sync::atomic::Ordering::Relaxed);

                        // Send ServerSettings
                        let mut server_settings = StringMap::new();
                        server_settings.insert("v", "2");
                        if let Some(extra) = &self.server_settings {
                            for (k, v) in extra.clone().into_vec() {
                                server_settings.insert(k, v);
                            }
                        }
                        let server_settings_frame = Frame::with_data(
                            Command::ServerSettings,
                            0,
                            Bytes::from(server_settings.to_bytes()),
                        );
                        self.write_frame(server_settings_frame).await?;
                    }
                }
            }
            Command::ServerSettings => {
                // Server settings (client side)
                if self.is_client && !frame.data.is_empty() {
                    let settings = StringMap::from_bytes(&frame.data);
                    if let Some(v_str) = settings.get("v")
                        && let Ok(v) = v_str.parse::<u8>()
                    {
                        self.peer_version
                            .store(v, std::sync::atomic::Ordering::Relaxed);
                        tracing::debug!("[Session] Server version: {}", v);
                    }
                }
            }
            Command::UpdatePaddingScheme => {
                // Server updates padding scheme (client side). The new factory
                // goes into the shared cell, so this session switches scheme
                // mid-flight and later sessions of the same client advertise
                // the new md5 instead of provoking another update frame.
                if self.is_client && !frame.data.is_empty() {
                    match PaddingFactory::new(&frame.data) {
                        Ok(factory) => {
                            let factory = Arc::new(factory);
                            tracing::debug!(
                                session_id = self.id,
                                "[Session] Padding scheme updated: {}",
                                factory.md5()
                            );
                            *self.padding.write().await = factory;
                        }
                        Err(e) => {
                            tracing::warn!(
                                session_id = self.id,
                                "[Session] Failed to update padding scheme {:x}: {}",
                                md5::compute(&frame.data),
                                e
                            );
                        }
                    }
                }
            }
            Command::Alert => {
                // Alert message - fatal error, should close session
                let alert_msg = if !frame.data.is_empty() {
                    String::from_utf8_lossy(&frame.data).to_string()
                } else {
                    "Unknown alert".to_string()
                };
                tracing::error!("[Session] Received Alert frame (fatal): {}", alert_msg);
                // Close admission and wake the writer too, not just the flag:
                // a blocked physical write must stop with the entire session.
                self.close().await?;
                return Err(AnyTlsError::Protocol(format!("Alert: {}", alert_msg)));
            }
            Command::HeartRequest => {
                // Heartbeat request - respond with HeartResponse
                tracing::debug!(
                    "[Session] Received HeartRequest (stream_id={})",
                    frame.stream_id
                );

                // Send HeartResponse immediately
                let response = Frame::control(Command::HeartResponse, frame.stream_id);

                if let Err(e) = self.write_control_frame(response).await {
                    tracing::error!("[Session] Failed to send HeartResponse: {}", e);
                    return Err(e);
                }

                tracing::debug!(
                    "[Session] Sent HeartResponse (stream_id={})",
                    frame.stream_id
                );
            }
            Command::HeartResponse => {
                // Heartbeat response - log for now
                tracing::debug!(
                    "[Session] Received HeartResponse (stream_id={})",
                    frame.stream_id
                );

                if let Some(heartbeat_state) = &self.heartbeat {
                    let mut last = heartbeat_state.last_received.lock().await;
                    *last = Instant::now();
                }
            }
            _ => {
                // Unhandled command - log and ignore
                tracing::debug!(
                    "[Session] Unhandled command: {:?} (stream_id={})",
                    frame.cmd,
                    frame.stream_id
                );
            }
        }
        Ok(())
    }

    /// Create a new stream (client side).
    ///
    /// Returns the stream and its SYNACK receiver. The receiver always
    /// resolves exactly once: `Ok(())` on a successful SynAck, or
    /// `Err(..)` on a SynAck error payload, an inbound/outbound `Fin`
    /// eviction, or session close — every eviction path resolves it, so
    /// a caller may hold it across a local `stream.close()` without
    /// needing its own timeout (issue #543).
    pub async fn open_stream(
        &self,
    ) -> Result<(Arc<Stream>, tokio::sync::oneshot::Receiver<Result<()>>)> {
        if self.is_closed() {
            tracing::warn!("[Session] Attempted to open stream on closed session");
            return Err(AnyTlsError::SessionClosed);
        }

        let stream_id = self
            .stream_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tracing::debug!(
            "[Session] Opening new stream {} (client={})",
            stream_id,
            self.is_client
        );

        // Create channels for this stream
        let (receive_tx, receive_rx) = mpsc::unbounded_channel();

        // 创建 StreamReader
        let reader = crate::session::StreamReader::new(stream_id, receive_rx);

        let (stream, synack_rx) = Stream::new(stream_id, reader, self.stream_data_tx.clone());

        let stream = Arc::new(stream);

        // Acquire both locks before mutating either map, in close()'s order.
        {
            let mut streams = self.streams.write().await;
            let mut receive_map = self.stream_receive_tx.write().await;
            if self.is_closed() {
                return Err(AnyTlsError::SessionClosed);
            }
            receive_map.insert(stream_id, receive_tx);
            streams.insert(stream_id, stream.clone());
        }
        let mut guard = crate::session::stream::OpeningStreamGuard::new(Arc::clone(&stream));

        tracing::trace!("[Session] Stream {} stored in session", stream_id);

        // Send SYN frame
        tracing::trace!("[Session] Sending SYN frame for stream {}", stream_id);
        let frame = Frame::control(Command::Syn, stream_id);
        self.write_frame(frame).await?;
        tracing::debug!("[Session] SYN frame sent for stream {}", stream_id);

        guard.disarm();
        Ok((stream, synack_rx))
    }

    /// Disable buffering (this will flush buffer on next write)
    pub fn disable_buffering(&self) {
        self.buffering
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Write a data frame to connection
    pub async fn write_data_frame(&self, stream_id: u32, data: Bytes) -> Result<()> {
        tracing::trace!(
            session_id = self.id(),
            stream_id,
            bytes = data.len(),
            "[Session] write_data_frame: stream_id={}, data_len={}",
            stream_id,
            data.len()
        );
        let frame = Frame::data(stream_id, data);
        self.write_frame(frame).await
    }

    /// Write a control frame to connection
    pub async fn write_control_frame(&self, frame: Frame) -> Result<()> {
        self.write_frame(frame).await
    }

    /// Write a frame to the connection
    pub async fn write_frame(&self, frame: Frame) -> Result<()> {
        self.stream_data_tx.write_frame(frame).await
    }

    // Only the session writer task performs wire I/O. start_client also calls
    // this before spawning tasks, solely to buffer the initial Settings.
    async fn write_frame_inner(&self, frame: Frame) -> Result<()> {
        use tokio_util::codec::Encoder;
        let frame_cmd = frame.cmd;
        let frame_stream_id = frame.stream_id;
        let mut codec = FrameCodec;
        let mut buffer = BytesMut::new();
        codec.encode(frame, &mut buffer)?;
        tracing::trace!(
            session_id = self.id(),
            "[Session] write_frame: encoded frame cmd={:?}, stream_id={}, buffer_len={}",
            frame_cmd,
            frame_stream_id,
            buffer.len()
        );

        // Check if buffering
        if self.buffering.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::trace!(
                "[Session] write_frame: Buffering frame cmd={:?}, stream_id={}",
                frame_cmd,
                frame_stream_id
            );
            let mut buf = self.buffer.lock().await;
            let old_len = buf.len();
            buf.extend_from_slice(&buffer);
            tracing::debug!(
                "[Session] write_frame: Buffered frame (buffer size: {} -> {})",
                old_len,
                buf.len()
            );
            return Ok(());
        }

        // Flush buffer if any
        {
            let mut buf = self.buffer.lock().await;
            if !buf.is_empty() {
                let buffered_len = buf.len();
                tracing::debug!(
                    "[Session] write_frame: Flushing {} buffered bytes along with new frame ({} bytes)",
                    buffered_len,
                    buffer.len()
                );

                // Log first frame's header for debugging
                if buffered_len >= 7 {
                    tracing::debug!(
                        "[Session] First buffered frame header: cmd={}, stream_id={:?}, data_len={:?}",
                        buf[0],
                        u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
                        u16::from_be_bytes([buf[5], buf[6]])
                    );
                }

                let mut combined = BytesMut::from(&buf[..]);
                combined.extend_from_slice(&buffer);
                buffer = combined;
                buf.clear();
            }
        }

        // Per-frame wire details are intentionally trace-only: AnyTLS emits a
        // frame for every relay chunk, so info-level logging is a hot-path
        // throughput bottleneck under the application's default filter.
        if buffer.len() >= 7 {
            tracing::trace!(
                "[Session] About to send frame header: cmd={}, stream_id={:?}, data_len={:?}, total_buffer_len={}",
                buffer[0],
                u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]),
                u16::from_be_bytes([buffer[5], buffer[6]]),
                buffer.len()
            );
        }

        // Write with padding if enabled
        self.write_with_padding(buffer).await
    }

    /// Write buffer to connection with padding applied
    async fn write_with_padding(&self, mut buffer: BytesMut) -> Result<()> {
        use crate::padding::CHECK_MARK;
        use crate::protocol::{Command, HEADER_OVERHEAD_SIZE};
        use bytes::BufMut;

        if !self.send_padding {
            // No padding, write directly
            tracing::trace!(
                "[Session] write_with_padding: Writing {} bytes without padding",
                buffer.len()
            );
            let mut writer = self.writer.lock().await;
            if let Err(e) = writer.write_all(&buffer).await {
                return Err(AnyTlsError::Io(e));
            }
            if let Err(e) = writer.flush().await {
                return Err(AnyTlsError::Io(e));
            }
            tracing::trace!(
                "[Session] write_with_padding: Successfully wrote {} bytes to connection",
                buffer.len()
            );
            return Ok(());
        }

        // Increment packet counter
        let pkt = self
            .pkt_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let padding_factory = {
            let padding_guard = self.padding.read().await;
            padding_guard.clone()
        };
        let stop = padding_factory.stop();

        if pkt >= stop {
            // Stop padding after stop packets
            // Note: We should probably disable send_padding, but that requires mutable access
            // For now, just write directly
            let mut writer = self.writer.lock().await;
            if let Err(e) = writer.write_all(&buffer).await {
                return Err(AnyTlsError::Io(e));
            }
            if let Err(e) = writer.flush().await {
                return Err(AnyTlsError::Io(e));
            }
            return Ok(());
        }

        // Get padding sizes for this packet
        let pkt_sizes = padding_factory.generate_record_payload_sizes(pkt);

        // If no sizes defined, write directly
        if pkt_sizes.is_empty() {
            let mut writer = self.writer.lock().await;
            if let Err(e) = writer.write_all(&buffer).await {
                return Err(AnyTlsError::Io(e));
            }
            if let Err(e) = writer.flush().await {
                return Err(AnyTlsError::Io(e));
            }
            return Ok(());
        }

        let mut writer = self.writer.lock().await;

        for size in pkt_sizes {
            let remain_payload_len = buffer.len();

            if size == CHECK_MARK {
                // Check mark: if no remaining payload, return early
                if remain_payload_len == 0 {
                    break;
                }
                // Otherwise continue to next size
                continue;
            }

            let size = size as usize;

            tracing::trace!(
                "[Session] write_with_padding: Processing size={}, remain_payload_len={}",
                size,
                remain_payload_len
            );

            if remain_payload_len > size {
                // This packet is all payload - send exactly size bytes
                // Note: This may split a frame in the middle, but that's okay for TLS records
                // The receiver will reassemble frames from the stream
                tracing::debug!(
                    "[Session] write_with_padding: Splitting payload: sending {} bytes (remain={})",
                    size,
                    remain_payload_len
                );
                if size >= 7 {
                    tracing::debug!(
                        "[Session] write_with_padding: First 7 bytes being sent: {:?}",
                        &buffer[..7]
                    );
                }
                if let Err(e) = writer.write_all(&buffer[..size]).await {
                    return Err(AnyTlsError::Io(e));
                }
                buffer = buffer.split_off(size);
            } else if remain_payload_len > 0 {
                // This packet contains payload + padding
                let padding_len = size.saturating_sub(remain_payload_len + HEADER_OVERHEAD_SIZE);

                if padding_len > 0 {
                    // Create padding frame (cmdWaste)
                    let mut padding_frame =
                        BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + padding_len);
                    padding_frame.put_u8(Command::Waste as u8);
                    padding_frame.put_u32(0); // stream_id = 0
                    padding_frame.put_u16(padding_len as u16);
                    padding_frame.put_slice(&vec![0u8; padding_len]); // padding data (zeros)

                    // Combine payload and padding
                    buffer.put_slice(&padding_frame);
                }

                if let Err(e) = writer.write_all(&buffer).await {
                    return Err(AnyTlsError::Io(e));
                }
                buffer.clear();
            } else {
                // This packet is all padding
                let mut padding_frame = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + size);
                padding_frame.put_u8(Command::Waste as u8);
                padding_frame.put_u32(0); // stream_id = 0
                padding_frame.put_u16(size as u16);
                padding_frame.put_slice(&vec![0u8; size]); // padding data (zeros)

                if let Err(e) = writer.write_all(&padding_frame).await {
                    return Err(AnyTlsError::Io(e));
                }
            }
        }

        // Write any remaining payload
        if !buffer.is_empty() {
            tracing::trace!(
                "[Session] write_with_padding: Writing {} remaining payload bytes",
                buffer.len()
            );
            if let Err(e) = writer.write_all(&buffer).await {
                return Err(AnyTlsError::Io(e));
            }
        }

        tracing::trace!("[Session] write_with_padding: Flushing writer");
        if let Err(e) = writer.flush().await {
            return Err(AnyTlsError::Io(e));
        }
        tracing::debug!("[Session] write_with_padding: Successfully wrote and flushed data");
        Ok(())
    }

    /// Start the client session (send settings and start recv loop)
    pub async fn start_client(self: Arc<Self>) -> Result<()> {
        use crate::util::StringMap;

        // Send settings frame
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("client", "anytls-rs/0.1.0");
        let padding_md5 = {
            let padding_guard = self.padding.read().await;
            padding_guard.md5().to_string()
        };
        settings.insert("padding-md5", padding_md5);

        let frame = Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));

        self.buffering
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.write_frame_inner(frame).await?;

        // Start receive loop in background
        let session = Arc::clone(&self);
        tokio::spawn(async move {
            tracing::debug!(
                "[Session] recv_loop task spawned (client={})",
                session.is_client
            );
            match session.recv_loop().await {
                Ok(()) => {
                    tracing::debug!("[Session] recv_loop task completed normally");
                }
                Err(AnyTlsError::Io(e)) => {
                    // Check if this is a close_notify error (normal connection close)
                    let error_msg = e.to_string();
                    if error_msg.contains("close_notify")
                        || error_msg.contains("unexpected EOF")
                        || e.kind() == std::io::ErrorKind::UnexpectedEof
                    {
                        tracing::debug!(
                            "[Session] recv_loop task ended: Connection closed by peer (no close_notify) - this is normal"
                        );
                    } else {
                        tracing::error!("[Session] recv_loop task error: {}", e);
                    }
                }
                Err(AnyTlsError::SessionClosed) => {
                    tracing::debug!("[Session] recv_loop task ended: Session closed");
                }
                Err(e) => {
                    tracing::error!("[Session] recv_loop task error: {}", e);
                }
            }
            // The read side is gone: mark the session closed so the pool stops
            // handing it out, its writer half is shut down, and the heartbeat
            // task exits — otherwise a server-closed session lingered in the
            // pool (heartbeat keeping its socket open) and leaked its fd.
            let _ = session.close().await;
        });

        // Start stream data processing in background
        let session = Arc::clone(&self);
        tokio::spawn(async move {
            tracing::debug!(
                "[Session] process_stream_data task spawned (client={})",
                session.is_client
            );
            if let Err(e) = session.process_stream_data().await {
                tracing::error!("[Session] process_stream_data task error: {}", e);
            } else {
                tracing::debug!("[Session] process_stream_data task completed normally");
            }
        });

        if let Some(heartbeat_state) = self.heartbeat.as_ref().map(Arc::clone) {
            let session = Arc::clone(&self);
            tokio::spawn(async move {
                let session_id = session.id();
                let mut ticker = time::interval(heartbeat_state.interval);
                ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

                loop {
                    ticker.tick().await;

                    if session.is_closed() {
                        tracing::debug!(
                            session_id = session_id,
                            "[Session] Heartbeat loop exiting because session is closed"
                        );
                        break;
                    }

                    let last_seen = {
                        let guard = heartbeat_state.last_received.lock().await;
                        Instant::now().saturating_duration_since(*guard)
                    };

                    if last_seen > heartbeat_state.timeout {
                        tracing::warn!(
                            session_id = session_id,
                            elapsed_ms = last_seen.as_millis() as u64,
                            "[Session] Heartbeat timeout detected; closing session"
                        );
                        if let Err(e) = session.close().await {
                            tracing::error!(
                                session_id = session_id,
                                "[Session] Failed to close session after heartbeat timeout: {}",
                                e
                            );
                        }
                        break;
                    }

                    if let Err(e) = session
                        .write_control_frame(Frame::control(Command::HeartRequest, 0))
                        .await
                    {
                        tracing::error!(
                            session_id = session_id,
                            "[Session] Failed to send HeartRequest: {}",
                            e
                        );
                        if let Err(close_err) = session.close().await {
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] Failed to close session after heartbeat error: {}",
                                close_err
                            );
                        }
                        break;
                    }

                    tracing::trace!(
                        session_id = session_id,
                        "[Session] Heartbeat request sent successfully"
                    );
                }
            });
        }

        Ok(())
    }

    /// Run the sole wire writer. Cancelling a producer never cancels a frame.
    pub async fn process_stream_data(&self) -> Result<()> {
        let Some(mut receiver) = self.stream_data_rx.lock().await.take() else {
            return Ok(());
        };
        loop {
            let closed = self.close_notify.notified();
            tokio::pin!(closed);
            closed.as_mut().enable();
            if self.is_closed() {
                break;
            }
            let request = tokio::select! {
                biased;
                _ = &mut closed => break,
                request = receiver.recv() => match request {
                    Some(request) => request,
                    None => break,
                },
            };
            let (completion, result, fin_stream) = tokio::select! {
                biased;
                // Partial frames may only be abandoned when this entire
                // session is already closed and will never be pooled again.
                _ = &mut closed => break,
                result = async {
                    match request {
                        WriteRequest::Frame { frame, _permit, completion } => {
                            let fin = frame.cmd == Command::Fin;
                            let stream_id = frame.stream_id;
                            if fin {
                                // A cancelled initial dial must not leave its
                                // Settings/SYN/FIN buffered until another dial.
                                self.disable_buffering();
                            }
                            let result = self.write_frame_inner(frame).await;
                            // Hold capacity through the physical write/flush.
                            drop(_permit);
                            (completion, result, fin.then_some(stream_id))
                        }
                        WriteRequest::Flush(completion) => {
                            let result = self.flush_inner().await;
                            (Some(completion), result, None)
                        }
                    }
                } => result,
            };
            // Fin eviction runs AFTER the select: doing it inside the
            // write future let a racing `Session::close()` drop the future
            // between the map removal and the notify — the stream vanished
            // from `streams` while its synack-waiter still pended, the same
            // bug class the inbound Fin arm fixes (issue #543 review).
            // `open_stream` is pub, so an out-of-tree caller can hold a
            // live synack-waiter across a local close; mark the stream
            // closed too so a retained Arc<Stream> can't still queue PSH.
            if let Some(stream_id) = fin_stream {
                // Acquire both locks before mutating either map — the same
                // order `open_stream`/`close` use — then evict + close +
                // wake in one synchronous step: no cancellation point can
                // split removal from the waiter wakeup (issue #621).
                let mut streams = self.streams.write().await;
                let mut receive_map = self.stream_receive_tx.write().await;
                if let Some(stream) = streams.remove(&stream_id) {
                    receive_map.remove(&stream_id);
                    stream.close_with_error(AnyTlsError::StreamClosed);
                    stream.notify_synack(Err(AnyTlsError::StreamClosed));
                }
            }
            let failed = result.is_err();
            if let Err(error) = &result {
                tracing::debug!(session_id = self.id(), %error, "AnyTLS session writer failed");
            }
            if let Some(completion) = completion {
                let _ = completion.send(result);
            }
            if failed {
                // No writer lock is held here; close() can safely shut it down.
                self.close().await?;
                return Err(AnyTlsError::SessionClosed);
            }
        }
        Ok(())
    }

    async fn flush_inner(&self) -> Result<()> {
        self.disable_buffering();
        let buffered = std::mem::take(&mut *self.buffer.lock().await);
        if !buffered.is_empty() {
            self.write_with_padding(BytesMut::from(buffered.as_slice()))
                .await?;
        }
        self.writer.lock().await.flush().await?;
        Ok(())
    }

    /// Get session sequence number
    pub fn seq(&self) -> u64 {
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        self.seq.load(std::sync::atomic::Ordering::Relaxed).into()
    }

    /// Set session sequence number
    pub fn set_seq(&self, seq: u64) {
        // Truncates on targets whose `AtomicU` is 32-bit (MIPS32); the sequence
        // is only used for pool ordering, so wrapping there is harmless.
        self.seq.store(
            seq as meow_common::atomic::Uint,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Get peer version
    pub fn peer_version(&self) -> u8 {
        self.peer_version.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::PaddingFactory;
    use tokio::io::{DuplexStream, duplex};

    /// 创建一对连接的双工流（用于测试）
    fn create_connected_streams() -> (DuplexStream, DuplexStream) {
        duplex(8192)
    }

    /// 创建测试用的 PaddingFactory
    fn create_test_padding() -> Arc<PaddingFactory> {
        use crate::padding::DEFAULT_PADDING_SCHEME;
        Arc::new(PaddingFactory::new(DEFAULT_PADDING_SCHEME.as_bytes()).unwrap())
    }

    async fn read_frame(peer: &mut DuplexStream) -> Frame {
        time::timeout(Duration::from_secs(2), async {
            let mut header = [0; 7];
            peer.read_exact(&mut header).await.unwrap();
            let mut data = vec![0; u16::from_be_bytes([header[5], header[6]]) as usize];
            peer.read_exact(&mut data).await.unwrap();
            Frame::with_data(
                Command::from(header[0]),
                u32::from_be_bytes(header[1..5].try_into().unwrap()),
                Bytes::from(data),
            )
        })
        .await
        .expect("frame writer stalled")
    }

    #[tokio::test]
    async fn cancelled_open_finishes_syn_and_retires_stream() {
        use std::future::Future;
        use std::task::{Context, Waker};
        let (io, mut peer) = duplex(4);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(Session::new_server(reader, writer, create_test_padding()));
        let worker = Arc::clone(&session);
        let task = tokio::spawn(async move { worker.process_stream_data().await });
        let mut open = Box::pin(session.open_stream());
        assert!(
            open.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        // SYN is seven bytes but the wire only holds four. Cancel after the
        // first byte was observed, while write_all still has work to do.
        assert_eq!(peer.read_u8().await.unwrap(), u8::from(Command::Syn));
        drop(open);
        let mut tail = [0; 6];
        peer.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, [0, 0, 0, 1, 0, 0]);
        assert_eq!(read_frame(&mut peer).await, Frame::control(Command::Fin, 1));
        assert!(!session.has_active_streams().await);
        assert!(session.stream_receive_tx.read().await.is_empty());

        let next_session = Arc::clone(&session);
        let next = tokio::spawn(async move { next_session.open_stream().await.unwrap().0 });
        assert_eq!(read_frame(&mut peer).await, Frame::control(Command::Syn, 2));
        next.await.unwrap().close();
        assert_eq!(read_frame(&mut peer).await, Frame::control(Command::Fin, 2));
        session.close().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn writer_error_closes_session_without_relocking_itself() {
        let (io, peer) = duplex(4);
        drop(peer);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(Session::new_server(reader, writer, create_test_padding()));
        let worker = Arc::clone(&session);
        let task = tokio::spawn(async move { worker.process_stream_data().await });
        assert!(
            time::timeout(
                Duration::from_secs(2),
                session.write_data_frame(1, Bytes::from_static(b"failure"))
            )
            .await
            .unwrap()
            .is_err()
        );
        assert!(
            time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(session.is_closed());
        assert!(
            session
                .write_data_frame(2, Bytes::from_static(b"closed"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn peer_alert_stops_writer_and_notifies_opening_streams() {
        let (io, _peer) = duplex(64);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(Session::new_server(reader, writer, create_test_padding()));
        let worker = Arc::clone(&session);
        let task = tokio::spawn(async move { worker.process_stream_data().await });
        let (stream, synack) = session.open_stream().await.unwrap();
        assert!(
            session
                .handle_frame(Frame::with_data(
                    Command::Alert,
                    0,
                    Bytes::from_static(b"stop")
                ))
                .await
                .is_err()
        );
        assert!(stream.is_closed());
        assert!(synack.await.unwrap().is_err());
        time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(session.stream_data_tx.budget.is_closed());
        assert!(session.stream_receive_tx.read().await.is_empty());
    }

    #[tokio::test]
    async fn close_interrupts_blocked_writer_and_releases_budget() {
        let (io, _peer) = duplex(4);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(Session::new_server(reader, writer, create_test_padding()));
        let worker = Arc::clone(&session);
        let task = tokio::spawn(async move { worker.process_stream_data().await });
        let pending_session = Arc::clone(&session);
        let pending = tokio::spawn(async move {
            pending_session
                .write_data_frame(1, Bytes::from(vec![0; 512]))
                .await
        });
        tokio::task::yield_now().await;
        time::timeout(Duration::from_secs(2), session.close())
            .await
            .unwrap()
            .unwrap();
        assert!(pending.await.unwrap().is_err());
        task.await.unwrap().unwrap();
        assert!(session.stream_data_tx.budget.is_closed());
    }

    #[tokio::test]
    async fn frame_hot_path_emits_no_info_events() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tracing::instrument::WithSubscriber;
        use tracing_subscriber::{Layer, layer::SubscriberExt};
        struct CountInfo(Arc<AtomicUsize>);
        impl<S: tracing::Subscriber> Layer<S> for CountInfo {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if *event.metadata().level() == tracing::Level::INFO {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(CountInfo(Arc::clone(&count)));
        async {
            let session =
                Session::new_server(tokio::io::empty(), tokio::io::sink(), create_test_padding());
            for _ in 0..100 {
                session
                    .write_frame_inner(Frame::data(1, Bytes::from_static(b"data")))
                    .await
                    .unwrap();
            }
        }
        .with_subscriber(subscriber)
        .await;
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_heartbeat_request_response() {
        // 初始化日志
        let _ = tracing_subscriber::fmt::try_init();

        // 创建一对连接的流
        let (client_stream, server_stream) = create_connected_streams();
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, server_write) = tokio::io::split(server_stream);

        let padding = create_test_padding();

        // 创建客户端和服务器 Session
        let client_session = Arc::new(Session::new_client(
            client_read,
            client_write,
            Arc::clone(&padding).into_shared(),
            None,
        ));

        let server_session = Arc::new(Session::new_server(server_read, server_write, padding));

        // 手动启动 recv_loop 任务
        let client_clone = client_session.clone();
        tokio::spawn(async move {
            let _ = client_clone.recv_loop().await;
        });

        let server_clone = server_session.clone();
        tokio::spawn(async move {
            let _ = server_clone.recv_loop().await;
        });

        // 启动 process_stream_data 任务
        let client_clone2 = client_session.clone();
        tokio::spawn(async move {
            let _ = client_clone2.process_stream_data().await;
        });

        let server_clone2 = server_session.clone();
        tokio::spawn(async move {
            let _ = server_clone2.process_stream_data().await;
        });

        // 等待一下让任务启动
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // 客户端发送 HeartRequest
        let heart_request = Frame::control(Command::HeartRequest, 0);
        client_session
            .write_control_frame(heart_request)
            .await
            .unwrap();

        // 等待服务器处理和响应
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        // 测试通过标准：Session 没有关闭
        assert!(
            !client_session.is_closed(),
            "Client session should not be closed"
        );
        assert!(
            !server_session.is_closed(),
            "Server session should not be closed"
        );

        tracing::debug!("Heartbeat request-response test passed");
    }

    #[tokio::test]
    async fn test_heartbeat_multiple_requests() {
        let _ = tracing_subscriber::fmt::try_init();

        let (client_stream, server_stream) = create_connected_streams();
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, server_write) = tokio::io::split(server_stream);

        let padding = create_test_padding();

        let client_session = Arc::new(Session::new_client(
            client_read,
            client_write,
            Arc::clone(&padding).into_shared(),
            None,
        ));

        let server_session = Arc::new(Session::new_server(server_read, server_write, padding));

        // 启动任务
        let client_clone = client_session.clone();
        tokio::spawn(async move {
            let _ = client_clone.recv_loop().await;
        });
        let server_clone = server_session.clone();
        tokio::spawn(async move {
            let _ = server_clone.recv_loop().await;
        });
        let client_clone2 = client_session.clone();
        tokio::spawn(async move {
            let _ = client_clone2.process_stream_data().await;
        });
        let server_clone2 = server_session.clone();
        tokio::spawn(async move {
            let _ = server_clone2.process_stream_data().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // 发送多个心跳请求
        for i in 0..5 {
            let heart_request = Frame::control(Command::HeartRequest, i);
            client_session
                .write_control_frame(heart_request)
                .await
                .unwrap();

            // 等待响应
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        // 额外等待确保所有响应都被处理
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Session 应该仍然正常
        assert!(
            !client_session.is_closed(),
            "Client session should not be closed after multiple heartbeats"
        );
        assert!(
            !server_session.is_closed(),
            "Server session should not be closed after multiple heartbeats"
        );

        tracing::debug!("Multiple heartbeat requests test passed");
    }

    #[tokio::test]
    async fn test_heartbeat_bidirectional() {
        let _ = tracing_subscriber::fmt::try_init();

        let (stream1, stream2) = create_connected_streams();
        let (read1, write1) = tokio::io::split(stream1);
        let (read2, write2) = tokio::io::split(stream2);

        let padding = create_test_padding();

        let session1 = Arc::new(Session::new_client(
            read1,
            write1,
            Arc::clone(&padding).into_shared(),
            None,
        ));

        let session2 = Arc::new(Session::new_server(read2, write2, padding));

        // 启动任务
        let s1_clone = session1.clone();
        tokio::spawn(async move {
            let _ = s1_clone.recv_loop().await;
        });
        let s2_clone = session2.clone();
        tokio::spawn(async move {
            let _ = s2_clone.recv_loop().await;
        });
        let s1_clone2 = session1.clone();
        tokio::spawn(async move {
            let _ = s1_clone2.process_stream_data().await;
        });
        let s2_clone2 = session2.clone();
        tokio::spawn(async move {
            let _ = s2_clone2.process_stream_data().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Session 1 发送心跳给 Session 2
        session1
            .write_control_frame(Frame::control(Command::HeartRequest, 0))
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Session 2 发送心跳给 Session 1
        session2
            .write_control_frame(Frame::control(Command::HeartRequest, 1))
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // 双方都应该正常
        assert!(!session1.is_closed());
        assert!(!session2.is_closed());

        tracing::debug!("Bidirectional heartbeat test passed");
    }

    /// A pushed scheme must reach the live session *and* the client's shared
    /// cell — the global `OnceLock` this used to write could only ever be set
    /// once, so every push after the first session was silently dropped.
    #[tokio::test]
    async fn server_pushed_padding_scheme_replaces_the_shared_factory() {
        const SCHEME: &str = "stop=2\n0=50-50\n1=100-200";

        let padding = create_test_padding().into_shared();
        let before = padding.read().await.md5().to_string();
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            Arc::clone(&padding),
            None,
        ));

        session
            .handle_frame(Frame::with_data(
                Command::UpdatePaddingScheme,
                0,
                Bytes::from_static(SCHEME.as_bytes()),
            ))
            .await
            .unwrap();

        let pushed = PaddingFactory::new(SCHEME.as_bytes()).unwrap();
        assert_ne!(before, pushed.md5());
        // The live session pads with the pushed scheme…
        assert_eq!(session.padding.read().await.md5(), pushed.md5());
        assert_eq!(
            session
                .padding
                .read()
                .await
                .generate_record_payload_sizes(0),
            vec![50]
        );
        // …and so does the cell, so the next session advertises the new md5
        // instead of provoking another update frame.
        assert_eq!(padding.read().await.md5(), pushed.md5());
    }

    /// An unparsable scheme leaves the previous one in force.
    #[tokio::test]
    async fn invalid_pushed_padding_scheme_keeps_the_previous_factory() {
        let padding = create_test_padding().into_shared();
        let before = padding.read().await.md5().to_string();
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            Arc::clone(&padding),
            None,
        ));

        session
            .handle_frame(Frame::with_data(
                Command::UpdatePaddingScheme,
                0,
                Bytes::from_static(b"0=30-30"),
            ))
            .await
            .unwrap();

        assert_eq!(padding.read().await.md5(), before);
        assert_eq!(session.padding.read().await.md5(), before);
    }

    /// Server sessions never apply a pushed scheme.
    #[tokio::test]
    async fn server_session_ignores_padding_scheme_updates() {
        let session = Arc::new(Session::new_server(
            tokio::io::empty(),
            tokio::io::sink(),
            create_test_padding(),
        ));
        let before = session.padding.read().await.md5().to_string();

        session
            .handle_frame(Frame::with_data(
                Command::UpdatePaddingScheme,
                0,
                Bytes::from_static(b"stop=2\n0=50-50"),
            ))
            .await
            .unwrap();

        assert_eq!(session.padding.read().await.md5(), before);
    }

    /// Issue #543 — a bare `Fin` arriving before the `SynAck` must wake
    /// the pending synack-waiter. The client keeps `Arc<Stream>`, so
    /// without `notify_synack` the receiver pended until the internal
    /// bound and surfaced as a dial timeout instead of a clean error.
    #[tokio::test]
    async fn fin_before_synack_wakes_pending_waiter() {
        // Client session; the peer end plays the server.
        let (io, mut peer) = duplex(8192);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(Session::new_client(
            reader,
            writer,
            create_test_padding().into_shared(),
            None,
        ));
        let s = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = s.recv_loop().await;
        });
        let s = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = s.process_stream_data().await;
        });

        let (stream, synack_rx) = session.open_stream().await.unwrap();
        // The server sees the Syn and refuses the stream by FINing it
        // instead of SynAck-erroring it.
        let syn = read_frame(&mut peer).await;
        assert_eq!(syn.cmd, Command::Syn);
        let mut fin = Vec::with_capacity(7);
        fin.push(Command::Fin as u8);
        fin.extend_from_slice(&syn.stream_id.to_be_bytes());
        fin.extend_from_slice(&0u16.to_be_bytes());
        peer.write_all(&fin).await.unwrap();

        let result = time::timeout(Duration::from_secs(2), synack_rx)
            .await
            .expect("synack-waiter must wake on Fin, not hit the timeout");
        assert!(
            matches!(result, Ok(Err(AnyTlsError::StreamClosed))),
            "expected StreamClosed for the pending waiter, got {result:?}"
        );
        assert!(
            stream.is_closed(),
            "an inbound Fin must mark the stream closed locally — a retained \
             Arc<Stream> must not send_data for a dead stream"
        );
        assert!(
            !session.has_active_streams().await,
            "the Fin must also evict the stream from the session maps"
        );
        assert!(
            session.stream_receive_tx.read().await.is_empty(),
            "the Fin must also drop the stream's receive sender"
        );

        // Upstream `closeLocally` semantics: an inbound Fin must NOT be
        // answered with a Fin. Drain whatever the client emits for a
        // beat — only padding Waste frames may appear, never a Fin for
        // the dead stream id.
        let mut saw_reply_fin = false;
        while let Ok(frame) = time::timeout(Duration::from_millis(300), read_frame(&mut peer)).await
        {
            if frame.cmd == Command::Fin && frame.stream_id == syn.stream_id {
                saw_reply_fin = true;
            }
        }
        assert!(
            !saw_reply_fin,
            "an inbound Fin must not be answered with a Fin (closeLocally)"
        );
    }

    /// Issue #543 review — a SynAck carrying an error payload must evict
    /// + close + notify like the Fin arm: an `open_stream` caller that
    /// dropped `synack_rx` must not leak the map entries.
    #[tokio::test]
    async fn synack_error_evicts_and_wakes_waiter() {
        let (io, mut peer) = duplex(8192);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(Session::new_client(
            reader,
            writer,
            create_test_padding().into_shared(),
            None,
        ));
        let s = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = s.recv_loop().await;
        });
        let s = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = s.process_stream_data().await;
        });

        let (stream, synack_rx) = session.open_stream().await.unwrap();
        let syn = read_frame(&mut peer).await;
        assert_eq!(syn.cmd, Command::Syn);

        // Server refuses the stream with a SynAck error payload.
        let mut synack_err = Vec::with_capacity(16);
        synack_err.push(Command::SynAck as u8);
        synack_err.extend_from_slice(&syn.stream_id.to_be_bytes());
        let msg = b"refused";
        synack_err.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        synack_err.extend_from_slice(msg);
        peer.write_all(&synack_err).await.unwrap();

        let result = time::timeout(Duration::from_secs(2), synack_rx)
            .await
            .expect("synack-waiter must wake on a SynAck error");
        assert!(
            matches!(result, Ok(Err(AnyTlsError::Protocol(_)))),
            "expected the server's Protocol error, got {result:?}"
        );

        // Prove eviction even when nobody holds the waiter: drop a
        // second stream's receiver before its SynAck error arrives.
        let (_stream2, synack2) = session.open_stream().await.unwrap();
        let syn2 = loop {
            let frame = read_frame(&mut peer).await;
            if frame.cmd == Command::Syn {
                break frame;
            }
        };
        drop(synack2);
        let mut synack_err2 = Vec::with_capacity(16);
        synack_err2.push(Command::SynAck as u8);
        synack_err2.extend_from_slice(&syn2.stream_id.to_be_bytes());
        synack_err2.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        synack_err2.extend_from_slice(msg);
        peer.write_all(&synack_err2).await.unwrap();

        // Ordering: once a third stream's SynAck resolves, both error
        // frames have been processed in order.
        let (_stream3, synack3) = session.open_stream().await.unwrap();
        let syn3 = loop {
            let frame = read_frame(&mut peer).await;
            if frame.cmd == Command::Syn {
                break frame;
            }
        };
        let mut synack_ok = Vec::with_capacity(7);
        synack_ok.push(Command::SynAck as u8);
        synack_ok.extend_from_slice(&syn3.stream_id.to_be_bytes());
        synack_ok.extend_from_slice(&0u16.to_be_bytes());
        peer.write_all(&synack_ok).await.unwrap();
        time::timeout(Duration::from_secs(2), synack3)
            .await
            .expect("the third stream's synack-waiter must resolve")
            .unwrap()
            .unwrap();

        assert!(stream.is_closed());
        assert!(
            session.streams.read().await.get(&syn2.stream_id).is_none(),
            "a SynAck error must evict the stream even with no waiter held"
        );
        assert!(
            session
                .stream_receive_tx
                .read()
                .await
                .get(&syn2.stream_id)
                .is_none(),
            "a SynAck error must drop the receive sender too"
        );
    }

    /// Issue #543 — a Fin arriving AFTER the SynAck must still evict and
    /// close the established stream, while `notify_synack` no-ops on the
    /// already-landed acknowledgement (first notify wins).
    #[tokio::test]
    async fn fin_after_synack_evicts_without_renotifying() {
        // Client session; the peer end plays the server.
        let (io, mut peer) = duplex(8192);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(Session::new_client(
            reader,
            writer,
            create_test_padding().into_shared(),
            None,
        ));
        let s = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = s.recv_loop().await;
        });
        let s = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = s.process_stream_data().await;
        });

        let (stream, synack_rx) = session.open_stream().await.unwrap();
        let syn = read_frame(&mut peer).await;
        assert_eq!(syn.cmd, Command::Syn);
        let write_frame = |cmd: Command, stream_id: u32| -> Vec<u8> {
            let mut f = Vec::with_capacity(7);
            f.push(cmd as u8);
            f.extend_from_slice(&stream_id.to_be_bytes());
            f.extend_from_slice(&0u16.to_be_bytes());
            f
        };

        // Acknowledge the stream, then FIN it — the first notify wins.
        peer.write_all(&write_frame(Command::SynAck, syn.stream_id))
            .await
            .unwrap();
        let result = time::timeout(Duration::from_secs(2), synack_rx)
            .await
            .expect("synack-waiter must wake on SynAck");
        assert!(
            matches!(result, Ok(Ok(()))),
            "the SynAck must land first, got {result:?}"
        );

        peer.write_all(&write_frame(Command::Fin, syn.stream_id))
            .await
            .unwrap();

        // recv_loop handles frames in order: once a second stream's SynAck
        // resolves, the earlier Fin has already been processed.
        let (_stream2, synack2) = session.open_stream().await.unwrap();
        // Padding may append Waste frames after the first Syn; skip them.
        let syn2 = loop {
            let frame = read_frame(&mut peer).await;
            if frame.cmd == Command::Syn {
                break frame;
            }
        };
        peer.write_all(&write_frame(Command::SynAck, syn2.stream_id))
            .await
            .unwrap();
        time::timeout(Duration::from_secs(2), synack2)
            .await
            .expect("the second stream's synack-waiter must resolve")
            .unwrap()
            .unwrap();

        assert!(
            stream.is_closed(),
            "the Fin must mark the established stream closed"
        );
        assert!(
            session.streams.read().await.get(&syn.stream_id).is_none(),
            "the Fin must evict the established stream from `streams`"
        );
    }

    /// Issue #543 — the symmetric outbound direction: a locally initiated
    /// close writes a Fin through `process_stream_data`, whose eviction
    /// must wake a pending synack-waiter too. `open_stream` is pub, so an
    /// out-of-tree caller can hold `synack_rx` across the local close.
    #[tokio::test]
    async fn local_fin_eviction_wakes_pending_waiter() {
        let (io, mut peer) = duplex(8192);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(Session::new_client(
            reader,
            writer,
            create_test_padding().into_shared(),
            None,
        ));
        let s = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = s.recv_loop().await;
        });
        let s = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = s.process_stream_data().await;
        });

        let (stream, synack_rx) = session.open_stream().await.unwrap();
        let syn = read_frame(&mut peer).await;
        assert_eq!(syn.cmd, Command::Syn);

        // Close locally before any SynAck — the Fin the writer emits
        // must evict the stream and wake the waiter.
        stream.close();
        let result = time::timeout(Duration::from_secs(2), synack_rx)
            .await
            .expect("synack-waiter must wake on local Fin eviction");
        assert!(
            matches!(result, Ok(Err(AnyTlsError::StreamClosed))),
            "expected StreamClosed for the pending waiter, got {result:?}"
        );

        // The peer observes the Fin on the wire (padding may append
        // Waste frames after the Syn — skip them), and the stream is
        // gone from the session maps.
        let fin = loop {
            let frame = read_frame(&mut peer).await;
            if frame.cmd == Command::Fin {
                break frame;
            }
        };
        assert_eq!(fin.stream_id, syn.stream_id);
        assert!(
            !session.has_active_streams().await,
            "the local Fin must evict the stream from the session maps"
        );
        assert!(
            session.stream_receive_tx.read().await.is_empty(),
            "the local Fin must also drop the stream's receive sender"
        );
    }
}
#[cfg(test)]
mod padding_bounds_tests {
    use super::*;

    #[tokio::test]
    async fn maximum_padding_keeps_the_next_frame_aligned() {
        use tokio::io::AsyncReadExt;
        let (writer, mut reader) = tokio::io::duplex(2 * u16::MAX as usize);
        let padding =
            Arc::new(PaddingFactory::new(b"stop=2\n1=65535-65535").unwrap()).into_shared();
        let session = Session::new_client(tokio::io::empty(), writer, padding, None);
        session
            .pkt_counter
            .store(1, std::sync::atomic::Ordering::SeqCst);
        session.write_with_padding(BytesMut::new()).await.unwrap();
        // The next unpadded frame must start after the declared Waste payload,
        // even at the largest representable length.
        let next = [Command::Waste as u8, 0, 0, 0, 0, 0, 0];
        session
            .write_with_padding(BytesMut::from(next.as_slice()))
            .await
            .unwrap();
        let mut header = [0u8; 7];
        reader.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [Command::Waste as u8, 0, 0, 0, 0, 255, 255]);
        let mut payload = vec![1u8; u16::MAX as usize];
        reader.read_exact(&mut payload).await.unwrap();
        assert!(payload.iter().all(|b| *b == 0));
        reader.read_exact(&mut header).await.unwrap();
        assert_eq!(header, next);
    }

    #[tokio::test]
    async fn oversized_pushed_scheme_is_rejected_before_the_next_write() {
        let padding = PaddingFactory::default().into_shared();
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            Arc::clone(&padding),
            None,
        ));
        // A short, otherwise well-formed UpdatePaddingScheme received before
        // packet 1. No large allocation is performed by this probe.
        session
            .pkt_counter
            .store(1, std::sync::atomic::Ordering::SeqCst);
        session
            .handle_frame(Frame::with_data(
                Command::UpdatePaddingScheme,
                0,
                Bytes::from_static(b"stop=2\n1=2147483648-2147483648"),
            ))
            .await
            .unwrap();
        assert_eq!(padding.read().await.md5(), PaddingFactory::default().md5());
        let result = tokio::spawn(async move {
            session
                .write_with_padding(BytesMut::from(&b"payload"[..]))
                .await
        })
        .await;
        result
            .expect("server-pushed padding must not panic")
            .unwrap();
    }
}
