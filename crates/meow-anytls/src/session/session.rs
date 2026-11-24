//! Session implementation for AnyTLS protocol

use crate::padding::{PaddingFactory, SharedPaddingFactory};
use crate::protocol::{Command, Frame, FrameCodec, HEADER_OVERHEAD_SIZE};
use crate::session::Stream;
use crate::session::writer::{ControlTicket, StreamWriter, WriteRequest};
use crate::util::{AnyTlsError, Result, StringMap};
use bytes::{Bytes, BytesMut};
use md5;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, OwnedSemaphorePermit, RwLock, mpsc, oneshot};
use tokio::time::{self, Duration, Instant, MissedTickBehavior};
use tracing::{Instrument, Span, field, info_span};

static SESSION_COUNTER: meow_common::atomic::AtomicU = meow_common::atomic::AtomicU::new(1);
use tokio_util::codec::Decoder;

/// Grace period for a SynAck after `open_stream` on a v2+ peer before the
/// whole session is closed — mihomo arms the identical 3 s `synDone`
/// deadline (`sid >= 2 && peerVersion >= 2`, transport/anytls
/// session.go). A peer that still answers heartbeats but never SynAcks
/// would otherwise stay pooled and wedge every later dial for the 30 s
/// per-stream timeout (issue #625).
const SYN_WATCHDOG_TIMEOUT: Duration = Duration::from_secs(3);

/// Server-side admission caps on inbound PSH bytes still unconsumed by
/// the stream handler — the "stall a stream, starve the session" bound.
/// Per-stream saturation evicts that stream; session saturation kills
/// the session.
const MAX_STREAM_PENDING: usize = 256 * 1024;
const MAX_SESSION_PENDING: usize = 4 * 1024 * 1024;
/// Per-stream queued-item bound, independent of the byte budget: many
/// tiny PSH frames must not pile up channel entries without limit —
/// upstream bounds its pipe by buffers, this bounds ours by count.
const MAX_STREAM_PENDING_FRAMES: usize = 1024;
/// Maximum live streams per server session.
const MAX_STREAMS_PER_SESSION: usize = 128;

/// The shared control-write deadline — upstream's 5 s `writeAndRetry`
/// bound on every control frame. Applied twice by design: at admission
/// (`write_control_frame` — queue wait plus completion) and at the
/// writer's single commit point (the batch wire write in
/// `process_stream_data`), so no control frame can park either half
/// of the session on a wedged peer.
const CONTROL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Inbound-budget counters shared between one stream's receive-slot and
/// every payload it admitted: `session` points at the session-wide byte
/// counter so a queued item releases both scopes in one Drop. `frames`
/// is this stream's own queued-item count, released the same way.
#[derive(Debug)]
pub struct PendingBudget {
    stream: std::sync::atomic::AtomicUsize,
    frames: std::sync::atomic::AtomicUsize,
    session: Arc<std::sync::atomic::AtomicUsize>,
}

/// One inbound PSH payload in a stream's receive channel. Carries its
/// byte share of the per-stream and per-session budgets; when the item
/// drops — consumed, evicted, or torn down with the session — the
/// budget comes back, so every cleanup path releases without extra
/// bookkeeping. `Deref`s to the payload for the reader's slice ops.
pub struct PendingBytes {
    bytes: Bytes,
    budget: Option<Arc<PendingBudget>>,
}

impl PendingBytes {
    /// Unmetered payload — client-side receive paths admit no inbound
    /// cap, so they carry no budget.
    fn unmetered(bytes: Bytes) -> Self {
        Self {
            bytes,
            budget: None,
        }
    }
}

impl From<Bytes> for PendingBytes {
    /// Bare payload → unmetered item (client paths, tests).
    fn from(bytes: Bytes) -> Self {
        Self::unmetered(bytes)
    }
}

impl std::ops::Deref for PendingBytes {
    type Target = Bytes;
    fn deref(&self) -> &Bytes {
        &self.bytes
    }
}

impl Drop for PendingBytes {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget {
            budget
                .stream
                .fetch_sub(self.bytes.len(), std::sync::atomic::Ordering::Relaxed);
            budget
                .frames
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            budget
                .session
                .fetch_sub(self.bytes.len(), std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// A live stream's receive-slot: the channel plus this stream's budget.
/// Budget presence distinguishes server sessions (admission-enforced)
/// from client ones.
struct StreamRx {
    tx: mpsc::UnboundedSender<PendingBytes>,
    budget: Option<Arc<PendingBudget>>,
}

/// Type alias for new stream callback channel — BOUNDED: the accept
/// queue is part of the stream-admission budget, so a stalled
/// dispatcher can't let SYNs accumulate without limit.
type NewStreamCallback = Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<Arc<Stream>>>>>;

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

    // Channel for sending data to streams (stream_id -> receive slot)
    stream_receive_tx: Arc<RwLock<HashMap<u32, StreamRx>>>,

    // Session state
    is_closed: Arc<std::sync::atomic::AtomicBool>,

    // Teardown supervision (F07): `is_closed` is the persistent cancel
    // signal; `close_lock` serializes the destructive half so exactly
    // one caller runs it — a caller cancelled mid-teardown leaves the
    // lock for the NEXT `close()` caller, which re-checks
    // `teardown_done` and finishes the remaining steps itself.
    close_lock: tokio::sync::Mutex<()>,
    teardown_done: std::sync::atomic::AtomicBool,

    // Padding factory in force for this session. Client sessions share the
    // client's cell, so a server-pushed scheme reaches sessions opened later.
    padding: SharedPaddingFactory,

    // Client/Server specific
    is_client: bool,
    send_padding: bool,
    pkt_counter: Arc<std::sync::atomic::AtomicU32>,

    // Peer version
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

    // Session-level SYN watchdog (upstream `synDone` parity): while a
    // client stream `sid >= 2` on a v2+ peer awaits its SynAck, a spawned
    // deadline task holding `Weak<Session>` closes the session on expiry.
    // Sync mutex — held only across abort/store, never across an await.
    syn_watchdog: std::sync::Mutex<Option<tokio::task::AbortHandle>>,

    // Server side: total inbound PSH bytes still pending consumption
    // across every stream (the shared half of each `PendingBudget`).
    pending_in: Arc<std::sync::atomic::AtomicUsize>,

    // Server side: the client's Settings frame arrived. A SYN ahead of
    // it is a protocol violation (upstream refuses the session), not a
    // stream to route.
    client_settings_received: std::sync::atomic::AtomicBool,
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
            close_lock: tokio::sync::Mutex::new(()),
            teardown_done: std::sync::atomic::AtomicBool::new(false),
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
            syn_watchdog: std::sync::Mutex::new(None),
            pending_in: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            client_settings_received: std::sync::atomic::AtomicBool::new(false),
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
            close_lock: tokio::sync::Mutex::new(()),
            teardown_done: std::sync::atomic::AtomicBool::new(false),
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
            syn_watchdog: std::sync::Mutex::new(None),
            pending_in: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            client_settings_received: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Session identifier (unique per runtime)
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Set callback for new streams (server side only)
    pub fn set_stream_callback(&mut self, callback: tokio::sync::mpsc::Sender<Arc<Stream>>) {
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
        self.is_closed.load(std::sync::atomic::Ordering::Acquire)
    }

    fn initiate_close(&self) {
        self.is_closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.stream_data_tx.close();
        self.close_notify.notify_waiters();
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

    /// Close the session.
    ///
    /// Two distinct states: `is_closed` is the persistent CANCEL signal
    /// every waiter/loop observes, set before any await so a cancelled
    /// caller still leaves the session stopping. The destructive
    /// teardown — draining the stream maps, closing stream admission,
    /// shutting the transport writer — runs under `close_lock`: every
    /// caller queues for it, and whoever holds it runs whatever steps
    /// remain, so a `close()` cancelled mid-teardown is RESUMED by the
    /// next caller instead of leaving the session half-drained (F07).
    /// `teardown_done` is the separate completion state a second caller
    /// can trust, not merely "close was initiated".
    pub async fn close(&self) -> Result<()> {
        self.initiate_close();
        if self
            .teardown_done
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(());
        }
        let _guard = self.close_lock.lock().await;
        if self
            .teardown_done
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(());
        }

        // Drop stream admission — the accept channel's sender hangs
        // inside this mutex, so a dispatcher parked on `recv` ends when
        // teardown runs rather than pinning the listener's spawn set.
        if let Some(callback_guard) = &self.on_new_stream {
            *callback_guard.lock().await = None;
        }

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

        self.teardown_done
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Start the receive loop (should be run in a tokio task).
    ///
    /// Callers must wrap the future in `.instrument(span)` — holding an
    /// `Entered` guard across `.await` leaks this span onto whatever task the
    /// worker thread polls while this loop is parked.
    pub async fn recv_loop(&self) -> Result<()> {
        const RECV_BUF_CHUNK: usize = 64 * 1024 + HEADER_OVERHEAD_SIZE;
        let session_id = self.id();
        tracing::debug!(
            session_id = session_id,
            is_client = self.is_client,
            "[Session] recv_loop started"
        );
        let mut codec = FrameCodec;
        let mut buffer = BytesMut::with_capacity(RECV_BUF_CHUNK);
        let mut iteration = 0u64;
        let mut total_bytes_in: usize = 0;

        // The reader mutex exists for the loop's exclusive `&mut` read
        // access, but nothing else ever locks it — one acquire for the
        // loop's lifetime instead of a lock/unlock pair per read.
        let mut reader = self.reader.lock().await;

        loop {
            iteration += 1;
            // Subscribe BEFORE checking the flag: `notify_waiters`
            // retains no state, so a notify landing between a bare flag
            // check and a fresh `notified()` would be lost forever.
            let closed = self.close_notify.notified();
            tokio::pin!(closed);
            closed.as_mut().enable();
            if self.is_closed() {
                tracing::debug!(
                    session_id = session_id,
                    "[Session] recv_loop: Session closed (iteration {})",
                    iteration
                );
                break;
            }

            // Keep enough spare capacity to fit at least a full TLS record
            // without triggering a per-frame grow-and-copy when `decode`
            // reserves a max-sized frame.
            if buffer.capacity() - buffer.len() < 16 * 1024 {
                buffer.reserve(RECV_BUF_CHUNK);
            }

            // Race the read against session closure: a writer-side fatal
            // (backpressure, control-write deadline) must not leave the
            // read half parked on a peer that never speaks again.
            let n = match tokio::select! {
                n = reader.read_buf(&mut buffer) => Some(n),
                _ = &mut closed => None,
            } {
                Some(Ok(n)) => n,
                None => {
                    tracing::debug!(
                        session_id = session_id,
                        "[Session] recv_loop: Session closed while read pending (iteration {})",
                        iteration
                    );
                    break;
                }
                Some(Err(e)) => {
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

            tracing::trace!(
                session_id = session_id,
                "[Session] recv_loop: Read {} bytes, buffer size={} (iteration {})",
                n,
                buffer.len(),
                iteration
            );

            total_bytes_in += n;

            // Decode frames — `handle_frame` traces each frame's
            // cmd/stream_id/len, so no per-frame trace here.
            let mut frame_count = 0u32;
            while let Some(frame) = codec.decode(&mut buffer)? {
                frame_count += 1;
                self.handle_frame(frame).await?;
            }
            if frame_count == 0 && n > 0 {
                tracing::trace!(
                    session_id = session_id,
                    "[Session] recv_loop: No frames decoded from {} bytes read (iteration {}, buffer size={})",
                    n,
                    iteration,
                    buffer.len()
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
        Span::current().record("bytes_in", total_bytes_in as u64);
        Span::current().record("iterations", iteration);
        Ok(())
    }

    /// Handle an incoming frame from connection
    async fn handle_frame(&self, frame: Frame) -> Result<()> {
        let session_id = self.id();
        tracing::trace!(
            session_id = session_id,
            "[Session] handle_frame: Processing frame cmd={:?}, stream_id={}, data_len={}",
            frame.cmd,
            frame.stream_id,
            frame.data.len()
        );
        match frame.cmd {
            Command::Push => {
                // An empty PSH carries nothing — upstream skips it by
                // `hdr.Length() > 0` before the stream lookup. Enqueueing
                // it would both bypass the byte budget (0 bytes) and
                // surface a spurious 0-length read == EOF downstream.
                if frame.data.is_empty() {
                    return Ok(());
                }
                // Data frame — forward to the stream. `frame.data` MOVES
                // into the channel (no `Bytes` refcount clone), which is
                // what lets `StreamReader` hand the caller slices of the
                // very allocation the codec decoded.
                let receive_map = self.stream_receive_tx.read().await;

                if let Some(rx) = receive_map.get(&frame.stream_id) {
                    // Server-side admission: count the bytes AND the
                    // queue entry against the stream and session budgets
                    // BEFORE enqueueing. Only recv_loop mutates the
                    // counters upward, so the check-then-add is
                    // race-free; `PendingBytes::Drop` gives the counts
                    // back on every downstream path.
                    let budget = if self.is_client {
                        None
                    } else {
                        let len = frame.data.len();
                        let pending_stream = rx
                            .budget
                            .as_ref()
                            .map(|b| b.stream.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0)
                            + len;
                        let pending_frames = rx
                            .budget
                            .as_ref()
                            .map(|b| b.frames.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0)
                            + 1;
                        let pending_session =
                            self.pending_in.load(std::sync::atomic::Ordering::Relaxed) + len;
                        if pending_stream > MAX_STREAM_PENDING
                            || pending_frames > MAX_STREAM_PENDING_FRAMES
                        {
                            drop(receive_map);
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] stream {} exceeded {} B pending — evicting",
                                frame.stream_id,
                                MAX_STREAM_PENDING
                            );
                            let victim = self.streams.read().await.get(&frame.stream_id).cloned();
                            if let Some(victim) = victim {
                                let owner = victim.owner();
                                let _ = self
                                    .write_control_frame_owned(
                                        Frame::control(Command::Fin, frame.stream_id),
                                        owner,
                                    )
                                    .await;
                                self.evict_stream_if_same(
                                    frame.stream_id,
                                    &victim,
                                    AnyTlsError::StreamClosed,
                                )
                                .await;
                            }
                            return Ok(());
                        }
                        if pending_session > MAX_SESSION_PENDING {
                            drop(receive_map);
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] session pending data exceeded {} B — closing",
                                MAX_SESSION_PENDING
                            );
                            let _ = self.close().await;
                            return Err(AnyTlsError::Protocol(
                                "session pending data limit exceeded".into(),
                            ));
                        }
                        let budget = rx.budget.as_ref().expect("server slots are metered");
                        budget
                            .stream
                            .fetch_add(len, std::sync::atomic::Ordering::Relaxed);
                        budget
                            .frames
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.pending_in
                            .fetch_add(len, std::sync::atomic::Ordering::Relaxed);
                        Some(Arc::clone(budget))
                    };
                    if let Err(e) = rx.tx.send(PendingBytes {
                        bytes: frame.data,
                        budget,
                    }) {
                        tracing::error!(
                            session_id = session_id,
                            "[Session] handle_frame: Failed to send {} bytes to stream {} via channel: {}",
                            e.0.len(),
                            frame.stream_id,
                            e
                        );
                    }
                } else {
                    // Not an anomaly: a local FIN evicts the stream (see the
                    // writer loop's Fin eviction) while the peer's in-flight
                    // PSH frames are still on the wire, so every stream that
                    // closes while the peer is sending lands here. Keep it
                    // off the default `info` filter (one line per late frame
                    // otherwise).
                    tracing::trace!(
                        session_id = session_id,
                        "[Session] handle_frame: No receiver found for stream {} (available streams: {:?})",
                        frame.stream_id,
                        receive_map.keys().collect::<Vec<_>>()
                    );
                }
            }
            Command::Syn => {
                // Stream open (server side)
                if !self.is_client {
                    let stream_id = frame.stream_id;
                    // A SYN with payload is malformed — the command never
                    // carries data upstream.
                    if !frame.data.is_empty() {
                        return Err(AnyTlsError::Protocol("SYN with payload".into()));
                    }
                    tracing::debug!(
                        session_id = session_id,
                        "[Session] Received SYN for stream {} (server side)",
                        stream_id
                    );

                    // A SYN ahead of the client's Settings is a protocol
                    // violation, not a routeable stream: Alert like
                    // upstream `die` then close the session.
                    if !self
                        .client_settings_received
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        tracing::warn!(
                            session_id = session_id,
                            "[Session] SYN for stream {} before client Settings",
                            stream_id
                        );
                        // Upstream `die("client did not send its
                        // settings")` — the exact Alert text a peer
                        // surfaces to its operator.
                        let alert = Frame::with_data(
                            Command::Alert,
                            0,
                            Bytes::from_static(b"client did not send its settings"),
                        );
                        let _ = self.write_control_frame(alert).await;
                        let _ = self.close().await;
                        return Err(AnyTlsError::Protocol(
                            "client did not send its settings".into(),
                        ));
                    }

                    let (receive_tx, receive_rx) = mpsc::unbounded_channel();
                    let budget = Arc::new(PendingBudget {
                        stream: std::sync::atomic::AtomicUsize::new(0),
                        frames: std::sync::atomic::AtomicUsize::new(0),
                        session: Arc::clone(&self.pending_in),
                    });

                    // 创建 StreamReader
                    let reader = crate::session::StreamReader::new(stream_id, receive_rx);

                    // Server side: create stream without waiting for SYNACK
                    // The receiver is discarded since server doesn't need it
                    let (stream, _synack_rx) =
                        Stream::new(stream_id, reader, self.stream_data_tx.clone());

                    let stream = Arc::new(stream);
                    // Bind BEFORE registration so the instance identity is
                    // live for every FIN it may later emit.
                    stream.bind_self();

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
                        // A duplicate SID on a LIVE stream is ignored
                        // upstream (`streams.LoadOrStore` keeps the
                        // existing instance) — it must not recreate the
                        // stream, overwrite the map, or kill the session.
                        if streams.contains_key(&stream_id) {
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] duplicate SYN for live stream {} — ignored",
                                stream_id
                            );
                            return Ok(());
                        }
                        // Stream-count bound: a SYN flood must not grow
                        // the maps without limit. Refuse ONLY this stream
                        // — a FIN is the close primitive both versions
                        // share (upstream `stream.Close()` on refusal);
                        // no SynAck, which a v2 peer would misread as the
                        // stream being accepted.
                        if streams.len() >= MAX_STREAMS_PER_SESSION {
                            drop(receive_map);
                            drop(streams);
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] refusing stream {} — {} stream limit",
                                stream_id,
                                MAX_STREAMS_PER_SESSION
                            );
                            self.write_control_frame(Frame::control(Command::Fin, stream_id))
                                .await?;
                            return Ok(());
                        }
                        receive_map.insert(
                            stream_id,
                            StreamRx {
                                tx: receive_tx,
                                budget: Some(budget),
                            },
                        );
                        streams.insert(stream_id, stream.clone());
                    }

                    tracing::trace!(
                        session_id = session_id,
                        "[Session] Stream {} stored and ready for callback",
                        stream_id
                    );

                    // Notify callback if set — a BOUNDED admission queue:
                    // a saturated listener must refuse the stream
                    // (FIN + drop), never let inbound SYNs pile into an
                    // unbounded channel while handlers stall.
                    let mut refuse = false;
                    if let Some(callback_guard) = &self.on_new_stream {
                        let callback = callback_guard.lock().await;
                        if let Some(tx) = callback.as_ref() {
                            if tx.try_send(stream.clone()).is_err() {
                                refuse = true;
                            }
                        } else {
                            refuse = true;
                        }
                    } else {
                        refuse = true;
                    }
                    if refuse {
                        tracing::warn!(
                            session_id = session_id,
                            "[Session] stream {} admission saturated — refusing",
                            stream_id
                        );
                        let owner = stream.owner();
                        let res = self
                            .write_control_frame_owned(
                                Frame::control(Command::Fin, stream_id),
                                owner,
                            )
                            .await;
                        self.evict_stream_if_same(stream_id, &stream, AnyTlsError::StreamClosed)
                            .await;
                        res?;
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
                    // Any SynAck proves the peer's control plane is alive —
                    // disarm the session watchdog `open_stream` armed
                    // (upstream disarms on frame receipt, before the stream
                    // lookup, so an unknown-sid SynAck still counts).
                    if let Some(prev) = self.syn_watchdog.lock().unwrap().take() {
                        prev.abort();
                    }
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
                            tracing::debug!(
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
                // A FIN with payload is malformed — the command never
                // carries data upstream.
                if !frame.data.is_empty() {
                    return Err(AnyTlsError::Protocol("FIN with payload".into()));
                }
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
                // Client settings (server side). Only a NON-EMPTY map
                // arms SYN admission — an empty Settings frame carries
                // no `v`/client info and upstream leaves `hasSettings`
                // unset for it, so it must not unlock SYN.
                if self.is_client || frame.data.is_empty() {
                    return Ok(());
                }
                {
                    self.client_settings_received
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    let settings = StringMap::from_bytes(&frame.data);

                    // padding-md5 parity with upstream
                    // (`m["padding-md5"] != paddingF.Md5`): a missing key
                    // compares as "" — different from any real md5 — so a
                    // client that omits the fingerprint gets the raw
                    // scheme pushed exactly like a mismatched one.
                    {
                        let padding_guard = self.padding.read().await;
                        if settings.get("padding-md5").map(String::as_str)
                            != Some(padding_guard.md5())
                        {
                            tracing::debug!(
                                "[Session] Client padding-md5 missing/mismatch, sending update"
                            );
                            let update_frame = Frame::with_data(
                                Command::UpdatePaddingScheme,
                                0,
                                Bytes::copy_from_slice(padding_guard.raw_scheme()),
                            );
                            drop(padding_guard);
                            self.write_control_frame(update_frame).await?;
                        }
                    }

                    // Check client version — parse wide: `v=999` parses
                    // upstream (`strconv.Atoi`) and must negotiate v2;
                    // a u8 parse would reject it as overflow.
                    if let Some(v_str) = settings.get("v")
                        && let Ok(v) = v_str.parse::<u32>()
                        && v >= 2
                    {
                        self.peer_version.store(
                            v.min(u8::MAX as u32) as u8,
                            std::sync::atomic::Ordering::Relaxed,
                        );

                        // Send ServerSettings — extras merge FIRST so a
                        // custom entry can never shadow the protocol
                        // version: `v=2` is the server's own statement.
                        let mut server_settings = StringMap::new();
                        if let Some(extra) = &self.server_settings {
                            for (k, v) in extra.clone().into_vec() {
                                server_settings.insert(k, v);
                            }
                        }
                        server_settings.insert("v", "2");
                        let server_settings_frame = Frame::with_data(
                            Command::ServerSettings,
                            0,
                            Bytes::from(server_settings.to_bytes()),
                        );
                        self.write_control_frame(server_settings_frame).await?;
                    }
                }
            }
            Command::ServerSettings => {
                // Server settings (client side)
                if self.is_client && !frame.data.is_empty() {
                    let settings = StringMap::from_bytes(&frame.data);
                    if let Some(v_str) = settings.get("v")
                        && let Ok(v) = v_str.parse::<u32>()
                    {
                        self.peer_version.store(
                            v.min(u8::MAX as u32) as u8,
                            std::sync::atomic::Ordering::Relaxed,
                        );
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
                // Alert message - fatal error, should close session. An
                // EMPTY alert is ignored upstream (the handler only acts
                // on a non-empty payload), so it cannot kill the session.
                if frame.data.is_empty() {
                    return Ok(());
                }
                let alert_msg = String::from_utf8_lossy(&frame.data).to_string();
                tracing::error!("[Session] Received Alert frame (fatal): {}", alert_msg);
                // Close admission and wake the writer too, not just the flag:
                // a blocked physical write must stop with the entire session.
                self.close().await?;
                return Err(AnyTlsError::Protocol(format!("Alert: {}", alert_msg)));
            }
            Command::HeartRequest => {
                // Heartbeat request - respond with HeartResponse
                if !frame.data.is_empty() {
                    return Err(AnyTlsError::Protocol("HeartRequest with payload".into()));
                }
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
                if !frame.data.is_empty() {
                    return Err(AnyTlsError::Protocol("HeartResponse with payload".into()));
                }
                tracing::debug!(
                    "[Session] Received HeartResponse (stream_id={})",
                    frame.stream_id
                );

                if let Some(heartbeat_state) = &self.heartbeat {
                    let mut last = heartbeat_state.last_received.lock().await;
                    *last = Instant::now();
                }
            }
            Command::Waste => {
                // Padding bytes — expected on every padded write; the
                // scheme already spent them, so discard without a log.
            }
        }
        Ok(())
    }

    /// Evict a specific `Stream` generation from both maps (two-lock order
    /// like `close`), then mark it locally-closed and resolve its
    /// synack-waiter. Leaves a newer stream that recycled `stream_id`
    /// untouched (F05/F06).
    async fn evict_stream_if_same(&self, stream_id: u32, expected: &Arc<Stream>, err: AnyTlsError) {
        let removed = {
            let mut streams = self.streams.write().await;
            let mut receive_map = self.stream_receive_tx.write().await;
            let matches = streams
                .get(&stream_id)
                .is_some_and(|cur| Arc::ptr_eq(cur, expected));
            if matches {
                receive_map.remove(&stream_id);
                streams.remove(&stream_id)
            } else {
                None
            }
        };
        if let Some(stream) = removed {
            stream.close_with_error(AnyTlsError::StreamClosed);
            stream.notify_synack(Err(err));
        }
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
        self: &Arc<Self>,
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
        stream.bind_self();

        // Acquire both locks before mutating either map, in close()'s order.
        {
            let mut streams = self.streams.write().await;
            let mut receive_map = self.stream_receive_tx.write().await;
            if self.is_closed() {
                return Err(AnyTlsError::SessionClosed);
            }
            receive_map.insert(
                stream_id,
                StreamRx {
                    tx: receive_tx,
                    // A server session that opens streams itself (the dev
                    // fixture does) must meter inbound data on them too —
                    // the Push path's `expect` assumes every server slot
                    // carries a budget. Client sessions stay unmetered.
                    budget: (!self.is_client).then(|| {
                        Arc::new(PendingBudget {
                            stream: std::sync::atomic::AtomicUsize::new(0),
                            frames: std::sync::atomic::AtomicUsize::new(0),
                            session: Arc::clone(&self.pending_in),
                        })
                    }),
                },
            );
            streams.insert(stream_id, stream.clone());
        }
        let mut guard = crate::session::stream::OpeningStreamGuard::new(Arc::clone(&stream));

        tracing::trace!("[Session] Stream {} stored in session", stream_id);

        // Upstream `synDone` parity: on a v2+ peer, every open beyond the
        // first stream (sid >= 2 — sid 1 predates the ServerSettings
        // handshake) re-arms a session-level deadline that closes the
        // *session* when no SynAck arrives. Each open aborts the previous
        // deadline; a SynAck disarms it (see `Command::SynAck`). The task
        // holds `Weak` so a dropped session needs no cleanup, and close()
        // deliberately does NOT abort the handle — the watchdog task itself
        // may be the close() caller.
        //
        // The arm deliberately precedes the SYN enqueue — upstream arms
        // before `writeControlFrame` and keeps the watcher on write error.
        // One Rust-specific edge: if the caller drops this future while
        // `enqueue_frame` pends on the writer budget, the armed watchdog
        // outlives a SYN that was never enqueued and closes the session
        // ~3s later. Erring toward closing matches upstream intent (a
        // saturated writer budget is itself a wedged-session symptom), and
        // a cancel-path disarm cannot distinguish this arm from a later
        // open's re-armed one.
        if self.is_client
            && stream_id >= 2
            && self.peer_version.load(std::sync::atomic::Ordering::Relaxed) >= 2
            && !self.is_closed()
        {
            let weak = Arc::downgrade(self);
            let watchdog = tokio::spawn(async move {
                time::sleep(SYN_WATCHDOG_TIMEOUT).await;
                if let Some(session) = weak.upgrade() {
                    tracing::warn!(
                        session_id = session.id(),
                        "[Session] No SYNACK within {:?} of open_stream - closing session",
                        SYN_WATCHDOG_TIMEOUT
                    );
                    // Detach the close: `abort()` on this task's handle —
                    // by a racing SynAck disarm or a later re-arm — can
                    // still land while `close()` is suspended (writer lock
                    // + 1 s shutdown timeout), which would drop the future
                    // mid-teardown after `is_closed` was already set and
                    // strand the drain/shutdown forever (close() is
                    // idempotent and non-resumable). A spawned close runs
                    // to completion; an abort before the spawn is a clean
                    // disarm. Go parity: upstream's watcher goroutine is
                    // uncancellable once it selects the deadline branch.
                    tokio::spawn(async move {
                        let _ = session.close().await;
                    });
                }
            });
            let mut slot = self.syn_watchdog.lock().unwrap();
            if let Some(prev) = slot.replace(watchdog.abort_handle()) {
                prev.abort();
            }
        }

        // Send SYN frame — fire-and-forget into the session's single FIFO
        // writer (anytls-go `streamWrite` parity): ordering ahead of the
        // stream's first data frame is all the open needs. Awaiting the
        // wire write+flush here would cost every stream open one full
        // writer-queue round-trip on top of the address frame's.
        tracing::trace!("[Session] Sending SYN frame for stream {}", stream_id);
        let frame = Frame::control(Command::Syn, stream_id);
        self.stream_data_tx.enqueue_frame(frame).await?;
        tracing::trace!("[Session] SYN frame queued for stream {}", stream_id);

        guard.disarm();
        Ok((stream, synack_rx))
    }

    /// Disable buffering (this will flush buffer on next write)
    pub fn disable_buffering(&self) {
        self.buffering
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Queue a data frame without awaiting the wire write — the same
    /// FIFO as `write_data_frame`, minus the writer-queue round-trip
    /// (anytls-go parity: the stream-open address write never waited on
    /// a flush). A closed session still fails fast at enqueue time.
    pub async fn enqueue_data_frame(&self, stream_id: u32, data: Bytes) -> Result<()> {
        self.stream_data_tx
            .enqueue_frame(Frame::data(stream_id, data))
            .await
    }

    /// Enqueue a Flush marker at the tail of the writer FIFO — the
    /// queue-ordered replacement for a bare [`disable_buffering`]
    /// (Self::disable_buffering) call. While `buffering` holds, every
    /// classified frame folds into `self.buffer` untouched by the wire
    /// writer; when this marker drains, the batch's classification pass
    /// clears `buffering` and the accumulated image goes out as ONE
    /// atomic wire write. Enqueued immediately after the dial's address
    /// frame, that pins [Settings+SYN+addr] into packet 1 regardless of
    /// how the writer task happened to interleave its drains (upstream
    /// `writeConn` parity).
    ///
    /// Returns the barrier receiver; callers that only need the FIFO
    /// position drop it.
    pub(crate) fn enqueue_flush_marker(&self) -> Result<oneshot::Receiver<Result<()>>> {
        self.stream_data_tx.flush()
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

    /// Write a control frame to connection. Upstream bounds every
    /// control write (`writeAndRetry` in 5s); the queue-wait plus the
    /// physical write share one deadline so a wedged peer can't park a
    /// SYN/FIN/Alert forever.
    pub async fn write_control_frame(&self, frame: Frame) -> Result<()> {
        self.write_control_frame_owned(frame, None).await
    }

    /// `write_control_frame` carrying an owner token — checked under the
    /// physical writer lock right before bytes enter the transport, and
    /// marked abandoned if the caller's deadline expires or is cancelled
    /// before commit (F05/F06).
    async fn write_control_frame_owned(
        &self,
        frame: Frame,
        owner: Option<std::sync::Weak<Stream>>,
    ) -> Result<()> {
        struct AbandonOnDrop(Option<Arc<std::sync::atomic::AtomicBool>>);
        impl Drop for AbandonOnDrop {
            fn drop(&mut self) {
                if let Some(flag) = self.0.take() {
                    flag.store(true, std::sync::atomic::Ordering::Release);
                }
            }
        }

        let abandoned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut guard = AbandonOnDrop(Some(Arc::clone(&abandoned)));
        match tokio::time::timeout(
            CONTROL_WRITE_TIMEOUT,
            self.stream_data_tx
                .write_frame_cancellable(frame, owner, Some(abandoned)),
        )
        .await
        {
            Ok(result) => {
                guard.0 = None;
                result
            }
            Err(_) => Err(AnyTlsError::Protocol("control write deadline".into())),
        }
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

    /// Drive one transport write/flush step without ever dropping a
    /// partially-polled future mid-session (required by `SslStream` write
    /// retry semantics). Enforces `CONTROL_WRITE_TIMEOUT` only while a
    /// control frame is pending (`force_deadline` or queued `ControlTicket`),
    /// so data-only backpressure never kills a session and slow-but-progressing
    /// writes reset the timer on every forward step (NEW-02).
    async fn drive_io<F, T>(&self, fut: F, force_deadline: bool) -> Result<T>
    where
        F: std::future::Future<Output = std::io::Result<T>>,
    {
        tokio::pin!(fut);
        loop {
            let notified = self.stream_data_tx.control_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if force_deadline || self.stream_data_tx.has_pending_controls() {
                return match time::timeout(CONTROL_WRITE_TIMEOUT, &mut fut).await {
                    Ok(Ok(v)) => Ok(v),
                    Ok(Err(e)) => Err(AnyTlsError::Io(e)),
                    Err(_) => Err(AnyTlsError::Protocol("control write deadline".into())),
                };
            }
            tokio::select! {
                res = &mut fut => return res.map_err(AnyTlsError::Io),
                _ = &mut notified => {}
            }
        }
    }

    async fn write_all_progress(
        &self,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
        mut buf: &[u8],
        force_deadline: bool,
    ) -> Result<()> {
        while !buf.is_empty() {
            let n = self.drive_io(writer.write(buf), force_deadline).await?;
            if n == 0 {
                return Err(AnyTlsError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "anytls session writer accepted zero bytes",
                )));
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    /// Write buffer to connection with padding applied
    async fn write_with_padding(&self, buffer: BytesMut) -> Result<()> {
        let padding_factory = if self.send_padding {
            Some(self.padding.read().await.clone())
        } else {
            None
        };
        let mut writer = self.writer.lock().await;
        self.write_with_padding_locked(&mut **writer, padding_factory.as_deref(), buffer, false)
            .await
    }

    async fn write_with_padding_locked(
        &self,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
        padding_factory: Option<&PaddingFactory>,
        mut buffer: BytesMut,
        force_deadline: bool,
    ) -> Result<()> {
        use crate::padding::CHECK_MARK;
        use bytes::BufMut;

        let Some(padding_factory) = padding_factory.filter(|_| self.send_padding) else {
            self.write_all_progress(writer, &buffer, force_deadline)
                .await?;
            return self.drive_io(writer.flush(), force_deadline).await;
        };

        // Increment packet counter. The authentication packet already
        // consumed scheme index 0 (`send_authentication` calls
        // `generate_record_payload_sizes(0)` for padding0), so the first
        // padded session write must index the scheme at 1 — `fetch_add`
        // returns the OLD value, upstream `pktCounter.Add(1)` the new one.
        let pkt = self
            .pkt_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let stop = padding_factory.stop();

        if pkt >= stop {
            self.write_all_progress(writer, &buffer, force_deadline)
                .await?;
            return self.drive_io(writer.flush(), force_deadline).await;
        }

        let pkt_sizes = padding_factory.generate_record_payload_sizes(pkt);
        if pkt_sizes.is_empty() {
            self.write_all_progress(writer, &buffer, force_deadline)
                .await?;
            return self.drive_io(writer.flush(), force_deadline).await;
        }

        for size in pkt_sizes {
            let remain_payload_len = buffer.len();

            if size == CHECK_MARK {
                if remain_payload_len == 0 {
                    break;
                }
                continue;
            }

            let size = size as usize;

            if remain_payload_len > size {
                self.write_all_progress(writer, &buffer[..size], force_deadline)
                    .await?;
                buffer = buffer.split_off(size);
            } else if remain_payload_len > 0 {
                let padding_len = size.saturating_sub(remain_payload_len + HEADER_OVERHEAD_SIZE);

                if padding_len > 0 {
                    let mut padding_frame =
                        BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + padding_len);
                    padding_frame.put_u8(Command::Waste as u8);
                    padding_frame.put_u32(0);
                    padding_frame.put_u16(padding_len as u16);
                    padding_frame.put_bytes(0, padding_len);
                    buffer.put_slice(&padding_frame);
                }

                self.write_all_progress(writer, &buffer, force_deadline)
                    .await?;
                buffer.clear();
            } else {
                let mut padding_frame = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + size);
                padding_frame.put_u8(Command::Waste as u8);
                padding_frame.put_u32(0);
                padding_frame.put_u16(size as u16);
                padding_frame.put_bytes(0, size);

                self.write_all_progress(writer, &padding_frame, force_deadline)
                    .await?;
            }
        }

        if !buffer.is_empty() {
            self.write_all_progress(writer, &buffer, force_deadline)
                .await?;
        }

        self.drive_io(writer.flush(), force_deadline).await
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
        let recv_span = info_span!(
            "anytls.session.recv",
            session_id = session.id(),
            role = "client",
            bytes_in = field::Empty,
            iterations = field::Empty
        );
        tokio::spawn(
            async move {
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
            }
            .instrument(recv_span),
        );

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
    ///
    /// Each turn drains *every* queued request — `recv` for the first,
    /// `try_recv` for the rest — then writes the whole batch under one
    /// writer lock with one flush. That amortizes the upstream model
    /// (anytls-go/mihomo pay a single `conn.Write` under the session
    /// mutex per frame) into a single write call per queue depth instead
    /// of an MPSC hop + task wakeup + lock + flush *per frame*.
    pub async fn process_stream_data(&self) -> Result<()> {
        let Some(mut receiver) = self.stream_data_rx.lock().await.take() else {
            return Ok(());
        };
        // Reused across drains: the queue list itself, the classified
        // wire frames, and the contiguous encode scratch the
        // non-vectored and padding write paths fill.
        let mut requests: Vec<WriteRequest> = Vec::new();
        let mut frames: Vec<WireFrame> = Vec::new();
        let mut encode_scratch = BytesMut::with_capacity(64 * 1024);
        loop {
            let closed = self.close_notify.notified();
            tokio::pin!(closed);
            closed.as_mut().enable();
            if self.is_closed() {
                break;
            }
            let first = tokio::select! {
                biased;
                _ = &mut closed => break,
                request = receiver.recv() => match request {
                    Some(request) => request,
                    None => break,
                },
            };
            requests.push(first);
            while let Ok(request) = receiver.try_recv() {
                requests.push(request);
            }
            let result = tokio::select! {
                biased;
                // Partial frames may only be abandoned when this entire
                // session is already closed and will never be pooled again.
                _ = &mut closed => break,
                result = self.write_batch(&mut requests, &mut frames, &mut encode_scratch) => result,
            };
            requests.clear();
            frames.clear();
            if let Err(error) = &result {
                tracing::debug!(session_id = self.id(), %error, "AnyTLS session writer failed");
            }
            if result.is_err() {
                // No writer lock is held here; close() can safely shut it down.
                self.close().await?;
                return Err(AnyTlsError::SessionClosed);
            }
        }
        Ok(())
    }

    /// Encode and write one drained queue batch, resolve every request's
    /// completion, then evict the batch's FIN streams.
    ///
    /// Ordering is the queue's FIFO order end to end: frames admitted
    /// while `buffering` still holds fold into `self.buffer` and resolve
    /// immediately (the old `write_frame_inner` contract); `self.buffer`
    /// always leads the wire image; FIN and Flush markers disable
    /// buffering exactly where they sit in the queue.
    async fn write_batch(
        &self,
        requests: &mut Vec<WriteRequest>,
        frames: &mut Vec<WireFrame>,
        encode_scratch: &mut BytesMut,
    ) -> Result<()> {
        frames.reserve(requests.len());
        let mut flush_waiters: Vec<oneshot::Sender<Result<()>>> = Vec::new();
        for request in requests.drain(..) {
            match request {
                WriteRequest::Frame {
                    frame,
                    _permit,
                    _control,
                    completion,
                    owner,
                    abandoned,
                } => {
                    if frame.cmd == Command::Fin {
                        // A cancelled initial dial must not leave its
                        // Settings/SYN/FIN buffered until another dial.
                        self.disable_buffering();
                    }
                    if frame.data.len() > u16::MAX as usize {
                        return Err(AnyTlsError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "AnyTLS frame payload exceeds u16 length",
                        )));
                    }
                    let mut header = [0u8; HEADER_OVERHEAD_SIZE];
                    header[0] = u8::from(frame.cmd);
                    header[1..5].copy_from_slice(&frame.stream_id.to_be_bytes());
                    header[5..7].copy_from_slice(&(frame.data.len() as u16).to_be_bytes());
                    if self.buffering.load(std::sync::atomic::Ordering::Relaxed) {
                        if abandoned
                            .as_ref()
                            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire))
                        {
                            if let Some(completion) = completion {
                                let _ = completion.send(Err(AnyTlsError::Protocol(
                                    "control write deadline".into(),
                                )));
                            }
                            continue;
                        }
                        let mut buffer = self.buffer.lock().await;
                        buffer.extend_from_slice(&header);
                        buffer.extend_from_slice(&frame.data);
                        drop(buffer);
                        if let Some(completion) = completion {
                            let _ = completion.send(Ok(()));
                        }
                    } else {
                        frames.push(WireFrame::Split {
                            cmd: frame.cmd,
                            stream_id: frame.stream_id,
                            header,
                            data: frame.data,
                            _permit,
                            _control,
                            completion,
                            owner,
                            abandoned,
                        });
                    }
                }
                WriteRequest::Wire {
                    wire,
                    _permit,
                    completion,
                } => {
                    if self.buffering.load(std::sync::atomic::Ordering::Relaxed) {
                        self.buffer.lock().await.extend_from_slice(&wire);
                        if let Some(completion) = completion {
                            let _ = completion.send(Ok(()));
                        }
                    } else {
                        frames.push(WireFrame::Wire {
                            wire,
                            _permit,
                            completion,
                        });
                    }
                }
                WriteRequest::Flush(completion) => {
                    self.disable_buffering();
                    flush_waiters.push(completion);
                }
            }
        }

        let buffered = if self.buffering.load(std::sync::atomic::Ordering::Relaxed) {
            Vec::new()
        } else {
            std::mem::take(&mut *self.buffer.lock().await)
        };
        if buffered.is_empty() && frames.is_empty() && flush_waiters.is_empty() {
            return Ok(());
        }
        let padding_factory = if self.send_padding {
            let pf = self.padding.read().await.clone();
            (self.pkt_counter.load(std::sync::atomic::Ordering::Relaxed) < pf.stop()).then_some(pf)
        } else {
            None
        };
        let force_deadline = !buffered.is_empty();

        // Acquire the physical writer lock BEFORE checking owner/abandon
        // state so no frame can retire or recycle a SID between validation
        // and the wire write (F05/F06).
        let mut fin_streams: Vec<(u32, Option<std::sync::Weak<Stream>>)> = Vec::new();
        let result: Result<()> = {
            let mut writer = self.writer.lock().await;
            let needs_commit_check = frames.iter().any(|f| {
                matches!(
                    f,
                    WireFrame::Split {
                        abandoned: Some(_),
                        ..
                    } | WireFrame::Split {
                        owner: Some(_),
                        cmd: Command::Fin | Command::SynAck,
                        ..
                    }
                )
            });
            if needs_commit_check {
                let streams = self.streams.read().await;
                let mut kept = Vec::with_capacity(frames.len());
                for frame in frames.drain(..) {
                    match frame {
                        WireFrame::Split {
                            cmd,
                            stream_id,
                            header,
                            data,
                            _permit,
                            _control,
                            completion,
                            owner,
                            abandoned,
                        } => {
                            if abandoned
                                .as_ref()
                                .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire))
                            {
                                if let Some(completion) = completion {
                                    let _ = completion.send(Err(AnyTlsError::Protocol(
                                        "control write deadline".into(),
                                    )));
                                }
                                continue;
                            }
                            if let Some(owner_ref) = &owner
                                && matches!(cmd, Command::Fin | Command::SynAck)
                            {
                                let live = matches!(
                                    (owner_ref.upgrade(), streams.get(&stream_id)),
                                    (Some(o), Some(current)) if Arc::ptr_eq(&o, current)
                                );
                                if !live {
                                    if let Some(completion) = completion {
                                        let _ = completion.send(Err(AnyTlsError::StreamClosed));
                                    }
                                    continue;
                                }
                            }
                            kept.push(WireFrame::Split {
                                cmd,
                                stream_id,
                                header,
                                data,
                                _permit,
                                _control,
                                completion,
                                owner,
                                abandoned,
                            });
                        }
                        other => kept.push(other),
                    }
                }
                drop(streams);
                *frames = kept;
            }
            for frame in frames.iter() {
                if let WireFrame::Split {
                    cmd: Command::Fin,
                    stream_id,
                    owner,
                    ..
                } = frame
                {
                    fin_streams.push((*stream_id, owner.clone()));
                }
            }

            if buffered.is_empty() && frames.is_empty() {
                if flush_waiters.is_empty() {
                    Ok(())
                } else {
                    self.drive_io(writer.flush(), force_deadline).await
                }
            } else if padding_factory.is_some() {
                encode_scratch.clear();
                encode_scratch.reserve(
                    buffered.len() + frames.iter().map(WireFrame::wire_len).sum::<usize>(),
                );
                encode_scratch.extend_from_slice(&buffered);
                for frame in frames.iter() {
                    frame.encode_into(encode_scratch);
                }
                self.write_with_padding_locked(
                    &mut **writer,
                    padding_factory.as_deref(),
                    encode_scratch.split(),
                    force_deadline,
                )
                .await
            } else {
                self.write_wire_locked(
                    &mut **writer,
                    &buffered,
                    frames,
                    encode_scratch,
                    force_deadline,
                )
                .await
            }
        };

        if !fin_streams.is_empty() {
            let mut streams = self.streams.write().await;
            let mut receive_map = self.stream_receive_tx.write().await;
            for (stream_id, owner) in fin_streams {
                if let Some(owner) = &owner {
                    let live = matches!(
                        (owner.upgrade(), streams.get(&stream_id)),
                        (Some(o), Some(current)) if Arc::ptr_eq(&o, current)
                    );
                    if !live {
                        continue;
                    }
                }
                if let Some(stream) = streams.remove(&stream_id) {
                    receive_map.remove(&stream_id);
                    stream.close_with_error(AnyTlsError::StreamClosed);
                    stream.notify_synack(Err(AnyTlsError::StreamClosed));
                }
            }
        }

        for mut frame in frames.drain(..) {
            if let Some(completion) = frame.completion().take() {
                let _ = completion.send(clone_result(&result));
            }
        }
        for waiter in flush_waiters {
            let _ = waiter.send(clone_result(&result));
        }
        result
    }

    /// Unpadded batch write under an already-held writer lock + one flush.
    async fn write_wire_locked(
        &self,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
        buffered: &[u8],
        frames: &[WireFrame],
        encode_scratch: &mut BytesMut,
        force_deadline: bool,
    ) -> Result<()> {
        use std::io::IoSlice;
        if writer.is_write_vectored() {
            let mut slices: Vec<IoSlice<'_>> = Vec::with_capacity(1 + frames.len() * 2);
            if !buffered.is_empty() {
                slices.push(IoSlice::new(buffered));
            }
            for frame in frames {
                match frame {
                    WireFrame::Wire { wire, .. } => slices.push(IoSlice::new(wire)),
                    WireFrame::Split { header, data, .. } => {
                        slices.push(IoSlice::new(header));
                        if !data.is_empty() {
                            slices.push(IoSlice::new(data));
                        }
                    }
                }
            }
            let mut pending = slices.as_mut_slice();
            while !pending.is_empty() {
                let n = self
                    .drive_io(writer.write_vectored(pending), force_deadline)
                    .await?;
                if n == 0 {
                    return Err(AnyTlsError::Io(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "anytls session writer accepted zero bytes",
                    )));
                }
                IoSlice::advance_slices(&mut pending, n);
            }
        } else {
            encode_scratch.clear();
            encode_scratch
                .reserve(buffered.len() + frames.iter().map(WireFrame::wire_len).sum::<usize>());
            encode_scratch.extend_from_slice(buffered);
            for frame in frames {
                frame.encode_into(encode_scratch);
            }
            self.write_all_progress(writer, &encode_scratch[..], force_deadline)
                .await?;
        }
        self.drive_io(writer.flush(), force_deadline).await
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

    /// Split an already-authenticated transport into a server `Session`
    /// plus the stream-accept channel the dispatcher drains. TLS-free:
    /// the caller owns the outer handshake, the user-table auth preface,
    /// and the combined deadline. `run_server` still has to be spawned —
    /// nothing moves frames until then.
    /// Streams a SYN may park in the accept queue before the dispatcher
    /// drains them. Beyond it, admission is refused (FIN) rather than
    /// growing memory or wedging recv_loop.
    pub const STREAM_ACCEPT_QUEUE: usize = MAX_STREAMS_PER_SESSION;

    pub fn new_inbound<S>(
        io: S,
        padding: Arc<PaddingFactory>,
    ) -> (Arc<Self>, mpsc::Receiver<Arc<Stream>>)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = tokio::io::split(io);
        let mut session = Self::new_server(reader, writer, padding);
        let (tx, rx) = mpsc::channel(Self::STREAM_ACCEPT_QUEUE);
        session.set_stream_callback(tx);
        (Arc::new(session), rx)
    }

    /// Drive the session's read loop and its single writer task until
    /// the session dies — peer EOF, io error, or a protocol violation
    /// that `handle_frame` already closed it for. The caller still owns
    /// stream dispatch; this is the keepalive.
    ///
    /// Both halves are polled IN THIS TASK rather than spawned:
    /// aborting `run_server` drops them with it, and once either half
    /// finishes the survivor is polled concurrently with `close()` so a
    /// half holding `writer` or `close_lock` can release it instead of
    /// deadlocking teardown (NEW-01 / F07).
    pub async fn run_server(self: &Arc<Self>) {
        let recv = self.recv_loop();
        let writer = self.process_stream_data();
        tokio::pin!(recv);
        tokio::pin!(writer);
        let recv_ended = tokio::select! {
            _ = &mut recv => true,
            _ = &mut writer => false,
        };
        self.initiate_close();
        if recv_ended {
            let _ = tokio::join!(writer, self.close());
        } else {
            let _ = tokio::join!(recv, self.close());
        }
    }

    /// The stream-accept ACK the spec schedules: exactly one empty
    /// SynAck for a v2+ peer, none for v1. The production listener calls
    /// this after a TCP destination parses and validates, and right
    /// after the UoT marker is recognized — before any dial — so a
    /// blocked rule lookup cannot reorder it behind stream data.
    ///
    /// Awaiting the queue completion is deliberate: the caller that
    /// then hands the stream to routing can test "ACK precedes first
    /// data" deterministically.
    ///
    /// Takes the stream INSTANCE, not a bare sid: if a FIN already
    /// retired it and the SID has since been recycled, the ACK must
    /// not bless a different stream living under the same id (F05).
    pub async fn handshake_success(&self, stream: &Arc<Stream>) -> Result<()> {
        {
            let streams = self.streams.read().await;
            match streams.get(&stream.id()) {
                Some(current) if Arc::ptr_eq(current, stream) => {}
                _ => {
                    return Err(AnyTlsError::Protocol(format!(
                        "stream {} already retired before SynAck",
                        stream.id()
                    )));
                }
            }
        }
        if self.peer_version() >= 2 {
            // Owner-gated admission: the pre-check above proves the
            // instance is registered NOW, but the write commits later —
            // the writer rechecks at commit so a retirement landing in
            // the gap strands this SynAck instead of blessing a
            // recycled sid (F05).
            self.write_control_frame_owned(
                Frame::control(Command::SynAck, stream.id()),
                Some(Arc::downgrade(stream)),
            )
            .await?;
        }
        Ok(())
    }
}

/// A queued frame mid-drain. The budget permit rides inside so it is
/// held through the physical write.
enum WireFrame {
    /// Pre-encoded wire header + the owned `Bytes` payload (which moves
    /// to the wire unmodified — no copy).
    Split {
        cmd: Command,
        stream_id: u32,
        header: [u8; HEADER_OVERHEAD_SIZE],
        data: Bytes,
        _permit: Option<OwnedSemaphorePermit>,
        _control: Option<ControlTicket>,
        completion: Option<oneshot::Sender<Result<()>>>,
        owner: Option<std::sync::Weak<Stream>>,
        abandoned: Option<Arc<std::sync::atomic::AtomicBool>>,
    },
    /// `[header | payload]` already contiguous in one `Bytes` — the
    /// headroom path from `Stream::poll_write_bytes_data`. The wire
    /// write moves it verbatim: no header reassembly, no payload copy.
    Wire {
        wire: Bytes,
        _permit: Option<OwnedSemaphorePermit>,
        completion: Option<oneshot::Sender<Result<()>>>,
    },
}

impl WireFrame {
    /// Encoded byte length of this frame on the wire.
    fn wire_len(&self) -> usize {
        match self {
            WireFrame::Split { data, .. } => HEADER_OVERHEAD_SIZE + data.len(),
            WireFrame::Wire { wire, .. } => wire.len(),
        }
    }

    /// Append this frame's wire image to `scratch` (non-vectored and
    /// padding paths — the contiguous arm copies nothing, it extends
    /// straight from the owned `Bytes`).
    fn encode_into(&self, scratch: &mut BytesMut) {
        match self {
            WireFrame::Split { header, data, .. } => {
                scratch.extend_from_slice(header);
                scratch.extend_from_slice(data);
            }
            WireFrame::Wire { wire, .. } => scratch.extend_from_slice(wire),
        }
    }

    fn completion(&mut self) -> &mut Option<oneshot::Sender<Result<()>>> {
        match self {
            WireFrame::Split { completion, .. } | WireFrame::Wire { completion, .. } => completion,
        }
    }
}

/// One batch outcome fans out to every waiter of the drain;
/// `AnyTlsError` is not `Clone`, so each waiter gets an equivalent error.
fn clone_result(result: &Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(match e {
            AnyTlsError::Io(e) => AnyTlsError::Io(std::io::Error::new(e.kind(), e.to_string())),
            AnyTlsError::Protocol(s) => AnyTlsError::Protocol(s.clone()),
            _ => AnyTlsError::SessionClosed,
        }),
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
    async fn enqueued_syn_survives_immediate_stream_close() {
        let (io, mut peer) = duplex(4);
        let (reader, writer) = tokio::io::split(io);
        let session = Arc::new(Session::new_server(reader, writer, create_test_padding()));
        let worker = Arc::clone(&session);
        let task = tokio::spawn(async move { worker.process_stream_data().await });

        // The SYN enqueue is atomic: once `open_stream` returns, the
        // session writer owns the frame — closing the stream at once
        // cannot tear it, and the close's FIN lands behind it in the
        // same FIFO.
        let (stream, _synack_rx) = session.open_stream().await.unwrap();
        stream.close();

        // SYN is seven bytes but the wire only holds four — the writer
        // must still emit all of it, in order, before the FIN.
        assert_eq!(peer.read_u8().await.unwrap(), u8::from(Command::Syn));
        let mut tail = [0; 6];
        peer.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, [0, 0, 0, 1, 0, 0]);
        assert_eq!(read_frame(&mut peer).await, Frame::control(Command::Fin, 1));
        // Eviction runs on the writer task right after the wire write.
        for _ in 0..50 {
            if !session.has_active_streams().await {
                break;
            }
            tokio::task::yield_now().await;
        }
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

    /// An `AsyncWrite` that records every byte and counts write/flush
    /// calls — the seam for asserting a drained batch is ONE wire write.
    struct RecordingWriter {
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
        writes: Arc<std::sync::atomic::AtomicUsize>,
        flushes: Arc<std::sync::atomic::AtomicUsize>,
        vectored: bool,
    }

    impl tokio::io::AsyncWrite for RecordingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_write_vectored(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let mut total = 0;
            for buf in bufs {
                self.bytes.lock().unwrap().extend_from_slice(buf);
                total += buf.len();
            }
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::task::Poll::Ready(Ok(total))
        }
        fn is_write_vectored(&self) -> bool {
            self.vectored
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// N queued frames must reach the wire as ONE write under ONE writer
    /// lock + ONE flush — the drain-batch contract — on both the vectored
    /// and the contiguous write paths, in queue FIFO order.
    #[tokio::test]
    async fn queued_frames_write_as_one_batch() {
        for vectored in [true, false] {
            let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
            let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let flushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let writer = RecordingWriter {
                bytes: Arc::clone(&bytes),
                writes: Arc::clone(&writes),
                flushes: Arc::clone(&flushes),
                vectored,
            };
            let session = Arc::new(Session::new_server(
                tokio::io::empty(),
                writer,
                create_test_padding(),
            ));

            // Queue everything BEFORE the writer task starts, so its very
            // first recv+try_recv pass sees the full batch.
            const N: u8 = 8;
            for i in 0..N {
                session
                    .stream_data_tx
                    .enqueue_frame(Frame::data(1, Bytes::from(vec![i; 4])))
                    .await
                    .unwrap();
            }
            // The Flush marker is the barrier: it resolves once the batch
            // that carries it has been written + flushed.
            let barrier = session.stream_data_tx.flush().unwrap();

            let worker = Arc::clone(&session);
            let task = tokio::spawn(async move { worker.process_stream_data().await });
            time::timeout(Duration::from_secs(2), barrier)
                .await
                .expect("flush barrier must resolve")
                .unwrap()
                .unwrap();

            assert_eq!(
                writes.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "a drained batch must be a single write call (vectored={vectored})"
            );
            assert_eq!(
                flushes.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "a drained batch must flush once (vectored={vectored})"
            );

            let mut expect = Vec::new();
            for i in 0..N {
                expect.push(u8::from(Command::Push));
                expect.extend_from_slice(&1u32.to_be_bytes());
                expect.extend_from_slice(&4u16.to_be_bytes());
                expect.extend_from_slice(&[i; 4]);
            }
            assert_eq!(
                *bytes.lock().unwrap(),
                expect,
                "wire image must be the frames in FIFO order (vectored={vectored})"
            );

            session.close().await.unwrap();
            task.await.unwrap().unwrap();
        }
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

    /// The default log filter is `info`, so anything at `info` or above on
    /// the per-stream success path is one log line per proxied connection
    /// (issue #495 item 13). Drive a full client-side stream lifecycle —
    /// SYNACK, data, FIN, and the peer's in-flight PSH that lands after the
    /// local eviction — and require it to stay below `info`.
    #[tokio::test]
    async fn stream_lifecycle_emits_no_info_or_above_events() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tracing::instrument::WithSubscriber;
        use tracing_subscriber::{Layer, layer::SubscriberExt};
        struct CountInfoOrAbove(Arc<AtomicUsize>);
        impl<S: tracing::Subscriber> Layer<S> for CountInfoOrAbove {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                // `Level` orders by verbosity: ERROR < WARN < INFO < DEBUG.
                if *event.metadata().level() <= tracing::Level::INFO {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(CountInfoOrAbove(Arc::clone(&count)));
        async {
            let session = Arc::new(Session::new_client(
                tokio::io::empty(),
                tokio::io::sink(),
                create_test_padding().into_shared(),
                None,
            ));
            let worker = Arc::clone(&session);
            let writer = tokio::spawn(async move { worker.process_stream_data().await });

            let (stream, synack) = session.open_stream().await.unwrap();
            let stream_id = stream.id();

            session
                .handle_frame(Frame::control(Command::SynAck, stream_id))
                .await
                .unwrap();
            // The success arm really ran: the waiter resolved `Ok`.
            assert!(synack.await.unwrap().is_ok());

            session
                .handle_frame(Frame::data(stream_id, Bytes::from_static(b"data")))
                .await
                .unwrap();
            session
                .handle_frame(Frame::control(Command::Fin, stream_id))
                .await
                .unwrap();
            // Late PSH for the now-evicted stream (peer had it in flight).
            session
                .handle_frame(Frame::data(stream_id, Bytes::from_static(b"late")))
                .await
                .unwrap();

            writer.abort();
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
        // `write_with_padding` derives the scheme index as
        // `fetch_add(1) + 1` (auth consumed index 0 out-of-band), so a
        // fresh counter puts this write at scheme index 1 — the 65535
        // record the scheme declares.
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
        // packet 1. No large allocation is performed by this probe. The
        // counter stays at 0: `write_with_padding` indexes the scheme at
        // `fetch_add(1) + 1`, so the write below lands on index 1 — where
        // an accepted scheme would try to declare a 2 GiB payload.
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

    /// `write_frame` resolves its completion oneshot only when the session
    /// writer task drains the queue — every open_stream test needs it.
    fn spawn_writer(session: &Arc<Session>) -> tokio::task::JoinHandle<Result<()>> {
        let worker = Arc::clone(session);
        tokio::spawn(async move { worker.process_stream_data().await })
    }

    /// `AsyncWrite` that records `poll_shutdown` — the observable evidence
    /// that `close()` ran its writer-shutdown phase to completion.
    struct ShutdownTracker {
        flag: Arc<std::sync::atomic::AtomicBool>,
    }
    impl tokio::io::AsyncWrite for ShutdownTracker {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.flag.store(true, std::sync::atomic::Ordering::Relaxed);
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Upstream `synDone` parity (#625): on a v2+ peer, opening any stream
    /// beyond the first arms a session-level deadline — no SynAck within
    /// `SYN_WATCHDOG_TIMEOUT` closes the *session*.
    #[tokio::test(start_paused = true)]
    async fn syn_watchdog_closes_v2_session_without_synack() {
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            PaddingFactory::default().into_shared(),
            None,
        ));
        let _writer = spawn_writer(&session);
        session
            .peer_version
            .store(2, std::sync::atomic::Ordering::Relaxed);

        // sid 1 predates the ServerSettings handshake — never arms.
        let (_s1, _ack1) = session.open_stream().await.unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_none());

        let (_s2, _ack2) = session.open_stream().await.unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_some());
        // Let the spawned watchdog register its sleep before advancing.
        tokio::task::yield_now().await;

        time::advance(SYN_WATCHDOG_TIMEOUT - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(!session.is_closed());

        time::advance(Duration::from_millis(2)).await;
        for _ in 0..200 {
            if session.is_closed() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("syn watchdog must close the session past the deadline");
    }

    /// A SynAck disarms the deadline — the session must survive past it.
    #[tokio::test(start_paused = true)]
    async fn synack_disarms_session_watchdog() {
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            PaddingFactory::default().into_shared(),
            None,
        ));
        let _writer = spawn_writer(&session);
        session
            .peer_version
            .store(2, std::sync::atomic::Ordering::Relaxed);

        let (_s1, _a1) = session.open_stream().await.unwrap();
        let (_s2, _a2) = session.open_stream().await.unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_some());

        session
            .handle_frame(Frame::control(Command::SynAck, 2))
            .await
            .unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_none());

        time::advance(SYN_WATCHDOG_TIMEOUT * 2).await;
        tokio::task::yield_now().await;
        assert!(!session.is_closed());
    }

    /// Disarm happens before the stream lookup (upstream `cmdSYNACK`
    /// semantics): a SynAck for an unknown sid still proves the peer's
    /// control plane is alive and must cancel the deadline.
    #[tokio::test(start_paused = true)]
    async fn unknown_sid_synack_disarms_session_watchdog() {
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            PaddingFactory::default().into_shared(),
            None,
        ));
        let _writer = spawn_writer(&session);
        session
            .peer_version
            .store(2, std::sync::atomic::Ordering::Relaxed);

        let (_s1, _a1) = session.open_stream().await.unwrap();
        let (_s2, _a2) = session.open_stream().await.unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_some());

        session
            .handle_frame(Frame::control(Command::SynAck, 999))
            .await
            .unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_none());

        time::advance(SYN_WATCHDOG_TIMEOUT * 2).await;
        tokio::task::yield_now().await;
        assert!(!session.is_closed());
    }

    /// The #625 scenario: a peer that answers heartbeats but never SynAcks.
    /// Only SynAck may disarm — a HeartResponse mid-window must leave the
    /// deadline armed and the session must still close on expiry.
    #[tokio::test(start_paused = true)]
    async fn heart_response_does_not_disarm_session_watchdog() {
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            PaddingFactory::default().into_shared(),
            None,
        ));
        let _writer = spawn_writer(&session);
        session
            .peer_version
            .store(2, std::sync::atomic::Ordering::Relaxed);

        let (_s1, _a1) = session.open_stream().await.unwrap();
        let (_s2, _a2) = session.open_stream().await.unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_some());
        // Let the spawned watchdog register its sleep before advancing —
        // with fire-and-forget SYN enqueue `open_stream` no longer parks
        // on the writer queue, so the task needs an explicit yield slot.
        tokio::task::yield_now().await;

        session
            .handle_frame(Frame::control(Command::HeartResponse, 0))
            .await
            .unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_some());

        time::advance(SYN_WATCHDOG_TIMEOUT + Duration::from_millis(1)).await;
        for _ in 0..200 {
            if session.is_closed() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("heartbeat-only peer must still hit the synDone deadline");
    }

    /// Each new open aborts the previous deadline and starts a fresh one —
    /// a stale watchdog must not kill the session at its original expiry.
    #[tokio::test(start_paused = true)]
    async fn later_open_rearms_session_watchdog() {
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            PaddingFactory::default().into_shared(),
            None,
        ));
        let _writer = spawn_writer(&session);
        session
            .peer_version
            .store(2, std::sync::atomic::Ordering::Relaxed);

        let (_s1, _a1) = session.open_stream().await.unwrap();
        let (_s2, _a2) = session.open_stream().await.unwrap();
        tokio::task::yield_now().await;

        time::advance(Duration::from_secs(2)).await;
        // sid 3 re-arms at t=2s: the first deadline (t=3s) must not fire.
        let (_s3, _a3) = session.open_stream().await.unwrap();
        tokio::task::yield_now().await;

        time::advance(Duration::from_millis(1500)).await; // t = 3.5s
        tokio::task::yield_now().await;
        assert!(!session.is_closed());

        time::advance(Duration::from_secs(2)).await; // t = 5.5s, past the re-armed deadline
        for _ in 0..200 {
            if session.is_closed() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("re-armed watchdog must close the session at its own deadline");
    }

    /// A late SynAck must not kill a watchdog-initiated `close()` mid-flight:
    /// `is_closed` is set in close's synchronous prefix, so a cancelled close
    /// strands the stream drain + writer shutdown forever (close() is
    /// idempotent and never retries). The close is detached from the
    /// abortable watchdog task — abort lands before the detach point or
    /// misses it entirely (#625 review).
    #[tokio::test(start_paused = true)]
    async fn synack_cannot_abort_inflight_watchdog_close() {
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            ShutdownTracker {
                flag: Arc::clone(&shutdown),
            },
            PaddingFactory::default().into_shared(),
            None,
        ));
        let _writer = spawn_writer(&session);
        session
            .peer_version
            .store(2, std::sync::atomic::Ordering::Relaxed);

        let (_s1, _a1) = session.open_stream().await.unwrap();
        let (_s2, _a2) = session.open_stream().await.unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_some());
        tokio::task::yield_now().await;

        // Pend the watchdog's close() on the writer lock — close's last
        // suspension point — so the SynAck's abort lands while teardown is
        // mid-flight (the stream drain has already run).
        let writer_guard = session.writer.lock().await;
        time::advance(SYN_WATCHDOG_TIMEOUT).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        session
            .handle_frame(Frame::control(Command::SynAck, 2))
            .await
            .unwrap();
        drop(writer_guard);

        // The detached close must still finish — `writer.shutdown()` is
        // the tail of teardown. If the abort had killed the future the
        // flag would never be set.
        for _ in 0..200 {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                assert!(session.is_closed());
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("watchdog close aborted mid-flight: writer never shut down");
    }

    /// Server sessions never arm the watchdog even with a v2+ peer — the
    /// `is_client` gate is load-bearing: server sessions learn the peer
    /// version from the client's Settings frame, and `open_stream` is pub.
    #[tokio::test(start_paused = true)]
    async fn server_session_never_arms_watchdog() {
        let session = Arc::new(Session::new_server(
            tokio::io::empty(),
            tokio::io::sink(),
            PaddingFactory::default(),
        ));
        let _writer = spawn_writer(&session);
        session
            .peer_version
            .store(2, std::sync::atomic::Ordering::Relaxed);

        let (_s1, _a1) = session.open_stream().await.unwrap();
        let (_s2, _a2) = session.open_stream().await.unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_none());

        time::advance(SYN_WATCHDOG_TIMEOUT * 2).await;
        tokio::task::yield_now().await;
        assert!(!session.is_closed());
    }

    /// Below v2 the peer has no SynAck contract — no watchdog ever arms.
    #[tokio::test(start_paused = true)]
    async fn pre_v2_peer_never_arms_session_watchdog() {
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            PaddingFactory::default().into_shared(),
            None,
        ));
        let _writer = spawn_writer(&session);

        let (_s1, _a1) = session.open_stream().await.unwrap();
        let (_s2, _a2) = session.open_stream().await.unwrap();
        assert!(session.syn_watchdog.lock().unwrap().is_none());

        time::advance(SYN_WATCHDOG_TIMEOUT * 2).await;
        tokio::task::yield_now().await;
        assert!(!session.is_closed());
    }
}

/// Server-side wire contract tests: the frames a real client sends over
/// `new_inbound`'s transport and the exact frames it must see back —
/// W1 (v1 silence) / W2 (v2 ordering) / W3 (violation + budget paths).
#[cfg(test)]
mod server_protocol_tests {
    use super::*;
    use crate::StreamIo;
    use crate::padding::PaddingFactory;
    use crate::session::writer::MAX_FRAME_PAYLOAD;
    use crate::util::StringMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio::time;

    fn test_padding() -> Arc<PaddingFactory> {
        Arc::new(PaddingFactory::new(crate::padding::DEFAULT_PADDING_SCHEME.as_bytes()).unwrap())
    }

    fn spawn_server(
        io: DuplexStream,
    ) -> (
        Arc<Session>,
        mpsc::Receiver<Arc<Stream>>,
        tokio::task::JoinHandle<()>,
    ) {
        let (session, rx) = Session::new_inbound(io, test_padding());
        let worker = Arc::clone(&session);
        let task = tokio::spawn(async move { worker.run_server().await });
        (session, rx, task)
    }

    fn settings_frame(pairs: &[(&str, &str)]) -> Frame {
        let mut map = StringMap::new();
        for (k, v) in pairs {
            map.insert(*k, *v);
        }
        Frame::with_data(Command::Settings, 0, Bytes::from(map.to_bytes()))
    }

    async fn write_frame(peer: &mut DuplexStream, frame: &Frame) {
        peer.write_u8(u8::from(frame.cmd)).await.unwrap();
        peer.write_u32(frame.stream_id).await.unwrap();
        peer.write_u16(frame.data.len() as u16).await.unwrap();
        peer.write_all(&frame.data).await.unwrap();
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
    async fn v2_settings_then_synack_in_wire_order() {
        let (io, mut peer) = duplex(1 << 16);
        let (session, mut accept, task) = spawn_server(io);

        // v2 client that does not echo the server's padding md5: the
        // scheme push must precede the version handshake, exactly the
        // upstream ordering.
        write_frame(
            &mut peer,
            &settings_frame(&[("v", "2"), ("client", "meow-test")]),
        )
        .await;
        let update = read_frame(&mut peer).await;
        assert_eq!(update.cmd, Command::UpdatePaddingScheme);
        assert!(!update.data.is_empty());
        let server_settings = read_frame(&mut peer).await;
        assert_eq!(server_settings.cmd, Command::ServerSettings);
        let map = StringMap::from_bytes(&server_settings.data);
        assert_eq!(map.get("v").map(String::as_str), Some("2"));

        write_frame(&mut peer, &Frame::control(Command::Syn, 1)).await;
        let stream = time::timeout(Duration::from_secs(2), accept.recv())
            .await
            .expect("stream accept stalled")
            .expect("accept channel closed");
        assert_eq!(stream.id(), 1);
        session.handshake_success(&stream).await.unwrap();
        let synack = read_frame(&mut peer).await;
        assert_eq!(synack, Frame::control(Command::SynAck, 1));

        // `run_server` ends when the transport EOFs or the session dies —
        // close the client half to let the task drain deterministically.
        drop(peer);
        session.close().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn v1_peer_gets_no_server_settings_or_synack() {
        let (io, mut peer) = duplex(1 << 16);
        let padding = test_padding();
        let (session, mut accept, task) = spawn_server(io);

        // v1 client echoing the scheme md5 — no UpdatePaddingScheme,
        // no ServerSettings, no SynAck ever reach the wire.
        write_frame(
            &mut peer,
            &settings_frame(&[("v", "1"), ("padding-md5", padding.md5())]),
        )
        .await;
        write_frame(&mut peer, &Frame::control(Command::Syn, 1)).await;
        let stream = time::timeout(Duration::from_secs(2), accept.recv())
            .await
            .expect("stream accept stalled")
            .expect("accept channel closed");
        assert_eq!(stream.id(), 1);
        session.handshake_success(&stream).await.unwrap();

        // The next server→client frame must be the heartbeat answer —
        // proving nothing (settings/SynAck) was emitted ahead of it.
        write_frame(&mut peer, &Frame::control(Command::HeartRequest, 0)).await;
        let response = read_frame(&mut peer).await;
        assert_eq!(response.cmd, Command::HeartResponse);

        drop(peer);
        session.close().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn syn_before_settings_alerts_and_closes() {
        let (io, mut peer) = duplex(1 << 16);
        let (session, _accept, task) = spawn_server(io);

        write_frame(&mut peer, &Frame::control(Command::Syn, 1)).await;
        let alert = read_frame(&mut peer).await;
        assert_eq!(alert.cmd, Command::Alert);
        // Upstream `die` text verbatim — the peer surfaces it.
        assert_eq!(
            String::from_utf8_lossy(&alert.data),
            "client did not send its settings"
        );

        for _ in 0..50 {
            if session.is_closed() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(session.is_closed());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_stream_id_is_ignored() {
        let (io, mut peer) = duplex(1 << 16);
        let padding = test_padding();
        let (session, mut accept, task) = spawn_server(io);

        write_frame(
            &mut peer,
            &settings_frame(&[("v", "1"), ("padding-md5", padding.md5())]),
        )
        .await;
        write_frame(&mut peer, &Frame::control(Command::Syn, 9)).await;
        let stream = time::timeout(Duration::from_secs(2), accept.recv())
            .await
            .expect("stream accept stalled")
            .expect("accept channel closed");
        assert_eq!(stream.id(), 9);

        // Upstream `LoadOrStore` parity: the second SYN on the live SID
        // is ignored — NO Alert, no session death, no second stream.
        write_frame(&mut peer, &Frame::control(Command::Syn, 9)).await;
        write_frame(&mut peer, &Frame::control(Command::HeartRequest, 0)).await;
        let response = read_frame(&mut peer).await;
        assert_eq!(
            response.cmd,
            Command::HeartResponse,
            "the first post-dup frame must be the heartbeat answer — the dup SYN emitted nothing"
        );
        assert!(matches!(
            time::timeout(Duration::from_millis(500), accept.recv()).await,
            Err(_) | Ok(None)
        ));
        assert!(!session.is_closed());

        drop(peer);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn empty_psh_is_dropped_not_eof() {
        let (io, mut peer) = duplex(1 << 16);
        let padding = test_padding();
        let (_session, mut accept, task) = spawn_server(io);

        write_frame(
            &mut peer,
            &settings_frame(&[("v", "1"), ("padding-md5", padding.md5())]),
        )
        .await;
        write_frame(&mut peer, &Frame::control(Command::Syn, 3)).await;
        let stream = time::timeout(Duration::from_secs(2), accept.recv())
            .await
            .expect("stream accept stalled")
            .expect("accept channel closed");

        // Zero-length PSH: carries no data — must NOT queue (a 0-byte
        // channel entry reads as a spurious EOF downstream, F02).
        write_frame(&mut peer, &Frame::control(Command::Push, 3)).await;
        // Real data after it must arrive intact and ordered.
        write_frame(
            &mut peer,
            &Frame::with_data(Command::Push, 3, Bytes::from_static(b"hello")),
        )
        .await;

        use tokio::io::AsyncReadExt as _;
        let mut io_stream = StreamIo(stream);
        let mut buf = [0u8; 5];
        time::timeout(Duration::from_secs(2), io_stream.read_exact(&mut buf))
            .await
            .expect("read stalled")
            .expect("read failed");
        assert_eq!(&buf, b"hello");
        // And the stream must not be EOF'd by the empty frame: a further
        // read pends rather than returning Ok(0).
        let mut one = [0u8; 1];
        assert!(
            time::timeout(Duration::from_millis(200), io_stream.read(&mut one))
                .await
                .is_err(),
            "empty PSH must not surface a 0-byte (EOF) read"
        );

        drop(peer);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn v2_stream_limit_refuses_with_fin() {
        let (io, mut peer) = duplex(1 << 16);
        let padding = test_padding();
        let (session, mut accept, _task) = spawn_server(io);

        write_frame(
            &mut peer,
            &settings_frame(&[("v", "2"), ("padding-md5", padding.md5())]),
        )
        .await;
        let server_settings = read_frame(&mut peer).await;
        assert_eq!(server_settings.cmd, Command::ServerSettings);

        for sid in 1..=MAX_STREAMS_PER_SESSION as u32 {
            write_frame(&mut peer, &Frame::control(Command::Syn, sid)).await;
            let stream = time::timeout(Duration::from_secs(2), accept.recv())
                .await
                .expect("stream accept stalled")
                .expect("accept channel closed");
            assert_eq!(stream.id(), sid);
        }

        let overflow = MAX_STREAMS_PER_SESSION as u32 + 1;
        write_frame(&mut peer, &Frame::control(Command::Syn, overflow)).await;
        let refusal = read_frame(&mut peer).await;
        // Upstream refusal closes ONLY the stream: a bare FIN, and no
        // SynAck — a v2 client must not read an accept for a refused SID.
        assert_eq!(refusal.cmd, Command::Fin);
        assert_eq!(refusal.stream_id, overflow);
        assert!(refusal.data.is_empty());
        assert!(
            time::timeout(Duration::from_millis(500), accept.recv())
                .await
                .is_err(),
            "refused stream must not reach the accept channel"
        );
        assert!(!session.is_closed());
    }

    #[tokio::test]
    async fn per_stream_pending_overflow_evicts_only_that_stream() {
        let (io, mut peer) = duplex(1 << 16);
        let padding = test_padding();
        let (session, mut accept, _task) = spawn_server(io);

        write_frame(
            &mut peer,
            &settings_frame(&[("v", "1"), ("padding-md5", padding.md5())]),
        )
        .await;
        for sid in [1u32, 2] {
            write_frame(&mut peer, &Frame::control(Command::Syn, sid)).await;
            accept.recv().await.unwrap();
        }

        // Nobody drains stream 1: flood it past the 256 KiB per-stream
        // pending bound. MAX_FRAME_PAYLOAD-sized PSH frames reach it in
        // five sends.
        let chunk = vec![0xAA; MAX_FRAME_PAYLOAD];
        let mut sent = 0usize;
        while sent <= MAX_STREAM_PENDING {
            write_frame(&mut peer, &Frame::data(1, Bytes::copy_from_slice(&chunk))).await;
            sent += chunk.len();
        }

        // Stream 1 is evicted; the session and stream 2 stay healthy —
        // prove it by pushing one PSH to stream 2 and reading it back
        // through the stream API.
        write_frame(&mut peer, &Frame::data(2, Bytes::from_static(b"ok"))).await;
        // The eviction is synchronous inside the read loop that just
        // consumed the flood, so by the time a new frame lands the map
        // already reflects it.
        for _ in 0..50 {
            if !session.has_active_streams().await || session.is_closed() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!session.is_closed());
        assert!(session.has_active_streams().await, "stream 2 must survive");
    }

    #[tokio::test]
    async fn teardown_completes_when_recv_fails_while_writer_holds_lock() {
        // Small duplex so one data frame stalls `writer` inside `write_batch`
        // while holding `self.writer`. A protocol error on `recv_loop` then
        // ends `recv` first; `run_server` must wake and join `writer` rather
        // than deadlocking on `self.writer` inside `close()` (NEW-01).
        let (io, mut peer) = duplex(64);
        let padding = test_padding();
        let (session, mut accept, task) = spawn_server(io);

        write_frame(
            &mut peer,
            &settings_frame(&[("v", "1"), ("padding-md5", padding.md5())]),
        )
        .await;
        write_frame(&mut peer, &Frame::control(Command::Syn, 1)).await;
        let stream = accept.recv().await.unwrap();
        stream
            .send_data(Bytes::from(vec![0xAB; 4096]))
            .await
            .unwrap();
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Malformed SYN with payload makes `recv_loop` return `Err` directly.
        write_frame(
            &mut peer,
            &Frame::with_data(Command::Syn, 2, Bytes::from_static(b"bad")),
        )
        .await;

        time::timeout(Duration::from_secs(2), task)
            .await
            .expect("run_server deadlocked on writer lock")
            .unwrap();
        assert!(
            session
                .teardown_done
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn data_only_backpressure_survives_control_deadline() {
        let (io, mut peer) = duplex(64);
        let padding = test_padding();
        let (session, mut accept, task) = spawn_server(io);

        write_frame(
            &mut peer,
            &settings_frame(&[("v", "1"), ("padding-md5", padding.md5())]),
        )
        .await;
        write_frame(&mut peer, &Frame::control(Command::Syn, 1)).await;
        let stream = accept.recv().await.unwrap();
        stream
            .send_data(Bytes::from(vec![0xCD; 1024]))
            .await
            .unwrap();
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Peer pauses reading past CONTROL_WRITE_TIMEOUT; pure PSH backpressure
        // must not kill the session (NEW-02).
        time::advance(CONTROL_WRITE_TIMEOUT * 2).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(!session.is_closed());

        let got = read_frame(&mut peer).await;
        assert_eq!(got.cmd, Command::Push);
        assert_eq!(got.data.len(), 1024);

        drop(peer);
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn commit_gate_strands_stale_frames_when_sid_recycles_under_backpressure() {
        // Fill the server->client pipe so `writer` holds `self.writer` on a
        // PSH batch. Queue a SynAck and an overflow FIN for generation 1 of
        // SID 7, let the overflow FIN time out (F06), retire generation 1 via
        // peer FIN and open generation 2 on the SAME SID 7 (F05), then drain
        // the pipe: neither the stale SynAck nor the abandoned FIN may reach
        // the peer or evict generation 2.
        let (io, mut peer) = duplex(128);
        let padding = test_padding();
        let (session, mut accept, task) = spawn_server(io);

        write_frame(
            &mut peer,
            &settings_frame(&[("v", "2"), ("padding-md5", padding.md5())]),
        )
        .await;
        let _ = read_frame(&mut peer).await; // ServerSettings

        // Stream 1 clogs the server->client pipe with pure PSH data.
        write_frame(&mut peer, &Frame::control(Command::Syn, 1)).await;
        let s1 = accept.recv().await.unwrap();
        s1.send_data(Bytes::from(vec![0x11; 4096])).await.unwrap();
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Open SID 7 (gen 1) and queue its SynAck behind the stalled PSH.
        write_frame(&mut peer, &Frame::control(Command::Syn, 7)).await;
        let s7_gen1 = accept.recv().await.unwrap();
        let ack_session = Arc::clone(&session);
        let s7_for_ack = Arc::clone(&s7_gen1);
        let ack_handle =
            tokio::spawn(async move { ack_session.handshake_success(&s7_for_ack).await });
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Peer retires SID 7 (gen 1) and immediately reopens SID 7 (gen 2)
        // BEFORE the server pipe drains.
        write_frame(&mut peer, &Frame::control(Command::Fin, 7)).await;
        write_frame(&mut peer, &Frame::control(Command::Syn, 7)).await;
        let s7_gen2 = accept.recv().await.unwrap();
        assert!(!Arc::ptr_eq(&s7_gen1, &s7_gen2));

        // Drain the stalled PSH on stream 1, then send a heartbeat to flush
        // any frame the writer committed behind it.
        let clogged = read_frame(&mut peer).await;
        assert_eq!((clogged.cmd, clogged.stream_id), (Command::Push, 1));
        assert!(ack_handle.await.unwrap().is_err());

        write_frame(&mut peer, &Frame::control(Command::HeartRequest, 0)).await;
        let next = read_frame(&mut peer).await;
        assert_eq!(
            next.cmd,
            Command::HeartResponse,
            "stale gen-1 SynAck must not reach the wire for gen-2 SID 7"
        );

        // Gen 2 is still registered and can now legitimately ACK and carry data.
        session.handshake_success(&s7_gen2).await.unwrap();
        let gen2_ack = read_frame(&mut peer).await;
        assert_eq!(gen2_ack, Frame::control(Command::SynAck, 7));

        drop(peer);
        task.await.unwrap();
    }
}
