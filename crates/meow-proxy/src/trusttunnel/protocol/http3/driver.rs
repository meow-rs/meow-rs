//! The quiche driver for one HTTP/3 connection: a single task owning the UDP
//! socket, the `quiche::Connection` and its `quiche::h3::Connection`. It runs
//! the QUIC event loop and bridges quiche's synchronous state machine to the
//! async [`H3Stream`] handles the pool hands out.
//!
//! The pool never touches quiche: it sends [`Cmd`]s (open a CONNECT stream,
//! write bytes) and reads payload over per-stream channels. Read-side
//! backpressure is real — the driver stops pulling a stream's body while that
//! stream's inbound channel is full, so a stalled consumer throttles the
//! endpoint through QUIC flow control, and `read_notify` wakes the driver
//! when the consumer drains.

use super::stream::{H3Stream, WRITE_BUFFER_BYTES};
use http::StatusCode;
use quiche::h3::{self, NameValue as _};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, mpsc::error::TrySendError, oneshot, Notify, OwnedSemaphorePermit, Semaphore},
};
use tokio_util::sync::CancellationToken;

/// HTTP/3 error codes this client sends (PROTOCOL.md §10.2).
const H3_NO_ERROR: u64 = 0x100;
const H3_REQUEST_CANCELLED: u64 = 0x10c;

const CMD_CHANNEL_CAP: usize = 256;
const STREAM_READ_CHANNEL_CAP: usize = 16;
const BODY_CHUNK_BYTES: usize = 16 * 1024;

/// Pool → driver commands.
pub(super) enum Cmd {
    Open {
        headers: Vec<h3::Header>,
        fin: bool,
        reply: oneshot::Sender<io::Result<(StatusCode, H3Stream)>>,
    },
    Write {
        id: u64,
        data: Vec<u8>,
        permit: OwnedSemaphorePermit,
    },
}

/// A CONNECT waiting for stream credit.
struct PendingOpen {
    headers: Vec<h3::Header>,
    fin: bool,
    reply: oneshot::Sender<io::Result<(StatusCode, H3Stream)>>,
}

/// Driver → [`H3Stream`] read items.
pub(super) enum ReadItem {
    Data(Vec<u8>),
    Eof,
    Err(io::ErrorKind),
}

/// What the pool can learn about a live connection without asking the driver.
pub(super) struct Shared {
    /// Streams already open plus the peer's remaining credit: how many
    /// streams this connection could carry in total, right now. The pool
    /// compares its own lease count against it, so a connection whose credit
    /// has run out stops attracting dials and the pool spreads instead.
    pub(super) ceiling: AtomicUsize,
    /// The peer's remaining bidirectional stream credit.
    pub(super) credit: AtomicUsize,
    pub(super) closed: AtomicBool,
    /// Sticky admission state: stream credit cannot undo a GOAWAY.
    pub(super) accepting: AtomicBool,
}

struct WriteChunk {
    data: Vec<u8>,
    offset: usize,
    /// Returning this permit makes the corresponding bytes writable again.
    _permit: Option<OwnedSemaphorePermit>,
}

struct StreamState {
    read_tx: mpsc::Sender<ReadItem>,
    out: VecDeque<WriteChunk>,
    capacity: Arc<Semaphore>,
    /// The CONNECT's reply, and the handle that goes with it. Both are taken
    /// when the response headers arrive: until then the caller is still
    /// awaiting, and nothing has been written to the stream.
    reply: Option<oneshot::Sender<io::Result<(StatusCode, H3Stream)>>>,
    handle: Option<H3Stream>,
    /// Set to tell the app the write half is done; the FIN itself is sent by
    /// the driver, since only it may touch quiche.
    shutdown: Arc<AtomicBool>,
    fin_sent: bool,
    /// The peer has body bytes for us that `recv_body` has not drained yet.
    body_readable: bool,
    inbound: VecDeque<Vec<u8>>,
    eof_pending: bool,
    eof_sent: bool,
    read_closed: bool,
    failure: Option<io::ErrorKind>,
}

impl StreamState {
    fn abandoned(&self) -> bool {
        match (&self.reply, &self.handle) {
            // Still awaiting the response: the caller giving up (a timeout,
            // or a cancelled dial) is the only way out.
            (Some(reply), _) => reply.is_closed(),
            // Handed out, then dropped: the stream is over once our own FIN
            // is out, or if the app never asked for one.
            _ => {
                self.read_tx.is_closed()
                    && (!self.shutdown.load(Ordering::Acquire) || self.fin_sent)
            }
        }
    }

    fn finished(&self) -> bool {
        self.fin_sent && (self.eof_sent || self.read_closed)
    }

    /// Fail the stream: the caller (or the reader) learns why, and nothing
    /// more is written.
    fn fail(&mut self, kind: io::ErrorKind, reason: &'static str) {
        if self.failure.is_some() {
            return;
        }
        self.failure = Some(kind);
        self.capacity.close();
        self.out.clear();
        self.fin_sent = true;
        self.eof_pending = true;
        if let Some(reply) = self.reply.take() {
            self.handle = None;
            let _ = reply.send(Err(io::Error::new(kind, reason)));
        }
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        self.capacity.close();
    }
}

/// Driver state that is *not* the quiche connection, so helpers can borrow it
/// alongside `&mut conn`.
struct State {
    socket: UdpSocket,
    local: SocketAddr,
    cmd_tx: mpsc::WeakSender<Cmd>,
    cmd_rx: mpsc::Receiver<Cmd>,
    read_notify: Arc<Notify>,
    streams: HashMap<u64, StreamState>,
    /// CONNECTs quiche has no stream credit for yet. They are retried every
    /// iteration, which is what absorbs the race between the pool reading
    /// [`Shared::credit`] and this driver spending it.
    queued: VecDeque<PendingOpen>,
    shared: Arc<Shared>,
}

/// Dial state through to a connection the pool can use: resolves once the
/// QUIC handshake completes, HTTP/3 is negotiated and its control streams are
/// up. Everything the connection owns stops when `cancel` fires.
pub(super) async fn spawn(
    socket: UdpSocket,
    local: SocketAddr,
    conn: quiche::Connection,
    cancel: CancellationToken,
) -> io::Result<(mpsc::Sender<Cmd>, Arc<Shared>)> {
    let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_CAP);
    let shared = Arc::new(Shared {
        ceiling: AtomicUsize::new(usize::MAX),
        credit: AtomicUsize::new(usize::MAX),
        closed: AtomicBool::new(false),
        accepting: AtomicBool::new(true),
    });
    let state = State {
        socket,
        local,
        cmd_tx: cmd_tx.downgrade(),
        cmd_rx,
        read_notify: Arc::new(Notify::new()),
        streams: HashMap::new(),
        queued: VecDeque::new(),
        shared: Arc::clone(&shared),
    };
    let (ready_tx, ready_rx) = oneshot::channel();
    let driving = Arc::clone(&shared);
    let canceled = cancel.clone();
    super::super::spawn_scoped(async move {
        tokio::select! {
            () = canceled.cancelled() => {}
            () = run(state, conn, ready_tx) => {}
        }
        driving.closed.store(true, Ordering::Relaxed);
        driving.accepting.store(false, Ordering::Release);
        canceled.cancel();
    });
    match ready_rx.await {
        Ok(Ok(())) => Ok((cmd_tx, shared)),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "TrustTunnel H3 driver stopped before the handshake completed",
        )),
    }
}

async fn run(
    mut st: State,
    mut conn: quiche::Connection,
    ready_tx: oneshot::Sender<io::Result<()>>,
) {
    let mut ready_tx = Some(ready_tx);
    let mut http3: Option<h3::Connection> = None;
    // Set once every command sender is gone. A closed `mpsc::Receiver`
    // resolves `Ready(None)` on every poll, so leaving that `select!` arm
    // enabled would spin the whole drain period (3×PTO) on a worker thread,
    // re-closing an already-closing connection each turn. Reachable today: a
    // dial whose deadline drops `spawn` while it awaits `ready_rx` drops the
    // only strong `cmd_tx`.
    let mut commands_done = false;
    let mut recv_buf = vec![0u8; 65535];
    let mut send_buf = vec![0u8; 1500];
    let mut body_buf = vec![0u8; BODY_CHUNK_BYTES];

    if let Err(error) = flush_send(&mut st, &mut conn, &mut send_buf).await {
        settle(&mut ready_tx, error);
        return;
    }

    let exit: io::Error = 'driver: loop {
        let timeout = conn.timeout();
        tokio::select! {
            result = st.socket.recv_from(&mut recv_buf) => match result {
                Ok((n, from)) => {
                    let info = quiche::RecvInfo { from, to: st.local };
                    if let Err(error) = conn.recv(&mut recv_buf[..n], info) {
                        tracing::debug!(%error, "TrustTunnel H3 dropped a QUIC packet");
                    }
                }
                Err(error) => break 'driver error,
            },
            cmd = st.cmd_rx.recv(), if !commands_done => match cmd {
                Some(cmd) => handle_cmd(&mut st, cmd),
                // Every handle is gone, including the pool's. Say goodbye
                // once and stop polling this arm; the loop now wakes only on
                // socket and timer events until the drain completes.
                None => {
                    commands_done = true;
                    let _ = conn.close(true, H3_NO_ERROR, b"");
                }
            },
            () = sleep_opt(timeout) => conn.on_timeout(),
            () = st.read_notify.notified() => {}
        }

        if http3.is_none() && conn.is_established() {
            match establish(&mut conn) {
                Ok(negotiated) => {
                    http3 = Some(negotiated);
                    if let Some(ready) = ready_tx.take() {
                        let _ = ready.send(Ok(()));
                    }
                }
                Err(error) => break 'driver error,
            }
        }
        // A connection that starts draining before HTTP/3 is up never
        // handshaked (a rejected certificate, an ALPN the endpoint will not
        // speak). Report it now: quiche only marks such a connection closed
        // once the drain timer elapses, which is long enough to swallow the
        // real reason behind the dial deadline.
        if http3.is_none() && conn.is_draining() {
            break 'driver handshake_failed(&conn);
        }

        if let Some(http3) = http3.as_mut() {
            if let Err(error) = poll_events(&mut st, &mut conn, http3, &mut body_buf) {
                break 'driver error;
            }
            start_queued(&mut st, &mut conn, http3);
            pump_bodies(&mut st, &mut conn, http3, &mut body_buf);
            pump_writes(&mut st, &mut conn, http3);
            cleanup(&mut st, &mut conn);
            publish(&mut st, &conn);
        }

        if let Err(error) = flush_send(&mut st, &mut conn, &mut send_buf).await {
            break 'driver error;
        }
        if conn.is_closed() {
            break 'driver closed_reason(&conn);
        }
    };

    settle(&mut ready_tx, clone_error(&exit));
    st.shared.credit.store(0, Ordering::Relaxed);
    st.shared.ceiling.store(0, Ordering::Relaxed);
    // Only a received FIN is a clean EOF; anything still queued here learns
    // the connection failed, after whatever payload already reached it.
    for (_, mut stream) in st.streams.drain() {
        stream.fail(exit.kind(), "TrustTunnel H3 connection closed");
    }
    for open in st.queued.drain(..) {
        let _ = open.reply.send(Err(clone_error(&exit)));
    }
}

/// Create the HTTP/3 layer over an established QUIC connection, refusing an
/// endpoint that did not negotiate `h3` (PROTOCOL.md §3.2).
fn establish(conn: &mut quiche::Connection) -> io::Result<h3::Connection> {
    if conn.application_proto() != super::tls::ALPN_H3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TrustTunnel endpoint did not negotiate h3",
        ));
    }
    let config =
        h3::Config::new().map_err(|e| io::Error::other(format!("TrustTunnel H3 config: {e}")))?;
    h3::Connection::with_transport(conn, &config)
        .map_err(|e| io::Error::other(format!("TrustTunnel H3 handshake: {e}")))
}

/// Drain HTTP/3 events. An error here is connection-fatal; per-stream
/// failures are recorded on the stream.
fn poll_events(
    st: &mut State,
    conn: &mut quiche::Connection,
    http3: &mut h3::Connection,
    body_buf: &mut [u8],
) -> io::Result<()> {
    loop {
        match http3.poll(conn) {
            Ok((id, h3::Event::Headers { list, .. })) => {
                respond(st, id, &list);
            }
            Ok((id, h3::Event::Data)) => {
                if let Some(stream) = st.streams.get_mut(&id) {
                    stream.body_readable = true;
                } else {
                    // A stream we have already reaped; drain it so HTTP/3's
                    // own flow control keeps moving.
                    while http3.recv_body(conn, id, body_buf).is_ok() {}
                }
            }
            Ok((id, h3::Event::Finished)) => {
                if let Some(stream) = st.streams.get_mut(&id) {
                    if stream.reply.is_some() {
                        stream.fail(
                            io::ErrorKind::UnexpectedEof,
                            "TrustTunnel CONNECT ended without a response",
                        );
                    } else {
                        stream.eof_pending = true;
                    }
                }
            }
            Ok((id, h3::Event::Reset(code))) => {
                if let Some(stream) = st.streams.get_mut(&id) {
                    stream.fail(
                        io::ErrorKind::ConnectionReset,
                        "TrustTunnel endpoint reset the stream",
                    );
                    tracing::debug!(id, code, "TrustTunnel H3 stream reset by the endpoint");
                }
            }
            Ok((_, h3::Event::GoAway)) => {
                // No new request may be sent after a GOAWAY. Established
                // streams keep running; the pool stops electing this
                // connection as soon as it sees no credit.
                st.shared.accepting.store(false, Ordering::Release);
                st.shared.credit.store(0, Ordering::Relaxed);
                st.shared.ceiling.store(0, Ordering::Relaxed);
                for open in st.queued.drain(..) {
                    let _ = open.reply.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "TrustTunnel endpoint is going away",
                    )));
                }
            }
            Ok((_, h3::Event::PriorityUpdate)) => {}
            Err(h3::Error::Done) => return Ok(()),
            Err(error) => return Err(io::Error::other(format!("TrustTunnel H3 failed: {error}"))),
        }
    }
}

/// Deliver a response's status to whoever is awaiting the CONNECT.
fn respond(st: &mut State, id: u64, list: &[h3::Header]) {
    let Some(stream) = st.streams.get_mut(&id) else {
        return;
    };
    let status = match status_of(list) {
        Ok(status) => status,
        Err(error) => {
            let kind = error.kind();
            stream.fail(kind, "TrustTunnel H3 response was malformed");
            return;
        }
    };
    // An informational response is not the answer to the CONNECT; the final
    // one is still coming.
    if status.is_informational() {
        return;
    }
    let (Some(reply), Some(handle)) = (stream.reply.take(), stream.handle.take()) else {
        // A second final response on the same stream is a protocol error on
        // the endpoint's part, not something to act on.
        return;
    };
    let _ = reply.send(Ok((status, handle)));
}

fn status_of(list: &[h3::Header]) -> io::Result<StatusCode> {
    let malformed = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TrustTunnel H3 response has no usable :status",
        )
    };
    let raw = list
        .iter()
        .find(|header| header.name() == b":status")
        .ok_or_else(malformed)?;
    std::str::from_utf8(raw.value())
        .ok()
        .and_then(|text| text.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .ok_or_else(malformed)
}

/// Start the CONNECTs that are waiting for stream credit.
fn start_queued(st: &mut State, conn: &mut quiche::Connection, http3: &mut h3::Connection) {
    while let Some(PendingOpen {
        headers,
        fin,
        reply,
    }) = st.queued.pop_front()
    {
        if reply.is_closed() {
            continue;
        }
        match http3.send_request(conn, &headers, fin) {
            Ok(id) => {
                let (read_tx, read_rx) = mpsc::channel(STREAM_READ_CHANNEL_CAP);
                let capacity = Arc::new(Semaphore::new(WRITE_BUFFER_BYTES as usize));
                let shutdown = Arc::new(AtomicBool::new(false));
                let Some(cmd_tx) = st.cmd_tx.upgrade() else {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "TrustTunnel H3 connection closed",
                    )));
                    return;
                };
                let handle = H3Stream::new(
                    id,
                    read_rx,
                    Arc::clone(&st.read_notify),
                    cmd_tx,
                    Arc::clone(&capacity),
                    Arc::clone(&shutdown),
                );
                st.streams.insert(
                    id,
                    StreamState {
                        read_tx,
                        out: VecDeque::new(),
                        capacity,
                        reply: Some(reply),
                        handle: Some(handle),
                        shutdown,
                        // A `_check` CONNECT is sent with its FIN already
                        // set, so the driver owes no further one.
                        fin_sent: fin,
                        body_readable: false,
                        inbound: VecDeque::new(),
                        eof_pending: false,
                        eof_sent: false,
                        read_closed: false,
                        failure: None,
                    },
                );
            }
            // No credit for another stream yet. Keep it at the front and
            // retry on a later iteration; the caller's dial deadline is what
            // bounds the wait.
            Err(
                h3::Error::StreamBlocked
                | h3::Error::TransportError(quiche::Error::StreamLimit | quiche::Error::Done),
            ) => {
                st.queued.push_front(PendingOpen {
                    headers,
                    fin,
                    reply,
                });
                return;
            }
            // After a GOAWAY quiche refuses new requests outright.
            Err(h3::Error::FrameUnexpected) => {
                let _ = reply.send(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "TrustTunnel endpoint is going away",
                )));
            }
            Err(error) => {
                let _ = reply.send(Err(io::Error::other(format!(
                    "TrustTunnel CONNECT could not be sent: {error}"
                ))));
            }
        }
    }
}

/// Move buffered payload into HTTP/3 DATA frames, and send the FIN once the
/// app has shut the write half down.
fn pump_writes(st: &mut State, conn: &mut quiche::Connection, http3: &mut h3::Connection) {
    for (&id, stream) in &mut st.streams {
        while let Some(chunk) = stream.out.front_mut() {
            match http3.send_body(conn, id, &chunk.data[chunk.offset..], false) {
                Ok(0) | Err(h3::Error::Done) | Err(h3::Error::StreamBlocked) => break,
                Ok(written) => {
                    chunk.offset += written;
                    if chunk.offset == chunk.data.len() {
                        stream.out.pop_front();
                    }
                }
                Err(error) => {
                    tracing::debug!(id, %error, "TrustTunnel H3 stream write failed");
                    stream.fail(
                        io::ErrorKind::BrokenPipe,
                        "TrustTunnel H3 stream write failed",
                    );
                    break;
                }
            }
        }
        if stream.out.is_empty() && stream.shutdown.load(Ordering::Acquire) && !stream.fin_sent {
            match http3.send_body(conn, id, &[], true) {
                Ok(_) => stream.fin_sent = true,
                Err(h3::Error::Done | h3::Error::StreamBlocked) => {}
                Err(error) => {
                    tracing::debug!(id, %error, "TrustTunnel H3 stream finish failed");
                    stream.fail(
                        io::ErrorKind::BrokenPipe,
                        "TrustTunnel H3 stream could not be finished",
                    );
                }
            }
        }
        let _ = flush_pending(stream);
    }
}

/// Pull body bytes for every stream whose consumer has room.
///
/// HTTP/3 re-arms its `Data` event only once `recv_body` has drained the
/// stream, so a partially drained stream would never be reported again —
/// hence the per-stream `body_readable` flag and this unconditional sweep,
/// rather than reading only what `poll()` just announced.
fn pump_bodies(
    st: &mut State,
    conn: &mut quiche::Connection,
    http3: &mut h3::Connection,
    body_buf: &mut [u8],
) {
    for (&id, stream) in &mut st.streams {
        if !stream.body_readable || stream.failure.is_some() {
            continue;
        }
        loop {
            if !flush_pending(stream) {
                // The consumer is full: stop here with the flag set, so QUIC
                // flow control throttles the endpoint until it drains.
                break;
            }
            match http3.recv_body(conn, id, body_buf) {
                Ok(0) => break,
                Ok(read) => stream.inbound.push_back(body_buf[..read].to_vec()),
                Err(h3::Error::Done) => {
                    stream.body_readable = false;
                    break;
                }
                Err(error) => {
                    tracing::debug!(id, %error, "TrustTunnel H3 stream read failed");
                    stream.fail(
                        io::ErrorKind::ConnectionReset,
                        "TrustTunnel H3 stream read failed",
                    );
                    break;
                }
            }
        }
        let _ = flush_pending(stream);
    }
}

/// Try to hand buffered inbound chunks to the consumer. Returns `false` when
/// the consumer's channel is full.
fn flush_pending(stream: &mut StreamState) -> bool {
    while let Some(chunk) = stream.inbound.pop_front() {
        match stream.read_tx.try_send(ReadItem::Data(chunk)) {
            Ok(()) => {}
            Err(TrySendError::Full(ReadItem::Data(chunk))) => {
                stream.inbound.push_front(chunk);
                return false;
            }
            Err(TrySendError::Full(_)) => unreachable!("only Data is sent here"),
            Err(TrySendError::Closed(_)) => {
                stream.inbound.clear();
                stream.read_closed = true;
                return true;
            }
        }
    }
    if stream.eof_pending && !stream.eof_sent && !stream.read_closed {
        let terminal = stream.failure.map_or(ReadItem::Eof, ReadItem::Err);
        match stream.read_tx.try_send(terminal) {
            Ok(()) => stream.eof_sent = true,
            Err(TrySendError::Full(_)) => return false,
            Err(TrySendError::Closed(_)) => stream.read_closed = true,
        }
    }
    true
}

fn handle_cmd(st: &mut State, cmd: Cmd) {
    match cmd {
        Cmd::Write { id, data, permit } => {
            if let Some(stream) = st.streams.get_mut(&id) {
                if stream.failure.is_none() {
                    stream.out.push_back(WriteChunk {
                        data,
                        offset: 0,
                        _permit: Some(permit),
                    });
                }
            }
        }
        Cmd::Open {
            headers,
            fin,
            reply,
        } => st.queued.push_back(PendingOpen {
            headers,
            fin,
            reply,
        }),
    }
}

/// Reap finished and abandoned streams, resetting whatever the endpoint still
/// believes is live.
fn cleanup(st: &mut State, conn: &mut quiche::Connection) {
    let done: Vec<u64> = st
        .streams
        .iter()
        .filter(|(_, stream)| stream.finished() || stream.abandoned())
        .map(|(&id, _)| id)
        .collect();
    for id in done {
        let reaped = st.streams.remove(&id);
        let graceful = reaped.is_some_and(|stream| stream.fin_sent && stream.failure.is_none());
        if !graceful {
            let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, H3_REQUEST_CANCELLED);
        }
        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, H3_REQUEST_CANCELLED);
    }
}

/// Publish what the pool reads between dials.
fn publish(st: &mut State, conn: &quiche::Connection) {
    if !st.shared.accepting.load(Ordering::Acquire) {
        st.shared.credit.store(0, Ordering::Relaxed);
        st.shared.ceiling.store(0, Ordering::Relaxed);
        return;
    }
    let credit = usize::try_from(conn.peer_streams_left_bidi()).unwrap_or(usize::MAX);
    let queued = st.queued.len();
    // Opens still waiting for credit have no stream of their own yet, so
    // count them with the open ones: without that the pool would keep
    // electing a connection whose whole credit is already promised.
    let ceiling = st
        .streams
        .len()
        .saturating_add(queued)
        .saturating_add(credit);
    st.shared
        .credit
        .store(credit.saturating_sub(queued), Ordering::Relaxed);
    st.shared.ceiling.store(ceiling, Ordering::Relaxed);
}

/// Drain quiche's send queue to the socket.
async fn flush_send(
    st: &mut State,
    conn: &mut quiche::Connection,
    out: &mut [u8],
) -> io::Result<()> {
    loop {
        let (written, info) = match conn.send(out) {
            Ok(value) => value,
            Err(quiche::Error::Done) => return Ok(()),
            Err(error) => return Err(io::Error::other(format!("TrustTunnel QUIC send: {error}"))),
        };
        st.socket.send_to(&out[..written], info.to).await?;
    }
}

/// Why a handshake failed. The TLS alert the endpoint sent arrives as a
/// CONNECTION_CLOSE error code, and a locally rejected certificate shows up
/// as our own; either is more useful than "the connection closed".
fn handshake_failed(conn: &quiche::Connection) -> io::Error {
    let Some(error) = conn.local_error().or_else(|| conn.peer_error()) else {
        return closed_reason(conn);
    };
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "TrustTunnel QUIC handshake failed (error {:#x})",
            error.error_code
        ),
    )
}

/// Why a closed connection closed, with the errno preserved when there is
/// one: a local resource failure must not look like an unhealthy endpoint.
fn closed_reason(conn: &quiche::Connection) -> io::Error {
    if let Some(error) = conn.peer_error() {
        return io::Error::other(format!(
            "TrustTunnel endpoint closed the connection (error {:#x})",
            error.error_code
        ));
    }
    if conn.is_timed_out() {
        return io::Error::new(
            io::ErrorKind::TimedOut,
            "TrustTunnel H3 connection timed out",
        );
    }
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "TrustTunnel H3 connection closed",
    )
}

/// `io::Error` is not `Clone`; the dial reply and the stream teardown both
/// need the reason, and both only read its kind and message.
fn clone_error(error: &io::Error) -> io::Error {
    error.raw_os_error().map_or_else(
        || io::Error::new(error.kind(), error.to_string()),
        io::Error::from_raw_os_error,
    )
}

fn settle(ready_tx: &mut Option<oneshot::Sender<io::Result<()>>>, error: io::Error) {
    if let Some(ready) = ready_tx.take() {
        let _ = ready.send(Err(error));
    }
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending().await,
    }
}
