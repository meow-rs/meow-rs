//! Snell v6 record layer.
//!
//! A v6 stream is a sequence of records. Each record has a 7-byte header —
//! version `4`, two reserved bytes, then the padding and payload lengths as
//! big-endian `u16` — followed by the padding and up to `0xffff` payload
//! bytes. AES-128-GCM seals headers and payloads under the argon2id session
//! key; the 12-byte little-endian nonce counter advances after every seal or
//! open, as in v4.
//!
//! How records hit the wire depends on the server's `mode`:
//!
//! | mode         | stream start   | record                                                   |
//! |--------------|----------------|----------------------------------------------------------|
//! | `default`    | salt block     | `prefix ‖ seal(hdr, ad=prefix) ‖ padding ⇄ seal(payload, ad=padding)` |
//! | `unshaped`   | 16-byte salt   | `seal(hdr) ‖ seal(payload)`                              |
//! | `unsafe-raw` | —              | `hdr ‖ payload`                                          |
//!
//! In `default` mode a PSK-derived shape profile decides the prefix and
//! padding lengths, the filler bytes, the salt placement inside the salt
//! block and the `⇄` byte interleaving of padding and sealed payload. The
//! other two modes carry no padding and the reader rejects any.
//!
//! A record without payload is a zero chunk (half-close). It surfaces as
//! v4's zero-chunk error so [`super::protocol::is_zero_chunk`] recognises it;
//! in `default` mode its padding is skipped.
//!
//! Requests are *deferred* ([`V6Conn::defer_request`]) and sent at the head
//! of the next record, so a session's first payload bytes share a record with
//! its request. A read issued before anything was written (server-speaks-
//! first protocols) or an explicit flush sends a deferred request by itself.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::Aes128Gcm;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};

use super::cipher::{aes_gcm, snell_kdf};
use super::v4::{increment_nonce, zero_chunk_err};
use super::v6_shape::{ShapeProfile, ShapeState, RECORD_LEN_MAX, SALT_LEN};

/// Largest payload one record can carry.
pub const MAX_RECORD_PAYLOAD: usize = RECORD_LEN_MAX;

const RECORD_VERSION: u8 = 4;
const HEADER_LEN: usize = 7;
const TAG_LEN: usize = 16;
const SEALED_HEADER_LEN: usize = HEADER_LEN + TAG_LEN;
const NONCE_LEN: usize = 12;

/// Userspace read buffer on the underlying stream (see `v4`).
const READ_BUFFER_SIZE: usize = 64 * 1024;

/// Caller bytes taken per `poll_write`; bounds the staging buffer, which is
/// kept across writes.
const WRITE_CHUNK: usize = 16 * 1024;

/// Record framing, as configured by the server's `mode` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnellV6Mode {
    /// PSK-derived traffic shaping (the server default).
    #[default]
    Default,
    /// AES-128-GCM records without shaping.
    Unshaped,
    /// Plaintext records, for an underlay that is already encrypted.
    UnsafeRaw,
}

impl SnellV6Mode {
    /// Parse a server `mode` value; empty selects `default`.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "" | "default" => Some(Self::Default),
            "unshaped" => Some(Self::Unshaped),
            "unsafe-raw" => Some(Self::UnsafeRaw),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Unshaped => "unshaped",
            Self::UnsafeRaw => "unsafe-raw",
        }
    }
}

/// Per-adapter record framing. The `default`-mode profile is derived from
/// the PSK once and shared by every connection.
#[derive(Debug, Clone)]
pub struct V6Codec(Framing);

#[derive(Debug, Clone)]
enum Framing {
    Shaped(Arc<ShapeProfile>),
    Sealed,
    Plain,
}

impl V6Codec {
    pub fn new(mode: SnellV6Mode, psk: &[u8]) -> Self {
        Self(match mode {
            SnellV6Mode::Default => Framing::Shaped(Arc::new(ShapeProfile::new(psk))),
            SnellV6Mode::Unshaped => Framing::Sealed,
            SnellV6Mode::UnsafeRaw => Framing::Plain,
        })
    }

    pub fn mode(&self) -> SnellV6Mode {
        match self.0 {
            Framing::Shaped(_) => SnellV6Mode::Default,
            Framing::Sealed => SnellV6Mode::Unshaped,
            Framing::Plain => SnellV6Mode::UnsafeRaw,
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "snell v6: EOF inside a record",
    )
}

/// One direction's AES-128-GCM key and nonce counter. The expanded key
/// schedule is boxed (as v4's is shared) to keep `V6Conn` small.
struct SessionKey {
    aead: Box<Aes128Gcm>,
    nonce: [u8; NONCE_LEN],
}

impl SessionKey {
    fn derive(psk: &[u8], salt: &[u8; SALT_LEN]) -> Self {
        Self {
            aead: Box::new(aes_gcm(&snell_kdf(psk, salt, 16))),
            nonce: [0; NONCE_LEN],
        }
    }

    fn seal(&mut self, ad: &[u8], data: &mut [u8], tag_out: &mut [u8]) -> io::Result<()> {
        let tag = self
            .aead
            .encrypt_in_place_detached(GenericArray::from_slice(&self.nonce), ad, data)
            .map_err(|_| io::Error::other("snell v6: encrypt failed"))?;
        tag_out.copy_from_slice(&tag);
        increment_nonce(&mut self.nonce);
        Ok(())
    }

    fn open(&mut self, ad: &[u8], data: &mut [u8], tag: &[u8]) -> io::Result<()> {
        self.aead
            .decrypt_in_place_detached(
                GenericArray::from_slice(&self.nonce),
                ad,
                data,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| invalid("snell v6: decrypt failed (psk or mode mismatch?)"))?;
        increment_nonce(&mut self.nonce);
        Ok(())
    }
}

fn encode_header(padding_len: usize, payload_len: usize) -> [u8; HEADER_LEN] {
    let [p0, p1] = (padding_len as u16).to_be_bytes();
    let [l0, l1] = (payload_len as u16).to_be_bytes();
    [RECORD_VERSION, 0, 0, p0, p1, l0, l1]
}

/// Decode a plaintext header into `(padding_len, payload_len)`. Only the
/// shaped framing tolerates padding and non-zero reserved bytes.
fn decode_header(header: &[u8], shaped: bool) -> io::Result<(usize, usize)> {
    if header[0] != RECORD_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("snell v6: bad record version {}", header[0]),
        ));
    }
    let padding_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let payload_len = usize::from(u16::from_be_bytes([header[5], header[6]]));
    if !shaped {
        if header[1] != 0 || header[2] != 0 {
            return Err(invalid("snell v6: reserved header bytes are non-zero"));
        }
        if padding_len != 0 {
            return Err(invalid(
                "snell v6: unexpected padding in non-default record",
            ));
        }
    }
    Ok((padding_len, payload_len))
}

// ─── Send side ───────────────────────────────────────────────────────────────

struct SendHalf {
    /// `None` for plaintext framing.
    key: Option<SessionKey>,
    /// Salt still to announce at the head of the first record.
    salt: Option<[u8; SALT_LEN]>,
    shape: ShapeState,
    /// Encoded records; `out[sent..]` is not yet accepted by the transport.
    out: Vec<u8>,
    sent: usize,
    /// Caller bytes the staged records stand for, reported by the
    /// `poll_write` that sees them through. `None` for internal records.
    owed: Option<usize>,
    /// Request waiting for the next record.
    request: Option<Vec<u8>>,
    /// A request went out by itself and still needs a transport flush.
    request_unflushed: bool,
}

impl SendHalf {
    fn new(psk: &[u8], framing: &Framing) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        Self::with_salt(psk, framing, salt)
    }

    fn with_salt(psk: &[u8], framing: &Framing, salt: [u8; SALT_LEN]) -> Self {
        let keyed = !matches!(framing, Framing::Plain);
        Self {
            key: keyed.then(|| SessionKey::derive(psk, &salt)),
            salt: keyed.then_some(salt),
            shape: ShapeState::default(),
            out: Vec::new(),
            sent: 0,
            owed: None,
            request: None,
            request_unflushed: false,
        }
    }

    fn has_unsent(&self) -> bool {
        self.sent < self.out.len()
    }

    /// Payload budget of the next record. Shaped framing ramps it; every
    /// record, including zero chunks and datagrams, takes one step.
    fn budget(&mut self, framing: &Framing, now: i64) -> usize {
        match framing {
            Framing::Shaped(profile) => profile.next_budget(&mut self.shape, now),
            Framing::Sealed | Framing::Plain => MAX_RECORD_PAYLOAD,
        }
    }

    /// Append one record carrying `payload` (empty: a zero chunk).
    fn push_record(&mut self, framing: &Framing, payload: &[u8]) -> io::Result<()> {
        debug_assert!(payload.len() <= MAX_RECORD_PAYLOAD);
        match framing {
            Framing::Shaped(profile) => self.push_shaped(profile, payload),
            Framing::Sealed => self.push_sealed(payload),
            Framing::Plain => {
                self.out.extend_from_slice(&encode_header(0, payload.len()));
                self.out.extend_from_slice(payload);
                Ok(())
            }
        }
    }

    fn push_sealed(&mut self, payload: &[u8]) -> io::Result<()> {
        let Self { key, salt, out, .. } = self;
        let key = key.as_mut().expect("sealed framing is keyed");
        if let Some(salt) = salt.take() {
            out.extend_from_slice(&salt);
        }
        let at = out.len();
        out.extend_from_slice(&encode_header(0, payload.len()));
        out.resize(at + SEALED_HEADER_LEN, 0);
        let (header, tag) = out[at..].split_at_mut(HEADER_LEN);
        key.seal(&[], header, tag)?;
        if !payload.is_empty() {
            let at = out.len();
            out.extend_from_slice(payload);
            out.resize(at + payload.len() + TAG_LEN, 0);
            let (body, tag) = out[at..].split_at_mut(payload.len());
            key.seal(&[], body, tag)?;
        }
        Ok(())
    }

    fn push_shaped(&mut self, profile: &ShapeProfile, payload: &[u8]) -> io::Result<()> {
        let Self {
            key,
            salt,
            shape,
            out,
            ..
        } = self;
        let key = key.as_mut().expect("shaped framing is keyed");
        let seq = shape.seq;
        let opening = salt.is_some();
        let block_len = if opening { profile.salt_block_len() } else { 0 };
        let prefix_len = profile.prefix_len(seq);
        let padding_len = profile.padding_len(seq, payload.len(), prefix_len, opening);
        let sealed_len = if payload.is_empty() {
            0
        } else {
            payload.len() + TAG_LEN
        };

        let at = out.len();
        out.resize(
            at + block_len + prefix_len + SEALED_HEADER_LEN + padding_len + sealed_len,
            0,
        );
        let (block, rest) = out[at..].split_at_mut(block_len);
        let (prefix, rest) = rest.split_at_mut(prefix_len);
        let (header, rest) = rest.split_at_mut(SEALED_HEADER_LEN);
        let (padding, sealed) = rest.split_at_mut(padding_len);

        if let Some(salt) = salt.take() {
            profile.write_salt_block(&salt, block);
        }
        profile.fill(seq, prefix);
        profile.fill(seq, padding);
        let (header, header_tag) = header.split_at_mut(HEADER_LEN);
        header.copy_from_slice(&encode_header(padding_len, payload.len()));
        key.seal(prefix, header, header_tag)?;
        if !payload.is_empty() {
            let (body, tag) = sealed.split_at_mut(payload.len());
            body.copy_from_slice(payload);
            // Authenticated against the padding as written, before the
            // interleave scrambles both.
            key.seal(padding, body, tag)?;
            profile.interleave(seq, padding, sealed);
        }
        shape.seq = seq.wrapping_add(1);
        Ok(())
    }

    /// Stage `data` as stream records, with a deferred request at the head
    /// of the first one. The request is never split, so that record may
    /// exceed its budget by the request length. Empty `data` stages just
    /// the request, if any.
    fn push_stream(&mut self, framing: &Framing, mut data: &[u8], now: i64) -> io::Result<()> {
        if let Some(mut record) = self.request.take() {
            let room = self
                .budget(framing, now)
                .saturating_sub(record.len())
                .min(MAX_RECORD_PAYLOAD - record.len());
            let (head, rest) = data.split_at(data.len().min(room));
            record.extend_from_slice(head);
            self.push_record(framing, &record)?;
            data = rest;
        }
        while !data.is_empty() {
            let budget = self.budget(framing, now);
            let (head, rest) = data.split_at(data.len().min(budget));
            self.push_record(framing, head)?;
            data = rest;
        }
        Ok(())
    }

    fn push_zero_chunk(&mut self, framing: &Framing, now: i64) -> io::Result<()> {
        self.push_stream(framing, &[], now)?;
        self.budget(framing, now);
        self.push_record(framing, &[])
    }

    /// One datagram, one record — whatever the budget says.
    fn push_packet(&mut self, framing: &Framing, packet: &[u8], now: i64) -> io::Result<()> {
        if packet.len() > MAX_RECORD_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell v6: packet frame too large",
            ));
        }
        self.push_stream(framing, &[], now)?;
        self.budget(framing, now);
        self.push_record(framing, packet)
    }
}

// ─── Receive side ────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum RecvState {
    /// Expecting the peer's salt (or salt block).
    Salt,
    /// Expecting a record's prefix and header.
    Header,
    /// Expecting padding, payload and tag.
    Body {
        padding_len: usize,
        payload_len: usize,
        seq: u32,
    },
    /// Discarding a zero chunk's padding.
    SkipPadding(usize),
    /// Payload ready at `buf[at..end]`.
    Deliver { at: usize, end: usize },
}

struct RecvHalf {
    state: RecvState,
    key: Option<SessionKey>,
    seq: u32,
    buf: Vec<u8>,
    filled: usize,
}

impl RecvHalf {
    fn new(framing: &Framing) -> Self {
        Self {
            state: if matches!(framing, Framing::Plain) {
                RecvState::Header
            } else {
                RecvState::Salt
            },
            key: None,
            seq: 0,
            buf: Vec::new(),
            filled: 0,
        }
    }

    /// Read until `buf[..len]` is complete. `Ok(false)` is a clean EOF
    /// before the first byte; EOF after that is an error.
    fn poll_fill<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        len: usize,
    ) -> Poll<io::Result<bool>> {
        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }
        while self.filled < len {
            let mut rb = ReadBuf::new(&mut self.buf[self.filled..len]);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut rb))?;
            match rb.filled().len() {
                0 if self.filled == 0 => return Poll::Ready(Ok(false)),
                0 => return Poll::Ready(Err(truncated())),
                n => self.filled += n,
            }
        }
        self.filled = 0;
        Poll::Ready(Ok(true))
    }

    /// Advance the state machine by one step. `Ok(false)` is a clean EOF on
    /// a record boundary.
    fn poll_step<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        framing: &Framing,
        psk: &[u8],
    ) -> Poll<io::Result<bool>> {
        match self.state {
            RecvState::Salt => {
                let len = match framing {
                    Framing::Shaped(profile) => profile.salt_block_len(),
                    Framing::Sealed | Framing::Plain => SALT_LEN,
                };
                if !ready!(self.poll_fill(io, cx, len))? {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell v6: server closed before its first record (psk or mode mismatch?)",
                    )));
                }
                let salt = match framing {
                    Framing::Shaped(profile) => profile.read_salt_block(&self.buf[..len]),
                    Framing::Sealed | Framing::Plain => {
                        self.buf[..SALT_LEN].try_into().expect("salt-sized slice")
                    }
                };
                self.key = Some(SessionKey::derive(psk, &salt));
                self.state = RecvState::Header;
            }
            RecvState::Header => {
                let prefix_len = match framing {
                    Framing::Shaped(profile) => profile.prefix_len(self.seq),
                    Framing::Sealed | Framing::Plain => 0,
                };
                let header_len = if self.key.is_some() {
                    SEALED_HEADER_LEN
                } else {
                    HEADER_LEN
                };
                if !ready!(self.poll_fill(io, cx, prefix_len + header_len))? {
                    return Poll::Ready(Ok(false));
                }
                let (prefix, header) = self.buf[..prefix_len + header_len].split_at_mut(prefix_len);
                let (header, tag) = header.split_at_mut(HEADER_LEN);
                if let Some(key) = &mut self.key {
                    key.open(prefix, header, tag)?;
                }
                let (padding_len, payload_len) =
                    decode_header(header, matches!(framing, Framing::Shaped(_)))?;
                let seq = self.seq;
                self.seq = seq.wrapping_add(1);
                self.state = match (padding_len, payload_len) {
                    (0, 0) => return Poll::Ready(Err(zero_chunk_err())),
                    (padding_len, 0) => RecvState::SkipPadding(padding_len),
                    (padding_len, payload_len) => RecvState::Body {
                        padding_len,
                        payload_len,
                        seq,
                    },
                };
            }
            RecvState::SkipPadding(len) => {
                if !ready!(self.poll_fill(io, cx, len))? {
                    return Poll::Ready(Err(truncated()));
                }
                self.state = RecvState::Header;
                return Poll::Ready(Err(zero_chunk_err()));
            }
            RecvState::Body {
                padding_len,
                payload_len,
                seq,
            } => {
                let tag_len = if self.key.is_some() { TAG_LEN } else { 0 };
                let len = padding_len + payload_len + tag_len;
                if !ready!(self.poll_fill(io, cx, len))? {
                    return Poll::Ready(Err(truncated()));
                }
                if let Some(key) = &mut self.key {
                    let (padding, sealed) = self.buf[..len].split_at_mut(padding_len);
                    if let Framing::Shaped(profile) = framing {
                        profile.interleave(seq, padding, sealed);
                    }
                    let (body, tag) = sealed.split_at_mut(payload_len);
                    key.open(padding, body, tag)?;
                }
                self.state = RecvState::Deliver {
                    at: padding_len,
                    end: padding_len + payload_len,
                };
            }
            RecvState::Deliver { .. } => {}
        }
        Poll::Ready(Ok(true))
    }
}

// ─── V6Conn ──────────────────────────────────────────────────────────────────

/// Snell v6 record stream over an `AsyncRead + AsyncWrite` transport.
pub struct V6Conn<S> {
    io: BufReader<S>,
    psk: Arc<[u8]>,
    framing: Framing,
    send: SendHalf,
    recv: RecvHalf,
}

impl<S: AsyncRead> V6Conn<S> {
    pub fn new(io: S, psk: Arc<[u8]>, codec: V6Codec) -> Self {
        let send = SendHalf::new(&psk, &codec.0);
        Self::with_send_half(io, psk, codec, send)
    }

    fn with_send_half(io: S, psk: Arc<[u8]>, codec: V6Codec, send: SendHalf) -> Self {
        Self {
            io: BufReader::with_capacity(READ_BUFFER_SIZE, io),
            psk,
            recv: RecvHalf::new(&codec.0),
            framing: codec.0,
            send,
        }
    }
}

impl<S> V6Conn<S> {
    /// Queue `request` for the head of the next record. Replaces a request
    /// that has not gone out yet.
    pub fn defer_request(&mut self, request: Vec<u8>) {
        self.send.request = Some(request);
    }

    /// Stage one datagram as a single record; `poll_flush` sends it.
    pub fn stage_packet_frame(&mut self, packet: &[u8]) -> io::Result<()> {
        self.send.push_packet(&self.framing, packet, unix_now())
    }

    pub fn has_pending_write(&self) -> bool {
        self.send.has_unsent()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> V6Conn<S> {
    /// Hand every staged byte to the transport.
    fn poll_send_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let send = &mut self.send;
        while send.has_unsent() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &send.out[send.sent..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snell v6: transport accepted no bytes",
                )));
            }
            send.sent += n;
        }
        send.out.clear();
        send.sent = 0;
        Poll::Ready(Ok(()))
    }

    /// Put a still-deferred request on the wire by itself: the server
    /// answers nothing until it has one.
    fn poll_send_request(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.send.request.is_some() {
            self.send.push_stream(&self.framing, &[], unix_now())?;
            self.send.request_unflushed = true;
        }
        if self.send.request_unflushed {
            // May also push records a pending `poll_write` staged; that
            // write still reports its count on the next call.
            ready!(self.poll_send_out(cx))?;
            ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            self.send.request_unflushed = false;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for V6Conn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_send_request(cx))?;
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let RecvState::Deliver { at, end } = this.recv.state {
                let n = (end - at).min(out.remaining());
                out.put_slice(&this.recv.buf[at..at + n]);
                this.recv.state = if at + n == end {
                    RecvState::Header
                } else {
                    RecvState::Deliver { at: at + n, end }
                };
                return Poll::Ready(Ok(()));
            }
            if !ready!(this
                .recv
                .poll_step(&mut this.io, cx, &this.framing, &this.psk))?
            {
                // Clean EOF between records: the peer closed without a
                // zero chunk.
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for V6Conn<S> {
    /// Stages the (capped) input as records and sends them. If the transport
    /// pends, the records stay staged and the next call — whatever its
    /// input — finishes them and reports this input's count, as `V4Conn`
    /// does. An empty `buf` stages a zero chunk (behind a deferred request)
    /// and reports `Ok(0)`.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_send_out(cx))?;
        if let Some(n) = this.send.owed.take() {
            return Poll::Ready(Ok(n));
        }
        let now = unix_now();
        let n = if buf.is_empty() {
            this.send.push_zero_chunk(&this.framing, now)?;
            0
        } else {
            let n = buf.len().min(WRITE_CHUNK);
            this.send.push_stream(&this.framing, &buf[..n], now)?;
            n
        };
        this.send.owed = Some(n);
        ready!(this.poll_send_out(cx))?;
        this.send.owed = None;
        Poll::Ready(Ok(n))
    }

    /// Sends staged records (and a still-deferred request by itself), then
    /// flushes the transport.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.send.request.is_some() {
            this.send.push_stream(&this.framing, &[], unix_now())?;
        }
        ready!(this.poll_send_out(cx))?;
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        this.send.request_unflushed = false;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_send_out(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snell::v4::is_zero_chunk;
    use sha2::{Digest, Sha256};
    use std::future::Future;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    const MODES: [SnellV6Mode; 3] = [
        SnellV6Mode::Default,
        SnellV6Mode::Unshaped,
        SnellV6Mode::UnsafeRaw,
    ];

    async fn within<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("test future timed out")
    }

    fn pattern(n: usize, mul: usize, add: usize) -> Vec<u8> {
        (0..n).map(|i| (i * mul + add) as u8).collect()
    }

    /// Two ends of one v6 stream. The framing is symmetric — each direction
    /// opens with its own salt — so a `V6Conn` also stands in for the server.
    fn pair_with(
        client_mode: SnellV6Mode,
        server_mode: SnellV6Mode,
    ) -> (V6Conn<DuplexStream>, V6Conn<DuplexStream>) {
        let psk: Arc<[u8]> = Arc::from(b"v6-unit-psk".as_slice());
        let (a, b) = tokio::io::duplex(1 << 16);
        (
            V6Conn::new(a, Arc::clone(&psk), V6Codec::new(client_mode, &psk)),
            V6Conn::new(b, Arc::clone(&psk), V6Codec::new(server_mode, &psk)),
        )
    }

    fn pair(mode: SnellV6Mode) -> (V6Conn<DuplexStream>, V6Conn<DuplexStream>) {
        pair_with(mode, mode)
    }

    async fn send_zero_chunk(conn: &mut V6Conn<DuplexStream>) {
        while std::future::poll_fn(|cx| Pin::new(&mut *conn).poll_write(cx, &[]))
            .await
            .unwrap()
            != 0
        {}
        conn.flush().await.unwrap();
    }

    /// Everything up to the peer's zero chunk.
    async fn read_session(conn: &mut V6Conn<DuplexStream>) -> Vec<u8> {
        let mut got = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            match conn.read(&mut buf).await {
                Ok(0) => panic!("EOF before zero chunk"),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) if is_zero_chunk(&e) => return got,
                Err(e) => panic!("read failed: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn request_and_bulk_data_round_trip_in_every_mode() {
        for mode in MODES {
            let (mut client, mut server) = pair(mode);
            let data = pattern(300_000, 13, 7);
            client.defer_request(b"REQUEST".to_vec());
            let writer = async {
                client.write_all(&data).await.unwrap();
                send_zero_chunk(&mut client).await;
                client
            };
            let (_client, got) =
                within(async { tokio::join!(writer, read_session(&mut server)) }).await;
            assert_eq!(&got[..7], b"REQUEST", "{mode:?}");
            assert!(got[7..] == data[..], "{mode:?}: payload mismatch");
        }
    }

    #[tokio::test]
    async fn request_shares_the_first_record_with_data() {
        for mode in MODES {
            let (mut client, mut server) = pair(mode);
            client.defer_request(b"REQ".to_vec());
            within(client.write_all(b"hello")).await.unwrap();
            let mut buf = [0u8; 64];
            let n = within(server.read(&mut buf)).await.unwrap();
            assert_eq!(&buf[..n], b"REQhello", "{mode:?}");
        }
    }

    #[tokio::test]
    async fn reading_first_sends_the_request_alone() {
        for mode in MODES {
            let (mut client, mut server) = pair(mode);
            client.defer_request(b"REQ".to_vec());
            let server_side = async {
                let mut buf = [0u8; 64];
                let n = server.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"REQ", "{mode:?}");
                server.write_all(b"banner").await.unwrap();
                server.flush().await.unwrap();
            };
            let client_side = async {
                let mut buf = [0u8; 6];
                client.read_exact(&mut buf).await.unwrap();
                buf
            };
            let ((), got) = within(async { tokio::join!(server_side, client_side) }).await;
            assert_eq!(&got, b"banner", "{mode:?}");
        }
    }

    #[tokio::test]
    async fn closing_without_data_sends_request_then_zero_chunk() {
        for mode in MODES {
            let (mut client, mut server) = pair(mode);
            client.defer_request(b"REQ".to_vec());
            within(send_zero_chunk(&mut client)).await;
            assert_eq!(within(read_session(&mut server)).await, b"REQ", "{mode:?}");
        }
    }

    #[tokio::test]
    async fn sessions_continue_on_one_record_stream() {
        for mode in MODES {
            let (mut client, mut server) = pair(mode);
            for session in 0..4u8 {
                let request = vec![b'R', session];
                let upload = pattern(5000 + usize::from(session) * 900, 3, session.into());
                let download = pattern(7000 - usize::from(session) * 500, 5, session.into());
                client.defer_request(request.clone());
                let client_side = async {
                    client.write_all(&upload).await.unwrap();
                    send_zero_chunk(&mut client).await;
                    read_session(&mut client).await
                };
                let server_side = async {
                    let got = read_session(&mut server).await;
                    server.write_all(&download).await.unwrap();
                    send_zero_chunk(&mut server).await;
                    got
                };
                let (downloaded, uploaded) =
                    within(async { tokio::join!(client_side, server_side) }).await;
                assert_eq!(uploaded[..2], request[..], "{mode:?} #{session}");
                assert!(uploaded[2..] == upload[..], "{mode:?} #{session}");
                assert!(downloaded == download, "{mode:?} #{session}");
            }
        }
    }

    #[tokio::test]
    async fn packet_frames_keep_datagram_boundaries() {
        for mode in MODES {
            let (mut client, mut server) = pair(mode);
            let packets = [
                pattern(1, 1, 9),
                pattern(1400, 7, 1),
                pattern(MAX_RECORD_PAYLOAD, 3, 2),
            ];
            let client_side = async {
                for packet in &packets {
                    client.stage_packet_frame(packet).unwrap();
                    client.flush().await.unwrap();
                }
            };
            let server_side = async {
                let mut buf = vec![0u8; MAX_RECORD_PAYLOAD];
                let mut got = Vec::new();
                for _ in 0..packets.len() {
                    let n = server.read(&mut buf).await.unwrap();
                    got.push(buf[..n].to_vec());
                }
                got
            };
            let ((), got) = within(async { tokio::join!(client_side, server_side) }).await;
            assert!(got == packets, "{mode:?}");
            assert_eq!(
                client
                    .stage_packet_frame(&vec![0; MAX_RECORD_PAYLOAD + 1])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[tokio::test]
    async fn plain_reader_rejects_padding_and_reserved_bytes() {
        for (record, reason) in [
            (
                &[4u8, 0, 0, 0, 1, 0, 1, 0xaa, 0xbb][..],
                "unexpected padding",
            ),
            (&[4u8, 1, 0, 0, 0, 0, 1, 0xbb][..], "reserved header bytes"),
            (&[5u8, 0, 0, 0, 0, 0, 1, 0xbb][..], "bad record version"),
        ] {
            let (mut raw, b) = tokio::io::duplex(1 << 10);
            let psk: Arc<[u8]> = Arc::from(b"k".as_slice());
            let mut conn = V6Conn::new(
                b,
                Arc::clone(&psk),
                V6Codec::new(SnellV6Mode::UnsafeRaw, &psk),
            );
            raw.write_all(record).await.unwrap();
            let err = within(conn.read(&mut [0u8; 16])).await.unwrap_err();
            assert!(err.to_string().contains(reason), "{err}");
        }
    }

    #[tokio::test]
    async fn mode_mismatch_fails_instead_of_yielding_garbage() {
        use SnellV6Mode::{Default, UnsafeRaw, Unshaped};
        for (client_mode, server_mode) in [
            (Default, Unshaped),
            (Unshaped, Default),
            (Unshaped, UnsafeRaw),
            (UnsafeRaw, Unshaped),
            (Default, UnsafeRaw),
        ] {
            let (mut client, mut server) = pair_with(client_mode, server_mode);
            client.defer_request(b"REQ".to_vec());
            let writer = async {
                client.write_all(&pattern(4000, 1, 0)).await.unwrap();
                // Dropping the client closes the transport, so a reader
                // still waiting for bytes sees EOF instead of hanging.
                drop(client);
            };
            let reader = async {
                let mut buf = vec![0u8; 8192];
                loop {
                    match server.read(&mut buf).await {
                        Ok(0) => break Err("clean EOF"),
                        Ok(_) => {}
                        Err(e) => break Ok(e),
                    }
                }
            };
            let ((), result) = within(async { tokio::join!(writer, reader) }).await;
            assert!(
                result.is_ok(),
                "{client_mode:?} -> {server_mode:?} was not detected"
            );
        }
    }

    #[test]
    fn mode_names_round_trip() {
        assert_eq!(SnellV6Mode::parse(""), Some(SnellV6Mode::Default));
        for mode in MODES {
            assert_eq!(SnellV6Mode::parse(mode.as_str()), Some(mode));
            let psk = b"k";
            assert_eq!(V6Codec::new(mode, psk).mode(), mode);
        }
        assert_eq!(SnellV6Mode::parse("shaped"), None);
    }

    /// `write(3000)`, zero chunk, 700-byte datagram on a fresh writer with
    /// a fixed salt and clock.
    fn scripted_wire(mode: SnellV6Mode, psk: &str) -> Vec<u8> {
        const NOW: i64 = 1_700_000_000;
        let codec = V6Codec::new(mode, psk.as_bytes());
        let salt = std::array::from_fn(|i| 0xa0 + i as u8);
        let mut send = SendHalf::with_salt(psk.as_bytes(), &codec.0, salt);
        send.push_stream(&codec.0, &pattern(3000, 7, 3), NOW)
            .unwrap();
        send.push_zero_chunk(&codec.0, NOW).unwrap();
        send.push_packet(&codec.0, &pattern(700, 11, 5), NOW)
            .unwrap();
        send.out
    }

    /// Regression pin on the exact bytes each framing writes. Recorded once
    /// the writer interoperated with a real snell-server v6.
    #[test]
    fn scripted_wire_is_stable() {
        let mut h = Sha256::new();
        for i in 0..64 {
            h.update(scripted_wire(SnellV6Mode::Default, &format!("v6-wire-{i}")));
        }
        h.update(scripted_wire(SnellV6Mode::Unshaped, "v6-wire"));
        h.update(scripted_wire(SnellV6Mode::UnsafeRaw, "v6-wire"));
        assert_eq!(
            hex::encode(h.finalize()),
            "78d692abc31b7006e784f66a434233a0439dcfe177086dd8365296dd92499dfd"
        );
    }

    #[tokio::test]
    async fn scripted_wire_decodes() {
        for mode in MODES {
            let psk = "v6-wire";
            let wire = scripted_wire(mode, psk);
            let (mut raw, b) = tokio::io::duplex(1 << 16);
            let psk: Arc<[u8]> = Arc::from(psk.as_bytes());
            let mut conn = V6Conn::new(b, Arc::clone(&psk), V6Codec::new(mode, &psk));
            let feed = async {
                raw.write_all(&wire).await.unwrap();
                raw
            };
            let read = async {
                let stream = read_session(&mut conn).await;
                let mut packet = vec![0u8; 1024];
                let n = conn.read(&mut packet).await.unwrap();
                (stream, packet[..n].to_vec())
            };
            let (_raw, (stream, packet)) = within(async { tokio::join!(feed, read) }).await;
            assert!(stream == pattern(3000, 7, 3), "{mode:?}");
            assert!(packet == pattern(700, 11, 5), "{mode:?}");
        }
    }
}
