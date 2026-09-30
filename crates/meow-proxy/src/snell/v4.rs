//! Snell v4 AEAD frame codec.
//!
//! Port of opensnell `components/snell/v4.go` (which itself ports mihomo's
//! `transport/snell/v4.go`). Wraps an existing `AsyncRead + AsyncWrite`
//! stream with the v4 frame format:
//!
//! 1. The first write emits a 16-byte random salt, then frame(s); reader
//!    consumes the salt before its first frame.
//! 2. Each frame is `[AEAD-sealed 7-byte header][padding (interleaved with
//!    payload's even bytes)][AEAD-sealed payload]`.
//! 3. Header layout (plaintext, 7 B): `[ver=4][0][0][padding_len:u16
//!    BE][payload_len:u16 BE]`.
//! 4. Nonce: 12-byte little-endian counter incremented after every Seal/Open.
//! 5. A frame with `payload_len == 0 && padding_len == 0` signals the peer's
//!    half-close (`ErrZeroChunk`, surfaced as a tagged `io::Error`).
//!
//! The writer also implements opensnell's payload-limit ramp-up: the first
//! frame fits within one MTU (1460 B), then each subsequent frame in a burst
//! grows up to `MAX_PAYLOAD_LENGTH` (16383 B). After 30 s of inactivity the
//! ramp restarts. Initial-burst padding is bit-balanced against the payload
//! cipher's `popcount` to defeat the trivial entropy fingerprint of AEAD-only
//! traffic.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};

use super::cipher::{aes_gcm, snell_kdf, Aes128Gcm};

pub const V4_SALT_SIZE: usize = 16;
pub const V4_NONCE_SIZE: usize = 12;
pub const V4_HEADER_PLAIN_SIZE: usize = 7;
pub const V4_GCM_TAG: usize = 16;
pub const V4_HEADER_CIPHER_SIZE: usize = V4_HEADER_PLAIN_SIZE + V4_GCM_TAG;

const V4_FRAME_SIZE: usize = 1460;
const V4_INITIAL_PADDING_MIN: u16 = 0x100;
const V4_INITIAL_PADDING_SPAN: u16 = 0x100;
const V4_BURST_RESET_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Largest snell frame payload — matches mihomo's `maxLength` (0x3FFF).
pub const MAX_PAYLOAD_LENGTH: usize = 0x3FFF;

/// Userspace read buffer on the underlying stream. Without it, every frame
/// costs two `recv()` syscalls (23-byte sealed header + body); 64 KiB holds
/// ~40 max-size frames per `recv()`. Mirrors mihomo PR #2821. Writes are
/// unaffected — `BufReader` passes `AsyncWrite` straight through.
const V4_READ_BUFFER_SIZE: usize = 64 * 1024;

const ZERO_CHUNK_KIND: io::ErrorKind = io::ErrorKind::UnexpectedEof;
const ZERO_CHUNK_MSG: &str = "snell: zero chunk";

/// True iff the I/O error is the v4 zero-chunk half-close signal.
pub fn is_zero_chunk(err: &io::Error) -> bool {
    err.kind() == ZERO_CHUNK_KIND
        && err
            .get_ref()
            .is_some_and(|e| e.to_string() == ZERO_CHUNK_MSG)
}

pub(super) fn zero_chunk_err() -> io::Error {
    io::Error::new(ZERO_CHUNK_KIND, ZERO_CHUNK_MSG)
}

pub(super) fn increment_nonce(nonce: &mut [u8; V4_NONCE_SIZE]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

fn swap_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    let mut i = 0;
    while i < limit {
        std::mem::swap(&mut padding[i], &mut payload_cipher[i]);
        i += 2;
    }
}

fn make_v4_bit_count_padding(length: usize, one_bits: usize) -> io::Result<Vec<u8>> {
    let total_bits = 8 * length;
    if one_bits > total_bits {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snell v4 invalid padding bit count",
        ));
    }
    let mut bitset = vec![0u8; total_bits];
    for slot in bitset.iter_mut().take(one_bits) {
        *slot = 1;
    }
    let mut rng = rand::rng();
    for i in (1..total_bits).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        bitset.swap(i, j);
    }
    let mut padding = vec![0u8; length];
    for (i, bit) in bitset.into_iter().enumerate() {
        if bit == 1 {
            padding[i / 8] |= 1 << (i % 8);
        }
    }
    Ok(padding)
}

fn make_v4_random_padding(length: usize) -> Vec<u8> {
    let mut padding = vec![0u8; length];
    rand::rng().fill_bytes(&mut padding);
    padding
}

fn count_v4_payload_ones(payload_cipher: &[u8]) -> usize {
    let limit = payload_cipher.len() & !3;
    payload_cipher[..limit]
        .iter()
        .map(|b| b.count_ones() as usize)
        .sum()
}

fn random_unit_f64() -> f64 {
    (rand::rng().next_u64() % (1u64 << 53)) as f64 / 2f64.powi(53)
}

fn make_v4_padding(payload_cipher: &[u8], padding_length: usize) -> io::Result<Vec<u8>> {
    if padding_length == 0 {
        return Ok(Vec::new());
    }
    let payload_ones = count_v4_payload_ones(payload_cipher);
    let payload_zeros = 8 * payload_cipher.len() - payload_ones;
    if payload_zeros == 0 {
        return Ok(make_v4_random_padding(padding_length));
    }
    let ratio = payload_ones as f64 / payload_zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        return Ok(make_v4_random_padding(padding_length));
    }
    let target_base = if payload_zeros < payload_ones {
        0.4
    } else {
        1.6
    };
    let target_ratio = target_base + random_unit_f64() / 10.0;
    let total_bits = 8 * (padding_length + payload_cipher.len());
    let target_ones_f =
        total_bits as f64 * (target_ratio / (target_ratio + 1.0)) - payload_ones as f64;
    if !target_ones_f.is_finite() || target_ones_f < 0.0 {
        return Ok(make_v4_random_padding(padding_length));
    }
    let target_ones = target_ones_f as usize;
    if target_ones > 8 * padding_length {
        return Ok(make_v4_random_padding(padding_length));
    }
    make_v4_bit_count_padding(padding_length, target_ones)
}

// ─── Reader state machine ────────────────────────────────────────────────────

enum ReaderState {
    /// Consuming the peer's 16-byte salt; once full, derive the AEAD via PSK.
    NeedSalt {
        salt_buf: [u8; V4_SALT_SIZE],
        salt_progress: usize,
    },
    /// Reading the next frame's 23-byte sealed header.
    ReadingHeader {
        aead: Arc<Aes128Gcm>,
        nonce: [u8; V4_NONCE_SIZE],
        header_buf: [u8; V4_HEADER_CIPHER_SIZE],
        header_progress: usize,
    },
    /// Reading `padding_len + payload_len + 16` body bytes.
    ReadingBody {
        aead: Arc<Aes128Gcm>,
        nonce: [u8; V4_NONCE_SIZE],
        padding_len: usize,
        payload_len: usize,
        body_buf: Vec<u8>,
        body_progress: usize,
    },
    /// Decrypted payload pending — drain into caller before next frame.
    Drain {
        aead: Arc<Aes128Gcm>,
        nonce: [u8; V4_NONCE_SIZE],
        payload: Vec<u8>,
        payload_off: usize,
    },
}

// ─── Writer state ────────────────────────────────────────────────────────────

struct Writer {
    aead: Arc<Aes128Gcm>,
    nonce: [u8; V4_NONCE_SIZE],
    salt: [u8; V4_SALT_SIZE],
    salt_sent: bool,
    initial_padding_length: u16,
    payload_limit: u16,
    last_write: Option<Instant>,
    /// Bytes already pushed downstream from the in-flight frame.
    pending: Vec<u8>,
    pending_off: usize,
    /// Number of caller bytes the in-flight frame represents (reported on
    /// successful drain).
    pending_input: usize,
}

impl Writer {
    fn new(psk: &[u8]) -> Self {
        let mut salt = [0u8; V4_SALT_SIZE];
        rand::rng().fill_bytes(&mut salt);
        let aead = aes_gcm(&snell_kdf(psk, &salt, 16));
        let padding_delta = (rand::rng().next_u32() % u32::from(V4_INITIAL_PADDING_SPAN)) as u16;
        Self {
            aead: Arc::new(aead),
            nonce: [0u8; V4_NONCE_SIZE],
            salt,
            salt_sent: false,
            initial_padding_length: V4_INITIAL_PADDING_MIN + padding_delta,
            payload_limit: 0,
            last_write: None,
            pending: Vec::new(),
            pending_off: 0,
            pending_input: 0,
        }
    }

    fn next_payload_limit(&mut self) -> u16 {
        let now = Instant::now();
        let limit = match self.last_write {
            None => V4_FRAME_SIZE as u16 - 55 - self.initial_padding_length,
            Some(t) if now.duration_since(t) > V4_BURST_RESET_AFTER => V4_FRAME_SIZE as u16 - 39,
            Some(_) => self.payload_limit,
        };
        self.last_write = Some(now);
        if limit < MAX_PAYLOAD_LENGTH as u16 {
            let next = limit as usize + V4_FRAME_SIZE - 39;
            self.payload_limit = next.min(MAX_PAYLOAD_LENGTH) as u16;
        } else {
            self.payload_limit = MAX_PAYLOAD_LENGTH as u16;
        }
        limit
    }

    fn next_frame_padding_length(&self, payload_length: usize) -> usize {
        if self.salt_sent || payload_length == 0 {
            0
        } else {
            self.initial_padding_length as usize
        }
    }

    fn stage_frame(&mut self, payload: &[u8], padding_length: usize) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD_LENGTH || padding_length > MAX_PAYLOAD_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell v4 frame too large",
            ));
        }
        if payload.is_empty() && padding_length != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell v4 zero chunk with padding",
            ));
        }

        let mut header = [0u8; V4_HEADER_PLAIN_SIZE];
        header[0] = 4;
        header[3..5].copy_from_slice(&(padding_length as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());

        let mut header_buf: Vec<u8> = Vec::with_capacity(V4_HEADER_CIPHER_SIZE);
        header_buf.extend_from_slice(&header);
        seal_in_place(&self.aead, &self.nonce, &mut header_buf)?;
        increment_nonce(&mut self.nonce);

        let mut payload_buf: Vec<u8> = Vec::new();
        if !payload.is_empty() {
            payload_buf.extend_from_slice(payload);
            seal_in_place(&self.aead, &self.nonce, &mut payload_buf)?;
            increment_nonce(&mut self.nonce);
        }

        let mut padding = if padding_length > 0 {
            make_v4_padding(&payload_buf, padding_length)?
        } else {
            Vec::new()
        };
        if padding_length > 0 {
            swap_padding(&mut padding, &mut payload_buf);
        }

        let mut frame: Vec<u8> = Vec::with_capacity(
            if self.salt_sent { 0 } else { V4_SALT_SIZE }
                + header_buf.len()
                + padding.len()
                + payload_buf.len(),
        );
        if !self.salt_sent {
            frame.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        frame.extend_from_slice(&header_buf);
        frame.extend_from_slice(&padding);
        frame.extend_from_slice(&payload_buf);

        self.pending = frame;
        self.pending_off = 0;
        Ok(())
    }
}

fn seal_in_place(
    aead: &Aes128Gcm,
    nonce: &[u8; V4_NONCE_SIZE],
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    aead.seal_append(nonce, buf)
        .map_err(|_| io::Error::other("snell v4 encrypt failed"))
}

fn open_in_place(
    aead: &Aes128Gcm,
    nonce: &[u8; V4_NONCE_SIZE],
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    aead.open_trailing(nonce, buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "snell v4 decrypt failed"))
}

// ─── V4Conn ──────────────────────────────────────────────────────────────────

/// AEAD frame wrapper around an `AsyncRead + AsyncWrite` byte stream.
pub struct V4Conn<S> {
    inner: BufReader<S>,
    psk: Arc<[u8]>,
    writer: Writer,
    reader: ReaderState,
}

impl<S: AsyncRead> V4Conn<S> {
    pub fn new(inner: S, psk: Arc<[u8]>) -> Self {
        let writer = Writer::new(&psk);
        Self {
            inner: BufReader::with_capacity(V4_READ_BUFFER_SIZE, inner),
            psk,
            writer,
            reader: ReaderState::NeedSalt {
                salt_buf: [0u8; V4_SALT_SIZE],
                salt_progress: 0,
            },
        }
    }
}

impl<S> V4Conn<S> {
    /// Stage a single frame carrying `buf` as a UDP datagram payload. The
    /// caller is responsible for draining the stream to completion (see
    /// `Snell::poll_write_packet_frame`, which the higher-level
    /// `SnellPacketConn::write_packet` drives with a per-poll stream lock).
    pub fn stage_packet_frame(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.len() > MAX_PAYLOAD_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell v4 packet frame too large",
            ));
        }
        let padding_length = self.writer.next_frame_padding_length(buf.len());
        self.writer.pending_input = buf.len();
        self.writer.stage_frame(buf, padding_length)
    }

    pub fn has_pending_write(&self) -> bool {
        self.writer.pending_off < self.writer.pending.len()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for V4Conn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.reader {
                ReaderState::NeedSalt {
                    salt_buf,
                    salt_progress,
                } => {
                    let mut tmp = [0u8; V4_SALT_SIZE];
                    let need = V4_SALT_SIZE - *salt_progress;
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell v4 EOF before salt",
                        )));
                    }
                    salt_buf[*salt_progress..*salt_progress + n].copy_from_slice(&tmp[..n]);
                    *salt_progress += n;
                    if *salt_progress < V4_SALT_SIZE {
                        continue;
                    }
                    let aead = Arc::new(aes_gcm(&snell_kdf(&this.psk, &salt_buf[..], 16)));
                    this.reader = ReaderState::ReadingHeader {
                        aead,
                        nonce: [0u8; V4_NONCE_SIZE],
                        header_buf: [0u8; V4_HEADER_CIPHER_SIZE],
                        header_progress: 0,
                    };
                }
                ReaderState::Drain {
                    aead,
                    nonce,
                    payload,
                    payload_off,
                } => {
                    let avail = &payload[*payload_off..];
                    if avail.is_empty() {
                        let aead = Arc::clone(aead);
                        let nonce = *nonce;
                        this.reader = ReaderState::ReadingHeader {
                            aead,
                            nonce,
                            header_buf: [0u8; V4_HEADER_CIPHER_SIZE],
                            header_progress: 0,
                        };
                        continue;
                    }
                    let take = avail.len().min(out.remaining());
                    out.put_slice(&avail[..take]);
                    *payload_off += take;
                    return Poll::Ready(Ok(()));
                }
                ReaderState::ReadingHeader {
                    aead,
                    nonce,
                    header_buf,
                    header_progress,
                } => {
                    let need = V4_HEADER_CIPHER_SIZE - *header_progress;
                    let mut tmp = [0u8; V4_HEADER_CIPHER_SIZE];
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let n = rb.filled().len();
                    if n == 0 {
                        // Clean EOF on a frame boundary: the peer closed the
                        // TCP without sending the zero-chunk half-close.
                        // Treat it as a normal EOF for the caller (matches
                        // io.EOF semantics in opensnell's Reader). Mid-header
                        // partial reads, however, are protocol errors.
                        if *header_progress == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell v4 EOF mid-header",
                        )));
                    }
                    header_buf[*header_progress..*header_progress + n].copy_from_slice(&tmp[..n]);
                    *header_progress += n;
                    if *header_progress < V4_HEADER_CIPHER_SIZE {
                        continue;
                    }
                    let mut sealed = header_buf.to_vec();
                    if let Err(e) = open_in_place(aead, nonce, &mut sealed) {
                        return Poll::Ready(Err(e));
                    }
                    increment_nonce(nonce);
                    if sealed.len() != V4_HEADER_PLAIN_SIZE || sealed[0] != 4 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snell v4 invalid frame header",
                        )));
                    }
                    let padding_len = u16::from_be_bytes([sealed[3], sealed[4]]) as usize;
                    let payload_len = u16::from_be_bytes([sealed[5], sealed[6]]) as usize;
                    if payload_len == 0 {
                        if padding_len != 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "snell v4 zero chunk with padding",
                            )));
                        }
                        let aead_keep = Arc::clone(aead);
                        let nonce_keep = *nonce;
                        this.reader = ReaderState::ReadingHeader {
                            aead: aead_keep,
                            nonce: nonce_keep,
                            header_buf: [0u8; V4_HEADER_CIPHER_SIZE],
                            header_progress: 0,
                        };
                        return Poll::Ready(Err(zero_chunk_err()));
                    }
                    if payload_len > MAX_PAYLOAD_LENGTH || padding_len > MAX_PAYLOAD_LENGTH {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snell v4 frame too large",
                        )));
                    }
                    let body_size = padding_len + payload_len + V4_GCM_TAG;
                    let aead = Arc::clone(aead);
                    let nonce = *nonce;
                    this.reader = ReaderState::ReadingBody {
                        aead,
                        nonce,
                        padding_len,
                        payload_len,
                        body_buf: vec![0u8; body_size],
                        body_progress: 0,
                    };
                }
                ReaderState::ReadingBody {
                    aead,
                    nonce,
                    padding_len,
                    payload_len,
                    body_buf,
                    body_progress,
                } => {
                    if *body_progress < body_buf.len() {
                        let mut rb = ReadBuf::new(&mut body_buf[*body_progress..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) => {}
                        }
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "snell v4 EOF mid-body",
                            )));
                        }
                        *body_progress += n;
                        if *body_progress < body_buf.len() {
                            continue;
                        }
                    }
                    let (padding_part, payload_part) = body_buf.split_at_mut(*padding_len);
                    if *padding_len > 0 {
                        swap_padding(padding_part, payload_part);
                    }
                    let mut payload_cipher = payload_part.to_vec();
                    if let Err(e) = open_in_place(aead, nonce, &mut payload_cipher) {
                        return Poll::Ready(Err(e));
                    }
                    increment_nonce(nonce);
                    debug_assert_eq!(payload_cipher.len(), *payload_len);
                    let aead = Arc::clone(aead);
                    let nonce = *nonce;
                    this.reader = ReaderState::Drain {
                        aead,
                        nonce,
                        payload: payload_cipher,
                        payload_off: 0,
                    };
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for V4Conn<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.writer.pending_off < this.writer.pending.len() {
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let consumed = std::mem::take(&mut this.writer.pending_input);
                    return Poll::Ready(Ok(consumed));
                }
            }
        }

        if buf.is_empty() {
            this.writer.pending_input = 0;
            this.writer.stage_frame(&[], 0)?;
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
            }
        } else {
            let limit = this.writer.next_payload_limit() as usize;
            let limit = if limit == 0 || limit > MAX_PAYLOAD_LENGTH {
                MAX_PAYLOAD_LENGTH
            } else {
                limit
            };
            let take = buf.len().min(limit);
            let chunk = &buf[..take];
            let padding_length = this.writer.next_frame_padding_length(chunk.len());
            this.writer.pending_input = take;
            this.writer.stage_frame(chunk, padding_length)?;
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let consumed = std::mem::take(&mut this.writer.pending_input);
                    Poll::Ready(Ok(consumed))
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.writer.pending_off < this.writer.pending.len() {
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.writer.pending_off < this.writer.pending.len() {
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn drain_writer<S: AsyncWrite + Unpin>(
    writer: &mut Writer,
    inner: &mut S,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while writer.pending_off < writer.pending.len() {
        let slice = &writer.pending[writer.pending_off..];
        match Pin::new(&mut *inner).poll_write(cx, slice) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snell v4: short write",
                )));
            }
            Poll::Ready(Ok(n)) => writer.pending_off += n,
        }
    }
    writer.pending.clear();
    writer.pending_off = 0;
    Poll::Ready(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn increment_nonce_wraps() {
        let mut n = [0xFFu8; V4_NONCE_SIZE];
        increment_nonce(&mut n);
        assert_eq!(n, [0u8; V4_NONCE_SIZE]);
    }

    #[test]
    fn swap_padding_round_trips() {
        let mut p = vec![1u8, 2, 3, 4, 5, 6];
        let mut c = vec![10u8, 20, 30, 40, 50, 60];
        let (orig_p, orig_c) = (p.clone(), c.clone());
        swap_padding(&mut p, &mut c);
        swap_padding(&mut p, &mut c);
        assert_eq!(p, orig_p);
        assert_eq!(c, orig_c);
    }

    #[test]
    fn bit_count_padding_has_requested_ones() {
        let pad = make_v4_bit_count_padding(16, 40).unwrap();
        let ones: u32 = pad.iter().map(|b| b.count_ones()).sum();
        assert_eq!(ones, 40);
    }

    /// End-to-end: two V4Conn instances over a duplex stream should round-trip
    /// arbitrary payloads, including bursts that overflow the first-frame limit.
    #[tokio::test]
    async fn v4_round_trip_through_duplex() {
        let (a, b) = tokio::io::duplex(1 << 18);
        let psk: Arc<[u8]> = Arc::from(b"shared-secret".as_slice());
        let mut alice = V4Conn::new(a, Arc::clone(&psk));
        let mut bob = V4Conn::new(b, psk);

        // Alice writes a small payload, then a large burst.
        let small = b"hello-world";
        let large: Vec<u8> = (0..32_000u32).map(|i| (i % 251) as u8).collect();

        let writer = tokio::spawn(async move {
            alice.write_all(small).await.unwrap();
            alice.write_all(&large).await.unwrap();
            alice.flush().await.unwrap();
            // Keep alice alive for the read side to consume everything.
            alice
        });

        let mut got_small = vec![0u8; small.len()];
        bob.read_exact(&mut got_small).await.unwrap();
        assert_eq!(got_small, small);

        let mut got_large = vec![0u8; 32_000];
        bob.read_exact(&mut got_large).await.unwrap();
        let expected: Vec<u8> = (0..32_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(got_large, expected);

        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn v4_zero_chunk_surfaces_as_tagged_error() {
        let (a, b) = tokio::io::duplex(8192);
        let psk: Arc<[u8]> = Arc::from(b"k".as_slice());
        let mut alice = V4Conn::new(a, Arc::clone(&psk));
        let mut bob = V4Conn::new(b, psk);

        // Alice sends one real frame, then a zero chunk. `write_all(&[])`
        // is a no-op in tokio because the future short-circuits on empty
        // input, so we drive `poll_write(&[])` by hand to actually emit
        // the zero-chunk frame.
        alice.write_all(b"abc").await.unwrap();
        alice.flush().await.unwrap();
        std::future::poll_fn(|cx| Pin::new(&mut alice).poll_write(cx, &[]))
            .await
            .unwrap();
        alice.flush().await.unwrap();

        let mut buf = [0u8; 3];
        bob.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");

        let mut more = [0u8; 1];
        let err = bob.read_exact(&mut more).await.unwrap_err();
        assert!(is_zero_chunk(&err), "expected zero-chunk tag, got {err:?}");
    }
}
