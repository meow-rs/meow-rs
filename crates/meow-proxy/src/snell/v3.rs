//! Snell v3 AEAD stream codec.
//!
//! Mihomo implements Snell v3 by wrapping the TCP stream in its
//! `shadowaead.NewConn` with a Snell-specific cipher: 16-byte salt,
//! Argon2id-derived AES-128-GCM key, and the Shadowsocks AEAD stream frame
//! layout. Each record is:
//!
//! 1. First write sends a 16-byte random salt.
//! 2. Record header: AEAD-sealed 2-byte big-endian payload length.
//! 3. Record body: AEAD-sealed payload bytes, omitted when length is zero.
//! 4. Nonce: 12-byte little-endian counter incremented after each Seal/Open.
//! 5. A zero-length header is the Snell half-close signal.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};

use super::cipher::{aes_gcm, snell_kdf, Aes128Gcm};
use super::v4::MAX_PAYLOAD_LENGTH;

pub const V3_SALT_SIZE: usize = 16;
pub const V3_NONCE_SIZE: usize = 12;
const V3_LENGTH_PLAIN_SIZE: usize = 2;
const V3_GCM_TAG: usize = 16;
const V3_LENGTH_CIPHER_SIZE: usize = V3_LENGTH_PLAIN_SIZE + V3_GCM_TAG;
const V3_READ_BUFFER_SIZE: usize = 64 * 1024;

const ZERO_CHUNK_KIND: io::ErrorKind = io::ErrorKind::UnexpectedEof;
const ZERO_CHUNK_MSG: &str = "snell v3: zero chunk";

pub fn is_zero_chunk(err: &io::Error) -> bool {
    err.kind() == ZERO_CHUNK_KIND
        && err
            .get_ref()
            .is_some_and(|e| e.to_string() == ZERO_CHUNK_MSG)
}

fn zero_chunk_err() -> io::Error {
    io::Error::new(ZERO_CHUNK_KIND, ZERO_CHUNK_MSG)
}

fn increment_nonce(nonce: &mut [u8; V3_NONCE_SIZE]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

enum ReaderState {
    NeedSalt {
        salt_buf: [u8; V3_SALT_SIZE],
        salt_progress: usize,
    },
    ReadingHeader {
        aead: Arc<Aes128Gcm>,
        nonce: [u8; V3_NONCE_SIZE],
        header_buf: [u8; V3_LENGTH_CIPHER_SIZE],
        header_progress: usize,
    },
    ReadingPayload {
        aead: Arc<Aes128Gcm>,
        nonce: [u8; V3_NONCE_SIZE],
        payload_len: usize,
        payload_buf: Vec<u8>,
        payload_progress: usize,
    },
    Drain {
        aead: Arc<Aes128Gcm>,
        nonce: [u8; V3_NONCE_SIZE],
        payload: Vec<u8>,
        payload_off: usize,
    },
}

struct Writer {
    aead: Arc<Aes128Gcm>,
    nonce: [u8; V3_NONCE_SIZE],
    salt: [u8; V3_SALT_SIZE],
    salt_sent: bool,
    pending: Vec<u8>,
    pending_off: usize,
    pending_input: usize,
}

impl Writer {
    fn new(psk: &[u8]) -> Self {
        let mut salt = [0u8; V3_SALT_SIZE];
        rand::rng().fill_bytes(&mut salt);
        let aead = aes_gcm(&snell_kdf(psk, &salt, 16));
        Self {
            aead: Arc::new(aead),
            nonce: [0u8; V3_NONCE_SIZE],
            salt,
            salt_sent: false,
            pending: Vec::new(),
            pending_off: 0,
            pending_input: 0,
        }
    }

    fn stage_record(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell v3 record too large",
            ));
        }

        let mut header = Vec::with_capacity(V3_LENGTH_CIPHER_SIZE);
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        seal_in_place(&self.aead, &self.nonce, &mut header)?;
        increment_nonce(&mut self.nonce);

        let mut body = Vec::new();
        if !payload.is_empty() {
            body.extend_from_slice(payload);
            seal_in_place(&self.aead, &self.nonce, &mut body)?;
            increment_nonce(&mut self.nonce);
        }

        let mut frame = Vec::with_capacity(
            if self.salt_sent { 0 } else { V3_SALT_SIZE } + header.len() + body.len(),
        );
        if !self.salt_sent {
            frame.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&body);

        self.pending = frame;
        self.pending_off = 0;
        Ok(())
    }
}

fn seal_in_place(
    aead: &Aes128Gcm,
    nonce: &[u8; V3_NONCE_SIZE],
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    aead.seal_append(nonce, buf)
        .map_err(|_| io::Error::other("snell v3 encrypt failed"))
}

fn open_in_place(
    aead: &Aes128Gcm,
    nonce: &[u8; V3_NONCE_SIZE],
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    aead.open_trailing(nonce, buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "snell v3 decrypt failed"))
}

pub struct V3Conn<S> {
    inner: BufReader<S>,
    psk: Arc<[u8]>,
    writer: Writer,
    reader: ReaderState,
}

impl<S: AsyncRead> V3Conn<S> {
    pub fn new(inner: S, psk: Arc<[u8]>) -> Self {
        let writer = Writer::new(&psk);
        Self {
            inner: BufReader::with_capacity(V3_READ_BUFFER_SIZE, inner),
            psk,
            writer,
            reader: ReaderState::NeedSalt {
                salt_buf: [0u8; V3_SALT_SIZE],
                salt_progress: 0,
            },
        }
    }
}

impl<S> V3Conn<S> {
    pub fn has_pending_write(&self) -> bool {
        self.writer.pending_off < self.writer.pending.len()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for V3Conn<S> {
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
                    let mut tmp = [0u8; V3_SALT_SIZE];
                    let need = V3_SALT_SIZE - *salt_progress;
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
                            "snell v3 EOF before salt",
                        )));
                    }
                    salt_buf[*salt_progress..*salt_progress + n].copy_from_slice(&tmp[..n]);
                    *salt_progress += n;
                    if *salt_progress < V3_SALT_SIZE {
                        continue;
                    }
                    let aead = Arc::new(aes_gcm(&snell_kdf(&this.psk, &salt_buf[..], 16)));
                    this.reader = ReaderState::ReadingHeader {
                        aead,
                        nonce: [0u8; V3_NONCE_SIZE],
                        header_buf: [0u8; V3_LENGTH_CIPHER_SIZE],
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
                            header_buf: [0u8; V3_LENGTH_CIPHER_SIZE],
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
                    let need = V3_LENGTH_CIPHER_SIZE - *header_progress;
                    let mut tmp = [0u8; V3_LENGTH_CIPHER_SIZE];
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let n = rb.filled().len();
                    if n == 0 {
                        if *header_progress == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell v3 EOF mid-header",
                        )));
                    }
                    header_buf[*header_progress..*header_progress + n].copy_from_slice(&tmp[..n]);
                    *header_progress += n;
                    if *header_progress < V3_LENGTH_CIPHER_SIZE {
                        continue;
                    }
                    let mut sealed = header_buf.to_vec();
                    if let Err(e) = open_in_place(aead, nonce, &mut sealed) {
                        return Poll::Ready(Err(e));
                    }
                    increment_nonce(nonce);
                    if sealed.len() != V3_LENGTH_PLAIN_SIZE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snell v3 invalid length header",
                        )));
                    }
                    let payload_len = usize::from(u16::from_be_bytes([sealed[0], sealed[1]]))
                        & MAX_PAYLOAD_LENGTH;
                    if payload_len == 0 {
                        let aead_keep = Arc::clone(aead);
                        let nonce_keep = *nonce;
                        this.reader = ReaderState::ReadingHeader {
                            aead: aead_keep,
                            nonce: nonce_keep,
                            header_buf: [0u8; V3_LENGTH_CIPHER_SIZE],
                            header_progress: 0,
                        };
                        return Poll::Ready(Err(zero_chunk_err()));
                    }
                    let aead = Arc::clone(aead);
                    let nonce = *nonce;
                    this.reader = ReaderState::ReadingPayload {
                        aead,
                        nonce,
                        payload_len,
                        payload_buf: vec![0u8; payload_len + V3_GCM_TAG],
                        payload_progress: 0,
                    };
                }
                ReaderState::ReadingPayload {
                    aead,
                    nonce,
                    payload_len,
                    payload_buf,
                    payload_progress,
                } => {
                    if *payload_progress < payload_buf.len() {
                        let mut rb = ReadBuf::new(&mut payload_buf[*payload_progress..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) => {}
                        }
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "snell v3 EOF mid-payload",
                            )));
                        }
                        *payload_progress += n;
                        if *payload_progress < payload_buf.len() {
                            continue;
                        }
                    }
                    let mut payload = payload_buf.to_vec();
                    if let Err(e) = open_in_place(aead, nonce, &mut payload) {
                        return Poll::Ready(Err(e));
                    }
                    increment_nonce(nonce);
                    debug_assert_eq!(payload.len(), *payload_len);
                    let aead = Arc::clone(aead);
                    let nonce = *nonce;
                    this.reader = ReaderState::Drain {
                        aead,
                        nonce,
                        payload,
                        payload_off: 0,
                    };
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for V3Conn<S> {
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
            this.writer.stage_record(&[])?;
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
            }
        } else {
            let take = buf.len().min(MAX_PAYLOAD_LENGTH);
            this.writer.pending_input = take;
            this.writer.stage_record(&buf[..take])?;
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
                    "snell v3: short write",
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
        let mut n = [0xFFu8; V3_NONCE_SIZE];
        increment_nonce(&mut n);
        assert_eq!(n, [0u8; V3_NONCE_SIZE]);
    }

    #[tokio::test]
    async fn v3_round_trip_through_duplex() {
        let (a, b) = tokio::io::duplex(1 << 18);
        let psk: Arc<[u8]> = Arc::from(b"shared-secret".as_slice());
        let mut alice = V3Conn::new(a, Arc::clone(&psk));
        let mut bob = V3Conn::new(b, psk);

        let small = b"hello-v3";
        let large: Vec<u8> = (0..32_000u32).map(|i| (i % 251) as u8).collect();
        let large_to_write = large.clone();

        let writer = tokio::spawn(async move {
            alice.write_all(small).await.unwrap();
            alice.write_all(&large_to_write).await.unwrap();
            alice.flush().await.unwrap();
            alice
        });

        let mut got_small = vec![0u8; small.len()];
        bob.read_exact(&mut got_small).await.unwrap();
        assert_eq!(got_small, small);

        let mut got_large = vec![0u8; 32_000];
        bob.read_exact(&mut got_large).await.unwrap();
        assert_eq!(got_large, large);

        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn v3_zero_chunk_surfaces_as_tagged_error() {
        let (a, b) = tokio::io::duplex(8192);
        let psk: Arc<[u8]> = Arc::from(b"k".as_slice());
        let mut alice = V3Conn::new(a, Arc::clone(&psk));
        let mut bob = V3Conn::new(b, psk);

        alice.write_all(b"abc").await.unwrap();
        alice.flush().await.unwrap();
        std::future::poll_fn(|cx| Pin::new(&mut alice).poll_write(cx, &[]))
            .await
            .unwrap();
        alice.flush().await.unwrap();

        let mut got = [0u8; 3];
        bob.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"abc");

        let mut scratch = [0u8; 1];
        let err = bob.read(&mut scratch).await.unwrap_err();
        assert!(is_zero_chunk(&err), "expected zero-chunk tag, got {err:?}");
    }
}
