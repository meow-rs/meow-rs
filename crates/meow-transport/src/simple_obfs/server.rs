//! Native simple-obfs **server** implementation (HTTP and TLS modes).
//!
//! The upstream Go `transport/simple-obfs` package ships only the *client*
//! codec (`HttpObfs` / `TlsObfs` in `client`); the server side is
//! conventionally an external `obfs-server` binary. meow-rs inlines the server
//! codec here so its `shadowsocks` listener can terminate simple-obfs without
//! an external plugin.
//!
//! The two codecs are the exact inverse of the client ones — byte-compatible
//! with the framing `client` produces and consumes, so a meow-rs
//! obfs-client ↔ meow-rs obfs-server pair interops and a meow-rs server
//! interops with the reference `obfs-local` client (same wire format).
//!
//! # HTTP
//! - **read** (client→server): the client's first write is a fake
//!   `GET / HTTP/1.1` request (`headers\r\n\r\n body`). Strip up to and
//!   including `\r\n\r\n`, surface the body; passthrough afterwards.
//! - **write** (server→client): the client strips up to `\r\n\r\n` on its
//!   first read, so the server's first write prepends a fake
//!   `HTTP/1.1 101` response header; passthrough afterwards.
//!
//! # TLS
//! - **read** (client→server): the client's first write is a fake TLS
//!   ClientHello with the first payload embedded in the `session_ticket`
//!   extension at a fixed body offset (137). The server reads the record,
//!   extracts the payload, then reads subsequent app-data records
//!   (`0x17 0x03 0x03 len u16 payload`).
//! - **write** (server→client): the client discards
//!   `TLS_FIRST_RESPONSE_DISCARD` = 105 bytes then reads
//!   `len u16 payload`; subsequent frames are
//!   `0x17 0x03 0x03 len u16 payload`. So the server's first write emits 105
//!   fake bytes (a pseudo ServerHello + ChangeCipherSpec prefix) then
//!   `len u16 payload`; later writes are plain app-data records.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const TLS_CHUNK_SIZE: usize = 1 << 14; // 16 KiB, matches client
const TLS_FIRST_RESPONSE_DISCARD: usize = 105;
/// Body offset (within the ClientHello record body, *after* the 5-byte TLS
/// record header) at which the `session_ticket` extension's 2-byte length
/// field begins. The embedded payload follows immediately. Derived from the
/// fixed layout of `client::build_client_hello`:
/// `4 (hs hdr) + 2 (ver) + 32 (random) + 33 (session_id) + 58 (cipher_suites)
///  + 2 (compression) + 2 (ext_len) + 2 (ext_type) = 135`.
const TLS_SESSION_TICKET_LEN_OFF: usize = 135;

// ---------------------------------------------------------------------------
// HTTP simple-obfs server
// ---------------------------------------------------------------------------

/// HTTP simple-obfs server wrapper — the inverse of `client::HttpObfs`.
pub struct HttpObfsServer<S> {
    inner: S,
    // Read side: strip the first request's HTTP headers.
    first_request: bool,
    response_scratch: Vec<u8>,
    leftover: Vec<u8>,
    leftover_off: usize,
    // Write side: prepend a fake HTTP response header on the first write.
    first_response: bool,
    write_buf: Vec<u8>,
    write_buf_off: usize,
    pending_input: usize,
}

impl<S> HttpObfsServer<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            first_request: true,
            response_scratch: Vec::new(),
            leftover: Vec::new(),
            leftover_off: 0,
            first_response: true,
            write_buf: Vec::new(),
            write_buf_off: 0,
            pending_input: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpObfsServer<S> {
    fn poll_drain_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_buf_off < self.write_buf.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_buf_off..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs-server: write zero",
                )));
            }
            self.write_buf_off += n;
        }
        self.write_buf.clear();
        self.write_buf_off = 0;
        Poll::Ready(Ok(()))
    }
}

/// The fake HTTP response header the server prepends to its first write.
/// The client strips everything up to and including `\r\n\r\n`, so the exact
/// headers are not wire-critical; they mimic a WebSocket upgrade response for
/// plausibility to a passive observer (matching the client's test fixture).
fn http_response_header() -> &'static [u8] {
    b"HTTP/1.1 101 Switching Protocols\r\n\
      Server: nginx\r\n\
      Upgrade: websocket\r\n\
      Connection: Upgrade\r\n\
      \r\n"
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpObfsServer<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Deliver any leftover body bytes from the first request first.
        if this.leftover_off < this.leftover.len() {
            let avail = &this.leftover[this.leftover_off..];
            let take = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..take]);
            this.leftover_off += take;
            if this.leftover_off >= this.leftover.len() {
                this.leftover.clear();
                this.leftover_off = 0;
            }
            return Poll::Ready(Ok(()));
        }

        if this.first_request {
            // Read until we find the `\r\n\r\n` request terminator, then
            // surface everything after it as the first payload.
            const MAX_HEADER: usize = 16 * 1024;
            loop {
                let mut tmp = [0u8; 1024];
                let mut rb = ReadBuf::new(&mut tmp);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                let n = rb.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(())); // EOF before headers complete
                }
                this.response_scratch.extend_from_slice(&tmp[..n]);
                if let Some(idx) = find_double_crlf(&this.response_scratch) {
                    this.first_request = false;
                    let body_start = idx + 4;
                    let body = &this.response_scratch[body_start..];
                    let take = body.len().min(buf.remaining());
                    buf.put_slice(&body[..take]);
                    if take < body.len() {
                        this.leftover.extend_from_slice(&body[take..]);
                        this.leftover_off = 0;
                    }
                    this.response_scratch.clear();
                    this.response_scratch.shrink_to_fit();
                    return Poll::Ready(Ok(()));
                }
                if this.response_scratch.len() > MAX_HEADER {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "obfs-server http: request header exceeds limit",
                    )));
                }
            }
        }

        // Passthrough.
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpObfsServer<S> {
    /// # `pending_input` invariant
    ///
    /// When a previous `poll_write` returned `Pending` (its framed bytes are
    /// still draining), the next call finishes the drain and reports
    /// `Ok(pending_input)` — the length of the *previous* buffer. This is
    /// correct only when the caller retries with the same (unconsumed)
    /// buffer, which is the `AsyncWriteExt::write_all` contract. Callers that
    /// drop a pending `poll_write` and call again with a *different* buffer
    /// would see the wrong consumed count. All in-tree callers use
    /// `write_all`, so this is safe.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
            let consumed = this.pending_input;
            this.pending_input = 0;
            return Poll::Ready(Ok(consumed));
        }

        if this.first_response {
            this.first_response = false;
            let header = http_response_header();
            let mut framed = Vec::with_capacity(header.len() + buf.len());
            framed.extend_from_slice(header);
            framed.extend_from_slice(buf);
            this.write_buf = framed;
            this.write_buf_off = 0;
            this.pending_input = buf.len();
        } else {
            // Passthrough — write directly, no buffer copy.
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        match this.poll_drain_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                let consumed = this.pending_input;
                this.pending_input = 0;
                Poll::Ready(Ok(consumed))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn find_double_crlf(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    for i in 0..=data.len() - 4 {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// TLS simple-obfs server
// ---------------------------------------------------------------------------

/// TLS simple-obfs server wrapper — the inverse of `client::TlsObfs`.
pub struct TlsObfsServer<S> {
    inner: S,
    // Read state.
    read_phase: TlsServerReadPhase,
    /// Buffer for accumulating the first ClientHello record body.
    hello_buf: Vec<u8>,
    /// Leftover payload extracted from the ClientHello that didn't fit in the
    /// caller's first read buffer.
    leftover: Vec<u8>,
    leftover_off: usize,
    /// Accumulates the 5-byte ClientHello record header across partial reads
    /// (TCP is a byte stream; a single `poll_read` may return fewer than 5
    /// bytes even when data is available).
    hello_header_buf: [u8; 5],
    hello_header_progress: usize,
    len_buf: [u8; 2],
    len_progress: usize,
    // Write state.
    first_response: bool,
    write_buf: Vec<u8>,
    write_buf_off: usize,
    pending_input: usize,
}

#[derive(Debug, Clone, Copy)]
enum TlsServerReadPhase {
    /// Reading the 5-byte ClientHello record header.
    HelloHeader,
    /// Reading `n` more bytes of the ClientHello record body.
    HelloBody(usize),
    /// Discarding `n` bytes (the 3-byte app-data record header
    /// `0x17 0x03 0x03`).
    Discard(usize),
    /// Reading the 2-byte big-endian payload length.
    Length,
    /// Reading `n` more bytes of payload into the caller's buffer.
    Payload(usize),
}

impl<S> TlsObfsServer<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_phase: TlsServerReadPhase::HelloHeader,
            hello_buf: Vec::new(),
            leftover: Vec::new(),
            leftover_off: 0,
            hello_header_buf: [0u8; 5],
            hello_header_progress: 0,
            len_buf: [0u8; 2],
            len_progress: 0,
            first_response: true,
            write_buf: Vec::new(),
            write_buf_off: 0,
            pending_input: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsObfsServer<S> {
    fn poll_drain_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_buf_off < self.write_buf.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_buf_off..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs-server: write zero",
                )));
            }
            self.write_buf_off += n;
        }
        self.write_buf.clear();
        self.write_buf_off = 0;
        Poll::Ready(Ok(()))
    }
}

/// The 105-byte fake prefix the server emits before its first payload. The
/// client discards exactly [`TLS_FIRST_RESPONSE_DISCARD`] bytes, so the
/// content is not wire-critical; it mimics a TLS ServerHello + ChangeCipherSpec
/// prefix for plausibility. Computed at compile time — no per-connection
/// randomness is needed (the client never inspects it).
static TLS_FAKE_RESPONSE_PREFIX: [u8; TLS_FIRST_RESPONSE_DISCARD] = {
    let mut buf = [0u8; TLS_FIRST_RESPONSE_DISCARD];
    // ServerHello record: type 0x16, version 0x0303, body length 86 (0x0056).
    buf[0] = 0x16;
    buf[1] = 0x03;
    buf[2] = 0x03;
    buf[3] = 0x00;
    buf[4] = 0x56;
    // buf[5..91] = 86 zero bytes (ServerHello body) — already zeroed.
    // ChangeCipherSpec record: type 0x14, version 0x0303, length 1, byte 0x01.
    buf[91] = 0x14;
    buf[92] = 0x03;
    buf[93] = 0x03;
    buf[94] = 0x00;
    buf[95] = 0x01;
    buf[96] = 0x01;
    // Pad the remaining 8 bytes (97..105) with a fake record type byte.
    let mut i = 97;
    while i < TLS_FIRST_RESPONSE_DISCARD {
        buf[i] = 0x17;
        i += 1;
    }
    buf
};

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsObfsServer<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Deliver leftover payload from the ClientHello extraction first.
        if this.leftover_off < this.leftover.len() {
            let avail = &this.leftover[this.leftover_off..];
            let take = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..take]);
            this.leftover_off += take;
            if this.leftover_off >= this.leftover.len() {
                this.leftover.clear();
                this.leftover_off = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            match this.read_phase {
                TlsServerReadPhase::HelloHeader => {
                    // Read the 5-byte TLS record header, buffering across
                    // partial reads (TCP may deliver fewer than 5 bytes in a
                    // single poll_read, even when data is available).
                    let need = 5 - this.hello_header_progress;
                    let mut tmp = [0u8; 5];
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.hello_header_buf
                        [this.hello_header_progress..this.hello_header_progress + n]
                        .copy_from_slice(&tmp[..n]);
                    this.hello_header_progress += n;
                    if this.hello_header_progress < 5 {
                        continue; // need more header bytes
                    }
                    // Full header received — expect a handshake record (0x16).
                    if this.hello_header_buf[0] != 0x16 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "obfs-server tls: expected ClientHello record",
                        )));
                    }
                    let record_len =
                        u16::from_be_bytes([this.hello_header_buf[3], this.hello_header_buf[4]])
                            as usize;
                    this.hello_buf.reserve(record_len);
                    this.read_phase = TlsServerReadPhase::HelloBody(record_len);
                }
                TlsServerReadPhase::HelloBody(remaining) => {
                    if remaining == 0 {
                        // Body complete — extract the session_ticket payload.
                        let body = &this.hello_buf;
                        if body.len() < TLS_SESSION_TICKET_LEN_OFF + 2 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "obfs-server tls: ClientHello too short",
                            )));
                        }
                        let data_len = u16::from_be_bytes([
                            body[TLS_SESSION_TICKET_LEN_OFF],
                            body[TLS_SESSION_TICKET_LEN_OFF + 1],
                        ]) as usize;
                        let data_start = TLS_SESSION_TICKET_LEN_OFF + 2;
                        if body.len() < data_start + data_len {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "obfs-server tls: session_ticket payload truncated",
                            )));
                        }
                        let data = &body[data_start..data_start + data_len];
                        let take = data.len().min(buf.remaining());
                        buf.put_slice(&data[..take]);
                        if take < data.len() {
                            this.leftover.extend_from_slice(&data[take..]);
                            this.leftover_off = 0;
                        }
                        this.hello_buf.clear();
                        this.hello_buf.shrink_to_fit();
                        // Subsequent reads parse app-data records.
                        this.read_phase = TlsServerReadPhase::Discard(3);
                        return Poll::Ready(Ok(()));
                    }
                    let mut tmp = [0u8; 4096];
                    let want = remaining.min(tmp.len());
                    let mut rb = ReadBuf::new(&mut tmp[..want]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF mid-body
                    }
                    this.hello_buf.extend_from_slice(&tmp[..n]);
                    this.read_phase = TlsServerReadPhase::HelloBody(remaining - n);
                }
                TlsServerReadPhase::Discard(0) => {
                    this.read_phase = TlsServerReadPhase::Length;
                    this.len_progress = 0;
                }
                TlsServerReadPhase::Discard(remaining) => {
                    let mut tmp = [0u8; 256];
                    let take = remaining.min(tmp.len());
                    let mut rb = ReadBuf::new(&mut tmp[..take]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.read_phase = TlsServerReadPhase::Discard(remaining - n);
                }
                TlsServerReadPhase::Length => {
                    if this.len_progress >= 2 {
                        let length =
                            u16::from_be_bytes([this.len_buf[0], this.len_buf[1]]) as usize;
                        this.read_phase = TlsServerReadPhase::Payload(length);
                        continue;
                    }
                    let mut tmp = [0u8; 2];
                    let need = 2 - this.len_progress;
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.len_buf[this.len_progress..this.len_progress + n]
                        .copy_from_slice(&tmp[..n]);
                    this.len_progress += n;
                }
                TlsServerReadPhase::Payload(0) => {
                    // Frame finished — next frame starts with a 3-byte header.
                    this.read_phase = TlsServerReadPhase::Discard(3);
                }
                TlsServerReadPhase::Payload(remaining) => {
                    let space = buf.remaining().min(remaining);
                    if space == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    // Read directly into the caller's buffer (zero heap
                    // allocation). `initialize_unfilled` borrows `buf`
                    // mutably; the borrow ends when the block scope closes,
                    // so `buf.advance` below is free to borrow again.
                    let added = {
                        let unfilled = buf.initialize_unfilled();
                        let mut rb = ReadBuf::new(&mut unfilled[..space]);
                        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                        rb.filled().len()
                    };
                    if added == 0 {
                        return Poll::Ready(Ok(())); // EOF mid-frame
                    }
                    buf.advance(added);
                    this.read_phase = TlsServerReadPhase::Payload(remaining - added);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsObfsServer<S> {
    /// Same `pending_input` invariant as `HttpObfsServer::poll_write` — see
    /// that method's doc comment.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
            let consumed = this.pending_input;
            this.pending_input = 0;
            return Poll::Ready(Ok(consumed));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(TLS_CHUNK_SIZE);
        let chunk = &buf[..take];

        if this.first_response {
            this.first_response = false;
            let mut framed = Vec::with_capacity(TLS_FIRST_RESPONSE_DISCARD + 2 + chunk.len());
            framed.extend_from_slice(&TLS_FAKE_RESPONSE_PREFIX);
            framed.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            framed.extend_from_slice(chunk);
            this.write_buf = framed;
        } else {
            let mut framed = Vec::with_capacity(5 + chunk.len());
            framed.extend_from_slice(&[0x17, 0x03, 0x03]);
            framed.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            framed.extend_from_slice(chunk);
            this.write_buf = framed;
        }
        this.write_buf_off = 0;
        this.pending_input = take;

        match this.poll_drain_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                let consumed = this.pending_input;
                this.pending_input = 0;
                Poll::Ready(Ok(consumed))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simple_obfs::client::{HttpObfs, TlsObfs};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ── HTTP: client ↔ server round-trip through a duplex ──────────────────

    #[tokio::test]
    async fn http_client_to_server_round_trip() {
        // client writes through HttpObfs, server reads through HttpObfsServer.
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut client = HttpObfs::new(client_io, "example.com".to_string(), 80).unwrap();
        let mut server = HttpObfsServer::new(server_io);

        client.write_all(b"FIRST_PAYLOAD").await.unwrap();
        client.write_all(b"_SECOND").await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();
        drop(client);

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"FIRST_PAYLOAD_SECOND");
    }

    #[tokio::test]
    async fn http_server_to_client_round_trip() {
        // server writes through HttpObfsServer, client reads through HttpObfs.
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut client = HttpObfs::new(client_io, "example.com".to_string(), 80).unwrap();
        let mut server = HttpObfsServer::new(server_io);

        server.write_all(b"REPLY_BODY").await.unwrap();
        server.write_all(b"_MORE").await.unwrap();
        server.flush().await.unwrap();
        server.shutdown().await.unwrap();
        drop(server);

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"REPLY_BODY_MORE");
    }

    // ── TLS: client ↔ server round-trip ────────────────────────────────────

    #[tokio::test]
    async fn tls_client_to_server_round_trip() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let mut client = TlsObfs::new(client_io, "example.com".to_string()).unwrap();
        let mut server = TlsObfsServer::new(server_io);

        client.write_all(b"SECRET_FIRST").await.unwrap();
        client.write_all(b"_SECOND_CHUNK").await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; 64];
        let n = server.read(&mut got).await.unwrap();
        assert_eq!(&got[..n], b"SECRET_FIRST");
        let m = server.read(&mut got).await.unwrap();
        assert_eq!(&got[..m], b"_SECOND_CHUNK");
    }

    #[tokio::test]
    async fn tls_server_to_client_round_trip() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let mut client = TlsObfs::new(client_io, "example.com".to_string()).unwrap();
        let mut server = TlsObfsServer::new(server_io);

        server.write_all(b"SERVER_REPLY").await.unwrap();
        server.write_all(b"_AGAIN").await.unwrap();
        server.flush().await.unwrap();

        let mut got = vec![0u8; 64];
        let n = client.read(&mut got).await.unwrap();
        assert_eq!(&got[..n], b"SERVER_REPLY");
        let m = client.read(&mut got).await.unwrap();
        assert_eq!(&got[..m], b"_AGAIN");
    }

    #[tokio::test]
    async fn tls_large_payload_round_trip() {
        // Exercise multi-chunk framing (> 16 KiB).
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let mut client = TlsObfs::new(client_io, "example.com".to_string()).unwrap();
        let mut server = TlsObfsServer::new(server_io);

        let payload: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();
        drop(client);

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, payload);
    }
}
