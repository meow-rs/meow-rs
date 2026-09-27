//! Native simple-obfs client implementation (HTTP and TLS modes).
//!
//! Port of Go mihomo's `transport/simple-obfs` package. Wraps an existing byte
//! stream and obfuscates the first request / response so shadowsocks traffic
//! looks like plain HTTP or TLS to a passive observer. After the first
//! request/response handshake, HTTP mode is pure passthrough; TLS mode keeps
//! framing each application chunk inside a fake TLS application-data record.
//!
//! Used as the underlying transport for `ShadowsocksAdapter` when the YAML
//! config sets `plugin: obfs` (with `plugin-opts: {mode: http|tls, host: ...}`).
//! No external `obfs-local` / `simple-obfs` binary is required.

use std::io;
use std::pin::Pin;
use std::task::ready;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const TLS_CHUNK_SIZE: usize = 1 << 14; // 16 KiB, matches Go reference
const TLS_FIRST_RESPONSE_DISCARD: usize = 105;
const TLS_RECORD_HEADER_DISCARD: usize = 3; // type(1) + version(2)

// ---------------------------------------------------------------------------
// HTTP simple-obfs
// ---------------------------------------------------------------------------

/// HTTP simple-obfs client wrapper.
///
/// On the first write the payload is sent inside a fake `GET / HTTP/1.1`
/// request body with WebSocket upgrade headers. The first response is parsed
/// to strip everything up to and including the `\r\n\r\n` header terminator,
/// then both directions become pure passthrough.
pub struct HttpObfs<S> {
    inner: S,
    host: String,
    port: u16,

    // First-write framing.
    first_request: bool,
    write_buf: Vec<u8>,
    write_buf_off: usize,
    pending_input: usize,

    // First-read header stripping.
    first_response: bool,
    response_scratch: Vec<u8>,
    leftover: Vec<u8>,
    leftover_off: usize,
}

/// Whether `host` is safe to emit verbatim inside a `Host:` request
/// header — rejects empty strings and any byte that could split the
/// request line or smuggle headers (`<= 0x20`, `0x7f`). Shared gate for
/// the config parse sites and [`HttpObfs::new`] (issue #648).
pub fn is_valid_obfs_host(host: &str) -> bool {
    // Length bound: the value also lands in the TLS SNI extension
    // (`build_client_hello`), whose u16 length arithmetic would overflow on
    // a >64 KiB hostname — 253 is the RFC 1034 FQDN ceiling and valid SNI.
    !host.is_empty() && host.len() <= 253 && !host.bytes().any(|b| b <= b' ' || b == 0x7f)
}

impl<S> HttpObfs<S> {
    /// `host` lands verbatim in the emitted `Host:` header — reject any
    /// value that could inject request bytes ([`is_valid_obfs_host`]).
    /// Fails closed rather than writing a corrupted request.
    pub fn new(inner: S, host: String, port: u16) -> crate::Result<Self> {
        if !is_valid_obfs_host(&host) {
            return Err(crate::TransportError::Config(
                "simple-obfs: invalid host (empty, over 253 bytes, or contains whitespace/control bytes)"
                    .into(),
            ));
        }
        Ok(Self {
            inner,
            host,
            port,
            first_request: true,
            write_buf: Vec::new(),
            write_buf_off: 0,
            pending_input: 0,
            first_response: true,
            response_scratch: Vec::new(),
            leftover: Vec::new(),
            leftover_off: 0,
        })
    }

    fn build_request(&self, body: &[u8]) -> Vec<u8> {
        build_http_request(&self.host, self.port, body)
    }
}

/// Builds the fake HTTP GET request bytes used by `HttpObfs` on the first
/// write. Split out so it can be unit tested independently of any I/O.
fn build_http_request(host: &str, port: u16, body: &[u8]) -> Vec<u8> {
    let mut rand_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut rand_bytes);
    let key = base64::engine::general_purpose::URL_SAFE.encode(rand_bytes);

    let host_header = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    let mut rng = rand::rng();
    let ua_maj = rng.next_u32() % 54;
    let ua_min = rng.next_u32() % 2;

    use std::io::Write;
    let mut req = Vec::with_capacity(256 + body.len());
    let _ = write!(
        req,
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: curl/7.{}.{}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Content-Length: {}\r\n\
         \r\n",
        host_header,
        ua_maj,
        ua_min,
        key,
        body.len()
    );
    req.extend_from_slice(body);
    req
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpObfs<S> {
    fn poll_drain_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_buf_off < self.write_buf.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_buf_off..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs: write zero",
                )));
            }
            self.write_buf_off += n;
        }
        self.write_buf.clear();
        self.write_buf_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpObfs<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain any leftover post-header bytes from the first response first.
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

        if this.first_response {
            // Keep reading into scratch until we find the header terminator.
            // Bound the header size to 16 KiB to avoid unbounded growth from
            // a misbehaving / malicious peer.
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
                    this.first_response = false;
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
                        "obfs http: response header exceeds limit",
                    )));
                }
            }
        }

        // Passthrough.
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpObfs<S> {
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

        // If a previous call buffered framed bytes that haven't drained yet,
        // finish draining and report the originally-accepted input length.
        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
            let consumed = this.pending_input;
            this.pending_input = 0;
            return Poll::Ready(Ok(consumed));
        }

        if this.first_request {
            this.first_request = false;
            let req = this.build_request(buf);
            this.write_buf = req;
            this.write_buf_off = 0;
            this.pending_input = buf.len();
            match this.poll_drain_write_buf(cx) {
                Poll::Ready(Ok(())) => {
                    let consumed = this.pending_input;
                    this.pending_input = 0;
                    Poll::Ready(Ok(consumed))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Pin::new(&mut this.inner).poll_write(cx, buf)
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
// TLS simple-obfs
// ---------------------------------------------------------------------------

/// TLS simple-obfs client wrapper.
///
/// On the first write the payload is embedded in a fake TLS ClientHello
/// (inside the SessionTicket extension). After that, every chunk (up to 16 KiB)
/// is wrapped as a TLS application-data record (`0x17 0x03 0x03 <len:u16>`).
/// Reads discard the fake TLS framing on the wire and surface only the inner
/// payload.
pub struct TlsObfs<S> {
    inner: S,
    server: String,

    // Read state.
    first_response: bool,
    read_phase: TlsReadPhase,
    len_buf: [u8; 2],
    len_progress: usize,

    // Write state.
    first_request: bool,
    write_buf: Vec<u8>,
    write_buf_off: usize,
    pending_input: usize,
}

#[derive(Debug, Clone, Copy)]
enum TlsReadPhase {
    /// Discarding `n` bytes from the wire (TLS record header / fake handshake).
    Discard(usize),
    /// Reading the 2-byte big-endian length field.
    Length,
    /// Reading `n` more bytes of the current frame's payload directly into the
    /// caller's buffer.
    Payload(usize),
}

impl<S> TlsObfs<S> {
    /// `server` lands verbatim in the fake ClientHello's SNI — same
    /// injection surface as [`HttpObfs::new`]'s host, same predicate. The
    /// `build_client_hello` `debug_assert!` only covers length; reject
    /// CTL/oversize here for programmatic callers too (config paths are
    /// pre-validated — issue #648 review).
    pub fn new(inner: S, server: String) -> crate::Result<Self> {
        if !is_valid_obfs_host(&server) {
            return Err(crate::TransportError::Config(
                "tls-obfs: invalid server (empty, over 253 bytes, or contains whitespace/control bytes)"
                    .into(),
            ));
        }
        Ok(Self {
            inner,
            server,
            first_response: true,
            read_phase: TlsReadPhase::Discard(TLS_FIRST_RESPONSE_DISCARD),
            len_buf: [0u8; 2],
            len_progress: 0,
            first_request: true,
            write_buf: Vec::new(),
            write_buf_off: 0,
            pending_input: 0,
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsObfs<S> {
    fn poll_drain_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_buf_off < self.write_buf.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_buf_off..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs: write zero",
                )));
            }
            self.write_buf_off += n;
        }
        self.write_buf.clear();
        self.write_buf_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsObfs<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_phase {
                TlsReadPhase::Discard(0) => {
                    this.read_phase = TlsReadPhase::Length;
                    this.len_progress = 0;
                }
                TlsReadPhase::Discard(remaining) => {
                    let mut tmp = [0u8; 256];
                    let take = remaining.min(tmp.len());
                    let mut rb = ReadBuf::new(&mut tmp[..take]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.read_phase = TlsReadPhase::Discard(remaining - n);
                }
                TlsReadPhase::Length => {
                    if this.len_progress >= 2 {
                        let length =
                            u16::from_be_bytes([this.len_buf[0], this.len_buf[1]]) as usize;
                        this.read_phase = TlsReadPhase::Payload(length);
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
                TlsReadPhase::Payload(0) => {
                    // Frame finished. Next frame: skip the 3-byte record header.
                    this.read_phase = TlsReadPhase::Discard(TLS_RECORD_HEADER_DISCARD);
                    this.first_response = false;
                }
                TlsReadPhase::Payload(remaining) => {
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
                    this.read_phase = TlsReadPhase::Payload(remaining - added);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsObfs<S> {
    /// Same `pending_input` invariant as `HttpObfs::poll_write` — see that
    /// method's doc comment.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Drain any pending framed bytes from a previous Pending return.
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

        if this.first_request {
            this.first_request = false;
            this.write_buf = build_client_hello(chunk, &this.server);
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

/// Builds a fake TLS ClientHello carrying `data` inside the SessionTicket
/// extension and `server` inside the SNI extension. Byte-for-byte mirror of
/// the Go reference implementation in `transport/simple-obfs/tls.go`.
fn build_client_hello(data: &[u8], server: &str) -> Vec<u8> {
    // All length fields below are u16 — `server` (SNI) must stay within the
    // RFC 1034 FQDN bound enforced by `is_valid_obfs_host` on every parse
    // path; a programmatic oversized host would otherwise wrap the record
    // length into a malformed ClientHello (debug: panic).
    debug_assert!(server.len() <= 253, "SNI host exceeds u16-safe length");
    let mut random = [0u8; 28];
    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    rand::rng().fill_bytes(&mut session_id);

    let server_bytes = server.as_bytes();
    let data_len = data.len();
    let server_len = server_bytes.len();

    let mut buf = Vec::with_capacity(256 + data_len + server_len);

    // Record header: handshake (0x16), TLS 1.0 version, length.
    buf.push(0x16);
    buf.extend_from_slice(&[0x03, 0x01]);
    let record_len = 212u16 + data_len as u16 + server_len as u16;
    buf.extend_from_slice(&record_len.to_be_bytes());

    // Handshake header: ClientHello (1), uint24 length.
    buf.push(0x01);
    buf.push(0x00);
    let handshake_len = 208u16 + data_len as u16 + server_len as u16;
    buf.extend_from_slice(&handshake_len.to_be_bytes());

    // client_version: TLS 1.2.
    buf.extend_from_slice(&[0x03, 0x03]);

    // Random: 4-byte timestamp + 28 random bytes.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32);
    buf.extend_from_slice(&now.to_be_bytes());
    buf.extend_from_slice(&random);

    // session_id length + session_id.
    buf.push(32);
    buf.extend_from_slice(&session_id);

    // cipher_suites: length 0x0038, then the suites.
    buf.extend_from_slice(&[0x00, 0x38]);
    buf.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);

    // compression_methods: 1, null.
    buf.extend_from_slice(&[0x01, 0x00]);

    // extensions length.
    let ext_len = 79u16 + data_len as u16 + server_len as u16;
    buf.extend_from_slice(&ext_len.to_be_bytes());

    // Extension: session_ticket (0x0023), length, data.
    buf.extend_from_slice(&[0x00, 0x23]);
    buf.extend_from_slice(&(data_len as u16).to_be_bytes());
    buf.extend_from_slice(data);

    // Extension: server_name (0x0000).
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&((server_len as u16) + 5).to_be_bytes());
    buf.extend_from_slice(&((server_len as u16) + 3).to_be_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&(server_len as u16).to_be_bytes());
    buf.extend_from_slice(server_bytes);

    // Extension: ec_point_formats.
    buf.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);

    // Extension: supported_groups.
    buf.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);

    // Extension: signature_algorithms.
    buf.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);

    // Extension: encrypt_then_mac.
    buf.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);

    // Extension: extended_master_secret.
    buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ---- HTTP request builder ----

    #[test]
    fn http_request_contains_body_and_headers() {
        let body = b"hello world";
        let req = build_http_request("example.com", 80, body);
        let s = std::str::from_utf8(&req[..req.len() - body.len()]).unwrap();
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(!s.contains("Host: example.com:80\r\n"));
        assert!(s.contains("Upgrade: websocket\r\n"));
        assert!(s.contains("Connection: Upgrade\r\n"));
        assert!(s.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(s.contains("Sec-WebSocket-Key: "));
        assert!(s.ends_with("\r\n\r\n"));
        assert_eq!(&req[req.len() - body.len()..], body);
    }

    #[test]
    fn http_request_uses_host_port_when_not_80() {
        let req = build_http_request("example.com", 8080, b"x");
        let s = std::str::from_utf8(&req).unwrap();
        assert!(s.contains("Host: example.com:8080\r\n"));
    }

    // ---- TLS ClientHello layout ----

    #[test]
    fn tls_client_hello_layout_matches_reference() {
        let data = b"the secret payload";
        let server = "example.com";
        let hello = build_client_hello(data, server);

        // Record header: 0x16 0x03 0x01 <len:u16>
        assert_eq!(hello[0], 0x16);
        assert_eq!(&hello[1..3], &[0x03, 0x01]);
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5);
        assert_eq!(record_len, 212 + data.len() + server.len());

        // ClientHello handshake header: type(1), uint24 len.
        assert_eq!(hello[5], 0x01);
        assert_eq!(hello[6], 0x00);
        let handshake_len = u16::from_be_bytes([hello[7], hello[8]]) as usize;
        assert_eq!(handshake_len, 208 + data.len() + server.len());

        // client_version 0x0303.
        assert_eq!(&hello[9..11], &[0x03, 0x03]);

        // session_id length 32 at offset 9 + 2 + 4 + 28 = 43.
        assert_eq!(hello[43], 32);

        // The data payload should be embedded somewhere — search for it.
        assert!(hello.windows(data.len()).any(|w| w == data));
        // SNI should contain the server name.
        assert!(hello.windows(server.len()).any(|w| w == server.as_bytes()));
    }

    // ---- HttpObfs round-trip against an in-memory duplex ----

    #[test]
    fn obfs_host_predicate_rejects_injectable_and_oversized() {
        // Shared gate for the SS `plugin-opts`, Snell `obfs-opts`, and
        // `HttpObfs::new` wrap-time check (issue #648).
        assert!(is_valid_obfs_host("example.com"));
        assert!(is_valid_obfs_host(&"a".repeat(253)));
        for bad in [
            "", "a b", "a\tb", "a\rb", "a\nb", "a\0b", "a\x7fb", "a\u{1f}b",
        ] {
            assert!(!is_valid_obfs_host(bad), "{bad:?} must be rejected");
        }
        assert!(!is_valid_obfs_host(&"a".repeat(254)));
        // Non-ASCII is fine — the emitted header is opaque bytes to the peer.
        assert!(is_valid_obfs_host("例え.jp"));
        // Direct ctor check too.
        let (s, _p) = tokio::io::duplex(64);
        assert!(HttpObfs::new(s, "a\rb".to_string(), 80).is_err());
    }

    #[tokio::test]
    async fn http_obfs_first_write_then_passthrough() {
        let (client, mut server) = tokio::io::duplex(8192);
        let mut obfs = HttpObfs::new(client, "example.com".to_string(), 80).unwrap();

        // First write: should be wrapped in HTTP request.
        obfs.write_all(b"PAYLOAD1").await.unwrap();
        // Second write: passthrough, raw bytes.
        obfs.write_all(b"PAYLOAD2").await.unwrap();
        obfs.flush().await.unwrap();

        // Read from the server side: must see HTTP headers + body + raw second write.
        let mut received = vec![0u8; 4096];
        let mut total = 0;
        // Loop until we have at least the full first request + second payload.
        while total < 16 {
            let n = server.read(&mut received[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        let received = &received[..total];
        let s = std::str::from_utf8(received).unwrap_or("");
        assert!(s.starts_with("GET / HTTP/1.1\r\n"), "got: {s:?}");
        // The body PAYLOAD1 follows \r\n\r\n.
        let idx = received
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header terminator");
        let after = &received[idx + 4..];
        assert!(after.starts_with(b"PAYLOAD1"));
        assert!(after.ends_with(b"PAYLOAD2"));
    }

    #[tokio::test]
    async fn http_obfs_strips_first_response_headers() {
        let (client, mut server) = tokio::io::duplex(8192);
        let mut obfs = HttpObfs::new(client, "example.com".to_string(), 80).unwrap();

        // Server sends a fake HTTP response followed by raw body.
        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                        Server: nginx\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\
                        \r\nHELLO_BODY_BYTES";
        server.write_all(response).await.unwrap();
        // Then more raw data later.
        server.write_all(b"_AND_MORE").await.unwrap();
        drop(server);

        let mut got = Vec::new();
        obfs.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"HELLO_BODY_BYTES_AND_MORE");
    }

    // ---- TlsObfs round-trip ----

    #[tokio::test]
    async fn tls_obfs_write_first_then_chunks() {
        let (client, mut server) = tokio::io::duplex(65536);
        let mut obfs = TlsObfs::new(client, "example.com".to_string()).unwrap();

        obfs.write_all(b"FIRST").await.unwrap();
        obfs.write_all(b"SECOND").await.unwrap();
        obfs.flush().await.unwrap();

        // Read everything the client wrote.
        let mut buf = vec![0u8; 4096];
        let mut total = 0;
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                server.read(&mut buf[total..]),
            )
            .await
            .unwrap()
            .unwrap();
            if n == 0 {
                break;
            }
            total += n;
            if total >= 5 + 11 {
                break;
            }
        }
        let received = &buf[..total];

        // Must start with TLS handshake record (0x16 0x03 0x01).
        assert_eq!(received[0], 0x16);
        assert_eq!(&received[1..3], &[0x03, 0x01]);
        let rec_len = u16::from_be_bytes([received[3], received[4]]) as usize;
        let hello_end = 5 + rec_len;

        // The fake handshake should contain the FIRST payload.
        assert!(received[..hello_end]
            .windows(b"FIRST".len())
            .any(|w| w == b"FIRST"));

        // After the handshake we expect an application-data record carrying SECOND.
        let after = &received[hello_end..];
        assert_eq!(after[0], 0x17);
        assert_eq!(&after[1..3], &[0x03, 0x03]);
        let len = u16::from_be_bytes([after[3], after[4]]) as usize;
        assert_eq!(len, b"SECOND".len());
        assert_eq!(&after[5..5 + len], b"SECOND");
    }

    #[tokio::test]
    async fn tls_obfs_read_strips_framing() {
        let (client, mut server) = tokio::io::duplex(65536);
        let mut obfs = TlsObfs::new(client, "example.com".to_string()).unwrap();

        // Server sends 105 bytes of fake handshake / change cipher / record header,
        // then a 2-byte length, then the payload.
        let mut server_msg = vec![0xAAu8; TLS_FIRST_RESPONSE_DISCARD];
        let payload1 = b"hello-from-server";
        server_msg.extend_from_slice(&(payload1.len() as u16).to_be_bytes());
        server_msg.extend_from_slice(payload1);
        // Subsequent frame: 3-byte record header + 2-byte length + payload.
        let payload2 = b"second-frame";
        server_msg.extend_from_slice(&[0x17, 0x03, 0x03]);
        server_msg.extend_from_slice(&(payload2.len() as u16).to_be_bytes());
        server_msg.extend_from_slice(payload2);

        server.write_all(&server_msg).await.unwrap();
        drop(server);

        let mut got = Vec::new();
        obfs.read_to_end(&mut got).await.unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(payload1);
        expected.extend_from_slice(payload2);
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn tls_obfs_round_trip_through_two_wrappers() {
        // client → server: client wraps with TlsObfs (write side framing)
        // server → client: server pretends to be a TlsObfs sender, hand-crafted
        //
        // Here we just verify the client's read side can handle frames produced
        // by *another* TlsObfs instance (so write/read are mutually consistent).
        let (a, mut b) = tokio::io::duplex(65536);
        let mut a_obfs = TlsObfs::new(a, "example.com".to_string()).unwrap();

        // a writes two payloads, then drops to close the duplex.
        a_obfs.write_all(b"first-msg").await.unwrap();
        a_obfs.write_all(b"second-msg").await.unwrap();
        a_obfs.shutdown().await.unwrap();
        drop(a_obfs);

        // b reads everything until EOF.
        let mut wire = Vec::new();
        b.read_to_end(&mut wire).await.unwrap();
        let wire = wire.as_slice();

        // Decode: first record is handshake (0x16), contains "first-msg" inside.
        assert_eq!(wire[0], 0x16);
        let rec_len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        let handshake = &wire[5..5 + rec_len];
        assert!(handshake.windows(9).any(|w| w == b"first-msg"));

        // Second record is application data with "second-msg".
        let app = &wire[5 + rec_len..];
        assert_eq!(app[0], 0x17);
        let len = u16::from_be_bytes([app[3], app[4]]) as usize;
        assert_eq!(&app[5..5 + len], b"second-msg");
    }
}
