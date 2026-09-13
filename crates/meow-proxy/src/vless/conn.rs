//! `VlessConn` — TCP passthrough connection wrapping a transport-layer stream.
//!
//! After construction (`new().await`), the VLESS request header has been sent and
//! the VLESS response header has been read and validated.  Subsequent `AsyncRead`
//! and `AsyncWrite` calls pass through to the underlying stream directly.
//!
//! `VlessPacketConn` is the UDP-over-TCP variant.  Each datagram is framed with
//! a 2-byte big-endian length prefix (standard VLESS UDP encoding).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{BufMut, Bytes, BytesMut};
use meow_common::{MeowError, ProxyConn, ProxyPacketConn, Result};
use meow_transport::Stream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

#[cfg(feature = "mux")]
use super::header::encode_mux_request;
use super::header::{encode_request, Cmd, VlessAddr};

// ─── VlessConn ────────────────────────────────────────────────────────────────

/// A VLESS TCP connection — request header sent, response header consumed lazily.
///
/// The response header is read on the first `poll_read` call, not during
/// construction. This matches upstream xray-core behavior where the server
/// only sends the response after connecting to the destination.
pub struct VlessConn {
    pub(crate) inner: Box<dyn Stream>,
    /// `true` until the 2-byte response header has been consumed.
    pub(crate) response_pending: bool,
    /// Partial response-header read progress.  Cancel-safe: a Pending
    /// between the two header bytes must not lose the byte already
    /// consumed (a local buffer would shift the whole stream by one byte).
    pub(crate) response_buf: [u8; 2],
    pub(crate) response_pos: usize,
    /// Scratch buffer for the response addon bytes (usually empty).
    pub(crate) response_addon: Vec<u8>,
    /// Pre-encoded request header, written ahead of the first payload.
    /// `Some` only for deferred-header connections (Vision): the request
    /// must ride inside the first Vision-padded record, matching
    /// mihomo/xray, so it is emitted on the first write instead of during
    /// construction.
    pub(crate) header_pending: Option<Bytes>,
    /// Set once the deferred header has reached the inner stream and cleared
    /// after the next flush.  A read-first protocol must flush the request
    /// before waiting for the server response.
    pub(crate) header_needs_flush: bool,
}

impl VlessConn {
    /// Establish a VLESS connection:
    /// 1. Write the request header.
    /// 2. Return immediately — response header is read lazily on first read.
    pub async fn new(
        mut stream: Box<dyn Stream>,
        uuid_bytes: &[u8; 16],
        flow: Option<&str>,
        cmd: Cmd,
        dst_port: u16,
        addr: &VlessAddr,
    ) -> Result<Self> {
        // Write the VLESS request header.
        let mut buf = BytesMut::new();
        encode_request(&mut buf, uuid_bytes, flow, cmd, dst_port, addr);
        tracing::debug!("VLESS: writing {} byte request header", buf.len());
        stream.write_all(&buf).await.map_err(MeowError::Io)?;
        stream.flush().await.map_err(MeowError::Io)?;
        tracing::debug!("VLESS: request header sent, response will be read lazily");

        Ok(Self {
            inner: stream,
            response_pending: true,
            response_buf: [0; 2],
            response_pos: 0,
            response_addon: Vec::new(),
            header_pending: None,
            header_needs_flush: false,
        })
    }

    /// Like [`Self::new`], but defers the request header to the first
    /// write so a wrapping Vision layer can pad it together with the first
    /// payload (xray expects the request inside the first Vision record).
    #[cfg(any(feature = "mux", feature = "vless-vision"))]
    pub async fn new_deferred(
        stream: Box<dyn Stream>,
        uuid_bytes: &[u8; 16],
        flow: Option<&str>,
        cmd: Cmd,
        dst_port: u16,
        addr: &VlessAddr,
    ) -> Result<Self> {
        let mut buf = BytesMut::new();
        encode_request(&mut buf, uuid_bytes, flow, cmd, dst_port, addr);
        Ok(Self {
            inner: stream,
            response_pending: true,
            response_buf: [0; 2],
            response_pos: 0,
            response_addon: Vec::new(),
            header_pending: Some(buf.freeze()),
            header_needs_flush: false,
        })
    }

    /// Establish a VLESS Mux.Cool session connection: the request header
    /// carries `Cmd::Mux` (0x03) and no address — the per-stream targets
    /// ride Mux.Cool frames.  The response header is consumed lazily on the
    /// first read, exactly like `Self::new`: the server still answers
    /// `[version][addon_length]` before the first mux frame.
    ///
    /// Used by the Mux.Cool session dialer
    /// (`VlessAdapter::with_mux` with `protocol: muxcool`).
    #[cfg(feature = "mux")]
    pub async fn new_mux(
        mut stream: Box<dyn Stream>,
        uuid_bytes: &[u8; 16],
        flow: Option<&str>,
    ) -> Result<Self> {
        let mut buf = BytesMut::new();
        encode_mux_request(&mut buf, uuid_bytes, flow);
        stream.write_all(&buf).await.map_err(MeowError::Io)?;
        stream.flush().await.map_err(MeowError::Io)?;
        Ok(Self {
            inner: stream,
            response_pending: true,
            response_buf: [0; 2],
            response_pos: 0,
            response_addon: Vec::new(),
            header_pending: None,
            header_needs_flush: false,
        })
    }

    /// Deferred variant of `Self::new_mux` for Vision: the Mux request
    /// header rides inside the first Vision record together with the first
    /// Mux.Cool frame (xray expects the request inside the first record).
    #[cfg(feature = "mux")]
    pub async fn new_mux_deferred(
        stream: Box<dyn Stream>,
        uuid_bytes: &[u8; 16],
        flow: Option<&str>,
    ) -> Result<Self> {
        let mut buf = BytesMut::new();
        encode_mux_request(&mut buf, uuid_bytes, flow);
        Ok(Self {
            inner: stream,
            response_pending: true,
            response_buf: [0; 2],
            response_pos: 0,
            response_addon: Vec::new(),
            header_pending: Some(buf.freeze()),
            header_needs_flush: false,
        })
    }

    /// Write a deferred request header before the caller's first payload.
    /// Header-only progress may continue inside one poll; payload progress is
    /// reported immediately so `AsyncWrite` never returns `Pending` or
    /// `Ok(0)` after consuming caller bytes.
    fn poll_write_deferred(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let Some(header) = self.header_pending.take() else {
                return Pin::new(&mut *self.inner).poll_write(cx, buf);
            };
            let header_len = header.len();
            let mut combined = BytesMut::with_capacity(header_len + buf.len());
            combined.extend_from_slice(&header);
            combined.extend_from_slice(buf);
            match Pin::new(&mut *self.inner).poll_write(cx, &combined) {
                Poll::Pending => {
                    self.header_pending = Some(header);
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    self.header_pending = Some(header);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vless: failed to write deferred request header",
                    )));
                }
                Poll::Ready(Ok(written)) if written < header_len => {
                    self.header_pending = Some(header.slice(written..));
                }
                Poll::Ready(Ok(written)) => {
                    self.header_needs_flush = true;
                    let payload_written = written - header_len;
                    if payload_written > 0 || buf.is_empty() {
                        return Poll::Ready(Ok(payload_written));
                    }
                }
            }
        }
    }

    /// Ensure a deferred request is sent and flushed before reading or
    /// shutting down.  This is the server-first path used by SMTP, IMAP,
    /// MySQL and similar protocols that do not write application data first.
    fn poll_flush_deferred_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.header_pending.is_some() {
            let written = ready!(self.poll_write_deferred(cx, &[]))?;
            debug_assert_eq!(written, 0);
        }
        if self.header_needs_flush {
            ready!(Pin::new(&mut *self.inner).poll_flush(cx))?;
            self.header_needs_flush = false;
        }
        Poll::Ready(Ok(()))
    }

    // Called only from the Vision wrapper (vless-vision feature).
    #[cfg_attr(not(feature = "vless-vision"), allow(dead_code))]
    pub(crate) fn enable_raw_read_passthrough(&mut self) -> bool {
        meow_transport::enable_raw_read_passthrough(&mut *self.inner)
    }

    #[cfg_attr(not(feature = "vless-vision"), allow(dead_code))]
    pub(crate) fn enable_raw_write_passthrough(&mut self) -> bool {
        meow_transport::enable_raw_write_passthrough(&mut *self.inner)
    }
}

// ─── AsyncRead / AsyncWrite pass-through ──────────────────────────────────────

impl AsyncRead for VlessConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Lazily consume the response header on first read.  Progress lives
        // in self (response_buf/response_pos): a Pending between the two
        // header bytes must keep the byte already consumed — a local buffer
        // would lose it and shift the whole stream by one byte.
        let this = &mut *self;
        ready!(this.poll_flush_deferred_header(cx))?;
        if this.response_pending {
            while this.response_pos < 2 {
                let pos = this.response_pos;
                let mut tmp = ReadBuf::new(&mut this.response_buf[pos..]);
                match Pin::new(&mut *this.inner).poll_read(cx, &mut tmp) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "vless: server closed before response header",
                            )));
                        }
                        this.response_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let version = this.response_buf[0];
            let addon_length = this.response_buf[1] as usize;
            if version != 0x00 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("vless: version mismatch: expected 0x00, got {version:#04x}"),
                )));
            }
            // Discard addon bytes if any — also cancel-safe: progress
            // counts against the persistent response_pos, and the scratch
            // buffer survives Pending.
            if addon_length > 0 {
                if this.response_addon.len() != addon_length {
                    this.response_addon = vec![0u8; addon_length];
                }
                while this.response_pos - 2 < addon_length {
                    let pos = this.response_pos - 2;
                    let mut tmp = ReadBuf::new(&mut this.response_addon[pos..]);
                    match Pin::new(&mut *this.inner).poll_read(cx, &mut tmp) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "vless: EOF during addon discard",
                                )));
                            }
                            this.response_pos += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
            this.response_pending = false;
            this.response_addon = Vec::new();
            tracing::debug!("VLESS: response header consumed lazily");
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.poll_write_deferred(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_deferred_header(cx))?;
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_deferred_header(cx))?;
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl Unpin for VlessConn {}

impl ProxyConn for VlessConn {}

// ─── VlessPacketConn (UDP-over-TCP) ──────────────────────────────────────────

/// A VLESS UDP connection over TCP.
///
/// Each datagram is framed as `u16_be(length) + data`.  The VLESS request
/// header (cmd=0x02) is sent on construction; the response header is
/// consumed **lazily** on the first read — xray/sing-vmess only write it
/// together with the first reply datagram, so eager consumption during
/// construction would deadlock (server waits for the first datagram before
/// answering, client waits for the answer before sending it).
///
/// The stream is split into independent read/write halves, each behind its
/// own `Mutex`, so a `read_packet` parked waiting for a server datagram never
/// blocks `write_packet` on the same connection (issue #278). The tunnel
/// drives the two directions from separate tasks; with a single stream-wide
/// lock any flow needing interleaved sends while a recv is pending (QUIC,
/// WireGuard, games) stalled after the first packet.
///
/// The read side cannot desync: `VlessUdpReader` owns its progress. The
/// write side can — a `write_packet` future dropped mid-`write_all` has a
/// frame prefix on the wire and the peer parses the next frame's header as
/// payload — so an incomplete write poisons the conn and every later op
/// fails fast (issue #514).
pub struct VlessPacketConn {
    reader: tokio::sync::Mutex<VlessUdpReader>,
    writer: tokio::sync::Mutex<tokio::io::WriteHalf<Box<dyn Stream>>>,
    poisoned: std::sync::atomic::AtomicBool,
}

/// Cancel-safe UDP reader.  The response header, the per-datagram length
/// prefix and the payload all persist their read progress across dropped
/// `read_packet` futures — a lost half-read would desynchronise the
/// UDP-over-TCP framing forever (callers may still cancel a read by
/// dropping the future, e.g. task abort).
struct VlessUdpReader {
    stream: tokio::io::ReadHalf<Box<dyn Stream>>,
    /// VLESS response header `[version][addon_length]`; `hdr_pos < 2`
    /// means the response phase is still active.
    hdr: [u8; 2],
    hdr_pos: usize,
    /// True once the response header (and any addon bytes) were consumed.
    header_done: bool,
    /// Per-datagram length prefix, big-endian.
    len: [u8; 2],
    len_pos: usize,
    /// Datagram payload (or the response addon bytes mid-discard).
    payload: Vec<u8>,
    payload_pos: usize,
}

impl VlessUdpReader {
    fn new(stream: tokio::io::ReadHalf<Box<dyn Stream>>) -> Self {
        Self {
            stream,
            hdr: [0; 2],
            hdr_pos: 0,
            header_done: false,
            len: [0; 2],
            len_pos: 0,
            payload: Vec::new(),
            payload_pos: 0,
        }
    }

    /// Reset the per-datagram state for the next packet (the response
    /// header is read exactly once and stays consumed).
    fn reset_datagram(&mut self) {
        self.len_pos = 0;
        self.payload.clear();
        self.payload_pos = 0;
    }

    async fn read_packet(&mut self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr)> {
        use tokio::io::AsyncReadExt;
        // Phase 1: response header [version][addon_length], consumed
        // lazily on the first read (it rides with the first reply
        // datagram).  Progress persists so a cancelled read resumes
        // instead of shifting the stream by the lost bytes.
        if !self.header_done {
            while self.hdr_pos < self.hdr.len() {
                let n = self
                    .stream
                    .read(&mut self.hdr[self.hdr_pos..])
                    .await
                    .map_err(MeowError::Io)?;
                if n == 0 {
                    return Err(MeowError::Proxy(
                        "vless: server closed after header — check UUID and server config".into(),
                    ));
                }
                self.hdr_pos += n;
            }
            let version = self.hdr[0];
            let addon_length = self.hdr[1] as usize;
            if version != 0x00 {
                // upstream: closes silently. NOT silent — we surface the reason.
                tracing::warn!(
                    version = %format!("{:#04x}", version),
                    "vless: response version mismatch (expected 0x00) — \
                     check UUID and whether a TLS layer is required"
                );
                return Err(MeowError::Proxy(format!(
                    "vless: version mismatch: expected 0x00, got {version:#04x}"
                )));
            }
            if addon_length > 0 {
                // Discard the addon bytes (UDP sends none; keep the same
                // tolerance as the TCP path) with persistent progress.
                // Only reset when the size changes: a cancelled
                // `read_packet` future re-enters here with `header_done`
                // still false, and resetting `payload_pos` to 0 would
                // re-read `addon_length` bytes, eating the head of the
                // first datagram and desyncing the UDP framing.
                if self.payload.len() != addon_length {
                    self.payload.resize(addon_length, 0);
                    self.payload_pos = 0;
                }
                while self.payload_pos < self.payload.len() {
                    let n = self
                        .stream
                        .read(&mut self.payload[self.payload_pos..])
                        .await
                        .map_err(MeowError::Io)?;
                    if n == 0 {
                        return Err(MeowError::Proxy(
                            "vless: server closed mid response-header addon".into(),
                        ));
                    }
                    self.payload_pos += n;
                }
                self.payload.clear();
                self.payload_pos = 0;
            }
            self.header_done = true;
        }
        // Phase 2: per-datagram `u16_be(len)`.
        while self.len_pos < self.len.len() {
            let n = self
                .stream
                .read(&mut self.len[self.len_pos..])
                .await
                .map_err(MeowError::Io)?;
            if n == 0 {
                return Err(MeowError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "vless: EOF while reading UDP packet length",
                )));
            }
            self.len_pos += n;
        }
        // Phase 3: payload (sized once per datagram; partial progress
        // survives cancellation).
        if self.payload.is_empty() && self.payload_pos == 0 {
            self.payload
                .resize(u16::from_be_bytes(self.len) as usize, 0);
        }
        while self.payload_pos < self.payload.len() {
            let n = self
                .stream
                .read(&mut self.payload[self.payload_pos..])
                .await
                .map_err(MeowError::Io)?;
            if n == 0 {
                return Err(MeowError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "vless: EOF while reading UDP packet payload",
                )));
            }
            self.payload_pos += n;
        }
        let packet_len = self.payload.len();
        if packet_len > buf.len() {
            // The oversized payload was fully drained into the internal
            // buffer, so the stream framing stays aligned for the next
            // read — surface the error only after the drain.
            self.reset_datagram();
            return Err(MeowError::Proxy(format!(
                "vless: UDP packet ({packet_len} bytes) exceeds read buffer ({} bytes)",
                buf.len()
            )));
        }
        buf[..packet_len].copy_from_slice(&self.payload);
        self.reset_datagram();
        // Return a placeholder source address (connection-oriented
        // UDP-over-TCP has no per-datagram source addr).
        let placeholder: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        Ok((packet_len, placeholder))
    }
}

impl VlessPacketConn {
    /// Create a UDP-over-TCP VLESS connection.
    pub async fn new(
        mut stream: Box<dyn Stream>,
        uuid_bytes: &[u8; 16],
        dst_port: u16,
        addr: &VlessAddr,
    ) -> Result<Self> {
        // Write request header with Cmd::Udp.
        let mut buf = BytesMut::new();
        encode_request(&mut buf, uuid_bytes, None, Cmd::Udp, dst_port, addr);
        stream.write_all(&buf).await.map_err(MeowError::Io)?;
        stream.flush().await.map_err(MeowError::Io)?;

        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: tokio::sync::Mutex::new(VlessUdpReader::new(reader)),
            writer: tokio::sync::Mutex::new(writer),
            poisoned: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

#[async_trait::async_trait]
impl ProxyPacketConn for VlessPacketConn {
    /// Write a UDP packet as `u16_be(len) + data`.
    async fn write_packet(&self, buf: &[u8], _addr: &std::net::SocketAddr) -> Result<usize> {
        crate::check_not_desynced(&self.poisoned)?;
        let mut writer = self.writer.lock().await;
        // Re-check after the lock: a write parked behind one cancelled
        // mid-frame must not append after the torn frame.
        crate::check_not_desynced(&self.poisoned)?;
        let mut frame = BytesMut::with_capacity(2 + buf.len());
        frame.put_u16(buf.len() as u16);
        frame.put_slice(buf);
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);
        writer.write_all(&frame).await.map_err(MeowError::Io)?;
        // Fully buffered once `write_all` returns; a cancelled `flush`
        // cannot tear framing, so it runs unguarded.
        guard.complete = true;
        writer.flush().await.map_err(MeowError::Io)?;
        Ok(buf.len())
    }

    /// Read a UDP packet: consume `u16_be(len)` then `len` bytes.  The
    /// VLESS response header is consumed lazily on the first read (it rides
    /// with the first reply datagram).  All progress is persistent, so a
    /// cancelled future resumes from where it stopped.
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr)> {
        // No post-lock re-check needed: this reader never loses bytes, so
        // the poison can only come from the write side — and a conn with a
        // torn uplink is dead regardless of what the peer still sends.
        crate::check_not_desynced(&self.poisoned)?;
        let mut reader = self.reader.lock().await;
        reader.read_packet(buf).await
    }

    fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Err(MeowError::NotSupported(
            "VlessPacketConn has no local UDP addr (UDP-over-TCP)".into(),
        ))
    }

    fn close(&self) -> Result<()> {
        // Stream closes when VlessPacketConn is dropped.
        Ok(())
    }
}

// ─── Unit tests (§F) ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    struct ChunkedStream {
        inner: tokio::io::DuplexStream,
        max_write: usize,
    }

    impl AsyncRead for ChunkedStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ChunkedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let count = buf.len().min(this.max_write);
            Pin::new(&mut this.inner).poll_write(cx, &buf[..count])
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// Test UUID: b831381d-6324-4d53-ad4f-8cda48b30811
    const TEST_UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    /// Spawn a minimal VLESS mock server:
    /// 1. Reads (and ignores) `header_len` bytes (the request header).
    /// 2. Sends [0x00, 0x00] (valid response header).
    /// 3. Echoes all subsequent bytes.
    ///
    /// Returns `(server_stream, header_bytes_rx)` — `header_bytes_rx` yields
    /// the raw request-header bytes the server received.
    async fn spawn_mock(
        header_len: usize,
        server_side: Box<dyn Stream>,
    ) -> tokio::sync::oneshot::Receiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut s = server_side;
            let mut req_hdr = vec![0u8; header_len];
            s.read_exact(&mut req_hdr).await.unwrap();
            let _ = tx.send(req_hdr);
            // Send valid response header.
            s.write_all(&[0x00, 0x00]).await.unwrap();
            // Echo payload.
            let mut buf = [0u8; 4096];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        rx
    }

    // ─── F1: request header written on connect ────────────────────────────────

    #[tokio::test]
    async fn vless_conn_writes_request_header_on_connect() {
        // The minimum VLESS header for IPv4 is:
        // version(1) + uuid(16) + addon_length(1) + cmd(1) + port(2) + addr_type(1) + ipv4(4) = 26
        let (client, server) = duplex(1024);
        let hdr_rx = spawn_mock(26, Box::new(server)).await;

        let conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("VlessConn::new");

        let hdr = hdr_rx.await.expect("header bytes");
        drop(conn);

        // version must be 0x00
        assert_eq!(hdr[0], 0x00, "version byte must be 0x00");
        // uuid must match
        assert_eq!(&hdr[1..17], &TEST_UUID, "uuid must match");
    }

    #[cfg(any(feature = "mux", feature = "vless-vision"))]
    #[tokio::test]
    async fn deferred_header_handles_one_byte_partial_writes() {
        let (client, mut server) = duplex(1024);
        tokio::spawn(async move {
            let mut request = vec![0u8; 26 + 4];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[26..], b"ping");
            server.write_all(&[0x00, 0x00, b'!']).await.unwrap();
        });

        let mut conn = VlessConn::new_deferred(
            Box::new(ChunkedStream {
                inner: client,
                max_write: 1,
            }),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .unwrap();
        conn.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 1];
        conn.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [b'!']);
    }

    #[cfg(any(feature = "mux", feature = "vless-vision"))]
    #[tokio::test]
    async fn deferred_header_is_flushed_before_server_first_read() {
        let (client, mut server) = duplex(1024);
        tokio::spawn(async move {
            let mut request = vec![0u8; 26];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(&[0x00, 0x00]).await.unwrap();
            server.write_all(b"banner").await.unwrap();
        });

        let mut conn = VlessConn::new_deferred(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            25,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .unwrap();
        let mut banner = [0u8; 6];
        conn.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"banner");
    }

    // ─── F2: payload round-trip ───────────────────────────────────────────────

    #[tokio::test]
    async fn vless_conn_tcp_payload_round_trips() {
        use tokio::io::AsyncReadExt;
        let (client, server) = duplex(4096);
        spawn_mock(26, Box::new(server)).await;

        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("VlessConn::new");

        let payload = vec![0xAB; 1024];
        conn.write_all(&payload).await.unwrap();

        let mut received = vec![0u8; 1024];
        conn.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload, "round-trip payload must match");
    }

    // ─── F3: response header discarded ───────────────────────────────────────

    #[tokio::test]
    async fn vless_conn_reads_and_discards_response_header() {
        use tokio::io::AsyncReadExt;
        let (client, server) = duplex(1024);
        // The mock sends [0x00, 0x00] then a distinguishable byte pattern.
        tokio::spawn(async move {
            let mut s = server;
            // Consume the request header.
            let mut hdr = vec![0u8; 26];
            s.read_exact(&mut hdr).await.unwrap();
            // Send response header + payload.
            s.write_all(&[0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF])
                .await
                .unwrap();
        });

        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("VlessConn::new");

        // First read must yield payload bytes (0xDE 0xAD 0xBE 0xEF), not response header.
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            buf,
            [0xDE, 0xAD, 0xBE, 0xEF],
            "response header must be discarded"
        );
    }

    // ─── F4: nonzero addon_length in response ─────────────────────────────────

    /// Mock sends [0x00, 0x03, 0xAA, 0xBB, 0xCC] (version=0, addon=3 bytes).
    /// VlessConn must discard the 3 addon bytes and expose only subsequent payload.
    #[tokio::test]
    async fn vless_conn_response_with_nonzero_addon_length() {
        use tokio::io::AsyncReadExt;
        let (client, server) = duplex(1024);
        tokio::spawn(async move {
            let mut s = server;
            let mut hdr = vec![0u8; 26];
            s.read_exact(&mut hdr).await.unwrap();
            // Response: version=0, addon_length=3, 3 addon bytes, then payload.
            s.write_all(&[0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x42])
                .await
                .unwrap();
        });

        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("VlessConn::new");

        let mut buf = [0u8; 1];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            buf[0], 0x42,
            "addon bytes must be discarded; next byte is payload 0x42"
        );
    }

    // ─── F5: version mismatch → ConnError ────────────────────────────────────

    #[tokio::test]
    async fn vless_conn_version_mismatch_tears_down() {
        let (client, server) = duplex(1024);
        tokio::spawn(async move {
            let mut s = server;
            let mut hdr = vec![0u8; 26];
            let _ = s.read_exact(&mut hdr).await;
            s.write_all(&[0x01, 0x00]).await.unwrap();
        });

        // VlessConn::new succeeds (response is read lazily).
        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("new succeeds with lazy response");

        // First read triggers lazy response consumption and must error.
        let mut buf = [0u8; 1];
        let result = tokio::io::AsyncReadExt::read(&mut conn, &mut buf).await;
        assert!(result.is_err(), "version mismatch must return Err on read");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("version") || msg.contains("mismatch"),
            "error must mention version mismatch, got: {msg}"
        );
    }

    // ─── F6: server EOF after header ─────────────────────────────────────────

    #[tokio::test]
    async fn vless_conn_server_eof_after_header() {
        let (client, server) = duplex(1024);
        tokio::spawn(async move {
            let mut s = server;
            let mut hdr = vec![0u8; 26];
            let _ = s.read_exact(&mut hdr).await;
            // Close immediately (no response).
            drop(s);
        });

        // VlessConn::new succeeds (response is read lazily).
        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("new succeeds with lazy response");

        // First read triggers lazy response consumption and must error on EOF.
        let mut buf = [0u8; 1];
        let result = tokio::io::AsyncReadExt::read(&mut conn, &mut buf).await;
        assert!(result.is_err(), "EOF after header must return Err on read");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("closed")
                || msg.contains("eof")
                || msg.contains("EOF")
                || msg.contains("server")
                || msg.contains("Eof"),
            "error must give diagnostic, got: {msg}"
        );
    }

    // ─── Issue #278: parked read must not starve writes ───────────────────────

    /// Regression for issue #278: with the whole stream behind one async
    /// mutex, a `read_packet` parked waiting for a server datagram held the
    /// lock and every `write_packet` deadlocked, stalling any flow that
    /// interleaves sends with a pending recv (QUIC, WireGuard, games).
    #[tokio::test]
    async fn vless_packet_conn_write_proceeds_while_read_parked() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::time::timeout;

        let (client, server) = duplex(4096);
        // Mock server: consume the request header, ack, then echo one framed
        // datagram once it arrives.
        tokio::spawn(async move {
            let mut s = server;
            let mut hdr = vec![0u8; 26];
            s.read_exact(&mut hdr).await.unwrap();
            s.write_all(&[0x00, 0x00]).await.unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0u8; n];
            s.read_exact(&mut payload).await.unwrap();
            s.write_all(&len).await.unwrap();
            s.write_all(&payload).await.unwrap();
        });

        let conn = Arc::new(
            VlessPacketConn::new(
                Box::new(client),
                &TEST_UUID,
                53,
                &VlessAddr::Ipv4([8, 8, 8, 8]),
            )
            .await
            .expect("VlessPacketConn::new"),
        );

        // Park a reader while no server datagram is available.
        let reader_conn = Arc::clone(&conn);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            reader_conn
                .read_packet(&mut buf)
                .await
                .map(|(n, _)| buf[..n].to_vec())
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Old design: deadlocked here (reader held the stream lock).
        let dst = "8.8.8.8:53".parse().unwrap();
        timeout(Duration::from_secs(5), conn.write_packet(b"ping", &dst))
            .await
            .expect("write_packet must not deadlock while a read is parked")
            .expect("write_packet");

        let echoed = timeout(Duration::from_secs(5), reader)
            .await
            .expect("parked reader timed out")
            .expect("reader task")
            .expect("read_packet");
        assert_eq!(echoed, b"ping");
    }

    // ─── F8b: lazy response header (xray/sing-vmess semantics) ───────────────

    /// The server answers the VLESS response header only together with the
    /// first reply datagram.  `VlessPacketConn::new` must return without
    /// waiting for it (eager consumption deadlocks: the server waits for the
    /// first datagram before answering, the client waits for the answer
    /// before sending that datagram).
    #[tokio::test]
    async fn vless_packet_conn_handles_lazy_response_header() {
        use tokio::io::AsyncWriteExt;

        let (client, server) = duplex(4096);
        tokio::spawn(async move {
            let mut s = server;
            let mut hdr = vec![0u8; 26];
            s.read_exact(&mut hdr).await.unwrap();
            // NO response header yet — wait for the first datagram frame.
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0u8; n];
            s.read_exact(&mut payload).await.unwrap();
            // First server write = response header + echoed datagram frame.
            s.write_all(&[0x00, 0x00]).await.unwrap();
            s.write_all(&len).await.unwrap();
            s.write_all(&payload).await.unwrap();
        });

        let conn = VlessPacketConn::new(
            Box::new(client),
            &TEST_UUID,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        )
        .await
        .expect("VlessPacketConn::new");

        let dst = "8.8.8.8:53".parse().unwrap();
        conn.write_packet(b"ping", &dst).await.unwrap();
        let mut buf = [0u8; 8];
        let (n, _src) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

    // ─── F7: UDP cmd byte is 0x02 ─────────────────────────────────────────────

    /// Guards against copy-paste of the TCP path without flipping the cmd byte.
    #[tokio::test]
    async fn vless_packet_conn_cmd_byte_is_0x02() {
        let (client, server) = duplex(1024);
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            let mut s = server;
            // Capture first 26 bytes (UDP header = same size as basic IPv4 TCP header).
            let mut hdr = vec![0u8; 26];
            s.read_exact(&mut hdr).await.unwrap();
            let _ = tx.send(hdr);
            s.write_all(&[0x00, 0x00]).await.unwrap();
            // Drain.
            let mut buf = [0u8; 64];
            while s.read(&mut buf).await.unwrap_or(0) > 0 {}
        });

        let _conn = VlessPacketConn::new(
            Box::new(client),
            &TEST_UUID,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        )
        .await
        .expect("VlessPacketConn::new");

        let hdr = rx.await.expect("header");
        // cmd byte at offset 18 (version=1 + uuid=16 + addon_length=1)
        assert_eq!(hdr[18], 0x02, "UDP cmd must be 0x02, not 0x01");
    }

    // ─── F8: Mux request (CommandMux=0x03) omits port/address ─────────────────

    /// The Mux.Cool session request is exactly
    /// `version(1) + uuid(16) + addon_length(1) + cmd(1)` = 19 bytes — no
    /// port or address follow (xray encoding.go::EncodeRequestHeader skips
    /// them for `RequestCommandMux`; sing-vmess skips the parse likewise).
    #[cfg(feature = "mux")]
    #[tokio::test]
    async fn vless_mux_request_omits_port_and_address() {
        let (client, server) = duplex(1024);
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            let mut s = server;
            let mut hdr = vec![0u8; 19];
            s.read_exact(&mut hdr).await.unwrap();
            let _ = tx.send(hdr);
            s.write_all(&[0x00, 0x00]).await.unwrap();
            // Drain anything further (there must be nothing after 19 bytes
            // until the client's first mux frame — covered by mux tests).
            let mut buf = [0u8; 64];
            while s.read(&mut buf).await.unwrap_or(0) > 0 {}
        });

        let _conn = VlessConn::new_mux(Box::new(client), &TEST_UUID, None)
            .await
            .expect("VlessConn::new_mux");

        let hdr = rx.await.expect("header");
        assert_eq!(hdr.len(), 19, "mux request must be exactly 19 bytes");
        assert_eq!(hdr[0], 0x00, "version must be 0x00");
        assert_eq!(&hdr[1..17], &TEST_UUID, "uuid must match");
        assert_eq!(hdr[17], 0x00, "no flow addon");
        assert_eq!(hdr[18], 0x03, "command must be CommandMux (0x03)");
    }

    // ─── F6: UDP reader cancellation safety ─────────────────────────────────

    /// A read cancelled halfway through the response header must resume
    /// instead of shifting the stream: the next read sees the full
    /// datagram.
    #[tokio::test]
    async fn udp_read_survives_cancellation_mid_response() {
        let (client, mut server) = duplex(1024);
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            let mut request = vec![0u8; 26];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(&[0x00]).await.unwrap(); // first header byte only
            let _ = go_rx.await;
            server
                .write_all(&[0x00, 0x00, 0x04, b'p', b'o', b'n', b'g'])
                .await
                .unwrap();
        });
        let conn = VlessPacketConn::new(
            Box::new(client),
            &TEST_UUID,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                conn.read_packet(&mut buf)
            )
            .await
            .is_err(),
            "the read must wait for the second response byte"
        );
        go_tx.send(()).unwrap();
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            conn.read_packet(&mut buf),
        )
        .await
        .expect("the resumed read must complete")
        .unwrap();
        assert_eq!(&buf[..n], b"pong");
        server_task.await.unwrap();
    }

    /// A read cancelled halfway through a datagram payload must resume
    /// the same datagram.
    #[tokio::test]
    async fn udp_read_survives_cancellation_mid_payload() {
        let (client, mut server) = duplex(1024);
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            let mut request = vec![0u8; 26];
            server.read_exact(&mut request).await.unwrap();
            // Full response + length prefix + half the payload.
            server
                .write_all(&[0x00, 0x00, 0x00, 0x04, b'p', b'o'])
                .await
                .unwrap();
            let _ = go_rx.await;
            server.write_all(b"ng").await.unwrap();
        });
        let conn = VlessPacketConn::new(
            Box::new(client),
            &TEST_UUID,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                conn.read_packet(&mut buf)
            )
            .await
            .is_err(),
            "the read must wait for the rest of the payload"
        );
        go_tx.send(()).unwrap();
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            conn.read_packet(&mut buf),
        )
        .await
        .expect("the resumed read must complete")
        .unwrap();
        assert_eq!(&buf[..n], b"pong");
        server_task.await.unwrap();
    }

    /// Response version mismatch → hard error naming the problem (the
    /// shared decode_response behavior, now owned by the UDP reader).
    #[tokio::test]
    async fn udp_response_version_mismatch_errors() {
        let (client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut request = vec![0u8; 26];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(&[0x01, 0x00]).await.unwrap();
        });
        let conn = VlessPacketConn::new(
            Box::new(client),
            &TEST_UUID,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        let err = conn.read_packet(&mut buf).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("version mismatch"),
            "error must mention the version mismatch, got: {msg}"
        );
        server_task.await.unwrap();
    }

    /// Non-zero addon_length: the addon bytes are discarded and the next
    /// datagram reads aligned.
    #[tokio::test]
    async fn udp_response_addon_is_discarded() {
        let (client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut request = vec![0u8; 26];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[0x00, 0x02, 0xAA, 0xBB, 0x00, 0x04, b'p', b'o', b'n', b'g'])
                .await
                .unwrap();
        });
        let conn = VlessPacketConn::new(
            Box::new(client),
            &TEST_UUID,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
        server_task.await.unwrap();
    }

    /// A response truncated mid-header must error cleanly, not panic.
    #[tokio::test]
    async fn udp_truncated_response_errors() {
        let (client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut request = vec![0u8; 26];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(&[0x00]).await.unwrap();
            drop(server);
        });
        let conn = VlessPacketConn::new(
            Box::new(client),
            &TEST_UUID,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        assert!(conn.read_packet(&mut buf).await.is_err());
        server_task.await.unwrap();
    }

    /// Issue #514 review: the resumable reader makes cancelled READS safe,
    /// but a `write_packet` future dropped mid-`write_all` has already put
    /// a frame prefix on the wire — the peer parses the next frame's header
    /// as payload. The write path poisons the conn so every later op fails
    /// fast instead of feeding a desynced stream.
    #[tokio::test]
    async fn udp_cancelled_write_poisons_conn() {
        let (client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            // Consume the request header, then never read again so the
            // next datagram write pends mid-frame.
            let mut request = vec![0u8; 26];
            server.read_exact(&mut request).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let conn = VlessPacketConn::new(
            Box::new(client),
            &TEST_UUID,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        )
        .await
        .unwrap();
        let dst: std::net::SocketAddr = "9.9.9.9:53".parse().unwrap();

        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.write_packet(&[0xAA; 4096], &dst),
        )
        .await;
        assert!(cancelled.is_err(), "write must have timed out mid-frame");

        let err = conn.write_packet(b"x", &dst).await.unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "write after a cancelled write must fail fast, got {err:?}"
        );
        let mut buf = [0u8; 64];
        let err = conn.read_packet(&mut buf).await.unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "read on a write-poisoned conn must fail fast, got {err:?}"
        );
        server_task.abort();
    }
}
