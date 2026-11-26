//! Server-side XTLS Vision connection codec.
//!
//! The role split matters here: the client policy in `client.rs` is kept
//! interoperable with the existing outbound implementation, while this
//! server policy validates the inbound padding UUID, performs record-aligned
//! inner-TLS recognition, and only promises DIRECT when the transport can
//! actually switch that direction to raw TCP.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use meow_common::ProxyConn;
use meow_transport::Stream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::codec::{
    capped_padding_len, encode_padding_frame_with_padding_len, PaddingCommand, PaddingReadPhase,
    PaddingReader, TlsAppRecordTracker, COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT,
    COMMAND_PADDING_END, FRAME_CONTENT_CAP, PADDING_HEADER_LEN, PADDING_SCRATCH_LEN, UUID_LEN,
};
use super::filter::TlsInspector;

/// Inbound Vision stream shape.  TCP inner traffic may earn DIRECT; XUDP
/// frames share the same padding codec but must never become DIRECT evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionServerMode {
    Tcp,
    Xudp,
}

#[derive(Debug, Clone, Copy)]
struct PendingServerWrite {
    command: u8,
    end_padding_after_drain: bool,
}

const EMPTY_CONTROL_FRAME_BYTE_BUDGET: usize = 64 * 1024;

fn write_terminated_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "vision server: write side terminated after a failed DIRECT switch",
    )
}

/// Server-side Vision codec for one authenticated VLESS connection.
///
/// Construction starts after the VLESS request header has been consumed
/// from the already-decrypted outer stream.  The constant `00 00` response
/// header is prepended to the first downlink frame, never emitted as a
/// standalone ACK.
pub struct VisionServerConn {
    inner: Box<dyn Stream>,
    user_uuid: [u8; UUID_LEN],
    mode: VisionServerMode,
    reader: PaddingReader,
    inspector: TlsInspector,
    downlink_records: TlsAppRecordTracker,
    pad_scratch: [u8; PADDING_SCRATCH_LEN],
    write_padding: bool,
    write_sent_uuid: bool,
    response_pending: bool,
    write_frame: Vec<u8>,
    write_frame_pos: usize,
    pending_write: Option<PendingServerWrite>,
    raw_write_capable: bool,
    read_raw: bool,
    write_raw: bool,
    write_terminated: bool,
}

impl VisionServerConn {
    pub fn new(
        mut inner: Box<dyn Stream>,
        user_uuid: [u8; UUID_LEN],
        mode: VisionServerMode,
    ) -> Self {
        // Probe once up front: the server never promises DIRECT unless the
        // transport declared the raw write switch before any frame went out.
        let raw_write_capable = meow_transport::supports_raw_passthrough(&mut *inner);
        Self {
            inner,
            user_uuid,
            mode,
            reader: PaddingReader::new(),
            inspector: TlsInspector::new(),
            downlink_records: TlsAppRecordTracker::new(),
            pad_scratch: [0; PADDING_SCRATCH_LEN],
            write_padding: true,
            write_sent_uuid: false,
            response_pending: true,
            // The single reusable pending frame the spec budgets: worst case
            // is a 16 KiB content slice with a full 21-byte header (large
            // content is unpadded, short content totals under 1400 bytes
            // with padding), plus the two response bytes on the first frame.
            // Capacity never grows after construction.
            write_frame: Vec::with_capacity(2 + PADDING_HEADER_LEN + FRAME_CONTENT_CAP),
            write_frame_pos: 0,
            pending_write: None,
            raw_write_capable,
            read_raw: false,
            write_raw: false,
            write_terminated: false,
        }
    }

    pub fn read_switched_to_raw(&self) -> bool {
        self.read_raw
    }

    pub fn write_switched_to_raw(&self) -> bool {
        self.write_raw
    }

    pub fn padding_write_active(&self) -> bool {
        self.write_padding
    }

    fn inspect_uplink(&mut self, chunk: &[u8]) {
        // xray stops filtering a direction once it is raw; before that the
        // filter keeps running even after END, which the shared budget and
        // the conclusive-server-hello cut-off both rely on.
        if self.read_raw {
            return;
        }
        match self.mode {
            VisionServerMode::Tcp => self.inspector.observe_client_stream(chunk),
            VisionServerMode::Xudp => self.inspector.observe_opaque_packet(chunk),
        }
    }

    fn inspect_downlink(&mut self, chunk: &[u8]) -> bool {
        if self.write_raw {
            return false;
        }
        match self.mode {
            VisionServerMode::Tcp => {
                let serverhello_end = self.inspector.observe_server_stream(chunk);
                let start = if self.downlink_records.active() {
                    0
                } else {
                    let Some(start) = serverhello_end else {
                        return false;
                    };
                    self.downlink_records.activate();
                    start
                };
                if start > chunk.len() {
                    return false;
                }
                self.downlink_records.feed_batch(&chunk[start..])
            }
            VisionServerMode::Xudp => {
                self.inspector.observe_opaque_packet(chunk);
                false
            }
        }
    }

    fn drain_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_none() {
            return Poll::Ready(Ok(()));
        }

        while self.write_frame_pos < self.write_frame.len() {
            let written = {
                let frame = &self.write_frame[self.write_frame_pos..];
                Pin::new(&mut *self.inner).poll_write(cx, frame)
            };
            match written {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vision server: zero write during frame drain",
                    )));
                }
                Poll::Ready(Ok(n)) => self.write_frame_pos += n,
            }
        }

        let direct_frame = self
            .pending_write
            .as_ref()
            .is_some_and(|pending| pending.command == COMMAND_PADDING_DIRECT);
        if direct_frame {
            // AsyncWrite completion only proves that the frame entered the
            // outer TLS writer.  The raw switch happens after that writer's
            // flush boundary so no ciphertext record is still pending.
            match Pin::new(&mut *self.inner).poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }

        let pending = self
            .pending_write
            .take()
            .expect("pending presence checked above");
        self.write_frame.clear();
        self.write_frame_pos = 0;

        if pending.end_padding_after_drain {
            self.write_padding = false;
            // END/DIRECT permanently leave the framing path; release the one
            // reusable 16 KiB frame allocation instead of carrying it through
            // the raw-stream lifetime.
            self.write_frame = Vec::new();
            if pending.command == COMMAND_PADDING_DIRECT {
                // The DIRECT frame itself has now completely passed through
                // the outer TLS writer.  Only the next write may become raw;
                // failing here terminates the conn rather than retroactively
                // rewriting the promised DIRECT into END.
                if !meow_transport::enable_raw_write_passthrough(&mut *self.inner) {
                    self.write_terminated = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "vision server: DIRECT promised but transport cannot switch writes to raw",
                    )));
                }
                self.write_raw = true;
                tracing::debug!("XTLS Vision server direct write passthrough enabled");
            }
        }
        Poll::Ready(Ok(()))
    }

    fn append_frame_prefix(&mut self) {
        if self.response_pending {
            self.write_frame
                .extend_from_slice(&super::super::header::RESPONSE_HEADER);
            self.response_pending = false;
        }
    }

    fn begin_frame(
        &mut self,
        command: u8,
        content: &[u8],
        end_padding_after_drain: bool,
        force_long_padding: bool,
    ) {
        self.write_frame.clear();
        self.write_frame_pos = 0;
        self.append_frame_prefix();
        let long_padding = force_long_padding || self.inspector.is_tls();
        let padding_len = capped_padding_len(content.len(), long_padding);
        encode_padding_frame_with_padding_len(
            &mut self.write_frame,
            command,
            (!self.write_sent_uuid).then_some(&self.user_uuid),
            content,
            padding_len,
        );
        tracing::debug!(
            command,
            content_len = content.len(),
            padding_len,
            frame_len = self.write_frame.len(),
            "XTLS Vision server write padding"
        );
        self.write_sent_uuid = true;
        self.pending_write = Some(PendingServerWrite {
            command,
            end_padding_after_drain,
        });
    }

    /// Build one padded write frame from the head of `buf` and return the
    /// number of caller bytes ownership of which moved into the frame.  Once
    /// copied, those bytes belong to the connection; the caller is never
    /// charged for drain progress made after a later cancellation.
    fn prepare_write_frame(&mut self, buf: &[u8]) -> usize {
        debug_assert!(!buf.is_empty());

        let mut take = buf.len().min(FRAME_CONTENT_CAP);
        if self.downlink_records.active() && take < buf.len() {
            take = self.downlink_records.aligned_cut(buf, FRAME_CONTENT_CAP);
        }
        debug_assert!(take > 0);
        let final_batch_frame = take == buf.len();
        let content = &buf[..take];

        // Only the bytes actually owned by this frame feed the TLS inspectors
        // and the cross-write record tracker.  The not-yet-accepted remainder
        // is examined when a later write accepts it.
        let complete_record_boundary = self.inspect_downlink(content);

        let mut command = COMMAND_PADDING_CONTINUE;
        let mut end_after_drain = false;
        if final_batch_frame && complete_record_boundary && self.inspector.is_tls() {
            end_after_drain = true;
            if self.inspector.enable_xtls() && self.raw_write_capable {
                command = COMMAND_PADDING_DIRECT;
            } else {
                if self.inspector.enable_xtls() {
                    tracing::debug!("XTLS Vision server: transport cannot write raw, sending END");
                }
                command = COMMAND_PADDING_END;
            }
        } else if (!self.inspector.is_tls12_or_above() && self.inspector.packets_left() <= 1)
            || (self.inspector.is_tls12_or_above()
                && self.inspector.packets_left() == 0
                && !self.downlink_records.active())
        {
            // xray finishes one packet early for non-TLS traffic.  A
            // ServerHello-shaped stream that exhausts the same budget before
            // producing a record boundary is likewise inconclusive: it must
            // fall back to END rather than staying framed forever.
            command = COMMAND_PADDING_END;
            end_after_drain = true;
        }

        self.begin_frame(command, content, end_after_drain, false);
        take
    }

    fn build_camouflage_frame(&mut self) -> bool {
        if !self.write_padding || self.pending_write.is_some() || self.write_terminated {
            return false;
        }
        // xray's empty first-frame special case always uses long padding to
        // hide the VLESS header timing/shape, independent of IsTLS.
        self.begin_frame(COMMAND_PADDING_CONTINUE, &[], false, true);
        true
    }

    /// Emit one empty-content camouflage frame while padding is active.
    /// Normal server traffic never needs this; it exists for codec-level
    /// interoperability with peers and tests that exercise the xray form.
    pub async fn write_camouflage_frame(&mut self) -> io::Result<()> {
        if !self.build_camouflage_frame() {
            return Ok(());
        }
        futures::future::poll_fn(|cx| match self.drain_pending_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        })
        .await?;
        self.inner.flush().await
    }

    fn finish_inbound_frame(&mut self, command: PaddingCommand) -> io::Result<()> {
        match command {
            PaddingCommand::Continue | PaddingCommand::End => Ok(()),
            PaddingCommand::Direct => {
                if self.mode != VisionServerMode::Tcp || !self.inspector.enable_xtls() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vision server: inbound DIRECT without a validated TLS 1.3 inner stream",
                    ));
                }
                if !meow_transport::enable_raw_read_passthrough(&mut *self.inner) {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "vision server: client sent DIRECT but transport cannot switch reads to raw",
                    ));
                }
                self.read_raw = true;
                tracing::debug!("XTLS Vision server direct read passthrough enabled");
                Ok(())
            }
        }
    }
}

impl AsyncRead for VisionServerConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let mut empty_control_frames = 0usize;
        let mut control_frame_bytes = 0usize;
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            match this.reader.phase() {
                PaddingReadPhase::Eof => return Poll::Ready(Ok(())),
                PaddingReadPhase::Through => {
                    let filled_before = buf.filled().len();
                    let poll = Pin::new(&mut *this.inner).poll_read(cx, buf);
                    if matches!(poll, Poll::Ready(Ok(()))) {
                        let filled = buf.filled().len();
                        if filled > filled_before {
                            let chunk = &buf.filled()[filled_before..filled];
                            this.inspect_uplink(chunk);
                        }
                    }
                    return poll;
                }
                PaddingReadPhase::Header { need_uuid } => {
                    while !this.reader.header_complete() {
                        let n = {
                            let dst = this.reader.header_write_buf();
                            let mut scratch = ReadBuf::new(dst);
                            match Pin::new(&mut *this.inner).poll_read(cx, &mut scratch) {
                                Poll::Pending => return Poll::Pending,
                                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                                Poll::Ready(Ok(())) => scratch.filled().len(),
                            }
                        };
                        if n == 0 {
                            if this.reader.header_filled() == 0 && need_uuid {
                                tracing::debug!("vision server: EOF before first padding frame");
                            } else if this.reader.header_filled() != 0 {
                                tracing::debug!(
                                    partial = this.reader.header_filled(),
                                    "vision server: EOF mid padding header (clean close)"
                                );
                            }
                            this.reader.set_eof();
                            return Poll::Ready(Ok(()));
                        }
                        this.reader.note_header_bytes(n);
                        control_frame_bytes += n;
                    }

                    let header = this.reader.finish_header();
                    if let Some(uuid) = header.uuid {
                        // Deliberate hardening over xray v26.3.27: upstream
                        // degrades a wrong first-frame UUID into pass-through
                        // of garbage bytes.  The spec closes the authenticated
                        // connection instead of forwarding those bytes to the
                        // target.
                        if uuid != this.user_uuid {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "vision server: padding UUID mismatch",
                            )));
                        }
                    }
                    if PaddingCommand::try_from(header.command).is_err() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("vision server: unknown padding command {}", header.command),
                        )));
                    }
                }
                PaddingReadPhase::Content {
                    remaining_content, ..
                } => {
                    // Content is copied straight into the relay's ReadBuf:
                    // no intermediate allocation exists on this path and the
                    // peer's u16 length fields cannot create one either.
                    let want = remaining_content.min(buf.remaining());
                    if want == 0 {
                        continue;
                    }
                    let filled_before = buf.filled().len();
                    let n = {
                        let mut bounded = buf.take(want);
                        match Pin::new(&mut *this.inner).poll_read(cx, &mut bounded) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Ready(Ok(())) => bounded.filled().len(),
                        }
                    };
                    if n == 0 {
                        tracing::debug!(
                            remaining_content,
                            "vision server: EOF mid padded content (clean close)"
                        );
                        this.reader.set_eof();
                        return Poll::Ready(Ok(()));
                    }
                    buf.advance(n);
                    this.reader.consume_content(n);
                    let chunk = &buf.filled()[filled_before..filled_before + n];
                    this.inspect_uplink(chunk);
                    return Poll::Ready(Ok(()));
                }
                PaddingReadPhase::Padding {
                    command,
                    remaining_padding,
                } => {
                    if remaining_padding > 0 {
                        let want = remaining_padding.min(PADDING_SCRATCH_LEN);
                        let n = {
                            let mut scratch = ReadBuf::new(&mut this.pad_scratch[..want]);
                            match Pin::new(&mut *this.inner).poll_read(cx, &mut scratch) {
                                Poll::Pending => return Poll::Pending,
                                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                                Poll::Ready(Ok(())) => scratch.filled().len(),
                            }
                        };
                        if n == 0 {
                            tracing::debug!(
                                remaining_padding,
                                "vision server: EOF mid padding (clean close)"
                            );
                            this.reader.set_eof();
                            return Poll::Ready(Ok(()));
                        }
                        this.reader.consume_padding(n);
                        control_frame_bytes += n;
                        continue;
                    }

                    let parsed = match this.reader.complete_frame(command) {
                        Ok(parsed) => parsed,
                        Err(other) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("vision server: unknown padding command {other}"),
                            )));
                        }
                    };
                    if let Err(error) = this.finish_inbound_frame(parsed) {
                        return Poll::Ready(Err(error));
                    }
                    if parsed == PaddingCommand::Continue {
                        empty_control_frames += 1;
                        if empty_control_frames >= 8
                            || control_frame_bytes >= EMPTY_CONTROL_FRAME_BYTE_BUDGET
                        {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for VisionServerConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_terminated {
            return Poll::Ready(Err(write_terminated_error()));
        }
        if this.pending_write.is_some() {
            match this.drain_pending_write(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.write_padding {
            return Pin::new(&mut *this.inner).poll_write(cx, buf);
        }

        let taken = this.prepare_write_frame(buf);
        Poll::Ready(Ok(taken))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_terminated {
            return Poll::Ready(Err(write_terminated_error()));
        }
        if let Poll::Ready(done) = this.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_terminated {
            return Poll::Ready(Err(write_terminated_error()));
        }
        if let Poll::Ready(done) = this.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl Unpin for VisionServerConn {}

impl ProxyConn for VisionServerConn {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::golden::vectors;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    const UUID: [u8; 16] = vectors::GOLDEN_UUID;

    fn server_over_pipe(mode: VisionServerMode) -> (VisionServerConn, DuplexStream) {
        let (inner, peer) = duplex(256 * 1024);
        (VisionServerConn::new(Box::new(inner), UUID, mode), peer)
    }

    /// Parse one server-emitted frame from the peer end, returning the
    /// vision command, content bytes and padding length.  `first` frames
    /// carry the 16-byte UUID; the two response header bytes must precede
    /// the very first frame and are asserted by the caller instead.
    async fn read_server_frame(peer: &mut DuplexStream, first: bool) -> (u8, Vec<u8>, usize) {
        if first {
            let mut uuid = [0u8; 16];
            peer.read_exact(&mut uuid).await.unwrap();
            assert_eq!(uuid, UUID, "first downlink frame embeds the account UUID");
        }
        let mut head = [0u8; 5];
        peer.read_exact(&mut head).await.unwrap();
        let content_len = u16::from_be_bytes([head[1], head[2]]) as usize;
        let padding_len = u16::from_be_bytes([head[3], head[4]]) as usize;
        let mut content = vec![0u8; content_len];
        peer.read_exact(&mut content).await.unwrap();
        let mut padding = vec![0u8; padding_len];
        peer.read_exact(&mut padding).await.unwrap();
        assert!(
            padding.iter().all(|&b| b == 0),
            "padding bytes are zero-filled on the wire"
        );
        (head[0], content, padding_len)
    }

    async fn read_response_header(peer: &mut DuplexStream) {
        let mut response = [0u8; 2];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response, super::super::super::header::RESPONSE_HEADER);
    }

    fn feed_frame(command: u8, with_uuid: bool, content: &[u8], padding_len: usize) -> Vec<u8> {
        let mut frame = Vec::new();
        if with_uuid {
            frame.extend_from_slice(&UUID);
        }
        frame.push(command);
        frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
        frame.extend_from_slice(content);
        frame.resize(frame.len() + padding_len, 0);
        frame
    }

    fn golden_serverhello() -> Vec<u8> {
        vectors::decode(vectors::TLS13_SERVERHELLO_DECISION)
    }

    fn app_data_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![0x17, 0x03, 0x03];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn serverhello_record(cipher: u16, extensions_vector: Option<&[u8]>) -> Vec<u8> {
        let mut body = 0x0303u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        if let Some(extensions) = extensions_vector {
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(extensions);
        }

        let handshake_len = 4 + body.len();
        let mut record = vec![
            0x16,
            0x03,
            0x03,
            (handshake_len >> 8) as u8,
            handshake_len as u8,
            0x02,
        ];
        record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        record.extend_from_slice(&body);
        record
    }

    fn parse_written_frames(wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
        assert_eq!(
            wire[..2],
            super::super::super::header::RESPONSE_HEADER,
            "server writes start with the VLESS response header"
        );
        let mut pos = 2;
        let mut first = true;
        let mut frames = Vec::new();
        while pos < wire.len() {
            if first {
                assert_eq!(&wire[pos..pos + 16], &UUID);
                pos += 16;
                first = false;
            }
            let command = wire[pos];
            let content_len = u16::from_be_bytes([wire[pos + 1], wire[pos + 2]]) as usize;
            let padding_len = u16::from_be_bytes([wire[pos + 3], wire[pos + 4]]) as usize;
            pos += 5;
            let content = wire[pos..pos + content_len].to_vec();
            pos += content_len;
            assert!(wire[pos..pos + padding_len].iter().all(|&b| b == 0));
            pos += padding_len;
            frames.push((command, content));
        }
        frames
    }

    #[derive(Debug, PartialEq, Eq)]
    enum WriteEvent {
        Write(Vec<u8>),
        FlushPending,
        FlushReady,
    }

    struct FlushGateStream {
        events: Vec<WriteEvent>,
        first_flush_pending: bool,
    }

    impl FlushGateStream {
        fn new() -> Self {
            Self {
                events: Vec::new(),
                first_flush_pending: true,
            }
        }
    }

    impl AsyncRead for FlushGateStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FlushGateStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.events.push(WriteEvent::Write(buf.to_vec()));
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.first_flush_pending {
                self.first_flush_pending = false;
                self.events.push(WriteEvent::FlushPending);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.events.push(WriteEvent::FlushReady);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PartialThenPendingStream {
        written: Vec<u8>,
        max_write: usize,
        writes_until_pending: usize,
    }

    impl PartialThenPendingStream {
        fn new(max_write: usize, writes_until_pending: usize) -> Self {
            Self {
                written: Vec::new(),
                max_write,
                writes_until_pending,
            }
        }
    }

    impl AsyncRead for PartialThenPendingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PartialThenPendingStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.writes_until_pending == 0 {
                self.writes_until_pending = usize::MAX;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.writes_until_pending -= 1;
            let n = self.max_write.min(buf.len());
            self.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_write_once(conn: &mut VisionServerConn, buf: &[u8]) -> Poll<io::Result<usize>> {
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(conn).poll_write(&mut cx, buf)
    }

    fn poll_flush_once(conn: &mut VisionServerConn) -> Poll<io::Result<()>> {
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(conn).poll_flush(&mut cx)
    }

    // ─── Read side: golden frames and frame-boundary tolerance ────────

    #[tokio::test]
    async fn golden_01_first_uplink_frame_decodes_byte_exactly() {
        let bytes = vectors::decode(vectors::TCP_REQUEST_FIRST_UPLINK_FRAME);
        let frame = &bytes[52..];
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        peer.write_all(frame).await.unwrap();

        let mut got = [0u8; 27];
        conn.read_exact(&mut got).await.unwrap();
        // The golden content is the first 27 bytes of the inner ClientHello
        // fragment frozen in the vector.
        assert_eq!(&got, &bytes[73..100]);
    }

    #[tokio::test]
    async fn golden_02_empty_first_frame_is_tolerated() {
        let bytes = vectors::decode(vectors::TCP_REQUEST_EMPTY_FIRST_FRAME);
        let frame = &bytes[52..];
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        peer.write_all(frame).await.unwrap();
        // The empty camouflage frame carries no content: a real frame after
        // it must still decode.
        let payload = b"after-empty";
        peer.write_all(&feed_frame(COMMAND_PADDING_CONTINUE, false, payload, 10))
            .await
            .unwrap();
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload);
    }

    #[tokio::test]
    async fn wrong_uuid_first_frame_is_fatal() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        let mut frame = feed_frame(COMMAND_PADDING_CONTINUE, true, b"x", 0);
        frame[0] ^= 0xff; // corrupt the first UUID byte
        peer.write_all(&frame).await.unwrap();
        let err = conn.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn unknown_padding_command_is_fatal() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        peer.write_all(&feed_frame(0x42, true, b"x", 0))
            .await
            .unwrap();
        let err = conn.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn eof_variants_are_clean_closes() {
        // Mid-content EOF: the seven delivered bytes stay delivered.
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        let mut frame = Vec::new();
        frame.extend_from_slice(&UUID);
        frame.push(COMMAND_PADDING_CONTINUE);
        frame.extend_from_slice(&100u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(b"only-7b");
        peer.write_all(&frame).await.unwrap();
        let mut got = [0u8; 7];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"only-7b");
        drop(peer);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);

        // Mid-header EOF.
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        peer.write_all(&UUID).await.unwrap();
        peer.write_all(&[COMMAND_PADDING_CONTINUE, 0x00])
            .await
            .unwrap();
        drop(peer);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);

        // Mid-padding EOF.
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        let mut frame = feed_frame(COMMAND_PADDING_CONTINUE, true, b"data", 50);
        frame.truncate(frame.len() - 30); // 20 of 50 padding bytes missing
        peer.write_all(&frame).await.unwrap();
        let mut got = [0u8; 4];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"data");
        drop(peer);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn huge_padding_lengths_are_discarded_in_fixed_scratch() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        // Maximum u16 padding — the fixed 1 KiB scratch must discard it in
        // iterations; nothing is allocated per peer-controlled length.
        peer.write_all(&feed_frame(
            COMMAND_PADDING_CONTINUE,
            true,
            b"c",
            u16::MAX as usize,
        ))
        .await
        .unwrap();
        let payload = b"real";
        peer.write_all(&feed_frame(COMMAND_PADDING_CONTINUE, false, payload, 0))
            .await
            .unwrap();
        let mut got = [0u8; 1];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"c");
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload);
    }

    #[tokio::test]
    async fn byte_by_byte_frame_delivery_decodes_identically() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        let payload = b"split me everywhere";
        let frame = feed_frame(COMMAND_PADDING_CONTINUE, true, payload, 37);
        let writer = tokio::spawn(async move {
            for &byte in &frame {
                peer.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn end_frame_lets_plain_stream_bytes_flow() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        peer.write_all(&feed_frame(COMMAND_PADDING_END, true, b"framed", 5))
            .await
            .unwrap();
        peer.write_all(b"plain-tail").await.unwrap();
        let mut got = [0u8; 6];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"framed");
        let mut tail = [0u8; 10];
        conn.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"plain-tail");
    }

    #[tokio::test]
    async fn inbound_direct_without_tls13_evidence_is_rejected() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        peer.write_all(&feed_frame(COMMAND_PADDING_DIRECT, true, b"x", 0))
            .await
            .unwrap();
        let mut buf = [0u8; 1];
        // The DIRECT frame's own content is delivered first…
        assert_eq!(conn.read(&mut buf).await.unwrap(), 1);
        // …then the frame completes and the unjustified DIRECT is fatal.
        let err = conn.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn golden_05_xudp_frame_passes_through_uninterpreted() {
        // The frozen 43-byte XUDP New+Data frame rides vision padding as
        // opaque content: the server codec must deliver it byte-exactly and
        // must not try to interpret the inner XUDP structure itself.
        let xudp = vectors::decode(vectors::XUDP_NEW_DATA);
        assert_eq!(xudp.len(), 43);
        // Keep/End and reply datagrams (vectors 06/07) are equally opaque:
        // concatenate the whole uplink sequence across frame boundaries.
        let mut stream_content = xudp.clone();
        stream_content.extend(vectors::decode(vectors::XUDP_KEEP_END));
        stream_content.extend(vectors::decode(vectors::XUDP_REPLY_KEEP_DATA));
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Xudp);
        peer.write_all(&feed_frame(
            COMMAND_PADDING_CONTINUE,
            true,
            &stream_content,
            20,
        ))
        .await
        .unwrap();
        let mut got = vec![0u8; stream_content.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(got, stream_content);
    }

    #[tokio::test]
    async fn xudp_mode_tls_shaped_payload_is_not_direct_evidence() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Xudp);
        // A full fake TLS client hello plus server hello inside XUDP content:
        // none of it may arm the inspector.
        let mut shaped = vec![0x16, 0x03, 0x01, 0x00, 0x01, 0x01];
        shaped.extend_from_slice(&golden_serverhello());
        peer.write_all(&feed_frame(COMMAND_PADDING_CONTINUE, true, &shaped, 0))
            .await
            .unwrap();
        let mut got = vec![0u8; shaped.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert!(!conn.inspector.is_tls());
        assert!(!conn.inspector.enable_xtls());
        assert_eq!(
            conn.inspector.packets_left(),
            super::super::codec::TLS_FILTER_PACKETS - 1
        );
    }

    // ─── Write side: response header, frame layout, padding commands ──

    #[tokio::test]
    async fn first_write_prepends_response_header_and_embeds_uuid_once() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        conn.write_all(b"hello").await.unwrap();
        conn.write_all(b"world").await.unwrap();
        conn.flush().await.unwrap();

        read_response_header(&mut peer).await;
        let (command, content, _) = read_server_frame(&mut peer, true).await;
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert_eq!(content, b"hello");
        let (_, content, _) = read_server_frame(&mut peer, false).await;
        assert_eq!(content, b"world");
    }

    #[tokio::test]
    async fn write_layout_matches_golden_03_structure() {
        // Golden 03 writes the 37-byte `17 03 03 00 20 aa×32` content as the
        // first downlink frame.  Reproduce that write and compare structure:
        // the response header outside framing, uuid embedded once, content
        // byte-exact, padding consistent with the generation rule.
        let golden = vectors::decode(vectors::RESPONSE_FIRST_DOWNLINK_FRAME);
        let content = &golden[23..60];
        assert_eq!(content.len(), 37);

        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        conn.write_all(content).await.unwrap();
        conn.flush().await.unwrap();

        read_response_header(&mut peer).await;
        let (command, got, padding_len) = read_server_frame(&mut peer, true).await;
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert_eq!(got, content, "frame content is byte-exact");
        // Non-TLS short padding: [0, 256); the frozen golden value 100 lies
        // in the same interval.
        assert!(padding_len < 256);
    }

    #[tokio::test]
    async fn tls13_flow_ends_padding_with_end_when_transport_cannot_go_raw() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        assert!(!conn.raw_write_capable, "duplex is not raw-capable");
        // Arm the inspector as if the target had answered a TLS 1.3 hello.
        conn.write_all(&golden_serverhello()).await.unwrap();
        assert!(conn.inspector.enable_xtls());

        let batch = app_data_record(b"application-data");
        conn.write_all(&batch).await.unwrap();
        conn.write_all(b"after-end").await.unwrap();
        conn.flush().await.unwrap();

        read_response_header(&mut peer).await;
        let (command, _, _) = read_server_frame(&mut peer, true).await;
        assert_eq!(
            command, COMMAND_PADDING_CONTINUE,
            "hello frame continues padding"
        );
        let (command, content, _) = read_server_frame(&mut peer, false).await;
        assert_eq!(
            command, COMMAND_PADDING_END,
            "TLS 1.3 app-data over a non-raw transport earns END, never DIRECT"
        );
        assert_eq!(content, batch);
        // After END the remaining bytes flow unframed.
        let mut tail = [0u8; 9];
        peer.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"after-end");
    }

    #[test]
    fn partial_write_cancel_then_different_payload_does_not_skip_caller_bytes() {
        let stream = PartialThenPendingStream::new(7, 1);
        let mut conn = VisionServerConn::new(Box::new(stream), UUID, VisionServerMode::Tcp);

        let first_payload = vec![b'A'; 37];
        assert!(matches!(
            poll_write_once(&mut conn, &first_payload),
            Poll::Ready(Ok(n)) if n == first_payload.len()
        ));

        // The first drain attempt makes partial progress and then pends.  That
        // poll is dropped as a cancelled write; no caller byte from this
        // payload has been accepted into the frame yet.
        let cancelled_payload = vec![b'B'; 53];
        assert!(matches!(
            poll_write_once(&mut conn, &cancelled_payload),
            Poll::Pending
        ));

        let replacement_payload = vec![b'C'; 53];
        assert!(matches!(
            poll_write_once(&mut conn, &replacement_payload),
            Poll::Ready(Ok(n)) if n == replacement_payload.len()
        ));
        assert!(matches!(poll_flush_once(&mut conn), Poll::Ready(Ok(()))));

        let written = conn
            .inner
            .as_mut()
            .as_any_mut()
            .downcast_mut::<PartialThenPendingStream>()
            .expect("test stream type")
            .written
            .clone();
        let frames = parse_written_frames(&written);
        assert_eq!(frames.len(), 2, "cancelled payload was never accepted");
        assert_eq!(frames[0].1, first_payload);
        assert_eq!(frames[1].1, replacement_payload);
    }

    #[tokio::test]
    async fn empty_control_frames_yield_on_the_byte_budget() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        peer.write_all(&feed_frame(
            COMMAND_PADDING_CONTINUE,
            true,
            &[],
            u16::MAX as usize,
        ))
        .await
        .unwrap();
        peer.write_all(&feed_frame(COMMAND_PADDING_CONTINUE, false, b"after", 0))
            .await
            .unwrap();

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut got = [0u8; 5];
        let filled = {
            let mut read_buf = ReadBuf::new(&mut got);
            assert!(matches!(
                Pin::new(&mut conn).poll_read(&mut cx, &mut read_buf),
                Poll::Pending
            ));
            assert_eq!(read_buf.filled().len(), 0);
            assert!(matches!(
                Pin::new(&mut conn).poll_read(&mut cx, &mut read_buf),
                Poll::Ready(Ok(()))
            ));
            read_buf.filled().len()
        };
        assert_eq!(&got[..filled], b"after");
    }

    #[tokio::test]
    async fn tls12_serverhello_ends_padding_without_direct() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        conn.raw_write_capable = true;
        let hello = serverhello_record(0x1301, None);
        conn.write_all(&hello).await.unwrap();

        let batch = app_data_record(b"tls12-application-data");
        conn.write_all(&batch).await.unwrap();
        conn.flush().await.unwrap();

        read_response_header(&mut peer).await;
        let (command, _, _) = read_server_frame(&mut peer, true).await;
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        let (command, content, _) = read_server_frame(&mut peer, false).await;
        assert_eq!(
            command, COMMAND_PADDING_END,
            "TLS 1.2 must never promise DIRECT"
        );
        assert_eq!(content, batch);
        assert_eq!(
            conn.write_frame.capacity(),
            0,
            "END releases the frame allocation"
        );
    }

    #[tokio::test]
    async fn fragmented_serverhello_exhausting_the_budget_falls_back_to_end() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        let hello = golden_serverhello();
        let chunks: Vec<_> = hello.chunks(10).collect();
        assert_eq!(chunks.len(), 9);
        for chunk in &chunks[..8] {
            conn.write_all(chunk).await.unwrap();
        }
        conn.flush().await.unwrap();
        conn.write_all(chunks[8]).await.unwrap();
        conn.flush().await.unwrap();

        read_response_header(&mut peer).await;
        let mut reassembled = Vec::new();
        for index in 0..8 {
            let (command, content, _) = read_server_frame(&mut peer, index == 0).await;
            assert_eq!(
                command,
                if index == 7 {
                    COMMAND_PADDING_END
                } else {
                    COMMAND_PADDING_CONTINUE
                }
            );
            reassembled.extend_from_slice(&content);
        }
        assert_eq!(reassembled, hello[..80]);
        let mut tail = vec![0u8; chunks[8].len()];
        peer.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, chunks[8]);
    }

    #[tokio::test]
    async fn direct_record_fragmented_across_writes_switches_on_completion() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        conn.raw_write_capable = true;
        conn.write_all(&golden_serverhello()).await.unwrap();
        conn.flush().await.unwrap();

        let record = app_data_record(b"fragmented application record");
        // Two bytes leave even the record header split across write batches.
        let split = 2;
        conn.write_all(&record[..split]).await.unwrap();
        conn.flush().await.unwrap();
        conn.write_all(&record[split..]).await.unwrap();
        let err = conn.flush().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        read_response_header(&mut peer).await;
        let (command, _, _) = read_server_frame(&mut peer, true).await;
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        let (command, first, _) = read_server_frame(&mut peer, false).await;
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert_eq!(first, record[..split]);
        let (command, rest, _) = read_server_frame(&mut peer, false).await;
        assert_eq!(
            command, COMMAND_PADDING_DIRECT,
            "completion of the cross-write record must still earn DIRECT"
        );
        assert_eq!(rest, record[split..]);
        assert_eq!(
            conn.write_frame.capacity(),
            0,
            "DIRECT releases the frame allocation"
        );
    }

    #[test]
    fn direct_raw_switch_waits_for_outer_flush() {
        let mut conn = VisionServerConn::new(
            Box::new(FlushGateStream::new()),
            UUID,
            VisionServerMode::Tcp,
        );
        conn.raw_write_capable = true;

        let hello = golden_serverhello();
        assert!(matches!(
            poll_write_once(&mut conn, &hello),
            Poll::Ready(Ok(n)) if n == hello.len()
        ));
        let batch = app_data_record(b"flush-boundary");
        assert!(matches!(
            poll_write_once(&mut conn, &batch),
            Poll::Ready(Ok(n)) if n == batch.len()
        ));

        let raw = b"raw-after-direct";
        assert!(
            matches!(poll_write_once(&mut conn, raw), Poll::Pending),
            "the first raw write must wait behind the outer-TLS flush"
        );
        let poll = poll_write_once(&mut conn, raw);
        assert!(
            matches!(poll, Poll::Ready(Err(ref error)) if error.kind() == io::ErrorKind::Unsupported),
            "the plain test stream cannot really switch after the flush: {poll:?}"
        );

        let events = &conn
            .inner
            .as_mut()
            .as_any_mut()
            .downcast_ref::<FlushGateStream>()
            .expect("concrete test stream")
            .events;
        let flush_ready = events
            .iter()
            .position(|event| matches!(event, WriteEvent::FlushReady))
            .expect("outer TLS flush completes before raw writes");
        let direct_write = events[..flush_ready]
            .iter()
            .rposition(|event| matches!(event, WriteEvent::Write(_)))
            .expect("DIRECT frame write precedes the flush");
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, WriteEvent::Write(bytes) if bytes == raw)),
            "raw payload must not bypass a failed post-flush switch: {events:?}"
        );
        assert!(
            direct_write < flush_ready,
            "wire order must be DIRECT frame, then outer flush: {events:?}"
        );
        assert!(events[direct_write..flush_ready]
            .iter()
            .any(|event| matches!(event, WriteEvent::FlushPending)));
    }

    #[tokio::test]
    async fn tls13_flow_promises_direct_only_with_a_raw_capable_transport() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        // Test-only capability injection: the decision logic must select
        // DIRECT; the duplex transport then fails the actual switch, which
        // the spec turns into connection termination rather than a
        // retroactive END.
        conn.raw_write_capable = true;
        conn.write_all(&golden_serverhello()).await.unwrap();

        let batch = app_data_record(b"x");
        // Ownership of the batch passes into the pending DIRECT frame when
        // it is copied; the failed raw switch surfaces when flush guarantees
        // that frame's drain.
        conn.write_all(&batch).await.unwrap();
        let err = conn.flush().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        // The frames are on the wire regardless: the DIRECT promise was
        // emitted and is never retroactively rewritten into an END.
        read_response_header(&mut peer).await;
        let (command, _, _) = read_server_frame(&mut peer, true).await;
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        let (command, content, _) = read_server_frame(&mut peer, false).await;
        assert_eq!(command, COMMAND_PADDING_DIRECT);
        assert_eq!(content, batch);

        // The write side is permanently terminated: writes, flush and
        // shutdown all fail rather than touching the half-switched transport.
        let err = conn.write_all(b"more").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(conn.flush().await.is_err());
        assert!(conn.shutdown().await.is_err());
    }

    #[tokio::test]
    async fn non_tls_traffic_ends_padding_when_the_budget_runs_out() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        // Plain-text writes: the seventh batch leaves the shared budget at
        // one, so padding finishes one packet early (xray compatibility
        // rule) on that frame; further writes flow unframed.
        for _ in 0..7 {
            conn.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        }
        conn.write_all(b"raw-tail").await.unwrap();
        conn.flush().await.unwrap();

        read_response_header(&mut peer).await;
        let mut commands = Vec::new();
        for index in 0..7 {
            let (command, _, _) = read_server_frame(&mut peer, index == 0).await;
            commands.push(command);
        }
        assert_eq!(
            commands,
            [
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_END,
            ],
            "padding must end exactly on the seventh frame: {commands:?}"
        );
        assert!(!conn.padding_write_active());
        // The eighth write went onto the wire unframed.
        let mut tail = [0u8; 8];
        peer.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"raw-tail");
    }

    #[tokio::test]
    async fn large_complete_record_write_cuts_frames_at_record_boundaries() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        conn.write_all(&golden_serverhello()).await.unwrap();

        // 200 small app-data records of 105 bytes each = 21 000 bytes,
        // larger than one 16 KiB frame, written as a single batch.
        let single = app_data_record(&[0u8; 100]);
        assert_eq!(single.len(), 105);
        let mut batch = Vec::new();
        for _ in 0..200 {
            batch.extend_from_slice(&single);
        }
        conn.write_all(&batch).await.unwrap();
        conn.flush().await.unwrap();

        read_response_header(&mut peer).await;
        let (command, first_content, _) = read_server_frame(&mut peer, true).await;
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        // Frame one is the padded server hello — regenerate ordering: the
        // first frame actually carries the hello; read on for the batch.
        if first_content != golden_serverhello() {
            panic!("first frame must carry the server hello");
        }
        let (command, chunk1, _) = read_server_frame(&mut peer, false).await;
        assert_eq!(command, COMMAND_PADDING_CONTINUE, "non-final chunk");
        assert_eq!(
            chunk1.len() % 105,
            0,
            "record-aligned cut: len {}",
            chunk1.len()
        );
        assert!(chunk1.len() <= FRAME_CONTENT_CAP);
        let (command, chunk2, _) = read_server_frame(&mut peer, false).await;
        assert_eq!(
            command, COMMAND_PADDING_END,
            "the batch's final frame ends padding (non-raw transport)"
        );
        assert_eq!(chunk1.len() + chunk2.len(), batch.len());
        let mut reassembled = chunk1.clone();
        reassembled.extend_from_slice(&chunk2);
        assert_eq!(reassembled, batch);
    }

    #[tokio::test]
    async fn camouflage_frame_is_long_padded_empty_content() {
        let (mut conn, mut peer) = server_over_pipe(VisionServerMode::Tcp);
        conn.write_camouflage_frame().await.unwrap();
        read_response_header(&mut peer).await;
        let (command, content, padding_len) = read_server_frame(&mut peer, true).await;
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert!(content.is_empty());
        // xray hides the header with long padding: content+pad ∈ [900,1400).
        assert!((900..1400).contains(&padding_len), "padding {padding_len}");
    }

    // ─── Cross-role interop: the existing client against this server ──

    #[tokio::test]
    async fn client_written_frames_decode_on_the_server() {
        use crate::vless::conn::VlessConn;
        use crate::vless::vision::client::VisionConn;

        let (client_inner, server_inner) = duplex(256 * 1024);
        let vless = VlessConn {
            inner: Box::new(client_inner),
            response_pending: false,
            response_buf: [0; 2],
            response_pos: 0,
            response_addon: Vec::new(),
            header_pending: None,
            header_needs_flush: false,
        };
        let mut client = VisionConn::new(vless, UUID);
        let mut server = VisionServerConn::new(Box::new(server_inner), UUID, VisionServerMode::Tcp);

        // Non-TLS client payload: the client ends padding after its budget;
        // every content byte must surface on the server side exactly once.
        let payload = b"client-to-server payload";
        client.write_all(payload).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; payload.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload);
    }

    #[tokio::test]
    async fn server_written_frames_decode_on_the_client() {
        use crate::vless::conn::VlessConn;
        use crate::vless::vision::client::VisionConn;

        let (client_inner, server_inner) = duplex(256 * 1024);
        let vless = VlessConn {
            inner: Box::new(client_inner),
            response_pending: true,
            response_buf: [0; 2],
            response_pos: 0,
            response_addon: Vec::new(),
            header_pending: None,
            header_needs_flush: false,
        };
        let mut client = VisionConn::new(vless, UUID);
        let mut server = VisionServerConn::new(Box::new(server_inner), UUID, VisionServerMode::Tcp);

        let payload = b"server-to-client payload";
        server.write_all(payload).await.unwrap();
        server.flush().await.unwrap();

        // The client first consumes the two-byte response header inside its
        // VlessConn layer, then the padded frame — output must be exact.
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload);
    }
}
