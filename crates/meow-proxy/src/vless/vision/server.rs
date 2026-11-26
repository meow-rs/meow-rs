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
    capped_padding_len, encode_padding_frame_with_padding_len, is_complete_tls_application_records,
    record_aligned_cut, PaddingCommand, PaddingReadPhase, PaddingReader, COMMAND_PADDING_CONTINUE,
    COMMAND_PADDING_DIRECT, COMMAND_PADDING_END, FRAME_CONTENT_CAP, PADDING_HEADER_LEN,
    PADDING_SCRATCH_LEN, UUID_LEN,
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
    consumed: usize,
    command: u8,
    end_padding_after_drain: bool,
}

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

    fn inspect_downlink(&mut self, chunk: &[u8]) {
        if self.write_raw {
            return;
        }
        match self.mode {
            VisionServerMode::Tcp => self.inspector.observe_server_stream(chunk),
            VisionServerMode::Xudp => self.inspector.observe_opaque_packet(chunk),
        }
    }

    fn drain_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>> {
        if self.pending_write.is_none() {
            return Poll::Ready(Ok(None));
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

        let pending = self
            .pending_write
            .take()
            .expect("pending presence checked above");
        self.write_frame.clear();
        self.write_frame_pos = 0;

        if pending.end_padding_after_drain {
            self.write_padding = false;
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
        Poll::Ready(Ok(Some(pending.consumed)))
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
        consumed: usize,
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
            consumed,
            command,
            end_padding_after_drain,
        });
    }

    /// Build one padded write frame from the head of `buf` and return the
    /// number of caller bytes ownership of which moved into the frame.
    ///
    /// Each `poll_write` call is one batch, evaluated fresh: padding
    /// decisions depend only on monotonic inspector state and structural
    /// record completeness, so a `write_all` retry of the remainder reaches
    /// the same decision as one uninterrupted batch — and a cancelled write
    /// can never leak stale batch state onto unrelated later payload
    /// (spec §6 cancellation contract).
    fn prepare_write_frame(&mut self, buf: &[u8]) -> usize {
        debug_assert!(!buf.is_empty());
        self.inspect_downlink(buf);

        let complete_records = is_complete_tls_application_records(buf);
        let mut take = buf.len().min(FRAME_CONTENT_CAP);
        if complete_records && take < buf.len() {
            // Cutting at a record boundary keeps the retry slice starting
            // with `17 03 03`, so the remainder re-evaluates as complete
            // records and the batch's final frame can still earn DIRECT.
            take = record_aligned_cut(buf, FRAME_CONTENT_CAP);
        }
        debug_assert!(take > 0);
        let final_batch_frame = take == buf.len();
        let content = &buf[..take];

        let mut command = COMMAND_PADDING_CONTINUE;
        let mut end_after_drain = false;
        if final_batch_frame && complete_records && self.inspector.is_tls() {
            // xray frames the whole batch and ends padding on its last
            // buffer.  A complete-records buffer starts with `17 03 03` by
            // construction, so xray's separate prefix check is implied.
            end_after_drain = true;
            if self.inspector.enable_xtls() && self.raw_write_capable {
                command = COMMAND_PADDING_DIRECT;
            } else {
                if self.inspector.enable_xtls() {
                    tracing::debug!("XTLS Vision server: transport cannot write raw, sending END");
                }
                command = COMMAND_PADDING_END;
            }
        } else if !self.inspector.is_tls12_or_above() && self.inspector.packets_left() <= 1 {
            // xray finishes one packet early for non-TLS traffic — even
            // mid-batch, with the remainder flowing unframed.  Here the END
            // lands on this frame and the caller's retry, if any, bypasses
            // framing because `write_padding` is already off.
            command = COMMAND_PADDING_END;
            end_after_drain = true;
        }

        self.begin_frame(command, content, take, end_after_drain, false);
        take
    }

    fn build_camouflage_frame(&mut self) -> bool {
        if !self.write_padding || self.pending_write.is_some() || self.write_terminated {
            return false;
        }
        // xray's empty first-frame special case always uses long padding to
        // hide the VLESS header timing/shape, independent of IsTLS.
        self.begin_frame(COMMAND_PADDING_CONTINUE, &[], 0, false, true);
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
                        if empty_control_frames >= 8 {
                            // Empty camouflage frames are legal, but a peer
                            // may stream them forever.  Yield cooperatively
                            // instead of monopolising the executor inside one
                            // poll_read.
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
            return match this.drain_pending_write(cx) {
                Poll::Ready(Ok(Some(n))) => Poll::Ready(Ok(n)),
                Poll::Ready(Ok(None)) => Poll::Ready(Ok(0)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            };
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.write_padding {
            this.inspect_downlink(buf);
            return Pin::new(&mut *this.inner).poll_write(cx, buf);
        }

        this.prepare_write_frame(buf);
        match this.drain_pending_write(cx) {
            Poll::Ready(Ok(Some(n))) => Poll::Ready(Ok(n)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(0)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
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
        // The DIRECT frame drains onto the wire, then the switch failure
        // surfaces inside the same write — the client error contract.
        let err = conn.write_all(&batch).await.unwrap_err();
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
