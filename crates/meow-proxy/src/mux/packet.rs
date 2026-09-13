//! UDP-over-mux packet stream (sing-mux clientPacketConn / serverPacketConn).
//!
//! A UDP flow is one mux stream opened with the stream-request flagUDP bit;
//! its payload is length-prefixed datagrams: `[len u16 BE][data]` in both
//! directions (identical framing to meow's VLESS UDP-over-TCP).  The first
//! server→client byte is still the stream response status (consumed by
//! `MuxStream`), and the stream is bound to the destination carried in the
//! stream request — datagrams carry no per-packet address.

use super::client::{MuxSession, MuxStream};
use bytes::{BufMut, BytesMut};
use meow_common::{MeowError, ProxyPacketConn, Result};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// One UDP flow multiplexed over a mux stream.  Dropping it half-closes
/// the stream and decrements the session's stream count.
pub struct MuxPacketConn {
    reader: Mutex<PacketReader>,
    writer: Mutex<PacketWriter>,
    session: Arc<MuxSession>,
    /// The destination bound in the stream request; every read reports this
    /// as the datagram source (no per-packet addressing in sing-mux UDP).
    destination: SocketAddr,
}

impl MuxPacketConn {
    pub(crate) fn new(
        stream: MuxStream,
        session: Arc<MuxSession>,
        destination: SocketAddr,
    ) -> Self {
        // Split so a blocked read (no upstream datagram yet) cannot
        // head-of-line block writes — the SOCKS5 UDP relay runs the
        // server→client reader on a separate task from client→server
        // writes, and QUIC-style flows write while waiting for reads.
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(PacketReader::new(reader)),
            writer: Mutex::new(PacketWriter::new(writer)),
            session,
            destination,
        }
    }
}

impl Drop for MuxPacketConn {
    fn drop(&mut self) {
        self.session.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

impl MuxPacketConn {
    /// Write one datagram as `[len u16 BE][data]`.
    pub async fn write_datagram(&self, data: &[u8]) -> Result<usize> {
        if data.len() > u16::MAX as usize {
            return Err(MeowError::Proxy(format!(
                "mux: UDP packet ({} bytes) exceeds u16 framing",
                data.len()
            )));
        }
        let mut writer = self.writer.lock().await;
        writer.write_datagram(data).await.map_err(MeowError::Io)?;
        Ok(data.len())
    }

    /// Read one datagram: `[len u16 BE][data]`.  The stream response status
    /// byte is consumed lazily on the first read by `MuxStream`.
    pub async fn read_datagram(&self, buf: &mut [u8]) -> Result<usize> {
        let mut reader = self.reader.lock().await;
        reader.read_datagram(buf).await
    }
}

/// Cancel-safe datagram reader.  Length and payload progress survive a
/// dropped `read_packet` future (callers may cancel a read by dropping
/// the future, e.g. on task abort).
struct PacketReader {
    stream: tokio::io::ReadHalf<MuxStream>,
    len: [u8; 2],
    len_pos: usize,
    payload: Vec<u8>,
    payload_pos: usize,
}

impl PacketReader {
    fn new(stream: tokio::io::ReadHalf<MuxStream>) -> Self {
        Self {
            stream,
            len: [0; 2],
            len_pos: 0,
            payload: Vec::new(),
            payload_pos: 0,
        }
    }

    fn reset(&mut self) {
        self.len_pos = 0;
        self.payload.clear();
        self.payload_pos = 0;
    }

    async fn read_datagram(&mut self, out: &mut [u8]) -> Result<usize> {
        while self.len_pos < self.len.len() {
            let read = self
                .stream
                .read(&mut self.len[self.len_pos..])
                .await
                .map_err(MeowError::Io)?;
            if read == 0 {
                return Err(MeowError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "mux: EOF while reading UDP packet length",
                )));
            }
            self.len_pos += read;
        }

        if self.payload.is_empty() && self.payload_pos == 0 {
            self.payload
                .resize(u16::from_be_bytes(self.len) as usize, 0);
        }
        while self.payload_pos < self.payload.len() {
            let read = self
                .stream
                .read(&mut self.payload[self.payload_pos..])
                .await
                .map_err(MeowError::Io)?;
            if read == 0 {
                return Err(MeowError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "mux: EOF while reading UDP packet payload",
                )));
            }
            self.payload_pos += read;
        }

        let packet_len = self.payload.len();
        if packet_len > out.len() {
            self.reset();
            return Err(MeowError::Proxy(format!(
                "mux: UDP packet ({packet_len} bytes) exceeds read buffer ({} bytes)",
                out.len()
            )));
        }
        out[..packet_len].copy_from_slice(&self.payload);
        self.reset();
        Ok(packet_len)
    }
}

struct PacketWriter<W = tokio::io::WriteHalf<MuxStream>> {
    stream: W,
    /// Cancellation-safe write state: the combined frame (length prefix
    /// and data) and the byte offset already written. A `write_datagram`
    /// future dropped mid-write re-enters and resumes from `offset`
    /// instead of re-writing the length prefix and desyncing the peer
    /// framing. Mirrors `PacketReader`'s persistent-progress pattern.
    pending: Option<(bytes::Bytes, usize)>,
}

impl<W: tokio::io::AsyncWrite + Unpin> PacketWriter<W> {
    fn new(stream: W) -> Self {
        Self {
            stream,
            pending: None,
        }
    }

    async fn write_datagram(&mut self, data: &[u8]) -> std::io::Result<()> {
        // Recovering from a cancelled write: the pending frame owns its
        // bytes, so a leftover frame is never a caller error.
        //
        // - Same data: this call is a retry of the cancelled write —
        //   resume the pending frame from its offset.
        // - Different data, nothing on the wire yet (offset 0): nothing
        //   is committed — discard the stale frame and send the new one.
        // - Different data after a partial write: the length prefix is
        //   committed, so first complete the stale frame on the wire
        //   (preserving peer framing — the cancelled datagram is
        //   delivered late rather than truncated), then frame and send
        //   the new datagram.  Two wire datagrams, no error, no drop.
        //
        // Datagram identity is content-based: after a cancelled partial
        // write, a *new* datagram carrying identical bytes is
        // indistinguishable from a retry of the cancelled one and will
        // be coalesced into a single wire datagram — acceptable under
        // UDP's lossy delivery semantics.
        //
        // Errors surfaced here are always stream I/O errors (the
        // transport died mid-frame), never caller misuse: draining a
        // stale frame on a dead stream reports the underlying write
        // error, and the frame is kept so the state stays consistent
        // if the caller retries anyway.
        if let Some((frame, offset)) = &self.pending {
            if &frame[2..] != data {
                if *offset == 0 {
                    self.pending = None;
                } else {
                    self.drain_pending().await?;
                }
            }
        }

        // Prepare the combined frame on first entry (or after the
        // previous one completed).  Owning the bytes is required because
        // the caller's `&[u8]` may be gone after cancellation.
        if self.pending.is_none() {
            let mut frame = BytesMut::with_capacity(2 + data.len());
            frame.put_u16(data.len() as u16);
            frame.put_slice(data);
            self.pending = Some((frame.freeze(), 0));
        }

        self.drain_pending().await?;
        self.stream.flush().await
    }

    /// Write the pending frame to completion, resuming from the stored
    /// offset if a previous call was cancelled mid-write.  Uses
    /// individual `write` calls (not `write_all`) so each successful
    /// write updates the offset before the next await point —
    /// `write_all` loses its internal progress on cancellation, which
    /// would duplicate already-sent bytes.  On error the frame (and its
    /// offset) survive, so a later call can still resume it.
    async fn drain_pending(&mut self) -> std::io::Result<()> {
        loop {
            let Some((frame, offset)) = self.pending.as_ref() else {
                return Ok(());
            };
            if *offset >= frame.len() {
                self.pending = None;
                return Ok(());
            }
            let n = self.stream.write(&frame[*offset..]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "mux: zero-length write during datagram send",
                ));
            }
            self.pending.as_mut().unwrap().1 += n;
        }
    }
}

#[async_trait::async_trait]
impl ProxyPacketConn for MuxPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let n = self.read_datagram(buf).await?;
        Ok((n, self.destination))
    }

    async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
        self.write_datagram(buf).await
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Err(MeowError::NotSupported(
            "MuxPacketConn has no local UDP addr (UDP-over-mux)".into(),
        ))
    }

    fn close(&self) -> Result<()> {
        // The stream half-closes when MuxPacketConn is dropped.
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::super::address;
    use super::super::client::{MuxStreamKind, SessionKind};
    use super::super::smux;
    use super::*;
    use meow_common::atomic::AtomicU;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Minimal sing-mux UDP server over a duplex pipe (smux session):
    /// asserts the stream request carries flagUDP, writes the response
    /// status byte, then echoes the datagram bytes verbatim.
    async fn run_udp_server<S>(mut io: S) -> tokio::task::JoinHandle<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            let mut header = [0u8; 8];
            let mut first_psh = true;
            loop {
                if io.read_exact(&mut header).await.is_err() {
                    return;
                }
                let cmd = header[1];
                let length = u16::from_le_bytes([header[2], header[3]]) as usize;
                let sid = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
                let mut payload = vec![0u8; length];
                if !payload.is_empty() && io.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let mut send = async |cmd: u8, data: &[u8]| {
                    let mut buf = bytes::BytesMut::with_capacity(8 + data.len());
                    bytes::BufMut::put_u8(&mut buf, 0x01);
                    bytes::BufMut::put_u8(&mut buf, cmd);
                    bytes::BufMut::put_u16_le(&mut buf, data.len() as u16);
                    bytes::BufMut::put_u32_le(&mut buf, sid);
                    buf.extend_from_slice(data);
                    io.write_all(&buf).await
                };
                match cmd {
                    0 => {
                        let _ = sid;
                    } // SYN (no response)
                    2 => {
                        // PSH
                        if first_psh {
                            first_psh = false;
                            assert_eq!(
                                u16::from_be_bytes([payload[0], payload[1]]),
                                1,
                                "stream request must carry flagUDP"
                            );
                            let _ = send(2, &[0x00]).await; // status success
                        } else {
                            let _ = send(2, &payload).await; // echo datagram
                        }
                    }
                    1 => {
                        let _ = send(1, &[]).await;
                    } // FIN
                    _ => {}
                }
            }
        })
    }

    #[tokio::test]
    async fn udp_datagram_round_trip_over_smux() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_udp_server(server_io).await;
        let session = Arc::new(smux::Session::client(client_io).unwrap());
        let smux_stream = session.open_stream().await.unwrap();
        let mut stream = MuxStream::new(MuxStreamKind::Smux(smux_stream));
        stream
            .write_all(&address::encode_stream_request_with_flags("127.0.0.1", 53, 1).unwrap())
            .await
            .unwrap();
        let session_arc = Arc::new(MuxSession {
            kind: SessionKind::Smux(session),
            streams: AtomicUsize::new(1),
            last_used_ms: AtomicU::new(0),
        });
        let conn = MuxPacketConn::new(
            stream,
            session_arc,
            "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
        );

        conn.write_packet(b"hello-udp", &"127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 32];
        let (n, src) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-udp");
        assert_eq!(src, "127.0.0.1:53".parse::<SocketAddr>().unwrap());
    }
    /// UDP round trip over a yamux session (parity with the smux test;
    /// the review flagged yamux UDP as untested).
    #[tokio::test]
    async fn udp_datagram_round_trip_over_yamux() {
        use super::super::yamux;
        use ::yamux::{Config, Connection, Mode};
        use tokio_util::compat::TokioAsyncReadCompatExt;

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let config = Config::default();
            let io = server_io.compat();
            let mut connection = Connection::new(io, config, Mode::Server);
            while let Some(result) =
                std::future::poll_fn(|cx| connection.poll_next_inbound(cx)).await
            {
                let Ok(stream) = result else {
                    return;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    use tokio_util::compat::FuturesAsyncReadCompatExt;
                    let mut stream = stream.compat();
                    // Stream request: flags(2) + IPv4 socksaddr(7).
                    let mut req = [0u8; 9];
                    if stream.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    assert_eq!(
                        u16::from_be_bytes([req[0], req[1]]),
                        1,
                        "stream request must carry flagUDP"
                    );
                    if stream.write_all(&[0x00]).await.is_err() {
                        return;
                    }
                    loop {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut payload = vec![0u8; len];
                        if stream.read_exact(&mut payload).await.is_err() {
                            return;
                        }
                        let mut out = bytes::BytesMut::with_capacity(2 + len);
                        bytes::BufMut::put_u16(&mut out, len as u16);
                        out.extend_from_slice(&payload);
                        if stream.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let session = Arc::new(yamux::Session::client(client_io).unwrap());
        let yamux_stream = session.open_stream().await.unwrap();
        let mut stream = MuxStream::new(MuxStreamKind::Yamux(yamux_stream));
        stream
            .write_all(&address::encode_stream_request_with_flags("127.0.0.1", 53, 1).unwrap())
            .await
            .unwrap();
        let session_arc = Arc::new(MuxSession {
            kind: SessionKind::Yamux(session),
            streams: AtomicUsize::new(1),
            last_used_ms: AtomicU::new(0),
        });
        let conn = MuxPacketConn::new(
            stream,
            session_arc,
            "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
        );
        conn.write_packet(b"yamux-udp", &"127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 32];
        let (n, _src) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"yamux-udp");
        drop(server);
    }
    /// Regression: a pending read (no upstream datagram yet) must not
    /// head-of-line block writes — the SOCKS5 UDP relay reads on a
    /// separate task while the client keeps sending.
    #[tokio::test]
    async fn write_not_blocked_by_pending_read() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut io = server_io;
            let mut header = [0u8; 8];
            let mut sid = 0u32;
            let mut psh_count = 0u32;
            loop {
                if io.read_exact(&mut header).await.is_err() {
                    return;
                }
                let cmd = header[1];
                let length = u16::from_le_bytes([header[2], header[3]]) as usize;
                let frame_sid = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
                let mut payload = vec![0u8; length];
                if !payload.is_empty() && io.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let mut send = async |cmd: u8, data: &[u8]| {
                    let mut buf = bytes::BytesMut::with_capacity(8 + data.len());
                    bytes::BufMut::put_u8(&mut buf, 0x01);
                    bytes::BufMut::put_u8(&mut buf, cmd);
                    bytes::BufMut::put_u16_le(&mut buf, data.len() as u16);
                    bytes::BufMut::put_u32_le(&mut buf, sid);
                    buf.extend_from_slice(data);
                    io.write_all(&buf).await
                };
                match cmd {
                    0 => {
                        sid = frame_sid;
                    }
                    2 => {
                        psh_count += 1;
                        if psh_count == 2 {
                            // First datagram bytes arrived: release the
                            // blocked read with the stream response status.
                            let _ = send(2, &[0x00]).await;
                        }
                        if psh_count >= 2 {
                            // The length prefix and payload may be split
                            // across smux frames; echo the byte stream, not
                            // an assumed one-frame datagram.
                            let _ = send(2, &payload).await;
                        }
                        // First PSH (stream request): stay silent so the
                        // client's read blocks.
                    }
                    _ => {}
                }
            }
        });
        let session = Arc::new(smux::Session::client(client_io).unwrap());
        let smux_stream = session.open_stream().await.unwrap();
        let mut stream = MuxStream::new(MuxStreamKind::Smux(smux_stream));
        stream
            .write_all(&address::encode_stream_request_with_flags("127.0.0.1", 53, 1).unwrap())
            .await
            .unwrap();
        let session_arc = Arc::new(MuxSession {
            kind: SessionKind::Smux(session),
            streams: AtomicUsize::new(1),
            last_used_ms: AtomicU::new(0),
        });
        let conn = Arc::new(MuxPacketConn::new(
            stream,
            session_arc,
            "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
        ));
        let reader = Arc::clone(&conn);
        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            reader.read_packet(&mut buf).await.map(|(n, _)| n)
        });
        // Let the reader grab its half and park on the empty stream.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            conn.write_packet(b"x", &"127.0.0.1:53".parse().unwrap())
                .await
                .unwrap();
        })
        .await
        .expect("write must not block behind a pending read");
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), read_task)
            .await
            .expect("read must complete after the server responds")
            .unwrap()
            .unwrap();
        assert_eq!(n, 1);
        drop(server);
    }

    #[tokio::test]
    async fn cancelled_read_after_length_prefix_resumes_payload() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let (prefix_sent_tx, prefix_sent_rx) = tokio::sync::oneshot::channel();
        let (continue_tx, continue_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut sid = 0;
            for _ in 0..2 {
                let mut header = [0u8; 8];
                server_io.read_exact(&mut header).await.unwrap();
                sid = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
                let length = u16::from_le_bytes([header[2], header[3]]) as usize;
                let mut payload = vec![0u8; length];
                server_io.read_exact(&mut payload).await.unwrap();
            }

            let mut prefix = bytes::BytesMut::with_capacity(11);
            bytes::BufMut::put_u8(&mut prefix, 0x01);
            bytes::BufMut::put_u8(&mut prefix, 0x02);
            bytes::BufMut::put_u16_le(&mut prefix, 3);
            bytes::BufMut::put_u32_le(&mut prefix, sid);
            prefix.extend_from_slice(&[0x00, 0x00, 0x04]);
            server_io.write_all(&prefix).await.unwrap();
            let _ = prefix_sent_tx.send(());
            let _ = continue_rx.await;

            let mut payload = bytes::BytesMut::with_capacity(12);
            bytes::BufMut::put_u8(&mut payload, 0x01);
            bytes::BufMut::put_u8(&mut payload, 0x02);
            bytes::BufMut::put_u16_le(&mut payload, 4);
            bytes::BufMut::put_u32_le(&mut payload, sid);
            payload.extend_from_slice(b"pong");
            server_io.write_all(&payload).await.unwrap();
        });

        let session = Arc::new(smux::Session::client(client_io).unwrap());
        let smux_stream = session.open_stream().await.unwrap();
        let mut stream = MuxStream::new(MuxStreamKind::Smux(smux_stream));
        stream
            .write_all(&address::encode_stream_request_with_flags("127.0.0.1", 53, 1).unwrap())
            .await
            .unwrap();
        let session_arc = Arc::new(MuxSession {
            kind: SessionKind::Smux(session),
            streams: AtomicUsize::new(1),
            last_used_ms: AtomicU::new(0),
        });
        let conn = MuxPacketConn::new(
            stream,
            session_arc,
            "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
        );

        prefix_sent_rx.await.unwrap();
        let mut buf = [0u8; 8];
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            conn.read_datagram(&mut buf),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "the first read must wait for the payload"
        );

        continue_tx.send(()).unwrap();
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            conn.read_datagram(&mut buf),
        )
        .await
        .expect("the resumed read must complete")
        .unwrap();
        assert_eq!(&buf[..n], b"pong");
        server.await.unwrap();
    }

    /// Poll `write_datagram(data)` exactly once with a no-op waker and
    /// drop the future — a deterministic mid-write cancellation.  Returns
    /// the offset the writer parked at.
    fn cancel_one_write<W: tokio::io::AsyncWrite + Unpin>(
        writer: &mut PacketWriter<W>,
        data: &[u8],
    ) -> usize {
        use std::future::Future;
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut fut = Box::pin(writer.write_datagram(data));
        assert!(
            fut.as_mut().poll(&mut cx).is_pending(),
            "the write must park mid-frame for the cancellation test"
        );
        drop(fut);
        writer.pending.as_ref().expect("frame must survive").1
    }

    /// A retry with the same datagram resumes the cancelled frame: the
    /// peer sees exactly one well-formed frame, and the next datagram
    /// starts on a clean boundary.
    #[tokio::test]
    async fn cancelled_partial_write_resumes_with_same_data() {
        let (client, mut peer) = tokio::io::duplex(4);
        let mut writer = PacketWriter::new(client);
        // Frame is 6 bytes ([len u16][AAAA]); the 4-byte pipe takes the
        // first 4 and parks the write.
        assert_eq!(cancel_one_write(&mut writer, b"AAAA"), 4);
        let mut head = [0u8; 4];
        peer.read_exact(&mut head).await.unwrap();
        writer.write_datagram(b"AAAA").await.unwrap();
        let mut tail = [0u8; 2];
        peer.read_exact(&mut tail).await.unwrap();
        assert_eq!([head.as_slice(), &tail].concat(), b"\x00\x04AAAA");
        // Offset bookkeeping reset: the next datagram frames cleanly.
        writer.write_datagram(b"Z").await.unwrap();
        let mut next = [0u8; 3];
        peer.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"\x00\x01Z");
    }

    /// A *different* datagram after a cancelled partial write recovers
    /// instead of erroring (supersedes the issue #422 reject, which made
    /// every relay loop tear the UDP flow down): the stale frame is
    /// completed on the wire first — the cancelled datagram is delivered
    /// late rather than truncated — then the new datagram is framed and
    /// sent.  Two well-formed wire datagrams, correct framing for both.
    #[tokio::test]
    async fn cancelled_partial_write_different_data_completes_stale_then_sends_new() {
        let (client, mut peer) = tokio::io::duplex(4);
        let mut writer = PacketWriter::new(client);
        // Frame is 6 bytes ([len u16][AAAA]); the 4-byte pipe takes the
        // first 4 and parks the write mid-frame.
        assert_eq!(cancel_one_write(&mut writer, b"AAAA"), 4);
        // Drive the write and the peer read together: the stale tail
        // (2 bytes) plus the new frame (4 bytes) exceed the pipe.
        let mut wire = [0u8; 10];
        let (write_res, read_res) =
            tokio::join!(writer.write_datagram(b"BB"), peer.read_exact(&mut wire));
        write_res.unwrap();
        read_res.unwrap();
        assert_eq!(&wire, b"\x00\x04AAAA\x00\x02BB");
        // The writer is back on a clean frame boundary.
        writer.write_datagram(b"Z").await.unwrap();
        let mut next = [0u8; 3];
        peer.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"\x00\x01Z");
    }

    /// A cancelled write that never reached the wire (offset 0) has
    /// committed nothing: different data on the next call replaces the
    /// stale frame instead of erroring.
    #[tokio::test]
    async fn cancelled_unwritten_frame_replaced_by_new_data() {
        let (mut client, mut peer) = tokio::io::duplex(4);
        // Fill the pipe so the first write cannot make progress.
        client.write_all(&[0xEE; 4]).await.unwrap();
        let mut writer = PacketWriter::new(client);
        assert_eq!(cancel_one_write(&mut writer, b"AAAA"), 0);
        let mut filler = [0u8; 4];
        peer.read_exact(&mut filler).await.unwrap();
        writer.write_datagram(b"BB").await.unwrap();
        let mut frame = [0u8; 4];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x00\x02BB");
    }

    /// Live interop probe against a running sing-box VLESS mux inbound
    /// (127.0.0.1:4411) and the host UDP echo server
    /// (target/e2e/udp_echo.py on :18082).  Run with `--ignored` —
    /// requires both servers to be up.  Exercises the full UDP path:
    /// VLESS handshake → mux request header → flagUDP stream request →
    /// datagram framing → sing-box direct UDP relay → echo.
    #[tokio::test]
    #[ignore]
    #[cfg(all(feature = "mux", feature = "vless"))]
    async fn live_singbox_vless_udp_probe() {
        use crate::mux::{DialFn, MuxClient, MuxOptions, Protocol};
        use crate::vless::header::{Cmd, VlessAddr};
        use crate::vless::VlessConn;
        use crate::StreamConn;
        use meow_common::{MeowError, ProxyConn};

        // b831381d-6324-4d53-ad4f-8cda48b30811
        const UUID: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let dial: DialFn = Arc::new(move || {
            Box::pin(async move {
                let tcp = tokio::net::TcpStream::connect(("127.0.0.1", 4411))
                    .await
                    .map_err(MeowError::Io)?;
                let addr = VlessAddr::domain(super::super::MUX_DESTINATION_FQDN).unwrap();
                let conn = VlessConn::new(
                    Box::new(tcp),
                    &UUID,
                    None,
                    Cmd::Tcp,
                    super::super::MUX_DESTINATION_PORT,
                    &addr,
                )
                .await?;
                Ok(Box::new(StreamConn(Box::new(conn))) as Box<dyn ProxyConn>)
            })
        });
        let client = MuxClient::new(
            dial,
            MuxOptions {
                protocol: Protocol::H2Mux,
                ..MuxOptions::default()
            },
        );
        let conn = client.open_packet_stream("127.0.0.1", 18082).await.unwrap();
        conn.write_packet(b"ping-udp", &"127.0.0.1:18082".parse().unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, src) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping-udp");
        assert_eq!(src, "127.0.0.1:18082".parse::<SocketAddr>().unwrap());
    }
}
