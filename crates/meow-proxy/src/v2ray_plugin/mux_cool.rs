//! Mux.Cool client framing for the built-in `v2ray-plugin` transport.
//!
//! An official `v2ray-plugin` server started with its default options
//! (`mux=1`) aims its inbound at `v1.mux.cool`, which makes v2ray-core
//! demultiplex every WebSocket connection as Mux.Cool; the upstream client,
//! also `mux=1` by default, frames its traffic to match. An unframed stream
//! fails there with `common/mux: invalid metalen`: the server reads the
//! Shadowsocks salt as a frame header.
//!
//! [`MuxCoolStream`] carries one sub-connection per WebSocket connection.
//! Shadowsocks already dials one connection per proxied flow, so there is
//! nothing to multiplex, only the framing to speak. That is why this does
//! not reuse `mux::muxcool`, the VLESS/VMess multiplexer: it runs a session
//! task with per-stream channels, and it sits behind the `mux` feature,
//! which the `minimal` build that ships `ss` leaves out.
//!
//! Written from the Mux.Cool specification (v2fly developer docs,
//! `protocols/muxcool`), v2ray-core's `common/mux` (`frame.go`,
//! `writer.go`, `client.go`) and v2ray-plugin's `main.go`, all MIT.
//!
//! # Wire format
//!
//! ```text
//! frame   = meta_len:u16be meta [data_len:u16be data]   ; data iff opt has D
//! meta    = id:u16be status:u8 opt:u8 [target]          ; target iff New
//! status  = 0x01 New | 0x02 Keep | 0x03 End | 0x04 KeepAlive
//! opt     = 0x01 D (carries data) | 0x02 E (session error)
//! target  = network:u8 (0x01 TCP) port:u16be atype:u8 (0x01 IPv4) address
//! ```
//!
//! # Sending
//!
//! The first write opens the session with a New frame that carries the
//! data, session id 1 (v2ray-core's client numbers sessions from 1). Its
//! target is TCP `127.0.0.1:0`, the bytes the upstream client sends: its
//! local inbound is a dokodemo-door with address `127.0.0.1` and no port,
//! and the mux client forwards that destination. The server never dials
//! it, as its freedom outbound overrides the destination with the
//! Shadowsocks server. Later writes are Keep frames of at most
//! [`MAX_PAYLOAD`] bytes.
//!
//! Shutdown sends End, which closes our half of the session; the server
//! keeps relaying the target's reply until the target closes, then sends
//! End back. The WebSocket under the session is shut down only once that
//! End has arrived (or the stream is dropped): a WebSocket close would make
//! the server stop writing and lose the reply still in flight.
//!
//! # Receiving
//!
//! Keep and End frames for our session deliver their data, and End is EOF.
//! KeepAlive frames and frames for any other session id are skipped along
//! with their data. The E option on our session, a metadata length outside
//! v2ray-core's 4..=512 and an unknown status are errors.
//!
//! # Copies
//!
//! Received data is read from the WebSocket straight into the caller's
//! buffer. A sent frame is assembled in one reused buffer, header and data
//! together, so that it leaves as one WebSocket message: writing the header
//! on its own would cost an extra message, with its own allocation and
//! header, per frame, more than the one slice copy of the data.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEP_ALIVE: u8 = 0x04;

const OPT_DATA: u8 = 0x01;
const OPT_ERROR: u8 = 0x02;

const NETWORK_TCP: u8 = 0x01;
const ATYPE_IPV4: u8 = 0x01;

/// Id of our one sub-connection.
const SESSION_ID: u16 = 1;
const SID: [u8; 2] = SESSION_ID.to_be_bytes();

/// Data bytes per sent frame: v2ray-core's writer splits stream data at
/// 8 KiB. A frame header plus this much data also fits one WebSocket
/// message.
pub(super) const MAX_PAYLOAD: usize = 8 * 1024;
const _: () = assert!(MAX_PAYLOAD <= u16::MAX as usize);

/// v2ray-core's bounds on the metadata length: shorter cannot hold id,
/// status and option, longer is `invalid metalen`.
const MIN_META: usize = 4;
const MAX_META: usize = 512;

/// New frame up to its data length: meta length 12, our id, New, D, then
/// the target TCP `127.0.0.1:0` (port before address).
const NEW_HEAD: [u8; 14] = [
    0,
    12,
    SID[0],
    SID[1],
    STATUS_NEW,
    OPT_DATA,
    NETWORK_TCP,
    0,
    0,
    ATYPE_IPV4,
    127,
    0,
    0,
    1,
];

/// Keep frame up to its data length.
const KEEP_HEAD: [u8; 6] = [0, 4, SID[0], SID[1], STATUS_KEEP, OPT_DATA];

/// End frame: no data.
const END_FRAME: [u8; 6] = [0, 4, SID[0], SID[1], STATUS_END, 0];

/// Room for the longest frame header: metadata length, metadata, data
/// length. Doubles as the scratch space for skipped data.
const HEADER_CAP: usize = 2 + MAX_META + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteState {
    /// Nothing sent: the first data frame is New.
    Idle,
    /// The session is open: data frames are Keep.
    Open,
    /// End is queued.
    Ending,
    /// End is flushed: our half of the session is closed.
    Ended,
    /// Shut down before any data: the server never saw a session, so there
    /// is nothing to End.
    Unopened,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    /// Assembling a frame header in `header[..header_len]`.
    Header,
    /// Inside a frame's data: `remaining` bytes go to the caller when
    /// `deliver`, are skipped otherwise; `end` (End frame data) means EOF
    /// follows.
    Data {
        remaining: usize,
        deliver: bool,
        end: bool,
    },
    /// The server ended our session, or closed the connection between
    /// frames.
    Eof,
    /// A framing or session error: the frame boundaries are lost.
    Failed(io::ErrorKind),
}

/// One Mux.Cool sub-connection over `inner` (the plugin's WebSocket).
pub(super) struct MuxCoolStream<S> {
    inner: S,
    /// The frame being handed to `inner`, sent up to `write_pos`. Reused
    /// for every frame.
    write_buf: Vec<u8>,
    write_pos: usize,
    write: WriteState,
    read: ReadState,
    /// The frame header read so far, `header_need` bytes wanted: 2 until the
    /// metadata length is known, then the metadata, then the data length
    /// when D is set.
    header: [u8; HEADER_CAP],
    header_len: usize,
    header_need: usize,
}

impl<S> MuxCoolStream<S> {
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner,
            write_buf: Vec::new(),
            write_pos: 0,
            write: WriteState::Idle,
            read: ReadState::Header,
            header: [0; HEADER_CAP],
            header_len: 0,
            header_need: 2,
        }
    }
}

fn fail<T>(read: &mut ReadState, kind: io::ErrorKind, msg: String) -> Poll<io::Result<T>> {
    *read = ReadState::Failed(kind);
    Poll::Ready(Err(io::Error::new(kind, msg)))
}

impl<S: AsyncRead + AsyncWrite + Unpin> MuxCoolStream<S> {
    /// Hand the queued frame to `inner`; on completion the buffer is
    /// emptied (its allocation kept for the next frame).
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_pos += n;
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Read until `header[..header_need]` is filled. `Ok(false)` is EOF
    /// before the first byte of a frame.
    fn poll_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        while self.header_len < self.header_need {
            let mut rb = ReadBuf::new(&mut self.header[self.header_len..self.header_need]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                if self.header_len == 0 {
                    return Poll::Ready(Ok(false));
                }
                return fail(
                    &mut self.read,
                    io::ErrorKind::UnexpectedEof,
                    "mux.cool: connection closed inside a frame header".into(),
                );
            }
            self.header_len += n;
        }
        Poll::Ready(Ok(true))
    }
}

/// What follows a complete frame header: `header` holds the metadata
/// length, `meta_end - 2` bytes of metadata and, with D, the data length.
fn after_header(header: &[u8; HEADER_CAP], meta_end: usize) -> io::Result<ReadState> {
    let session = u16::from_be_bytes([header[2], header[3]]);
    let status = header[4];
    let opt = header[5];
    let data_len = if opt & OPT_DATA == 0 {
        0
    } else {
        usize::from(u16::from_be_bytes([header[meta_end], header[meta_end + 1]]))
    };
    match status {
        STATUS_KEEP | STATUS_END if session == SESSION_ID => {
            if opt & OPT_ERROR != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "mux.cool: the server ended the session with an error",
                ));
            }
            let end = status == STATUS_END;
            Ok(if data_len > 0 {
                ReadState::Data {
                    remaining: data_len,
                    deliver: true,
                    end,
                }
            } else if end {
                ReadState::Eof
            } else {
                ReadState::Header
            })
        }
        // KeepAlive, another session's frames, or a New (which a server
        // must not send): skipped, data and all.
        STATUS_NEW | STATUS_KEEP | STATUS_END | STATUS_KEEP_ALIVE => Ok(if data_len > 0 {
            ReadState::Data {
                remaining: data_len,
                deliver: false,
                end: false,
            }
        } else {
            ReadState::Header
        }),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("mux.cool: unknown session status {other:#04x}"),
        )),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MuxCoolStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A frame left queued by a busy WebSocket must not wait for the next
        // write: a caller that sent its request and now only reads would
        // wait forever. A write error shows on the next write or flush.
        if this.write_pos < this.write_buf.len() {
            let _ = this.poll_drain(cx);
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match this.read {
                ReadState::Eof => return Poll::Ready(Ok(())),
                ReadState::Failed(kind) => {
                    return Poll::Ready(Err(io::Error::new(
                        kind,
                        "mux.cool: session unusable after an earlier error",
                    )));
                }
                ReadState::Data {
                    remaining,
                    deliver: true,
                    end,
                } => {
                    let limit = remaining.min(buf.remaining());
                    let n = {
                        let mut data = ReadBuf::new(buf.initialize_unfilled_to(limit));
                        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut data))?;
                        data.filled().len()
                    };
                    if n == 0 {
                        return fail(
                            &mut this.read,
                            io::ErrorKind::UnexpectedEof,
                            "mux.cool: connection closed inside frame data".into(),
                        );
                    }
                    buf.advance(n);
                    this.read = match remaining - n {
                        0 if end => ReadState::Eof,
                        0 => ReadState::Header,
                        remaining => ReadState::Data {
                            remaining,
                            deliver: true,
                            end,
                        },
                    };
                    return Poll::Ready(Ok(()));
                }
                ReadState::Data {
                    remaining,
                    deliver: false,
                    ..
                } => {
                    // The header buffer is free while inside data.
                    let limit = remaining.min(HEADER_CAP);
                    let mut skip = ReadBuf::new(&mut this.header[..limit]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut skip))?;
                    let n = skip.filled().len();
                    if n == 0 {
                        return fail(
                            &mut this.read,
                            io::ErrorKind::UnexpectedEof,
                            "mux.cool: connection closed inside frame data".into(),
                        );
                    }
                    this.read = if remaining == n {
                        ReadState::Header
                    } else {
                        ReadState::Data {
                            remaining: remaining - n,
                            deliver: false,
                            end: false,
                        }
                    };
                }
                ReadState::Header => {
                    if !ready!(this.poll_header(cx))? {
                        this.read = ReadState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    let meta_len =
                        usize::from(u16::from_be_bytes([this.header[0], this.header[1]]));
                    let meta_end = 2 + meta_len;
                    if this.header_need == 2 {
                        if !(MIN_META..=MAX_META).contains(&meta_len) {
                            return fail(
                                &mut this.read,
                                io::ErrorKind::InvalidData,
                                format!("mux.cool: invalid metadata length {meta_len}"),
                            );
                        }
                        this.header_need = meta_end;
                    } else if this.header_need == meta_end && this.header[5] & OPT_DATA != 0 {
                        // D is set: the data length follows the metadata.
                        this.header_need += 2;
                    } else {
                        this.header_len = 0;
                        this.header_need = 2;
                        match after_header(&this.header, meta_end) {
                            Ok(next) => this.read = next,
                            Err(e) => {
                                this.read = ReadState::Failed(e.kind());
                                return Poll::Ready(Err(e));
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MuxCoolStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let head: &[u8] = match this.write {
            WriteState::Idle => &NEW_HEAD,
            WriteState::Open => &KEEP_HEAD,
            WriteState::Ending | WriteState::Ended | WriteState::Unopened => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux.cool: write after shutdown",
                )));
            }
        };
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_PAYLOAD);
        // Lossless: MAX_PAYLOAD fits a u16 (asserted where it is defined).
        let len = (n as u16).to_be_bytes();
        this.write_buf.extend_from_slice(head);
        this.write_buf.extend_from_slice(&len);
        this.write_buf.extend_from_slice(&buf[..n]);
        this.write = WriteState::Open;
        // Hand the frame on now. If the WebSocket is busy it stays queued
        // for the next write, flush or read, which drain it first.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.write {
                WriteState::Idle => this.write = WriteState::Unopened,
                WriteState::Unopened => return Pin::new(&mut this.inner).poll_shutdown(cx),
                WriteState::Open => {
                    ready!(this.poll_drain(cx))?;
                    this.write_buf.extend_from_slice(&END_FRAME);
                    this.write = WriteState::Ending;
                }
                WriteState::Ending => {
                    ready!(this.poll_drain(cx))?;
                    ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                    this.write = WriteState::Ended;
                }
                WriteState::Ended => {
                    // Close the WebSocket only once the server's half is
                    // over too; until then its reply is still coming.
                    if matches!(this.read, ReadState::Eof | ReadState::Failed(_)) {
                        return Pin::new(&mut this.inner).poll_shutdown(cx);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::task::Waker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Scripted inner stream. Reads serve `chunks` in order, one chunk (or
    /// as much of it as fits) per read, then EOF; writes are recorded.
    #[derive(Default)]
    struct Mock {
        chunks: VecDeque<Vec<u8>>,
        /// Return Pending once before every read.
        stall_reads: bool,
        read_stalled: bool,
        written: Vec<u8>,
        /// Accept at most this many bytes per write (0: no limit).
        write_max: usize,
        /// Return Pending once before every write.
        stall_writes: bool,
        write_stalled: bool,
        shut_down: bool,
    }

    impl Mock {
        fn reading(chunks: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into_iter().filter(|c| !c.is_empty()).collect(),
                ..Self::default()
            }
        }
    }

    impl AsyncRead for Mock {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.stall_reads && !self.read_stalled {
                self.read_stalled = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.read_stalled = false;
            if let Some(mut chunk) = self.chunks.pop_front() {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    chunk.drain(..n);
                    self.chunks.push_front(chunk);
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Mock {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.stall_writes && !self.write_stalled {
                self.write_stalled = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.write_stalled = false;
            let n = match self.write_max {
                0 => buf.len(),
                max => buf.len().min(max),
            };
            self.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shut_down = true;
            Poll::Ready(Ok(()))
        }
    }

    /// A frame as a server would send it; `data` sets D.
    fn frame(session: u16, status: u8, opt: u8, data: Option<&[u8]>) -> Vec<u8> {
        let mut f = vec![0, 4];
        f.extend_from_slice(&session.to_be_bytes());
        f.push(status);
        f.push(opt | if data.is_some() { OPT_DATA } else { 0 });
        if let Some(data) = data {
            f.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            f.extend_from_slice(data);
        }
        f
    }

    fn keep(data: &[u8]) -> Vec<u8> {
        frame(SESSION_ID, STATUS_KEEP, 0, Some(data))
    }

    fn end() -> Vec<u8> {
        frame(SESSION_ID, STATUS_END, 0, None)
    }

    /// Split what the client wrote into (status, data) per frame, checking
    /// every frame's id and the New target on the way.
    fn sent_frames(mut wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut frames = Vec::new();
        while !wire.is_empty() {
            let meta_len = usize::from(u16::from_be_bytes([wire[0], wire[1]]));
            let meta = &wire[2..2 + meta_len];
            assert_eq!(u16::from_be_bytes([meta[0], meta[1]]), SESSION_ID);
            let (status, opt) = (meta[2], meta[3]);
            if status == STATUS_NEW {
                assert_eq!(&meta[4..], &[NETWORK_TCP, 0, 0, ATYPE_IPV4, 127, 0, 0, 1]);
            } else {
                assert_eq!(meta_len, 4);
            }
            wire = &wire[2 + meta_len..];
            let mut data = Vec::new();
            if opt & OPT_DATA != 0 {
                let len = usize::from(u16::from_be_bytes([wire[0], wire[1]]));
                data.extend_from_slice(&wire[2..2 + len]);
                wire = &wire[2 + len..];
            }
            frames.push((status, data));
        }
        frames
    }

    fn sent_data(frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
        frames.iter().flat_map(|(_, d)| d.iter().copied()).collect()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[tokio::test]
    async fn first_write_is_new_with_data_then_keep() {
        let mut s = MuxCoolStream::new(Mock::default());
        s.write_all(b"hello").await.unwrap();
        s.write_all(b"ab").await.unwrap();
        let mut want = vec![0, 12, 0, 1, 1, 1, 1, 0, 0, 1, 127, 0, 0, 1, 0, 5];
        want.extend_from_slice(b"hello");
        want.extend_from_slice(&[0, 4, 0, 1, 2, 1, 0, 2]);
        want.extend_from_slice(b"ab");
        assert_eq!(s.inner.written, want);
    }

    #[tokio::test]
    async fn writes_are_split_at_max_payload() {
        let data = pattern(2 * MAX_PAYLOAD + 100);
        let mut s = MuxCoolStream::new(Mock::default());
        s.write_all(&data).await.unwrap();
        let frames = sent_frames(&s.inner.written);
        let shape: Vec<(u8, usize)> = frames.iter().map(|(st, d)| (*st, d.len())).collect();
        assert_eq!(
            shape,
            [
                (STATUS_NEW, MAX_PAYLOAD),
                (STATUS_KEEP, MAX_PAYLOAD),
                (STATUS_KEEP, 100)
            ]
        );
        assert_eq!(sent_data(&frames), data);
    }

    /// A WebSocket that takes three bytes at a time and is busy every
    /// other call still gets whole, ordered frames.
    #[tokio::test]
    async fn frames_survive_a_slow_inner_stream() {
        let data = pattern(3 * MAX_PAYLOAD);
        let mut s = MuxCoolStream::new(Mock {
            write_max: 3,
            stall_writes: true,
            ..Mock::default()
        });
        for piece in data.chunks(1000) {
            s.write_all(piece).await.unwrap();
        }
        s.shutdown().await.unwrap();
        let frames = sent_frames(&s.inner.written);
        assert_eq!(frames.first().unwrap().0, STATUS_NEW);
        assert_eq!(frames.last().unwrap(), &(STATUS_END, Vec::new()));
        assert_eq!(sent_data(&frames), data);
    }

    /// A frame the WebSocket could not take yet goes out on the next read:
    /// a caller that wrote its request and then only reads must not stall.
    #[test]
    fn queued_frame_is_drained_by_a_read() {
        let mut s = MuxCoolStream::new(Mock {
            stall_writes: true,
            ..Mock::reading([end()])
        });
        let mut cx = Context::from_waker(Waker::noop());
        let n = Pin::new(&mut s).poll_write(&mut cx, b"request");
        assert!(matches!(n, Poll::Ready(Ok(7))), "{n:?}");
        assert!(
            s.inner.written.is_empty(),
            "the busy WebSocket took nothing"
        );
        let mut buf = [0u8; 16];
        let mut rb = ReadBuf::new(&mut buf);
        assert!(matches!(
            Pin::new(&mut s).poll_read(&mut cx, &mut rb),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            sent_frames(&s.inner.written),
            [(STATUS_NEW, b"request".to_vec())]
        );
    }

    /// Shutdown ends our half of the session; the reply still arrives, and
    /// the WebSocket closes only after the server's End.
    #[tokio::test]
    async fn shutdown_sends_end_and_keeps_reading_the_reply() {
        let mut s = MuxCoolStream::new(Mock::reading([keep(b"reply"), end()]));
        s.write_all(b"x").await.unwrap();
        s.shutdown().await.unwrap();
        assert!(s.inner.written.ends_with(&END_FRAME));
        assert!(!s.inner.shut_down, "the reply is still on its way");
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
        s.shutdown().await.unwrap();
        assert!(s.inner.shut_down);
        assert_eq!(
            sent_frames(&s.inner.written),
            [(STATUS_NEW, b"x".to_vec()), (STATUS_END, Vec::new())]
        );
    }

    #[tokio::test]
    async fn shutdown_after_the_server_ended_closes_the_websocket() {
        let mut s = MuxCoolStream::new(Mock::reading([keep(b"bye"), end()]));
        s.write_all(b"x").await.unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"bye");
        s.shutdown().await.unwrap();
        assert!(s.inner.written.ends_with(&END_FRAME));
        assert!(s.inner.shut_down);
    }

    #[tokio::test]
    async fn shutdown_before_any_write_sends_no_frame() {
        let mut s = MuxCoolStream::new(Mock::default());
        s.shutdown().await.unwrap();
        assert!(s.inner.written.is_empty());
        assert!(s.inner.shut_down);
        let err = s.write_all(b"late").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn write_after_shutdown_is_a_broken_pipe() {
        let mut s = MuxCoolStream::new(Mock::default());
        s.write_all(b"x").await.unwrap();
        s.shutdown().await.unwrap();
        let err = s.write_all(b"late").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// What a server may interleave with our data: KeepAlives with and
    /// without data, another session's frames (an error End included), a
    /// New, and a zero-length data frame of ours. Returns the wire bytes
    /// and the data the caller must see.
    fn busy_reply() -> (Vec<u8>, Vec<u8>) {
        let wire = [
            frame(0, STATUS_KEEP_ALIVE, 0, None),
            frame(7, STATUS_KEEP_ALIVE, 0, Some(b"ping")),
            frame(2, STATUS_KEEP, 0, Some(b"not ours")),
            keep(b"hello "),
            frame(2, STATUS_END, OPT_ERROR, None),
            keep(b""),
            frame(SESSION_ID, STATUS_NEW, 0, Some(b"no New from a server")),
            keep(&pattern(1000)),
            frame(3, STATUS_END, 0, Some(b"bye from 3")),
            keep(b"world"),
            end(),
            // Past our End: never read.
            keep(b"after the end"),
        ]
        .concat();
        let mut want = b"hello ".to_vec();
        want.extend_from_slice(&pattern(1000));
        want.extend_from_slice(b"world");
        (wire, want)
    }

    async fn read_all(mock: Mock) -> io::Result<Vec<u8>> {
        let mut s = MuxCoolStream::new(mock);
        let mut out = Vec::new();
        s.read_to_end(&mut out).await?;
        Ok(out)
    }

    #[tokio::test]
    async fn read_survives_a_split_at_every_byte_boundary() {
        let (wire, want) = busy_reply();
        for cut in 0..=wire.len() {
            let mock = Mock {
                stall_reads: true,
                ..Mock::reading([wire[..cut].to_vec(), wire[cut..].to_vec()])
            };
            assert_eq!(read_all(mock).await.unwrap(), want, "cut at {cut}");
        }
    }

    #[tokio::test]
    async fn read_survives_one_byte_at_a_time() {
        let (wire, want) = busy_reply();
        let mock = Mock {
            stall_reads: true,
            ..Mock::reading(wire.iter().map(|b| vec![*b]))
        };
        assert_eq!(read_all(mock).await.unwrap(), want);
    }

    #[tokio::test]
    async fn read_into_a_small_buffer() {
        let (wire, want) = busy_reply();
        let mut s = MuxCoolStream::new(Mock::reading([wire]));
        let mut out = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, want);
    }

    #[tokio::test]
    async fn end_with_data_delivers_it_then_eof() {
        let wire = [keep(b"a"), frame(SESSION_ID, STATUS_END, 0, Some(b"bc"))].concat();
        assert_eq!(read_all(Mock::reading([wire])).await.unwrap(), b"abc");
    }

    #[tokio::test]
    async fn connection_closed_between_frames_is_eof() {
        assert_eq!(read_all(Mock::reading([keep(b"a")])).await.unwrap(), b"a");
        assert!(read_all(Mock::default()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn connection_closed_inside_a_frame_is_unexpected_eof() {
        let whole = keep(b"abc");
        for cut in 1..whole.len() {
            let err = read_all(Mock::reading([whole[..cut].to_vec()]))
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "cut at {cut}");
        }
    }

    #[tokio::test]
    async fn error_option_on_our_session_fails_the_read() {
        for bad in [
            frame(SESSION_ID, STATUS_END, OPT_ERROR, None),
            frame(SESSION_ID, STATUS_KEEP, OPT_ERROR, Some(b"x")),
        ] {
            let mut s = MuxCoolStream::new(Mock::reading([keep(b"a"), bad]));
            let mut out = Vec::new();
            let err = s.read_to_end(&mut out).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
            assert_eq!(out, b"a");
            let mut buf = [0u8; 4];
            let again = s.read(&mut buf).await.unwrap_err();
            assert_eq!(again.kind(), io::ErrorKind::ConnectionReset);
        }
    }

    #[tokio::test]
    async fn malformed_metadata_length_is_rejected() {
        for meta_len in [0u16, 3, 513, u16::MAX] {
            let mut wire = meta_len.to_be_bytes().to_vec();
            wire.extend_from_slice(&[0; 600]);
            let err = read_all(Mock::reading([wire])).await.unwrap_err();
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "meta_len {meta_len}"
            );
        }
        // 512 itself is fine: a Keep padded with metadata bytes v2ray-core
        // ignores still parses.
        let mut wire = 512u16.to_be_bytes().to_vec();
        wire.extend_from_slice(&[0, 1, STATUS_KEEP, OPT_DATA]);
        wire.extend_from_slice(&[0; 508]);
        wire.extend_from_slice(&[0, 2]);
        wire.extend_from_slice(b"ok");
        assert_eq!(read_all(Mock::reading([wire])).await.unwrap(), b"ok");
    }

    #[tokio::test]
    async fn unknown_status_is_rejected() {
        let wire = frame(SESSION_ID, 0x05, 0, None);
        let err = read_all(Mock::reading([wire])).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
