//! sing-mux session padding (sagernet/sing-mux `padding.go`).
//!
//! With `padding: true` the client sends a version-1 request header with the
//! padding flag set, and then *both* ends wrap the physical connection in
//! this layer before the smux / yamux / h2mux session starts. The request
//! header itself is not framed. The first [`FIRST_PADDINGS`] writes in each
//! direction go out as
//!
//! ```text
//! [data_len u16 BE][padding_len u16 BE][data][padding_len bytes]
//! ```
//!
//! with `padding_len = 256 + rand(512)` and at most 65535 data bytes per
//! frame. Everything after that passes through unframed.

use rand::Rng;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Framed writes (and reads) per direction (`kFirstPaddings`).
pub const FIRST_PADDINGS: u8 = 16;
const HEADER_LEN: usize = 4;
/// Padding length is `PADDING_MIN + rand(PADDING_SPAN)`, i.e. 256..=767.
const PADDING_MIN: u16 = 256;
const PADDING_SPAN: u16 = 512;
/// Stack scratch for discarding inbound padding. A sing-mux peer pads at
/// most 767 bytes, so one read usually skips a whole frame's padding.
const SKIP_SCRATCH: usize = 1024;

/// A connection carrying a padded sing-mux session.
///
/// Writes are committed a frame at a time: a frame is built in an internal
/// buffer and reported as written once it is there, so a caller that
/// retries a `Pending` write with different bytes cannot tear or duplicate
/// a frame. The buffer is drained before new data is taken and on
/// flush/shutdown, and released once the padded phase is over.
pub struct PaddingConn<S> {
    inner: S,
    /// Frame headers parsed so far (`readPadding`).
    read_frames: u8,
    /// Header bytes collected across polls.
    read_header: [u8; HEADER_LEN],
    read_header_len: usize,
    /// Data bytes of the current frame not yet returned (`readRemaining`).
    read_remaining: usize,
    /// Padding bytes of the current frame not yet discarded
    /// (`paddingRemaining`).
    padding_remaining: usize,
    /// Frames committed so far (`writePadding`).
    write_frames: u8,
    /// Committed frame bytes; `write_pos` marks how far `inner` took them.
    write_buf: Vec<u8>,
    write_pos: usize,
}

impl<S> PaddingConn<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_frames: 0,
            read_header: [0; HEADER_LEN],
            read_header_len: 0,
            read_remaining: 0,
            padding_remaining: 0,
            write_frames: 0,
            write_buf: Vec::new(),
            write_pos: 0,
        }
    }
}

fn truncated(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("mux padding: connection closed inside a frame {what}"),
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for PaddingConn<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.read_remaining > 0 {
                let limit = this.read_remaining.min(buf.remaining());
                let mut data = ReadBuf::new(buf.initialize_unfilled_to(limit));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut data))?;
                let n = data.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(truncated("payload")));
                }
                buf.advance(n);
                this.read_remaining -= n;
                return Poll::Ready(Ok(()));
            }
            if this.padding_remaining > 0 {
                let mut scratch = [0u8; SKIP_SCRATCH];
                let limit = this.padding_remaining.min(SKIP_SCRATCH);
                let mut skip = ReadBuf::new(&mut scratch[..limit]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut skip))?;
                let n = skip.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(truncated("padding")));
                }
                this.padding_remaining -= n;
                continue;
            }
            if this.read_frames >= FIRST_PADDINGS {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            while this.read_header_len < HEADER_LEN {
                let mut header = ReadBuf::new(&mut this.read_header[this.read_header_len..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut header))?;
                let n = header.filled().len();
                if n == 0 {
                    // EOF on a frame boundary is a clean close.
                    return Poll::Ready(if this.read_header_len == 0 {
                        Ok(())
                    } else {
                        Err(truncated("header"))
                    });
                }
                this.read_header_len += n;
            }
            let [d0, d1, p0, p1] = this.read_header;
            this.read_header_len = 0;
            this.read_remaining = usize::from(u16::from_be_bytes([d0, d1]));
            this.padding_remaining = usize::from(u16::from_be_bytes([p0, p1]));
            this.read_frames += 1;
            // A zero-length frame must not surface as EOF: loop on to its
            // padding and the next frame.
        }
    }
}

impl<S: AsyncWrite + Unpin> PaddingConn<S> {
    /// Push committed frame bytes into `inner`.
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
        self.write_pos = 0;
        if self.write_frames >= FIRST_PADDINGS {
            // Padded phase over: no frame is ever built again.
            self.write_buf = Vec::new();
        } else {
            self.write_buf.clear();
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddingConn<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.write_frames >= FIRST_PADDINGS {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // sing-mux splits a larger write into 65535-byte frames; here each
        // poll commits one frame and the caller's write loop does the rest.
        let len = u16::try_from(buf.len()).unwrap_or(u16::MAX);
        let padding = PADDING_MIN + rand::rng().random_range(0..PADDING_SPAN);
        let frame_len = HEADER_LEN + usize::from(len) + usize::from(padding);
        this.write_buf.reserve(frame_len);
        this.write_buf.extend_from_slice(&len.to_be_bytes());
        this.write_buf.extend_from_slice(&padding.to_be_bytes());
        this.write_buf.extend_from_slice(&buf[..usize::from(len)]);
        this.write_buf.resize(frame_len, 0);
        this.write_frames += 1;
        // The frame is committed. Hand `inner` what it takes now; whatever
        // is left (Pending, or an error that recurs on retry) is drained by
        // the next write/flush/shutdown before anything else.
        let _ = this.poll_drain(cx);
        Poll::Ready(Ok(usize::from(len)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: meow_common::ProxyConn> meow_common::ProxyConn for PaddingConn<S> {
    fn remote_destination(&self) -> String {
        self.inner.remote_destination()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Waker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One padded frame as a sing-mux peer writes it.
    fn frame(data: &[u8], padding: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&padding.to_be_bytes());
        out.extend_from_slice(data);
        out.extend(std::iter::repeat_n(0xAA, usize::from(padding)));
        out
    }

    /// Split `FIRST_PADDINGS` frames off `wire`, asserting each header and
    /// padding; returns the frame payloads and the unframed tail.
    fn parse_frames(wire: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut frames = Vec::new();
        let mut rest = wire;
        for i in 0..FIRST_PADDINGS {
            assert!(rest.len() >= HEADER_LEN, "frame {i}: truncated header");
            let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
            let padding = u16::from_be_bytes([rest[2], rest[3]]);
            assert!(
                (256..=767).contains(&padding),
                "frame {i}: padding {padding} outside 256..=767"
            );
            let padding = usize::from(padding);
            assert!(rest.len() >= HEADER_LEN + len + padding, "frame {i}: short");
            frames.push(rest[HEADER_LEN..HEADER_LEN + len].to_vec());
            let pad = &rest[HEADER_LEN + len..HEADER_LEN + len + padding];
            assert!(pad.iter().all(|&b| b == 0), "frame {i}: padding not zeroed");
            rest = &rest[HEADER_LEN + len + padding..];
        }
        (frames, rest.to_vec())
    }

    /// Reader yielding one byte per ready poll, with a `Pending` between
    /// every byte, so each read-state field is carried across polls.
    struct Trickle {
        data: Vec<u8>,
        pos: usize,
        pend: bool,
    }

    impl AsyncRead for Trickle {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.pend = !this.pend;
            if this.pend {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if this.pos < this.data.len() {
                buf.put_slice(&this.data[this.pos..=this.pos]);
                this.pos += 1;
            }
            Poll::Ready(Ok(()))
        }
    }

    fn trickle(data: Vec<u8>) -> PaddingConn<Trickle> {
        PaddingConn::new(Trickle {
            data,
            pos: 0,
            pend: false,
        })
    }

    /// Writer accepting `budget` bytes, then `Pending` until refilled.
    struct Gated {
        wire: Vec<u8>,
        budget: usize,
    }

    impl AsyncWrite for Gated {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.budget == 0 {
                return Poll::Pending;
            }
            let n = buf.len().min(this.budget);
            this.budget -= n;
            this.wire.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn padded_write_is_byte_exact() {
        let mut conn = PaddingConn::new(Vec::new());
        for i in 0..FIRST_PADDINGS {
            conn.write_all(format!("msg-{i}").as_bytes()).await.unwrap();
        }
        conn.flush().await.unwrap();
        let wire = conn.inner;

        assert_eq!(&wire[..2], &5u16.to_be_bytes(), "data_len field");
        let padding = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
        assert_eq!(&wire[4..9], b"msg-0");
        assert!(wire[9..9 + padding].iter().all(|&b| b == 0));

        let (frames, tail) = parse_frames(&wire);
        for (i, data) in frames.iter().enumerate() {
            assert_eq!(data, format!("msg-{i}").as_bytes());
        }
        assert!(tail.is_empty(), "no bytes beyond the 16 frames");
    }

    #[tokio::test]
    async fn writes_pass_through_after_sixteen_frames() {
        let mut conn = PaddingConn::new(Vec::new());
        for i in 0..20u8 {
            conn.write_all(&[i; 3]).await.unwrap();
        }
        conn.flush().await.unwrap();
        assert_eq!(
            conn.write_buf.capacity(),
            0,
            "frame buffer released after the padded phase"
        );

        let (frames, tail) = parse_frames(&conn.inner);
        for (i, data) in (0u8..).zip(&frames) {
            assert_eq!(data, &[i; 3]);
        }
        let raw: Vec<u8> = (16u8..20).flat_map(|i| [i; 3]).collect();
        assert_eq!(tail, raw, "writes 17..20 go out unframed");
    }

    #[tokio::test]
    async fn large_write_is_split_into_u16_frames() {
        let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let mut conn = PaddingConn::new(Vec::new());

        let first = std::future::poll_fn(|cx| Pin::new(&mut conn).poll_write(cx, &payload))
            .await
            .unwrap();
        assert_eq!(first, 65_535, "one poll commits at most one frame");
        conn.write_all(&payload[first..]).await.unwrap();
        conn.flush().await.unwrap();

        let wire = &conn.inner;
        assert_eq!(&wire[..2], &u16::MAX.to_be_bytes());
        let pad0 = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
        let second = &wire[HEADER_LEN + 65_535 + pad0..];
        assert_eq!(&second[..2], &4_465u16.to_be_bytes());

        let mut reader = PaddingConn::new(wire.as_slice());
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, payload);
    }

    #[tokio::test]
    async fn reads_survive_one_byte_splits() {
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for i in 0..FIRST_PADDINGS {
            let data = format!("frame-{i}");
            wire.extend(frame(data.as_bytes(), 256 + u16::from(i) * 30));
            expected.extend_from_slice(data.as_bytes());
        }
        // Looks like a frame header, but frame 17 on is raw.
        wire.extend_from_slice(&[0x00, 0x04, 0x01, 0x00, b't', b'a', b'i', b'l']);
        expected.extend_from_slice(&[0x00, 0x04, 0x01, 0x00, b't', b'a', b'i', b'l']);

        let mut conn = trickle(wire);
        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, expected);
    }

    #[tokio::test]
    async fn zero_length_frame_is_not_eof() {
        let mut wire = frame(b"", 300);
        wire.extend(frame(b"after-empty", 256));
        let mut conn = trickle(wire);
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert!(n > 0, "the empty frame surfaced as EOF");
        assert_eq!(&buf[..n], &b"after-empty"[..n]);
        let mut out = buf[..n].to_vec();
        conn.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"after-empty");
        assert_eq!(conn.read_frames, 2, "the empty frame counts toward 16");
    }

    #[tokio::test]
    async fn truncated_frames_are_unexpected_eof() {
        let full = frame(b"payload", 300);
        for cut in [2, HEADER_LEN + 3, HEADER_LEN + 7 + 100] {
            let mut conn = PaddingConn::new(&full[..cut]);
            let mut out = Vec::new();
            let err = conn.read_to_end(&mut out).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "cut at {cut}");
        }
        let mut conn = PaddingConn::new(full.as_slice());
        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"payload", "EOF on a frame boundary is clean");
    }

    /// A `Pending` write followed by a retry with a different buffer: the
    /// bytes offered to the `Pending` call must never reach the wire, and
    /// the committed frame must go out exactly once.
    #[test]
    fn pending_write_retry_neither_tears_nor_duplicates() {
        let mut cx = Context::from_waker(Waker::noop());
        let mut conn = PaddingConn::new(Gated {
            wire: Vec::new(),
            budget: 10,
        });

        let first = Pin::new(&mut conn).poll_write(&mut cx, b"first");
        assert!(matches!(first, Poll::Ready(Ok(5))), "{first:?}");
        assert_eq!(conn.inner.wire.len(), 10, "frame partly on the wire");

        let blocked = Pin::new(&mut conn).poll_write(&mut cx, b"abandoned");
        assert!(blocked.is_pending());
        assert_eq!(conn.write_frames, 1, "a Pending write commits nothing");

        conn.inner.budget = usize::MAX;
        let retry = Pin::new(&mut conn).poll_write(&mut cx, b"retry");
        assert!(matches!(retry, Poll::Ready(Ok(5))), "{retry:?}");
        assert!(Pin::new(&mut conn).poll_flush(&mut cx).is_ready());

        let wire = &conn.inner.wire;
        let mut rest = wire.as_slice();
        for expected in [b"first".as_slice(), b"retry"] {
            let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
            let padding = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            assert_eq!(&rest[HEADER_LEN..HEADER_LEN + len], expected);
            rest = &rest[HEADER_LEN + len + padding..];
        }
        assert!(rest.is_empty(), "exactly two frames on the wire");
    }

    /// Two `PaddingConn`s over a small duplex pipe, well past the padded
    /// phase in both directions, including a >65535-byte write.
    #[tokio::test]
    async fn client_server_round_trip() {
        fn messages(seed: u8) -> Vec<Vec<u8>> {
            (0..40usize)
                .map(|i| {
                    let len = if i == 3 { 70_000 } else { 1 + i * 37 };
                    (0..len)
                        .map(|j| (j as u8).wrapping_mul(seed) ^ i as u8)
                        .collect()
                })
                .collect()
        }
        let (a, b) = tokio::io::duplex(97);
        let (client_rx, client_tx) = tokio::io::split(PaddingConn::new(a));
        let (server_rx, server_tx) = tokio::io::split(PaddingConn::new(b));
        let up = messages(3);
        let down = messages(7);
        let up_len: usize = up.iter().map(Vec::len).sum();
        let down_len: usize = down.iter().map(Vec::len).sum();

        let send = |mut tx: tokio::io::WriteHalf<_>, msgs: Vec<Vec<u8>>| async move {
            for msg in &msgs {
                tx.write_all(msg).await.unwrap();
                tx.flush().await.unwrap();
            }
            tx
        };
        let recv = |mut rx: tokio::io::ReadHalf<_>, len: usize| async move {
            let mut out = vec![0u8; len];
            rx.read_exact(&mut out).await.unwrap();
            out
        };
        let (_, _, got_up, got_down) = tokio::join!(
            send(client_tx, up.clone()),
            send(server_tx, down.clone()),
            recv(server_rx, up_len),
            recv(client_rx, down_len),
        );
        assert_eq!(got_up, up.concat());
        assert_eq!(got_down, down.concat());
    }
}
