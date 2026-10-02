//! XTLS-Vision padding wrapper for VLESS.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use meow_common::ProxyConn;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::conn::VlessConn;

const UUID_LEN: usize = 16;
const PADDING_HEADER_LEN: usize = UUID_LEN + 1 + 2 + 2;
const COMMAND_PADDING_CONTINUE: u8 = 0x00;
const COMMAND_PADDING_END: u8 = 0x01;
const COMMAND_PADDING_DIRECT: u8 = 0x02;
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_MAJOR: u8 = 0x03;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_SERVER_HELLO: u8 = 0x02;
const TLS13_SUPPORTED_VERSIONS_EXT: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS13_CIPHER_SUITES: [u16; 4] = [0x1301, 0x1302, 0x1303, 0x1304];
const TLS_FILTER_PACKETS: usize = 8;

enum ReadState {
    Header {
        buf: Vec<u8>,
        need_uuid: bool,
    },
    /// Terminal clean EOF — latched so repeated `poll_read`s stay cheap and
    /// do not re-emit the mid-frame debug notes.
    Eof,
    Content {
        command: u8,
        remaining_content: usize,
        remaining_padding: usize,
    },
    Padding {
        command: u8,
        remaining_padding: usize,
    },
    Through,
}

struct PendingWrite {
    frame: Vec<u8>,
    pos: usize,
    consumed: usize,
    command: u8,
    end_padding_after_drain: bool,
}

pub struct VisionConn {
    inner: VlessConn,
    user_uuid: [u8; UUID_LEN],
    read_state: ReadState,
    write_pending: Option<PendingWrite>,
    write_padding: bool,
    write_sent_uuid: bool,
    write_seen_tls: bool,
    write_direct_enabled: bool,
    /// The transport can switch writes to raw (plain TLS or REALITY over
    /// the socket).  Without it the uplink ends padding with END, which a
    /// Vision server accepts, instead of DIRECT (issue #495).
    raw_write_capable: bool,
    read_tls_filter: ServerHelloFilter,
    vision_entered: bool,
}

impl VisionConn {
    pub fn new(mut inner: VlessConn, user_uuid: [u8; UUID_LEN]) -> Self {
        let raw_write_capable = inner.supports_raw_passthrough();
        Self {
            inner,
            user_uuid,
            read_state: ReadState::Header {
                buf: Vec::with_capacity(PADDING_HEADER_LEN),
                need_uuid: true,
            },
            write_pending: None,
            write_padding: true,
            write_sent_uuid: false,
            write_seen_tls: false,
            write_direct_enabled: false,
            raw_write_capable,
            read_tls_filter: ServerHelloFilter::new(),
            vision_entered: false,
        }
    }

    #[allow(dead_code)]
    pub fn vision_entered(&self) -> bool {
        self.vision_entered
    }

    fn drain_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>> {
        let Some(pending) = &mut self.write_pending else {
            return Poll::Ready(Ok(None));
        };

        while pending.pos < pending.frame.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &pending.frame[pending.pos..])? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vision: zero write during frame drain",
                    )));
                }
                Poll::Ready(n) => pending.pos += n,
            }
        }

        let pending = self.write_pending.take().expect("pending checked above");
        if pending.end_padding_after_drain {
            self.write_padding = false;
            if pending.command == COMMAND_PADDING_DIRECT {
                if !self.enable_inner_raw_write_passthrough() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "vision: DIRECT requested but transport cannot switch to raw passthrough",
                    )));
                }
                tracing::debug!("XTLS Vision direct write passthrough enabled");
            }
        }
        Poll::Ready(Ok(Some(pending.consumed)))
    }

    fn build_write_frame(&mut self, buf: &[u8]) {
        let contains_tls_handshake = contains_tls_client_hello(buf);
        let starts_tls_app_data =
            buf.len() >= 3 && buf[0] == TLS_APPLICATION_DATA && buf[1] == TLS_MAJOR;
        if contains_tls_handshake {
            self.write_seen_tls = true;
            self.vision_entered = true;
        }

        let padding_tls = self.write_seen_tls;
        let mut command = COMMAND_PADDING_CONTINUE;
        let mut end_after_drain = false;
        if starts_tls_app_data && self.write_seen_tls {
            command = if self.write_direct_enabled && self.raw_write_capable {
                COMMAND_PADDING_DIRECT
            } else {
                if self.write_direct_enabled {
                    tracing::debug!("XTLS Vision: transport cannot write raw, sending END");
                }
                COMMAND_PADDING_END
            };
            end_after_drain = true;
        } else if !self.write_seen_tls && !contains_tls_handshake {
            command = COMMAND_PADDING_END;
            end_after_drain = true;
        }

        let frame = build_padding_frame(
            command,
            (!self.write_sent_uuid).then_some(&self.user_uuid),
            buf,
            padding_tls,
        );
        tracing::debug!(
            command,
            content_len = buf.len(),
            frame_len = frame.len(),
            padding_tls,
            contains_tls_handshake,
            starts_tls_app_data,
            "XTLS Vision write padding"
        );
        self.write_sent_uuid = true;
        self.write_pending = Some(PendingWrite {
            frame,
            pos: 0,
            consumed: buf.len(),
            command,
            end_padding_after_drain: end_after_drain,
        });
    }

    fn enable_inner_raw_read_passthrough(&mut self) -> bool {
        self.inner.enable_raw_read_passthrough()
    }

    fn enable_inner_raw_write_passthrough(&mut self) -> bool {
        self.inner.enable_raw_write_passthrough()
    }

    fn filter_server_tls(&mut self, chunk: &[u8]) {
        if !self.write_direct_enabled && self.read_tls_filter.observe(chunk) {
            self.write_direct_enabled = true;
            tracing::debug!("XTLS Vision found TLS 1.3, direct enabled");
        }
    }
}

fn contains_tls_client_hello(buf: &[u8]) -> bool {
    buf.windows(6)
        .any(|w| w[0] == TLS_HANDSHAKE && w[1] == TLS_MAJOR && w[5] == TLS_CLIENT_HELLO)
}

struct ServerHelloFilter {
    packets_left: usize,
    expected_len: Option<usize>,
    buffer: Vec<u8>,
    done: bool,
}

impl ServerHelloFilter {
    fn new() -> Self {
        Self {
            packets_left: TLS_FILTER_PACKETS,
            expected_len: None,
            buffer: Vec::new(),
            done: false,
        }
    }

    fn observe(&mut self, chunk: &[u8]) -> bool {
        if self.done || self.packets_left == 0 || chunk.is_empty() {
            return false;
        }
        self.packets_left -= 1;

        if self.expected_len.is_none() {
            self.buffer.extend_from_slice(chunk);
            let Some(pos) = find_tls_server_hello_start(&self.buffer) else {
                return false;
            };
            if pos > 0 {
                self.buffer.drain(..pos);
            }
            let record_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
            self.expected_len = Some(5 + record_len);
        } else {
            self.buffer.extend_from_slice(chunk);
        }

        let expected_len = self.expected_len.unwrap_or(self.buffer.len());
        if self.buffer.len() < expected_len {
            return false;
        }

        self.done = true;
        let hello = &self.buffer[..expected_len];
        let Some(cipher) = tls_server_hello_cipher_suite(hello) else {
            return false;
        };
        TLS13_CIPHER_SUITES.contains(&cipher)
            && hello
                .windows(TLS13_SUPPORTED_VERSIONS_EXT.len())
                .any(|w| w == TLS13_SUPPORTED_VERSIONS_EXT)
    }
}

fn find_tls_server_hello_start(buf: &[u8]) -> Option<usize> {
    buf.windows(6).position(|w| {
        w[0] == TLS_HANDSHAKE && w[1] == TLS_MAJOR && w[2] == TLS_MAJOR && w[5] == TLS_SERVER_HELLO
    })
}

fn tls_server_hello_cipher_suite(record: &[u8]) -> Option<u16> {
    if record.len() < 46 || !matches!(find_tls_server_hello_start(record), Some(0)) {
        return None;
    }
    let session_id_len = *record.get(43)? as usize;
    let cipher_offset = 44 + session_id_len;
    let bytes = record.get(cipher_offset..cipher_offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn build_padding_frame(
    command: u8,
    user_uuid: Option<&[u8; UUID_LEN]>,
    content: &[u8],
    padding_tls: bool,
) -> Vec<u8> {
    let padding_len = if content.len() < 900 {
        let mut rng = rand::rng();
        if padding_tls {
            (rng.next_u32() as usize % 500) + 900 - content.len()
        } else {
            rng.next_u32() as usize % 256
        }
    } else {
        0
    };

    let header_len = if user_uuid.is_some() {
        PADDING_HEADER_LEN
    } else {
        PADDING_HEADER_LEN - UUID_LEN
    };
    let mut frame = Vec::with_capacity(header_len + content.len() + padding_len);
    if let Some(uuid) = user_uuid {
        frame.extend_from_slice(uuid);
    }
    frame.push(command);
    frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
    frame.extend_from_slice(content);
    frame.resize(frame.len() + padding_len, 0);
    frame
}

impl AsyncRead for VisionConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let state = std::mem::replace(&mut self.read_state, ReadState::Through);
            match state {
                ReadState::Eof => {
                    self.read_state = ReadState::Eof;
                    return Poll::Ready(Ok(()));
                }
                ReadState::Through => {
                    self.read_state = ReadState::Through;
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
                ReadState::Header {
                    buf: mut h,
                    need_uuid,
                } => {
                    let need = if need_uuid {
                        PADDING_HEADER_LEN
                    } else {
                        PADDING_HEADER_LEN - UUID_LEN
                    };
                    while h.len() < need {
                        let mut tmp = [0u8; PADDING_HEADER_LEN];
                        let want = (need - h.len()).min(tmp.len());
                        let mut rb = ReadBuf::new(&mut tmp[..want]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = ReadState::Header { buf: h, need_uuid };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = ReadState::Header { buf: h, need_uuid };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    // Vision has no end-of-stream marker: a
                                    // peer finishes by simply closing the
                                    // transport, possibly mid-padding. Xray
                                    // and mihomo surface this as io.EOF, so
                                    // report a clean EOF and let the relay
                                    // take the graceful shutdown path.
                                    if h.is_empty() && need_uuid {
                                        tracing::debug!(
                                            "vision: EOF before first padding \
                                             frame (server closed without data)"
                                        );
                                    } else if !h.is_empty() {
                                        tracing::debug!(
                                            partial = h.len(),
                                            need,
                                            "vision: EOF mid padding header \
                                             (treated as clean close)"
                                        );
                                    }
                                    self.read_state = ReadState::Eof;
                                    return Poll::Ready(Ok(()));
                                }
                                h.extend_from_slice(rb.filled());
                            }
                        }
                    }

                    let offset = if need_uuid {
                        if h[..UUID_LEN] != self.user_uuid {
                            self.read_state = ReadState::Header { buf: h, need_uuid };
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "vision: server responded with unknown UUID",
                            )));
                        }
                        UUID_LEN
                    } else {
                        0
                    };
                    let command = h[offset];
                    let content_len = u16::from_be_bytes([h[offset + 1], h[offset + 2]]) as usize;
                    let padding_len = u16::from_be_bytes([h[offset + 3], h[offset + 4]]) as usize;
                    tracing::debug!(
                        command,
                        content_len,
                        padding_len,
                        need_uuid,
                        "XTLS Vision read padding"
                    );
                    self.read_state = ReadState::Content {
                        command,
                        remaining_content: content_len,
                        remaining_padding: padding_len,
                    };
                }
                ReadState::Content {
                    command,
                    mut remaining_content,
                    remaining_padding,
                } => {
                    if remaining_content == 0 {
                        self.read_state = ReadState::Padding {
                            command,
                            remaining_padding,
                        };
                        continue;
                    }
                    if buf.remaining() == 0 {
                        self.read_state = ReadState::Content {
                            command,
                            remaining_content,
                            remaining_padding,
                        };
                        return Poll::Ready(Ok(()));
                    }

                    let mut tmp = vec![0u8; remaining_content.min(buf.remaining()).min(8192)];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => {
                            self.read_state = ReadState::Content {
                                command,
                                remaining_content,
                                remaining_padding,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.read_state = ReadState::Content {
                                command,
                                remaining_content,
                                remaining_padding,
                            };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                // See the Header-state EOF arm: a mid-frame
                                // FIN is still a clean close — the bytes
                                // already delivered remain valid.
                                tracing::debug!(
                                    command,
                                    remaining_content,
                                    "vision: EOF mid padded content \
                                     (treated as clean close)"
                                );
                                self.read_state = ReadState::Eof;
                                return Poll::Ready(Ok(()));
                            }
                            remaining_content -= n;
                            self.filter_server_tls(rb.filled());
                            buf.put_slice(rb.filled());
                            self.read_state = if remaining_content == 0 {
                                ReadState::Padding {
                                    command,
                                    remaining_padding,
                                }
                            } else {
                                ReadState::Content {
                                    command,
                                    remaining_content,
                                    remaining_padding,
                                }
                            };
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                ReadState::Padding {
                    command,
                    mut remaining_padding,
                } => {
                    while remaining_padding > 0 {
                        let mut tmp = [0u8; 1024];
                        let want = remaining_padding.min(tmp.len());
                        let mut rb = ReadBuf::new(&mut tmp[..want]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = ReadState::Padding {
                                    command,
                                    remaining_padding,
                                };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = ReadState::Padding {
                                    command,
                                    remaining_padding,
                                };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    tracing::debug!(
                                        command,
                                        remaining_padding,
                                        "vision: EOF mid padding \
                                         (treated as clean close)"
                                    );
                                    self.read_state = ReadState::Eof;
                                    return Poll::Ready(Ok(()));
                                }
                                remaining_padding -= n;
                            }
                        }
                    }

                    self.read_state = match command {
                        COMMAND_PADDING_CONTINUE => ReadState::Header {
                            buf: Vec::with_capacity(PADDING_HEADER_LEN - UUID_LEN),
                            need_uuid: false,
                        },
                        COMMAND_PADDING_END => ReadState::Through,
                        COMMAND_PADDING_DIRECT => {
                            if !self.enable_inner_raw_read_passthrough() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    "vision: server sent DIRECT but this transport cannot switch \
                                     reads to raw (Vision needs raw TCP with tls or REALITY)",
                                )));
                            }
                            tracing::debug!("XTLS Vision direct passthrough enabled");
                            ReadState::Through
                        }
                        other => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("vision: unknown padding command {other}"),
                            )));
                        }
                    };
                }
            }
        }
    }
}

impl AsyncWrite for VisionConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Poll::Ready(done) = this.drain_pending_write(cx) {
            if let Some(n) = done? {
                return Poll::Ready(Ok(n));
            }
        } else {
            return Poll::Pending;
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.write_padding {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // The padding frame carries u16 content/padding length fields:
        // chunk large writes so those fields cannot wrap and
        // desynchronise the peer's vision decoder.
        let chunk_len = buf.len().min(16 * 1024);
        this.build_write_frame(&buf[..chunk_len]);
        match this.drain_pending_write(cx) {
            Poll::Ready(Ok(Some(n))) => Poll::Ready(Ok(n)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(0)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Unpin for VisionConn {}

impl ProxyConn for VisionConn {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    const UUID: [u8; UUID_LEN] = [0x11; UUID_LEN];
    const CLIENT_HELLO: [u8; 6] = [TLS_HANDSHAKE, TLS_MAJOR, 0x01, 0x00, 0x01, TLS_CLIENT_HELLO];
    const APP_DATA: [u8; 7] = [
        TLS_APPLICATION_DATA,
        TLS_MAJOR,
        TLS_MAJOR,
        0x00,
        0x02,
        b'h',
        b'i',
    ];

    /// A Vision conn over an in-memory pipe, which (like ws, gRPC or VLESS
    /// encryption) cannot switch to raw writes.
    fn vision_over_pipe() -> (VisionConn, tokio::io::DuplexStream) {
        let (client, server) = duplex(64 * 1024);
        let vless = VlessConn {
            inner: Box::new(client),
            response_pending: true,
            response_buf: [0; 2],
            response_pos: 0,
            response_addon: Vec::new(),
            header_pending: None,
            header_needs_flush: false,
        };
        (VisionConn::new(vless, UUID), server)
    }

    async fn read_frame(server: &mut tokio::io::DuplexStream, with_uuid: bool) -> (u8, Vec<u8>) {
        if with_uuid {
            let mut uuid = [0u8; UUID_LEN];
            server.read_exact(&mut uuid).await.unwrap();
            assert_eq!(uuid, UUID);
        }
        let mut head = [0u8; PADDING_HEADER_LEN - UUID_LEN];
        server.read_exact(&mut head).await.unwrap();
        let mut content = vec![0u8; u16::from_be_bytes([head[1], head[2]]) as usize];
        server.read_exact(&mut content).await.unwrap();
        let mut padding = vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
        server.read_exact(&mut padding).await.unwrap();
        (head[0], content)
    }

    /// The Vision request plus a server frame carrying the target's TLS 1.3
    /// ServerHello, which arms DIRECT for the next app-data write.
    async fn handshake_with_tls13_target(
        conn: &mut VisionConn,
        server: &mut tokio::io::DuplexStream,
    ) {
        conn.write_all(&CLIENT_HELLO).await.unwrap();
        let hello = tls13_server_hello(0x1301);
        let mut downlink = vec![0x00, 0x00];
        downlink.extend(build_padding_frame(
            COMMAND_PADDING_CONTINUE,
            Some(&UUID),
            &hello,
            true,
        ));
        server.write_all(&downlink).await.unwrap();
        let mut got = vec![0u8; hello.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(got, hello);
        assert!(conn.write_direct_enabled);
    }

    #[tokio::test]
    async fn uplink_direct_needs_a_raw_capable_transport() {
        let (mut conn, _server) = vision_over_pipe();
        assert!(!conn.raw_write_capable);
        conn.write_seen_tls = true;
        conn.write_direct_enabled = true;

        conn.build_write_frame(&APP_DATA);
        let pending = conn.write_pending.take().unwrap();
        assert_eq!(pending.command, COMMAND_PADDING_END);
        assert!(pending.end_padding_after_drain);

        conn.raw_write_capable = true;
        conn.build_write_frame(&APP_DATA);
        let pending = conn.write_pending.take().unwrap();
        assert_eq!(pending.command, COMMAND_PADDING_DIRECT);
        assert!(pending.end_padding_after_drain);
    }

    /// Issue #495: a TLS 1.3 target over a transport that cannot write raw
    /// used to fail the first app-data write with "DIRECT requested but
    /// transport cannot switch".  It must end padding and carry on.
    #[tokio::test]
    async fn tls13_target_over_non_raw_transport_ends_padding() {
        let (mut conn, mut server) = vision_over_pipe();
        handshake_with_tls13_target(&mut conn, &mut server).await;

        conn.write_all(&APP_DATA).await.unwrap();
        conn.write_all(b"tail").await.unwrap();
        conn.flush().await.unwrap();

        assert_eq!(
            read_frame(&mut server, true).await,
            (COMMAND_PADDING_CONTINUE, CLIENT_HELLO.to_vec())
        );
        assert_eq!(
            read_frame(&mut server, false).await,
            (COMMAND_PADDING_END, APP_DATA.to_vec())
        );
        let mut tail = [0u8; 4];
        server.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"tail");
    }

    #[tokio::test]
    async fn downlink_direct_over_non_raw_transport_is_a_clear_error() {
        let (mut conn, mut server) = vision_over_pipe();
        handshake_with_tls13_target(&mut conn, &mut server).await;

        let direct = build_padding_frame(COMMAND_PADDING_DIRECT, None, &APP_DATA, true);
        server.write_all(&direct).await.unwrap();
        let mut got = [0u8; APP_DATA.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(got, APP_DATA);
        let err = conn.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    /// Vision has no end-of-stream frame: peers terminate by closing the
    /// transport, possibly while the downlink is still padded.  Xray and
    /// mihomo surface that as io.EOF; erroring here would make the relay
    /// skip the graceful half-close (shutdown + linger) and drop the
    /// inbound socket abruptly.
    #[tokio::test]
    async fn eof_between_padding_frames_is_a_clean_eof() {
        let (mut conn, mut server) = vision_over_pipe();
        let mut downlink = vec![0x00, 0x00];
        downlink.extend(build_padding_frame(
            COMMAND_PADDING_CONTINUE,
            Some(&UUID),
            b"payload",
            false,
        ));
        server.write_all(&downlink).await.unwrap();

        let mut got = [0u8; 7];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"payload");

        drop(server);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);
    }

    /// A server that closes after the bare VLESS response header — before
    /// any padding frame — is still a normal termination (born-dead conn).
    #[tokio::test]
    async fn eof_before_first_padding_frame_is_a_clean_eof() {
        let (mut conn, mut server) = vision_over_pipe();
        server.write_all(&[0x00, 0x00]).await.unwrap();
        drop(server);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);
    }

    /// A FIN landing mid-frame likewise ends the stream cleanly: the bytes
    /// already decoded are delivered and the next read observes EOF.
    #[tokio::test]
    async fn eof_mid_padded_content_is_a_clean_eof() {
        let (mut conn, mut server) = vision_over_pipe();
        let mut downlink = vec![0x00, 0x00];
        downlink.extend_from_slice(&UUID);
        downlink.push(COMMAND_PADDING_CONTINUE);
        downlink.extend_from_slice(&100u16.to_be_bytes()); // claims 100 B content
        downlink.extend_from_slice(&0u16.to_be_bytes()); // no padding
        downlink.extend_from_slice(b"only-7b");
        server.write_all(&downlink).await.unwrap();

        let mut got = [0u8; 7];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"only-7b");

        drop(server);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);
    }

    /// Same for a FIN landing mid-header: the partial header bytes are
    /// undeliverable framing, the conn still ends as a clean EOF.
    #[tokio::test]
    async fn eof_mid_padding_header_is_a_clean_eof() {
        let (mut conn, mut server) = vision_over_pipe();
        let mut downlink = vec![0x00, 0x00];
        downlink.extend_from_slice(&UUID);
        downlink.extend_from_slice(&[COMMAND_PADDING_CONTINUE, 0x00]); // 2 of 5 header bytes
        server.write_all(&downlink).await.unwrap();

        drop(server);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);
    }

    /// And mid-padding-bytes: all content was delivered, the truncated
    /// padding run still ends as clean EOF.
    #[tokio::test]
    async fn eof_mid_padding_bytes_is_a_clean_eof() {
        let (mut conn, mut server) = vision_over_pipe();
        let mut downlink = vec![0x00, 0x00];
        downlink.extend_from_slice(&UUID);
        downlink.push(COMMAND_PADDING_CONTINUE);
        downlink.extend_from_slice(&4u16.to_be_bytes()); // 4 B content
        downlink.extend_from_slice(&50u16.to_be_bytes()); // claims 50 B padding
        downlink.extend_from_slice(b"data");
        downlink.extend_from_slice(&[0u8; 20]); // only 20 of 50 padding bytes
        server.write_all(&downlink).await.unwrap();

        let mut got = [0u8; 4];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"data");

        drop(server);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);
    }

    /// EOF is latched: further reads stay EOF without re-emitting the
    /// mid-frame debug note.
    #[tokio::test]
    async fn eof_is_latched_for_repeated_reads() {
        let (mut conn, mut server) = vision_over_pipe();
        server.write_all(&[0x00, 0x00]).await.unwrap();
        drop(server);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(conn.read(&mut [0u8; 8]).await.unwrap(), 0);
    }

    #[test]
    fn padding_frame_with_uuid_matches_mihomo_layout() {
        let content = b"\x16\x03\x01\x00\x01\x01";
        let frame = build_padding_frame(COMMAND_PADDING_CONTINUE, Some(&UUID), content, true);

        assert_eq!(&frame[..UUID_LEN], &UUID);
        assert_eq!(frame[UUID_LEN], COMMAND_PADDING_CONTINUE);

        let content_len = u16::from_be_bytes([frame[UUID_LEN + 1], frame[UUID_LEN + 2]]) as usize;
        let padding_len = u16::from_be_bytes([frame[UUID_LEN + 3], frame[UUID_LEN + 4]]) as usize;

        assert_eq!(content_len, content.len());
        assert_eq!(
            &frame[PADDING_HEADER_LEN..PADDING_HEADER_LEN + content.len()],
            content
        );
        assert_eq!(
            frame.len(),
            PADDING_HEADER_LEN + content.len() + padding_len
        );
        assert!(padding_len >= 900 - content.len());
        assert!(padding_len < 1400 - content.len());
    }

    #[test]
    fn padding_frame_without_uuid_uses_short_header() {
        let content = b"abc";
        let frame = build_padding_frame(COMMAND_PADDING_END, None, content, false);

        assert_eq!(frame[0], COMMAND_PADDING_END);
        let content_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        let padding_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;

        assert_eq!(content_len, content.len());
        assert_eq!(&frame[5..8], content);
        assert_eq!(frame.len(), 5 + content.len() + padding_len);
        assert!(padding_len < 256);
    }

    #[test]
    fn detects_client_hello_inside_vless_prefixed_payload() {
        let mut payload = vec![0u8; 56];
        payload.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x01, 0x01]);

        assert!(contains_tls_client_hello(&payload));
        assert!(!contains_tls_client_hello(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn server_hello_filter_detects_tls13() {
        let mut filter = ServerHelloFilter::new();

        assert!(filter.observe(&tls13_server_hello(0x1301)));
    }

    #[test]
    fn server_hello_filter_handles_fragmented_record_header() {
        let hello = tls13_server_hello(0x1301);
        let mut filter = ServerHelloFilter::new();

        assert!(!filter.observe(&hello[..3]));
        assert!(filter.observe(&hello[3..]));
    }

    #[test]
    fn server_hello_filter_rejects_non_tls13_cipher() {
        let mut filter = ServerHelloFilter::new();

        assert!(!filter.observe(&tls13_server_hello(0xc02f)));
    }

    fn tls13_server_hello(cipher_suite: u16) -> Vec<u8> {
        let supported_versions = TLS13_SUPPORTED_VERSIONS_EXT;
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(0);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(supported_versions.len() as u16).to_be_bytes());
        body.extend_from_slice(&supported_versions);

        let mut handshake = Vec::new();
        handshake.push(TLS_SERVER_HELLO);
        handshake.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.extend_from_slice(&[
            TLS_HANDSHAKE,
            TLS_MAJOR,
            TLS_MAJOR,
            ((handshake.len() >> 8) & 0xff) as u8,
            (handshake.len() & 0xff) as u8,
        ]);
        record.extend_from_slice(&handshake);
        record
    }
}
