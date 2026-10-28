//! Bounded encrypted-transport diagnostics. Wire prefixes require two compile gates.
use sha2::{Digest, Sha256};
use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
static NEXT: AtomicU64 = AtomicU64::new(1);
pub(crate) struct TracedSocket {
    inner: TcpStream,
    id: u64,
    sent: u64,
    received: u64,
    ended: bool,
    span: tracing::Span,
}
impl TracedSocket {
    pub(crate) fn new(inner: TcpStream) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let span = tracing::Span::current();
        if option_env!("PAWS_RAW_ENGINE_DIAGNOSTIC") == Some("1") {
            let peer = inner.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            let hash = Sha256::digest(peer.as_bytes());
            let peer = format!("{hash:x}");
            tracing::info!(id, peer=&peer[..16], local=?inner.local_addr(), "socket-trace event=connected");
        }
        Self {
            inner,
            id,
            sent: 0,
            received: 0,
            ended: false,
            span,
        }
    }
    fn event(&self, event: &str, amount: usize) {
        if option_env!("PAWS_RAW_ENGINE_DIAGNOSTIC") == Some("1") {
            self.span.in_scope(|| {
                tracing::info!(
                    id = self.id,
                    event,
                    amount,
                    sent = self.sent,
                    received = self.received,
                    peer_ended = self.ended,
                    tcp_info = %tcp_info(&self.inner),
                    "socket-trace"
                );
            });
        }
    }
}
impl AsyncRead for TracedSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut s.inner).poll_read(cx, buf);
        if let Poll::Ready(ref outcome) = result {
            let n = buf.filled().len() - before;
            let first = s.received == 0;
            s.received += n as u64;
            if let Err(e) = outcome {
                s.ended = e.kind() == io::ErrorKind::ConnectionReset;
                s.event(
                    if e.kind() == io::ErrorKind::ConnectionReset {
                        "peer-reset"
                    } else {
                        "read-error"
                    },
                    n,
                );
            } else if n == 0 && buf.remaining() > 0 {
                s.ended = true;
                s.event("peer-fin", 0);
            } else if first && n > 0 {
                s.event("first-read", n);
            }
        }
        result
    }
}
impl AsyncWrite for TracedSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let s = self.get_mut();
        let result = Pin::new(&mut s.inner).poll_write(cx, buf);
        match &result {
            Poll::Ready(Ok(n)) => {
                let first = s.sent == 0;
                let offset = s.sent;
                s.sent += *n as u64;
                if let Some((n, hex)) = wire_sample(
                    option_env!("PAWS_RAW_ENGINE_DIAGNOSTIC") == Some("1"),
                    option_env!("PAWS_SOCKET_WIRE_CAPTURE") == Some("1"),
                    offset,
                    buf,
                    *n,
                ) {
                    s.span.in_scope(|| {
                        tracing::info!(
                            id = s.id,
                            offset,
                            n,
                            hex = %hex,
                            "socket-trace event=wire-write-sample"
                        );
                    });
                }
                if first {
                    s.event("first-write", *n);
                }
            }
            Poll::Ready(Err(_)) => s.event("write-error", 0),
            _ => {}
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        s.event("local-shutdown", 0);
        Pin::new(&mut s.inner).poll_shutdown(cx)
    }
}
impl Drop for TracedSocket {
    fn drop(&mut self) {
        self.event("local-close", 0);
    }
}

// Capture only the successfully written prefix, including partial writes.
// The offset is the actual encrypted socket stream position, not a buffer offset.
fn wire_sample(
    raw: bool,
    wire: bool,
    offset: u64,
    buf: &[u8],
    written: usize,
) -> Option<(usize, String)> {
    const LIMIT: u64 = 2048;
    if !raw || !wire || offset >= LIMIT || written == 0 || written > buf.len() {
        return None;
    }
    let n = written.min((LIMIT - offset) as usize);
    let digits = b"0123456789abcdef";
    let mut hex = String::with_capacity(n * 2);
    for byte in &buf[..n] {
        hex.push(digits[(byte >> 4) as usize] as char);
        hex.push(digits[(byte & 15) as usize] as char);
    }
    Some((n, hex))
}

fn tcp_info(stream: &TcpStream) -> String {
    #[cfg(target_env = "ohos")]
    {
        use std::os::fd::AsRawFd;
        let mut info = [0u8; 256];
        let mut len = info.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                info.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc == 0 && len >= 104 {
            let read = |offset| u32::from_ne_bytes(info[offset..offset + 4].try_into().unwrap());
            return format!(
                "state:{} unacked:{} lost:{} retrans:{} rttUs:{} totalRetrans:{}",
                info[0],
                read(24),
                read(32),
                read(36),
                read(68),
                read(100)
            );
        }
    }
    let _ = stream;
    "unavailable".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn wire_prefix_requires_both_flags_and_only_includes_actual_successful_bytes() {
        let prepared = [0xde, 0xad, 0xbe, 0xef, 0x42];
        for (raw, wire) in [(false, false), (false, true), (true, false)] {
            assert!(wire_sample(raw, wire, 0, &prepared, 2).is_none());
        }
        assert_eq!(
            wire_sample(true, true, 0, &prepared, 2),
            Some((2, "dead".into()))
        );
        assert!(wire_sample(true, true, 0, &prepared, 0).is_none());
        assert!(wire_sample(true, true, 0, &prepared, 6).is_none());
    }
    #[test]
    fn wire_prefix_is_bounded_across_partial_writes_and_stream_offsets() {
        let prepared = vec![0xab; 4096];
        let (n, hex) = wire_sample(true, true, 0, &prepared, prepared.len()).unwrap();
        assert_eq!((n, hex.len()), (2048, 4096));
        assert_eq!(
            wire_sample(true, true, 2046, &prepared, 10),
            Some((2, "abab".into()))
        );
        assert!(wire_sample(true, true, 2048, &prepared, 10).is_none());
        assert!(wire_sample(true, true, u64::MAX, &prepared, 10).is_none());
    }
    #[tokio::test]
    async fn records_peer_eof_after_counting_actual_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut traced = TracedSocket::new(client);
        traced.write_all(b"request").await.unwrap();
        let mut request = [0; 7];
        peer.read_exact(&mut request).await.unwrap();
        peer.write_all(b"response").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut returned = Vec::new();
        traced.read_to_end(&mut returned).await.unwrap();
        assert_eq!((traced.sent, traced.received), (7, 8));
        assert!(traced.ended);
        assert_eq!(returned, b"response");
    }
    #[tokio::test]
    async fn local_half_close_is_not_reported_as_peer_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        let mut traced = TracedSocket::new(client);
        traced.shutdown().await.unwrap();
        assert!(!traced.ended);
    }
}
