//! B1 regression: packet 1 of an AnyTLS session must carry
//! [Settings + SYN + addr] as ONE atomic wire image — the client
//! fingerprint anytls-go pins by keeping `buffering` until the address
//! frame lands. The eager `self.buffer` drain inside `write_batch` used
//! to scatter the image across 1-3 nondeterministic packet groupings
//! depending on how the writer task's drains interleaved; a Flush
//! marker now sits behind the address frame in the session FIFO and its
//! drain clears `buffering`, flushing the accumulated image atomically.
//!
//! The recording transport below counts each `poll_write` call: on the
//! TLS transports this maps 1:1 to wire records, so "one write" == "one
//! packet" at the fingerprint level.

use anytls_rs::client::Client;
use anytls_rs::padding::PaddingFactory;
use anytls_rs::protocol::{Command, HEADER_OVERHEAD_SIZE};
use anytls_rs::session::Session;
use anytls_rs::util::{AnyTlsError, TlsConnect, TlsConnectFuture};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};
use tokio::net::TcpStream;

/// The client never touches its TLS hook on the on_tls path — a stub.
struct NoTls;

impl TlsConnect for NoTls {
    fn connect(&self, _tcp: TcpStream) -> TlsConnectFuture<'_> {
        Box::pin(async { Err(AnyTlsError::Protocol("NoTls stub".into())) })
    }
}

/// A duplex endpoint that records every `poll_write` buffer verbatim;
/// reads delegate to the peer so the session's recv_loop just parks.
struct RecordingStream {
    inner: DuplexStream,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl AsyncRead for RecordingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RecordingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.lock().unwrap().push(buf.to_vec());
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        // The recording must preserve per-call boundaries either way.
        let merged: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
        self.writes.lock().unwrap().push(merged);
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        false
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Decode `buf` into `(cmd, stream_id, payload)` triples.
fn decode_frames(buf: &[u8]) -> Vec<(Command, u32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = buf;
    while rest.len() >= HEADER_OVERHEAD_SIZE {
        let cmd = Command::from(rest[0]);
        let sid = u32::from_be_bytes(rest[1..5].try_into().unwrap());
        let len = u16::from_be_bytes([rest[5], rest[6]]) as usize;
        assert!(
            rest.len() >= HEADER_OVERHEAD_SIZE + len,
            "truncated frame: header len {len}, {} bytes left",
            rest.len()
        );
        out.push((
            cmd,
            sid,
            rest[HEADER_OVERHEAD_SIZE..HEADER_OVERHEAD_SIZE + len].to_vec(),
        ));
        rest = &rest[HEADER_OVERHEAD_SIZE + len..];
    }
    assert!(rest.is_empty(), "undecodable tail of {} bytes", rest.len());
    out
}

/// The expected SOCKS5-form address frame payload for host:port.
fn socks_addr(host: &str, port: u16) -> Vec<u8> {
    let mut v = vec![0x03, host.len() as u8];
    v.extend_from_slice(host.as_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v
}

/// Wait until `writes` holds at least `n` recorded calls.
async fn wait_writes(writes: &Arc<Mutex<Vec<Vec<u8>>>>, n: usize) -> Vec<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if writes.lock().unwrap().len() >= n {
                return writes.lock().unwrap().clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed out waiting for session writes")
}

fn client() -> Client {
    Client::new(
        "password",
        "unused.invalid:443".to_string(),
        Arc::new(NoTls),
        PaddingFactory::default(),
    )
}

/// Returns `(client_half, writes, server_peer)` — the peer must stay
/// bound for the session's lifetime: dropping it severs reads (recv_loop
/// exits → session closes) and makes writes fail.
fn recording() -> (RecordingStream, Arc<Mutex<Vec<Vec<u8>>>>, DuplexStream) {
    let (client_end, server_end) = duplex(64 * 1024);
    let writes = Arc::new(Mutex::new(Vec::new()));
    (
        RecordingStream {
            inner: client_end,
            writes: Arc::clone(&writes),
        },
        writes,
        server_end,
    )
}

/// Successful dial: after the one-shot auth record (write 0), the very
/// first session write must already be the atomic [Settings+SYN+addr]
/// image — possibly followed by a trailing `Waste` padding frame, but
/// never split across writes.
#[tokio::test]
async fn dial_flushes_settings_syn_addr_as_one_write() {
    let (stream, writes, _peer) = recording();

    let (_stream, session) = client()
        .create_proxy_stream_on_tls(stream, ("example.com".into(), 443))
        .await
        .expect("dial must succeed");

    let writes = wait_writes(&writes, 2).await;
    // writes[0] is the auth record (32 + 2 + 30 with the default scheme).
    assert_eq!(writes[0].len(), 32 + 2 + 30, "auth record");

    let frames = decode_frames(&writes[1]);
    assert!(
        frames.len() >= 3,
        "packet 1 must carry at least Settings+SYN+addr; got {frames:?}"
    );
    assert_eq!(frames[0].0, Command::Settings);
    assert_eq!(frames[0].1, 0);
    assert_eq!(frames[1].0, Command::Syn);
    assert_eq!(frames[2].0, Command::Push);
    assert_eq!(frames[2].1, frames[1].1, "addr rides the opened stream");
    assert_eq!(frames[2].2, socks_addr("example.com", 443));
    for (cmd, _, _) in &frames[3..] {
        assert_eq!(*cmd, Command::Waste, "only padding may trail: {frames:?}");
    }
    assert_eq!(
        writes.len(),
        2,
        "exactly two writes: auth, then the atomic first packet"
    );

    session.close().await.unwrap();
}

/// Cancelled dial: `Stream::close` enqueues a FIN whose drain also clears
/// `buffering` (existing FIN-marker arm), so [Settings+SYN+FIN] must
/// likewise reach the wire as one write.
#[tokio::test]
async fn cancelled_dial_flushes_settings_syn_fin_as_one_write() {
    let (stream, writes, _peer) = recording();

    // Manual session: new_client + start_client over the recording half;
    // the auth write (a `session_over_transport` step, private) is not
    // part of this path — writes[0] is the first packet directly.
    let (reader, writer) = tokio::io::split(stream);
    let session = Arc::new(Session::new_client(
        reader,
        writer,
        PaddingFactory::default().into_shared(),
        None,
    ));
    session.clone().start_client().await.unwrap();

    // The cancelled dial: SYN queued, FIN behind it, no Flush marker —
    // the FIN marker's own disable-buffering arm flushes the batch.
    let (stream, _synack_rx) = session.open_stream().await.unwrap();
    stream.close();

    let writes = wait_writes(&writes, 1).await;
    let frames = decode_frames(&writes[0]);
    assert!(
        frames.len() >= 3,
        "packet 1 must carry Settings+SYN+FIN; got {frames:?}"
    );
    assert_eq!(frames[0].0, Command::Settings);
    assert_eq!(frames[1].0, Command::Syn);
    assert_eq!(frames[2].0, Command::Fin);
    assert_eq!(frames[2].1, frames[1].1);

    session.close().await.unwrap();
}
