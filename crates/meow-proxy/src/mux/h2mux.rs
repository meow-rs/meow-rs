//! h2mux protocol (mihomo default), client side.
//!
//! Mirrors metacubex/sing-mux h2mux.go: the physical connection runs an
//! HTTP/2 client after the mux request header; each logical stream is one
//! CONNECT request to `https://localhost`.  The request body carries
//! client→server bytes as h2 DATA frames, the response body carries
//! server→client bytes.  No gun/grpc framing — raw passthrough.
//!
//! The response is resolved lazily on the first read, mirroring sing-mux's
//! lateHTTPConn: sing-box's h2mux server defers flushing the 200 headers
//! until its first response-body write, so awaiting the response before
//! returning the stream would deadlock (the server waits for our data
//! before it ever writes).

use bytes::Bytes;
use http::{Method, Request, StatusCode, Version};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

pub use meow_transport::h2_common::H2Stream as Stream;
use meow_transport::h2_common::{RecvState, StatusPolicy};

/// Timeout for the CONNECT response; mirrors sing-mux's `TCPTimeout`
/// (5 s).  The deadline is armed when the stream is opened, but it is
/// only *checked* while a read is being polled (`RecvState` resolves the
/// response lazily on the first read), so a stream that is never read
/// never times out.  On expiry the read side fails with TimedOut (the
/// caller tears the stream down).
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for acquiring send readiness (h2 `poll_ready`).  Without this,
/// a peer whose `SETTINGS_MAX_CONCURRENT_STREAMS` is exhausted can park
/// `open_stream` indefinitely — `RESPONSE_TIMEOUT` only covers the
/// response, not the open.  Mirrors `SESSION_SETUP_TIMEOUT` (5 s).
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// h2mux session over one physical connection (client role).  The concrete
/// IO type is erased — the driver task owns the h2 connection.
pub struct Session {
    send_request: h2::client::SendRequest<Bytes>,
    dead: Arc<AtomicBool>,
    _task: tokio::task::JoinHandle<()>,
}

impl Session {
    pub async fn client<S>(io: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Proxy-sized receive windows (4 MiB / stream, 16 MiB / connection)
        // instead of h2's 64 KiB default — see
        // `meow_transport::h2_common::client_builder`.
        let (send_request, connection) = meow_transport::h2_common::client_builder()
            .handshake::<_, Bytes>(io)
            .await
            .map_err(io::Error::other)?;
        let dead = Arc::new(AtomicBool::new(false));
        let driver_dead = Arc::clone(&dead);
        // Drive SETTINGS / WINDOW_UPDATE / PING frames; the future resolves
        // when the physical connection dies.
        let task = tokio::spawn(async move {
            let _ = connection.await;
            driver_dead.store(true, Ordering::SeqCst);
        });
        Ok(Self {
            send_request,
            dead,
            _task: task,
        })
    }

    /// Open one h2mux stream: a CONNECT request whose body/response body
    /// form the duplex channel.  Returns immediately — the server may not
    /// flush its 200 until the first response-body write (see module docs).
    pub async fn open_stream(&self) -> io::Result<Stream> {
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://localhost")
            .version(Version::HTTP_2)
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut send_request = self.send_request.clone();
        // h2 requires poll_ready/ready before send_request: sending
        // without readiness violates the documented contract and is
        // rejected once MAX_CONCURRENT_STREAMS is exhausted.  A timeout
        // prevents an exhausted peer from parking open_stream forever.
        send_request = tokio::time::timeout(OPEN_TIMEOUT, send_request.ready())
            .await
            .map_err(|_| io::Error::other("h2mux: timed out waiting for send readiness (open)"))?
            .map_err(io::Error::other)?;
        let (response_future, send_stream) = send_request
            .send_request(request, false)
            .map_err(io::Error::other)?;
        Ok(Stream::new(
            send_stream,
            RecvState::with_timeout(
                response_future,
                RESPONSE_TIMEOUT,
                StatusPolicy::Exact(StatusCode::OK),
                "h2mux",
            ),
        )
        .with_remote_no_error_eof())
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Aborting the driver task drops the h2 connection and the
        // underlying socket immediately.  Without this, an evicted idle
        // session could keep the physical connection (and its fd) alive
        // until the peer closes it.
        self._task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// h2mux echo server over a duplex pipe, mirroring sing-mux's
    /// h2MuxServerSession: answer every request with 200 and pipe the
    /// request body into the response body until the request half closes.
    async fn run_echo_server<S>(io: S) -> tokio::task::JoinHandle<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            let Ok(mut connection) = h2::server::handshake(io).await else {
                return;
            };
            // Keep polling accept(): only the connection's poll drives the
            // codec, so the buffered response frames need it to keep being
            // polled while per-stream handlers await request data.
            while let Some(result) = connection.accept().await {
                let Ok((request, mut respond)) = result else {
                    return;
                };
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    let response = http::Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .expect("static response");
                    let Ok(mut send) = respond.send_response(response, false) else {
                        return;
                    };
                    while let Some(chunk) = body.data().await {
                        let Ok(chunk) = chunk else {
                            break;
                        };
                        let _ = body.flow_control().release_capacity(chunk.len());
                        if send.send_data(chunk, false).is_err() {
                            break;
                        }
                    }
                    let _ = send.send_data(Bytes::new(), true);
                });
            }
        })
    }

    /// Server that answers 200 at once and pushes `body` as fast as the
    /// *client's* receive windows allow, resolving with the byte count once
    /// h2 has accepted everything.  Against the 64 KiB default windows it
    /// parks after 65 535 bytes until the client reads.
    fn run_push_server<S>(io: S, body: Vec<u8>) -> tokio::sync::oneshot::Receiver<usize>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(io).await.expect("handshake");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("one request")
                .expect("accept");
            tokio::spawn(async move { while connection.accept().await.is_some() {} });
            let response = http::Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("static response");
            let mut send = respond.send_response(response, false).expect("respond");
            let mut remaining = Bytes::from(body);
            let total = remaining.len();
            while !remaining.is_empty() {
                send.reserve_capacity(remaining.len());
                let granted = std::future::poll_fn(|cx| send.poll_capacity(cx))
                    .await
                    .expect("stream open")
                    .expect("capacity");
                let chunk = remaining.split_to(granted.min(remaining.len()));
                send.send_data(chunk, false).expect("send_data");
            }
            send.send_data(Bytes::new(), true).expect("eos");
            drop(request);
            let _ = done_tx.send(total);
        });
        done_rx
    }

    /// The session must advertise receive windows well above h2's 65 535-byte
    /// default (issue #495 item 12): a server pushes 1 MiB down one stream
    /// while the client does not read, which with the default windows parks
    /// after 64 KiB waiting for a WINDOW_UPDATE only a read can produce.
    #[tokio::test]
    async fn receive_window_absorbs_1mib_before_first_read() {
        const PAYLOAD_SIZE: usize = 1024 * 1024;

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let payload: Vec<u8> = (0u8..=255).cycle().take(PAYLOAD_SIZE).collect();
        let pushed = run_push_server(server_io, payload.clone());

        let session = Session::client(client_io).await.unwrap();
        let mut stream = session.open_stream().await.unwrap();

        // Deliberately no read until the server reports the whole push done.
        let pushed = tokio::time::timeout(Duration::from_secs(5), pushed)
            .await
            .expect("server must push 1 MiB into the client's receive window without a read")
            .expect("push server task");
        assert_eq!(pushed, PAYLOAD_SIZE);

        let mut recv = Vec::with_capacity(PAYLOAD_SIZE);
        stream.read_to_end(&mut recv).await.unwrap();
        assert_eq!(recv, payload, "pushed bytes must arrive intact");
    }

    #[tokio::test]
    async fn open_stream_echo_round_trip() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).await.unwrap());
        let mut stream = session.open_stream().await.unwrap();

        stream.write_all(b"hello h2mux").await.unwrap();
        let mut resp = [0u8; 11];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"hello h2mux");
    }

    #[tokio::test]
    async fn two_streams_multiplex_independently() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).await.unwrap());

        let mut a = session.open_stream().await.unwrap();
        let mut b = session.open_stream().await.unwrap();

        a.write_all(b"AAA").await.unwrap();
        b.write_all(b"BBB").await.unwrap();
        let mut buf = [0u8; 3];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"AAA");
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"BBB");
    }

    #[tokio::test]
    async fn concurrent_opens_all_succeed() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).await.unwrap());

        let opens = (0..8)
            .map(|i| {
                let session = Arc::clone(&session);
                async move { (i, session.open_stream().await.unwrap()) }
            })
            .collect::<Vec<_>>();
        let streams = futures::future::join_all(opens).await;
        assert_eq!(streams.len(), 8);
        for (i, mut stream) in streams {
            let payload = format!("stream-{i}").into_bytes();
            stream.write_all(&payload).await.unwrap();
            let mut resp = vec![0u8; payload.len()];
            stream.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, payload);
        }
    }

    /// Live interop probe against a running sing-box VLESS mux inbound
    /// (127.0.0.1:4411, see target/e2e/mux-interop/).  Run with
    /// `--ignored` — requires the server and the local web server
    /// (target/e2e/websrv.py on :18081) to be up.  Exercises the full client
    /// path: VLESS handshake → mux request header → CONNECT stream →
    /// stream-request flags + Socksaddr → response status byte → relay.
    #[tokio::test]
    #[ignore]
    #[cfg(all(feature = "mux", feature = "vless"))]
    async fn live_singbox_vless_probe() {
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
        let mut stream = client.open_stream("127.0.0.1", 18081).await.unwrap();
        stream
            .write_all(
                b"GET /page1.html HTTP/1.1
Host: 127.0.0.1
Connection: close

",
            )
            .await
            .unwrap();
        let mut resp = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp)
            .await
            .unwrap();
        assert!(
            resp.starts_with(b"HTTP/1.1 200"),
            "unexpected response: {}",
            String::from_utf8_lossy(&resp[..resp.len().min(120)])
        );
    }

    /// After `poll_write` stashes data and returns `Pending` (flow control
    /// window exhausted), a re-poll with a *different* buffer must be
    /// rejected with `InvalidInput` — otherwise stale bytes are sent under
    /// the new buffer's reported length.  This is the changed-buffer guard
    /// from the #417 review.
    #[tokio::test]
    async fn poll_write_rejects_changed_buffer_after_pending() {
        // Server that accepts the CONNECT, sends 200, and reads the body
        // very slowly — draining one small chunk per tick so the flow
        // control window stays nearly exhausted.
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let _server = tokio::spawn(async move {
            let Ok(mut connection) = h2::server::handshake(server_io).await else {
                return;
            };
            while let Some(result) = connection.accept().await {
                let Ok((request, mut respond)) = result else {
                    return;
                };
                let mut body = request.into_body();
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, false);
                // Read one chunk then hold — keeps the stream alive but
                // stops releasing flow control capacity.
                if let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
                // Keep the body alive (don't drop) so the stream isn't reset.
                std::mem::forget(body);
            }
        });

        let session = Session::client(client_io).await.unwrap();
        let mut stream = session.open_stream().await.unwrap();

        // Write enough to exhaust the per-stream window (65535 initial).
        // The server reads one chunk then holds, so after ~65535 bytes
        // the window is empty and subsequent writes Pending.
        let fill = vec![0xAA; 65535];
        if stream.write_all(&fill).await.is_err() {
            eprintln!("write_all failed — h2 stream closed early, skipping");
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        // This write stashes the data and returns Pending (window full).
        // Timeout interrupts the await, leaving pending_write set.
        let more = vec![0xBB; 100];
        let _ = tokio::time::timeout(Duration::from_millis(100), stream.write(&more)).await;

        // Re-poll with a different buffer — the guard must reject it.
        let different = vec![0xCC; 50];
        let result = stream.write(&different).await;
        assert!(
            result.is_err(),
            "changed buffer after Pending must be rejected"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "expected InvalidInput, got {err}"
        );
    }
}
