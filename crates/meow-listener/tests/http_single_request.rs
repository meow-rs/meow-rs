//! Regression tests for routing plain HTTP proxy connections one request at a
//! time. A second request on the client connection must never inherit the
//! first request's destination or upstream connection.
#![cfg(feature = "listener-http")]

mod common;

use common::direct_tunnel;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Real time the half-close tests give the relay to read the client's FIN
/// and arm its linger before they pause the clock.
const SETTLE: Duration = Duration::from_millis(200);

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accept_result, connect_result) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    let (server, _) = accept_result.unwrap();
    (server, connect_result.unwrap())
}

async fn spawn_capturing_origin(
    expected_body: &'static [u8],
    response: &'static [u8],
) -> (SocketAddr, oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (sender, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let boundary = loop {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before sending the request body");
            request.extend_from_slice(&chunk[..count]);
            if let Some(header_start) = request.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let boundary = header_start + 4 + expected_body.len();
                if request.len() >= boundary {
                    break boundary;
                }
            }
        };
        assert_eq!(
            &request[boundary - expected_body.len()..boundary],
            expected_body
        );
        assert_eq!(
            request.len(),
            boundary,
            "proxy forwarded a pipelined request"
        );
        sender.send(request).unwrap();
        stream.write_all(response).await.unwrap();
    });
    (addr, receiver)
}

async fn spawn_proxy_handler(server_stream: TcpStream) -> tokio::task::JoinHandle<()> {
    let tunnel = direct_tunnel();
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    tokio::spawn(async move {
        meow_listener::http_proxy::handle_http(&tunnel, server_stream, src, None, None, "test", 0)
            .await;
    })
}

async fn read_response_and_wait_for_close(client: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .expect("proxy did not close the client connection")
        .unwrap();
    response
}

const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";

#[tokio::test]
async fn pipelined_second_origin_is_not_sent_on_first_connection() {
    let (first_addr, first_request) = spawn_capturing_origin(b"", OK_RESPONSE).await;
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_addr = second_listener.local_addr().unwrap();
    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;

    let requests = format!(
        "GET http://{first_addr}/one HTTP/1.1\r\n\
         Host: {first_addr}\r\n\
         Connection: keep-alive\r\n\r\n\
         GET http://{second_addr}/two HTTP/1.1\r\n\
         Host: {second_addr}\r\n\r\n"
    );
    client.write_all(requests.as_bytes()).await.unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    );

    let received = first_request.await.unwrap();
    let received_text = String::from_utf8(received).unwrap();
    assert!(received_text.starts_with("GET /one HTTP/1.1\r\n"));
    assert!(received_text.contains("\r\nConnection: close\r\n"));
    assert!(!received_text.contains("keep-alive"));
    assert!(!received_text.contains("/two"));
    assert!(!received_text.contains(&second_addr.to_string()));

    assert!(
        tokio::time::timeout(Duration::from_millis(200), second_listener.accept())
            .await
            .is_err(),
        "the pipelined request was routed to its own origin instead of closing"
    );
    handler.await.unwrap();
}

#[tokio::test]
async fn content_length_body_stops_before_pipelined_request() {
    let (origin_addr, origin_request) = spawn_capturing_origin(b"hello world", OK_RESPONSE).await;
    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;

    let headers_and_partial_body = format!(
        "POST http://{origin_addr}/submit HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         Content-Length: 11\r\n\r\n\
         hello"
    );
    client
        .write_all(headers_and_partial_body.as_bytes())
        .await
        .unwrap();
    tokio::task::yield_now().await;
    client
        .write_all(
            b" worldGET http://example.invalid/next HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
        )
        .await
        .unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert!(response.ends_with(b"OK"));

    let received = origin_request.await.unwrap();
    let body_start = received
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(&received[body_start..], b"hello world");
    assert!(received.starts_with(b"POST /submit HTTP/1.1\r\n"));
    handler.await.unwrap();
}

#[tokio::test]
async fn chunked_body_and_trailers_stop_before_pipelined_request() {
    const CHUNKED_BODY: &[u8] =
        b"5\r\nhello\r\n6;sample=yes\r\n world\r\n0\r\nX-Trailer: done\r\n\r\n";
    let (origin_addr, origin_request) = spawn_capturing_origin(CHUNKED_BODY, OK_RESPONSE).await;
    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;

    let headers = format!(
        "POST http://{origin_addr}/chunks HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         Transfer-Encoding: chunked\r\n\r\n"
    );
    client.write_all(headers.as_bytes()).await.unwrap();
    client
        .write_all(
            b"5\r\nhello\r\n6;sample=yes\r\n world\r\n0\r\nX-Trailer: done\r\n\r\n\
              GET http://example.invalid/next HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
        )
        .await
        .unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert!(response.ends_with(b"OK"));

    let received = origin_request.await.unwrap();
    let body_start = received
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(&received[body_start..], CHUNKED_BODY);
    assert!(received.starts_with(b"POST /chunks HTTP/1.1\r\n"));
    handler.await.unwrap();
}

#[tokio::test]
async fn final_response_replaces_hop_by_hop_headers_after_informational_response() {
    const RESPONSE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n\
        HTTP/1.1 200 OK\r\n\
        Connection: X-Hop\r\n\
        X-Hop: secret\r\n\
        Keep-Alive: timeout=5\r\n\
        Content-Length: 2\r\n\r\nOK";
    let (origin_addr, origin_request) = spawn_capturing_origin(b"", RESPONSE).await;
    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;

    client
        .write_all(
            format!("GET http://{origin_addr}/ HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let response = read_response_and_wait_for_close(&mut client).await;

    assert_eq!(
        response,
        b"HTTP/1.1 100 Continue\r\n\r\n\
          HTTP/1.1 200 OK\r\n\
          Content-Length: 2\r\n\
          Connection: close\r\n\r\nOK"
    );
    origin_request.await.unwrap();
    handler.await.unwrap();
}

#[tokio::test]
async fn bodyless_request_does_not_half_close_upstream_before_response() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy half-closed the bodyless request early");
            request.extend_from_slice(&chunk[..count]);
        }

        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.read(&mut byte))
                .await
                .is_err(),
            "upstream saw EOF before it sent the response"
        );
        stream.write_all(OK_RESPONSE).await.unwrap();
    });

    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;
    client
        .write_all(
            format!("GET http://{origin_addr}/ HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert!(response.ends_with(b"OK"));
    origin_task.await.unwrap();
    handler.await.unwrap();
}

#[tokio::test]
async fn final_response_stops_an_incomplete_request_upload() {
    const TOO_LARGE: &[u8] = b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n";
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before sending request headers");
            request.extend_from_slice(&chunk[..count]);
        }
        stream.write_all(TOO_LARGE).await.unwrap();
    });

    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;
    client
        .write_all(
            format!(
                "POST http://{origin_addr}/upload HTTP/1.1\r\n\
                 Host: {origin_addr}\r\n\
                 Content-Length: 100\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert_eq!(
        response,
        b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    origin_task.await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .expect("proxy retained an incomplete upload after the final response")
        .unwrap();
}

#[tokio::test]
async fn client_eof_reaps_a_silent_origin_without_half_closing_it_early() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding the request");
            request.extend_from_slice(&chunk[..count]);
        }
        request_seen_tx.send(()).unwrap();

        let mut byte = [0u8; 1];
        assert_eq!(
            stream.read(&mut byte).await.unwrap(),
            0,
            "proxy forwarded bytes beyond the request boundary"
        );
    });

    let (server_stream, mut client) = loopback_pair().await;
    let mut handler = spawn_proxy_handler(server_stream).await;
    client
        .write_all(
            format!("GET http://{origin_addr}/ HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    request_seen_rx.await.unwrap();
    // Keep the client write half open until the origin has received the
    // request.
    client.shutdown().await.unwrap();
    let fin = tokio::time::Instant::now();

    // The I/O runs on the real clock: paused from the start, Tokio would
    // auto-advance while the proxy's dial or the relay's FIN read waits on
    // a real socket, firing the dial timeout or the linger early (seen as
    // an occasional hang). Give the relay real time to read the FIN and
    // arm the linger, then pause and move the clock relative to `fin`; the
    // deadline lies between `fin + LINGER` and `fin + SETTLE + LINGER`.
    tokio::time::sleep(SETTLE).await;
    tokio::time::pause();
    assert!(
        !handler.is_finished(),
        "client EOF half-closed the upstream before it could respond"
    );
    tokio::time::advance(
        meow_tunnel::relay::RELAY_HALF_CLOSE_LINGER - Duration::from_millis(1) - fin.elapsed(),
    )
    .await;
    tokio::task::yield_now().await;
    assert!(
        !handler.is_finished(),
        "silent upstream was reaped before the half-close linger"
    );
    tokio::time::advance(SETTLE + Duration::from_millis(2)).await;
    tokio::time::timeout(Duration::from_secs(1), &mut handler)
        .await
        .expect("client EOF did not arm the half-close linger")
        .unwrap();
    origin_task.await.unwrap();
}

#[tokio::test]
async fn queued_pipeline_does_not_reset_a_large_response() {
    const BODY_LEN: usize = 1024 * 1024;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding the request");
            request.extend_from_slice(&chunk[..count]);
        }
        assert!(!request.windows(5).any(|window| window == b"/next"));

        stream
            .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY_LEN}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        stream.write_all(&vec![b'x'; BODY_LEN]).await.unwrap();
    });

    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;
    let padding = "p".repeat(16 * 1024);
    let requests = format!(
        "GET http://{origin_addr}/large HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n\
         GET http://example.invalid/next HTTP/1.1\r\nHost: example.invalid\r\nX-Pad: {padding}\r\n\r\n"
    );
    client.write_all(requests.as_bytes()).await.unwrap();

    // Let the origin fill the proxy's client-facing send buffer before this
    // client starts consuming the response. Unread pipelined request bytes at
    // close used to turn that close into an RST and truncate the response.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let response = read_response_and_wait_for_close(&mut client).await;
    let body_start = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(response.len() - body_start, BODY_LEN);
    assert!(response[body_start..].iter().all(|byte| *byte == b'x'));
    origin_task.await.unwrap();
    handler.await.unwrap();
}

#[tokio::test]
async fn expect_continue_forwards_the_body_after_the_interim_response() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding request headers");
            request.extend_from_slice(&chunk[..count]);
        }
        assert!(request
            .windows(b"Expect: 100-continue".len())
            .any(|window| window.eq_ignore_ascii_case(b"Expect: 100-continue")));
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();

        let body_start = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        while request.len() - body_start < 5 {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding the request body");
            request.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(&request[body_start..body_start + 5], b"hello");
        stream.write_all(OK_RESPONSE).await.unwrap();
    });

    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;
    client
        .write_all(
            format!(
                "POST http://{origin_addr}/upload HTTP/1.1\r\n\
                 Host: {origin_addr}\r\n\
                 Content-Length: 5\r\n\
                 Expect: 100-continue\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut interim = vec![0u8; b"HTTP/1.1 100 Continue\r\n\r\n".len()];
    client.read_exact(&mut interim).await.unwrap();
    assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    client.write_all(b"hello").await.unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    );
    origin_task.await.unwrap();
    handler.await.unwrap();
}

#[tokio::test]
async fn http_1_0_request_and_split_response_head_are_supported() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding the request");
            request.extend_from_slice(&chunk[..count]);
        }
        assert!(request.starts_with(b"GET /legacy HTTP/1.0\r\n"));
        stream.write_all(b"HTTP/1.0 200 OK\r").await.unwrap();
        tokio::task::yield_now().await;
        stream
            .write_all(b"\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();
    });

    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;
    client
        .write_all(
            format!("GET http://{origin_addr}/legacy HTTP/1.0\r\nHost: {origin_addr}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert_eq!(
        response,
        b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    );
    origin_task.await.unwrap();
    handler.await.unwrap();
}

#[tokio::test]
async fn websocket_upgrade_switches_to_an_opaque_tunnel() {
    const CLIENT_FRAME: &[u8] = b"client-frame";
    const SERVER_FRAME: &[u8] = b"server-frame";

    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding the upgrade");
            request.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(
            request,
            format!(
                "GET /chat HTTP/1.1\r\n\
                 Host: {origin_addr}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: upgrade\r\n\r\n"
            )
            .as_bytes()
        );

        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.read(&mut byte))
                .await
                .is_err(),
            "client protocol bytes reached the origin before its 101 response"
        );
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade, X-Origin-Hop\r\n\
                  Upgrade: websocket\r\n\
                  X-Origin-Hop: drop-me\r\n\
                  X-End-To-End: kept\r\n\r\n",
            )
            .await
            .unwrap();

        let mut client_frame = [0u8; CLIENT_FRAME.len()];
        stream.read_exact(&mut client_frame).await.unwrap();
        assert_eq!(&client_frame, CLIENT_FRAME);
        stream.write_all(SERVER_FRAME).await.unwrap();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .expect("client half-close was not forwarded through the upgraded tunnel")
                .unwrap(),
            0
        );
        stream.shutdown().await.unwrap();
    });

    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;
    let request = format!(
        "GET ws://{origin_addr}/chat HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         Connection: keep-alive, Upgrade, X-Hop\r\n\
         Upgrade: websocket\r\n\
         X-Hop: drop-me\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    // Exercise bytes coalesced with the request head: they must be held until
    // the origin has accepted the protocol switch, then relayed losslessly.
    client.write_all(CLIENT_FRAME).await.unwrap();

    let mut response_head = Vec::new();
    while !response_head.windows(4).any(|window| window == b"\r\n\r\n") {
        response_head.push(client.read_u8().await.unwrap());
    }
    assert_eq!(
        response_head,
        b"HTTP/1.1 101 Switching Protocols\r\n\
          Upgrade: websocket\r\n\
          X-End-To-End: kept\r\n\
          Connection: upgrade\r\n\r\n"
    );

    let mut server_frame = [0u8; SERVER_FRAME.len()];
    client.read_exact(&mut server_frame).await.unwrap();
    assert_eq!(&server_frame, SERVER_FRAME);
    client.shutdown().await.unwrap();

    origin_task.await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .expect("upgraded relay did not close after both peers finished")
        .unwrap();
}

#[tokio::test]
async fn declined_upgrade_closes_without_forwarding_protocol_bytes() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding the upgrade");
            request.extend_from_slice(&chunk[..count]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
            .await
            .unwrap();

        let mut trailing = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut trailing))
            .await
            .expect("proxy did not half-close a declined upgrade")
            .unwrap();
        assert!(
            trailing.is_empty(),
            "protocol bytes were forwarded without a 101 response"
        );
        stream.write_all(b"OK").await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;
    let request = format!(
        "GET http://{origin_addr}/chat HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    client.write_all(b"must-not-leak").await.unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    );
    origin_task.await.unwrap();
    handler.await.unwrap();
}

#[tokio::test]
async fn rejected_response_head_becomes_a_502() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding the request");
            request.extend_from_slice(&chunk[..count]);
        }
        // A response head larger than the proxy's cap, never terminated.
        // The proxy may drop the connection mid-write; ignore write errors.
        let huge = format!("HTTP/1.1 200 OK\r\nX-Big: {}\r\n", "p".repeat(16 * 1024));
        let _ = stream.write_all(huge.as_bytes()).await;
    });

    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;
    client
        .write_all(
            format!("GET http://{origin_addr}/ HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert_eq!(
        response, b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        "a rejected upstream response head must yield an explicit 502, not a silent close"
    );
    origin_task.await.unwrap();
    handler.await.unwrap();
}

#[tokio::test]
async fn interim_response_hop_by_hop_headers_are_stripped() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding the request");
            request.extend_from_slice(&chunk[..count]);
        }
        stream
            .write_all(
                b"HTTP/1.1 103 Early Hints\r\n\
                  Connection: keep-alive, X-Hop\r\n\
                  Keep-Alive: timeout=99\r\n\
                  X-Hop: secret\r\n\
                  Link: </style.css>; rel=preload\r\n\r\n",
            )
            .await
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();
    });

    let (server_stream, mut client) = loopback_pair().await;
    let handler = spawn_proxy_handler(server_stream).await;
    client
        .write_all(
            format!("GET http://{origin_addr}/ HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let response = read_response_and_wait_for_close(&mut client).await;
    assert_eq!(
        response,
        b"HTTP/1.1 103 Early Hints\r\n\
          Link: </style.css>; rel=preload\r\n\r\n\
          HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            .as_slice(),
        "interim hop-by-hop headers must not reach the client"
    );
    origin_task.await.unwrap();
    handler.await.unwrap();
}

#[tokio::test]
async fn abandoned_upgrade_is_reaped_by_the_half_close_linger() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "proxy closed before forwarding the upgrade");
            request.extend_from_slice(&chunk[..count]);
        }
        request_seen_tx.send(()).unwrap();

        // Never send a response. The held client protocol bytes must not
        // reach this origin, and the proxy must still reap the connection.
        let mut byte = [0u8; 1];
        assert_eq!(
            stream.read(&mut byte).await.unwrap(),
            0,
            "held protocol bytes were forwarded without a 101 response"
        );
    });

    let (server_stream, mut client) = loopback_pair().await;
    let mut handler = spawn_proxy_handler(server_stream).await;
    let request = format!(
        "GET ws://{origin_addr}/chat HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    // Early protocol bytes exercise the bounded hold: the client FIN behind
    // them must still be observed while the upgrade decision is pending.
    client.write_all(b"early-protocol-bytes").await.unwrap();
    request_seen_rx.await.unwrap();
    // Keep the client write half open until the origin has received the
    // request, as in client_eof_reaps_a_silent_origin.
    client.shutdown().await.unwrap();
    let fin = tokio::time::Instant::now();

    // The I/O runs on the real clock: paused from the start, Tokio would
    // auto-advance while the proxy's dial or the relay's FIN read waits on
    // a real socket, firing the dial timeout or the linger early (seen as
    // an occasional hang). Give the relay real time to read the FIN and
    // arm the linger, then pause and move the clock relative to `fin`; the
    // deadline lies between `fin + LINGER` and `fin + SETTLE + LINGER`.
    tokio::time::sleep(SETTLE).await;
    tokio::time::pause();
    assert!(
        !handler.is_finished(),
        "client EOF closed the connection before the half-close linger"
    );
    tokio::time::advance(
        meow_tunnel::relay::RELAY_HALF_CLOSE_LINGER - Duration::from_millis(1) - fin.elapsed(),
    )
    .await;
    tokio::task::yield_now().await;
    assert!(
        !handler.is_finished(),
        "the silent origin was reaped before the half-close linger"
    );
    tokio::time::advance(SETTLE + Duration::from_millis(2)).await;
    tokio::time::timeout(Duration::from_secs(1), &mut handler)
        .await
        .expect("an abandoned upgrade handshake did not arm the half-close linger")
        .unwrap();
    origin_task.await.unwrap();
}
