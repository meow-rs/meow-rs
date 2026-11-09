#![cfg(feature = "listener-http")]

mod common;

use common::direct_tunnel;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    (accepted.unwrap().0, connected.unwrap())
}

async fn assert_bad_request(request: &[u8]) {
    let (server_stream, mut client_stream) = loopback_pair().await;
    let tunnel = direct_tunnel();
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let handle = tokio::spawn(async move {
        meow_listener::http_proxy::handle_http(&tunnel, server_stream, src, None, None, "test", 0)
            .await;
    });

    client_stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        client_stream.read_to_end(&mut response),
    )
    .await
    .expect("proxy did not reject malformed headers promptly")
    .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "unexpected response: {:?}",
        String::from_utf8_lossy(&response)
    );
    handle.await.unwrap();
}

#[tokio::test]
async fn bare_lf_header_is_rejected_instead_of_normalized() {
    assert_bad_request(b"GET http://127.0.0.1:9/ HTTP/1.1\r\nX-A: 1\nContent-Length: 0\r\n\r\n")
        .await;
}

#[tokio::test]
async fn bare_cr_header_is_rejected() {
    assert_bad_request(b"GET http://127.0.0.1:9/ HTTP/1.1\r\nX-A: 1\rContent-Length: 0\r\n\r\n")
        .await;
}

#[tokio::test]
async fn conflicting_content_length_and_transfer_encoding_are_rejected() {
    assert_bad_request(
        b"POST http://127.0.0.1:9/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n",
    )
    .await;
    assert_bad_request(
        b"POST http://127.0.0.1:9/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn transfer_encoding_on_http_1_0_is_rejected() {
    assert_bad_request(b"POST http://127.0.0.1:9/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await;
}

/// RFC 9110 §5.4: a duplicated `Host` field makes the authority ambiguous.
/// Origin-form requests were already refused on the hostname gate (a dup
/// leaves no authority to route); absolute-form requests forwarded the
/// pair verbatim — both forms now reject the same way (issue #869).
#[tokio::test]
async fn duplicate_host_headers_are_rejected() {
    assert_bad_request(
        b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
    )
    .await;
    assert_bad_request(b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n").await;
}

/// The streaming validator runs per socket read, so a head delivered one byte
/// at a time must reach the same verdict as one delivered in a single write.
#[tokio::test]
async fn bare_lf_is_rejected_when_the_head_arrives_one_byte_per_write() {
    let (server_stream, mut client_stream) = loopback_pair().await;
    let tunnel = direct_tunnel();
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let handle = tokio::spawn(async move {
        meow_listener::http_proxy::handle_http(&tunnel, server_stream, src, None, None, "test", 0)
            .await;
    });

    let request = b"GET http://127.0.0.1:9/ HTTP/1.1\r\nX-A: 1\nContent-Length: 0\r\n\r\n";
    let writer = tokio::spawn(async move {
        for byte in request {
            // A rejection mid-stream closes the connection, so a short write
            // here is the success path, not a failure.
            if client_stream.write_all(&[*byte]).await.is_err() {
                break;
            }
        }
        let mut response = Vec::new();
        let _ = client_stream.read_to_end(&mut response).await;
        response
    });

    let response = tokio::time::timeout(Duration::from_secs(2), writer)
        .await
        .expect("proxy did not reject the dribbled head promptly")
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "unexpected response: {:?}",
        String::from_utf8_lossy(&response)
    );
    handle.await.unwrap();
}

/// The inverse property: a body containing a bare LF must not be mistaken for a
/// malformed header when it arrives in a later read than the head.
#[tokio::test]
async fn body_line_feeds_in_a_later_read_are_not_header_errors() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "origin saw EOF before the request completed");
            request.extend_from_slice(&chunk[..read]);
            if request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .is_some_and(|end| request.len() >= end + 4 + 3)
            {
                break;
            }
        }
        captured_tx.send(request).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let (server_stream, mut client_stream) = loopback_pair().await;
    let tunnel = direct_tunnel();
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let handle = tokio::spawn(async move {
        meow_listener::http_proxy::handle_http(&tunnel, server_stream, src, None, None, "test", 0)
            .await;
    });

    let head = format!(
        "POST http://{origin_addr}/upload HTTP/1.1\r\nHost: {origin_addr}\r\nContent-Length: 3\r\n\r\n"
    );
    client_stream.write_all(head.as_bytes()).await.unwrap();
    client_stream.flush().await.unwrap();
    // Force a separate read on the listener side before the body lands.
    tokio::time::sleep(Duration::from_millis(50)).await;
    client_stream.write_all(b"a\nb").await.unwrap();
    client_stream.shutdown().await.unwrap();

    let captured = tokio::time::timeout(Duration::from_secs(2), captured_rx)
        .await
        .expect("origin did not receive the request")
        .unwrap();
    assert!(captured.ends_with(b"Content-Length: 3\r\nConnection: close\r\n\r\na\nb"));

    let mut response = Vec::new();
    client_stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 204 No Content\r\n"));
    handle.await.unwrap();
}

#[tokio::test]
async fn valid_obs_text_is_preserved_and_body_line_feeds_are_not_header_errors() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "origin saw EOF before the request completed");
            request.extend_from_slice(&chunk[..read]);
            if request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .is_some_and(|end| request.len() >= end + 4 + 3)
            {
                break;
            }
        }
        captured_tx.send(request).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let (server_stream, mut client_stream) = loopback_pair().await;
    let tunnel = direct_tunnel();
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let handle = tokio::spawn(async move {
        meow_listener::http_proxy::handle_http(&tunnel, server_stream, src, None, None, "test", 0)
            .await;
    });

    let mut request =
        format!("POST http://{origin_addr}/upload HTTP/1.1\r\nHost: {origin_addr}\r\nX-Word: caf")
            .into_bytes();
    request.extend_from_slice(b"\xe9\r\nContent-Length: 3\r\n\r\na\nb");
    client_stream.write_all(&request).await.unwrap();
    client_stream.shutdown().await.unwrap();

    let captured = tokio::time::timeout(Duration::from_secs(1), captured_rx)
        .await
        .expect("origin did not receive the request")
        .unwrap();
    let expected_prefix =
        format!("POST /upload HTTP/1.1\r\nHost: {origin_addr}\r\nX-Word: caf").into_bytes();
    assert!(captured.starts_with(&expected_prefix));
    assert!(captured.ends_with(b"\xe9\r\nContent-Length: 3\r\nConnection: close\r\n\r\na\nb"));

    let mut response = Vec::new();
    client_stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 204 No Content\r\n"));
    handle.await.unwrap();
}
