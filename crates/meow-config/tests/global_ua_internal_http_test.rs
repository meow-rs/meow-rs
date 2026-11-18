//! `global-ua` on the internal HTTP client (issue #974).
//!
//! Lives in its own integration binary, not the `internal_http` unit
//! tests: `build_config` unconditionally installs the process-global UA,
//! and the ~20 same-binary unit tests that call it would race the wire
//! assertions below. A separate binary gives this test the process to
//! itself (`global_ua_serial` still guards, cheaply).

use meow_config::internal_http::fetch;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Reads one request head off `stream`, lowercased for case-insensitive
/// header-name matching (HTTP/1.1 field names are case-insensitive).
async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut byte = [0];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        request.push(byte[0]);
    }
    String::from_utf8(request).unwrap().to_ascii_lowercase()
}

/// The process-wide `global-ua` override reaches the wire, while a
/// request-supplied `User-Agent` still replaces it — one field line,
/// like Go's `req.Header` set (mihomo parity).
#[tokio::test]
async fn fetch_emits_global_ua_and_request_ua_wins() {
    let _serial = meow_config::global_ua_serial().lock().await;
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            meow_common::set_global_ua(None);
        }
    }
    let _reset = Reset;
    meow_common::set_global_ua(Some("mihomo/v1.18.0"));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/x", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            requests.push(read_request(&mut stream).await);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        }
        requests
    });
    let body = fetch(&url, None, &[]).await.unwrap();
    assert_eq!(body, b"ok");
    let body = fetch(&url, None, &[("USER-AGENT".into(), "custom/1".into())])
        .await
        .unwrap();
    assert_eq!(body, b"ok");
    let requests = server.await.unwrap();
    assert!(
        requests[0].contains("user-agent: mihomo/v1.18.0\r\n"),
        "the configured global UA must reach the wire: {}",
        requests[0]
    );
    assert!(
        !requests[1].contains("mihomo/v1.18.0"),
        "the request UA replaces the global: {}",
        requests[1]
    );
    assert!(
        requests[1].contains("user-agent: custom/1\r\n"),
        "{}",
        requests[1]
    );
    assert_eq!(
        requests[1]
            .lines()
            .filter(|line| line.starts_with("user-agent:"))
            .count(),
        1
    );
}
