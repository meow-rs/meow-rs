use super::*;
use tokio::io::{AsyncRead, AsyncWrite};

fn answer() -> Vec<u8> {
    let mut response = Message::new(42, MessageType::Response, OpCode::Query);
    response.add_query(Query::query("example.test".parse().unwrap(), RecordType::A));
    response.to_bytes().unwrap()
}

fn framed(body: &[u8], kind: usize) -> Vec<u8> {
    match kind {
        0 => [
            format!(
                "HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh: {}\r\nContent-Encoding: identity\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body.to_vec(),
        ]
        .concat(),
        1 => {
            let mut out = b"HTTP/1.1 200 OK\r\nTrAnSfEr-EnCoDiNg: Chunked\r\n\r\n".to_vec();
            for chunk in body.chunks(7) {
                out.extend_from_slice(
                    format!("{:x}; foo=\"a;\\\"b\";bar=baz\r\n", chunk.len()).as_bytes(),
                );
                out.extend_from_slice(chunk);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"0;finished\r\nX-Checksum: ignored\r\n\r\n");
            out
        }
        _ => [
            b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n".as_slice(),
            body,
        ]
        .concat(),
    }
}

async fn request<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
        assert!(head.len() < 4096);
    }
    let head = String::from_utf8(head).unwrap();
    let n: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    let mut body = vec![0; n];
    stream.read_exact(&mut body).await.unwrap();
    assert_eq!(body, answer());
    head
}

async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    bytes: Vec<u8>,
    fragment: usize,
) -> String {
    let head = request(&mut stream).await;
    for piece in bytes.chunks(fragment) {
        if stream.write_all(piece).await.is_err() {
            break;
        }
        tokio::task::yield_now().await;
    }
    head
}

async fn decode(bytes: Vec<u8>, fragment: usize) -> Result<Vec<u8>, ClientError> {
    let (mut client, server) = tokio::io::duplex(512);
    let task = tokio::spawn(respond(server, bytes, fragment));
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        doh_http_exchange(&mut client, "dns.example", "/dns-query", &answer()),
    )
    .await
    .unwrap();
    drop(client);
    task.await.unwrap();
    result.map(|(body, _)| body)
}

#[tokio::test]
async fn doh_three_framings_return_identical_dns_bytes_fragmented() {
    for kind in 0..3 {
        for fragment in [1, 7, 4096] {
            let got = decode(framed(&answer(), kind), fragment).await.unwrap();
            assert_eq!(got, answer(), "framing {kind}, fragment {fragment}");
            assert_eq!(Message::from_bytes(&got).unwrap().metadata.id, 42);
        }
    }
}

#[tokio::test]
async fn doh_complete_length_and_chunked_do_not_wait_for_eof() {
    for kind in 0..2 {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let (release, held) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            request(&mut server).await;
            server.write_all(&framed(&answer(), kind)).await.unwrap();
            let _ = held.await;
        });
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            doh_http_exchange(&mut client, "dns.example", "/dns-query", &answer()),
        )
        .await;
        drop(release);
        task.await.unwrap();
        assert_eq!(
            result
                .expect("complete framed body must not wait for EOF")
                .unwrap()
                .0,
            answer()
        );
    }
}

struct StreamProxy {
    addr: SocketAddr,
    health: meow_common::ProxyHealth,
    calls: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl meow_common::ProxyAdapter for StreamProxy {
    fn name(&self) -> &str {
        "dns-stream-fixture"
    }
    fn adapter_type(&self) -> meow_common::AdapterType {
        meow_common::AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    fn health(&self) -> &meow_common::ProxyHealth {
        &self.health
    }
    async fn dial_tcp(
        &self,
        metadata: &meow_common::Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
        assert!(metadata.internal);
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(tokio::net::TcpStream::connect(self.addr).await?))
    }
    async fn dial_udp(
        &self,
        _: &meow_common::Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
        panic!("no UDP/system DNS fallback")
    }
}
impl meow_common::Proxy for StreamProxy {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
        Vec::new()
    }
}

#[tokio::test]
async fn doh_actual_direct_and_proxy_stream_paths_share_framing_and_fail_closed() {
    // Exercises the production socket selection and HTTP stream boundary, not
    // a new trusted TLS fixture. TLS connect/SNI/certificate policy is unchanged.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bypass = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = Arc::new(StreamProxy {
        addr: listener.local_addr().unwrap(),
        health: meow_common::ProxyHealth::new(),
        calls: Default::default(),
    });
    for proxied in [false, true] {
        for valid in [true, false] {
            let response = if valid {
                framed(&answer(), 1)
            } else {
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\ninvalid".to_vec()
            };
            let dyn_proxy: DnsProxy = Arc::<StreamProxy>::clone(&proxy);
            let addr = if proxied {
                bypass.local_addr().unwrap()
            } else {
                listener.local_addr().unwrap()
            };
            let mut client = DnsClient::doh(addr, "dns.example", "/dns-query");
            if proxied {
                client = client.with_proxy(dyn_proxy);
            }
            let mut stream = client.dial_tls_inner().await.unwrap();
            let (peer, _) = listener.accept().await.unwrap();
            let task = tokio::spawn(respond(peer, response, 1));
            let result =
                doh_http_exchange(&mut stream, "dns.example", "/dns-query", &answer()).await;
            if valid {
                assert_eq!(result.unwrap().0, answer());
            } else {
                assert!(result.is_err());
            }
            drop(stream);
            task.await.unwrap();
        }
    }
    assert_eq!(proxy.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), bypass.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn doh_informational_responses_precede_final_response() {
    let bytes = [
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n".to_vec(),
        framed(&answer(), 1),
    ]
    .concat();
    assert_eq!(decode(bytes, 1).await.unwrap(), answer());
}

#[tokio::test]
async fn upstream_total_response_budget_rejects_without_peer_eof() {
    let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    for bytes in [
        format!(
            "HTTP/1.1 200 OK\r\nX: {}",
            "x".repeat(MAX_DOH_RESPONSE_BYTES + 1)
        ),
        format!("{chunked}1;{}", "x".repeat(MAX_DOH_RESPONSE_BYTES + 1)),
        format!(
            "{chunked}0\r\nX: {}",
            "x".repeat(MAX_DOH_RESPONSE_BYTES + 1)
        ),
        format!(
            "HTTP/1.0 200 OK\r\n\r\n{}",
            "x".repeat(MAX_DOH_RESPONSE_BYTES + 1)
        ),
    ] {
        // Buffer must hold the whole over-limit payload without a reader.
        let (mut client, mut server) = tokio::io::duplex(MAX_DOH_RESPONSE_BYTES * 2 + 4096);
        server.write_all(bytes.as_bytes()).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), read_http_response(&mut client))
            .await
            .expect("upstream total budget terminates even without EOF");
        assert!(matches!(result, Err(ClientError::Protocol(_))));
    }
}
