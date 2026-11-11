use super::*;
use hickory_proto::serialize::binary::BinEncodable;
use std::time::Duration;
use tokio::net::TcpStream;

fn query(name: &str) -> Vec<u8> {
    let mut message = Message::new(123, MessageType::Query, hickory_proto::op::OpCode::Query);
    message.add_query(hickory_proto::op::Query::query(
        name.parse().unwrap(),
        RecordType::A,
    ));
    message.to_bytes().unwrap()
}

fn resolver(upstream: SocketAddr) -> Arc<Resolver> {
    let resolver = Arc::new(Resolver::new(
        vec![upstream],
        Vec::new(),
        meow_common::DnsMode::Normal,
        meow_trie::DomainTrie::new(),
        false,
        true,
    ));
    resolver.preload_cache(
        "local.test",
        &["10.0.0.7".parse().unwrap()],
        Duration::from_secs(300),
    );
    resolver
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, name: &str) {
    let bytes = query(name);
    stream.write_u16(bytes.len() as u16).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
}

async fn response<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let length = stream.read_u16().await.unwrap();
        let mut answer = vec![0; length as usize];
        stream.read_exact(&mut answer).await.unwrap();
        answer
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn tcp_udp_share_upstream_budget_but_local_queries_and_idle_streams_do_not() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bound = DnsServer::new(
        resolver(upstream.local_addr().unwrap()),
        "127.0.0.1:0".parse().unwrap(),
    )
    .bind()
    .await
    .unwrap();
    let addr = bound.local_addr().unwrap();
    let dropped = bound.dropped_counter();
    let task = tokio::spawn(bound.run());
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut requests = Vec::new();
    let mut buffer = [0; 512];
    for index in 0..MAX_IN_FLIGHT {
        udp.send_to(&query(&format!("held-{index}.test")), addr)
            .await
            .unwrap();
        let (n, peer) =
            tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        requests.push((buffer[..n].to_vec(), peer));
    }
    let mut waiting = TcpStream::connect(addr).await.unwrap();
    send(&mut waiting, "waiting.test").await;
    // Admission succeeds beyond the work budget, and fresh cache answers on
    // another stream are immediate even while that query waits for a permit.
    let mut local = TcpStream::connect(addr).await.unwrap();
    send(&mut local, "local.test").await;
    let answer = response(&mut local).await;
    assert_eq!(&answer[answer.len() - 4..], &[10, 0, 0, 7]);
    udp.send_to(&query("dropped.test"), addr).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while dropped.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(dropped.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), upstream.recv_from(&mut buffer))
            .await
            .is_err()
    );
    let (mut request, peer) = requests.remove(0);
    request[2] = 0x81;
    request[3] = 0x80;
    upstream.send_to(&request, peer).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert!(buffer[..n]
        .windows(b"waiting".len())
        .any(|part| part == b"waiting"));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    for client in [&mut local, &mut waiting] {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), client.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn tcp_cancelled_and_failed_upstream_queries_release_work_permit() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let budget = Arc::new(tokio::sync::Semaphore::new(1));
    let slot = new_resolver_slot(resolver(upstream.local_addr().unwrap()));
    let (mut client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(serve_tcp_stream(
        server,
        Arc::clone(&slot),
        Arc::clone(&budget),
    ));
    send(&mut client, "cancel.test").await;
    tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut [0; 512]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(budget.available_permits(), 0);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(budget.available_permits(), 1);
    // No usable upstream: resolution fails to SERVFAIL, without retaining
    // the permit in an idle, still-open client connection.
    *slot.write() = Arc::new(Resolver::new(
        Vec::new(),
        Vec::new(),
        meow_common::DnsMode::Normal,
        meow_trie::DomainTrie::new(),
        false,
        true,
    ));
    let (mut client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(serve_tcp_stream(server, slot, Arc::clone(&budget)));
    send(&mut client, "failed.test").await;
    let answer = response(&mut client).await;
    assert_eq!(answer[3] & 0xf, 2);
    assert_eq!(budget.available_permits(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn tcp_waiting_for_work_permit_uses_original_exchange_deadline() {
    let budget = Arc::new(tokio::sync::Semaphore::new(1));
    let held = budget.acquire().await.unwrap();
    let slot = new_resolver_slot(resolver("127.0.0.1:9".parse().unwrap()));
    let (mut client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(serve_tcp_stream(server, slot, Arc::clone(&budget)));
    send(&mut client, "waiting.test").await;
    let start = tokio::time::Instant::now();
    let error = task.await.unwrap().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(start.elapsed(), TCP_EXCHANGE_TIMEOUT);
    drop(held);
    assert_eq!(budget.available_permits(), 1);
}
