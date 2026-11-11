#![cfg(unix)]

use super::*;
use hickory_proto::serialize::binary::BinEncodable;
use std::time::Duration;
use tokio::net::TcpStream;

fn cached_resolver(octet: u8) -> Arc<Resolver> {
    let resolver = Arc::new(Resolver::new(
        Vec::new(),
        Vec::new(),
        meow_common::DnsMode::Normal,
        meow_trie::DomainTrie::new(),
        true,
        true,
    ));
    resolver.preload_cache(
        "example.com",
        &[std::net::Ipv4Addr::new(10, 0, 0, octet).into()],
        Duration::from_secs(300),
    );
    resolver
}

fn query() -> Vec<u8> {
    let mut message = Message::new(123, MessageType::Query, hickory_proto::op::OpCode::Query);
    message.add_query(hickory_proto::op::Query::query(
        "example.com".parse().unwrap(),
        RecordType::A,
    ));
    message.to_bytes().unwrap()
}

async fn ask(stream: &mut TcpStream, octet: u8) {
    tokio::time::timeout(Duration::from_secs(2), async {
        let q = query();
        stream.write_u16(q.len() as u16).await.unwrap();
        stream.write_all(&q).await.unwrap();
        let n = stream.read_u16().await.unwrap();
        let mut answer = vec![0; n as usize];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer[answer.len() - 4..], &[10, 0, 0, octet]);
    })
    .await
    .expect("cached TCP query remains available");
}

// RLIMIT is process-wide. Run only this test in a fresh child; a parent watchdog
// also detects a single-thread accept busy loop (which would starve Tokio timers).
#[cfg(unix)]
#[test]
fn tcp_emfile_preserves_cached_tcp_udp_and_recovers() {
    const CHILD: &str = "MEOW_DNS_EMFILE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(emfile_child());
        return;
    }
    let mut child = std::process::Command::new("sh")
        .args(["-c", "ulimit -n 96; exec \"$1\" --exact server::admission_tests::tcp_emfile_preserves_cached_tcp_udp_and_recovers --nocapture", "dns-emfile"])
        .arg(std::env::current_exe().unwrap()).env(CHILD, "1")
        .spawn().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "EMFILE child failed: {status}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("EMFILE child hung (possible accept busy loop)");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
async fn emfile_child() {
    let bound = DnsServer::new(cached_resolver(1), "127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    let addr = bound.local_addr().unwrap();
    let slot = bound.resolver_slot();
    let task = tokio::spawn(bound.run());
    let mut existing = TcpStream::connect(addr).await.unwrap();
    ask(&mut existing, 1).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Reserve the client's FD before exhausting the child. connect() then
    // queues a genuine connection that accept() cannot allocate an FD for.
    let pending = tokio::net::TcpSocket::new_v4().unwrap();
    let mut files = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => files.push(file),
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(24));
                eprintln!("actual EMFILE reached with {} held files", files.len());
                break;
            }
        }
    }
    let pending = pending.connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(180)).await;
    if task.is_finished() {
        panic!("DNS listener exited under EMFILE: {:?}", task.await);
    }
    // No upstream sockets are needed: both generations are fresh cache hits.
    *slot.write() = cached_resolver(2);
    ask(&mut existing, 2).await;
    udp.send_to(&query(), addr).await.unwrap();
    let mut answer = [0; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&answer[n - 4..n], &[10, 0, 0, 2]);
    // Darwin may discard the pending connection when accept fails with
    // EMFILE; recovery promises new admission, not retention of that SYN.
    drop(pending);
    files.clear();
    let mut recovered = TcpStream::connect(addr).await.unwrap();
    ask(&mut recovered, 2).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    for stream in [&mut existing, &mut recovered] {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    DnsServer::new(cached_resolver(1), addr)
        .bind()
        .await
        .unwrap();
    eprintln!("EMFILE: cached TCP/UDP, reload, recovery and cancellation passed");
}
