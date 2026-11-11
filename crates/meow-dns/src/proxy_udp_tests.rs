//! DNS proxy transport contracts, including cancellation and no replay.
use super::*;
use meow_common::{
    AdapterType, DelayHistory, Metadata, Network, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn,
};
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tokio::sync::Notify;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Valid,
    Unspecified,
    Mapped,
    MappedUnspecified,
    Truncated,
    Short,
    Error,
    ReadError,
    WritePending,
    ReadPending,
}

struct State {
    mode: Mode,
    udp: bool,
    closed: AtomicUsize,
    tcp: AtomicUsize,
    sent: AtomicUsize,
    read: AtomicUsize,
    started: Notify,
    seen: Mutex<Vec<Metadata>>,
    replies: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
}
struct TestProxy {
    state: Arc<State>,
    health: ProxyHealth,
}
struct Packet(Arc<State>);

#[async_trait::async_trait]
impl ProxyPacketConn for Packet {
    async fn write_packet(&self, wire: &[u8], addr: &SocketAddr) -> meow_common::Result<usize> {
        self.0.sent.fetch_add(1, Ordering::SeqCst);
        if self.0.mode == Mode::WritePending {
            self.0.started.notify_one();
            std::future::pending::<()>().await;
        }
        if self.0.mode == Mode::Short {
            return Ok(wire.len() - 1);
        }
        if self.0.mode == Mode::Error {
            return Err(io::Error::from_raw_os_error(24).into());
        }
        let mut response = Message::from_bytes(wire).unwrap();
        response.metadata.message_type = MessageType::Response;
        response.metadata.truncation = self.0.mode == Mode::Truncated;
        let mut replies = self.0.replies.lock().unwrap();
        // A wrong peer, malformed payload, wrong ID, or wrong question must
        // never finish the exchange (nor cause a TCP retry if TC is set).
        let mut bad = response.clone();
        bad.metadata.truncation = true;
        replies.push_back((bad.to_bytes().unwrap(), "192.0.2.2:53".parse().unwrap()));
        replies.push_back((bad.to_bytes().unwrap(), SocketAddr::new(addr.ip(), 54)));
        replies.push_back((vec![0], *addr));
        bad.metadata.id = bad.metadata.id.wrapping_add(1);
        replies.push_back((bad.to_bytes().unwrap(), *addr));
        bad.metadata.id = response.metadata.id;
        bad.queries[0].query_type = RecordType::AAAA;
        replies.push_back((bad.to_bytes().unwrap(), *addr));
        let peer = match self.0.mode {
            Mode::Unspecified => "0.0.0.0:0".parse().unwrap(),
            Mode::MappedUnspecified => "[::ffff:0.0.0.0]:0".parse().unwrap(),
            Mode::Mapped => "[::ffff:192.0.2.1]:53".parse().unwrap(),
            _ => *addr,
        };
        replies.push_back((response.to_bytes().unwrap(), peer));
        Ok(wire.len())
    }
    async fn read_packet(&self, buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
        self.0.read.fetch_add(1, Ordering::SeqCst);
        if self.0.mode == Mode::ReadPending {
            self.0.started.notify_one();
            std::future::pending::<()>().await;
        }
        if self.0.mode == Mode::ReadError {
            return Err(io::Error::from_raw_os_error(24).into());
        }
        let (wire, peer) = self
            .0
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("no repeated send");
        buf[..wire.len()].copy_from_slice(&wire);
        Ok((wire.len(), peer))
    }
    fn local_addr(&self) -> meow_common::Result<SocketAddr> {
        Ok("0.0.0.0:0".parse().unwrap())
    }
    fn close(&self) -> meow_common::Result<()> {
        self.0.closed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProxyAdapter for TestProxy {
    fn name(&self) -> &str {
        "DNS fixture"
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        self.state.udp
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
    async fn dial_tcp(&self, m: &Metadata) -> meow_common::Result<Box<dyn ProxyConn>> {
        self.state.tcp.fetch_add(1, Ordering::SeqCst);
        self.state.seen.lock().unwrap().push(m.clone());
        assert_eq!(
            self.state.closed.load(Ordering::SeqCst),
            usize::from(self.state.mode == Mode::Truncated)
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let wire = read_lp(&mut server).await.unwrap();
            let mut reply = Message::from_bytes(&wire).unwrap();
            reply.metadata.message_type = MessageType::Response;
            write_lp(&mut server, &reply.to_bytes().unwrap())
                .await
                .unwrap();
        });
        Ok(Box::new(client))
    }
    async fn dial_udp(&self, m: &Metadata) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
        self.state.seen.lock().unwrap().push(m.clone());
        Ok(Box::new(Packet(Arc::clone(&self.state))))
    }
}
impl Proxy for TestProxy {
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
    fn delay_history(&self) -> Vec<DelayHistory> {
        vec![]
    }
}

fn fixture(mode: Mode, udp: bool, tcp: bool) -> (DnsClient, Arc<State>) {
    let state = Arc::new(State {
        mode,
        udp,
        closed: 0.into(),
        tcp: 0.into(),
        sent: 0.into(),
        read: 0.into(),
        started: Notify::new(),
        seen: Mutex::new(vec![]),
        replies: Mutex::new(VecDeque::new()),
    });
    let addr = "192.0.2.1:53".parse().unwrap();
    let client = if tcp {
        DnsClient::tcp(addr)
    } else {
        DnsClient::udp(addr)
    };
    (
        client.with_proxy(Arc::new(TestProxy {
            state: Arc::clone(&state),
            health: ProxyHealth::new(),
        })),
        state,
    )
}

#[tokio::test]
async fn udp_proxy_validates_source_and_question_and_closes() {
    for mode in [
        Mode::Valid,
        Mode::Unspecified,
        Mode::Mapped,
        Mode::MappedUnspecified,
    ] {
        let (client, state) = fixture(mode, true, false);
        client.query("fixture.test", RecordType::A).await.unwrap();
        assert_eq!(state.read.load(Ordering::SeqCst), 6);
        assert_eq!(state.sent.load(Ordering::SeqCst), 1);
        assert_eq!(state.tcp.load(Ordering::SeqCst), 0);
        assert_eq!(state.closed.load(Ordering::SeqCst), 1);
        let metadata = state.seen.lock().unwrap();
        let m = &metadata[0];
        assert!(m.internal);
        assert_eq!(m.network, Network::Udp);
        assert_eq!(m.conn_type, meow_common::ConnType::Inner);
        assert_eq!(m.dst_ip, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(m.dst_port, 53);
    }
}

#[tokio::test]
async fn udp_proxy_mapped_nameserver_dials_canonical_ip() {
    // A v4-mapped IPv6 nameserver must reach the adapter as plain IPv4 —
    // DirectAdapter-style dials fail on the mapped form.
    let state = Arc::new(State {
        mode: Mode::Valid,
        udp: true,
        closed: 0.into(),
        tcp: 0.into(),
        sent: 0.into(),
        read: 0.into(),
        started: Notify::new(),
        seen: Mutex::new(vec![]),
        replies: Mutex::new(VecDeque::new()),
    });
    let client =
        DnsClient::udp("[::ffff:192.0.2.1]:53".parse().unwrap()).with_proxy(Arc::new(TestProxy {
            state: Arc::clone(&state),
            health: ProxyHealth::new(),
        }));
    client.query("fixture.test", RecordType::A).await.unwrap();
    let seen = state.seen.lock().unwrap();
    assert_eq!(seen[0].host, "192.0.2.1");
    assert_eq!(seen[0].dst_ip, Some("192.0.2.1".parse().unwrap()));
    assert_eq!(seen[0].dst_port, 53);
}

#[tokio::test]
async fn udp_proxy_send_or_read_failure_never_retries_tcp() {
    for mode in [Mode::Short, Mode::Error, Mode::ReadError] {
        let (client, state) = fixture(mode, true, false);
        let error = client
            .query("fixture.test", RecordType::A)
            .await
            .unwrap_err();
        if mode != Mode::Short {
            assert!(matches!(error, ClientError::Io(e) if e.raw_os_error() == Some(24)));
        }
        assert_eq!(state.sent.load(Ordering::SeqCst), 1);
        assert_eq!(state.tcp.load(Ordering::SeqCst), 0);
        assert_eq!(state.closed.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn udp_proxy_cancel_and_timeout_close_pending_read_and_write() {
    for mode in [Mode::WritePending, Mode::ReadPending] {
        let (client, state) = fixture(mode, true, false);
        let task = tokio::spawn(async move { client.query("fixture.test", RecordType::A).await });
        tokio::time::timeout(Duration::from_secs(1), state.started.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(state.closed.load(Ordering::SeqCst), 1);
        assert_eq!(state.tcp.load(Ordering::SeqCst), 0);
        let (client, state) = fixture(mode, true, false);
        let error = client
            .with_timeout(Duration::from_millis(20))
            .query("fixture.test", RecordType::A)
            .await
            .unwrap_err();
        assert!(matches!(error, ClientError::Timeout(_)));
        assert_eq!(state.closed.load(Ordering::SeqCst), 1);
        assert_eq!(state.tcp.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn udp_proxy_truncated_valid_answer_uses_same_proxy_tcp() {
    let (client, state) = fixture(Mode::Truncated, true, false);
    assert!(
        !client
            .query("fixture.test", RecordType::A)
            .await
            .unwrap()
            .metadata
            .truncation
    );
    assert_eq!(state.tcp.load(Ordering::SeqCst), 1);
    assert_eq!(state.closed.load(Ordering::SeqCst), 1);
    assert_eq!(state.seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn udp_proxy_tcp_only_and_explicit_tcp_preserve_compatibility() {
    for (udp, tcp) in [(false, false), (true, true)] {
        let (client, state) = fixture(Mode::Valid, udp, tcp);
        client.query("fixture.test", RecordType::A).await.unwrap();
        assert_eq!(state.tcp.load(Ordering::SeqCst), 1);
        assert_eq!(state.sent.load(Ordering::SeqCst), 0);
        assert_eq!(state.closed.load(Ordering::SeqCst), 0);
        assert_eq!(state.seen.lock().unwrap()[0].network, Network::Tcp);
    }
}

#[tokio::test]
async fn udp_proxy_hostname_keeps_remote_resolution_over_tcp() {
    let (client, state) = fixture(Mode::Valid, true, false);
    client
        .with_proxy_target(Arc::from("resolver.example"), 5353)
        .query("fixture.test", RecordType::A)
        .await
        .unwrap();
    assert_eq!(state.sent.load(Ordering::SeqCst), 0);
    assert_eq!(state.tcp.load(Ordering::SeqCst), 1);
    let seen = state.seen.lock().unwrap();
    assert_eq!(seen[0].host, "resolver.example");
    assert_eq!(seen[0].dst_ip, None);
    assert_eq!(seen[0].dst_port, 5353);
}
