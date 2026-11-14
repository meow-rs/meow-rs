//! Integration test for DNS-via-proxy (issue #67 phase 2, ADR-0012).
//!
//! Sets up tiny in-process upstreams — a plain RFC-7766 TCP DNS stub, a
//! DoT stub (boring `SslAcceptor` + `rcgen` chain) and a DoH stub —
//! and plugs a mock [`Proxy`] adapter in front of them. The mock records
//! the [`Metadata`] it was asked to dial and then connects onward, so
//! each test proves the DNS exchange actually went through
//! `proxy.dial_tcp` and not through the global socket factory.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(feature = "encrypted")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use meow_common::{
    AdapterType, ConnType, DelayHistory, Metadata, Network, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, Result as MeowResult,
};
use meow_dns::client::DnsClient;
#[cfg(feature = "encrypted")]
use meow_dns::HostEntry;
use meow_dns::{NameServerEntry, Resolver};
#[cfg(feature = "encrypted")]
use meow_trie::DomainTrie;
use parking_lot::Mutex;
#[cfg(feature = "encrypted")]
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const T: Duration = Duration::from_secs(5);

/// Build the canned `A example.com.` → `203.0.113.7` response for a
/// decoded request message.
fn answer_for(req_msg: &Message) -> Message {
    let mut resp = Message::new(req_msg.id, MessageType::Response, OpCode::Query);
    resp.metadata.response_code = ResponseCode::NoError;
    resp.metadata.recursion_available = true;
    for q in &req_msg.queries {
        resp.add_query(q.clone());
        if q.query_type == RecordType::A {
            let name: Name = "example.com.".parse().unwrap();
            let rec = Record::from_rdata(name, 60, RData::A(A(Ipv4Addr::new(203, 0, 113, 7))));
            resp.add_answer(rec);
        }
    }
    resp
}

/// Read one RFC-7766 length-prefixed DNS message off `sock`; `None` on
/// EOF, truncation, or an undecodable frame.
async fn read_dns_frame<S>(sock: &mut S) -> Option<Message>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 2];
    sock.read_exact(&mut len_buf).await.ok()?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut req = vec![0u8; len];
    sock.read_exact(&mut req).await.ok()?;
    Message::from_bytes(&req).ok()
}

/// Write one RFC-7766 length-prefixed DNS message; `false` if the conn
/// died underneath the write.
async fn write_dns_frame<S>(sock: &mut S, msg: &Message) -> bool
where
    S: AsyncWriteExt + Unpin,
{
    let wire = msg.to_bytes().unwrap();
    let lenb = (wire.len() as u16).to_be_bytes();
    sock.write_all(&lenb).await.is_ok() && sock.write_all(&wire).await.is_ok()
}

/// Read one RFC-7766 length-prefixed DNS message off `sock` and write the
/// canned response back, same framing.
async fn serve_one_dns_frame<S>(sock: &mut S)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let Some(req_msg) = read_dns_frame(sock).await else {
        return;
    };
    let _ = write_dns_frame(sock, &answer_for(&req_msg)).await;
}

/// Start a stub DNS-over-TCP server that always answers `A example.com.` →
/// `203.0.113.7`. Returns the bound address.
async fn start_dns_tcp_stub() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                serve_one_dns_frame(&mut sock).await;
            });
        }
    });
    addr
}

/// A `boring` TLS acceptor for `sans` plus the DER bytes the client's
/// `with_tls_additional_roots` hook must trust (the cert is self-signed,
/// so the leaf doubles as its own root). The hook exists only in test /
/// debug builds, so the callers that use it are `debug_assertions`-gated
/// too — under `cargo test --release` both sides disappear together.
#[cfg(feature = "encrypted")]
fn tls_acceptor(sans: &[&str]) -> (boring::ssl::SslAcceptor, Vec<u8>) {
    let ck = rcgen::generate_simple_self_signed(
        sans.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>(),
    )
    .expect("rcgen cert generation failed");
    let cert = boring::x509::X509::from_der(ck.cert.der()).unwrap();
    let key = boring::pkey::PKey::private_key_from_der(&ck.key_pair.serialize_der()).unwrap();
    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    builder.set_certificate(&cert).unwrap();
    builder.set_private_key(&key).unwrap();
    builder.check_private_key().unwrap();
    (builder.build(), ck.cert.der().to_vec())
}

/// Per-connection behaviour of the configurable DoT stub — the fault
/// modes the TLS pool must survive.
///
/// `KeepAlive` is the only variant release builds ever construct
/// (`proxied_hostname_tls_upstream_dials_domain`); the fault variants
/// are consumed exclusively by `debug_assertions` tests. Rather than
/// cfg-splitting the enum — the `first`/`conn_index` plumbing in
/// `serve_dot_conn` would all need gating too — the dead-code lint is
/// allowed here with reason (review I1).
#[cfg(feature = "encrypted")]
#[allow(
    dead_code,
    reason = "fault variants are constructed only by `debug_assertions` tests; release builds use KeepAlive alone"
)]
enum DotBehavior {
    /// Answer every frame until the conn dies — RFC 7766 keep-alive, the
    /// mode pooling exists for.
    KeepAlive,
    /// Answer the first frame on each conn, then close it. The next
    /// query meets the pooled conn's liveness probe (or an exchange-time
    /// EOF) and must redial.
    CloseAfterFirst,
    /// Answer the first frame on each conn, then silently drop further
    /// frames without closing — the NAT/upstream half-close the reuse
    /// deadline bounds.
    SilentAfterFirst,
    /// Answer every frame only after `delay` — a slow-but-working
    /// upstream whose proven exchange RTT exceeds `timeout/2`, the band
    /// where a capped reuse deadline can never be met (review M2).
    Delayed { delay: Duration },
    /// Conn #0's first frame gets the correct answer, its second frame a
    /// response with a wrong transaction ID; every later conn behaves
    /// like [`DotBehavior::KeepAlive`]. Drives the "a `Protocol` error is
    /// never retried and never pooled" test.
    WrongIdOnSecond,
    /// [`DotBehavior::KeepAlive`] plus: a query for `held.example` blocks
    /// on `release` after reporting through `held_tx`, so a test can hold
    /// an exchange in flight across `reset_connections`.
    Gated {
        held_tx: tokio::sync::mpsc::UnboundedSender<()>,
        release: Arc<tokio::sync::Notify>,
    },
}

/// A running DoT stub: bound addr, DER root for the client's
/// `with_tls_additional_roots`, and the TCP accept counter — the conn
/// budget pooling exists to shrink.
#[cfg(feature = "encrypted")]
struct DotStub {
    addr: SocketAddr,
    /// Read only by `debug_assertions` tests (the
    /// `with_tls_additional_roots` hook they call doesn't exist in
    /// release) — allowed, not cfg-split, per review I1.
    #[allow(dead_code, reason = "read only by `debug_assertions` tests")]
    root: Vec<u8>,
    /// Pool-reuse evidence — likewise read only by `debug_assertions`
    /// tests.
    #[allow(dead_code, reason = "read only by `debug_assertions` tests")]
    accepts: Arc<AtomicUsize>,
}

/// Serve frames on one DoT conn under `behavior`; `conn_index` is the
/// accept order of this conn.
#[cfg(feature = "encrypted")]
async fn serve_dot_conn<S>(stream: &mut S, conn_index: usize, behavior: &DotBehavior)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut first = true;
    while let Some(req_msg) = read_dns_frame(stream).await {
        let mut wrong_id = false;
        match behavior {
            DotBehavior::KeepAlive => {}
            DotBehavior::CloseAfterFirst => {
                let _ = write_dns_frame(stream, &answer_for(&req_msg)).await;
                return;
            }
            DotBehavior::SilentAfterFirst => {
                if !first {
                    // Read and drop: the conn stays open but never
                    // answers again.
                    continue;
                }
            }
            DotBehavior::Delayed { delay } => {
                tokio::time::sleep(*delay).await;
            }
            DotBehavior::WrongIdOnSecond => {
                if conn_index == 0 && !first {
                    wrong_id = true;
                }
            }
            DotBehavior::Gated { held_tx, release } => {
                let held = req_msg
                    .queries
                    .first()
                    .is_some_and(|q| q.name().to_ascii().trim_end_matches('.') == "held.example");
                if held {
                    let notified = release.notified();
                    let _ = held_tx.send(());
                    notified.await;
                }
            }
        }
        first = false;
        let mut resp = answer_for(&req_msg);
        if wrong_id {
            resp.metadata.id = req_msg.id.wrapping_add(1);
        }
        if !write_dns_frame(stream, &resp).await {
            return;
        }
    }
}

/// Start a DoT stub under `behavior`: TLS, then the same length-prefixed
/// exchange as the plain TCP stub, per conn.
#[cfg(feature = "encrypted")]
async fn start_dot_stub_with(behavior: DotBehavior) -> DotStub {
    let (acceptor, root) = tls_acceptor(&["dot-stub.test"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let server_accepts = Arc::clone(&accepts);
    let behavior = Arc::new(behavior);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let conn_index = server_accepts.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let behavior = Arc::clone(&behavior);
            tokio::spawn(async move {
                let Ok(mut stream) = tokio_boring::accept(&acceptor, tcp).await else {
                    return;
                };
                serve_dot_conn(&mut stream, conn_index, &behavior).await;
            });
        }
    });
    DotStub {
        addr,
        root,
        accepts,
    }
}

/// The plain keep-alive DoT stub used by the routing tests.
#[cfg(feature = "encrypted")]
async fn start_dot_stub() -> DotStub {
    start_dot_stub_with(DotBehavior::KeepAlive).await
}

/// How the DoH stub frames its `200` response and how long the conn
/// lives — the pool-eligibility matrix of RFC 7230 §3.3 plus the
/// dead-conn fault modes the pool must survive (review M4).
#[cfg(all(feature = "encrypted", debug_assertions))]
#[derive(Clone, Copy)]
enum DohFraming {
    /// `Content-Length` + keep-alive → poolable.
    ContentLength,
    /// `Transfer-Encoding: chunked` + keep-alive → poolable.
    Chunked,
    /// `Content-Length` + `Connection: close` → correct answer, spent
    /// conn (the historical stub shape).
    CloseHeader,
    /// No CL/TE: the body is close-delimited → correct answer, spent
    /// conn.
    EofDelimited,
    /// One `Content-Length` keep-alive response per conn, then drop:
    /// the answer marks the conn poolable but it is already dead — the
    /// next checkout must catch it at the liveness probe.
    CloseAfterFirst,
    /// `Content-Length` keep-alive responses — except the second
    /// request on a conn, which gets half a head then `close_notify` +
    /// FIN. The liveness probe still sees an open conn (no FIN has been
    /// sent yet), so the EOF lands *inside* the exchange and must
    /// classify `Io` for the fresh retry to fire (review M3).
    HalfCloseOnSecond,
}

/// A running DoH stub — see [`DotStub`].
#[cfg(all(feature = "encrypted", debug_assertions))]
struct DohStub {
    addr: SocketAddr,
    root: Vec<u8>,
    accepts: Arc<AtomicUsize>,
}

/// Serve HTTP/1.1 POST requests on one DoH conn under `framing`:
/// keep-alive framings loop per conn; the close framings serve once.
#[cfg(all(feature = "encrypted", debug_assertions))]
async fn serve_doh_conn<S>(stream: &mut S, framing: DohFraming)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut requests = 0usize;
    loop {
        // Request headers up to the first blank line, then the
        // Content-Length body.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if stream.read_exact(&mut byte).await.is_err() {
                return;
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 8192 {
                return;
            }
        }
        let head_str = String::from_utf8_lossy(&head);
        let len: usize = head_str
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }
        let Ok(req_msg) = Message::from_bytes(&body) else {
            return;
        };
        requests += 1;
        if matches!(framing, DohFraming::HalfCloseOnSecond) && requests == 2 {
            // Half-close mid-response: partial head bytes, then
            // close_notify + FIN. The conn was open at probe time, so
            // this EOF lands inside the client's exchange — it must
            // classify `Io` for the fresh retry to fire (review M3).
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Len").await;
            let _ = stream.shutdown().await;
            return;
        }
        let wire = answer_for(&req_msg).to_bytes().unwrap();
        let (head, tail) = match framing {
            DohFraming::ContentLength
            | DohFraming::CloseAfterFirst
            | DohFraming::HalfCloseOnSecond => (
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/dns-message\r\n\
                     Content-Length: {}\r\n\
                     \r\n",
                    wire.len()
                ),
                wire,
            ),
            DohFraming::Chunked => {
                let mut framed = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/dns-message\r\n\
                     Transfer-Encoding: chunked\r\n\
                     \r\n{:x}\r\n",
                    wire.len()
                )
                .into_bytes();
                framed.extend_from_slice(&wire);
                framed.extend_from_slice(b"\r\n0\r\n\r\n");
                (String::new(), framed)
            }
            DohFraming::CloseHeader => (
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/dns-message\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n",
                    wire.len()
                ),
                wire,
            ),
            DohFraming::EofDelimited => (
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/dns-message\r\n\
                 \r\n"
                    .to_string(),
                wire,
            ),
        };
        if !head.is_empty() && stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        if stream.write_all(&tail).await.is_err() {
            return;
        }
        match framing {
            // Close framings: one response per conn, then drop it.
            DohFraming::CloseHeader | DohFraming::EofDelimited | DohFraming::CloseAfterFirst => {
                return
            }
            DohFraming::ContentLength | DohFraming::Chunked | DohFraming::HalfCloseOnSecond => {}
        }
    }
}

/// Start a DoH stub under `framing`. Only the `debug_assertions`-gated
/// DoH tests consume the DER root, so the stub is gated with it (dead
/// code otherwise under `--release`).
#[cfg(all(feature = "encrypted", debug_assertions))]
async fn start_doh_stub_with(framing: DohFraming) -> DohStub {
    let (acceptor, root) = tls_acceptor(&["doh-stub.test"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let server_accepts = Arc::clone(&accepts);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            server_accepts.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = tokio_boring::accept(&acceptor, tcp).await else {
                    return;
                };
                serve_doh_conn(&mut stream, framing).await;
            });
        }
    });
    DohStub {
        addr,
        root,
        accepts,
    }
}

/// The historical DoH stub: a `Connection: close` response, one per conn.
#[cfg(all(feature = "encrypted", debug_assertions))]
async fn start_doh_stub() -> DohStub {
    start_doh_stub_with(DohFraming::CloseHeader).await
}

/// What the mock proxy was asked to dial — the canonical DNS-via-proxy
/// metadata shape (issue #67 phase 2): `host` is the IP string for IP
/// targets and the domain for hostname targets, `dst_ip` is `None`
/// exactly when the proxy must resolve the domain remotely, `conn_type`
/// is `Inner` housekeeping traffic on `network: Tcp` (never a proxied
/// UDP flow masquerading as the DNS exchange), and `internal` is set so
/// lazy groups don't count it as use.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DialRecord {
    host: String,
    dst_ip: Option<IpAddr>,
    dst_port: u16,
    conn_type: ConnType,
    network: Network,
    internal: bool,
}

/// Mock proxy adapter: records the destination metadata of every dial,
/// then opens the TCP connection itself so the exchange really completes.
/// For a *domain* target (`dst_ip: None`) it connects to `forward_to` —
/// simulating a remote proxy that resolves the domain on its own side,
/// which is the whole point of the `?proxy=` hostname path.
struct MockProxy {
    name: String,
    dialed: Arc<Mutex<Vec<DialRecord>>>,
    forward_to: SocketAddr,
}

#[async_trait]
impl ProxyAdapter for MockProxy {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
        self.dialed.lock().push(DialRecord {
            host: metadata.host.to_string(),
            dst_ip: metadata.dst_ip,
            dst_port: metadata.dst_port,
            conn_type: metadata.conn_type,
            network: metadata.network,
            internal: metadata.internal,
        });
        let target = match metadata.dst_ip {
            Some(ip) => SocketAddr::new(ip, metadata.dst_port),
            None => self.forward_to,
        };
        let stream = TcpStream::connect(target)
            .await
            .map_err(meow_common::MeowError::Io)?;
        Ok(Box::new(stream))
    }
    async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
        unimplemented!("test mock has no UDP")
    }
    fn health(&self) -> &ProxyHealth {
        static H: std::sync::OnceLock<ProxyHealth> = std::sync::OnceLock::new();
        H.get_or_init(ProxyHealth::new)
    }
}

impl Proxy for MockProxy {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        Vec::new()
    }
}

fn mock_proxy(dialed: &Arc<Mutex<Vec<DialRecord>>>, forward_to: SocketAddr) -> Arc<dyn Proxy> {
    Arc::new(MockProxy {
        name: "PROXY-A".to_string(),
        dialed: Arc::clone(dialed),
        forward_to,
    })
}

fn assert_example_answer(msg: &Message) {
    let mut got: Option<IpAddr> = None;
    for ans in &msg.answers {
        if let RData::A(a) = &ans.data {
            got = Some(IpAddr::V4(a.0));
        }
    }
    assert_eq!(got, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
}

#[tokio::test]
async fn dns_client_routes_tcp_query_through_proxy() {
    let dns_addr = start_dns_tcp_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, dns_addr);

    let client = DnsClient::tcp(dns_addr).with_proxy(proxy);
    let msg = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("query must succeed");

    assert_example_answer(&msg);
    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: dns_addr.ip().to_string(),
            dst_ip: Some(dns_addr.ip()),
            dst_port: dns_addr.port(),
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "proxy must have been the dialer for the DNS exchange"
    );
}

#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_query_routes_through_proxy() {
    let stub = start_dot_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, stub.addr);

    let client = DnsClient::dot(stub.addr, "dot-stub.test")
        .with_proxy(proxy)
        .with_tls_additional_roots(stub.root);
    let msg = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("DoT query through the proxy must succeed");

    assert_example_answer(&msg);
    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: stub.addr.ip().to_string(),
            dst_ip: Some(stub.addr.ip()),
            dst_port: stub.addr.port(),
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "DoT exchange must dial through proxy.dial_tcp"
    );
}

#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_query_routes_through_proxy() {
    let stub = start_doh_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, stub.addr);

    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_proxy(proxy)
        .with_tls_additional_roots(stub.root);
    let msg = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("DoH query through the proxy must succeed");

    assert_example_answer(&msg);
    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: stub.addr.ip().to_string(),
            dst_ip: Some(stub.addr.ip()),
            dst_port: stub.addr.port(),
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "DoH exchange must dial through proxy.dial_tcp"
    );
}

/// The flagship `?proxy=` property: a *hostname* upstream whose name is
/// locally unresolvable still builds and routes — the adapter is asked to
/// dial the **domain** (`dst_ip: None`), which it resolves on the remote
/// side (the mock's `forward_to`). No bootstrap lookup runs.
#[tokio::test]
async fn proxied_hostname_tcp_upstream_needs_no_bootstrap() {
    let dns_addr = start_dns_tcp_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, dns_addr);

    // `unresolvable.invalid` cannot bootstrap-resolve anywhere — RFC
    // 2606 reserves the TLD as always-NXDOMAIN. `build_single_…` still
    // produces a client, because the proxy gets the name remotely.
    let entry = NameServerEntry::parse("tcp://unresolvable.invalid#PROXY-A").unwrap();
    assert_eq!(entry.proxy.as_deref(), Some("PROXY-A"));
    let resolved = HashMap::new();
    let client = Resolver::build_single_resolver_with_proxy(&entry.url, &resolved, Some(proxy));

    let msg = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("query through remote-resolved domain must succeed");

    assert_example_answer(&msg);
    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: "unresolvable.invalid".to_string(),
            dst_ip: None,
            dst_port: 53,
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "proxy must be asked to dial the domain, not a resolved IP"
    );
}

/// Same property for an encrypted upstream: `tls://<unresolvable>` +
/// `?proxy=` builds with no bootstrap and hands the domain to
/// `proxy.dial_tcp`. TLS then fails — the stub cert doesn't cover the
/// bogus SNI — but the recorded metadata proves the whole
/// `dial_tcp → connect_typed` chain ran.
#[cfg(feature = "encrypted")]
#[tokio::test]
async fn proxied_hostname_tls_upstream_dials_domain() {
    let stub = start_dot_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, stub.addr);

    let entry = NameServerEntry::parse("tls://unresolvable.invalid?proxy=PROXY-A").unwrap();
    assert_eq!(entry.proxy.as_deref(), Some("PROXY-A"));
    let resolved = HashMap::new();
    let client = Resolver::build_single_resolver_with_proxy(&entry.url, &resolved, Some(proxy));

    let err = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect_err("TLS must reject the stub cert for 'unresolvable.invalid'");
    assert!(
        matches!(err, meow_dns::client::ClientError::Tls(_)),
        "expected the TLS layer to be reached (dial → handshake); got {err:?}"
    );

    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![DialRecord {
            host: "unresolvable.invalid".to_string(),
            dst_ip: None,
            dst_port: 853,
            conn_type: ConnType::Inner,
            network: Network::Tcp,
            internal: true,
        }],
        "proxy must be asked to dial the domain, not a resolved IP"
    );
}

/// End-to-end resolver build: a `?proxy=` hostname main nameserver skips
/// bootstrap entirely — the `.invalid` TLD would make a real bootstrap
/// lookup fail, so a successful build is itself the assertion. Then a
/// resolve hands the domain to `dial_tcp` (the mock's `forward_to` is a
/// closed port, so the query itself dies at connect — the dial record is
/// the evidence).
#[cfg(feature = "encrypted")]
#[tokio::test]
async fn resolver_build_skips_bootstrap_for_proxied_hostnames() {
    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, "127.0.0.1:9".parse().unwrap());

    let entry =
        NameServerEntry::parse("https://unresolvable.invalid/dns-query?proxy=PROXY-A").unwrap();
    let mut registry: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
    registry.insert(SmolStr::from("PROXY-A"), proxy);

    let resolver = Resolver::new_with_bootstrap_with_proxies(
        vec![entry],
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        DomainTrie::<HostEntry>::new(),
        false,
        false,
        None,
        None,
        &registry,
        false,
    )
    .await
    .expect("proxied hostname upstream must build without bootstrap");

    let _ = timeout(T, resolver.resolve_ip("example.com")).await;
    assert!(
        dialed.lock().iter().any(|d| {
            d.host == "unresolvable.invalid"
                && d.dst_ip.is_none()
                && d.conn_type == ConnType::Inner
                && d.network == Network::Tcp
                && d.internal
        }),
        "resolve must dial the upstream *domain* through the proxy; got {:?}",
        dialed.lock()
    );
}

/// `?proxy=` is parsed before the feature gate: without `encrypted` the
/// scheme itself is already the error, and the chain must name it
/// (`EncryptedFeatureDisabled`), not a params error.
#[cfg(not(feature = "encrypted"))]
#[test]
fn query_proxy_requires_encrypted_feature() {
    let err = NameServerEntry::parse("tls://1.1.1.1?proxy=P").unwrap_err();
    assert!(matches!(
        err,
        meow_dns::NameServerParseError::EncryptedFeatureDisabled
    ));
}

// ---------------------------------------------------------------------
// DoT/DoH TLS session pooling (feat/dns-tls-pool).
//
// Every test needs `with_tls_additional_roots` (debug/test-only trust
// hook) plus the stub's accept counter, so the whole section is gated on
// `debug_assertions` like `doh_query_routes_through_proxy`.
// ---------------------------------------------------------------------

/// Two sequential DoT queries to a keep-alive upstream must ride one TCP
/// conn + one TLS handshake: accept #2 never happens.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_pool_reuses_one_connection_direct() {
    let stub = start_dot_stub_with(DotBehavior::KeepAlive).await;
    let client =
        DnsClient::dot(stub.addr, "dot-stub.test").with_tls_additional_roots(stub.root.clone());

    for name in ["a.example.com", "b.example.com"] {
        let msg = timeout(T, client.query(name, RecordType::A))
            .await
            .expect("must not stall")
            .expect("query must succeed");
        assert_example_answer(&msg);
    }
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        1,
        "the second query must reuse the pooled TLS conn"
    );
}

/// Same for DoH: a `Content-Length` keep-alive response keeps the conn
/// poolable, so the second query reuses it.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_pool_reuses_one_connection_direct() {
    let stub = start_doh_stub_with(DohFraming::ContentLength).await;
    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_tls_additional_roots(stub.root.clone());

    for name in ["a.example.com", "b.example.com"] {
        let msg = timeout(T, client.query(name, RecordType::A))
            .await
            .expect("must not stall")
            .expect("query must succeed");
        assert_example_answer(&msg);
    }
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        1,
        "the second query must reuse the pooled TLS conn"
    );
}

/// The `?proxy=` arm of the same pool: reuse skips `dial_tcp` entirely —
/// two queries, one recorded dial.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_pool_reuses_via_proxy() {
    let stub = start_dot_stub_with(DotBehavior::KeepAlive).await;
    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, stub.addr);
    let client = DnsClient::dot(stub.addr, "dot-stub.test")
        .with_proxy(proxy)
        .with_tls_additional_roots(stub.root.clone());

    for name in ["a.example.com", "b.example.com"] {
        let msg = timeout(T, client.query(name, RecordType::A))
            .await
            .expect("must not stall")
            .expect("query must succeed");
        assert_example_answer(&msg);
    }
    assert_eq!(
        dialed.lock().len(),
        1,
        "reusing a pooled proxied conn must skip proxy.dial_tcp"
    );
    assert_eq!(stub.accepts.load(Ordering::SeqCst), 1);
}

#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_pool_reuses_via_proxy() {
    let stub = start_doh_stub_with(DohFraming::ContentLength).await;
    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, stub.addr);
    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_proxy(proxy)
        .with_tls_additional_roots(stub.root.clone());

    for name in ["a.example.com", "b.example.com"] {
        let msg = timeout(T, client.query(name, RecordType::A))
            .await
            .expect("must not stall")
            .expect("query must succeed");
        assert_example_answer(&msg);
    }
    assert_eq!(
        dialed.lock().len(),
        1,
        "reusing a pooled proxied conn must skip proxy.dial_tcp"
    );
    assert_eq!(stub.accepts.load(Ordering::SeqCst), 1);
}

/// Fault injection: the upstream answers once then closes the conn. The
/// next query meets the liveness probe (or an exchange-time EOF) and must
/// redial — still a correct answer, now on conn #2.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_pool_recovers_when_server_closes_after_response() {
    let stub = start_dot_stub_with(DotBehavior::CloseAfterFirst).await;
    let client =
        DnsClient::dot(stub.addr, "dot-stub.test").with_tls_additional_roots(stub.root.clone());

    for name in ["a.example.com", "b.example.com"] {
        let msg = timeout(T, client.query(name, RecordType::A))
            .await
            .expect("must not stall")
            .expect("query must succeed even after the pooled conn died");
        assert_example_answer(&msg);
    }
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        2,
        "the dead pooled conn must be detected and redialed"
    );
}

/// Fault injection: the pooled conn stays open but silently stops
/// answering (the NAT half-close). The reuse attempt must hit its
/// bounded deadline — `min(timeout/2, max(4×est_rtt, 250ms))` — and retry
/// on a fresh conn well inside the query timeout.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_pool_silent_conn_retries_within_bounded_deadline() {
    let stub = start_dot_stub_with(DotBehavior::SilentAfterFirst).await;
    let client = DnsClient::dot(stub.addr, "dot-stub.test")
        .with_timeout(Duration::from_secs(4))
        .with_tls_additional_roots(stub.root.clone());

    timeout(T, client.query("a.example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("priming query must succeed");

    let started = std::time::Instant::now();
    let msg = timeout(T, client.query("b.example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("query must succeed via the bounded-deadline retry");
    assert_example_answer(&msg);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the silent pooled conn must be abandoned well inside the query timeout"
    );
    assert_eq!(stub.accepts.load(Ordering::SeqCst), 2);
}

/// Slow-but-working upstream (review M2): the pooled conn's proven RTT
/// exceeds `timeout/2`, so its capped reuse deadline can never be met —
/// the client must skip the attempt and dial fresh. That skip is what
/// keeps both halves of the query budget reachable: previously the
/// second query burned `t/2` on a doomed reuse and the fresh dial +
/// exchange timed out inside the remaining `t/2`.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_pool_skips_reuse_when_proven_rtt_exceeds_half_timeout() {
    // 600 ms > `timeout / 2` of the 1 s client — while a full fresh
    // dial + exchange still fits inside 1 s.
    let stub = start_dot_stub_with(DotBehavior::Delayed {
        delay: Duration::from_millis(600),
    })
    .await;
    let client = DnsClient::dot(stub.addr, "dot-stub.test")
        .with_timeout(Duration::from_secs(1))
        .with_tls_additional_roots(stub.root.clone());

    for index in 0..3 {
        let msg = timeout(
            T,
            client.query(&format!("n{index}.example.com"), RecordType::A),
        )
        .await
        .expect("must not stall")
        .expect("a proven-RTT beyond t/2 must skip reuse, not time out");
        assert_example_answer(&msg);
    }
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        3,
        "every query must skip the doomed reuse attempt and dial fresh"
    );
}

/// A wrong-ID response on a reused conn is a `Protocol` error — never
/// staleness, so the retry whitelist must NOT fire: no second dial, no
/// re-pool. The *next* query still succeeds on a fresh conn.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_pool_protocol_error_is_never_retried() {
    let stub = start_dot_stub_with(DotBehavior::WrongIdOnSecond).await;
    let client =
        DnsClient::dot(stub.addr, "dot-stub.test").with_tls_additional_roots(stub.root.clone());

    timeout(T, client.query("a.example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("priming query must succeed");
    assert_eq!(stub.accepts.load(Ordering::SeqCst), 1);

    let err = timeout(T, client.query("b.example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect_err("a wrong-ID response is a protocol violation");
    assert!(
        matches!(err, meow_dns::client::ClientError::Protocol(_)),
        "expected Protocol error, got {err:?}"
    );
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        1,
        "a Protocol error must not be retried — no second dial"
    );

    // The desynced conn was dropped, not re-pooled: the next query dials
    // conn #2 and succeeds.
    let msg = timeout(T, client.query("c.example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("query after the protocol failure must succeed");
    assert_example_answer(&msg);
    assert_eq!(stub.accepts.load(Ordering::SeqCst), 2);
}

/// DoH framing matrix at the pool level: `Content-Length` and chunked
/// keep-alive conns are pooled (accepts==1 after 2 queries);
/// `Connection: close` and close-delimited answers are still correct but
/// cost a new conn each (accepts==2).
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_pool_framing_matrix() {
    for (framing, want_accepts, label) in [
        (
            DohFraming::ContentLength,
            1,
            "Content-Length must be poolable",
        ),
        (DohFraming::Chunked, 1, "chunked must be poolable"),
        (
            DohFraming::CloseHeader,
            2,
            "Connection: close answers but must not pool",
        ),
        (
            DohFraming::EofDelimited,
            2,
            "close-delimited answers but must not pool",
        ),
    ] {
        let stub = start_doh_stub_with(framing).await;
        let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
            .with_tls_additional_roots(stub.root.clone());
        for name in ["a.example.com", "b.example.com"] {
            let msg = timeout(T, client.query(name, RecordType::A))
                .await
                .expect("must not stall")
                .unwrap_or_else(|e| panic!("{label}: query must succeed, got {e:?}"));
            assert_example_answer(&msg);
        }
        assert_eq!(stub.accepts.load(Ordering::SeqCst), want_accepts, "{label}");
    }
}

/// DoH dead-conn recovery, probe side (review M4): the upstream serves
/// one poolable (`Content-Length` keep-alive) answer per conn then
/// drops it, so the pooled conn is dead by the next checkout — the
/// liveness probe must reject it and the query succeed on a fresh conn.
///
/// `tls_probe_rejections` is the mutation pin: accepts alone cannot
/// separate "probe caught it" from "exchange-EOF caught it" — without
/// the probe the query is still rescued by the `{Io, deadline}` retry
/// and accepts==2, but the counter never moves.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_pool_recovers_when_server_closes_after_response() {
    let stub = start_doh_stub_with(DohFraming::CloseAfterFirst).await;
    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_tls_additional_roots(stub.root.clone());

    let msg = timeout(T, client.query("a.example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("priming query must succeed");
    assert_example_answer(&msg);
    assert_eq!(stub.accepts.load(Ordering::SeqCst), 1);

    // Let the server's FIN land before the probe polls — on loopback
    // 100 ms is far beyond scheduling jitter.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let msg = timeout(T, client.query("b.example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("query must succeed even after the pooled conn died");
    assert_example_answer(&msg);
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        2,
        "the dead pooled conn must be detected and redialed"
    );
    assert_eq!(
        client.tls_probe_rejections(),
        1,
        "the liveness probe — not the exchange-time EOF — must have caught the dead conn"
    );
}

/// The `?proxy=` arm of the same dead-conn recovery (review I4): a
/// pooled conn dialed through `proxy.dial_tcp` is probed, rejected and
/// redialed exactly like a direct one — the second dial is visible both
/// in the stub's accept counter and in the proxy's dial log, and the
/// redialed exchange rides a conn carrying the same `internal`/
/// `ConnType::Inner` metadata.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_pool_recovers_when_server_closes_after_response_via_proxy() {
    let stub = start_doh_stub_with(DohFraming::CloseAfterFirst).await;
    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, stub.addr);
    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_proxy(proxy)
        .with_tls_additional_roots(stub.root.clone());

    let msg = timeout(T, client.query("a.example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("priming query must succeed");
    assert_example_answer(&msg);
    assert_eq!(stub.accepts.load(Ordering::SeqCst), 1);
    assert_eq!(dialed.lock().len(), 1);

    // Let the server's FIN land before the probe polls — same margin
    // as the direct-path test above.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let msg = timeout(T, client.query("b.example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("query must succeed even after the pooled proxied conn died");
    assert_example_answer(&msg);
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        2,
        "the dead pooled proxied conn must be detected and redialed"
    );
    assert_eq!(
        client.tls_probe_rejections(),
        1,
        "the liveness probe — not the exchange-time EOF — must have caught the dead proxied conn"
    );
    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap.len(),
        2,
        "the pooled-conn redial must go through proxy.dial_tcp again"
    );
    assert!(
        dialed_snap.iter().all(|d| d.conn_type == ConnType::Inner
            && d.network == Network::Tcp
            && d.internal
            && d.dst_ip == Some(stub.addr.ip())
            && d.dst_port == stub.addr.port()),
        "every proxied dial — fresh or pooled-redial — must carry the DNS housekeeping metadata; got {dialed_snap:?}"
    );
}

/// DoH dead-conn recovery, exchange side (review M3/M4): the pooled
/// conn stays open — the probe sees it alive — then the server
/// half-closes *mid-response*. That EOF inside the exchange must
/// classify `Io` (not `Protocol`) so the `{Io, deadline}` whitelist
/// retries on a fresh conn. `probe_rejections == 0` pins the path: the
/// EOF — not the probe — detected the dead conn.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_pool_retries_when_conn_half_closes_mid_response() {
    let stub = start_doh_stub_with(DohFraming::HalfCloseOnSecond).await;
    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_tls_additional_roots(stub.root.clone());

    for name in ["a.example.com", "b.example.com"] {
        let msg = timeout(T, client.query(name, RecordType::A))
            .await
            .expect("must not stall")
            .expect("query must succeed via the fresh retry after the mid-response EOF");
        assert_example_answer(&msg);
    }
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        2,
        "the mid-response EOF must be retried on a fresh conn"
    );
    assert_eq!(
        client.tls_probe_rejections(),
        0,
        "the conn was open at probe time — the exchange-time EOF did the detection"
    );
}

/// `reset_connections` covers the TLS pool too: idle conns close and the
/// next query redials; a conn checked out across the reset finishes its
/// exchange but is never returned to the pool (issue #695 mirror).
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_pool_reset_connections_redials_and_never_pools_in_flight() {
    let (held_tx, mut held_rx) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let stub = start_dot_stub_with(DotBehavior::Gated {
        held_tx,
        release: Arc::clone(&release),
    })
    .await;
    let client = Arc::new(
        DnsClient::dot(stub.addr, "dot-stub.test").with_tls_additional_roots(stub.root.clone()),
    );

    client.query("warm.example", RecordType::A).await.unwrap();
    client.query("reuse.example", RecordType::A).await.unwrap();
    assert_eq!(stub.accepts.load(Ordering::SeqCst), 1, "the pool is reused");

    assert_eq!(client.reset_connections(), 1, "the idle conn closes now");
    assert_eq!(client.reset_connections(), 0, "nothing left to close");
    client
        .query("after-reset.example", RecordType::A)
        .await
        .unwrap();
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        2,
        "a reset forces a redial"
    );

    // Empty the pool so the held query rides a fresh conn (the pooled
    // attempt's short deadline would otherwise race the hold).
    client.reset_connections();
    let in_flight = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.query("held.example", RecordType::A).await }
    });
    held_rx.recv().await.unwrap();
    assert_eq!(stub.accepts.load(Ordering::SeqCst), 3);
    assert_eq!(
        client.reset_connections(),
        0,
        "the in-flight conn is checked out, not idle"
    );
    release.notify_one();
    in_flight
        .await
        .unwrap()
        .expect("an in-flight query completes across a reset");

    client
        .query("after-in-flight.example", RecordType::A)
        .await
        .unwrap();
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        4,
        "the conn that was in flight across the reset must not be pooled"
    );
}

/// Eight concurrent cold queries each dial their own conn — concurrency
/// is never capped at the pool size — and the surplus validated conns
/// close at push, leaving at most `TLS_POOL_CAPACITY` (4) idle.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn dot_pool_burst_is_not_capped_at_pool_size() {
    let stub = start_dot_stub_with(DotBehavior::KeepAlive).await;
    let client = Arc::new(
        DnsClient::dot(stub.addr, "dot-stub.test").with_tls_additional_roots(stub.root.clone()),
    );

    let burst = 8usize;
    let queries: Vec<_> = (0..burst)
        .map(|index| {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                client
                    .query(&format!("burst-{index}.example.com"), RecordType::A)
                    .await
            })
        })
        .collect();
    for query in queries {
        let msg = timeout(T, query)
            .await
            .expect("must not stall")
            .expect("join")
            .expect("every concurrent query must succeed");
        assert_example_answer(&msg);
    }
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        burst,
        "a cold burst pays one conn per query — never queued behind the pool"
    );
    let idle = client.reset_connections();
    assert!(
        idle <= 4,
        "surplus conns must close at push, leaving <= TLS_POOL_CAPACITY idle (saw {idle})"
    );
}

/// Mutation control: with the pool disabled the same sequence pays full
/// price — the reuse assertions above measure real pooling, not a no-op.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn tls_pool_disabled_pays_full_price() {
    let stub = start_dot_stub_with(DotBehavior::KeepAlive).await;
    let client = DnsClient::dot(stub.addr, "dot-stub.test")
        .with_tls_additional_roots(stub.root.clone())
        .with_tls_pool_disabled();

    for index in 0..3 {
        let msg = timeout(
            T,
            client.query(&format!("n{index}.example.com"), RecordType::A),
        )
        .await
        .expect("must not stall")
        .expect("query must succeed un-pooled");
        assert_example_answer(&msg);
    }
    assert_eq!(
        stub.accepts.load(Ordering::SeqCst),
        3,
        "a pool-disabled client must dial once per query"
    );
}

/// A DoH stub shaped like Yandex DNS (77.88.8.8): it accepts either ALPN
/// and prefers `h2`, but closes every HTTP/1.1 request unanswered. The
/// counters split accepted conns by negotiated protocol and count h2
/// streams; `streams_per_conn` closes a conn after that many answers.
#[cfg(all(feature = "encrypted", debug_assertions))]
struct H2DohStub {
    addr: SocketAddr,
    root: Vec<u8>,
    http1_conns: Arc<AtomicUsize>,
    h2_conns: Arc<AtomicUsize>,
    h2_streams: Arc<AtomicUsize>,
}

#[cfg(all(feature = "encrypted", debug_assertions))]
async fn start_h2_doh_stub(streams_per_conn: Option<usize>) -> H2DohStub {
    let ck = rcgen::generate_simple_self_signed(vec!["doh-stub.test".to_string()]).unwrap();
    let cert = boring::x509::X509::from_der(ck.cert.der()).unwrap();
    let key = boring::pkey::PKey::private_key_from_der(&ck.key_pair.serialize_der()).unwrap();
    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    builder.set_certificate(&cert).unwrap();
    builder.set_private_key(&key).unwrap();
    builder.set_alpn_select_callback(|_, client| {
        boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", client)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let http1_conns = Arc::new(AtomicUsize::new(0));
    let h2_conns = Arc::new(AtomicUsize::new(0));
    let h2_streams = Arc::new(AtomicUsize::new(0));
    let counters = (
        Arc::clone(&http1_conns),
        Arc::clone(&h2_conns),
        Arc::clone(&h2_streams),
    );
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let (h1, h2c, streams) = (
                Arc::clone(&counters.0),
                Arc::clone(&counters.1),
                Arc::clone(&counters.2),
            );
            tokio::spawn(async move {
                let Ok(mut stream) = tokio_boring::accept(&acceptor, tcp).await else {
                    return;
                };
                if stream.ssl().selected_alpn_protocol() != Some(b"h2") {
                    h1.fetch_add(1, Ordering::SeqCst);
                    // Read the request, then close without a response.
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.shutdown().await;
                    return;
                }
                h2c.fetch_add(1, Ordering::SeqCst);
                let Ok(mut conn) = h2::server::handshake(stream).await else {
                    return;
                };
                let mut answered = 0usize;
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    assert_eq!(request.method(), http::Method::POST);
                    assert_eq!(request.uri().path(), "/dns-query");
                    streams.fetch_add(1, Ordering::SeqCst);
                    // Each stream answers on its own task, so concurrent
                    // queries really share the conn.
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        let mut wire = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            wire.extend_from_slice(&chunk);
                        }
                        let Ok(req_msg) = Message::from_bytes(&wire) else {
                            return;
                        };
                        let answer = answer_for(&req_msg).to_bytes().unwrap();
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(response, false) else {
                            return;
                        };
                        let _ = send.send_data(bytes::Bytes::from(answer), true);
                    });
                    answered += 1;
                    if streams_per_conn.is_some_and(|limit| answered >= limit) {
                        conn.graceful_shutdown();
                    }
                }
            });
        }
    });
    H2DohStub {
        addr,
        root: ck.cert.der().to_vec(),
        http1_conns,
        h2_conns,
        h2_streams,
    }
}

#[cfg(all(feature = "encrypted", debug_assertions))]
async fn query_ok(client: &DnsClient, name: &str) {
    let msg = timeout(T, client.query(name, RecordType::A))
        .await
        .expect("must not stall")
        .expect("DoH query must succeed over h2");
    assert_example_answer(&msg);
}

/// A server that answers only over h2 (Yandex DNS closes HTTP/1.1
/// requests) is reached by offering `h2` in ALPN, and every query after
/// the first, sequential or concurrent, is a stream on the same conn.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_negotiates_h2_and_shares_one_connection() {
    let stub = start_h2_doh_stub(None).await;
    let client = Arc::new(
        DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
            .with_tls_additional_roots(stub.root.clone()),
    );

    for name in ["a.example.com", "b.example.com", "c.example.com"] {
        query_ok(&client, name).await;
    }
    let burst = futures::future::join_all((0..8).map(|index| {
        let client = Arc::clone(&client);
        async move { query_ok(&client, &format!("n{index}.example.com")).await }
    }));
    timeout(T, burst).await.expect("burst must not stall");

    assert_eq!(stub.http1_conns.load(Ordering::SeqCst), 0);
    assert_eq!(
        stub.h2_conns.load(Ordering::SeqCst),
        1,
        "every query after the first rides the shared h2 conn"
    );
    assert_eq!(stub.h2_streams.load(Ordering::SeqCst), 11);
}

/// The same over a `?proxy=` dial: one proxied dial serves every query.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_h2_via_proxy_dials_once() {
    let stub = start_h2_doh_stub(None).await;
    let dialed = Arc::new(Mutex::new(Vec::<DialRecord>::new()));
    let proxy = mock_proxy(&dialed, stub.addr);
    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_proxy(proxy)
        .with_tls_additional_roots(stub.root.clone());

    for name in ["a.example.com", "b.example.com", "c.example.com"] {
        query_ok(&client, name).await;
    }
    assert_eq!(stub.http1_conns.load(Ordering::SeqCst), 0);
    assert_eq!(stub.h2_conns.load(Ordering::SeqCst), 1);
    assert_eq!(dialed.lock().len(), 1, "the shared h2 conn is dialed once");
}

/// A server that ends the h2 conn after each answer (GOAWAY) costs a
/// redial, never a failed query.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_h2_redials_after_server_goaway() {
    let stub = start_h2_doh_stub(Some(1)).await;
    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_tls_additional_roots(stub.root.clone());

    for index in 0..4 {
        query_ok(&client, &format!("n{index}.example.com")).await;
        // Let the GOAWAY reach the client between queries part of the
        // time; the reuse path's retry covers the rest.
        if index % 2 == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    assert_eq!(stub.h2_streams.load(Ordering::SeqCst), 4);
    assert_eq!(stub.h2_conns.load(Ordering::SeqCst), 4);
}

/// `reset_connections` retires the shared h2 conn: the next query dials.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_h2_reset_connections_redials() {
    let stub = start_h2_doh_stub(None).await;
    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_tls_additional_roots(stub.root.clone());

    query_ok(&client, "a.example.com").await;
    assert_eq!(client.reset_connections(), 1, "the shared h2 conn closes");
    query_ok(&client, "b.example.com").await;
    assert_eq!(stub.h2_conns.load(Ordering::SeqCst), 2);
}

/// Mutation control for the sharing assertions: with the pool disabled
/// every h2 query dials its own conn.
#[cfg(all(feature = "encrypted", debug_assertions))]
#[tokio::test]
async fn doh_h2_pool_disabled_dials_per_query() {
    let stub = start_h2_doh_stub(None).await;
    let client = DnsClient::doh(stub.addr, "doh-stub.test", "/dns-query")
        .with_tls_additional_roots(stub.root.clone())
        .with_tls_pool_disabled();

    for name in ["a.example.com", "b.example.com", "c.example.com"] {
        query_ok(&client, name).await;
    }
    assert_eq!(stub.h2_conns.load(Ordering::SeqCst), 3);
}
