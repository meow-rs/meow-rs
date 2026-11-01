// `DnsClient::with_tls_additional_roots` — the hook that trusts the peer's
// self-signed chain without disabling verification — exists only when
// `debug_assertions` is on (the library is not built with `cfg(test)` here),
// which is also how the sibling `proxy_routed_dns` suite gates its TLS tests.
#![cfg(all(feature = "quic-dns", debug_assertions))]

//! DNS over QUIC and DoH-over-HTTP/3 against a real in-process QUIC server.
//!
//! The peer below is an actual `quiche` server with a self-signed
//! certificate, BoringSSL handshake and `quiche::h3` request handling —
//! because that is the only way to cover what these transports add: RFC 9250
//! stream framing, the zero transaction ID on the wire, connection reuse
//! across queries, a real HTTP/3 request/response (headers, body, FIN), and
//! the `prefer-h3` fallback to the HTTP/1.1 DoH path when QUIC is not
//! answered at all.
//!
//! Everything here is hermetic: no public resolver is contacted, so the suite
//! runs in CI without outbound DNS.

use std::collections::{hash_map::Entry, HashMap};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use quiche::h3::{self, NameValue as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use meow_common::{
    AdapterType, ConnType, DelayHistory, MeowError, Metadata, Network, Proxy, ProxyAdapter,
    ProxyConn, ProxyHealth, ProxyPacketConn,
};
use meow_dns::{ClientError, DnsClient};

/// The address every in-process server answers with.
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);
const TTL: u32 = 30;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Proto {
    Doq,
    H3,
}

/// What the in-process endpoint saw.
#[derive(Default)]
struct Observed {
    /// Transaction IDs as they arrived on the wire.
    ids: Vec<u16>,
    /// `(method, path, content-type)` per HTTP/3 request.
    requests: Vec<(String, String, String)>,
}

struct Endpoint {
    addr: SocketAddr,
    cert: Vec<u8>,
    observed: Arc<Mutex<Observed>>,
    connections: Arc<AtomicUsize>,
    /// UDP datagrams that reached this port. The `prefer-h3` fallback test
    /// binds a silent UDP socket so "did the second query try QUIC again?"
    /// becomes observable instead of inferred.
    datagrams: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Endpoint {
    fn ids(&self) -> Vec<u16> {
        self.observed.lock().unwrap().ids.clone()
    }

    fn requests(&self) -> Vec<(String, String, String)> {
        self.observed.lock().unwrap().requests.clone()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn datagrams(&self) -> usize {
        self.datagrams.load(Ordering::SeqCst)
    }
}

fn identity() -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (key.cert.der().to_vec(), key.key_pair.serialize_der())
}

/// Answer a serialized query: A for `a.*`, NXDOMAIN for `nx.*`, mirroring
/// what the resolver distinguishes upstream.
fn answer(query: &[u8], id: u16) -> Vec<u8> {
    let request = Message::from_bytes(query).expect("server saw a malformed query");
    let mut response = Message::new(id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_available = true;
    for question in &request.queries {
        response.add_query(question.clone());
        let name = question.name().clone();
        if name.to_string().starts_with("nx") {
            response.metadata.response_code = ResponseCode::NXDomain;
        } else {
            response.add_answer(Record::from_rdata(name, TTL, RData::A(A(ANSWER))));
        }
    }
    response.to_bytes().unwrap()
}

/// Start a QUIC endpoint. `proto` selects the ALPN (`doq` or `h3`).
async fn spawn(proto: Proto) -> Endpoint {
    let (cert, key) = identity();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let config = server_config(proto, &(cert.clone(), key));
    let observed = Arc::new(Mutex::new(Observed::default()));
    let connections = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(serve_quic(
        socket,
        proto,
        config,
        Arc::clone(&observed),
        Arc::clone(&connections),
    ));
    Endpoint {
        addr,
        cert,
        observed,
        connections,
        datagrams: Arc::new(AtomicUsize::new(0)),
        task,
    }
}

/// A TLS DoH-over-HTTP/1.1 endpoint whose UDP port stays closed, so a QUIC
/// attempt cannot be answered and the `prefer-h3` fallback is exercised.
async fn spawn_h1_only() -> Endpoint {
    let (cert, key) = identity();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let observed = Arc::new(Mutex::new(Observed::default()));
    let connections = Arc::new(AtomicUsize::new(0));
    tokio::spawn(serve_h1_listener(
        listener,
        Arc::clone(&observed),
        (cert.clone(), key),
    ));
    // A silent UDP socket on the same port: any QUIC attempt shows up here as
    // a datagram and is never answered (so the attempt fails at its budget).
    let datagrams = Arc::new(AtomicUsize::new(0));
    if let Ok(udp) = UdpSocket::bind(addr).await {
        let datagrams = Arc::clone(&datagrams);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok((n, _)) = udp.recv_from(&mut buf).await {
                if n > 0 {
                    datagrams.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }
    Endpoint {
        addr,
        cert,
        observed,
        connections,
        datagrams,
        task: tokio::spawn(std::future::pending()),
    }
}

fn server_config(proto: Proto, (cert, key): &(Vec<u8>, Vec<u8>)) -> quiche::Config {
    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
    ssl.set_certificate(&boring::x509::X509::from_der(cert).unwrap())
        .unwrap();
    ssl.set_private_key(&boring::pkey::PKey::private_key_from_der(key).unwrap())
        .unwrap();
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
    let alpn: &[&[u8]] = match proto {
        Proto::Doq => &[b"doq"],
        Proto::H3 => h3::APPLICATION_PROTOCOL,
    };
    config.set_application_protos(alpn).unwrap();
    config.set_max_idle_timeout(30_000);
    config.set_initial_max_data(4 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(1024 * 1024);
    config.set_initial_max_stream_data_uni(1024 * 1024);
    config.set_initial_max_streams_bidi(32);
    config.set_initial_max_streams_uni(8);
    config
}

struct Peer {
    conn: quiche::Connection,
    h3: Option<h3::Connection>,
    /// DoQ: bytes received per stream. h3: the request body per stream plus
    /// its `:path`.
    streams: HashMap<u64, StreamBuf>,
}

#[derive(Default)]
struct StreamBuf {
    body: Vec<u8>,
    path: String,
    method: String,
    content_type: String,
    answered: bool,
}

async fn serve_quic(
    socket: UdpSocket,
    proto: Proto,
    mut config: quiche::Config,
    observed: Arc<Mutex<Observed>>,
    connections: Arc<AtomicUsize>,
) {
    let local = socket.local_addr().unwrap();
    let h3_config = h3::Config::new().unwrap();
    let mut peers: HashMap<SocketAddr, Peer> = HashMap::new();
    let mut incoming = vec![0u8; 65_535];
    let mut outgoing = vec![0u8; 1350];
    let mut scratch = vec![0u8; 4 * 1024];

    loop {
        let timeout = peers.values().filter_map(|peer| peer.conn.timeout()).min();
        tokio::select! {
            result = socket.recv_from(&mut incoming) => {
                let Ok((n, from)) = result else { continue };
                if let Entry::Vacant(slot) = peers.entry(from) {
                    let Ok(header) = quiche::Header::from_slice(&mut incoming[..n], quiche::MAX_CONN_ID_LEN) else { continue };
                    if header.ty != quiche::Type::Initial {
                        continue;
                    }
                    let conn = quiche::accept(&header.dcid, None, local, from, &mut config)
                        .expect("accept");
                    connections.fetch_add(1, Ordering::SeqCst);
                    slot.insert(Peer { conn, h3: None, streams: HashMap::new() });
                }
                let peer = peers.get_mut(&from).expect("just inserted");
                let info = quiche::RecvInfo { from, to: local };
                let _ = peer.conn.recv(&mut incoming[..n], info);
            }
            () = sleep_opt(timeout) => {
                for peer in peers.values_mut() {
                    peer.conn.on_timeout();
                }
            }
        }

        for peer in peers.values_mut() {
            let Peer { conn, h3, streams } = peer;
            // DoQ: every readable bidi stream is one query.
            if proto == Proto::Doq {
                let readable: Vec<u64> = conn.readable().collect();
                for id in readable {
                    let entry = streams.entry(id).or_default();
                    // Drain what the stream delivered this round; `Done`
                    // (and a dead stream) both end the loop.
                    while let Ok((n, fin)) = conn.stream_recv(id, &mut scratch) {
                        entry.body.extend_from_slice(&scratch[..n]);
                        if fin || doq_frame_complete(&entry.body) {
                            break;
                        }
                    }
                    if entry.answered || !doq_frame_complete(&entry.body) {
                        continue;
                    }
                    // RFC 9250 §4.2: length-prefixed message, ID zero.
                    let len = usize::from(u16::from_be_bytes([entry.body[0], entry.body[1]]));
                    let query = &entry.body[2..2 + len];
                    observed
                        .lock()
                        .unwrap()
                        .ids
                        .push(u16::from_be_bytes([query[0], query[1]]));
                    let response = answer(query, 0);
                    let mut framed = Vec::with_capacity(response.len() + 2);
                    framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&response);
                    let _ = conn.stream_send(id, &framed, true);
                    entry.answered = true;
                }
            } else {
                if h3.is_none() && conn.is_established() {
                    *h3 =
                        Some(h3::Connection::with_transport(conn, &h3_config).expect("h3 server"));
                }
                if let Some(http3) = h3.as_mut() {
                    let mut replies = Vec::new();
                    loop {
                        match http3.poll(conn) {
                            Ok((id, h3::Event::Headers { list, .. })) => {
                                let entry = streams.entry(id).or_default();
                                entry.method = header(&list, b":method");
                                entry.path = header(&list, b":path");
                                entry.content_type = header(&list, b"content-type");
                                observed.lock().unwrap().requests.push((
                                    entry.method.clone(),
                                    entry.path.clone(),
                                    entry.content_type.clone(),
                                ));
                            }
                            Ok((id, h3::Event::Data)) => loop {
                                let entry = streams.entry(id).or_default();
                                match http3.recv_body(conn, id, &mut scratch) {
                                    Ok(n) => entry.body.extend_from_slice(&scratch[..n]),
                                    Err(_) => break,
                                }
                            },
                            Ok((id, h3::Event::Finished)) => {
                                replies.push(id);
                            }
                            Ok((id, h3::Event::Reset(_))) => {
                                streams.remove(&id);
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                    for id in replies {
                        let Some(entry) = streams.get(&id) else {
                            continue;
                        };
                        if entry.answered {
                            continue;
                        }
                        // HTTP/3 carries its own framing, so the DNS
                        // transaction ID is the client's own — unlike DoQ.
                        let request_id = u16::from_be_bytes([entry.body[0], entry.body[1]]);
                        let body = answer(&entry.body, request_id);
                        let headers = [
                            h3::Header::new(b":status", b"200"),
                            h3::Header::new(b"content-type", b"application/dns-message"),
                        ];
                        let _ = http3.send_response(conn, id, &headers, false);
                        let _ = http3.send_body(conn, id, &body, true);
                        streams.get_mut(&id).unwrap().answered = true;
                    }
                }
            }
        }

        for peer in peers.values_mut() {
            while let Ok((written, info)) = peer.conn.send(&mut outgoing) {
                let _ = socket.send_to(&outgoing[..written], info.to).await;
            }
        }
        peers.retain(|_, peer| !peer.conn.is_closed());
    }
}

fn doq_frame_complete(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    buf.len() >= len + 2
}

fn header(list: &[h3::Header], name: &[u8]) -> String {
    list.iter()
        .find(|h| h.name() == name)
        .map(|h| String::from_utf8_lossy(h.value()).into_owned())
        .unwrap_or_default()
}

/// Minimal DoH-over-HTTP/1.1 responder: one TLS POST per connection.
async fn serve_h1_listener(
    listener: TcpListener,
    observed: Arc<Mutex<Observed>>,
    (cert, key): (Vec<u8>, Vec<u8>),
) {
    let mut acceptor =
        boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls())
            .expect("acceptor");
    acceptor
        .set_certificate(&boring::x509::X509::from_der(&cert).expect("cert"))
        .expect("set_certificate");
    acceptor
        .set_private_key(&boring::pkey::PKey::private_key_from_der(&key).expect("key"))
        .expect("set_private_key");
    acceptor.set_alpn_select_callback(|_, _| Ok(b"http/1.1"));
    let acceptor = acceptor.build();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let observed = Arc::clone(&observed);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(mut stream) = tokio_boring::accept(&acceptor, stream).await else {
                return;
            };
            let mut buf = vec![0u8; 64 * 1024];
            let mut filled = 0;
            loop {
                let Ok(n) = stream.read(&mut buf[filled..]).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                filled += n;
                let text = String::from_utf8_lossy(&buf[..filled]).to_string();
                let Some(header_end) = text.find("\r\n\r\n") else {
                    continue;
                };
                let header_len = header_end + 4;
                let content_length = text[..header_end]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.eq_ignore_ascii_case("content-length") {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                if filled < header_len + content_length {
                    continue;
                }
                if content_length < 2 {
                    // Not a DNS message; nothing to answer.
                    return;
                }
                let body = &buf[header_len..header_len + content_length];
                let request_id = u16::from_be_bytes([body[0], body[1]]);
                observed.lock().unwrap().ids.push(request_id);
                let response = answer(body, request_id);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
                return;
            }
        });
    }
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(timeout) => tokio::time::sleep(timeout).await,
        None => std::future::pending().await,
    }
}

fn client_addr(endpoint: &Endpoint) -> SocketAddr {
    endpoint.addr
}

// ------------------------------------------------------------------- the tests

/// DoQ: RFC 9250 framing both ways, ID 0 on the wire, and one connection
/// reused by the second query.
#[tokio::test]
async fn doq_queries_round_trip_and_reuse_one_connection() {
    let endpoint = spawn(Proto::Doq).await;
    let client = DnsClient::doq(client_addr(&endpoint), "localhost")
        .with_timeout(Duration::from_secs(5))
        .with_tls_additional_roots(endpoint.cert.clone());

    let first = client.query("a.test", RecordType::A).await.unwrap();
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);
    let ips: Vec<_> = first
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    assert_eq!(ips, vec![ANSWER]);

    let second = client.query("b.test", RecordType::A).await.unwrap();
    assert_eq!(second.queries[0].name().to_string(), "b.test.");

    // RFC 9250 §4.2.1: both queries left with transaction ID 0 …
    assert_eq!(endpoint.ids(), vec![0, 0]);
    // … and shared one QUIC connection.
    assert_eq!(
        endpoint.connections(),
        1,
        "second query must reuse the connection"
    );
}

/// The wire ID is zeroed without disturbing the caller: the response the
/// client returns carries the ID it asked with, or validation would fail.
#[tokio::test]
async fn doq_restores_the_caller_transaction_id() {
    let endpoint = spawn(Proto::Doq).await;
    let client = DnsClient::doq(client_addr(&endpoint), "localhost")
        .with_timeout(Duration::from_secs(5))
        .with_tls_additional_roots(endpoint.cert.clone());
    // `query` validates ID/opcode/question internally, so a mismatch would
    // surface here as a Protocol error.
    let response = client.query("id.test", RecordType::A).await.unwrap();
    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.answers.len(), 1);
}

/// `reset_connections` retires the live connection; the next query dials a
/// fresh one instead of failing.
#[tokio::test]
async fn doq_redials_after_reset_connections() {
    let endpoint = spawn(Proto::Doq).await;
    let client = DnsClient::doq(client_addr(&endpoint), "localhost")
        .with_timeout(Duration::from_secs(5))
        .with_tls_additional_roots(endpoint.cert.clone());
    client.query("a.test", RecordType::A).await.unwrap();
    assert_eq!(endpoint.connections(), 1);
    client.reset_connections();
    client.query("b.test", RecordType::A).await.unwrap();
    assert_eq!(
        endpoint.connections(),
        2,
        "reset must force a new handshake"
    );
}

/// NXDOMAIN survives the transport: the response rcode is relayed, not
/// collapsed into an empty answer.
#[tokio::test]
async fn doq_relays_negative_rcodes() {
    let endpoint = spawn(Proto::Doq).await;
    let client = DnsClient::doq(client_addr(&endpoint), "localhost")
        .with_timeout(Duration::from_secs(5))
        .with_tls_additional_roots(endpoint.cert.clone());
    let response = client.query("nx.test", RecordType::A).await.unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(response.answers.is_empty());
}

/// An untrusted certificate is a hard verdict, not something the transport
/// retries or hides.
#[tokio::test]
async fn doq_rejects_an_untrusted_certificate() {
    let endpoint = spawn(Proto::Doq).await;
    let client =
        DnsClient::doq(client_addr(&endpoint), "localhost").with_timeout(Duration::from_secs(5));
    let err = client.query("a.test", RecordType::A).await.unwrap_err();
    assert!(
        matches!(err, ClientError::Tls(_)),
        "expected a certificate verdict, got {err:?}"
    );
}

/// DoH3: a real HTTP/3 POST with the RFC 8484 media type both ways.
#[tokio::test]
async fn doh3_posts_dns_messages_over_http3() {
    let endpoint = spawn(Proto::H3).await;
    let client = DnsClient::doh3(client_addr(&endpoint), "localhost", "/dns-query")
        .with_timeout(Duration::from_secs(5))
        .with_tls_additional_roots(endpoint.cert.clone());

    let response = client.query("a.test", RecordType::A).await.unwrap();
    assert_eq!(response.answers.len(), 1);
    let requests = endpoint.requests();
    assert_eq!(requests.len(), 1, "one POST per query");
    assert_eq!(requests[0].0, "POST");
    assert_eq!(requests[0].1, "/dns-query");
    assert_eq!(requests[0].2, "application/dns-message");

    // A second query multiplexes over the same QUIC connection.
    client.query("b.test", RecordType::A).await.unwrap();
    assert_eq!(endpoint.requests().len(), 2);
    assert_eq!(endpoint.connections(), 1);
}

/// `prefer-h3` falls back to HTTP/1.1 DoH when the QUIC path is dead, and
/// parks HTTP/3 so the next query does not pay another failed handshake.
#[tokio::test]
async fn doh3_falls_back_to_http1_and_parks_h3() {
    let endpoint = spawn_h1_only().await;
    let client = DnsClient::doh3(client_addr(&endpoint), "localhost", "/dns-query")
        .with_timeout(Duration::from_secs(3))
        .with_tls_additional_roots(endpoint.cert.clone());

    let first = client.query("a.test", RecordType::A).await.unwrap();
    assert_eq!(first.answers.len(), 1);
    let attempts = endpoint.datagrams();
    assert!(attempts > 0, "the first query must try QUIC once");

    let second = client.query("b.test", RecordType::A).await.unwrap();
    assert_eq!(second.answers.len(), 1);
    // Both answers came from the HTTP/1.1 fallback (the only listener).
    assert_eq!(endpoint.ids().len(), 2);
    // …and the failed handshake is parked: the second query goes straight to
    // HTTP/1.1 instead of paying another QUIC attempt.
    assert_eq!(
        endpoint.datagrams(),
        attempts,
        "HTTP/3 must stay parked after a failed handshake"
    );
}

/// `?h3=true` / mihomo's per-entry form means HTTP/3 only: no HTTP/1.1
/// fallback, so the QUIC failure is the answer.
#[tokio::test]
async fn doh3_force_reports_the_quic_failure() {
    let endpoint = spawn_h1_only().await;
    let client = DnsClient::doh3_force(client_addr(&endpoint), "localhost", "/dns-query")
        .with_timeout(Duration::from_secs(2))
        .with_tls_additional_roots(endpoint.cert.clone());
    let err = client.query("a.test", RecordType::A).await.unwrap_err();
    // HTTP/3 only: no fallback, so the QUIC failure is the answer.
    assert!(
        matches!(err, ClientError::Io(_) | ClientError::Timeout(_)),
        "force must report the transport failure, got {err:?}"
    );
    assert!(endpoint.ids().is_empty(), "h1 must not be touched");
}

/// The fallback answers a wire-faithful name (trailing dot included), i.e.
/// the relay path shares the resolver's name handling.
#[tokio::test]
async fn doh3_fallback_answers_a_wire_name() {
    let endpoint = spawn_h1_only().await;
    let client = DnsClient::doh3(client_addr(&endpoint), "localhost", "/dns-query")
        .with_timeout(Duration::from_secs(3))
        .with_tls_additional_roots(endpoint.cert.clone());
    // `Name` parsing of a trailing dot exercises the generic relay's name
    // handling on the fallback path too.
    let name = Name::from_ascii("c.test.").unwrap();
    let response = client.query_name(&name, RecordType::A).await.unwrap();
    assert_eq!(response.queries[0].name().to_string(), "c.test.");
}

/// A proxy adapter that carries datagrams itself: what `?proxy=` gives a QUIC
/// upstream. It records the dial metadata and relays every packet to the
/// endpoint, so the QUIC handshake and the query really travel through the
/// adapter's association instead of a direct socket.
struct UdpRelayProxy {
    dialed: Arc<Mutex<Vec<Metadata>>>,
    peer: SocketAddr,
}

#[async_trait::async_trait]
impl ProxyAdapter for UdpRelayProxy {
    fn name(&self) -> &str {
        "UDP-RELAY"
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        true
    }
    async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>, MeowError> {
        Err(MeowError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "udp-only test proxy",
        )))
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>, MeowError> {
        self.dialed.lock().unwrap().push(metadata.clone());
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(MeowError::Io)?;
        Ok(Box::new(RelayPacketConn {
            socket,
            peer: self.peer,
        }))
    }
    fn health(&self) -> &ProxyHealth {
        static H: std::sync::OnceLock<ProxyHealth> = std::sync::OnceLock::new();
        H.get_or_init(ProxyHealth::new)
    }
}

impl Proxy for UdpRelayProxy {
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

struct RelayPacketConn {
    socket: UdpSocket,
    peer: SocketAddr,
}

#[async_trait::async_trait]
impl ProxyPacketConn for RelayPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), MeowError> {
        self.socket.recv_from(buf).await.map_err(MeowError::Io)
    }
    async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> Result<usize, MeowError> {
        self.socket
            .send_to(buf, self.peer)
            .await
            .map_err(MeowError::Io)
    }
    fn local_addr(&self) -> Result<SocketAddr, MeowError> {
        self.socket.local_addr().map_err(MeowError::Io)
    }
    fn close(&self) -> Result<(), MeowError> {
        Ok(())
    }
}

/// `?proxy=` for a QUIC upstream: the exchange rides the adapter's datagram
/// association (recorded here), not a direct socket.
#[tokio::test]
async fn doq_routes_through_a_proxy_datagram() {
    let endpoint = spawn(Proto::Doq).await;
    let dialed = Arc::new(Mutex::new(Vec::<Metadata>::new()));
    let proxy: Arc<dyn Proxy> = Arc::new(UdpRelayProxy {
        dialed: Arc::clone(&dialed),
        peer: endpoint.addr,
    });

    let client = DnsClient::doq(endpoint.addr, "localhost")
        .with_timeout(Duration::from_secs(5))
        .with_proxy(proxy)
        .with_tls_additional_roots(endpoint.cert.clone());

    let response = client.query("a.test", RecordType::A).await.unwrap();
    assert_eq!(response.answers.len(), 1);

    let dialed = dialed.lock().unwrap().clone();
    assert_eq!(dialed.len(), 1, "one QUIC connection, one datagram dial");
    assert_eq!(dialed[0].network, Network::Udp);
    assert_eq!(dialed[0].conn_type, ConnType::Inner);
    assert_eq!(dialed[0].dst_port, endpoint.addr.port());
    assert!(dialed[0].internal, "DNS-via-proxy dials are housekeeping");
}
