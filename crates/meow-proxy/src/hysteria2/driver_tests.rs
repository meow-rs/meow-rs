//! Portable QUIC peer for lifecycle, flow-control and TCP response regressions.
use super::*;
use crate::hysteria2::ReconnectableClient;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

const TARGET: &str = "target:80";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
/// The echo peer's send cap and scratch buffer: the client's production
/// cap plus QUIC header headroom — this peer's connection ID makes its
/// outgoing packet header slightly larger than the incoming one, and
/// the echo must still fit complete client datagrams. Tied to the
/// production constant so the 1452-band behaviour stays under test.
const PEER_SEND_CAP: usize = crate::hysteria2::tls::MAX_SEND_UDP_PAYLOAD + 48;

#[tokio::test]
async fn raw_udp_round_trip_without_http3_datagrams() {
    let peer = peer(true, Some(0), 16).await;
    let client = peer.client(true);
    let mut udp = timeout(TEST_TIMEOUT, client.udp()).await.unwrap().unwrap();
    for size in [1, 64, 4096] {
        let payload = vec![42; size];
        udp.send(&payload, TARGET).unwrap();
        let (received, addr) = timeout(TEST_TIMEOUT, udp.recv()).await.unwrap().unwrap();
        assert_eq!(received, payload);
        assert_eq!(addr, TARGET);
    }
}

struct Peer {
    addr: SocketAddr,
    read_payload: Arc<AtomicBool>,
    stop_writes: Arc<AtomicBool>,
    auth_seen: mpsc::UnboundedReceiver<SocketAddr>,
    /// Datagrams the peer received that are too small to carry payload —
    /// ACK-only packets plus any other sub-100-byte control traffic.
    small_rx: Arc<AtomicUsize>,
    /// Largest client datagram the peer has seen on the wire — the
    /// injected-path send cap shows up here.
    max_rx: Arc<AtomicUsize>,
    /// Datagrams the peer sent that are big enough to carry payload.
    big_tx: Arc<AtomicUsize>,
    /// Bytes to push down every established stream, taken (reset to 0) by the peer.
    flood: Arc<AtomicUsize>,
    /// Yield to the client after every datagram sent, so it sees packets one
    /// at a time like a paced network instead of one loopback burst.
    trickle: Arc<AtomicBool>,
    /// Set to make the peer send one lone QUIC datagram (taken by the peer).
    lone_dgram: Arc<AtomicBool>,
    /// Set to make the peer send a lone PING — a sub-100-byte packet that
    /// carries no stream or datagram payload (taken by the peer).
    ping: Arc<AtomicBool>,
    /// Microseconds from the peer's last payload datagram to the next ACK-only
    /// datagram it received; `u64::MAX` until that ACK arrives.
    ack_lag_us: Arc<AtomicU64>,
    task: DriverTask,
}

impl Peer {
    /// A single-slot client: this peer serves one QUIC connection, which
    /// is exactly the `quic-connections: 1` legacy shape.
    fn client(&self, fast_open: bool) -> ReconnectableClient {
        client_to(self.addr, fast_open, 1)
    }
}

fn client_to(addr: SocketAddr, fast_open: bool, connections: usize) -> ReconnectableClient {
    ReconnectableClient::new(
        Config {
            server_addr: addr.to_string(),
            server_name: "localhost".into(),
            insecure: true,
            fast_open,
            ..Config::default()
        },
        connections,
    )
}

async fn peer(authenticate: bool, response: Option<u8>, stream_limit: u64) -> Peer {
    peer_with_idle_timeout(authenticate, response, stream_limit, 30_000).await
}

async fn peer_with_idle_timeout(
    authenticate: bool,
    response: Option<u8>,
    stream_limit: u64,
    idle_timeout_ms: u64,
) -> Peer {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer_on(
        socket,
        authenticate,
        response,
        stream_limit,
        idle_timeout_ms,
    )
}

/// A peer serving its single QUIC connection on an already bound `socket`
/// (re-binding a dropped peer's address stands in for a server that accepts
/// a second connection).
fn peer_on(
    socket: UdpSocket,
    authenticate: bool,
    response: Option<u8>,
    stream_limit: u64,
    idle_timeout_ms: u64,
) -> Peer {
    let local = socket.local_addr().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
    ssl.set_certificate(&boring::x509::X509::from_der(key.cert.der()).unwrap())
        .unwrap();
    ssl.set_private_key(
        &boring::pkey::PKey::private_key_from_der(&key.key_pair.serialize_der()).unwrap(),
    )
    .unwrap();
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_max_idle_timeout(idle_timeout_ms);
    config.set_initial_max_streams_bidi(stream_limit);
    config.set_initial_max_streams_uni(16);
    config.set_initial_max_data(1 << 20);
    config.set_initial_max_stream_data_bidi_remote(64 * 1024);
    config.set_initial_max_stream_data_uni(64 * 1024);
    config.enable_dgram(true, 64, 64);
    config.set_max_send_udp_payload_size(PEER_SEND_CAP);
    let read_payload = Arc::new(AtomicBool::new(true));
    let read_enabled = Arc::clone(&read_payload);
    let stop_writes = Arc::new(AtomicBool::new(false));
    let stop_requested = Arc::clone(&stop_writes);
    let (auth_tx, auth_seen) = mpsc::unbounded_channel();
    let small_rx = Arc::new(AtomicUsize::new(0));
    let big_tx = Arc::new(AtomicUsize::new(0));
    let max_rx = Arc::new(AtomicUsize::new(0));
    let (small_rx_task, big_tx_task, max_rx_task) = (
        Arc::clone(&small_rx),
        Arc::clone(&big_tx),
        Arc::clone(&max_rx),
    );
    let flood = Arc::new(AtomicUsize::new(0));
    let flood_task = Arc::clone(&flood);
    let trickle = Arc::new(AtomicBool::new(false));
    let trickle_task = Arc::clone(&trickle);
    let lone_dgram = Arc::new(AtomicBool::new(false));
    let lone_dgram_task = Arc::clone(&lone_dgram);
    let ping = Arc::new(AtomicBool::new(false));
    let ping_task = Arc::clone(&ping);
    let ack_lag_us = Arc::new(AtomicU64::new(u64::MAX));
    let ack_lag_task = Arc::clone(&ack_lag_us);
    let task = DriverTask(tokio::spawn(async move {
        let mut incoming = vec![0; 65535];
        let (n, remote) = socket.recv_from(&mut incoming).await.unwrap();
        let header =
            quiche::Header::from_slice(&mut incoming[..n], quiche::MAX_CONN_ID_LEN).unwrap();
        let mut conn = quiche::accept(&header.dcid, None, local, remote, &mut config).unwrap();
        conn.recv(
            &mut incoming[..n],
            quiche::RecvInfo {
                from: remote,
                to: local,
            },
        )
        .unwrap();
        let mut h3 = None;
        let mut authenticated = false;
        let mut requests: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut established = std::collections::HashSet::new();
        let mut pending: HashMap<u64, VecDeque<u8>> = HashMap::new();
        let mut finished = std::collections::HashSet::new();
        let mut out = [0; PEER_SEND_CAP];
        let mut last_data_tx = std::time::Instant::now();
        loop {
            if conn.is_established() && h3.is_none() {
                h3 = Some(
                    quiche::h3::Connection::with_transport(
                        &mut conn,
                        &quiche::h3::Config::new().unwrap(),
                    )
                    .unwrap(),
                );
            }
            if !authenticated {
                if let Some(h3) = h3.as_mut() {
                    loop {
                        match h3.poll(&mut conn) {
                            Ok((id, quiche::h3::Event::Headers { .. })) => {
                                let _ = auth_tx.send(remote);
                                if authenticate {
                                    h3.send_response(
                                        &mut conn,
                                        id,
                                        &[
                                            quiche::h3::Header::new(b":status", b"233"),
                                            quiche::h3::Header::new(b"hysteria-udp", b"true"),
                                        ],
                                        true,
                                    )
                                    .unwrap();
                                    authenticated = true;
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => panic!("peer auth: {e}"),
                        }
                    }
                }
            }
            if authenticated {
                // Hysteria uses raw QUIC datagrams. Advertising HTTP/3
                // datagrams starts a competing receiver in quic-go.
                if let Some(settings) = h3.as_ref().unwrap().peer_settings_raw() {
                    assert!(!settings.iter().any(|&(id, value)| id == 0x33 && value == 1));
                }
                while let Ok(n) = conn.dgram_recv(&mut incoming) {
                    conn.dgram_send(&incoming[..n]).unwrap();
                }
                if stop_requested.swap(false, Ordering::Relaxed) {
                    for &id in &established {
                        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 42);
                    }
                }
                for id in conn.readable() {
                    if established.contains(&id) && !read_enabled.load(Ordering::Relaxed) {
                        continue;
                    }
                    let mut bytes = [0; 16384];
                    loop {
                        match conn.stream_recv(id, &mut bytes) {
                            Ok((n, fin)) => {
                                if id != 0 && id % 4 == 0 {
                                    let payload = if established.contains(&id) {
                                        bytes[..n].to_vec()
                                    } else {
                                        let request = requests.entry(id).or_default();
                                        request.extend_from_slice(&bytes[..n]);
                                        let expected =
                                            proto::encode_tcp_request(TARGET, &[]).unwrap();
                                        if request.len() < expected.len() {
                                            break;
                                        }
                                        assert_eq!(&request[..expected.len()], expected);
                                        established.insert(id);
                                        if let Some(status) = response {
                                            pending.entry(id).or_default().extend([status, 0, 0]);
                                        }
                                        request.split_off(expected.len())
                                    };
                                    pending.entry(id).or_default().extend(payload);
                                    if fin {
                                        finished.insert(id);
                                    }
                                }
                                if fin {
                                    break;
                                }
                                if established.contains(&id)
                                    && !read_enabled.load(Ordering::Relaxed)
                                {
                                    break;
                                }
                            }
                            Err(quiche::Error::Done) => break,
                            Err(quiche::Error::StreamReset(_)) => {
                                let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, 0);
                                pending.remove(&id);
                                break;
                            }
                            Err(e) => panic!("peer receive: {e}"),
                        }
                    }
                }
                if lone_dgram_task.swap(false, Ordering::Relaxed) {
                    // Re-arm the measurement baseline here: a ≥100-byte
                    // packet sent long ago (handshake, round trip) must not
                    // leave a stale `last_data_tx` inflating a sample should
                    // a stray small packet arrive before this datagram's ACK.
                    last_data_tx = std::time::Instant::now();
                    conn.dgram_send(&[0x55; 300]).unwrap();
                }
                if ping_task.swap(false, Ordering::Relaxed) {
                    conn.send_ack_eliciting().unwrap();
                }
                let flooded = flood_task.swap(0, Ordering::Relaxed);
                if flooded > 0 {
                    for &id in &established {
                        pending.entry(id).or_default().extend(vec![0x37; flooded]);
                    }
                }
                for (&id, data) in &mut pending {
                    while !data.is_empty() {
                        match conn.stream_send(id, data.make_contiguous(), false) {
                            Ok(n) => {
                                data.drain(..n);
                            }
                            Err(quiche::Error::Done) => break,
                            Err(quiche::Error::StreamStopped(_)) => {
                                data.clear();
                                break;
                            }
                            Err(e) => panic!("peer send: {e}"),
                        }
                    }
                    if data.is_empty() && finished.remove(&id) {
                        conn.stream_send(id, &[], true).unwrap();
                    }
                }
            }
            while let Ok((n, info)) = conn.send(&mut out) {
                if n > 1000 {
                    big_tx_task.fetch_add(1, Ordering::Relaxed);
                }
                if n >= 100 {
                    last_data_tx = std::time::Instant::now();
                }
                socket.send_to(&out[..n], info.to).await.unwrap();
                if trickle_task.load(Ordering::Relaxed) {
                    tokio::task::yield_now().await;
                }
            }
            if conn.is_closed() {
                break;
            }
            tokio::select! {
                packet = socket.recv_from(&mut incoming) => {
                    let (n, from) = packet.unwrap();
                    max_rx_task.fetch_max(n, Ordering::Relaxed);
                    if n < 100 {
                        small_rx_task.fetch_add(1, Ordering::Relaxed);
                        if ack_lag_task.load(Ordering::Relaxed) == u64::MAX {
                            ack_lag_task
                                .store(last_data_tx.elapsed().as_micros() as u64, Ordering::Relaxed);
                        }
                    }
                    let _ = conn.recv(&mut incoming[..n], quiche::RecvInfo { from, to: local });
                }
                _ = sleep_opt(conn.timeout()) => conn.on_timeout(),
                _ = sleep(Duration::from_millis(5)) => {}
            }
        }
    }));
    Peer {
        addr: local,
        read_payload,
        stop_writes,
        auth_seen,
        small_rx,
        max_rx,
        big_tx,
        flood,
        trickle,
        lone_dgram,
        ping,
        ack_lag_us,
        task,
    }
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(d) => sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

async fn round_trip(stream: &mut DuplexStream) {
    timeout(TEST_TIMEOUT, async {
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn terminal_write_failure_reaches_both_halves() {
    let peer = peer(true, Some(0), 16).await;
    let client = peer.client(false);
    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    peer.stop_writes.store(true, Ordering::Relaxed);
    let error = timeout(TEST_TIMEOUT, async {
        loop {
            if let Err(error) = stream.write_all(b"hello").await {
                break error;
            }
            if let Err(error) = stream.flush().await {
                break error;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    let mut bytes = Vec::new();
    let error = timeout(TEST_TIMEOUT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn write_budget_survives_draining_the_command_channel() {
    let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
    let (read_tx, read_rx) = mpsc::channel(16);
    let (connected_tx, connected_rx) = oneshot::channel();
    let capacity = Arc::new(Semaphore::new(WRITE_BUFFER_BYTES as usize));
    let mut stream = DuplexStream::new(
        4,
        read_rx,
        Arc::new(Notify::new()),
        cmd_tx,
        Arc::clone(&capacity),
        connected_rx,
        Arc::new(AtomicBool::new(false)),
    );
    connected_tx.send(Ok(())).unwrap();
    stream.wait_connected().await.unwrap();
    let mut queued = Vec::new();
    for _ in 0..4 {
        assert_eq!(stream.write(&[0; 16384]).await.unwrap(), 16384);
        // Draining the bounded channel must NOT release the byte budget.
        queued.push(cmd_rx.recv().await.unwrap());
    }
    assert_eq!(capacity.available_permits(), 0);
    assert!(timeout(Duration::from_millis(20), stream.write(b"x"))
        .await
        .is_err());
    assert!(timeout(Duration::from_millis(20), stream.flush())
        .await
        .is_err());
    queued.clear();
    timeout(TEST_TIMEOUT, stream.flush())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(capacity.available_permits(), WRITE_BUFFER_BYTES as usize);
    drop(read_tx);
}

#[tokio::test]
async fn stream_limit_retries_the_intact_tcp_request() {
    let peer = peer(true, Some(0), 1).await;
    let client = peer.client(false);
    let mut first = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut first).await;
    let second = client.tcp_connect(TARGET);
    tokio::pin!(second);
    assert!(timeout(Duration::from_millis(100), &mut second)
        .await
        .is_err());
    drop(first);
    let mut second = timeout(TEST_TIMEOUT, second).await.unwrap().unwrap();
    round_trip(&mut second).await;
    assert!(!peer.task.0.is_finished());
}

#[tokio::test]
async fn non_fast_open_waits_and_reports_remote_errors() {
    let peer = peer(true, None, 16).await;
    let client = peer.client(false);
    assert!(
        timeout(Duration::from_millis(150), client.tcp_connect(TARGET))
            .await
            .is_err()
    );
    // A peer supports one QUIC connection: use a fresh peer for the fast-open case.
    let fast_peer = self::peer(true, None, 16).await;
    let fast_client = fast_peer.client(true);
    let _stream = timeout(TEST_TIMEOUT, fast_client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();

    let rejected = self::peer(true, Some(1), 16).await;
    let client = rejected.client(false);
    let result = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap();
    assert!(
        matches!(result, Err(Error::Protocol(message)) if message.contains("remote TCP error"))
    );
}

#[tokio::test]
async fn stalled_peer_backpressures_and_resuming_preserves_payload() {
    let peer = peer(true, Some(0), 16).await;
    peer.read_payload.store(false, Ordering::Relaxed);
    let client = peer.client(false);
    let stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let payload = vec![0x5a; 2 * 1024 * 1024];
    let mut writing = tokio::spawn(async move {
        writer.write_all(&payload).await.unwrap();
        writer.shutdown().await.unwrap();
    });
    assert!(timeout(Duration::from_millis(200), &mut writing)
        .await
        .is_err());
    peer.read_payload.store(true, Ordering::Relaxed);
    let reading = async {
        let mut echoed = Vec::new();
        reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, vec![0x5a; 2 * 1024 * 1024]);
    };
    timeout(Duration::from_secs(15), async {
        tokio::join!(reading, async {
            writing.await.unwrap();
        });
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn non_fast_open_response_timeout_is_bounded() {
    let peer = peer(true, None, 16).await;
    let client = peer.client(false);
    let result = timeout(Duration::from_secs(12), client.tcp_connect(TARGET))
        .await
        .expect("TCP response wait exceeded the client deadline");
    assert!(matches!(result, Err(Error::Quic(message)) if message.contains("TCP connect timeout")));
}

#[tokio::test]
async fn keepalive_preserves_an_idle_tcp_stream() {
    // Shrink the negotiated idle timeout to 18s (the client's own is 30s):
    // the client's 10s keepalive ping still lands ~8s inside the window,
    // so the property under test — keepalive defeats the idle deadline —
    // is the same as crossing 30s, without paying 32s of real time.
    let peer = peer_with_idle_timeout(true, Some(0), 16, 18_000).await;
    let client = peer.client(false);
    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut stream).await;
    // quiche uses std::time::Instant, so Tokio's virtual clock cannot
    // exercise its idle timeout. This intentionally crosses it in real time.
    sleep(Duration::from_secs(20)).await;
    round_trip(&mut stream).await;
}

async fn assert_socket_released(addr: SocketAddr) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if UdpSocket::bind(addr).await.is_ok() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("driver retained its UDP socket");
}

#[tokio::test]
async fn cancelling_authentication_releases_the_driver_socket() {
    let mut peer = peer(false, None, 16).await;
    let client = peer.client(false);
    let dial = tokio::spawn(async move { client.tcp_connect(TARGET).await });
    let addr = timeout(TEST_TIMEOUT, peer.auth_seen.recv())
        .await
        .unwrap()
        .unwrap();
    dial.abort();
    assert!(matches!(dial.await, Err(error) if error.is_cancelled()));
    assert_socket_released(addr).await;
}

#[tokio::test]
async fn dropping_the_client_releases_an_authenticated_driver() {
    let mut peer = peer(true, Some(0), 16).await;
    let client = peer.client(false);
    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    let addr = peer.auth_seen.recv().await.unwrap();
    drop(client);
    assert_socket_released(addr).await;
    let error = timeout(TEST_TIMEOUT, stream.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}

/// Issue #695: a reset drops the cached connection — its driver and UDP
/// socket are released and an in-flight stream fails — and the next dial
/// reconnects instead of reusing it.
#[tokio::test]
async fn reset_releases_the_cached_connection_and_reconnects() {
    let mut first = peer(true, Some(0), 16).await;
    let server = first.addr;
    let client = Arc::new(first.client(false));
    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut stream).await;
    let local = first.auth_seen.recv().await.unwrap();

    assert!(
        client.reset(),
        "the idle cache lock is free: dropped synchronously"
    );
    assert_socket_released(local).await;
    let error = timeout(TEST_TIMEOUT, stream.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);

    // The peer serves one connection; a fresh one on the same address
    // proves the next dial reconnects rather than reusing the dropped one.
    drop(first);
    let rebound = timeout(TEST_TIMEOUT, async {
        loop {
            if let Ok(socket) = UdpSocket::bind(server).await {
                break socket;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first peer released its address");
    let mut second = peer_on(rebound, true, Some(0), 16, 30_000);
    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut stream).await;
    timeout(TEST_TIMEOUT, second.auth_seen.recv())
        .await
        .unwrap()
        .expect("the post-reset dial authenticated on a new connection");
    assert!(client.reset(), "the reconnected connection was cached");
}

/// Dial `addr` straight into a driver with non-default [`AckCoalesce`]
/// thresholds — `ReconnectableClient` always takes the defaults, so the
/// coalescing tests drive the raw [`ConnHandle`]. The returned handle must
/// outlive the stream: dropping it aborts the driver task.
async fn dial_with_coalesce(addr: SocketAddr, coalesce: AckCoalesce) -> (ConnHandle, DuplexStream) {
    let cfg = Config {
        server_name: "localhost".into(),
        insecure: true,
        ..Config::default()
    };
    let handle = crate::hysteria2::client::connect_addr(&cfg, addr, "localhost", coalesce)
        .await
        .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    handle
        .cmd_tx
        .send(Cmd::OpenTcp {
            first_frame: proto::encode_tcp_request(TARGET, &[]).unwrap(),
            fast_open: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
    let mut stream = reply_rx.await.unwrap().unwrap();
    stream.wait_connected().await.unwrap();
    (handle, stream)
}

/// A pure download: the client writes nothing, so no upstream data carries its
/// ACKs. With the peer's datagrams arriving one per receive wakeup, held-back
/// ACKs must cut the ACK-only packets well below one per payload packet (a
/// driver that flushes on every wakeup answers more than half of them).
/// The hold's wall-clock deadline would tie the ratio to the runner's speed —
/// a slow machine drains one datagram per wakeup slower than the deadline —
/// so the test pins a deadline longer than the transfer itself and leaves the
/// 8-datagram rule the only hold-ender. Deadline semantics stay with
/// [`lone_packet_is_acked_within_the_coalescing_deadline`].
#[tokio::test]
async fn download_acks_are_coalesced_across_wakeups() {
    let peer = peer(true, Some(0), 16).await;
    // Longer than the read timeout below: `delay` can never end a hold, so
    // at most one ACK-only packet leaves per ACK_COALESCE_PKTS payload
    // packets — ratio 1/8 against the asserted 1/3, on a runner of any speed.
    let (_handle, mut stream) = timeout(
        TEST_TIMEOUT,
        dial_with_coalesce(
            peer.addr,
            AckCoalesce {
                delay: Duration::from_secs(60),
                ..AckCoalesce::default()
            },
        ),
    )
    .await
    .unwrap();
    round_trip(&mut stream).await;
    // Let the application-write quiet window pass and the handshake ACKs drain.
    sleep(Duration::from_millis(50)).await;
    let (small0, big0) = (
        peer.small_rx.load(Ordering::Relaxed),
        peer.big_tx.load(Ordering::Relaxed),
    );
    let size = 4 * 1024 * 1024;
    peer.trickle.store(true, Ordering::Relaxed);
    peer.flood.store(size, Ordering::Relaxed);
    let mut got = vec![0u8; size];
    timeout(Duration::from_secs(15), stream.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    let (small, big) = (
        peer.small_rx.load(Ordering::Relaxed) - small0,
        peer.big_tx.load(Ordering::Relaxed) - big0,
    );
    eprintln!("DOWNLOAD_ACK_RATIO small_rx={small} big_tx={big}");
    assert!(big > 1000, "peer sent only {big} payload packets");
    assert!(
        small * 3 < big,
        "{small} ACK-only packets for {big} payload packets"
    );
}

/// A lone packet (a single QUIC datagram, nothing for a reader to wake the
/// driver with) must not wait for more packets: its ACK leaves within the
/// coalescing deadline. quiche keeps no delayed-ACK timer — an ACK rides on
/// whatever the next `send()` emits — so the fallback this test rules out is
/// the ACK leaving only when the peer's next PTO probe wakes the driver
/// (~35 ms here).
#[tokio::test]
async fn lone_packet_is_acked_within_the_coalescing_deadline() {
    let peer = peer(true, Some(0), 16).await;
    let client = peer.client(false);
    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut stream).await;
    sleep(Duration::from_millis(50)).await;
    let mut lags = Vec::new();
    for _ in 0..10 {
        peer.ack_lag_us.store(u64::MAX, Ordering::Relaxed);
        peer.lone_dgram.store(true, Ordering::Relaxed);
        timeout(TEST_TIMEOUT, async {
            while peer.ack_lag_us.load(Ordering::Relaxed) == u64::MAX {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the lone packet was never acknowledged");
        lags.push(peer.ack_lag_us.load(Ordering::Relaxed));
        sleep(Duration::from_millis(50)).await;
    }
    lags.sort_unstable();
    let median = lags[lags.len() / 2];
    eprintln!("LONE_ACK_LAG_US {lags:?}");
    // The ACK must ride our deadline timer, not the peer's ~35 ms PTO probe.
    // The real bound is the OS timer tick: ~1 ms on Linux, up to ~16 ms at
    // Windows' default 15.6 ms resolution. 22 ms clears that with slack
    // while staying under the 25 ms `max_ack_delay` and the PTO path.
    assert!(median < 22_000, "median ACK lag {median} us: {lags:?}");
}

/// The `delivered` gate, pinned with an unreachable hold: `pkts` and `delay`
/// are set beyond anything the test can wait out, so a hold can end only
/// through the safety gates — a wakeup that delivered no payload, queued
/// frames, a command or a closed connection. A lone PING from the peer
/// carries no payload (nothing for `pump_reads`/`pump_datagrams` to move):
/// it must end the hold and flush the held ACK, not feed the hold. That is
/// the gate the upload regression depends on — an upload's inbound
/// bare-ACK stream is exactly such traffic, and if it could keep a hold
/// alive the ACK would wait out the deadline (here, the full 60 s).
#[tokio::test]
async fn non_delivery_wakeup_ends_the_ack_hold() {
    let peer = peer(true, Some(0), 16).await;
    let (_handle, mut stream) = timeout(
        TEST_TIMEOUT,
        dial_with_coalesce(
            peer.addr,
            AckCoalesce {
                pkts: u32::MAX,
                delay: Duration::from_secs(60),
            },
        ),
    )
    .await
    .unwrap();
    round_trip(&mut stream).await;
    // Past the 1 ms application-quiet window, with handshake ACKs drained.
    sleep(Duration::from_millis(50)).await;

    // A delivered datagram opens a hold whose count and deadline rules
    // cannot end it inside the test window. `ack_lag_us` records the first
    // sub-100-byte packet the peer sees after it: the held ACK leaving.
    peer.ack_lag_us.store(u64::MAX, Ordering::Relaxed);
    peer.lone_dgram.store(true, Ordering::Relaxed);
    // Let the hold take — and the peer's PTO probes come and go — then land
    // a wakeup that is guaranteed to deliver no payload.
    sleep(Duration::from_millis(80)).await;
    peer.ping.store(true, Ordering::Relaxed);
    timeout(TEST_TIMEOUT, async {
        while peer.ack_lag_us.load(Ordering::Relaxed) == u64::MAX {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("a wakeup with no delivered payload must end the hold, not feed it");

    // The complementary gate: queued application bytes never wait on a
    // hold. Open a second hold, then write — the echo returns promptly,
    // not after `delay`.
    peer.lone_dgram.store(true, Ordering::Relaxed);
    sleep(Duration::from_millis(80)).await;
    stream.write_all(b"hi").await.unwrap();
    let mut echoed = [0; 2];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"hi");
}

// ─── dialer-proxy injection (issue #899 follow-up) ─────────────────────────
//
// A `ProxyPacketConn` that actually carries datagrams: the injected
// `SocketIo` path is exercised end to end — the client's whole QUIC
// connection (Initial included) rides the front association's bridge to the
// in-process peer. `remote` is what `write_packet` would stamp; the bridge
// is connected-mode so the arg is inert, like a bound front conn.
struct BridgedConn {
    socket: UdpSocket,
    remote: SocketAddr,
    closed: AtomicBool,
    /// Association-death button: `notify_waiters` ends a parked
    /// `read_packet`, the way a dead front conn ends the pump, and
    /// `killed` fails every subsequent call so the error is permanent.
    kill: Arc<tokio::sync::Notify>,
    killed: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl meow_common::ProxyPacketConn for BridgedConn {
    async fn read_packet(&self, buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
        if self.killed.load(Ordering::Relaxed) {
            return Err(meow_common::MeowError::Proxy(
                "front association died".into(),
            ));
        }
        tokio::select! {
            n = self.socket.recv(buf) => {
                n.map(|n| (n, self.remote)).map_err(meow_common::MeowError::Io)
            }
            _ = self.kill.notified() => {
                Err(meow_common::MeowError::Proxy("front association died".into()))
            }
        }
    }
    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> meow_common::Result<usize> {
        let _ = addr;
        if self.killed.load(Ordering::Relaxed) {
            return Err(meow_common::MeowError::Proxy(
                "front association died".into(),
            ));
        }
        self.socket
            .send(buf)
            .await
            .map_err(meow_common::MeowError::Io)
    }
    fn local_addr(&self) -> meow_common::Result<SocketAddr> {
        self.socket.local_addr().map_err(meow_common::MeowError::Io)
    }
    fn close(&self) -> meow_common::Result<()> {
        self.closed.store(true, Ordering::Relaxed);
        Ok(())
    }
}

/// A `TcpDialer` standing in for the injected `dialer-proxy` front: every
/// `dial_udp_conn` is recorded (`(target, internal)`), then bound to a real
/// socket so the association actually reaches the peer.
struct BridgingDialer {
    dials: std::sync::Mutex<Vec<(crate::dialer::UdpTarget, bool)>>,
    /// One death switch per produced conn — the test kills a single
    /// association without poisoning the one its redial creates.
    conns: std::sync::Mutex<Vec<(Arc<tokio::sync::Notify>, Arc<AtomicBool>)>>,
}

#[async_trait::async_trait]
impl crate::dialer::TcpDialer for BridgingDialer {
    async fn dial(
        &self,
        _host: &str,
        _port: u16,
        _internal: bool,
    ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "bridge dialer carries UDP only",
        ))
    }
    fn is_proxy(&self) -> bool {
        true
    }
    async fn dial_udp_conn(
        &self,
        remote: crate::dialer::UdpTarget,
        internal: bool,
    ) -> std::io::Result<Arc<dyn meow_common::ProxyPacketConn>> {
        self.dials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((remote.clone(), internal));
        let crate::dialer::UdpTarget::Addr(remote) = remote else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "bridge dialer resolves nothing",
            ));
        };
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(remote).await?;
        let kill = Arc::new(tokio::sync::Notify::new());
        let killed = Arc::new(AtomicBool::new(false));
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((Arc::clone(&kill), Arc::clone(&killed)));
        Ok(Arc::new(BridgedConn {
            socket,
            remote,
            closed: AtomicBool::new(false),
            kill,
            killed,
        }))
    }
}

/// The whole QUIC connection — Initial through auth to proxied traffic —
/// must ride the injected front association, not a raw UDP socket. The
/// `Addr` dial is non-internal: user traffic keeps a lazy front alive
/// (issue #555's rule).
#[tokio::test]
async fn quic_transport_rides_injected_socket_io() {
    let peer = peer(true, Some(0), 16).await;
    let dialer = Arc::new(BridgingDialer {
        dials: std::sync::Mutex::new(Vec::new()),
        conns: std::sync::Mutex::new(Vec::new()),
    });
    #[allow(
        clippy::clone_on_ref_ptr,
        reason = "the Arc<BridgingDialer> → Arc<dyn TcpDialer> unsize cannot ride Arc::clone(&_)"
    )]
    let dialer_dyn: Arc<dyn crate::dialer::TcpDialer> = dialer.clone();
    let client = ReconnectableClient::with_dialer(
        Config {
            server_addr: peer.addr.to_string(),
            server_name: "localhost".into(),
            insecure: true,
            fast_open: true,
            ..Config::default()
        },
        dialer_dyn,
        1,
    );

    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut stream).await;

    // UDP over the same injected connection: the datagram session's echo
    // still comes back through the front association.
    let mut udp = timeout(TEST_TIMEOUT, client.udp()).await.unwrap().unwrap();
    udp.send(b"hop", TARGET).unwrap();
    let (received, addr) = timeout(TEST_TIMEOUT, udp.recv()).await.unwrap().unwrap();
    assert_eq!(received, b"hop");
    assert_eq!(addr, TARGET);

    // One association dial, to the literal endpoint, non-internal.
    assert_eq!(
        dialer
            .dials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_slice(),
        &[(crate::dialer::UdpTarget::Addr(peer.addr), false)]
    );
}

/// The injected endpoint's [`SocketIo::mtu_hint`] reaches quiche:
/// `connect_addr_with_io` clamps `set_max_send_udp_payload_size` to the
/// front-path cap, so on the wire a chained client's datagrams stay ≤1280
/// instead of the raw-path 1452 that fragments once the front's
/// per-packet overhead pushes them past a 1500 MTU.
#[tokio::test]
async fn injected_socket_mtu_hint_caps_client_datagrams() {
    let peer = peer(true, Some(0), 16).await;
    let dialer = Arc::new(BridgingDialer {
        dials: std::sync::Mutex::new(Vec::new()),
        conns: std::sync::Mutex::new(Vec::new()),
    });
    #[allow(
        clippy::clone_on_ref_ptr,
        reason = "the Arc<BridgingDialer> → Arc<dyn TcpDialer> unsize cannot ride Arc::clone(&_)"
    )]
    let dialer_dyn: Arc<dyn crate::dialer::TcpDialer> = dialer.clone();
    let client = ReconnectableClient::with_dialer(
        Config {
            server_addr: peer.addr.to_string(),
            server_name: "localhost".into(),
            insecure: true,
            fast_open: true,
            ..Config::default()
        },
        dialer_dyn,
        1,
    );

    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    // Enough stream data to emit full-size datagrams; the peer records
    // the largest client datagram it sees.
    timeout(TEST_TIMEOUT, async {
        stream.write_all(&[0x55; 64 * 1024]).await.unwrap();
        stream.flush().await.unwrap();
    })
    .await
    .unwrap();

    timeout(TEST_TIMEOUT, async {
        while peer.max_rx.load(Ordering::Relaxed) <= 1000 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the peer must see full-size client datagrams");
    assert!(
        peer.max_rx.load(Ordering::Relaxed) <= 1280,
        "client datagrams on a front association must stay at the 1280 hint: {}",
        peer.max_rx.load(Ordering::Relaxed)
    );
}

/// `DriverSocket::Io` semantics at the seam: `send_to` ignores `dest` on a
/// bound endpoint and `recv_from`/`try_recv_from` report the association
/// peer — never a per-packet source.
#[tokio::test]
async fn io_socket_reports_the_bound_peer() {
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = sink.local_addr().unwrap();
    let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    raw.connect(peer_addr).await.unwrap();
    let conn_addr = raw.local_addr().unwrap();
    let conn: Arc<dyn meow_common::ProxyPacketConn> = Arc::new(BridgedConn {
        socket: raw,
        remote: peer_addr,
        closed: AtomicBool::new(false),
        kill: Arc::new(tokio::sync::Notify::new()),
        killed: Arc::new(AtomicBool::new(false)),
    });
    let io = crate::dialer::PacketConnSocket::new(conn, peer_addr);
    let mut socket = DriverSocket::Io {
        io: Box::new(io),
        peer: peer_addr,
    };

    // Empty queue: the drain pass ends instead of pending.
    let mut buf = [0u8; 64];
    assert!(socket.try_recv_from(&mut buf).unwrap().is_none());

    // Inbound: every datagram reports the bound peer as `from`.
    sink.send_to(b"pong", conn_addr).await.unwrap();
    let (n, from) = timeout(TEST_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"pong");
    assert_eq!(from, peer_addr);

    // …and the next queued datagram surfaces through the drain pass.
    sink.send_to(b"pong2", conn_addr).await.unwrap();
    timeout(TEST_TIMEOUT, async {
        loop {
            if let Some((n, from)) = socket.try_recv_from(&mut buf).unwrap() {
                assert_eq!(&buf[..n], b"pong2");
                assert_eq!(from, peer_addr);
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();

    // Outbound: dest is advisory on a bound endpoint — the payload still
    // reaches the peer.
    socket.send_to(b"reply", peer_addr).await.unwrap();
    let mut got = [0u8; 16];
    let (n, _) = timeout(TEST_TIMEOUT, sink.recv_from(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got[..n], b"reply");
}

/// The `dialer-proxy` reconnect contract: when the front association
/// dies, the cached `ConnHandle` goes `is_active() == false` and the next
/// `handle()` must `dial_udp_conn` a *fresh* association — a bound
/// `PacketConnSocket` can never be re-dialed, so a reused one would leave
/// the reconnected QUIC session writing into a dead endpoint.
#[tokio::test]
async fn dead_front_association_redials_a_fresh_association() {
    let first = peer(true, Some(0), 16).await;
    let server = first.addr;
    let dialer = Arc::new(BridgingDialer {
        dials: std::sync::Mutex::new(Vec::new()),
        conns: std::sync::Mutex::new(Vec::new()),
    });
    #[allow(
        clippy::clone_on_ref_ptr,
        reason = "the Arc<BridgingDialer> → Arc<dyn TcpDialer> unsize cannot ride Arc::clone(&_)"
    )]
    let dialer_dyn: Arc<dyn crate::dialer::TcpDialer> = dialer.clone();
    let client = ReconnectableClient::with_dialer(
        Config {
            server_addr: server.to_string(),
            server_name: "localhost".into(),
            insecure: true,
            fast_open: true,
            ..Config::default()
        },
        dialer_dyn,
        1,
    );

    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut stream).await;
    drop(stream);

    // Kill the association the first connection rides: the parked read
    // errors, the driver's recv pump dies, `is_active()` flips.
    {
        let (kill, killed) = {
            let conns = dialer
                .conns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(conns.len(), 1, "the first connect dialed once");
            conns[0].clone()
        };
        killed.store(true, Ordering::Relaxed);
        kill.notify_waiters();
    }

    // The peer serves one connection; a fresh one on the same address is
    // the only way a second handshake can complete (the
    // `reset_releases_the_cached_connection_and_reconnects` precedent).
    drop(first);
    let rebound = timeout(TEST_TIMEOUT, async {
        loop {
            if let Ok(socket) = UdpSocket::bind(server).await {
                break socket;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first peer released its address");
    let mut second = peer_on(rebound, true, Some(0), 16, 30_000);

    // A connect attempted while `is_active` is still flipping fails fast
    // on the dead handle, so retry — the winning attempt is the one that
    // re-dials a new association.
    let mut stream = timeout(TEST_TIMEOUT, async {
        loop {
            match client.tcp_connect(TARGET).await {
                Ok(stream) => break stream,
                Err(_) => sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .expect("the redial must produce a live connection");
    round_trip(&mut stream).await;
    timeout(TEST_TIMEOUT, second.auth_seen.recv())
        .await
        .unwrap()
        .expect("the redial authenticated on a new connection");

    assert_eq!(
        dialer
            .dials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        2,
        "a dead association must be re-dialed through the front, not reused"
    );
}

// ─── K-way QUIC connection pool (perf spec ITEM A) ──────────────────────
//
// `peer_on` serves a single QUIC connection, which a pool can never
// spread across: `PeerMulti` demuxes the socket by client source address
// and spawns one connection task per new source — the same per-connection
// service as the single peer (auth, request accumulation, echo, datagram
// echo), minus the single-peer instrumentation the pool tests don't use.

struct PeerMulti {
    addr: SocketAddr,
    /// Connections accepted so far — one per client slot that has dialed.
    accepts: Arc<AtomicUsize>,
    /// Connection ordinal reported each time a proxy TCP stream
    /// establishes, so a test can verify streams spread across conns.
    stream_seen: mpsc::UnboundedReceiver<usize>,
    /// `(ordinal, client addr)` per auth — the per-connection `auth_seen`.
    auth_seen: mpsc::UnboundedReceiver<(usize, SocketAddr)>,
    /// Aborts the demux and every accepted connection task on drop.
    _tasks: PeerMultiTasks,
}

struct PeerMultiTasks {
    _demux: DriverTask,
    /// Held only so dropping the peer aborts every accepted conn task.
    _conns: Arc<std::sync::Mutex<Vec<DriverTask>>>,
}

/// What every pool connection task shares: the credentials/config recipe
/// (quiche `Config` is not `Clone`, so each task rebuilds it) plus the
/// reporting channels.
struct PoolConnParams {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    authenticate: bool,
    response: Option<u8>,
    stream_limit: u64,
    idle_timeout_ms: u64,
    auth_tx: mpsc::UnboundedSender<(usize, SocketAddr)>,
    stream_tx: mpsc::UnboundedSender<usize>,
}

impl PeerMulti {
    fn client(&self, fast_open: bool, connections: usize) -> ReconnectableClient {
        client_to(self.addr, fast_open, connections)
    }
}

async fn peer_multi() -> PeerMulti {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer_multi_on(socket, true, Some(0), 16, 30_000)
}

fn peer_multi_on(
    socket: UdpSocket,
    authenticate: bool,
    response: Option<u8>,
    stream_limit: u64,
    idle_timeout_ms: u64,
) -> PeerMulti {
    let local = socket.local_addr().unwrap();
    let socket = Arc::new(socket);
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (auth_tx, auth_seen) = mpsc::unbounded_channel();
    let (stream_tx, stream_seen) = mpsc::unbounded_channel();
    let params = Arc::new(PoolConnParams {
        cert_der: key.cert.der().to_vec(),
        key_der: key.key_pair.serialize_der(),
        authenticate,
        response,
        stream_limit,
        idle_timeout_ms,
        auth_tx,
        stream_tx,
    });
    let accepts = Arc::new(AtomicUsize::new(0));
    let conns: Arc<std::sync::Mutex<Vec<DriverTask>>> = Default::default();
    let demux = {
        let socket = Arc::clone(&socket);
        let accepts = Arc::clone(&accepts);
        let conns = Arc::clone(&conns);
        let params = Arc::clone(&params);
        tokio::spawn(async move {
            let mut incoming = vec![0; 65535];
            let mut peers: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
            let mut next_ordinal = 0usize;
            while let Ok((n, from)) = socket.recv_from(&mut incoming).await {
                let mut data = incoming[..n].to_vec();
                if let Some(tx) = peers.get(&from) {
                    // A 256-deep buffer can only fill under a wedged conn —
                    // dropping there beats stalling every other connection.
                    let _ = tx.try_send(data);
                    continue;
                }
                // New client source: accept it as a fresh connection.
                let dcid = {
                    let Ok(header) = quiche::Header::from_slice(&mut data, quiche::MAX_CONN_ID_LEN)
                    else {
                        continue;
                    };
                    header.dcid.to_vec()
                };
                let ordinal = next_ordinal;
                next_ordinal += 1;
                accepts.fetch_add(1, Ordering::Relaxed);
                let (tx, rx) = mpsc::channel(256);
                let task = tokio::spawn(pool_conn(
                    Arc::clone(&socket),
                    local,
                    from,
                    dcid,
                    data,
                    rx,
                    ordinal,
                    Arc::clone(&params),
                ));
                conns.lock().unwrap().push(DriverTask(task));
                peers.insert(from, tx);
            }
        })
    };
    PeerMulti {
        addr: local,
        accepts,
        stream_seen,
        auth_seen,
        _tasks: PeerMultiTasks {
            _demux: DriverTask(demux),
            _conns: conns,
        },
    }
}

/// One accepted connection of [`PeerMulti`]: receives datagrams for its
/// client source over `rx` (the demux owns the socket read side) and
/// answers through the shared socket's send half.
#[allow(
    clippy::too_many_arguments,
    reason = "test peer: the eight leading args are the per-connection wiring a struct would only rename"
)]
async fn pool_conn(
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    remote: SocketAddr,
    dcid: Vec<u8>,
    first: Vec<u8>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    ordinal: usize,
    params: Arc<PoolConnParams>,
) {
    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
    ssl.set_certificate(&boring::x509::X509::from_der(&params.cert_der).unwrap())
        .unwrap();
    ssl.set_private_key(&boring::pkey::PKey::private_key_from_der(&params.key_der).unwrap())
        .unwrap();
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_max_idle_timeout(params.idle_timeout_ms);
    config.set_initial_max_streams_bidi(params.stream_limit);
    config.set_initial_max_streams_uni(16);
    config.set_initial_max_data(1 << 20);
    config.set_initial_max_stream_data_bidi_remote(64 * 1024);
    config.set_initial_max_stream_data_uni(64 * 1024);
    config.enable_dgram(true, 64, 64);
    config.set_max_send_udp_payload_size(PEER_SEND_CAP);
    let dcid = quiche::ConnectionId::from_ref(&dcid);
    let mut conn = quiche::accept(&dcid, None, local, remote, &mut config).unwrap();
    let mut first = first;
    conn.recv(
        &mut first,
        quiche::RecvInfo {
            from: remote,
            to: local,
        },
    )
    .unwrap();
    let mut h3 = None;
    let mut authenticated = false;
    let mut requests: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut established = std::collections::HashSet::new();
    let mut pending: HashMap<u64, VecDeque<u8>> = HashMap::new();
    let mut finished = std::collections::HashSet::new();
    let mut dgram = vec![0; 65535];
    let mut out = [0; PEER_SEND_CAP];
    loop {
        if conn.is_established() && h3.is_none() {
            h3 = Some(
                quiche::h3::Connection::with_transport(
                    &mut conn,
                    &quiche::h3::Config::new().unwrap(),
                )
                .unwrap(),
            );
        }
        if !authenticated {
            if let Some(h3) = h3.as_mut() {
                loop {
                    match h3.poll(&mut conn) {
                        Ok((id, quiche::h3::Event::Headers { .. })) => {
                            let _ = params.auth_tx.send((ordinal, remote));
                            if params.authenticate {
                                h3.send_response(
                                    &mut conn,
                                    id,
                                    &[
                                        quiche::h3::Header::new(b":status", b"233"),
                                        quiche::h3::Header::new(b"hysteria-udp", b"true"),
                                    ],
                                    true,
                                )
                                .unwrap();
                                authenticated = true;
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(quiche::h3::Error::Done) => break,
                        Err(e) => panic!("pool peer auth: {e}"),
                    }
                }
            }
        }
        if authenticated {
            while let Ok(n) = conn.dgram_recv(&mut dgram) {
                conn.dgram_send(&dgram[..n]).unwrap();
            }
            for id in conn.readable() {
                let mut bytes = [0; 16384];
                loop {
                    match conn.stream_recv(id, &mut bytes) {
                        Ok((n, fin)) => {
                            if id != 0 && id % 4 == 0 {
                                let payload = if established.contains(&id) {
                                    bytes[..n].to_vec()
                                } else {
                                    let request = requests.entry(id).or_default();
                                    request.extend_from_slice(&bytes[..n]);
                                    let expected = proto::encode_tcp_request(TARGET, &[]).unwrap();
                                    if request.len() < expected.len() {
                                        break;
                                    }
                                    assert_eq!(&request[..expected.len()], expected);
                                    established.insert(id);
                                    let _ = params.stream_tx.send(ordinal);
                                    if let Some(status) = params.response {
                                        pending.entry(id).or_default().extend([status, 0, 0]);
                                    }
                                    request.split_off(expected.len())
                                };
                                pending.entry(id).or_default().extend(payload);
                                if fin {
                                    finished.insert(id);
                                }
                            }
                            if fin {
                                break;
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(quiche::Error::StreamReset(_)) => {
                            let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, 0);
                            pending.remove(&id);
                            break;
                        }
                        Err(e) => panic!("pool peer receive: {e}"),
                    }
                }
            }
            for (&id, data) in &mut pending {
                while !data.is_empty() {
                    match conn.stream_send(id, data.make_contiguous(), false) {
                        Ok(n) => {
                            data.drain(..n);
                        }
                        Err(quiche::Error::Done) => break,
                        Err(quiche::Error::StreamStopped(_)) => {
                            data.clear();
                            break;
                        }
                        Err(e) => panic!("pool peer send: {e}"),
                    }
                }
                if data.is_empty() && finished.remove(&id) {
                    conn.stream_send(id, &[], true).unwrap();
                }
            }
        }
        while let Ok((n, info)) = conn.send(&mut out) {
            socket.send_to(&out[..n], info.to).await.unwrap();
        }
        if conn.is_closed() {
            return;
        }
        tokio::select! {
            packet = rx.recv() => {
                match packet {
                    Some(mut data) => {
                        let _ = conn.recv(
                            &mut data,
                            quiche::RecvInfo {
                                from: remote,
                                to: local,
                            },
                        );
                    }
                    None => return,
                }
            }
            _ = sleep_opt(conn.timeout()) => conn.on_timeout(),
            _ = sleep(Duration::from_millis(5)) => {}
        }
    }
}

/// Spec ITEM A, round-robin: `quic-connections` opens K independent QUIC
/// connections and spreads new streams across them — six sequential dials
/// on K=3 must establish exactly three connections, two streams each, and
/// leave every slot populated.
#[tokio::test]
async fn pool_round_robins_streams_across_connections() {
    let mut peer = peer_multi().await;
    let client = peer.client(true, 3);
    for _ in 0..6 {
        let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
            .await
            .unwrap()
            .unwrap();
        round_trip(&mut stream).await;
    }
    for i in 0..3 {
        assert!(client.slot_live(i).await, "slot {i} must hold a connection");
    }
    assert_eq!(peer.accepts.load(Ordering::Relaxed), 3);
    let mut seen = Vec::new();
    while let Ok(ordinal) = peer.stream_seen.try_recv() {
        seen.push(ordinal);
    }
    seen.sort_unstable();
    assert_eq!(seen, [0, 0, 1, 1, 2, 2], "streams must spread evenly");
    // Three distinct client sockets authenticated — one per connection.
    let mut auths = Vec::new();
    while let Ok((ordinal, _)) = peer.auth_seen.try_recv() {
        auths.push(ordinal);
    }
    auths.sort_unstable();
    assert_eq!(auths, [0, 1, 2]);
}

/// One dead slot must not take its siblings' streams down, and the next
/// claim on that slot lazily reconnects it — no reset, no pool rebuild.
/// (The spec's "per-slot reconnect isolation" case.)
#[tokio::test]
async fn pool_slot_death_is_isolated_and_heals() {
    let peer = peer_multi().await;
    let client = peer.client(true, 3);
    let mut s0 = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    let mut s1 = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    let mut s2 = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();

    client.drop_slot(1).await;
    // The stream riding slot 1's connection fails with it — same driver-
    // abort path as dropping the client — while the other slots' streams
    // keep echoing.
    let error = timeout(TEST_TIMEOUT, s1.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    round_trip(&mut s0).await;
    round_trip(&mut s2).await;

    // The cursor resumes on slot 0 (claim 4): still alive, no redial.
    let _s3 = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    assert!(!client.slot_live(1).await);
    // Claim 5 lands on slot 1: lazily redialed on a fresh connection.
    let mut healed = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut healed).await;
    assert!(client.slot_live(1).await);
    assert_eq!(
        peer.accepts.load(Ordering::Relaxed),
        4,
        "only the dead slot redials"
    );
}

/// `reset` must drain EVERY slot, not only the one the single-connection
/// cache used to hold: all drivers die, all slots go lazy, and the next K
/// claims redial fresh connections (the "pool reset closing all slots"
/// case).
#[tokio::test]
async fn pool_reset_drains_every_slot() {
    let peer = peer_multi().await;
    let client = Arc::new(peer.client(false, 3));
    let mut streams = Vec::new();
    for _ in 0..3 {
        let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
            .await
            .unwrap()
            .unwrap();
        round_trip(&mut stream).await;
        streams.push(stream);
    }
    for i in 0..3 {
        assert!(client.slot_live(i).await, "slot {i} populated before reset");
    }

    assert!(
        client.reset(),
        "idle slot locks drop connections synchronously"
    );
    for i in 0..3 {
        assert!(!client.slot_live(i).await, "slot {i} drained by reset");
    }
    for stream in &mut streams {
        let error = timeout(TEST_TIMEOUT, stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }

    // The next K claims redial — one fresh connection per slot.
    for _ in 0..3 {
        let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
            .await
            .unwrap()
            .unwrap();
        round_trip(&mut stream).await;
    }
    for i in 0..3 {
        assert!(client.slot_live(i).await, "slot {i} redialed after reset");
    }
    assert_eq!(peer.accepts.load(Ordering::Relaxed), 6);
}

/// `quic-connections: 1` is the legacy shape: every stream and UDP
/// session multiplexes onto a single connection — the pool must never
/// dial a second one.
#[tokio::test]
async fn pool_single_slot_multiplexes_everything() {
    let peer = peer_multi().await;
    let client = peer.client(true, 1);
    let mut udp = timeout(TEST_TIMEOUT, client.udp()).await.unwrap().unwrap();
    udp.send(b"one", TARGET).unwrap();
    let (data, addr) = timeout(TEST_TIMEOUT, udp.recv()).await.unwrap().unwrap();
    assert_eq!(data, b"one");
    assert_eq!(addr, TARGET);
    for _ in 0..3 {
        let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
            .await
            .unwrap()
            .unwrap();
        round_trip(&mut stream).await;
    }
    assert_eq!(
        peer.accepts.load(Ordering::Relaxed),
        1,
        "K=1 muxes TCP and UDP on one connection"
    );
}

/// A UDP session pins the connection it registered on (slot affinity):
/// dropping another slot leaves it alone; dropping its own slot ends it.
#[tokio::test]
async fn pool_udp_sessions_ride_their_own_slot() {
    let peer = peer_multi().await;
    let client = peer.client(true, 2);
    let mut a = timeout(TEST_TIMEOUT, client.udp()).await.unwrap().unwrap();
    let mut b = timeout(TEST_TIMEOUT, client.udp()).await.unwrap().unwrap();
    a.send(b"one", TARGET).unwrap();
    let (data, addr) = timeout(TEST_TIMEOUT, a.recv()).await.unwrap().unwrap();
    assert_eq!((data.as_slice(), addr.as_str()), (&b"one"[..], TARGET));

    // Session a rides slot 0: killing that connection ends it.
    client.drop_slot(0).await;
    let err = timeout(TEST_TIMEOUT, a.recv()).await.unwrap().unwrap_err();
    assert!(matches!(err, Error::Closed), "dead-slot session must close");

    // Session b's connection is untouched — it still echoes.
    b.send(b"two", TARGET).unwrap();
    let (data, addr) = timeout(TEST_TIMEOUT, b.recv()).await.unwrap().unwrap();
    assert_eq!((data.as_slice(), addr.as_str()), (&b"two"[..], TARGET));
}

/// `dialer-proxy` pooling: every slot binds a front UDP association of
/// its own — a bound `PacketConnSocket` can never be redialed, so sharing
/// one would strand every other slot on a dead endpoint.
#[tokio::test]
async fn pool_slots_bind_their_own_front_associations() {
    let peer = peer_multi().await;
    let dialer = Arc::new(BridgingDialer {
        dials: std::sync::Mutex::new(Vec::new()),
        conns: std::sync::Mutex::new(Vec::new()),
    });
    #[allow(
        clippy::clone_on_ref_ptr,
        reason = "the Arc<BridgingDialer> → Arc<dyn TcpDialer> unsize cannot ride Arc::clone(&_)"
    )]
    let dialer_dyn: Arc<dyn crate::dialer::TcpDialer> = dialer.clone();
    let client = ReconnectableClient::with_dialer(
        Config {
            server_addr: peer.addr.to_string(),
            server_name: "localhost".into(),
            insecure: true,
            fast_open: true,
            ..Config::default()
        },
        dialer_dyn,
        2,
    );

    for _ in 0..2 {
        let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
            .await
            .unwrap()
            .unwrap();
        round_trip(&mut stream).await;
    }

    let dials = dialer
        .dials
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(dials.len(), 2, "each slot must dial its own association");
    assert!(
        dials.iter().all(|(target, internal)| matches!(
            target,
            crate::dialer::UdpTarget::Addr(addr) if *addr == peer.addr
        ) && !internal),
        "both associations bind the literal endpoint non-internally: {dials:?}"
    );
    assert_eq!(peer.accepts.load(Ordering::Relaxed), 2);
}
