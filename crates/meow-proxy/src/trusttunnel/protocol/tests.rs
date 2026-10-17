use super::{Client, H2Connector, IoStream, Options, StreamConnector};
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Build a client whose pooled connections are mock HTTP/2 peers.
fn client(mock: Arc<Mock>, options: Options) -> io::Result<Client> {
    Client::new(Arc::new(H2Connector::new(mock)), options)
}

/// Every CONNECT the mock accepted, as `(authority, headers)`.
type Captured = Arc<std::sync::Mutex<Vec<(String, http::HeaderMap)>>>;

#[derive(Default)]
struct Mock {
    captured: Captured,
    connections: AtomicUsize,
    reject: bool,
    malformed_udp: bool,
    goaway: bool,
    stall_check: bool,
    check_started: Arc<tokio::sync::Notify>,
    maximum_udp_reply: bool,
    zero_udp_destination: bool,
    peer_stream_limit: Option<u32>,
}
#[async_trait]
impl StreamConnector for Mock {
    async fn connect(&self) -> io::Result<Box<dyn IoStream>> {
        self.connections.fetch_add(1, Ordering::SeqCst);
        let (client, peer) = tokio::io::duplex(8192);
        let reject = self.reject;
        let malformed = self.malformed_udp;
        let goaway = self.goaway;
        let stall_check = self.stall_check;
        let check_started = Arc::clone(&self.check_started);
        let maximum_udp_reply = self.maximum_udp_reply;
        let zero_udp_destination = self.zero_udp_destination;
        let peer_stream_limit = self.peer_stream_limit;
        let captured = Arc::clone(&self.captured);
        tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            if let Some(limit) = peer_stream_limit {
                builder.max_concurrent_streams(limit);
            }
            let mut server = builder.handshake(peer).await.unwrap();
            while let Some(Ok((request, mut response))) = server.accept().await {
                assert_eq!(request.method(), http::Method::CONNECT);
                assert_eq!(
                    request.headers()["proxy-authorization"],
                    "Basic Zml4dHVyZTpzZWNyZXQ="
                );
                let authority = request.uri().authority().unwrap().as_str().to_owned();
                captured
                    .lock()
                    .unwrap()
                    .push((authority.clone(), request.headers().clone()));
                if stall_check && authority == "_check" {
                    check_started.notify_one();
                    tokio::spawn(async move {
                        let _request = request;
                        let _response = response;
                        std::future::pending::<()>().await;
                    });
                    continue;
                }
                if authority == "silent.test:443" {
                    // The CONNECT is accepted and never answered. A pooled
                    // connection whose peer went away without saying so —
                    // an expired NAT entry, a slept laptop — looks exactly
                    // like this from the client's side: no error, no
                    // response, just the dial deadline.
                    tokio::spawn(async move {
                        let _request = request;
                        let _response = response;
                        std::future::pending::<()>().await;
                    });
                    continue;
                }
                // A refusal the endpoint *answers*: the target could not be
                // reached, which says nothing about this connection.
                let refused = authority == "refuse.test:443";
                let status = if reject {
                    407
                } else if refused {
                    502
                } else {
                    200
                };
                let reply = http::Response::builder().status(status).body(()).unwrap();
                let mut send = response
                    .send_response(reply, reject || refused || authority == "_check")
                    .unwrap();
                let mut recv = request.into_body();
                if goaway && authority == "drain.test:443" {
                    server.graceful_shutdown();
                }
                tokio::spawn(async move {
                    if reject || refused || authority == "_check" {
                        return;
                    }
                    if authority == "hold.test:443" {
                        // Hold the peer's stream slot for the whole test:
                        // dropping either half would reset the stream and
                        // hand the slot back.
                        let _held = (recv, send);
                        std::future::pending::<()>().await;
                        return;
                    }
                    if authority == "flood.test:80" {
                        // Exceed h2's DATA-frame flood budget (256 frames
                        // per useful frame), without useful payload.
                        for _ in 0..8192 {
                            if send.send_data(Bytes::new(), false).is_err() {
                                break;
                            }
                        }
                        std::future::pending::<()>().await;
                    }
                    if authority == "_udp2" && malformed {
                        // 36-byte header + 65508-byte payload is the largest
                        // legal reply. Keep the stream open: EOF must not
                        // make a missing length guard pass this regression.
                        send.send_data(Bytes::from_static(&[0, 1, 0, 9]), false)
                            .unwrap();
                        std::future::pending::<()>().await;
                    }
                    let mut pending = Vec::new();
                    let mut special_reply_sent = false;
                    while let Some(Ok(data)) = recv.data().await {
                        recv.flow_control().release_capacity(data.len()).unwrap();
                        if authority == "_udp2" {
                            pending.extend_from_slice(&data);
                            while pending.len() >= 4 {
                                let length =
                                    u32::from_be_bytes(pending[..4].try_into().unwrap()) as usize;
                                if pending.len() < length + 4 {
                                    break;
                                }
                                let body = &pending[4..4 + length];
                                let app_len = body[36] as usize;
                                assert_eq!(app_len, 0);
                                let maximum = maximum_udp_reply && !special_reply_sent;
                                let zero_destination = zero_udp_destination && !special_reply_sent;
                                let payload = if maximum {
                                    vec![42; 65508]
                                } else {
                                    body[37 + app_len..].to_vec()
                                };
                                let mut frame = Vec::new();
                                frame.extend_from_slice(
                                    &((36 + payload.len()) as u32).to_be_bytes(),
                                );
                                frame.extend_from_slice(&body[18..36]);
                                if zero_destination {
                                    frame.extend_from_slice(&[0; 18]);
                                } else {
                                    frame.extend_from_slice(&body[..18]);
                                }
                                frame.extend_from_slice(&payload);
                                special_reply_sent = true;
                                send_all(&mut send, Bytes::from(frame)).await;
                                pending.drain(..length + 4);
                            }
                        } else {
                            send_all(&mut send, data).await;
                            if authority == "framing.test:80" {
                                send.send_data(Bytes::new(), false).unwrap();
                            }
                        }
                    }
                    let _ = send.send_data(Bytes::new(), true);
                });
            }
        });
        Ok(Box::new(client))
    }
}
async fn send_all(send: &mut h2::SendStream<Bytes>, mut data: Bytes) {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
        if capacity == 0 {
            continue;
        }
        let len = capacity.min(data.len());
        if send.send_data(data.split_to(len), false).is_err() {
            return;
        }
    }
}
fn setup(reject: bool, malformed_udp: bool) -> (Client, Arc<Mock>) {
    let mock = Arc::new(Mock {
        connections: AtomicUsize::new(0),
        reject,
        malformed_udp,
        goaway: false,
        stall_check: false,
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    options.timeout = Duration::from_secs(2);
    (client(Arc::<Mock>::clone(&mock), options).unwrap(), mock)
}

/// A server-side connection recycle must cost nothing user-visible. The
/// GOAWAY'd connection stops admitting streams, the dial transparently lands
/// on a fresh one, and the draining stream finishes its work.
///
/// Reading the `live` echo first is the barrier that makes this
/// deterministic: the mock queues the GOAWAY frame before the echo task's
/// DATA, so a client that has read the echo has already processed the GOAWAY.
#[tokio::test]
async fn goaway_recycle_moves_the_dial_to_a_fresh_connection() {
    let mock = Arc::new(Mock {
        connections: AtomicUsize::new(0),
        reject: false,
        malformed_udp: false,
        goaway: true,
        stall_check: false,
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let client = client(Arc::<Mock>::clone(&mock), options).unwrap();
    let mut stream = client.tcp("drain.test:443").await.unwrap();
    stream.write_all(b"live").await.unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"live");
    // Nothing had been written when admission was refused, so re-electing a
    // session is not a request replay — and without it every routine recycle
    // would surface as a dial failure that also feeds `DialFailureTracker`
    // toward dead-marking a healthy member.
    let _next = client
        .tcp("new.test:80")
        .await
        .expect("a recycle must not be a user-visible dial failure");
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
    stream.write_all(b"safe").await.unwrap();
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"safe");
    // The second dial reuses the fresh connection rather than growing again.
    let _reused = client.tcp("new.test:80").await.unwrap();
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn tcp_large_transfer_half_close_reuse_and_stream_drop_isolation() {
    let (client, mock) = setup(false, false);
    let first = client.tcp("example.test:443").await.unwrap();
    let mut second = client.tcp("[::1]:443").await.unwrap();
    drop(first);
    let payload = vec![0x6a; 1024 * 1024];
    let expected = payload.clone();
    let (mut read, mut write) = tokio::io::split(second);
    let send = tokio::spawn(async move {
        write.write_all(&payload).await.unwrap();
        write.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), read.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    send.await.unwrap();
    assert_eq!(received, expected);
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
    second = client.tcp("new.test:80").await.unwrap();
    second.write_all(b"still alive").await.unwrap();
    let mut buffer = [0; 11];
    second.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"still alive");
}

#[tokio::test]
async fn udp_multiplex_ipv4_ipv6_empty_max_payload_and_duplicate_source() {
    let (client, mock) = setup(false, false);
    let a = client.udp().await.unwrap();
    let b = client.udp().await.unwrap();
    assert_ne!(a.local_addr(), b.local_addr());
    let destinations: [SocketAddr; 3] = [
        "127.0.0.1:53".parse().unwrap(),
        "[2001:db8::2]:53".parse().unwrap(),
        "[::1]:53".parse().unwrap(),
    ];
    for (peer, destination, data) in [
        (&a, destinations[0], vec![]),
        (&b, destinations[1], vec![8; 65434]),
        (&a, destinations[2], b"ipv6 loopback".to_vec()),
    ] {
        peer.send_to(&data, destination).await.unwrap();
        let mut buffer = vec![0; 65507];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, destination);
        assert_eq!(&buffer[..length], data);
    }
    a.close();
    assert!(a.send_to(b"closed", destinations[0]).await.is_err());
    b.send_to(b"other survives", destinations[1]).await.unwrap();
    let mut buffer = [0; 64];
    let (n, _) = b.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..n], b"other survives");
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn authentication_failure_retires_session_without_replaying() {
    let (client, mock) = setup(true, false);
    let error = client.tcp("example.test:80").await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(client.session_count(), 0);
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reset_closes_pending_reads_and_next_dial_creates_new_session() {
    let (client, mock) = setup(false, false);
    let a = client.udp().await.unwrap();
    let mut tcp = client.tcp("example.test:80").await.unwrap();
    client.reset();
    let mut buffer = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_secs(1), a.recv_from(&mut buffer))
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), tcp.read(&mut buffer))
            .await
            .unwrap()
            .is_err()
    );
    let _new = client.tcp("example.test:80").await.unwrap();
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn maximum_legal_udp_reply_keeps_other_associations_alive() {
    let mock = Arc::new(Mock {
        maximum_udp_reply: true,
        ..Mock::default()
    });
    let client = client(mock, Options::new("fixture".into(), "secret".into())).unwrap();
    let a = client.udp().await.unwrap();
    let b = client.udp().await.unwrap();
    let target = "[2001:db8::1]:53".parse().unwrap();
    a.send_to(b"maximum reply", target).await.unwrap();
    let mut buffer = vec![0; 65508];
    let (length, source) = tokio::time::timeout(Duration::from_secs(2), a.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, target);
    assert_eq!(length, 65508);
    assert!(buffer.iter().all(|byte| *byte == 42));
    b.send_to(b"other survives", target).await.unwrap();
    let (length, source) = tokio::time::timeout(Duration::from_secs(1), b.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, target);
    assert_eq!(&buffer[..length], b"other survives");
    assert_eq!(client.session_count(), 1);
}

#[tokio::test]
async fn oversized_udp_send_is_dropped_without_failing_the_flow() {
    let (client, _) = setup(false, false);
    let association = client.udp().await.unwrap();
    let session = Arc::clone(&super::lock(&client.0.sessions)[0]);
    let mux = Arc::clone(session.udp.lock().await.as_ref().unwrap());
    let target = "192.0.2.2:53".parse().unwrap();
    for length in [65435, 65507, 65508] {
        // Reported as sent, on purpose: `handle_udp` tears the NAT entry
        // down on any `write_packet` error, so one jumbo datagram must not
        // cost every other flow sharing the association.
        let sent = association
            .send_to(&vec![42; length], target)
            .await
            .expect("an undersizable datagram must not fail the association");
        assert_eq!(sent, length);
    }
    assert_eq!(mux.dropped_oversized.load(Ordering::Relaxed), 3);
    association.send_to(b"valid", target).await.unwrap();
    let mut buffer = [0; 16];
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(1), association.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        &buffer[..length],
        b"valid",
        "dropped payload must never enter the send queue"
    );
}

#[tokio::test]
async fn short_udp_buffers_truncate_and_consume_the_whole_datagram() {
    let (client, _) = setup(false, false);
    let association = client.udp().await.unwrap();
    let target = "192.0.2.2:53".parse().unwrap();
    association.send_to(b"abcdefgh", target).await.unwrap();
    let mut buffer = [0; 3];
    let (length, source) = association.recv_from(&mut buffer).await.unwrap();
    assert_eq!((length, source), (3, target));
    assert_eq!(&buffer, b"abc");
    association.send_to(b"discard", target).await.unwrap();
    assert_eq!(association.recv_from(&mut []).await.unwrap(), (0, target));
    association.send_to(b"new", target).await.unwrap();
    let (length, _) = association.recv_from(&mut buffer).await.unwrap();
    assert_eq!((&buffer[..length], length), (b"new".as_slice(), 3));
}

#[tokio::test]
async fn unmatched_udp_reply_is_counted_without_guessing_an_association() {
    let mock = Arc::new(Mock {
        zero_udp_destination: true,
        ..Mock::default()
    });
    let client = client(mock, Options::new("fixture".into(), "secret".into())).unwrap();
    let association = client.udp().await.unwrap();
    let session = Arc::clone(&super::lock(&client.0.sessions)[0]);
    let mux = Arc::clone(session.udp.lock().await.as_ref().unwrap());
    let target = "192.0.2.2:53".parse().unwrap();
    association.send_to(b"unmatched", target).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while mux.dropped_unmatched.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("an unrouteable reply must be observable");
    association.send_to(b"matched", target).await.unwrap();
    let mut buffer = [0; 32];
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(1), association.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buffer[..length], b"matched");
    assert_eq!(mux.dropped_unmatched.load(Ordering::Relaxed), 1);
    assert_eq!(client.session_count(), 1);
}

#[tokio::test]
async fn oversized_udp_frame_disconnects_bounded_reader() {
    let (client, _) = setup(false, true);
    let a = client.udp().await.unwrap();
    let mut buffer = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_secs(1), a.recv_from(&mut buffer))
            .await
            .expect("oversized header must cancel the association without waiting for EOF")
            .is_err()
    );
}

#[tokio::test]
async fn legal_empty_frames_between_payloads_keep_reused_session_alive() {
    let (client, mock) = setup(false, false);
    let mut stream = client.tcp("framing.test:80").await.unwrap();
    let body = [42; 1024];
    for _ in 0..300 {
        stream.write_all(&body).await.unwrap();
        let mut reply = [0; 1024];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, body);
    }
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
    client.reset();
}

#[tokio::test]
async fn empty_frame_flood_still_closes_connection_with_bounded_budget() {
    let (client, _) = setup(false, false);
    let mut stream = client.tcp("flood.test:80").await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("too_many_data_frames"));
}

#[tokio::test]
async fn reset_also_closes_goaway_streams_removed_from_the_admission_pool() {
    let mock = Arc::new(Mock {
        connections: AtomicUsize::new(0),
        reject: false,
        malformed_udp: false,
        goaway: true,
        stall_check: false,
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let client = client(mock, options).unwrap();
    let mut stream = client.tcp("drain.test:443").await.unwrap();
    stream.write_all(b"live").await.unwrap();
    stream.read_exact(&mut [0; 4]).await.unwrap();
    let _retired = client.tcp("retire.test:80").await.unwrap();
    let _new = client.tcp("new.test:80").await.unwrap();
    client.reset();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
            .await
            .expect("retired session survived network reset")
            .is_err()
    );
}

#[tokio::test]
async fn udp_association_limit_is_local_and_recovers_after_drop() {
    let (client, _) = setup(false, false);
    let mut associations = Vec::new();
    for _ in 0..128 {
        associations.push(client.udp().await.unwrap());
    }
    let error = client.udp().await.err().unwrap();
    assert!(meow_common::MeowError::Io(error).is_local_resource_error());
    associations.pop();
    client.udp().await.unwrap();
}

#[tokio::test]
async fn shared_udp_budget_drops_are_counted_and_recover() {
    let (client, _) = setup(false, false);
    let association = client.udp().await.unwrap();
    let session = Arc::clone(&super::lock(&client.0.sessions)[0]);
    let mux = Arc::clone(session.udp.lock().await.as_ref().unwrap());
    let budget = Arc::clone(&mux.budget)
        .try_acquire_many_owned(4 * 1024 * 1024)
        .unwrap();
    let target = "192.0.2.2:53".parse().unwrap();
    association.send_to(b"drop", target).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while mux.dropped_budget.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shared-budget pressure must be observable");
    drop(budget);
    association.send_to(b"live", target).await.unwrap();
    let mut buffer = [0; 16];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(1), association.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(source, target);
    assert_eq!(&buffer[..length], b"live");
    assert_eq!(mux.dropped_budget.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn stalled_health_check_times_out_without_publishing_a_session() {
    let mock = Arc::new(Mock {
        connections: AtomicUsize::new(0),
        reject: false,
        malformed_udp: false,
        goaway: false,
        stall_check: true,
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.health_check = true;
    options.timeout = Duration::from_millis(500);
    let client = client(Arc::<Mock>::clone(&mock), options).unwrap();
    let first = client.tcp("example.test:80");
    tokio::pin!(first);
    tokio::select! {
        result = &mut first => panic!("dial finished before the pending check: {}", result.is_ok()),
        () = mock.check_started.notified() => {},
    }
    assert_eq!(
        client.session_count(),
        0,
        "unchecked session must stay private"
    );
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
    let (first, concurrent) = tokio::join!(first, client.tcp("concurrent.test:80"));
    let error = first.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "TrustTunnel CONNECT timed out");
    assert_eq!(concurrent.err().unwrap().kind(), io::ErrorKind::TimedOut);
    assert_eq!(client.session_count(), 0);
    let next = tokio::time::timeout(Duration::from_secs(1), client.tcp("next.test:80"))
        .await
        .expect("creation lock must be released after a failed check")
        .err()
        .unwrap();
    assert_eq!(next.kind(), io::ErrorKind::TimedOut);
    assert_eq!(client.session_count(), 0);
}

#[tokio::test]
async fn stalled_udp_health_check_uses_the_outer_connect_deadline() {
    let mock = Arc::new(Mock {
        stall_check: true,
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.health_check = true;
    options.timeout = Duration::from_millis(100);
    let client = client(Arc::<Mock>::clone(&mock), options).unwrap();
    for _ in 0..2 {
        let error = client.udp().await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "TrustTunnel UDP CONNECT timed out");
        assert_eq!(client.session_count(), 0);
    }
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
}

/// A connection sitting at the peer's `SETTINGS_MAX_CONCURRENT_STREAMS` is
/// indistinguishable from an idle one in our own accounting, so admission is
/// where the limit shows up. Parking there would spend the caller's entire
/// dial deadline on a connection that cannot serve it while a sibling could:
/// the dial has to move on instead.
#[tokio::test]
async fn peer_stream_limit_moves_the_dial_to_another_connection() {
    let mock = Arc::new(Mock {
        peer_stream_limit: Some(1),
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 2;
    let client = client(Arc::<Mock>::clone(&mock), options).unwrap();
    // Occupy the peer's only stream slot and never release it.
    let _held = client.tcp("hold.test:443").await.unwrap();
    let mut stream = tokio::time::timeout(Duration::from_secs(3), client.tcp("next.test:80"))
        .await
        .expect("a full connection must not burn the whole dial deadline")
        .expect("a sibling connection must carry the dial");
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
    stream.write_all(b"second").await.unwrap();
    let mut bytes = [0; 6];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"second");
}

/// Same situation at the connection cap: there is nowhere left to go, and
/// saying so beats a timeout. The distinction matters because
/// `DialFailureTracker` dead-marks a member on an ordinary dial error but
/// not on a local-resource one — a local pool ceiling is not the node being
/// broken.
#[tokio::test]
async fn peer_stream_limit_at_the_connection_cap_is_a_local_resource_error() {
    let mock = Arc::new(Mock {
        peer_stream_limit: Some(1),
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let client = client(Arc::<Mock>::clone(&mock), options).unwrap();
    let _held = client.tcp("hold.test:443").await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(3), client.tcp("next.test:80"))
        .await
        .expect("the dial must give up long before its own deadline")
        .err()
        .unwrap();
    assert!(
        meow_common::MeowError::Io(error).is_local_resource_error(),
        "a pool ceiling must not dead-mark the node"
    );
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
}

/// Build a client over a fresh mock with caller-chosen options.
fn with_options(options: Options) -> (Client, Arc<Mock>) {
    let mock = Arc::new(Mock {
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    (client(Arc::<Mock>::clone(&mock), options).unwrap(), mock)
}

/// The one `user-agent` the peer saw for `authority`.
fn agent(mock: &Mock, authority: &str) -> String {
    let captured = mock.captured.lock().unwrap();
    let (_, headers) = captured
        .iter()
        .find(|(seen, _)| seen == authority)
        .unwrap_or_else(|| panic!("no CONNECT for {authority} in {captured:?}"));
    assert_eq!(
        headers.get_all(http::header::USER_AGENT).iter().count(),
        1,
        "exactly one user-agent per request"
    );
    headers[http::header::USER_AGENT]
        .to_str()
        .unwrap()
        .to_owned()
}

/// The specification varies the user-agent by CONNECT target: `<platform>`
/// alone on `_check` (§8.2), `<platform> _udp2` on the datagram multiplexer
/// (§6.1), and `<platform> <app_name>` on a tunnel (§5.1). Sending one fixed
/// string for all three is itself something to match on, so assert the shape
/// rather than just "a user-agent is present".
#[tokio::test]
async fn the_user_agent_follows_the_specs_per_stream_shape() {
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    options.health_check = true;
    options.platform = "ios".into();
    options.app_name = "AdGuard".into();
    let (client, mock) = with_options(options);
    let _tunnel = client.tcp("example.test:443").await.unwrap();
    let _datagrams = client.udp().await.unwrap();
    assert_eq!(agent(&mock, "_check"), "ios");
    assert_eq!(agent(&mock, "_udp2"), "ios _udp2");
    assert_eq!(agent(&mock, "example.test:443"), "ios AdGuard");
}

/// The default platform is this host's, and the application name carries no
/// version: `meow/0.22.0` pinned every session to one build of one client.
#[tokio::test]
async fn the_default_user_agent_names_the_platform_without_a_version() {
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let (client, mock) = with_options(options);
    let _tunnel = client.tcp("example.test:443").await.unwrap();
    let agent = agent(&mock, "example.test:443");
    let (platform, app) = agent.split_once(' ').expect(&agent);
    assert!(!platform.is_empty() && !platform.contains(' '));
    assert_eq!(app, "meow");
    assert!(!agent.contains(env!("CARGO_PKG_VERSION")), "{agent}");
}

/// Padding headers exist to stop the handshake from being a constant. A value
/// fixed for the session's life would be exactly that constant, so the
/// placeholder has to be re-rolled per CONNECT — the two dials below share
/// one connection precisely so a per-session render would show up here.
#[tokio::test]
async fn configured_headers_ride_along_and_reroll_each_request() {
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    options.headers = super::ExtraHeaders::new(
        &[
            ("x-padding".into(), "<random-string(16-32)>".into()),
            ("x-fixed".into(), "constant".into()),
        ],
        8,
    )
    .unwrap();
    let (client, mock) = with_options(options);
    let _first = client.tcp("first.test:443").await.unwrap();
    let _second = client.tcp("second.test:443").await.unwrap();
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
    let captured = mock.captured.lock().unwrap().clone();
    let mut paddings = Vec::new();
    for (authority, headers) in &captured {
        let padding = headers["x-padding"].to_str().unwrap();
        assert!(
            (16..=32).contains(&padding.len()),
            "{authority}: {padding:?}"
        );
        assert_eq!(headers["x-fixed"], "constant");
        paddings.push(padding.to_owned());
    }
    assert_eq!(paddings.len(), 2);
    assert_ne!(
        paddings[0], paddings[1],
        "the padding must be re-rolled per request, not per session"
    );
}

/// An operator matching a specific client needs the whole header, not just
/// its two fields — and must not end up sending two of them.
#[tokio::test]
async fn a_configured_user_agent_replaces_the_spec_shaped_one() {
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    options.health_check = true;
    options.headers =
        super::ExtraHeaders::new(&[("User-Agent".into(), "ios AdGuard/2.1".into())], 8).unwrap();
    let (client, mock) = with_options(options);
    let _tunnel = client.tcp("example.test:443").await.unwrap();
    assert_eq!(agent(&mock, "_check"), "ios AdGuard/2.1");
    assert_eq!(agent(&mock, "example.test:443"), "ios AdGuard/2.1");
}

/// A CONNECT that never gets its response headers retires the connection it
/// was sent on.
///
/// Nothing else can: a silent peer errors nothing, so `admit` grants and the
/// request lands in the kernel buffer. If only the caller's deadline ended
/// the dial, the session would stay pooled and `existing()` would elect it
/// again — with no active streams it is the *least loaded* candidate — so
/// every subsequent dial would burn its whole deadline too, until the
/// kernel's retransmit timeout finally errored the socket. Each failure is an
/// ordinary `TimedOut`, which is what `DialFailureTracker` dead-marks a
/// healthy node over.
#[tokio::test]
async fn an_unanswered_connect_retires_the_connection_it_was_sent_on() {
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 2;
    options.timeout = Duration::from_millis(300);
    let (client, mock) = with_options(options);
    let error = client.tcp("silent.test:443").await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        client.session_count(),
        0,
        "a connection that never answered must stop attracting dials"
    );
    // The next dial therefore handshakes a fresh connection instead of
    // paying the deadline again on the dead one.
    let mut stream = tokio::time::timeout(Duration::from_secs(3), client.tcp("next.test:80"))
        .await
        .expect("the dial must not re-elect the silent connection")
        .expect("a fresh connection must carry it");
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
    stream.write_all(b"alive").await.unwrap();
    let mut bytes = [0; 5];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"alive");
    assert_eq!(client.session_count(), 1);
}

/// The opposite case, so the retire above is not simply "any failed dial
/// kills the connection": a CONNECT the endpoint *answers* with a refusal
/// says nothing bad about the connection, and the stream it was refused on
/// is the only thing lost.
#[tokio::test]
async fn an_answered_refusal_keeps_the_connection_pooled() {
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let (client, mock) = with_options(options);
    let _live = client.tcp("first.test:443").await.unwrap();
    let error = client.tcp("refuse.test:443").await.err().unwrap();
    assert!(error.to_string().contains("502"), "{error}");
    assert_eq!(client.session_count(), 1);
    let _reused = client.tcp("second.test:443").await.unwrap();
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
}

/// `Connector::connect` promises that everything the connection owns stops
/// when its token fires, and the pool owes that token a `cancel()` however
/// the dial ends — including the caller's deadline dropping the future
/// mid-handshake. Dropping a `CancellationToken` does not cancel it, and a
/// transport that spawns before its handshake resolves (the H3 driver does)
/// would otherwise be left running with nobody to retire it.
#[tokio::test]
async fn a_dial_abandoned_mid_handshake_cancels_the_connections_token() {
    struct Stalling {
        token: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>>,
    }
    #[async_trait]
    impl super::Connector for Stalling {
        async fn connect(
            &self,
            cancel: tokio_util::sync::CancellationToken,
        ) -> io::Result<Box<dyn super::Connection>> {
            *self.token.lock().unwrap() = Some(cancel);
            std::future::pending().await
        }
    }
    let connector = Arc::new(Stalling {
        token: std::sync::Mutex::new(None),
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.timeout = Duration::from_millis(200);
    let client = Client::new(Arc::<Stalling>::clone(&connector), options).unwrap();
    let error = client.tcp("example.test:443").await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let token = connector.token.lock().unwrap().clone().unwrap();
    assert!(
        token.is_cancelled(),
        "an abandoned dial must still retire whatever its connector started"
    );
}

/// The credential header is the adapter's own; a config that could overwrite
/// it would either break authentication or put the credential in a header of
/// the operator's choosing.
#[test]
fn the_credential_header_cannot_be_overridden() {
    let error = super::ExtraHeaders::new(&[("proxy-authorization".into(), "Basic x".into())], 8)
        .unwrap_err();
    assert!(error.contains("set by the adapter itself"), "{error}");
}

/// A platform token with a space would make the endpoint read the next field
/// as the application name, so it is refused at construction.
#[test]
fn an_unsendable_platform_token_is_refused() {
    let mut options = Options::new("fixture".into(), "secret".into());
    options.platform = "i os".into();
    let mock = Arc::new(Mock::default());
    let error = client(mock, options).err().unwrap();
    assert!(error.to_string().contains("platform"), "{error}");
}

async fn retirement_echo(client: &Client) {
    let mut stream = client.tcp("fresh.test:443").await.unwrap();
    retirement_tcp_echo(&mut stream).await;
}

async fn retirement_tcp_echo(stream: &mut super::TunnelStream) {
    tokio::time::timeout(Duration::from_secs(1), async {
        stream.write_all(b"alive").await.unwrap();
        let mut bytes = [0; 5];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"alive");
    })
    .await
    .expect("established TCP stream stopped during retirement");
}

async fn retirement_udp_echo(association: &super::UdpAssociation) {
    let target = "192.0.2.1:53".parse().unwrap();
    association.send_to(b"alive", target).await.unwrap();
    let mut bytes = [0; 16];
    let (n, from) = tokio::time::timeout(Duration::from_secs(1), association.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, target);
    assert_eq!(&bytes[..n], b"alive");
}

fn retirement_options() -> Options {
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    options.timeout = Duration::from_millis(400);
    options
}

#[tokio::test]
async fn retirement_releases_udp_mux_after_last_association() {
    let mock = Arc::new(Mock::default());
    let client = client(Arc::clone(&mock), retirement_options()).unwrap();
    let association = client.udp().await.unwrap();
    retirement_udp_echo(&association).await;
    let retired = Arc::downgrade(&super::lock(&client.0.sessions)[0]);
    assert_eq!(
        client.tcp("silent.test:443").await.err().unwrap().kind(),
        io::ErrorKind::TimedOut
    );
    retirement_echo(&client).await;
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
    retirement_udp_echo(&association).await;
    drop(association);
    tokio::time::timeout(Duration::from_secs(1), async {
        while retired.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retired UDP session required reset to release its last lease");
}

#[tokio::test]
async fn retirement_releases_an_already_idle_udp_mux() {
    let mock = Arc::new(Mock::default());
    let client = client(Arc::clone(&mock), retirement_options()).unwrap();
    let association = client.udp().await.unwrap();
    retirement_udp_echo(&association).await;
    drop(association);
    let retired = Arc::downgrade(&super::lock(&client.0.sessions)[0]);
    assert_eq!(
        client.tcp("silent.test:443").await.err().unwrap().kind(),
        io::ErrorKind::TimedOut
    );
    retirement_echo(&client).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while retired.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("idle cached UDP mux kept the retired session alive");
}

#[tokio::test]
async fn retirement_preserves_other_associations_and_tcp_until_they_close() {
    let mock = Arc::new(Mock::default());
    let client = client(Arc::clone(&mock), retirement_options()).unwrap();
    let first = client.udp().await.unwrap();
    let second = client.udp().await.unwrap();
    let mut tcp = client.tcp("held.test:443").await.unwrap();
    let retired = Arc::downgrade(&super::lock(&client.0.sessions)[0]);
    let session = Arc::clone(&super::lock(&client.0.sessions)[0]);
    let mux = Arc::clone(session.udp.lock().await.as_ref().unwrap());
    drop(session);
    assert_eq!(
        client.tcp("silent.test:443").await.err().unwrap().kind(),
        io::ErrorKind::TimedOut
    );
    retirement_echo(&client).await;
    assert!(
        mux.associate().is_err(),
        "retired mux accepted a new association"
    );
    drop(first);
    retirement_udp_echo(&second).await;
    retirement_tcp_echo(&mut tcp).await;
    second.close();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !mux.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("last association did not stop the retired UDP tasks");
    retirement_tcp_echo(&mut tcp).await;
    drop(tcp);
    tokio::time::timeout(Duration::from_secs(1), async {
        while retired.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TCP completed but the retired session stayed alive");
}

/// `existing()` elects only reusable sessions, but a concurrent dial's
/// `InFlight` can retire the elected one before `udp()` takes its mux slot.
/// The cached mux is then still open — a live association holds it — yet
/// refuses new ones, and the link underneath may still admit, so neither
/// check notices. The dial must take the same single retry a refused
/// admission gets instead of surfacing the mux's `BrokenPipe`.
#[tokio::test]
async fn retirement_between_election_and_mux_reuse_retries_the_dial() {
    let mock = Arc::new(Mock::default());
    let client = client(Arc::clone(&mock), retirement_options()).unwrap();
    let held = client.udp().await.unwrap();
    let session = Arc::clone(&super::lock(&client.0.sessions)[0]);
    // Park the next dial between election and the slot.
    let slot = session.udp.lock().await;
    let leased = session.active.load(Ordering::Acquire);
    let dial = tokio::spawn({
        let client = client.clone();
        async move { client.udp().await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while session.active.load(Ordering::Acquire) == leased {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the dial never elected the pooled session");
    // What the concurrent dial's dropped `InFlight` does.
    session.retire();
    drop(slot);
    let association = tokio::time::timeout(Duration::from_secs(3), dial)
        .await
        .unwrap()
        .unwrap()
        .expect("a retirement between election and reuse must cost the retry, not the dial");
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
    retirement_udp_echo(&association).await;
    retirement_udp_echo(&held).await;
}

#[tokio::test]
async fn retirement_closed_udp_rejects_oversized_packets() {
    let (client, _) = setup(false, false);
    let association = client.udp().await.unwrap();
    let target = "192.0.2.1:53".parse().unwrap();
    let jumbo = vec![0; 65_435];
    assert_eq!(
        association.send_to(&jumbo, target).await.unwrap(),
        jumbo.len()
    );
    retirement_udp_echo(&association).await;
    association.close();
    for payload in [&b"closed"[..], &jumbo[..]] {
        assert_eq!(
            association
                .send_to(payload, target)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
