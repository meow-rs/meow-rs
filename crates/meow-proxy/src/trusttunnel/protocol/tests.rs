use super::{Client, Connector, IoStream, Options};
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

struct Mock {
    connections: AtomicUsize,
    reject: bool,
    malformed_udp: bool,
    goaway: bool,
}
#[async_trait]
impl Connector for Mock {
    async fn connect(&self, _internal: bool) -> io::Result<Box<dyn IoStream>> {
        self.connections.fetch_add(1, Ordering::SeqCst);
        let (client, peer) = tokio::io::duplex(8192);
        let reject = self.reject;
        let malformed = self.malformed_udp;
        let goaway = self.goaway;
        tokio::spawn(async move {
            let mut server = h2::server::handshake(peer).await.unwrap();
            while let Some(Ok((request, mut response))) = server.accept().await {
                assert_eq!(request.method(), http::Method::CONNECT);
                assert_eq!(
                    request.headers()["proxy-authorization"],
                    "Basic Zml4dHVyZTpzZWNyZXQ="
                );
                let authority = request.uri().authority().unwrap().as_str().to_owned();
                let status = if reject { 407 } else { 200 };
                let reply = http::Response::builder().status(status).body(()).unwrap();
                let mut send = response
                    .send_response(reply, reject || authority == "_check")
                    .unwrap();
                let mut recv = request.into_body();
                if goaway && authority == "drain.test:443" {
                    server.graceful_shutdown();
                }
                tokio::spawn(async move {
                    if reject || authority == "_check" {
                        return;
                    }
                    if authority == "flood.test:80" {
                        // More empty frames than the 2 MiB connection window's
                        // framing budget permits, without any useful payload.
                        for _ in 0..8192 {
                            if send.send_data(Bytes::new(), false).is_err() {
                                break;
                            }
                        }
                        std::future::pending::<()>().await;
                    }
                    if authority == "_udp2" && malformed {
                        send.send_data(Bytes::from_static(&[0, 1, 0, 0]), true)
                            .unwrap();
                        return;
                    }
                    let mut pending = Vec::new();
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
                                let mut frame = Vec::new();
                                frame.extend_from_slice(
                                    &((length - app_len - 1) as u32).to_be_bytes(),
                                );
                                frame.extend_from_slice(&body[18..36]);
                                frame.extend_from_slice(&body[..18]);
                                frame.extend_from_slice(&body[37 + app_len..]);
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
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    options.timeout = Duration::from_secs(2);
    (
        Client::new(Arc::<Mock>::clone(&mock), options).unwrap(),
        mock,
    )
}

#[tokio::test]
async fn goaway_retires_new_admission_but_keeps_existing_streams_alive() {
    let mock = Arc::new(Mock {
        connections: AtomicUsize::new(0),
        reject: false,
        malformed_udp: false,
        goaway: true,
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let client = Client::new(Arc::<Mock>::clone(&mock), options).unwrap();
    let mut stream = client.tcp("drain.test:443").await.unwrap();
    stream.write_all(b"live").await.unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"live");
    assert!(client.tcp("new.test:80").await.is_err());
    stream.write_all(b"safe").await.unwrap();
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"safe");
    let _next = client.tcp("new.test:80").await.unwrap();
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
    let a = client
        .udp("192.0.2.1:1234".parse().unwrap(), "fixture")
        .await
        .unwrap();
    let b = client
        .udp("192.0.2.1:1234".parse().unwrap(), "")
        .await
        .unwrap();
    assert_ne!(a.local_addr(), b.local_addr());
    let destinations: [SocketAddr; 3] = [
        "127.0.0.1:53".parse().unwrap(),
        "[2001:db8::2]:53".parse().unwrap(),
        "[::1]:53".parse().unwrap(),
    ];
    for (peer, destination, data) in [
        (&a, destinations[0], vec![]),
        (&b, destinations[1], vec![8; 65507]),
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
    let a = client
        .udp("192.0.2.1:1234".parse().unwrap(), "")
        .await
        .unwrap();
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
async fn oversized_udp_frame_disconnects_bounded_reader() {
    let (client, _) = setup(false, true);
    let a = client
        .udp("192.0.2.1:1234".parse().unwrap(), "")
        .await
        .unwrap();
    let mut buffer = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_secs(1), a.recv_from(&mut buffer))
            .await
            .unwrap()
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
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let client = Client::new(mock, options).unwrap();
    let mut stream = client.tcp("drain.test:443").await.unwrap();
    stream.write_all(b"live").await.unwrap();
    stream.read_exact(&mut [0; 4]).await.unwrap();
    assert!(client.tcp("retire.test:80").await.is_err());
    let _new = client.tcp("new.test:80").await.unwrap();
    client.reset();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
            .await
            .expect("retired session survived network reset")
            .is_err()
    );
}
