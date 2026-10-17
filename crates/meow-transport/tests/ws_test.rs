//! WebSocket layer tests — cases B1..B4 from
//! `docs/specs/transport-layer-test-plan.md`, plus B10..B12 regression
//! cases for the deferred-upgrade fd lifecycle (issue #669).

mod support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use meow_transport::{
    ws::{WsConfig, WsLayer},
    Transport,
};
use support::{log_capture::capture_logs, loopback::spawn_ws_server};
use tokio::net::TcpStream;

// ─── B1: ws_handshake_upgrade ─────────────────────────────────────────────────

/// Loopback server accepts a plain WebSocket upgrade with custom extra headers;
/// client-side connect succeeds and the server captures those headers.
#[tokio::test]
async fn ws_handshake_upgrade() {
    let (addr, info_rx) = spawn_ws_server().await;

    let config = WsConfig {
        path: "/ws".into(),
        host_header: Some("localhost".into()),
        extra_headers: vec![("X-Custom".into(), "hello".into())],
        ..WsConfig::default()
    };

    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    let layer = WsLayer::new(config).expect("WsLayer::new");
    let result = layer.connect(Box::new(tcp)).await;
    assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());

    let info = info_rx.await.expect("WsConnInfo");
    assert_eq!(
        info.host.as_deref(),
        Some("localhost"),
        "Host header mismatch"
    );
    assert_eq!(
        info.headers.get("x-custom").map(String::as_str),
        Some("hello"),
        "X-Custom header not received by server"
    );
}

// ─── B2: ws_host_header_override ─────────────────────────────────────────────

/// When `host_header` is set, the server receives `Host: cdn.example.com`.
#[tokio::test]
async fn ws_host_header_override() {
    let (addr, info_rx) = spawn_ws_server().await;

    let config = WsConfig {
        path: "/".into(),
        host_header: Some("cdn.example.com".into()),
        ..WsConfig::default()
    };

    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    WsLayer::new(config)
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
        .expect("ws connect");

    let info = info_rx.await.expect("WsConnInfo");
    assert_eq!(
        info.host.as_deref(),
        Some("cdn.example.com"),
        "Host header should be cdn.example.com"
    );
}

/// A read-only tunnel must answer peer pings without an application write or
/// flush. The duplex capacity is smaller than the pong frame so the automatic
/// reply also has to recover from write backpressure while reads stay pending.
#[tokio::test]
async fn ws_read_only_client_replies_to_ping_under_backpressure() {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::AsyncReadExt;
    use tokio_tungstenite::tungstenite::Message;

    let (client_io, peer_io) = tokio::io::duplex(64);
    let peer = async move {
        let mut ws = tokio_tungstenite::accept_async(peer_io)
            .await
            .expect("peer accepts upgrade");
        for marker in [0x35, 0x79] {
            let payload = vec![marker; 125];
            ws.send(Message::Ping(payload.clone().into()))
                .await
                .expect("peer sends ping");
            let reply = ws
                .next()
                .await
                .expect("peer receives pong")
                .expect("pong is a valid frame");
            assert_eq!(reply, Message::Pong(payload.into()));
        }
        ws.send(Message::Binary(b"ok".to_vec().into()))
            .await
            .expect("peer sends application data");
    };
    let client = async move {
        let mut stream = WsLayer::new(WsConfig {
            host_header: Some("localhost".into()),
            ..WsConfig::default()
        })
        .expect("WsLayer::new")
        .connect(Box::new(client_io))
        .await
        .expect("client upgrades");
        let mut received = [0; 2];
        stream
            .read_exact(&mut received)
            .await
            .expect("client receives application data after replying to pings");
        assert_eq!(&received, b"ok");
    };

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(peer, client);
    })
    .await
    .expect("read-only client must flush matching pongs without user writes");
}

/// AsyncWrite accepts arbitrary caller slices and preserves every byte when
/// a stalled peer forces partial writes. Exercise both a mux-sized batch and
/// repeated small writes without allowing the peer to read before backpressure.
#[tokio::test]
async fn ws_writes_preserve_bytes_under_backpressure() {
    use futures_util::{future::poll_fn, StreamExt};
    use std::future::Future;
    use std::task::Poll;
    use tokio::io::AsyncWriteExt;
    use tokio_tungstenite::tungstenite::Message;

    for write_size in [256 * 1024, 1024] {
        let expected: Vec<u8> = (0..256 * 1024).map(|index| (index % 251) as u8).collect();
        let sent = expected.clone();
        let (client_io, peer_io) = tokio::io::duplex(64);
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let peer = async move {
            let mut ws = tokio_tungstenite::accept_async(peer_io)
                .await
                .expect("peer accepts upgrade");
            resume_rx.await.expect("client encountered backpressure");
            let mut received = Vec::with_capacity(expected.len());
            while received.len() < expected.len() {
                match ws
                    .next()
                    .await
                    .expect("peer receives all bytes")
                    .expect("valid binary frame")
                {
                    Message::Binary(bytes) => received.extend_from_slice(&bytes),
                    frame => panic!("unexpected application frame: {frame:?}"),
                }
            }
            assert_eq!(received, expected, "caller write size: {write_size}");
        };
        let client = async move {
            let mut stream = WsLayer::new(WsConfig {
                host_header: Some("localhost".into()),
                ..WsConfig::default()
            })
            .expect("WsLayer::new")
            .connect(Box::new(client_io))
            .await
            .expect("client upgrades");
            let mut write = Box::pin(async {
                for chunk in sent.chunks(write_size) {
                    stream.write_all(chunk).await?;
                }
                stream.flush().await
            });
            poll_fn(|cx| match write.as_mut().poll(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(Ok(())) => panic!("stalled peer must cause backpressure"),
                Poll::Ready(Err(error)) => panic!("stalled write must remain pending: {error}"),
            })
            .await;
            resume_tx.send(()).expect("peer is waiting to resume");
            write.await.expect("all caller bytes are accepted");
        };

        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(peer, client);
        })
        .await
        .expect("writes must complete when the peer resumes reading");
    }
}

// ─── B3: ws_early_data_encoded_in_protocol_header ────────────────────────────

/// With `max_early_data = 32`, writing 16 bytes and then flushing sends those
/// bytes base64url-encoded in the `Sec-WebSocket-Protocol` upgrade header
/// (not as a binary frame).
#[tokio::test]
async fn ws_early_data_encoded_in_protocol_header() {
    let (addr, info_rx) = spawn_ws_server().await;

    let payload: Vec<u8> = (0u8..16).collect();

    let config = WsConfig {
        path: "/".into(),
        host_header: Some("localhost".into()),
        max_early_data: 32,
        early_data_header_name: Some("Sec-WebSocket-Protocol".into()),
        ..WsConfig::default()
    };

    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    let mut stream = WsLayer::new(config)
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
        .expect("ws connect returns deferred stream");

    // Write 16 bytes into the early-data buffer (32 cap, so no upgrade yet).
    tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
        .await
        .expect("write early data");

    // Flush triggers the upgrade with the 16 bytes in the header.
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .expect("flush triggers upgrade");

    let info = info_rx.await.expect("WsConnInfo");

    let encoded = info
        .sec_ws_protocol
        .expect("Sec-WebSocket-Protocol header must be present");

    let decoded = URL_SAFE_NO_PAD
        .decode(&encoded)
        .expect("Sec-WebSocket-Protocol must be valid base64url");

    assert_eq!(
        decoded, payload,
        "early data decoded from Sec-WebSocket-Protocol must match written bytes"
    );
}

// ─── B10: ws_upgrade_abort_on_drop_releases_connection ───────────────────────

/// A peer that accepts TCP but never answers the upgrade must not pin the
/// inner fd after the caller drops the stream: the spawned handshake task
/// is aborted on drop, closing the connection promptly (issue #669).
#[tokio::test]
async fn ws_upgrade_abort_on_drop_releases_connection() {
    use tokio::net::TcpListener;

    // Server reads the upgrade request and then stays silent forever.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt as _;
        let (mut conn, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4096];
        loop {
            match conn.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = eof_tx.send(());
                    return;
                }
                Ok(_) => {} // keep draining; never respond
            }
        }
    });

    let config = WsConfig {
        path: "/".into(),
        host_header: Some("localhost".into()),
        // Deferred upgrade: connect returns before the handshake runs.
        max_early_data: 32,
        ..WsConfig::default()
    };

    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    let mut stream = WsLayer::new(config)
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
        .expect("ws connect returns deferred stream");

    // Kick the upgrade: flush spawns the handshake task; the silent peer
    // leaves it pending, so the timeout cancels just the flush future —
    // the stream stays in `Upgrading`.
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"abc")
        .await
        .expect("buffer early data");
    let flush = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::io::AsyncWriteExt::flush(&mut stream),
    )
    .await;
    assert!(flush.is_err(), "silent peer: flush must still be pending");

    drop(stream);

    // On the pre-fix code the spawned task kept the fd open while waiting
    // on the silent peer, so EOF never arrived.
    tokio::time::timeout(std::time::Duration::from_secs(3), eof_rx)
        .await
        .expect("inner fd must be released when the stream is dropped")
        .expect("eof channel");
}

// ─── B11: ws_failed_upgrade_retry_returns_error_not_panic ────────────────────

/// After a failed deferred upgrade the stream stays in `Upgrading`;
/// polling again must return an error, not panic on the consumed
/// `JoinHandle` (regression guard for poll-after-completion).
#[tokio::test]
async fn ws_failed_upgrade_retry_returns_error_not_panic() {
    use tokio::net::TcpListener;

    // Server accepts, then immediately closes — the upgrade fails fast.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("accept");
        drop(conn);
    });

    let config = WsConfig {
        path: "/".into(),
        host_header: Some("localhost".into()),
        max_early_data: 32,
        ..WsConfig::default()
    };
    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    let mut stream = WsLayer::new(config)
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
        .expect("ws connect returns deferred stream");

    // First poll resolves the (failed) handshake; a second poll reaches
    // the already-consumed JoinHandle and must not panic. The outer
    // timeout keeps a hang-regression a test failure, not a stall.
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::io::AsyncWriteExt::flush(&mut stream),
    )
    .await;
    assert!(matches!(first, Ok(Err(_))), "first flush must error");
    assert!(
        tokio::io::AsyncWriteExt::flush(&mut stream).await.is_err(),
        "retry after failed upgrade must error, not panic"
    );
}

// ─── B12: ws_upgrade_timeout bounds silent peers ─────────────────────────────

/// The 10s UPGRADE_TIMEOUT bounds a silent peer on both the deferred task
/// and the eager connect path (issue #669). `start_paused` fast-forwards
/// tokio timers while the socket stays genuinely quiet.
#[tokio::test(start_paused = true)]
async fn ws_upgrade_timeout_bounds_silent_peers() {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4096];
        while conn.read(&mut buf).await.unwrap_or(0) > 0 {}
    });

    // Deferred path: start the upgrade, then fast-forward past the bound.
    let deferred = WsConfig {
        path: "/".into(),
        host_header: Some("localhost".into()),
        max_early_data: 32,
        ..WsConfig::default()
    };
    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    let mut stream = WsLayer::new(deferred)
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
        .expect("deferred connect");
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"abc")
        .await
        .expect("buffer early data");
    let flush = tokio::spawn(async move { tokio::io::AsyncWriteExt::flush(&mut stream).await });
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    // Virtual-time outer guard: a regressed (unbounded) upgrade timer
    // would otherwise hang the test until the harness timeout.
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), flush)
        .await
        .expect("deferred upgrade must resolve (timer regressed to unbounded?)")
        .expect("flush task");
    assert!(result.is_err(), "deferred upgrade must time out");

    // Eager path (max_early_data = 0): connect() itself carries the bound.
    let listener2 = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr2 = listener2.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let (mut conn, _) = listener2.accept().await.expect("accept");
        let mut buf = [0u8; 4096];
        while conn.read(&mut buf).await.unwrap_or(0) > 0 {}
    });
    let tcp = TcpStream::connect(addr2).await.expect("TCP connect");
    let connect = tokio::spawn(async move {
        WsLayer::new(WsConfig {
            path: "/".into(),
            host_header: Some("localhost".into()),
            ..WsConfig::default()
        })
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    let connected = tokio::time::timeout(std::time::Duration::from_secs(60), connect)
        .await
        .expect("eager upgrade must resolve (timer regressed to unbounded?)")
        .expect("connect task");
    assert!(connected.is_err(), "eager upgrade must time out");
}

// ─── B4: ws_host_conflict_warns ──────────────────────────────────────────────

/// When both `host_header` and an `extra_headers["Host"]` entry are set,
/// exactly one warning is logged at construction time and `host_header` wins.
///
/// The warn fires synchronously in `WsLayer::new()`, so we can capture it
/// with `capture_logs`.  We also verify the server receives `host_header`'s
/// value, confirming the Host header takes precedence at connect time.
#[tokio::test]
async fn ws_host_conflict_warns() {
    let (addr, info_rx) = spawn_ws_server().await;

    let config = WsConfig {
        path: "/".into(),
        host_header: Some("winner.example.com".into()),
        extra_headers: vec![("Host".into(), "loser.example.com".into())],
        ..WsConfig::default()
    };

    // Warn fires synchronously in WsLayer::new().
    let logs = capture_logs(|| {
        WsLayer::new(config.clone()).expect("WsLayer::new with host_header set");
    });

    let warn_count = logs.count_containing(&["host_header", "wins"]);
    assert_eq!(
        warn_count,
        1,
        "expected exactly 1 host-conflict warn, got {}. Logs: {:?}",
        warn_count,
        logs.lines()
    );

    // Also verify host_header wins at connect time: server gets "winner.example.com".
    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    WsLayer::new(config)
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
        .expect("ws connect");

    let info = info_rx.await.expect("WsConnInfo");
    assert_eq!(
        info.host.as_deref(),
        Some("winner.example.com"),
        "host_header must take precedence over extra_headers[Host]"
    );
}
